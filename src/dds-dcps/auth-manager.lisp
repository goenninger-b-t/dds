;;;; DDS-Security 1.1 §8.7 / §9.5 authentication + key-exchange MANAGER (M7/P6 Slice 2b-ii + 2c).
;;;; The orchestrator that ties together the auth handshake (§8.7.2.4, dds-security/auth),
;;;; the §9.5.3 KxKey derivation, and the §9.5.2 per-writer KeyMaterial exchange, and gates
;;;; endpoint matching strictly on authentication. Lives in the DCPS layer (mirrors
;;;; type-gate.lisp): it needs BOTH dds-security (crypto) AND dds-disc (hooks, send, matching),
;;;; so it sits above both — dds-disc stays crypto/format-agnostic (it delivers RAW PSM envelope
;;;; octets; the manager parses + dispatches by message_class_id).
;;;;
;;;; Per-participant state hangs off the domain-participant (DP-AUTH-STATE, analogous to
;;;; DP-TYPE-GATE-STATE). Per-remote state (AUTH-REMOTE, keyed by 12-octet GUID prefix) lives in
;;;; the disc-node's manager-owned DISC-NODE-AUTH-STATE table (T4). Three hooks are installed on
;;;; the disc-node: ON-PARTICIPANT-DISCOVERED (the requester trigger / replier pre-stash),
;;;; ON-STATELESS-MESSAGE (the raw-envelope dispatcher driving the handshake + receiving key
;;;; material), and AUTH-GATE (the §7.3 endpoint-match verdict). All hook bodies run OUTSIDE the
;;;; node lock on the receiver thread and are fail-closed: a malformed message NEVER crashes the
;;;; receiver thread, and a failed/rejected handshake or a KeyMaterial decrypt failure installs
;;;; NO keys -> the remote stays unmatched (no plaintext fallback for a security-enabled
;;;; participant). Secrets (KxKey) are held in dds.pal foreign buffers (T2).
;;;;
;;;; Spec: OMG DDS-Security 1.1 §8.7 (authentication), §9.5.2 (KeyMaterial), §9.5.3 (key
;;;; derivation), §7.4.3/§7.4.4 (ParticipantStatelessMessage / ParticipantGenericMessage), §7.3
;;;; (endpoint match gating). Design: docs/superpowers/specs/2026-06-26-dds-security-auth-keyx-design.md.

(in-package #:dds.dcps)

;;; --- per-participant manager state (behind DP-AUTH-STATE) ---

(defstruct* (auth-manager-state (:constructor %make-auth-manager-state))
  "Per-participant DDS-Security §8.7 authentication-manager state behind DP-AUTH-STATE.
   IDENTITY is the local identity-handle (with the private key) the handshake runs from
   (the disc-node holds only the IdentityToken octets, so the manager owns the handle).
   The per-remote AUTH-REMOTE records live in the disc-node's DISC-NODE-AUTH-STATE table
   (keyed by 12-octet prefix); LOCK guards every read/update of those records across the
   receiver + app threads (never held across DDS.DISC:RESUME-PARKED-MATCHES, which takes
   the node lock). A NIL DP-AUTH-STATE means security is OFF for this participant.
   CRYPTO-MANAGER: the §8.5 key-management hub (crypto-manager.lisp) this participant drives
   for the §9.5.2 KeyMaterial registries + the §8.5.2 crypto-token exchange over PVMS (T8).
   Set by %install-crypto-manager; the :authenticated->:keyed promotion is mediated through it
   (the KEYX per-writer WRITER-KM-TABLE is RETIRED — the per-writer/entity KeyMaterial now lives
   in the crypto-manager EntityCrypto registries, exchanged over reliable PVMS, design §6.4/§7.2).
   Typed T to avoid an auth-manager-state<->crypto-manager defstruct cycle (crypto-manager loads after).
   PERM-CREDENTIAL: the local participant's signed Permissions document octets (the configured create-participant
   :permissions, the S/MIME §9.4.1.1 form) emitted as the §9.3.2.1 handshake c.perm so a conformant peer's
   validate_remote_permissions accepts us; empty (default) for an auth-only / no-AccessControl participant (T6).
   PSM-SEQ: the monotonic §7.4.3.3 ParticipantStatelessMessage message_identity.sequence_number counter for this
   participant's stateless writer — ONE per-participant counter shared across the AuthRequestMessageToken + all
   handshake tokens (was hardcoded 0, a §7.4.3.3 violation that made a strict RTI Connext stateless reader dedup
   our retransmits). Bumped under LOCK via %am-next-psm-seq; first emitted value is 1 (OpenDDS stateless_sequence_number_)."
  (identity (error 'contract-violation :detail "auth-manager-state: :identity is required (the local identity-handle)")   ; NOCOND(CONTRACT): required-initarg poison default
            :type dds.security:identity-handle)
  (lock (dds.pal:make-lock "auth-manager") :type t)
  (crypto-manager nil :type t)
  (perm-credential (make-array 0 :element-type '(unsigned-byte 8))
                   :type (simple-array (unsigned-byte 8) (*)))
  (psm-seq 0 :type integer))

;;; --- per-remote auth/key state (DISC-NODE-AUTH-STATE: 12-octet prefix -> AUTH-REMOTE) ---

(defstruct* (auth-remote (:constructor %make-auth-remote))
  "Per-remote DDS-Security authentication + key-exchange state, keyed by the remote's
   12-octet GUID prefix in DISC-NODE-AUTH-STATE (the manager owns this table). The state
   machine (§8.7 / §9.5):
     :none          discovered + validated; role/suite/remote-token recorded, no handshake yet.
     :handshaking   an in-flight §8.7.2.4 handshake (HANDLE non-NIL).
     :authenticated handshake complete (SharedSecret); the crypto-manager has been driven to derive the
                    §9.5.3.1 PVMS bootstrap KM + send our crypto tokens; the remote's tokens are NOT yet in.
     :keyed         authenticated AND the §8.5 crypto established — the crypto-manager installed the remote's
                    ParticipantCrypto + core builtin EntityCrypto (T8, design §7.2) -> endpoint matching is
                    resumed (DDS.DISC:RESUME-PARKED-MATCHES). The keys live in the crypto-manager registries.
     :rejected      terminal refusal (malformed/untrusted remote, unsupported algo, bad handshake).
   HANDLE: the in-flight handshake-handle (foreign DH/cert state; freed on teardown). At :authenticated it
                 carries the SharedSecret the crypto-manager derives the PVMS bootstrap KM from (T8).
   ROLE: :requester (local GUID < remote) or :replier (§8.7.2.4 ordering).
   LAST-SENT: the last handshake token (internal octets) WE transmitted for this remote (the request
                 for a requester, the reply for a replier). The §8.7 handshake rides the BEST-EFFORT
                 ParticipantStatelessMessage, so it is RETRANSMITTED on SPDP re-announce until it is
                 superseded: the requester re-sends its request while still :awaiting-reply (the replier
                 may not have discovered us when the first request went out), and a replier re-sends this
                 stored reply on a duplicate request rather than feeding the Req into the Final-expecting
                 state machine (which would falsely reject). NIL until we send our first token.
   REMOTE-TOKEN: the remote IdentityToken octets (stashed at discovery so the replier can pick
                 the suite when the request arrives on the wire). SELF-ASSERTED — never the §8.4
                 authorization identity (a peer can claim any cert-sn here).
   VALIDATED-SUBJECT: the remote's VALIDATED handshake-cert subject name (x509-subject-name of the
                 §8.7 chain-verified peer cert, surfaced from the handshake-handle at :authenticated;
                 §8.7.2.5). The §8.4 permissions-gate authorizes on THIS — unforgeable, since the remote
                 proved possession of the private key for the cert this subject is read from. NIL until
                 :authenticated.
   SUITE: the §9.3.2 auth-suite selected for this pair.
   FUTURE-CHALLENGE: our OWN §8.7.2.3 future_challenge nonce for this remote (32 octets), minted ONCE at
                 discovery and reused (stable). It is BOTH the nonce we send in our AuthRequestMessageToken AND —
                 as the requester's challenge1 / replier's challenge2 — our precommitted handshake challenge a
                 full peer (RTI Connext) binds to byte-for-byte (§8.7.2.4/§8.7.2.5). NIL for a non-secured remote.
   REMOTE-FUTURE-CHALLENGE: the remote's §8.7.2.3 future_challenge (32 octets), parsed from ITS
                 AuthRequestMessageToken; NIL until received, then LATCHED first-write-wins (a later CONFLICTING
                 auth_request is IGNORED — the AuthRequestMessageToken rides the UNAUTHENTICATED PSM channel, so a
                 forged one could poison this; a legit peer's nonce is stable across retransmits, so latching never
                 rejects a legit update). When present AND equal to the handshake challenge our replier/requester
                 binds it (§8.7.2.5 defense-in-depth); a MISMATCH (a poisoned/forged nonce) DOWNGRADES to Sign-only
                 rather than hard-REJECT (%am-effective-expected-challenge), so a forged auth_request cannot
                 false-REJECT a legitimate peer (an availability DoS) — the §8.7 cert-chain + Sign gate still
                 decides, never a false-ACCEPT.
                 §8.7.2.3-optional: a peer that sends none (Fast DDS) leaves this NIL -> the check is SKIPPED
                 (absence must not false-reject a conformant peer).
   (The KEYX KX-KEY / REMOTE-KM / LOCAL-KM / LOCAL-SENT-P / PENDING-CT slots are RETIRED in T8: the §9.5.2
   KeyMaterial exchange moved off best-effort PSM onto the crypto-manager + reliable PVMS, design §6.4.)"
  (state        :none :type (member :none :handshaking :authenticated :keyed :rejected))
  (handle       nil :type (or null dds.security:handshake-handle))
  (role         :requester :type (member :requester :replier))
  (last-sent    nil :type (or null (simple-array (unsigned-byte 8) (*))))
  (remote-token nil :type (or null (simple-array (unsigned-byte 8) (*))))
  (validated-subject nil :type (or null string))
  (suite        nil :type (or null dds.security:auth-suite))
  (future-challenge nil :type (or null (simple-array (unsigned-byte 8) (32))))
  (remote-future-challenge nil :type (or null (simple-array (unsigned-byte 8) (32)))))

;;; --- diagnostics ---

(defparameter *auth-manager-log* nil
  "Opt-in diagnostics stream for the DDS-Security §8.7 auth manager (one line per state
   transition / notable event). NIL (default) = silent. Set to *STANDARD-OUTPUT* (or any
   stream) to trace the handshake + key-exchange. Never a wire constant; diagnostics only.")

(defun* %am-log (prefix event)
    (function ((simple-array (unsigned-byte 8) (12)) string) t)
  "One diagnostic line per auth-manager event for the remote 12-octet PREFIX to
   *AUTH-MANAGER-LOG* when set; a NIL stream is silent."
  (when *auth-manager-log*
    (format *auth-manager-log* "~&; auth-manager[~{~2,'0x~}]: ~a~%"
            (coerce (subseq prefix 0 (min 6 (length prefix))) 'list) event))
  t)

;;; --- prefix / GUID helpers ---

(defun* %remote-endpoint-prefix (remote)
    (function (dds.rtps.discovery:endpoint-data) (simple-array (unsigned-byte 8) (12)))
  "The remote participant's 12-octet GUID prefix from REMOTE's 16-octet endpoint GUID
   (GUID_t = GuidPrefix_t(12) + EntityId_t(4), RTPS 2.5 §9.3.1.2) — the AUTH-REMOTE table
   key for this remote. Mirrors %REMOTE-GUID-PREFIX in type-gate.lisp."
  (let ((p (make-array 12 :element-type '(unsigned-byte 8))))
    (replace p (dds.rtps.discovery:endpoint-data-guid remote) :end2 12)
    p))

(defun* %guid-from-prefix (prefix entity-id)
    (function ((simple-array (unsigned-byte 8) (12)) (unsigned-byte 32))
              (simple-array (unsigned-byte 8) (16)))
  "Build a 16-octet GUID_t from a 12-octet participant PREFIX + 32-bit ENTITY-ID (big-endian
   in octets 12-15, GUID_t = GuidPrefix_t + EntityId_t, RTPS 2.5 §9.3.1.2)."
  (let ((g (make-array 16 :element-type '(unsigned-byte 8) :initial-element 0)))
    (replace g prefix :end2 12)
    (setf (aref g 12) (ldb (byte 8 24) entity-id)
          (aref g 13) (ldb (byte 8 16) entity-id)
          (aref g 14) (ldb (byte 8  8) entity-id)
          (aref g 15) (ldb (byte 8  0) entity-id))
    g))

(defun* %prefix-lex< (a b)
    (function ((simple-array (unsigned-byte 8) (12)) (simple-array (unsigned-byte 8) (12))) t)
  "T iff 12-octet GUID prefix A is lexicographically less than B (left-to-right, first
   differing octet decides). The DDS-Security §8.7.2.4 role ordering on the REAL RTPS
   participant GUIDs: the participant entity-id (ENTITYID_PARTICIPANT) is identical for both,
   so comparing the 12-octet prefixes is equivalent to comparing the full 16-octet GUIDs.
   Using the real GUIDs (not validate-remote-identity's T1 cert-sn stand-in) makes the
   requester/replier split deterministic + complementary on both peers."
  (dotimes (i 12 nil)
    (let ((ai (aref a i)) (bi (aref b i)))
      (when (< ai bi) (return t))
      (when (> ai bi) (return nil)))))

;; (T8 removed %local-writer-guid — the KEYX PSM crypto-token senders that used it are retired; the
;; crypto-manager now builds per-entity GUIDs via %guid-from-prefix + the node's user/builtin EntityIds.)

;;; --- PSM send helpers ---

(defun* %am-next-psm-seq (ms)
    (function (auth-manager-state) integer)
  "Return the next monotonic §7.4.3.3 ParticipantStatelessMessage message_identity.sequence_number for MS's
   participant — ONE per-participant counter shared across the AuthRequestMessageToken + all handshake tokens
   (OpenDDS stateless_sequence_number_). First value is 1 (RTPS/DDS-Security a valid PSM seq is >= 1). CALLER
   MUST NOT already hold the manager lock (this takes it for the bump)."
  (dds.pal:with-lock ((auth-manager-state-lock ms))
    (incf (auth-manager-state-psm-seq ms))))

(defun* %am-send-psm-dh (ms node src-prefix dest-prefix message-class-id dh related-guid related-sn)
    (function (auth-manager-state dds.disc:disc-node (simple-array (unsigned-byte 8) (12))
               (simple-array (unsigned-byte 8) (12)) string (simple-array (unsigned-byte 8) (*))
               (or null (simple-array (unsigned-byte 8) (16))) (or null integer)) t)
  "Wrap one CDR-LE DataHolder DH as a §7.4.4 ParticipantGenericMessage with MESSAGE-CLASS-ID and send it over
   the §7.4.3 PSM stateless transport to DEST-PREFIX. message_identity.source_guid = the participant GUID
   (ENTITYID_PARTICIPANT); message_identity.sequence_number = the next monotonic §7.4.3.3 counter
   (%am-next-psm-seq — a strict RTI Connext stateless reader dedups repeats of a stale seq, so this MUST advance).
   related_message_identity echoes (RELATED-GUID . RELATED-SN), or GUID_UNKNOWN/0 when originating (§7.4.3)."
  (let* ((src-guid (%guid-from-prefix src-prefix dds.rtps.message:+entityid-participant+))
         (dst-guid (%guid-from-prefix dest-prefix dds.rtps.message:+entityid-participant+))
         (zero     (make-array 16 :element-type '(unsigned-byte 8) :initial-element 0))
         (env      (dds.security:make-generic-message
                    :source-guid           src-guid
                    :sequence-number       (%am-next-psm-seq ms)
                    ;; §7.4.3 correlation: echo the INCOMING message_identity (RELATED-GUID . RELATED-SN)
                    ;; into related_message_identity so the replier (Fast DDS) matches our Final to its Reply
                    ;; (else SecurityManager.cpp:1554 treats it as a missed-reply and resends, never authorizing);
                    ;; NIL -> GUID_unknown/0 = an originating message (Request / AuthRequest; §8.7.2.4/§8.7.2.3).
                    :related-guid          (or related-guid zero)
                    :related-sn            (or related-sn 0)
                    :dest-participant-guid dst-guid
                    :dest-endpoint-guid    zero
                    ;; source_endpoint_key MUST be GUID_UNKNOWN for the participant-to-participant auth handshake
                    ;; (§7.4.4): Fast DDS generate_authentication_message leaves it unknown and its receiver DROPS
                    ;; a message whose source_endpoint_key != unknown (SecurityManager process_participant_stateless_message).
                    :source-endpoint-guid  zero
                    :message-class-id      message-class-id
                    :dataholders           (list dh))))
    (dds.disc:%send-stateless-message node dest-prefix env))
  t)

(defun* %am-send-handshake (ms node src-prefix dest-prefix token-octets &optional related-guid related-sn)
    (function (auth-manager-state dds.disc:disc-node (simple-array (unsigned-byte 8) (12))
               (simple-array (unsigned-byte 8) (12)) (simple-array (unsigned-byte 8) (*))
               &optional (or null (simple-array (unsigned-byte 8) (16))) (or null integer)) t)
  "Wrap a handshake-token (TOKEN-OCTETS = the internal tagged format the handshake API emits) as a §7.4.4
   ParticipantGenericMessage with message_class_id +AUTH-MESSAGE-CLASS-ID+ and send it over the §7.4.3 PSM
   stateless transport to DEST-PREFIX. The token is parsed back to a handshake-token then re-serialized to a
   §9.3.4 CDR-LE DataHolder (the wire format) — the 2b-i bridge between the internal format and the wire format."
  (let ((tok (dds.security::%parse-token token-octets)))
    (when tok
      (%am-send-psm-dh ms node src-prefix dest-prefix dds.security:+auth-message-class-id+
                       (dds.security:handshake-token->dataholder tok) related-guid related-sn)))
  t)

(defun* %am-send-auth-request (ms node src-prefix dest-prefix nonce)
    (function (auth-manager-state dds.disc:disc-node (simple-array (unsigned-byte 8) (12))
               (simple-array (unsigned-byte 8) (12)) (simple-array (unsigned-byte 8) (32))) t)
  "Send our §8.7.2.3 AuthRequestMessageToken to DEST-PREFIX over the PSM stateless transport: message_class_id
   +AUTH-REQUEST-MESSAGE-CLASS-ID+ ('dds.sec.auth_request'), one DataHolder class_id +AUTH-REQUEST-CLASS-ID+
   ('DDS:Auth:PKI-DH:1.0+AuthReq') with the single binary property future_challenge = NONCE. related_message_identity
   = GUID_UNKNOWN/0 (originating; §7.4.3). This precommits our handshake challenge; a full replier (RTI Connext)
   requires it before it will process our HandshakeRequest. A peer that needs no auth_request (Fast DDS) DISCARDS
   the unknown class silently (SecurityManager 'Discarted ParticipantGenericMessage'), so this never false-rejects."
  (let* ((tok (dds.security::%make-handshake-token
               :class-id dds.security:+auth-request-class-id+
               :binary-props (list (cons dds.security:+prop-future-challenge+ nonce))))
         (dh  (dds.security:handshake-token->dataholder tok)))
    (%am-send-psm-dh ms node src-prefix dest-prefix dds.security:+auth-request-message-class-id+ dh nil nil))
  t)

;; Defined in crypto-manager.lisp (loaded after this file); forward-declared so %am-drive-handshake +
;; %install-auth-manager reach the T8 §8.5 crypto-token exchange / promotion without a compile-time
;; undefined-function warning (the crypto-manager mediates :authenticated->:keyed, design §7.2).
(declaim (ftype (function (t dds.disc:disc-node (simple-array (unsigned-byte 8) (12))) (eql t))
                cm-on-authenticated))
(declaim (ftype (function (domain-participant auth-manager-state dds.disc:disc-node) t)
                %install-crypto-manager))

;;; --- :authenticated transition (CALLER HOLDS the manager lock) ---

(defun* %am-mark-authenticated (ar)
    (function (auth-remote) boolean)
  "Mark AR :authenticated on a completed §8.7.2.4 handshake (CALLER HOLDS the manager lock). Returns T iff
   it JUST transitioned from :none/:handshaking (so the caller drives the §8.5 crypto-token exchange ONCE,
   OUTSIDE the lock — cm-on-authenticated). Idempotent: a no-op NIL if already :authenticated/:keyed/
   :rejected. The KEYX in-lock KxKey-derive + per-writer-KM + crypto-token-send is RETIRED — the bootstrap-KM
   derivation + token exchange now live in cm-on-authenticated over reliable PVMS (T8, design §6.4/§7.2)."
  (when (member (auth-remote-state ar) '(:none :handshaking))
    (setf (auth-remote-state ar) :authenticated)
    t))

(defun* %am-bind-and-check-subject (ar prefix)
    (function (auth-remote (simple-array (unsigned-byte 8) (12))) boolean)
  "Record AR's VALIDATED handshake-cert subject (the §8.4 gate's unforgeable authorization identity,
   surfaced from the handshake-handle PEER-SUBJECT) and apply the §8.7.2.5 token-vs-credential check.
   Returns T to proceed, or NIL to REJECT (the caller fails closed) when the validated cert subject
   disagrees with the cert-sn advertised in AR's self-asserted SPDP IdentityToken (a forged identity
   claim). A NIL validated-or-claimed subject does not itself reject (the AccessControl gate fail-closes
   on a NIL validated subject); only a present-but-different pair is a forgery. CALLER HOLDS the lock."
  (let ((handle (auth-remote-handle ar)))
    (when handle
      (setf (auth-remote-validated-subject ar) (dds.security:handshake-handle-peer-subject handle))))
  (let ((validated (auth-remote-validated-subject ar))
        (claimed (and (auth-remote-remote-token ar)
                      (nth-value 0 (dds.security::%parse-remote-token-strings
                                    (auth-remote-remote-token ar))))))
    (cond
      ((and validated claimed (not (string= validated claimed)))
       (%am-log prefix "8.7.2.5 reject: validated cert subject != advertised IdentityToken cert-sn")
       nil)
      (t t))))

;;; --- discovery hook: requester trigger / replier pre-stash ---

(defun* %am-validate-and-record (ms node prefix spdp)
    (function (auth-manager-state dds.disc:disc-node (simple-array (unsigned-byte 8) (12))
               dds.rtps.discovery:spdp-data)
              (or auth-remote null))
  "Under the manager lock: validate the remote's IdentityToken (from SPDP), select the §9.3.2
   suite, and (idempotently) create + record the AUTH-REMOTE keyed by PREFIX in the disc-node's
   auth-state table. Returns the AUTH-REMOTE (NIL when there is no IdentityToken — a plain peer —
   so the caller does nothing). A malformed token or an unsupported/mismatched algo records a
   :rejected AUTH-REMOTE (the strict gate then refuses the peer). An already-recorded remote is
   returned unchanged (re-announce idempotency)."
  (let ((token (dds.rtps.discovery:spdp-data-identity-token-octets spdp)))
    (when (null token) (return-from %am-validate-and-record nil))
    (dds.pal:with-lock ((auth-manager-state-lock ms))
      (let ((existing (gethash prefix (dds.disc:disc-node-auth-state node))))
        (when existing (return-from %am-validate-and-record existing))
        ;; §8.7.2.3: mint our future_challenge ONCE per remote here (stable across retransmits) — it is our
        ;; AuthRequestMessageToken nonce AND our precommitted handshake challenge1/challenge2 (§8.7.2.4/§8.7.2.5).
        (let ((ar (%make-auth-remote :remote-token (copy-seq token)
                                     :future-challenge (dds.security:generate-future-challenge))))
          (setf (gethash (copy-seq prefix) (dds.disc:disc-node-auth-state node)) ar)
          ;; role from the REAL RTPS GUID prefixes (§8.7.2.4): deterministic + complementary on
          ;; both peers (validate-remote-identity's T1 cert-sn-hash stand-in is NOT used for the role)
          (setf (auth-remote-role ar)
                (if (%prefix-lex< (dds.disc:disc-node-guid-prefix node) prefix) :requester :replier))
          (multiple-value-bind (verdict role reason)
              (dds.security:validate-remote-identity (auth-manager-state-identity ms) token)
            (declare (ignore role reason))
            (cond
              ((not (eq verdict :ok))
               (setf (auth-remote-state ar) :rejected)
               (%am-log prefix "remote IdentityToken rejected"))
              (t
               (let ((suite (dds.security:select-suite-for-identities
                             (auth-manager-state-identity ms) token)))
                 (if (null suite)
                     (progn (setf (auth-remote-state ar) :rejected)
                            (%am-log prefix "no common auth suite (unsupported/mismatched algo) -> reject"))
                     (setf (auth-remote-suite ar) suite))))))
          ar)))))

(defun* %am-on-participant-discovered (p node prefix spdp)
    (function (domain-participant dds.disc:disc-node (simple-array (unsigned-byte 8) (12))
               dds.rtps.discovery:spdp-data)
              t)
  "ON-PARTICIPANT-DISCOVERED hook (receiver thread, OUTSIDE the node lock): validate + record
   the remote (%AM-VALIDATE-AND-RECORD), then — if this participant is the :requester for the
   pair (§8.7.2.4 GUID order) and the suite was selected — initiate the §8.7.2.4 handshake:
   BEGIN-HANDSHAKE-REQUEST, stash the in-flight handle, set :handshaking, and send the request
   over PSM. The :replier records the remote + suite and WAITS for the request on the wire
   (driven by %AM-ON-STATELESS-MESSAGE). Fail-closed: a plain (no-IdentityToken) peer is a no-op
   here; the strict gate refuses it at match time."
  (let ((ms (dp-auth-state p)))
    (when (null ms) (return-from %am-on-participant-discovered t))
    (let ((ar (%am-validate-and-record ms node prefix spdp))
          (req-octets nil) (req-handle nil) (do-send nil) (resend nil)
          (send-ar nil) (auth-nonce nil))
      (when (null ar) (return-from %am-on-participant-discovered t))
      (dds.pal:with-lock ((auth-manager-state-lock ms))
        ;; §8.7.2.3: (re)send our AuthRequestMessageToken while not yet authenticated (BOTH roles; OpenDDS sends
        ;; regardless of role). A full replier (RTI Connext) requires our future_challenge before it processes our
        ;; HandshakeRequest; ours↔ours/Fast-DDS ignore/tolerate it. Retransmitted on each SPDP re-announce (best-effort PSM).
        (when (and (member (auth-remote-state ar) '(:none :handshaking))
                   (auth-remote-future-challenge ar))
          (setf send-ar t auth-nonce (auth-remote-future-challenge ar)))
        (cond
          ;; first request: requester begins the §8.7.2.4 handshake
          ((and (eq (auth-remote-state ar) :none)
                (eq (auth-remote-role ar) :requester)
                (auth-remote-suite ar)
                (null (auth-remote-handle ar)))
           (multiple-value-setq (req-octets req-handle)
             (dds.security:begin-handshake-request
              (auth-manager-state-identity ms) (auth-manager-state-identity ms)
              (auth-remote-suite ar)
              ;; §9.3.2.1 c.perm: our signed Permissions credential so the replier's validate_remote_permissions accepts us (T6)
              (auth-manager-state-perm-credential ms)
              ;; §8.7.2.4: challenge1 = our precommitted future_challenge (verbatim) so a full replier binds to it
              (auth-remote-future-challenge ar)))
           (when req-handle
             (setf (auth-remote-handle ar) req-handle
                   (auth-remote-state ar) :handshaking
                   (auth-remote-last-sent ar) req-octets
                   do-send t)))
          ;; re-announce while still awaiting the reply: RETRANSMIT the request (best-effort PSM; the
          ;; replier may not have discovered us when the first request went out — the role/ordering is
          ;; cert-derived per §9.3.2.1, so the requester can be the later-joining peer)
          ((and (eq (auth-remote-role ar) :requester)
                (eq (auth-remote-state ar) :handshaking)
                (auth-remote-handle ar)
                (eq (dds.security:handshake-handle-state (auth-remote-handle ar)) :awaiting-reply)
                (auth-remote-last-sent ar))
           (setf req-octets (auth-remote-last-sent ar) do-send t resend t))))
      ;; sends OUTSIDE the manager lock (PSM send takes the node lock internally); the AuthRequestMessageToken
      ;; goes FIRST so a full replier has our future_challenge before it processes the HandshakeRequest (§8.7.2.3).
      (when send-ar
        (%am-send-auth-request ms node (dds.disc:disc-node-guid-prefix node) prefix auth-nonce))
      (when do-send
        (unless resend (%am-log prefix "requester: sent HandshakeRequest"))
        (%am-send-handshake ms node (dds.disc:disc-node-guid-prefix node) prefix req-octets))))
  t)

;;; --- stateless-message hook: parse + dispatch by message_class_id ---

(defun* %am-token-class (token-octets)
    (function ((simple-array (unsigned-byte 8) (*))) (or string null))
  "Return the §9.3.2.1 handshake-token class_id string for TOKEN-OCTETS (internal tagged format),
   or NIL on malformed input. Lets the manager recognise an OUT-OF-ROLE handshake message WITHOUT
   driving the §8.7.2.4 state machine: a Req arriving at an already-replied replier (re-send the
   stored reply), or a non-Reply arriving at a requester still awaiting the Reply (drop it — never
   let a stray/duplicate/echoed token false-reject the handshake). Fail-closed: NIL on malformed."
  (let ((tok (dds.security::%parse-token token-octets)))
    (and tok (dds.security::handshake-token-class-id tok))))

(defun* %am-token-is-request-p (token-octets)
    (function ((simple-array (unsigned-byte 8) (*))) boolean)
  "T iff TOKEN-OCTETS (internal handshake-token format) is a HandshakeRequestMessageToken
   (§9.3.2.1). Used to recognise a RETRANSMITTED request arriving at an already-replied replier so
   the manager re-sends its stored reply instead of feeding a Req into the Final-expecting state
   machine (which would falsely reject the handshake). Fail-closed: NIL on any malformed input."
  (let ((c (%am-token-class token-octets)))
    (dds.security::%class-id-role-match-p c dds.security::+handshake-request-class-id+)))

(defun* %am-effective-expected-challenge (stored token-octets prop-name prefix)
    (function ((or null (simple-array (unsigned-byte 8) (32)))
               (simple-array (unsigned-byte 8) (*)) string (simple-array (unsigned-byte 8) (12)))
              (or null (simple-array (unsigned-byte 8) (*))))
  "The §8.7.2.3 challenge-binding availability hardening (fail-closed DoS guard): decide the EXPECTED-CHALLENGE
   to feed the strict handshake API for the incoming token, given the LATCHED remote future_challenge STORED
   (the AuthRequestMessageToken nonce) and the binding property PROP-NAME (+prop-challenge1+ for a replier
   verifying a Request, +prop-challenge2+ for a requester verifying a Reply). Returns:
     STORED — when the token's PROP-NAME challenge EQUALS the stored nonce: the §8.7.2.5 binding is ENFORCED
              (the strict API re-verifies it; a positive freshness proof, defense-in-depth kept);
     NIL    — when STORED is NIL (no auth_request seen; §8.7.2.3-optional absence-tolerance, unchanged), OR the
              token carries no such challenge, OR the token's challenge MISMATCHES the stored nonce. A MISMATCH
              DOWNGRADES the binding to Sign-only (logs a possible forged-auth_request event) rather than letting
              the strict API hard-REJECT — since a forged auth_request on the unauthenticated PSM channel could
              poison STORED and thereby false-REJECT a LEGITIMATE peer (an availability DoS, ADR 0040 carry #2).
   This NEVER causes a false-ACCEPT: the downgrade only ever SKIPS the byte-exact nonce cross-binding (the same
   absence path a spec-literal Fast DDS peer already takes); the §8.7 cert-chain + Sign1/Sign2 possession proof
   (and the handshake's own un-poisonable challenge ECHO checks) remain FULLY enforced by the API and decide the
   verdict. The strict handshake-API binding is UNCHANGED (still fail-closed on a supplied mismatch — the
   run-auth-challenge-binding-test asserts it); this hardening governs only WHICH nonce the manager trusts to
   supply from the unauthenticated channel."
  (when (null stored) (return-from %am-effective-expected-challenge nil))
  (let* ((tok  (dds.security::%parse-token token-octets))
         (chal (and tok (dds.security::%token-get tok prop-name))))
    (cond
      ((null chal) nil)
      ((equalp chal stored) stored)
      (t (%am-log prefix "challenge-binding mismatch vs latched future_challenge -> downgrade to Sign-only (possible forged auth_request DoS)")
         nil))))

(defun* %am-drive-handshake (ms node prefix ar token-octets in-guid in-sn)
    (function (auth-manager-state dds.disc:disc-node (simple-array (unsigned-byte 8) (12))
               auth-remote (simple-array (unsigned-byte 8) (*))
               (or null (simple-array (unsigned-byte 8) (16))) integer)
              t)
  "Drive the §8.7.2.4 handshake one step for AR given the incoming handshake token (internal
   tagged octets). Under the manager lock: a :replier with no in-flight handle does
   BEGIN-HANDSHAKE-REPLY (first request); otherwise PROCESS-HANDSHAKE drives the next step; on
   reaching :authenticated AR is marked :authenticated (%AM-MARK-AUTHENTICATED). The produced next
   handshake token is sent over PSM, and the §8.5 crypto-token exchange (cm-on-authenticated: PVMS
   bootstrap-KM derive + token send over reliable PVMS) is driven, BOTH OUTSIDE the lock (never hold the
   lock across a network send — the type-gate discipline). Fail-closed: a nil/failed handshake step records
   :rejected and installs no keys. Returns T (hook ignores it).
   IN-GUID is nullable (parse-generic-message returns NIL guid on error); IN-SN is non-null integer because
   parse-generic-message always returns integer for the SN position (0 on error, never NIL) — the asymmetry
   is intentional and mirrors the VALUES return type of parse-generic-message."
  (let ((next-octets nil) (do-cm nil) (resend nil))
    (dds.pal:with-lock ((auth-manager-state-lock ms))
      (block in-lock
        (when (eq (auth-remote-state ar) :rejected)
          (return-from in-lock nil))
        (cond
          ;; replier, first message: begin the reply
          ((and (eq (auth-remote-role ar) :replier) (null (auth-remote-handle ar)))
           (let ((suite (auth-remote-suite ar)))
             (when suite
               (multiple-value-bind (reply-octets reply-handle)
                   (dds.security:begin-handshake-reply
                    (auth-manager-state-identity ms) (auth-manager-state-identity ms)
                    token-octets suite
                    ;; §9.3.2.1 c.perm: our signed Permissions credential so the requester's validate_remote_permissions accepts us (T6)
                    (auth-manager-state-perm-credential ms)
                    ;; §8.7.2.5: bind the request's challenge1 to the requester's LATCHED future_challenge WHEN they
                    ;; match; a mismatch (poisoned/forged auth_request) DOWNGRADES to Sign-only, never a hard-REJECT
                    ;; (%am-effective-expected-challenge); NIL when no auth_request (§8.7.2.3-optional). challenge2 = OUR nonce.
                    (%am-effective-expected-challenge (auth-remote-remote-future-challenge ar)
                                                      token-octets dds.security::+prop-challenge1+ prefix)
                    (auth-remote-future-challenge ar))
                 (cond
                   ((and reply-octets reply-handle)
                    (setf (auth-remote-handle ar) reply-handle
                          (auth-remote-state ar) :handshaking
                          (auth-remote-last-sent ar) reply-octets
                          next-octets reply-octets)
                    (%am-log prefix "replier: sent HandshakeReply"))
                   (t (setf (auth-remote-state ar) :rejected)
                      (%am-log prefix "replier: begin-handshake-reply failed -> reject")))))))
          ;; replier, already replied: a RETRANSMITTED request -> re-send the stored reply (best-effort
          ;; PSM retransmit). Never feed a Req into %process-final — it expects a Final and would reject.
          ((and (eq (auth-remote-role ar) :replier)
                (eq (auth-remote-state ar) :handshaking)
                (auth-remote-handle ar)
                (auth-remote-last-sent ar)
                (%am-token-is-request-p token-octets))
           (setf resend (auth-remote-last-sent ar)))
          ;; in-flight handshake: drive the next step
          ((auth-remote-handle ar)
           (let ((tclass (%am-token-class token-octets)))
             ;; requester still awaiting the Reply: DROP any non-Reply token (a stray/duplicate/echoed
             ;; Request or a misrouted message) WITHOUT driving the state machine. Feeding it to
             ;; %process-reply would reject on the class_id mismatch and latch :rejected, which then
             ;; IGNORES the genuine HandshakeReply when it arrives (§8.7.2.4: the requester processes
             ;; ONLY the HandshakeReply). This is the requester-side analogue of the replier's
             ;; duplicate-request guard above; it never false-rejects on an out-of-role token.
             (if (and (eq (auth-remote-role ar) :requester)
                      (eq (dds.security:handshake-handle-state (auth-remote-handle ar)) :awaiting-reply)
                      (not (dds.security::%class-id-role-match-p tclass dds.security::+handshake-reply-class-id+)))
                 (%am-log prefix (format nil "requester: dropped out-of-role token (class=~a; awaiting HandshakeReply)"
                                         tclass))
                 (multiple-value-bind (out status)
                     (dds.security:process-handshake (auth-remote-handle ar) token-octets
                                                     ;; §8.7.2.5: the requester binds the reply's challenge2 to the
                                                     ;; replier's LATCHED future_challenge WHEN they match; a mismatch
                                                     ;; DOWNGRADES to Sign-only (not a hard-REJECT). NIL for the replier's
                                                     ;; :awaiting-final step (the API ignores expected-challenge2 there).
                                                     (if (eq (auth-remote-role ar) :requester)
                                                         (%am-effective-expected-challenge
                                                          (auth-remote-remote-future-challenge ar)
                                                          token-octets dds.security::+prop-challenge2+ prefix)
                                                         nil))
                   (case status
                     (:rejected
                      (setf (auth-remote-state ar) :rejected)
                      (%am-log prefix "handshake step rejected"))
                     ((:continue :authenticated)
                      (when out (setf next-octets out (auth-remote-last-sent ar) out))
                      ;; :continue with our state :authenticated (requester after Reply) OR :authenticated
                      (when (eq (dds.security:handshake-handle-state (auth-remote-handle ar)) :authenticated)
                        ;; authorize on the VALIDATED handshake-cert subject (unforgeable) + §8.7.2.5 token-vs-cert binding
                        (if (%am-bind-and-check-subject ar prefix)
                            (when (%am-mark-authenticated ar) (setf do-cm t))
                            (setf (auth-remote-state ar) :rejected next-octets nil))))))))))))
    ;; send the produced handshake token OUTSIDE the manager lock; echo the incoming message_identity
    ;; (IN-GUID . IN-SN) as related_message_identity so a replier peer correlates our Final to its Reply
    (when next-octets
      (%am-send-handshake ms node (dds.disc:disc-node-guid-prefix node) prefix next-octets in-guid in-sn))
    ;; retransmit the stored reply for a duplicate request, OUTSIDE the lock (best-effort PSM)
    (when resend
      (%am-send-handshake ms node (dds.disc:disc-node-guid-prefix node) prefix resend in-guid in-sn))
    ;; drive the §8.5.2 crypto-token exchange over reliable PVMS OUTSIDE the lock (T8): derive+install the
    ;; §9.5.3.1 bootstrap KM, register local crypto, send our Participant + builtin/user EntityCrypto tokens.
    (when do-cm
      (%am-log prefix "authenticated; driving crypto-token exchange over PVMS")
      (cm-on-authenticated (auth-manager-state-crypto-manager ms) node prefix))
    t))

(defun* %am-store-remote-future-challenge (ms node src-prefix dh-list)
    (function (auth-manager-state dds.disc:disc-node (simple-array (unsigned-byte 8) (12)) list) t)
  "Parse a received §8.7.2.3 AuthRequestMessageToken (the first DataHolder of DH-LIST) and store the peer's
   future_challenge nonce on its AUTH-REMOTE (REMOTE-FUTURE-CHALLENGE) so our replier binds the request's
   challenge1 to it and our requester binds the reply's challenge2 to it (§8.7.2.5). Version-tolerant class_id
   match (RTI emits 1.2, ours 1.0). Accepts only a 32-octet future_challenge value. FAIL-CLOSED: a malformed
   token, a wrong class, a missing/short nonce, or an unknown remote is a SILENT no-op (never crashes the
   receiver thread, never installs anything). The nonce is LATCHED first-write-wins per remote: the FIRST
   well-formed auth_request stores it; a later one carrying the SAME nonce is a no-op (legit retransmit); a
   later one carrying a DIFFERENT nonce is IGNORED (the PSM channel is unauthenticated — a forged auth_request
   must not overwrite an already-latched nonce, closing the forged-LATER-overwrite false-REJECT DoS variant).
   Absence just leaves REMOTE-FUTURE-CHALLENGE NIL, so the §8.7.2.5 binding checks SKIP (spec-optional); a
   poisoned (forged-FIRST) nonce never false-ACCEPTS — a mismatch DOWNGRADES to Sign-only at the bind site
   (%am-effective-expected-challenge), and the §8.7 cert-chain + Sign gate still decides."
  (when dh-list
    (let ((tok (dds.security:dataholder->handshake-token (car dh-list))))
      (when (and tok
                 (dds.security::%class-id-role-match-p
                  (dds.security::handshake-token-class-id tok) dds.security:+auth-request-class-id+))
        (let ((nonce (dds.security::%token-get tok dds.security:+prop-future-challenge+)))
          (when (and nonce (= (length nonce) 32))
            (dds.pal:with-lock ((auth-manager-state-lock ms))
              (let ((ar (gethash src-prefix (dds.disc:disc-node-auth-state node))))
                (when ar
                  (let ((existing (auth-remote-remote-future-challenge ar)))
                    (cond
                      ((null existing)
                       ;; first-write-wins latch: the first well-formed auth_request stores the nonce
                       (let ((stored (make-array 32 :element-type '(unsigned-byte 8))))
                         (replace stored nonce :end2 32)
                         (setf (auth-remote-remote-future-challenge ar) stored))
                       (%am-log src-prefix "peer AuthRequestMessageToken: future_challenge latched"))
                      ((equalp existing nonce)
                       ;; legit retransmit (a peer's nonce is stable) -> no-op
                       (%am-log src-prefix "peer AuthRequestMessageToken: retransmit (future_challenge unchanged)"))
                      (t
                       ;; a DIFFERENT nonce after latch = a possible forged auth_request on the unauthenticated PSM -> IGNORE
                       (%am-log src-prefix "peer AuthRequestMessageToken: IGNORED conflicting future_challenge (already latched; possible forged auth_request)"))))))))))))
  t)

(defun* %am-on-stateless-message (p node src-prefix envelope-octets)
    (function (domain-participant dds.disc:disc-node (simple-array (unsigned-byte 8) (12))
               (simple-array (unsigned-byte 8) (*)))
              t)
  "ON-STATELESS-MESSAGE hook (receiver thread, OUTSIDE the node lock, RAW envelope octets from
   dds-disc per Decision 1): PARSE-GENERIC-MESSAGE, read message_class_id, and DISPATCH the §8.7
   AUTHENTICATION classes only —
     +AUTH-REQUEST-MESSAGE-CLASS-ID+ ('dds.sec.auth_request') -> store the peer's §8.7.2.3 future_challenge
       (%AM-STORE-REMOTE-FUTURE-CHALLENGE); no state-machine drive.
     +AUTH-MESSAGE-CLASS-ID+ ('dds.sec.auth')          -> handshake path
       (DATAHOLDER->HANDSHAKE-TOKEN -> %SERIALIZE-TOKEN -> %AM-DRIVE-HANDSHAKE).
   The §8.5.2 CRYPTO-TOKEN exchange NO LONGER rides PSM (T8): it moved to the reliable PVMS endpoint
   (%am-on-volatile-secure -> cm-on-crypto-token), so any non-handshake class here is dropped (the prior
   best-effort-PSM +gm-participant-crypto-tokens+ path is RETIRED). The :authenticated->:keyed promotion is
   now mediated by the crypto-manager (%cm-try-promote), not here.
   FAIL-CLOSED throughout (block/return-from; no handler-case in nested mvb — Clasp): any
   malformed/unknown/unsolicited message is silently dropped; the receiver thread MUST NOT crash."
  (block %am-on-psm
    (let ((ms (dp-auth-state p)))
      (when (null ms) (return-from %am-on-psm t))
      ;; parse the envelope (fail-closed: NIL source-guid on any malformed input, §7.4.4)
      (multiple-value-bind (src-guid sn rel-guid rel-sn dest-part dest-ep src-ep class-id dh-list)
          (dds.security:parse-generic-message envelope-octets)
        (declare (ignore rel-guid rel-sn dest-part dest-ep src-ep))
        (when (null class-id) (return-from %am-on-psm t))
        ;; §8.7.2.3 AuthRequestMessageToken ('dds.sec.auth_request'): store the peer's future_challenge and
        ;; return (it drives no state machine — it only supplies the nonce the handshake binds to, §8.7.2.5).
        (when (string= class-id dds.security:+auth-request-message-class-id+)
          (%am-store-remote-future-challenge ms node src-prefix dh-list)
          (return-from %am-on-psm t))
        ;; only the §8.7 handshake class rides PSM otherwise (crypto tokens moved to PVMS, T8)
        (unless (string= class-id dds.security:+auth-message-class-id+) (return-from %am-on-psm t))
        ;; locate the per-remote record (must already exist from discovery)
        (let ((ar (dds.pal:with-lock ((auth-manager-state-lock ms))
                    (gethash src-prefix (dds.disc:disc-node-auth-state node)))))
          (when (null ar) (return-from %am-on-psm t))
          (when (null dh-list) (return-from %am-on-psm t))
          (let ((tok (dds.security:dataholder->handshake-token (car dh-list))))
            (when (null tok) (return-from %am-on-psm t))
            (%am-drive-handshake ms node src-prefix ar (dds.security::%serialize-token tok) src-guid sn))))))
  t)

;; T8: the KEYX %am-install-crypto-resolver (CRYPTO-KEYS backed by WRITER-KM-TABLE encode + per-remote
;; AUTH-REMOTE REMOTE-KM decode) is RETIRED. The user-data encode/decode resolver is now the crypto-manager's
;; cm-decode-keys (§8.5 EntityCrypto registries), installed by %cm-try-promote on the :authenticated->:keyed
;; promotion — the per-writer/entity KeyMaterial flows over reliable PVMS, not best-effort PSM (design §6.4/§7.2).

;;; --- the strict auth-gate (§7.3, consulted at endpoint match, OUTSIDE the node lock) ---

(defun* %participant-auth-gate (p node remote local)
    (function (domain-participant dds.disc:disc-node
               dds.rtps.discovery:endpoint-data dds.rtps.discovery:endpoint-data)
              (member :compatible :incompatible :pending))
  "The DDS-Security §7.3 strict authentication gate installed on P's disc-node AUTH-GATE hook
   (consulted as the SECOND sequential gate after the type-gate returns :compatible, in
   %MATCH-REMOTE-ENDPOINT; both directions, receiver thread, OUTSIDE the node lock). Verdict
   ladder (Decision: strict authenticated-only, allow_unauthenticated = FALSE):
     local NOT security-enabled (no DP-AUTH-STATE)        -> :compatible (security off, unchanged);
     remote :keyed (authenticated + keys installed)        -> :compatible;
     remote :authenticated, keying required (protection)   -> :pending (park; resumed on :keyed);
     remote :authenticated, keying NOT required (all-NONE governance) -> :compatible (§8.4.2.9 auth+permissions);
     remote :handshaking (in flight)                       -> :pending (park; resumed on :authenticated/:keyed);
     remote has NO AUTH-REMOTE (plain peer, no IdentityToken) OR :rejected / :none
                                                           -> :incompatible (strict refuse).
   LOCAL is unused (the verdict is per remote participant); REMOTE supplies the prefix key."
  (let ((ms (dp-auth-state p)))
    (declare (ignore local))
    (block gate
      (when (null ms) (return-from gate :compatible))   ; security OFF: unchanged plain path
      (let* ((prefix (%remote-endpoint-prefix remote))
             (ar (dds.pal:with-lock ((auth-manager-state-lock ms))
                   (gethash prefix (dds.disc:disc-node-auth-state node)))))
        (when (null ar) (return-from gate :incompatible))   ; plain peer: strict refuse
        (let ((state (dds.pal:with-lock ((auth-manager-state-lock ms))
                       (auth-remote-state ar))))
          (case state
            (:keyed :compatible)
            ;; §7.3/§8.5: a keying-mandating governance parks :authenticated until :keyed (crypto established);
            ;; an all-NONE governance (disc-node-crypto-keying-required-p NIL) matches at :authenticated on §8.7
            ;; auth + §8.4 permissions (§8.4.2.9 — keying is a precondition only for PROTECTED endpoints, and a
            ;; conformant peer such as RTI Connext sends no crypto token at GOV=none). NEVER weakens: the state
            ;; must still be :authenticated (§8.7 PKI-DH cert-chain + Sign verified); the §8.4 permissions-gate runs next.
            (:authenticated (if (dds.disc:disc-node-crypto-keying-required-p node) :pending :compatible))
            (:handshaking :pending)
            (t :incompatible)))))))   ; :rejected / :none -> strict refuse

;;; --- installer (mirror %INSTALL-TYPE-GATE) ---

(defun* %install-auth-manager (p identity-handle &optional perm-octets)
    (function (domain-participant dds.security:identity-handle
               &optional (or null (simple-array (unsigned-byte 8) (*))))
              domain-participant)
  "Create P's DDS-Security §8.7 auth-manager state (holding IDENTITY-HANDLE — the local identity
   with the private key, and PERM-OCTETS — the configured signed Permissions credential emitted as the
   §9.3.2.1 handshake c.perm; NIL/absent = empty c.perm) and install its hooks on P's disc-node: ON-PARTICIPANT-DISCOVERED
   (the requester trigger / replier pre-stash), ON-STATELESS-MESSAGE (the raw-envelope §8.7 handshake
   dispatcher), and AUTH-GATE (the strict §7.3 endpoint-match verdict); plus the §8.5 crypto-manager +
   reliable PVMS endpoint with the crypto-token receiver hook (%install-crypto-manager, T8). Installed
   ONLY for a security-enabled participant (an identity configured); a participant with no
   identity keeps DP-AUTH-STATE NIL and the gate stays :compatible (byte-identical plain path).
   The disc-node must already advertise this identity's IdentityToken in SPDP. Returns P."
  (let ((ms (%make-auth-manager-state
             :identity identity-handle
             :perm-credential (or perm-octets (make-array 0 :element-type '(unsigned-byte 8))))))
    (setf (dp-auth-state p) ms)
    (let ((node (dp-node p)))
      (setf (dds.disc:disc-node-on-participant-discovered node)
            (lambda (n prefix spdp) (%am-on-participant-discovered p n prefix spdp)))
      (setf (dds.disc:disc-node-on-stateless-message node)
            (lambda (n src-prefix envelope) (%am-on-stateless-message p n src-prefix envelope)))
      (setf (dds.disc:disc-node-auth-gate node)
            (lambda (n remote local) (%participant-auth-gate p n remote local)))
      ;; T8: §8.5 crypto-manager + reliable PVMS endpoint (crypto-token exchange carrier) + receiver hook
      (%install-crypto-manager p ms node)))
  p)
