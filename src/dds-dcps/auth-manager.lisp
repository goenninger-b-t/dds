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
   Typed T to avoid an auth-manager-state<->crypto-manager defstruct cycle (crypto-manager loads after)."
  (identity (error "auth-manager-state: :identity is required (the local identity-handle)")
            :type dds.security:identity-handle)
  (lock (dds.pal:make-lock "auth-manager") :type t)
  (crypto-manager nil :type t))

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
   REMOTE-TOKEN: the remote IdentityToken octets (stashed at discovery so the replier can pick
                 the suite when the request arrives on the wire). SELF-ASSERTED — never the §8.4
                 authorization identity (a peer can claim any cert-sn here).
   VALIDATED-SUBJECT: the remote's VALIDATED handshake-cert subject name (x509-subject-name of the
                 §8.7 chain-verified peer cert, surfaced from the handshake-handle at :authenticated;
                 §8.7.2.5). The §8.4 permissions-gate authorizes on THIS — unforgeable, since the remote
                 proved possession of the private key for the cert this subject is read from. NIL until
                 :authenticated.
   SUITE: the §9.3.2 auth-suite selected for this pair.
   (The KEYX KX-KEY / REMOTE-KM / LOCAL-KM / LOCAL-SENT-P / PENDING-CT slots are RETIRED in T8: the §9.5.2
   KeyMaterial exchange moved off best-effort PSM onto the crypto-manager + reliable PVMS, design §6.4.)"
  (state        :none :type (member :none :handshaking :authenticated :keyed :rejected))
  (handle       nil :type (or null dds.security:handshake-handle))
  (role         :requester :type (member :requester :replier))
  (remote-token nil :type (or null (simple-array (unsigned-byte 8) (*))))
  (validated-subject nil :type (or null string))
  (suite        nil :type (or null dds.security:auth-suite)))

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

(defun* %am-send-handshake (node src-prefix dest-prefix token-octets)
    (function (dds.disc:disc-node (simple-array (unsigned-byte 8) (12))
               (simple-array (unsigned-byte 8) (12)) (simple-array (unsigned-byte 8) (*))) t)
  "Wrap a handshake-token (TOKEN-OCTETS = the internal tagged format the handshake API emits)
   as a §7.4.4 ParticipantGenericMessage with message_class_id +AUTH-MESSAGE-CLASS-ID+ and send
   it over the §7.4.3 PSM stateless transport to DEST-PREFIX. The token is parsed back to a
   handshake-token then re-serialized to a §9.3.4 CDR-LE DataHolder (the wire format) — the
   2b-i bridge between the handshake's internal format and the DataHolder wire format."
  (let ((tok (dds.security::%parse-token token-octets)))
    (when tok
      (let* ((dh       (dds.security:handshake-token->dataholder tok))
             (src-guid (%guid-from-prefix src-prefix dds.rtps.message:+entityid-participant+))
             (dst-guid (%guid-from-prefix dest-prefix dds.rtps.message:+entityid-participant+))
             (zero     (make-array 16 :element-type '(unsigned-byte 8) :initial-element 0))
             (env      (dds.security:make-generic-message
                        :source-guid           src-guid
                        :sequence-number       0
                        :related-guid          zero
                        :related-sn            0
                        :dest-participant-guid dst-guid
                        :dest-endpoint-guid    zero
                        :source-endpoint-guid  src-guid
                        :message-class-id      dds.security:+auth-message-class-id+
                        :dataholders           (list dh))))
        (dds.disc:%send-stateless-message node dest-prefix env))))
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
        (let ((ar (%make-auth-remote :remote-token (copy-seq token))))
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
          (req-octets nil) (req-handle nil) (do-send nil))
      (when (null ar) (return-from %am-on-participant-discovered t))
      (dds.pal:with-lock ((auth-manager-state-lock ms))
        (when (and (eq (auth-remote-state ar) :none)
                   (eq (auth-remote-role ar) :requester)
                   (auth-remote-suite ar)
                   (null (auth-remote-handle ar)))
          (multiple-value-setq (req-octets req-handle)
            (dds.security:begin-handshake-request
             (auth-manager-state-identity ms) (auth-manager-state-identity ms)
             (auth-remote-suite ar)))
          (when req-handle
            (setf (auth-remote-handle ar) req-handle
                  (auth-remote-state ar) :handshaking
                  do-send t))))
      ;; send OUTSIDE the manager lock (PSM send takes the node lock internally)
      (when do-send
        (%am-log prefix "requester: sent HandshakeRequest")
        (%am-send-handshake node (dds.disc:disc-node-guid-prefix node) prefix req-octets))))
  t)

;;; --- stateless-message hook: parse + dispatch by message_class_id ---

(defun* %am-drive-handshake (ms node prefix ar token-octets)
    (function (auth-manager-state dds.disc:disc-node (simple-array (unsigned-byte 8) (12))
               auth-remote (simple-array (unsigned-byte 8) (*)))
              t)
  "Drive the §8.7.2.4 handshake one step for AR given the incoming handshake token (internal
   tagged octets). Under the manager lock: a :replier with no in-flight handle does
   BEGIN-HANDSHAKE-REPLY (first request); otherwise PROCESS-HANDSHAKE drives the next step; on
   reaching :authenticated AR is marked :authenticated (%AM-MARK-AUTHENTICATED). The produced next
   handshake token is sent over PSM, and the §8.5 crypto-token exchange (cm-on-authenticated: PVMS
   bootstrap-KM derive + token send over reliable PVMS) is driven, BOTH OUTSIDE the lock (never hold the
   lock across a network send — the type-gate discipline). Fail-closed: a nil/failed handshake step records
   :rejected and installs no keys. Returns T (hook ignores it)."
  (let ((next-octets nil) (do-cm nil))
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
                    token-octets suite)
                 (cond
                   ((and reply-octets reply-handle)
                    (setf (auth-remote-handle ar) reply-handle
                          (auth-remote-state ar) :handshaking
                          next-octets reply-octets)
                    (%am-log prefix "replier: sent HandshakeReply"))
                   (t (setf (auth-remote-state ar) :rejected)
                      (%am-log prefix "replier: begin-handshake-reply failed -> reject")))))))
          ;; in-flight handshake: drive the next step
          ((auth-remote-handle ar)
           (multiple-value-bind (out status)
               (dds.security:process-handshake (auth-remote-handle ar) token-octets)
             (case status
               (:rejected
                (setf (auth-remote-state ar) :rejected)
                (%am-log prefix "handshake step rejected"))
               ((:continue :authenticated)
                (when out (setf next-octets out))
                ;; :continue with our state :authenticated (requester after Reply) OR :authenticated
                (when (eq (dds.security:handshake-handle-state (auth-remote-handle ar)) :authenticated)
                  ;; authorize on the VALIDATED handshake-cert subject (unforgeable) + §8.7.2.5 token-vs-cert binding
                  (if (%am-bind-and-check-subject ar prefix)
                      (when (%am-mark-authenticated ar) (setf do-cm t))
                      (setf (auth-remote-state ar) :rejected next-octets nil))))))))))
    ;; send the produced handshake token OUTSIDE the manager lock
    (when next-octets
      (%am-send-handshake node (dds.disc:disc-node-guid-prefix node) prefix next-octets))
    ;; drive the §8.5.2 crypto-token exchange over reliable PVMS OUTSIDE the lock (T8): derive+install the
    ;; §9.5.3.1 bootstrap KM, register local crypto, send our Participant + builtin/user EntityCrypto tokens.
    (when do-cm
      (%am-log prefix "authenticated; driving crypto-token exchange over PVMS")
      (cm-on-authenticated (auth-manager-state-crypto-manager ms) node prefix))
    t))

(defun* %am-on-stateless-message (p node src-prefix envelope-octets)
    (function (domain-participant dds.disc:disc-node (simple-array (unsigned-byte 8) (12))
               (simple-array (unsigned-byte 8) (*)))
              t)
  "ON-STATELESS-MESSAGE hook (receiver thread, OUTSIDE the node lock, RAW envelope octets from
   dds-disc per Decision 1): PARSE-GENERIC-MESSAGE, read message_class_id, and DISPATCH the §8.7
   AUTHENTICATION handshake only —
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
        (declare (ignore src-guid sn rel-guid rel-sn dest-part dest-ep src-ep))
        (when (null class-id) (return-from %am-on-psm t))
        ;; only the §8.7 handshake class rides PSM now (crypto tokens moved to PVMS, T8)
        (unless (string= class-id dds.security:+auth-message-class-id+) (return-from %am-on-psm t))
        ;; locate the per-remote record (must already exist from discovery)
        (let ((ar (dds.pal:with-lock ((auth-manager-state-lock ms))
                    (gethash src-prefix (dds.disc:disc-node-auth-state node)))))
          (when (null ar) (return-from %am-on-psm t))
          (when (null dh-list) (return-from %am-on-psm t))
          (let ((tok (dds.security:dataholder->handshake-token (car dh-list))))
            (when (null tok) (return-from %am-on-psm t))
            (%am-drive-handshake ms node src-prefix ar (dds.security::%serialize-token tok)))))))
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
     remote :handshaking / :authenticated (in flight)      -> :pending (park; resumed on :keyed);
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
            ((:handshaking :authenticated) :pending)
            (t :incompatible)))))))   ; :rejected / :none -> strict refuse

;;; --- installer (mirror %INSTALL-TYPE-GATE) ---

(defun* %install-auth-manager (p identity-handle)
    (function (domain-participant dds.security:identity-handle) domain-participant)
  "Create P's DDS-Security §8.7 auth-manager state (holding IDENTITY-HANDLE — the local identity
   with the private key) and install its hooks on P's disc-node: ON-PARTICIPANT-DISCOVERED
   (the requester trigger / replier pre-stash), ON-STATELESS-MESSAGE (the raw-envelope §8.7 handshake
   dispatcher), and AUTH-GATE (the strict §7.3 endpoint-match verdict); plus the §8.5 crypto-manager +
   reliable PVMS endpoint with the crypto-token receiver hook (%install-crypto-manager, T8). Installed
   ONLY for a security-enabled participant (an identity configured); a participant with no
   identity keeps DP-AUTH-STATE NIL and the gate stays :compatible (byte-identical plain path).
   The disc-node must already advertise this identity's IdentityToken in SPDP. Returns P."
  (let ((ms (%make-auth-manager-state :identity identity-handle)))
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
