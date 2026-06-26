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
   WRITER-KM-TABLE: per-local-writer KeyMaterial table (16-octet writer GUID -> KEY-MATERIAL).
   §9.5 requires ONE KeyMaterial per writer shared across ALL authenticated remotes; this table
   is the get-or-create source so every remote receives the identical key for a given writer
   GUID, and the encode resolver can return a stable, single value keyed by writer GUID."
  (identity (error "auth-manager-state: :identity is required (the local identity-handle)")
            :type dds.security:identity-handle)
  (lock (dds.pal:make-lock "auth-manager") :type t)
  (writer-km-table (make-hash-table :test 'equalp) :type hash-table))

;;; --- per-remote auth/key state (DISC-NODE-AUTH-STATE: 12-octet prefix -> AUTH-REMOTE) ---

(defstruct* (auth-remote (:constructor %make-auth-remote))
  "Per-remote DDS-Security authentication + key-exchange state, keyed by the remote's
   12-octet GUID prefix in DISC-NODE-AUTH-STATE (the manager owns this table). The state
   machine (§8.7 / §9.5):
     :none          discovered + validated; role/suite/remote-token recorded, no handshake yet.
     :handshaking   an in-flight §8.7.2.4 handshake (HANDLE non-NIL).
     :authenticated handshake complete (SharedSecret); KX-KEY derived + our CryptoTokens sent;
                    the remote's KeyMaterial is NOT yet installed.
     :keyed         authenticated AND the remote writer KeyMaterial installed (REMOTE-KM non-NIL)
                    -> endpoint matching is resumed (DDS.DISC:RESUME-PARKED-MATCHES).
     :rejected      terminal refusal (malformed/untrusted remote, unsupported algo, bad handshake).
   HANDLE: the in-flight handshake-handle (foreign DH/cert state; freed on teardown).
   KX-KEY: the derived §9.5.3 KxKey (dds.pal foreign buffer; freed on teardown).
   REMOTE-KM: the installed remote writer KeyMaterial (§9.5.2; NIL until a CryptoToken decrypts).
   ROLE: :requester (local GUID < remote) or :replier (§8.7.2.4 ordering).
   REMOTE-TOKEN: the remote IdentityToken octets (stashed at discovery so the replier can pick
                 the suite when the request arrives on the wire).
   SUITE: the §9.3.2 auth-suite selected for this pair.
   PENDING-CT: CryptoToken envelopes received before KX-KEY existed (best-effort PSM has no
               resend) — drained once KX-KEY is derived. LOCAL-SENT-P dedupes our own send."
  (state        :none :type (member :none :handshaking :authenticated :keyed :rejected))
  (handle       nil :type (or null dds.security:handshake-handle))
  (kx-key       nil :type (or null dds.security:kx-key-handle))
  (remote-km    nil :type (or null dds.security:key-material))
  (role         :requester :type (member :requester :replier))
  (remote-token nil :type (or null (simple-array (unsigned-byte 8) (*))))
  (suite        nil :type (or null dds.security:auth-suite))
  (pending-ct   '() :type list)
  (local-km     nil :type (or null dds.security:key-material))
  (local-sent-p nil :type t))

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

(defun* %local-writer-guid (node)
    (function (dds.disc:disc-node) (simple-array (unsigned-byte 8) (16)))
  "The local participant's 16-octet user-data writer GUID (prefix + the node's
   user-writer EntityId, RTPS 2.5 §9.3.1.2) — the §9.5.2 KeyMaterial sender_key_id source for
   the CryptoTokens we send (ties the key material to the writer the participant advertises)."
  (%guid-from-prefix (dds.disc:disc-node-guid-prefix node)
                     (dds.disc:disc-node-user-writer-id node)))

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

(defun* %am-send-crypto-tokens (node dest-prefix km kx-key)
    (function (dds.disc:disc-node (simple-array (unsigned-byte 8) (12))
               dds.security:key-material dds.security:kx-key-handle) t)
  "Build a §7.4.4 CryptoToken ParticipantGenericMessage carrying KM (the local writer's §9.5.2
   KeyMaterial), KxKey-encrypted under KX-KEY (keys never in clear, §9.5.3 intent), and send it
   over the PSM stateless transport to DEST-PREFIX (message_class_id
   'dds.sec.participant_crypto_tokens', T3)."
  (dds.disc:%send-stateless-message
   node dest-prefix
   (dds.security:make-crypto-token-message
    km (dds.security:kx-key-bytes kx-key)
    (%local-writer-guid node)
    (%guid-from-prefix dest-prefix dds.rtps.message:+entityid-participant+)))
  t)

;;; --- key-exchange internals (CALLER HOLDS the manager lock) ---

(defun* %am-get-or-create-writer-km (ms writer-guid)
    (function (auth-manager-state (simple-array (unsigned-byte 8) (16)))
              dds.security:key-material)
  "Get-or-create the single §9.5.2 KeyMaterial for WRITER-GUID from MS's WRITER-KM-TABLE.
   If the table already has an entry for WRITER-GUID return it unchanged (idempotent);
   otherwise call GENERATE-WRITER-KEY-MATERIAL once and store + return the result.
   CALLER HOLDS the manager lock (the table is under MS's LOCK). The EQUALP hash-table key
   ensures 16-octet array identity-by-value, not pointer identity (RTPS 2.5 §9.3.1.2)."
  (let ((existing (gethash writer-guid (auth-manager-state-writer-km-table ms))))
    (or existing
        (let ((km (dds.security:generate-writer-key-material writer-guid)))
          (setf (gethash (copy-seq writer-guid)
                         (auth-manager-state-writer-km-table ms))
                km)
          km))))

(defun* %am-install-crypto-token (ar env kx-key)
    (function (auth-remote (simple-array (unsigned-byte 8) (*)) dds.security:kx-key-handle) t)
  "Parse + authenticate one CryptoToken envelope ENV under KX-KEY and, on success, install the
   remote writer KeyMaterial into AR (§9.5.2). Fail-closed: PARSE-CRYPTO-TOKEN-MESSAGE returns
   NIL on any malformed/truncated/forged/wrong-class input (bad KxKey, tamper) -> no install
   (the remote stays unmatched; no plaintext fallback). CALLER HOLDS the manager lock."
  (let ((km (dds.security:parse-crypto-token-message env (dds.security:kx-key-bytes kx-key))))
    (when km
      (setf (auth-remote-remote-km ar) km)))
  t)

(defun* %am-on-authenticated (ms node ar)
    (function (auth-manager-state dds.disc:disc-node auth-remote) t)
  "In-lock key-exchange work on reaching :authenticated for AR (CALLER HOLDS the manager lock;
   no network I/O here — the PSM send is done by the caller OUTSIDE the lock, matching the
   type-gate's never-hold-the-lock-across-a-send discipline). Derive the §9.5.3 KxKey from the
   handshake's SharedSecret + challenges (idempotent — once). Get-or-create the single §9.5.2
   writer KeyMaterial for the local writer GUID from MS's WRITER-KM-TABLE (%AM-GET-OR-CREATE-WRITER-KM)
   and stash it in AR's LOCAL-KM (§9.5: ONE KeyMaterial per writer, identical for every remote).
   Drain any CryptoTokens that arrived before the KxKey existed. Returns T iff the caller must
   send the stashed CryptoTokens. Fail-closed: a missing SharedSecret leaves AR with no key
   material (it stays unmatched)."
  (let ((handle (auth-remote-handle ar)))
    (unless (and handle (eq (dds.security:handshake-handle-state handle) :authenticated))
      (return-from %am-on-authenticated nil))
    ;; derive the KxKey once (symmetric: both sides get the same key from the same SharedSecret+challenges)
    (unless (auth-remote-kx-key ar)
      (let ((ss (dds.security:handshake-shared-secret handle)))
        (when ss
          (setf (auth-remote-kx-key ar)
                (dds.security:derive-kx-key
                 (dds.security:shared-secret-bytes ss)
                 (dds.security:shared-secret-handle-challenge1-bytes ss)
                 (dds.security:shared-secret-handle-challenge2-bytes ss))))))
    (let ((kx-key (auth-remote-kx-key ar)) (want-send nil))
      (when kx-key
        ;; get-or-create the single per-writer KeyMaterial (§9.5: same key sent to every remote)
        (when (not (auth-remote-local-sent-p ar))
          (let ((km (%am-get-or-create-writer-km ms (%local-writer-guid node))))
            (setf (auth-remote-local-km ar) km
                  want-send t)))
        ;; drain any CryptoTokens that arrived before the KxKey was ready (PSM best-effort, no resend)
        (let ((pending (auth-remote-pending-ct ar)))
          (setf (auth-remote-pending-ct ar) '())
          (dolist (env (nreverse pending))
            (%am-install-crypto-token ar env kx-key))))
      (when (member (auth-remote-state ar) '(:none :handshaking))
        (setf (auth-remote-state ar) :authenticated))
      want-send)))

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
   reaching :authenticated the in-lock key-exchange work runs (%AM-ON-AUTHENTICATED). Both the
   produced next handshake token AND the stashed CryptoTokens are sent over PSM OUTSIDE the lock
   (never hold the lock across a network send — the type-gate discipline). Fail-closed: a
   nil/failed handshake step records :rejected and installs no keys. Returns T (hook ignores it)."
  (let ((next-octets nil) (send-ct nil) (km nil) (kx-key nil))
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
                  (when (%am-on-authenticated ms node ar)
                    (setf send-ct t km (auth-remote-local-km ar)
                          kx-key (auth-remote-kx-key ar)))))))))))
    ;; send the produced token + the CryptoTokens OUTSIDE the manager lock
    (when next-octets
      (%am-send-handshake node (dds.disc:disc-node-guid-prefix node) prefix next-octets))
    (when (and send-ct km kx-key)
      (%am-send-crypto-tokens node prefix km kx-key)
      (dds.pal:with-lock ((auth-manager-state-lock ms))
        (setf (auth-remote-local-sent-p ar) t))
      (%am-log prefix "authenticated; KxKey derived; sent writer CryptoTokens"))
    t))

(defun* %am-on-stateless-message (p node src-prefix envelope-octets)
    (function (domain-participant dds.disc:disc-node (simple-array (unsigned-byte 8) (12))
               (simple-array (unsigned-byte 8) (*)))
              t)
  "ON-STATELESS-MESSAGE hook (receiver thread, OUTSIDE the node lock, RAW envelope octets from
   dds-disc per Decision 1): PARSE-GENERIC-MESSAGE, read message_class_id, and DISPATCH —
     +AUTH-MESSAGE-CLASS-ID+ ('dds.sec.auth')          -> handshake path
       (DATAHOLDER->HANDSHAKE-TOKEN -> %SERIALIZE-TOKEN -> %AM-DRIVE-HANDSHAKE);
     +GM-PARTICIPANT-CRYPTO-TOKENS+ ('dds.sec.participant_crypto_tokens') -> key-material path
       (install now if the KxKey exists, else buffer until %AM-ON-AUTHENTICATED drains it).
   When BOTH authenticated AND the remote KeyMaterial is installed -> :keyed -> resume matches.
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
        ;; locate the per-remote record (must already exist from discovery)
        (let ((ar (dds.pal:with-lock ((auth-manager-state-lock ms))
                    (gethash src-prefix (dds.disc:disc-node-auth-state node)))))
          (when (null ar) (return-from %am-on-psm t))
          (cond
            ;; --- handshake path ---
            ((string= class-id dds.security:+auth-message-class-id+)
             (when (null dh-list) (return-from %am-on-psm t))
             (let ((tok (dds.security:dataholder->handshake-token (car dh-list))))
               (when (null tok) (return-from %am-on-psm t))
               (%am-drive-handshake ms node src-prefix ar (dds.security::%serialize-token tok))))
            ;; --- crypto-token (key-material) path ---
            ((string= class-id dds.security:+gm-participant-crypto-tokens+)
             (dds.pal:with-lock ((auth-manager-state-lock ms))
               (let ((kx-key (auth-remote-kx-key ar)))
                 (if kx-key
                     (%am-install-crypto-token ar envelope-octets kx-key)
                     ;; KxKey not derived yet (we authenticate slightly later): buffer it
                     (push (copy-seq envelope-octets) (auth-remote-pending-ct ar))))))
            ;; --- unknown class: drop (fail-closed) ---
            (t (return-from %am-on-psm t)))
          ;; both authenticated AND remote KeyMaterial installed -> :keyed -> resume (outside lock)
          (let ((flip nil))
            (dds.pal:with-lock ((auth-manager-state-lock ms))
              (when (and (eq (auth-remote-state ar) :authenticated)
                         (auth-remote-remote-km ar))
                (setf (auth-remote-state ar) :keyed flip t)))
            (when flip
              (%am-log src-prefix "keyed; installing crypto-keys resolver + resuming matches")
              (%am-install-crypto-resolver p ms node)   ; T6: wire the dynamic key resolver before resuming
              (dds.disc:resume-parked-matches node)))))))
  t)

(defun* %am-install-crypto-resolver (p ms node)
    (function (domain-participant auth-manager-state dds.disc:disc-node) (eql t))
  "Install a CRYPTO-KEYS resolver on NODE's CRYPTO-TRANSFORM, backed by MS's WRITER-KM-TABLE
   (per-writer encode) and per-remote AUTH-REMOTE tables (per-remote decode). Encode closure:
   resolves the local writer's KeyMaterial by an O(1) lookup in MS's WRITER-KM-TABLE, keyed by
   the 16-octet writer GUID (§9.5: one KeyMaterial per writer, identical value for ALL remotes;
   no maphash scan, no non-determinism across multiple authenticated peers). Decode closure:
   resolves the remote writer's KeyMaterial by the first 12 octets (RTPS 2.5 §9.3.1.2 GuidPrefix_t)
   of the 16-octet wire GUID, looked up in the per-remote AUTH-REMOTE table (§9.5.2 REMOTE-KM).
   Both closures hold the manager lock and read dynamically so later :keyed remotes are visible.
   Fails closed: NIL -> caller drops the sample (no plaintext fallback). CALLER DOES NOT HOLD lock."
  (declare (ignore p))
  (setf (dds.disc:disc-node-crypto-transform node)
        (dds.security:make-crypto-keys
         :encode-key-fn
         (lambda (writer-guid)
           ; O(1) table lookup — the single per-writer KeyMaterial, same for every authenticated remote
           (dds.pal:with-lock ((auth-manager-state-lock ms))
             (gethash writer-guid (auth-manager-state-writer-km-table ms))))
         :decode-key-fn
         (lambda (remote-writer-guid)
           ; resolve remote KeyMaterial by the 12-octet GuidPrefix of the wire writer GUID
           (let ((prefix (make-array 12 :element-type '(unsigned-byte 8))))
             (replace prefix remote-writer-guid :end2 12)
             (dds.pal:with-lock ((auth-manager-state-lock ms))
               (let ((ar (gethash prefix (dds.disc:disc-node-auth-state node))))
                 (when (and ar (eq (auth-remote-state ar) :keyed))
                   (auth-remote-remote-km ar))))))))
  t)

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
   with the private key) and install its three hooks on P's disc-node: ON-PARTICIPANT-DISCOVERED
   (the requester trigger / replier pre-stash), ON-STATELESS-MESSAGE (the raw-envelope handshake
   + key-material dispatcher), and AUTH-GATE (the strict §7.3 endpoint-match verdict). Installed
   ONLY for a security-enabled participant (an identity configured); a participant with no
   identity keeps DP-AUTH-STATE NIL and the gate stays :compatible (byte-identical plain path).
   The disc-node must already advertise this identity's IdentityToken in SPDP. Returns P."
  (setf (dp-auth-state p) (%make-auth-manager-state :identity identity-handle))
  (let ((node (dp-node p)))
    (setf (dds.disc:disc-node-on-participant-discovered node)
          (lambda (n prefix spdp) (%am-on-participant-discovered p n prefix spdp)))
    (setf (dds.disc:disc-node-on-stateless-message node)
          (lambda (n src-prefix envelope) (%am-on-stateless-message p n src-prefix envelope)))
    (setf (dds.disc:disc-node-auth-gate node)
          (lambda (n remote local) (%participant-auth-gate p n remote local))))
  p)
