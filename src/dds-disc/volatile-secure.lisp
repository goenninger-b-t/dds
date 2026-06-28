;;;; L5 — Reliable ParticipantVolatileMessageSecure (PVMS) builtin endpoint
;;;; (DDS-Security 1.1 §7.4.5 / §9.5.3.1; M7/P6 Slice 4 T7). The secure, RELIABLE,
;;;; VOLATILE (KEEP_ALL, no durability) builtin endpoint that carries the crypto-token
;;;; exchange between two authenticated participants. Two parts:
;;;;
;;;;  1. BOOTSTRAP-KEY DERIVATION (§9.5.3.1). PVMS protects its OWN traffic with a
;;;;     KeyMaterial derived DIRECTLY from the authenticated SharedSecret + the two
;;;;     handshake challenges — no token exchange is needed (that would be circular,
;;;;     since PVMS is the carrier for the OTHER tokens). %pvms-derive-bootstrap-km
;;;;     builds the §9.5.2 KeyMaterial whose master_salt = KxSalt and master_sender_key
;;;;     = KxKey (the SAME §9.5.3 KxKey/KxSalt KDFs the KEYX tier already pins, reused
;;;;     here — DRY), sender_key_id = all-zeros, transformation_kind = AES256-GCM. This
;;;;     is Fast DDS's "Participant2ParticipantKxKeyMaterial". Corroborated CLEAN-ROOM
;;;;     (read-only, no code copied) against eProsima Fast DDS (Apache-2.0)
;;;;     src/cpp/security/cryptography/AESGCMGMAC_KeyFactory.cpp
;;;;     register_matched_remote_participant() (the KxKeyMaterial block) +
;;;;     register_local_datawriter()/datareader() (the BuiltinParticipantVolatileMessage-
;;;;     Secure* use_kx_keys path, EndpointPluginAttributes = IS_SUBMESSAGE_ENCRYPTED,
;;;;     i.e. PVMS protection-kind = ENCRYPT). See docs/provenance.md (M7/P6 T7).
;;;;
;;;;  2. RELIABLE, PROTECTED TRANSPORT. The endpoint REUSES the M2 reliable
;;;;     writer/reader state machine (dds.rtps.reliable — HEARTBEAT/ACKNACK repair),
;;;;     configured VOLATILE (KEEP_ALL, no durability: a late joiner does NOT get old
;;;;     tokens), at the secure PVMS EntityIds (writer 0xff0202c3 / reader 0xff0202c4).
;;;;     Each payload (an opaque crypto-token ParticipantGenericMessage T8 supplies)
;;;;     rides as the SerializedPayload of a DATA submessage that is submessage-protected
;;;;     (ENCRYPT) with the bootstrap KM via the T2 codec (encode/decode-datawriter-
;;;;     submessage). HEARTBEAT/ACKNACK ride in the clear (they drive the reliability
;;;;     engine; protecting them too is a noted §8.5 refinement deferred past this thin
;;;;     slice — the conformance-critical protected unit, the DATA payload + its
;;;;     bootstrap-KM round-trip, is what T7 delivers, per the brief).
;;;;
;;;; The bootstrap KM is PER-MATCHED-REMOTE (each remote's SharedSecret), kept on the
;;;; disc-node keyed by the remote 12-octet GUID prefix (set-pvms-bootstrap-km); T8
;;;; populates it at :authenticated, the receive/resend paths resolve it by src-prefix.
;;;;
;;;; SECURITY POSTURE (NFR-SEC-POSTURE / the operating contract §4): decode is
;;;; FAIL-CLOSED — a missing KM, an undecryptable/malformed/tampered PVMS submessage, or
;;;; a wrong-EntityId inner DATA yields a silent DROP, never a signal out of the receiver
;;;; thread, never plaintext on a failure. The codec bounds-checks every field.
;;;;
;;;; NONCE-UNIQUENESS CARRY (T8). The bootstrap KM is SYMMETRIC across the pair (both
;;;; sides derive identical KxKey/KxSalt bytes). Our codec's session_id is the Slice-1
;;;; +fixed-session-id+ (all-zeros) and the nonce = session_id ∥ per-KM iv_suffix; two
;;;; participants encoding under the same key from iv-counter 0 would COLLIDE nonces
;;;; (catastrophic for AES-GCM). T7's traffic is one-directional per exchange (the test
;;;; sender encodes DATA; the peer answers in the clear), so no reuse occurs here. T8,
;;;; which wires the BIDIRECTIONAL token exchange + owns the :authenticated promotion
;;;; (and knows initiator vs responder), MUST give the two sides disjoint nonce spaces
;;;; (distinct session_ids or iv_suffix ranges by role) — exactly as Fast DDS sets a
;;;; distinct Session.session_id per remote crypto. Flagged, never silent.
;;;;
;;;; Control-plane only (the security handshake/token carrier) — per-message heap
;;;; allocation is intentional, mirroring stateless-message.lisp / participant-message.lisp.

(in-package #:dds.disc)

(defparameter *pvms-debug-drop-sns* nil
  "Debug-only whole-DATA loss injection for the PVMS endpoint (default NIL = off): a list of
   PVMS-writer sequence numbers whose protected DATA %pvms-emit-data silently SKIPS on EVERY send
   (initial push AND ACKNACK-driven resend, mirroring *debug-drop-sample-numbers* on the user path),
   proving lost-sample recovery via the HEARTBEAT/ACKNACK repair path once the SN is removed from the
   list (RTPS 2.5 §8.4.2.2). Set GLOBALLY with setf (not a thread-local let) so the receiver-thread
   resend path observes it too. Never set in production (a local test seam, not a wire constant).")

(defparameter *pvms-debug-on-emit* nil
  "Debug-only capture hook for the PVMS endpoint (default NIL = off, ZERO production effect): when bound to a
   function of one argument, %pvms-emit-data calls it with the freshly-ENCODED secured submessage octets (the
   SEC_PREFIX ‖ §9.5.3.3.1 CryptoHeader ‖ SEC_BODY ‖ SEC_POSTFIX bracket encode-datawriter-submessage built)
   just before the datagram send — the ONLY seam that observes the ACTUAL on-wire per-role session_id the
   encode path threaded (CryptoHeader offset 12, octet[4]), so a regression reverting the encode to the
   all-zero +fixed-session-id+ is caught on the WIRE, not merely in the %pvms-role-session-id helper. Fires
   only for what is truly sent (a SN dropped via *pvms-debug-drop-sns* captures nothing). Unlike
   *pvms-debug-drop-sns*, bind it with a thread-local let so ONLY the calling thread's synchronous emit is
   captured (the receiver-thread resend sees the global NIL) — the on-wire session_id test relies on that to
   keep the two directions' captures uncontaminated. Never set in production (a test seam, not a wire constant).")

;;; --- §9.5.3.1 bootstrap KeyMaterial derivation (SharedSecret-derived, no exchange) ---

(defun* %pvms-derive-bootstrap-km (shared-secret challenge1 challenge2)
    (function ((simple-array (unsigned-byte 8) (32))
               (simple-array (unsigned-byte 8) (*))
               (simple-array (unsigned-byte 8) (*)))
              dds.security:key-material)
  "Derive the ParticipantVolatileMessageSecure protection KeyMaterial DIRECTLY from the authenticated
   SHARED-SECRET (32 octets, SHA-256(ECDH/FFDH) §9.3.3) and the two 32-octet handshake nonces
   CHALLENGE1 (initiator) / CHALLENGE2 (responder) — DDS-Security 1.1 §9.5.3.1. NO token exchange:
   PVMS is the bootstrap carrier for the OTHER crypto tokens, so its own protection key must be derivable
   from the SharedSecret alone. The result is the §9.5.2 KeyMaterial_AES_GCM_GMAC:
     transformation_kind = AES256-GCM {0,0,0,4};
     master_salt         = KxSalt = HMAC-SHA256(SHA-256(challenge1 ∥ 'keyexchange salt' ∥ challenge2), shared_secret);
     master_sender_key   = KxKey  = HMAC-SHA256(SHA-256(challenge2 ∥ 'key exchange key' ∥ challenge1), shared_secret);
     sender_key_id       = 0x00000000 (the on-wire transformation_key_id the decoder sees for PVMS).
   The §9.5.3 KxKey/KxSalt KDFs are REUSED verbatim (derive-kx-key / derive-kx-salt) — they are already
   pinned + dual-corroborated (the KEYX spike); this assembles their outputs into the volatile-endpoint
   KeyMaterial rather than using them to wrap tokens (that is the KEYX tier's distinct use of the SAME
   primitive). The returned key-material plugs straight into encode/decode-datawriter-submessage.
   Corroborated CLEAN-ROOM (read-only, no code copied) against eProsima Fast DDS (Apache-2.0)
   AESGCMGMAC_KeyFactory.cpp register_matched_remote_participant() Participant2ParticipantKxKeyMaterial:
   buffer.transformation_kind=c_transfrom_kind_aes256_gcm; sender_key_id.fill(0);
   create_kx_key(master_salt, challenge_1,'keyexchange salt',challenge_2,shared_secret);
   create_kx_key(master_sender_key, challenge_2,'key exchange key',challenge_1,shared_secret) — and that
   same buffer is the BuiltinParticipantVolatileMessageSecureWriter's EntityKeyMaterial with
   PLUGIN_ENDPOINT_SECURITY_ATTRIBUTES_FLAG_IS_SUBMESSAGE_ENCRYPTED (PVMS = ENCRYPT). See docs/provenance.md."
  (let ((salt-h (dds.security:derive-kx-salt shared-secret challenge1 challenge2))
        (key-h  (dds.security:derive-kx-key  shared-secret challenge1 challenge2)))
    (unwind-protect
         (dds.security:make-key-material
          :transformation-kind (copy-seq dds.security:+transformation-kind-aes256-gcm+)
          :master-salt         (copy-seq (dds.security:kx-key-bytes salt-h))
          :sender-key-id       (make-array 4 :element-type '(unsigned-byte 8) :initial-element 0)
          :master-sender-key   (copy-seq (dds.security:kx-key-bytes key-h)))
      ;; the derived bytes are copied into the KeyMaterial; release the foreign KxKey/KxSalt buffers.
      (dds.security:free-kx-key salt-h)
      (dds.security:free-kx-key key-h))))

;;; --- per-matched-remote bootstrap KM store (set at :authenticated by T8; resolved by src-prefix) ---

(defun* set-pvms-bootstrap-km (node prefix km)
    (function (disc-node (simple-array (unsigned-byte 8) (12)) dds.security:key-material) dds.security:key-material)
  "Install the §9.5.3.1 PVMS bootstrap KeyMaterial KM for the matched remote participant PREFIX (its
   12-octet GUID prefix) on NODE, lock-guarded — the per-matched-remote key the protected PVMS send +
   receive + resend paths resolve by PREFIX. The DDS-Security manager (T8) calls this once the remote
   reaches :authenticated (the SharedSecret is known); %send-volatile-secure / %on-volatile-secure /
   %on-pvms-acknack then find it. Returns KM."
  (dds.pal:with-lock ((disc-node-lock node))
    (setf (gethash (copy-seq prefix) (disc-node-pvms-bootstrap-kms node)) km)))

(defun* %pvms-bootstrap-km (node prefix)
    (function (disc-node (simple-array (unsigned-byte 8) (12))) (or null dds.security:key-material))
  "The §9.5.3.1 PVMS bootstrap KeyMaterial for remote participant PREFIX, or NIL if none is installed
   (PREFIX not yet :authenticated). Lock-guarded. NIL is the fail-closed signal: no protected PVMS
   traffic can be sent to / accepted from a remote without its bootstrap KM."
  (dds.pal:with-lock ((disc-node-lock node))
    (gethash prefix (disc-node-pvms-bootstrap-kms node))))

;;; --- per-role session_id: DISJOINT nonce spaces for the SYMMETRIC bootstrap KM (T8, safety-critical) ---

(defun* %pvms-prefix-greater-p (a b)
    (function ((simple-array (unsigned-byte 8) (12)) (simple-array (unsigned-byte 8) (12))) t)
  "T iff 12-octet GUID prefix A is lexicographically GREATER than B (first differing octet decides; RTPS
   2.5 §9.3.1.2). The deterministic, complementary winner/loser discriminator for the per-role PVMS
   session_id: distinct participants never tie, and the two peers agree on which prefix is the winner."
  (dotimes (i 12 nil)
    (let ((ai (aref a i)) (bi (aref b i)))
      (when (> ai bi) (return t))
      (when (< ai bi) (return nil)))))

(defun* %pvms-prefix-fold-u32 (prefix)
    (function ((simple-array (unsigned-byte 8) (12))) (unsigned-byte 32))
  "Fold a 12-octet GUID prefix into a u32 by XORing its three big-endian 32-bit words — a deterministic,
   both-sides-agree base for the per-role session_id (the value is non-secret; only its per-role DISTINCTNESS
   matters, since session_id self-describes on the wire)."
  (let ((acc 0))
    (declare (type (unsigned-byte 32) acc))
    (dotimes (w 3 acc)
      (let ((o (* w 4)))
        (setf acc (logxor acc (logior (ash (aref prefix o) 24) (ash (aref prefix (+ o 1)) 16)
                                      (ash (aref prefix (+ o 2)) 8) (aref prefix (+ o 3)))))))))

(defun* %pvms-role-session-id (local-prefix remote-prefix)
    (function ((simple-array (unsigned-byte 8) (12)) (simple-array (unsigned-byte 8) (12)))
              (simple-array (unsigned-byte 8) (4)))
  "The 4-octet §9.5.3.3.4.4 session_id LOCAL-PREFIX uses to ENCODE PVMS submessages destined for
   REMOTE-PREFIX (DDS-Security 1.1 §9.5.3.1; T8, SAFETY-CRITICAL). The PVMS bootstrap KM is SYMMETRIC (both
   peers derive identical KxKey/KxSalt bytes), so if BOTH directions encoded with the same session_id from
   iv_suffix 0 they would reuse the SAME (key, nonce) — CATASTROPHIC for AES-GCM (NIST SP 800-38D §8.3:
   confidentiality AND integrity break). This gives the two directions DISJOINT nonce spaces: the
   lexicographically GREATER prefix is the deterministic 'winner' (both peers agree, RTPS GUIDs are
   unique); base = (2^31 | fold(winner-prefix)) is non-zero with its high bit set; the winner's outbound
   session_id = base-1, the loser's = base (distinct: base != base-1, both non-zero — distinct from the
   non-PVMS all-zero +fixed-session-id+ too). Because the session key is derived from session_id AND the
   nonce is session_id∥iv_suffix, the two directions use DIFFERENT session keys AND non-overlapping nonces.
   DECODE needs no agreement: the codec reads session_id from the wire CryptoHeader. Corroborated CLEAN-ROOM
   against eProsima Fast DDS (Apache-2.0) AESGCMGMAC_KeyFactory.cpp register_matched_remote_participant
   (the per-remote Session.session_id = max(...) with a '-=1' tiebreak that separates the two directions);
   our value derivation is our-implementation-choice (the wire is self-describing; only per-role
   DISTINCTNESS is load-bearing for our-to-our). See docs/provenance.md (M7/P6 T8)."
  (let* ((winner (if (%pvms-prefix-greater-p local-prefix remote-prefix) local-prefix remote-prefix))
         (base   (logior #x80000000 (%pvms-prefix-fold-u32 winner)))
         (sid    (if (equalp winner local-prefix) (logand (1- base) #xffffffff) base))
         (out    (make-array 4 :element-type '(unsigned-byte 8))))
    (setf (aref out 0) (ldb (byte 8 24) sid) (aref out 1) (ldb (byte 8 16) sid)
          (aref out 2) (ldb (byte 8 8) sid)  (aref out 3) (ldb (byte 8 0) sid))
    out))

;;; --- endpoint setup (reliable, volatile: KEEP_ALL, no durability) ---

(defun* enable-volatile-secure (node &key on-volatile-secure)
    (function (disc-node &key (:on-volatile-secure (or null function))) disc-node)
  "Give NODE the reliable ParticipantVolatileMessageSecure builtin endpoint (DDS-Security 1.1 §7.4.5):
   a VOLATILE (KEEP_ALL, no durability — late joiners do NOT replay old tokens, §9.5.3.1) reliable
   writer + reader reusing the M2 reliable engine (HEARTBEAT/ACKNACK repair), at the secure PVMS
   EntityIds. Installs the ON-VOLATILE-SECURE receiver hook (node src-prefix payload-octets) -> t,
   invoked once per newly-delivered recovered crypto-token ParticipantGenericMessage payload (mirrors
   on-stateless-message; dds-disc stays format-agnostic, the dds-dcps crypto-manager parses/dispatches).
   Idempotent in effect (re-enabling resets the writer/reader). Call after the participant is
   :authenticated and its bootstrap KM is installed (set-pvms-bootstrap-km).
   T8: the writer/reader/hook slot mutations are LOCK-GUARDED (disc-node-lock) — the receiver thread reads
   pvms-writer/pvms-reader/on-volatile-secure in %on-volatile-secure / %on-pvms-heartbeat / %on-pvms-acknack,
   so install must be atomic w.r.t. those reads (T7 left this unguarded; T8 owns the fix)."
  (let ((w (dds.rtps.reliable:make-rtps-writer
            :hc (dds.rtps.history:make-history-cache :keep-all 1 nil nil)))   ; KEEP_ALL, unlimited, no durability
        (r (dds.rtps.reliable:make-rtps-reader)))
    (dds.pal:with-lock ((disc-node-lock node))
      (setf (disc-node-pvms-writer node) w
            (disc-node-pvms-reader node) r)
      (when on-volatile-secure
        (setf (disc-node-on-volatile-secure node) on-volatile-secure))))
  node)

;;; --- outbound: build + protect + reliably send a PVMS DATA ---

(defun* %pvms-build-plain-data (sn payload)
    (function (integer (simple-array (unsigned-byte 8) (*))) (simple-array (unsigned-byte 8) (*)))
  "Build the PLAINTEXT PVMS DATA submessage (RTPS 2.5 §9.4.5.4) carrying PAYLOAD as its SerializedPayload:
   readerId = +entityid-participant-volatile-secure-reader+, writerId =
   +entityid-participant-volatile-secure-writer+, writerSN = SN, E=1 little-endian. PAYLOAD is the opaque
   crypto-token ParticipantGenericMessage blob (no extra encapsulation header — it IS the SerializedPayload,
   like the PSM envelope). Returned as a fresh exact-length octet vector — the PLAIN-SUBMESSAGE region the
   T2 submessage codec then protects. Off-heap scratch (control-plane) freed before return."
  (let* ((buf (dds.core.buffer:make-octet-buffer (+ 64 (length payload))))
         (cur (dds.core.buffer:cursor buf :endianness :little)))
    (unwind-protect
         (progn
           (dds.rtps.message:write-data
            cur dds.rtps.discovery:+entityid-participant-volatile-secure-reader+
            dds.rtps.discovery:+entityid-participant-volatile-secure-writer+
            sn payload 0 (length payload))
           (subseq (dds.core.buffer:octet-buffer-vec buf) 0 (dds.core.buffer:cursor-position cur)))
      (dds.pal:free-static (dds.core.buffer:octet-buffer-vec buf)))))

(defun* %pvms-emit-data (node km sn payload host port session-id)
    (function (disc-node dds.security:key-material integer (simple-array (unsigned-byte 8) (*))
               string (unsigned-byte 16) (simple-array (unsigned-byte 8) (4))) t)
  "Build the plaintext PVMS DATA for (SN, PAYLOAD), submessage-protect it under KM with ENCRYPT (the T2
   codec encode-datawriter-submessage → SEC_PREFIX ∥ CryptoHeader ∥ SEC_BODY[ciphertext] ∥ SEC_POSTFIX,
   DDS-Security 1.1 §8.5.1.7 / §9.5.3.1 — PVMS is submessage-ENCRYPTED), and send the secured bracket as
   one datagram to HOST:PORT. A fresh per-call message buffer (control-plane; the reused tx/rx buffers are
   untouched, so this is safe from any thread). No-op (still T) if the codec returns NIL. Each call re-seals
   with a fresh nonce (the KM's monotonic iv_suffix), so a RESEND is a new ciphertext over the same plaintext
   — correct AES-GCM practice; the reader decodes either. SESSION-ID is the per-role 4-octet §9.5.3.3.4.4
   session_id (%pvms-role-session-id) giving this direction a nonce space DISJOINT from the peer's — the
   SYMMETRIC bootstrap KM otherwise would reuse (key, nonce) across the pair (T8, safety-critical).
   Loss injection: a SN in *pvms-debug-drop-sns* is silently skipped on EVERY send (initial + resend), so
   reliable repair is exercised once the SN is removed."
  (unless (member sn *pvms-debug-drop-sns*)
    (let* ((plain   (%pvms-build-plain-data sn payload))
           (secured (dds.security:encode-datawriter-submessage km :encrypt plain :session-id session-id)))
      (when secured
        (when *pvms-debug-on-emit* (funcall *pvms-debug-on-emit* secured))   ; test seam: observe the on-wire session_id
        (let ((buf (dds.core.buffer:make-octet-buffer (+ 64 (length secured)))))
          (unwind-protect
               (%send-msg-buf node buf
                              (lambda (mc) (dds.core.buffer:put-octets mc secured 0 (length secured)))
                              host port)
            (dds.pal:free-static (dds.core.buffer:octet-buffer-vec buf)))))))
  t)

(defun* %pvms-emit-heartbeat (node host port)
    (function (disc-node string (unsigned-byte 16)) t)
  "Send one NON-FINAL PVMS-writer HEARTBEAT (firstSN,lastSN,count from the reliable writer) to HOST:PORT
   in the CLEAR (RTPS 2.5 §8.3.7.5 / §8.4.2.2; FinalFlag NOT_SET solicits an ACKNACK) — the control
   submessage that drives the reliability engine so a peer NACKs a lost PVMS DATA. readerId/writerId = the
   secure PVMS reader/writer EntityIds. A no-op (still T) when the endpoint is not enabled. Fresh per-call
   buffer (control-plane)."
  (let ((w (disc-node-pvms-writer node)))
    (when w
      (multiple-value-bind (first last count) (dds.rtps.reliable:writer-heartbeat w)
        (let ((buf (dds.core.buffer:make-octet-buffer 64)))
          (unwind-protect
               (%send-msg-buf node buf
                              (lambda (mc)
                                (dds.rtps.message:write-heartbeat
                                 mc dds.rtps.discovery:+entityid-participant-volatile-secure-reader+
                                 dds.rtps.discovery:+entityid-participant-volatile-secure-writer+
                                 first last count :final nil))
                              host port)
            (dds.pal:free-static (dds.core.buffer:octet-buffer-vec buf)))))))
  t)

(defun* %send-volatile-secure (node dest-prefix payload-octets)
    (function (disc-node (simple-array (unsigned-byte 8) (12)) (simple-array (unsigned-byte 8) (*))) t)
  "Reliably send PAYLOAD-OCTETS (an opaque crypto-token ParticipantGenericMessage, supplied by T8) to the
   matched remote participant DEST-PREFIX over the ParticipantVolatileMessageSecure endpoint, submessage-
   protected (ENCRYPT) with DEST-PREFIX's §9.5.3.1 bootstrap KM (DDS-Security 1.1 §7.4.5 / §9.5.3.1). Stores
   the payload in the reliable writer's VOLATILE HistoryCache (so the change is ACKNACK-repairable), emits
   the protected DATA datagram, then a clear HEARTBEAT datagram soliciting the ACKNACK. The DATA and
   HEARTBEAT are SEPARATE datagrams so a lost DATA still leaves a HEARTBEAT to trigger repair (RTPS 2.5
   §8.4.2.2). A no-op (still returns T — the PSM/WLP convention) when DEST-PREFIX has no installed bootstrap
   KM (not yet :authenticated), the endpoint is not enabled, or DEST-PREFIX has no resolved metatraffic
   locator. Loss injection (test seam): %pvms-emit-data skips any SN in *pvms-debug-drop-sns* on every send,
   so a dropped DATA is recovered through the HEARTBEAT/ACKNACK path once the SN is cleared from the list."
  (let ((km (%pvms-bootstrap-km node dest-prefix))
        (writer (disc-node-pvms-writer node))
        (hp (%remote-metatraffic node dest-prefix))
        (sid (%pvms-role-session-id (disc-node-guid-prefix node) dest-prefix)))
    (when (and km writer hp)
      (let ((sn (dds.rtps.reliable:writer-write writer payload-octets)))
        (when (integerp sn)
          (%pvms-emit-data node km sn payload-octets (car hp) (cdr hp) sid)
          (%pvms-emit-heartbeat node (car hp) (cdr hp))))))
  t)

(defun* %pvms-push-heartbeat (node dest-prefix)
    (function (disc-node (simple-array (unsigned-byte 8) (12))) t)
  "Re-emit the PVMS-writer HEARTBEAT to DEST-PREFIX's metatraffic locator (RTPS 2.5 §8.4.2.2) — the
   periodic/idempotent re-solicit that keeps reliability live and re-prompts an ACKNACK if a PVMS DATA (or
   an earlier ACKNACK/resend) was lost. A no-op (still T) when the endpoint is not enabled or DEST-PREFIX has
   no resolved locator. Drives the reliable repair the same way announce-endpoints' %push-heartbeat does for
   the user writer."
  (let ((hp (%remote-metatraffic node dest-prefix)))
    (when hp (%pvms-emit-heartbeat node (car hp) (cdr hp))))
  t)

(defun* %pvms-authenticated-prefixes (node)
    (function (disc-node) list)
  "Snapshot (UNDER the node lock) the 12-octet GUID prefixes of every matched-remote with a §9.5.3.1
   bootstrap KM installed — the :authenticated peers the PVMS writer has matched (the pvms-bootstrap-kms
   keys). The single shared 'who are my matched PVMS remotes' source for %pvms-push-heartbeats-all (the
   re-solicit fan-out) and %pvms-matched-reader-keys (the purge bound) — one definition, no duplicated
   maphash (DRY). Returned as a fresh list so callers iterate OUTSIDE the lock (no lock held across a network
   send or a writer-lock acquisition)."
  (let ((prefixes '()))
    (dds.pal:with-lock ((disc-node-lock node))
      (maphash (lambda (k v) (declare (ignore v)) (push k prefixes))
               (disc-node-pvms-bootstrap-kms node)))
    prefixes))

(defun* %pvms-matched-reader-keys (node)
    (function (disc-node) list)
  "The full 16-octet GUIDs of every matched PVMS remote READER (one per :authenticated peer) — the
   writer-proxy keys that bound the VOLATILE purge in writer-purge-acked (RTPS 2.5 §8.4.1). The PVMS writer
   is ONE-per-node SHARED across all matched remotes over a SINGLE SN space, so its acked history MUST be
   purged only below the SLOWEST reader's ack: purging on the lone ACKNACKing reader's key (the pre-fix bug)
   drops changes a slower peer has not yet acked, and (shared SN space + in-order reliable reader) that peer
   can never repair the hole — STALLing its token delivery so it never reaches :keyed (the N>2 failure). Each
   key is %source-guid(prefix, +entityid-participant-volatile-secure-reader+) — IDENTICAL to the rkey
   %on-pvms-acknack advances from an ACKNACK — so a peer that has not yet ACKed reads acked-base 1 in
   writer-purge-acked and HOLDS the watermark (nothing purged until EVERY matched PVMS reader acks). The PVMS
   endpoint is always RELIABLE, so (unlike the user path's %matched-reader-keys) there is no best-effort
   reader to exclude. Mirrors the proven user-data %matched-reader-keys."
  (loop for prefix in (%pvms-authenticated-prefixes node)
        collect (%source-guid prefix dds.rtps.discovery:+entityid-participant-volatile-secure-reader+)))

(defun* %pvms-push-heartbeats-all (node)
    (function (disc-node) (eql t))
  "Re-emit the PVMS-writer HEARTBEAT to EVERY matched-remote that has a §9.5.3.1 bootstrap KM installed
   (i.e. the :authenticated peers — the pvms-bootstrap-kms keys) on the announce cadence (RTPS 2.5 §8.4.2.2;
   T8). This is the periodic re-solicit that DRIVES reliable crypto-token delivery + repair: a peer that
   was not yet keyed when our token DATA first arrived (it dropped them, fail-closed) re-NACKs once it has
   its own bootstrap KM, pulling the retained tokens. A no-op (still T) when the PVMS endpoint is not enabled.
   The prefixes are snapshotted UNDER the node lock (%pvms-authenticated-prefixes), then each heartbeat is
   sent OUTSIDE the lock (no lock held across a network send). Mirrors %push-heartbeat for the user writer,
   fanned over the keyed peers."
  (when (disc-node-pvms-writer node)
    (dolist (p (%pvms-authenticated-prefixes node)) (%pvms-push-heartbeat node p)))
  t)

;;; --- inbound: decode + reliably deliver / answer / repair ---

(defun* %on-volatile-secure (node src-prefix submessage-octets)
    (function (disc-node (simple-array (unsigned-byte 8) (12)) (simple-array (unsigned-byte 8) (*))) t)
  "Receiver thread: a submessage-protection bracket (SEC_PREFIX ... SEC_POSTFIX) carrying a PVMS DATA from
   remote SRC-PREFIX. Recover the plaintext DATA submessage with SRC-PREFIX's §9.5.3.1 bootstrap KM (the T2
   codec decode-datawriter-submessage, DDS-Security 1.1 §8.5.1.7 / §9.5.3.1), parse it, feed its SN to the
   reliable reader (so the ACKNACK/HEARTBEAT bookkeeping is correct), and deliver the recovered crypto-token
   ParticipantGenericMessage payload to the ON-VOLATILE-SECURE hook EXACTLY ONCE per (writer,SN) — duplicate
   SNs (a resend after the original arrived) are de-duplicated (reader-dedup-accept-p) so the hook never
   double-fires. FAIL-CLOSED (NFR-SEC-POSTURE): a missing KM, an undecryptable/malformed/truncated/tampered
   bracket, a too-short or wrong-EntityId / no-payload inner DATA → a silent DROP (still returns T), never a
   signal out of the receiver thread, never plaintext on a failure. The hook fires OUTSIDE the node lock."
  (block %on-pvms
    (let ((km (%pvms-bootstrap-km node src-prefix))
          (reader (disc-node-pvms-reader node)))
      (unless (and km reader) (return-from %on-pvms t))                      ; no KM / not enabled -> drop
      (let ((plain (dds.security:decode-datawriter-submessage km submessage-octets)))
        (unless (and plain (>= (length plain) 4)) (return-from %on-pvms t))  ; auth/parse fail -> drop
        ;; PLAIN is a complete DATA submessage (header + body) we built with write-data (E=1 LE).
        (let ((cur (dds.core.buffer:cursor (dds.core.buffer:octet-buffer-over plain) :endianness :little)))
          (multiple-value-bind (id flags octets le) (dds.rtps.message:parse-submessage-header cur)
            (unless (and id (= id dds.rtps.message:+submsg-data+)) (return-from %on-pvms t))
            (dds.core.buffer:cursor-set-endianness cur (if le :little :big))
            (multiple-value-bind (rdr wid sn has-payload poff plen)
                (dds.rtps.message:parse-data-body cur flags octets)
              (declare (ignore rdr))
              (unless (and sn has-payload (plusp plen)
                           (= wid dds.rtps.discovery:+entityid-participant-volatile-secure-writer+))
                (return-from %on-pvms t))
              (let ((wguid (%source-guid src-prefix wid))
                    (payload (make-array plen :element-type '(unsigned-byte 8))))
                ;; PLAIN is the recovered DATA-submessage octet vector itself; copy out [poff, poff+plen).
                (replace payload plain :start2 poff :end2 (+ poff plen))
                ;; reliable state ALWAYS (keeps ACKNACK/complete correct); app delivery dedup-gated.
                (dds.rtps.reliable:reader-on-data reader wguid sn payload)
                (when (and (dds.rtps.reliable:reader-dedup-accept-p reader wguid sn)
                           (disc-node-on-volatile-secure node))
                  (funcall (disc-node-on-volatile-secure node) node src-prefix payload)))))))))
  t)

(defun* %on-pvms-heartbeat (node src-prefix first last)
    (function (disc-node (simple-array (unsigned-byte 8) (12)) integer integer) t)
  "Receiver thread: a clear HEARTBEAT [FIRST,LAST] from remote SRC-PREFIX's PVMS writer. Apply the range to
   the reliable reader's writer-proxy (keyed by the remote writer's full 16-octet GUID, §8.3.5.4), compute
   the ACKNACK (acking received PVMS SNs, NACKing the missing), and send it in the clear to SRC-PREFIX's
   metatraffic locator (RTPS 2.5 §8.3.7.1) — the repair trigger that pulls a dropped PVMS DATA. writerId in
   the ACKNACK = the PVMS writer EntityId so the peer routes it to its PVMS writer. A no-op (still T) when the
   endpoint is not enabled or SRC-PREFIX has no resolved locator. Fresh per-call buffer (control-plane)."
  (let ((reader (disc-node-pvms-reader node))
        (hp (%remote-metatraffic node src-prefix)))
    (when (and reader hp)
      (let ((wguid (%source-guid src-prefix dds.rtps.discovery:+entityid-participant-volatile-secure-writer+)))
        (dds.rtps.reliable:reader-on-heartbeat reader wguid first last)
        (multiple-value-bind (base numbits bitmap) (dds.rtps.reliable:reader-acknack reader wguid)
          (let ((buf (dds.core.buffer:make-octet-buffer 64)))
            (unwind-protect
                 (%send-msg-buf node buf
                                (lambda (mc)
                                  (dds.rtps.message:write-acknack
                                   mc dds.rtps.discovery:+entityid-participant-volatile-secure-reader+
                                   dds.rtps.discovery:+entityid-participant-volatile-secure-writer+
                                   base numbits bitmap (incf (disc-node-ack-count node)) :final t))
                                (car hp) (cdr hp))
              (dds.pal:free-static (dds.core.buffer:octet-buffer-vec buf))))))))
  t)

(defun* %on-pvms-acknack (node src-prefix c flags)
    (function (disc-node (simple-array (unsigned-byte 8) (12)) dds.core.buffer:cursor (unsigned-byte 8)) t)
  "Receiver thread: parse a clear ACKNACK; when it targets our PVMS writer, RESEND each NACKed change still
   in the reliable writer's HistoryCache as a freshly-protected PVMS DATA to SRC-PREFIX (re-encoded with a
   fresh nonce under SRC-PREFIX's bootstrap KM), and return T (handled). NIL for any other writer (the
   caller falls through to the user ACKNACK path). The writer-proxy is keyed by the REMOTE reader's full
   16-octet GUID (SRC-PREFIX + the ACKNACK's reader EntityId, §8.3.5.4). This is the recovery path for a
   dropped PVMS DATA. A no-op resend (still returns T-handled) when the bootstrap KM or the locator is
   missing (fail-closed)."
  (multiple-value-bind (rid wid base numbits bitmap count finalp)
      (dds.rtps.message:parse-acknack-body c flags)
    (declare (ignore count finalp))
    (when (and wid (= wid dds.rtps.discovery:+entityid-participant-volatile-secure-writer+))
      (let ((writer (disc-node-pvms-writer node))
            (km (%pvms-bootstrap-km node src-prefix))
            (hp (%remote-metatraffic node src-prefix))
            (rkey (%source-guid src-prefix rid))
            (sid (%pvms-role-session-id (disc-node-guid-prefix node) src-prefix)))
        (when (and writer km hp base)
          (multiple-value-bind (resends gaps)
              (dds.rtps.reliable:writer-on-acknack writer rkey base numbits bitmap)
            (declare (ignore gaps))   ; KEEP_ALL volatile never evicts in this slice -> no GAP needed
            (dolist (ch resends)
              (let ((sn (dds.rtps.history:cache-change-sn ch))
                    (pl (dds.rtps.history:cache-change-serialized-payload ch)))
                (when pl (%pvms-emit-data node km sn pl (car hp) (cdr hp) sid))))
            ;; T8 review fix (N>2 correctness): bound the VOLATILE PVMS writer history by the SLOWEST matched
            ;; PVMS reader's ack — purge over ALL matched-remote reader keys, NOT the lone ACKNACKer's rkey
            ;; (the shared one-per-node writer spans every remote on ONE SN space; a single-key purge would
            ;; drop changes a slower peer has not acked + cannot repair → its token delivery STALLS, §8.4.1).
            (dds.rtps.reliable:writer-purge-acked writer (%pvms-matched-reader-keys node) :volatile))))
      t)))

;;; --- tests (two-node reliable repair + fail-closed; dds-disc test suite) ---

(defun* %pvms-test-derive-km (seed)
    (function ((unsigned-byte 8)) dds.security:key-material)
  "Test helper: derive a §9.5.3.1 bootstrap KM from a deterministic SEED — a 32-octet shared-secret all
   = SEED and two 32-octet challenges (all = SEED+1 and SEED+2). Two calls with the SAME seed yield
   key-materials with IDENTICAL key bytes (the symmetric per-pair KM); DIFFERENT seeds yield independent
   keys (the fail-closed negative). Test-only."
  (flet ((vec (b) (make-array 32 :element-type '(unsigned-byte 8) :initial-element b)))
    (%pvms-derive-bootstrap-km (vec seed) (vec (logand (+ seed 1) #xff)) (vec (logand (+ seed 2) #xff)))))

(defun* %pvms-test-discover (node1 node2)
    (function (disc-node disc-node) t)
  "Test helper: make NODE1 and NODE2 discover each other via SPDP over loopback (so %remote-metatraffic
   resolves each other's metatraffic locator), asserting discovery completes within a bounded wait."
  (setf (disc-node-peers node1) (list (cons "127.0.0.1" (disc-node-port node2))))
  (setf (disc-node-peers node2) (list (cons "127.0.0.1" (disc-node-port node1))))
  (start-node node1)
  (start-node node2)
  (announce-participant node1)
  (announce-participant node2)
  (loop repeat 100
        until (and (plusp (disc-node-discovered-count node1))
                   (plusp (disc-node-discovered-count node2)))
        do (sleep 0.02))
  (assert (and (plusp (disc-node-discovered-count node1))
               (plusp (disc-node-discovered-count node2)))
          () "PVMS test: SPDP discovery did not complete")
  t)

(defun* run-volatile-secure-reliable-test ()
    (function () (eql t))
  "Reliable, bootstrap-protected ParticipantVolatileMessageSecure delivery (DDS-Security 1.1 §7.4.5 /
   §9.5.3.1; M7/P6 Slice 4 T7). Two participants discover over SPDP; both derive the SAME symmetric §9.5.3.1
   bootstrap KM (same shared-secret + challenges) and install it for the peer. Node A %send-volatile-secure a
   known payload to B while SN 1 is in *pvms-debug-drop-sns* (every protected DATA — initial AND resend — is
   lost); the clear HEARTBEAT still reaches B, B ACKNACKs, but the resends are dropped, so B stays empty.
   The drop is then CLEARED and the HEARTBEAT/ACKNACK loop repairs the gap. Asserts: (1) B stays empty while
   the DATA is being dropped — the loss injection is real; (2) B delivers the payload after the repair within
   a bounded wait — reliability; (3) the recovered bytes equal the sent payload — the bootstrap-KM submessage
   protection round-trips; (4) the hook fired EXACTLY ONCE despite continued HEARTBEAT re-solicits — no
   double-delivery (dedup). Bounded; no unbounded wait."
  (let* ((p1 (make-array 12 :element-type '(unsigned-byte 8) :initial-element 11))
         (p2 (make-array 12 :element-type '(unsigned-byte 8) :initial-element 22))
         (node1 (make-disc-node :guid-prefix p1 :host "127.0.0.1" :port 0))
         (node2 (make-disc-node :guid-prefix p2 :host "127.0.0.1" :port 0))
         (payload (make-array 11 :element-type '(unsigned-byte 8)
                              :initial-contents '(#xDD #x50 #xEC #xC0 #xDE #x01 #x02 #x03 #x04 #x05 #x06)))
         (box (cons 0 nil))
         (lk (dds.pal:make-lock "pvms-test")))
    (unwind-protect
         (progn
           (%pvms-test-discover node1 node2)
           (enable-volatile-secure node1)
           (enable-volatile-secure node2
             :on-volatile-secure (lambda (n sp pl)
                                   (declare (ignore n sp))
                                   (dds.pal:with-lock (lk) (incf (car box)) (setf (cdr box) pl))))
           ;; symmetric per-pair bootstrap KM (same derivation inputs -> identical key bytes)
           (set-pvms-bootstrap-km node1 p2 (%pvms-test-derive-km 7))
           (set-pvms-bootstrap-km node2 p1 (%pvms-test-derive-km 7))
           ;; DROP SN 1 on EVERY send (global setf so the receiver-thread resend sees it too) -> B stays empty while the HEARTBEAT/ACKNACK loop runs but the resends are lost.
           (setf *pvms-debug-drop-sns* (list 1))
           (%send-volatile-secure node1 p2 payload)
           (loop repeat 6 do (%pvms-push-heartbeat node1 p2) (sleep 0.02))   ; drive HB; resends still dropped
           (assert (zerop (dds.pal:with-lock (lk) (car box))) ()
                   "PVMS drop hook failed: B received the DATA while it was being dropped")
           ;; CLEAR the drop; the next ACKNACK-driven resend must repair the gap (RTPS 2.5 §8.4.2.2)
           (setf *pvms-debug-drop-sns* nil)
           (loop repeat 60
                 until (plusp (dds.pal:with-lock (lk) (car box)))
                 do (%pvms-push-heartbeat node1 p2) (sleep 0.02))
           (assert (plusp (dds.pal:with-lock (lk) (car box))) ()
                   "PVMS reliable repair failed: B never delivered the dropped DATA via HEARTBEAT/ACKNACK")
           (assert (equalp (dds.pal:with-lock (lk) (cdr box)) payload) ()
                   "PVMS bootstrap-KM round-trip failed: recovered payload bytes differ")
           ;; continued HEARTBEATs must NOT re-deliver (dedup -> exactly once)
           (loop repeat 10 do (%pvms-push-heartbeat node1 p2) (sleep 0.01))
           (assert (= 1 (dds.pal:with-lock (lk) (car box))) ()
                   "PVMS delivered more than once (dedup failed)")
           t)
      (setf *pvms-debug-drop-sns* nil)
      (stop-node node1)
      (stop-node node2))))

(defun* run-volatile-secure-fail-closed-test ()
    (function () (eql t))
  "Non-vacuous fail-closed counterpart to run-volatile-secure-reliable-test (NFR-SEC-POSTURE,
   DDS-Security 1.1 §9.5.3.1). Same two-node setup, but B installs a WRONG bootstrap KM for A (derived from a
   DIFFERENT shared-secret), so the AES-GCM authentication of A's protected PVMS DATA FAILS at B. Node A
   sends (no drop); A's HEARTBEATs drive B to ACKNACK and A to resend, repeatedly. Asserts B NEVER delivers
   the payload — a wrong key is a silent DROP, never plaintext, never a crash. Proves the positive test's
   delivery is due to correct decryption, not an unconditional hand-off."
  (let* ((p1 (make-array 12 :element-type '(unsigned-byte 8) :initial-element 33))
         (p2 (make-array 12 :element-type '(unsigned-byte 8) :initial-element 44))
         (node1 (make-disc-node :guid-prefix p1 :host "127.0.0.1" :port 0))
         (node2 (make-disc-node :guid-prefix p2 :host "127.0.0.1" :port 0))
         (payload (make-array 8 :element-type '(unsigned-byte 8)
                              :initial-contents '(#xFA #xCE #xFE #xED #x10 #x20 #x30 #x40)))
         (delivered (cons 0 nil))
         (lk (dds.pal:make-lock "pvms-fc-test")))
    (unwind-protect
         (progn
           (%pvms-test-discover node1 node2)
           (enable-volatile-secure node1)
           (enable-volatile-secure node2
             :on-volatile-secure (lambda (n sp pl)
                                   (declare (ignore n sp pl))
                                   (dds.pal:with-lock (lk) (incf (car delivered)))))
           (set-pvms-bootstrap-km node1 p2 (%pvms-test-derive-km 7))     ; A protects with KM(seed 7)
           (set-pvms-bootstrap-km node2 p1 (%pvms-test-derive-km 9))     ; B decodes with KM(seed 9) -> WRONG
           (%send-volatile-secure node1 p2 payload)
           ;; drive HEARTBEAT/ACKNACK/resend repeatedly: every resend must still fail to decode at B
           (loop repeat 30 do (%pvms-push-heartbeat node1 p2) (sleep 0.02))
           (assert (zerop (dds.pal:with-lock (lk) (car delivered))) ()
                   "PVMS fail-closed breach: B delivered a payload it could not authenticate (wrong KM)")
           t)
      (stop-node node1)
      (stop-node node2))))

(defun* run-volatile-secure-purge-bound-test ()
    (function () (eql t))
  "N>2 PVMS purge-bound correctness (T8 review fix; RTPS 2.5 §8.4.1). The PVMS writer is ONE-per-node SHARED
   across all matched remotes on a SINGLE SN space, so its VOLATILE history must be purged only below the
   SLOWEST matched reader's ack — purging on the lone ACKNACKing reader's key (the pre-fix bug) drops changes
   a slower peer has not yet acked and (shared SN + in-order reliable reader) cannot repair, STALLing that
   peer's token delivery so it never reaches :keyed. Simulates THREE :authenticated peers (three bootstrap
   KMs installed): writes two PVMS changes; two peers ACK both, the third does NOT. Asserts:
     (1) %pvms-matched-reader-keys returns exactly the three peers' PVMS reader GUIDs (the purge key set);
     (2) the FIXED purge over ALL keys purges NOTHING while the third peer is un-acked (its proxy holds
         acked-base 1 → min watermark 1) — both changes survive (safety);
     (3) once the third peer ACKs, the SAME purge drops both (liveness — the bound still reclaims);
     (4) RED: the OLD single-key purge WOULD have dropped both the moment one peer acked — the demonstrated
         defect the fix prevents (run on a fresh writer so the live one is undisturbed).
   Pure value/engine level (no network, no crypto: dummy KMs) — deterministic on both impls."
  (let* ((p0 (make-array 12 :element-type '(unsigned-byte 8) :initial-element 1))
         (pa (make-array 12 :element-type '(unsigned-byte 8) :initial-element 2))
         (pb (make-array 12 :element-type '(unsigned-byte 8) :initial-element 3))
         (pc (make-array 12 :element-type '(unsigned-byte 8) :initial-element 4))
         (node (make-disc-node :guid-prefix p0 :host "127.0.0.1" :port 0))
         (rkey-a (%source-guid pa dds.rtps.discovery:+entityid-participant-volatile-secure-reader+))
         (rkey-b (%source-guid pb dds.rtps.discovery:+entityid-participant-volatile-secure-reader+))
         (rkey-c (%source-guid pc dds.rtps.discovery:+entityid-participant-volatile-secure-reader+))
         (zero-bitmap (make-array 1 :element-type '(unsigned-byte 32) :initial-element 0)))
    (unwind-protect
         (progn
           (enable-volatile-secure node)
           (set-pvms-bootstrap-km node pa (dds.security:make-key-material))   ; dummy KM (purge ignores the value)
           (set-pvms-bootstrap-km node pb (dds.security:make-key-material))
           (set-pvms-bootstrap-km node pc (dds.security:make-key-material))
           ;; (1) the matched-reader key set is exactly the three peers' PVMS reader GUIDs
           (let ((keys (%pvms-matched-reader-keys node)))
             (assert (= 3 (length keys)) () "expected 3 matched PVMS reader keys, got ~d" (length keys))
             (assert (and (member rkey-a keys :test #'equalp)
                          (member rkey-b keys :test #'equalp)
                          (member rkey-c keys :test #'equalp)) ()
                     "%pvms-matched-reader-keys must return each authenticated peer's PVMS reader GUID"))
           (let ((writer (disc-node-pvms-writer node)))
             (dds.rtps.reliable:writer-write writer (make-array 4 :element-type '(unsigned-byte 8) :initial-element 1))
             (dds.rtps.reliable:writer-write writer (make-array 4 :element-type '(unsigned-byte 8) :initial-element 2))
             (assert (= 2 (dds.rtps.history:hc-change-count (dds.rtps.reliable:rtps-writer-hc writer))) ()
                     "setup: writer must hold 2 changes")
             ;; peers A and B ACK both (acked-base advances to 3); peer C never ACKs (proxy holds acked-base 1)
             (dds.rtps.reliable:writer-on-acknack writer rkey-a 3 0 zero-bitmap)
             (dds.rtps.reliable:writer-on-acknack writer rkey-b 3 0 zero-bitmap)
             ;; (2) safety: FIXED purge over ALL keys — C un-acked → min watermark 1 → NOTHING purged
             (assert (zerop (dds.rtps.reliable:writer-purge-acked writer (%pvms-matched-reader-keys node) :volatile)) ()
                     "N>2 purge bug: a change was purged while a matched PVMS reader had not yet ACKed")
             (assert (= 2 (dds.rtps.history:hc-change-count (dds.rtps.reliable:rtps-writer-hc writer))) ()
                     "N>2 purge bug: a change peer C still needs was dropped (cannot be repaired → C stalls)")
             ;; (3) liveness: once C ACKs, the SAME full-key purge reclaims both
             (dds.rtps.reliable:writer-on-acknack writer rkey-c 3 0 zero-bitmap)
             (assert (= 2 (dds.rtps.reliable:writer-purge-acked writer (%pvms-matched-reader-keys node) :volatile)) ()
                     "liveness: after every matched PVMS reader ACKed, the full-key purge must reclaim both changes")
             (assert (zerop (dds.rtps.history:hc-change-count (dds.rtps.reliable:rtps-writer-hc writer))) ()
                     "liveness: the VOLATILE PVMS history must be empty after all readers ACKed"))
           ;; (4) RED: the OLD single-key purge WOULD drop both the moment ONE peer acks (the defect the fix
           ;;     prevents) — demonstrated on a FRESH writer so the assertion is non-destructive to the above.
           (let ((w2 (dds.rtps.reliable:make-rtps-writer
                      :hc (dds.rtps.history:make-history-cache :keep-all 1 nil nil))))
             (dds.rtps.reliable:writer-write w2 (make-array 4 :element-type '(unsigned-byte 8) :initial-element 1))
             (dds.rtps.reliable:writer-write w2 (make-array 4 :element-type '(unsigned-byte 8) :initial-element 2))
             (dds.rtps.reliable:writer-on-acknack w2 rkey-a 3 0 zero-bitmap)   ; only ONE peer acks
             (assert (= 2 (dds.rtps.reliable:writer-purge-acked w2 (list rkey-a) :volatile)) ()
                     "RED demo: the lone-ACKNACKer single-key purge should drop both (proving the N>2 defect the fix prevents)"))
           t)
      (stop-node node))))

(defun* %pvms-wire-session-id (secured)
    (function ((simple-array (unsigned-byte 8) (*))) (simple-array (unsigned-byte 8) (*)))
  "Extract the 4-octet session_id from a captured on-wire PVMS secured submessage SECURED (the
   SEC_PREFIX ‖ CryptoHeader ‖ … bracket encode-datawriter-submessage produced). Offset = the 4-octet
   SEC_PREFIX SubmessageHeader (RTPS 2.5 §9.4.5.1) + the §9.5.3.3.1 CryptoHeader's transformation_kind[4] +
   transformation_key_id[4] = 12, so session_id is SECURED[12,16). Test helper for the nonce-disjointness
   on-wire guard (T8 review fix)."
  (subseq secured 12 16))

(defun* run-volatile-secure-session-id-on-wire-test ()
    (function () (eql t))
  "On-WIRE per-role nonce-disjointness guard (T8 review fix; DDS-Security 1.1 §9.5.3.1, NIST SP 800-38D §8.3).
   Strengthens the %pvms-role-session-id helper check (secure-discovery-keyed assertion (e)) by capturing the
   ACTUAL secured PVMS DATA bytes BOTH directions emit and parsing the session_id straight out of the on-wire
   §9.5.3.3.1 CryptoHeader. A revert of the encode path (%pvms-emit-data / %send-volatile-secure) to the
   all-zero +fixed-session-id+ would still functionally reach :keyed (decode is self-describing) yet silently
   REUSE the (key, nonce) of the SYMMETRIC bootstrap KM — this test fails LOUDLY on that revert; the
   helper-only check would not. Two discovered nodes install the same symmetric bootstrap KM; A
   %send-volatile-secure to B and B to A are each captured via a thread-local *pvms-debug-on-emit* (so a
   receiver-thread resend — seeing the global NIL — never contaminates the other direction). Asserts the two
   captured on-wire session_ids (1) DIFFER, (2) are both NON-ZERO (so each ≠ the all-zero non-PVMS
   +fixed-session-id+), and (3) each EQUALS the %pvms-role-session-id for its direction (the encode path
   threaded the per-role value, not some other constant). Bounded; no unbounded wait."
  (let* ((p1 (make-array 12 :element-type '(unsigned-byte 8) :initial-element 11))
         (p2 (make-array 12 :element-type '(unsigned-byte 8) :initial-element 22))
         (node1 (make-disc-node :guid-prefix p1 :host "127.0.0.1" :port 0))
         (node2 (make-disc-node :guid-prefix p2 :host "127.0.0.1" :port 0))
         (payload (make-array 6 :element-type '(unsigned-byte 8)
                              :initial-contents '(#x53 #x49 #x44 #x01 #x02 #x03)))
         (cap-ab nil) (cap-ba nil))
    (unwind-protect
         (progn
           (%pvms-test-discover node1 node2)
           (enable-volatile-secure node1)
           (enable-volatile-secure node2)
           (set-pvms-bootstrap-km node1 p2 (%pvms-test-derive-km 7))   ; same symmetric KM both ways
           (set-pvms-bootstrap-km node2 p1 (%pvms-test-derive-km 7))
           ;; capture ONLY this thread's synchronous emit (let-bound, so the receiver-thread resend — which
           ;; sees the global NIL — never contaminates the other direction). One %pvms-emit-data per
           ;; %send-volatile-secure → exactly one capture each.
           (let ((*pvms-debug-on-emit* (lambda (s) (setf cap-ab (copy-seq s)))))
             (%send-volatile-secure node1 p2 payload))
           (let ((*pvms-debug-on-emit* (lambda (s) (setf cap-ba (copy-seq s)))))
             (%send-volatile-secure node2 p1 payload))
           (assert (and cap-ab cap-ba) ()
                   "PVMS on-wire test: secured DATA was not captured in both directions")
           (let ((sid-ab (%pvms-wire-session-id cap-ab))
                 (sid-ba (%pvms-wire-session-id cap-ba))
                 (exp-ab (%pvms-role-session-id p1 p2))
                 (exp-ba (%pvms-role-session-id p2 p1)))
             ;; (1) the two ON-WIRE session_ids DIFFER → no shared (key, nonce) on the symmetric bootstrap KM
             (assert (not (equalp sid-ab sid-ba)) ()
                     "PVMS on-wire nonce reuse: A->B and B->A session_ids are EQUAL — AES-GCM (key, nonce) reuse on the symmetric bootstrap KM")
             ;; (2) both NON-ZERO → each differs from the all-zero non-PVMS +fixed-session-id+
             (assert (and (notevery #'zerop sid-ab) (notevery #'zerop sid-ba)) ()
                     "PVMS on-wire session_id is all-zero (== the non-PVMS +fixed-session-id+): the encode path did not thread the per-role session_id")
             ;; (3) each on-wire value EQUALS the per-role helper → the encode path threaded the RIGHT value
             (assert (and (equalp sid-ab exp-ab) (equalp sid-ba exp-ba)) ()
                     "PVMS on-wire session_id != %pvms-role-session-id: the encode path threaded the wrong value")
             t))
      (stop-node node1)
      (stop-node node2))))
