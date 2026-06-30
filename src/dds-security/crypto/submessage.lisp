(in-package #:dds.security)

;;;; DDS-Security 1.1 §8.5.1.7-.9 submessage protection (Slice 4 / WP-DDS-SECURITY-SECURE-DISCOVERY
;;;; T2): protect a single RTPS submessage (a DATA from a DataWriter, an ACKNACK from a DataReader,
;;;; ...) as a SEC_PREFIX (0x31) ... SEC_POSTFIX (0x32) bracket, where SEC_PREFIX carries the §7.3.7
;;;; CryptoHeader and SEC_POSTFIX the CryptoFooter (the T1 wire codec, reused verbatim — DRY). What
;;;; sits BETWEEN them is MODE-dependent, per the conformant AES-GCM-GMAC plugin framing
;;;; (§9.5.3.3.4.3/.4; the operating contract Global Constraint — OMG conformance is non-negotiable, a
;;;; false REJECT is the worst defect class). Two protection modes (SIGN+ENCRYPT; origin-authentication
;;;; / receiver-specific MACs is T3, which extends the CryptoFooter list here):
;;;;
;;;;   :encrypt  CryptoHeader.transformation_kind = AES256_GCM {0,0,0,4}; a SEC_BODY (0x30) carrying the
;;;;             length-prefixed CryptoContent = ciphertext sits between PREFIX and POSTFIX;
;;;;             AAD = EMPTY; common_mac = the GCM tag over (empty AAD, ciphertext).
;;;;   :sign     CryptoHeader.transformation_kind = AES256_GMAC {0,0,0,3}; NO SEC_BODY — the ORIGINAL
;;;;             submessage sits VERBATIM between PREFIX and POSTFIX (§9.5.3.3.4.3; Fast DDS
;;;;             serialize_SecureDataBody SIGN branch copies the submessage and emits no SEC_BODY);
;;;;             AAD = that original submessage; common_mac = the GMAC over it (no cipher).
;;;;
;;;; AAD DECISION (the operating contract §4 — the wire is the oracle; match the readable conformant
;;;; impl we interop with). Fast-DDS-faithful, corroborated CLEAN-ROOM (read-only, no code copied)
;;;; against eProsima Fast DDS (Apache-2.0) src/cpp/security/cryptography/AESGCMGMAC_Transform.cpp:
;;;; serialize_SecureDataBody ENCRYPT branch encrypts the plaintext with NO prior EVP_EncryptUpdate
;;;; AAD call (=> empty AAD); the SIGN branch calls EVP_EncryptUpdate(ctx, NULL, plain_buffer)
;;;; (=> plaintext-as-AAD, empty ciphertext) and copies the plaintext out verbatim;
;;;; encode_datawriter_submessage serializes the SecureDataHeader SEPARATELY and never feeds it to
;;;; the cipher. The CryptoHeader is implicitly integrity-bound anyway: transformation_key_id /
;;;; session_id / init_vector_suffix derive the session key + nonce, so tampering them makes the GCM
;;;; tag fail to verify. The wire transformation_kind (GCM vs GMAC) is what the decoder dispatches on.
;;;; See docs/provenance.md (M7/P6 T2) for the exact files/lines.
;;;;
;;;; DECOUPLING: dds.security does NOT depend on dds.rtps (constants.lisp re-pins the secure
;;;; submessageId octets for exactly this reason; the secure-discovery integration edge is
;;;; dds.rtps -> dds.security, T9, so the reverse would be circular). The 4-octet RTPS
;;;; SubmessageHeader is therefore written/parsed HERE with dds.core.buffer primitives
;;;; (%write-sec-submessage-header / %parse-sec-submessage-header) — the identical 4-octet layout
;;;; dds.rtps.message:write-submessage-header produces, with no cross-system dependency.
;;;;
;;;; DRY: the session-key + nonce + AES-GCM core is %seal-with-km / %open-with-km (transform.lisp),
;;;; shared with the Slice-1 serialized-payload tier; only the AAD differs (a parameter). The
;;;; CryptoHeader / CryptoContent / CryptoFooter codec is crypto/crypto-header.lisp (T1).
;;;;
;;;; DRY (T4): the bracket assembly + recovery are factored into %encode-secured-region /
;;;; %decode-secured-region, parameterized by the (prefix-kind, postfix-kind) submessage ids — the
;;;; submessage tier (this file) passes SEC_PREFIX/SEC_POSTFIX; the whole-RTPS-message tier
;;;; (crypto/rtps-message.lisp, T4) passes SRTPS_PREFIX/SRTPS_POSTFIX over the same engine. The ONLY
;;;; decode difference is locating the SIGN body: the submessage tier wraps ONE submessage
;;;; (%read-embedded-submessage); the RTPS tier wraps the whole submessage STREAM, so it WALKS
;;;; submessage-by-submessage to the trailing postfix (%walk-verbatim-body, sign-walk-p) — corroborated
;;;; CLEAN-ROOM against Fast DDS decode_rtps_message (see docs/provenance.md, M7/P6 T4).
;;;;
;;;; SECURITY POSTURE (NFR-SEC-POSTURE / the operating contract §4): decode is FAIL-CLOSED and
;;;; bounds-checked even at (safety 0) — the SEC_PREFIX -> {SEC_BODY (ENCRYPT) | verbatim (SIGN)} ->
;;;; SEC_POSTFIX bracket (kinds, order)
;;;; is validated and every field read is check-room'd against the buffer extent BEFORE use; any
;;;; malformed / truncated / re-ordered / unknown-kind / GCM-auth-fail input yields NIL, never an OOB
;;;; read, never a signal to the caller, never plaintext on a failure.

;;; --- local constants (NOT wire constants pinned from a spec table; see notes) ---

(defconstant +sec-submessage-le-flags+ #x01
  "SubmessageHeader flags octet for a security submessage written little-endian: E (EndiannessFlag,
   bit 0) = 1 (DDSI-RTPS 2.5 §9.4.5.1.2). This codec emits little-endian (the RTPS common case,
   matching the Slice-1/T1 cursor convention and Fast DDS encode_datawriter_submessage flags=BIT(0)).")

;; +empty-octets+ (the shared EMPTY AAD / EMPTY plaintext for %seal-with-km / %open-with-km) is defined in
;; crypto.lisp (the first dds-security file) so BOTH this submessage tier AND the transform.lisp payload tier
;; reference the one instance across the load order (DRY) — Fast-DDS-faithful empty AAD, see its docstring.

(defconstant +sec-submessage-header-len+ 4
  "RTPS SubmessageHeader width = submessageId(1)+flags(1)+octetsToNextHeader(u16) (DDSI-RTPS 2.5
   §9.4.5.1); NOT re-pinning the dds.rtps constant, just the local extent for the inlined header.")

;;; --- protection-mode <-> on-wire CryptoTransformKind ---

(defun* %mode->kind (mode)
    (function ((member :sign :encrypt)) (simple-array (unsigned-byte 8) (*)))
  "Map the protection MODE keyword to its on-wire CryptoTransformKind octet[4] (§9.5.3.3.1 Table):
   :encrypt -> +transformation-kind-aes256-gcm+ {0,0,0,4}; :sign -> +transformation-kind-aes256-gmac+
   {0,0,0,3}. The kind written into the CryptoHeader is what the decoder dispatches on to know the
   framing: ENCRYPT opens a SEC_BODY ciphertext under empty AAD; SIGN verifies a GMAC over the original
   submessage that sits VERBATIM (no SEC_BODY) between SEC_PREFIX and SEC_POSTFIX (§9.5.3.3.4.3)."
  (ecase mode
    (:encrypt +transformation-kind-aes256-gcm+)
    (:sign    +transformation-kind-aes256-gmac+)))

(defun* %kind->mode (kind)
    (function ((simple-array (unsigned-byte 8) (*))) (or (member :sign :encrypt) null))
  "Inverse of %MODE->KIND: map a wire CryptoTransformKind octet[4] to its protection mode, or NIL
   for any unrecognised kind (fail-closed — never guess a mode for an unknown/AES128 transform)."
  (cond ((equalp kind +transformation-kind-aes256-gcm+)  :encrypt)
        ((equalp kind +transformation-kind-aes256-gmac+) :sign)
        (t nil)))

;;; --- inlined 4-octet RTPS SubmessageHeader (no dds.rtps dependency; see file note) ---

(defun* %write-sec-submessage-header (cursor submessage-id octets-to-next)
    (function (dds.core.buffer:cursor (unsigned-byte 8) (unsigned-byte 16)) fixnum)
  "Write a 4-octet RTPS SubmessageHeader at CURSOR (DDSI-RTPS 2.5 §9.4.5.1):
   submessageId(1) ‖ flags(1, E=1 little-endian) ‖ octetsToNextHeader(u16, cursor LE). Returns the
   new cursor position. Identical layout to dds.rtps.message:write-submessage-header, inlined to keep
   dds.security free of a dds.rtps dependency (see file note)."
  (dds.core.buffer:put-u8 cursor submessage-id)
  (dds.core.buffer:put-u8 cursor +sec-submessage-le-flags+)
  (dds.core.buffer:put-u16 cursor octets-to-next)
  (dds.core.buffer:cursor-position cursor))

(defun* %parse-sec-submessage-header (cursor)
    (function (dds.core.buffer:cursor) (or (unsigned-byte 8) null))
  "Parse a 4-octet RTPS SubmessageHeader at CURSOR; return its submessageId, advancing CURSOR past
   the 4 octets. The E flag (bit 0 of the flags octet, §9.4.5.1.2) selects octetsToNextHeader
   endianness independent of the cursor (read but not returned — this codec validates the bracket by
   submessageId + order + the bounds-checked inner CryptoContent length, not by octetsToNextHeader).
   check-room guards all 4 octets BEFORE any read; a shortfall signals buffer-overflow (caught by the
   decode handler -> NIL), never an OOB read (NFR-SEC-POSTURE), even at (safety 0)."
  (dds.core.buffer:check-room cursor +sec-submessage-header-len+)
  (let* ((id  (dds.core.buffer:get-u8 cursor))
         (le  (logbitp 0 (dds.core.buffer:get-u8 cursor)))
         (o0  (dds.core.buffer:get-u8 cursor))
         (o1  (dds.core.buffer:get-u8 cursor)))
    ;; octetsToNextHeader is read for spec-faithful cursor advance; the bracket integrity is enforced
    ;; downstream (kind/order + the inner length's own check-room), so the value is intentionally unused.
    (declare (ignore le o0 o1))
    id))

;;; --- origin authentication: receiver-specific session-key KDF + per-receiver MAC (§9.5.3.3.4.3, T3) ---
;;; The receiver-specific session key is the analogue of derive-session-key (crypto.lisp) under the
;;; +kdf-label-session-receiver-key+ label (so it lives HERE, where that constant — pinned in
;;; crypto/constants.lisp, loaded just before this file — is visible; key-material.lisp loads earlier).
;;; The per-receiver MAC is a pure GMAC over the common_mac under that key, using the SAME 12-octet init
;;; vector (session_id∥iv_suffix) as the common_mac. Both the input (common_mac) and the IV (shared with
;;; the common_mac) are corroborated CLEAN-ROOM (read-only) against eProsima Fast DDS (Apache-2.0)
;;; AESGCMGMAC_Transform.cpp serialize_SecureDataTag / deserialize_SecureDataTag (see docs/provenance.md).

(defun* derive-receiver-specific-session-key (master-receiver-specific-key master-salt session-id)
    (function ((simple-array (unsigned-byte 8) (*))
               (simple-array (unsigned-byte 8) (*))
               (simple-array (unsigned-byte 8) (*)))
              (simple-array (unsigned-byte 8) (32)))
  "Derive the 32-byte AES-256 receiver-specific session key for origin authentication
   (DDS-Security 1.1 §9.5.3.3.4.3):
     receiver_session_key = HMAC-SHA256(master_receiver_specific_key,
                                        'SessionReceiverKey' || master_salt || session_id).
   The receiver analogue of derive-session-key — the SAME framing (the shared %derive-labeled-session-key,
   DRY), only the label differs (+kdf-label-session-receiver-key+ vs +session-key-id-string+). Consumed by
   compute-receiver-specific-mac on encode and %verify-receiver-mac on decode (T4/T6/T8 reuse it).
   MASTER-RECEIVER-SPECIFIC-KEY/MASTER-SALT 32 octets, SESSION-ID 4 octets. Returns a fresh 32-byte vector.
   NO trailing counter — Fast-DDS/Cyclone-aligned. Corroborated CLEAN-ROOM against Fast DDS
   AESGCMGMAC_Transform.cpp compute_sessionkey(receiver_specific=true) (source = receiver_seq(18) ‖
   master_salt(32) ‖ session_id(4), no counter; label at L1481) AND Cyclone crypto_calculate_session_key
   (T-RECONCILE reconciled the wire to drop the prior '0001' counter; see docs/provenance.md)."
  (%require-len master-receiver-specific-key 32 "master_receiver_specific_key")
  (%require-len master-salt                  32 "master_salt")
  (%require-len session-id                    4 "session_id")
  (%derive-labeled-session-key master-receiver-specific-key master-salt session-id
                               +kdf-label-session-receiver-key+))

(defun* compute-receiver-specific-mac (recv-session-key nonce common-mac)
    (function ((simple-array (unsigned-byte 8) (*))
               (simple-array (unsigned-byte 8) (*))
               (simple-array (unsigned-byte 8) (*)))
              (simple-array (unsigned-byte 8) (*)))
  "Compute the 16-octet per-receiver GMAC for origin authentication (DDS-Security 1.1 §9.5.3.3.4.3):
   AES-256-GCM under RECV-SESSION-KEY with NONCE (the SAME 12-octet init vector session_id∥iv_suffix the
   common_mac was sealed with), AAD = COMMON-MAC (16 octets), EMPTY plaintext — the resulting 16-octet
   GCM tag IS the receiver_mac. RECV-SESSION-KEY 32 octets, NONCE 12 octets, COMMON-MAC 16 octets.
   Returns the 16-octet tag (typed loosely, as dds.dare:aes-256-gcm-seal returns the tag).
   Corroborated CLEAN-ROOM against Fast DDS AESGCMGMAC_Transform.cpp serialize_SecureDataTag: the receiver
   MAC reuses the common_mac's initialization_vector (L1771 comment 'the same Initialization Vector as
   before'; EVP_EncryptInit L1790-1792) and feeds tag.common_mac (16 octets) as AAD with NO ciphertext
   (EVP_EncryptUpdate(NULL,…,common_mac,16) L1800; EVP_CTRL_GCM_GET_TAG 16 L1815). See docs/provenance.md."
  (%require-len recv-session-key 32 "receiver_session_key")
  (%require-len nonce            12 "init_vector")
  (%require-len common-mac       16 "common_mac")
  (multiple-value-bind (ct tag)
      (dds.dare:aes-256-gcm-seal recv-session-key nonce common-mac +empty-octets+)
    (declare (ignore ct))
    tag))

(defun* %ct-equal (a b)
    (function ((simple-array (unsigned-byte 8) (*)) (simple-array (unsigned-byte 8) (*))) boolean)
  "Constant-time octet-vector equality for the receiver-MAC check — no early-exit byte compare that
   leaks where the first mismatch is. Returns NIL immediately ONLY on a length mismatch (length is
   public; both are 16-octet MACs); otherwise XOR-accumulates every byte and tests the accumulator for
   zero, so the per-byte work is identical for equal and unequal inputs of equal length (NFR-SEC-POSTURE)."
  (let ((na (length a)) (nb (length b)))
    (if (/= na nb)
        nil
        (let ((acc 0))
          (declare (type (unsigned-byte 8) acc))
          (dotimes (i na)
            (setf acc (logior acc (logxor (aref a i) (aref b i)))))
          (zerop acc)))))

(defun* %compute-receiver-macs (km session-id iv-suffix common-mac receivers)
    (function (key-material
               (simple-array (unsigned-byte 8) (*)) (simple-array (unsigned-byte 8) (*))
               (simple-array (unsigned-byte 8) (*)) list)
              list)
  "Build the CryptoFooter receiver_specific_macs list (origin authentication, §9.5.3.3.4.3) for ENCODE —
   the counterpart of %verify-receiver-mac. For each receiver descriptor
   (receiver-key-id . master-receiver-specific-key) in RECEIVERS, derive the receiver-specific session
   key (KM's master_salt, SESSION-ID) and compute its GMAC over COMMON-MAC with nonce = session_id∥
   iv_suffix (the SAME init vector the common_mac was sealed with); return the list of
   (receiver-key-id . mac) conses in RECEIVERS order. EMPTY RECEIVERS -> NIL (plain SIGN/ENCRYPT,
   rsm_count 0). Corroborated against Fast DDS serialize_SecureDataTag (see docs/provenance.md)."
  (when receivers
    (let ((nonce (%km-nonce session-id iv-suffix))
          (salt  (key-material-master-salt km)))
      (mapcar (lambda (r)
                (cons (car r)
                      (compute-receiver-specific-mac
                       (derive-receiver-specific-session-key (cdr r) salt session-id)
                       nonce common-mac)))
              receivers))))

(defun* %verify-receiver-mac (km session-id iv-suffix common-mac receiver-macs
                              my-receiver-key-id my-receiver-key)
    (function (key-material
               (simple-array (unsigned-byte 8) (*)) (simple-array (unsigned-byte 8) (*))
               (simple-array (unsigned-byte 8) (*)) list
               (or (simple-array (unsigned-byte 8) (*)) null)
               (or (simple-array (unsigned-byte 8) (*)) null))
              boolean)
  "Origin-authentication gate (DDS-Security 1.1 §9.5.3.3.4.3) — the DECODE counterpart of
   %compute-receiver-macs. When MY-RECEIVER-KEY-ID is NIL, origin-auth is NOT requested -> T (the
   common_mac alone governs; backward-compatible). When set: fail-closed (NIL) if MY-RECEIVER-KEY is NIL,
   or if no RECEIVER-MACS entry's key_id equals MY-RECEIVER-KEY-ID (the message does not target this
   receiver). Otherwise recompute this receiver's GMAC — derive-receiver-specific-session-key over
   MY-RECEIVER-KEY, KM's master_salt and SESSION-ID, then compute-receiver-specific-mac over COMMON-MAC
   with nonce = session_id∥iv_suffix (the SAME init vector as the common_mac) — and %ct-equal it against
   the wire mac; mismatch -> NIL. The key_id LOOKUP is not constant-time (key_ids are public); the MAC
   COMPARE is (no early-exit leak). Mirrors Fast DDS deserialize_SecureDataTag (find key_id, then verify
   the GMAC under the same IV; see docs/provenance.md). Runs inside %decode-secured-submessage's
   fail-closed handler, so any signal still resolves to NIL."
  (if (null my-receiver-key-id)
      t
      (and my-receiver-key
           (let ((entry (assoc my-receiver-key-id receiver-macs :test #'equalp)))
             (and entry
                  (%ct-equal (compute-receiver-specific-mac
                              (derive-receiver-specific-session-key
                               my-receiver-key (key-material-master-salt km) session-id)
                              (%km-nonce session-id iv-suffix)
                              common-mac)
                             (cdr entry)))))))

;;; --- encode (shared core for datawriter + datareader; §8.5 — same mechanism, no copy-paste) ---

(defun* %encode-secured-region (km mode plain-region receivers prefix-kind postfix-kind
                                &optional (session-id +fixed-session-id+))
    (function (key-material (member :sign :encrypt) (simple-array (unsigned-byte 8) (*)) list
               (unsigned-byte 8) (unsigned-byte 8) &optional (simple-array (unsigned-byte 8) (*)))
              (or (simple-array (unsigned-byte 8) (*)) null))
  "Build the PREFIX-KIND ... POSTFIX-KIND bracket protecting the octet region PLAIN-REGION under KM per
   MODE — the SHARED engine behind BOTH the §8.5.1.7-.9 submessage tier (PREFIX-KIND/POSTFIX-KIND =
   SEC_PREFIX 0x31 / SEC_POSTFIX 0x32; PLAIN-REGION = one submessage) AND the §8.5.1.10-.12 whole-RTPS
   tier (T4: SRTPS_PREFIX 0x33 / SRTPS_POSTFIX 0x34; PLAIN-REGION = the whole submessage stream). The two
   tiers are the SAME crypto mechanism — only the bracket submessage ids and the protected unit differ
   (DRY, no copy-paste). RECEIVERS is the origin-authentication receiver list — a list of
   (receiver-key-id . master-receiver-specific-key) conses, EMPTY for plain SIGN/ENCRYPT. AFTER the seal,
   %compute-receiver-macs derives each receiver-specific session key + GMAC over the common_mac (same IV)
   and the (key_id . mac) entries fill the CryptoFooter receiver_specific_macs (§9.5.3.3.4.3); an empty
   RECEIVERS writes rsm_count 0 (the plain Slice-1/T2 tag).
   SESSION-ID (optional, default +fixed-session-id+ = all-zeros, the Slice-1/T2/T4 corpus value — DO NOT
   perturb the non-PVMS tiers): the 4-octet §9.5.3.3.4.4 session_id written into the CryptoHeader and
   folded into BOTH the session-key KDF and the AES-GCM nonce. T8 passes a per-role NON-ZERO session_id for
   the SYMMETRIC PVMS bootstrap KM so the two directions use DISJOINT (key, nonce) spaces — no AES-GCM nonce
   reuse across the pair (decode reads session_id from the wire, so this is self-describing; see
   dds.disc:%pvms-role-session-id and docs/provenance.md M7/P6 T8).
   Steps:
     1. Claim a UNIQUE iv_suffix from KM's monotonic counter (%km-next-iv-suffix; structural nonce
        uniqueness).
     2. %seal-with-km (DRY): derive the session key, nonce = session_id∥iv_suffix, AES-256-GCM seal.
        ENCRYPT seals the region under EMPTY AAD -> (ciphertext, tag). SIGN seals EMPTY plaintext
        under the region as AAD -> (empty, tag=GMAC).
     3. Assemble the bracket into an off-heap (static-arena) scratch buffer via the T1 codec — ENCRYPT
        inserts a SEC_BODY (0x30) holding the length-prefixed ciphertext (§9.5.3.3.4.4); SIGN inserts
        NO SEC_BODY, writing the region VERBATIM between PREFIX and POSTFIX (§9.5.3.3.4.3) — then return
        a fresh heap copy (no caller free obligation) and free the scratch.
   Returns NIL only if the AEAD primitive itself fails (it does not, for well-formed inputs)."
  (let* ((iv-suffix  (%km-next-iv-suffix km))
         (session-id (copy-seq session-id))
         (kind       (%mode->kind mode))
         (key-id     (key-material-sender-key-id km)))
    (multiple-value-bind (ciphertext tag)
        (ecase mode
          (:encrypt (%seal-with-km km session-id iv-suffix +empty-octets+ plain-region))
          (:sign    (%seal-with-km km session-id iv-suffix plain-region +empty-octets+)))
      ;; Between PREFIX and POSTFIX: ENCRYPT inserts a SEC_BODY (0x30) holding the length-prefixed
      ;; ciphertext (§9.5.3.3.4.4); SIGN/GMAC inserts NO SEC_BODY — the region VERBATIM (§9.5.3.3.4.3) —
      ;; so the middle region's length + writer are mode-dependent. common_mac = tag.
      ;; Origin auth (§9.5.3.3.4.3): derive each receiver's GMAC over the common_mac (same IV) AFTER the
      ;; seal — empty RECEIVERS -> empty list -> rsm_count 0 (the plain SIGN/ENCRYPT tag, unchanged).
      (let* ((receiver-macs (%compute-receiver-macs km session-id iv-suffix tag receivers))
             (postfix-len (+ +common-mac-len+ +receiver-specific-macs-count-len+
                             (* (length receiver-macs)
                                (+ +transformation-key-id-len+ +common-mac-len+))))
             ;; ENCRYPT SEC_BODY 4-align pad: zero octets AFTER the ciphertext so the SEC_POSTFIX starts
             ;; 4-aligned (Fast DDS serialize_SecureDataBody, L1692-1702: "Align submessage to 4"). The
             ;; SEC_BODY content starts 4-aligned (PREFIX 24 + SEC_BODY hdr 4 + cnt_length 4 = 32), so the
             ;; align reduces to (-|ciphertext| mod 4); the plaintext is NEVER padded (the recovered submessage
             ;; reflects its TRUE length). SIGN has no SEC_BODY -> no pad here (its alignment is the T12 carry).
             (ct-pad (ecase mode (:encrypt (mod (- (length ciphertext)) 4)) (:sign 0)))
             (mid-len (ecase mode
                        (:encrypt (+ +sec-submessage-header-len+ +crypto-content-length-len+
                                     (length ciphertext) ct-pad))
                        (:sign    (length plain-region))))
             (total (+ +sec-submessage-header-len+ +secure-data-header-len+   ; PREFIX
                       mid-len                                                 ; SEC_BODY (ENCRYPT) | verbatim (SIGN)
                       +sec-submessage-header-len+ postfix-len))              ; POSTFIX
             (scratch (dds.pal:alloc-static total)))      ; off-heap assembly scratch (NFR-MEM)
        (unwind-protect
             (let ((cur (dds.core.buffer:cursor (dds.core.buffer:octet-buffer-over scratch)
                                                :endianness :little)))
               (%write-sec-submessage-header cur prefix-kind +secure-data-header-len+)
               (serialize-crypto-header cur kind key-id session-id iv-suffix)
               (ecase mode
                 ;; ENCRYPT: SEC_BODY (0x30) ‖ crypto_content (cnt_length = TRUE ciphertext length, BE)
                 ;; ‖ ciphertext ‖ 4-align pad (§9.5.3.3.4.4; Fast DDS serialize_SecureDataBody L1677-1702:
                 ;; octetsToNextHeader = (|ciphertext|+4+3)&~3 covers cnt_length + ciphertext + pad).
                 (:encrypt (%write-sec-submessage-header cur +submessage-sec-body+
                                                         (+ +crypto-content-length-len+ (length ciphertext) ct-pad))
                           (serialize-crypto-content cur ciphertext)
                           (dotimes (_ ct-pad) (dds.core.buffer:put-u8 cur 0)))
                 ;; SIGN: the region VERBATIM, no SEC_BODY, no length prefix (§9.5.3.3.4.3).
                 (:sign (dds.core.buffer:put-octets cur plain-region 0 (length plain-region))))
               (%write-sec-submessage-header cur postfix-kind postfix-len)
               (serialize-crypto-footer cur tag receiver-macs)
               (subseq scratch 0 total))                  ; fresh heap copy; caller need not free
          (dds.pal:free-static scratch))))))

(defun* %encode-secured-submessage (km mode plain-submessage receivers
                                    &optional (session-id +fixed-session-id+))
    (function (key-material (member :sign :encrypt) (simple-array (unsigned-byte 8) (*)) list
               &optional (simple-array (unsigned-byte 8) (*)))
              (or (simple-array (unsigned-byte 8) (*)) null))
  "Build the SEC_PREFIX(0x31) ... SEC_POSTFIX(0x32) submessage-protection bracket (§8.5.1.7-.9) over
   PLAIN-SUBMESSAGE — the thin submessage-tier wrapper over the shared %encode-secured-region (the §8.5
   DataWriter and DataReader submessage protection transforms are the SAME mechanism; the whole-RTPS tier
   reuses the same engine with the SRTPS kinds, T4). SESSION-ID threads through to the bracket's CryptoHeader
   + nonce (default +fixed-session-id+, unchanged for the non-PVMS tiers; T8 PVMS passes a per-role
   non-zero value). See %encode-secured-region for the full contract."
  (%encode-secured-region km mode plain-submessage receivers
                          +submessage-sec-prefix+ +submessage-sec-postfix+ session-id))

(defun* encode-datawriter-submessage (km kind plain-submessage &key (receivers '())
                                      (session-id +fixed-session-id+))
    (function (key-material (member :sign :encrypt) (simple-array (unsigned-byte 8) (*))
               &key (:receivers list) (:session-id (simple-array (unsigned-byte 8) (*))))
              (or (simple-array (unsigned-byte 8) (*)) null))
  "Protect a DataWriter RTPS submessage (PLAIN-SUBMESSAGE octets) under KM per KIND (:sign | :encrypt)
   per DDS-Security 1.1 §8.5.1.7/.9; return the SEC_PREFIX ... SEC_POSTFIX octets, or NIL.
   :encrypt hides the plaintext (a SEC_BODY carries the ciphertext, empty AAD); :sign leaves the
   ORIGINAL submessage verbatim between PREFIX and POSTFIX with NO SEC_BODY (§9.5.3.3.4.3) and a GMAC
   common_mac (original-submessage-as-AAD). RECEIVERS enables origin authentication (the
   *_WITH_ORIGIN_AUTHENTICATION kinds, §9.5.3.3.4.3): a list of
   (receiver-key-id . master-receiver-specific-key) conses (4- and 32-octet vectors); for each, a
   receiver-specific GMAC over the common_mac is emitted into the CryptoFooter receiver_specific_macs.
   EMPTY RECEIVERS (the default) is plain SIGN/ENCRYPT (rsm_count 0).
   SESSION-ID (§9.5.3.3.4.4; default +fixed-session-id+ = all-zeros, the byte-exact corpus value for the
   Slice-1/T2/T4 tiers — UNCHANGED): the 4-octet session_id carried in the CryptoHeader and folded into the
   session-key KDF + AES-GCM nonce. T8's PVMS bootstrap-KM path passes a per-role NON-ZERO session_id so the
   two directions of the SYMMETRIC bootstrap key never share a (key, nonce) — the nonce-disjointness that
   prevents catastrophic AES-GCM reuse (dds.disc:%pvms-role-session-id). Inverse: decode-datawriter-submessage."
  (%encode-secured-submessage km kind plain-submessage receivers session-id))

(defun* encode-datareader-submessage (km kind plain-submessage &key (receivers '())
                                      (session-id +fixed-session-id+))
    (function (key-material (member :sign :encrypt) (simple-array (unsigned-byte 8) (*))
               &key (:receivers list) (:session-id (simple-array (unsigned-byte 8) (*))))
              (or (simple-array (unsigned-byte 8) (*)) null))
  "Protect a DataReader RTPS submessage (e.g. ACKNACK / NACK_FRAG) under KM per KIND, per
   DDS-Security 1.1 §8.5.1.8/.9. SAME transform as encode-datawriter-submessage (§8.5; the
   DataWriter/DataReader split is which submessages each protects, not the crypto) — both delegate to
   the one shared engine (%encode-secured-submessage), no copy-paste. RECEIVERS enables origin
   authentication exactly as for encode-datawriter-submessage. SESSION-ID threads identically (default
   +fixed-session-id+, unchanged; T8 PVMS per-role non-zero). Inverse: decode-datareader-submessage."
  (%encode-secured-submessage km kind plain-submessage receivers session-id))

;;; --- decode (shared core; fail-closed) ---

(defun* %parse-sec-postfix-mac (cursor postfix-kind)
    (function (dds.core.buffer:cursor (unsigned-byte 8))
              (values (or (simple-array (unsigned-byte 8) (*)) null) list))
  "Parse the POSTFIX-KIND submessage ‖ its §7.3.7 CryptoFooter at CURSOR; return (values COMMON-MAC
   RECEIVER-MACS) — COMMON-MAC the 16-octet common_mac (NIL first value on any bracket/shortfall failure,
   fail-closed; NFR-SEC-POSTURE) and RECEIVER-MACS the parsed (and bounds-/count-capped by
   parse-crypto-footer) receiver_specific_macs list of (key_id . mac) conses (possibly empty). POSTFIX-KIND
   is +submessage-sec-postfix+ (0x32, submessage tier) or +submessage-srtps-postfix+ (0x34, RTPS tier).
   Shared by the ENCRYPT and SIGN decode branches of BOTH tiers — the trailing-CryptoFooter framing is
   identical (DRY). The origin-auth gate (%verify-receiver-mac) consumes RECEIVER-MACS (T3)."
  (if (eql (%parse-sec-submessage-header cursor) postfix-kind)
      (parse-crypto-footer cursor)
      (values nil '())))

(defun* %read-embedded-submessage (cursor)
    (function (dds.core.buffer:cursor) (simple-array (unsigned-byte 8) (*)))
  "Read one complete embedded RTPS submessage VERBATIM at CURSOR and return it as a fresh
   (4 + octetsToNextHeader)-octet vector, advancing CURSOR past it. Layout (DDSI-RTPS 2.5 §9.4.5.1):
   submessageId(1) ‖ flags(1) ‖ octetsToNextHeader(u16, endianness per the embedded E flag = bit 0 of
   flags, §9.4.5.1.2) ‖ octetsToNextHeader payload octets. This is the AES256-GMAC (SIGN) recovery
   (DDS-Security 1.1 §9.5.3.3.4.3): SIGN protection emits NO SEC_BODY — the original submessage sits
   VERBATIM between SEC_PREFIX and SEC_POSTFIX — so decode parses the submessage's OWN header to find
   its extent (distinct from %parse-sec-submessage-header, which discards the header bytes + length).
   check-room guards the payload extent BEFORE allocating the result and get-octets bounds-checks each
   read; a truncated / over-declared embedded length signals buffer-overflow (caught -> NIL by the
   decode handler), never an OOB read or an unbounded allocation (NFR-SEC-POSTURE), even at (safety 0)."
  (let ((hdr (make-array +sec-submessage-header-len+ :element-type '(unsigned-byte 8))))
    (dds.core.buffer:get-octets cursor hdr 0 +sec-submessage-header-len+)
    (let ((octn (if (logbitp 0 (aref hdr 1))
                    (logior (aref hdr 2) (ash (aref hdr 3) 8))      ; E=1 little-endian
                    (logior (ash (aref hdr 2) 8) (aref hdr 3)))))   ; E=0 big-endian
      (dds.core.buffer:check-room cursor octn)
      (let ((out (make-array (+ +sec-submessage-header-len+ octn) :element-type '(unsigned-byte 8))))
        (replace out hdr)
        (dds.core.buffer:get-octets cursor out +sec-submessage-header-len+ octn)
        out))))

(defun* %walk-verbatim-body (cursor postfix-kind secured-octets)
    (function (dds.core.buffer:cursor (unsigned-byte 8) (simple-array (unsigned-byte 8) (*)))
              (simple-array (unsigned-byte 8) (*)))
  "Recover the SIGN/GMAC body of a WHOLE-RTPS-message bracket (T4, §8.5.1.10-.12 / §9.5.3.3.4.3): the
   protected unit is the ENTIRE submessage STREAM, which sits VERBATIM (no SEC_BODY) between SRTPS_PREFIX
   and the trailing SRTPS_POSTFIX. Starting at CURSOR (just after the CryptoHeader), WALK the stream
   submessage-by-submessage — reading each 4-octet RTPS SubmessageHeader (id ‖ flags ‖ octetsToNextHeader,
   DDSI-RTPS 2.5 §9.4.5.1, the embedded E flag = bit 0 of flags selecting octetsToNextHeader endianness)
   and advancing octetsToNextHeader payload octets — until the next submessageId equals POSTFIX-KIND
   (0x34); return the verbatim body = SECURED-OCTETS[body-start, postfix-start) and REWIND CURSOR to the
   postfix start so the shared %parse-sec-postfix-mac re-reads the postfix header + CryptoFooter (DRY).
   This is the §8.5.1.12 decode-locate, corroborated CLEAN-ROOM against Fast DDS decode_rtps_message (the
   `while (!is_encrypted && id != SRTPS_POSTFIX)` submessage-skip loop; see docs/provenance.md, M7/P6 T4).
   Self-consistent with %encode-secured-region's verbatim write: NO inter-submessage 4-byte re-alignment
   (the encode pads none); live cross-vendor alignment reconciliation is deferred to T12.
   check-room guards EVERY 4-octet header read AND each octetsToNextHeader advance BEFORE it happens, so a
   truncated / over-declared / postfix-less stream signals buffer-overflow (caught -> NIL by the decode
   handler), never an OOB read, an unbounded scan, or a non-terminating loop (each iteration advances >=4
   octets, bounded by the buffer extent), even at (safety 0) (NFR-SEC-POSTURE)."
  (let ((body-start (dds.core.buffer:cursor-position cursor)))
    (loop
      (let ((mark (dds.core.buffer:cursor-position cursor)))
        (dds.core.buffer:check-room cursor +sec-submessage-header-len+)
        (let ((id (dds.core.buffer:get-u8 cursor)))
          (when (eql id postfix-kind)
            ;; rewind to the postfix submessage start; the shared postfix parser re-reads it (DRY).
            (dds.core.buffer:cursor-set-position cursor mark)
            (return (subseq secured-octets body-start mark)))
          (let* ((flags (dds.core.buffer:get-u8 cursor))
                 (o0    (dds.core.buffer:get-u8 cursor))
                 (o1    (dds.core.buffer:get-u8 cursor))
                 (octn  (if (logbitp 0 flags)
                            (logior o0 (ash o1 8))          ; E=1 little-endian
                            (logior (ash o0 8) o1))))       ; E=0 big-endian
            (dds.core.buffer:check-room cursor octn)
            (dds.core.buffer:cursor-set-position cursor
                                                 (+ (dds.core.buffer:cursor-position cursor) octn))))))))

(defun* %decode-secured-region (km secured-octets my-receiver-key-id my-receiver-key
                                prefix-kind postfix-kind sign-walk-p)
    (function (key-material (simple-array (unsigned-byte 8) (*))
               (or (simple-array (unsigned-byte 8) (*)) null)
               (or (simple-array (unsigned-byte 8) (*)) null)
               (unsigned-byte 8) (unsigned-byte 8) t)
              (or (simple-array (unsigned-byte 8) (*)) null))
  "Recover the protected region from a PREFIX-KIND ... POSTFIX-KIND bracket produced by
   %encode-secured-region, or NIL on ANY failure (fail-closed; NFR-SEC-POSTURE) — the SHARED engine
   behind BOTH the submessage tier (decode-datawriter-/datareader-submessage; PREFIX/POSTFIX-KIND =
   SEC_PREFIX/SEC_POSTFIX, SIGN-WALK-P NIL) AND the whole-RTPS tier (decode-rtps-message, T4; SRTPS_PREFIX/
   SRTPS_POSTFIX, SIGN-WALK-P T). The wire CryptoHeader.transformation_kind (parsed from the prefix)
   selects the mode AND the framing:
     ENCRYPT — PREFIX ‖ SEC_BODY(0x30, length-prefixed ciphertext) ‖ POSTFIX; open the ciphertext under
       EMPTY AAD (§9.5.3.3.4.4). Identical for both tiers.
     SIGN — PREFIX ‖ <region VERBATIM, no SEC_BODY> ‖ POSTFIX; recover the region, verify the GMAC over it
       (AAD = the region), return it (§9.5.3.3.4.3). Locating the verbatim region is the ONLY tier
       difference: SIGN-WALK-P NIL reads ONE embedded submessage (%read-embedded-submessage, submessage
       tier); SIGN-WALK-P T WALKS the whole submessage stream to the trailing postfix
       (%walk-verbatim-body, RTPS tier — corroborated against Fast DDS decode_rtps_message).
   ORIGIN AUTH (§9.5.3.3.4.3): when MY-RECEIVER-KEY-ID is non-NIL, AFTER the common_mac verifies the
   gate %verify-receiver-mac MUST also find + verify THIS receiver's entry in the CryptoFooter
   receiver_specific_macs (recompute under MY-RECEIVER-KEY, constant-time compare); absent or mismatched
   -> NIL even though the common_mac is valid. MY-RECEIVER-KEY-ID NIL = origin-auth not expected (the
   common_mac alone governs; backward-compatible). The bracket (submessageId + order) is validated and
   every field is bounds-checked against the buffer extent BEFORE use (the T1 parsers +
   %parse-sec-submessage-header + %read-embedded-submessage + %walk-verbatim-body all check-room first).
   Any malformed / truncated / re-ordered / unknown-kind / GMAC-or-GCM-auth-fail / receiver-MAC-fail input
   -> NIL, never an OOB read, never a signal escaping to the caller, never a tampered region on a failure,
   even at (safety 0)."
  (handler-case
      (block decode
        (let ((cur (dds.core.buffer:cursor (dds.core.buffer:octet-buffer-over secured-octets)
                                           :endianness :little)))
          ;; PREFIX -> CryptoHeader -> mode (the wire transformation_kind selects the framing).
          (unless (eql (%parse-sec-submessage-header cur) prefix-kind)
            (return-from decode nil))
          (multiple-value-bind (kind key-id session-id iv-suffix) (parse-crypto-header cur)
            (declare (ignore key-id))
            (unless kind (return-from decode nil))
            (let ((mode (%kind->mode kind)))
              (unless mode (return-from decode nil))
              (ecase mode
                ;; ENCRYPT: SEC_BODY(0x30) ciphertext -> POSTFIX -> open under EMPTY AAD.
                (:encrypt
                 (unless (eql (%parse-sec-submessage-header cur) +submessage-sec-body+)
                   (return-from decode nil))
                 (let ((body (parse-crypto-content cur)))
                   (unless body (return-from decode nil))
                   ;; Skip the SEC_BODY 4-align pad (zero octets after the ciphertext) so the SEC_POSTFIX is
                   ;; read 4-aligned (Fast DDS deserialize_SecureDataBody L2052-2061 "Align submessage to 4").
                   ;; The cursor position is bracket-relative (origin 0 at the bracket start), so the pad is
                   ;; (-pos) mod 4 — fixed by the bracket-relative position alone, never the bracket's datagram
                   ;; offset. check-room bounds it -> a pad overrunning the bracket fails closed (the outer
                   ;; handler -> NIL), never an OOB read, even at (safety 0) (NFR-SEC-POSTURE).
                   (let ((pad (mod (- (dds.core.buffer:cursor-position cur)) 4)))
                     (when (plusp pad)
                       (dds.core.buffer:check-room cur pad)
                       (dds.core.buffer:cursor-set-position cur (+ (dds.core.buffer:cursor-position cur) pad))))
                   (multiple-value-bind (common-mac receiver-macs)
                       (%parse-sec-postfix-mac cur postfix-kind)
                     (unless common-mac (return-from decode nil))
                     (let ((pt (%open-with-km km session-id iv-suffix +empty-octets+ body common-mac)))
                       (and pt
                            (%verify-receiver-mac km session-id iv-suffix common-mac receiver-macs
                                                  my-receiver-key-id my-receiver-key)
                            pt)))))
                ;; SIGN: NO SEC_BODY — the region is VERBATIM here (§9.5.3.3.4.3). Recover it (one
                ;; submessage, or WALK the whole stream), verify the GMAC over it (AAD), return it; never
                ;; the bytes if the GMAC fails.
                (:sign
                 (let ((original (if sign-walk-p
                                     (%walk-verbatim-body cur postfix-kind secured-octets)
                                     (%read-embedded-submessage cur))))
                   (multiple-value-bind (common-mac receiver-macs)
                       (%parse-sec-postfix-mac cur postfix-kind)
                     (unless common-mac (return-from decode nil))
                     (and (%open-with-km km session-id iv-suffix original +empty-octets+ common-mac)
                          (%verify-receiver-mac km session-id iv-suffix common-mac receiver-macs
                                                my-receiver-key-id my-receiver-key)
                          original)))))))))
    ;; Any condition (bounds, malformed, etc.) -> NIL (fail-closed).
    (error () nil)))

(defun* %decode-secured-submessage (km secured-octets my-receiver-key-id my-receiver-key)
    (function (key-material (simple-array (unsigned-byte 8) (*))
               (or (simple-array (unsigned-byte 8) (*)) null)
               (or (simple-array (unsigned-byte 8) (*)) null))
              (or (simple-array (unsigned-byte 8) (*)) null))
  "Recover the plaintext submessage from a SEC_PREFIX(0x31) ... SEC_POSTFIX(0x32) bracket (§8.5.1.7-.9) —
   the thin submessage-tier wrapper over the shared %decode-secured-region (SIGN reads ONE embedded
   submessage; SIGN-WALK-P NIL). See %decode-secured-region for the full fail-closed / origin-auth
   contract. Fail-closed: any malformed/truncated/tampered input -> NIL."
  (%decode-secured-region km secured-octets my-receiver-key-id my-receiver-key
                          +submessage-sec-prefix+ +submessage-sec-postfix+ nil))

(defun* decode-datawriter-submessage (km secured-octets &key (my-receiver-key-id nil) (my-receiver-key nil))
    (function (key-material (simple-array (unsigned-byte 8) (*))
               &key (:my-receiver-key-id (or (simple-array (unsigned-byte 8) (*)) null))
                    (:my-receiver-key (or (simple-array (unsigned-byte 8) (*)) null)))
              (or (simple-array (unsigned-byte 8) (*)) null))
  "Recover the plaintext DataWriter submessage from SECURED-OCTETS (the SEC_PREFIX ... SEC_POSTFIX
   bracket from encode-datawriter-submessage — SEC_BODY for ENCRYPT, the original submessage verbatim
   for SIGN, §9.5.3.3.4.3) under KM, or NIL on any failure (fail-closed; DDS-Security 1.1 §8.5.1.7/.9).
   For origin authentication (§9.5.3.3.4.3), pass MY-RECEIVER-KEY-ID (this receiver's 4-octet
   receiver_specific_key_id) and MY-RECEIVER-KEY (its 32-octet master_receiver_specific_key): the decoder
   then ALSO verifies this receiver's entry in the CryptoFooter receiver_specific_macs and fails-closed
   (NIL) if it is absent or does not match, even when the common_mac is valid. Both NIL (default) =
   origin-auth not expected. Delegates to the shared %decode-secured-submessage engine."
  (%decode-secured-submessage km secured-octets my-receiver-key-id my-receiver-key))

(defun* decode-datareader-submessage (km secured-octets &key (my-receiver-key-id nil) (my-receiver-key nil))
    (function (key-material (simple-array (unsigned-byte 8) (*))
               &key (:my-receiver-key-id (or (simple-array (unsigned-byte 8) (*)) null))
                    (:my-receiver-key (or (simple-array (unsigned-byte 8) (*)) null)))
              (or (simple-array (unsigned-byte 8) (*)) null))
  "Recover the plaintext DataReader submessage from SECURED-OCTETS under KM, or NIL on any failure
   (fail-closed; DDS-Security 1.1 §8.5.1.8/.9). SAME mechanism as decode-datawriter-submessage — both
   delegate to %decode-secured-submessage, no copy-paste. MY-RECEIVER-KEY-ID / MY-RECEIVER-KEY enable
   origin-authentication verification exactly as for decode-datawriter-submessage."
  (%decode-secured-submessage km secured-octets my-receiver-key-id my-receiver-key))
