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
;;;; (%embedded-submessage-len); the RTPS tier wraps the whole submessage STREAM, so it WALKS
;;;; submessage-by-submessage to the trailing postfix (%walk-verbatim-len, sign-walk-p) — corroborated
;;;; CLEAN-ROOM against Fast DDS decode_rtps_message (see docs/provenance.md, M7/P6 T4).
;;;;
;;;; ZERO-ALLOC (Slice 2 / ZA-2): %encode-secured-region / %decode-secured-region are now thin ALLOCATING
;;;; wrappers over the into-buffer cores %encode-secured-region-into / %decode-secured-region-into, which
;;;; write/parse the bracket directly through a STATIC octet-buffer by RAW OFFSET (no cursor consed) — the
;;;; ZA-1 payload-tier trick extended to the submessage + whole-RTPS tiers. The cores are byte-IDENTICAL to
;;;; the pre-ZA-2 assembly (same field widths/offsets, big-endian %put-u32-be-at, §9.5.3.3.3/.4.4 4-align
;;;; pads, aes-256-gcm-seal-into ct+tag), so the T2/T4 byte-exact corpora exercise them. Common-path encode
;;;; (RECEIVERS empty) + ENCRYPT decode are zero GC-heap alloc; SIGN decode materializes the verbatim region
;;;; once (open-into's full-length AAD).
;;;; ORIGIN AUTHENTICATION zero-alloc (WP-SECURITY-ORIGIN-AUTH-ZEROALLOC, ADR-0039 residual (a) closed): the
;;;; RECEIVERS (encode) / my-receiver-key (decode) *_WITH_ORIGIN_AUTHENTICATION path is now ALSO zero GC-heap
;;;; alloc — encode via %put-receiver-macs-into (each receiver GMAC written straight into the CryptoFooter by
;;;; offset via aes-256-gcm-seal-into pt-len-0 under the %km-receiver-session-key-at cached key + the in-place
;;;; common_mac/nonce), decode via %verify-receiver-mac-into (find + GMAC-verify THIS receiver's footer entry
;;;; IN PLACE via aes-256-gcm-open-into ct-len-0). The old allocating %compute-receiver-macs /
;;;; %verify-receiver-mac / %parse-sec-postfix-mac are RETAINED as byte-identity reference implementations.
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

(defun* %recv-key-id-eq-at (vec off key-id)
    (function ((simple-array (unsigned-byte 8) (*)) fixnum (simple-array (unsigned-byte 8) (*))) boolean)
  "T iff the 4-octet receiver_specific_key_id VEC[OFF..OFF+4] equals KEY-ID, compared BY OFFSET with no
   allocation (the CryptoFooter entry key_id match — key_ids are public, so a plain byte compare, not
   constant-time; NFR-SEC-POSTURE puts the constant-time compare on the MAC, not the id). Caller guarantees
   OFF+4 <= (length VEC) and (length KEY-ID) = +transformation-key-id-len+."
  (and (= (length key-id) +transformation-key-id-len+)
       (= (aref vec off)       (aref key-id 0))
       (= (aref vec (+ off 1)) (aref key-id 1))
       (= (aref vec (+ off 2)) (aref key-id 2))
       (= (aref vec (+ off 3)) (aref key-id 3))))

(defun* %km-receiver-session-key-at (km recv-key-id recv-master-key session-id-vec session-id-off)
    (function (key-material (simple-array (unsigned-byte 8) (*)) (simple-array (unsigned-byte 8) (*))
               (simple-array (unsigned-byte 8) (*)) fixnum)
              (simple-array (unsigned-byte 8) (32)))
  "Cached §9.5.3.3.4.3 receiver-specific session key for origin authentication — the receiver analogue of
   %km-session-key-at (key-material.lisp), closing the ADR-0039 residual (a) per-receiver KDF alloc. The key
   is HMAC-SHA256(RECV-MASTER-KEY, 'SessionReceiverKey' || KM.master_salt || session_id) — constant for a fixed
   (receiver master key, KM salt, session_id) triple, so it is derived ONCE and reused (zero-alloc on hit). The
   cache discriminant is (RECV-KEY-ID, RECV-MASTER-KEY, the 4-octet session_id at SESSION-ID-VEC[OFF..OFF+4]). The
   MASTER KEY is part of the discriminant, not just the 4-octet key_id: the SAME key_id may be presented with a
   DIFFERENT master key (a wrong-key origin-auth probe — an encoder that cached under the CORRECT key must NOT then
   hand a decoder verifying under a WRONG key the correct derived key), and the derived key depends on the master
   key — keying by key_id alone would return a stale key and bypass the receiver-MAC gate (the e2e origin-auth
   breach test). Single-slot + fence-published EXACTLY like %km-session-key-at: the hit path is lock-free +
   zero-alloc; the miss path stores key -> RELEASE fence -> session_id -> master_key -> key_id (the gate), and the
   hit path loads key_id + master_key + session_id -> ACQUIRE fence -> key, so a weak-memory reader that observes a
   matching (key_id, master_key, session_id) is guaranteed to see the published key (arm64/Apple Silicon; the
   operating contract §4). A torn read (any discriminant field stale) fails the match and re-derives — the
   deterministic HMAC makes a benign concurrent same-value miss harmless, and a wrong key can never forge a valid
   GMAC, so the WORST case is a spurious re-derive or a fail-closed drop, never an origin-auth bypass (mirrors
   %km-session-key-at's tear model — which ADR 0059 has since made IMPOSSIBLE: the four discriminant/key fields are
   now ONE immutable session-cache object published by a single store, so no reader can observe them torn apart).
   The derived key + the cached master-key discriminant copy are EPHEMERAL plain
   GC-HEAP vectors (re-derivable, GC-reclaimed, not secrets-at-rest — a foreign-static copy per session_id would
   leak un-wiped keys on session_id rotation; ADR-0034). FAIL-CLOSED: a zeroized KM signals
   KEY-MATERIAL-ZEROIZED-ERROR before touching the freed master_salt (a single flag check off the zero-alloc hit
   path)."
  (when (key-material-zeroized km) (error 'key-material-zeroized-error))   ; NOCOND(FAILFAST): use-after-free (KM used past zeroize/teardown); cannot fire in correct code; a NIL return would be a fail-open origin-auth bypass (ADR-0034) so it fail-fasts
  (assert (<= (+ session-id-off 4) (length session-id-vec)))   ; NOCOND(FAILFAST): bounds invariant on an already-length-validated secured payload; cannot fire in correct code; fail-fast on a corrupt/too-short vector
  (let ((sc (key-material-cached-recv-session km)))   ; ONE load of the published (discriminant, key) object (ADR 0059)
    (if (and sc
             (%recv-key-id-eq-at recv-key-id 0 (session-cache-recv-key-id sc))
             (equalp (session-cache-recv-master-key sc) recv-master-key)
             (%session-id-eq-at (session-cache-id sc) session-id-vec session-id-off))
        (progn
          ;; Acquire fence: the object's fields must be seen as the release-publishing thread wrote them.
          (dds.pal:fence :acquire)
          (session-cache-key sc))
        (let* ((sid (subseq session-id-vec session-id-off (+ session-id-off 4)))
               (k   (derive-receiver-specific-session-key recv-master-key (key-material-master-salt km) sid))  ; ephemeral GC-heap key
               (new (%make-session-cache                                  ; fully built BEFORE publication
                     sid k
                     (subseq recv-key-id 0 (length recv-key-id))              ; GC-heap discriminant copies
                     (subseq recv-master-key 0 (length recv-master-key)))))
          ;; Release fence: the object's fields are visible before the pointer that publishes them.
          (dds.pal:fence :release)
          (setf (key-material-cached-recv-session km) new)   ; ONE store: the FOUR discriminant/key fields can no longer be observed torn apart
          k))))

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

(defun* %put-receiver-macs-into (km vec sid-abs mac-abs entries-abs receivers)
    (function (key-material (simple-array (unsigned-byte 8) (*)) fixnum fixnum fixnum list) (eql t))
  "ZERO-ALLOC ENCODE of the CryptoFooter receiver_specific_macs (origin authentication, §9.5.3.3.4.3) — the
   into-buffer core behind %encode-secured-region-into's origin-auth branch, closing the ADR-0039 residual (a)
   allocating %compute-receiver-macs fallback. For each (receiver_specific_key_id . master_receiver_specific_key)
   in RECEIVERS, write its 20-octet {key_id(4) ‖ GMAC(16)} entry directly into VEC starting at ENTRIES-ABS, in
   order, BY RAW OFFSET: the key_id is copied in place (replace, no cons) and the GMAC is written straight into the
   footer via aes-256-gcm-seal-into with pt-len 0 (the T1 GMAC-into) — AAD = the common_mac read IN PLACE at
   VEC[MAC-ABS..+16], nonce = the CryptoHeader session_id‖iv_suffix sub-slice IN PLACE at VEC[SID-ABS..+12] (the
   SAME 12-octet init vector the common_mac was sealed with), key = the receiver-specific session key from the
   %km-receiver-session-key-at cache (derived once per (key_id, session_id) — zero-alloc on hit). Byte-IDENTICAL to
   the allocating %compute-receiver-macs path (same GMAC over the same common_mac under the same derived key), so the
   T3 128/120 origin-auth corpus proves it. AAD aliases OUT's backing memory — safe (EVP consumes AAD before
   GET_TAG writes the tag; aes-256-gcm-seal-into docstring). Caller (%encode-secured-region-into) has bounds-checked
   the whole footer extent; RECEIVERS empty is a no-op (this branch is entered only for a positive count). Returns T."
  (let ((eoff entries-abs))
    (declare (type fixnum eoff))
    (dolist (r receivers t)
      (let ((rk (%km-receiver-session-key-at km (car r) (cdr r) vec sid-abs)))
        (replace vec (car r) :start1 eoff :end1 (+ eoff +transformation-key-id-len+))
        (dds.dare:aes-256-gcm-seal-into vec (+ eoff +transformation-key-id-len+) (+ eoff +transformation-key-id-len+)
                                        rk vec sid-abs
                                        vec +empty-octets+ 0 0
                                        mac-abs +common-mac-len+)
        (incf eoff (+ +transformation-key-id-len+ +common-mac-len+))))))

(defun* %verify-receiver-mac-into (km secured secured-off postfix-off my-receiver-key-id my-receiver-key scratch)
    (function (key-material (simple-array (unsigned-byte 8) (*)) fixnum fixnum
               (or (simple-array (unsigned-byte 8) (*)) null)
               (or (simple-array (unsigned-byte 8) (*)) null)
               (simple-array (unsigned-byte 8) (*)))
              boolean)
  "ZERO-ALLOC origin-authentication gate (§9.5.3.3.4.3) BY RAW OFFSET — the into-buffer decode counterpart of
   %put-receiver-macs-into, closing the ADR-0039 residual (a) allocating %decode-verify-origin-auth /
   %verify-receiver-mac fallback. When MY-RECEIVER-KEY-ID is NIL, origin-auth is NOT requested -> T (the common_mac
   alone governs, already verified by the -into core). Otherwise, over the bracket at SECURED[SECURED-OFF..] whose
   POSTFIX submessage header is at POSTFIX-OFF (as returned by %decode-secured-region-into): locate the CryptoFooter
   IN PLACE — common_mac at MAC-LOC = POSTFIX-OFF+4, then the §9.5.3.3.3 4-align pad (vs the bracket start), then
   receiver_specific_macs_count(u32 BE), then {key_id(4),mac(16)}* entries — find the entry whose key_id equals
   MY-RECEIVER-KEY-ID (%recv-key-id-eq-at, by offset, no materialization), and VERIFY its wire GMAC IN PLACE with
   aes-256-gcm-open-into (ct-len 0): key = the %km-receiver-session-key-at cached receiver key, nonce = SECURED
   session_id‖iv_suffix in place, AAD = the common_mac in place at MAC-LOC, tag = the wire mac in place — EVP does
   the constant-time tag compare. SCRATCH is any ALLOC-STATIC-backed vector (nothing is written — ct-len 0 emits no
   plaintext and no fail-closed wipe; it only satisfies open-into's static PT-OUT). Fail-closed (NIL) if
   MY-RECEIVER-KEY is NIL, the footer bounds are bad, no entry targets this receiver, or the GMAC mismatches — even
   when the common_mac is valid (never a bypass). Every offset is validated against END before use, safety-0-safe
   (NFR-SEC-POSTURE); the caller runs it inside a fail-closed handler so any signal resolves to NIL. Byte-identical
   verification to the allocating %verify-receiver-mac (same GMAC / same IV / same key)."
  (if (null my-receiver-key-id)
      t
      (and my-receiver-key
           (let* ((base     secured-off)
                  (end      (length secured))
                  (sid-off  (+ base +sec-submessage-header-len+ +secure-data-header-session-id-off+))  ; session_id‖iv_suffix
                  (mac-loc  (+ postfix-off +sec-submessage-header-len+))
                  (mac-end  (- (+ mac-loc +common-mac-len+) base))
                  (rsm-loc  (+ mac-loc +common-mac-len+ (mod (- mac-end) 4)))
                  (entry-len (+ +transformation-key-id-len+ +common-mac-len+)))
             (declare (type fixnum base end sid-off mac-loc mac-end rsm-loc entry-len))
             (and (<= (+ rsm-loc +receiver-specific-macs-count-len+) end)
                  (let ((count       (%get-u32-be-at secured rsm-loc))
                        (entries-loc (+ rsm-loc +receiver-specific-macs-count-len+)))
                    (declare (type (unsigned-byte 32) count))
                    (and (<= count +max-receiver-specific-macs+)
                         (<= (+ entries-loc (* count entry-len)) end)
                         (dotimes (i count nil)
                           (let ((eoff (+ entries-loc (* i entry-len))))
                             (when (%recv-key-id-eq-at secured eoff my-receiver-key-id)
                               (return
                                 ;; GMAC verify IN PLACE: ct-len 0, AAD = common_mac at MAC-LOC, tag = wire mac at eoff+4.
                                 (and (dds.dare:aes-256-gcm-open-into
                                       scratch 0
                                       (%km-receiver-session-key-at km my-receiver-key-id my-receiver-key secured sid-off)
                                       secured sid-off
                                       secured
                                       secured mac-loc 0
                                       secured (+ eoff +transformation-key-id-len+)
                                       mac-loc +common-mac-len+)
                                      t))))))))))))

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

(defun* %put-sec-header-at (vec off submessage-id octets-to-next)
    (function ((simple-array (unsigned-byte 8) (*)) fixnum (unsigned-byte 8) (unsigned-byte 16)) (eql t))
  "Write a 4-octet RTPS SubmessageHeader into VEC[OFF..OFF+4] by RAW OFFSET, no cursor (the zero-alloc
   analogue of %write-sec-submessage-header; DDSI-RTPS 2.5 §9.4.5.1): submessageId(1) ‖ flags(1, E=1
   little-endian = +sec-submessage-le-flags+) ‖ octetsToNextHeader(u16, little-endian low‖high). Emits the
   SAME 4 octets %write-sec-submessage-header's cursor path does. Caller guarantees OFF+4 <= (length VEC)
   (the -into O(1) total-extent check bounds it). Returns T."
  (setf (aref vec off)       submessage-id
        (aref vec (+ off 1)) +sec-submessage-le-flags+
        (aref vec (+ off 2)) (logand octets-to-next #xff)
        (aref vec (+ off 3)) (logand (ash octets-to-next -8) #xff))
  t)

(defun* %encode-secured-region-into (out-buf out-off km mode plain plain-off plain-len
                                     receivers prefix-kind postfix-kind
                                     &optional (session-id +fixed-session-id+))
    (function (dds.core.buffer:octet-buffer fixnum key-material (member :sign :encrypt)
               (simple-array (unsigned-byte 8) (*)) fixnum fixnum list
               (unsigned-byte 8) (unsigned-byte 8)
               &optional (simple-array (unsigned-byte 8) (*)))
              fixnum)
  "Build the PREFIX-KIND ... POSTFIX-KIND bracket protecting PLAIN[PLAIN-OFF..+PLAIN-LEN] under KM per MODE
   directly INTO the STATIC octet-buffer OUT-BUF starting at OUT-OFF; return the total bracket length. The
   zero-alloc core behind %encode-secured-region (the thin allocating wrapper), so the T2/T4 byte-exact
   corpora exercise it — BYTE-IDENTICAL to %encode-secured-region by construction (same field widths/offsets,
   the SAME big-endian %put-u32-be-at length/count, the SAME §9.5.3.3.3/.4.4 4-align pads, and
   aes-256-gcm-seal-into emits ct+tag byte-identical to aes-256-gcm-seal). Shared by BOTH the §8.5.1.7-.9
   submessage tier (SEC_PREFIX 0x31 / SEC_POSTFIX 0x32) AND the §8.5.1.10-.12 whole-RTPS tier (SRTPS_PREFIX
   0x33 / SRTPS_POSTFIX 0x34) — only the bracket ids + the protected unit differ (DRY).
   ZERO GC-heap allocation on the common path (RECEIVERS empty): the 4-byte submessage headers, the 20-byte
   §9.5.3.3.1 CryptoHeader, the SEC_BODY header + cnt_length, the 4-align pads and rsm_count are RAW OFFSET
   writes (no cursor is consed); the 12-byte AES-GCM nonce is the in-place CryptoHeader session_id‖iv_suffix
   sub-slice (OUT-BUF[OUT-OFF+12..+24], written first — no nonce buffer); the iv_suffix is stamped in place by
   %km-next-iv-suffix-into; the session key is cached per KM (%km-session-key-at). ENCRYPT: aes-256-gcm-seal-into
   writes the ciphertext at the SEC_BODY content offset + the common_mac (tag) at the POSTFIX offset, under
   EMPTY AAD (§9.5.3.3.4.4). SIGN: the region is copied VERBATIM (no SEC_BODY, §9.5.3.3.4.3) and
   aes-256-gcm-seal-into with pt-len 0 authenticates AAD = PLAIN[PLAIN-OFF..+PLAIN-LEN] (the verbatim
   region, bounded by aes-256-gcm-seal-into's aad-off/aad-len — the symmetric mate of the decode side's
   bounded AAD) as a GMAC, so MODE :sign works BY OFFSET too (the whole-RTPS dataplane wrap passes
   PLAIN-OFF 20 / PLAIN-LEN len-20 with no subseq; byte-identical for the wrappers' PLAIN-OFF 0 case).
   RECEIVERS non-empty (origin authentication, §9.5.3.3.4.3) is the DEFERRED allocating fallback: after the
   seal, %compute-receiver-macs derives each receiver-specific GMAC over the common_mac (read in place) and
   the {key_id,mac} entries are written into the CryptoFooter (this branch MAY allocate — do not rely on it
   for zero-alloc; empty RECEIVERS writes rsm_count 0, the plain tag). SESSION-ID (default +fixed-session-id+
   = all-zeros, the Slice-1/T2/T4 corpus value; T8 PVMS per-role non-zero) is written into the CryptoHeader
   and folded into the KDF + nonce. OUT-BUF must hold OUT-OFF + the bracket length, else BUFFER-OVERFLOW (an
   O(1) extent check BEFORE any write, safety-0-safe; NFR-SEC-POSTURE). Returns the total bracket length."
  (let* ((vec         (dds.core.buffer:octet-buffer-vec out-buf))
         (count       (length receivers))
         (kind        (%mode->kind mode))
         (key-id      (key-material-sender-key-id km))
         (hdr-loc     +sec-submessage-header-len+)                             ; CryptoHeader start = 4
         (sid-loc     (+ hdr-loc +transformation-kind-len+ +transformation-key-id-len+))  ; session_id = 12
         (iv-loc      (+ sid-loc +session-id-len+))                            ; iv_suffix = 16
         (mid-loc     (+ hdr-loc +secure-data-header-len+))                    ; middle region = 24
         (ct-len      (ecase mode (:encrypt plain-len) (:sign 0)))
         ;; §9.5.3.3.4.4 SEC_BODY 4-align pad: the SEC_BODY content starts 4-aligned (24+4+4=32), so it reduces
         ;; to (-|ciphertext| mod 4); the plaintext is never padded. SIGN has no SEC_BODY -> no pad.
         (ct-pad      (ecase mode (:encrypt (mod (- ct-len) 4)) (:sign 0)))
         (ct-loc      (+ mid-loc +sec-submessage-header-len+ +crypto-content-length-len+))  ; ciphertext = 32
         (postfix-loc (ecase mode (:encrypt (+ ct-loc ct-len ct-pad)) (:sign (+ mid-loc plain-len))))
         (mac-loc     (+ postfix-loc +sec-submessage-header-len+))             ; common_mac
         ;; §9.5.3.3.3 rsm_count 4-align vs the bracket start; 0 for the 4-aligned brackets (the T12 carry)
         (align-pad   (mod (- (+ mac-loc +common-mac-len+)) 4))
         (rsm-loc     (+ mac-loc +common-mac-len+ align-pad))
         (entries-loc (+ rsm-loc +receiver-specific-macs-count-len+))
         (macs-bytes  (* count (+ +transformation-key-id-len+ +common-mac-len+)))
         (postfix-len (+ +common-mac-len+ +receiver-specific-macs-count-len+ macs-bytes))
         (total       (+ entries-loc macs-bytes)))
    ;; O(1) output-extent check BEFORE any write (safety-0-safe); caller sizes OUT-BUF (the per-node submessage-scratch pool) to hold OUT-OFF + the bracket length.
    (unless (<= (+ out-off total) (length vec))   ; NOCOND(GUARD): cannot fire on valid input; %maybe-wrap-user-submessages fail-closes / drops on overflow — defense-in-depth (NFR-SEC-POSTURE)
      (error 'dds.core.buffer:buffer-overflow :need (+ out-off total) :have (length vec)))
    ;; PREFIX submessage header ‖ CryptoHeader (kind ‖ key_id ‖ session_id ‖ iv_suffix), by raw offset
    (%put-sec-header-at vec out-off prefix-kind +secure-data-header-len+)
    (replace vec kind       :start1 (+ out-off hdr-loc) :end1 (+ out-off hdr-loc +transformation-kind-len+))
    (replace vec key-id     :start1 (+ out-off hdr-loc +transformation-kind-len+) :end1 (+ out-off sid-loc))
    (replace vec session-id :start1 (+ out-off sid-loc) :end1 (+ out-off iv-loc))
    (%km-next-iv-suffix-into km vec (+ out-off iv-loc))
    ;; middle region + AES-256-GCM seal (nonce = the in-place CryptoHeader session_id‖iv_suffix sub-slice)
    (ecase mode
      (:encrypt
       (%put-sec-header-at vec (+ out-off mid-loc) +submessage-sec-body+
                           (+ +crypto-content-length-len+ ct-len ct-pad))
       (%put-u32-be-at vec (+ out-off mid-loc +sec-submessage-header-len+) ct-len)
       (dds.dare:aes-256-gcm-seal-into vec (+ out-off ct-loc) (+ out-off mac-loc)
                                       (%km-session-key-at km vec (+ out-off sid-loc))
                                       vec (+ out-off sid-loc)
                                       +empty-octets+ plain plain-off plain-len)
       (dotimes (i ct-pad) (setf (aref vec (+ out-off ct-loc ct-len i)) 0)))
      (:sign
       (dotimes (i plain-len) (setf (aref vec (+ out-off mid-loc i)) (aref plain (+ plain-off i))))
       (dds.dare:aes-256-gcm-seal-into vec (+ out-off mid-loc) (+ out-off mac-loc)
                                       (%km-session-key-at km vec (+ out-off sid-loc))
                                       vec (+ out-off sid-loc)
                                       plain +empty-octets+ 0 0 plain-off plain-len)))
    ;; POSTFIX submessage header ‖ CryptoFooter (common_mac already sealed at MAC-LOC): 4-align pad ‖ rsm_count
    (%put-sec-header-at vec (+ out-off postfix-loc) postfix-kind postfix-len)
    (dotimes (i align-pad) (setf (aref vec (+ out-off mac-loc +common-mac-len+ i)) 0))
    (%put-u32-be-at vec (+ out-off rsm-loc) count)
    ;; origin authentication (§9.5.3.3.4.3): write receiver_specific_macs BY OFFSET (zero-alloc, ADR-0039 residual
    ;; (a) closed) — each 20-octet {key_id ‖ GMAC} entry written straight into the CryptoFooter via the cached
    ;; receiver session key + aes-256-gcm-seal-into (GMAC over the in-place common_mac, nonce = the in-place
    ;; session_id‖iv_suffix); byte-identical to the allocating %compute-receiver-macs path (the T3 corpus proves it).
    (when (plusp count)
      (%put-receiver-macs-into km vec (+ out-off sid-loc) (+ out-off mac-loc) (+ out-off entries-loc) receivers))
    total))

(defun* %encode-secured-region (km mode plain-region receivers prefix-kind postfix-kind
                                &optional (session-id +fixed-session-id+))
    (function (key-material (member :sign :encrypt) (simple-array (unsigned-byte 8) (*)) list
               (unsigned-byte 8) (unsigned-byte 8) &optional (simple-array (unsigned-byte 8) (*)))
              (or (simple-array (unsigned-byte 8) (*)) null))
  "Build the PREFIX-KIND ... POSTFIX-KIND bracket protecting PLAIN-REGION under KM per MODE and return a fresh
   octet vector — the SHARED engine behind BOTH the §8.5.1.7-.9 submessage tier (SEC_PREFIX 0x31 / SEC_POSTFIX
   0x32; PLAIN-REGION = one submessage) AND the §8.5.1.10-.12 whole-RTPS tier (SRTPS_PREFIX 0x33 / SRTPS_POSTFIX
   0x34; PLAIN-REGION = the whole submessage stream) — only the bracket ids + protected unit differ (DRY).
   Thin ALLOCATING wrapper over the zero-alloc core %encode-secured-region-into: allocate a static scratch
   octet-buffer, build the bracket into it (unique iv_suffix, AES-256-GCM seal, ENCRYPT SEC_BODY / SIGN
   verbatim, empty AAD / GMAC; see the core for the full algorithm + spec citations), copy out the exact bytes
   and free the scratch. RECEIVERS is the origin-authentication receiver list (a list of
   (receiver-key-id . master-receiver-specific-key) conses, EMPTY for plain SIGN/ENCRYPT -> rsm_count 0).
   SESSION-ID (default +fixed-session-id+ = all-zeros, the Slice-1/T2/T4 corpus value; T8 PVMS per-role non-zero)
   is written into the CryptoHeader + folded into the KDF + nonce. The wire is byte-identical to the pre-ZA-2
   assembly (the byte-exact corpora prove it). Returns a fresh octet vector."
  (let ((out (dds.core.buffer:make-octet-buffer
              (+ 64 (length plain-region) (* (length receivers)
                                             (+ +transformation-key-id-len+ +common-mac-len+))))))
    (unwind-protect
         (let ((len (%encode-secured-region-into out 0 km mode plain-region 0 (length plain-region)
                                                 receivers prefix-kind postfix-kind session-id)))
           (subseq (dds.core.buffer:octet-buffer-vec out) 0 len))
      (dds.pal:free-static (dds.core.buffer:octet-buffer-vec out)))))

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

(defun* %embedded-submessage-len (secured off end)
    (function ((simple-array (unsigned-byte 8) (*)) fixnum fixnum) (or fixnum null))
  "Length (4 + octetsToNextHeader) of ONE embedded RTPS submessage at SECURED[OFF] — the AES256-GMAC (SIGN)
   submessage-tier verbatim region (§9.5.3.3.4.3) — or NIL if the 4-octet header or its payload would exceed
   END. Zero-alloc, length-only analogue of the recovery step (no make-array): the embedded E flag (bit 0 of
   the flags octet, DDSI-RTPS 2.5 §9.4.5.1.2) selects octetsToNextHeader endianness. Every offset is validated
   against END BEFORE any read; a truncated / over-declared length -> NIL (fail-closed; NFR-SEC-POSTURE), never
   an OOB read, even at (safety 0)."
  (when (<= (+ off +sec-submessage-header-len+) end)
    (let* ((flags (aref secured (+ off 1)))
           (o0    (aref secured (+ off 2)))
           (o1    (aref secured (+ off 3)))
           (octn  (if (logbitp 0 flags) (logior o0 (ash o1 8)) (logior (ash o0 8) o1)))
           (total (+ +sec-submessage-header-len+ octn)))
      (when (<= (+ off total) end) total))))

(defun* %walk-verbatim-len (secured off end postfix-kind)
    (function ((simple-array (unsigned-byte 8) (*)) fixnum fixnum (unsigned-byte 8)) (or fixnum null))
  "Length of the WHOLE-RTPS-message verbatim body (T4, §8.5.1.12): (postfix-start - OFF), where postfix-start
   is the first submessage in SECURED[OFF..END) whose submessageId = POSTFIX-KIND — the zero-alloc, length-only
   analogue of the SIGN stream-walk recovery (no subseq). WALK submessage-by-submessage (4-octet header, the
   embedded E flag = bit 0 of the flags octet selecting octetsToNextHeader endianness, DDSI-RTPS 2.5
   §9.4.5.1.2), each iteration advancing >= 4 octets; every read is validated against END BEFORE it happens, so
   a truncated / postfix-less / over-declared stream -> NIL (fail-closed; NFR-SEC-POSTURE), never an OOB read,
   an unbounded scan, or a non-terminating loop, even at (safety 0). Corroborated CLEAN-ROOM against Fast DDS
   decode_rtps_message (the submessage-skip loop; see docs/provenance.md, M7/P6 T4). Self-consistent with the
   encode verbatim write: NO inter-submessage re-alignment (live cross-vendor reconciliation is the T12 carry)."
  (let ((pos off))
    (declare (type fixnum pos))
    (loop
      (when (> (+ pos +sec-submessage-header-len+) end) (return nil))
      (let ((id (aref secured pos)))
        (when (= id postfix-kind) (return (- pos off)))
        (let* ((flags (aref secured (+ pos 1)))
               (o0    (aref secured (+ pos 2)))
               (o1    (aref secured (+ pos 3)))
               (octn  (if (logbitp 0 flags) (logior o0 (ash o1 8)) (logior (ash o0 8) o1)))
               (next  (+ pos +sec-submessage-header-len+ octn)))
          (when (> next end) (return nil))
          (setf pos next))))))

(defun* %footer-bounds-ok-p (secured base mac-loc end)
    (function ((simple-array (unsigned-byte 8) (*)) fixnum fixnum fixnum) t)
  "T iff the §9.5.3.3.3 CryptoFooter at MAC-LOC — common_mac(16) ‖ 4-align pad (vs the bracket start BASE) ‖
   receiver_specific_macs_count(u32 BE) ‖ {key_id(4),mac(16)}*count — fits within END and count <=
   +max-receiver-specific-macs+; NIL otherwise. The zero-alloc, VERIFY-FREE fail-closed bounds parity with
   parse-crypto-footer (the receiver_specific_macs themselves are verified by the wrapper's origin-auth gate,
   not here). Every offset is validated BEFORE any read (NFR-SEC-POSTURE), even at (safety 0)."
  (let* ((mac-end (- (+ mac-loc +common-mac-len+) base))          ; bracket-relative end of common_mac
         (rsm-loc (+ mac-loc +common-mac-len+ (mod (- mac-end) 4))))
    (and (<= (+ rsm-loc +receiver-specific-macs-count-len+) end)
         (let ((count (%get-u32-be-at secured rsm-loc)))
           (and (<= count +max-receiver-specific-macs+)
                (<= (+ rsm-loc +receiver-specific-macs-count-len+
                       (* count (+ +transformation-key-id-len+ +common-mac-len+)))
                    end))))))

(defun* %decode-secured-region-into (pt-out pt-off km secured secured-off secured-len sign-walk-p)
    (function (dds.core.buffer:octet-buffer fixnum key-material
               (simple-array (unsigned-byte 8) (*)) fixnum fixnum t)
              (values (or fixnum null) (or (member :sign :encrypt) null) (or fixnum null) (or fixnum null)))
  "Recover the protected region from a PREFIX ... POSTFIX bracket in SECURED[SECURED-OFF..+SECURED-LEN] by
   RAW OFFSET (no make-array on the parse path); return (values DATA-LEN MODE DATA-OFF POSTFIX-OFF), or a
   single NIL on ANY failure (fail-closed; NFR-SEC-POSTURE). The zero-alloc core behind %decode-secured-region
   (the thin allocating wrapper + the origin-auth gate). The tier is selected by SIGN-WALK-P: NIL = the
   §8.5.1.7-.9 submessage tier (SEC_PREFIX 0x31 / SEC_POSTFIX 0x32, SIGN reads ONE embedded submessage); T =
   the §8.5.1.10-.12 whole-RTPS tier (SRTPS_PREFIX 0x33 / SRTPS_POSTFIX 0x34, SIGN WALKS the stream to the
   trailing postfix) — the expected prefix/postfix ids derive from SIGN-WALK-P (the two callers pass them 1:1).
   The wire CryptoHeader.transformation_kind selects the mode + framing:
     ENCRYPT ({0,0,0,4}) — SEC_BODY(0x30) length-prefixed ciphertext; aes-256-gcm-open-into writes the
       plaintext into PT-OUT[PT-OFF..+DATA-LEN] under EMPTY AAD (§9.5.3.3.4.4); DATA-LEN = plaintext length,
       DATA-OFF = the ciphertext offset in SECURED. ZERO GC-heap allocation (empty AAD, nonce = SECURED
       session_id‖iv_suffix in place, session key cached, ct/tag read in place).
     SIGN ({0,0,0,3}) — the region VERBATIM (no SEC_BODY, §9.5.3.3.4.3); verify the GMAC over it (AAD = the
       region) and return its bounds — DATA-OFF = the verbatim-region offset in SECURED, DATA-LEN = its length
       (NO copy into PT-OUT; the wrapper materializes the bounds). The verbatim region is materialized ONCE as
       the GMAC AAD (the only residual alloc — aes-256-gcm-open-into needs a full-length AAD vector).
   POSTFIX-OFF (the 4th value) is the POSTFIX submessage-header offset, so the wrapper can parse the
   CryptoFooter for the origin-auth gate without recomputation. The bracket (submessageId + order + every
   length within extent, incl. the CryptoFooter via %footer-bounds-ok-p) is validated BEFORE the AEAD open;
   any malformed / truncated / re-ordered / unknown-kind / GCM-or-GMAC-auth-fail input -> NIL, never an OOB
   read, never a signal to the caller, never plaintext on a failure, even at (safety 0). Origin-auth
   (receiver_specific_macs) is NOT verified here — the common_mac governs; the wrapper adds the receiver gate."
  (handler-case
      (block dec
        (let* ((base    secured-off)
               (end     (+ secured-off secured-len))
               (prefix  (if sign-walk-p +submessage-srtps-prefix+ +submessage-sec-prefix+))
               (postfix (if sign-walk-p +submessage-srtps-postfix+ +submessage-sec-postfix+))
               ;; smallest possible bracket = PREFIX(4)+CryptoHeader(20)+POSTFIX(4)+SecureDataTag(20) = 48
               (min-len (+ +sec-submessage-header-len+ +secure-data-header-len+
                           +sec-submessage-header-len+ +secure-data-tag-len+)))
          (unless (and (<= 0 base) (<= end (length secured)) (>= secured-len min-len)
                       (= (aref secured base) prefix))
            (return-from dec nil))
          (let* ((hdr-loc (+ base +sec-submessage-header-len+))                              ; CryptoHeader
                 (sid-off (+ hdr-loc +transformation-kind-len+ +transformation-key-id-len+)) ; session_id (nonce)
                 (kind-u32 (%get-u32-be-at secured hdr-loc))
                 (mode (cond ((= kind-u32 4) :encrypt) ((= kind-u32 3) :sign) (t nil))))
            (unless mode (return-from dec nil))
            (ecase mode
              (:encrypt
               (let ((body-loc (+ hdr-loc +secure-data-header-len+)))                        ; SEC_BODY header
                 (unless (and (<= (+ body-loc +sec-submessage-header-len+ +crypto-content-length-len+) end)
                              (= (aref secured body-loc) +submessage-sec-body+))
                   (return-from dec nil))
                 (let* ((ct-off  (+ body-loc +sec-submessage-header-len+ +crypto-content-length-len+))
                        (ct-len  (%get-u32-be-at secured (+ body-loc +sec-submessage-header-len+)))
                        (ct-pad  (mod (- ct-len) 4))
                        (postfix-loc (+ ct-off ct-len ct-pad))
                        (mac-loc (+ postfix-loc +sec-submessage-header-len+)))
                   (unless (and (<= (+ ct-off ct-len) end) (<= (+ mac-loc +common-mac-len+) end)
                                (%footer-bounds-ok-p secured base mac-loc end)
                                (= (aref secured postfix-loc) postfix))
                     (return-from dec nil))
                   (if (dds.dare:aes-256-gcm-open-into (dds.core.buffer:octet-buffer-vec pt-out) pt-off
                                                       (%km-session-key-at km secured sid-off)
                                                       secured sid-off +empty-octets+
                                                       secured ct-off ct-len secured mac-loc)
                       (values ct-len :encrypt ct-off postfix-loc)
                       nil))))
              (:sign
               (let* ((region-off (+ hdr-loc +secure-data-header-len+))
                      (region-len (if sign-walk-p
                                      (%walk-verbatim-len secured region-off end postfix)
                                      (%embedded-submessage-len secured region-off end))))
                 (unless region-len (return-from dec nil))
                 (let* ((postfix-loc (+ region-off region-len))
                        (mac-loc (+ postfix-loc +sec-submessage-header-len+)))
                   (unless (and (<= (+ mac-loc +common-mac-len+) end)
                                (%footer-bounds-ok-p secured base mac-loc end)
                                (= (aref secured postfix-loc) postfix))
                     (return-from dec nil))
                   ;; GMAC verify: ct-len=0, AAD = secured[region-off..+region-len] via aad-off/aad-len (no subseq, zero-alloc).
                   (if (dds.dare:aes-256-gcm-open-into (dds.core.buffer:octet-buffer-vec pt-out) pt-off
                                                       (%km-session-key-at km secured sid-off)
                                                       secured sid-off
                                                       secured
                                                       secured region-off 0 secured mac-loc
                                                       region-off region-len)
                       (values region-len :sign region-off postfix-loc)
                       nil))))))))
    ;; Any condition (bounds, malformed, EVP, etc.) -> NIL (fail-closed).
    (error () nil)))

(defun* %decode-secured-region-verify-into (pt-out pt-off km secured secured-off secured-len sign-walk-p
                                            my-receiver-key-id my-receiver-key)
    (function (dds.core.buffer:octet-buffer fixnum key-material
               (simple-array (unsigned-byte 8) (*)) fixnum fixnum t
               (or (simple-array (unsigned-byte 8) (*)) null)
               (or (simple-array (unsigned-byte 8) (*)) null))
              (values (or fixnum null) (or (member :sign :encrypt) null) (or fixnum null) (or fixnum null)))
  "ZERO-ALLOC decode + origin-authentication verify BY RAW OFFSET (the ADR-0039 residual (a) live-path core): run
   %decode-secured-region-into (validates the bracket + verifies the common_mac + recovers the region), then — when
   MY-RECEIVER-KEY-ID is non-NIL — %verify-receiver-mac-into over the returned POSTFIX-OFF (finds + GMAC-verifies
   THIS receiver's CryptoFooter entry IN PLACE). Return the same (values DATA-LEN MODE DATA-OFF POSTFIX-OFF) as
   %decode-secured-region-into on success, or a single NIL on decode failure OR receiver-MAC failure (fail-closed;
   NFR-SEC-POSTURE — never a bypass, never plaintext on failure). The verify reuses PT-OUT's static vec as the
   open-into GMAC-verify sink (nothing written — ct-len 0 — so the recovered ENCRYPT plaintext already in PT-OUT is
   untouched). MY-RECEIVER-KEY-ID NIL = origin-auth not requested -> identical to %decode-secured-region-into. Shared
   by the whole-RTPS + submessage -into verify entries; wrapped in a fail-closed handler by callers."
  (multiple-value-bind (data-len mode data-off postfix-off)
      (%decode-secured-region-into pt-out pt-off km secured secured-off secured-len sign-walk-p)
    (if (and data-len
             (%verify-receiver-mac-into km secured secured-off postfix-off my-receiver-key-id my-receiver-key
                                        (dds.core.buffer:octet-buffer-vec pt-out)))
        (values data-len mode data-off postfix-off)
        nil)))

(defun* %decode-verify-origin-auth (km secured postfix-off my-receiver-key-id my-receiver-key scratch)
    (function (key-material (simple-array (unsigned-byte 8) (*)) fixnum
               (or (simple-array (unsigned-byte 8) (*)) null)
               (or (simple-array (unsigned-byte 8) (*)) null)
               (simple-array (unsigned-byte 8) (*)))
              boolean)
  "Origin-authentication gate (§9.5.3.3.4.3) for the decode wrapper — T when MY-RECEIVER-KEY-ID is NIL
   (origin-auth not requested; the common_mac alone governs, already verified by the -into core) OR when THIS
   receiver's entry verifies; NIL (fail-closed) if requested but absent/mismatched even though the common_mac
   is valid. Thin delegation to the ZERO-ALLOC %verify-receiver-mac-into (the ADR-0039 residual (a) fix): the
   CryptoFooter at the POSTFIX submessage (POSTFIX-OFF) is located + verified BY OFFSET — no cursor / footer
   parse / subseq materialization. SCRATCH is the caller's static PT-OUT reused as the open-into GMAC-verify
   sink (nothing is written — ct-len 0). Runs inside %decode-secured-region's fail-closed handler, so any signal
   still resolves to NIL."
  (%verify-receiver-mac-into km secured 0 postfix-off my-receiver-key-id my-receiver-key scratch))

(defun* %decode-secured-region (km secured-octets my-receiver-key-id my-receiver-key
                                prefix-kind postfix-kind sign-walk-p)
    (function (key-material (simple-array (unsigned-byte 8) (*))
               (or (simple-array (unsigned-byte 8) (*)) null)
               (or (simple-array (unsigned-byte 8) (*)) null)
               (unsigned-byte 8) (unsigned-byte 8) t)
              (or (simple-array (unsigned-byte 8) (*)) null))
  "Recover the protected region from a PREFIX-KIND ... POSTFIX-KIND bracket produced by %encode-secured-region,
   or NIL on ANY failure (fail-closed; NFR-SEC-POSTURE) — the SHARED engine behind BOTH the submessage tier
   (decode-datawriter-/datareader-submessage; SEC_PREFIX/SEC_POSTFIX, SIGN-WALK-P NIL) AND the whole-RTPS tier
   (decode-rtps-message, T4; SRTPS_PREFIX/SRTPS_POSTFIX, SIGN-WALK-P T). Thin ALLOCATING wrapper over the
   zero-alloc core %decode-secured-region-into (+ the origin-auth gate %decode-verify-origin-auth): allocate a
   static scratch PT-OUT, recover the region into it (the core validates the bracket + verifies the common_mac —
   ENCRYPT opens the SEC_BODY ciphertext under EMPTY AAD into PT-OUT; SIGN verifies the GMAC over the verbatim
   region and returns its bounds), materialize the result (ENCRYPT: copy PT-OUT; SIGN: copy the verbatim-region
   bounds from SECURED-OCTETS, preserving the return type), free the scratch. PREFIX-KIND is derivable from
   SIGN-WALK-P (the core validates the wire prefix), so it is unused here; POSTFIX-KIND drives the origin-auth
   footer parse. ORIGIN AUTH (§9.5.3.3.4.3): when MY-RECEIVER-KEY-ID is non-NIL, AFTER the common_mac verifies
   the gate ALSO finds + verifies THIS receiver's entry in the CryptoFooter receiver_specific_macs (recompute
   under MY-RECEIVER-KEY, constant-time compare); absent or mismatched -> NIL even though the common_mac is
   valid. MY-RECEIVER-KEY-ID NIL = origin-auth not expected (backward-compatible). Any malformed / truncated /
   re-ordered / unknown-kind / auth-fail / receiver-MAC-fail input -> NIL, never a tampered region, even at
   (safety 0)."
  (declare (ignore prefix-kind postfix-kind))
  (let ((pt-out (dds.core.buffer:make-octet-buffer (max 1 (length secured-octets)))))
    (unwind-protect
         (handler-case
             (multiple-value-bind (len mode region-off postfix-off)
                 (%decode-secured-region-into pt-out 0 km secured-octets 0 (length secured-octets) sign-walk-p)
               (when (and len
                          (or (null my-receiver-key-id)
                              (%decode-verify-origin-auth km secured-octets postfix-off
                                                          my-receiver-key-id my-receiver-key
                                                          (dds.core.buffer:octet-buffer-vec pt-out))))
                 (ecase mode
                   (:encrypt (subseq (dds.core.buffer:octet-buffer-vec pt-out) 0 len))
                   (:sign    (subseq secured-octets region-off (+ region-off len))))))
           ;; Any condition (bounds, malformed, etc.) -> NIL (fail-closed).
           (error () nil))
      (dds.pal:free-static (dds.core.buffer:octet-buffer-vec pt-out)))))

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

;;;; ZERO-ALLOC (Slice 2 / ZA-2 T4): the into-buffer SUBMESSAGE tier for the live dataplane. The allocating
;;;; encode/decode-datawriter/datareader-submessage above stay UNCHANGED (the WITH_ORIGIN_AUTHENTICATION
;;;; receiver-MAC gate + the deferred allocating fallback ride them); the -into entries below let the dds.disc
;;;; send/receive paths wrap / unwrap ONE user submessage bracket through a caller-owned STATIC buffer BY RAW
;;;; OFFSET (no per-submessage subseq / →octets), reusing the SAME %encode/%decode-secured-region-into cores as
;;;; the whole-RTPS tier (rtps-message.lisp), only the bracket ids differ (SEC_PREFIX 0x31 / SEC_POSTFIX 0x32 vs
;;;; SRTPS_PREFIX/POSTFIX) — DRY. The §8.5 DataWriter and DataReader submessage transforms are the SAME mechanism
;;;; (Fast DDS encode_datawriter_/datareader_submessage share one AEAD path), so the two encode -into (and the two
;;;; decode -into) entries are byte-identical thin delegations — the split is only which §8.5 codec the peer pairs,
;;;; exactly like the allocating pair. Byte-identical wire to the allocating pair (same cores → the T2 corpus covers them).

(defun* encode-datawriter-submessage-into (out-buf out-off km kind plain plain-off plain-len &key (receivers '()))
    (function (dds.core.buffer:octet-buffer fixnum key-material (member :sign :encrypt)
               (simple-array (unsigned-byte 8) (*)) fixnum fixnum &key (:receivers list))
              fixnum)
  "Protect the DataWriter submessage PLAIN[PLAIN-OFF..+PLAIN-LEN] under KM per KIND (:sign | :encrypt) directly INTO
   the caller's STATIC octet-buffer OUT-BUF starting at OUT-OFF, and return the total SEC_PREFIX(0x31) ‖ <body> ‖
   SEC_POSTFIX(0x32) bracket length (DDS-Security 1.1 §8.5.1.7/.9) — the zero-alloc, into-buffer twin of
   encode-datawriter-submessage (which allocates a fresh →octets vector). The thin submessage-tier delegation to the
   shared %encode-secured-region-into core with the SEC_PREFIX/SEC_POSTFIX bracket ids; BYTE-IDENTICAL to
   encode-datawriter-submessage by construction (same core), so the T2 byte-exact corpus covers it. Works BY OFFSET for
   BOTH kinds (the SIGN GMAC AAD is bounded to PLAIN[PLAIN-OFF..+PLAIN-LEN]), so the dataplane multi-bracket wrap passes
   its input datagram vec + submessage offset + submessage length with NO per-submessage subseq. Common path (RECEIVERS
   empty) conses ~0 GC-heap B/call; RECEIVERS non-empty (origin authentication, §9.5.3.3.4.3) is the core's deferred
   allocating fallback (still written into OUT-BUF). OUT-BUF must hold OUT-OFF + the bracket length, else BUFFER-OVERFLOW
   (an O(1) extent check BEFORE any write, safety-0-safe; NFR-SEC-POSTURE — the caller fail-closes / drops on overflow).
   Consumed by dds.disc %maybe-wrap-user-submessages over a per-node submessage-scratch pool. Inverse: decode-datawriter-submessage-into."
  (%encode-secured-region-into out-buf out-off km kind plain plain-off plain-len receivers
                               +submessage-sec-prefix+ +submessage-sec-postfix+))

(defun* encode-datareader-submessage-into (out-buf out-off km kind plain plain-off plain-len &key (receivers '()))
    (function (dds.core.buffer:octet-buffer fixnum key-material (member :sign :encrypt)
               (simple-array (unsigned-byte 8) (*)) fixnum fixnum &key (:receivers list))
              fixnum)
  "Protect the DataReader submessage PLAIN[PLAIN-OFF..+PLAIN-LEN] under KM per KIND (:sign | :encrypt) directly INTO
   OUT-BUF at OUT-OFF, returning the SEC_PREFIX(0x31) ‖ <body> ‖ SEC_POSTFIX(0x32) bracket length (DDS-Security 1.1
   §8.5.1.8/.9) — the zero-alloc twin of encode-datareader-submessage. SAME §8.5 transform as
   encode-datawriter-submessage-into (both delegate to the one shared %encode-secured-region-into core with the
   SEC_PREFIX/SEC_POSTFIX ids — byte-identical wire, no copy-paste); the DataWriter/DataReader split is only which
   §8.5 codec the receiver pairs for decode, not the crypto. See encode-datawriter-submessage-into for the full
   contract (BY-OFFSET both kinds, common-path zero-alloc, O(1) extent check → BUFFER-OVERFLOW on overflow).
   Inverse: decode-datareader-submessage-into."
  (%encode-secured-region-into out-buf out-off km kind plain plain-off plain-len receivers
                               +submessage-sec-prefix+ +submessage-sec-postfix+))

(defun* decode-datawriter-submessage-into (pt-out pt-off km secured secured-off secured-len
                                           &key (my-receiver-key-id nil) (my-receiver-key nil))
    (function (dds.core.buffer:octet-buffer fixnum key-material
               (simple-array (unsigned-byte 8) (*)) fixnum fixnum
               &key (:my-receiver-key-id (or (simple-array (unsigned-byte 8) (*)) null))
                    (:my-receiver-key (or (simple-array (unsigned-byte 8) (*)) null)))
              (values (or fixnum null) (or (member :sign :encrypt) null) (or fixnum null) (or fixnum null)))
  "Recover the protected DataWriter submessage from a SEC_PREFIX(0x31) ... SEC_POSTFIX(0x32) bracket in
   SECURED[SECURED-OFF..+SECURED-LEN] under KM BY RAW OFFSET; return (values DATA-LEN MODE DATA-OFF POSTFIX-OFF), or a
   single NIL on ANY failure (fail-closed; NFR-SEC-POSTURE) — the zero-alloc, into-buffer twin of
   decode-datawriter-submessage (which allocates the recovered vector). The thin submessage-tier delegation to the
   shared %decode-secured-region-into core (SIGN-WALK-P NIL — the submessage-tier SIGN body is ONE embedded submessage,
   located by %embedded-submessage-len, not the whole-RTPS stream walk). The core validates the bracket + verifies the
   common_mac before any AEAD open. ENCRYPT: aes-256-gcm-open-into writes the recovered submessage into
   PT-OUT[PT-OFF..+DATA-LEN] (zero GC-heap alloc); DATA-OFF is the ciphertext offset in SECURED. SIGN: NO copy into
   PT-OUT — DATA-OFF is the verbatim-submessage offset in SECURED (the caller moves it in place); DATA-LEN its length.
   POSTFIX-OFF is the SEC_POSTFIX offset. ORIGIN AUTHENTICATION (§9.5.3.3.4.3, the WITH_ORIGIN_AUTHENTICATION tier):
   pass MY-RECEIVER-KEY-ID (this receiver's 4-octet receiver_specific_key_id) + MY-RECEIVER-KEY (its 32-octet
   master_receiver_specific_key) and the decoder ALSO GMAC-verifies THIS receiver's CryptoFooter entry BY OFFSET
   (%verify-receiver-mac-into, reusing PT-OUT's static vec as the verify sink — nothing written) and fails-closed NIL
   if absent/mismatched even when the common_mac is valid — now ZERO-ALLOC (ADR-0039 residual (a) closed), no longer
   the allocating decode-datawriter-submessage fallback. Both NIL (default) = origin-auth not expected (identical to
   the common tier). Consumed over a reused per-node RX buffer by dds.disc %on-user-secure-submessage. Inverse:
   encode-datawriter-submessage-into."
  (if my-receiver-key-id
      (%decode-secured-region-verify-into pt-out pt-off km secured secured-off secured-len nil
                                          my-receiver-key-id my-receiver-key)
      (%decode-secured-region-into pt-out pt-off km secured secured-off secured-len nil)))

(defun* decode-datareader-submessage-into (pt-out pt-off km secured secured-off secured-len
                                           &key (my-receiver-key-id nil) (my-receiver-key nil))
    (function (dds.core.buffer:octet-buffer fixnum key-material
               (simple-array (unsigned-byte 8) (*)) fixnum fixnum
               &key (:my-receiver-key-id (or (simple-array (unsigned-byte 8) (*)) null))
                    (:my-receiver-key (or (simple-array (unsigned-byte 8) (*)) null)))
              (values (or fixnum null) (or (member :sign :encrypt) null) (or fixnum null) (or fixnum null)))
  "Recover the protected DataReader submessage from a SEC_PREFIX(0x31) ... SEC_POSTFIX(0x32) bracket in
   SECURED[SECURED-OFF..+SECURED-LEN] under KM BY RAW OFFSET; return (values DATA-LEN MODE DATA-OFF POSTFIX-OFF), or NIL
   on ANY failure (fail-closed) — the zero-alloc twin of decode-datareader-submessage. SAME §8.5 transform as
   decode-datawriter-submessage-into (both delegate to the one shared %decode-secured-region-into core, SIGN-WALK-P NIL —
   no copy-paste). MY-RECEIVER-KEY-ID / MY-RECEIVER-KEY enable the ZERO-ALLOC origin-authentication verify exactly as for
   decode-datawriter-submessage-into. See decode-datawriter-submessage-into for the full fail-closed contract. Inverse:
   encode-datareader-submessage-into."
  (if my-receiver-key-id
      (%decode-secured-region-verify-into pt-out pt-off km secured secured-off secured-len nil
                                          my-receiver-key-id my-receiver-key)
      (%decode-secured-region-into pt-out pt-off km secured secured-off secured-len nil)))
