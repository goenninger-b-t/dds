(in-package #:dds.security)

;;; DDS-Security 1.1 §9.5.3.3.4.4/4.5 — encode-serialized-payload / decode-serialized-payload.
;;; Depends on: crypto.lisp (serialize/parse-secured-payload, derive-session-key, wire constants)
;;;              key-material.lisp (key-material struct + accessors)
;;; Loaded after both in dds-security.asd.

;;; NONCE-UNIQUENESS ARGUMENT (AES-GCM nonce = session_id(4) ∥ iv_suffix(8), 12 bytes total):
;;; AES-GCM nonce reuse under the SAME session key is catastrophic (§9.5.3.3.4.3; NIST SP 800-38D
;;; §8.3: a single repeated nonce-key pair exposes the authentication key and enables plaintext
;;; recovery). The session key is derived from (master_sender_key, master_salt, session_id)
;;; (§9.5.3.3.4.2). We fix session_id = all-zeros for this Slice-1 scaffold, so a different
;;; session_id cannot rescue us from iv_suffix reuse under the same session key. Therefore
;;; iv_suffix MUST be globally unique per km:
;;;   * key-material stores an iv-counter (unsigned-byte 64) field and an iv-counter-lock.
;;;   * %km-next-iv-suffix claims the next counter value under the lock, then increments it.
;;;   * Two concurrent encode callers on the same km each observe a DIFFERENT counter value —
;;;     uniqueness is STRUCTURAL, not relying on timing.
;;;   * (unsigned-byte 64) wraps at 2^64 ≈ 18 × 10^18 encodes; at 10 Gb/s ≈ 10^7 msg/s
;;;     that is ~58 000 years — no operational key lives long enough to wrap.
;;; The iv_suffix is written as a big-endian uint64 into the 8-byte field (monotonically
;;; increasing, easy to audit). session_id = all-zeros.
;;; SINGLE-INSTANCE CONSTRAINT: nonce uniqueness is STRUCTURAL only WITHIN a single key-material
;;; instance; two instances sharing the same master_sender_key+master_salt both start iv-counter
;;; at 0 and will produce colliding nonces under the same session key (catastrophic for AES-GCM);
;;; at most ONE key-material instance may be live per master key — the Slice-2 Auth handshake
;;; enforces this by deriving a unique per-writer key via the DH exchange (§9.5.3.3.4.2).

(defconstant +fixed-session-id+
    (if (boundp '+fixed-session-id+)
        (symbol-value '+fixed-session-id+)
        (make-array 4 :element-type '(unsigned-byte 8) :initial-element 0))
  "Session_id used by encode-serialized-payload: all-zeros (Slice-1 scaffold; §9.5.3.3.4.4).
   The Slice-2 rekeying protocol rotates session_id per-rekeying-epoch; nonce uniqueness here
   is guaranteed entirely by the monotonic iv_suffix counter (see nonce-uniqueness argument above).")

(defconstant +secure-data-header-session-id-off+
    (+ +transformation-kind-len+ +transformation-key-id-len+)
  "Octet offset of session_id within the §9.5.3.3.1 SecureDataHeader = kind(4)+key_id(4) = 8; also the
   start of the 12-byte AES-GCM nonce (session_id(4)‖iv_suffix(8) = SecuredPayload[8..20], §9.5.3.3.4.3).
   The into-buffer codec passes this as the nonce-off into aes-256-gcm-seal-into/-open-into and as the
   session_id offset into %km-session-key-at, so no nonce/session_id vector is materialized per sample.")

(defconstant +secure-data-header-iv-suffix-off+
    (+ +secure-data-header-session-id-off+ +session-id-len+)
  "Octet offset of init_vector_suffix within the §9.5.3.3.1 SecureDataHeader = kind(4)+key_id(4)+
   session_id(4) = 12. encode-serialized-payload-into stamps the monotonic counter in place here.")

(defun* %km-next-iv-suffix-into (km vec off)
    (function (key-material (simple-array (unsigned-byte 8) (*)) fixnum) (eql t))
  "Claim the next monotonic iv_suffix from KM under KM-IV-COUNTER-LOCK, increment the counter, and write
   its 8-byte big-endian encoding directly into VEC[OFF..OFF+8] — the zero-alloc core of %km-next-iv-suffix
   (encode-serialized-payload-into stamps it straight into the SecureDataHeader iv_suffix field, no make-array).
   Nonce uniqueness is STRUCTURAL: the lock ensures no two concurrent callers observe the same counter value,
   and (unsigned-byte 64) never wraps in any realistic key lifetime (see the nonce-uniqueness argument above).
   Caller guarantees OFF+8 <= (length VEC). Returns T."
  (let ((val (dds.pal:with-lock ((key-material-iv-counter-lock km))
               (let ((v (key-material-iv-counter km)))
                 (setf (key-material-iv-counter km) (+ v 1))
                 v))))
    ;; big-endian uint64 encoding into 8 bytes, in place
    (dotimes (i 8 t)
      (setf (aref vec (+ off (- 7 i))) (logand (ash val (* i -8)) #xff)))))

(defun* %km-next-iv-suffix (km)
    (function (key-material) (simple-array (unsigned-byte 8) (*)))
  "Claim the next monotonic iv_suffix from KM under KM-IV-COUNTER-LOCK, increment the counter,
   and return the 8-byte big-endian encoding of the claimed value (allocating wrapper over the
   zero-alloc %km-next-iv-suffix-into, DRY). Nonce uniqueness is STRUCTURAL: the lock ensures no two
   concurrent callers observe the same counter value, and (unsigned-byte 64) never wraps in any
   realistic key lifetime (see nonce-uniqueness argument above encode-serialized-payload in transform.lisp)."
  (let ((buf (make-array +init-vector-suffix-len+ :element-type '(unsigned-byte 8) :initial-element 0)))
    (%km-next-iv-suffix-into km buf 0)
    buf))

;;; --- shared session-key + nonce + AES-GCM core (DRY across all §9.5.3.3 protection tiers) ---
;;; The AAD is a PARAMETER so each tier composes its own authenticated-but-not-encrypted region. All three
;;; conformant tiers use the SAME EMPTY AAD (+empty-octets+), corroborated CLEAN-ROOM against Fast DDS
;;; AESGCMGMAC_Transform.cpp serialize_SecureDataBody (one function, ENCRYPT sets no AAD; see provenance):
;;;   * serialized-payload (Slice 1, here, T10-INTEROP-RECONCILE): AAD = EMPTY (was the 20-byte SecureDataHeader;
;;;     reconciled to empty — header integrity now via the decode kind/key_id find_key check + the nonce).
;;;   * submessage protection (Slice 4 T2, crypto/submessage.lisp): AAD = empty (ENCRYPT) or the plaintext
;;;     submessage (SIGN/GMAC).
;;; The CryptoHeader is NEVER folded in here; the caller decides the AAD. session_id + iv_suffix together form the
;;; 12-byte nonce — uniqueness is the caller's responsibility (%km-next-iv-suffix).

(defun* %km-nonce (session-id iv-suffix)
    (function ((simple-array (unsigned-byte 8) (*)) (simple-array (unsigned-byte 8) (*)))
              (simple-array (unsigned-byte 8) (12)))
  "Build the 12-byte AES-GCM nonce = session_id(4) ∥ iv_suffix(8) (§9.5.3.3.4.3; NIST SP 800-38D
   §8.2.1). SESSION-ID must be 4 octets and IV-SUFFIX 8 (caller precondition)."
  (let ((nonce (make-array 12 :element-type '(unsigned-byte 8))))
    (replace nonce session-id :start1 0 :end1 4)
    (replace nonce iv-suffix  :start1 4 :end1 12)
    nonce))

(defun* %seal-with-km (km session-id iv-suffix aad plaintext)
    (function (key-material
               (simple-array (unsigned-byte 8) (*)) (simple-array (unsigned-byte 8) (*))
               (simple-array (unsigned-byte 8) (*)) (simple-array (unsigned-byte 8) (*)))
              (values (simple-array (unsigned-byte 8) (*)) (simple-array (unsigned-byte 8) (*))))
  "Shared AES-256-GCM seal: look up the cached session key for KM via %KM-SESSION-KEY-AT
   (derives once per session_id via §9.5.3.3.4.2 KDF; zero-alloc on hit), build the nonce from
   SESSION-ID∥IV-SUFFIX, and seal PLAINTEXT authenticating AAD. Returns (values CIPHERTEXT TAG).
   AAD is a PARAMETER (see the section note above) — empty PLAINTEXT yields a pure GMAC tag over AAD."
  (dds.dare:aes-256-gcm-seal (%km-session-key-at km session-id 0)
                             (%km-nonce session-id iv-suffix)
                             aad plaintext))

(defun* %open-with-km (km session-id iv-suffix aad ciphertext tag)
    (function (key-material
               (simple-array (unsigned-byte 8) (*)) (simple-array (unsigned-byte 8) (*))
               (simple-array (unsigned-byte 8) (*)) (simple-array (unsigned-byte 8) (*))
               (simple-array (unsigned-byte 8) (*)))
              (or (simple-array (unsigned-byte 8) (*)) null))
  "Shared AES-256-GCM open: look up the cached session key via %KM-SESSION-KEY-AT (same key as
   %SEAL-WITH-KM for the same SESSION-ID; §9.5.3.3.4.2), build the nonce from SESSION-ID∥IV-SUFFIX,
   and open CIPHERTEXT/TAG authenticating AAD. Returns the plaintext, or NIL on any GCM authentication
   failure (fail-closed; NIST SP 800-38D §8.3). AAD is a PARAMETER (see the section note above)."
  (dds.dare:aes-256-gcm-open (%km-session-key-at km session-id 0)
                             (%km-nonce session-id iv-suffix)
                             aad ciphertext tag))

;;; --- zero-alloc into-buffer SecuredPayload codec core (§9.5.3.3.4.4/4.5) + thin allocating wrappers ---
;;; The -into core writes the §9.5.3.3 SecuredPayload directly through a STATIC octet-buffer's SAP with NO
;;; GC-heap allocation: the 12-byte AES-GCM nonce is the in-place SecuredPayload[8..20] sub-slice (no nonce
;;; buffer), ciphertext+tag are sealed through the buffer SAP, and the session key is cached per KM. It is
;;; byte-IDENTICAL to (serialize-secured-payload kind key_id session_id iv_suffix (aes-256-gcm-seal ...)) by
;;; CONSTRUCTION — it reuses the SAME §7.3.7 header codec (serialize-crypto-header), the SAME big-endian
;;; length/count encoder (%put-u32-be) and the SAME §9.5.3.3.3 4-align pad (align), and aes-256-gcm-seal-into
;;; emits ct+tag byte-identical to aes-256-gcm-seal (NIST SP 800-38D TC16, Task-1 KAT). encode/decode-serialized-
;;; payload are thin allocating wrappers over it, so the byte-exact corpora exercise the core (the wire is unchanged).

(defun* %get-u32-be-at (vec off)
    (function ((simple-array (unsigned-byte 8) (*)) fixnum) (unsigned-byte 32))
  "Read a big-endian uint32 from VEC[OFF..OFF+4] with NO allocation — the in-place decode-side reader for the
   §9.5.3.3.4.4 crypto_content length and the §9.5.3.3.3 receiver_specific_macs_count (big-endian on the wire,
   independent of any cursor endianness; see %get-u32-be) so decode-serialized-payload-into stays zero-alloc.
   Caller guarantees OFF+4 <= (length VEC) (validated before the read; NFR-SEC-POSTURE)."
  (logior (ash (aref vec off) 24)
          (ash (aref vec (+ off 1)) 16)
          (ash (aref vec (+ off 2)) 8)
          (aref vec (+ off 3))))

(defun* %put-u32-be-at (vec off value)
    (function ((simple-array (unsigned-byte 8) (*)) fixnum (unsigned-byte 32)) (eql t))
  "Write VALUE as a big-endian uint32 into VEC[OFF..OFF+4] with NO allocation — the in-place encode-side writer
   (the inverse of %get-u32-be-at) for the §9.5.3.3.4.4 crypto_content length and the §9.5.3.3.3
   receiver_specific_macs_count (big-endian on the wire, independent of any cursor; byte-identical to %put-u32-be)
   so encode-serialized-payload-into stays cursor-free / zero GC-heap alloc. Caller guarantees OFF+4 <= (length VEC)
   (the encode-side O(1) total-extent check). Returns T."
  (setf (aref vec off)       (logand (ash value -24) #xff)
        (aref vec (+ off 1)) (logand (ash value -16) #xff)
        (aref vec (+ off 2)) (logand (ash value -8)  #xff)
        (aref vec (+ off 3)) (logand value           #xff))
  t)

(defun* encode-serialized-payload-into (out-buf km plaintext)
    (function (dds.core.buffer:octet-buffer key-material (simple-array (unsigned-byte 8) (*))) fixnum)
  "Build the DDS-Security §9.5.3.3 SecuredPayload for PLAINTEXT under KM into OUT-BUF (a STATIC octet-buffer,
   dds.core.buffer:make-octet-buffer) starting at position 0; return the total octet length. ZERO GC-heap
   allocation in this codec: the SecureDataHeader, the crypto_content length, the §9.5.3.3.3 4-align pad and the
   rsm_count are written through OUT-BUF's vector with RAW OFFSET WRITES — no cursor struct is consed (a cursor
   cannot be stack-allocated here: dds.core.buffer:cursor is not inlined, so binding one heap-conses per call —
   measured ~48 B/call, eliminated). The 12-byte AES-GCM nonce is the contiguous OUT-BUF[8..20] sub-slice
   (session_id(4)‖iv_suffix(8), §9.5.3.3.4.3) written in place — no nonce buffer; ciphertext+tag are sealed
   directly through OUT-BUF's static SAP by aes-256-gcm-seal-into; the iv_suffix is stamped in place by
   %km-next-iv-suffix-into; the session key is cached per KM. (The only residual per-call consing is the OpenSSL
   EVP FFI SAP-boxing inside aes-256-gcm-seal-into, shared IDENTICALLY with decode-serialized-payload-into — a
   dds.dare follow-on, out of this codec's scope.) OUT-BUF must hold >= 44 + |PLAINTEXT| + 3 octets, else
   BUFFER-OVERFLOW (O(1) extent check before any write, safety-0-safe; NFR-SEC-POSTURE). Algorithm (§9.5.3.3.4.4):
   claim a UNIQUE iv_suffix (monotonic counter, STRUCTURAL nonce uniqueness — see the argument at the top of
   transform.lisp); AES-256-GCM seal under EMPTY AAD (+empty-octets+, Fast-DDS-faithful — Fast DDS
   serialize_SecureDataBody ENCRYPT sets no AAD; header integrity is the decode find_key kind/key_id check + the
   nonce; T10-INTEROP-RECONCILE, see docs/provenance.md); rsm_count = 0 (no origin auth). The layout is
   BYTE-IDENTICAL to serialize-secured-payload (same field widths/offsets + big-endian %put-u32-be-at + the (-N)
   mod 4 pad; seal-into == seal), proven by the byte-exact corpora AND the serialize-secured-payload oracle pin in
   run-security-payload-into-test. Returns the total length (44 + N + pad)."
  (let* ((vec     (dds.core.buffer:octet-buffer-vec out-buf))
         (n       (length plaintext))
         (ct-off  (+ +secure-data-header-len+ +crypto-content-length-len+))  ; ciphertext starts at 24
         (tag-off (+ ct-off n))                                              ; common_mac @ 24+N
         (pad     (mod (- n) 4))                                             ; §9.5.3.3.3 SecureDataTag 4-align pad
         (rsm-off (+ tag-off +common-mac-len+ pad))                          ; rsm_count @ 40+N+pad
         (total   (+ rsm-off +receiver-specific-macs-count-len+)))           ; 44+N+pad
    ;; O(1) output-extent bound BEFORE any write (safety-0-safe; replaces the cursor check-room) — NFR-SEC-POSTURE
    (unless (<= total (length vec))
      (error 'dds.core.buffer:buffer-overflow :need total :have (length vec)))
    ;; SecureDataHeader kind‖key_id‖session_id by raw offset write (same widths/offsets as serialize-crypto-header)
    (replace vec (key-material-transformation-kind km) :start1 0 :end1 +transformation-kind-len+)
    (replace vec (key-material-sender-key-id km)
             :start1 +transformation-kind-len+ :end1 +secure-data-header-session-id-off+)
    (replace vec +fixed-session-id+
             :start1 +secure-data-header-session-id-off+ :end1 +secure-data-header-iv-suffix-off+)
    ;; stamp the monotonic iv_suffix in place at offset 12 (byte-identical to serialize-secured-payload's header)
    (%km-next-iv-suffix-into km vec +secure-data-header-iv-suffix-off+)
    ;; crypto_content length (uint32 BE, §9.5.3.3.4.4) — byte-identical to serialize-crypto-content's %put-u32-be
    (%put-u32-be-at vec +secure-data-header-len+ n)
    ;; ciphertext + common_mac sealed directly into OUT-BUF; nonce = OUT-BUF[8..20] sub-slice; EMPTY AAD
    (dds.dare:aes-256-gcm-seal-into vec ct-off tag-off
                                    (%km-session-key-at km +fixed-session-id+ 0)
                                    vec +secure-data-header-session-id-off+
                                    +empty-octets+ plaintext 0 n)
    ;; SecureDataTag tail: zero the §9.5.3.3.3 4-align pad after common_mac, then rsm_count=0 (uint32 BE)
    (dotimes (i pad) (setf (aref vec (+ tag-off +common-mac-len+ i)) 0))
    (%put-u32-be-at vec rsm-off +receiver-specific-macs-count-payload-protection+)
    total))

(defun* decode-serialized-payload-into (pt-out km secured)
    (function (dds.core.buffer:octet-buffer key-material (simple-array (unsigned-byte 8) (*)))
              (or fixnum null))
  "Recover the plaintext from a DDS-Security §9.5.3.3 SecuredPayload SECURED under KM into PT-OUT (a STATIC
   octet-buffer); return the plaintext length on success, NIL on ANY failure — fail-closed (NFR-SEC-POSTURE;
   NIST SP 800-38D §8.3). ZERO GC-heap allocation: the nonce is the SECURED[8..20] sub-slice, the session key
   is %km-session-key-at(KM, SECURED, 8) (byte-compared against the cache in place), and aes-256-gcm-open-into
   writes the plaintext through PT-OUT's static SAP — no per-sample vector is materialized. ALL length/offset
   checks run BEFORE any field read (safe even at (safety 0)): min frame >= 44, then the EXACT frame
   (len == 44 + ct_len + pad, mirroring parse-secured-payload), which also bounds the ct/tag/nonce reads.
   The find_key gate (wire kind/key_id byte-compared to the KM, no alloc — the empty-AAD header-integrity gate,
   Fast DDS AESGCMGMAC_Transform::find_key) and the rsm_count==0 check (payload protection, §9.5.3.3.4.4 step 10)
   run before the open. AAD = EMPTY (Fast-DDS-faithful, T10-INTEROP-RECONCILE). On NIL no readable plaintext
   remains (aes-256-gcm-open-into zeroizes its output region; NIST SP 800-38D §7.2). PT-OUT must hold >= ct_len
   octets. Behaviourally identical to decode-serialized-payload/parse-secured-payload, zero-alloc."
  (handler-case
      (let ((len (length secured)))
        ;; min frame = header(20) + ct_len(4) + SecureDataTag(20) = 44 (§9.5.3.3)
        (when (< len (+ +secure-data-header-len+ +crypto-content-length-len+ +secure-data-tag-len+))
          (return-from decode-serialized-payload-into nil))
        (let* ((ct-len  (%get-u32-be-at secured +secure-data-header-len+))                ; crypto_content.length BE @ 20
               (ct-off  (+ +secure-data-header-len+ +crypto-content-length-len+))         ; 24
               (tag-off (+ ct-off ct-len))                                                ; common_mac @ 24+N
               (pad     (mod (- ct-len) 4))                                               ; §9.5.3.3.3 4-align pad
               (rsm-off (+ tag-off +common-mac-len+ pad)))                                ; rsm_count @ 40+N+pad
          ;; EXACT frame (mirror parse-secured-payload: total == 44+ct_len+pad) — also bounds the ct/tag/nonce reads
          (when (/= len (+ rsm-off +receiver-specific-macs-count-len+))
            (return-from decode-serialized-payload-into nil))
          ;; find_key (empty-AAD header-integrity gate): wire kind/key_id MUST equal the KM, byte-compared, no alloc
          (when (or (mismatch secured (key-material-transformation-kind km)
                              :start1 0 :end1 +transformation-kind-len+)
                    (mismatch secured (key-material-sender-key-id km)
                              :start1 +transformation-kind-len+ :end1 +secure-data-header-session-id-off+))
            (return-from decode-serialized-payload-into nil))
          ;; payload protection: rsm_count MUST be 0 (§9.5.3.3.4.4 step 10) — fail-closed like parse-secured-payload
          (when (/= +receiver-specific-macs-count-payload-protection+ (%get-u32-be-at secured rsm-off))
            (return-from decode-serialized-payload-into nil))
          ;; AES-256-GCM open: nonce = SECURED[8..20], EMPTY AAD, ct/tag read in place, plaintext via PT-OUT SAP
          (if (dds.dare:aes-256-gcm-open-into (dds.core.buffer:octet-buffer-vec pt-out) 0
                                              (%km-session-key-at km secured +secure-data-header-session-id-off+)
                                              secured +secure-data-header-session-id-off+
                                              +empty-octets+
                                              secured ct-off ct-len
                                              secured tag-off)
              ct-len
              nil)))
    ;; Any condition (bounds, constraint, EVP, etc.) -> NIL (fail-closed).
    (error () nil)))

(defun* encode-serialized-payload (km plaintext)
    (function (key-material (simple-array (unsigned-byte 8) (*)))
              (simple-array (unsigned-byte 8) (*)))
  "Encrypt PLAINTEXT under KM and return a fresh DDS-Security §9.5.3.3 SecuredPayload octet vector. Thin
   ALLOCATING wrapper over the zero-alloc core encode-serialized-payload-into: it allocates a static scratch
   octet-buffer, builds the SecuredPayload into it (§9.5.3.3.4.4: unique iv_suffix, AES-256-GCM seal under
   EMPTY AAD, rsm_count=0; see the core for the full algorithm + spec citations), copies out the exact bytes,
   and frees the scratch. The wire is byte-identical to serialize-secured-payload (the core reuses the §7.3.7
   codecs; the byte-exact corpora prove it). AAD = EMPTY (Fast-DDS-faithful, T10-INTEROP-RECONCILE; header
   integrity is the decode find_key kind/key_id check + the nonce). Returns a fresh octet vector."
  (let ((out (dds.core.buffer:make-octet-buffer (+ 64 (length plaintext)))))
    (unwind-protect
         (let ((len (encode-serialized-payload-into out km plaintext)))
           (subseq (dds.core.buffer:octet-buffer-vec out) 0 len))
      (dds.pal:free-static (dds.core.buffer:octet-buffer-vec out)))))

(defun* decode-serialized-payload (km secured-octets)
    (function (key-material (simple-array (unsigned-byte 8) (*)))
              (or (simple-array (unsigned-byte 8) (*)) null))
  "Decrypt a DDS-Security §9.5.3.3 SecuredPayload produced by encode-serialized-payload; return the plaintext
   octet vector on success, NIL on any failure (bounds violation, find_key mismatch, GCM auth failure, or
   malformed blob) — fail-closed (NFR-SEC-POSTURE; NIST SP 800-38D §8.3). Thin ALLOCATING wrapper over the
   zero-alloc core decode-serialized-payload-into: it allocates a static scratch octet-buffer, recovers the
   plaintext into it (§9.5.3.3.4.5: min/exact-frame bounds, find_key kind/key_id gate, rsm_count==0 check,
   AES-256-GCM open under EMPTY AAD; see the core for the full algorithm + spec citations), copies out the
   exact plaintext (or NIL), and frees the scratch. AAD = EMPTY (Fast-DDS-faithful, T10-INTEROP-RECONCILE).
   Returns a fresh octet vector, or NIL."
  (let ((pt-out (dds.core.buffer:make-octet-buffer (max 1 (length secured-octets)))))
    (unwind-protect
         (let ((plen (decode-serialized-payload-into pt-out km secured-octets)))
           (and plen (subseq (dds.core.buffer:octet-buffer-vec pt-out) 0 plen)))
      (dds.pal:free-static (dds.core.buffer:octet-buffer-vec pt-out)))))
