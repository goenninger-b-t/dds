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

(defun* %km-gmac-p (km)
    (function (key-material) boolean)
  "T iff KM advertises the §9.5.3.3.1 AES256-GMAC transformation_kind {0,0,0,3} — the SIGN sub-tier that
   AUTHENTICATES the VISIBLE serialized payload with a GMAC common_mac and does NOT encrypt it (§9.5.3.3.4.3);
   NIL for AES256-GCM {0,0,0,4}, the ENCRYPT tier (§9.5.3.3.4.4). Selects the branch in encode/decode-serialized-
   payload-into. Zero-alloc (a 4-octet mismatch, no consing) so the per-sample secured path stays alloc-free."
  (null (mismatch (key-material-transformation-kind km) +transformation-kind-aes256-gmac+)))

(defun* key-material-encrypt-p (km)
    (function (key-material) boolean)
  "T iff KM is the §9.5.3.3.1 AES256-GCM ENCRYPT tier {0,0,0,4} — the CONFIDENTIALITY sub-tier that HIDES the
   serialized payload as ciphertext (§9.5.3.3.4.4); NIL for AES256-GMAC {0,0,0,3}, the SIGN sub-tier that leaves
   the payload VISIBLE but AUTHENTICATED by a common_mac (§9.5.3.3.4.3). The negation of %km-gmac-p (DRY).
   Zero-alloc (a 4-octet compare, no consing).
   NOTE (ADR 0058): this is NOT the ZC/SHMEM overlay eligibility gate. It was, while the overlay served the
   ENCRYPT tier only; the overlay now covers BOTH tiers (a SIGN writer seals a GMAC SecuredPayload into the
   slot — visible payload, authenticated), so eligibility asks only whether a payload KM resolves at all."
  (not (%km-gmac-p km)))

(defun* secured-payload-length (km plaintext-len)
    (function (key-material (integer 0)) (integer 0))
  "The EXACT octet length of the §9.5.3.3 SecuredPayload encode-serialized-payload-into will produce for a
   PLAINTEXT-LEN-octet plaintext under KM — the same per-tier arithmetic as the encoder, in one place (DRY),
   so a caller can size a buffer or gate on a capacity WITHOUT sealing first or hardcoding the framing:
     SIGN / AES256-GMAC {0,0,0,3} (§9.5.3.3.4.3): header(20) ‖ plaintext ‖ 4-align pad ‖ common_mac(16) ‖
       rsm_count(4)  =  40 + align4(N)  — no crypto_content length prefix (that is ENCRYPT-only).
     ENCRYPT / AES256-GCM {0,0,0,4} (§9.5.3.3.4.4): header(20) ‖ crypto_content.length(4) ‖ ciphertext(N) ‖
       common_mac(16) ‖ 4-align pad ‖ rsm_count(4)  =  44 + N + pad4(N).
   Used by the Zero-Copy overlay send gate (ADR 0051/0058) to decide whether the sealed payload fits a pool
   slot before it touches the pool — a fail-closed capacity check, not an estimate."
  (let ((pad (mod (- plaintext-len) 4)))
    (if (%km-gmac-p km)
        (+ +secure-data-header-len+ plaintext-len pad
           +common-mac-len+ +receiver-specific-macs-count-len+)
        (+ +secure-data-header-len+ +crypto-content-length-len+ plaintext-len
           +common-mac-len+ pad +receiver-specific-macs-count-len+))))

(defun* %put-crypto-header-into (km vec)
    (function (key-material (simple-array (unsigned-byte 8) (*))) (eql t))
  "Write the §9.5.3.3.1 SecureDataHeader — transformation_kind(4) ‖ transformation_key_id(4) ‖ session_id(4) ‖
   init_vector_suffix(8) = 20 octets — for KM into VEC[0..20], stamping a UNIQUE monotonic iv_suffix in place
   (%km-next-iv-suffix-into) and session_id = +fixed-session-id+ (all-zeros). The SHARED header writer for BOTH the
   ENCRYPT (§9.5.3.3.4.4) and GMAC (§9.5.3.3.4.3) branches of encode-serialized-payload-into — the two tiers differ
   ONLY in the body/tag, never the header (DRY). Zero GC-heap alloc (raw offset writes); the SecuredPayload always
   starts at VEC position 0 (no submessage bracket at this tier). Caller guarantees (length VEC) >= 20. Returns T."
  (replace vec (key-material-transformation-kind km) :start1 0 :end1 +transformation-kind-len+)
  (replace vec (key-material-sender-key-id km)
           :start1 +transformation-kind-len+ :end1 +secure-data-header-session-id-off+)
  (replace vec +fixed-session-id+
           :start1 +secure-data-header-session-id-off+ :end1 +secure-data-header-iv-suffix-off+)
  (%km-next-iv-suffix-into km vec +secure-data-header-iv-suffix-off+)
  t)

(defun* %payload-find-key-mismatch-p (secured km)
    (function ((simple-array (unsigned-byte 8) (*)) key-material) boolean)
  "T iff the wire SecureDataHeader in SECURED does NOT match KM on transformation_kind[0..4) OR
   transformation_key_id[4..8) — the §9.5.3.3.4.5 find_key gate (Fast DDS AESGCMGMAC_Transform::find_key), the
   empty-AAD header-integrity check SHARED by BOTH the ENCRYPT and GMAC decode branches (DRY). Byte-compared in
   place (mismatch), zero-alloc. A mismatch means this SecuredPayload was not sealed for KM -> the caller
   fail-closes (NIL). Caller guarantees (length SECURED) >= 8."
  (or (and (mismatch secured (key-material-transformation-kind km)
                     :start1 0 :end1 +transformation-kind-len+) t)
      (and (mismatch secured (key-material-sender-key-id km)
                     :start1 +transformation-kind-len+ :end1 +secure-data-header-session-id-off+) t)))

(defun* encode-serialized-payload-into (out-buf km plaintext)
    (function (dds.core.buffer:octet-buffer key-material (simple-array (unsigned-byte 8) (*))) fixnum)
  "Build the DDS-Security §9.5.3.3 SecuredPayload for PLAINTEXT under KM into OUT-BUF (a STATIC octet-buffer,
   dds.core.buffer:make-octet-buffer) starting at position 0; return the total octet length. The tier is selected
   by KM's transformation_kind (§9.5.3.3.1): AES256-GCM {0,0,0,4} -> ENCRYPT (§9.5.3.3.4.4, the payload is HIDDEN
   as ciphertext); AES256-GMAC {0,0,0,3} -> SIGN (§9.5.3.3.4.3, the payload stays VISIBLE and is AUTHENTICATED by a
   GMAC common_mac). Both share the 20-byte §9.5.3.3.1 SecureDataHeader (%put-crypto-header-into) and an rsm_count=0
   §9.5.3.3.3 SecureDataTag common_mac; they differ ONLY in the body:
     ENCRYPT: crypto_content.length(4, BE) ‖ ciphertext(N) ‖ common_mac(16) ‖ ((-N) mod 4) pad ‖ rsm_count(4).
              Total = 44 + N + pad. AES-256-GCM seal under EMPTY AAD -> ciphertext + tag. BYTE-IDENTICAL to
              serialize-secured-payload (same widths/offsets + big-endian %put-u32-be-at + the pad; seal-into == seal),
              proven by the byte-exact corpora AND the serialize-secured-payload oracle pin in run-security-payload-into-test.
     GMAC:    plaintext(N) ‖ 4-align pad (((-N) mod 4) zero octets) ‖ common_mac(16) ‖ rsm_count(4). Total = 40 + align4(N),
              NO crypto_content.length prefix (that is ENCRYPT-only). The SerializedPayload is 4-aligned so the enclosing
              DATA submessage's octetsToNextHeader stays a multiple of 4 (RTPS 2.5 §8.3.3.2.3 / §9.4.5.1.3): a non-4-aligned
              inner submessage makes a conformant peer's secure-RTPS submessage walk fail to locate SRTPS_POSTFIX and reject
              the whole message — observed LIVE against RTI Connext 7.3.1 (WP-SECURITY-DATA-SIGN-LIVE-CONNEXT). The 4-align
              pad is part of the GMAC'd body — the common_mac authenticates plaintext‖pad and decode returns align4(N) octets
              whose trailing pad the CDR deserializer ignores — byte-exact to live Connext (our decode GMAC-verified Connext's
              4-aligned GMAC payloads). aes-256-gcm-seal-into with pt-len 0 GMACs AAD = OUT-BUF[20,20+align4(N)) -> common_mac
              (the ZA-2 GMAC-into pattern). Corroborated CLEAN-ROOM against Fast DDS AESGCMGMAC_Transform.cpp
              serialize_SecureDataBody (!do_encryption: verbatim body, no cnt_length); decode_serialized_payload recovers
              N = total-20(header)-20(tag); see docs/provenance.md. For a 4-aligned N the pad is 0 -> byte-identical to the
              run-security-gmac-payload-test golden.
   ZERO GC-heap allocation in EITHER tier: the SecureDataHeader, lengths, pad and rsm_count are written through OUT-BUF's
   vector with RAW OFFSET WRITES — no cursor struct is consed; the 12-byte AES-GCM nonce is the contiguous OUT-BUF[8..20]
   sub-slice (session_id(4)‖iv_suffix(8), §9.5.3.3.4.3) written in place — no nonce buffer; ciphertext/plaintext + tag are
   sealed directly through OUT-BUF's static SAP by aes-256-gcm-seal-into; the iv_suffix is stamped in place by
   %km-next-iv-suffix-into (STRUCTURAL nonce uniqueness — see the argument at the top of transform.lisp); the session key
   is cached per KM. (The only residual per-call consing is the OpenSSL EVP FFI SAP-boxing inside aes-256-gcm-seal-into,
   shared with decode.) OUT-BUF must hold the total length, else BUFFER-OVERFLOW (an O(1) extent check BEFORE any write,
   safety-0-safe; NFR-SEC-POSTURE). rsm_count = 0 (no origin auth). Returns the total length."
  (let* ((vec (dds.core.buffer:octet-buffer-vec out-buf))
         (n   (length plaintext)))
    (if (%km-gmac-p km)
        ;; --- GMAC / SIGN sub-tier (§9.5.3.3.4.3): VISIBLE 4-aligned plaintext + GMAC common_mac, no length prefix ---
        (let* ((pad     (mod (- n) 4))                                    ; §8.3.3.2.3 4-align the SerializedPayload so octetsToNextHeader stays 4-aligned
               (body-n  (+ n pad))                                        ; GMAC'd body = plaintext ‖ 4-align pad
               (ct-off  +secure-data-header-len+)                         ; visible plaintext @ 20
               (tag-off (+ ct-off body-n))                                ; common_mac @ 20+align4(N)
               (rsm-off (+ tag-off +common-mac-len+))                     ; rsm_count @ 36+align4(N)
               (total   (+ rsm-off +receiver-specific-macs-count-len+)))  ; 40+align4(N), a multiple of 4
          ;; §9.5.3.3.4.3 GMAC/!encrypt: SecuredPayload = header(20)‖plaintext(N)‖4-align pad‖common_mac(16)‖rsm_count(4); the pad rides INSIDE the GMAC'd body (Fast DDS/Connext-compatible) so the SecuredPayload is 4-aligned — a non-4-aligned inner DATA submessage makes a conformant peer's secure-RTPS submessage walk fail to find SRTPS_POSTFIX (observed live, WP-SECURITY-DATA-SIGN-LIVE-CONNEXT); the trailing pad is authenticated + ignored by the receiver's CDR deserializer
          (unless (<= total (length vec))
            (error 'dds.core.buffer:buffer-overflow :need total :have (length vec)))
          (%put-crypto-header-into km vec)
          ;; visible plaintext VERBATIM as the CryptoContent, then the 4-align pad zeroed (Fast DDS serialize_SecureDataBody !do_encryption)
          (replace vec plaintext :start1 ct-off :end1 (+ ct-off n))
          (dotimes (i pad) (setf (aref vec (+ ct-off n i)) 0))
          ;; GMAC over plaintext‖pad IN PLACE (AAD = OUT-BUF[20,20+align4(N)), pt-len 0 -> tag only) -> common_mac @ tag-off; nonce = OUT-BUF[8..20]
          (dds.dare:aes-256-gcm-seal-into vec ct-off tag-off
                                          (%km-session-key-at km +fixed-session-id+ 0)
                                          vec +secure-data-header-session-id-off+
                                          vec +empty-octets+ 0 0 ct-off body-n)
          (%put-u32-be-at vec rsm-off +receiver-specific-macs-count-payload-protection+)
          total)
        ;; --- ENCRYPT tier (§9.5.3.3.4.4): ciphertext + GCM tag under EMPTY AAD (UNCHANGED, byte-identical) ---
        (let* ((ct-off  (+ +secure-data-header-len+ +crypto-content-length-len+))  ; ciphertext starts at 24
               (tag-off (+ ct-off n))                                              ; common_mac @ 24+N
               (pad     (mod (- n) 4))                                             ; §9.5.3.3.3 SecureDataTag 4-align pad
               (rsm-off (+ tag-off +common-mac-len+ pad))                          ; rsm_count @ 40+N+pad
               (total   (+ rsm-off +receiver-specific-macs-count-len+)))           ; 44+N+pad
          ;; O(1) output-extent bound BEFORE any write (safety-0-safe; replaces the cursor check-room) — NFR-SEC-POSTURE
          (unless (<= total (length vec))
            (error 'dds.core.buffer:buffer-overflow :need total :have (length vec)))
          (%put-crypto-header-into km vec)
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
          total))))

(defun* decode-serialized-payload-into (pt-out km secured)
    (function (dds.core.buffer:octet-buffer key-material (simple-array (unsigned-byte 8) (*)))
              (or fixnum null))
  "Recover the plaintext from a DDS-Security §9.5.3.3 SecuredPayload SECURED under KM into PT-OUT (a STATIC
   octet-buffer); return the plaintext length on success, NIL on ANY failure — fail-closed (NFR-SEC-POSTURE;
   NIST SP 800-38D §8.3). The tier is selected by KM's transformation_kind (§9.5.3.3.1): AES256-GCM -> ENCRYPT
   (§9.5.3.3.4.5, AES-256-GCM open of the ciphertext), AES256-GMAC -> SIGN (§9.5.3.3.4.3, GMAC-verify the VISIBLE
   plaintext). ZERO GC-heap allocation in EITHER tier: the nonce is the SECURED[8..20] sub-slice, the session key is
   %km-session-key-at(KM, SECURED, 8) (byte-compared against the cache in place), and aes-256-gcm-open-into
   writes/verifies through static SAPs — no per-sample vector is materialized. ALL length/offset checks run BEFORE any
   field read (safe even at (safety 0)); the shared find_key gate (%payload-find-key-mismatch-p — wire kind/key_id
   byte-compared to KM, the empty-AAD header-integrity gate, Fast DDS AESGCMGMAC_Transform::find_key) and the
   rsm_count==0 check (payload protection, §9.5.3.3.4.4 step 10) run before the open/verify.
     ENCRYPT: min frame >= 44, then the EXACT frame (len == 44 + ct_len + pad, mirroring parse-secured-payload),
              which bounds the ct/tag/nonce reads; AES-256-GCM open (EMPTY AAD, ct/tag in place) -> plaintext via
              PT-OUT SAP, or NIL on auth failure (aes-256-gcm-open-into zeroizes its output region; SP 800-38D §7.2).
     GMAC:    min frame >= 40 (header 20 + SecureDataTag 20, NO crypto_content.length at this tier); N = len - 40
              (Fast DDS decode_serialized_payload !is_encrypted: body = total - sizeof(header) - (sizeof(u32)+16)). N
              MUST fit PT-OUT — a larger recovered payload fail-closes to NIL (RESOURCE_LIMITS, NFR-MEM), NEVER a silent
              truncation of a verified payload (the pooled decode buffer is *secured-payload-max-bytes*; the allocating
              wrapper sizes PT-OUT to len, so it never trips). Then GMAC-verify the VISIBLE content SECURED[20..20+N]
              (AAD, ct-len 0) against common_mac SECURED[20+N..36+N] with nonce SECURED[8..20]. On verify success the
              visible plaintext is copied to PT-OUT and its length N returned; on ANY mismatch/tamper -> NIL (no
              false-ACCEPT of an unauthenticated payload).
   On NIL no readable plaintext remains. PT-OUT must hold >= the plaintext length. Behaviourally identical to
   decode-serialized-payload (the allocating wrapper), zero-alloc."
  (handler-case
      (let ((len (length secured)))
        (if (%km-gmac-p km)
            ;; --- GMAC / SIGN verify (§9.5.3.3.4.3): the CryptoContent IS the plaintext; authenticate it ---
            (progn
              ;; min frame = header(20) + SecureDataTag(20) = 40 (no crypto_content.length at this tier)
              (when (< len (+ +secure-data-header-len+ +secure-data-tag-len+))
                (return-from decode-serialized-payload-into nil))
              (let* ((n       (- len +secure-data-header-len+ +secure-data-tag-len+))  ; visible content length = len-40
                     (ct-off  +secure-data-header-len+)                                ; visible content @ 20
                     (tag-off (+ ct-off n))                                            ; common_mac @ 20+N
                     (rsm-off (+ tag-off +common-mac-len+)))                           ; rsm_count @ 36+N (= len-4)
                ;; RESOURCE_LIMITS fail-closed (NFR-MEM): the recovered plaintext N (= len-40) MUST fit PT-OUT — the GMAC replace below is length-bounded by PT-OUT and would SILENTLY TRUNCATE a larger verified payload (the ENCRYPT tier's aes-256-gcm-open-into already extent-guards); reject instead, never truncate a verified payload
                (when (> n (dds.pal:static-length (dds.core.buffer:octet-buffer-vec pt-out)))
                  (return-from decode-serialized-payload-into nil))
                ;; find_key (empty-AAD header-integrity gate): wire kind/key_id MUST equal the KM, byte-compared, no alloc
                (when (%payload-find-key-mismatch-p secured km)
                  (return-from decode-serialized-payload-into nil))
                ;; payload protection: rsm_count MUST be 0 (§9.5.3.3.4.4 step 10)
                (when (/= +receiver-specific-macs-count-payload-protection+ (%get-u32-be-at secured rsm-off))
                  (return-from decode-serialized-payload-into nil))
                ;; GMAC verify IN PLACE: ct-len 0, AAD = the VISIBLE content [20,20+N), tag = common_mac @ tag-off,
                ;; nonce = SECURED[8..20]. aes-256-gcm-open-into returns T iff the GMAC matches (fail-closed NIL else).
                (if (dds.dare:aes-256-gcm-open-into (dds.core.buffer:octet-buffer-vec pt-out) 0
                                                    (%km-session-key-at km secured +secure-data-header-session-id-off+)
                                                    secured +secure-data-header-session-id-off+
                                                    secured
                                                    secured ct-off 0
                                                    secured tag-off
                                                    ct-off n)
                    ;; authenticated: copy the visible plaintext out to PT-OUT and return its length
                    (progn (replace (dds.core.buffer:octet-buffer-vec pt-out) secured
                                    :start1 0 :start2 ct-off :end2 tag-off)
                           n)
                    nil)))
            ;; --- ENCRYPT open (§9.5.3.3.4.5): AES-256-GCM decrypt the ciphertext (UNCHANGED, byte-identical) ---
            (progn
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
                (when (%payload-find-key-mismatch-p secured km)
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
                    nil)))))
    ;; Any condition (bounds, constraint, EVP, etc.) -> NIL (fail-closed).
    (error () nil)))

(defun* encode-serialized-payload (km plaintext)
    (function (key-material (simple-array (unsigned-byte 8) (*)))
              (simple-array (unsigned-byte 8) (*)))
  "Protect PLAINTEXT under KM and return a fresh DDS-Security §9.5.3.3 SecuredPayload octet vector. The tier is
   selected by KM's transformation_kind: AES256-GCM -> ENCRYPT (§9.5.3.3.4.4, ciphertext, HIDDEN), AES256-GMAC ->
   SIGN (§9.5.3.3.4.3, the VISIBLE plaintext + a GMAC common_mac). Thin ALLOCATING wrapper over the zero-alloc core
   encode-serialized-payload-into: it allocates a static scratch octet-buffer, builds the SecuredPayload into it
   (unique iv_suffix, rsm_count=0; see the core for the full per-tier algorithm + spec citations), copies out the
   exact bytes, and frees the scratch. The ENCRYPT wire is byte-identical to serialize-secured-payload (the byte-exact
   corpora prove it); the GMAC wire is byte-exact to §9.5.3.3.4.3 (Fast-DDS-faithful, run-security-gmac-payload-test).
   AAD = EMPTY (ENCRYPT) or the plaintext (GMAC); header integrity is the decode find_key kind/key_id check + the
   nonce (T10-INTEROP-RECONCILE). Returns a fresh octet vector."
  (let ((out (dds.core.buffer:make-octet-buffer (+ 64 (length plaintext)))))
    (unwind-protect
         (let ((len (encode-serialized-payload-into out km plaintext)))
           (subseq (dds.core.buffer:octet-buffer-vec out) 0 len))
      (dds.pal:free-static (dds.core.buffer:octet-buffer-vec out)))))

(defun* decode-serialized-payload (km secured-octets)
    (function (key-material (simple-array (unsigned-byte 8) (*)))
              (or (simple-array (unsigned-byte 8) (*)) null))
  "Recover the plaintext from a DDS-Security §9.5.3.3 SecuredPayload produced by encode-serialized-payload; return
   the plaintext octet vector on success, NIL on any failure (bounds violation, find_key mismatch, GCM/GMAC auth
   failure, or malformed blob) — fail-closed (NFR-SEC-POSTURE; NIST SP 800-38D §8.3). The tier is selected by KM's
   transformation_kind: AES256-GCM -> ENCRYPT (§9.5.3.3.4.5, AES-256-GCM open), AES256-GMAC -> SIGN (§9.5.3.3.4.3,
   GMAC-verify the VISIBLE plaintext). Thin ALLOCATING wrapper over the zero-alloc core decode-serialized-payload-into:
   it allocates a static scratch octet-buffer, recovers the plaintext into it (per-tier min/exact-frame bounds, find_key
   kind/key_id gate, rsm_count==0 check, AES-256-GCM open / GMAC verify; see the core for the full algorithm + spec
   citations), copies out the exact plaintext (or NIL), and frees the scratch. AAD = EMPTY (ENCRYPT) or the visible
   plaintext (GMAC) — T10-INTEROP-RECONCILE. Returns a fresh octet vector, or NIL."
  (let ((pt-out (dds.core.buffer:make-octet-buffer (max 1 (length secured-octets)))))
    (unwind-protect
         (let ((plen (decode-serialized-payload-into pt-out km secured-octets)))
           (and plen (subseq (dds.core.buffer:octet-buffer-vec pt-out) 0 plen)))
      (dds.pal:free-static (dds.core.buffer:octet-buffer-vec pt-out)))))
