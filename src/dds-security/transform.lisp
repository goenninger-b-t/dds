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

(defun* %km-next-iv-suffix (km)
    (function (key-material) (simple-array (unsigned-byte 8) (*)))
  "Claim the next monotonic iv_suffix from KM under KM-IV-COUNTER-LOCK, increment the counter,
   and return the 8-byte big-endian encoding of the claimed value. Nonce uniqueness is STRUCTURAL:
   the lock ensures no two concurrent callers observe the same counter value, and
   (unsigned-byte 64) never wraps in any realistic key lifetime (see nonce-uniqueness argument
   above encode-serialized-payload in transform.lisp)."
  (let ((val (dds.pal:with-lock ((key-material-iv-counter-lock km))
               (let ((v (key-material-iv-counter km)))
                 (setf (key-material-iv-counter km) (+ v 1))
                 v)))
        (buf (make-array +init-vector-suffix-len+ :element-type '(unsigned-byte 8) :initial-element 0)))
    ;; big-endian uint64 encoding into 8 bytes
    (dotimes (i 8)
      (setf (aref buf (- 7 i)) (logand (ash val (* i -8)) #xff)))
    buf))

(defun* %assemble-header-aad (kind key-id session-id iv-suffix)
    (function ((simple-array (unsigned-byte 8) (*))
               (simple-array (unsigned-byte 8) (*))
               (simple-array (unsigned-byte 8) (*))
               (simple-array (unsigned-byte 8) (*)))
              (simple-array (unsigned-byte 8) (*)))
  "Assemble the 20-byte SecureDataHeader = kind(4)∥key_id(4)∥session_id(4)∥iv_suffix(8) as the
   GCM AAD buffer (§9.5.3.3.4.4). Byte layout mirrors serialize-secured-payload so that decode
   reconstructs the BYTE-IDENTICAL 20-byte header from the parsed fields — GCM authentication
   fails if even one bit differs between seal-time AAD and open-time AAD."
  (let* ((hdr (make-array +secure-data-header-len+ :element-type '(unsigned-byte 8)))
         (cur (dds.core.buffer:cursor (dds.core.buffer:octet-buffer-over hdr) :endianness :little)))
    (dds.core.buffer:put-octets cur kind 0 +transformation-kind-len+)
    (dds.core.buffer:put-octets cur key-id 0 +transformation-key-id-len+)
    (dds.core.buffer:put-octets cur session-id 0 +session-id-len+)
    (dds.core.buffer:put-octets cur iv-suffix 0 +init-vector-suffix-len+)
    hdr))

;;; --- shared session-key + nonce + AES-GCM core (DRY across all §9.5.3.3 protection tiers) ---
;;; The AAD is a PARAMETER so each tier composes its own authenticated-but-not-encrypted region:
;;;   * serialized-payload (Slice 1, here): AAD = the 20-byte SecureDataHeader (§9.5.3.3.4.4).
;;;   * submessage protection (Slice 4 T2, crypto/submessage.lisp): AAD = empty (ENCRYPT) or the
;;;     plaintext submessage (SIGN/GMAC) — Fast-DDS-faithful (the operating contract §4: the wire is
;;;     the oracle; corroborated against eProsima Fast DDS AESGCMGMAC_Transform.cpp, see provenance).
;;; The CryptoHeader is NEVER folded in here; the caller decides the AAD. session_id + iv_suffix
;;; together form the 12-byte nonce — uniqueness is the caller's responsibility (%km-next-iv-suffix).

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
  "Shared AES-256-GCM seal: derive the session key from KM (derive-session-key over
   master_sender_key, master_salt, SESSION-ID; §9.5.3.3.4.2), build the nonce from
   SESSION-ID∥IV-SUFFIX, and seal PLAINTEXT authenticating AAD. Returns (values CIPHERTEXT TAG).
   AAD is a PARAMETER (see the section note above) — empty PLAINTEXT yields a pure GMAC tag over AAD."
  (dds.dare:aes-256-gcm-seal (derive-session-key (key-material-master-sender-key km)
                                                 (key-material-master-salt km)
                                                 session-id)
                             (%km-nonce session-id iv-suffix)
                             aad plaintext))

(defun* %open-with-km (km session-id iv-suffix aad ciphertext tag)
    (function (key-material
               (simple-array (unsigned-byte 8) (*)) (simple-array (unsigned-byte 8) (*))
               (simple-array (unsigned-byte 8) (*)) (simple-array (unsigned-byte 8) (*))
               (simple-array (unsigned-byte 8) (*)))
              (or (simple-array (unsigned-byte 8) (*)) null))
  "Shared AES-256-GCM open: derive the same session key + nonce as %SEAL-WITH-KM and open
   CIPHERTEXT/TAG authenticating AAD. Returns the plaintext, or NIL on any GCM authentication
   failure (fail-closed; NIST SP 800-38D §8.3). AAD is a PARAMETER (see the section note above)."
  (dds.dare:aes-256-gcm-open (derive-session-key (key-material-master-sender-key km)
                                                 (key-material-master-salt km)
                                                 session-id)
                             (%km-nonce session-id iv-suffix)
                             aad ciphertext tag))

(defun* encode-serialized-payload (km plaintext)
    (function (key-material (simple-array (unsigned-byte 8) (*)))
              (simple-array (unsigned-byte 8) (*)))
  "Encrypt PLAINTEXT under KM and return a DDS-Security §9.5.3.3 SecuredPayload octet vector.
   Algorithm (§9.5.3.3.4.4):
     1. Claim a UNIQUE iv_suffix from km's monotonic counter (%km-next-iv-suffix) — STRUCTURAL
        nonce uniqueness; see the nonce-uniqueness argument at the top of transform.lisp.
     2. Derive the AES-256 session key: derive-session-key(km.master_sender_key, km.master_salt,
        +fixed-session-id+) per §9.5.3.3.4.2.
     3. Assemble the 20-byte SecureDataHeader (kind∥key_id∥session_id∥iv_suffix) as the GCM AAD.
     4. AES-256-GCM seal: nonce = session_id(4)∥iv_suffix(8) (12 bytes); returns (ciphertext, tag).
     5. Serialize via serialize-secured-payload.
   Returns a fresh octet vector. AAD = the exact 20-byte header placed in the blob so that
   decode-serialized-payload can reconstruct it byte-identically from the parsed fields."
  (let* ((iv-suffix  (%km-next-iv-suffix km))
         (session-id (copy-seq +fixed-session-id+))
         (kind       (key-material-transformation-kind km))
         (key-id     (key-material-sender-key-id km))
         ;; serialized-payload AAD = the exact 20-byte SecureDataHeader (§9.5.3.3.4.4); the shared
         ;; %seal-with-km derives the session key + nonce (DRY with the submessage tier).
         (aad        (%assemble-header-aad kind key-id session-id iv-suffix)))
    (multiple-value-bind (ciphertext tag)
        (%seal-with-km km session-id iv-suffix aad plaintext)
      (serialize-secured-payload kind key-id session-id iv-suffix ciphertext tag))))

(defun* decode-serialized-payload (km secured-octets)
    (function (key-material (simple-array (unsigned-byte 8) (*)))
              (or (simple-array (unsigned-byte 8) (*)) null))
  "Decrypt a DDS-Security §9.5.3.3 SecuredPayload produced by encode-serialized-payload.
   Returns the plaintext octet vector on success, NIL on any failure (bounds violation, GCM auth
   failure, or malformed blob) — fail-closed (NFR-SEC-POSTURE; NIST SP 800-38D §8.3).
   Algorithm (§9.5.3.3.4.5):
     1. parse-secured-payload: extract kind, key_id, session_id, iv_suffix, ciphertext, tag.
        Any SECURED-PAYLOAD-MALFORMED signal is caught -> NIL (no crash, no OOB).
     2. Reconstruct the 20-byte SecureDataHeader as AAD from the WIRE-PARSED kind and key_id
        (§9.5.3.3.4.5 — AAD = the received SecureDataHeader); on a legitimate blob the wire fields
        equal the encode-side km fields so the AAD is byte-identical and auth passes, while
        tampering any header byte changes the AAD and forces a GCM authentication failure.
     3. Derive the same session key: derive-session-key(km.master_sender_key, km.master_salt,
        parsed session_id).
     4. AES-256-GCM open with (skey, nonce, aad, ct, tag): dds.dare:aes-256-gcm-open returns
        NIL on auth failure — propagate NIL directly."
  (handler-case
      (multiple-value-bind (kind key-id session-id iv-suffix ciphertext tag)
          (parse-secured-payload secured-octets)
        ;; AAD = the WIRE-PARSED 20-byte SecureDataHeader (§9.5.3.3.4.5); the shared %open-with-km
        ;; re-derives the session key + nonce. Tampering any header byte changes the AAD -> GCM fail.
        (%open-with-km km session-id iv-suffix
                       (%assemble-header-aad kind key-id session-id iv-suffix)
                       ciphertext tag))
    ;; Any condition (malformed blob, constraint, etc.) -> NIL (fail-closed).
    (error () nil)))
