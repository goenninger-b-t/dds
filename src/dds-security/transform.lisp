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
     3. AES-256-GCM seal with EMPTY AAD: nonce = session_id(4)∥iv_suffix(8) (12 bytes); returns
        (ciphertext, tag).
     4. Serialize via serialize-secured-payload.
   Returns a fresh octet vector. AAD = EMPTY (+empty-octets+) — Fast-DDS-faithful (corroborated CLEAN-ROOM
   against eProsima Fast DDS AESGCMGMAC_Transform.cpp encode_serialized_payload -> serialize_SecureDataBody,
   whose ENCRYPT branch sets NO AAD; the SAME function as the submessage tier, so payload + submessage share
   the empty-AAD posture, the byte-exact submessage corpus already proves it). The header fields are integrity-
   bound WITHOUT AAD: session_id/iv_suffix derive the nonce (tamper -> GCM fail), and decode rejects a wire
   kind/key_id that does not match the KM (the Fast DDS find_key check; see decode-serialized-payload). This is
   the T10-INTEROP-RECONCILE of the Slice-1 carry (was the 20-byte SecureDataHeader as AAD); see docs/provenance.md."
  (let* ((iv-suffix  (%km-next-iv-suffix km))
         (session-id (copy-seq +fixed-session-id+))
         (kind       (key-material-transformation-kind km))
         (key-id     (key-material-sender-key-id km)))
    (multiple-value-bind (ciphertext tag)
        (%seal-with-km km session-id iv-suffix +empty-octets+ plaintext)   ; empty AAD (Fast-DDS-faithful, DRY)
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
     2. Verify the WIRE kind/key_id MATCH the KM (the Fast DDS AESGCMGMAC_Transform::find_key check:
        transformation_kind AND transformation_key_id both equal the KeyMaterial's) -> NIL on mismatch.
        This integrity-binds the SecureDataHeader kind/key_id WITHOUT folding them into the AAD (so the
        wire stays Fast-DDS-faithful with EMPTY AAD); a kind/key_id tamper is rejected here, while a
        session_id/iv_suffix tamper is caught by the GCM auth (they derive the nonce).
     3. Derive the same session key: derive-session-key(km.master_sender_key, km.master_salt,
        parsed session_id).
     4. AES-256-GCM open with (skey, nonce, EMPTY aad, ct, tag): dds.dare:aes-256-gcm-open returns
        NIL on auth failure — propagate NIL directly. AAD = EMPTY (Fast-DDS-faithful, T10-INTEROP-RECONCILE)."
  (handler-case
      (multiple-value-bind (kind key-id session-id iv-suffix ciphertext tag)
          (parse-secured-payload secured-octets)
        ;; Fast DDS find_key: the wire kind/key_id MUST match the KM, else fail-closed (the header integrity
        ;; gate now that the AAD is EMPTY; a kind or key_id bit-flip is rejected here, not via the GCM tag).
        (when (and (equalp kind   (key-material-transformation-kind km))
                   (equalp key-id (key-material-sender-key-id km)))
          ;; AAD = EMPTY (+empty-octets+, Fast-DDS-faithful, DRY); session_id/iv_suffix derive the nonce, so
          ;; tampering them forces a GCM auth failure. The shared %open-with-km re-derives the session key + nonce.
          (%open-with-km km session-id iv-suffix +empty-octets+ ciphertext tag)))
    ;; Any condition (malformed blob, constraint, etc.) -> NIL (fail-closed).
    (error () nil)))
