(in-package #:dds.security)

;;; DDS-Security 1.1 §9.5.2 CryptoTransformKeyMaterial_DH — the pre-shared key bundle that
;;; parameterizes encode/decode-serialized-payload. Every field name and width is pinned from
;;; §9.5.2 Table 65; none from memory.

;;; MVP SCAFFOLD: make-test-key-material returns a FIXED pre-shared KeyMaterial for offline
;;; testing. The Slice-2 Auth handshake (DDS-Security §8.7 authentication plugin) replaces
;;; this with keys derived from the DH exchange. Do not ship this test key in production.

(defconstant +km-master-salt-len+ 32
  "CryptoTransformKeyMaterial.master_salt width: 32 octets (DDS-Security 1.1 §9.5.2 Table 65).")
(defconstant +km-sender-key-id-len+ 4
  "CryptoTransformKeyMaterial.sender_key_id width: octet[4] (§9.5.2 Table 65).")
(defconstant +km-master-sender-key-len+ 32
  "CryptoTransformKeyMaterial.master_sender_key width: 32 octets for AES-256 (§9.5.2 Table 65).")
(defconstant +km-receiver-specific-key-id-len+ 4
  "CryptoTransformKeyMaterial.receiver_specific_key_id width: octet[4] (§9.5.2 Table 65).")
(defconstant +km-master-receiver-specific-key-len+ 32
  "CryptoTransformKeyMaterial.master_receiver_specific_key width: 32 octets (§9.5.2 Table 65).
   All-zeros when receiver_specific_key_id is zero (participant-level protection, no per-receiver key).")

(defstruct* key-material
  "DDS-Security 1.1 §9.5.2 CryptoTransformKeyMaterial_DH — the key bundle used by
   encode-serialized-payload / decode-serialized-payload. Fields:
     transformation-kind : octet[4] — the CryptoTransformKind selecting the AEAD algorithm.
     master-salt         : octet[32] — entropy mixed into the session-key KDF (§9.5.3.3.4.2).
     sender-key-id       : octet[4]  — the CryptoTransformKeyId placed in SecureDataHeader.
     master-sender-key   : octet[32] — the HMAC-SHA256 key in the session-key KDF (§9.5.3.3.4.2).
     iv-counter          : (unsigned-byte 64) — MONOTONIC counter incremented on every encode call;
                           combined with session-id forms the 12-byte AES-GCM nonce. Held under
                           iv-counter-lock to make nonce uniqueness STRUCTURAL — two concurrent
                           encodes of the same km never race to the same counter value.
     iv-counter-lock     : opaque lock — guards iv-counter.
   MVP SCAFFOLD — the Slice-2 Auth handshake replaces make-test-key-material."
  (transformation-kind +transformation-kind-aes256-gcm+
   :type (simple-array (unsigned-byte 8) (*)))
  (master-salt (make-array +km-master-salt-len+ :element-type '(unsigned-byte 8) :initial-element 0)
   :type (simple-array (unsigned-byte 8) (*)))
  (sender-key-id (make-array +km-sender-key-id-len+ :element-type '(unsigned-byte 8) :initial-element 0)
   :type (simple-array (unsigned-byte 8) (*)))
  (master-sender-key (make-array +km-master-sender-key-len+ :element-type '(unsigned-byte 8) :initial-element 0)
   :type (simple-array (unsigned-byte 8) (*)))
  ;; §9.5.2 Table 65: receiver-specific key fields. All-zeros = no per-receiver key (participant-level).
  (receiver-specific-key-id
   (make-array +km-receiver-specific-key-id-len+ :element-type '(unsigned-byte 8) :initial-element 0)
   :type (simple-array (unsigned-byte 8) (*)))
  (master-receiver-specific-key
   (make-array +km-master-receiver-specific-key-len+ :element-type '(unsigned-byte 8) :initial-element 0)
   :type (simple-array (unsigned-byte 8) (*)))
  ;; Nonce-uniqueness state: iv-counter is the only mutable field; must be incremented atomically.
  (iv-counter 0 :type (unsigned-byte 64))
  (iv-counter-lock (dds.pal:make-lock "km-iv") :type t))

;;; Fixed test key material — a known, PUBLISHED, non-secret value for offline round-trip tests.
;;; The 32-byte master_sender_key and master_salt are the two consecutive NIST SP 800-56C rev2
;;; §4.2 example KDK values (each the ASCII encoding of a 32-character string of successive hex
;;; digits), providing a recognisable independent reference. The sender_key_id is 0xDEADBEEF.
;;; MUST NOT be used outside test harnesses — no session derives security from this key.

(defconstant +test-master-sender-key+
    (if (boundp '+test-master-sender-key+)
        (symbol-value '+test-master-sender-key+)
        (make-array 32 :element-type '(unsigned-byte 8)
                       :initial-contents
                       '(#x00 #x01 #x02 #x03 #x04 #x05 #x06 #x07
                         #x08 #x09 #x0a #x0b #x0c #x0d #x0e #x0f
                         #x10 #x11 #x12 #x13 #x14 #x15 #x16 #x17
                         #x18 #x19 #x1a #x1b #x1c #x1d #x1e #x1f)))
  "Fixed AES-256 master_sender_key for make-test-key-material (test scaffold only; §9.5.2 Table 65).
   Value: consecutive bytes 0x00..0x1F (32 octets). Not secret; for offline tests only.")

(defconstant +test-master-salt+
    (if (boundp '+test-master-salt+)
        (symbol-value '+test-master-salt+)
        (make-array 32 :element-type '(unsigned-byte 8)
                       :initial-contents
                       '(#x40 #x41 #x42 #x43 #x44 #x45 #x46 #x47
                         #x48 #x49 #x4a #x4b #x4c #x4d #x4e #x4f
                         #x50 #x51 #x52 #x53 #x54 #x55 #x56 #x57
                         #x58 #x59 #x5a #x5b #x5c #x5d #x5e #x5f)))
  "Fixed master_salt for make-test-key-material (test scaffold only; §9.5.2 Table 65).
   Value: consecutive bytes 0x40..0x5F (32 octets). Not secret; for offline tests only.")

(defconstant +test-sender-key-id+
    (if (boundp '+test-sender-key-id+)
        (symbol-value '+test-sender-key-id+)
        (make-array 4 :element-type '(unsigned-byte 8)
                      :initial-contents '(#xde #xad #xbe #xef)))
  "Fixed sender_key_id for make-test-key-material (test scaffold only). Value: 0xDEADBEEF.")

(defstruct* (crypto-keys (:constructor make-crypto-keys))
  "Per-writer key resolver for the DDS-Security §9.5.3.3 secured data path (T6).
   ENCODE-KEY-FN resolves the local writer's KeyMaterial by its 16-octet GUID for outgoing samples
   (§9.5.3.3.4.4). DECODE-KEY-FN resolves the remote writer's KeyMaterial by its 16-octet wire GUID
   for incoming samples (§9.5.3.3.4.5). Both return NIL when no key exists — caller MUST fail-closed."
  (encode-key-fn (error "crypto-keys: :encode-key-fn required") :type function)
  (decode-key-fn (error "crypto-keys: :decode-key-fn required") :type function))

(defun* make-test-key-material ()
    (function () key-material)
  "Return a fresh key-material with FIXED pre-shared test values (§9.5.2; Table 65 field names).
   Intended for offline unit / round-trip tests only. The Slice-2 Auth handshake replaces this
   with per-session KEM-derived keys. Every field is a COPY so callers cannot alias the constants.
   NONCE-REUSE WARNING: because this returns a fresh instance with iv-counter=0 over a FIXED
   master key, at most ONE instance may be used to ENCODE at a time — two encoders over this
   fixed key start at the same counter and produce colliding nonces (catastrophic for AES-GCM);
   it is an offline test/round-trip scaffold replaced by the Slice-2 per-writer derived key."
  (make-key-material
   :transformation-kind (copy-seq +transformation-kind-aes256-gcm+)
   :master-salt         (copy-seq +test-master-salt+)
   :sender-key-id       (copy-seq +test-sender-key-id+)
   :master-sender-key   (copy-seq +test-master-sender-key+)
   :iv-counter          0
   :iv-counter-lock     (dds.pal:make-lock "km-iv")))

;;; --- generic §8.5 CryptoKeyFactory KeyMaterial generator (T6) ---
;;; The single random-fill primitive behind both the participant/entity KeyMaterial the
;;; crypto-manager mints and the per-writer KeyMaterial (generate-writer-key-material delegates here).

(defparameter *sender-key-id-counter* 0
  "Monotonic source for the allocated 4-octet CryptoTransformKeyId (sender_key_id, §9.5.2 Table 65)
   handed out by GENERATE-KEY-MATERIAL. Guarded by *SENDER-KEY-ID-LOCK*; the first allocation is 1
   (never zero on the wire). Process-global so every KeyMaterial a participant mints carries a
   distinct transformation_key_id, keeping a receiver's O(1) transformation_key_id -> KeyMaterial
   decode index unambiguous. NOT a wire constant — an allocation counter (§9.5.2 leaves
   CryptoTransformKeyId assignment to the implementation).")

(defparameter *sender-key-id-lock* (dds.pal:make-lock "sender-key-id")
  "Guards *SENDER-KEY-ID-COUNTER* across concurrent GENERATE-KEY-MATERIAL calls (control-plane).")

(defun* %alloc-sender-key-id ()
    (function () (simple-array (unsigned-byte 8) (*)))
  "Allocate the next process-unique, NON-ZERO 4-octet sender_key_id (big-endian; §9.5.2 Table 65),
   wrapping modulo 2^32 and skipping zero. Control-plane (keying), never the hot path."
  (let ((n (dds.pal:with-lock (*sender-key-id-lock*)
             (let ((c (logand (1+ *sender-key-id-counter*) #xffffffff)))
               (when (zerop c) (setf c 1))
               (setf *sender-key-id-counter* c)))))
    (let ((kid (make-array 4 :element-type '(unsigned-byte 8))))
      (setf (aref kid 0) (ldb (byte 8 24) n)
            (aref kid 1) (ldb (byte 8 16) n)
            (aref kid 2) (ldb (byte 8 8) n)
            (aref kid 3) (ldb (byte 8 0) n))
      kid)))

(defun* %nonzero-random-key-id ()
    (function () (simple-array (unsigned-byte 8) (*)))
  "A cryptographically random NON-ZERO 4-octet receiver_specific_key_id (§9.5.2 Table 65), resampled
   until non-zero: zero is the §9.5.3.3.4.3 'origin authentication disabled' sentinel, so a random
   draw must never collide with it (the T6 fix for the T3 carry). Control-plane."
  (loop for kid = (dds.dare:random-bytes 4)
        when (notevery #'zerop kid) return kid))

(defun* generate-key-material (&key (origin-auth nil) (kind :encrypt))
    (function (&key (:origin-auth t) (:kind (member :sign :encrypt))) key-material)
  "Generate a fresh §9.5.2 KeyMaterial_AES_GCM_GMAC — the generic §8.5 CryptoKeyFactory primitive
   reused for participant- and entity-level keys (and, via GENERATE-WRITER-KEY-MATERIAL, per-writer
   keys). master_salt (32B) + master_sender_key (32B) are cryptographically random
   (dds.dare:random-bytes); sender_key_id is a process-unique NON-ZERO 4-octet allocation
   (%ALLOC-SENDER-KEY-ID) so a receiver's O(1) transformation_key_id -> KeyMaterial decode index
   stays unambiguous. KIND selects the §9.5.2 Table 65 transformation_kind the KeyMaterial ADVERTISES:
   :encrypt (default) -> AES256-GCM {0,0,0,4}; :sign -> AES256-GMAC {0,0,0,3}. This MUST equal the wire
   CryptoHeader transformation_kind a peer sees for this endpoint's submessages, because a conformant
   receiver (Fast DDS AESGCMGMAC_Transform::find_key) matches a stored KeyMaterial to an inbound submessage
   on BOTH transformation_kind AND sender_key_id — a SIGN endpoint advertising a GCM KeyMaterial is rejected
   'Key material not found' (the AES-256 master key is identical for GCM and GMAC; only the advertised kind +
   the SEC_BODY-vs-verbatim framing differ). With ORIGIN-AUTH NIL (default) the receiver-specific fields stay
   all-zero (no per-receiver origin authentication, §9.5.2). With ORIGIN-AUTH true both are populated: a
   NON-ZERO random receiver_specific_key_id (zero is the §9.5.3.3.4.3 origin-auth-disabled sentinel — never
   emitted) + a random 32B master_receiver_specific_key, for the *_WITH_ORIGIN_AUTHENTICATION protection kinds
   (§9.5.3.3.4.3; consumed by derive-receiver-specific-session-key / compute-receiver-specific-mac). Keys are
   plain heap vectors per ADR 0034 (KeyMaterial foreign-backing + zeroize-on-teardown is a deferred hardening
   follow-on); the caller owns the key-material lifecycle. Control-plane, not the hot path."
  ; HARDENING-GAP: KeyMaterial master key/salt are GC-heap (ADR 0034 deferral); not the hot path.
  (let ((tk (ecase kind
              (:encrypt +transformation-kind-aes256-gcm+)
              (:sign    +transformation-kind-aes256-gmac+))))
    (if origin-auth
        (make-key-material :transformation-kind          (copy-seq tk)
                           :master-salt                  (dds.dare:random-bytes 32)
                           :sender-key-id                (%alloc-sender-key-id)
                           :master-sender-key            (dds.dare:random-bytes 32)
                           :receiver-specific-key-id     (%nonzero-random-key-id)
                           :master-receiver-specific-key (dds.dare:random-bytes 32))
        (make-key-material :transformation-kind (copy-seq tk)
                           :master-salt         (dds.dare:random-bytes 32)
                           :sender-key-id       (%alloc-sender-key-id)
                           :master-sender-key   (dds.dare:random-bytes 32)))))
