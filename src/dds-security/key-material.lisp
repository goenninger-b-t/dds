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
