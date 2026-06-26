(in-package #:dds.security)

;;; DDS-Security 1.1 §9.5.3 KxKey and KxSalt derivation from the authenticated SharedSecret.
;;; Construction: create_kx_key(first, cookie, second, shared_secret) =
;;;   HMAC-SHA256(key = SHA-256(first(32B) || cookie(16B) || second(32B)),
;;;               data = shared_secret(32B))
;;; KxKey:  first=challenge_2, cookie="key exchange key", second=challenge_1.
;;; KxSalt: first=challenge_1, cookie="keyexchange salt", second=challenge_2.
;;; Spec: OMG DDS-Security 1.1 §9.5.3; corroborated by Fast DDS AESGCMGMAC_KeyFactory.cpp
;;; create_kx_key(). All labels are 16 ASCII bytes; SHA-256 input is exactly 80 octets.
;;; Spike: docs/superpowers/spikes/2026-06-26-dds-security-keyexchange.md §2.2–§2.5.
;;; No hand-rolled crypto; all primitives from dds.dare/OpenSSL.

;;; --- KxKey KDF label constants (§9.5.3; spike §2.5, §7) ---

(defconstant +kxkey-label+
    (if (boundp '+kxkey-label+) (symbol-value '+kxkey-label+) "key exchange key")
  "DDS-Security 1.1 §9.5.3 KxKey label: ASCII 'key exchange key', 16 bytes.
   Hex: 6b65792065786368616e6765206b6579 (spike §7). Used as the SHA-256 cookie for KxKey derivation.")

(defconstant +kxsalt-label+
    (if (boundp '+kxsalt-label+) (symbol-value '+kxsalt-label+) "keyexchange salt")
  "DDS-Security 1.1 §9.5.3 KxSalt label: ASCII 'keyexchange salt', 16 bytes.
   Hex: 6b657965786368616e67652073616c74 (spike §7). Used as the SHA-256 cookie for KxSalt derivation.")

(defconstant +kxkey-label-len+ 16
  "Length of the KxKey/KxSalt ASCII label in octets (§9.5.3; spike §2.5). Both labels are exactly 16 bytes.")

(defconstant +kx-sha-input-len+ 80
  "SHA-256 input length for the KxKey/KxSalt KDF: challenge(32) + label(16) + challenge(32) = 80 octets (§9.5.3; spike §2.4).")

(defconstant +kx-output-len+ 32
  "KxKey and KxSalt output length in octets: HMAC-SHA256 = 32 bytes = AES-256 key (§9.5.3; spike §2.2).")

;;; --- kx-key-handle: foreign-backed 32-byte key buffer ---

(defstruct* (kx-key-handle (:constructor %make-kx-key-handle))
  "Handle for a derived DDS-Security §9.5.3 KxKey or KxSalt (32-byte AES-256 key).
   Bytes are held in a dds.pal foreign-backed buffer (non-GC'd, stable address).
   MUST be freed via FREE-KX-KEY when no longer needed."
  (bytes (error "kx-key-handle: :bytes is required (must be a dds.pal foreign buffer)")
         :type (simple-array (unsigned-byte 8) (32))))

;;; --- internal KDF step ---

(defun* %kx-create-key (first-challenge cookie second-challenge shared-secret)
    (function ((simple-array (unsigned-byte 8) (*))
               string
               (simple-array (unsigned-byte 8) (*))
               (simple-array (unsigned-byte 8) (*)))
              (simple-array (unsigned-byte 8) (32)))
  "Core KxKey KDF (§9.5.3; spike §2.4): HMAC-SHA256(key=SHA-256(first||cookie||second), data=shared_secret).
   FIRST-CHALLENGE and SECOND-CHALLENGE are 32-byte nonces; COOKIE is the 16-byte ASCII label;
   SHARED-SECRET is the 32-byte SHA-256(ECDH/FFDH) value. Returns a fresh 32-byte heap vector.
   SHA-256 input is 80 octets = 32+16+32. No hand-rolled crypto; all via dds.dare primitives."
  (let* ((label-bytes (%ascii-octets cookie))
         (tmp (make-array +kx-sha-input-len+ :element-type '(unsigned-byte 8)))
         (pos 0))
    (dotimes (i 32)
      (setf (aref tmp pos) (aref first-challenge i))
      (incf pos))
    (dotimes (i +kxkey-label-len+)
      (setf (aref tmp pos) (aref label-bytes i))
      (incf pos))
    (dotimes (i 32)
      (setf (aref tmp pos) (aref second-challenge i))
      (incf pos))
    (let ((sha (dds.dare:sha-256 tmp)))
      (dds.dare:hmac-sha256 sha shared-secret))))

;;; --- public API ---

(defun* derive-kx-key (shared-secret challenge1 challenge2)
    (function ((simple-array (unsigned-byte 8) (32))
               (simple-array (unsigned-byte 8) (*))
               (simple-array (unsigned-byte 8) (*)))
              kx-key-handle)
  "Derive the DDS-Security 1.1 §9.5.3 KxKey from SHARED-SECRET, CHALLENGE1 (initiator nonce),
   and CHALLENGE2 (responder nonce). Construction (spike §2.2):
     KxKey = HMAC-SHA256(key=SHA-256(challenge_2 || 'key exchange key' || challenge_1),
                         data=shared_secret).
   Note challenges are swapped relative to KxSalt (challenge_2 is FIRST here). Returns a fresh
   KX-KEY-HANDLE whose bytes are held in a dds.pal foreign-backed buffer; caller must free it
   with FREE-KX-KEY. All inputs must be 32 bytes (both challenges and shared_secret). Signals
   SECURED-PAYLOAD-MALFORMED for wrong-length inputs (fail-closed, NFR-SEC-POSTURE)."
  (%require-len shared-secret 32 "shared_secret")
  (%require-len challenge1     32 "challenge1")
  (%require-len challenge2     32 "challenge2")
  (let* ((raw (%kx-create-key challenge2 +kxkey-label+ challenge1 shared-secret))
         (buf (dds.pal:alloc-static +kx-output-len+)))
    (dotimes (i +kx-output-len+)
      (setf (aref buf i) (aref raw i)))
    (fill raw 0)
    (%make-kx-key-handle :bytes buf)))

(defun* derive-kx-salt (shared-secret challenge1 challenge2)
    (function ((simple-array (unsigned-byte 8) (32))
               (simple-array (unsigned-byte 8) (*))
               (simple-array (unsigned-byte 8) (*)))
              kx-key-handle)
  "Derive the DDS-Security 1.1 §9.5.3 KxSalt from SHARED-SECRET, CHALLENGE1, and CHALLENGE2.
   Construction (spike §2.3):
     KxSalt = HMAC-SHA256(key=SHA-256(challenge_1 || 'keyexchange salt' || challenge_2),
                          data=shared_secret).
   Note challenges are swapped relative to KxKey (challenge_1 is FIRST here). Returns a fresh
   KX-KEY-HANDLE; caller must free it with FREE-KX-KEY. Used as master_salt in KxKeyMaterial (§9.5.2)."
  (%require-len shared-secret 32 "shared_secret")
  (%require-len challenge1     32 "challenge1")
  (%require-len challenge2     32 "challenge2")
  (let* ((raw (%kx-create-key challenge1 +kxsalt-label+ challenge2 shared-secret))
         (buf (dds.pal:alloc-static +kx-output-len+)))
    (dotimes (i +kx-output-len+)
      (setf (aref buf i) (aref raw i)))
    (fill raw 0)
    (%make-kx-key-handle :bytes buf)))

(defun* kx-key-bytes (handle)
    (function (kx-key-handle) (simple-array (unsigned-byte 8) (32)))
  "Return the 32-byte KxKey or KxSalt bytes from HANDLE (DDS-Security §9.5.3).
   The returned vector is the live foreign-backed buffer: do not retain past FREE-KX-KEY."
  (kx-key-handle-bytes handle))

(defun* free-kx-key (handle)
    (function ((or kx-key-handle null)) null)
  "Zeroize and free the dds.pal foreign-backed key buffer in HANDLE. Idempotent: NIL is a no-op.
   Every KX-KEY-HANDLE returned by DERIVE-KX-KEY or DERIVE-KX-SALT must be freed here."
  (when handle
    (let ((buf (kx-key-handle-bytes handle)))
      (fill buf 0)
      (dds.pal:free-static buf)))
  nil)

;;; === T3: §9.5.2 KeyMaterial generation + KxKey-encrypted CryptoToken codec ===
;;;
;;; KeyMaterial CDR layout (88 bytes, AES256-GCM, no receiver-specific key):
;;;   [0..3]   transformation_kind = {0x00,0x00,0x00,0x04}     (§9.5.2 Table 65; spike §3.2)
;;;   [4..6]   padding              = {0x00,0x00,0x00}
;;;   [7]      master_salt length   = 0x20 (= 32)
;;;   [8..39]  master_salt[0..31]
;;;   [40..43] sender_key_id[0..3]
;;;   [44..46] padding              = {0x00,0x00,0x00}
;;;   [47]     master_sender_key length = 0x20 (= 32)
;;;   [48..79] master_sender_key[0..31]
;;;   [80..83] receiver_specific_key_id = {0x00,0x00,0x00,0x00}
;;;   [84..87] absent-key marker    = {0x00,0x00,0x00,0x00}
;;; Source: Fast DDS AESGCMGMAC_KeyExchange.cpp KeyMaterialCDRSerialize(); spike §3.2.
;;; NEEDS-VERIFICATION §6.2 (spike): this is Fast DDS proprietary framing, not standard CDR
;;; uint32 sequence-length; cross-vendor Connext alignment deferred to Slice 5 / ADR 0034.
;;;
;;; KxKey AEAD wrap construction (our-to-our, pending Slice-5 cross-vendor verification):
;;;   Plaintext: 88-byte KeyMaterial CDR.
;;;   Key: kx-key-bytes (32 bytes, AES-256-GCM key).
;;;   Nonce: FRESH random 12 bytes (dds.dare:random-bytes 12), PREPENDED to the blob.
;;;     Uniqueness: nonce space is 2^96; key-exchange generates O(1) messages per session;
;;;     nonce reuse probability < 2^-64 per pair across 10^9 messages (negligible).
;;;   AAD: empty (the class_id and property name in the DataHolder envelope already identify
;;;     the context; empty AAD is the conservative choice pending Slice-5 spec review).
;;;   Wire blob: nonce(12) || ciphertext(88) || tag(16) = 116 bytes.
;;; Spec basis: OMG DDS-Security 1.1 §9.5.3 intent (KxKey protects KeyMaterial in transit).
;;; Fast DDS deviation: Fast DDS sends plaintext (commented-out AEAD calls). We implement
;;; the spec-conformant encrypted path. ADR 0034 to document the plaintext-compat carry.
;;; Spike §6.1 (NEEDS-VERIFICATION): decision to implement spec-conformant KxKey-AEAD-wrap.
;;;
;;; CryptoToken DataHolder identifiers (§9.5; spike §4; Fast DDS SecurityManager.cpp):
;;;   class_id                    = "DDS:Crypto:AES_GCM_GMAC"
;;;   binary property name        = "dds.cryp.keymat"
;;;   GenericMessage class_ids    (spike §4; §7.4.4):
;;;     participant crypto tokens = "dds.sec.participant_crypto_tokens"
;;;     datawriter crypto tokens  = "dds.sec.datawriter_crypto_tokens"
;;;     datareader crypto tokens  = "dds.sec.datareader_crypto_tokens"

(defconstant +crypto-token-class-id+
    (if (boundp '+crypto-token-class-id+) (symbol-value '+crypto-token-class-id+)
        "DDS:Crypto:AES_GCM_GMAC")
  "DDS-Security 1.1 §9.5 CryptoToken DataHolder class_id. Spike §7 / Fast DDS SecurityManager.cpp.")

(defconstant +crypto-token-keymat-prop+
    (if (boundp '+crypto-token-keymat-prop+) (symbol-value '+crypto-token-keymat-prop+)
        "dds.cryp.keymat")
  "DDS-Security 1.1 §9.5 CryptoToken binary property name for the KeyMaterial CDR bytes. Spike §7.")

(defconstant +gm-participant-crypto-tokens+
    (if (boundp '+gm-participant-crypto-tokens+) (symbol-value '+gm-participant-crypto-tokens+)
        "dds.sec.participant_crypto_tokens")
  "DDS-Security 1.1 §7.4.4 GenericMessage class_id for participant crypto token exchange. Spike §7.")

(defconstant +gm-datawriter-crypto-tokens+
    (if (boundp '+gm-datawriter-crypto-tokens+) (symbol-value '+gm-datawriter-crypto-tokens+)
        "dds.sec.datawriter_crypto_tokens")
  "DDS-Security 1.1 §7.4.4 GenericMessage class_id for DataWriter crypto token exchange. Spike §7.")

(defconstant +gm-datareader-crypto-tokens+
    (if (boundp '+gm-datareader-crypto-tokens+) (symbol-value '+gm-datareader-crypto-tokens+)
        "dds.sec.datareader_crypto_tokens")
  "DDS-Security 1.1 §7.4.4 GenericMessage class_id for DataReader crypto token exchange. Spike §7.")

(defconstant +km-cdr-len+ 88
  "Byte length of the serialized KeyMaterial_AES_GCM_GMAC CDR for AES256-GCM, no receiver-specific key.
   Layout: kind(4)+pad(3)+1+salt(32)+kid(4)+pad(3)+1+sender-key(32)+rsm-id(4)+absent-marker(4) = 88.
   Source: Fast DDS KeyMaterialCDRSerialize(); spike §3.2.")

(defconstant +kx-nonce-len+ 12
  "AES-GCM nonce length in bytes. NIST SP 800-38D §8.2.1 96-bit IV for the random construction.")

(defconstant +aes-gcm-tag-len-kx+ 16
  "AES-GCM authentication tag length in bytes (NIST SP 800-38D, 128-bit tag).")

(defconstant +km-cdr-wrapped-len+ 116
  "Byte length of the KxKey-wrapped KeyMaterial blob: nonce(12) || ciphertext(88) || tag(16) = 116.")

;;; --- KeyMaterial CDR serializer ---

(defun* %serialize-km-cdr (km)
    (function (key-material) (simple-array (unsigned-byte 8) (*)))
  "Serialize KM to the 88-byte Fast DDS proprietary KeyMaterial CDR format (spike §3.2).
   Layout: kind(4){0x00,0x00,0x00,0x04} + pad(3) + len-byte(0x20) + salt(32) +
           key-id(4) + pad(3) + len-byte(0x20) + sender-key(32) + rsm-id(4){zeros} + absent(4){zeros}.
   NEEDS-VERIFICATION §6.2: proprietary framing; not standard CDR uint32 sequence-length encoding."
  (let ((out (make-array +km-cdr-len+ :element-type '(unsigned-byte 8) :initial-element 0))
        (kind (key-material-transformation-kind km))
        (salt (key-material-master-salt km))
        (kid  (key-material-sender-key-id km))
        (mkey (key-material-master-sender-key km)))
    ;; [0..3] transformation_kind
    (setf (aref out 0) (aref kind 0)
          (aref out 1) (aref kind 1)
          (aref out 2) (aref kind 2)
          (aref out 3) (aref kind 3))
    ;; [4..6] padding = {0x00,0x00,0x00}; [7] = 0x20 (32 = length of master_salt)
    (setf (aref out 7) #x20)
    ;; [8..39] master_salt
    (dotimes (i 32) (setf (aref out (+ 8 i)) (aref salt i)))
    ;; [40..43] sender_key_id
    (setf (aref out 40) (aref kid 0)
          (aref out 41) (aref kid 1)
          (aref out 42) (aref kid 2)
          (aref out 43) (aref kid 3))
    ;; [44..46] padding = {0x00,0x00,0x00}; [47] = 0x20 (32 = length of master_sender_key)
    (setf (aref out 47) #x20)
    ;; [48..79] master_sender_key
    (dotimes (i 32) (setf (aref out (+ 48 i)) (aref mkey i)))
    ;; [80..83] receiver_specific_key_id = {0x00,0x00,0x00,0x00} (all-zeros = absent)
    ;; [84..87] absent-key marker        = {0x00,0x00,0x00,0x00}
    ;; both are already zero from :initial-element 0
    out))

;;; --- KeyMaterial CDR deserializer ---

(defun* %parse-km-cdr (cdr)
    (function ((simple-array (unsigned-byte 8) (*))) (or key-material null))
  "Parse an 88-byte KeyMaterial CDR blob into a key-material struct. Returns NIL if malformed.
   Checks: exact length 88; transformation_kind[0..2] must be {0x00,0x00,0x00}; kind[3] in {0x01,0x02,0x04};
   length bytes at [7] and [47] must be 0x20 (32); bytes [80..87] (receiver_specific_key_id + absent-marker)
   must all be zero (participant-level AES_GCM only; receiver-specific keys are rejected). Fail-closed (NFR-SEC-POSTURE)."
  (block %parse-km
    (let ((n (length cdr)))
      (unless (= n +km-cdr-len+) (return-from %parse-km nil))
      ;; kind[0..2] must be zeros; kind[3] is the actual algorithm byte (0x04 = AES256-GCM)
      (unless (and (zerop (aref cdr 0)) (zerop (aref cdr 1)) (zerop (aref cdr 2)))
        (return-from %parse-km nil))
      (let ((algo-byte (aref cdr 3)))
        (unless (member algo-byte '(#x01 #x02 #x04))
          (return-from %parse-km nil)))
      ;; length bytes must be 0x20 (= 32)
      (unless (and (= (aref cdr 7) #x20) (= (aref cdr 47) #x20))
        (return-from %parse-km nil))
      ;; receiver_specific_key_id [80..83] and absent-key marker [84..87] must all be zero
      (unless (and (zerop (aref cdr 80)) (zerop (aref cdr 81))
                   (zerop (aref cdr 82)) (zerop (aref cdr 83))
                   (zerop (aref cdr 84)) (zerop (aref cdr 85))
                   (zerop (aref cdr 86)) (zerop (aref cdr 87)))
        (return-from %parse-km nil))
      (let ((kind (make-array 4 :element-type '(unsigned-byte 8)))
            (salt (make-array 32 :element-type '(unsigned-byte 8)))
            (kid  (make-array 4 :element-type '(unsigned-byte 8)))
            (mkey (make-array 32 :element-type '(unsigned-byte 8))))
        (dotimes (i 4)  (setf (aref kind i) (aref cdr i)))
        (dotimes (i 32) (setf (aref salt i) (aref cdr (+ 8 i))))
        (dotimes (i 4)  (setf (aref kid i)  (aref cdr (+ 40 i))))
        (dotimes (i 32) (setf (aref mkey i) (aref cdr (+ 48 i))))
        (make-key-material :transformation-kind kind
                           :master-salt salt
                           :sender-key-id kid
                           :master-sender-key mkey)))))

;;; --- Key-id derivation from writer GUID ---

(defun* %guid-key-id (writer-guid)
    (function ((simple-array (unsigned-byte 8) (16))) (simple-array (unsigned-byte 8) (4)))
  "Derive a 4-byte CryptoTransformKeyId from WRITER-GUID (first 4 bytes, big-endian).
   This is a deterministic, non-secret mapping used only for sender_key_id disambiguation.
   Spec: §9.5.2 Table 65 does not mandate derivation; this is our-implementation choice."
  (let ((kid (make-array 4 :element-type '(unsigned-byte 8))))
    (dotimes (i 4) (setf (aref kid i) (aref writer-guid i)))
    kid))

;;; --- Public API ---

(defun* generate-writer-key-material (writer-guid)
    (function ((simple-array (unsigned-byte 8) (16))) key-material)
  "Generate a fresh §9.5.2 KeyMaterial_AES_GCM_GMAC for WRITER-GUID.
   master_salt (32B) and master_sender_key (32B) are cryptographically random (dds.dare:random-bytes).
   sender_key_id is derived from the first 4 bytes of WRITER-GUID.
   transformation_kind = {0x00,0x00,0x00,0x04} (AES256-GCM, §9.5.2 Table 65).
   receiver_specific_key_id = all-zeros (participant-level protection; §9.5.2).
   Secrets are plain heap vectors (not foreign-backed) — the caller holds the key-material struct
   and is responsible for zeroizing on teardown (T5 manager allocates and frees these)."
  ; HARDENING-GAP: KeyMaterial master key/salt are GC-heap (Slice-1 key-material struct); foreign-backing is a follow-on (see ADR 0034). Control-plane, not hot-path.
  (let* ((kind (copy-seq +transformation-kind-aes256-gcm+))
         (salt (dds.dare:random-bytes 32))
         (kid  (%guid-key-id writer-guid))
         (mkey (dds.dare:random-bytes 32)))
    (make-key-material :transformation-kind kind
                       :master-salt         salt
                       :sender-key-id       kid
                       :master-sender-key   mkey)))

(defun* serialize-crypto-token (km kx-key)
    (function (key-material (simple-array (unsigned-byte 8) (32)))
              (simple-array (unsigned-byte 8) (*)))
  "Serialize KM as a KxKey-encrypted CryptoToken CDR-LE DataHolder blob (§9.5.2 / §9.3.4).
   Encryption: AES-256-GCM(key=KX-KEY, nonce=random-12B, aad=empty, pt=88-byte-KM-CDR).
   Output DataHolder: class_id='DDS:Crypto:AES_GCM_GMAC'; binary property 'dds.cryp.keymat'
   contains nonce(12)||ciphertext(88)||tag(16) = 116 bytes.
   KxKey wrap construction: our-to-our, pending Slice-5 cross-vendor verification (ADR 0034).
   Spike §6.1 / §3.4."
  (let* ((km-cdr  (%serialize-km-cdr km))
         (nonce   (dds.dare:random-bytes +kx-nonce-len+))
         (aad     (make-array 0 :element-type '(unsigned-byte 8))))
    (multiple-value-bind (ciphertext tag)
        (dds.dare:aes-256-gcm-seal kx-key nonce aad km-cdr)
      ;; wipe plaintext KM CDR immediately
      (fill km-cdr 0)
      ;; build wire blob: nonce(12) || ciphertext(88) || tag(16)
      (let ((blob (make-array +km-cdr-wrapped-len+ :element-type '(unsigned-byte 8))))
        (replace blob nonce      :start1 0  :end1 12)
        (replace blob ciphertext :start1 12 :end1 100)
        (replace blob tag        :start1 100 :end1 116)
        ;; encode as DataHolder using the existing 2b-i codec (spike §3.3 / §6.6)
        (handshake-token->dataholder
         (%make-handshake-token
          :class-id      +crypto-token-class-id+
          :binary-props  (list (cons +crypto-token-keymat-prop+ blob))))))))

(defun* parse-crypto-token (octets kx-key)
    (function ((simple-array (unsigned-byte 8) (*))
               (simple-array (unsigned-byte 8) (32)))
              (or key-material null))
  "Parse and authenticate a KxKey-encrypted CryptoToken DataHolder blob.
   Returns a key-material on success, NIL on any malformed/truncated/forged input (fail-closed).
   Bounds-checks every length before reading/allocating. Caps: exactly 1 binary property;
   the 'dds.cryp.keymat' value must be exactly 116 bytes (nonce+ct+tag). A wrong KX-KEY
   or any byte flip in the ciphertext or tag causes AES-GCM authentication failure -> NIL.
   NFR-SEC-POSTURE: never crashes on adversarial input; handler-bind wraps dds.dare:aes-256-gcm-open
   so EVP allocation errors signal->NIL (not handler-case in nested mvb — Clasp miscompiles that).
   Uses block/return-from throughout. Spike §6.1 / §3.3."
  (block %parse-crypto-token
    (let ((tok (dataholder->handshake-token octets)))
      (unless tok (return-from %parse-crypto-token nil))
      (unless (string= (handshake-token-class-id tok) +crypto-token-class-id+)
        (return-from %parse-crypto-token nil))
      (let ((props (handshake-token-binary-props tok)))
        ;; exactly 1 binary property (spike §6.3)
        (unless (= (length props) 1) (return-from %parse-crypto-token nil))
        (let ((pair (car props)))
          (unless (string= (car pair) +crypto-token-keymat-prop+)
            (return-from %parse-crypto-token nil))
          (let ((blob (cdr pair)))
            ;; blob must be exactly nonce(12)+ct(88)+tag(16) = 116 bytes
            (unless (= (length blob) +km-cdr-wrapped-len+)
              (return-from %parse-crypto-token nil))
            (let* ((nonce (make-array +kx-nonce-len+ :element-type '(unsigned-byte 8)))
                   (ct    (make-array +km-cdr-len+   :element-type '(unsigned-byte 8)))
                   (tag   (make-array +aes-gcm-tag-len-kx+ :element-type '(unsigned-byte 8)))
                   (aad   (make-array 0 :element-type '(unsigned-byte 8))))
              (replace nonce blob :start2 0   :end2 12)
              (replace ct    blob :start2 12  :end2 100)
              (replace tag   blob :start2 100 :end2 116)
              (handler-bind
                  ((error (lambda (c) (declare (ignore c))
                            (return-from %parse-crypto-token nil))))
                (let ((pt (dds.dare:aes-256-gcm-open kx-key nonce aad ct tag)))
                  (unless pt (return-from %parse-crypto-token nil))
                  ;; AEAD succeeded; now parse the 88-byte KeyMaterial CDR
                  (let ((km (%parse-km-cdr pt)))
                    (fill pt 0) ; wipe decrypted material
                    km))))))))))


(defun* make-crypto-token-message (km kx-key src-guid dest-guid)
    (function (key-material
               (simple-array (unsigned-byte 8) (32))
               (simple-array (unsigned-byte 8) (16))
               (simple-array (unsigned-byte 8) (16)))
              (simple-array (unsigned-byte 8) (*)))
  "Build a §7.4.4 ParticipantGenericMessage wrapping one KxKey-encrypted CryptoToken DataHolder.
   message_class_id = 'dds.sec.participant_crypto_tokens' (§7.4.4; spike §4).
   destination_endpoint_key = all-zeros (participant-level; spike §4).
   Sequence number and related GUIDs are all-zeros (deferred to T5 manager). Spike §3.3 / §6.6."
  (let* ((dh-blob  (serialize-crypto-token km kx-key))
         (zero-16  (make-array 16 :element-type '(unsigned-byte 8) :initial-element 0)))
    (make-generic-message
     :source-guid             src-guid
     :sequence-number         0
     :related-guid            zero-16
     :related-sn              0
     :dest-participant-guid   dest-guid
     :dest-endpoint-guid      zero-16
     :source-endpoint-guid    src-guid
     :message-class-id        +gm-participant-crypto-tokens+
     :dataholders             (list dh-blob))))

(defun* parse-crypto-token-message (octets kx-key)
    (function ((simple-array (unsigned-byte 8) (*))
               (simple-array (unsigned-byte 8) (32)))
              (or key-material null))
  "Parse a §7.4.4 ParticipantGenericMessage containing one CryptoToken DataHolder.
   Returns a key-material on success; NIL on any malformed/truncated/forged/wrong-class input.
   Cap: exactly 1 DataHolder per message (spike §6.3); validates message_class_id.
   Fail-closed: all parse failures return NIL, no signals."
  (block %parse-ctm
    (multiple-value-bind (src-guid sn rel-guid rel-sn dest-part dest-ep src-ep class-id dh-list)
        (parse-generic-message octets)
      (declare (ignore sn rel-guid rel-sn dest-part dest-ep src-ep))
      (unless src-guid (return-from %parse-ctm nil))
      (unless (string= class-id +gm-participant-crypto-tokens+)
        (return-from %parse-ctm nil))
      ;; cap: exactly 1 DataHolder (spike §6.3)
      (unless (= (length dh-list) 1) (return-from %parse-ctm nil))
      (parse-crypto-token (car dh-list) kx-key))))
