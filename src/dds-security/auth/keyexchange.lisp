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
;;; KeyMaterial CDR layout (88 bytes, AES256-GCM, NO receiver-specific key):
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
;;; ORIGIN-AUTH form (120 bytes, AES256-GCM, WITH receiver-specific key — the *_WITH_ORIGIN_AUTHENTICATION
;;; tier, §9.5.3.3.4.3): identical through [83], then the absent-marker is replaced by a populated
;;; master_receiver_specific_key sequence:
;;;   [80..83] receiver_specific_key_id (NON-ZERO — the Fast DDS has_specific_key discriminator)
;;;   [84..86] padding              = {0x00,0x00,0x00}
;;;   [87]     master_receiver_specific_key length = 0x20 (= 32)
;;;   [88..119] master_receiver_specific_key[0..31]
;;; Source: Fast DDS AESGCMGMAC_KeyExchange.cpp KeyMaterialCDRSerialize() L432-454 (serialize) +
;;; KeyMaterialCDRDeserialize() L511-528 (parse): the presence of the receiver key is keyed on
;;; has_specific_key = OR of receiver_specific_key_id's 4 octets (non-zero -> the 3-pad+len(0x20)+32B
;;; sequence; zero -> 4 zero octets) — corroborated CLEAN-ROOM (read-only, no code copied); spike §3.2.
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

(defconstant +km-cdr-len-origin-auth+ 120
  "Byte length of the serialized KeyMaterial_AES_GCM_GMAC CDR for AES256-GCM WITH a receiver-specific key
   (the *_WITH_ORIGIN_AUTHENTICATION tier, §9.5.3.3.4.3): the 88-byte form with the absent-marker[4] replaced
   by a populated master_receiver_specific_key sequence pad(3)+len(0x20)+key(32). 88-4+36 = 120.
   Source: Fast DDS KeyMaterialCDRSerialize() L447-453 (the has_specific_key non-zero branch).")

(defconstant +kx-nonce-len+ 12
  "AES-GCM nonce length in bytes. NIST SP 800-38D §8.2.1 96-bit IV for the random construction.")

(defconstant +aes-gcm-tag-len-kx+ 16
  "AES-GCM authentication tag length in bytes (NIST SP 800-38D, 128-bit tag).")

(defconstant +km-cdr-wrapped-len+ 116
  "Byte length of the KxKey-wrapped KeyMaterial blob: nonce(12) || ciphertext(88) || tag(16) = 116.")

;;; --- KeyMaterial CDR serializer ---

(defun* %serialize-km-cdr (km)
    (function (key-material) (simple-array (unsigned-byte 8) (*)))
  "Serialize KM to the Fast DDS proprietary KeyMaterial CDR format (spike §3.2): the 88-byte no-origin-auth
   form, or the 120-byte *_WITH_ORIGIN_AUTHENTICATION form when KM carries a NON-ZERO receiver_specific_key_id
   (the Fast DDS has_specific_key discriminator, KeyMaterialCDRSerialize L432-454).
   Layout: kind(4){0,0,0,4} + pad(3)+len(0x20)+salt(32) + key-id(4) + pad(3)+len(0x20)+sender-key(32) +
           rsm-id(4) + {absent: zeros(4)} | {present: pad(3)+len(0x20)+recv-key(32)}.
   Byte-identical to the prior 88-byte serializer when receiver_specific_key_id is all-zero (the SIGN/ENCRYPT
   path is unchanged). NEEDS-VERIFICATION §6.2: proprietary framing; not standard CDR uint32 sequence-length."
  (let* ((rsk-id      (key-material-receiver-specific-key-id km))
         (origin-auth (notevery #'zerop rsk-id))   ; Fast DDS has_specific_key (rsm-id non-zero)
         (out  (make-array (if origin-auth +km-cdr-len-origin-auth+ +km-cdr-len+)
                           :element-type '(unsigned-byte 8) :initial-element 0))
         (kind (key-material-transformation-kind km))
         (salt (key-material-master-salt km))
         (kid  (key-material-sender-key-id km))
         (mkey (key-material-master-sender-key km)))
    ;; [0..3] transformation_kind
    (dotimes (i 4) (setf (aref out i) (aref kind i)))
    ;; [4..6] padding = {0x00,0x00,0x00}; [7] = 0x20 (32 = length of master_salt); [8..39] master_salt
    (setf (aref out 7) #x20)
    (dotimes (i 32) (setf (aref out (+ 8 i)) (aref salt i)))
    ;; [40..43] sender_key_id
    (dotimes (i 4) (setf (aref out (+ 40 i)) (aref kid i)))
    ;; [44..46] padding = {0x00,0x00,0x00}; [47] = 0x20 (32 = length of master_sender_key); [48..79]
    (setf (aref out 47) #x20)
    (dotimes (i 32) (setf (aref out (+ 48 i)) (aref mkey i)))
    ;; [80..83] receiver_specific_key_id (all-zero when not origin-auth -> the 88-byte absent form follows)
    (when origin-auth
      (let ((rsk (key-material-master-receiver-specific-key km)))
        (dotimes (i 4) (setf (aref out (+ 80 i)) (aref rsk-id i)))
        ;; [84..86] padding; [87] = 0x20 (master_receiver_specific_key length); [88..119] the key
        (setf (aref out 87) #x20)
        (dotimes (i 32) (setf (aref out (+ 88 i)) (aref rsk i)))))
    out))

;;; --- KeyMaterial CDR deserializer ---

(defun* %parse-km-cdr (cdr)
    (function ((simple-array (unsigned-byte 8) (*))) (or key-material null))
  "Parse a KeyMaterial CDR blob (the 88-byte no-origin-auth form OR the 120-byte *_WITH_ORIGIN_AUTHENTICATION
   form) into a key-material struct. Returns NIL if malformed (fail-closed, NFR-SEC-POSTURE).
   Checks: length 88 or 120; transformation_kind[0..2] = {0,0,0}; kind[3] in {0x01,0x02,0x03,0x04} (the four
   §9.5.2.1.1 non-NONE CryptoTransformKind values: AES128_GMAC/GCM, AES256_GMAC/GCM); length bytes at
   [7] and [47] = 0x20 (32). The receiver-specific key follows Fast DDS has_specific_key (KeyMaterialCDRDeserialize
   L511-528): receiver_specific_key_id [80..83] all-zero -> the 88-byte absent form ([84..87] must be zero);
   non-zero -> the 120-byte form ([84..86]=0, [87]=0x20, master_receiver_specific_key at [88..119]). Any length/
   form/marker mismatch fails closed. The carried receiver key is retained so the matched-remote EntityCrypto the
   token installs keeps the remote's origin-auth receiver key (§9.5.3.3.4.3)."
  (block %parse-km
    (let ((n (length cdr)))
      (unless (or (= n +km-cdr-len+) (= n +km-cdr-len-origin-auth+)) (return-from %parse-km nil))
      ;; kind[0..2] must be zeros; kind[3] is the algorithm byte — the FOUR defined non-NONE
      ;; CryptoTransformKind values (DDS-Security 1.1 §9.5.2.1.1 Table 70 / dds_security_plugins_psm.idl):
      ;; 0x01 AES128_GMAC, 0x02 AES128_GCM, 0x03 AES256_GMAC, 0x04 AES256_GCM. 0x03 was previously
      ;; omitted; Fast DDS sends the participant ParticipantKeyMaterial with kind {0,0,0,3} (AES256_GMAC)
      ;; under a GMAC-tier governance, so a conformant parser MUST accept it (live cross-vendor: the
      ;; ParticipantCryptoToken KeyMaterial carried 0x03 -> a false REJECT blocked :keyed). Corroborated
      ;; CLEAN-ROOM vs Fast DDS AESGCMGMAC_KeyFactory (c_transfrom_kind_aes256_gmac); see docs/provenance.md.
      (unless (and (zerop (aref cdr 0)) (zerop (aref cdr 1)) (zerop (aref cdr 2)))
        (return-from %parse-km nil))
      (unless (member (aref cdr 3) '(#x01 #x02 #x03 #x04)) (return-from %parse-km nil))
      ;; master_salt / master_sender_key length bytes must be 0x20 (= 32)
      (unless (and (= (aref cdr 7) #x20) (= (aref cdr 47) #x20))
        (return-from %parse-km nil))
      ;; receiver_specific_key_id [80..83]; has_specific_key = OR of its 4 octets (Fast DDS L511-519)
      (let ((rsk-id      (make-array 4 :element-type '(unsigned-byte 8)))
            (origin-auth nil))
        (dotimes (i 4)
          (setf (aref rsk-id i) (aref cdr (+ 80 i)))
          (unless (zerop (aref rsk-id i)) (setf origin-auth t)))
        ;; form/marker consistency: absent -> 88B with [84..87]=0; present -> 120B with [84..86]=0,[87]=0x20
        (if origin-auth
            (unless (and (= n +km-cdr-len-origin-auth+)
                         (zerop (aref cdr 84)) (zerop (aref cdr 85)) (zerop (aref cdr 86))
                         (= (aref cdr 87) #x20))
              (return-from %parse-km nil))
            (unless (and (= n +km-cdr-len+)
                         (zerop (aref cdr 84)) (zerop (aref cdr 85))
                         (zerop (aref cdr 86)) (zerop (aref cdr 87)))
              (return-from %parse-km nil)))
        (let ((kind (make-array 4 :element-type '(unsigned-byte 8)))
              (salt (make-array 32 :element-type '(unsigned-byte 8)))
              (kid  (make-array 4 :element-type '(unsigned-byte 8)))
              (mkey (make-array 32 :element-type '(unsigned-byte 8)))
              (rsk  (make-array 32 :element-type '(unsigned-byte 8) :initial-element 0)))
          (dotimes (i 4)  (setf (aref kind i) (aref cdr i)))
          (dotimes (i 32) (setf (aref salt i) (aref cdr (+ 8 i))))
          (dotimes (i 4)  (setf (aref kid i)  (aref cdr (+ 40 i))))
          (dotimes (i 32) (setf (aref mkey i) (aref cdr (+ 48 i))))
          (when origin-auth (dotimes (i 32) (setf (aref rsk i) (aref cdr (+ 88 i)))))
          (make-key-material :transformation-kind          kind
                             :master-salt                  salt
                             :sender-key-id                kid
                             :master-sender-key            mkey
                             :receiver-specific-key-id     rsk-id
                             :master-receiver-specific-key rsk))))))

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

(defun* generate-writer-key-material (writer-guid &key (origin-auth nil))
    (function ((simple-array (unsigned-byte 8) (16)) &key (:origin-auth t)) key-material)
  "Generate a fresh §9.5.2 KeyMaterial_AES_GCM_GMAC for WRITER-GUID. Delegates the random
   master_salt / master_sender_key + (under ORIGIN-AUTH) the NON-ZERO receiver-specific fill to the
   generic GENERATE-KEY-MATERIAL (DRY — the single CryptoKeyFactory primitive, key-material.lisp),
   then OVERRIDES sender_key_id with the deterministic GUID-derived id (%GUID-KEY-ID: the first 4
   octets of WRITER-GUID) so the on-wire transformation_key_id ties the KeyMaterial to the writer
   the participant advertises (§9.5.2 Table 65; the derivation is our-implementation choice, not a
   spec mandate). transformation_kind = AES256-GCM. ORIGIN-AUTH true additionally carries the
   non-zero receiver-specific key material for the *_WITH_ORIGIN_AUTHENTICATION kinds (§9.5.3.3.4.3).
   Secrets are plain heap vectors (ADR 0034 deferral) — the caller owns the key-material struct.
   Control-plane, not the hot path."
  (let ((km (generate-key-material :origin-auth origin-auth)))
    (setf (key-material-sender-key-id km) (%guid-key-id writer-guid))
    km))

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


;;; === T8 (WP-DDS-SECURITY-SECURE-DISCOVERY): PLAINTEXT CryptoToken DataHolder (§8.5.2 conformant) ===
;;; The conformant §8.5.2 crypto-token exchange rides the §9.5.2 KeyMaterial as a PLAINTEXT DataHolder
;;; INSIDE a PVMS submessage-protected message — the PVMS ENCRYPT (T7 bootstrap key) provides the
;;; confidentiality, so the token is NOT app-encrypted. This REPLACES KEYX's interim KxKey-AEAD wrap over
;;; best-effort PSM (T8 HARD CONSTRAINT #2): the KxKey wrap (serialize-crypto-token / parse-crypto-token)
;;; remains for the KEYX KAT regression but is no longer on the live exchange path.

(defun* serialize-crypto-token-plain (km)
    (function (key-material) (simple-array (unsigned-byte 8) (*)))
  "Serialize KM as a PLAINTEXT CryptoToken CDR-LE DataHolder blob (§8.5.2 / §9.5.2 / §9.3.4) — the
   conformant token payload that rides INSIDE a PVMS submessage-protected message (T8). DataHolder:
   class_id +crypto-token-class-id+; one binary property +crypto-token-keymat-prop+ carrying the §9.5.2
   KeyMaterial CDR (%serialize-km-cdr — 88-byte no-origin-auth or 120-byte *_WITH_ORIGIN_AUTHENTICATION
   form, carrying the receiver-specific key) IN THE CLEAR. NO KxKey AEAD wrap (the PVMS submessage ENCRYPT
   is the confidentiality boundary, §6.5). Inverse: parse-crypto-token-plain."
  (handshake-token->dataholder
   (%make-handshake-token
    :class-id     +crypto-token-class-id+
    :binary-props (list (cons +crypto-token-keymat-prop+ (%serialize-km-cdr km))))))

(defun* parse-crypto-token-plain (octets)
    (function ((simple-array (unsigned-byte 8) (*))) (or key-material null))
  "Parse a PLAINTEXT CryptoToken DataHolder (inverse of serialize-crypto-token-plain). Returns the §9.5.2
   key-material, or NIL on any malformed/truncated/wrong-class/wrong-length input (fail-closed,
   NFR-SEC-POSTURE). Bounds-checked: dataholder->handshake-token caps every length; exactly 1 binary
   property named +crypto-token-keymat-prop+; the value is parsed by %parse-km-cdr which enforces the 88-octet
   no-origin-auth OR 120-octet origin-auth KeyMaterial CDR layout (retaining the receiver-specific key when
   present). NO decryption (the PVMS layer already authenticated + decrypted)."
  (block %p
    (let ((tok (dataholder->handshake-token octets)))
      (unless tok (return-from %p nil))
      (unless (string= (handshake-token-class-id tok) +crypto-token-class-id+) (return-from %p nil))
      (let ((props (handshake-token-binary-props tok)))
        (unless (= (length props) 1) (return-from %p nil))
        (let ((pair (car props)))
          (unless (string= (car pair) +crypto-token-keymat-prop+) (return-from %p nil))
          (%parse-km-cdr (cdr pair)))))))

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
