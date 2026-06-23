(in-package #:dds.security)

;;; DDS-Security 1.1 §9.5.3.3 serialized-payload protection — AES256-GCM SecuredPayload wire
;;; format + §9.5.3.3.4.2 HMAC-SHA256 session-key KDF. Every field width / constant / layout is
;;; pinned from the §9.5.3.3 spec clause and the T0 spike doc
;;; (docs/superpowers/spikes/2026-06-22-dds-security-payload-wire.md, §2/§3/§7); none from memory.
;;; Crypto is reused from DDS.DARE (OpenSSL >= 3.5); no hand-rolled crypto.

;;; --- pinned wire constants (DDS-Security 1.1 §9.5.3.3.1 Table 69; spike §2.2/§7) ---

(defconstant +transformation-kind-aes256-gcm+
    (if (boundp '+transformation-kind-aes256-gcm+)
        (symbol-value '+transformation-kind-aes256-gcm+)
        (make-array 4 :element-type '(unsigned-byte 8) :initial-contents '(#x00 #x00 #x00 #x04)))
  "CryptoTransformKind octet[4] for AES256-GCM = {0x00,0x00,0x00,0x04}, as a 4-octet vector
   (DDS-Security 1.1 §9.5.3.3.1 Table 69; spike §2.2). Endian-independent (opaque octet[4]).
   The boundp-guard makes a reload a no-op so defconstant's same-value rule holds for the literal.")

(defconstant +transformation-kind-len+ 4 "CryptoTransformKind width: octet[4] (§9.5.3.3.1).")
(defconstant +transformation-key-id-len+ 4 "CryptoTransformKeyId width: octet[4] (§9.5.3.3.1; opaque, spike §8.2).")
(defconstant +session-id-len+ 4 "SecureDataHeader.session_id width: octet[4] (§9.5.3.3.1; spike §2.2).")
(defconstant +init-vector-suffix-len+ 8 "SecureDataHeader.init_vector_suffix width: octet[8] (§9.5.3.3.1; spike §2.2).")
(defconstant +secure-data-header-len+ 20
  "SecureDataHeader total width = kind(4)+key_id(4)+session_id(4)+iv_suffix(8) (§9.5.3.3.1; spike §2.2).")
(defconstant +crypto-content-length-len+ 4
  "crypto_content sequence<octet> length-prefix width: uint32 (§9.5.3.3.4.4; spike §2.3).")
(defconstant +common-mac-len+ 16
  "SecureDataTag.common_mac width = AES-GCM 128-bit tag, 16 octets (§9.5.3.3.3; spike §2.4/§5).")
(defconstant +receiver-specific-macs-count-len+ 4
  "SecureDataTag.receiver_specific_macs_count width: uint32 (§9.5.3.3.3; spike §2.4).")
(defconstant +receiver-specific-macs-count-payload-protection+ 0
  "receiver_specific_macs_count for plain ENCRYPT without WITH_ORIGIN_AUTHENTICATION = 0
   (§9.5.3.3.4.4 step 10; spike §2.4).")
(defconstant +secure-data-tag-len+ 20
  "SecureDataTag total width for rsm_count=0 = common_mac(16)+count(4) (§9.5.3.3.3; spike §2.4).")

;;; The §9.5.3.3.4.2 KDF id/counter literals (spec Table 70; spike §3.1).
(defconstant +session-key-id-string+
    (if (boundp '+session-key-id-string+) (symbol-value '+session-key-id-string+) "SessionKey")
  "DDS-Security §9.5.3.3.4.2 Table 70 session-key id_string (ASCII, 10 octets); spike §3.1.")
(defconstant +session-key-counter-string+
    (if (boundp '+session-key-counter-string+) (symbol-value '+session-key-counter-string+) "0001")
  "DDS-Security §9.5.3.3.4.2 Table 70 session-key counter_string (ASCII, 4 octets); spike §3.1.")
(defconstant +session-key-len+ 32 "AES-256 session key length in octets (§9.5.3.3.4.2; spike §3.1).")

;;; CDR-encapsulation-header decision (spec §9.5.3.3.4.4 + spike §2.1/§8 item 1):
;;; the spec does NOT mandate a 4-byte CDR encapsulation header before the SecureDataHeader; whether
;;; Connext prepends one inside the DATA serialized-payload field is implementation-defined and
;;; unconfirmed (the live Connext capture was blocked — spike §1). This serializer therefore produces
;;; the SPEC-MINIMAL bare SecuredPayload (SecureDataHeader || crypto_content || SecureDataTag), the
;;; spike §2.5 "NO CDR header" layout. A live Connext byte-compare to settle whether a CDR header is
;;; present is the deferred follow-on (spike §8). The header is never part of the AAD or plaintext.

(define-condition secured-payload-malformed (error)
  ((reason :initarg :reason :reader secured-payload-malformed-reason))
  (:report (lambda (c s) (format s "malformed SecuredPayload: ~a" (secured-payload-malformed-reason c))))
  (:documentation
   "Signalled by PARSE-SECURED-PAYLOAD when the input is too short or self-inconsistent
    (a declared crypto_content length that overflows the buffer). Fail-closed: a malformed
    or hostile SecuredPayload never yields a partial parse or an OOB read (NFR-SEC-POSTURE)."))

;;; --- internal octet helpers (kept local; mirror the established dds.dare/test style) ---

(defun* %ascii-octets (s)
    (function (string) (simple-array (unsigned-byte 8) (*)))
  "Convert ASCII string S to an octet vector (KDF literal marshalling; no Unicode)."
  (let* ((n (length s))
         (v (make-array n :element-type '(unsigned-byte 8))))
    (dotimes (i n v)
      (setf (aref v i) (char-code (char s i))))))

(defun* %require-len (octets n field)
    (function ((simple-array (unsigned-byte 8) (*)) fixnum string) t)
  "Signal SECURED-PAYLOAD-MALFORMED unless OCTETS is exactly N long; names FIELD in the message."
  (unless (= (length octets) n)
    (error 'secured-payload-malformed
           :reason (format nil "~a must be ~d octets, got ~d" field n (length octets))))
  t)

;;; --- serialize-secured-payload (§9.5.3.3.4.4; spike §2.5) ---

(defun* serialize-secured-payload (kind key-id session-id iv-suffix ciphertext tag)
    (function ((simple-array (unsigned-byte 8) (*))
               (simple-array (unsigned-byte 8) (*))
               (simple-array (unsigned-byte 8) (*))
               (simple-array (unsigned-byte 8) (*))
               (simple-array (unsigned-byte 8) (*))
               (simple-array (unsigned-byte 8) (*)))
              (simple-array (unsigned-byte 8) (*)))
  "Serialize a DDS-Security 1.1 §9.5.3.3 AES256-GCM SecuredPayload (spike §2.5).
   KIND octet[4] (transformation_kind), KEY-ID octet[4] (transformation_key_id), SESSION-ID octet[4],
   IV-SUFFIX octet[8] (init_vector_suffix), CIPHERTEXT N octets, TAG 16 octets (common_mac).
   Produces (no CDR encapsulation header — see file note):
     SecureDataHeader(20) || crypto_content.length(uint32 LE)=N || ciphertext(N)
                          || common_mac(16) || receiver_specific_macs_count(uint32 LE)=0.
   The 20-byte SecureDataHeader is exactly the AEAD AAD (§9.5.3.3.4.4). Returns a fresh octet vector.
   crypto_content.length and receiver_specific_macs_count use little-endian (RTPS E-flag=1, the
   common case; spike §2.3/§8 item 3 — at count=0 the latter is endian-irrelevant)."
  (%require-len kind +transformation-kind-len+ "transformation_kind")
  (%require-len key-id +transformation-key-id-len+ "transformation_key_id")
  (%require-len session-id +session-id-len+ "session_id")
  (%require-len iv-suffix +init-vector-suffix-len+ "init_vector_suffix")
  (%require-len tag +common-mac-len+ "common_mac")
  (let* ((ct-n  (length ciphertext))
         (total (+ +secure-data-header-len+ +crypto-content-length-len+ ct-n +secure-data-tag-len+))
         (out   (make-array total :element-type '(unsigned-byte 8)))
         (cur   (dds.core.buffer:cursor (dds.core.buffer:octet-buffer-over out) :endianness :little)))
    (dds.core.buffer:put-octets cur kind 0 +transformation-kind-len+)
    (dds.core.buffer:put-octets cur key-id 0 +transformation-key-id-len+)
    (dds.core.buffer:put-octets cur session-id 0 +session-id-len+)
    (dds.core.buffer:put-octets cur iv-suffix 0 +init-vector-suffix-len+)
    (dds.core.buffer:put-u32 cur ct-n)
    (dds.core.buffer:put-octets cur ciphertext 0 ct-n)
    (dds.core.buffer:put-octets cur tag 0 +common-mac-len+)
    (dds.core.buffer:put-u32 cur +receiver-specific-macs-count-payload-protection+)
    out))

;;; --- parse-secured-payload (§9.5.3.3; spike §2.5) — bounds-checked, fail-closed ---

(defun* parse-secured-payload (octets)
    (function ((simple-array (unsigned-byte 8) (*)))
              (values (simple-array (unsigned-byte 8) (*))
                      (simple-array (unsigned-byte 8) (*))
                      (simple-array (unsigned-byte 8) (*))
                      (simple-array (unsigned-byte 8) (*))
                      (simple-array (unsigned-byte 8) (*))
                      (simple-array (unsigned-byte 8) (*))))
  "Parse a bare DDS-Security §9.5.3.3 SecuredPayload (no CDR header; the serialize-secured-payload
   inverse). Returns (values KIND KEY-ID SESSION-ID IV-SUFFIX CIPHERTEXT TAG).
   Every field read is bounds-checked against the input length BEFORE allocating: a too-short input
   or a declared crypto_content length that overflows the remaining bytes signals
   SECURED-PAYLOAD-MALFORMED, never an OOB read or a partial parse (NFR-SEC-POSTURE), even at
   (safety 0). crypto_content.length and receiver_specific_macs_count are read little-endian."
  (let ((n (length octets)))
    (when (< n (+ +secure-data-header-len+ +crypto-content-length-len+
                  +secure-data-tag-len+))
      (error 'secured-payload-malformed
             :reason (format nil "input ~d octets < minimum ~d (header+ct_len+tag)"
                             n (+ +secure-data-header-len+ +crypto-content-length-len+
                                  +secure-data-tag-len+))))
    (let* ((cur (dds.core.buffer:cursor (dds.core.buffer:octet-buffer-over octets) :endianness :little))
           (kind      (make-array +transformation-kind-len+ :element-type '(unsigned-byte 8)))
           (key-id    (make-array +transformation-key-id-len+ :element-type '(unsigned-byte 8)))
           (session-id (make-array +session-id-len+ :element-type '(unsigned-byte 8)))
           (iv-suffix (make-array +init-vector-suffix-len+ :element-type '(unsigned-byte 8)))
           (tag       (make-array +common-mac-len+ :element-type '(unsigned-byte 8))))
      (dds.core.buffer:get-octets cur kind 0 +transformation-kind-len+)
      (dds.core.buffer:get-octets cur key-id 0 +transformation-key-id-len+)
      (dds.core.buffer:get-octets cur session-id 0 +session-id-len+)
      (dds.core.buffer:get-octets cur iv-suffix 0 +init-vector-suffix-len+)
      (let ((ct-n (dds.core.buffer:get-u32 cur)))
        (unless (= ct-n (- n +secure-data-header-len+ +crypto-content-length-len+ +secure-data-tag-len+))
          (error 'secured-payload-malformed
                 :reason (format nil "crypto_content.length ~d inconsistent with input length ~d" ct-n n)))
        (let ((ciphertext (make-array ct-n :element-type '(unsigned-byte 8))))
          (dds.core.buffer:get-octets cur ciphertext 0 ct-n)
          (dds.core.buffer:get-octets cur tag 0 +common-mac-len+)
          (let ((rsm-count (dds.core.buffer:get-u32 cur)))
            (unless (= rsm-count +receiver-specific-macs-count-payload-protection+)
              (error 'secured-payload-malformed
                     :reason (format nil "receiver_specific_macs_count ~d unsupported (expected 0)" rsm-count))))
          (values kind key-id session-id iv-suffix ciphertext tag))))))

;;; --- derive-session-key (§9.5.3.3.4.2; spike §3.1) ---

(defun* derive-session-key (master-key master-salt session-id)
    (function ((simple-array (unsigned-byte 8) (*))
               (simple-array (unsigned-byte 8) (*))
               (simple-array (unsigned-byte 8) (*)))
              (simple-array (unsigned-byte 8) (32)))
  "Derive the 32-byte AES-256 session key per DDS-Security 1.1 §9.5.3.3.4.2 (spike §3.1):
     session_key = HMAC-SHA256(master_sender_key,
                               'SessionKey' || master_salt || session_id || '0001').
   MASTER-KEY = master_sender_key (32 octets), MASTER-SALT = master_salt (32 octets),
   SESSION-ID = the 4-octet SecureDataHeader.session_id (spliced in verbatim).
   Uses HMAC-SHA256 (NOT HKDF-SHA384) per the spec; the MAC primitive is dds.dare:hmac-sha256.
   Returns a fresh 32-byte vector. Signals SECURED-PAYLOAD-MALFORMED for wrong-size inputs (fail-closed)."
  (%require-len master-key  32 "master_sender_key")
  (%require-len master-salt 32 "master_salt")
  (%require-len session-id   4 "session_id")
  (let* ((id   (%ascii-octets +session-key-id-string+))
         (ctr  (%ascii-octets +session-key-counter-string+))
         (data (make-array (+ (length id) (length master-salt) (length session-id) (length ctr))
                           :element-type '(unsigned-byte 8)))
         (cur  (dds.core.buffer:cursor (dds.core.buffer:octet-buffer-over data) :endianness :little)))
    (dds.core.buffer:put-octets cur id 0 (length id))
    (dds.core.buffer:put-octets cur master-salt 0 (length master-salt))
    (dds.core.buffer:put-octets cur session-id 0 (length session-id))
    (dds.core.buffer:put-octets cur ctr 0 (length ctr))
    (dds.dare:hmac-sha256 master-key data)))
