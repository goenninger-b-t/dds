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

(defconstant +transformation-kind-aes256-gmac+
    (if (boundp '+transformation-kind-aes256-gmac+)
        (symbol-value '+transformation-kind-aes256-gmac+)
        (make-array 4 :element-type '(unsigned-byte 8) :initial-contents '(#x00 #x00 #x00 #x03)))
  "CryptoTransformKind octet[4] for AES256-GMAC (authentication-only, NO encryption) =
   {0x00,0x00,0x00,0x03}, as a 4-octet vector (DDS-Security 1.1 §9.5.3.3.1 Table 69). Selects the
   SIGN protection mode: the SEC_BODY carries the plaintext verbatim and the common_mac is a GMAC
   over it. Used by submessage protection (crypto/submessage.lisp) to signal SIGN vs ENCRYPT on the
   wire. Corroborated (read-only, no code copied) against eProsima Fast DDS (Apache-2.0)
   AESGCMGMAC_Types.h CRYPTO_TRANSFORMATION_KIND_AES256_GMAC { {0,0,0,3} }; see docs/provenance.md.
   The boundp-guard makes a reload a no-op so defconstant's same-value rule holds for the literal.")

(defconstant +empty-octets+
    (if (boundp '+empty-octets+)
        (symbol-value '+empty-octets+)
        (make-array 0 :element-type '(unsigned-byte 8)))
  "A shared zero-length octet vector: the EMPTY AAD passed to %seal-with-km / %open-with-km across ALL the
   §9.5.3.3 AES-GCM-GMAC protection tiers (serialized-payload, submessage, whole-RTPS) — Fast-DDS-faithful,
   corroborated CLEAN-ROOM against eProsima Fast DDS (Apache-2.0) AESGCMGMAC_Transform.cpp serialize_SecureDataBody,
   whose ENCRYPT branch encrypts the plaintext with NO prior EVP_EncryptUpdate AAD call (=> empty AAD) and is the
   SAME function for the serialized-payload and submessage paths (see docs/provenance.md). Defined here (the first
   dds-security file) so transform.lisp (payload tier) AND crypto/submessage.lisp (submessage tier) both reference
   the one instance (DRY across the load order). Also the EMPTY plaintext (SIGN/GMAC) handed to the seal. Boundp-
   guarded so a reload is a no-op (defconstant same-value rule).")

;;; The §9.5.3.3 wire-element field widths (+transformation-kind-len+ .. +receiver-specific-macs-count-len+) are pinned in crypto/crypto-header.lisp (the shared §7.3.7 codec, loaded first) as the single source of truth; reused here by name (DRY).
(defconstant +receiver-specific-macs-count-payload-protection+ 0
  "receiver_specific_macs_count for plain ENCRYPT without WITH_ORIGIN_AUTHENTICATION = 0
   (§9.5.3.3.4.4 step 10; spike §2.4).")
(defconstant +secure-data-tag-len+ 20
  "SecureDataTag total width for rsm_count=0 = common_mac(16)+count(4) (§9.5.3.3.3; spike §2.4).")

;;; The §9.5.3.3.4.2 KDF id_string literal (spike §3.1). NOTE: the conformant AES-GCM-GMAC session-key
;;; KDF has NO trailing counter — Fast DDS compute_sessionkey AND Cyclone crypto_calculate_session_key both
;;; hash id_string ‖ master_salt ‖ session_id with no counter (corroborated CLEAN-ROOM, read-only; see
;;; docs/provenance.md, M7/P6 T-RECONCILE). An earlier "0001" counter constant was removed reconciling to
;;; the wire oracle (the operating contract §4 — the wire is the oracle; non-interop is the worst defect).
(defconstant +session-key-id-string+
    (if (boundp '+session-key-id-string+) (symbol-value '+session-key-id-string+) "SessionKey")
  "DDS-Security §9.5.3.3.4.2 session-key id_string (ASCII, 10 octets); spike §3.1.")
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
     SecureDataHeader(20) || crypto_content.length(uint32 BE)=N || ciphertext(N)
                          || common_mac(16) || <pad to 4-align> || receiver_specific_macs_count(uint32 BE)=0.
   The §9.5.3.3.3 SecureDataTag aligns the receiver_specific_macs_count to a 4-byte boundary relative to the
   SecuredPayload start (Fast DDS serialize_SecureDataTag): the pad = (-N) mod 4 octets after the common_mac
   (zero when N is a multiple of 4) — without it a conformant peer's decode_serialized_payload mis-reads the
   tag length ('Error in fastcdr trying to deserialize SecureDataTag length'). serialize-crypto-footer writes
   the pad. The 20-byte SecureDataHeader is exactly the AEAD AAD (§9.5.3.3.4.4). Returns a fresh octet vector.
   crypto_content.length and receiver_specific_macs_count are BIG-ENDIAN (§9.5.3.3.3/.4.4; the codec
   forces it via %put-u32-be independent of the cursor's little-endian stream — Fast-DDS/Cyclone-aligned;
   see docs/provenance.md, M7/P6 T-RECONCILE; at count=0 the latter is endian-irrelevant)."
  (%require-len kind +transformation-kind-len+ "transformation_kind")
  (%require-len key-id +transformation-key-id-len+ "transformation_key_id")
  (%require-len session-id +session-id-len+ "session_id")
  (%require-len iv-suffix +init-vector-suffix-len+ "init_vector_suffix")
  (%require-len tag +common-mac-len+ "common_mac")
  (let* ((ct-n  (length ciphertext))
         (tag-pad (mod (- ct-n) 4))   ; §9.5.3.3.3 SecureDataTag rsm_count 4-align pad after the common_mac
         (total (+ +secure-data-header-len+ +crypto-content-length-len+ ct-n tag-pad +secure-data-tag-len+))
         (out   (make-array total :element-type '(unsigned-byte 8)))
         (cur   (dds.core.buffer:cursor (dds.core.buffer:octet-buffer-over out) :endianness :little)))
    ;; DRY: delegate to the §7.3.7 codec (SecureDataHeader=CryptoHeader, crypto_content=CryptoContent, rsm=0 SecureDataTag=empty CryptoFooter).
    (serialize-crypto-header cur kind key-id session-id iv-suffix)
    (serialize-crypto-content cur ciphertext)
    (serialize-crypto-footer cur tag '())
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
   (safety 0). crypto_content.length and receiver_specific_macs_count are read BIG-ENDIAN (§9.5.3.3.3/.4.4;
   via %get-u32-be, independent of the cursor's little-endian stream — Fast-DDS/Cyclone-aligned)."
  (let ((n (length octets)))
    (when (< n (+ +secure-data-header-len+ +crypto-content-length-len+
                  +secure-data-tag-len+))
      (error 'secured-payload-malformed
             :reason (format nil "input ~d octets < minimum ~d (header+ct_len+tag)"
                             n (+ +secure-data-header-len+ +crypto-content-length-len+
                                  +secure-data-tag-len+))))
    (let ((cur (dds.core.buffer:cursor (dds.core.buffer:octet-buffer-over octets) :endianness :little)))
      ;; DRY: delegate field extraction to the §7.3.7 codec; re-assert the Slice-1 invariants (exact length consistency + rsm_count=0).
      (multiple-value-bind (kind key-id session-id iv-suffix) (parse-crypto-header cur)
        (unless kind
          (error 'secured-payload-malformed :reason "truncated SecureDataHeader (CryptoHeader)"))
        (let ((ciphertext (parse-crypto-content cur)))
          (unless ciphertext
            (error 'secured-payload-malformed
                   :reason "crypto_content.length overflows the input (truncated or over-declared)"))
          (unless (= (length ciphertext)
                     (- n +secure-data-header-len+ +crypto-content-length-len+ +secure-data-tag-len+
                        (mod (- (length ciphertext)) 4)))   ; the §9.5.3.3.3 SecureDataTag 4-align pad
            (error 'secured-payload-malformed
                   :reason (format nil "crypto_content.length ~d inconsistent with input length ~d"
                                   (length ciphertext) n)))
          (multiple-value-bind (tag receiver-macs) (parse-crypto-footer cur)
            (unless tag
              (error 'secured-payload-malformed :reason "truncated SecureDataTag (CryptoFooter)"))
            (unless (= (length receiver-macs) +receiver-specific-macs-count-payload-protection+)
              (error 'secured-payload-malformed
                     :reason (format nil "receiver_specific_macs_count ~d unsupported (expected ~d)"
                                     (length receiver-macs) +receiver-specific-macs-count-payload-protection+)))
            (values kind key-id session-id iv-suffix ciphertext tag)))))))

;;; --- derive-session-key (§9.5.3.3.4.2; spike §3.1) ---

(defun* %derive-labeled-session-key (master-key master-salt session-id id-string)
    (function ((simple-array (unsigned-byte 8) (*))
               (simple-array (unsigned-byte 8) (*))
               (simple-array (unsigned-byte 8) (*))
               string)
              (simple-array (unsigned-byte 8) (32)))
  "Shared §9.5.3.3.4.2/.4.3 session-key KDF body, parameterized by the ID-STRING label:
     session_key = HMAC-SHA256(MASTER-KEY, ID-STRING || master_salt || session_id).
   The single construction behind BOTH derive-session-key (label 'SessionKey', the sender/common key,
   §9.5.3.3.4.2) AND derive-receiver-specific-session-key (label 'SessionReceiverKey', the origin-auth
   receiver key, §9.5.3.3.4.3, crypto/submessage.lisp) — so the framing is defined ONCE (DRY).
   MASTER-KEY/MASTER-SALT 32 octets, SESSION-ID 4 octets (caller validates length). Returns a fresh
   32-byte vector via dds.dare:hmac-sha256. NO trailing counter: this matches the conformant wire — Fast
   DDS compute_sessionkey AND Cyclone crypto_calculate_session_key both hash exactly id_string ‖
   master_salt ‖ session_id (corroborated CLEAN-ROOM; the operating contract §4 — the wire is the oracle;
   see docs/provenance.md, M7/P6 T-RECONCILE). SESSION-ID is spliced verbatim from the wire SecureDataHeader
   (Fast-DDS-faithful: its wire session_id == its KDF session_id bytes)."
  (let* ((id   (%ascii-octets id-string))
         (data (make-array (+ (length id) (length master-salt) (length session-id))
                           :element-type '(unsigned-byte 8)))
         (cur  (dds.core.buffer:cursor (dds.core.buffer:octet-buffer-over data) :endianness :little)))
    (dds.core.buffer:put-octets cur id 0 (length id))
    (dds.core.buffer:put-octets cur master-salt 0 (length master-salt))
    (dds.core.buffer:put-octets cur session-id 0 (length session-id))
    (dds.dare:hmac-sha256 master-key data)))

(defun* derive-session-key (master-key master-salt session-id)
    (function ((simple-array (unsigned-byte 8) (*))
               (simple-array (unsigned-byte 8) (*))
               (simple-array (unsigned-byte 8) (*)))
              (simple-array (unsigned-byte 8) (32)))
  "Derive the 32-byte AES-256 session key per DDS-Security 1.1 §9.5.3.3.4.2 (spike §3.1):
     session_key = HMAC-SHA256(master_sender_key,
                               'SessionKey' || master_salt || session_id).
   MASTER-KEY = master_sender_key (32 octets), MASTER-SALT = master_salt (32 octets),
   SESSION-ID = the 4-octet SecureDataHeader.session_id (spliced in verbatim).
   Uses HMAC-SHA256 (NOT HKDF-SHA384) per the spec; the MAC primitive is dds.dare:hmac-sha256.
   Delegates to the shared %derive-labeled-session-key with the 'SessionKey' label (DRY with the
   origin-auth receiver-key KDF). Returns a fresh 32-byte vector. Signals SECURED-PAYLOAD-MALFORMED for
   wrong-size inputs (fail-closed)."
  (%require-len master-key  32 "master_sender_key")
  (%require-len master-salt 32 "master_salt")
  (%require-len session-id   4 "session_id")
  (%derive-labeled-session-key master-key master-salt session-id +session-key-id-string+))
