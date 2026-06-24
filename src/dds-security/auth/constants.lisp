(in-package #:dds.security)

;;; DDS-Security 1.1 §8.7/§9.3 DDS:Auth:PKI-DH wire constants — class_id strings, algorithm
;;; identifier strings, HandshakeMessageToken binary-property NAME strings, IdentityToken
;;; string-property NAME strings, and MODP-2048 group parameters. NO logic; pure pinned constants.
;;; Every value cited from its OMG DDS-Security 1.1 §-clause; all corroborated against Fast DDS
;;; Apache-2.0 source (reading only, no code copied); provenance: spike
;;; docs/superpowers/spikes/2026-06-23-dds-security-auth-wire.md.

;;; --- class_id strings (§9.3.1 / §8.7.2 / §8.7.2.4) ---

(defconstant +auth-plugin-class-id+
    (if (boundp '+auth-plugin-class-id+)
        (symbol-value '+auth-plugin-class-id+)
        "DDS:Auth:PKI-DH:1.0")
  "IdentityToken class_id for DDS:Auth:PKI-DH (DDS-Security 1.1 §9.3.1 / §8.7.2).")

(defconstant +handshake-request-class-id+
    (if (boundp '+handshake-request-class-id+)
        (symbol-value '+handshake-request-class-id+)
        "DDS:Auth:PKI-DH:1.0+Req")
  "HandshakeRequestMessageToken class_id (DDS-Security 1.1 §9.3.2.1 / §8.7.2.4).")

(defconstant +handshake-reply-class-id+
    (if (boundp '+handshake-reply-class-id+)
        (symbol-value '+handshake-reply-class-id+)
        "DDS:Auth:PKI-DH:1.0+Reply")
  "HandshakeReplyMessageToken class_id (DDS-Security 1.1 §9.3.2.2 / §8.7.2.4).")

(defconstant +handshake-final-class-id+
    (if (boundp '+handshake-final-class-id+)
        (symbol-value '+handshake-final-class-id+)
        "DDS:Auth:PKI-DH:1.0+Final")
  "HandshakeFinalMessageToken class_id (DDS-Security 1.1 §9.3.2.3 / §8.7.2.4).")

;;; --- kagree_algo strings (§9.3 / §9.3.2) ---

(defconstant +kagree-algo-ecdh+
    (if (boundp '+kagree-algo-ecdh+)
        (symbol-value '+kagree-algo-ecdh+)
        "ECDH+prime256v1-CEUM")
  "kagree_algo for EC P-256 suite: ECDH ephemeral key agreement (DDS-Security 1.1 §9.3 / §9.3.2).")

(defconstant +kagree-algo-ffdh+
    (if (boundp '+kagree-algo-ffdh+)
        (symbol-value '+kagree-algo-ffdh+)
        "DH+MODP-2048-256")
  "kagree_algo for RSA/FFDH suite: DH over MODP-2048 (DDS-Security 1.1 §9.3 / §9.3.2 / RFC 3526 §3).")

;;; --- dsign_algo strings (§9.3 / §9.3.2) ---

(defconstant +dsign-algo-ecdsa+
    (if (boundp '+dsign-algo-ecdsa+)
        (symbol-value '+dsign-algo-ecdsa+)
        "ECDSA-SHA256")
  "dsign_algo for EC P-256 suite: ECDSA with SHA-256 (DDS-Security 1.1 §9.3 / §9.3.2).")

(defconstant +dsign-algo-rsa+
    (if (boundp '+dsign-algo-rsa+)
        (symbol-value '+dsign-algo-rsa+)
        "RSASSA-PSS-SHA256")
  "dsign_algo for RSA suite: RSASSA-PSS SHA-256 MGF1-SHA256 (DDS-Security 1.1 §9.3 / §9.3.2).")

;;; --- IdentityToken algorithm strings for dds.cert.algo / dds.ca.algo (§8.7.2.2 / §9.3.1) ---

(defconstant +token-algo-rsa+
    (if (boundp '+token-algo-rsa+)
        (symbol-value '+token-algo-rsa+)
        "RSA-2048")
  "dds.cert.algo / dds.ca.algo value for RSA-2048 certificates (DDS-Security 1.1 §8.7.2.2 / §9.3.1).")

(defconstant +token-algo-ec+
    (if (boundp '+token-algo-ec+)
        (symbol-value '+token-algo-ec+)
        "EC-prime256v1")
  "dds.cert.algo / dds.ca.algo value for EC P-256 certificates (DDS-Security 1.1 §8.7.2.2 / §9.3.1).")

;;; --- IdentityToken property NAMES (§8.7.2.2 / §9.3.1) — string Properties, not binary ---

(defconstant +id-token-prop-cert-sn+
    (if (boundp '+id-token-prop-cert-sn+)
        (symbol-value '+id-token-prop-cert-sn+)
        "dds.cert.sn")
  "IdentityToken property name for certificate Subject Name (DDS-Security 1.1 §8.7.2.2 / §9.3.1).")

(defconstant +id-token-prop-cert-algo+
    (if (boundp '+id-token-prop-cert-algo+)
        (symbol-value '+id-token-prop-cert-algo+)
        "dds.cert.algo")
  "IdentityToken property name for certificate algorithm (DDS-Security 1.1 §8.7.2.2 / §9.3.1).")

(defconstant +id-token-prop-ca-sn+
    (if (boundp '+id-token-prop-ca-sn+)
        (symbol-value '+id-token-prop-ca-sn+)
        "dds.ca.sn")
  "IdentityToken property name for Identity CA Subject Name (DDS-Security 1.1 §8.7.2.2 / §9.3.1).")

(defconstant +id-token-prop-ca-algo+
    (if (boundp '+id-token-prop-ca-algo+)
        (symbol-value '+id-token-prop-ca-algo+)
        "dds.ca.algo")
  "IdentityToken property name for Identity CA algorithm (DDS-Security 1.1 §8.7.2.2 / §9.3.1).")

;;; --- HandshakeMessageToken binary-property NAMES (§8.7.2.4 / §9.3.2) ---
;;; All HandshakeRequest/Reply/Final token entries are binary_properties (octets, not strings).

(defconstant +prop-c-id+
    (if (boundp '+prop-c-id+)
        (symbol-value '+prop-c-id+)
        "c.id")
  "HandshakeMessageToken binary-property name: DER identity certificate (DDS-Security 1.1 §9.3.2.1).")

(defconstant +prop-c-perm+
    (if (boundp '+prop-c-perm+)
        (symbol-value '+prop-c-perm+)
        "c.perm")
  "HandshakeMessageToken binary-property name: signed permissions document (DDS-Security 1.1 §9.3.2.1).")

(defconstant +prop-c-pdata+
    (if (boundp '+prop-c-pdata+)
        (symbol-value '+prop-c-pdata+)
        "c.pdata")
  "HandshakeMessageToken binary-property name: CDR ParticipantBuiltinTopicData (§9.3.2.1).")

(defconstant +prop-c-dsign-algo+
    (if (boundp '+prop-c-dsign-algo+)
        (symbol-value '+prop-c-dsign-algo+)
        "c.dsign_algo")
  "HandshakeMessageToken binary-property name: dsign_algo octets (DDS-Security 1.1 §9.3.2.1).")

(defconstant +prop-c-kagree-algo+
    (if (boundp '+prop-c-kagree-algo+)
        (symbol-value '+prop-c-kagree-algo+)
        "c.kagree_algo")
  "HandshakeMessageToken binary-property name: kagree_algo octets (DDS-Security 1.1 §9.3.2.1).")

(defconstant +prop-hash-c1+
    (if (boundp '+prop-hash-c1+)
        (symbol-value '+prop-hash-c1+)
        "hash_c1")
  "HandshakeMessageToken binary-property name: SHA-256 of initiator c.* properties (§9.3.2.1).")

(defconstant +prop-hash-c2+
    (if (boundp '+prop-hash-c2+)
        (symbol-value '+prop-hash-c2+)
        "hash_c2")
  "HandshakeMessageToken binary-property name: SHA-256 of responder c.* properties (§9.3.2.2).")

(defconstant +prop-dh1+
    (if (boundp '+prop-dh1+)
        (symbol-value '+prop-dh1+)
        "dh1")
  "HandshakeMessageToken binary-property name: initiator ephemeral DH/ECDH public key (§9.3.2.1).")

(defconstant +prop-dh2+
    (if (boundp '+prop-dh2+)
        (symbol-value '+prop-dh2+)
        "dh2")
  "HandshakeMessageToken binary-property name: responder ephemeral DH/ECDH public key (§9.3.2.2).")

(defconstant +prop-challenge1+
    (if (boundp '+prop-challenge1+)
        (symbol-value '+prop-challenge1+)
        "challenge1")
  "HandshakeMessageToken binary-property name: 32-byte initiator random nonce (§9.3.2.1).")

(defconstant +prop-challenge2+
    (if (boundp '+prop-challenge2+)
        (symbol-value '+prop-challenge2+)
        "challenge2")
  "HandshakeMessageToken binary-property name: 32-byte responder random nonce (§9.3.2.2).")

(defconstant +prop-signature+
    (if (boundp '+prop-signature+)
        (symbol-value '+prop-signature+)
        "signature")
  "HandshakeMessageToken binary-property name: digital signature (§9.3.2.2 Sign2 / §9.3.2.3 Sign1).")

;;; --- SharedSecret slot names (§9.3.3) ---

(defconstant +shared-secret-name+
    (if (boundp '+shared-secret-name+)
        (symbol-value '+shared-secret-name+)
        "SharedSecret")
  "SharedSecretHandle slot name for the 32-byte SHA-256(DH-agreed-value) secret (§9.3.3).")

(defconstant +shared-secret-challenge1-name+
    (if (boundp '+shared-secret-challenge1-name+)
        (symbol-value '+shared-secret-challenge1-name+)
        "Challenge1")
  "SharedSecretHandle slot name for the initiator challenge nonce (§9.3.3).")

(defconstant +shared-secret-challenge2-name+
    (if (boundp '+shared-secret-challenge2-name+)
        (symbol-value '+shared-secret-challenge2-name+)
        "Challenge2")
  "SharedSecretHandle slot name for the responder challenge nonce (§9.3.3).")

;;; --- Field widths ---

(defconstant +challenge-len+ 32
  "challenge1 / challenge2 nonce length in octets (DDS-Security 1.1 §9.3.2.1).")

(defconstant +hash-len+ 32
  "hash_c1 / hash_c2 / SharedSecret SHA-256 digest length in octets (§9.3.2 / §9.3.3).")

;;; --- RFC 3526 §3 MODP-2048 Group 14 parameters (DH+MODP-2048-256) ---
;;; Used when kagree_algo = +kagree-algo-ffdh+. Canonical big-endian 256-byte prime.
;;; Source: IETF RFC 3526 §3 (https://www.rfc-editor.org/rfc/rfc3526, Group 14).

(defparameter +modp-2048-g+
    (make-array 1 :element-type '(unsigned-byte 8) :initial-contents '(2))
  "RFC 3526 §3 MODP-2048 Group 14 generator g = 2 (1 octet, big-endian).")

(defparameter +modp-2048-p+
    (let ((hex
           ;; RFC 3526 §3 Group 14 prime (2048-bit, 256 octets big-endian)
           "FFFFFFFF FFFFFFFF C90FDAA2 2168C234 C4C6628B 80DC1CD1\
            29024E08 8A67CC74 020BBEA6 3B139B22 514A0879 8E3404DD\
            EF9519B3 CD3A431B 302B0A6D F25F1437 4FE1356D 6D51C245\
            E485B576 625E7EC6 F44C42E9 A637ED6B 0BFF5CB6 F406B7ED\
            EE386BFB 5A899FA5 AE9F2411 7C4B1FE6 49286651 ECE45B3D\
            C2007CB8 A163BF05 98DA4836 1C55D39A 69163FA8 FD24CF5F\
            83655D23 DCA3AD96 1C62F356 208552BB 9ED52907 7096966D\
            670C354E 4ABC9804 F1746C08 CA18217C 32905E46 2E36CE3B\
            E39E772C 180E8603 9B2783A2 EC07A28F B5C55DF0 6F4C52C9\
            DE2BCBF6 95581718 3995497C EA956AE5 15D22618 98FA0510\
            15728E5A 8AACAA68 FFFFFFFF FFFFFFFF"))
      (let* ((digits (remove #\space (remove #\newline hex)))
             (n (/ (length digits) 2))
             (v (make-array n :element-type '(unsigned-byte 8))))
        (dotimes (i n v)
          (setf (aref v i)
                (parse-integer digits :start (* i 2) :end (+ (* i 2) 2) :radix 16)))))
  "RFC 3526 §3 MODP-2048 Group 14 prime p (256 octets, big-endian).")

;;; --- Signature input sequence count (§9.3.2.2 / §9.3.2.3) ---

(defconstant +sig-input-property-count+ 6
  "Number of binary properties in the CDR-serialized BinaryPropertySeq fed to the signature
   (DDS-Security 1.1 §9.3.2.2 Sign2 / §9.3.2.3 Sign1 — exactly 6 properties in fixed order).")

;;; --- Test-PKI fixture paths (interop/security-auth/pki/; generated by gen-test-pki.sh) ---
;;; DDS_REPO_ROOT env var overrides; otherwise defaults to the ASDF system source root.

(defparameter +test-pki-root+
    (uiop:pathname-directory-pathname
     (merge-pathnames
      "interop/security-auth/pki/"
      (or (uiop:getenv "DDS_REPO_ROOT")
          (asdf:system-source-directory :dds-security))))
  "Root directory of the test-PKI fixture (interop/security-auth/pki/).")
