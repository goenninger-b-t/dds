(in-package #:dds.tests)

;;; DDS-Security 1.1 §8.7 Authentication plugin T1 tests: PKI identity load + IdentityToken.
;;; Tests: (a) validate-local-identity on EC fixture -> identity-handle; (b) identity-token
;;; byte-exact vs locked regression vector; (c) wrong-CA cert fails closed; (d) validate-remote-
;;; identity between two distinct-GUID handles returns :ok + consistent :requester/:replier role.
;;;
;;; IdentityToken regression vector derived from the committed T0 fixture cert
;;; (interop/security-auth/pki/participant_ec/identity_cert.pem) by running the CDR LE DataHolder
;;; serialization on 2026-06-23, re-locked 2026-06-24 after PKI regeneration (gen-test-pki.sh), and
;;; re-locked 2026-06-28 (WP-DDS-SECURITY-FASTDDS-INTEROP T1) to the §9.3.4-conformant Property form:
;;; name+value only, NO propagate byte on the wire (the flag is a LOCAL include/exclude filter, never
;;; serialized; the serialized count = the propagate==true Property count). Dropping the 4 propagate+pad
;;; fields takes the DataHolder from 240 to 224 octets. Subject CNs are deterministic so the
;;; serialization is byte-stable across regenerations.
;;; See the operating contract §5 (Definition of Done) for the derivation record.

;;; Locked byte-exact IdentityToken for the EC participant fixture cert.
;;; class_id="DDS:Auth:PKI-DH:1.0", dds.cert.sn="/CN=TestParticipantEC/O=DDS-Test/C=DE",
;;; dds.cert.algo="EC-prime256v1", dds.ca.sn="/CN=TestIdentityCA/O=DDS-Test/C=DE",
;;; dds.ca.algo="EC-prime256v1". CDR LE DataHolder, 224 bytes (§9.3.4: name+value Properties, no propagate).
(defparameter +ec-identity-token-vector+
    (make-array 224 :element-type '(unsigned-byte 8) :initial-contents
     '(20 0 0 0 68 68 83 58 65 117 116 104 58 80 75 73 45 68 72 58 49 46 48 0   ; class_id
       4 0 0 0                                                                    ; prop count=4
       12 0 0 0 100 100 115 46 99 101 114 116 46 115 110 0                       ; "dds.cert.sn"
       38 0 0 0 47 67 78 61 84 101 115 116 80 97 114 116 105 99 105 112 97 110   ; "/CN=TestParticipantEC
       116 69 67 47 79 61 68 68 83 45 84 101 115 116 47 67 61 68 69 0 0 0        ;  /O=DDS-Test/C=DE"
       14 0 0 0 100 100 115 46 99 101 114 116 46 97 108 103 111 0 0 0            ; "dds.cert.algo"
       14 0 0 0 69 67 45 112 114 105 109 101 50 53 54 118 49 0 0 0               ; "EC-prime256v1"
       10 0 0 0 100 100 115 46 99 97 46 115 110 0 0 0                            ; "dds.ca.sn"
       35 0 0 0 47 67 78 61 84 101 115 116 73 100 101 110 116 105 116 121 67 65  ; "/CN=TestIdentityCA
       47 79 61 68 68 83 45 84 101 115 116 47 67 61 68 69 0 0                    ;  /O=DDS-Test/C=DE"
       12 0 0 0 100 100 115 46 99 97 46 97 108 103 111 0                         ; "dds.ca.algo"
       14 0 0 0 69 67 45 112 114 105 109 101 50 53 54 118 49 0 0 0               ; "EC-prime256v1"
       0 0 0 0))                                                                  ; binary_properties count=0
  "Locked byte-exact IdentityToken for the T0 EC participant fixture cert (224 octets, CDR LE; §9.3.4 name+value Properties, no propagate byte).")

(defun* %read-fixture-pem (relative-path)
    (function (string) (simple-array (unsigned-byte 8) (*)))
  "Read a PKI fixture PEM file relative to the test-PKI root and return its bytes."
  (let* ((path (merge-pathnames relative-path dds.security:+test-pki-root+)))
    (with-open-file (s path :element-type '(unsigned-byte 8))
      (let* ((n (file-length s))
             (v (make-array n :element-type '(unsigned-byte 8))))
        (read-sequence v s)
        v))))

(defun* run-auth-identity-test ()
    (function () t)
  "DDS-Security §8.7 Auth T1: PKI identity load + IdentityToken byte-exactness.
   (a) validate-local-identity on EC fixture -> identity-handle (not nil).
   (b) identity-token equals the locked 224-byte regression vector (byte-exact; §9.3.4 no propagate).
   (c) wrong-CA cert with the test CA -> (values nil reason) (chain-verify fail-closed).
   (d) validate-remote-identity between two distinct-GUID handles -> :ok + :requester/:replier.
   Requires OpenSSL >= 3.5; skips gracefully if absent. Both SBCL and Clasp must pass."
  (handler-case (dds.dare:dare-available-p)
    (dds.dare:dare-unavailable (c)
      (format t "~&  [auth-identity] SKIP — OpenSSL >= 3.5 not available: ~a~%"
              (dds.dare:dare-unavailable-reason c))
      (return-from run-auth-identity-test t)))

  (let* ((ca-pem       (%read-fixture-pem "ca/ca-cert.pem"))
         (ec-cert-pem  (%read-fixture-pem "participant_ec/identity_cert.pem"))
         (ec-key-pem   (%read-fixture-pem "participant_ec/identity_key.pem"))
         (wrong-cert-pem (%read-fixture-pem "wrong_ca/wrong-identity-cert.pem"))
         (guid-a       (make-array 16 :element-type '(unsigned-byte 8)
                                      :initial-contents '(1 2 3 4 5 6 7 8 9 10 11 12 13 14 15 16)))
         (guid-b       (make-array 16 :element-type '(unsigned-byte 8)
                                      :initial-contents '(200 2 3 4 5 6 7 8 9 10 11 12 13 14 15 16))))

    ;; (a) validate-local-identity on EC fixture must return an identity-handle
    (multiple-value-bind (handle reason)
        (dds.security:validate-local-identity ca-pem ec-cert-pem ec-key-pem guid-a)
      (%check :auth-local-identity-ok (not (null handle))
              (format nil "validate-local-identity returned nil; reason: ~a" reason))

      (unwind-protect
           (progn
             ;; (b) identity-token must be byte-exact vs the locked regression vector
             (let ((tok (dds.security:identity-token handle)))
               (%check :auth-token-non-empty (> (length tok) 0)
                       "identity-token returned empty vector")
               (%check :auth-token-length (= (length tok) 224)
                       (format nil "identity-token length ~d != 224" (length tok)))
               (%check :auth-token-byte-exact (equalp tok +ec-identity-token-vector+)
                       (format nil "identity-token byte mismatch; first 20 bytes: ~{~d ~}"
                               (coerce (subseq tok 0 (min 20 (length tok))) 'list))))

             ;; (c) wrong-CA cert must fail chain-verify (fail-closed)
             (multiple-value-bind (bad-handle bad-reason)
                 (dds.security:validate-local-identity ca-pem wrong-cert-pem ec-key-pem guid-b)
               (%check :auth-wrong-ca-rejected (null bad-handle)
                       "wrong-CA cert must not produce a valid identity-handle")
               (%check :auth-wrong-ca-reason (not (null bad-reason))
                       "wrong-CA rejection must include a reason string")
               (when bad-handle (dds.security:free-identity-handle bad-handle)))

             ;; (d) validate-remote-identity: use handle as local + the IdentityToken of a second handle.
             ;; Verdict must be :ok and the role deterministic. NOTE: this role is the T1 NON-AUTHORITATIVE
             ;; stand-in (the IdentityToken carries no GUID; the real §8.7.2.4 role is decided by the auth
             ;; manager on the real RTPS prefixes, %prefix-lex<). Since validate-local-identity now stores
             ;; the §9.3.2.1 adjusted GUID (octet 0 has bit-0 set, so >= 0x80) and the remote stand-in GUID
             ;; is the cert subject-name string (X509_NAME_oneline, leading '/' = 0x2F), the local GUID
             ;; sorts ABOVE the remote stand-in => :replier (deterministic).
             (multiple-value-bind (handle-b reason-b)
                 (dds.security:validate-local-identity ca-pem ec-cert-pem ec-key-pem guid-b)
               (%check :auth-second-handle-ok (not (null handle-b))
                       (format nil "second validate-local-identity failed: ~a" reason-b))
               (unwind-protect
                    (let ((remote-tok (dds.security:identity-token handle-b)))
                      (multiple-value-bind (verdict role reason-r)
                          (dds.security:validate-remote-identity handle remote-tok)
                        (%check :auth-remote-verdict (eq verdict :ok)
                                (format nil "validate-remote-identity verdict ~a; reason: ~a"
                                        verdict reason-r))
                        (%check :auth-remote-role-valid (member role '(:requester :replier))
                                (format nil "validate-remote-identity role ~a not :requester/:replier" role))
                        ;; §9.3.2.1 adjusted local GUID (octet 0 >= 0x80) sorts above the cert-sn stand-in
                        ;; (leading '/' = 0x2F) => :replier; deterministic (the auth manager decides the
                        ;; authoritative role on the real RTPS prefixes, not this stand-in).
                        (%check :auth-remote-role-correct (eq role :replier)
                                (format nil "adjusted local GUID (>=0x80) sorts above cert-sn stand-in; expected :replier, got ~a" role))))
                 (dds.security:free-identity-handle handle-b))))
        (dds.security:free-identity-handle handle))))

  t)

(defun* run-auth-sha256-kat ()
    (function () t)
  "SHA-256 NIST known-answer test: SHA-256('') = e3b0c44298fc1c14... (NIST FIPS 180-4 §6.2).
   Verifies dds.dare:sha-256 against the NIST FIPS 180-4 empty-string test vector. Both impls must pass."
  (handler-case (dds.dare:dare-available-p)
    (dds.dare:dare-unavailable (c)
      (format t "~&  [sha256-kat] SKIP: ~a~%" (dds.dare:dare-unavailable-reason c))
      (return-from run-auth-sha256-kat t)))
  (let* ((empty    (make-array 0 :element-type '(unsigned-byte 8)))
         (result   (dds.dare:sha-256 empty))
         (expected #(#xe3 #xb0 #xc4 #x42 #x98 #xfc #x1c #x14
                     #x9a #xfb #xf4 #xc8 #x99 #x6f #xb9 #x24
                     #x27 #xae #x41 #xe4 #x64 #x9b #x93 #x4c
                     #xa4 #x95 #x99 #x1b #x78 #x52 #xb8 #x55)))
    (%check :sha256-kat-len (= (length result) 32)
            (format nil "SHA-256 output length ~d != 32" (length result)))
    (%check :sha256-kat-val (equalp result expected)
            (format nil "SHA-256('') mismatch; got ~{~2,'0x~}" (coerce result 'list))))
  t)

(defun* run-auth-ecdsa-kat ()
    (function () t)
  "Published-vector KATs for ECDH P-256 and ECDSA-SHA256 using ec-p256-import-private/public.
   ECDH KAT: RFC 5903 §8.1 (Group 19 / P-256, IKEv2 ECDH test vectors, IETF 2007).
     Vectors: i (initiator private, BE), r (responder private, BE);
     g^i = 04||gix||giy, g^r = 04||grx||gry (uncompressed public points);
     g^ir = shared-secret x-coordinate (32 bytes). Source: https://www.rfc-editor.org/rfc/rfc5903.txt
   ECDSA KAT: RFC 6979 §A.2.5 (P-256 / SHA-256, message 'sample', deterministic ECDSA).
     Vectors: Ux, Uy (public key); message = ASCII 'sample'; r, s (DER-encoded ECDSA-Sig-Value).
     Source: https://www.rfc-editor.org/rfc/rfc6979.txt §A.2.5
     ecdsa-verify takes the raw message and hashes SHA-256 internally (EVP_DigestVerify).
   Both SBCL and Clasp must pass."
  (handler-case (dds.dare:dare-available-p)
    (dds.dare:dare-unavailable (c)
      (format t "~&  [ecdsa-kat] SKIP: ~a~%" (dds.dare:dare-unavailable-reason c))
      (return-from run-auth-ecdsa-kat t)))

  ;;; --- RFC 5903 §8.1 ECDH KAT (Group 19, P-256) ---
  ;; Initiator private key i (big-endian, 32 bytes) — RFC 5903 §8.1
  (let* ((da-scalar #(#xc8 #x8f #x01 #xf5 #x10 #xd9 #xac #x3f
                      #x70 #xa2 #x92 #xda #xa2 #x31 #x6d #xe5
                      #x44 #xe9 #xaa #xb8 #xaf #xe8 #x40 #x49
                      #xc6 #x2a #x9c #x57 #x86 #x2d #x14 #x33))
         ;; g^i = 04||gix||giy (uncompressed) — RFC 5903 §8.1
         ;; gix: DAD0B653 94221CF9 B051E1FE CA5787D0 98DFE637 FC90B9EF 945D0C37 72581180
         ;; giy: 5271A046 1CDB8252 D61F1C45 6FA3E59A B1F45B33 ACCF5F58 389E0577 B8990BB3
         (pub-a-point #(#x04
                        #xda #xd0 #xb6 #x53 #x94 #x22 #x1c #xf9
                        #xb0 #x51 #xe1 #xfe #xca #x57 #x87 #xd0
                        #x98 #xdf #xe6 #x37 #xfc #x90 #xb9 #xef
                        #x94 #x5d #x0c #x37 #x72 #x58 #x11 #x80
                        #x52 #x71 #xa0 #x46 #x1c #xdb #x82 #x52
                        #xd6 #x1f #x1c #x45 #x6f #xa3 #xe5 #x9a
                        #xb1 #xf4 #x5b #x33 #xac #xcf #x5f #x58
                        #x38 #x9e #x05 #x77 #xb8 #x99 #x0b #xb3))
         ;; Responder private key r (big-endian, 32 bytes) — RFC 5903 §8.1
         (db-scalar #(#xc6 #xef #x9c #x5d #x78 #xae #x01 #x2a
                      #x01 #x11 #x64 #xac #xb3 #x97 #xce #x20
                      #x88 #x68 #x5d #x8f #x06 #xbf #x9b #xe0
                      #xb2 #x83 #xab #x46 #x47 #x6b #xee #x53))
         ;; g^r = 04||grx||gry (uncompressed) — RFC 5903 §8.1
         ;; grx: D12DFB52 89C8D4F8 1208B702 70398C34 2296970A 0BCCB74C 736FC755 4494BF63
         ;; gry: 56FBF3CA 366CC23E 8157854C 13C58D6A AC23F046 ADA30F83 53E74F33 039872AB
         (pub-b-point #(#x04
                        #xd1 #x2d #xfb #x52 #x89 #xc8 #xd4 #xf8
                        #x12 #x08 #xb7 #x02 #x70 #x39 #x8c #x34
                        #x22 #x96 #x97 #x0a #x0b #xcc #xb7 #x4c
                        #x73 #x6f #xc7 #x55 #x44 #x94 #xbf #x63
                        #x56 #xfb #xf3 #xca #x36 #x6c #xc2 #x3e
                        #x81 #x57 #x85 #x4c #x13 #xc5 #x8d #x6a
                        #xac #x23 #xf0 #x46 #xad #xa3 #x0f #x83
                        #x53 #xe7 #x4f #x33 #x03 #x98 #x72 #xab))
         ;; SPKI DER for g^i (91 bytes, SubjectPublicKeyInfo — ecdh-compute peer argument format)
         (spki-a #(#x30 #x59 #x30 #x13 #x06 #x07 #x2a #x86 #x48 #xce #x3d #x02 #x01
                   #x06 #x08 #x2a #x86 #x48 #xce #x3d #x03 #x01 #x07 #x03 #x42 #x00 #x04
                   #xda #xd0 #xb6 #x53 #x94 #x22 #x1c #xf9 #xb0 #x51 #xe1 #xfe #xca #x57
                   #x87 #xd0 #x98 #xdf #xe6 #x37 #xfc #x90 #xb9 #xef #x94 #x5d #x0c #x37
                   #x72 #x58 #x11 #x80 #x52 #x71 #xa0 #x46 #x1c #xdb #x82 #x52 #xd6 #x1f
                   #x1c #x45 #x6f #xa3 #xe5 #x9a #xb1 #xf4 #x5b #x33 #xac #xcf #x5f #x58
                   #x38 #x9e #x05 #x77 #xb8 #x99 #x0b #xb3))
         ;; SPKI DER for g^r (91 bytes)
         (spki-b #(#x30 #x59 #x30 #x13 #x06 #x07 #x2a #x86 #x48 #xce #x3d #x02 #x01
                   #x06 #x08 #x2a #x86 #x48 #xce #x3d #x03 #x01 #x07 #x03 #x42 #x00 #x04
                   #xd1 #x2d #xfb #x52 #x89 #xc8 #xd4 #xf8 #x12 #x08 #xb7 #x02 #x70 #x39
                   #x8c #x34 #x22 #x96 #x97 #x0a #x0b #xcc #xb7 #x4c #x73 #x6f #xc7 #x55
                   #x44 #x94 #xbf #x63 #x56 #xfb #xf3 #xca #x36 #x6c #xc2 #x3e #x81 #x57
                   #x85 #x4c #x13 #xc5 #x8d #x6a #xac #x23 #xf0 #x46 #xad #xa3 #x0f #x83
                   #x53 #xe7 #x4f #x33 #x03 #x98 #x72 #xab))
         ;; g^ir x-coordinate (32 bytes) — RFC 5903 §8.1
         ;; D6840F6B 42F6EDAF D13116E0 E1256520 2FEF8E9E CE7DCE03 812464D0 4B9442DE
         (z-expected #(#xd6 #x84 #x0f #x6b #x42 #xf6 #xed #xaf
                       #xd1 #x31 #x16 #xe0 #xe1 #x25 #x65 #x20
                       #x2f #xef #x8e #x9e #xce #x7d #xce #x03
                       #x81 #x24 #x64 #xd0 #x4b #x94 #x42 #xde)))
    (let ((priv-a (dds.dare:ec-p256-import-private
                   (coerce da-scalar '(simple-array (unsigned-byte 8) (*)))
                   (coerce pub-a-point '(simple-array (unsigned-byte 8) (*)))))
          (priv-b (dds.dare:ec-p256-import-private
                   (coerce db-scalar '(simple-array (unsigned-byte 8) (*)))
                   (coerce pub-b-point '(simple-array (unsigned-byte 8) (*))))))
      (unwind-protect
           (progn
             (let ((z-ab (dds.dare:ecdh-compute
                          priv-a (coerce spki-b '(simple-array (unsigned-byte 8) (*)))))
                   (z-ba (dds.dare:ecdh-compute
                          priv-b (coerce spki-a '(simple-array (unsigned-byte 8) (*))))))
               (%check :ecdh-rfc5903-ab (equalp z-ab (coerce z-expected '(simple-array (unsigned-byte 8) (*))))
                       (format nil "ECDH RFC 5903 §8.1: i*g^r mismatch; got ~{~2,'0x~}"
                               (coerce z-ab 'list)))
               (%check :ecdh-rfc5903-ba (equalp z-ba (coerce z-expected '(simple-array (unsigned-byte 8) (*))))
                       (format nil "ECDH RFC 5903 §8.1: r*g^i mismatch; got ~{~2,'0x~}"
                               (coerce z-ba 'list)))))
        (dds.dare:pkey-free priv-a)
        (dds.dare:pkey-free priv-b))))

  ;;; --- RFC 6979 §A.2.5 ECDSA-P256/SHA-256 KAT ---
  ;; Source: RFC 6979 §A.2.5, P-256, SHA-256, message = ASCII "sample".
  ;; https://www.rfc-editor.org/rfc/rfc6979.txt §A.2.5
  ;; Ux: 60FED4BA 255A9D31 C961EB74 C6356D68 C049B892 3B61FA6C E669622E 60F29FB6
  ;; Uy: 7903FE10 08B8BC99 A41AE9E9 5628BC64 F2F1B20C 2D7E9F51 77A3C294 D4462299
  ;; r:  EFD48B2A ACB6A8FD 1140DD9C D45E81D6 9D2C877B 56AAF991 C34D0EA8 4EAF3716
  ;; s:  F7CB1C94 2D657C41 D436C7A1 B6E29F65 F3E900DB B9AFF406 4DC4AB2F 843ACDA8
  ;; DER: SEQUENCE { INTEGER(00||r), INTEGER(00||s) } = 30 46 02 21 00 <r> 02 21 00 <s>
  ;; ecdsa-verify(pub, data, der-sig) — hashes SHA-256 internally via EVP_DigestVerify.
  (let* ((rfc6979-pub-point
          (coerce #(#x04
                    ;; Ux
                    #x60 #xfe #xd4 #xba #x25 #x5a #x9d #x31
                    #xc9 #x61 #xeb #x74 #xc6 #x35 #x6d #x68
                    #xc0 #x49 #xb8 #x92 #x3b #x61 #xfa #x6c
                    #xe6 #x69 #x62 #x2e #x60 #xf2 #x9f #xb6
                    ;; Uy
                    #x79 #x03 #xfe #x10 #x08 #xb8 #xbc #x99
                    #xa4 #x1a #xe9 #xe9 #x56 #x28 #xbc #x64
                    #xf2 #xf1 #xb2 #x0c #x2d #x7e #x9f #x51
                    #x77 #xa3 #xc2 #x94 #xd4 #x46 #x22 #x99)
                  '(simple-array (unsigned-byte 8) (*))))
         ;; message = ASCII "sample" (6 bytes) — ecdsa-verify hashes SHA-256 internally
         (rfc6979-msg
          (coerce #(#x73 #x61 #x6d #x70 #x6c #x65)
                  '(simple-array (unsigned-byte 8) (*))))
         ;; DER ECDSA-Sig-Value: 30 46 02 21 00 <r-32> 02 21 00 <s-32> (72 bytes total)
         ;; r and s each have high bit set, so both take 02 21 00 <32 bytes> encoding.
         (rfc6979-sig-valid
          (coerce #(#x30 #x46
                    #x02 #x21 #x00
                    ;; r: EFD48B2AACB6A8FD1140DD9CD45E81D69D2C877B56AAF991C34D0EA84EAF3716
                    #xef #xd4 #x8b #x2a #xac #xb6 #xa8 #xfd
                    #x11 #x40 #xdd #x9c #xd4 #x5e #x81 #xd6
                    #x9d #x2c #x87 #x7b #x56 #xaa #xf9 #x91
                    #xc3 #x4d #x0e #xa8 #x4e #xaf #x37 #x16
                    #x02 #x21 #x00
                    ;; s: F7CB1C942D657C41D436C7A1B6E29F65F3E900DBB9AFF4064DC4AB2F843ACDA8
                    #xf7 #xcb #x1c #x94 #x2d #x65 #x7c #x41
                    #xd4 #x36 #xc7 #xa1 #xb6 #xe2 #x9f #x65
                    #xf3 #xe9 #x00 #xdb #xb9 #xaf #xf4 #x06
                    #x4d #xc4 #xab #x2f #x84 #x3a #xcd #xa8)
                  '(simple-array (unsigned-byte 8) (*))))
         ;; invalid sig: SEQUENCE{INTEGER(1),INTEGER(1)} — structurally valid DER, wrong values
         (rfc6979-sig-invalid
          (coerce #(#x30 #x06 #x02 #x01 #x01 #x02 #x01 #x01)
                  '(simple-array (unsigned-byte 8) (*))))
         (pub-handle (dds.dare:ec-p256-import-public rfc6979-pub-point)))
    (unwind-protect
         (progn
           (%check :ecdsa-rfc6979-valid
                   (dds.dare:ecdsa-verify pub-handle rfc6979-msg rfc6979-sig-valid)
                   "ECDSA RFC 6979 §A.2.5 P-256/SHA-256 'sample': valid sig not verified")
           (%check :ecdsa-rfc6979-invalid
                   (not (dds.dare:ecdsa-verify pub-handle rfc6979-msg rfc6979-sig-invalid))
                   "ECDSA RFC 6979 §A.2.5: invalid sig (R=S=1) must return NIL"))
      (dds.dare:pkey-free pub-handle)))
  t)

;;; T3: FFDH MODP-2048 + RSA-PSS-SHA256 KATs and full RSA handshake test.

(defun* run-auth-rsa-pss-kat ()
    (function () t)
  "Wycheproof RSASSA-PSS-SHA256 known-answer test (saltlen=32, MGF1-SHA256, RSA-2048).
   Source: Google Wycheproof rsa_pss_2048_sha256_mgf1_32_test.json, fetched 2026-06-24
           URL: https://raw.githubusercontent.com/google/wycheproof/master/testvectors_v1/
                rsa_pss_2048_sha256_mgf1_32_test.json
   tcId=1: msg='' (empty), valid signature.
   tcId=62: msg=313233343030, invalid signature (wrong salt / tampered).
   Key: RSA-2048 public key (n, e=010001) from Wycheproof test group 1.
   Both SBCL and Clasp must pass."
  (handler-case (dds.dare:dare-available-p)
    (dds.dare:dare-unavailable (c)
      (format t "~&  [rsa-pss-kat] SKIP: ~a~%" (dds.dare:dare-unavailable-reason c))
      (return-from run-auth-rsa-pss-kat t)))

  ;; SubjectPublicKeyInfo DER for Wycheproof testGroups[0].key (RSA-2048, e=65537).
  ;; Derived from the JSON key's n/e via Python cryptography library (SubjectPublicKeyInfo, 294 bytes).
  ;; Imported via d2i_PUBKEY (same SPKI path used by ffdh-gen-keypair round-trip).
  (let* (
         ;; tcId=1: msg="" (empty octet vector), valid signature
         ;; Wycheproof rsa_pss_2048_sha256_mgf1_32_test.json tcId=1, result="valid"
         (msg-1 (make-array 0 :element-type '(unsigned-byte 8)))
         (sig-1
          (coerce #(#x4f #x01 #xe0 #xc1 #x2b #x08 #x62 #x5e #xca #xc8 #x9a #x69 #x23 #x19 #x06
                    #xed #xf8 #x26 #x38 #x0f #x37 #xc9 #x59 #xa9 #x66 #x90 #xd0 #x46 #x31 #x6d
                    #x68 #xff #xce #x9d #x5c #x47 #x16 #x94 #xfc #xeb #xfc #x6b #x45 #x53 #x48
                    #x64 #x68 #x92 #x56 #xe4 #xfc #x81 #xc7 #x8e #x58 #x3f #x67 #x5d #x0c #x94
                    #xb4 #x49 #x64 #x74 #x51 #xe8 #x1b #xef #xf0 #x1a #x11 #xa5 #x16 #xd5 #xe5
                    #xce #x3f #x1a #x91 #x04 #x37 #xcb #x8a #x3a #x50 #x96 #xb1 #x9f #xb1 #x5f
                    #x45 #x24 #xa3 #x5b #x23 #xd8 #x9c #xdb #xa1 #x2c #xf5 #xb7 #x1a #xac #x10
                    #x47 #xb2 #x8c #x56 #x2d #xf7 #xc5 #x54 #x2c #x34 #xce #x23 #xa1 #x82 #xcf
                    #x7e #x0e #x23 #x19 #x34 #xb1 #x72 #x94 #x79 #x9d #x44 #x87 #x7a #x1d #x68
                    #xef #x1b #x8f #x07 #x36 #x19 #xb7 #x61 #x8e #x6b #x7c #x22 #xdb #x20 #x03
                    #x0d #x98 #xcf #x59 #x1f #xfc #x3d #x4d #xa5 #xf5 #x86 #x13 #xec #xd5 #xec
                    #xfc #x3b #x40 #xa1 #xd0 #x2f #x40 #x89 #x1c #xa4 #x36 #x95 #xcd #x4c #x08
                    #x8b #x05 #xa8 #x05 #x4c #x89 #xc5 #x95 #xa4 #x7e #x27 #x48 #x16 #xf3 #x53
                    #x84 #x22 #x6f #x74 #x45 #x9e #xe6 #x3e #x25 #xa1 #xbf #xc0 #x3c #x36 #x04
                    #x90 #x55 #x2e #xc3 #x83 #x43 #xf8 #xac #xe5 #x02 #xf0 #x65 #x30 #x3b #x00
                    #xbc #x0e #xc3 #x20 #x71 #x1b #x21 #x1f #xde #x92 #xe5 #x7f #xeb #x90 #x13
                    #xc3 #x60 #x93 #x42 #x49 #x5e #xc0 #xd7 #xca #xbd #xec #x21 #xe5 #x4a #xcc
                    #x38)
                  '(simple-array (unsigned-byte 8) (*))))
         ;; tcId=62: msg=313233343030, invalid signature
         ;; Wycheproof rsa_pss_2048_sha256_mgf1_32_test.json tcId=62, result="invalid"
         (msg-62
          (coerce #(#x31 #x32 #x33 #x34 #x30 #x30)
                  '(simple-array (unsigned-byte 8) (*))))
         (sig-62
          (coerce #(#x67 #xd1 #xd1 #xc0 #xa3 #x98 #x14 #x86 #x25 #x31 #x7c #x3f #x5e #x44 #xb7
                    #x38 #xbd #xf4 #x61 #xc2 #x7a #x59 #x59 #x4b #x39 #xeb #xb2 #xae #xbe #xf2
                    #x33 #xc7 #x80 #x93 #x79 #xe5 #x44 #x11 #x41 #x1b #x82 #xd2 #xe7 #xac #x88
                    #xf9 #x89 #xb5 #x83 #x73 #xd5 #x32 #xc7 #x58 #xba #xea #x12 #x18 #x78 #xce
                    #x97 #x59 #x44 #x17 #x38 #xd1 #x21 #x88 #x1c #x1f #xa2 #xd0 #x44 #x21 #xf0
                    #x2d #xd5 #x65 #xb1 #x27 #x70 #xd8 #x44 #x61 #x1e #xd1 #x87 #x3a #x0b #x64
                    #xd8 #x22 #x70 #x9a #x6b #x78 #xd6 #xd3 #x89 #x2b #x29 #x44 #x04 #xbc #xe6
                    #x71 #x10 #x01 #xd6 #xc3 #xa5 #x45 #x46 #xc7 #x6a #x1d #x17 #x81 #x96 #x74
                    #xb0 #xbe #x90 #x44 #x97 #xa2 #x33 #xb4 #x66 #xfe #x4b #xec #xc8 #x32 #xde
                    #xe7 #x40 #xf9 #xab #x79 #xe5 #xb9 #xf5 #xdb #x0b #x0f #x9a #xac #x00 #x84
                    #xba #x05 #xce #xbf #x42 #x30 #x3b #x5c #xa2 #xad #x95 #xe3 #xd6 #x1b #x29
                    #xed #x64 #x75 #x54 #x5c #x02 #xe9 #x3e #x7b #x0e #x11 #x8a #xf9 #x2f #x5c
                    #xdd #xb1 #xfa #xeb #x2c #xbc #x23 #xc9 #xe6 #x9c #x12 #x0e #x29 #xdf #x7f
                    #xe3 #x19 #x91 #xe8 #x87 #xb3 #xb2 #x9e #x77 #x68 #x8c #x60 #xe8 #x0b #xe6
                    #x5c #xcc #xf3 #xd7 #x86 #x1a #x7a #x14 #xc3 #x9e #x6a #x6e #x56 #x45 #x56
                    #x8e #x2c #xc5 #xe4 #xa1 #x7b #x75 #xdb #x1d #xd4 #x15 #xaa #xdb #x45 #xe1
                    #x12 #xa9 #xb5 #x82 #xb2 #xff #x6e #x82 #xa4 #x3d #x7a #x73 #x47 #xb7 #xb5
                    #x6d)
                  '(simple-array (unsigned-byte 8) (*))))
         ;; Import RSA-2048 public key via SubjectPublicKeyInfo DER + d2i_PUBKEY
         ;; DER derived from Wycheproof testGroups[0].key (n,e above); generated with Python
         ;; cryptography v42 (SubjectPublicKeyInfo, RSA-2048 PKCS#1, 294 bytes).
         ;; d2i_PUBKEY is the same path used by ffdh-gen-keypair SPKI round-trip.
         (pub-der-bytes
          (coerce #(#x30 #x82 #x01 #x22 #x30 #x0d #x06 #x09 #x2a #x86 #x48 #x86 #xf7 #x0d #x01
                    #x01 #x01 #x05 #x00 #x03 #x82 #x01 #x0f #x00 #x30 #x82 #x01 #x0a #x02 #x82
                    #x01 #x01 #x00 #xa2 #xb4 #x51 #xa0 #x7d #x0a #xa5 #xf9 #x6e #x45 #x56 #x71
                    #x51 #x35 #x50 #x51 #x4a #x8a #x5b #x46 #x2e #xbe #xf7 #x17 #x09 #x4f #xa1
                    #xfe #xe8 #x22 #x24 #xe6 #x37 #xf9 #x74 #x6d #x3f #x7c #xaf #xd3 #x18 #x78
                    #xd8 #x03 #x25 #xb6 #xef #x5a #x17 #x00 #xf6 #x59 #x03 #xb4 #x69 #x42 #x9e
                    #x89 #xd6 #xea #xc8 #x84 #x50 #x97 #xb5 #xab #x39 #x31 #x89 #xdb #x92 #x51
                    #x2e #xd8 #xa7 #x71 #x1a #x12 #x53 #xfa #xcd #x20 #xf7 #x9c #x15 #xe8 #x24
                    #x7f #x3d #x3e #x42 #xe4 #x6e #x48 #xc9 #x8e #x25 #x4a #x2f #xe9 #x76 #x53
                    #x13 #xa0 #x3e #xff #x8f #x17 #xe1 #xa0 #x29 #x39 #x7a #x1f #xa2 #x6a #x8d
                    #xce #x26 #xf4 #x90 #xed #x81 #x29 #x96 #x15 #xd9 #x81 #x4c #x22 #xda #x61
                    #x04 #x28 #xe0 #x9c #x7d #x96 #x58 #x59 #x42 #x66 #xf5 #xc0 #x21 #xd0 #xfc
                    #xec #xa0 #x8d #x94 #x5a #x12 #xbe #x82 #xde #x4d #x1e #xce #x6b #x4c #x03
                    #x14 #x5b #x5d #x34 #x95 #xd4 #xed #x54 #x11 #xeb #x87 #x8d #xaf #x05 #xfd
                    #x7a #xfc #x3e #x09 #xad #xa0 #xf1 #x12 #x64 #x22 #xf5 #x90 #x97 #x5a #x19
                    #x69 #x81 #x6f #x48 #x69 #x8b #xcb #xba #x1b #x4d #x9c #xae #x79 #xd4 #x60
                    #xd8 #xf9 #xf8 #x5e #x79 #x75 #x00 #x5d #x9b #xc2 #x2c #x4e #x5a #xc0 #xf7
                    #xc1 #xa4 #x5d #x12 #x56 #x9a #x62 #x80 #x7d #x3b #x9a #x02 #xe5 #xa5 #x30
                    #xe7 #x73 #x06 #x6f #x45 #x3d #x1f #x5b #x4c #x2e #x9c #xf7 #x82 #x02 #x83
                    #xf7 #x42 #xb9 #xd5 #x02 #x03 #x01 #x00 #x01)
                  '(simple-array (unsigned-byte 8) (*))))
         (pub-handle (let ((n (length pub-der-bytes)))
                       (cffi:with-foreign-pointer (der-ptr n)
                         (dotimes (i n)
                           (setf (cffi:mem-aref der-ptr :uint8 i) (aref pub-der-bytes i)))
                         (cffi:with-foreign-pointer (pp (cffi:foreign-type-size :pointer))
                           (setf (cffi:mem-ref pp :pointer) der-ptr)
                           (let ((pkey (cffi:foreign-funcall-pointer (dds.dare::%ossl-sym "d2i_PUBKEY") nil
                                                                      :pointer (cffi:null-pointer)
                                                                      :pointer pp
                                                                      :long n
                                                                      :pointer)))
                             (if (cffi:null-pointer-p pkey)
                                 (error "RSA-PSS KAT: d2i_PUBKEY failed")
                                 pkey)))))))
    (unwind-protect
         (progn
           (%check :rsa-pss-kat-pub-ok (not (cffi:null-pointer-p pub-handle))
                   "RSA-PSS KAT: public key import failed")
           ;; tcId=1: valid signature on empty message
           (%check :rsa-pss-kat-valid
                   (dds.dare:rsa-pss-verify pub-handle msg-1 sig-1)
                   "RSA-PSS KAT: Wycheproof tcId=1 (empty msg, valid sig) not verified")
           ;; tcId=62: invalid signature
           (%check :rsa-pss-kat-invalid
                   (not (dds.dare:rsa-pss-verify pub-handle msg-62 sig-62))
                   "RSA-PSS KAT: Wycheproof tcId=62 (invalid sig) must return NIL"))
      (dds.dare:pkey-free pub-handle)))
  t)

(defun* run-auth-ffdh-kat ()
    (function () t)
  "FFDH MODP-2048 key agreement self-consistency round-trip KAT.
   No published MODP-2048 DH shared-secret KAT vector located (NIST CAVP KAS-FFC test packages
   target SP 800-56A group-parameter sets, not RFC 3526 Group 14 directly; searched 2026-06-24).
   KAT method: generate two ephemeral key pairs (A, B); assert
     ffdh-compute(A-priv, B-pub) == ffdh-compute(B-priv, A-pub) (DH commutativity property).
   Also asserts the shared secret length = 256 bytes (MODP-2048 group order, RFC 3526 §3)
   and that SHA-256 of the shared secret is 32 bytes (DDS-Security §9.3.3). Both SBCL/Clasp."
  (handler-case (dds.dare:dare-available-p)
    (dds.dare:dare-unavailable (c)
      (format t "~&  [ffdh-kat] SKIP: ~a~%" (dds.dare:dare-unavailable-reason c))
      (return-from run-auth-ffdh-kat t)))
  (multiple-value-bind (pub-a priv-a)
      (dds.dare:ffdh-gen-keypair dds.security::+modp-2048-p+ dds.security::+modp-2048-g+)
    (unwind-protect
         (multiple-value-bind (pub-b priv-b)
             (dds.dare:ffdh-gen-keypair dds.security::+modp-2048-p+ dds.security::+modp-2048-g+)
           (unwind-protect
                (let ((zab (dds.dare:ffdh-compute priv-a pub-b))
                      (zba (dds.dare:ffdh-compute priv-b pub-a)))
                  (%check :ffdh-len-ab (= (length zab) 256)
                          (format nil "FFDH shared secret length ~d != 256" (length zab)))
                  (%check :ffdh-round-trip (equalp zab zba)
                          "FFDH MODP-2048 round-trip: ffdh-compute(A,B-pub) != ffdh-compute(B,A-pub)")
                  (let ((sha (dds.dare:sha-256 zab)))
                    (%check :ffdh-sha256-len (= (length sha) 32)
                            (format nil "SHA-256(FFDH) length ~d != 32" (length sha)))))
             (dds.dare:pkey-free priv-b)))
      (dds.dare:pkey-free priv-a)))
  t)

(defun* run-auth-suite-selection-test ()
    (function () t)
  "DDS-Security 1.1 §9.3.2 suite selection: select-auth-suite returns correct suite per cert kind.
   (:ec  :ec)  -> +suite-ecdh+  (ECDH+prime256v1-CEUM / ECDSA-SHA256).
   (:rsa :rsa) -> +suite-ffdh+  (DH+MODP-2048-256 / RSASSA-PSS-SHA256).
   (:ec  :rsa) -> NIL  (mismatched -> no common suite -> handshake must reject).
   (:rsa :ec)  -> NIL  (same, reversed direction).
   %cert-algo->kind: \"EC-prime256v1\"->:ec, \"RSA-2048\"->:rsa, unknown->NIL (§8.7.2.2 / §9.3.1).
   Both SBCL and Clasp must pass."
  (%check :sel-ec-ec
          (eq (dds.security:select-auth-suite :ec :ec) dds.security:+suite-ecdh+)
          "select-auth-suite(:ec :ec) must return +suite-ecdh+")
  (%check :sel-rsa-rsa
          (eq (dds.security:select-auth-suite :rsa :rsa) dds.security:+suite-ffdh+)
          "select-auth-suite(:rsa :rsa) must return +suite-ffdh+")
  (%check :sel-ec-rsa
          (null (dds.security:select-auth-suite :ec :rsa))
          "select-auth-suite(:ec :rsa) must return NIL (no common suite)")
  (%check :sel-rsa-ec
          (null (dds.security:select-auth-suite :rsa :ec))
          "select-auth-suite(:rsa :ec) must return NIL (no common suite)")
  ;; %cert-algo->kind: IdentityToken algo string -> cert kind (§8.7.2.2 / §9.3.1)
  (%check :cert-algo->kind-ec
          (eq (dds.security::%cert-algo->kind "EC-prime256v1") :ec)
          "%cert-algo->kind(\"EC-prime256v1\") must return :EC")
  (%check :cert-algo->kind-rsa
          (eq (dds.security::%cert-algo->kind "RSA-2048") :rsa)
          "%cert-algo->kind(\"RSA-2048\") must return :RSA")
  (%check :cert-algo->kind-unknown
          (null (dds.security::%cert-algo->kind "bogus"))
          "%cert-algo->kind(\"bogus\") must return NIL (unrecognized algo)")
  ;; Round-trip: algo string from suite -> kind -> select-auth-suite
  (%check :cert-algo-round-trip-ec
          (eq (dds.security:select-auth-suite
               (dds.security::%cert-algo->kind dds.security::+token-algo-ec+)
               (dds.security::%cert-algo->kind dds.security::+token-algo-ec+))
              dds.security:+suite-ecdh+)
          "round-trip EC-prime256v1 -> :ec -> select-auth-suite must yield +suite-ecdh+")
  (%check :cert-algo-round-trip-rsa
          (eq (dds.security:select-auth-suite
               (dds.security::%cert-algo->kind dds.security::+token-algo-rsa+)
               (dds.security::%cert-algo->kind dds.security::+token-algo-rsa+))
              dds.security:+suite-ffdh+)
          "round-trip RSA-2048 -> :rsa -> select-auth-suite must yield +suite-ffdh+")
  t)

(defun* run-auth-handshake-rsa-test ()
    (function () t)
  "DDS-Security 1.1 §8.7.2.4 three-message PKI-DH handshake via +suite-ffdh+ (RSA-2048 certs).
   Happy-path: participant_rsa (GUID-A < GUID-B) is requester; participant_rsa_b is replier.
   Full Request->Reply->Final: both handles -> :authenticated; SharedSecrets byte-equal (32 bytes).
   Negative: tampered reply -> requester :rejected. Both SBCL and Clasp must pass."
  (handler-case (dds.dare:dare-available-p)
    (dds.dare:dare-unavailable (c)
      (format t "~&  [auth-handshake-rsa] SKIP: ~a~%" (dds.dare:dare-unavailable-reason c))
      (return-from run-auth-handshake-rsa-test t)))
  (let* ((ca-pem     (%read-fixture-pem "ca/ca-cert.pem"))
         (rsa-cert-a (%read-fixture-pem "participant_rsa/identity_cert.pem"))
         (rsa-key-a  (%read-fixture-pem "participant_rsa/identity_key.pem"))
         (rsa-cert-b (%read-fixture-pem "participant_rsa_b/identity_cert.pem"))
         (rsa-key-b  (%read-fixture-pem "participant_rsa_b/identity_key.pem"))
         ;; guid-a < guid-b (lexicographic) -> A is requester
         (guid-a     (make-array 16 :element-type '(unsigned-byte 8)
                                    :initial-contents '(1 2 3 4 5 6 7 8 9 10 11 12 13 14 15 16)))
         (guid-b     (make-array 16 :element-type '(unsigned-byte 8)
                                    :initial-contents '(200 2 3 4 5 6 7 8 9 10 11 12 13 14 15 16))))
    (multiple-value-bind (id-a reason-a)
        (dds.security:validate-local-identity ca-pem rsa-cert-a rsa-key-a guid-a)
      (%check :hs-rsa-id-a-ok (not (null id-a))
              (format nil "validate-local-identity RSA-A failed: ~a" reason-a))
      (unless id-a (return-from run-auth-handshake-rsa-test t))
      (unwind-protect
           (multiple-value-bind (id-b reason-b)
               (dds.security:validate-local-identity ca-pem rsa-cert-b rsa-key-b guid-b)
             (%check :hs-rsa-id-b-ok (not (null id-b))
                     (format nil "validate-local-identity RSA-B failed: ~a" reason-b))
             (unless id-b (return-from run-auth-handshake-rsa-test t))
             (unwind-protect
                  (progn
                    ;; === Happy-path via +suite-ffdh+ ===
                    (multiple-value-bind (req-tok req-hdl)
                        (dds.security:begin-handshake-request id-a id-b dds.security:+suite-ffdh+)
                      (%check :hs-rsa-req-tok (and req-tok (> (length req-tok) 0))
                              "begin-handshake-request(FFDH) returned empty token")
                      (%check :hs-rsa-req-hdl (not (null req-hdl)) "begin-handshake-request(FFDH) nil handle")
                      (unwind-protect
                           (multiple-value-bind (rep-tok rep-hdl)
                               (dds.security:begin-handshake-reply id-b id-a req-tok dds.security:+suite-ffdh+)
                             (%check :hs-rsa-rep-tok (and rep-tok (> (length rep-tok) 0))
                                     "begin-handshake-reply(FFDH) returned empty token")
                             (%check :hs-rsa-rep-hdl (not (null rep-hdl)) "begin-handshake-reply(FFDH) nil handle")
                             (unwind-protect
                                  (multiple-value-bind (final-tok req-status)
                                      (dds.security:process-handshake req-hdl rep-tok)
                                    (%check :hs-rsa-final-tok (and final-tok (> (length final-tok) 0))
                                            "process-handshake(req,reply) FFDH returned empty final")
                                    (%check :hs-rsa-req-continue (eq req-status :continue)
                                            (format nil "process-handshake FFDH req status ~a" req-status))
                                    (%check :hs-rsa-req-state
                                            (eq (dds.security:handshake-handle-state req-hdl) :authenticated)
                                            "FFDH requester not :authenticated after Final generation")
                                    (multiple-value-bind (nil-tok rep-status)
                                        (dds.security:process-handshake rep-hdl final-tok)
                                      (%check :hs-rsa-rep-auth (eq rep-status :authenticated)
                                              (format nil "FFDH replier status ~a != :authenticated" rep-status))
                                      (%check :hs-rsa-rep-nil-tok (null nil-tok)
                                              "FFDH replier must return nil token after Final")
                                      (let ((ss-req (dds.security:handshake-shared-secret req-hdl))
                                            (ss-rep (dds.security:handshake-shared-secret rep-hdl)))
                                        (%check :hs-rsa-req-ss (not (null ss-req)) "FFDH requester SharedSecret nil")
                                        (%check :hs-rsa-rep-ss (not (null ss-rep)) "FFDH replier SharedSecret nil")
                                        (when (and ss-req ss-rep)
                                          (let ((b-req (dds.security:shared-secret-bytes ss-req))
                                                (b-rep (dds.security:shared-secret-bytes ss-rep)))
                                            (%check :hs-rsa-ss-len-req (= (length b-req) 32)
                                                    (format nil "FFDH req SharedSecret length ~d != 32" (length b-req)))
                                            (%check :hs-rsa-ss-len-rep (= (length b-rep) 32)
                                                    (format nil "FFDH rep SharedSecret length ~d != 32" (length b-rep)))
                                            (%check :hs-rsa-ss-equal (equalp b-req b-rep)
                                                    "FFDH SharedSecret mismatch req vs rep"))))))
                               (dds.security:free-handshake-handle rep-hdl)))
                        (dds.security:free-handshake-handle req-hdl)))
                    ;; === Negative: tampered reply -> requester rejects ===
                    (multiple-value-bind (req-tok-n req-hdl-n)
                        (dds.security:begin-handshake-request id-a id-b dds.security:+suite-ffdh+)
                      (multiple-value-bind (rep-tok-n rep-hdl-n)
                          (dds.security:begin-handshake-reply id-b id-a req-tok-n dds.security:+suite-ffdh+)
                        (unwind-protect
                             (let* ((tampered (copy-seq rep-tok-n))
                                    (last-idx (1- (length tampered))))
                               (setf (aref tampered last-idx) (logxor (aref tampered last-idx) #xFF))
                               (multiple-value-bind (ignore neg-status)
                                   (dds.security:process-handshake req-hdl-n tampered)
                                 (declare (ignore ignore))
                                 (%check :hs-rsa-neg-rejected (eq neg-status :rejected)
                                         (format nil "FFDH tampered reply -> ~a (expected :rejected)" neg-status))))
                          (dds.security:free-handshake-handle rep-hdl-n)
                          (dds.security:free-handshake-handle req-hdl-n)))))
               (dds.security:free-identity-handle id-b)))
        (dds.security:free-identity-handle id-a))))
  t)

;;; ============================================================
;;; T4: fail-closed negative battery, token corpus, parser fuzz
;;; ============================================================

(defun* %run-ecdh-happy-path (id-a id-b)
    (function (dds.security:identity-handle dds.security:identity-handle)
              (values (simple-array (unsigned-byte 8) (*)) dds.security:handshake-handle
                      (simple-array (unsigned-byte 8) (*)) dds.security:handshake-handle))
  "Drive one complete ECDH Request->Reply and return (req-tok req-hdl rep-tok rep-hdl).
   Callers MUST free both handles; only use inside unwind-protect."
  (multiple-value-bind (req-tok req-hdl)
      (dds.security:begin-handshake-request id-a id-b dds.security:+suite-ecdh+)
    (multiple-value-bind (rep-tok rep-hdl)
        (dds.security:begin-handshake-reply id-b id-a req-tok dds.security:+suite-ecdh+)
      (values req-tok req-hdl rep-tok rep-hdl))))

(defun* %run-ffdh-happy-path (id-a id-b)
    (function (dds.security:identity-handle dds.security:identity-handle)
              (values (simple-array (unsigned-byte 8) (*)) dds.security:handshake-handle
                      (simple-array (unsigned-byte 8) (*)) dds.security:handshake-handle))
  "Drive one complete FFDH Request->Reply and return (req-tok req-hdl rep-tok rep-hdl).
   Callers MUST free both handles; only use inside unwind-protect."
  (multiple-value-bind (req-tok req-hdl)
      (dds.security:begin-handshake-request id-a id-b dds.security:+suite-ffdh+)
    (multiple-value-bind (rep-tok rep-hdl)
        (dds.security:begin-handshake-reply id-b id-a req-tok dds.security:+suite-ffdh+)
      (values req-tok req-hdl rep-tok rep-hdl))))

(defun* %tamper-last-byte (v)
    (function ((simple-array (unsigned-byte 8) (*))) (simple-array (unsigned-byte 8) (*)))
  "Return a copy of V with the last byte XOR'd with #xFF (signature tamper)."
  (let* ((n (length v))
         (out (copy-seq v)))
    (setf (aref out (1- n)) (logxor (aref out (1- n)) #xFF))
    out))

(defun* run-auth-negatives-test ()
    (function () t)
  "T4 fail-closed negative battery for DDS-Security §8.7.2.4 PKI-DH handshake.
   Each negative asserts :rejected / (values nil reason) with NO SharedSecret and NO throw.
   Each is paired with a matching positive-control so the test cannot pass by always-rejecting.
   Internal token format is the in-process tagged binary (not CDR DataHolder wire — Slice 5).
   Requires OpenSSL >= 3.5; skips gracefully if absent. Both SBCL and Clasp must pass."
  (handler-case (dds.dare:dare-available-p)
    (dds.dare:dare-unavailable (c)
      (format t "~&  [auth-negatives] SKIP — OpenSSL >= 3.5 not available: ~a~%"
              (dds.dare:dare-unavailable-reason c))
      (return-from run-auth-negatives-test t)))

  (let* ((ca-pem        (%read-fixture-pem "ca/ca-cert.pem"))
         (ec-cert-a     (%read-fixture-pem "participant_ec/identity_cert.pem"))
         (ec-key-a      (%read-fixture-pem "participant_ec/identity_key.pem"))
         (ec-cert-b     (%read-fixture-pem "participant_ec_b/identity_cert.pem"))
         (ec-key-b      (%read-fixture-pem "participant_ec_b/identity_key.pem"))
         (rsa-cert-a    (%read-fixture-pem "participant_rsa/identity_cert.pem"))
         (rsa-key-a     (%read-fixture-pem "participant_rsa/identity_key.pem"))
         (rsa-cert-b    (%read-fixture-pem "participant_rsa_b/identity_cert.pem"))
         (rsa-key-b     (%read-fixture-pem "participant_rsa_b/identity_key.pem"))
         (wrong-cert    (%read-fixture-pem "wrong_ca/wrong-identity-cert.pem"))
         (guid-a        (make-array 16 :element-type '(unsigned-byte 8)
                                       :initial-contents '(1 2 3 4 5 6 7 8 9 10 11 12 13 14 15 16)))
         (guid-b        (make-array 16 :element-type '(unsigned-byte 8)
                                       :initial-contents '(200 2 3 4 5 6 7 8 9 10 11 12 13 14 15 16))))

    (multiple-value-bind (id-a reason-a)
        (dds.security:validate-local-identity ca-pem ec-cert-a ec-key-a guid-a)
      (%check :neg-id-a-ok (not (null id-a)) (format nil "EC-A identity failed: ~a" reason-a))
      (unless id-a (return-from run-auth-negatives-test t))
      (unwind-protect
           (multiple-value-bind (id-b reason-b)
               (dds.security:validate-local-identity ca-pem ec-cert-b ec-key-b guid-b)
             (%check :neg-id-b-ok (not (null id-b)) (format nil "EC-B identity failed: ~a" reason-b))
             (unless id-b (return-from run-auth-negatives-test t))
             (unwind-protect
                  (progn

                    ;; ----- N1: Untrusted CA cert -> validate-local-identity fails closed -----
                    ;; Positive: ec-cert-a with the test CA is :neg-id-a-ok above.
                    (multiple-value-bind (bad-h bad-r)
                        (dds.security:validate-local-identity ca-pem wrong-cert ec-key-a guid-a)
                      (%check :neg-wrong-ca-nil (null bad-h)
                              "N1: wrong-CA cert must not produce an identity-handle")
                      (%check :neg-wrong-ca-reason (not (null bad-r))
                              "N1: wrong-CA rejection must carry a reason")
                      (when bad-h (dds.security:free-identity-handle bad-h)))

                    ;; ----- N2: Tampered cert byte -> validate-local-identity fails closed -----
                    ;; Positive: ec-cert-a loads fine (asserted as :neg-id-a-ok above).
                    (let* ((tampered-cert (copy-seq ec-cert-a))
                           (mid (truncate (length tampered-cert) 2)))
                      (setf (aref tampered-cert mid) (logxor (aref tampered-cert mid) #xFF))
                      (multiple-value-bind (bad-h2 bad-r2)
                          (dds.security:validate-local-identity ca-pem tampered-cert ec-key-a guid-a)
                        (%check :neg-tampered-cert-nil (null bad-h2)
                                "N2: tampered cert must not produce an identity-handle")
                        (%check :neg-tampered-cert-reason (not (null bad-r2))
                                "N2: tampered cert rejection must carry a reason")
                        (when bad-h2 (dds.security:free-identity-handle bad-h2))))

                    ;; ----- N3 ECDH: bad Reply signature -> requester :rejected -----
                    ;; Positive: process-handshake(req,genuine-reply) -> :continue + non-empty Final.
                    (multiple-value-bind (req-tok-pos req-hdl-pos rep-tok-pos rep-hdl-pos)
                        (%run-ecdh-happy-path id-a id-b)
                      (unwind-protect
                           (multiple-value-bind (pos-final pos-status)
                               (dds.security:process-handshake req-hdl-pos rep-tok-pos)
                             (%check :neg3-ecdh-pos-continue (eq pos-status :continue)
                                     (format nil "N3 positive ECDH: status ~a != :continue" pos-status))
                             (%check :neg3-ecdh-pos-final (and pos-final (> (length pos-final) 0))
                                     "N3 positive ECDH: final token must be non-empty"))
                        (dds.security:free-handshake-handle rep-hdl-pos)
                        (dds.security:free-handshake-handle req-hdl-pos)))

                    ;; N3 negative: tamper last byte of Reply -> :rejected, no SharedSecret
                    (multiple-value-bind (req-tok-n req-hdl-n rep-tok-n rep-hdl-n)
                        (%run-ecdh-happy-path id-a id-b)
                      (unwind-protect
                           (let* ((tampered-rep (%tamper-last-byte rep-tok-n))
                                  (neg3-status  (nth-value 1 (dds.security:process-handshake
                                                              req-hdl-n tampered-rep))))
                             (%check :neg3-ecdh-rejected (eq neg3-status :rejected)
                                     (format nil "N3 ECDH: bad Reply sig -> ~a (want :rejected)" neg3-status))
                             (%check :neg3-ecdh-no-ss (null (dds.security:handshake-shared-secret req-hdl-n))
                                     "N3 ECDH: requester must have NIL SharedSecret after rejection"))
                        (dds.security:free-handshake-handle rep-hdl-n)
                        (dds.security:free-handshake-handle req-hdl-n)))

                    ;; ----- N4 FFDH: bad Reply signature -> requester :rejected -----
                    (multiple-value-bind (id-ra reason-ra)
                        (dds.security:validate-local-identity ca-pem rsa-cert-a rsa-key-a guid-a)
                      (%check :neg-id-ra-ok (not (null id-ra)) (format nil "RSA-A failed: ~a" reason-ra))
                      (unless id-ra (return-from run-auth-negatives-test t))
                      (unwind-protect
                           (multiple-value-bind (id-rb reason-rb)
                               (dds.security:validate-local-identity ca-pem rsa-cert-b rsa-key-b guid-b)
                             (%check :neg-id-rb-ok (not (null id-rb)) (format nil "RSA-B failed: ~a" reason-rb))
                             (unless id-rb (return-from run-auth-negatives-test t))
                             (unwind-protect
                                  (progn
                                    ;; positive: FFDH Request->Reply -> :continue
                                    (multiple-value-bind (req-tp req-hp rep-tp rep-hp)
                                        (%run-ffdh-happy-path id-ra id-rb)
                                      (unwind-protect
                                           (multiple-value-bind (fin-tp pos-st)
                                               (dds.security:process-handshake req-hp rep-tp)
                                             (declare (ignore fin-tp))
                                             (%check :neg4-ffdh-pos-continue (eq pos-st :continue)
                                                     (format nil "N4 FFDH positive: status ~a != :continue" pos-st)))
                                        (dds.security:free-handshake-handle rep-hp)
                                        (dds.security:free-handshake-handle req-hp)))
                                    ;; negative: tamper FFDH Reply -> :rejected
                                    (multiple-value-bind (req-tn req-hn rep-tn rep-hn)
                                        (%run-ffdh-happy-path id-ra id-rb)
                                      (unwind-protect
                                           (let* ((tampered-ffdh-rep (%tamper-last-byte rep-tn))
                                                  (neg4-status (nth-value 1 (dds.security:process-handshake
                                                                             req-hn tampered-ffdh-rep))))
                                             (%check :neg4-ffdh-rejected (eq neg4-status :rejected)
                                                     (format nil "N4 FFDH: bad Reply -> ~a" neg4-status))
                                             (%check :neg4-ffdh-no-ss (null (dds.security:handshake-shared-secret req-hn))
                                                     "N4 FFDH: must have NIL SharedSecret after rejection"))
                                        (dds.security:free-handshake-handle rep-hn)
                                        (dds.security:free-handshake-handle req-hn))))
                               (dds.security:free-identity-handle id-rb)))
                        (dds.security:free-identity-handle id-ra)))

                    ;; ----- N5 ECDH: tampered Final -> replier :rejected -----
                    ;; Positive: requester reaches :authenticated (generates Final).
                    (multiple-value-bind (req-tok-f req-hdl-f rep-tok-f rep-hdl-f)
                        (%run-ecdh-happy-path id-a id-b)
                      (unwind-protect
                           (multiple-value-bind (final-tok-f _f-st)
                               (dds.security:process-handshake req-hdl-f rep-tok-f)
                             (declare (ignore _f-st))
                             (%check :neg5-req-state-auth
                                     (eq (dds.security:handshake-handle-state req-hdl-f) :authenticated)
                                     "N5: requester must be :authenticated after generating Final")
                             (let* ((tampered-final (%tamper-last-byte final-tok-f))
                                    (neg5-status    (nth-value 1 (dds.security:process-handshake
                                                                  rep-hdl-f tampered-final))))
                               (%check :neg5-ecdh-final-rejected (eq neg5-status :rejected)
                                       (format nil "N5 ECDH: tampered Final -> ~a (want :rejected)" neg5-status))
                               (%check :neg5-ecdh-no-ss (null (dds.security:handshake-shared-secret rep-hdl-f))
                                       "N5 ECDH: replier must have NIL SharedSecret after Final rejection")))
                        (dds.security:free-handshake-handle rep-hdl-f)
                        (dds.security:free-handshake-handle req-hdl-f)))

                    ;; ----- N6: wrong nonce / stale challenge in token -> :rejected -----
                    ;; Substitute wrong challenge1 in the Reply so the requester's echo-check fails.
                    ;; M1: positive-control — genuine Reply must yield :continue before we tamper.
                    (multiple-value-bind (req-tok-nc req-hdl-nc rep-tok-nc rep-hdl-nc)
                        (%run-ecdh-happy-path id-a id-b)
                      (declare (ignore req-tok-nc))
                      (unwind-protect
                           (let* ((pos6-status (nth-value 1 (dds.security:process-handshake
                                                             req-hdl-nc rep-tok-nc))))
                             (%check :neg6-genuine-rep-ok
                                     (member pos6-status '(:continue :authenticated))
                                     (format nil "N6 positive: genuine Reply -> ~a (want :continue)"
                                             pos6-status)))
                        (dds.security:free-handshake-handle rep-hdl-nc)
                        (dds.security:free-handshake-handle req-hdl-nc)))
                    ;; N6 negative: stale nonce — a fresh set of handles is needed here
                    (multiple-value-bind (req-tok-nc2 req-hdl-nc2 rep-tok-nc2 rep-hdl-nc2)
                        (%run-ecdh-happy-path id-a id-b)
                      (declare (ignore req-tok-nc2))
                      (unwind-protect
                           (let* ((stale-nonce (make-array 32 :element-type '(unsigned-byte 8)
                                                              :initial-element 42))
                                  (parsed-rep  (dds.security::%parse-token rep-tok-nc2)))
                             ;; C2: genuine Reply from a correctly-loaded identity MUST parse
                             (%check :neg6-rep-parseable (not (null parsed-rep))
                                     "N6: genuine Reply token must parse")
                             ;; Proceed only when parsed-rep is valid; %check already recorded failure
                             (when parsed-rep
                               (let* ((new-props (mapcar (lambda (pair)
                                                           (if (string= (car pair)
                                                                        dds.security::+prop-challenge1+)
                                                               (cons (car pair) stale-nonce)
                                                               pair))
                                                         (dds.security::handshake-token-binary-props parsed-rep)))
                                      (stale-blob (dds.security::%serialize-token
                                                   (dds.security::%make-handshake-token
                                                    :class-id (dds.security::handshake-token-class-id parsed-rep)
                                                    :binary-props new-props)))
                                      (neg6-status (nth-value 1 (dds.security:process-handshake
                                                                 req-hdl-nc2 stale-blob))))
                                 (%check :neg6-wrong-nonce-rejected (eq neg6-status :rejected)
                                         (format nil "N6: wrong nonce in Reply -> ~a (want :rejected)"
                                                 neg6-status)))))
                        (dds.security:free-handshake-handle rep-hdl-nc2)
                        (dds.security:free-handshake-handle req-hdl-nc2)))

                    ;; ----- N7: mismatched suite / select-auth-suite -> nil -----
                    ;; Positive: (:ec :ec) -> +suite-ecdh+, (:rsa :rsa) -> +suite-ffdh+.
                    (%check :neg7-sel-ec-ec-pos
                            (eq (dds.security:select-auth-suite :ec :ec) dds.security:+suite-ecdh+)
                            "N7 positive: (:ec :ec) must return +suite-ecdh+")
                    (%check :neg7-sel-rsa-rsa-pos
                            (eq (dds.security:select-auth-suite :rsa :rsa) dds.security:+suite-ffdh+)
                            "N7 positive: (:rsa :rsa) must return +suite-ffdh+")
                    (%check :neg7-ec-rsa-nil
                            (null (dds.security:select-auth-suite :ec :rsa))
                            "N7: (:ec :rsa) must return NIL (no common suite)")
                    (%check :neg7-rsa-ec-nil
                            (null (dds.security:select-auth-suite :rsa :ec))
                            "N7: (:rsa :ec) must return NIL (no common suite)")

                    ;; ----- N8: malformed / truncated token -> process-handshake :rejected -----
                    ;; truncated 4-byte blob: has magic but no class-id length
                    (multiple-value-bind (req-tok-m req-hdl-m rep-tok-m rep-hdl-m)
                        (%run-ecdh-happy-path id-a id-b)
                      (declare (ignore req-tok-m rep-tok-m))
                      (unwind-protect
                           (let ((short-blob (make-array 4 :element-type '(unsigned-byte 8)
                                                           :initial-contents '(#xD0 #xDD #x53 #x70))))
                             (let ((neg8a-status (nth-value 1 (dds.security:process-handshake
                                                               req-hdl-m short-blob))))
                               (%check :neg8-truncated-rejected (eq neg8a-status :rejected)
                                       (format nil "N8a: 4-byte truncated blob -> ~a" neg8a-status))))
                        (dds.security:free-handshake-handle rep-hdl-m)
                        (dds.security:free-handshake-handle req-hdl-m)))

                    ;; oversized random-looking blob: has magic + rest is repeating 0xAB
                    (multiple-value-bind (rq2 req-hdl-ov rp2 rep-hdl-ov)
                        (%run-ecdh-happy-path id-a id-b)
                      (declare (ignore rq2 rp2))
                      (unwind-protect
                           (let* ((big-blob (make-array 4096 :element-type '(unsigned-byte 8)
                                                             :initial-element #xAB))
                                  (neg8b-status (progn
                                                  (setf (aref big-blob 0) #xD0
                                                        (aref big-blob 1) #xDD
                                                        (aref big-blob 2) #x53
                                                        (aref big-blob 3) #x70)
                                                  (nth-value 1 (dds.security:process-handshake
                                                                req-hdl-ov big-blob)))))
                             (%check :neg8-oversized-rejected (eq neg8b-status :rejected)
                                     (format nil "N8b: 4096-byte garbage blob -> ~a" neg8b-status)))
                        (dds.security:free-handshake-handle rep-hdl-ov)
                        (dds.security:free-handshake-handle req-hdl-ov)))

                    ;; ----- N9: §9.3.2 algo-vs-suite cross-check: replier rejects on suite mismatch -----
                    ;; Positive control: genuine ECDH request -> ECDH replier -> non-nil reply.
                    (multiple-value-bind (req-tok-good req-hdl-good)
                        (dds.security:begin-handshake-request id-a id-b dds.security:+suite-ecdh+)
                      (unwind-protect
                           (multiple-value-bind (rep-tok-good rep-hdl-good)
                               (dds.security:begin-handshake-reply id-b id-a req-tok-good dds.security:+suite-ecdh+)
                             (when rep-hdl-good (dds.security:free-handshake-handle rep-hdl-good))
                             (%check :neg9-ecdh-pos-reply (not (null rep-tok-good))
                                     "N9 positive: genuine ECDH request must produce a reply token"))
                        (dds.security:free-handshake-handle req-hdl-good)))
                    ;; N9a: cross-suite dsign+kagree mismatch (non-vacuous guard proof).
                    ;; Build a genuine FFDH request (RSA identity, +suite-ffdh+): its hash_c1 is
                    ;; internally consistent (computed from FFDH algo strings) so the hash check
                    ;; in begin-handshake-reply would PASS.  The cert chain also verifies (same CA).
                    ;; Only the algo-guard (§9.3.2) catches the mismatch.
                    ;; Proof: remove the guard -> begin-handshake-reply returns non-nil (accepted).
                    (multiple-value-bind (id-ra reason-ra)
                        (dds.security:validate-local-identity ca-pem rsa-cert-a rsa-key-a guid-a)
                      (%check :neg9a-id-ra-ok (not (null id-ra))
                              (format nil "N9a: RSA-A identity failed: ~a" reason-ra))
                      (when id-ra
                        (unwind-protect
                             (multiple-value-bind (id-rb reason-rb)
                                 (dds.security:validate-local-identity ca-pem rsa-cert-b rsa-key-b guid-b)
                               (%check :neg9a-id-rb-ok (not (null id-rb))
                                       (format nil "N9a: RSA-B identity failed: ~a" reason-rb))
                               (when id-rb
                                 (unwind-protect
                                      (multiple-value-bind (ffdh-req-tok ffdh-req-hdl)
                                          (dds.security:begin-handshake-request id-ra id-rb dds.security:+suite-ffdh+)
                                        (%check :neg9a-ffdh-req-tok (and ffdh-req-tok (> (length ffdh-req-tok) 0))
                                                "N9a: FFDH begin-handshake-request returned empty token")
                                        (unwind-protect
                                             (multiple-value-bind (nil-tok9a nil-hdl9a)
                                                 ;; present FFDH request to ECDH replier (id-b) — suite mismatch
                                                 (dds.security:begin-handshake-reply id-b id-ra ffdh-req-tok dds.security:+suite-ecdh+)
                                               (when nil-hdl9a (dds.security:free-handshake-handle nil-hdl9a))
                                               (%check :neg9a-cross-suite-nil-tok (null nil-tok9a)
                                                       "N9a: FFDH request to ECDH replier must return nil token (algo-vs-suite guard §9.3.2)")
                                               (%check :neg9a-cross-suite-nil-hdl (null nil-hdl9a)
                                                       "N9a: FFDH request to ECDH replier must return nil handle"))
                                          (dds.security:free-handshake-handle ffdh-req-hdl)))
                                   (dds.security:free-identity-handle id-rb))))
                          (dds.security:free-identity-handle id-ra))))
                    ;; N9b: kagree-only mismatch (isolates the second branch of the guard's `and`).
                    ;; Start from a genuine ECDH request (c.dsign_algo="ECDSA-SHA256" correct),
                    ;; replace c.kagree_algo with the FFDH value, and recompute hash_c1 using the
                    ;; altered kagree string so the hash check does NOT mask the guard.
                    ;; Without the guard, hash_c1 matches and begin-handshake-reply proceeds.
                    (multiple-value-bind (req-tok-nb req-hdl-nb)
                        (dds.security:begin-handshake-request id-a id-b dds.security:+suite-ecdh+)
                      (unwind-protect
                           (let* ((parsed-nb (dds.security::%parse-token req-tok-nb)))
                             (%check :neg9b-req-parseable (not (null parsed-nb))
                                     "N9b: ECDH request token must parse")
                             (when parsed-nb
                               (let* ((cert-der-nb   (cdr (find dds.security::+prop-c-id+
                                                                 (dds.security::handshake-token-binary-props parsed-nb)
                                                                 :key #'car :test #'string=)))
                                      (perm-nb       (or (cdr (find dds.security::+prop-c-perm+
                                                                     (dds.security::handshake-token-binary-props parsed-nb)
                                                                     :key #'car :test #'string=))
                                                         (make-array 0 :element-type '(unsigned-byte 8))))
                                      (pdata-nb      (or (cdr (find dds.security::+prop-c-pdata+
                                                                     (dds.security::handshake-token-binary-props parsed-nb)
                                                                     :key #'car :test #'string=))
                                                         (make-array 0 :element-type '(unsigned-byte 8))))
                                      ;; keep dsign as ECDSA (correct for ECDH suite), swap kagree to FFDH
                                      (dsign-str-nb  (dds.security::auth-suite-dsign-algo-str dds.security:+suite-ecdh+))
                                      (ffdh-kagree-str (dds.security::auth-suite-kagree-algo-str dds.security:+suite-ffdh+))
                                      (ffdh-kagree-bytes (map '(simple-array (unsigned-byte 8) (*))
                                                              #'char-code ffdh-kagree-str))
                                      ;; recompute hash_c1 so it is consistent with the tampered kagree
                                      (new-hash-c1   (dds.security::%compute-hash-c
                                                       dds.security:+suite-ecdh+
                                                       cert-der-nb perm-nb pdata-nb
                                                       dsign-str-nb ffdh-kagree-str))
                                      (props-nb (dds.security::handshake-token-binary-props parsed-nb))
                                      ;; replace c.kagree_algo and hash_c1 in the property list
                                      (new-props-nb
                                        (mapcar (lambda (pair)
                                                  (cond
                                                    ((string= (car pair) dds.security::+prop-c-kagree-algo+)
                                                     (cons (car pair) ffdh-kagree-bytes))
                                                    ((string= (car pair) dds.security::+prop-hash-c1+)
                                                     (cons (car pair) new-hash-c1))
                                                    (t pair)))
                                                props-nb))
                                      (tampered-nb   (dds.security::%serialize-token
                                                       (dds.security::%make-handshake-token
                                                        :class-id (dds.security::handshake-token-class-id parsed-nb)
                                                        :binary-props new-props-nb))))
                                 (multiple-value-bind (nil-tok9b nil-hdl9b)
                                     (dds.security:begin-handshake-reply id-b id-a tampered-nb dds.security:+suite-ecdh+)
                                   (when nil-hdl9b (dds.security:free-handshake-handle nil-hdl9b))
                                   (%check :neg9b-kagree-mismatch-nil-tok (null nil-tok9b)
                                           "N9b: kagree-only mismatch must cause begin-handshake-reply to return nil token")
                                   (%check :neg9b-kagree-mismatch-nil-hdl (null nil-hdl9b)
                                           "N9b: kagree-only mismatch must cause begin-handshake-reply to return nil handle")))))
                        (dds.security:free-handshake-handle req-hdl-nb))))

               (dds.security:free-identity-handle id-b)))
        (dds.security:free-identity-handle id-a))))

  t)

(defun* %challenge-differs (nonce)
    (function ((simple-array (unsigned-byte 8) (32))) (simple-array (unsigned-byte 8) (32)))
  "Return a fresh 32-octet nonce guaranteed to DIFFER from NONCE (flip byte 0) — a stand-in for a
   replayed / wrong future_challenge in the §8.7.2.5 anti-replay negative assertions."
  (let ((out (copy-seq nonce)))
    (setf (aref out 0) (logxor (aref out 0) #xFF))
    out))

(defun* run-auth-challenge-binding-test ()
    (function () t)
  "WP-DDS-SECURITY-CONNEXT-INTEROP Slice 5b: the §8.7.2.3 AuthRequestMessageToken challenge-binding
   (anti-replay) gate at the handshake-API layer (dds-security). Requester precommits future_challenge
   FC1 (challenge1 = FC1 verbatim); replier precommits FC2 (challenge2 = FC2 verbatim). Assertions:
     (a) BIND-APPLIED: the request token's challenge1 EQUALS the supplied FC1 (verbatim, no hashing).
     (b) POSITIVE: replier accepts with EXPECTED-CHALLENGE1=FC1; requester accepts the reply with
         EXPECTED-CHALLENGE2=FC2; both reach :authenticated with byte-equal SharedSecrets.
     (c) NEG-REPLIER: replier REJECTS (values NIL NIL) when EXPECTED-CHALLENGE1 != the request's challenge1
         (a replayed/forged request) — the §8.7.2.5 fail-closed replier gate.
     (d) NEG-REQUESTER: requester REJECTS (:rejected) when EXPECTED-CHALLENGE2 != the reply's challenge2.
     (e) ABSENCE-TOLERANCE: replier with EXPECTED-CHALLENGE1=NIL (no auth_request seen) still ACCEPTS the
         bound request — §8.7.2.3-optional, absence must NOT false-reject a conformant peer.
   Requires OpenSSL >= 3.5; skips gracefully if absent. Both SBCL and Clasp must pass."
  (handler-case (dds.dare:dare-available-p)
    (dds.dare:dare-unavailable (c)
      (format t "~&  [auth-challenge-binding] SKIP — OpenSSL >= 3.5 not available: ~a~%"
              (dds.dare:dare-unavailable-reason c))
      (return-from run-auth-challenge-binding-test t)))
  (let* ((ca-pem    (%read-fixture-pem "ca/ca-cert.pem"))
         (ec-cert-a (%read-fixture-pem "participant_ec/identity_cert.pem"))
         (ec-key-a  (%read-fixture-pem "participant_ec/identity_key.pem"))
         (ec-cert-b (%read-fixture-pem "participant_ec_b/identity_cert.pem"))
         (ec-key-b  (%read-fixture-pem "participant_ec_b/identity_key.pem"))
         (guid-a    (make-array 16 :element-type '(unsigned-byte 8)
                                   :initial-contents '(1 2 3 4 5 6 7 8 9 10 11 12 0 2 1 #xC3)))
         (guid-b    (make-array 16 :element-type '(unsigned-byte 8)
                                   :initial-contents '(200 2 3 4 5 6 7 8 9 10 11 12 0 2 1 #xC3))))
    (multiple-value-bind (id-a reason-a)
        (dds.security:validate-local-identity ca-pem ec-cert-a ec-key-a guid-a)
      (%check :cb-id-a (not (null id-a)) (format nil "validate-local-identity A: ~a" reason-a))
      (unless id-a (return-from run-auth-challenge-binding-test t))
      (unwind-protect
           (multiple-value-bind (id-b reason-b)
               (dds.security:validate-local-identity ca-pem ec-cert-b ec-key-b guid-b)
             (%check :cb-id-b (not (null id-b)) (format nil "validate-local-identity B: ~a" reason-b))
             (unless id-b (return-from run-auth-challenge-binding-test t))
             (unwind-protect
                  (let ((fc1 (dds.security:generate-future-challenge))
                        (fc2 (dds.security:generate-future-challenge)))
                    ;; --- (a)+(b) positive: bound request, replier verifies FC1, requester verifies FC2 ---
                    (multiple-value-bind (req-tok req-hdl)
                        (dds.security:begin-handshake-request
                         id-a id-b dds.security:+suite-ecdh+
                         (make-array 0 :element-type '(unsigned-byte 8)) fc1)
                      (unwind-protect
                           (progn
                             ;; (a) the wire challenge1 IS the precommitted future_challenge (verbatim)
                             (let* ((rt (dds.security::%parse-token req-tok))
                                    (c1 (and rt (dds.security::%token-get
                                                 rt dds.security::+prop-challenge1+))))
                               (%check :cb-bind-applied (and c1 (equalp c1 fc1))
                                       "request challenge1 must EQUAL the supplied future_challenge FC1"))
                             (multiple-value-bind (rep-tok rep-hdl)
                                 (dds.security:begin-handshake-reply
                                  id-b id-a req-tok dds.security:+suite-ecdh+
                                  (make-array 0 :element-type '(unsigned-byte 8)) fc1 fc2)
                               (%check :cb-reply-ok (and rep-tok rep-hdl)
                                       "replier must ACCEPT a request whose challenge1 == expected FC1")
                               (unwind-protect
                                    (multiple-value-bind (final-tok status)
                                        (dds.security:process-handshake req-hdl rep-tok fc2)
                                      (%check :cb-req-continue (eq status :continue)
                                              (format nil "requester step (FC2 ok) status ~a" status))
                                      (%check :cb-final-tok (not (null final-tok))
                                              "requester must produce a Final token")
                                      (when final-tok
                                        (let ((fs (nth-value 1 (dds.security:process-handshake
                                                                rep-hdl final-tok))))
                                          (%check :cb-replier-auth (eq fs :authenticated)
                                                  (format nil "replier Final status ~a" fs))))
                                      (let ((ss-a (dds.security:handshake-shared-secret req-hdl))
                                            (ss-b (dds.security:handshake-shared-secret rep-hdl)))
                                        (%check :cb-ss-equal
                                                (and ss-a ss-b
                                                     (equalp (dds.security:shared-secret-bytes ss-a)
                                                             (dds.security:shared-secret-bytes ss-b)))
                                                "SharedSecrets must be byte-equal after bound handshake")))
                                 (dds.security:free-handshake-handle rep-hdl))))
                        (dds.security:free-handshake-handle req-hdl)))
                    ;; --- (c) NEG-REPLIER: wrong expected-challenge1 -> reject (values NIL NIL) ---
                    (multiple-value-bind (req-tok2 req-hdl2)
                        (dds.security:begin-handshake-request
                         id-a id-b dds.security:+suite-ecdh+
                         (make-array 0 :element-type '(unsigned-byte 8)) fc1)
                      (unwind-protect
                           (multiple-value-bind (rep-tok2 rep-hdl2)
                               (dds.security:begin-handshake-reply
                                id-b id-a req-tok2 dds.security:+suite-ecdh+
                                (make-array 0 :element-type '(unsigned-byte 8))
                                (%challenge-differs fc1) fc2)
                             (%check :cb-neg-replier (and (null rep-tok2) (null rep-hdl2))
                                     "replier MUST reject when challenge1 != expected future_challenge")
                             (when rep-hdl2 (dds.security:free-handshake-handle rep-hdl2)))
                        (dds.security:free-handshake-handle req-hdl2)))
                    ;; --- (d) NEG-REQUESTER: wrong expected-challenge2 -> :rejected ---
                    (multiple-value-bind (req-tok3 req-hdl3)
                        (dds.security:begin-handshake-request
                         id-a id-b dds.security:+suite-ecdh+
                         (make-array 0 :element-type '(unsigned-byte 8)) fc1)
                      (unwind-protect
                           (multiple-value-bind (rep-tok3 rep-hdl3)
                               (dds.security:begin-handshake-reply
                                id-b id-a req-tok3 dds.security:+suite-ecdh+
                                (make-array 0 :element-type '(unsigned-byte 8)) fc1 fc2)
                             (unwind-protect
                                  (let ((st (nth-value 1 (dds.security:process-handshake
                                                          req-hdl3 rep-tok3 (%challenge-differs fc2)))))
                                    (%check :cb-neg-requester (eq st :rejected)
                                            (format nil "requester MUST reject on wrong FC2 (status ~a)" st)))
                               (when rep-hdl3 (dds.security:free-handshake-handle rep-hdl3))))
                        (dds.security:free-handshake-handle req-hdl3)))
                    ;; --- (e) ABSENCE-TOLERANCE: expected-challenge1 NIL accepts the bound request ---
                    (multiple-value-bind (req-tok4 req-hdl4)
                        (dds.security:begin-handshake-request
                         id-a id-b dds.security:+suite-ecdh+
                         (make-array 0 :element-type '(unsigned-byte 8)) fc1)
                      (unwind-protect
                           (multiple-value-bind (rep-tok4 rep-hdl4)
                               (dds.security:begin-handshake-reply
                                id-b id-a req-tok4 dds.security:+suite-ecdh+
                                (make-array 0 :element-type '(unsigned-byte 8)) nil nil)
                             (%check :cb-absence-ok (and rep-tok4 rep-hdl4)
                                     "replier with NIL expected-challenge1 must ACCEPT (absence-tolerance)")
                             (when rep-hdl4 (dds.security:free-handshake-handle rep-hdl4)))
                        (dds.security:free-handshake-handle req-hdl4))))
               (dds.security:free-identity-handle id-b)))
        (dds.security:free-identity-handle id-a))))
  t)

(defun* run-auth-token-corpus-test ()
    (function () t)
  "T4 token self-consistency corpus for the internal handshake token format.
   Token format: internal in-process tagged binary (magic #xD0 #xDD #x53 #x70 | LE fields).
   This is NOT a CDR DataHolder / ParticipantStatelessMessage wire vector — that Connext-interop
   byte-match is deferred to Slice 5. This test locks the INTERNAL serializer round-trip
   and structural invariants (class_id presence, prop set, field ordering) for regression.
   Nonces and ephemeral DH keys are non-deterministic; we assert structural invariants +
   round-trip identity rather than full byte-exact vectors.
   Both SBCL and Clasp must pass."
  (handler-case (dds.dare:dare-available-p)
    (dds.dare:dare-unavailable (c)
      (format t "~&  [auth-token-corpus] SKIP — OpenSSL >= 3.5 not available: ~a~%"
              (dds.dare:dare-unavailable-reason c))
      (return-from run-auth-token-corpus-test t)))

  (let* ((ca-pem    (%read-fixture-pem "ca/ca-cert.pem"))
         (ec-cert-a (%read-fixture-pem "participant_ec/identity_cert.pem"))
         (ec-key-a  (%read-fixture-pem "participant_ec/identity_key.pem"))
         (ec-cert-b (%read-fixture-pem "participant_ec_b/identity_cert.pem"))
         (ec-key-b  (%read-fixture-pem "participant_ec_b/identity_key.pem"))
         (guid-a    (make-array 16 :element-type '(unsigned-byte 8)
                                   :initial-contents '(1 2 3 4 5 6 7 8 9 10 11 12 13 14 15 16)))
         (guid-b    (make-array 16 :element-type '(unsigned-byte 8)
                                   :initial-contents '(200 2 3 4 5 6 7 8 9 10 11 12 13 14 15 16))))

    (multiple-value-bind (id-a reason-a)
        (dds.security:validate-local-identity ca-pem ec-cert-a ec-key-a guid-a)
      (%check :corpus-id-a-ok (not (null id-a)) (format nil "corpus EC-A failed: ~a" reason-a))
      (unless id-a (return-from run-auth-token-corpus-test t))
      (unwind-protect
           (multiple-value-bind (id-b reason-b)
               (dds.security:validate-local-identity ca-pem ec-cert-b ec-key-b guid-b)
             (%check :corpus-id-b-ok (not (null id-b)) (format nil "corpus EC-B failed: ~a" reason-b))
             (unless id-b (return-from run-auth-token-corpus-test t))
             (unwind-protect
                  (progn
                    ;; ---- Request token structural invariants ----
                    (multiple-value-bind (req-tok req-hdl)
                        (dds.security:begin-handshake-request id-a id-b dds.security:+suite-ecdh+)
                      (unwind-protect
                           (progn
                             (%check :corpus-req-non-empty (> (length req-tok) 4)
                                     "Request token must be > 4 bytes")
                             ;; magic bytes must be present at offset 0
                             (%check :corpus-req-magic-0 (= (aref req-tok 0) dds.security::+token-magic-0+)
                                     "Request token byte-0 != magic-0")
                             (%check :corpus-req-magic-1 (= (aref req-tok 1) dds.security::+token-magic-1+)
                                     "Request token byte-1 != magic-1")
                             (%check :corpus-req-magic-2 (= (aref req-tok 2) dds.security::+token-magic-2+)
                                     "Request token byte-2 != magic-2")
                             (%check :corpus-req-magic-3 (= (aref req-tok 3) dds.security::+token-magic-3+)
                                     "Request token byte-3 != magic-3")
                             ;; round-trip: parse -> re-serialize -> same bytes
                             (let ((rt-tok (dds.security::%parse-token req-tok)))
                               (%check :corpus-req-parse-ok (not (null rt-tok))
                                       "Request token failed round-trip parse")
                               (when rt-tok
                                 ;; class_id must be the Req string
                                 (%check :corpus-req-class-id
                                         (string= (dds.security::handshake-token-class-id rt-tok)
                                                  dds.security::+handshake-request-class-id+)
                                         (format nil "Request class_id '~a' != +handshake-request-class-id+"
                                                 (dds.security::handshake-token-class-id rt-tok)))
                                 ;; must carry all 8 required Request properties (§9.3.2.1)
                                 (let ((names (mapcar #'car (dds.security::handshake-token-binary-props rt-tok))))
                                   (%check :corpus-req-prop-count (= (length names) 8)
                                           (format nil "Request has ~d props, expected 8" (length names)))
                                   (dolist (expected-name (list dds.security::+prop-c-id+
                                                                dds.security::+prop-c-perm+
                                                                dds.security::+prop-c-pdata+
                                                                dds.security::+prop-c-dsign-algo+
                                                                dds.security::+prop-c-kagree-algo+
                                                                dds.security::+prop-hash-c1+
                                                                dds.security::+prop-dh1+
                                                                dds.security::+prop-challenge1+))
                                     (%check (intern (format nil "CORPUS-REQ-HAS-~a" expected-name) :keyword)
                                             (member expected-name names :test #'string=)
                                             (format nil "Request missing property '~a'" expected-name))))
                                 ;; re-serialized bytes must be byte-identical to the original
                                 (let ((reser (dds.security::%serialize-token rt-tok)))
                                   (%check :corpus-req-roundtrip-bytes (equalp req-tok reser)
                                           (format nil "Request round-trip byte mismatch (len ~d vs ~d)"
                                                   (length req-tok) (length reser))))))

                             ;; ---- Reply token structural invariants ----
                             (multiple-value-bind (rep-tok rep-hdl)
                                 (dds.security:begin-handshake-reply id-b id-a req-tok dds.security:+suite-ecdh+)
                               (unwind-protect
                                    (progn
                                      (%check :corpus-rep-non-empty (> (length rep-tok) 4)
                                              "Reply token must be > 4 bytes")
                                      (%check :corpus-rep-magic-0 (= (aref rep-tok 0) dds.security::+token-magic-0+)
                                              "Reply token byte-0 != magic-0")
                                      (let ((rt-rep (dds.security::%parse-token rep-tok)))
                                        (%check :corpus-rep-parse-ok (not (null rt-rep))
                                                "Reply token failed round-trip parse")
                                        (when rt-rep
                                          (%check :corpus-rep-class-id
                                                  (string= (dds.security::handshake-token-class-id rt-rep)
                                                           dds.security::+handshake-reply-class-id+)
                                                  (format nil "Reply class_id '~a' != +handshake-reply-class-id+"
                                                          (dds.security::handshake-token-class-id rt-rep)))
                                          ;; Reply must carry 12 properties (§9.3.2.2: c.id..signature)
                                          (let ((rep-names (mapcar #'car (dds.security::handshake-token-binary-props rt-rep))))
                                            (%check :corpus-rep-prop-count (= (length rep-names) 12)
                                                    (format nil "Reply has ~d props, expected 12" (length rep-names)))
                                            (dolist (expected (list dds.security::+prop-c-id+
                                                                     dds.security::+prop-hash-c2+
                                                                     dds.security::+prop-dh2+
                                                                     dds.security::+prop-challenge2+
                                                                     dds.security::+prop-signature+))
                                              (%check (intern (format nil "CORPUS-REP-HAS-~a" expected) :keyword)
                                                      (member expected rep-names :test #'string=)
                                                      (format nil "Reply missing property '~a'" expected))))
                                          ;; round-trip: re-serialized bytes identical
                                          (let ((reser-rep (dds.security::%serialize-token rt-rep)))
                                            (%check :corpus-rep-roundtrip-bytes (equalp rep-tok reser-rep)
                                                    (format nil "Reply round-trip mismatch (~d vs ~d)"
                                                            (length rep-tok) (length reser-rep))))))

                                      ;; ---- Final token structural invariants ----
                                      (multiple-value-bind (final-tok final-status)
                                          (dds.security:process-handshake req-hdl rep-tok)
                                        (%check :corpus-final-status-continue (eq final-status :continue)
                                                (format nil "corpus: process-handshake req status ~a" final-status))
                                        (%check :corpus-final-non-empty (and final-tok (> (length final-tok) 4))
                                                "Final token must be > 4 bytes")
                                        (when final-tok
                                          (%check :corpus-final-magic-0 (= (aref final-tok 0) dds.security::+token-magic-0+)
                                                  "Final token byte-0 != magic-0")
                                          (let ((rt-fin (dds.security::%parse-token final-tok)))
                                            (%check :corpus-final-parse-ok (not (null rt-fin))
                                                    "Final token failed round-trip parse")
                                            (when rt-fin
                                              (%check :corpus-final-class-id
                                                      (string= (dds.security::handshake-token-class-id rt-fin)
                                                               dds.security::+handshake-final-class-id+)
                                                      (format nil "Final class_id '~a' != +handshake-final-class-id+"
                                                              (dds.security::handshake-token-class-id rt-fin)))
                                              ;; Final has 7 properties (§9.3.2.3)
                                              (let ((fin-names (mapcar #'car (dds.security::handshake-token-binary-props rt-fin))))
                                                (%check :corpus-final-prop-count (= (length fin-names) 7)
                                                        (format nil "Final has ~d props, expected 7" (length fin-names)))
                                                (dolist (expected (list dds.security::+prop-hash-c1+
                                                                         dds.security::+prop-hash-c2+
                                                                         dds.security::+prop-dh1+
                                                                         dds.security::+prop-dh2+
                                                                         dds.security::+prop-signature+))
                                                  (%check (intern (format nil "CORPUS-FIN-HAS-~a" expected) :keyword)
                                                          (member expected fin-names :test #'string=)
                                                          (format nil "Final missing property '~a'" expected))))
                                              ;; round-trip
                                              (let ((reser-fin (dds.security::%serialize-token rt-fin)))
                                                (%check :corpus-final-roundtrip-bytes (equalp final-tok reser-fin)
                                                        (format nil "Final round-trip mismatch (~d vs ~d)"
                                                                (length final-tok) (length reser-fin)))))))))
                                 (dds.security:free-handshake-handle rep-hdl))))
                        (dds.security:free-handshake-handle req-hdl))))
               (dds.security:free-identity-handle id-b)))
        (dds.security:free-identity-handle id-a))))
  t)

;;; Safety-0 compiled fuzz helper — compiled separately so (safety 0) applies to the inner loop.
;;; process-handshake itself is NOT safety-0 compiled; we just drive it from a tight loop
;;; that itself runs at (safety 0). This is the same pattern as run-security-payload-fuzz-test.

(defun* %fuzz-process-handshake-loop (handle blobs)
    (function (dds.security:handshake-handle list) (unsigned-byte 32))
  "Feed each blob in BLOBS through process-handshake on HANDLE; return the count that returned :rejected.
   Compiled at (safety 0) for the inner loop to exercise the parser under declarations-off optimization.
   The handle is reset to :awaiting-reply before each call to ensure it is always processable."
  (declare (optimize (safety 0) (speed 3)))
  (let ((rejected-count 0))
    (declare (type (unsigned-byte 32) rejected-count))
    (dolist (blob blobs rejected-count)
      (setf (dds.security::handshake-handle-state handle) :awaiting-reply)
      (multiple-value-bind (tok-out status)
          (dds.security:process-handshake handle blob)
        (declare (ignore tok-out))
        (when (eq status :rejected)
          (incf rejected-count))))))

(defun* run-auth-token-fuzz-test ()
    (function () t)
  "T4 parser fuzz: N=2000 malformed/short/oversized/random token blobs through process-handshake.
   Tests BOTH a normal-optimization path AND a (safety 0) compiled inner loop (NFR-SEC-POSTURE).
   Invariant: every input returns (:rejected NIL) or equivalent — never OOB, never crash, never throw.
   Uses a deterministic seed (make-random-state nil, xorshift-like index-based fill, no Date.now).
   Requires OpenSSL >= 3.5; skips gracefully if absent. Both SBCL and Clasp must pass."
  (handler-case (dds.dare:dare-available-p)
    (dds.dare:dare-unavailable (c)
      (format t "~&  [auth-token-fuzz] SKIP — OpenSSL >= 3.5 not available: ~a~%"
              (dds.dare:dare-unavailable-reason c))
      (return-from run-auth-token-fuzz-test t)))

  (let* ((ca-pem    (%read-fixture-pem "ca/ca-cert.pem"))
         (ec-cert-a (%read-fixture-pem "participant_ec/identity_cert.pem"))
         (ec-key-a  (%read-fixture-pem "participant_ec/identity_key.pem"))
         (ec-cert-b (%read-fixture-pem "participant_ec_b/identity_cert.pem"))
         (ec-key-b  (%read-fixture-pem "participant_ec_b/identity_key.pem"))
         (guid-a    (make-array 16 :element-type '(unsigned-byte 8)
                                   :initial-contents '(1 2 3 4 5 6 7 8 9 10 11 12 13 14 15 16)))
         (guid-b    (make-array 16 :element-type '(unsigned-byte 8)
                                   :initial-contents '(200 2 3 4 5 6 7 8 9 10 11 12 13 14 15 16))))

    (multiple-value-bind (id-a reason-a)
        (dds.security:validate-local-identity ca-pem ec-cert-a ec-key-a guid-a)
      (%check :fuzz-id-a-ok (not (null id-a)) (format nil "fuzz EC-A failed: ~a" reason-a))
      (unless id-a (return-from run-auth-token-fuzz-test t))
      (unwind-protect
           (multiple-value-bind (id-b reason-b)
               (dds.security:validate-local-identity ca-pem ec-cert-b ec-key-b guid-b)
             (%check :fuzz-id-b-ok (not (null id-b)) (format nil "fuzz EC-B failed: ~a" reason-b))
             (unless id-b (return-from run-auth-token-fuzz-test t))
             (unwind-protect
                  (multiple-value-bind (req-tok-fuzz req-hdl-fuzz rep-tok-fuzz rep-hdl-fuzz)
                      (%run-ecdh-happy-path id-a id-b)
                    (declare (ignore req-tok-fuzz rep-tok-fuzz))
                    ;; acquire rep-hdl-fuzz as a permanent template then immediately free it:
                    ;; we use req-hdl-fuzz (in :awaiting-reply) for all fuzz iterations
                    (dds.security:free-handshake-handle rep-hdl-fuzz)
                    (unwind-protect
                         (let ((fuzz-count 0)
                               (fuzz-blobs '()))

                           ;; Build 2000 deterministic blobs (no random-state surprises across runs)

                           ;; Case A (44 blobs): zero-length through 43-byte, all zeros
                           (dotimes (len 44)
                             (push (make-array len :element-type '(unsigned-byte 8) :initial-element 0) fuzz-blobs))

                           ;; Case B (50 blobs): magic header + various garbage bodies (sizes 4..53)
                           (dotimes (k 50)
                             (let* ((sz (+ 4 k))
                                    (b  (make-array sz :element-type '(unsigned-byte 8) :initial-element 0)))
                               (setf (aref b 0) #xD0 (aref b 1) #xDD
                                     (aref b 2) #x53 (aref b 3) #x70)
                               (push b fuzz-blobs)))

                           ;; Case C: 1906 deterministic "random" blobs of size 60, 128, 256, 512, 1024
                           (let ((sizes '(60 128 256 512 1024)))
                             (dotimes (idx 1906)
                               (let* ((sz   (nth (mod idx (length sizes)) sizes))
                                      (blob (make-array sz :element-type '(unsigned-byte 8))))
                                 ;; deterministic fill: byte[i] = (i * idx + 37) mod 256
                                 (dotimes (i sz)
                                   (setf (aref blob i)
                                         (ldb (byte 8 0) (+ (* i (1+ idx)) 37))))
                                 (push blob fuzz-blobs))))

                           (setf fuzz-blobs (nreverse fuzz-blobs))
                           (setf fuzz-count (length fuzz-blobs))

                           ;; Normal-optimization pass: every blob must return :rejected
                           (let ((normal-rejected 0))
                             (declare (type (unsigned-byte 32) normal-rejected))
                             (dolist (blob fuzz-blobs)
                               (handler-case
                                   (progn
                                     (setf (dds.security::handshake-handle-state req-hdl-fuzz) :awaiting-reply)
                                     (multiple-value-bind (tok-out status)
                                         (dds.security:process-handshake req-hdl-fuzz blob)
                                       (declare (ignore tok-out))
                                       (%check :fuzz-normal-closed
                                               (eq status :rejected)
                                               (format nil "fuzz normal: blob returned ~a (expect :rejected)" status))
                                       (when (eq status :rejected)
                                         (incf normal-rejected))))
                                 (error (e)
                                   (error 'test-failure :name :fuzz-normal-escaped
                                          :detail (format nil "fuzz normal: signal escaped: ~a" e)))))
                             (%check :fuzz-normal-all-rejected (= normal-rejected fuzz-count)
                                     (format nil "fuzz normal: ~d of ~d blobs rejected (expect all)"
                                             normal-rejected fuzz-count)))

                           ;; safety-0 compiled pass via %fuzz-process-handshake-loop
                           (let ((safety0-rejected
                                   (handler-case
                                       (%fuzz-process-handshake-loop req-hdl-fuzz fuzz-blobs)
                                     (error (e)
                                       (error 'test-failure :name :fuzz-safety0-escaped
                                              :detail (format nil "fuzz safety-0: signal escaped: ~a" e))))))
                             ;; All 2000 blobs must be :rejected under the safety-0 path
                             (%check :fuzz-safety0-all-rejected (= safety0-rejected fuzz-count)
                                     (format nil "fuzz safety-0: ~d of ~d blobs rejected (expect all)"
                                             safety0-rejected fuzz-count)))

                           (format t "~&  [auth-token-fuzz] ~d blobs exercised (normal + safety-0)~%"
                                   fuzz-count))
                      (dds.security:free-handshake-handle req-hdl-fuzz)))
               (dds.security:free-identity-handle id-b)))
        (dds.security:free-identity-handle id-a))))
  t)

(defun* run-auth-handshake-ecdh-test ()
    (function () t)
  "DDS-Security 1.1 §8.7.2.4 three-message PKI-DH handshake + §9.3.3 SharedSecret.
   Happy-path: participant_ec (GUID-A < GUID-B) is requester; participant_ec_b is replier.
   Full Request->Reply->Final: both handles -> :authenticated; SharedSecrets byte-equal.
   Negative (a): tampered reply signature -> requester returns :rejected.
   Negative (b): tampered Final -> replier returns :rejected. Both SBCL and Clasp must pass."
  (handler-case (dds.dare:dare-available-p)
    (dds.dare:dare-unavailable (c)
      (format t "~&  [auth-handshake-ecdh] SKIP: ~a~%" (dds.dare:dare-unavailable-reason c))
      (return-from run-auth-handshake-ecdh-test t)))
  (let* ((ca-pem    (%read-fixture-pem "ca/ca-cert.pem"))
         (ec-cert-a (%read-fixture-pem "participant_ec/identity_cert.pem"))
         (ec-key-a  (%read-fixture-pem "participant_ec/identity_key.pem"))
         (ec-cert-b (%read-fixture-pem "participant_ec_b/identity_cert.pem"))
         (ec-key-b  (%read-fixture-pem "participant_ec_b/identity_key.pem"))
         (guid-a    (make-array 16 :element-type '(unsigned-byte 8)
                                   :initial-contents '(1 2 3 4 5 6 7 8 9 10 11 12 13 14 15 16)))
         (guid-b    (make-array 16 :element-type '(unsigned-byte 8)
                                   :initial-contents '(200 2 3 4 5 6 7 8 9 10 11 12 13 14 15 16))))
    (multiple-value-bind (id-a reason-a)
        (dds.security:validate-local-identity ca-pem ec-cert-a ec-key-a guid-a)
      (%check :hs-id-a-ok (not (null id-a))
              (format nil "validate-local-identity A failed: ~a" reason-a))
      (unless id-a (return-from run-auth-handshake-ecdh-test t))
      (unwind-protect
           (multiple-value-bind (id-b reason-b)
               (dds.security:validate-local-identity ca-pem ec-cert-b ec-key-b guid-b)
             (%check :hs-id-b-ok (not (null id-b))
                     (format nil "validate-local-identity B failed: ~a" reason-b))
             (unless id-b (return-from run-auth-handshake-ecdh-test t))
             (unwind-protect
                  (progn
                    ;; === Happy-path ===
                    (multiple-value-bind (req-tok req-hdl)
                        (dds.security:begin-handshake-request id-a id-b dds.security:+suite-ecdh+)
                      (%check :hs-req-tok-ok (and req-tok (> (length req-tok) 0))
                              "begin-handshake-request returned empty token")
                      (%check :hs-req-hdl-ok (not (null req-hdl)) "begin-handshake-request nil handle")
                      (unwind-protect
                           (multiple-value-bind (rep-tok rep-hdl)
                               (dds.security:begin-handshake-reply id-b id-a req-tok dds.security:+suite-ecdh+)
                             (%check :hs-rep-tok-ok (and rep-tok (> (length rep-tok) 0))
                                     "begin-handshake-reply returned empty token")
                             (%check :hs-rep-hdl-ok (not (null rep-hdl)) "begin-handshake-reply nil handle")
                             (unwind-protect
                                  (multiple-value-bind (final-tok req-status)
                                      (dds.security:process-handshake req-hdl rep-tok)
                                    (%check :hs-final-tok-ok (and final-tok (> (length final-tok) 0))
                                            "process-handshake(req,reply) returned empty final")
                                    (%check :hs-req-continue (eq req-status :continue)
                                            (format nil "process-handshake(req,reply) status ~a != :continue" req-status))
                                    (%check :hs-req-state (eq (dds.security:handshake-handle-state req-hdl) :authenticated)
                                            "requester state not :authenticated after Final generation")
                                    (multiple-value-bind (nil-tok rep-status)
                                        (dds.security:process-handshake rep-hdl final-tok)
                                      (%check :hs-rep-auth (eq rep-status :authenticated)
                                              (format nil "process-handshake(rep,final) status ~a != :authenticated" rep-status))
                                      (%check :hs-rep-nil-tok (null nil-tok)
                                              "process-handshake(rep,final) must return nil token")
                                      (let ((ss-req (dds.security:handshake-shared-secret req-hdl))
                                            (ss-rep (dds.security:handshake-shared-secret rep-hdl)))
                                        (%check :hs-req-ss-ok (not (null ss-req)) "requester SharedSecret nil")
                                        (%check :hs-rep-ss-ok (not (null ss-rep)) "replier SharedSecret nil")
                                        (when (and ss-req ss-rep)
                                          (let ((b-req (dds.security:shared-secret-bytes ss-req))
                                                (b-rep (dds.security:shared-secret-bytes ss-rep)))
                                            (%check :hs-ss-len-req (= (length b-req) 32)
                                                    (format nil "req SharedSecret length ~d != 32" (length b-req)))
                                            (%check :hs-ss-len-rep (= (length b-rep) 32)
                                                    (format nil "rep SharedSecret length ~d != 32" (length b-rep)))
                                            (%check :hs-ss-equal (equalp b-req b-rep)
                                                    "SharedSecret mismatch req vs rep"))))))
                               (dds.security:free-handshake-handle rep-hdl)))
                        (dds.security:free-handshake-handle req-hdl)))
                    ;; === Negative (a): tampered reply -> requester rejects ===
                    (multiple-value-bind (req-tok-n req-hdl-n)
                        (dds.security:begin-handshake-request id-a id-b dds.security:+suite-ecdh+)
                      (multiple-value-bind (rep-tok-n rep-hdl-n)
                          (dds.security:begin-handshake-reply id-b id-a req-tok-n dds.security:+suite-ecdh+)
                        (unwind-protect
                             (let* ((tampered (copy-seq rep-tok-n))
                                    (last-idx (1- (length tampered))))
                               (setf (aref tampered last-idx) (logxor (aref tampered last-idx) #xFF))
                               (multiple-value-bind (tok-ignore neg-a-status)
                                   (dds.security:process-handshake req-hdl-n tampered)
                                 (declare (ignore tok-ignore))
                                 (%check :hs-neg-a-rejected (eq neg-a-status :rejected)
                                         (format nil "tampered reply -> ~a (expected :rejected)" neg-a-status))))
                          (dds.security:free-handshake-handle rep-hdl-n)
                          (dds.security:free-handshake-handle req-hdl-n))))
                    ;; === Negative (b): tampered Final -> replier rejects ===
                    (multiple-value-bind (req-tok-b req-hdl-b)
                        (dds.security:begin-handshake-request id-a id-b dds.security:+suite-ecdh+)
                      (multiple-value-bind (rep-tok-b rep-hdl-b)
                          (dds.security:begin-handshake-reply id-b id-a req-tok-b dds.security:+suite-ecdh+)
                        (unwind-protect
                             (multiple-value-bind (final-tok-b _status-b)
                                 (dds.security:process-handshake req-hdl-b rep-tok-b)
                               (declare (ignore _status-b))
                               (let* ((tampered-f (copy-seq final-tok-b))
                                      (last-idx   (1- (length tampered-f))))
                                 (setf (aref tampered-f last-idx) (logxor (aref tampered-f last-idx) #xFF))
                                 (multiple-value-bind (tok-ignore neg-b-status)
                                     (dds.security:process-handshake rep-hdl-b tampered-f)
                                   (declare (ignore tok-ignore))
                                   (%check :hs-neg-b-rejected (eq neg-b-status :rejected)
                                           (format nil "tampered Final -> ~a (expected :rejected)" neg-b-status)))))
                          (dds.security:free-handshake-handle rep-hdl-b)
                          (dds.security:free-handshake-handle req-hdl-b)))))
               (dds.security:free-identity-handle id-b)))
        (dds.security:free-identity-handle id-a))))
  t)

(defun* run-auth-spdp-identity-token-test ()
    (function () t)
  "WP-DDS-SECURITY-AUTH-2BI T1: PID_IDENTITY_TOKEN + PSM endpoint-set bits in SPDP.
   (a) WITH token: serialize-spdp-data -> parse-spdp-data round-trips the token bytes exactly
       and the parsed builtin-endpoint-set has both PSM bits (22 and 23) set.
   (b) DEFAULT-OFF byte-identical: identity-token-octets NIL -> no PID_IDENTITY_TOKEN in
       the serialized bytes, and the parsed builtin-endpoint-set lacks both PSM bits.
   Requires OpenSSL >= 3.5 for the fixture IdentityToken; skips gracefully if absent."
  (handler-case (dds.dare:dare-available-p)
    (dds.dare:dare-unavailable (c)
      (format t "~&  [auth-spdp-identity-token] SKIP — OpenSSL >= 3.5 not available: ~a~%"
              (dds.dare:dare-unavailable-reason c))
      (return-from run-auth-spdp-identity-token-test t)))

  ;; Acquire a fixture IdentityToken from validate-local-identity on the EC fixture.
  (let* ((ca-pem      (%read-fixture-pem "ca/ca-cert.pem"))
         (ec-cert-pem (%read-fixture-pem "participant_ec/identity_cert.pem"))
         (ec-key-pem  (%read-fixture-pem "participant_ec/identity_key.pem"))
         (guid-a      (make-array 16 :element-type '(unsigned-byte 8)
                                     :initial-contents '(1 2 3 4 5 6 7 8 9 10 11 12 13 14 15 16))))
    (multiple-value-bind (handle reason)
        (dds.security:validate-local-identity ca-pem ec-cert-pem ec-key-pem guid-a)
      (%check :spdp-tok-handle-ok (not (null handle))
              (format nil "validate-local-identity failed: ~a" reason))
      (when (null handle) (return-from run-auth-spdp-identity-token-test t))
      (unwind-protect
           (let* ((tok-octets (dds.security:identity-token handle))
                  ;; --- (a) WITH token ---
                  (prefix (make-array 12 :element-type '(unsigned-byte 8)
                                         :initial-contents '(1 2 3 4 5 6 7 8 9 10 11 12)))
                  (ep-set-with (logior dds.rtps.discovery:+builtin-endpoint-set-default+
                                       dds.rtps.discovery:+be-participant-stateless-writer+
                                       dds.rtps.discovery:+be-participant-stateless-reader+))
                  (data-with (dds.rtps.discovery:make-spdp-data
                              :guid-prefix prefix
                              :version-major 2 :version-minor 5
                              :vendor-id #x010F
                              :lease-duration-seconds 100
                              :builtin-endpoint-set ep-set-with
                              :identity-token-octets tok-octets))
                  (ob-with (dds.core.buffer:make-octet-buffer 2048))
                  (wc-with (dds.core.buffer:cursor ob-with :endianness :little)))
             (dds.rtps.discovery:serialize-spdp-data wc-with data-with)
             (let* ((rc-with (dds.core.buffer:cursor ob-with :endianness :little))
                    (parsed-with (dds.rtps.discovery:parse-spdp-data rc-with)))
               (%check :spdp-tok-parsed-non-nil (not (null parsed-with))
                       "parse-spdp-data returned NIL on WITH-token data")
               (when parsed-with
                 (%check :spdp-tok-round-trip
                         (equalp (dds.rtps.discovery:spdp-data-identity-token-octets parsed-with)
                                 tok-octets)
                         (format nil "identity-token-octets mismatch after round-trip (len ~d vs ~d)"
                                 (length (dds.rtps.discovery:spdp-data-identity-token-octets parsed-with))
                                 (length tok-octets)))
                 (%check :spdp-tok-psm-writer-bit
                         (logtest (dds.rtps.discovery:spdp-data-builtin-endpoint-set parsed-with)
                                  dds.rtps.discovery:+be-participant-stateless-writer+)
                         "parsed builtin-endpoint-set missing +be-participant-stateless-writer+ (bit 22)")
                 (%check :spdp-tok-psm-reader-bit
                         (logtest (dds.rtps.discovery:spdp-data-builtin-endpoint-set parsed-with)
                                  dds.rtps.discovery:+be-participant-stateless-reader+)
                         "parsed builtin-endpoint-set missing +be-participant-stateless-reader+ (bit 23)")))

             ;; --- (b) DEFAULT-OFF: no token, no PSM bits, byte-identical ---
             (let* ((data-off (dds.rtps.discovery:make-spdp-data
                               :guid-prefix prefix
                               :version-major 2 :version-minor 5
                               :vendor-id #x010F
                               :lease-duration-seconds 100
                               :builtin-endpoint-set dds.rtps.discovery:+builtin-endpoint-set-default+))
                    (ob-off (dds.core.buffer:make-octet-buffer 2048))
                    (wc-off (dds.core.buffer:cursor ob-off :endianness :little)))
               (dds.rtps.discovery:serialize-spdp-data wc-off data-off)
               (let* ((rc-off (dds.core.buffer:cursor ob-off :endianness :little))
                      (parsed-off (dds.rtps.discovery:parse-spdp-data rc-off)))
                 (%check :spdp-off-parsed-non-nil (not (null parsed-off))
                         "parse-spdp-data returned NIL on DEFAULT-OFF data")
                 (when parsed-off
                   (%check :spdp-off-no-token
                           (null (dds.rtps.discovery:spdp-data-identity-token-octets parsed-off))
                           "identity-token-octets must be NIL in DEFAULT-OFF path")
                   (%check :spdp-off-no-psm-writer
                           (not (logtest (dds.rtps.discovery:spdp-data-builtin-endpoint-set parsed-off)
                                         dds.rtps.discovery:+be-participant-stateless-writer+))
                           "DEFAULT-OFF must NOT have +be-participant-stateless-writer+ bit")
                   (%check :spdp-off-no-psm-reader
                           (not (logtest (dds.rtps.discovery:spdp-data-builtin-endpoint-set parsed-off)
                                         dds.rtps.discovery:+be-participant-stateless-reader+))
                           "DEFAULT-OFF must NOT have +be-participant-stateless-reader+ bit")
                   (%check :spdp-off-endpoint-set-exact
                           (= (dds.rtps.discovery:spdp-data-builtin-endpoint-set parsed-off)
                              dds.rtps.discovery:+builtin-endpoint-set-default+)
                           (format nil "DEFAULT-OFF builtin-endpoint-set ~d != +builtin-endpoint-set-default+ ~d"
                                   (dds.rtps.discovery:spdp-data-builtin-endpoint-set parsed-off)
                                   dds.rtps.discovery:+builtin-endpoint-set-default+))))))
        (dds.security:free-identity-handle handle))))
  t)

;;; ============================================================
;;; T2: §9.3.4 DataHolder + §7.4.4 ParticipantGenericMessage wire codec
;;; ============================================================

;;; Self-consistency byte corpus: CDR-LE DataHolder leading bytes for class_id "DDS:Auth:PKI-DH:1.0+Req".
;;; class_id CDR-LE encoding: u32-LE(len+1=25) | "DDS:Auth:PKI-DH:1.0+Req" | NUL | 3-pad
;;; u32-LE(25) = 19 00 00 00; then 24 ASCII chars + NUL = 25 bytes; pad = (4 - 25%4)%4 = 3.
;;; So bytes 0..31: 19 00 00 00 44 44 53 3a ... 52 65 71 00 [pad 00 00 00]
;;; PropertySeq count=0: bytes 32..35: 00 00 00 00
;;; This vector covers only the first 36 bytes (class_id + PropSeq-count).
(defparameter +dataholder-req-prefix-vector+
    (let* ((class-id "DDS:Auth:PKI-DH:1.0+Req")
           (cid-len  (1+ (length class-id)))           ; 25 (includes NUL)
           (cid-pad  (mod (- 4 (mod cid-len 4)) 4))   ; pad to 4 = 3
           (total    (+ 4 cid-len cid-pad 4))          ; u32 + cid+NUL+pad + PropSeq-count-u32 = 36
           (v        (make-array total :element-type '(unsigned-byte 8) :initial-element 0)))
      ;; u32-LE(cid-len)
      (setf (aref v 0) (ldb (byte 8  0) cid-len)
            (aref v 1) (ldb (byte 8  8) cid-len)
            (aref v 2) (ldb (byte 8 16) cid-len)
            (aref v 3) (ldb (byte 8 24) cid-len))
      ;; ASCII bytes
      (dotimes (i (length class-id))
        (setf (aref v (+ 4 i)) (char-code (char class-id i))))
      ;; NUL already 0 at offset (+ 4 (length class-id)); pad bytes already 0
      ;; PropSeq count = 0 at bytes (+ 4 cid-len cid-pad)..+3 (already 0)
      v)
  "Self-consistency byte corpus: CDR-LE DataHolder class_id prefix + PropSeq count=0 for +Req (36 bytes).")

(defun* run-auth-wire-codec-test ()
    (function () t)
  "WP-DDS-SECURITY-AUTH-2BI T2: §9.3.4 DataHolder + §7.4.4 ParticipantGenericMessage wire codec.
   (a) Round-trip fidelity: Request token -> handshake-token->dataholder -> dataholder->handshake-token
       -> the reconstructed token drives begin-handshake-reply on the peer to the SAME next state.
   (b) ParticipantGenericMessage round-trip: make-generic-message -> parse-generic-message ->
       message-class-id + GUIDs + DataHolder list round-trip byte-identically.
   (c) Self-consistency prefix: DataHolder leading bytes match the T0-pinned CDR-LE layout
       (the locked +dataholder-req-prefix-vector+ above).
   Requires OpenSSL >= 3.5; skips gracefully if absent. Both SBCL and Clasp must pass."
  (handler-case (dds.dare:dare-available-p)
    (dds.dare:dare-unavailable (c)
      (format t "~&  [auth-wire-codec] SKIP — OpenSSL >= 3.5 not available: ~a~%"
              (dds.dare:dare-unavailable-reason c))
      (return-from run-auth-wire-codec-test t)))

  (let* ((ca-pem    (%read-fixture-pem "ca/ca-cert.pem"))
         (ec-cert-a (%read-fixture-pem "participant_ec/identity_cert.pem"))
         (ec-key-a  (%read-fixture-pem "participant_ec/identity_key.pem"))
         (ec-cert-b (%read-fixture-pem "participant_ec_b/identity_cert.pem"))
         (ec-key-b  (%read-fixture-pem "participant_ec_b/identity_key.pem"))
         (guid-a    (make-array 16 :element-type '(unsigned-byte 8)
                                   :initial-contents '(1 2 3 4 5 6 7 8 9 10 11 12 13 14 15 16)))
         (guid-b    (make-array 16 :element-type '(unsigned-byte 8)
                                   :initial-contents '(200 2 3 4 5 6 7 8 9 10 11 12 13 14 15 16))))
    (multiple-value-bind (id-a reason-a)
        (dds.security:validate-local-identity ca-pem ec-cert-a ec-key-a guid-a)
      (%check :wire-id-a-ok (not (null id-a))
              (format nil "validate-local-identity A failed: ~a" reason-a))
      (unless id-a (return-from run-auth-wire-codec-test t))
      (unwind-protect
           (multiple-value-bind (id-b reason-b)
               (dds.security:validate-local-identity ca-pem ec-cert-b ec-key-b guid-b)
             (%check :wire-id-b-ok (not (null id-b))
                     (format nil "validate-local-identity B failed: ~a" reason-b))
             (unless id-b (return-from run-auth-wire-codec-test t))
             (unwind-protect
                  (progn

                    ;; --- (a) DataHolder round-trip fidelity ---
                    ;; begin-handshake-request returns internal tagged-binary octets + handle.
                    ;; %parse-token recovers the handshake-token struct; then serialize to DataHolder,
                    ;; parse back, re-serialize to tagged-binary, feed into begin-handshake-reply.
                    (multiple-value-bind (req-tok-octets req-hdl)
                        (dds.security:begin-handshake-request id-a id-b dds.security:+suite-ecdh+)
                      (unwind-protect
                           (progn
                             ;; recover struct from the internal tagged-binary
                             (let ((req-struct (dds.security::%parse-token req-tok-octets)))
                               (%check :wire-req-struct-ok (not (null req-struct))
                                       "wire-codec: %parse-token on req-tok returned NIL")
                               (when req-struct
                                 ;; serialize to DataHolder CDR-LE
                                 (let* ((dh-octets (dds.security:handshake-token->dataholder req-struct))
                                        (dh-len    (length dh-octets)))
                                   (%check :wire-dh-non-empty (> dh-len 0)
                                           "wire-codec: handshake-token->dataholder returned empty")

                                   ;; (c) self-consistency: leading bytes match the pinned prefix vector
                                   (let ((prefix-len (length +dataholder-req-prefix-vector+)))
                                     (%check :wire-dh-prefix-len (>= dh-len prefix-len)
                                             (format nil "wire-codec: DataHolder ~d bytes < prefix ~d" dh-len prefix-len))
                                     (when (>= dh-len prefix-len)
                                       (%check :wire-dh-prefix-exact
                                               (equalp (subseq dh-octets 0 prefix-len)
                                                       +dataholder-req-prefix-vector+)
                                               (format nil "wire-codec: DataHolder prefix mismatch; first ~d: ~{~d ~}"
                                                       prefix-len
                                                       (coerce (subseq dh-octets 0 (min prefix-len dh-len)) 'list)))))

                                   ;; parse DataHolder back to token
                                   (let ((rt-tok (dds.security:dataholder->handshake-token dh-octets)))
                                     (%check :wire-rt-tok-ok (not (null rt-tok))
                                             "wire-codec: dataholder->handshake-token returned NIL")
                                     (when rt-tok
                                       ;; class_id must match
                                       (%check :wire-rt-class-id
                                               (string= (dds.security::handshake-token-class-id rt-tok)
                                                        dds.security::+handshake-request-class-id+)
                                               (format nil "wire-codec: round-trip class_id '~a'"
                                                       (dds.security::handshake-token-class-id rt-tok)))
                                       ;; binary-props count must match
                                       (%check :wire-rt-prop-count
                                               (= (length (dds.security::handshake-token-binary-props rt-tok))
                                                  (length (dds.security::handshake-token-binary-props req-struct)))
                                               (format nil "wire-codec: prop count ~d vs ~d"
                                                       (length (dds.security::handshake-token-binary-props rt-tok))
                                                       (length (dds.security::handshake-token-binary-props req-struct))))
                                       ;; re-serialize to tagged binary and drive begin-handshake-reply
                                       (let* ((rt-octets (dds.security::%serialize-token rt-tok))
                                              (rep-tok-rt (nth-value 0
                                                            (dds.security:begin-handshake-reply
                                                             id-b id-a rt-octets dds.security:+suite-ecdh+)))
                                              (rep-tok-direct (nth-value 0
                                                               (dds.security:begin-handshake-reply
                                                                id-b id-a req-tok-octets dds.security:+suite-ecdh+))))
                                         ;; both paths must yield non-nil reply tokens (same next state)
                                         (%check :wire-rt-reply-ok (not (null rep-tok-rt))
                                                 "wire-codec: begin-handshake-reply on round-tripped token returned NIL")
                                         (%check :wire-direct-reply-ok (not (null rep-tok-direct))
                                                 "wire-codec: begin-handshake-reply on direct token returned NIL"))))))
                        (dds.security:free-handshake-handle req-hdl)))

                    ;; --- (b) ParticipantGenericMessage round-trip ---
                    (multiple-value-bind (req-tok2 req-hdl2)
                        (dds.security:begin-handshake-request id-a id-b dds.security:+suite-ecdh+)
                      (unwind-protect
                           (let* ((req-struct2 (dds.security::%parse-token req-tok2))
                                  (dh-blob     (dds.security:handshake-token->dataholder req-struct2))
                                  (src-guid    (make-array 16 :element-type '(unsigned-byte 8)
                                                              :initial-contents '(1 2 3 4 5 6 7 8 9 10 11 12 0 0 2 195)))
                                  (rel-guid    (make-array 16 :element-type '(unsigned-byte 8)
                                                              :initial-element 0))
                                  (dest-pg     (make-array 16 :element-type '(unsigned-byte 8)
                                                              :initial-contents '(200 2 3 4 5 6 7 8 9 10 11 12 0 0 0 193)))
                                  (dest-ep     (make-array 16 :element-type '(unsigned-byte 8)
                                                              :initial-contents '(0 0 0 0 0 0 0 0 0 0 0 0 0 2 1 196)))
                                  (src-ep      (make-array 16 :element-type '(unsigned-byte 8)
                                                              :initial-contents '(0 0 0 0 0 0 0 0 0 0 0 0 0 2 1 195)))
                                  (msg-class   dds.security:+auth-message-class-id+)
                                  (envelope    (dds.security:make-generic-message
                                                :source-guid src-guid
                                                :sequence-number 1
                                                :related-guid rel-guid
                                                :related-sn 0
                                                :dest-participant-guid dest-pg
                                                :dest-endpoint-guid dest-ep
                                                :source-endpoint-guid src-ep
                                                :message-class-id msg-class
                                                :dataholders (list dh-blob))))
                             (%check :wire-env-non-empty (> (length envelope) 0)
                                     "wire-codec: make-generic-message returned empty envelope")
                             (multiple-value-bind (p-src-guid p-sn p-rel-guid p-rel-sn
                                                   p-dest-pg p-dest-ep p-src-ep
                                                   p-class p-dh-list)
                                 (dds.security:parse-generic-message envelope)
                               (%check :wire-parse-src-guid-ok (not (null p-src-guid))
                                       "wire-codec: parse-generic-message returned NIL source-guid")
                               (when p-src-guid
                                 (%check :wire-parse-src-guid (equalp p-src-guid src-guid)
                                         "wire-codec: parsed source-guid mismatch")
                                 (%check :wire-parse-sn (= p-sn 1)
                                         (format nil "wire-codec: parsed SN ~d != 1" p-sn))
                                 (%check :wire-parse-rel-guid (equalp p-rel-guid rel-guid)
                                         "wire-codec: parsed related-guid mismatch")
                                 (%check :wire-parse-rel-sn (= p-rel-sn 0)
                                         (format nil "wire-codec: parsed related-SN ~d != 0" p-rel-sn))
                                 (%check :wire-parse-dest-pg (equalp p-dest-pg dest-pg)
                                         "wire-codec: parsed dest-participant-guid mismatch")
                                 (%check :wire-parse-dest-ep (equalp p-dest-ep dest-ep)
                                         "wire-codec: parsed dest-endpoint-guid mismatch")
                                 (%check :wire-parse-src-ep (equalp p-src-ep src-ep)
                                         "wire-codec: parsed source-endpoint-guid mismatch")
                                 (%check :wire-parse-class-id (string= p-class msg-class)
                                         (format nil "wire-codec: parsed class-id '~a' != '~a'" p-class msg-class))
                                 (%check :wire-parse-dh-count (= (length p-dh-list) 1)
                                         (format nil "wire-codec: parsed ~d DataHolders, expected 1"
                                                 (length p-dh-list)))
                                 (when (= (length p-dh-list) 1)
                                   (%check :wire-parse-dh-bytes (equalp (car p-dh-list) dh-blob)
                                           (format nil "wire-codec: DataHolder blob round-trip mismatch (~d vs ~d bytes)"
                                                   (length (car p-dh-list)) (length dh-blob)))))))
                        (dds.security:free-handshake-handle req-hdl2))))
               (dds.security:free-identity-handle id-b)))
        (dds.security:free-identity-handle id-a))))
  t)))

;;; Safety-0 compiled fuzz inner loop for the wire codec parsers.

(defun* %fuzz-wire-parse-loop-s0 (blobs)
    (function (list) (unsigned-byte 32))
  "Feed each blob through dataholder->handshake-token AND parse-generic-message at (safety 0).
   Returns count of blobs where BOTH parsers returned NIL/nil-head (fail-closed). safety-0 arm."
  (declare (optimize (safety 0) (speed 3)))
  (let ((nil-count 0))
    (declare (type (unsigned-byte 32) nil-count))
    (dolist (blob blobs nil-count)
      (let ((dh-result (dds.security:dataholder->handshake-token blob)))
        (when (null dh-result) (incf nil-count)))
      (let ((pgm-head (nth-value 0 (dds.security:parse-generic-message blob))))
        (when (null pgm-head) (incf nil-count))))))

(defun* run-auth-wire-fuzz-test ()
    (function () t)
  "WP-DDS-SECURITY-AUTH-2BI T2: parser fuzz — N=2000 malformed/short/oversized/random blobs.
   Drives dataholder->handshake-token AND parse-generic-message; asserts fail-closed (-> NIL).
   Tests BOTH a normal-optimization path AND a (safety 0) compiled inner loop (NFR-SEC-POSTURE).
   Deterministic blob generation (index-based fill, no random-state). Both SBCL and Clasp must pass."
  (let* ((fuzz-blobs '())
         (fuzz-count 0))

    ;; Case A (44 blobs): zero-length through 43-byte, all zeros
    (dotimes (len 44)
      (push (make-array len :element-type '(unsigned-byte 8) :initial-element 0) fuzz-blobs))

    ;; Case B (50 blobs): various sizes 4..53, deterministic fill
    (dotimes (k 50)
      (let* ((sz (+ 4 k))
             (b  (make-array sz :element-type '(unsigned-byte 8))))
        (dotimes (i sz) (setf (aref b i) (ldb (byte 8 0) (+ (* i k) 37))))
        (push b fuzz-blobs)))

    ;; Case C (1906 blobs): sizes 60 128 256 512 1024, deterministic fill
    (let ((sizes '(60 128 256 512 1024)))
      (dotimes (idx 1906)
        (let* ((sz   (nth (mod idx (length sizes)) sizes))
               (blob (make-array sz :element-type '(unsigned-byte 8))))
          (dotimes (i sz)
            (setf (aref blob i) (ldb (byte 8 0) (+ (* i (1+ idx)) 37))))
          (push blob fuzz-blobs))))

    (setf fuzz-blobs  (nreverse fuzz-blobs))
    (setf fuzz-count  (length fuzz-blobs))

    ;; Normal-optimization pass: every blob through both parsers -> NIL (fail-closed)
    (let ((normal-dh-nil-count  0)
          (normal-pgm-nil-count 0))
      (declare (type (unsigned-byte 32) normal-dh-nil-count normal-pgm-nil-count))
      (dolist (blob fuzz-blobs)
        (let ((result
                (handler-case
                    (dds.security:dataholder->handshake-token blob)
                  (error (e)
                    (error 'test-failure :name :wire-fuzz-dh-escaped
                           :detail (format nil "wire-fuzz: dataholder->handshake-token signalled: ~a" e))))))
          (%check :wire-fuzz-dh-closed (null result)
                  (format nil "wire-fuzz: dataholder->handshake-token did not return NIL on blob len ~d"
                          (length blob)))
          (when (null result) (incf normal-dh-nil-count)))
        (let ((head
                (handler-case
                    (nth-value 0 (dds.security:parse-generic-message blob))
                  (error (e)
                    (error 'test-failure :name :wire-fuzz-pgm-escaped
                           :detail (format nil "wire-fuzz: parse-generic-message signalled: ~a" e))))))
          (%check :wire-fuzz-pgm-closed (null head)
                  (format nil "wire-fuzz: parse-generic-message did not return NIL on blob len ~d"
                          (length blob)))
          (when (null head) (incf normal-pgm-nil-count))))

      (%check :wire-fuzz-normal-dh-all-nil (= normal-dh-nil-count fuzz-count)
              (format nil "wire-fuzz normal dh: ~d/~d returned NIL" normal-dh-nil-count fuzz-count))
      (%check :wire-fuzz-normal-pgm-all-nil (= normal-pgm-nil-count fuzz-count)
              (format nil "wire-fuzz normal pgm: ~d/~d returned NIL" normal-pgm-nil-count fuzz-count)))

    ;; safety-0 pass: count blobs where BOTH parsers returned NIL (each blob counted twice)
    (let ((safety0-count
            (handler-case
                (%fuzz-wire-parse-loop-s0 fuzz-blobs)
              (error (e)
                (error 'test-failure :name :wire-fuzz-s0-escaped
                       :detail (format nil "wire-fuzz safety-0: signalled: ~a" e))))))
      ;; Each blob contributes up to 2 increments (one per parser); total = 2*fuzz-count when all NIL
      (%check :wire-fuzz-s0-all-nil (= safety0-count (* 2 fuzz-count))
              (format nil "wire-fuzz safety-0: ~d/~d nil-results (expect ~d)"
                      safety0-count (* 2 fuzz-count) (* 2 fuzz-count))))

    (format t "~&  [auth-wire-fuzz] ~d blobs exercised (dataholder + pgm, normal + safety-0)~%"
            fuzz-count))
  t)

;;; ============================================================
;;; T3: ParticipantStatelessMessage builtin endpoints + handshake over the wire
;;; ============================================================

(defun* %psm-guid-from-prefix (prefix entity-id)
    (function ((simple-array (unsigned-byte 8) (12)) (unsigned-byte 32)) (simple-array (unsigned-byte 8) (16)))
  "Build a 16-octet GUID_t from a 12-octet participant PREFIX + 32-bit ENTITY-ID (big-endian bytes 12-15)."
  (let ((g (make-array 16 :element-type '(unsigned-byte 8) :initial-element 0)))
    (replace g prefix :start1 0 :end1 12)
    (setf (aref g 12) (ldb (byte 8 24) entity-id)
          (aref g 13) (ldb (byte 8 16) entity-id)
          (aref g 14) (ldb (byte 8  8) entity-id)
          (aref g 15) (ldb (byte 8  0) entity-id))
    g))

;;; Shared mutable handshake state threaded across the two PSM receiver closures (lock-protected).
(defstruct* (wire-hs-state (:constructor make-wire-hs-state
                                          (&key id-a id-b prefix-a prefix-b)))
  "Lock-protected handshake state shared between the two PSM receiver callbacks."
  (lock    (dds.pal:make-lock "whs") :type t)
  (id-a    nil :type t)
  (id-b    nil :type t)
  (prefix-a (make-array 12 :element-type '(unsigned-byte 8)) :type (simple-array (unsigned-byte 8) (12)))
  (prefix-b (make-array 12 :element-type '(unsigned-byte 8)) :type (simple-array (unsigned-byte 8) (12)))
  (a-hdl   nil :type t)
  (b-hdl   nil :type t)
  (a-done  nil :type t)
  (b-done  nil :type t)
  (a-ss    nil :type t)
  (b-ss    nil :type t)
  (a-sn    1   :type integer)
  (b-sn    1   :type integer))

(defun* %psm-send-token-msg (from-node from-prefix to-prefix token sn)
    (function (t (simple-array (unsigned-byte 8) (12)) (simple-array (unsigned-byte 8) (12)) t integer) t)
  "Serialize TOKEN into a ParticipantGenericMessage and send it via PSM unicast."
  (let* ((dh-octets (dds.security:handshake-token->dataholder token))
         (src-guid  (%psm-guid-from-prefix
                     from-prefix dds.rtps.discovery:+entityid-participant-stateless-writer+))
         (dst-guid  (%psm-guid-from-prefix
                     to-prefix dds.rtps.discovery:+entityid-participant-stateless-reader+))
         (zero      (make-array 16 :element-type '(unsigned-byte 8) :initial-element 0))
         (env       (dds.security:make-generic-message
                     :source-guid           src-guid
                     :sequence-number       sn
                     :related-guid          zero
                     :related-sn            0
                     :dest-participant-guid (%psm-guid-from-prefix to-prefix dds.rtps.message:+entityid-participant+)
                     :dest-endpoint-guid    dst-guid
                     :source-endpoint-guid  src-guid
                     :message-class-id      dds.security:+auth-message-class-id+
                     :dataholders           (list dh-octets))))
    (dds.disc:%send-stateless-message from-node to-prefix env))
  t)

(defun* %psm-envelope->token-octets (envelope)
    (function ((simple-array (unsigned-byte 8) (*))) (or (simple-array (unsigned-byte 8) (*)) null))
  "Decode a RAW PSM ParticipantGenericMessage ENVELOPE (the post-Decision-1 hook contract:
   dds-disc now delivers raw envelope octets, not a parsed token) back into the handshake's
   internal tagged token octets: parse-generic-message -> first DataHolder ->
   dataholder->handshake-token -> %serialize-token. NIL on any malformed/missing input."
  (multiple-value-bind (src-guid sn rel-guid rel-sn dest-part dest-ep src-ep class-id dh-list)
      (dds.security:parse-generic-message envelope)
    (declare (ignore sn rel-guid rel-sn dest-part dest-ep src-ep class-id))
    (when (and src-guid dh-list)
      (let ((tok (dds.security:dataholder->handshake-token (car dh-list))))
        (when tok (dds.security::%serialize-token tok))))))

(defun* %psm-on-a-callback (node envelope state)
    (function (t (simple-array (unsigned-byte 8) (*)) wire-hs-state) t)
  "PSM callback for node-A (requester): HandshakeReply -> process-handshake -> send Final.
   Receives the RAW PSM envelope (Decision 1); decodes it to the handshake token internally."
  (let ((token-octets (%psm-envelope->token-octets envelope)))
    (when (null token-octets) (return-from %psm-on-a-callback t))
   (dds.pal:with-lock ((wire-hs-state-lock state))
    (unless (wire-hs-state-a-done state)
      (when (wire-hs-state-a-hdl state)
        (multiple-value-bind (final-octets status)
            (dds.security:process-handshake
             (wire-hs-state-a-hdl state)
             token-octets)
          ;; :continue = requester reached :authenticated (holds the secret; sends Final) per §8.7.2.4
          (when (eq status :continue)
            (setf (wire-hs-state-a-done state) t)
            (let ((ss (dds.security:handshake-shared-secret (wire-hs-state-a-hdl state))))
              (when ss
                (setf (wire-hs-state-a-ss state) (dds.security:shared-secret-bytes ss))))
            (when final-octets
              (let ((ft (dds.security::%parse-token final-octets)))
                (when ft
                  (let ((sn (incf (wire-hs-state-a-sn state))))
                    (%psm-send-token-msg node
                                        (wire-hs-state-prefix-a state)
                                        (wire-hs-state-prefix-b state)
                                        ft sn)))))))))))
  t)

(defun* %psm-on-b-callback (node envelope state)
    (function (t (simple-array (unsigned-byte 8) (*)) wire-hs-state) t)
  "PSM callback for node-B (replier): HandshakeRequest -> begin-handshake-reply; Final -> :authenticated.
   Receives the RAW PSM envelope (Decision 1); decodes it to the handshake token internally."
  (let ((token-octets (%psm-envelope->token-octets envelope)))
    (when (null token-octets) (return-from %psm-on-b-callback t))
   (dds.pal:with-lock ((wire-hs-state-lock state))
    (unless (wire-hs-state-b-done state)
      (if (null (wire-hs-state-b-hdl state))
          (multiple-value-bind (rep-octets rep-hdl)
              (dds.security:begin-handshake-reply
               (wire-hs-state-id-b state)
               (wire-hs-state-id-a state)
               token-octets
               dds.security:+suite-ecdh+)
            (when (and rep-octets rep-hdl)
              (setf (wire-hs-state-b-hdl state) rep-hdl)
              (let ((rt (dds.security::%parse-token rep-octets)))
                (when rt
                  (let ((sn (incf (wire-hs-state-b-sn state))))
                    (%psm-send-token-msg node
                                        (wire-hs-state-prefix-b state)
                                        (wire-hs-state-prefix-a state)
                                        rt sn))))))
          (multiple-value-bind (nil-tok status)
              (dds.security:process-handshake
               (wire-hs-state-b-hdl state)
               token-octets)
            (declare (ignore nil-tok))
            (when (eq status :authenticated)
              (setf (wire-hs-state-b-done state) t)
              (let ((ss (dds.security:handshake-shared-secret (wire-hs-state-b-hdl state))))
                (when ss
                  (setf (wire-hs-state-b-ss state) (dds.security:shared-secret-bytes ss))))))))))
  t)

(defun* run-auth-handshake-over-wire-test ()
    (function () t)
  "WP-DDS-SECURITY-AUTH-2BI T3: PSM builtin endpoints, end-to-end handshake over UDP wire.
   (a) Two real disc-nodes perform REAL SPDP discovery on loopback.
   (b) Node-A (GUID prefix 0x01...) is the requester (GUID-A < GUID-B, §8.7.2.4).
       begin-handshake-request -> handshake-token->dataholder -> make-generic-message ->
       %send-stateless-message (node-A, B-prefix, env).
   (c) Node-B's on-stateless-message callback receives the token (UDP wire) -> begin-handshake-reply.
   (d) Node-A receives the Reply -> process-handshake -> sends Final.
   (e) Node-B receives the Final -> process-handshake -> :authenticated.
   (f) Both reach :authenticated with byte-equal SharedSecrets (bounded 4 s poll).
   Requires OpenSSL >= 3.5; skips gracefully if absent. Both SBCL and Clasp must pass."
  (handler-case (dds.dare:dare-available-p)
    (dds.dare:dare-unavailable (c)
      (format t "~&  [auth-handshake-over-wire] SKIP — OpenSSL >= 3.5 not available: ~a~%"
              (dds.dare:dare-unavailable-reason c))
      (return-from run-auth-handshake-over-wire-test t)))

  (let* ((ca-pem    (%read-fixture-pem "ca/ca-cert.pem"))
         (ec-cert-a (%read-fixture-pem "participant_ec/identity_cert.pem"))
         (ec-key-a  (%read-fixture-pem "participant_ec/identity_key.pem"))
         (ec-cert-b (%read-fixture-pem "participant_ec_b/identity_cert.pem"))
         (ec-key-b  (%read-fixture-pem "participant_ec_b/identity_key.pem"))
         ;; GUID-A (0x01..) < GUID-B (0xC8..) — A is always the requester (§8.7.2.4)
         (guid-a-16 (make-array 16 :element-type '(unsigned-byte 8)
                                   :initial-contents '(1 2 3 4 5 6 7 8 9 10 11 12 0 2 1 #xC3)))
         (guid-b-16 (make-array 16 :element-type '(unsigned-byte 8)
                                   :initial-contents '(200 2 3 4 5 6 7 8 9 10 11 12 0 2 1 #xC3)))
         (prefix-a  (subseq guid-a-16 0 12))
         (prefix-b  (subseq guid-b-16 0 12)))

    (multiple-value-bind (id-a reason-a)
        (dds.security:validate-local-identity ca-pem ec-cert-a ec-key-a guid-a-16)
      (%check :wire-hs-id-a (not (null id-a))
              (format nil "validate-local-identity A failed: ~a" reason-a))
      (unless id-a (return-from run-auth-handshake-over-wire-test t))
      (unwind-protect
           (multiple-value-bind (id-b reason-b)
               (dds.security:validate-local-identity ca-pem ec-cert-b ec-key-b guid-b-16)
             (%check :wire-hs-id-b (not (null id-b))
                     (format nil "validate-local-identity B failed: ~a" reason-b))
             (unless id-b (return-from run-auth-handshake-over-wire-test t))
             (unwind-protect
                  (let* ((state (make-wire-hs-state :id-a id-a :id-b id-b
                                                    :prefix-a prefix-a :prefix-b prefix-b))
                         (node-a (dds.disc:make-disc-node
                                  :guid-prefix prefix-a
                                  :host "127.0.0.1" :port 0
                                  :identity-token-octets (dds.security:identity-token id-a)
                                  :on-stateless-message
                                  (lambda (node src-prefix envelope)
                                    (declare (ignore src-prefix))
                                    (%psm-on-a-callback node envelope state))))
                         (node-b (dds.disc:make-disc-node
                                  :guid-prefix prefix-b
                                  :host "127.0.0.1" :port 0
                                  :identity-token-octets (dds.security:identity-token id-b)
                                  :on-stateless-message
                                  (lambda (node src-prefix envelope)
                                    (declare (ignore src-prefix))
                                    (%psm-on-b-callback node envelope state)))))
                    (unwind-protect
                         (progn
                           ;; wire peer lists for unicast SPDP
                           (setf (dds.disc:disc-node-peers node-a)
                                 (list (cons "127.0.0.1" (dds.disc:disc-node-port node-b))))
                           (setf (dds.disc:disc-node-peers node-b)
                                 (list (cons "127.0.0.1" (dds.disc:disc-node-port node-a))))
                           (dds.disc:start-node node-a)
                           (dds.disc:start-node node-b)

                           ;; Phase 1: REAL SPDP discovery — poll until mutual discovery
                           (dds.disc:announce-participant node-a)
                           (dds.disc:announce-participant node-b)
                           (loop repeat 200
                                 until (and (plusp (dds.disc:disc-node-discovered-count node-a))
                                            (plusp (dds.disc:disc-node-discovered-count node-b)))
                                 do (dds.disc:announce-participant node-a)
                                    (dds.disc:announce-participant node-b)
                                    (sleep 0.02))
                           (%check :wire-hs-spdp-a
                                   (plusp (dds.disc:disc-node-discovered-count node-a))
                                   "node-A did not discover node-B via SPDP")
                           (%check :wire-hs-spdp-b
                                   (plusp (dds.disc:disc-node-discovered-count node-b))
                                   "node-B did not discover node-A via SPDP")

                           ;; Phase 2: initiate the handshake from node-A (requester)
                           (multiple-value-bind (req-octets req-hdl)
                               (dds.security:begin-handshake-request
                                id-a id-b dds.security:+suite-ecdh+)
                             (%check :wire-hs-req-hdl (not (null req-hdl))
                                     "begin-handshake-request returned nil handle")
                             (when req-hdl
                               (dds.pal:with-lock ((wire-hs-state-lock state))
                                 (setf (wire-hs-state-a-hdl state) req-hdl))
                               (let ((rt (dds.security::%parse-token req-octets)))
                                 (%check :wire-hs-req-tok (not (null rt))
                                         "begin-handshake-request: internal token parse failed")
                                 (when rt
                                   (%psm-send-token-msg node-a prefix-a prefix-b
                                                        rt (wire-hs-state-a-sn state))))

                               ;; Phase 3: poll for completion (bounded; 4 seconds max)
                               (loop repeat 200
                                     until (dds.pal:with-lock ((wire-hs-state-lock state))
                                             (and (wire-hs-state-a-done state)
                                                  (wire-hs-state-b-done state)))
                                     do (sleep 0.02))

                               (let* ((done-a (dds.pal:with-lock ((wire-hs-state-lock state))
                                                (wire-hs-state-a-done state)))
                                      (done-b (dds.pal:with-lock ((wire-hs-state-lock state))
                                                (wire-hs-state-b-done state)))
                                      (ss-a   (dds.pal:with-lock ((wire-hs-state-lock state))
                                                (wire-hs-state-a-ss state)))
                                      (ss-b   (dds.pal:with-lock ((wire-hs-state-lock state))
                                                (wire-hs-state-b-ss state))))
                                 (%check :wire-hs-a-authenticated done-a
                                         "node-A did not reach :authenticated within timeout")
                                 (%check :wire-hs-b-authenticated done-b
                                         "node-B did not reach :authenticated within timeout")
                                 (when (and done-a done-b)
                                   (%check :wire-hs-ss-a-ok (not (null ss-a))
                                           "node-A SharedSecret is nil after :authenticated")
                                   (%check :wire-hs-ss-b-ok (not (null ss-b))
                                           "node-B SharedSecret is nil after :authenticated")
                                   (when (and ss-a ss-b)
                                     (%check :wire-hs-ss-len-a (= (length ss-a) 32)
                                             (format nil "node-A SS length ~d != 32" (length ss-a)))
                                     (%check :wire-hs-ss-len-b (= (length ss-b) 32)
                                             (format nil "node-B SS length ~d != 32" (length ss-b)))
                                     (%check :wire-hs-ss-equal (equalp ss-a ss-b)
                                             "SharedSecret mismatch between node-A and node-B")))
                                 (dds.pal:with-lock ((wire-hs-state-lock state))
                                   (when (wire-hs-state-a-hdl state)
                                     (dds.security:free-handshake-handle (wire-hs-state-a-hdl state))
                                     (setf (wire-hs-state-a-hdl state) nil))
                                   (when (wire-hs-state-b-hdl state)
                                     (dds.security:free-handshake-handle (wire-hs-state-b-hdl state))
                                     (setf (wire-hs-state-b-hdl state) nil)))))))
                      (dds.disc:stop-node node-a)
                      (dds.disc:stop-node node-b)))
               (dds.security:free-identity-handle id-b)))
        (dds.security:free-identity-handle id-a))))
  t)

;;; ============================================================
;;; WP-DDS-SECURITY-AUTH-KEYX T5: the auth manager — end-to-end over the wire
;;; ============================================================
;;; Two in-process security-enabled DomainParticipants (each with %install-auth-manager and a
;;; distinct EC identity) discover each other via SPDP; the auth manager then drives the §8.7.2.4
;;; handshake over the §7.4.3 PSM wire, derives the §9.5.3 KxKey, exchanges §9.5.2 per-writer
;;; KeyMaterial KxKey-encrypted, and transitions each remote to :keyed. The headline assertion:
;;; BOTH participants reach auth-remote state :keyed for each other AND each installed the other's
;;; writer KeyMaterial. NON-VACUOUS: the pre-exchange snapshot asserts NOT-yet-:keyed (proving the
;;; :keyed state is produced by the exchange, not a constant).

(defun* %am-remote-for (p remote-prefix)
    (function (dds.dcps:domain-participant (simple-array (unsigned-byte 8) (12)))
              (or dds.dcps::auth-remote null))
  "P's auth-manager per-remote AUTH-REMOTE record for REMOTE-PREFIX (NIL if not yet created).
   Reads the disc-node's manager-owned auth-state table under the manager lock."
  (let ((ms (dds.dcps::dp-auth-state p)))
    (when ms
      (dds.pal:with-lock ((dds.dcps::auth-manager-state-lock ms))
        (gethash remote-prefix (dds.disc:disc-node-auth-state (dds.dcps::dp-node p)))))))

(defun* %am-remote-state (p remote-prefix)
    (function (dds.dcps:domain-participant (simple-array (unsigned-byte 8) (12))) t)
  "The auth-remote STATE keyword P holds for REMOTE-PREFIX, or NIL if no record yet."
  (let ((ar (%am-remote-for p remote-prefix)))
    (when ar (dds.dcps::auth-remote-state ar))))

(defun* %cm-for (p)
    (function (dds.dcps:domain-participant) t)
  "P's §8.5 crypto-manager (T8), or NIL if P is not security-enabled."
  (let ((ms (dds.dcps::dp-auth-state p)))
    (when ms (dds.dcps::auth-manager-state-crypto-manager ms))))

(defun* %cm-has-remote-participant-p (p remote-prefix)
    (function (dds.dcps:domain-participant (simple-array (unsigned-byte 8) (12))) t)
  "T iff P's crypto-manager has installed REMOTE-PREFIX's ParticipantCrypto KeyMaterial (T8 §8.5.2)."
  (let ((cm (%cm-for p)))
    (and cm (not (null (dds.dcps::cm-decode-participant-km cm remote-prefix))) t)))

(defun* %cm-has-remote-entity-p (p remote-prefix entity-id)
    (function (dds.dcps:domain-participant (simple-array (unsigned-byte 8) (12)) (unsigned-byte 32)) t)
  "T iff P's crypto-manager has installed REMOTE-PREFIX's EntityCrypto for ENTITY-ID (by the 16-octet GUID;
   T8 §8.5.2). Used to assert the remote secure-SEDP builtin DW/DR + user-endpoint tokens are installed."
  (let ((cm (%cm-for p)))
    (and cm
         (not (null (dds.dcps::cm-decode-entity-km
                     cm (dds.dcps::%guid-from-prefix remote-prefix entity-id))))
         t)))

(defun* %cm-local-entity-origin-auth-p (p entity-id)
    (function (dds.dcps:domain-participant (unsigned-byte 32)) t)
  "T iff P's crypto-manager registered the LOCAL EntityCrypto for ENTITY-ID WITH origin-auth — a non-zero
   receiver_specific_key_id (§9.5.3.3.4.3; T-ORIGINAUTH). Proves governance drove the receiver-specific key
   mint for the secure-SEDP receiving readers."
  (let ((cm (%cm-for p)))
    (and cm
         (let ((km (dds.dcps::cm-encode-entity-km cm entity-id)))
           (and km (notevery #'zerop (dds.security:key-material-receiver-specific-key-id km)) t)))))

(defun* %am-remote-keyed-p (p remote-prefix)
    (function (dds.dcps:domain-participant (simple-array (unsigned-byte 8) (12))) t)
  "T iff P's auth-remote for REMOTE-PREFIX is :keyed AND the crypto-manager installed REMOTE-PREFIX's
   ParticipantCrypto (T8: the §8.5.2 crypto-token exchange over PVMS landed; the per-writer/entity
   KeyMaterial now lives in the crypto-manager registries, not the retired auth-remote REMOTE-KM)."
  (let ((ar (%am-remote-for p remote-prefix)))
    (and ar
         (eq (dds.dcps::auth-remote-state ar) :keyed)
         (%cm-has-remote-participant-p p remote-prefix)
         t)))

(defun* run-auth-manager-handshake-test ()
    (function () t)
  "WP-DDS-SECURITY-AUTH-KEYX T5 / SECURE-DISCOVERY T8: the auth manager (dds-dcps) drives the §8.7 handshake
   + §8.5.2 crypto-token exchange end-to-end between two security-enabled participants on discovery.
   (a) Two DomainParticipants are created with distinct EC identities (participant_ec /
       participant_ec_b) -> security-enabled (DP-AUTH-STATE set, IdentityToken advertised).
   (b) NON-VACUITY: before discovery completes, neither holds a :keyed remote.
   (c) On SPDP discovery the manager runs the handshake (requester by §8.7.2.4 GUID order), derives the
       §9.5.3.1 PVMS bootstrap KM, exchanges crypto tokens over reliable PVMS, and reaches :keyed BOTH ways.
   (d) T8 (migrated off auth-remote-remote-km): each crypto-manager installed the OTHER's ParticipantCrypto
       (§8.5.2) — the per-writer/entity KeyMaterial now lives in the crypto-manager registries.
   Requires OpenSSL >= 3.5; skips gracefully if absent. Both SBCL and Clasp must pass."
  (handler-case (dds.dare:dare-available-p)
    (dds.dare:dare-unavailable (c)
      (format t "~&  [auth-manager-handshake] SKIP — OpenSSL >= 3.5 not available: ~a~%"
              (dds.dare:dare-unavailable-reason c))
      (return-from run-auth-manager-handshake-test t)))

  (let* ((ca-pem    (%read-fixture-pem "ca/ca-cert.pem"))
         (ec-cert-a (%read-fixture-pem "participant_ec/identity_cert.pem"))
         (ec-key-a  (%read-fixture-pem "participant_ec/identity_key.pem"))
         (ec-cert-b (%read-fixture-pem "participant_ec_b/identity_cert.pem"))
         (ec-key-b  (%read-fixture-pem "participant_ec_b/identity_key.pem"))
         ;; identity GUIDs are not used for the role (the manager uses the real RTPS prefixes);
         ;; distinct values kept for parity with the over-wire setup.
         (guid-a    (make-array 16 :element-type '(unsigned-byte 8)
                                   :initial-contents '(1 2 3 4 5 6 7 8 9 10 11 12 13 14 15 16)))
         (guid-b    (make-array 16 :element-type '(unsigned-byte 8)
                                   :initial-contents '(200 2 3 4 5 6 7 8 9 10 11 12 13 14 15 16))))
    (multiple-value-bind (id-a reason-a)
        (dds.security:validate-local-identity ca-pem ec-cert-a ec-key-a guid-a)
      (%check :am-id-a (not (null id-a))
              (format nil "validate-local-identity A failed: ~a" reason-a))
      (unless id-a (return-from run-auth-manager-handshake-test t))
      (unwind-protect
           (multiple-value-bind (id-b reason-b)
               (dds.security:validate-local-identity ca-pem ec-cert-b ec-key-b guid-b)
             (%check :am-id-b (not (null id-b))
                     (format nil "validate-local-identity B failed: ~a" reason-b))
             (unless id-b (return-from run-auth-manager-handshake-test t))
             (unwind-protect
             (let ((p-a (dds.dcps:create-participant :domain (test-domain) :identity id-a))
                   (p-b (dds.dcps:create-participant :domain (test-domain) :identity id-b)))
               (unwind-protect
                    (let ((prefix-a (dds.disc:disc-node-guid-prefix (dds.dcps::dp-node p-a)))
                          (prefix-b (dds.disc:disc-node-guid-prefix (dds.dcps::dp-node p-b))))
                      ;; security-enabled both sides
                      (%check :am-secure-a (not (null (dds.dcps::dp-auth-state p-a)))
                              "participant A must be security-enabled (DP-AUTH-STATE set)")
                      (%check :am-secure-b (not (null (dds.dcps::dp-auth-state p-b)))
                              "participant B must be security-enabled (DP-AUTH-STATE set)")
                      ;; NON-VACUITY: before discovery, neither holds a :keyed remote
                      (%check :am-not-keyed-before
                              (and (not (%am-remote-keyed-p p-a prefix-b))
                                   (not (%am-remote-keyed-p p-b prefix-a)))
                              "no remote may be :keyed before the handshake/key-exchange completes")
                      ;; drive discovery + the handshake/key-exchange (bounded; ~6 s max)
                      (loop repeat 300
                            until (and (%am-remote-keyed-p p-a prefix-b)
                                       (%am-remote-keyed-p p-b prefix-a))
                            do (dds.dcps:spin p-a) (dds.dcps:spin p-b) (sleep 0.02))
                      ;; headline: BOTH reached :keyed for each other
                      (%check :am-a-keyed-b (%am-remote-keyed-p p-a prefix-b)
                              (format nil "A did not reach :keyed for B (state ~a)"
                                      (%am-remote-state p-a prefix-b)))
                      (%check :am-b-keyed-a (%am-remote-keyed-p p-b prefix-a)
                              (format nil "B did not reach :keyed for A (state ~a)"
                                      (%am-remote-state p-b prefix-a)))
                      ;; T8: each crypto-manager installed the OTHER's ParticipantCrypto (§8.5.2; was
                      ;; auth-remote-remote-km — now in the crypto-manager EntityCrypto/ParticipantCrypto registry)
                      (%check :am-a-has-b-km
                              (%cm-has-remote-participant-p p-a prefix-b)
                              "A's crypto-manager must have installed B's ParticipantCrypto")
                      (%check :am-b-has-a-km
                              (%cm-has-remote-participant-p p-b prefix-a)
                              "B's crypto-manager must have installed A's ParticipantCrypto"))
                 (dds.dcps:delete-participant p-a)
                 (dds.dcps:delete-participant p-b)))
               (dds.security:free-identity-handle id-b)))
        (dds.security:free-identity-handle id-a))))
  t)

;;; ============================================================
;;; WP-DDS-SECURITY-AUTH-KEYX T6: end-to-end encrypted pub/sub via exchanged keys
;;; ============================================================

(defun* run-auth-encrypted-pubsub-keyx-test ()
    (function () t)
  "WP-DDS-SECURITY-AUTH-KEYX T6: encrypted pub/sub using per-writer keys from the auth
   manager (§9.5.2 / §9.5.3.3), NOT the Slice-1 make-test-key-material scaffold.
   Two security-enabled DomainParticipants A (writer) and B (reader) complete the
   §8.7 handshake and §9.5 key exchange to :keyed. After :keyed the auth manager
   installs a CRYPTO-KEYS resolver (not a plain KEY-MATERIAL) on each participant's
   disc-node CRYPTO-TRANSFORM. A then publishes a known plaintext; the resolver provides
   the encode key. B decrypts with its decode resolver and the received plaintext MUST
   equal the original byte-exact. Assertions:
     (a)  Both reach :keyed -> auth + key exchange complete.
     (b)  Each participant's CRYPTO-TRANSFORM is a CRYPTO-KEYS struct (not a KEY-MATERIAL).
     (c)  A's encode resolver returns a non-nil KEY-MATERIAL for A's writer GUID.
     (c2) A's encode resolver returns EQ the same instance stored in WRITER-KM-TABLE
          (§9.5 per-writer table invariant: one stable km shared across all remotes).
     (d)  B's decode resolver returns a non-nil KEY-MATERIAL for A's wire writer GUID.
     (e)  B receives EXACTLY the original plaintext PT (encode+decode round-trip byte-exact).
   No make-test-key-material is used anywhere in this test.
   Requires OpenSSL >= 3.5; skips gracefully if absent. Both SBCL and Clasp must pass."
  (handler-case (dds.dare:dare-available-p)
    (dds.dare:dare-unavailable (c)
      (format t "~&  [auth-encrypted-pubsub-keyx] SKIP — OpenSSL >= 3.5 not available: ~a~%"
              (dds.dare:dare-unavailable-reason c))
      (return-from run-auth-encrypted-pubsub-keyx-test t)))

  (let* ((ca-pem    (%read-fixture-pem "ca/ca-cert.pem"))
         (ec-cert-a (%read-fixture-pem "participant_ec/identity_cert.pem"))
         (ec-key-a  (%read-fixture-pem "participant_ec/identity_key.pem"))
         (ec-cert-b (%read-fixture-pem "participant_ec_b/identity_cert.pem"))
         (ec-key-b  (%read-fixture-pem "participant_ec_b/identity_key.pem"))
         (guid-a    (make-array 16 :element-type '(unsigned-byte 8)
                                   :initial-contents '(1 2 3 4 5 6 7 8 9 10 11 12 13 14 15 16)))
         (guid-b    (make-array 16 :element-type '(unsigned-byte 8)
                                   :initial-contents '(200 2 3 4 5 6 7 8 9 10 11 12 13 14 15 16))))
    (multiple-value-bind (id-a reason-a)
        (dds.security:validate-local-identity ca-pem ec-cert-a ec-key-a guid-a)
      (%check :kpub-id-a (not (null id-a))
              (format nil "validate-local-identity A failed: ~a" reason-a))
      (unless id-a (return-from run-auth-encrypted-pubsub-keyx-test t))
      (unwind-protect
           (multiple-value-bind (id-b reason-b)
               (dds.security:validate-local-identity ca-pem ec-cert-b ec-key-b guid-b)
             (%check :kpub-id-b (not (null id-b))
                     (format nil "validate-local-identity B failed: ~a" reason-b))
             (unless id-b (return-from run-auth-encrypted-pubsub-keyx-test t))
             (unwind-protect
                  (let ((p-a (dds.dcps:create-participant :domain (test-domain) :identity id-a))
                        (p-b (dds.dcps:create-participant :domain (test-domain) :identity id-b)))
                    (unwind-protect
                         (let* ((node-a (dds.dcps::dp-node p-a))
                                (node-b (dds.dcps::dp-node p-b))
                                (prefix-a (dds.disc:disc-node-guid-prefix node-a))
                                (prefix-b (dds.disc:disc-node-guid-prefix node-b))
                                (pt (make-array 8 :element-type '(unsigned-byte 8)
                                                  :initial-contents '(#x4b #x45 #x59 #x58 #x44 #x41 #x54 #x41))))
                           ;; wire up unicast peers for reliable connectivity (bypass multicast CI variability)
                           (setf (dds.disc:disc-node-peers node-a)
                                 (list (cons "127.0.0.1" (dds.disc:disc-node-port node-b))))
                           (setf (dds.disc:disc-node-peers node-b)
                                 (list (cons "127.0.0.1" (dds.disc:disc-node-port node-a))))
                           ;; add writer on A and reader on B (must precede announce-endpoints)
                           (dds.disc:add-local-writer node-a :topic "KxTopic" :type "KxType"
                                                      :qos (dds.qos:make-writer-qos
                                                            :reliability :reliable
                                                            :durability :transient-local))
                           (dds.disc:enable-publisher node-a :history-kind :keep-all)
                           (dds.disc:add-local-reader node-b :topic "KxTopic" :type "KxType"
                                                      :qos (dds.qos:make-reader-qos
                                                            :reliability :reliable
                                                            :durability :transient-local))
                           (dds.disc:enable-subscriber node-b)
                           ;; NON-VACUITY: before the handshake completes, neither is :keyed
                           (%check :kpub-not-keyed-before
                                   (and (not (%am-remote-keyed-p p-a prefix-b))
                                        (not (%am-remote-keyed-p p-b prefix-a)))
                                   "no remote may be :keyed before the handshake completes")
                           ;; drive auth handshake + key exchange to :keyed (bounded ~6 s)
                           (loop repeat 300
                                 until (and (%am-remote-keyed-p p-a prefix-b)
                                            (%am-remote-keyed-p p-b prefix-a))
                                 do (dds.dcps:spin p-a) (dds.dcps:spin p-b) (sleep 0.02))
                           ;; (a) both reached :keyed
                           (%check :kpub-a-keyed (%am-remote-keyed-p p-a prefix-b)
                                   (format nil "A did not reach :keyed for B (state ~a)"
                                           (%am-remote-state p-a prefix-b)))
                           (%check :kpub-b-keyed (%am-remote-keyed-p p-b prefix-a)
                                   (format nil "B did not reach :keyed for A (state ~a)"
                                           (%am-remote-state p-b prefix-a)))
                           ;; (b) CRYPTO-TRANSFORM is a CRYPTO-KEYS struct (the T6 resolver, not a plain KEY-MATERIAL)
                           (%check :kpub-a-crypto-keys
                                   (typep (dds.disc:disc-node-crypto-transform node-a) 'dds.security:crypto-keys)
                                   (format nil "A's crypto-transform is ~a, expected CRYPTO-KEYS"
                                           (type-of (dds.disc:disc-node-crypto-transform node-a))))
                           (%check :kpub-b-crypto-keys
                                   (typep (dds.disc:disc-node-crypto-transform node-b) 'dds.security:crypto-keys)
                                   (format nil "B's crypto-transform is ~a, expected CRYPTO-KEYS"
                                           (type-of (dds.disc:disc-node-crypto-transform node-b))))
                           ;; (c) A's encode resolver returns a KEY-MATERIAL for A's writer GUID
                           (let* ((ct-a (dds.disc:disc-node-crypto-transform node-a))
                                  (writer-guid-a (let ((g (make-array 16 :element-type '(unsigned-byte 8) :initial-element 0)))
                                                   (replace g prefix-a :end2 12)
                                                   (let ((id (dds.disc:disc-node-user-writer-id node-a)))
                                                     (setf (aref g 12) (ldb (byte 8 24) id)
                                                           (aref g 13) (ldb (byte 8 16) id)
                                                           (aref g 14) (ldb (byte 8  8) id)
                                                           (aref g 15) (ldb (byte 8  0) id)))
                                                   g))
                                  (encode-km (funcall (dds.security:crypto-keys-encode-key-fn ct-a) writer-guid-a)))
                             (%check :kpub-encode-km
                                     (typep encode-km 'dds.security:key-material)
                                     (format nil "A's encode resolver returned ~a (expect KEY-MATERIAL)" encode-km))
                             ;; (c2) T8: the encode resolver returns the SAME (eq) KM the crypto-manager holds
                             ;; in LOCAL-ENTITY-CRYPTO for A's user-writer EntityId (§8.5: one stable KM per
                             ;; local entity; the KEYX writer-km-table is RETIRED — keys now in the crypto-manager)
                             (let* ((cm-a (%cm-for p-a))
                                    (entity-km (dds.dcps::cm-encode-entity-km
                                                cm-a (dds.disc:disc-node-user-writer-id node-a))))
                               (%check :kpub-single-writer-km
                                       (and entity-km (eq encode-km entity-km))
                                       (format nil "encode resolver returned ~a but crypto-manager LOCAL-ENTITY-CRYPTO has ~a (must be EQ)"
                                               encode-km entity-km)))
                             ;; SecuredPayload-on-wire proof: encode-serialized-payload must produce
                             ;; ciphertext starting with the §9.5.3.3.1 Table 69 AES256-GCM kind
                             ;; header #(0 0 0 4), NOT the plaintext.  Assertion FAILS if encode
                             ;; were a no-op passthrough (pt starts with #x4b, not #x00).
                             (when (typep encode-km 'dds.security:key-material)
                               (let ((wire-bytes (dds.security:encode-serialized-payload encode-km pt)))
                                 (%check :kpub-wire-not-plaintext
                                         (not (search pt wire-bytes :test #'eql))
                                         (format nil "wire bytes contain the plaintext — encode-serialized-payload is a passthrough; first 8: ~{~2,'0x~^ ~}"
                                                 (coerce (subseq wire-bytes 0 (min 8 (length wire-bytes))) 'list)))
                                 (%check :kpub-wire-secured-payload-header
                                         (and (>= (length wire-bytes) 4)
                                              (= (aref wire-bytes 0) 0)
                                              (= (aref wire-bytes 1) 0)
                                              (= (aref wire-bytes 2) 0)
                                              (= (aref wire-bytes 3) 4))
                                         (format nil "wire payload must begin with AES256-GCM kind #(0 0 0 4) §9.5.3.3.1 Table 69; got ~{~2,'0x~^ ~}"
                                                 (coerce (subseq wire-bytes 0 (min 4 (length wire-bytes))) 'list)))))
                             ;; (d) B's decode resolver returns a KEY-MATERIAL for A's user-writer GUID. T8: A's
                             ;; user-writer EntityCrypto rides datawriter_crypto_tokens over reliable PVMS and is
                             ;; installed AFTER :keyed (which gates on the participant + secure-SEDP builtins, sent
                             ;; first), so wait (bounded) for that later token to land before asserting.
                             (loop repeat 200
                                   until (%cm-has-remote-entity-p p-b prefix-a
                                                                  (dds.disc:disc-node-user-writer-id node-a))
                                   do (dds.dcps:spin p-a) (dds.dcps:spin p-b) (sleep 0.02))
                             (let* ((ct-b (dds.disc:disc-node-crypto-transform node-b))
                                    (decode-km (funcall (dds.security:crypto-keys-decode-key-fn ct-b) writer-guid-a)))
                               (%check :kpub-decode-km
                                       (typep decode-km 'dds.security:key-material)
                                       (format nil "B's decode resolver returned ~a for A's GUID (expect KEY-MATERIAL)" decode-km))
                               ;; (e) publish PT from A, wait for B to receive the decrypted plaintext
                               (dds.disc:publish-sample node-a pt)
                               ;; drive discovery+delivery: spin both + re-announce endpoints until B has a sample
                               (loop repeat 400
                                     until (plusp (dds.disc:node-sample-count node-b))
                                     do (dds.dcps:spin p-a) (dds.dcps:spin p-b) (sleep 0.02))
                               (%check :kpub-b-received
                                       (plusp (dds.disc:node-sample-count node-b))
                                       "B did not receive any sample after encrypted publish from A")
                               (let* ((b-key (first (dds.disc:node-sample-sns node-b)))
                                      (b-payload (dds.disc:node-sample node-b b-key)))
                                 (%check :kpub-b-plaintext
                                         (and b-payload (equalp b-payload pt))
                                         (format nil "B received ~a but expected plaintext ~{~2,'0x~^ ~}"
                                                 (and b-payload (coerce b-payload 'list))
                                                 (coerce pt 'list))))))
                           t)
                      (ignore-errors (dds.dcps:delete-participant p-a))
                      (ignore-errors (dds.dcps:delete-participant p-b))))
               (dds.security:free-identity-handle id-b)))
        (dds.security:free-identity-handle id-a))))
  t)

;;; ============================================================
;;; WP-DDS-SECURITY-SECURE-DISCOVERY T8: crypto-token exchange over PVMS + :authenticated->:keyed promotion
;;; ============================================================
;;; Two security-enabled participants authenticate (Slice 2) then exchange §8.5.2 crypto tokens over the
;;; reliable PVMS endpoint (T7) and BOTH reach auth-remote :keyed with the remote's ParticipantCrypto +
;;; secure-SEDP builtin EntityCrypto installed in each crypto-manager (design §6.4/§7.2). The headline
;;; safety property — DISJOINT per-role nonce spaces for the SYMMETRIC PVMS bootstrap KM — is asserted
;;; structurally (the two roles' PVMS encode session_ids DIFFER, so no AES-GCM (key, nonce) reuse).

(defun* run-secure-discovery-keyed-test ()
    (function () t)
  "WP-DDS-SECURITY-SECURE-DISCOVERY T8: end-to-end :authenticated->:keyed via crypto-token exchange over
   reliable PVMS. Two security-enabled DomainParticipants (distinct EC identities) discover over SPDP,
   authenticate (§8.7), derive the §9.5.3.1 PVMS bootstrap KM, exchange Participant + builtin EntityCrypto
   tokens over PVMS, install the remote's, and reach :keyed BOTH directions. Assertions:
     (a) NON-VACUITY: before the exchange, neither holds a :keyed remote.
     (b) both reach :keyed (auth + crypto established).
     (c) each crypto-manager installed the remote's ParticipantCrypto.
     (d) each installed the remote's secure-SEDP publications-secure-writer (DW) EntityCrypto (a builtin token).
     (e) NONCE-DISJOINTNESS (safety-critical, HARD CONSTRAINT #1): %pvms-role-session-id is DIFFERENT for the
         two directions (A->B vs B->A), so the symmetric bootstrap KM never reuses a (key, nonce) pair.
   Requires OpenSSL >= 3.5; skips gracefully if absent. Both SBCL and Clasp must pass."
  (handler-case (dds.dare:dare-available-p)
    (dds.dare:dare-unavailable (c)
      (format t "~&  [secure-discovery-keyed] SKIP — OpenSSL >= 3.5 not available: ~a~%"
              (dds.dare:dare-unavailable-reason c))
      (return-from run-secure-discovery-keyed-test t)))
  (let* ((ca-pem    (%read-fixture-pem "ca/ca-cert.pem"))
         (ec-cert-a (%read-fixture-pem "participant_ec/identity_cert.pem"))
         (ec-key-a  (%read-fixture-pem "participant_ec/identity_key.pem"))
         (ec-cert-b (%read-fixture-pem "participant_ec_b/identity_cert.pem"))
         (ec-key-b  (%read-fixture-pem "participant_ec_b/identity_key.pem"))
         (guid-a    (make-array 16 :element-type '(unsigned-byte 8)
                                   :initial-contents '(1 2 3 4 5 6 7 8 9 10 11 12 13 14 15 16)))
         (guid-b    (make-array 16 :element-type '(unsigned-byte 8)
                                   :initial-contents '(200 2 3 4 5 6 7 8 9 10 11 12 13 14 15 16)))
         (pub-w     dds.rtps.discovery:+entityid-sedp-pub-secure-writer+))
    (multiple-value-bind (id-a reason-a)
        (dds.security:validate-local-identity ca-pem ec-cert-a ec-key-a guid-a)
      (%check :sdk-id-a (not (null id-a)) (format nil "validate-local-identity A failed: ~a" reason-a))
      (unless id-a (return-from run-secure-discovery-keyed-test t))
      (unwind-protect
           (multiple-value-bind (id-b reason-b)
               (dds.security:validate-local-identity ca-pem ec-cert-b ec-key-b guid-b)
             (%check :sdk-id-b (not (null id-b)) (format nil "validate-local-identity B failed: ~a" reason-b))
             (unless id-b (return-from run-secure-discovery-keyed-test t))
             (unwind-protect
                  (let ((p-a (dds.dcps:create-participant :domain (test-domain) :identity id-a))
                        (p-b (dds.dcps:create-participant :domain (test-domain) :identity id-b)))
                    (unwind-protect
                         (let* ((node-a (dds.dcps::dp-node p-a))
                                (node-b (dds.dcps::dp-node p-b))
                                (prefix-a (dds.disc:disc-node-guid-prefix node-a))
                                (prefix-b (dds.disc:disc-node-guid-prefix node-b)))
                           (setf (dds.disc:disc-node-peers node-a)
                                 (list (cons "127.0.0.1" (dds.disc:disc-node-port node-b))))
                           (setf (dds.disc:disc-node-peers node-b)
                                 (list (cons "127.0.0.1" (dds.disc:disc-node-port node-a))))
                           ;; (a) NON-VACUITY: nobody keyed before the exchange
                           (%check :sdk-not-keyed-before
                                   (and (not (%am-remote-keyed-p p-a prefix-b))
                                        (not (%am-remote-keyed-p p-b prefix-a)))
                                   "no remote may be :keyed before the crypto-token exchange completes")
                           ;; drive auth + crypto-token exchange to :keyed AND pub-w EntityCrypto installed
                           (loop repeat 400
                                 until (and (%am-remote-keyed-p p-a prefix-b)
                                            (%am-remote-keyed-p p-b prefix-a)
                                            (%cm-has-remote-entity-p p-a prefix-b pub-w)
                                            (%cm-has-remote-entity-p p-b prefix-a pub-w))
                                 do (dds.dcps:spin p-a) (dds.dcps:spin p-b) (sleep 0.02))
                           ;; (b) both reached :keyed
                           (%check :sdk-a-keyed (%am-remote-keyed-p p-a prefix-b)
                                   (format nil "A did not reach :keyed for B (state ~a)"
                                           (%am-remote-state p-a prefix-b)))
                           (%check :sdk-b-keyed (%am-remote-keyed-p p-b prefix-a)
                                   (format nil "B did not reach :keyed for A (state ~a)"
                                           (%am-remote-state p-b prefix-a)))
                           ;; (c) each installed the remote ParticipantCrypto
                           (%check :sdk-a-has-b-participant (%cm-has-remote-participant-p p-a prefix-b)
                                   "A's crypto-manager must have installed B's ParticipantCrypto")
                           (%check :sdk-b-has-a-participant (%cm-has-remote-participant-p p-b prefix-a)
                                   "B's crypto-manager must have installed A's ParticipantCrypto")
                           ;; (d) each installed the remote secure-SEDP-pub-writer EntityCrypto (a builtin DW token)
                           (%check :sdk-a-has-b-pubw (%cm-has-remote-entity-p p-a prefix-b pub-w)
                                   "A must have installed B's secure-SEDP-pub-writer EntityCrypto (DW token)")
                           (%check :sdk-b-has-a-pubw (%cm-has-remote-entity-p p-b prefix-a pub-w)
                                   "B must have installed A's secure-SEDP-pub-writer EntityCrypto (DW token)")
                           ;; (e) NONCE-DISJOINTNESS: the two roles' PVMS encode session_ids MUST differ
                           (let ((sid-ab (dds.disc:%pvms-role-session-id prefix-a prefix-b))
                                 (sid-ba (dds.disc:%pvms-role-session-id prefix-b prefix-a)))
                             (%check :sdk-nonce-disjoint
                                     (not (equalp sid-ab sid-ba))
                                     (format nil "PVMS per-role session_ids MUST differ (A->B ~{~2,'0x~} vs B->A ~{~2,'0x~}) — equal => AES-GCM nonce reuse on the symmetric bootstrap KM"
                                             (coerce sid-ab 'list) (coerce sid-ba 'list)))
                             ;; both session_ids must be NON-ZERO (distinct from the non-PVMS +fixed-session-id+)
                             (%check :sdk-nonce-nonzero
                                     (and (notevery #'zerop sid-ab) (notevery #'zerop sid-ba))
                                     "PVMS per-role session_ids must be non-zero (distinct from the all-zero non-PVMS session_id)"))
                           t)
                      (ignore-errors (dds.dcps:delete-participant p-a))
                      (ignore-errors (dds.dcps:delete-participant p-b))))
               (dds.security:free-identity-handle id-b)))
        (dds.security:free-identity-handle id-a))))
  t)

;;; ============================================================
;;; WP-DDS-SECURITY-AUTH-KEYX T2: §9.5.3 KxKey derivation KAT
;;; ============================================================
;;; KAT strategy (spike §5.1–§5.5):
;;;   (a) RFC 4231 §4.2 TC1 + §4.5 TC4 — validate dds.dare:hmac-sha256 against published vectors.
;;;   SHA-256 inner step is already covered by run-auth-sha256-kat (spike §5.5, §B.2 KAT passes).
;;;   (b) Structural/determinism checks on derive-kx-key — no fabricated composed KAT exists.
;;; Explicit statement: No published end-to-end DDS-Security KxKey test vector exists (spike §5.5).
;;; The two-impl (Clasp + SBCL) cross-check is the composition conformance method.

(defun* run-auth-kxkey-kat ()
    (function () t)
  "DDS-Security 1.1 §9.5.3 KxKey/KxSalt derivation KAT + published primitive vectors.
   (a) HMAC-SHA256 RFC 4231 §4.2 TC1 and §4.5 TC4 — validates dds.dare:hmac-sha256.
       SHA-256 inner step is already covered by run-auth-sha256-kat (spike §5.5).
   (b) Structural checks on derive-kx-key: 32-byte output; deterministic; KxKey != KxSalt
       (swapped challenges take effect); KxKey != raw shared_secret; free-kx-key returns nil.
   No fabricated composed KxKey expected-value is asserted (spike §5.5 — none published).
   Clasp and SBCL cross-check on identical fixed inputs is the composition conformance method.
   Requires OpenSSL >= 3.5; skips gracefully if absent. Both impls must pass."
  (handler-case (dds.dare:dare-available-p)
    (dds.dare:dare-unavailable (c)
      (format t "~&  [kxkey-kat] SKIP — OpenSSL >= 3.5 not available: ~a~%"
              (dds.dare:dare-unavailable-reason c))
      (return-from run-auth-kxkey-kat t)))

  ;;; --- (a) RFC 4231 §4.2 TC1: HMAC-SHA256 primitive KAT ---
  ;; Source: https://www.rfc-editor.org/rfc/rfc4231#section-4.2 (spike §5.2)
  ;; Key: 0b0b0b...0b (20 bytes), Data: "Hi There" (8 bytes)
  ;; Expected HMAC-SHA-256: b0344c61d8db38535ca8afceaf0bf12b881dc200c9833da726e9376c2e32cff7
  (let* ((tc1-key
          (coerce #(#x0b #x0b #x0b #x0b #x0b #x0b #x0b #x0b #x0b #x0b
                    #x0b #x0b #x0b #x0b #x0b #x0b #x0b #x0b #x0b #x0b)
                  '(simple-array (unsigned-byte 8) (*))))
         (tc1-data
          (coerce #(#x48 #x69 #x20 #x54 #x68 #x65 #x72 #x65)
                  '(simple-array (unsigned-byte 8) (*))))
         (tc1-expected
          #(#xb0 #x34 #x4c #x61 #xd8 #xdb #x38 #x53 #x5c #xa8 #xaf #xce #xaf #x0b #xf1 #x2b
            #x88 #x1d #xc2 #x00 #xc9 #x83 #x3d #xa7 #x26 #xe9 #x37 #x6c #x2e #x32 #xcf #xf7))
         (tc1-got (dds.dare:hmac-sha256 tc1-key tc1-data)))
    (%check :kxkey-hmac-tc1-len (= (length tc1-got) 32)
            (format nil "RFC 4231 TC1: HMAC-SHA256 length ~d != 32" (length tc1-got)))
    (%check :kxkey-hmac-tc1-val (equalp tc1-got (coerce tc1-expected '(simple-array (unsigned-byte 8) (*))))
            (format nil "RFC 4231 TC1: HMAC-SHA256 mismatch; got ~{~2,'0x~}" (coerce tc1-got 'list))))

  ;;; --- RFC 4231 §4.5 TC4: HMAC-SHA256 primitive KAT ---
  ;; Source: https://www.rfc-editor.org/rfc/rfc4231#section-4.5 (spike §5.3)
  ;; Key: 0102030405...19 (25 bytes), Data: cdcd...cd (50 bytes of 0xcd)
  ;; Expected HMAC-SHA-256: 82558a389a443c0ea4cc819899f2083a85f0faa3e578f8077a2e3ff46729665b
  (let* ((tc4-key
          (coerce #(#x01 #x02 #x03 #x04 #x05 #x06 #x07 #x08 #x09 #x0a #x0b #x0c #x0d
                    #x0e #x0f #x10 #x11 #x12 #x13 #x14 #x15 #x16 #x17 #x18 #x19)
                  '(simple-array (unsigned-byte 8) (*))))
         (tc4-data
          (make-array 50 :element-type '(unsigned-byte 8) :initial-element #xcd))
         (tc4-expected
          #(#x82 #x55 #x8a #x38 #x9a #x44 #x3c #x0e #xa4 #xcc #x81 #x98 #x99 #xf2 #x08 #x3a
            #x85 #xf0 #xfa #xa3 #xe5 #x78 #xf8 #x07 #x7a #x2e #x3f #xf4 #x67 #x29 #x66 #x5b))
         (tc4-got (dds.dare:hmac-sha256 tc4-key tc4-data)))
    (%check :kxkey-hmac-tc4-len (= (length tc4-got) 32)
            (format nil "RFC 4231 TC4: HMAC-SHA256 length ~d != 32" (length tc4-got)))
    (%check :kxkey-hmac-tc4-val (equalp tc4-got (coerce tc4-expected '(simple-array (unsigned-byte 8) (*))))
            (format nil "RFC 4231 TC4: HMAC-SHA256 mismatch; got ~{~2,'0x~}" (coerce tc4-got 'list))))

  ;;; --- (b) derive-kx-key structural / determinism / asymmetry checks ---
  ;; Fixed inputs (no published composed vector exists; Clasp+SBCL cross-check is the method).
  (let* ((shared-secret
          (make-array 32 :element-type '(unsigned-byte 8)
                         :initial-contents '(#x01 #x02 #x03 #x04 #x05 #x06 #x07 #x08
                                             #x09 #x0a #x0b #x0c #x0d #x0e #x0f #x10
                                             #x11 #x12 #x13 #x14 #x15 #x16 #x17 #x18
                                             #x19 #x1a #x1b #x1c #x1d #x1e #x1f #x20)))
         (challenge1
          (make-array 32 :element-type '(unsigned-byte 8)
                         :initial-contents '(#xa1 #xa2 #xa3 #xa4 #xa5 #xa6 #xa7 #xa8
                                             #xa9 #xaa #xab #xac #xad #xae #xaf #xb0
                                             #xb1 #xb2 #xb3 #xb4 #xb5 #xb6 #xb7 #xb8
                                             #xb9 #xba #xbb #xbc #xbd #xbe #xbf #xc0)))
         (challenge2
          (make-array 32 :element-type '(unsigned-byte 8)
                         :initial-contents '(#xc1 #xc2 #xc3 #xc4 #xc5 #xc6 #xc7 #xc8
                                             #xc9 #xca #xcb #xcc #xcd #xce #xcf #xd0
                                             #xd1 #xd2 #xd3 #xd4 #xd5 #xd6 #xd7 #xd8
                                             #xd9 #xda #xdb #xdc #xdd #xde #xdf #xe0)))
         (kx1 (dds.security:derive-kx-key shared-secret challenge1 challenge2))
         (kx2 (dds.security:derive-kx-key shared-secret challenge1 challenge2))
         (kxs (dds.security:derive-kx-salt shared-secret challenge1 challenge2)))
    (unwind-protect
         (progn
           ;; Output length must be 32 bytes
           (%check :kxkey-len-32 (= (length (dds.security:kx-key-bytes kx1)) 32)
                   (format nil "derive-kx-key output length ~d != 32"
                           (length (dds.security:kx-key-bytes kx1))))
           ;; Determinism: same inputs must yield same output
           (%check :kxkey-deterministic
                   (equalp (dds.security:kx-key-bytes kx1) (dds.security:kx-key-bytes kx2))
                   "derive-kx-key is not deterministic for identical inputs")
           ;; KxKey != KxSalt: swapped challenges must produce a distinct output
           (%check :kxkey-ne-kxsalt
                   (not (equalp (dds.security:kx-key-bytes kx1) (dds.security:kx-key-bytes kxs)))
                   "KxKey == KxSalt: challenge swap had no effect (construction error)")
           ;; KxKey != raw shared_secret (output is derived, not copied)
           (%check :kxkey-ne-secret
                   (not (equalp (dds.security:kx-key-bytes kx1) shared-secret))
                   "KxKey == raw shared_secret (KDF produced identity output)"))
      (dds.security:free-kx-key kx1)
      (dds.security:free-kx-key kx2)
      (dds.security:free-kx-key kxs)))

  ;; free-kx-key must return nil (idempotent)
  (%check :kxkey-free-nil (null (dds.security:free-kx-key nil))
          "free-kx-key(nil) must return nil")

  t)

;;; ============================================================
;;; WP-DDS-SECURITY-AUTH-KEYX T3: §9.5.2 KeyMaterial round-trip + fuzz
;;; ============================================================

;;; KAT fixtures for T3 tests: fixed shared-secret and challenges (same as run-auth-kxkey-kat).
(defparameter *kat-shared-secret*
  (make-array 32 :element-type '(unsigned-byte 8)
                 :initial-contents '(#x01 #x02 #x03 #x04 #x05 #x06 #x07 #x08
                                     #x09 #x0a #x0b #x0c #x0d #x0e #x0f #x10
                                     #x11 #x12 #x13 #x14 #x15 #x16 #x17 #x18
                                     #x19 #x1a #x1b #x1c #x1d #x1e #x1f #x20))
  "Fixed shared-secret for T3 KAT (non-secret test fixture; not for production).")

(defparameter *kat-challenge1*
  (make-array 32 :element-type '(unsigned-byte 8)
                 :initial-contents '(#xa1 #xa2 #xa3 #xa4 #xa5 #xa6 #xa7 #xa8
                                     #xa9 #xaa #xab #xac #xad #xae #xaf #xb0
                                     #xb1 #xb2 #xb3 #xb4 #xb5 #xb6 #xb7 #xb8
                                     #xb9 #xba #xbb #xbc #xbd #xbe #xbf #xc0))
  "Fixed challenge1 for T3 KAT (non-secret test fixture).")

(defparameter *kat-challenge2*
  (make-array 32 :element-type '(unsigned-byte 8)
                 :initial-contents '(#xc1 #xc2 #xc3 #xc4 #xc5 #xc6 #xc7 #xc8
                                     #xc9 #xca #xcb #xcc #xcd #xce #xcf #xd0
                                     #xd1 #xd2 #xd3 #xd4 #xd5 #xd6 #xd7 #xd8
                                     #xd9 #xda #xdb #xdc #xdd #xde #xdf #xe0))
  "Fixed challenge2 for T3 KAT (non-secret test fixture).")

(defparameter *some-writer-guid*
  (make-array 16 :element-type '(unsigned-byte 8)
                 :initial-contents '(#x01 #x02 #x03 #x04 #x05 #x06 #x07 #x08
                                     #x09 #x0a #x0b #x0c #x0d #x0e #x0f #x10))
  "Fixed writer GUID for T3 KAT (test fixture only).")

(defparameter *wrong-kx-bytes*
  (make-array 32 :element-type '(unsigned-byte 8)
                 :initial-contents '(#xff #xfe #xfd #xfc #xfb #xfa #xf9 #xf8
                                     #xf7 #xf6 #xf5 #xf4 #xf3 #xf2 #xf1 #xf0
                                     #xef #xee #xed #xec #xeb #xea #xe9 #xe8
                                     #xe7 #xe6 #xe5 #xe4 #xe3 #xe2 #xe1 #xe0))
  "Wrong KxKey for T3 fail-closed proofs (deliberately wrong key; must cause AEAD auth failure).")

(defun* run-auth-keymaterial-roundtrip ()
    (function () t)
  "WP-DDS-SECURITY-AUTH-KEYX T3: §9.5.2 KeyMaterial generation + CryptoToken codec round-trip.
   NON-VACUOUS: genuinely generated KeyMaterial (not hardcoded); fail-closed proofs included.
   (a) generate KM -> serialize-crypto-token under KxKey -> parse-crypto-token under SAME KxKey
       -> parsed KM slots byte-equal originals (round-trip).
   (b) parse under WRONG KxKey -> NIL (GCM auth failure proves AEAD gate is active).
   (c) flipped ciphertext byte -> NIL; (d) flipped tag byte -> NIL.
   (e) make-crypto-token-message / parse-crypto-token-message envelope round-trip.
   (f) 2-DataHolder message -> NIL (cap enforced, spike §6.3).
   Requires OpenSSL >= 3.5; skips gracefully if absent. Both SBCL and Clasp must pass."
  (handler-case (dds.dare:dare-available-p)
    (dds.dare:dare-unavailable (c)
      (format t "~&  [auth-keymaterial-roundtrip] SKIP — OpenSSL >= 3.5 not available: ~a~%"
              (dds.dare:dare-unavailable-reason c))
      (return-from run-auth-keymaterial-roundtrip t)))

  (let* ((kx  (dds.security:derive-kx-key *kat-shared-secret* *kat-challenge1* *kat-challenge2*))
         (km  (dds.security:generate-writer-key-material *some-writer-guid*)))
    (unwind-protect
         (let* ((kx-bytes (dds.security:kx-key-bytes kx))
                (tok (dds.security:serialize-crypto-token km kx-bytes)))

           ;; (a) round-trip: parse under the same KxKey -> byte-equal fields
           (let ((got (dds.security:parse-crypto-token tok kx-bytes)))
             (%check :km-rt-not-nil (not (null got))
                     "parse-crypto-token returned NIL on valid token + correct KxKey")
             (when got
               (%check :km-rt-kind
                       (equalp (dds.security:key-material-transformation-kind got)
                               (dds.security:key-material-transformation-kind km))
                       "round-trip: transformation-kind mismatch")
               (%check :km-rt-salt
                       (equalp (dds.security:key-material-master-salt got)
                               (dds.security:key-material-master-salt km))
                       "round-trip: master-salt mismatch")
               (%check :km-rt-kid
                       (equalp (dds.security:key-material-sender-key-id got)
                               (dds.security:key-material-sender-key-id km))
                       "round-trip: sender-key-id mismatch")
               (%check :km-rt-key
                       (equalp (dds.security:key-material-master-sender-key got)
                               (dds.security:key-material-master-sender-key km))
                       "round-trip: master-sender-key mismatch")))

           ;; (b) wrong KxKey -> NIL (GCM auth failure)
           (%check :km-wrong-kx
                   (null (dds.security:parse-crypto-token tok *wrong-kx-bytes*))
                   "parse-crypto-token under wrong KxKey must return NIL (GCM auth must gate)")

           ;; (c) flipped byte inside ciphertext/tag area -> NIL
           ;; DataHolder layout (§9.3.4, T1 name+value-only): class_id CDR string + PropertySeq(count=0) +
           ;; BinaryPropertySeq (count=1 + name CDR string + value u32-len + 116-byte blob).
           ;; The 116-byte blob (nonce(12)||ct(88)||tag(16)) is now the LAST field (no trailing propagate);
           ;; the GCM tag is the final 16 bytes. Flipping the last byte lands in the tag -> auth failure.
           (let* ((tok-flip (copy-seq tok))
                  (n-tok    (length tok-flip))
                  (flip-idx (- n-tok 1))) ; last byte = final GCM tag byte (no trailing propagate, T1)
             (when (> flip-idx 0)
               (setf (aref tok-flip flip-idx)
                     (logxor (aref tok-flip flip-idx) #xFF)))
             (%check :km-flip-byte
                     (null (dds.security:parse-crypto-token tok-flip kx-bytes))
                     "parse-crypto-token with flipped tag byte must return NIL (GCM auth failure)"))

           ;; (d) empty / zero-length input -> NIL
           (%check :km-empty-nil
                   (null (dds.security:parse-crypto-token
                          (make-array 0 :element-type '(unsigned-byte 8)) kx-bytes))
                   "parse-crypto-token on empty input must return NIL")

           ;; (e) envelope round-trip
           (let* ((src-guid  *some-writer-guid*)
                  (dest-guid (make-array 16 :element-type '(unsigned-byte 8) :initial-element 0))
                  (env (dds.security:make-crypto-token-message km kx-bytes src-guid dest-guid))
                  (km2 (dds.security:parse-crypto-token-message env kx-bytes)))
             (%check :ctm-not-nil (not (null km2))
                     "parse-crypto-token-message returned NIL on valid envelope")
             (when km2
               (%check :ctm-key
                       (equalp (dds.security:key-material-master-sender-key km2)
                               (dds.security:key-material-master-sender-key km))
                       "envelope round-trip: master-sender-key mismatch")))

           ;; (f) envelope with wrong class_id -> NIL
           ;; Construct a GenericMessage with class_id != +gm-participant-crypto-tokens+
           (let* ((zero-16  (make-array 16 :element-type '(unsigned-byte 8) :initial-element 0))
                  (dh-blob  (dds.security:serialize-crypto-token km kx-bytes))
                  (bad-env  (dds.security:make-generic-message
                             :source-guid          *some-writer-guid*
                             :sequence-number      0
                             :related-guid         zero-16
                             :related-sn           0
                             :dest-participant-guid zero-16
                             :dest-endpoint-guid   zero-16
                             :source-endpoint-guid *some-writer-guid*
                             :message-class-id     "dds.sec.WRONG"
                             :dataholders          (list dh-blob))))
             (%check :ctm-wrong-class
                     (null (dds.security:parse-crypto-token-message bad-env kx-bytes))
                     "parse-crypto-token-message with wrong class_id must return NIL"))

           ;; (g) 2-DataHolder message -> NIL (cap enforced directly; spike §6.3)
           (let* ((zero-16  (make-array 16 :element-type '(unsigned-byte 8) :initial-element 0))
                  (dh1      (dds.security:serialize-crypto-token km kx-bytes))
                  (dh2      (dds.security:serialize-crypto-token km kx-bytes))
                  (two-dh-env (dds.security:make-generic-message
                               :source-guid          *some-writer-guid*
                               :sequence-number      0
                               :related-guid         zero-16
                               :related-sn           0
                               :dest-participant-guid zero-16
                               :dest-endpoint-guid   zero-16
                               :source-endpoint-guid *some-writer-guid*
                               :message-class-id     dds.security::+gm-participant-crypto-tokens+
                               :dataholders          (list dh1 dh2))))
             (%check :ctm-two-dataholder-nil
                     (null (dds.security:parse-crypto-token-message two-dh-env kx-bytes))
                     "parse-crypto-token-message with 2 DataHolders must return NIL (cap: exactly 1 DH per message)")))
      (dds.security:free-kx-key kx)))
  t)

(defun* run-auth-keymaterial-origin-auth-cdr ()
    (function () t)
  "WP-DDS-SECURITY-SECURE-DISCOVERY T-ORIGINAUTH: the §9.5.2 KeyMaterial CDR codec carries the POPULATED
   receiver-specific fields (the 120-byte *_WITH_ORIGIN_AUTHENTICATION form, Fast DDS KeyMaterialCDRSerialize
   L432-454 / KeyMaterialCDRDeserialize L511-528 has_specific_key discriminator) — the crypto-token exchange
   must retain the remote's receiver key so origin-auth can be wired. Deterministic (no OpenSSL — explicit
   KeyMaterial), both impls. Asserts:
   (a) a populated origin-auth KeyMaterial serializes to exactly 120 octets and round-trips
       receiver_specific_key_id + master_receiver_specific_key (and master_salt) byte-exact;
   (b) NON-VACUOUS byte-identical carry: a no-origin-auth KeyMaterial still serializes to exactly 88 octets
       with all-zero receiver fields (the SIGN/ENCRYPT token path is unchanged)."
  (let* ((oa-km (dds.security:make-key-material
                 :transformation-kind          (copy-seq dds.security:+transformation-kind-aes256-gcm+)
                 :master-salt                  (make-array 32 :element-type '(unsigned-byte 8) :initial-element #x11)
                 :sender-key-id                (make-array 4 :element-type '(unsigned-byte 8) :initial-contents '(1 2 3 4))
                 :master-sender-key            (make-array 32 :element-type '(unsigned-byte 8) :initial-element #x22)
                 :receiver-specific-key-id     (make-array 4 :element-type '(unsigned-byte 8) :initial-contents '(9 8 7 6))
                 :master-receiver-specific-key (make-array 32 :element-type '(unsigned-byte 8) :initial-element #x33)))
         (oa-cdr  (dds.security::%serialize-km-cdr oa-km))
         (oa-back (dds.security::%parse-km-cdr oa-cdr)))
    (%check :km-oa-len (= (length oa-cdr) 120)
            (format nil "origin-auth KeyMaterial CDR must be 120 octets; got ~d" (length oa-cdr)))
    (%check :km-oa-parsed (not (null oa-back)) "%parse-km-cdr must accept the 120-byte origin-auth form")
    (when oa-back
      (%check :km-oa-rsk-id
              (equalp (dds.security:key-material-receiver-specific-key-id oa-back)
                      (dds.security:key-material-receiver-specific-key-id oa-km))
              "round-trip must preserve receiver_specific_key_id")
      (%check :km-oa-rsk-key
              (equalp (dds.security:key-material-master-receiver-specific-key oa-back)
                      (dds.security:key-material-master-receiver-specific-key oa-km))
              "round-trip must preserve master_receiver_specific_key (the receiver key the token carries)")
      (%check :km-oa-salt
              (equalp (dds.security:key-material-master-salt oa-back)
                      (dds.security:key-material-master-salt oa-km))
              "round-trip must preserve master_salt"))
    ;; (b) no-origin-auth form stays the byte-identical 88-byte CDR with all-zero receiver fields
    (let* ((plain-km   (dds.security:make-key-material
                        :transformation-kind (copy-seq dds.security:+transformation-kind-aes256-gcm+)
                        :master-salt         (make-array 32 :element-type '(unsigned-byte 8) :initial-element #x44)
                        :sender-key-id       (make-array 4 :element-type '(unsigned-byte 8) :initial-contents '(5 6 7 8))
                        :master-sender-key   (make-array 32 :element-type '(unsigned-byte 8) :initial-element #x55)))
           (plain-cdr  (dds.security::%serialize-km-cdr plain-km))
           (plain-back (dds.security::%parse-km-cdr plain-cdr)))
      (%check :km-plain-len (= (length plain-cdr) 88)
              (format nil "no-origin-auth KeyMaterial CDR must stay 88 octets; got ~d" (length plain-cdr)))
      (%check :km-plain-rsk-zero
              (and plain-back (every #'zerop (dds.security:key-material-receiver-specific-key-id plain-back))
                   (every #'zerop (dds.security:key-material-master-receiver-specific-key plain-back)))
              "no-origin-auth round-trip must keep the receiver-specific fields all-zero")))
  t)

;;; Safety-0 compiled inner loop for crypto-token parser fuzz.

(defun* %fuzz-crypto-token-loop-s0 (blobs kx-key)
    (function (list (simple-array (unsigned-byte 8) (32))) (unsigned-byte 32))
  "Feed each blob through parse-crypto-token and parse-crypto-token-message at (safety 0).
   Returns count of nil results (both parsers * blobs). All must be NIL and no signals must escape."
  (declare (optimize (safety 0) (speed 3)))
  (let ((nil-count 0))
    (declare (type (unsigned-byte 32) nil-count))
    (dolist (blob blobs nil-count)
      (let ((r1 (dds.security:parse-crypto-token blob kx-key)))
        (when (null r1) (incf nil-count)))
      (let ((r2 (dds.security:parse-crypto-token-message blob kx-key)))
        (when (null r2) (incf nil-count))))))

(defun* run-auth-cryptotoken-fuzz ()
    (function () t)
  "WP-DDS-SECURITY-AUTH-KEYX T3 fuzz: 2000 random/truncated blobs through parse-crypto-token
   and parse-crypto-token-message, under BOTH normal and (safety 0) compiled paths (NFR-SEC-POSTURE).
   Every result must be NIL and nothing must crash or signal (fail-closed).
   Blob sizes: 0..299 bytes (covers truncations and near-valid lengths).
   Requires OpenSSL >= 3.5; skips gracefully if absent. Both SBCL and Clasp must pass."
  (handler-case (dds.dare:dare-available-p)
    (dds.dare:dare-unavailable (c)
      (format t "~&  [auth-cryptotoken-fuzz] SKIP — OpenSSL >= 3.5 not available: ~a~%"
              (dds.dare:dare-unavailable-reason c))
      (return-from run-auth-cryptotoken-fuzz t)))

  ;; A fixed but non-trivial KxKey for fuzz parsing (not used for anything real)
  (let* ((fuzz-kx-key (make-array 32 :element-type '(unsigned-byte 8)
                                     :initial-contents '(#x42 #x42 #x42 #x42 #x42 #x42 #x42 #x42
                                                         #x42 #x42 #x42 #x42 #x42 #x42 #x42 #x42
                                                         #x42 #x42 #x42 #x42 #x42 #x42 #x42 #x42
                                                         #x42 #x42 #x42 #x42 #x42 #x42 #x42 #x42)))
         (fuzz-blobs '())
         (crash-count 0)
         (non-nil-count 0))
    ;; Build deterministic blob list (matches pattern in run-auth-wire-fuzz-test)
    (dotimes (_ 1000)
      (let* ((idx (length fuzz-blobs))
             (sz  (mod (* idx 17) 300))
             (blob (make-array (max sz 0) :element-type '(unsigned-byte 8)
                                          :initial-element (ldb (byte 8 0) (+ (* idx 7) 42)))))
        ;; non-trivial fill: byte[i] = (i * idx + 37) mod 256
        (dotimes (i (length blob))
          (setf (aref blob i) (ldb (byte 8 0) (+ (* i (1+ idx)) 37))))
        (push blob fuzz-blobs)))
    (dotimes (i 1000)
      (let* ((sz (mod i 300))
             (blob (make-array sz :element-type '(unsigned-byte 8) :initial-element (mod i 256))))
        (push blob fuzz-blobs)))
    (setf fuzz-blobs (nreverse fuzz-blobs))
    (let ((fuzz-count (length fuzz-blobs)))
      ;; Normal-optimization pass
      (dolist (blob fuzz-blobs)
        (let ((r1 (handler-case
                      (dds.security:parse-crypto-token blob fuzz-kx-key)
                    (error (c) (declare (ignore c)) :crashed))))
          (when (eq r1 :crashed) (incf crash-count))
          (when (and (not (null r1)) (not (eq r1 :crashed))) (incf non-nil-count)))
        (let ((r2 (handler-case
                      (dds.security:parse-crypto-token-message blob fuzz-kx-key)
                    (error (c) (declare (ignore c)) :crashed))))
          (when (eq r2 :crashed) (incf crash-count))
          (when (and (not (null r2)) (not (eq r2 :crashed))) (incf non-nil-count))))
      (%check :fuzz-no-crash (zerop crash-count)
              (format nil "parse-crypto-token/message crashed ~d time(s) on fuzz input" crash-count))
      (%check :fuzz-all-nil (zerop non-nil-count)
              (format nil "parse-crypto-token/message returned non-NIL ~d time(s) on random input" non-nil-count))
      ;; safety-0 compiled pass: both parsers * fuzz-count blobs = 2*fuzz-count expected nil results
      (let ((s0-nil-count
              (handler-case
                  (%fuzz-crypto-token-loop-s0 fuzz-blobs fuzz-kx-key)
                (error (e)
                  (error 'test-failure :name :fuzz-ct-s0-escaped
                         :detail (format nil "cryptotoken-fuzz safety-0: signal escaped: ~a" e))))))
        (%check :fuzz-s0-all-nil (= s0-nil-count (* 2 fuzz-count))
                (format nil "cryptotoken-fuzz safety-0: ~d/~d nil-results (expect ~d)"
                        s0-nil-count (* 2 fuzz-count) (* 2 fuzz-count))))
      (format t "~&  [auth-cryptotoken-fuzz] ~d blobs exercised (parse-crypto-token + parse-ctm-message, normal + safety-0)~%"
              fuzz-count)))
  t)

;;; ============================================================
;;; WP-DDS-SECURITY-AUTH-KEYX T7: strict-refuse + don't-break-plain integration
;;; ============================================================
;;; T7a: a security-enabled participant strictly refuses a plain (no-identity) peer
;;;      (auth-gate returns :incompatible because the plain peer has no IdentityToken ->
;;;      no AUTH-REMOTE entry -> gate verdict = :incompatible -> endpoint never matched).
;;;      NON-VACUOUS: a plain<->plain pair on the SAME topic/type/QoS DOES match — proving
;;;      the non-match is the auth-gate's strict refusal, not a topic/type/QoS mismatch.
;;;
;;; T7b: two plain participants (no identity) match and exchange data byte-exact as the
;;;      non-security baseline does — the security build does not regress the default path.

(defun* run-auth-secured-refuses-plain-test ()
    (function () t)
  "WP-DDS-SECURITY-AUTH-KEYX T7a: DDS-Security §7.3 strict posture (allow_unauthenticated=FALSE).
   Setup: security-enabled participant SEC (with EC identity) + plain participant PLAIN (no identity),
   both on topic 'SecPlainTopic'/'SPType' with matching reliable/transient-local QoS.
   Assert: after discovery, SEC's disc-node-matched-count for PLAIN is 0 — the auth-gate
   returns :incompatible (plain peer has no IdentityToken -> no AUTH-REMOTE -> strict refuse).
   NON-VACUOUS: plain participants C and D on the SAME topic/type/QoS DO match (matched-count >=1),
   proving the SEC<->PLAIN non-match is the auth-gate, not a topic/type/QoS mismatch.
   Requires OpenSSL >= 3.5 (identity load); skips gracefully if absent. Both SBCL and Clasp must pass."
  (handler-case (dds.dare:dare-available-p)
    (dds.dare:dare-unavailable (c)
      (format t "~&  [auth-secured-refuses-plain] SKIP — OpenSSL >= 3.5 not available: ~a~%"
              (dds.dare:dare-unavailable-reason c))
      (return-from run-auth-secured-refuses-plain-test t)))

  (let* ((ca-pem    (%read-fixture-pem "ca/ca-cert.pem"))
         (ec-cert   (%read-fixture-pem "participant_ec/identity_cert.pem"))
         (ec-key    (%read-fixture-pem "participant_ec/identity_key.pem"))
         (guid-sec  (make-array 16 :element-type '(unsigned-byte 8)
                                   :initial-contents '(10 0 0 0 0 0 0 0 0 0 0 0 0 0 0 1))))
    (multiple-value-bind (id-sec reason-sec)
        (dds.security:validate-local-identity ca-pem ec-cert ec-key guid-sec)
      (%check :srp-id-ok (not (null id-sec))
              (format nil "validate-local-identity failed: ~a" reason-sec))
      (unless id-sec (return-from run-auth-secured-refuses-plain-test t))
      (unwind-protect
           ;; SEC: security-enabled (has identity, auth-gate installed, IdentityToken in SPDP)
           ;; PLAIN: no identity (dp-auth-state NIL, no IdentityToken in SPDP)
           (let ((p-sec nil) (p-plain nil)
                 ;; NON-VACUITY control: C and D are both plain, same topic/type/QoS
                 (p-c nil) (p-d nil))
             (unwind-protect
                  (progn
                    (setf p-sec   (dds.dcps:create-participant :domain (test-domain +td-no-double-delivery+) :identity id-sec))
                    (setf p-plain (dds.dcps:create-participant :domain (test-domain +td-no-double-delivery+)))
                    (setf p-c     (dds.dcps:create-participant :domain (test-domain +td-no-double-delivery+)))
                    (setf p-d     (dds.dcps:create-participant :domain (test-domain +td-no-double-delivery+)))
                    (let* ((node-sec   (dds.dcps::dp-node p-sec))
                         (node-plain (dds.dcps::dp-node p-plain))
                         (node-c     (dds.dcps::dp-node p-c))
                         (node-d     (dds.dcps::dp-node p-d))
                         (topic      "SecPlainTopic")
                         (ttype      "SPType")
                         (wqos       (dds.qos:make-writer-qos :reliability :reliable
                                                              :durability :transient-local))
                         (rqos       (dds.qos:make-reader-qos :reliability :reliable
                                                              :durability :transient-local)))
                    ;; set up endpoints on all four nodes (same topic/type/QoS)
                    (dds.disc:add-local-writer node-sec :topic topic :type ttype :qos wqos)
                    (dds.disc:enable-publisher node-sec :history-kind :keep-all)
                    (dds.disc:add-local-reader node-plain :topic topic :type ttype :qos rqos)
                    (dds.disc:enable-subscriber node-plain)
                    (dds.disc:add-local-writer node-c :topic topic :type ttype :qos wqos)
                    (dds.disc:enable-publisher node-c :history-kind :keep-all)
                    (dds.disc:add-local-reader node-d :topic topic :type ttype :qos rqos)
                    (dds.disc:enable-subscriber node-d)
                    ;; wire SEC<->PLAIN for mutual discovery; C<->D for the control pair
                    (setf (dds.disc:disc-node-peers node-sec)
                          (list (cons "127.0.0.1" (dds.disc:disc-node-port node-plain))))
                    (setf (dds.disc:disc-node-peers node-plain)
                          (list (cons "127.0.0.1" (dds.disc:disc-node-port node-sec))))
                    (setf (dds.disc:disc-node-peers node-c)
                          (list (cons "127.0.0.1" (dds.disc:disc-node-port node-d))))
                    (setf (dds.disc:disc-node-peers node-d)
                          (list (cons "127.0.0.1" (dds.disc:disc-node-port node-c))))
                    ;; drive discovery for both pairs (~3 s budget each)
                    ;; control pair C<->D must match (plain<->plain: no gate)
                    (loop repeat 200
                          until (>= (dds.disc:disc-node-matched-count node-c) 1)
                          do (dds.dcps:spin p-c) (dds.dcps:spin p-d) (sleep 0.02))
                    ;; drive SEC<->PLAIN discovery (same budget); SEC must NOT match PLAIN
                    (loop repeat 200
                          do (dds.dcps:spin p-sec) (dds.dcps:spin p-plain) (sleep 0.02))
                    ;; precondition: verify auth-state config before headline assertions
                    (%check :srp-sec-has-auth-state
                            (not (null (dds.dcps::dp-auth-state p-sec)))
                            "SEC participant must have DP-AUTH-STATE set (security-enabled)")
                    (%check :srp-plain-no-auth-state
                            (null (dds.dcps::dp-auth-state p-plain))
                            "PLAIN participant must have NIL DP-AUTH-STATE (no identity)")
                    ;; === NON-VACUITY: C<->D plain pair matched ===
                    (%check :srp-control-matched
                            (>= (dds.disc:disc-node-matched-count node-c) 1)
                            (format nil "NON-VACUITY FAILED: plain<->plain C/D did not match (count ~d); topic/QoS config error"
                                    (dds.disc:disc-node-matched-count node-c)))
                    ;; === HEADLINE: SEC must NOT match the plain peer ===
                    (%check :srp-sec-refuses-plain
                            (zerop (dds.disc:disc-node-matched-count node-sec))
                            (format nil "STRICT-REFUSE FAILED: security-enabled SEC matched ~d plain endpoint(s) — auth-gate must return :incompatible for a peer with no IdentityToken"
                                    (dds.disc:disc-node-matched-count node-sec)))
                    t))
               (when p-d     (ignore-errors (dds.dcps:delete-participant p-d)))
               (when p-c     (ignore-errors (dds.dcps:delete-participant p-c)))
               (when p-plain (ignore-errors (dds.dcps:delete-participant p-plain)))
               (when p-sec   (ignore-errors (dds.dcps:delete-participant p-sec)))))
        (dds.security:free-identity-handle id-sec))))
  t)

(defun* run-auth-plain-byte-identical-test ()
    (function () t)
  "WP-DDS-SECURITY-AUTH-KEYX T7b: don't-break-plain guarantee.
   Two PLAIN participants (no identity configured) on topic 'PlainIdTopic'/'PIType' with
   reliable/transient-local QoS discover each other, match, and exchange a data sample
   byte-exact — exactly as the non-security baseline does. Confirms: no IdentityToken in SPDP,
   no PSM bits, normal SEDP match, and DATA delivery with exact payload recovery.
   Proves the security build does not regress the unauthenticated default path.
   No OpenSSL dependency; must pass on BOTH SBCL and Clasp unconditionally."
  (let ((p-w nil)
        (p-r nil))
    (unwind-protect
         (progn
           (setf p-w (dds.dcps:create-participant :domain (test-domain +td-origin-accessor+)))
           (setf p-r (dds.dcps:create-participant :domain (test-domain +td-origin-accessor+)))
           (let* ((node-w (dds.dcps::dp-node p-w))
                (node-r (dds.dcps::dp-node p-r))
                (topic  "PlainIdTopic")
                (ttype  "PIType")
                (pt     (make-array 8 :element-type '(unsigned-byte 8)
                                      :initial-contents '(#x50 #x4c #x41 #x49 #x4e #x44 #x41 #x54))))
           ;; neither participant must be security-enabled
           (%check :pbi-w-no-auth (null (dds.dcps::dp-auth-state p-w))
                   "writer participant must have NIL DP-AUTH-STATE (plain path)")
           (%check :pbi-r-no-auth (null (dds.dcps::dp-auth-state p-r))
                   "reader participant must have NIL DP-AUTH-STATE (plain path)")
           ;; set up endpoints
           (dds.disc:add-local-writer node-w :topic topic :type ttype
                                      :qos (dds.qos:make-writer-qos :reliability :reliable
                                                                     :durability :transient-local))
           (dds.disc:enable-publisher node-w :history-kind :keep-all)
           (dds.disc:add-local-reader node-r :topic topic :type ttype
                                      :qos (dds.qos:make-reader-qos :reliability :reliable
                                                                     :durability :transient-local))
           (dds.disc:enable-subscriber node-r)
           ;; unicast peer wiring
           (setf (dds.disc:disc-node-peers node-w)
                 (list (cons "127.0.0.1" (dds.disc:disc-node-port node-r))))
           (setf (dds.disc:disc-node-peers node-r)
                 (list (cons "127.0.0.1" (dds.disc:disc-node-port node-w))))
           ;; drive discovery until matched
           (loop repeat 300
                 until (>= (dds.disc:disc-node-matched-count node-w) 1)
                 do (dds.dcps:spin p-w) (dds.dcps:spin p-r) (sleep 0.02))
           ;; assert matched
           (%check :pbi-matched
                   (>= (dds.disc:disc-node-matched-count node-w) 1)
                   (format nil "plain<->plain writer/reader did not match (count ~d)"
                           (dds.disc:disc-node-matched-count node-w)))
           ;; publish sample and wait for delivery
           (dds.disc:publish-sample node-w pt)
           (loop repeat 300
                 until (plusp (dds.disc:node-sample-count node-r))
                 do (dds.dcps:spin p-w) (dds.dcps:spin p-r) (sleep 0.02))
           (%check :pbi-received
                   (plusp (dds.disc:node-sample-count node-r))
                   "plain reader did not receive any sample from plain writer")
           ;; assert payload byte-exact
           (let* ((key     (first (dds.disc:node-sample-sns node-r)))
                  (payload (dds.disc:node-sample node-r key)))
             (%check :pbi-byte-exact
                     (and payload (equalp payload pt))
                     (format nil "plain round-trip payload mismatch: got ~a; expected ~{~2,'0x~^ ~}"
                             (and payload (coerce payload 'list))
                             (coerce pt 'list))))
           t))
      (when p-r (ignore-errors (dds.dcps:delete-participant p-r)))
      (when p-w (ignore-errors (dds.dcps:delete-participant p-w)))))
  t)

;;; T1 (WP-DDS-SECURITY-ACCESS-CONTROL): CMS S/MIME verification KAT.
;;; DDS-Security 1.1 §9.4.1.1 mandates PEM PKCS7 opaque CMS SignedData (SHA-256).
;;; Fixtures: interop/security-access-control/pki/ (generated by gen-test-permissions.sh).

(defun* %read-ac-fixture-pem (relative-path)
    (function (string) (simple-array (unsigned-byte 8) (*)))
  "Read an access-control PKI fixture file relative to +TEST-AC-PKI-ROOT+."
  (let* ((path (merge-pathnames relative-path dds.security:+test-ac-pki-root+)))
    (with-open-file (s path :element-type '(unsigned-byte 8))
      (let* ((n (file-length s))
             (v (make-array n :element-type '(unsigned-byte 8))))
        (read-sequence v s)
        v))))

(defun* %read-ssd-fixture-pem (relative-path)
    (function (string) (simple-array (unsigned-byte 8) (*)))
  "Read a secure-discovery PKI fixture file relative to +TEST-SSD-PKI-ROOT+ (the T0 governance-secure.p7s
   etc.; the perm-CA + Identity-CA are REUSED from the access-control / auth fixtures, T0 spike)."
  (let* ((path (merge-pathnames relative-path dds.security:+test-ssd-pki-root+)))
    (with-open-file (s path :element-type '(unsigned-byte 8))
      (let* ((n (file-length s))
             (v (make-array n :element-type '(unsigned-byte 8))))
        (read-sequence v s)
        v))))

;;; ============================================================
;;; WP-DDS-SECURITY-SECURE-DISCOVERY T9: secure SEDP end-to-end (protected DiscoveredWriterData over the
;;; secure SEDP endpoints; protected topic off plain SEDP; gate on :keyed; plain peer refused)
;;; ============================================================
;;; Two security-enabled participants under governance discovery_protection_kind=ENCRYPT + a topic_rule with
;;; enable_discovery_protection=true authenticate, reach :keyed, and exchange the protected Square endpoint
;;; ONLY over the submessage-protected secure SEDP builtin endpoints (0xff0003/0xff0004) — never plain SEDP —
;;; then match + flow user data byte-exact. A PLAIN (unauthenticated) peer on the same topic never learns the
;;; protected endpoint (the non-vacuous control). Governance NONE -> plain SEDP, asserted byte-identical
;;; structurally by the disc-level run-secure-sedp-roundtrip-test + the plain-byte-identical auth test.

(defun* %run-secure-discovery-e2e (gov-p7s-name topic-visible-p &optional (origin-auth-p nil))
    (function (string t &optional t) t)
  "WP-DDS-SECURITY-SECURE-DISCOVERY T9 (+ T-ORIGINAUTH): secure SEDP DiscoveredWriter/ReaderData end-to-end under
   the signed governance GOV-P7S-NAME (discovery_protection_kind ENCRYPT, SIGN, or ENCRYPT_WITH_ORIGIN_AUTHENTICATION).
   Two security-enabled + access-controlled DomainParticipants A (Square writer) and B (Square reader) authenticate
   and reach :keyed; a third PLAIN participant (no identity) with a Square reader is the non-vacuous control.
   Assertions:
     (a) A and B both reach :keyed (auth + crypto established).
     (b) A advertises secure discovery (the discovery-protected-topic-p predicate is installed -> SPDP
         BuiltinEndpointSet bits 16-19), and a CryptoHeader/SEC_PREFIX bracket is emitted on the wire.
     (c) B MATCHES A's Square writer — A's Square endpoint is OMITTED from plain SEDP (protected), so the
         ONLY path is the submessage-protected secure SEDP endpoint; the endpoints match BOTH directions.
     (d) a Square sample round-trips byte-exact (user data flows after the secure match).
     (e) the on-wire posture HONORS the governance directive (NOT a hardcoded ENCRYPT): when TOPIC-VISIBLE-P
         is NIL (ENCRYPT) the plaintext topic name 'Square' NEVER appears on the wire (confidentiality — it
         rides only inside the secure SEDP ENCRYPT); when T (SIGN, governance-sign — discovery AND rtps both
         SIGN) 'Square' DOES appear in cleartext but ONLY inside a protection bracket — a SEC_PREFIX, or the
         verbatim-SIGN whole-RTPS SRTPS_PREFIX wrap that carries it (authenticated-but-visible, never plain
         SEDP), proving we SIGNed (the review defect was silently ENCRYPTing a SIGN directive).
     (f) NON-VACUOUS control: the PLAIN peer NEVER matches A's protected writer (invisible over plain SEDP).
     (g) ORIGIN-AUTH (when ORIGIN-AUTH-P, T-ORIGINAUTH): governance drove the secure-SEDP RECEIVING readers
         (pub/sub-secure-reader) to be registered WITH a receiver-specific key (non-zero receiver_specific_key_id,
         §9.5.3.3.4.3) on BOTH A and B. With the local reader keyed for origin-auth, the decode-receiver resolver
         sets my-receiver-key-id, so decode REQUIRES a valid receiver-specific MAC — hence B's match (c) PROVES the
         per-receiver MAC was emitted by A and verified by B (decode fails closed without it, even on a valid
         common_mac). The wrong-receiver-key fail-closed control is run-secure-sedp-origin-auth-tamper-test.
   Requires OpenSSL >= 3.5; skips gracefully if absent. Both SBCL and Clasp must pass."
  (handler-case (dds.dare:dare-available-p)
    (dds.dare:dare-unavailable (c)
      (format t "~&  [secure-discovery-e2e ~a] SKIP — OpenSSL >= 3.5 not available: ~a~%"
              gov-p7s-name (dds.dare:dare-unavailable-reason c))
      (return-from %run-secure-discovery-e2e t)))
  (let* ((ca-pem    (%read-fixture-pem "ca/ca-cert.pem"))
         (ec-cert-a (%read-fixture-pem "participant_ec/identity_cert.pem"))
         (ec-key-a  (%read-fixture-pem "participant_ec/identity_key.pem"))
         (ec-cert-b (%read-fixture-pem "participant_ec_b/identity_cert.pem"))
         (ec-key-b  (%read-fixture-pem "participant_ec_b/identity_key.pem"))
         (perm-ca   (%read-ac-fixture-pem "perm-ca-cert.pem"))           ; reused (T0): signs the governance .p7s
         (gov-p7s   (%read-ssd-fixture-pem gov-p7s-name))                ; discovery_protection_kind ENCRYPT | SIGN
         (perm-p7s  (%read-ac-fixture-pem "permissions.p7s"))            ; allows Square pub/sub for both subjects
         (guid-a    (make-array 16 :element-type '(unsigned-byte 8)
                                   :initial-contents '(1 2 3 4 5 6 7 8 9 10 11 12 13 14 15 9)))
         (guid-b    (make-array 16 :element-type '(unsigned-byte 8)
                                   :initial-contents '(200 2 3 4 5 6 7 8 9 10 11 12 13 14 15 9)))
         (topic       "Square")
         (topic-bytes (map '(simple-array (unsigned-byte 8) (*)) #'char-code topic))
         (pt          (make-array 8 :element-type '(unsigned-byte 8)
                                    :initial-contents '(#x53 #x44 #x50 #x52 #x54 #x30 #x30 #x31)))
         (captured '())
         (sec-bracket-seen nil)
         (rtps-wrapped-seen nil)   ; T10: an SRTPS_PREFIX (0x33) whole-RTPS-message bracket on the wire
         (lk (dds.pal:make-lock "secure-discovery-protected")))
    (multiple-value-bind (id-a reason-a)
        (dds.security:validate-local-identity ca-pem ec-cert-a ec-key-a guid-a)
      (%check :sdp-id-a (not (null id-a)) (format nil "validate-local-identity A failed: ~a" reason-a))
      (unless id-a (return-from %run-secure-discovery-e2e t))
      (unwind-protect
           (multiple-value-bind (id-b reason-b)
               (dds.security:validate-local-identity ca-pem ec-cert-b ec-key-b guid-b)
             (%check :sdp-id-b (not (null id-b)) (format nil "validate-local-identity B failed: ~a" reason-b))
             (unless id-b (return-from %run-secure-discovery-e2e t))
             (unwind-protect
                  (let ((p-a (dds.dcps:create-participant
                              :domain (test-domain +td-secure-discovery+) :identity id-a
                              :permissions-ca perm-ca :governance gov-p7s :permissions perm-p7s))
                        (p-b (dds.dcps:create-participant
                              :domain (test-domain +td-secure-discovery+) :identity id-b
                              :permissions-ca perm-ca :governance gov-p7s :permissions perm-p7s))
                        (p-plain (dds.dcps:create-participant :domain (test-domain +td-secure-discovery+))))   ; plain control: no identity
                    (unwind-protect
                         (let* ((node-a (dds.dcps::dp-node p-a))
                                (node-b (dds.dcps::dp-node p-b))
                                (node-plain (dds.dcps::dp-node p-plain))
                                (prefix-a (dds.disc:disc-node-guid-prefix node-a))
                                (prefix-b (dds.disc:disc-node-guid-prefix node-b))
                                (wqos (dds.qos:make-writer-qos :reliability :reliable :durability :transient-local))
                                (rqos (dds.qos:make-reader-qos :reliability :reliable :durability :transient-local)))
                           (setf (dds.disc:disc-node-peers node-a)
                                 (list (cons "127.0.0.1" (dds.disc:disc-node-port node-b))
                                       (cons "127.0.0.1" (dds.disc:disc-node-port node-plain))))
                           (setf (dds.disc:disc-node-peers node-b)
                                 (list (cons "127.0.0.1" (dds.disc:disc-node-port node-a))))
                           (setf (dds.disc:disc-node-peers node-plain)
                                 (list (cons "127.0.0.1" (dds.disc:disc-node-port node-a))))
                           ;; protected Square writer on A, Square reader on B + on the plain control
                           (dds.disc:add-local-writer node-a :topic topic :type "ShapeType" :qos wqos)
                           (dds.disc:enable-publisher node-a :history-kind :keep-all)
                           (dds.disc:add-local-reader node-b :topic topic :type "ShapeType" :qos rqos)
                           (dds.disc:enable-subscriber node-b)
                           (dds.disc:add-local-reader node-plain :topic topic :type "ShapeType" :qos rqos)
                           (dds.disc:enable-subscriber node-plain)
                           ;; (b-pre) the protecting governance installed the discovery-protected predicate on A + B
                           (%check :sdp-a-protected
                                   (not (null (dds.disc:disc-node-discovery-protected-topic-p node-a)))
                                   "A must have the discovery-protected-topic-p predicate installed (protecting governance)")
                           ;; (a-pre) NON-VACUITY: nobody keyed before the exchange
                           (%check :sdp-not-keyed-before
                                   (and (not (%am-remote-keyed-p p-a prefix-b))
                                        (not (%am-remote-keyed-p p-b prefix-a)))
                                   "no remote may be :keyed before the crypto-token exchange completes")
                           ;; drive auth + crypto-token exchange to :keyed (bounded ~8 s)
                           (loop repeat 400
                                 until (and (%am-remote-keyed-p p-a prefix-b)
                                            (%am-remote-keyed-p p-b prefix-a))
                                 do (dds.dcps:spin p-a) (dds.dcps:spin p-b) (dds.dcps:spin p-plain) (sleep 0.02))
                           ;; (a) both reached :keyed
                           (%check :sdp-a-keyed (%am-remote-keyed-p p-a prefix-b)
                                   (format nil "A did not reach :keyed for B (state ~a)" (%am-remote-state p-a prefix-b)))
                           (%check :sdp-b-keyed (%am-remote-keyed-p p-b prefix-a)
                                   (format nil "B did not reach :keyed for A (state ~a)" (%am-remote-state p-b prefix-a)))
                           ;; (g) ORIGIN-AUTH: governance drove the secure-SEDP receiving readers to carry a
                           ;; receiver-specific key (the receiver-MAC mint) on BOTH peers; with the local reader
                           ;; keyed, decode demands a valid receiver-specific MAC, so the later match (c) proves it.
                           (when origin-auth-p
                             (%check :sdp-a-reader-origin-auth
                                     (%cm-local-entity-origin-auth-p p-a dds.rtps.discovery:+entityid-sedp-pub-secure-reader+)
                                     "A's secure-SEDP pub-reader EntityCrypto must be registered WITH origin-auth (non-zero receiver_specific_key_id) under ENCRYPT_WITH_ORIGIN_AUTHENTICATION")
                             (%check :sdp-b-reader-origin-auth
                                     (%cm-local-entity-origin-auth-p p-b dds.rtps.discovery:+entityid-sedp-pub-secure-reader+)
                                     "B's secure-SEDP pub-reader EntityCrypto must be registered WITH origin-auth (non-zero receiver_specific_key_id) under ENCRYPT_WITH_ORIGIN_AUTHENTICATION"))
                           ;; capture A's + B's outbound datagrams (confidentiality + SEC_PREFIX-on-wire proof)
                           ;; while driving to the secure match + sample delivery
                           (let ((dds.disc:*datagram-sink*
                                   (lambda (dg)
                                     (dds.pal:with-lock (lk)
                                       (push dg captured)
                                       (when (> (length dg) 20)
                                         (cond ((= (aref dg 20) dds.security:+submessage-sec-prefix+)
                                                (setf sec-bracket-seen t))
                                               ((= (aref dg 20) dds.security:+submessage-srtps-prefix+)
                                                (setf rtps-wrapped-seen t))))))))   ; T10 whole-RTPS bracket
                             (loop repeat 300
                                   until (and (plusp (dds.disc:disc-node-matched-count node-b))
                                              (plusp (dds.disc:node-sample-count node-b)))
                                   do (when (plusp (dds.disc:disc-node-matched-count node-a))
                                        (dds.disc:publish-sample node-a pt))
                                      (dds.dcps:spin p-a) (dds.dcps:spin p-b) (dds.dcps:spin p-plain)
                                      (sleep 0.02)))
                           ;; (c) B matched A's protected writer over secure SEDP (A's writer is off plain SEDP)
                           (%check :sdp-b-matched (plusp (dds.disc:disc-node-matched-count node-b))
                                   "B did not match A's discovery-protected Square writer (the only path is secure SEDP)")
                           (%check :sdp-b-matched-topic
                                   (member topic (dds.disc:disc-node-matched-topics node-b) :test #'string=)
                                   "B matched the wrong topic (expected the protected Square)")
                           ;; (b) a SEC_PREFIX submessage-protection bracket carrying the protected SEDP was on the wire
                           (%check :sdp-sec-prefix-on-wire sec-bracket-seen
                                   "no SEC_PREFIX submessage-protection bracket was emitted on the wire")
                           ;; (d) the Square sample round-trips byte-exact
                           (%check :sdp-b-received (plusp (dds.disc:node-sample-count node-b))
                                   "B did not receive a Square sample after the secure match")
                           (let* ((b-key     (first (dds.disc:node-sample-sns node-b)))
                                  (b-payload (and b-key (dds.disc:node-sample node-b b-key))))
                             (%check :sdp-byte-exact (and b-payload (equalp b-payload pt))
                                     (format nil "Square sample byte mismatch; got ~a expected ~{~2,'0x~^ ~}"
                                             (and b-payload (coerce b-payload 'list)) (coerce pt 'list))))
                           ;; (h) T10 whole-RTPS-message protection: every governance fixture sets a non-NONE
                           ;;     rtps_protection_kind (governance-secure/-origin-auth = ENCRYPT, governance-sign =
                           ;;     SIGN), so ALL of A's keyed traffic — the secure-SEDP metatraffic AND the user-data
                           ;;     Square DATA to the :keyed B — is SRTPS-wrapped on the wire (offset 20 = SRTPS_PREFIX)
                           ;;     and B decoded it ((d) byte-exact above traverses the unwrap+re-dispatch path; the
                           ;;     SIGN wrap rides the topic verbatim, which is why the (e) SIGN visibility check accepts
                           ;;     an SRTPS_PREFIX). The non-vacuous wrong-ParticipantCrypto / wrong-receiver-key
                           ;;     controls are run-rtps-protection-test.
                           (%check :sdp-rtps-wrapped (dds.pal:with-lock (lk) rtps-wrapped-seen)
                                   "T10: no SRTPS whole-RTPS-message bracket on the wire though rtps_protection_kind=ENCRYPT — A's keyed user data must be wrapped")
                           ;; (e) on-wire posture HONORS the governance directive: ENCRYPT hides the topic name
                           ;;     (never cleartext); SIGN leaves it VISIBLE but ONLY inside a SEC_PREFIX bracket
                           ;;     (never plain SEDP) and it MUST appear (proving SIGN, not a silent ENCRYPT).
                           (if topic-visible-p
                               (%check :sdp-topic-visible-signed
                                       (dds.pal:with-lock (lk)
                                         (and (some (lambda (dg) (search topic-bytes dg)) captured)
                                              ;; Every 'Square' datagram rides inside a PROTECTION bracket — a bare
                                              ;; submessage SEC_PREFIX (0x31) OR, under a SIGN rtps_protection tier
                                              ;; (governance-sign, so the T10 whole-RTPS wrap is verbatim-SIGN, topic
                                              ;; still visible), a whole-RTPS SRTPS_PREFIX (0x33) with the SEC_PREFIX
                                              ;; SIGN bracket inside — NEVER a plain SEDP DATA. Accepting SRTPS_PREFIX
                                              ;; is not a weakening: both are protection brackets (the topic is never
                                              ;; unprotected on the wire).
                                              (every (lambda (dg)
                                                       (or (not (search topic-bytes dg))
                                                           (and (> (length dg) 20)
                                                                (or (= (aref dg 20) dds.security:+submessage-sec-prefix+)
                                                                    (= (aref dg 20) dds.security:+submessage-srtps-prefix+)))))
                                                     captured)))
                                       "SIGN secure discovery must expose 'Square' in cleartext INSIDE a protection bracket (SEC_PREFIX or a SIGN SRTPS_PREFIX whole-RTPS wrap; honoring SIGN, never plain SEDP, never silently ENCRYPTed)")
                               (%check :sdp-topic-not-on-wire
                                       (dds.pal:with-lock (lk)
                                         (notany (lambda (dg) (search topic-bytes dg)) captured))
                                       "confidentiality breach: the protected topic name 'Square' appeared in CLEARTEXT on the wire"))
                           ;; (f) NON-VACUOUS control: the plain peer never matched A's protected writer
                           (loop repeat 50
                                 do (dds.dcps:spin p-a) (dds.dcps:spin p-plain) (sleep 0.02))
                           (%check :sdp-plain-refused (zerop (dds.disc:disc-node-matched-count node-plain))
                                   (format nil "control breach: a PLAIN peer matched a discovery-protected endpoint (~d) — it must be invisible over plain SEDP"
                                           (dds.disc:disc-node-matched-count node-plain)))
                           t)
                      (ignore-errors (dds.dcps:delete-participant p-plain))
                      (ignore-errors (dds.dcps:delete-participant p-b))
                      (ignore-errors (dds.dcps:delete-participant p-a))))
               (dds.security:free-identity-handle id-b)))
        (dds.security:free-identity-handle id-a))))
  t)

(defun* run-secure-discovery-protected-test ()
    (function () t)
  "Secure SEDP e2e under governance discovery_protection_kind = ENCRYPT (confidential): 'Square' never appears
   on the wire in cleartext. Delegates to %run-secure-discovery-e2e; see its full contract."
  (%run-secure-discovery-e2e "governance-secure.p7s" nil))

(defun* run-secure-discovery-protected-sign-test ()
    (function () t)
  "Secure SEDP e2e under governance discovery_protection_kind = SIGN (authenticated-but-visible; the T9 review
   conformance fix): A's protected Square DiscoveredWriterData flows SIGNED over secure SEDP — a SEC_PREFIX
   bracket is emitted and 'Square' IS visible in cleartext INSIDE that bracket (never plain SEDP), proving the
   announce HONORS SIGN instead of hardcoding ENCRYPT. Delegates to %run-secure-discovery-e2e."
  (%run-secure-discovery-e2e "governance-sign.p7s" t))

(defun* run-secure-discovery-origin-auth-test ()
    (function () t)
  "WP-DDS-SECURITY-SECURE-DISCOVERY T-ORIGINAUTH: secure SEDP e2e under governance discovery_protection_kind =
   ENCRYPT_WITH_ORIGIN_AUTHENTICATION (the T0 governance-origin-auth.p7s) — the origin-auth tier T9 previously
   REFUSED is now WIRED. Two security-enabled + access-controlled participants authenticate, reach :keyed
   (exchanging the 120-byte receiver-specific KeyMaterial), and B matches A's protected Square writer over the
   secure SEDP endpoints with a per-receiver MAC (§9.5.3.3.4.3). 'Square' never appears in cleartext (ENCRYPT
   base). The (g) assertions prove BOTH peers minted the secure-SEDP readers WITH a receiver-specific key, so
   the match is gated on a verified receiver-specific MAC (decode fails closed without it). The non-vacuous
   wrong-receiver-key control is run-secure-sedp-origin-auth-tamper-test. Delegates to %run-secure-discovery-e2e
   with ORIGIN-AUTH-P. Requires OpenSSL >= 3.5; skips gracefully if absent. Both SBCL and Clasp must pass."
  (%run-secure-discovery-e2e "governance-origin-auth.p7s" nil t))

(defun* run-protection-kind-base-test ()
    (function () t)
  "WP-DDS-SECURITY-SECURE-DISCOVERY T9 review: dds.security:protection-kind-base decomposes a §9.4.1.2
   ProtectionKind into (values BASE-KIND ORIGIN-AUTH-P). Deterministic (no OpenSSL); both impls. Asserts the
   5-value mapping the secure-SEDP announce (base kind) + the origin-auth fail-closed gate (origin-auth-p) rely on."
  (flet ((base (k) (nth-value 0 (dds.security:protection-kind-base k)))
         (oa   (k) (nth-value 1 (dds.security:protection-kind-base k))))
    (%check :pkb-none    (and (eq (base :none) :none)       (not (oa :none)))    "NONE -> (:none nil)")
    (%check :pkb-sign    (and (eq (base :sign) :sign)       (not (oa :sign)))    "SIGN -> (:sign nil)")
    (%check :pkb-encrypt (and (eq (base :encrypt) :encrypt) (not (oa :encrypt))) "ENCRYPT -> (:encrypt nil)")
    (%check :pkb-sign-oa (and (eq (base :sign-with-origin-auth) :sign) (oa :sign-with-origin-auth))
            "SIGN_WITH_ORIGIN_AUTHENTICATION -> (:sign t)")
    (%check :pkb-enc-oa  (and (eq (base :encrypt-with-origin-auth) :encrypt) (oa :encrypt-with-origin-auth))
            "ENCRYPT_WITH_ORIGIN_AUTHENTICATION -> (:encrypt t)"))
  t)

(defun* run-cms-verify-kat ()
    (function () t)
  "KAT for DDS.DARE:CMS-VERIFY against the Permissions CA (DDS-Security 1.1 §9.4.1.1).
   (a) Good: governance.p7s + perm-ca-cert.pem -> verified bytes containing domain_access_rules.
   (b) Tampered: 1-byte-flipped governance.p7s -> NIL (CMS signature invalid, fail-closed).
   (c) Wrong CA: governance.p7s + identity CA -> NIL (chain verify fails, fail-closed).
   Both SBCL and Clasp must pass."
  (handler-case (dds.dare:dare-available-p)
    (dds.dare:dare-unavailable (c)
      (format t "~&  [cms-verify-kat] SKIP: ~a~%" (dds.dare:dare-unavailable-reason c))
      (return-from run-cms-verify-kat t)))
  (let* ((p7s-octets     (%read-ac-fixture-pem "governance.p7s"))
         (perm-ca-octets (%read-ac-fixture-pem "perm-ca-cert.pem"))
         (needle (map '(simple-array (unsigned-byte 8) (*))
                      #'char-code "domain_access_rules")))
    ;; (a) Good path: valid signature + correct CA -> content with domain_access_rules
    (let ((ca (dds.dare:x509-load-ca perm-ca-octets)))
      (unwind-protect
           (let ((good (dds.dare:cms-verify p7s-octets ca)))
             (%check :cms-verify-good
                     (and good (plusp (length good)))
                     "cms-verify(governance.p7s, perm-ca) must return non-nil bytes")
             (%check :cms-verify-content
                     (and good (search needle good))
                     "cms-verify result must contain ASCII domain_access_rules"))
        (dds.dare:x509-ca-free ca)))
    ;; (b) Tampered: flip one byte in the base64 CMS payload -> signature invalid
    (let* ((tampered (copy-seq p7s-octets))
           (mid (floor (length tampered) 2))
           (ca (dds.dare:x509-load-ca perm-ca-octets)))
      (setf (aref tampered mid) (logxor (aref tampered mid) #x01))
      (unwind-protect
           (%check :cms-verify-tampered
                   (null (dds.dare:cms-verify tampered ca))
                   "cms-verify(tampered.p7s, perm-ca) must return NIL")
        (dds.dare:x509-ca-free ca)))
    ;; (c) Wrong CA: verify governance.p7s against the identity CA -> chain fails
    (let* ((id-ca-octets (%read-fixture-pem "ca/ca-cert.pem"))
           (wrong-ca (dds.dare:x509-load-ca id-ca-octets)))
      (unwind-protect
           (%check :cms-verify-wrong-ca
                   (null (dds.dare:cms-verify p7s-octets wrong-ca))
                   "cms-verify(governance.p7s, identity-ca) must return NIL")
        (dds.dare:x509-ca-free wrong-ca))))
  t)

;;; DDS-Security 1.1 §8.5 CryptoKeyFactory/CryptoKeyExchange hub (T6) tests: the generic
;;; KeyMaterial generator (generate-key-material) + the dds.dcps crypto-manager registries
;;; (ParticipantCrypto + EntityCrypto) + the key resolvers the §9.5.3.3 data path uses.

(defun* %cm-generator-units ()
    (function () t)
  "generate-key-material (§8.5 CryptoKeyFactory primitive): non-zero random master_salt +
   master_sender_key; a process-unique NON-ZERO allocated sender_key_id (distinct across calls);
   all-zero receiver-specific fields by default; NON-ZERO receiver-specific under :origin-auth (the
   T3 carry fix — zero is the §9.5.3.3.4.3 origin-auth-disabled sentinel). generate-writer-key-material
   still delegates (its sender_key_id is the GUID-derived first 4 octets; receiver-specific populated)."
  (let* ((zeros4  (make-array 4  :element-type '(unsigned-byte 8) :initial-element 0))
         (zeros32 (make-array 32 :element-type '(unsigned-byte 8) :initial-element 0))
         (km1 (dds.security:generate-key-material))
         (km2 (dds.security:generate-key-material))
         (kmo (dds.security:generate-key-material :origin-auth t)))
    (%check :cm-gen-salt (not (equalp (dds.security:key-material-master-salt km1) zeros32))
            "generate-key-material fills a non-zero master_salt")
    (%check :cm-gen-key (not (equalp (dds.security:key-material-master-sender-key km1) zeros32))
            "generate-key-material fills a non-zero master_sender_key")
    (%check :cm-gen-kid-nonzero (notevery #'zerop (dds.security:key-material-sender-key-id km1))
            "generate-key-material allocates a non-zero sender_key_id")
    (%check :cm-gen-kid-unique (not (equalp (dds.security:key-material-sender-key-id km1)
                                            (dds.security:key-material-sender-key-id km2)))
            "generate-key-material allocates DISTINCT sender_key_ids on successive calls (allocator)")
    (%check :cm-gen-off-zero
            (and (equalp (dds.security:key-material-receiver-specific-key-id km1) zeros4)
                 (equalp (dds.security:key-material-master-receiver-specific-key km1) zeros32))
            "generate-key-material (no :origin-auth) leaves the receiver-specific slots all-zero")
    (%check :cm-gen-on-nonzero
            (and (notevery #'zerop (dds.security:key-material-receiver-specific-key-id kmo))
                 (not (equalp (dds.security:key-material-master-receiver-specific-key kmo) zeros32)))
            "generate-key-material :origin-auth t populates a NON-ZERO receiver_specific_key_id + master key")
    (dotimes (i 64)
      (%check :cm-gen-rskid-never-zero
              (notevery #'zerop (dds.security:key-material-receiver-specific-key-id
                                 (dds.security:generate-key-material :origin-auth t)))
              "receiver_specific_key_id is never the all-zero origin-auth-disabled sentinel (T3 carry fix)"))
    (let* ((guid (make-array 16 :element-type '(unsigned-byte 8) :initial-element 9))
           (wkm (dds.security:generate-writer-key-material guid :origin-auth t)))
      (%check :cm-gen-writer-kid
              (equalp (dds.security:key-material-sender-key-id wkm)
                      (make-array 4 :element-type '(unsigned-byte 8) :initial-element 9))
              "generate-writer-key-material overrides sender_key_id with the GUID-derived id (delegation intact)")
      (%check :cm-gen-writer-rs
              (notevery #'zerop (dds.security:key-material-receiver-specific-key-id wkm))
              "generate-writer-key-material :origin-auth t still populates non-zero receiver-specific (delegation)")))
  t)

(defun* %cm-participant-registry ()
    (function () t)
  "cm-register-local-participant returns a populated KM and is idempotent (one ParticipantCrypto per
   participant); cm-encode-participant-km returns it. cm-register-matched-remote-participant +
   cm-decode-participant-km resolve by the 12-octet GUID-prefix; an unknown prefix -> NIL (fail-closed)."
  (let* ((cm  (dds.dcps::make-crypto-manager))
         (lp  (dds.dcps::cm-register-local-participant cm :origin-auth t))
         (lp2 (dds.dcps::cm-register-local-participant cm))
         (zeros32 (make-array 32 :element-type '(unsigned-byte 8) :initial-element 0))
         (prefix (make-array 12 :element-type '(unsigned-byte 8) :initial-element 3))
         (other  (make-array 12 :element-type '(unsigned-byte 8) :initial-element 7))
         (rkm (dds.security:generate-key-material)))
    (%check :cm-lp-populated (not (equalp (dds.security:key-material-master-sender-key lp) zeros32))
            "cm-register-local-participant returns a KM with a populated master_sender_key")
    (%check :cm-lp-rs (notevery #'zerop (dds.security:key-material-receiver-specific-key-id lp))
            "cm-register-local-participant :origin-auth t populates the receiver-specific key_id")
    (%check :cm-lp-idempotent (eq lp lp2)
            "cm-register-local-participant is idempotent (same KM instance on re-register)")
    (%check :cm-lp-encode (eq lp (dds.dcps::cm-encode-participant-km cm))
            "cm-encode-participant-km returns the registered local participant KM")
    (dds.dcps::cm-register-matched-remote-participant cm prefix rkm)
    (%check :cm-rp-resolve (eq rkm (dds.dcps::cm-decode-participant-km cm prefix))
            "cm-decode-participant-km resolves the remote participant KM by GUID-prefix")
    (%check :cm-rp-unknown (null (dds.dcps::cm-decode-participant-km cm other))
            "cm-decode-participant-km returns NIL on an unknown prefix (fail-closed)"))
  t)

(defun* %cm-entity-registry ()
    (function () t)
  "cm-register-local-entity is populated + idempotent per entity-id; cm-encode-entity-km resolves it.
   cm-register-matched-remote-entity installs under BOTH the (prefix.entity) GUID and the
   transformation_key_id index; cm-decode-entity-km-by-key-id resolves by the wire transformation_key_id;
   unknown entity-id / key-id -> NIL (fail-closed)."
  (let* ((cm  (dds.dcps::make-crypto-manager))
         (eid #x00000102)
         (le  (dds.dcps::cm-register-local-entity cm eid))
         (le2 (dds.dcps::cm-register-local-entity cm eid))
         (prefix (make-array 12 :element-type '(unsigned-byte 8) :initial-element 5))
         (reid #x00000103)
         (rkm  (dds.security:generate-key-material))
         (rkid (dds.security:key-material-sender-key-id rkm)))
    (%check :cm-le-idempotent (eq le le2)
            "cm-register-local-entity is idempotent per entity-id")
    (%check :cm-le-encode (eq le (dds.dcps::cm-encode-entity-km cm eid))
            "cm-encode-entity-km resolves the local entity KM by entity-id")
    (%check :cm-le-unknown (null (dds.dcps::cm-encode-entity-km cm #x000001c7))
            "cm-encode-entity-km returns NIL on an unknown entity-id (fail-closed)")
    (dds.dcps::cm-register-matched-remote-entity cm prefix reid rkm)
    (%check :cm-re-by-key-id (eq rkm (dds.dcps::cm-decode-entity-km-by-key-id cm rkid))
            "cm-decode-entity-km-by-key-id resolves the remote entity KM by transformation_key_id")
    (%check :cm-re-key-id-unknown
            (null (dds.dcps::cm-decode-entity-km-by-key-id
                   cm (make-array 4 :element-type '(unsigned-byte 8) :initial-element #xfe)))
            "cm-decode-entity-km-by-key-id returns NIL on an unknown key-id (fail-closed)"))
  t)

(defun* %cm-resolvers ()
    (function () t)
  "cm-encode-keys / cm-decode-keys return a dds.security:crypto-keys whose closures resolve the
   EntityCrypto by the 16-octet GUID (the shape the dataplane disc-node CRYPTO-TRANSFORM installs):
   encode by the local writer GUID (entity-id extracted from octets 12-15), decode by the remote
   writer GUID; an unknown GUID -> NIL (fail-closed)."
  (let* ((cm   (dds.dcps::make-crypto-manager))
         (leid #x00000102)
         (le   (dds.dcps::cm-register-local-entity cm leid))
         (lguid (make-array 16 :element-type '(unsigned-byte 8) :initial-element 0))
         (rprefix (make-array 12 :element-type '(unsigned-byte 8) :initial-element 4))
         (reid #x00000107)
         (rkm  (dds.security:generate-key-material))
         (ck-e (dds.dcps::cm-encode-keys cm))
         (ck-d (dds.dcps::cm-decode-keys cm)))
    (setf (aref lguid 12) #x00 (aref lguid 13) #x00 (aref lguid 14) #x01 (aref lguid 15) #x02)
    (%check :cm-ck-encode
            (eq le (funcall (dds.security:crypto-keys-encode-key-fn ck-e) lguid))
            "cm-encode-keys' encode closure resolves the local entity KM from the writer GUID's entity-id")
    (dds.dcps::cm-register-matched-remote-entity cm rprefix reid rkm)
    (let ((rguid (make-array 16 :element-type '(unsigned-byte 8) :initial-element 4))
          (unknown (make-array 16 :element-type '(unsigned-byte 8) :initial-element #xab)))
      (setf (aref rguid 12) #x00 (aref rguid 13) #x00 (aref rguid 14) #x01 (aref rguid 15) #x07)
      (%check :cm-ck-decode
              (eq rkm (funcall (dds.security:crypto-keys-decode-key-fn ck-d) rguid))
              "cm-decode-keys' decode closure resolves the remote entity KM by the wire GUID")
      (%check :cm-ck-decode-unknown
              (null (funcall (dds.security:crypto-keys-decode-key-fn ck-d) unknown))
              "cm-decode-keys' decode closure returns NIL on an unknown GUID (fail-closed)")))
  t)

(defun* %cm-concurrency-smoke ()
    (function () t)
  "Light concurrency smoke: N threads concurrently register disjoint remote entities + resolve them on
   ONE crypto-manager. After join, every thread's KMs resolved by transformation_key_id and the index
   holds exactly N*M entries — the single manager lock keeps the registries uncorrupted under concurrent
   read+write (a lost update would drop the count or fail a resolve). Threads do only register/resolve
   (no CLOS error-signaling inside threads, per the Clasp threading note)."
  (let* ((cm (dds.dcps::make-crypto-manager))
         (n-threads 8)
         (per 50)
         (oks (make-array n-threads :initial-element nil)))
    (let ((threads
            (loop for ti from 0 below n-threads
                  collect
                  (let ((ti ti))
                    (dds.pal:spawn
                     (lambda ()
                       (let ((all-ok t))
                         (dotimes (j per)
                           (let* ((prefix (make-array 12 :element-type '(unsigned-byte 8) :initial-element ti))
                                  (eid (+ #x01000000 (* ti 1000) j))
                                  (km (dds.security:generate-key-material)))
                             (setf (aref prefix 11) (logand j #xff))
                             (dds.dcps::cm-register-matched-remote-entity cm prefix eid km)
                             (unless (eq km (dds.dcps::cm-decode-entity-km-by-key-id
                                             cm (dds.security:key-material-sender-key-id km)))
                               (setf all-ok nil))))
                         (setf (aref oks ti) all-ok)))
                     :name "cm-smoke")))))
      (dolist (th threads) (dds.pal:join th)))
    (%check :cm-smoke-resolves (every #'identity oks)
            "every thread's concurrently-registered KMs resolved correctly (no lost update under the lock)")
    (%check :cm-smoke-count
            (= (* n-threads per) (hash-table-count (dds.dcps::crypto-manager-key-id-index cm)))
            "the transformation_key_id index holds exactly N*M entries after concurrent registration"))
  t)

(defun* %cm-rtps-origin-auth ()
    (function () t)
  "T10 participant-tier rtps_protection origin-auth resolvers (cm-rtps-encode-receivers / cm-rtps-decode-receiver,
   §9.5.3.3.4.3) driven THROUGH the real resolvers — the review fold-in (the run-rtps-protection-test wrong-key
   control used MANUAL closures, leaving cm-rtps-* with only positive e2e coverage). A is the sender; B-good holds
   the matching participant receiver key, B-bad a DIFFERENT one. A holds B-good's ParticipantCrypto as the matched
   remote, so cm-rtps-encode-receivers resolves B-good's receiver descriptor (A MACs the per-receiver MAC under
   it). BOTH B's hold A's ParticipantCrypto, so the common_mac (A's sender key) verifies for BOTH — isolating the
   receiver-MAC gate. On the SAME SRTPS datagram: cm-rtps-decode-receiver(B-good) recovers the stream byte-exact;
   a no-receiver-key decode recovers it too (the common_mac alone is valid); cm-rtps-decode-receiver(B-bad) -> NIL
   (the WRONG participant receiver key fails the receiver-MAC though the common_mac is valid, §9.5.3.3.4.3)."
  (let* ((pa (make-array 12 :element-type '(unsigned-byte 8) :initial-element #x5a))   ; A's prefix (sender)
         (pb (make-array 12 :element-type '(unsigned-byte 8) :initial-element #x6b))   ; B's prefix (receiver)
         (cm-a      (dds.dcps::make-crypto-manager))                                   ; the sender
         (cm-b-good (dds.dcps::make-crypto-manager))                                   ; the correct receiver
         (cm-b-bad  (dds.dcps::make-crypto-manager))                                   ; the wrong-receiver-key control
         (km-a    (dds.dcps::cm-register-local-participant cm-a))                      ; A's ParticipantCrypto (sender key)
         (km-good (dds.dcps::cm-register-local-participant cm-b-good :origin-auth t))  ; B-good's participant receiver key
         (stream  (map '(simple-array (unsigned-byte 8) (*)) #'char-code "SRTPSPAYLOAD-XYZ")))
    (dds.dcps::cm-register-local-participant cm-b-bad :origin-auth t)   ; B-bad's DIFFERENT receiver key (read via the resolver)
    ;; A learns B-good's ParticipantCrypto (from its ParticipantCryptoToken) -> MACs the per-receiver MAC under it.
    (dds.dcps::cm-register-matched-remote-participant cm-a pb km-good)
    ;; both B's hold A's ParticipantCrypto -> the common_mac (A's sender key) verifies for BOTH.
    (dds.dcps::cm-register-matched-remote-participant cm-b-good pa km-a)
    (dds.dcps::cm-register-matched-remote-participant cm-b-bad  pa km-a)
    (let* ((receivers (dds.dcps::cm-rtps-encode-receivers cm-a pb))    ; THROUGH the encode resolver -> B-good's descriptor
           (rd-good   (dds.dcps::cm-rtps-decode-receiver cm-b-good))   ; THROUGH the decode resolver -> B-good's descriptor
           (rd-bad    (dds.dcps::cm-rtps-decode-receiver cm-b-bad))    ; THROUGH the decode resolver -> the WRONG descriptor
           (km-good-v (dds.dcps::cm-decode-participant-km cm-b-good pa))
           (km-bad-v  (dds.dcps::cm-decode-participant-km cm-b-bad pa))
           (srtps     (dds.security:encode-rtps-message km-a :encrypt stream :receivers receivers)))
      (%check :cm-rtps-oa-encode-receivers (and receivers (consp (first receivers)))
              "cm-rtps-encode-receivers resolves the matched-remote participant receiver descriptor (origin-auth)")
      (%check :cm-rtps-oa-decode-good
              (equalp stream (dds.security:decode-rtps-message
                              km-good-v srtps :my-receiver-key-id (car rd-good) :my-receiver-key (cdr rd-good)))
              "the CORRECT participant receiver key (via cm-rtps-decode-receiver) decodes the SRTPS datagram byte-exact")
      (%check :cm-rtps-oa-common-mac-valid
              (equalp stream (dds.security:decode-rtps-message km-bad-v srtps))
              "the common_mac is valid (a no-receiver-key decode of the SAME datagram recovers the stream) — isolating the receiver-MAC gate")
      (%check :cm-rtps-oa-decode-wrong
              (null (dds.security:decode-rtps-message
                     km-bad-v srtps :my-receiver-key-id (car rd-bad) :my-receiver-key (cdr rd-bad)))
              "the WRONG participant receiver key (via cm-rtps-decode-receiver) fails closed though the common_mac is valid (§9.5.3.3.4.3)")))
  t)

(defun* run-security-crypto-manager-test ()
    (function () t)
  "DDS-Security 1.1 §8.5 key-management hub (WP-DDS-SECURITY-SECURE-DISCOVERY T6): the generic
   §9.5.2 KeyMaterial generator (generate-key-material — CryptoKeyFactory primitive, the T3
   non-zero receiver_specific_key_id fix, and the generate-writer-key-material DRY delegation) plus
   the dds.dcps crypto-manager ParticipantCrypto + EntityCrypto registries and the encode/decode key
   resolvers the §9.5.3.3 data path consumes (by GUID-prefix for participant, by transformation_key_id
   / inner GUID for entity), each fail-closed on a miss, with a light concurrency smoke over the
   single manager lock. Requires OpenSSL >= 3.5 (random KeyMaterial); skips only if truly absent.
   Both SBCL and Clasp must pass identically."
  (handler-case (dds.dare:dare-available-p)
    (dds.dare:dare-unavailable (c)
      (format t "~&  [security-crypto-manager] SKIP — OpenSSL >= 3.5 not available: ~a~%"
              (dds.dare:dare-unavailable-reason c))
      (return-from run-security-crypto-manager-test t)))
  (%cm-generator-units)
  (%cm-participant-registry)
  (%cm-entity-registry)
  (%cm-resolvers)
  (%cm-rtps-origin-auth)
  (%cm-concurrency-smoke)
  t)
