(in-package #:dds.tests)

;;; DDS-Security 1.1 §8.7 Authentication plugin T1 tests: PKI identity load + IdentityToken.
;;; Tests: (a) validate-local-identity on EC fixture -> identity-handle; (b) identity-token
;;; byte-exact vs locked regression vector; (c) wrong-CA cert fails closed; (d) validate-remote-
;;; identity between two distinct-GUID handles returns :ok + consistent :requester/:replier role.
;;;
;;; IdentityToken regression vector derived from the committed T0 fixture cert
;;; (interop/security-auth/pki/participant_ec/identity_cert.pem) by running the CDR LE DataHolder
;;; serialization on 2026-06-23 and re-locked 2026-06-24 after PKI regeneration (gen-test-pki.sh);
;;; subject CNs are deterministic so the serialization is byte-stable across regenerations.
;;; See the operating contract §5 (Definition of Done) for the derivation record.

;;; Locked byte-exact IdentityToken for the EC participant fixture cert.
;;; class_id="DDS:Auth:PKI-DH:1.0", dds.cert.sn="/CN=TestParticipantEC/O=DDS-Test/C=DE",
;;; dds.cert.algo="EC-prime256v1", dds.ca.sn="/CN=TestIdentityCA/O=DDS-Test/C=DE",
;;; dds.ca.algo="EC-prime256v1". CDR LE DataHolder, 240 bytes.
(defparameter +ec-identity-token-vector+
    (make-array 240 :element-type '(unsigned-byte 8) :initial-contents
     '(20 0 0 0 68 68 83 58 65 117 116 104 58 80 75 73 45 68 72 58 49 46 48 0   ; class_id
       4 0 0 0                                                                    ; prop count=4
       12 0 0 0 100 100 115 46 99 101 114 116 46 115 110 0                       ; "dds.cert.sn"
       38 0 0 0 47 67 78 61 84 101 115 116 80 97 114 116 105 99 105 112 97 110   ; "/CN=TestParticipantEC
       116 69 67 47 79 61 68 68 83 45 84 101 115 116 47 67 61 68 69 0 0 0        ;  /O=DDS-Test/C=DE"
       1 0 0 0                                                                    ; propagate+pad
       14 0 0 0 100 100 115 46 99 101 114 116 46 97 108 103 111 0 0 0            ; "dds.cert.algo"
       14 0 0 0 69 67 45 112 114 105 109 101 50 53 54 118 49 0 0 0               ; "EC-prime256v1"
       1 0 0 0                                                                    ; propagate+pad
       10 0 0 0 100 100 115 46 99 97 46 115 110 0 0 0                            ; "dds.ca.sn"
       35 0 0 0 47 67 78 61 84 101 115 116 73 100 101 110 116 105 116 121 67 65  ; "/CN=TestIdentityCA
       47 79 61 68 68 83 45 84 101 115 116 47 67 61 68 69 0 0                    ;  /O=DDS-Test/C=DE"
       1 0 0 0                                                                    ; propagate+pad
       12 0 0 0 100 100 115 46 99 97 46 97 108 103 111 0                         ; "dds.ca.algo"
       14 0 0 0 69 67 45 112 114 105 109 101 50 53 54 118 49 0 0 0               ; "EC-prime256v1"
       1 0 0 0                                                                    ; propagate+pad
       0 0 0 0))                                                                  ; binary_properties count=0
  "Locked byte-exact IdentityToken for the T0 EC participant fixture cert (240 octets, CDR LE).")

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
   (b) identity-token equals the locked 240-byte regression vector (byte-exact).
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
               (%check :auth-token-length (= (length tok) 240)
                       (format nil "identity-token length ~d != 240" (length tok)))
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

             ;; (d) validate-remote-identity: use handle (guid-a) as local + token of a second
             ;; handle (guid-b). Both GUIDs are distinct; role must be consistent with ordering.
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
                        ;; guid-a = #(1 2 ...) < guid-b = #(200 2 ...) => local is :requester
                        (%check :auth-remote-role-correct (eq role :requester)
                                (format nil "GUID-a < GUID-b so local must be :requester; got ~a" role))))
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
   (:rsa :ec)  -> NIL  (same, reversed direction). Both SBCL and Clasp must pass."
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
                        (dds.security:free-handshake-handle req-hdl-ov))))

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
