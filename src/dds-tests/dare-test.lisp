(in-package #:dds.tests)

;;; DDS.DARE Task-1 KAT tests — SHA-384 (NIST FIPS 180-4) + HKDF-SHA384 (Google Wycheproof).
;;; The HKDF vectors are AUTHENTIC published test vectors (independent implementation), so our
;;; OpenSSL reproducing them is genuine independent conformance — never a self-generated vector.

(defun* run-dare-sha384-hkdf-kat-test ()
    (function () t)
  "SHA-384 (NIST FIPS 180-4 §B.2) + HKDF-SHA384 (Google Wycheproof) known-answer tests.
   Requires OpenSSL >= 3.5 on the host; skips only if truly absent (host without OpenSSL 3.x).
   Both SBCL and Clasp must pass identically when OpenSSL 3.x is installed."
  (handler-case (dds.dare:dare-available-p)
    (dds.dare:dare-unavailable (c)
      (format t "~&  [dare-sha384-hkdf-kat] SKIP — OpenSSL >= 3.5 not available on this host: ~a~%"
              (dds.dare:dare-unavailable-reason c))
      (return-from run-dare-sha384-hkdf-kat-test t)))

  ;; SHA-384("abc") — NIST FIPS 180-4 §B.2 example, 48-byte digest.
  ;; Source: FIPS PUB 180-4 (Aug 2015), Appendix B.2, p. 19.
  ;;   cb00753f 45a35e8b b5a03d69 9ac65007 272c32ab 0eded163
  ;;   1a8b605a 43ff5bed 8086072b a1e7cc23 58baeca1 34c825a7
  (let* ((input   (dds.dare::%ascii "abc"))
         (digest  (dds.dare:sha-384 input))
         (expected (make-array 48 :element-type '(unsigned-byte 8)
                                  :initial-contents
                                  '(#xcb #x00 #x75 #x3f #x45 #xa3 #x5e #x8b
                                    #xb5 #xa0 #x3d #x69 #x9a #xc6 #x50 #x07
                                    #x27 #x2c #x32 #xab #x0e #xde #xd1 #x63
                                    #x1a #x8b #x60 #x5a #x43 #xff #x5b #xed
                                    #x80 #x86 #x07 #x2b #xa1 #xe7 #xcc #x23
                                    #x58 #xba #xec #xa1 #x34 #xc8 #x25 #xa7))))
    (%check :sha384-abc-length  (= (length digest) 48) "SHA-384 output must be 48 bytes")
    (%check :sha384-abc-kat
            (equalp digest expected)
            (format nil "SHA-384(abc) KAT mismatch; got ~{~2,'0x~^ ~}"
                    (coerce digest 'list))))

  ;; HKDF-SHA384 — AUTHENTIC published vectors (independent implementation): our OpenSSL
  ;; reproducing them is genuine independent conformance, not a self-generated vector.
  ;; Source: Google Wycheproof, testvectors_v1/hkdf_sha384_test.json
  ;;   (algorithm "HKDF-SHA-384", schema hkdf_test_schema_v1.json; Apache-2.0).
  ;; Pinned verbatim as the published hex strings, decoded with %hex-octets.
  ;; tcId 1 (valid): empty salt + empty info — matches derive-dek's actual empty-salt usage
  ;;   (RFC 5869 §2.2: an empty salt is treated as HashLen zero octets).
  (let* ((ikm  (%hex-octets "24aeff2645e3e0f5494a9a102778c43a"))
         (salt (make-array 0 :element-type '(unsigned-byte 8)))
         (info (make-array 0 :element-type '(unsigned-byte 8)))
         (okm  (dds.dare:hkdf-sha384 ikm salt info 20))
         (expected (%hex-octets "4b7045423d9156424b0b85d95a7d602fba3924b1")))
    (%check :hkdf-sha384-wycheproof-tc1-length (= (length okm) 20)
            "HKDF-SHA384 Wycheproof tcId 1 output must be 20 bytes")
    (%check :hkdf-sha384-wycheproof-tc1
            (equalp okm expected)
            (format nil "HKDF-SHA384 Wycheproof tcId 1 mismatch; got ~{~2,'0x~^ ~}"
                    (coerce okm 'list))))
  ;; tcId 4 (valid): empty salt + non-empty info (the published salt is zero-length).
  (let* ((ikm  (%hex-octets "06eb26f8ccf28580c8f28d5b4dc47a49"))
         (salt (make-array 0 :element-type '(unsigned-byte 8)))
         (info (%hex-octets "d5f081e81e8cf9ded199f3ae43c80a2dfe3d9cf2"))
         (okm  (dds.dare:hkdf-sha384 ikm salt info 20))
         (expected (%hex-octets "ac2b3c7b3a3538d5a471a03849208437e0c2201a")))
    (%check :hkdf-sha384-wycheproof-tc4-length (= (length okm) 20)
            "HKDF-SHA384 Wycheproof tcId 4 output must be 20 bytes")
    (%check :hkdf-sha384-wycheproof-tc4
            (equalp okm expected)
            (format nil "HKDF-SHA384 Wycheproof tcId 4 mismatch; got ~{~2,'0x~^ ~}"
                    (coerce okm 'list))))

  ;; Sanity: dare-available-p returns T (OpenSSL >= 3.5 + ML-KEM-1024 fetchable).
  (%check :dare-available-p (dds.dare:dare-available-p) "dare-available-p must return T")

  t)

(defun* run-dare-aes-gcm-kat-test ()
    (function () t)
  "AES-256-GCM seal/open NIST KAT + tamper tests (FIPS 197, SP 800-38D).
   Vector: NIST SP 800-38D (Nov 2007) Appendix B, Test Case 16.
     K  = feffe992...67308308 (32 bytes, doubled 128-bit key)
     IV = cafebabefacedbaddecaf888 (12 bytes)
     P  = d9313225...637b39 (60 bytes)
     A  = feedface...abaddad2 (20 bytes)
     C  = 522dc1f0...bcc9f662 (60 bytes)
     T  = 76fc6ece0f4e1768cddf8853bb2d551b (16 bytes)"
  (handler-case (dds.dare:dare-available-p)
    (dds.dare:dare-unavailable (c)
      (format t "~&  [dare-aes-gcm-kat] SKIP — OpenSSL >= 3.5 not available: ~a~%"
              (dds.dare:dare-unavailable-reason c))
      (return-from run-dare-aes-gcm-kat-test t)))

  ;; NIST SP 800-38D Appendix B TC16 key/IV/PT/AAD
  (let* ((key (make-array 32 :element-type '(unsigned-byte 8)
                             :initial-contents
                             '(#xfe #xff #xe9 #x92 #x86 #x65 #x73 #x1c
                               #x6d #x6a #x8f #x94 #x67 #x30 #x83 #x08
                               #xfe #xff #xe9 #x92 #x86 #x65 #x73 #x1c
                               #x6d #x6a #x8f #x94 #x67 #x30 #x83 #x08)))
         (nonce (make-array 12 :element-type '(unsigned-byte 8)
                               :initial-contents
                               '(#xca #xfe #xba #xbe #xfa #xce #xdb #xad
                                 #xde #xca #xf8 #x88)))
         (aad (make-array 20 :element-type '(unsigned-byte 8)
                             :initial-contents
                             '(#xfe #xed #xfa #xce #xde #xad #xbe #xef
                               #xfe #xed #xfa #xce #xde #xad #xbe #xef
                               #xab #xad #xda #xd2)))
         (pt (make-array 60 :element-type '(unsigned-byte 8)
                            :initial-contents
                            '(#xd9 #x31 #x32 #x25 #xf8 #x84 #x06 #xe5
                              #xa5 #x59 #x09 #xc5 #xaf #xf5 #x26 #x9a
                              #x86 #xa7 #xa9 #x53 #x15 #x34 #xf7 #xda
                              #x2e #x4c #x30 #x3d #x8a #x31 #x8a #x72
                              #x1c #x3c #x0c #x95 #x95 #x68 #x09 #x53
                              #x2f #xcf #x0e #x24 #x49 #xa6 #xb5 #x25
                              #xb1 #x6a #xed #xf5 #xaa #x0d #xe6 #x57
                              #xba #x63 #x7b #x39)))
         (expected-ct (make-array 60 :element-type '(unsigned-byte 8)
                                     :initial-contents
                                     '(#x52 #x2d #xc1 #xf0 #x99 #x56 #x7d #x07
                                       #xf4 #x7f #x37 #xa3 #x2a #x84 #x42 #x7d
                                       #x64 #x3a #x8c #xdc #xbf #xe5 #xc0 #xc9
                                       #x75 #x98 #xa2 #xbd #x25 #x55 #xd1 #xaa
                                       #x8c #xb0 #x8e #x48 #x59 #x0d #xbb #x3d
                                       #xa7 #xb0 #x8b #x10 #x56 #x82 #x88 #x38
                                       #xc5 #xf6 #x1e #x63 #x93 #xba #x7a #x0a
                                       #xbc #xc9 #xf6 #x62)))
         (expected-tag (make-array 16 :element-type '(unsigned-byte 8)
                                      :initial-contents
                                      '(#x76 #xfc #x6e #xce #x0f #x4e #x17 #x68
                                        #xcd #xdf #x88 #x53 #xbb #x2d #x55 #x1b))))

    ;; seal: must produce the byte-exact NIST CT and tag
    (multiple-value-bind (ct tag)
        (dds.dare:aes-256-gcm-seal key nonce aad pt)
      (%check :aes-gcm-ct-len   (= (length ct) 60)  "seal: ciphertext length must equal plaintext length")
      (%check :aes-gcm-tag-len  (= (length tag) 16) "seal: tag must be 16 bytes")
      (%check :aes-gcm-ct-kat
              (equalp ct expected-ct)
              (format nil "seal: CT mismatch; got ~{~2,'0x~^ ~}" (coerce ct 'list)))
      (%check :aes-gcm-tag-kat
              (equalp tag expected-tag)
              (format nil "seal: Tag mismatch; got ~{~2,'0x~^ ~}" (coerce tag 'list)))

      ;; open: must round-trip to original plaintext
      (let ((decrypted (dds.dare:aes-256-gcm-open key nonce aad ct tag)))
        (%check :aes-gcm-open-non-nil decrypted "open: must return non-NIL for valid (ct,tag,aad)")
        (%check :aes-gcm-open-roundtrip
                (equalp decrypted pt)
                (format nil "open: plaintext mismatch; got ~{~2,'0x~^ ~}" (coerce decrypted 'list))))

      ;; fail-closed: 1-bit tag flip -> NIL
      (let* ((bad-tag (copy-seq tag)))
        (setf (aref bad-tag 0) (logxor (aref bad-tag 0) 1))
        (%check :aes-gcm-tag-tamper
                (null (dds.dare:aes-256-gcm-open key nonce aad ct bad-tag))
                "open: 1-bit tag flip must return NIL (fail-closed)"))

      ;; fail-closed: 1-bit CT flip -> NIL
      (let* ((bad-ct (copy-seq ct)))
        (setf (aref bad-ct 0) (logxor (aref bad-ct 0) 1))
        (%check :aes-gcm-ct-tamper
                (null (dds.dare:aes-256-gcm-open key nonce aad bad-ct tag))
                "open: 1-bit CT flip must return NIL (fail-closed)"))

      ;; fail-closed: 1-bit AAD flip -> NIL
      (let* ((bad-aad (copy-seq aad)))
        (setf (aref bad-aad 0) (logxor (aref bad-aad 0) 1))
        (%check :aes-gcm-aad-tamper
                (null (dds.dare:aes-256-gcm-open key nonce bad-aad ct tag))
                "open: 1-bit AAD flip must return NIL (fail-closed)")))

    ;; into-buffer variants must be byte-identical to the allocating entries (NIST TC16)
    (let* ((out (dds.pal:alloc-static (+ 60 16)))      ; ct(60) || tag(16)
           (nonce-s (dds.pal:alloc-static 12))
           (pt-s (dds.pal:alloc-static 60)))
      (replace nonce-s nonce) (replace pt-s pt)
      (dds.dare:aes-256-gcm-seal-into out 0 60 key nonce-s 0 aad pt-s 0 60)
      (%check :aes-gcm-seal-into-ct  (equalp (subseq out 0 60) expected-ct) "seal-into: CT must match NIST KAT")
      (%check :aes-gcm-seal-into-tag (equalp (subseq out 60 76) expected-tag) "seal-into: tag must match NIST KAT")
      (let ((pt-out (dds.pal:alloc-static 60)))
        (%check :aes-gcm-open-into-ok (eq t (dds.dare:aes-256-gcm-open-into pt-out 0 key nonce-s 0 aad out 0 60 out 60))
                "open-into: must return T for valid (ct,tag)")
        (%check :aes-gcm-open-into-rt (equalp pt-out pt) "open-into: plaintext must round-trip")
        (setf (aref out 60) (logxor (aref out 60) 1))   ; tamper tag
        (%check :aes-gcm-open-into-tamper
                (null (dds.dare:aes-256-gcm-open-into pt-out 0 key nonce-s 0 aad out 0 60 out 60))
                "open-into: tag tamper must return NIL (fail-closed)")
        (%check :aes-gcm-open-into-tamper-wiped (every #'zerop pt-out)
                "open-into: tampered open must leave the plaintext region zeroed (no leak)")
        (dds.pal:free-static pt-out))
      (dds.pal:free-static out) (dds.pal:free-static nonce-s) (dds.pal:free-static pt-s))

    ;; GMAC-into (SIGN, §9.5.3.3.4.3): pt-len=0 writes tag-only, zero ciphertext bytes.
    ;; Reference: allocating aes-256-gcm-seal(key,nonce,aad,empty-pt) — byte-identical by contract.
    ;; Overlap-out safety: EVP reads AAD (EncryptUpdate) before GET_TAG writes the tag;
    ;; sequential EVP call order means aad-ptr / out-SAP aliasing is safe.
    (let* ((empty-pt  (make-array 0 :element-type '(unsigned-byte 8)))
           (ref-gmac  (nth-value 1 (dds.dare:aes-256-gcm-seal key nonce aad empty-pt)))
           (gout      (dds.pal:alloc-static 16))
           (gns       (dds.pal:alloc-static 12)))
      (replace gns nonce)
      ;; seal-into GMAC: ct-off=0, pt-len=0 => 0 CT bytes; tag-off=0 => tag at gout[0..16]
      (dds.dare:aes-256-gcm-seal-into gout 0 0 key gns 0 aad empty-pt 0 0)
      (%check :aes-gcm-gmac-into-tag
              (equalp (subseq gout 0 16) ref-gmac)
              (format nil "GMAC-into: tag mismatch; got ~{~2,'0x~^ ~}; want ~{~2,'0x~^ ~}"
                      (coerce (subseq gout 0 16) 'list) (coerce ref-gmac 'list)))
      ;; open-into GMAC verify: ct-len=0, correct tag -> T
      (let ((gpto (dds.pal:alloc-static 1)))
        (%check :aes-gcm-gmac-open-into-ok
                (eq t (dds.dare:aes-256-gcm-open-into gpto 0 key gns 0 aad gout 0 0 gout 0))
                "GMAC open-into: must return T for correct tag")
        ;; tamper tag byte -> fail-closed NIL
        (setf (aref gout 0) (logxor (aref gout 0) 1))
        (%check :aes-gcm-gmac-open-into-tamper
                (null (dds.dare:aes-256-gcm-open-into gpto 0 key gns 0 aad gout 0 0 gout 0))
                "GMAC open-into: tampered tag must return NIL (fail-closed)")
        (dds.pal:free-static gpto))
      ;; overlap-out case: ov-out[0..20] = AAD data, tag at ov-out[20..36]
      ;; simulates the ZA-2 SIGN core where the verbatim region lives in the same buffer as the tag
      (let* ((ov-out (dds.pal:alloc-static 36))
             (ov-ns  (dds.pal:alloc-static 12)))
        (replace ov-ns nonce)
        (replace ov-out aad)
        (dds.dare:aes-256-gcm-seal-into ov-out 0 20 key ov-ns 0 aad empty-pt 0 0)
        (%check :aes-gcm-gmac-overlap-out
                (equalp (subseq ov-out 20 36) ref-gmac)
                (format nil "GMAC overlap-out: tag mismatch; got ~{~2,'0x~^ ~}; want ~{~2,'0x~^ ~}"
                        (coerce (subseq ov-out 20 36) 'list) (coerce ref-gmac 'list)))
        (dds.pal:free-static ov-out)
        (dds.pal:free-static ov-ns))
      (dds.pal:free-static gout)
      (dds.pal:free-static gns))

    ;; AAD-region (ZA-2 review fix): open-into with aad-off+aad-len selecting a sub-slice of a larger
    ;; buffer must be byte-identical to the full-vector call; proves the region path is correct and
    ;; backward-compatible (NIST SP 800-38D Appendix B TC16 key/nonce/pt/aad/ct/tag reused).
    (let* ((padded (let ((v (make-array (+ 5 20 3) :element-type '(unsigned-byte 8))))
                     (replace v aad :start1 5)  ; embed the 20-octet NIST AAD at offset 5 in a 28-byte envelope
                     v))
           (ns2    (dds.pal:alloc-static 12))
           (pt2    (dds.pal:alloc-static 60))
           (enc    (dds.pal:alloc-static 76)))  ; ct(60) || tag(16)
      (replace ns2 nonce)
      (replace pt2 pt)
      (dds.dare:aes-256-gcm-seal-into enc 0 60 key ns2 0 aad pt2 0 60)  ; seal under the full AAD
      (let ((pt-r (dds.pal:alloc-static 60)))
        ;; aad-off=5 aad-len=20 -> padded[5..25] = the real AAD -> must succeed + plaintext byte-exact
        (%check :aes-gcm-open-into-aad-region-ok
                (eq t (dds.dare:aes-256-gcm-open-into pt-r 0 key ns2 0 padded enc 0 60 enc 60 5 20))
                "open-into AAD-region [5,+20): must return T for correct aad sub-slice (NIST TC16)")
        (%check :aes-gcm-open-into-aad-region-rt
                (equalp pt-r pt)
                (format nil "open-into AAD-region: plaintext must match NIST TC16; first 8 B: ~{~2,'0x~^ ~}"
                        (coerce (subseq pt-r 0 8) 'list)))
        ;; aad-off=0 -> padded[0..20] are zero-padding, NOT the real AAD -> auth failure (fail-closed)
        (%check :aes-gcm-open-into-aad-region-mismatch
                (null (dds.dare:aes-256-gcm-open-into pt-r 0 key ns2 0 padded enc 0 60 enc 60 0 20))
                "open-into AAD-region: wrong aad-off (zero-padded prefix) must return NIL (fail-closed)")
        (%check :aes-gcm-open-into-aad-region-mismatch-wiped
                (every #'zerop pt-r)
                "open-into AAD-region: auth failure must leave pt-r region zeroed (no leak)")
        (dds.pal:free-static pt-r))
      (dds.pal:free-static enc) (dds.pal:free-static pt2) (dds.pal:free-static ns2))

    t))

(defun* run-dare-image-restart-reresolve-test ()
    (function () t)
  "WP-ADR-SMALL-CARRIES C3 (ADR 0038/0039 saved-image residual, resolved): the DARE libcrypto foreign-pointer
   caches survive an image restart (save-lisp-and-die). Actually dumping + restarting an image in-test is
   impractical, so this SIMULATES the post-restart staleness — NIL out a sample of %ossl-sym boxes + the
   EVP_aes_256_gcm() cipher singleton (the exact caches a re-mapped libcrypto dangles) — then drives the real
   image-restart hook %DARE-RERESOLVE-FOREIGN-POINTERS and proves it (a) REPOPULATES every nulled cache and
   (b) re-resolves them CORRECTLY: a seal/open through the re-resolved pointers is BYTE-IDENTICAL to the same
   operation through the original (pre-null) pointers, and fail-closed on a tamper. Vectors are self-referential
   (a reference seal captured before nulling), so no KAT constant is duplicated. Requires OpenSSL >= 3.5."
  (handler-case (dds.dare:dare-available-p)
    (dds.dare:dare-unavailable (c)
      (format t "~&  [dare-image-restart-reresolve] SKIP — OpenSSL >= 3.5 not available: ~a~%"
              (dds.dare:dare-unavailable-reason c))
      (return-from run-dare-image-restart-reresolve-test t)))
  (let* ((key (make-array 32 :element-type '(unsigned-byte 8) :initial-element #x2a))
         (nonce (make-array 12 :element-type '(unsigned-byte 8) :initial-element #x13))
         (aad (octets 1 2 3 4 5 6 7 8))
         (pt (octets #xde #xad #xbe #xef #xca #xfe #xba #xbe #x00 #x11 #x22 #x33))
         ;; reference output through the LIVE (pre-restart) caches — the correctness oracle
         (ref-ct nil) (ref-tag nil)
         ;; the exact cache set a re-mapped libcrypto dangles: the seal/open EVP boxes + the cipher singleton
         (box-names '("EVP_EncryptInit_ex" "EVP_EncryptUpdate" "EVP_EncryptFinal_ex"
                      "EVP_DecryptInit_ex" "EVP_DecryptUpdate" "EVP_CIPHER_CTX_new"))
         (boxes (mapcar #'dds.dare::%ossl-sym-box box-names)))
    (multiple-value-bind (ct tag) (dds.dare:aes-256-gcm-seal key nonce aad pt)
      (setf ref-ct ct ref-tag tag))
    ;; simulate the dumped-image restart: dangle the cached pointers
    (dolist (b boxes) (setf (svref b 0) nil))
    (setf dds.dare::*%aes-256-gcm-cipher* nil)
    (%check :dare-reresolve-staleness-simulated
            (and (every (lambda (b) (null (svref b 0))) boxes)
                 (null dds.dare::*%aes-256-gcm-cipher*))
            "pre-condition: nulled boxes + cipher must be NIL (dangling-pointer simulation)")
    ;; drive the REAL image-restart hook
    (%check :dare-reresolve-returns-t
            (eq t (dds.dare::%dare-reresolve-foreign-pointers))
            "%dare-reresolve-foreign-pointers must return T")
    ;; (a) every nulled cache repopulated
    (%check :dare-reresolve-boxes-repopulated
            (every (lambda (b) (svref b 0)) boxes)
            "re-resolve must repopulate every %ossl-sym box slot (no dangling NIL)")
    (%check :dare-reresolve-cipher-repopulated
            dds.dare::*%aes-256-gcm-cipher*
            "re-resolve must repopulate *%aes-256-gcm-cipher*")
    ;; (b) re-resolved pointers are CORRECT: byte-identical seal + round-trip open + tamper fail-closed
    (multiple-value-bind (ct2 tag2) (dds.dare:aes-256-gcm-seal key nonce aad pt)
      (%check :dare-reresolve-seal-byte-identical
              (and (equalp ct2 ref-ct) (equalp tag2 ref-tag))
              "seal through re-resolved pointers must be byte-identical to the pre-restart output")
      (%check :dare-reresolve-open-roundtrip
              (equalp (dds.dare:aes-256-gcm-open key nonce aad ct2 tag2) pt)
              "open through re-resolved pointers must round-trip to the plaintext")
      (let ((bad (copy-seq tag2)))
        (setf (aref bad 0) (logxor (aref bad 0) 1))
        (%check :dare-reresolve-open-tamper-fail-closed
                (null (dds.dare:aes-256-gcm-open key nonce aad ct2 bad))
                "open through re-resolved pointers must fail-closed (NIL) on a tampered tag"))))
  t)

(defun* run-dare-ml-kem-kat-test ()
    (function () t)
  "ML-KEM-1024 (FIPS-203) round-trip + byte-exact decaps KAT + wrong-key tests.
   API: ml-kem-1024-keygen -> (pub priv); ml-kem-1024-encapsulate(pub) -> (ct ss);
   ml-kem-1024-decapsulate(priv ct) -> ss.
   (a) Round-trip: keygen->encapsulate(pub)->decapsulate(priv,ct) => same 32-byte ss.
   (b) Byte-exact decaps KAT: fixed (dk,c) => expected K byte-exactly (FIPS-203 Alg. 18
       is a pure deterministic function of (dk,c); no seed/IKME hook needed for decaps).
       Vector: C2SP/CCTV ML-KEM intermediate test vectors (independent of OpenSSL/host).
       Source: https://github.com/C2SP/CCTV/blob/main/ML-KEM/intermediate/ML-KEM-1024.txt
       (pq-crystals reference implementation; NOT derived from host OpenSSL).
       FIPS-203 (Aug 2024) §7.3 Alg. 18: K = ML-KEM.Decaps(dk, c).
   (c) Decaps determinism: same (dk,c) => same K on two independent calls (FIPS-203 §7.3).
   (d) Wrong-key: decapsulate(other-priv, ct) => DIFFERENT ss (ML-KEM implicit rejection,
       FIPS-203 §7.3: always rc=1 but K differs on key mismatch).
   Requires OpenSSL >= 3.5 on the host; skips only if truly absent."
  (handler-case (dds.dare:dare-available-p)
    (dds.dare:dare-unavailable (c)
      (format t "~&  [dare-ml-kem-kat] SKIP — OpenSSL >= 3.5 not available: ~a~%"
              (dds.dare:dare-unavailable-reason c))
      (return-from run-dare-ml-kem-kat-test t)))

  ;; (b) Byte-exact decaps KAT — deterministic pure function, no hook needed.
  ;; Vector: C2SP/CCTV ML-KEM-1024 intermediate test vectors (pq-crystals reference impl).
  ;; Source: https://github.com/C2SP/CCTV/blob/main/ML-KEM/intermediate/ML-KEM-1024.txt
  ;; Independent of host OpenSSL; NOT self-generated. FIPS-203 Alg. 18: K = ML-KEM.Decaps(dk,c).
  (let* ((dk (%hex-octets
              (concatenate 'string
               "82b25c61f7099f870f988428ad662203f75c638390c593035b3aa1a91092b2d2"
               "76fddb56bcab637e00a26ee68058376ad13c0e5d7b31ed29b2c24710b47b6024"
               "6214bf308f8dd77379590842740c84ab6d8adc71a1cb22c4e98e58112d803998"
               "a104bd606cb439e0b686384148a209f5d171e4b63e29f66863aacba2c5a48960"
               "0dfb64b65ce21f848b4c7621c6a3e65792497d1354a72e22405057cf9330332b"
               "419ca396cf69d374df850a2481c943488ab45cb71c992e12034baa94272a32cc"
               "694294ab6867d4f8758f972520ec5f90159fda33ad91d893273ac9a3e35f2976"
               "bbff525a2de84cbc55acbca91fa9ea91700abb87323d2a67c95d62cad3dc534a"
               "a83ff3fb6837ea908f0b953ca88bfb01b62068a1ade3c19e7b153f8b34b19295"
               "e054334f59b73855c030e597b688c3d2a14a336a2929393e0b27171315805e5c"
               "c3053b6d90843d82b933c1cc1574c18d9dda933f3b33b8cb7bf7143f6f595b1e"
               "c7113fd46f629930f28c4d4f666ce24bccd8bca5d74488de3b2480b176c0eb6f"
               "9dd19434ec33563303fcf7cdbe09c55d4216ad524379e451e74a2121c442c441"
               "2de5e137ed18421e07779b598860cc2e4e42c10f58a01617936c454845318373"
               "9c5624c68915b79a25a90257b1437a1583a9107d7d0587bee15570f3c008b914"
               "0f779cdce06fba05ac57991020162bb2096911594109f9032a09007eea48e1b5"
               "b5e11c9643d75284256c5a73b935668abb12aeeab7b040f71e17a74235e166d1"
               "942f7caa890869ccb1184cd44a9e82a89f31e83602e21de2b5cacfc254282470"
               "e0c66b020a5b058043e9135ab06c4fe1329d7a280ba6dc3de017c1041a26cf3b"
               "10d305c73594c469ac11b091bcb20412dfdc3ef0b712aee31fc2a81bfbd9990c"
               "a296fe45bcb992ba92d4148591a2f80990f218a2991bb3f3098a36c6568db8a4"
               "0ab03b9e017305d893b48285a5178ee6b80dd2c5555837c3e976afd36b895c10"
               "acb438ca7009ad7723b31b3aa6a680156ec3cfe4e813dbf010e6e5b39a890b76"
               "984d20e965c5a39a6cda801ec55c55245abe3b946bda7c8e70c99ac62e2ca2c2"
               "ce165722d710a1c443a6467f91c63ed53c3f223580fbd058b6c8b4f134ae3b49"
               "0ae97466e1983b0e669b22615df1732df9e9a98d4575720571ffa60dc888a65f"
               "6644902a9ad89a93c4b22132515d808ca445bab49e3276caa8a48d272b823477"
               "a0bc151491c229ab38bd6a4485257374cbcd03d6a6c655b6a1d06751995fa1c3"
               "94116476f399673b5b40857cb9c68721168a936d89a3008923b81c2d7eb94ba6"
               "3c3eff45b4ccb48a9d2142e8d5238ce904376bcd1e088b864a6a5acab75b138b"
               "9be44b08f00825bc3a804835337cac36bc41ca8bab90384a51341875c7ad27d1"
               "09afa36e2965cafe1922811762a077af789b8d6c490c0f102b62869ca38a83ef"
               "fb05f14ac82346645de63cb60bba30b665a3f1c9f842952aea89fe630f6404b6"
               "3164a39692180d806d65da3c1be076ae77b42d665edd2b93c1210427909d294a"
               "2fbad460444032a727960210005b7b3ad367cc300738187b3c64bbc00b16257f"
               "09182537129b14bf94c482bfdb9b82634821862a7fb0234ae0b5685582de054c"
               "b5575e9f8464336609cbd7ad5b486117ac4ea2468be9147e8c96b3a07993d572"
               "5f85c31c79405541c2c13b3abdc55b2dfa2ab02842a711a2b877097769c22be0"
               "65622ab0a92d5108bfa10c644935ee4652efca95fafca3b5cccf0187a45708cf"
               "68838ffa79427a0400f8439f15b11e064b2b777c0715aa8a91c96ea7f1a851f4"
               "7f8f077514a36c901059892273ca8695b3b418c8187558d18f1b9153d6c0b966"
               "e08f9a675889aa519224cdc4fc1fee51082ec26cea593124435f4bf95b3d852a"
               "d9554953088aae602e0ad3023d17576123929b1150fa496b850ab4e5f372ab71"
               "88f3127d2dcb970df56c4f5a2548903bd5ec50fb9196cf2374d7cc7282437577"
               "43083d4a93c4b6adca54314a3200fe5a303aba4c07d4cf3eb632eca5b353190d"
               "ecd984395192d1f63d3d9291e00aa17e0872df27a405832d0a7b43115b05e6a4"
               "cb9293812ab26eb2e148e4b5082ba99039d6847a03be1693afc09a3ab9504410"
               "7586e0db02720145c84cc800b669c51c8a96e526c4a99970234409414ed623cc"
               "ed859032bbb74c7412a7271c8ef23a5a08c31551a2a5cb8ada78538ce6c96d11"
               "625cb45e87b133163b16a4705aba1514f006afccbccf3c5c05acbc4563771bb8"
               "508072745d0ba56f57566181c3073b6c2b0dda50a2a83e74c67bcd48c0820b80"
               "9d03a6ae4193dbd3bc06d072d2c64fd1e0b408a9c29818cd2df7790f9779536b"
               "0a076b4fb57b56f8cbb8ea3290c2f8b381c993d9eb49d8b4873ec660895528ab"
               "9ac306a66ae8209e2db9b79cb89220fab9d5cbb290ac690c79199218229aa827"
               "6393a73c826459429baed8365b88733871450e9523959c3f28691a3a0622e923"
               "259d2c90a61ca1525caf75a3a4292036957a5966d55840927234e1c5445b6685"
               "396890e3ccb9869147e63ce0b23defbb1c00f46df3819dd4a5756a355f61c179"
               "3b25a9b713c3abd12605198083773cf26909ffc92cd423cd290ba1801c694e7c"
               "80d6e2c9c1b943c69a5e7387ade187b21bd2a598c49ec772cde74656f1b43fa2"
               "1021bcb86db8f91e03522bb4a76823483033f68659b57fa972c42673795b9a5d"
               "afa229fd8818f940a1b38a925cf06af712332b789a6f64ce91c7010af8a53110"
               "1de8541a3ba4b4b893bfe7e791e693a5987a3d2d7224aeb213c5aba14aa0686e"
               "fbbf31258d37122c304151916a9291181ffe788864f52acf001d788a3d80e4ad"
               "14623e9c402090b73fae5cb4225802cc4ab9c323c8cb914231c31c14c12a20ab"
               "7b5df5b6815bc04d991a32b6ccd229cf9692bf2e549ceb66512be58afe284b1d"
               "4990e46b5bafcca72589024e0b710169445e793cbbda9ca2664882199a54c314"
               "84d9364c2545876758999027c8f6423fa1a9ea810731092ca41c2451f29452c2"
               "4d1d120517e06eaac91a77a47dec3c036ff84bfda92bcb396a36a75007014c0b"
               "6882a939b7e2c109c6046c04e9c1e4b1bd83444cf7838ca909946b512cb8d06e"
               "d3ab66a62071eb439632cccbced23c06c3456cdabf321328a17263e6aa3fee00"
               "28bef312cc99477ac71c53909740502e340b7cc06111eeb90bb08c58bfb97d78"
               "acbb10e7240ee5672062783636565c1744217787ffa33287f5075464b97707ae"
               "c6864b38c918e0ebaf40fc9aac6128db4863a40c80b9d23261344a370c7b2dcb"
               "76e38623e5443242bcce9fb872b4c589b886aeb9fc79347cbf216b6ea8d1c7f5"
               "c5802fa24d1e68a4dc161699f90681069898e41d34a82cced119189b65475879"
               "72c4b17851a292f728f638a90164b97416c5b5b9231f1c675cf12c8ec1ce4866"
               "673f61addf98950263680efb56124b5936862f5328a3de923c4b2435b543ceee"
               "3b9761b5515aaaaecbdbb9cf8202090c82a2e5301fd0aee4fa4b39b0302d1813"
               "ab87cc1ba15595c36ef953401a92b8a88465c29ca4062626bc45b2a762c4ed95"
               "7e53551827322351701db42c73e340566a476f559ac776283816da810c76af10"
               "f41482577544302e80eb6ab2fb720c2a950464c62970a450e65983c336dde770"
               "39722c614143a2b72c40256cf2142365ebaf288b0d9d69b56671b45f72c90a26"
               "ad50229d8fd6291ae6306d614aba34b65af02fa7cc2f5d7c5c8f4b30dc715f65"
               "f82c6320088fe0cfd4f05dc63a22ffeb0f38f68c5e08af5603c605007c9efc1f"
               "1574c94d322191f248cf34246d9bb06c650e85a8ce1832860689af7791054bd0"
               "1b79a11cc41ca05f3a174d9393191bc541678989b0a6fbea82c488aa828b0770"
               "03a69b335098d00616e28d7853ab98b54c0b99840ff94393532285ccbc003120"
               "cd8b77c5c18d0e654750893de5c071a60a152350cc537a34a60c7032c21623c1"
               "bd0ce38046b986e786051e9891a7784223b45cc09682dbfacd92776f594377d0"
               "7290667a81726c7a62ab1e883329b22205b3e72165c846261429dd3cccedd493"
               "3bb38f4b9000a066c2464844ab47899269033078c1f2473e564a2c697caeded4"
               "cda82b8516c287b23a84ee997fe9206874f73d130a73d5a14e10668365089a96"
               "95b7870806fa8431663120eac9b9133937117cb3bcf862e306747139253f181d"
               "eb0352e6bb6b888561d46b3406fa31ec08520b275bacb6b1fd1bc40076958ed1"
               "bf96b70c5f567c9f83a3abdcc85e81aa0f99a50c2aac18a4177aa0bd1d7caaab"
               "b11e09a3bc211685396750a4723c8c8334433019c1844c9aa22b6e6995bc703d"
               "db09edbe4f1a61a62a23531cf707976a861efef13e8347210d77f3d080e9ba89"
               "fa12bd4f75caa74f23b4af606902f6187dd9be62a43b1b529344f1114e69391d"
               "5f574ef7f013d4336801fed022178c3ed91d0b6d51325315fc1dcabf4770a2ea")))
         (c (%hex-octets
             (concatenate 'string
              "87bd17e107d5e37b7d67c45df2453f04e778cfb38c425da461d52be742d7f53e"
              "ca92a84fa0752f78c062b63bf7f67cb281c243a1ecaf67aead78868b20a9d6c3"
              "567b32782143ce00616aa573b1e01153702f8bab17513ba24a3b777dba87f026"
              "d92e960b75ab084b2f2f549d532b4016a9ec7fe9494d9aa5907c854c20f993ea"
              "fff4221d7688f6a188c6a70bf794d76f62df8d350e122028d6038f76ac91d0c4"
              "814fa1ba1fa4c8dd42e9f4d733aa3b9a52a4d1b1241962986d64e28b62ae149d"
              "e34d96de819b64441af85e044d894b17bb3f69d72cee5e698260af9312a03967"
              "f0b82cb24b01828730b17f5ebd2bc76d510e0fc0b00bfe814fe9a7ee4c430b80"
              "3109fb6ac0454ddf65931e9745542bb02ab1620ebf8968426c6425599419f9dc"
              "b814f9c302146778baf342df8922de9e229d9af6a4113143211597da785d11a8"
              "74f3c90bf1733f331a5e3348355863e45a0f0661076e4e2d5cda109fe370e64f"
              "edfaeee5d3ea0131d7b8bf3a6344abf7dcc77699f4325c6f0e9aaa8b4bfae413"
              "e22c5ea945b5d59b417c733780d03069f169be61813c15391f2dd1619cd93357"
              "ceadf8688e97b37e162a19335e3e17c676e540a0646a50f0c88357dad7e868ac"
              "1570e0ec068bce9b87e1de6c3e03098f77ee87854d97e20cf9e1bc15d9ce1833"
              "814a9f15667d8f61396bfdaf0132211ba1e639f65a4a7735e6edf3b6355f586e"
              "7434a5ffba59f7790c091c806debd0921d64d3360cf8eb42aa6238924865dbe7"
              "9b50552317752633b44e1f64ebeab992225c395010a91d0966ca3b5356d20234"
              "89c38fbab20582a6cf6ba5d946e97a090da7496f8ab2e197f3a2113893980d6c"
              "48bcf834536b255ff6520350638e563b049ade5243a6c7210e56d8873f96ad5a"
              "2a8d527d4598255b7f5d5d663e8e18917f2ffa7fca37a5e0917c8a2343446b35"
              "87345ca13c78c29e813455744b8037a3c6da691087f9cd3b3bb64b948eba4edd"
              "f7d0dbcff1d31b2759e0c82d36b56e3ea3c0d21fe7d19855ff5632cdeeea2c78"
              "a5bdea96263445c653e4a12447d4c1200240ad537875571d4bf88dcc40b35437"
              "942b85aedeb211969551a9ff863704d6d9f097858ff2da1d3525aeb656a90881"
              "9d0438ebb16eb81b10087f3c0d9c036a59bf3ee15579f85f1ecb16ecbf807167"
              "548635401ab6c1ca6c1edb6eed3c1efe0d2eaad683ccbfc89aa7c4dea656983c"
              "c0b959445f92c596011667e83528a964ba4a067991e745372bc05792958ed2f7"
              "76b57ec98f8181e2caf7b542999c04dea5075247e70fa43ceae837fc9b3a9354"
              "668309cfbffe0194937c7064e03ad6c756c5b3e4bb0c514018d31b7084db418f"
              "105b48ba93b86095591df4157aaa82f9c186e54181e6966751ce26a6f8357b61"
              "000944218bc69c309f720a35cff5dfd27bad2197000c3f9ccb97bd00049a4a66"
              "bbc18105026430fab2aac0713534473cf1f46cf92d31f3129eeb95772f2c3ad5"
              "590210a3fcbd6603cd7420fca5fb5516629edf73d86ef03899f279d3b8f1962a"
              "71dc0d3702cb164bacac3414e9f4736992ac8fe2afeffeca9d6dfb0af61901ad"
              "f9b210afcb2a1e990cd9bbba5b90ed1e230f9e39b1888ccd8fd9e1b5c37bfbf8"
              "02fd6d90adfa632ec26f90cd0f4d7ab3859ef964d726851c4d2b120d154c86ac"
              "60a05918a9b0381f4cdad739261d43ce4e79de1f4fbaf09cbb3dc329303bb03a"
              "f964fbd45c0b1e801530293e39754ff36c5681395931b0bff4896cb3ece79c53"
              "1c72597de5451a1c56448cc25d2aacc9f1404b6440f6eb10567b0965d8d18a03"
              "68ba4d1723359130fadc83f80848c23274e7cdfcaf97ee63750cb206e25caf8b"
              "0b8b2cf066c2ccd61d844873d912109e28ee334f71eeba2d3cdc31d93415e55e"
              "82362119f81cef055694d869bff6e0d70e1ed69834b9fd40768611e1d88be19b"
              "d77d946f4910c0564b1ce0ccf0e53a45b8f065d8ec2023f226f20928f351971d"
              "3e9fa566626f295ff96c21f0d113de8e81c502d6553ddc41652271e41215f6bf"
              "3a6e0a26d284ad504b3c4fae26995b644789a262e8db27a0b41c21b82194d6ed"
              "1c4cd6ac97355b83e3f7e4f8656d33761f4bef98bfd50f1d03178b6a5be67bc1"
              "ea79dff6a7cd673dc10f63900631fd6052e0f4deedbc21dc87ca42554047ac78"
              "dba3aa4ccaae14e5eae6c1ded7990cb44b72b971e43882329347888957446a75")))
         (expected-k (make-array 32 :element-type '(unsigned-byte 8)
                                    :initial-contents
                                    '(#x6c #x4f #x4a #x23 #x12 #x55 #xa8 #xcd
                                      #xfb #x74 #x24 #xc8 #xda #xbf #x3a #x62
                                      #x4c #xef #xaf #xfd #x28 #x96 #x4e #xfe
                                      #x22 #x0a #xb6 #x17 #x8f #xa6 #xb3 #x24))))
    (%check :ml-kem-dk-len  (= (length dk) 3168)  "KAT dk must be 3168 bytes (FIPS-203 Table 2)")
    (%check :ml-kem-c-len   (= (length c)  1568)  "KAT c must be 1568 bytes (FIPS-203 Table 2)")
    ;; k and k2 are foreign secret static-vectors this test OWNS — free after all use.
    (let ((k (dds.dare:ml-kem-1024-decapsulate dk c)))
      (unwind-protect
           (progn
             (%check :ml-kem-decaps-kat-len (= (length k) 32) "KAT K must be 32 bytes")
             (%check :ml-kem-decaps-kat
                     (equalp k expected-k)
                     (format nil "byte-exact decaps KAT FAIL: got ~{~2,'0x~}; expected ~{~2,'0x~}"
                             (coerce k 'list) (coerce expected-k 'list)))
             ;; (c) Decaps determinism: same (dk,c) => same K on a second call (FIPS-203 Alg. 18 is pure).
             (let ((k2 (dds.dare:ml-kem-1024-decapsulate dk c)))
               (unwind-protect
                    (%check :ml-kem-decaps-determinism
                            (equalp k k2)
                            "decaps determinism FAIL: two calls with same (dk,c) returned different K")
                 (dds.dare:free-secret-octets k2))))
        (dds.dare:free-secret-octets k))))

  ;; (a) Round-trip: keygen -> encapsulate(pub) -> decapsulate(priv,ct) => same ss.
  ;; priv-key (static), ss-enc/ss-dec/ss-wrong (static), priv2 (static) are OWNED secrets — free after use.
  (multiple-value-bind (pub-key priv-key)
      (dds.dare:ml-kem-1024-keygen)
    (unwind-protect
         (progn
           (%check :ml-kem-pub-len (= (length pub-key) 1568)
                   (format nil "pub key must be 1568 bytes (FIPS-203 Table 2); got ~a" (length pub-key)))
           (%check :ml-kem-priv-len (= (length priv-key) 3168)
                   (format nil "priv key must be 3168 bytes (FIPS-203 Table 2); got ~a" (length priv-key)))
           (multiple-value-bind (ct ss-enc)
               (dds.dare:ml-kem-1024-encapsulate pub-key)
             (unwind-protect
                  (progn
                    (%check :ml-kem-ct-len (= (length ct) 1568)
                            (format nil "ciphertext must be 1568 bytes (FIPS-203 Table 2); got ~a" (length ct)))
                    (%check :ml-kem-ss-enc-len (= (length ss-enc) 32)
                            (format nil "shared secret must be 32 bytes (FIPS-203 Table 2); got ~a" (length ss-enc)))
                    (let ((ss-dec (dds.dare:ml-kem-1024-decapsulate priv-key ct)))
                      (unwind-protect
                           (progn
                             (%check :ml-kem-ss-dec-len (= (length ss-dec) 32)
                                     (format nil "decaps shared secret must be 32 bytes; got ~a" (length ss-dec)))
                             (%check :ml-kem-roundtrip
                                     (equalp ss-enc ss-dec)
                                     (format nil "round-trip FAIL: encaps ss ~{~2,'0x~^ ~} /= decaps ss ~{~2,'0x~^ ~}"
                                             (coerce ss-enc 'list) (coerce ss-dec 'list)))
                             ;; (d) Wrong-key: different private key -> different ss (FIPS-203 §7.3).
                             (multiple-value-bind (pub2 priv2)
                                 (dds.dare:ml-kem-1024-keygen)
                               (declare (ignore pub2))
                               (let ((ss-wrong (dds.dare:ml-kem-1024-decapsulate priv2 ct)))
                                 (unwind-protect
                                      (%check :ml-kem-wrong-key-differs
                                              (not (equalp ss-dec ss-wrong))
                                              "wrong-key implicit rejection FAIL: different dk yielded same ss")
                                   (dds.dare:free-secret-octets ss-wrong)
                                   (dds.dare:free-secret-octets priv2)))))
                        (dds.dare:free-secret-octets ss-dec))))
               (dds.dare:free-secret-octets ss-enc))))
      (dds.dare:free-secret-octets priv-key)))

  t)

(defun* run-dare-envelope-test ()
    (function () t)
  "KEM-DEM envelope: derive-dek, seal-payload, open-payload, make-record-aad round-trips and rejection tests."
  (handler-case (dds.dare:dare-available-p)
    (dds.dare:dare-unavailable (c)
      (format t "~&  [dare-envelope] SKIP — OpenSSL >= 3.5 not available: ~a~%"
              (dds.dare:dare-unavailable-reason c))
      (return-from run-dare-envelope-test t)))

  ;; generate a real ML-KEM shared secret and derive the DEK from it
  (multiple-value-bind (pub priv)
      (dds.dare:ml-kem-1024-keygen)
    (multiple-value-bind (kem-ct ss-enc)
        (dds.dare:ml-kem-1024-encapsulate pub)
      (let* ((ss-dec (dds.dare:ml-kem-1024-decapsulate priv kem-ct))
             (dek     (dds.dare:derive-dek ss-enc))
             ;; round-trip sanity: both sides derive the same DEK
             (dek2    (dds.dare:derive-dek ss-dec))
             (nonce   (make-array 12 :element-type '(unsigned-byte 8)
                                     :initial-contents '(1 2 3 4 5 6 7 8 9 10 11 12)))
             (topic   "DaRETestTopic")
             (guid    (make-array 16 :element-type '(unsigned-byte 8)
                                     :initial-contents '(0 1 2 3 4 5 6 7 8 9 10 11 12 13 14 15)))
             (sn      42)
             (aad     (dds.dare:make-record-aad topic guid sn :data))
             (pt      (make-array 8 :element-type '(unsigned-byte 8)
                                    :initial-contents '(65 66 67 68 69 70 71 72))) ; "ABCDEFGH"
             (sealed  (dds.dare:seal-payload dek nonce aad pt)))
        ;; ss-enc/ss-dec (static) + dek/dek2 (static) + priv (static) are OWNED secrets — free at end.
        (unwind-protect
         (progn
        (%check :dek-len    (= (length dek) 32)           "derive-dek must return 32 bytes")
        (%check :dek2-match (equalp dek dek2)             "both-side DEKs must match")

        ;; version byte and blob length
        (%check :sealed-version (= (aref sealed 0) #x01)  "sealed blob must start with 0x01 version byte")
        (%check :sealed-len     (= (length sealed) (+ 1 12 (length pt) 16))
                (format nil "sealed blob length must be 1+12+~d+16; got ~d" (length pt) (length sealed)))

        ;; round-trip
        (let ((recovered (dds.dare:open-payload dek sealed aad)))
          (%check :open-non-nil  recovered               "open-payload must return non-NIL for valid sealed blob")
          (%check :open-roundtrip (equalp recovered pt)
                  (format nil "open-payload roundtrip mismatch; got ~{~2,'0x~^ ~}" (coerce recovered 'list))))

        ;; tamper: version byte
        (let ((bad (copy-seq sealed)))
          (setf (aref bad 0) #x02)
          (%check :tamper-version (null (dds.dare:open-payload dek bad aad))
                  "version byte tamper must return NIL"))

        ;; tamper: nonce byte (byte 1 = first nonce byte)
        (let ((bad (copy-seq sealed)))
          (setf (aref bad 1) (logxor (aref bad 1) #xff))
          (%check :tamper-nonce (null (dds.dare:open-payload dek bad aad))
                  "nonce tamper must return NIL"))

        ;; tamper: ciphertext byte (byte 13 = first ct byte)
        (let ((bad (copy-seq sealed)))
          (setf (aref bad 13) (logxor (aref bad 13) 1))
          (%check :tamper-ct (null (dds.dare:open-payload dek bad aad))
                  "ciphertext tamper must return NIL"))

        ;; tamper: tag byte (last 16 bytes)
        (let ((bad (copy-seq sealed))
              (last (1- (length sealed))))
          (setf (aref bad last) (logxor (aref bad last) 1))
          (%check :tamper-tag (null (dds.dare:open-payload dek bad aad))
                  "tag tamper must return NIL"))

        ;; wrong DEK
        (let ((bad-dek (make-array 32 :element-type '(unsigned-byte 8) :initial-element #xab)))
          (%check :wrong-dek (null (dds.dare:open-payload bad-dek sealed aad))
                  "wrong DEK must return NIL"))

        ;; changed AAD: different topic
        (let ((bad-aad (dds.dare:make-record-aad "OtherTopic" guid sn :data)))
          (%check :changed-aad-topic (null (dds.dare:open-payload dek sealed bad-aad))
                  "changed topic in AAD must return NIL"))

        ;; changed AAD: different sn
        (let ((bad-aad (dds.dare:make-record-aad topic guid 99 :data)))
          (%check :changed-aad-sn (null (dds.dare:open-payload dek sealed bad-aad))
                  "changed sn in AAD must return NIL"))

        ;; bounds: truncated sealed blobs — must return NIL, no error
        (dolist (short-len '(0 1 5 28))
          (let ((short (make-array short-len :element-type '(unsigned-byte 8)
                                             :initial-element #x01)))
            (%check :truncated (null (dds.dare:open-payload dek short aad))
                    (format nil "truncated sealed (len=~d) must return NIL" short-len))))

        t)
          (dds.dare:free-secret-octets dek2)
          (dds.dare:free-secret-octets dek)
          (dds.dare:free-secret-octets ss-dec))
        (dds.dare:free-secret-octets ss-enc))
      (dds.dare:free-secret-octets priv)))

  t)

(defun* run-dare-key-provider-test ()
    (function () t)
  "Pluggable key-provider vtable + file-based ML-KEM-1024 provider: generate, reload, perms-refuse.
   (1) make-file-key-provider in a temp dir + open: generates keypair, files exist, private-key perms 0600.
   (2) A second provider on the same dir opens and loads the same public key — encapsulate to provider-1's
       public key then key-provider-decapsulate on provider-2 yields the matching shared secret
       (round-trip through file load).
   (3) chmod private key to 0644 -> next open REFUSES (signals a clear error).
   (4) *perms-mode-reader* bound to (constantly nil) -> open REFUSES (fail-closed on unverifiable perms).
   Uses unwind-protect to clean up the temp dir."
  (handler-case (dds.dare:dare-available-p)
    (dds.dare:dare-unavailable (c)
      (format t "~&  [dare-key-provider] SKIP — OpenSSL >= 3.5 not available: ~a~%"
              (dds.dare:dare-unavailable-reason c))
      (return-from run-dare-key-provider-test t)))

  (let* ((tmp-dir (uiop:merge-pathnames*
                   (make-pathname :directory (list :relative
                                                   (format nil "dds-dare-kp-test-~a"
                                                           (get-universal-time))))
                   (uiop:temporary-directory))))
    (unwind-protect
         (progn
           ;; (1) first provider: open must generate the keypair
           (let ((kp1 (dds.dare:make-file-key-provider :dir tmp-dir)))
             (dds.dare:key-provider-open kp1)
             (let* ((pub-file  (uiop:merge-pathnames* "ml-kem-1024.pub" tmp-dir))
                    (priv-file (uiop:merge-pathnames* "ml-kem-1024.key" tmp-dir))
                    (pub1      (dds.dare:key-provider-recipient-public-key kp1)))
               (%check :kp1-pub-file-exists
                       (uiop:file-exists-p pub-file)
                       "public key file must exist after first open")
               (%check :kp1-priv-file-exists
                       (uiop:file-exists-p priv-file)
                       "private key file must exist after first open")
               (%check :kp1-pub-len
                       (= (length pub1) 1568)
                       (format nil "public key must be 1568 bytes (FIPS-203 Table 2); got ~a"
                               (length pub1)))

               ;; (2) second provider on same dir: open loads existing keypair
               (let ((kp2 (dds.dare:make-file-key-provider :dir tmp-dir)))
                 (dds.dare:key-provider-open kp2)
                 (let* ((pub2 (dds.dare:key-provider-recipient-public-key kp2)))
                   (%check :kp2-pub-matches-kp1
                           (equalp pub1 pub2)
                           "loaded public key must match the generated one")

                   ;; encapsulate to provider-1's public key; decapsulate via provider-2.
                   ;; ss-enc (encapsulate) + ss-dec (decapsulate, CALLER-owned) are static secrets — free after use.
                   (multiple-value-bind (kem-ct ss-enc)
                       (dds.dare:ml-kem-1024-encapsulate pub1)
                     (unwind-protect
                          (let ((ss-dec (dds.dare:key-provider-decapsulate kp2 kem-ct)))
                            (unwind-protect
                                 (progn
                                   (%check :kp-roundtrip-ss-len
                                           (= (length ss-dec) 32)
                                           "decapsulated shared secret must be 32 bytes")
                                   (%check :kp-roundtrip
                                           (equalp ss-enc ss-dec)
                                           "encapsulate->decapsulate round-trip FAIL: shared secrets differ"))
                              (dds.dare:free-secret-octets ss-dec)))
                       (dds.dare:free-secret-octets ss-enc)))

                   (dds.dare:key-provider-close kp2)))

               ;; (3) loosen private key perms to 0644 -> next open must signal
               (uiop:run-program (list "chmod" "644"
                                       (uiop:native-namestring priv-file)))
               (let ((kp3 (dds.dare:make-file-key-provider :dir tmp-dir)))
                 (%check :kp3-perms-refuse
                         (handler-case
                             (progn (dds.dare:key-provider-open kp3) nil)
                           (error () t))
                         "open with world-readable private key must signal an error"))

               ;; (4) simulate ls unavailable: *perms-mode-reader* -> nil => fail-CLOSED
               ;; Restore 0600 first so the failure is from unverifiable, not loose perms.
               (uiop:run-program (list "chmod" "600"
                                       (uiop:native-namestring priv-file)))
               (let* ((kp4  (dds.dare:make-file-key-provider :dir tmp-dir))
                      (signaled
                        (let ((dds.dare::*perms-mode-reader* (constantly nil)))
                          (handler-case
                              (progn (dds.dare:key-provider-open kp4) nil)
                            (error () t)))))
                 (%check :kp4-unverifiable-refuse
                         signaled
                         "open must signal when ls is unavailable (fail-closed on unverifiable perms)"))

               (dds.dare:key-provider-close kp1))))

      ;; cleanup: remove temp dir tree
      (when (uiop:directory-exists-p tmp-dir)
        (uiop:delete-directory-tree tmp-dir :validate t))))

  t)

(defun* run-dare-encrypted-store-test ()
    (function () t)
  "Encrypted durable-store decorator: put/get-range round-trip, sealed inner payloads, tamper drop."
  (handler-case (dds.dare:dare-available-p)
    (dds.dare:dare-unavailable (c)
      (format t "~&  [dare-encrypted-store] SKIP — OpenSSL >= 3.5 not available: ~a~%"
              (dds.dare:dare-unavailable-reason c))
      (return-from run-dare-encrypted-store-test t)))

  (let* ((tmp-dir (uiop:merge-pathnames*
                   (make-pathname :directory (list :relative
                                                   (format nil "dds-dare-enc-test-~a"
                                                           (get-universal-time))))
                   (uiop:temporary-directory))))
    (unwind-protect
         (progn
           (let* ((kp (dds.dare:make-file-key-provider :dir tmp-dir))
                  (inner (dds.durability:make-memory-store))
                  (enc (dds.durability:make-encrypted-store inner kp))
                  (topics (list "Square" "Circle" "Square"))
                  (guids (list (make-array 16 :element-type '(unsigned-byte 8) :initial-element 1)
                               (make-array 16 :element-type '(unsigned-byte 8) :initial-element 2)
                               (make-array 16 :element-type '(unsigned-byte 8) :initial-element 3)))
                  (sns (list 1 1 2))
                  (kinds (list :data :data :dispose))
                  (payloads (list (make-array 4 :element-type '(unsigned-byte 8) :initial-contents '(10 20 30 40))
                                  (make-array 3 :element-type '(unsigned-byte 8) :initial-contents '(50 60 70))
                                  (make-array 5 :element-type '(unsigned-byte 8) :initial-contents '(1 2 3 4 5)))))
             ;; (a) put N records through the encrypted store
             (loop for topic in topics
                   for guid in guids
                   for sn in sns
                   for kind in kinds
                   for payload in payloads
                   do (dds.durability:store-put enc topic guid sn nil kind payload))
             ;; (a) get-range round-trips each payload byte-exact
             (let ((sq-recs (dds.durability:store-get-range enc "Square")))
               (%check :enc-sq-count (= 2 (length sq-recs)) "Square should have 2 records")
               (let ((p1 (dds.durability:durable-record-payload (first sq-recs)))
                     (p2 (dds.durability:durable-record-payload (second sq-recs))))
                 (%check :enc-sq-payload-1
                         (equalp p1 (first payloads))
                         (format nil "Square sn1 payload mismatch: ~s" (coerce p1 'list)))
                 (%check :enc-sq-payload-2
                         (equalp p2 (third payloads))
                         (format nil "Square sn2 payload mismatch: ~s" (coerce p2 'list)))))
             (let ((ci-recs (dds.durability:store-get-range enc "Circle")))
               (%check :enc-ci-count (= 1 (length ci-recs)) "Circle should have 1 record")
               (%check :enc-ci-payload
                       (equalp (dds.durability:durable-record-payload (first ci-recs)) (second payloads))
                       "Circle payload mismatch"))
             ;; (b) inner store's raw payloads are SEALED (start with #x01 version byte, != plaintext)
             (let ((inner-sq (dds.durability:store-get-range inner "Square")))
               (%check :enc-inner-sealed-version
                       (= #x01 (aref (dds.durability:durable-record-payload (first inner-sq)) 0))
                       "inner store payload must start with DARE version byte #x01")
               (%check :enc-inner-not-plaintext
                       (not (equalp (dds.durability:durable-record-payload (first inner-sq)) (first payloads)))
                       "inner store payload must not equal plaintext"))
             ;; (c) topics/count delegate correctly
             (%check :enc-topics
                     (null (set-difference (dds.durability:store-topics enc) '("Square" "Circle") :test #'string=))
                     "topics must be Square + Circle")
             (%check :enc-count-sq (= 2 (dds.durability:store-count enc "Square")) "count Square = 2")
             (%check :enc-count-ci (= 1 (dds.durability:store-count enc "Circle")) "count Circle = 1")
             ;; (d) tamper test: inject a tampered sealed blob with same DEK, assert hook fires + record dropped
             (let* ((inner2 (dds.durability:make-memory-store))
                    (enc2   (dds.durability:make-encrypted-store inner2 kp))
                    (guid2  (make-array 16 :element-type '(unsigned-byte 8) :initial-element 9))
                    (real-payload (make-array 4 :element-type '(unsigned-byte 8)
                                               :initial-contents '(11 22 33 44)))
                    (hook-count 0))
               ;; put one real record so inner2 has a valid sealed blob
               (dds.durability:store-put enc2 "T" guid2 1 nil :data real-payload)
               ;; extract the sealed blob and verify round-trip before tamper
               (let* ((pre (dds.durability:store-get-range enc2 "T")))
                 (%check :enc-tamper-pre-count (= 1 (length pre)) "pre-tamper get-range must yield 1"))
               ;; now inject a tampered sealed blob at sn=2 directly into inner2 (bypasses enc2 seal)
               (let* ((sealed-rec (first (dds.durability:store-get-range inner2 "T")))
                      (sealed-blob (dds.durability:durable-record-payload sealed-rec))
                      (tampered (copy-seq sealed-blob)))
                 (setf (aref tampered 13) (logxor (aref tampered 13) #xff))
                 ;; inject tampered as sn=2 directly into the inner store
                 (dds.durability:store-put inner2 "T" guid2 2 nil :data tampered)
                 ;; now get-range on enc2 should yield only sn=1; sn=2 tampered -> dropped + hook fires
                 (let ((dds.durability:*dare-error-hook*
                         (lambda (c ctx n) (declare (ignore c ctx)) (setf hook-count n) t)))
                   (let ((result (dds.durability:store-get-range enc2 "T")))
                     (%check :enc-tamper-drop
                             (= 1 (length result))
                             (format nil "tampered record must be DROPPED; got ~d records" (length result)))
                     (%check :enc-tamper-hook-fired
                             (= 1 hook-count)
                             "hook must fire exactly once on the tampered record drop")
                     (%check :enc-tamper-sn1-present
                             (= 1 (dds.durability:durable-record-sn (first result)))
                             "the surviving record must be sn=1 (the valid one)"))))
               ;; free the DEK held by both encrypted stores at end-of-life (foreign static-vectors)
               (dds.durability:store-close enc2))
             (dds.durability:store-close enc)))
      (when (uiop:directory-exists-p tmp-dir)
        (uiop:delete-directory-tree tmp-dir :validate t))))
  t)

(defun* run-dare-encrypted-store-lifecycle-test ()
    (function () t)
  "Encrypted-store close/reopen lifecycle (§6 secret-material conformance): a store round-trips,
   store-close frees+zeroizes the DEK, store-open re-derives a fresh DEK, the round-trip still
   works, and a second store-close is safe (no double-free, no error). Exercises the
   foreign-backed static-vector zeroize+free + re-derive paths."
  (handler-case (dds.dare:dare-available-p)
    (dds.dare:dare-unavailable (c)
      (format t "~&  [dare-encrypted-store-lifecycle] SKIP — OpenSSL >= 3.5 not available: ~a~%"
              (dds.dare:dare-unavailable-reason c))
      (return-from run-dare-encrypted-store-lifecycle-test t)))
  (let* ((tmp-dir (uiop:merge-pathnames*
                   (make-pathname :directory (list :relative
                                                   (format nil "dds-dare-lifecycle-test-~a"
                                                           (get-universal-time))))
                   (uiop:temporary-directory)))
         (guid    (make-array 16 :element-type '(unsigned-byte 8) :initial-element 7))
         (payload (make-array 6 :element-type '(unsigned-byte 8)
                                :initial-contents '(9 8 7 6 5 4))))
    (unwind-protect
         (let* ((kp    (dds.dare:make-file-key-provider :dir tmp-dir))
                (inner (dds.durability:make-memory-store))
                (enc   (dds.durability:make-encrypted-store inner kp)))
           ;; (a) initial round-trip
           (dds.durability:store-put enc "Square" guid 1 nil :data payload)
           (let ((recs (dds.durability:store-get-range enc "Square")))
             (%check :lifecycle-initial-count (= 1 (length recs)) "initial get-range must yield 1")
             (%check :lifecycle-initial-roundtrip
                     (equalp (dds.durability:durable-record-payload (first recs)) payload)
                     "initial payload must round-trip byte-exact"))
           ;; (b) close frees + zeroizes the DEK (and closes the key provider)
           (%check :lifecycle-close-1 (dds.durability:store-close enc) "first store-close must return T")
           ;; (c) reopen re-derives a FRESH ephemeral DEK; records sealed under the prior DEK are
           ;; intentionally unreadable now, so purge them, then a fresh put/get-range round-trips.
           (%check :lifecycle-reopen (dds.durability:store-open enc) "store-open must return T")
           (dds.durability:store-purge enc "Square")
           (dds.durability:store-put enc "Square" guid 2 nil :data payload)
           (let ((recs (dds.durability:store-get-range enc "Square")))
             (%check :lifecycle-reopen-count (= 1 (length recs)) "after reopen+purge get-range must yield 1")
             (%check :lifecycle-reopen-roundtrip
                     (equalp (dds.durability:durable-record-payload (first recs)) payload)
                     "after reopen, a put/get-range must round-trip byte-exact under the fresh DEK"))
           ;; (d) a second close is safe — no double-free, no error
           (%check :lifecycle-close-2 (dds.durability:store-close enc) "second store-close must be safe (no double-free)"))
      (when (uiop:directory-exists-p tmp-dir)
        (uiop:delete-directory-tree tmp-dir :validate t))))
  t)

(defun* run-dare-envelope-v2-test ()
    (function () t)
  "Envelope v2: epoch-aware seal-payload-v2/open-payload-v2, AAD-bound epoch-id, fail-closed, bounds-checked.
   Builds a DEK via derive-dek of a fixed shared secret, verifies v2 blob structure, round-trips,
   unknown-epoch -> NIL, 1-bit flips -> NIL, changed AAD -> NIL, short blobs -> NIL.
   AAD-binding discriminator: patches header epoch to epoch+1 with a lookup that always returns
   the same DEK — GCM must fail, proving epoch-id is bound inside the AEAD (not just the header).
   Regression: v1 seal-payload/open-payload are deterministic (unchanged) + round-trip correctly."
  (handler-case (dds.dare:dare-available-p)
    (dds.dare:dare-unavailable (c)
      (format t "~&  [dare-envelope-v2] SKIP — OpenSSL >= 3.5 not available: ~a~%"
              (dds.dare:dare-unavailable-reason c))
      (return-from run-dare-envelope-v2-test t)))

  (let* ((shared-secret (make-array 32 :element-type '(unsigned-byte 8) :initial-element #x42))
         (dek  (dds.dare:derive-dek shared-secret))
         (nonce (make-array 12 :element-type '(unsigned-byte 8)
                               :initial-contents '(1 2 3 4 5 6 7 8 9 10 11 12)))
         (aad   (make-array 4 :element-type '(unsigned-byte 8) :initial-contents '(#xde #xad #xbe #xef)))
         (pt    (make-array 5 :element-type '(unsigned-byte 8) :initial-contents '(10 20 30 40 50)))
         (epoch-id 7))
    (unwind-protect
         (let ((blob (dds.dare:seal-payload-v2 dek epoch-id nonce aad pt)))
           ;; version byte must be #x02
           (%check :v2-version-byte (= #x02 (aref blob 0)) "v2 blob must start with #x02")
           ;; bytes 1-4: epoch-id 7 as 4-byte LE
           (%check :v2-epoch-b0 (= 7 (aref blob 1)) "epoch-id byte 0 must be 7")
           (%check :v2-epoch-b1 (= 0 (aref blob 2)) "epoch-id byte 1 must be 0")
           (%check :v2-epoch-b2 (= 0 (aref blob 3)) "epoch-id byte 2 must be 0")
           (%check :v2-epoch-b3 (= 0 (aref blob 4)) "epoch-id byte 3 must be 0")
           ;; total length = 1 + 4 + 12 + len(pt) + 16
           (%check :v2-blob-len (= (length blob) (+ 1 4 12 (length pt) 16))
                   (format nil "v2 blob length mismatch; got ~d" (length blob)))
           ;; round-trip: correct epoch lookup -> plaintext
           (let ((rt (dds.dare:open-payload-v2 (lambda (e) (if (= e epoch-id) dek nil)) blob aad)))
             (%check :v2-roundtrip-non-nil rt "open-payload-v2 must return non-NIL for valid blob")
             (%check :v2-roundtrip (equalp rt pt)
                     (format nil "open-payload-v2 roundtrip mismatch; got ~{~2,'0x~^ ~}" (coerce rt 'list))))
           ;; unknown epoch -> NIL
           (%check :v2-unknown-epoch
                   (null (dds.dare:open-payload-v2 (lambda (e) (declare (ignore e)) nil) blob aad))
                   "unknown epoch must return NIL")
           ;; 1-bit flip in epoch-id byte -> NIL (dek-lookup returns NIL for unknown epoch)
           (let ((bad (copy-seq blob)))
             (setf (aref bad 1) (logxor (aref bad 1) 1))
             (%check :v2-flip-epoch
                     (null (dds.dare:open-payload-v2 (lambda (e) (if (= e epoch-id) dek nil)) bad aad))
                     "1-bit flip in epoch-id must return NIL"))
           ;; AAD-binding proof: seal under epoch-id, patch header to claim epoch-id+1, open
           ;; with a lookup that returns the SAME dek for any epoch — GCM MUST fail because
           ;; seal bound aad||epoch-id-LE and open recomputes aad||(epoch-id+1)-LE.
           (let* ((patched (copy-seq blob))
                  (ep2     (1+ epoch-id)))
             (dotimes (i 4) (setf (aref patched (1+ i)) (ldb (byte 8 (* 8 i)) ep2)))
             (%check :v2-epoch-aad-binding
                     (null (dds.dare:open-payload-v2 (lambda (e) (declare (ignore e)) dek) patched aad))
                     "header epoch tampered (epoch+1, same DEK) MUST fail GCM -> proves epoch-id is inside AEAD AAD"))
           ;; 1-bit flip in nonce -> NIL
           (let ((bad (copy-seq blob)))
             (setf (aref bad 5) (logxor (aref bad 5) 1))
             (%check :v2-flip-nonce
                     (null (dds.dare:open-payload-v2 (lambda (e) (if (= e epoch-id) dek nil)) bad aad))
                     "1-bit flip in nonce must return NIL"))
           ;; 1-bit flip in ct -> NIL
           (let ((bad (copy-seq blob)))
             (setf (aref bad 17) (logxor (aref bad 17) 1))
             (%check :v2-flip-ct
                     (null (dds.dare:open-payload-v2 (lambda (e) (if (= e epoch-id) dek nil)) bad aad))
                     "1-bit flip in ct must return NIL"))
           ;; 1-bit flip in tag -> NIL
           (let ((bad (copy-seq blob)))
             (setf (aref bad (1- (length blob))) (logxor (aref bad (1- (length blob))) 1))
             (%check :v2-flip-tag
                     (null (dds.dare:open-payload-v2 (lambda (e) (if (= e epoch-id) dek nil)) bad aad))
                     "1-bit flip in tag must return NIL"))
           ;; changed AAD -> NIL
           (let ((bad-aad (make-array 4 :element-type '(unsigned-byte 8) :initial-contents '(#xff #xff #xff #xff))))
             (%check :v2-changed-aad
                     (null (dds.dare:open-payload-v2 (lambda (e) (if (= e epoch-id) dek nil)) blob bad-aad))
                     "changed AAD must return NIL"))
           ;; short blobs -> NIL, no error
           (dolist (short-len '(0 1 16 32))
             (let ((short (make-array short-len :element-type '(unsigned-byte 8) :initial-element #x02)))
               (%check :v2-short-blob
                       (null (dds.dare:open-payload-v2 (lambda (e) (declare (ignore e)) dek) short aad))
                       (format nil "short blob (len=~d) must return NIL" short-len))))
           ;; v1 regression: seal-payload/open-payload deterministic + correct round-trip
           ;; (:v1-deterministic checks GCM determinism with same inputs; v1 code is unmodified in this diff)
           (let* ((v1-nonce (make-array 12 :element-type '(unsigned-byte 8) :initial-element #xab))
                  (v1-aad   (make-array 2  :element-type '(unsigned-byte 8) :initial-contents '(#xca #xfe)))
                  (v1-pt    (make-array 3  :element-type '(unsigned-byte 8) :initial-contents '(1 2 3)))
                  (sealed1  (dds.dare:seal-payload dek v1-nonce v1-aad v1-pt))
                  (sealed2  (dds.dare:seal-payload dek v1-nonce v1-aad v1-pt)))
             (%check :v1-deterministic (equalp sealed1 sealed2)
                     "v1 seal-payload must produce identical bytes for identical inputs (GCM determinism)")
             (%check :v1-regression-version (= #x01 (aref sealed1 0))
                     "v1 sealed blob must still start with #x01")
             (let ((rt1 (dds.dare:open-payload dek sealed1 v1-aad)))
               (%check :v1-regression-roundtrip (equalp rt1 v1-pt)
                       "v1 open-payload must still round-trip"))))
      (dds.dare:free-secret-octets dek)))
  t)

;;; --- Task 3 (WP-DURABILITY-PERSISTENT): epoch-aware encrypted-store cross-restart test ---
;;; Composes make-file-store (inner, disk) + make-encrypted-store :epoch-dir (v2 seal/open
;;; by epoch-id, persisted epochs.dat). Proves: cross-restart re-open re-derives prior epochs'
;;; DEKs, a fresh epoch is minted per run with puts, records round-trip byte-exact across runs,
;;; on-disk frames are sealed (start #x02, never plaintext), tamper -> fail-closed drop.

(defun* %pst-octets (b)
    (function (list) (simple-array (unsigned-byte 8) (*)))
  "Build a (simple-array (unsigned-byte 8) (*)) from list B (persistent-store-test fixture)."
  (make-array (length b) :element-type '(unsigned-byte 8) :initial-contents b))

(defun* %pst-read-all-log-bytes (dir)
    (function (pathname) (simple-array (unsigned-byte 8) (*)))
  "Concatenate every D/topics/*.log file's raw bytes (for the no-plaintext-on-disk assertion)."
  (let* ((topics-dir (merge-pathnames (make-pathname :directory '(:relative "topics")) dir))
         (out '()))
    (when (uiop:directory-exists-p topics-dir)
      (dolist (path (uiop:directory-files topics-dir "*.log"))
        (with-open-file (s path :element-type '(unsigned-byte 8))
          (let ((v (make-array (file-length s) :element-type '(unsigned-byte 8))))
            (read-sequence v s)
            (push v out)))))
    (let* ((total (reduce #'+ out :key #'length :initial-value 0))
           (cat   (make-array total :element-type '(unsigned-byte 8)))
           (pos   0))
      (dolist (v (nreverse out) cat)
        (replace cat v :start1 pos)
        (incf pos (length v))))))

(defun* %pst-subseq-present-p (haystack needle)
    (function ((simple-array (unsigned-byte 8) (*)) (simple-array (unsigned-byte 8) (*))) boolean)
  "Return T iff octet vector NEEDLE occurs as a contiguous subsequence of HAYSTACK."
  (let ((hn (length haystack)) (nn (length needle)))
    (when (zerop nn) (return-from %pst-subseq-present-p t))
    (loop for start from 0 to (- hn nn)
          when (loop for i below nn always (= (aref haystack (+ start i)) (aref needle i)))
            do (return-from %pst-subseq-present-p t))
    nil))

(defun* %pst-epoch-count (dir)
    (function (pathname) (integer 0))
  "Count epochs in D/epochs.dat via the production loader (replay + tail-recover)."
  (hash-table-count (dds.durability::%load-epoch-table dir)))

(defun* %pst-read-epochs-dat (dir)
    (function (pathname) (simple-array (unsigned-byte 8) (*)))
  "Read D/epochs.dat into a fresh octet vector (empty vector if absent)."
  (let ((path (dds.durability::%epochs-dat-path dir)))
    (if (probe-file path)
        (with-open-file (s path :element-type '(unsigned-byte 8))
          (let ((v (make-array (file-length s) :element-type '(unsigned-byte 8))))
            (read-sequence v s)
            v))
        (make-array 0 :element-type '(unsigned-byte 8)))))

(defun* %pst-epochs-kem-cts (dir)
    (function (pathname) list)
  "Return an alist of (epoch-id . kem-ct-vector) parsed from D/epochs.dat, sorted by epoch-id."
  (let ((tbl (dds.durability::%load-epoch-table dir))
        (acc '()))
    (maphash (lambda (id ct) (push (cons id ct) acc)) tbl)
    (sort acc #'< :key #'car)))

(defun* %pst-sealed-epoch-id (blob)
    (function ((simple-array (unsigned-byte 8) (*))) (unsigned-byte 32))
  "Extract epoch-id from a v2 sealed blob: bytes 1-4 LE (after the version byte at 0)."
  (dds.durability::%get-u32-le blob 1))

(defun* %pst-sealed-nonce (blob)
    (function ((simple-array (unsigned-byte 8) (*))) (simple-array (unsigned-byte 8) (*)))
  "Extract the 12-byte nonce from a v2 sealed blob: bytes 5-16 (after ver(1)+epoch-id(4))."
  (let ((v (make-array 12 :element-type '(unsigned-byte 8))))
    (replace v blob :start2 5 :end2 17)
    v))

(defun* run-dare-persistent-store-test ()
    (function () t)
  "Epoch-aware encrypted-store cross-restart: persisted epochs.dat, per-epoch DEK, lazy mint
   on first put, v2 seal/open by epoch-id. Three runs over the SAME store dir D + key dir K:
   run1 puts N -> get-range byte-exact, inner frames sealed (start #x02, no plaintext on disk),
   epochs.dat has exactly 1 epoch; run2 re-opens (epoch-1 DEK re-derived) -> N still byte-exact,
   put M more -> 2 epochs; run3 -> all N+M open byte-exact; a tampered on-disk frame is DROPPED."
  (handler-case (dds.dare:dare-available-p)
    (dds.dare:dare-unavailable (c)
      (format t "~&  [dare-persistent-store] SKIP — OpenSSL >= 3.5 not available: ~a~%"
              (dds.dare:dare-unavailable-reason c))
      (return-from run-dare-persistent-store-test t)))

  (let* ((d-dir (uiop:merge-pathnames*
                 (make-pathname :directory (list :relative
                                                 (format nil "dds-pst-d-~a" (get-universal-time))))
                 (uiop:temporary-directory)))
         (k-dir (uiop:merge-pathnames*
                 (make-pathname :directory (list :relative
                                                 (format nil "dds-pst-k-~a" (get-universal-time))))
                 (uiop:temporary-directory)))
         (g1 (make-array 16 :element-type '(unsigned-byte 8) :initial-element 1))
         (g2 (make-array 16 :element-type '(unsigned-byte 8) :initial-element 2))
         ;; distinctive plaintexts so a no-plaintext-on-disk substring scan is meaningful
         (pa (%pst-octets '(#xA0 #xA1 #xA2 #xA3 #xA4 #xA5 #xA6 #xA7)))
         (pb (%pst-octets '(#xB0 #xB1 #xB2 #xB3 #xB4 #xB5 #xB6 #xB7)))
         (pc (%pst-octets '(#xC0 #xC1 #xC2 #xC3 #xC4 #xC5 #xC6 #xC7))))
    (unwind-protect
         (progn
           ;; --- RUN 1: put N=2, byte-exact round-trip, sealed-on-disk, 1 epoch ---
           (let* ((kp1  (dds.dare:make-file-key-provider :dir k-dir))
                  (fs1  (dds.durability:make-file-store :dir d-dir))
                  (enc1 (dds.durability:make-encrypted-store fs1 kp1 :epoch-dir d-dir)))
             (dds.durability:store-open enc1)
             (dds.durability:store-put enc1 "Square" g1 1 nil :data pa)
             (dds.durability:store-put enc1 "Square" g1 2 nil :data pb)
             ;; (a) get-range round-trips byte-exact
             (let ((recs (dds.durability:store-get-range enc1 "Square")))
               (%check :pst1-count (= 2 (length recs)) "run1 Square count must be 2")
               (%check :pst1-rt1 (equalp pa (dds.durability:durable-record-payload (first recs)))
                       "run1 sn1 payload must round-trip byte-exact")
               (%check :pst1-rt2 (equalp pb (dds.durability:durable-record-payload (second recs)))
                       "run1 sn2 payload must round-trip byte-exact"))
             ;; (b) the INNER file-store's on-disk frame payloads are SEALED (start #x02, != plaintext)
             (let ((inner-recs (dds.durability:store-get-range fs1 "Square")))
               (%check :pst1-inner-sealed-v2
                       (= #x02 (aref (dds.durability:durable-record-payload (first inner-recs)) 0))
                       "inner sealed payload must start with v2 version byte #x02")
               (%check :pst1-inner-not-plaintext
                       (not (equalp (dds.durability:durable-record-payload (first inner-recs)) pa))
                       "inner sealed payload must not equal plaintext"))
             ;; (b') no plaintext on disk: neither pa nor pb appears verbatim in any *.log
             (let ((raw (%pst-read-all-log-bytes d-dir)))
               (%check :pst1-disk-no-pa (not (%pst-subseq-present-p raw pa))
                       "plaintext pa must not appear on disk")
               (%check :pst1-disk-no-pb (not (%pst-subseq-present-p raw pb))
                       "plaintext pb must not appear on disk"))
             ;; (c) epochs.dat has exactly 1 epoch after a run with puts
             (%check :pst1-epochs-1 (= 1 (%pst-epoch-count d-dir)) "run1 must mint exactly 1 epoch")
             (dds.durability:store-close enc1))

           ;; --- RUN 2: re-open SAME D+K, N still byte-exact (epoch-1 DEK re-derived), put M=1 -> 2 epochs ---
           (let* ((kp2  (dds.dare:make-file-key-provider :dir k-dir))
                  (fs2  (dds.durability:make-file-store :dir d-dir))
                  (enc2 (dds.durability:make-encrypted-store fs2 kp2 :epoch-dir d-dir)))
             (dds.durability:store-open enc2)
             ;; (a) run-1's records open byte-exact under the re-derived epoch-1 DEK
             (let ((recs (dds.durability:store-get-range enc2 "Square")))
               (%check :pst2-count (= 2 (length recs)) "run2 must see run1's 2 records")
               (%check :pst2-rt1 (equalp pa (dds.durability:durable-record-payload (first recs)))
                       "run2 re-derives epoch-1 DEK: sn1 byte-exact")
               (%check :pst2-rt2 (equalp pb (dds.durability:durable-record-payload (second recs)))
                       "run2 re-derives epoch-1 DEK: sn2 byte-exact"))
             ;; still 1 epoch before any put in run2 (open does not mint)
             (%check :pst2-epochs-pre-1 (= 1 (%pst-epoch-count d-dir))
                     "run2 open must NOT mint an epoch before the first put")
             ;; put M=1 more -> mints epoch 2
             (dds.durability:store-put enc2 "Square" g2 7 nil :data pc)
             (%check :pst2-epochs-2 (= 2 (%pst-epoch-count d-dir)) "run2 first put must mint epoch 2")
             ;; (a) all 3 now open byte-exact within run2 (epoch-1 + epoch-2 DEKs both live)
             (let ((recs (dds.durability:store-get-range enc2 "Square")))
               (%check :pst2-count-3 (= 3 (length recs)) "run2 must now see 3 records")
               (%check :pst2-rt-pc
                       (find pc recs :key #'dds.durability:durable-record-payload :test #'equalp)
                       "run2 new epoch-2 record must round-trip byte-exact"))
             (dds.durability:store-close enc2))

           ;; --- SECURITY ASSERTIONS (after 2-run sequence; d-dir has 2 epochs + all sealed records) ---

           ;; (sec-a) cross-epoch DEK distinctness: epoch-1 and epoch-2 kem-ct bytes must differ
           (let ((entries (%pst-epochs-kem-cts d-dir)))
             (%check :pst-sec-epoch-count (= 2 (length entries))
                     (format nil "expected exactly 2 epoch entries; got ~d" (length entries)))
             (let ((ct1 (cdr (first entries)))
                   (ct2 (cdr (second entries))))
               (%check :pst-sec-kem-ct-distinct
                       (not (equalp ct1 ct2))
                       "epoch-1 and epoch-2 kem-ct must be DIFFERENT (distinct encapsulations)")))

           ;; (sec-b+c) cross-run epoch-id and intra-epoch nonce distinctness via a single ro open.
           (let* ((fs-ro (dds.durability:make-file-store :dir d-dir)))
             (dds.durability:store-open fs-ro)
             (let ((blobs (mapcar #'dds.durability:durable-record-payload
                                  (dds.durability:store-get-range fs-ro "Square"))))
               (%check :pst-sec-blobs-count (= 3 (length blobs))
                       (format nil "expected 3 sealed blobs; got ~d" (length blobs)))
               ;; sec-b: run-1 records (first two, sn=1,2) have epoch-id=1; run-2 record (sn=7) has epoch-id=2
               (let ((eid-run1 (%pst-sealed-epoch-id (first blobs)))
                     (eid-run2 (%pst-sealed-epoch-id (third blobs))))
                 (%check :pst-sec-cross-run-epoch-distinct
                         (not (= eid-run1 eid-run2))
                         (format nil "run-1 epoch-id ~d must differ from run-2 epoch-id ~d"
                                 eid-run1 eid-run2)))
               ;; sec-c: run-1's two records share epoch-1 but must have distinct nonces (counter++)
               (let ((n1 (%pst-sealed-nonce (first blobs)))
                     (n2 (%pst-sealed-nonce (second blobs))))
                 (%check :pst-sec-intra-epoch-nonce-distinct
                         (not (equalp n1 n2))
                         "intra-epoch nonces for sn=1 and sn=2 must be DIFFERENT (counter increments)")))
             (dds.durability:store-close fs-ro))

           ;; --- RUN 3: re-open SAME D+K, BOTH runs' records open byte-exact (epoch 1 + 2 re-derived) ---
           (let* ((kp3  (dds.dare:make-file-key-provider :dir k-dir))
                  (fs3  (dds.durability:make-file-store :dir d-dir))
                  (enc3 (dds.durability:make-encrypted-store fs3 kp3 :epoch-dir d-dir)))
             (dds.durability:store-open enc3)
             (let ((recs (dds.durability:store-get-range enc3 "Square")))
               (%check :pst3-count (= 3 (length recs)) "run3 must see all 3 records")
               (%check :pst3-rt-pa (find pa recs :key #'dds.durability:durable-record-payload :test #'equalp)
                       "run3 epoch-1 record pa byte-exact")
               (%check :pst3-rt-pb (find pb recs :key #'dds.durability:durable-record-payload :test #'equalp)
                       "run3 epoch-1 record pb byte-exact")
               (%check :pst3-rt-pc (find pc recs :key #'dds.durability:durable-record-payload :test #'equalp)
                       "run3 epoch-2 record pc byte-exact"))
             ;; tamper: flip a byte inside a sealed on-disk frame -> get-range DROPS it (no error)
             (let* ((inner (dds.durability:store-get-range fs3 "Square"))
                    (target (first inner))
                    (blob   (dds.durability:durable-record-payload target))
                    (tampered (copy-seq blob))
                    (hook-count 0))
               ;; flip a ciphertext byte (past the v2 header: 1 ver + 4 epoch + 12 nonce = 17)
               (setf (aref tampered 18) (logxor (aref tampered 18) #xff))
               ;; re-inject the tampered blob under a NEW sn directly into the inner file store
               (dds.durability:store-put fs3 "Square"
                                         (dds.durability:durable-record-writer-guid target)
                                         999 nil :data tampered)
               (let ((dds.durability:*dare-error-hook*
                       (lambda (c ctx n) (declare (ignore c ctx)) (setf hook-count n) t)))
                 (let ((recs (dds.durability:store-get-range enc3 "Square")))
                   (%check :pst3-tamper-drop (= 3 (length recs))
                           (format nil "tampered frame must be DROPPED; expected 3, got ~d" (length recs)))
                   (%check :pst3-tamper-hook (= 1 hook-count)
                           "tamper must fire the dare-error-hook exactly once"))))
             (dds.durability:store-close enc3)))
      (when (uiop:directory-exists-p d-dir)
        (uiop:delete-directory-tree d-dir :validate t))
      (when (uiop:directory-exists-p k-dir)
        (uiop:delete-directory-tree k-dir :validate t))))
  t)

;;; --- v2 key-hash AAD binding (WP-DURABILITY-PERSISTENT review) ---
;;; The file store writes key-hash to the frame in CLEARTEXT (CRC-only). A disk-write adversary
;;; could flip a record's key-hash and fix the trivial CRC to mis-route an instance's lifecycle.
;;; %record-aad-v2 binds key-hash into the AEAD, so a flipped key-hash now fails the GCM tag.

(defun* run-dare-keyhash-aad-test ()
    (function () t)
  "v2 AEAD binds key-hash: a disk-tampered (key-hash flipped, CRC fixed) frame must be DROPPED
   (fail-closed), not returned with the wrong key-hash. Control: the keyed record round-trips untampered."
  (handler-case (dds.dare:dare-available-p)
    (dds.dare:dare-unavailable (c)
      (format t "~&  [dare-keyhash-aad] SKIP — OpenSSL >= 3.5 not available: ~a~%"
              (dds.dare:dare-unavailable-reason c))
      (return-from run-dare-keyhash-aad-test t)))
  (let* ((d-dir (uiop:merge-pathnames* (make-pathname :directory (list :relative (format nil "dds-khaad-d-~a" (get-universal-time)))) (uiop:temporary-directory)))
         (k-dir (uiop:merge-pathnames* (make-pathname :directory (list :relative (format nil "dds-khaad-k-~a" (get-universal-time)))) (uiop:temporary-directory)))
         (g1 (make-array 16 :element-type '(unsigned-byte 8) :initial-element 1))
         (kh (make-array 16 :element-type '(unsigned-byte 8) :initial-element #xAA))
         (pa (%pst-octets '(#xA0 #xA1 #xA2 #xA3 #xA4 #xA5 #xA6 #xA7)))
         (topic "K"))
    (unwind-protect
         (progn
           ;; RUN 1: put a KEYED record, prove benign round-trip (S1 no-regression), seal to disk
           (let* ((kp  (dds.dare:make-file-key-provider :dir k-dir))
                  (fs  (dds.durability:make-file-store :dir d-dir))
                  (enc (dds.durability:make-encrypted-store fs kp :epoch-dir d-dir)))
             (dds.durability:store-open enc)
             (dds.durability:store-put enc topic g1 1 kh :data pa)
             (let ((recs (dds.durability:store-get-range enc topic)))
               (%check :khaad-control-rt
                       (and (= 1 (length recs))
                            (equalp pa (dds.durability:durable-record-payload (first recs)))
                            (equalp kh (dds.durability:durable-record-key-hash (first recs))))
                       "control: keyed record must round-trip byte-exact (key-hash in AAD, no regression)"))
             (dds.durability:store-close enc))
           ;; TAMPER: flip a key-hash byte + recompute BOTH the header CRC and the frame CRC so the
           ;; frame still parses — proving a CRC (which an on-disk adversary can recompute) is NOT a
           ;; MAC; the key-hash binding is enforced by the AEAD AAD, not the CRCs. v2 keyed frame:
           ;; magic(2)+flags(1)+guid(16)+sn(8)=27, key-hash 27..42, plen 43..46, header-crc 47..50,
           ;; payload from 51, frame-crc at 51+plen (ADR 0026 §10.9).
           (let* ((tid (dds.durability::%topic->id topic))
                  (log-path (merge-pathnames (make-pathname :directory '(:relative "topics") :name tid :type "log") d-dir))
                  (raw (with-open-file (fin log-path :element-type '(unsigned-byte 8))
                         (let ((v (make-array (file-length fin) :element-type '(unsigned-byte 8))))
                           (read-sequence v fin) v))))
             (setf (aref raw 27) (logxor (aref raw 27) #xFF))
             ;; recompute the header CRC (over [0,47), which now covers the flipped key-hash) …
             (dds.durability::%put-u32-le raw 47 (dds.durability::%crc32 raw 0 47))
             (let* ((plen    (dds.durability::%get-u32-le raw 43))
                    (crc-off (+ 51 plen)))
               ;; … and the trailing frame CRC, so the tampered frame passes both CRC gates
               (dds.durability::%put-u32-le raw crc-off (dds.durability::%crc32 raw 0 crc-off))
               (with-open-file (fout log-path :direction :output :element-type '(unsigned-byte 8) :if-exists :supersede)
                 (write-sequence raw fout))))
           ;; RUN 2: reopen → frame parses (both CRCs valid) but key-hash is in the AAD → GCM fail → DROP
           (let* ((kp2  (dds.dare:make-file-key-provider :dir k-dir))
                  (fs2  (dds.durability:make-file-store :dir d-dir))
                  (enc2 (dds.durability:make-encrypted-store fs2 kp2 :epoch-dir d-dir))
                  (hook-count 0))
             (dds.durability:store-open enc2)
             (%check :khaad-frame-parses
                     (= 1 (dds.durability:store-count fs2 topic))
                     "tampered frame must still parse at the file layer (CRC was recomputed)")
             (let ((dds.durability:*dare-error-hook*
                     (lambda (c ctx n) (declare (ignore c ctx)) (setf hook-count n) t)))
               (let ((recs (dds.durability:store-get-range enc2 topic)))
                 (%check :khaad-tamper-drop (zerop (length recs))
                         (format nil "tampered key-hash must be DROPPED by the AEAD; got ~d records" (length recs)))
                 (%check :khaad-tamper-hook (= 1 hook-count)
                         "key-hash tamper must fire the dare-error-hook exactly once")))
             (dds.durability:store-close enc2)))
      (when (uiop:directory-exists-p d-dir) (ignore-errors (uiop:delete-directory-tree d-dir :validate t)))
      (when (uiop:directory-exists-p k-dir) (ignore-errors (uiop:delete-directory-tree k-dir :validate t)))))
  t)

;;; --- epochs.dat replay recovery (WP-DURABILITY-PERSISTENT review) ---
;;; Mirrors the topic-log torn-vs-corrupt discipline + exercises the +epochs-max-ctlen+ cap.

(defun* run-dare-epochs-recovery-test ()
    (function () t)
  "epochs.dat replay recovery: torn trailing entry truncate-recovers; mid-file CRC corruption errors;
   an over-cap kem-ct-len errors (the +epochs-max-ctlen+ sanity cap, never a silent truncation).
   No crypto: %append-epoch / %load-epoch-table are CRC framing over opaque kem-ct bytes."
  (let ((ct1 (%pst-octets (loop for i below 40 collect (logand (+ i 1) 255))))
        (ct2 (%pst-octets (loop for i below 40 collect (logand (+ i 200) 255)))))
    (flet ((fresh-dir (tag)
             (let ((d (uiop:merge-pathnames*
                       (make-pathname :directory (list :relative (format nil "dds-eprec-~a-~a" tag (get-universal-time))))
                       (uiop:temporary-directory))))
               (dds.durability::%append-epoch d 1 ct1)
               (dds.durability::%append-epoch d 2 ct2)
               d)))
      ;; control: a clean 2-entry table loads both
      (let ((d (fresh-dir "ok")))
        (unwind-protect
             (%check :eprec-control (= 2 (hash-table-count (dds.durability::%load-epoch-table d)))
                     "clean epochs.dat must load both entries")
          (ignore-errors (uiop:delete-directory-tree d :validate t))))
      ;; (a) torn trailing entry → truncate-recover to 1 entry, no error
      (let ((d (fresh-dir "torn")))
        (unwind-protect
             (let* ((path (dds.durability::%epochs-dat-path d))
                    (sz   (length (%pst-read-epochs-dat d))))
               (dds.durability::%truncate-file path (- sz 3))
               (%check :eprec-torn (= 1 (hash-table-count (dds.durability::%load-epoch-table d)))
                       "torn trailing epochs.dat entry must truncate-recover to 1 entry, no error"))
          (ignore-errors (uiop:delete-directory-tree d :validate t))))
      ;; (b) mid-file CRC corruption (flip a byte inside entry 1's kem-ct) → error
      (let ((d (fresh-dir "corrupt")))
        (unwind-protect
             (let* ((path (dds.durability::%epochs-dat-path d))
                    (raw  (%pst-read-epochs-dat d))
                    (errored nil))
               (setf (aref raw 8) (logxor (aref raw 8) #xFF))
               (with-open-file (out path :direction :output :element-type '(unsigned-byte 8) :if-exists :supersede)
                 (write-sequence raw out))
               (handler-case (dds.durability::%load-epoch-table d) (error () (setf errored t)))
               (%check :eprec-corrupt errored
                       "mid-file epochs.dat corruption must signal an error (fail loud)"))
          (ignore-errors (uiop:delete-directory-tree d :validate t))))
      ;; (c) over-cap kem-ct-len (entry-1 ctlen field at offset 4) → :corrupt → error
      (let ((d (fresh-dir "overcap")))
        (unwind-protect
             (let* ((path (dds.durability::%epochs-dat-path d))
                    (raw  (%pst-read-epochs-dat d))
                    (errored nil))
               (dotimes (i 4) (setf (aref raw (+ 4 i)) #xFF))
               (with-open-file (out path :direction :output :element-type '(unsigned-byte 8) :if-exists :supersede)
                 (write-sequence raw out))
               (handler-case (dds.durability::%load-epoch-table d) (error () (setf errored t)))
               (%check :eprec-overcap errored
                       "an over-cap epochs.dat kem-ct-len must fail loud (:corrupt), not silently truncate"))
          (ignore-errors (uiop:delete-directory-tree d :validate t))))))
  t)
