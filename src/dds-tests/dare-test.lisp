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

    t))

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
