(in-package #:dds.tests)

;;; DDS-Security 1.1 §9.5.3.3 Slice-1 tests: SecuredPayload (de)serialization byte-exactness,
;;; round-trip + fail-closed bounds checks, HMAC-SHA256 (RFC 4231 KAT), and the §9.5.3.3.4.2
;;; session-key KDF composition. The HMAC vector is the AUTHENTIC published RFC 4231 Test Case 2,
;;; so our OpenSSL reproducing it is genuine independent conformance, not a self-generated vector.

(defun* run-security-secured-payload-corpus-test ()
    (function () t)
  "DDS-Security §9.5.3.3 SecuredPayload corpus + HMAC-SHA256 (RFC 4231) + session-key KDF.
   (a) serialize-secured-payload on a known field set => the EXACT reference byte vector (spike §2.5).
   (b) parse-secured-payload round-trips those bytes back to the 6 fields.
   (c) parse-secured-payload fail-closed: truncated / over-declared inputs signal, no OOB read.
   (d) hmac-sha256 matches RFC 4231 HMAC-SHA-256 Test Case 2 (published vector).
   (e) derive-session-key composes 'SessionKey'||salt||session_id under HMAC-SHA256 (§9.5.3.3.4.2; no trailing counter — Fast-DDS/Cyclone-aligned, T-RECONCILE 2026-06-27).
   Requires OpenSSL >= 3.5; skips only if truly absent. Both SBCL and Clasp must pass identically."
  (multiple-value-bind (%dare-ok %dare-reason) (dds.dare:dare-available-p)
    (unless %dare-ok
      (format t "~&  [security-secured-payload] SKIP — OpenSSL >= 3.5 not available: ~a~%"
              %dare-reason)
      (return-from run-security-secured-payload-corpus-test t)))

  ;; (a) byte-exact serialize. Known field set (spike §6 header fields + a fixed ct/tag).
  ;;   kind   = 00 00 00 04                       (AES256-GCM, §9.5.3.3.1 Table 69)
  ;;   key_id = aa bb cc dd                        (opaque octet[4])
  ;;   session_id = 01 00 00 00                     (octet[4])
  ;;   iv_suffix  = 11 22 33 44 55 66 77 88         (octet[8])
  ;;   ciphertext = de ad be ef                     (4 octets)
  ;;   common_mac = a0 a1 .. af                      (16 octets)
  ;; Expected SecuredPayload (no CDR header; spike §2.5 "NO CDR header" table):
  ;;   SecureDataHeader(20) || ct_len(uint32 BE=4)=00 00 00 04 || ciphertext(4)
  ;;     || common_mac(16) || rsm_count(uint32 BE=0)=00 00 00 00     => 48 octets total.
  (let* ((kind       (%hex-octets "00000004"))
         (key-id     (%hex-octets "aabbccdd"))
         (session-id (%hex-octets "01000000"))
         (iv-suffix  (%hex-octets "1122334455667788"))
         (ciphertext (%hex-octets "deadbeef"))
         (tag        (%hex-octets "a0a1a2a3a4a5a6a7a8a9aaabacadaeaf"))
         (expected   (%hex-octets
                      (concatenate 'string
                       "00000004" "aabbccdd" "01000000" "1122334455667788" ; SecureDataHeader(20)
                       "00000004"                                          ; crypto_content.length=4 BE
                       "deadbeef"                                          ; ciphertext(4)
                       "a0a1a2a3a4a5a6a7a8a9aaabacadaeaf"                  ; common_mac(16)
                       "00000000")))                                       ; rsm_count=0 BE
         (got (dds.security:serialize-secured-payload kind key-id session-id iv-suffix ciphertext tag)))
    (%check :secured-payload-len (= (length got) 48)
            (format nil "SecuredPayload must be 48 octets; got ~d" (length got)))
    (%check :secured-payload-byte-exact
            (equalp got expected)
            (format nil "SecuredPayload byte mismatch;~% got ~{~2,'0x~^ ~}" (coerce got 'list)))

    ;; (b) parse round-trips the 6 fields back, byte-identical.
    (multiple-value-bind (p-kind p-key-id p-sid p-iv p-ct p-tag)
        (dds.security:parse-secured-payload got)
      (%check :parse-kind   (equalp p-kind kind)             "parse: transformation_kind round-trip")
      (%check :parse-key-id (equalp p-key-id key-id)         "parse: transformation_key_id round-trip")
      (%check :parse-sid    (equalp p-sid session-id)        "parse: session_id round-trip")
      (%check :parse-iv     (equalp p-iv iv-suffix)          "parse: init_vector_suffix round-trip")
      (%check :parse-ct     (equalp p-ct ciphertext)         "parse: ciphertext round-trip")
      (%check :parse-tag    (equalp p-tag tag)               "parse: common_mac round-trip"))

    ;; (c) fail-closed: truncated inputs (< 44-octet minimum) must return a malformed STATUS (ADR 0064), never OOB-read.
    (dolist (short-len '(0 1 19 20 24 43))
      (let ((short (make-array short-len :element-type '(unsigned-byte 8) :initial-element #x00)))
        (%check :parse-truncated
                (handler-case (if (nth-value 6 (dds.security:parse-secured-payload short)) t nil)
                  (error () nil))   ; a raw error would be a bug
                (format nil "parse truncated (len=~d) must return a malformed status (7th value)" short-len))))
    ;; (c) fail-closed: a crypto_content.length that overflows the buffer must return a status.
    (let ((over (copy-seq got)))
      ;; SecureDataHeader is 20 bytes; ct_len uint32 BE lives at offset 20. Inflate it to 0xffffffff (endian-invariant).
      (setf (aref over 20) #xff (aref over 21) #xff (aref over 22) #xff (aref over 23) #xff)
      (%check :parse-overdeclared
              (handler-case (if (nth-value 6 (dds.security:parse-secured-payload over)) t nil)
                (error () nil))
              "parse with over-declared crypto_content.length must return a status (no OOB read)")))

  ;; (d) HMAC-SHA256 KAT — RFC 4231 §4.3 Test Case 2 (AUTHENTIC published vector).
  ;;   Key  = "Jefe"                              = 4a656665                      (4 octets)
  ;;   Data = "what do ya want for nothing?"      = 7768617420646f...6e673f       (28 octets)
  ;;   HMAC-SHA-256 = 5bdcc146bf60754e6a042426089575c75a003f089d2739839dec58b964ec3843
  ;; Source: RFC 4231 (Dec 2005) §4.3.
  (let* ((key      (%hex-octets "4a656665"))
         (data     (%hex-octets "7768617420646f2079612077616e7420666f72206e6f7468696e673f"))
         (mac      (dds.dare:hmac-sha256 key data))
         (expected (%hex-octets "5bdcc146bf60754e6a042426089575c75a003f089d2739839dec58b964ec3843")))
    (%check :hmac-sha256-rfc4231-tc2-len (= (length mac) 32)
            "HMAC-SHA256 output must be 32 bytes")
    (%check :hmac-sha256-rfc4231-tc2
            (equalp mac expected)
            (format nil "HMAC-SHA256 RFC 4231 TC2 mismatch; got ~{~2,'0x~^ ~}" (coerce mac 'list))))

  ;; (e) derive-session-key composition (§9.5.3.3.4.2): the KDF must splice
  ;;   'SessionKey' || master_salt || session_id (NO counter — Fast-DDS/Cyclone-aligned, T-RECONCILE) and
  ;;   HMAC-SHA256 it under master_sender_key.
  ;;   Checked against an INDEPENDENTLY assembled HMAC input (verifies splice order + the primitive wiring;
  ;;   the primitive itself is KAT'd against RFC 4231 in (d)).
  (let* ((master-key  (%hex-octets
                       (concatenate 'string "000102030405060708090a0b0c0d0e0f"
                                            "101112131415161718191a1b1c1d1e1f")))
         (master-salt (%hex-octets
                       (concatenate 'string "404142434445464748494a4b4c4d4e4f"
                                            "505152535455565758595a5b5c5d5e5f")))
         (session-id  (%hex-octets "01000000"))
         (sk          (dds.security:derive-session-key master-key master-salt session-id))
         ;; independent reference: "SessionKey"(53657373696f6e4b6579) || salt || session_id (NO counter)
         (kdf-data    (%hex-octets
                       (concatenate 'string
                        "53657373696f6e4b6579"                  ; "SessionKey"
                        "404142434445464748494a4b4c4d4e4f"       ; master_salt[0:16]
                        "505152535455565758595a5b5c5d5e5f"       ; master_salt[16:32]
                        "01000000")))                            ; session_id (4 bytes, spliced verbatim)
         (ref         (dds.dare:hmac-sha256 master-key kdf-data)))
    (%check :derive-session-key-len (= (length sk) 32)
            "derive-session-key output must be 32 bytes (AES-256 session key)")
    (%check :derive-session-key-composition
            (equalp sk ref)
            (format nil "derive-session-key composition mismatch; got ~{~2,'0x~^ ~}" (coerce sk 'list))))

  ;; (f) derive-session-key fail-closed: wrong-size master-key signals secured-payload-malformed.
  (%check :derive-session-key-bad-key-len
          (handler-case
              (progn (dds.security:derive-session-key
                      (make-array 16 :element-type '(unsigned-byte 8) :initial-element 0)
                      (make-array 32 :element-type '(unsigned-byte 8) :initial-element 0)
                      (make-array 4  :element-type '(unsigned-byte 8) :initial-element 0))
                     nil)
            (dds.security:secured-payload-malformed () t))
          "derive-session-key with 16-byte master-key must signal secured-payload-malformed (fail-closed)")

  t)

(defun* run-security-secured-payload-pad-corpus-test ()
    (function () t)
  "DDS-Security §9.5.3.3.3 SecureDataTag 4-byte alignment — the NON-4-aligned-ciphertext SecuredPayload
   byte-exact golden (WP-DDS-SECURITY-FASTDDS-INTEROP Slice-5 cross-vendor reconcile; ADR 0037 + the
   ADR 0031 SecureDataTag-align addendum). Fast DDS serialize_SecureDataTag 4-aligns the
   receiver_specific_macs_count to the SecuredPayload start, so the pad after common_mac = (-N) mod 4 octets;
   omitting it makes a conformant peer's decode_serialized_payload mis-read the tag length. This regression-proofs
   the pad PLACEMENT (the exact zero octets between common_mac and rsm_count) OFFLINE — no live peer and no
   OpenSSL, because serialize/parse-secured-payload are pure byte layout. Deterministic: kind/key_id from
   make-test-key-material, fixed session_id/iv/ct/tag.
   (a) N=18 (pad=2): byte-exact vs the reference vector incl. the 2 zero pad octets, then round-trip.
   (b) N in {17,18,19}: the pad = (-N) mod 4 is all-zero, rsm_count lands 4-aligned, and it round-trips.
   (c) N=4 (already 4-aligned): pad=0, total 48 — byte-identical to the shipped corpus (the no-pad guard).
   Both SBCL and Clasp must pass identically."
  ;; (a) N=18 ciphertext (NOT a multiple of 4) -> pad = (-18) mod 4 = 2 zero octets between common_mac and rsm_count.
  (let* ((km         (dds.security:make-test-key-material))
         (kind       (dds.security:key-material-transformation-kind km)) ; #(0 0 0 4) AES256-GCM
         (key-id     (dds.security:key-material-sender-key-id km))       ; #(de ad be ef)
         (session-id (%hex-octets "01000000"))
         (iv-suffix  (%hex-octets "1122334455667788"))
         (ct18       (%hex-octets "000102030405060708090a0b0c0d0e0f1011")) ; 18 octets
         (tag        (%hex-octets "a0a1a2a3a4a5a6a7a8a9aaabacadaeaf"))
         (expected   (%hex-octets
                      (concatenate 'string
                       "00000004" "deadbeef" "01000000" "1122334455667788" ; SecureDataHeader(20)
                       "00000012"                                          ; crypto_content.length=18 BE
                       "000102030405060708090a0b0c0d0e0f1011"              ; ciphertext(18)
                       "a0a1a2a3a4a5a6a7a8a9aaabacadaeaf"                  ; common_mac(16)
                       "0000"                                              ; SecureDataTag 4-align pad = 2 zero octets
                       "00000000")))                                       ; rsm_count=0 BE, 4-aligned
         (got        (dds.security:serialize-secured-payload kind key-id session-id iv-suffix ct18 tag)))
    (%check :pad-secured-payload-len (= (length got) 64)
            (format nil "non-4-aligned (N=18) SecuredPayload must be 64 octets; got ~d" (length got)))
    (%check :pad-secured-payload-byte-exact (equalp got expected)
            (format nil "padded SecuredPayload byte mismatch;~% got ~{~2,'0x~^ ~}" (coerce got 'list)))
    ;; the pad sits at offsets 58,59 (immediately after the 16-octet common_mac) and MUST be zero.
    (%check :pad-secured-payload-pad-zero (and (zerop (aref got 58)) (zerop (aref got 59)))
            "the SecureDataTag 4-align pad octets (58,59) must be zero")
    (multiple-value-bind (p-kind p-key-id p-sid p-iv p-ct p-tag)
        (dds.security:parse-secured-payload got)
      (declare (ignore p-kind p-key-id p-sid p-iv))
      (%check :pad-secured-payload-rt-ct  (equalp p-ct ct18) "padded SecuredPayload: ciphertext round-trip past the pad")
      (%check :pad-secured-payload-rt-tag (equalp p-tag tag) "padded SecuredPayload: common_mac round-trip past the pad")))
  ;; (b) every non-zero residue class: pad = (-N) mod 4 octets, all-zero, rsm_count 4-aligned, round-trips.
  (let ((kind (%hex-octets "00000004")) (key-id (%hex-octets "deadbeef"))
        (session-id (%hex-octets "01000000")) (iv-suffix (%hex-octets "1122334455667788"))
        (tag (%hex-octets "a0a1a2a3a4a5a6a7a8a9aaabacadaeaf")))
    (dolist (n '(17 18 19))
      (let* ((ct      (let ((a (make-array n :element-type '(unsigned-byte 8))))
                        (dotimes (i n) (setf (aref a i) (logand i #xff))) a))
             (pad     (mod (- n) 4))
             (pad-off (+ 20 4 n 16))                                    ; header+ct_len+ct+common_mac
             (blob    (dds.security:serialize-secured-payload kind key-id session-id iv-suffix ct tag)))
        (%check :pad-residue-len (= (length blob) (+ 20 4 n 16 pad 4))
                (format nil "N=~d SecuredPayload length must be ~d; got ~d" n (+ 20 4 n 16 pad 4) (length blob)))
        (%check :pad-residue-zero (every #'zerop (subseq blob pad-off (+ pad-off pad)))
                (format nil "N=~d the ~d pad octet(s) after common_mac must be zero" n pad))
        (%check :pad-residue-rsm-aligned (zerop (mod (+ pad-off pad) 4))
                (format nil "N=~d receiver_specific_macs_count must start 4-aligned (offset ~d)" n (+ pad-off pad)))
        (multiple-value-bind (k ki s iv c tg) (dds.security:parse-secured-payload blob)
          (declare (ignore k ki s iv))
          (%check :pad-residue-rt (and (equalp c ct) (equalp tg tag))
                  (format nil "N=~d padded SecuredPayload must round-trip past the pad" n))))))
  ;; (c) no-pad guard: a 4-aligned ciphertext (N=4) emits NO pad -> 48 octets, byte-identical to the shipped corpus.
  (let* ((kind (%hex-octets "00000004")) (key-id (%hex-octets "deadbeef"))
         (session-id (%hex-octets "01000000")) (iv-suffix (%hex-octets "1122334455667788"))
         (ct (%hex-octets "deadbeef")) (tag (%hex-octets "a0a1a2a3a4a5a6a7a8a9aaabacadaeaf"))
         (blob (dds.security:serialize-secured-payload kind key-id session-id iv-suffix ct tag)))
    (%check :pad-aligned-no-pad (= (length blob) 48)
            (format nil "a 4-aligned (N=4) SecuredPayload must stay 48 octets (pad=0); got ~d" (length blob))))
  t)

(defun* run-security-payload-roundtrip-test ()
    (function () t)
  "DDS-Security §9.5.3.3 encode/decode-serialized-payload: round-trip, tamper-fails-closed,
   nonce-distinct, and short/garbage-blob bounds check.
   (a) Round-trip: decode(km, encode(km, PT)) = PT byte-exact.
   (b) Tamper ciphertext: flip one CT byte -> decode returns NIL (AES-GCM auth failure, fail-closed).
   (c) Tamper tag: flip one tag byte -> decode returns NIL (AES-GCM auth failure, fail-closed).
   (d) Tamper transformation_kind (byte 3) -> NIL (find_key kind mismatch; empty-AAD, §9.5.3.3.4.5).
   (e) Garbage blob: short or all-zero blobs -> decode returns NIL (not a crash).
   (f) Nonce-distinct: two consecutive encodes of the same plaintext produce DIFFERENT iv_suffix
       values in the SecureDataHeader — proving the monotonic counter advances (nonce uniqueness).
   (g) Tamper transformation_key_id (a byte in 4..7) -> NIL (find_key key_id mismatch — the empty-AAD
       header-integrity gate for key_id, the same mechanism as (d)'s kind).
   (h) Tamper session_id (a byte in 8..11) -> NIL: session_id derives BOTH the session key (§9.5.3.3.4.2)
       AND the nonce (§9.5.3.3.4.3), so the GCM tag fails to verify (fail-closed).
   (i) Tamper init_vector_suffix (a byte in 12..19) -> NIL: it forms the GCM nonce with session_id, so a
       flip changes the nonce and the GCM tag fails to verify (fail-closed).
   (g)/(h)/(i) close the empty-AAD directed-tamper coverage gap (T10 review fix-3): with AAD now EMPTY, each
   SecureDataHeader field's integrity binding (find_key for kind/key_id; the KDF+nonce for session_id/iv_suffix)
   is exercised by a directed byte flip, not left analytical.
   Requires OpenSSL >= 3.5; skips only if truly absent. Both SBCL and Clasp must pass identically."
  (multiple-value-bind (%dare-ok %dare-reason) (dds.dare:dare-available-p)
    (unless %dare-ok
      (format t "~&  [security-payload-roundtrip] SKIP — OpenSSL >= 3.5 not available: ~a~%"
              %dare-reason)
      (return-from run-security-payload-roundtrip-test t)))

  (let* ((km (dds.security:make-test-key-material))
         (pt (make-array 16 :element-type '(unsigned-byte 8)
                            :initial-contents '(#x00 #x01 #x02 #x03 #x04 #x05 #x06 #x07
                                                #x08 #x09 #x0a #x0b #x0c #x0d #x0e #x0f))))

    ;; (a) round-trip: decode(km, encode(km, pt)) must equal pt byte-exact.
    (let* ((blob     (dds.security:encode-serialized-payload km pt))
           (recovered (dds.security:decode-serialized-payload km blob)))
      (%check :roundtrip-non-nil recovered
              "decode of encode must return non-NIL for a valid SecuredPayload")
      (%check :roundtrip-byte-exact
              (equalp recovered pt)
              (format nil "roundtrip mismatch; got ~{~2,'0x~^ ~}" (coerce recovered 'list))))

    ;; (b) tamper ciphertext: the ciphertext starts at byte 24 (after 20-byte header + 4-byte ct_len).
    ;;     Flip one ciphertext byte -> GCM auth must fail -> NIL.
    (let* ((blob (dds.security:encode-serialized-payload km pt))
           (bad  (copy-seq blob)))
      (setf (aref bad 24) (logxor (aref bad 24) #x01))
      (%check :tamper-ct-nil
              (null (dds.security:decode-serialized-payload km bad))
              "1-byte CT tamper must return NIL (AES-GCM fail-closed)"))

    ;; (c) tamper tag: the 16-byte common_mac follows the ciphertext.
    ;;     blob = header(20) + ct_len(4) + ct(16) + tag(16) + rsm_count(4) = 60 bytes.
    ;;     tag starts at offset 40 (20+4+16).
    (let* ((blob (dds.security:encode-serialized-payload km pt))
           (bad  (copy-seq blob))
           (tag-offset (+ 20 4 (length pt)))) ; header(20) + ct_len(4) + ct(pt-len) = start of tag
      (setf (aref bad tag-offset) (logxor (aref bad tag-offset) #x80))
      (%check :tamper-tag-nil
              (null (dds.security:decode-serialized-payload km bad))
              "1-byte tag tamper must return NIL (AES-GCM fail-closed)"))

    ;; (d) tamper header transformation_kind (bytes 0..3): the AAD is now EMPTY (Fast-DDS-faithful,
    ;;   T10-INTEROP-RECONCILE), so kind/key_id integrity is the decode find_key check — the WIRE kind/key_id
    ;;   must match the KM (Fast DDS AESGCMGMAC_Transform::find_key) — and a kind bit-flip is rejected there.
    (let* ((blob (dds.security:encode-serialized-payload km pt))
           (bad  (copy-seq blob)))
      (setf (aref bad 3) (logxor (aref bad 3) #x01))   ; flip bit in transformation_kind
      (%check :tamper-header-nil
              (null (dds.security:decode-serialized-payload km bad))
              "1-byte transformation_kind tamper must return NIL (find_key kind mismatch; §9.5.3.3.4.5)"))

    ;; (e) garbage / short blobs -> NIL (not a crash, not a signal to the caller).
    (dolist (garbage (list
                      (make-array 0  :element-type '(unsigned-byte 8))
                      (make-array 1  :element-type '(unsigned-byte 8) :initial-element 0)
                      (make-array 43 :element-type '(unsigned-byte 8) :initial-element #xaa)
                      (make-array 60 :element-type '(unsigned-byte 8) :initial-element 0)))
      (%check :garbage-nil
              (null (dds.security:decode-serialized-payload km garbage))
              (format nil "garbage blob (len=~d) must return NIL" (length garbage))))

    ;; (f) nonce-distinct: two consecutive encodes -> parse -> iv_suffix values must differ.
    ;;     iv_suffix lives at bytes 12..19 of the SecuredPayload (offset 12 in the header).
    (let* ((blob1 (dds.security:encode-serialized-payload km pt))
           (blob2 (dds.security:encode-serialized-payload km pt)))
      (multiple-value-bind (_ _1 _2 iv1 _3 _4) (dds.security:parse-secured-payload blob1)
        (declare (ignore _ _1 _2 _3 _4))
        (multiple-value-bind (_ _1 _2 iv2 _3 _4) (dds.security:parse-secured-payload blob2)
          (declare (ignore _ _1 _2 _3 _4))
          (%check :nonce-distinct
                  (not (equalp iv1 iv2))
                  (format nil "two consecutive encodes must produce different iv_suffix values; both got ~{~2,'0x~^ ~}"
                          (coerce iv1 'list))))))

    ;; (g) tamper transformation_key_id (bytes 4..7): with empty AAD, key_id integrity is the decode find_key
    ;;     check (the WIRE key_id must equal the KM's), so a key_id bit-flip -> NIL (same gate as kind, byte 4).
    (let* ((blob (dds.security:encode-serialized-payload km pt))
           (bad  (copy-seq blob)))
      (setf (aref bad 4) (logxor (aref bad 4) #x01))   ; flip bit in transformation_key_id
      (%check :tamper-key-id-nil
              (null (dds.security:decode-serialized-payload km bad))
              "1-byte transformation_key_id tamper must return NIL (find_key key_id mismatch; §9.5.3.3.4.5)"))

    ;; (h) tamper session_id (bytes 8..11): session_id derives the session key AND the GCM nonce, so a flip
    ;;     changes both -> AES-GCM auth fail -> NIL (fail-closed; not a find_key reject).
    (let* ((blob (dds.security:encode-serialized-payload km pt))
           (bad  (copy-seq blob)))
      (setf (aref bad 8) (logxor (aref bad 8) #x01))   ; flip bit in session_id
      (%check :tamper-session-id-nil
              (null (dds.security:decode-serialized-payload km bad))
              "1-byte session_id tamper must return NIL (session-key + nonce change -> GCM fail-closed)"))

    ;; (i) tamper init_vector_suffix (bytes 12..19): it forms the GCM nonce with session_id, so a flip changes
    ;;     the nonce -> AES-GCM auth fail -> NIL (fail-closed).
    (let* ((blob (dds.security:encode-serialized-payload km pt))
           (bad  (copy-seq blob)))
      (setf (aref bad 12) (logxor (aref bad 12) #x01))   ; flip bit in init_vector_suffix
      (%check :tamper-iv-suffix-nil
              (null (dds.security:decode-serialized-payload km bad))
              "1-byte init_vector_suffix tamper must return NIL (nonce change -> GCM fail-closed)")))

  t)

(defun* run-security-payload-into-test ()
    (function () t)
  "DDS-Security §9.5.3.3 zero-alloc into-buffer codec (encode/decode-serialized-payload-into):
   (a) encode-serialized-payload-into is pinned BYTE-FOR-BYTE to the INDEPENDENT serialize-secured-payload
       oracle — the expected SecuredPayload is rebuilt via derive-session-key + the unchanged allocating
       aes-256-gcm-seal (over session_id=all-zeros ‖ counter-0 iv_suffix=all-zeros, EMPTY AAD) +
       serialize-secured-payload (all crypto.lisp, untouched by the into-core), NOT via the allocating
       encode-serialized-payload wrapper (which now delegates to the same core — a core-vs-core tautology that
       would round-trip a symmetric divergence clean). The 19-octet plaintext is NOT 4-aligned (pad=1), so this
       also pins the §9.5.3.3.3 pad placement / tag offset / big-endian length the corpora alone would miss.
   (b) decode-serialized-payload-into round-trips the plaintext byte-exact through a static PT-OUT buffer.
   (c) decode-serialized-payload-into on an over-short input fails closed (-> NIL, no read/crash).
   All static buffers are freed under unwind-protect so a %check failure never leaks them.
   Requires OpenSSL >= 3.5; skips only if truly absent. Both SBCL and Clasp must pass identically."
  (multiple-value-bind (%dare-ok %dare-reason) (dds.dare:dare-available-p)
    (unless %dare-ok
      (format t "~&  [security-payload-into] SKIP — OpenSSL >= 3.5 not available: ~a~%"
              %dare-reason)
      (return-from run-security-payload-into-test t)))
  (let* ((km     (dds.security:make-test-key-material))      ; CORE km under test, iv-counter 0
         (km-or  (dds.security:make-test-key-material))      ; ORACLE km, same fixed master key/salt, counter 0
         (pt     (map '(simple-array (unsigned-byte 8) (*)) #'char-code "zero-alloc payload!"))
         (out    (dds.core.buffer:make-octet-buffer (+ 64 (length pt))))
         (pt-out (dds.core.buffer:make-octet-buffer 256)))
    (unwind-protect
         (let* ((len  (dds.security:encode-serialized-payload-into out km pt))   ; CORE under test, counter 0
                (core (subseq (dds.core.buffer:octet-buffer-vec out) 0 len))
                ;; INDEPENDENT oracle: session_id=all-zeros (+fixed-session-id+, not exported -> reproduced
                ;; inline), iv_suffix=counter-0 BE=all-zeros (fresh km); session key + seal + framing all via
                ;; the unchanged crypto.lisp primitives, never the encode wrapper.
                (sid   (make-array 4  :element-type '(unsigned-byte 8) :initial-element 0))
                (iv    (make-array 8  :element-type '(unsigned-byte 8) :initial-element 0))
                (aad   (make-array 0  :element-type '(unsigned-byte 8)))
                (skey  (dds.security:derive-session-key
                        (dds.security:key-material-master-sender-key km-or)
                        (dds.security:key-material-master-salt km-or) sid))
                (nonce (let ((nn (make-array 12 :element-type '(unsigned-byte 8))))
                         (replace nn sid :start1 0 :end1 4) (replace nn iv :start1 4 :end1 12) nn)))
           (multiple-value-bind (ct tag) (dds.dare:aes-256-gcm-seal skey nonce aad pt)
             (let ((oracle (dds.security:serialize-secured-payload
                            (dds.security:key-material-transformation-kind km-or)
                            (dds.security:key-material-sender-key-id km-or)
                            sid iv ct tag)))
               (%check :payload-into-oracle-pinned
                       (equalp core oracle)
                       (format nil "encode-into must equal the serialize-secured-payload oracle byte-for-byte;~% core ~{~2,'0x~^ ~}"
                               (coerce core 'list)))))
           ;; round-trip: decode-into recovers the plaintext byte-exact through a static PT-OUT buffer
           (let ((plen (dds.security:decode-serialized-payload-into pt-out km core)))
             (%check :payload-into-decode
                     (and plen (equalp (subseq (dds.core.buffer:octet-buffer-vec pt-out) 0 plen) pt))
                     "decode-into must round-trip the plaintext"))
           ;; fail-closed: a too-short input -> NIL (no read, no crash)
           (%check :payload-into-failclosed
                   (null (dds.security:decode-serialized-payload-into
                          pt-out km (make-array 8 :element-type '(unsigned-byte 8))))
                   "decode-into on a too-short input must return NIL (fail-closed)"))
      (dds.pal:free-static (dds.core.buffer:octet-buffer-vec out))
      (dds.pal:free-static (dds.core.buffer:octet-buffer-vec pt-out))))
  t)

(defun* run-security-gmac-payload-test ()
    (function () t)
  "DDS-Security §9.5.3.3.4.3 data_protection=SIGN payload-tier GMAC (WP-SECURITY-DATA-SIGN-PAYLOAD): a GMAC km
   (make-test-key-material :kind :sign, AES256-GMAC {0,0,0,3}) AUTHENTICATES the VISIBLE serialized payload without
   encrypting it. Asserts, on BOTH impls (Clasp first):
   (a) round-trip: decode(km, encode(km, PT)) = PT byte-exact.
   (b) header kind = AES256-GMAC {0,0,0,3} (byte 3 = 3) — the wire signal a peer's find_key dispatches on.
   (c) VISIBLE: the plaintext appears VERBATIM at offset 20 in the SecuredPayload (not hidden as ciphertext).
   (d) layout: total = 40 + N for a 4-aligned N (NO crypto_content.length prefix; the SerializedPayload is already
       4-aligned so the pad is empty — §9.5.3.3.4.3, Fast DDS serialize_SecureDataBody !do_encryption), vs the
       ENCRYPT tier's 44 + N + pad.
   (k) NON-4-aligned N (WP-SECURITY-DATA-SIGN-LIVE-CONNEXT / Slice-5d): the SerializedPayload is 4-aligned INSIDE the
       GMAC'd body, so total = 40 + align4(N). For N in {34 (the live HelloWorld payload), 33, 35} (pad widths 2/3/1):
       (k.1) length = 40 + align4(N), NOT 40+N; (k.2) plaintext visible verbatim at 20; (k.3) decode returns the
       align4(N) span whose LEADING N octets equal the input (the pad is transparent to the payload — self-delimiting
       CDR); (k.4) the trailing pad octets are ZERO (deterministic wire); (k.5) flipping a pad octet -> decode NIL
       (the pad rides INSIDE the GMAC AAD, authenticated, not ignored). Pins the RTPS §8.3.3.2.3 4-alignment the live
       Connext interop requires — a broken (mod (- n) 4), a non-zero pad, or a GMAC extent off-by-pad now fails `make test`.
   (e) BYTE-EXACT golden: the SecuredPayload equals an INDEPENDENT oracle — header ‖ PT verbatim ‖ GMAC(PT) ‖
       rsm_count=0, the GMAC via the unchanged allocating aes-256-gcm-seal (AAD=PT, empty plaintext) over
       derive-session-key(session_id=0) ‖ counter-0 iv_suffix=0, assembled by hand (never the encode wrapper).
   (f) tamper the VISIBLE payload (offset 20) -> decode NIL (fail-closed; NO false-ACCEPT of a mutated payload).
   (g) tamper the common_mac -> decode NIL (GMAC mismatch, fail-closed).
   (h) tamper transformation_kind -> decode NIL (find_key gate).
   (i) the zero-alloc -into core round-trips a GMAC payload byte-exact and conses no more than the ENCRYPT -into
       core (both dominated by the shared EVP FFI residual; SBCL-exact via dds.pal:bytes-consed, Clasp reports 0).
   (j) the ENCRYPT km is UNCHANGED (byte-3 kind = 4, has the length prefix) — the GMAC branch is additive.
   Requires OpenSSL >= 3.5; skips only if truly absent."
  (multiple-value-bind (%dare-ok %dare-reason) (dds.dare:dare-available-p)
    (unless %dare-ok
      (format t "~&  [security-gmac-payload] SKIP — OpenSSL >= 3.5 not available: ~a~%"
              %dare-reason)
      (return-from run-security-gmac-payload-test t)))
  (let* ((km   (dds.security:make-test-key-material :kind :sign))   ; GMAC km under test, iv-counter 0
         (pt   (make-array 16 :element-type '(unsigned-byte 8)
                              :initial-contents '(#xca #xfe #xba #xbe #x01 #x02 #x03 #x04
                                                  #x05 #x06 #x07 #x08 #x09 #x0a #x0b #x0c)))
         (n    (length pt)))
    ;; (a) round-trip
    (let* ((blob (dds.security:encode-serialized-payload km pt))
           (rec  (dds.security:decode-serialized-payload km blob)))
      (%check :gmac-roundtrip (and rec (equalp rec pt)) "GMAC decode(encode(PT)) must equal PT byte-exact")
      ;; (b) header kind = GMAC {0,0,0,3}
      (%check :gmac-kind (and (zerop (aref blob 0)) (zerop (aref blob 1)) (zerop (aref blob 2)) (= 3 (aref blob 3)))
              "SecuredPayload transformation_kind must be AES256-GMAC {0,0,0,3}")
      ;; (c) VISIBLE plaintext verbatim at offset 20
      (%check :gmac-visible (equalp (subseq blob 20 (+ 20 n)) pt)
              "the plaintext must be VISIBLE verbatim at offset 20 (GMAC authenticates but does not encrypt)")
      ;; (d) layout: total = 40 + N (no length prefix, no pad for the 4-aligned N above)
      (%check :gmac-layout (= (length blob) (+ 40 n))
              (format nil "GMAC SecuredPayload length must be 40+N=~d (no ct_len prefix, no pad); got ~d" (+ 40 n) (length blob))))
    ;; (k) NON-4-aligned N (WP-SECURITY-DATA-SIGN-LIVE-CONNEXT / Slice-5d, §8.3.3.2.3): the SerializedPayload is
    ;;     4-aligned INSIDE the GMAC'd body -> total = 40 + align4(N), so the enclosing DATA submessage stays
    ;;     4-aligned (a non-4-aligned inner submessage makes a conformant peer's secure-RTPS walk reject the
    ;;     message — the bug the ENCRYPT/data=NONE tiers masked). N=34 is the live HelloWorld payload that
    ;;     surfaced it; 33 (pad 3) + 35 (pad 1) exercise the other two non-zero pad widths.
    (dolist (n2 '(34 33 35))
      (let* ((ptn  (let ((a (make-array n2 :element-type '(unsigned-byte 8))))
                     (dotimes (i n2 a) (setf (aref a i) (logand (+ i 1) #xff)))))
             (body (* 4 (ceiling n2 4)))                          ; align4(N)
             (padw (- body n2))                                   ; ((-N) mod 4), = 2/3/1 here
             (blob (dds.security:encode-serialized-payload km ptn))
             (rec  (dds.security:decode-serialized-payload km blob)))
        ;; (k.1) padded layout: total = 40 + align4(N), NOT 40+N
        (%check :gmac-nonaligned-layout (= (length blob) (+ 40 body))
                (format nil "non-aligned GMAC length must be 40+align4(~d)=~d (padded), not 40+N=~d; got ~d"
                        n2 (+ 40 body) (+ 40 n2) (length blob)))
        ;; (k.2) VISIBLE plaintext still verbatim at offset 20 (the pad follows it, does not displace it)
        (%check :gmac-nonaligned-visible (equalp (subseq blob 20 (+ 20 n2)) ptn)
                "non-aligned: the plaintext must be VISIBLE verbatim at offset 20")
        ;; (k.3) round-trip: decode returns the align4(N) span whose LEADING N octets equal the input (pad transparent)
        (%check :gmac-nonaligned-roundtrip
                (and rec (= (length rec) body) (equalp (subseq rec 0 n2) ptn))
                (format nil "non-aligned decode must return the align4(~d)=~d span with leading ~d octets = PT" n2 body n2))
        ;; (k.4) the pad octets [20+N, 20+align4(N)) are ZERO (deterministic, so the wire is reproducible)
        (%check :gmac-nonaligned-pad-zero (every #'zerop (subseq blob (+ 20 n2) (+ 20 body)))
                (format nil "non-aligned: the ~d pad octet(s) at [~d,~d) must be zero" padw (+ 20 n2) (+ 20 body)))
        ;; (k.5) flip a PAD byte -> decode NIL: proves the pad rides INSIDE the GMAC AAD (authenticated), not ignored
        (let ((bad (copy-seq blob)))
          (setf (aref bad (+ 20 n2)) (logxor (aref bad (+ 20 n2)) #x01))   ; first pad octet @ 20+N
          (%check :gmac-nonaligned-pad-authenticated (null (dds.security:decode-serialized-payload km bad))
                  "flipping a pad octet must fail the GMAC -> NIL (the pad is inside the authenticated body)"))))
    ;; (e) BYTE-EXACT golden — independent oracle (fresh kms so both use counter-0 iv_suffix = all-zeros)
    (let* ((km-t  (dds.security:make-test-key-material :kind :sign))   ; encode under test, counter 0
           (km-or (dds.security:make-test-key-material :kind :sign))   ; oracle key derivation only, counter 0
           (blob  (dds.security:encode-serialized-payload km-t pt))
           (sid   (make-array 4 :element-type '(unsigned-byte 8) :initial-element 0))
           (iv    (make-array 8 :element-type '(unsigned-byte 8) :initial-element 0))
           (empty (make-array 0 :element-type '(unsigned-byte 8)))
           (skey  (dds.security:derive-session-key
                   (dds.security:key-material-master-sender-key km-or)
                   (dds.security:key-material-master-salt km-or) sid))
           (nonce (let ((nn (make-array 12 :element-type '(unsigned-byte 8))))
                    (replace nn sid :start1 0 :end1 4) (replace nn iv :start1 4 :end1 12) nn)))
      (multiple-value-bind (ct tag) (dds.dare:aes-256-gcm-seal skey nonce pt empty)   ; AAD=PT, empty plaintext -> GMAC tag
        (declare (ignore ct))
        (let ((oracle (concatenate '(simple-array (unsigned-byte 8) (*))
                                   (dds.security:key-material-transformation-kind km-or)   ; kind (GMAC)
                                   (dds.security:key-material-sender-key-id km-or)          ; key_id
                                   sid iv pt tag
                                   (make-array 4 :element-type '(unsigned-byte 8) :initial-element 0))))  ; rsm_count=0
          (%check :gmac-golden (equalp blob oracle)
                  (format nil "GMAC SecuredPayload must equal the independent oracle byte-for-byte;~% blob ~{~2,'0x~^ ~}"
                          (coerce blob 'list))))))
    ;; (f) tamper the VISIBLE payload -> decode fail-closed (no false-ACCEPT)
    (let* ((blob (dds.security:encode-serialized-payload km pt)) (bad (copy-seq blob)))
      (setf (aref bad 20) (logxor (aref bad 20) #x01))
      (%check :gmac-tamper-payload (null (dds.security:decode-serialized-payload km bad))
              "a 1-byte flip of the VISIBLE payload must fail the GMAC -> NIL (no false-ACCEPT)"))
    ;; (g) tamper the common_mac -> decode fail-closed
    (let* ((blob (dds.security:encode-serialized-payload km pt)) (bad (copy-seq blob)))
      (setf (aref bad (+ 20 n)) (logxor (aref bad (+ 20 n)) #x80))   ; common_mac @ 20+N
      (%check :gmac-tamper-mac (null (dds.security:decode-serialized-payload km bad))
              "a 1-byte common_mac flip must fail the GMAC -> NIL (fail-closed)"))
    ;; (h) tamper transformation_kind -> find_key reject
    (let* ((blob (dds.security:encode-serialized-payload km pt)) (bad (copy-seq blob)))
      (setf (aref bad 3) (logxor (aref bad 3) #x01))
      (%check :gmac-tamper-kind (null (dds.security:decode-serialized-payload km bad))
              "a transformation_kind flip must return NIL (find_key gate)"))
    ;; (i) zero-alloc -into core: round-trip byte-exact + conses no more than the ENCRYPT -into core
    (let ((out    (dds.core.buffer:make-octet-buffer (+ 64 n)))
          (pt-out (dds.core.buffer:make-octet-buffer 256))
          (kg     (dds.security:make-test-key-material :kind :sign))
          (ke     (dds.security:make-test-key-material :kind :encrypt))
          (sbcl   (eq (dds.pal:pal-impl-name) :sbcl))
          (iters  1000))
      (unwind-protect
           (progn
             (let ((len (dds.security:encode-serialized-payload-into out kg pt)))
               (%check :gmac-into-len (= len (+ 40 n)) "encode-into GMAC length = 40+N")
               (let ((plen (dds.security:decode-serialized-payload-into pt-out kg
                            (subseq (dds.core.buffer:octet-buffer-vec out) 0 len))))
                 (%check :gmac-into-roundtrip
                         (and plen (equalp (subseq (dds.core.buffer:octet-buffer-vec pt-out) 0 plen) pt))
                         "decode-into must round-trip the GMAC plaintext byte-exact")))
             ;; alloc parity: GMAC per-iter conses within a small tolerance of ENCRYPT (both share the EVP FFI residual)
             (let* ((gbps (let ((b (dds.pal:bytes-consed)))
                            (dotimes (i iters) (dds.security:encode-serialized-payload-into out kg pt))
                            (/ (float (- (dds.pal:bytes-consed) b)) iters)))
                    (ebps (let ((b (dds.pal:bytes-consed)))
                            (dotimes (i iters) (dds.security:encode-serialized-payload-into out ke pt))
                            (/ (float (- (dds.pal:bytes-consed) b)) iters))))
               (%check :gmac-into-alloc-parity
                       (or (not sbcl) (<= gbps (+ ebps 8.0)))
                       (format nil "GMAC encode-into must cons no more than ENCRYPT (~,4f vs ~,4f B/op)" gbps ebps))))
        (dds.pal:free-static (dds.core.buffer:octet-buffer-vec out))
        (dds.pal:free-static (dds.core.buffer:octet-buffer-vec pt-out))))
    ;; (j) the ENCRYPT tier is UNCHANGED (byte-3 kind = 4, carries the 4-byte crypto_content.length prefix)
    (let* ((ke   (dds.security:make-test-key-material :kind :encrypt))
           (eblob (dds.security:encode-serialized-payload ke pt)))
      (%check :encrypt-unchanged
              (and (= 4 (aref eblob 3)) (= (length eblob) (+ 44 n (mod (- n) 4))))
              "the ENCRYPT tier must stay GCM {0,0,0,4} with the ct_len prefix (44+N+pad); the GMAC branch is additive")))
  t)

(defun* run-security-payload-fuzz-test ()
    (function () t)
  "Fuzz decode-serialized-payload with random/short/oversized inputs (both prod + (safety 0)).
   Invariant: for every input, decode returns NIL or the correct plaintext — never OOB, never crash,
   never a partial decode, never a signal escaping to the caller (NFR-SEC-POSTURE). Two km arms:
   the ENCRYPT (AES256-GCM) km — minimum-size boundary (< 44 bytes), over-declared ct_len, all-zero
   payloads 0..80, and fully random 60-byte payloads with a valid parse shape (invalid ciphertext);
   AND the SIGN (AES256-GMAC, data=SIGN) km — the visible-payload GMAC decode branch (§9.5.3.3.4.3),
   fed sub-minimum (< 40) blobs, all-zero 40..80 blobs, and random 60-byte blobs with a MATCHING
   kind/key_id header (so find_key passes and the GMAC verify itself must reject) → always NIL, never
   a tampered accept / OOB / unbounded alloc. Requires OpenSSL >= 3.5; skips only if truly absent.
   Both SBCL and Clasp must pass identically."
  (multiple-value-bind (%dare-ok %dare-reason) (dds.dare:dare-available-p)
    (unless %dare-ok
      (format t "~&  [security-payload-fuzz] SKIP — OpenSSL >= 3.5 not available: ~a~%"
              %dare-reason)
      (return-from run-security-payload-fuzz-test t)))

  (let* ((km    (dds.security:make-test-key-material))
         (pt-ok (make-array 8 :element-type '(unsigned-byte 8)
                              :initial-contents '(65 66 67 68 69 70 71 72)))
         (valid (dds.security:encode-serialized-payload km pt-ok))
         (fuzz-count 0))

    ;; Case A: zero-length and sub-minimum blobs (< 44 bytes) -> NIL.
    (dotimes (len 44)
      (let ((blob (make-array len :element-type '(unsigned-byte 8) :initial-element #x00)))
        (let ((r (dds.security:decode-serialized-payload km blob)))
          (%check :fuzz-short-nil (null r)
                  (format nil "fuzz short blob len=~d must return NIL" len)))
        (incf fuzz-count)))

    ;; Case B: all-zero blobs of sizes 44..80 (valid parse shape but wrong ciphertext) -> NIL.
    (loop for len from 44 to 80 do
      (let* ((blob (make-array len :element-type '(unsigned-byte 8) :initial-element #x00))
             (ct-n (- len 44))
             ;; ct_len is BIG-ENDIAN on the §9.5.3.3.4.4 wire (T-RECONCILE), so write it via a big-endian cursor.
             (cur  (dds.core.buffer:cursor (dds.core.buffer:octet-buffer-over blob) :endianness :big)))
        ;; write consistent ct_len so parse-secured-payload does not signal on inconsistency
        (dds.core.buffer:cursor-set-position cur 20)
        (dds.core.buffer:put-u32 cur ct-n)
        (let ((r (dds.security:decode-serialized-payload km blob)))
          (%check :fuzz-zero-blob-nil (null r)
                  (format nil "fuzz all-zero blob len=~d must return NIL" len)))
        (incf fuzz-count)))

    ;; Case C: 2000 random 60-byte blobs with a valid header parse shape (ct_len=16) but
    ;;         random ciphertext -> AES-GCM open must return NIL (wrong key/tag).
    ;;         We write a consistent ct_len=16 at offset 20 so parse passes; the rest is random.
    (let ((n-random 2000))
      (dotimes (_ n-random)
        (let* ((blob (make-array 60 :element-type '(unsigned-byte 8)))
               ;; ct_len + rsm_count are BIG-ENDIAN on the §9.5.3.3 wire (T-RECONCILE); write them big-endian.
               (cur  (dds.core.buffer:cursor (dds.core.buffer:octet-buffer-over blob) :endianness :big)))
          ;; fill with pseudo-random bytes (xorshift from loop counter for reproducibility)
          (dotimes (i 60) (setf (aref blob i) (random 256)))
          ;; fix ct_len=16 so parse-secured-payload accepts the blob (60 = 20+4+16+16+4)
          (dds.core.buffer:cursor-set-position cur 20)
          (dds.core.buffer:put-u32 cur 16)
          ;; fix rsm_count=0 so parse-secured-payload does not signal on count
          (dds.core.buffer:cursor-set-position cur 56)
          (dds.core.buffer:put-u32 cur 0)
          (let ((r (dds.security:decode-serialized-payload km blob)))
            ;; random ct under a fixed key cannot pass AES-GCM auth (prob 2^-128); non-NIL is a regression
            (%check :fuzz-random-nil
                    (null r)
                    (format nil "fuzz random blob must return NIL; non-NIL means GCM auth bypassed"))
            (incf fuzz-count)))))

    ;; Case D: the single valid blob still round-trips (regression guard: fuzz did not corrupt km).
    (let ((recovered (dds.security:decode-serialized-payload km valid)))
      (%check :fuzz-valid-still-works
              (and recovered (equalp recovered pt-ok))
              "valid blob must still decode correctly after fuzz run"))

    ;; --- GMAC (data=SIGN) km arm: exercise the visible-payload GMAC decode branch (§9.5.3.3.4.3) ---
    (let* ((gkm    (dds.security:make-test-key-material :kind :sign))
           (gvalid (dds.security:encode-serialized-payload gkm pt-ok))   ; pt-ok is 8 B (4-aligned) -> encode ok
           (ghdr-k (dds.security:key-material-transformation-kind gkm))  ; GMAC {0,0,0,3}
           (ghdr-i (dds.security:key-material-sender-key-id gkm)))
      ;; Case G-A: sub-minimum GMAC blobs (< 40 = header 20 + SecureDataTag 20) -> NIL.
      (dotimes (len 40)
        (let ((blob (make-array len :element-type '(unsigned-byte 8) :initial-element #x00)))
          (%check :fuzz-gmac-short-nil (null (dds.security:decode-serialized-payload gkm blob))
                  (format nil "GMAC fuzz short blob len=~d must return NIL" len))
          (incf fuzz-count)))
      ;; Case G-B: all-zero GMAC-shaped blobs 40..80 (valid frame length, zero header mismatches find_key) -> NIL.
      (loop for len from 40 to 80 do
        (let ((blob (make-array len :element-type '(unsigned-byte 8) :initial-element #x00)))
          (%check :fuzz-gmac-zero-blob-nil (null (dds.security:decode-serialized-payload gkm blob))
                  (format nil "GMAC fuzz all-zero blob len=~d must return NIL" len))
          (incf fuzz-count)))
      ;; Case G-C: 2000 random 60-byte GMAC blobs with a MATCHING kind/key_id header (find_key passes, rsm_count=0)
      ;;           so the GMAC verify ITSELF must reject the random visible-content+mac -> NIL (auth 2^-128).
      (dotimes (_ 2000)
        (let ((blob (make-array 60 :element-type '(unsigned-byte 8))))   ; 60 = 40 + N, N=20: content[20,40) mac[40,56) rsm[56,60)
          (dotimes (i 60) (setf (aref blob i) (random 256)))
          (replace blob ghdr-k :start1 0 :end1 4)                        ; kind = GMAC so find_key does not short-circuit
          (replace blob ghdr-i :start1 4 :end1 8)                        ; key_id = gkm so find_key passes -> GMAC must reject
          (setf (aref blob 56) 0 (aref blob 57) 0 (aref blob 58) 0 (aref blob 59) 0)   ; rsm_count = 0 (BE) so the count gate passes
          (%check :fuzz-gmac-random-nil (null (dds.security:decode-serialized-payload gkm blob))
                  "GMAC fuzz random blob must return NIL; non-NIL means GMAC auth bypassed")
          (incf fuzz-count)))
      ;; Case G-D: the valid GMAC blob still round-trips (regression guard: fuzz did not corrupt gkm).
      (let ((rec (dds.security:decode-serialized-payload gkm gvalid)))
        (%check :fuzz-gmac-valid-still-works (and rec (equalp rec pt-ok))
                "valid GMAC blob must still decode correctly after fuzz run")))

    (format t "~&  [security-payload-fuzz] ~d inputs exercised~%" fuzz-count))

  t)

(defun* run-security-encrypted-pubsub-test ()
    (function () t)
  "DDS-Security §9.5.3.3 Slice-1 disc-node integration: encrypted our-to-our pub/sub (ADR 0031).
   Three nodes on domain 83, topic 'SSquare' / type 'ShapeType' — RELIABLE / TRANSIENT_LOCAL:
     PUB  : crypto-transform = shared-km  (encode on publish)
     SUB  : crypto-transform = shared-km  (decode on receive -> plaintext delivered)
     PLAIN: crypto-transform = NIL        (no decode hook; receives the raw SecuredPayload ciphertext)
   Assertions:
     (a) SUB receives EXACTLY the plaintext PT (decode-serialized-payload round-tripped byte-exact).
     (b) PLAIN receives bytes that are NOT PT (the wire carried the SecuredPayload, not the plaintext).
     (c) PLAIN's received bytes begin with #x00 #x00 #x00 #x04 (AES256-GCM transformation_kind,
         DDS-Security 1.1 §9.5.3.3.1 Table 69), proving the §9.5.3.3 SecuredPayload is on the wire.
   NOTE: cross-vendor Connext-Security wire interop is DEFERRED (ADR 0031 §cross-vendor-deferral);
   the Connext Security plugins are a separate licensed add-on not installed here.
   Requires OpenSSL >= 3.5 (same gate as the lower-layer security tests above).
   Both SBCL and Clasp must pass identically (Clasp FIRST per the operating contract)."
  (multiple-value-bind (%dare-ok %dare-reason) (dds.dare:dare-available-p)
    (unless %dare-ok
      (format t "~&  [security-encrypted-pubsub] SKIP — OpenSSL >= 3.5 not available: ~a~%"
              %dare-reason)
      (return-from run-security-encrypted-pubsub-test t)))

  ;; ONE shared km instance: both pub and sub share the same iv-counter so nonces never collide.
  (let* ((shared-km (dds.security:make-test-key-material))
         (pt (make-array 8 :element-type '(unsigned-byte 8)
                           :initial-contents '(#x53 #x51 #x55 #x41 #x52 #x45 #x20 #x01))) ; "SQUARE  "
         (pub-prefix (%make-test-prefix #xE1))
         (sub-prefix (%make-test-prefix #xE2))
         (plain-prefix (%make-test-prefix #xE3))
         ;; PUB: encodes on publish; SUB: decodes on receive; PLAIN: no crypto (sees raw wire bytes)
         (pub-node (dds.disc:make-disc-node :guid-prefix pub-prefix :domain (test-domain +td-encrypted-pubsub+)
                                            :host "127.0.0.1" :port 0 :multicast nil
                                            :crypto-transform shared-km))
         (sub-node (dds.disc:make-disc-node :guid-prefix sub-prefix :domain (test-domain +td-encrypted-pubsub+)
                                            :host "127.0.0.1" :port 0 :multicast nil
                                            :crypto-transform shared-km))
         (plain-node (dds.disc:make-disc-node :guid-prefix plain-prefix :domain (test-domain +td-encrypted-pubsub+)
                                              :host "127.0.0.1" :port 0 :multicast nil)))
    (unwind-protect
         (progn
           (dds.disc:add-local-writer pub-node :topic "SSquare" :type "ShapeType"
                                     :qos (dds.qos:make-writer-qos :reliability :reliable
                                                                    :durability :transient-local))
           (dds.disc:enable-publisher pub-node :history-kind :keep-all)
           (dds.disc:start-node pub-node)
           (dds.disc:add-local-reader sub-node :topic "SSquare" :type "ShapeType"
                                     :qos (dds.qos:make-reader-qos :reliability :reliable
                                                                    :durability :transient-local))
           (dds.disc:enable-subscriber sub-node)
           (dds.disc:set-secured-loan-capable sub-node t)   ; T5b: secured receive via the LOAN registry (zero per-sample plaintext alloc); crypto already on -> eager decode-pool carve
           (dds.disc:start-node sub-node)
           (dds.disc:add-local-reader plain-node :topic "SSquare" :type "ShapeType"
                                     :qos (dds.qos:make-reader-qos :reliability :reliable
                                                                    :durability :transient-local))
           (dds.disc:enable-subscriber plain-node)
           (dds.disc:start-node plain-node)
           ;; wire up unicast peers: pub -> sub + plain; sub -> pub; plain -> pub
           (let ((pp (dds.disc:disc-node-port pub-node))
                 (sp (dds.disc:disc-node-port sub-node))
                 (qp (dds.disc:disc-node-port plain-node)))
             (setf (dds.disc:disc-node-peers pub-node)
                   (list (cons "127.0.0.1" sp) (cons "127.0.0.1" qp)))
             (setf (dds.disc:disc-node-peers sub-node)   (list (cons "127.0.0.1" pp)))
             (setf (dds.disc:disc-node-peers plain-node) (list (cons "127.0.0.1" pp))))
           ;; discover + match: pub must match BOTH sub and plain (at least 2 matched readers)
           (loop repeat 400
                 until (>= (dds.disc:disc-node-matched-count pub-node) 2)
                 do (dds.disc:announce-participant pub-node) (dds.disc:announce-endpoints pub-node)
                    (dds.disc:announce-participant sub-node) (dds.disc:announce-endpoints sub-node)
                    (dds.disc:announce-participant plain-node) (dds.disc:announce-endpoints plain-node)
                    (sleep 0.02))
           (%check :crypto-pubsub-matched
                   (>= (dds.disc:disc-node-matched-count pub-node) 2)
                   "pub must match at least 2 readers (sub-with-key + plain) before publishing")
           ;; publish the plaintext: pub encodes it before writer-write (§9.5.3.3.4.4)
           (dds.disc:publish-sample pub-node pt)
           ;; wait for BOTH sub-node and plain-node to receive the sample
           (loop repeat 300
                 until (and (plusp (dds.disc:node-sample-count sub-node))
                            (plusp (dds.disc:node-sample-count plain-node)))
                 do (dds.disc:announce-participant pub-node) (dds.disc:announce-endpoints pub-node)
                    (sleep 0.02))
           ;; (a) SUB receives the decrypted plaintext PT byte-exact (§9.5.3.3.4.5) — via the T5b LOAN read contract:
           ;; node-take-loaned returns a secured-loan-handle, the plaintext is read IN PLACE (secured-loan-bytes,
           ;; zero copy), and node-return-loan releases the pooled buffer (pool-in-use back to baseline -> no leak).
           (%check :crypto-sub-received
                   (plusp (dds.disc:node-sample-count sub-node))
                   "sub-with-key did not receive any sample")
           (multiple-value-bind (data count) (dds.disc:node-take-loaned sub-node)   ; T5d: (values reused-VEC COUNT)
             (%check :crypto-sub-loan
                     (and (plusp count) (dds.disc:secured-loan-handle-p (aref data 0)))
                     "secured loan-capable sub must deliver a SECURED-LOAN-HANDLE (not a bare plaintext vector)")
             (let* ((h (aref data 0))
                    (len (dds.disc:secured-loan-handle-len h))
                    (bytes (dds.disc:secured-loan-bytes h)))   ; read the plaintext IN PLACE over [0, len) — no copy
               (%check :crypto-sub-plaintext
                       (and (= len (length pt))
                            (loop for i below len always (= (aref bytes i) (aref pt i))))
                       (format nil "sub-with-key loan recovered ~a but expected plaintext ~{~2,'0x~^ ~}"
                               (loop for i below len collect (aref bytes i)) (coerce pt 'list)))
               (dds.disc:node-return-loan sub-node data count)   ; the read-contract obligation: return every loan taken
               (%check :crypto-sub-loan-returned
                       (and (dds.disc:disc-node-decode-pool sub-node)
                            (zerop (dds.core.arena:pool-in-use (dds.disc:disc-node-decode-pool sub-node)))
                            (null (dds.disc:secured-loan-handle-buffer h))
                            (zerop (dds.disc:node-sample-count sub-node)))
                       "after node-return-loan the pooled buffer is back (pool-in-use 0), the handle is invalidated, and the samples-store entry is gone — no leak, no dangling buffer")))
           ;; (b) PLAIN receives the raw SecuredPayload (NOT the plaintext)
           (%check :crypto-plain-received
                   (plusp (dds.disc:node-sample-count plain-node))
                   "plain-node did not receive any sample (expected ciphertext delivery)")
           (let* ((plain-key (first (dds.disc:node-sample-sns plain-node)))
                  (plain-payload (dds.disc:node-sample plain-node plain-key)))
             (%check :crypto-plain-not-plaintext
                     (and plain-payload (not (equalp plain-payload pt)))
                     "plain-node must NOT receive the plaintext (wire must carry SecuredPayload)")
             ;; (c) first 4 bytes of wire payload = AES256-GCM transformation_kind (§9.5.3.3.1 Table 69)
             (%check :crypto-wire-header
                     (and plain-payload
                          (>= (length plain-payload) 4)
                          (= (aref plain-payload 0) 0)
                          (= (aref plain-payload 1) 0)
                          (= (aref plain-payload 2) 0)
                          (= (aref plain-payload 3) 4))
                     (format nil "wire payload must begin with AES256-GCM kind #(0 0 0 4); got ~{~2,'0x~^ ~}"
                             (coerce (subseq plain-payload 0 (min 4 (length plain-payload))) 'list)))))
      (ignore-errors (dds.disc:stop-node pub-node))
      (ignore-errors (dds.disc:stop-node sub-node))
      (ignore-errors (dds.disc:stop-node plain-node))))
  t)

(defun* run-secured-decode-loan-alloc-test ()
    (function () t)
  "Test (WP-DDS-SECURITY-ZEROALLOC-AEAD T5b): the DECODE-side loan eliminates the per-sample plaintext alloc, the
   loan lifecycle is leak-free + byte-exact, and pool exhaustion is SAMPLE_REJECTED (never a GC fallback).
   Part 1 (the focused decode-path alloc check, SBCL-exact via dds.pal:bytes-consed; Clasp reports 0 -> the delta
   is not measurable and the assertion is skipped, NFR-PORT): a steady loop of decode-serialized-payload-INTO a
   pooled buffer conses far LESS per sample than the allocating decode-serialized-payload (which copies out a fresh
   plaintext) — the plaintext copy is gone (the loan path's per-sample consing does NOT scale with plaintext size;
   only the shared OpenSSL EVP FFI residue remains, a dds.dare follow-on). Part 2 (the live receive path, no
   sockets — %deliver-user-sample driven directly): one sample is received as a SECURED-LOAN-HANDLE, read in place
   byte-exact via secured-loan-bytes, and node-return-loan returns its buffer (pool-in-use back to baseline — no
   leak); then samples beyond the pool capacity are fed WITHOUT returning, so the pool exhausts and the surplus is
   rejected (decode-pool-rejects increments, node-sample-count capped) — RESOURCE_LIMITS / SAMPLE_REJECTED, never
   a GC-heap fallback. Requires OpenSSL >= 3.5; both impls must pass identically (Clasp FIRST)."
  (multiple-value-bind (%dare-ok %dare-reason) (dds.dare:dare-available-p)
    (unless %dare-ok
      (format t "~&  [secured-decode-loan-alloc] SKIP — OpenSSL >= 3.5 not available: ~a~%"
              %dare-reason)
      (return-from run-secured-decode-loan-alloc-test t)))
  ;; -- Part 1: the focused decode-path alloc proof (isolated codec + pool; no node) --
  (let* ((km (dds.security:make-test-key-material))
         (pt-size 4096)
         (pt (let ((v (make-array pt-size :element-type '(unsigned-byte 8))))
               (dotimes (i pt-size v) (setf (aref v i) (logand (* i 7) #xff)))))
         (secured (dds.security:encode-serialized-payload km pt))   ; the SecuredPayload ciphertext to decode each iter
         (element-bytes (+ pt-size 64))
         (arena (dds.core.arena:init-arena :bytes (* element-bytes 8)))
         (pool (dds.core.arena:make-buffer-pool arena element-bytes 8)))
    (unwind-protect
         (progn
           ;; byte-exact: decode-into-pool recovers the EXACT plaintext (same bytes the allocating decode delivers)
           (let* ((buf (dds.core.arena:pool-acquire pool))
                  (plen (dds.security:decode-serialized-payload-into buf km secured))
                  (bytes (dds.core.buffer:octet-buffer-vec buf)))
             (%check :loan-alloc-byte-exact
                     (and plen (= plen pt-size)
                          (loop for i below pt-size always (= (aref bytes i) (aref pt i))))
                     "decode-serialized-payload-into recovers the plaintext byte-exact into the pooled buffer")
             (dds.core.arena:pool-release pool buf))
           ;; measure: N iters of the loan decode (into pool) vs the allocating decode (fresh plaintext each call)
           (let* ((n 200)
                  (loan-consed (let ((before (dds.pal:bytes-consed)))
                                 (dotimes (i n)
                                   (let ((b (dds.core.arena:pool-acquire pool)))
                                     (dds.security:decode-serialized-payload-into b km secured)
                                     (dds.core.arena:pool-release pool b)))
                                 (- (dds.pal:bytes-consed) before)))
                  (old-consed (let ((before (dds.pal:bytes-consed)))
                                (dotimes (i n) (dds.security:decode-serialized-payload km secured))
                                (- (dds.pal:bytes-consed) before))))
             (format t "~&  [secured-decode-loan-alloc] decode-INTO-pool=~,4f B/sample  allocating-decode=~,4f B/sample (plaintext ~d B)~%"
                     (/ (float loan-consed) n) (/ (float old-consed) n) pt-size)
             (if (zerop old-consed)
                 (format t "  [skip] dds.pal:bytes-consed is 0 on this impl (Clasp NFR-PORT gap) — alloc delta not measurable~%")
                 (progn
                   (%check :loan-alloc-eliminates-plaintext (< (/ loan-consed n) pt-size)
                           "the loan decode path does NOT cons the per-sample plaintext (< plaintext size per sample)")
                   (%check :loan-alloc-beats-allocating (< loan-consed old-consed)
                           "the loan decode path conses strictly less than the allocating decode")))))
      (dds.core.arena:teardown-arena arena)))
  ;; -- Part 2: the live receive path — loan lifecycle (byte-exact + no leak) + exhaustion -> SAMPLE_REJECTED --
  (let* ((km (dds.security:make-test-key-material))
         (pt (make-array 8 :element-type '(unsigned-byte 8)
                           :initial-contents '(#x53 #x51 #x55 #x41 #x52 #x45 #x20 #x01)))
         (secured (dds.security:encode-serialized-payload km pt))
         (src (%make-test-prefix #xA1))
         (wid #x00000102)
         (node (let ((dds.disc:*shmem-enabled* nil))
                 (dds.disc:make-disc-node :guid-prefix (%make-test-prefix #xE7) :domain (test-domain +td-secured-decode-loan-alloc+)
                                          :host "127.0.0.1" :port 0 :multicast nil :crypto-transform km))))
    (unwind-protect
         (let ((cap 1) (head 1))   ; capture the tiny-pool sizing — the specials revert to defaults after the carve, so the cap assertion must read these
           (dds.disc:enable-subscriber node)
           ;; tiny pool (capacity = 1 + 1 = 2) so exhaustion is reachable with a handful of un-returned loans
           (let ((dds.disc:*secured-pool-capacity* cap)
                 (dds.disc:*secured-pool-headroom* head)
                 (dds.disc:*secured-payload-max-bytes* 256))
             (dds.disc:set-secured-loan-capable node t))
           ;; one sample: received as a loan handle, read in place byte-exact, returned -> pool-in-use back to 0
           (dds.disc::%deliver-user-sample node wid 1 secured src (dds.disc::%source-guid src wid) 1)
           (multiple-value-bind (data count) (dds.disc:node-take-loaned node)   ; T5d: (values reused-VEC COUNT)
             (%check :loan-rx-handle
                     (and (plusp count) (dds.disc:secured-loan-handle-p (aref data 0)))
                     "a secured loan-capable receive stores a SECURED-LOAN-HANDLE")
             (let* ((h (aref data 0)) (len (dds.disc:secured-loan-handle-len h)) (bytes (dds.disc:secured-loan-bytes h)))
               (%check :loan-rx-byte-exact
                       (and (= len (length pt)) (loop for i below len always (= (aref bytes i) (aref pt i))))
                       "the loaned plaintext is byte-exact (read in place)")
               (dds.disc:node-return-loan node data count)
               (%check :loan-rx-returned
                       (and (zerop (dds.core.arena:pool-in-use (dds.disc:disc-node-decode-pool node)))
                            (null (dds.disc:secured-loan-handle-buffer h))
                            (zerop (dds.disc:node-sample-count node)))
                       "node-return-loan returns the buffer (pool-in-use 0), invalidates the handle + the store entry — no leak/dangle")))
           ;; exhaustion: feed SN 2..6 WITHOUT returning; pool cap 2 -> 2 admitted, the rest SAMPLE_REJECTED (no GC)
           (loop for sn from 2 to 6
                 do (dds.disc::%deliver-user-sample node wid sn secured src (dds.disc::%source-guid src wid) sn))
           (%check :loan-exhaust-rejected
                   (>= (dds.disc:disc-node-decode-pool-rejects node) 1)
                   "pool exhaustion increments decode-pool-rejects (SAMPLE_REJECTED) — never a GC-heap fallback")
           (%check :loan-exhaust-capped
                   (<= (dds.disc:node-sample-count node) (+ cap head))
                   "only pool-capacity samples are admitted; the surplus is rejected (bounded, no GC fallback)"))
      (dds.disc:stop-node node)))   ; stop-node returns the still-loaned exhaustion buffers, then tears the arena down
  t)

(defun* run-secured-decode-loan-dup-test ()
    (function () t)
  "Test (WP-DDS-SECURITY-ZEROALLOC-AEAD T5b review, Finding 1): a RETRANSMITTED DUPLICATE of an
   already-accepted-but-undrained secured sample must NOT evict the stored loan. On a reliable link the
   duplicate acquires a FRESH pooled buffer, decodes, and builds a second handle that shares the original's
   (GUID,SN); the dedup gate rejects it, so it is released. Because the store-eviction is IDENTITY-GUARDED
   (only the handle still OCCUPYING the slot removes it), the duplicate frees only its OWN buffer and the
   accepted original survives — no silent sample loss, no pinned pool slot. Asserts: (a) node-take-loaned still
   returns the ORIGINAL byte-exact AFTER the duplicate (no silent loss); (b) the duplicate adds no net pin (its
   buffer is freed immediately); (c) pool-in-use returns to baseline 0 once the app returns the original's loan
   (no leak). No sockets — %deliver-user-sample driven directly (the dup is a second call with the same effective
   GUID+SN, which reader-dedup-accept-p rejects). Requires OpenSSL >= 3.5; both impls must pass identically (Clasp FIRST)."
  (multiple-value-bind (%dare-ok %dare-reason) (dds.dare:dare-available-p)
    (unless %dare-ok
      (format t "~&  [secured-decode-loan-dup] SKIP — OpenSSL >= 3.5 not available: ~a~%"
              %dare-reason)
      (return-from run-secured-decode-loan-dup-test t)))
  (let* ((km (dds.security:make-test-key-material))
         (pt (make-array 8 :element-type '(unsigned-byte 8)
                           :initial-contents '(#x53 #x51 #x55 #x41 #x52 #x45 #x20 #x01)))
         (secured (dds.security:encode-serialized-payload km pt))
         (src (%make-test-prefix #xA2))
         (wid #x00000102)
         (node (let ((dds.disc:*shmem-enabled* nil))
                 (dds.disc:make-disc-node :guid-prefix (%make-test-prefix #xE8) :domain (test-domain +td-secured-decode-loan-dup+)
                                          :host "127.0.0.1" :port 0 :multicast nil :crypto-transform km))))
    (unwind-protect
         (progn
           (dds.disc:enable-subscriber node)
           (dds.disc:set-secured-loan-capable node t)   ; default-sized decode pool: room for the original + the dup's transient buffer
           ;; deliver SN 1, then a DUPLICATE of SN 1 (same effective GUID+SN) BEFORE take — the dup must free its OWN buffer, not evict SN 1
           (dds.disc::%deliver-user-sample node wid 1 secured src (dds.disc::%source-guid src wid) 1)
           (let ((pinned-after-first (dds.core.arena:pool-in-use (dds.disc:disc-node-decode-pool node))))
             (dds.disc::%deliver-user-sample node wid 1 secured src (dds.disc::%source-guid src wid) 1)
             (%check :loan-dup-no-extra-pin
                     (= (dds.core.arena:pool-in-use (dds.disc:disc-node-decode-pool node)) pinned-after-first)
                     "the deduped duplicate frees its own buffer immediately — no extra pinned pool slot"))
           ;; no silent loss: the ORIGINAL is still delivered byte-exact (the dup did NOT evict its store entry)
           (multiple-value-bind (data count) (dds.disc:node-take-loaned node)   ; T5d: (values reused-VEC COUNT)
             (%check :loan-dup-delivered
                     (and (= 1 count) (dds.disc:secured-loan-handle-p (aref data 0)))
                     "after a duplicate the original secured sample IS still delivered (no silent loss)")
             (let* ((h (aref data 0)) (len (dds.disc:secured-loan-handle-len h)) (bytes (dds.disc:secured-loan-bytes h)))
               (%check :loan-dup-byte-exact
                       (and (= len (length pt)) (loop for i below len always (= (aref bytes i) (aref pt i))))
                       "the surviving original loan is byte-exact (the dup neither corrupted nor replaced it)")
               (dds.disc:node-return-loan node data count)
               (%check :loan-dup-no-leak
                       (and (zerop (dds.core.arena:pool-in-use (dds.disc:disc-node-decode-pool node)))
                            (null (dds.disc:secured-loan-handle-buffer h))
                            (zerop (dds.disc:node-sample-count node)))
                       "after return-loan pool-in-use is back to 0 (dup freed immediately, original on return) — no leak/dangle"))))
      (dds.disc:stop-node node)))
  t)

(defun* run-dcps-secured-take-loan-test ()
    (function () t)
  "Test (WP-DCPS-SECURED-TAKE-LOAN, ADR 0038 residual (i)): the DCPS reader loan lifecycle wires the disc-node
   secured decode loan up through DataReader::take/read-loaned + return_loan, mirroring the FlatData ZC loan.
   Driven at the DCPS layer (dds.dcps:create-participant/create-datareader + take-loaned), receiving one secured
   sample directly via %deliver-user-sample (deterministic, no sockets). Parts:
     (1) OPT-IN: a secured reader (crypto-transform injected -> node-secured-reader-p) becomes secured-loan-capable
         at create-datareader; a PLAIN reader (no crypto) does NOT (the allocating decode path stays byte-identical).
     (2) ROUNDTRIP: take-loaned returns the DESERIALIZED struct as DATA (byte-exact fields vs the sent sample) and
         the dds.disc:secured-loan-handle in LOANS; the handle is registered in dr-secured-loans, is
         secured-loan-handle-p and NOT flatdata-view-p (structural type-dispatch proof).
     (3) RETURN: return-loan releases the loan -> disc-node pool-in-use back to 0, the handle buffer NIL, the
         samples-store entry gone (no leak/dangle), dr-secured-loans empty, the cache entry invalidated.
     (4) IDEMPOTENT / no double-free: a SECOND return-loan of the same loans, and a following return-all-loans, are
         safe no-ops (single-owner + membership-guard + node-return-loan idempotence).
     (5) SWEEP: a reader that drained a loan but never returned it -> return-all-loans (reader-close) releases it
         (pool-in-use back to 0) — no lingering plaintext, no leak.
   Requires OpenSSL >= 3.5 (same gate as the lower-layer secured tests); both impls must pass identically (Clasp FIRST)."
  (multiple-value-bind (%dare-ok %dare-reason) (dds.dare:dare-available-p)
    (unless %dare-ok
      (format t "~&  [dcps-secured-take-loan] SKIP — OpenSSL >= 3.5 not available: ~a~%"
              %dare-reason)
      (return-from run-dcps-secured-take-loan-test t)))
  (let* ((km (dds.security:make-test-key-material))
         (ts (dds.types:find-type-support "shape-type"))
         (sample (make-shape-type :color "BLUE" :x 100 :y 150 :shapesize 30))
         (pt (dds.dcps::%serialize-sample ts sample :xcdr2))   ; the plaintext SerializedPayload the reader deserializes
         (secured (dds.security:encode-serialized-payload km pt))
         (src (%make-test-prefix #xA5))
         (wid #x00000102))
    ;; -- Part 1 (plain reader unaffected): no crypto -> not secured-loan-capable, allocating path byte-identical --
    (let ((pp (dds.dcps:create-participant :domain (test-domain +td-dcps-secured-take-loan+))))
      (unwind-protect
           (let* ((sub (dds.dcps:create-subscriber pp))
                  (topic (dds.dcps:create-topic pp "PlainSquare" "shape-type" ts)))
             (dds.dcps:create-datareader sub topic)
             (%check :dstl-plain-not-loan-capable
                     (not (dds.disc:disc-node-secured-loan-capable (dds.dcps::dp-node pp)))
                     "a PLAIN reader (no data_protection) must NOT be secured-loan-capable (allocating path byte-identical)"))
        (dds.dcps:delete-participant pp)))
    ;; -- Parts 2-4 (roundtrip + return + idempotent) on a SECURED reader --
    (let ((p (dds.dcps:create-participant :domain (test-domain +td-dcps-secured-take-loan+))))
      (unwind-protect
           (let ((node (dds.dcps::dp-node p)))
             (setf (dds.disc:disc-node-crypto-transform node) km)   ; data_protection ON (direct-KM :unset+crypto) -> node-secured-reader-p
             (let* ((sub (dds.dcps:create-subscriber p))
                    (topic (dds.dcps:create-topic p "SecSquare" "shape-type" ts))
                    (dr (dds.dcps:create-datareader sub topic)))   ; opt-in fires here (eager decode-pool carve)
               (%check :dstl-opt-in
                       (dds.disc:disc-node-secured-loan-capable node)
                       "a SECURED reader must be secured-loan-capable after create-datareader (the opt-in)")
               (dds.disc::%deliver-user-sample node wid 1 secured src (dds.disc::%source-guid src wid) 1)
               (multiple-value-bind (data loans) (dds.dcps:take-loaned dr)
                 (%check :dstl-take-one (and (= 1 (length data)) (= 1 (length loans)))
                         "take-loaned must return exactly one sample + one loan")
                 (let ((q (first data)) (h (first loans)))
                   (%check :dstl-data-is-struct
                           (and (not (dds.disc:secured-loan-handle-p q))
                                (string= (shape-type-color q) "BLUE") (= (shape-type-x q) 100)
                                (= (shape-type-y q) 150) (= (shape-type-shapesize q) 30))
                           "the DATA is the deserialized struct, byte-exact vs the sent sample (typed copy persists)")
                   (%check :dstl-loan-is-handle
                           (and (dds.disc:secured-loan-handle-p h)
                                (not (dds.types:flatdata-view-p h))
                                (member h (dds.dcps::dr-secured-loans dr)))
                           "the LOAN is a secured-loan-handle (NOT a flatdata-view), registered in dr-secured-loans (structural type-dispatch)")
                   (%check :dstl-pool-in-use-1
                           (= 1 (dds.core.arena:pool-in-use (dds.disc:disc-node-decode-pool node)))
                           "one decode-pool buffer is in use while the loan is outstanding")
                   (dds.dcps:return-loan dr loans)
                   (%check :dstl-returned
                           (and (zerop (dds.core.arena:pool-in-use (dds.disc:disc-node-decode-pool node)))
                                (null (dds.disc:secured-loan-handle-buffer h))
                                (zerop (dds.disc:node-sample-count node))
                                (null (dds.dcps::dr-secured-loans dr)))
                           "return-loan releases the pooled buffer (pool-in-use 0), invalidates the handle + store entry, empties dr-secured-loans — no leak/dangle")
                   ;; idempotent: a second return-loan + a return-all-loans are safe no-ops (single-owner, no double-free)
                   (dds.dcps:return-loan dr loans)
                   (dds.dcps::return-all-loans dr)
                   (%check :dstl-idempotent
                           (and (zerop (dds.core.arena:pool-in-use (dds.disc:disc-node-decode-pool node)))
                                (null (dds.dcps::dr-secured-loans dr)))
                           "a double return-loan / a following return-all-loans are safe no-ops (no double-free)")))))
        (dds.dcps:delete-participant p)))
    ;; -- Part 5 (reader-close sweep of a drained-but-never-returned loan) --
    (let ((p2 (dds.dcps:create-participant :domain (test-domain +td-dcps-secured-take-loan+))))
      (unwind-protect
           (let ((node (dds.dcps::dp-node p2)))
             (setf (dds.disc:disc-node-crypto-transform node) km)
             (let* ((sub (dds.dcps:create-subscriber p2))
                    (topic (dds.dcps:create-topic p2 "SweepSquare" "shape-type" ts))
                    (dr (dds.dcps:create-datareader sub topic)))
               (dds.disc::%deliver-user-sample node wid 1 secured src (dds.disc::%source-guid src wid) 1)
               (multiple-value-bind (data loans) (dds.dcps:take-loaned dr)
                 (declare (ignore data loans))   ; drained + registered, but DELIBERATELY not returned
                 (%check :dstl-sweep-pinned
                         (= 1 (dds.core.arena:pool-in-use (dds.disc:disc-node-decode-pool node)))
                         "a drained-but-unreturned loan pins one decode-pool buffer"))
               (dds.dcps::return-all-loans dr)   ; reader-close safety sweep
               (%check :dstl-sweep-released
                       (and (zerop (dds.core.arena:pool-in-use (dds.disc:disc-node-decode-pool node)))
                            (null (dds.dcps::dr-secured-loans dr)))
                       "reader-close (return-all-loans) sweeps the outstanding secured loan — no leak, no lingering plaintext")))
        (dds.dcps:delete-participant p2)))
    ;; -- Part 6 (COPY API release-after-snapshot): a secured reader using take-samples / read-samples releases the
    ;; decode loan per consume, so N >> pool-capacity samples never pin/exhaust the pool (the auto-opt-in regression) --
    (let ((p3 (dds.dcps:create-participant :domain (test-domain +td-dcps-secured-take-loan+))))
      (unwind-protect
           (let ((node (dds.dcps::dp-node p3)))
             (setf (dds.disc:disc-node-crypto-transform node) km)
             (let* ((sub (dds.dcps:create-subscriber p3))
                    (topic (dds.dcps:create-topic p3 "CopySquare" "shape-type" ts))
                    ;; carve a TINY decode pool (capacity 2+1=3) so an un-released copy-API reader would exhaust it fast
                    (dr (let ((dds.disc:*secured-pool-capacity* 2)
                              (dds.disc:*secured-pool-headroom* 1)
                              (dds.disc:*secured-payload-max-bytes* 256))
                          (dds.dcps:create-datareader sub topic))))
               ;; take-samples arm: 10 sequential deliveries (>> capacity 3); each take releases its loan
               (dotimes (i 10)
                 (let ((sn (+ 1 i)))
                   (dds.disc::%deliver-user-sample node wid sn secured src (dds.disc::%source-guid src wid) sn)
                   (let ((got (dds.dcps:take-samples dr)))
                     (%check :dstl-copy-take-one
                             (and (= 1 (length got))
                                  (= 100 (shape-type-x (dds.dcps:cached-sample-data (first got)))))
                             "take-samples returns the sample byte-exact on a secured reader")
                     (%check :dstl-copy-take-released
                             (and (null (dds.dcps::dr-secured-loans dr))
                                  (zerop (dds.core.arena:pool-in-use (dds.disc:disc-node-decode-pool node))))
                             "take-samples RELEASES the secured decode loan per consume (registry empty, pool-in-use 0 — no pinning)"))))
               (%check :dstl-copy-take-no-reject
                       (zerop (dds.disc:disc-node-decode-pool-rejects node))
                       "10 take-samples on a capacity-3 pool caused ZERO SAMPLE_REJECTED (release-after-copy fixes the auto-opt-in regression)")
               ;; read-samples arm: read is non-destructive but also releases the loan (data struct is independent + stays readable)
               (dds.disc::%deliver-user-sample node wid 11 secured src (dds.disc::%source-guid src wid) 11)
               (let ((got (dds.dcps:read-samples dr)))
                 (%check :dstl-copy-read-one
                         (and (= 1 (length got))
                              (= 150 (shape-type-y (dds.dcps:cached-sample-data (first got)))))
                         "read-samples returns the secured sample byte-exact")
                 (%check :dstl-copy-read-released
                         (and (null (dds.dcps::dr-secured-loans dr))
                              (zerop (dds.core.arena:pool-in-use (dds.disc:disc-node-decode-pool node))))
                         "read-samples RELEASES the secured decode loan (registry empty, pool-in-use 0) yet keeps the readable struct in cache"))
               ;; a SECOND read-samples still returns the same readable struct — no double-release, no error
               (let ((again (dds.dcps:read-samples dr)))
                 (%check :dstl-copy-read-idempotent
                         (and (= 1 (length again))
                              (= 150 (shape-type-y (dds.dcps:cached-sample-data (first again))))
                              (zerop (dds.core.arena:pool-in-use (dds.disc:disc-node-decode-pool node))))
                         "a re-read of an already-released secured sample is a safe no-op (struct still readable, no double-release)"))))
        (dds.dcps:delete-participant p3))))
  t)

(defun* run-dcps-same-topic-secured-readers-test ()
    (function () t)
  "WP-DCPS-API-COMPLETION S6.T1: the DCPS end-to-end verification that TWO SAME-TOPIC SECURED DataReaders
   on ONE participant each decode a SHARED secured sample — the same-topic multi-reader fence is genuinely
   lifted at the DCPS layer (previously only disc-model coverage existed). Both readers create with distinct
   EntityIds (node-user-reader-count 2), are routed to ONE remote secured writer (so the shared secured
   decode handle's return-count = 2), and each take-loaned's the ONE stored handle: both deserialize the
   plaintext (no sample-loss), reader-1's early return DEFERS (the shared handle buffer + (guid,SN) survive
   for reader-2), and only reader-2's return (the last, count -> 0) purges the slot + frees the pooled buffer
   (2C3 return-count purge-defer — no leak, no double-free/UAF). OpenSSL-gated; Clasp FIRST."
  (multiple-value-bind (%dare-ok %dare-reason) (dds.dare:dare-available-p)
    (unless %dare-ok
      (format t "~&  [dcps-same-topic-secured-readers] SKIP — OpenSSL >= 3.5 not available: ~a~%"
              %dare-reason)
      (return-from run-dcps-same-topic-secured-readers-test t)))
  (let* ((km (dds.security:make-test-key-material))
         (ts (dds.types:find-type-support "shape-type"))
         (sample (make-shape-type :color "BLUE" :x 100 :y 150 :shapesize 30))
         (pt (dds.dcps::%serialize-sample ts sample :xcdr2))
         (secured (dds.security:encode-serialized-payload km pt))
         (src (%make-test-prefix #xA5))
         (wid #x00000102)
         (wguid (dds.disc::%source-guid src wid))
         (p (dds.dcps:create-participant :domain (test-domain +td-dcps-secured-take-loan+))))
    (unwind-protect
         (let ((node (dds.dcps::dp-node p)))
           (setf (dds.disc:disc-node-crypto-transform node) km)   ; data_protection ON -> node-secured-reader-p
           (let* ((sub (dds.dcps:create-subscriber p))
                  (topic (dds.dcps:create-topic p "SecSquare" "shape-type" ts))
                  (dr1 (dds.dcps:create-datareader sub topic))    ; two SAME-topic secured readers
                  (dr2 (dds.dcps:create-datareader sub topic)))
             (%check :sts-two-registered
                     (and (/= (dds.dcps::dr-entity-id dr1) (dds.dcps::dr-entity-id dr2))
                          (= 2 (dds.disc:node-user-reader-count node))
                          (dds.disc:disc-node-secured-loan-capable node))
                     "two SAME-topic secured readers register with DISTINCT EntityIds + secured-loan-capable (fence lifted)")
             ;; route BOTH readers to the one remote writer BEFORE the sample (offline: no live SEDP) so
             ;; %deliver-user-sample sets the shared handle's return-count = 2 (route length).
             (dds.disc::%reader-route-add node wguid (dds.dcps::dr-entity-id dr1))
             (dds.disc::%reader-route-add node wguid (dds.dcps::dr-entity-id dr2))
             (dds.disc::%deliver-user-sample node wid 1 secured src wguid 1)
             (multiple-value-bind (d1 l1) (dds.dcps:take-loaned dr1)
               (%check :sts-r1-decodes
                       (and (= 1 (length d1)) (= 1 (length l1))
                            (string= "BLUE" (shape-type-color (first d1))) (= 100 (shape-type-x (first d1))))
                       "reader-1 take-loaned decodes the shared secured sample -> plaintext BLUE")
               (multiple-value-bind (d2 l2) (dds.dcps:take-loaned dr2)
                 (%check :sts-r2-decodes
                         (and (= 1 (length d2)) (= 1 (length l2))
                              (string= "BLUE" (shape-type-color (first d2))) (= 150 (shape-type-y (first d2))))
                         "reader-2 ALSO decodes the SAME shared secured sample -> plaintext BLUE (no sample-loss)")
                 (%check :sts-shared-handle (eq (first l1) (first l2))
                         "both readers hold the SAME shared secured-loan-handle (one decode, K=2 drainers)")
                 (dds.dcps:return-loan dr1 l1)   ; reader-1 returns FIRST -> must DEFER
                 (%check :sts-defer
                         (and (dds.disc:secured-loan-handle-buffer (first l2))
                              (dds.disc:node-sample node (cons wguid 1)))
                         "reader-1's early return DEFERS: the shared buffer + (guid,SN) survive for reader-2 (2C3)")
                 (dds.dcps:return-loan dr2 l2)   ; reader-2 returns LAST -> purge + free
                 (%check :sts-purge
                         (and (null (dds.disc:secured-loan-handle-buffer (first l1)))
                              (zerop (dds.core.arena:pool-in-use (dds.disc:disc-node-decode-pool node)))
                              (zerop (dds.disc:node-sample-count node)))
                         "reader-2's return (the last) purges the shared handle + store slot + frees the buffer (no leak/double-free)")))))
      (dds.dcps:delete-participant p)))
  t)

(defun* %secured-store-table-entries (outer)
    (function (hash-table) (integer 0))
  "WP-SECURED-STORE-GROWTH: total (GUID,SN) entries across a 2-level per-(guid,sn) store table OUTER (sum of the
   inner SN-map counts) — the store-growth metric the leak-proof test asserts stays bounded / purged."
  (let ((n 0))
    (declare (type (integer 0) n))
    (maphash (lambda (g inner) (declare (ignore g)) (incf n (hash-table-count inner))) outer)
    n))

(defun* run-secured-store-growth-test ()
    (function () t)
  "Test (WP-SECURED-STORE-GROWTH): closes a PRE-EXISTING unbounded-heap-growth path in the secured-receive
   samples store (ADR 0038 residual (h), ADR 0039 carry). Two arms, each RED on the pre-fix code:
   ARM 1 (purged on loan release): stream MANY secured samples, take+return each loan. Pre-fix
   %secured-loan-release remhashed ONLY disc-node-samples, leaking the parallel per-(guid,sn) tables
   (sample-writers / -writer-guids / -key-hashes / -origins) — they grew to N. The fix purges ALL tables at one
   choke (%purge-secured-sample), so after N cycles every table is back to empty.
   ARM 2 (bounded high-water, if reachable): force the arena-carve-fail path (the decode pool cannot carve) and
   stream MANY secured samples WITHOUT draining. Pre-fix the bare-vector store grew to N; the fix caps it at the
   pool working-set budget and fails closed (RESOURCE_LIMITS / SAMPLE_REJECTED). Skipped if carve-fail is
   unreachable on this impl/platform (the impossibly-large carve unexpectedly succeeded).
   No sockets — %deliver-user-sample driven directly. Requires OpenSSL >= 3.5; both impls pass identically (Clasp FIRST)."
  (multiple-value-bind (%dare-ok %dare-reason) (dds.dare:dare-available-p)
    (unless %dare-ok
      (format t "~&  [secured-store-growth] SKIP — OpenSSL >= 3.5 not available: ~a~%"
              %dare-reason)
      (return-from run-secured-store-growth-test t)))
  (let* ((km (dds.security:make-test-key-material))
         (pt (make-array 16 :element-type '(unsigned-byte 8) :initial-element #x5A))
         (secured (dds.security:encode-serialized-payload km pt))
         (kh (make-array 16 :element-type '(unsigned-byte 8) :initial-element #x7C))   ; a captured key-hash -> also populates sample-key-hashes
         (src (%make-test-prefix #xA3))
         (wid #x00000102)
         (n 2000))
    ;; -- ARM 1: parallel-table purge on loan release (deterministic, always runs) --
    (let ((node (let ((dds.disc:*shmem-enabled* nil))
                  (dds.disc:make-disc-node :guid-prefix (%make-test-prefix #xE9)
                                           :domain (test-domain +td-secured-store-growth+)
                                           :host "127.0.0.1" :port 0 :multicast nil :crypto-transform km))))
      (unwind-protect
           (let ((guid (dds.disc::%source-guid src wid)))
             (dds.disc:enable-subscriber node)
             ;; small pool (cap 4 + headroom 2): take+return each loan so ONE buffer recycles across all N samples
             ;; -> the pooled buffers never leak; the ONLY thing that can grow is the parallel METADATA tables.
             (let ((dds.disc:*secured-pool-capacity* 4) (dds.disc:*secured-pool-headroom* 2))
               (dds.disc:set-secured-loan-capable node t))
             (dotimes (i n)
               (let ((sn (1+ i)))
                 (dds.disc::%deliver-user-sample node wid sn secured src guid sn kh)   ; key-hash populates sample-key-hashes too
                 (multiple-value-bind (data count) (dds.disc:node-take-loaned node)
                   (dds.disc:node-return-loan node data count))))
             ;; after N deliver+take+return cycles EVERY parallel table is purged (fix); pre-fix sample-writers /
             ;; -writer-guids / -key-hashes each held N entries while disc-node-samples WAS purged (the leak).
             (dds.pal:with-lock ((dds.disc::disc-node-lock node))
               (%check :store-growth-samples-purged
                       (zerop (%secured-store-table-entries (dds.disc::disc-node-samples node)))
                       (format nil "disc-node-samples must be empty after ~d take+return cycles" n))
               (%check :store-growth-writers-purged
                       (zerop (%secured-store-table-entries (dds.disc::disc-node-sample-writers node)))
                       (format nil "sample-writers must be purged on loan release; pre-fix leaked ~d entries (unbounded)" n))
               (%check :store-growth-writer-guids-purged
                       (zerop (%secured-store-table-entries (dds.disc::disc-node-sample-writer-guids node)))
                       (format nil "sample-writer-guids must be purged on loan release; pre-fix leaked ~d entries (unbounded)" n))
               (%check :store-growth-key-hashes-purged
                       (zerop (%secured-store-table-entries (dds.disc::disc-node-sample-key-hashes node)))
                       (format nil "sample-key-hashes must be purged on loan release; pre-fix leaked ~d entries (unbounded)" n))
               (%check :store-growth-origins-purged
                       (zerop (%secured-store-table-entries (dds.disc::disc-node-sample-origins node)))
                       "sample-origins must be purged on loan release (single-choke invariant)")))
        (dds.disc:stop-node node)))
    ;; -- ARM 2: arena-carve-fail bare-vector store bounded (if the carve-fail path is reachable) --
    (let* ((cap 4) (head 2) (bound (+ cap head))
           (node (let ((dds.disc:*shmem-enabled* nil))
                   (dds.disc:make-disc-node :guid-prefix (%make-test-prefix #xEA)
                                            :domain (test-domain +td-secured-store-growth+)
                                            :host "127.0.0.1" :port 0 :multicast nil :crypto-transform km))))
      (unwind-protect
           (let ((guid (dds.disc::%source-guid src wid)))
             (dds.disc:enable-subscriber node)
             ;; force carve-fail: an impossibly-large element size makes the static-arena carve fail (graceful,
             ;; caught -> pool stays NIL -> the allocating bare-vector fallback). If the huge carve unexpectedly
             ;; succeeds (e.g. a 5-level-paging overcommit), carve-fail is unreachable here -> SKIP the arm.
             (let ((dds.disc:*secured-payload-max-bytes* (ash 1 48))
                   (dds.disc:*secured-pool-capacity* cap)
                   (dds.disc:*secured-pool-headroom* head))
               (ignore-errors (dds.disc:set-secured-loan-capable node t))
               (if (dds.disc:disc-node-decode-pool node)
                   (format t "~&  [secured-store-growth] SKIP ARM 2 — carve-fail unreachable (huge static alloc succeeded on this platform)~%")
                   (progn
                     (dotimes (i n)
                       (dds.disc::%deliver-user-sample node wid (1+ i) secured src guid (1+ i) kh))   ; NO drain -> pre-fix grows unbounded
                     (%check :carve-fail-store-bounded
                             (<= (dds.disc:node-sample-count node) bound)
                             (format nil "arena-carve-fail store must be bounded at the pool budget (~d); got ~d after ~d undrained samples (pre-fix = ~d, unbounded)"
                                     bound (dds.disc:node-sample-count node) n n))
                     (%check :carve-fail-tables-bounded
                             (<= (dds.pal:with-lock ((dds.disc::disc-node-lock node))
                                   (%secured-store-table-entries (dds.disc::disc-node-sample-writers node)))
                                 bound)
                             "the parallel tables must be bounded on the carve-fail path too (same cap)")
                     (%check :carve-fail-rejected
                             (>= (dds.disc:disc-node-decode-pool-rejects node) 1)
                             "carve-fail over the cap must fail-closed (SAMPLE_REJECTED / decode-pool-rejects), never a GC-silent unbounded store")))))
        (dds.disc:stop-node node))))
  t)

(defun* run-decode-fail-suppress-test ()
    (function () t)
  "Test (WP-RESIDUAL-FIXES-BATCH-A / ADR 0031 limitation 1 RESOLVED; RTPS 2.5 §8.3.5 / §8.4): the reliable-reader
   decode-failure retransmit-suppression is BOUNDED and FAIL-SAFE, avoiding BOTH the data-loss trap and the
   unbounded-churn bug. No sockets — %deliver-user-sample driven directly.
   ARM (a) MISSING KM MUST NEVER SUPPRESS (data-loss trap): a decode failure caused by an unresolved remote key
   (the key-exchange race) records NO failure count and does NOT suppress the SN, so the SN keeps being NACKed;
   once the key ARRIVES the very same (writer-GUID, SN) is delivered byte-exact — the today self-healing behavior
   is preserved (NO data loss).
   ARM (b) PERSISTENT KM-PRESENT TAG FAILURE suppresses AFTER a bounded count, without wedging later SNs: a
   tampered SecuredPayload with the key PRESENT fails the AEAD tag every time; the SN is NACKed for the first
   *decode-fail-suppress-threshold*-1 failures (still recoverable) and only THEN marked GAP-irrelevant so the
   writer stops retransmitting it (fail-closed: it is NEVER delivered). A subsequent GOOD higher SN still decodes
   and is delivered — no head-of-line wedge.
   ARM (c) BOUNDED TRACKING (NFR-MEM/NFR-SEC-POSTURE): with *decode-fail-track-limit* rebound small, a flood of
   DISTINCT failing SNs never grows the per-writer counter map past the cap (an attacker streaming garbage cannot
   exhaust memory through the counter table), while an already-tracked SN still progresses to suppression.
   Requires OpenSSL >= 3.5; both impls must pass identically (Clasp FIRST)."
  (multiple-value-bind (%dare-ok %dare-reason) (dds.dare:dare-available-p)
    (unless %dare-ok
      (format t "~&  [decode-fail-suppress] SKIP — OpenSSL >= 3.5 not available: ~a~%"
              %dare-reason)
      (return-from run-decode-fail-suppress-test t)))
  (let* ((km (dds.security:make-test-key-material))
         (pt (make-array 8 :element-type '(unsigned-byte 8)
                           :initial-contents '(#x53 #x51 #x55 #x41 #x52 #x45 #x20 #x02)))
         (secured (dds.security:encode-serialized-payload km pt))
         (src (%make-test-prefix #xA4))
         (wid #x00000102))
    ;; -- ARM (a): missing-KM failure NEVER suppresses; the sample is delivered once the key arrives (no loss) --
    (let* ((have-key nil)                                             ; the resolver returns the key only after it "arrives"
           (ck (dds.security:make-crypto-keys
                :encode-key-fn (lambda (g) (declare (ignore g)) nil)
                :decode-key-fn (lambda (g) (declare (ignore g)) (and have-key km))))
           (node (let ((dds.disc:*shmem-enabled* nil))
                   (dds.disc:make-disc-node :guid-prefix (%make-test-prefix #xEB)
                                            :domain (test-domain +td-decode-fail-suppress+)
                                            :host "127.0.0.1" :port 0 :multicast nil :crypto-transform ck))))
      (unwind-protect
           (let ((guid (dds.disc::%source-guid src wid)))
             (dds.disc:enable-subscriber node)
             (let ((reader (dds.disc::disc-node-user-reader node)))
             (dds.rtps.reliable:reader-on-heartbeat reader guid 1 1)   ; the writer advertises [1,1]
             ;; key NOT yet arrived -> decode returns NIL because the KEY is missing (not a tag failure)
             (dds.disc::%deliver-user-sample node wid 1 secured src guid 1)
             (%check :dfs-missing-not-delivered
                     (zerop (dds.disc:node-sample-count node))
                     "a missing-KM sample must not be delivered (fail-closed)")
             (%check :dfs-missing-not-counted
                     (zerop (hash-table-count (dds.disc::disc-node-decode-fail-counts node)))
                     "a missing-KM failure must record NO failure count (it must not head toward suppression)")
             (multiple-value-bind (base nb bm) (dds.rtps.reliable:reader-acknack reader guid)
               (declare (ignore bm))
               (%check :dfs-missing-still-nacked
                       (and (= base 1) (>= nb 1))
                       "the missing-KM SN must STILL be NACKed (never suppressed) so it can self-heal"))
             ;; the key ARRIVES -> the SAME SN, redelivered on the writer's retransmit, decodes + is delivered (NO loss)
             (setf have-key t)
             (dds.disc::%deliver-user-sample node wid 1 secured src guid 1)
             (%check :dfs-missing-heals
                     (= 1 (dds.disc:node-sample-count node))
                     "once the key arrives the previously-undecodable SN is delivered (the self-healing, no data loss)")))
        (dds.disc:stop-node node)))
    ;; -- ARM (b): persistent KM-present tag failure suppresses after N, later SNs still flow --
    (let* ((tampered (let ((v (copy-seq secured))) (setf (aref v (1- (length v))) (logxor #xFF (aref v (1- (length v))))) v))   ; flip the last tag octet -> AEAD verify fails, KEY present
           (node (let ((dds.disc:*shmem-enabled* nil))
                   (dds.disc:make-disc-node :guid-prefix (%make-test-prefix #xEC)
                                            :domain (test-domain +td-decode-fail-suppress+)
                                            :host "127.0.0.1" :port 0 :multicast nil :crypto-transform km))))
      (unwind-protect
           (let* ((guid (dds.disc::%source-guid src wid))
                  (thresh dds.disc:*decode-fail-suppress-threshold*)
                  (lost-count 0))
             (setf (dds.disc:disc-node-on-sample-lost node)   ; ADR 0060: SAMPLE_LOST on suppression (DDS 1.4 §2.2.4.1)
                   (lambda (rid n) (declare (ignore rid)) (incf lost-count n)))
             (dds.disc:enable-subscriber node)
             (let ((reader (dds.disc::disc-node-user-reader node)))
             (dds.rtps.reliable:reader-on-heartbeat reader guid 1 2)   ; the writer advertises [1,2]
             ;; the first THRESH-1 tampered deliveries keep the SN NACKable (still recoverable — no premature suppress)
             (dotimes (i (1- thresh))
               (dds.disc::%deliver-user-sample node wid 1 tampered src guid 1)
               (multiple-value-bind (base nb bm) (dds.rtps.reliable:reader-acknack reader guid)
                 (declare (ignore bm))
                 (%check :dfs-tamper-still-nacked
                         (and (= base 1) (>= nb 1))
                         (format nil "after ~d/~d tag failures SN 1 must still be NACKed (not yet suppressed)" (1+ i) thresh))))
             ;; the THRESH-th failure trips suppression: SN 1 becomes GAP-irrelevant (never delivered — fail-closed)
             (dds.disc::%deliver-user-sample node wid 1 tampered src guid 1)
             (%check :dfs-tamper-not-delivered
                     (zerop (dds.disc:node-sample-count node))
                     "a persistently-tampered sample is NEVER delivered (fail-closed)")
             (%check :dfs-tamper-suppressed
                     (eq :gap (gethash 1 (dds.rtps.reliable:writer-proxy-received
                                          (dds.rtps.reliable:get-writer-proxy reader guid))))
                     "after the threshold the tampered SN is marked GAP-irrelevant (suppressed)")
             (%check :dfs-counter-cleared
                     (let ((entry (gethash guid (dds.disc::disc-node-decode-fail-counts node))))   ; (km-key-id . SN-table), ADR 0059
                       (or (null entry) (null (gethash 1 (cdr entry)))))
                     "the failure counter for a suppressed SN is dropped (bounded memory)")
             ;; ADR 0060: a suppressed SN can never be recovered (the reader stops NACKing it) -> SAMPLE_LOST.
             ;; ADR 0054 left this uncounted in v1, so a real loss reached the app with NO status.
             (%check :dfs-sample-lost-fired
                     (plusp lost-count)
                     "suppressing a permanently-undecodable SN raises SAMPLE_LOST on the matched DataReader (ADR 0060; RED before: the loss was silent)")
             ;; a subsequent GOOD higher SN still decodes + delivers -> no head-of-line wedge
             (dds.disc::%deliver-user-sample node wid 2 secured src guid 2)
             (%check :dfs-later-sn-flows
                     (= 1 (dds.disc:node-sample-count node))
                     "a GOOD later SN still flows after a lower SN was suppressed (no head-of-line wedge)")
             (multiple-value-bind (base nb bm) (dds.rtps.reliable:reader-acknack reader guid)
               (declare (ignore bm))
               (%check :dfs-no-more-nack
                       (and (= base 3) (zerop nb))
                       "with SN 1 suppressed (:gap) and SN 2 received, the reader NACKs nothing (writer stops retransmitting)"))))
        (dds.disc:stop-node node)))
    ;; -- ARM (c): the counter table is capped per writer (a distinct-SN garbage flood cannot exhaust memory) --
    (let* ((tampered (let ((v (copy-seq secured))) (setf (aref v (1- (length v))) (logxor #xFF (aref v (1- (length v))))) v))
           (node (let ((dds.disc:*shmem-enabled* nil))
                   (dds.disc:make-disc-node :guid-prefix (%make-test-prefix #xED)
                                            :domain (test-domain +td-decode-fail-suppress+)
                                            :host "127.0.0.1" :port 0 :multicast nil :crypto-transform km))))
      (unwind-protect
           (let ((guid (dds.disc::%source-guid src wid))
                 (cap 8))
             (dds.disc:enable-subscriber node)
             (let ((dds.disc:*decode-fail-track-limit* cap))
               (loop for sn from 1 to (* 4 cap)   ; 4x the cap of DISTINCT one-shot failing SNs
                     do (dds.disc::%deliver-user-sample node wid sn tampered src guid sn))
               (%check :dfs-track-capped
                       (<= (hash-table-count (cdr (gethash guid (dds.disc::disc-node-decode-fail-counts node)))) cap)
                       (format nil "the per-writer failure-counter map must stay <= *decode-fail-track-limit* (~d)" cap))))
        (dds.disc:stop-node node))))
  t)

(defun* run-security-encrypted-fragmented-test ()
    (function () t)
  "DDS-Security §9.5.3.3 Slice-1 DATA_FRAG path: encode -> fragment -> reassemble -> decode (ADR 0031).
   Two nodes on domain 84 (no collision with domain-83 pubsub test); BOTH share ONE key-material instance.
   Plaintext is 2000 octets (> dds.rtps.reliable:*fragment-size* 1024), so the encoded SecuredPayload
   (plaintext + ~44-byte SecureDataHeader overhead) fragments into multiple DATA_FRAGs on send.
   Asserts the subscriber receives the EXACT 2000-byte original plaintext byte-exact after
   encode -> fragment -> reassemble -> decode — proving the common-sink decode covers the DATA_FRAG path.
   Requires OpenSSL >= 3.5; skips only if truly absent. Both SBCL and Clasp must pass identically."
  (multiple-value-bind (%dare-ok %dare-reason) (dds.dare:dare-available-p)
    (unless %dare-ok
      (format t "~&  [security-encrypted-fragmented] SKIP — OpenSSL >= 3.5 not available: ~a~%"
              %dare-reason)
      (return-from run-security-encrypted-fragmented-test t)))

  ;; ONE shared km — two instances would collide nonces under the same master key (ADR 0031 §T2).
  (let* ((shared-km (dds.security:make-test-key-material))
         ;; 2000-byte recognizable pattern: octet[i] = (i*7) mod 256
         (pt-size 2000)
         (pt (let ((v (make-array pt-size :element-type '(unsigned-byte 8))))
               (dotimes (i pt-size v) (setf (aref v i) (logand (* i 7) #xff)))))
         (pub-prefix (%make-test-prefix #xF1))
         (sub-prefix (%make-test-prefix #xF2))
         (pub-node (dds.disc:make-disc-node :guid-prefix pub-prefix :domain (test-domain +td-encrypted-fragmented+)
                                            :host "127.0.0.1" :port 0 :multicast nil
                                            :crypto-transform shared-km))
         (sub-node (dds.disc:make-disc-node :guid-prefix sub-prefix :domain (test-domain +td-encrypted-fragmented+)
                                            :host "127.0.0.1" :port 0 :multicast nil
                                            :crypto-transform shared-km)))
    (unwind-protect
         (progn
           (dds.disc:add-local-writer pub-node :topic "SLarge" :type "ShapeType"
                                     :qos (dds.qos:make-writer-qos :reliability :reliable
                                                                    :durability :transient-local))
           (dds.disc:enable-publisher pub-node :history-kind :keep-all)
           (dds.disc:start-node pub-node)
           (dds.disc:add-local-reader sub-node :topic "SLarge" :type "ShapeType"
                                     :qos (dds.qos:make-reader-qos :reliability :reliable
                                                                    :durability :transient-local))
           (dds.disc:enable-subscriber sub-node)
           (dds.disc:start-node sub-node)
           ;; unicast wiring: pub -> sub, sub -> pub
           (let ((pp (dds.disc:disc-node-port pub-node))
                 (sp (dds.disc:disc-node-port sub-node)))
             (setf (dds.disc:disc-node-peers pub-node) (list (cons "127.0.0.1" sp)))
             (setf (dds.disc:disc-node-peers sub-node) (list (cons "127.0.0.1" pp))))
           ;; discover + match
           (loop repeat 400
                 until (>= (dds.disc:disc-node-matched-count pub-node) 1)
                 do (dds.disc:announce-participant pub-node) (dds.disc:announce-endpoints pub-node)
                    (dds.disc:announce-participant sub-node) (dds.disc:announce-endpoints sub-node)
                    (sleep 0.02))
           (%check :crypto-frag-matched
                   (>= (dds.disc:disc-node-matched-count pub-node) 1)
                   "pub must match sub before publishing the large encrypted sample")
           ;; publish 2000-byte plaintext: encode produces SecuredPayload > *fragment-size* -> DATA_FRAGs
           (dds.disc:publish-sample pub-node pt)
           ;; wait for sub to receive and reassemble
           (loop repeat 400
                 until (plusp (dds.disc:node-sample-count sub-node))
                 do (dds.disc:announce-participant pub-node) (dds.disc:announce-endpoints pub-node)
                    (sleep 0.02))
           (%check :crypto-frag-received
                   (plusp (dds.disc:node-sample-count sub-node))
                   "sub did not receive the reassembled encrypted sample (DATA_FRAG path)")
           (let* ((sn   (first (dds.disc:node-sample-sns sub-node)))
                  (got  (dds.disc:node-sample sub-node sn)))
             (%check :crypto-frag-length
                     (and got (= pt-size (length got)))
                     (format nil "decoded payload length ~a; expected ~d" (and got (length got)) pt-size))
             (%check :crypto-frag-byte-exact
                     (and got (equalp got pt))
                     "decoded payload does not match original plaintext (DATA_FRAG encode->reassemble->decode failure)")))
      (ignore-errors (dds.disc:stop-node pub-node))
      (ignore-errors (dds.disc:stop-node sub-node))))
  t)

(defun* run-security-encode-pool-alloc-test ()
    (function () t)
  "WP-DDS-SECURITY-ZEROALLOC-AEAD T5a focused encode-path alloc check: a steady-state secured encode over a
   REUSED key-material + plaintext through the POOL (writer-acquire-payload-buffer + encode-serialized-payload-into
   + writer-release-payload-buffer) conses materially LESS per iteration than the allocating wrapper
   (encode-serialized-payload, which subseqs a fresh per-sample payload vector) — proving the encode pool removed
   the per-sample payload allocation. The win measured here is at least the payload size per sample. SBCL-exact
   (dds.pal:bytes-consed); Clasp reports 0 by the NFR-PORT gap, so the inequality is asserted only on a measuring
   impl. The full live-publish-path 0.0000 proof (publisher AND subscriber) is the T5c gate. Requires OpenSSL >= 3.5."
  (multiple-value-bind (%dare-ok %dare-reason) (dds.dare:dare-available-p)
    (unless %dare-ok
      (format t "~&  [security-encode-pool-alloc] SKIP — OpenSSL >= 3.5 not available: ~a~%"
              %dare-reason)
      (return-from run-security-encode-pool-alloc-test t)))
  (let* ((km (dds.security:make-test-key-material))
         (pt (make-array 256 :element-type '(unsigned-byte 8) :initial-element 7))
         (iters 5000)
         (element-bytes (+ 44 256 3 16))
         (arena (dds.core.arena:init-arena :bytes (* element-bytes 4)))
         (pool (dds.core.arena:make-buffer-pool arena element-bytes 2))
         (writer (dds.rtps.reliable:make-rtps-writer
                  :hc (dds.rtps.history:make-history-cache :keep-last 1 nil nil))))
    (setf (dds.rtps.history:history-cache-payload-pool (dds.rtps.reliable:rtps-writer-hc writer)) pool)
    (unwind-protect
         (progn
           ;; warm both paths (resolve EVP fn-pointers + cache the session key) so the steady-state delta is alloc-only
           (dds.security:encode-serialized-payload km pt)
           (let ((b (dds.rtps.reliable:writer-acquire-payload-buffer writer)))
             (dds.security:encode-serialized-payload-into b km pt)
             (dds.rtps.reliable:writer-release-payload-buffer writer b))
           (let ((alloc0 (dds.pal:bytes-consed)))
             (dotimes (i iters) (dds.security:encode-serialized-payload km pt))   ; allocating wrapper: subseqs a fresh payload
             (let ((alloc-bytes (- (dds.pal:bytes-consed) alloc0))
                   (pool0 (dds.pal:bytes-consed)))
               (dotimes (i iters)   ; pooled: acquire + encode-into + release, no per-sample payload alloc
                 (let ((b (dds.rtps.reliable:writer-acquire-payload-buffer writer)))
                   (dds.security:encode-serialized-payload-into b km pt)
                   (dds.rtps.reliable:writer-release-payload-buffer writer b)))
               (let ((pool-bytes (- (dds.pal:bytes-consed) pool0)))
                 (format t "~&  [security-encode-pool-alloc] allocating encode: ~,1f B/sample; pooled encode: ~,1f B/sample (~d samples, ~d-byte plaintext)~%"
                         (/ alloc-bytes (float iters)) (/ pool-bytes (float iters)) iters (length pt))
                 ;; on a measuring impl (SBCL) the pooled encode must cons less than the allocating one by AT LEAST
                 ;; the payload size per sample (the eliminated subseq); Clasp's bytes-consed=0 -> alloc-bytes 0 -> skip
                 (when (plusp alloc-bytes)
                   (%check :encode-pool-removed-alloc
                           (< (+ pool-bytes (* iters (length pt))) alloc-bytes)
                           (format nil "pooled encode (~,1f B/sample) must save >= the payload size vs allocating (~,1f B/sample)"
                                   (/ pool-bytes (float iters)) (/ alloc-bytes (float iters)))))))))
      (dds.core.arena:teardown-arena arena)))
  t)

(defun* run-secured-live-zeroalloc-test ()
    (function () t)
  "WP-DDS-SECURITY-ZEROALLOC-AEAD T5c (the gating PROOF): the LIVE secured pub+sub path is zero-alloc OVER the
   non-secured baseline for the PAYLOAD codec, and pool exhaustion is BACKPRESSURE, never a GC fallback. HONEST
   framing (no overclaim): enabling data_protection adds 0.0000 B/sample for the encode+decode PAYLOAD codec; it is
   NOT a claim that the whole datagram path is 0 (a full loop still conses pre-existing NON-security allocs — the
   make-cache-change struct, RTPS framing — IDENTICALLY with security on or off, so they cancel in the delta).
   Part A (live-path delta, SBCL-exact via dds.pal:bytes-consed; Clasp reports 0 -> the deltas are 0 and the
   measured assertions self-skip, NFR-PORT): a steady-state publish-sample loop conses IDENTICALLY with
   data_protection ON vs OFF (delta 0.0000 -> the live publish encode is alloc-free relative to plain); and — since
   T5d pooled the loan wrapper (freelisted secured-loan-handle + fixed-vector registry + reused take vec) — the
   secured RECEIVE loan path now ALSO adds 0.0000 B/sample OVER plain, at BOTH 256-B and 4096-B payloads (asserted
   with the same large-window / GC-quantum tolerance as the publish proof), whereas the allocating (non-loan)
   decode it replaces still copies a full plaintext per sample (delta SCALES with payload). So enabling
   data_protection is zero-alloc on the full secured receive loop, matching the encode side.
   Part B (ENCODE pool exhaustion): a secured KEEP_ALL writer with a tiny pool and no readers fills the pool, then
   publish-sample returns :timeout (RETCODE_TIMEOUT / RESOURCE_LIMITS) — never an error/crash, never a GC fallback;
   the exhausted publishes cons far below one plaintext (no per-sample heap fallback).
   Part C (DECODE pool exhaustion): a secured loan-capable reader fed past its tiny decode pool without returning
   loans increments disc-node-decode-pool-rejects (SAMPLE_REJECTED), caps node-sample-count at the pool capacity,
   and conses far below one plaintext per rejected sample (no GC fallback).
   Requires OpenSSL >= 3.5; both impls must pass identically (Clasp FIRST)."
  (multiple-value-bind (%dare-ok %dare-reason) (dds.dare:dare-available-p)
    (unless %dare-ok
      (format t "~&  [secured-live-zeroalloc] SKIP — OpenSSL >= 3.5 not available: ~a~%"
              %dare-reason)
      (return-from run-secured-live-zeroalloc-test t)))
  (let ((km (dds.security:make-test-key-material))
        (sbcl (eq (dds.pal:pal-impl-name) :sbcl)))
    ;; -- Part A: live-path delta — publish 0.0000 over plain + the honest receive decomposition --
    (let* ((pt   (make-array 256  :element-type '(unsigned-byte 8) :initial-element 7))
           (pt4k (make-array 4096 :element-type '(unsigned-byte 8) :initial-element 7))
           (ct   (dds.security:encode-serialized-payload km pt))
           (ct4k (dds.security:encode-serialized-payload km pt4k))
           ;; the receive path conses common non-security framing -> get-bytes-consed has a ~64KB GC-boundary
           ;; quantum; a LARGE window (N) resolves the true 0 loan delta (T5d) the same way NPUB does for publish.
           ;; NA (the allocating-decode window) stays small — its per-sample plaintext copy is a huge signal that
           ;; needs no precision and a large NA would cons 100s of MB. Clasp smokes (tiny windows; bytes-consed 0).
           (n    (if sbcl 100000 2000))
           (na   (if sbcl 8000 2000))
           (npub (if sbcl 200000 2000)))
      ;; publish delta: same warmed node (cancels the common non-security residual in one heap state -> ~0 delta).
      ;; receive deltas: SEPARATE fresh nodes per config so both grow their reliable proxy/store IDENTICALLY 0->N
      ;; (fully symmetric -> the loan wrapper is the only difference, and T5d made it 0). The EXACT 0.0000 wrapper
      ;; proof is the deterministic %secured-wrapper-cycle-bps check below; this end-to-end delta corroborates it
      ;; to within the cross-node ~64KB GC-boundary accounting quantum.
      (multiple-value-bind (pub-plain pub-sec) (%secured-live-publish-delta-bps km pt npub)
        (let* ((rx-plain  (%secured-live-receive-bps km pt   nil nil n))    ; plain receive (bare-vector store)
               (rx-loan   (%secured-live-receive-bps km ct   t   t   n))    ; secured, loan-capable (T5b/T5d pooled wrapper)
               (rx-alloc  (%secured-live-receive-bps km ct   t   nil na))   ; secured, NOT loan-capable (allocating decode) — big signal, small window
               (rx-plain4 (%secured-live-receive-bps km pt4k nil nil n))
               (rx-loan4  (%secured-live-receive-bps km ct4k t   t   n))
               (rx-alloc4 (%secured-live-receive-bps km ct4k t   nil na))
               (wrap-bps  (%secured-wrapper-cycle-bps km 200000))          ; DETERMINISTIC exact wrapper-cycle alloc (0.0000)
               (pub-delta   (- pub-sec  pub-plain))
               (loan-delta  (- rx-loan  rx-plain))
               (loan-delta4 (- rx-loan4 rx-plain4))
               (alloc-delta (- rx-alloc rx-plain))
               (alloc-delta4 (- rx-alloc4 rx-plain4)))
          (format t "~&  [secured-live-zeroalloc] PUBLISH  plain=~,4f secured=~,4f -> data_protection delta=~,4f B/sample~%"
                  pub-plain pub-sec pub-delta)
          (format t "  [secured-live-zeroalloc] RECEIVE@256  plain=~,4f loan=~,4f (delta ~,4f) alloc-decode=~,4f (delta ~,4f)~%"
                  rx-plain rx-loan loan-delta rx-alloc alloc-delta)
          (format t "  [secured-live-zeroalloc] RECEIVE@4096 loan delta=~,4f  alloc-decode delta=~,4f  (loan 256-vs-4096 diff ~,4f)~%"
                  loan-delta4 alloc-delta4 (abs (- loan-delta loan-delta4)))
          (format t "  [secured-live-zeroalloc] WRAPPER-CYCLE (acquire+fill+register+deregister+release+recycle) = ~,4f B/sample (deterministic, exact)~%"
                  wrap-bps)
          (if (not sbcl)
              (format t "  [skip] dds.pal:bytes-consed is 0 on this impl (Clasp NFR-PORT gap) — delta assertions smoked, not measured~%")
              (progn
                ;; PRIMARY: the live publish path adds 0.0000 B/sample when data_protection is enabled (encode is alloc-free
                ;; vs plain). Tolerance 2.0 absorbs SBCL get-bytes-consed's ~64KB GC-boundary accounting quantum
                ;; (~0.33 B/sample at n=200000) on the common non-security framing; the true delta is 0 (the aead-encode-live
                ;; mem arm measures the pool encode itself at an exact 0.0000, and per-GC-phase the two are bit-identical).
                (%check :live-publish-zero-delta (< (abs pub-delta) 2.0)
                        (format nil "live publish: data_protection adds ~,4f B/sample over plain (expected ~~0; GC-accounting quantum ~,4f)"
                                pub-delta (/ 65536.0 npub)))
                ;; T5d: the secured-receive loan path adds 0.0000 B/sample OVER plain. The EXACT zero is proven
                ;; deterministically by :live-rx-wrapper-zero-alloc below (no GC-quantum caveat); THIS end-to-end
                ;; delta corroborates it but is a SEPARATE-node subtraction so it carries cross-node GC-boundary
                ;; accounting noise (observed |delta| ~1, sign varies by GC phase) — bounded FAR below the ~72-87
                ;; B/sample T5b wrapper it replaces and below even one 16-B cons, and payload-size-INDEPENDENT (the
                ;; 256-B and 4096-B deltas match), i.e. not a per-sample struct/list/payload alloc.
                (%check :live-rx-loan-zero-delta-256 (< (abs loan-delta) 16.0)
                        (format nil "secured-receive loan path adds ~,4f B/sample over plain (256-B; ~~0 within cross-node GC noise, < one 16-B cons — exact 0 proven by the wrapper-cycle check)" loan-delta))
                (%check :live-rx-loan-zero-delta-4096 (< (abs loan-delta4) 16.0)
                        (format nil "secured-receive loan path adds ~,4f B/sample over plain (4096-B; ~~0, payload-size-independent)" loan-delta4))
                ;; the allocating decode it REPLACES copies a full plaintext per sample (scales 16x with the payload):
                (%check :live-rx-loan-beats-allocating (< rx-loan rx-alloc)
                        (format nil "the loan path (~,4f) must cons strictly less than the allocating decode (~,4f) it replaces" rx-loan rx-alloc))
                (%check :live-rx-allocating-scales (> alloc-delta4 (+ alloc-delta 1000.0))
                        (format nil "the allocating decode must SCALE with payload (256:~,4f vs 4096:~,4f) — proving the loan eliminated the per-sample plaintext copy" alloc-delta alloc-delta4))
                ;; EXACT, deterministic proof (no GC-quantum caveat): the full T5d loan-wrapper cycle conses 0.0000 B/sample.
                (%check :live-rx-wrapper-zero-alloc (< wrap-bps 1.0)
                        (format nil "the T5d loan-wrapper cycle must be zero-alloc; measured ~,4f B/sample" wrap-bps)))))))
    ;; -- Part B: ENCODE pool exhaustion -> publish-sample :timeout (RESOURCE_LIMITS), never GC --
    (let ((node (let ((dds.disc:*shmem-enabled* nil) (dds.disc:*secured-pool-capacity* 2) (dds.disc:*secured-pool-headroom* 1))
                  (let ((n (dds.disc:make-disc-node :guid-prefix (%make-test-prefix #xEA) :domain (test-domain +td-secured-zeroalloc-encode+)
                                                    :host "127.0.0.1" :port 0 :multicast nil :crypto-transform km)))
                    (dds.disc:add-local-writer n :topic "ZAEnc" :type "X")
                    (dds.disc:enable-publisher n :history-kind :keep-all)   ; carve encode pool of capacity 2+1 = 3
                    n)))
          (big (make-array 4096 :element-type '(unsigned-byte 8) :initial-element 9)))
      (unwind-protect
           (let ((results (loop repeat 12 collect (dds.disc:publish-sample node big))))   ; KEEP_ALL + no readers -> buffers held -> pool exhausts
             (%check :encode-exhaust-timeout
                     (and (member :timeout results) t)
                     "a full secured encode pool must make publish-sample return :timeout (RESOURCE_LIMITS), not error/crash")
             (%check :encode-exhaust-admitted-bounded
                     (<= (count t results) 3)
                     (format nil "only pool-capacity (3) publishes are admitted before exhaustion; got ~d admitted" (count t results)))
             (when sbcl
               (let ((before (dds.pal:bytes-consed)))
                 (dotimes (i 5000) (dds.disc:publish-sample node big))   ; all exhausted -> :timeout
                 (let ((per (/ (float (- (dds.pal:bytes-consed) before)) 5000)))
                   (%check :encode-exhaust-no-gc (< per 256.0)
                           (format nil "exhausted publish conses ~,4f B/call — must be far below the ~d-B plaintext (no GC fallback)"
                                   per (length big)))))))
        (dds.disc:stop-node node)))
    ;; -- Part C: DECODE pool exhaustion -> SAMPLE_REJECTED (decode-pool-rejects), capped, never GC --
    (let* ((big (make-array 4096 :element-type '(unsigned-byte 8) :initial-element 9))
           (cbig (dds.security:encode-serialized-payload km big))
           (src (%make-test-prefix #xAB)) (wid #x00000102)
           (node (let ((dds.disc:*shmem-enabled* nil))
                   (dds.disc:make-disc-node :guid-prefix (%make-test-prefix #xEB) :domain (test-domain +td-secured-zeroalloc-decode+)
                                            :host "127.0.0.1" :port 0 :multicast nil :crypto-transform km))))
      (unwind-protect
           (let ((guid (dds.disc::%source-guid src wid)) (cap 1) (head 1))
             (dds.disc:enable-subscriber node)
             (let ((dds.disc:*secured-pool-capacity* cap) (dds.disc:*secured-pool-headroom* head))
               (dds.disc:set-secured-loan-capable node t))   ; carve decode pool of capacity 1+1 = 2
             (let ((before (dds.pal:bytes-consed)))
               (loop for sn from 1 to 5000 do (dds.disc::%deliver-user-sample node wid sn cbig src guid sn))   ; loans never returned -> exhaust
               (%check :decode-exhaust-rejected
                       (>= (dds.disc:disc-node-decode-pool-rejects node) 1)
                       "decode pool exhaustion must increment decode-pool-rejects (SAMPLE_REJECTED), never a GC fallback")
               (%check :decode-exhaust-capped
                       (<= (dds.disc:node-sample-count node) (+ cap head))
                       (format nil "only pool-capacity (~d) samples are admitted; got ~d" (+ cap head) (dds.disc:node-sample-count node)))
               (when sbcl
                 (let ((per (/ (float (- (dds.pal:bytes-consed) before)) 5000)))
                   (%check :decode-exhaust-no-gc (< per 256.0)
                           (format nil "exhausted deliver conses ~,4f B/sample — far below the ~d-B plaintext (no GC fallback)"
                                   per (length big)))))))
        (dds.disc:stop-node node))))
  t)

(defun* run-secured-submsg-exhaust-passthrough-test ()
    (function () t)
  "WP-DDS-SECURITY-ZEROALLOC-AEAD T4 (ZA-2) REVIEW: on submessage-scratch pool EXHAUSTION,
   %maybe-wrap-user-submessages must PASS THROUGH (return LEN, byte-identical) a datagram carrying NO
   protectable user submessage — NOT drop it — while STILL fail-closed (NIL) dropping a datagram that DOES
   carry a protectable submessage (a required wrap that could not be performed: never emit an unprotected
   datagram to a keyed peer). Regression guard: pre-fix the exhausted path unconditionally returned NIL,
   dropping even a no-wrap datagram (a false REJECT — the worst class). The exhausted path walks headers +
   the resolver only (no AES-GCM), so this runs UNCONDITIONALLY on BOTH impls (Clasp first).
     (a) DIRECT pre-scan: %prescan-user-submessages returns LEN for an INFO_DST+INFO_TS datagram and NIL for
         an INFO_DST+DATA datagram — the shared %submessage-extent walk + %user-submessage-protectable-p
         predicate, the SAME the wrap loop uses (so pre-scan and wrap CANNOT diverge into a leak).
     (b) INTEGRATION (pool drained): %maybe-wrap-user-submessages passes the INFO-only datagram THROUGH
         (returns LEN) — the RED->GREEN of the review (pre-fix this returned NIL) — and still DROPS (NIL) the
         DATA datagram (required-wrap fail-closed preserved).
     (c) ZERO-ALLOC: the pre-scan conses nothing (SBCL-exact dds.pal:bytes-consed; Clasp reports 0 -> skip)."
  (let* ((km   (dds.security:make-test-key-material))
         (node (let ((dds.disc:*shmem-enabled* nil))
                 (dds.disc:make-disc-node :guid-prefix (%make-test-prefix #xE7)
                                          :domain (test-domain +td-secured-submsg-exhaust+)
                                          :host "127.0.0.1" :port 0 :multicast nil)))
         (sbcl (eq (dds.pal:pal-impl-name) :sbcl))
         (info-specs (list (cons dds.rtps.message:+submsg-info-dst+ 12)
                           (cons dds.rtps.message:+submsg-info-ts+ 8)))         ; nothing protectable (INFO_* only)
         (data-specs (list (cons dds.rtps.message:+submsg-info-dst+ 12)
                           (cons dds.rtps.message:+submsg-data+ 16))))          ; INFO then a protectable DATA
    (flet ((datagram (specs)                          ; build over a GC-heap array (read-only path; no static leak)
             (let* ((buf (dds.core.buffer:octet-buffer-over
                          (make-array 256 :element-type '(unsigned-byte 8) :initial-element 0)))
                    (mc  (dds.core.buffer:cursor buf :endianness :little)))
               (dds.rtps.message:write-header mc (%make-test-prefix #x01))
               (dolist (s specs)                      ; E-flag set (LE) so octetsToNextHeader is read LE = the body-len
                 (dds.rtps.message:write-submessage-header mc (car s) #x01 (cdr s))
                 (dotimes (k (cdr s)) (dds.core.buffer:put-u8 mc 0)))
               (values buf (dds.core.buffer:cursor-position mc)))))
      (unwind-protect
           (progn
             ;; metadata_protection ON (keyed): the resolver returns a KM for any writer/reader submessage.
             (setf (dds.disc:disc-node-user-submessage-protection-kind node) :encrypt
                   (dds.disc:disc-node-user-submessage-encode node)
                   (lambda (writer-p) (declare (ignore writer-p)) (values km :encrypt)))
             ;; (a) DIRECT pre-scan classification.
             (multiple-value-bind (ibuf ilen) (datagram info-specs)
               (%check :prescan-passthrough (eql (dds.disc::%prescan-user-submessages node ibuf ilen) ilen)
                       "pre-scan: a no-protectable-submessage datagram must return LEN (pass-through)"))
             (multiple-value-bind (dbuf dlen) (datagram data-specs)
               (%check :prescan-required-drop (null (dds.disc::%prescan-user-submessages node dbuf dlen))
                       "pre-scan: a datagram with a protectable (DATA) submessage must return NIL (fail-closed)"))
             ;; (b) INTEGRATION: drain the submessage-scratch pool, then exercise the full wrap entry point.
             (let ((pool (dds.disc::%ensure-submsg-scratch-pool node)) (held '()))
               (loop for b = (dds.core.arena:pool-acquire pool) while b do (push b held))   ; borrow ALL -> exhausted
               (unwind-protect
                    (progn
                      (multiple-value-bind (ibuf ilen) (datagram info-specs)
                        (%check :exhaust-passthrough
                                (eql (dds.disc::%maybe-wrap-user-submessages node ibuf ilen) ilen)
                                "EXHAUSTED submsg-scratch + a no-protectable-submessage datagram must PASS THROUGH (LEN), not drop (ZA-2 regression)"))
                      (multiple-value-bind (dbuf dlen) (datagram data-specs)
                        (%check :exhaust-required-drop
                                (null (dds.disc::%maybe-wrap-user-submessages node dbuf dlen))
                                "EXHAUSTED submsg-scratch + a protectable (DATA) datagram must stay fail-closed (NIL drop)"))
                      ;; (c) ZERO-ALLOC pre-scan (raw-offset walk + predicate cons nothing).
                      (multiple-value-bind (ibuf ilen) (datagram info-specs)
                        (dds.disc::%prescan-user-submessages node ibuf ilen)   ; warm
                        (if (not sbcl)
                            (format t "~&  [submsg-exhaust] bytes-consed 0 on this impl (Clasp NFR-PORT) — pre-scan alloc not measurable~%")
                            (let ((before (dds.pal:bytes-consed)))
                              (dotimes (i 50000) (dds.disc::%prescan-user-submessages node ibuf ilen))
                              (let ((per (/ (float (- (dds.pal:bytes-consed) before)) 50000)))
                                (format t "~&  [submsg-exhaust] pre-scan bytes/call = ~,4f (50000 iters)~%" per)
                                (%check :prescan-zero-alloc (< per 1.0)
                                        (format nil "the exhaustion pre-scan must be zero-alloc; got ~,4f B/call" per)))))))
                 (dolist (b held) (dds.core.arena:pool-release pool b)))))
        (dds.disc:stop-node node))))
  t)

;;; DDS-Security 1.1 §7.3.7 shared crypto wire codec (Slice 4 T1): the CryptoHeader (20B) /
;;; CryptoContent (length-prefixed) / CryptoFooter (common_mac + receiver_specific_macs list)
;;; elements that submessage-protection (T2), RTPS-message-protection (T4), and the Slice-1
;;; serialized-payload tier all reuse. Pure wire codec — no OpenSSL — so it runs unconditionally.

(defun* run-security-crypto-header-corpus-test ()
    (function () t)
  "DDS-Security 1.1 §7.3.7 shared crypto wire codec (Slice 4 T1) byte-exact + round-trip corpus:
   (1) serialize/parse-crypto-header — the 20-byte CryptoHeader, byte-exact + field round-trip.
   (2) parse-crypto-header fail-closed on < 20 octets -> NIL (no OOB read).
   (3) serialize/parse-crypto-content — uint32-length-prefixed CryptoContent, byte-exact + round-trip.
   (4) parse-crypto-content fail-closed: an over-declared length -> NIL (cap before allocate).
   (5) serialize/parse-crypto-footer with 0 receiver-MACs (the empty footer == Slice-1 SecureDataTag).
   (6) serialize/parse-crypto-footer with 2 receiver-MACs (key_id + GMAC entries), byte-exact + round-trip.
   (7) parse-crypto-footer fail-closed: truncated footer and count > +max-receiver-specific-macs+ -> NIL.
   (8) composition: header || content || footer via ONE cursor, parsed back (the T2/T4 usage pattern).
   (9) Slice-1 byte-identity regression: serialize/parse-secured-payload still produce/round-trip the
       pinned 48-octet vector after the DRY refactor to delegate to this codec.
   Pure wire codec (no crypto) — both SBCL and Clasp must pass identically (Clasp FIRST)."
  ;; (1) CryptoHeader 20-byte byte-exact + round-trip (reuses the Slice-1 known header fields).
  (let* ((kind       (%hex-octets "00000004"))
         (key-id     (%hex-octets "aabbccdd"))
         (session-id (%hex-octets "01000000"))
         (iv-suffix  (%hex-octets "1122334455667788"))
         (expected   (%hex-octets "00000004aabbccdd010000001122334455667788"))
         (out        (make-array 20 :element-type '(unsigned-byte 8)))
         (cur        (dds.core.buffer:cursor (dds.core.buffer:octet-buffer-over out) :endianness :little))
         (n          (dds.security:serialize-crypto-header cur kind key-id session-id iv-suffix)))
    (%check :crypto-header-bytes-written (= n 20) "serialize-crypto-header must return 20")
    (%check :crypto-header-byte-exact (equalp out expected)
            (format nil "CryptoHeader byte mismatch; got ~{~2,'0x~^ ~}" (coerce out 'list)))
    (let ((rc (dds.core.buffer:cursor (dds.core.buffer:octet-buffer-over expected) :endianness :little)))
      (multiple-value-bind (p-kind p-key-id p-sid p-iv) (dds.security:parse-crypto-header rc)
        (%check :crypto-header-rt-kind   (equalp p-kind kind)        "parse-crypto-header kind round-trip")
        (%check :crypto-header-rt-key-id (equalp p-key-id key-id)    "parse-crypto-header key_id round-trip")
        (%check :crypto-header-rt-sid    (equalp p-sid session-id)   "parse-crypto-header session_id round-trip")
        (%check :crypto-header-rt-iv     (equalp p-iv iv-suffix)     "parse-crypto-header iv_suffix round-trip"))))
  ;; (2) CryptoHeader fail-closed: < 20 octets -> NIL.
  (dolist (short-len '(0 1 19))
    (let ((rc (dds.core.buffer:cursor
               (dds.core.buffer:octet-buffer-over
                (make-array short-len :element-type '(unsigned-byte 8) :initial-element 0))
               :endianness :little)))
      (%check :crypto-header-short-nil (null (dds.security:parse-crypto-header rc))
              (format nil "parse-crypto-header on ~d octets must return NIL" short-len))))
  ;; (3) CryptoContent length-prefixed byte-exact + round-trip. Length is BIG-ENDIAN (§9.5.3.3.4.4; T-RECONCILE).
  (let* ((ciphertext (%hex-octets "deadbeef"))
         (expected   (%hex-octets "00000004deadbeef"))
         (out        (make-array 8 :element-type '(unsigned-byte 8)))
         (cur        (dds.core.buffer:cursor (dds.core.buffer:octet-buffer-over out) :endianness :little))
         (n          (dds.security:serialize-crypto-content cur ciphertext)))
    (%check :crypto-content-bytes-written (= n 8) "serialize-crypto-content must return 4+len")
    (%check :crypto-content-byte-exact (equalp out expected)
            (format nil "CryptoContent byte mismatch; got ~{~2,'0x~^ ~}" (coerce out 'list)))
    (let ((rc (dds.core.buffer:cursor (dds.core.buffer:octet-buffer-over expected) :endianness :little)))
      (%check :crypto-content-rt (equalp (dds.security:parse-crypto-content rc) ciphertext)
              "parse-crypto-content round-trip")))
  ;; (4) CryptoContent fail-closed: declared length overflows buffer -> NIL.
  (let ((rc (dds.core.buffer:cursor (dds.core.buffer:octet-buffer-over (%hex-octets "ffffffff00"))
                                    :endianness :little)))
    (%check :crypto-content-overflow-nil (null (dds.security:parse-crypto-content rc))
            "parse-crypto-content with over-declared length must return NIL (cap before allocate)"))
  ;; (5) CryptoFooter, 0 receiver-MACs (empty footer == Slice-1 SecureDataTag).
  (let* ((common-mac (%hex-octets "a0a1a2a3a4a5a6a7a8a9aaabacadaeaf"))
         (expected   (%hex-octets "a0a1a2a3a4a5a6a7a8a9aaabacadaeaf00000000"))
         (out        (make-array 20 :element-type '(unsigned-byte 8)))
         (cur        (dds.core.buffer:cursor (dds.core.buffer:octet-buffer-over out) :endianness :little))
         (n          (dds.security:serialize-crypto-footer cur common-mac '())))
    (%check :crypto-footer0-bytes-written (= n 20) "serialize-crypto-footer (0 macs) must return 20")
    (%check :crypto-footer0-byte-exact (equalp out expected)
            (format nil "CryptoFooter(0) byte mismatch; got ~{~2,'0x~^ ~}" (coerce out 'list)))
    (let ((rc (dds.core.buffer:cursor (dds.core.buffer:octet-buffer-over expected) :endianness :little)))
      (multiple-value-bind (p-mac p-macs) (dds.security:parse-crypto-footer rc)
        (%check :crypto-footer0-rt-mac   (equalp p-mac common-mac) "parse-crypto-footer(0) common_mac round-trip")
        (%check :crypto-footer0-rt-empty (null p-macs)             "parse-crypto-footer(0) receiver-macs must be empty"))))
  ;; (6) CryptoFooter, 2 receiver-MACs (each = key_id(4) || GMAC(16)). Count is BIG-ENDIAN (§9.5.3.3.3; T-RECONCILE).
  (let* ((common-mac (%hex-octets "a0a1a2a3a4a5a6a7a8a9aaabacadaeaf"))
         (kid1 (%hex-octets "11111111")) (mac1 (%hex-octets "b0b1b2b3b4b5b6b7b8b9babbbcbdbebf"))
         (kid2 (%hex-octets "22222222")) (mac2 (%hex-octets "c0c1c2c3c4c5c6c7c8c9cacbcccdcecf"))
         (rmacs (list (cons kid1 mac1) (cons kid2 mac2)))
         (expected (%hex-octets (concatenate 'string
                     "a0a1a2a3a4a5a6a7a8a9aaabacadaeaf" "00000002"
                     "11111111" "b0b1b2b3b4b5b6b7b8b9babbbcbdbebf"
                     "22222222" "c0c1c2c3c4c5c6c7c8c9cacbcccdcecf")))
         (out (make-array 60 :element-type '(unsigned-byte 8)))
         (cur (dds.core.buffer:cursor (dds.core.buffer:octet-buffer-over out) :endianness :little))
         (n   (dds.security:serialize-crypto-footer cur common-mac rmacs)))
    (%check :crypto-footer2-bytes-written (= n 60) "serialize-crypto-footer (2 macs) must return 60")
    (%check :crypto-footer2-byte-exact (equalp out expected)
            (format nil "CryptoFooter(2) byte mismatch; got ~{~2,'0x~^ ~}" (coerce out 'list)))
    (let ((rc (dds.core.buffer:cursor (dds.core.buffer:octet-buffer-over expected) :endianness :little)))
      (multiple-value-bind (p-mac p-macs) (dds.security:parse-crypto-footer rc)
        (%check :crypto-footer2-rt-mac   (equalp p-mac common-mac)  "parse-crypto-footer(2) common_mac round-trip")
        (%check :crypto-footer2-rt-count (= (length p-macs) 2)      "parse-crypto-footer(2) must return 2 entries")
        (%check :crypto-footer2-rt-e0 (and (equalp (car (first p-macs)) kid1) (equalp (cdr (first p-macs)) mac1))
                "parse-crypto-footer(2) entry 0 (key_id . mac) round-trip")
        (%check :crypto-footer2-rt-e1 (and (equalp (car (second p-macs)) kid2) (equalp (cdr (second p-macs)) mac2))
                "parse-crypto-footer(2) entry 1 (key_id . mac) round-trip"))))
  ;; (7) CryptoFooter fail-closed: truncated (< 20) and count > +max-receiver-specific-macs+ -> NIL.
  (dolist (short-len '(0 15 19))
    (let ((rc (dds.core.buffer:cursor
               (dds.core.buffer:octet-buffer-over
                (make-array short-len :element-type '(unsigned-byte 8) :initial-element 0))
               :endianness :little)))
      (%check :crypto-footer-short-nil (null (dds.security:parse-crypto-footer rc))
              (format nil "parse-crypto-footer on ~d octets must return NIL" short-len))))
  (let ((blob (make-array 20 :element-type '(unsigned-byte 8) :initial-element 0)))
    ;; the rsm_count is BIG-ENDIAN on the wire (§9.5.3.3.3; T-RECONCILE), so write it big-endian for parse to read it.
    (let ((wc (dds.core.buffer:cursor (dds.core.buffer:octet-buffer-over blob) :endianness :big)))
      (dds.core.buffer:cursor-set-position wc 16)
      (dds.core.buffer:put-u32 wc (+ dds.security:+max-receiver-specific-macs+ 1)))
    (let ((rc (dds.core.buffer:cursor (dds.core.buffer:octet-buffer-over blob) :endianness :little)))
      (%check :crypto-footer-cap-nil (null (dds.security:parse-crypto-footer rc))
              "parse-crypto-footer with count > +max-receiver-specific-macs+ must return NIL (cap before allocate)")))
  ;; (8) Composition (T2/T4 usage): header || content || footer(1) via ONE cursor, parsed back.
  (let* ((kind (%hex-octets "00000004")) (key-id (%hex-octets "aabbccdd"))
         (session-id (%hex-octets "01000000")) (iv-suffix (%hex-octets "1122334455667788"))
         (ciphertext (%hex-octets "cafebabe"))
         (common-mac (%hex-octets "a0a1a2a3a4a5a6a7a8a9aaabacadaeaf"))
         (kid1 (%hex-octets "11111111")) (mac1 (%hex-octets "b0b1b2b3b4b5b6b7b8b9babbbcbdbebf"))
         (rmacs (list (cons kid1 mac1)))
         (total (+ 20 8 (+ 16 4 20)))
         (out (make-array total :element-type '(unsigned-byte 8)))
         (wc  (dds.core.buffer:cursor (dds.core.buffer:octet-buffer-over out) :endianness :little)))
    (dds.security:serialize-crypto-header wc kind key-id session-id iv-suffix)
    (dds.security:serialize-crypto-content wc ciphertext)
    (dds.security:serialize-crypto-footer wc common-mac rmacs)
    (let ((rc (dds.core.buffer:cursor (dds.core.buffer:octet-buffer-over out) :endianness :little)))
      (multiple-value-bind (p-kind p-key-id p-sid p-iv) (dds.security:parse-crypto-header rc)
        (let ((p-ct (dds.security:parse-crypto-content rc)))
          (multiple-value-bind (p-mac p-macs) (dds.security:parse-crypto-footer rc)
            (%check :crypto-compose
                    (and (equalp p-kind kind) (equalp p-key-id key-id) (equalp p-sid session-id)
                         (equalp p-iv iv-suffix) (equalp p-ct ciphertext) (equalp p-mac common-mac)
                         (= (length p-macs) 1)
                         (equalp (car (first p-macs)) kid1) (equalp (cdr (first p-macs)) mac1))
                    "header || content || footer compose + parse round-trip (T2/T4 usage)"))))))
  ;; (9) Slice-1 byte-identity regression: serialize/parse-secured-payload after the DRY refactor.
  (let* ((kind (%hex-octets "00000004")) (key-id (%hex-octets "aabbccdd"))
         (session-id (%hex-octets "01000000")) (iv-suffix (%hex-octets "1122334455667788"))
         (ciphertext (%hex-octets "deadbeef")) (tag (%hex-octets "a0a1a2a3a4a5a6a7a8a9aaabacadaeaf"))
         (expected (%hex-octets (concatenate 'string
                     "00000004" "aabbccdd" "01000000" "1122334455667788"
                     "00000004" "deadbeef" "a0a1a2a3a4a5a6a7a8a9aaabacadaeaf" "00000000")))
         (got (dds.security:serialize-secured-payload kind key-id session-id iv-suffix ciphertext tag)))
    (%check :slice1-byte-identical (equalp got expected)
            (format nil "Slice-1 SecuredPayload byte-identity regression; got ~{~2,'0x~^ ~}" (coerce got 'list)))
    (multiple-value-bind (p-kind p-key-id p-sid p-iv p-ct p-tag) (dds.security:parse-secured-payload got)
      (%check :slice1-rt
              (and (equalp p-kind kind) (equalp p-key-id key-id) (equalp p-sid session-id)
                   (equalp p-iv iv-suffix) (equalp p-ct ciphertext) (equalp p-tag tag))
              "Slice-1 parse-secured-payload round-trip after refactor")))
  t)

;;; --- Slice 4 T2: §8.5.1.7-.9 submessage protection (SEC_PREFIX ... SEC_POSTFIX; SEC_BODY for
;;; ENCRYPT, original submessage verbatim for SIGN per §9.5.3.3.4.3) ---

(defun* %t2-fixed-plain-submessage ()
    (function () (simple-array (unsigned-byte 8) (*)))
  "A fixed 32-octet stand-in 'plain RTPS submessage' for the T2 corpus (deterministic; the transform
   is content-agnostic). Recognisable bytes so SEARCH can prove plaintext present/absent on the wire."
  (%hex-octets "15051c0000001000000100000000000001000000000000004041424344454647"))

(defun* %t2-encrypt-vector ()
    (function () (or (simple-array (unsigned-byte 8) (*)) null))
  "The deterministic full 88-octet ENCRYPT secured-submessage corpus vector for
   (make-test-key-material, :encrypt, %t2-fixed-plain-submessage) — fresh km (iv_suffix=0, session_id=0),
   so the AES-256-GCM ciphertext + common_mac are fixed + reproducible on SBCL and Clasp (same OpenSSL).
   Pins the framing AND the empty-AAD ENCRYPT crypto output: a change to the AAD decision breaks this."
  (%hex-octets (concatenate 'string
    "31011400" "00000004" "deadbeef" "00000000" "0000000000000000"   ; SEC_PREFIX + CryptoHeader{GCM}
    "30012400" "00000020"                                            ; SEC_BODY hdr + ct_len=32 BE
    "d1bd9271c1ed8ad90d8c7d7d6cf3d3f5" "e9675f30d58adea818c2583b5c8b2183" ; ciphertext(32)
    "32011400"                                                       ; SEC_POSTFIX hdr
    "d677c4601e4b1ec56b28c5f3cf5d7cd5"                               ; common_mac(16)
    "00000000")))                                                    ; rsm_count=0

(defun* %t2-sign-vector ()
    (function () (or (simple-array (unsigned-byte 8) (*)) null))
  "The deterministic full 80-octet SIGN secured-submessage corpus vector for
   (make-test-key-material, :sign, %t2-fixed-plain-submessage). Per §9.5.3.3.4.3 SIGN/GMAC inserts NO
   SEC_BODY — the ORIGINAL submessage sits VERBATIM between SEC_PREFIX and SEC_POSTFIX; only the
   16-octet common_mac is a GMAC over it. Pins the conformant SIGN framing (no SEC_BODY) + the
   original-submessage-as-AAD GMAC + the AES256_GMAC {0,0,0,3} kind: a change to the framing or the AAD
   decision breaks this. The GMAC is unchanged from the prior (non-conformant SEC_BODY) framing — it is
   computed over the same plaintext AAD, key and nonce; only the wrapping changed."
  (%hex-octets (concatenate 'string
    "31011400" "00000003" "deadbeef" "00000000" "0000000000000000"   ; SEC_PREFIX + CryptoHeader{GMAC} (24)
    "15051c0000001000000100000000000001000000000000004041424344454647" ; original submessage VERBATIM(32), NO SEC_BODY
    "32011400"                                                       ; SEC_POSTFIX hdr
    "1fbc522bb1eea5a7f0e7476f0965009d"                               ; common_mac=GMAC(16)
    "00000000")))                                                    ; rsm_count=0

;;; Split into per-aspect helpers: each is a small compilation unit (a single ~150-line function makes
;;; SBCL's flow analysis super-linear and very slow to compile; small functions compile fast + read clearer).

(defun* %t2-flip (octets index mask)
    (function ((simple-array (unsigned-byte 8) (*)) fixnum (unsigned-byte 8))
              (simple-array (unsigned-byte 8) (*)))
  "Return a fresh copy of OCTETS with the octet at INDEX XOR'd by MASK (test mutation helper)."
  (let ((b (copy-seq octets)))
    (setf (aref b index) (logxor (aref b index) mask))
    b))

(defun* %t2-set (octets index value)
    (function ((simple-array (unsigned-byte 8) (*)) fixnum (unsigned-byte 8))
              (simple-array (unsigned-byte 8) (*)))
  "Return a fresh copy of OCTETS with the octet at INDEX set to VALUE (test mutation helper)."
  (let ((b (copy-seq octets)))
    (setf (aref b index) value)
    b))

(defun* %t2-corpus-encrypt (sub)
    (function ((simple-array (unsigned-byte 8) (*))) t)
  "T2 corpus block (1): ENCRYPT byte-exact + structural invariants for a fresh test-km + SUB."
  (let* ((km  (dds.security:make-test-key-material))
         (enc (dds.security:encode-datawriter-submessage km :encrypt sub)))
    (%check :t2-encrypt-len (= (length enc) 88)
            (format nil "ENCRYPT secured submessage must be 88 octets; got ~d" (length enc)))
    (%check :t2-encrypt-prefix-exact
            (equalp (subseq enc 0 32)
                    (%hex-octets (concatenate 'string
                      "31011400" "00000004" "deadbeef" "00000000" "0000000000000000"
                      "30012400" "00000020")))
            "ENCRYPT deterministic prefix (SEC_PREFIX+CryptoHeader{GCM}+SEC_BODY hdr+ct_len BE) byte-exact")
    (when (%t2-encrypt-vector)
      (%check :t2-encrypt-byte-exact (equalp enc (%t2-encrypt-vector))
              (format nil "ENCRYPT full 88-octet vector byte mismatch; got ~{~2,'0x~^ ~}" (coerce enc 'list))))
    (%check :t2-encrypt-postfix-hdr (equalp (subseq enc 64 68) (%hex-octets "32011400"))
            "ENCRYPT SEC_POSTFIX header byte-exact (id 0x32, E=1, octn=20)")
    (%check :t2-encrypt-rsm0 (equalp (subseq enc 84 88) (%hex-octets "00000000"))
            "ENCRYPT CryptoFooter receiver_specific_macs_count = 0")
    (%check :t2-encrypt-plaintext-absent (null (search sub enc))
            "ENCRYPT: the plaintext submessage must NOT appear on the wire (ciphertext)"))
  t)

(defun* %t2-corpus-sign (sub)
    (function ((simple-array (unsigned-byte 8) (*))) t)
  "T2 corpus block (2): SIGN byte-exact — original submessage VERBATIM between SEC_PREFIX and
   SEC_POSTFIX with NO SEC_BODY (§9.5.3.3.4.3), GMAC common_mac, kind=GMAC."
  (let* ((km  (dds.security:make-test-key-material))
         (sgn (dds.security:encode-datawriter-submessage km :sign sub)))
    (%check :t2-sign-len (= (length sgn) 80)
            (format nil "SIGN secured submessage must be 80 octets (no SEC_BODY); got ~d" (length sgn)))
    (%check :t2-sign-prefix-exact
            (equalp (subseq sgn 0 24)
                    (%hex-octets (concatenate 'string
                      "31011400" "00000003" "deadbeef" "00000000" "0000000000000000")))
            "SIGN deterministic prefix (SEC_PREFIX + CryptoHeader kind = AES256_GMAC {0,0,0,3}) byte-exact, NO SEC_BODY")
    (%check :t2-sign-body-verbatim
            (and (eql (search sub sgn) 24) (equalp (subseq sgn 24 56) sub))
            "SIGN: the original submessage is VERBATIM between SEC_PREFIX and SEC_POSTFIX at offset 24 (no SEC_BODY)")
    (%check :t2-sign-no-sec-body (not (eql (aref sgn 24) dds.security:+submessage-sec-body+))
            "SIGN: no SEC_BODY (0x30) follows the CryptoHeader — the original submessage begins immediately at offset 24 (conformant framing)")
    (when (%t2-sign-vector)
      (%check :t2-sign-byte-exact (equalp sgn (%t2-sign-vector))
              (format nil "SIGN full 80-octet vector byte mismatch; got ~{~2,'0x~^ ~}" (coerce sgn 'list))))
    (%check :t2-sign-postfix-hdr (equalp (subseq sgn 56 60) (%hex-octets "32011400"))
            "SIGN SEC_POSTFIX header byte-exact")
    (%check :t2-sign-rsm0 (equalp (subseq sgn 76 80) (%hex-octets "00000000"))
            "SIGN CryptoFooter receiver_specific_macs_count = 0"))
  t)

(defun* %t2-corpus-sign-aad-span (sub)
    (function ((simple-array (unsigned-byte 8) (*))) t)
  "T2 corpus block (2b) — ADR-0037 SIGN-AAD regression pin (§8.5.1.9 datawriter submessage protection /
   §9.5.3.3.4.3): assert our SIGN encode's common_mac is the GMAC computed over AAD = EXACTLY the verbatim
   (visible) submessage region between SEC_PREFIX and SEC_POSTFIX — the confirmed cross-vendor-conformant span.
   Recomputes the GMAC OUR-TO-OUR via %seal-with-km under the CryptoHeader's OWN session_id/iv_suffix (empty
   plaintext => a pure GMAC over the AAD) and equalp-compares it to the on-wire common_mac; an off-by-one wider
   span must NOT reproduce it (the boundary is exact). A future codec change that widened/narrowed the SIGN AAD
   span FAILS here rather than silently regressing cross-vendor SIGN. Additive assertion; no corpus regen."
  (let* ((km      (dds.security:make-test-key-material))
         (sgn     (dds.security:encode-datawriter-submessage km :sign sub))
         (n       (length sub))
         (sid     (subseq sgn 12 16))                 ; §7.3.7 CryptoHeader session_id (after SEC_PREFIX hdr(4)+kind(4)+key_id(4))
         (ivs     (subseq sgn 16 24))                 ; §7.3.7 CryptoHeader init_vector_suffix (8)
         (span    (subseq sgn 24 (+ 24 n)))           ; AAD = the verbatim visible submessage (NO SEC_BODY), offset 24..24+len
         (mac-off (+ 24 n 4))                         ; common_mac follows the SEC_POSTFIX submessage header (4)
         (wire-mac (subseq sgn mac-off (+ mac-off 16)))
         (empty   (make-array 0 :element-type '(unsigned-byte 8))))
    (%check :t2-sign-aad-visible-is-input (equalp span sub)
            "SIGN: the visible AAD span (offset 24..24+len) must be the ORIGINAL submessage verbatim")
    (multiple-value-bind (ct tag) (dds.security::%seal-with-km km sid ivs span empty)
      (declare (ignore ct))
      (%check :t2-sign-aad-span-gmac (equalp tag wire-mac)
              "SIGN common_mac MUST equal GMAC over AAD = the verbatim visible submessage span (§8.5.1.9 / §9.5.3.3.4.3) — the on-wire GMAC pins the exact AAD span (a widened/narrowed span would break cross-vendor SIGN)"))
    (multiple-value-bind (ct tag) (dds.security::%seal-with-km km sid ivs (subseq sgn 23 (+ 24 n)) empty)
      (declare (ignore ct))
      (%check :t2-sign-aad-span-boundary-exact (not (equalp tag wire-mac))
              "SIGN AAD span boundary is EXACT: a GMAC over a one-octet-wider span (offset 23, one CryptoHeader byte) must NOT match the on-wire common_mac")))
  t)

(defun* %t2-corpus-roundtrip (sub)
    (function ((simple-array (unsigned-byte 8) (*))) t)
  "T2 corpus block (3): round-trip both KINDs, both directions — decode(encode(km,KIND,SUB)) = SUB."
  (dolist (kind '(:encrypt :sign) t)
    (let* ((kmw (dds.security:make-test-key-material))
           (dec (dds.security:decode-datawriter-submessage
                 kmw (dds.security:encode-datawriter-submessage kmw kind sub))))
      (%check :t2-writer-roundtrip (and dec (equalp dec sub))
              (format nil "datawriter ~a round-trip must recover the plaintext byte-exact" kind)))
    (let* ((kmr (dds.security:make-test-key-material))
           (dec (dds.security:decode-datareader-submessage
                 kmr (dds.security:encode-datareader-submessage kmr kind sub))))
      (%check :t2-reader-roundtrip (and dec (equalp dec sub))
              (format nil "datareader ~a round-trip must recover the plaintext byte-exact" kind)))))

(defun* %t2-decode-dw (blob)
    (function ((simple-array (unsigned-byte 8) (*))) (or (simple-array (unsigned-byte 8) (*)) null))
  "Decode BLOB with a fresh same-key test km (the negatives feed adversarial BLOBs); NIL = rejected."
  (dds.security:decode-datawriter-submessage (dds.security:make-test-key-material) blob))

(defun* %t2-corpus-negatives (sub)
    (function ((simple-array (unsigned-byte 8) (*))) t)
  "T2 corpus block (4): negatives — every one MUST fail-closed to NIL."
  (let* ((km  (dds.security:make-test-key-material))
         (enc (dds.security:encode-datawriter-submessage km :encrypt sub))
         (sgn (dds.security:encode-datawriter-submessage (dds.security:make-test-key-material) :sign sub))
         (km2 (dds.security:make-key-material
               :master-sender-key (make-array 32 :element-type '(unsigned-byte 8) :initial-element #xAA)
               :master-salt       (make-array 32 :element-type '(unsigned-byte 8) :initial-element #x55)
               :sender-key-id     (dds.security:key-material-sender-key-id km))))
    ;; control: a same-key fresh km decodes the vector, so each negative isolates the injected fault.
    (%check :t2-neg-control (equalp (%t2-decode-dw enc) sub)
            "control: a same-key fresh km decodes the ENCRYPT vector")
    (%check :t2-neg-wrong-key (null (dds.security:decode-datawriter-submessage km2 enc))
            "wrong master key must return NIL (GCM auth fail-closed)")
    (%check :t2-neg-flip-tag-encrypt (null (%t2-decode-dw (%t2-flip enc 68 #x80)))
            "ENCRYPT: a 1-octet common_mac flip must return NIL")
    ;; new 80-octet SIGN wire: common_mac(GMAC) at offset 60; original submessage at offsets 24..56.
    (%check :t2-neg-flip-tag-sign (null (%t2-decode-dw (%t2-flip sgn 60 #x01)))
            "SIGN: a 1-octet GMAC flip must return NIL")
    (%check :t2-neg-flip-ct (null (%t2-decode-dw (%t2-flip enc 32 #x01)))
            "ENCRYPT: a 1-octet ciphertext flip must return NIL")
    ;; SIGN body tamper (a content octet inside the verbatim original): NIL, and NEVER the tampered plaintext.
    (%check :t2-neg-flip-sign-body (null (%t2-decode-dw (%t2-flip sgn 40 #x01)))
            "SIGN: a 1-octet flip in the verbatim original submessage must return NIL (never the tampered plaintext)")
    (dolist (cut '(0 1 4 23 24 31 32 63 67 87))
      (%check :t2-neg-truncated (null (%t2-decode-dw (subseq enc 0 cut)))
              (format nil "truncated secured submessage (len=~d) must return NIL" cut)))
    (%check :t2-neg-reordered (null (%t2-decode-dw (%t2-set enc 0 dds.security:+submessage-sec-body+)))
            "a re-ordered bracket (SEC_PREFIX id corrupted) must return NIL")
    (%check :t2-neg-body-id (null (%t2-decode-dw (%t2-set enc 24 dds.security:+submessage-sec-postfix+)))
            "a corrupted SEC_BODY submessageId must return NIL")
    ;; unknown transformation_kind (AES128_GCM {0,0,0,2}): CryptoHeader.kind low octet at offset 7.
    (%check :t2-neg-unknown-kind (null (%t2-decode-dw (%t2-set enc 7 #x02)))
            "an unknown/unsupported transformation_kind must return NIL (fail-closed)"))
  t)

(defun* run-security-submessage-corpus-test ()
    (function () t)
  "DDS-Security 1.1 §8.5.1.7-.9 submessage protection corpus (Slice 4 T2): the SEC_PREFIX(0x31) ...
   SEC_POSTFIX(0x32) bracket, SIGN + ENCRYPT, both directions. The middle region is mode-dependent:
   ENCRYPT inserts a SEC_BODY(0x30) ciphertext (§9.5.3.3.4.4); SIGN inserts NO SEC_BODY — the original
   submessage VERBATIM (§9.5.3.3.4.3).
   (1) ENCRYPT byte-exact: a fresh test-km + fixed submessage => the EXACT 88-octet secured vector
       (deterministic: monotonic iv_suffix=0, fixed key); the plaintext is NOT on the wire.
   (2) SIGN byte-exact: => the EXACT 80-octet secured vector; the original submessage IS verbatim
       between SEC_PREFIX and SEC_POSTFIX with no SEC_BODY; the CryptoHeader kind is AES256_GMAC
       {0,0,0,3} (vs GCM {0,0,0,4} for ENCRYPT).
   (3) round-trip: decode(encode(km,KIND,sub)) = sub byte-exact, both KINDs, both directions.
   (4) negatives, fail-closed -> NIL: wrong key; flipped common_mac; flipped ciphertext (ENCRYPT);
       flipped original submessage (SIGN — and NEVER returns the tampered plaintext); truncation;
       a re-ordered bracket; an unknown transformation_kind.
   Requires OpenSSL >= 3.5; skips only if truly absent. Both SBCL and Clasp must pass identically."
  (multiple-value-bind (%dare-ok %dare-reason) (dds.dare:dare-available-p)
    (unless %dare-ok
      (format t "~&  [security-submessage] SKIP — OpenSSL >= 3.5 not available: ~a~%"
              %dare-reason)
      (return-from run-security-submessage-corpus-test t)))
  (let ((sub (%t2-fixed-plain-submessage)))
    (%t2-corpus-encrypt sub)
    (%t2-corpus-sign sub)
    (%t2-corpus-sign-aad-span sub)
    (%t2-corpus-roundtrip sub)
    (%t2-corpus-negatives sub))
  t)

;;; --- Slice 4 T3: §9.5.3.3.4.3 origin authentication (the *_WITH_ORIGIN_AUTHENTICATION kinds) ---
;;; Per-matched-receiver key material + a receiver_specific_macs list in the CryptoFooter: encode emits a
;;; receiver-specific GMAC (over the common_mac, under each receiver's session key, SAME init vector as the
;;; common_mac) per receiver; decode finds + verifies its OWN entry (constant-time) IN ADDITION to the
;;; common_mac. The non-vacuity gate (the point): decode as a receiver with a WRONG receiver key MUST
;;; return NIL even though the common_mac is valid, while the SAME bytes decoded with origin-auth OFF MUST
;;; succeed on the common_mac alone — proving the failure is specifically the receiver-MAC check.

(defun* %t3-recvs ()
    (function () list)
  "The two FIXED origin-auth receiver descriptors (receiver-key-id . master-receiver-specific-key) for
   the T3 corpus: key_ids aaaa0001 / bbbb0002, master keys 0x11*32 / 0x22*32 (deterministic, non-secret).
   The footer carries one receiver_specific_macs entry per descriptor, in this order."
  (list (cons (%hex-octets "aaaa0001")
              (make-array 32 :element-type '(unsigned-byte 8) :initial-element #x11))
        (cons (%hex-octets "bbbb0002")
              (make-array 32 :element-type '(unsigned-byte 8) :initial-element #x22))))

(defun* %t3-encrypt-vector ()
    (function () (or (simple-array (unsigned-byte 8) (*)) null))
  "The deterministic full 128-octet ENCRYPT origin-auth secured-submessage corpus vector for
   (make-test-key-material, :encrypt, %t2-fixed-plain-submessage, :receivers (%t3-recvs)) — fresh km
   (iv_suffix=0, session_id=0). The SEC_PREFIX+CryptoHeader+SEC_BODY+ciphertext+common_mac are
   byte-identical to the plain T2 ENCRYPT vector; only the SEC_POSTFIX grows: octetsToNextHeader 20->60,
   rsm_count 0->2, then {aaaa0001‖GMAC} {bbbb0002‖GMAC}. The two GMACs are AES-256-GCM tags over the
   common_mac under each receiver-specific session key (same IV as the common_mac), reproducible across
   SBCL+Clasp (same OpenSSL). A change to the receiver-MAC input/IV/KDF breaks this."
  (%hex-octets (concatenate 'string
    "31011400" "00000004" "deadbeef" "00000000" "0000000000000000"   ; SEC_PREFIX + CryptoHeader{GCM}
    "30012400" "00000020"                                            ; SEC_BODY hdr + ct_len=32 BE
    "d1bd9271c1ed8ad90d8c7d7d6cf3d3f5" "e9675f30d58adea818c2583b5c8b2183" ; ciphertext(32) — == T2
    "32013c00"                                                       ; SEC_POSTFIX hdr (octn=0x3c=60)
    "d677c4601e4b1ec56b28c5f3cf5d7cd5"                               ; common_mac(16) — == T2 ENCRYPT
    "00000002"                                                       ; rsm_count = 2 (BIG-ENDIAN)
    "aaaa0001" "3b5d2ca626145cf53298633fa40b6a23"                    ; receiver 1: key_id ‖ GMAC
    "bbbb0002" "df1ae3df2b4f25a939e47d2024002ca3")))                 ; receiver 2: key_id ‖ GMAC

(defun* %t3-sign-vector ()
    (function () (or (simple-array (unsigned-byte 8) (*)) null))
  "The deterministic full 120-octet SIGN origin-auth secured-submessage corpus vector for
   (make-test-key-material, :sign, %t2-fixed-plain-submessage, :receivers (%t3-recvs)). Per §9.5.3.3.4.3
   SIGN inserts NO SEC_BODY — the original submessage is verbatim; the common_mac is the GMAC over it
   (== the plain T2 SIGN common_mac). The CryptoFooter then carries rsm_count=2 + the two receiver GMACs
   over that common_mac. A change to the framing or the receiver-MAC construction breaks this."
  (%hex-octets (concatenate 'string
    "31011400" "00000003" "deadbeef" "00000000" "0000000000000000"   ; SEC_PREFIX + CryptoHeader{GMAC}
    "15051c0000001000000100000000000001000000000000004041424344454647" ; original submessage VERBATIM(32)
    "32013c00"                                                       ; SEC_POSTFIX hdr (octn=0x3c=60)
    "1fbc522bb1eea5a7f0e7476f0965009d"                               ; common_mac=GMAC(16) — == T2 SIGN
    "00000002"                                                       ; rsm_count = 2 (BIG-ENDIAN)
    "aaaa0001" "7e292e0b5480357e1145a0fb27fc7059"                    ; receiver 1: key_id ‖ GMAC
    "bbbb0002" "95556dba66af84c62fd3e58359ec10eb")))                 ; receiver 2: key_id ‖ GMAC

(defun* %t3-corpus-encode (sub)
    (function ((simple-array (unsigned-byte 8) (*))) t)
  "T3 corpus block (1): byte-exact origin-auth encode — ENCRYPT (128) + SIGN (120) with 2 receivers, the
   footer carrying 2 {key_id,mac} entries; the receiver-MAC bytes are deterministic + reproducible."
  (let* ((km  (dds.security:make-test-key-material))
         (enc (dds.security:encode-datawriter-submessage km :encrypt sub :receivers (%t3-recvs)))
         (kmw (dds.security:make-test-key-material))
         (sgn (dds.security:encode-datareader-submessage kmw :sign sub :receivers (%t3-recvs))))
    ;; ENCRYPT byte-exact + structure.
    (%check :t3-encrypt-len (= (length enc) 128)
            (format nil "ENCRYPT+origin-auth must be 128 octets (88 + 2*20); got ~d" (length enc)))
    (%check :t3-encrypt-byte-exact (equalp enc (%t3-encrypt-vector))
            (format nil "ENCRYPT+origin-auth 128-octet vector byte mismatch; got ~(~{~2,'0x~}~)" (coerce enc 'list)))
    (%check :t3-encrypt-prefix-eq-t2 (equalp (subseq enc 0 64) (subseq (%t2-encrypt-vector) 0 64))
            "ENCRYPT+origin-auth bytes [0..63] (PREFIX+HEADER+BODY+ciphertext) == the plain T2 ENCRYPT vector")
    (%check :t3-encrypt-common-mac-eq-t2 (equalp (subseq enc 68 84) (subseq (%t2-encrypt-vector) 68 84))
            "ENCRYPT+origin-auth common_mac == the plain T2 ENCRYPT common_mac (receivers don't change the seal)")
    (%check :t3-encrypt-postfix-octn (equalp (subseq enc 64 68) (%hex-octets "32013c00"))
            "ENCRYPT+origin-auth SEC_POSTFIX octetsToNextHeader = 60 (0x3c) for a 2-receiver footer")
    (%check :t3-encrypt-rsm2 (equalp (subseq enc 84 88) (%hex-octets "00000002"))
            "ENCRYPT+origin-auth CryptoFooter receiver_specific_macs_count = 2 (BIG-ENDIAN)")
    (%check :t3-encrypt-kid0 (equalp (subseq enc 88 92) (%hex-octets "aaaa0001"))
            "ENCRYPT+origin-auth footer entry 0 key_id = aaaa0001")
    (%check :t3-encrypt-kid1 (equalp (subseq enc 108 112) (%hex-octets "bbbb0002"))
            "ENCRYPT+origin-auth footer entry 1 key_id = bbbb0002")
    ;; SIGN byte-exact + structure.
    (%check :t3-sign-len (= (length sgn) 120)
            (format nil "SIGN+origin-auth must be 120 octets (80 + 2*20); got ~d" (length sgn)))
    (%check :t3-sign-byte-exact (equalp sgn (%t3-sign-vector))
            (format nil "SIGN+origin-auth 120-octet vector byte mismatch; got ~(~{~2,'0x~}~)" (coerce sgn 'list)))
    (%check :t3-sign-rsm2 (equalp (subseq sgn 76 80) (%hex-octets "00000002"))
            "SIGN+origin-auth CryptoFooter receiver_specific_macs_count = 2 (BIG-ENDIAN)"))
  t)

(defun* %t3-corpus-decode (sub)
    (function ((simple-array (unsigned-byte 8) (*))) t)
  "T3 corpus block (2): the non-vacuous origin-auth gate, for BOTH ENCRYPT and SIGN, BOTH directions.
   On the SAME encoded bytes: decode as receiver #2 with the RIGHT key -> the plaintext; with a WRONG
   receiver key -> NIL even though the common_mac is valid; with an ABSENT key_id -> NIL; with
   origin-auth OFF -> the plaintext on the common_mac alone. The wrong-key/off pair on identical bytes is
   the non-vacuity proof: a vacuous gate could not make wrong-key NIL while off succeeds."
  (let ((kid2 (%hex-octets "bbbb0002"))
        (mk2  (make-array 32 :element-type '(unsigned-byte 8) :initial-element #x22))
        (wrong (make-array 32 :element-type '(unsigned-byte 8) :initial-element #x99))
        (absent (%hex-octets "cccc0003")))
    (dolist (kind '(:encrypt :sign) t)
      ;; datawriter direction
      (let* ((km  (dds.security:make-test-key-material))
             (blob (dds.security:encode-datawriter-submessage km kind sub :receivers (%t3-recvs))))
        (%check :t3-dw-right
                (equalp (dds.security:decode-datawriter-submessage
                         (dds.security:make-test-key-material) blob
                         :my-receiver-key-id kid2 :my-receiver-key mk2) sub)
                (format nil "~a datawriter: receiver #2 with the right key recovers the plaintext" kind))
        (%check :t3-dw-wrong-key
                (null (dds.security:decode-datawriter-submessage
                       (dds.security:make-test-key-material) blob
                       :my-receiver-key-id kid2 :my-receiver-key wrong))
                (format nil "~a datawriter: receiver #2 with a WRONG receiver key -> NIL (common_mac is valid; origin-auth gates)" kind))
        (%check :t3-dw-absent
                (null (dds.security:decode-datawriter-submessage
                       (dds.security:make-test-key-material) blob
                       :my-receiver-key-id absent :my-receiver-key mk2))
                (format nil "~a datawriter: an ABSENT receiver key_id -> NIL (no entry targets me)" kind))
        (%check :t3-dw-off
                (equalp (dds.security:decode-datawriter-submessage
                         (dds.security:make-test-key-material) blob) sub)
                (format nil "~a datawriter: origin-auth OFF decodes the SAME bytes on the common_mac alone (non-vacuity)" kind)))
      ;; datareader direction (same mechanism)
      (let* ((kmr  (dds.security:make-test-key-material))
             (blob (dds.security:encode-datareader-submessage kmr kind sub :receivers (%t3-recvs))))
        (%check :t3-dr-right
                (equalp (dds.security:decode-datareader-submessage
                         (dds.security:make-test-key-material) blob
                         :my-receiver-key-id kid2 :my-receiver-key mk2) sub)
                (format nil "~a datareader: receiver #2 with the right key recovers the plaintext" kind))
        (%check :t3-dr-wrong-key
                (null (dds.security:decode-datareader-submessage
                       (dds.security:make-test-key-material) blob
                       :my-receiver-key-id kid2 :my-receiver-key wrong))
                (format nil "~a datareader: a WRONG receiver key -> NIL (origin-auth gates)" kind))
        (%check :t3-dr-off
                (equalp (dds.security:decode-datareader-submessage
                         (dds.security:make-test-key-material) blob) sub)
                (format nil "~a datareader: origin-auth OFF decodes on the common_mac alone" kind)))))
  t)

(defun* %t3-kdf-mac-units ()
    (function () t)
  "T3 corpus block (3): KDF + MAC + generator unit checks.
   (a) derive-receiver-specific-session-key is deterministic, 32 octets, and DIFFERS from
       derive-session-key for the same inputs (the label 'SessionReceiverKey' vs 'SessionKey' is live).
   (b) compute-receiver-specific-mac is a 16-octet GMAC that round-trips (encode == recompute) and is
       sensitive to the common_mac, the IV, and the key.
   (c) generate-writer-key-material populates the receiver-specific slots only under :origin-auth t."
  (let* ((salt (dds.security:key-material-master-salt (dds.security:make-test-key-material)))
         (sid  (make-array 4 :element-type '(unsigned-byte 8) :initial-element 0))
         (rmk  (make-array 32 :element-type '(unsigned-byte 8) :initial-element #x11))
         (rsk1 (dds.security:derive-receiver-specific-session-key rmk salt sid))
         (rsk2 (dds.security:derive-receiver-specific-session-key rmk salt sid))
         (snd  (dds.security:derive-session-key rmk salt sid)))
    (%check :t3-kdf-len (= (length rsk1) 32) "derive-receiver-specific-session-key returns 32 octets")
    (%check :t3-kdf-deterministic (equalp rsk1 rsk2) "derive-receiver-specific-session-key is deterministic")
    (%check :t3-kdf-distinct-label (not (equalp rsk1 snd))
            "receiver-specific session key DIFFERS from the sender session key for the same inputs (label is live)")
    (let* ((nonce (make-array 12 :element-type '(unsigned-byte 8) :initial-element 0))
           (cmac  (%hex-octets "07b0926653cdc9711817032c7e1df610"))
           (m1    (dds.security:compute-receiver-specific-mac rsk1 nonce cmac))
           (m2    (dds.security:compute-receiver-specific-mac rsk1 nonce cmac))
           (nonce2 (make-array 12 :element-type '(unsigned-byte 8) :initial-element 1))
           (cmac2 (%hex-octets "00000000000000000000000000000000")))
      (%check :t3-mac-len (= (length m1) 16) "compute-receiver-specific-mac returns 16 octets")
      (%check :t3-mac-deterministic (equalp m1 m2) "compute-receiver-specific-mac is deterministic (recompute == encode)")
      (%check :t3-mac-iv-sensitive (not (equalp m1 (dds.security:compute-receiver-specific-mac rsk1 nonce2 cmac)))
              "compute-receiver-specific-mac depends on the IV")
      (%check :t3-mac-input-sensitive (not (equalp m1 (dds.security:compute-receiver-specific-mac rsk1 nonce cmac2)))
              "compute-receiver-specific-mac depends on the common_mac input")
      (%check :t3-mac-key-sensitive (not (equalp m1 (dds.security:compute-receiver-specific-mac snd nonce cmac)))
              "compute-receiver-specific-mac depends on the receiver session key")))
  (let* ((guid (make-array 16 :element-type '(unsigned-byte 8) :initial-element 7))
         (km-off (dds.security:generate-writer-key-material guid))
         (km-on  (dds.security:generate-writer-key-material guid :origin-auth t))
         (zeros4 (make-array 4 :element-type '(unsigned-byte 8) :initial-element 0))
         (zeros32 (make-array 32 :element-type '(unsigned-byte 8) :initial-element 0)))
    (%check :t3-gen-off-zero
            (and (equalp (dds.security:key-material-receiver-specific-key-id km-off) zeros4)
                 (equalp (dds.security:key-material-master-receiver-specific-key km-off) zeros32))
            "generate-writer-key-material (no :origin-auth) leaves the receiver-specific slots all-zero")
    (%check :t3-gen-on-populated
            (and (not (equalp (dds.security:key-material-receiver-specific-key-id km-on) zeros4))
                 (not (equalp (dds.security:key-material-master-receiver-specific-key km-on) zeros32)))
            "generate-writer-key-material :origin-auth t populates a non-zero receiver-specific key_id + master key"))
  t)

(defun* %t3-into-verify (sub)
    (function ((simple-array (unsigned-byte 8) (*))) t)
  "T3 corpus block (4): the ZERO-ALLOC into-buffer origin-auth verify entries (ADR-0039 residual (a)) round-trip
   IDENTICALLY to the allocating gate — proving the by-offset %put-receiver-macs-into (encode) + %verify-receiver-
   mac-into (decode) live path is correct AND fail-closed, so the 0 B/sample mem arms are non-vacuous. On the SAME
   receiver-MAC bracket built by encode-datawriter-submessage-into / encode-rtps-message-into (:receivers), decode
   via decode-{datawriter-submessage,rtps-message}-into with :my-receiver-key-id/:my-receiver-key: receiver #2 RIGHT
   key -> byte-exact recovery; WRONG key -> NIL though the common_mac is valid; ABSENT key_id -> NIL; NO key ->
   common_mac alone. Both submessage (SIGN-walk one embedded) + whole-RTPS (SIGN-walk the stream) tiers."
  (let ((kid2 (%hex-octets "bbbb0002"))
        (mk2   (make-array 32 :element-type '(unsigned-byte 8) :initial-element #x22))
        (wrong (make-array 32 :element-type '(unsigned-byte 8) :initial-element #x99))
        (absent (%hex-octets "cccc0003")))
    (flet ((dw-dec (secured blen rkid rk)
             (let ((pt (dds.core.buffer:make-octet-buffer 256)))
               (unwind-protect
                    (multiple-value-bind (dl mode doff poff)
                        (dds.security:decode-datawriter-submessage-into
                         pt 0 (dds.security:make-test-key-material) secured 0 blen
                         :my-receiver-key-id rkid :my-receiver-key rk)
                      (declare (ignore poff))
                      (when dl
                        (ecase mode
                          (:encrypt (subseq (dds.core.buffer:octet-buffer-vec pt) 0 dl))
                          (:sign    (subseq secured doff (+ doff dl))))))
                 (dds.pal:free-static (dds.core.buffer:octet-buffer-vec pt)))))
           (rtps-dec (secured blen rkid rk)
             (let ((pt (dds.core.buffer:make-octet-buffer 256)))
               (unwind-protect
                    (multiple-value-bind (dl mode doff poff)
                        (dds.security:decode-rtps-message-into
                         pt 0 (dds.security:make-test-key-material) secured 0 blen
                         :my-receiver-key-id rkid :my-receiver-key rk)
                      (declare (ignore poff))
                      (when dl
                        (ecase mode
                          (:encrypt (subseq (dds.core.buffer:octet-buffer-vec pt) 0 dl))
                          (:sign    (subseq secured doff (+ doff dl))))))
                 (dds.pal:free-static (dds.core.buffer:octet-buffer-vec pt))))))
      ;; submessage tier (SEC_PREFIX/SEC_POSTFIX), both kinds
      (dolist (kind '(:encrypt :sign))
        (let* ((km   (dds.security:make-test-key-material))
               (obuf (dds.core.buffer:make-octet-buffer 256))
               (blen (dds.security:encode-datawriter-submessage-into obuf 0 km kind sub 0 (length sub)
                                                                     :receivers (%t3-recvs)))
               (secured (dds.core.buffer:octet-buffer-vec obuf)))
          (unwind-protect
               (progn
                 (%check :t3-into-dw-right  (equalp (dw-dec secured blen kid2 mk2) sub)
                         (format nil "~a -into datawriter: receiver #2 RIGHT key recovers byte-exact" kind))
                 (%check :t3-into-dw-wrong  (null (dw-dec secured blen kid2 wrong))
                         (format nil "~a -into datawriter: WRONG receiver key -> NIL (common_mac valid; origin-auth gates)" kind))
                 (%check :t3-into-dw-absent (null (dw-dec secured blen absent mk2))
                         (format nil "~a -into datawriter: ABSENT key_id -> NIL (no entry targets me)" kind))
                 (%check :t3-into-dw-off    (equalp (dw-dec secured blen nil nil) sub)
                         (format nil "~a -into datawriter: no key -> common_mac alone (non-vacuity)" kind)))
            (dds.pal:free-static secured))))
      ;; whole-RTPS tier (SRTPS_PREFIX/SRTPS_POSTFIX), both kinds — SUB is a valid one-submessage stream
      (dolist (kind '(:encrypt :sign) t)
        (let* ((km   (dds.security:make-test-key-material))
               (obuf (dds.core.buffer:make-octet-buffer 256))
               (blen (dds.security:encode-rtps-message-into obuf 0 km kind sub 0 (length sub)
                                                            :receivers (%t3-recvs)))
               (secured (dds.core.buffer:octet-buffer-vec obuf)))
          (unwind-protect
               (progn
                 (%check :t3-into-rtps-right (equalp (rtps-dec secured blen kid2 mk2) sub)
                         (format nil "~a -into rtps: receiver #2 RIGHT key recovers byte-exact" kind))
                 (%check :t3-into-rtps-wrong (null (rtps-dec secured blen kid2 wrong))
                         (format nil "~a -into rtps: WRONG receiver key -> NIL (fail-closed)" kind))
                 (%check :t3-into-rtps-off   (equalp (rtps-dec secured blen nil nil) sub)
                         (format nil "~a -into rtps: no key -> common_mac alone" kind)))
            (dds.pal:free-static secured)))))))

(defun* run-security-origin-auth-test ()
    (function () t)
  "DDS-Security 1.1 §9.5.3.3.4.3 origin authentication corpus (Slice 4 T3): receiver-specific session-key
   KDF + per-receiver GMAC over the common_mac (same init vector), the receiver_specific_macs CryptoFooter
   list (encode emits, decode verifies its OWN entry constant-time).
   (1) byte-exact: ENCRYPT (128) + SIGN (120) with 2 receivers; the seal (ciphertext + common_mac) is
       unchanged vs plain T2, only the footer grows (rsm_count 2 + {key_id,mac}*2); deterministic.
   (2) NON-VACUOUS gate, both kinds + directions: receiver #2 right key -> plaintext; WRONG receiver key
       -> NIL though the common_mac is valid; ABSENT key_id -> NIL; origin-auth OFF on the SAME bytes ->
       plaintext on the common_mac alone (proving the failure is specifically the receiver-MAC check).
   (3) KDF/MAC/generator units (deterministic, label-distinct, IV/input/key-sensitive; :origin-auth slot
       population).
   (4) the ZERO-ALLOC into-buffer verify entries (ADR-0039 residual (a)): decode-{datawriter-submessage,
       rtps-message}-into with :my-receiver-key-id/:my-receiver-key round-trip identically + fail-closed,
       so the origin-auth 0 B/sample mem arms are non-vacuous.
   Requires OpenSSL >= 3.5; skips only if truly absent. Both SBCL and Clasp must pass identically."
  (multiple-value-bind (%dare-ok %dare-reason) (dds.dare:dare-available-p)
    (unless %dare-ok
      (format t "~&  [security-origin-auth] SKIP — OpenSSL >= 3.5 not available: ~a~%"
              %dare-reason)
      (return-from run-security-origin-auth-test t)))
  (let ((sub (%t2-fixed-plain-submessage)))
    (%t3-corpus-encode sub)
    (%t3-corpus-decode sub)
    (%t3-kdf-mac-units)
    (%t3-into-verify sub))
  t)

;;; --- Slice 4 T4: §8.5.1.10-.12 whole-RTPS-message protection (SRTPS_PREFIX(0x33) ... SRTPS_POSTFIX
;;; (0x34); SEC_BODY for ENCRYPT, the whole submessage STREAM verbatim for SIGN per §9.5.3.3.4.3). Same
;;; AES-GCM-GMAC engine as T2/T3 (the shared %encode/%decode-secured-region) — the protected unit is the
;;; whole stream, so SIGN decode WALKS the stream to the trailing SRTPS_POSTFIX. ParticipantCrypto-keyed.

(defun* %t4-fixed-stream ()
    (function () (simple-array (unsigned-byte 8) (*)))
  "A fixed 44-octet stand-in 'submessage STREAM' (everything after the 20-octet RTPS Header) for the T4
   corpus: TWO concatenated RTPS submessages — an INFO_TS-shaped one (id 0x09, E=1, octetsToNextHeader 8)
   then a DATA-shaped one (id 0x15, octetsToNextHeader 28) — so SIGN decode genuinely WALKS more than one
   submessage to reach the trailing SRTPS_POSTFIX. Deterministic; the transform is content-agnostic."
  (%hex-octets (concatenate 'string
    "09010800" "1122334455667788"                                   ; INFO_TS-shaped submessage (12)
    "15051c00" "00001000000100000000000001000000000000004041424344454647"))) ; DATA-shaped submessage (32)

(defun* %t4-encrypt-vector ()
    (function () (or (simple-array (unsigned-byte 8) (*)) null))
  "The deterministic full 100-octet ENCRYPT whole-RTPS corpus vector for
   (make-test-key-material, :encrypt, %t4-fixed-stream) — fresh km (iv_suffix=0, session_id=0), so the
   AES-256-GCM ciphertext + common_mac are fixed + reproducible on SBCL and Clasp (same OpenSSL). Pins the
   SRTPS framing (SRTPS_PREFIX/SEC_BODY/SRTPS_POSTFIX) AND the empty-AAD ENCRYPT crypto output: a change to
   the AAD decision / kinds / key derivation breaks this."
  (%hex-octets (concatenate 'string
    "33011400" "00000004" "deadbeef" "00000000" "0000000000000000"   ; SRTPS_PREFIX + CryptoHeader{GCM} (24)
    "30013000" "0000002c"                                            ; SEC_BODY hdr (octn=48) + ct_len=44 BE (8)
    "cdb98671d0cfa99d58eb0af579f6cff5" "e8674f30d58bdea858831a7819ce67c4" ; ciphertext(44)
    "e48841cbe0ae092abfba4d4f"
    "34011400"                                                       ; SRTPS_POSTFIX hdr (4)
    "1c8af294f86896f082b24791ee409ace"                               ; common_mac(16)
    "00000000")))                                                    ; rsm_count=0 (4)

(defun* %t4-sign-vector ()
    (function () (or (simple-array (unsigned-byte 8) (*)) null))
  "The deterministic full 92-octet SIGN whole-RTPS corpus vector for
   (make-test-key-material, :sign, %t4-fixed-stream). Per §9.5.3.3.4.3 SIGN/GMAC inserts NO SEC_BODY — the
   ORIGINAL submessage STREAM sits VERBATIM between SRTPS_PREFIX and SRTPS_POSTFIX; only the 16-octet
   common_mac is a GMAC over it. Pins the conformant SIGN framing (no SEC_BODY), the stream-as-AAD GMAC, and
   the AES256_GMAC {0,0,0,3} kind."
  (%hex-octets (concatenate 'string
    "33011400" "00000003" "deadbeef" "00000000" "0000000000000000"   ; SRTPS_PREFIX + CryptoHeader{GMAC} (24)
    "09010800" "1122334455667788"                                    ; stream VERBATIM submessage 1 (12)
    "15051c00" "00001000000100000000000001000000000000004041424344454647" ; stream VERBATIM submessage 2 (32)
    "34011400"                                                       ; SRTPS_POSTFIX hdr (4)
    "e61b0a64284da8ccd2894053364e1a74"                               ; common_mac=GMAC(16)
    "00000000")))                                                    ; rsm_count=0 (4)

(defun* %t4-corpus-encrypt (stream)
    (function ((simple-array (unsigned-byte 8) (*))) t)
  "T4 corpus block (1): ENCRYPT byte-exact + structural invariants for a fresh test-km + STREAM."
  (let* ((km  (dds.security:make-test-key-material))
         (enc (dds.security:encode-rtps-message km :encrypt stream)))
    (%check :t4-encrypt-len (= (length enc) 100)
            (format nil "ENCRYPT whole-RTPS message must be 100 octets; got ~d" (length enc)))
    (%check :t4-encrypt-prefix-exact
            (equalp (subseq enc 0 32)
                    (%hex-octets (concatenate 'string
                      "33011400" "00000004" "deadbeef" "00000000" "0000000000000000"
                      "30013000" "0000002c")))
            "ENCRYPT deterministic prefix (SRTPS_PREFIX 0x33 + CryptoHeader{GCM} + SEC_BODY hdr octn=48 + ct_len=44 BE) byte-exact")
    (when (%t4-encrypt-vector)
      (%check :t4-encrypt-byte-exact (equalp enc (%t4-encrypt-vector))
              (format nil "ENCRYPT full 100-octet vector byte mismatch; got ~(~{~2,'0x~}~)" (coerce enc 'list))))
    (%check :t4-encrypt-postfix-hdr (equalp (subseq enc 76 80) (%hex-octets "34011400"))
            "ENCRYPT SRTPS_POSTFIX header byte-exact (id 0x34, E=1, octn=20)")
    (%check :t4-encrypt-rsm0 (equalp (subseq enc 96 100) (%hex-octets "00000000"))
            "ENCRYPT CryptoFooter receiver_specific_macs_count = 0")
    (%check :t4-encrypt-stream-absent (null (search stream enc))
            "ENCRYPT: the plaintext submessage stream must NOT appear on the wire (ciphertext)"))
  t)

(defun* %t4-corpus-sign (stream)
    (function ((simple-array (unsigned-byte 8) (*))) t)
  "T4 corpus block (2): SIGN byte-exact — the whole submessage STREAM VERBATIM between SRTPS_PREFIX and
   SRTPS_POSTFIX with NO SEC_BODY (§9.5.3.3.4.3), GMAC common_mac, kind=GMAC."
  (let* ((km  (dds.security:make-test-key-material))
         (sgn (dds.security:encode-rtps-message km :sign stream)))
    (%check :t4-sign-len (= (length sgn) 92)
            (format nil "SIGN whole-RTPS message must be 92 octets (no SEC_BODY); got ~d" (length sgn)))
    (%check :t4-sign-prefix-exact
            (equalp (subseq sgn 0 24)
                    (%hex-octets (concatenate 'string
                      "33011400" "00000003" "deadbeef" "00000000" "0000000000000000")))
            "SIGN deterministic prefix (SRTPS_PREFIX 0x33 + CryptoHeader kind = AES256_GMAC {0,0,0,3}) byte-exact, NO SEC_BODY")
    (%check :t4-sign-stream-verbatim
            (and (eql (search stream sgn) 24) (equalp (subseq sgn 24 68) stream))
            "SIGN: the original stream is VERBATIM between SRTPS_PREFIX and SRTPS_POSTFIX at offset 24 (no SEC_BODY)")
    (%check :t4-sign-no-sec-body (not (eql (aref sgn 24) dds.security:+submessage-sec-body+))
            "SIGN: no SEC_BODY (0x30) follows the CryptoHeader — the stream begins immediately at offset 24 (conformant framing)")
    (when (%t4-sign-vector)
      (%check :t4-sign-byte-exact (equalp sgn (%t4-sign-vector))
              (format nil "SIGN full 92-octet vector byte mismatch; got ~(~{~2,'0x~}~)" (coerce sgn 'list))))
    (%check :t4-sign-postfix-hdr (equalp (subseq sgn 68 72) (%hex-octets "34011400"))
            "SIGN SRTPS_POSTFIX header byte-exact")
    (%check :t4-sign-rsm0 (equalp (subseq sgn 88 92) (%hex-octets "00000000"))
            "SIGN CryptoFooter receiver_specific_macs_count = 0"))
  t)

(defun* %t4-corpus-roundtrip (stream)
    (function ((simple-array (unsigned-byte 8) (*))) t)
  "T4 corpus block (3): round-trip both KINDs — decode-rtps-message(km, encode-rtps-message(km,KIND,stream))
   = stream byte-exact; the SIGN walk must recover the multi-submessage stream verbatim."
  (dolist (kind '(:encrypt :sign) t)
    (let* ((km  (dds.security:make-test-key-material))
           (dec (dds.security:decode-rtps-message
                 km (dds.security:encode-rtps-message km kind stream))))
      (%check :t4-roundtrip (and dec (equalp dec stream))
              (format nil "whole-RTPS ~a round-trip must recover the submessage stream byte-exact" kind)))))

(defun* %t4-decode (blob)
    (function ((simple-array (unsigned-byte 8) (*))) (or (simple-array (unsigned-byte 8) (*)) null))
  "Decode BLOB with a fresh same-key test km (negatives feed adversarial BLOBs); NIL = rejected."
  (dds.security:decode-rtps-message (dds.security:make-test-key-material) blob))

(defun* %t4-corpus-negatives (stream)
    (function ((simple-array (unsigned-byte 8) (*))) t)
  "T4 corpus block (4): negatives — every one MUST fail-closed to NIL (never a tampered stream)."
  (let* ((km  (dds.security:make-test-key-material))
         (enc (dds.security:encode-rtps-message km :encrypt stream))
         (sgn (dds.security:encode-rtps-message (dds.security:make-test-key-material) :sign stream))
         (km2 (dds.security:make-key-material
               :master-sender-key (make-array 32 :element-type '(unsigned-byte 8) :initial-element #xAA)
               :master-salt       (make-array 32 :element-type '(unsigned-byte 8) :initial-element #x55)
               :sender-key-id     (dds.security:key-material-sender-key-id km))))
    (%check :t4-neg-control (equalp (%t4-decode enc) stream)
            "control: a same-key fresh km decodes the ENCRYPT vector")
    (%check :t4-neg-wrong-key (null (dds.security:decode-rtps-message km2 enc))
            "wrong master key must return NIL (GCM auth fail-closed)")
    ;; ENCRYPT (100): common_mac at offset 80; ciphertext at offset 32; SRTPS_POSTFIX id at 76; SEC_BODY id at 24.
    (%check :t4-neg-flip-tag-encrypt (null (%t4-decode (%t2-flip enc 80 #x80)))
            "ENCRYPT: a 1-octet common_mac flip must return NIL")
    (%check :t4-neg-flip-ct (null (%t4-decode (%t2-flip enc 32 #x01)))
            "ENCRYPT: a 1-octet ciphertext flip must return NIL")
    (%check :t4-neg-body-id (null (%t4-decode (%t2-set enc 24 dds.security:+submessage-srtps-postfix+)))
            "a corrupted SEC_BODY submessageId must return NIL")
    (%check :t4-neg-postfix-id-encrypt (null (%t4-decode (%t2-set enc 76 #x15)))
            "ENCRYPT: a corrupted SRTPS_POSTFIX submessageId must return NIL")
    ;; SIGN (92): common_mac(GMAC) at offset 72; stream at 24..68; SRTPS_POSTFIX id at 68.
    (%check :t4-neg-flip-tag-sign (null (%t4-decode (%t2-flip sgn 72 #x01)))
            "SIGN: a 1-octet GMAC flip must return NIL")
    (%check :t4-neg-flip-sign-stream (null (%t4-decode (%t2-flip sgn 40 #x01)))
            "SIGN: a 1-octet flip in the verbatim stream must return NIL (never the tampered stream)")
    (%check :t4-neg-postfix-id-sign (null (%t4-decode (%t2-set sgn 68 #x15)))
            "SIGN: a corrupted SRTPS_POSTFIX submessageId must return NIL (the walk never finds the postfix)")
    (dolist (cut '(0 1 4 23 24 31 32 75 79 99))
      (%check :t4-neg-truncated (null (%t4-decode (subseq enc 0 cut)))
              (format nil "truncated whole-RTPS message (len=~d) must return NIL" cut)))
    (%check :t4-neg-reordered (null (%t4-decode (%t2-set enc 0 dds.security:+submessage-sec-body+)))
            "a re-ordered bracket (SRTPS_PREFIX id corrupted) must return NIL")
    ;; unknown transformation_kind (AES128_GCM {0,0,0,2}): CryptoHeader.kind low octet at offset 7.
    (%check :t4-neg-unknown-kind (null (%t4-decode (%t2-set enc 7 #x02)))
            "an unknown/unsupported transformation_kind must return NIL (fail-closed)"))
  t)

(defun* %t4-corpus-origin-auth (stream)
    (function ((simple-array (unsigned-byte 8) (*))) t)
  "T4 corpus block (5): origin authentication over the whole-RTPS tier — encode emits receiver_specific_macs;
   decode-rtps-message verifies its OWN entry (non-vacuous gate). Same %t3-recvs descriptors as the
   submessage tier. On the SAME encoded bytes: right receiver key -> the stream; WRONG key -> NIL though the
   common_mac is valid; ABSENT key_id -> NIL; origin-auth OFF -> the stream on the common_mac alone."
  (let ((kid2  (%hex-octets "bbbb0002"))
        (mk2   (make-array 32 :element-type '(unsigned-byte 8) :initial-element #x22))
        (wrong (make-array 32 :element-type '(unsigned-byte 8) :initial-element #x99))
        (absent (%hex-octets "cccc0003")))
    (dolist (kind '(:encrypt :sign) t)
      (let* ((km   (dds.security:make-test-key-material))
             (blob (dds.security:encode-rtps-message km kind stream :receivers (%t3-recvs))))
        (%check :t4-oa-rsm2-present
                (let ((d (dds.security:decode-rtps-message (dds.security:make-test-key-material) blob)))
                  (and d (equalp d stream)))
                (format nil "~a whole-RTPS+origin-auth: origin-auth OFF decodes on the common_mac alone (footer present)" kind))
        (%check :t4-oa-right
                (equalp (dds.security:decode-rtps-message
                         (dds.security:make-test-key-material) blob
                         :my-receiver-key-id kid2 :my-receiver-key mk2) stream)
                (format nil "~a whole-RTPS: receiver #2 with the right key recovers the stream" kind))
        (%check :t4-oa-wrong-key
                (null (dds.security:decode-rtps-message
                       (dds.security:make-test-key-material) blob
                       :my-receiver-key-id kid2 :my-receiver-key wrong))
                (format nil "~a whole-RTPS: receiver #2 with a WRONG receiver key -> NIL (common_mac valid; origin-auth gates)" kind))
        (%check :t4-oa-absent
                (null (dds.security:decode-rtps-message
                       (dds.security:make-test-key-material) blob
                       :my-receiver-key-id absent :my-receiver-key mk2))
                (format nil "~a whole-RTPS: an ABSENT receiver key_id -> NIL (no entry targets me)" kind)))))
  t)

(defun* run-security-rtps-message-corpus-test ()
    (function () t)
  "DDS-Security 1.1 §8.5.1.10-.12 whole-RTPS-message protection corpus (Slice 4 T4): the SRTPS_PREFIX(0x33)
   ... SRTPS_POSTFIX(0x34) bracket protecting the ENTIRE submessage stream, SIGN + ENCRYPT, ParticipantCrypto
   -keyed. The middle region is mode-dependent: ENCRYPT inserts a SEC_BODY(0x30) ciphertext (§9.5.3.3.4.4);
   SIGN inserts NO SEC_BODY — the whole stream VERBATIM (§9.5.3.3.4.3), recovered on decode by WALKING the
   submessage stream to the trailing SRTPS_POSTFIX.
   (1) ENCRYPT byte-exact: fresh test-km + fixed 2-submessage stream => the EXACT 100-octet vector
       (deterministic: iv_suffix=0, fixed key); the stream is NOT on the wire.
   (2) SIGN byte-exact: => the EXACT 92-octet vector; the stream IS verbatim between SRTPS_PREFIX and
       SRTPS_POSTFIX with no SEC_BODY; the CryptoHeader kind is AES256_GMAC {0,0,0,3}.
   (3) round-trip: decode(encode(km,KIND,stream)) = stream byte-exact, both KINDs (the SIGN walk recovers
       the multi-submessage stream).
   (4) negatives, fail-closed -> NIL: wrong key; flipped common_mac/GMAC; flipped ciphertext (ENCRYPT);
       flipped stream byte (SIGN — and NEVER the tampered stream); truncation; a re-ordered bracket; a
       corrupted SEC_BODY / SRTPS_POSTFIX submessageId; an unknown transformation_kind.
   (5) origin authentication: encode with 2 receivers; decode verifies its OWN entry — right key -> stream;
       wrong key -> NIL (non-vacuous, common_mac valid); absent key_id -> NIL; off -> stream.
   Requires OpenSSL >= 3.5; skips only if truly absent. Both SBCL and Clasp must pass identically (Clasp FIRST)."
  (multiple-value-bind (%dare-ok %dare-reason) (dds.dare:dare-available-p)
    (unless %dare-ok
      (format t "~&  [security-rtps-message] SKIP — OpenSSL >= 3.5 not available: ~a~%"
              %dare-reason)
      (return-from run-security-rtps-message-corpus-test t)))
  (let ((stream (%t4-fixed-stream)))
    (%t4-corpus-encrypt stream)
    (%t4-corpus-sign stream)
    (%t4-corpus-roundtrip stream)
    (%t4-corpus-negatives stream)
    (%t4-corpus-origin-auth stream))
  t)

;;; --- Slice 2 (ZA-2) T2: the zero-alloc into-buffer bracket core %encode/%decode-secured-region-into ---
;;; The -into core writes the §8.5.1.7-.12 SEC_PREFIX/SRTPS_PREFIX bracket directly through a STATIC
;;; octet-buffer with no per-sample GC-heap allocation; the allocating %encode/%decode-secured-region are
;;; thin wrappers over it (so the T2/T4 byte-exact corpora already exercise the core). These oracle-pin
;;; the core against the INDEPENDENT frozen corpus goldens (%t2/%t4-*-vector), verified vs Fast DDS +
;;; tshark, so the pin is not a wrapper-vs-core tautology; the round-trip proves decode-into recovers the
;;; plaintext (ENCRYPT into PT-OUT) / the verbatim-region bounds (SIGN, no copy); the alloc arm proves 0.

(defun* %za2-region-into-combo (mode plain prefix postfix golden sign-walk-p tier)
    (function ((member :sign :encrypt) (simple-array (unsigned-byte 8) (*))
               (unsigned-byte 8) (unsigned-byte 8)
               (or (simple-array (unsigned-byte 8) (*)) null) t string) t)
  "ZA-2 oracle-pin + round-trip for one (MODE, TIER) combo: %encode-secured-region-into (fresh km, iv
   counter 0 -> deterministic iv_suffix/session_id 0) is byte-identical to the INDEPENDENT frozen corpus
   GOLDEN and to the allocating %encode-secured-region wrapper; %decode-secured-region-into round-trips
   (ENCRYPT plaintext into PT-OUT; SIGN returns the verbatim-region bounds in SECURED, no copy).
   PREFIX/POSTFIX select the tier bracket kinds; SIGN-WALK-P selects one-embedded-submessage (submessage
   tier) vs stream-walk (whole-RTPS tier) SIGN decode; TIER is a label for the failure detail."
  (let ((km     (dds.security:make-test-key-material))
        (out    (dds.core.buffer:make-octet-buffer (+ 128 (length plain))))
        (pt-out (dds.core.buffer:make-octet-buffer (+ 16 (length plain)))))
    (unwind-protect
         (let* ((len  (dds.security::%encode-secured-region-into out 0 km mode plain 0 (length plain)
                                                                 '() prefix postfix))
                (core (subseq (dds.core.buffer:octet-buffer-vec out) 0 len)))
           ;; (a) INDEPENDENT golden pin — the core reproduces the frozen Fast-DDS/tshark-verified corpus byte
           (%check :za2-region-into-golden (equalp core golden)
                   (format nil "~a ~a encode-into must equal the frozen corpus golden byte-for-byte; got ~(~{~2,'0x~}~)"
                           tier mode (coerce core 'list)))
           ;; (b) consistency with the allocating %encode-secured-region wrapper (which now routes the core)
           (%check :za2-region-into-wrapper
                   (equalp core (dds.security::%encode-secured-region
                                 (dds.security:make-test-key-material) mode plain '() prefix postfix))
                   (format nil "~a ~a encode-into must equal the allocating %encode-secured-region wrapper" tier mode))
           ;; (c) decode-into round-trip
           (multiple-value-bind (dlen dmode roff)
               (dds.security::%decode-secured-region-into pt-out 0 (dds.security:make-test-key-material)
                                                          core 0 (length core) sign-walk-p)
             (ecase mode
               (:encrypt
                (%check :za2-region-into-decode
                        (and dlen (eq dmode :encrypt) (= dlen (length plain))
                             (equalp (subseq (dds.core.buffer:octet-buffer-vec pt-out) 0 dlen) plain))
                        (format nil "~a ENCRYPT decode-into must recover the plaintext byte-exact into PT-OUT" tier)))
               (:sign
                (%check :za2-region-into-decode
                        (and dlen (eq dmode :sign) (= dlen (length plain)) roff
                             (equalp (subseq core roff (+ roff dlen)) plain))
                        (format nil "~a SIGN decode-into must return bounds pointing at the verbatim region byte-exact" tier))))))
      (dds.pal:free-static (dds.core.buffer:octet-buffer-vec out))
      (dds.pal:free-static (dds.core.buffer:octet-buffer-vec pt-out))))
  t)

(defun* %za2-region-into-zeroalloc (sub)
    (function ((simple-array (unsigned-byte 8) (*))) t)
  "ZA-2 zero-alloc proof: the %encode-secured-region-into ENCRYPT core, over a REUSED static out-buffer +
   REUSED key-material, conses ~0 GC-heap B/call (SBCL-exact via dds.pal:bytes-consed; Clasp reports 0 by
   the NFR-PORT gap -> the delta is 0 and the assertion passes vacuously). Proves the core adds no
   per-sample GC-heap allocation (the only residual is the EVP-FFI boxing shared with the T1 KAT)."
  (let ((km    (dds.security:make-test-key-material))
        (out   (dds.core.buffer:make-octet-buffer 256))
        (iters 4000))
    (unwind-protect
         (progn
           (dds.security::%encode-secured-region-into out 0 km :encrypt sub 0 (length sub) '()
                                                      dds.security:+submessage-sec-prefix+
                                                      dds.security:+submessage-sec-postfix+)  ; warm
           (let ((before (dds.pal:bytes-consed)))
             (dotimes (i iters)
               (dds.security::%encode-secured-region-into out 0 km :encrypt sub 0 (length sub) '()
                                                          dds.security:+submessage-sec-prefix+
                                                          dds.security:+submessage-sec-postfix+))
             (let* ((delta (- (dds.pal:bytes-consed) before))
                    (per   (/ (float delta) iters)))
               (format t "~&  [secured-region-into] ENCODE core (ENCRYPT, reused out-buffer) = ~,4f B/call (~d iters, ~d B total)~%"
                       per iters delta)
               (%check :za2-region-into-zeroalloc (< per 1.0)
                       (format nil "encode-into core must cons ~~0 GC-heap B/call; got ~,4f" per)))))
      (dds.pal:free-static (dds.core.buffer:octet-buffer-vec out))))
  t)

(defun* %za2-sign-decode-zeroalloc (blob)
    (function ((simple-array (unsigned-byte 8) (*))) t)
  "ZA-2 zero-alloc proof for the SIGN decode path: %decode-secured-region-into with a REUSED pre-encoded
   SIGN blob + REUSED km + REUSED pt-out must cons ~0 GC-heap B/call after the aad-region fix
   (was (length plain) B/call from the verbatim-region subseq; Clasp bytes-consed=0 -> skip NFR-PORT)."
  (let ((km    (dds.security:make-test-key-material))
        (pt    (dds.core.buffer:make-octet-buffer 128))
        (iters 4000))
    (unwind-protect
         (progn
           (dds.security::%decode-secured-region-into pt 0 km blob 0 (length blob) nil) ; warm
           (let ((before (dds.pal:bytes-consed)))
             (dotimes (i iters)
               (dds.security::%decode-secured-region-into pt 0 km blob 0 (length blob) nil))
             (let* ((delta (- (dds.pal:bytes-consed) before))
                    (per   (/ (float delta) iters)))
               (format t "~&  [secured-region-into] SIGN decode-into (reused blob+pt) = ~,4f B/call (~d iters, ~d B total)~%"
                       per iters delta)
               (if (zerop (dds.pal:bytes-consed))
                   (format t "  [skip] dds.pal:bytes-consed is 0 on this impl — SIGN decode alloc not measurable~%")
                   (%check :za2-sign-decode-zeroalloc (< per 1.0)
                           (format nil "SIGN decode-into must cons ~~0 GC-heap B/call after the region fix; got ~,4f" per))))))
      (dds.pal:free-static (dds.core.buffer:octet-buffer-vec pt))))
  t)

(defun* run-security-secured-region-into-test ()
    (function () t)
  "DDS-Security 1.1 §8.5.1.7-.12 zero-alloc into-buffer bracket codec (%encode/%decode-secured-region-into,
   Slice 2 / ZA-2 T2):
   (a) ENCODE oracle-pin — %encode-secured-region-into (fresh km, iv counter 0) is byte-identical to the
       INDEPENDENT frozen T2/T4 corpus goldens (%t2-encrypt/sign-vector 88/80, %t4-encrypt/sign-vector
       100/92), ENCRYPT + SIGN, in BOTH the SEC_PREFIX/SEC_POSTFIX submessage tier AND the SRTPS_PREFIX/
       SRTPS_POSTFIX whole-RTPS tier; it also equals the allocating %encode-secured-region wrapper.
   (b) DECODE round-trip — %decode-secured-region-into recovers ENCRYPT plaintext byte-exact into a static
       PT-OUT; for SIGN it returns the (offset,len) bounds pointing at the verbatim region in SECURED
       byte-exact (no copy), both tiers (SIGN-WALK-P NIL reads one embedded submessage; T walks the stream).
   (c) fail-closed — a too-short input -> NIL, both tiers.
   (d) zero-alloc — the ENCODE core (ENCRYPT, reused out-buffer) conses ~0 B/call on a measuring impl (SBCL).
   Requires OpenSSL >= 3.5; skips only if truly absent. Both SBCL and Clasp must pass identically (Clasp FIRST)."
  (multiple-value-bind (%dare-ok %dare-reason) (dds.dare:dare-available-p)
    (unless %dare-ok
      (format t "~&  [security-secured-region-into] SKIP — OpenSSL >= 3.5 not available: ~a~%"
              %dare-reason)
      (return-from run-security-secured-region-into-test t)))
  (let ((sub    (%t2-fixed-plain-submessage))
        (stream (%t4-fixed-stream)))
    ;; submessage tier (SEC_PREFIX/SEC_POSTFIX, sign-walk-p NIL)
    (%za2-region-into-combo :encrypt sub dds.security:+submessage-sec-prefix+
                            dds.security:+submessage-sec-postfix+ (%t2-encrypt-vector) nil "submsg")
    (%za2-region-into-combo :sign sub dds.security:+submessage-sec-prefix+
                            dds.security:+submessage-sec-postfix+ (%t2-sign-vector) nil "submsg")
    ;; whole-RTPS tier (SRTPS_PREFIX/SRTPS_POSTFIX, sign-walk-p T)
    (%za2-region-into-combo :encrypt stream dds.security:+submessage-srtps-prefix+
                            dds.security:+submessage-srtps-postfix+ (%t4-encrypt-vector) t "srtps")
    (%za2-region-into-combo :sign stream dds.security:+submessage-srtps-prefix+
                            dds.security:+submessage-srtps-postfix+ (%t4-sign-vector) t "srtps")
    ;; fail-closed: a too-short input -> NIL (both tiers)
    (let ((pt (dds.core.buffer:make-octet-buffer 8)))
      (unwind-protect
           (progn
             (%check :za2-failclosed-submsg
                     (null (dds.security::%decode-secured-region-into
                            pt 0 (dds.security:make-test-key-material)
                            (make-array 8 :element-type '(unsigned-byte 8)) 0 8 nil))
                     "decode-into on a too-short submessage input must return NIL (fail-closed)")
             (%check :za2-failclosed-srtps
                     (null (dds.security::%decode-secured-region-into
                            pt 0 (dds.security:make-test-key-material)
                            (make-array 8 :element-type '(unsigned-byte 8)) 0 8 t))
                     "decode-into on a too-short whole-RTPS input must return NIL (fail-closed)"))
        (dds.pal:free-static (dds.core.buffer:octet-buffer-vec pt))))
    ;; zero-alloc proof for the ENCODE core over a reused out-buffer
    (%za2-region-into-zeroalloc sub)
    ;; SIGN decode bytes-consed: reused pre-encoded blob + km + pt -> ~0 B/call (subseq gone after fix)
    (%za2-sign-decode-zeroalloc (%t2-sign-vector)))
  t)

(defun* %t4-bench-stream (size)
    (function (fixnum) (simple-array (unsigned-byte 8) (*)))
  "A representative SIZE-octet submessage STREAM for the T4 micro-bench: a 4-octet RTPS DATA-shaped
   SubmessageHeader (id 0x15, E=1, octetsToNextHeader = SIZE-4) + a (SIZE-4)-octet recognizable payload.
   The transform is content-agnostic; SIZE is the datagram-after-RTPS-Header size driving the measurement."
  (let ((v (make-array size :element-type '(unsigned-byte 8) :initial-element 0))
        (octn (- size 4)))
    (setf (aref v 0) #x15 (aref v 1) #x01
          (aref v 2) (logand octn #xff) (aref v 3) (logand (ash octn -8) #xff))
    (dotimes (i octn v) (setf (aref v (+ 4 i)) (logand (* i 7) #xff)))))

(defun* run-rtps-message-bench (&key (iters 100000) (size 256) (stream *standard-output*))
    (function (&key (:iters fixnum) (:size fixnum) (:stream t)) t)
  "Micro-bench the §8.5.1.10-.12 whole-RTPS-message protection (T4) encode + decode of a representative
   SIZE-octet datagram submessage stream, ITERS each, for SIGN and ENCRYPT, on the static-arena-backed
   encode scratch. Reports ns/op (dds.pal:monotonic-ns) + GC bytes/op (dds.pal:bytes-consed delta; SBCL
   exact, Clasp reports 0 — NFR-PORT) as a markdown table to STREAM. This is the T4 BASELINE; T10 re-measures
   the integrated send/%handle-datagram path. Encode advances the km iv-counter per call (no nonce reuse);
   decode re-decodes one pre-encoded blob (keyed by the wire iv). SKIPs if OpenSSL<3.5."
  (multiple-value-bind (%dare-ok %dare-reason) (dds.dare:dare-available-p)
    (unless %dare-ok
      (format stream "~&  [rtps-message-bench] SKIP — OpenSSL >= 3.5 not available: ~a~%"
              %dare-reason)
      (return-from run-rtps-message-bench t)))
  (let ((subs (%t4-bench-stream size)))
    (flet ((bench-encode (kind)
             (let ((km (dds.security:make-test-key-material)))
               (dds.security:encode-rtps-message km kind subs)         ; warmup
               (let ((b0 (dds.pal:bytes-consed)) (t0 (dds.pal:monotonic-ns)))
                 (dotimes (_ iters) (dds.security:encode-rtps-message km kind subs))
                 (values (/ (- (dds.pal:monotonic-ns) t0) iters)
                         (/ (- (dds.pal:bytes-consed) b0) iters)))))
           (bench-decode (kind)
             (let* ((km   (dds.security:make-test-key-material))
                    (blob (dds.security:encode-rtps-message km kind subs))
                    (dkm  (dds.security:make-test-key-material)))
               (dds.security:decode-rtps-message dkm blob)             ; warmup
               (let ((b0 (dds.pal:bytes-consed)) (t0 (dds.pal:monotonic-ns)))
                 (dotimes (_ iters) (dds.security:decode-rtps-message dkm blob))
                 (values (/ (- (dds.pal:monotonic-ns) t0) iters)
                         (/ (- (dds.pal:bytes-consed) b0) iters))))))
      (format stream "~&# WP-DDS-SECURITY-SECURE-DISCOVERY T4 — whole-RTPS-message protection micro-bench~%~%")
      (format stream "Encode + decode of a representative ~d-octet datagram submessage stream, ~d iterations each (§8.5.1.10-.12). Encode scratch is static-arena-backed (dds.pal:alloc-static); the GMAC/GCM core is the shared %seal/%open-with-km over DDS.DARE/OpenSSL. ns/op = dds.pal:monotonic-ns delta / iters; GC bytes/op = dds.pal:bytes-consed delta / iters (SBCL exact; Clasp reports 0, NFR-PORT). T4 BASELINE; T10 re-measures the integrated path.~%~%" size iters)
      (format stream "| op | ns/op | GC bytes/op |~%|----|-------|-------------|~%")
      (dolist (kind '(:sign :encrypt))
        (multiple-value-bind (ens enb) (bench-encode kind)
          (format stream "| encode ~(~a~) | ~,1f | ~d |~%" kind (float ens) (round enb)))
        (multiple-value-bind (dens denb) (bench-decode kind)
          (format stream "| decode ~(~a~) | ~,1f | ~d |~%" kind (float dens) (round denb))))
      (format stream "~%")))
  t)

(defun* run-rtps-protection-bench (&key (iters 100000) (size 256) (stream *standard-output*))
    (function (&key (:iters fixnum) (:size fixnum) (:stream t)) t)
  "T10 INTEGRATED before/after bench for whole-RTPS-message protection (rtps_protection_kind) on the live send /
   receive datagram path (DDS-Security 1.1 §8.5.1.10-.12). Three rows on a representative SIZE-octet post-header
   submessage stream, ITERS each, ENCRYPT tier:
     plain         — the baseline: NO wrap (the send path when the dest is not :keyed / rtps_protection NONE) ->
                     0 added ns, 0 added GC bytes (byte-identical send).
     T4-encode     — the codec alone (encode-rtps-message), the T4 micro-bench baseline.
     T10-send      — the INTEGRATED send wrap %maybe-wrap-srtps does: subseq(buf,20,len) + encode-rtps-message +
                     in-place replace into the REUSED node buffer (no fresh message-sized datagram array).
     T4-decode     — the codec alone (decode-rtps-message).
     T10-recv      — the INTEGRATED receive unwrap %handle-datagram does: subseq(buf,20,size) + decode-rtps-message
                     + in-place replace into the REUSED inbound buffer, then re-dispatch (the copy measured here).
   ns/op = dds.pal:monotonic-ns delta / iters; GC bytes/op = dds.pal:bytes-consed delta / iters (SBCL exact;
   Clasp reports 0 — NFR-PORT). The T10-send/recv vs T4 delta is the documented residual: the codec's →octets
   return + AEAD intermediates (the inherited T4 carry) PLUS one plain-region subseq per datagram; the node
   send/receive BUFFER is reused in place (no per-datagram message-sized array). SKIPs if OpenSSL<3.5."
  (multiple-value-bind (%dare-ok %dare-reason) (dds.dare:dare-available-p)
    (unless %dare-ok
      (format stream "~&  [rtps-protection-bench] SKIP — OpenSSL >= 3.5 not available: ~a~%"
              %dare-reason)
      (return-from run-rtps-protection-bench t)))
  (let* ((subs (%t4-bench-stream size))                                   ; the post-header submessage stream
         (km   (dds.security:make-test-key-material))
         (dkm  (dds.security:make-test-key-material))
         (blob (dds.security:encode-rtps-message km :encrypt subs))       ; a pre-encoded SRTPS bracket for decode
         (buf  (make-array (+ 20 (max size (length blob)) 64) :element-type '(unsigned-byte 8))))   ; reused node-buffer stand-in
    (replace buf subs :start1 20)
    (flet ((measure (thunk)
             (declare (type function thunk))
             (funcall thunk)                                              ; warmup
             (let ((b0 (dds.pal:bytes-consed)) (t0 (dds.pal:monotonic-ns)))
               (dotimes (_ iters) (funcall thunk))
               (values (/ (- (dds.pal:monotonic-ns) t0) iters) (/ (- (dds.pal:bytes-consed) b0) iters)))))
      (format stream "~&# WP-DDS-SECURITY-SECURE-DISCOVERY T10 — rtps_protection integrated send/receive bench~%~%")
      (format stream "Integrated whole-RTPS-message protection of a representative ~d-octet post-header submessage stream, ~d iterations each, ENCRYPT tier (§8.5.1.10-.12). The send wrap (%maybe-wrap-srtps) and receive unwrap (%handle-datagram) overwrite the REUSED node buffer in place — no fresh per-datagram message-sized array; the residual GC is the codec's →octets return + AEAD intermediates (the inherited T4 carry) + one plain-region subseq per datagram. ns/op = dds.pal:monotonic-ns delta / iters; GC bytes/op = dds.pal:bytes-consed delta / iters (SBCL exact; Clasp 0, NFR-PORT). 'plain' is the unwrapped send (dest not :keyed / rtps NONE) — byte-identical, 0 added.~%~%" size iters)
      (format stream "| path | ns/op | GC bytes/op |~%|------|-------|-------------|~%")
      (format stream "| plain (no wrap) | ~,1f | ~d |~%" 0.0 0)
      (multiple-value-bind (ns b) (measure (lambda () (dds.security:encode-rtps-message km :encrypt subs)))
        (format stream "| T4-encode (codec) | ~,1f | ~d |~%" (float ns) (round b)))
      (multiple-value-bind (ns b)
          ;; the integrated SEND: plain-region subseq (from the reused buffer) + encode + in-place replace
          (measure (lambda () (let ((w (dds.security:encode-rtps-message km :encrypt (subseq buf 20 (+ 20 size)))))
                                (replace buf w :start1 20)
                                (replace buf subs :start1 20))))   ; restore the plain region for the next iter
        (format stream "| T10-send (integrated) | ~,1f | ~d |~%" (float ns) (round b)))
      (multiple-value-bind (ns b) (measure (lambda () (dds.security:decode-rtps-message dkm blob)))
        (format stream "| T4-decode (codec) | ~,1f | ~d |~%" (float ns) (round b)))
      (multiple-value-bind (ns b)
          ;; the integrated RECEIVE: SRTPS subseq (from the reused inbound buffer) + decode
          (measure (lambda () (let ((st (dds.security:decode-rtps-message dkm (subseq blob 0 (length blob)))))
                                (declare (ignore st)))))
        (format stream "| T10-recv (integrated) | ~,1f | ~d |~%" (float ns) (round b)))
      (format stream "~%")))
  t)

(defun* run-security-session-key-cache-test ()
    (function () t)
  "Per-KeyMaterial session-key cache (WP-DDS-SECURITY-ZEROALLOC-AEAD T2, §9.5.3.3.4.2).
   Verifies: (a) the cached key is byte-identical to a fresh derive-session-key result;
   (b) a second call with the same session_id returns the SAME object (cache hit, EQ identity).
   The hit path is lock-free + zero-alloc; the miss derives once and stores the result.
   Both SBCL and Clasp must pass identically."
  (let* ((km     (dds.security:make-test-key-material))
         ;; +fixed-session-id+ = all-zeros (not exported; reproduced inline)
         (sid    (make-array 4 :element-type '(unsigned-byte 8) :initial-element 0))
         (direct (dds.security:derive-session-key
                  (dds.security:key-material-master-sender-key km)
                  (dds.security:key-material-master-salt km)
                  sid))
         (k1     (dds.security::%km-session-key-at km sid 0))
         (k2     (dds.security::%km-session-key-at km sid 0)))
    (%check :skcache-correct (equalp k1 direct)
            "cached key must equal a fresh derive-session-key result")
    (%check :skcache-reused  (eq k1 k2)
            "second call with same session_id must return the SAME object (cache hit)")
    t))

(defun* run-security-keymaterial-harden-test ()
    (function () t)
  "ADR-0034 KeyMaterial secret hygiene (WP-SECURITY-KEYMATERIAL-HARDEN, M7/P6). Proves:
   (a) the three §9.5.2 MASTER secret slots (master_salt, master_sender_key, master_receiver_specific_key) are
       FOREIGN/STATIC (dds.pal:static-vector-p; a plain heap array answers NIL — non-vacuous), while the derived
       §9.5.3.3.4.2/.4.3 session-key caches are plain GC-HEAP (NOT foreign-static) — the A2 revert: a foreign-static
       copy per session_id would UNBOUNDEDLY leak un-wiped keys on session_id rotation (reachable pre-auth) and
       free-on-replace would UAF the lock-free hit path, so the caches stay heap;
   (b) SESSION_ID-ROTATION NO-LEAK: deriving MANY distinct session_ids through %km-session-key-at (+ the receiver
       path) yields a plain GC-HEAP key EVERY time — never foreign-static — so a session_id-rotating peer allocates
       ZERO foreign-static buffers (a bounded single-slot cache, GC-reclaimed; the exact leak the revert closes);
   (c) zeroize-key-material WIPES the MASTER bytes (fill-0 before release), DROPS the heap caches, and sets the
       fail-closed KEY-MATERIAL-ZEROIZED marker (a zeroized KM is structurally unusable);
   (d) FAIL-CLOSED GUARD: after teardown the master-secret-reading entry points (%km-session-key-at,
       %km-receiver-session-key-at, km-receiver-descriptor-list) SIGNAL key-material-zeroized-error rather than
       dereference the freed master buffers (defense-in-depth; km-receiver-descriptor-list must NOT return NIL —
       that would be a fail-OPEN origin-auth bypass);
   (e) the choke is IDEMPOTENT (a second call is a safe no-op).
   Wipe proof (both impls, no use-after-free): the choke fills-0 THEN releases each MASTER slot, and in the SAME
   block sets KEY-MATERIAL-ZEROIZED and NULLs the caches — so the flag + a nulled cache are UAF-safe evidence the
   wipe path ran. The direct read-back-is-all-zero assertion on the master slots is CLASP-only: Clasp free-static
   RECYCLES the vector (live, zeroed) so the read is safe, whereas SBCL free-static-vector frees the whole object
   (header+data) so a post-free read is UAF. The off-heap DISCRIMINATION (a heap array / a derived cache -> NIL) is
   likewise SBCL-only (Clasp/Boehm is non-moving; static-vector-p answers T for any octet vector by design).
   STORAGE change only — the corpus/KAT/roundtrip tests prove keys + wire are unchanged. Both SBCL and Clasp must
   pass identically."
  (let* ((km   (dds.security:generate-key-material :origin-auth t))
         (salt (dds.security:key-material-master-salt km))
         (mkey (dds.security:key-material-master-sender-key km))
         (rkey (dds.security:key-material-master-receiver-specific-key km))
         (rkid (dds.security:key-material-receiver-specific-key-id km))
         (sid  (make-array 4 :element-type '(unsigned-byte 8) :initial-contents '(0 0 0 1)))
         (heap (make-array 32 :element-type '(unsigned-byte 8) :initial-element 7))
         (sbcl (eq (dds.pal:pal-impl-name) :sbcl)))
    ;; (a) MASTER secrets are foreign/static, not GC-heap; a plain heap array is NOT (non-vacuous control)
    (%check :km-salt-static (dds.pal:static-vector-p salt) "master_salt must be foreign/static (off GC heap)")
    (%check :km-mkey-static (dds.pal:static-vector-p mkey) "master_sender_key must be foreign/static")
    (%check :km-rkey-static (dds.pal:static-vector-p rkey) "master_receiver_specific_key must be foreign/static")
    ;; non-vacuous off-heap discrimination is SBCL-only (Clasp/Boehm is non-moving; see the predicate docstring)
    (when sbcl
      (%check :heap-not-static (not (dds.pal:static-vector-p heap))
              "on SBCL a plain GC-heap array must NOT answer static-vector-p (non-vacuous off-heap proof)"))
    (%check :km-salt-real (notevery #'zerop salt) "master_salt must carry real (non-zero) key bytes pre-wipe")
    (%check :km-mkey-real (notevery #'zerop mkey) "master_sender_key must carry real key bytes pre-wipe")
    (%check :km-rkey-real (notevery #'zerop rkey) "master_receiver_specific_key must carry real bytes pre-wipe")
    ;; derived §9.5.3.3.4.2 session-key cache is EPHEMERAL GC-HEAP (NOT foreign-static) + non-zero — the A2 revert
    (let ((sk (dds.security::%km-session-key-at km sid 0)))
      (when sbcl
        (%check :km-sesskey-heap (not (dds.pal:static-vector-p sk))
                "derived session key must be GC-heap (not foreign-static) — no per-session_id foreign leak"))
      (%check :km-sesskey-real (notevery #'zerop sk) "derived session key must be non-zero"))
    (%check :km-cache-populated (not (null (dds.security::key-material-cached-send-session km)))
            "session-key cache populated after derive (pre-wipe)")
    ;; (b) SESSION_ID-ROTATION NO-LEAK: many DISTINCT session_ids -> every derived key GC-heap, never static
    (dotimes (i 8)
      (let* ((rsid (make-array 4 :element-type '(unsigned-byte 8) :initial-contents (list 0 0 0 (+ 2 i))))
             (ck   (dds.security::%km-session-key-at km rsid 0))
             (rk   (dds.security::%km-receiver-session-key-at km rkid rkey rsid 0)))
        (%check :km-rot-common-real (notevery #'zerop ck) "rotated common session key non-zero")
        (%check :km-rot-recv-real   (notevery #'zerop rk) "rotated receiver session key non-zero")
        (when sbcl
          (%check :km-rot-common-heap (not (dds.pal:static-vector-p ck))
                  "each rotated common session key is GC-heap (not foreign-static) — no session_id-rotation leak")
          (%check :km-rot-recv-heap (not (dds.pal:static-vector-p rk))
                  "each rotated receiver session key is GC-heap (not foreign-static)")
          (%check :km-rot-recv-mkey-heap
                  (not (dds.pal:static-vector-p
                        (dds.security::session-cache-recv-master-key
                         (dds.security::key-material-cached-recv-session km))))
                  "the recv session-cache's master-key discriminant is GC-heap (not foreign-static)"))))
    ;; after rotation the cache slot still holds ONE heap vector (bounded single slot, GC-reclaimable — no leak)
    (when sbcl
      (%check :km-cache-slot-heap
              (not (dds.pal:static-vector-p
                    (dds.security::session-cache-key
                     (dds.security::key-material-cached-send-session km))))
              "the session-cache holds a single GC-heap key after rotation (bounded, no foreign leak)"))
    ;; (c) zeroize-on-teardown wipes MASTER secrets + drops the caches + marks the KM unusable
    (%check :km-not-yet-zeroized (not (dds.security:key-material-zeroized km))
            "KM must not be marked zeroized before the choke (non-vacuous)")
    (%check :km-zeroize-returns-nil (null (dds.security:zeroize-key-material km))
            "zeroize-key-material returns NIL")
    (%check :km-zeroized-flag (dds.security:key-material-zeroized km)
            "zeroize-key-material sets the fail-closed KEY-MATERIAL-ZEROIZED marker")
    ;; UAF-safe on both impls: the caches (which held real key bytes) are dropped in the same wipe block
    (%check :km-cache-nulled (null (dds.security::key-material-cached-send-session km))
            "derived session-key cache dropped after the choke")
    (%check :km-recv-cache-nulled (null (dds.security::key-material-cached-recv-session km))
            "receiver-key cache dropped after the choke")
    ;; direct read-back byte-wipe proof is Clasp-only (recycle-safe); SBCL frees the whole object (post-free = UAF)
    (when (eq (dds.pal:pal-impl-name) :clasp)
      (%check :km-salt-wiped (every #'zerop salt) "master_salt bytes wiped to all-zero after the choke (Clasp recycle read)")
      (%check :km-mkey-wiped (every #'zerop mkey) "master_sender_key bytes wiped to all-zero after the choke")
      (%check :km-rkey-wiped (every #'zerop rkey) "master_receiver_specific_key bytes wiped to all-zero after the choke"))
    ;; (d) FAIL-CLOSED GUARD: the master-secret-reading entries SIGNAL on a zeroized KM (no UAF of freed masters)
    (flet ((fail-closed-p (thunk)
             (handler-case (progn (funcall thunk) nil)
               (dds.security:key-material-zeroized-error () t))))
      (%check :km-guard-session
              (fail-closed-p (lambda () (dds.security::%km-session-key-at km sid 0)))
              "%km-session-key-at fails closed (signals) on a zeroized KM — no dereference of freed masters")
      (%check :km-guard-recv
              (fail-closed-p (lambda ()
                               (dds.security::%km-receiver-session-key-at
                                km
                                (make-array 4 :element-type '(unsigned-byte 8) :initial-element 1)
                                (make-array 32 :element-type '(unsigned-byte 8) :initial-element 2)
                                sid 0)))
              "%km-receiver-session-key-at fails closed on a zeroized KM")
      (%check :km-guard-descr
              (fail-closed-p (lambda () (dds.security::km-receiver-descriptor-list km)))
              "km-receiver-descriptor-list fails closed on a zeroized KM (never a fail-OPEN NIL bypass)"))
    ;; (e) idempotent: a second call is a safe no-op
    (%check :km-zeroize-idempotent (null (dds.security:zeroize-key-material km))
            "zeroize-key-material is idempotent (second call = NIL no-op, no crash)"))
  t)
