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
  (handler-case (dds.dare:dare-available-p)
    (dds.dare:dare-unavailable (c)
      (format t "~&  [security-secured-payload] SKIP — OpenSSL >= 3.5 not available: ~a~%"
              (dds.dare:dare-unavailable-reason c))
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

    ;; (c) fail-closed: truncated inputs (< 44-octet minimum) must SIGNAL, never OOB-read.
    (dolist (short-len '(0 1 19 20 24 43))
      (let ((short (make-array short-len :element-type '(unsigned-byte 8) :initial-element #x00)))
        (%check :parse-truncated
                (handler-case (progn (dds.security:parse-secured-payload short) nil)
                  (dds.security:secured-payload-malformed () t))
                (format nil "parse truncated (len=~d) must signal secured-payload-malformed" short-len))))
    ;; (c) fail-closed: a crypto_content.length that overflows the buffer must SIGNAL.
    (let ((over (copy-seq got)))
      ;; SecureDataHeader is 20 bytes; ct_len uint32 BE lives at offset 20. Inflate it to 0xffffffff (endian-invariant).
      (setf (aref over 20) #xff (aref over 21) #xff (aref over 22) #xff (aref over 23) #xff)
      (%check :parse-overdeclared
              (handler-case (progn (dds.security:parse-secured-payload over) nil)
                (dds.security:secured-payload-malformed () t))
              "parse with over-declared crypto_content.length must signal (no OOB read)")))

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
  (handler-case (dds.dare:dare-available-p)
    (dds.dare:dare-unavailable (c)
      (format t "~&  [security-payload-roundtrip] SKIP — OpenSSL >= 3.5 not available: ~a~%"
              (dds.dare:dare-unavailable-reason c))
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

(defun* run-security-payload-fuzz-test ()
    (function () t)
  "Fuzz decode-serialized-payload with N=2000 random/short/oversized inputs (both prod + (safety 0)).
   Invariant: for every input, decode returns NIL or the correct plaintext — never OOB, never crash,
   never a partial decode, never a signal escaping to the caller (NFR-SEC-POSTURE). Includes the
   minimum-size boundary (< 44 bytes), over-declared ct_len, all-zero payloads of every size 0..80,
   and fully random 60-byte payloads with random header fields (valid parse, invalid ciphertext).
   Requires OpenSSL >= 3.5; skips only if truly absent. Both SBCL and Clasp must pass identically."
  (handler-case (dds.dare:dare-available-p)
    (dds.dare:dare-unavailable (c)
      (format t "~&  [security-payload-fuzz] SKIP — OpenSSL >= 3.5 not available: ~a~%"
              (dds.dare:dare-unavailable-reason c))
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
  (handler-case (dds.dare:dare-available-p)
    (dds.dare:dare-unavailable (c)
      (format t "~&  [security-encrypted-pubsub] SKIP — OpenSSL >= 3.5 not available: ~a~%"
              (dds.dare:dare-unavailable-reason c))
      (return-from run-security-encrypted-pubsub-test t)))

  ;; ONE shared km instance: both pub and sub share the same iv-counter so nonces never collide.
  (let* ((shared-km (dds.security:make-test-key-material))
         (pt (make-array 8 :element-type '(unsigned-byte 8)
                           :initial-contents '(#x53 #x51 #x55 #x41 #x52 #x45 #x20 #x01))) ; "SQUARE  "
         (pub-prefix (%make-test-prefix #xE1))
         (sub-prefix (%make-test-prefix #xE2))
         (plain-prefix (%make-test-prefix #xE3))
         ;; PUB: encodes on publish; SUB: decodes on receive; PLAIN: no crypto (sees raw wire bytes)
         (pub-node (dds.disc:make-disc-node :guid-prefix pub-prefix :domain 83
                                            :host "127.0.0.1" :port 0 :multicast nil
                                            :crypto-transform shared-km))
         (sub-node (dds.disc:make-disc-node :guid-prefix sub-prefix :domain 83
                                            :host "127.0.0.1" :port 0 :multicast nil
                                            :crypto-transform shared-km))
         (plain-node (dds.disc:make-disc-node :guid-prefix plain-prefix :domain 83
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
           ;; (a) SUB receives the decrypted plaintext PT byte-exact (§9.5.3.3.4.5)
           (%check :crypto-sub-received
                   (plusp (dds.disc:node-sample-count sub-node))
                   "sub-with-key did not receive any sample")
           (let* ((sub-key (first (dds.disc:node-sample-sns sub-node)))
                  (sub-payload (dds.disc:node-sample sub-node sub-key)))
             (%check :crypto-sub-plaintext
                     (and sub-payload (equalp sub-payload pt))
                     (format nil "sub-with-key received ~a but expected plaintext ~{~2,'0x~^ ~}"
                             (and sub-payload (coerce sub-payload 'list))
                             (coerce pt 'list))))
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

(defun* run-security-encrypted-fragmented-test ()
    (function () t)
  "DDS-Security §9.5.3.3 Slice-1 DATA_FRAG path: encode -> fragment -> reassemble -> decode (ADR 0031).
   Two nodes on domain 84 (no collision with domain-83 pubsub test); BOTH share ONE key-material instance.
   Plaintext is 2000 octets (> dds.rtps.reliable:*fragment-size* 1024), so the encoded SecuredPayload
   (plaintext + ~44-byte SecureDataHeader overhead) fragments into multiple DATA_FRAGs on send.
   Asserts the subscriber receives the EXACT 2000-byte original plaintext byte-exact after
   encode -> fragment -> reassemble -> decode — proving the common-sink decode covers the DATA_FRAG path.
   Requires OpenSSL >= 3.5; skips only if truly absent. Both SBCL and Clasp must pass identically."
  (handler-case (dds.dare:dare-available-p)
    (dds.dare:dare-unavailable (c)
      (format t "~&  [security-encrypted-fragmented] SKIP — OpenSSL >= 3.5 not available: ~a~%"
              (dds.dare:dare-unavailable-reason c))
      (return-from run-security-encrypted-fragmented-test t)))

  ;; ONE shared km — two instances would collide nonces under the same master key (ADR 0031 §T2).
  (let* ((shared-km (dds.security:make-test-key-material))
         ;; 2000-byte recognizable pattern: octet[i] = (i*7) mod 256
         (pt-size 2000)
         (pt (let ((v (make-array pt-size :element-type '(unsigned-byte 8))))
               (dotimes (i pt-size v) (setf (aref v i) (logand (* i 7) #xff)))))
         (pub-prefix (%make-test-prefix #xF1))
         (sub-prefix (%make-test-prefix #xF2))
         (pub-node (dds.disc:make-disc-node :guid-prefix pub-prefix :domain 84
                                            :host "127.0.0.1" :port 0 :multicast nil
                                            :crypto-transform shared-km))
         (sub-node (dds.disc:make-disc-node :guid-prefix sub-prefix :domain 84
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
  (handler-case (dds.dare:dare-available-p)
    (dds.dare:dare-unavailable (c)
      (format t "~&  [security-submessage] SKIP — OpenSSL >= 3.5 not available: ~a~%"
              (dds.dare:dare-unavailable-reason c))
      (return-from run-security-submessage-corpus-test t)))
  (let ((sub (%t2-fixed-plain-submessage)))
    (%t2-corpus-encrypt sub)
    (%t2-corpus-sign sub)
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
   Requires OpenSSL >= 3.5; skips only if truly absent. Both SBCL and Clasp must pass identically."
  (handler-case (dds.dare:dare-available-p)
    (dds.dare:dare-unavailable (c)
      (format t "~&  [security-origin-auth] SKIP — OpenSSL >= 3.5 not available: ~a~%"
              (dds.dare:dare-unavailable-reason c))
      (return-from run-security-origin-auth-test t)))
  (let ((sub (%t2-fixed-plain-submessage)))
    (%t3-corpus-encode sub)
    (%t3-corpus-decode sub)
    (%t3-kdf-mac-units))
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
  (handler-case (dds.dare:dare-available-p)
    (dds.dare:dare-unavailable (c)
      (format t "~&  [security-rtps-message] SKIP — OpenSSL >= 3.5 not available: ~a~%"
              (dds.dare:dare-unavailable-reason c))
      (return-from run-security-rtps-message-corpus-test t)))
  (let ((stream (%t4-fixed-stream)))
    (%t4-corpus-encrypt stream)
    (%t4-corpus-sign stream)
    (%t4-corpus-roundtrip stream)
    (%t4-corpus-negatives stream)
    (%t4-corpus-origin-auth stream))
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
  (handler-case (dds.dare:dare-available-p)
    (dds.dare:dare-unavailable (c)
      (format stream "~&  [rtps-message-bench] SKIP — OpenSSL >= 3.5 not available: ~a~%"
              (dds.dare:dare-unavailable-reason c))
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
  (handler-case (dds.dare:dare-available-p)
    (dds.dare:dare-unavailable (c)
      (format stream "~&  [rtps-protection-bench] SKIP — OpenSSL >= 3.5 not available: ~a~%"
              (dds.dare:dare-unavailable-reason c))
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
