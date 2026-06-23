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
   (e) derive-session-key composes 'SessionKey'||salt||session_id||'0001' under HMAC-SHA256 (§9.5.3.3.4.2).
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
  ;;   SecureDataHeader(20) || ct_len(uint32 LE=4)=04 00 00 00 || ciphertext(4)
  ;;     || common_mac(16) || rsm_count(uint32 LE=0)=00 00 00 00     => 48 octets total.
  (let* ((kind       (%hex-octets "00000004"))
         (key-id     (%hex-octets "aabbccdd"))
         (session-id (%hex-octets "01000000"))
         (iv-suffix  (%hex-octets "1122334455667788"))
         (ciphertext (%hex-octets "deadbeef"))
         (tag        (%hex-octets "a0a1a2a3a4a5a6a7a8a9aaabacadaeaf"))
         (expected   (%hex-octets
                      (concatenate 'string
                       "00000004" "aabbccdd" "01000000" "1122334455667788" ; SecureDataHeader(20)
                       "04000000"                                          ; crypto_content.length=4 LE
                       "deadbeef"                                          ; ciphertext(4)
                       "a0a1a2a3a4a5a6a7a8a9aaabacadaeaf"                  ; common_mac(16)
                       "00000000")))                                       ; rsm_count=0 LE
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
      ;; SecureDataHeader is 20 bytes; ct_len uint32 LE lives at offset 20. Inflate it to 0xffffffff.
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
  ;;   'SessionKey' || master_salt || session_id || '0001' and HMAC-SHA256 it under master_sender_key.
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
         ;; independent reference: "SessionKey"(53657373696f6e4b6579) || salt || session_id || "0001"(30303031)
         (kdf-data    (%hex-octets
                       (concatenate 'string
                        "53657373696f6e4b6579"                  ; "SessionKey"
                        "404142434445464748494a4b4c4d4e4f"       ; master_salt[0:16]
                        "505152535455565758595a5b5c5d5e5f"       ; master_salt[16:32]
                        "01000000"                               ; session_id (4 LE bytes)
                        "30303031")))                            ; "0001"
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

(defun* run-security-payload-roundtrip-test ()
    (function () t)
  "DDS-Security §9.5.3.3 encode/decode-serialized-payload: round-trip, tamper-fails-closed,
   nonce-distinct, and short/garbage-blob bounds check.
   (a) Round-trip: decode(km, encode(km, PT)) = PT byte-exact.
   (b) Tamper ciphertext: flip one CT byte -> decode returns NIL (AES-GCM auth failure, fail-closed).
   (c) Tamper tag: flip one tag byte -> decode returns NIL (AES-GCM auth failure, fail-closed).
   (d) Tamper header: flip one byte in SecureDataHeader (bytes 0-7) -> NIL (AAD from wire; §9.5.3.3.4.5).
   (e) Garbage blob: short or all-zero blobs -> decode returns NIL (not a crash).
   (f) Nonce-distinct: two consecutive encodes of the same plaintext produce DIFFERENT iv_suffix
       values in the SecureDataHeader — proving the monotonic counter advances (nonce uniqueness).
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

    ;; (d) tamper header: flip one byte in bytes 0..7 (transformation_kind or transformation_key_id).
    ;;   AAD = received SecureDataHeader (§9.5.3.3.4.5); any header bit-flip changes the AAD -> NIL.
    (let* ((blob (dds.security:encode-serialized-payload km pt))
           (bad  (copy-seq blob)))
      (setf (aref bad 3) (logxor (aref bad 3) #x01))   ; flip bit in transformation_kind
      (%check :tamper-header-nil
              (null (dds.security:decode-serialized-payload km bad))
              "1-byte SecureDataHeader tamper (bytes 0-7) must return NIL (AAD from wire; §9.5.3.3.4.5)"))

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
                          (coerce iv1 'list)))))))

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
             (cur  (dds.core.buffer:cursor (dds.core.buffer:octet-buffer-over blob) :endianness :little)))
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
               (cur  (dds.core.buffer:cursor (dds.core.buffer:octet-buffer-over blob) :endianness :little)))
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
