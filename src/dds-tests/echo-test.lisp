(in-package #:dds.tests)

(define-condition test-failure (error)
  ((name :initarg :name :reader test-failure-name)
   (detail :initarg :detail :reader test-failure-detail))
  (:report (lambda (c s) (format s "TEST FAILED [~a]: ~a"
                                 (test-failure-name c) (test-failure-detail c)))))


(defun* %check (name ok detail)
    (function (t t t) t)
  "Test assertion: unless OK, signal TEST-FAILURE named NAME with DETAIL; otherwise return T."
  (unless ok (error 'test-failure :name name :detail detail))
  t)

(defun* octets (&rest bytes)
    (function (&rest (unsigned-byte 8)) (simple-array (unsigned-byte 8) (*)))
  "Build a (simple-array (unsigned-byte 8) (*)) from the BYTES argument list (test fixture)."
  (make-array (length bytes) :element-type '(unsigned-byte 8)
                             :initial-contents bytes))

(defun* run-echo-test ()
    (function () t)
  "M0 exit test: octets -> static pooled buffer -> mock loopback transport ->
   read back -> verify identity -> release -> verify zero leak."
  (let* ((arena (dds.core.arena:init-arena :bytes (* 256 1024)))
         (pool (dds.core.arena:make-buffer-pool arena 256 8))
         (payload (octets 68 68 83 45 69 67 72 79))   ; "DDS-ECHO"
         (n (length payload))
         (sbuf (dds.core.arena:pool-acquire pool))
         (received nil))
    (%check :pool-acquire sbuf "pool-acquire returned NIL (unexpected exhaustion)")
    (let ((wc (dds.core.buffer:cursor sbuf :endianness :little)))
      (dds.core.buffer:put-octets wc payload 0 n)
      (let ((tr (dds.xport:make-mock-transport
                 :on-receive
                 (lambda (buffer off len)
                   (declare (ignore off))
                   (let ((rc (dds.core.buffer:cursor buffer :endianness :little))
                         (dst (make-array len :element-type '(unsigned-byte 8))))
                     (dds.core.buffer:get-octets rc dst 0 len)
                     (setf received dst))))))
        (dds.xport:send tr nil sbuf 0 n)))
    (%check :received-non-nil received "transport never delivered the payload")
    (%check :round-trip (equalp received payload)
            (format nil "round-trip mismatch: ~s vs ~s" received payload))
    (dds.core.arena:pool-release pool sbuf)
    (%check :zero-leak (zerop (dds.core.arena:pool-in-use pool))
            "pool in-use non-zero after release (buffer leak)")
    (%check :high-water (= 1 (dds.core.arena:pool-high-water pool))
            "unexpected pool high-water mark")
    (dds.core.arena:teardown-arena arena)
    t))

;;; XCDR codec round-trip (M1, P0). Hand-written codec in the shape the type
;;; compiler will emit; proves internal consistency + the XCDR2 alignment cap.
;;; tsample's i64 follows one i32, so it sits at a 4-aligned/not-8-aligned offset:
;;; XCDR1 pads to 8, XCDR2 does not — the encodings MUST differ in length (R3).

(defstruct* (tsample (:constructor make-tsample))
  "Test fixture struct (i32 id; i64 ts; string label) exercising the hand-written XCDR byte-exact reference codec."
  (id 0 :type (signed-byte 32))
  (ts 0 :type (signed-byte 64))
  (label "" :type string))


(defun* tsample= (a b)
    (function (tsample tsample) boolean)
  "Field-by-field equality of two TSAMPLE test structs."
  (and (= (tsample-id a) (tsample-id b))
       (= (tsample-ts a) (tsample-ts b))
       (string= (tsample-label a) (tsample-label b))))

(defun* serialize-tsample (p c mode)
    (function (tsample dds.core.buffer:cursor symbol) t)
  "Serialize TSAMPLE P into cursor C in XCDR MODE via the hand-written reference codec (byte-exact test)."
  (dds.cdr:cdr-put-i32 c (tsample-id p) mode)
  (dds.cdr:cdr-put-i64 c (tsample-ts p) mode)
  (dds.cdr:cdr-put-string c (tsample-label p) mode))

(defun* deserialize-tsample (c mode)
    (function (dds.core.buffer:cursor symbol) tsample)
  "Deserialize a TSAMPLE from cursor C in XCDR MODE via the hand-written reference codec."
  (let* ((id (dds.cdr:cdr-get-i32 c mode))
         (ts (dds.cdr:cdr-get-i64 c mode))
         (label (dds.cdr:cdr-get-string c mode)))
    (make-tsample :id id :ts ts :label label)))

(defun* run-codec-roundtrip-test ()
    (function () t)
  "Serialize/deserialize a struct in both XCDR modes; verify identity and that
   the 8-byte member forces an XCDR1/XCDR2 length divergence (FR-CDR-2, R3)."
  (let* ((arena (dds.core.arena:init-arena :bytes (* 256 1024)))
         (pool (dds.core.arena:make-buffer-pool arena 512 4))
         (p (make-tsample :id -7 :ts -1234567890123 :label "shape")))
    (flet ((rt (mode)
             (let* ((b (dds.core.arena:pool-acquire pool))
                    (wc (dds.core.buffer:cursor b :endianness :little)))
               (serialize-tsample p wc mode)
               (let ((len (dds.core.buffer:cursor-position wc))
                     (rc (dds.core.buffer:cursor b :endianness :little)))
                 (let ((q (deserialize-tsample rc mode)))
                   (dds.core.arena:pool-release pool b)
                   (values q len))))))
      (multiple-value-bind (q1 len1) (rt :xcdr1)
        (multiple-value-bind (q2 len2) (rt :xcdr2)
          (%check :xcdr1-roundtrip (tsample= p q1) "XCDR1 round-trip mismatch")
          (%check :xcdr2-roundtrip (tsample= p q2) "XCDR2 round-trip mismatch")
          (%check :xcdr-alignment-divergence (/= len1 len2)
                  (format nil "expected XCDR1(~d) != XCDR2(~d) for an 8-byte member"
                          len1 len2))
          (dds.core.arena:teardown-arena arena)
          t)))))

;;; Byte-exact corpus seed (M1, P0). Values are pinned from the in-repo normative
;;; specs (docs/specs): encapsulation ids from XTypes 1.3 §7.6 Table 60 (the wire
;;; identifier table, dissector-confirmed); EMHEADER1 from §7.4.3.4.2; RTPS 2.5 §10.2.
;;; This is the spec-sourced seed of FR-CDR-8; full payload byte-exactness vs. RTI
;;; vectors is the interop follow-up.

(defun* %first-bytes (buf n)
    (function (dds.core.buffer:octet-buffer (integer 0)) list)
  "The first N octets of octet-buffer BUF as a list (test diagnostic)."
  (let ((vec (dds.core.buffer:octet-buffer-vec buf)))
    (loop for i below n collect (aref vec i))))

(defun* run-byte-exact-test ()
    (function () t)
  "Test: XCDR1 vs XCDR2 byte-exact seed vectors + the 8-byte-alignment divergence (FR-CDR, P0)."
  (let* ((arena (dds.core.arena:init-arena :bytes (* 64 1024)))
         (pool (dds.core.arena:make-buffer-pool arena 64 6)))
    (flet ((fresh (&optional (e :little))
             (dds.core.buffer:cursor (dds.core.arena:pool-acquire pool) :endianness e)))
      ;; encapsulation header bytes (XTypes 1.3 §7.6 Table 60 / RTPS §10.2),
      ;; tshark-RTPS-dissector-confirmed: CDR2_LE=0x07, PL_CDR2_BE=0x0a.
      (let ((c (fresh)))
        (dds.cdr:make-encapsulation-header c :plain-cdr2-le)
        (%check :encap-plain-cdr2-le
                (equal '(#x00 #x07 #x00 #x00)
                       (%first-bytes (dds.core.buffer:cursor-buffer c) 4))
                "PLAIN_CDR2_LE header bytes")
        (%check :encap-origin (= 4 (dds.core.buffer:cursor-origin c))
                "alignment origin not reset to 4"))
      (let ((c (fresh)))
        (dds.cdr:make-encapsulation-header c :pl-cdr2-be)
        (%check :encap-pl-cdr2-be
                (equal '(#x00 #x0a #x00 #x00)
                       (%first-bytes (dds.core.buffer:cursor-buffer c) 4))
                "PL_CDR2_BE header bytes"))
      ;; header parse round-trip
      (let ((c (fresh)))
        (dds.cdr:make-encapsulation-header c :delimited-cdr-le)
        (dds.core.buffer:cursor-reset c)
        (multiple-value-bind (rep opt) (dds.cdr:parse-encapsulation-header c)
          (%check :encap-parse (and (eq rep :delimited-cdr-le) (= opt 0))
                  "header parse round-trip")))
      ;; primitive byte-exactness
      (let ((c (fresh)))
        (dds.cdr:cdr-put-i32 c 1 :xcdr2)
        (%check :i32-le-one (equal '(#x01 #x00 #x00 #x00)
                                   (%first-bytes (dds.core.buffer:cursor-buffer c) 4))
                "i32=1 little-endian"))
      (let ((c (fresh :big)))
        (dds.cdr:cdr-put-u16 c #x0102 :xcdr2)
        (%check :u16-be (equal '(#x01 #x02)
                               (%first-bytes (dds.core.buffer:cursor-buffer c) 2))
                "u16=0x0102 big-endian"))
      ;; EMHEADER1 bitfield (XTypes §7.4.3.4.2): M_FLAG=1, LC=2(4-byte), id=5
      (%check :emheader1-encode (= #xA0000005 (dds.cdr:emheader1-encode t 2 5))
              "EMHEADER1 encode")
      (multiple-value-bind (mu lc id) (dds.cdr:emheader1-decode #xA0000005)
        (%check :emheader1-decode (and mu (= lc 2) (= id 5)) "EMHEADER1 decode"))
      ;; RTPS §10.2 origin reset: XCDR1 8-byte alignment is relative to the
      ;; post-header origin (pos 4), not buffer position 0.
      (let ((c (fresh :big)))
        (dds.cdr:make-encapsulation-header c :plain-cdr-be)   ; origin->4, pos 4
        (dds.cdr:cdr-put-u8 c 9 :xcdr1)                        ; pos 5
        (dds.cdr:cdr-put-i64 c 1 :xcdr1)                       ; align8 rel origin -> pos 12, then +8
        (%check :origin-align (= 20 (dds.core.buffer:cursor-position c))
                "XCDR1 8-byte alignment must be relative to the post-header origin"))
      (dds.core.arena:teardown-arena arena)
      t)))

;;; MD5 (RFC 1321) — vendored clean-room (M4 foundation for XTypes EquivalenceHash/
;;; NameHash + the >16-byte keyhash). Verified byte-exact against the RFC 1321 test
;;; suite AND the XTypes spec NameHash example ("color" -> 70 dd a5 df).

(defun* %ascii-octets (s)
    (function (string) (simple-array (unsigned-byte 8) (*)))
  "The ASCII code points of string S as a (simple-array (unsigned-byte 8) (*))."
  (map '(simple-array (unsigned-byte 8) (*)) #'char-code s))

(defun* %hex-octets (hex)
    (function (string) (simple-array (unsigned-byte 8) (*)))
  "Parse hex string HEX (whitespace ignored) into a (simple-array (unsigned-byte 8) (*))."
  (let ((out (make-array (floor (length hex) 2) :element-type '(unsigned-byte 8))))
    (dotimes (i (length out) out)
      (setf (aref out i) (parse-integer hex :start (* 2 i) :end (+ 2 (* 2 i)) :radix 16)))))

(defun* run-md5-test ()
    (function () t)
  "MD5 byte-exactness vs the RFC 1321 test suite + the XTypes NameHash example."
  (flet ((chk (name input expected-hex)
           (%check name (equalp (dds.core.md5:md5 (%ascii-octets input)) (%hex-octets expected-hex))
                   (format nil "MD5(~s) mismatch" input))))
    (chk :md5-empty  "" "d41d8cd98f00b204e9800998ecf8427e")
    (chk :md5-a      "a" "0cc175b9c0f1b6a831c399e269772661")
    (chk :md5-abc    "abc" "900150983cd24fb0d6963f7d28e17f72")
    (chk :md5-msg    "message digest" "f96b697d7cb7938d525a2f31aaf161d0")
    (chk :md5-alpha  "abcdefghijklmnopqrstuvwxyz" "c3fcd3d76192e4007dfb496cca67e13b")
    ;; 80 octets -> spans two blocks (exercises the multi-block + padding path)
    (chk :md5-80     "12345678901234567890123456789012345678901234567890123456789012345678901234567890"
                     "57edf4a22be3c955ac49da2e2107b67a")
    ;; XTypes 1.3 §TypeObject NameHash example: MD5("color")[0:4] = 70 dd a5 df
    (%check :md5-namehash-color
            (equalp (subseq (dds.core.md5:md5 (%ascii-octets "color")) 0 4)
                    (octets #x70 #xdd #xa5 #xdf))
            "XTypes NameHash example color -> 70 dd a5 df"))
  t)

(defun* run-all-tests ()
    (function () t)
  "Run every landed test; signal on first failure, else report and return T."
  (let ((tests '(("md5-rfc1321"               . run-md5-test)
                 ("echo-over-mock-transport" . run-echo-test)
                 ("xcdr-codec-roundtrip"     . run-codec-roundtrip-test)
                 ("xcdr-byte-exact-seed"     . run-byte-exact-test)
                 ("xcdr-generated-type"      . run-generated-type-test)
                 ("xcdr-generated-sequence"  . run-generated-sequence-test)
                 ("xcdr-generated-nested"    . run-generated-nested-test)
                 ("dds-keyhash"              . run-keyhash-test)
                 ("xtypes-model"             . run-xtypes-model-test)
                 ("xtypes-assignability"     . run-assignability-test)
                 ("xtypes-typeobject-cdr"    . run-typeobject-cdr-test)
                 ("xtypes-type-information"  . run-type-information-test)
                 ("xtypes-type-object-lb"    . run-type-object-lb-test)
                 ("sedp-type-object-lb"      . run-sedp-type-object-lb-test)
                 ("xtypes-type-compat-soft"  . run-type-compat-soft-test)
                 ("sedp-type-information"    . run-sedp-type-information-test)
                 ("zero-alloc-into"          . run-generated-into-test)
                 ("rtps-wire-byte-exact"     . run-rtps-wire-test)
                 ("rtps-seqnum-bitmap"       . run-rtps-seqnum-test)
                 ("rtps-fragnum-set"         . run-fragnum-set-test)
                 ("rtps-submessages"         . run-rtps-submessage-test)
                 ("rtps-data"                . run-rtps-data-test)
                 ("rtps-data-frag"           . run-rtps-data-frag-test)
                 ("rtps-heartbeat-frag"      . run-heartbeat-frag-test)
                 ("rtps-nack-frag"           . run-nack-frag-test)
                 ("rtps-reassembly"          . run-reassembly-test)
                 ("rtps-frag-acknack"        . run-frag-acknack-test)
                 ("rtps-frag-plan"           . run-frag-plan-test)
                 ("rtps-writer-frag-glue"    . run-writer-frag-glue-test)
                 ("rtps-frag-roundtrip"      . run-frag-roundtrip-test)
                 ("rtps-frag-lossy"          . run-frag-lossy-test)
                 ("rtps-message-dispatch"    . run-rtps-dispatch-test)
                 ("rtps-parameterlist"       . run-paramlist-test)
                 ("rtps-port-mapping"        . run-port-mapping-test)
                 ("rtps-history-cache"       . run-history-test)
                 ("rtps-reliable-delivery"   . run-reliability-test)
                 ("rtps-gap-handling"        . run-gap-handling-test)
                 ("property-based"           . run-pbt-tests)
                 ("udp-loopback"             . run-udp-loopback-test)
                 ("rtps-discovery-spdp"      . dds.rtps.discovery:run-discovery-test)
                 ("rtps-discovery-sedp"      . dds.rtps.discovery:run-sedp-test)
                 ("udp-transport"           . dds.xport.udp:run-udp-transport-test)
                 ("udp-receiver-thread"      . dds.xport.udp:run-udp-receiver-test)
                 ("end-to-end-udp"           . run-end-to-end-test)
                 ("spdp-discovery-over-udp"  . dds.disc:run-spdp-discovery-test)
                 ("sedp-matching-over-udp"   . dds.disc:run-sedp-discovery-test)
                 ("multicast-spdp-discovery" . dds.disc:run-mcast-discovery-test)
                 ("foreign-locator-robust"   . dds.disc:run-locator-filter-test)
                 ("reliable-data-over-udp"   . dds.disc:run-dataplane-test)
                 ("typed-shape-over-udp"     . run-typed-dataplane-test)
                 ("qos-rxo-truth-table"      . dds.qos:run-qos-rxo-test)
                 ("dcps-entity-write-take"   . run-dcps-entity-test)
                 ("dcps-instance-read-take"  . run-dcps-instance-test)
                 ("dcps-rxo-blocks-match"    . run-dcps-rxo-test)
                 ("dcps-conditions-waitset"  . run-dcps-waitset-test)
                 ("dcps-matched-status"      . run-dcps-matched-status-test)
                 ("dcps-incompatible-qos"    . run-dcps-incompatible-qos-test)
                 ("dcps-query-condition"     . run-dcps-query-condition-test)
                 ("dcps-condvar-wake"        . run-dcps-condvar-wake-test)
                 ("dcps-content-filter"      . run-dcps-filter-test)
                 ("dcps-content-filtered-topic" . run-dcps-content-filtered-topic-test)
                 ("dcps-querycondition-sql"  . run-dcps-querycondition-sql-test)
                 ("dcps-inconsistent-topic"  . run-dcps-inconsistent-topic-test)
                 ("dcps-sample-rejected"     . run-dcps-sample-rejected-test)
                 ("dcps-builtin-topics"      . run-dcps-builtin-topics-test)
                 ("dcps-type-compat"         . run-dcps-type-compat-test))))
    (dolist (test tests)
      (format t "~&  [test] ~a ... " (car test))
      (funcall (cdr test))
      (format t "ok~%"))
    (format t "~&tests: ~d passed.~%" (length tests))
    t))
