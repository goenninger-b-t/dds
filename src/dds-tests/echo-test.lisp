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
          ;; hostile wire lengths must signal buffer-overflow BEFORE any allocation (NFR-SEC-POSTURE)
          (let* ((b (dds.core.arena:pool-acquire pool))
                 (wc (dds.core.buffer:cursor b :endianness :little)))
            (dds.cdr:cdr-put-u32 wc #xFFFFFFFF :xcdr2)
            (flet ((overflows-p (reader)
                     (handler-case
                         (progn (funcall reader (dds.core.buffer:cursor b :endianness :little))
                                nil)
                       (dds.core.buffer:buffer-overflow () t)
                       (serious-condition () nil))))
              (%check :hostile-string-length
                      (overflows-p (lambda (rc) (dds.cdr:cdr-get-string rc :xcdr2)))
                      "cdr-get-string must pre-validate a 0xFFFFFFFF length (buffer-overflow)")
              (%check :hostile-sequence-count
                      (overflows-p (lambda (rc)
                                     (dds.cdr:cdr-get-sequence rc #'dds.cdr:cdr-get-u8 :xcdr2)))
                      "cdr-get-sequence must pre-validate a 0xFFFFFFFF count (buffer-overflow)"))
            (dds.core.arena:pool-release pool b))
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

(defun* run-encap-options-pad-test ()
    (function () t)
  "Test: the encapsulation options low-2-bits encode the trailing pad count to the next
   4-byte boundary for ALL CDR representations including PLAIN_CDR/XCDR1 (XTypes 1.3
   §7.6.3.1.2, D3 — the clause is universal, its normative example uses PLAIN_CDR);
   parse recovers it."
  (let* ((arena (dds.core.arena:init-arena :bytes (* 64 1024)))
         (pool (dds.core.arena:make-buffer-pool arena 64 8)))
    (flet ((fresh ()
             (dds.core.buffer:cursor (dds.core.arena:pool-acquire pool) :endianness :little))
           (opt-lo (c) (aref (dds.core.buffer:octet-buffer-vec (dds.core.buffer:cursor-buffer c)) 3)))
      ;; body-len 5 -> pad 3
      (let ((c (fresh)))
        (dds.cdr:make-encapsulation-header c :plain-cdr2-le)
        (loop repeat 5 do (dds.core.buffer:put-u8 c #xaa))
        (dds.cdr:finalize-encapsulation-options c :plain-cdr2-le)
        (%check :pad-5 (= 3 (logand (opt-lo c) 3)) "body-len 5 must encode pad 3"))
      ;; body-len 1 -> pad 3
      (let ((c (fresh)))
        (dds.cdr:make-encapsulation-header c :plain-cdr2-le)
        (dds.core.buffer:put-u8 c #xaa)
        (dds.cdr:finalize-encapsulation-options c :plain-cdr2-le)
        (%check :pad-1 (= 3 (logand (opt-lo c) 3)) "body-len 1 must encode pad 3"))
      ;; body-len 2 -> pad 2
      (let ((c (fresh)))
        (dds.cdr:make-encapsulation-header c :plain-cdr2-le)
        (dds.core.buffer:put-u8 c #xaa) (dds.core.buffer:put-u8 c #xbb)
        (dds.cdr:finalize-encapsulation-options c :plain-cdr2-le)
        (%check :pad-2 (= 2 (logand (opt-lo c) 3)) "body-len 2 must encode pad 2"))
      ;; body-len 4 (4-aligned) -> pad 0
      (let ((c (fresh)))
        (dds.cdr:make-encapsulation-header c :plain-cdr2-le)
        (loop repeat 4 do (dds.core.buffer:put-u8 c #xaa))
        (dds.cdr:finalize-encapsulation-options c :plain-cdr2-le)
        (%check :pad-0 (= 0 (logand (opt-lo c) 3)) "4-aligned body must encode pad 0"))
      ;; XCDR1 (PLAIN_CDR) also encodes the pad — §7.6.3.1.2 is universal (its example is PLAIN_CDR)
      (let ((c (fresh)))
        (dds.cdr:make-encapsulation-header c :plain-cdr-be)
        (dds.core.buffer:put-u8 c #xaa)
        (dds.cdr:finalize-encapsulation-options c :plain-cdr-be)
        (%check :pad-xcdr1 (= 3 (logand (opt-lo c) 3)) "PLAIN_CDR body-len 1 must encode pad 3"))
      ;; round-trip: parse recovers the pad count as a third value
      (let ((c (fresh)))
        (dds.cdr:make-encapsulation-header c :plain-cdr2-le)
        (loop repeat 5 do (dds.core.buffer:put-u8 c #xaa))
        (dds.cdr:finalize-encapsulation-options c :plain-cdr2-le)
        (dds.core.buffer:cursor-reset c)
        (multiple-value-bind (rep opt pad) (dds.cdr:parse-encapsulation-header c)
          (declare (ignore opt))
          (%check :pad-roundtrip (and (eq rep :plain-cdr2-le) (= pad 3))
                  "parse must recover pad count 3"))))
    (dds.core.arena:teardown-arena arena)
    t))

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

(defun* run-pal-fence-test ()
    (function () (eql t))
  "fence must accept :acquire/:release/:full and return without error (real barrier, not the M0 no-op)."
  (dolist (k '(:acquire :release :full) t)
    (dds.pal:fence k)))

(defun* run-pal-sap-atomics-test ()
    (function () (eql t))
  "cas-sap-u64 / atomic-incf-sap-u64 / load/store on a foreign 8-byte region behave atomically (single-thread correctness)."
  (unless (eq (dds.pal:pal-impl-name) :sbcl) (return-from run-pal-sap-atomics-test t))
  (let ((m (dds.pal:alloc-static 16)))
    (unwind-protect
         (let ((sap (dds.pal:static-pointer m)))
           (dds.pal:store-sap-u64 sap 0 0)
           (%check :cas-ok    (= 0 (dds.pal:cas-sap-u64 sap 0 0 42)) "cas returns prev")
           (%check :cas-set   (= 42 (dds.pal:load-sap-u64 sap 0)) "cas stored new")
           (%check :cas-fail  (= 42 (dds.pal:cas-sap-u64 sap 0 0 99)) "cas mismatch returns prev")
           (%check :cas-nochg (= 42 (dds.pal:load-sap-u64 sap 0)) "cas mismatch no write")
           (%check :incf      (= 47 (dds.pal:atomic-incf-sap-u64 sap 0 5)) "incf returns new")
           t)
      (dds.pal:free-static m))))

(defun* run-sap-ref-test ()
    (function () (eql t))
  "WP-FLATDATA-ZC-LOAN Task A1 (FR-PF-3/4, R6 — NOT cleared for ship, see ADR 0017): the PAL
   fixed-width SAP reads that back the FlatData-over-Zero-Copy read-in-place accessors are
   byte-exact little-endian. Write known octets into an octet-buffer, take its buffer-sap, and
   assert load-sap-u8/u16/u32 at offsets 0/2/4 EQUAL the little-endian composition of the same
   underlying aref bytes (the byte-exact oracle). SBCL only — ZC is SBCL-only (ADR 0013); on
   Clasp the primitives are a documented NFR-PORT gap, so assert each signals PAL-UNIMPLEMENTED."
  (let* ((buf (dds.core.buffer:make-octet-buffer 16))
         (vec (dds.core.buffer:octet-buffer-vec buf))
         (bytes (octets #x11 #x22 #xAA #xBB #x01 #x02 #x03 #x04)))
    (unwind-protect
         (let ((wc (dds.core.buffer:cursor buf :endianness :little))
               (sap (dds.core.buffer:buffer-sap buf)))
           (dds.core.buffer:put-octets wc bytes 0 (length bytes))
           (if (eq (dds.pal:pal-impl-name) :sbcl)
               (progn
                 (%check :sap-u8
                         (= (dds.pal:load-sap-u8 sap 0) (aref vec 0))
                         "load-sap-u8 @0 must equal the underlying octet")
                 (%check :sap-u16
                         (= (dds.pal:load-sap-u16 sap 2)
                            (logior (aref vec 2) (ash (aref vec 3) 8)))
                         "load-sap-u16 @2 must equal the little-endian 2-octet composition")
                 (%check :sap-u32
                         (= (dds.pal:load-sap-u32 sap 4)
                            (logior (aref vec 4) (ash (aref vec 5) 8)
                                    (ash (aref vec 6) 16) (ash (aref vec 7) 24)))
                         "load-sap-u32 @4 must equal the little-endian 4-octet composition"))
               (flet ((unimplemented-p (thunk)
                        (handler-case (progn (funcall thunk) nil)
                          (dds.pal:pal-unimplemented () t))))
                 (%check :sap-u8-gap  (unimplemented-p (lambda () (dds.pal:load-sap-u8 sap 0)))
                         "load-sap-u8 must signal PAL-UNIMPLEMENTED off SBCL (NFR-PORT)")
                 (%check :sap-u16-gap (unimplemented-p (lambda () (dds.pal:load-sap-u16 sap 2)))
                         "load-sap-u16 must signal PAL-UNIMPLEMENTED off SBCL (NFR-PORT)")
                 (%check :sap-u32-gap (unimplemented-p (lambda () (dds.pal:load-sap-u32 sap 4)))
                         "load-sap-u32 must signal PAL-UNIMPLEMENTED off SBCL (NFR-PORT)")))
           t)
      (dds.pal:free-static vec))))

(defun* %shm-attach-by-name-reliable-p ()
    (function () t)
  "True except on Clasp/macOS-arm64, whose plain cffi:foreign-funcall mispasses shm_open's variadic
   mode_t -> the created object is unre-openable (documented NFR-PORT gap, ADR 0013). Delegates to the
   single transport-layer definition to keep the platform fact in one place (DRY)."
  (dds.xport.shmem:shm-attach-by-name-reliable-p))

(defun* run-pal-shm-test ()
    (function () (eql t))
  "Create a segment, prove MAP_SHARED sharing via a second mapping (deterministic on every target),
   and assert shm-attach by name sees the same memory (mandatory on SBCL all platforms + Clasp/non-macOS;
   the Clasp/macOS-arm64 variadic-mode_t ABI gap is tolerated at runtime, NFR-PORT)."
  (let* ((name (format nil "/dds-test-shm-b1-~a" (random 1000000))) (size 4096))
    (ignore-errors (dds.pal:shm-destroy name))
    (let ((seg (dds.pal:shm-create name size)))
      (unwind-protect
           (progn
             (setf (cffi:mem-ref (dds.pal:shm-sap seg) :uint32 0) #xCAFEF00D)
             ;; second mmap of the same fd proves MAP_SHARED (deterministic everywhere)
             (let ((sap2 (dds.pal::%mmap-shared (dds.pal::shm-segment-fd seg) size)))
               (unwind-protect
                    (%check :shm-shared-second-mapping
                            (= #xCAFEF00D (cffi:mem-ref sap2 :uint32 0))
                            "second mapping sees the first's write")
                 (cffi:foreign-funcall "munmap" :pointer sap2 :unsigned-long size :int)))
             ;; by-name attach: cross-process path. Deterministic with the SBCL varargs create
             ;; (verified macOS arm64); Clasp/macOS-arm64 mispasses the variadic mode -> tolerated.
             (handler-case
                 (let ((seg2 (dds.pal:shm-attach name size)))
                   (unwind-protect
                        (%check :shm-attach-by-name
                                (= #xCAFEF00D (cffi:mem-ref (dds.pal:shm-sap seg2) :uint32 0))
                                "named attach sees the first's write")
                     (dds.pal:shm-detach seg2)))
               (error (e)
                 (when (%shm-attach-by-name-reliable-p) (error e))))
             t)
        (dds.pal:shm-detach seg)
        (dds.pal:shm-destroy name)))))

(defun* run-pal-pshared-test ()
    (function () (eql t))
  "A PROCESS_SHARED mutex+cond in a foreign buffer: a waiter thread blocks on the cond and is woken by a signal."
  (let ((m (dds.pal:alloc-static 256)))
    (unwind-protect
         (let ((sap (dds.pal:static-pointer m)) (mx 0) (cv 64) (flag 128) (woke nil))
           (dds.pal:store-sap-u64 sap flag 0)
           (dds.pal:pshared-mutex-init sap mx)
           (dds.pal:pshared-cond-init sap cv)
           (let ((th (dds.pal:spawn
                       (lambda ()
                         (dds.pal:pshared-lock sap mx)
                         (loop until (= 1 (dds.pal:load-sap-u64 sap flag))
                               do (dds.pal:pshared-cond-wait sap cv mx))
                         (dds.pal:pshared-unlock sap mx)
                         (setf woke t)))))
             (sleep 0.05)
             (dds.pal:pshared-lock sap mx)
             (dds.pal:store-sap-u64 sap flag 1)
             (dds.pal:pshared-cond-signal sap cv)
             (dds.pal:pshared-unlock sap mx)
             (dds.pal:join th)
             (%check :woke woke "waiter thread woke after the signal")
             (dds.pal:pshared-destroy sap mx cv)
             t))
      (dds.pal:free-static m))))

(defun* run-shmem-ring-init-test ()
    (function () (eql t))
  "SHMEM ring header+notify init/validate: magic, version, lane-count, capacity round-trip on a real segment."
  (let ((m (dds.pal:alloc-static (dds.xport.shmem::%segment-bytes 4 4096))))
    (unwind-protect
         (let ((sap (dds.pal:static-pointer m)))
           (dds.xport.shmem::%ring-init sap 4 4096)
           (%check :shmem-validate (dds.xport.shmem::%ring-validate sap) "ring validate after init")
           (%check :shmem-lane-count (= 4 (dds.xport.shmem::%ring-lane-count sap)) "lane-count round-trip")
           (%check :shmem-capacity (= 4096 (dds.xport.shmem::%ring-capacity sap)) "capacity round-trip")
           (dds.pal:pshared-destroy sap dds.xport.shmem::+mutex-off+ dds.xport.shmem::+cond-off+)
           t)
      (dds.pal:free-static m))))

(defun* run-shmem-lane-claim-test ()
    (function () (eql t))
  "SHMEM mutex-guarded lane claim: two tokens take two distinct lanes; re-claim is idempotent; full -> NIL."
  (let ((m (dds.pal:alloc-static (dds.xport.shmem::%segment-bytes 2 4096))))
    (unwind-protect
         (let ((sap (dds.pal:static-pointer m)))
           (dds.xport.shmem::%ring-init sap 2 4096)
           (let ((a (dds.xport.shmem::%claim-lane sap 111))
                 (b (dds.xport.shmem::%claim-lane sap 222)))
             (%check :shmem-claim-a a "first token must get a lane")
             (%check :shmem-claim-b b "second token must get a lane")
             (%check :shmem-claim-distinct (/= a b) "two tokens must get distinct lanes")
             (%check :shmem-claim-reuse (= a (dds.xport.shmem::%claim-lane sap 111)) "re-claim returns same lane")
             (%check :shmem-claim-full (null (dds.xport.shmem::%claim-lane sap 333)) "third token must get NIL (full)"))
           (dds.pal:pshared-destroy sap dds.xport.shmem::+mutex-off+ dds.xport.shmem::+cond-off+)
           t)
      (dds.pal:free-static m))))

(defun* run-shmem-enqueue-test ()
    (function () (eql t))
  "SHMEM SPSC enqueue: a 5-byte record advances the write-cursor to round8(4+5)=16; an oversize record rejects."
  (let ((m (dds.pal:alloc-static (dds.xport.shmem::%segment-bytes 1 64))))
    (unwind-protect
         (let ((sap (dds.pal:static-pointer m))
               (p (octets 1 2 3 4 5))
               (big (make-array 60 :element-type '(unsigned-byte 8) :initial-element 0)))
           (dds.xport.shmem::%ring-init sap 1 64)
           (%check :shmem-enq-ok (dds.xport.shmem::%lane-enqueue sap 0 64 p 0 5) "enqueue of 5 bytes must succeed")
           (%check :shmem-enq-cursor
                   (= 16 (dds.pal:load-sap-u64 sap (+ (dds.xport.shmem::%lane-desc-off 0)
                                                      dds.xport.shmem::+lane-off-write+)))
                   "write-cursor must be round8(4+5)=16")
           (%check :shmem-enq-reject (null (dds.xport.shmem::%lane-enqueue sap 0 64 big 0 60))
                   "a record of len cap-4 must be rejected (does not fit)")
           (dds.pal:pshared-destroy sap dds.xport.shmem::+mutex-off+ dds.xport.shmem::+cond-off+)
           t)
      (dds.pal:free-static m))))

(defun* run-shmem-drain-test ()
    (function () (eql t))
  "SHMEM SPSC drain: two enqueued records (3x9, 2x7) are delivered in order with the right sizes/first-bytes."
  (let ((m (dds.pal:alloc-static (dds.xport.shmem::%segment-bytes 1 64))))
    (unwind-protect
         (let ((sap (dds.pal:static-pointer m))
               (a (octets 9 9 9))
               (b (octets 7 7))
               (sink (dds.core.buffer:make-octet-buffer 64))
               (got '()))
           (dds.xport.shmem::%ring-init sap 1 64)
           (dds.xport.shmem::%lane-enqueue sap 0 64 a 0 3)
           (dds.xport.shmem::%lane-enqueue sap 0 64 b 0 2)
           (dds.xport.shmem::%lane-drain
            sap 0 64 sink
            (lambda (s size)
              (push (cons size (aref (dds.core.buffer:octet-buffer-vec s) 0)) got)))
           (setf got (nreverse got))
           (%check :shmem-drain-count (= 2 (length got)) "drain must deliver both records")
           (%check :shmem-drain-first (equal '(3 . 9) (first got)) "first record: size 3, byte 9")
           (%check :shmem-drain-second (equal '(2 . 7) (second got)) "second record: size 2, byte 7")
           (dds.pal:pshared-destroy sap dds.xport.shmem::+mutex-off+ dds.xport.shmem::+cond-off+)
           t)
      (dds.pal:free-static m))))

(defun* run-shmem-drain-resource-guard-test ()
    (function () (eql t))
  "A garbage write-cursor (w - r >> capacity) must NOT flood on-datagram: the drain rejects w-r > capacity (NFR-SEC-POSTURE)."
  (let* ((lanes 1) (cap 64) (m (dds.pal:alloc-static (dds.xport.shmem::%segment-bytes lanes cap))) (n 0))
    (unwind-protect
         (let ((sap (dds.pal:static-pointer m)))
           (dds.xport.shmem::%ring-init sap lanes cap)
           ;; forge a write-cursor 10*capacity ahead with no real records written
           (dds.pal:store-sap-u64 sap (+ (dds.xport.shmem::%lane-desc-off 0) dds.xport.shmem::+lane-off-write+) (* 10 cap))
           (let ((sink (dds.core.buffer:make-octet-buffer cap)))
             (dds.xport.shmem::%lane-drain sap 0 cap sink (lambda (buf size) (declare (ignore buf size)) (incf n))))
           (%check :no-flood (zerop n) "drain must deliver 0 records for a w-r > capacity garbage cursor")
           (dds.pal:pshared-destroy sap dds.xport.shmem::+mutex-off+ dds.xport.shmem::+cond-off+)
           t)
      (dds.pal:free-static m))))

(defun* run-zc-pool-init-test ()
    (function () (eql t))
  "WP-ZEROCOPY pool layout + init/validate (FR-PF-3, ADR 0014; R6 off-by-default feature): a 4-slot pool of
   256-byte slots, in a static foreign region (no SHMEM segment needed for the unit), validates, reports its
   slot-count, and threads all 4 slots onto the freelist."
  (let ((m (dds.pal:alloc-static (dds.xport.zerocopy::%zc-bytes 4 256))))
    (unwind-protect
         (let ((sap (dds.pal:static-pointer m)))
           (dds.xport.zerocopy::%zc-init sap 4 256)
           (%check :zc-validate (dds.xport.zerocopy::%zc-validate sap) "pool validate after init")
           (%check :zc-slot-count (= 4 (dds.xport.zerocopy::%zc-slot-count sap)) "slot-count round-trip")
           (%check :zc-slot-bytes (= 256 (dds.xport.zerocopy::%zc-slot-bytes sap)) "slot-bytes round-trip")
           (%check :zc-free-count (= 4 (dds.xport.zerocopy::%zc-free-count sap)) "all 4 slots on the freelist")
           (dds.xport.zerocopy::%zc-destroy sap)
           t)
      (dds.pal:free-static m))))

(defun* run-zc-pool-loan-test ()
    (function () (eql t))
  "WP-ZEROCOPY loan/release (FR-PF-3, ADR 0014) under the WP-FLATDATA-ZC-LOAN safety contract (R6, ADR 0017):
   in a 2-slot pool, two loans take distinct slots; with BOTH slots loaned (refcount>0) a third loan returns
   NIL — force-reclaim NEVER overwrites a held slot (the binary safety gate); after releasing the oldest
   (slot 0), a fresh loan force-reclaims that now-UNLOANED slot (lowest pubseq) with a bumped generation;
   releasing a valid (slot,generation) succeeds; a stale generation or a double-release is a no-op. SBCL only
   since WP-ZC-LOAN-LOCKFREE Phase B (R6, ADR 0018): %zc-release is now a lock-free cas-sap-u32 refcount decrement, an
   SBCL-only PAL primitive (ZC is an NFR-PORT gap on Clasp, ADR 0013); Clasp pass-skips."
  (if (not (eq (dds.pal:pal-impl-name) :sbcl))
      (progn
        (format t "~&  [skip] zc-pool-loan: %zc-release uses cas-sap-u32 (SBCL-only since WP-ZC-LOAN-LOCKFREE, ADR 0018) — NFR-PORT gap~%")
        t)
      (let ((m (dds.pal:alloc-static (dds.xport.zerocopy::%zc-bytes 2 32)))
            (payload (octets 1 2 3 4)))
        (unwind-protect
             (let ((sap (dds.pal:static-pointer m)))
               (dds.xport.zerocopy::%zc-init sap 2 32)
               (multiple-value-bind (i0 g0) (dds.xport.zerocopy::%zc-loan sap payload 0 4 1)
                 (multiple-value-bind (i1 g1) (dds.xport.zerocopy::%zc-loan sap payload 0 4 1)
                   (declare (ignore g1))
                   (%check :zc-loan-i0 (eql i0 0) "first loan must take slot 0")
                   (%check :zc-loan-i1 (eql i1 1) "second loan must take slot 1")
                   (%check :zc-loan-distinct (/= i0 i1) "two loans must take distinct slots")
                   (%check :zc-loan-g0 (= g0 1) "first loan bumps slot 0 generation to 1")
                   ;; pool now full AND both slots loaned (refcount>0) -> the third loan finds no reclaimable
                   ;; slot and returns NIL (the writer's non-ZC fallback); NEITHER held slot is overwritten
                   (multiple-value-bind (ifull gfull) (dds.xport.zerocopy::%zc-loan sap payload 0 4 1)
                     (declare (ignore gfull))
                     (%check :zc-loan-full-nil (null ifull)
                             "with both slots loaned the third loan must return NIL (never reclaim a held slot)"))
                   ;; release slot 0 (the oldest) -> it becomes reclaimable; slot 1 stays held
                   (%check :zc-release-oldest (dds.xport.zerocopy::%zc-release sap i0 g0)
                           "releasing the oldest held slot must succeed (T)")
                   ;; now a fresh loan force-reclaims the freed slot 0 (back on the freelist) with a bumped gen
                   (multiple-value-bind (i2 g2) (dds.xport.zerocopy::%zc-loan sap payload 0 4 1)
                     (%check :zc-reclaim-unloaned (eql i2 0) "the next loan must reuse the now-unloaned slot (0)")
                     (%check :zc-reclaim-gen (= g2 2) "reusing slot 0 must bump its generation to 2")
                     ;; a release with the STALE generation g0 (now superseded by g2) is a no-op
                     (%check :zc-release-stale (null (dds.xport.zerocopy::%zc-release sap i0 g0))
                             "release with a stale generation must be a no-op (NIL)")
                     ;; a release of the live (slot,generation) succeeds and frees the slot
                     (%check :zc-release-valid (dds.xport.zerocopy::%zc-release sap i2 g2)
                             "release of a live (slot,generation) must succeed (T)")
                     ;; slot 0 is back on the freelist; slot 1 is still loaned -> exactly one free
                     (%check :zc-release-frees (= 1 (dds.xport.zerocopy::%zc-free-count sap))
                             "the released slot must return to the freelist (free-count 1)")
                     ;; a double-release of a freed slot must NOT push it onto the freelist again
                     ;; (the refcount-0 guard prevents a freelist cycle; the free-count stays 1)
                     (dds.xport.zerocopy::%zc-release sap i2 g2)
                     (%check :zc-release-no-double-free (= 1 (dds.xport.zerocopy::%zc-free-count sap))
                             "a double-release must not re-push the slot (free-count stays 1)")
                     ;; an out-of-range slot index is a no-op (untrusted bounds)
                     (%check :zc-release-oob (null (dds.xport.zerocopy::%zc-release sap 99 0))
                             "release of an out-of-range slot must be a no-op (NIL)"))))
               (dds.xport.zerocopy::%zc-destroy sap)
               t)
          (dds.pal:free-static m)))))

(defun* run-zc-pool-resolve-test ()
    (function () (eql t))
  "WP-ZEROCOPY reader resolve (FR-PF-3, ADR 0014; NFR-SEC-POSTURE): loan a payload, resolve (slot,gen) into
   a sink -> returns LEN and the bytes match; a wrong generation or an out-of-range slot returns NIL and
   copies nothing (the sink is left untouched)."
  (let ((m (dds.pal:alloc-static (dds.xport.zerocopy::%zc-bytes 2 32)))
        (payload (octets 11 22 33 44 55)))
    (unwind-protect
         (let ((sap (dds.pal:static-pointer m))
               (sink (make-array 32 :element-type '(unsigned-byte 8) :initial-element #xEE)))
           (dds.xport.zerocopy::%zc-init sap 2 32)
           (multiple-value-bind (i g) (dds.xport.zerocopy::%zc-loan sap payload 0 5 1)
             (let ((len (dds.xport.zerocopy::%zc-resolve sap i g sink)))
               (%check :zc-resolve-len (eql len 5) "resolve must return the loaned LEN (5)")
               (%check :zc-resolve-bytes
                       (loop for k below 5 always (= (aref sink k) (aref payload k)))
                       "resolve must copy the slot payload bytes into the sink"))
             ;; wrong generation -> NIL, no copy (the sink past the first resolve stays the sentinel)
             (let ((sink2 (make-array 32 :element-type '(unsigned-byte 8) :initial-element #xEE)))
               (%check :zc-resolve-wrong-gen
                       (null (dds.xport.zerocopy::%zc-resolve sap i (logand (1+ g) #xFFFFFFFF) sink2))
                       "resolve with a wrong generation must return NIL")
               (%check :zc-resolve-wrong-gen-nocopy
                       (loop for k below 32 always (= (aref sink2 k) #xEE))
                       "a wrong-generation resolve must copy nothing")
               ;; out-of-range slot index -> NIL, no copy (untrusted bounds)
               (%check :zc-resolve-oob
                       (null (dds.xport.zerocopy::%zc-resolve sap 99 g sink2))
                       "resolve of an out-of-range slot must return NIL")
               (%check :zc-resolve-oob-nocopy
                       (loop for k below 32 always (= (aref sink2 k) #xEE))
                       "an out-of-range resolve must copy nothing")))
           (dds.xport.zerocopy::%zc-destroy sap)
           t)
      (dds.pal:free-static m))))

(defun* run-zc-pool-align-test ()
    (function () (eql t))
  "WP-ZEROCOPY slot-stride 8-alignment regression (FR-PF-3, ADR 0014): a pool with slot-bytes=13
   (non-8-aligned) and 3 slots loans distinct payloads into slots 0,1,2 (the slots that would be
   misaligned without the fix), resolves each back into a sink, asserts byte-exact match. Without
   %zc-slot-stride rounding, slot 1+ would be misaligned and the u64 pubseq store/load
   (dds.pal:store/load-sap-u64, documented aligned) would be UB on strict-align targets. Runs on BOTH
   impls: the alignment is proven via %zc-resolve (mutex'd, Clasp-portable); the loaned slots need no
   explicit %zc-release here (%zc-destroy + free-static tear the region down regardless of refcount), so
   the test does NOT invoke the SBCL-only lock-free release (WP-ZC-LOAN-LOCKFREE, ADR 0018) and keeps its
   Clasp alignment coverage."
  (let ((m (dds.pal:alloc-static (dds.xport.zerocopy::%zc-bytes 3 13))))
    (unwind-protect
         (let ((sap (dds.pal:static-pointer m))
               (p0 (octets 1 2 3 4 5 6 7 8 9 10 11 12 13))
               (p1 (octets 20 21 22 23 24 25 26 27 28 29 30 31 32))
               (p2 (octets 40 41 42 43 44 45 46 47 48 49 50 51 52))
               (sink (make-array 13 :element-type '(unsigned-byte 8) :initial-element 0)))
           (dds.xport.zerocopy::%zc-init sap 3 13)
           (multiple-value-bind (i0 g0) (dds.xport.zerocopy::%zc-loan sap p0 0 13 1)
             (multiple-value-bind (i1 g1) (dds.xport.zerocopy::%zc-loan sap p1 0 13 1)
               (multiple-value-bind (i2 g2) (dds.xport.zerocopy::%zc-loan sap p2 0 13 1)
                 (%check :zc-align-slots-distinct (and (/= i0 i1) (/= i1 i2) (/= i0 i2))
                         "three loans must use three distinct slots")
                 ;; resolve each and assert byte-exact payload recovery
                 (let ((len0 (dds.xport.zerocopy::%zc-resolve sap i0 g0 sink)))
                   (%check :zc-align-resolve0-len (eql len0 13) "slot 0 resolve must return 13")
                   (%check :zc-align-resolve0-bytes
                           (loop for k below 13 always (= (aref sink k) (aref p0 k)))
                           "slot 0 payload mismatch (misaligned pubseq would corrupt or fault here)"))
                 (let ((len1 (dds.xport.zerocopy::%zc-resolve sap i1 g1 sink)))
                   (%check :zc-align-resolve1-len (eql len1 13) "slot 1 resolve must return 13")
                   (%check :zc-align-resolve1-bytes
                           (loop for k below 13 always (= (aref sink k) (aref p1 k)))
                           "slot 1 payload mismatch (misaligned without fix)"))
                 (let ((len2 (dds.xport.zerocopy::%zc-resolve sap i2 g2 sink)))
                   (%check :zc-align-resolve2-len (eql len2 13) "slot 2 resolve must return 13")
                   (%check :zc-align-resolve2-bytes
                           (loop for k below 13 always (= (aref sink k) (aref p2 k)))
                           "slot 2 payload mismatch (misaligned without fix)")))))
           (dds.xport.zerocopy::%zc-destroy sap)
           t)
      (dds.pal:free-static m))))

(defun* run-zc-loan-acquire-test ()
    (function () (eql t))
  "WP-FLATDATA-ZC-LOAN Task C1 (FR-PF-3/4, R6, ADR 0017; NOT cleared for ship — pending counsel): the
   literal-0-copy %zc-acquire-for-read. Loan a payload (refcount=1); acquire returns a handle whose payload
   octets — read via dds.pal:load-sap-u8 over the returned POOL-SAP at PAYLOAD-BASE — EQUAL the loaned
   payload, WITHOUT a copy and WITHOUT bumping the refcount (the slot is held by the loan's existing count);
   a forged/stale generation ⇒ NIL; a forged over-long recorded LEN is CLAMPED to slot-bytes (no OOB read).
   SBCL only (load-sap-u8 is SBCL-only, ZC ADR 0013); Clasp pass-skips."
  (if (eq (dds.pal:pal-impl-name) :sbcl)
      (let ((m (dds.pal:alloc-static (dds.xport.zerocopy::%zc-bytes 2 32)))
            (payload (octets 11 22 33 44 55)))
        (unwind-protect
             (let ((sap (dds.pal:static-pointer m)))
               (dds.xport.zerocopy::%zc-init sap 2 32)
               (multiple-value-bind (i g) (dds.xport.zerocopy::%zc-loan sap payload 0 5 1)
                 ;; acquire returns the live handle WITHOUT copying and WITHOUT touching the refcount
                 (multiple-value-bind (psap idx gen len base)
                     (dds.xport.zerocopy::%zc-acquire-for-read sap i g)
                   (%check :zc-acq-handle psap "acquire of a live (slot,generation) must return a handle")
                   (%check :zc-acq-slot (eql idx i) "acquire must echo the slot index")
                   (%check :zc-acq-gen (eql gen g) "acquire must echo the generation")
                   (%check :zc-acq-len (eql len 5) "acquire must return the clamped payload length (5)")
                   (%check :zc-acq-bytes
                           (loop for k below 5 always (= (dds.pal:load-sap-u8 psap (+ base k)) (aref payload k)))
                           "the SAP-read payload bytes must equal the loaned payload (literal 0-copy)")
                   ;; acquire did NOT increment the refcount: a single release returns the slot fully
                   (%check :zc-acq-no-refcount-bump (dds.xport.zerocopy::%zc-release psap idx gen)
                           "one release must apply (acquire must not have bumped the refcount)")
                   (%check :zc-acq-released-frees (= 2 (dds.xport.zerocopy::%zc-free-count sap))
                           "after the single release the slot must be back on the freelist (acquire held no extra count)"))
                 ;; a forged/stale generation ⇒ NIL (single value), no handle
                 (%check :zc-acq-stale-gen
                         (null (dds.xport.zerocopy::%zc-acquire-for-read sap i (logand (+ g 7) #xFFFFFFFF)))
                         "acquire with a stale/forged generation must return NIL")
                 ;; an out-of-range slot ⇒ NIL (untrusted bounds)
                 (%check :zc-acq-oob
                         (null (dds.xport.zerocopy::%zc-acquire-for-read sap 99 g))
                         "acquire of an out-of-range slot must return NIL"))
               ;; forged over-long recorded LEN ⇒ acquire CLAMPS to slot-bytes (no OOB exposure)
               (multiple-value-bind (i2 g2) (dds.xport.zerocopy::%zc-loan sap payload 0 4 1)
                 (let ((b (dds.xport.zerocopy::%zc-slot-off sap i2)))
                   (setf (cffi:mem-ref sap :uint32 (+ b dds.xport.zerocopy::+zc-slot-off-len+)) #xFFFFFFFF))
                 (multiple-value-bind (psap2 idx2 gen2 len2 base2)
                     (dds.xport.zerocopy::%zc-acquire-for-read sap i2 g2)
                   (declare (ignore idx2 gen2 base2))
                   (%check :zc-acq-forged-len-handle psap2 "acquire of a forged-LEN slot must still return a handle")
                   (%check :zc-acq-forged-len-clamped (eql len2 32)
                           "a forged over-long recorded LEN must be CLAMPED to slot-bytes (32), never exposed OOB"))
                 (dds.xport.zerocopy::%zc-release sap i2 g2))
               (dds.xport.zerocopy::%zc-destroy sap)
               t)
          (dds.pal:free-static m)))
      (progn
        (format t "~&  [skip] zc-loan-acquire: load-sap-u8 is SBCL-only (ZC, ADR 0013) — NFR-PORT gap~%")
        t)))

(defun* run-zc-reclaim-skips-loaned-test ()
    (function () (eql t))
  "WP-FLATDATA-ZC-LOAN Task C1 — THE BINARY SAFETY GATE (FR-PF-3/4, R6, ADR 0017; NOT cleared for ship —
   pending counsel): force-reclaim MUST skip refcount>0 slots, so a HELD loan is never overwritten under the
   reader. In a 2-slot pool, loan A (refcount=1, NOT released) + fill the other slot, then force a further
   loan: the pool is full and every slot is loaned (refcount>0) ⇒ %zc-loan returns NIL (the writer's non-ZC
   fallback) and A is NOT reclaimed (its generation + payload stay intact while held). Then %zc-release A ⇒
   exactly one slot frees and the next loan reuses it (A is reclaimable only once unloaned). SBCL only since
   WP-ZC-LOAN-LOCKFREE Phase B (R6, ADR 0018): %zc-release is now a lock-free cas-sap-u32 refcount decrement, an
   SBCL-only PAL primitive (ZC is an NFR-PORT gap on Clasp, ADR 0013); Clasp pass-skips."
  (if (not (eq (dds.pal:pal-impl-name) :sbcl))
      (progn
        (format t "~&  [skip] zc-reclaim-skips-loaned: %zc-release uses cas-sap-u32 (SBCL-only since WP-ZC-LOAN-LOCKFREE, ADR 0018) — NFR-PORT gap~%")
        t)
      (let ((m (dds.pal:alloc-static (dds.xport.zerocopy::%zc-bytes 2 32)))
            (pa (octets 91 92 93 94 95))
            (pb (octets 60 61 62 63)))
        (unwind-protect
             (let ((sap (dds.pal:static-pointer m))
                   (sink (make-array 32 :element-type '(unsigned-byte 8) :initial-element 0)))
               (dds.xport.zerocopy::%zc-init sap 2 32)
               ;; loan A into slot 0 (refcount=1) and HOLD it (never release while the pool is pressured)
               (multiple-value-bind (ia ga) (dds.xport.zerocopy::%zc-loan sap pa 0 5 1)
                 (%check :zc-skip-loan-a (eql ia 0) "A must take slot 0")
                 ;; loan B into the only other slot (refcount=1) — now both slots are loaned (refcount>0)
                 (multiple-value-bind (ib gb) (dds.xport.zerocopy::%zc-loan sap pb 0 4 1)
                   (declare (ignore gb))
                   (%check :zc-skip-loan-b (eql ib 1) "B must take slot 1 (pool now full, both loaned)")
                   ;; the pool is full AND every slot is loaned ⇒ a further loan finds NO reclaimable slot ⇒ NIL
                   (multiple-value-bind (ifull gfull) (dds.xport.zerocopy::%zc-loan sap pb 0 4 1)
                     (declare (ignore gfull))
                     (%check :zc-skip-loan-full-nil (null ifull)
                             "with every slot loaned (refcount>0) %zc-loan must return NIL (non-ZC fallback), never reclaim a held slot"))
                   ;; A was NOT reclaimed: its generation is unchanged and its payload is intact under the read
                   (%check :zc-skip-a-gen-intact (= ga (cffi:mem-ref sap :uint32
                                                                      (+ (dds.xport.zerocopy::%zc-slot-off sap ia)
                                                                         dds.xport.zerocopy::+zc-slot-off-generation+)))
                           "the held loan A's generation must be UNCHANGED (it was never reclaimed)")
                   (let ((len (dds.xport.zerocopy::%zc-resolve sap ia ga sink)))
                     (%check :zc-skip-a-len (eql len 5) "the held loan A must still resolve (LEN 5) — not overwritten")
                     (%check :zc-skip-a-bytes (loop for k below 5 always (= (aref sink k) (aref pa k)))
                             "the held loan A's payload must be byte-intact (force-reclaim skipped it)")))
                 ;; release A ⇒ exactly one slot returns to the freelist (B still held)
                 (%check :zc-skip-release-a (dds.xport.zerocopy::%zc-release sap ia ga) "releasing A must apply")
                 (%check :zc-skip-one-free (= 1 (dds.xport.zerocopy::%zc-free-count sap))
                         "after releasing A exactly one slot frees (B still loaned)")
                 ;; now A's slot is reclaimable/reusable: the next loan succeeds and reuses slot 0
                 (multiple-value-bind (ic gc) (dds.xport.zerocopy::%zc-loan sap pb 0 4 1)
                   (declare (ignore gc))
                   (%check :zc-skip-reuse (eql ic 0) "once unloaned, A's slot must be reusable by a fresh loan")))
               (dds.xport.zerocopy::%zc-destroy sap)
               t)
          (dds.pal:free-static m)))))

(defun* run-zc-release-idempotent-test ()
    (function () (eql t))
  "WP-FLATDATA-ZC-LOAN Task C1 (FR-PF-3/4, R6, ADR 0017; NOT cleared for ship — pending counsel): %zc-release
   is idempotent / double-return-safe. Release a slot to refcount 0 (reclaimable); a SECOND release of the same
   (slot,generation) is a validated NO-OP — the refcount stays 0 (never negative) and the reclaimable count is
   unchanged; a release with a stale generation is also a no-op. Guards a double return_loan of one view and a
   reader-close returning an already-returned loan. SBCL only since WP-ZC-LOAN-LOCKFREE Phase B (R6, ADR 0018):
   %zc-release is now a lock-free cas-sap-u32 refcount decrement, an SBCL-only PAL primitive (ZC is an NFR-PORT gap on
   Clasp, ADR 0013); Clasp pass-skips (the lock-free double-return-safety also has run-zc-lockfree-release-test)."
  (if (not (eq (dds.pal:pal-impl-name) :sbcl))
      (progn
        (format t "~&  [skip] zc-release-idempotent: %zc-release uses cas-sap-u32 (SBCL-only since WP-ZC-LOAN-LOCKFREE, ADR 0018) — NFR-PORT gap~%")
        t)
      (let ((m (dds.pal:alloc-static (dds.xport.zerocopy::%zc-bytes 2 32)))
            (payload (octets 7 8 9)))
        (unwind-protect
             (let ((sap (dds.pal:static-pointer m)))
               (dds.xport.zerocopy::%zc-init sap 2 32)
               (multiple-value-bind (i g) (dds.xport.zerocopy::%zc-loan sap payload 0 3 1)
                 ;; first release: refcount 1 -> 0, slot reclaimable
                 (%check :zc-idem-first (dds.xport.zerocopy::%zc-release sap i g) "the first release must apply (T)")
                 (%check :zc-idem-one-free (= 2 (dds.xport.zerocopy::%zc-free-count sap))
                         "after the first release both slots are reclaimable (the slot returned)")
                 ;; the slot's refcount is 0
                 (%check :zc-idem-refcount-zero
                         (zerop (cffi:mem-ref sap :uint32 (+ (dds.xport.zerocopy::%zc-slot-off sap i)
                                                             dds.xport.zerocopy::+zc-slot-off-refcount+)))
                         "the released slot's refcount must be 0")
                 ;; SECOND release of the SAME (slot,generation): a no-op — refcount stays 0
                 (dds.xport.zerocopy::%zc-release sap i g)
                 (%check :zc-idem-still-zero
                         (zerop (cffi:mem-ref sap :uint32 (+ (dds.xport.zerocopy::%zc-slot-off sap i)
                                                             dds.xport.zerocopy::+zc-slot-off-refcount+)))
                         "a double release must leave the refcount at 0 (never negative / wrapped)")
                 (%check :zc-idem-no-double-push (= 2 (dds.xport.zerocopy::%zc-free-count sap))
                         "a double release must NOT change the reclaimable count (still 2)")
                 ;; a release with a stale generation is a no-op (NIL)
                 (%check :zc-idem-stale-gen
                         (null (dds.xport.zerocopy::%zc-release sap i (logand (+ g 9) #xFFFFFFFF)))
                         "a release with a stale generation must be a no-op (NIL)")
                 (%check :zc-idem-stale-no-push (= 2 (dds.xport.zerocopy::%zc-free-count sap))
                         "a stale-generation release must not change the reclaimable count"))
               (dds.xport.zerocopy::%zc-destroy sap)
               t)
          (dds.pal:free-static m)))))

(defun* run-zc-loan-nofreelist-test ()
    (function () (eql t))
  "WP-ZC-LOAN-LOCKFREE Phase A (FR-PF-3/4, NFR-PERF-7, R6, ADR 0018; NOT cleared for ship — pending counsel):
   the freelist was DROPPED — a slot is reclaimable iff refcount==0 and the writer SCANS for the lowest-pubseq
   (oldest) such slot. Proves slot reuse WITHOUT any freelist: (1) loan/release/loan cycles correctly reuse a
   slot (the scan finds the released slot, with a bumped generation); (2) reclaim is OLDEST-FIRST — with two
   slots free, the next loan reuses the lower-pubseq one; (3) a fully-loaned pool (every slot refcount>0) ⇒
   %zc-loan returns NIL (the writer's non-ZC fallback, never reclaiming a held slot). SBCL only (ZC is SBCL,
   ADR 0013); Clasp pass-skips."
  (if (eq (dds.pal:pal-impl-name) :sbcl)
      (let ((m1 (dds.pal:alloc-static (dds.xport.zerocopy::%zc-bytes 1 32)))
            (m3 (dds.pal:alloc-static (dds.xport.zerocopy::%zc-bytes 3 32)))
            (p (octets 1 2 3 4)))
        (unwind-protect
             (let ((s1 (dds.pal:static-pointer m1))
                   (s3 (dds.pal:static-pointer m3)))
               ;; (1) loan/release/loan on a 1-SLOT pool: the writer-scan finds the just-released slot and
               ;; reuses it (unambiguous with one slot — no freelist), bumping the generation each cycle.
               (dds.xport.zerocopy::%zc-init s1 1 32)
               (%check :zcnf-1-init (= 1 (dds.xport.zerocopy::%zc-free-count s1))
                       "1-slot pool: the slot is reclaimable (refcount==0) after init, no freelist")
               (multiple-value-bind (i0 g0) (dds.xport.zerocopy::%zc-loan s1 p 0 4 1)
                 (%check :zcnf-1-loan (eql i0 0) "loan takes the only slot 0")
                 (%check :zcnf-1-loan-gen (= g0 1) "loan bumps slot 0 generation to 1")
                 (%check :zcnf-1-loaned-zero (= 0 (dds.xport.zerocopy::%zc-free-count s1))
                         "the loaned slot is not reclaimable (refcount>0)")
                 ;; full + loaned ⇒ a second loan finds nothing reclaimable ⇒ NIL (never overwrites the held slot)
                 (multiple-value-bind (ifull gfull) (dds.xport.zerocopy::%zc-loan s1 p 0 4 1)
                   (declare (ignore gfull))
                   (%check :zcnf-1-full-nil (null ifull) "a loan against the held-full 1-slot pool returns NIL"))
                 (%check :zcnf-1-rel (dds.xport.zerocopy::%zc-release s1 i0 g0) "release of slot 0 applies")
                 (%check :zcnf-1-rel-free (= 1 (dds.xport.zerocopy::%zc-free-count s1))
                         "after release the slot is reclaimable again (refcount==0, no freelist)")
                 (multiple-value-bind (ir gr) (dds.xport.zerocopy::%zc-loan s1 p 0 4 1)
                   (%check :zcnf-1-reuse (eql ir 0) "the writer-scan reuses the released slot 0 (no freelist)")
                   (%check :zcnf-1-reuse-gen (= gr 2) "reusing slot 0 bumps its generation to 2")
                   (dds.xport.zerocopy::%zc-release s1 ir gr)))
               ;; (2)+(3) on a 3-SLOT pool: loan all three (so each slot has a distinct, increasing pubseq —
               ;; no leftover pubseq-0 slot to confound the ordering), then test oldest-first reclaim + full-pool.
               (dds.xport.zerocopy::%zc-init s3 3 32)
               (multiple-value-bind (ia ga) (dds.xport.zerocopy::%zc-loan s3 p 0 4 1)
                 (multiple-value-bind (ib gb) (dds.xport.zerocopy::%zc-loan s3 p 0 4 1)
                   (multiple-value-bind (ic gc) (dds.xport.zerocopy::%zc-loan s3 p 0 4 1)
                     (%check :zcnf-3-fill (and (eql ia 0) (eql ib 1) (eql ic 2))
                             "three loans take the three distinct slots (pubseq 0<1<2)")
                     (%check :zcnf-3-full-free (= 0 (dds.xport.zerocopy::%zc-free-count s3))
                             "a fully-loaned 3-slot pool has 0 reclaimable slots")
                     ;; full AND every slot loaned ⇒ a further loan returns NIL (never reclaims a held slot)
                     (multiple-value-bind (ifull gfull) (dds.xport.zerocopy::%zc-loan s3 p 0 4 1)
                       (declare (ignore gfull))
                       (%check :zcnf-3-full-nil (null ifull)
                               "every slot loaned (refcount>0) ⇒ %zc-loan NIL (non-ZC fallback), no reclaim"))
                     ;; release B (slot 1) then C (slot 2): both reclaimable; slot 1 has the LOWER pubseq
                     (%check :zcnf-3-relB (dds.xport.zerocopy::%zc-release s3 ib gb) "release of slot 1 applies")
                     (%check :zcnf-3-relC (dds.xport.zerocopy::%zc-release s3 ic gc) "release of slot 2 applies")
                     (%check :zcnf-3-two-free (= 2 (dds.xport.zerocopy::%zc-free-count s3))
                             "slots 1 and 2 reclaimable, slot 0 still held ⇒ 2 reclaimable")
                     ;; the writer-scan reuses the LOWEST-pubseq reclaimable slot (slot 1, older than slot 2)
                     (multiple-value-bind (id gd) (dds.xport.zerocopy::%zc-loan s3 p 0 4 1)
                       (%check :zcnf-3-oldest-first (eql id 1)
                               "oldest-first: the lower-pubseq free slot (1) is reused before slot 2")
                       ;; one free slot left (slot 2) ⇒ a loan reuses it ⇒ pool full again
                       (multiple-value-bind (ie ge) (dds.xport.zerocopy::%zc-loan s3 p 0 4 1)
                         (%check :zcnf-3-reuse2 (eql ie 2) "the remaining free slot (2) is reused")
                         ;; release everything held; the pool fully recovers (all refcount==0), no leak
                         (dds.xport.zerocopy::%zc-release s3 ia ga)
                         (dds.xport.zerocopy::%zc-release s3 id gd)
                         (dds.xport.zerocopy::%zc-release s3 ie ge)))))
                 (%check :zcnf-3-recover (= 3 (dds.xport.zerocopy::%zc-free-count s3))
                         "after all returns the 3-slot pool is fully reclaimable (3), no refcount leak, no freelist"))
               (dds.xport.zerocopy::%zc-destroy s1)
               (dds.xport.zerocopy::%zc-destroy s3)
               t)
          (progn (dds.pal:free-static m1) (dds.pal:free-static m3))))
      (progn
        (format t "~&  [skip] zc-loan-nofreelist: Zero-Copy is SBCL-only (ADR 0013) — NFR-PORT gap~%")
        t)))

(defun* run-zc-lockfree-acquire-test ()
    (function () (eql t))
  "WP-ZC-LOAN-LOCKFREE Phase B (FR-PF-3/4, NFR-PERF-7, R6, ADR 0018; NOT cleared for ship — pending counsel):
   the LOCK-FREE FENCED-READ %zc-acquire-for-read (no mutex). Proves: (1) BYTE-EXACT — the payload read via the
   returned POOL-SAP at PAYLOAD-BASE (dds.pal:load-sap-u8) EQUALS the loaned payload (the acquire-fence pairs
   with the writer's release-store-LAST generation ⇒ the payload is visible); (2) a STALE/FORGED generation ⇒
   NIL (single value) before any payload read; an OOB slot ⇒ NIL; (3) a FORGED over-long recorded LEN ⇒ CLAMPED
   to slot-bytes (no OOB read at (safety 0)); (4) THE HEADLINE — the lock-free acquire CONSES 0 BYTES per call
   (the ~31 B CFFI pthread-mutex residue is gone). SBCL only (load-sap-u8 + bytes-consed are SBCL-exact, ZC
   ADR 0013); Clasp pass-skips."
  (if (eq (dds.pal:pal-impl-name) :sbcl)
      (let ((m (dds.pal:alloc-static (dds.xport.zerocopy::%zc-bytes 2 32)))
            (payload (octets 11 22 33 44 55)))
        (unwind-protect
             (let ((sap (dds.pal:static-pointer m)))
               (dds.xport.zerocopy::%zc-init sap 2 32)
               (multiple-value-bind (i g) (dds.xport.zerocopy::%zc-loan sap payload 0 5 1)
                 ;; (1) lock-free acquire returns a byte-exact view WITHOUT a copy/refcount bump
                 (multiple-value-bind (psap idx gen len base)
                     (dds.xport.zerocopy::%zc-acquire-for-read sap i g)
                   (%check :zclf-acq-handle psap "lock-free acquire of a live (slot,generation) must return a handle")
                   (%check :zclf-acq-slot (eql idx i) "lock-free acquire must echo the slot index")
                   (%check :zclf-acq-gen (eql gen g) "lock-free acquire must echo the generation")
                   (%check :zclf-acq-len (eql len 5) "lock-free acquire must return the clamped payload length (5)")
                   (%check :zclf-acq-bytes
                           (loop for k below 5 always (= (dds.pal:load-sap-u8 psap (+ base k)) (aref payload k)))
                           "the SAP-read payload bytes must equal the loaned payload (lock-free fenced read, 0-copy)")
                   (%check :zclf-acq-no-refcount-bump (dds.xport.zerocopy::%zc-release psap idx gen)
                           "one release must apply (lock-free acquire must not have bumped the refcount)")
                   (%check :zclf-acq-released-frees (= 2 (dds.xport.zerocopy::%zc-free-count sap))
                           "after the single release the slot must be reclaimable (acquire held no extra count)"))
                 ;; (2) a stale/forged generation ⇒ NIL (single value); an OOB slot ⇒ NIL
                 (%check :zclf-acq-stale-gen
                         (null (dds.xport.zerocopy::%zc-acquire-for-read sap i (logand (+ g 7) #xFFFFFFFF)))
                         "lock-free acquire with a stale/forged generation must return NIL (no payload read)")
                 (%check :zclf-acq-oob
                         (null (dds.xport.zerocopy::%zc-acquire-for-read sap 99 g))
                         "lock-free acquire of an out-of-range slot must return NIL"))
               ;; (3) a forged over-long recorded LEN ⇒ CLAMPED to slot-bytes (no OOB exposure even lock-free)
               (multiple-value-bind (i2 g2) (dds.xport.zerocopy::%zc-loan sap payload 0 4 1)
                 (let ((b (dds.xport.zerocopy::%zc-slot-off sap i2)))
                   (setf (cffi:mem-ref sap :uint32 (+ b dds.xport.zerocopy::+zc-slot-off-len+)) #xFFFFFFFF))
                 (multiple-value-bind (psap2 idx2 gen2 len2 base2)
                     (dds.xport.zerocopy::%zc-acquire-for-read sap i2 g2)
                   (declare (ignore idx2 gen2 base2))
                   (%check :zclf-acq-forged-len-handle psap2 "lock-free acquire of a forged-LEN slot must still return a handle")
                   (%check :zclf-acq-forged-len-clamped (eql len2 32)
                           "a forged over-long recorded LEN must be CLAMPED to slot-bytes (32), never exposed OOB"))
                 ;; (4) THE HEADLINE: the lock-free acquire CONSES 0 BYTES per call (mutex residue gone)
                 (let ((iters 20000)
                       (before (dds.pal:bytes-consed)))
                   (dotimes (k iters) (dds.xport.zerocopy::%zc-acquire-for-read sap i2 g2))
                   (let ((per (floor (max 0 (- (dds.pal:bytes-consed) before)) iters)))
                     (format t "~&  zc-lockfree-acquire: ~d bytes/sample (0-alloc fenced read; the ~~31 B mutex residue eliminated)~%" per)
                     (%check :zclf-acq-zero-alloc (zerop per)
                             (format nil "the lock-free acquire must cons 0 bytes/sample (got ~d — the mutex residue must be gone)" per))))
                 (dds.xport.zerocopy::%zc-release sap i2 g2))
               (dds.xport.zerocopy::%zc-destroy sap)
               t)
          (dds.pal:free-static m)))
      (progn
        (format t "~&  [skip] zc-lockfree-acquire: load-sap-u8 + bytes-consed are SBCL-only (ZC, ADR 0013) — NFR-PORT gap~%")
        t)))

(defun* run-zc-lockfree-release-test ()
    (function () (eql t))
  "WP-ZC-LOAN-LOCKFREE Phase B (FR-PF-3/4, NFR-PERF-7, R6, ADR 0018; NOT cleared for ship — pending counsel):
   the LOCK-FREE cas-sap-u32 ATOMIC DECREMENT OF THE REFCOUNT SUB-FIELD %zc-release (no mutex). Proves: (1) a
   release DECREMENTS the refcount and the slot FREES at refcount 0 (the writer reuses it — a subsequent
   %zc-loan succeeds); (2) DOUBLE-RETURN is a SAFE NO-OP — a second release of an already-0 slot leaves the
   refcount at 0, NEVER wraps to ~4e9 (no underflow); (3) a STALE-generation release is a NO-OP (NIL); (4) the
   direct u32-refcount CAS touches ONLY the refcount cell @+0 — the generation @+4 is PRESERVED (read generation
   after a release, assert unchanged); (5) THE HEADLINE — the lock-free release CONSES 0 BYTES per call (the
   mutex residue is gone; see run-zc-lockfree-release-biggen-test for 0-alloc AT ANY generation).
   SBCL only (cas-sap-u32 + bytes-consed are SBCL-exact, ZC ADR 0013); Clasp pass-skips."
  (if (eq (dds.pal:pal-impl-name) :sbcl)
      (let ((m (dds.pal:alloc-static (dds.xport.zerocopy::%zc-bytes 2 32)))
            (payload (octets 7 8 9)))
        (unwind-protect
             (let ((sap (dds.pal:static-pointer m)))
               (dds.xport.zerocopy::%zc-init sap 2 32)
               ;; loan a slot to refcount=2 so the first release leaves it HELD (refcount 1), proving decrement
               (multiple-value-bind (i g) (dds.xport.zerocopy::%zc-loan sap payload 0 3 2)
                 (%check :zclf-rel-first (dds.xport.zerocopy::%zc-release sap i g)
                         "the first lock-free release (rc 2->1) must apply (T)")
                 (%check :zclf-rel-still-held (= 1 (%zc-slot-refcount sap i))
                         "after one release of a 2-count loan the slot stays HELD (refcount 1) — the decrement is exact")
                 (%check :zclf-rel-not-yet-free (= 1 (dds.xport.zerocopy::%zc-free-count sap))
                         "the still-held slot is not yet reclaimable (only slot 1 is free)")
                 ;; (4) the generation @+4 is PRESERVED across the cas-decf (the direct u32 CAS touches only refcount @+0)
                 (%check :zclf-rel-gen-preserved
                         (= g (cffi:mem-ref sap :uint32 (+ (dds.xport.zerocopy::%zc-slot-off sap i)
                                                           dds.xport.zerocopy::+zc-slot-off-generation+)))
                         "the cas-decf must preserve the generation @+4, decrementing ONLY the refcount @+0")
                 ;; (1) the second release (rc 1->0) FREES the slot
                 (%check :zclf-rel-second (dds.xport.zerocopy::%zc-release sap i g)
                         "the second lock-free release (rc 1->0) must apply (T)")
                 (%check :zclf-rel-refcount-zero (zerop (%zc-slot-refcount sap i))
                         "the released slot's refcount must be 0")
                 (%check :zclf-rel-frees (= 2 (dds.xport.zerocopy::%zc-free-count sap))
                         "at refcount 0 the slot becomes reclaimable (both slots free)")
                 ;; (2) DOUBLE-RETURN of the already-0 slot: a validated no-op — refcount stays 0, NO underflow/wrap
                 (dds.xport.zerocopy::%zc-release sap i g)
                 (%check :zclf-rel-double-no-underflow (zerop (%zc-slot-refcount sap i))
                         "a double return must leave the refcount at 0 (never decremented below 0 / wrapped to ~4e9)")
                 (%check :zclf-rel-double-no-realloc (= 2 (dds.xport.zerocopy::%zc-free-count sap))
                         "a double return must not change the reclaimable count")
                 ;; the freed slot is reusable: a fresh loan succeeds (the writer reclaims a refcount==0 slot)
                 (multiple-value-bind (i2 g2) (dds.xport.zerocopy::%zc-loan sap payload 0 3 1)
                   (%check :zclf-rel-reusable (and i2 t)
                           "after the release a fresh %zc-loan must succeed (the freed slot is reclaimable)")
                   ;; (3) a STALE-generation release is a no-op (NIL)
                   (%check :zclf-rel-stale-gen
                           (null (dds.xport.zerocopy::%zc-release sap i2 (logand (+ g2 9) #xFFFFFFFF)))
                           "a lock-free release with a stale generation must be a no-op (NIL)")
                   (%check :zclf-rel-stale-held (= 1 (%zc-slot-refcount sap i2))
                           "a stale-generation release must NOT touch the refcount (still held at 1)")
                   ;; (5) THE HEADLINE: 0 bytes/sample over a loop (the mutex residue is gone)
                   (let ((iters 20000)
                         (before (dds.pal:bytes-consed)))
                     ;; release a slot already at 0 repeatedly: the guarded no-op path, payload-independent, 0-alloc
                     (dds.xport.zerocopy::%zc-release sap i g)   ; ensure slot i is at refcount 0
                     (dotimes (k iters) (dds.xport.zerocopy::%zc-release sap i g))
                     (let ((per (floor (max 0 (- (dds.pal:bytes-consed) before)) iters)))
                       (format t "~&  zc-lockfree-release: ~d bytes/sample (0-alloc cas-decf; the ~~31 B mutex residue eliminated)~%" per)
                       (%check :zclf-rel-zero-alloc (zerop per)
                               (format nil "the lock-free release must cons 0 bytes/sample (got ~d — the mutex residue must be gone)" per))))
                   (dds.xport.zerocopy::%zc-release sap i2 g2)))
               (dds.xport.zerocopy::%zc-destroy sap)
               t)
          (dds.pal:free-static m)))
      (progn
        (format t "~&  [skip] zc-lockfree-release: cas-sap-u32 + bytes-consed are SBCL-only (ZC, ADR 0013) — NFR-PORT gap~%")
        t)))

(defun* run-zc-lockfree-release-biggen-test ()
    (function () (eql t))
  "WP-ZC-LOAN-LOCKFREE Phase B regression (NFR-PERF-7, NFR-MEM, R6, ADR 0018; NOT cleared for ship — pending
   counsel): %zc-release is 0-alloc AT ANY GENERATION. THE HEADLINE — a slot whose generation has grown past
   ~2^30 must STILL release at 0 bytes/sample. The pre-fix u64-overlay code (load-sap-u64 of the combined
   (generation<<32)|refcount word) BOXED A BIGNUM there — once generation >= 2^30 the combined u64 exceeds
   most-positive-fixnum (2^62-1) — silently regressing the long-running writer's loaned RX to ~32 GC-bytes/sample.
   The direct u32-refcount cas-sap-u32 never materialises the combined word, so it is fixnum/0-alloc at every
   generation. Proves at generation #x80000000 (=2^31, >= 2^30): (1) the release decrement still applies + frees;
   (2) the release CONSES 0 BYTES/sample (this MUST have measured ~32 B against the pre-fix overlay); (3)
   double-return is still a safe no-op (refcount stays 0, no underflow); (4) a stale-generation release is a
   no-op; (5) the generation high-half @+4 is PRESERVED across the u32-refcount CAS (the CAS touches ONLY @+0).
   Re-asserts the small-generation 0-alloc too (the fix is generation-independent). SBCL only (cas-sap-u32 +
   bytes-consed are SBCL-exact, ZC ADR 0013); Clasp pass-skips."
  (if (eq (dds.pal:pal-impl-name) :sbcl)
      (let ((m (dds.pal:alloc-static (dds.xport.zerocopy::%zc-bytes 2 32)))
            (payload (octets 4 5 6))
            (biggen #x80000000))   ; 2^31, well past the 2^30 boxing threshold of the old u64 overlay
        (unwind-protect
             (let ((sap (dds.pal:static-pointer m)))
               (dds.xport.zerocopy::%zc-init sap 2 32)
               ;; loan slot 0 (refcount=1), then drive its generation to BIGGEN directly (a real long-running
               ;; slot would reach it by ~2^31 loans; writing the field is the deterministic equivalent)
               (multiple-value-bind (i g) (dds.xport.zerocopy::%zc-loan sap payload 0 3 1)
                 (declare (ignore g))
                 (let ((b (dds.xport.zerocopy::%zc-slot-off sap i)))
                   (setf (cffi:mem-ref sap :uint32 (+ b dds.xport.zerocopy::+zc-slot-off-generation+)) biggen)
                   ;; (2) THE HEADLINE: release at the LARGE generation conses 0 bytes/sample (no bignum overlay).
                   ;; Drive the guarded no-op path (refcount already 0 after the real release below would be the
                   ;; same site); first prove the live decrement frees, then loop the no-op path for the measure.
                   (%check :zclf-rel-biggen-frees (dds.xport.zerocopy::%zc-release sap i biggen)
                           "a release at generation 2^31 (rc 1->0) must apply (T) — the decrement path runs at any gen")
                   (%check :zclf-rel-biggen-refcount-zero (zerop (%zc-slot-refcount sap i))
                           "the big-generation release must leave refcount 0")
                   ;; (5) the generation high-half @+4 is PRESERVED — the u32-refcount CAS touches ONLY @+0
                   (%check :zclf-rel-biggen-gen-preserved
                           (= biggen (cffi:mem-ref sap :uint32 (+ b dds.xport.zerocopy::+zc-slot-off-generation+)))
                           "the u32-refcount CAS must NOT touch the generation @+4 (preserved exactly at 2^31)")
                   ;; (3) double-return at the big generation: still a validated no-op, NO underflow/wrap
                   (dds.xport.zerocopy::%zc-release sap i biggen)
                   (%check :zclf-rel-biggen-double-no-underflow (zerop (%zc-slot-refcount sap i))
                           "a double return at generation 2^31 must leave refcount 0 (never wrapped to ~4e9)")
                   ;; (4) a stale-generation release at the big generation is a no-op (NIL), no decrement
                   (let ((held (dds.xport.zerocopy::%zc-loan sap payload 0 3 1)))
                     (setf (cffi:mem-ref sap :uint32 (+ (dds.xport.zerocopy::%zc-slot-off sap held)
                                                        dds.xport.zerocopy::+zc-slot-off-generation+)) biggen)
                     (%check :zclf-rel-biggen-stale
                             (null (dds.xport.zerocopy::%zc-release sap held (logand (+ biggen 9) #xFFFFFFFF)))
                             "a release with a stale generation (near 2^31) must be a no-op (NIL)")
                     (%check :zclf-rel-biggen-stale-held (= 1 (%zc-slot-refcount sap held))
                             "a stale-generation release must NOT touch the refcount (still held at 1)")
                     ;; (2) measure: release a slot already at refcount 0 at the BIG generation, in a loop.
                     ;; The guarded no-op path still loads the refcount + (pre-fix) the combined u64 — exactly the
                     ;; boxing site. 0-alloc here proves no bignum at gen 2^31.
                     (let ((iters 20000)
                           (before (dds.pal:bytes-consed)))
                       (dotimes (k iters) (dds.xport.zerocopy::%zc-release sap i biggen))
                       (let ((per (floor (max 0 (- (dds.pal:bytes-consed) before)) iters)))
                         (format t "~&  zc-lockfree-release-biggen: ~d bytes/sample at generation 2^31 (0-alloc direct u32 CAS; the pre-fix u64-overlay boxed ~~32 B here)~%" per)
                         (%check :zclf-rel-biggen-zero-alloc (zerop per)
                                 (format nil "the release must cons 0 bytes/sample at generation 2^31 (got ~d — the pre-fix combined-u64 overlay boxed a bignum here)" per))))
                     ;; small-generation 0-alloc still holds (the fix is generation-independent)
                     (let* ((s2 (dds.xport.zerocopy::%zc-slot-off sap held)))
                       (setf (cffi:mem-ref sap :uint32 (+ s2 dds.xport.zerocopy::+zc-slot-off-generation+)) 3
                             (cffi:mem-ref sap :uint32 (+ s2 dds.xport.zerocopy::+zc-slot-off-refcount+)) 0)
                       (let ((iters 20000)
                             (before (dds.pal:bytes-consed)))
                         (dotimes (k iters) (dds.xport.zerocopy::%zc-release sap held 3))
                         (let ((per (floor (max 0 (- (dds.pal:bytes-consed) before)) iters)))
                           (format t "~&  zc-lockfree-release-biggen: ~d bytes/sample at a small generation (re-assert 0-alloc)~%" per)
                           (%check :zclf-rel-smallgen-zero-alloc (zerop per)
                                   (format nil "the release must cons 0 bytes/sample at a small generation too (got ~d)" per))))))))
               (dds.xport.zerocopy::%zc-destroy sap)
               t)
          (dds.pal:free-static m)))
      (progn
        (format t "~&  [skip] zc-lockfree-release-biggen: cas-sap-u32 + bytes-consed are SBCL-only (ZC, ADR 0013) — NFR-PORT gap~%")
        t)))

(defun* run-zc-lockfree-stress-test ()
    (function () (eql t))
  "WP-ZC-LOAN-LOCKFREE Phase B — THE LOCK-FREE CONCURRENCY GATE (FR-PF-3/4, NFR-SEC, R6, ADR 0018; NOT cleared
   for ship — pending counsel). The binary-gate safety property of the lock-free acquire/release under REAL
   threads: N reader threads each acquire (lock-free fenced read) -> read the held view -> release (lock-free
   cas-decf), concurrently with a writer that loans + scans + force-reclaims, for a bounded time. Asserts:
   (1) NO TORN READ — every held view that resolves stays BYTE-CORRECT (force-reclaim skips refcount>0, and the
   cas-decf full-barrier orders the reader's payload reads before refcount->0, so a held slot is never
   overwritten mid-read); (2) NO refcount UNDERFLOW/LEAK — after every thread joins and all loans drain, the
   pool FULLY reclaims (free-count == K) and no slot's refcount wrapped; (3) NO slot overwritten under a reader;
   (4) the writer made progress (the lock-free readers never block it). Bounded behind a deadline so a
   regression FAILS rather than wedges. SBCL only (ZC pool + foreign SAP reads, ADR 0013); Clasp pass-skips."
  (if (not (eq (dds.pal:pal-impl-name) :sbcl))
      (progn
        (format t "~&  [skip] zc-lockfree-stress: ZC pool + load-sap-u8 are SBCL-only (ADR 0013) — NFR-PORT gap~%")
        t)
      (let* ((k 8)
             (slot-bytes 64)
             (nreaders 4)
             (mem (dds.pal:alloc-static (dds.xport.zerocopy::%zc-bytes k slot-bytes)))
             (sap (dds.pal:static-pointer mem))
             (churn (octets 200 201 202 203 204))   ; the writer's churn payload
             (stop nil) (writer-iters 0) (writer-error nil) (reader-error nil)
             (torn nil) (underflow nil)
             (writer-thread nil) (reader-threads '()))
        (unwind-protect
             (progn
               (dds.xport.zerocopy::%zc-init sap k slot-bytes)
               ;; WRITER: churn the pool (loan distinct payloads + immediately release) for a bounded count
               (setf writer-thread
                     (dds.pal:spawn
                      (lambda ()
                        (handler-case
                            (dotimes (i 200000)
                              (when stop (return))
                              ;; a payload whose bytes are derived from i, so a torn read across a reclaim shows up
                              (let ((p (octets (logand i #xff) (logand (ash i -8) #xff) 0 0 0)))
                                (multiple-value-bind (s g) (dds.xport.zerocopy::%zc-loan sap p 0 (length p) 1)
                                  (incf writer-iters)
                                  (when s (dds.xport.zerocopy::%zc-release sap s g))))   ; cycle the slot
                              (when (zerop (mod i 128)) (sleep 0.00005)))
                          (error (e) (setf writer-error e))))
                      :name "zclf-stress-writer"))
               ;; READERS: each loans HELD, acquires, verifies the held view stays byte-correct, releases — looped
               (dotimes (r nreaders)
                 (push
                  (dds.pal:spawn
                   (lambda ()
                     (handler-case
                         (let ((held (octets (+ 100 r) (+ 110 r) (+ 120 r) (+ 130 r) (+ 140 r)))
                               (deadline (+ (dds.pal:monotonic-ns) 2000000000)))   ; 2s bound (fail, never wedge)
                           (loop repeat 50000
                                 while (and (not stop) (< (dds.pal:monotonic-ns) deadline))
                                 do (multiple-value-bind (hslot hgen) (dds.xport.zerocopy::%zc-loan sap held 0 (length held) 1)
                                      (when hslot
                                        ;; lock-free acquire the slot WE just loaned; its bytes must equal HELD
                                        (multiple-value-bind (psap idx hg hlen hbase)
                                            (dds.xport.zerocopy::%zc-acquire-for-read sap hslot hgen)
                                          (declare (ignore idx hg))
                                          (when psap
                                            (unless (loop for j below (min (length held) hlen)
                                                          always (= (dds.pal:load-sap-u8 psap (+ hbase j)) (aref held j)))
                                              (setf torn t)))
                                          ;; release; if it returned T at a non-positive count we'd have underflowed
                                          (dds.xport.zerocopy::%zc-release sap hslot hgen))))))
                       (error (e) (setf reader-error e))))
                   :name (format nil "zclf-stress-reader-~d" r))
                  reader-threads))
               ;; wait (bounded) for the writer to actually churn so the reads overlap real reclaim
               (let ((start-deadline (+ (dds.pal:monotonic-ns) 2000000000)))
                 (loop until (or (plusp writer-iters) (> (dds.pal:monotonic-ns) start-deadline))
                       do (sleep 0.0005)))
               ;; let the readers run their bounded loops, then stop the writer
               (dolist (rt reader-threads) (dds.pal:join rt))
               (setf reader-threads '())
               (setf stop t)
               (dds.pal:join writer-thread) (setf writer-thread nil)
               (%check :zclf-stress-writer-no-error (null writer-error)
                       (format nil "the concurrent writer must not error (no crash under lock-free churn); got ~a" writer-error))
               (%check :zclf-stress-reader-no-error (null reader-error)
                       (format nil "no reader thread may error (no crash in the lock-free acquire/release); got ~a" reader-error))
               (%check :zclf-stress-writer-progressed (plusp writer-iters)
                       "the writer must have made progress (the lock-free readers never block it)")
               (%check :zclf-stress-no-torn-read (null torn)
                       "no held view may tear: a slot held at refcount>0 is never overwritten mid-read (no UAF / torn read)")
               ;; (2) NO underflow/leak: every refcount is 0..K (never wrapped) and the pool fully reclaims
               (dotimes (i k)
                 (let ((rc (%zc-slot-refcount sap i)))
                   (when (> rc k) (setf underflow t))))
               (%check :zclf-stress-no-underflow (null underflow)
                       "no slot's refcount may have wrapped (underflow would show as a huge u32, > K)")
               (%check :zclf-stress-full-reclaim (= k (dds.xport.zerocopy::%zc-free-count sap))
                       (format nil "after all threads join + all loans drain the pool must FULLY reclaim (free-count = K = ~d), no refcount leak" k)))
          (setf stop t)
          (dolist (rt reader-threads) (ignore-errors (dds.pal:join rt)))
          (when writer-thread (ignore-errors (dds.pal:join writer-thread)))
          (dds.xport.zerocopy::%zc-destroy sap)
          (dds.pal:free-static mem))
        t)))

(defun* run-shmem-locator-wire-test ()
    (function () (eql t))
  "SHMEM Locator_t + PID_SHMEM_HOST_UUID ride additively in SPDP (FR-XPORT-2, ADR 0013):
   a SHMEM locator round-trips beside a UDP locator (no regression), the host-uuid round-trips,
   and a truncated PID_SHMEM_HOST_UUID is ignored fail-open (host-uuid stays 0, never errors)."
  (let* ((prefix (make-array 12 :element-type '(unsigned-byte 8)
                             :initial-contents '(9 9 9 9 8 8 8 8 7 7 7 7)))
         (udp (dds.rtps.discovery:make-locator
               :kind dds.rtps.discovery:+locator-kind-udpv4+ :port 7411
               :address (dds.rtps.discovery:make-ipv4-locator
                         (octets 192 168 1 77))))
         (shm (dds.rtps.discovery:make-shmem-locator-wire 8 65536))
         (data (dds.rtps.discovery:make-spdp-data
                :guid-prefix prefix :host-uuid #xCAFEBABEF00D1234
                :default-unicast-locators (list udp shm)))
         (ob (dds.core.buffer:make-octet-buffer 512))
         (wc (dds.core.buffer:cursor ob :endianness :little)))
    (dds.rtps.discovery:serialize-spdp-data wc data)
    (let* ((rc (dds.core.buffer:cursor ob :endianness :little))
           (back (dds.rtps.discovery:parse-spdp-data rc)))
      (%check :parsed back "parse-spdp-data returned NIL")
      (%check :host-uuid (= (dds.rtps.discovery:spdp-data-host-uuid back) #xCAFEBABEF00D1234)
              "host-uuid did not round-trip")
      (let* ((locs (dds.rtps.discovery:spdp-data-default-unicast-locators back))
             (sloc (find dds.rtps.discovery:+locator-kind-shmem+ locs
                         :key #'dds.rtps.discovery:locator-kind))
             (uloc (find dds.rtps.discovery:+locator-kind-udpv4+ locs
                         :key #'dds.rtps.discovery:locator-kind)))
        (%check :shmem-present sloc "no SHMEM-kind locator in parsed default-unicast-locators")
        (%check :shmem-lanes (= (dds.rtps.discovery:shmem-locator-wire-lane-count sloc) 8)
                "SHMEM locator lane-count != 8")
        (%check :shmem-capacity (= (dds.rtps.discovery:locator-port sloc) 65536)
                "SHMEM locator capacity (port) != 65536")
        (%check :udp-present uloc "UDP locator regressed (not in parsed list)")
        (%check :udp-addr (string= (dds.rtps.discovery:locator-ipv4-string uloc) "192.168.1.77")
                "UDP locator address did not round-trip"))))
  ;; fail-open: a truncated PID_SHMEM_HOST_UUID (len 4) is ignored, never an error; host-uuid stays 0.
  (let* ((ob (dds.core.buffer:make-octet-buffer 64))
         (wc (dds.core.buffer:cursor ob :endianness :little))
         (bad (octets 1 2 3 4)))
    (dds.rtps.message:write-parameter wc dds.rtps.message:+pid-shmem-host-uuid+ bad 0 4)
    (dds.rtps.message:write-parameter-sentinel wc)
    (let* ((rc (dds.core.buffer:cursor ob :endianness :little))
           (back (dds.rtps.discovery:parse-spdp-data rc)))
      (%check :failopen-parsed back "truncated PID_SHMEM_HOST_UUID must parse, not error")
      (%check :failopen-zero (zerop (dds.rtps.discovery:spdp-data-host-uuid back))
              "truncated PID_SHMEM_HOST_UUID must leave host-uuid 0 (fail-open)")))
  t)

(defun* run-zc-ref-codec-test ()
    (function () t)
  "WP-ZEROCOPY Phase C1: encode-zc-reference round-trips via parse-zc-reference;
   a normal-representation-id payload returns NIL; a too-short buffer returns NIL (NFR-SEC-POSTURE)."
  (let* ((arena (dds.core.arena:init-arena :bytes (* 64 1024)))
         (pool  (dds.core.arena:make-buffer-pool arena 64 4)))
    (let* ((b  (dds.core.arena:pool-acquire pool))
           (wc (dds.core.buffer:cursor b :endianness :little)))
      ;; encode (slot=5, gen=42, slot-bytes=65536)
      (dds.cdr:encode-zc-reference wc 5 42 65536)
      (let ((pos (dds.core.buffer:cursor-position wc)))
        (%check :zc-ref-len (= 20 pos) (format nil "expected 20 octets, got ~d" pos)))
      ;; round-trip: parse must recover the same values
      (let ((vec (dds.core.buffer:octet-buffer-vec b)))
        (multiple-value-bind (idx gen sb) (dds.cdr:parse-zc-reference vec 0 20)
          (%check :zc-ref-slot-index (eql idx 5)     (format nil "slot-index ~s != 5" idx))
          (%check :zc-ref-generation (eql gen 42)    (format nil "generation ~s != 42" gen))
          (%check :zc-ref-slot-bytes (eql sb 65536)  (format nil "slot-bytes ~s != 65536" sb)))
        ;; a buffer whose leading u16 is CDR_LE (#x0001) must return NIL
        (let ((normal-buf (make-array 20 :element-type '(unsigned-byte 8) :initial-element 0)))
          ;; CDR_LE = #x0001: hi=0x00, lo=0x01
          (setf (aref normal-buf 0) #x00 (aref normal-buf 1) #x01)
          (multiple-value-bind (idx2 g2 sb2)
              (dds.cdr:parse-zc-reference normal-buf 0 20)
            (declare (ignore g2 sb2))
            (%check :zc-ref-rejects-normal (null idx2) "normal rep-id must return NIL")))
        ;; a too-short buffer (len 8) must return NIL
        (multiple-value-bind (idx3 g3 sb3)
            (dds.cdr:parse-zc-reference vec 0 8)
          (declare (ignore g3 sb3))
          (%check :zc-ref-rejects-short (null idx3) "len < 20 must return NIL"))))
    (dds.core.arena:teardown-arena arena)
    t))

(defun* run-zc-sedp-flag-test ()
    (function () t)
  "WP-ZEROCOPY Phase D1: the SEDP PID_ZEROCOPY_CAPABLE flag round-trips fail-open. An endpoint-data
   with zerocopy-capable T serializes the vendor PID and parses back T; one without it elides the PID
   and parses back NIL (an absent PID is the fail-open default, ADR 0014, FR-PF-3)."
  (let ((arena (dds.core.arena:init-arena :bytes (* 64 1024))))
    (flet ((roundtrip (zc-p)
             (let* ((pool (dds.core.arena:make-buffer-pool arena 512 2))
                    (b (dds.core.arena:pool-acquire pool))
                    (c (dds.core.buffer:cursor b :endianness :little))
                    (guid (make-array 16 :element-type '(unsigned-byte 8) :initial-element 7))
                    (ep (dds.rtps.discovery:make-endpoint-data
                         :role :writer :guid guid :topic-name "ZcT" :type-name "X"
                         :zerocopy-capable zc-p)))
               (dds.cdr:make-encapsulation-header c :pl-cdr-le)
               (dds.rtps.discovery:serialize-endpoint-data c ep)
               (let ((rc (dds.core.buffer:cursor b :endianness :little)))
                 (dds.cdr:parse-encapsulation-header rc)
                 (dds.rtps.discovery:endpoint-data-zerocopy-capable
                  (dds.rtps.discovery:parse-endpoint-data rc :writer))))))
      (%check :zc-sedp-flag-on  (eq t   (roundtrip t))   "zerocopy-capable T must parse back T")
      (%check :zc-sedp-flag-off (eq nil (roundtrip nil)) "absent PID_ZEROCOPY_CAPABLE must parse back NIL"))
    (dds.core.arena:teardown-arena arena)
    t))

(defun* run-zc-resolve-drop-test ()
    (function () t)
  "WP-ZEROCOPY Phase D3 (NFR-SEC-POSTURE, FR-PF-3, ADR 0014): a forged 16-byte reference — to a
   non-existent writer pool AND, against this node's own pool, to a bad slot/generation — is DROPPED
   safely (best-effort) with no crash and no sample stored. The reference is untrusted cross-process
   input: %zc-attach-pool tolerates a garbage source prefix (attach fails -> :none -> drop) and %zc-resolve
   bounds-checks slot-index + validates generation. Skips where SHMEM (hence a ZC pool) is unavailable."
  (unless (dds.xport.shmem:shm-attach-by-name-reliable-p) (return-from run-zc-resolve-drop-test t))
  (let* ((dds.disc:*shmem-enabled* t)
         (dds.disc:*zerocopy-enabled* t)
         (node (dds.disc:make-disc-node
                :guid-prefix (make-array 12 :element-type '(unsigned-byte 8) :initial-element 70)
                :host "127.0.0.1" :port 0)))
    (unwind-protect
         (progn
           (dds.disc:add-local-reader node :topic "ZcDrop" :type "X"
                                      :reliability dds.rtps.discovery:+reliability-reliable+)
           (dds.disc:enable-subscriber node)
           (%check :zc-drop-armed (dds.disc::disc-node-zc-pool node) "node must have a ZC pool to exercise the resolve path")
           ;; forge a zc-ref payload in an octet-buffer at offset 0
           (let* ((b (dds.core.buffer:make-octet-buffer 64))
                  (c (dds.core.buffer:cursor b :endianness :little))
                  (bad-prefix (make-array 12 :element-type '(unsigned-byte 8) :initial-element 99)))   ; no such writer pool
             (dds.cdr:encode-zc-reference c 3 7 dds.disc:+zerocopy-pool-slot-bytes+)   ; slot 3, gen 7
             (let ((plen (dds.core.buffer:cursor-position c)))
               ;; (a) ref to a NON-EXISTENT pool (garbage source prefix) -> drop (NIL), no crash
               (%check :zc-drop-no-pool
                       (null (dds.disc::%zc-try-resolve node b 0 plen bad-prefix))
                       "a ref to a non-existent writer pool must resolve to NIL (drop), not crash")
               ;; (b) ref to THIS node's own pool but a stale slot/generation -> drop (NIL)
               (%check :zc-drop-stale-gen
                       (null (dds.disc::%zc-try-resolve node b 0 plen (dds.disc::disc-node-guid-prefix node)))
                       "a ref with a non-matching generation must resolve to NIL (drop)")
               ;; (c) end-to-end via the on-data hook: a forged ref must store NO sample
               (dds.disc::%on-user-data node #x00000102 1 b 0 plen bad-prefix)
               (%check :zc-drop-no-sample (zerop (dds.disc:node-sample-count node))
                       "a forged ZC reference must deliver NO sample (best-effort drop)")
               ;; (d) a NORMAL (non-ref) payload still delivers on the same path (sanity: drop logic is ref-gated)
               (let* ((nb (dds.core.buffer:make-octet-buffer 16))
                      (nc (dds.core.buffer:cursor nb :endianness :little)))
                 (dds.core.buffer:put-octets nc (octets 1 2 3 4 5 6 7 8) 0 8)
                 (dds.disc::%on-user-data node #x00000102 2 nb 0 8
                                          (dds.disc::disc-node-guid-prefix node))
                 (%check :zc-drop-normal-delivers (= 1 (dds.disc:node-sample-count node))
                         "a normal (non-ref) payload must still be delivered when ZC is armed")
                 (dds.pal:free-static (dds.core.buffer:octet-buffer-vec nb)))
               (dds.pal:free-static (dds.core.buffer:octet-buffer-vec b)))))
      (dds.disc:stop-node node))
    t))

(defun* %zc-slot-refcount (sap slot)
    (function (t (integer 0)) (unsigned-byte 32))
  "Test helper (WP-FLATDATA-ZC-LOAN, R6, ADR 0017): the live u32 refcount of pool SLOT off SAP, read directly
   (like the other zc-pool tests reach %-internals). Lets the defer test prove a loaned slot is NOT released."
  (cffi:mem-ref sap :uint32 (+ (dds.xport.zerocopy::%zc-slot-off sap slot)
                               dds.xport.zerocopy::+zc-slot-off-refcount+)))

(defun* run-zc-defer-test ()
    (function () t)
  "WP-FLATDATA-ZC-LOAN Task D (FR-PF-3/4, R6, ADR 0017; NOT cleared for ship — pending counsel): the disc
   receiver thread DEFERS ZC resolution for a LOAN-CAPABLE reader and RESOLVES-COPIES-RELEASES for a
   non-loan-capable one. Single-process + deterministic (no networking, the run-zc-resolve-drop-test technique):
   loan a FlatData payload into the node's OWN pool, encode the 16-byte ref, then drive %on-user-data with the
   node's own guid-prefix as the source (so %zc-attach-pool attaches the node's own pool).
     (1) LOAN-CAPABLE: the stored sample is an UNRESOLVED zc-loan-marker (NOT a copied octet-vector) AND the slot
         is NOT released (refcount still 1, the slot still loaned) — the slot lifetime is handed to DCPS.
     (2) NON-LOAN-CAPABLE: the stored sample is a normal resolved octet-vector EQUAL to the published payload AND
         the slot WAS released (refcount 0, freed) — the shipped resolve-copy-release path, byte-unchanged.
   Skips where SHMEM (hence a ZC pool) is unavailable (Clasp/macOS by-name-attach gap, ADR 0013)."
  (unless (dds.xport.shmem:shm-attach-by-name-reliable-p) (return-from run-zc-defer-test t))
  (let* ((dds.disc:*shmem-enabled* t)
         (dds.disc:*zerocopy-enabled* t)
         (va 200) (vb 3000000000) (vc 12345678901234567890)
         (fd (make-fd-abc-flatdata)))
    (setf (fd-abc-a-fd fd) va (fd-abc-b-fd fd) vb (fd-abc-c-fd fd) vc)
    (let ((payload (subseq (dds.core.buffer:octet-buffer-vec fd) 0 +fd-abc-flatdata-size+)))
      (unwind-protect
           (dolist (loan-capable '(t nil))
             (let ((node (dds.disc:make-disc-node
                          :guid-prefix (make-array 12 :element-type '(unsigned-byte 8)
                                                   :initial-element (if loan-capable 71 72))
                          :host "127.0.0.1" :port 0)))
               (unwind-protect
                    (progn
                      (dds.disc:add-local-reader node :topic "ZcDefer" :type "fd-abc"
                                                 :reliability dds.rtps.discovery:+reliability-reliable+)
                      (dds.disc:enable-subscriber node)
                      (when loan-capable (dds.disc:set-zc-loan-capable node t))
                      (let* ((sap (dds.disc::disc-node-zc-pool-sap node))
                             (b (dds.core.buffer:make-octet-buffer 64))
                             (c (dds.core.buffer:cursor b :endianness :little)))
                        (multiple-value-bind (slot gen)
                            (dds.xport.zerocopy::%zc-loan sap payload 0 (length payload) 1)
                          (%check :zc-defer-loaned (and slot t) "could not loan the FlatData payload into the pool")
                          (dds.cdr:encode-zc-reference c slot gen dds.disc:+zerocopy-pool-slot-bytes+)
                          (let ((plen (dds.core.buffer:cursor-position c)))
                            (dds.disc::%on-user-data node #x00000102 1 b 0 plen
                                                     (dds.disc::disc-node-guid-prefix node))
                            (let ((got (dds.disc:node-sample-by-sn node 1)))
                              (%check :zc-defer-stored (and got t) "%on-user-data stored no sample")
                              (if loan-capable
                                  (progn
                                    (%check :zc-defer-marker (dds.disc:zc-loan-marker-p got)
                                            "a loan-capable reader must store an UNRESOLVED zc-loan-marker, not a copy")
                                    (%check :zc-defer-marker-slot
                                            (and (= (dds.disc:zc-loan-marker-slot-index got) slot)
                                                 (= (dds.disc:zc-loan-marker-generation got) gen))
                                            "the marker must carry the loan handle (slot + generation)")
                                    (%check :zc-defer-not-released (= 1 (%zc-slot-refcount sap slot))
                                            "a loan-capable reader must NOT release the slot (refcount stays 1, still loaned)"))
                                  (progn
                                    (%check :zc-defer-resolved
                                            (and (typep got '(simple-array (unsigned-byte 8) (*)))
                                                 (equalp got payload))
                                            "a non-loan-capable reader must resolve+copy the payload (shipped path)")
                                    (%check :zc-defer-released (zerop (%zc-slot-refcount sap slot))
                                            "a non-loan-capable reader must release the slot (refcount 0, freed)"))))
                            (dds.pal:free-static (dds.core.buffer:octet-buffer-vec b))))))
                 (dds.disc:stop-node node))))
        (dds.pal:free-static (dds.core.buffer:octet-buffer-vec fd)))))
  t)

;;; WP-FLATDATA compile-time gate (FR-PF-4, ADR 0015)
(defun* run-flatdata-rejects-variable-test ()
    (function () (eql t))
  "A :flatdata t type with a variable-size member must be a compile-time error (FlatData v1 = fixed-size only)."
  (%check :flatdata-rejects-string
          (nth-value 1 (ignore-errors
                         (macroexpand-1 '(dds.gen:define-dds-type flatdata-bad-t (:flatdata t)
                                          (n :u32) (s :string)))))
          "define-dds-type :flatdata t with a :string member must signal at macroexpand")
  t)

;;; WP-FLATDATA compile-time XCDR2 offsets (FR-PF-4, ADR 0015; R6). fd-abc's u8/u32/u64 mix
;;; forces the alignment path: u8@0, u32@4 (3-byte pad), u64@8 (XCDR2 4-cap, no 8-pad).
(dds.gen:define-dds-type fd-abc (:flatdata t)
  (a :u8) (b :u32) (c :u64))

(defun* run-flatdata-offsets-test ()
    (function () (eql t))
  "%flatdata-offsets lands each FINAL fixed-size scalar where the classic serialize writes it:
   serialize an equal struct (body at origin 4), then read each field back at 4+body-offset (the oracle)."
  (multiple-value-bind (offs body-size) (dds.gen::%flatdata-offsets
                                         (mapcar #'dds.gen::%parse-member
                                                 '((a :u8) (b :u32) (c :u64))))
    (%check :fd-offsets-values
            (equal offs '((a . 0) (b . 4) (c . 8)))
            (format nil "unexpected XCDR2 body offsets ~s" offs))
    (%check :fd-body-size (= body-size 16)
            (format nil "unexpected body size ~d (want 16)" body-size))
    (let* ((arena (dds.core.arena:init-arena :bytes (* 64 1024)))
           (pool (dds.core.arena:make-buffer-pool arena 256 1))
           (va 200) (vb 3000000000) (vc 12345678901234567890)
           (s (make-fd-abc :a va :b vb :c vc))
           (b (dds.core.arena:pool-acquire pool))
           (wc (dds.core.buffer:cursor b :endianness :little)))
      ;; mirror the engine: 4-byte XCDR2-LE encap header sets the body origin to offset 4
      (dds.cdr:make-encapsulation-header wc :plain-cdr2-le)
      (serialize-fd-abc s wc :xcdr2)
      (let ((vec (dds.core.buffer:octet-buffer-vec b)))
        (flet ((le (off n) (let ((v 0)) (dotimes (i n v) (setf v (logior v (ash (aref vec (+ 4 off i)) (* 8 i)))))))
               (boff (slot) (cdr (assoc slot offs))))
          (%check :fd-off-a (= (le (boff 'a) 1) va)
                  (format nil "u8 @body~d != ~d" (boff 'a) va))
          (%check :fd-off-b (= (le (boff 'b) 4) vb)
                  (format nil "u32 @body~d != ~d" (boff 'b) vb))
          (%check :fd-off-c (= (le (boff 'c) 8) vc)
                  (format nil "u64 @body~d != ~d" (boff 'c) vc))))
      (dds.core.arena:pool-release pool b)
      (dds.core.arena:teardown-arena arena)))
  t)

;;; WP-FLATDATA Offset accessors — byte-exact oracle (FR-PF-4, ADR 0015; R6). Build a FlatData buffer
;;; via the Offset setters and assert its body bytes EQUAL the classic serialize of an equal struct
;;; (in-memory == wire). i32-signed/i64-signed values exercise the two's-complement accessor paths.
(dds.gen:define-dds-type fd-sig (:flatdata t)
  (a :u8) (b :i32) (c :i64))

;;; WP-FLATDATA non-4-aligned tail (FR-PF-4, ADR 0015; R6, MUST-FIX false-REJECT). fd-tail's body ends on
;;; an odd offset (u32@0..3, u8@4 -> unpadded body 5); the engine does NOT tail-pad — it writes a 9-octet
;;; payload and records pad 3 in the encap OPTIONS field. +fd-tail-flatdata-size+ MUST be 9, not 12, and the
;;; OPTIONS byte MUST match, or a length==+size+ wrap-check would false-REJECT the engine's own payload.
(dds.gen:define-dds-type fd-tail (:flatdata t)
  (a :u32) (b :u8))

;;; WP-FLATDATA cap discriminator (FR-PF-4, ADR 0015; R6). u32@0,u64@body4 under XCDR2's 4-byte alignment
;;; cap (FR-CDR-2): body 12, payload 16. A wrong 8-cap would put u64@body8 -> body 16, payload 20 — so this
;;; type's engine size discriminates a 4-vs-8 cap regression that fd-abc/fd-sig (64-bit member @body8) cannot.
(dds.gen:define-dds-type fd-disc (:flatdata t)
  (a :u32) (b :u64))

;;; WP-FLATDATA narrow-width accessor coverage (FR-PF-4, ADR 0015; R6). Exercises the u16/i16/bool/i8 form
;;; builders no other FlatData type touches; unpadded body = u16@0 + i16@2 + bool@4 + i8@5 = 6.
(dds.gen:define-dds-type fd-narrow (:flatdata t)
  (a :u16) (b :i16) (c :bool) (d :i8))

(defun* %flatdata-byte-exact (fd-buf size-const ser struct triples)
    (function (dds.core.buffer:octet-buffer (integer 0) function t list) t)
  "Byte-exact FlatData oracle for arbitrary arity: write each member of FD-BUF via its (getter setter value)
   TRIPLE, read it back via the getter, then serialize STRUCT through the CLASSIC path EXACTLY as
   %serialize-sample does (encap header at origin 4, body, finalize-encapsulation-options) and assert the
   FlatData buffer equals it byte-for-byte over [0,SIZE-CONST) — both the body AND the 4-byte encap header
   (incl. the OPTIONS pad bits) — and that the classic payload length equals SIZE-CONST. The engine is the
   only oracle (no hardcoded wire bytes)."
  (loop for (getter setter val) in triples
        do (funcall (fdefinition `(setf ,setter)) val fd-buf)
           (%check :fd-acc-rt (eql (funcall getter fd-buf) val)
                   (format nil "getter ~a read-back mismatch (set ~s)" getter val)))
  (let* ((cb (dds.core.buffer:make-octet-buffer (+ size-const 8)))
         (wc (dds.core.buffer:cursor cb :endianness :little)))
    (dds.cdr:make-encapsulation-header wc :plain-cdr2-le)
    (funcall ser struct wc :xcdr2)
    (dds.cdr:finalize-encapsulation-options wc :plain-cdr2-le)
    (let ((fv (dds.core.buffer:octet-buffer-vec fd-buf))
          (cv (dds.core.buffer:octet-buffer-vec cb))
          (wrote (dds.core.buffer:cursor-position wc)))
      (%check :fd-acc-len (= wrote size-const)
              (format nil "classic serialize wrote ~d, FlatData size ~d" wrote size-const))
      (%check :fd-acc-byte-exact
              (loop for i from 4 below size-const always (= (aref fv i) (aref cv i)))
              (format nil "in-memory != wire (body): ~s vs ~s"
                      (subseq fv 0 size-const) (subseq cv 0 size-const)))
      (%check :fd-acc-encap
              (loop for i below 4 always (= (aref fv i) (aref cv i)))
              (format nil "encapsulation header (incl. OPTIONS) mismatch: ~s vs ~s"
                      (subseq fv 0 4) (subseq cv 0 4))))
    (dds.pal:free-static (dds.core.buffer:octet-buffer-vec cb)))
  t)

(defun* run-flatdata-accessor-test ()
    (function () (eql t))
  "FlatData Offset accessors round-trip AND the buffer's body bytes + encap header (incl. OPTIONS pad bits)
   equal the classic serialize of an equal struct — the byte-exact in-memory==wire oracle (FR-PF-4). Covers
   unsigned u8/u32/u64; two's-complement signed i32/i64; a non-4-aligned tail (false-REJECT regression); a
   4-vs-8 alignment-cap discriminator; and the narrow u16/i16/bool/i8 accessor forms.
   All buffers are PAL-static make-octet-buffer (FlatData via the constructor; classic scratch via the oracle
   helper), each freed via free-static — no arena/pool is needed here."
  (progn
    ;; case 1: unsigned u8/u32/u64 (fd-abc from the offsets test) — 64-bit member @body8, payload 20
    (let ((b (make-fd-abc-flatdata)))
      (%check :fd-abc-size (= +fd-abc-flatdata-size+ 20)
              (format nil "unexpected +fd-abc-flatdata-size+ ~d" +fd-abc-flatdata-size+))
      (%flatdata-byte-exact
       b +fd-abc-flatdata-size+ #'serialize-fd-abc
       (make-fd-abc :a 200 :b 3000000000 :c 12345678901234567890)
       '((fd-abc-a-fd fd-abc-a-fd 200) (fd-abc-b-fd fd-abc-b-fd 3000000000)
         (fd-abc-c-fd fd-abc-c-fd 12345678901234567890)))
      (dds.pal:free-static (dds.core.buffer:octet-buffer-vec b)))
    ;; case 2: signed i32/i64 (negative values exercise the two's-complement accessor)
    (let ((b (make-fd-sig-flatdata)))
      (%flatdata-byte-exact
       b +fd-sig-flatdata-size+ #'serialize-fd-sig
       (make-fd-sig :a 7 :b -123456789 :c -1234567890123456789)
       '((fd-sig-a-fd fd-sig-a-fd 7) (fd-sig-b-fd fd-sig-b-fd -123456789)
         (fd-sig-c-fd fd-sig-c-fd -1234567890123456789)))
      (dds.pal:free-static (dds.core.buffer:octet-buffer-vec b)))
    ;; case 3: non-4-aligned tail (u32 + u8) — body 5, payload 9, OPTIONS pad 3 (MUST-FIX false-REJECT)
    (let ((b (make-fd-tail-flatdata)))
      (%check :fd-tail-size (= +fd-tail-flatdata-size+ 9)
              (format nil "+fd-tail-flatdata-size+ must be 9 (4 encap + 5 unpadded body), got ~d — a tail-padded ~
                12 would false-REJECT the engine's own 9-octet payload" +fd-tail-flatdata-size+))
      (%flatdata-byte-exact
       b +fd-tail-flatdata-size+ #'serialize-fd-tail
       (make-fd-tail :a #x11223344 :b #xAB)
       '((fd-tail-a-fd fd-tail-a-fd #x11223344) (fd-tail-b-fd fd-tail-b-fd #xAB)))
      (dds.pal:free-static (dds.core.buffer:octet-buffer-vec b)))
    ;; case 4: alignment-cap discriminator (u32 + u64) — u64 MUST sit @body4 (XCDR2 4-cap): payload 16, not 20
    (let ((b (make-fd-disc-flatdata)))
      (%check :fd-disc-size (= +fd-disc-flatdata-size+ 16)
              (format nil "+fd-disc-flatdata-size+ must be 16 (u64 @body4 under XCDR2's 4-byte cap); a wrong ~
                8-cap would put u64 @body8 -> 20. got ~d" +fd-disc-flatdata-size+))
      (%flatdata-byte-exact
       b +fd-disc-flatdata-size+ #'serialize-fd-disc
       (make-fd-disc :a #xDEADBEEF :b #x0123456789ABCDEF)
       '((fd-disc-a-fd fd-disc-a-fd #xDEADBEEF) (fd-disc-b-fd fd-disc-b-fd #x0123456789ABCDEF)))
      (dds.pal:free-static (dds.core.buffer:octet-buffer-vec b)))
    ;; case 5: narrow widths (u16/i16/bool/i8) with a negative i16/i8 and bool t — body 6, payload 10
    ;; (NB: all scratch + FlatData buffers are PAL-static make-octet-buffer, freed per case via free-static)
    (let ((b (make-fd-narrow-flatdata)))
      (%check :fd-narrow-size (= +fd-narrow-flatdata-size+ 10)
              (format nil "+fd-narrow-flatdata-size+ must be 10 (4 encap + 6 unpadded body), got ~d"
                      +fd-narrow-flatdata-size+))
      (%flatdata-byte-exact
       b +fd-narrow-flatdata-size+ #'serialize-fd-narrow
       (make-fd-narrow :a #xBEEF :b -12345 :c t :d -42)
       '((fd-narrow-a-fd fd-narrow-a-fd #xBEEF) (fd-narrow-b-fd fd-narrow-b-fd -12345)
         (fd-narrow-c-fd fd-narrow-c-fd t) (fd-narrow-d-fd fd-narrow-d-fd -42)))
      ;; bool nil round-trips too (the setter writes 0, the getter reads /=0 -> NIL)
      (setf (fd-narrow-c-fd b) nil)
      (%check :fd-narrow-bool-nil (null (fd-narrow-c-fd b)) "bool NIL must round-trip via the Offset accessor")
      (dds.pal:free-static (dds.core.buffer:octet-buffer-vec b)))
    ;; the layout is wired into the type-support hook
    (let* ((ts (dds.types:find-type-support "fd-abc"))
           (lay (dds.types:type-support-flatdata-offset ts)))
      (%check :fd-layout-present (dds.types:flatdata-layout-p lay)
              "type-support flatdata-offset is not a flatdata-layout")
      (%check :fd-layout-size (= (dds.types:flatdata-layout-size lay) +fd-abc-flatdata-size+)
              "flatdata-layout size mismatch")
      (%check :fd-layout-fields (= 3 (length (dds.types:flatdata-layout-fields lay)))
              "flatdata-layout fields count mismatch")
      ;; a non-FlatData type leaves the hook NIL (engine/codegen untouched)
      (%check :fd-nonflat-nil (null (dds.types:type-support-flatdata-offset
                                     (dds.types:find-type-support "gsample")))
              "non-FlatData type unexpectedly has a flatdata-layout")))
  t)

;;; WP-FLATDATA Phase C: serialize=identity / deserialize=read-in-place via the type-support vtable
;;; (FR-PF-4, NFR-PERF-7, ADR 0015; R6). The engine hot path is unchanged — it funcalls the vtable; FlatData
;;; only swaps the function pointers. These two tests prove (1) the swapped serialize+deserialize codecs and
;;; (2) that the FlatData and classic codecs are interchangeable on the wire (decode direction).

(defun* %fd-measure-bytes (label iters thunk)
    (function (string (integer 1) function) single-float)
  "Run THUNK ITERS times, print + return its mean dds.pal:bytes-consed per call (NFR-PERF-7 honest-measurement
   harness, mirrors run-mem-test). On Clasp bytes-consed is 0 (NFR-PORT gap) so it reports 0."
  (declare (type function thunk))
  (let ((before (dds.pal:bytes-consed)))
    (dotimes (i iters) (funcall thunk))
    (let* ((delta (- (dds.pal:bytes-consed) before))
           (per (/ (float delta) iters)))
      (format t "~&  fd-mem[~14a]: ~10d bytes / ~d iters = ~,4f bytes/sample (~a)~%"
              label delta iters per (dds.pal:pal-impl-name))
      per)))

(defun* run-flatdata-zero-alloc-test ()
    (function () (eql t))
  "WP-FLATDATA honest GC-bytes/sample measurement (NFR-PERF-7, FR-LANG-7), separating the TX win, the deferred
   ZC RX path, and the engine's ACTUAL non-ZC RX path. Mirrors run-mem-test's dds.pal:bytes-consed harness:
   reusable write+RX buffers reset per iteration; on SBCL it asserts, on Clasp bytes-consed is 0 (NFR-PORT gap)
   so it only smokes. Four numbers, each on the FUNCTION the engine actually funcalls:
     serialize-id     = vtable :serialize (FlatData identity, into the engine's reused cursor)  -> assert ~0 (real TX win).
     deser-into-loan  = deserialize-into-<name>-fd, the inner copy into a PRE-LOANED target — the 0-alloc path
                        Phase D's Zero-Copy uses (the loaned target IS the ZC slot); NOT the engine's non-ZC RX
                        path today -> assert ~0.
     vtable-deser     = deserialize-<name>-fd, the type-support :deserialize slot %deserialize-sample funcalls on
                        the NON-ZC RX path; allocates one fresh FlatData buffer wrapper per sample (a true 0-copy
                        SAP view with refcount lifetime is DEFERRED beyond v1 — an engine-contract change, see
                        ADR 0015 Phase-D outcome) -> NOT 0; regression-guarded <= classic.
     classic-deser    = the classic per-field deserialize-<name> -> the baseline the vtable-deser must not beat.
   No overclaim: the engine non-ZC RX path is ~vtable-deser bytes (modestly below classic + 0 per-field decode);
   Phase D delivered a SAFE SINGLE COPY ZC RX (~830x less than the v1 sink+re-copy), NOT literal-0-copy; the
   literal-0-copy + 0-alloc RX view is DEFERRED beyond v1 (an engine-contract change; R6, ADR 0015)."
  (let* ((ts (dds.types:find-type-support "fd-abc"))
         (fd (make-fd-abc-flatdata))               ; the FlatData sample (the buffer IS the SerializedPayload)
         (target (make-fd-abc-flatdata))           ; a loaned RX FlatData buffer (deserialize-into copies into it)
         (wbuf (dds.core.buffer:make-octet-buffer (+ +fd-abc-flatdata-size+ 8)))
         (wc (dds.core.buffer:cursor wbuf :endianness :little))
         (rxbuf (dds.core.buffer:make-octet-buffer +fd-abc-flatdata-size+))
         (rc (dds.core.buffer:cursor rxbuf :endianness :little))
         (ser (dds.types:type-support-serialize ts))
         (vdes (dds.types:type-support-deserialize ts))   ; the engine's non-ZC RX vtable slot = deserialize-fd-abc-fd
         (iters 100000)
         (sbcl-p (eq (dds.pal:pal-impl-name) :sbcl)))
    (declare (type function ser vdes))
    (setf (fd-abc-a-fd fd) 200 (fd-abc-b-fd fd) 3000000000 (fd-abc-c-fd fd) 12345678901234567890)
    ;; Build the RX wire payload ONCE (encap header + body), exactly as %serialize-sample delivers it.
    (replace (dds.core.buffer:octet-buffer-vec rxbuf) (dds.dcps::%serialize-sample ts fd))
    ;; warm every path (the engine writes the header then calls :serialize for the body, origin reset to 4;
    ;; reset rc before each parse-encapsulation-header so the encap id is read at position 0, never mid-body)
    (dds.cdr:make-encapsulation-header wc :plain-cdr2-le)
    (funcall ser fd wc :xcdr2)
    (dds.core.buffer:cursor-set-position rc 4)
    (deserialize-into-fd-abc-fd target rc :xcdr2)
    (dds.core.buffer:cursor-reset rc)
    (dds.cdr:parse-encapsulation-header rc)
    (dds.pal:free-static (dds.core.buffer:octet-buffer-vec (funcall vdes rc :xcdr2)))
    (dds.core.buffer:cursor-reset rc)
    (dds.cdr:parse-encapsulation-header rc)
    (deserialize-fd-abc rc :xcdr2)
    ;; serialize=identity: header once at origin 4, then the FlatData body block-copy (put-octets = replace)
    (let ((ser-per (%fd-measure-bytes
                    "serialize-id" iters
                    (lambda ()
                      (dds.core.buffer:cursor-reset wc)
                      (dds.cdr:make-encapsulation-header wc :plain-cdr2-le)
                      (funcall ser fd wc :xcdr2))))
          ;; deserialize=read-in-place into the loaned target — the 0-alloc path Phase D ZC uses (loaned target =
          ;; the ZC slot); NOT the engine's non-ZC RX path today.
          (loan-per (%fd-measure-bytes
                     "deser-into-loan" iters
                     (lambda ()
                       (dds.core.buffer:cursor-set-position rc 4)
                       (deserialize-into-fd-abc-fd target rc :xcdr2))))
          ;; vtable :deserialize — the function %deserialize-sample funcalls on the engine's NON-ZC RX path.
          ;; It allocates a fresh FlatData buffer per sample (free it to avoid a foreign leak; free-static is a
          ;; foreign release, NOT GC, so it does not perturb bytes-consed). Replicate the engine: parse the encap
          ;; header (positions to 4 AND resets the alignment origin) each iteration.
          (vtable-per (%fd-measure-bytes
                       "vtable-deser" iters
                       (lambda ()
                         (dds.core.buffer:cursor-reset rc)
                         (dds.cdr:parse-encapsulation-header rc)
                         (dds.pal:free-static (dds.core.buffer:octet-buffer-vec (funcall vdes rc :xcdr2))))))
          ;; classic per-field deserialize — the baseline the FlatData vtable deserialize must not regress past.
          (classic-per (%fd-measure-bytes
                        "classic-deser" iters
                        (lambda ()
                          (dds.core.buffer:cursor-reset rc)
                          (dds.cdr:parse-encapsulation-header rc)
                          (deserialize-fd-abc rc :xcdr2)))))
      (format t "~&  fd-mem: TX serialize = ~,4f (0-alloc win); RX non-ZC vtable = ~,4f vs classic = ~,4f; ~
                 literal-0-copy+0-alloc RX deferred beyond v1 (engine-contract change; loaned-target path = ~,4f).~%"
              ser-per vtable-per classic-per loan-per)
      (when sbcl-p
        ;; the two genuine 0-alloc paths: serialize=identity (TX) and the loaned-target inner copy (Phase-D ZC)
        (%check :fd-serialize-zero-alloc (< ser-per 1.0)
                (format nil "serialize-id: ~,4f bytes/sample (expected ~~0, the FlatData TX win)" ser-per))
        (%check :fd-loan-zero-alloc (< loan-per 1.0)
                (format nil "deser-into-loan: ~,4f bytes/sample (expected ~~0, the Phase-D ZC path)" loan-per))
        ;; the engine's non-ZC RX vtable deserialize is NOT 0 (Phase D pools the buffer); guard only that it does
        ;; not REGRESS past the classic per-field decode — it should be modestly better + 0 per-field work.
        (%check :fd-vtable-not-worse-than-classic (<= vtable-per classic-per)
                (format nil "vtable-deser ~,4f must be <= classic-deser ~,4f (regression guard; not 0 until Phase D)"
                        vtable-per classic-per))))
    (dds.pal:free-static (dds.core.buffer:octet-buffer-vec fd))
    (dds.pal:free-static (dds.core.buffer:octet-buffer-vec target))
    (dds.pal:free-static (dds.core.buffer:octet-buffer-vec wbuf))
    (dds.pal:free-static (dds.core.buffer:octet-buffer-vec rxbuf))
    t))

;;;; ---- WP-FLATDATA Phase E1a bench (FR-PF-4, NFR-PERF-7, FR-LANG-7; R6, ADR 0015) ----
;;;; HONEST measurement (FR-LANG-7): the FlatData TX is a genuine 0-alloc identity copy and the loaned-target
;;;; inner RX path is 0-alloc, but the ENGINE-VISIBLE non-ZC RX vtable still allocates one buffer/sample and the
;;;; ZC RX is a SAFE SINGLE COPY out of SHMEM (~830x less than the WP-ZEROCOPY-v1 sink+re-copy) — NOT literal
;;;; 0-copy. No path is reported "~0" unless bytes-consed actually reads ~0. NOT cleared for ship — counsel R6.

(defun* %fd-measure-ns (label iters thunk)
    (function (string (integer 1) function) double-float)
  "Run THUNK ITERS times and print + return its mean wall time in nanoseconds (total elapsed / ITERS — the
   PAL clock is ~us resolution, so a single op reads 0; the per-op figure is the amortised loop time, the same
   method perftest.lisp uses). The time companion to %fd-measure-bytes (DRY)."
  (declare (type function thunk))
  (let ((t0 (dds.pal:monotonic-ns)))
    (dotimes (i iters) (funcall thunk))
    (let ((per (/ (float (max 0 (- (dds.pal:monotonic-ns) t0)) 1.0d0) iters)))
      (format t "~&  fd-ns[~16a]: ~,1f ns/op (~d iters)~%" label per iters)
      per)))

(defun* %fd-bench-row (stream label fd-bytes fd-ns classic-bytes classic-ns note)
    (function (t string real real real real string) t)
  "Emit one markdown comparison row to STREAM: a measured FlatData path (FD-BYTES GC bytes/op, FD-NS ns/op) vs
   its classic counterpart (CLASSIC-BYTES, CLASSIC-NS) with a free-text NOTE. Used by run-bench-flatdata."
  (format stream "~&| ~a | ~,1f | ~,1f | ~,1f | ~,1f | ~a |~%"
          label (float fd-bytes 1.0) (float fd-ns 1.0) (float classic-bytes 1.0) (float classic-ns 1.0) note)
  t)

(defun* %fd-zc-bench-bytes (iters)
    (function ((integer 1)) (values (integer 0) (integer 0)))
  "Measure the WP-FLATDATA-over-ZC RX GC bytes/sample on a standalone in-process ZC pool (the same pool ABI the
   data plane uses): loan ONE slot with an fd-abc-sized payload, then resolve it ITERS times each way — the NEW
   safe single-copy (%zc-resolve-fresh) vs the WP-ZEROCOPY-v1 sink+re-copy (%fd-zc-rx-bytes-v1, DRY) — and
   return (values new-bytes v1-bytes). Pass-returns (0 0) where SHMEM by-name attach is unreliable (Clasp/macOS
   gap, ADR 0013), since the pool's PTHREAD_PROCESS_SHARED mutex needs a usable SHMEM segment."
  (if (not (dds.xport.shmem:shm-attach-by-name-reliable-p))
      (values 0 0)
      (let* ((slots 8)
             (slot-bytes dds.disc:+zerocopy-pool-slot-bytes+)
             (seg-bytes (dds.xport.zerocopy::%zc-bytes slots slot-bytes))
             (mem (dds.pal:alloc-static seg-bytes))
             (sap (dds.pal:static-pointer mem))
             (payload (let ((v (make-array +fd-abc-flatdata-size+ :element-type '(unsigned-byte 8))))
                        (dotimes (i +fd-abc-flatdata-size+ v) (setf (aref v i) (logand i #xff))))))
        (dds.xport.zerocopy::%zc-init sap slots slot-bytes)
        (unwind-protect
             (multiple-value-bind (slot gen)
                 (dds.xport.zerocopy::%zc-loan sap payload 0 (length payload) 1)
               (if (null slot)
                   (values 0 0)
                   (let ((new-bytes (%fd-zc-rx-bytes-new sap slot gen iters))
                         (v1-bytes (%fd-zc-rx-bytes-v1 sap slot gen iters)))
                     (dds.xport.zerocopy::%zc-release sap slot gen)
                     (values new-bytes v1-bytes))))
          (dds.xport.zerocopy::%zc-destroy sap)
          (dds.pal:free-static mem)))))

(defun* %bench-git-head ()
    (function () string)
  "The current short git HEAD (`git rev-parse --short HEAD`), derived AT RUN TIME so a bench report is never
   stamped with a stale SHA; \"unknown\" if git is unavailable / not a work tree (the report stays self-consistent)."
  (handler-case
      (let ((s (string-trim '(#\Space #\Newline #\Return #\Tab)
                            (with-output-to-string (out)
                              (uiop:run-program (list "git" "rev-parse" "--short" "HEAD")
                                                :output out :error-output nil :ignore-error-status t)))))
        (if (and (plusp (length s)) (every (lambda (c) (digit-char-p c 16)) s)) s "unknown"))
    (error () "unknown")))

(defun* %bench-date-string ()
    (function () string)
  "Today's date as YYYY-MM-DD from get-decoded-time, derived AT RUN TIME (no hardcoded date in a bench report)."
  (multiple-value-bind (s m h day month year) (get-decoded-time)
    (declare (ignore s m h))
    (format nil "~4,'0d-~2,'0d-~2,'0d" year month day)))

(defun* %bench-ratio (a b)
    (function (real real) double-float)
  "A/B as a double-float for a bench report, or 0.0d0 when B is 0 (div-by-zero-safe; Clasp bytes-consed=0 gap)."
  (if (zerop b) 0.0d0 (/ (coerce a 'double-float) b)))

(defun* %set-view-from-acquire (view psap idx gen len base)
    (function (dds.types:flatdata-view t (integer 0) (unsigned-byte 32) (integer 0) (integer 0)) dds.types:flatdata-view)
  "WP-FLATDATA-ZC-LOAN (R6, ADR 0017; NOT cleared for ship — pending counsel): in-place-init VIEW from a
   %zc-acquire-for-read result (POOL-SAP/SLOT/GENERATION/PAYLOAD-LEN/PAYLOAD-BASE) — the BASE-OFFSET is
   PAYLOAD-BASE+4 (past the 4-octet encap header, to the XCDR2 body) and LEN is the body length. The DRY core
   the bench RX/CYCLE measurement helpers reuse to recycle one view struct (no per-sample GC alloc; mirrors the
   DCPS %loan-view, sans the per-reader freelist). Returns VIEW."
  (setf (dds.types:flatdata-view-slot-sap view) psap
        (dds.types:flatdata-view-base-offset view) (+ base 4)
        (dds.types:flatdata-view-len view) (max 0 (- len 4))
        (dds.types:flatdata-view-pool-sap view) psap
        (dds.types:flatdata-view-slot-index view) idx
        (dds.types:flatdata-view-generation view) gen)
  view)

(defun* run-bench-flatdata (&key (file nil) (iters 200000) (zc-iters 100000))
    (function (&key (:file (or null string pathname)) (:iters (integer 1)) (:zc-iters (integer 1))) t)
  "WP-FLATDATA Phase E1a bench (FR-PF-4, NFR-PERF-7, FR-LANG-7; R6, ADR 0015 — NOT cleared for ship, counsel
   R6). HONEST before/after numbers for a FINAL fixed-size FlatData type (fd-abc: u8/u32/u64, 20-octet payload)
   vs the classic per-field codec for the SAME type, over the EXACT functions the engine funcalls. Prints a
   markdown report to *standard-output*; when FILE is given, ALSO writes it there (broadcast — captured by
   make bench-flatdata). Each row is GC bytes/op (dds.pal:bytes-consed delta, NFR-PERF-8 oracle; SBCL-exact,
   Clasp=0 by NFR-PORT gap) + ns/op (amortised over ITERS; the PAL clock is ~us so a single op reads 0). The
   measured paths (DRY — reuses %fd-measure-bytes + the ZC measurement helpers): TX serialize (FlatData
   identity vs classic per-field); RX deserialize (the engine-visible vtable deserialize-<name>-fd vs classic
   deserialize-<name>, AND the loaned-target 0-alloc inner path deserialize-into-<name>-fd); the Offset
   accessors (get/set, 0-alloc); and FlatData-over-ZC RX (the safe single-copy %zc-resolve-fresh vs the
   WP-ZEROCOPY-v1 sink+re-copy, ~830x measured). NO OVERCLAIM: only TX serialize + the loaned-target inner path are
   genuinely ~0; the engine non-ZC RX vtable allocates one buffer/sample and the ZC RX is a SAFE SINGLE COPY
   out of SHMEM, NOT literal 0-copy (a Lisp octet-buffer cannot wrap a raw foreign SAP; ZC delivery is into an
   async store read off-thread with no slot-aware release hook — literal-0-copy RX is DEFERRED, see ADR 0015
   Phase-D outcome). TX also still has the app->slot copy on the ZC path (loan-write API follow-up)."
  (let* ((ts (dds.types:find-type-support "fd-abc"))
         (fd (make-fd-abc-flatdata))
         (target (make-fd-abc-flatdata))
         (wbuf (dds.core.buffer:make-octet-buffer (+ +fd-abc-flatdata-size+ 8)))
         (wc (dds.core.buffer:cursor wbuf :endianness :little))
         (rxbuf (dds.core.buffer:make-octet-buffer +fd-abc-flatdata-size+))
         (rc (dds.core.buffer:cursor rxbuf :endianness :little))
         (ser (dds.types:type-support-serialize ts))
         (vdes (dds.types:type-support-deserialize ts))
         (classic-ser #'serialize-fd-abc)
         (sbcl-p (eq (dds.pal:pal-impl-name) :sbcl)))
    (declare (type function ser vdes classic-ser))
    (setf (fd-abc-a-fd fd) 200 (fd-abc-b-fd fd) 3000000000 (fd-abc-c-fd fd) 12345678901234567890)
    (replace (dds.core.buffer:octet-buffer-vec rxbuf) (dds.dcps::%serialize-sample ts fd))
    (let ((cl-struct (make-fd-abc :a 200 :b 3000000000 :c 12345678901234567890)))
      (flet ((emit (stream)
               (format stream "~&# WP-FLATDATA — ser/deser cost + ZC-RX vs classic (honest) (FR-PF-4, NFR-PERF-7, FR-LANG-7)~%~%")
               (format stream "**NOT cleared for ship — pending counsel (R6); see ADR 0015.** FlatData + Zero-Copy are R6 patent-gated.~%~%")
               (format stream "Phase E1a of WP-FLATDATA: quantify the cost of a FINAL fixed-size FlatData type (`fd-abc`: `u8`/`u32`/`u64`, 20-octet payload) against the CLASSIC per-field codec for the SAME type, over the EXACT functions the engine funcalls. Per the operating contract no hot-path change lands without a before/after measurement; this is that measurement. Generated by `dds.tests:run-bench-flatdata` (entry: `make bench-flatdata`).~%~%")
               (format stream "## Environment~%~%")
               (format stream "| field | value |~%|-------|-------|~%")
               (format stream "| host | ~a (~a) |~%" (machine-instance) (machine-version))
               (format stream "| os | ~a ~a ~a |~%" (software-type) (software-version) (machine-type))
               (format stream "| impl | ~a ~a |~%" (lisp-implementation-type) (lisp-implementation-version))
               (format stream "| HEAD | ~a |~%" (%bench-git-head))
               (format stream "| date | ~a |~%" (%bench-date-string))
               (format stream "| FlatData type | `fd-abc` (`u8`,`u32`,`u64`) -> `+fd-abc-flatdata-size+` = ~d octets (4 encap + 16 body) |~%" +fd-abc-flatdata-size+)
               (format stream "| iters (ser/deser/accessor) | ~d |~%" iters)
               (format stream "| iters (ZC-RX) | ~d |~%" zc-iters)
               (format stream "~%## Method~%~%")
               (format stream "Each path is measured over the FUNCTION the engine actually funcalls (the type-support vtable slot), not a hand-rolled stand-in. GC bytes/op is the `dds.pal:bytes-consed` delta over the loop (NFR-PERF-8 oracle; SBCL-exact, Clasp reports 0 — a documented NFR-PORT gap). ns/op is total elapsed (`dds.pal:monotonic-ns`, ~~microsecond resolution) divided by the iteration count: a single op reads 0 on this clock, so the per-op figure is the amortised loop time (the same method `perftest.lisp` uses) and is a coarse RELATIVE indicator, not an absolute single-op latency. The TX serialize loop resets the write cursor + re-writes the encap header each iteration (as `%serialize-sample` does); the RX loops re-parse the encap header each iteration (as `%deserialize-sample` does). Reusable write/RX buffers are PAL-static and freed at the end.~%~%")
               (format stream "## Serialize / deserialize / accessor cost — FlatData vs classic (same `fd-abc`)~%~%")
               (format stream "| path | FD bytes/op | FD ns/op | classic bytes/op | classic ns/op | note |~%")
               (format stream "|------|-------------|----------|------------------|---------------|------|~%"))
             (rows (stream new-bytes v1-bytes)
               (let* ((ser-bytes (%fd-measure-bytes "ser-id" iters
                                   (lambda () (dds.core.buffer:cursor-reset wc)
                                     (dds.cdr:make-encapsulation-header wc :plain-cdr2-le)
                                     (funcall ser fd wc :xcdr2))))
                      (ser-ns (%fd-measure-ns "ser-id" iters
                                (lambda () (dds.core.buffer:cursor-reset wc)
                                  (dds.cdr:make-encapsulation-header wc :plain-cdr2-le)
                                  (funcall ser fd wc :xcdr2))))
                      (cser-bytes (%fd-measure-bytes "ser-classic" iters
                                    (lambda () (dds.core.buffer:cursor-reset wc)
                                      (dds.cdr:make-encapsulation-header wc :plain-cdr2-le)
                                      (funcall classic-ser cl-struct wc :xcdr2))))
                      (cser-ns (%fd-measure-ns "ser-classic" iters
                                 (lambda () (dds.core.buffer:cursor-reset wc)
                                   (dds.cdr:make-encapsulation-header wc :plain-cdr2-le)
                                   (funcall classic-ser cl-struct wc :xcdr2))))
                      (vdes-bytes (%fd-measure-bytes "vtable-deser" iters
                                    (lambda () (dds.core.buffer:cursor-reset rc)
                                      (dds.cdr:parse-encapsulation-header rc)
                                      (dds.pal:free-static (dds.core.buffer:octet-buffer-vec (funcall vdes rc :xcdr2))))))
                      (vdes-ns (%fd-measure-ns "vtable-deser" iters
                                 (lambda () (dds.core.buffer:cursor-reset rc)
                                   (dds.cdr:parse-encapsulation-header rc)
                                   (dds.pal:free-static (dds.core.buffer:octet-buffer-vec (funcall vdes rc :xcdr2))))))
                      (cdes-bytes (%fd-measure-bytes "classic-deser" iters
                                    (lambda () (dds.core.buffer:cursor-reset rc)
                                      (dds.cdr:parse-encapsulation-header rc)
                                      (deserialize-fd-abc rc :xcdr2))))
                      (cdes-ns (%fd-measure-ns "classic-deser" iters
                                 (lambda () (dds.core.buffer:cursor-reset rc)
                                   (dds.cdr:parse-encapsulation-header rc)
                                   (deserialize-fd-abc rc :xcdr2))))
                      (loan-bytes (%fd-measure-bytes "deser-into-loan" iters
                                    (lambda () (dds.core.buffer:cursor-set-position rc 4)
                                      (deserialize-into-fd-abc-fd target rc :xcdr2))))
                      (loan-ns (%fd-measure-ns "deser-into-loan" iters
                                 (lambda () (dds.core.buffer:cursor-set-position rc 4)
                                   (deserialize-into-fd-abc-fd target rc :xcdr2))))
                      ;; fixnum-fitting fields (a:u8, b:u32) — the GENUINE read/write-in-place 0-alloc property
                      (get-bytes (%fd-measure-bytes "accessor-get-fx" iters
                                   (lambda () (fd-abc-a-fd fd) (fd-abc-b-fd fd))))
                      (get-ns (%fd-measure-ns "accessor-get-fx" iters
                                (lambda () (fd-abc-a-fd fd) (fd-abc-b-fd fd))))
                      (set-bytes (%fd-measure-bytes "accessor-set-fx" iters
                                   (lambda () (setf (fd-abc-a-fd fd) 200 (fd-abc-b-fd fd) 3000000000))))
                      (set-ns (%fd-measure-ns "accessor-set-fx" iters
                                (lambda () (setf (fd-abc-a-fd fd) 200 (fd-abc-b-fd fd) 3000000000))))
                      ;; u64 c > most-positive-fixnum: read-in-place is 0-copy but returning the integer BOXES a bignum (a Lisp cost, not FlatData)
                      (get64-bytes (%fd-measure-bytes "accessor-get-u64" iters (lambda () (fd-abc-c-fd fd))))
                      (get64-ns (%fd-measure-ns "accessor-get-u64" iters (lambda () (fd-abc-c-fd fd)))))
                 (%fd-bench-row stream "**TX serialize** (engine `:serialize`)" ser-bytes ser-ns cser-bytes cser-ns
                                "FlatData = block-copy identity, 0 per-field encode (the TX win)")
                 (%fd-bench-row stream "**RX deserialize** (engine non-ZC `:deserialize`)" vdes-bytes vdes-ns cdes-bytes cdes-ns
                                "FlatData allocs 1 buffer/sample; win = modest GC-heap + 0 per-field decode")
                 (%fd-bench-row stream "**RX deser into loaned target** (0-alloc inner)" loan-bytes loan-ns cdes-bytes cdes-ns
                                "the path Phase-D ZC uses (loaned target = the slot); 0-alloc")
                 (%fd-bench-row stream "**Offset accessor GET** (`a`:u8 + `b`:u32, fixnum)" get-bytes get-ns 0 0
                                "read in place, 0-alloc (no classic equivalent — struct slots)")
                 (%fd-bench-row stream "**Offset accessor SET** (`a`:u8 + `b`:u32, fixnum)" set-bytes set-ns 0 0
                                "write in place, 0-alloc")
                 (%fd-bench-row stream "**Offset accessor GET** (`c`:u64 > fixnum)" get64-bytes get64-ns 0 0
                                "read in place IS 0-copy, but returning a >fixnum u64 BOXES a bignum (a Lisp cost, not FlatData)")
                 (format stream "~%## FlatData over Zero-Copy — RX (safe single copy out of SHMEM, NOT literal-0-copy)~%~%")
                 (if (and (zerop new-bytes) (zerop v1-bytes))
                     (format stream "(SHMEM by-name attach unreliable on this platform — ZC-RX bench skipped; Clasp/macOS gap, ADR 0013)~%~%")
                     (progn
                       (format stream "| RX path | GC bytes/sample | vs v1 |~%|---------|-----------------|-------|~%")
                       (format stream "| WP-FLATDATA-over-ZC single-copy (`%zc-resolve-fresh`) | ~d | 1x |~%" new-bytes)
                       (format stream "| WP-ZEROCOPY-v1 sink(65536)+re-copy | ~d | ~dx |~%~%"
                               v1-bytes (if (plusp new-bytes) (round v1-bytes new-bytes) 0))
                       (format stream "The FlatData-over-ZC RX allocates ONE exact-length (~d-octet) owned vector, read in place from the SHMEM slot under a single mutex hold — no 65536-byte scratch sink, no second copy: a **~dx** reduction in RX GC bytes/sample vs WP-ZEROCOPY-v1.~%~%"
                               +fd-abc-flatdata-size+ (if (plusp new-bytes) (round v1-bytes new-bytes) 0))))
                 (format stream "## Honest framing (FR-LANG-7) — no path is claimed ~~0 unless it measures ~~0~%~%")
                 (format stream "- **TX serialize** and **RX-into-loaned-target** are the only GENUINELY ~~0-alloc paths (block-copy identity / copy into a caller-owned buffer; the loaned buffer IS the ZC slot on the Phase-D path).~%")
                 (format stream "- The **engine-visible non-ZC RX vtable** (`deserialize-<name>-fd`) allocates ONE FlatData buffer per sample (~,1f bytes/op here) — modestly below the classic per-field decode (~,1f) with 0 per-field work, NOT zero. The classic vtable likewise allocates a fresh sample per call.~%" vdes-bytes cdes-bytes)
                 (format stream "- The **FlatData-over-ZC RX is a SAFE SINGLE COPY out of shared memory** (~~~dx less than WP-ZEROCOPY-v1's sink+re-copy — ~~3 orders of magnitude), **NOT literal-0-copy**. A Lisp octet-buffer cannot wrap a raw foreign SAP, and ZC delivery is into an async store read on another thread with no slot-aware release hook, so a literal-0-copy SHMEM VIEW would be a cross-process use-after-free. **TX still has the one app->slot copy** (a loan-write API is the follow-up). **Literal-0-copy RX is DEFERRED** — it needs SAP-backed accessors plus a DCPS-level refcount-spanning ZC read path (ADR 0015, Phase-D outcome).~%~%"
                         (if (plusp new-bytes) (round v1-bytes new-bytes) 830))
                 (format stream "Method: ~d iterations (~d for ZC-RX); GC bytes/op = `dds.pal:bytes-consed` delta (SBCL-exact, Clasp=0); ns/op = `dds.pal:monotonic-ns` total/iters (~~us clock, amortised). Impl: ~a ~a on ~a.~%"
                         iters zc-iters (lisp-implementation-type) (lisp-implementation-version) (machine-instance))
                 (when sbcl-p
                   ;; honest regression guards: the two genuine 0-alloc paths must be ~0; the vtable must not regress past classic
                   (assert (< ser-bytes 1.0) () "bench: FlatData TX serialize must be ~0 GC bytes/op, got ~,4f" ser-bytes)
                   (assert (< loan-bytes 1.0) () "bench: deser-into-loaned-target must be ~0 GC bytes/op, got ~,4f" loan-bytes)
                   (assert (< get-bytes 1.0) () "bench: Offset accessor GET must be 0-alloc, got ~,4f" get-bytes)
                   (assert (< set-bytes 1.0) () "bench: Offset accessor SET must be 0-alloc, got ~,4f" set-bytes)
                   (assert (<= vdes-bytes cdes-bytes) () "bench: vtable RX (~,4f) must not regress past classic (~,4f)" vdes-bytes cdes-bytes)))))
        ;; warm every measured path once (engine writes the header then :serialize for the body, origin 4)
        (dds.cdr:make-encapsulation-header wc :plain-cdr2-le) (funcall ser fd wc :xcdr2)
        (dds.core.buffer:cursor-set-position rc 4) (deserialize-into-fd-abc-fd target rc :xcdr2)
        (multiple-value-bind (new-bytes v1-bytes) (%fd-zc-bench-bytes zc-iters)
          (emit *standard-output*)
          (rows *standard-output* new-bytes v1-bytes)
          (when file
            (with-open-file (s file :direction :output :if-exists :supersede :if-does-not-exist :create)
              (emit s)
              ;; re-run the measured loops into the file stream (cheap vs a long bench; keeps the file self-contained)
              (rows s new-bytes v1-bytes))
            (format t "~&  wrote ~a~%" file)))))
    (dds.pal:free-static (dds.core.buffer:octet-buffer-vec fd))
    (dds.pal:free-static (dds.core.buffer:octet-buffer-vec target))
    (dds.pal:free-static (dds.core.buffer:octet-buffer-vec wbuf))
    (dds.pal:free-static (dds.core.buffer:octet-buffer-vec rxbuf))
    t))

(defun* %fd-zc-loan-cycle-bytes (sap payload iters)
    (function (t (simple-array (unsigned-byte 8) (*)) (integer 1)) (integer 0))
  "WP-FLATDATA-ZC-LOAN (R6, ADR 0017; NOT cleared for ship — pending counsel): mean GC bytes/sample of the FULL
   explicit loan/return CYCLE over ITERS calls — %zc-acquire-for-read (the loan) + a field read off the SAP +
   %zc-release (the return) — on a slot freshly %zc-loan'd each iteration. The honest cost the loan API ADDS over
   a bare read: the explicit acquire + release (each takes the pool mutex) + the app's return obligation. SBCL
   bytes-consed exact; Clasp reads 0 (NFR-PORT gap)."
  (let ((view (dds.types:make-flatdata-view))
        (before (dds.pal:bytes-consed)))
    (dotimes (i iters)
      (multiple-value-bind (slot gen) (dds.xport.zerocopy::%zc-loan sap payload 0 (length payload) 1)
        (when slot
          (multiple-value-bind (psap idx g len base) (dds.xport.zerocopy::%zc-acquire-for-read sap slot gen)
            (when psap
              (%set-view-from-acquire view psap idx g len base)
              (fd-abc-a-fd view)                          ; read a field off the slot SAP (0-copy)
              (dds.xport.zerocopy::%zc-release psap idx g)))))) ; return-loan
    (floor (max 0 (- (dds.pal:bytes-consed) before)) iters)))

(defun* run-bench-flatdata-zc-loan (&key (file nil) (iters 100000))
    (function (&key (:file (or null string pathname)) (:iters (integer 1))) t)
  "WP-FLATDATA-ZC-LOAN Phase F2 bench (FR-PF-3/4, NFR-PERF-7, FR-LANG-7; R6, ADR 0017 — NOT cleared for ship,
   counsel R6). The literal-0-copy RX headline measurement: the RX GC bytes/sample PROGRESSION across the three
   FlatData-over-Zero-Copy RX strategies for a FINAL fixed-size FlatData type (fd-abc, 20-octet payload), over
   the EXACT pool primitives the loan path funcalls (DRY — reuses %fd-zc-loan-rx-bytes + %fd-zc-rx-bytes-new +
   %fd-zc-rx-bytes-v1 + %fd-zc-loan-cycle-bytes + the bench env helpers). Prints a markdown report to
   *standard-output*; when FILE is given, ALSO writes it there (broadcast — captured by make
   bench-flatdata-zc-loan). HONEST (FR-LANG-7), NO OVERCLAIM: the literal-0-copy loan RX eliminates the
   per-sample OWNED DELIVERY VECTOR (the alloc win); its residue is the bare pool-mutex acquire (a fixed,
   payload-independent CFFI cost the v1 single-copy ALSO pays), and the loan API ADDS an explicit
   %zc-acquire-for-read + %zc-release + the app's return-loan OBLIGATION over a copy-and-forget read — a real
   cost, stated plainly. SBCL only (ZC + foreign SAP reads, ADR 0013); on Clasp the SHMEM by-name attach is
   unreliable so the bench pass-skips. NOT cleared for ship — pending counsel (R6)."
  (let* ((fd (make-fd-abc-flatdata))
         (sbcl-p (eq (dds.pal:pal-impl-name) :sbcl))
         (have-shmem (dds.xport.shmem:shm-attach-by-name-reliable-p)))
    (setf (fd-abc-a-fd fd) 200 (fd-abc-b-fd fd) 3000000000 (fd-abc-c-fd fd) 12345678901234567890)
    (let ((payload (subseq (dds.core.buffer:octet-buffer-vec fd) 0 +fd-abc-flatdata-size+)))
      (multiple-value-bind (loan-bytes new-bytes v1-bytes cycle-bytes)
          (if (not have-shmem)
              (values 0 0 0 0)
              (let* ((mem (dds.pal:alloc-static (dds.xport.zerocopy::%zc-bytes 2 +fd-abc-flatdata-size+)))
                     (sap (dds.pal:static-pointer mem)))
                (dds.xport.zerocopy::%zc-init sap 2 +fd-abc-flatdata-size+)
                (unwind-protect
                     (multiple-value-bind (slot gen) (dds.xport.zerocopy::%zc-loan sap payload 0 +fd-abc-flatdata-size+ 1)
                       (let ((lb (%fd-zc-loan-rx-bytes sap slot gen iters))    ; force a fixed eval order, all four kept
                             (nb (%fd-zc-rx-bytes-new sap slot gen iters))
                             (vb (%fd-zc-rx-bytes-v1 sap slot gen iters))
                             (cb (%fd-zc-loan-cycle-bytes sap payload iters)))
                         (dds.xport.zerocopy::%zc-release sap slot gen)         ; balance the measurement loan
                         (values lb nb vb cb)))
                  (dds.xport.zerocopy::%zc-destroy sap)
                  (dds.pal:free-static mem))))
        (flet ((emit (stream)
                 (format stream "~&# WP-FLATDATA-ZC-LOAN — literal-0-copy RX (FlatData over Zero-Copy via loan/return_loan) (FR-PF-3/4, NFR-PERF-7, FR-LANG-7)~%~%")
                 (format stream "**NOT cleared for ship — pending counsel (R6); see ADR 0017.** `dds.disc:*zerocopy-enabled*` is default OFF and the per-type `:flatdata t` opt-in is off by default; this report exercises the loan path with both armed inside the bench only.~%~%")
                 (format stream "Phase F2 of WP-FLATDATA-ZC-LOAN: the headline literal-0-copy RX measurement. A FlatData reader on the same host reads fields **directly from the writer's SHMEM pool slot** via an explicit `take-loaned`/`return-loan` read API, eliminating the per-sample OWNED DELIVERY VECTOR the WP-ZEROCOPY+FlatData v1 single-copy resolve still allocates. Measured over the EXACT pool primitives the loan path funcalls (`%zc-acquire-for-read` / the SAP-mode Offset accessor / `%zc-release`). Per the operating contract no hot-path change lands without a before/after measurement; this is that measurement. Generated by `dds.tests:run-bench-flatdata-zc-loan` (entry: `make bench-flatdata-zc-loan`).~%~%")
                 (format stream "## Environment~%~%| field | value |~%|-------|-------|~%")
                 (format stream "| host | ~a (~a) |~%" (machine-instance) (machine-version))
                 (format stream "| os | ~a ~a ~a |~%" (software-type) (software-version) (machine-type))
                 (format stream "| impl | ~a ~a |~%" (lisp-implementation-type) (lisp-implementation-version))
                 (format stream "| HEAD | ~a |~%" (%bench-git-head))
                 (format stream "| date | ~a |~%" (%bench-date-string))
                 (format stream "| FlatData type | `fd-abc` (`u8`,`u32`,`u64`) -> `+fd-abc-flatdata-size+` = ~d octets (4 encap + 16 body) |~%" +fd-abc-flatdata-size+)
                 (format stream "| pool slot bytes | `+zerocopy-pool-slot-bytes+` = ~d (the WP-ZEROCOPY-v1 sink size) |~%" dds.disc:+zerocopy-pool-slot-bytes+)
                 (format stream "| iters | ~d |~%" iters)
                 (format stream "~%## Method~%~%")
                 (format stream "Each RX strategy resolves ONE loaned slot `iters` times; the resolve does NOT touch the slot refcount, so a single loaned slot serves every iteration. GC bytes/sample is the `dds.pal:bytes-consed` delta over the loop divided by `iters` (NFR-PERF-8 oracle; SBCL-exact, Clasp reports 0 — a documented NFR-PORT gap). The literal-0-copy loan RX reuses one `flatdata-view` struct (the per-reader view recycling the DCPS loan registry does) and reads a field straight off the slot SAP. The loan/return CYCLE row additionally `%zc-loan`s + `%zc-release`s each iteration to price the explicit loan + return obligation. NOTE: this is the per-sample RX allocation, not end-to-end latency.~%~%")
                 (if (not have-shmem)
                     (format stream "(SHMEM by-name attach unreliable on this platform — the ZC loan bench pass-skipped; Clasp/macOS gap, ADR 0013)~%~%")
                     (progn
                       (format stream "## RX GC bytes/sample — the literal-0-copy progression~%~%")
                       (format stream "| RX strategy | GC bytes/sample | vs literal-0-copy loan | what it allocates |~%")
                       (format stream "|-------------|-----------------|------------------------|-------------------|~%")
                       (format stream "| **literal-0-copy loan** (`%zc-acquire-for-read` + SAP read; `take-loaned`) | **~d** | 1x | NO owned vector — only the pool mutex acquire (fixed, payload-independent) |~%" loan-bytes)
                       (format stream "| FlatData+ZC v1 single-copy (`%zc-resolve-fresh`) | ~d | ~,1fx | the mutex + one exact-length (~d-octet) OWNED vector |~%"
                               new-bytes (%bench-ratio new-bytes loan-bytes) +fd-abc-flatdata-size+)
                       (format stream "| WP-ZEROCOPY-v1 sink+re-copy | ~d | ~,1fx | the mutex + a ~d-octet sink + a re-copy |~%~%"
                               v1-bytes (%bench-ratio v1-bytes loan-bytes) dds.disc:+zerocopy-pool-slot-bytes+)
                       (format stream "The literal-0-copy loan RX allocates **~d** GC bytes/sample vs the FlatData+ZC v1 single-copy's **~d** and the WP-ZEROCOPY-v1 sink's **~d** — the progression `~d -> ~d -> ~d`. The win is the **eliminated per-sample owned delivery vector** (the ~~~d-octet vector at the single-copy step is gone): the reader reads fields straight off the writer's slot SAP. The residual ~d B is the pool-mutex acquire/release — a FIXED, payload-independent CFFI cost the v1 single-copy ALSO pays on top of its owned vector.~%~%"
                               loan-bytes new-bytes v1-bytes v1-bytes new-bytes loan-bytes (max 0 (- new-bytes loan-bytes)) loan-bytes)
                       (format stream "## The loan / return per-sample overhead (FR-LANG-7 — the honest cost)~%~%")
                       (format stream "| operation | GC bytes/sample |~%|-----------|-----------------|~%")
                       (format stream "| loan acquire + read (RX only) | ~d |~%" loan-bytes)
                       (format stream "| full loan + return CYCLE (`%zc-loan` + acquire + read + `%zc-release`) | ~d |~%~%" cycle-bytes)
                       (format stream "Literal-0-copy RX is the allocation win, but it is **not free**: the loan API adds an explicit `%zc-acquire-for-read` (the loan) and `%zc-release` (the return) — each taking the pool mutex — plus the app's **explicit `return-loan` obligation** (a leaked loan pins a slot until the writer's pool gracefully falls back to non-ZC). The full loan+return cycle costs **~d** GC bytes/sample here (the per-sample mutex traffic of loan + acquire + release), vs the **~d** B the read-only literal-0-copy RX pays. No `0-cost`/`free` claim: the RX *allocation* is eliminated; the loan/return *calls* and the return *obligation* are real.~%~%"
                               cycle-bytes loan-bytes)))
                 (format stream "Method: ~d iterations; GC bytes/sample = `dds.pal:bytes-consed` delta / iters (SBCL-exact, Clasp=0). Cross-process FlatData-over-ZC is proven byte-exact by `make zc-xproc` (the 16-byte reference resolves across two OS processes; literal-0-copy is a LOCAL read optimization — the wire is byte-identical). Impl: ~a ~a on ~a.~%"
                         iters (lisp-implementation-type) (lisp-implementation-version) (machine-instance))
                 (when (and sbcl-p have-shmem)
                   (assert (< loan-bytes new-bytes) () "bench: the literal-0-copy loan RX (~d) must allocate strictly less than the v1 single-copy (~d) — the owned vector eliminated" loan-bytes new-bytes)
                   (assert (<= loan-bytes 64) () "bench: the literal-0-copy loan RX (~d) must be a small fixed mutex overhead, not a per-sample owned vector" loan-bytes)
                   (assert (< loan-bytes v1-bytes) () "bench: the literal-0-copy loan RX (~d) must allocate far less than the WP-ZEROCOPY-v1 sink (~d)" loan-bytes v1-bytes))))
          (emit *standard-output*)
          (when file
            (with-open-file (s file :direction :output :if-exists :supersede :if-does-not-exist :create)
              (emit s))
            (format t "~&  wrote ~a~%" file)))))
    (dds.pal:free-static (dds.core.buffer:octet-buffer-vec fd)))
  t)

(defun* %fd-zc-loan-scan-ns (slots payload iters)
    (function ((integer 1) (simple-array (unsigned-byte 8) (*)) (integer 1)) double-float)
  "WP-ZC-LOAN-LOCKFREE Phase C (R6, ADR 0018; NOT cleared for ship — pending counsel): mean ns/loan of the
   WRITER's %zc-loan over a pool of SLOTS slots, ITERS times. Each iteration %zc-loan SCANS all refcount==0
   slots for the lowest-pubseq one (the freelist was dropped — the loan is O(slots)), then %zc-release returns
   it to refcount==0 so the next loan re-scans the full pool — so the timing reflects the worst case (every
   slot a reclaim candidate). The honest WRITER-SIDE cost the 0-alloc reader RX trades for: it RISES with
   SLOTS (the O(slots) sensitivity). monotonic-ns total/iters (~us clock, amortised, the same method
   perftest.lisp uses); SBCL. Pass-returns 0.0d0 where SHMEM by-name attach is unreliable (Clasp/macOS gap,
   ADR 0013), since the pool's PTHREAD_PROCESS_SHARED mutex needs a usable SHMEM segment."
  (if (not (dds.xport.shmem:shm-attach-by-name-reliable-p))
      0.0d0
      (let* ((slot-bytes +fd-abc-flatdata-size+)
             (mem (dds.pal:alloc-static (dds.xport.zerocopy::%zc-bytes slots slot-bytes)))
             (sap (dds.pal:static-pointer mem)))
        (dds.xport.zerocopy::%zc-init sap slots slot-bytes)
        (unwind-protect
             (let ((t0 (dds.pal:monotonic-ns)))
               (dotimes (i iters)
                 (multiple-value-bind (slot gen) (dds.xport.zerocopy::%zc-loan sap payload 0 (length payload) 1)
                   (when slot (dds.xport.zerocopy::%zc-release sap slot gen)))) ; return to refcount==0 -> next loan re-scans
               (/ (float (max 0 (- (dds.pal:monotonic-ns) t0)) 1.0d0) iters))
          (dds.xport.zerocopy::%zc-destroy sap)
          (dds.pal:free-static mem)))))

(defun* run-bench-zc-loan-lockfree (&key (file nil) (iters 100000) (scan-iters 200000)
                                         (scan-slots '(2 8 32 128)))
    (function (&key (:file (or null string pathname)) (:iters (integer 1)) (:scan-iters (integer 1))
                    (:scan-slots list)) t)
  "WP-ZC-LOAN-LOCKFREE Phase C bench (NFR-PERF-7, FR-LANG-7; R6, ADR 0018 — NOT cleared for ship, counsel R6).
   The HONEST two-sided measurement of the lock-free 0-alloc loaned RX. (1) THE HEADLINE: the loaned RX
   per-sample GC-bytes-consed is now LITERAL ~0 (the lock-free %zc-acquire-for-read + %zc-release) — the full
   RX progression 65552 (ZC-v1 sink) -> 79 (FlatData+ZC v1 single-copy) -> 31 (the prior mutex'd loan,
   WP-FLATDATA-ZC-LOAN/ADR 0017) -> 0 (this WP, lock-free). The 0/79/65552 rows are MEASURED live over the
   exact pool primitives (DRY — reuses %fd-zc-loan-rx-bytes + %fd-zc-rx-bytes-new + %fd-zc-rx-bytes-v1 +
   %fd-zc-loan-cycle-bytes + the bench env helpers); the 31 is the documented prior-art figure from ADR 0017's
   report (the mutex it measured is GONE, so it is not re-measurable here — it is the before-this-WP baseline,
   stated for the progression). (2) THE WRITER COST (the honest tradeoff): the loan went from O(1) freelist-pop
   to an O(slots) refcount==0 scan; %fd-zc-loan-scan-ns benches %zc-loan at several pool sizes to show the
   O(slots) sensitivity. NO `0-cost`/`free` claim: the reader RX is 0-alloc (the win); the WRITER pays a small
   bounded scan (writer-side, amortized — a lock-free freelist to restore O(1) is a noted follow-up). Prints a
   markdown report to *standard-output*; when FILE is given ALSO writes it there (broadcast — captured by make
   bench-zc-loan-lockfree). SBCL only (ZC + foreign-SAP atomics, ADR 0013); on Clasp the SHMEM by-name attach
   is unreliable so the bench pass-skips. NOT cleared for ship — pending counsel (R6)."
  (let* ((fd (make-fd-abc-flatdata))
         (sbcl-p (eq (dds.pal:pal-impl-name) :sbcl))
         (have-shmem (dds.xport.shmem:shm-attach-by-name-reliable-p)))
    (setf (fd-abc-a-fd fd) 200 (fd-abc-b-fd fd) 3000000000 (fd-abc-c-fd fd) 12345678901234567890)
    (let ((payload (subseq (dds.core.buffer:octet-buffer-vec fd) 0 +fd-abc-flatdata-size+)))
      (multiple-value-bind (loan-bytes new-bytes v1-bytes cycle-bytes)
          (if (not have-shmem)
              (values 0 0 0 0)
              (let* ((mem (dds.pal:alloc-static (dds.xport.zerocopy::%zc-bytes 2 +fd-abc-flatdata-size+)))
                     (sap (dds.pal:static-pointer mem)))
                (dds.xport.zerocopy::%zc-init sap 2 +fd-abc-flatdata-size+)
                (unwind-protect
                     (multiple-value-bind (slot gen) (dds.xport.zerocopy::%zc-loan sap payload 0 +fd-abc-flatdata-size+ 1)
                       (let ((lb (%fd-zc-loan-rx-bytes sap slot gen iters))    ; force a fixed eval order, all four kept
                             (nb (%fd-zc-rx-bytes-new sap slot gen iters))
                             (vb (%fd-zc-rx-bytes-v1 sap slot gen iters))
                             (cb (%fd-zc-loan-cycle-bytes sap payload iters)))
                         (dds.xport.zerocopy::%zc-release sap slot gen)         ; balance the measurement loan
                         (values lb nb vb cb)))
                  (dds.xport.zerocopy::%zc-destroy sap)
                  (dds.pal:free-static mem))))
        (let ((scan-rows (if (not have-shmem)
                             nil
                             (mapcar (lambda (n) (cons n (%fd-zc-loan-scan-ns n payload scan-iters))) scan-slots))))
          (flet ((emit (stream)
                   (format stream "~&# WP-ZC-LOAN-LOCKFREE — lock-free 0-alloc loaned RX (FlatData over Zero-Copy) (NFR-PERF-7, FR-LANG-7, R6)~%~%")
                   (format stream "**NOT cleared for ship — pending counsel (R6); see ADR 0018.** `dds.disc:*zerocopy-enabled*` is default OFF and the per-type `:flatdata t` opt-in is off by default; this report exercises the lock-free loan path with both armed inside the bench only.~%~%")
                   (format stream "Phase C of WP-ZC-LOAN-LOCKFREE: the headline 0-alloc loaned RX measurement + the honest writer tradeoff. The reader's loan acquire (`%zc-acquire-for-read`) and return (`%zc-release`) are now LOCK-FREE — a generation acquire-load + a `dds.pal:fence :acquire` on acquire, and a direct `cas-sap-u32` refcount decrement on release — so the per-sample loaned RX (acquire + read + return) allocates **literal 0 GC-heap bytes** and copies 0 bytes. The price: the writer's `%zc-loan` lost its O(1) freelist-pop (the freelist was dropped — a lock-free release cannot maintain it without a second CAS) and now does an O(slots) `refcount==0` scan. Both sides are measured below over the EXACT pool primitives the loan path funcalls. Per the operating contract no hot-path change lands without a before/after measurement; this is that measurement. Generated by `dds.tests:run-bench-zc-loan-lockfree` (entry: `make bench-zc-loan-lockfree`).~%~%")
                   (format stream "## Environment~%~%| field | value |~%|-------|-------|~%")
                   (format stream "| host | ~a (~a) |~%" (machine-instance) (machine-version))
                   (format stream "| os | ~a ~a ~a |~%" (software-type) (software-version) (machine-type))
                   (format stream "| impl | ~a ~a |~%" (lisp-implementation-type) (lisp-implementation-version))
                   (format stream "| HEAD | ~a |~%" (%bench-git-head))
                   (format stream "| date | ~a |~%" (%bench-date-string))
                   (format stream "| FlatData type | `fd-abc` (`u8`,`u32`,`u64`) -> `+fd-abc-flatdata-size+` = ~d octets (4 encap + 16 body) |~%" +fd-abc-flatdata-size+)
                   (format stream "| pool slot bytes | `+zerocopy-pool-slot-bytes+` = ~d (the WP-ZEROCOPY-v1 sink size) |~%" dds.disc:+zerocopy-pool-slot-bytes+)
                   (format stream "| RX iters | ~d |~%" iters)
                   (format stream "| writer-scan iters | ~d |~%" scan-iters)
                   (format stream "~%## Method~%~%")
                   (format stream "**RX:** each RX strategy resolves ONE loaned slot `iters` times; the resolve does NOT touch the slot refcount, so a single loaned slot serves every iteration. GC bytes/sample is the `dds.pal:bytes-consed` delta over the loop / `iters` (SBCL-exact, Clasp reports 0 — a documented NFR-PORT gap). The lock-free loan RX reuses one `flatdata-view` struct (the per-reader view recycling the DCPS loan registry does) and reads a field straight off the slot SAP — no mutex, no copy. **Writer:** `%fd-zc-loan-scan-ns` builds a pool of N slots and times `%zc-loan` + `%zc-release` over `writer-scan iters` iterations (`dds.pal:monotonic-ns` total / iters, ~~us clock, amortised — the same method `perftest.lisp` uses); each loan re-scans all N `refcount==0` slots for the lowest pubseq (the worst case — every slot a reclaim candidate), so ns/loan RISES with N (the O(slots) sensitivity). NOTE: these are per-sample RX allocation + per-loan writer time, not end-to-end latency.~%~%")
                   (if (not have-shmem)
                       (format stream "(SHMEM by-name attach unreliable on this platform — the ZC lock-free loan bench pass-skipped; Clasp/macOS gap, ADR 0013)~%~%")
                       (progn
                         (format stream "## The headline — loaned RX GC bytes/sample is now LITERAL 0 (lock-free)~%~%")
                         (format stream "| RX strategy | GC bytes/sample | what it allocates |~%")
                         (format stream "|-------------|-----------------|-------------------|~%")
                         (format stream "| **lock-free loan** (`%zc-acquire-for-read` + SAP read + `%zc-release`; THIS WP) | **~d** | NOTHING — fenced generation-load + cas-u32 decrement, no mutex, no owned vector |~%" loan-bytes)
                         (format stream "| prior mutex'd loan (WP-FLATDATA-ZC-LOAN, ADR 0017) | 31 | the pool `pthread_mutex_lock`/`unlock` CFFI cons (acquire + release), payload-independent |~%")
                         (format stream "| FlatData+ZC v1 single-copy (`%zc-resolve-fresh`) | ~d | the mutex + one exact-length (~d-octet) OWNED vector |~%"
                                 new-bytes +fd-abc-flatdata-size+)
                         (format stream "| WP-ZEROCOPY-v1 sink+re-copy | ~d | the mutex + a ~d-octet sink + a re-copy |~%~%"
                                 v1-bytes dds.disc:+zerocopy-pool-slot-bytes+)
                         (format stream "The lock-free loaned RX allocates **~d** GC bytes/sample — the full progression **65552 -> 79 -> 31 -> 0**: the WP-ZEROCOPY-v1 sink (`~d`) -> FlatData+ZC v1 single-copy (`~d`, the owned vector) -> the prior mutex'd loan (`31`, the residual pool-mutex CFFI cons, ADR 0017) -> **`~d`, literal 0** (this WP). The last step removed the pool mutex from BOTH the acquire (a fenced generation-load that doubles as the stale-ref validate) and the release (a direct `cas-sap-u32` refcount decrement — 0-alloc at any generation, ADR 0018 Phase-B amendment): the reader's per-sample loan path no longer touches the GC heap at all. (The `31` row is the documented before-this-WP figure from ADR 0017's bench; the mutex it measured is gone, so it is not re-measured here.)~%~%"
                                 loan-bytes v1-bytes new-bytes loan-bytes)
                         (format stream "## The writer cost (FR-LANG-7 — the honest tradeoff): O(1) freelist-pop -> O(slots) scan~%~%")
                         (format stream "| pool slots | writer `%zc-loan` ns/loan |~%|------------|---------------------------|~%")
                         (dolist (row scan-rows) (format stream "| ~d | ~,1f |~%" (car row) (cdr row)))
                         (format stream "~%The freelist that gave the loan its O(1) pop was DROPPED (a lock-free `cas`-decrement release cannot maintain a freelist without a second CAS), so `%zc-loan` now SCANS the pool for the lowest-pubseq `refcount==0` slot — **O(slots)**. The table shows the ns/loan rising with the pool size (the O(slots) sensitivity)~a. Stated plainly: **the reader RX is now 0-alloc — that is the win — and the writer pays a small bounded scan** (writer-side, amortized over the data plane, and a writer typically has few pool slots). A lock-free freelist (a CAS stack) to restore the writer's O(1) loan while keeping the lock-free release is a **noted follow-up** (ADR 0018 §Out of scope), to revisit only if this O(slots) scan benches as a real cost in a real workload.~%~%"
                                 (if (and (>= (length scan-rows) 2)
                                          (> (cdr (car (last scan-rows))) (cdr (first scan-rows))))
                                     (format nil " — ~,1f ns at ~d slots vs ~,1f ns at ~d slots, ~,1fx"
                                             (cdr (car (last scan-rows))) (car (car (last scan-rows)))
                                             (cdr (first scan-rows)) (car (first scan-rows))
                                             (%bench-ratio (cdr (car (last scan-rows))) (cdr (first scan-rows))))
                                     ""))
                         (format stream "## The loan / return per-sample overhead (FR-LANG-7 — still not free)~%~%")
                         (format stream "| operation | GC bytes/sample |~%|-----------|-----------------|~%")
                         (format stream "| lock-free loan acquire + read (RX only) | ~d |~%" loan-bytes)
                         (format stream "| full lock-free loan + return CYCLE (`%zc-loan` + acquire + read + `%zc-release`) | ~d |~%~%" cycle-bytes)
                         (format stream "The RX *allocation* is eliminated (literal 0), but the loan API is **not free**: it adds an explicit `%zc-acquire-for-read` (the loan) and `%zc-release` (the return), plus the app's **explicit `return-loan` obligation** (a leaked loan pins a slot at `refcount>0` until the writer's pool gracefully falls back to non-ZC), plus the writer's O(slots) scan above. The full lock-free loan+return CYCLE costs **~d** GC bytes/sample here (down from the ADR-0017 mutex'd cycle's ~~96 B — the acquire + release mutex traffic is gone). No `0-cost`/`free` claim: the RX *allocation* is 0; the loan/return *calls*, the return *obligation*, and the writer *scan* are real.~%~%"
                                 cycle-bytes)))
                   (format stream "Method: RX ~d iterations, writer-scan ~d iterations; GC bytes/sample = `dds.pal:bytes-consed` delta / iters (SBCL-exact, Clasp=0); writer ns/loan = `dds.pal:monotonic-ns` total / iters (~~us clock, amortised). The memory-ordering handshake (the writer's payload -> `fence :release` -> generation-store-LAST pairing with the reader's generation acquire-load -> `fence :acquire`; the `cas-sap-u32` full-barrier release) is verified byte-exact CROSS-PROCESS by `make zc-xproc` (the reference resolves across two OS processes — a same-process bench cannot prove the fence pairing) + the `zc-lockfree-stress` / `zc-lockfree-release-biggen` unit tests. Impl: ~a ~a on ~a.~%"
                           iters scan-iters (lisp-implementation-type) (lisp-implementation-version) (machine-instance))
                   (when (and sbcl-p have-shmem)
                     (assert (zerop loan-bytes) () "bench: the lock-free loaned RX (~d) must be LITERAL 0 GC bytes/sample (no mutex, no owned vector)" loan-bytes)
                     (assert (< loan-bytes new-bytes) () "bench: the lock-free loaned RX (~d) must allocate strictly less than the v1 single-copy (~d)" loan-bytes new-bytes)
                     (assert (< loan-bytes v1-bytes) () "bench: the lock-free loaned RX (~d) must allocate far less than the WP-ZEROCOPY-v1 sink (~d)" loan-bytes v1-bytes))))
            (emit *standard-output*)
            (when file
              (with-open-file (s file :direction :output :if-exists :supersede :if-does-not-exist :create)
                (emit s))
              (format t "~&  wrote ~a~%" file))))))
    (dds.pal:free-static (dds.core.buffer:octet-buffer-vec fd)))
  t)

(defun* run-flatdata-deser-interop-test ()
    (function () (eql t))
  "WP-FLATDATA in-memory==wire at DESERIALIZE (FR-PF-4): the FlatData and classic codecs are interchangeable on
   the wire in the decode direction (Phase B proved the encode direction byte-exact). (a) A FlatData buffer
   filled via the Offset setters, fed to the CLASSIC deserialize-fd-abc, yields a STRUCT whose fields equal what
   was set. (b) The classic serialize of an equal struct, fed to the FlatData read-in-place (deserialize-fd-abc /
   the Offset getters), yields accessor reads equal to the same values. Uses the engine's own
   %serialize-sample / %deserialize-sample so no wire bytes are hardcoded (the engine is the oracle)."
  (let ((ts (dds.types:find-type-support "fd-abc"))
        (va 200) (vb 3000000000) (vc 12345678901234567890))
    ;; (a) FlatData buffer (via setters) -> classic deserialize -> equal STRUCT
    (let ((fd (make-fd-abc-flatdata)))
      (setf (fd-abc-a-fd fd) va (fd-abc-b-fd fd) vb (fd-abc-c-fd fd) vc)
      (let* ((wire (dds.dcps::%serialize-sample ts fd))         ; FlatData identity TX
             (ob (dds.core.buffer:make-octet-buffer (length wire)))
             (rc (progn (replace (dds.core.buffer:octet-buffer-vec ob) wire)
                        (dds.core.buffer:cursor ob :endianness :little))))
        (dds.cdr:parse-encapsulation-header rc)
        (let ((st (deserialize-fd-abc rc :xcdr2)))             ; CLASSIC decode of FlatData-produced wire
          (%check :fd-interop-a (and (fd-abc-p st) (= (fd-abc-a st) va) (= (fd-abc-b st) vb) (= (fd-abc-c st) vc))
                  (format nil "classic decode of FlatData wire mismatch: ~s" st)))
        (dds.pal:free-static (dds.core.buffer:octet-buffer-vec ob)))
      (dds.pal:free-static (dds.core.buffer:octet-buffer-vec fd)))
    ;; (b) classic serialize of a struct -> FlatData read-in-place -> equal accessor reads. Build the classic
    ;; wire form directly (serialize-fd-abc, NOT via %serialize-sample, whose vtable is now the FlatData identity
    ;; serializer expecting a buffer), exactly as %serialize-sample frames it (header + body + finalize-options).
    (let* ((st (make-fd-abc :a va :b vb :c vc))
           (cb (dds.core.buffer:make-octet-buffer (+ +fd-abc-flatdata-size+ 8)))
           (wc (dds.core.buffer:cursor cb :endianness :little)))
      (dds.cdr:make-encapsulation-header wc :plain-cdr2-le)
      (serialize-fd-abc st wc :xcdr2)
      (dds.cdr:finalize-encapsulation-options wc :plain-cdr2-le)
      (let* ((len (dds.core.buffer:cursor-position wc))
             (wire (make-array len :element-type '(unsigned-byte 8))))
        (replace wire (dds.core.buffer:octet-buffer-vec cb) :end1 len)
        (let ((sample (dds.dcps::%deserialize-sample ts wire)))   ; FlatData read-in-place RX (vtable :deserialize)
          (%check :fd-interop-b (and (= (fd-abc-a-fd sample) va) (= (fd-abc-b-fd sample) vb) (= (fd-abc-c-fd sample) vc))
                  (format nil "FlatData read-in-place of classic wire mismatch: a=~d b=~d c=~d"
                          (fd-abc-a-fd sample) (fd-abc-b-fd sample) (fd-abc-c-fd sample)))
          (dds.pal:free-static (dds.core.buffer:octet-buffer-vec sample))))
      (dds.pal:free-static (dds.core.buffer:octet-buffer-vec cb))))
  t)

;;; WP-FLATDATA-ZC-LOAN Task B1 (FR-PF-3/4, R6 — NOT cleared for ship, see ADR 0017): the SAP-mode Offset
;;; getter form is byte-exact to the shipped aref getter. Build a :flatdata value in an owned octet-buffer via
;;; the owned setters, then for each field COMPILE %flatdata-sap-getter-form over the buffer's SAP at body
;;; offset 4+off and assert the SAP read EQUALS the owned aref accessor — for all widths + signed-negative +
;;; bool. SBCL only (load-sap-u8 is SBCL-only, ZC is SBCL-only, ADR 0013); Clasp pass-skips cleanly.
(defun* %fd-sap-getter-byte-exact (spec build-fn getter-fn-alist)
    (function (list function list) t)
  "B1 helper (DRY): SPEC is the define-dds-type member list; BUILD-FN fills + returns an owned FlatData buffer;
   GETTER-FN-ALIST maps each member slot to its owned -fd accessor. For each member compute (off nbytes signed
   bool) from the SAME dds.gen helpers the codegen uses, COMPILE the SAP getter form over the buffer's SAP, and
   assert the SAP read = the owned aref read (the byte-exact oracle). Frees the buffer. NOT cleared for ship (R6)."
  (let* ((parsed (mapcar #'dds.gen::%parse-member spec))
         (offs (dds.gen::%flatdata-offsets parsed))
         (buf (funcall build-fn))
         (sap (dds.core.buffer:buffer-sap buf)))
    (unwind-protect
         (dolist (m parsed)
           (let* ((slot (getf m :slot))
                  (off (cdr (assoc slot offs)))
                  (base (+ 4 off))
                  (owned-fn (cdr (assoc slot getter-fn-alist))))
             (multiple-value-bind (nbytes signed-p bool-p) (dds.gen::%flatdata-field-kind m)
               (let* ((form (dds.gen::%flatdata-sap-getter-form 's base nbytes signed-p bool-p))
                      (sap-read (funcall (compile nil `(lambda (s) ,form)) sap))
                      (owned-read (funcall owned-fn buf)))
                 (%check (intern (format nil "FD-SAP-~a" slot) :keyword)
                         (eql sap-read owned-read)
                         (format nil "SAP getter for ~a (~d bytes @body~d) read ~s, aref accessor read ~s"
                                 slot nbytes off sap-read owned-read))))))
      (dds.pal:free-static (dds.core.buffer:octet-buffer-vec buf)))
    t))

(defun* run-flatdata-sap-getter-test ()
    (function () (eql t))
  "WP-FLATDATA-ZC-LOAN Task B1 (FR-PF-3/4, R6, ADR 0017): %flatdata-sap-getter-form is byte-exact to the shipped
   aref getter for every width + signed-negative + bool. Builds each value in an owned octet-buffer via the owned
   setters, COMPILEs the SAP getter form over the buffer's SAP at 4+body-offset, and asserts it EQUALS the owned
   accessor (the byte-exact oracle is the FlatData buffer). SBCL only (load-sap-u8 is SBCL-only); Clasp pass-skips."
  (if (eq (dds.pal:pal-impl-name) :sbcl)
      (progn
        ;; unsigned u8/u32/u64
        (%fd-sap-getter-byte-exact
         '((a :u8) (b :u32) (c :u64))
         (lambda () (let ((b (make-fd-abc-flatdata)))
                      (setf (fd-abc-a-fd b) 200 (fd-abc-b-fd b) 3000000000 (fd-abc-c-fd b) 12345678901234567890)
                      b))
         (list (cons 'a #'fd-abc-a-fd) (cons 'b #'fd-abc-b-fd) (cons 'c #'fd-abc-c-fd)))
        ;; signed i32/i64 negative (two's-complement) + u8
        (%fd-sap-getter-byte-exact
         '((a :u8) (b :i32) (c :i64))
         (lambda () (let ((b (make-fd-sig-flatdata)))
                      (setf (fd-sig-a-fd b) 7 (fd-sig-b-fd b) -123456789 (fd-sig-c-fd b) -1234567890123456789)
                      b))
         (list (cons 'a #'fd-sig-a-fd) (cons 'b #'fd-sig-b-fd) (cons 'c #'fd-sig-c-fd)))
        ;; narrow u16/i16/bool/i8 with a negative i16/i8 and bool t
        (%fd-sap-getter-byte-exact
         '((a :u16) (b :i16) (c :bool) (d :i8))
         (lambda () (let ((b (make-fd-narrow-flatdata)))
                      (setf (fd-narrow-a-fd b) #xBEEF (fd-narrow-b-fd b) -12345
                            (fd-narrow-c-fd b) t (fd-narrow-d-fd b) -42)
                      b))
         (list (cons 'a #'fd-narrow-a-fd) (cons 'b #'fd-narrow-b-fd)
               (cons 'c #'fd-narrow-c-fd) (cons 'd #'fd-narrow-d-fd)))
        ;; bool nil too (raw 0 -> /=0 is NIL)
        (%fd-sap-getter-byte-exact
         '((a :u16) (b :i16) (c :bool) (d :i8))
         (lambda () (let ((b (make-fd-narrow-flatdata)))
                      (setf (fd-narrow-a-fd b) 0 (fd-narrow-b-fd b) 0 (fd-narrow-c-fd b) nil (fd-narrow-d-fd b) 0)
                      b))
         (list (cons 'a #'fd-narrow-a-fd) (cons 'b #'fd-narrow-b-fd)
               (cons 'c #'fd-narrow-c-fd) (cons 'd #'fd-narrow-d-fd))))
      (format t "~&  [skip] flatdata-sap-getter: load-sap-u8 is SBCL-only (ZC, ADR 0013) — NFR-PORT gap~%"))
  t)

;;; WP-FLATDATA-ZC-LOAN Task B2 (FR-PF-3/4, R6, ADR 0017): the re-emitted <name>-<field>-fd dispatches owned
;;; octet-buffer vs flatdata-view on one struct-type branch. Build a :flatdata value in an OWNED buffer (the
;;; owned path reads unchanged), wrap a flatdata-view over that buffer's SAP (base-offset 4), and read every
;;; field via the SAME -fd accessor on the view -> equals the owned read, all widths/signed/bool. SBCL only.
(defun* %fd-view-accessor-byte-exact (build-fn getter-fn-alist)
    (function (function list) t)
  "B2 helper (DRY): BUILD-FN fills + returns an owned FlatData buffer; GETTER-FN-ALIST maps each member slot to
   its (now dispatching) -fd accessor. Wrap a flatdata-view over the buffer's SAP (base-offset 4) and assert each
   -fd accessor on the VIEW = the same accessor on the OWNED buffer (byte-exact). Frees the buffer. NOT cleared (R6)."
  (let* ((buf (funcall build-fn))
         (view (dds.types:make-flatdata-view :slot-sap (dds.core.buffer:buffer-sap buf)
                                             :base-offset 4
                                             :len (dds.core.buffer:octet-buffer-capacity buf))))
    (unwind-protect
         (dolist (entry getter-fn-alist)
           (let* ((slot (car entry)) (fn (cdr entry))
                  (owned-read (funcall fn buf))
                  (view-read (funcall fn view)))
             (%check (intern (format nil "FD-VIEW-~a" slot) :keyword)
                     (eql view-read owned-read)
                     (format nil "view accessor for ~a read ~s, owned accessor read ~s" slot view-read owned-read))))
      (dds.pal:free-static (dds.core.buffer:octet-buffer-vec buf)))
    t))

(defun* run-flatdata-view-accessor-test ()
    (function () (eql t))
  "WP-FLATDATA-ZC-LOAN Task B2 (FR-PF-3/4, R6, ADR 0017): the single -fd accessor surface reads a flatdata-view
   (SAP path) byte-exactly to an owned octet-buffer (aref path), via the predicted struct-type dispatch branch —
   for every width + signed-negative + bool (the owned read is the oracle). SBCL only (the view holds a live SAP
   the SAP accessors read; load-sap-u8 is SBCL-only); Clasp pass-skips."
  (if (eq (dds.pal:pal-impl-name) :sbcl)
      (progn
        (%fd-view-accessor-byte-exact
         (lambda () (let ((b (make-fd-abc-flatdata)))
                      (setf (fd-abc-a-fd b) 200 (fd-abc-b-fd b) 3000000000 (fd-abc-c-fd b) 12345678901234567890)
                      b))
         (list (cons 'a #'fd-abc-a-fd) (cons 'b #'fd-abc-b-fd) (cons 'c #'fd-abc-c-fd)))
        (%fd-view-accessor-byte-exact
         (lambda () (let ((b (make-fd-sig-flatdata)))
                      (setf (fd-sig-a-fd b) 7 (fd-sig-b-fd b) -123456789 (fd-sig-c-fd b) -1234567890123456789)
                      b))
         (list (cons 'a #'fd-sig-a-fd) (cons 'b #'fd-sig-b-fd) (cons 'c #'fd-sig-c-fd)))
        (%fd-view-accessor-byte-exact
         (lambda () (let ((b (make-fd-narrow-flatdata)))
                      (setf (fd-narrow-a-fd b) #xBEEF (fd-narrow-b-fd b) -12345
                            (fd-narrow-c-fd b) t (fd-narrow-d-fd b) -42)
                      b))
         (list (cons 'a #'fd-narrow-a-fd) (cons 'b #'fd-narrow-b-fd)
               (cons 'c #'fd-narrow-c-fd) (cons 'd #'fd-narrow-d-fd)))
        ;; bool nil through the view too
        (%fd-view-accessor-byte-exact
         (lambda () (let ((b (make-fd-narrow-flatdata)))
                      (setf (fd-narrow-a-fd b) 0 (fd-narrow-b-fd b) 0 (fd-narrow-c-fd b) nil (fd-narrow-d-fd b) 0)
                      b))
         (list (cons 'c #'fd-narrow-c-fd))))
      (format t "~&  [skip] flatdata-view-accessor: load-sap-u8 is SBCL-only (ZC, ADR 0013) — NFR-PORT gap~%"))
  t)

(defun* run-flow-token-bucket-test ()
    (function () t)
  "WP-ASYNC-FLOW (FR-PF-2, flow-control half), ADR 0016: the bytes/period token bucket with a deterministic
   INJECTED clock (a closure over a settable ns counter — no wall-clock dependence). Asserts: starts full;
   acquire-success consumes and returns 0; a third acquire over the remaining tokens returns a POSITIVE
   deficit-wait with NO consume; a half-period elapse refills ~rate*delta capped at MAX-BURST; tokens never
   exceed MAX-BURST after a long idle; an over-MAX-BURST acquire SUCCEEDS via retry-then-refill within a small
   bound and drains the bucket to 0 (the no-livelock guarantee — FAILS against the pre-fix wait=1-forever code);
   a low-rate refill stepped in sub-quantum increments delivers the IDEAL token count with no remainder loss
   (FAILS against the pre-fix advance-to-NOW refill); and zero/negative :tokens-per-period or :period are
   rejected at construction."
  (let* ((clk 0)
         (clock-fn (lambda () clk))
         (b (dds.disc:make-flow-token-bucket :tokens-per-period 1000 :period 1000000000
                                             :max-burst 1000 :clock-fn clock-fn)))
    (%check :fb-starts-full (= 1000 (dds.disc:flow-token-bucket-tokens b))
            "token bucket must start full at MAX-BURST (1000)")
    (%check :fb-acquire-1 (= 0 (dds.disc::%fb-acquire b 400))
            "first acquire of 400 with a full bucket must succeed (return 0)")
    (%check :fb-after-1 (= 600 (dds.disc:flow-token-bucket-tokens b))
            "after acquiring 400 of 1000, 600 tokens must remain")
    (%check :fb-acquire-2 (= 0 (dds.disc::%fb-acquire b 400))
            "second acquire of 400 (200 left after) must succeed (return 0)")
    (%check :fb-after-2 (= 200 (dds.disc:flow-token-bucket-tokens b))
            "after consuming 800 of 1000, 200 tokens must remain")
    (let ((wait (dds.disc::%fb-acquire b 400)))
      (%check :fb-deficit-positive (and (integerp wait) (plusp wait))
              "a third acquire of 400 with only 200 tokens must return a POSITIVE deficit-wait")
      (%check :fb-deficit-no-consume (= 200 (dds.disc:flow-token-bucket-tokens b))
              "the deficit-wait acquire must NOT consume any tokens (still 200)")
      (%check :fb-deficit-value (= 200000000 wait)
              (format nil "deficit-wait for 200 missing bytes at 1000 B/1e9 ns must be 2e8 ns, got ~d" wait)))
    (setf clk 500000000)
    (let ((tokens (dds.disc::%fb-refill b)))
      (%check :fb-half-period-refill (= 700 tokens)
              (format nil "half a period (5e8 ns) must add ~~500 tokens to 200 => 700 (capped at 1000), got ~d"
                      tokens)))
    (setf clk 1000000000000)
    (let ((tokens (dds.disc::%fb-refill b)))
      (%check :fb-cap-at-max-burst (= 1000 tokens)
              (format nil "tokens must never exceed MAX-BURST (1000) after a long idle, got ~d" tokens)))
    (dds.disc::%fb-acquire b 1000)
    (let ((sent nil) (iters 0) (cap 3) (drained-from (dds.disc:flow-token-bucket-tokens b)))
      (loop for i from 1 to cap
            for wait = (dds.disc::%fb-acquire b 1500)
            do (setf iters i)
            when (= 0 wait) do (setf sent t) (loop-finish)
            else do (incf clk wait) (dds.disc::%fb-refill b))
      (%check :fb-over-burst-drained (= 0 drained-from)
              (format nil "over-burst probe must start from a drained (non-full) bucket, got ~d" drained-from))
      (%check :fb-over-burst-no-livelock sent
              (format nil "an over-MAX-BURST (1500 > 1000) acquire from EMPTY must SUCCEED via deficit-wait + ~
                           refill-to-full + retry within ~d iterations (pre-fix livelocks: wait=1 forever), ~
                           got sent=~S after ~d iters"
                      cap sent iters))
      (%check :fb-over-burst-iters (>= iters 2)
              (format nil "the non-full over-burst path must take a deficit-then-retry (>= 2 iters), got ~d"
                      iters))
      (%check :fb-over-burst-consumes (= 0 (dds.disc:flow-token-bucket-tokens b))
              (format nil "an over-MAX-BURST success must drain the bucket to 0 (clamped, no debt), got ~d"
                      (dds.disc:flow-token-bucket-tokens b))))
    (let* ((fclk 0)
           (fb (dds.disc:make-flow-token-bucket :tokens-per-period 1 :period 1000000000
                                                :max-burst 1000 :clock-fn (lambda () fclk))))
      (dds.disc::%fb-acquire fb 1000)
      (dotimes (i 5) (incf fclk 400000000) (dds.disc::%fb-refill fb))
      (%check :fb-refill-fidelity (= 2 (dds.disc:flow-token-bucket-tokens fb))
              (format nil "5 x 0.4e9 ns (=2.0e9 ns) at 1 tok/1e9 ns must deliver exactly 2 tokens (no ~
                           sub-quantum loss); pre-fix advances last-refill to NOW and delivers 1, got ~d"
                      (dds.disc:flow-token-bucket-tokens fb))))
    (%check :fb-reject-zero-tpp
            (null (ignore-errors (dds.disc:make-flow-token-bucket :tokens-per-period 0 :period 1000000000
                                                                  :max-burst 1000 :clock-fn clock-fn)))
            "make-flow-token-bucket must reject :tokens-per-period 0")
    (%check :fb-reject-neg-tpp
            (null (ignore-errors (dds.disc:make-flow-token-bucket :tokens-per-period -5 :period 1000000000
                                                                  :max-burst 1000 :clock-fn clock-fn)))
            "make-flow-token-bucket must reject a negative :tokens-per-period")
    (%check :fb-reject-zero-period
            (null (ignore-errors (dds.disc:make-flow-token-bucket :tokens-per-period 1000 :period 0
                                                                  :max-burst 1000 :clock-fn clock-fn)))
            "make-flow-token-bucket must reject :period 0")
    (%check :fb-reject-neg-period
            (null (ignore-errors (dds.disc:make-flow-token-bucket :tokens-per-period 1000 :period -1
                                                                  :max-burst 1000 :clock-fn clock-fn)))
            "make-flow-token-bucket must reject a negative :period"))
  t)

(defun* %bp-writer (max-samples max-blocking-ns &optional (kind :keep-all))
    (function ((or null (integer 1)) (or null (integer 0)) &optional (member :keep-last :keep-all))
              dds.rtps.reliable:rtps-writer)
  "Build a reliable rtps-writer with a HISTORY KIND (KEEP_ALL by default) / RESOURCE_LIMITS MAX-SAMPLES
   cache and RELIABILITY MAX-BLOCKING-NS — the backpressure test fixture (WP-ASYNC-FLOW, ADR 0016)."
  (dds.rtps.reliable:make-rtps-writer
   :hc (dds.rtps.history:make-history-cache kind 1 max-samples nil)
   :max-blocking-ns max-blocking-ns))

(defun* %bp-payload ()
    (function () (simple-array (unsigned-byte 8) (*)))
  "A 4-octet payload for the backpressure test."
  (octets 9 9 9 9))

(defun* run-flow-backpressure-test ()
    (function () t)
  "WP-ASYNC-FLOW (FR-PF-2/FR-QOS), ADR 0016 §Backpressure: DDS-standard block-up-to-max_blocking_time
   backpressure in the reliable writer. SBCL-only (real blocking + threads); Clasp pass-skipped (the known
   Clasp multithread-condvar SIGSEGV, NFR-PORT). Four cases:
   (1) BLOCK→TIMEOUT — a KEEP_ALL writer at MAX-SAMPLES with a stalled drain (no purge): a worker-thread
       writer-write of the next sample BLOCKS, then returns the :timeout sentinel after ~max_blocking_time
       (200 ms ± tolerance) with the cache intact and NO SN consumed (the SN stream stays hole-free);
   (2) UNBLOCK-ON-SPACE-SIGNAL — a worker blocks on a full cache with a GENEROUS deadline; the main thread
       frees space via the REAL ACKNACK purge path (writer-purge-acked, which broadcasts space-cv) BEFORE
       the deadline; the worker WAKES and SUCCEEDS (returns an SN), proving the CV wakeup (elapsed << the
       deadline), not a timeout;
   (3) MAX_BLOCKING = 0 — a full cache returns :timeout IMMEDIATELY (~0 elapsed), the non-blocking degenerate;
   (4) DEFAULT NO-BLOCK regression — an unlimited (max_samples NIL) and a KEEP_LAST writer NEVER block and
       NEVER return :timeout (every writer-write returns an integer SN) — the default path is unchanged."
  (when (eq (uiop:implementation-type) :clasp) (return-from run-flow-backpressure-test t))
  ;; -- Case 1: block then TIMEOUT at ~max_blocking_time (stalled drain, no purge) --
  (let* ((block-ms 200)
         (w (%bp-writer 3 (* block-ms 1000000)))
         (rkey 11) (result :unset) (elapsed-ms nil))
    (dotimes (i 3)
      (%check :bp1-fill (integerp (dds.rtps.reliable:writer-write w (%bp-payload)))
              "filling the bounded cache to max_samples must succeed (return an SN)"))   ; SN 1,2,3
    (let* ((t0 (dds.pal:monotonic-ns))
           (th (dds.pal:spawn (lambda () (setf result (dds.rtps.reliable:writer-write w (%bp-payload))))
                              :name "bp-block")))
      (dds.pal:join th)
      (setf elapsed-ms (/ (- (dds.pal:monotonic-ns) t0) 1000000.0d0)))
    (%check :bp1-timeout (eq :timeout result)
            (format nil "a write into a full KEEP_ALL cache must return :timeout after max_blocking_time, got ~S" result))
    (%check :bp1-blocked-approx (and (>= elapsed-ms (* block-ms 0.7)) (<= elapsed-ms (* block-ms 3.0)))
            (format nil "the blocked write must take ~~~d ms (>= 0.7x, <= 3x), got ~,1f ms" block-ms elapsed-ms))
    (%check :bp1-cache-intact (= 3 (dds.rtps.history:hc-change-count (dds.rtps.reliable:rtps-writer-hc w)))
            "a timed-out write must leave the cache intact (still 3 changes)")
    ;; the timed-out write consumed NO SN (hole-free): free space, then the next write takes SN 4 (not 5)
    (setf (dds.rtps.reliable:reader-proxy-acked-base (dds.rtps.reliable:get-reader-proxy w rkey)) 4)
    (dds.rtps.reliable:writer-purge-acked w (list rkey))
    (%check :bp1-no-sn-consumed (eql 4 (dds.rtps.reliable:writer-write w (%bp-payload)))
            "a timed-out write must NOT consume a sequence number: the next successful write takes SN 4 (hole-free)"))
  ;; -- Case 2: unblock BEFORE the deadline via the real ACKNACK purge path (proves the CV wakeup) --
  (let* ((deadline-ms 3000)
         (w (%bp-writer 3 (* deadline-ms 1000000)))
         (rkey 77) (result :unset) (elapsed-ms nil))
    (dotimes (i 3) (dds.rtps.reliable:writer-write w (%bp-payload)))   ; SN 1,2,3 fill the cache
    (setf (dds.rtps.reliable:reader-proxy-acked-base
           (dds.rtps.reliable:get-reader-proxy w rkey))
          3)   ; the reader has ACKed SN 1,2 (acked-base 3) -> writer-purge-acked drops them
    (let* ((t0 (dds.pal:monotonic-ns))
           (th (dds.pal:spawn (lambda () (setf result (dds.rtps.reliable:writer-write w (%bp-payload))))
                              :name "bp-unblock")))
      (sleep 0.1)   ; let the worker reach the wait (still blocked: nothing has freed space yet)
      (%check :bp2-still-blocked (eq result :unset)
              "the worker write must still be BLOCKED before any space is freed")
      (let ((purged (dds.rtps.reliable:writer-purge-acked w (list rkey))))   ; REAL purge path: frees space + broadcasts space-cv
        (%check :bp2-purged (= 2 purged)
                (format nil "writer-purge-acked must drop the 2 acked changes (SN 1,2), got ~d" purged)))
      (dds.pal:join th)
      (setf elapsed-ms (/ (- (dds.pal:monotonic-ns) t0) 1000000.0d0)))
    (%check :bp2-success (integerp result)
            (format nil "the blocked write must SUCCEED (return an SN) once the purge frees space + signals, got ~S" result))
    (%check :bp2-sn-4 (eql result 4)
            (format nil "the unblocked write must take the next SN (4), got ~S" result))
    (%check :bp2-woke-early (< elapsed-ms (* deadline-ms 0.5))
            (format nil "the write must be WOKEN by the space-signal WELL before its ~d ms deadline (proves the CV wakeup, not a timeout), got ~,1f ms"
                    deadline-ms elapsed-ms)))
  ;; -- Case 3: max_blocking_time = 0 -> immediate :timeout when full (no blocking) --
  (let* ((w (%bp-writer 2 0)) (result :unset) (elapsed-ms nil))
    (dotimes (i 2) (dds.rtps.reliable:writer-write w (%bp-payload)))   ; fill to max_samples=2
    (let ((t0 (dds.pal:monotonic-ns)))
      (setf result (dds.rtps.reliable:writer-write w (%bp-payload))
            elapsed-ms (/ (- (dds.pal:monotonic-ns) t0) 1000000.0d0)))
    (%check :bp3-immediate-timeout (eq :timeout result)
            (format nil "max_blocking_time 0 on a full cache must return :timeout immediately, got ~S" result))
    (%check :bp3-no-block (< elapsed-ms 50)
            (format nil "max_blocking_time 0 must NOT block (~~0 ms), got ~,1f ms" elapsed-ms)))
  ;; -- Case 4: default (unlimited / KEEP_LAST) never blocks, never times out (regression) --
  (let ((w (%bp-writer nil (* 200 1000000))))   ; KEEP_ALL, max_samples NIL = unlimited, with a max_blocking set
    (dotimes (i 50)
      (%check :bp4-unlimited-ok (integerp (dds.rtps.reliable:writer-write w (%bp-payload)))
              "an UNLIMITED KEEP_ALL writer must never block / time out (always returns an SN)")))
  (let ((w (%bp-writer 2 (* 200 1000000) :keep-last)))   ; KEEP_LAST depth-1 with a finite max_samples + max_blocking
    (dotimes (i 50)
      (%check :bp4-keeplast-ok (integerp (dds.rtps.reliable:writer-write w (%bp-payload)))
              "a KEEP_LAST writer must never block / time out (it evicts, never rejects)")))
  ;; lifecycle change respects the bound consistently with a data write (full cache + 0 blocking -> :timeout)
  (let ((w (%bp-writer 1 0)))
    (dds.rtps.reliable:writer-write w (%bp-payload))   ; fill the single slot
    (%check :bp4-lifecycle-bounded
            (eq :timeout (dds.rtps.reliable:writer-lifecycle-change
                          w (make-array 16 :element-type '(unsigned-byte 8) :initial-element 0) 1))
            "writer-lifecycle-change must also return :timeout on a full bounded cache (the bound applies to all changes)"))
  ;; bounded cache + max-blocking-ns NIL: a full cache must REJECT with :timeout and consume NO SN
  ;; (never an unrepairable SN hole from a silently-rejected hc-add-change)
  (let ((w (%bp-writer 2 nil)) (rkey 22))
    (dotimes (i 2) (dds.rtps.reliable:writer-write w (%bp-payload)))   ; SN 1,2 fill the cache (no blocking config)
    (%check :bp4-bounded-noblock-timeout
            (eq :timeout (dds.rtps.reliable:writer-write w (%bp-payload)))
            "a full bounded cache with max-blocking-ns NIL must return :timeout immediately (no blocking)")
    (%check :bp4-bounded-noblock-intact (= 2 (dds.rtps.history:hc-change-count (dds.rtps.reliable:rtps-writer-hc w)))
            "the rejected write must not grow the cache (still 2)")
    (setf (dds.rtps.reliable:reader-proxy-acked-base (dds.rtps.reliable:get-reader-proxy w rkey)) 3)
    (dds.rtps.reliable:writer-purge-acked w (list rkey))   ; free SN 1,2 -> room
    (%check :bp4-bounded-noblock-no-hole (eql 3 (dds.rtps.reliable:writer-write w (%bp-payload)))
            "the next successful write after a :timeout must take SN 3 (no SN consumed by the rejected write — hole-free)"))
  t)

(defun* run-all-tests ()
    (function () t)
  "Run every landed test; signal on first failure, else report and return T."
  (let ((tests '(("md5-rfc1321"               . run-md5-test)
                 ("echo-over-mock-transport" . run-echo-test)
                 ("pal-fence"                . run-pal-fence-test)
                 ("pal-sap-atomics"          . run-pal-sap-atomics-test)
                 ("pal-sap-ref"              . run-sap-ref-test)
                 ("pal-shm"                  . run-pal-shm-test)
                 ("pal-pshared"              . run-pal-pshared-test)
                 ("xcdr-codec-roundtrip"     . run-codec-roundtrip-test)
                 ("xcdr-byte-exact-seed"     . run-byte-exact-test)
                 ("xcdr-encap-options-pad"   . run-encap-options-pad-test)
                 ("xcdr-generated-type"      . run-generated-type-test)
                 ("xcdr-generated-sequence"  . run-generated-sequence-test)
                 ("xcdr-generated-nested"    . run-generated-nested-test)
                 ("tx-representation"        . run-tx-representation-test)
                 ("tx-rx-representation-roundtrip" . run-tx-rx-representation-roundtrip-test)
                 ("type-support-keyed-p"     . run-keyed-p-test)
                 ("dds-keyhash"              . run-keyhash-test)
                 ("keyed-flatdata-keyhash"   . run-keyed-flatdata-keyhash-test)
                 ("keyed-flat-interop-keyhash" . run-keyed-flat-interop-keyhash-test)
                 ("xtypes-model"             . run-xtypes-model-test)
                 ("xtypes-assignability"     . run-assignability-test)
                 ("int8-uint8-byte-kinds"    . run-int8-uint8-byte-kinds-test)
                 ("enum-model"               . run-enum-model-test)
                 ("enum-assignability"       . run-enum-assignability-test)
                 ("array-model"              . run-array-model-test)
                 ("array-assignability"      . run-array-assignability-test)
                 ("union-model"              . run-union-model-test)
                 ("union-assignability"      . run-union-assignability-test)
                 ("xtypes-typeobject-cdr"    . run-typeobject-cdr-test)
                 ("xtypes-type-information"  . run-type-information-test)
                 ("fastdds-type-information-vector" . run-fastdds-type-information-vector-test)
                 ("fastdds-typelookup-reply-vector" . run-fastdds-typelookup-reply-vector-test)
                 ("typelookup-request"       . run-typelookup-request-test)
                 ("typelookup-reply"         . run-typelookup-reply-test)
                 ("typelookup-vectors"       . run-typelookup-vector-test)
                 ("typeobject-parse"         . run-typeobject-parse-test)
                 ("typelookup-server"        . run-typelookup-server-test)
                 ("xtypes-type-object-lb"    . run-type-object-lb-test)
                 ("lto-tokenize"             . run-lto-tokenize-test)
                 ("lto-parse-shape"          . run-lto-parse-shape-test)
                 ("lto-parse-primitives"     . run-lto-parse-primitives-test)
                 ("lto-parse-strings-keys"   . run-lto-parse-strings-keys-test)
                 ("lto-parse-extensibility"  . run-lto-parse-extensibility-test)
                 ("lto-parse-sequence"       . run-lto-parse-sequence-test)
                 ("lto-assignability"        . run-lto-assignability-test)
                 ("lto-parse-nested"         . run-lto-parse-nested-test)
                 ("lto-unmodelable-unsupported" . run-lto-unmodelable-unsupported-test)
                 ("lto-parse-enum"           . run-lto-parse-enum-test)
                 ("lto-parse-aggregates-unsupported" . run-lto-parse-aggregates-unsupported-test)
                 ("lto-enum-assignability"   . run-lto-enum-assignability-test)
                 ("lto-array-assignability"  . run-lto-array-assignability-test)
                 ("lto-union-assignability"  . run-lto-union-assignability-test)
                 ("sedp-type-object-lb"      . run-sedp-type-object-lb-test)
                 ("xtypes-type-compat-soft"  . run-type-compat-soft-test)
                 ("sedp-type-information"    . run-sedp-type-information-test)
                 ("sedp-default-reliability" . run-sedp-default-reliability-test)
                 ("endpoint-kind"            . run-endpoint-kind-test)
                 ("keyed-match"              . run-keyed-match-test)
                 ("acknack-addressing"       . run-acknack-addressing-test)
                 ("push-spdp-peer-isolation" . run-push-spdp-peer-isolation-test)
                 ("colocated-push"           . run-colocated-push-test)
                 ("coalesce-pack"            . run-coalesce-pack-test)
                 ("coalesce-split"           . run-coalesce-split-test)
                 ("coalesce-large-pack"      . run-coalesce-large-pack-test)
                 ("gap-send-on-missing-sn"   . run-gap-send-on-missing-sn-test)
                 ("reader-gap-reception"     . run-reader-gap-reception-test)
                 ("reader-gap-range-cap"     . run-reader-gap-range-cap-test)
                 ("keeplast-writer-perinstance-e2e" . run-keeplast-writer-perinstance-e2e-test)
                 ("keeplast-interior-hole-gap-e2e"  . run-keeplast-interior-hole-gap-e2e-test)
                 ("keeplast-firstsn-advance"        . run-keeplast-firstsn-advance-test)
                 ("keeplast-reader-perinstance-e2e" . run-keeplast-reader-perinstance-e2e-test)
                 ("keeplast-unkeyed-collapse"       . run-keeplast-unkeyed-collapse-test)
                 ("keeplast-keepall-regression"     . run-keeplast-keepall-regression-test)
                 ("keeplast-reliability-composition" . run-keeplast-reliability-composition-test)
                 ("batch-defer"              . run-batch-defer-test)
                 ("async-decoupled"          . run-async-decoupled-test)
                 ("async-emit-fault-survives" . run-async-emit-fault-survives-test)
                 ("emit-fault-inert"         . run-emit-fault-inert-test)
                 ("flow-step-equivalence"    . run-flow-step-equivalence-test)
                 ("flow-token-bucket"        . run-flow-token-bucket-test)
                 ("flow-backpressure"        . run-flow-backpressure-test)
                 ("flow-controller-lifecycle" . run-flow-controller-lifecycle-test)
                 ("flow-pacing"              . run-flow-pacing-test)
                 ("flow-multiwriter-rr"      . run-flow-multiwriter-rr-test)
                 ("flow-concurrency-stress"  . run-flow-concurrency-stress-test)
                 ("flow-teardown"            . run-flow-teardown-test)
                 ("flow-off-byte-identical"  . run-flow-off-byte-identical-test)
                 ("flow-emit-fault-no-spin"  . run-flow-emit-fault-no-spin-test)
                 ("flow-emit-fault-no-spin-multi" . run-flow-emit-fault-no-spin-multi-test)
                 ("reliable-repair-after-drop" . run-reliable-repair-after-drop-test)
                 ("hook-self-error"          . run-hook-self-error-test)
                 ("shmem-end-to-end"         . run-shmem-end-to-end-test)
                 ("shmem-send-self-guard"    . run-shmem-send-self-guard-test)
                 ("shmem-send-self-guard-no-regression" . run-shmem-send-self-guard-no-regression-test)
                 ("zerocopy-end-to-end"      . run-zerocopy-end-to-end-test)
                 ("flatdata-zerocopy"        . run-flatdata-zerocopy-test)
                 ("zc-defer"                 . run-zc-defer-test)
                 ("dcps-loan-roundtrip"      . run-dcps-loan-roundtrip-test)
                 ("loan-read-return-take"    . run-loan-read-return-take-test)
                 ("loan-handle-dealias"      . run-loan-handle-dealias-test)
                 ("flatdata-zc-loan-e2e"     . run-flatdata-zc-loan-e2e-test)
                 ("keyed-flatdata-loan-handle" . run-keyed-flatdata-loan-handle-test)
                 ("keyed-flatdata-loan-keeplast" . run-keyed-flatdata-loan-keeplast-test)
                 ("keyed-flatdata-copy-behavior" . run-keyed-flatdata-copy-behavior-test)
                 ("keyed-flatdata-dispose"    . run-keyed-flatdata-dispose-test)
                 ("flatdata-zc-loan-stress"  . run-flatdata-zc-loan-stress-test)
                 ("reliable-zc-retransmit"   . run-reliable-zc-retransmit-test)
                 ("reliable-zc-poolfull-fallback" . run-reliable-zc-poolfull-fallback-test)
                 ("reliable-zc-mixed"        . run-reliable-zc-mixed-test)
                 ("reliable-zc-slot-outlives-purge" . run-reliable-zc-slot-outlives-purge-test)
                 ("reliable-zc-qos"          . run-reliable-zc-qos-test)
                 ("lease-sweep"              . run-lease-sweep-test)
                 ("tce-disallow-default"     . run-tce-disallow-default-test)
                 ("zero-alloc-into"          . run-generated-into-test)
                 ("rtps-wire-byte-exact"     . run-rtps-wire-test)
                 ("rtps-seqnum-bitmap"       . run-rtps-seqnum-test)
                 ("rtps-fragnum-set"         . run-fragnum-set-test)
                 ("rtps-submessages"         . run-rtps-submessage-test)
                 ("rtps-data"                . run-rtps-data-test)
                 ("status-info-codec"        . run-status-info-codec-test)
                 ("lifecycle-change-list"    . run-lifecycle-change-list-test)
                 ("rtps-data-frag"           . run-rtps-data-frag-test)
                 ("connext-data-frag-vector" . run-connext-data-frag-vector-test)
                 ("rtps-heartbeat-frag"      . run-heartbeat-frag-test)
                 ("rtps-nack-frag"           . run-nack-frag-test)
                 ("connext-nack-frag-vector" . run-connext-nack-frag-vector-test)
                 ("rtps-reassembly"          . run-reassembly-test)
                 ("rtps-frag-acknack"        . run-frag-acknack-test)
                 ("rtps-frag-plan"           . run-frag-plan-test)
                 ("rtps-writer-frag-glue"    . run-writer-frag-glue-test)
                 ("rtps-frag-roundtrip"      . run-frag-roundtrip-test)
                 ("rtps-frag-lossy"          . run-frag-lossy-test)
                 ("rtps-message-dispatch"    . run-rtps-dispatch-test)
                 ("rtps-parameterlist"       . run-paramlist-test)
                 ("pid-liveliness"           . run-pid-liveliness-test)
                 ("ownership-codec"          . run-ownership-codec-test)
                 ("rtps-port-mapping"        . run-port-mapping-test)
                 ("rtps-participant-message" . run-participant-message-codec-test)
                 ("fastdds-participant-message" . run-fastdds-participant-message-test)
                 ("rtps-history-cache"       . run-history-test)
                 ("hc-perinstance-keeplast"  . run-hc-perinstance-keeplast-test)
                 ("hc-keeplast-unkeyed"      . run-hc-keeplast-unkeyed-test)
                 ("hc-remove-change-consistency" . run-hc-remove-change-consistency-test)
                 ("rtps-reliable-delivery"   . run-reliability-test)
                 ("rtps-writer-pushonce"     . run-writer-pushonce-test)
                 ("rtps-history-purge"       . run-history-purge-test)
                 ("durability-retention"     . run-durability-retention-test)
                 ("durability-replays"       . run-durability-replays-test)
                 ("durability-reader-gate"   . run-durability-reader-gate-test)
                 ("durability-finalize"      . run-durability-finalize-test)
                 ("rtps-reader-compaction"   . run-reader-compaction-test)
                 ("purge-reliable-only"      . run-purge-reliable-only-test)
                 ("rtps-gap-handling"        . run-gap-handling-test)
                 ("rtps-reliable-multiwriter" . run-reliable-multiwriter-test)
                 ("property-based"           . run-pbt-tests)
                 ("udp-loopback"             . run-udp-loopback-test)
                 ("rtps-discovery-spdp"      . dds.rtps.discovery:run-discovery-test)
                 ("rtps-discovery-sedp"      . dds.rtps.discovery:run-sedp-test)
                 ("rtps-data-representation-wire" . dds.rtps.discovery:run-data-representation-wire-test)
                 ("rtps-data-representation-malformed" . dds.rtps.discovery:run-data-representation-malformed-test)
                 ("shmem-locator-wire"       . run-shmem-locator-wire-test)
                 ("udp-transport"           . dds.xport.udp:run-udp-transport-test)
                 ("udp-receiver-thread"      . dds.xport.udp:run-udp-receiver-test)
                 ("end-to-end-udp"           . run-end-to-end-test)
                 ("spdp-discovery-over-udp"  . dds.disc:run-spdp-discovery-test)
                 ("sedp-matching-over-udp"   . dds.disc:run-sedp-discovery-test)
                 ("multicast-spdp-discovery" . dds.disc:run-mcast-discovery-test)
                 ("participant-liveliness"   . dds.disc:run-participant-liveliness-test)
                 ("foreign-locator-robust"   . dds.disc:run-locator-filter-test)
                 ("reliable-data-over-udp"   . dds.disc:run-dataplane-test)
                 ("large-data-over-udp"      . dds.disc:run-large-dataplane-test)
                 ("lost-final-sample-repair" . dds.disc:run-lost-final-sample-test)
                 ("dispose-over-udp"         . dds.disc:run-dispose-dataplane-test)
                 ("dispose-reliable-repair"  . dds.disc:run-dispose-repair-test)
                 ("typed-shape-over-udp"     . run-typed-dataplane-test)
                 ("qos-rxo-truth-table"      . dds.qos:run-qos-rxo-test)
                 ("qos-data-representation-rxo" . dds.qos:run-data-representation-rxo-test)
                 ("dcps-entity-write-take"   . run-dcps-entity-test)
                 ("nokey-roundtrip"          . run-nokey-roundtrip-test)
                 ("dcps-instance-read-take"  . run-dcps-instance-test)
                 ("dcps-dispose-unregister"  . run-dcps-dispose-test)
                 ("dcps-durability-latejoiner" . run-dcps-durability-latejoiner-test)
                 ("dcps-durability-keeplast" . run-dcps-durability-keeplast-test)
                 ("keeplast-keyhash-threaded" . run-keeplast-keyhash-threaded-test)
                 ("dcps-instance-state"      . run-dcps-instance-state-test)
                 ("dcps-no-writers"          . run-dcps-no-writers-test)
                 ("dcps-disposed-sticky"     . run-dcps-disposed-sticky-test)
                 ("dcps-writer-unmatch"      . run-dcps-writer-unmatch-test)
                 ("dcps-drain-sn-order"      . run-dcps-drain-sn-order-test)
                 ("dcps-autodispose-reader"  . run-dcps-autodispose-reader-test)
                 ("dcps-autopurge"           . run-dcps-autopurge-test)
                 ("dcps-autodispose-writer"  . run-dcps-autodispose-writer-test)
                 ("dcps-exclusive-ownership" . run-dcps-exclusive-ownership-test)
                 ("dcps-exclusive-pre-match" . run-dcps-exclusive-pre-match-test)
                 ("dcps-dispose-owner-clear" . run-dcps-dispose-owner-clear-test)
                 ("dcps-multiwriter-dispose" . run-dcps-multiwriter-dispose-test)
                 ("dcps-rxo-blocks-match"    . run-dcps-rxo-test)
                 ("dcps-conditions-waitset"  . run-dcps-waitset-test)
                 ("dcps-matched-status"      . run-dcps-matched-status-test)
                 ("lease-unmatch"            . run-lease-unmatch-test)
                 ("liveliness-changed"       . run-liveliness-changed-test)
                 ("liveliness-lost"          . run-liveliness-lost-test)
                 ("dcps-incompatible-qos"    . run-dcps-incompatible-qos-test)
                 ("dcps-query-condition"     . run-dcps-query-condition-test)
                 ("dcps-condvar-wake"        . run-dcps-condvar-wake-test)
                 ("dcps-content-filter"      . run-dcps-filter-test)
                 ("dcps-content-filtered-topic" . run-dcps-content-filtered-topic-test)
                 ("dcps-querycondition-sql"  . run-dcps-querycondition-sql-test)
                 ("dcps-inconsistent-topic"  . run-dcps-inconsistent-topic-test)
                 ("dcps-sample-rejected"     . run-dcps-sample-rejected-test)
                 ("dcps-builtin-topics"      . run-dcps-builtin-topics-test)
                 ("dcps-type-compat"         . run-dcps-type-compat-test)
                 ("dcps-large-frag"          . run-dcps-large-test)
                 ("typelookup-endpoints"     . run-typelookup-endpoints-test)
                 ("sedp-type-gate"           . run-type-gate-test)
                 ("dcps-type-gate"           . run-dcps-type-gate-test)
                 ("dcps-legacy-gate"         . run-dcps-legacy-gate-test)
                 ("perftest-smoke"           . dds.bench:run-bench-smoke)
                 ("perftest-shmem-smoke"     . dds.bench:run-bench-shmem-smoke)
                 ("perftest-zerocopy-smoke"  . dds.bench:run-bench-zerocopy-smoke)
                 ("perftest-keeplast-smoke"  . dds.bench:run-keeplast-bench-smoke)
                 ("shmem-ring-init"          . run-shmem-ring-init-test)
                 ("shmem-lane-claim"         . run-shmem-lane-claim-test)
                 ("shmem-enqueue"            . run-shmem-enqueue-test)
                 ("shmem-drain"              . run-shmem-drain-test)
                 ("shmem-drain-resource-guard" . run-shmem-drain-resource-guard-test)
                 ("zc-pool-init"             . run-zc-pool-init-test)
                 ("zc-pool-loan"             . run-zc-pool-loan-test)
                 ("zc-pool-resolve"          . run-zc-pool-resolve-test)
                 ("zc-pool-align"            . run-zc-pool-align-test)
                 ("zc-loan-acquire"          . run-zc-loan-acquire-test)
                 ("zc-reclaim-skips-loaned"  . run-zc-reclaim-skips-loaned-test)
                 ("zc-release-idempotent"    . run-zc-release-idempotent-test)
                 ("zc-loan-nofreelist"       . run-zc-loan-nofreelist-test)
                 ("zc-lockfree-acquire"      . run-zc-lockfree-acquire-test)
                 ("zc-lockfree-release"      . run-zc-lockfree-release-test)
                 ("zc-lockfree-release-biggen" . run-zc-lockfree-release-biggen-test)
                 ("zc-lockfree-stress"       . run-zc-lockfree-stress-test)
                 ("shmem-transport"          . dds.xport.shmem:run-shmem-transport-test)
                 ("shmem-receiver-thread"    . dds.xport.shmem:run-shmem-receiver-test)
                 ("shmem-stress"             . dds.xport.shmem:run-shmem-stress-test)
                 ("zc-ref-codec"             . run-zc-ref-codec-test)
                 ("zc-sedp-flag"             . run-zc-sedp-flag-test)
                 ("zc-resolve-drop"          . run-zc-resolve-drop-test)
                 ("flatdata-rejects-variable" . run-flatdata-rejects-variable-test)
                 ("flatdata-offsets"         . run-flatdata-offsets-test)
                 ("flatdata-accessor"        . run-flatdata-accessor-test)
                 ("flatdata-zero-alloc"      . run-flatdata-zero-alloc-test)
                 ("flatdata-deser-interop"   . run-flatdata-deser-interop-test)
                 ("flatdata-sap-getter"      . run-flatdata-sap-getter-test)
                 ("flatdata-view-accessor"   . run-flatdata-view-accessor-test)
                 ("flatdata-transcode-xcdr1be" . run-flatdata-transcode-xcdr1be-test)
                 ("flatdata-transcode-xcdr1le" . run-flatdata-transcode-xcdr1le-test)
                 ("flatdata-transcode-xcdr2be" . run-flatdata-transcode-xcdr2be-test)
                 ("flatdata-transcode-native"  . run-flatdata-transcode-native-test)
                 ("flatdata-transcode-rejects-pl" . run-flatdata-transcode-rejects-pl-test)
                 ("durability-store"             . run-durability-store-test)
                 ("durability-spec"              . run-durability-spec-test)
                 ("durability-collect"           . run-durability-collect-test)
                 ("durability-transient"         . run-durability-transient-test)
                 ("durability-runner"            . run-durability-runner-test)
                 ("durability-supervisor"        . run-durability-supervisor-test)
                 ("durability-runner-lifecycle"  . run-durability-runner-lifecycle-test)
                 ("durability-config"            . run-durability-config-test)
                 ("durability-process-smoke"     . run-durability-process-smoke-test)
                 ("durability-writer-rep"        . run-durability-writer-rep-test)
                 ("original-writer-info"         . run-original-writer-info-vector-test)
                 ("data-inline-qos-emit"         . run-data-inline-qos-emit-test)
                 ("relay-emit"                   . run-relay-emit-test)
                 ("original-writer-dedup"        . run-original-writer-dedup-test)
                 ("dedup-cap"                    . run-dedup-cap-test)
                 ("vendor-sedp-pid"              . run-vendor-sedp-pid-test)
                 ("durability-no-double-delivery" . run-durability-no-double-delivery-test)
                 ("durability-multitopic"         . run-durability-multitopic-test)
                 ("durability-dispose-replay"     . run-durability-dispose-replay-test)
                 ("dare-sha384-hkdf-kat"          . run-dare-sha384-hkdf-kat-test)
                 ("dare-aes-gcm-kat"             . run-dare-aes-gcm-kat-test)
                 ("dare-ml-kem-kat"              . run-dare-ml-kem-kat-test)
                 ("dare-envelope"                . run-dare-envelope-test)
                 ("dare-key-provider"            . run-dare-key-provider-test)
                 ("dare-encrypted-store"         . run-dare-encrypted-store-test)
                 ("dare-encrypted-store-lifecycle" . run-dare-encrypted-store-lifecycle-test)
                 ("dare-service-transparency"    . run-dare-service-transparency-test))))
    (dolist (test tests)
      (format t "~&  [test] ~a ... " (car test))
      (funcall (cdr test))
      (format t "ok~%"))
    (format t "~&tests: ~d passed.~%" (length tests))
    t))
