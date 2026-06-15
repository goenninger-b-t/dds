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
  "WP-ZEROCOPY loan/release (FR-PF-3, ADR 0014): in a 2-slot pool, two loans take distinct slots; a third
   loan force-reclaims the oldest (slot 0) with a bumped generation; releasing a valid (slot,generation)
   succeeds; releasing with a stale generation is a no-op (NIL)."
  (let ((m (dds.pal:alloc-static (dds.xport.zerocopy::%zc-bytes 2 32)))
        (payload (octets 1 2 3 4)))
    (unwind-protect
         (let ((sap (dds.pal:static-pointer m)))
           (dds.xport.zerocopy::%zc-init sap 2 32)
           (multiple-value-bind (i0 g0) (dds.xport.zerocopy::%zc-loan sap payload 0 4 1)
             (multiple-value-bind (i1 g1) (dds.xport.zerocopy::%zc-loan sap payload 0 4 1)
               (%check :zc-loan-i0 (eql i0 0) "first loan must take slot 0")
               (%check :zc-loan-i1 (eql i1 1) "second loan must take slot 1")
               (%check :zc-loan-distinct (/= i0 i1) "two loans must take distinct slots")
               (%check :zc-loan-g0 (= g0 1) "first loan bumps slot 0 generation to 1")
               (%check :zc-loan-g1 (= g1 1) "second loan bumps slot 1 generation to 1")
               ;; pool now full -> third loan force-reclaims the oldest (slot 0, lowest pubseq)
               (multiple-value-bind (i2 g2) (dds.xport.zerocopy::%zc-loan sap payload 0 4 1)
                 (%check :zc-reclaim-oldest (eql i2 0) "third loan must force-reclaim the oldest slot (0)")
                 (%check :zc-reclaim-gen (= g2 2) "force-reclaim must bump slot 0 generation to 2")
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
      (dds.pal:free-static m))))

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
   misaligned without the fix), resolves each back into a sink, asserts byte-exact match, then
   releases each. Without %zc-slot-stride rounding, slot 1+ would be misaligned and the u64 pubseq
   store/load (dds.pal:store/load-sap-u64, documented aligned) would be UB on strict-align targets."
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
                           "slot 2 payload mismatch (misaligned without fix)"))
                 (dds.xport.zerocopy::%zc-release sap i0 g0)
                 (dds.xport.zerocopy::%zc-release sap i1 g1)
                 (dds.xport.zerocopy::%zc-release sap i2 g2))))
           (dds.xport.zerocopy::%zc-destroy sap)
           t)
      (dds.pal:free-static m))))

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

(defun* run-all-tests ()
    (function () t)
  "Run every landed test; signal on first failure, else report and return T."
  (let ((tests '(("md5-rfc1321"               . run-md5-test)
                 ("echo-over-mock-transport" . run-echo-test)
                 ("pal-fence"                . run-pal-fence-test)
                 ("pal-sap-atomics"          . run-pal-sap-atomics-test)
                 ("pal-shm"                  . run-pal-shm-test)
                 ("pal-pshared"              . run-pal-pshared-test)
                 ("xcdr-codec-roundtrip"     . run-codec-roundtrip-test)
                 ("xcdr-byte-exact-seed"     . run-byte-exact-test)
                 ("xcdr-encap-options-pad"   . run-encap-options-pad-test)
                 ("xcdr-generated-type"      . run-generated-type-test)
                 ("xcdr-generated-sequence"  . run-generated-sequence-test)
                 ("xcdr-generated-nested"    . run-generated-nested-test)
                 ("type-support-keyed-p"     . run-keyed-p-test)
                 ("dds-keyhash"              . run-keyhash-test)
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
                 ("batch-defer"              . run-batch-defer-test)
                 ("async-decoupled"          . run-async-decoupled-test)
                 ("shmem-end-to-end"         . run-shmem-end-to-end-test)
                 ("zerocopy-end-to-end"      . run-zerocopy-end-to-end-test)
                 ("flatdata-zerocopy"        . run-flatdata-zerocopy-test)
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
                 ("rtps-reliable-delivery"   . run-reliability-test)
                 ("rtps-writer-pushonce"     . run-writer-pushonce-test)
                 ("rtps-history-purge"       . run-history-purge-test)
                 ("rtps-reader-compaction"   . run-reader-compaction-test)
                 ("purge-reliable-only"      . run-purge-reliable-only-test)
                 ("rtps-gap-handling"        . run-gap-handling-test)
                 ("rtps-reliable-multiwriter" . run-reliable-multiwriter-test)
                 ("property-based"           . run-pbt-tests)
                 ("udp-loopback"             . run-udp-loopback-test)
                 ("rtps-discovery-spdp"      . dds.rtps.discovery:run-discovery-test)
                 ("rtps-discovery-sedp"      . dds.rtps.discovery:run-sedp-test)
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
                 ("dcps-entity-write-take"   . run-dcps-entity-test)
                 ("nokey-roundtrip"          . run-nokey-roundtrip-test)
                 ("dcps-instance-read-take"  . run-dcps-instance-test)
                 ("dcps-dispose-unregister"  . run-dcps-dispose-test)
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
                 ("shmem-ring-init"          . run-shmem-ring-init-test)
                 ("shmem-lane-claim"         . run-shmem-lane-claim-test)
                 ("shmem-enqueue"            . run-shmem-enqueue-test)
                 ("shmem-drain"              . run-shmem-drain-test)
                 ("shmem-drain-resource-guard" . run-shmem-drain-resource-guard-test)
                 ("zc-pool-init"             . run-zc-pool-init-test)
                 ("zc-pool-loan"             . run-zc-pool-loan-test)
                 ("zc-pool-resolve"          . run-zc-pool-resolve-test)
                 ("zc-pool-align"            . run-zc-pool-align-test)
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
                 ("flatdata-deser-interop"   . run-flatdata-deser-interop-test))))
    (dolist (test tests)
      (format t "~&  [test] ~a ... " (car test))
      (funcall (cdr test))
      (format t "ok~%"))
    (format t "~&tests: ~d passed.~%" (length tests))
    t))
