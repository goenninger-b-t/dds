(in-package #:dds.tests)

;;;; Property-based testing harness (NFR-TEST). Dependency-free and deterministic:
;;;; a seeded xorshift32 PRNG gives reproducible, non-flaky runs on SBCL + Clasp.
;;;; Properties: CDR codec round-trip, SequenceNumber/Set round-trip, and parser
;;;; robustness against random bytes (the fuzz gate, NFR-SEC-POSTURE). Shrinking
;;;; is not implemented; the first failing input is reported verbatim.

(defstruct (prng (:constructor %make-prng))
  (state 1 :type (unsigned-byte 32)))

(declaim (ftype (function (integer) prng) make-prng))
(defun make-prng (seed)
  (%make-prng :state (logand #xFFFFFFFF (max 1 seed))))

(declaim (ftype (function (prng) (unsigned-byte 32)) prng-next))
(defun prng-next (prng)
  "xorshift32 — portable, deterministic, fixnum-friendly on 64-bit."
  (let ((x (prng-state prng)))
    (setf x (logand #xFFFFFFFF (logxor x (ash x 13))))
    (setf x (logand #xFFFFFFFF (logxor x (ash x -17))))
    (setf x (logand #xFFFFFFFF (logxor x (ash x 5))))
    (setf (prng-state prng) x)))

(declaim (ftype (function (prng integer integer) integer) prng-int))
(defun prng-int (prng lo hi)
  (+ lo (mod (prng-next prng) (1+ (- hi lo)))))

(declaim (ftype (function (prng) (signed-byte 32)) prng-i32))
(defun prng-i32 (prng)
  (let ((u (prng-next prng))) (if (>= u #x80000000) (- u #x100000000) u)))

(declaim (ftype (function (prng) (unsigned-byte 64)) prng-u64))
(defun prng-u64 (prng)
  (logior (ash (prng-next prng) 32) (prng-next prng)))

(declaim (ftype (function (prng) (signed-byte 64)) prng-i64))
(defun prng-i64 (prng)
  (let ((u (prng-u64 prng))) (if (>= u (ash 1 63)) (- u (ash 1 64)) u)))

(declaim (ftype (function (prng (integer 0)) string) prng-ascii-string))
(defun prng-ascii-string (prng maxlen)
  (let* ((n (prng-int prng 0 maxlen)) (s (make-string n)))
    (dotimes (i n) (setf (char s i) (code-char (prng-int prng 32 126))))
    s))

(declaim (ftype (function (t prng (integer 0) function function) t) check-property))
(defun check-property (name prng n generator property)
  "Run PROPERTY over N inputs from (GENERATOR prng). PROPERTY returns generalized
   boolean; a NIL result or any signalled error fails the property, reporting the
   first offending input (no shrinking)."
  (dotimes (i n)
    (let* ((input (funcall generator prng))
           (ok (handler-case (funcall property input)
                 (error (e)
                   (error 'test-failure :name name
                          :detail (format nil "case ~d input ~s signalled: ~a" i input e))))))
      (unless ok
        (error 'test-failure :name name
               :detail (format nil "case ~d falsified for input ~s" i input)))))
  t)

;;; ---- generators + properties ----

(declaim (ftype (function (gsample gsample) t) gsample=))
(defun gsample= (a b)
  (and (= (gsample-id a) (gsample-id b))
       (= (gsample-ts a) (gsample-ts b))
       (string= (gsample-label a) (gsample-label b))))

(declaim (ftype (function (prng) gsample) gen-gsample))
(defun gen-gsample (prng)
  (make-gsample :id (prng-i32 prng) :ts (prng-i64 prng)
                :label (prng-ascii-string prng 16)))

(declaim (ftype (function (gsample dds.core.buffer:octet-buffer symbol) t) %cdr-rt))
(defun %cdr-rt (s buf mode)
  (serialize-gsample s (dds.core.buffer:cursor buf :endianness :little) mode)
  (gsample= s (deserialize-gsample (dds.core.buffer:cursor buf :endianness :little) mode)))

(declaim (ftype (function (integer dds.core.buffer:octet-buffer) t) %seqnum-rt))
(defun %seqnum-rt (v buf)
  (dds.rtps.message:write-sequence-number (dds.core.buffer:cursor buf :endianness :little) v)
  (= v (dds.rtps.message:read-sequence-number
        (dds.core.buffer:cursor buf :endianness :little))))

(declaim (ftype (function (prng) list) gen-snset))
(defun gen-snset (prng)
  (let* ((base (prng-int prng 1 1000000))
         (numbits (prng-int prng 0 256))
         (words (ceiling numbits 32))
         (bm (make-array (max 1 words) :element-type '(unsigned-byte 32) :initial-element 0)))
    (dotimes (i words) (setf (aref bm i) (prng-next prng)))
    (list base numbits bm)))

(declaim (ftype (function (list dds.core.buffer:octet-buffer) t) %snset-rt))
(defun %snset-rt (snset buf)
  (destructuring-bind (base numbits bm) snset
    (dds.rtps.message:write-sequence-number-set
     (dds.core.buffer:cursor buf :endianness :little) base numbits bm)
    (multiple-value-bind (b2 nb2 bm2)
        (dds.rtps.message:read-sequence-number-set
         (dds.core.buffer:cursor buf :endianness :little))
      (and b2 (= base b2) (= numbits nb2)
           (loop for i below (ceiling numbits 32) always (= (aref bm i) (aref bm2 i)))))))

(declaim (ftype (function () simple-vector) gen-fuzz-buffers))
(defun gen-fuzz-buffers ()
  (map 'simple-vector (lambda (n) (dds.core.buffer:make-octet-buffer n))
       #(1 3 4 8 12 16 20 24 28 32 48 64)))

(declaim (ftype (function (prng simple-vector) list) gen-fuzz))
(defun gen-fuzz (prng fuzzbufs)
  "Pick a pre-allocated buffer, overwrite it with random octets; return
   (buffer random-flags random-octets-to-next)."
  (let* ((buf (svref fuzzbufs (prng-int prng 0 (1- (length fuzzbufs)))))
         (vec (dds.core.buffer:octet-buffer-vec buf)))
    (dotimes (i (dds.core.buffer:octet-buffer-capacity buf))
      (setf (aref vec i) (prng-int prng 0 255)))
    (list buf (prng-int prng 0 255) (prng-int prng 0 65535))))

(declaim (ftype (function () t) run-pbt-tests))
(defun run-pbt-tests ()
  "Run all property-based tests; signal test-failure on the first falsification."
  (let* ((arena (dds.core.arena:init-arena :bytes (* 256 1024)))
         (pool (dds.core.arena:make-buffer-pool arena 1024 1))
         (buf (dds.core.arena:pool-acquire pool))
         (prng (make-prng #x12345678))
         (runs 400)
         (fuzzbufs (gen-fuzz-buffers)))
    (check-property "cdr-roundtrip-xcdr1+2" prng runs #'gen-gsample
                    (lambda (s) (and (%cdr-rt s buf :xcdr1) (%cdr-rt s buf :xcdr2))))
    (check-property "sequence-number-roundtrip" prng runs #'prng-i64
                    (lambda (v) (%seqnum-rt v buf)))
    (check-property "sequence-number-set-roundtrip" prng runs #'gen-snset
                    (lambda (snset) (%snset-rt snset buf)))
    (check-property "rtps-parser-fuzz-no-oob" prng (* 4 runs)
                    (lambda (p) (gen-fuzz p fuzzbufs))
                    (lambda (case)
                      (destructuring-bind (b flags octets) case
                        (flet ((safe (thunk)
                                 (handler-case (progn (funcall thunk) t) (error () nil))))
                          (and (safe (lambda () (dds.rtps.message:parse-header
                                                 (dds.core.buffer:cursor b))))
                               (safe (lambda () (dds.rtps.message:parse-submessage-header
                                                 (dds.core.buffer:cursor b))))
                               (safe (lambda () (dds.rtps.message:read-sequence-number-set
                                                 (dds.core.buffer:cursor b))))
                               (safe (lambda () (dds.rtps.message:parse-heartbeat-body
                                                 (dds.core.buffer:cursor b) flags)))
                               (safe (lambda () (dds.rtps.message:parse-acknack-body
                                                 (dds.core.buffer:cursor b) flags)))
                               (safe (lambda () (dds.rtps.message:parse-gap-body
                                                 (dds.core.buffer:cursor b) flags)))
                               (safe (lambda () (dds.rtps.message:parse-data-body
                                                 (dds.core.buffer:cursor b) flags octets)))
                               (safe (lambda () (dds.rtps.message:parse-data-frag-body
                                                 (dds.core.buffer:cursor b) flags octets))))))))
    (format t "~&  pbt: 4 properties x ~d cases each, deterministic seed.~%" runs)
    (loop for b across fuzzbufs
          do (dds.pal:free-static (dds.core.buffer:octet-buffer-vec b)))
    (dds.core.arena:pool-release pool buf)
    (dds.core.arena:teardown-arena arena)
    t))
