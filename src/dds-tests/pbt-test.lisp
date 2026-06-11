(in-package #:dds.tests)

;;;; Property-based testing harness (NFR-TEST). Dependency-free and deterministic:
;;;; a seeded xorshift32 PRNG gives reproducible, non-flaky runs on SBCL + Clasp.
;;;; Properties: CDR codec round-trip, SequenceNumber/Set round-trip, and parser
;;;; robustness against random bytes (the fuzz gate, NFR-SEC-POSTURE). Shrinking
;;;; is not implemented; the first failing input is reported verbatim.

(defstruct* (prng (:constructor %make-prng))
  "Deterministic PRNG state for reproducible property-based-test generators (seeded; no Math.random/time dependency)."
  (state 1 :type (unsigned-byte 32)))

(defun* make-prng (seed)
    (function (integer) prng)
  "Construct a deterministic test PRNG seeded by SEED (reproducible property-based-test generator)."
  (%make-prng :state (logand #xFFFFFFFF (max 1 seed))))

(defun* prng-next (prng)
    (function (prng) (unsigned-byte 32))
  "xorshift32 — portable, deterministic, fixnum-friendly on 64-bit."
  (let ((x (prng-state prng)))
    (setf x (logand #xFFFFFFFF (logxor x (ash x 13))))
    (setf x (logand #xFFFFFFFF (logxor x (ash x -17))))
    (setf x (logand #xFFFFFFFF (logxor x (ash x 5))))
    (setf (prng-state prng) x)))

(defun* prng-int (prng lo hi)
    (function (prng integer integer) integer)
  "A pseudo-random integer in [LO, HI] from PRNG (advances its state)."
  (+ lo (mod (prng-next prng) (1+ (- hi lo)))))

(defun* prng-i32 (prng)
    (function (prng) (signed-byte 32))
  "A pseudo-random signed 32-bit integer from PRNG."
  (let ((u (prng-next prng))) (if (>= u #x80000000) (- u #x100000000) u)))

(defun* prng-u64 (prng)
    (function (prng) (unsigned-byte 64))
  "A pseudo-random unsigned 64-bit integer from PRNG."
  (logior (ash (prng-next prng) 32) (prng-next prng)))

(defun* prng-i64 (prng)
    (function (prng) (signed-byte 64))
  "A pseudo-random signed 64-bit integer from PRNG."
  (let ((u (prng-u64 prng))) (if (>= u (ash 1 63)) (- u (ash 1 64)) u)))

(defun* prng-ascii-string (prng maxlen)
    (function (prng (integer 0)) string)
  "A pseudo-random printable-ASCII string of length up to MAX from PRNG."
  (let* ((n (prng-int prng 0 maxlen)) (s (make-string n)))
    (dotimes (i n) (setf (char s i) (code-char (prng-int prng 32 126))))
    s))

(defun* check-property (name prng n generator property)
    (function (t prng (integer 0) function function) t)
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

(defun* gsample= (a b)
    (function (gsample gsample) t)
  "Field-by-field equality of two GSAMPLE generated test structs."
  (and (= (gsample-id a) (gsample-id b))
       (= (gsample-ts a) (gsample-ts b))
       (string= (gsample-label a) (gsample-label b))))

(defun* gen-gsample (prng)
    (function (prng) gsample)
  "Generate a pseudo-random GSAMPLE from PRNG (property-based-test input)."
  (make-gsample :id (prng-i32 prng) :ts (prng-i64 prng)
                :label (prng-ascii-string prng 16)))

(defun* %cdr-rt (s buf mode)
    (function (gsample dds.core.buffer:octet-buffer symbol) t)
  "Round-trip GSAMPLE S through the XCDR codec into BUF in MODE and return the decoded value."
  (serialize-gsample s (dds.core.buffer:cursor buf :endianness :little) mode)
  (gsample= s (deserialize-gsample (dds.core.buffer:cursor buf :endianness :little) mode)))

(defun* %seqnum-rt (v buf)
    (function (integer dds.core.buffer:octet-buffer) t)
  "Round-trip a sequence number through its RTPS wire codec and return the decoded value."
  (dds.rtps.message:write-sequence-number (dds.core.buffer:cursor buf :endianness :little) v)
  (= v (dds.rtps.message:read-sequence-number
        (dds.core.buffer:cursor buf :endianness :little))))

(defun* gen-snset (prng)
    (function (prng) list)
  "Generate a pseudo-random RTPS SequenceNumberSet from PRNG."
  (let* ((base (prng-int prng 1 1000000))
         (numbits (prng-int prng 0 256))
         (words (ceiling numbits 32))
         (bm (make-array (max 1 words) :element-type '(unsigned-byte 32) :initial-element 0)))
    (dotimes (i words) (setf (aref bm i) (prng-next prng)))
    (list base numbits bm)))

(defun* %snset-rt (snset buf)
    (function (list dds.core.buffer:octet-buffer) t)
  "Round-trip SNSET through its RTPS wire codec and return the decoded value."
  (destructuring-bind (base numbits bm) snset
    (dds.rtps.message:write-sequence-number-set
     (dds.core.buffer:cursor buf :endianness :little) base numbits bm)
    (multiple-value-bind (b2 nb2 bm2)
        (dds.rtps.message:read-sequence-number-set
         (dds.core.buffer:cursor buf :endianness :little))
      (and b2 (= base b2) (= numbits nb2)
           (loop for i below (ceiling numbits 32) always (= (aref bm i) (aref bm2 i)))))))

(defun* gen-fuzz-buffers ()
    (function () simple-vector)
  "Generate a list of pseudo-random octet buffers for the parser fuzz tests."
  (map 'simple-vector (lambda (n) (dds.core.buffer:make-octet-buffer n))
       #(1 3 4 8 12 16 20 24 28 32 48 64)))

(defun* gen-fuzz (prng fuzzbufs)
    (function (prng simple-vector) list)
  "Pick a pre-allocated buffer, overwrite it with random octets; return
   (buffer random-flags random-octets-to-next)."
  (let* ((buf (svref fuzzbufs (prng-int prng 0 (1- (length fuzzbufs)))))
         (vec (dds.core.buffer:octet-buffer-vec buf)))
    (dotimes (i (dds.core.buffer:octet-buffer-capacity buf))
      (setf (aref vec i) (prng-int prng 0 255)))
    (list buf (prng-int prng 0 255) (prng-int prng 0 65535))))

(defun* gen-tl-seeds ()
    (function () simple-vector)
  "Build one VALID serialized TypeLookup_Request, TypeLookup_Reply, and MinimalTypeObject
   each (small inputs via the dds.types serializers); the truncation/mutation fuzz seeds."
  (let ((guid (make-array 16 :element-type '(unsigned-byte 8) :initial-element 7))
        (hash (make-array 14 :element-type '(unsigned-byte 8) :initial-element 3))
        (cont (make-array 4 :element-type '(unsigned-byte 8) :initial-element 9))
        (tobj (make-array 8 :element-type '(unsigned-byte 8) :initial-element 0)))
    ;; tobj = DHEADER-prefixed TypeObject octets: LE size 4 + 4 payload octets
    (setf (aref tobj 0) 4)
    (vector (dds.types:serialize-type-lookup-request
             :writer-guid guid :sn 1 :instance-name "tl" :operation :get-deps
             :type-ids (list hash) :continuation cont)
            (dds.types:serialize-type-lookup-reply
             :related-guid guid :related-sn 1 :operation :get-types
             :pairs (list (cons hash tobj)))
            (dds.types:minimal-type-object-octets
             (dds.types:make-minimal-struct-type
              :name "z" :extensibility :final
              :members (list (dds.types:make-struct-member
                              "x" 0 (dds.types:primitive-type-identifier :i32))
                             (dds.types:make-struct-member
                              "s" 1 (dds.types:primitive-type-identifier :string)
                              :key-p t)))))))

(defun* gen-tl-fuzz (prng seeds)
    (function (prng simple-vector) (simple-array (unsigned-byte 8) (*)))
  "A TypeLookup-parser fuzz input from one of three families: pure-random octets,
   a truncation of a valid sample, or a byte-mutated copy of a valid sample."
  (let ((seed (svref seeds (prng-int prng 0 (1- (length seeds))))))
    (ecase (prng-int prng 0 2)
      (0 (let* ((n (prng-int prng 0 96))
                (v (make-array n :element-type '(unsigned-byte 8))))
           (dotimes (i n) (setf (aref v i) (prng-int prng 0 255)))
           v))
      (1 (subseq seed 0 (prng-int prng 0 (length seed))))
      (2 (let ((v (copy-seq seed)))
           (dotimes (k (prng-int prng 1 8))
             (setf (aref v (prng-int prng 0 (1- (length v))))
                   (prng-int prng 0 255)))
           v)))))

(defun* run-pbt-tests ()
    (function () t)
  "Run all property-based tests; signal test-failure on the first falsification."
  (let* ((arena (dds.core.arena:init-arena :bytes (* 256 1024)))
         (pool (dds.core.arena:make-buffer-pool arena 1024 1))
         (buf (dds.core.arena:pool-acquire pool))
         (prng (make-prng #x12345678))
         (runs 400)
         (fuzzbufs (gen-fuzz-buffers))
         (tlseeds (gen-tl-seeds)))
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
                                                 (dds.core.buffer:cursor b) flags octets)))
                               (safe (lambda () (dds.rtps.message:read-fragment-number-set
                                                 (dds.core.buffer:cursor b))))
                               (safe (lambda () (dds.rtps.message:parse-heartbeat-frag-body
                                                 (dds.core.buffer:cursor b) flags)))
                               (safe (lambda () (dds.rtps.message:parse-nack-frag-body
                                                 (dds.core.buffer:cursor b) flags))))))))
    ;; TypeLookup + TypeObject parsers contract NEVER-signal: no safe-wrap, a signal fails
    ;; RUNS (not 4x): each case feeds all three parsers and rejects signal internally (Clasp cost)
    (check-property "typelookup-parser-fuzz-no-signal" prng runs
                    (lambda (p) (gen-tl-fuzz p tlseeds))
                    (lambda (v)
                      (let ((rq (dds.types:parse-type-lookup-request v))
                            (rp (dds.types:parse-type-lookup-reply v))
                            (rm (dds.types:parse-minimal-type-object v)))
                        (and (member rq '(nil :get-types :get-deps :unknown))
                             (member rp '(nil :get-types :get-deps :unknown))
                             (or (member rm '(nil :unsupported))
                                 (typep rm 'dds.types:minimal-struct-type))
                             t))))
    ;; legacy-TypeObject tokenizer NEVER-signal: result is NIL or an lto-node (no error type)
    ;; seeds: inflated C_Shape LB (the real wire capture) + the three TypeLookup seeds (cross-feed)
    (let* ((lto-inflated (dds.types:inflate-type-object-lb (%connext-c-shape-lb)))
           (lto-seeds (concatenate 'simple-vector (vector lto-inflated) tlseeds)))
      (check-property "lto-tokenizer-fuzz-no-signal" prng runs
                      (lambda (p) (gen-tl-fuzz p lto-seeds))
                      (lambda (v)
                        (let ((result (dds.types:tokenize-legacy-type-object v)))
                          (or (null result) (dds.types:lto-node-p result))))))
    (format t "~&  pbt: 6 properties x ~d cases each, deterministic seed.~%" runs)
    (loop for b across fuzzbufs
          do (dds.pal:free-static (dds.core.buffer:octet-buffer-vec b)))
    (dds.core.arena:pool-release pool buf)
    (dds.core.arena:teardown-arena arena)
    t))
