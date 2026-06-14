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

;;; ---- SHMEM ring-drain fuzz ----

(defconstant +fuzz-ring-cap+ 256 "Per-lane ring capacity (bytes) used by the drain fuzz (multiple of 8).")
(defconstant +fuzz-ring-lanes+ 1 "Lane count for the drain fuzz segment.")

(defun* %fuzz-ring-data-off ()
    (function () (integer 0))
  "Byte offset of lane 0's data region in the drain-fuzz segment (1 lane, cap=+fuzz-ring-cap+)."
  (dds.xport.shmem::%lane-data-off +fuzz-ring-lanes+ 0 +fuzz-ring-cap+))

(defun* %fuzz-ring-write-cursor-off ()
    (function () (integer 0))
  "Byte offset of lane 0's write-cursor in the drain-fuzz segment."
  (+ (dds.xport.shmem::%lane-desc-off 0) dds.xport.shmem::+lane-off-write+))

(defun* %fuzz-ring-read-cursor-off ()
    (function () (integer 0))
  "Byte offset of lane 0's read-cursor in the drain-fuzz segment."
  (+ (dds.xport.shmem::%lane-desc-off 0) dds.xport.shmem::+lane-off-read+))

(defun* %adversarial-cursor (prng)
    (function (prng) (unsigned-byte 64))
  "A pseudo-random adversarial cursor value from the PRNG: uniform u64 or a boundary case (0, cap, huge)."
  (let ((pick (prng-int prng 0 7)))
    (case pick
      (0 0)
      (1 +fuzz-ring-cap+)
      (2 (* 10 +fuzz-ring-cap+))
      (3 (1- +fuzz-ring-cap+))
      (4 (ash 1 63))
      (5 (1- (ash 1 64)))
      (t (prng-u64 prng)))))

(defun* gen-ring-drain-fuzz (prng)
    (function (prng) list)
  "A (w r seed) triple for one drain-fuzz iteration: adversarial write/read cursors + a data-fill seed."
  (list (%adversarial-cursor prng) (%adversarial-cursor prng) (prng-next prng)))

(defun* %fill-ring-data-random (sap seed)
    (function (t (unsigned-byte 32)) t)
  "Overwrite the lane-0 data region with deterministic pseudo-random bytes derived from SEED."
  (let ((data-off (%fuzz-ring-data-off)) (x (logand #xFFFFFFFF (max 1 seed))))
    (dotimes (i +fuzz-ring-cap+)
      (setf x (logand #xFFFFFFFF (logxor x (ash x 13))))
      (setf x (logand #xFFFFFFFF (logxor x (ash x -17))))
      (setf x (logand #xFFFFFFFF (logxor x (ash x 5))))
      (setf (cffi:mem-ref sap :uint8 (+ data-off i)) (logand x #xFF)))))

(defun* %fill-ring-data-skip-markers (sap)
    (function (t) t)
  "Write +SKIP-MARKER+ len fields at multiple ring positions to exercise the skip path."
  (let ((data-off (%fuzz-ring-data-off)) (skip dds.xport.shmem::+skip-marker+))
    (setf (cffi:mem-ref sap :uint32 (+ data-off 0)) skip)
    (setf (cffi:mem-ref sap :uint32 (+ data-off 8)) skip)
    (setf (cffi:mem-ref sap :uint32 (+ data-off 128)) skip)))

(defun* fuzz-shmem-ring-drain ()
    (function () t)
  "Property-based fuzz of %LANE-DRAIN: adversarial bytes + cursors, 2000 iterations.
   Verifies: no OOB/error escapes, terminates, callback count bounded by capacity/8."
  (let* ((seg-bytes (dds.xport.shmem::%segment-bytes +fuzz-ring-lanes+ +fuzz-ring-cap+))
         (mem (dds.pal:alloc-static seg-bytes))
         (sap (dds.pal:static-pointer mem))
         (sink (dds.core.buffer:make-octet-buffer +fuzz-ring-cap+))
         (prng (make-prng #xDEADBEEF))
         (max-cbs (+ (truncate +fuzz-ring-cap+ 8) 4))  ; bound: capacity/8 + slack
         (iters 2000))
    (dds.xport.shmem::%ring-init sap +fuzz-ring-lanes+ +fuzz-ring-cap+)
    (unwind-protect
         (dotimes (i iters t)
           (let* ((triple (gen-ring-drain-fuzz prng))
                  (w (first triple)) (r (second triple)) (seed (third triple))
                  ;; every 5th iteration: skip-marker path; every 10th: max-record boundary
                  (use-skip (zerop (mod i 5)))
                  (use-maxr (zerop (mod i 10)))
                  (cbs 0))
             (if use-skip
                 (%fill-ring-data-skip-markers sap)
                 (%fill-ring-data-random sap seed))
             (when use-maxr
               ;; write a max-record len at position 0 to exercise the boundary check
               (setf (cffi:mem-ref sap :uint32 (%fuzz-ring-data-off))
                     (dds.xport.shmem::%ring-max-record sap)))
             (dds.pal:store-sap-u64 sap (%fuzz-ring-write-cursor-off) w)
             (dds.pal:store-sap-u64 sap (%fuzz-ring-read-cursor-off) r)
             ;; the drain is synchronous and non-blocking; no timeout guard needed
             (handler-case
                 (dds.xport.shmem::%lane-drain
                  sap 0 +fuzz-ring-cap+ sink
                  (lambda (buf size) (declare (ignore buf size)) (incf cbs)))
               (error (e)
                 (error 'test-failure :name "shmem-ring-drain-fuzz"
                        :detail (format nil "iter ~d w=~d r=~d signalled: ~a" i w r e))))
             (unless (<= cbs max-cbs)
               (error 'test-failure :name "shmem-ring-drain-fuzz"
                      :detail (format nil "iter ~d w=~d r=~d: ~d callbacks > bound ~d (w-r guard failed)"
                                      i w r cbs max-cbs)))))
      (dds.pal:pshared-destroy sap dds.xport.shmem::+mutex-off+ dds.xport.shmem::+cond-off+)
      (dds.pal:free-static (dds.core.buffer:octet-buffer-vec sink))
      (dds.pal:free-static mem))))

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
    ;; ring-drain fuzz runs independently (its own memory + prng, 2000 iterations)
    (fuzz-shmem-ring-drain)
    (format t "~&  pbt: 6 properties x ~d cases each + ring-drain fuzz 2000 iters, deterministic seed.~%" runs)
    (loop for b across fuzzbufs
          do (dds.pal:free-static (dds.core.buffer:octet-buffer-vec b)))
    (dds.core.arena:pool-release pool buf)
    (dds.core.arena:teardown-arena arena)
    t))
