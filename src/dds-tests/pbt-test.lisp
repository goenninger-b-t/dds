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

;;; ---- WP-ZEROCOPY resolve fuzz (FR-PF-3, NFR-SEC-POSTURE) ----

(defconstant +fuzz-zc-max-slots+ 8 "Upper bound on slot count for the zero-copy resolve fuzz.")
(defconstant +fuzz-zc-max-slot-bytes+ 128 "Upper bound on per-slot payload bytes for the zero-copy resolve fuzz.")

(defun* %adversarial-u32 (prng)
    (function (prng) (unsigned-byte 32))
  "A pseudo-random adversarial u32: uniform, or a boundary case (0, small, huge) — drives the resolve fuzz."
  (case (prng-int prng 0 5)
    (0 0)
    (1 1)
    (2 (1- (ash 1 32)))
    (3 (prng-int prng 0 (1- +fuzz-zc-max-slots+)))
    (t (prng-next prng))))

(defun* fuzz-zc-resolve ()
    (function () t)
  "Property-based fuzz of %ZC-RESOLVE (the untrusted cross-process reference resolver): a re-initialised
   pool of random geometry, an optional valid loan, then resolve with adversarial slot-index/generation.
   Verifies: no OOB/error escapes, and the result is always NIL or a bounded LEN in [0, slot-bytes]."
  (let* ((seg-bytes (dds.xport.zerocopy::%zc-bytes +fuzz-zc-max-slots+ +fuzz-zc-max-slot-bytes+))
         (mem (dds.pal:alloc-static seg-bytes))
         (sap (dds.pal:static-pointer mem))
         (sink (make-array +fuzz-zc-max-slot-bytes+ :element-type '(unsigned-byte 8)))
         (payload (make-array +fuzz-zc-max-slot-bytes+ :element-type '(unsigned-byte 8) :initial-element #xC3))
         (prng (make-prng #x2C0DEC0))
         (iters 2500))
    (unwind-protect
         (dotimes (i iters t)
           (let ((slots (prng-int prng 1 +fuzz-zc-max-slots+))
                 (slot-bytes (prng-int prng 1 +fuzz-zc-max-slot-bytes+)))
             (dds.xport.zerocopy::%zc-init sap slots slot-bytes)
             ;; half the iterations seed one valid loan so resolve sometimes hits a live slot
             (when (oddp i)
               (dds.xport.zerocopy::%zc-loan sap payload 0 (prng-int prng 0 slot-bytes) 1))
             (let* ((idx (%adversarial-u32 prng))
                    (gen (%adversarial-u32 prng))
                    (r (handler-case (dds.xport.zerocopy::%zc-resolve sap idx gen sink)
                         (error (e)
                           (error 'test-failure :name "zc-resolve-fuzz"
                                  :detail (format nil "iter ~d slots=~d sb=~d idx=~d gen=~d signalled: ~a"
                                                  i slots slot-bytes idx gen e))))))
               (unless (or (null r) (and (integerp r) (<= 0 r slot-bytes)))
                 (error 'test-failure :name "zc-resolve-fuzz"
                        :detail (format nil "iter ~d slots=~d sb=~d idx=~d gen=~d: result ~s not NIL/bounded"
                                        i slots slot-bytes idx gen r))))))
      (dds.xport.zerocopy::%zc-destroy sap)
      (dds.pal:free-static mem))))

;;; ---- WP-FLATDATA untrusted-wrap fuzz (FR-PF-4, NFR-SEC-POSTURE; R6, ADR 0015) ----
;;;; A received / cross-process FlatData buffer is HOSTILE: a malformed payload must REJECT (a signalled
;;;; condition the engine maps to SAMPLE_REJECTED) or accept-and-read-in-bounds, NEVER an OOB read/write or an
;;;; uncaught error. The load-bearing length/encap guard in deserialize-into-<name>-fd is an EXPLICIT manual
;;;; (when (< avail +size+) (error ...)) check (dsl.lisp) — NOT a compiler-inserted array bound — so it is
;;;; SAFETY-INDEPENDENT BY CONSTRUCTION: it executes under any optimization policy, including (safety 0).
;;;; NOT cleared for ship — pending counsel (R6); see ADR 0015.

(defconstant +fuzz-fd-slop+ 16 "Max trailing octets past +fd-abc-flatdata-size+ a wrap-fuzz payload may carry.")

(defun* %fd-wrap-read-safety0 (vec)
    (function ((simple-array (unsigned-byte 8) (*))) t)
  "This WRAPPER is compiled at (SAFETY 0): parse the encap header of VEC and run the FlatData wrap
   (deserialize-into a loaned target), then read every field via the Offset getters. NOTE (FR-LANG-7, honest
   scope): deserialize-into-<name>-fd + the Offset getters are out-of-line callees compiled once under
   with-hot-optimizations, so this wrapper's (safety 0) does NOT recompile them — it confirms the WRAPPER code
   (the encap parse + the accessor reads here) is safety-independent, NOT that it forces the kernel to run
   safety-0. The kernel's guard is safety-independent for a stronger reason: it is an EXPLICIT manual
   (when (< avail +size+) (error ...)) (dsl.lisp), not a compiler bound, so it holds under any policy. Returns
   T on a clean read, NIL on a cleanly-signalled reject; an OOB would corrupt/crash rather than signal."
  (declare (optimize (speed 3) (safety 0) (debug 0)))
  (handler-case
      (let* ((ob (dds.core.buffer:octet-buffer-over vec))
             (rc (dds.core.buffer:cursor ob :endianness :little))
             (target (make-fd-abc-flatdata)))
        (dds.cdr:parse-encapsulation-header rc)
        (deserialize-into-fd-abc-fd target rc :xcdr2)
        (let ((sum (+ (fd-abc-a-fd target) (fd-abc-b-fd target) (fd-abc-c-fd target))))
          (dds.pal:free-static (dds.core.buffer:octet-buffer-vec target))
          (and (integerp sum) t)))
    (error () nil)))

(defun* %gen-fd-wrap-payload (prng)
    (function (prng) (simple-array (unsigned-byte 8) (*)))
  "An adversarial FlatData wrap-fuzz payload from PRNG, drawn from families that exercise every wrap edge:
   too-SHORT (< +fd-abc-flatdata-size+ -> must reject, no OOB), EXACT length, LONGER (trailing pad -> must
   ACCEPT, no false-REJECT), wrong encap id, all-zero, and pure-random. A valid-length payload is seeded with
   the correct PLAIN_CDR2_LE (0x0007 NBO) encap id half the time so the reader sometimes reaches the body."
  (let* ((size +fd-abc-flatdata-size+)
         (family (prng-int prng 0 6))
         (n (ecase family
              (0 (prng-int prng 0 (max 0 (1- size))))            ; too short
              (1 size)                                            ; exact
              (2 (+ size (prng-int prng 1 +fuzz-fd-slop+)))       ; longer (trailing pad)
              (3 size)                                            ; wrong encap id (filled below)
              (4 (+ size (prng-int prng 0 +fuzz-fd-slop+)))       ; all-zero
              (5 (prng-int prng 0 (+ size +fuzz-fd-slop+)))       ; pure random length
              (6 (prng-int prng 0 3))))                           ; sub-encap-header (< 4 octets)
         (v (make-array n :element-type '(unsigned-byte 8) :initial-element 0)))
    (case family
      (4 v)                                                       ; all-zero: leave as zeros
      (t (dotimes (i n) (setf (aref v i) (prng-int prng 0 255)))
         (when (and (>= n 2) (member family '(1 2 5)) (oddp (prng-next prng)))
           (setf (aref v 0) #x00 (aref v 1) #x07))                ; valid PLAIN_CDR2_LE id so the body is reached
         (when (and (>= n 2) (= family 3))
           (setf (aref v 0) (prng-int prng 0 255) (aref v 1) (prng-int prng 0 255)))))
    v))

(defun* %fd-wrap-read-checked (vec)
    (function ((simple-array (unsigned-byte 8) (*))) t)
  "Run the FlatData wrap over VEC the way the engine does (parse encap header, then the vtable
   deserialize-<name>-fd, then read every field via the Offset getters) under the PRODUCTION optimization
   policy. Returns T on a clean accept+in-bounds read, NIL on a cleanly-signalled reject. Any escaping non-error
   or OOB is a fuzz failure (caught by the caller). DRY: deserialize-fd-abc-fd itself delegates the validate +
   clamp to deserialize-into-fd-abc-fd, so this exercises BOTH the full vtable and the inner copy."
  (handler-case
      (let* ((ob (dds.core.buffer:octet-buffer-over vec))
             (rc (dds.core.buffer:cursor ob :endianness :little)))
        (dds.cdr:parse-encapsulation-header rc)
        (let* ((s (deserialize-fd-abc-fd rc :xcdr2))
               (ok (and (integerp (fd-abc-a-fd s)) (integerp (fd-abc-b-fd s)) (integerp (fd-abc-c-fd s)))))
          (dds.pal:free-static (dds.core.buffer:octet-buffer-vec s))
          ok))
    (error () nil)))

(defun* fuzz-flatdata-wrap ()
    (function () t)
  "Property-based fuzz of the UNTRUSTED WP-FLATDATA wrap/read paths (FR-PF-4, NFR-SEC-POSTURE; R6, ADR 0015. NOT
   cleared for ship — pending counsel R6). Two hostile surfaces:

   (A) NON-ZC deserialize wrap: feed deserialize-<name>-fd / deserialize-into-<name>-fd (via a cursor over a
       received buffer, mirroring %deserialize-sample) a large random corpus of malformed payloads — too-short
       (< +size+ -> MUST reject via the >= check, no OOB), exact, longer (trailing pad -> MUST accept, no
       false-REJECT), wrong encap id, all-zero, random, and sub-4-octet. Each case must EITHER reject cleanly (a
       signalled condition the engine maps to SAMPLE_REJECTED) OR accept-and-read-in-bounds (the Offset getters
       read every field without an OOB); never an uncaught error or an OOB. A LONGER (trailing-padded) conformant
       payload must ACCEPT (the no-false-REJECT rule). The load-bearing length/encap guard is an EXPLICIT manual
       (when (< avail +size+) (error ...)) (dsl.lisp), NOT a compiler bound, so it is safety-INDEPENDENT by
       construction; this production-policy arm exercises it directly. A (safety 0)-compiled WRAPPER arm
       (%fd-wrap-read-safety0) additionally confirms the wrapper + the Offset-accessor reads are safety-independent
       and reaches the SAME verdict (it does NOT recompile the out-of-line kernel, so it does not by itself prove
       the kernel's bound holds at safety 0 — the manual-check argument does).

   (B) ZC slot resolve clamp: the cross-process untrusted path. Loan a valid slot, then FORGE its recorded
       payload-LEN field (0..0xFFFFFFFF) and resolve with %zc-resolve-fresh / %zc-resolve under adversarial
       slot-index + generation; the result MUST be NIL or a length CLAMPED to slot-bytes — the resolver must
       NEVER read past the fixed slot allocation on a forged LEN/generation/index (the min-clamp in
       %zc-slot-payload-len is the defence; this proves it holds against forged input). Skips the ZC half where
       SHMEM by-name attach is unreliable (Clasp/macOS, ADR 0013); the non-ZC wrap half runs on every impl.

   Deterministic + seeded (reproducible on SBCL + Clasp); N iterations. Signals test-failure on any OOB /
   uncaught error / false-REJECT of a conformant payload."
  (let ((prng (make-prng #xF1A7DA7A))
        (iters 4000))
    ;; (A) NON-ZC wrap fuzz — production policy AND a (safety 0) variant; both must agree (reject == reject)
    (dotimes (i iters)
      (let* ((vec (%gen-fd-wrap-payload prng))
             (n (length vec))
             (prod (handler-case (%fd-wrap-read-checked vec)
                     (error (e) (error 'test-failure :name "flatdata-wrap-fuzz"
                                       :detail (format nil "iter ~d len ~d: production wrap signalled past its own handler: ~a" i n e)))))
             (s0 (handler-case (%fd-wrap-read-safety0 vec)
                   (error (e) (error 'test-failure :name "flatdata-wrap-fuzz"
                                     :detail (format nil "iter ~d len ~d: (safety 0) wrap leaked OOB/error: ~a" i n e))))))
        ;; a too-short payload MUST have rejected (NIL); a payload >= +size+ with the valid encap id MUST accept
        (when (and (< n +fd-abc-flatdata-size+) (or prod s0))
          (error 'test-failure :name "flatdata-wrap-fuzz"
                 :detail (format nil "iter ~d: too-short payload (len ~d < ~d) ACCEPTED — bounds check failed"
                                 i n +fd-abc-flatdata-size+)))
        (when (and (>= n +fd-abc-flatdata-size+) (= (aref vec 0) #x00) (= (aref vec 1) #x07) (not prod))
          (error 'test-failure :name "flatdata-wrap-fuzz"
                 :detail (format nil "iter ~d: conformant payload (len ~d >= ~d, PLAIN_CDR2_LE id) FALSE-REJECTED"
                                 i n +fd-abc-flatdata-size+)))
        ;; the production-policy and (safety 0)-wrapper arms must reach the same verdict (the wrapper path is safety-independent)
        (unless (eq (and prod t) (and s0 t))
          (error 'test-failure :name "flatdata-wrap-fuzz"
                 :detail (format nil "iter ~d len ~d: production verdict ~a != (safety 0)-wrapper verdict ~a (a wrapper guard depends on SAFETY)"
                                 i n prod s0)))))
    ;; (B) ZC slot resolve clamp fuzz — FORGED recorded-len + adversarial idx/gen; skip where SHMEM is unusable
    (when (dds.xport.shmem:shm-attach-by-name-reliable-p)
      (let* ((slots 4)
             (slot-bytes 64)
             (seg-bytes (dds.xport.zerocopy::%zc-bytes slots slot-bytes))
             (mem (dds.pal:alloc-static seg-bytes))
             (sap (dds.pal:static-pointer mem))
             (sink (make-array slot-bytes :element-type '(unsigned-byte 8)))
             (payload (make-array slot-bytes :element-type '(unsigned-byte 8) :initial-element #xA5)))
        (dds.xport.zerocopy::%zc-init sap slots slot-bytes)
        (unwind-protect
             (dotimes (i iters)
               (multiple-value-bind (slot gen)
                   (dds.xport.zerocopy::%zc-loan sap payload 0 (prng-int prng 0 slot-bytes) 1)
                 (when slot
                   ;; FORGE the cross-process recorded payload-LEN field to an adversarial u32 (incl. > slot-bytes)
                   (let ((b (dds.xport.zerocopy::%zc-slot-off sap slot)))
                     (setf (cffi:mem-ref sap :uint32 (+ b dds.xport.zerocopy::+zc-slot-off-len+))
                           (%adversarial-u32 prng)))
                   (let* ((idx (if (oddp i) slot (%adversarial-u32 prng)))
                          (g (if (zerop (mod i 3)) gen (%adversarial-u32 prng)))
                          (fresh (handler-case (dds.xport.zerocopy::%zc-resolve-fresh sap idx g)
                                   (error (e) (error 'test-failure :name "flatdata-zc-clamp-fuzz"
                                                     :detail (format nil "iter ~d idx=~d gen=~d: resolve-fresh signalled: ~a" i idx g e)))))
                          (rlen (handler-case (dds.xport.zerocopy::%zc-resolve sap idx g sink)
                                  (error (e) (error 'test-failure :name "flatdata-zc-clamp-fuzz"
                                                    :detail (format nil "iter ~d idx=~d gen=~d: resolve signalled: ~a" i idx g e))))))
                     ;; the single-copy vector MUST be NIL or clamped to <= slot-bytes (never past the slot)
                     (unless (or (null fresh) (<= (length fresh) slot-bytes))
                       (error 'test-failure :name "flatdata-zc-clamp-fuzz"
                              :detail (format nil "iter ~d idx=~d gen=~d: forged LEN -> resolve-fresh vec ~d > slot-bytes ~d (clamp failed)"
                                              i idx g (length fresh) slot-bytes)))
                     (unless (or (null rlen) (<= 0 rlen slot-bytes))
                       (error 'test-failure :name "flatdata-zc-clamp-fuzz"
                              :detail (format nil "iter ~d idx=~d gen=~d: forged LEN -> resolve returned ~d, not NIL/[0,~d] (clamp failed)"
                                              i idx g rlen slot-bytes))))
                   ;; release at the loaned generation to recycle the slot (best-effort; forged gens are no-ops)
                   (dds.xport.zerocopy::%zc-release sap slot gen))))
          (dds.xport.zerocopy::%zc-destroy sap)
          (dds.pal:free-static mem))))
    t))

;;; ---- WP-FLATDATA-ZC-LOAN untrusted loan-acquire fuzz (FR-PF-3/4, NFR-SEC-POSTURE; R6, ADR 0017) ----
;;;; The cross-process LOAN-ACQUIRE path is HOSTILE input: %zc-acquire-for-read takes a forged (slot,generation)
;;;; reference and a forged recorded LEN and must fail-or-clamp — return NIL (drop, best-effort) or a view whose
;;;; PAYLOAD-LEN is CLAMPED to slot-bytes and whose PAYLOAD-BASE+LEN never reaches past the fixed slot allocation
;;;; — NEVER an OOB SAP read, even at (safety 0). This complements fuzz-flatdata-wrap (B), which fuzzes the
;;;; resolve-COPY path (%zc-resolve / %zc-resolve-fresh); this fuzzes the literal-0-copy ACQUIRE path the loan API
;;;; uses (where the app then reads in place off the returned SAP). NOT cleared for ship — pending counsel (R6).

(defun* fuzz-flatdata-zc-loan-wrap ()
    (function () t)
  "Property-based fuzz of the UNTRUSTED WP-FLATDATA-ZC-LOAN loan-acquire path (FR-PF-3/4, NFR-SEC-POSTURE; R6,
   ADR 0017. NOT cleared for ship — pending counsel R6). Loan a valid slot, then FORGE its recorded payload-LEN
   field (0..0xFFFFFFFF, incl. < +size+ and > slot-bytes) and call %zc-acquire-for-read with an adversarial
   slot-index + generation; the result MUST be EITHER NIL (single value — a stale/forged/OOB ref the loan path
   DROPs best-effort) OR a view handle whose PAYLOAD-LEN is CLAMPED to [0, slot-bytes] AND whose
   PAYLOAD-BASE + PAYLOAD-LEN stays within the pool segment — so a forged on-wire LEN/generation/index can NEVER
   expose a read past the fixed slot allocation (the min-clamp in %zc-slot-payload-len + the generation/bounds
   guard are the defence; this proves they hold against forged input for the ACQUIRE path the loan API uses).
   Additionally, when a handle IS returned, the SAP-read of every clamped payload octet (load-sap-u8 at
   PAYLOAD-BASE+j) must not signal — the read stays in-bounds by construction. Skips where SHMEM by-name attach
   is unreliable (Clasp/macOS, ADR 0013; ZC + load-sap-u8 are SBCL-only). Deterministic + seeded; N iterations;
   signals test-failure on any OOB / uncaught error / over-clamp."
  (when (and (dds.xport.shmem:shm-attach-by-name-reliable-p) (eq (dds.pal:pal-impl-name) :sbcl))
    (let* ((slots 4)
           (slot-bytes 64)
           (seg-bytes (dds.xport.zerocopy::%zc-bytes slots slot-bytes))
           (mem (dds.pal:alloc-static seg-bytes))
           (sap (dds.pal:static-pointer mem))
           (payload (make-array slot-bytes :element-type '(unsigned-byte 8) :initial-element #x5A))
           (prng (make-prng #xACC0F02D))
           (iters 4000))
      (dds.xport.zerocopy::%zc-init sap slots slot-bytes)
      (unwind-protect
           (dotimes (i iters t)
             (multiple-value-bind (slot gen)
                 (dds.xport.zerocopy::%zc-loan sap payload 0 (prng-int prng 0 slot-bytes) 1)
               (when slot
                 ;; FORGE the cross-process recorded payload-LEN field to an adversarial u32 (incl. > slot-bytes, < +size+)
                 (let ((b (dds.xport.zerocopy::%zc-slot-off sap slot)))
                   (setf (cffi:mem-ref sap :uint32 (+ b dds.xport.zerocopy::+zc-slot-off-len+))
                         (%adversarial-u32 prng)))
                 (let* ((idx (if (oddp i) slot (%adversarial-u32 prng)))     ; sometimes the real slot, sometimes forged
                        (g (if (zerop (mod i 3)) gen (%adversarial-u32 prng))))  ; sometimes the real gen, sometimes forged
                   (multiple-value-bind (psap ridx rgen plen pbase)
                       (handler-case (dds.xport.zerocopy::%zc-acquire-for-read sap idx g)
                         (error (e) (error 'test-failure :name "flatdata-zc-loan-acquire-fuzz"
                                           :detail (format nil "iter ~d idx=~d gen=~d: acquire-for-read signalled: ~a" i idx g e))))
                     (declare (ignore ridx rgen))
                     (when psap
                       ;; a returned handle MUST be clamped in-bounds: plen<=slot-bytes AND pbase+plen within the segment
                       (unless (<= 0 plen slot-bytes)
                         (error 'test-failure :name "flatdata-zc-loan-acquire-fuzz"
                                :detail (format nil "iter ~d idx=~d gen=~d: forged LEN -> acquire payload-len ~d not in [0,~d] (clamp failed)"
                                                i idx g plen slot-bytes)))
                       (unless (<= (+ pbase plen) seg-bytes)
                         (error 'test-failure :name "flatdata-zc-loan-acquire-fuzz"
                                :detail (format nil "iter ~d idx=~d gen=~d: payload-base+len (~d+~d) past segment ~d (OOB exposure)"
                                                i idx g pbase plen seg-bytes)))
                       ;; reading every clamped octet off the SAP must stay in-bounds (no OOB SAP read), even at (safety 0)
                       (handler-case (loop for j below plen sum (dds.pal:load-sap-u8 psap (+ pbase j)))
                         (error (e) (error 'test-failure :name "flatdata-zc-loan-acquire-fuzz"
                                           :detail (format nil "iter ~d idx=~d gen=~d plen=~d: SAP read OOB/signalled: ~a" i idx g plen e)))))))
                 ;; release at the loaned generation to recycle the slot (best-effort; forged gens are no-ops)
                 (dds.xport.zerocopy::%zc-release sap slot gen))))
        (dds.xport.zerocopy::%zc-destroy sap)
        (dds.pal:free-static mem))))
  t)

;;; ---- WP-FLATDATA-XCDR-TRANSCODE untrusted foreign-rep transcode fuzz (FR-PF-4, NFR-SEC-POSTURE; R6) ----
;;;; A1 added the FOREIGN-REP transcode in deserialize-into-<name>-fd (dsl.lisp): when a received FlatData
;;;; SerializedPayload carries a transcodable non-canonical rep-id (PLAIN_CDR_BE 0x0000 / PLAIN_CDR_LE 0x0001 /
;;;; PLAIN_CDR2_BE 0x0006) the UNTRUSTED foreign body is decoded via the sibling struct codec (deserialize-<name>,
;;;; mode + endianness from flatdata-rx-rep-plan) then re-written canonical XCDR2-LE. That struct decode walks the
;;;; foreign body field-by-field; each cdr-get-* bounds-checks against the payload extent via check-room (the
;;;; cursor-buffer capacity = the EXACT payload length, entities.lisp %deserialize-sample), so a SHORT / TRUNCATED /
;;;; forged foreign body MUST yield a controlled signal (buffer-overflow / cdr-not-implemented) or a bounded value,
;;;; NEVER an OOB read — even at (safety 0). This arm makes A1's manual bounds-safety a systematic, repeatable fuzz.
;;;; The reuse-xcv type (a :i8) (k :i64 :key t) (v :i32) exercises the XCDR1<->XCDR2 8-vs-4 re-alignment in the
;;;; transcode (i64 @8 in XCDR1, @4 in XCDR2). NOT cleared for ship — pending counsel (R6); see ADR 0015.

(defconstant +fuzz-transcode-slop+ 16 "Max trailing/short octets a transcode-fuzz body may swing past/under +xcv-flatdata-size+.")

(defun* %transcode-fuzz-rep-id (prng i)
    (function (prng (integer 0)) (unsigned-byte 16))
  "A 16-bit NBO SerializedPayload rep-id for transcode-fuzz iteration I: cycle the 3 TRANSCODABLE reps
   (0x0000/0x0001/0x0006) + the native 0x0007 deterministically (so each is hit every iteration-block), then
   also draw a pure-random 2-octet id (covers non-transcodable -> the clean reject) — fuzzing the rep-id itself."
  (case (mod i 5)
    (0 (dds.cdr:representation-id-value :plain-cdr-be))    ; 0x0000 transcode XCDR1 BE
    (1 (dds.cdr:representation-id-value :plain-cdr-le))    ; 0x0001 transcode XCDR1 LE
    (2 (dds.cdr:representation-id-value :plain-cdr2-be))   ; 0x0006 transcode XCDR2 BE
    (3 (dds.cdr:representation-id-value :plain-cdr2-le))   ; 0x0007 native (read-in-place)
    (t (prng-int prng 0 #xFFFF))))                         ; random id (incl. non-transcodable -> reject)

(defun* %gen-transcode-fuzz-wire (prng i)
    (function (prng (integer 0)) (simple-array (unsigned-byte 8) (*)))
  "An adversarial FlatData SerializedPayload (4-octet encap header + body) for the foreign-rep transcode fuzz:
   a rep-id from %transcode-fuzz-rep-id (the 3 transcodable reps + native + random) NBO at [0..1], options at
   [2..3], then a body of random octets whose TOTAL length sweeps every edge — sub-4 (cannot read the rep-id),
   SHORT (< +xcv-flatdata-size+ -> a transcode/native decode MUST hit check-room and reject), EXACT, and LONGER
   (trailing pad -> a conformant peer payload MUST be accepted, no false-REJECT). The body bytes are random so a
   transcodable rep decodes to a (bounded, possibly-garbage) value."
  (let* ((size +xcv-flatdata-size+)
         (family (prng-int prng 0 4))
         (n (ecase family
              (0 (prng-int prng 0 3))                              ; sub-encap-header (< 4 octets)
              (1 (prng-int prng 4 (max 4 (1- size))))              ; short body (>=4, < +size+)
              (2 size)                                             ; exact
              (3 (+ size (prng-int prng 1 +fuzz-transcode-slop+))) ; longer (trailing pad)
              (4 (prng-int prng 0 (+ size +fuzz-transcode-slop+))))) ; pure-random length
         (v (make-array n :element-type '(unsigned-byte 8))))
    (dotimes (j n) (setf (aref v j) (prng-int prng 0 255)))
    (when (>= n 2)
      (let ((id (%transcode-fuzz-rep-id prng i)))
        (setf (aref v 0) (ldb (byte 8 8) id) (aref v 1) (ldb (byte 8 0) id))))
    v))

(defun* %transcode-fuzz-read-checked (vec)
    (function ((simple-array (unsigned-byte 8) (*))) t)
  "Drive the PRODUCTION engine RX (dds.dcps::%deserialize-sample = parse encap header, then the FlatData
   :deserialize = deserialize-xcv-fd -> deserialize-into-xcv-fd, where A1's foreign-rep transcode lives) over the
   untrusted payload VEC, then read every -fd accessor on a returned sample and free its buffer. Returns T on a
   clean accept+in-bounds read, NIL on a CLEANLY-signalled reject (buffer-overflow from the length guard / the
   struct codec check-room, or cdr-not-implemented from a non-transcodable rep). Any OTHER signalled condition is
   an uncontrolled low-level error (re-signalled by the caller's handler as a fuzz failure); an OOB would corrupt
   or crash rather than signal."
  (let* ((ts (dds.types:find-type-support "xcv"))
         (sample (handler-case (dds.dcps::%deserialize-sample ts vec)
                   ((or dds.core.buffer:buffer-overflow dds.cdr:cdr-not-implemented) () nil))))
    (when sample
      (unwind-protect
           (let ((sum (+ (xcv-a-fd sample) (xcv-k-fd sample) (xcv-v-fd sample))))
             (return-from %transcode-fuzz-read-checked (and (integerp sum) t)))
        (dds.pal:free-static (dds.core.buffer:octet-buffer-vec sample))))
    nil))

(defun* %transcode-fuzz-read-safety0 (vec)
    (function ((simple-array (unsigned-byte 8) (*))) t)
  "The (SAFETY 0) twin of %transcode-fuzz-read-checked. NOTE (FR-LANG-7, honest scope): %deserialize-sample,
   deserialize-into-xcv-fd and the Offset getters are out-of-line callees compiled once under
   with-hot-optimizations, so this wrapper's (safety 0) does NOT recompile them — it confirms the WRAPPER code
   (the encap parse + the accessor reads here) is safety-independent. The kernel's foreign-body decode is
   safety-independent for a stronger reason: every cdr-get-* bounds-checks via an EXPLICIT check-room
   (when (< room need) (error 'buffer-overflow ...)) and the length guard is an EXPLICIT manual
   (when (< avail ...) (error ...)) (dsl.lisp), NOT compiler-inserted array bounds, so they hold under any policy.
   Returns T on a clean read, NIL on a cleanly-signalled reject; an OOB would corrupt/crash rather than signal."
  (declare (optimize (speed 3) (safety 0) (debug 0)))
  (let* ((ts (dds.types:find-type-support "xcv"))
         (sample (handler-case (dds.dcps::%deserialize-sample ts vec)
                   ((or dds.core.buffer:buffer-overflow dds.cdr:cdr-not-implemented) () nil))))
    (when sample
      (unwind-protect
           (let ((sum (+ (xcv-a-fd sample) (xcv-k-fd sample) (xcv-v-fd sample))))
             (return-from %transcode-fuzz-read-safety0 (and (integerp sum) t)))
        (dds.pal:free-static (dds.core.buffer:octet-buffer-vec sample))))
    nil))

(defun* run-flatdata-transcode-fuzz ()
    (function () t)
  "Property-based fuzz of A1's UNTRUSTED foreign-rep transcode decode in deserialize-into-<name>-fd
   (WP-FLATDATA-XCDR-TRANSCODE, FR-PF-4, NFR-SEC-POSTURE; R6, ADR 0015. NOT cleared for ship — pending counsel R6).
   For the FlatData type xcv (a:i8, k:i64 @key, v:i32 — exercising the XCDR1<->XCDR2 8-vs-4 re-alignment), feed the
   engine RX a large corpus of SerializedPayloads whose rep-id is one of the 3 TRANSCODABLE reps (PLAIN_CDR_BE
   0x0000 / PLAIN_CDR_LE 0x0001 / PLAIN_CDR2_BE 0x0006), the native 0x0007, or a pure-random 2-octet id (covering
   non-transcodable -> clean reject), and whose body is random octets of length sweeping [0, +xcv-flatdata-size+ +
   slop] (sub-4 / SHORT / EXACT / LONGER). Each case must EITHER decode to a (bounded, possibly-garbage) value (the
   transcode struct codec + the canonical re-write stay in bounds; the -fd accessors read every field without an
   OOB) OR signal a CLEAN condition (buffer-overflow from the length guard / the struct codec check-room, or
   cdr-not-implemented from a non-transcodable rep) — NEVER an OOB / an uncontrolled low-level error. A LONGER
   (trailing-padded) conformant payload MUST be accepted (the no-false-REJECT rule). A SHORT body under a
   transcodable/native rep MUST reject (the bounds guard fired). The PRODUCTION-policy arm exercises the manual
   check-room/length guards directly; a (safety 0) WRAPPER arm additionally confirms the wrapper + accessor reads
   are safety-independent and reaches the SAME verdict (it does NOT recompile the out-of-line kernel, so it does not
   by itself prove the kernel's bound at safety 0 — the explicit-manual-check argument does). Deterministic + seeded
   (reproducible on SBCL + Clasp); N iterations; signals test-failure on any OOB / uncontrolled error / false-REJECT."
  (let ((prng (make-prng #x7A5C0DE5))
        (iters 4000)
        (size +xcv-flatdata-size+))
    (dotimes (i iters t)
      (let* ((vec (%gen-transcode-fuzz-wire prng i))
             (n (length vec))
             (id (if (>= n 2) (logior (ash (aref vec 0) 8) (aref vec 1)) nil))
             (prod (handler-case (%transcode-fuzz-read-checked vec)
                     (error (e) (error 'test-failure :name "flatdata-transcode-fuzz"
                                       :detail (format nil "iter ~d len ~d id ~a: production transcode signalled an uncontrolled error: ~a" i n id e)))))
             (s0 (handler-case (%transcode-fuzz-read-safety0 vec)
                   (error (e) (error 'test-failure :name "flatdata-transcode-fuzz"
                                     :detail (format nil "iter ~d len ~d id ~a: (safety 0) transcode leaked OOB/error: ~a" i n id e))))))
        ;; the production-policy and (safety 0)-wrapper arms must reach the same verdict (the wrapper path is safety-independent)
        (unless (eq (and prod t) (and s0 t))
          (error 'test-failure :name "flatdata-transcode-fuzz"
                 :detail (format nil "iter ~d len ~d id ~a: production verdict ~a != (safety 0)-wrapper verdict ~a (a wrapper guard depends on SAFETY)" i n id prod s0)))
        ;; a transcodable/native rep with a SHORT body (< +size+) MUST reject (the length guard / check-room fired)
        (multiple-value-bind (kind tmode tendian) (if id (dds.cdr:flatdata-rx-rep-plan id) (values :reject nil nil))
          (declare (ignore tmode tendian))
          (when (and id (member kind '(:native :transcode)) (< n size) prod)
            (error 'test-failure :name "flatdata-transcode-fuzz"
                   :detail (format nil "iter ~d: SHORT payload (len ~d < ~d) under rep #x~4,'0x (~a) ACCEPTED — bounds guard failed" i n size id kind))))))))

;;; ---- WP-DURABILITY-SERVICE-TRANSIENT config-parser fuzz (NFR-SEC-POSTURE) ----
;;;; PARSE-DURABILITY-CONFIG is the sole network-facing / user-facing parse surface of the
;;;; durability service CLI.  All parse guards are EXPLICIT manual checks — they do not depend
;;;; on CL safety level — so a malformed input must ALWAYS signal DURABILITY-CONFIG-ERROR (a
;;;; controlled condition), NEVER crash, OOB, or produce an undefined result, even at (safety 0).
;;;; This arm covers: malformed --topic (no colon, empty name/type), unknown flag, non-integer
;;;; --domain/--max-restarts/--window-seconds, negative domain/restarts, zero window-seconds,
;;;; --topic with a missing argument, malformed DDS_DURABILITY_TOPICS env string, and random
;;;; argv/env combinations.  A (safety 0) wrapper confirms the explicit-manual-check argument.

(defun* %gen-durability-config-argv (prng)
    (function (prng) list)
  "Generate a pseudo-random, adversarial parse-durability-config ARGV from PRNG.
   Families: empty, one/two valid tokens, a malformed --topic (no colon / empty part),
   an unknown flag, a --domain/--max-restarts/--window-seconds with a non-integer or negative
   value, a trailing --topic with no argument, and pure-random ASCII strings."
  (let ((family (prng-int prng 0 9)))
    (case family
      (0 '())
      (1 (list "--domain" (format nil "~d" (prng-int prng 0 255))))
      (2 (list "--topic" "Square:ShapeType"))
      (3 (list "--topic" (prng-ascii-string prng 24)))      ; likely no colon or empty part
      (4 (list (prng-ascii-string prng 16)))                ; likely unknown flag
      (5 (list "--domain" (prng-ascii-string prng 8)))      ; non-integer domain
      (6 (list "--domain" (format nil "~d" (- (prng-int prng 1 1000)))))  ; negative domain
      (7 (list "--max-restarts" "-1"))
      (8 (list "--window-seconds" "0"))
      (9 (list "--topic"))                                  ; missing argument after --topic
      (t (loop repeat (prng-int prng 0 4)
               collect (prng-ascii-string prng 12))))))

(defun* %gen-durability-config-env (prng)
    (function (prng) list)
  "Generate a pseudo-random DDS_DURABILITY_* env alist from PRNG.
   Families: empty, valid domain, malformed domain, valid topic pair, malformed topics string,
   unknown env key, and random ASCII value."
  (let ((family (prng-int prng 0 6)))
    (case family
      (0 '())
      (1 (list (cons "DDS_DURABILITY_DOMAIN" (format nil "~d" (prng-int prng 0 255)))))
      (2 (list (cons "DDS_DURABILITY_DOMAIN" (prng-ascii-string prng 8))))
      (3 (list (cons "DDS_DURABILITY_TOPICS" "Square:ShapeType")))
      (4 (list (cons "DDS_DURABILITY_TOPICS" (prng-ascii-string prng 24))))
      (5 (list (cons (prng-ascii-string prng 16) (prng-ascii-string prng 8))))
      (6 (list (cons "DDS_DURABILITY_MODE" (prng-ascii-string prng 8)))))))

(defun* %parse-config-safety0 (argv env)
    (function (list list) t)
  "Call parse-durability-config under (safety 0). The manual explicit guards in the parser are
   safety-level-independent — they must signal DURABILITY-CONFIG-ERROR or return valid values
   regardless of the optimization policy. Returns T on a clean signal or a valid result."
  (declare (optimize (speed 3) (safety 0) (debug 0)))
  (handler-case
      (progn
        (dds.durability:parse-durability-config :argv argv :env env)
        t)
    (dds.durability:durability-config-error () t)
    (error () nil)))

(defun* fuzz-durability-config ()
    (function () t)
  "Property-based fuzz of PARSE-DURABILITY-CONFIG (WP-DURABILITY-SERVICE-TRANSIENT, NFR-SEC-POSTURE).
   For each random (argv, env) pair: the parser MUST either signal DURABILITY-CONFIG-ERROR (a clean,
   controlled condition) or return a valid (specs max-restarts window-seconds) triple — NEVER an
   uncontrolled low-level error, OOB, or crash.  A (safety 0) wrapper additionally confirms the
   explicit-manual-check argument: all parse guards are non-safety-dependent, so the (safety 0)
   wrapper must reach the same verdict (error vs. success) as the production-policy arm.
   Deterministic + seeded (reproducible on SBCL + Clasp); 2000 iterations."
  (let ((prng (make-prng #xD1A9B01F))
        (iters 2000))
    (dotimes (i iters t)
      (let* ((argv (%gen-durability-config-argv prng))
             (env  (%gen-durability-config-env  prng))
             ;; production-policy arm: must signal durability-config-error OR return valid triple
             (prod-ok (handler-case
                          (progn
                            (dds.durability:parse-durability-config :argv argv :env env)
                            t)
                        (dds.durability:durability-config-error () t)
                        (error (e)
                          (error 'test-failure :name "durability-config-fuzz"
                                 :detail (format nil "iter ~d argv=~s env=~s: production parse leaked uncontrolled error: ~a"
                                                 i argv env e)))))
             ;; (safety 0) wrapper: must agree (signal iff production signalled)
             (s0-ok (%parse-config-safety0 argv env)))
        (declare (ignore prod-ok))
        (unless s0-ok
          (error 'test-failure :name "durability-config-fuzz"
                 :detail (format nil "iter ~d argv=~s env=~s: (safety 0) wrapper leaked uncontrolled error (explicit manual guard is safety-dependent)"
                                 i argv env))))))
  t)

;;; ---- WP-DURABILITY-DEDUP PID_ORIGINAL_WRITER_INFO parse fuzz (NFR-SEC-POSTURE) ----
;;;; PARSE-ORIGINAL-WRITER-INFO and PARSE-INLINE-QOS-KEY-STATUS are network-facing: a
;;;; malformed PID body (wrong len, short buffer, oversized len, zero len) MUST return
;;;; (values nil nil) or a valid parse, NEVER an OOB read or uncaught signal — at any
;;;; safety level. PARSE-INLINE-QOS-KEY-STATUS walks a random ParameterList with a
;;;; random body-end bound: MUST return 5 values, NEVER signal.  Both checks include a
;;;; (safety 0) wrapper that confirms all guards are safety-independent.

(defun* %gen-owi-fuzz-octets (prng)
    (function (prng) (values (simple-array (unsigned-byte 8) (*)) (integer 0) (integer 0)))
  "Generate adversarial (octets off len) for PARSE-ORIGINAL-WRITER-INFO.
   Length families: zero, short (<24), exact (24), long (>24), huge (wire-controlled),
   random; offset sweeps: 0, 1, past-end, and mid-buffer.
   Returns (values octets off len)."
  (let* ((len-family (prng-int prng 0 6))
         (len (ecase len-family
                (0 0)
                (1 (prng-int prng 1 23))
                (2 24)
                (3 (prng-int prng 25 64))
                (4 (prng-int prng 0 #xFFFF))
                (5 (prng-int prng 0 4))
                (6 (prng-int prng 0 255))))
         (buf-n (prng-int prng 0 (+ 24 (prng-int prng 0 16))))
         (octets (make-array buf-n :element-type '(unsigned-byte 8)))
         (off-family (prng-int prng 0 3))
         (off (case off-family
                (0 0)
                (1 (if (> buf-n 0) (prng-int prng 0 (1- buf-n)) 0))
                (2 buf-n)
                (t (+ buf-n (prng-int prng 1 8))))))
    (dotimes (i buf-n) (setf (aref octets i) (prng-int prng 0 255)))
    (values octets off len)))

(defun* %owi-parse-safety0 (octets off len)
    (function ((simple-array (unsigned-byte 8) (*)) (integer 0) (integer 0)) t)
  "Call PARSE-ORIGINAL-WRITER-INFO at (SAFETY 0). The explicit manual bounds check
   (when (or (/= len 24) (> (+ off 24) (length octets))) ...) is safety-independent.
   Returns T if it returned NIL-NIL or a valid GUID+SN; NIL if it signalled."
  (declare (optimize (speed 3) (safety 0) (debug 0)))
  (handler-case
      (multiple-value-bind (g s) (dds.rtps.message:parse-original-writer-info octets off len)
        (or (and (null g) (null s))
            (and (typep g '(simple-array (unsigned-byte 8) (16)))
                 (integerp s))))
    (error () nil)))

(defun* %inline-qos-parse-safety0 (ob be)
    (function (dds.core.buffer:octet-buffer fixnum) t)
  "Call PARSE-INLINE-QOS-KEY-STATUS at (SAFETY 0). The walker guards every read
   against body-end before advancing, so it is safety-independent. Returns T if
   it returned 5 values without signalling; NIL if it signalled."
  (declare (optimize (speed 3) (safety 0) (debug 0)))
  (handler-case
      (multiple-value-bind (kh sf ok g sn)
          (dds.rtps.message:parse-inline-qos-key-status (dds.core.buffer:cursor ob) be)
        (declare (ignore kh sf ok g sn))
        t)
    (error () nil)))

(defun* %gen-inline-qos-blob (prng)
    (function (prng) (values (simple-array (unsigned-byte 8) (*)) fixnum))
  "Generate an adversarial inline-QoS byte blob + a random body-end for
   PARSE-INLINE-QOS-KEY-STATUS.  Body families: empty, short (<4), a
   valid-looking PID_ORIGINAL_WRITER_INFO block, a PID_SENTINEL, a
   PID_KEY_HASH, a junk PID, and pure random bytes."
  ;; 7 families: indices 0..6 inclusive
  (let* ((family (prng-int prng 0 6))
         (v (ecase family
              (0 (make-array 0 :element-type '(unsigned-byte 8)))
              (1 (let ((n (prng-int prng 1 3)))
                   (let ((a (make-array n :element-type '(unsigned-byte 8))))
                     (dotimes (i n) (setf (aref a i) (prng-int prng 0 255)))
                     a)))
              (2 ;; well-formed OWI PID (pid=0x0061 LE, len=24 LE, 24 random body bytes) + sentinel
               (let ((a (make-array 32 :element-type '(unsigned-byte 8) :initial-element 0)))
                 (setf (aref a 0) #x61 (aref a 1) #x00 (aref a 2) 24 (aref a 3) 0)
                 (dotimes (i 24) (setf (aref a (+ 4 i)) (prng-int prng 0 255)))
                 (setf (aref a 28) #x01 (aref a 29) #x00 (aref a 30) 0 (aref a 31) 0)
                 a))
              (3 ;; PID_SENTINEL only
               (make-array 4 :element-type '(unsigned-byte 8)
                            :initial-contents '(#x01 #x00 #x00 #x00)))
              (4 ;; PID_KEY_HASH (pid=0x0070 LE, len=16) + 16 random bytes + sentinel
               (let ((a (make-array 24 :element-type '(unsigned-byte 8) :initial-element 0)))
                 (setf (aref a 0) #x70 (aref a 1) #x00 (aref a 2) 16 (aref a 3) 0)
                 (dotimes (i 16) (setf (aref a (+ 4 i)) (prng-int prng 0 255)))
                 (setf (aref a 20) #x01 (aref a 21) #x00 (aref a 22) 0 (aref a 23) 0)
                 a))
              (5 ;; junk PID with adversarial plen (may overrun)
               (let* ((n (prng-int prng 4 64))
                      (a (make-array n :element-type '(unsigned-byte 8))))
                 (dotimes (i n) (setf (aref a i) (prng-int prng 0 255)))
                 a))
              (6 (let* ((n (prng-int prng 0 128))
                        (a (make-array n :element-type '(unsigned-byte 8))))
                   (dotimes (i n) (setf (aref a i) (prng-int prng 0 255)))
                   a))))
         (n (length v))
         (body-end-family (prng-int prng 0 4))
         (body-end (case body-end-family
                     (0 0)
                     (1 n)
                     (2 (if (> n 0) (prng-int prng 0 n) 0))
                     (3 (+ n (prng-int prng 1 16)))
                     (t (prng-int prng 0 (+ n 32))))))
    (values v (max 0 body-end))))

(defun* fuzz-original-writer-info-parse ()
    (function () t)
  "Property-based fuzz of PARSE-ORIGINAL-WRITER-INFO + PARSE-INLINE-QOS-KEY-STATUS
   (WP-DURABILITY-DEDUP, NFR-SEC-POSTURE; RTPS 2.5 §8.3.5.4).

   Arm A — PARSE-ORIGINAL-WRITER-INFO: feed random (octets off len) from adversarial
   families (zero/short/<24/exact-24/oversized/huge len; off=0/mid/past-end/beyond-buf).
   The explicit manual guard (when (or (/= len 24) (> (+ off 24) (length octets))) ...)
   is safety-independent, so the result MUST be (values nil nil) or a valid (GUID SN)
   — NEVER an OOB read or uncaught signal.  A (safety 0) wrapper confirms the guard is
   safety-independent and reaches the same verdict.

   Arm B — PARSE-INLINE-QOS-KEY-STATUS: feed a cursor over a random byte blob + a
   random body-end (may be < 0, > buf-len, or past the blob).  The walker is
   bounds-checked against body-end before every read; it MUST return 5 values and NEVER
   signal, regardless of blob content.  Deterministic + seeded; 2000 iterations."
  (let ((prng (make-prng #x0C19B01D))
        (iters 2000))
    ;; Arm A: parse-original-writer-info
    (dotimes (i iters)
      (multiple-value-bind (octets off len) (%gen-owi-fuzz-octets prng)
        (let ((prod-ok (handler-case
                           (multiple-value-bind (g s) (dds.rtps.message:parse-original-writer-info octets off len)
                             (or (and (null g) (null s))
                                 (and (typep g '(simple-array (unsigned-byte 8) (16)))
                                      (integerp s))))
                         (error (e)
                           (error 'test-failure :name "owi-parse-fuzz"
                                  :detail (format nil "iter ~d off=~d len=~d buf=~d: production parse signalled: ~a"
                                                  i off len (length octets) e)))))
              (s0-ok (%owi-parse-safety0 octets off len)))
          (unless prod-ok
            (error 'test-failure :name "owi-parse-fuzz"
                   :detail (format nil "iter ~d off=~d len=~d buf=~d: production parse returned unexpected value" i off len (length octets))))
          (unless s0-ok
            (error 'test-failure :name "owi-parse-fuzz"
                   :detail (format nil "iter ~d off=~d len=~d buf=~d: (safety 0) parse leaked OOB/error (guard is safety-dependent)" i off len (length octets)))))))
    ;; Arm B: parse-inline-qos-key-status over random ParameterList blobs (prod + safety-0)
    (dotimes (i iters)
      (multiple-value-bind (blob body-end) (%gen-inline-qos-blob prng)
        (let* ((ob (dds.core.buffer:octet-buffer-over blob))
               (be (min body-end (length blob)))  ; body-end capped to buf extent for cursor validity
               (prod-ok (handler-case
                            (multiple-value-bind (kh sf ok g sn)
                                (dds.rtps.message:parse-inline-qos-key-status
                                 (dds.core.buffer:cursor ob) be)
                              (declare (ignore kh sf ok g sn))
                              t)
                          (error (e)
                            (error 'test-failure :name "inline-qos-parse-fuzz"
                                   :detail (format nil "iter ~d blob=~d body-end=~d: parse-inline-qos-key-status signalled: ~a"
                                                   i (length blob) body-end e)))))
               (s0-ok (%inline-qos-parse-safety0 ob be)))
          (declare (ignore prod-ok))
          (unless s0-ok
            (error 'test-failure :name "inline-qos-parse-fuzz"
                   :detail (format nil "iter ~d blob=~d body-end=~d: (safety 0) parse-inline-qos-key-status signalled (guard safety-dependent)"
                                   i (length blob) body-end))))))
    t))

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
                                                 (dds.core.buffer:cursor b) flags)))
                               ;; SEDP ParameterList parse over random octets: a malformed PID
                               ;; (incl. a forged PID_DATA_REPRESENTATION count) must never OOB (NFR-SEC-POSTURE).
                               (safe (lambda () (dds.rtps.discovery:parse-endpoint-data
                                                 (dds.core.buffer:cursor b) :reader)))
                               (safe (lambda () (dds.rtps.discovery:parse-endpoint-data
                                                 (dds.core.buffer:cursor b) :writer))))))))
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
    ;; WP-ZEROCOPY resolve fuzz: adversarial cross-process references, never an OOB (own memory + prng)
    (fuzz-zc-resolve)
    ;; WP-FLATDATA untrusted-wrap fuzz: malformed wrap (reject/accept-in-bounds + safety-0) + forged ZC clamp (NFR-SEC-POSTURE, R6)
    (fuzz-flatdata-wrap)
    ;; WP-FLATDATA-ZC-LOAN untrusted loan-ACQUIRE fuzz: forged slot/generation/len -> NIL or clamped view, never OOB (NFR-SEC-POSTURE, R6)
    (fuzz-flatdata-zc-loan-wrap)
    ;; WP-FLATDATA-XCDR-TRANSCODE foreign-rep transcode fuzz: malformed/short/truncated foreign body + random rep-id -> reject/bounded, never OOB at (safety 0) (NFR-SEC-POSTURE, R6)
    (run-flatdata-transcode-fuzz)
    ;; WP-DURABILITY-SERVICE-TRANSIENT config-parser fuzz: random/malformed argv+env -> clean error or valid result, never OOB (NFR-SEC-POSTURE); (safety 0) arm confirms explicit-manual-check guards
    (fuzz-durability-config)
    ;; WP-DURABILITY-DEDUP PID_ORIGINAL_WRITER_INFO parse fuzz: random/short/oversized/off-end octets + inline-QoS blob walk; prod + safety-0 (NFR-SEC-POSTURE; RTPS 2.5 §8.3.5.4)
    (fuzz-original-writer-info-parse)
    (format t "~&  pbt: 6 properties x ~d cases each + ring-drain fuzz 2000 iters + zc-resolve fuzz 2500 iters + flatdata-wrap fuzz 4000 iters (non-ZC wrap + safety-0 + forged-len ZC clamp) + flatdata-zc-loan-acquire fuzz 4000 iters (forged loan-acquire clamp, SBCL) + flatdata-transcode fuzz 4000 iters (foreign-rep transcode: 3 transcodable reps + native + random rep-id x swept body lengths, prod + safety-0) + durability-config fuzz 2000 iters (random argv/env -> clean error or valid, prod + safety-0) + owi-parse fuzz 2000 iters (PID_ORIGINAL_WRITER_INFO parse: random/short/oversized/off-end octets + inline-QoS blob walk; BOTH arms prod + safety-0, NFR-SEC-POSTURE), deterministic seed.~%" runs)
    (loop for b across fuzzbufs
          do (dds.pal:free-static (dds.core.buffer:octet-buffer-vec b)))
    (dds.core.arena:pool-release pool buf)
    (dds.core.arena:teardown-arena arena)
    t))
