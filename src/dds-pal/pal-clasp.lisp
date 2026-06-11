;;;; DDS.PAL — Clasp (boehmprecise) implementation of the L0 contract.
;;;; This file is the ONLY M0 location permitted to carry #+clasp conditionals.

(in-package #:dds.pal)

#-clasp
(eval-when (:compile-toplevel :load-toplevel :execute)
  (warn "pal-clasp.lisp loaded on a non-Clasp build; capabilities will stub out."))


(defun* pal-impl-name ()
    (function () keyword)
  "Return a keyword naming the running implementation."
  #+clasp :clasp
  #-clasp :unknown)

;;; ---- memory: off-heap, non-GC'd, raw-pointer-addressable ----

(defvar *static-pool* (make-hash-table :test #'eql)
  "Length-keyed recycle pool for ALLOC-STATIC vectors on Clasp (length -> list of
   free vectors). Clasp's GCTOOLS:DEALLOCATE-UNMANAGED-INSTANCE (the backend of
   STATIC-VECTORS:FREE-STATIC-VECTOR) passes the object pointer — an interior
   pointer of the malloc'd header block — to GC_free, which corrupts Boehm's
   small-object freelists and crashes later allocations (SIGILL/SIGSEGV inside
   GC_malloc_kind). FREE-STATIC therefore never truly deallocates on Clasp; it
   recycles through this pool. Bounded by the peak number of live static vectors
   per size. Documented NFR-PORT gap until the upstream deallocator is fixed.")

(defvar *static-pool-lock* (bordeaux-threads:make-lock "dds-static-pool")
  "Guards *STATIC-POOL*: FREE-STATIC also runs on receiver threads.")

(defun* alloc-static (n-bytes)
    (function ((integer 0)) (simple-array (unsigned-byte 8) (*)))
  "Allocate N-BYTES of off-heap octet memory the GC neither scans, moves, nor
   reclaims. Returns a foreign-backed (unsigned-byte 8) vector with a stable
   address; contents unspecified. The single representation stable across all
   three target GCs. On Clasp, satisfied from *STATIC-POOL* when a free vector
   of exactly N-BYTES exists (recycled vectors are zero-filled as hygiene)."
  (declare (type (integer 0) n-bytes))
  (let ((recycled (bordeaux-threads:with-lock-held (*static-pool-lock*)
                    (let ((free (gethash n-bytes *static-pool*)))
                      (when free
                        (setf (gethash n-bytes *static-pool*) (rest free))
                        (first free))))))
    (if recycled
        (fill (the (simple-array (unsigned-byte 8) (*)) recycled) 0)
        (static-vectors:make-static-vector n-bytes :element-type '(unsigned-byte 8)))))

(defun* free-static (vec)
    (function ((simple-array (unsigned-byte 8) (*))) t)
  "Release memory obtained from ALLOC-STATIC. Idempotency is the caller's job.
   On Clasp this recycles VEC into *STATIC-POOL* instead of deallocating, because
   GCTOOLS:DEALLOCATE-UNMANAGED-INSTANCE GC_frees an interior pointer and corrupts
   the Boehm heap (see *STATIC-POOL*)."
  (bordeaux-threads:with-lock-held (*static-pool-lock*)
    (push vec (gethash (length vec) *static-pool*)))
  t)

(defun* static-pointer (vec)
    (function ((simple-array (unsigned-byte 8) (*))) t)
  "Return the raw foreign pointer to VEC for syscalls / SHMEM. Stable across GC."
  (static-vectors:static-vector-pointer vec))

(defun* static-length (vec)
    (function ((simple-array (unsigned-byte 8) (*))) (integer 0))
  "Octet length of a static region from ALLOC-STATIC."
  (length vec))

(declaim (inline mem-ref-u8 mem-set-u8))
(defun* mem-ref-u8 (vec index)
    (function ((simple-array (unsigned-byte 8) (*)) (integer 0)) (unsigned-byte 8))
  "Typed raw read of one octet. Bounds enforced by the array type."
  (declare (type (simple-array (unsigned-byte 8) (*)) vec))
  (aref vec index))
(defun* mem-set-u8 (vec index value)
    (function ((simple-array (unsigned-byte 8) (*)) (integer 0) (unsigned-byte 8)) (unsigned-byte 8))
  "Typed raw write of one octet."
  (declare (type (simple-array (unsigned-byte 8) (*)) vec)
           (type (unsigned-byte 8) value))
  (setf (aref vec index) value))

(defun* bytes-consed ()
    (function () integer)
  "Total bytes allocated so far. Clasp/Boehm exposes no cheap exact counter here;
   returns 0 — a documented NFR-PORT measurement gap (the mem gate runs on SBCL)."
  0)

;;; ---- clock ----

(defun* monotonic-ns ()
    (function () integer)
  "Monotonic time in nanoseconds. M0 uses the portable real-time clock scaled to
   ns; a CFFI clock_gettime(CLOCK_MONOTONIC) fast path replaces this later."
  (multiple-value-bind (q) (truncate (* (get-internal-real-time)
                                        (/ 1000000000 internal-time-units-per-second)))
    q))

;;; ---- atomics / threads / gc: M0 stubs over portable libs ----
;;; bordeaux-threads is available; native CAS/fence fast paths land in M1.

(defun* cas (place-fn old new)
    (function (t t t) t)
  "Atomic compare-and-swap. M0 stub: signals PAL-UNIMPLEMENTED; a native CAS fast
   path lands in M1."
  (declare (ignore place-fn old new))
  (error 'pal-unimplemented :op 'cas))
(defun* atomic-incf (place-fn &optional (delta 1))
    (function (t &optional integer) t)
  "Atomic increment by DELTA. M0 stub: signals PAL-UNIMPLEMENTED; a native fast path
   lands in M1."
  (declare (ignore place-fn delta))
  (error 'pal-unimplemented :op 'atomic-incf))
(defun* fence (&optional (kind :full))
    (function (&optional t) (values))
  "Memory fence of the given KIND. M0 no-op; a native fence fast path lands in M1."
  (declare (ignore kind)) (values))

(defun* spawn (fn &key name)
    (function (function &key (:name (or null string))) t)
  "Spawn a thread running FN, named NAME (default \"dds\"). Returns the thread."
  (bordeaux-threads:make-thread fn :name (or name "dds")))
(defun* join (thread)
    (function (t) t)
  "Block until THREAD finishes; return its result."
  (bordeaux-threads:join-thread thread))
(defun* make-lock (&optional name)
    (function (&optional (or null string)) t)
  "Create a mutex named NAME (default \"dds-lock\")."
  (bordeaux-threads:make-lock (or name "dds-lock")))
(defmacro with-lock ((lock) &body body)
  "Evaluate BODY with LOCK held."
  `(bordeaux-threads:with-lock-held (,lock) ,@body))
(defun* make-condvar ()
    (function () t)
  "Create a condition variable for use with CONDVAR-WAIT / CONDVAR-SIGNAL."
  (bordeaux-threads:make-condition-variable))
(defun* condvar-wait (cv lock &optional timeout-seconds)
    (function (t t &optional t) t)
  "Wait on condition variable CV releasing LOCK. NIL TIMEOUT-SECONDS waits forever,
   else a bounded wait; re-check the predicate on wake (ADR 0007)."
  (if timeout-seconds
      (bordeaux-threads:condition-wait cv lock :timeout timeout-seconds)
      (bordeaux-threads:condition-wait cv lock)))
(defun* condvar-signal (cv)
    (function (t) t)
  "Wake one thread waiting on condition variable CV."
  (bordeaux-threads:condition-notify cv))

(defun* gc-suggest ()
    (function () (values))
  "Suggest a GC to the implementation. M0 no-op."
  (values))
(defmacro with-gc-inhibited (&body body)
  "M0: no-op wrapper. A bounded, audited GC-inhibition window lands behind an
   explicit unsafe flag in a later ADR (REQUIREMENTS NFR-DET)."
  `(progn ,@body))
