;;;; DDS.PAL — SBCL implementation of the L0 contract.
;;;; This file is the ONLY M0 location permitted to carry #+sbcl conditionals.
;;;; M0 uses portable libraries (static-vectors / bordeaux-threads); SBCL-native
;;;; fast paths (sb-sys:sap-ref-*, sb-ext:cas, define-vop) land in M1, gated by a
;;;; before/after bench number (FR-LANG-7).

(in-package #:dds.pal)

;; SBCL ships sb-bsd-sockets as a contrib; load it so pal-net.lisp (the shared
;; native UDP layer) compiles. Clasp bundles sb-bsd-sockets preloaded.
(eval-when (:compile-toplevel :load-toplevel :execute)
  (require :sb-bsd-sockets))

#-sbcl
(eval-when (:compile-toplevel :load-toplevel :execute)
  (warn "pal-sbcl.lisp loaded on a non-SBCL build; capabilities will stub out."))

(declaim (ftype (function () keyword) pal-impl-name))
(declaim (ftype (function ((integer 0)) (simple-array (unsigned-byte 8) (*))) alloc-static))
(declaim (ftype (function ((simple-array (unsigned-byte 8) (*))) t) free-static))
(declaim (ftype (function ((simple-array (unsigned-byte 8) (*))) t) static-pointer))
(declaim (ftype (function ((simple-array (unsigned-byte 8) (*))) (integer 0)) static-length))
(declaim (ftype (function ((simple-array (unsigned-byte 8) (*)) (integer 0)) (unsigned-byte 8)) mem-ref-u8))
(declaim (ftype (function ((simple-array (unsigned-byte 8) (*)) (integer 0) (unsigned-byte 8)) (unsigned-byte 8)) mem-set-u8))
(declaim (ftype (function () integer) monotonic-ns))
(declaim (ftype (function (t t t) t) cas))
(declaim (ftype (function (t &optional integer) t) atomic-incf))
(declaim (ftype (function (&optional t) (values)) fence))
(declaim (ftype (function (function &key (:name (or null string))) t) spawn))
(declaim (ftype (function (t) t) join))
(declaim (ftype (function (&optional (or null string)) t) make-lock))
(declaim (ftype (function () t) make-condvar))
(declaim (ftype (function (t t &optional t) t) condvar-wait))
(declaim (ftype (function (t) t) condvar-signal))
(declaim (ftype (function () (values)) gc-suggest))

(defun pal-impl-name ()
  "Return a keyword naming the running implementation."
  #+sbcl :sbcl
  #-sbcl :unknown)

;;; ---- memory: off-heap, non-GC'd, raw-pointer-addressable ----

(defun alloc-static (n-bytes)
  "Allocate N-BYTES of off-heap octet memory the GC neither scans, moves, nor
   reclaims. Returns a foreign-backed (unsigned-byte 8) vector with a stable
   address (SBCL static-vectors are foreign-allocated, so the SAP is GC-stable)."
  (declare (type (integer 0) n-bytes))
  (static-vectors:make-static-vector n-bytes :element-type '(unsigned-byte 8)))

(defun free-static (vec)
  "Release memory obtained from ALLOC-STATIC. Idempotency is the caller's job."
  (static-vectors:free-static-vector vec))

(defun static-pointer (vec)
  "Return the raw foreign pointer (SBCL system-area-pointer) to VEC for syscalls."
  (static-vectors:static-vector-pointer vec))

(defun static-length (vec)
  "Octet length of a static region from ALLOC-STATIC."
  (length vec))

(declaim (inline mem-ref-u8 mem-set-u8))
(defun mem-ref-u8 (vec index)
  "Typed raw read of one octet."
  (declare (type (simple-array (unsigned-byte 8) (*)) vec))
  (aref vec index))
(defun mem-set-u8 (vec index value)
  "Typed raw write of one octet."
  (declare (type (simple-array (unsigned-byte 8) (*)) vec)
           (type (unsigned-byte 8) value))
  (setf (aref vec index) value))

(declaim (ftype (function () integer) bytes-consed))
(defun bytes-consed ()
  "Total bytes consed so far (sb-ext:get-bytes-consed) — the NFR-PERF-8 oracle."
  (sb-ext:get-bytes-consed))

;;; ---- clock ----

(defun monotonic-ns ()
  "Monotonic time in nanoseconds. M0 uses the portable real-time clock scaled to
   ns; a CFFI clock_gettime(CLOCK_MONOTONIC) fast path replaces this in M1."
  (multiple-value-bind (q) (truncate (* (get-internal-real-time)
                                        (/ 1000000000 internal-time-units-per-second)))
    q))

;;; ---- atomics / threads / gc: M0 stubs over portable libs ----
;;; sb-ext:cas / sb-thread:barrier fast paths land in M1.

(defun cas (place-fn old new)
  "Atomic compare-and-swap. M0 stub: signals PAL-UNIMPLEMENTED; the sb-ext:cas fast
   path lands in M1."
  (declare (ignore place-fn old new))
  (error 'pal-unimplemented :op 'cas))
(defun atomic-incf (place-fn &optional (delta 1))
  "Atomic increment by DELTA. M0 stub: signals PAL-UNIMPLEMENTED; the native fast
   path lands in M1."
  (declare (ignore place-fn delta))
  (error 'pal-unimplemented :op 'atomic-incf))
(defun fence (&optional (kind :full))
  "Memory fence of the given KIND. M0 no-op; an sb-thread:barrier fast path lands in M1."
  (declare (ignore kind)) (values))

(defun spawn (fn &key name)
  "Spawn a thread running FN, named NAME (default \"dds\"). Returns the thread."
  (bordeaux-threads:make-thread fn :name (or name "dds")))
(defun join (thread)
  "Block until THREAD finishes; return its result."
  (bordeaux-threads:join-thread thread))
(defun make-lock (&optional name)
  "Create a mutex named NAME (default \"dds-lock\")."
  (bordeaux-threads:make-lock (or name "dds-lock")))
(defmacro with-lock ((lock) &body body)
  "Evaluate BODY with LOCK held."
  `(bordeaux-threads:with-lock-held (,lock) ,@body))
(defun make-condvar ()
  "Create a condition variable for use with CONDVAR-WAIT / CONDVAR-SIGNAL."
  (bordeaux-threads:make-condition-variable))
(defun condvar-wait (cv lock &optional timeout-seconds)
  "Wait on condition variable CV releasing LOCK. NIL TIMEOUT-SECONDS waits forever,
   else a bounded wait; re-check the predicate on wake (ADR 0007)."
  (if timeout-seconds
      (bordeaux-threads:condition-wait cv lock :timeout timeout-seconds)
      (bordeaux-threads:condition-wait cv lock)))
(defun condvar-signal (cv)
  "Wake one thread waiting on condition variable CV."
  (bordeaux-threads:condition-notify cv))

(defun gc-suggest ()
  "Suggest a GC to the implementation. M0 no-op."
  (values))
(defmacro with-gc-inhibited (&body body)
  "M0: no-op wrapper. SBCL's sb-sys:without-gcing lands behind an explicit unsafe
   flag in a later ADR (REQUIREMENTS NFR-DET)."
  `(progn ,@body))
