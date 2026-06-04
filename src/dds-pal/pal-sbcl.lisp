;;;; DDS.PAL — SBCL implementation of the L0 contract.
;;;; This file is the ONLY M0 location permitted to carry #+sbcl conditionals.
;;;; M0 uses portable libraries (static-vectors / bordeaux-threads); SBCL-native
;;;; fast paths (sb-sys:sap-ref-*, sb-ext:cas, define-vop) land in M1, gated by a
;;;; before/after bench number (FR-LANG-7).

(in-package #:dds.pal)

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
(declaim (ftype (function (t t) t) condvar-wait))
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

;;; ---- clock ----

(defun monotonic-ns ()
  "Monotonic time in nanoseconds. M0 uses the portable real-time clock scaled to
   ns; a CFFI clock_gettime(CLOCK_MONOTONIC) fast path replaces this in M1."
  (multiple-value-bind (q) (truncate (* (get-internal-real-time)
                                        (/ 1000000000 internal-time-units-per-second)))
    q))

;;; ---- atomics / threads / gc: M0 stubs over portable libs ----
;;; sb-ext:cas / sb-thread:barrier fast paths land in M1.

(defun cas (place-fn old new) (declare (ignore place-fn old new))
  (error 'pal-unimplemented :op 'cas))
(defun atomic-incf (place-fn &optional (delta 1)) (declare (ignore place-fn delta))
  (error 'pal-unimplemented :op 'atomic-incf))
(defun fence (&optional (kind :full)) (declare (ignore kind)) (values))

(defun spawn (fn &key name) (bordeaux-threads:make-thread fn :name (or name "dds")))
(defun join (thread) (bordeaux-threads:join-thread thread))
(defun make-lock (&optional name) (bordeaux-threads:make-lock (or name "dds-lock")))
(defmacro with-lock ((lock) &body body)
  `(bordeaux-threads:with-lock-held (,lock) ,@body))
(defun make-condvar () (bordeaux-threads:make-condition-variable))
(defun condvar-wait (cv lock) (bordeaux-threads:condition-wait cv lock))
(defun condvar-signal (cv) (bordeaux-threads:condition-notify cv))

(defun gc-suggest () (values))
(defmacro with-gc-inhibited (&body body)
  "M0: no-op wrapper. SBCL's sb-sys:without-gcing lands behind an explicit unsafe
   flag in a later ADR (REQUIREMENTS NFR-DET)."
  `(progn ,@body))
