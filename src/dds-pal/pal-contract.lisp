;;;; DDS.PAL — L0 Platform Abstraction Layer contract (frozen M0).
;;;; Impl-agnostic surface only. Per-impl code lives in pal-<impl>.lisp and is
;;;; the ONLY place where #+sbcl/#+allegro/#+clasp reader conditionals may appear.

(defpackage #:net.goenninger.dds.pal
  (:nicknames #:dds.pal)
  (:use #:common-lisp)
  (:documentation
   "Platform Abstraction Layer: the single frozen contract (REQUIREMENTS NFR-PORT,
    IMPLEMENTATION-PLAN §7.6). Every layer above L0 depends ONLY on these symbols.
    Capabilities: off-heap static memory, typed raw R/W, bounded pin, atomics,
    threads, sockets, monotonic clock, GC control, optimization hints.")
  (:export
   ;; conditions
   #:pal-error #:pal-unimplemented #:pal-op
   ;; capability introspection
   #:+pal-capabilities+ #:pal-impl-name
   ;; memory (off-heap, non-GC'd, raw-pointer-addressable)
   #:alloc-static #:free-static #:static-pointer #:static-length
   #:mem-ref-u8 #:mem-set-u8
   ;; atomics
   #:cas #:atomic-incf #:fence
   ;; threads
   #:spawn #:join #:make-lock #:with-lock #:make-condvar #:condvar-wait #:condvar-signal
   ;; clock
   #:monotonic-ns
   ;; gc control
   #:gc-suggest #:with-gc-inhibited
   ;; optimization hints
   #:with-hot-optimizations))

(in-package #:dds.pal)

(define-condition pal-error (error) ()
  (:documentation "Base class for all PAL-level failures (control plane only)."))

(define-condition pal-unimplemented (pal-error)
  ((op :initarg :op :reader pal-op :initform nil))
  (:report (lambda (c s)
             (format s "PAL capability not implemented on this build: ~s"
                     (pal-op c))))
  (:documentation "Signalled by a capability stub not yet provided for this impl."))

(defparameter +pal-capabilities+
  '(:memory :atomics :threads :sockets :clock :gc-control :opt-hints)
  "The capability groups every PAL implementation MUST eventually satisfy.")

(defmacro with-hot-optimizations (&body body)
  "Expand to this build's strongest safe-enough hot-path declarations.
   M0 baseline keeps SAFETY at 1 while the manual bounds-checks (NFR-SEC-POSTURE)
   are being established; a later ADR drops designated kernels to (safety 0)."
  `(locally (declare (optimize (speed 3) (safety 1) (debug 0) (space 0)))
     ,@body))
