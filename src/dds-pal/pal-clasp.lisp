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
   per size. Documented NFR-PORT gap until the upstream deallocator is fixed
   (reported: clasp-developers/clasp#1793).")

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

(defun* static-vector-p (vec)
    (function (t) boolean)
  "T iff VEC is an octet vector safe to address by a raw, GC-stable SAP. On Clasp/Boehm the GC is NON-MOVING,
   so ALLOC-STATIC returns an ordinary (address-stable) Boehm vector INDISTINGUISHABLE from MAKE-ARRAY (same
   class + type) — there is no foreign/off-heap sub-representation to test for, and the moving-GC secret-copy
   threat the SBCL predicate guards against does not exist here (documented NFR-PORT semantic). So this answers
   T for any (simple-array (unsigned-byte 8) (*)); on Clasp the cross-impl hardening evidence is the
   zeroize-on-teardown WIPE, while the off-heap DISCRIMINATION (heap array -> NIL) is SBCL-only (ADR-0034)."
  (and (typep vec '(simple-array (unsigned-byte 8) (*))) t))

;; CFFI inc-pointer over static-vector-pointer; Clasp bytes-consed=0, so correctness (not zero-box) is the bar
(declaim (inline static-sap+))
(defun* static-sap+ (vec offset)
    (function ((simple-array (unsigned-byte 8) (*)) (integer 0)) t)
  "Raw foreign pointer at VEC[OFFSET], computed inline (CFFI inc-pointer over static-vector-pointer).
   VEC MUST be an ALLOC-STATIC-backed (foreign, non-moving) vector. Equivalent to
   (static-vectors:static-vector-pointer VEC :offset OFFSET); the boxing entry point STATIC-POINTER
   remains for control-plane use. (Clasp's BYTES-CONSED returns 0 — a documented NFR-PORT gap — so the
   binding zero-box gate runs on SBCL; here the contract is functional equivalence.)"
  (declare (optimize speed (safety 0)))
  (cffi:inc-pointer (static-vectors:static-vector-pointer vec) offset))

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

;;; ---- atomics / threads / gc ----
;;; Generic CAS/fetch-add over an ATOMIC-CELL (M0 stub CLOSED, ADR 0041). The SAP-targeted
;;; foreign-cell atomics below stay a documented NFR-PORT gap (no Clasp foreign atomic, ADR 0013).

(defun* cas (cell old new)
    (function (atomic-cell (unsigned-byte 64) (unsigned-byte 64)) (unsigned-byte 64))
  "Atomically compare-and-swap CELL's VALUE: if it = OLD store NEW, and return the PREVIOUS
   value either way (the swap succeeded iff the return is = OLD). A full-barrier
   (sequentially-consistent) RMW via mp:cas over the (unsigned-byte 64) ATOMIC-CELL-VALUE slot
   (Clasp lowers a known struct-slot place through core:acas — unlike a raw foreign cell, which
   has no atomic expander, ADR 0013). Returns the previous value, matching the SAP sibling
   CAS-SAP-U64's contract (ADR 0041)."
  (mp:cas (atomic-cell-value cell) old new))
(defun* atomic-incf (cell &optional (delta 1))
    (function (atomic-cell &optional fixnum) (unsigned-byte 64))
  "Atomically add DELTA (signed; default 1) to CELL's VALUE modulo 2^64 and return the NEW value.
   A full-barrier (sequentially-consistent) RMW via mp:atomic-incf, which returns the NEW value on
   Clasp (masked to 64 bits for the uniform (unsigned-byte 64) contract; matching the SAP sibling
   ATOMIC-INCF-SAP-U64). A negative DELTA decrements (modular). (ADR 0041.)"
  (declare (type fixnum delta))
  (logand (mp:atomic-incf (atomic-cell-value cell) delta) #xFFFFFFFFFFFFFFFF))
(defun* fence (&optional (kind :full))
    (function (&optional t) (values))
  "Real memory barrier (M1) via mp:fence. KIND maps to the C++11 memory order it expects."
  (mp:fence (ecase kind
              (:acquire :acquire)
              (:release :release)
              (:full    :sequentially-consistent)))
  (values))

(defun* load-sap-u8 (sap offset)
    (function (t (integer 0)) (unsigned-byte 8))
  "8-bit unsigned read of the foreign location at SAP+OFFSET. NFR-PORT gap: backs the
   FlatData-over-Zero-Copy read-in-place accessors (WP-FLATDATA-ZC-LOAN, R6 — NOT cleared
   for ship, see ADR 0017), and ZC is SBCL-only (ADR 0013), so the loan path never runs on
   Clasp; signals PAL-UNIMPLEMENTED rather than offering a half-path (consistent with the
   cas-sap-u64 stub)."
  (declare (ignore sap offset))
  (error 'pal-unimplemented :op 'load-sap-u8))
(defun* load-sap-u16 (sap offset)
    (function (t (integer 0)) (unsigned-byte 16))
  "16-bit little-endian unsigned read of the foreign location at SAP+OFFSET. Same NFR-PORT
   gap as LOAD-SAP-U8: ZC is SBCL-only (ADR 0013), so the FlatData-ZC loan path
   (WP-FLATDATA-ZC-LOAN, R6 — NOT cleared for ship, see ADR 0017) never runs on Clasp;
   signals PAL-UNIMPLEMENTED."
  (declare (ignore sap offset))
  (error 'pal-unimplemented :op 'load-sap-u16))
(defun* load-sap-u32 (sap offset)
    (function (t (integer 0)) (unsigned-byte 32))
  "32-bit little-endian unsigned read of the foreign location at SAP+OFFSET. Same NFR-PORT
   gap as LOAD-SAP-U8: ZC is SBCL-only (ADR 0013), so the FlatData-ZC loan path
   (WP-FLATDATA-ZC-LOAN, R6 — NOT cleared for ship, see ADR 0017) never runs on Clasp;
   signals PAL-UNIMPLEMENTED."
  (declare (ignore sap offset))
  (error 'pal-unimplemented :op 'load-sap-u32))
(defun* load-sap-u64 (sap offset)
    (function (t (integer 0)) (unsigned-byte 64))
  "Aligned 64-bit read of the foreign location at SAP+OFFSET (bytes). Masked to unsigned
   because Clasp's CFFI :uint64 mem-ref sign-extends a high-bit-set word (probed A4)."
  (logand (cffi:mem-ref sap :uint64 offset) #xFFFFFFFFFFFFFFFF))
(defun* store-sap-u64 (sap offset value)
    (function (t (integer 0) (unsigned-byte 64)) (unsigned-byte 64))
  "Aligned 64-bit write of VALUE at SAP+OFFSET (bytes)."
  (setf (cffi:mem-ref sap :uint64 offset) value))
(defun* cas-sap-u64 (sap offset old new)
    (function (t (integer 0) (unsigned-byte 64) (unsigned-byte 64)) (unsigned-byte 64))
  "Atomic compare-and-swap of the u64 at SAP+OFFSET; returns the PREVIOUS value (= OLD on
   success). NFR-PORT gap: Clasp has no hardware atomic over a raw foreign cell — mp:cas
   rejects a cffi:mem-ref place (NOT-ATOMIC), and the only foreign-backed primitive
   (core:acas on a (unsigned-byte 64) static-vector) silently drops the store when the
   compare operand exceeds most-positive-fixnum (probed A4); signals PAL-UNIMPLEMENTED so the
   SHMEM ring stays SBCL-only and Clasp falls back to UDP (ADR 0013, FR-XPORT-2)."
  (declare (ignore sap offset old new))
  (error 'pal-unimplemented :op 'cas-sap-u64))
(defun* cas-sap-u32 (sap offset old new)
    (function (t (integer 0) (unsigned-byte 32) (unsigned-byte 32)) (unsigned-byte 32))
  "Atomic compare-and-swap of the u32 at SAP+OFFSET; returns the PREVIOUS value (= OLD on success). The
   full-barrier atomic backing the lock-free loan release (WP-ZC-LOAN-LOCKFREE, R6 — NOT cleared for ship,
   see ADR 0018). Same NFR-PORT gap as CAS-SAP-U64: no Clasp hardware atomic over a raw foreign cell, and ZC
   is SBCL-only (ADR 0013), so the loan-release path never runs on Clasp; signals PAL-UNIMPLEMENTED."
  (declare (ignore sap offset old new))
  (error 'pal-unimplemented :op 'cas-sap-u32))
(defun* atomic-incf-sap-u64 (sap offset delta)
    (function (t (integer 0) (unsigned-byte 64)) (unsigned-byte 64))
  "Atomically add DELTA to the u64 at SAP+OFFSET; returns the NEW value. Same NFR-PORT gap as
   CAS-SAP-U64 (no Clasp foreign atomic); signals PAL-UNIMPLEMENTED (ADR 0013, FR-XPORT-2)."
  (declare (ignore sap offset delta))
  (error 'pal-unimplemented :op 'atomic-incf-sap-u64))

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
(defun* condvar-broadcast (cv)
    (function (t) t)
  "Wake ALL threads waiting on condition variable CV (each re-checks its predicate on wake). bordeaux-threads
   0.9.4 has no portable broadcast, so this uses Clasp's native MP::CONDITION-VARIABLE-BROADCAST (the bt
   condvar IS an MP:CONDITION-VARIABLE, the same object bt's CONDITION-NOTIFY drives) — the only correct way
   to release several waiters on one event (e.g. several publishers blocked on a full HistoryCache, ADR 0016
   §Backpressure)."
  (mp:condition-variable-broadcast cv))

;;; Per-signal callback table; guarded by *signal-handler-lock*.
;;; Clasp dispatches POSIX signals as Lisp conditions via mp:service-interrupt;
;;; the :around methods below intercept core:sigterm / core:sigint and call the
;;; registered callback instead of the default (ext:quit 1 for SIGTERM; the default
;;; SIGINT action for SIGINT). Unregistered signals fall through to call-next-method.
(defvar *signal-handlers* '()
  "Alist of (signal-keyword . callback) for install-signal-handler on Clasp.")

(defvar *signal-handler-lock* (bordeaux-threads:make-lock "dds-signal-handlers")
  "Guards *SIGNAL-HANDLERS* for concurrent install-signal-handler calls.")

(defmethod mp:service-interrupt :around ((i core:sigterm))
  "Intercept SIGTERM: call the registered :term callback (if any) instead of terminating."
  (let ((h (bordeaux-threads:with-lock-held (*signal-handler-lock*)
              (cdr (assoc :term *signal-handlers*)))))
    (if h (funcall h) (call-next-method))))

(defmethod mp:service-interrupt :around ((i core:sigint))
  "Intercept SIGINT: call the registered :int callback (if any) instead of the default SIGINT action (the terminal interrupt)."
  (let ((h (bordeaux-threads:with-lock-held (*signal-handler-lock*)
              (cdr (assoc :int *signal-handlers*)))))
    (if h (funcall h) (call-next-method))))

(defun* install-signal-handler (signals callback)
    (function (list function) (eql t))
  "Register CALLBACK (a 0-arg fn) for each signal in SIGNALS (list of (member :term :int)) —
   Clasp via mp:service-interrupt :around methods on core:sigterm/core:sigint. The handler
   suppresses the default termination/terminal-interrupt action when a callback is registered. CALLBACK
   must be minimal (set a flag / wake a thread), never do teardown inline.
   No reader conditional escapes dds-pal/."
  (bordeaux-threads:with-lock-held (*signal-handler-lock*)
    (dolist (s signals)
      (ecase s
        (:term (setf *signal-handlers*
                     (cons (cons :term callback)
                           (remove :term *signal-handlers* :key #'car))))
        (:int  (setf *signal-handlers*
                     (cons (cons :int callback)
                           (remove :int *signal-handlers* :key #'car)))))))
  t)

(defun* register-image-restart-hook (hook)
    (function ((or symbol function)) (eql t))
  "Register HOOK (a 0-arg function or fbound symbol) to run at IMAGE STARTUP — after a save-lisp-and-die snapshot
   is restarted, before the toplevel — via core:*initialize-hooks* (Clasp's standard-toplevel funcalls each hook
   at startup). The portable seam for re-resolving state a dumped snapshot cannot carry live across restart
   (foreign-symbol pointers, re-mapped shared libraries; Clasp re-opens CFFI libraries on snapshot restart but
   self-cached raw pointers still need re-resolution). The owning module registers ONCE at its load time.
   Idempotent (pushnew, eq). No reader conditional escapes dds-pal/."
  (pushnew hook core:*initialize-hooks* :test #'eq)
  t)

(defun* gc-suggest ()
    (function () (values))
  "Suggest a GC to the implementation. M0 no-op."
  (values))
(defmacro with-gc-inhibited (&body body)
  "M0: no-op wrapper. A bounded, audited GC-inhibition window lands behind an
   explicit unsafe flag in a later ADR (REQUIREMENTS NFR-DET)."
  `(progn ,@body))

(defun* fsync-stream (stream)
    (function (stream) (eql t))
  "Flush CL stream buffers. Clasp has no direct fdatasync path (NFR-PORT gap);
   finish-output + force-output is the documented fallback."
  (finish-output stream)
  (force-output stream)
  t)
