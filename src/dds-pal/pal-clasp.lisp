;;;; DDS.PAL — Clasp (boehmprecise) implementation of the L0 contract.
;;;; This file is the ONLY M0 location permitted to carry #+clasp conditionals.

(in-package #:dds.pal)

#-clasp
(eval-when (:compile-toplevel :load-toplevel :execute)
  ;; A diagnostic, not a condition (ADR 0064: nothing in our code signals). WARN would unwind into the
  ;; loading image's handlers and, under a warnings-as-errors build policy, fail a build that is merely
  ;; loading the wrong PAL for its implementation.
  (format *error-output*
          "~&dds.pal: pal-clasp.lisp loaded on a non-Clasp build — this PAL is not the one for this image.~%"))


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
   address. ALWAYS ZERO-FILLED (NFR-SEC-POSTURE) — recycled vectors were already zeroed 'as hygiene', but a
   FRESH make-static-vector was not, and the contract said 'contents unspecified'. That is UNSAFE HERE:
   these buffers reach the WIRE. A FlatData sample IS its SerializedPayload, and nothing writes its
   inter-field ALIGNMENT PADDING, so every pad octet was leftover heap contents transmitted to any peer —
   an information disclosure, and a non-deterministic payload (it passed on macOS, failed on Linux; see
   pal-sbcl.lisp). The single representation stable across all three target GCs. Satisfied from
   *STATIC-POOL* when a free vector of exactly N-BYTES exists."
  (declare (type (integer 0) n-bytes))
  (let ((recycled (bordeaux-threads:with-lock-held (*static-pool-lock*)
                    (let ((free (gethash n-bytes *static-pool*)))
                      (when free
                        (setf (gethash n-bytes *static-pool*) (rest free))
                        (first free))))))
    (if recycled
        (fill (the (simple-array (unsigned-byte 8) (*)) recycled) 0)
        (static-vectors:make-static-vector n-bytes :element-type '(unsigned-byte 8)
                                                   :initial-element 0))))

(defun* free-static (vec)
    (function ((simple-array (unsigned-byte 8) (*))) t)
  "Release memory obtained from ALLOC-STATIC. Idempotency is the caller's job.
   On Clasp this recycles VEC into *STATIC-POOL* instead of deallocating, because
   GCTOOLS:DEALLOCATE-UNMANAGED-INSTANCE GC_frees an interior pointer and corrupts
   the Boehm heap (see *STATIC-POOL*)."
  (bordeaux-threads:with-lock-held (*static-pool-lock*)
    (push vec (gethash (length vec) *static-pool*)))
  t)

(declaim (inline static-pointer))   ; MEASURED: out of line this BOXES a system-area-pointer (16 B) on every raw sendto/recvfrom and every SHMEM sap-copy — the same defect %ptr+ had
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

(defun* internal-bug-p (condition)
    (function (t) t)
  "T iff CONDITION is the implementation reporting a violation of its OWN internal invariants — an
   interpreter/compiler/runtime BUG, not a condition our code raised or could have anticipated.

   WHY THIS EXISTS (ADR 0100). A sender-thread guard that catches ERROR and continues is correct for an
   ordinary emit failure (a peer's segment vanished; the datagram falls back to UDP; RTPS repair covers the
   rest). It is WRONG for an internal-invariant violation: that says a DATA STRUCTURE IS ALREADY CORRUPT, so
   \"carry on and use it again\" is the one response guaranteed to make things worse. Absorbing it also
   HIDES it — the defect that motivated this ADR degraded SHMEM to UDP silently for as long as it existed,
   with no test ever going red.

   Implementation-specific by nature, hence the PAL: SBCL signals SB-INT:BUG (\"failed AVER: ...\") for these.
   An implementation with no distinguished internal-bug type returns NIL, which restores exactly the previous
   catch-everything behaviour — a documented NFR-PORT gap, never a silent behaviour change."
  (declare (ignore condition))
  nil)   ; Clasp has no distinguished internal-bug condition type — documented NFR-PORT gap

;;; ---- clock ----

;; MONOTONIC-NS lives in pal-net.lisp — ONE clock_gettime implementation shared by both impls.

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
  "8-bit unsigned read of the foreign location at SAP+OFFSET (bytes). Backs the FlatData-over-Zero-Copy
   read-in-place accessors (WP-FLATDATA-ZC-LOAN, ADR 0017): a literal-0-copy field read straight off a SHMEM
   pool slot SAP, byte-exact to the aref accessor (XCDR2-LE). Same contract as the SBCL PAL's sb-sys:sap-ref-8.

   WAS A PAL-UNIMPLEMENTED STUB, and the stub was never justified: cffi:mem-ref reads a foreign cell on
   Clasp exactly as it does on SBCL (this file's LOAD-SAP-U64 already did precisely that). The gap was
   asserted, not measured — owner directive 2026-07-14: Clasp and SBCL MUST be equally fitted."
  (cffi:mem-ref sap :uint8 offset))
(defun* load-sap-u16 (sap offset)
    (function (t (integer 0)) (unsigned-byte 16))
  "Aligned 16-bit little-endian unsigned read of the foreign location at SAP+OFFSET (bytes). Backs the
   FlatData-over-Zero-Copy read-in-place accessors (ADR 0017), byte-exact to the aref accessor. Same
   contract as the SBCL PAL's sb-sys:sap-ref-16. (Was an unjustified PAL-UNIMPLEMENTED stub — see
   LOAD-SAP-U8.)"
  (cffi:mem-ref sap :uint16 offset))
(defun* load-sap-u32 (sap offset)
    (function (t (integer 0)) (unsigned-byte 32))
  "Aligned 32-bit little-endian unsigned read of the foreign location at SAP+OFFSET (bytes). Backs the
   FlatData-over-Zero-Copy read-in-place accessors (ADR 0017), byte-exact to the aref accessor. Same
   contract as the SBCL PAL's sb-sys:sap-ref-32. (Was an unjustified PAL-UNIMPLEMENTED stub — see
   LOAD-SAP-U8.)"
  (cffi:mem-ref sap :uint32 offset))

;;; IEEE 754 bit-pattern conversion (ADR 0111 §2.3). Clasp's EXT primitives already use the UNSIGNED
;;; convention in both directions — probed, not assumed: (ext:single-float-to-bits -1.0f0) => 3212836864
;;; = #xBF800000, and (ext:single-float-to-bits -0.0f0) => #x80000000. So unlike the SBCL PAL, which must
;;; convert between its signed pattern and the wire's unsigned one, these are direct.
(defun* f32-bits (x)
    (function (single-float) (unsigned-byte 32))
  "The IEEE 754 binary32 bit pattern of X as a 32-bit unsigned integer (XTypes 1.3 Table 31: Float32,
   encoded size 4, alignment 4, [IEEE-754]). Total over denormals, the infinities and NaNs."
  (ext:single-float-to-bits x))
(defun* f32-from-bits (b)
    (function ((unsigned-byte 32)) single-float)
  "The single-float whose IEEE 754 binary32 bit pattern is B. Exact inverse of F32-BITS."
  (ext:bits-to-single-float b))
(defun* f64-bits (x)
    (function (double-float) (unsigned-byte 64))
  "The IEEE 754 binary64 bit pattern of X as a 64-bit unsigned integer (XTypes 1.3 Table 31: Float64,
   encoded size 8, alignment 8, [IEEE-754]). Total, as F32-BITS."
  (ext:double-float-to-bits x))
(defun* f64-from-bits (b)
    (function ((unsigned-byte 64)) double-float)
  "The double-float whose IEEE 754 binary64 bit pattern is B. Exact inverse of F64-BITS."
  (ext:bits-to-double-float b))

(defun* load-sap-u64 (sap offset)
    (function (t (integer 0)) (unsigned-byte 64))
  "Aligned 64-bit read of the foreign location at SAP+OFFSET (bytes). Masked to unsigned
   because Clasp's CFFI :uint64 mem-ref sign-extends a high-bit-set word (probed A4)."
  (logand (cffi:mem-ref sap :uint64 offset) #xFFFFFFFFFFFFFFFF))
(defun* store-sap-u64 (sap offset value)
    (function (t (integer 0) (unsigned-byte 64)) (unsigned-byte 64))
  "Aligned 64-bit write of VALUE at SAP+OFFSET (bytes)."
  (setf (cffi:mem-ref sap :uint64 offset) value))
(defun* store-sap-u8 (sap offset value)
    (function (t (integer 0) (unsigned-byte 8)) (unsigned-byte 8))
  "8-bit write of VALUE at SAP+OFFSET (bytes). Backs the FlatData loan-write SAP-mode Offset setters
   (WP-FLATDATA-LOAN-WRITE, ADR 0042): a literal-0-copy field write straight into a SHMEM pool slot SAP,
   byte-exact to the aref setter (XCDR2-LE). Same contract as the SBCL PAL's (setf sb-sys:sap-ref-8).
   (Was an unjustified PAL-UNIMPLEMENTED stub — see LOAD-SAP-U8.)"
  (setf (cffi:mem-ref sap :uint8 offset) value))
;;; ---- atomics over a RAW FOREIGN CELL (the NFR-PORT gap that ADR 0013 declared unclosable) ----
;;
;; It was closable. The three primitives below were PAL-UNIMPLEMENTED stubs on the claim that "Clasp has no
;; hardware atomic over a raw foreign cell" — true of the LISP-side operators that were tried (mp:cas
;; rejects a cffi:mem-ref place as NOT-ATOMIC; core:acas on a static-vector silently drops a store whose
;; compare operand exceeds most-positive-fixnum), but the conclusion did not follow. The C ATOMIC RUNTIME is
;; already linked into the Clasp image and its symbols resolve: __atomic_compare_exchange_8 / _4 and
;; __atomic_fetch_add_8 are the very functions the compiler emits for C11 _Atomic / GCC __atomic builtins.
;; They are real hardware atomics (arm64 CASAL / x86 LOCK CMPXCHG), they are valid on MAP_SHARED memory
;; across PROCESSES, and they take the address as a plain pointer — exactly our SHMEM/ZC use.
;;
;; MEASURED, not assumed (scratch harness, this Clasp build): CAS returns the previous value on both the
;; success and the failure arm, round-trips a FULL-WIDTH 2^64-1 operand (the exact case core:acas dropped),
;; and 8 threads x 10 000 CAS-increments and fetch-adds each LOSE NOTHING (80 000/80 000).
;;
;; Consequence: Clasp is no longer SHMEM-blind or ZC-blind for want of an atomic. Owner directive
;; 2026-07-14 — Clasp and SBCL MUST be equally fitted.
;;
;; __ATOMIC_SEQ_CST = 5 (GCC/LLVM memory-order enum: RELAXED 0, CONSUME 1, ACQUIRE 2, RELEASE 3, ACQ_REL 4,
;; SEQ_CST 5 — read from the compiler's atomic ABI, not from memory). SEQ_CST is a FULL barrier, matching
;; SBCL's sb-ext:cas, so both PALs give the ring and the refcount identical ordering.
(defconstant +atomic-seq-cst+ 5
  "GCC/LLVM __ATOMIC_SEQ_CST memory order (the atomic ABI's enum value). A FULL barrier — the same ordering
   sb-ext:cas gives on the SBCL PAL, so the SHMEM ring and the zero-copy refcount behave identically on
   both implementations.")

(defparameter *cas-u64-fp* (%global-symbol-pointer "__atomic_compare_exchange_8")
  "The RESOLVED __atomic_compare_exchange_8 pointer, looked up ONCE at load. Cached for the same reason as
   *CLOCK-GETTIME-FP*: a by-NAME foreign call on Clasp re-resolves the symbol on EVERY call (~3.8 us of
   dlsym), and CAS is on the SHMEM lane-claim / zero-copy refcount hot path.")
(defparameter *cas-u32-fp* (%global-symbol-pointer "__atomic_compare_exchange_4")
  "The RESOLVED __atomic_compare_exchange_4 pointer, looked up ONCE at load (see *CAS-U64-FP*).")
(defparameter *fetch-add-u64-fp* (%global-symbol-pointer "__atomic_fetch_add_8")
  "The RESOLVED __atomic_fetch_add_8 pointer, looked up ONCE at load (see *CAS-U64-FP*).")

(defmacro %cas-sap (fp sap offset old new ctype)
  "Expand to a compare-and-swap of the CTYPE (:uint64 / :uint32) cell at SAP+OFFSET from OLD to NEW via the
   C atomic-runtime entry FP, yielding the PREVIOUS value (= OLD on success).

   A MACRO, not a function, because cffi:foreign-funcall-pointer is itself a macro: the foreign type must be
   a LITERAL at the call site, so it cannot be selected at runtime (an (IF ...) there is read as a CFFI type
   named IF, which is exactly how the first cut failed to compile).

   The C ABI takes EXPECTED **by pointer** and OVERWRITES it with the actual value when the compare fails —
   which IS the previous value our contract must return, so the failure arm reads it back out of the cell.
   The read-back is masked because Clasp's CFFI :uint64 mem-ref SIGN-EXTENDS a high-bit-set word (the same
   defect LOAD-SAP-U64 masks). Uses this thread's pre-allocated scratch (dds.pal:*thread-atomic-cell*) so
   the CAS retry loop does NO per-call foreign malloc (~3.3 us on Clasp — the *thread-timespec* lesson); a
   thread the PAL did not create has none and falls back to a per-call WITH-FOREIGN-OBJECT."
  (let ((cell (gensym "CELL")) (ok (gensym "OK")) (run (gensym "RUN")))
    `(flet ((,run (,cell)
              (setf (cffi:mem-ref ,cell ,ctype) ,old)
              (let ((,ok (cffi:foreign-funcall-pointer
                          ,fp () :pointer (cffi:inc-pointer ,sap ,offset)
                          :pointer ,cell ,ctype ,new
                          :int +atomic-seq-cst+ :int +atomic-seq-cst+ :int)))
                (if (zerop ,ok)
                    (logand (cffi:mem-ref ,cell ,ctype) #xFFFFFFFFFFFFFFFF)  ; failed: the ACTUAL previous value
                    ,old))))                                                 ; succeeded: the previous value WAS old
       (let ((,cell *thread-atomic-cell*))
         (if ,cell
             (,run ,cell)
             (cffi:with-foreign-object (,cell :uint64) (,run ,cell)))))))

(defun* cas-sap-u64 (sap offset old new)
    (function (t (integer 0) (unsigned-byte 64) (unsigned-byte 64)) (unsigned-byte 64))
  "Atomic compare-and-swap of the u64 at SAP+OFFSET; returns the PREVIOUS value (= OLD on success). Backs
   the SHMEM ring's lane claim and cursor publication (FR-XPORT-2). Full-barrier (SEQ_CST), matching the
   SBCL PAL's sb-ext:cas. Real hardware CAS via the C atomic runtime — see the block comment above; this was
   a PAL-UNIMPLEMENTED stub, and the gap it claimed does not exist."
  (%cas-sap *cas-u64-fp* sap offset old new :uint64))

(defun* cas-sap-u32 (sap offset old new)
    (function (t (integer 0) (unsigned-byte 32) (unsigned-byte 32)) (unsigned-byte 32))
  "Atomic compare-and-swap of the u32 at SAP+OFFSET; returns the PREVIOUS value (= OLD on success). The
   full-barrier atomic backing the lock-free loan release: it CASes ONLY the 4-byte refcount sub-field
   directly, so the combined (generation<<32)|refcount value never materialises — no bignum boxing at any
   generation (WP-ZC-LOAN-LOCKFREE, ADR 0018). Same ordering as CAS-SAP-U64."
  (%cas-sap *cas-u32-fp* sap offset old new :uint32))

(defun* atomic-incf-sap-u64 (sap offset delta)
    (function (t (integer 0) (unsigned-byte 64)) (unsigned-byte 64))
  "Atomically add DELTA to the u64 at SAP+OFFSET; returns the NEW value. __atomic_fetch_add_8 returns the
   PREVIOUS value, so the new one is prev+DELTA taken mod 2^64 (the counter wraps like the C atomic does,
   and like the SBCL PAL's). Full-barrier (SEQ_CST)."
  (logand (+ delta (cffi:foreign-funcall-pointer
                    *fetch-add-u64-fp* () :pointer (cffi:inc-pointer sap offset)
                    :uint64 delta :int +atomic-seq-cst+ :uint64))
          #xFFFFFFFFFFFFFFFF))

;; SPAWN lives in pal-net.lisp — identical bordeaux-threads call on both impls, and it must wrap the thread
;; body in CALL-WITH-THREAD-CLOCK (defined there) to give the thread its MONOTONIC-NS scratch.
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
    (function (stream) (values (or null (eql t)) (or null keyword)))
  "Flush CL stream buffers. Clasp has no direct fdatasync path (NFR-PORT gap);
   finish-output + force-output is the documented fallback. Returns (VALUES T STATUS) for contract parity
   with the SBCL impl (ADR 0064); Clasp cannot observe an fdatasync failure, so STATUS is always NIL."
  (finish-output stream)
  (force-output stream)
  (values t nil))

(defun* fsync-directory (path)
    (function ((or pathname string)) (eql t))
  "Persist the DIRENT of a newly-created or renamed file: open(PATH, O_RDONLY), fsync(fd), close(fd).
   POSIX requires fsyncing the CONTAINING DIRECTORY (not just the file contents) so a create/rename
   survives a power loss (ADR 0026 §10.10 / §10.11, ADR 0029). The CFFI open/fsync/close path is
   impl-agnostic (identical body in pal-sbcl.lisp — unlike fsync-stream this needs no NFR-PORT split,
   since it targets a raw directory fd, not a CL fd-stream). O_RDONLY = 0 on Linux and macOS. On
   macOS fsync(2) on a directory fd is valid and flushes the dirent; F_FULLFSYNC is a stronger
   guarantee not required here. Returns (VALUES T STATUS): STATUS is NIL on success, or :FSYNC-FAILED on
   open/fsync failure — a dirent flush the OS reports as failed must NOT be reported as success (ADR 0064:
   a status VALUE, never an unwind; fail-closed, NFR-SEC-POSTURE). return-from through unwind-protect still runs close."
  (let* ((native (uiop:native-namestring (uiop:ensure-directory-pathname path)))
         (fd     (cffi:foreign-funcall "open" :string native :int 0 :int))) ; O_RDONLY = 0 (POSIX)
    (when (minusp (the (signed-byte 32) fd))
      (return-from fsync-directory (values nil :fsync-failed)))
    (unwind-protect
         (when (minusp (the (signed-byte 32) (cffi:foreign-funcall "fsync" :int fd :int)))
           (return-from fsync-directory (values nil :fsync-failed)))
      (cffi:foreign-funcall "close" :int fd :int))
    (values t nil)))

(defun* lisp-eval-command (forms)
    (function (list) (or null list))
  "The command list for LAUNCH-PROGRAM that starts a CHILD of this same Lisp and evaluates each string in
   FORMS, in order (ADR 0116). The binary is this image's own (UIOP:ARGV0), so a child is always the same
   implementation as its parent.

   Clasp evaluates with --eval and has no --dynamic-space-size; --non-interactive keeps a failing child from parking in a REPL that never exits.

   ⛔ THE FLAGS ARE NOT COSMETIC. A child handed another implementation's flags does not report an error —
   it treats them as garbage and the parent waits forever for a service that never started, which is how
   the durability runner's SBCL-only argv stalled the whole suite on AllegroCL."
  (let ((bin (uiop:argv0)))
    (when (and bin (plusp (length bin)))          ; no argv0 => the caller cannot launch a child at all
      (append (list bin) (list "--non-interactive")
              (loop for f in forms append (list "--eval" f))))))
