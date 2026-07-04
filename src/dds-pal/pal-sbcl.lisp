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


(defun* pal-impl-name ()
    (function () keyword)
  "Return a keyword naming the running implementation."
  #+sbcl :sbcl
  #-sbcl :unknown)

;;; ---- memory: off-heap, non-GC'd, raw-pointer-addressable ----

(defun* alloc-static (n-bytes)
    (function ((integer 0)) (simple-array (unsigned-byte 8) (*)))
  "Allocate N-BYTES of off-heap octet memory the GC neither scans, moves, nor
   reclaims. Returns a foreign-backed (unsigned-byte 8) vector with a stable
   address (SBCL static-vectors are foreign-allocated, so the SAP is GC-stable)."
  (declare (type (integer 0) n-bytes))
  (static-vectors:make-static-vector n-bytes :element-type '(unsigned-byte 8)))

(defun* free-static (vec)
    (function ((simple-array (unsigned-byte 8) (*))) t)
  "Release memory obtained from ALLOC-STATIC. Idempotency is the caller's job."
  (static-vectors:free-static-vector vec))

(defun* static-pointer (vec)
    (function ((simple-array (unsigned-byte 8) (*))) t)
  "Return the raw foreign pointer (SBCL system-area-pointer) to VEC for syscalls."
  (static-vectors:static-vector-pointer vec))

(defun* static-length (vec)
    (function ((simple-array (unsigned-byte 8) (*))) (integer 0))
  "Octet length of a static region from ALLOC-STATIC."
  (length vec))

(defun* static-vector-p (vec)
    (function (t) boolean)
  "T iff VEC is an ALLOC-STATIC-backed (foreign, off the GC dynamic space, non-moved, SAP-addressable) octet
   vector, NIL for a plain GC-heap array. sb-ext:heap-allocated-p returns NIL for a static-vectors foreign
   vector and a space keyword (e.g. :dynamic) for a heap array. The secret-hygiene predicate: anything a raw
   SAP addresses must be foreign/static so a MOVING GC cannot copy it (operating contract §4); proves
   KeyMaterial secrets live off the GC heap (ADR-0034)."
  (and (typep vec '(simple-array (unsigned-byte 8) (*)))
       (null (sb-ext:heap-allocated-p vec))
       t))

;; sb-sys:sap+ over vector-sap == static-vector-pointer for a static-vectors vec (verified); inline-unboxed
(declaim (inline static-sap+))
(defun* static-sap+ (vec offset)
    (function ((simple-array (unsigned-byte 8) (*)) (integer 0)) t)
  "Raw foreign SAP at VEC[OFFSET], computed inline WITHOUT boxing the pointer (the safety-0 body
   preserves unboxing even at a default-safety caller, so a hot-path FFI :pointer arg conses 0 B).
   VEC MUST be an ALLOC-STATIC-backed (foreign, non-moving) vector — a GC-movable heap vector's SAP
   would be unsafe. Equivalent to (static-vectors:static-vector-pointer VEC :offset OFFSET) but
   non-consing; the boxing entry point STATIC-POINTER remains for control-plane use."
  (declare (optimize speed (safety 0)))
  (sb-sys:sap+ (sb-sys:vector-sap vec) offset))

(declaim (inline mem-ref-u8 mem-set-u8))
(defun* mem-ref-u8 (vec index)
    (function ((simple-array (unsigned-byte 8) (*)) (integer 0)) (unsigned-byte 8))
  "Typed raw read of one octet."
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
  "Total bytes consed so far (sb-ext:get-bytes-consed) — the NFR-PERF-8 oracle."
  (sb-ext:get-bytes-consed))

;;; ---- clock ----

(defun* monotonic-ns ()
    (function () integer)
  "Monotonic time in nanoseconds. M0 uses the portable real-time clock scaled to
   ns; a CFFI clock_gettime(CLOCK_MONOTONIC) fast path replaces this in M1."
  (multiple-value-bind (q) (truncate (* (get-internal-real-time)
                                        (/ 1000000000 internal-time-units-per-second)))
    q))

;;; ---- atomics / threads / gc ----
;;; Generic CAS/fetch-add over an ATOMIC-CELL (M0 stub CLOSED, ADR 0041); the
;;; SAP-targeted hot-path atomics are below (M1, ADR 0013).

(defun* cas (cell old new)
    (function (atomic-cell (unsigned-byte 64) (unsigned-byte 64)) (unsigned-byte 64))
  "Atomically compare-and-swap CELL's VALUE: if it = OLD store NEW, and return the PREVIOUS
   value either way (the swap succeeded iff the return is = OLD). A full-barrier
   (sequentially-consistent) RMW via sb-ext:cas over the (unsigned-byte 64) ATOMIC-CELL-VALUE
   slot (lowers to a LOCK CMPXCHG / arm64 CASAL carrying acquire+release ordering). Returns the
   previous value, matching the SAP sibling CAS-SAP-U64 (ADR 0041)."
  (sb-ext:cas (atomic-cell-value cell) old new))
(defun* atomic-incf (cell &optional (delta 1))
    (function (atomic-cell &optional fixnum) (unsigned-byte 64))
  "Atomically add DELTA (signed; default 1) to CELL's VALUE modulo 2^64 and return the NEW value.
   A full-barrier (sequentially-consistent) RMW via sb-ext:atomic-incf, which returns the OLD
   value on SBCL — normalized here to the new by (+ old delta) masked to 64 bits (matching the SAP
   sibling ATOMIC-INCF-SAP-U64, which also returns the new). A negative DELTA decrements (modular).
   (ADR 0041.)"
  (declare (type fixnum delta))
  (logand (+ (sb-ext:atomic-incf (atomic-cell-value cell) delta) delta) #xFFFFFFFFFFFFFFFF))
(defun* fence (&optional (kind :full))
    (function (&optional t) (values))
  "Real memory barrier (M1). :acquire = load barrier, :release = store barrier, :full = full."
  (ecase kind
    (:acquire (sb-thread:barrier (:read)))
    (:release (sb-thread:barrier (:write)))
    (:full    (sb-thread:barrier (:memory))))
  (values))

(defun* load-sap-u8 (sap offset)
    (function (t (integer 0)) (unsigned-byte 8))
  "8-bit unsigned read of the foreign location at SAP+OFFSET (bytes). Backs the
   FlatData-over-Zero-Copy read-in-place accessors (WP-FLATDATA-ZC-LOAN, R6 — NOT
   cleared for ship, see ADR 0017): a literal-0-copy field read straight off a
   SHMEM pool slot SAP, byte-exact to the aref accessor (XCDR2-LE)."
  (sb-sys:sap-ref-8 sap offset))
(defun* load-sap-u16 (sap offset)
    (function (t (integer 0)) (unsigned-byte 16))
  "Aligned 16-bit little-endian unsigned read of the foreign location at SAP+OFFSET
   (bytes). Backs the FlatData-over-Zero-Copy read-in-place accessors
   (WP-FLATDATA-ZC-LOAN, R6 — NOT cleared for ship, see ADR 0017): a literal-0-copy
   field read straight off a SHMEM pool slot SAP, byte-exact to the aref accessor."
  (sb-sys:sap-ref-16 sap offset))
(defun* load-sap-u32 (sap offset)
    (function (t (integer 0)) (unsigned-byte 32))
  "Aligned 32-bit little-endian unsigned read of the foreign location at SAP+OFFSET
   (bytes). Backs the FlatData-over-Zero-Copy read-in-place accessors
   (WP-FLATDATA-ZC-LOAN, R6 — NOT cleared for ship, see ADR 0017): a literal-0-copy
   field read straight off a SHMEM pool slot SAP, byte-exact to the aref accessor."
  (sb-sys:sap-ref-32 sap offset))
(defun* load-sap-u64 (sap offset)
    (function (t (integer 0)) (unsigned-byte 64))
  "Aligned 64-bit read of the foreign location at SAP+OFFSET (bytes)."
  (sb-sys:sap-ref-64 sap offset))
(defun* store-sap-u64 (sap offset value)
    (function (t (integer 0) (unsigned-byte 64)) (unsigned-byte 64))
  "Aligned 64-bit write of VALUE at SAP+OFFSET (bytes)."
  (setf (sb-sys:sap-ref-64 sap offset) value))
(defun* store-sap-u8 (sap offset value)
    (function (t (integer 0) (unsigned-byte 8)) (unsigned-byte 8))
  "8-bit write of VALUE at SAP+OFFSET (bytes). Backs the FlatData loan-write SAP-mode Offset
   setters (WP-FLATDATA-LOAN-WRITE, R6 — NOT cleared for ship, see ADR 0042): a literal-0-copy
   field write straight into a SHMEM pool slot SAP, byte-exact to the aref setter (XCDR2-LE)."
  (setf (sb-sys:sap-ref-8 sap offset) value))
(defun* cas-sap-u64 (sap offset old new)
    (function (t (integer 0) (unsigned-byte 64) (unsigned-byte 64)) (unsigned-byte 64))
  "Atomic compare-and-swap of the u64 at SAP+OFFSET; returns the PREVIOUS value (= OLD on success)."
  (sb-ext:cas (sb-sys:sap-ref-64 sap offset) old new))
(defun* cas-sap-u32 (sap offset old new)
    (function (t (integer 0) (unsigned-byte 32) (unsigned-byte 32)) (unsigned-byte 32))
  "Atomic compare-and-swap of the u32 at SAP+OFFSET; returns the PREVIOUS value (= OLD on success). The
   full-barrier (arm64 CASAL) atomic backing the lock-free loan release: it CASes ONLY the 4-byte refcount
   sub-field directly, so the combined (generation<<32)|refcount value never materialises — no bignum boxing
   at any generation (NFR-MEM, the 0-alloc-at-any-generation fix). Same acquire+release ordering as
   CAS-SAP-U64 (WP-ZC-LOAN-LOCKFREE, R6 — NOT cleared for ship, see ADR 0018)."
  (sb-ext:cas (sb-sys:sap-ref-32 sap offset) old new))
(defun* atomic-incf-sap-u64 (sap offset delta)
    (function (t (integer 0) (unsigned-byte 64)) (unsigned-byte 64))
  "Atomically add DELTA to the u64 at SAP+OFFSET; returns the NEW value."
  ;; sb-ext:atomic-incf rejects SAP-REF places; build fetch-add from the supported CAS-SAP-U64.
  (loop
    (let* ((old (sb-sys:sap-ref-64 sap offset))
           (new (logand (+ old delta) #xFFFFFFFFFFFFFFFF)))
      (when (= old (cas-sap-u64 sap offset old new))
        (return new)))))

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
   0.9.4 has no portable broadcast, so this uses the native SB-THREAD:CONDITION-BROADCAST (the bt condvar is
   an SB-THREAD:WAITQUEUE) — the only correct way to release several waiters on one event (e.g. several
   publishers blocked on a full HistoryCache, ADR 0016 §Backpressure)."
  (sb-thread:condition-broadcast cv))

(defun* install-signal-handler (signals callback)
    (function (list function) (eql t))
  "Register CALLBACK (a 0-arg fn) for each signal in SIGNALS (list of (member :term :int)) — SBCL via
   sb-sys:enable-interrupt. The handler runs CALLBACK in the signal context; CALLBACK must be minimal
   (set a flag / wake a thread), never do teardown inline. No reader conditional escapes dds-pal/."
  (dolist (s signals)
    (let ((signum (ecase s
                    (:term sb-unix:sigterm)
                    (:int  sb-unix:sigint))))
      (sb-sys:enable-interrupt
       signum
       (lambda (signo info context)
         (declare (ignore signo info context))
         (funcall callback)))))
  t)

(defun* register-image-restart-hook (hook)
    (function ((or symbol function)) (eql t))
  "Register HOOK (a 0-arg function or fbound symbol) to run at IMAGE STARTUP — after a save-lisp-and-die dump
   is restarted, before the toplevel — via sb-ext:*init-hooks*. The portable seam for re-resolving state a
   dumped core cannot carry live across restart (foreign-symbol pointers, re-mapped shared libraries). The
   owning module registers ONCE at its load time; on a load-from-source run the hook simply never fires (no
   restart occurs). Idempotent (pushnew, eq). No reader conditional escapes dds-pal/."
  (pushnew hook sb-ext:*init-hooks* :test #'eq)
  t)

(defun* gc-suggest ()
    (function () (values))
  "Suggest a GC to the implementation. M0 no-op."
  (values))
(defmacro with-gc-inhibited (&body body)
  "M0: no-op wrapper. SBCL's sb-sys:without-gcing lands behind an explicit unsafe
   flag in a later ADR (REQUIREMENTS NFR-DET)."
  `(progn ,@body))

(defun* fsync-stream (stream)
    (function (stream) (eql t))
  "Flush CL stream buffers then fdatasync the underlying fd on SBCL fd-streams.
   Falls back to finish-output when the stream is not an SBCL fd-stream (NFR-PORT).
   SIGNALS an error if fdatasync(2) returns -1 (EIO/ENOSPC): a durability flush that the OS
   reports as failed must NOT be reported as success — the caller surfaces it (fail-closed,
   NFR-SEC-POSTURE: never silently treat un-synced data as durable)."
  (finish-output stream)
  #+sbcl
  (let ((fd (when (typep stream 'sb-sys:fd-stream) (sb-sys:fd-stream-fd stream))))
    (when (and fd (minusp (the (signed-byte 32)
                               (cffi:foreign-funcall "fdatasync" :int fd :int))))
      (error "dds.pal:fsync-stream: fdatasync(fd=~d) failed" fd)))
  t)

(defun* fsync-directory (path)
    (function ((or pathname string)) (eql t))
  "Persist the DIRENT of a newly-created or renamed file: open(PATH, O_RDONLY), fsync(fd), close(fd).
   POSIX requires fsyncing the CONTAINING DIRECTORY (not just the file contents) so a create/rename
   survives a power loss (ADR 0026 §10.10 / §10.11, ADR 0029). The CFFI open/fsync/close path is
   impl-agnostic (identical body in pal-clasp.lisp — no NFR-PORT split needed, unlike fsync-stream).
   O_RDONLY = 0 on Linux and macOS. On macOS fsync(2) on a directory fd is valid and flushes the
   dirent to the drive; F_FULLFSYNC (full platter flush) is a stronger guarantee not required here.
   SIGNALS an error on open/fsync failure — a dirent flush the OS reports as failed must NOT be
   reported as success (fail-closed, NFR-SEC-POSTURE)."
  (let* ((native (uiop:native-namestring (uiop:ensure-directory-pathname path)))
         (fd     (cffi:foreign-funcall "open" :string native :int 0 :int))) ; O_RDONLY = 0 (POSIX)
    (when (minusp (the (signed-byte 32) fd))
      (error "dds.pal:fsync-directory: open(~a, O_RDONLY) failed" native))
    (unwind-protect
         (when (minusp (the (signed-byte 32) (cffi:foreign-funcall "fsync" :int fd :int)))
           (error "dds.pal:fsync-directory: fsync(fd=~d, ~a) failed" fd native))
      (cffi:foreign-funcall "close" :int fd :int))
    t))
