;;;; DDS.PAL — AllegroCL implementation of the L0 contract (ADR 0004 follow-through, ADR 0113).
;;;; This file is the ONLY location permitted to carry #+allegro conditionals.
;;;;
;;;; Verified against International Allegro CL Enterprise Edition 11.0, 64-bit Linux (x86-64) SMP.
;;;; Every implementation choice below was PROBED on that build, not inferred: the three backends genuinely
;;;; disagree (SBCL's single-float-bits is SIGNED, Clasp's is UNSIGNED, Allegro's is a pair of unsigned
;;;; shorts; SBCL's atomic-incf returns the OLD value, Allegro's incf-atomic returns the NEW), and absorbing
;;;; exactly that is what the PAL exists for.
;;;;
;;;; ⚠️ SCOPE: this file completes the 36 per-implementation symbols of the PAL CONTRACT. The SOCKET layer
;;;; in pal-net.lisp is separate and NOT yet ported — 16 of its 68 functions are written against
;;;; SB-BSD-SOCKETS, which SBCL and Clasp both bundle and AllegroCL does not, so :DDS-PAL still does not
;;;; load here. The other 32 pal-net functions are pure CFFI (mmap, POSIX/SysV shm, semaphores, pshared
;;;; mutex+condvar) and are expected to work unchanged. See ADR 0113.

(in-package #:dds.pal)

#-allegro
(eval-when (:compile-toplevel :load-toplevel :execute)
  ;; A diagnostic, not a condition (ADR 0064: nothing in our code signals), and not a WARN — under a
  ;; warnings-as-errors build policy that would fail a build merely for loading the wrong PAL.
  (format *error-output*
          "~&dds.pal: pal-allegro.lisp loaded on a non-Allegro build — this PAL is not the one for this image.~%"))

#+allegro
(progn

;;; ---- FOREIGN ATOMICS AVAILABILITY -------------------------------------------------------------------
;;;
;;; ⛔ LIBATOMIC MUST BE LOADED EXPLICITLY HERE. The SAP atomics below call the GCC/C11 primitives
;;; __atomic_compare_exchange_4/_8 and __atomic_fetch_add_8 through %GLOBAL-SYMBOL-POINTER, exactly as the
;;; Clasp PAL does. On Clasp they resolve for free because its runtime already links libatomic; in an
;;; Allegro image they resolve to NIL until the library is mapped — PROBED: all three answer NIL before
;;; this load and a valid pointer after it. Without this the SHMEM lane claim and the Zero-Copy refcount
;;; would fail at their first call rather than at load, which is the worst place to discover it.
(eval-when (:load-toplevel :execute)
  (handler-case (cffi:load-foreign-library "libatomic.so.1")
    (error () nil)))   ; absent libatomic: the pointers below stay NIL and the SAP atomics report it

;;; ---- OFF-HEAP STATIC MEMORY --------------------------------------------------------------------------

(defun* alloc-static (n-bytes)
    (function ((integer 0)) (simple-array (unsigned-byte 8) (*)))
  "N-BYTES of zeroed off-heap, non-GC'd, raw-pointer-addressable octets (REQUIREMENTS NFR-MEM). Backed by
   STATIC-VECTORS, whose Allegro backend was probed working (allocate, aref, take a pointer, free)."
  (static-vectors:make-static-vector n-bytes :element-type '(unsigned-byte 8) :initial-element 0))

(defun* free-static (vec)
    (function ((simple-array (unsigned-byte 8) (*))) t)
  "Release VEC, previously returned by ALLOC-STATIC. Foreign memory: never reclaimed by the GC."
  (static-vectors:free-static-vector vec)
  t)

(declaim (inline static-pointer))
(defun* static-pointer (vec)
    (function ((simple-array (unsigned-byte 8) (*))) t)
  "The foreign address of VEC's first octet. ⚠️ On Allegro CFFI represents a pointer as an INTEGER, not a
   wrapper object (probed) — every PAL consumer passes it straight back to CFFI, so this is immaterial to
   callers, but it is why nothing here may assume CFFI:POINTERP."
  (static-vectors:static-vector-pointer vec))

(defun* static-length (vec)
    (function ((simple-array (unsigned-byte 8) (*))) (integer 0))
  "VEC's length in octets."
  (length vec))

(declaim (inline static-sap+))
(defun* static-sap+ (vec offset)
    (function ((simple-array (unsigned-byte 8) (*)) (integer 0)) t)
  "A foreign pointer to VEC's octet at OFFSET."
  (declare (optimize speed (safety 0)))
  (cffi:inc-pointer (static-vectors:static-vector-pointer vec) offset))

(defun* static-vector-p (vec)
    (function (t) boolean)
  "T iff VEC is usable as a static octet vector. Like the Clasp PAL, this cannot DISCRIMINATE an off-heap
   vector from a heap one — that discrimination is SBCL-only (ADR 0034) — so it answers the type question
   only. A documented NFR-PORT gap, not a silent difference: the teardown WIPE still runs; what is missing
   is the ability to REJECT a heap array handed in by mistake."
  (and (typep vec '(simple-array (unsigned-byte 8) (*))) t))

(declaim (inline mem-ref-u8 mem-set-u8))
(defun* mem-ref-u8 (vec index)
    (function ((simple-array (unsigned-byte 8) (*)) (integer 0)) (unsigned-byte 8))
  "VEC's octet at INDEX."
  (declare (type (simple-array (unsigned-byte 8) (*)) vec))
  (aref vec index))

(defun* mem-set-u8 (vec index value)
    (function ((simple-array (unsigned-byte 8) (*)) (integer 0) (unsigned-byte 8)) (unsigned-byte 8))
  "Set VEC's octet at INDEX to VALUE."
  (declare (type (simple-array (unsigned-byte 8) (*)) vec) (type (unsigned-byte 8) value))
  (setf (aref vec index) value))

;;; ---- FOREIGN SAP TYPED ACCESS ------------------------------------------------------------------------

(defun* load-sap-u8 (sap offset)
    (function (t (integer 0)) (unsigned-byte 8))
  "Aligned 8-bit unsigned read of the foreign location at SAP+OFFSET (bytes)."
  (cffi:mem-ref sap :uint8 offset))
(defun* load-sap-u16 (sap offset)
    (function (t (integer 0)) (unsigned-byte 16))
  "Aligned 16-bit unsigned read of the foreign location at SAP+OFFSET (bytes)."
  (cffi:mem-ref sap :uint16 offset))
(defun* load-sap-u32 (sap offset)
    (function (t (integer 0)) (unsigned-byte 32))
  "Aligned 32-bit unsigned read of the foreign location at SAP+OFFSET (bytes)."
  (cffi:mem-ref sap :uint32 offset))
(defun* load-sap-u64 (sap offset)
    (function (t (integer 0)) (unsigned-byte 64))
  "Aligned 64-bit read of the foreign location at SAP+OFFSET (bytes), masked to unsigned — the same guard
   the Clasp PAL carries, because a CFFI :uint64 mem-ref that sign-extends a high-bit-set word would make
   every SHMEM cursor comparison wrong at the 2^63 boundary."
  (logand (cffi:mem-ref sap :uint64 offset) #xFFFFFFFFFFFFFFFF))

(defun* store-sap-u8 (sap offset value)
    (function (t (integer 0) (unsigned-byte 8)) (unsigned-byte 8))
  "Aligned 8-bit store to the foreign location at SAP+OFFSET (bytes)."
  (setf (cffi:mem-ref sap :uint8 offset) value))
(defun* store-sap-u64 (sap offset value)
    (function (t (integer 0) (unsigned-byte 64)) (unsigned-byte 64))
  "Aligned 64-bit store to the foreign location at SAP+OFFSET (bytes)."
  (setf (cffi:mem-ref sap :uint64 offset) value))

;;; ---- ATOMICS ------------------------------------------------------------------------------------------

(defparameter *cas-u64-fp* (%global-symbol-pointer "__atomic_compare_exchange_8")
  "The resolved __atomic_compare_exchange_8 pointer, looked up ONCE at load (after libatomic is mapped).
   Cached because a by-name foreign call re-resolves through dlsym on every call, and CAS is on the SHMEM
   lane-claim / Zero-Copy refcount hot path.")
(defparameter *cas-u32-fp* (%global-symbol-pointer "__atomic_compare_exchange_4")
  "The resolved __atomic_compare_exchange_4 pointer (see *CAS-U64-FP*).")
(defparameter *fetch-add-u64-fp* (%global-symbol-pointer "__atomic_fetch_add_8")
  "The resolved __atomic_fetch_add_8 pointer (see *CAS-U64-FP*).")

(defconstant +atomic-seq-cst+ 5
  "The C11 memory_order_seq_cst enumerator, passed to the __atomic_* builtins. Pinned from the GCC/C11
   __atomic builtins ABI, where the memory-order enumerators are 0=relaxed, 1=consume, 2=acquire,
   3=release, 4=acq_rel, 5=seq_cst — the same value the Clasp PAL uses, and not a value to reconstruct
   from memory.")

(defmacro %cas-sap (fp sap offset old new ctype)
  "Compare-and-swap the CTYPE-wide foreign word at SAP+OFFSET, returning the PREVIOUS value. The C11
   builtin takes the expected value BY REFERENCE and overwrites it with the actual one on failure, which
   is exactly the previous-value semantics the PAL contract wants — so the expected slot is read back
   rather than guessed."
  `(cffi:with-foreign-object (expected ,ctype)
     (setf (cffi:mem-ref expected ,ctype) ,old)
     (cffi:foreign-funcall-pointer
      ,fp () :pointer (cffi:inc-pointer ,sap ,offset) :pointer expected
      ,ctype ,new :int 0 :int +atomic-seq-cst+ :int +atomic-seq-cst+ :int)
     (cffi:mem-ref expected ,ctype)))

(defun* cas-sap-u64 (sap offset old new)
    (function (t (integer 0) (unsigned-byte 64) (unsigned-byte 64)) (unsigned-byte 64))
  "Atomically compare-and-swap the 64-bit foreign word at SAP+OFFSET; return the PREVIOUS value (the swap
   succeeded iff the return is = OLD). Sequentially consistent."
  (%cas-sap *cas-u64-fp* sap offset old new :uint64))

(defun* cas-sap-u32 (sap offset old new)
    (function (t (integer 0) (unsigned-byte 32) (unsigned-byte 32)) (unsigned-byte 32))
  "Atomically compare-and-swap the 32-bit foreign word at SAP+OFFSET; return the PREVIOUS value.
   Sequentially consistent. Backs the Zero-Copy refcount's direct u32 CAS."
  (%cas-sap *cas-u32-fp* sap offset old new :uint32))

(defun* atomic-incf-sap-u64 (sap offset delta)
    (function (t (integer 0) (unsigned-byte 64)) (unsigned-byte 64))
  "Atomically add DELTA to the 64-bit foreign word at SAP+OFFSET and return the NEW value, modulo 2^64.
   __atomic_fetch_add returns the OLD value, so DELTA is added back — matching ATOMIC-INCF, which also
   returns the new."
  (logand (+ delta (cffi:foreign-funcall-pointer
                    *fetch-add-u64-fp* () :pointer (cffi:inc-pointer sap offset)
                    :uint64 delta :int +atomic-seq-cst+ :uint64))
          #xFFFFFFFFFFFFFFFF))

(defun* cas (cell old new)
    (function (atomic-cell (unsigned-byte 64) (unsigned-byte 64)) (unsigned-byte 64))
  "Atomically compare-and-swap CELL's VALUE: if it = OLD store NEW, and return the PREVIOUS value either
   way (the swap succeeded iff the return is = OLD), matching the SAP sibling CAS-SAP-U64 (ADR 0041).

   ⚠️ ALLEGRO'S PRIMITIVE ANSWERS A BOOLEAN, NOT THE PREVIOUS VALUE. EXCL::ATOMIC-CONDITIONAL-SETF is
   (PLACE NEW-VAL OLD-VAL) — note new BEFORE old, the reverse of this function's argument order — and
   returns T/NIL (probed). On success the previous value WAS old, so it is returned exactly. On failure
   the slot is re-read, and that re-read is NOT atomic with the failed swap: a caller can therefore be
   told a previous value that has already changed again. That is sound for the only use this contract
   sanctions — a CAS retry loop, which re-reads and retries anyway — and it is why callers must treat a
   non-OLD return as 'retry', never as 'the value is now exactly this'."
  (if (excl::atomic-conditional-setf (atomic-cell-value cell) new old)
      old
      (atomic-cell-value cell)))

(defun* atomic-incf (cell &optional (delta 1))
    (function (atomic-cell &optional fixnum) (unsigned-byte 64))
  "Atomically add DELTA (signed; default 1) to CELL's VALUE modulo 2^64 and return the NEW value.
   EXCL::INCF-ATOMIC already returns the NEW value (probed: 9 + 3 => 12), unlike SBCL's ATOMIC-INCF which
   returns the old — so no normalisation is needed here, only the 64-bit mask."
  (declare (type fixnum delta))
  (logand (excl::incf-atomic (atomic-cell-value cell) delta) #xFFFFFFFFFFFFFFFF))

(defun* fence (&optional (kind :full))
    (function (&optional t) (values))
  "A memory barrier. MP::MEMORY-BARRIER is a full (sequentially-consistent) barrier, which is STRONGER than
   :acquire or :release and therefore a correct implementation of all three — never weaker, which is the
   only direction that could break the SHMEM ring's release/acquire handshake."
  (declare (ignore kind))
  (mp::memory-barrier)
  (values))

;;; ---- THREADS, LOCKS, CONDITION VARIABLES --------------------------------------------------------------

(defun* make-lock (&optional name)
    (function (&optional (or null string)) t)
  "A mutex. Via BORDEAUX-THREADS, whose Allegro backend is present and loads."
  (bordeaux-threads:make-lock (or name "dds-lock")))

(defmacro with-lock ((lock) &body body)
  "Evaluate BODY with LOCK held."
  `(bordeaux-threads:with-lock-held (,lock) ,@body))

(defun* join (thread)
    (function (t) t)
  "Wait for THREAD to finish and return its value."
  (bordeaux-threads:join-thread thread))

(defun* make-condvar ()
    (function () t)
  "A condition variable for use with CONDVAR-WAIT / CONDVAR-SIGNAL."
  (bordeaux-threads:make-condition-variable))

(defun* condvar-wait (cv lock &optional timeout-seconds)
    (function (t t &optional t) t)
  "Wait on CV releasing LOCK. NIL TIMEOUT-SECONDS waits forever, else a bounded wait; re-check the
   predicate on wake (ADR 0007)."
  (if timeout-seconds
      (bordeaux-threads:condition-wait cv lock :timeout timeout-seconds)
      (bordeaux-threads:condition-wait cv lock)))

(defun* condvar-signal (cv)
    (function (t) t)
  "Wake ONE thread waiting on CV."
  (bordeaux-threads:condition-notify cv))

(defun* condvar-broadcast (cv)
    (function (t) t)
  "Wake EVERY thread waiting on CV. Goes to MP: rather than BORDEAUX-THREADS: because this
   bordeaux-threads has no CONDITION-BROADCAST at all (probed NIL) — signalling in a loop would be a
   different operation, not an equivalent one, since it cannot bound the number of waiters."
  (mp::condition-variable-broadcast cv))

;;; ---- GC, PLATFORM MISCELLANY --------------------------------------------------------------------------

(defun* bytes-consed ()
    (function () integer)
  "Total heap octets consed by this image. Returns 0 on AllegroCL — a documented NFR-PORT MEASUREMENT gap,
   identical to the Clasp PAL's, and the reason `make gate-mem` runs on SBCL. It is a gap in the ability to
   MEASURE allocation here, never a difference in how much is allocated."
  0)

(defun* gc-suggest ()
    (function () (values))
  "Suggest a collection. EXCL:GC runs a scavenge (probed callable, with and without a full-GC argument)."
  (excl::gc)
  (values))

(defmacro with-gc-inhibited (&body body)
  "Evaluate BODY with the GC inhibited where the implementation supports it. On AllegroCL this is a plain
   PROGN, exactly as on Clasp: the hot paths that would need it draw from the static arena and touch no
   GC-managed memory, so inhibiting nothing changes nothing. Kept as a macro so the contract has one
   spelling on every implementation."
  `(progn ,@body))

(defun* pal-impl-name ()
    (function () keyword)
  "This image's implementation keyword."
  :allegro)

(defun* internal-bug-p (condition)
    (function (t) t)
  "T iff CONDITION signals an IMPLEMENTATION-INTERNAL invariant violation (as opposed to an ordinary
   runtime failure) — ADR 0100 uses it to latch a corrupt structure out of the send path instead of
   folding it into routine fallback. NIL on AllegroCL: no distinguished internal-bug condition type is
   relied upon, so this is a documented NFR-PORT gap, the same one Clasp carries. The consequence is
   explicit — an internal bug here is treated as a routine emit failure, which is the pre-ADR-0100
   behaviour, never a silent change."
  (declare (ignore condition))
  nil)

(defun* install-signal-handler (signals callback)
    (function (list function) (eql t))
  "Install CALLBACK for each of SIGNALS (keywords, e.g. :INT :TERM). EXCL::SET-SIGNAL-HANDLER takes the
   signal NUMBER, so the keywords are mapped from the POSIX numbers on Linux/x86-64: SIGINT 2, SIGTERM 15,
   SIGHUP 1. An unrecognised keyword is skipped rather than guessed at."
  (dolist (s signals t)
    (let ((n (case s (:int 2) (:term 15) (:hup 1) (t nil))))
      (when n (excl::set-signal-handler n callback)))))

(defun* register-image-restart-hook (hook)
    (function ((or symbol function)) (eql t))
  "Arrange for HOOK to run when a dumped image restarts — the point at which every cached foreign pointer
   from the previous process is stale and must be re-resolved. AllegroCL calls
   EXCL::*RESTART-INIT-FUNCTION* once on restart, and it holds ONE function rather than a list, so this
   CHAINS: the previous value (if any) is called first, then HOOK. Chaining rather than overwriting is the
   difference between two subsystems both getting their re-resolve and one silently losing it."
  (let ((prev excl::*restart-init-function*))
    (setf excl::*restart-init-function*
          (lambda () (when prev (funcall prev)) (funcall hook))))
  t)

(defun* fsync-stream (stream)
    (function (stream) (values (or null (eql t)) (or null keyword)))
  "Flush STREAM's buffers toward the device. Lisp-level flush only, as on Clasp — a documented durability
   gap versus the SBCL PAL, which reaches the file descriptor. Returns (values T NIL)."
  (finish-output stream)
  (force-output stream)
  (values t nil))

(defun* fsync-directory (path)
    (function ((or pathname string)) (eql t))
  "fsync(2) the DIRECTORY at PATH, so a rename into it is durable. Opens O_RDONLY through CFFI — the same
   portable route the Clasp PAL takes, since no Lisp-level operation reaches a directory fd."
  (let* ((native (uiop:native-namestring (uiop:ensure-directory-pathname path)))
         (fd (cffi:foreign-funcall "open" :string native :int 0 :int)))
    (when (minusp (the (signed-byte 32) fd))
      (return-from fsync-directory t))          ; cannot open: nothing to sync, never a hard failure
    (unwind-protect (cffi:foreign-funcall "fsync" :int fd :int)
      (cffi:foreign-funcall "close" :int fd :int)))
  t)

;;; ---- IEEE 754 BIT-PATTERN CONVERSION (ADR 0111 §2.3) --------------------------------------------------
;;;
;;; AllegroCL exposes the conversion as 16-bit SHORTS, most-significant first and UNSIGNED, rather than as
;;; one integer: (excl::single-float-to-shorts -1.0f0) => 49024, 0 = #xBF80 #x0000, and
;;; (excl::double-float-to-shorts -1.0d0) => 49136, 0, 0, 0 = #xBFF0 0 0 0. Probed, not assumed.
;;;
;;; ⚠️ NEGATIVE ZERO IS BIT-FAITHFUL THROUGH THESE PRIMITIVES, but NOT through Allegro's READER: the literal
;;; -0.0f0 reads as +0.0 (bits 0), and (- 0.0f0) is +0.0 too, while (* -1.0f0 0.0f0) is a true negative zero
;;; (bits #x80000000) which these carry intact both ways. FLOAT-SIGN also reports 1.0 for it. A test that
;;; builds negative zero from the literal therefore silently tests +0.0 here while passing on SBCL, which is
;;; why RUN-FLOAT-PRIMITIVES-TEST constructs it by multiplication and asserts its bit pattern first.

(defun* f32-bits (x)
    (function (single-float) (unsigned-byte 32))
  "The IEEE 754 binary32 bit pattern of X as a 32-bit unsigned integer (XTypes 1.3 Table 31: Float32,
   encoded size 4, alignment 4). Total over denormals, the infinities, NaNs and negative zero."
  (multiple-value-bind (hi lo) (excl::single-float-to-shorts x)
    (logior (ash hi 16) lo)))

(defun* f32-from-bits (b)
    (function ((unsigned-byte 32)) single-float)
  "The single-float whose IEEE 754 binary32 bit pattern is B. Exact inverse of F32-BITS."
  (excl::shorts-to-single-float (ldb (byte 16 16) b) (ldb (byte 16 0) b)))

(defun* f64-bits (x)
    (function (double-float) (unsigned-byte 64))
  "The IEEE 754 binary64 bit pattern of X as a 64-bit unsigned integer (XTypes 1.3 Table 31: Float64,
   encoded size 8, alignment 8). Total, as F32-BITS."
  (multiple-value-bind (a b c d) (excl::double-float-to-shorts x)
    (logior (ash a 48) (ash b 32) (ash c 16) d)))

(defun* f64-from-bits (v)
    (function ((unsigned-byte 64)) double-float)
  "The double-float whose IEEE 754 binary64 bit pattern is V. Exact inverse of F64-BITS."
  (excl::shorts-to-double-float (ldb (byte 16 48) v) (ldb (byte 16 32) v)
                                (ldb (byte 16 16) v) (ldb (byte 16 0) v)))

(defun* lisp-eval-command (forms)
    (function (list) (or null list))
  "The command list for LAUNCH-PROGRAM that starts a CHILD of this same Lisp and evaluates each string in
   FORMS, in order (ADR 0116). The binary is this image's own (UIOP:ARGV0), so a child is always the same
   implementation as its parent.

   AllegroCL evaluates with -e (NOT --eval) and has no --dynamic-space-size; -batch is what makes it non-interactive. ⚠️ -q is deliberately NOT passed: it suppresses the init file, which is where a site puts its ASDF/Quicklisp bootstrap — and a child that cannot find ASDF is exactly the failure this function exists to avoid.

   ⛔ THE FLAGS ARE NOT COSMETIC. A child handed another implementation's flags does not report an error —
   it treats them as garbage and the parent waits forever for a service that never started, which is how
   the durability runner's SBCL-only argv stalled the whole suite on AllegroCL."
  (let ((bin (uiop:argv0)))
    (when (and bin (plusp (length bin)))          ; no argv0 => the caller cannot launch a child at all
      (append (list bin) (list "-batch")
              (loop for f in forms append (list "-e" f))))))

) ; #+allegro
