;;;; DDS.PAL — L0 Platform Abstraction Layer contract (frozen M0).
;;;; Impl-agnostic surface only. Per-impl code lives in pal-<impl>.lisp and is
;;;; the ONLY place where #+sbcl/#+allegro/#+clasp reader conditionals may appear.

(defpackage #:net.goenninger.dds.pal
  (:nicknames #:dds.pal)
  (:use #:common-lisp #:net.goenninger.dds.lang)
  (:documentation
   "Platform Abstraction Layer: the single frozen contract (REQUIREMENTS NFR-PORT,
    IMPLEMENTATION-PLAN §7.6). Every layer above L0 depends ONLY on these symbols.
    Capabilities: off-heap static memory, typed raw R/W, bounded pin, atomics,
    threads, sockets, monotonic clock, GC control, optimization hints.")
  (:export
   ;; conditions
   #:pal-error #:pal-op
   ;; capability introspection
   #:+pal-capabilities+ #:pal-impl-name
   ;; memory (off-heap, non-GC'd, raw-pointer-addressable)
   #:alloc-static #:free-static #:static-pointer #:static-length #:static-sap+
   #:sap-copy-in #:sap-copy-out #:*memcpy-fp*
   #:static-vector-p
   #:mem-ref-u8 #:mem-set-u8
   ;; atomics: generic CAS / fetch-add over a PAL ATOMIC-CELL (M0 stub CLOSED, ADR 0041);
   ;; foreign-SAP fast paths for the hot path (M1, ADR 0013)
   #:cas #:atomic-incf #:fence #:atomic-cell #:make-atomic-cell #:atomic-cell-value
   #:cas-sap-u64 #:cas-sap-u32 #:atomic-incf-sap-u64 #:load-sap-u64 #:store-sap-u64
   ;; foreign-SAP fixed-width unsigned reads — back the FlatData-ZC read-in-place
   ;; accessors (WP-FLATDATA-ZC-LOAN; R6, NOT cleared for ship — see ADR 0017).
   ;; IMPLEMENTED ON BOTH IMPLS (the Clasp stubs are gone — see the PAL-UNIMPLEMENTED note below).
   #:load-sap-u8 #:load-sap-u16 #:load-sap-u32
   ;; foreign-SAP 8-bit write — backs the FlatData loan-write SAP-mode Offset setters
   ;; (WP-FLATDATA-LOAN-WRITE; R6, NOT cleared for ship — see ADR 0042). Both impls.
   #:store-sap-u8
   ;; shared memory segments + in-segment PTHREAD_PROCESS_SHARED mutex/condvar (FR-XPORT-2, ADR 0013)
   #:shm-create #:shm-attach #:shm-detach #:shm-destroy #:shm-sap #:shm-segment-size
  ;; System V shared memory (shmget/shmat) — a SECOND mechanism, distinct from the POSIX objects
  ;; above, needed to reach RTI Connext's shared-memory segments, which are keyed by integer
  ;; (segment = 0x400000 + RTPS port) rather than named (ADR 0081)
  #:sysv-shm-attach-readonly #:sysv-shm-attach-readwrite #:sysv-shm-create #:sysv-shm-detach #:sysv-shm-destroy
  #:sysv-shm-sap #:sysv-shm-segment-size #:sysv-shm-segment-key #:sysv-shm-segment-p
  ;; System V semaphores (semget/semop/semctl) — the mutex + data-flag guarding an RTI Connext
  ;; shared-memory ring; a writer takes the mutex and raises the data flag with SETVAL (ADR 0081 §5.0)
  #:sysv-sem-open #:sysv-sem-create #:sysv-sem-op #:sysv-sem-setval #:sysv-sem-getval #:sysv-sem-destroy
  #:sysv-sem-set #:sysv-sem-set-p #:sysv-sem-set-key #:sysv-sem-setval-reliable-p
   #:pshared-mutex-init #:pshared-cond-init #:pshared-lock #:pshared-unlock
   #:pshared-cond-wait #:pshared-cond-signal #:pshared-cond-broadcast #:pshared-destroy
   ;; threads (condvar-wait: (cv lock &optional timeout-seconds) -> woke-p; nil timeout
   ;; = wait forever, else bounded; re-check the predicate on wake — ADR 0007)
   #:spawn #:join #:make-lock #:with-lock #:make-condvar #:condvar-wait #:condvar-signal
   #:condvar-broadcast
   ;; thread introspection (control-plane: the background-thread lifecycle gates, WP-DCPS-API-COMPLETION S7)
   #:live-threads #:thread-name
   ;; process signal handling (SIGTERM/SIGINT -> 0-arg callback; ADR 0026 §10 graceful teardown)
   #:install-signal-handler
   ;; image lifecycle: run a 0-arg hook at startup after a save-lisp-and-die restart, so a dumped core
   ;; can re-resolve state it cannot carry live across restart, e.g. foreign-symbol pointers / re-mapped
   ;; libraries (dds.dare EVP re-resolution; ADR 0038/0039 saved-image residual)
   #:register-image-restart-hook
   ;; clock
   #:monotonic-ns #:realtime-ns
   ;; UDPv4 sockets (native, FR-XPORT-1)
   #:udp-open #:udp-local-port #:udp-send-to #:udp-recv #:udp-close
   #:udp-set-reuse-port #:udp-join-multicast
   ;; The zero-allocation raw sendto(2)/recvfrom(2) datagram paths (NFR-MEM, ADR 0065/0066):
   ;; the A/B levers + escape hatches
   #:*udp-raw-sendto* #:*udp-raw-recvfrom*
   ;; TCPv4 stream sockets (native, FR-XPORT-1). Byte-stream full-send / full-frame recv loops
   ;; (a stream is not message-framed): tcp-send loops over short writes, tcp-recv loops until LEN
   ;; bytes or peer-close (status :EOF). tcp-set-recv-timeout arms SO_RCVTIMEO so a stalled tcp-recv
   ;; returns status :TIMEOUT (a DoS/idle guard) instead of blocking forever. tcp-shutdown (shutdown(2) SHUT_RDWR)
   ;; portably WAKES a thread blocked in tcp-recv (Linux + Darwin) WITHOUT freeing the fd — the clean
   ;; cross-thread server-stop wake, no double-close (ADR 0050 §4.8). Backs the durability MICROSERVICE
   ;; persistence backend (ADR 0050).
   #:tcp-connect #:tcp-listen #:tcp-accept #:tcp-local-port #:tcp-send #:tcp-recv #:tcp-close
   #:tcp-shutdown #:tcp-set-recv-timeout
   ;; gc control / measurement
   #:gc-suggest #:with-gc-inhibited #:bytes-consed
   ;; optimization hints
   #:with-hot-optimizations
   ;; file sync (group-commit; fdatasync on SBCL, finish-output on Clasp — NFR-PORT)
   #:fsync-stream
   ;; directory sync: open(dir,O_RDONLY)+fsync+close so a newly-created/renamed dirent
   ;; (log file, epochs.dat, compaction rename) survives power loss — POSIX requires
   ;; fsyncing the CONTAINING directory to persist the dirent (ADR 0026 §10.10)
   #:fsync-directory))

(in-package #:dds.pal)

(define-condition pal-error (error) ()
  (:documentation "Base class for all PAL-level failures (control plane only). RETAINED ONLY AS A TYPE for
   any consumer still naming it; NOTHING IN THIS STACK SIGNALS IT (ADR 0064 — no Lisp conditions in our
   code). It carries no subclasses any more."))

;; PAL-UNIMPLEMENTED is GONE, and not because it was converted to a status — because THE GAP IT NAMED DOES
;; NOT EXIST. It was signalled by seven Clasp capability stubs (load-sap-u8/u16/u32, store-sap-u8,
;; cas-sap-u64/u32, atomic-incf-sap-u64) on the claim that Clasp cannot read, write, or atomically
;; compare-and-swap a raw foreign cell. cffi:mem-ref does the loads/stores on Clasp exactly as
;; sb-sys:sap-ref-N does on SBCL, and the C atomic runtime linked into the Clasp image
;; (__atomic_compare_exchange_8/_4, __atomic_fetch_add_8) gives real hardware CAS over a plain pointer —
;; measured: full-width 2^64-1 operands round-trip and 8-thread contention loses nothing. All seven are
;; implemented; the Clasp PAL is now capability-equal to the SBCL PAL (owner directive 2026-07-14).

;; PAL-TIMEOUT is GONE (operating contract: no Lisp conditions in our code). TCP-RECV's read/idle timeout
;; was the one PAL condition on a data path; it is now the STATUS VALUE :TIMEOUT, returned as TCP-RECV's
;; second value and distinguished from :EOF and from data exactly as the condition was. Nothing signals,
;; so nothing has to catch: a stalled/slow-loris peer is a status the caller tests, not a stack unwind.

(defparameter +pal-capabilities+
  '(:memory :atomics :threads :sockets :clock :gc-control :opt-hints)
  "The capability groups every PAL implementation MUST eventually satisfy.")

(defmacro with-hot-optimizations (&body body)
  "Expand to this build's strongest safe-enough hot-path declarations.
   M0 baseline keeps SAFETY at 1 while the manual bounds-checks (NFR-SEC-POSTURE)
   are being established; a later ADR drops designated kernels to (safety 0)."
  `(locally (declare (optimize (speed 3) (safety 1) (debug 0) (space 0)))
     ,@body))

;;; ---- atomics: the ATOMIC-CELL the per-impl CAS / ATOMIC-INCF target ----
;;; Impl-agnostic (identical defstruct on both impls), so it lives in the contract; only the
;;; per-impl CAS/ATOMIC-INCF ops carry reader conditionals (pal-<impl>.lisp).

(defstruct* (atomic-cell (:constructor make-atomic-cell))
  "A PAL atomic counter cell: a single (unsigned-byte 64) VALUE slot that CAS and ATOMIC-INCF
   operate on atomically. It is the CONCRETE PLACE the M0 generic atomics needed to close their
   stub (ADR 0041): the native read-modify-write primitives (SBCL sb-ext:, Clasp mp:) are
   place-form MACROS that must see a compile-time-known place, so the old runtime place-fn
   indirection could not be lowered to a hardware atomic (ADR 0013) — a first-class cell whose
   FIXED slot those macros target is the portable way to expose them as ordinary functions. A
   single (unsigned-byte 64) slot is the one representation both sb-ext:cas/atomic-incf and
   mp:cas/atomic-incf accept for BOTH ops (probed). Build with MAKE-ATOMIC-CELL (VALUE defaults
   0); read the live value with ATOMIC-CELL-VALUE — a plain (relaxed) load, so use CAS/ATOMIC-INCF
   for an atomic RMW and FENCE for standalone ordering."
  (value 0 :type (unsigned-byte 64)))
