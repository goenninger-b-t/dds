;;;; L7 — Transports. The transport record (IMPLEMENTATION-PLAN §7.5) is a plain
;;;; defstruct whose per-packet SEND slot is a stored function, so the latency
;;;; path stays dispatch-free even if the transport object is configured via CLOS.

(defpackage #:net.goenninger.dds.xport
  (:nicknames #:dds.xport)
  (:use #:common-lisp #:net.goenninger.dds.lang)
  (:documentation
   "Pluggable transport record (IMPLEMENTATION-PLAN §7.5). Adding a transport =
    constructing one record; the RTPS engine is untouched (FR-XPORT-5). M0 ships
    the record shape + a synchronous loopback mock used by the echo exit test.")
  (:export #:transport #:transport-p #:transport-kind
           #:transport-send #:transport-receive-loop
           #:transport-open-receive-resource #:transport-close
           #:transport-max-message-size #:transport-locator-kind
           #:send #:make-transport #:make-mock-transport))

(defpackage #:net.goenninger.dds.xport.udp
  (:nicknames #:dds.xport.udp)
  (:use #:common-lisp #:net.goenninger.dds.lang)
  (:documentation
   "UDPv4 transport (ADR 0006): wraps the frozen DDS.XPORT transport record
    around the native DDS.PAL UDP socket layer. make-udp-transport returns the
    raw PAL socket as a second value since the record has no slot for it.")
  (:export #:make-udp-transport #:udp-locator #:make-udp-locator
           #:udp-locator-host #:udp-locator-port
           #:udp-transport-local-port #:udp-transport-recv
           #:start-udp-receiver
           #:run-udp-transport-test #:run-udp-receiver-test))

(defpackage #:net.goenninger.dds.xport.shmem
  (:nicknames #:dds.xport.shmem)
  (:use #:common-lisp #:net.goenninger.dds.lang)
  (:documentation
   "POSIX shared-memory intra-host transport ring (FR-XPORT-2). Per-receiver
    segment: header + a pshared notify block (mutex+cond) + K per-sender SPSC
    lanes. Lane claim is mutex-guarded (no foreign CAS -> full Clasp parity); the
    SPSC enqueue/drain hot path is raw SAP read/write with release/acquire fences.
    Public API: make-shmem-transport returns a participant's receive segment + the
    frozen transport record; the receiver thread cond-waits on the notify block.
    %-internals are reached via :: by the test package.")
  (:export #:make-shmem-transport #:shmem-transport #:shmem-transport-transport
           #:shmem-transport-locator
           #:shmem-locator #:make-shmem-locator
           #:shmem-locator-name #:shmem-locator-host-uuid
           #:shmem-locator-lane-count #:shmem-locator-capacity
           #:seg-name-for-guid
           #:shmem-receive-drain #:shmem-transport-close
           #:start-shmem-receiver #:stop-shmem-receiver
           #:shm-attach-by-name-reliable-p
           #:*debug-shmem-send-fault* #:shmem-send-test-fault
           #:run-shmem-transport-test #:run-shmem-receiver-test #:run-shmem-stress-test))

(defpackage #:net.goenninger.dds.xport.zerocopy
  (:nicknames #:dds.xport.zerocopy)
  (:use #:common-lisp #:net.goenninger.dds.lang)
  (:documentation
   "WP-ZEROCOPY SHMEM sample-pool (FR-PF-3; ADR 0014). A per-writer pool of
    fixed-size slots over an mmap segment: the writer loans a slot, copies one
    serialized SerializedPayload in, and publishes a 16-byte reference instead of
    the payload; a same-host reader resolves the reference (bounds + generation
    guarded) and copies the slot out. All slot state (per-slot
    refcount/generation/len/pubseq) is mutated UNDER the pool's PTHREAD_PROCESS_SHARED
    mutex (no foreign-SAP CAS -> full Clasp parity); the freelist was dropped, so a
    slot is reclaimable iff refcount==0 and the writer scans for the oldest such slot
    (WP-ZC-LOAN-LOCKFREE, ADR 0018). Generation is the single guard for
    stale refs, force-reclaim mid-read, and untrusted cross-process references.
    NOT cleared for ship — pending counsel (R6); the path is off by default
    behind dds.disc:*zerocopy-enabled*. %-internals are reached via :: by tests.")
  (:export #:%zc-bytes #:%zc-init #:%zc-validate #:%zc-destroy
           #:%zc-slot-count #:%zc-slot-bytes #:%zc-free-count
           #:%zc-loan #:%zc-loan-acquire #:%zc-loan-commit #:%zc-loan-abort
           #:%zc-release #:%zc-resolve #:%zc-acquire-for-read
           #:*zc-pubseq*))
