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
           #:*shmem-rx-spin-iterations* #:start-shmem-receiver #:stop-shmem-receiver
           #:shm-attach-by-name-reliable-p
           #:*debug-shmem-send-fault* #:shmem-send-test-fault
           ;; The resolved-once destination cache (NFR-MEM, ADR 0067): the A/B lever + escape hatch
           #:*shmem-dest-cache*
           #:run-shmem-transport-test #:run-shmem-receiver-test #:run-shmem-stress-test
           #:run-shmem-dest-cache-test
           #:run-shmem-attach-cache-race-test))

(defpackage #:net.goenninger.dds.xport.rti-shmem
  (:nicknames #:dds.xport.rti-shmem)
  (:use #:common-lisp #:net.goenninger.dds.lang)
  (:documentation
   "RTI Connext shared-memory segment recognition (ADR 0081). Distinct from DDS.XPORT.SHMEM, which is
    OUR OWN POSIX-shm transport: Connext uses System V segments keyed by integer (segment key =
    0x400000 + RTPS port) and identifies a host by a `shmemUUID` carried BOTH in its advertised
    Locator_t and in the segment header. This package answers co-location — whether an RTI peer is on
    this machine — which per RTI's published header requires reading the segment, not just the locator.
    Read-only throughout; nothing here writes to a segment owned by Connext. The layout is measured, not
    published: see docs/adr/0081-*.md and the reproduction harness interop/connext/shmem-layout/.")
  (:export #:rti-shmem-same-host-p #:rti-shmem-segment-key
           #:+rti-shmem-segment-key-base+ #:+rti-shmem-semaphore-key-base+ #:+rti-shmem-mutex-key-base+
           #:+rti-shmem-protocol-major-validated+ #:+rti-shmem-uuid-bytes+
           #:rti-shmem-segment-properties #:rti-shmem-datagram-fits-p
           #:rti-shmem-properties #:rti-shmem-properties-p
           #:rti-shmem-properties-segment-size #:rti-shmem-properties-receive-buffer-size
           #:rti-shmem-properties-message-size-max #:rti-shmem-properties-received-message-count-max
           #:rti-shmem-ring-start #:rti-shmem-ring-modulus #:rti-shmem-record-offset
           #:rti-shmem-read-record #:rti-shmem-write-record
           #:run-rti-shmem-recognition-test #:run-rti-shmem-properties-test
           #:run-rti-shmem-ring-address-test #:run-rti-shmem-read-record-test
           #:run-rti-shmem-write-roundtrip-test))

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
           #:%zc-release #:%zc-pin #:%zc-resolve #:%zc-acquire-for-read
           #:*zc-pubseq*))
