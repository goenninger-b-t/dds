;;;; L5 — SPDP + SEDP discovery over UDP (FR-DISC-1/4). A disc-node owns a
;;;; metatraffic UDPv4 socket and a background receiver thread. SPDP: it announces
;;;; its SPDPdiscoveredParticipantData to its unicast peers and records the
;;;; participants it learns from inbound SPDP. SEDP: it announces its local
;;;; publication/subscription endpoints to discovered participants and records the
;;;; remote endpoints that satisfy RxO matching against its local ones. The wire
;;;; codecs + builtin EntityIds are pinned from docs/specs in DDS.RTPS.*; nothing
;;;; here is memorized. Discovery is control-plane: all serialization reuses two
;;;; per-node scratch buffers (allocated once, freed in stop-node) so repeated
;;;; announces allocate zero foreign memory (NFR-MEM). Single announce thread
;;;; assumed. Multicast still deferred.

(in-package #:dds.disc)

(defparameter *shmem-enabled*
  (and (find-package :net.goenninger.dds.xport.shmem)
       (not (and (eq (dds.pal:pal-impl-name) :clasp) (uiop:os-macosx-p))))
  "Master switch (read once per node at make-disc-node into the SHMEM slot) for routing same-host user
   DATA over the shared-memory transport (FR-XPORT-2) instead of UDP. Default: T on SBCL everywhere and
   Clasp/Linux (where the SHMEM package is present and by-name attach works); NIL on Clasp/macOS — that
   platform's shm_open variadic-mode ABI gap (ADR 0013, dds.xport.shmem:shm-attach-by-name-reliable-p)
   makes a created segment unre-openable by name, so SHMEM is unusable there and UDP carries everything.
   Rebind to NIL before make-disc-node to force the all-UDP path (e.g. cross-host deployments where no
   same-host peer can exist). Not a wire constant — a local transport-selection policy.")

;;;; NOT cleared for ship — pending counsel (R6); see ADR 0014.
(defvar *zerocopy-enabled* nil
  "WP-ZEROCOPY master switch (FR-PF-3). DEFAULT NIL — Zero-Copy is patent-gated (R6) and NOT cleared for
   ship pending counsel; it never engages unless explicitly enabled. When T (and SHMEM is available + a
   matched reader is same-host + ZC-capable) the writer sends a 16-byte reference instead of the payload.")

;;;; NOT cleared for ship — pending counsel (R6); see ADR 0014.
(defconstant +zerocopy-pool-slots+ 32
  "WP-ZEROCOPY per-writer pool slot count K (FR-PF-3, ADR 0014). Defined ONCE; used by BOTH the node's
   pool creation and the advertised slot geometry (the WP-SHMEM DRY lesson). NOT a wire constant.")

;;;; NOT cleared for ship — pending counsel (R6); see ADR 0014.
(defconstant +zerocopy-pool-slot-bytes+ 65536
  "WP-ZEROCOPY per-slot payload capacity in octets (FR-PF-3, ADR 0014). A serialized SerializedPayload
   larger than this falls back to normal DATA (%zc-loan returns NIL). Defined ONCE; used by BOTH pool
   creation and the advertised geometry. NOT a wire constant.")

;;;; NOT cleared for ship — pending counsel (R6); see ADR 0014.
(defparameter *zerocopy-min-payload-bytes* 1024
  "WP-ZEROCOPY size threshold (FR-PF-3): a serialized SerializedPayload at or below this many octets is
   NOT worth a pool slot + a 16-byte reference (the small-sample path is the WP-SHMEM/batching target),
   so the writer sends it as normal DATA. Only payloads STRICTLY LARGER are stored in the pool and sent
   as a reference. A local policy, NOT a wire constant; tunable.")

(defconstant +shmem-default-lane-count+ 8
  "Default per-receiver SHMEM lane count (max concurrent same-host senders); must match the advertised wire locator (FR-XPORT-2).")

(defconstant +shmem-default-capacity+ 65536
  "Default per-lane SHMEM ring capacity in bytes (multiple of 8); must match the advertised wire locator (FR-XPORT-2).")

(defun* %host-uuid ()
    (function () (unsigned-byte 64))
  "A u64 identifying THIS host so same-host SHMEM peers match: the low 8 octets of the MD5 (reusing the
   vendored dds.core.md5, no new dependency) of (uiop:hostname). Deterministic — same hostname yields the
   same uuid — so two participants on one host agree without exchanging it out of band. A boot-id would
   harden against same-hostname-different-host, but hostname suffices for v1: a collision only makes a
   cross-host SHMEM attempt fail and fall back to UDP (no data loss). Not a wire constant."
  (let ((d (dds.core.md5:md5 (map '(simple-array (unsigned-byte 8) (*)) #'char-code (uiop:hostname))))
        (v 0))
    (dotimes (i 8 v) (setf v (logior (ash v 8) (aref d i))))))

(defstruct* (disc-node (:constructor %make-disc-node))
  "A minimal RTPS participant for discovery. SOCKET/TRANSPORT carry metatraffic;
   PEERS are unicast SPDP targets; DISCOVERED maps a remote 12-octet GUID prefix
   to its SPDP data; LOCAL-WRITERS/LOCAL-READERS are this node's endpoints; MATCHES
   maps a remote 16-octet endpoint GUID to the remote endpoint-data that matched a
   local endpoint; INCOMPAT maps a remote GUID whose topic+type agreed but whose QoS
   failed RxO (drives OFFERED/REQUESTED_INCOMPATIBLE_QOS). LOCK guards DISCOVERED +
   MATCHES + INCOMPAT + PARKED-MATCHES plus the TypeLookup service state (TL-PENDING,
   TL-REQ-SN, TL-REPLY-SN, TL-SENT) and the Writer Liveliness Protocol state
   (PM-WRITER-SN, REMOTE-LIVELINESS) across the receiver thread. REMOTE-LIVELINESS maps
   a (12-octet remote prefix . ParticipantMessageData kind) to the internal-real-time
   stamp of the last inbound liveliness assertion from that participant (RTPS 2.5
   §8.4.13.5); PM-WRITER-SN is the BuiltinParticipantMessageWriter's monotonic SN.
   LIVELINESS-STATE maps a matched remote-writer GUID to its current alive-p flag so
   %liveliness-sweep fires ON-LIVELINESS-CHANGED only on an alive<->not-alive TRANSITION
   (RTPS 2.5 §8.4.13). ON-MATCH /
   ON-INCOMPATIBLE-QOS / ON-SAMPLE are optional control-plane hooks the DCPS layer
   installs to surface matched/incompatible events and newly-arrived user data to the
   application (DDS statuses, listeners, and the condvar-driven WaitSet wake); each
   match/incompatible hook fires once per remote endpoint, ON-SAMPLE once per stored
   user sample. ON-UNMATCH is the dual of ON-MATCH: %lease-sweep fires it (direction .
   remote) for every matched endpoint removed when its participant leases out (RTPS 2.5
   §8.5.3.3.2). PARTICIPANT-LAST-SEEN stamps each discovered prefix's last SPDP refresh
   so the sweep can detect stale entries (guarded by LOCK). TYPE-GATE is an optional type-compatibility gate consulted OUTSIDE
   the lock (user code, like the ON-* hooks) as (funcall gate node remote local) —
   REMOTE + LOCAL are dds.rtps.discovery:endpoint-data — before a match is recorded
   in EITHER direction; verdicts: :compatible (record + fire as usual), :incompatible
   (routed to the INCONSISTENT_TOPIC path, like a type-name mismatch), :pending (the
   (direction . remote) decision is parked on PARKED-MATCHES, deduped by remote GUID,
   until resume-parked-matches re-runs it); a NIL gate (default) behaves exactly as
   :compatible. TX-PAYLOAD/TX-MSG are the reused announce scratch buffers. SHMEM (when
   *shmem-enabled*) is this node's shared-memory receive transport; HOST-UUID identifies the host so a
   same-host peer that advertised a SHMEM locator receives user DATA over SHMEM instead of UDP
   (FR-XPORT-2); SHMEM-SENDS counts those routed datagrams. SHMEM-DEST-CACHE memoizes each remote
   prefix's resolved shmem-locator (or :none) so the steady-state send does no per-datagram resolve +
   make-shmem-locator allocation (a peer is resolved at most once; the entry is invalidated on that
   peer's SPDP re-discovery and on its lease-out). Discovery/HEARTBEAT/ACKNACK always stay UDP."
  (guid-prefix (make-array 12 :element-type '(unsigned-byte 8) :initial-element 0)
               :type (simple-array (unsigned-byte 8) (12)))
  (domain 0 :type (integer 0))
  (advertise-address "127.0.0.1" :type string)
  (socket nil :type t)
  (transport nil :type (or null dds.xport:transport))
  (spdp-sn 0 :type integer)
  (sedp-sn 0 :type integer)
  (peers '() :type list)
  (discovered (make-hash-table :test 'equalp) :type hash-table)
  (matches (make-hash-table :test 'equalp) :type hash-table)
  (incompat (make-hash-table :test 'equalp) :type hash-table)
  (inconsistent (make-hash-table :test 'equalp) :type hash-table)
  (parked-matches '() :type list) ; (direction . remote endpoint-data), TYPE-GATE :pending; stale snapshots are pre-empted by SEDP re-announce

  (discovered-writers (make-hash-table :test 'equalp) :type hash-table) ; all remote publications
  (discovered-readers (make-hash-table :test 'equalp) :type hash-table) ; all remote subscriptions
  (local-writers '() :type list)
  (local-readers '() :type list)
  (lock (dds.pal:make-lock "disc-node") :type t)
  (tx-payload nil :type (or null dds.core.buffer:octet-buffer))
  (tx-msg nil :type (or null dds.core.buffer:octet-buffer))
  (rx-tx-msg nil :type (or null dds.core.buffer:octet-buffer))
  (user-writer nil :type (or null dds.rtps.reliable:rtps-writer))
  (user-reader nil :type (or null dds.rtps.reliable:rtps-reader))
  (user-writer-id #x00000102 :type (unsigned-byte 32)) ; this node's user-data writer EntityId (kind reflects keyed-ness)
  (user-reader-id #x00000107 :type (unsigned-byte 32)) ; this node's user-data reader EntityId
  ;; FR-XPORT-2 SHMEM intra-host data plane (same-host user DATA only; discovery/HB/ACKNACK stay UDP)
  (shmem nil :type t)                     ; this node's shmem-transport (NIL = SHMEM off: *shmem-enabled* nil or pkg absent)
  (host-uuid 0 :type (unsigned-byte 64))  ; u64 host id (MD5 of hostname); a remote with the SAME uuid is same-host
  (shmem-sends 0 :type (integer 0))       ; count of user DATA datagrams this node routed over SHMEM (proof/diagnostic)
  (shmem-send-faults 0 :type fixnum)      ; WP-SHMEM-SEND-SELF-GUARD: count of SIGNALED %shmem-send faults caught in %send-raw-buf and degraded to the UDP fallback (proof/diagnostic; FR-XPORT-2)
  (shmem-dest-cache (make-hash-table :test 'equalp) :type hash-table) ; remote 12-octet prefix -> shmem-locator | :none; one-time resolve per peer (hot-path send reads, no lock/alloc); invalidated on SPDP re-discovery + lease-out
  ;; WP-ZEROCOPY (FR-PF-3, ADR 0014; NOT cleared for ship — pending counsel R6). All NIL/0 unless
  ;; *zerocopy-enabled* AND this node has SHMEM. ZC-POOL is this writer's per-participant SHMEM
  ;; sample-pool segment (named seg-name-for-guid + "z"); ZC-POOL-SAP caches its mapped base SAP so the
  ;; publish hook needs no per-sample shm-sap call. ZC-SENDS counts samples sent as a 16-byte reference
  ;; (proof/diagnostic). ZC-ATTACH-CACHE memoizes, on the READER side, each source participant's attached
  ;; pool segment keyed by its 12-octet prefix (attach once per remote writer; the resolved payload is
  ;; copied into a FRESH per-datagram vector so concurrent receiver threads — UDP + SHMEM — never share a
  ;; sink; freed in stop-node). ZC-ATTACH-LOCK serializes the first attach for one remote writer across
  ;; receiver threads.
  (zc-pool nil :type t)                    ; this writer's pool shm-segment (NIL = ZC off)
  (zc-pool-sap nil :type t)                ; cached mapped base SAP of zc-pool
  (zc-sends 0 :type (integer 0))           ; user samples this node published as a zero-copy reference
  (zc-attach-cache (make-hash-table :test 'equalp) :type hash-table) ; reader side: remote 12-octet prefix -> attached pool shm-segment | :none
  (zc-attach-lock (dds.pal:make-lock "zc-attach") :type t)
  (zc-loan-capable nil :type t)            ; WP-FLATDATA-ZC-LOAN (FR-PF-3/4, R6, ADR 0017): DCPS set this iff the local reader is on a :flatdata topic AND ZC armed -> the receiver thread stores the UNRESOLVED ref (no copy/release; the slot stays loaned via the writer's refcount) and DCPS take-loaned/return-loan owns the slot lifetime. NIL (default) = today's resolve-copy-release. NOT cleared for ship — pending counsel (R6)
  (batch-max-samples 1 :type (integer 1)) ; WP-BATCH size trigger: flush the accumulated batch every N publishes (1 = flush per write, no batching)
  (batch-pending 0 :type (integer 0))     ; samples accumulated since the last flush (a flush pacer; %push-data always sends all unsent)
  ;; WP-ASYNC: a background sender thread decoupling the push from write() (nil async-thread = synchronous, default)
  (async-thread nil :type t)
  (async-lock (dds.pal:make-lock "async") :type t)
  (async-cv (dds.pal:make-condvar) :type t)
  (async-pending nil :type t)             ; work to flush (guarded by async-lock)
  (async-stop nil :type t)                ; shutdown requested (guarded by async-lock)
  (async-tx-msg nil :type (or null dds.core.buffer:octet-buffer)) ; the sender thread's OWN scratch buffer
  (async-emit-errors 0 :type fixnum) ; WP-SENDER-ERROR-RESILIENCE: count of emit errors the async sender thread caught + survived (FR-PF-2)
  (flow-step-state nil :type t) ; WP-ASYNC-FLOW: the node's in-progress per-datagram send plan ((host . port) . PLAN), threaded across %flow-step-emit calls; NIL = rebuild on next call
  (flow-controller nil :type t) ; WP-ASYNC-FLOW: the flow-controller this writer is associated with (NIL = none); set/cleared under the CONTROLLER lock; non-NIL makes publish async-and-paced (the controller thread sends)
  (flow-pending nil :type t)    ; WP-ASYNC-FLOW: new unsent work awaiting a fresh plan snapshot; set by %flow-signal, cleared by the scheduler — guarded by the CONTROLLER lock (NOT the node lock)
  (samples (make-hash-table :test 'equalp) :type hash-table) ; 2-level: 16-octet src GUID (equalp) -> SN (eql) -> payload (§8.3.5.4: SN is per-writer; no per-sample composite-key alloc)
  (sample-writers (make-hash-table :test 'equalp) :type hash-table) ; src GUID -> SN -> writer EntityId (reader-side instance writers-set, DDS 1.4 §2.2.2.5.1.3)
  (sample-writer-guids (make-hash-table :test 'equalp) :type hash-table) ; src GUID -> SN -> 16-octet source GUID (EXCLUSIVE ownership arbitration, DDS 1.4 §2.2.3.9.2)
  (sample-origins (make-hash-table :test 'equalp) :type hash-table) ; src GUID -> SN -> (effective-origin-GUID . effective-origin-SN): the PID_ORIGINAL_WRITER_INFO logical origin when the received sample was relayed (RTPS 2.5 §8.3.5.4), absent for a direct sample (then the wire GUID/SN IS the origin)
  (capture-data-key-hash nil :type boolean) ; durability collect node opts in to materialize the wire PID_KEY_HASH on :data (control-plane); default NIL = byte-identical, no hot-path alloc (ADR 0029, RTPS 2.5 §9.6.4.8)
  (sample-key-hashes (make-hash-table :test 'equalp) :type hash-table) ; src GUID -> SN -> 16-octet wire key-hash of the :data sample (RTPS 2.5 §9.6.4.8), absent when not captured
  (lifecycle-changes (make-hash-table :test 'equalp) :type hash-table) ; 2-level: 16-octet src GUID (equalp) -> SN (eql) -> (kind key-hash status writer-id source-guid) (§8.3.5.4: SN is per-writer; no per-change composite-key alloc)
  (ack-count 0 :type integer)
  (acks-in 0 :type integer)
  (builtin-readers (make-hash-table :test 'equalp) :type hash-table) ; remote 12-octet prefix -> reliable SEDP reader
  (participant-last-seen (make-hash-table :test 'equalp) :type hash-table) ; remote 12-octet prefix -> internal-real-time of last SPDP refresh
  ;; TypeLookup service endpoint state (typelookup-endpoints.lisp, XTypes 1.3 §7.6.3.3)
  (tl-pending (make-hash-table :test 'eql) :type hash-table) ; request SN -> tl-pending-entry
  (tl-req-sn 1 :type integer)
  (tl-reply-sn 1 :type integer)
  (tl-sent '() :type list) ; reply writer resend store: newest-first (sn . reply-octets)
  ;; Writer Liveliness Protocol state (participant-message.lisp, RTPS 2.5 §8.4.13)
  (pm-writer-sn 1 :type integer) ; BuiltinParticipantMessageWriter per-writer SN (1-based)
  (remote-liveliness (make-hash-table :test 'equalp) :type hash-table) ; (12-octet prefix . kind) -> %lease-now stamp
  (liveliness-state (make-hash-table :test 'equalp) :type hash-table) ; matched remote-writer 16-octet GUID -> alive-p (reader-side LIVELINESS_CHANGED transition flag)

  (on-data nil :type (or null function))
  (on-lifecycle nil :type (or null function))
  (on-lifecycle-event nil :type (or null function)) ; DCPS-facing: fired after a dispose/unregister is classified (S2)
  (on-heartbeat nil :type (or null function))
  (on-acknack nil :type (or null function))
  (on-gap nil :type (or null function))
  (on-data-frag nil :type (or null function))
  (on-heartbeat-frag nil :type (or null function))
  (on-nack-frag nil :type (or null function))
  (on-match nil :type (or null function))
  (on-unmatch nil :type (or null function))
  (on-liveliness-changed nil :type (or null function))
  (type-gate nil :type (or null function))
  (on-incompatible-qos nil :type (or null function))
  (on-inconsistent-topic nil :type (or null function))
  (on-sample nil :type (or null function))
  (mcast-socket nil :type t)
  (mcast-rx-thread nil :type t)
  (rx-thread nil :type t))

(defparameter +spdp-multicast-group+ "239.255.0.1"
  "Well-known SPDP DefaultMulticastLocator address (RTPS 2.5 §9.6.1.1): all
   participants announce + listen on UDPv4 239.255.0.1 : spdp-multicast-port.")

(defun* %zc-pool-name (guid)
    (function ((simple-array (unsigned-byte 8) (12))) string)
  "WP-ZEROCOPY pool segment name for a participant's 12-octet GUID prefix: the SHMEM receive-segment name
   (dds.xport.shmem:seg-name-for-guid, '/dds' + 10 hex = 14 chars) suffixed 'z' -> 15 chars, under the
   macOS ~31-char shm-name cap. The reader derives the SAME name from the DATA source prefix (no extra
   advertisement). ADR 0014; NOT a wire constant."
  (concatenate 'string (dds.xport.shmem:seg-name-for-guid guid) "z"))

(defun* %zc-make-pool (node)
    (function (disc-node) t)
  "Create + init this node's WP-ZEROCOPY writer pool (FR-PF-3, ADR 0014): an shm segment of
   +zerocopy-pool-slots+ x +zerocopy-pool-slot-bytes+ named %zc-pool-name. A stale leftover is unlinked +
   recreated by shm-create. Caller has gated on *zerocopy-enabled* AND the node having SHMEM. NOT cleared
   for ship — pending counsel (R6)."
  (let ((seg (dds.pal:shm-create (%zc-pool-name (disc-node-guid-prefix node))
                                 (dds.xport.zerocopy::%zc-bytes +zerocopy-pool-slots+ +zerocopy-pool-slot-bytes+))))
    (dds.xport.zerocopy::%zc-init (dds.pal:shm-sap seg) +zerocopy-pool-slots+ +zerocopy-pool-slot-bytes+)
    (setf (disc-node-zc-pool node) seg
          (disc-node-zc-pool-sap node) (dds.pal:shm-sap seg)))
  t)

(defun* %zc-node-capable-p (node)
    (function (disc-node) t)
  "T iff NODE is WP-ZEROCOPY-capable (FR-PF-3, ADR 0014): it has a writer pool (created at make-disc-node
   iff *zerocopy-enabled* was set then — the pool slot is the single source of truth, mirroring
   disc-node-shmem; not the special, which may be invisible to a later announce thread). Its local
   endpoints advertise PID_ZEROCOPY_CAPABLE iff this holds, so a peer only sends this node zero-copy
   references when it can actually resolve them (fail-open). NOT cleared for ship — pending counsel (R6)."
  (and (disc-node-zc-pool node) t))

(defun* make-disc-node (&key (guid-prefix (make-array 12 :element-type '(unsigned-byte 8)
                                                     :initial-element 0))
                            (domain 0) (host "127.0.0.1") (port 0) (peers '()) multicast
                            (advertise-address "127.0.0.1") (batch-max-samples 1)
                            (capture-data-key-hash nil))
    (function (&key (:guid-prefix (simple-array (unsigned-byte 8) (12))) (:domain (integer 0)) (:host string) (:port (unsigned-byte 16)) (:peers list) (:multicast t) (:advertise-address string) (:batch-max-samples (integer 1)) (:capture-data-key-hash t)) disc-node)
  "Open a metatraffic UDPv4 socket bound to HOST:PORT and build a discovery node.
   PEERS is a list of (host-string . port) the node announces SPDP to (FR-DISC-4).
   MULTICAST opens a second socket bound to the SPDP multicast port and joins the
   well-known group, so the node also discovers peers via multicast (FR-DISC-3).
   BATCH-MAX-SAMPLES > 1 enables WP-BATCH write-side batching (FR-PF-1): publish-sample defers the push
   until N samples accumulate or flush-batch fires (the announce cadence / stop-node), amortizing
   per-sample overhead for small samples (NFR-PERF-4). Default 1 = flush every write (no batching).
   CAPTURE-DATA-KEY-HASH (ADR 0029, RTPS 2.5 §9.6.4.8): when non-NIL, the receiver thread
   materializes the wire PID_KEY_HASH even on :data samples with payload (the durability collect node
   uses this; default NIL = byte-identical, no hot-path alloc)."
  ;; In multicast mode bind the unicast socket to 0.0.0.0: a loopback-bound socket
  ;; cannot egress to a multicast group (EADDRNOTAVAIL), and 0.0.0.0 still receives
  ;; unicast SEDP addressed to 127.0.0.1:port.
  (multiple-value-bind (tr sock)
      (dds.xport.udp:make-udp-transport :host (if multicast "0.0.0.0" host) :port port)
    (let* ((host-uuid (%host-uuid))
           (node (%make-disc-node :guid-prefix guid-prefix :domain domain
                                  :advertise-address advertise-address
                                  :socket sock :transport tr :peers peers
                                  :batch-max-samples batch-max-samples
                                  :capture-data-key-hash (and capture-data-key-hash t)
                                  :host-uuid host-uuid
                                  :shmem (when *shmem-enabled*   ; SHMEM receive segment for same-host user DATA (FR-XPORT-2)
                                           (dds.xport.shmem:make-shmem-transport
                                            :participant-guid guid-prefix :host-uuid host-uuid
                                            :lane-count +shmem-default-lane-count+ :capacity +shmem-default-capacity+))
                                  :tx-payload (dds.core.buffer:make-octet-buffer 512)
                                  :tx-msg (dds.core.buffer:make-octet-buffer 2048)
                                  :rx-tx-msg (dds.core.buffer:make-octet-buffer 2048))))
      (when multicast
        (let ((ms (dds.pal:udp-open :host "0.0.0.0"
                                    :port (dds.rtps.message:spdp-multicast-port domain)
                                    :reuse-port t)))
          (dds.pal:udp-join-multicast ms +spdp-multicast-group+)
          (setf (disc-node-mcast-socket node) ms)))
      (when (and *zerocopy-enabled* (disc-node-shmem node))   ; WP-ZEROCOPY writer pool (FR-PF-3, ADR 0014)
        (%zc-make-pool node))
      node)))

(defun* disc-node-port (node)
    (function (disc-node) (integer 0 65535))
  "The bound metatraffic UDP port of NODE."
  (dds.xport.udp:udp-transport-local-port (disc-node-socket node)))

(defun* %locator-port (p)
    (function ((unsigned-byte 32)) (unsigned-byte 16))
  "Narrow a wire Locator port (u32) to the UDP port range (u16)."
  (ldb (byte 16 0) p))

(defun* %make-endpoint-guid (prefix key kind)
    (function ((simple-array (unsigned-byte 8) (12)) (unsigned-byte 8) (unsigned-byte 8)) (simple-array (unsigned-byte 8) (16)))
  "GUID_t = 12-octet participant PREFIX + 4-octet entity id (00 00 KEY KIND),
   RTPS 2.5 §9.3.1.2."
  (let ((g (make-array 16 :element-type '(unsigned-byte 8) :initial-element 0)))
    (replace g prefix :start1 0 :end1 12)
    (setf (aref g 14) key (aref g 15) kind)
    g))

(defun* %ipv4-octets (host)
    (function (string) (simple-array (unsigned-byte 8) (4)))
  "Parse a dotted-quad 'a.b.c.d' string into a 4-octet vector."
  (let ((v (make-array 4 :element-type '(unsigned-byte 8))) (start 0))
    (dotimes (i 4 v)
      (let ((dot (position #\. host :start start)))
        (setf (aref v i) (parse-integer host :start start :end dot)
              start (if dot (1+ dot) (length host)))))))

(defun* %node-spdp-data (node)
    (function (disc-node) dds.rtps.discovery:spdp-data)
  "Build NODE's SPDPdiscoveredParticipantData: its GUID prefix + a unicast locator
   at <advertise-address>:<bound port> (default 127.0.0.1), protocol version 2.5. When SHMEM is on, ALSO
   advertise a SHMEM Locator_t (lanes+capacity) in default-unicast and the host-uuid (FR-XPORT-2) so a
   same-host peer can route user DATA over shared memory; metatraffic stays UDP-only (discovery on UDP)."
  (let* ((addr (dds.rtps.discovery:make-ipv4-locator
                (%ipv4-octets (disc-node-advertise-address node))))
         (port (disc-node-port node))
         (loc (dds.rtps.discovery:make-locator
               :kind dds.rtps.discovery:+locator-kind-udpv4+ :port port :address addr))
         (sm (disc-node-shmem node)))
    (dds.rtps.discovery:make-spdp-data
     :guid-prefix (disc-node-guid-prefix node)
     :version-major 2 :version-minor 5
     :vendor-id dds.rtps.message:*vendor-id*
     :default-unicast-locators (if sm
                                   (list loc (dds.rtps.discovery:make-shmem-locator-wire +shmem-default-lane-count+ +shmem-default-capacity+))
                                   (list loc))
     :metatraffic-unicast-locators (list loc)
     :host-uuid (if sm (disc-node-host-uuid node) 0)
     :lease-duration-seconds 100
     :builtin-endpoint-set dds.rtps.discovery:+builtin-endpoint-set-default+)))

(defun* %send-paramlist (node reader-id writer-id sn serialize-fn host port)
    (function (disc-node (unsigned-byte 32) (unsigned-byte 32) integer function string (unsigned-byte 16)) t)
  "Build a PL_CDR_LE SerializedPayload by calling SERIALIZE-FN on a fresh cursor
   over the node's reusable payload buffer, wrap it in a DATA submessage
   (READER-ID/WRITER-ID/SN) in the node's reusable message buffer, and send it to
   HOST:PORT. Reuses per-node scratch buffers — single announce thread assumed."
  (let* ((pl (disc-node-tx-payload node))
         (pc (dds.core.buffer:cursor pl :endianness :little)))
    (dds.cdr:make-encapsulation-header pc :pl-cdr-le)
    (funcall serialize-fn pc)
    (let* ((pl-len (dds.core.buffer:cursor-position pc))
           (pl-vec (dds.core.buffer:octet-buffer-vec pl))
           (msg (disc-node-tx-msg node))
           (mc (dds.core.buffer:cursor msg :endianness :little)))
      (dds.rtps.message:write-header mc (disc-node-guid-prefix node))
      (dds.rtps.message:write-data mc reader-id writer-id sn pl-vec 0 pl-len)
      (dds.xport:send (disc-node-transport node)
                      (dds.xport.udp:make-udp-locator :host host :port port)
                      msg 0 (dds.core.buffer:cursor-position mc)))))

(defun* announce-participant (node)
    (function (disc-node) (eql t))
  "Announce NODE's SPDPdiscoveredParticipantData (writer = SPDP builtin participant
   writer) to every unicast peer (FR-DISC-1/4) and, if multicast is enabled, to the
   well-known SPDP multicast group (FR-DISC-3). The SPDP data advertises the node's
   unicast metatraffic locator, so SEDP comes back unicast either way. Also asserts
   this participant's Writer Liveliness on the announce cadence (RTPS 2.5 §8.4.13.5,
   via assert-participant-liveliness)."
  (assert-participant-liveliness node)
  (incf (disc-node-spdp-sn node))
  (let ((sn (disc-node-spdp-sn node))
        (data (%node-spdp-data node)))
    (flet ((send-spdp (host port)
             (%send-paramlist node
                              dds.rtps.discovery:+entityid-spdp-reader+
                              dds.rtps.discovery:+entityid-spdp-writer+
                              sn
                              (lambda (c) (dds.rtps.discovery:serialize-spdp-data c data))
                              host port)))
      (dolist (peer (disc-node-peers node))
        (send-spdp (car peer) (cdr peer)))
      (when (disc-node-mcast-socket node)
        (send-spdp +spdp-multicast-group+
                   (dds.rtps.message:spdp-multicast-port (disc-node-domain node))))))
  t)

(defun* %qos-from-reliability (reliability)
    (function (integer) dds.qos:qos)
  "Build a QoS from a legacy wire reliability constant (back-compat for callers that
   pass :reliability rather than a full :qos)."
  (dds.qos:make-qos :reliability (if (>= reliability dds.rtps.discovery:+reliability-reliable+)
                                     :reliable :best-effort)))

(defun* add-local-writer (node &key (topic "") (type "")
                                   (reliability dds.rtps.discovery:+reliability-reliable+)
                                   (key 1) qos type-information (keyed t))
    (function (disc-node &key (:topic string) (:type string) (:reliability integer) (:key (unsigned-byte 8)) (:qos t) (:type-information t) (:keyed t)) dds.rtps.discovery:endpoint-data)
  "Register a local publication (writer endpoint) on NODE with QOS (or a QoS derived from
   the legacy :reliability constant). TYPE-INFORMATION is the opaque serialized XTypes
   TypeInformation for PID_TYPE_INFORMATION. announce-endpoints sends it via SEDP. KEYED
   selects the RTPS entity kind (RTPS 2.5 §9.3.1.2 Table 9.1): T (default) -> 0x02 (writer
   WITH_KEY), NIL -> 0x03 (writer NO_KEY); a keyed remote reader (RTI Connext) will not
   match a no-key writer. Sets NODE's user-writer-id so the data plane sends with this id."
  (let* ((kind (if keyed #x02 #x03))
         (ep (dds.rtps.discovery:make-endpoint-data
              :role :writer
              :guid (%make-endpoint-guid (disc-node-guid-prefix node) key kind)
              :topic-name topic :type-name type :type-information type-information
              :qos (or qos (%qos-from-reliability reliability)))))
    (setf (disc-node-user-writer-id node) (logior (ash key 8) kind))
    (push ep (disc-node-local-writers node))
    ep))

(defun* add-local-reader (node &key (topic "") (type "")
                                   (reliability dds.rtps.discovery:+reliability-best-effort+)
                                   (key 1) qos type-information (keyed t))
    (function (disc-node &key (:topic string) (:type string) (:reliability integer) (:key (unsigned-byte 8)) (:qos t) (:type-information t) (:keyed t)) dds.rtps.discovery:endpoint-data)
  "Register a local subscription (reader endpoint) on NODE with QOS (or a QoS derived from
   the legacy :reliability constant). TYPE-INFORMATION is the opaque serialized XTypes
   TypeInformation for PID_TYPE_INFORMATION. announce-endpoints sends it via SEDP. KEYED
   selects the RTPS entity kind (RTPS 2.5 §9.3.1.2 Table 9.1): T (default) -> 0x07 (reader
   WITH_KEY), NIL -> 0x04 (reader NO_KEY); a keyed reader will not match a no-key remote
   writer (and vice versa) — the disagreement is a silent non-match, not INCONSISTENT_TOPIC.
   Sets NODE's user-reader-id so the data plane routes HEARTBEAT/ACKNACK with this id."
  (let* ((kind (if keyed #x07 #x04))
         (ep (dds.rtps.discovery:make-endpoint-data
              :role :reader
              :guid (%make-endpoint-guid (disc-node-guid-prefix node) key kind)
              :topic-name topic :type-name type :type-information type-information
              :qos (or qos (%qos-from-reliability reliability)))))
    (setf (disc-node-user-reader-id node) (logior (ash key 8) kind))
    (push ep (disc-node-local-readers node))
    ep))

(defun* %discovered-participants (node)
    (function (disc-node) list)
  "Snapshot the discovered participants' SPDP data (lock-guarded)."
  (dds.pal:with-lock ((disc-node-lock node))
    (loop for v being the hash-values of (disc-node-discovered node) collect v)))

(defun* %send-endpoint (node reader-id writer-id ep sn host port)
    (function (disc-node (unsigned-byte 32) (unsigned-byte 32) dds.rtps.discovery:endpoint-data integer string (unsigned-byte 16)) t)
  "Announce one local endpoint EP via a SEDP DATA submessage to HOST:PORT with the STABLE
   per-writer sequence number SN. Re-announcing an endpoint RESENDS the same SN (a
   retransmission), never a fresh one: a remote RELIABLE SEDP reader cannot deliver any
   sample while an earlier SN is missing, so an ever-incrementing SN plus one lost push
   would gap it permanently (RTPS 2.5 §8.5.4 — each endpoint is one writer sample)."
  (%send-paramlist node reader-id writer-id sn
                   (lambda (c) (dds.rtps.discovery:serialize-endpoint-data c ep))
                   host port))

;;; ---- Reliable builtin (SEDP) discovery: ACKNACK remote builtin writers so a
;;; reliable peer (e.g. RTI Connext) pushes its SEDP DATA(w)/(r). A remote builtin
;;; writer (pub 0x...03c2 / sub 0x...04c2) is RELIABLE; without an ACKNACK it never
;;; sends its endpoint data. Builtin writers share their EntityId across participants,
;;; so SN state is tracked per remote participant (12-octet source GUID prefix).

(defun* %sedp-reader-id-for (writer-id)
    (function ((unsigned-byte 32)) (or null (unsigned-byte 32)))
  "The local SEDP reader EntityId matching a remote builtin SEDP writer WRITER-ID
   (publications/subscriptions), or NIL if WRITER-ID is not a builtin SEDP writer."
  (cond ((= writer-id dds.rtps.discovery:+entityid-sedp-pub-writer+)
         dds.rtps.discovery:+entityid-sedp-pub-reader+)
        ((= writer-id dds.rtps.discovery:+entityid-sedp-sub-writer+)
         dds.rtps.discovery:+entityid-sedp-sub-reader+)
        (t nil)))

(defun* %source-prefix (buf)
    (function (dds.core.buffer:octet-buffer) (simple-array (unsigned-byte 8) (12)))
  "The 12-octet source GUID prefix from the RTPS header of datagram BUF (offset 8; §9.4.4)."
  (let ((p (make-array 12 :element-type '(unsigned-byte 8))))
    (replace p (dds.core.buffer:octet-buffer-vec buf) :start2 8 :end2 20)
    p))

;; Endpoint GUID classifiers: defined in dataplane.lisp (loaded after this file).
(declaim (ftype (function ((simple-array (unsigned-byte 8) (16))) t) %writer-guid-p %reader-guid-p))

;; %lease-sweep is defined below but called from announce-endpoints above it.
(declaim (ftype (function (disc-node) (eql t)) %lease-sweep))

;; %source-guid is defined in dataplane.lisp (loaded after this file).
(declaim (ftype (function ((simple-array (unsigned-byte 8) (12)) (unsigned-byte 32))
                          (simple-array (unsigned-byte 8) (16))) %source-guid))

;; TypeLookup endpoint handlers: defined in typelookup-endpoints.lisp (loaded after this file).
(declaim (ftype (function ((unsigned-byte 32)) t) %tl-writer-p)
         (ftype (function ((unsigned-byte 32)) (or null (unsigned-byte 32))) %tl-reader-id-for)
         (ftype (function (disc-node (simple-array (unsigned-byte 8) (12)) (unsigned-byte 32) integer dds.core.buffer:octet-buffer (integer 0) (integer 0)) t) %on-tl-data)
         (ftype (function (disc-node (simple-array (unsigned-byte 8) (12)) dds.core.buffer:cursor (unsigned-byte 8)) t) %on-tl-acknack)
         (ftype (function (disc-node) (eql t)) tl-sweep))

;; Writer Liveliness Protocol handlers: defined in participant-message.lisp (loaded after this file).
(declaim (ftype (function (disc-node (simple-array (unsigned-byte 8) (12)) (unsigned-byte 32) integer dds.core.buffer:octet-buffer (integer 0) (integer 0)) t) %on-participant-message)
         (ftype (function (disc-node) (eql t)) assert-participant-liveliness)
         (ftype (function (disc-node) (eql t)) %liveliness-sweep))

(defun* %builtin-reader-nl (node prefix)
    (function (disc-node (simple-array (unsigned-byte 8) (12))) t)
  "Get/create the per-remote reliable SEDP reader for PREFIX. CALLER HOLDS the node lock."
  (or (gethash prefix (disc-node-builtin-readers node))
      (setf (gethash (copy-seq prefix) (disc-node-builtin-readers node))
            (dds.rtps.reliable:make-rtps-reader))))

(defun* %builtin-acknack-values (node prefix wid &optional hb-first hb-last)
    (function (disc-node (simple-array (unsigned-byte 8) (12)) (unsigned-byte 32) &optional (or null integer) (or null integer)) (values integer (unsigned-byte 32) (simple-array (unsigned-byte 32) (*)) (unsigned-byte 32)))
  "Under the node lock: optionally apply a HEARTBEAT range [HB-FIRST, HB-LAST] to the
   per-remote SEDP reader for WID, then compute its ACKNACK. Returns (values base numbits
   bitmap count). BITMAP is freshly allocated so it is safe to use outside the lock."
  (dds.pal:with-lock ((disc-node-lock node))
    (let ((reader (%builtin-reader-nl node prefix)))
      (when (and hb-first hb-last)
        (dds.rtps.reliable:reader-on-heartbeat reader wid hb-first hb-last))
      (multiple-value-bind (base numbits bitmap) (dds.rtps.reliable:reader-acknack reader wid)
        (values base numbits bitmap (incf (disc-node-ack-count node)))))))

(defun* %builtin-on-data (node prefix wid sn)
    (function (disc-node (simple-array (unsigned-byte 8) (12)) (unsigned-byte 32) integer) t)
  "Under the node lock: record a received builtin SEDP DATA SN from remote PREFIX's
   writer WID so the next ACKNACK advances past it (stops the reliable retransmit)."
  (dds.pal:with-lock ((disc-node-lock node))
    (dds.rtps.reliable:reader-on-data (%builtin-reader-nl node prefix) wid sn
                                       #.(make-array 0 :element-type '(unsigned-byte 8)))))

(defun* %remote-metatraffic (node prefix)
    (function (disc-node (simple-array (unsigned-byte 8) (12))) (or null cons))
  "The (host . port) of participant PREFIX's metatraffic unicast locator, or NIL."
  (let ((spdp (dds.pal:with-lock ((disc-node-lock node))
                (gethash prefix (disc-node-discovered node)))))
    (when spdp
      (let ((loc (dds.rtps.discovery:usable-udpv4-locator
                  (dds.rtps.discovery:spdp-data-metatraffic-unicast-locators spdp))))
        (when loc
          (let ((port (%locator-port (dds.rtps.discovery:locator-port loc))))
            (when (plusp port)
              (cons (dds.rtps.discovery:locator-ipv4-string loc) port))))))))

(defun* %send-acknack (node buf reader-id writer-id base numbits bitmap count final host port)
    (function (disc-node dds.core.buffer:octet-buffer (unsigned-byte 32) (unsigned-byte 32) integer (unsigned-byte 32) (simple-array (unsigned-byte 32) (*)) (unsigned-byte 32) t string (unsigned-byte 16)) t)
  "Build an RTPS message (Header + ACKNACK) into BUF and send it to HOST:PORT. BUF is the
   caller-thread scratch buffer (tx-msg on the announce thread, rx-tx-msg on the receiver)."
  (let ((mc (dds.core.buffer:cursor buf :endianness :little)))
    (dds.rtps.message:write-header mc (disc-node-guid-prefix node))
    (dds.rtps.message:write-acknack mc reader-id writer-id base numbits bitmap count :final final)
    (dds.xport:send (disc-node-transport node)
                    (dds.xport.udp:make-udp-locator :host host :port port)
                    buf 0 (dds.core.buffer:cursor-position mc))))

(defun* %on-builtin-heartbeat (node prefix rid wid first last)
    (function (disc-node (simple-array (unsigned-byte 8) (12)) (unsigned-byte 32) (unsigned-byte 32) integer integer) t)
  "Receiver-thread: a HEARTBEAT from remote PREFIX's builtin writer WID (SEDP or
   TypeLookup). Apply its range, then ACKNACK from our matching builtin reader RID to
   that participant's metatraffic locator to pull what is missing. Uses the
   receiver-thread rx-tx-msg buffer."
  (let ((hp (%remote-metatraffic node prefix)))
    (when hp
      (multiple-value-bind (base numbits bitmap count)
          (%builtin-acknack-values node prefix wid first last)
        (%send-acknack node (disc-node-rx-tx-msg node) rid wid base numbits bitmap count
                       t (car hp) (cdr hp))))))

(defun* announce-endpoints (node)
    (function (disc-node) (eql t))
  "Send NODE's local publications (SEDP publications writer) and subscriptions
   (SEDP subscriptions writer) to every discovered participant's metatraffic
   unicast locator (RTPS 2.5 §8.5.4). Also drives tl-sweep (expiring overdue
   TypeLookup queries), %lease-sweep (pruning lease-expired participants, RTPS 2.5
   §8.5.3.3.2), %liveliness-sweep (reader-side Writer Liveliness timing -> the
   ON-LIVELINESS-CHANGED hook, RTPS 2.5 §8.4.13), and %push-heartbeat (the periodic
   standalone user-data HEARTBEAT that keeps reliability live and repairs a lost final
   sample, RTPS 2.5 §8.4.2.2) on the periodic announce cadence."
  ;; WP-ZEROCOPY (FR-PF-3): stamp each local endpoint's advertised ZC-capable flag from this node's
  ;; current capability so SEDP carries PID_ZEROCOPY_CAPABLE iff the node can resolve a reference. NIL
  ;; (ZC off / no pool) leaves the flag NIL -> the PID is elided -> byte-identical SEDP to today.
  (let ((zc (%zc-node-capable-p node)))
    (dolist (w (disc-node-local-writers node)) (setf (dds.rtps.discovery:endpoint-data-zerocopy-capable w) zc))
    (dolist (r (disc-node-local-readers node)) (setf (dds.rtps.discovery:endpoint-data-zerocopy-capable r) zc)))
  (dolist (p (%discovered-participants node))
    (let ((loc (dds.rtps.discovery:usable-udpv4-locator
                (dds.rtps.discovery:spdp-data-metatraffic-unicast-locators p))))
      (when loc
        (let ((host (dds.rtps.discovery:locator-ipv4-string loc))
              (port (%locator-port (dds.rtps.discovery:locator-port loc))))
          ;; STABLE per-writer SNs: reverse -> add-order (oldest first); each endpoint's
          ;; 1-based add-order index is its fixed SN, unchanged as later endpoints are
          ;; pushed on. The publications (0x3c2) and subscriptions (0x4c2) writers each
          ;; have their own 1-based SN space.
          (loop for w in (reverse (disc-node-local-writers node)) for wsn from 1 do
            (%send-endpoint node
                            dds.rtps.discovery:+entityid-sedp-pub-reader+
                            dds.rtps.discovery:+entityid-sedp-pub-writer+
                            w wsn host port))
          (loop for r in (reverse (disc-node-local-readers node)) for rsn from 1 do
            (%send-endpoint node
                            dds.rtps.discovery:+entityid-sedp-sub-reader+
                            dds.rtps.discovery:+entityid-sedp-sub-writer+
                            r rsn host port))
          ;; Pre-emptive ACKNACK to the peer's reliable builtin SEDP writers so it
          ;; pushes its publication/subscription endpoint data (RTPS 2.5 §8.4.10.4).
          ;; non-final -> solicit a HEARTBEAT; the per-remote reader advances the ACK
          ;; as the SEDP arrives, so this stops soliciting once endpoints are in.
          (let ((prefix (dds.rtps.discovery:spdp-data-guid-prefix p)))
            (dolist (wid (list dds.rtps.discovery:+entityid-sedp-pub-writer+
                               dds.rtps.discovery:+entityid-sedp-sub-writer+))
              (multiple-value-bind (base numbits bitmap count)
                  (%builtin-acknack-values node prefix wid)
                (%send-acknack node (disc-node-tx-msg node)
                               (%sedp-reader-id-for wid) wid base numbits bitmap count
                               nil host port))))))))
  (tl-sweep node)
  (%lease-sweep node)
  (%liveliness-sweep node)
  (flush-batch node)        ; WP-BATCH time trigger: flush a partial batch on the announce cadence
  (%push-heartbeat node)
  t)

(defun* %lease-now ()
    (function () (integer 0))
  "Monotonic internal-real-time stamp for lease/liveliness bookkeeping."
  (get-internal-real-time))

(defun* %lease-stale-p (last-seen lease-seconds now)
    (function (integer integer (integer 0)) t)
  "T iff LAST-SEEN is older than LEASE-SECONDS before NOW — the SPDP HistoryCache
   stale-entry test (RTPS 2.5 §8.5.3.3.2: not refreshed within its leaseDuration)."
  (> (- now last-seen) (* lease-seconds internal-time-units-per-second)))

(defun* %invalidate-shmem-dest (node prefix)
    (function (disc-node (simple-array (unsigned-byte 8) (12))) t)
  "Drop the cached SHMEM destination for the remote 12-octet PREFIX (FR-XPORT-2). CALLER HOLDS the
   node lock. Called whenever PREFIX's SPDP is re-recorded (its advertised locators / host-uuid may
   have changed) or it leases out, so the next send re-resolves rather than reusing a stale locator."
  (remhash prefix (disc-node-shmem-dest-cache node))
  t)

(defun* %record-participant (node spdp)
    (function (disc-node dds.rtps.discovery:spdp-data) t)
  "Record a discovered participant (its SPDP data) keyed by GUID prefix and stamp its
   last-seen for lease tracking (RTPS 2.5 §8.5.3.3.2), ignoring this node's own
   announcements (loopback echo / self in peers). Invalidates the participant's cached SHMEM
   destination (FR-XPORT-2): a fresh SPDP may change its advertised SHMEM locator / host-uuid, so the
   memoized dest is dropped and re-resolved on the next send."
  (let ((prefix (dds.rtps.discovery:spdp-data-guid-prefix spdp)))
    (unless (equalp prefix (disc-node-guid-prefix node))
      (dds.pal:with-lock ((disc-node-lock node))
        (let ((key (copy-seq prefix)))
          (setf (gethash key (disc-node-discovered node)) spdp)
          (setf (gethash key (disc-node-participant-last-seen node)) (%lease-now))
          (%invalidate-shmem-dest node prefix))))))

(defun* %seed-discovered-stale (node prefix lease-seconds seconds-ago)
    (function (disc-node (simple-array (unsigned-byte 8) (12)) integer (integer 0)) t)
  "Test seam: record a discovered participant for PREFIX whose SPDP announces
   LEASE-SECONDS and whose last-seen is SECONDS-AGO in the past (the stamp may be
   negative this early after boot — only NOW - last-seen matters), so %lease-sweep sees
   it as stale (RTPS 2.5 §8.5.3.3.2)."
  (dds.pal:with-lock ((disc-node-lock node))
    (let ((key (copy-seq prefix)))
      (setf (gethash key (disc-node-discovered node))
            (dds.rtps.discovery:make-spdp-data :guid-prefix prefix
                                               :lease-duration-seconds lease-seconds))
      (setf (gethash key (disc-node-participant-last-seen node))
            (- (%lease-now) (* seconds-ago internal-time-units-per-second)))))
  t)

(defun* %fire-unmatch (node direction remote)
    (function (disc-node keyword dds.rtps.discovery:endpoint-data) t)
  "Invoke the ON-UNMATCH hook (if installed) OUTSIDE the node lock for a REMOTE endpoint
   unmatched by participant-lease expiry (DIRECTION :remote-writer / :remote-reader)."
  (when (disc-node-on-unmatch node)
    (funcall (disc-node-on-unmatch node) direction remote)))

(defun* %purge-prefix (node prefix accessor)
    (function (disc-node (simple-array (unsigned-byte 8) (12)) function) t)
  "Remove every entry in (ACCESSOR NODE)'s table whose remote 16-octet GUID's first 12
   octets equal PREFIX. CALLER HOLDS the node lock."
  (let ((table (funcall accessor node)) (dead '()))
    (maphash (lambda (guid ep)
               (declare (ignore ep))
               (when (%guid-prefix-match-p guid prefix) (push guid dead)))
             table)
    (dolist (guid dead) (remhash guid table)))
  t)

(defun* %guid-prefix-match-p (guid prefix)
    (function ((simple-array (unsigned-byte 8) (16)) (simple-array (unsigned-byte 8) (12))) t)
  "T iff the 16-octet endpoint GUID's first 12 octets (its participant prefix, RTPS 2.5
   §9.3.1.2) equal the 12-octet PREFIX."
  (dotimes (i 12 t)
    (unless (= (aref guid i) (aref prefix i)) (return nil))))

(defun* %collect-and-remove-matches (node prefix removed-place)
    (function (disc-node (simple-array (unsigned-byte 8) (12)) function) t)
  "Remove every match whose remote GUID prefix equals PREFIX, classify its direction
   from the GUID entity kind (a removed remote WRITER -> :remote-writer, READER ->
   :remote-reader; RTPS 2.5 §9.3.1.2 Table 9.1 via %writer-guid-p/%reader-guid-p), and
   push (direction . remote) via REMOVED-PLACE. CALLER HOLDS the node lock."
  (let ((table (disc-node-matches node)) (dead '()))
    (maphash (lambda (guid remote)
               (when (%guid-prefix-match-p guid prefix)
                 (push (cons guid remote) dead)))
             table)
    (dolist (entry dead)
      (let* ((remote (cdr entry))
             (guid (dds.rtps.discovery:endpoint-data-guid remote))
             (direction (cond ((%writer-guid-p guid) :remote-writer)
                              ((%reader-guid-p guid) :remote-reader)
                              (t :remote-writer))))
        (remhash (car entry) table)
        (funcall removed-place (cons direction remote)))))
  t)

(defun* %lease-sweep (node)
    (function (disc-node) (eql t))
  "Prune every discovered participant whose SPDP last-seen is older than its announced
   leaseDuration (RTPS 2.5 §8.5.3.3.2 — the SPDPbuiltinParticipantReader removes stale
   entries): under the node lock remove its discovered entry, last-seen, builtin-reader,
   every discovered-writers/readers endpoint + match keyed by that 12-octet prefix,
   collecting the removed MATCHED endpoints; then fire on-unmatch per removed match
   OUTSIDE the lock. Idempotent (a re-announced participant re-adds)."
  (let ((removed '()))
    (dds.pal:with-lock ((disc-node-lock node))
      (let ((now (%lease-now)) (dead '()))
        (maphash (lambda (prefix spdp)
                   (let ((ls (gethash prefix (disc-node-participant-last-seen node))))
                     (when (and ls (%lease-stale-p
                                    ls (dds.rtps.discovery:spdp-data-lease-duration-seconds spdp) now))
                       (push prefix dead))))
                 (disc-node-discovered node))
        (dolist (prefix dead)
          (remhash prefix (disc-node-discovered node))
          (remhash prefix (disc-node-participant-last-seen node))
          (remhash prefix (disc-node-builtin-readers node))
          (%invalidate-shmem-dest node prefix)   ; a leased-out peer's cached SHMEM dest must not be reused
          (%purge-prefix node prefix #'disc-node-discovered-writers)
          (%purge-prefix node prefix #'disc-node-discovered-readers)
          (%collect-and-remove-matches node prefix
                                       (lambda (dm) (push dm removed))))))
    (dolist (dm removed) (%fire-unmatch node (car dm) (cdr dm)))
    t))

(defun* %record-match (node remote)
    (function (disc-node dds.rtps.discovery:endpoint-data) boolean)
  "Record a matched REMOTE endpoint keyed by its 16-octet GUID (lock-guarded). Returns
   T only the FIRST time REMOTE is recorded (so a MATCHED status fires once, not once
   per re-announce); NIL if REMOTE was already matched."
  (dds.pal:with-lock ((disc-node-lock node))
    (let ((key (copy-seq (dds.rtps.discovery:endpoint-data-guid remote))))
      (if (nth-value 1 (gethash key (disc-node-matches node)))
          nil
          (progn (setf (gethash key (disc-node-matches node)) remote) t)))))

(defun* %record-incompat (node remote)
    (function (disc-node dds.rtps.discovery:endpoint-data) boolean)
  "Record REMOTE as RxO-incompatible (topic+type matched, QoS failed), keyed by its
   GUID (lock-guarded). Returns T only the first time, so INCOMPATIBLE_QOS fires once
   per remote endpoint, not once per re-announce."
  (dds.pal:with-lock ((disc-node-lock node))
    (let ((key (copy-seq (dds.rtps.discovery:endpoint-data-guid remote))))
      (if (nth-value 1 (gethash key (disc-node-incompat node)))
          nil
          (progn (setf (gethash key (disc-node-incompat node)) remote) t)))))

(defun* %record-inconsistent (node remote)
    (function (disc-node dds.rtps.discovery:endpoint-data) boolean)
  "Record REMOTE as an inconsistent-topic source (same topic name as a local endpoint,
   different type name), keyed by its GUID. Returns T only the first time, so
   INCONSISTENT_TOPIC fires once per remote endpoint."
  (dds.pal:with-lock ((disc-node-lock node))
    (let ((key (copy-seq (dds.rtps.discovery:endpoint-data-guid remote))))
      (if (nth-value 1 (gethash key (disc-node-inconsistent node)))
          nil
          (progn (setf (gethash key (disc-node-inconsistent node)) remote) t)))))

(defun* %fire-match (node kind remote)
    (function (disc-node keyword dds.rtps.discovery:endpoint-data) t)
  "Invoke the ON-MATCH hook (if installed) once for a newly-matched REMOTE endpoint."
  (when (disc-node-on-match node)
    (funcall (disc-node-on-match node) kind remote)))

(defun* %fire-inconsistent (node topic-name)
    (function (disc-node string) t)
  "Invoke the ON-INCONSISTENT-TOPIC hook (if installed) for a newly-detected topic-name
   collision (same name, different type) — drives INCONSISTENT_TOPIC (FR-DCPS-3)."
  (when (disc-node-on-inconsistent-topic node)
    (funcall (disc-node-on-inconsistent-topic node) topic-name)))

(defun* %fire-incompat (node kind remote bad)
    (function (disc-node keyword dds.rtps.discovery:endpoint-data list) t)
  "Invoke the ON-INCOMPATIBLE-QOS hook (if installed) for a newly-detected RxO
   incompatibility, passing the failing-policy keyword list BAD (FR-QOS-2 / FR-DCPS-3)."
  (when (disc-node-on-incompatible-qos node)
    (funcall (disc-node-on-incompatible-qos node) kind remote bad)))

(defun* %record-discovered (table remote)
    (function (hash-table dds.rtps.discovery:endpoint-data) t)
  "Record a discovered remote endpoint REMOTE in TABLE keyed by its 16-octet GUID
   (lock-free; TABLE is guarded by the caller). Latest data wins; used by the builtin-
   topic readers (FR-DCPS-6) to surface ALL discovered endpoints, matched or not."
  (setf (gethash (copy-seq (dds.rtps.discovery:endpoint-data-guid remote)) table) remote))

(defun* disc-node-discovered-writers-list (node)
    (function (disc-node) list)
  "Snapshot of every discovered remote publication (endpoint-data), lock-guarded."
  (dds.pal:with-lock ((disc-node-lock node))
    (loop for v being the hash-values of (disc-node-discovered-writers node) collect v)))

(defun* disc-node-discovered-readers-list (node)
    (function (disc-node) list)
  "Snapshot of every discovered remote subscription (endpoint-data), lock-guarded."
  (dds.pal:with-lock ((disc-node-lock node))
    (loop for v being the hash-values of (disc-node-discovered-readers node) collect v)))

(defun* %consult-type-gate (node remote local)
    (function (disc-node dds.rtps.discovery:endpoint-data dds.rtps.discovery:endpoint-data) t)
  "Ask the TYPE-GATE hook for a type-compatibility verdict on the (REMOTE, LOCAL)
   endpoint pair. Called OUTSIDE the node lock on the receiver thread (the gate is
   user code, like the ON-* hooks — see %fire-match). A NIL gate — and any verdict
   other than :incompatible / :pending — proceeds as :compatible."
  (let ((gate (disc-node-type-gate node)))
    (if gate (funcall gate node remote local) :compatible)))

(defun* %park-match (node direction remote)
    (function (disc-node (member :remote-writer :remote-reader) dds.rtps.discovery:endpoint-data) (eql t))
  "Park a TYPE-GATE :pending match decision as (DIRECTION . REMOTE) (lock-guarded),
   deduped by the remote 16-octet GUID; resume-parked-matches re-runs it. A parked
   REMOTE snapshot may go stale, but a fresh SEDP re-announcement re-runs the match
   through the normal path anyway (pre-emption), so resume callers need no refresh."
  (dds.pal:with-lock ((disc-node-lock node))
    (let ((guid (dds.rtps.discovery:endpoint-data-guid remote)))
      (unless (member guid (disc-node-parked-matches node)
                      :key (lambda (e) (dds.rtps.discovery:endpoint-data-guid (cdr e)))
                      :test #'equalp)
        (push (cons direction remote) (disc-node-parked-matches node)))))
  t)

(defun* %match-remote-endpoint (node remote direction)
    (function (disc-node dds.rtps.discovery:endpoint-data (member :remote-writer :remote-reader)) (eql t))
  "Test discovered REMOTE against each local endpoint of the opposite kind (DIRECTION
   :remote-writer -> local readers; :remote-reader -> local writers). A local whose
   keyed-ness (WITH_KEY vs NO_KEY, RTPS 2.5 §9.3.1.2) disagrees with REMOTE is a silent
   non-match — a fundamental endpoint-kind incompatibility below type consistency, so it
   never fires INCONSISTENT_TOPIC. On the first RxO-compatible, same-kind local, consult
   the TYPE-GATE: :compatible (or no gate) records +
   announces the match; :incompatible joins the INCONSISTENT_TOPIC path; :pending
   parks the decision for resume-parked-matches. Else, against a local on the SAME
   topic name: a different type name is an INCONSISTENT_TOPIC; a matching type whose
   QoS failed RxO is OFFERED/REQUESTED_INCOMPATIBLE_QOS (failing policies)."
  (let ((incompat nil) (inconsistent nil) (writer-p (eq direction :remote-writer)))
    (dolist (local (if writer-p (disc-node-local-readers node) (disc-node-local-writers node)))
      (multiple-value-bind (ok bad)
          (if writer-p
              ;; endpoint-match-p wants writer-data first: REMOTE is the writer here
              (dds.rtps.discovery:endpoint-match-p remote local)
              ;; LOCAL is the writer here (REMOTE is a reader); writer-data still first
              (dds.rtps.discovery:endpoint-match-p local remote))
        (cond
          ;; topic+type+qos agree but keyed-ness disagrees: a fundamental endpoint-kind
          ;; incompatibility below type consistency -> silent non-match (RTPS 2.5 §9.3.1.2)
          ((and ok (not (eq (%endpoint-keyed-p (dds.rtps.discovery:endpoint-data-guid local))
                            (%endpoint-keyed-p (dds.rtps.discovery:endpoint-data-guid remote))))))
          (ok (case (%consult-type-gate node remote local)
                (:incompatible
                 (setf inconsistent (dds.rtps.discovery:endpoint-data-topic-name local)))
                (:pending
                 (%park-match node direction remote)
                 ;; deliberately short-circuits the incompat/inconsistent bookkeeping below
                 (return-from %match-remote-endpoint t))
                (t (when (%record-match node remote) (%fire-match node direction remote))
                   (return-from %match-remote-endpoint t))))
          ((string= (dds.rtps.discovery:endpoint-data-topic-name remote)
                    (dds.rtps.discovery:endpoint-data-topic-name local))
           (if (string= (dds.rtps.discovery:endpoint-data-type-name remote)
                        (dds.rtps.discovery:endpoint-data-type-name local))
               (setf incompat bad)
               (setf inconsistent (dds.rtps.discovery:endpoint-data-topic-name local)))))))
    (cond
      ((and incompat (%record-incompat node remote))
       (%fire-incompat node direction remote incompat))
      ((and inconsistent (%record-inconsistent node remote))
       (%fire-inconsistent node inconsistent))))
  t)

(defun* %match-remote-writer (node remote)
    (function (disc-node dds.rtps.discovery:endpoint-data) (eql t))
  "REMOTE is a discovered publication: match it against the local readers (:remote-writer)."
  (%match-remote-endpoint node remote :remote-writer))

(defun* %match-remote-reader (node remote)
    (function (disc-node dds.rtps.discovery:endpoint-data) (eql t))
  "REMOTE is a discovered subscription: match it against the local writers (:remote-reader)."
  (%match-remote-endpoint node remote :remote-reader))

(defun* resume-parked-matches (node)
    (function (disc-node) (eql t))
  "Re-run every parked (TYPE-GATE :pending) match decision: take + clear the parked
   list under the node lock, then outside the lock re-run the SEDP match for each
   entry — the gate is consulted again; a still-:pending verdict re-parks the entry
   (still deduped by remote GUID). Call once the gate installer has a verdict (e.g.
   a TypeLookup reply arrived)."
  (let ((parked (dds.pal:with-lock ((disc-node-lock node))
                  (shiftf (disc-node-parked-matches node) '()))))
    (dolist (entry parked)
      (%match-remote-endpoint node (cdr entry) (car entry))))
  t)

(defun* disc-node-parked-count (node)
    (function (disc-node) (integer 0))
  "Number of parked (TYPE-GATE :pending) match decisions awaiting resume-parked-matches
   (lock-guarded; diagnostic)."
  (dds.pal:with-lock ((disc-node-lock node))
    (length (disc-node-parked-matches node))))

(defun* %handle-datagram (node buf size)
    (function (disc-node dds.core.buffer:octet-buffer (integer 0)) t)
  "Dispatch an inbound datagram (bounded by SIZE). DATA is routed by writerId: SPDP
   -> record participant; SEDP publications/subscriptions -> match; any other DATA
   plus HEARTBEAT/ACKNACK -> the installed data-plane hooks (nil = ignore). The
   discovery SerializedPayloads are ParameterLists (encap header + list); a user
   DATA payload is opaque bytes handed to the on-data hook as a [poff,plen) region."
  (let ((cursor (dds.core.buffer:cursor buf :endianness :little))
        (src-prefix (%source-prefix buf)))
    (dds.rtps.message:dispatch-message
     cursor
     (lambda (id flags c body-len)
       (cond
         ((= id dds.rtps.message:+submsg-data+)
          (multiple-value-bind (rdr wtr sn has-payload poff plen keyp kind key-hash status-flags
                                orig-guid orig-sn)
              (dds.rtps.message:parse-data-body c flags body-len (disc-node-capture-data-key-hash node))
            (declare (ignore rdr keyp))
            (when (and (not has-payload) (not (eq kind :data)) (disc-node-on-lifecycle node))
              ;; A no-payload dispose/unregister DATA (RTPS 2.5 §9.6.4.9): route the named instance +
              ;; StatusInfo + datagram SRC-PREFIX (§9.4.4) to the lifecycle hook (S2 owner-clear needs
              ;; the FULL source GUID, DDS 1.4 §2.2.3.9.2 — mirrors the on-data hook below).
              (funcall (disc-node-on-lifecycle node) wtr sn kind key-hash status-flags src-prefix))
            (when has-payload
              (cond
                ((= wtr dds.rtps.discovery:+entityid-spdp-writer+)
                 (let ((pc (dds.core.buffer:cursor buf :endianness :little)))
                   (dds.core.buffer:cursor-set-position pc poff)
                   (dds.cdr:parse-encapsulation-header pc)
                   (let ((spdp (dds.rtps.discovery:parse-spdp-data pc)))
                     (when spdp (%record-participant node spdp)))))
                ((= wtr dds.rtps.discovery:+entityid-sedp-pub-writer+)
                 (let ((pc (dds.core.buffer:cursor buf :endianness :little)))
                   (dds.core.buffer:cursor-set-position pc poff)
                   (dds.cdr:parse-encapsulation-header pc)
                   (let ((ep (dds.rtps.discovery:parse-endpoint-data pc :writer)))
                     (when ep
                       (dds.pal:with-lock ((disc-node-lock node))
                         (%record-discovered (disc-node-discovered-writers node) ep))
                       (%match-remote-writer node ep))
                     (%builtin-on-data node src-prefix wtr sn))))
                ((= wtr dds.rtps.discovery:+entityid-sedp-sub-writer+)
                 (let ((pc (dds.core.buffer:cursor buf :endianness :little)))
                   (dds.core.buffer:cursor-set-position pc poff)
                   (dds.cdr:parse-encapsulation-header pc)
                   (let ((ep (dds.rtps.discovery:parse-endpoint-data pc :reader)))
                     (when ep
                       (dds.pal:with-lock ((disc-node-lock node))
                         (%record-discovered (disc-node-discovered-readers node) ep))
                       (%match-remote-reader node ep))
                     (%builtin-on-data node src-prefix wtr sn))))
                ((%tl-writer-p wtr)
                 (%on-tl-data node src-prefix wtr sn buf poff plen))
                ((= wtr dds.rtps.discovery:+entityid-p2p-participant-message-writer+)
                 (%on-participant-message node src-prefix wtr sn buf poff plen))
                ((disc-node-on-data node)
                 ;; Pass orig-guid/orig-sn (PID_ORIGINAL_WRITER_INFO, §8.3.5.4) and key-hash
                 ;; (PID_KEY_HASH, §9.6.4.8 — only non-NIL when capture-data-key-hash is set on
                 ;; the node) into the data-plane hook. %on-user-data gates APP delivery; it MUST
                 ;; call reader-on-data unconditionally for RTPS reliable NACK/HEARTBEAT correctness.
                 (funcall (disc-node-on-data node) wtr sn buf poff plen src-prefix
                          orig-guid orig-sn key-hash))))))
         ((= id dds.rtps.message:+submsg-heartbeat+)
          (let ((pos (dds.core.buffer:cursor-position c)))
            (multiple-value-bind (rid wid first last hcount hfinal hlive)
                (dds.rtps.message:parse-heartbeat-body c flags)
              (declare (ignore rid hcount hfinal hlive))
              (let ((bid (or (%sedp-reader-id-for wid) (%tl-reader-id-for wid))))
                (cond
                  (bid (%on-builtin-heartbeat node src-prefix bid wid first last))
                  ((disc-node-on-heartbeat node)
                   (dds.core.buffer:cursor-set-position c pos)
                   (funcall (disc-node-on-heartbeat node) c flags src-prefix)))))))
         ((= id dds.rtps.message:+submsg-acknack+)
          (let ((pos (dds.core.buffer:cursor-position c)))
            (unless (%on-tl-acknack node src-prefix c flags)
              (when (disc-node-on-acknack node)
                (dds.core.buffer:cursor-set-position c pos)
                (funcall (disc-node-on-acknack node) c flags src-prefix)))))
         ((and (= id dds.rtps.message:+submsg-gap+) (disc-node-on-gap node))
          ;; RTPS 2.5 §8.3.7.4: a GAP marks evicted/irrelevant SNs so the reliable reader stops NACKing them.
          (funcall (disc-node-on-gap node) c flags src-prefix))
         ((and (= id dds.rtps.message:+submsg-data-frag+) (disc-node-on-data-frag node))
          (funcall (disc-node-on-data-frag node) c flags body-len buf src-prefix))
         ((and (= id dds.rtps.message:+submsg-heartbeat-frag+) (disc-node-on-heartbeat-frag node))
          (funcall (disc-node-on-heartbeat-frag node) c flags src-prefix))
         ((and (= id dds.rtps.message:+submsg-nack-frag+) (disc-node-on-nack-frag node))
          (funcall (disc-node-on-nack-frag node) c flags))))
     size)
    t))

(defun* start-node (node)
    (function (disc-node) disc-node)
  "Spawn the background receiver thread(s) that process inbound datagrams for NODE:
   the unicast metatraffic socket always, plus the multicast socket if enabled, plus the SHMEM receive
   segment when SHMEM is on (FR-XPORT-2). All feed the SAME %handle-datagram, so the engine is identical
   regardless of which transport carried a datagram. Returns NODE."
  (setf (disc-node-rx-thread node)
        (dds.xport.udp:start-udp-receiver
         (disc-node-socket node)
         (lambda (buf size) (%handle-datagram node buf size))))
  (when (disc-node-mcast-socket node)
    (setf (disc-node-mcast-rx-thread node)
          (dds.xport.udp:start-udp-receiver
           (disc-node-mcast-socket node)
           (lambda (buf size) (%handle-datagram node buf size)))))
  (when (disc-node-shmem node)
    (dds.xport.shmem:start-shmem-receiver
     (disc-node-shmem node)
     (lambda (buf size) (%handle-datagram node buf size))))
  node)

(defun* stop-node (node)
    (function (disc-node) (eql t))
  "Close NODE's socket(s), join its receiver thread(s) — UDP, multicast, AND the SHMEM receiver when on
   (FR-XPORT-2) — then free the reusable announce scratch buffers. The joins MUST precede the frees: an
   in-flight %HANDLE-DATAGRAM on ANY receiver thread (a SHMEM record feeds the same entry point) writes
   into RX-TX-MSG/TX-MSG, so freeing first is a use-after-free (observed via canary instrumentation). The
   WP-ASYNC sender (which may itself SHMEM-send) is stopped+joined first. Idempotent."
  (when (disc-node-flow-controller node)   ; WP-ASYNC-FLOW: unregister from any flow-controller BEFORE the frees below — unregister is a PER-NODE EMIT BARRIER (it removes NODE from the writers list, then BLOCKS until the SHARED scheduler is not mid-emit on NODE), so the subsequent udp-close/shmem-close/free-static never race a live scheduler send on NODE (no use-after-free). A bare unregister-without-join would NOT be safe; the barrier is what makes it safe (ADR 0016 §Teardown)
    (flow-controller-unregister (disc-node-flow-controller node) node))
  (cond
    ((disc-node-async-thread node)       ; WP-ASYNC: stop + drain + JOIN the sender BEFORE closing the socket
     (dds.pal:with-lock ((disc-node-async-lock node))
       (setf (disc-node-async-stop node) t (disc-node-async-pending node) t)
       (dds.pal:condvar-signal (disc-node-async-cv node)))
     (dds.pal:join (disc-node-async-thread node))
     (setf (disc-node-async-thread node) nil)
     (when (disc-node-async-tx-msg node)
       (dds.pal:free-static (dds.core.buffer:octet-buffer-vec (disc-node-async-tx-msg node)))
       (setf (disc-node-async-tx-msg node) nil)))
    ((disc-node-user-writer node) (flush-batch node)))   ; WP-BATCH: drain a pending batch before closing the socket
  (dds.pal:udp-close (disc-node-socket node))
  (when (disc-node-mcast-socket node)
    (dds.pal:udp-close (disc-node-mcast-socket node))
    (setf (disc-node-mcast-socket node) nil))
  (when (disc-node-rx-thread node)
    (dds.pal:join (disc-node-rx-thread node))
    (setf (disc-node-rx-thread node) nil))
  (when (disc-node-mcast-rx-thread node)
    (dds.pal:join (disc-node-mcast-rx-thread node))
    (setf (disc-node-mcast-rx-thread node) nil))
  (when (disc-node-shmem node)         ; FR-XPORT-2: JOIN the SHMEM receiver (it feeds %handle-datagram -> rx-tx-msg) BEFORE the frees
    (dds.xport.shmem:shmem-transport-close (disc-node-shmem node))
    (setf (disc-node-shmem node) nil))
  ;; WP-ZEROCOPY teardown (FR-PF-3, ADR 0014) AFTER the receiver join (UAF rule: %handle-datagram may
  ;; %zc-resolve against an attached pool on a receiver thread): detach every reader-side attached pool,
  ;; then destroy the writer pool's mutex + detach + unlink its segment.
  (when (plusp (hash-table-count (disc-node-zc-attach-cache node)))
    (maphash (lambda (k seg) (declare (ignore k))
               (unless (eq seg :none) (ignore-errors (dds.pal:shm-detach seg))))
             (disc-node-zc-attach-cache node))
    (clrhash (disc-node-zc-attach-cache node)))
  (when (disc-node-zc-pool node)
    (dds.xport.zerocopy::%zc-destroy (disc-node-zc-pool-sap node))
    (dds.pal:shm-detach (disc-node-zc-pool node))
    (dds.pal:shm-destroy (%zc-pool-name (disc-node-guid-prefix node)))
    (setf (disc-node-zc-pool node) nil (disc-node-zc-pool-sap node) nil))
  (when (disc-node-tx-payload node)
    (dds.pal:free-static (dds.core.buffer:octet-buffer-vec (disc-node-tx-payload node)))
    (setf (disc-node-tx-payload node) nil))
  (when (disc-node-tx-msg node)
    (dds.pal:free-static (dds.core.buffer:octet-buffer-vec (disc-node-tx-msg node)))
    (setf (disc-node-tx-msg node) nil))
  (when (disc-node-rx-tx-msg node)
    (dds.pal:free-static (dds.core.buffer:octet-buffer-vec (disc-node-rx-tx-msg node)))
    (setf (disc-node-rx-tx-msg node) nil))
  t)

(defun* disc-node-discovered-count (node)
    (function (disc-node) (integer 0))
  "Number of remote participants NODE has discovered."
  (dds.pal:with-lock ((disc-node-lock node))
    (hash-table-count (disc-node-discovered node))))

(defun* disc-node-discovered-prefixes (node)
    (function (disc-node) list)
  "List of the 12-octet GUID prefixes NODE has discovered."
  (dds.pal:with-lock ((disc-node-lock node))
    (loop for k being the hash-keys of (disc-node-discovered node) collect k)))

(defun* disc-node-matched-count (node)
    (function (disc-node) (integer 0))
  "Number of remote endpoints that matched one of NODE's local endpoints."
  (dds.pal:with-lock ((disc-node-lock node))
    (hash-table-count (disc-node-matches node))))

(defun* disc-node-matched-topics (node)
    (function (disc-node) list)
  "Topic names of the remote endpoints NODE has matched."
  (dds.pal:with-lock ((disc-node-lock node))
    (loop for v being the hash-values of (disc-node-matches node)
          collect (dds.rtps.discovery:endpoint-data-topic-name v))))

(defun* run-spdp-discovery-test ()
    (function () (eql t))
  "Two participants on 127.0.0.1, each carrying the other as a unicast peer. Both
   announce SPDP; assert each discovers the other's GUID prefix within a bounded
   wait. Exercises announce -> datagram -> receiver thread -> dispatch -> parse
   SPDP -> record (FR-DISC-1/4)."
  (let* ((p1 (make-array 12 :element-type '(unsigned-byte 8)
                         :initial-contents '(1 1 1 1 1 1 1 1 1 1 1 1)))
         (p2 (make-array 12 :element-type '(unsigned-byte 8)
                         :initial-contents '(2 2 2 2 2 2 2 2 2 2 2 2)))
         (node1 (make-disc-node :guid-prefix p1 :host "127.0.0.1" :port 0))
         (node2 (make-disc-node :guid-prefix p2 :host "127.0.0.1" :port 0)))
    (unwind-protect
         (progn
           (setf (disc-node-peers node1) (list (cons "127.0.0.1" (disc-node-port node2))))
           (setf (disc-node-peers node2) (list (cons "127.0.0.1" (disc-node-port node1))))
           (start-node node1)
           (start-node node2)
           (announce-participant node1)
           (announce-participant node2)
           (loop repeat 100
                 until (and (plusp (disc-node-discovered-count node1))
                            (plusp (disc-node-discovered-count node2)))
                 do (sleep 0.02))
           (assert (plusp (disc-node-discovered-count node1)) ()
                   "node1 did not discover node2 over SPDP/UDP")
           (assert (plusp (disc-node-discovered-count node2)) ()
                   "node2 did not discover node1 over SPDP/UDP")
           (assert (member p2 (disc-node-discovered-prefixes node1) :test #'equalp) ()
                   "node1 recorded the wrong GUID prefix")
           (assert (member p1 (disc-node-discovered-prefixes node2) :test #'equalp) ()
                   "node2 recorded the wrong GUID prefix")
           t)
      (stop-node node1)
      (stop-node node2))))

(defun* run-sedp-discovery-test ()
    (function () (eql t))
  "Full discovery handshake over UDP: two participants on 127.0.0.1 first discover
   each other via SPDP, then exchange endpoints via SEDP. node1 offers a RELIABLE
   writer on (Square, ShapeType); node2 requests a BEST_EFFORT reader on the same
   topic/type. Assert each records the other as a match (RxO compatible: offered
   RELIABLE >= requested BEST_EFFORT) within a bounded wait (FR-DISC-1/4, FR-QOS-2)."
  (let* ((p1 (make-array 12 :element-type '(unsigned-byte 8)
                         :initial-contents '(1 1 1 1 1 1 1 1 1 1 1 1)))
         (p2 (make-array 12 :element-type '(unsigned-byte 8)
                         :initial-contents '(2 2 2 2 2 2 2 2 2 2 2 2)))
         (node1 (make-disc-node :guid-prefix p1 :host "127.0.0.1" :port 0))
         (node2 (make-disc-node :guid-prefix p2 :host "127.0.0.1" :port 0)))
    (unwind-protect
         (progn
           (add-local-writer node1 :topic "Square" :type "ShapeType"
                                   :reliability dds.rtps.discovery:+reliability-reliable+)
           (add-local-reader node2 :topic "Square" :type "ShapeType"
                                   :reliability dds.rtps.discovery:+reliability-best-effort+)
           (setf (disc-node-peers node1) (list (cons "127.0.0.1" (disc-node-port node2))))
           (setf (disc-node-peers node2) (list (cons "127.0.0.1" (disc-node-port node1))))
           (start-node node1)
           (start-node node2)
           (announce-participant node1)
           (announce-participant node2)
           (loop repeat 100
                 until (and (plusp (disc-node-discovered-count node1))
                            (plusp (disc-node-discovered-count node2)))
                 do (sleep 0.02))
           (assert (and (plusp (disc-node-discovered-count node1))
                        (plusp (disc-node-discovered-count node2)))
                   () "SPDP did not complete before SEDP")
           (announce-endpoints node1)
           (announce-endpoints node2)
           (loop repeat 100
                 until (and (plusp (disc-node-matched-count node1))
                            (plusp (disc-node-matched-count node2)))
                 do (sleep 0.02))
           (assert (plusp (disc-node-matched-count node2)) ()
                   "node2's reader did not match node1's writer over SEDP/UDP")
           (assert (plusp (disc-node-matched-count node1)) ()
                   "node1's writer did not match node2's reader over SEDP/UDP")
           (assert (member "Square" (disc-node-matched-topics node1) :test #'string=) ()
                   "node1 matched the wrong topic")
           (assert (member "Square" (disc-node-matched-topics node2) :test #'string=) ()
                   "node2 matched the wrong topic")
           t)
      (stop-node node1)
      (stop-node node2))))

(defun* run-mcast-discovery-test ()
    (function () (eql t))
  "Two participants with NO unicast peers discover each other purely via multicast
   SPDP (well-known group 239.255.0.1 : spdp-multicast-port, RTPS 2.5 §9.6.1.1),
   then match endpoints via unicast SEDP routed to the multicast-discovered unicast
   locators. Proves discovery works with zero initial-peer configuration (FR-DISC-3)."
  (let* ((p1 (make-array 12 :element-type '(unsigned-byte 8)
                         :initial-contents '(1 1 1 1 1 1 1 1 1 1 1 1)))
         (p2 (make-array 12 :element-type '(unsigned-byte 8)
                         :initial-contents '(2 2 2 2 2 2 2 2 2 2 2 2)))
         (node1 (make-disc-node :guid-prefix p1 :host "127.0.0.1" :port 0 :multicast t))
         (node2 (make-disc-node :guid-prefix p2 :host "127.0.0.1" :port 0 :multicast t)))
    (unwind-protect
         (progn
           (add-local-writer node1 :topic "Square" :type "ShapeType"
                                   :reliability dds.rtps.discovery:+reliability-reliable+)
           (add-local-reader node2 :topic "Square" :type "ShapeType"
                                   :reliability dds.rtps.discovery:+reliability-best-effort+)
           (start-node node1)
           (start-node node2)
           (announce-participant node1)
           (announce-participant node2)
           (loop repeat 150
                 until (and (member p2 (disc-node-discovered-prefixes node1) :test #'equalp)
                            (member p1 (disc-node-discovered-prefixes node2) :test #'equalp))
                 do (sleep 0.02))
           (assert (member p2 (disc-node-discovered-prefixes node1) :test #'equalp) ()
                   "node1 did not discover node2 via multicast SPDP")
           (assert (member p1 (disc-node-discovered-prefixes node2) :test #'equalp) ()
                   "node2 did not discover node1 via multicast SPDP")
           (announce-endpoints node1)
           (announce-endpoints node2)
           (loop repeat 100
                 until (and (plusp (disc-node-matched-count node1))
                            (plusp (disc-node-matched-count node2)))
                 do (sleep 0.02))
           (assert (plusp (disc-node-matched-count node1)) ()
                   "node1 did not match node2's endpoint after multicast discovery")
           (assert (plusp (disc-node-matched-count node2)) ()
                   "node2 did not match node1's endpoint after multicast discovery")
           t)
      (stop-node node1)
      (stop-node node2))))
