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

;;;; WP-DDS-SECURITY-ZEROALLOC-AEAD T3 (ZA-2): whole-RTPS (rtps_protection / SRTPS) zero-alloc dataplane sizing.

(defparameter *max-datagram-bytes* 65507
  "STEP-1 PROBE: the capacity of the node's tx-msg / rx-tx-msg send buffers. Default 2048 = the pre-change
   hardcoded value, so this step is semantically a NO-OP.")

(defparameter *metatraffic-payload-bytes* 512
  "STEP-3 PROBE: the capacity of the node's tx-payload buffer (discovery ParameterList scratch).")

(defparameter *srtps-scratch-datagram-bytes* nil
  "STEP-4 PROBE: NIL => follow *max-datagram-bytes* (what the SRTPS pools must be able to wrap).")

(defun* srtps-scratch-datagram-bytes ()
    (function () (integer 1))
  "Effective SRTPS scratch datagram size."
  (or *srtps-scratch-datagram-bytes* *max-datagram-bytes*))

(defconstant +srtps-scratch-datagram-bytes+ 2048
  "WP-DDS-SECURITY-ZEROALLOC-AEAD T3: the datagram byte size the SRTPS send-scratch pool buffers and the SECURE-RX-POOL
   RX buffers are sized to — the node's message-buffer size (tx-msg / rx-tx-msg / async-tx-msg, all 2048). A wrapped
   datagram never exceeds this + the SRTPS bracket overhead, and a recovered stream is never longer than the ciphertext;
   NOT a wire constant (a local buffer-size policy, matching the coalescing/IP-MTU headroom of the send buffers).")

(defconstant +srtps-scratch-overhead+ 56
  "WP-DDS-SECURITY-ZEROALLOC-AEAD T3: the SRTPS whole-RTPS bracket overhead (octets) added over the protected
   submessage stream — SRTPS_PREFIX(4) + CryptoHeader(20) + SEC_BODY hdr(4) + CryptoContent len(4) + SRTPS_POSTFIX(4)
   + common_mac(16) + rsm_count(4) = 56 (empty receivers; the 4-align pads ride the 2028-octet input-vs-2048-buffer
   slack), DDS-Security 1.1 §9.5.3.3.4.3/.4. The send-scratch pool element size is +srtps-scratch-datagram-bytes+
   + this.")

(defconstant +submsg-scratch-overhead+ 8192
  "WP-DDS-SECURITY-ZEROALLOC-AEAD T4 (ZA-2): the expansion headroom (octets) the per-node SUBMESSAGE-scratch pool adds
   over +srtps-scratch-datagram-bytes+ (2048) — the metadata_protection (§8.5.1.7-.9) send wrap emits ONE SEC_PREFIX ...
   SEC_POSTFIX bracket PER user submessage (~+56 octets each, DDS-Security 1.1 §9.5.3.3.4.3/.4: PREFIX(4) +
   CryptoHeader(20) + [SEC_BODY hdr(4)+cnt_len(4)+pad(<4)] + POSTFIX(4) + common_mac(16) + pad(<4) + rsm_count(4)), so a
   datagram of N small user submessages expands by ~N*56 during the walk. 8192 = the pre-ZA-2 `(make-octet-buffer (+ len
   8192))` headroom preserved verbatim (byte-identical drop threshold): it covers ~132 brackets of expansion, far above a
   2048-datagram's max ~72 submessages*62 = ~4464, so the walk never overflows the scratch on a realistic datagram — the
   FINAL fit-to-BUF (<= the 2048 send-buffer capacity) check governs the drop exactly as before. A wrapped result larger
   than the send buffer is fail-closed-dropped (NFR-SEC-POSTURE), matching the pre-ZA-2 code. NOT a wire constant (a local
   buffer-size policy). Kept a DEDICATED pool (not enlarging the send-scratch pool) so the SRTPS send path keeps its
   efficient 2104-octet buffers — the 10240-octet submessage buffers are reserved lazily only when metadata_protection engages.")

(defparameter *srtps-send-scratch-capacity* 8
  "WP-DDS-SECURITY-ZEROALLOC-AEAD T3: number of datagram-sized buffers in EACH of a node's SRTPS scratch pools — the
   send-scratch pool (%maybe-wrap-srtps borrows: the publish caller, the receiver thread's ACKNACK, the async sender,
   the flow scheduler) AND, since the T3(ZA-2) review, the RX SECURE-RX-POOL (%handle-datagram borrows one per SRTPS
   unwrap: the unicast / multicast / SHMEM receiver threads — a distinct buffer per concurrent decode, no shared sink).
   A small fixed count + headroom, comfortably covering both the concurrent sender threads and the <=3 receiver threads.
   Each borrow is held only for one bracket build / one decode+copy-back then released; exhaustion -> the borrow is NIL
   -> a fail-closed drop (RESOURCE_LIMITS backpressure, never a GC fallback; NFR-MEM). Raise for deeper concurrency.
   Not a wire constant.")

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

;;;; NOT cleared for ship — pending counsel (R6); see ADR 0044.
(defparameter *zc-pin-budget* 16
  "WP-ACKED-SLOT-PINNING slot-pin budget (FR-PF-4, R6, ADR 0044): the maximum number of Zero-Copy pool slots
   that may be simultaneously PINNED (held live until every matched reliable reader ACKs) per node, so an
   eligible loan-written change can serve retransmit / non-ZC / extra-ZC destinations from the still-committed
   slot instead of a per-write retained-payload heap copy. Default 16 — half of +zerocopy-pool-slots+ (32) — so
   pinning never starves fresh classic loans or RX loans. At budget a new eligible write falls back to the
   retained payload (materialised on demand from its still-armed slot); no starvation, no error. A local
   resource heuristic, NOT a wire constant; tunable. NOT cleared for ship — pending counsel (R6).")

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
  (match-pairs (make-hash-table :test 'equalp) :type hash-table) ; WP-N-ENDPOINT-2C2 (ADR 0048): per-(LOCAL,REMOTE) match set — remote 16-octet GUID (equalp) -> list of matched LOCAL user-endpoint EntityIds. The per-endpoint MATCHED status/crypto/durability fire idempotency key (once per pair, NOT per SEDP re-announce); the lease-sweep fires unmatch per pair. disc-node-matches stays per-remote (presence/count/HB-gate). Node-lock guarded.
  (incompat (make-hash-table :test 'equalp) :type hash-table)
  (incompat-pairs (make-hash-table :test 'equalp) :type hash-table) ; WP-DDS-INCOMPAT-QOS-PERPAIR (ADR 0048 §16.3): per-(LOCAL,REMOTE) INCOMPATIBLE_QOS fire set — remote 16-octet GUID (equalp) -> list of already-fired incompatible LOCAL EntityIds. Mirrors match-pairs EXACTLY: the per-endpoint {OFFERED,REQUESTED}_INCOMPATIBLE_QOS idempotency key (once per (local,remote) pair, NOT per SEDP re-announce), so BOTH same-topic incompatible locals fire + a LATE local (created after the remote was recorded) fires. disc-node-incompat stays per-remote presence. Both purged by prefix on lease-expiry/participant-lost (%lease-sweep) so a re-discovery re-fires + the tables stay bounded. Node-lock guarded.
  (inconsistent (make-hash-table :test 'equalp) :type hash-table)
  (parked-matches '() :type list) ; (direction . remote endpoint-data), TYPE-GATE :pending; stale snapshots are pre-empted by SEDP re-announce

  (discovered-writers (make-hash-table :test 'equalp) :type hash-table) ; all remote publications
  (discovered-readers (make-hash-table :test 'equalp) :type hash-table) ; all remote subscriptions
  (local-writers '() :type list)
  (local-readers '() :type list)
  ;; ADR 0060: local endpoints that are REGISTERED with the engine but NOT YET ENABLED (DDS 1.4 §2.2.2.1.1.7:
  ;; "a disabled entity does not communicate"). Endpoint EntityId -> T. announce-endpoints does not SEDP-announce
  ;; them and %match-remote-endpoint does not match them, so a created-disabled endpoint is invisible on the wire
  ;; until enable(). Empty in the default (autoenable) path -> byte-identical announce/match.
  (unenabled-endpoints (make-hash-table :test 'eql) :type hash-table)
  (lock (dds.pal:make-lock "disc-node") :type t)
  (tx-payload nil :type (or null dds.core.buffer:octet-buffer))
  (tx-msg nil :type (or null dds.core.buffer:octet-buffer))
  (rx-tx-msg nil :type (or null dds.core.buffer:octet-buffer))
  ;; WP-N-ENDPOINT-S0-REGISTRY (ADR 0048): user endpoint ENGINE-INSTANCE registries — each an alist (EntityId u32 .
  ;; engine instance). N=1 today: the compat accessors disc-node-user-writer/-reader return the PRIMARY (first-
  ;; registered) entry, so the ~163 existing read sites are byte-identical. N-local send fan-out = S1, deliver = S2.
  (user-writers '() :type list)
  (user-readers '() :type list)
  (primary-user-writer nil :type (or null dds.rtps.reliable:rtps-writer)) ; first-registered user writer (N=1 identity)
  (primary-user-reader nil :type (or null dds.rtps.reliable:rtps-reader)) ; first-registered user reader (N=1 identity)
  (user-writer-id #x00000102 :type (unsigned-byte 32)) ; this node's user-data writer EntityId (kind reflects keyed-ness)
  (user-reader-id #x00000107 :type (unsigned-byte 32)) ; this node's user-data reader EntityId
  (user-writer-key-next 1 :type (integer 1)) ; WP-N-ENDPOINT-S1 (ADR 0048): next distinct per-participant USER-writer entity KEY; starts 1 so the first writer keeps EntityId #x0102/#x0103 (byte-identical), each subsequent DataWriter gets a distinct key -> distinct EntityId + SEDP GUID (RTPS 2.5 §9.3.1.2). Builtin/secure keys are untouched.
  (user-reader-key-next 1 :type (integer 1)) ; WP-N-ENDPOINT-S2 (ADR 0048): next distinct per-participant USER-reader entity KEY; starts 1 so the first reader keeps EntityId #x0107/#x0104 (byte-identical), each subsequent DataReader gets a distinct key -> distinct EntityId + SEDP GUID (RTPS 2.5 §9.3.1.2). Writer/reader keys are SEPARATE counters (kind 0x02/0x03 vs 0x07/0x04 disjoints them); builtin/secure keys are untouched.
  (reader-routes (make-hash-table :test 'equalp) :type hash-table) ; WP-N-ENDPOINT-S2 (ADR 0048): the DELIVERY ROUTE — remote-writer 16-octet GUID (equalp) -> list of local user-reader EntityIds matched to it. Populated at %match-remote-endpoint (idempotent), purged on unmatch/lease-expiry (by prefix) + re-added on re-announce. The %drain source-GUID filter (each reader deserializes ONLY its matched writers) and the receive-hook demux (drive/ACKNACK the engine reader matched to the source writer, not unconditionally the primary) read it. Node-lock guarded.
  (reader-join-watermarks (make-hash-table :test 'eql) :type hash-table) ; WP-N-ENDPOINT-2C3 (ADR 0048/0017; MEMORY-SAFETY): the mid-stream ZC-joiner high-water. local user-reader EntityId (eql) -> hash(remote-writer 16-octet GUID equalp -> highest stored SN AT THE MOMENT this reader was route-added to that writer). Set ATOMICALLY with %reader-route-add (same node-lock section) ONLY for a JOINER (the writer's route was already non-empty) on a ZC-loan-capable node. %drain consults max(dr-drained, this) so a joiner NEVER drains a marker delivered before it joined (a marker whose demux %zc-bump did not count it -> would be a cross-reader use-after-free). Empty for the first reader / non-loan nodes (byte-identical). Node-lock guarded.
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
  (zc-armed-changes '() :type list)        ; WP-FLATDATA-LOAN-WRITE (R6, ADR 0042): changes born :armed with a pre-committed slot, pending their push pass — the leak-safety sweep registry (guarded by LOCK; drained by %zc-armed-sweep after each push pass / at stop-node)
  (zc-pin-count (dds.pal:make-atomic-cell) :type dds.pal:atomic-cell)   ; WP-ACKED-SLOT-PINNING (R6, ADR 0044): live count of currently-pinned slots (atomic; incremented at a granted pin in publish-sample, decremented in the HistoryCache zc-release-fn at the change-removal choke) — gates *zc-pin-budget*
  (zc-loan-capable nil :type t)            ; WP-FLATDATA-ZC-LOAN (FR-PF-3/4, R6, ADR 0017): DCPS set this iff the local reader is on a :flatdata topic AND ZC armed -> the receiver thread stores the UNRESOLVED ref (no copy/release; the slot stays loaned via the writer's refcount) and DCPS take-loaned/return-loan owns the slot lifetime. NIL (default) = today's resolve-copy-release. NOT cleared for ship — pending counsel (R6)
  ;; WP-DCPS-API-COMPLETION S7: the leaseDuration this node ANNOUNCES in SPDP (PID_PARTICIPANT_LEASE_DURATION,
  ;; RTPS 2.5 §8.5.3.3.2) — how long a peer keeps us alive after our last announcement. Spec default {100, 0}
  ;; (Table 9.18); DCPS overrides it from the participant's DISCOVERY_CONFIG QoS. Read per announce (live-changeable).
  (lease-duration-seconds 100 :type (signed-byte 32))
  (lease-duration-nanosec 0 :type (integer 0))
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
  (flow-controller nil :type t) ; WP-ASYNC-FLOW: the flow-controller this NODE's writers are associated with (NIL = none); set/cleared under the CONTROLLER lock; non-NIL makes publish async-and-paced (the controller thread sends). NODE-scoped (one participant, one controller); the per-WRITER send cursor + EDF/priority scheduling keys live in FLOW-WRITER-STATES (WP-N-ENDPOINT-S1B)
  (flow-writer-states '() :type list) ; WP-N-ENDPOINT-S1B (ADR 0048): alist writer-EntityId (u32, eql) -> flow-writer-state, one per associated local user DataWriter — the SELECTION ENTRY the controller round-robins / EDF / priority-selects, so scheduling spans ALL the participant's writers (the already-node-global %flow-policy-select naturally orders across them). Holds each writer's own send cursor (step-state/refs), pending signal, and scheduling keys (head-ns/budget/priority/last-served). Created at flow-controller-associate / register-under-controller. CONTROLLER-lock-guarded
  (samples (make-hash-table :test 'equalp) :type hash-table) ; 2-level: 16-octet src GUID (equalp) -> SN (eql) -> payload (§8.3.5.4: SN is per-writer; no per-sample composite-key alloc)
  (sample-writers (make-hash-table :test 'equalp) :type hash-table) ; src GUID -> SN -> writer EntityId (reader-side instance writers-set, DDS 1.4 §2.2.2.5.1.3)
  (sample-writer-guids (make-hash-table :test 'equalp) :type hash-table) ; src GUID -> SN -> 16-octet source GUID (EXCLUSIVE ownership arbitration, DDS 1.4 §2.2.3.9.2)
  (durability-gate-active nil :type boolean)   ; ADR 0059: T once the DCPS layer owns the reader-side durability baseline (create-datareader / %reader-durability-init arm a WriterProxy per matched writer). ONLY then does "matched but no proxy" mean the ADR 0043 window — a bare dds.disc node (the low-level tests, the shapes runners) never arms by design, so the HEARTBEAT guard must not fire there.
  (hb-unarmed-drops 0 :type (integer 0))   ; ADR 0043 residual / ADR 0059: user HEARTBEATs dropped because the writer was MATCHED but its reader-side durability baseline was not yet ARMED. MUST stay 0: the window is unreachable while SEDP + user HEARTBEATs share the one unicast rx thread. A non-zero value means a WP reopened it (user-data multicast / split metatraffic) and MUST arm the baseline atomically with %record-match — the drop keeps it fail-SAFE (no silent DURABILITY violation) but the writer's history request is delayed a HEARTBEAT period until then.
  (decode-fail-counts (make-hash-table :test 'equalp) :type hash-table) ; ADR 0031 lim.1 + ADR 0059: src GUID -> (KM sender_key_id . (SN -> consecutive KM-PRESENT decode-failure count)); the key-id STAMP resets the classification if a writer's KM is ever rotated (so samples under a NEW key are never suppressed by the STALE key's failures — discharges the ADR 0031 lim.1 forward requirement); bounds retransmit churn of a permanently-undecodable secured sample (never counts a missing-KM failure); pruned on writer unmatch + capped (NFR-MEM/NFR-SEC-POSTURE)
  (sample-origins (make-hash-table :test 'equalp) :type hash-table) ; src GUID -> SN -> (effective-origin-GUID . effective-origin-SN): the PID_ORIGINAL_WRITER_INFO logical origin when the received sample was relayed (RTPS 2.5 §8.3.5.4), absent for a direct sample (then the wire GUID/SN IS the origin)
  (capture-data-key-hash nil :type boolean) ; durability collect node opts in to materialize the wire PID_KEY_HASH on :data (control-plane); default NIL = byte-identical, no hot-path alloc (ADR 0029, RTPS 2.5 §9.6.4.8)
  (crypto-transform nil :type t) ; DDS-Security 1.1 §9.5.3.3 Slice-1: key-material for AES256-GCM serialized-payload protection; NIL = security OFF, byte-identical hot path (ADR 0031)
  (payload-arena nil :type list) ; WP-DDS-SECURITY-ZEROALLOC-AEAD T5a: the LIST of per-node static arenas backing the secured-payload pools (carved by %ensure-secured-payload-pool — at enable when crypto is already on, or lazily on the first secured publish when keys arrive after enable via the live DDS-Security handshake; stop-node tears every one down). WP-N-ENDPOINT-S3 (ADR 0048): a LIST (was a single slot) so N secured writers' carved arenas are ALL reachable at teardown — a 2nd secured writer's carve no longer orphans the first's. NIL = security OFF / no pool, byte-identical
  (payload-arena-lock (dds.pal:make-lock "payload-arena") :type t) ; WP-N-ENDPOINT-S3: guards the payload-arena LIST push (the per-writer carve runs under the per-WRITER lock, so two writers racing their first secured publish would lost-update the shared list — orphaning one arena at teardown; a dedicated LEAF lock serializes the push, no ordering hazard). Read lock-free at stop-node (quiesced, all threads joined).
  ;; WP-DDS-SECURITY-ZEROALLOC-AEAD T5b: per-node DECODE side (data_protection RECEIVE). SECURED-LOAN-CAPABLE
  ;; (opt-in; set-secured-loan-capable) routes a secured receive through the LOAN pattern: the receiver thread
  ;; decodes the SecuredPayload into a DECODE-POOL buffer (decode-serialized-payload-into, zero per-sample
  ;; plaintext alloc) and stores a SECURED-LOAN-HANDLE (not a bare plaintext vector) in disc-node-samples — the
  ;; buffer lifetime is tied to the loan registry (SECURED-LOANS), NOT the never-purged samples store, so it
  ;; cannot leak/pin. DECODE-ARENA is the static arena backing DECODE-POOL (a fixed pool of plaintext buffers,
  ;; carved lazily by %ensure-secured-decode-pool). DECODE-POOL-LOCK serializes pool-acquire/release across the
  ;; single receiver thread + the app thread (return-loan); it nests INSIDE disc-node-lock (lock order:
  ;; disc-node-lock outer). DECODE-POOL-REJECTS counts samples dropped on pool exhaustion (SAMPLE_REJECTED;
  ;; un-acked -> writer backpressure, never a GC fallback). WP-DDS-SECURITY-ZEROALLOC-AEAD T5d de-cons the loan
  ;; WRAPPER so the secured RECEIVE adds 0 B/sample over plain: DECODE-HANDLE-VEC/-TOP is a FREELIST of
  ;; preallocated secured-loan-handle structs (recycled on return like the buffer pool — no per-sample struct
  ;; cons; guarded by DECODE-POOL-LOCK, paired 1:1 with the buffer pool so acquire never fails when a buffer was
  ;; free). SECURED-LOAN-VEC/-COUNT is the outstanding-loan registry as a fixed vector + fill pointer (O(1)
  ;; register/deregister via the handle's REG-INDEX swap-remove — replaces the per-loan list cons; guarded by
  ;; disc-node-lock). SECURED-TAKE-VEC is the reused node-take-loaned result buffer (single-consumer — the node's
  ;; one user reader — so no per-take list cons). All three carved once by %ensure-secured-decode-pool, sized to
  ;; the pool capacity. All NIL/0/#() default = secured loan OFF -> the allocating decode-serialized-payload path,
  ;; byte-identical.
  (secured-loan-capable nil :type boolean)
  (decode-arena nil :type t)
  (decode-pool nil :type t)
  (decode-pool-lock (dds.pal:make-lock "decode-pool") :type t)
  (decode-handle-vec #() :type simple-vector)
  (decode-handle-top 0 :type fixnum)
  (secured-loan-vec #() :type simple-vector)
  (secured-loan-count 0 :type fixnum)
  (secured-take-vec nil :type (or null simple-vector))
  (decode-pool-rejects 0 :type (integer 0))
  (sample-key-hashes (make-hash-table :test 'equalp) :type hash-table) ; src GUID -> SN -> 16-octet wire key-hash of the :data sample (RTPS 2.5 §9.6.4.8), absent when not captured
  (sample-timestamps (make-hash-table :test 'equalp) :type hash-table) ; S5.T4: src GUID -> SN -> source_timestamp (nanoseconds) from the preceding INFO_TS (RTPS 2.5 §9.4.5.9), absent when the DATA carried none
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
  ;; ParticipantStatelessMessage writer SN (stateless-message.lisp, DDS-Security 1.1 §7.4.3): a valid
  ;; RTPS writerSN MUST be >= 1 (RTPS 2.5 §8.3.5.4 / §8.4.2) — a conformant reader (Fast DDS
  ;; MessageReceiver: sequenceNumber <= 0 -> "bad sequence Number") drops a SN-0 DATA before the
  ;; security layer. Monotonic from 1 (incf before each send), so handshake retransmits are fresh samples.
  (psm-writer-sn 0 :type integer)
  ;; Writer Liveliness Protocol state (participant-message.lisp, RTPS 2.5 §8.4.13)
  (pm-writer-sn 1 :type integer) ; BuiltinParticipantMessageWriter per-writer SN (1-based)
  (remote-liveliness (make-hash-table :test 'equalp) :type hash-table) ; (12-octet prefix . kind) -> %lease-now stamp
  (liveliness-state (make-hash-table :test 'equalp) :type hash-table) ; matched remote-writer 16-octet GUID -> alive-p (reader-side LIVELINESS_CHANGED transition flag)

  ;; DDS-Security 1.1 §7.4.3.2 IdentityToken octets for SPDP; NIL = security OFF, byte-identical.
  (identity-token-octets nil :type (or null (simple-array (unsigned-byte 8) (*))))
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
  ;; ADR-0034 MINOR-4: called (node prefix) OUTSIDE the lock by %lease-sweep for each REMOTE participant that leased out,
  ;; so the security layer drops that lost peer's KeyMaterials from the crypto-manager (cm-forget-remote-participant:
  ;; unresolve + wipe secrets; bounded active tables). NIL = security OFF / no crypto-manager -> no-op.
  (on-participant-lost nil :type (or null function))
  (on-liveliness-changed nil :type (or null function))
  (type-gate nil :type (or null function))
  (on-incompatible-qos nil :type (or null function))
  (on-inconsistent-topic nil :type (or null function))
  (on-sample nil :type (or null function))
  (on-sample-lost nil :type (or null function)) ; DCPS-facing (S4): (reader-id n) after a reliable GAP declares n never-received SNs permanently gone (SAMPLE_LOST, DDS 1.4 §2.2.4.1)
  ;; Slice 2b-i: PSM receiver callback (DDS-Security 1.1 §7.4.3 / §8.7); NIL = PSM messages ignored.
  (on-stateless-message nil :type (or null function))
  ;; Slice 4 (T7): reliable ParticipantVolatileMessageSecure endpoint (DDS-Security 1.1 §7.4.5 / §9.5.3.1).
  ;; PVMS-WRITER/PVMS-READER are the VOLATILE (KEEP_ALL, no durability) reliable engine state at the secure
  ;; PVMS EntityIds (created by enable-volatile-secure). PVMS-BOOTSTRAP-KMS maps a remote 12-octet GUID prefix
  ;; to that pair's §9.5.3.1 SharedSecret-derived bootstrap KeyMaterial (set at :authenticated by the crypto
  ;; manager; lock-guarded). ON-VOLATILE-SECURE (mirrors ON-STATELESS-MESSAGE) is the receiver hook delivered
  ;; each recovered crypto-token ParticipantGenericMessage payload; NIL = no PVMS delivery. All NIL/empty
  ;; unless enable-volatile-secure is called — security OFF, byte-identical.
  (pvms-writer nil :type (or null dds.rtps.reliable:rtps-writer))
  (pvms-reader nil :type (or null dds.rtps.reliable:rtps-reader))
  (pvms-bootstrap-kms (make-hash-table :test 'equalp) :type hash-table)
  ;; ADR-0036/0040 carry: PVMS bootstrap KMs pruned on peer-loss (%prune-pvms-bootstrap-km) are WIPED in place then
  ;; parked HERE — their foreign-static buffers are freed at the QUIESCED stop-node teardown (never mid-run: a
  ;; concurrent %on-volatile-secure decode may still reference a just-pruned KM -> no UAF). Bounded by peer churn per teardown.
  (retired-pvms-kms nil :type list)
  (on-volatile-secure nil :type (or null function))
  ;; Slice 4 (T9): secure SEDP builtin endpoints (DDS-Security 1.1 §7.4.5 / §8.4.1.6 / §9.4.1.2.3). All three
  ;; closures are installed cross-layer by the dds-dcps managers (the disc layer stays crypto/policy-free):
  ;; SECURE-SEDP-ENCODE-KM (entity-id -> local secure-SEDP EntityCrypto §9.5.2 key-material | nil) is the
  ;; ENCODE source for a protected announce; SECURE-SEDP-DECODE-KM (4-octet CryptoHeader transformation_key_id
  ;; -> remote secure-SEDP EntityCrypto | nil) is BOTH the inbound SEC_PREFIX-bracket discriminator (secure SEDP
  ;; vs PVMS) AND the DECODE source; DISCOVERY-PROTECTED-TOPIC-P (topic-name -> boolean) routes a topic's
  ;; DiscoveredWriter/ReaderData to the secure SEDP endpoints ONLY (off plain SEDP) and, being non-NIL, marks
  ;; secure discovery active so %node-spdp-data advertises BuiltinEndpointSet bits 16-19. All NIL (default) =
  ;; security OFF / no discovery protection -> byte-identical plain SEDP, no secure bits, SEC_PREFIX -> PVMS.
  ;; SECURE-SEDP-PROTECTION-KIND is the EFFECTIVE base submessage-protection kind a protected announce uses
  ;; (DDS-Security 1.1 §9.4.1.2.3 governance discovery_protection_kind: :sign = authenticated-but-visible,
  ;; :encrypt = confidential) — installed from governance by the dds-dcps AccessControl manager so the announce
  ;; HONORS the directive instead of hardcoding ENCRYPT (a SIGN governance must SIGN, not ENCRYPT). Read only on
  ;; the secure path (when discovery-protected-topic-p is set); the :encrypt default is inert otherwise.
  (secure-sedp-encode-km nil :type (or null function))
  (secure-sedp-decode-km nil :type (or null function))
  (discovery-protected-topic-p nil :type (or null function))
  (secure-sedp-protection-kind :encrypt :type (member :sign :encrypt))
  ;; T-ORIGINAUTH (DDS-Security 1.1 §9.5.3.3.4.3): origin-authentication for the secure-SEDP tier — the
  ;; *_WITH_ORIGIN_AUTHENTICATION discovery_protection_kind variants add per-receiver MACs on top of the base
  ;; SIGN/ENCRYPT. SECURE-SEDP-ORIGIN-AUTH (boolean) is set from governance by the dds-dcps AccessControl
  ;; manager; it drives the crypto-manager to mint receiver-specific keys for the secure-SEDP READER EntityCryptos.
  ;; SECURE-SEDP-ENCODE-RECEIVERS (writer-entity-id remote-prefix) -> the matched-remote READER's receiver
  ;; descriptors ((receiver_specific_key_id . master_receiver_specific_key) ...) for encode :receivers, or NIL
  ;; (the crypto-manager cm-secure-sedp-encode-receivers). SECURE-SEDP-DECODE-RECEIVER-KM (4-octet
  ;; transformation_key_id) -> the LOCAL receiving READER's (key_id . key) cons for decode my-receiver-key, or NIL
  ;; (cm-secure-sedp-decode-receiver). All NIL = no origin-auth -> encode passes no :receivers / decode passes no
  ;; my-receiver-key -> plain SIGN/ENCRYPT, byte-identical to the non-origin-auth path.
  (secure-sedp-origin-auth nil :type boolean)
  (secure-sedp-encode-receivers nil :type (or null function))
  (secure-sedp-decode-receiver-km nil :type (or null function))
  ;; ADR-0040 carry (submessage-substitution defense, §8.5.1.9 / §9.5.2 Table 65): SECURE-SEDP-DECODE-SENDER-ENTITY
  ;; (4-octet transformation_key_id) -> the EXPECTED remote sender entity-id the key_id was registered under
  ;; (crypto-manager REMOTE-KEY-ID-ENTITY, written atomically with the KM), so %on-secure-builtin cross-checks the
  ;; decrypted INNER writer-sourced submessage's writerId (DATA/HEARTBEAT) against it and DROPS a mismatch
  ;; fail-closed. NIL (security OFF / no resolver / unknown key_id) -> no cross-check (no false-REJECT), byte-identical.
  (secure-sedp-decode-sender-entity nil :type (or null function))
  ;; Slice 4 (T11): secure participant-message (liveliness/WLP) + secure SPDP re-announce builtin endpoints
  ;; (DDS-Security 1.1 §7.4.5 / §8.4.1.6 / §9.4.1.2.3). Both tiers REUSE the generic secure-builtin EntityCrypto
  ;; resolvers above (SECURE-SEDP-ENCODE-KM / -DECODE-KM / -ENCODE-RECEIVERS / -DECODE-RECEIVER-KM resolve ANY
  ;; registered secure builtin entity by its EntityId / wire transformation_key_id — not SEDP-specific), so only
  ;; the per-tier PROTECTION KIND + ORIGIN-AUTH flag and the per-writer SNs are tier-local here.
  ;; SECURE-PM-PROTECTION-KIND is the EFFECTIVE base submessage-protection kind for the Writer Liveliness Protocol
  ;; (governance liveliness_protection_kind via the AccessControl manager: :none = OFF -> plain WLP, byte-identical;
  ;; :sign authenticated-but-visible | :encrypt confidential). When != :none, assert-participant-liveliness routes
  ;; EVERY assertion over the secure BuiltinParticipantMessageSecureWriter (0xff0200c2), submessage-protected, to the
  ;; :authenticated peers ONLY (NEVER plain WLP — a confidential liveliness assertion must not leak), and SPDP
  ;; advertises BuiltinEndpointSet bits 20/21. SECURE-PM-ORIGIN-AUTH adds the per-receiver MAC tier (§9.5.3.3.4.3).
  ;; The secure SPDP re-announce rides the DISCOVERY protection tier (bits 26/27 are DISC_BUILTIN_ENDPOINT_PARTICIPANT
  ;; _SECURE_*): it is gated on DISCOVERY-PROTECTED-TOPIC-P being non-NIL (= discovery protection active) and uses
  ;; SECURE-SEDP-PROTECTION-KIND / -ORIGIN-AUTH (same governance discovery_protection_kind as secure SEDP), so no
  ;; separate SPDP protection slot is needed. SECURE-PM-WRITER-SN / SECURE-SPDP-SN are the per-secure-writer SN
  ;; spaces (distinct EntityIds -> distinct SN spaces, RTPS 2.5 §8.3.5.4); 1-based / 0-then-incf to mirror the plain
  ;; pm-writer-sn / spdp-sn. All default OFF (:none / 0 / 1) -> security OFF is byte-identical (no secure WLP/SPDP).
  (secure-pm-protection-kind :none :type (member :none :sign :encrypt))
  (secure-pm-origin-auth nil :type boolean)
  (secure-pm-writer-sn 1 :type integer)
  (secure-spdp-sn 0 :type integer)
  ;; DDS-Security 1.1 §7.3 / §8.5: T (default) = §8.5 crypto-token keying (ParticipantCrypto / EntityCrypto
  ;; exchange over PVMS) is a precondition for endpoint matching — the auth + permissions gates require the
  ;; remote to reach :keyed. NIL = the participant's governance mandates NO protection (every rtps/discovery/
  ;; liveliness/metadata/data kind NONE), so matched endpoints communicate in the clear and gate on §8.7
  ;; authentication + §8.4 permissions at :authenticated alone (§8.4.2.9 — matching is an access-control
  ;; decision; §8.5 crypto is engaged only for protected endpoints). Set from dds.security:governance-any-
  ;; protection-p by %install-access-control; DEFAULT T is fail-closed (auth-only / no-AccessControl keeps the
  ;; strict :keyed gate, byte-identical to before). A conformant reference peer (RTI Connext) exchanges no
  ;; participant crypto token when rtps_protection=NONE, so requiring :keyed there is an over-strict false-REJECT.
  (crypto-keying-required-p t :type boolean)
  ;; Slice 4 (T10): whole-RTPS-message protection (rtps_protection_kind, DDS-Security 1.1 §8.5.1.10-.12 /
  ;; §9.4.1.2.3). Once two participants are :keyed, the SENDER wraps the post-RTPS-header submessage stream of
  ;; its USER-DATA datagrams as SRTPS_PREFIX ‖ SEC_BODY ‖ SRTPS_POSTFIX keyed by the per-pair ParticipantCrypto,
  ;; and the receiver unwraps + re-dispatches. SPDP (multicast bootstrap) + PSM (pre-keying auth) are EXEMPT.
  ;; All four are installed cross-layer by the dds-dcps managers (the disc layer stays crypto/policy-free; it
  ;; only calls the CLOSURES). RTPS-PROTECTION-KIND is the EFFECTIVE base kind (:none default = OFF, byte-identical;
  ;; :sign | :encrypt from governance rtps_protection_kind via the AccessControl manager) the encode closure reads.
  ;; RTPS-PROTECTION-ORIGIN-AUTH (boolean) is set from governance; it drives the crypto-manager to mint the local
  ;; ParticipantCrypto's receiver-specific key (§9.5.3.3.4.3). RTPS-PROTECTION-ENCODE (dest 12-octet prefix ->
  ;; (values local-ParticipantCrypto-KM kind receivers) | NIL when the dest is not :keyed / rtps_protection NONE)
  ;; is the SEND wrap resolver; RTPS-PROTECTION-DECODE (src 12-octet prefix -> (values remote-ParticipantCrypto-KM
  ;; my-receiver-key-id my-receiver-key) | NIL when the src is unknown/not keyed) is the RECEIVE unwrap resolver.
  ;; All NIL/default = security OFF / rtps_protection NONE -> the send is byte-identical and a wrapped datagram is
  ;; dropped (a security-OFF node has no key for it). Set/installed by %install-access-control + %install-crypto-manager.
  (rtps-protection-kind :none :type (member :none :sign :encrypt))
  (rtps-protection-origin-auth nil :type boolean)
  (rtps-protection-encode nil :type (or null function))
  (rtps-protection-decode nil :type (or null function))
  ;; WP-DDS-SECURITY-ZEROALLOC-AEAD T3 (ZA-2): whole-RTPS (rtps_protection / SRTPS) zero-alloc dataplane scratch.
  ;; SEND-SCRATCH-POOL is a per-node fixed pool of datagram-sized static octet-buffers %maybe-wrap-srtps borrows to
  ;; build the SRTPS bracket BY OFFSET (encode-rtps-message-into) with no per-datagram subseq/→octets; SEND-SCRATCH-ARENA
  ;; backs it, SEND-SCRATCH-LOCK guards its acquire/release + carve. SECURE-RX-POOL is the SYMMETRIC RX pool the SRTPS
  ;; unwrap borrows a DISTINCT datagram-sized buffer from per decode to open ENCRYPT plaintext into (decode-rtps-message
  ;; -into) before copying back in place (SIGN moves in place, buffer unused) — a POOL, not one reused buffer, because
  ;; start-node runs up to THREE receiver threads (unicast / multicast / SHMEM) all feeding %handle-datagram, so a
  ;; single shared RX sink would race across transports (T3(ZA-2) review: thread A's decode->copy-back window vs thread
  ;; B decoding into the same buffer -> A copies B's plaintext -> wrong-sample delivery). SECURE-RX-ARENA backs it,
  ;; SECURE-RX-LOCK guards its acquire/release + carve (a DEDICATED lock so RX pool ops never contend with send pool
  ;; ops). Both pools are carved LAZILY on the first SRTPS wrap/unwrap (consistent with the other per-node security
  ;; pools + zero-cost when rtps_protection is off), double-checked under their lock, and torn down in stop-node.
  ;; Exhaustion -> fail-closed drop (RESOURCE_LIMITS backpressure, never a GC fallback; NFR-MEM). All NIL default =
  ;; rtps_protection off / not yet engaged -> byte-identical (the pools are never touched, no static memory reserved).
  (send-scratch-pool nil :type t)
  (send-scratch-arena nil :type t)
  (send-scratch-lock (dds.pal:make-lock "send-scratch") :type t)
  (secure-rx-pool nil :type t)
  (secure-rx-arena nil :type t)
  (secure-rx-lock (dds.pal:make-lock "secure-rx") :type t)
  ;; WP-DDS-SECURITY-ZEROALLOC-AEAD T5 (ZA-2): the RX SEC_PREFIX-bracket EXTRACTION pool. %handle-datagram borrows one
  ;; DISTINCT datagram-sized buffer per secured submessage to copy the [SEC_PREFIX,datagram-end) bracket into (the
  ;; decode INPUT), replacing the pre-T5 per-bracket (make-array (- size start)). A DEDICATED pool (its own
  ;; BRACKET-RX-LOCK), SEPARATE from SECURE-RX-POOL, because the bracket is the decode INPUT while %on-user-secure-
  ;; submessage decodes it INTO a SECURE-RX buffer (the OUTPUT): the two MUST be distinct live buffers, guaranteed here
  ;; by construction (two pools). Per-thread distinct borrow (≤3 receiver threads) — mirrors the T3 RX-race fix, so no
  ;; shared-sink race. Carved LAZILY on the first secured-bracket receive, double-checked under BRACKET-RX-LOCK, torn
  ;; down in stop-node. Runtime EXHAUSTION -> fail-closed drop (RESOURCE_LIMITS, never a GC fallback; NFR-MEM);
  ;; not-carved (arena exhausted) OR an oversized bracket -> the allocating make-array fallback (byte-identical). NIL
  ;; default = no secured receive yet -> zero static memory reserved (byte-identical plain path).
  (bracket-rx-pool nil :type t)
  (bracket-rx-arena nil :type t)
  (bracket-rx-lock (dds.pal:make-lock "bracket-rx") :type t)
  ;; WP-DDS-SECURITY-ZEROALLOC-AEAD T5 (ZA-2): the RX key_id scratch pool. %on-secure-submessage borrows one DISTINCT
  ;; 4-octet buffer per secured bracket to copy the §9.5.3.3.1 CryptoHeader transformation_key_id
  ;; into (%secure-bracket-key-id-into) before the equalp-keyed key_id resolvers look it up — replacing the pre-T5
  ;; per-bracket (subseq bracket 8 12). A dynamic-extent stack array cannot serve: this SBCL heap-allocates a
  ;; dynamic-extent SPECIALIZED (unsigned-byte 8) array (only simple-vectors stack-allocate), and the resolvers require
  ;; a (simple-array (unsigned-byte 8)); a pooled per-thread buffer is the alloc-free, race-free, resolver-compatible
  ;; scratch. Per-thread distinct borrow (≤3 receiver threads); carved LAZILY, double-checked under KEY-ID-RX-LOCK,
  ;; torn down in stop-node. Runtime EXHAUSTION -> fail-closed drop; not-carved (arena exhausted) -> a heap 4-array
  ;; fallback (byte-identical). NIL default = no secured receive yet -> zero static memory reserved.
  (key-id-rx-pool nil :type t)
  (key-id-rx-arena nil :type t)
  (key-id-rx-lock (dds.pal:make-lock "key-id-rx") :type t)
  ;; WP-DDS-SECURITY-ZEROALLOC-AEAD T4 (ZA-2): the metadata_protection (§8.5.1.7-.9) SEND multi-bracket wrap
  ;; (%maybe-wrap-user-submessages) builds the wrapped submessage stream BY OFFSET into a datagram-sized scratch
  ;; borrowed from this DEDICATED pool (element-bytes +srtps-scratch-datagram-bytes+ + +submsg-scratch-overhead+ =
  ;; ~10240, sized for the ~+56-octet-per-submessage bracket expansion), replacing the pre-ZA-2 per-datagram
  ;; (make-octet-buffer (+ len 8192)) + per-submessage subseq. A DEDICATED pool (not the 2104-octet send-scratch
  ;; pool) so the SRTPS send path stays efficient; carved LAZILY on the first user submessage wrap, double-checked
  ;; under SUBMSG-SCRATCH-LOCK (dedicated so it never contends with the send / RX pool ops), torn down in stop-node.
  ;; Exhaustion -> fail-closed drop (RESOURCE_LIMITS, never a GC fallback; NFR-MEM); carve-failed (arena exhausted)
  ;; -> the allocating fallback. All NIL default = metadata_protection off / not yet engaged -> byte-identical.
  (submsg-scratch-pool nil :type t)
  (submsg-scratch-arena nil :type t)
  (submsg-scratch-lock (dds.pal:make-lock "submsg-scratch") :type t)
  ;; WP-SECURITY-ZC-SHMEM-OVERLAY (ADR 0051): lazily-carved pool of slot-sized static octet-buffers a wire-protected
  ;; ENCRYPT-tier writer seals its in-slot data_protection SecuredPayload into (encode-serialized-payload-into), so the
  ;; Zero-Copy/SHMEM slot holds CIPHERTEXT, never the cleartext payload. NIL until the first overlay publish (a node with
  ;; no ENCRYPT-tier ZC writer reserves no static memory); arena stored only after the carve succeeds (teardown
  ;; reachability); stop-node tears it down. Exhaustion/carve-fail -> fail-closed skip (writer stays gated off, never a GC
  ;; fallback). Dedicated ZC-OVERLAY-SCRATCH-LOCK so its ops never contend with the send / RX / submsg pool ops.
  (zc-overlay-scratch-pool nil :type t)
  (zc-overlay-scratch-arena nil :type t)
  (zc-overlay-scratch-lock (dds.pal:make-lock "zc-overlay-scratch") :type t)
  ;; Slice 5 (WP-DDS-SECURITY-FASTDDS-INTEROP): USER-DATA submessage protection (metadata_protection_kind,
  ;; DDS-Security 1.1 §8.5.1.7-.9 / §9.4.1.2.3). When governance sets the user topic's metadata_protection_kind
  ;; != NONE, EACH user-plane submessage (DATA/DATA_FRAG/HEARTBEAT/GAP/HEARTBEAT_FRAG from the writer;
  ;; ACKNACK/NACK_FRAG from the reader) is individually wrapped as a SEC_PREFIX ‖ CryptoHeader ‖ SEC_BODY (ENCRYPT)
  ;; | verbatim (SIGN) ‖ SEC_POSTFIX bracket under the LOCAL user endpoint's EntityCrypto, INSIDE the rtps_protection
  ;; SRTPS wrap (submessage protection is inner, whole-message outer — Fast DDS RTPSMessageGroup send order). INFO_*
  ;; submessages pass through unprotected. USER-SUBMESSAGE-PROTECTION-KIND is the EFFECTIVE base kind (:none default
  ;; = OFF, byte-identical; :sign | :encrypt from governance metadata_protection_kind via create-datawriter/reader).
  ;; USER-SUBMESSAGE-ENCODE (writer-p -> (values local-EntityCrypto-KM kind) | NIL when not keyed / kind NONE) is the
  ;; SEND wrap resolver (writer-p T = the user WRITER's EntityCrypto for a DATA/HEARTBEAT/…, NIL = the user READER's
  ;; for an ACKNACK). USER-SUBMESSAGE-DECODE (4-octet transformation_key_id -> the REMOTE user EntityCrypto KM, or NIL
  ;; when the key_id is not a USER endpoint — so a builtin bracket still routes to %on-secure-builtin) is the RECEIVE
  ;; resolver. All NIL/default = security OFF / metadata_protection NONE -> the user submessage path is byte-identical.
  ;; Installed by %install-crypto-manager + create-datawriter/datareader (the kind from governance).
  (user-submessage-protection-kind :none :type (member :none :sign :encrypt))
  ;; §9.4.1.2.4 data_protection_kind (serialized-payload SecuredPayload tier). :none = the payload rides PLAIN, so
  ;; the crypto-transform serialized-payload encode/decode is SKIPPED (a SIGN tier with data=NONE: metadata_protection
  ;; SIGN authenticates the visible payload; applying data_protection to a plain payload would encrypt-on-send /
  ;; decode-fail-drop-on-receive). :UNSET (default) = no governance has determined it — the crypto-transform, when
  ;; installed (a keyed peer / a test that sets it directly), is applied as before (backward-identical); ONLY an
  ;; EXPLICIT :none from governance skips it. Set from governance (%install-access-control participant default +
  ;; %set-user-metadata-protection per-topic) to :none | :sign | :encrypt.
  (user-data-protection-kind :unset :type (member :unset :none :sign :encrypt))
  ;; ADR 0046 §9.4.1.2.4/§9.5 per-ROLE protection kinds (the FIX for the cross-role false-ACCEPT downgrade): the writer's
  ;; OWN topic kinds and the reader's OWN topic kinds, resolved+CACHED at add-local time from each role's topic — NEVER a
  ;; shared slot either role mutates. publish-sample reads user-WRITER-data-protection-kind; %deliver-user-sample reads
  ;; user-READER-data-protection-kind; user-submessage-encode picks the role's submessage kind by writer-p; %cm-entity-
  ;; protection-kind derives each role's km from the role that owns the EntityId. Defaults mirror the shared slots
  ;; (:unset data / :none submessage) so the no-governance / direct-KM / keyed paths stay byte-identical. The shared
  ;; user-{data,submessage}-protection-kind slots above/below remain as the MOST-PROTECTIVE MAX (monotonic) for the
  ;; participant-scope consumers ONLY (the datagram fast-skip gate, prescan, ZC/loan wire-protection guards).
  (user-writer-data-protection-kind :unset :type (member :unset :none :sign :encrypt))
  (user-writer-submessage-protection-kind :none :type (member :none :sign :encrypt))
  (user-reader-data-protection-kind :unset :type (member :unset :none :sign :encrypt))
  (user-reader-submessage-protection-kind :none :type (member :none :sign :encrypt))
  ;; WP-N-ENDPOINT-S3 (ADR 0048): the PER-ENDPOINT generalization of the 2 ADR-0046 role slots — EntityId ->
  ;; (data-protection-kind . metadata/submessage-protection-kind) resolved from THAT endpoint's OWN topic at
  ;; add-local, so N secured writers each key from their own topic (the send-crux + %cm-entity-protection-kind read
  ;; it). Strictly FINER than the role slots: adding one endpoint never mutates another's entry (no cross-role/
  ;; cross-endpoint downgrade). Empty (security OFF / no governance) -> the role-slot fallback -> byte-identical.
  (user-endpoint-protection-kind (make-hash-table :test 'eql) :type hash-table)
  ;; §9.4.1.2.4 per-topic data_protection resolver (topic-name -> :none|:sign|:encrypt) installed from governance by %install-access-control; add-local-{writer,reader} refine user-data-protection-kind via it to the endpoint's ACTUAL rule (no first-rule participant-default downgrade). NIL = security OFF / no governance -> unchanged.
  (topic-data-protection-resolver nil :type (or null function))
  ;; §9.4.1.2.4 per-topic metadata_protection resolver (topic-name -> :none|:sign|:encrypt) installed from governance by %install-access-control; add-local-{writer,reader} refine user-submessage-protection-kind via it to the endpoint's ACTUAL rule (no first-rule participant-default downgrade). NIL = security OFF / no governance -> unchanged.
  (topic-metadata-protection-resolver nil :type (or null function))
  (user-submessage-encode nil :type (or null function))
  (user-submessage-decode nil :type (or null function))
  ;; DDS-Security 1.1 §7.3.4: called (node prefix spdp) outside the lock on first SPDP from a security-capable remote.
  (on-participant-discovered nil :type (or null function))
  ;; DDS-Security 1.1 §7.3: endpoint auth gate (node remote local) -> :compatible|:incompatible|:pending; NIL = security OFF.
  (auth-gate nil :type (or null function))
  ;; DDS-Security 1.1 §7.3: manager-owned per-participant auth state (12-octet prefix -> opaque).
  (auth-state (make-hash-table :test 'equalp) :type hash-table)
  ;; DDS-Security 1.1 §8.4: access-control gate (node remote local) -> :compatible|:incompatible|:pending; NIL = AC OFF.
  (permissions-gate nil :type (or null function))
  (mcast-socket nil :type t)
  (mcast-rx-thread nil :type t)
  (rx-thread nil :type t))

(defstruct* (flow-writer-state (:constructor %make-flow-writer-state))
  "WP-N-ENDPOINT-S1B (ADR 0048): the per-WRITER flow-control state — the flow-controller's SELECTION ENTRY. One per
   associated local user DataWriter. The token BUCKET, the scheduler thread, and the RR cursor stay NODE/controller-
   shared (one participant = one aggregate rate); only the send CURSOR + scheduling keys are per-writer, so the
   already-node-global EDF/priority min-key selector (%flow-policy-select) naturally orders samples ACROSS the
   participant's writers (a tight-LATENCY_BUDGET writer ahead of a loose one, even on the same node). NODE + WRITER
   identify the drained endpoint: the plan builds THIS writer's unsent set into the shared scratch under
   *emit-writer*. STEP-STATE is the in-progress per-datagram plan (NIL = rebuild); STEP-REFS the send-refs held from
   snapshot until the plan drains (release-safety, operating contract §4); PENDING the new-unsent-work signal;
   HEAD-NS/LATENCY-BUDGET-NS the :edf deadline summands; TRANSPORT-PRIORITY/LAST-SERVED-NS the :priority effective-key
   inputs. All CONTROLLER-lock-guarded except STEP-STATE/STEP-REFS, which only the single scheduler/drain thread
   mutates (the same single-mutator discipline as the pre-S1B node slots)."
  (node nil :type t)                     ; the owning disc-node (socket / tx buffers / node lock)
  (writer nil :type t)                   ; the rtps-writer engine instance (its OWN GUID / HistoryCache / EntityId)
  (step-state nil :type t)               ; in-progress per-datagram send plan; NIL = rebuild on next step
  (step-refs nil :type list)             ; send-refs held from snapshot until the plan drains (release-safety)
  (pending nil :type t)                  ; new unsent work awaiting a fresh plan snapshot
  (latency-budget-ns 0 :type integer)    ; cached LATENCY_BUDGET (ns) — the :edf key summand
  (transport-priority 0 :type integer)   ; cached TRANSPORT_PRIORITY — the :priority base
  (head-ns 0 :type integer)              ; :edf head-of-line write-time
  (last-served-ns 0 :type integer))      ; :priority aging baseline

(defun* %flow-writer-state-for (node writer)
    (function (disc-node (or null dds.rtps.reliable:rtps-writer)) t)
  "The per-writer flow-state (flow-writer-state) for engine WRITER under NODE's associated controller, looked up by
   EntityId (WP-N-ENDPOINT-S1B); falls back to the first registered state (defensive — every associated writer has
   one). NIL when the node has no flow-writer-states (no controller associated)."
  (let ((states (disc-node-flow-writer-states node)))
    (when states
      (or (and writer (cdr (assoc (dds.rtps.reliable:rtps-writer-entityid writer) states :test #'eql)))
          (cdr (first states))))))

;; WP-N-ENDPOINT-S0-REGISTRY (ADR 0048): compat accessors + register/lookup/enumerate API over the user-endpoint
;; registries. Control plane (endpoint create/enable), never the per-sample hot path. N=1: exactly one entry, so the
;; compat accessor returns the sole engine instance the pre-S0 slot returned — byte-identical.
(defun* disc-node-user-writer (node)
    (function (disc-node) (or null dds.rtps.reliable:rtps-writer))
  "This node's PRIMARY (first-registered) user engine writer, or NIL — the N=1 compat accessor over the user-writer
   registry (WP-N-ENDPOINT-S0; S1 fans out the send path across %all-user-writers)."
  (disc-node-primary-user-writer node))

(defun* disc-node-user-reader (node)
    (function (disc-node) (or null dds.rtps.reliable:rtps-reader))
  "This node's PRIMARY (first-registered) user engine reader, or NIL — the N=1 compat accessor over the user-reader
   registry (WP-N-ENDPOINT-S0; S2 routes delivery across %all-user-readers)."
  (disc-node-primary-user-reader node))

(defun* %register-user-writer (node entity-id writer)
    (function (disc-node (unsigned-byte 32) dds.rtps.reliable:rtps-writer) dds.rtps.reliable:rtps-writer)
  "Register WRITER under ENTITY-ID in NODE's user-writer registry (WP-N-ENDPOINT-S1, ADR 0048); the first
   registered becomes primary (N=1 identity for disc-node-user-writer). Re-registering the SAME id REPLACES the
   entry in place (byte-identical to the pre-S0 enable-publisher engine-writer clobber), keeping the primary ref
   current if that id IS the primary. A NEW distinct id ADDS an N-th local writer (each with its own EntityId +
   HistoryCache; a 2nd SECURED writer is SUPPORTED — WP-N-ENDPOINT-S3, each keyed under its OWN EntityCrypto km; a
   2nd writer under an associated flow-controller is SUPPORTED — WP-N-ENDPOINT-S1B, each becomes a per-writer
   selection entry; a 2nd RETAINING-durability writer is SUPPORTED — WP-N-ENDPOINT-S2B, the match-time late-joiner
   replay (%writer-durability-init / %prearm-writer-future-base / finalize-writer-durability) is per-writer so each
   durable writer replays its OWN retained history under its OWN GUID). When a controller is associated, EACH
   registered writer (first or N-th, new or re-registered) is (re)registered with it as a per-writer flow-state
   (flow-controller-add-writer, S1b)."
  (let ((cell (assoc entity-id (disc-node-user-writers node) :test #'eql)))
    (cond (cell (let ((was-primary (eq (cdr cell) (disc-node-primary-user-writer node))))
                  (setf (cdr cell) writer)
                  (when was-primary (setf (disc-node-primary-user-writer node) writer))))
          ((null (disc-node-user-writers node))   ; first writer -> primary (N=1 identity)
           (push (cons entity-id writer) (disc-node-user-writers node))
           (setf (disc-node-primary-user-writer node) writer))
          (t (push (cons entity-id writer) (disc-node-user-writers node))))   ; N-th writer (S2B: durable multi-writer supported); primary unchanged
    (when (disc-node-flow-controller node)   ; WP-N-ENDPOINT-S1B: (re)register this writer as a per-writer flow-state
      (flow-controller-add-writer (disc-node-flow-controller node) node writer)))
  writer)

(defun* %alloc-user-writer-key (node)
    (function (disc-node) (unsigned-byte 8))
  "Allocate + return the next distinct per-participant USER-writer entity KEY (WP-N-ENDPOINT-S1, ADR 0048; RTPS
   2.5 §9.3.1.2). Starts at 1 so the first DataWriter keeps EntityId #x0102/#x0103 (byte-identical to pre-S1);
   each subsequent writer gets a distinct key -> a distinct EntityId + SEDP GUID. Builtin/secure EntityIds are
   NOT drawn from here. Fail-fasts if the 1-octet key space (255 writers/participant) is exhausted."
  (let ((k (disc-node-user-writer-key-next node)))
    (when (> k #xff)
      (error "disc-node: user-writer entity-key space exhausted (>255 DataWriters on one participant)"))
    (setf (disc-node-user-writer-key-next node) (1+ k))
    k))

(defun* %alloc-user-reader-key (node)
    (function (disc-node) (unsigned-byte 8))
  "Allocate + return the next distinct per-participant USER-reader entity KEY (WP-N-ENDPOINT-S2, ADR 0048; RTPS
   2.5 §9.3.1.2). Starts at 1 so the first DataReader keeps EntityId #x0107/#x0104 (byte-identical to pre-S2);
   each subsequent reader gets a distinct key -> a distinct EntityId + SEDP GUID. Writer + reader keys are
   SEPARATE counters (the entity KIND — 0x07/0x04 reader vs 0x02/0x03 writer — keeps their EntityIds disjoint even
   at the same key). Builtin/secure EntityIds are NOT drawn from here. Fail-fasts if the 1-octet key space (255
   readers/participant) is exhausted."
  (let ((k (disc-node-user-reader-key-next node)))
    (when (> k #xff)
      (error "disc-node: user-reader entity-key space exhausted (>255 DataReaders on one participant)"))
    (setf (disc-node-user-reader-key-next node) (1+ k))
    k))

(defun* %register-user-reader (node entity-id reader)
    (function (disc-node (unsigned-byte 32) dds.rtps.reliable:rtps-reader) dds.rtps.reliable:rtps-reader)
  "Register READER under ENTITY-ID in NODE's user-reader registry (WP-N-ENDPOINT-S2, ADR 0048); the first
   registered becomes primary (N=1 identity for disc-node-user-reader). Re-registering the SAME id REPLACES the
   entry in place (byte-identical to the pre-S0 enable-subscriber engine-reader clobber), keeping the primary ref
   current if that id IS the primary. A NEW distinct id ADDS an N-th local reader (each with its own EntityId +
   engine rtps-reader; the receive-hook demux + the %drain source-GUID filter route delivery per reader).
   WP-N-ENDPOINT-S4/2C3 (ADR 0048): the secured/ZC-loan-capable fence is LIFTED — a 2nd loan-capable reader now
   registers, AND (2C3) the SAME-topic fence in add-local-reader is ALSO lifted: two SAME-topic loan-capable
   readers match the SAME remote writer, so they DO share one (guid,SN) store slot / ZC marker. The cross-reader
   use-after-free is then prevented not by disjointness but by explicit refcounting: the secured decode handle's
   return-count = route length (purge/free only on the LAST reader's return) and the ZC slot's join-watermark +
   %count-eligible-drainers demux bump. Per-reader delivery (%deliver-user-sample source-GUID + per-reader
   dr-drained high-water) + per-reader dr-secured-loans keep delivery + release isolated. Verified end-to-end at
   the DCPS layer by run-dcps-same-topic-secured-readers-test (WP-DCPS-API-COMPLETION S6.T1)."
  (let ((cell (assoc entity-id (disc-node-user-readers node) :test #'eql)))
    (cond (cell (let ((was-primary (eq (cdr cell) (disc-node-primary-user-reader node))))
                  (setf (cdr cell) reader)
                  (when was-primary (setf (disc-node-primary-user-reader node) reader))))
          ((null (disc-node-user-readers node))   ; first reader -> primary (N=1 identity)
           (push (cons entity-id reader) (disc-node-user-readers node))
           (setf (disc-node-primary-user-reader node) reader))
          (t (push (cons entity-id reader) (disc-node-user-readers node)))))   ; N-th reader (S4: secured/ZC fence lifted; same-topic fence in add-local-reader is the UAF guard); primary unchanged
  reader)

(defun* %reader-route-add (node writer-guid reader-entity-id)
    (function (disc-node (simple-array (unsigned-byte 8) (16)) (unsigned-byte 32)) t)
  "WP-N-ENDPOINT-S2/2C1 (ADR 0048): record that local reader READER-ENTITY-ID is matched to remote writer
   WRITER-GUID in the delivery route (node-lock guarded, idempotent — a re-announce never duplicates a reader-id).
   The route is the source-GUID filter for %drain (no cross-topic deserialize) AND the receive-hook demux key.
   WP-N-ENDPOINT-2C1: same-topic route-add-all conses the NEW reader to the FRONT, so %reader-routes-for's canonical
   (first) reader = the LAST-added. A same-topic reader joining MID-STREAM thus becomes canonical with an EMPTY
   reliable proxy -> a transient full-history re-NACK/retransmit over the shared store until it catches up (bounded,
   NO data loss — the per-reader dr-drained dedup absorbs the replay). Different-topic / N=1 routes hold a single id
   (byte-identical). Making canonicity the FIRST-joined reader (append) is a tracked 2c follow-on.
   WP-N-ENDPOINT-2C3 (ADR 0048/0017; MEMORY-SAFETY): the MATCH-TIME ZC-joiner high-water freeze. When this is a
   JOINER (the writer's route is ALREADY non-empty) on a ZC-loan-capable node, ATOMICALLY — in the SAME node-lock
   section as the route-add — freeze this reader's join-watermark for this writer to the CURRENT max stored SN. Read
   BEFORE the id is consed so it reflects the pre-join state. This is the load-bearing atomicity: because the marker
   demux ({route-snapshot -> %zc-bump(K-1) -> store} in %deliver-user-marker) runs under the SAME node lock, the two
   critical sections serialize — every marker STORED before this route-add is <= the frozen watermark (the joiner
   skips it, and it was never bumped for this reader) and every marker STORED after has this reader in its route
   snapshot (so it was bumped for it). Closes the [freeze,route-add] window that a registration-time freeze left
   open (a marker delivered in the gap, unbumped, would be drained+released by the joiner -> premature free while a
   sibling still views = UAF). The FIRST reader (empty route) is NOT frozen (drains from SN 1, byte-identical)."
  (dds.pal:with-lock ((disc-node-lock node))
    (let* ((key (copy-seq writer-guid))
           (ids (gethash key (disc-node-reader-routes node))))
      (unless (member reader-entity-id ids :test #'eql)
        (when (and ids (disc-node-zc-loan-capable node))   ; JOINER (route already non-empty) on a ZC-loan-capable node -> freeze its ZC high-water NOW, atomic with the route-add
          (setf (gethash writer-guid
                         (or (gethash reader-entity-id (disc-node-reader-join-watermarks node))
                             (setf (gethash reader-entity-id (disc-node-reader-join-watermarks node))
                                   (make-hash-table :test 'equalp))))
                (%node-max-stored-sn node writer-guid)))
        (setf (gethash key (disc-node-reader-routes node)) (cons reader-entity-id ids)))))
  t)

(defun* %node-max-stored-sn (node writer-guid)
    (function (disc-node (simple-array (unsigned-byte 8) (16))) integer)
  "WP-N-ENDPOINT-2C3 (ADR 0048): the highest RTPS SN currently stored for source writer WRITER-GUID (0 if none).
   CALLER HOLDS THE NODE LOCK (read against the live store, atomic with %reader-route-add's freeze). The store's
   inner per-writer SN map is keyed by SN, so this is a max over its keys — bounded by the matched-writer history,
   not by sample count."
  (let ((inner (gethash writer-guid (disc-node-samples node)))
        (m 0))
    (when inner (loop for sn being the hash-keys of inner do (when (> sn m) (setf m sn))))
    m))

(defun* %node-reader-join-watermark-unlocked (node reader-entity-id writer-guid)
    (function (disc-node (unsigned-byte 32) (simple-array (unsigned-byte 8) (16))) integer)
  "WP-DDS-ZC-REFCOUNT-LEAK (ADR 0048 §17.7): the lock-free body of node-reader-join-watermark — the frozen ZC-joiner
   high-water for local reader READER-ENTITY-ID against remote writer WRITER-GUID (0 if not a frozen joiner). CALLER
   HOLDS THE NODE LOCK. Split out so the demux (%deliver-user-marker via %count-eligible-drainers, already under the
   node lock) reads watermarks WITHOUT re-taking the lock — calling the public lock-taking accessor there would deadlock."
  (let ((inner (gethash reader-entity-id (disc-node-reader-join-watermarks node))))
    (if inner (gethash writer-guid inner 0) 0)))

(defun* node-reader-join-watermark (node reader-entity-id writer-guid)
    (function (disc-node (unsigned-byte 32) (simple-array (unsigned-byte 8) (16))) integer)
  "WP-N-ENDPOINT-2C3 (ADR 0048/0017): the ZC-joiner high-water for local reader READER-ENTITY-ID against remote
   writer WRITER-GUID — the max stored SN at the moment this reader was route-added to that writer (0 if this reader
   is not a frozen joiner for it). %drain gates a stored marker for this reader on max(dr-drained, this), so a
   mid-stream ZC joiner never drains a marker delivered before it joined (whose demux %zc-bump did not count it).
   Node-lock guarded."
  (dds.pal:with-lock ((disc-node-lock node))
    (%node-reader-join-watermark-unlocked node reader-entity-id writer-guid)))

(defun* %count-eligible-drainers (node writer-guid sn ids)
    (function (disc-node (simple-array (unsigned-byte 8) (16)) integer list) (integer 0))
  "WP-DDS-ZC-REFCOUNT-LEAK (ADR 0048 §17.7): count the route members (local reader EntityIds IDS, matched to remote
   writer WRITER-GUID) that WILL drain the marker at SN — those for whom SN > their frozen join-watermark, the EXACT
   W-term of the %drain gate (dds.dcps %drain: SN > max(dr-drained, join-watermark)). %deliver-user-marker sizes the
   ZC slot refcount bump to (this - 1) (over the writer's preset 1) so a FROZEN joiner (watermark >= SN, which SKIPS
   the marker) is NOT counted -> its phantom +1 is never added -> the slot's refcount can reach 0 -> no leak. CALLER
   HOLDS THE NODE LOCK.
   MEMORY-SAFETY (the #1 constraint): this omits the dcps-layer dr-drained term (unreachable from dds.disc — dds.dcps
   depends on dds.disc, never the reverse), and dr-drained can only RAISE the effective watermark; hence this count is
   a SUPERSET of the true drainers (SN > max(dr-drained, wm) implies SN > wm) and NEVER a subset — it can OVER-count
   (a smaller SAFE leak) but NEVER UNDER-count (an under-count would free a slot a drainer still holds = a cross-reader
   use-after-free, strictly worse than the leak). The frozen watermark is CONSTANT from demux through drain for a
   matched reader (frozen at route-add, purged only on unmatch), so a reader counted here is EXACTLY a reader the drain
   gate's W-term admits — no premature release. The strict `>` matches the drain gate: SN == watermark is NOT a drainer."
  (let ((n 0))
    (dolist (rid ids n)
      (when (> sn (%node-reader-join-watermark-unlocked node rid writer-guid)) (incf n)))))

(defun* node-user-reader-count (node)
    (function (disc-node) (integer 0))
  "Count of registered local user DataReaders on NODE (WP-N-ENDPOINT-S2). N<=1 keeps the %drain filter a
   pass-through (byte-identical to pre-S2 single-reader delivery); N>=2 engages the source-GUID filter."
  (length (disc-node-user-readers node)))

(defun* node-reader-matches-writer-p (node reader-entity-id writer-guid)
    (function (disc-node (unsigned-byte 32) (simple-array (unsigned-byte 8) (16))) boolean)
  "WP-N-ENDPOINT-S2 (ADR 0048): T iff local reader READER-ENTITY-ID is matched to remote writer WRITER-GUID (route
   membership, node-lock guarded). The %drain source-GUID filter (N>=2) keeps a stored sample for THIS reader only
   when this returns T — so a reader deserializes ONLY its own matched writers' bytes (no cross-topic corruption)."
  (dds.pal:with-lock ((disc-node-lock node))
    (and (member reader-entity-id (gethash writer-guid (disc-node-reader-routes node)) :test #'eql) t)))

(defun* %user-writer-for (node entity-id)
    (function (disc-node (unsigned-byte 32)) (or null dds.rtps.reliable:rtps-writer))
  "NODE's registered user engine writer for ENTITY-ID, or NIL (S1 send routing)."
  (cdr (assoc entity-id (disc-node-user-writers node) :test #'eql)))

(defun* %resolve-user-writer (node writer-id)
    (function (disc-node (or null (unsigned-byte 32))) (or null dds.rtps.reliable:rtps-writer))
  "Resolve the local user engine writer WRITER-ID names under NODE, or the PRIMARY when WRITER-ID is NIL or
   unregistered (WP-N-ENDPOINT-S1; the single publish-side writer-selection rule, factored DRY so the flow-signal
   at the tail of publish-sample resolves the SAME writer the writer-write used). N=1 = the primary, byte-identical."
  (or (and writer-id (%user-writer-for node writer-id))
      (disc-node-user-writer node)))

(defun* %user-reader-for (node entity-id)
    (function (disc-node (unsigned-byte 32)) (or null dds.rtps.reliable:rtps-reader))
  "NODE's registered user engine reader for ENTITY-ID, or NIL (S2 deliver routing)."
  (cdr (assoc entity-id (disc-node-user-readers node) :test #'eql)))

(defun* %all-user-writers (node)
    (function (disc-node) list)
  "Fresh list of NODE's registered user engine writers in REGISTRATION order (primary/first-registered first) —
   the deterministic S1 send fan-out order (each writer pushes its OWN unsent changes + HEARTBEATs, so the order
   is functionally independent; the enumeration is nonetheless fixed and MUST NOT be assumed 'primary first' by
   correctness). At N=1 the sole writer is the primary (byte-identical to the pre-fan-out single-primary path)."
  (nreverse (mapcar #'cdr (disc-node-user-writers node))))

(defun* %all-user-readers (node)
    (function (disc-node) list)
  "Fresh list of NODE's registered user engine readers in REGISTRATION order (primary/first-registered first) —
   the deterministic S2 deliver fan-out order (not yet fanned out; S1 keeps a single user reader)."
  (nreverse (mapcar #'cdr (disc-node-user-readers node))))

(defun* %all-user-writer-ids (node)
    (function (disc-node) list)
  "Fresh list of NODE's registered user WRITER EntityIds (the registry alist KEYS) in registration order — the
   WP-N-ENDPOINT-S3 (ADR 0048) enumeration %cm-local-token-entities pairs with +gm-datawriter-crypto-tokens+ so the
   §8.5.2 token exchange registers + sends ONE EntityCrypto per local writer. At N=1 = (list user-writer-id),
   byte-identical to the pre-S3 node-single id."
  (nreverse (mapcar #'car (disc-node-user-writers node))))

(defun* %all-user-reader-ids (node)
    (function (disc-node) list)
  "Fresh list of NODE's registered user READER EntityIds (the registry alist KEYS) in registration order — the
   WP-N-ENDPOINT-S3 (ADR 0048) enumeration %cm-local-token-entities pairs with +gm-datareader-crypto-tokens+. At N=1
   = (list user-reader-id), byte-identical to the pre-S3 node-single id (secured multi-READER stays Slice S4)."
  (nreverse (mapcar #'car (disc-node-user-readers node))))

(defun* remove-local-writer (node ep entity-id)
    (function (disc-node (or null dds.rtps.discovery:endpoint-data) (unsigned-byte 32)) (eql t))
  "WP-DCPS-API-COMPLETION S2.T4 (DDS 1.4 §2.2.2.4.1.5 delete_datawriter): remove the local user writer
   ENTITY-ID (its SEDP endpoint EP, or NIL) from NODE. Under the NODE LOCK — the SAME lock the receiver/
   sender push drivers take when they iterate the user-writer registry — drop the writer from the
   user-writer registry (repointing the primary to the next remaining writer, or NIL, if it WAS primary)
   and remove EP from disc-node-local-writers so announce-endpoints stops advertising it via SEDP. Taking
   the node lock is what makes this race-free against a concurrent send/retransmit (no use-after-free).
   Idempotent (an unregistered id / absent EP removes nothing). When the writer is under an associated
   flow-controller it is first removed from that controller (flow-controller-remove-writer — its own lock +
   per-node emit barrier, so pacing STOPS synchronously for this writer and delete is not left racing a queued
   datagram; done OUTSIDE the node lock to avoid a lock-order inversion with the scheduler's emit path). Other
   NODE-SCOPED resources shared with sibling endpoints (the ZC pool, the secured payload pools) are released at
   stop-node — deleting one of N endpoints must not tear down a pool a sibling still uses."
  (let ((fc (disc-node-flow-controller node))   ; flow removal FIRST, outside the node lock (barrier must not hold it)
        (w (cdr (assoc entity-id (disc-node-user-writers node) :test #'eql))))
    (when (and fc w) (flow-controller-remove-writer fc node w)))
  (dds.pal:with-lock ((disc-node-lock node))
    (let ((cell (assoc entity-id (disc-node-user-writers node) :test #'eql)))
      (when cell
        (setf (disc-node-user-writers node) (remove cell (disc-node-user-writers node)))
        (when (eq (disc-node-primary-user-writer node) (cdr cell))
          (setf (disc-node-primary-user-writer node) (cdr (first (disc-node-user-writers node)))))))
    (when ep
      (setf (disc-node-local-writers node) (remove ep (disc-node-local-writers node)))))
  t)

(defun* remove-local-reader (node ep entity-id)
    (function (disc-node (or null dds.rtps.discovery:endpoint-data) (unsigned-byte 32)) (eql t))
  "WP-DCPS-API-COMPLETION S2.T4 (DDS 1.4 §2.2.2.5.1.5 delete_datareader): remove the local user reader
   ENTITY-ID (its SEDP endpoint EP, or NIL) from NODE. Under the NODE LOCK — the SAME lock the receive-hook
   demux + %reader-route-add take — drop the reader from the user-reader registry (repointing the primary if
   it WAS primary), remove EP from disc-node-local-readers (SEDP stops advertising it), purge ENTITY-ID from
   every remote-writer delivery route in disc-node-reader-routes so no arriving sample is demuxed to the gone
   reader, and drop its mid-stream ZC-joiner high-water map. Taking the node lock serializes this against the
   receiver thread (no use-after-free). Idempotent. The CALLER (delete_datareader) MUST have returned this
   reader's outstanding loans BEFORE calling this (the delete-participant discipline), so no held refcount pins
   a writer pool. Node-scoped pools are freed at stop-node (a sibling reader may still use them)."
  (dds.pal:with-lock ((disc-node-lock node))
    (let ((cell (assoc entity-id (disc-node-user-readers node) :test #'eql)))
      (when cell
        (setf (disc-node-user-readers node) (remove cell (disc-node-user-readers node)))
        (when (eq (disc-node-primary-user-reader node) (cdr cell))
          (setf (disc-node-primary-user-reader node) (cdr (first (disc-node-user-readers node)))))))
    (when ep
      (setf (disc-node-local-readers node) (remove ep (disc-node-local-readers node))))
    (maphash (lambda (guid ids)
               (let ((pruned (remove entity-id ids :test #'eql)))
                 (if pruned
                     (setf (gethash guid (disc-node-reader-routes node)) pruned)
                     (remhash guid (disc-node-reader-routes node)))))
             (disc-node-reader-routes node))
    (remhash entity-id (disc-node-reader-join-watermarks node)))
  t)

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
                            (capture-data-key-hash nil) (crypto-transform nil)
                            (identity-token-octets nil) (on-stateless-message nil)
                            (lease-duration-seconds 100) (lease-duration-nanosec 0))
    (function (&key (:guid-prefix (simple-array (unsigned-byte 8) (12))) (:domain (integer 0)) (:host string) (:port (unsigned-byte 16)) (:peers list) (:multicast t) (:advertise-address string) (:batch-max-samples (integer 1)) (:capture-data-key-hash t) (:crypto-transform t) (:identity-token-octets t) (:on-stateless-message t) (:lease-duration-seconds (signed-byte 32)) (:lease-duration-nanosec (integer 0))) disc-node)
  "Open a metatraffic UDPv4 socket bound to HOST:PORT and build a discovery node.
   PEERS is a list of (host-string . port) the node announces SPDP to (FR-DISC-4).
   MULTICAST opens a second socket bound to the SPDP multicast port and joins the
   well-known group, so the node also discovers peers via multicast (FR-DISC-3).
   BATCH-MAX-SAMPLES > 1 enables WP-BATCH write-side batching (FR-PF-1): publish-sample defers the push
   until N samples accumulate or flush-batch fires (the announce cadence / stop-node), amortizing
   per-sample overhead for small samples (NFR-PERF-4). Default 1 = flush every write (no batching).
   CAPTURE-DATA-KEY-HASH (ADR 0029, RTPS 2.5 §9.6.4.8): when non-NIL, the receiver thread
   materializes the wire PID_KEY_HASH even on :data samples with payload (the durability collect node
   uses this; default NIL = byte-identical, no hot-path alloc).
   CRYPTO-TRANSFORM (ADR 0031, DDS-Security 1.1 §9.5.3.3): a dds.security:key-material; when non-NIL,
   publish-sample AES256-GCM-encodes the SerializedPayload before wire emission, and the receiver
   decodes before delivery (fail-closed on auth failure). NIL (default) = security OFF, byte-identical.
   IDENTITY-TOKEN-OCTETS (§7.4.3.2): CDR-LE IdentityToken DataHolder octets from validate-local-identity
   + identity-token; when non-NIL the node advertises PID_IDENTITY_TOKEN + PSM endpoint-set bits in SPDP.
   NIL (default) = security OFF, byte-identical SPDP (no PID_IDENTITY_TOKEN, no PSM bits).
   LEASE-DURATION-SECONDS / LEASE-DURATION-NANOSEC (WP-DCPS-API-COMPLETION S7, RTPS 2.5 §8.5.3.3.2): the
   leaseDuration this node announces in SPDP (PID_PARTICIPANT_LEASE_DURATION) — how long a peer keeps this
   participant alive after its last announcement before pruning it as stale. Default {100, 0} = the RTPS 2.5
   Table 9.18 spec default (byte-identical to the pre-S7 hardcoded value). DCPS drives these from the
   participant's DISCOVERY_CONFIG QoS; they are re-read on every announce, so set_qos re-applies live.
   ON-STATELESS-MESSAGE (Slice 2b-i, §7.4.3 / §8.7): function (node src-prefix envelope-octets) -> t
   invoked by the receiver thread when a PSM DATA arrives — delivered the RAW ParticipantGenericMessage
   envelope octets (§7.4.4); dds-disc stays crypto/format-agnostic and the consumer (the dds-dcps auth
   manager) does parse-generic-message + dispatch by message_class_id (handshake vs crypto-token, which
   share this endpoint with different DataHolders). Fail-closed: only the payload buffer-extent is
   bounds-checked here; a bad-extent payload is dropped. NIL (default) = PSM messages silently ignored."
  ;; In multicast mode bind the unicast socket to 0.0.0.0: a loopback-bound socket
  ;; cannot egress to a multicast group (EADDRNOTAVAIL), and 0.0.0.0 still receives
  ;; unicast SEDP addressed to 127.0.0.1:port.
  (multiple-value-bind (tr sock)
      (dds.xport.udp:make-udp-transport :host (if multicast "0.0.0.0" host) :port port)
    (let* ((host-uuid (%host-uuid))
           (node (%make-disc-node :guid-prefix guid-prefix :domain domain
                                  :advertise-address advertise-address
                                  :socket sock :transport tr :peers peers
                                  :lease-duration-seconds lease-duration-seconds
                                  :lease-duration-nanosec lease-duration-nanosec
                                  :batch-max-samples batch-max-samples
                                  :capture-data-key-hash (and capture-data-key-hash t)
                                  :crypto-transform crypto-transform
                                  :identity-token-octets identity-token-octets
                                  :on-stateless-message on-stateless-message
                                  :host-uuid host-uuid
                                  :shmem (when *shmem-enabled*   ; SHMEM receive segment for same-host user DATA (FR-XPORT-2)
                                           (dds.xport.shmem:make-shmem-transport
                                            :participant-guid guid-prefix :host-uuid host-uuid
                                            :lane-count +shmem-default-lane-count+ :capacity +shmem-default-capacity+))
                                  :tx-payload (dds.core.buffer:make-octet-buffer *metatraffic-payload-bytes*)
                                  :tx-msg (dds.core.buffer:make-octet-buffer *max-datagram-bytes*)
                                  :rx-tx-msg (dds.core.buffer:make-octet-buffer *max-datagram-bytes*))))
      (when multicast
        (let ((ms (dds.pal:udp-open :host "0.0.0.0"
                                    :port (dds.rtps.message:spdp-multicast-port domain)
                                    :reuse-port t)))
          (dds.pal:udp-join-multicast ms +spdp-multicast-group+)
          (setf (disc-node-mcast-socket node) ms)))
      (when (and *zerocopy-enabled* (disc-node-shmem node))   ; WP-ZEROCOPY writer pool (FR-PF-3, ADR 0014)
        (%zc-make-pool node))
      ;; DDS-Security §9.5.3.3 Slice-1 (ADR 0031): crypto + ZC unsupported — SecuredPayload cannot be applied in-place to a ZC loan.
      (when (and crypto-transform (disc-node-zc-pool node))
        (error "crypto-transform and zero-copy are mutually exclusive in Slice 1 (ADR 0031 known-limitation 4): use one or the other"))
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

(defun* %secure-pm-active-p (node)
    (function (disc-node) boolean)
  "T iff this participant protects the Writer Liveliness Protocol — its governance liveliness_protection_kind
   is non-NONE (the EFFECTIVE base kind SECURE-PM-PROTECTION-KIND, set from governance by the AccessControl
   manager; DDS-Security 1.1 §9.4.1.2.3, T11). When T, EVERY WLP assertion rides the secure
   BuiltinParticipantMessageSecureWriter (0xff0200c2) submessage-protected to the :authenticated peers and
   plain WLP is fully suppressed (no confidential liveliness leak); SPDP advertises bits 20/21. NIL (the
   default) -> plain WLP, byte-identical to the pre-T11 path."
  (not (eq (disc-node-secure-pm-protection-kind node) :none)))

(defun* %node-spdp-data (node)
    (function (disc-node) dds.rtps.discovery:spdp-data)
  "Build NODE's SPDPdiscoveredParticipantData: its GUID prefix + a unicast locator
   at <advertise-address>:<bound port> (default 127.0.0.1), protocol version 2.5. When SHMEM is on, ALSO
   advertise a SHMEM Locator_t (lanes+capacity) in default-unicast and the host-uuid (FR-XPORT-2) so a
   same-host peer can route user DATA over shared memory; metatraffic stays UDP-only (discovery on UDP).
   When the node carries an IdentityToken, ORs in the PSM endpoint-set bits 22/23 (§7.4.6.1) so a
   security-aware peer learns this participant has ParticipantStatelessMessage endpoints (Slice 2b-i).
   When discovery protection is active (discovery-protected-topic-p installed) ORs in the secure SEDP bits
   16-19 (T9) AND the secure SPDP re-announce bits 26/27 (T11, DISC_BUILTIN_ENDPOINT_PARTICIPANT_SECURE_*);
   when liveliness protection is active (%secure-pm-active-p) ORs in the secure participant-message bits 20/21
   (T11). All default off -> byte-identical SPDP (the Slice 2c/4 baseline)."
  (let* ((addr (dds.rtps.discovery:make-ipv4-locator
                (%ipv4-octets (disc-node-advertise-address node))))
         (port (disc-node-port node))
         (loc (dds.rtps.discovery:make-locator
               :kind dds.rtps.discovery:+locator-kind-udpv4+ :port port :address addr))
         (sm (disc-node-shmem node))
         (tok (disc-node-identity-token-octets node))
         ;; OR PSM bits 22/23 when we carry an IdentityToken (Slice 2b-i); secure SEDP bits 16-19 + secure SPDP
         ;; re-announce bits 26/27 when discovery protection is active (T9/T11); secure participant-message bits
         ;; 20/21 when liveliness protection is active (T11; DDS-Security 1.1 §7.4.6.1); PVMS bits 24/25 when the
         ;; reliable ParticipantVolatileMessageSecure crypto-token endpoint is enabled (Slice-5 T5). All default
         ;; off -> byte-identical SPDP (the Slice 2c/4 baseline).
         (ep-set (logior dds.rtps.discovery:+builtin-endpoint-set-default+
                         (if tok
                             (logior dds.rtps.discovery:+be-participant-stateless-writer+
                                     dds.rtps.discovery:+be-participant-stateless-reader+)
                             0)
                         (if (disc-node-discovery-protected-topic-p node)
                             (logior dds.rtps.discovery:+be-sedp-pub-secure-writer+
                                     dds.rtps.discovery:+be-sedp-pub-secure-reader+
                                     dds.rtps.discovery:+be-sedp-sub-secure-writer+
                                     dds.rtps.discovery:+be-sedp-sub-secure-reader+
                                     dds.rtps.discovery:+be-participant-secure-announcer+
                                     dds.rtps.discovery:+be-participant-secure-detector+)
                             0)
                         (if (%secure-pm-active-p node)
                             (logior dds.rtps.discovery:+be-participant-message-secure-writer+
                                     dds.rtps.discovery:+be-participant-message-secure-reader+)
                             0)
                         ;; §7.4.6.1 / §9.5.3.1: advertise PVMS bit 24/25 iff the endpoint exists, so a peer matches
                         ;; PVMS and exchanges crypto tokens (Fast DDS SecurityManager.cpp builtin_endpoints +
                         ;; match_builtin_key_exchange_endpoints gate matching on these bits — without them no tokens flow)
                         (if (disc-node-pvms-writer node) dds.rtps.discovery:+be-participant-volatile-secure-writer+ 0)
                         (if (disc-node-pvms-reader node) dds.rtps.discovery:+be-participant-volatile-secure-reader+ 0))))
    (dds.rtps.discovery:make-spdp-data
     :guid-prefix (disc-node-guid-prefix node)
     :version-major 2 :version-minor 5
     :vendor-id dds.rtps.message:*vendor-id*
     :default-unicast-locators (if sm
                                   (list loc (dds.rtps.discovery:make-shmem-locator-wire +shmem-default-lane-count+ +shmem-default-capacity+))
                                   (list loc))
     :metatraffic-unicast-locators (list loc)
     :host-uuid (if sm (disc-node-host-uuid node) 0)
     :lease-duration-seconds (disc-node-lease-duration-seconds node)
     :lease-duration-nanosec (disc-node-lease-duration-nanosec node)
     :builtin-endpoint-set ep-set
     :identity-token-octets tok)))

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
   via assert-participant-liveliness).
   T11: the PLAIN SPDP always sends (the bootstrap channel — it carries the Identity/Permissions tokens a peer
   needs to authenticate). When discovery protection is active AND peers are :keyed, ALSO re-announce the same
   ParticipantBuiltinTopicData over the secure SPDP writer (0xff0101c2) submessage-protected
   (%announce-secure-spdp); a no-op otherwise (security OFF -> byte-identical)."
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
  (%announce-secure-spdp node)   ; T11: protected re-announce over secure SPDP (off plain; no-op when security OFF)
  t)

(defun* %qos-from-reliability (reliability)
    (function (integer) dds.qos:qos)
  "Build a QoS from a legacy wire reliability constant (back-compat for callers that
   pass :reliability rather than a full :qos)."
  (dds.qos:make-qos :reliability (if (>= reliability dds.rtps.discovery:+reliability-reliable+)
                                     :reliable :best-effort)))

(defun* %protection-kind-max (a b)
    (function ((member :unset :none :sign :encrypt) (member :unset :none :sign :encrypt))
              (member :unset :none :sign :encrypt))
  "ADR 0046: the MORE-protective of two protection kinds (rank :encrypt>:sign>:none>:unset). Used to keep the
   participant-scope shared user-{data,submessage}-protection-kind slots at the MONOTONIC MAX over both roles, so the
   datagram fast-skip gate / ZC-loan wire-protection guards never skip a wrap or admit plaintext while ANY live role
   is protected (conservative, fail-closed; the actual per-role action is decided from the per-role fields)."
  (flet ((rank (k) (ecase k (:unset 0) (:none 1) (:sign 2) (:encrypt 3))))
    (if (>= (rank a) (rank b)) a b)))

(defun* %refine-user-protection (node topic role)
    (function (disc-node string (member :writer :reader)) t)
  "DDS-Security 1.1 §9.4.1.2.4 (ADR 0046): resolve+cache ROLE's (the WRITER's or the READER's) OWN per-topic
   metadata_protection AND data_protection from TOPIC via the resolvers installed by %install-access-control, into the
   PER-ROLE fields (user-{writer,reader}-{data,submessage}-protection-kind) — so add-local-writer gates the writer and
   add-local-reader the reader by ITS topic's REAL rule, independently: adding a reader never lowers the writer's kind
   (the cross-role false-ACCEPT downgrade is eliminated by construction). Neither the first-rule participant-default
   downgrade (a later SIGN/ENCRYPT topic wrongly left :none = false-ACCEPT) nor over-protection of a genuine
   metadata/data=NONE topic (false-REJECT). The shared user-{data,submessage}-protection-kind slots are kept at the
   MONOTONIC MAX over both roles for the participant-scope consumers only. No resolver (security OFF / no governance)
   leaves every slot unchanged (byte-identical to the pre-security path). Returns T."
  (let ((mresolver (disc-node-topic-metadata-protection-resolver node))
        (dresolver (disc-node-topic-data-protection-resolver node)))
    (when mresolver
      (let ((k (funcall mresolver topic)))
        (ecase role
          (:writer (setf (disc-node-user-writer-submessage-protection-kind node) k))
          (:reader (setf (disc-node-user-reader-submessage-protection-kind node) k)))
        (setf (disc-node-user-submessage-protection-kind node)
              (%protection-kind-max (disc-node-user-writer-submessage-protection-kind node)
                                    (disc-node-user-reader-submessage-protection-kind node)))))
    (when dresolver
      (let ((k (funcall dresolver topic)))
        (ecase role
          (:writer (setf (disc-node-user-writer-data-protection-kind node) k))
          (:reader (setf (disc-node-user-reader-data-protection-kind node) k)))
        (setf (disc-node-user-data-protection-kind node)
              (%protection-kind-max (disc-node-user-writer-data-protection-kind node)
                                    (disc-node-user-reader-data-protection-kind node)))))
    ;; WP-N-ENDPOINT-S3 (ADR 0048): also cache THIS endpoint's (data . submessage) kinds keyed by its EntityId, so N
    ;; secured writers each key from their OWN topic. Reads back the just-set per-role slots (DRY, authoritative). The
    ;; entity-id is current (add-local-{writer,reader} set user-{writer,reader}-id just before calling here).
    (when (or mresolver dresolver)
      (ecase role
        (:writer (setf (gethash (disc-node-user-writer-id node) (disc-node-user-endpoint-protection-kind node))
                       (cons (disc-node-user-writer-data-protection-kind node)
                             (disc-node-user-writer-submessage-protection-kind node))))
        (:reader (setf (gethash (disc-node-user-reader-id node) (disc-node-user-endpoint-protection-kind node))
                       (cons (disc-node-user-reader-data-protection-kind node)
                             (disc-node-user-reader-submessage-protection-kind node)))))))
  t)

(defun* %user-endpoint-kinds (node entity-id)
    (function (disc-node (unsigned-byte 32))
              (values (member :unset :none :sign :encrypt) (member :none :sign :encrypt) boolean))
  "WP-N-ENDPOINT-S3 / ADR 0046: the (values DATA-PROTECTION-KIND SUBMESSAGE-PROTECTION-KIND USERP) of the LOCAL user
   endpoint ENTITY-ID — from the per-endpoint map (populated per endpoint at add-local from its OWN topic), with a
   role-slot fallback for N=1 / no-map (byte-identical to the pre-S3 per-role slots). USERP (3rd value) is T iff
   ENTITY-ID is a known local user endpoint (a map entry OR the primary writer/reader id) — NIL for a builtin /
   unknown id (the caller then uses its non-user default). The send-crux (publish-sample) reads the DATA kind for the
   publishing writer; %cm-entity-protection-kind derives each endpoint's km kind from both."
  (let ((c (gethash entity-id (disc-node-user-endpoint-protection-kind node))))
    (cond (c (values (car c) (cdr c) t))
          ((= entity-id (disc-node-user-writer-id node))
           (values (disc-node-user-writer-data-protection-kind node)
                   (disc-node-user-writer-submessage-protection-kind node) t))
          ((= entity-id (disc-node-user-reader-id node))
           (values (disc-node-user-reader-data-protection-kind node)
                   (disc-node-user-reader-submessage-protection-kind node) t))
          (t (values :unset :none nil)))))

(defun* add-local-writer (node &key (topic "") (type "")
                                   (reliability dds.rtps.discovery:+reliability-reliable+)
                                   (key nil) qos type-information (keyed t) (enabled t))
    (function (disc-node &key (:topic string) (:type string) (:reliability integer) (:key (or null (unsigned-byte 8))) (:qos t) (:type-information t) (:keyed t) (:enabled t)) dds.rtps.discovery:endpoint-data)
  "Register a local publication (writer endpoint) on NODE with QOS (or a QoS derived from
   the legacy :reliability constant). TYPE-INFORMATION is the opaque serialized XTypes
   TypeInformation for PID_TYPE_INFORMATION. announce-endpoints sends it via SEDP. KEYED
   selects the RTPS entity kind (RTPS 2.5 §9.3.1.2 Table 9.1): T (default) -> 0x02 (writer
   WITH_KEY), NIL -> 0x03 (writer NO_KEY); a keyed remote reader (RTI Connext) will not
   match a no-key writer. KEY (NIL default) draws the next DISTINCT per-participant entity KEY
   (WP-N-ENDPOINT-S1, ADR 0048) so a 2nd/N-th DataWriter gets a distinct EntityId + SEDP GUID
   (the first stays #x0102/#x0103, byte-identical); pass an explicit KEY to pin it. Sets NODE's
   user-writer-id so enable-publisher registers + the data plane sends with this id.
   WP-N-ENDPOINT-2C2 (ADR 0048): a 2nd/N-th SAME-topic user DataWriter — SECURED or RETAINING-durability
   (TRANSIENT_LOCAL/TRANSIENT/PERSISTENT) — now REGISTERS (fences B + C lifted). %match-remote-endpoint fires
   the match PER matched local writer keyed by the per-(local,remote) pair, so each same-topic writer gets its
   OWN PUBLICATION_MATCHED, its OWN §8.5.2 crypto-token re-exchange keyed to its OWN EntityId (each secured
   writer's DW CryptoToken carries its OWN km/sender_key_id), and its OWN durability match-side replay
   (%writer-durability-init/%prearm with ITS writer-id). Distinct EntityIds/GUIDs on the wire are correct
   (RTPS 2.5 §9.3.1.2). Byte-identical at N=1 / distinct topics."
  (let ((wqos (or qos (%qos-from-reliability reliability))))
    (let* ((key (or key (%alloc-user-writer-key node)))
           (kind (if keyed #x02 #x03))
           (ep (dds.rtps.discovery:make-endpoint-data
                :role :writer
                :guid (%make-endpoint-guid (disc-node-guid-prefix node) key kind)
                :topic-name topic :type-name type :type-information type-information
                :qos wqos)))
      (setf (disc-node-user-writer-id node) (logior (ash key 8) kind))
      (%refine-user-protection node topic :writer)   ; ADR 0046 §9.4.1.2.4: cache the WRITER's OWN per-topic metadata + data protection (cross-role downgrade fix)
      (unless enabled   ; ADR 0060: created-disabled -> registered but NOT announced/matched until enable-local-endpoint
        (setf (gethash (%guid-entityid (dds.rtps.discovery:endpoint-data-guid ep))
                       (disc-node-unenabled-endpoints node)) t))
      (push ep (disc-node-local-writers node))
      ep)))

(defun* add-local-reader (node &key (topic "") (type "")
                                   (reliability dds.rtps.discovery:+reliability-best-effort+)
                                   (key nil) qos type-information (keyed t) (enabled t))
    (function (disc-node &key (:topic string) (:type string) (:reliability integer) (:key (or null (unsigned-byte 8))) (:qos t) (:type-information t) (:keyed t) (:enabled t)) dds.rtps.discovery:endpoint-data)
  "Register a local subscription (reader endpoint) on NODE with QOS (or a QoS derived from
   the legacy :reliability constant). TYPE-INFORMATION is the opaque serialized XTypes
   TypeInformation for PID_TYPE_INFORMATION. announce-endpoints sends it via SEDP. KEYED
   selects the RTPS entity kind (RTPS 2.5 §9.3.1.2 Table 9.1): T (default) -> 0x07 (reader
   WITH_KEY), NIL -> 0x04 (reader NO_KEY); a keyed reader will not match a no-key remote
   writer (and vice versa) — the disagreement is a silent non-match, not INCONSISTENT_TOPIC.
   KEY (NIL default) draws the next DISTINCT per-participant entity KEY (WP-N-ENDPOINT-S2, ADR 0048)
   so a 2nd/N-th DataReader gets a distinct EntityId + SEDP GUID (the first stays #x0107/#x0104,
   byte-identical); pass an explicit KEY to pin it. Sets NODE's user-reader-id so enable-subscriber
   registers + the data plane routes HEARTBEAT/ACKNACK with this id.
   WP-N-ENDPOINT-2C1 (ADR 0048): a 2nd NON-loan-capable reader on a topic ALREADY held by a local reader on this
   participant now REGISTERS (fence A lifted for the non-loan case). %match-remote-endpoint route-adds ALL matching
   local readers per remote-writer GUID (route-add-all — the source-GUID route holds a LIST), so BOTH same-topic
   readers are routed and each drains W's full stream over its OWN per-reader dr-drained high-water (no cross-
   consumption). Two DIFFERENT-topic readers still each match their own writer (distinct GUIDs).
   WP-N-ENDPOINT-2C3 (ADR 0017/0048): the LAST same-topic fence is LIFTED — a 2nd SAME-topic LOAN-CAPABLE
   (secured-decode / zero-copy) reader now REGISTERS with a distinct EntityId. The ADR-0017 cross-reader
   use-after-free is closed at its true site: the ZC demux-time refcount bump (%deliver-user-marker counts all K
   co-located holders before any drain/release), the mid-stream-joiner ZC high-water freeze (create-datareader), and
   the secured store-purge-defer (%secured-loan-release, purge only after all K readers return). This whole
   participant-with-N-same-topic-loan-capable-readers case is now correct in full generality."
  (let* ((key (or key (%alloc-user-reader-key node)))
         (kind (if keyed #x07 #x04))
         (ep (dds.rtps.discovery:make-endpoint-data
              :role :reader
              :guid (%make-endpoint-guid (disc-node-guid-prefix node) key kind)
              :topic-name topic :type-name type :type-information type-information
              :qos (or qos (%qos-from-reliability reliability)))))
    (setf (disc-node-user-reader-id node) (logior (ash key 8) kind))
    (%refine-user-protection node topic :reader)   ; ADR 0046 §9.4.1.2.4: cache the READER's OWN per-topic metadata + data protection (cross-role downgrade fix)
    (unless enabled   ; ADR 0060: created-disabled -> registered but NOT announced/matched until enable-local-endpoint
      (setf (gethash (%guid-entityid (dds.rtps.discovery:endpoint-data-guid ep))
                     (disc-node-unenabled-endpoints node)) t))
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

(defun* %local-user-writer-id-for-topic (node topic)
    (function (disc-node string) (or null (unsigned-byte 32)))
  "The EntityId of NODE's local user WRITER on TOPIC (WP-N-ENDPOINT-S3, ADR 0048), or NIL. Resolves the matched
   local writer for a :remote-reader match so cm-on-endpoint-match re-sends THAT writer's OWN §8.5.2.2 DW CryptoToken
   (source = its EntityCrypto) keyed to the matched remote — not the node-single writer id. NIL (no local writer on
   TOPIC) -> the node-single fallback (byte-identical N=1). Uses %guid-entityid (declaimed above; defined in
   dataplane.lisp)."
  (let ((ep (find topic (disc-node-local-writers node)
                  :key #'dds.rtps.discovery:endpoint-data-topic-name :test #'string=)))
    (and ep (%guid-entityid (dds.rtps.discovery:endpoint-data-guid ep)))))

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

;; User-vs-builtin writer-EntityId classifier (T10 receive enforcement): defined in dataplane.lisp (loaded after this file).
(declaim (ftype (function ((unsigned-byte 32)) t) %user-writer-entityid-p))

;; WP-N-ENDPOINT-S2: %guid-entityid / node-secured-reader-p are defined in dataplane.lisp (loaded after this file);
;; forward-declared so %match-remote-endpoint (route-add) and %register-user-reader (route-add-all; no same-topic fail-fast — S6) reach them clean.
(declaim (ftype (function ((simple-array (unsigned-byte 8) (16))) (unsigned-byte 32)) %guid-entityid))
(declaim (ftype (function (disc-node) boolean) node-secured-reader-p))

;; %lease-sweep is defined below but called from announce-endpoints above it.
(declaim (ftype (function (disc-node) (eql t)) %lease-sweep))

;; WP-DDS-SECURITY-ZEROALLOC-AEAD T5b: defined in dataplane.lisp (loaded after this file); forward-declared so
;; stop-node releases every outstanding secured loan (returns its pooled buffer to the pool) before teardown-arena.
(declaim (ftype (function (disc-node) t) node-return-all-loans))

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

;; Slice 2b-i PSM handler: defined in stateless-message.lisp (loaded after this file).
(declaim (ftype (function (disc-node (simple-array (unsigned-byte 8) (12)) (unsigned-byte 32) integer dds.core.buffer:octet-buffer (integer 0) (integer 0)) t) %on-stateless-message)
         (ftype (function (disc-node (simple-array (unsigned-byte 8) (12)) (simple-array (unsigned-byte 8) (*))) t) %send-stateless-message))

;; Slice 4 PVMS handlers: defined in volatile-secure.lisp (loaded after this file).
(declaim (ftype (function (disc-node (simple-array (unsigned-byte 8) (12)) (simple-array (unsigned-byte 8) (*))) t) %on-volatile-secure)
         (ftype (function (disc-node (simple-array (unsigned-byte 8) (12)) integer integer) t) %on-pvms-heartbeat)
         (ftype (function (disc-node (simple-array (unsigned-byte 8) (12)) dds.core.buffer:cursor (unsigned-byte 8)) t) %on-pvms-acknack)
         ;; ADR-0036/0040 carry: PVMS bootstrap-KM peer-loss prune, called by %lease-sweep (below).
         (ftype (function (disc-node (simple-array (unsigned-byte 8) (12))) (or null dds.security:key-material)) %prune-pvms-bootstrap-km))

;; Slice 4 (T9/T11) secure builtin endpoints: defined in secure-sedp.lisp (loaded after this file).
;; %on-secure-submessage is the SEC_PREFIX dispatcher %handle-datagram routes to (it now routes secure SEDP +
;; secure participant-message + secure SPDP by the recovered inner writerId, T11). %announce-secure-endpoints is
;; the protected SEDP announce; %announce-secure-liveliness the protected WLP announce (called from
;; assert-participant-liveliness); %announce-secure-spdp the protected SPDP re-announce (called from
;; announce-participant). All no-op when security is OFF (byte-identical).
(declaim (ftype (function (disc-node (simple-array (unsigned-byte 8) (12)) (simple-array (unsigned-byte 8) (*)) fixnum t) t) %on-secure-submessage)
         (ftype (function (disc-node) (eql t)) %announce-secure-endpoints
                %announce-secure-liveliness %announce-secure-spdp %send-secure-builtin-heartbeats))

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

(defun* %endpoint-enabled-p (node ep)
    (function (disc-node dds.rtps.discovery:endpoint-data) boolean)
  "T iff local endpoint EP is ENABLED, i.e. it may communicate (DDS 1.4 §2.2.2.1.1.7). An endpoint created under
   a factory whose ENTITY_FACTORY autoenable_created_entities is FALSE is registered with the engine but stays
   UNENABLED until enable() — it must not be SEDP-announced and must not match a remote, or a disabled entity
   would communicate. Default (autoenable on) -> the table is empty -> T for everything, byte-identical."
  (not (gethash (%guid-entityid (dds.rtps.discovery:endpoint-data-guid ep))
                (disc-node-unenabled-endpoints node))))

(defun* enable-local-endpoint (node entity-id)
    (function (disc-node (unsigned-byte 32)) (eql t))
  "Mark the local endpoint ENTITY-ID ENABLED (DDS 1.4 §2.2.2.1.1.7) — from now on announce-endpoints SEDP-
   announces it and %match-remote-endpoint may match it. Called by the DCPS enable() on a DataWriter/DataReader
   that was created disabled. Idempotent; enabling is monotonic (DDS has no disable)."
  (remhash entity-id (disc-node-unenabled-endpoints node))
  t)

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
  ;; T9: partition local endpoints — discovery-PROTECTED topics flow ONLY over secure SEDP
  ;; (%announce-secure-endpoints, below); the UNPROTECTED complement flows over plain SEDP here. With no
  ;; discovery protection (the predicate is NIL) PLAIN-WRITERS/READERS are the full add-order lists -> the
  ;; plain SEDP announce is byte-identical to today. Each SEDP writer's SN space is its OWN subset's 1-based
  ;; index, so the protected/unprotected split keeps every per-writer SN stable (RTPS 2.5 §8.5.4).
  ;; ADR 0060: a created-DISABLED endpoint is registered with the engine but must NOT be announced — a disabled
  ;; entity does not communicate (DDS 1.4 §2.2.2.1.1.7). Filter FIRST, so both the plain and the secure SEDP
  ;; announce see the enabled set. Empty unenabled-table (the autoenable default) -> the full add-order lists.
  (let* ((protp (disc-node-discovery-protected-topic-p node))
         (enabled-writers (remove-if-not (lambda (w) (%endpoint-enabled-p node w))
                                         (reverse (disc-node-local-writers node))))
         (enabled-readers (remove-if-not (lambda (r) (%endpoint-enabled-p node r))
                                         (reverse (disc-node-local-readers node))))
         (plain-writers (if protp
                            (remove-if (lambda (w) (funcall protp (dds.rtps.discovery:endpoint-data-topic-name w)))
                                       enabled-writers)
                            enabled-writers))
         (plain-readers (if protp
                            (remove-if (lambda (r) (funcall protp (dds.rtps.discovery:endpoint-data-topic-name r)))
                                       enabled-readers)
                            enabled-readers)))
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
          (loop for w in plain-writers for wsn from 1 do
            (%send-endpoint node
                            dds.rtps.discovery:+entityid-sedp-pub-reader+
                            dds.rtps.discovery:+entityid-sedp-pub-writer+
                            w wsn host port))
          (loop for r in plain-readers for rsn from 1 do
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
                               nil host port))))))))) ; close: dolist p + the plain/secure-partition let*
  (%announce-secure-endpoints node)   ; T9: protected DiscoveredWriter/ReaderData over secure SEDP (off plain SEDP)
  (tl-sweep node)
  (%lease-sweep node)
  (%liveliness-sweep node)
  (flush-batch node)        ; WP-BATCH time trigger: flush a partial batch on the announce cadence
  (%push-heartbeat node)
  (%pvms-push-heartbeats-all node)   ; T8: drive reliable PVMS crypto-token delivery + repair to keyed peers
  (%send-secure-builtin-heartbeats node)   ; T9pull: solicit a reliable peer's ACKNACK of OUR secure-SEDP endpoints
  t)

(defun* %lease-now ()
    (function () (integer 0))
  "Monotonic internal-real-time stamp for lease/liveliness bookkeeping."
  (get-internal-real-time))

(defun* %lease-stale-p (last-seen lease-seconds now)
    (function (integer real (integer 0)) t)
  "T iff LAST-SEEN is older than LEASE-SECONDS before NOW — the SPDP HistoryCache
   stale-entry test (RTPS 2.5 §8.5.3.3.2: not refreshed within its leaseDuration).
   LEASE-SECONDS is a REAL (a peer may announce a sub-second Duration_t fraction)."
  (> (- now last-seen) (* lease-seconds internal-time-units-per-second)))

(defun* %spdp-lease-seconds (spdp)
    (function (dds.rtps.discovery:spdp-data) real)
  "A discovered peer's announced leaseDuration as SECONDS, whole + fractional (RTPS 2.5 §9.3.2.3
   Duration_t {seconds, fraction}). The fraction is load-bearing: truncating it would read a peer's
   sub-second lease as 0 and prune a perfectly live peer on the next sweep (a false REJECT)."
  (+ (dds.rtps.discovery:spdp-data-lease-duration-seconds spdp)
     (/ (dds.rtps.discovery:spdp-data-lease-duration-nanosec spdp) 1000000000)))

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
      (let ((hook nil))
        (dds.pal:with-lock ((disc-node-lock node))
          (let ((key (copy-seq prefix)))
            (setf (gethash key (disc-node-discovered node)) spdp)
            (setf (gethash key (disc-node-participant-last-seen node)) (%lease-now))
            (%invalidate-shmem-dest node prefix)
            ;; Fire ON-PARTICIPANT-DISCOVERED for a SECURITY-enabled peer on EVERY SPDP (first +
            ;; re-announce), not only first discovery: the §8.7 handshake rides the best-effort
            ;; ParticipantStatelessMessage, so the auth manager uses the re-announce cadence to
            ;; RETRANSMIT a request the replier may have missed (idempotent for an already-recorded /
            ;; authenticated remote). A plain (no-IdentityToken) peer is unaffected — the hook is
            ;; installed only for a security-enabled participant.
            (when (dds.rtps.discovery:spdp-data-identity-token-octets spdp)
              (setf hook (disc-node-on-participant-discovered node)))))
        (when hook
          (funcall hook node prefix spdp))))))

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

(defun* %fire-unmatch (node direction remote local-entity-id)
    (function (disc-node keyword dds.rtps.discovery:endpoint-data (or null (unsigned-byte 32))) t)
  "Invoke the ON-UNMATCH hook (if installed) OUTSIDE the node lock for a REMOTE endpoint
   unmatched by participant-lease expiry (DIRECTION :remote-writer / :remote-reader).
   WP-N-ENDPOINT-2C2 (ADR 0048): LOCAL-ENTITY-ID is the matched LOCAL endpoint's EntityId (from the
   per-pair match set), threaded so the status DECREMENT lands on the RIGHT same-topic endpoint; fired
   once per (local,remote) pair. NIL -> the hook falls back to topic resolution (byte-identical N=1)."
  (when (disc-node-on-unmatch node)
    (funcall (disc-node-on-unmatch node) direction remote local-entity-id)))

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

(defun* %purge-reader-join-watermarks (node prefix)
    (function (disc-node (simple-array (unsigned-byte 8) (12))) t)
  "WP-N-ENDPOINT-2C3 (ADR 0048/0017): drop every ZC-joiner high-water whose remote writer GUID prefix equals PREFIX
   (a lost / lease-expired participant), across EVERY local reader's inner table, and prune a now-empty inner table.
   CALLER HOLDS the node lock. Mirrors the reader-routes purge (%purge-prefix) but reader-join-watermarks is keyed
   by the LOCAL reader EntityId at the outer level and the remote writer GUID at the INNER level, so the prefix match
   is on the inner keys. Correct (never a UAF): the watermark only ever RAISES the drain-gate, so a stale entry can
   at worst make a reader SKIP a marker it should get (bounded sample-loss); purging it on unmatch/lease-expiry both
   (a) bounds the table (per-(reader,writer) entries stop accumulating as entity-ids advance) and (b) lets a
   same-GUID re-announce RE-FREEZE the watermark to the current max stored SN via the match-time %reader-route-add
   freeze — restoring correct gating with no stale-gate loss."
  (let ((outer (disc-node-reader-join-watermarks node)) (dead-readers '()))
    (maphash (lambda (rid inner)
               (let ((dead '()))
                 (maphash (lambda (guid sn)
                            (declare (ignore sn))
                            (when (%guid-prefix-match-p guid prefix) (push guid dead)))
                          inner)
                 (dolist (g dead) (remhash g inner))
                 (when (zerop (hash-table-count inner)) (push rid dead-readers))))
             outer)
    (dolist (rid dead-readers) (remhash rid outer)))
  t)

(defun* %collect-and-remove-matches (node prefix removed-place)
    (function (disc-node (simple-array (unsigned-byte 8) (12)) function) t)
  "Remove every match whose remote GUID prefix equals PREFIX, classify its direction
   from the GUID entity kind (a removed remote WRITER -> :remote-writer, READER ->
   :remote-reader; RTPS 2.5 §9.3.1.2 Table 9.1 via %writer-guid-p/%reader-guid-p), and push
   (direction remote . local-entity-id) via REMOVED-PLACE. CALLER HOLDS the node lock.
   WP-N-ENDPOINT-2C2 (ADR 0048): fire ONE unmatch entry PER matched (local,remote) PAIR (from
   DISC-NODE-MATCH-PAIRS) so the status DECREMENT lands on the RIGHT same-topic endpoint(s); a remote
   with no recorded pair (direct-injected match) fires one entry with LOCAL-ENTITY-ID NIL (topic fallback)."
  (let ((table (disc-node-matches node)) (pairs (disc-node-match-pairs node)) (dead '()))
    (maphash (lambda (guid remote)
               (when (%guid-prefix-match-p guid prefix)
                 (push (cons guid remote) dead)))
             table)
    (dolist (entry dead)
      (let* ((key (car entry))
             (remote (cdr entry))
             (guid (dds.rtps.discovery:endpoint-data-guid remote))
             (direction (cond ((%writer-guid-p guid) :remote-writer)
                              ((%reader-guid-p guid) :remote-reader)
                              (t :remote-writer)))
             (eids (gethash key pairs)))
        (remhash key table)
        (remhash key pairs)
        (if eids
            (dolist (eid eids) (funcall removed-place (list* direction remote eid)))
            (funcall removed-place (list* direction remote nil))))))
  t)

(defun* %lease-sweep (node)
    (function (disc-node) (eql t))
  "Prune every discovered participant whose SPDP last-seen is older than its announced
   leaseDuration (RTPS 2.5 §8.5.3.3.2 — the SPDPbuiltinParticipantReader removes stale
   entries): under the node lock remove its discovered entry, last-seen, builtin-reader,
   every discovered-writers/readers endpoint + match keyed by that 12-octet prefix,
   collecting the removed MATCHED endpoints; then fire on-unmatch per removed match
   OUTSIDE the lock. Idempotent (a re-announced participant re-adds)."
  (let ((removed '()) (lost '()))
    (dds.pal:with-lock ((disc-node-lock node))
      (let ((now (%lease-now)) (dead '()))
        (maphash (lambda (prefix spdp)
                   (let ((ls (gethash prefix (disc-node-participant-last-seen node))))
                     (when (and ls (%lease-stale-p ls (%spdp-lease-seconds spdp) now))
                       (push prefix dead))))
                 (disc-node-discovered node))
        (dolist (prefix dead)
          (remhash prefix (disc-node-discovered node))
          (remhash prefix (disc-node-participant-last-seen node))
          (remhash prefix (disc-node-builtin-readers node))
          (remhash prefix (disc-node-auth-state node))
          (%invalidate-shmem-dest node prefix)   ; a leased-out peer's cached SHMEM dest must not be reused
          (%purge-prefix node prefix #'disc-node-discovered-writers)
          (%purge-prefix node prefix #'disc-node-discovered-readers)
          (%purge-prefix node prefix #'disc-node-reader-routes)   ; WP-N-ENDPOINT-S2 (ADR 0048): drop the lost writer's delivery route (unmatch/lease-expiry) so a reader stops draining a gone writer; a re-announce re-adds it
          (%purge-reader-join-watermarks node prefix)   ; WP-N-ENDPOINT-2C3 (ADR 0048): drop the lost writer's ZC-joiner high-waters alongside the route (bounds the table; a re-announce re-freezes the watermark via the match-time route-add so a lease-flap never leaves a stale drain-gate = sample-loss)

          (%purge-prefix node prefix #'disc-node-decode-fail-counts)   ; ADR 0031 lim.1: drop the lost writer's decode-failure counters
          (%purge-prefix node prefix #'disc-node-incompat)         ; WP-DDS-INCOMPAT-QOS-PERPAIR (ADR 0048 §16.3): drop the lost peer's INCOMPATIBLE_QOS presence
          (%purge-prefix node prefix #'disc-node-incompat-pairs)   ; ...and its per-pair fire set (an incompatible remote is NOT in disc-node-matches, so it needs its OWN prefix-purge — %collect-and-remove-matches only covers matched remotes); a re-discovery re-fires + the tables stay bounded
          (%purge-prefix node prefix #'disc-node-inconsistent)     ; WP-DDS-INCOMPAT-QOS-PERPAIR F1b: drop the lost peer's INCONSISTENT_TOPIC gate too (pre-existing stuck-gate, now symmetric with incompat) so a re-discovered inconsistent remote re-fires
          (%collect-and-remove-matches node prefix
                                       (lambda (dm) (push dm removed)))
          (push prefix lost))))   ; ADR-0034 MINOR-4: fire on-participant-lost per dead peer OUTSIDE the lock
    (dolist (dm removed) (%fire-unmatch node (car dm) (cadr dm) (cddr dm)))
    (dolist (prefix lost)
      (%prune-pvms-bootstrap-km node prefix)   ; ADR-0036/0040: prune the lost peer's PVMS bootstrap KM (disc-internal)
      (when (disc-node-on-participant-lost node)
        (funcall (disc-node-on-participant-lost node) prefix)))   ; ADR-0034: drop the lost peer's crypto-manager KMs
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

(defun* %record-match-pair (node remote local-entity-id)
    (function (disc-node dds.rtps.discovery:endpoint-data (unsigned-byte 32)) boolean)
  "WP-N-ENDPOINT-2C2 (ADR 0048): record a matched (LOCAL-ENTITY-ID, REMOTE) PAIR in DISC-NODE-MATCH-PAIRS
   (remote 16-octet GUID -> list of matched local EntityIds, lock-guarded). Returns T only the FIRST time
   THIS pair is recorded, so the per-endpoint MATCHED status/crypto/durability fires once per (local,remote)
   pair and NOT again on a SEDP RE-ANNOUNCE. disc-node-matches (per-remote presence) is recorded separately,
   so matched-count / the HEARTBEAT gate are unchanged. At N=1 one local per remote -> per-pair == per-remote
   (byte-identical)."
  (dds.pal:with-lock ((disc-node-lock node))
    (let* ((key (copy-seq (dds.rtps.discovery:endpoint-data-guid remote)))
           (eids (gethash key (disc-node-match-pairs node))))
      (if (member local-entity-id eids :test #'=)
          nil
          (progn (setf (gethash key (disc-node-match-pairs node)) (cons local-entity-id eids)) t)))))

(defun* %guid-matched-p (node guid)
    (function (disc-node (simple-array (unsigned-byte 8) (16))) t)
  "T iff the 16-octet GUID is a MATCHED remote endpoint (lock-guarded peek of DISC-NODE-MATCHES, equalp-keyed,
   RTPS 2.5 §9.4.4). WP-ACKNACK-MATCH-GATE — two uses: (1) the reader-side HEARTBEAT match gate in
   %on-user-heartbeat / %on-user-heartbeat-frag (RTPS 2.5 §8.4.10.1: a StatefulReader processes a writer's
   HEARTBEAT — and answers with an ACKNACK / NACK_FRAG — only for a MATCHED writer, so a pre-match user
   HEARTBEAT never creates a WriterProxy nor NACKs pre-join history before the on-match durability baseline,
   DDS 1.4 §2.2.3.4, is armed); (2) FIRST-match gating of the writer-side durability pre-arm below."
  (dds.pal:with-lock ((disc-node-lock node))
    (nth-value 1 (gethash guid (disc-node-matches node)))))

(defun* %prearm-writer-future-base (node reader-guid &optional writer-id)
    (function (disc-node (simple-array (unsigned-byte 8) (16)) &optional (or null (unsigned-byte 32))) (eql t))
  "WP-ACKNACK-MATCH-GATE (DDS 1.4 §2.2.3.4; RTPS 2.5 §8.4.2.2 / §8.4.10.1): FUTURE-only-base the reliable
   writer's ReaderProxy for a newly-matched remote READER (READER-GUID) BEFORE the match is RECORDED — i.e.
   before %reader-push-targets can make the reader a push destination — closing the symmetric writer-side
   window in which a concurrent publish racing the match would replay pre-join history from the default
   UNSENT-BASE 1 to a VOLATILE reader. Sets ONLY UNSENT-BASE = lastSN+1 (deadlock-proof: the engine arms it
   itself, never waiting on the external hook; the WRITER-HEARTBEAT snapshot read intentionally bumps
   HB-COUNT — a benign gap, Count need only be monotonic per RTPS 2.5 §8.3.7.5); the durability-aware on-match hook
   (%writer-durability-init) then REFINES it (a TL<->TL match to firstSN for late-joiner replay; the
   ACKNACK-repair path replays independently of UNSENT-BASE, so TL replay stays intact even though the base
   starts future-only). WP-N-ENDPOINT-S2B (ADR 0048): WRITER-ID selects the MATCHED local writer (the one whose
   topic RxO-matched this reader), so the prearm and the durability-init REFINE the SAME (writer,reader) proxy
   base — never the primary when the match is on an N-th durable writer; NIL (or unregistered) -> the primary
   (byte-identical N=1). The CALLER first-match-gates this (%guid-matched-p) so a re-announce never re-futures
   past unsent LIVE samples. A no-op (still T) with no user writer — the discovery-less/no-hook path is not
   pre-armed by the caller and keeps the default UNSENT-BASE 1 push-all (byte-identical)."
  (let ((w (%resolve-user-writer node writer-id)))
    (when w
      (multiple-value-bind (first last count) (dds.rtps.reliable:writer-heartbeat w)
        (declare (ignore first count))
        (dds.rtps.reliable:init-reader-proxy-base w (copy-seq reader-guid) (1+ last)))))
  t)

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

(defun* %record-incompat-pair (node remote local-entity-id)
    (function (disc-node dds.rtps.discovery:endpoint-data (unsigned-byte 32)) boolean)
  "WP-DDS-INCOMPAT-QOS-PERPAIR (ADR 0048 §16.3): record an RxO-INCOMPATIBLE (LOCAL-ENTITY-ID, REMOTE) PAIR in
   DISC-NODE-INCOMPAT-PAIRS (remote 16-octet GUID (equalp) -> list of already-fired incompatible LOCAL EntityIds,
   lock-guarded). Returns T only the FIRST time THIS pair is recorded, so the per-endpoint {OFFERED,REQUESTED}_
   INCOMPATIBLE_QOS status fires once per (local,remote) pair and NOT again on a SEDP RE-ANNOUNCE. Mirrors
   %record-match-pair EXACTLY; disc-node-incompat (per-remote presence) is recorded separately. At N=1 one
   incompatible local per remote -> per-pair == per-remote (byte-identical)."
  (dds.pal:with-lock ((disc-node-lock node))
    (let* ((key (copy-seq (dds.rtps.discovery:endpoint-data-guid remote)))
           (eids (gethash key (disc-node-incompat-pairs node))))
      (if (member local-entity-id eids :test #'=)
          nil
          (progn (setf (gethash key (disc-node-incompat-pairs node)) (cons local-entity-id eids)) t)))))

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

(defun* %fire-match (node kind remote local-entity-id)
    (function (disc-node keyword dds.rtps.discovery:endpoint-data (or null (unsigned-byte 32))) t)
  "Invoke the ON-MATCH hook (if installed) once per newly-matched (LOCAL-ENTITY-ID, REMOTE) PAIR.
   WP-N-ENDPOINT-2C2 (ADR 0048): LOCAL-ENTITY-ID is the EntityId of the matched LOCAL endpoint (the
   one that RxO-matched REMOTE), threaded so the DCPS hook lands SUBSCRIPTION_MATCHED/PUBLICATION_MATCHED
   + the §8.5.2 crypto-token + the durability match-side on the RIGHT same-topic endpoint (by EntityId),
   never the first-by-topic; NIL -> the hook falls back to topic resolution (byte-identical N=1)."
  (when (disc-node-on-match node)
    (funcall (disc-node-on-match node) kind remote local-entity-id)))

(defun* %fire-inconsistent (node topic-name)
    (function (disc-node string) t)
  "Invoke the ON-INCONSISTENT-TOPIC hook (if installed) for a newly-detected topic-name
   collision (same name, different type) — drives INCONSISTENT_TOPIC (FR-DCPS-3)."
  (when (disc-node-on-inconsistent-topic node)
    (funcall (disc-node-on-inconsistent-topic node) topic-name)))

(defun* %fire-incompat (node kind remote bad local-entity-id)
    (function (disc-node keyword dds.rtps.discovery:endpoint-data list (or null (unsigned-byte 32))) t)
  "Invoke the ON-INCOMPATIBLE-QOS hook (if installed) for a newly-detected RxO
   incompatibility, passing the failing-policy keyword list BAD (FR-QOS-2 / FR-DCPS-3).
   WP-N-ENDPOINT-2C2 (ADR 0048): LOCAL-ENTITY-ID is the incompatible LOCAL endpoint's EntityId, threaded
   so REQUESTED/OFFERED_INCOMPATIBLE_QOS lands on the RIGHT same-topic endpoint (by EntityId); NIL ->
   the hook falls back to topic resolution (byte-identical N=1)."
  (when (disc-node-on-incompatible-qos node)
    (funcall (disc-node-on-incompatible-qos node) kind remote bad local-entity-id)))

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

(defun* %consult-auth-gate (node remote local)
    (function (disc-node dds.rtps.discovery:endpoint-data dds.rtps.discovery:endpoint-data) t)
  "Ask the AUTH-GATE hook for an authentication verdict on (REMOTE, LOCAL), outside the
   node lock (receiver thread). A NIL gate — and any verdict other than :incompatible /
   :pending — proceeds as :compatible (security OFF = unchanged)."
  (let ((gate (disc-node-auth-gate node)))
    (if gate (funcall gate node remote local) :compatible)))

(defun* %consult-permissions-gate (node remote local)
    (function (disc-node dds.rtps.discovery:endpoint-data dds.rtps.discovery:endpoint-data) t)
  "Ask the PERMISSIONS-GATE hook for an access-control verdict on (REMOTE, LOCAL), outside
   the node lock (receiver thread). A NIL gate — and any verdict other than :incompatible /
   :pending — proceeds as :compatible (AC OFF = unchanged). DDS-Security 1.1 §8.4."
  (let ((gate (disc-node-permissions-gate node)))
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
   QoS failed RxO is OFFERED/REQUESTED_INCOMPATIBLE_QOS (failing policies).
   WP-DDS-INCOMPAT-QOS-PERPAIR (ADR 0048 §16.3): the incompatible verdict is collected PER (local,remote) PAIR
   (not a single overwritten scalar) and fired once per NEW pair, gated by %record-incompat-pair — so BOTH
   same-topic incompatible locals fire, a LATE local (created after REMOTE was recorded) fires, and a re-announce
   re-fires nothing; mirrors the match path's %record-match-pair/%fire-match. INCONSISTENT_TOPIC stays per-remote and
   fires INDEPENDENTLY of INCOMPATIBLE_QOS (F1: a remote with both a QoS-incompatible same-type sibling and a
   type-inconsistent sibling fires BOTH statuses — they are separate DDS 1.4 §2.2.4.1 statuses on different entities)."
  (let ((incompats nil) (inconsistent nil) (parked nil) (writer-p (eq direction :remote-writer)))
    (dolist (local (remove-if-not (lambda (l) (%endpoint-enabled-p node l))   ; ADR 0060: a DISABLED local endpoint must not match a remote (DDS 1.4 §2.2.2.1.1.7)
                                  (if writer-p (disc-node-local-readers node) (disc-node-local-writers node))))
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
                 ;; WP-N-ENDPOINT-2C1: park THIS remote (resume re-runs it) but keep scanning locals so a
                 ;; sibling same-topic reader that fully matches is still route-added (route-add-all)
                 (setf parked t))
                (t (case (%consult-auth-gate node remote local)
                     (:incompatible nil) ; auth refuses unauthenticated peer; no INCONSISTENT_TOPIC
                     (:pending (%park-match node direction remote) (setf parked t))
                     (t (case (%consult-permissions-gate node remote local)
                          (:incompatible nil) ; access denied; no INCONSISTENT_TOPIC
                          (:pending (%park-match node direction remote) (setf parked t))
                          (t
                           ;; WP-N-ENDPOINT-2C2 (ADR 0048): fire the prearm/route-add/status PER matched LOCAL
                           ;; endpoint, gated by the per-(local,remote) PAIR so each fires ONCE and NOT again on a
                           ;; SEDP re-announce. LOCAL-EID = the matched local endpoint's EntityId (threaded to the hook).
                           (let* ((remote-guid (dds.rtps.discovery:endpoint-data-guid remote))
                                  (local-eid (%guid-entityid (dds.rtps.discovery:endpoint-data-guid local)))
                                  (first-pair (%record-match-pair node remote local-eid)))
                             ;; WP-ACKNACK-MATCH-GATE (DDS 1.4 §2.2.3.4; RTPS 2.5 §8.4.2.2): arm the writer-side
                             ;; durability baseline BEFORE the match is recorded (before the reader becomes a
                             ;; %reader-push-targets destination), on the FIRST match of THIS (writer,reader) pair
                             ;; only (a re-announce must not re-future past unsent LIVE samples). WP-N-ENDPOINT-2C2:
                             ;; per-pair (was per-remote), so a 2nd same-topic writer's baseline is armed too.
                             (when (and first-pair (not writer-p))
                               (%prearm-writer-future-base node remote-guid local-eid))
                             ;; WP-N-ENDPOINT-2C1 (ADR 0048): a matched remote WRITER -> route-add ALL RxO-compatible
                             ;; local readers (the route holds a LIST; idempotent), so a 2nd same-topic reader is added too.
                             (when writer-p
                               (%reader-route-add node remote-guid local-eid))
                             ;; per-REMOTE presence (matched-count / HB-gate / lease-sweep) — idempotent; unconditional.
                             (%record-match node remote)
                             ;; per-(local,remote) PAIR status/crypto/durability fire — once per pair, threading LOCAL-EID
                             ;; so it lands on the RIGHT same-topic endpoint. DO NOT return; continue the dolist (all locals).
                             (when first-pair (%fire-match node direction remote local-eid))))))))))
          ((string= (dds.rtps.discovery:endpoint-data-topic-name remote)
                    (dds.rtps.discovery:endpoint-data-topic-name local))
           (if (string= (dds.rtps.discovery:endpoint-data-type-name remote)
                        (dds.rtps.discovery:endpoint-data-type-name local))
               ;; WP-DDS-INCOMPAT-QOS-PERPAIR (ADR 0048 §16.3): COLLECT one (local-eid . bad) entry per incompatible
               ;; (local,remote) pair — NOT a single overwritten scalar — so BOTH same-topic incompatible locals (and
               ;; a LATE one) each fire REQUESTED/OFFERED_INCOMPATIBLE_QOS on the RIGHT endpoint (by EntityId).
               (push (cons (%guid-entityid (dds.rtps.discovery:endpoint-data-guid local)) bad) incompats)
               (setf inconsistent (dds.rtps.discovery:endpoint-data-topic-name local)))))))
    ;; WP-N-ENDPOINT-2C1: a PARKED (type-pending) local suppresses the incompat/inconsistent verdict for this
    ;; remote — the pending decision is not yet final (resume-parked-matches re-runs it); mirrors the pre-2c1
    ;; park short-circuit, which returned before this cond, without stopping the route-add-all scan of siblings.
    (unless parked
      ;; WP-DDS-INCOMPAT-QOS-PERPAIR (ADR 0048 §16.3): fire INCOMPATIBLE_QOS once per NEW (local,remote) pair,
      ;; threading THAT pair's local-eid (mirrors the match path's %record-match-pair/%fire-match). %record-incompat
      ;; keeps the per-remote presence (analog of %record-match), recorded once; a re-announce re-fires nothing.
      (when incompats
        (%record-incompat node remote)
        (dolist (pair incompats)
          (when (%record-incompat-pair node remote (car pair))
            (%fire-incompat node direction remote (cdr pair) (car pair)))))
      ;; WP-DDS-INCOMPAT-QOS-PERPAIR F1: INCONSISTENT_TOPIC is an INDEPENDENT status on the Topic entity (DDS 1.4
      ;; §2.2.4.1), NOT mutually exclusive with a SIBLING's INCOMPATIBLE_QOS — fire it per NEW inconsistent remote
      ;; regardless of any incompat pair this scan (its own per-remote idempotency gate). A remote with BOTH a
      ;; QoS-incompatible same-type sibling AND a type-inconsistent sibling fires BOTH statuses (was: incompat SHADOWED it).
      (when (and inconsistent (%record-inconsistent node remote))
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

(defun* %rtps-protection-required-from (node src-prefix)
    (function (disc-node (simple-array (unsigned-byte 8) (12))) t)
  "T iff NODE MUST require whole-RTPS-message protection (rtps_protection) on USER data inbound from the
   participant at SRC-PREFIX (DDS-Security 1.1 §8.5.1.10-.12 / §9.4.1.2.3) — the receive complement of the
   send-side SRTPS wrap gate (%maybe-wrap-srtps). True when NODE's governance sets a non-NONE rtps_protection
   tier (RTPS-PROTECTION-KIND) AND that source is :KEYED — its ParticipantCrypto resolves through the installed
   RTPS-PROTECTION-DECODE resolver. When T, a PLAIN (non-SRTPS) USER-DATA submessage carrying SRC-PREFIX is
   FORGED — a legitimate keyed peer ALWAYS SRTPS-wraps user data and user data flows only after :keyed, so a
   plain user-DATA from a keyed-rtps peer cannot legitimately occur — and %handle-datagram drops it fail-closed
   (NFR-SEC-POSTURE). NIL (governance rtps_protection NONE, security OFF so no decode resolver installed, or an
   unknown/not-keyed source) -> plain user data is delivered unchanged (byte-identical). The builtin-metatraffic
   exemption is applied by writerId at the drop site (%user-writer-entityid-p), not here. Control-plane: gated on
   the installed resolver, so a security-OFF node short-circuits to NIL at zero cost."
  (let ((dec (disc-node-rtps-protection-decode node)))
    (and dec
         (not (eq (disc-node-rtps-protection-kind node) :none))
         (funcall dec src-prefix)
         t)))

(defmacro %with-scratch ((var pool lock) &body body)
  "Borrow one datagram-sized scratch octet-buffer from POOL (a dds.core.arena buffer-pool) under LOCK, bind it to
   VAR, run BODY, and RELEASE it (always, even on non-local exit) — the shared SRTPS zero-alloc borrow used by BOTH
   the send wrap (%with-send-scratch) and the RX unwrap (%with-secure-rx-scratch), WP-DDS-SECURITY-ZEROALLOC-AEAD T3
   (+ the T3(ZA-2) review). Evaluates to BODY's value, or NIL when POOL is NIL (not carved) or EXHAUSTED (no buffer
   free): the caller treats NIL as the fail-closed required-but-failed drop (RESOURCE_LIMITS backpressure, never a GC
   fallback; NFR-MEM). The acquire + release are O(1) index ops under LOCK so concurrent sender/receiver threads
   never corrupt the pool AND each gets a DISTINCT buffer; BODY (the AEAD op + copy) runs OUTSIDE the lock."
  (let ((p (gensym "POOL")) (lk (gensym "LK")) (b (gensym "BUF")))
    `(let* ((,p  ,pool)
            (,lk ,lock)
            (,b  (and ,p (dds.pal:with-lock (,lk) (dds.core.arena:pool-acquire ,p)))))
       (when ,b
         (unwind-protect (let ((,var ,b)) ,@body)
           (dds.pal:with-lock (,lk) (dds.core.arena:pool-release ,p ,b)))))))

(defmacro %with-secure-rx-scratch ((var node) &body body)
  "Borrow one RX decode buffer from NODE's SECURE-RX-POOL (%with-scratch over the RX pool + its dedicated lock) — the
   RX twin of %with-send-scratch; NIL body value on a not-carved / exhausted pool (fail-closed drop). Each concurrent
   receiver thread (unicast / multicast / SHMEM) gets a DISTINCT buffer, so the SRTPS decode->copy-back window never
   races across transports. WP-DDS-SECURITY-ZEROALLOC-AEAD T3(ZA-2) review."
  (let ((n (gensym "NODE")))
    `(let ((,n ,node))
       (%with-scratch (,var (disc-node-secure-rx-pool ,n) (disc-node-secure-rx-lock ,n))
         ,@body))))

(defun* %ensure-secure-rx-pool (node)
    (function (disc-node) t)
  "Return NODE's SRTPS RX decode pool (SECURE-RX-POOL), carving it (arena + fixed pool of datagram-sized static
   buffers) lazily on the first SRTPS unwrap and returning it thereafter (WP-DDS-SECURITY-ZEROALLOC-AEAD T3(ZA-2)
   review). element-bytes = +srtps-scratch-datagram-bytes+ (a recovered stream is never longer than the ciphertext);
   capacity = *srtps-send-scratch-capacity* (the <=3 receiver threads + headroom). %handle-datagram borrows one
   DISTINCT buffer per SRTPS unwrap (%with-secure-rx-scratch); decode-rtps-message-into opens ENCRYPT plaintext into
   it, it is copied back in place, then released (SIGN moves the verbatim region in place, buffer unused) — so the
   concurrent unicast / multicast / SHMEM receiver threads NEVER share a decode sink (the T3(ZA-2) review fix; the
   pre-review single reused buffer raced: thread A's decode->copy-back window vs thread B decoding into the same
   buffer -> A delivered B's plaintext). Carved OFF the steady state (first secured receive only) under SECURE-RX-LOCK,
   double-checked so it happens exactly once across the receiver threads (a DEDICATED lock, so the RX pool ops never
   contend with the send-scratch pool ops). On arena/static-alloc failure returns NIL — %handle-datagram then falls
   back to the allocating decode-rtps-message (correct, byte-identical wire, self-heals when the arena frees), never a
   per-datagram GC on the pooled path. The arena is stored only after the pool carve succeeds (teardown reachability);
   stop-node tears it down. NIL until the first unwrap -> a node with rtps_protection off reserves no static memory,
   consistent with the send-scratch pool + the other per-node security pools (all lazy)."
  (or (disc-node-secure-rx-pool node)
      (dds.pal:with-lock ((disc-node-secure-rx-lock node))
        (or (disc-node-secure-rx-pool node)
            (handler-case
                (let* ((eb    (srtps-scratch-datagram-bytes))
                       (cap   *srtps-send-scratch-capacity*)
                       (arena (dds.core.arena:init-arena :bytes (* eb (1+ cap))))   ; +1 slot slack
                       (pool  (dds.core.arena:make-buffer-pool arena eb cap)))
                  (setf (disc-node-secure-rx-arena node) arena   ; store the arena only after the carve succeeds (teardown reachability)
                        (disc-node-secure-rx-pool node) pool))   ; set the pool LAST — the double-checked-carve flag
              (error () nil))))))   ; arena-exhausted / static-alloc failure -> leave NIL -> allocating fallback

(defmacro %with-bracket-rx-scratch ((var node) &body body)
  "Borrow one RX SEC_PREFIX-bracket buffer from NODE's BRACKET-RX-POOL (%with-scratch over the bracket pool + its
   dedicated lock) — the buffer %handle-datagram copies an inbound submessage-protection bracket INTO before dispatch
   (WP-DDS-SECURITY-ZEROALLOC-AEAD T5 / ZA-2). NIL body value on a not-carved / EXHAUSTED pool (fail-closed drop). A
   DEDICATED pool, so the borrowed bracket (the decode INPUT) is a DISTINCT live buffer from the SECURE-RX decode
   OUTPUT %on-user-secure-submessage opens into; each concurrent receiver thread gets its own bracket buffer (no
   shared-sink race — the T3(ZA-2) RX-race invariant)."
  (let ((n (gensym "NODE")))
    `(let ((,n ,node))
       (%with-scratch (,var (disc-node-bracket-rx-pool ,n) (disc-node-bracket-rx-lock ,n))
         ,@body))))

(defun* %ensure-bracket-rx-pool (node)
    (function (disc-node) t)
  "Return NODE's RX SEC_PREFIX-bracket EXTRACTION pool (BRACKET-RX-POOL), carving it (arena + fixed pool of
   datagram-sized static buffers) lazily on the first secured-bracket receive and returning it thereafter
   (WP-DDS-SECURITY-ZEROALLOC-AEAD T5 / ZA-2). element-bytes = +srtps-scratch-datagram-bytes+ (a bracket is a sub-region
   of a datagram, never longer than the datagram); capacity = *srtps-send-scratch-capacity* (the <=3 receiver threads +
   headroom). %handle-datagram borrows one DISTINCT buffer per secured submessage (%with-bracket-rx-scratch) to copy the
   [SEC_PREFIX,datagram-end) bracket into — the decode INPUT — which %on-user-secure-submessage then decodes INTO a
   SECURE-RX buffer (the OUTPUT): a DEDICATED pool keeps the two DISTINCT by construction, and gives each receiver thread
   its own bracket buffer so the extract->dispatch window never races (mirrors %ensure-secure-rx-pool + the T3(ZA-2)
   RX-race fix; a DEDICATED BRACKET-RX-LOCK so its ops never contend with the SECURE-RX / send pool ops). Carved OFF the
   steady state (first secured receive only) under BRACKET-RX-LOCK, double-checked so it happens exactly once across the
   receiver threads. On arena/static-alloc failure returns NIL — %handle-datagram then falls back to the allocating
   make-array bracket (correct, byte-identical, self-heals when the arena frees), never a per-datagram GC on the pooled
   path. The arena is stored only after the pool carve succeeds (teardown reachability); stop-node tears it down. NIL
   until the first secured bracket -> a node that never receives one reserves no static memory (byte-identical plain
   path), consistent with the other per-node security pools (all lazy)."
  (or (disc-node-bracket-rx-pool node)
      (dds.pal:with-lock ((disc-node-bracket-rx-lock node))
        (or (disc-node-bracket-rx-pool node)
            (handler-case
                (let* ((eb    (srtps-scratch-datagram-bytes))
                       (cap   *srtps-send-scratch-capacity*)
                       (arena (dds.core.arena:init-arena :bytes (* eb (1+ cap))))   ; +1 slot slack
                       (pool  (dds.core.arena:make-buffer-pool arena eb cap)))
                  (setf (disc-node-bracket-rx-arena node) arena   ; store the arena only after the carve succeeds (teardown reachability)
                        (disc-node-bracket-rx-pool node) pool))   ; set the pool LAST — the double-checked-carve flag
              (error () nil))))))   ; arena-exhausted / static-alloc failure -> leave NIL -> allocating fallback

(defmacro %with-key-id-rx-scratch ((var node) &body body)
  "Borrow one RX key_id scratch buffer (exactly 4 octets) from NODE's KEY-ID-RX-POOL (%with-scratch over the
   key_id pool + its dedicated lock) — the per-thread buffer %on-secure-submessage copies the §9.5.3.3.1 CryptoHeader
   transformation_key_id into before the equalp-keyed key_id resolvers look it up (WP-DDS-SECURITY-ZEROALLOC-AEAD T5 /
   ZA-2). NIL body value on a not-carved / EXHAUSTED pool. A DEDICATED pool gives each receiver thread its own key_id
   scratch (no shared-sink race), alloc-free — a dynamic-extent stack array cannot serve (this SBCL heap-allocates
   dynamic-extent specialized (unsigned-byte 8) arrays; the resolvers require a specialized array)."
  (let ((n (gensym "NODE")))
    `(let ((,n ,node))
       (%with-scratch (,var (disc-node-key-id-rx-pool ,n) (disc-node-key-id-rx-lock ,n))
         ,@body))))

(defun* %ensure-key-id-rx-pool (node)
    (function (disc-node) t)
  "Return NODE's RX key_id scratch pool (KEY-ID-RX-POOL), carving it (arena + fixed pool of small static buffers)
   lazily on the first secured-bracket receive and returning it thereafter (WP-DDS-SECURITY-ZEROALLOC-AEAD T5 / ZA-2).
   element-bytes = 4 (the key_id is exactly 4 octets — the equalp resolvers hash the whole vector); capacity = *srtps-send-scratch-capacity*
   (the <=3 receiver threads + headroom). %on-secure-submessage borrows one DISTINCT buffer per bracket to copy the
   §9.5.3.3.1 transformation_key_id into (%secure-bracket-key-id-into) for the equalp key_id resolvers — a per-thread
   alloc-free specialized scratch (a dynamic-extent stack array does NOT stack-allocate for a specialized (unsigned-byte
   8) array on this SBCL; only simple-vectors do, which the resolvers cannot take). Carved OFF the steady state under a
   DEDICATED KEY-ID-RX-LOCK, double-checked so it happens exactly once across the receiver threads. On arena/static-alloc
   failure returns NIL — %on-secure-submessage then falls back to an allocating heap 4-array (correct, byte-identical,
   self-heals). Torn down in stop-node. NIL until the first secured bracket -> zero static memory when no secured
   receive occurs, consistent with the other per-node security pools (all lazy)."
  (or (disc-node-key-id-rx-pool node)
      (dds.pal:with-lock ((disc-node-key-id-rx-lock node))
        (or (disc-node-key-id-rx-pool node)
            (handler-case
                (let* ((eb    4)   ; the key_id is EXACTLY 4 octets — the equalp key_id resolvers hash the whole vector
                       (cap   *srtps-send-scratch-capacity*)
                       (arena (dds.core.arena:init-arena :bytes (* eb (1+ cap))))   ; +1 slot slack
                       (pool  (dds.core.arena:make-buffer-pool arena eb cap)))
                  (setf (disc-node-key-id-rx-arena node) arena   ; store the arena only after the carve succeeds (teardown reachability)
                        (disc-node-key-id-rx-pool node) pool))   ; set the pool LAST — the double-checked-carve flag
              (error () nil))))))   ; arena-exhausted / static-alloc failure -> leave NIL -> allocating fallback

(defvar *rx-source-timestamp* nil
  "S5.T4: the source_timestamp (nanoseconds) applied to the DATA currently being received, set from the
   INFO_TS submessage that preceded it in the datagram (RTPS 2.5 §9.4.5.9 / §8.3.7.9) and read at the store
   (%deliver-user-sample -> %record-sample-timestamp -> the drain's SampleInfo.source_timestamp). Bound
   per datagram in %handle-datagram; NIL (no INFO_TS) stores no timestamp — SampleInfo.source_timestamp
   stays NIL, the pre-S5 reception-order behaviour. Receiver-thread dynamic extent.")

(defun* %handle-datagram (node buf size &optional rtps-unwrapped)
    (function (disc-node dds.core.buffer:octet-buffer (integer 0) &optional t) t)
  "Dispatch an inbound datagram (bounded by SIZE). DATA is routed by writerId: SPDP
   -> record participant; SEDP publications/subscriptions -> match; any other DATA
   plus HEARTBEAT/ACKNACK -> the installed data-plane hooks (nil = ignore). The
   discovery SerializedPayloads are ParameterLists (encap header + list); a user
   DATA payload is opaque bytes handed to the on-data hook as a [poff,plen) region.
   T10 receive-side rtps_protection ENFORCEMENT (DDS-Security 1.1 §8.5.1.10-.12, the receive complement of the
   send-side SRTPS wrap): when NODE requires rtps_protection from this :keyed source
   (%rtps-protection-required-from) AND the datagram arrived PLAIN (not SRTPS-wrapped), EVERY USER-plane
   submessage — user DATA / DATA_FRAG (discriminated by %user-writer-entityid-p) AND the user reliability-control
   submessages HEARTBEAT / ACKNACK / GAP / HEARTBEAT_FRAG / NACK_FRAG (the user fall-through branches, reached
   only after the builtin handlers below decline) — is a FORGEABLE injection (the source GUID-prefix is
   unauthenticated on a plain datagram; a legitimate keyed-rtps peer ALWAYS SRTPS-wraps user traffic) and is
   DROPPED fail-closed before it reaches any user reader/writer or its reliable state (no forged sample, no
   GAP-marking, no acked-base advance / HistoryCache purge, no reader-proxy corruption). Builtin metatraffic
   (SPDP/SEDP/PSM/PVMS/PMW/TL — builtin EntityIds, kind 0xc?), INCLUDING builtin reliability (SEDP/TL HEARTBEAT
   via the BID clause, TypeLookup/PVMS ACKNACK/HEARTBEAT), is INTENTIONALLY plain in this slice (metatraffic
   rtps-wrapping is the T12 carry) and is routed to its builtin handlers BEFORE the gated user fall-through, so
   it is NEVER dropped (no false-REJECT). RTPS-UNWRAPPED (set only by this function's own post-SRTPS-decode
   re-dispatch) suppresses the enforcement — the inner plaintext was just authenticated by the SRTPS unwrap, so
   its user submessages are delivered (else the just-decoded sample would be self-dropped). NONE governance /
   security OFF / a not-keyed source -> enforcement off, byte-identical."
  (let* ((cursor (dds.core.buffer:cursor buf :endianness :little))
         (src-prefix (%source-prefix buf))
         ;; T10 receive enforcement, computed ONCE: when NODE requires rtps_protection from this :keyed source AND
         ;; this datagram is NOT SRTPS-wrapped, drop its plain USER-DATA (forged) — applied by writerId below.
         ;; RTPS-UNWRAPPED (the post-SRTPS-decode re-dispatch) forces it off (the inner plaintext is authenticated).
         (enforce-rtps (and (not rtps-unwrapped) (%rtps-protection-required-from node src-prefix))))
    ;; T10 whole-RTPS-message protection (DDS-Security 1.1 §8.5.1.12): a datagram whose FIRST submessage (at
    ;; offset 20, right after the 20-octet RTPS Header §9.4.4) is SRTPS_PREFIX (0x33) is rtps_protection-wrapped.
    ;; Resolve the REMOTE ParticipantCrypto by the datagram's source GUID-prefix, decrypt the submessage stream,
    ;; overwrite the post-header region IN PLACE (the recovered stream is never longer than the ciphertext), and
    ;; RE-DISPATCH (recurse — the recovered first submessage is never SRTPS_PREFIX, so no further recursion). Gated
    ;; on a crypto-manager having installed the decode resolver (NIL = security OFF -> the whole branch is skipped,
    ;; byte-identical; a security-OFF node has no key for an SRTPS datagram anyway). FAIL-CLOSED: an unknown/not-keyed
    ;; source (NIL KM), an undecryptable/forged/origin-auth-failed bracket (NIL stream), or one that would not fit ->
    ;; a silent DROP (never dispatch unverified submessages, never a signal out of the receiver thread; NFR-SEC-POSTURE).
    (let ((dec (disc-node-rtps-protection-decode node)))
      (when (and dec (> size 20)
                 (= (aref (dds.core.buffer:octet-buffer-vec buf) 20) dds.security:+submessage-srtps-prefix+))
        (multiple-value-bind (km my-rk-id my-rk) (funcall dec src-prefix)
          (when km
            (let* ((vec (dds.core.buffer:octet-buffer-vec buf))
                   (cap (dds.core.buffer:octet-buffer-capacity buf))
                   ;; A per-node RX POOL gives each concurrent receiver thread (unicast / multicast / SHMEM) a DISTINCT
                   ;; decode buffer — no shared mutable sink, so the decode->copy-back window never races across
                   ;; transports (T3(ZA-2) review). The WITH_ORIGIN_AUTHENTICATION tier (my-rk-id set) now ALSO rides
                   ;; the pool: decode-rtps-message-into GMAC-verifies THIS participant's receiver MAC BY OFFSET,
                   ;; zero-alloc (ADR-0039 residual (a) closed) — no longer the allocating decode-rtps-message.
                   (pool (%ensure-secure-rx-pool node)))
              (if pool
                  ;; ZA-2 zero-alloc + T3(ZA-2) race-fix: BORROW a DISTINCT RX scratch, open the SRTPS bracket at
                  ;; [20,SIZE) BY OFFSET — ENCRYPT plaintext into the scratch, SIGN returns the verbatim-region bounds
                  ;; in VEC (moved in place, scratch unused) — copy back at 20, then the borrow scope RELEASES the
                  ;; scratch BEFORE re-dispatch (the recovered plaintext now lives in BUF). Origin-auth (my-rk-id set):
                  ;; the receiver-MAC is verified in place (the scratch doubles as the ct-len-0 GMAC-verify sink) and a
                  ;; bad/absent MAC -> NIL -> fail-closed drop. Pool exhausted / decode fail / MAC fail / won't-fit ->
                  ;; NEW-SIZE NIL -> fail-closed drop (RESOURCE_LIMITS, never a GC fallback). No subseq / →octets.
                  (let ((new-size (%with-secure-rx-scratch (rx node)
                                    (multiple-value-bind (data-len mode data-off postfix-off)
                                        (dds.security:decode-rtps-message-into rx 0 km vec 20 (- size 20)
                                                                               :my-receiver-key-id my-rk-id
                                                                               :my-receiver-key my-rk)
                                      (declare (ignore postfix-off))
                                      (when (and data-len (<= (+ 20 data-len) cap))
                                        (ecase mode
                                          (:encrypt (replace vec (dds.core.buffer:octet-buffer-vec rx)
                                                             :start1 20 :end1 (+ 20 data-len) :end2 data-len))
                                          ;; same-vec move is always LEFTWARD (data-off 44 = 20+SRTPS_PREFIX+CryptoHeader > start1 20) -> forward-copy safe (CLHS overlap impl-defined; NFR-PORT)
                                          (:sign    (replace vec vec :start1 20 :start2 data-off :end2 (+ data-off data-len))))
                                        (+ 20 data-len))))))
                    ;; RTPS-UNWRAPPED t: the inner plaintext is already authenticated by this unwrap, so the
                    ;; re-dispatch must NOT re-apply the plain-user-DATA enforcement (it would self-drop the sample).
                    (when new-size (%handle-datagram node buf new-size t)))
                  ;; the RX pool could not be carved (arena exhausted at first secured receive): the allocating
                  ;; decode-rtps-message — the degrade path (common tier AND origin-auth, its receiver-MAC gate);
                  ;; correct + byte-identical wire (a subseq of the recovered stream), self-heals when the arena
                  ;; frees, never a per-datagram GC on the common pooled path (which now covers origin-auth too).
                  (let ((stream (dds.security:decode-rtps-message km (subseq vec 20 size)
                                                                  :my-receiver-key-id my-rk-id :my-receiver-key my-rk)))
                    (when (and stream (<= (+ 20 (length stream)) cap))
                      (replace vec stream :start1 20)
                      (%handle-datagram node buf (+ 20 (length stream)) t)))))))
        (return-from %handle-datagram t)))   ; SRTPS datagram: decoded+re-dispatched, or dropped (fail-closed)
    (let ((*rx-source-timestamp* nil))   ; S5.T4: per-datagram INFO_TS source_timestamp (ns), set by the INFO_TS clause + read at the store (%deliver-user-sample); reset each datagram
     (dds.rtps.message:dispatch-message
     cursor
     (lambda (id flags c body-len)
       (cond
         ((= id dds.rtps.message:+submsg-data+)
          (multiple-value-bind (rdr wtr sn has-payload poff plen keyp kind key-hash status-flags
                                orig-guid orig-sn)
              (dds.rtps.message:parse-data-body c flags body-len (disc-node-capture-data-key-hash node))
            (declare (ignore rdr keyp))
            ;; T10 receive-side rtps_protection ENFORCEMENT (NFR-SEC-POSTURE): a PLAIN (non-SRTPS) DATA carrying a
            ;; USER writerId (a user DataWriter, %user-writer-entityid-p) from a keyed-rtps peer is a forged
            ;; cleartext injection (the source GUID-prefix is unauthenticated on a plain datagram) -> DROP it (no
            ;; user-data delivery AND no lifecycle dispose/unregister event) before it reaches a user reader.
            ;; Builtin metatraffic (SPDP/SEDP/PSM/PVMS/PMW/TL — builtin EntityId kind 0xc?) fails
            ;; %user-writer-entityid-p so it is NEVER dropped (it is intentionally plain in this slice; metatraffic
            ;; rtps-wrapping is the T12 carry). ENFORCE-RTPS is NIL when governance rtps_protection is NONE /
            ;; security is OFF / the source is not :keyed -> byte-identical plain delivery (and on the post-SRTPS
            ;; re-dispatch, so the just-decoded authentic user DATA is delivered).
            (unless (and enforce-rtps (%user-writer-entityid-p wtr))
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
                  ;; Slice 2b-i: PSM DATA — ParticipantStatelessMessage (DDS-Security 1.1 §7.4.3)
                  ((= wtr dds.rtps.discovery:+entityid-participant-stateless-writer+)
                   (%on-stateless-message node src-prefix wtr sn buf poff plen))
                  ;; USER-writer DATA only (§9.3.1.2 kind 0x02/0x03). A SECURE builtin writerId (0xff..c2) that reaches
                  ;; the DATA fall-through — a secure-SEDP/SPDP/PM DiscoveredData whose SEC bracket was decoded + the
                  ;; recovered plain DATA re-dispatched here — is METATRAFFIC (handled by %on-secure-builtin), NOT a user
                  ;; sample: never deliver it to the user reader. Previously the always-on data_protection decode masked
                  ;; this (a builtin ParameterList is not a valid SecuredPayload -> dropped); under data_protection=NONE
                  ;; (the SIGN tier) that filter is gone, so gate the user delivery on %user-writer-entityid-p explicitly.
                  ((and (disc-node-on-data node) (%user-writer-entityid-p wtr))
                   ;; Pass orig-guid/orig-sn (PID_ORIGINAL_WRITER_INFO, §8.3.5.4) and key-hash
                   ;; (PID_KEY_HASH, §9.6.4.8 — only non-NIL when capture-data-key-hash is set on
                   ;; the node) into the data-plane hook. %on-user-data gates APP delivery; it MUST
                   ;; call reader-on-data unconditionally for RTPS reliable NACK/HEARTBEAT correctness.
                   (funcall (disc-node-on-data node) wtr sn buf poff plen src-prefix
                            orig-guid orig-sn key-hash)))))))
         ((= id dds.rtps.message:+submsg-info-ts+)
          ;; S5.T4 (RTPS 2.5 §9.4.5.9 / §8.3.7.9): an INFO_TS sets the source_timestamp applied to the
          ;; DATA submessage(s) that FOLLOW it in this datagram (I flag / short body -> parse-info-ts NIL
          ;; -> clear it). Stored (in *rx-source-timestamp*, read by %deliver-user-sample) as nanoseconds
          ;; (sec*1e9 + the 2^-32 fraction converted via the shared discovery codec). Connext / Fast DDS
          ;; prefix every user DATA with one, so this populates the reader's SampleInfo source_timestamp on
          ;; cross-vendor traffic too.
          (multiple-value-bind (sec fraction) (dds.rtps.message:parse-info-ts c flags)
            (setf *rx-source-timestamp* (when sec
                                          (+ (* sec 1000000000)
                                             (dds.qos:wire-fraction->duration-nanosec fraction))))))
         ((= id dds.security:+submessage-sec-prefix+)
          ;; DDS-Security 1.1 §8.5.1.7 / §7.4.5: a SEC_PREFIX...SEC_POSTFIX submessage-protection bracket. The
          ;; SAME id now carries the reliable PVMS crypto-token exchange (T7), the secure SEDP
          ;; DiscoveredWriter/ReaderData (T9), AND the secure participant-message (liveliness) + secure SPDP
          ;; re-announce (T11), so %on-secure-submessage disambiguates by the wire CryptoHeader
          ;; transformation_key_id (a secure builtin EntityCrypto -> %on-secure-builtin, which after decode routes
          ;; by the recovered inner writerId to SEDP-match / liveliness / record-participant; else -> PVMS, whose
          ;; all-zero bootstrap key_id never lands in the EntityCrypto index). Each path decodes the whole bracket
          ;; (codec bounds-checks + ignores trailing octets) + verifies the inner writerId, fail-closed. Trailing
          ;; SEC_BODY/SEC_POSTFIX dispatch-message walks match no clause.
          ;; T10 review fix-1: ENFORCE-RTPS is passed so a BARE user metadata_protection bracket (no outer SRTPS)
          ;; from a keyed-rtps peer that REQUIRES rtps_protection is DROPPED on the USER route (§8.5.1.10-.12),
          ;; like the sibling plain-user clauses below; BUILTIN secure brackets stay exempt (metatraffic plain
          ;; this slice). On the post-SRTPS re-dispatch ENFORCE-RTPS is NIL (rtps-unwrapped=t), so the legit
          ;; wrapped user bracket IS delivered.
          (let ((start (- (dds.core.buffer:cursor-position c) 4)))   ; SEC_PREFIX submessage-header start
            (when (and (>= start 0) (> size start))
              ;; WP-DDS-SECURITY-ZEROALLOC-AEAD T5 (ZA-2): copy [SEC_PREFIX,datagram-end) — the decode INPUT — into a
              ;; POOLED per-thread bracket buffer (BRACKET-RX-POOL, DISTINCT from the SECURE-RX decode-OUTPUT pool
              ;; %on-user-secure-submessage opens into), replacing the pre-T5 per-bracket (make-array (- size start)).
              ;; %on-secure-submessage consumes the bracket SYNCHRONOUSLY (builtin secure-SEDP/PVMS AND user metadata
              ;; paths) before the next bracket is extracted, and the recovered plaintext is never itself a SEC_PREFIX,
              ;; so a per-thread reused bracket buffer is safe (no nested bracket borrow). Runtime pool exhaustion ->
              ;; %with-bracket-rx-scratch NIL -> a fail-closed DROP (RESOURCE_LIMITS, never a GC fallback; NFR-MEM);
              ;; a not-carved pool (arena exhausted) OR an oversized bracket -> the allocating make-array fallback
              ;; (byte-identical to the pre-T5 path; correct; no false-REJECT; self-heals when the arena frees).
              (let* ((blen (- size start))
                     (pool (%ensure-bracket-rx-pool node)))
                (if (and pool (<= blen +srtps-scratch-datagram-bytes+))
                    (%with-bracket-rx-scratch (br node)
                      (replace (dds.core.buffer:octet-buffer-vec br) (dds.core.buffer:octet-buffer-vec buf)
                               :start2 start :end2 size)
                      (%on-secure-submessage node src-prefix (dds.core.buffer:octet-buffer-vec br) blen enforce-rtps))
                    (let ((bracket (make-array blen :element-type '(unsigned-byte 8))))
                      (replace bracket (dds.core.buffer:octet-buffer-vec buf) :start2 start :end2 size)
                      (%on-secure-submessage node src-prefix bracket blen enforce-rtps)))))))
         ((= id dds.rtps.message:+submsg-heartbeat+)
          (let ((pos (dds.core.buffer:cursor-position c)))
            (multiple-value-bind (rid wid first last hcount hfinal hlive)
                (dds.rtps.message:parse-heartbeat-body c flags)
              (declare (ignore rid hcount hfinal hlive))
              (let ((bid (or (%sedp-reader-id-for wid) (%tl-reader-id-for wid))))
                (cond
                  (bid (%on-builtin-heartbeat node src-prefix bid wid first last))
                  ;; T10 receive enforcement: the USER fall-through (a user reader's HEARTBEAT handler,
                  ;; %on-user-heartbeat) — gate on (not enforce-rtps) so a forged PLAIN HEARTBEAT from a
                  ;; keyed-rtps peer is DROPPED before it corrupts the user reader-proxy / reflects a NACK
                  ;; storm. Builtin HEARTBEAT (SEDP/TL via BID) is handled ABOVE; the PVMS HEARTBEAT is now
                  ;; submessage-protected (decoded via %on-secure-submessage -> %on-volatile-secure demux,
                  ;; Slice 5), so it NEVER arrives on this clear path -> exempt (DDS-Security 1.1 §8.5.1.10).
                  ((and (disc-node-on-heartbeat node) (not enforce-rtps))
                   (dds.core.buffer:cursor-set-position c pos)
                   (funcall (disc-node-on-heartbeat node) c flags src-prefix)))))))
         ((= id dds.rtps.message:+submsg-acknack+)
          (let ((pos (dds.core.buffer:cursor-position c)))
            (unless (%on-tl-acknack node src-prefix c flags)
              ;; T10 receive enforcement: the USER fall-through (a user writer's ACKNACK handler,
              ;; %on-user-acknack) — gate on (not enforce-rtps) so a forged PLAIN ACKNACK from a keyed-rtps
              ;; peer cannot advance the acked-base / purge unacked HistoryCache changes the real reader never
              ;; got (permanent data loss). Builtin ACKNACK (TypeLookup) is consumed ABOVE; the PVMS ACKNACK is
              ;; now submessage-protected (decoded via %on-secure-submessage -> %on-volatile-secure demux,
              ;; Slice 5), so it NEVER arrives on this clear path -> exempt (DDS-Security 1.1 §8.5.1.10).
              (when (and (disc-node-on-acknack node) (not enforce-rtps))
                (dds.core.buffer:cursor-set-position c pos)
                (funcall (disc-node-on-acknack node) c flags src-prefix)))))
         ;; T10 receive enforcement: GAP routes ONLY to the user reader's handler (%on-user-gap, itself gated on
         ;; a user writer EntityId — there is NO builtin GAP handler, so builtin GAP is already a no-op here) —
         ;; gate the clause on (not enforce-rtps) so a forged PLAIN GAP from a keyed-rtps peer cannot mark user
         ;; SNs :gap (silent sample suppression — the reader stops NACKing evicted SNs forever). DDS-Security 1.1
         ;; §8.5.1.10 / RTPS 2.5 §8.3.7.4.
         ((and (= id dds.rtps.message:+submsg-gap+) (disc-node-on-gap node) (not enforce-rtps))
          ;; RTPS 2.5 §8.3.7.4: a GAP marks evicted/irrelevant SNs so the reliable reader stops NACKing them.
          (funcall (disc-node-on-gap node) c flags src-prefix))
         ;; T10 enforcement (DATA_FRAG path, RTPS 2.5 §9.4.5.7): on-data-frag is EXCLUSIVELY the user-data-frag
         ;; consumer (%on-user-data-frag, itself gated on %user-writer-entityid-p) — there is no builtin DATA_FRAG
         ;; handler — so a plain fragment that would be DELIVERED necessarily carries a USER writerId. Gating the
         ;; clause on (not enforce-rtps) therefore drops exactly the forgeable plain user fragments from a
         ;; keyed-rtps peer and never any builtin metatraffic (which this clause never delivered) — equivalent to
         ;; the per-writerId drop applied to whole DATA above.
         ((and (= id dds.rtps.message:+submsg-data-frag+) (disc-node-on-data-frag node) (not enforce-rtps))
          (funcall (disc-node-on-data-frag node) c flags body-len buf src-prefix))
         ;; T10 receive enforcement: HEARTBEAT_FRAG / NACK_FRAG are user-only (their handlers are gated on a user
         ;; writer EntityId and there is NO builtin frag handler — exactly like DATA_FRAG above) — gate on
         ;; (not enforce-rtps) so a forged PLAIN fragment-reliability submessage from a keyed-rtps peer is dropped
         ;; before it touches user reassembly / writer state (DDS-Security 1.1 §8.5.1.10).
         ((and (= id dds.rtps.message:+submsg-heartbeat-frag+) (disc-node-on-heartbeat-frag node) (not enforce-rtps))
          (funcall (disc-node-on-heartbeat-frag node) c flags src-prefix))
         ((and (= id dds.rtps.message:+submsg-nack-frag+) (disc-node-on-nack-frag node) (not enforce-rtps))
          (funcall (disc-node-on-nack-frag node) c flags))))
     size))
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

(defun* %zc-drop-armed (node change)
    (function (disc-node dds.rtps.history:cache-change) t)
  "WP-FLATDATA-LOAN-WRITE (FR-PF-4, R6, ADR 0042; NOT cleared for ship — pending counsel). ONE-SHOT release of
   CHANGE's pre-committed Zero-Copy slot if (and only if) it is still :armed: writer-zc-unarm flips the state
   under the writer lock (so a concurrent claim/unarm on another thread can never double-spend the refcount),
   and on a won transition the slot is %zc-released (refcount 1 -> 0, reclaimable; the committed generation is
   left in place — a later loan on the slot bumps it, invalidating any stale ref). A change with no slot, or one
   already :consumed/:released, is an O(1) no-op. Fired by the send-site fallback decision (%zc-change-item: the
   security gate, a non-ZC destination, or a non-:data/undersized change), the post-push-pass sweep
   (%zc-armed-sweep), and the stop-node teardown sweep (ADR 0042 lifecycle)."
  (when (eq (dds.rtps.history:cache-change-zc-state change) :armed)   ; fast hint; the transition re-checks under the lock
    (let ((writer (disc-node-user-writer node))
          (sap (disc-node-zc-pool-sap node)))
      (when (and writer sap
                 (dds.rtps.reliable:writer-zc-unarm writer change))   ; won the one-shot :armed -> :released
        (dds.xport.zerocopy::%zc-release sap
                                         (dds.rtps.history:cache-change-zc-slot change)
                                         (dds.rtps.history:cache-change-zc-generation change)))))
  t)

(defun* %zc-armed-sweep (node &optional (snapshot nil snapshot-p))
    (function (disc-node &optional list) t)
  "WP-FLATDATA-LOAN-WRITE leak-safety sweep (FR-PF-4, R6, ADR 0042; NOT cleared for ship — pending counsel).
   Release every still-:armed pre-committed slot among SNAPSHOT's registry entries (default: the ENTIRE current
   registry — the stop-node teardown sweep) and drop the swept entries from the node's registry. The push-pass
   callers (%push-data-buf / %node-datagram-plan) snapshot the registry head BEFORE the pass and sweep exactly
   that snapshot AFTER it — entries armed concurrently (a mid-pass publish on another thread) are prepended
   ahead of the snapshot and survive to their own pass, so a fresh loan is never released before it was ever
   presented to a destination. A swept change that the pass already consumed/released is a no-op (%zc-drop-armed
   is one-shot); a change the pass never presented (zero destinations, debug-drop, KEEP_LAST-evicted before its
   push) is released HERE — a committed slot can therefore never strand at refcount>=1 beyond one push pass
   (or node lifetime for a never-pushing writer), and the pool degrades gracefully, never wedges (ADR 0042)."
  (let ((entries (if snapshot-p
                     snapshot
                     (dds.pal:with-lock ((disc-node-lock node)) (disc-node-zc-armed-changes node)))))
    (when entries
      (dolist (change entries) (%zc-drop-armed node change))
      (dds.pal:with-lock ((disc-node-lock node))
        (setf (disc-node-zc-armed-changes node)
              (ldiff (disc-node-zc-armed-changes node) entries)))))
  t)

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
    (%zc-armed-sweep node)   ; WP-FLATDATA-LOAN-WRITE (ADR 0042): release any armed-but-never-pushed pre-committed slot BEFORE the pool dies (no stranded refcount observable by a still-attached reader)
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
  (when (disc-node-secure-rx-arena node)   ; WP-DDS-SECURITY-ZEROALLOC-AEAD T3(ZA-2) review: free the SRTPS RX decode pool's static buffers AFTER every receiver thread is joined (no live borrow)
    (dds.core.arena:teardown-arena (disc-node-secure-rx-arena node))
    (setf (disc-node-secure-rx-arena node) nil (disc-node-secure-rx-pool node) nil))
  (when (disc-node-bracket-rx-arena node)   ; WP-DDS-SECURITY-ZEROALLOC-AEAD T5(ZA-2): free the RX SEC_PREFIX-bracket pool's static buffers AFTER every receiver thread is joined (no live borrow)
    (dds.core.arena:teardown-arena (disc-node-bracket-rx-arena node))
    (setf (disc-node-bracket-rx-arena node) nil (disc-node-bracket-rx-pool node) nil))
  (when (disc-node-key-id-rx-arena node)   ; WP-DDS-SECURITY-ZEROALLOC-AEAD T5(ZA-2): free the RX key_id scratch pool's static buffers AFTER every receiver thread is joined (no live borrow)
    (dds.core.arena:teardown-arena (disc-node-key-id-rx-arena node))
    (setf (disc-node-key-id-rx-arena node) nil (disc-node-key-id-rx-pool node) nil))
  (when (disc-node-send-scratch-arena node)   ; WP-DDS-SECURITY-ZEROALLOC-AEAD T3: free the SRTPS send-scratch pool's static buffers AFTER every sender/receiver thread is joined (no live borrow)
    (dds.core.arena:teardown-arena (disc-node-send-scratch-arena node))
    (setf (disc-node-send-scratch-arena node) nil (disc-node-send-scratch-pool node) nil))
  (when (disc-node-submsg-scratch-arena node)   ; WP-DDS-SECURITY-ZEROALLOC-AEAD T4: free the metadata_protection submessage-scratch pool's static buffers AFTER every sender thread is joined (no live borrow)
    (dds.core.arena:teardown-arena (disc-node-submsg-scratch-arena node))
    (setf (disc-node-submsg-scratch-arena node) nil (disc-node-submsg-scratch-pool node) nil))
  (when (disc-node-zc-overlay-scratch-arena node)   ; WP-SECURITY-ZC-SHMEM-OVERLAY (ADR 0051): free the in-slot SecuredPayload seal-scratch pool's static buffers AFTER every sender thread is joined (no live borrow)
    (dds.core.arena:teardown-arena (disc-node-zc-overlay-scratch-arena node))
    (setf (disc-node-zc-overlay-scratch-arena node) nil (disc-node-zc-overlay-scratch-pool node) nil))
  (dolist (a (disc-node-payload-arena node))   ; WP-DDS-SECURITY-ZEROALLOC-AEAD T5a / WP-N-ENDPOINT-S3: free EVERY secured writer's payload-pool arena (a LIST now) AFTER every sender/receiver thread is joined (no live acquire/release) — no per-writer arena orphaned
    (dds.core.arena:teardown-arena a))
  (setf (disc-node-payload-arena node) nil)
  (when (disc-node-decode-arena node)   ; WP-DDS-SECURITY-ZEROALLOC-AEAD T5b: return every outstanding secured loan (so loaned buffers re-enter the pool's slots) BEFORE freeing the decode pool's static buffers — the receiver thread is already joined (no live acquire)
    (node-return-all-loans node)
    (dds.core.arena:teardown-arena (disc-node-decode-arena node))
    (setf (disc-node-decode-arena node) nil (disc-node-decode-pool node) nil))
  ;; ADR-0034 secret hygiene: zeroize + free the PVMS bootstrap KeyMaterials (KxKey/KxSalt-derived secrets) AFTER the receiver thread is joined (no live PVMS resolver), then clear the table (a post-teardown resolve returns NIL, fail-closed)
  (maphash (lambda (prefix km) (declare (ignore prefix)) (dds.security:zeroize-key-material km))
           (disc-node-pvms-bootstrap-kms node))
  (clrhash (disc-node-pvms-bootstrap-kms node))
  ;; ADR-0036/0040 carry: also free the PVMS bootstrap KMs pruned on peer-loss (wiped in place at prune; the sole foreign free is deferred to HERE, the quiesced point — no mid-run free)
  (dolist (km (disc-node-retired-pvms-kms node)) (dds.security:zeroize-key-material km))
  (setf (disc-node-retired-pvms-kms node) nil)
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

(defun* disc-node-matched-endpoints-for (node local-entity-id)
    (function (disc-node (unsigned-byte 32)) list)
  "The endpoint-data of every remote endpoint currently MATCHED to NODE's LOCAL user endpoint named by
   LOCAL-ENTITY-ID (RTPS 2.5 §9.3.1.2) — walk the per-(LOCAL,REMOTE) match-pairs, keep the remotes whose
   matched-local set contains LOCAL-ENTITY-ID, and return their endpoint-data from disc-node-matches. The
   introspection source for DDS get_matched_publications/subscriptions (DDS 1.4 §2.2.2.4.2.10 /
   §2.2.2.5.2.10): a local writer's matches are all remote readers, a local reader's all remote writers."
  (let ((out '()))
    (dds.pal:with-lock ((disc-node-lock node))
      (maphash (lambda (remote-guid local-eids)
                 (when (member local-entity-id local-eids)
                   (let ((ep (gethash remote-guid (disc-node-matches node))))
                     (when ep (push ep out)))))
               (disc-node-match-pairs node)))
    out))

(defun* %disc-node-matched-count-for-prefix (node prefix)
    (function (disc-node (simple-array (unsigned-byte 8) (12))) (integer 0))
  "TEST-SUPPORT: how many of NODE's matched remote endpoints carry PREFIX as their
   12-octet participant GUID-prefix (RTPS 2.5 §9.3.1.2) — a peer-scoped matched-count
   that excludes foreign participants sharing the domain. Lock-guarded like
   disc-node-matched-count; reuses %guid-prefix-match-p over the match keys (the remote
   16-octet endpoint GUIDs)."
  (dds.pal:with-lock ((disc-node-lock node))
    (loop for guid being the hash-keys of (disc-node-matches node)
          count (%guid-prefix-match-p guid prefix))))

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
