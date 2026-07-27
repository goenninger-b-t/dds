# QoS & Requested/Offered (RxO) matching

The `dds-qos` system (layer L3) is the control plane's value model: the DDS 1.4 QoS
policy set as a copy-by-value `defstruct`, plus the single Requested/Offered (RxO)
compatibility implementation that decides whether a writer and a reader may match. It is
deliberately foundational — it depends only on `dds-core`, so **both** the discovery
matcher ([Discovery](discovery.md)) and the DCPS entity layer ([DCPS](dcps.md)) share one
`qos-rxo-compatible` rather than re-deriving the §2.2.3 truth table twice. It also carries
the XTypes `TYPE_CONSISTENCY_ENFORCEMENT` policy used by the [type system](type-system.md),
which is reader-only and intentionally *not* part of RxO.

All symbols below are exported from the `net.goenninger.dds.qos` package (nickname
`dds.qos`). The docstrings in `src/dds-qos/qos.lisp` are the contract; this page condenses
them.

## API reference

### Duration_t and its total order

| Symbol | Description |
|---|---|
| `dds.qos:qos-duration` | DDS `Duration_t` struct: a `sec` + `nanosec` pair, both non-negative integers. |
| `dds.qos:make-qos-duration` | Constructor: `(make-qos-duration &optional (sec 0) (nanosec 0))`. |
| `dds.qos:qos-duration-sec` | Accessor for the seconds field. |
| `dds.qos:qos-duration-nanosec` | Accessor for the nanoseconds field. |
| `dds.qos:+duration-zero+` | The zero duration `{0, 0}`; the minimum of the total order. |
| `dds.qos:+duration-infinite+` | `DURATION_INFINITE` = `{0x7fffffff, 0x7fffffff}`; the maximum of the total order. |
| `dds.qos:duration<=` | Total order on `Duration_t`: `(duration<= a b)` is true when `a <= b`, with `DURATION_INFINITE` comparing as the maximum. Drives the duration-policy RxO checks. |

### The `qos` value struct

`dds.qos:qos` (constructor `dds.qos:make-qos`, copier `dds.qos:copy-qos`) holds the
RxO-relevant and commonly-held policies; defaults follow DDS 1.4 §2.2.3. Each slot below has
a package-qualified accessor.

| Accessor | Policy / slot | Default |
|---|---|---|
| `dds.qos:qos-reliability` | RELIABILITY kind — `:best-effort` or `:reliable` | `:best-effort` |
| `reliability-max-blocking` (slot) | RELIABILITY `max_blocking_time` (`qos-duration`) — the **block-up-to** bound a reliable write waits on a full bounded HistoryCache before `RETCODE_TIMEOUT` (see Backpressure below) | `{0, 100 ms}` |
| `dds.qos:qos-durability` | DURABILITY kind — `:volatile`, `:transient-local`, `:transient`, `:persistent` | `:volatile` |
| `dds.qos:qos-deadline` | DEADLINE period (`qos-duration`) | `+duration-infinite+` |
| `dds.qos:qos-latency-budget` | LATENCY_BUDGET duration (`qos-duration`) | `+duration-zero+` |
| `dds.qos:qos-ownership` | OWNERSHIP kind — `:shared` or `:exclusive` | `:shared` |
| `dds.qos:qos-ownership-strength` | OWNERSHIP_STRENGTH (integer) | `0` |
| `dds.qos:qos-transport-priority` | TRANSPORT_PRIORITY (`(signed-byte 32)`, DDS 1.4 §2.2.3.13) — writer-local hint; **not** an RxO policy, **not** SEDP-propagated. Anchors the flow-controller `:priority` scheduling policy (see Transports). | `0` |
| `dds.qos:qos-liveliness` | LIVELINESS kind — `:automatic`, `:manual-by-participant`, `:manual-by-topic` | `:automatic` |
| `dds.qos:qos-liveliness-lease` | LIVELINESS lease duration (`qos-duration`) | `+duration-infinite+` |
| `dds.qos:qos-destination-order` | DESTINATION_ORDER kind — `:by-reception-timestamp` or `:by-source-timestamp` | `:by-reception-timestamp` |
| `dds.qos:qos-presentation-scope` | PRESENTATION access scope — `:instance`, `:topic`, `:group` | `:instance` |
| `dds.qos:qos-presentation-coherent` | PRESENTATION `coherent_access` flag | `nil` |
| `dds.qos:qos-presentation-ordered` | PRESENTATION `ordered_access` flag | `nil` |
| `dds.qos:qos-data-representation` | DATA_REPRESENTATION list (XTypes 1.3 §7.6.3.1.1). Writer: the *offered* representation is `(first …)`. Reader: the *set* of accepted representations. The base `make-qos` default is `(:xcdr1)` (it models a peer that elides `PID_DATA_REPRESENTATION`); the role-aware constructors advertise the truth — see below. | `(:xcdr1)` |
| `dds.qos:qos-partition` | PARTITION — a list of partition-name strings | `()` |
| `dds.qos:qos-autodispose-unregistered-instances` | WRITER_DATA_LIFECYCLE `autodispose_unregistered_instances` (writer-local, non-RxO, §2.2.3.21) — `t` makes a writer's `unregister_instance` also dispose the instance | `t` |
| `dds.qos:qos-autopurge-nowriter-samples-delay` | READER_DATA_LIFECYCLE `autopurge_nowriter_samples_delay` (reader-local, non-RxO, §2.2.3.22) — delay after which a `NOT_ALIVE_NO_WRITERS` instance's samples + resources are purged. `+duration-infinite+` = never purge | `+duration-infinite+` |
| `dds.qos:qos-autopurge-disposed-samples-delay` | READER_DATA_LIFECYCLE `autopurge_disposed_samples_delay` (reader-local, non-RxO, §2.2.3.22) — delay after which a `NOT_ALIVE_DISPOSED` instance's samples + resources are purged. `+duration-infinite+` = never purge | `+duration-infinite+` |
| `dds.qos:qos-history-kind` | HISTORY kind (held, non-RxO) — `:keep-last` or `:keep-all` | `:keep-last` |
| `dds.qos:qos-history-depth` | HISTORY depth (held, non-RxO) | `1` |
| `dds.qos:qos-lifespan` | LIFESPAN duration (held, non-RxO) | `+duration-infinite+` |
| `dds.qos:qos-resource-max-samples` | RESOURCE_LIMITS `max_samples` (`-1` = `LENGTH_UNLIMITED`) | `-1` |
| `dds.qos:qos-resource-max-instances` | RESOURCE_LIMITS `max_instances` (`-1` = `LENGTH_UNLIMITED`) | `-1` |
| `dds.qos:qos-resource-max-samples-per-instance` | RESOURCE_LIMITS `max_samples_per_instance` (`-1` = `LENGTH_UNLIMITED`) | `-1` |
| `dds.qos:qos-type-consistency` | TYPE_CONSISTENCY_ENFORCEMENT policy (a `type-consistency-enforcement`, reader-only, not RxO) | `(make-type-consistency-enforcement)` |
| `dds.qos:qos-writer-cache-high-watermark` / `-low-watermark` | RELIABLE_WRITER_CACHE watermarks (**vendor extension**, ADR 0089; writer-only, not RxO, not in SEDP) — unacknowledged-sample thresholds that open and close a backpressure episode; see below | `nil` (disabled) |
| `dds.qos:qos-acknowledgment-kind` | ACKNOWLEDGMENT_KIND (**vendor extension**, ADR 0090) — `:protocol` / `:application-auto` / `:application-explicit`; **RxO-checked by EQUALITY** between RELIABLE endpoints; see below | `:protocol` |

### Endpoint-flavoured constructors

| Symbol | Description |
|---|---|
| `dds.qos:make-writer-qos` | `(make-writer-qos &rest args)` — a `qos` with DataWriter defaults (RELIABILITY defaults to `:reliable`; DATA_REPRESENTATION defaults to `(:xcdr2)` — the offered representation TX serializes/sends, XTypes 1.3 §7.6.3.1.1); `args` override slots. |
| `dds.qos:make-reader-qos` | `(make-reader-qos &rest args)` — a `qos` with DataReader defaults (RELIABILITY defaults to `:best-effort`; DATA_REPRESENTATION defaults to `(:xcdr2 :xcdr1)` — the accepted set, XCDR2 preferred, XCDR1 read via the struct codec/FlatData transcode, XTypes 1.3 §7.6.3.1.1); `args` override slots. |

### HISTORY: per-instance KEEP_LAST (DDS 1.4 §2.2.3.18)

HISTORY governs how many samples an endpoint retains. **`KEEP_LAST` keeps the last `depth` values of
*each instance*** (each topic key), not a global last-`depth` — so one fast-writing key can never starve
another. This holds on **both sides**: the writer's `HistoryCache` keeps the last `depth` changes of each
key (for reliable retransmit / late-joiners), and the DataReader's cache keeps the last `depth` samples of
each key (a lossy *drop* of an instance's oldest, distinct from the RESOURCE_LIMITS *reject*). `KEEP_ALL`
retains every sample, bounded only by RESOURCE_LIMITS (`max_samples`). An **unkeyed** (NO_KEY) type has a
single instance, so KEEP_LAST collapses to a global last-`depth`.

**Default + opt-out.** The generic default is the spec value **`KEEP_LAST` depth 1** (the QoS table above) —
an unconfigured writer/reader keeps the latest sample per key. Where you need full retention (a burst-then-
drain pattern, a late joiner that must catch up on more than the latest per key, or a test that writes more
than `depth` and expects all retained), set **`KEEP_ALL`** explicitly (e.g. `make-writer-qos :history-kind
:keep-all`, or `dds.disc:enable-publisher … :history-kind :keep-all` at the engine layer).

```lisp
;; A keyed KEEP_LAST depth-2 writer keeps the LAST 2 samples of EACH key.
;; Writing 3 samples for key "A" then 1 for key "B" retains {A2,A3} AND {B1} —
;; a global last-2 would have wrongly dropped A's history when B wrote.
(let ((w (dds.dcps:create-datawriter
          pub topic :qos (dds.qos:make-writer-qos :history-kind :keep-last :history-depth 2))))
  (dds.dcps:write-sample w (make-keyed-sample :key "A" :v 1))
  (dds.dcps:write-sample w (make-keyed-sample :key "A" :v 2))
  (dds.dcps:write-sample w (make-keyed-sample :key "A" :v 3))   ; A@1 evicted; A keeps {2,3}
  (dds.dcps:write-sample w (make-keyed-sample :key "B" :v 1)))  ; B keeps {1}, A untouched
```

**GAP interaction (RTPS 2.5 §8.3.7.4).** Per-instance eviction can remove an **interior** sequence number
(depth 1: write A@1, B@2, B@3 → evicting B's oldest SN2 leaves a hole at SN2 inside `[firstSN, lastSN]`). A
reliable reader that NACKs the evicted SN receives a **GAP** marking it irrelevant (sent by the writer data
plane, wired in both directions) — so the reader advances its ACK past the hole instead of NACKing forever;
low-end evictions are additionally covered by the HEARTBEAT `firstSN` advance. See
[rtps-engine](rtps-engine.md) (HistoryCache + GAP) and [ADR 0019](../adr/0019-perinstance-keeplast.md). The
writer-side per-instance machinery cost is benched honestly in `bench/report/2026-06-16-wp-keeplast.md`
(`make bench-keeplast`): a keyed KEEP_LAST writer adds ~16-octet keyhash/sample + the index cons (freed on
evict); KEEP_ALL and unkeyed stay as before (NO 0-cost claim).

### Backpressure: block up to `max_blocking_time` (RELIABILITY × RESOURCE_LIMITS)

DDS-standard **block-up-to-`max_blocking_time`** flow control (WP-ASYNC-FLOW, FR-PF-2/FR-QOS,
[ADR 0016](../adr/0016-async-flow-control.md) §Backpressure). When a **reliable** writer's HistoryCache is
**HISTORY KEEP_ALL** with a finite **RESOURCE_LIMITS `max_samples`** and **full**, a write
(`publish-sample` / `write-sample` / dispose / unregister) **blocks** on a space-available condvar for up to
**RELIABILITY `max_blocking_time`**, then returns **`RETCODE_TIMEOUT`** (the `:timeout` sentinel;
`dds.dcps:+retcode-timeout+`) with the cache **intact** and **no sequence number consumed**. Space becomes
available — and the blocked write wakes — when the cache shrinks: a KEEP_ALL cache shrinks only on the
**ACKNACK purge** (`writer-purge-acked`, the slowest reader having acknowledged, §8.4.1), plus
**controller teardown** (so a blocked publish reaches its `:timeout` once the paced drain stops).
`max_blocking_time = 0` ⇒ **immediate** `:timeout` when full (the non-blocking
degenerate). The bound applies to **all** changes (data + dispose/unregister), each occupying a SN.

This is the standard RELIABILITY behaviour, **wire-invisible** and **additive on conforming RTPS** — it
changes only *when* (or whether) a write proceeds, never the submessage bytes. The bound is **per-writer**
(each writer's cache); paired with a `flow-controller` (which paces the aggregate drain rate) it keeps the
backlog bounded (NFR-MEM) regardless of how slow the drain or the readers are. **Wiring:** the engine reads
`max_samples` + `max_blocking_time` via `dds.disc:enable-publisher`'s `:max-samples` / `:max-blocking-ns`
keywords (both `nil` by default ⇒ **unlimited cache, no blocking** — byte-identical to a writer with no
bound). The DCPS `write-sample` / `dispose-instance` / `unregister-instance` surface `+retcode-timeout+`.

### RxO compatibility

`dds.qos:qos-rxo-compatible` — `(qos-rxo-compatible offered requested)` decides RxO
compatibility of an OFFERED (writer) QoS against a REQUESTED (reader) QoS per DDS 1.4
§2.2.3. It returns **two values**: `(values compatible-p incompatible)`, where
`compatible-p` is a boolean and `incompatible` is the ordered list of policy keywords that
failed. A non-empty list is exactly the set of policies that would raise
OFFERED/REQUESTED_INCOMPATIBLE_QOS and block the endpoint match. The rule per policy class:

- **Kind-ordered** (`:reliability`, `:durability`, `:liveliness`, `:destination-order`,
  `:presentation`): the offered ordinal rank must be `>=` the requested rank.
- **Duration** (`:deadline`, `:latency-budget`, and the liveliness lease): offered
  duration must be `<=` requested.
- **`:ownership`**: the kinds must be *equal*.
- **`:data-representation`**: the writer's offered representation `(first offered)` must be a
  member of the reader's accepted-representation set.

(PARTITION is **not** checked here — see `partition-match-p` below.)

### Partition matching

`dds.qos:partition-match-p` — `(partition-match-p a b)` is true when the two partition lists
overlap (DDS 1.4 §2.2.3 PARTITION). An empty partition list denotes the default partition,
which matches another empty list. A partition mismatch silently prevents matching and is
**not** an RxO incompatibility (no status is raised). v1 does exact name matching;
wildcard/`fnmatch` names are a later increment (see [Notes / status](#notes--status)).

### `TYPE_CONSISTENCY_ENFORCEMENT` policy

`dds.qos:type-consistency-enforcement` (constructor `dds.qos:make-type-consistency-enforcement`,
copier `dds.qos:copy-type-consistency-enforcement`) is the XTypes 1.3 §7.6.3.4 policy
(policy id 24). It applies to **DataReaders only**, has **no** request/offered semantics, and
is therefore deliberately absent from `qos-rxo-compatible`. Its `kind` selects coercion vs
equivalence; the four boolean flags modulate `ALLOW_TYPE_COERCION` assignability. Fields and
their defaults per §7.6.3.4.1:

| Accessor | Meaning | Default |
|---|---|---|
| `dds.qos:type-consistency-enforcement-kind` | `:allow-type-coercion` or `:disallow-type-coercion` | `:allow-type-coercion` |
| `dds.qos:type-consistency-enforcement-ignore-sequence-bounds` | ignore sequence bounds during assignability | `t` |
| `dds.qos:type-consistency-enforcement-ignore-string-bounds` | ignore string bounds during assignability | `t` |
| `dds.qos:type-consistency-enforcement-ignore-member-names` | match members by ID only, not name | `nil` |
| `dds.qos:type-consistency-enforcement-prevent-type-widening` | forbid a wider writer type building a narrower reader type | `nil` |
| `dds.qos:type-consistency-enforcement-force-type-validation` | require type info to be present in order to match | `nil` |

The enforcement *decision* (assignability vs structural equivalence) lives in the type system —
see `enforce-type-consistency` on the [Type system](type-system.md) page; this policy is just
the value carrier the reader holds.

One caveat, recorded in **ADR 0057**: against a peer that advertises its type *only* via the legacy
`PID_TYPE_OBJECT_LB` (a stock Connext peer — no `PID_TYPE_INFORMATION`, no TCE on the wire), an
explicit `:disallow-type-coercion` **cannot be honoured soundly** and is downgraded to assignability
with all bounds ignored. A legacy TypeObject's bounds are a code-generator artifact (`rtiddsgen`
silently bounds an unbounded `string` at 255), so judging *equivalence* from one would reject a peer
using the very same type. Structure (members, ids, kinds, key flags) still gates normally.

### DISCOVERY_CONFIG (vendor extension) — announce cadence + announced lease

DDS 1.4 standardizes **no** discovery-cadence policy, so — as every vendor does — this stack supplies
one as an extension. It is **participant-scoped** (ignored on any other entity), has **no** RxO
semantics, is never advertised in SEDP, and is **changeable**: `set_qos` re-applies both fields live
(no restart). Because it carries no OMG `QosPolicyId_t`, an inconsistency reports
`+qos-policy-id-invalid+` rather than an invented id.

| Accessor | Meaning | Default |
|---|---|---|
| `dds.qos:qos-discovery-announce-period` | How often an `:autonomous` participant's background announcer re-sends SPDP + SEDP and runs the lease/liveliness/autopurge sweeps | `{1, 0}` (1 s) |
| `dds.qos:qos-discovery-lease-duration` | The `leaseDuration` we announce in SPDP (`PID_PARTICIPANT_LEASE_DURATION`): how long a peer keeps us alive after our last announcement before pruning us as stale (RTPS 2.5 §8.5.3.3.2) | `{100, 0}` (100 s) |

The lease default is the **spec** default (RTPS 2.5 Table 9.18), so the wire is unchanged unless you
change it. The announce-period default (1 s) is deliberately *more frequent* than the RTPS 2.5 §9.6.2.4
default announcement rate (`resendPeriod = {30, 0}`), trading a little metatraffic for prompt discovery;
announcing more often than a peer requires is always interop-safe.

**Consistency rule:** the announce period must be finite, positive, and **strictly shorter than** the
announced lease — otherwise peers would age this participant out *between its own announcements* and it
would flap in and out of every peer's discovery set. Violating it yields `INCONSISTENT_POLICY`.

```lisp
;; announce every 250 ms, tell peers to prune us if silent for 5 s
(dds.dcps:create-participant
  :domain 0 :autonomous t
  :qos (dds.qos:make-qos
         :discovery-announce-period (dds.qos:make-qos-duration 0 250000000)
         :discovery-lease-duration  (dds.qos:make-qos-duration 5 0)))
```

### RELIABLE_WRITER_CACHE watermarks (vendor extension, ADR 0089) — backpressure episodes

The second vendor extension, and the same shape as the first: **DataWriter-scoped** (ignored on any
other entity), **no** RxO semantics, never advertised in SEDP, and no OMG `QosPolicyId_t`, so an
inconsistency reports `+qos-policy-id-invalid+` rather than an invented id.

| Accessor | Meaning | Default |
|---|---|---|
| `dds.qos:qos-writer-cache-high-watermark` | Unacknowledged samples at which a **backpressure episode opens** — the writer's send window has built up | `nil` (disabled) |
| `dds.qos:qos-writer-cache-low-watermark` | Unacknowledged samples at which an open episode **closes** — the writer has recovered | `nil` (disabled) |

They are the thresholds behind the vendor `RELIABLE_WRITER_CACHE_CHANGED` status (see
[DCPS](dcps.md#vendor-extension-statuses-adr-0080-adr-0089)). Rising to the high watermark opens an
episode; falling to the low watermark, or draining to empty, closes one. **The low and empty
transitions fire only inside an open episode** — otherwise a reliable writer with one sample in flight
would report a drain to zero on *every* sample, which is an application callback on the data path saying
nothing.

**Consistency rule:** when both are set, low must be **strictly below** high — equal thresholds leave no
hysteresis band, so a single sample sitting on the boundary satisfies both crossing tests at once.
Violating it yields `INCONSISTENT_POLICY`. Either one left `nil` disables the episode machinery and is
trivially consistent.

**Why the default is disabled, unlike Connext.** RTI documents `low_watermark = 0`,
`high_watermark = 1` for the corresponding `DataWriterProtocol` fields. There the pair primarily drives
an *internal* mode — the switch to `fast_heartbeat_period` — and the status change costs two counter
increments. Here it drives an *application callback*, and at `{0, 1}` an exchange with one sample in
flight crosses high on every write and low on every acknowledgement: two invocations per sample. A
status whose purpose is to announce backpressure must be silent when there is none, so this stack
diverges deliberately. Disabled, the status still reports the FULL transition and still tracks its
levels, so `get-reliable-writer-cache-changed-status` stays useful at all times.

```lisp
;; tell me when 500 samples are outstanding, and again when it recovers to 50
(dds.dcps:create-datawriter
  pub topic
  :qos (dds.qos:make-writer-qos
         :reliability :reliable :history-kind :keep-all
         :writer-cache-high-watermark 500
         :writer-cache-low-watermark  50))
```

### ACKNOWLEDGMENT_KIND (vendor extension, ADR 0090) — and why it is RxO-checked by EQUALITY

The third vendor extension, and the **only one of the three that participates in RxO**. DDS 1.4 defines
no application acknowledgment at all — an exhaustive search of RTPS 2.5 finds nothing, and the DCPS IDL
has only `wait_for_acknowledgments`, which is protocol-level — so this mirrors RTI's
`DDS_ReliabilityQosPolicy.acknowledgment_kind`. It is effective only when RELIABILITY is `:reliable`.

| `dds.qos:qos-acknowledgment-kind` | when a sample counts as acknowledged |
|---|---|
| `:protocol` *(default)* | by the RTPS protocol — today's behaviour, unchanged |
| `:application-auto` | when the subscribing application **accesses** it (`read`/`take`) |
| `:application-explicit` | only on an explicit `acknowledge-sample` / `acknowledge-all` |

**Every other ordered policy has a safe direction** — a stronger offer satisfies a weaker request. This
one has **none**, because the two mismatches fail in *opposite* ways and neither announces itself:

| mismatch | what happens |
|---|---|
| writer `:protocol` ← reader `:application-*` | the writer purges on protocol acks alone, so the reader believes it holds an end-to-end guarantee it does not have — **silent data loss** |
| writer `:application-*` ← reader `:protocol` | the writer waits for acknowledgments that reader will never send; its history grows until RESOURCE_LIMITS blocks or rejects — **silent stall** |

Neither is recoverable at runtime, so a mismatch is **refused at match time** and reported as
`INCOMPATIBLE_QOS` — the one outcome an operator can see and act on. (OWNERSHIP is checked by equality
for the same structural reason.) Two *different* application kinds do not match either: when a sample
becomes acknowledged is precisely what they disagree about.

**Best-effort endpoints are exempt.** A BEST_EFFORT pair acknowledges nothing whatever either side asked
for, so refusing that match would block endpoints that cannot possibly disagree.

Being a vendor policy it carries **no OMG `QosPolicyId_t`**, so the incompatible-QoS status reports
`+qos-policy-id-invalid+` rather than an invented id that could collide with a future OMG assignment —
the same convention DISCOVERY_CONFIG and the watermarks follow. The failing policy is still named in
keyword form, so it is identifiable.

```lisp
;; both sides must agree, or they will not match
(dds.dcps:create-datawriter pub topic
  :qos (dds.qos:make-writer-qos :reliability :reliable
                                :acknowledgment-kind :application-explicit))
(dds.dcps:create-datareader sub topic
  :qos (dds.qos:make-reader-qos :reliability :reliable
                                :acknowledgment-kind :application-explicit))
```

## Examples

All examples are adapted from passing tests: `run-qos-rxo-test` (in `src/dds-qos/qos.lisp`)
and `run-dcps-incompatible-qos-test` / `run-assignability-test` (in
`src/dds-tests/integration-test.lisp`).

### Build a writer and a reader QoS

```lisp
(ql:quickload :dds-qos)

;; make-writer-qos defaults RELIABILITY to :reliable; make-reader-qos to :best-effort.
;; Extra keyword args override individual slots.
(let ((w (dds.qos:make-writer-qos))
      (r (dds.qos:make-reader-qos :durability :transient-local)))
  (values (dds.qos:qos-reliability w)            ; => :reliable
          (dds.qos:qos-reliability r)            ; => :best-effort
          (dds.qos:qos-durability  r)))          ; => :transient-local
```

### DATA_REPRESENTATION — bind a writer to XCDR1, and what it does on the wire

```lisp
;; A writer OFFERS a single representation (it serializes/sends in it); a reader ACCEPTS a set.
;; The role-aware defaults advertise the truth in SEDP (PID_DATA_REPRESENTATION 0x0073,
;; XTypes 1.3 §7.6.3.1.1): writer -> (:xcdr2), reader -> (:xcdr2 :xcdr1).
(dds.qos:qos-data-representation (dds.qos:make-writer-qos))   ; => (:XCDR2)   offered
(dds.qos:qos-data-representation (dds.qos:make-reader-qos))   ; => (:XCDR2 :XCDR1) accepted set

;; Bind a writer to XCDR1 (e.g. to serve a fixed-size @final peer whose reader accepts XCDR1 only,
;; as RTI Connext and Fast DDS Shapes readers do). The writer then SERIALIZES + SENDS XCDR1-LE:
;; the SerializedPayload encapsulation id is PLAIN_CDR_LE (0x0001), vs the default PLAIN_CDR2_LE (0x0007).
(let ((w (dds.qos:make-writer-qos :data-representation '(:xcdr1))))
  (dds.qos:qos-data-representation w))                        ; => (:XCDR1)

;; RxO (DDS 1.4 §2.2.3 / XTypes 1.3 §7.6.3.1.1): the writer's OFFERED rep (first of its list) must be
;; a member of the reader's accepted set. Our reader accepts both, so either writer matches it:
(dds.qos:qos-rxo-compatible (dds.qos:make-writer-qos :data-representation '(:xcdr1))
                            (dds.qos:make-reader-qos))        ; => T,   NIL  (XCDR1 ∈ {XCDR2,XCDR1})
(dds.qos:qos-rxo-compatible (dds.qos:make-writer-qos)         ; offers (:xcdr2)
                            (dds.qos:make-reader-qos))        ; => T,   NIL  (XCDR2 ∈ {XCDR2,XCDR1})

;; A reader that accepts XCDR1 ONLY correctly REJECTS a default (:xcdr2) writer — a TRUE incompatibility
;; (OFFERED/REQUESTED_INCOMPATIBLE_QOS, policy id 23), NOT a false-reject. Bind the writer to (:xcdr1)
;; to serve such a peer (this is exactly the live Connext/Fast DDS Shapes-reader case).
(dds.qos:qos-rxo-compatible (dds.qos:make-writer-qos)                          ; offers (:xcdr2)
                            (dds.qos:make-reader-qos :data-representation '(:xcdr1)))
;; => NIL, (:DATA-REPRESENTATION)
```

The RX side decodes whichever standard representation the encapsulation header declares
(`PLAIN_CDR_LE`/`_BE` → XCDR1, `PLAIN_CDR2_LE`/`_BE` → XCDR2), so a reader accepting `(:xcdr2 :xcdr1)`
reads either representation a peer wrote. The representation applies ONLY to the user-data payload —
never to the keyhash (always XCDR2-BE, RTPS 2.5 §9.6.4.8) or discovery. See ADR 0020 and
`interop/data-representation/README.md` for the live wire proof.

### Check RxO — a compatible and an incompatible pair

```lisp
;; Compatible: a RELIABLE writer satisfies a BEST_EFFORT reader (offered rank >= requested).
;; qos-rxo-compatible returns (values compatible-p incompatible-policy-list).
(dds.qos:qos-rxo-compatible (dds.qos:make-writer-qos)
                            (dds.qos:make-reader-qos))
;; => T, NIL          ; compatible, no incompatible policies

;; Incompatible: a VOLATILE writer cannot satisfy a reader requesting TRANSIENT_LOCAL
;; (offered durability rank < requested). This is the case run-dcps-incompatible-qos-test
;; drives end-to-end into REQUESTED/OFFERED_INCOMPATIBLE_QOS.
(dds.qos:qos-rxo-compatible (dds.qos:make-qos :durability :volatile)
                            (dds.qos:make-qos :durability :transient-local))
;; => NIL, (:DURABILITY)

;; Multiple simultaneous failures are all reported (order-independent set):
(nth-value 1
  (dds.qos:qos-rxo-compatible
    (dds.qos:make-qos :reliability :best-effort :ownership :shared)
    (dds.qos:make-qos :reliability :reliable    :ownership :exclusive)))
;; => (:RELIABILITY :OWNERSHIP)
```

### Partition matching (gates the match, no status)

```lisp
;; Empty (default) partitions match each other.
(dds.qos:partition-match-p (dds.qos:make-qos) (dds.qos:make-qos))           ; => T

;; Overlapping name lists match; disjoint ones do not.
(dds.qos:partition-match-p (dds.qos:make-qos :partition '("A" "B"))
                           (dds.qos:make-qos :partition '("B")))            ; => T
(dds.qos:partition-match-p (dds.qos:make-qos :partition '("A"))
                           (dds.qos:make-qos :partition '("B")))            ; => NIL
```

### TYPE_CONSISTENCY_ENFORCEMENT defaults

```lisp
;; The policy's spec defaults (XTypes 1.3 §7.6.3.4.1), as checked by run-assignability-test.
(let ((tce (dds.qos:make-type-consistency-enforcement)))
  (list (dds.qos:type-consistency-enforcement-kind tce)                     ; :ALLOW-TYPE-COERCION
        (dds.qos:type-consistency-enforcement-ignore-sequence-bounds tce)   ; T
        (dds.qos:type-consistency-enforcement-ignore-string-bounds tce)     ; T
        (dds.qos:type-consistency-enforcement-ignore-member-names tce)      ; NIL
        (dds.qos:type-consistency-enforcement-prevent-type-widening tce)    ; NIL
        (dds.qos:type-consistency-enforcement-force-type-validation tce)))  ; NIL

;; A reader QoS carries it by default:
(dds.qos:type-consistency-enforcement-kind
 (dds.qos:qos-type-consistency (dds.qos:make-reader-qos)))                  ; => :ALLOW-TYPE-COERCION
```

## Notes / status

- **RxO-relevant policies** (checked by `qos-rxo-compatible`): RELIABILITY, DURABILITY,
  DEADLINE, LATENCY_BUDGET, OWNERSHIP, LIVELINESS (kind + lease), DESTINATION_ORDER,
  PRESENTATION (scope + the coherent/ordered flags), and DATA_REPRESENTATION.
- **Held (non-RxO) policies** carried for completeness but not part of compatibility:
  HISTORY (kind + depth), LIFESPAN, RESOURCE_LIMITS (`max_samples` /
  `max_instances` / `max_samples_per_instance`), OWNERSHIP_STRENGTH,
  WRITER_DATA_LIFECYCLE (`autodispose_unregistered_instances`), and
  TYPE_CONSISTENCY_ENFORCEMENT.
- **WRITER_DATA_LIFECYCLE is writer-local (DDS 1.4 §2.2.3.21, default TRUE).** With
  `autodispose_unregistered_instances` TRUE a `DataWriter::unregister_instance` also disposes the
  instance (the reader reports `NOT_ALIVE_DISPOSED`); FALSE leaves it at `NOT_ALIVE_NO_WRITERS`. It is
  not advertised in SEDP and excluded from `qos-rxo-compatible`.
- **READER_DATA_LIFECYCLE is reader-local (DDS 1.4 §2.2.3.22, both delays default INFINITE).** The two
  `autopurge_*_samples_delay` durations control when a DataReader purges all internal information +
  untaken samples for a `NOT_ALIVE` instance: `autopurge_disposed_samples_delay` after it became
  `NOT_ALIVE_DISPOSED`, `autopurge_nowriter_samples_delay` after it became `NOT_ALIVE_NO_WRITERS`. Both
  default `+duration-infinite+`, so **by default nothing is ever purged** (the common case is a no-op).
  Reader-local: not advertised in SEDP and excluded from `qos-rxo-compatible`. See the
  [DCPS page](dcps.md) for the purge mechanics.
- **PARTITION gates matching but raises no status.** It is excluded from
  `qos-rxo-compatible` and handled by `partition-match-p`; a mismatch silently prevents the
  match. Per the source docstring, **wildcard / `fnmatch` partition names are a later
  increment — v1 matches names exactly.**
- **TYPE_CONSISTENCY_ENFORCEMENT is reader-only and deliberately excluded from RxO.** It has
  no request/offered semantics and is immutable after enable; the actual enforcement
  decision (assignability under `:allow-type-coercion` vs structural equivalence under
  `:disallow-type-coercion`) is made by the [type system](type-system.md), not here.
- **The QoS set is the RxO-relevant + commonly-held subset, not yet the full 22+2 policies.**
  The source notes the remaining policies are filled in as the entity model lands.
- The `reliability-max-blocking` slot exists on the `qos` struct (default `100 ms`, used for
  RELIABILITY `max_blocking_time`) but its accessor is **not currently exported**, so it is
  omitted from the API reference above.

## See also

- [DCPS — the DDS entity API](dcps.md) — where RxO failures surface as
  REQUESTED/OFFERED_INCOMPATIBLE_QOS statuses + listeners.
- [Type system & code generation](type-system.md) — assignability and `enforce-type-consistency`.
- [Discovery](discovery.md) — SEDP endpoint matching driven by `qos-rxo-compatible` +
  `partition-match-p`.
