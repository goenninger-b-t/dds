# DCPS — the DDS entity API

`dds-dcps` (package nickname `dds.dcps`) is the **DDS 1.4 application API** (layer L6): the
CLOS entity model — `DomainParticipant`, `Publisher`/`Subscriber`, `Topic`,
`DataWriter`/`DataReader` — sitting over the RTPS engine and discovery
([Discovery](discovery.md)). It is control-plane, so it is CLOS throughout; the *typed*
`write`/`read`/`take` path reaches the monomorphic XCDR codec through the `type-support`
vtable stored on the `Topic` (see [Type system](type-system.md)). One simplification holds in
v1: **discovery is caller-driven** — you call `dds.dcps:spin` to drive each
SPDP/SEDP announcement cycle (there is no background announcer yet). RxO QoS compatibility
gates matching and delivery; see [QoS](qos.md).

**Multiple DataWriters per participant (WP-N-ENDPOINT-S1, ADR 0048).** A participant may
carry **N non-secured `DataWriter`s** on different topics — each gets a distinct `EntityId`
(and SEDP GUID), publishes into its own HistoryCache, and repairs independently (an inbound
ACKNACK/NACK_FRAG routes to the addressed writer by its `writerId`). At N=1 the wire and timing
are byte-identical to before. A 2nd DataWriter under an associated **flow-controller** is **supported**
(Slice S1b, WP-N-ENDPOINT-S1B-FLOW): the controller drives ALL of a participant's writers as per-writer
selection entries, rate-paced at the shared aggregate with EDF/priority ordering across them. **Two or more
SAME-topic DataWriters on one participant are now supported** (Slice 2c-2, WP-N-ENDPOINT-2C2-WRITERS, ADR 0048
§16): each gets a distinct `EntityId`/SEDP GUID (S1), and — via the matched-LOCAL EntityId threaded through the
match hook, fired per-(local,remote) pair — each same-topic writer gets its OWN `PUBLICATION_MATCHED`, its OWN
§8.5.2 crypto-token keyed to its EntityId (secured), and its OWN durability replay (`add-local-writer` fences B
[secured] + C [durable] LIFTED). A remote reader dedups the two by their distinct source GUIDs and receives both
streams.

**Multiple DataReaders per participant (WP-N-ENDPOINT-S2, ADR 0048).** A participant (Subscriber)
may carry **N non-secured `DataReader`s** on different topics — each gets a distinct `EntityId`
(and SEDP GUID) and receives ONLY its own topic's samples, byte-exactly deserialized under its
own type-support. Each received sample enters the node-global store keyed by its source-writer
GUID; a per-reader **matched-writer-GUID route** (built at endpoint match, purged on
unmatch/lease-expiry, re-added on re-announce) drives a source-GUID **filter** in the reader's
drain — so a reader never deserializes a sibling reader's bytes (the cross-topic-deserialize
corruption hazard is closed) — and the receive hooks **demux** each writer's DATA/HEARTBEAT to the
engine reader matched to it (so ACKNACKs carry the correct reader id). At N=1 the wire and timing
are byte-identical to before. **Two or more DIFFERENT-topic non-secured readers are the supported
N-reader case.** N **loan-capable** (secured or zero-copy) DataReaders on **distinct** topics are
also supported (WP-N-ENDPOINT-S4, ADR 0048): the receive decode tier is per-reader (each decodes
under ITS OWN topic's protection kind) and the ZC marker path demuxes to the matched reader; the
cross-reader use-after-free is structurally unreachable (different-topic readers share no source-GUID
slot). **Same-topic NON-loan multi-reader (Slice 2c-1, WP-N-ENDPOINT-2C1-READERS, ADR 0048) is now
supported:** two or more SAME-topic NON-loan-capable `DataReader`s on one participant each receive the
writer's FULL stream. The endpoint match route-adds ALL matching local readers (route-add-all — the
delivery route holds a LIST), so both readers' EntityIds are routed to the writer's GUID; the per-reader
`dr-drained` high-water over the shared NON-purged store gives each reader the complete stream with **no
cross-consumption** (reader-A taking a sample never denies it to reader-B), and the HEARTBEAT hook fans
out one ACKNACK per matched reader-id (so a dropped sample is repaired for BOTH readers, each proxy's
ACKNACK serviced). **Same-topic per-endpoint STATUS is now complete (Slice 2c-2):** the match/unmatch/
incompatible hooks thread the matched-LOCAL EntityId (`%fire-match` → `%on-disc-match`) and resolve the DCPS
entity by that EntityId (`%participant-reader/writer-by-entity-id`), fired once per (local,remote) pair
(no double-count on SEDP re-announce; unmatch decrements the right endpoint), so BOTH same-topic readers AND
writers get their own `SUBSCRIPTION_MATCHED`/`PUBLICATION_MATCHED`/incompatible-QoS status counter + listener
callback. **`REQUESTED`/`OFFERED_INCOMPATIBLE_QOS` is fully per-pair** (WP-DDS-INCOMPAT-QOS-PERPAIR, ADR 0048
§16.3): the incompatible path COLLECTS one `(local-eid . bad)` entry per incompatible `(local,remote)` pair and
fires once per NEW pair, gated by `%record-incompat-pair`/`disc-node-incompat-pairs` (the exact mirror of the
match-pair path), so when BOTH same-topic locals are incompatible with one remote BOTH get the status (not just
the last), a LATE local created after the remote was recorded fires, a re-announce re-fires nothing, and a
re-discovery after unmatch/lease-expiry re-fires. `INCOMPATIBLE_QOS` (endpoint status) and `INCONSISTENT_TOPIC`
(Topic status) are **independent** (DDS 1.4 §2.2.4.1): a remote with a QoS-incompatible same-type local AND a
type-inconsistent local fires BOTH, and `disc-node-inconsistent` is purged on lease-expiry so a re-discovered
inconsistent remote re-fires. Also newly reachable: two same-topic-NAME readers of DIFFERENT
types both register (the fence is loan-capable-scoped), so a match fires `INCONSISTENT_TOPIC` for the
type-mismatched reader alongside `SUBSCRIPTION_MATCHED` for the compatible one (semantically correct, no
data hazard). **Same-topic LOAN-CAPABLE multi-reader (Slice 2c-3, WP-N-ENDPOINT-2C3-LOAN-UAF, ADR 0048/0017)
is now supported — the LAST same-topic fence is LIFTED and the N-user-endpoint milestone is COMPLETE in full
generality.** Two or more SAME-topic secured-decode / zero-copy `DataReader`s co-located on one participant
are memory-safe: the ADR-0017 cross-reader use-after-free is closed at its site — a **demux-time `%zc-bump` by
(ELIGIBLE−1)** in `%deliver-user-marker` (`ELIGIBLE = %count-eligible-drainers` = the route members that WILL
drain the marker, i.e. those whose frozen join-watermark is below its SN — the EXACT W-term of the `%drain` gate)
counts every co-located holder that will actually drain on the receiver thread BEFORE the marker is drainable (so
reader-A's `return-loan` can never free a slot reader-B still views; the slot frees only at the true refcount 0);
a **mid-stream-joiner ZC high-water freeze at MATCH time** (atomic with `%reader-route-add` under the node lock; the demux `{route-snapshot, ELIGIBLE, bump, store}` shares that lock) so a joiner never drains a marker delivered before it joined — closing the `[freeze,route-add]` window a registration-time freeze would leave open;
and a **secured store-purge-defer** (per-`(guid,SN)` return-count) frees the shared decode handle only after ALL
K readers return (no early-return sample-loss). K=1 (N=1 / different-topic) is byte-identical. A **FROZEN joiner**
(watermark ≥ SN, which its `%drain` skips) is EXCLUDED from `ELIGIBLE`, so its phantom +1 is never added — this
closes the **§17.7 out-of-order-across-join refcount LEAK** (WP-DDS-ZC-REFCOUNT-LEAK); memory-safety is preserved
because `ELIGIBLE` omits the unreachable dcps `dr-drained` term (which only RAISES the drain bar), making it a
SUPERSET of the true drainers that can never UNDER-count a drainer — an under-count would be the very cross-reader
UAF, strictly worse than the leak (`run-n-reader-2c3-zc-refcount-leak-test`, SBCL-only; ADR 0048 §17.7 now has no
open residuals).

**Per-endpoint status/listener dispatch (WP-N-ENDPOINT-S5, ADR 0048) — the milestone is COMPLETE.**
Every status counter, listener callback, and WaitSet/DATA_AVAILABLE wake is now delivered to the
`DataWriter`/`DataReader` the event is **about**, not to the last-created endpoint. The disc→DCPS
hooks resolve the local entity by the remote's **topic** (SUBSCRIPTION/PUBLICATION_MATCHED, unmatch,
REQUESTED/OFFERED_INCOMPATIBLE_QOS) or by the remote writer GUID's S2 **delivery route**
(LIVELINESS_CHANGED); an event with no matching local endpoint is dropped, never mis-delivered. The
two data-ready wakes (dispose/unregister lifecycle and new-data) carry no routable writer identity
from the disc layer, so they wake every local reader — the S2 source-GUID drain filter still governs
which reader actually sees which sample, so a spurious wake is a benign, permitted DATA_AVAILABLE.
The old single `dp-user-reader`/`dp-user-writer` back-refs are retired. At N=1 every path is
byte-identical. With this slice the **different-topic N-user-endpoint capability is complete**: N
writers + N readers per participant on distinct topics, including secured and loan-capable, each with
correct per-endpoint status and delivery. **Flow-ON multi-writer (Slice S1b) has since landed** (the
flow-controller drives all of a participant's writers). **Same-topic multi-reader (2c-1), same-topic
multi-WRITER + per-endpoint same-topic status (2c-2), and same-topic LOAN-CAPABLE multi-reader (2c-3, the
ADR-0017 refcount-per-reader UAF, closed at its site) have all landed — the N-user-endpoint milestone is
COMPLETE in full generality (same-topic + different-topic, all endpoint kinds).**

## API reference

All symbols below are exported from `dds.dcps`. One-line descriptions are condensed from the
source docstrings (`src/dds-dcps/*.lisp`); the docstrings are the contract.

### Lifecycle (participants, pub/sub, topics, endpoints)

| Symbol | Description |
|---|---|
| `dds.dcps:create-participant` (`&key domain qos advertise-address`) | Open the RTPS engine (a multicast disc-node) for `domain`, install the status hooks, start the receiver, return an enabled `domain-participant`. |
| `dds.dcps:delete-participant` (`p`) | Delete the participant and its contained entities; stop the engine. |
| `dds.dcps:create-publisher` (`p`) | Create an enabled `publisher` (DataWriter factory) in `p`. |
| `dds.dcps:create-subscriber` (`p`) | Create an enabled `subscriber` (DataReader factory) in `p`. |
| `dds.dcps:create-topic` (`p name type-name type-support`) | Bind a topic `name` + `type-name` to a registered `type-support` (the generated codec bundle). |
| `dds.dcps:create-datawriter` (`pub topic &key qos`) | Register a local writer in the engine on the topic's name/type with `qos`. **N non-secured writers per participant** (WP-N-ENDPOINT-S1, ADR 0048): each gets a distinct `EntityId` + its own HistoryCache; a 2nd writer under a flow-controller is supported (Slice S1b — per-writer flow-state) and a 2nd secured writer is supported (Slice S3). The endpoint kind (`WITH_KEY`/`NO_KEY`) is selected from the topic type's keyed-ness. |
| `dds.dcps:create-datareader` (`sub topic &key qos`) | Register a local reader (N readers per participant on **distinct** topics, each a distinct `EntityId`; WP-N-ENDPOINT-S2/S4). `topic` may be a `topic` or a `content-filtered-topic`. The endpoint kind (`WITH_KEY`/`NO_KEY`) is selected from the topic type's keyed-ness. N **loan-capable** (secured or ZC) readers on distinct topics are supported (S4 — each decodes under its own tier; the ZC marker demuxes per reader). Two or more **SAME-topic** readers are supported — NON-loan (Slice 2c-1 — route-add-all: both receive the writer's full stream, no cross-consumption) AND **loan-capable** (secured / ZC; Slice 2c-3 — the ADR-0017 refcount-per-reader UAF is closed via the demux-time `%zc-bump` by (ELIGIBLE−1), `ELIGIBLE` = the route members that will drain the marker (`SN > join-watermark`) so a frozen joiner is excluded — the joiner high-water freeze + the secured store-purge-defer + the §17.7 out-of-order-across-join leak fix, WP-DDS-ZC-REFCOUNT-LEAK). |
| `dds.dcps:spin` (`p`) | Drive **one** discovery announcement cycle (SPDP + SEDP) for `p`. Caller-driven in v1. |
| `dds.dcps:discovered-count` (`p`) | Number of remote participants `p` has discovered. |
| `dds.dcps:matched-count` (`p`) | Number of remote endpoints matched against `p`'s local endpoints. |
| `dds.dcps:entity` / `domain-participant` / `publisher` / `subscriber` / `topic` / `data-writer` / `data-reader` | The CLOS entity classes (base `entity` carries QoS + the enabled flag). |
| `dds.dcps:entity-qos` (`e`) | The entity's QoS object. |
| `dds.dcps:entity-enabled-p` (`e`) | The entity's enabled flag. |

### QoS management (DDS 1.4 §2.2.4.1 / §2.2.3, WP-DCPS-API-COMPLETION S1)

| Symbol | Description |
|---|---|
| `dds.dcps:get-qos` (`entity`) | `Entity::get_qos` (DDS 1.4 §2.2.4.1) — return a **copy** of the entity's effective QoS. An entity created without an explicit QoS reports a fresh default. |
| `dds.dcps:set-qos` (`entity qos`) | `Entity::set_qos` (DDS 1.4 §2.2.4.1) — install `qos`, returning `:ok`, `:inconsistent-policy` (the §2.2.3.18/§2.2.3.19 cross-policy rules failed), or `:immutable-policy` (a §2.2.3-immutable policy changed while the entity is enabled). On a non-`:ok` code the QoS is left unchanged. |
| `dds.dcps:qos-policy-immutable-p` (`policy`) | `T` iff the QoS `policy` keyword is immutable-after-`enable` per the DDS 1.4 §2.2.3 per-policy "changeable" column (immutable: `:reliability` `:durability` `:presentation` `:ownership` `:liveliness` `:destination-order` `:history` `:resource-limits` `:data-representation` `:type-consistency`; every other policy is changeable). |
| `dds.dcps:+retcode-immutable-policy+` / `+retcode-inconsistent-policy+` | The `set_qos` return codes `:immutable-policy` / `:inconsistent-policy` (DDS 1.4 §2.2.4.4). |
| `dds.dcps:get-default-datawriter-qos` / `set-default-datawriter-qos` (`pub [qos]`) | Publisher default DataWriter QoS (DDS 1.4 §2.2.2.4.1), applied by `create-datawriter` when no explicit `:qos` is given. `set-` returns `:ok`/`:inconsistent-policy`. |
| `dds.dcps:get-default-datareader-qos` / `set-default-datareader-qos` (`sub [qos]`) | Subscriber default DataReader QoS (DDS 1.4 §2.2.2.5.1), applied by `create-datareader`. |
| `dds.dcps:get-default-topic-qos` / `-publisher-qos` / `-subscriber-qos` (`p [qos]`) | DomainParticipant default Topic/Publisher/Subscriber QoS (DDS 1.4 §2.2.2.2.2), applied by `create-topic`/`create-publisher`/`create-subscriber`. |
| `dds.dcps:get-default-participant-qos` / `set-default-participant-qos` (`[qos]`) | The DomainParticipantFactory default participant QoS (DDS 1.4 §2.2.2.2.2), applied by `create-participant`. Provisional module-level home until S2's factory singleton formalizes it. |

### Entity lifecycle (DDS 1.4 §2.2.2, WP-DCPS-API-COMPLETION S2, ADR 0052)

| Symbol | Description |
|---|---|
| `dds.dcps:get-participant-factory` / `get-instance` | `DomainParticipantFactory::get_instance` (DDS 1.4 §2.2.2.2.2) — the process-wide factory **singleton** (both names return the same object). |
| `dds.dcps:lookup-participant` (`factory domain`) | `DomainParticipantFactory::lookup_participant` — a registered participant on `domain`, or `nil`. `create-participant` registers with the factory; `delete-participant` unregisters. |
| `dds.dcps:participant-factory-autoenable-p` / `set-participant-factory-autoenable` (`factory [bool]`) | The factory's `ENTITY_FACTORY` `autoenable_created_entities` policy (DDS 1.4 §2.2.3.23) — `T` (default) auto-enables a participant at `create-participant`, `nil` creates it disabled. A **local** policy, never on the wire. |
| `dds.dcps:participant-publishers` / `-subscribers` / `-topics` (`p`) | Enumerate a DomainParticipant's contained Publishers / Subscribers / Topics (DDS 1.4 §2.2.2.2.1). Fresh lists. |
| `dds.dcps:publisher-datawriters` (`pub`) / `subscriber-datareaders` (`sub`) | Enumerate a Publisher's DataWriters / a Subscriber's DataReaders (DDS 1.4 §2.2.2.4.1 / §2.2.2.5.1). |
| `dds.dcps:entity-autoenable-created-entities` (`entity`) | An entity's own `ENTITY_FACTORY` `autoenable_created_entities` (DDS 1.4 §2.2.3.23) — governs whether the children IT creates are enabled at create (default `T`). |
| `dds.dcps:enable` (`entity`) | `Entity::enable` (DDS 1.4 §2.2.2.1.1.7) — transition to enabled; idempotent (`:ok`), `:precondition-not-met` if the factory-parent is still disabled. A **disabled** entity's data operations — `write-sample`, `register-instance`, `dispose-instance`, `unregister-instance`, `loan-sample`, `write-loaned`, `read-samples`, `take-samples` — return `:not-enabled`; the NOT_ENABLED-safe set (`get_qos`/`set_qos`/`enable`/`get_statuscondition`/`set_listener`) stays live. |
| `dds.dcps:delete-datawriter` / `delete-datareader` (`parent child`) | `Publisher::delete_datawriter` / `Subscriber::delete_datareader` (DDS 1.4 §2.2.2.4.1.5 / §2.2.2.5.1.5) — `:ok`, or `:precondition-not-met` if not contained. Returns/discards the child's outstanding loans, unregisters it from discovery + the engine (no use-after-free), disables it. |
| `dds.dcps:delete-publisher` / `delete-subscriber` / `delete-topic` (`p child`) | DomainParticipant child deletes (DDS 1.4 §2.2.2.2.1) — `:precondition-not-met` if the Publisher/Subscriber still holds endpoints, or the Topic is still referenced by an endpoint; else `:ok`. |
| `dds.dcps:delete-contained-entities` (`entity`) | Recursive teardown (DDS 1.4 §2.2.2.2.1.11 / §2.2.2.4.1.13 / §2.2.2.5.1.13) — a Publisher/Subscriber deletes its endpoints; a DomainParticipant empties+deletes Publishers, Subscribers, then Topics. Always `:ok`. |
| `dds.dcps:+retcode-not-enabled+` / `+retcode-precondition-not-met+` | The `:not-enabled` / `:precondition-not-met` return codes (DDS 1.4 §2.2.4.4). |

### Write / read / take + SampleInfo

| Symbol | Description |
|---|---|
| `dds.dcps:write-sample` (`dw sample`) | `DataWriter::write` — serialize `sample` via the topic type-support and publish it reliably to matched readers. |
| `dds.dcps:register-instance` (`dw sample`) | `DataWriter::register_instance` (DDS 1.4 §2.2.2.4.2.5) — register `sample`'s instance and return its 16-octet handle (the type-support key-hash; `HANDLE_NIL` for an unkeyed type). Writer-local; no wire message. |
| `dds.dcps:dispose-instance` (`dw sample-or-handle`) | `DataWriter::dispose` (DDS 1.4 §2.2.2.4.2.10) — dispose the instance (a sample or a registered handle); emits a no-payload dispose `DATA` (StatusInfo Disposed, RTPS 2.5 §9.6.4.9) over the reliable engine. Returns the handle. |
| `dds.dcps:unregister-instance` (`dw sample-or-handle`) | `DataWriter::unregister_instance` (DDS 1.4 §2.2.2.4.2.7) — unregister the instance over the reliable engine. Per `WRITER_DATA_LIFECYCLE.autodispose_unregistered_instances` (§2.2.3.21, default **TRUE**) the unregister also **disposes** the instance: the no-payload `DATA` carries StatusInfo `Disposed\|Unregistered` (0x03) so readers report `NOT_ALIVE_DISPOSED`; with autodispose `FALSE` it carries `Unregistered` (0x02) only. Returns the handle. |
| `dds.dcps:read-samples` (`dr &key states where`) | `DataReader::read` — return the cached samples whose sample-state is in `states` (default `(:read :not-read)` = ANY) and whose data satisfies `where`, **without** removing them; mark each `:read` and set its view-state. Returns a list of `cached-sample`. |
| `dds.dcps:take-samples` (`dr &key states where`) | `DataReader::take` — like `read-samples` but **removes** the returned samples from the cache. |
| `dds.dcps:samples-available` (`dr`) | Drain newly-received samples into the cache and return the cache size, **without** marking anything `:read` — for polling before a read/take. |
| `dds.dcps:take-loaned` (`dr`) | **WP-FLATDATA-ZC-LOAN literal-0-copy RX (FR-PF-3/4, R6, ADR 0017; NOT cleared for ship — pending counsel).** `DataReader::take` **by loan**: returns `(values DATA-LIST LOANS)`; for a `:flatdata` reader created with `dds.disc:*zerocopy-enabled*` on, each loaned sample is a `dds.types:flatdata-view` read **directly off the writer's SHMEM slot — literal 0 intra-host copies** (`<name>-<field>-fd` accessors), and `LOANS` is the list to hand back to `return-loan`. **Removes** the returned samples (mirrors `take-samples`). A copy-backed sample mixed in is delivered as today with a `NIL` loan slot. |
| `dds.dcps:read-loaned` (`dr`) | Like `take-loaned` but **leaves** the samples in the cache (mirrors `read-samples` vs `take-samples`). |
| `dds.dcps:return-loan` (`dr loans`) | `DataReader::return_loan` — release each loaned `flatdata-view` (`%zc-release` the slot, recycle the view). **Invalidates the view's cache entry**: since `read-loaned` leaves samples in the cache, returning a view also drops its cached sample, so a returned loan is **never re-read** (reading after return is a no-op, never a stale read of the next sample's recycled-slot bytes). **Idempotent / double-return-safe.** A leaked loan pins a slot → the writer's pool gracefully falls back to non-ZC. Reader-close (`delete-participant`) returns every outstanding loan (no leaked refcount). |
| `dds.dcps:loan-sample` (`dw`) | **WP-FLATDATA-LOAN-WRITE zero-copy TX loan (FR-PF-4, R6, ADR 0042; NOT cleared for ship — pending counsel).** `DataWriter` loan-write — the TX dual of `take-loaned`. Returns a `dds.dcps:writer-loan` the app fills via the existing `<name>-<field>-fd` setters. When the full ZC-TX eligibility holds (FlatData type, `+<name>-flatdata-size+` clears `*zerocopy-min-payload-bytes*`, the node has a writer pool, the writer is **not** wire-protected, SBCL) the loan is **slot-backed**: the sample is a `dds.types:flatdata-view` over a freshly-acquired pool slot, so the setters write **straight into shared memory** (no app→buffer copy). Otherwise it degrades **gracefully** to a `make-<name>-flatdata` octet-buffer — same API, no error. **Security (ADR 0036 Carry-10 + ADR 0042 §6):** a wire-protected (secured) writer NEVER gets a slot-backed loan, and — unlike the classic ZC path — `data_protection` is ALSO gated (the slot would hold pre-transform plaintext); both fail closed to the fallback sample. |
| `dds.dcps:write-loaned` (`dw loan`) | Publish the loaned sample. Slot-backed: `%zc-loan-commit` the slot, then publish with the change **carrying the pre-committed slot**: the send site emits the slot's 20-octet ref to the FIRST ZC-eligible destination with **no payload→slot copy** (the end-to-end 0-copy leg, ADR 0042 §5). For a **PIN-ELIGIBLE** writer (reliable + VOLATILE/finalized + a matched reliable reader, WP-ACKED-SLOT-PINNING ADR 0044) the committed slot is **PINNED** (a second refcount hold) until the full-ACK purge — so retransmission / non-ZC / extra-ZC destinations read the slot **on demand** and the per-write **retained-payload heap copy is eliminated**; an ineligible writer (or exhausted `*zc-pin-budget*`) materialises the RETAINED payload eagerly (one slot→heap copy), the always-correct fallback. Fallback (non-slot): exactly `write-sample`. Returns `+retcode-ok+` / `+retcode-timeout+` (same backpressure as `write-sample`). **Idempotent** (a re-write, or a write after `discard-loan`, is a no-op). |
| `dds.dcps:discard-loan` (`dw loan`) | Abandon the loan **without** publishing (slot-backed → `%zc-loan-abort` the slot: refcount→0, **no generation published**, invisible to every reader). **Idempotent / double-discard-safe.** |
| `dds.dcps:discard-all-loans` (`dw`) | Writer-close safety sweep — discard every outstanding writer-loan (mirrors `return-all-loans`) so no acquired-but-unpublished slot is left held. |
| `dds.dcps:cached-sample` | A read/take result element: the deserialized data + its `sample-info`. |
| `dds.dcps:cached-sample-data` (`cs`) | The deserialized sample struct out of a `cached-sample`. |
| `dds.dcps:cached-sample-info` (`cs`) | The `sample-info` out of a `cached-sample`. |
| `dds.dcps:sample-info` / `make-sample-info` | The DDS 1.4 `SampleInfo` struct + its constructor. |
| `dds.dcps:sample-info-sample-state` (`si`) | `:read` or `:not-read`. |
| `dds.dcps:sample-info-view-state` (`si`) | `:new` or `:not-new` (first access of the instance vs. later). |
| `dds.dcps:sample-info-instance-state` (`si`) | `:alive` / `:not-alive-disposed` / `:not-alive-no-writers` (DDS 1.4 §2.2.2.5.1.3) — the reader's per-instance state at the time `read`/`take` was called. A received `dispose` yields `:not-alive-disposed`; the last writer of an instance unregistering or vanishing yields `:not-alive-no-writers`; a later data sample revives it to `:alive`. |
| `dds.dcps:sample-info-instance-handle` (`si`) | The 16-octet instance handle (key-hash; `HANDLE_NIL` for an unkeyed type). |
| `dds.dcps:sample-info-valid-data` (`si`) | Whether the sample carries Data (DDS 1.4 §2.2.2.5.1.4). `t` for a normal data sample; `nil` for the **invalid-data** notification a dispose/unregister/no-writers transition produces — that sample carries only the `SampleInfo` (the new `instance-state`), no Data. The application MUST check `valid-data` before accessing `cached-sample-data`. |
| `dds.dcps:sample-info-source-timestamp` (`si`) | Source timestamp (v1: `nil`). |
| `dds.dcps:sample-info-publication-handle` (`si`) | Writer handle (v1: `nil`). |
| `dds.dcps:sample-info-sequence-number` (`si`) | Vendor extension: the RTPS writer sequence number of the sample. |
| `dds.dcps:sample-info-disposed-generation-count` / `-no-writers-generation-count` (`si`) | DDS 1.4 §2.2.2.5.1.5 per-instance generation counts: `disposed-generation-count` is incremented each time the instance transitions `NOT_ALIVE_DISPOSED -> ALIVE`, `no-writers-generation-count` each time it transitions `NOT_ALIVE_NO_WRITERS -> ALIVE`. Each sample's `SampleInfo` snapshots the counts. |
| `dds.dcps:sample-info-sample-rank` / `-generation-rank` / `-absolute-generation-rank` (`si`) | DDS ranks (v1: default `0`). |

#### Worked example — the literal-0-copy loan read (WP-FLATDATA-ZC-LOAN, ADR 0017; R6, NOT cleared for ship)

A `:flatdata t` reader on the same host as the writer, created while `dds.disc:*zerocopy-enabled*` is on, reads fields **straight off the writer's SHMEM slot** (literal 0 intra-host copies) via the explicit `take-loaned` / `return-loan` loan API (mirroring OMG DDS `take()` + `return_loan()`):

```lisp
(let ((dds.disc:*shmem-enabled* t) (dds.disc:*zerocopy-enabled* t))   ; arm ZC (default OFF, R6); same-host
  ;; ... a FlatData topic "fd-abc"; dr is a DataReader on it; the writer publishes fd over Zero-Copy ...
  (multiple-value-bind (samples loans) (dds.dcps:take-loaned dr)       ; borrow the samples BY REFERENCE
    (dolist (view samples)                                             ; each is a dds.types:flatdata-view (NOT a copy)
      (when (dds.types:flatdata-view-p view)                           ; (a copy-backed sample mixed in is a struct)
        (format t "a=~d b=~d c=~d~%"
                (fd-abc-a-fd view) (fd-abc-b-fd view) (fd-abc-c-fd view))))  ; 0-copy reads off the writer's slot SAP
    (dds.dcps:return-loan dr loans)))                                  ; RELEASE the slots (idempotent; reader-close also returns)
```

The slot is held by the writer's `refcount` from `%zc-loan` → the disc receiver-thread store (no release) → `take-loaned`'s `%zc-acquire-for-read` (no refcount inc) → the app's reads → `return-loan`'s `%zc-release`; **force-reclaim skips `refcount>0` slots**, so a held loan is never overwritten under the read (no UAF). The app **must** `return-loan` (a leaked loan pins a slot until the writer's pool gracefully falls back to non-ZC; reader-close returns any outstanding loan). Since WP-ZC-LOAN-LOCKFREE (R6, ADR 0018; **NOT cleared for ship — pending counsel**) the RX is **literal 0-alloc**: `%zc-acquire-for-read` is a **lock-free fenced read** (generation acquire-load → `dds.pal:fence :acquire` → validate → clamped read, no mutex, no copy) and `%zc-release` is a **lock-free `cas-sap-u32` refcount decrement** (it CASes the u32 refcount sub-field directly — 0-alloc at any generation, no combined-word bignum overlay; no mutex), so the loaned RX per-sample (acquire + read + return) consing is **literal 0 GC bytes/sample** — the progression `65552 → 79 → 31 → 0` (the prior mutex'd loan 31, the v1 single-copy ~79, the WP-ZEROCOPY-v1 sink ~65551), with the writer's O(slots) loan scan benched at several pool sizes (`make bench-zc-loan-lockfree`, `bench/report/2026-06-16-wp-zc-loan-lockfree.md`). The publish/acquire handshake is the generation as a release/acquire sync variable (`%zc-loan` writes payload → `fence :release` → generation-store LAST; the reader's generation acquire-load + `fence :acquire` then sees the payload — no torn read), and the `cas`-decrement's full barrier orders the reader's payload reads before `refcount→0` so the writer (which reclaims only `refcount==0`) never overwrites a slot mid-read. Honest (FR-LANG-7): the loan API still ADDS the explicit acquire/release calls + the app's return obligation — no `0-cost` claim. See the [type-system wiki](type-system.md) for the FlatData accessor surface. **SBCL only** (ZC + the `cas-sap-u32` / `load-sap-u32` PAL atomics, ADR 0013); with `*zerocopy-enabled*` off or a non-FlatData reader the read path is byte-identical to the copied delivery. **Follow-ups (not done):** the app-facing ZC loan-write API, keyed / variable-size FlatData over ZC; the writer-loan is now an **O(slots) scan** (the freelist was dropped, ADR 0018) — a lock-free freelist (CAS stack) to restore O(1) loan is a deferred follow-up; and the **loan-capable-reader sharing invariant** — the slot refcount is 1 per destination participant and the `zc-loan-marker` is stored once per source-GUID→SN, so two loan-capable readers **sharing one source-GUID→SN slot** would let the first `return-loan` (`refcount` 1→0) free a slot the second still views (a cross-reader use-after-free). Since **WP-N-ENDPOINT-S4** (ADR 0048) N loan-capable readers per `disc-node` on **distinct** topics are supported (disjoint source-GUIDs — no shared slot), and since **WP-N-ENDPOINT-2C3** (ADR 0048/0017) N **SAME-topic** loan-capable readers are ALSO supported: the shared-slot UAF is closed at its site by the **demux-time `%zc-bump` by (ELIGIBLE−1)** in `%deliver-user-marker` (`ELIGIBLE = %count-eligible-drainers` = the co-located holders that WILL drain the marker, `SN > join-watermark`; each counted before any `%zc-release`, so the slot frees only at the true refcount 0), the **mid-stream-joiner ZC high-water freeze at MATCH time** (atomic with `%reader-route-add` under the node lock, consulted by `%drain` as `max(dr-drained, join-watermark)` — a joiner never drains a marker delivered before it joined, closing the `[freeze,route-add]` window), and the **secured store-purge-defer** (per-`(guid,SN)` return-count — the shared decode handle is freed only after all K readers return). K=1 is byte-identical. A **frozen joiner** (`join-watermark ≥ SN`, which `%drain` skips) is EXCLUDED from `ELIGIBLE` — its phantom +1 is never added, closing the **§17.7 out-of-order-across-join refcount leak** (WP-DDS-ZC-REFCOUNT-LEAK); `ELIGIBLE` omits the disc-unreachable dcps `dr-drained` term (which only raises the drain bar) so it is a SUPERSET of the true drainers and never UNDER-counts a drainer (an under-count would be the UAF, worse than the leak) — SBCL-only `run-n-reader-2c3-zc-refcount-leak-test`.

#### Worked example — the zero-copy loan WRITE (WP-FLATDATA-LOAN-WRITE, ADR 0042; R6, NOT cleared for ship)

The TX dual: a `:flatdata t` writer on the same host as a ZC reader writes a sample **straight into its SHMEM pool slot** via `loan-sample` + the `<name>-<field>-fd` setters + `write-loaned` (mirroring a zero-copy `loan()` / `write()`), eliminating the app→buffer copy `write-sample` pays:

```lisp
(let ((dds.disc:*shmem-enabled* t) (dds.disc:*zerocopy-enabled* t))   ; arm ZC (default OFF, R6); same-host
  ;; ... a FlatData topic "fd-abc"; dw is a DataWriter on it ...
  (let* ((loan (dds.dcps:loan-sample dw))              ; borrow a writable sample (slot-backed when eligible)
         (s (dds.dcps:writer-loan-sample loan)))       ; the FlatData sample (a flatdata-view over the slot)
    (setf (fd-abc-a-fd s) 200                          ; write fields STRAIGHT INTO the SHMEM slot (SAP setters)
          (fd-abc-b-fd s) 3000000000
          (fd-abc-c-fd s) 4000000000000000000)
    (dds.dcps:write-loaned dw loan)))                  ; commit + publish (or dds.dcps:discard-loan to abandon)
```

`loan-sample` returns a `writer-loan` whose `sample` is a `dds.types:flatdata-view` over a freshly-acquired pool slot; the **same `<name>-<field>-fd` setters** that write an owned FlatData buffer dual-dispatch to a `store-sap-u8` write into the slot (byte-exact — test `flatdata-sap-setter`). The generation is stored **only at `write-loaned`'s `%zc-loan-commit`**, after the app's field writes + a `dds.pal:fence :release`, so a lock-free reader (`%zc-acquire-for-read`) can **never** observe a slot mid-write (ADR 0042 §2 ordering; tests `loan-write-primitive` / `loan-write-abort`). If the node has no pool / the type is too small / the writer is wire-protected / the pool is saturated / on Clasp, `loan-sample` degrades **gracefully** to a `make-<name>-flatdata` buffer and `write-loaned` is exactly `write-sample` — same API, no error, byte-identical downstream. **Security (ADR 0036 Carry-10, RESOLVED):** a wire-protected writer's `loan-sample` returns the non-slot fallback, so plaintext never lands in a pool slot. **The send-site integration (ADR 0042 §5):** the published change **carries the pre-committed slot** (`cache-change` zc-slot/zc-generation/zc-state), and the send plan's `%zc-change-item` claims it ONE-SHOT to emit the slot's 20-octet ref to the FIRST ZC-eligible destination — the delivered bytes ARE the app's SAP-setter writes, end-to-end 0-copy on that leg (proven by `dcps-loan-write-e2e`: the reader's `take-loaned` view carries exactly the loan's slot+generation). A retransmit, a non-ZC or extra ZC destination, or a security-gate veto is served from the sample bytes — for a **PIN-ELIGIBLE** writer read **on demand from the still-pinned committed slot** (WP-ACKED-SLOT-PINNING, ADR 0044; the slot is held past the HistoryCache change by a second TX refcount released at the full-ACK purge and every change-drop site — KEEP_LAST eviction, dispose, timeout, teardown — exactly once, structurally the two-gate `hc-try-release-pooled` pattern), otherwise from the RETAINED payload `write-loaned` materialises eagerly (one slot→heap copy, the always-correct fallback for an ineligible writer / exhausted `*zc-pin-budget*`). The gate veto / fallback decision / push-pass sweep / `stop-node` sweep releases an unconsumed slot, so a committed slot never strands (the `loan-write-sendsite` + `acked-slot-pin-*` lifecycle tests). **Honest framing (FR-LANG-7, claims scoped precisely):** the SEND-SITE payload→slot copy is eliminated (the 0-copy claim) and the POOL PRIMITIVES are 0-GC; for a PIN-ELIGIBLE writer the per-write **retained-payload heap vector is ELIMINATED** (WP-ACKED-SLOT-PINNING — the `acked-slot-pinning` bench arm shows ~8.2 KiB GC bytes/sample eliminated for an 8 KiB sample; the pin itself is a 0-GC `%zc-pin` CAS), leaving only the loan struct + view (freelist-recycled) + one armed-registry cell per write; an INELIGIBLE writer still allocates the retained payload (the fallback). Measured by `make bench-flatdata-loan-write` (`bench/report/2026-07-04-wp-acked-slot-pinning.md`): primitive level BASELINE ~160 GC bytes / ~255 ns/sample (2 copies) vs LOAN-WRITE ~32 GC bytes / ~167 ns/sample (0 copies); send-site arm (8 KiB sample) fresh-`%zc-loan` ~20098 ns vs pre-committed-slot claim ~602 ns (~33x, the eliminated payload→slot copy); DCPS-cycle arm (unmatched writer, 20-octet sample — no ZC destination to pay the overhead back) `write-sample` ~507 GC B / ~858 ns vs `loan-sample`→`write-loaned` ~845 GC B / ~1460 ns — loan-write pays a fixed overhead that only wins with a same-host ZC reader and a payload size worth the eliminated copy. The slot is a **self-describing SerializedPayload** (the type's encap header is written in place at `loan-sample`, byte-identical to the classic path). **SBCL only** (`store-sap-u8` is SBCL-only, ZC ADR 0013).

#### Reliable ZC loan (WP-RELIABLE-ZC, scope A; R6, ADR 0017; NOT cleared for ship — pending counsel)

A ZC loan sample delivered by a **RELIABLE** DataWriter rides the **existing reliable path with no separate reliability gate** — it has a SequenceNumber, is NACKable and retransmittable like any DATA. The model, verified + hardened by five SBCL scenarios (`run-reliable-zc-{retransmit,poolfull-fallback,mixed,slot-outlives-purge,qos}-test`; Clasp pass-skip — ZC is an NFR-PORT gap; 211 green both impls):

- **The reader ACKs on receive** (reliable completion), then holds the loan until `return-loan` (read lifetime). Its ACK/NACK bookkeeping for a ZC ref is identical to a normal DATA.
- **The loan composes with reliability via the refcount.** The writer purges the HistoryCache change on full-ACK (RTPS 2.5 §8.4.1), freeing the HC copy — but the loaned **slot outlives the purge**: the reader's refcount holds it (force-reclaim skips `refcount>0`) until `return-loan`, so there is no use-after-free even after the change is gone from the HistoryCache.
- **The ZC win under reliability is reader-RX (0-copy / 0-alloc) + the 16-byte wire reference.** **Honest note (FR-LANG-7): the writer keeps the HistoryCache full-payload copy** (it needs it to retransmit and to serve any non-ZC / remote reader), so the **writer-side is double-storage — NOT zero-copy — under reliability** (the v1 cost). There is no writer-side-zero-copy claim for reliable.
- **The retransmit is reliable via COPY-FALLBACK, not re-loan.** As-built, the ACKNACK repair leg re-emits the **full retained HistoryCache payload** (byte-exact, no loss; the retransmit path `%on-user-acknack` omits the `zc-readers` argument the initial-push path passes, so it takes the normal full-payload DATA branch). A loan-capable reader delivers that retransmit **as an owned copy** (a non-`flatdata-view` sample, `NIL` loan), not a ZC view. Reliability (ultimate byte-exact delivery) holds; the ZC win is simply not re-applied on the repair leg.
- A saturated ZC pool ⇒ `%zc-loan` NIL ⇒ the writer sends the full payload ⇒ the loan-capable reader delivers it **as a copy**, never a silent drop; a single `take-loaned` correctly returns interleaved ZC views and fallback copies, all byte-exact, with `return-loan` releasing only the views.

A **latent reliability/memory bug** was found + fixed in the course of this work (commit `0a03bf5`): `dds.qos:make-reader-qos` / `make-writer-qos` silently dropped a caller's `:reliability` override (the injected default was the leftmost — and thus winning — keyword, HyperSpec 3.4.1.4), so a RELIABLE-requesting reader advertised BEST_EFFORT, was excluded from the writer's matched-reader purge set, and the writer never purged its HistoryCache on full-ACK for it → unbounded HC growth. The caller's keyword now wins. **Scope-B follow-ups (not done): re-loan-on-retransmit** (re-send a ZC ref on the ACKNACK path — needs per-peer `%zc-readers` so the slot refcount stays 1 per resolving destination, avoiding a double-free when a resend fans to multiple peers) and **true writer-side reliable ZC** (the HistoryCache change references the slot, no full-payload copy, when all readers are same-host ZC).

### Conditions + WaitSets

| Symbol | Description |
|---|---|
| `dds.dcps:wait-condition` | Base DDS `Condition` (CLOS class; named `wait-condition` to avoid clashing with `cl:condition`). |
| `dds.dcps:guard-condition` | App-controlled trigger. |
| `dds.dcps:read-condition` | Triggers when its `DataReader` holds samples matching a sample-state mask. |
| `dds.dcps:query-condition` | A `read-condition` that also filters by a query predicate. |
| `dds.dcps:status-condition` | Triggers when an enabled status in its mask is active on an entity. |
| `dds.dcps:wait-set` | A set of conditions to wait on (condvar-driven). |
| `dds.dcps:make-guard-condition` () | Create a `GuardCondition`. |
| `dds.dcps:set-trigger-value` (`gc value`) | `GuardCondition::set_trigger_value` — set the trigger and wake any waiting WaitSet. |
| `dds.dcps:create-readcondition` (`reader &key states`) | `DataReader::create_readcondition` — triggers when samples matching `states` (default `(:not-read)`) exist. |
| `dds.dcps:create-querycondition` (`reader &key states query expression parameters`) | `DataReader::create_querycondition`. With `:expression` (a DDS Annex B query) + `:parameters`, compiles against the topic type; otherwise `:query` is a Lisp predicate over the deserialized sample. |
| `dds.dcps:qc-query-fn` (`qc`) | The compiled query predicate of a `query-condition`. |
| `dds.dcps:make-status-condition` (`entity &key mask`) | A `StatusCondition` for `entity` enabled for the statuses in `mask` (default `(:data-available)`). |
| `dds.dcps:get-statuscondition` (`entity`) | `Entity::get_statuscondition` (dds_rtf2_dcps.idl §682) — the entity's own StatusCondition, created lazily with all applicable statuses enabled and bound to its status-changes bitmask; idempotent. |
| `dds.dcps:set-enabled-statuses` (`sc mask`) | `StatusCondition::set_enabled_statuses` (§288) — restrict which status keywords make `sc` trigger (its trigger becomes the entity's status-changes bitmask ∧ `mask`, plus level-based `:data-available`). |
| `dds.dcps:get-enabled-statuses` (`sc`) | `StatusCondition::get_enabled_statuses` (§287) — the currently enabled status keywords. |
| `dds.dcps:make-wait-set` () | Create a `WaitSet`. |
| `dds.dcps:attach-condition` (`ws c`) | `WaitSet::attach_condition`. |
| `dds.dcps:detach-condition` (`ws c`) | `WaitSet::detach_condition`. |
| `dds.dcps:wait-set-wait` (`ws timeout-seconds`) | `WaitSet::wait` — block until ≥1 attached condition triggers or the timeout elapses; return the list of triggered conditions (empty on timeout). |
| `dds.dcps:condition-trigger-value` (`c`) | `Condition::get_trigger_value`. |
| `dds.dcps:read-w-condition` (`dr condition`) | `DataReader::read_w_condition` — non-destructive read of the samples a condition selects (its state mask + a QueryCondition's predicate). |
| `dds.dcps:take-w-condition` (`dr condition`) | `DataReader::take_w_condition` — take (remove) those samples. |

> WaitSet semantics: `wait-set-wait` is condvar-driven (ADR 0007). The disc receiver thread
> signals the WaitSet when new user data arrives (DATA_AVAILABLE), and `set-trigger-value`
> signals for a `guard-condition`; each wait is also capped internally (~0.5 s) so that the
> change-driven statuses, which are not explicitly signalled, still surface. Create + attach
> conditions before waiting (single-threaded setup, single waiter per WaitSet).

### Statuses + listeners

Communication statuses (FR-DCPS-3) are value structs mutated on the receiver thread under the
entity's status lock. Every status flows through one internal `%notify-status` chokepoint that
(a) updates the struct, (b) sets the status's bit in the entity's **status-changes bitmask**,
(c) triggers the entity's StatusCondition, and (d) delivers the status to a listener up the
**containment hierarchy** (WP-DCPS-API-COMPLETION S3, ADR 0053, DDS 1.4 §2.2.4.1): it walks
entity → parent (Publisher/Subscriber) → DomainParticipant and fires the **most-specific enabled**
listener (whose mask names the status), stopping there. If a listener handles the status, the
chokepoint also resets its `*_change` counters and **clears the status bit** — the §2.2.4.1
reset-on-listener-invocation, so a StatusCondition watching the same status no longer triggers. If
no listener up the chain is enabled, the bit stays set and no callback fires. Reading a status via a
`get-*-status` accessor performs the SAME reset (DDS 1.4 §2.2.2.1.9): reset the `*_change` counters
**and** clear the bit. `get-status-changes` (below) reports the bitmask.

| Symbol | Description |
|---|---|
| `dds.dcps:get-status-changes` (`entity`) | `Entity::get_status_changes` (dds_rtf2_dcps.idl §684) — the StatusMask of communication statuses changed since last read (set on fire, cleared by the matching `get-*-status`). |
| `dds.dcps:+status-subscription-matched+` … | The 13 DDS `StatusKind` bit constants (dds_rtf2_dcps.idl §80-92): `+status-inconsistent-topic+`, `+status-offered-deadline-missed+`, `+status-requested-deadline-missed+`, `+status-offered-incompatible-qos+`, `+status-requested-incompatible-qos+`, `+status-sample-lost+`, `+status-sample-rejected+`, `+status-data-on-readers+`, `+status-data-available+`, `+status-liveliness-lost+`, `+status-liveliness-changed+`, `+status-publication-matched+`, `+status-subscription-matched+`. |
| `dds.dcps:get-subscription-matched-status` (`dr`) | Snapshot the reader's SUBSCRIPTION_MATCHED status (resets `*_change`, clears the bit). |
| `dds.dcps:get-publication-matched-status` (`dw`) | Snapshot the writer's PUBLICATION_MATCHED status. |
| `dds.dcps:get-requested-incompatible-qos-status` (`dr`) | Snapshot the reader's REQUESTED_INCOMPATIBLE_QOS status. |
| `dds.dcps:get-offered-incompatible-qos-status` (`dw`) | Snapshot the writer's OFFERED_INCOMPATIBLE_QOS status. |
| `dds.dcps:get-inconsistent-topic-status` (`tp`) | Snapshot the topic's INCONSISTENT_TOPIC status. |
| `dds.dcps:get-sample-rejected-status` (`dr`) | Snapshot the reader's SAMPLE_REJECTED status. |
| `dds.dcps:get-liveliness-changed-status` (`dr`) | Snapshot the reader's LIVELINESS_CHANGED status (resets `*_change`). |
| `dds.dcps:get-liveliness-lost-status` (`dw`) | Snapshot the writer's LIVELINESS_LOST status (resets `total_count_change`). |
| `dds.dcps:assert-liveliness` (`dw`) | `DataWriter::assert_liveliness` (DDS 1.4 §2.2.3.11) — manually assert the writer's liveliness; kind-aware (MANUAL_BY_TOPIC asserts this writer, MANUAL_BY_PARTICIPANT asserts all such writers of the participant, AUTOMATIC is asserted by the cadence). A `write` also asserts. |
| `dds.dcps:subscription-matched-status` / `publication-matched-status` | The matched-status structs (`-total-count`, `-total-count-change`, `-current-count`, `-current-count-change`, and `-last-publication-handle` / `-last-subscription-handle`). |
| `dds.dcps:requested-incompatible-qos-status` / `offered-incompatible-qos-status` | The incompatible-QoS structs (`-total-count`, `-total-count-change`, `-last-policy-id`, `-policies`). |
| `dds.dcps:inconsistent-topic-status` | INCONSISTENT_TOPIC struct (`-total-count`, `-total-count-change`). |
| `dds.dcps:sample-rejected-status` | SAMPLE_REJECTED struct (`-total-count`, `-total-count-change`, `-last-reason`, `-last-instance-handle`). |
| `dds.dcps:liveliness-changed-status` | LIVELINESS_CHANGED struct (`-alive-count`, `-not-alive-count`, `-alive-count-change`, `-not-alive-count-change`, `-last-publication-handle`). |
| `dds.dcps:liveliness-lost-status` | LIVELINESS_LOST struct (`-total-count` monotonic, `-total-count-change`); a writer that fails to assert its own liveliness within its offered lease. |
| `dds.dcps:sample-lost-status` | SAMPLE_LOST struct (`-total-count`, `-total-count-change`); dds_rtf2_dcps.idl §99-102 (no `last_reason` in RTF2). **Struct only — not yet fired (S4).** |
| `dds.dcps:offered-deadline-missed-status` / `requested-deadline-missed-status` | The deadline-missed structs (`-total-count`, `-total-count-change`, `-last-instance-handle`); dds_rtf2_dcps.idl §131-135 / §137-141. **Structs only — not yet fired (S4).** |
| `dds.dcps:sample-rejected-reason` | The reason type: `:not-rejected` / `:rejected-by-instances-limit` / `:rejected-by-samples-limit` / `:rejected-by-samples-per-instance-limit`. |
| `dds.dcps:qos-policy-count` / `make-qos-policy-count` / `qos-policy-count-policy-id` / `qos-policy-count-count` | A `{policy-id, count}` entry in an incompatible-QoS `policies` list. |
| `dds.dcps:rxo-policy-id` (`keyword`) | The DDS `QosPolicyId_t` for an RxO failing-policy keyword. |
| `dds.dcps:+qos-policy-id-durability+` / `-reliability+` / `-deadline+` / `-latency-budget+` / `-ownership+` / `-liveliness+` / `-destination-order+` / `-presentation+` / `-data-representation+` | The DDS `QosPolicyId_t` constants. |
| `dds.dcps:listener` / `data-reader-listener` / `data-writer-listener` / `topic-listener` / `publisher-listener` / `subscriber-listener` / `domain-participant-listener` | The CLOS listener base classes — all six DDS 1.4 interfaces (dds_rtf2_dcps.idl §199/§206/§221/§224/§247/§253). Subclass and override the `on-*` methods you care about (base methods are no-ops); a `domain-participant-listener` may override any callback (it aggregates all). |
| `dds.dcps:set-listener` (`entity listener mask`) | `Entity::set_listener` (DDS 1.4 §2.2.4.1) — uniform installer on **all six** entity kinds; `mask` is the list of status keywords the listener handles (participates in hierarchy propagation); `nil` clears. |
| `dds.dcps:get-listener` (`entity`) | `Entity::get_listener` — the installed listener object (or `nil`), on all six kinds. |
| `dds.dcps:set-reader-listener` / `set-writer-listener` / `set-topic-listener` (`entity listener mask`) | The endpoint/topic-specific setters (retained; equivalent to `set-listener` on those kinds). |
| `dds.dcps:on-data-on-readers` (`l subscriber`) | SubscriberListener callback (dds_rtf2_dcps.idl §248) — fires when a Subscriber/Participant listener is enabled for `:data-on-readers`; handling it **suppresses** the readers' `on_data_available` (precedence, DDS 1.4 §2.2.4.1). |
| `dds.dcps:get-datareaders` (`subscriber &key sample-states`) | `Subscriber::get_datareaders` (§993) — the readers holding a sample whose `sample_state` is in `sample-states` (default `(:not-read)`). |
| `dds.dcps:notify-datareaders` (`subscriber`) | `Subscriber::notify_datareaders` (§998) — fire `on_data_available` on each reader with new data (call from `on_data_on_readers`). |
| `dds.dcps:on-data-available` (`l reader`) | DataReaderListener callback — fires from the receiver thread on new user data (unless a `on_data_on_readers` handled DATA_ON_READERS first). |
| `dds.dcps:on-subscription-matched` / `on-requested-incompatible-qos` / `on-sample-rejected` / `on-liveliness-changed` (`l reader status`) | DataReaderListener callbacks that fire in v1. `on-liveliness-changed` fires from the announce cadence when a matched remote writer's liveliness goes stale/fresh (RTPS 2.5 §8.4.13). |
| `dds.dcps:on-publication-matched` / `on-offered-incompatible-qos` / `on-liveliness-lost` (`l writer status`) | DataWriterListener callbacks that fire in v1. `on-liveliness-lost` fires from the announce cadence (`spin`) when a local writer fails to assert its own liveliness within its offered lease (DDS 1.4 §2.2.3.11). |
| `dds.dcps:on-inconsistent-topic` (`l topic status`) | TopicListener callback that fires in v1. |
| `dds.dcps:on-requested-deadline-missed` / `on-sample-lost` (`l reader status`); `dds.dcps:on-offered-deadline-missed` (`l writer status`) | DataReader/DataWriterListener callbacks that fire in v1 (WP-DCPS-API-COMPLETION S4, DDS 1.4 §2.2.3.7 / §2.2.4.1). DEADLINE misses fire from a per-participant background monitor thread; SAMPLE_LOST fires on a best-effort SN-skip (drain) or an irrecoverable reliable GAP. |
| `dds.dcps:get-offered-deadline-missed-status` (`writer`) / `get-requested-deadline-missed-status` / `get-sample-lost-status` (`reader`) | Snapshot getters for the three S4 statuses; each applies the §2.2.2.1.9 read-communication-status reset (zeroes `total_count_change`, clears the status-changed bit; `total_count` stays monotonic). |

### Advisory type-compatibility (ADR 0009)

When a remote endpoint matches a local DataReader/DataWriter, the matcher assesses the peer's advertised complete TypeObject (the RTI vendor `PID_TYPE_OBJECT_LB`, when the peer carries one) against the local type's member-name fingerprint and records the verdict on the local entity. This is **purely advisory / diagnostic** — the peer is already matched on topic + type name, and the heuristic **never gates or rejects a match** (RTI's legacy TypeObject is not the OMG CompleteTypeObject, so a missing name is inconclusive). See [type system](type-system.md) for the fingerprint and the verdict keywords.

| Symbol | Description |
|---|---|
| `dds.dcps:entity-type-compat` (`entity`) | The advisory type-object fingerprint verdict for the most recently matched remote, recorded per DataReader/DataWriter (one of the `assess-type-object-lb` verdict keywords); `NIL` on other entities and until a first match. Inspection only — it never affects matching. |
| `dds.dcps:*type-compat-log*` | When set to a stream (default `NIL` = silent), the matcher writes one advisory verdict line per freshly matched remote to it (and the FR-TYPE-4 gate below writes one line per recorded gate verdict). Diagnostics opt-in only. The matcher runs on the discovery receiver thread, so set this with a process-global `setf`, not a thread-local `let` in another thread. |

### Assignability-gated matching (FR-TYPE-4)

Every participant installs an **assignability gate** on its engine's `type-gate` hook (see
[discovery](discovery.md)). Unlike the ADR 0009 advisory above, this gate **does decide the
match** — but only when it can genuinely assess the types; every unassessable case falls
back to today's name-based matching, never to a rejection. The verdict ladder, evaluated
on the discovery receiver thread for **both** match directions:

1. A verdict already recorded for this remote GUID replays (the post-resume re-run, and a recorded legacy-TypeObject verdict, never re-assess).
2. The remote endpoint carries no `PID_TYPE_INFORMATION` but **does** carry the RTI vendor `PID_TYPE_OBJECT_LB` (a stock Connext peer, ADR 0009) → the **fail-open legacy-TypeObject rung** (below). With neither → **`:compatible`** (name-based, the pre-XTypes behavior).
3. Malformed TypeInformation, no local Minimal TypeObject (the local type-support is resolved through the participant's Topic of the endpoint's topic name, falling back to the global registry under its type name), or an unserializable local hash → **`:compatible`** (cannot assess; logged).
4. The remote's EquivalenceHash equals the local one → **`:compatible`** (fast path, zero wire traffic).
5. Otherwise the remote Minimal TypeObject is fetched from the remote participant's **TypeLookup service** (`getTypes`, XTypes 1.3 §7.6.3.3.3) — the match decision parks as `:pending` meanwhile. If the remote participant has not been SPDP-discovered yet (SEDP can outrun SPDP across the two sockets), the gate stays `:pending` *without* querying; the peer's SEDP re-announce re-runs it once the locator is known. Nested `EK_MINIMAL` member hashes are resolved with bounded follow-up queries (at most `*typelookup-max-depth*` rounds), attaching each fetched model to the referencing TypeIdentifier.
6. Fully resolved, the verdict is XTypes 1.3 §7.6.3.4.2 Step 1: the **reader-side** type must be `is-assignable-from` the writer-side type under the reader's `TYPE_CONSISTENCY_ENFORCEMENT` QoS (`ALLOW_TYPE_COERCION` → assignability with the four option flags; `DISALLOW_TYPE_COERCION` → Minimal equivalence). The direction is recovered from the remote GUID's entityKind octet (writer = `0x02`/`0x03`, reader = `0x04`/`0x07` in the low six bits, RTPS 2.5 §9.3.1.2 Table 9.1). `:incompatible` routes to the INCONSISTENT_TOPIC path (status + listener on the local Topic).
7. A TypeLookup timeout/failure, an unknown hash, depth exhaustion, or an unresolvable nesting records the **`:compatible` fallback** (logged via `*type-compat-log*`) and the match completes by name.

**Fail-open legacy-TypeObject rung (rung 2, ADR 0009).** Stock RTI Connext advertises its type only through the vendor `PID_TYPE_OBJECT_LB` (0x8021), never the minimal-hash `PID_TYPE_INFORMATION`, so the TypeInformation ladder above never engages for it. When a remote carries an LB but no TypeInformation, the gate ZLIB-inflates it and runs the clean-room structural parser (`dds.types:parse-legacy-type-object`). **Only a confident `minimal-struct-type` parse gates**: it is assessed against the local type-support's Minimal TypeObject under the *same* reader-side `TYPE_CONSISTENCY_ENFORCEMENT` derivation rung 6 uses (assignable → `:compatible`; not assignable → `:incompatible`, routed to the INCONSISTENT_TOPIC path), and the verdict is recorded per remote GUID (the verdict replay at rung 1 short-circuits the re-parse on every re-run). **Every other outcome falls open to `:compatible` (name-match, logged) and can never reject** — an `:unsupported` parse (a tree with an unmodelable member: enum/union/array/bitmask/over-depth nesting), a `NIL` parse (untokenizable / failed inflate), or no local Minimal TypeObject to assess against. The advisory `assess-type-object-lb` fingerprint (recorded at match per ADR 0009) is a separate, purely diagnostic signal and is unaffected. This is the **fail-open guarantee**: a stock Connext peer whose legacy type we cannot confidently model still matches by name, exactly as before the rung existed.

**Proven live against RTI Connext 7.3.1 (2026-06-11, ADR 0011 — completes the ADR 0010 amended M4 gate).** The fail-open legacy rung was exercised end-to-end against a live Connext writer (`interop/connext/typeobject-corpus/corpus_pub 0 Square C_Shape`) by the DCPS-level gated subscriber `dds.shapes:run-gated-subscriber` (`make gated-sub`). With a local type matching C_Shape (color string@key; x/y/shapesize long) bound under the wire topic/type-name, the gate parsed Connext's real `PID_TYPE_OBJECT_LB` and returned `:compatible` — the endpoints matched and 25 C_Shape samples were delivered. With the local `shapesize` retyped long→`i64` (not assignable), the gate returned `:incompatible` — INCONSISTENT_TOPIC was raised and **zero** samples were delivered. Re-running the compatible case after the incompatible one still matched and delivered: a genuinely compatible Connext peer is never false-rejected. (The standalone `dds.shapes:run-subscriber` is a bare `dds.disc` node with **no** gate — only a DCPS participant, whose `create-participant` installs the gate, exercises this rung; that is why the live test required a DCPS-level subscriber harness.)

Known gap: an unreachable TypeLookup service costs `*typelookup-timeout*` (default 3 s) of parked-match latency per remote endpoint before the name fallback. Known gap: a timeout/unassessable fallback verdict of `:compatible` is replayed for that remote GUID on every re-announce and is never re-assessed until FIFO eviction — a later-reachable TypeLookup service is not re-consulted for an already-decided endpoint. Known gap: `TYPE_CONSISTENCY_ENFORCEMENT` does not ride our SEDP ParameterList yet, so when
the **remote** endpoint is the reader its policy assumes the §7.6.3.4.1 defaults.

| Symbol | Description |
|---|---|
| `dds.dcps:*max-typeobject-cache-entries*` | Cap (default 256) on the parsed remote TypeObjects and per-remote verdicts each participant's gate retains; FIFO-evicted at the cap (resource-exhaustion guard). Read at insertion time. |
| `dds.dcps:*typelookup-max-depth*` | Maximum nested-type TypeLookup follow-up rounds (default 4) before the gate falls back to name-based matching. Bounds wire traffic and recursion. |

### Content-filtered topics + query conditions

| Symbol | Description |
|---|---|
| `dds.dcps:content-filtered-topic` | A `TopicDescription` over a related `Topic` + a compiled filter predicate; v1 filters reader-side. |
| `dds.dcps:create-contentfilteredtopic` (`participant name related-topic filter-expression &optional parameters`) | `DomainParticipant::create_contentfilteredtopic` — compile a DDS Annex B `filter-expression` + `parameters` against the related topic's type. |
| `dds.dcps:set-cft-expression-parameters` (`cft parameters`) | `ContentFilteredTopic::set_expression_parameters` — recompile with new parameters; already-created readers pick it up. |
| `dds.dcps:cft-name` / `cft-related-topic` / `cft-expression` / `cft-parameters` (`cft`) | Accessors on a `content-filtered-topic`. |
| `dds.dcps:compile-filter` (`expression parameters resolver`) | Compile a DDS Annex B filter/query expression into a predicate `(lambda (sample) -> boolean)`. `resolver` maps a FIELDNAME to a unary accessor. |
| `dds.dcps:lex-filter` (`str`) | Tokenize a filter/query expression. |
| `dds.dcps:filter-error` / `filter-error-detail` | The condition signalled on a lexical/syntactic/field-resolution error, and its detail accessor. |

> The grammar is the DDS 1.4 Annex B subset: comparisons (`= > >= < <= <> !=`), `LIKE`
> (`%`/`_` wildcards), `BETWEEN … AND …`, `AND`/`OR`/`NOT`, parentheses, `%n` positional
> parameters, and field-vs-field comparisons. v1 supports single-level field names.

### Builtin topics

The builtin-topic readers (FR-DCPS-6) surface what discovery already collected. Each returns a
list of value structs.

| Symbol | Description |
|---|---|
| `dds.dcps:get-builtin-participant-data` (`p`) | DCPSParticipant — one entry per discovered remote participant. |
| `dds.dcps:get-builtin-publication-data` (`p`) | DCPSPublication — one entry per discovered remote writer. |
| `dds.dcps:get-builtin-subscription-data` (`p`) | DCPSSubscription — one entry per discovered remote reader. |
| `dds.dcps:get-builtin-topic-data` (`p`) | DCPSTopic — one entry per distinct (topic, type) discovered. |
| `dds.dcps:participant-builtin-topic-data` / `-key` | DCPSParticipant struct + its `BuiltinTopicKey_t` accessor. |
| `dds.dcps:publication-builtin-topic-data` + `-key` / `-participant-key` / `-topic-name` / `-type-name` / `-reliability` / `-durability` | DCPSPublication struct + accessors. |
| `dds.dcps:subscription-builtin-topic-data` + `-key` / `-participant-key` / `-topic-name` / `-type-name` / `-reliability` / `-durability` | DCPSSubscription struct + accessors. |
| `dds.dcps:topic-builtin-topic-data` + `-name` / `-type-name` | DCPSTopic struct + accessors. |

## Examples

All examples assume `(ql:quickload :dds)` and use the package nicknames. They are adapted from
the passing tests in `src/dds-tests/integration-test.lisp`. The topic type is defined with
`define-dds-type` (see [Type system](type-system.md)), which registers a `type-support`
retrieved by name with `dds.types:find-type-support`.

### 1. Basic write / take

Two participants discover each other over UDP loopback; a writer writes one sample and the
reader takes it. (Adapted from `run-dcps-entity-test`.)

```lisp
(dds.gen:define-dds-type dcps-msg (:extensibility :final)
  (id   :i32)
  (text :string))

(let* ((ts (dds.types:find-type-support "dcps-msg"))
       (p1 (dds.dcps:create-participant :domain 0))
       (p2 (dds.dcps:create-participant :domain 0)))
  (unwind-protect
       (let* ((tw  (dds.dcps:create-topic p1 "DcpsTopic" "dcps-msg" ts))
              (tr  (dds.dcps:create-topic p2 "DcpsTopic" "dcps-msg" ts))
              (dw  (dds.dcps:create-datawriter (dds.dcps:create-publisher  p1) tw))
              (dr  (dds.dcps:create-datareader (dds.dcps:create-subscriber p2) tr)))
         ;; caller-driven discovery: spin until the endpoints match
         (loop repeat 150
               until (and (plusp (dds.dcps:matched-count p1))
                          (plusp (dds.dcps:matched-count p2)))
               do (dds.dcps:spin p1) (dds.dcps:spin p2) (sleep 0.02))
         (dds.dcps:write-sample dw (make-dcps-msg :id 42 :text "hello-dcps"))
         (let ((got nil))
           (loop repeat 150 until got
                 do (let ((s (dds.dcps:take-samples dr)))
                      (when s (setf got (dds.dcps:cached-sample-data (first s)))))
                    (sleep 0.02))
           (format t "~&got id=~d text=~s~%" (dcps-msg-id got) (dcps-msg-text got))))
    (dds.dcps:delete-participant p1)
    (dds.dcps:delete-participant p2)))
```

### 2. Instances + read vs. take + SampleInfo states

A keyed type (`color` is the `@key`) groups samples into instances. `read-samples` is
non-destructive and marks samples `:read`, transitioning the per-instance view-state from
`:new` to `:not-new`; `take-samples` removes them. (Adapted from `run-dcps-instance-test`.)

```lisp
(dds.gen:define-dds-type shape-type (:extensibility :final)
  (color :string :key t)
  (x :i32) (y :i32) (shapesize :i32))

;; helper accessors over a cached-sample's SampleInfo (as used in the tests)
(flet ((view-state (cs) (dds.dcps:sample-info-view-state    (dds.dcps:cached-sample-info cs)))
       (sample-state (cs) (dds.dcps:sample-info-sample-state (dds.dcps:cached-sample-info cs)))
       (handle (cs) (dds.dcps:sample-info-instance-handle    (dds.dcps:cached-sample-info cs))))
  (let* ((ts (dds.types:find-type-support "shape-type"))
         (p1 (dds.dcps:create-participant :domain 0))
         (p2 (dds.dcps:create-participant :domain 0)))
    (unwind-protect
         (let* ((tw (dds.dcps:create-topic p1 "Square" "shape-type" ts))
                (tr (dds.dcps:create-topic p2 "Square" "shape-type" ts))
                (dw (dds.dcps:create-datawriter (dds.dcps:create-publisher  p1) tw))
                (dr (dds.dcps:create-datareader (dds.dcps:create-subscriber p2) tr)))
           (loop repeat 100
                 until (and (plusp (dds.dcps:matched-count p1)) (plusp (dds.dcps:matched-count p2)))
                 do (dds.dcps:spin p1) (dds.dcps:spin p2) (sleep 0.02))
           ;; 3 samples in 2 instances (BLUE x2, RED x1)
           (dds.dcps:write-sample dw (make-shape-type :color "BLUE" :x 1 :y 1 :shapesize 10))
           (dds.dcps:write-sample dw (make-shape-type :color "RED"  :x 2 :y 2 :shapesize 20))
           (dds.dcps:write-sample dw (make-shape-type :color "BLUE" :x 3 :y 3 :shapesize 30))
           (loop repeat 200 until (>= (dds.dcps:samples-available dr) 3) do (sleep 0.02))

           ;; first read of the unread samples: all :new, now marked :read; 2 distinct handles
           (let ((r1 (dds.dcps:read-samples dr :states '(:not-read))))
             (assert (= 3 (length r1)))
             (assert (= 2 (length (remove-duplicates (mapcar #'handle r1) :test #'equalp))))
             (assert (every (lambda (cs) (eq :new  (view-state cs)))   r1))
             (assert (every (lambda (cs) (eq :read (sample-state cs))) r1)))

           ;; non-destructive: a plain read still returns all 3, now :not-new
           (let ((r2 (dds.dcps:read-samples dr)))   ; default :states = (:read :not-read)
             (assert (= 3 (length r2)))
             (assert (every (lambda (cs) (eq :not-new (view-state cs))) r2)))

           ;; take removes everything
           (assert (= 3 (length (dds.dcps:take-samples dr))))
           (assert (zerop (dds.dcps:samples-available dr))))
      (dds.dcps:delete-participant p1)
      (dds.dcps:delete-participant p2))))
```

### 3. A WaitSet + ReadCondition

Block on a `WaitSet` until a sample arrives (the receiver thread wakes the WaitSet's condvar),
then read it. (Adapted from `run-dcps-waitset-test` / `run-dcps-condvar-wake-test`.)

```lisp
(let ((ts (dds.types:find-type-support "dcps-msg"))
      (p1 (dds.dcps:create-participant :domain 0))
      (p2 (dds.dcps:create-participant :domain 0)))
  (unwind-protect
       (let* ((tw (dds.dcps:create-topic p1 "WsTopic" "dcps-msg" ts))
              (tr (dds.dcps:create-topic p2 "WsTopic" "dcps-msg" ts))
              (dw (dds.dcps:create-datawriter (dds.dcps:create-publisher  p1) tw))
              (dr (dds.dcps:create-datareader (dds.dcps:create-subscriber p2) tr))
              (rc (dds.dcps:create-readcondition dr))     ; default states '(:not-read)
              (ws (dds.dcps:make-wait-set)))
         (dds.dcps:attach-condition ws rc)
         (loop repeat 150
               until (and (plusp (dds.dcps:matched-count p1)) (plusp (dds.dcps:matched-count p2)))
               do (dds.dcps:spin p1) (dds.dcps:spin p2) (sleep 0.02))
         ;; no data yet -> wait times out (empty list)
         (assert (null (dds.dcps:wait-set-wait ws 0.2)))
         (dds.dcps:write-sample dw (make-dcps-msg :id 99 :text "ws"))
         ;; the ReadCondition is in the returned trigger list once the sample arrives
         (let ((triggered (dds.dcps:wait-set-wait ws 3.0)))
           (assert (member rc triggered))
           (let ((s (dds.dcps:read-w-condition dr rc)))
             (format t "~&awaited id=~d~%" (dcps-msg-id (dds.dcps:cached-sample-data (first s)))))))
    (dds.dcps:delete-participant p1)
    (dds.dcps:delete-participant p2)))
```

A `query-condition` works the same way but adds a predicate; with a Lisp predicate
(`run-dcps-query-condition-test`):

```lisp
(let ((qc (dds.dcps:create-querycondition
           dr :states '(:not-read) :query (lambda (m) (> (dcps-msg-id m) 50)))))
  ;; ... attach to a WaitSet; only samples with id > 50 trigger it.
  ;; read_w_condition returns just the matching, unread samples:
  (dds.dcps:read-w-condition dr qc))
```

…or with a DDS Annex B query expression compiled against the topic type
(`run-dcps-querycondition-sql-test`):

```lisp
(let ((qc (dds.dcps:create-querycondition
           dr :states '(:not-read)
              :expression "id > %0 AND text <> 'skip'" :parameters '("50"))))
  (funcall (dds.dcps:qc-query-fn qc) (make-dcps-msg :id 99 :text "ok")))   ; => T
```

### 4. A ContentFilteredTopic

A reader created on a `content-filtered-topic` matches writers on the **related** topic but
only surfaces samples passing the filter (reader-side). (Adapted from
`run-dcps-content-filtered-topic-test`.)

```lisp
(let ((ts (dds.types:find-type-support "shape-type"))
      (p1 (dds.dcps:create-participant :domain 0))
      (p2 (dds.dcps:create-participant :domain 0)))
  (unwind-protect
       (let* ((tw  (dds.dcps:create-topic p1 "Square" "shape-type" ts))
              (tr  (dds.dcps:create-topic p2 "Square" "shape-type" ts))
              ;; filter: x > %0, parameter 0 = "50"
              (cft (dds.dcps:create-contentfilteredtopic p2 "FastSquare" tr "x > %0" '("50")))
              (dw  (dds.dcps:create-datawriter (dds.dcps:create-publisher  p1) tw))
              (dr  (dds.dcps:create-datareader (dds.dcps:create-subscriber p2) cft)))
         (loop repeat 150
               until (and (plusp (dds.dcps:matched-count p1)) (plusp (dds.dcps:matched-count p2)))
               do (dds.dcps:spin p1) (dds.dcps:spin p2) (sleep 0.02))
         (dds.dcps:write-sample dw (make-shape-type :color "BLUE" :x 100 :y 1 :shapesize 10))
         (dds.dcps:write-sample dw (make-shape-type :color "BLUE" :x 10  :y 2 :shapesize 10))  ; filtered out
         (dds.dcps:write-sample dw (make-shape-type :color "BLUE" :x 200 :y 3 :shapesize 10))
         (loop repeat 250 until (>= (dds.dcps:samples-available dr) 2) do (sleep 0.02))
         ;; only x=100 and x=200 reach read/take; x=10 was drained + dropped
         (let ((xs (mapcar (lambda (cs) (shape-type-x (dds.dcps:cached-sample-data cs)))
                           (dds.dcps:take-samples dr))))
           (format t "~&delivered x values: ~a~%" xs)))   ; => (100 200)
    (dds.dcps:delete-participant p1)
    (dds.dcps:delete-participant p2)))
```

`set-cft-expression-parameters` recompiles the predicate (e.g. raise the threshold), and
readers already created on the CFT pick up the new predicate.

### 5. A CLOS listener for SUBSCRIPTION_MATCHED

Subclass `data-reader-listener`, override the callback, and install it with a status mask. The
callback fires from the receiver thread, so guard shared state with a lock. (Adapted from
`run-dcps-matched-status-test`.)

```lisp
(defclass matched-listener (dds.dcps:data-reader-listener)
  ((hits :initform '() :accessor ml-hits)
   (lock :initform (dds.pal:make-lock "matched") :accessor ml-lock)))

(defmethod dds.dcps:on-subscription-matched ((l matched-listener) reader status)
  (declare (ignore reader))
  (dds.pal:with-lock ((ml-lock l))
    (push (dds.dcps:subscription-matched-status-current-count status) (ml-hits l))))

(let ((ts (dds.types:find-type-support "dcps-msg"))
      (p1 (dds.dcps:create-participant :domain 0))
      (p2 (dds.dcps:create-participant :domain 0))
      (rl (make-instance 'matched-listener)))
  (unwind-protect
       (let* ((tw (dds.dcps:create-topic p1 "MatchTopic" "dcps-msg" ts))
              (tr (dds.dcps:create-topic p2 "MatchTopic" "dcps-msg" ts))
              (dw (dds.dcps:create-datawriter (dds.dcps:create-publisher  p1) tw))
              (dr (dds.dcps:create-datareader (dds.dcps:create-subscriber p2) tr)))
         (declare (ignore dw))
         (dds.dcps:set-reader-listener dr rl '(:subscription-matched))
         (loop repeat 150
               until (and (plusp (dds.dcps:matched-count p1)) (plusp (dds.dcps:matched-count p2)))
               do (dds.dcps:spin p1) (dds.dcps:spin p2) (sleep 0.02))
         ;; the listener has fired; the status also reports the match:
         (let ((sm (dds.dcps:get-subscription-matched-status dr)))
           (format t "~&total=~d current=~d (listener hits: ~a)~%"
                   (dds.dcps:subscription-matched-status-total-count sm)
                   (dds.dcps:subscription-matched-status-current-count sm)
                   (dds.pal:with-lock ((ml-lock rl)) (copy-list (ml-hits rl))))))
    (dds.dcps:delete-participant p1)
    (dds.dcps:delete-participant p2)))
```

### 6. Builtin topics

After discovery, read the DCPS builtin topics to enumerate the discovered participants and
endpoints. (Adapted from `run-dcps-builtin-topics-test`.)

```lisp
;; p1 and p2 are matched participants (writer on p1, reader on p2, topic "BTopic"/"dcps-msg")
(dds.dcps:get-builtin-participant-data p1)   ; => list of participant-builtin-topic-data

;; p1's view of remote readers:
(find-if (lambda (s)
           (and (string= "BTopic"   (dds.dcps:subscription-builtin-topic-data-topic-name s))
                (string= "dcps-msg" (dds.dcps:subscription-builtin-topic-data-type-name s))))
         (dds.dcps:get-builtin-subscription-data p1))

;; p2's view of remote writers:
(find-if (lambda (pp) (string= "BTopic" (dds.dcps:publication-builtin-topic-data-topic-name pp)))
         (dds.dcps:get-builtin-publication-data p2))

;; distinct (topic, type) pairs seen by p1:
(find "BTopic" (dds.dcps:get-builtin-topic-data p1)
      :key #'dds.dcps:topic-builtin-topic-data-name :test #'string=)
```

## Notes / status

This is a v1 of the DCPS layer (M3/P2, with M4 XTypes plumbing). The following are visible in
the source as deferred or simplified — do not rely on them yet:

- **One endpoint pair per participant (N=1).** Each `DomainParticipant` today drives exactly one
  `DataWriter` and one `DataReader`. As of the N-user-endpoint **Slice S0 registry** (ADR 0048), the
  engine writer/reader instances are held in entity-id-keyed registries on the disc-node; the compat
  accessors return the **primary** (first-registered) entry, so N=1 is byte-identical. This is the
  foundation only — N local user endpoints still need per-endpoint send fan-out (**Slice S1**) and
  delivery routing (**Slice S2**). Registering a **second, distinct** `EntityId` today fail-fasts with a
  clear "not yet supported (S1/S2)" error instead of silently clobbering.
- **Caller-driven discovery.** You must call `dds.dcps:spin` to drive SPDP/SEDP; there is no
  background announcer (the engine's announce buffers are not yet thread-isolated).
- **Instance lifecycle: writer + reader side (S1 + S2).** Writer side (S1): `register_instance` /
  `dispose` / `unregister_instance` emit the no-payload dispose/unregister `DATA` over the reliable
  engine (StatusInfo Disposed/Unregistered, RTPS 2.5 §9.6.4.9; reliably ACKNACK-repairable). Reader
  side (S2, DDS 1.4 §2.2.2.5.1.3/.4/.5): the reader keeps a per-instance state and surfaces it in
  `SampleInfo`. The reader applies the state from the StatusInfo_t **flag bits**: the `Unregistered`
  bit drops the source writer from the instance's writers-set, then the `Disposed` bit set ->
  `:not-alive-disposed` (disposed dominates, §2.2.2.5.1.3, even when `Unregistered` is also set), else
  the writers-set emptied while alive -> `:not-alive-no-writers`. A later data sample revives
  the instance to `:alive` and bumps the matching generation count. A dispose/unregister/no-writers
  transition delivers an **invalid-data** sample (`valid-data nil`, no Data, carrying the new
  `instance-state` + generation counts) through `read`/`take`, and fires `on_data_available`. The
  ranks, `source-timestamp`, and `publication-handle` stay at their defaults (`0` / `nil`); there is
  no `write_w_timestamp`. Live Connext interop of the reader-side transition is a later stage.
- **`WRITER_DATA_LIFECYCLE.autodispose_unregistered_instances` (DDS 1.4 §2.2.3.21, default TRUE).** By
  default a `DataWriter::unregister_instance` **also disposes** the instance — behaviour identical to
  calling `dispose` before the unregister (§2.2.3.21) — so the unregister `DATA` carries StatusInfo
  `Disposed\|Unregistered` (0x03) and a reader reports `NOT_ALIVE_DISPOSED`, matching the conformant
  Fast DDS default. Create the writer with `(make-writer-qos :autodispose-unregistered-instances nil)`
  to suppress the auto-dispose: the unregister then carries `Unregistered` (0x02) only and a reader
  reports `NOT_ALIVE_NO_WRITERS` once the last writer is gone. The policy is **writer-local** — it is
  not advertised in SEDP and not part of RxO compatibility.
- **`READER_DATA_LIFECYCLE` autopurge (DDS 1.4 §2.2.3.22, both delays default INFINITE).** A
  `DataReader` purges **all** internal information + untaken samples for a `NOT_ALIVE` instance after a
  configurable delay: `autopurge_disposed_samples_delay` once the instance is `NOT_ALIVE_DISPOSED`,
  `autopurge_nowriter_samples_delay` once it is `NOT_ALIVE_NO_WRITERS`
  (`make-reader-qos :autopurge-disposed-samples-delay {5 0}` etc.). Each instance records the
  internal-time stamp of its `ALIVE -> NOT_ALIVE` transition; the purge sweep runs on the DCPS announce
  cadence (`spin`, beside the writer-liveliness sweep) and, when the applicable delay is **finite** and
  has elapsed, removes that instance's cached samples, its instance record, and its view-state entry —
  so a later sample for the same key starts a **fresh `ALIVE` instance** (view-state `NEW`, generation
  counts reset to `0`). **Both delays default `+duration-infinite+`, so by default nothing is ever
  purged** (the common case is a no-op). The policy is **reader-local** — not advertised in SEDP and
  not part of RxO compatibility. The purge runs on the user/`spin` thread (the cache owner), never the
  receiver thread.
- **EXCLUSIVE OWNERSHIP arbitration: reader side (S1).** An `EXCLUSIVE` `DataReader`
  (`make-reader-qos :ownership :exclusive`) delivers, **per instance**, only the samples of the
  **owner** — the highest-`OWNERSHIP_STRENGTH` alive matched writer (DDS 1.4 §2.2.3.9.2 / §2.2.3.10).
  Lower-strength writers' samples are **dropped** (they never enter the cache); the dropped writer is
  still registered in the instance's writers-set, so liveliness / no-writers tracking is unaffected.
  The owner is chosen from the writer's SEDP-carried `OWNERSHIP_STRENGTH`; the first writer to modify
  an instance owns it until a strictly higher-strength writer modifies it. A same-strength tie is
  broken by a **consistent lexicographic GUID compare** (the spec leaves the choice
  implementation-defined but requires every reader make the **same** one). **Takeover:** when the
  owner unmatches (lease expiry), goes not-alive (LIVELINESS, §2.2.3.9.2 cause c), or
  disposes/unregisters its instance (§2.2.3.23.1), it relinquishes ownership; the next sample from the
  now-highest alive writer reclaims it. A `SHARED` reader (the default) does **no** arbitration —
  every writer's samples are delivered, exactly as before. Arbitration needs the **full 16-octet
  source GUID** per sample (two writers on different participants share an `EntityId`), recorded by
  the engine alongside the writer `EntityId`. Reader-side only; cross-reader consistency is per
  §2.2.3.9.2 (each reader decides independently).
  - **Per-writer keying (no SN aliasing).** The engine's reader-side sample store is **2-level** —
    keyed by the **source GUID** then the RTPS `SequenceNumber` (RTPS 2.5 §8.3.5.4: an SN is unique
    only *within one writer GUID*), so two writers sharing `EntityId` `0x102` on different
    participants do **not** alias in the SN space (an SN-only key would silently dedup the second
    writer's data). The drain's per-writer high-water mark is likewise keyed by the source GUID. The
    2-level keying also avoids a per-sample composite-key allocation on the receive path (NFR-MEM).
  - **Pre-match keep-pending.** A sample from a writer that is **identified but not yet SEDP-matched**
    (its `OWNERSHIP_STRENGTH` is unresolved) is dropped on the current drain but its per-writer
    watermark is **left pending** — the reliable engine has already ACKed it, so advancing the
    watermark would lose it permanently. A later drain re-evaluates it once the match completes and
    the strength is known, so no EXCLUSIVE data is lost across the SEDP race (DDS 1.4 §2.2.3.9.2).
  - **Per-writer keying of the dispose + ACKNACK/repair paths (done).** The dispose/unregister
    **lifecycle** store is now **2-level** (source GUID → SN, mirroring the data store), and the
    reliable-engine **writer/reader proxies** are keyed by an **opaque per-endpoint key** (the data
    plane passes the remote endpoint's full 16-octet GUID) — so two writers sharing `EntityId` `0x102`
    on different participants no longer alias in the DISPOSE or ACKNACK/REPAIR paths either (RTPS 2.5
    §8.3.5.4: an SN is unique only within one writer GUID). The inbound ACKNACK is keyed by the
    **remote reader** GUID (fixing an earlier bug where every reader's ACKNACK mapped to one proxy via
    the local reader-id), and the proactive push keys by the same per-reader GUID so the send-once and
    acknowledged watermarks stay on one proxy for the single-reader common case.
- **MATCHED decrements on lease expiry.** When a discovered participant vanishes and its
  lease expires (RTPS 2.5 §8.5.3.3.2), each pruned match decrements the affected local
  endpoint's SUBSCRIPTION_MATCHED / PUBLICATION_MATCHED `current_count` (`current_count_change`
  negative, `last_*_handle` set to the vanished remote's GUID) and fires the matched listener.
  `total_count` is **never** decremented — it is monotonic per DDS 1.4 §2.2.4.1.
- **Reader-side LIVELINESS_CHANGED is produced.** On the announce cadence the discovery
  `%liveliness-sweep` judges each matched remote writer alive vs not-alive — alive while a
  liveliness assertion of the writer's offered LIVELINESS kind (an AUTOMATIC /
  MANUAL_BY_PARTICIPANT `ParticipantMessageData`) has arrived within the writer's offered
  `lease_duration` (RTPS 2.5 §8.4.13). It fires `on_liveliness_changed` and bumps the reader's
  LIVELINESS_CHANGED status **only on an alive↔not-alive transition** (DDS 1.4 §2.2.4.1):
  alive→not-alive does `alive_count--` / `not_alive_count++` (with the `*_change` deltas), the
  reverse on a fresh assertion; `last_publication_handle` is the transitioned writer's GUID.
- **Writer-side LIVELINESS_LOST is produced.** On the DCPS announce cadence (`spin`) the
  `%writer-liveliness-sweep` checks each local DataWriter's OWN liveliness (DDS 1.4 §2.2.3.11):
  a writer fires `on_liveliness_lost` (and bumps LIVELINESS_LOST `total_count`, monotonic per
  DDS 1.4 §2.2.4.1) when it has not asserted within its offered `lease_duration`. Assertion is
  kind-aware: AUTOMATIC writers are asserted by the cadence (so they only go lost if the
  participant stops announcing — degenerate); MANUAL_BY_PARTICIPANT writers are asserted by a
  `write` or `assert_liveliness` on **any** of the participant's MANUAL_BY_PARTICIPANT writers;
  MANUAL_BY_TOPIC writers only by a `write` / `assert_liveliness` on **that** writer. The loss
  fires **once per going-lost transition**; re-asserting transitions the writer back to alive
  (it never decrements `total_count`), and a later re-loss increments again. An infinite lease
  never goes lost.
- **All standard communication statuses fire (FR-DCPS-3).** MATCHED, INCOMPATIBLE_QOS,
  INCONSISTENT_TOPIC, SAMPLE_REJECTED, LIVELINESS_CHANGED/LOST, DATA_AVAILABLE/ON_READERS, and —
  since WP-DCPS-API-COMPLETION S4 — OFFERED/REQUESTED_DEADLINE_MISSED and SAMPLE_LOST are all
  produced and surfaced, each with its `get-*-status` accessor and the §2.2.2.1.9 read-reset.
  DEADLINE misses fire from a per-participant background monitor thread that arms a per-instance
  timer on each write (offered) / received sample (requested) and fires when a period elapses with
  no rearm (the default DURATION_INFINITE arms nothing — no thread, zero cost). SAMPLE_LOST fires
  when a sample is permanently unavailable: a best-effort gap in the delivered SN stream, or an
  irrecoverable reliable GAP (the writer purged history the reader never received — a KEEP_LAST
  overwrite / RESOURCE_LIMITS eviction). A secure-undecryptable suppressed sample is not counted in
  v1 (ADR 0031 governs that path).
- **Content filtering is reader-side only.** A `ContentFilteredTopic` presents its related
  topic's name/type for SEDP matching and applies the filter in the reader's drain; the writer
  sends every sample. Writer-side filtering is a later increment.
- **RESOURCE_LIMITS rejection is at the DCPS cache.** `SAMPLE_REJECTED` enforcement
  (`max_samples`, `max_instances`, `max_samples_per_instance`) happens in the reader's drain,
  not in the RTPS HistoryCache.
- **Types: `:final` extensibility only.** `define-dds-type` rejects `:appendable`/`:mutable`,
  and only scalar/string `@key` members are supported (see [Type system](type-system.md)).

## See also

- [QoS & RxO matching](qos.md) — the policies behind `matched-count`, REQUESTED/OFFERED_INCOMPATIBLE_QOS.
- [Type system & code generation](type-system.md) — `define-dds-type`, the `type-support` vtable, `find-type-support`.
- [Discovery](discovery.md) — SPDP/SEDP, the `disc-node`, and what `spin` drives.
