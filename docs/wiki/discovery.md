# Discovery

Discovery (**L5**, system `dds-disc`) is the control plane that lets two RTPS participants
find each other and agree on which endpoints to connect. A `disc-node` is a minimal RTPS
participant: it owns a metatraffic UDPv4 socket and a background receiver thread, announces
its `SPDPdiscoveredParticipantData` to its peers (and optionally a multicast group), exchanges
endpoint descriptions via SEDP, matches local against remote endpoints by the DDS RxO rules,
and — once a writer/reader pair matches — carries user samples over the reliable
HEARTBEAT/ACKNACK data plane. It sits directly on top of the [RTPS engine](rtps-engine.md):
the wire codecs and builtin EntityIds live in `dds.rtps.discovery` and `dds.rtps.message`, and
the value-level reliable state machines come from `dds.rtps.reliable`. The [DCPS](dcps.md)
layer drives a `disc-node` through its hooks.

Two packages are in play:

| Package | Nickname | Responsibility |
|---|---|---|
| `net.goenninger.dds.rtps.discovery` | `dds.rtps.discovery` | the `Locator_t` codec, builtin EntityIds, and the SPDP/SEDP `ParameterList` build/parse (the data **shapes** on the wire) |
| `net.goenninger.dds.disc` | `dds.disc` | the `disc-node` — sockets, threads, announce/record, RxO matching, the reliable user-data plane (the **behaviour**) |

`dds.rtps.discovery` is a CLOS-free package (`defstruct` + monomorphic functions, every parser
bounds-checked). `dds.disc` is control-plane, not a measured hot path; its serialization reuses
per-node scratch buffers so repeated announces allocate zero foreign memory.

---

## API reference

### Builtin EntityIds & `Locator_t` (`dds.rtps.discovery`)

Builtin EntityIds (RTPS 2.5 §9.3.1.3 Table 9.2) and the 24-octet `Locator_t`
(§9.3.2.1 / §9.3.2.4).

- Builtin EntityIds: `dds.rtps.discovery:+entityid-spdp-writer+`, `+entityid-spdp-reader+`, `+entityid-sedp-pub-writer+`, `+entityid-sedp-pub-reader+`, `+entityid-sedp-sub-writer+`, `+entityid-sedp-sub-reader+`.
- `dds.rtps.discovery:+locator-kind-udpv4+` — `LOCATOR_KIND_UDPv4 = 1` (§9.3.2.1 / §9.3.2.4).
- `dds.rtps.discovery:+locator-bytes+` — `Locator_t` size = `{long kind; unsigned long port; octet address[16];}` = 24 octets.
- `dds.rtps.discovery:write-locator` *(cursor kind port address)* — write a 24-octet `Locator_t`: kind (i32) + port (u32) in cursor endianness, then 16 raw address octets.
- `dds.rtps.discovery:read-locator` *(cursor)* — read a 24-octet `Locator_t`; returns `(values kind port address)` (kind is the signed i32), or `NIL` if fewer than 24 octets remain. Bounds-checked.
- `dds.rtps.discovery:make-ipv4-locator` *(ip)* — build a 16-octet Locator address from a 4-octet IPv4 vector: 12 leading zeros then `a.b.c.d` at `[12..15]` (§9.3.2.4).
- `dds.rtps.discovery:make-locator` *(&key kind port address)* — construct a `locator` struct (transport `KIND`, `PORT` u32, 16-octet `ADDRESS`).
- `dds.rtps.discovery:locator` / `locator-p` — the struct type and predicate.
- Accessors: `locator-kind`, `locator-port`, `locator-address`.
- `dds.rtps.discovery:locator-ipv4-string` *(loc)* — dotted-quad for a UDPv4 locator (IPv4 in octets 12..15).
- `dds.rtps.discovery:locator-usable-udpv4-p` *(loc)* — T iff `loc` is a UDPv4 locator with a routable (non-`0.0.0.0`) address.
- `dds.rtps.discovery:usable-udpv4-locator` *(locators)* — the first routable UDPv4 locator in a list, or `NIL` — the locator-list selection that lets the data plane reach a foreign participant advertising several.

### Writer Liveliness Protocol — `ParticipantMessageData` (`dds.rtps.discovery`)

The wire foundation of the Writer Liveliness Protocol (RTPS 2.5 §8.4.13). The
`BuiltinParticipantMessageWriter`/`Reader` carry a `ParticipantMessageData` sample
(§8.4.13.4 / §9.6.3.2) whose DDS key is `participantGuidPrefix + kind`.

This codec is **byte-validated against the conformant peer eProsima Fast DDS 3.6.1**: a live
Fast DDS `BuiltinParticipantMessageWriter` (`0x000200c2`) AUTOMATIC-liveliness `DATA` is
decoded by `parse-participant-message` and reproduced byte-exact by
`serialize-participant-message` (locked test `fastdds-participant-message`). Note that live
RTI Connext does **not** emit the standard `ParticipantMessageData` — it uses the proprietary
`NDDSPING` — so a conformant peer is the oracle here; and a peer emits the message only when a
local writer has a *finite*-lease `LIVELINESS` that actually asserts.

- P2P built-in endpoint EntityIds (§9.6.2.2 / §8.4.13.2): `dds.rtps.discovery:+entityid-p2p-participant-message-writer+` = `{{00,02,00},c2}` (`#x000200c2`), `+entityid-p2p-participant-message-reader+` = `{{00,02,00},c7}` (`#x000200c7`).
- `kind` values (§9.6.3.2), stored as the integer the wire `octet[4]` encodes big-endian: `+pmd-kind-unknown+` = 0 `{0,0,0,0}`, `+pmd-kind-automatic+` = 1 `{0,0,0,1}`, `+pmd-kind-manual-by-participant+` = 2 `{0,0,0,2}`.
- `availableBuiltinEndpoints` bits (§9.4.2.10): `+be-participant-message-writer+` = bit 10, `+be-participant-message-reader+` = bit 11. Both are set in `+builtin-endpoint-set-default+` now that the Writer Liveliness Protocol endpoints are wired (see the disc-layer section below).
- `dds.rtps.discovery:make-participant-message` *(&key guid-prefix kind data)* — construct the struct (12-octet `GUID-PREFIX`, integer `KIND`, octet-vector `DATA`).
- `dds.rtps.discovery:participant-message` / `participant-message-p` — the struct type and predicate.
- Accessors: `participant-message-guid-prefix`, `participant-message-kind`, `participant-message-data`.
- `dds.rtps.discovery:serialize-participant-message` *(pm)* — the bare CDR struct bytes (no encapsulation): `prefix(12)` + `kind` as `octet[4]` big-endian + `data.length` (u32 LE) + data octets, no trailing pad. The discovery layer wraps these in the `SerializedPayload` encapsulation header.
- `dds.rtps.discovery:parse-participant-message` *(bytes)* — parse the bare CDR struct; returns a `participant-message`, or `NIL` on truncation or an over-long `data.length`. Every field is bounds-checked before it is read.

### SPDP — discovered participant data (`dds.rtps.discovery`)

`SPDPdiscoveredParticipantData` (§8.5.3.2 / §9.6.2.2): the subset of
`ParticipantBuiltinTopicData` carried as a `ParameterList` in the SPDP DATA.

- `dds.rtps.discovery:make-spdp-data` *(&key guid-prefix version-major version-minor vendor-id default-unicast-locators metatraffic-unicast-locators lease-duration-seconds builtin-endpoint-set)* — construct the SPDP struct (GUID prefix, protocol version, vendor id, default/metatraffic unicast locator lists, lease duration, builtin-endpoint set).
- `dds.rtps.discovery:spdp-data` / `spdp-data-p` — the struct type and predicate.
- Accessors: `spdp-data-guid-prefix`, `spdp-data-version-major`, `spdp-data-version-minor`, `spdp-data-vendor-id`, `spdp-data-default-unicast-locators`, `spdp-data-metatraffic-unicast-locators`, `spdp-data-lease-duration-seconds`, `spdp-data-builtin-endpoint-set`.
- `dds.rtps.discovery:serialize-spdp-data` *(cursor data)* — serialize SPDP data as a `ParameterList` terminated by `PID_SENTINEL` (§8.5.3.2 / §9.4.2.11).
- `dds.rtps.discovery:parse-spdp-data` *(cursor)* — parse an SPDP `ParameterList` into an `spdp-data` struct, or `NIL` if the list is truncated. Bounds-checked.
- `dds.rtps.discovery:run-discovery-test` — standalone round-trip + byte-exact `Locator_t` check (no external test framework).

### SEDP — endpoint data & RxO matching (`dds.rtps.discovery`)

`DiscoveredWriterData` / `DiscoveredReaderData` (§8.5.4 / §9.6.2.2): a 16-octet GUID, topic +
type names, the QoS carried for RxO matching, and optional `PID_TYPE_INFORMATION`. One
`endpoint-data` struct serves both roles in v1.

- `dds.rtps.discovery:+reliability-best-effort+` (1) / `+reliability-reliable+` (2) — `ReliabilityQosPolicyKind` wire values (RELIABLE is the stronger/higher RxO value) (DDS-XTypes 1.3 §7.6.3.1.2 IDL).
- `dds.rtps.discovery:make-endpoint-data` *(&key guid topic-name type-name qos type-information)* — construct an endpoint description (the `qos` is a `dds.qos:qos`; `type-information` is opaque pre-serialized XTypes `TypeInformation`).
- `dds.rtps.discovery:endpoint-data` / `endpoint-data-p` — the struct type and predicate.
- Accessors: `endpoint-data-guid`, `endpoint-data-topic-name`, `endpoint-data-type-name`, `endpoint-data-qos`, `endpoint-data-type-information`.
- `dds.rtps.discovery:serialize-endpoint-data` *(cursor data)* — serialize as a `ParameterList` terminated by `PID_SENTINEL` (§8.5.4 / §9.4.2.11). Emits `PID_TYPE_INFORMATION` only when present (peers skip unknown PIDs).
- `dds.rtps.discovery:parse-endpoint-data` *(cursor role)* — parse a SEDP `ParameterList` into an `endpoint-data` struct, or `NIL` if truncated. Bounds-checked. The required `ROLE` (`:writer` / `:reader`) seeds the QoS defaults an **absent** parameter must assume (RTPS 2.5 §9.4.2.11.2): a DCPSPublication defaults RELIABILITY to RELIABLE, a DCPSSubscription to BEST_EFFORT (DDS 1.4 §2.2.3). RTI Connext elides default-valued PIDs, so a reliable Connext writer carries **no** `PID_RELIABILITY` — parsing it with reader defaults would fail the RxO check and silently prevent the match.
- `dds.rtps.discovery:endpoint-match-p` *(writer-data reader-data)* — `(values MATCH-P INCOMPATIBLE)`: topic + type names equal AND the offered (writer) QoS is RxO-compatible with the requested (reader) QoS (the full DDS 1.4 §2.2.3 table via `dds.qos:qos-rxo-compatible`). `INCOMPATIBLE` is the failing-policy list; `'(:topic-or-type)` on a name mismatch.
- `dds.rtps.discovery:run-sedp-test` — standalone round-trip + RxO truth-table check.

### The `disc-node` (`dds.disc`)

A minimal RTPS participant for discovery and the user-data plane.

- `dds.disc:make-disc-node` *(&key guid-prefix domain host port peers multicast advertise-address)* — open a metatraffic UDPv4 socket bound to `HOST:PORT` and build a node. `PEERS` is a list of `(host-string . port)` the node announces SPDP to. `MULTICAST` opens a second socket bound to the SPDP multicast port and joins the well-known group (FR-DISC-1/3/4).
- `dds.disc:disc-node` / `disc-node-p` — the struct type and predicate.
- `dds.disc:disc-node-guid-prefix` *(node)* — the node's 12-octet GUID prefix.
- `dds.disc:disc-node-port` *(node)* — the bound metatraffic UDP port.
- `dds.disc:disc-node-peers` *(node)* — the static unicast SPDP peer list (settable via `setf`).
- `dds.disc:start-node` *(node)* — spawn the background receiver thread(s): the unicast metatraffic socket always, plus the multicast socket if enabled. Returns `node`.
- `dds.disc:stop-node` *(node)* — close the node's socket(s) (terminating its receiver thread(s)) and free the reusable announce scratch buffers. Idempotent.

### Announce & register endpoints (`dds.disc`)

- `dds.disc:announce-participant` *(node)* — announce the node's `SPDPdiscoveredParticipantData` (SPDP builtin participant writer) to every unicast peer and, if multicast is enabled, to the well-known SPDP multicast group. Also asserts the node's Writer Liveliness on the announce cadence (`assert-participant-liveliness`, RTPS 2.5 §8.4.13.5).
- `dds.disc:add-local-writer` *(node &key topic type reliability key keyed qos type-information)* — register a local publication (writer endpoint). `KEYED` (default `T`) selects the RTPS 2.5 §9.3.1.2 entity kind: `WITH_KEY` `0x02` or `NO_KEY` `0x03`, and sets the node's data-plane writer EntityId accordingly (`0x102`/`0x103`). `TYPE-INFORMATION` is the opaque serialized XTypes `TypeInformation` for `PID_TYPE_INFORMATION`.
- `dds.disc:add-local-reader` *(node &key topic type reliability key keyed qos type-information)* — register a local subscription (reader endpoint). `KEYED` (default `T`) selects the entity kind: reader `WITH_KEY` `0x07` or `NO_KEY` `0x04` (node id `0x107`/`0x104`). A keyed/no-key endpoint-kind disagreement is a silent non-match at discovery (`%match-remote-endpoint`); DCPS `create-datawriter`/`create-datareader` derive `KEYED` from `type-support-keyed-p` (a type with a `@key` member is keyed). Live-confirmed both directions vs Connext 7.3.1 (`interop/connext/nokey/`).
- `dds.disc:announce-endpoints` *(node)* — send the node's local publications (SEDP publications writer) and subscriptions (SEDP subscriptions writer) to every discovered participant's metatraffic unicast locator (§8.5.4).

### Writer Liveliness — assertion & inbound stamps (`dds.disc`)

The disc layer wires the `BuiltinParticipantMessageWriter`/`Reader` (RTPS 2.5 §8.4.13) onto the discovery node, mirroring the TypeLookup endpoints.

- `dds.disc:assert-participant-liveliness` *(node)* — assert the participant's Writer Liveliness on the announce cadence (§8.4.13.5). For each liveliness kind the local writers require — one `AUTOMATIC` instance if any local writer's `LIVELINESS` QoS is `:automatic`, one `MANUAL_BY_PARTICIPANT` instance if any is `:manual-by-participant` (the two are distinct DDS-key instances `participantGuidPrefix + kind`) — write one `ParticipantMessageData` to every discovered participant's metatraffic unicast locator via the `BuiltinParticipantMessageWriter`. Driven by `announce-participant`. `MANUAL_BY_TOPIC` is not carried by this protocol (§8.4.13.5). Cadence note: v1 uses the announce cadence as the assertion rate, which must (and does, for default leases) beat the smallest writer lease; a finer per-lease timer is a noted refinement.
- Reliability (§8.4.13.3): the `BuiltinParticipantMessageWriter` is `RELIABLE` — each assertion is a DATA submessage followed by a non-final `HEARTBEAT` for the PM writer, so a reliable peer can NACK a loss. No per-sample resend store is kept: the assertion is periodic + idempotent, so the next cadence re-sends any lost sample.
- `dds.disc:disc-node-remote-liveliness-stamp` *(node prefix kind)* — the internal-real-time stamp of the last liveliness assertion of `KIND` received from participant `PREFIX` (anti-spoof: keyed by the datagram's source GUID prefix), or `NIL` if none.
- `dds.disc:%liveliness-sweep` *(node)* — reader-side Writer Liveliness timing (RTPS 2.5 §8.4.13). On the announce cadence (driven by `announce-endpoints`, beside `%lease-sweep`), for each **matched remote writer** decide alive vs not-alive: alive while a liveliness assertion of the writer's offered `LIVELINESS` kind (its inbound `disc-node-remote-liveliness-stamp`) has arrived within the writer's offered `lease_duration`. A writer with an infinite lease, or `MANUAL_BY_TOPIC` (not carried by this protocol), is treated as always alive. Fires the `disc-node-on-liveliness-changed` hook *(guid alive-p)* only on an alive↔not-alive **transition** (a freshly matched writer starts alive), so the DCPS `LIVELINESS_CHANGED` status counts each crossing once. The DCPS layer installs the hook to bump the local `DataReader`'s `LIVELINESS_CHANGED` status (DDS 1.4 §2.2.4.1) and fire `on_liveliness_changed`.

### Discovered / matched state (`dds.disc`)

- `dds.disc:disc-node-discovered-count` *(node)* — number of remote participants discovered.
- `dds.disc:disc-node-discovered-prefixes` *(node)* — list of the 12-octet GUID prefixes discovered.
- `dds.disc:disc-node-matched-count` *(node)* — number of remote endpoints that matched one of the node's local endpoints.
- `dds.disc:disc-node-matched-topics` *(node)* — topic names of the matched remote endpoints.
- `dds.disc:disc-node-discovered-writers-list` *(node)* — snapshot of every discovered remote publication (matched or not; used by the builtin-topic readers).
- `dds.disc:disc-node-discovered-readers-list` *(node)* — snapshot of every discovered remote subscription.
- `dds.disc:node-discovered-participants` *(node)* — snapshot of the SPDP data for every discovered participant (diagnostic).
- `dds.disc:resolved-destination` *(spdp-data)* — the `(host . port)` this stack would send user data to for a participant (its resolved routable locator), or `NIL` (diagnostic).

### Control-plane hooks (`dds.disc`)

Optional callbacks the [DCPS](dcps.md) layer installs to surface events to the application
(DDS statuses, listeners, the WaitSet wake). Each fires once per remote endpoint
(`on-sample` once per stored user sample). All are settable via `setf`.

- `dds.disc:disc-node-on-match` — fired for a newly-matched remote endpoint (drives SUBSCRIPTION/PUBLICATION_MATCHED).
- `dds.disc:disc-node-on-unmatch` — fired (with `direction` and the remote `endpoint-data`) once per matched remote endpoint pruned by participant-lease expiry (RTPS 2.5 §8.5.3.3.2); DCPS reacts by **decrementing** the local DataReader's SUBSCRIPTION_MATCHED / DataWriter's PUBLICATION_MATCHED `current_count` (`current_count_change` negative; `total_count` stays monotonic, DDS 1.4 §2.2.4.1).
- `dds.disc:disc-node-on-incompatible-qos` — fired when a remote agreed on topic+type but failed RxO (drives OFFERED/REQUESTED_INCOMPATIBLE_QOS), passing the failing-policy list.
- `dds.disc:disc-node-on-inconsistent-topic` — fired on a same-name/different-type collision (drives INCONSISTENT_TOPIC).
- `dds.disc:disc-node-on-sample` — fired when a new user sample is stored (drives DATA_AVAILABLE + the condvar WaitSet wake).

#### Type-compatibility gate + parked matches

A dds-types-aware layer (DCPS) can interpose a **type-compatibility verdict** before any
SEDP match is recorded — e.g. XTypes assignability, possibly waiting on a TypeLookup query.
The DCPS layer installs exactly such a gate on every `DomainParticipant` (FR-TYPE-4 gated
matching — see [DCPS](dcps.md), "Assignability-gated matching"). This gate has been **proven
firing live against RTI Connext 7.3.1** (2026-06-11, ADR 0011): on a stock Connext peer's
`PID_TYPE_OBJECT_LB`, a compatible local type returns `:compatible` (the match records and
samples flow) and an incompatible one returns `:incompatible` (routed to INCONSISTENT_TOPIC,
no match, no data). Note the gate fires only for a **DCPS** participant — the standalone
`dds.shapes:run-subscriber` is a bare disc-node and installs no gate.

- `dds.disc:disc-node-type-gate` — optional gate consulted **before a match is recorded**, in both directions (discovered publication vs. local readers, discovered subscription vs. local writers). Contract: called as `(funcall gate node remote local)` where `remote` and `local` are the `dds.rtps.discovery:endpoint-data` pair that just passed topic/type-name + RxO matching; it runs on the receiver thread **outside the node lock** (the gate is user code, like the `on-*` hooks). Verdicts: `:compatible` — record + fire the match as usual; `:incompatible` — routed to the INCONSISTENT_TOPIC record/fire path (same as a type-name mismatch); `:pending` — the decision is **parked** (deduped by remote GUID, so a re-announced remote parks at most once) and no match is recorded until `resume-parked-matches`. A `NIL` gate (the default) — and any other return value — behaves as `:compatible`, byte-identical to plain SEDP matching.
- `dds.disc:resume-parked-matches` *(node)* — take + clear the parked list under the node lock, then re-run each parked match decision outside it; the gate is consulted again, so a still-`:pending` verdict re-parks the entry (still deduped). Call once the gate's verdict has resolved (e.g. a TypeLookup reply arrived).
- `dds.disc:disc-node-parked-count` *(node)* — number of parked match decisions awaiting `resume-parked-matches` (diagnostic).

### The reliable user-data plane (`dds.disc`)

Wires the value-level reliable writer/reader (`dds.rtps.reliable`) to UDP. For v1 the
user/metatraffic share one socket (routing is by EntityId), peers double as the data
destination, and the `SerializedPayload` is opaque bytes. A sample larger than
`dds.rtps.reliable:*fragment-size*` is sent as a series of **DATA_FRAG** submessages plus a
**HEARTBEAT_FRAG** (then the usual sample-level HEARTBEAT); inbound DATA_FRAGs are reassembled
per (writer, SN) with `*max-reassembly-bytes*`/`*max-reassembly-fragments*` guards, a
HEARTBEAT_FRAG is answered with a NACK_FRAG naming the still-missing fragments, and a peer's
NACK_FRAG is answered by resending exactly the named fragments (RTPS 2.5 §8.3.8.3 / §9.4.5.5;
validated live against RTI Connext 7.3.1 in both directions, including forced-loss NACK_FRAG
recovery).

- `dds.disc:enable-publisher` *(node)* — give the node a reliable user writer (KEEP_ALL) and install the writer-side data-plane hooks (retransmit on ACKNACK; resend named fragments on NACK_FRAG). Call after `add-local-writer`.
- `dds.disc:enable-subscriber` *(node)* — give the node a reliable user reader and install the reader-side hooks (store DATA, ACKNACK on HEARTBEAT, reassemble DATA_FRAG, NACK_FRAG on HEARTBEAT_FRAG). Call after `add-local-reader`.
- `dds.disc:publish-sample` *(node payload)* — publish an opaque `SerializedPayload` on the node's user writer: add it to the writer HistoryCache, then push DATA (or DATA_FRAGs + HEARTBEAT_FRAG) + HEARTBEAT to matched peers (FR-RTPS-8).
- `dds.disc:*debug-drop-fragment-numbers*` — debug-only fragment-loss injection (default `NIL` = off): a list of 1-based fragment numbers the send path silently withholds when fragmenting (initial push **and** sample-level ACKNACK retransmits) — the whole packed `DATA_FRAG` submessage is withheld if **any** fragment it contains is named; NACK_FRAG-driven resends are not filtered, so the peer's NACK_FRAG is the only recovery path — the live proof of fragment-level reliability. Never set in production. (`make large-pub DROP=3` sets it via `run-large-publisher :drop-fragments`.)
- `dds.disc:node-sample-count` *(node)* — number of distinct user samples the subscriber has received.
- `dds.disc:node-sample` *(node sn)* — the received payload for sequence number `SN`, or `NIL`.
- `dds.disc:node-sample-sns` *(node)* — sequence numbers of the user samples received so far (unordered; SNs may not start at 1 against Connext).
- `dds.disc:node-acks-in` *(node)* — count of ACKNACKs received for the node's user writer — i.e. how many times a matched reader (incl. a foreign one like RTI) acknowledged our data (`>0` proves a remote reliable reader is receiving; diagnostic).

### The TypeLookup service endpoints (`dds.disc`)

The four built-in TypeLookup service endpoints (DDS-XTypes 1.3 §7.6.3.3.3 Table 61) ride the
node's metatraffic socket; requests and replies travel as `DATA` submessages routed by
writerId, with the same per-remote reliable builtin bookkeeping SEDP uses (a peer's HEARTBEAT
is answered with a final ACKNACK) plus a bounded resend store for the reply writer (a peer's
ACKNACK NACKing a reply SN triggers a retransmit; the store is small because the service is
VOLATILE per §7.6.3.3.3). The server side answers any inbound `TypeLookup_Request` via the
transport-free core `dds.types:type-lookup-respond` over the global type registry (see
[Type system](type-system.md)). No oracle exists against Connext (RTI does not implement the
standard service, ADR 0010); the reference tshark dissector names all four EntityIds and
parses the request/reply `DATA` + the reply HEARTBEAT with no malformed markers, and the
byte-level encoding is now PEER-CONFIRMED against live Fast DDS 3.6.1 in both directions
(FR-IO-2 S4, 2026-06-12: our client consumed their server's reply, and — under the
non-stock vendor-gate-bypass diagnostic — their stock TypeLookup client consumed our
server's getTypeDependencies + getTypes replies and built its DynamicType from our MINIMAL
TypeObject; see the CONFIRM-VS-PEER walk in `interop/fastdds/README.md`).

- `dds.disc:+entityid-tl-req-writer+` / `dds.disc:+entityid-tl-req-reader+` — `ENTITYID_TL_SVC_REQ_WRITER/READER` = `{{00,03,00},c3/c4}` (XTypes 1.3 Table 61).
- `dds.disc:+entityid-tl-reply-writer+` / `dds.disc:+entityid-tl-reply-reader+` — `ENTITYID_TL_SVC_REPLY_WRITER/READER` = `{{00,03,01},c3/c4}` (XTypes 1.3 Table 61).
- `dds.disc:type-lookup-query` *(node prefix hashes continuation)* — ask participant `PREFIX`'s TypeLookup service for the TypeObjects of `HASHES` (a list of 14-octet EquivalenceHashes) via a `getTypes` request sent to its metatraffic locator. `CONTINUATION` is called exactly once, outside the node lock, with `(pairs okp)`: `okp` `T` plus the `(hash . typeobject-octets)` alist on a `REMOTE_EX_OK` reply (possibly empty — none of the hashes were known to the peer), or `(NIL NIL)` on a non-OK reply, on expiry, or immediately at the pending cap. Returns `T` if the request was recorded, `NIL` on the cap rejection. The request's `instanceName` is `"dds.builtin.TOS."` + the 24-char lowercase-hex target prefix (§7.6.3.3.4 is self-contradictory on the length; **accepted live by Fast DDS 3.6.1** — its server replied `REMOTE_EX_OK`, FR-IO-2 S4 leg A; Fast DDS's own client sends yet another form, a 32-char full-GUID hex whose entityId varies per call, which our server accepts since the parse never gates on `instanceName` — no implementation validates the length). A conformant server may answer a MINIMAL query with COMPLETE TypeObjects plus the `complete_to_minimal` mapping (XTypes 1.3 §7.6.3.3.4.2 — Fast DDS does): such pairs are reconstructed to MINIMAL (`dds.types:complete-to-minimal-type-object`) and delivered as `(minimal-hash . minimal-octets)` only when the reconstruction re-hashes to the mapped hash (else dropped, fail-open), so the continuation always sees MINIMAL-keyed pairs.
- `dds.disc:tl-sweep` *(node)* — expire every pending query past its deadline (continuation called with `(NIL NIL)`). Driven automatically on the periodic announce cadence (`announce-endpoints`); call directly to force expiry.
- `dds.disc:*typelookup-timeout*` — seconds before a pending query expires (default 3; read per query). Local policy — the service QoS itself is RELIABLE/KEEP_ALL/VOLATILE (§7.6.3.3.3).
- `dds.disc:*max-typelookup-pending*` — cap on in-flight client requests per node (default 64; NFR-SEC-POSTURE). At the cap a query is rejected immediately (continuation `(NIL NIL)`, return `NIL`).

### Standalone tests (`dds.disc`)

Self-contained, runnable end-to-end checks over UDP loopback (no external framework):

- `dds.disc:run-spdp-discovery-test` — two unicast-peered participants discover each other via SPDP.
- `dds.disc:run-sedp-discovery-test` — SPDP then SEDP: a RELIABLE writer + a BEST_EFFORT reader on the same topic/type match.
- `dds.disc:run-mcast-discovery-test` — two participants with **no** unicast peers discover purely via multicast SPDP, then match via unicast SEDP.
- `dds.disc:run-dataplane-test` — full stack: discover, match, then publish a user sample the subscriber receives reliably (asserts exact payload bytes).
- `dds.disc:run-large-dataplane-test` — same full stack with a 4000-octet sample: the writer fragments into DATA_FRAGs + HEARTBEAT_FRAG, the subscriber reassembles byte-exactly (RTPS 2.5 §9.4.5.5).
- `dds.disc:run-locator-filter-test` — locator-list selection + foreign-participant robustness (skip `0.0.0.0`, fall back, yield `NIL`, non-fatal send to `0.0.0.0`).

---

## Examples

The examples below are adapted from the verified tests in `src/dds-disc/disc.lisp`,
`src/dds-disc/dataplane.lisp`, and `src/dds-tests/integration-test.lisp`. Two participants in
one image on `127.0.0.1` is the normal pattern.

### 1. SPDP: two participants discover each other

Each carries the other as a unicast peer, both announce, and each records the other's GUID
prefix. Adapted from `dds.disc:run-spdp-discovery-test`.

```lisp
(let* ((p1    (make-array 12 :element-type '(unsigned-byte 8) :initial-element 1))
       (p2    (make-array 12 :element-type '(unsigned-byte 8) :initial-element 2))
       (node1 (dds.disc:make-disc-node :guid-prefix p1 :host "127.0.0.1" :port 0))
       (node2 (dds.disc:make-disc-node :guid-prefix p2 :host "127.0.0.1" :port 0)))
  (unwind-protect
       (progn
         ;; tell each node about the other's bound metatraffic port
         (setf (dds.disc:disc-node-peers node1)
               (list (cons "127.0.0.1" (dds.disc:disc-node-port node2))))
         (setf (dds.disc:disc-node-peers node2)
               (list (cons "127.0.0.1" (dds.disc:disc-node-port node1))))
         (dds.disc:start-node node1)
         (dds.disc:start-node node2)
         (dds.disc:announce-participant node1)
         (dds.disc:announce-participant node2)
         (loop repeat 100
               until (and (plusp (dds.disc:disc-node-discovered-count node1))
                          (plusp (dds.disc:disc-node-discovered-count node2)))
               do (sleep 0.02))
         (list (dds.disc:disc-node-discovered-count node1)     ; => 1
               (dds.disc:disc-node-discovered-count node2)))   ; => 1
    (dds.disc:stop-node node1)
    (dds.disc:stop-node node2)))
```

### 2. SEDP: register endpoints and match by RxO

After SPDP, each side announces its local endpoints; a RELIABLE writer and a BEST_EFFORT
reader on `(Square, ShapeType)` are RxO-compatible (offered RELIABLE ≥ requested BEST_EFFORT).
Adapted from `dds.disc:run-sedp-discovery-test`.

```lisp
;; ... node1, node2 created and peered as in example 1 ...
(dds.disc:add-local-writer node1 :topic "Square" :type "ShapeType"
                                 :reliability dds.rtps.discovery:+reliability-reliable+)
(dds.disc:add-local-reader node2 :topic "Square" :type "ShapeType"
                                 :reliability dds.rtps.discovery:+reliability-best-effort+)
(dds.disc:start-node node1)
(dds.disc:start-node node2)
(dds.disc:announce-participant node1)
(dds.disc:announce-participant node2)
(loop repeat 100
      until (and (plusp (dds.disc:disc-node-discovered-count node1))
                 (plusp (dds.disc:disc-node-discovered-count node2)))
      do (sleep 0.02))
;; now exchange endpoints over SEDP and wait for the RxO match
(dds.disc:announce-endpoints node1)
(dds.disc:announce-endpoints node2)
(loop repeat 100
      until (and (plusp (dds.disc:disc-node-matched-count node1))
                 (plusp (dds.disc:disc-node-matched-count node2)))
      do (sleep 0.02))
(dds.disc:disc-node-matched-topics node2)        ; => ("Square")
```

### 3. The reliable user-data plane: publish and receive

Once a pair matches, `enable-publisher` / `enable-subscriber` install the reliable data-plane
hooks; `publish-sample` then pushes DATA + HEARTBEAT and the subscriber answers with ACKNACK,
so the exact payload arrives even over a lossy/reordering link. Adapted from
`dds.disc:run-dataplane-test`.

```lisp
(let* ((p1    (make-array 12 :element-type '(unsigned-byte 8) :initial-element 1))
       (p2    (make-array 12 :element-type '(unsigned-byte 8) :initial-element 2))
       (node1 (dds.disc:make-disc-node :guid-prefix p1 :host "127.0.0.1" :port 0))
       (node2 (dds.disc:make-disc-node :guid-prefix p2 :host "127.0.0.1" :port 0))
       (payload (make-array 8 :element-type '(unsigned-byte 8)
                              :initial-contents '(#xDE #xAD #xBE #xEF #x01 #x02 #x03 #x04))))
  (unwind-protect
       (progn
         (dds.disc:add-local-writer node1 :topic "Square" :type "ShapeType"
                                    :reliability dds.rtps.discovery:+reliability-reliable+)
         (dds.disc:enable-publisher node1)
         (dds.disc:add-local-reader node2 :topic "Square" :type "ShapeType"
                                    :reliability dds.rtps.discovery:+reliability-reliable+)
         (dds.disc:enable-subscriber node2)
         (setf (dds.disc:disc-node-peers node1)
               (list (cons "127.0.0.1" (dds.disc:disc-node-port node2))))
         (setf (dds.disc:disc-node-peers node2)
               (list (cons "127.0.0.1" (dds.disc:disc-node-port node1))))
         (dds.disc:start-node node1) (dds.disc:start-node node2)
         (dds.disc:announce-participant node1) (dds.disc:announce-participant node2)
         (loop repeat 100
               until (and (plusp (dds.disc:disc-node-discovered-count node1))
                          (plusp (dds.disc:disc-node-discovered-count node2)))
               do (sleep 0.02))
         (dds.disc:announce-endpoints node1) (dds.disc:announce-endpoints node2)
         (loop repeat 100 until (plusp (dds.disc:disc-node-matched-count node2)) do (sleep 0.02))
         ;; publish; the reliable plane delivers it
         (dds.disc:publish-sample node1 payload)
         (loop repeat 150 until (plusp (dds.disc:node-sample-count node2)) do (sleep 0.02))
         (equalp (dds.disc:node-sample node2 1) payload))      ; => T
    (dds.disc:stop-node node1)
    (dds.disc:stop-node node2)))
```

### 4. A generated type across the full data plane

The data plane carries an opaque `SerializedPayload`; the application serializes/deserializes
with the generated XCDR codec at both ends — exactly as real DDS type-support does. Here a
generated `shape-type` (the canonical Connext Shapes type) flows discover → match → publish →
receive. Adapted from `run-typed-dataplane-test` in `integration-test.lisp`.

```lisp
;; the type and its %serialize-shape / %deserialize-shape helpers are defined in the test;
;; the middleware never sees the struct — only the PLAIN_CDR2_LE SerializedPayload bytes.
(dds.gen:define-dds-type shape-type (:extensibility :final)
  (color :string :key t) (x :i32) (y :i32) (shapesize :i32))

;; ... node1/node2 peered, publisher/subscriber enabled, discovered + matched as in example 3 ...
(dds.disc:publish-sample node1 (%serialize-shape (make-shape-type :color "BLUE"
                                                                  :x 100 :y 150 :shapesize 30)))
(loop repeat 150 until (plusp (dds.disc:node-sample-count node2)) do (sleep 0.02))
(let ((q (%deserialize-shape (dds.disc:node-sample node2 1))))
  (list (shape-type-color q) (shape-type-x q)))   ; => ("BLUE" 100)
```

### 5. Multicast SPDP with zero peer configuration

With `:multicast t` and **no** `peers`, participants discover via the well-known group
`239.255.0.1 : spdp-multicast-port`, then match via unicast SEDP routed to the
multicast-discovered locators. Adapted from `dds.disc:run-mcast-discovery-test`.

```lisp
(let* ((p1    (make-array 12 :element-type '(unsigned-byte 8) :initial-element 1))
       (p2    (make-array 12 :element-type '(unsigned-byte 8) :initial-element 2))
       (node1 (dds.disc:make-disc-node :guid-prefix p1 :host "127.0.0.1" :port 0 :multicast t))
       (node2 (dds.disc:make-disc-node :guid-prefix p2 :host "127.0.0.1" :port 0 :multicast t)))
  (unwind-protect
       (progn
         (dds.disc:add-local-writer node1 :topic "Square" :type "ShapeType"
                                    :reliability dds.rtps.discovery:+reliability-reliable+)
         (dds.disc:add-local-reader node2 :topic "Square" :type "ShapeType"
                                    :reliability dds.rtps.discovery:+reliability-best-effort+)
         (dds.disc:start-node node1) (dds.disc:start-node node2)
         (dds.disc:announce-participant node1) (dds.disc:announce-participant node2)
         (loop repeat 150
               until (and (member p2 (dds.disc:disc-node-discovered-prefixes node1) :test #'equalp)
                          (member p1 (dds.disc:disc-node-discovered-prefixes node2) :test #'equalp))
               do (sleep 0.02))
         (dds.disc:announce-endpoints node1) (dds.disc:announce-endpoints node2)
         (loop repeat 100
               until (and (plusp (dds.disc:disc-node-matched-count node1))
                          (plusp (dds.disc:disc-node-matched-count node2)))
               do (sleep 0.02))
         (list (dds.disc:disc-node-matched-count node1)
               (dds.disc:disc-node-matched-count node2)))     ; => (1 1)
    (dds.disc:stop-node node1)
    (dds.disc:stop-node node2)))
```

---

## `PID_TYPE_INFORMATION` on the wire

SEDP can carry the XTypes `TypeInformation` for an endpoint so a peer can look up and check the
remote type. It rides as a single Parameter (`PID_TYPE_INFORMATION`,
`dds.rtps.message:+pid-type-information+`, IDL `@id 0x0075` from DDS-XTypes 1.3) in the
endpoint's `ParameterList`. The engine treats it as **opaque pre-serialized bytes**: L4
(`dds-rtps`) must not depend on the L3 type system, so `endpoint-data-type-information` holds a
raw octet vector that `dds-disc`/`dds-dcps` build and interpret (see the field comment in
`discovery.lisp`). `serialize-endpoint-data` emits the Parameter only when it is present —
peers that don't understand the PID skip it, so this is backward-compatible. To attach it, pass
`:type-information <octets>` to `dds.disc:add-local-writer` / `add-local-reader`; on the wire it
round-trips byte-for-byte (asserted in `dds.rtps.discovery:run-sedp-test`). Building the
`TypeInformation` octets themselves is the [Type system](type-system.md)'s job.

---

## Notes / status

- **Connext interop is pending a Connext install.** Discovery correctness is proven by
  byte-exact `ParameterList`/`Locator_t` round-trips (`run-discovery-test`, `run-sedp-test`)
  and by the offline UDP-loopback handshakes above, not yet by a live RTI Connext capture. The
  locator-filter test exists specifically as a regression for foreign-stack robustness (RTI
  DDSSpy advertises several locators including `0.0.0.0`); see [Interop](interop.md).
- **One socket, peer-as-destination (v1).** User and metatraffic traffic share one UDP socket;
  routing is by EntityId. The reliable handshake runs in the receiver thread and uses the
  node's separate `rx-tx-msg` buffer, while `publish` runs on the caller thread and uses
  `tx-msg`, so no message buffer is shared across threads.
- **RxO blocks delivery, not just matching.** A topic-mismatched or RxO-incompatible peer never
  matches, and the data plane only sends to matched destinations — so an incompatible peer
  receives nothing (FR-QOS-2).
- **The user `SerializedPayload` is opaque bytes.** The data plane carries a `[offset, len)`
  region; a generated-type codec is applied by the caller (example 4) or the
  [DCPS](dcps.md) layer, not by `dds-disc`. The per-sample heap copies in `dataplane.lisp` are
  a documented v1 concern; that file is explicitly **not** a measured hot path (the gated
  hot-path files are untouched).
- **`disc-node` builtin-endpoint set is fixed.** Announced SPDP data advertises
  `builtin-endpoint-set #x0000043F` and a 100-second lease (see `%node-spdp-data`); these are
  not yet configurable.
- **Multicast send needs a `0.0.0.0`-bound unicast socket.** In `:multicast` mode the unicast
  socket binds to `0.0.0.0` (a loopback-bound socket cannot egress to a multicast group); it
  still receives unicast SEDP addressed to `127.0.0.1:port`.

## See also

- [RTPS engine](rtps-engine.md) — the submessage codec, HistoryCache, and reliable state machines this layer drives.
- [DCPS — the DDS entity API](dcps.md) — the DDS-level API that drives a `disc-node` through its hooks.
- [QoS & RxO matching](qos.md) — the `qos-rxo-compatible` rules behind `endpoint-match-p`.
- [Type system & code generation](type-system.md) — building the `PID_TYPE_INFORMATION` octets.
- [CDR codec, buffers & the arena](cdr-and-memory.md) — the encapsulation headers and buffers used by the announce path.
- [Transports](transports.md) — the UDPv4 transport (`dds.xport.udp`) the node sends through.
- [Interop with RTI Connext](interop.md) — the wire oracle and Shapes harness.
