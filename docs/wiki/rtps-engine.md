# RTPS engine

The RTPS engine (**L4**, system `dds-rtps`) is the wire-protocol heart of the stack: it
implements the OMG DDSI-RTPS 2.5 message framing, the submessage codec, the `HistoryCache`,
and the stateful reliable writer/reader state machines. It sits above the [CDR codec, buffers
& the arena](cdr-and-memory.md) (which give it the `octet-buffer`/`cursor` it reads and writes
through) and below [Discovery](discovery.md) and [DCPS](dcps.md), which drive it. Two of its
packages — `dds.rtps.message` (the network attack surface) and `dds.rtps.history` (the
per-sample `CacheChange` store) — are CLOS-free hot-path packages: `defstruct` + monomorphic
functions, with every wire constant pinned from the in-repo spec (`docs/specs/rtps-2_5.pdf`)
and every parser bounds-checked before it trusts wire data.

The engine is split across four packages:

| Package | Nickname | Responsibility |
|---|---|---|
| `net.goenninger.dds.rtps.message` | `dds.rtps.message` | Header + submessage framing, EntityId/SequenceNumber(Set), ParameterList (PID) codec, port mapping, the dispatch loop |
| `net.goenninger.dds.rtps.history` | `dds.rtps.history` | `CacheChange`, the `HistoryCache` (HISTORY + RESOURCE_LIMITS) |
| `net.goenninger.dds.rtps.reliable` | `dds.rtps.reliable` | the stateful reliable writer/reader (ReaderProxy/WriterProxy, HEARTBEAT/ACKNACK/GAP, reorder/dedup) |
| `net.goenninger.dds.rtps.discovery` | `dds.rtps.discovery` | SPDP/SEDP `Locator_t` + ParameterList codecs — covered on the [Discovery](discovery.md) page |

This page covers the first three. The discovery codecs (`dds.rtps.discovery`) are documented
under [Discovery](discovery.md) because that is where they are consumed.

---

## API reference

### Message header & framing (`dds.rtps.message`)

The 20-octet RTPS Header and the 4-octet SubmessageHeader (RTPS 2.5 §9.4.4 / §9.4.5.1).

- `dds.rtps.message:+protocol-id+` — the 4-octet RTPS message magic `'R','T','P','S'` (§9.4.4).
- `dds.rtps.message:+protocol-version-major+` / `+protocol-version-minor+` — ProtocolVersion 2.5 (§9.4.4).
- `dds.rtps.message:+vendor-id-unknown+` — `VENDORID_UNKNOWN = {0,0}` (§8.3.5.2). A conformant peer (e.g. RTI Connext) ignores a participant that advertises this; a non-zero id is required.
- `dds.rtps.message:+vendor-id-dev-provisional+` — `0x01FF`, this stack's provisional development VendorId (FR-RTPS-2), non-conflicting with the OMG DDS-RTPS registry (sequential assignments reach `0x0119` as of 2026-06-09). Replaced by an OMG-assigned id once obtained.
- `dds.rtps.message:*vendor-id*` — the 16-bit VendorId written into the RTPS header and the SPDP `PID_VENDORID`; defaults to `+vendor-id-dev-provisional+` (`0x01FF`).
- `dds.rtps.message:write-header` *(cursor guid-prefix &key vendor)* — write the 20-octet RTPS Header (12-octet GUID prefix; header fields are octet arrays, so no endianness).
- `dds.rtps.message:parse-header` *(cursor)* — parse a 20-octet Header; returns `(values major minor vendor guid-prefix)`, or `NIL` on a short buffer / wrong magic. Bounds-checked.
- `dds.rtps.message:write-submessage-header` *(cursor submessage-id flags octets-to-next)* — write a 4-octet SubmessageHeader; `octetsToNextHeader` is a u16 in the cursor's endianness, which the caller keeps consistent with the E flag.
- `dds.rtps.message:parse-submessage-header` *(cursor)* — parse a 4-octet SubmessageHeader; returns `(values submessage-id flags octets-to-next little-endian-p)`, or `NIL` on a short buffer. `octetsToNextHeader` is read with the endianness from the E flag, independent of the cursor.
- `dds.rtps.message:+flag-endianness+` — the submessage E (EndiannessFlag), bit 0; 1 = little-endian (§9.4.5.1.2).

**SubmessageKind ids** (§9.4.5.1.1): `+submsg-pad+`, `+submsg-acknack+`, `+submsg-heartbeat+`,
`+submsg-gap+`, `+submsg-info-ts+`, `+submsg-info-src+`, `+submsg-info-reply-ip4+`,
`+submsg-info-dst+`, `+submsg-info-reply+`, `+submsg-nack-frag+`, `+submsg-heartbeat-frag+`,
`+submsg-data+`, `+submsg-data-frag+`.

### EntityId & SequenceNumber (`dds.rtps.message`)

EntityId is 4 octets `entityKey[3]+entityKind`, MSB-first (§9.3.1.2); SequenceNumber is
`high (i32) + low (u32)` (§9.3.2.10).

- `dds.rtps.message:+entityid-unknown+` — `ENTITYID_UNKNOWN` as an MSB-first u32 (§9.3.1.2).
- `dds.rtps.message:+entityid-participant+` — `ENTITYID_PARTICIPANT = #x000001c1` (§9.3.1.2).
- `dds.rtps.message:write-entity-id` *(cursor entity-id)* — write a 4-octet EntityId MSB-first.
- `dds.rtps.message:read-entity-id` *(cursor)* — read a 4-octet EntityId as a u32 (MSB-first).
- `dds.rtps.message:+sequence-number-unknown+` — `SEQUENCENUMBER_UNKNOWN = {high=-1, low=0}` (§8.3.5.4).
- `dds.rtps.message:write-sequence-number` *(cursor seqnum)* — write an 8-octet SequenceNumber (high i32 then low u32, cursor endianness).
- `dds.rtps.message:read-sequence-number` *(cursor)* — read an 8-octet SequenceNumber as a signed 64-bit value.

### SequenceNumberSet (`dds.rtps.message`)

`bitmapBase + numBits + M=(numBits+31)/32` longs; offset `deltaN` maps to
`bitmap[deltaN/32]`, bit `(31 - deltaN%32)` — MSB-first (§9.4.2.6). The classic off-by-one
source.

- `dds.rtps.message:+seqnum-set-max-bits+` — maximum `numBits` in a SequenceNumberSet (256) (§9.4.2.6).
- `dds.rtps.message:write-sequence-number-set` *(cursor base numbits bitmap)* — write a SequenceNumberSet (`bitmapBase + numBits + M` longs).
- `dds.rtps.message:read-sequence-number-set` *(cursor)* — parse a SequenceNumberSet; returns `(values base numBits bitmap-words)`, or `NIL` on a short buffer / `numBits>256`. Bounds-checked.
- `dds.rtps.message:seqnum-set-bit` *(bitmap delta)* — set the bit for offset `DELTA` (word `DELTA/32`, bit `31 - DELTA%32`).
- `dds.rtps.message:seqnum-set-bit-p` *(bitmap delta)* — T iff the bit for offset `DELTA` is set.
- `dds.rtps.message:seqnum-set-member-p` *(base numbits bitmap seqnum)* — T iff `SEQNUM` is in the set, per the §9.4.2.6 membership rule.
- `dds.rtps.message:seqnum-set-from-sns` *(sns)* — build a SequenceNumberSet covering the non-empty SN list `SNS`: `(values base numBits bitmap)`, `base = min SN`, one bit set per SN via `seqnum-set-bit`. `SNS` must fit one 256-SN window (it does for the SNs of one inbound ACKNACK). Used to GAP the NACKed-but-evicted SNs (`%on-user-acknack`).

### Reliability submessages: HEARTBEAT / ACKNACK / GAP (`dds.rtps.message`)

Base forms of the three reliability submessages (§9.4.5.7 / §9.4.5.3 / §9.4.5.6). The E flag
derives from the cursor's endianness so the two stay consistent. The GroupInfo (G) and
Filtered (F) extensions are not emitted or parsed in v1.

- `dds.rtps.message:write-heartbeat` *(cursor reader-id writer-id first-sn last-sn count &key final liveliness)* — write a complete HEARTBEAT submessage (base form; body = 28).
- `dds.rtps.message:parse-heartbeat-body` *(cursor flags)* — parse a HEARTBEAT body after its header; returns `(values reader-id writer-id first-sn last-sn count final-p liveliness-p)` or `NIL`.
- `dds.rtps.message:write-acknack` *(cursor reader-id writer-id base numbits bitmap count &key final)* — write a complete ACKNACK submessage (body = 24+4*M).
- `dds.rtps.message:parse-acknack-body` *(cursor flags)* — parse an ACKNACK body; returns `(values reader-id writer-id base numbits bitmap count final-p)` or `NIL`.
- `dds.rtps.message:write-gap` *(cursor reader-id writer-id gap-start base numbits bitmap)* — write a complete GAP submessage (base form; body = 28+4*M).
- `dds.rtps.message:parse-gap-body` *(cursor flags)* — parse a GAP body (base form); returns `(values reader-id writer-id gap-start base numbits bitmap)` or `NIL`.
- HEARTBEAT flags: `+heartbeat-flag-final+` (F), `+heartbeat-flag-liveliness+` (L), `+heartbeat-flag-group-info+` (G; not v1).
- ACKNACK flag: `+acknack-flag-final+` (F).
- GAP flags: `+gap-flag-group-info+` (G), `+gap-flag-filtered+` (F; not parsed in v1).

### DATA submessage (`dds.rtps.message`)

`extraFlags + octetsToInlineQos + readerId + writerId + writerSN + [inlineQos if Q] +
serializedPayload [if D||K]` (§9.4.5.4). `write-data` emits the base form (Q=0);
`parse-data-body` parses both forms — when the Q flag is set the inlineQos `ParameterList`
is walked (bounds-checked) and `PID_KEY_HASH` / `PID_STATUS_INFO` are surfaced.
`serializedPayload` is passed/returned as a byte region, left in place for the caller.

- `dds.rtps.message:write-data` *(cursor reader-id writer-id writer-sn payload payload-off payload-len &key key)* — write a complete DATA submessage with a `serializedPayload`, no inlineQos. `KEY t` emits a key payload (K=1,D=0); else data (D=1,K=0).
- `dds.rtps.message:parse-data-body` *(cursor flags octets-to-next)* — parse a DATA body; returns `(values reader-id writer-id writer-sn has-payload payload-offset payload-len key-p change-kind key-hash status-flags)`, or `NIL` if the buffer is short / the inlineQos is malformed. With Q set the inlineQos is walked (bounds-checked); the 16-octet `key-hash` is materialized only for a no-payload lifecycle change (zero per-sample allocation on the hot keyed-DATA path).
- DATA flags: `+data-flag-inline-qos+` (Q), `+data-flag-data+` (D), `+data-flag-key+` (K), `+data-flag-non-standard+` (N).

### Instance lifecycle: dispose / unregister (`dds.rtps.message`)

A DDS instance dispose/unregister rides a **DATA submessage with flags E+Q only** — D clear,
K clear, **no serializedPayload**; the instance is named by `PID_KEY_HASH` (`0x0070`, an
`octet[16]` KeyHash_t, §9.6.4.8) and the lifecycle transition by `PID_STATUS_INFO`
(`0x0071`, `StatusInfo_t` = `octet[4]`, §9.6.4.9). `StatusInfo_t` flags live in the **last
octet** (`...F|U|D`): Disposed `0x01`, Unregistered `0x02`, Filtered `0x04`. The wire form is
pinned from the conformant eProsima Fast DDS oracle and verified byte-exact.

- `dds.rtps.message:status-info->kind` *(status-flags)* — derive the CacheChange kind: `U=1 → :unregister` (dominates), else `D=1 → :dispose`, else `:data` (§9.6.4.9).
- `dds.rtps.message:write-status-info-inline-qos` *(cursor key-hash status-flags)* — write the dispose/unregister inlineQos `ParameterList`: `PID_KEY_HASH` (16) + `PID_STATUS_INFO` (4) + `PID_SENTINEL` (reuses `write-parameter`/`-sentinel`).
- `dds.rtps.message:parse-inline-qos-key-status` *(cursor body-end &optional capture-key-hash)* — walk a Q-flag inlineQos `ParameterList` bounded by `BODY-END`, returning `(values key-hash status-flags walk-ok)`; bounds-checked (every read against `BODY-END` first, NFR-SEC-POSTURE), unknown PIDs skipped, a `KEY_HASH`/`STATUS_INFO` of the wrong length ignored. `CAPTURE-KEY-HASH` `NIL` suppresses the key-hash allocation.
- `dds.rtps.message:write-data-dispose` *(cursor reader-id writer-id writer-sn key-hash status-flags)* — write the full dispose/unregister DATA submessage (flags E+Q, body 52 = 20 fixed prefix + 32 inlineQos).
- StatusInfo flags: `+statusinfo-disposed+`, `+statusinfo-unregistered+`, `+statusinfo-filtered+`; PID `+pid-status-info+`.

### ParameterList / PID codec (`dds.rtps.message`)

A list of `(parameterId, length, value)` Parameters, each 4-byte aligned, terminated by
`PID_SENTINEL` (§9.4.2.11; FR-RTPS-9). The PID constants come from the §9.6.2.2 table. This
codec is the substrate the [Discovery](discovery.md) SPDP/SEDP `ParameterList`s are built on.

- `dds.rtps.message:write-parameter` *(cursor pid value off len)* — write one Parameter: pid + length (padded to a multiple of 4) + value + padding.
- `dds.rtps.message:write-parameter-sentinel` *(cursor)* — write `PID_SENTINEL`, terminating a ParameterList.
- `dds.rtps.message:parse-parameter-list` *(cursor handler)* — iterate Parameters until `PID_SENTINEL`, calling `(handler pid cursor len)` with the cursor at the value; returns `T` on clean termination, `NIL` on a truncated list. Bounds-checked.
- PID constants: `+pid-pad+`, `+pid-sentinel+`, `+pid-participant-lease-duration+`, `+pid-topic-name+`, `+pid-type-name+`, `+pid-protocol-version+`, `+pid-vendorid+`, `+pid-reliability+`, `+pid-durability+`, `+pid-default-unicast-locator+`, `+pid-metatraffic-unicast-locator+`, `+pid-participant-guid+`, `+pid-builtin-endpoint-set+`, `+pid-endpoint-guid+`, `+pid-key-hash+`, `+pid-status-info+`, `+pid-type-information+`.

### Port mapping (`dds.rtps.message`)

The RTPS well-known port formula (§9.6.1.1): `PB=7400 DG=250 PG=2 d0=0 d1=10 d2=1 d3=11`.

- `dds.rtps.message:spdp-multicast-port` *(domain)* — discovery (SPDP) multicast port: `PB + DG*domain + d0`.
- `dds.rtps.message:spdp-unicast-port` *(domain participant-id)* — discovery (SPDP) unicast port: `PB + DG*domain + d1 + PG*participantId`.
- `dds.rtps.message:user-multicast-port` *(domain)* — user-traffic multicast port: `PB + DG*domain + d2`.
- `dds.rtps.message:user-unicast-port` *(domain participant-id)* — user-traffic unicast port: `PB + DG*domain + d3 + PG*participantId`.

### Message dispatch (`dds.rtps.message`)

- `dds.rtps.message:dispatch-message` *(cursor handler &optional msg-end)* — parse an RTPS message: parse the Header, then for each submessage call `(handler id flags cursor body-len)` with the cursor at the body and its endianness set per the E flag. `MSG-END` bounds the message (e.g. a UDP datagram size); defaults to the buffer capacity. Returns `T` on a well-formed message, `NIL` on bad magic / truncation. Bounds-checked throughout.

### HistoryCache (`dds.rtps.history`)

The change store honouring HISTORY (KEEP_LAST depth / KEEP_ALL) and RESOURCE_LIMITS
(max_samples) (FR-RTPS-5). A hot-path package: the `cache-change` struct and the cache
ops are `defstruct` + monomorphic functions, no CLOS. KEEP_LAST is **per-instance** (DDS 1.4
§2.2.3.18): a secondary keyhash→SN index (`instances`) keeps the last `depth` changes of *each*
instance key, evicting an instance's *own* oldest SN at depth, not the global oldest. The index is
the KEEP_LAST eviction mechanism and is maintained for KEEP_LAST only — a **KEEP_ALL** cache keeps
no index (an O(1) change-table insert, bounded only by RESOURCE_LIMITS). A NIL / HANDLE_NIL keyhash
(an unkeyed type) collapses to one shared bucket = a global KEEP_LAST.

- `dds.rtps.history:make-cache-change` *(&key kind writer-guid sn instance-key-hash serialized-payload status-info source-timestamp inline-qos)* — construct a `CacheChange`: the pooled per-sample record (change `KIND` `:data`/`:dispose`/`:unregister`, writer GUID, sequence number, instance key hash, serialized payload, `STATUS-INFO` flags (StatusInfo_t for a dispose/unregister, §9.6.4.9), source timestamp, inline QoS).
- `dds.rtps.history:cache-change` / `cache-change-p` — the struct type and its predicate.
- Accessors: `cache-change-kind`, `cache-change-writer-guid`, `cache-change-sn`, `cache-change-instance-key-hash`, `cache-change-serialized-payload`, `cache-change-status-info`, `cache-change-source-timestamp`, `cache-change-inline-qos`.
- `dds.rtps.history:make-history-cache` *(kind depth resource-limits type-support)* — create a `HistoryCache` with HISTORY (`KIND` `:keep-last`/`:keep-all`, `DEPTH`) and RESOURCE_LIMITS (an integer, a plist with `:max-samples`, or `NIL` = unlimited).
- `dds.rtps.history:history-cache` — the struct type.
- `dds.rtps.history:hc-add-change` *(hc change)* — add a change, enforcing HISTORY + RESOURCE_LIMITS; returns `:OK`, `:DUPLICATE` (SN already present), or `:REJECTED-RESOURCE-LIMITS` (KEEP_ALL at max_samples). KEEP_LAST keeps the last `depth` values **per instance** (DDS 1.4 §2.2.3.18): when the change's instance is at depth, that instance's *own* oldest SN is evicted (not the global oldest); a NIL / HANDLE_NIL keyhash collapses to one bucket = global KEEP_LAST.
- `dds.rtps.history:hc-get-change` *(hc seqnum)* — the `CacheChange` with `SEQNUM`, or `NIL`.
- `dds.rtps.history:hc-remove-change` *(hc seqnum)* — remove the change with `SEQNUM`; returns `T` if one was present (and decrements the count).
- `dds.rtps.history:hc-change-count` *(hc)* — the number of changes currently stored.
- `dds.rtps.history:hc-min-seq` *(hc)* / `hc-max-seq` *(hc)* — lowest / highest sequence number present, or `NIL` if empty.
- `dds.rtps.history:hc-changes-for-reader` *(hc reader-proxy)* — the cache changes in ascending SN order (v1 ignores `READER-PROXY`; per-reader filtering lives in the reliable writer).
- `dds.rtps.history:history-not-implemented` — the condition signalled for not-yet-implemented HistoryCache behaviour.

### Reliable writer (`dds.rtps.reliable`)

The stateful reliable writer (§8.4.2): a `HistoryCache`, the last SN written, the HEARTBEAT
count, and a **per-reader-key** → `ReaderProxy` table. The proxy key is **opaque** (an `equalp`
hash key): the data plane passes the matched reader's full 16-octet GUID, so two readers sharing
EntityId `0x107` on different participants advance independent watermarks (a SequenceNumber is
unique only within one writer/reader GUID, §8.3.5.4); the value-level tests pass integers. Operates
on submessage field **values** (not bytes) so the state machine is directly testable; the
byte/transport wiring lives a layer up in [Discovery](discovery.md)'s data plane.

- `dds.rtps.reliable:make-rtps-writer` *(&key hc last-sn hb-count proxies space-cv max-blocking-ns)* — construct a reliable writer (pass `:hc` a `HistoryCache`). `:max-blocking-ns` (RELIABILITY `max_blocking_time` in ns; `nil` = never block) enables **block-up-to-`max_blocking_time` backpressure** on a full bounded cache (see `writer-write`); `:space-cv` is its paired space-available condvar (defaulted).
- `dds.rtps.reliable:rtps-writer` — the struct type.
- `dds.rtps.reliable:writer-write` *(writer payload)* — add a new `:data` change to the writer's HistoryCache; returns its sequence number, **or the `:timeout` sentinel (`RETCODE_TIMEOUT`)** under DDS-standard **block-up-to-`max_blocking_time` backpressure** (WP-ASYNC-FLOW, FR-PF-2/FR-QOS, ADR 0016 §Backpressure). When the cache is **KEEP_ALL** with a finite RESOURCE_LIMITS `max_samples` **and full**, the write **blocks** on a space-available condvar for up to the writer's `max_blocking_time`, then returns `:timeout` with the cache intact and **no SN consumed** (the SN stream stays hole-free); `max_blocking_time = 0` ⇒ immediate `:timeout`. Space is signalled whenever the cache shrinks — a KEEP_ALL cache shrinks only on the **ACKNACK purge** (`writer-purge-acked`, the slowest reader having ACKed, §8.4.1), plus controller **teardown** (so a blocked publish reaches its `:timeout` once the paced drain stops). For a writer with **no finite `max_samples`** (the default — unlimited KEEP_ALL or KEEP_LAST) this **never blocks and never returns `:timeout`** — byte-identical to before.
- `dds.rtps.reliable:writer-lifecycle-change` *(writer key-hash status-flags)* — add a no-payload **dispose/unregister** change for the instance named by `KEY-HASH` (16 octets); the `KIND` is derived from `STATUS-FLAGS` (`status-info->kind`). It occupies a real SN, so it is reliably ordered and ACKNACK-repairable like any DATA (§8.4.2.2 / §9.6.4.9). Returns the SN, **or `:timeout`** under the same block-up-to-`max_blocking_time` backpressure as `writer-write` (a lifecycle change occupies a SN, so the cache bound applies to **all** changes consistently, ADR 0016 §Backpressure).
- `dds.rtps.reliable:writer-purge-acked` *(writer reader-keys)* — drop every change all matched readers have acknowledged (§8.4.1); returns the count purged. When the cache **shrinks**, broadcasts the writer's space-available condvar so a `writer-write`/`writer-lifecycle-change` blocked on a full KEEP_ALL cache wakes (the ACKNACK-purge half of the WP-ASYNC-FLOW backpressure signal, ADR 0016 §Backpressure).
- `dds.rtps.reliable:writer-heartbeat` *(writer)* — return `(values firstSN lastSN count)` for a HEARTBEAT (§8.3.7.5).
- `dds.rtps.reliable:writer-unsent-list` *(writer reader-id)* — the **unsent** changes for `READER-ID` (`next_unsent_change`, §8.4.2.2): the changes with SN ≥ the reader's *unsent* watermark, **as `CacheChange` objects** in SN order; advances that watermark past the highest SN returned so each change is **pushed exactly once** under `pushMode`. Returning the `CacheChange` (not a `(sn . payload)` cell) lets the data plane dispatch on `cache-change-kind` (a `:data` change → DATA/DATA_FRAG; a `:dispose`/`:unregister` change → a no-payload dispose DATA). The data plane (`%push-data`) pushes this, so N pre-ACKNACK writes emit N DATA submessages, not N(N+1)/2. Lost/late changes are repaired only via the ACKNACK path (`writer-on-acknack`).
- `dds.rtps.reliable:writer-data-list` *(writer reader-id)* — changes not yet acked by `READER-ID` (SN ≥ the *acknowledged* watermark), as a list of `CacheChange` objects in SN order. Not used by the push path (that uses `writer-unsent-list`); retained for diagnostics/tests.
- `dds.rtps.reliable:writer-on-acknack` *(writer reader-id base numbits bitmap)* — process an ACKNACK (§8.3.7.1): confirm SN < `BASE`, then for each NACKed SN return a resend if present, else a GAP. Returns `(values data-resends gap-sns)`, `data-resends` a list of `CacheChange` objects (so a resend dispatches `:data` vs `:dispose`/`:unregister` exactly as the initial push). The `requested_changes` repair path; independent of the unsent watermark.
- `dds.rtps.reliable:get-reader-proxy` *(writer reader-id)* — the `ReaderProxy` for the opaque per-reader key `READER-ID` (the data plane passes the remote reader's full GUID), created on first use. Keyed only as an `equalp` hash key so each remote reader's watermarks stay independent (§8.3.5.4).
- `dds.rtps.reliable:reader-proxy` — the struct type (the writer-side proxy for one matched reader).
- `dds.rtps.reliable:reader-proxy-acked-base` — the reader's **acknowledged** watermark (it has acknowledged all SN < acked-base; advanced by ACKNACK). Distinct from the **unsent** watermark `reader-proxy-unsent-base` (= 1 + highestSentChangeSN; the send-once push watermark, §8.4.2.2).

### Reliable reader (`dds.rtps.reliable`)

The stateful reliable reader (§8.4.10): a **per-writer-key** → `WriterProxy` table. The proxy key
is **opaque** (an `equalp` hash key): the data plane passes the matched writer's full 16-octet GUID,
so two writers sharing EntityId `0x102` on different participants keep independent received-SN sets /
HEARTBEAT ranges / ACKNACK / GAP / reassembly state (§8.3.5.4); the value-level tests pass integers.
Handles dedup (duplicate SN overwrites), reorder (stored by SN), and GAP.

- `dds.rtps.reliable:make-rtps-reader` *(&key proxies)* — construct a reliable reader.
- `dds.rtps.reliable:rtps-reader` — the struct type.
- `dds.rtps.reliable:reader-on-data` *(reader writer-id sn payload)* — accept a DATA; idempotent (duplicate SN overwrites — dedup); tracks the highest SN seen so reordered delivery is harmless.
- `dds.rtps.reliable:reader-on-heartbeat` *(reader writer-id first-sn last-sn)* — update the available range `[firstSN, lastSN]` (§8.3.7.5).
- `dds.rtps.reliable:reader-acknack` *(reader writer-id)* — compute an ACKNACK (§8.3.7.1): `(values base numBits bitmap)`. `BASE` is the lowest unreceived SN in `[first, last]` (or `last+1` if none); the bitmap NACKs the unreceived SNs in `[base, last]` (capped at 256).
- `dds.rtps.reliable:reader-on-gap` *(reader writer-id gap-start base numbits bitmap)* — mark GAPped SNs as irrelevant so they do not block the ack (§8.3.7.4): the range `[gapStart, base-1]` (lower-clamped to the proxy `first-sn`, upper-bounded by a hard cap of `*max-gap-range*` SNs) plus the SNs listed in the bitmap. `gapStart`/`base` are wire-controlled 64-bit values and `last-sn` is itself set from inbound HEARTBEATs, so the cap — independent of any wire value — is the resource-exhaustion guard against a `2^60`-span CPU+memory DoS (NFR-SEC-POSTURE); a larger evicted run is recovered loss-free over later GAP/HEARTBEAT rounds.
- `dds.rtps.reliable:reader-complete-p` *(reader writer-id)* — T iff every SN in the available range `[first, last]` has been received or GAPped.
- `dds.rtps.reliable:get-writer-proxy` *(reader writer-id)* — the `WriterProxy` for the opaque per-writer key `WRITER-ID` (the data plane passes the remote writer's full GUID), created on first use. Keyed only as an `equalp` hash key so two writers sharing EntityId `0x102` across participants get independent reliable state (§8.3.5.4).
- `dds.rtps.reliable:writer-proxy` — the struct type (the reader-side proxy for one matched writer).
- `dds.rtps.reliable:writer-proxy-received` — the SN → `payload | :gap` table of what the reader has seen.

---

## Examples

All examples below are adapted from the verified test suite in `src/dds-tests/rtps-test.lisp`
and `src/dds-tests/integration-test.lisp`. Buffers come from the [arena](cdr-and-memory.md);
the `cursor` carries the endianness.

### 1. Frame and dispatch a message (DATA + HEARTBEAT)

Build a Header, a DATA submessage, and a HEARTBEAT into one buffer, then walk them back out
with `dispatch-message`. Adapted from `run-rtps-dispatch-test`.

```lisp
(let* ((buf     (dds.core.buffer:make-octet-buffer 256))
       (c       (dds.core.buffer:cursor buf :endianness :little))
       (prefix  (make-array 12 :element-type '(unsigned-byte 8) :initial-element 0))
       (rid     dds.rtps.message:+entityid-participant+)
       (wid     dds.rtps.message:+entityid-unknown+)
       (payload (make-array 8 :element-type '(unsigned-byte 8)
                              :initial-contents '(0 #x11 0 0 #x2a 0 0 0))))
  ;; write: Header, then DATA (writerSN 7), then HEARTBEAT [1,7] count 1, FinalFlag set
  (dds.rtps.message:write-header c prefix :vendor 0)
  (dds.rtps.message:write-data c rid wid 7 payload 0 8)
  (dds.rtps.message:write-heartbeat c rid wid 1 7 1 :final t)
  ;; rewind and dispatch: the handler sees DATA then HEARTBEAT in order
  (dds.core.buffer:cursor-reset c)
  (let ((seen '()))
    (dds.rtps.message:dispatch-message
     c (lambda (id flags cur body-len)
         (cond
           ((= id dds.rtps.message:+submsg-data+)
            (multiple-value-bind (r w sn) (dds.rtps.message:parse-data-body cur flags body-len)
              (declare (ignore r w))
              (push (list :data sn) seen)))
           ((= id dds.rtps.message:+submsg-heartbeat+)
            (multiple-value-bind (r w first) (dds.rtps.message:parse-heartbeat-body cur flags)
              (declare (ignore r w))
              (push (list :heartbeat first) seen))))))
    (nreverse seen)))                 ; => ((:DATA 7) (:HEARTBEAT 1))
```

### 2. SequenceNumberSet round-trip + membership

The §9.4.2.6 spec example `1234/12:00110` (offsets 2 and 3 set). Adapted from
`run-rtps-seqnum-test`.

```lisp
(let* ((buf (dds.core.buffer:make-octet-buffer 64))
       (c   (dds.core.buffer:cursor buf :endianness :little))
       (bm  (make-array 1 :element-type '(unsigned-byte 32) :initial-element 0)))
  (dds.rtps.message:seqnum-set-bit bm 2)
  (dds.rtps.message:seqnum-set-bit bm 3)
  ;; bitmap word is MSB-first: offsets 2,3 -> #x30000000
  (dds.rtps.message:write-sequence-number-set c 1234 12 bm)
  ;; membership: base+2 and base+3 are in the set; base itself and base+4 are not
  (list (dds.rtps.message:seqnum-set-member-p 1234 12 bm 1236)    ; => T
        (dds.rtps.message:seqnum-set-member-p 1234 12 bm 1234)    ; => NIL
        ;; parse it back
        (multiple-value-list
         (progn (dds.core.buffer:cursor-reset c)
                (dds.rtps.message:read-sequence-number-set c)))))  ; => (1234 12 #(#x30000000))
```

### 3. HistoryCache: per-instance KEEP_LAST eviction and KEEP_ALL RESOURCE_LIMITS

Adapted from `run-history-test` / `run-hc-perinstance-keeplast-test`. KEEP_LAST keeps the last
`depth` values **per instance key** (DDS 1.4 §2.2.3.18) — at depth it evicts that instance's *own*
oldest SN, not the global oldest; an unkeyed change (no/HANDLE_NIL keyhash) collapses to one shared
bucket = a global KEEP_LAST. KEEP_ALL keeps everything (no per-instance index), rejecting beyond
`max_samples` and detecting duplicates.

```lisp
;; PER-INSTANCE KEEP_LAST depth 2, keyed: keep the last 2 changes of EACH key.
;; Write A@1, A@2, A@3 for key A and B@4 for key B; A's oldest (SN1) is evicted
;; (A now {2,3}), B keeps {4} — a GLOBAL last-2 would have wrongly dropped SN1+SN2.
(let ((hc (dds.rtps.history:make-history-cache :keep-last 2 nil nil))
      (ka (make-array 16 :element-type '(unsigned-byte 8) :initial-element #xaa))
      (kb (make-array 16 :element-type '(unsigned-byte 8) :initial-element #xbb)))
  (dolist (s '((1 . a) (2 . a) (3 . a) (4 . b)))
    (dds.rtps.history:hc-add-change
     hc (dds.rtps.history:make-cache-change
         :sn (car s) :instance-key-hash (if (eq (cdr s) 'a) ka kb))))
  (list (dds.rtps.history:hc-get-change hc 1)            ; => NIL (A's oldest, evicted)
        (and (dds.rtps.history:hc-get-change hc 2)
             (dds.rtps.history:hc-get-change hc 3)       ; A keeps its last 2 (SN 2,3)
             (dds.rtps.history:hc-get-change hc 4) t)))  ; B keeps SN 4 (NOT starved by A)

;; UNKEYED KEEP_LAST depth 3 (one bucket = global): adding SN 1..4 evicts SN 1
(let ((hc (dds.rtps.history:make-history-cache :keep-last 3 nil nil)))
  (dolist (sn '(1 2 3 4))
    (dds.rtps.history:hc-add-change hc (dds.rtps.history:make-cache-change :sn sn)))
  (list (dds.rtps.history:hc-change-count hc)            ; => 3
        (dds.rtps.history:hc-get-change hc 1)            ; => NIL (evicted)
        (mapcar #'dds.rtps.history:cache-change-sn
                (dds.rtps.history:hc-changes-for-reader hc nil)))) ; => (2 3 4)

;; KEEP_ALL with max_samples = 2: the 3rd add is rejected, a duplicate is detected
(let ((hc (dds.rtps.history:make-history-cache :keep-all 1 2 nil)))
  (list (dds.rtps.history:hc-add-change hc (dds.rtps.history:make-cache-change :sn 1)) ; :OK
        (dds.rtps.history:hc-add-change hc (dds.rtps.history:make-cache-change :sn 2)) ; :OK
        (dds.rtps.history:hc-add-change hc (dds.rtps.history:make-cache-change :sn 3)) ; :REJECTED-RESOURCE-LIMITS
        (dds.rtps.history:hc-add-change hc (dds.rtps.history:make-cache-change :sn 1)))) ; :DUPLICATE
```

### 4. Reliable delivery through a lossy/reorder/duplicate channel

The value-level writer/reader state machines driven by HEARTBEAT → ACKNACK → resend until
the reader is complete. Adapted from `run-reliability-test` (here without the loss injection,
to show the clean handshake).

```lisp
(let* ((writer (dds.rtps.reliable:make-rtps-writer
                :hc (dds.rtps.history:make-history-cache :keep-all 1 nil nil)))
       (reader (dds.rtps.reliable:make-rtps-reader))
       (wid 1) (rid 2) (n 10))
  ;; writer queues 10 samples
  (dotimes (i n) (dds.rtps.reliable:writer-write writer (format nil "m~d" (1+ i))))
  ;; one HEARTBEAT/ACKNACK/resend round, repeated until complete
  (dotimes (round 8)
    (multiple-value-bind (first last count) (dds.rtps.reliable:writer-heartbeat writer)
      (declare (ignore count))
      (dds.rtps.reliable:reader-on-heartbeat reader wid first last))
    (when (dds.rtps.reliable:reader-complete-p reader wid) (return))
    (multiple-value-bind (base numbits bitmap) (dds.rtps.reliable:reader-acknack reader wid)
      (multiple-value-bind (resends gaps)
          (dds.rtps.reliable:writer-on-acknack writer rid base numbits bitmap)
        (declare (ignore gaps))
        ;; "deliver" each NACKed CacheChange to the reader
        (dolist (ch resends)
          (dds.rtps.reliable:reader-on-data
           reader wid (dds.rtps.history:cache-change-sn ch)
           (dds.rtps.history:cache-change-serialized-payload ch))))))
  (dds.rtps.reliable:reader-complete-p reader wid))      ; => T
```

### 5. GAP: NACKing evicted samples

When a KEEP_LAST writer has already evicted low SNs, an ACKNACK for them yields a GAP (not a
resend) for the evicted range and a resend for what is still cached. Adapted from
`run-gap-handling-test`. On the wire the disc data plane (`%on-user-acknack`) sends that GAP to the
NACKing reader (`seqnum-set-from-sns` → `write-gap`, §8.3.7.4) alongside the DATA resends — so a
reliable reader advances past an evicted SN instead of NACKing it forever; the default unlimited
KEEP_ALL writer never evicts, so `gap-sns` is empty and no GAP is sent.

```lisp
(let* ((writer (dds.rtps.reliable:make-rtps-writer
                :hc (dds.rtps.history:make-history-cache :keep-last 2 nil nil)))
       (reader (dds.rtps.reliable:make-rtps-reader))
       (wid 1) (rid 2))
  (dotimes (i 5) (dds.rtps.reliable:writer-write writer (format nil "m~d" (1+ i)))) ; hc holds SN 4,5
  (dds.rtps.reliable:reader-on-heartbeat reader wid 1 5)        ; reader thinks [1,5] available
  (multiple-value-bind (base numbits bitmap) (dds.rtps.reliable:reader-acknack reader wid)
    (multiple-value-bind (resends gaps)
        (dds.rtps.reliable:writer-on-acknack writer rid base numbits bitmap)
      (list (mapcar #'dds.rtps.history:cache-change-sn resends) ; => (4 5)   present SNs resent
            gaps))))                  ; => (1 2 3)  evicted SNs gapped
```

---

## Notes / status

- **Connext interop is pending a Connext install.** Correctness here is established by
  byte-exact tests against the RTPS 2.5 spec clauses (e.g. the §9.4.5.4 DATA byte image and
  the §9.4.2.6 SequenceNumberSet bytes in `rtps-test.lisp`) and by an offline UDP-loopback
  end-to-end path (`run-end-to-end-test`), not yet by a live RTI Connext capture. The wire
  oracle (tshark RTPS dissector + Connext) is wired separately — see [Interop](interop.md).
- **VendorId is a provisional development value.** `dds.rtps.message:*vendor-id*` defaults to
  `+vendor-id-dev-provisional+` = `0x01FF` (FR-RTPS-2), pending an OMG-assigned id. This was changed
  from `VENDORID_UNKNOWN` (`0x0000`) after a live Connext 7.3.1 capture (2026-06-09) showed Connext
  ignores a participant advertising the zero/unknown VendorId — establishing no unicast discovery
  channel at all; with `0x01FF` Connext accepts the participant and runs the reliable channel. Some
  unit tests still write `:vendor 0` to the header codec directly (codec round-trip, not discovery).
- **DATA handles InlineQos (Q).** When the Q flag is set, `parse-data-body` SKIPS the inlineQos
  ParameterList (every read bounds-checked against the submessage extent first) and reports the
  `serializedPayload` that follows it. Required for keyed types: RTI Connext sends keyed user
  DATA with inlineQos carrying `PID_KEY_HASH`. The payload is handed back as a `[offset, len)`
  region in the receive buffer, left in place for the caller to deserialize. (Emitting inlineQos
  is still a v1 gap.)
- **DATA_FRAG codec (RTPS 2.5 §9.4.5.5).** `write-data-frag` / `parse-data-frag-body` implement the
  fragmented-DATA submessage (flags E=0x01/Q=0x02/K=0x04 pinned from §9.4.5.5; wire order
  `fragmentStartingNum/fragmentsInSubmessage/fragmentSize/sampleSize`); the parser is
  bounds-checked, fuzzed, and rejects the spec-invalid cases (fragmentStartingNum 0, frags 0,
  fragmentSize > sampleSize). The reliable engine carries the rest: `reader-on-data-frag`
  reassembly (guarded by `*max-reassembly-bytes*` / `*max-reassembly-fragments*`),
  `reader-frag-acknack` (NACK_FRAG generation), `writer-frag-plan` / `writer-frag-plan-for`
  (fragment packing + NACK_FRAG-named resends), `writer-frag-heartbeat`, `writer-on-nack-frag`;
  the UDP data plane wires them up (see [Discovery](discovery.md), including the debug-only
  `dds.disc:*debug-drop-fragment-numbers*` fragment-loss injection used for the live NACK_FRAG
  proof). Validated bidirectionally against live RTI Connext 7.3.1 (2026-06-10), including
  forced-fragment-loss recovery driven by Connext's NACK_FRAG. Real Connext-emitted DATA_FRAG
  and NACK_FRAG submessages are locked as byte-exact regression vectors (decode + re-encode);
  the NACK_FRAG capture exposed and fixed a wrong `write-nack-frag` octetsToNextHeader
  (24+4\*M → the spec-correct 28+4\*M, §9.4.5.14 + §9.4.2.8). HEARTBEAT_FRAG has no Connext
  vector: Connext 7.3.1 heartbeats fragmented samples with plain HEARTBEAT (our stack emits
  HEARTBEAT_FRAG and Connext accepts it).
- **HEARTBEAT/ACKNACK/GAP are base forms.** The GroupInfo (G) and Filtered/FilteredCount (F)
  extensions are neither emitted nor parsed in v1.
- **The reliable state machines are value-level, not byte-level.** `dds.rtps.reliable`
  operates on submessage field values so the logic is directly testable; the
  byte/transport/thread wiring lives in the [Discovery](discovery.md) data plane
  (`dataplane.lisp`). The docstrings note the per-reader-proxy / resend-list consing there as
  a documented v1 concern; it is not on a measured hot path.
- **HistoryCache v1 keys changes by SN in a hash-table**, with a secondary keyhash→SN index for
  **per-instance KEEP_LAST** (DDS 1.4 §2.2.3.18 — *done*, WP-KEEPLAST 2026-06-16; the index is
  maintained for KEEP_LAST only, so KEEP_ALL stays an O(1) change-table insert). A pooled,
  zero-alloc change store + non-consing iteration and LIFESPAN expiry remain tracked follow-ups
  (see the docstring in `history.lisp`). `hc-changes-for-reader` ignores its `reader-proxy`
  argument for now.

## See also

- [Discovery](discovery.md) — SPDP/SEDP and the reliable UDP data plane that drive this engine.
- [CDR codec, buffers & the arena](cdr-and-memory.md) — the `octet-buffer`/`cursor` and the static arena.
- [DCPS — the DDS entity API](dcps.md) — the DDS-level API layered over the engine.
- [Transports](transports.md) — the UDPv4 transport the data plane sends through.
- [Interop with RTI Connext](interop.md) — the wire oracle and Shapes interop harness.
