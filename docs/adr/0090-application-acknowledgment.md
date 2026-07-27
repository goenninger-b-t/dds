# ADR 0090 — Application Acknowledgment (APP-ACK)

- **Status:** **Accepted — Option A (Connext interop first), owner decision 2026-07-27.** ⚠️ Two things must be read with that: the owner's answer to the second question ("defer, decide after slice 1") was *conditioned on Option B* and so does not straightforwardly apply — see §5.1. And **the live capture taken immediately afterwards DISPROVED the main cost argument this ADR used to recommend against Option A** — see §3.1. The recommendation was wrong; the decision was better than the advice.
- **Date:** 2026-07-27
- **Requirements:** FR-QOS-4 (vendor-extension QoS namespace, separated from the standard policies), FR-DCPS-2/3 (listeners + status semantics), FR-RTPS-1 (submessage set), FR-IO-1 (Connext interop), NFR-IP (clean-room)
- **Relates to:** ADR 0089 (the vendor-status precedent this would follow), ADR 0086 (the "wire is the oracle" live-vector method), ADR 0020 (DATA_REPRESENTATION — a prior RxO-gated QoS), ADR 0064 (a status, never a printed line)
- **Contract touched:** none yet. Option B would add a vendor QoS to `DDS.QOS`, a submessage to `DDS.RTPS.MESSAGE`, reader→writer state to `DDS.RTPS.RELIABLE`, and a DCPS API + listener. All enumerated in §6.

---

## 1. The standard defines nothing. This was verified, not recalled.

The backlog note said "RTPS 2.5 defines no application acknowledgment." That is a pointer, not evidence,
so it was checked against the specs in `docs/specs/`:

| source | search | result |
|---|---|---|
| `rtps-2_5.pdf` (11 088 lines extracted) | `application.{0,20}acknowledg` / `acknowledg.{0,20}application` | **zero matches** |
| `rtps-2_5-xmi.xml` | same, plus submessage-kind names | **zero**; only `AckNack` exists |
| `dds_rtf2_dcps.idl` | `acknowledg` | **two matches**, both `wait_for_acknowledgments` (§2.2.2.4.2.24 / §2.2.2.5.2.x) |

`wait_for_acknowledgments` is **protocol**-level: it blocks until the RTPS layer has acknowledged, and says
nothing about the subscribing *application* having consumed anything. **There is no OMG clause to implement
from.** Application acknowledgment is an RTI vendor extension in its entirety.

That matters for how this ADR is written: for MUTABLE (ADR 0086) the spec was the oracle and the live
vector was the check. Here **there is no oracle** — only observed behaviour. Every claim below is sourced.

## 2. What RTI's product does (public API documentation; see `docs/provenance.md`)

- `DDS_ReliabilityQosPolicy.acknowledgment_kind`, of type
  `DDS_ReliabilityQosPolicyAcknowledgmentModeKind`, default `DDS_PROTOCOL_ACKNOWLEDGMENT_MODE`, effective
  only when `kind` is RELIABLE. Four values:
  - `PROTOCOL` — acknowledged by the RTPS protocol (today's behaviour).
  - `APPLICATION_AUTO` — acknowledged once the subscriber accesses the sample via `read`/`take`; if the
    sample was loaned, on `return_loan`.
  - `APPLICATION_ORDERED` — listed in the enumeration, **no published explanation found**. Recorded as an
    unknown rather than guessed at.
  - `APPLICATION_EXPLICIT` — acknowledged only when the application calls `acknowledge_sample` or
    `acknowledge_all` on the DataReader.
- `DDS_AcknowledgmentInfo` carries exactly four fields: `subscription_handle` (the acknowledging reader),
  `sample_identity` (which sample, plus cookie), `response_data` (an application payload the reader
  attached), and `valid_response_data` (false once a retention duration has elapsed).

## 3. ⚠️ The wire — and the two findings that should decide this

The wire format is not in any published document. It **is**, however, described by the **Wireshark RTPS
dissector** — independent, open-source (GPL), read here for *understanding only*, with nothing copied
(NFR-IP; provenance recorded). `tshark -G values` and `-G fields` on the installed Wireshark 4.6.6 yield:

```
rtps.sm.id  0x1c  APP_ACK
rtps.sm.id  0x1d  APP_ACK_CONF

APP_ACK       : virtualWriterCount(i32)
                  per virtual writer: octetsToNextVirtualWriter(i16), intervalCount(i16)
                    per interval:     intervalFlags(i16), intervalPayloadLength(i16), <payload>
                count(i32)
APP_ACK_CONF  : virtualWriterCount(u32), count(i32)
```

So it is a **two-submessage exchange** (the reader acknowledges; the writer confirms), carrying a list of
**sequence-number intervals per writer**, each interval bearing a payload — which is where
`response_data` rides. The `count` mirrors ACKNACK's, for dedup/ordering.

**FINDING 1 — the IDs sit in the OMG-reserved range, not the vendor range.** RTPS 2.5 §9.4.5.1.1 is
explicit: *"Submessages with IDs 0x00 to 0x7f (inclusive) are protocol-specific. They are defined as part
of the RTPS protocol… Submessages with ID's 0x80 to 0xff (inclusive) are vendor-specific; they will not be
defined by future versions of the protocol."* The vendor range exists precisely so extensions do not
collide with future standard assignments. **0x1c and 0x1d are inside the protocol range.** RTI has taken a
whole cluster there — `DATA_SESSION 0x14`, `ACKNACK_BATCH 0x17`, `DATA_BATCH 0x18`, `HEARTBEAT_BATCH 0x19`,
`ACKNACK_SESSION 0x1a`, `HEARTBEAT_SESSION 0x1b`, `APP_ACK 0x1c`, `APP_ACK_CONF 0x1d`,
`HEARTBEAT_VIRTUAL 0x1e` — while also using the vendor range elsewhere (`DATA_FRAG_SESSION 0x81`). Whatever
the history, the consequence for us is concrete: **anything we emit at 0x1c is squatting on space the OMG
may assign**, and can only be interpreted safely when the current VendorId says RTI (§8.3.3.2 rule 3 makes
that gating mandatory anyway).

**FINDING 2 — APP_ACK is built on RTI's *virtual writer* model, which this stack does not have.** The
outer loop is `virtualWriterCount`, and the neighbouring `HEARTBEAT_VIRTUAL 0x1e` is the same abstraction.
Virtual writers are how RTI decouples a logical data source from the physical writer that carries it
(Persistence Service, durable writer history, multi-channel). **"Interoperate with Connext APP-ACK" is
therefore not a small slice** — it drags in an identity model orthogonal to application acknowledgment
itself. That is not visible from the feature name, and it is the single most important thing this ADR has
to say.

**What we are safe on today:** our `dispatch-message` loop repositions unconditionally to
`body-start + body-len` for every submessage, known or not, so inbound 0x1c/0x1d are already ignored and
parsing continues — RTPS 2.5 §8.3.3.2 rule 3, satisfied by construction, not by a special case.

## 3.1 ⚠️ THE CAPTURE, AND THE CORRECTION IT FORCES TO FINDING 2

A live Connext↔Connext exchange was captured before writing any code (`interop/connext/appack/`, peers
written here against the public API; `APPLICATION_AUTO` chosen so the peer needs no vendor-extension call
and nothing about the C++ binding is assumed). 5 samples produced **5 APP_ACK and 5 APP_ACK_CONF**, all
from vendorId `01 01`.

**The hypothesised layout consumed all ten bodies EXACTLY — no leftover octets, no overrun.** That
self-check is the reason it is believed; a layout that merely looks plausible on one sample is how wire
bugs ship.

```
APP_ACK (0x1c) body                         APP_ACK_CONF (0x1d) body
  readerId                   4 octets         readerId                 4
  writerId                   4 octets         writerId                 4
  virtualWriterCount   i32   4                virtualWriterCount i32   4
  per virtual writer:                         per virtual writer:
    virtualWriterGuid       16                  virtualWriterGuid     16
    intervalCount        i16 2                count                i32 4
    octetsToNextVirtualWriter i16 2
    per interval:
      firstSN             SN 8
      lastSN              SN 8
      intervalFlags      i16 2
      intervalPayloadLength i16 2
      payload                n
  count                i32   4
```

Observed, for 5 sequential samples (`readerId 80000007`, `writerId 80000002`):

| APP_ACK | intervals | count |
|---|---|---|
| 1 | `SN 1..1 flags=0x0000` | 1 |
| 2 | `SN 1..1 flags=0x0100` · `SN 2..2 flags=0x0000` | 2 |
| 3 | `SN 1..2 flags=0x0100` · `SN 3..3 flags=0x0000` | 3 |
| 4 | `SN 1..3 flags=0x0100` · `SN 4..4 flags=0x0000` | 4 |
| 5 | `SN 1..4 flags=0x0100` · `SN 5..5 flags=0x0000` | 5 |

So the reader sends a **cumulative** picture each time — a coalesced run of already-reported SNs in one
state, plus the newly acknowledged SN in another — and the writer answers each with an APP_ACK_CONF
carrying the matching `count`. `intervalFlags` is evidently the per-interval state discriminator;
its exact encoding is **not yet pinned** (only two values were provoked) and must not be guessed.

**⚠️ THE CORRECTION. §3 Finding 2 claimed APP_ACK "drags in the virtual-writer identity model", and that
claim was the main reason this ADR recommended against Option A. The capture disproves it for the
ordinary case:** `virtualWriterCount` is **1**, and the virtual writer GUID is
`0101d0538841708d4c6180b8` + `80000002` — **byte-for-byte the writer's own guidPrefix and entityId**. The
indirection exists in the format but is *degenerate* for an ordinary writer: emit count 1 with the
writer's own GUID and it is satisfied. The virtual-writer model presumably becomes real for Persistence
Service / durable writer history / multi-channel writers — none of which are in this slice.

Option A is therefore materially cheaper than §5 estimated, and the recommendation there was built on an
over-estimate that fifteen minutes of capture would have caught. Recorded rather than quietly edited: the
lesson is that the cost argument against a wire feature should not be written *before* looking at the
wire, when looking is this cheap.

## 3.2 ⭐ THE QoS IS ON THE WIRE TOO — PID 0x800b, identified by measurement (slice A3b)

Slice A3b began by trying to make an `:application-explicit` pair match, and it could not. **Slice A3a
shipped the RxO gate without the wire.** `acknowledgment-kind` was never propagated in SEDP, so every
discovered endpoint read as `:protocol`, the equality gate compared each peer against a value nobody
advertised, and an application-acknowledgment pair **could never match at all**. The gate was correct and
the feature was unreachable — a shape worth naming, because a policy neither side can see cannot be
RxO-checked, and nothing in A3a's tests could notice (they called `qos-rxo-compatible` directly).

The fix needed a ParameterId, and rather than invent one, the A0 capture harness was re-run three times
against live Connext 7.3.1 with `acknowledgment_kind` changed in `USER_QOS_PROFILES.xml`, comparing the
SEDP publication and subscription ParameterLists:

| `acknowledgment_kind` | SEDP publication 0x800b | SEDP subscription 0x800b |
|---|---|---|
| `PROTOCOL` (the default) | **absent** | **absent** |
| `APPLICATION_AUTO` | `01 00 00 00` | `01 00 00 00` |
| `APPLICATION_EXPLICIT` | `03 00 00 00` | `03 00 00 00` |

**0x800b was the only field that moved**, it moved on both endpoint kinds, and every other vendor PID was
byte-identical across all three runs. The values line up with the published
`DDS_ReliabilityQosPolicyAcknowledgmentModeKind` order (PROTOCOL 0, APPLICATION_AUTO 1,
APPLICATION_ORDERED 2, APPLICATION_EXPLICIT 3), so the mapping rests on two independent sources rather
than on one observation. Clean-room: octets off the wire, exactly as `PID_TYPE_OBJECT_LB` and
`PID_ENTITY_VIRTUAL_GUID` were identified; no RTI source, header or `rtiddsgen` output was read.

Two consequences worth stating:

- **We omit it at `:protocol`, as RTI does.** An endpoint not using the feature puts nothing extra on the
  wire, and "absent" reads as `:protocol` — which is what RTI means by omitting it *and* the right reading
  of a peer that has never heard of the policy.
- **An unrecognised code becomes `:unsupported`, which matches nothing.** This inverts the rule every other
  wire-kind mapper in `dds.rtps.discovery` follows (fall back to the default, never reject — FR-QOS-2).
  For this policy falling back to `:protocol` would silently match a peer whose writer waits for
  acknowledgments we never send, or whose reader believes a guarantee we are not honouring: §4's two
  failure modes exactly. `APPLICATION_ORDERED` lands there deliberately — its semantics remain unsourced.

**A correlated observation deliberately not acted on:** vendor PID `0x8009` appeared on the *subscription*
record only, reading 1 whenever `acknowledgment_kind` was an APPLICATION kind and 0 under PROTOCOL. Being
reader-only it cannot be the RxO-paired policy, and its meaning is unsourced, so it is neither emitted nor
interpreted (ADR 0089 §5).

## 4. Why this is worth doing at all

APP-ACK is the difference between *"the middleware has it"* and *"the application has processed it."* For
a durable command/telemetry pipeline that is the only ack that means anything: with PROTOCOL acks a writer
may purge a sample the subscriber never got round to handling, and a crash loses it silently. It is also
the mechanism behind reliable request/reply patterns, so it is a prerequisite worth having in place before
item (3), DDS-RPC.

## 5. ▶️ THE DECISION REQUIRED

Given Finding 2, "APP-ACK with Connext interop" is materially bigger than the backlog entry implies. Three
ways forward:

| | option | what it buys | what it costs |
|---|---|---|---|
| **A** | **Connext-interoperable first.** Implement 0x1c/0x1d incl. enough virtual-writer encoding to match, gated on VendorId=RTI. | wire interop with Connext | the largest option, and the *format* is only knowable by capture — every field we cannot provoke in a live run stays a guess. Drags in the virtual-writer model. |
| **B** | **Our own APP-ACK first (recommended).** The full DDS-level feature ours↔ours, over a submessage in the **vendor range 0x80–0xff under our own VendorId**. Connext interop becomes a later, localized slice. | the whole application-visible feature, demonstrable and testable now; spec-clean; conformant peers ignore it by §8.3.3.2 | no Connext interop until slice 2 |
| **C** | **A vendor builtin endpoint** instead of a new submessage — acks as ordinary DATA on a vendor-specific builtin endpoint (RTPS 2.5 §9.3.1.2 permits entityKind `'01'` for vendor-specific entities; §9.6.2.2.1 reserves vendor ParameterIds). | reuses the whole reliable data path; no new submessage at all | inverts direction (the reader must publish, the writer subscribe), two more endpoints per participant, and ack latency now rides the builtin path |

**Recommendation: B.** It is the only option that delivers the application-visible feature without
guessing at an undocumented format, it keeps the vertical slice honest (every layer exercised, ours↔ours,
end to end), and it makes slice 2 a *substitution* — swap the encoder/decoder and the VendorId gate — rather
than an architecture change. C is spec-elegant but pays a structural cost for a benefit slice 1 does not
need. A front-loads the highest-uncertainty work before any of the semantics are proven.

**The question for the owner: A, B, or C — and if B, is Connext interop still required as slice 2, or is
ours↔ours the deliverable?** That second half matters, because it decides whether we spend on capture
tooling and a Connext APP-ACK peer at all.

### 5.1 What was decided, and the one thing left open

**Option A was chosen.** §3.1 then showed A to be cheaper than this ADR had argued, so the decision stands
on firmer ground than the advice it overrode.

**The second question and how it was settled.** It had been phrased *"if the first slice is ours↔ours
(Option B), is Connext interop still required later?"* and answered **"defer — decide after slice 1."**
With A chosen its premise did not hold, so it was carried rather than guessed at while A0 and A1 were
built — both were required under either reading.

**Resolved 2026-07-27, once slice 1 had produced the information the deferral was waiting for.** The
tension largely dissolved on facts rather than needing a choice: the Connext-facing work under A was
A0 + A1 + A2; A0 and A1 landed, and §3.1 showed A2 to be small. What actually remained open was never
about Connext at all — it was whether **A3, the vendor-neutral DCPS semantics and the bulk of the
work, gets built**. Answered: **yes — the full application-visible feature.** APP-ACK's whole value is
the distinction between *"the middleware has it"* and *"the application has processed it"*, which a
wire-only codec cannot express, and it is the prerequisite for the agreed item (3), DDS-RPC. The
expensive, uncertain part — an undocumented wire — turned out to be the cheap part, and it is already
committed.

## 6. The slice plan AS ACCEPTED — Option A, Connext-facing first (VSD, thinnest end-to-end first)

Revised after §3.1. The virtual-writer model is **not** a prerequisite; `virtualWriterCount = 1` with the
writer's own GUID satisfies the ordinary case.

- **Slice A0 — the capture. ✅ DONE** (this ADR §3.1). Peers at `interop/connext/appack/`, layout confirmed
  exact on 10/10 bodies. The remaining wire unknown is `intervalFlags`, which needs more provoked cases
  (explicit mode, response data, a gap in the acknowledged range) before any encoder may emit it.
- **Slice A1 — a byte-exact corpus vector + a decoder. ✅ DONE.** Three captured submessages committed to
  `corpus/rtps/` (a *new* corpus: these are submessages, not SerializedPayloads, and they are
  **decode**-verified rather than byte-compared, because nothing here emits them and comparing an encoder
  that deliberately does not exist would verify nothing). `parse-app-ack-body` /
  `parse-app-ack-conf-body` in `DDS.RTPS.MESSAGE`, visitor-style so the nested variable-length body needs
  no allocation in a hot-path-gated file. The corpus expectations are **hand-transcribed from the capture
  decode, never derived by running our own parser** — otherwise the gate compares the parser with itself,
  which is precisely how ADR 0061 shipped. Wire-supplied loop bounds are capped and read *signed*
  (NFR-SEC-POSTURE). Falsified three ways, each seen red: a corrupted vector octet, an emptied corpus
  directory, and a removed count guard.
- **Slice A2 — emit. ✅ DONE (codec half).** `write-app-ack` / `write-app-ack-conf`, and the corpus gate
  upgraded from decode-verify to a **byte-exact round trip** against RTI's own octets — all three vectors
  reproduce exactly. **The round trip earned its keep immediately, finding two things decode could not:**
  a wrong GUID offset in the gate, and the true meaning of `octetsToNextVirtualWriter`, which is measured
  from the start of `intervalCount` and so includes that field and itself (24 for one 20-octet interval,
  44 for two). The **decoder ignores that field**, so its meaning had never had to be understood — decode
  verification cannot test what it does not read. Still outstanding for A2: the *live* leg (our reader
  acknowledging a Connext writer), which needs the A3 QoS before there is anything to drive it.
- **Slice A3a — the QoS + its RxO gate. ✅ DONE.** `acknowledgment-kind`, RxO-checked **by equality**: a
  writer offering application acks must not match a reader that will never send them (silent stall), and a
  `:protocol` writer must not match an application reader (silent data loss). Neither direction is safe, so
  neither is allowed. **Its gap, found by A3b and recorded in §3.2: the policy was never put on the wire**,
  so the gate compared every peer against `:protocol` and the pair could not match. Closed in A3b.
- **Slice A3b — SEDP propagation + the reader API + emission. ✅ DONE.**
  - `PID_ACKNOWLEDGMENT_KIND` (0x800b) in SEDP, both roles, omitted at `:protocol` — §3.2.
  - `acknowledge-sample` / `acknowledge-all` on the DataReader, returning DDS ReturnCode_t. Both act only
    on samples the application has **ACCESSED** (read or taken): acknowledging the reader's whole cache
    would acknowledge exactly the samples this feature exists to keep a writer from purging. An SN that was
    never accessed is **refused** (`PRECONDITION_NOT_MET`), never acknowledged on faith.
  - `SampleInfo.publication_handle` is now populated — `acknowledge-sample` identifies a sample by (writer
    GUID, sequence number), because a sequence number is unique only within one writer (RTPS 2.5 §8.3.5.4).
    It is **aliased, not copied**, which costs 0 B/sample and places a constraint on ADR 0088: a memoised
    invariant GUID (its Option B) keeps this safe, a shared mutable scratch (its Option A) would rewrite a
    handle the application already holds.
  - The reader-side interval state machine, whose emitted octets are **byte-compared against RTI's captured
    APP_ACKs** by `make corpus` — the A2 round-trip lesson applied one level up: A2 re-derived the *layout*
    from a decode, this re-derives the *content* from the API and reproduces RTI's bytes for both committed
    vectors.
  - `node-send-app-ack`, **unicast to the writer's participant alone**. A reader's ACKNACK is fanned out to
    every matched peer harmlessly, because it is keyed by a SequenceNumberSet a foreign writer will not
    recognise; an APP_ACK names a *writerId*, and two writers in different participants routinely share an
    EntityId — fanned out it would tell a same-EntityId writer elsewhere that its sample was acknowledged
    by an application that never saw it. The integration test asserts the negative: a decoy participant
    with a same-topic writer receives **zero**.
  - Inbound 0x1c/0x1d are **recognised and counted** under a VendorId that gives them this meaning (RTI's,
    or ours for what we emit), so the ours↔ours test can prove the datagram landed. Recognised is **not**
    processed — no watermark, no listener, no APP_ACK_CONF.
- **Slice A3c — the writer side. ✅ DONE.**
  - **The APPLICATION watermark**, a *second* watermark on each `ReaderProxy` beside ADR 0089's
    acked-base, and the purge gated on `min` of the two. **This is the slice that makes the feature real**:
    without it the reader emits APP_ACKs, the writer reports an end-to-end guarantee, and it still purges
    on protocol acknowledgments alone — a writer reporting a guarantee it is not honouring, which is
    exactly the silent data loss §4 refuses to match on. Gated on the writer's own advertised QoS, so the
    `:protocol` default is byte-identical.
  - **Only the contiguous prefix advances it.** An APP_ACK may name disjoint ranges; a watermark means
    "everything below this". Taking the highest named sequence number would declare every hole beneath it
    acknowledged — **a false ack manufactured by the writer** rather than by the reader. A gap stops the
    advance; a later cumulative APP_ACK closes it. Monotonic, so a stale or reordered message cannot
    un-acknowledge anything.
  - **APP_ACK_CONF**, unicast back to the acknowledging reader, echoing the count.
  - **`on-application-acknowledgment`** + `application-acknowledgment-status` at StatusKind **bit 28**
    (27 stays reserved), with all three registrations. RTI's `DDS_AcknowledgmentInfo` fields
    `response_data` / `valid_response_data` are **deliberately absent** — nothing emits or parses response
    data yet, so they would be permanently NIL under names that promise otherwise (the ADR 0089 §5
    inert-field trap). They arrive with the slice that puts response data on the wire.
  - **T10 gated.** A forged plain APP_ACK from a keyed-rtps peer would advance an application watermark
    and let the writer purge samples no application processed — the same permanent-data-loss shape the
    ACKNACK gate exists to stop, and worse here because the loss is silent by construction.

### 6.2 ⚠️ A FOURTH SILENT FAILURE MODE IN THE STATUS MACHINERY, found by A3c

ADR 0089 established that a status needs **three registrations** and that each omission fails silently in
its own way. A3c found a fourth, *underneath* all three: **the callback fired and carried nothing.**

`%notify-status`'s `apply-fn` contract is `(values CHANGED-P SNAPSHOT RESET-THUNK)`. The first cut returned
the snapshot alone — so it became the `CHANGED-P` value (truthy, so the notification proceeded), `SNAPSHOT`
defaulted to `NIL`, and the listener was invoked with a **null status**. All three registrations were
present and correct; the ADR 0089 completeness test passed, because it checks that the registrations exist,
not that the payload arrives.

**What caught it was asserting on the status CONTENT rather than on the callback firing.** The integration
test's "did `on_application_acknowledgment` fire?" assertion passed; "does the status name the acknowledging
reader?" failed. **Generalise it: a test that only asks whether a callback fired cannot distinguish a
working notification from an empty one** — assert on what the notification carries.
- **`APPLICATION_ORDERED` stays out of scope** until its semantics can be sourced. No published explanation
  was found, and inventing one under RTI's name is what ADR 0089 §5 forbade.

### 6.1 (superseded) the plan had Option B been accepted

- **Slice 1 — MVP, ours↔ours, `APPLICATION_EXPLICIT` only.**
  QoS `acknowledgment-kind` (`:protocol` default | `:application-auto` | `:application-explicit`) as a
  vendor policy — **RxO-gated**, because a writer offering APPLICATION acks and a reader that will never
  send them must not match (that is a silent stall, the ADR 0057 failure shape). Reader API
  `acknowledge-sample` / `acknowledge-all`. One vendor-range submessage carrying {writer GUID, SN
  intervals, optional response data}. Writer-side: a change is not purgeable until app-acked — i.e. the
  ADR 0089 acked-watermark gains a second, *application* watermark. Listener
  `on-application-acknowledgment` + an `acknowledgment-info` struct, riding the ADR 0089 machinery **with
  all three registrations** and the completeness test covering it automatically.
- **Slice 2 — `APPLICATION_AUTO`**: ack on `read`/`take` (and on `return-loan` for loaned samples, which
  interacts with the FlatData/ZC loan paths — deliberately *not* slice 1).
- **Slice 3 — response data + retention**: `response_data` and the `valid_response_data` expiry.
- **Slice 4 (gated on the §5 answer) — Connext interop**: a live capture from a Connext APPLICATION_EXPLICIT
  pair, dissected by the Wireshark RTPS dissector that already names every field, turned into a byte-exact
  corpus vector, then a 0x1c/0x1d codec gated on VendorId=RTI.
- **`APPLICATION_ORDERED` is explicitly out of scope** until its semantics can be sourced. No published
  explanation was found, and inventing one under RTI's name is exactly what ADR 0089 §5 forbade.

**The failure mode to design against.** For most features a false *reject* is the worst outcome. Here it is
the opposite: **a false ACK is worse than no ack at all**, because the writer then purges a sample the
application never processed and reports success. Every ambiguous case must resolve to "not yet
acknowledged." That belongs in the slice-1 tests as an explicit, falsified assertion.

## 7. Open questions to settle inside slice 1

1. Does an app-ack also imply a protocol ack, or are the two watermarks independent? (Independent is the
   safer reading: a sample can be protocol-acked and not yet app-acked, never the reverse.)
2. What happens on reader liveliness loss with samples outstanding — does the writer keep them forever?
   `wait_for_acknowledgments` needs a defined interaction, and an unbounded retention is a DoS surface
   (NFR-SEC-POSTURE).
3. Interaction with `RESOURCE_LIMITS`: app-ack retention makes a KEEP_ALL cache grow until the application
   acknowledges. The existing block-up-to-`max_blocking_time` backpressure (ADR 0016) should cover it, but
   the test must prove it rather than assume it.
