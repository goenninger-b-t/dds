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

**Left open, honestly:** the second question was phrased *"if the first slice is ours↔ours (Option B), is
Connext interop still required later?"* and was answered **"defer — decide after slice 1."** With A chosen,
that premise does not hold, so the answer is ambiguous between two readings: (a) it was answering a
question that no longer applies, or (b) start Connext-first but re-evaluate scope once the first slice
lands. **Nothing in §6 depends on resolving it yet** — the capture, the corpus vector and the codec are
required under either reading — so the work proceeds and the question is carried here rather than guessed
at. It must be settled before the DCPS-semantics slices are scoped.

## 6. The slice plan AS ACCEPTED — Option A, Connext-facing first (VSD, thinnest end-to-end first)

Revised after §3.1. The virtual-writer model is **not** a prerequisite; `virtualWriterCount = 1` with the
writer's own GUID satisfies the ordinary case.

- **Slice A0 — the capture. ✅ DONE** (this ADR §3.1). Peers at `interop/connext/appack/`, layout confirmed
  exact on 10/10 bodies. The remaining wire unknown is `intervalFlags`, which needs more provoked cases
  (explicit mode, response data, a gap in the acknowledged range) before any encoder may emit it.
- **Slice A1 — a byte-exact corpus vector + a decoder.** Commit a captured APP_ACK and APP_ACK_CONF to
  `corpus/`, and implement `parse-app-ack` / `parse-app-ack-conf` in `DDS.RTPS.MESSAGE` **gated on
  vendorId = RTI**, verified against the vector under `make corpus`. Decode-only: inbound is already safely
  ignored today (§3), so this cannot regress anything, and it is the half that can be proven byte-exactly
  before any behaviour depends on it.
- **Slice A2 — emit.** `write-app-ack` from the reader side, byte-compared against the captured vector.
  Then a live leg: our reader acknowledging a Connext writer.
- **Slice A3 — the DCPS semantics.** The QoS (`acknowledgment-kind`, RxO-gated — a writer offering
  application acks must not match a reader that will never send them; that is a silent stall, the ADR 0057
  shape), the reader API, the writer-side application watermark beside ADR 0089's acked-watermark, and
  `on-application-acknowledgment` with **all three registrations** (ADR 0089 §2), covered automatically by
  the completeness test.
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
