# DATA_FRAG data-plane with fragment-level reliability + Connext interop

- **Date:** 2026-06-09
- **Status:** Design — approved for planning
- **Area:** RTPS data plane (L4 message + reliable engine), L5 discovery data-plane wiring, L6 DCPS driver type, interop harness
- **Requirements:** FR-RTPS (DATA_FRAG / fragment reliability), FR-IO (Connext interop), NFR-SEC-POSTURE (bounds + resource guards), the operating contract §4 (the wire is the oracle) and §6 (gates)

## 1. Goal & scope

Let DDS samples larger than a single datagram flow **reliably** between this stack and RTI Connext 7.3.1, using the RTPS **DATA_FRAG** submessage with **fragment-level reliability** (HEARTBEAT_FRAG + NACK_FRAG). A lost fragment is recovered by NACKing the specific missing fragment numbers, not by resending the whole sample.

In scope:
- New RTPS codecs: `FragmentNumberSet`, HEARTBEAT_FRAG, NACK_FRAG (DATA_FRAG codec already exists).
- Writer-side fragmentation, including packing **multiple whole fragments per DATA_FRAG submessage** (`fragmentsInSubmessage` > 1) up to the per-datagram budget.
- Reader-side reassembly with resource guards.
- The HEARTBEAT_FRAG / NACK_FRAG state machines on both ends.
- A driver type `LargeData` and a publish/subscribe harness.
- Live bidirectional fragmented interop with Connext 7.3.1.

Out of scope (separate features): multi-endpoint per participant (the stack stays v1 — one user writer + one user reader per participant); large types other than `LargeData`.

## 2. Decisions (locked during brainstorming)

1. **Fragment-level reliability**, not sample-level — HEARTBEAT_FRAG + NACK_FRAG, so only missing fragments are resent.
2. **Definition of done includes live Connext large-type interop** (bidirectional), like the M2 ShapeType gate — not offline-only.
3. **Driver type** `LargeData { @key long id; sequence<octet> payload; }`.
4. **Build approach A** — layered bottom-up, one commit per stage, each green before the next; pin codecs to a captured Connext fragmented exchange once the oracle exists.
5. **`fragmentsInSubmessage` > 1 is in scope** on send (packing policy).

## 3. Driver type

```
(dds.gen:define-dds-type large-data (:extensibility :final)
  (id :i32 :key t)
  (payload (:sequence :u8)))
```

`define-dds-type` already supports `(:sequence :u8)` and per-member `:key` (cf. the `gseq` test type). XCDR2 serialized size = id (4) + payload length prefix (4) + N octets, so a payload of a few KB produces a sample that exceeds `*fragment-size*` and Connext's configured fragmentation threshold. The Connext side uses a matching `LargeData.idl`.

## 4. Architecture & components (bottom-up; stage = commit boundary)

**Stage 1 — L4 codecs (`src/dds-rtps/message.lisp`).**
- `FragmentNumberSet` (RTPS 2.5 §9.4.2.8): `bitmapBase` = FragmentNumber (uint32), `numBits` (uint32), `bitmap` = ⌈numBits/32⌉ longs. Write + read, mirroring the existing `write/read-sequence-number-set` but with a 4-byte base (FragmentNumber) instead of the 8-byte SequenceNumber base.
- `write-heartbeat-frag` / `parse-heartbeat-frag-body` (§9.4.5.7): readerId, writerId, writerSN (SequenceNumber), `lastFragmentNum` (FragmentNumber uint32), count (Count uint32); EndiannessFlag.
- `write-nack-frag` / `parse-nack-frag-body` (§9.4.5.6): readerId, writerId, writerSN, `fragmentNumberState` (FragmentNumberSet), count.
- Exact octet layouts pinned from `docs/specs/` at implementation time (never from memory); every parser bounds-checks against the submessage extent first; clause cited in a one-line comment.

**Stage 2 — L4 reliable engine (`src/dds-rtps/reliable.lisp`).**
- *Writer.* A CacheChange whose serialized payload size > `*fragment-size*` is sent as DATA_FRAG submessages: `fragmentSize` constant across the sample, `fragmentStartingNum` 1-based, `fragmentsInSubmessage` = as many whole fragments as fit the datagram budget, the final submessage carrying the remainder. A HEARTBEAT_FRAG announces `lastFragmentNum` for samples a reader has not fully acked. On NACK_FRAG(sn, frag-set): resend exactly the requested fragments from the stored CacheChange payload (no payload duplication), coalescing contiguous missing fragment-numbers into as few DATA_FRAGs as the budget allows.
- *Reader.* A reassembly entry per `(writer-id, sn)`: a `sampleSize`-preallocated octet buffer + a received-fragment bitmap + a received count. On DATA_FRAG: bounds/guard-check, copy the submessage's fragment range into place, mark received (idempotent). On HEARTBEAT_FRAG with gaps: emit NACK_FRAG for the missing fragment numbers. On complete: hand the assembled octet vector to the existing `reader-on-data`, after which the normal sample-level HEARTBEAT/ACKNACK acks the whole SN. The fragment-level and sample-level reliability layers coexist.

**Stage 3 — L5 data-plane (`src/dds-disc/dataplane.lisp`, `disc.lisp`) + L6 DCPS.**
- Dispatch routes `+submsg-data-frag+` → reader reassembly; `+submsg-heartbeat-frag+` → reader; `+submsg-nack-frag+` → writer.
- `%push-data` fragments a large user sample (DATA_FRAG[…] + HEARTBEAT_FRAG) instead of DATA + HEARTBEAT; a new `%on-user-nackfrag` is the fragment resend path alongside `%on-user-acknack`.
- Reassembly state lives on the rtps-reader (per writer-proxy), not the disc-node, to keep layering clean.
- The `large-data` type is registered; a `large-pub` / `large-sub` harness mirrors `square-pub` / `square-sub`. DCPS `write-sample`/`take` are unchanged — fragmentation is transparent below DCPS (publish-sample already passes octets).
- Allocation note: reassembly allocates per large sample. This is control-plane for big payloads, not the steady-state zero-alloc hot path; documented, and bounded by the §7 reassembly guards.

**Stage 4 — Interop (`interop/connext/`).**
- `LargeData.idl` + rtiddsgen Connext publisher/subscriber apps.
- **Force fragmentation on loopback** by setting the Connext UDPv4 transport `message_size_max` small (QoS XML) so even a few-KB sample fragments; align `*fragment-size*` with it.
- Capture Connext's DATA_FRAG / HEARTBEAT_FRAG / NACK_FRAG with the tshark RTPS dissector; lock the bytes as regression vectors (pin codecs to the wire, not just the spec).
- Bidirectional: Connext→our `large-sub` (we reassemble) and our `large-pub`→Connext `large_sub` (Connext reassembles; we answer its NACK_FRAG).

## 5. Data flow

**Send (large sample):** `write-sample` → `%serialize-sample` (octets) → `publish-sample` → `writer-write` (CacheChange stored) → `%push-data`: size > `*fragment-size*` → DATA_FRAG[1..N] (multi-fragment submessages) + HEARTBEAT_FRAG → peer.

**Receive:** datagram → dispatch → DATA_FRAG → reassembly[(writer,sn)] accumulates → HEARTBEAT_FRAG gap → NACK_FRAG → writer resends only the missing fragments → complete → `reader-on-data`(assembled octets) → sample-level ACKNACK acks SN → DCPS `take`.

## 6. Special variables (new; documented + spec-cited per the contract §5.1)

- `*fragment-size*` — outbound fragment payload size in octets (RTPS `fragmentSize`, a uint16; ≤ 65535). Default **1024**.
- `*max-reassembly-bytes*` — reject an inbound `sampleSize` larger than this **before allocating** (resource-exhaustion guard). Default **4 MiB**.
- `*max-reassembly-fragments*` — cap fragments per sample. Default **8192**.

## 7. Error handling & security (NFR-SEC-POSTURE)

- Every fragment parser bounds-checks all lengths/offsets against the submessage extent before trusting wire data, even at `(safety 0)`.
- Reassembly rejects `sampleSize > *max-reassembly-bytes*` and total fragment count `> *max-reassembly-fragments*` **before** allocating the reassembly buffer.
- A fragment whose `fragmentSize`/`sampleSize` disagree with the sample's established values, or whose range exceeds `sampleSize`, drops the reassembly entry.
- Duplicate fragments are idempotent (the received-fragment bitmap).
- The parsers are added to the fuzz target (`make fuzz`).

## 8. Testing & Definition of Done

- **Byte-exact codec vectors + fuzz** for FragmentNumberSet, HEARTBEAT_FRAG, NACK_FRAG (round-trip + parser fuzz), including a `fragmentsInSubmessage` > 1 case.
- **Offline our↔our** `LargeData` round-trip: payload > `*fragment-size*`, packed multi-fragment submessages + remainder, full reassembly.
- **Lossy test:** drop specific fragments; assert NACK_FRAG names exactly the missing fragment numbers, the writer resends only those, and the sample completes.
- **`make wire`** tshark validation of our fragmented output.
- **Live Connext 7.3.1:** bidirectional fragmented `LargeData` exchange; Connext-capture regression vectors locked.
- **Gates:** gate-types, gate-hotpath, mem, fuzz green; full suite green on SBCL + Clasp.

## 9. Staged implementation (commit per stage; main green throughout)

1. Codecs + byte-exact/fuzz tests.
2. Writer fragmentation + reader reassembly + HEARTBEAT_FRAG/NACK_FRAG state machines + offline our↔our + lossy tests.
3. Data-plane wiring + `LargeData` type + `large-pub`/`large-sub` harness + offline e2e over UDP + `make wire`.
4. Connext `LargeData` oracle + harness + live bidirectional interop (fix what the wire reveals) + captured regression vectors.

## 10. Risks & open questions

- **Interop bug chain.** M2 took a six-fix chain to match live Connext. Fragmented interop adds frag-numbering, NACK_FRAG routing, and HEARTBEAT_FRAG timing as new failure surfaces. Mitigation: stages 1–3 prove the engine offline before interop debugging; codecs pinned to a real capture in stage 4. Suspect RTPS plumbing before type/semantics (the recurring M2 lesson).
- **Forcing Connext to fragment.** Default loopback may not fragment a sub-64 KB sample; rely on a small `message_size_max` in the Connext QoS XML, or a large enough payload. Confirm from a capture.
- **Count fields** (HEARTBEAT_FRAG/NACK_FRAG `Count`) and the interplay between sample-level and fragment-level reliability ordering — pin behavior from the spec and the capture.
- **fragmentsInSubmessage packing** must respect the constant-`fragmentSize`-per-sample rule and the datagram budget; the last submessage carries the partial final fragment.
