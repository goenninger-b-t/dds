# WP-DATA-REPRESENTATION — PID_DATA_REPRESENTATION on the wire + TX in the offered representation — design

**Goal (DDS-XTypes 1.3 §7.6.3.1.1, FR-QOS / FR-IO).** Two steps:
- **Step 1 (RX/advertise/match):** emit + parse **PID_DATA_REPRESENTATION (0x0073)** in SEDP, advertise our endpoints' TRUE accepted/offered representations, and let the EXISTING spec-strict RxO check match on real values. Today no PID is emitted → every discovered peer defaults to `(:xcdr1)` and the RxO check trivially matches; this closes that by signalling truthfully.
- **Step 2 (TX):** make the writer SERIALIZE + send in its OFFERED representation (XCDR1-LE **or** XCDR2-LE), instead of always XCDR2-LE — so an XCDR1-offering writer can serve an XCDR1-accepting reader.

Non-R6 except the FlatData TX-transcode (R6, FlatData-gated like the RX transcode). Both impls.

## Owner-confirmed decisions (brainstorm 2026-06-17)
1. **Truthful advertise + spec-strict RxO + interop-gate** (NOT a fail-open RxO): advertise our true reps; keep the existing `qos-rxo-compatible` rule; the Connext+Fast DDS interop verification is the gate that no real peer is newly false-rejected.
2. **Reader advertises `(:xcdr2 :xcdr1)`** (accepts both; prefers XCDR2 so a preference-honouring peer sends XCDR2 and our reader skips the transcode).
3. **TX-XCDR1 is in scope as step 2** (owner directive 2026-06-17).

## Wire-is-oracle (MANDATORY, do FIRST in implementation)
The exact `DataRepresentationId_t` enum values and the sequence/alignment/endianness encoding of the PID value MUST be pinned from the **DDS-XTypes 1.3 §7.6.3.1.1 clause text** AND verified **byte-exact against a live RTI Connext + Fast DDS SEDP capture** (tshark RTPS dissector). Do NOT hardcode any value from memory. Per the clause (to be CONFIRMED against the text + a capture, NOT trusted from this doc): `typedef short DataRepresentationId_t;` `typedef sequence<DataRepresentationId_t> DataRepresentationIdSeq;` `struct DataRepresentationQosPolicy { DataRepresentationIdSeq value; };`; the enum is believed `XCDR_DATA_REPRESENTATION=0, XML_DATA_REPRESENTATION=1, XCDR2_DATA_REPRESENTATION=2` — **verify**. The PID value in PL_CDR_LE = a CDR sequence: u32 length (LE) + length×`short` (LE, 2-byte each), padded to the 4-byte parameter boundary; the parameter `length` field covers the padded value. **Capture a real Connext + Fast DDS participant's SEDP and match byte-for-byte before trusting any of this.**

## Grounded current state (file:line — verified)
- `src/dds-qos/qos.lisp:122` — `(data-representation (list :xcdr1) :type list)`; the keywords `:xcdr1`/`:xcdr2`/`:xml` are the internal `DataRepresentationId_t`. DataWriter: OFFERED = `(first data-representation)`; DataReader: the accepted SET (qos.lisp:120-121 comments).
- `src/dds-qos/qos.lisp:187-188` — the RxO rule: `(unless (member (first (qos-data-representation offered)) (qos-data-representation requested)) (push :data-representation bad))`. Already wired via `qos-rxo-compatible` → `endpoint-match-p` (discovery.lisp:628-638). DO NOT change the rule.
- `src/dds-dcps/statuses.lisp:48` — `+qos-policy-id-data-representation+ = 23` + the `*rxo-keyword->policy-id*` mapping (drives OFFERED/REQUESTED_INCOMPATIBLE_QOS). Already present.
- `src/dds-rtps/discovery.lisp:485-553` `serialize-endpoint-data` / `:555-609` `%fill-endpoint-param` — the SEDP emit/parse; PID_RELIABILITY (emit :506-511, parse :569-572) + PID_LIVELINESS (:516-528 / :577-586) are the precedents to mirror. NO PID_DATA_REPRESENTATION emit/parse exists.
- `src/dds-rtps/discovery.lisp:461-483` `endpoint-data` — holds the QoS (`qos` slot); parsed PID lands in `(qos-data-representation (endpoint-data-qos data))`; NO new slot needed.
- `src/dds-rtps/message.lisp:677-731` — PID constants; `+pid-data-representation+` (0x0073) is MISSING (add + export in packages.lisp).
- `src/dds-cdr/cdr.lisp:10-39` — `+representation-ids+` (the 16-bit ENCAPSULATION ids — DISTINCT from `DataRepresentationId_t`) + `representation-id-value`/`-name` helpers. The encapsulation header uses these (XCDR1-LE = `:plain-cdr-le` 0x0001; XCDR2-LE = `:plain-cdr2-le` 0x0007).
- `src/dds-gen/dsl.lisp:201` `serialize-<name> (sample cursor &optional (mode :xcdr2))` — the struct codec ALREADY encodes both modes (`:xcdr1`/`:xcdr2`; `cdr-align` caps 8 vs 4). `:367` `fd-ser` (FlatData) is identity-XCDR2 (the buffer IS XCDR2-LE). `:360-362` the FlatData/struct serializer writes the encapsulation header — currently HARDCODED `:plain-cdr2-le`.

## Step 1 design — PID_DATA_REPRESENTATION emit/parse + advertising + RxO

### 1a. The PID constant + helpers
- `+pid-data-representation+ = #x0073` in `message.lisp` (docstring cites DDS-XTypes 1.3 §7.6.3.1.1 / the discovery-builtin-topic @id), exported.
- Keyword ↔ `DataRepresentationId_t` helpers (e.g. `%data-rep-wire` / `%wire-data-rep`) mapping `:xcdr1↔0`, `:xml↔1`, `:xcdr2↔2` (the VERIFIED values), beside the existing wire helpers in discovery.lisp. NOT the `+representation-ids+` encapsulation ids — keep them distinct.

### 1b. Emit (serialize-endpoint-data)
Emit PID_DATA_REPRESENTATION carrying the endpoint's `(qos-data-representation (endpoint-data-qos data))` as a `sequence<short>`: write u32 count + each rep as a `short` (mapped), pad to 4, `write-parameter`. Mirror the PID_RELIABILITY idiom (`%make-scratch` + `write-parameter`). Emit for BOTH readers and writers (each advertises its own list).

### 1c. Parse (%fill-endpoint-param)
On `+pid-data-representation+` with `len >= 4`: read the u32 count, bounds-check `count` against `len` (NFR-SEC-POSTURE — a malformed count must not over-read; cap to the parameter extent), read `count` shorts, map each to a keyword (unknown id → skip/ignore, fail-open — never reject the whole SEDP), store the list into `(qos-data-representation (endpoint-data-qos data))`. An ABSENT PID → leave the default (back-compat with peers that don't emit it).

### 1d. Truthful advertising via role-aware QoS defaults
The current `(:xcdr1)` default (qos.lisp:122) is reconciled in the role-specific constructors `make-reader-qos` / `make-writer-qos`:
- **Reader default `(:xcdr2 :xcdr1)`** — we accept both (XCDR2 native + XCDR1 via the struct codec / FlatData transcode); XCDR2 first = prefer XCDR2.
- **Writer default `(:xcdr2)`** — offered = what TX sends (step 2 makes TX honour this).
The QoS field IS the truth: SEDP emits it; RxO consumes it. **Default-change blast radius:** tests asserting the old `(:xcdr1)` default or relying on all-default matching are migrated (intent-preserving) — like the WP-KEEPLAST default flip. Our own pub/sub still match (writer `:xcdr2` ∈ reader `(:xcdr2 :xcdr1)`).

### 1e. RxO — UNCHANGED
The existing spec-strict rule + the policy-id-23 INCOMPATIBLE_QOS mapping already work; fed truthful values they yield correct, false-reject-safe matches. An XCDR1-only peer reader correctly won't match our (step-1) XCDR2-only writer — a TRUE incompatibility that **step 2 resolves** (the writer can then offer XCDR1).

## Step 2 design — TX in the offered representation (XCDR1-LE or XCDR2-LE)

### 2a. The selection (per-writer single rep)
The writer serializes + sends in its OFFERED rep = `(first (qos-data-representation writer-qos))`: `:xcdr2` → XCDR2-LE (default, unchanged wire), `:xcdr1` → XCDR1-LE. ONE rep per writer to ALL its readers (per-reader encoding for a mixed reader set is a follow-up). Opt-in: the default writer offered is `:xcdr2`, so existing wire is byte-identical; an app sets the writer QoS `(:xcdr1)` to send XCDR1.

### 2b. Non-FlatData (struct codec)
Thread the offered rep from the DataWriter QoS through the publish path (write-sample → the type-support serialize) so `serialize-<name>` is called with `mode :xcdr1` (the codec already supports it) and the encapsulation header is written for the matching encapsulation id (`:plain-cdr-le` 0x0001 for XCDR1-LE vs `:plain-cdr2-le` 0x0007 for XCDR2-LE) — replacing the hardcoded `:plain-cdr2-le` (dsl.lisp:360-362) with the rep-derived id (via `representation-id-value`). The serialized-size path (`sszi`/`ssz`) must also honour the mode (XCDR1 vs XCDR2 size differs — the 8-vs-4 alignment).

### 2c. FlatData (R6)
The FlatData buffer is XCDR2-LE (identity). For offered `:xcdr2` the identity 0-copy path is UNCHANGED. For offered `:xcdr1`, TX-transcode (symmetric to the RX transcode): decode the XCDR2-LE buffer via `deserialize-<name>` (XCDR2) → struct → `serialize-<name>` `mode :xcdr1` → XCDR1-LE wire. Allocs (the foreign-rep TX fallback, off the measured hot path); the native XCDR2 identity path stays 0-copy/0-alloc (`make mem` 0.0000). Carries the R6 `NOT cleared for ship` marker.

### 2d. Bounds / safety
TX is local (our own data) so the build is trusted; but the serialized-size + the buffer extent must be correct for XCDR1 (the 8-byte alignment makes XCDR1 ≥ XCDR2 size for 8-byte scalars) — size the TX buffer from the mode-aware `ssz`. No wire-data trust on TX.

## Test scenarios (oracle = byte-exact wire + the field/keyhash values + RxO outcome; both impls except live legs)
**Step 1:**
1. **SEDP round-trip** (both impls): serialize an endpoint with `data-representation (:xcdr2 :xcdr1)` → parse → assert the list round-trips; extend `run-sedp-test`.
2. **Wire byte-exact vs the clause + the captured oracle**: the emitted PID_DATA_REPRESENTATION bytes match the pinned §7.6.3.1.1 encoding AND a real Connext/Fast DDS SEDP capture.
3. **RxO matrix** (both impls): reader `(:xcdr2 :xcdr1)` matches a writer offering `:xcdr1` AND one offering `:xcdr2`; writer `:xcdr2` matches a reader accepting `{…:xcdr2…}`; an XCDR1-only reader does NOT match a `:xcdr2` writer (true incompatibility → INCOMPATIBLE_QOS policy-id 23).
4. **Malformed PID** (fuzz/bounds, both impls): a forged count / truncated value → clean reject of the PID (fail-open: the rest of the SEDP still parses), no OOB even at `(safety 0)`.
5. **Default-change migration**: the reader/writer default flip is reflected; migrated tests stay intent-preserving.
**Step 2:**
6. **TX XCDR1 byte-exact** (both impls): a writer offering `:xcdr1` emits a PLAIN_CDR_LE (0x0001) SerializedPayload whose body is the XCDR1 (8-byte-aligned) encoding — byte-exact vs an independent oracle; XCDR2 default unchanged (0x0007). Both non-FlatData AND FlatData (the FlatData TX-transcode).
7. **TX→RX round-trip** (both impls): our `:xcdr1` writer → our reader reads it (the reader already handles XCDR1 — struct codec / FlatData RX-transcode); field values + keyhash correct.
8. **mem**: the XCDR2 default TX path stays 0.0000 (FlatData identity unchanged); the XCDR1 TX-transcode allocs only on that fallback.

**Cross-DDS interop (the per-feature DoD — Connext + Fast DDS, agent runs both live):**
- **Step 1:** capture a real Connext + Fast DDS SEDP (pin/verify the PID wire format); confirm our emitted PID dissects identically (tshark); confirm bidirectional matching — our reader↔their writer, our writer↔their reader — still matches with no new false-rejects.
- **Step 2:** our `:xcdr1`-offering writer → a Connext + Fast DDS reader reads the samples (XCDR1 on the wire, tshark-confirmed); our `:xcdr2` writer → their reader (unchanged); a foreign XCDR1-offering writer → our reader (already works via the RX transcode, re-confirmed).

## Out of scope (follow-ups)
- Per-reader encoding selection for a MIXED reader set (different readers accepting different reps from one writer) — v1 is per-writer single rep.
- The XML representation (`:xml`) on TX/RX (we do XCDR only).
- BE TX (we send LE: XCDR1-LE / XCDR2-LE).

## Conformance citations
- DDS-XTypes 1.3 §7.6.3.1.1 (DataRepresentationQosPolicy, DataRepresentationId_t, the RxO rule); §7.6.3.1.2 / Table 60 (the ENCAPSULATION ids — distinct).
- RTPS 2.5 §8.5 (SEDP / DiscoveredReader/WriterData), §9.6 (the PL_CDR parameter encoding).
- DDS 1.4 §2.2.3 (QoS RxO / OFFERED_INCOMPATIBLE_QOS). NFR-SEC-POSTURE (the parse bounds). The cross-DDS-interop-per-feature DoD.
