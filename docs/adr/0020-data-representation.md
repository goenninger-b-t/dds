# ADR 0020 — WP-DATA-REPRESENTATION: PID_DATA_REPRESENTATION on the wire + TX in the offered representation

- **Status:** **Accepted** (2026-06-17, WP-DATA-REPRESENTATION Tasks 1–5). Two steps delivered under this
  ADR — Step 1 (Tasks 1–2): emit + parse `PID_DATA_REPRESENTATION` (0x0073) in SEDP, truthful role-aware
  advertising, and the spec-strict RxO match on real advertised values; Step 2 (Tasks 3–4): the writer
  serializes + sends in its OFFERED representation (XCDR1-LE or XCDR2-LE) and the reader decodes whichever
  standard representation the encapsulation header declares; Task 5 is the gate sweep + this finalization.
- **As-built (2026-06-17):** 248 tests green on SBCL (and on Clasp — the data-representation tests
  `rtps-data-representation-wire` / `rtps-data-representation-malformed` / `qos-rxo-truth-table` /
  `qos-data-representation-rxo` pass on both impls); `gate-types` (1321 defuns) / `gate-hotpath` (8 hot-path
  files) / `mem` (0.0000 bytes/sample on the serialize/deserialize/round-trip hot path) / `fuzz` (incl. the
  `flatdata-transcode` 4000-iter foreign-rep fuzz) all PASS. No before/after bench is warranted: the XCDR2
  default serialize/deserialize hot path is structurally unchanged (`make mem` 0.0000), and the XCDR1 path +
  the FlatData TX-transcode are the opt-in fallback off the measured default path — no measured-default number
  moved. The live cross-DDS interop (the per-feature DoD) is recorded in
  `interop/data-representation/README.md`.
- **Deciders:** A0 (integrator); owner-confirmed in the 2026-06-17 brainstorm (the truthful-advertise +
  spec-strict-RxO decision, the reader `(:xcdr2 :xcdr1)` default, and TX-XCDR1 in scope as step 2).
- **Amends:** nothing frozen. The SEDP emit/parse gain one PID (`+pid-data-representation+`, additive); the
  QoS `data-representation` slot already existed; the role-aware *defaults* changed (see *Default change*).
  The publish path threads an OFFERED-representation argument (additive, defaulting to `:xcdr2` → the
  existing wire). No exported signature whose absence would break a consumer was changed incompatibly.
- **Requires:** the QoS `data-representation` slot (`qos.lisp`); the existing RxO rule
  (`qos-rxo-compatible`); the `+representation-ids+` encapsulation-id table + `make-encapsulation-header`
  (`cdr.lisp`); the generated struct codec's dual-mode (`:xcdr1`/`:xcdr2`) serialize/serialized-size
  (`dsl.lisp`); the FlatData transcode builder (R6, WP-FLATDATA-XCDR-TRANSCODE / ADR 0015).
- **Feature:** FR-QOS / FR-IO (DataRepresentationQosPolicy), DDS-XTypes 1.3 §7.6.3.1.1 (the policy,
  `DataRepresentationId_t`, the RxO rule) + §7.6.3.1.2 / Table 60 (the *distinct* encapsulation ids);
  RTPS 2.5 §8.5 (SEDP), §9.6 (the PL_CDR parameter encoding), §10.2 (the SerializedPayload header).

## R6 note (scoped)

This work package is **standard DDS conformance and is NOT R6**, with **one R6 exception**: the FlatData
TX-transcode (the `:xcdr1`-offered FlatData write path, §"Decision" point 4) is gated like the existing
FlatData RX-transcode (ADR 0015) and carries the `NOT cleared for ship — pending counsel (R6)` marker.
Everything else — the PID emit/parse, the advertising, the RxO, the non-FlatData XCDR1 TX, the RX
generalization — is unrestricted standard DDS, green on both impls. Clean-room from OMG DDS 1.4 / DDSI-RTPS
2.5 / DDS-XTypes 1.3 + a live SEDP capture as the byte-exact oracle; **no RTI Connext source / headers /
`rtiddsgen` output, and no Apache-2.0 (Fast DDS) / EPL-EDL (Cyclone) / OpenDDS source, was read or copied.**

## Context

DDS-XTypes 1.3 §7.6.3.1.1 specifies the `DataRepresentationQosPolicy` — a writer OFFERS a single
representation (it serializes in it); a reader ACCEPTS a SET. The RxO rule (§7.6.3.1.1; DDS 1.4 §2.2.3):
the offered representation (the writer's, the *first* in its sequence) must be a member of the reader's
accepted set, else OFFERED/REQUESTED_INCOMPATIBLE_QOS (policy-id 23). The policy is carried in SEDP as
`PID_DATA_REPRESENTATION` (0x0073), a `sequence<DataRepresentationId_t>` where
`DataRepresentationId_t` is `short` with `XCDR_DATA_REPRESENTATION = 0` (XCDR1),
`XML_DATA_REPRESENTATION = 1`, `XCDR2_DATA_REPRESENTATION = 2`.

Before this WP the stack emitted **no** `PID_DATA_REPRESENTATION`, so every discovered peer defaulted to
`(:xcdr1)` and the RxO check matched trivially — a silent under-advertisement. And the writer always
serialized XCDR2-LE (`PLAIN_CDR2_LE` 0x0007) regardless of the offered representation, so it could not
serve a reader that accepts XCDR1 only. The two together meant the stack could not honestly express, nor
satisfy, a representation constraint — and, as the live interop below shows, both reference peers' fixed-size
`@final` readers accept XCDR1 only.

## Wire-is-oracle (done FIRST)

The `DataRepresentationId_t` enum values and the `sequence<short>` PL_CDR encoding of the PID value were
pinned from the **DDS-XTypes 1.3 §7.6.3.1.1** clause text AND verified **byte-exact** against a live RTI
Connext 7.3.1 + Fast DDS 3.6.1 SEDP capture (tshark RTPS dissector). The parameter is:
`73 00 LL 00` (id 0x0073, length LL, LE) then the CDR sequence `u32 count` (LE) + `count × short` (LE,
2 octets each), padded to the 4-octet parameter boundary; the parameter `length` covers the padded value.
Recorded in `interop/data-representation/captures/NOTES.md` (Task 1) and re-dissected from our own emitted
frames in `interop/data-representation/README.md` (Task 4). The encapsulation ids (Table 60 — `PLAIN_CDR_LE`
0x0001, `PLAIN_CDR2_LE` 0x0007) are a **distinct** namespace from `DataRepresentationId_t`; the two are kept
apart in the code (`%data-rep-wire` / `%wire-data-rep` for the PID; `+representation-ids+` for the header).

## Decision

1. **Truthful advertise + spec-strict RxO + the interop-gate (NOT a fail-open RxO).** We emit
   `PID_DATA_REPRESENTATION` carrying each endpoint's true accepted/offered list and keep the existing
   `qos-rxo-compatible` rule unchanged. The cross-DDS interop verification is the gate that proves no real
   peer is *newly* false-rejected — not a relaxation of the rule. An absent PID from a peer leaves the role
   default (back-compat with non-emitting peers). An unknown `DataRepresentationId_t` on parse is skipped
   (fail-open — never reject the whole SEDP). Malformed PID bytes (a forged count, a truncated value) are
   bounds-checked against the parameter extent and skipped cleanly, leaving the role default, with no OOB
   even at `(safety 0)` (NFR-SEC-POSTURE; test `rtps-data-representation-malformed` + the
   `flatdata-transcode`/parse fuzz).

2. **Role-aware advertising via the QoS-constructor defaults.** `make-reader-qos` defaults
   `data-representation` to `(:xcdr2 :xcdr1)` — we ACCEPT both (XCDR2 native + XCDR1 via the struct codec /
   FlatData RX-transcode), XCDR2 first so a preference-honouring peer sends XCDR2 and our reader skips the
   transcode. `make-writer-qos` defaults to `(:xcdr2)` — the single OFFERED representation TX sends. The QoS
   field IS the truth: SEDP emits it; RxO consumes it.

3. **TX in the offered representation (per-writer single rep).** The writer serializes + sends in
   `(first (qos-data-representation writer-qos))`: `:xcdr2` → XCDR2-LE `PLAIN_CDR2_LE` (0x0007, the default —
   byte-identical existing wire), `:xcdr1` → XCDR1-LE `PLAIN_CDR_LE` (0x0001). The codec alignment mode AND
   the encapsulation id are both rep-derived in one place (`%rep->codec`); the serialized-size path honours
   the mode (XCDR1's 8-byte alignment makes it ≥ XCDR2 for 8-byte scalars). ONE representation per writer to
   ALL its readers; the default is `:xcdr2`, so existing wire is unchanged and an app opts in by setting the
   writer QoS `(:xcdr1)`. The representation applies ONLY to the user-data payload — NEVER to the keyhash
   (always XCDR2-BE, RTPS 2.5 §9.6.4.8) or to discovery.

4. **The FlatData TX-transcode (R6).** A FlatData buffer is XCDR2-LE (identity), so the `:xcdr2` path stays
   the 0-copy identity serialize (`make mem` 0.0000, unchanged). An `:xcdr1`-offered FlatData write
   TX-transcodes (symmetric to the RX transcode): decode XCDR2-LE → struct → re-encode XCDR1-LE. It allocs
   (the foreign-rep TX fallback, off the measured hot path) and carries the R6 marker.

5. **RX generalization — decode any standard representation.** The reader decodes the body in the
   representation the SerializedPayload's encapsulation header declares (`%encap->codec`): `PLAIN_CDR_LE` →
   XCDR1-LE, `PLAIN_CDR_BE` → XCDR1-BE, `PLAIN_CDR2_LE` → XCDR2-LE, `PLAIN_CDR2_BE` → XCDR2-BE. The 8-vs-4
   alignment AND the endianness come from the wire, not a hardcoded `:xcdr2` — so a reader accepting
   `(:xcdr2 :xcdr1)` reads either representation a peer wrote.

## The key interop finding (load-bearing)

Both RTI Connext 7.3.1's and Fast DDS 3.6.1's `ShapeType` *reader* (a fixed-size `@final` type) accept
**`[XCDR1]` only** — they elide the default-valued PID (0 matches of 0x0073 from either peer in every
capture). So our default `[XCDR2]` writer is a **true RxO incompatibility** with their reader
(`first-of-offered XCDR2 ∉ accepted {XCDR1}`), not a false-reject: it is the *correct* reject of an
unsatisfiable representation request. Live, the contrast is stark and dissected on the wire:

| Leg | Result |
|---|---|
| our `[XCDR2]` writer → Connext reader | no match — Connext received **0** |
| our `[XCDR1]` writer → Connext reader | match — `CDR_LE (0x0001)` on wire, Connext received **37/50** |
| our `[XCDR2]` writer → Fast DDS reader | no match — Fast DDS received **0** |
| our `[XCDR1]` writer → Fast DDS reader | match — `CDR_LE (0x0001)` on wire, Fast DDS received **49/50** |
| Connext writer `[XCDR1]` → our `[XCDR2,XCDR1]` reader | match — **688** GREEN shapes decoded |
| Fast DDS writer `[XCDR1]` → our `[XCDR2,XCDR1]` reader | match — **126** GREEN shapes decoded |

The 0-vs-37/49 contrast is the proof that **TX-XCDR1 is required to serve these peers** (Step 2's
justification), and the 688/126 reverse legs prove the RX generalization (Step 1/3) reads their XCDR1 wire.
Full dissections, capture filenames, and honest caveats (the macOS-`lo0` user-data capture quirk; the
benign tshark "Malformed Packet" heuristic on our TypeObject-carrying SEDP frames) are in
`interop/data-representation/README.md`.

## Default change (blast radius)

`make-reader-qos` `(:xcdr1)` → `(:xcdr2 :xcdr1)` and `make-writer-qos` `(:xcdr1)` → `(:xcdr2)`. Our own
pub/sub still match (writer `:xcdr2` ∈ reader `(:xcdr2 :xcdr1)`). Tests asserting the old `(:xcdr1)`
default or relying on all-default matching were migrated intent-preservingly in the same commits (Task 2),
like the WP-KEEPLAST default flip (ADR 0019). The generic `dds.qos:qos` slot default
(`qos.lisp` `data-representation (list :xcdr1)`) is unchanged; the role-aware truth is set by the role
constructors.

## Out of scope (follow-ups)

- **Per-reader encoding selection for a MIXED reader set** (different readers accepting different reps from
  one writer) — v1 is per-writer single rep.
- **The XML representation (`:xml`)** on TX/RX (we do XCDR only; `:xml` parses/skips but is not serialized).
- **BE TX** — we send LE (XCDR1-LE / XCDR2-LE); the RX path *reads* BE (`%encap->codec` maps
  `PLAIN_CDR_BE` / `PLAIN_CDR2_BE`), it is only TX that is LE-only.

## Consequences

- The stack now honestly expresses and satisfies a representation constraint, and interoperates with a
  fixed-size `@final` peer reader that accepts XCDR1 only — the common Shapes-demo and many fixed-size IDL
  cases. The default wire is byte-identical (XCDR2-LE 0x0007); opting into XCDR1 is one QoS keyword.
- The RX path is representation-general (any of the four standard PLAIN encapsulations), removing a
  latent hardcoded-XCDR2 assumption.
- The FlatData `:xcdr1` write path is R6-gated (counsel); the FlatData `:xcdr2` identity path is unchanged
  and ships under the existing FlatData gating.
