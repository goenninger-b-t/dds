# Design — Cross-vendor coexistence dedup (recognize RTI's vendor per-sample origin)

- **Status:** Design (brainstormed, owner-approved 2026-06-20) — under owner spec review
- **WP:** WP-DURABILITY-COEXIST-DEDUP (M6/P5)
- **Relates to:** ADR 0024 (Phase-2 dedup — standard `PID_ORIGINAL_WRITER_INFO` + per-origin
  watermark); ADR 0026 §10 item 1 (this follow-on); the Phase-3b coexistence finding
  (`interop/durability-persistent/coexistence/`); REQUIREMENTS NFR-SEC-POSTURE (bounds-checked
  parse), NFR-MEM (bounded dedup), the OMG-conformance directive (a Connext/Fast DDS interop
  behaviour goes ON TOP of, never replacing, conformant behaviour), NFR-IP (clean-room),
  [[cross-dds-interop-required-per-feature]].

## Context — the problem

The durability service achieves no-double-delivery via the **OMG-standard** `PID_ORIGINAL_WRITER_INFO`
(0x0061): the relay writer stamps each relayed DATA's inline-QoS with the original writer's
`(GUID, SN)`, and a receiver keeps a bounded per-origin-GUID watermark and discards a `(GUID, SN)`
it has already delivered (`dds.rtps.reliable:reader-dedup-accept-p`, reliable.lisp:361; ADR 0024).
This makes a **dual relay** (our service + another relay of the same logical stream) deliver each
sample exactly once to a late-joiner.

Phase-3b established (`interop/durability-persistent/coexistence/`) that this is **not
cross-vendor-exercisable against RTI Persistence Service**: RTI PS stamps `PID_KEY_HASH` (0x0070)
+ **zero** `PID_ORIGINAL_WRITER_INFO` per sample, conveying origin identity via its **vendor
`PID_ENTITY_VIRTUAL_GUID`** (0x8002), advertised once per relay endpoint in SEDP (= the original
writer's GUID). So a receiver doing standard-OWI dedup has nothing to match RTI PS's stream against
ours on. ADR 0026 §10 item 1 recorded the follow-on: **recognize RTI's vendor origin-id so a live
dual-relay-exactly-once with RTI PS becomes exercisable** — a Connext-interop behaviour ON TOP of
the conformant standard-OWI dedup, never replacing it.

## Owner decisions (brainstorm 2026-06-20)

1. **Spike-first → live proof.** The first slice is a wire spike that captures + fully decodes a
   live RTI dual-relay, establishing RTI's exact per-sample origin encoding before any dedup
   design is committed (wire-is-oracle).
2. **Both directions.** Receiver-side recognition (our reader dedups our-relay vs RTI-PS) **and**
   emit-side (our relay stamps RTI-compatible per-sample origin so a Connext receiver dedups
   our-relay vs RTI-PS).
3. **Honest-finding fallback.** If the spike shows RTI's per-sample wire cannot carry a sample-level
   origin key, ship what the wire supports, document a second wire-dialect finding (à la Phase-3b),
   and prove the mechanism end-to-end with an our-stack test using a synthetic RTI-style encoding.
   Standard-OWI stays authoritative; never a false exactly-once claim.

## The crux (the spike's central question)

Our dedup key is a **per-sample** `(logical-origin-GUID, logical-origin-SN)`. For an our-stack
receiver to collapse "sample X relayed by us (OWI)" and "sample X relayed by RTI PS (vendor
encoding)" into one delivery, both must map to the **same** `(GUID, SN)`.

- Confirmed (Phase-3b): RTI PS advertises the original writer's GUID at the **endpoint** level
  (SEDP 0x8002); per sample it emits only `PID_KEY_HASH`.
- **Unconfirmed:** whether RTI emits a **per-sample** virtual identity — a `(virtualGUID,
  virtualSN)` under an RTI vendor inline-QoS PID we have not yet decoded — and, if so, whether
  `virtualGUID/virtualSN` equals the original writer's real `(GUID, SN)` (the namespace our OWI
  uses) or is a synthetic RTI namespace.

RTI Connext's own durability dedup is known to operate on a virtual-GUID / virtual-SN pair; the
spike must decode whether and how that pair appears **per sample** on the wire. The answer selects
the implementation branch (below). If no per-sample origin SN exists on RTI's wire, sample-level
cross-vendor dedup is wire-impossible → the honest-finding fallback.

## Approach — unify on the existing logical-origin key (chosen)

Three approaches were weighed:

- **#1 (CHOSEN) — one logical-origin key, multiple wire carriers.** Extend origin extraction so a
  sample's dedup key may come from the standard OWI **or** RTI's per-sample vendor origin (whichever
  is present), feeding the **same** watermark map and gate. Emit-side: our relay additionally stamps
  the RTI vendor per-sample origin (alongside OWI, behind the existing default-off persistence-relay
  flag). Minimal new structure; additive; default-safe. Cross-vendor dedup works iff RTI's virtual
  identity aligns with the original `(GUID, SN)` namespace (the spike's finding).
- **#2 — a separate RTI-vendor dedup map.** Rejected: an our-OWI sample and the RTI-vendor sample
  land in different maps, so the receiver never recognises they are the same logical sample — it
  defeats the cross-vendor goal (dedups only RTI-vs-RTI).
- **#3 — a pluggable canonical-origin normaliser (per-vendor extractor vtable).** Same effect as #1
  with more abstraction; YAGNI for two carriers. #1 keeps a clean extraction seam so #3 is a cheap
  later refactor if a third vendor appears.

## Mechanism (built on #1)

**Receiver-side.** At the receive gate (the `reader-dedup-accept-p` feed in dataplane.lisp:~1305,
which already runs **after** `reader-on-data` so reliable HEARTBEAT/ACKNACK state is untouched),
extract the logical-origin `(GUID, SN)` by a precedence chain:

1. `PID_ORIGINAL_WRITER_INFO` (0x0061) — the standard, primary, authoritative source;
2. RTI's per-sample vendor origin (spike-confirmed PID) — used only when OWI is absent;
3. native `(writerGUID, writerSN)` — the existing default when neither is present.

One watermark map, unchanged bound (`*max-gap-range*`), unchanged conformance properties
(no false-reject, no silent loss; a benign duplicate only at the pathological cap, ADR 0024).

**The identity-alignment branch (spike-decided):**

- **Branch A — RTI's virtual id == the real `(GUID, SN)`** (e.g., a non-durable-configured original
  writer where `virtualGUID == realGUID` and `virtualSN == writer SN`). Then our OWI key and the
  RTI-vendor key coincide directly → recognition alone achieves dedup. No change to what our relay
  collects.
- **Branch B — RTI's virtual id is a distinct namespace.** Then our service, when it collects from
  an RTI original writer that carries a virtual id, must **adopt that virtual identity** for its own
  OWI (stamp OWI with the virtual `(GUID, SN)` instead of the observed real one) so both relays
  share one namespace. Receiver-side recognition then collapses them.

The spec carries both branches; the spike selects one. If neither is achievable (no per-sample SN on
RTI's wire) → the honest-finding fallback.

**Emit-side.** Our relay writer, behind the **existing default-off** persistence-relay flag, stamps
each relayed DATA with the RTI vendor per-sample origin (`virtualGUID = origGUID`, `virtualSN =
origSN`) **in addition to** OWI — never replacing it. Default-off ⇒ the normal wire is byte-identical;
an our-stack receiver still consumes OWI (primary); a Connext receiver consumes the RTI vendor
encoding and dedups our-relay vs RTI-PS.

## VSD slices (thinnest end-to-end first)

- **Slice 0 — Spike (gates everything).** Live capture of an RTI/Connext TRANSIENT writer →
  RTI PS **and** our service → receivers; decode **every** per-sample PID incl. RTI vendor
  inline-QoS. Deliverable: a findings doc answering the crux question + selecting Branch A/B (or
  triggering the fallback) + the exact vendor PID id(s), byte layout, and a pinned byte vector.
- **Slice 1 — Receiver-side recognition (MVP, our-stack-proven).** Parse RTI's per-sample vendor
  origin; wire it into the precedence chain. Proven end-to-end **without** live RTI via a synthetic
  RTI-style stand-in relay (emits the vendor encoding instead of OWI) → our reader dedups to
  exactly-once. Bounds-checked parser (+ fuzz arm).
- **Slice 2 — Receiver-side LIVE.** The live dual-relay → our reader → exactly-once (if the spike
  confirmed the wire supports it; else the honest finding).
- **Slice 3 — Emit-side.** Our relay stamps the RTI vendor per-sample origin (additive, default-off);
  byte-pinned vs the Slice-0 vector; live Connext-reader dedup of our-relay vs RTI-PS.
- **Slice 4 — Capstone.** ADR (records as-built + the spike finding + Branch A/B chosen + any
  residual finding), docs lockstep (wiki/README/verification), the `no-double-delivery` test
  extended with a cross-vendor arm, full gate sweep both impls.

## Conformance & safety

- **On-top-of-standard.** Standard-OWI stays the primary, authoritative dedup source and the
  authoritative proof; RTI-vendor recognition/emit is strictly additive. OWI precedence when both
  present. No conformant behaviour is replaced.
- **Default-safe.** Emit-side is behind the existing default-off persistence-relay flag ⇒
  byte-identical normal wire; receiver-side recognition is inert unless an RTI vendor origin PID is
  actually present and OWI is absent.
- **Bounds-checked + fuzzed.** The new inbound vendor-PID parser validates every length/offset
  against the buffer extent before use, even at `(safety 0)`, and gets a fuzz arm (NFR-SEC-POSTURE).
- **Clean-room (NFR-IP).** RTI's vendor per-sample origin encoding is reverse-engineered from the
  Slice-0 capture + any RTI-published spec, never from RTI source; constants pinned from the capture
  and cited; provenance logged in `docs/provenance.md`.
- **NFR-MEM.** No new per-sample allocation on the measured path; `make mem` stays 0.0000 (the
  durability collect/dedup is control-plane).
- **Hot-path / portability.** No CLOS on a hot path; `defun*`/`defstruct*`; full type declarations;
  no reader conditionals outside `dds-pal/`; no AI attribution.

## Testing & interop (per-feature DoD)

- **Authoritative (our-stack, deterministic both impls):** `run-durability-no-double-delivery-test`
  gains a **cross-vendor arm** — a synthetic RTI-style relay emits the vendor per-sample origin
  encoding (no OWI) alongside our standard-OWI relay; the our-stack late-joiner reader must deliver
  exactly N (not 2N). Plus a parser unit test + the fuzz arm.
- **Live cross-DDS (both receiver directions):** (1) our late-joiner reader dedups a real RTI-PS +
  our-service dual relay of one RTI TRANSIENT writer → exactly-once; (2) a Connext late-joiner reader
  dedups our-relay (vendor-emitting) + RTI-PS → exactly-once. tshark-validated; honest caveats
  documented (e.g. the macOS `lo0` capture quirk). If the spike's adverse outcome holds, the live
  proof is replaced by the documented finding + the authoritative our-stack arm.

## Open questions (resolved by Slice 0)

- Does RTI emit a per-sample `(virtualGUID, virtualSN)`? Under which inline-QoS PID? Byte layout?
- Does `virtualGUID/virtualSN` equal the original writer's real `(GUID, SN)` (Branch A) or a
  synthetic namespace (Branch B)?
- Does RTI's original-writer virtual identity require a specific Connext writer QoS to be present?

## Follow-ons (not in this WP)

- The canonical-origin normaliser abstraction (Approach #3) if a third vendor's encoding appears.
- Emit-side coherent-set / instance-lifecycle parity with RTI PS beyond per-sample origin.
