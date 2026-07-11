# ADR 0012 — Fast DDS 3.6.1 peer: FR-IO-2 is met; the ADR 0010 deferred TypeLookup leg is closed

- **Status:** Accepted (2026-06-12); **RATIFIED by the owner 2026-07-11**
- **Deciders:** A0 (integrator), under the owner's standing go-ahead for this feature
- **Completes:** FR-IO-2 (REQUIREMENTS §8: wire-interoperate with ≥1 of Fast DDS / Cyclone
  DDS / OpenDDS); ADR 0010 decision 1 (the TypeLookup live leg deferred to a Fast DDS peer)
  and its consequence that the provisional minimal EquivalenceHash "remains without an
  external oracle until a Fast DDS peer exists"; the Fast DDS peer plan
  (`docs/superpowers/plans/2026-06-11-fastdds-peer.md`) and design spec
  (`docs/superpowers/specs/2026-06-11-fastdds-peer-design.md`).
- **Evidence:** live eProsima Fast DDS 3.6.1 (pinned source build, commit
  `4e81e8b71bcd…`; Fast CDR 2.3.5, foonathan_memory_vendor 1.4.1, fastddsgen 4.3.0) vs
  this stack, loopback, 2026-06-11/12. Captures + raw run logs archived under
  `interop/fastdds/captures/`; frame-level evidence tables and the CONFIRM-VS-PEER walk
  table in `interop/fastdds/README.md`. Feature commits `b56ac3a..27ed6b5` on `main`.

## Context

FR-IO-2 (a REQUIREMENTS MUST) was open: every prior live leg ran against RTI Connext only.
ADR 0010 had established from the wire and from RTI's own documentation that Connext
implements neither `PID_TYPE_INFORMATION` (0x0075) nor the standard TypeLookup service, and
deferred two things to a future open peer: the **live TypeLookup interop leg** (the service
was complete offline, its bytes frozen as self-pinned vectors) and the **external oracle for
the provisional minimal EquivalenceHash** (ADR 0009). Fast DDS was chosen over
Cyclone/OpenDDS because it is the one open peer implementing the standard TypeLookup
service (its dissection in tshark mirrors Fast DDS).

## Decision

Stand up a **pinned, natively built Fast DDS 3.6.1 toolchain** outside the repo
(`scripts/with-fastdds.sh`; test peer, not a code dependency — no SBOM entry, provenance in
`docs/provenance.md`) plus the **`interop/fastdds/` harness** (canonical `ShapeType.idl`
bound-aligned with our model — fastddsgen keeps `color` truly unbounded, unlike rtiddsgen's
silent 255 bound — fastddsgen 4.3.0 type support committed verbatim, thin RELIABLE pub/sub
mains, UDPv4-only profile so every byte is tshark-observable, TypeLookup pinned on via
`fastdds.type_propagation=enabled` since 3.x removed `<typelookup_config>`), and run the
staged live legs S0–S4. **FR-IO-2 is declared met** on the results below.

## Results (per stage; captures under `interop/fastdds/captures/`)

- **S0 — toolchain + harness** (`b56ac3a`, `5c6f0d1`): toolchain pinned + built;
  Fast DDS↔Fast DDS lo0 smoke green (48/50; first two pre-match under VOLATILE).
- **S1 — discovery census** (`410f190`): mutual SPDP/SEDP both directions. Their vendorId
  `01.0f`; SEDP carries 0x0075 (92 B, minimal + complete, EMHEADER1 LC=5,
  `dependent_typeid_count` −1); builtin-endpoint mask `0x0000fc3f` with all four Table-62
  TypeLookup bits; their EK_MINIMAL hash `bfe2a62ed811ac463c40c97d30ee` / size 87 for the
  same IDL **equals our provisional serializer's output** (`s1-forward-lo0.pcap`
  frs 236/237). Our LC=4 0x0075 was consumed (matched, 250/250 delivered).
- **S2 — data plane, the FR-IO-2 DoD** (`8ac0800`): dedicated bidirectional RELIABLE runs,
  tshark-validated. Forward `shapes_pub` → our subscriber **95/100** (sns 1–5 declared
  unavailable pre-match under VOLATILE via GAP of sn 5 + HEARTBEAT first=5, frs 50/51;
  zero post-match loss; payload fr 341 CDR_LE) and reverse our publisher → `shapes_sub`
  **250/250** incl. full pre-match recovery from sn 1 (payload fr 2420 CDR2_LE);
  HEARTBEAT/ACKNACK live on the user endpoints both directions (fwd 98 HB / 96 ACKNACK;
  rev 218 HB / 370 ACKNACK; 0 GAPs reverse, zero true retransmits forward)
  (`s2-forward-lo0.pcap`, `s2-reverse-lo0.pcap`).
- **Stability root causes fixed en route** (`6b5dd1b`): (1) Clasp's
  `gctools:deallocate-unmanaged-instance` GC_frees an interior pointer, corrupting a Boehm
  freelist on every static-vector free — worked around in `pal-clasp` by a lock-guarded
  exact-size recycle pool that never calls the broken deallocator (NFR-PORT gap until fixed
  upstream); (2) `dds.disc` `stop-node` freed the tx scratch buffers without joining the
  receiver threads that write into them (a 0xDD-canary shim caught the use-after-free on
  both implementations) — it now joins rx/mcast-rx threads before freeing.
- **S3 — EquivalenceHash externally confirmed** (`2b68ba1`): the live 92-octet 0x0075 value
  (frs 236/237; byte-identical in `s2-forward-lo0.pcap` fr 68) locked as the regression
  vector `fastdds-type-information-vector`; our ShapeType serializer reproduces the
  EK_MINIMAL hash + size 87 **byte-for-byte** — the first external oracle for the XCDR2
  MinimalTypeObject serializer + §7.3.4.9.1 hash, closing the ADR 0009 unconfirmed thread
  for the exercised path (FINAL struct + i32 + unbounded string8).
- **S4 leg A — our getTypes client vs their server** (`8b1e925`): `run-typelookup-probe`
  (`make fastdds-tl-probe`) PASS live — request fr 85, reply frs 86/87 of
  `s4-ourclient-lo0.pcap`; the returned TypeObject parses and re-hashes to the queried
  hash; our 24-char-prefix `instanceName` accepted (`REMOTE_EX_OK`).
- **S4 leg B vs stock Fast DDS** (`f1d3347`): the type-blind `type_probe` harness (no
  generated ShapeType linked; resolves the type via their own TypeLookup client +
  DynamicType) is proven end-to-end against an eProsima publisher (233 JSON samples).
  Against our publisher their client **can never fire** — the vendor gate (peer finding 2
  below); live run `s4-theirclient-lo0.pcap` (0x0075 delivered fr 389, callback reports
  `type_information.assigned=0`, zero TL DATA either direction).
- **S4 closeout — NON-STOCK diagnostic, clearly labeled** (`27ed6b5`): the one direction
  stock can never exercise (OUR `TypeLookup_Reply` consumed by THEIR client) was verified
  under a controller-approved **non-stock** local build with the SEDP vendor gate
  neutralized (one-line bypass in both `*ProxyData.cpp`; diff archived as
  `captures/s4-theirclient-patched-nonstock.diff`; the TypeLookup engine itself stayed
  stock): their client consumed our LC=4 0x0075 (`assigned=1`), sent getTypeDependencies
  (fr 2494) and getTypes (fr 2496), consumed both replies (frs 2495/2497), **built its
  DynamicType from our 87-octet MINIMAL TypeObject** (fr 2498) and took **600/600**
  RELIABLE samples (first user DATA fr 2500; `s4-theirclient-patched-lo0.pcap`). The stock
  build was restored, rebuilt and re-proven (`assigned=0`,
  `s4-theirclient-restored-probe.out`). **Never to be cited as a stock-peer result**; the
  stock verdict for leg B is the vendor-gate finding.
- **CONFIRM-VS-PEER walk closed** (walk table in `interop/fastdds/README.md`):
  **PEER-CONFIRMED** — (1) `instanceName` forms interop (our 24-char prefix hex accepted by
  their server; their 32-char full-GUID hex accepted by ours — the §7.6.3.3.4
  self-contradiction stands as a spec defect, both forms tolerated); (2) ReplyHeader
  `remoteEx` placement; (3) EMHEADER1 LC=5 NEXTINT-reuse (rule 22); (5) top-level `@final`
  ⇒ CDR2_LE `0x0007`, no top-level DHEADER; (6) Call/Return/Result union DHEADERs.
  **STILL-SELF-PINNED** — (4) the non-OK reply Return-arm omission (a live non-OK reply was
  never provoked; tshark-validated vector only), plus non-CDR2_LE encapsulations and the S3
  leftovers (complete-member emission; dependent-typeid insertion order).
- **Suites/gates:** 93 tests green on SBCL **and** Clasp (`GC_DONT_GC=1`; Clasp re-verified
  at the S4 boundary); `gate-types`, `gate-hotpath`, `make wire` green throughout.

### The three peer findings (Fast DDS 3.6.1)

1. **COMPLETE-reply latitude (conformant, fixed on our side):** queried for a MINIMAL
   TypeIdentifier, Fast DDS answers with the COMPLETE TypeObject keyed by the EK_COMPLETE
   TypeIdentifier plus the `complete_to_minimal` mapping — the XTypes 1.3 §7.6.3.3.4.2
   latitude our minimal-only client could not consume. Fixed failing-locked-vector-test-first
   (`fastdds-typelookup-reply-vector`, the 256-octet live reply from
   `s4-ourclient-run1-lo0.pcap` fr 61): `parse-type-lookup-reply` now parses
   `complete_to_minimal` and `dds.types:complete-to-minimal-type-object` reconstructs the
   MINIMAL model (NameHashes recomputed per §7.3.4.5; `@optional` details as `<is_present>`
   booleans per §7.4.3.5.2; unmappable members degrade `:unsupported`, fail-open); the pair
   is delivered only when the reconstruction's own hash equals the mapped hash — for
   ShapeType byte-identical to our own MinimalTypeObject.
2. **The SEDP vendor gate on 0x0075 (interop-hostile):** Fast DDS 3.6.1 unconditionally
   ignores `PID_TYPE_INFORMATION` from every non-eProsima vendorId
   (`WriterProxyData.cpp`/`ReaderProxyData.cpp`, "Ignore this PID when coming from other
   vendors"; no configuration disables it), so its TypeLookup client can never be triggered
   by a foreign announcement. Verified stock-live; the remaining direction was proven only
   under the clearly-labeled NON-STOCK diagnostic above.
3. **`json_serialize` NameHash defect (theirs, root-caused clean-room):**
   `DynamicTypeBuilderFactoryImpl::get_string_from_name_hash` (v3.6.1,
   `DynamicTypeBuilderFactoryImpl.cpp:1626`) streams raw `NameHash` `uint8_t` bytes through
   the `char` `operator<<` overload (`std::hex` inapplicable), producing non-UTF-8 member
   names from any MINIMAL TypeObject that their own JSON dumper then rejects
   (`type_error.316`). Data deserialization is unaffected (600/600 takes OK); not a framing
   defect on our side.

### The two findings fixed in our own stack

1. **LC=5 TypeInformation parsing:** `deserialize-type-information-hash` only consumed our
   own LC=4 emission; Fast DDS frames the mutable members with EMHEADER1 LC=5 (NEXTINT
   reused as the member's leading DHEADER, XTypes 1.3 §7.4.3.4.2). Fixed
   failing-test-first; both framings now accepted, our LC=4 emission unchanged (spec-legal;
   Fast DDS consumed it live).
2. **`cdr-get-string`/`cdr-get-sequence` pre-allocation hardening (NFR-SEC-POSTURE):** both
   now pre-validate the wire length/count against the remaining buffer extent (exported
   `dds.core.buffer:check-room`) BEFORE allocating the result — closing a
   reviewer-demonstrated remote heap-exhaustion (storage-condition escape) via a hostile
   `0xFFFFFFFF` length on the TypeLookup reply/request parse paths; locked by
   failing-first hostile cases in `xcdr-codec-roundtrip` and
   `fastdds-typelookup-reply-vector`.

## Consequences

- **FR-IO-2 is closed** (`docs/verification.csv` FR-IO row): bidirectional reliable shapes
  (S2, stock), EquivalenceHash + TypeInformation externally confirmed (S3, stock), the
  TypeLookup client leg live (S4 leg A, stock), and the server-reply leg live only under
  the labeled non-stock diagnostic — the stock/non-stock distinction travels with every
  citation of this result.
- **The TypeLookup vectors are peer-confirmed** except the non-OK Return-arm omission
  (never provoked live), non-CDR2_LE encapsulations, and the S3 leftovers — these stay
  self-pinned + tshark-validated (`typelookup-vectors`).
- **Connext remains the no-TypeLookup gold oracle** per ADR 0010: its type-compatibility
  gating runs on the legacy 0x8021 channel (ADR 0011); nothing here changes that split.
- **Cyclone DDS / OpenDDS stay optional** third vendors (FR-IO-2 needs ≥1; met). A peer
  without the vendor gate could exercise leg B stock with the harness unchanged.
- **Two upstream reports to eProsima are worth filing:** the SEDP vendor gate on 0x0075
  (defeats standard cross-vendor type discovery) and the `get_string_from_name_hash`
  non-UTF-8 member names. Both are documented with frame/line evidence above.
- Consumers: `docs/verification.csv` (FR-IO + FR-TYPE-3 rows), `docs/wiki/interop.md`,
  `README.md`, `docs/provenance.md`, `docs/MILESTONES.md` (M4 deferral resolved), the
  plan + spec (marked complete). Migration: none (docs-only closeout; no shipped behavior
  changed).
