# WP-DURABILITY-TRANSIENT-LOCAL Implementation Plan (M6 / P5)

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development. Steps use checkbox (`- [ ]`) syntax.

**Goal:** A TRANSIENT_LOCAL writer retains + replays its history to a late-joining TRANSIENT_LOCAL reader; a late-joining TRANSIENT_LOCAL reader requests + receives it; a VOLATILE reader gets only future samples. Plus an opt-in `durability-finalize`. Both sides, both impls, cross-DDS interop both directions.

**Architecture:** The DURABILITY QoS is already advertised/parsed/RxO-matched, and the reliable HEARTBEAT→ACKNACK→retransmit machinery already replays NACKed history. This WP adds (1) durability-aware retention (a TL writer doesn't full-ACK-purge), (2) durability-aware sequence-number init on both sides (writer proxy → firstSN for a TL reader; reader → firstSN if TL else lastSN+1), and (3) the opt-in finalize. The retention-duration *timer* is deferred (finalize is the v1 control).

**Tech Stack:** Common Lisp (SBCL + Clasp), `dds.rtps.reliable`/`dds.rtps.history`/`dds.disc`/`dds.dcps`, `defun*`/`defstruct*` + full types, the interop harness, tshark.

**Spec:** `docs/superpowers/specs/2026-06-18-wp-durability-transient-local-design.md` (read it).

**Conventions (NON-NEGOTIABLE):** one-line code comments; full type declarations; docstrings on new exported symbols (§5.1) citing DDS 1.4 §2.2.3.4 / RTPS 2.5 §8.4; the default (VOLATILE) path byte-identical; NO `#+sbcl/#+clasp` outside `dds-pal/`; NO AI-assistant/co-author attribution; clean-room; SBOM auto-staged; bench only if a hot-path number moves (it shouldn't — retention/replay is off the measured CDR path; assert `make mem` unaffected).

---

## Task 1: Writer-side durability-aware retention + late-joiner proxy-init

**Files:**
- Modify: `src/dds-rtps/reliable.lisp` — gate `writer-purge-acked` (~:220) on the writer's DURABILITY; add a durability-aware proxy-init (e.g. `init-reader-proxy-base writer reader-id base`, or extend `get-reader-proxy`); the `reader-proxy` struct (~:26) already has `unsent-base`.
- Modify: `src/dds-disc/dataplane.lisp` — the `writer-purge-acked` caller (~:1273); thread the writer's durability; on a TL-reader↔TL-writer match, set the new reader-proxy's `unsent-base = (hc-min-seq hc)` + trigger a HEARTBEAT.
- Modify: `src/dds-dcps/entities.lisp` — `%on-disc-match` / `%writer-matched` (~:1385-1393): thread the remote reader's durability (from `remote` endpoint-data-qos) + the writer's durability into the proxy-init.
- Need the writer's own durability: find where the writer's QoS lives (the disc-node user-writer's endpoint-data / the DataWriter QoS).
- Test: `src/dds-tests/` (where reliable/dataplane tests live) — writer-retention + writer-replays tests.

- [ ] **Step 1: Write the failing writer-retention test.** A TL writer (durability :transient-local) publishes N; simulate all current matched readers ACKing (drive `writer-purge-acked` / the ACKNACK path); assert the HC still holds the N samples (NOT purged). Contrast: a VOLATILE writer's HC purges to empty on full-ACK. Run → FAIL (purge is durability-blind today).
- [ ] **Step 2: Gate `writer-purge-acked` on durability.** VOLATILE → purge as today; TRANSIENT_LOCAL → do NOT full-ACK-purge (retention bounded by HISTORY: the existing KEEP_LAST `%hc-index-drop` per-instance eviction still applies; KEEP_ALL bounded by RESOURCE_LIMITS). Thread the writer's durability to the purge decision. Run Step-1 → pass.
- [ ] **Step 3: Write the failing writer-replays test.** A TL writer publishes N; a NEW reader matches (durability TL); assert the writer initializes that reader's proxy to `unsent-base = firstSN` (= `hc-min-seq`) AND the reader receives all N retained (drive the existing push/HEARTBEAT→NACK→retransmit; the test reader can be a loopback reader that NACKs the advertised range, OR assert the proxy base + that `%changes-from firstSN` / a triggered push sends all N). Run → FAIL.
- [ ] **Step 4: Durability-aware proxy-init at match.** In `%writer-matched` (or a new lower hook), when the matched remote reader is TRANSIENT_LOCAL AND the writer is TRANSIENT_LOCAL, pre-init that reader's proxy `unsent-base = (hc-min-seq writer-hc)` (replay all) + trigger a HEARTBEAT to it; else `unsent-base = lastSN+1` (future-only, today's effective behavior). Add the proxy-init entry point (get-reader-proxy takes no QoS today). Run Step-3 → pass.
- [ ] **Step 5: Both impls + commit.** `make test-sbcl` + `make test-clasp` green; `make mem` unaffected.
```bash
git add -A
git commit -m "feat(rtps): WP-DURABILITY-TRANSIENT-LOCAL writer retains for late-joiners + firstSN proxy-init on a TL match (M6/P5, DDS 1.4 §2.2.3.4)"
```

---

## Task 2: Reader-side durability gate + the our-to-our late-joiner slice

**Files:**
- Modify: the reader-side writer-proxy / NACK path (`src/dds-rtps/reliable.lisp` reader-side, or `src/dds-disc/` reader handling) — on matching a writer + the first HEARTBEAT, a TRANSIENT_LOCAL reader (matched a TL writer) expects from `firstSN` (NACK the full advertised range); a VOLATILE reader sets its expected base = `lastSN+1` (skip the history). Thread the reader's own durability + the matched writer's durability.
- Modify: `src/dds-dcps/entities.lisp` — `%reader-matched` (~:1388): thread durability into the reader-side init.
- Test: the our-to-our late-joiner end-to-end test (now both sides land).

- [ ] **Step 1: Write the failing our-to-our late-joiner test (the MVP slice).** A TL writer publishes N; THEN a TL reader joins; assert the late reader receives all N retained samples. AND a VOLATILE late reader receives 0 of the pre-existing N (only future-published). Run → the VOLATILE-skips part FAILS (today a late reader NACKs the advertised range regardless of durability → wrongly gets history).
- [ ] **Step 2: Reader-side durability gate.** On the first HEARTBEAT from a matched writer: a VOLATILE reader sets its writer-proxy expected base = `lastSN+1` (skip the advertised history, NACK only future gaps); a TRANSIENT_LOCAL reader (matched a TL writer) keeps the full-range NACK (request history). Run Step-1 → pass (TL gets all N; VOLATILE gets 0 of pre-existing).
- [ ] **Step 3: Per-instance KEEP_LAST retention test.** A TL KEEP_LAST(depth) writer; a late-joiner gets the last `depth` per instance (not the full history). Both impls.
- [ ] **Step 4: RxO + default regression.** A VOLATILE writer still does NOT match a TL reader (existing RxO unchanged); the VOLATILE→VOLATILE default path byte-identical; `make mem` unaffected.
- [ ] **Step 5: Both impls + commit.**
```bash
git add -A
git commit -m "feat(rtps): WP-DURABILITY-TRANSIENT-LOCAL reader-side history request (TL pulls firstSN, VOLATILE skips) — our-to-our late-joiner end-to-end (M6/P5)"
```

---

## Task 3: The `durability-finalize` extension (opt-in, on top)

**Files:**
- Modify: `src/dds-dcps/entities.lisp` (a `durability-finalize (dw)` DCPS function + export) + `src/dds-rtps/reliable.lisp` (a per-writer finalized flag consulted by `writer-purge-acked`).
- Test.

- [ ] **Step 1: Write the failing finalize test.** A TL writer publishes N; `durability-finalize`; the current readers ACK; assert the retained history is released (purged once ACKed); a subsequent TL late-joiner gets NOTHING of the pre-finalize history; samples published AFTER finalize behave VOLATILE. Run → FAIL.
- [ ] **Step 2: Implement.** `durability-finalize (dw)` sets a per-writer flag; `writer-purge-acked` treats a finalized TL writer as VOLATILE (full-ACK purge re-enabled). Docstring: cite this as a NON-STANDARD extension on top of the conformant default (DDS leaves TL lifetime to the durability service). Default off → standard TL. Run → pass.
- [ ] **Step 3: Both impls + commit.**
```bash
git add -A
git commit -m "feat(dcps): WP-DURABILITY-TRANSIENT-LOCAL durability-finalize — opt-in 'no more late-joiners' releases retained history (extension on top of standard TL)"
```

---

## Task 4: Cross-DDS interop (the per-feature DoD — both directions, live Connext + Fast DDS)

**Files:** Create `interop/durability-transient-local/README.md` + captures; reuse the shapes harness + the Connext/Fast DDS subs/pubs; a TRANSIENT_LOCAL config (the publisher/subscriber harness needs a DURABILITY=transient-local gate — add it, mirroring REP=/RELIABLE=). Do NOT commit vendor binaries.

- [ ] **Step 1: Our TL writer → a late-joining Connext + Fast DDS TL reader.** Start our TL reliable writer, publish N, THEN start the foreign TL subscriber; assert it receives the N RETAINED samples. tshark: our HEARTBEAT advertises [firstSN,lastSN], the foreign reader NACKs, we retransmit the history. Both peers.
- [ ] **Step 2: Our late-joining TL reader ← a Connext + Fast DDS TL writer.** The foreign TL writer publishes N first, THEN our TL reader joins; assert our reader receives the N history. A VOLATILE variant of our reader receives only post-join samples. Both peers.
- [ ] **Step 3: README + captures + commit.** Honest results per leg + direction; tshark evidence.
```bash
git add -A
git commit -m "test(interop): WP-DURABILITY-TRANSIENT-LOCAL late-joiner delivery LIVE both directions vs Connext + Fast DDS (M6/P5)"
```

---

## Task 5: Gates + docs (capstone)

**Files:** `docs/adr/0021-durability-transient-local.md` (new — next free ADR; confirm the number); `README.md`; `docs/wiki/` (a durability/QoS page — TRANSIENT_LOCAL semantics, the late-joiner mechanism, the `durability-finalize` API + the deferred timer); `docs/verification.csv`; `docs/provenance.md`.

- [ ] **Step 1: Full gate sweep, both impls.** `make build test corpus gate-types gate-hotpath mem fuzz` on SBCL + Clasp. Report each + totals. `make mem` 0.0000 (retention/replay is off the measured CDR path) — state NO bench warranted.
- [ ] **Step 2: ADR** — the decision record: TRANSIENT_LOCAL durability + late-joiner; durability-aware retention + the firstSN proxy-init both sides; the reliable-machinery reuse; the finalize extension (on top); TRANSIENT/PERSISTENT + the durability service are the FOLLOW-ON slices (now in-scope per ADR 0021), NOT this WP; LIFESPAN + the retention-duration timer remain deferred; the M6 exit gate.
- [ ] **Step 3: Docs lockstep (§5.1)** — README status (M6/P5 TRANSIENT_LOCAL landed); wiki API + worked example (a TL writer + a late-joining TL reader; `durability-finalize`); verification.csv (the retention + late-joiner both-sides tests + the live interop both directions); provenance (clean-room; DDS 1.4 §2.2.3.4).
- [ ] **Step 4: Commit.**
```bash
git add -A
git commit -m "docs(disc): WP-DURABILITY-TRANSIENT-LOCAL ADR/README/wiki/verification — TRANSIENT_LOCAL durability + late-joiner (M6/P5, §5.1)"
```

---

## Self-review notes (author)
- **Spec coverage:** T1 = writer retention + proxy-init (§Design 1,2); T2 = reader-side gate + the our-to-our slice (§Design 3); T3 = finalize (§Design 4); T4 = interop DoD (§Tests 6); T5 = gates + docs. All covered. The retention-duration timer is deferred (spec §4).
- **The MVP slice** (our-to-our TL late-joiner) is demonstrable after T1+T2; T1's writer-retention is the enabler, T2's reader-gate makes VOLATILE-vs-TL correct (without it a VOLATILE reader wrongly pulls history).
- **Reuse:** the existing HEARTBEAT/ACKNACK/retransmit does the replay; this WP only adds durability-aware retention + SN-init. No new wire submessages.
- **Type/naming consistency:** `unsent-base`/`acked-base` (reader-proxy); `hc-min-seq` = firstSN; durability keywords `:volatile`/`:transient-local`; `durability-finalize`.
- **Conformance:** default TL = conformant (retain for lifetime); finalize = opt-in extension on top. VOLATILE default byte-identical. RxO unchanged.
- **Open implementation note:** confirm where the writer's OWN durability is read (the disc-node user-writer's endpoint-data-qos vs the DataWriter QoS) — both T1 (purge + proxy-init) and T2 (reader gate) need the local + the matched-remote durability at the match layer.
