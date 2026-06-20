# Cross-vendor coexistence dedup — Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Make the durability service's no-double-delivery dedup recognize RTI Persistence Service's vendor per-sample origin so a dual-relay (our service + RTI PS) achieves cross-vendor exactly-once — a Connext-interop behaviour ON TOP of the conformant standard-OWI dedup, never replacing it.

**Architecture:** One logical-origin `(GUID, SN)` dedup key with multiple wire carriers (precedence: standard `PID_ORIGINAL_WRITER_INFO` 0x0061 → RTI vendor per-sample origin → native `(writerGUID, writerSN)`), feeding the existing per-origin watermark gate (`reader-dedup-accept-p`). Receiver-side recognition + emit-side stamping (additive, default-off). Spike-first: Task 1 decodes RTI's exact per-sample encoding on the live wire before the dedup specifics are committed.

**Tech Stack:** Common Lisp (SBCL + Clasp), the existing `dds-rtps` / `dds-disc` / `dds-durability` systems; tshark RTPS dissector + the `interop/durability-persistent/coexistence/` harness; RTI Connext 7.3.1 + RTI Persistence Service v7.3.1 + Fast DDS 3.6.1 (live peers, agent-run).

## Global Constraints

(Every task's requirements implicitly include these — verbatim from the spec + operating contract.)

- **Clasp AND SBCL both validate, Clasp run FIRST for tests** (NON-NEGOTIABLE); no skip without a documented NFR-PORT gap.
- **On-top-of-standard:** standard-OWI (0x0061) stays the primary, authoritative dedup source and proof; RTI-vendor recognition/emit is strictly additive; OWI precedence when both present; no conformant behaviour replaced.
- **Default-safe:** emit-side behind the existing default-off persistence-relay flag ⇒ byte-identical normal wire; receiver-side recognition inert unless an RTI vendor origin is present AND OWI absent.
- **Bounds-check every parser even at `(safety 0)`** (NFR-SEC-POSTURE); the new inbound vendor-PID parser gets a fuzz arm.
- **Clean-room (NFR-IP):** RTI's vendor encoding is reverse-engineered from the Task-1 capture + RTI-published spec only, never RTI source; constants pinned from the capture and cited; provenance logged in `docs/provenance.md`.
- **`defun*` / `defstruct*` for every fn/struct; full type declarations (FR-LANG-8); no reader conditionals outside `dds-pal/`.**
- **`make mem` stays 0.0000** (control-plane; no per-sample alloc on the measured path) → no bench warranted.
- **No AI / assistant attribution** in any repo file.
- **Cross-DDS interop per feature:** live proof both receiver directions + an our-stack authoritative test; tshark-validated; honest caveats documented.
- **Process:** commits autonomous within the branch `wp-durability-coexist-dedup`; HOLD PUSH; final whole-branch review → squash-merge presented for owner approval.

## Spike-gating & re-plan checkpoint

Task 1 is a SPIKE whose deliverable is `docs/superpowers/spikes/2026-06-20-rti-vendor-origin-findings.md` plus a pinned constants file `src/dds-rtps/rti-vendor-origin.lisp` (the vendor PID id(s), byte layout, and a captured byte vector) and a **Branch decision**:
- **Branch A** — RTI's per-sample virtual `(GUID, SN)` equals the original writer's real `(GUID, SN)`: receiver recognition alone suffices.
- **Branch B** — RTI's virtual identity is a distinct namespace: our service must additionally **adopt the virtual identity** when collecting from an RTI original (stamp our OWI with the virtual id) so both relays share one namespace.
- **Fallback** — no per-sample origin SN on RTI's wire: ship the honest second wire-dialect finding; the our-stack synthetic-relay test (Task 3) stays authoritative; no live exactly-once claim.

Tasks 3–6 reference the Task-1-pinned constants and the selected branch. **After Task 1, the controller updates Tasks 3–6 in this plan with the spike's concrete values before executing them.** Task 2 is spike-agnostic and proceeds regardless.

---

### Task 1: SPIKE — decode RTI's per-sample origin encoding on the live wire

**Files:**
- Create: `docs/superpowers/spikes/2026-06-20-rti-vendor-origin-findings.md` (the findings + Branch decision + pinned byte vector)
- Create: `src/dds-rtps/rti-vendor-origin.lisp` (pinned constants: PID id(s), offsets, lengths — values from the capture; loaded by `dds-rtps.asd` after `message.lisp`)
- Reuse: `interop/durability-persistent/coexistence/` (RTI_PS_TRANSIENT.xml, USER_QOS_PROFILES.xml, run-coexistence.sh, analyze-capture.py)
- Modify (extend, if tshark can't dissect the vendor PID): `interop/durability-persistent/coexistence/analyze-capture.py` (raw inline-QoS ParameterList byte walk)

**Interfaces:**
- Produces (for Tasks 3–6): in `src/dds-rtps/rti-vendor-origin.lisp` — `+pid-rti-virtual-guid+` (the per-sample vendor PID id), `+rti-virtual-origin-len+`, and a documented byte layout (GUID offset/len, virtual-SN offset/len), each cited to the capture; the findings doc's `Branch: A|B|fallback` line.

This is an investigation, not TDD — no code review (findings doc + pinned constants only). Acceptance is the crux question answered with wire evidence.

- [ ] **Step 1: Stand up the live RTI dual-relay.** An RTI/Connext TRANSIENT-durability writer on a topic (reuse the coexistence Shapes pub or `rtiddsgen`), RTI Persistence Service relaying it (the coexistence `RTI_PS_TRANSIENT.xml`), and our durability service collecting+relaying the same topic. Run via the coexistence harness on a free domain.

- [ ] **Step 2: Capture both relays' DATA + the original writer's DATA.** `tshark` with the RTPS dissector on loopback; save a `.pcap` under `interop/durability-coexist-dedup/spike/captures/`.

- [ ] **Step 3: Decode EVERY per-sample inline-QoS PID** on (a) the original RTI writer's DATA and (b) RTI PS's relayed DATA. Where tshark does not dissect an RTI vendor PID (0x80xx), extend `analyze-capture.py` to raw-walk the inline-QoS ParameterList and dump each (pid, len, bytes). Record: is there a per-sample virtual `(GUID, SN)` PID? its id + byte layout?

- [ ] **Step 4: Answer the crux.** Does RTI PS's relayed DATA carry the SAME virtual `(GUID, SN)` per sample as the original writer's DATA (proving it is RTI's cross-relay dedup key)? Does `virtualGUID/virtualSN == the original writer's real (GUID, SN)` (Branch A) or a synthetic namespace (Branch B)? Or is there no per-sample SN (fallback)?

- [ ] **Step 5: Pin the constants + a byte vector.** Write `src/dds-rtps/rti-vendor-origin.lisp` with `+pid-rti-virtual-guid+`, `+rti-virtual-origin-len+`, and the field offsets, each cited to the capture; capture one full inline-QoS value as a regression byte vector in the findings doc.

- [ ] **Step 6: Write the findings doc + Branch decision + commit.** `docs/superpowers/spikes/2026-06-20-rti-vendor-origin-findings.md` (evidence, the decoded layout, Branch A|B|fallback, provenance). Add the RTI-published-spec/source-of-understanding to `docs/provenance.md`.

```bash
git add src/dds-rtps/rti-vendor-origin.lisp dds-rtps.asd docs/superpowers/spikes/2026-06-20-rti-vendor-origin-findings.md docs/provenance.md interop/durability-coexist-dedup/spike/
git commit -m "spike(disc): WP-DURABILITY-COEXIST-DEDUP — decode RTI PS per-sample origin encoding (Branch A/B decision); pinned vendor-PID constants + byte vector (M6/P5, ADR 0026 §10)"
```

**RE-PLAN CHECKPOINT:** update Tasks 3–6 below with the pinned constant names/values + the selected Branch before executing Task 3.

---

### Task 2: Spike-agnostic refactor — single logical-origin extraction with a vendor seam

**Files:**
- Modify: `src/dds-disc/dataplane.lisp` (the dedup feed, ~1305–1335 — where `original-guid`/`original-sn` from `parse-inline-qos-key-status` are passed to `reader-dedup-accept-p`)
- Create: `src/dds-rtps/origin-key.lisp` (the `%logical-origin` precedence function; loaded after `message.lisp`)
- Modify: `dds-rtps.asd` (add `origin-key` component)
- Test: `src/dds-tests/durability-test.lisp` (a behavior-preserving unit test) + re-run `run-durability-no-double-delivery-test`

**Interfaces:**
- Produces: `dds.rtps.message:%logical-origin (owi-guid owi-sn vendor-guid vendor-sn native-guid native-sn) → (values guid sn)` — precedence OWI → vendor → native; returns the first non-NIL `(guid, sn)` pair. Tasks 3 fills `vendor-guid`/`vendor-sn` (NIL here).
- Consumes: the existing `parse-inline-qos-key-status` return (`original-guid`, `original-sn`).

- [ ] **Step 1: Write the failing test** (`origin-key-precedence` in durability-test.lisp): assert `%logical-origin` returns the OWI pair when OWI present; the native pair when OWI + vendor both NIL; the vendor pair when OWI NIL + vendor present.

```lisp
(defun* run-origin-key-precedence-test ()
    (function () t)
  "%logical-origin precedence: OWI > vendor > native."
  (let ((g-owi (make-array 16 :element-type '(unsigned-byte 8) :initial-element 1))
        (g-ven (make-array 16 :element-type '(unsigned-byte 8) :initial-element 2))
        (g-nat (make-array 16 :element-type '(unsigned-byte 8) :initial-element 3)))
    (multiple-value-bind (g s) (dds.rtps.message:%logical-origin g-owi 10 g-ven 20 g-nat 30)
      (%check :ok-owi (and (equalp g g-owi) (= s 10)) "OWI wins when present"))
    (multiple-value-bind (g s) (dds.rtps.message:%logical-origin nil nil g-ven 20 g-nat 30)
      (%check :ok-vendor (and (equalp g g-ven) (= s 20)) "vendor wins when OWI absent"))
    (multiple-value-bind (g s) (dds.rtps.message:%logical-origin nil nil nil nil g-nat 30)
      (%check :ok-native (and (equalp g g-nat) (= s 30)) "native is the fallback")))
  t)
```

- [ ] **Step 2: Run it (fails — `%logical-origin` undefined).** `make test-clasp` (or load dds-tests); expect FAIL.

- [ ] **Step 3: Implement `%logical-origin`** in `src/dds-rtps/origin-key.lisp` (`defun*`, full ftype, exported from `dds.rtps.message`):

```lisp
(defun* %logical-origin (owi-guid owi-sn vendor-guid vendor-sn native-guid native-sn)
    (function ((or null (simple-array (unsigned-byte 8) (*))) (or null integer)
               (or null (simple-array (unsigned-byte 8) (*))) (or null integer)
               (simple-array (unsigned-byte 8) (*)) integer)
              (values (simple-array (unsigned-byte 8) (*)) integer))
  "Logical-origin (GUID, SN) for dedup, by precedence: standard OWI (0x0061) > RTI vendor
   per-sample origin > native (writerGUID, writerSN). On-top-of-standard: OWI wins when present."
  (cond ((and owi-guid owi-sn) (values owi-guid owi-sn))
        ((and vendor-guid vendor-sn) (values vendor-guid vendor-sn))
        (t (values native-guid native-sn))))
```

- [ ] **Step 4: Wire it into the dedup feed** in dataplane.lisp — replace the direct `effective-guid`/`effective-sn` selection with `(%logical-origin original-guid original-sn nil nil writer-guid sn)` (vendor NIL until Task 3). Keep `reader-on-data` ALWAYS-run ordering intact.

- [ ] **Step 5: Run tests (Clasp first, then SBCL).** `make test-clasp && make test-sbcl`; the new test PASSES and `run-durability-no-double-delivery-test` + all existing dedup tests stay green (behavior-preserving).

- [ ] **Step 6: Commit.**

```bash
git add src/dds-rtps/origin-key.lisp dds-rtps.asd src/dds-disc/dataplane.lisp src/dds-tests/durability-test.lisp src/dds-tests/echo-test.lisp src/dds-tests/packages.lisp
git commit -m "refactor(disc): WP-DURABILITY-COEXIST-DEDUP — single %logical-origin precedence (OWI>vendor>native) at the dedup feed; behavior-preserving (M6/P5)"
```

---

### Task 3: Receiver-side recognition — parse RTI's per-sample origin + our-stack cross-vendor proof

**(Finalize from Task-1 findings: the `+pid-rti-virtual-guid+` constant + layout + Branch A/B.)**

**Files:**
- Modify: `src/dds-rtps/message.lisp` (`parse-inline-qos-key-status` — also extract the RTI vendor origin → return `vendor-guid`/`vendor-sn`); add `parse-rti-virtual-origin` (bounds-checked, mirrors `parse-original-writer-info`)
- Modify: `src/dds-disc/dataplane.lisp` (pass the parsed vendor origin into `%logical-origin`)
- Modify (Branch B ONLY): `src/dds-durability/service.lisp` (`%collect-loop` — when collecting from an RTI original carrying a virtual id, set the relay OWI to the virtual `(GUID, SN)`)
- Test: `src/dds-tests/durability-test.lisp` (the cross-vendor `no-double-delivery` arm + the parser unit test); `src/dds-tests/pbt-test.lisp` (a fuzz arm)

**Interfaces:**
- Consumes: `+pid-rti-virtual-guid+`, `+rti-virtual-origin-len+`, the layout (Task 1); `%logical-origin` (Task 2).
- Produces: `parse-rti-virtual-origin (octets offset len) → (values guid sn)` or `(values nil nil)`; `parse-inline-qos-key-status` extended return `(... vendor-guid vendor-sn)`.

- [ ] **Step 1: Write the failing parser test** — `parse-rti-virtual-origin` on a pinned valid vector → the expected `(guid, sn)`; on `len /= +rti-virtual-origin-len+` / OOB / short → `(values nil nil)` (fail-closed), incl. a `(safety 0)` twin (the bounds check is an explicit manual check). Use the Task-1 byte vector.

- [ ] **Step 2: Run it (fails).** Clasp first; expect FAIL.

- [ ] **Step 3: Implement `parse-rti-virtual-origin`** (`defun*`, full ftype, bounds-checked even at `(safety 0)`, mirroring `parse-original-writer-info` message.lisp:800) and call it from `parse-inline-qos-key-status` for `+pid-rti-virtual-guid+`; thread `vendor-guid`/`vendor-sn` through to the `%logical-origin` call in dataplane.lisp.

- [ ] **Step 3b (Branch B ONLY):** in `%collect-loop`, when the collected sample carries an RTI virtual id, stamp the relay's OWI with the virtual `(GUID, SN)` (so our relay and RTI PS share the namespace). Skip entirely under Branch A.

- [ ] **Step 4: Write the cross-vendor `no-double-delivery` arm** — extend `run-durability-no-double-delivery-test` (durability-test.lisp:1013) with a SYNTHETIC RTI-style stand-in relay that publishes the same N samples carrying the RTI vendor origin encoding (NO OWI) alongside our standard-OWI relay; the our-stack late-joiner reader must deliver exactly N (not 2N). This is the AUTHORITATIVE cross-vendor proof.

- [ ] **Step 5: Write the fuzz arm** (pbt-test.lisp) — random/short/oversized/off-end octets into `parse-rti-virtual-origin` + an inline-QoS blob walk carrying a forged vendor PID ⇒ NIL or a correct parse, never OOB, prod + `(safety 0)`.

- [ ] **Step 6: Run all (Clasp first, then SBCL) + gates.** `make test-clasp && make test-sbcl && make gate-hotpath && make gate-types && make mem && make fuzz`; all green; mem 0.0000.

- [ ] **Step 7: Commit.**

```bash
git add src/dds-rtps/message.lisp src/dds-disc/dataplane.lisp src/dds-durability/service.lisp src/dds-tests/durability-test.lisp src/dds-tests/pbt-test.lisp
git commit -m "feat(disc): WP-DURABILITY-COEXIST-DEDUP — recognize RTI per-sample virtual origin in dedup (additive, OWI-primary); our-stack cross-vendor no-double-delivery arm + bounds-checked+fuzzed parser (M6/P5, ADR 0026 §10)"
```

---

### Task 4: Receiver-side LIVE proof (or the honest finding)

**Files:**
- Create: `interop/durability-coexist-dedup/` (driver(s), run script, README, captures) — model on `interop/durability-persistent/coexistence/`

- [ ] **Step 1:** Stand up the live dual-relay: an RTI TRANSIENT writer → RTI PS **and** our durability service → an our-stack late-joiner reader, all same topic/domain.
- [ ] **Step 2:** Drive N samples; capture with tshark; assert the our-stack reader delivered exactly N (cross-vendor dedup collapsed the two relays).
- [ ] **Step 3:** Record wire evidence + honest caveats (e.g. macOS `lo0` quirk) in `interop/durability-coexist-dedup/README.md`. **If the spike's fallback held** (no per-sample SN), this step instead documents the second wire-dialect finding; the Task-3 our-stack arm remains authoritative.
- [ ] **Step 4: Commit** (`test(interop): ... receiver-side live cross-vendor exactly-once vs RTI PS (or honest finding)`).

---

### Task 5: Emit-side — our relay stamps RTI-compatible per-sample origin

**(Finalize from Task-1 findings: the emit byte layout + the existing persistence-relay flag name.)**

**Files:**
- Modify: `src/dds-rtps/message.lisp` (a `write-rti-virtual-origin` inline-QoS writer, mirroring the OWI writer) + `src/dds-disc/dataplane.lisp` (write-data inline-QoS: add the vendor origin when the persistence-relay flag is set)
- Modify: `src/dds-durability/service.lisp` (the relay writer already sets the persistence-relay vendor SEDP PIDs; gate the per-sample emit on the same flag)
- Test: `src/dds-tests/durability-test.lisp` (byte-pin the emitted inline-QoS vs the Task-1 vector; default-off ⇒ byte-identical wire)

- [ ] **Step 1: Failing test** — with the flag ON, the relayed DATA's inline-QoS contains the RTI vendor origin byte-identical to the Task-1 vector (for given `(virtualGUID, virtualSN)`); with the flag OFF (default), the wire is byte-identical to today (no vendor origin PID).
- [ ] **Step 2: Run (fails).** Clasp first.
- [ ] **Step 3: Implement** `write-rti-virtual-origin` + the gated emit (additive to OWI, never replacing; default-off).
- [ ] **Step 4: Run tests + gates (Clasp first, then SBCL).** Green; mem 0.0000; default path byte-identical (mutation-proven).
- [ ] **Step 5:** Live emit-side proof: a Connext late-joiner reader dedups our-relay (vendor-emitting) + RTI-PS → exactly-once; tshark-validated under `interop/durability-coexist-dedup/`. (Or the honest finding.)
- [ ] **Step 6: Commit** (`feat(disc): ... emit-side RTI-compatible per-sample origin (additive, default-off) + live Connext-reader dedup proof`).

---

### Task 6: Capstone — ADR, docs lockstep, gate sweep, final review

**Files:**
- Create: `docs/adr/0027-durability-coexist-dedup.md`
- Modify: `docs/wiki/durability.md` (§6.4 / §8.6 — the coexistence finding updated to "now exercisable"; the new vendor-recognition behaviour + default-off emit), `README.md` (P5 row), `docs/verification.csv` (a P5-COEXIST-DEDUP row)
- Modify: `docs/adr/0026-durability-persistent.md` (§10 item 1 → "landed in ADR 0027")

- [ ] **Step 1:** Write ADR 0027 (as-built: the precedence chain, the RTI vendor encoding + Branch A/B chosen, additive/default-safe, the spike finding, the live results or the honest finding, §followups).
- [ ] **Step 2:** Docs lockstep — wiki + README + verification.csv; docstrings on every new exported symbol/constant citing the capture-pinned clause; provenance current.
- [ ] **Step 3:** Full gate sweep BOTH impls (Clasp first): `make test-clasp && make test-sbcl && make gate-hotpath && make gate-types && make mem && make fuzz && make wire`; all green.
- [ ] **Step 4: Commit** the capstone (`docs(durability): WP-DURABILITY-COEXIST-DEDUP — ADR 0027 + wiki/README/verification capstone (M6/P5)`).
- [ ] **Step 5 (controller):** final whole-branch review (review agents over `main..HEAD`) → fix → squash-merge presented for owner approval, HOLD PUSH.

---

## Self-review (against the spec)

- **Spec coverage:** spike-first (Task 1) ✓; receiver-side recognition (Task 3) ✓; receiver-side live (Task 4) ✓; emit-side both build + live (Task 5) ✓; honest-finding fallback (Tasks 1/3/4 fallback branches) ✓; approach #1 unified key (Task 2 `%logical-origin`) ✓; conformance/safety (Global Constraints + Task 3 bounds+fuzz, Task 5 default-off) ✓; DoD authoritative our-stack arm (Task 3) + live both directions (Tasks 4–5) ✓; ADR/docs (Task 6) ✓.
- **Placeholders:** the spike-dependent specifics are named constants pinned by Task 1 (not TBDs) + an explicit Branch A/B fork + a re-plan checkpoint — the honest structure for a spike-first WP, not a content punt.
- **Type consistency:** `%logical-origin` (Task 2) signature is reused verbatim in Task 3's wiring; `parse-rti-virtual-origin` mirrors `parse-original-writer-info`'s `(values guid sn)` contract; `+pid-rti-virtual-guid+` / `+rti-virtual-origin-len+` named consistently across Tasks 1/3/5.

---

## RE-PLAN (post-spike, 2026-06-20 — premise OVERTURNED, Branch A; owner-approved re-scope)

Task 1's spike (controller-verified — independently re-decoded C1: 0x0061 on RTI PS relay, 1085 origins) found **RTI PS v7.3.1 emits the OMG-STANDARD `PID_ORIGINAL_WRITER_INFO` (0x0061)** — original writer's real `(GUID, SN)`, same PID/namespace/24B-LE layout — on its **retained-history REPLAY to a late-joiner**. That is exactly what our existing dedup (`reader-dedup-accept-p`, ADR 0024) consumes and what our relay already emits. So **cross-vendor dual-relay exactly-once vs RTI PS already works via the standard path, BOTH directions — there is NO vendor per-sample PID to recognize or emit.** The Phase-3b "ZERO OWI" finding was the live-forward path only (over-generalized from a flaky-late-joiner capture).

**Original Tasks 2–6 are SUPERSEDED** (the `%logical-origin` vendor seam, the vendor parse, the vendor emit — all dead code against a disproven premise). **No production-code change is required.** The owner approved the honest re-scope: correct the wrong finding + deliver the live proof + an explicit our-stack confirmation. Re-scoped tasks (briefs hand-authored under `.superpowers/sdd/`):

- **Task 2 (re-scoped): Live dual-relay exactly-once proof (both directions).** Promote the spike's `interop/durability-coexist-dedup/spike/` into a reliable coexistence harness: an RTI Connext TRANSIENT writer → RTI PS + our durability service; a late-joiner reliably discovers RTI PS **after the publisher exits** (the 0x0061 replay episode) with our relay also present (also 0x0061); assert the receiver delivers exactly N (dedup collapses the two 0x0061 streams). Direction (a): our-stack reader as receiver. Direction (b): a Connext reader as receiver (proves our standard-OWI emit is consumed by RTI's own dedup). tshark-validated; README + captures; honest caveats (lo0/DLT_NULL).

- **Task 3 (re-scoped): our-stack N-relay dedup confirmation.** Extend `run-durability-no-double-delivery-test` with a TWO-RELAY arm (publisher + our relay + a second relay, both stamping the same `(origGUID, origSN)` via OWI) → the our-stack reader delivers exactly N. Proves the receiver dedup is relay-count-agnostic — the cross-vendor property reduced to its essence (RTI PS is just another standard-OWI relay). Deterministic both impls.

- **Task 4 (re-scoped): capstone.** Correct the finding in ADR 0026 (§Threat-model/coexistence + §10 item 1 → landed), README P5 row, wiki §6.4/§8.6 — RTI PS emits standard OWI on the retained-history replay path; cross-vendor exactly-once works via standard OWI, both directions. Write ADR 0027 (as-built: standard-OWI cross-vendor dedup; corrected finding; live proof; the spike). `verification.csv` row. Full gate sweep both impls. Final whole-branch review → squash-merge presented for owner approval (HOLD PUSH).

---

## RE-PLAN 2 (post-Task-2 live finding, 2026-06-20 — owner chose INVEST)

Task 2's live attempt (controller-verified by re-decoding the dir-b capture) found a live cross-vendor dual-relay exactly-once is **blocked** by: **(B1)** our relay is TRANSIENT_LOCAL-only (rank 1); RTI PS replays its full retained history only to a TRANSIENT reader (rank 2) → no single receiver matches both; **(B2)** in the run the two relays stamped *different* origin GUIDs (our relay `010176…:80000002`, RTI PS `0101b87e…:80000002`) — most likely the harness drove two separate Connext publisher instances (both origins are Connext writer GUIDs; our `%collect-loop` records `node-sample-writer-guid` faithfully). **Confirmed** (corrects both subagents): RTI PS emits standard `0x0061` carrying the original Connext publisher's REAL GUID on replay. The owner chose to **INVEST**: add a TRANSIENT relay tier (a real, semantically-correct capability — a durability *service* relay should advertise TRANSIENT) + resolve B2 + prove live. The re-scoped Tasks 2–4 above are SUPERSEDED by:

- **Task 2 (production): configurable TRANSIENT relay tier.** The durability service's replay writer advertises a configurable DURABILITY — **default `:transient-local` (byte-identical to today)**, opt-in `:transient` via the service-spec. A TRANSIENT receiver then matches our relay (RxO). TDD: the relay writer advertises the configured tier; default byte-identical (mutation-proven); the existing retention/replay machinery is unchanged. Files: `src/dds-durability/service.lisp` (`%build-disc-node` relay-writer QoS + the service-spec option), `src/dds-durability/spec.lisp`.

- **Task 3 (live proof + B2 resolution): one-publisher dual-relay, both directions.** The harness drives ONE Connext TRANSIENT publisher; RTI PS + our service (now `:transient` relay) both relay it; **verify BOTH stamp the SAME origin `(GUID, SN)`** (resolves B2 — if our relay still diverges after one-publisher wiring, it is a collect bug → fix it in `%collect-loop`). Direction (a) our-stack reader → exactly N; direction (b) a Connext reader → exactly N. tshark-validated; `interop/durability-coexist-dedup/`.

- **Task 4: our-stack N-relay dedup confirmation arm.** (As re-scoped Task 3 above — extend `run-durability-no-double-delivery-test` with a two-`0x0061`-relay arm; deterministic both impls.)

- **Task 5: capstone.** Correct the Phase-3b/ADR-0026 finding; ADR 0027 (as-built: standard-OWI cross-vendor dedup + the TRANSIENT relay tier + the live proof both directions + the spike); README/wiki/verification; full gate sweep both impls; final whole-branch review → squash-merge presented for owner approval (HOLD PUSH).
