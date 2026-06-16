# WP-KEEPLAST (per-instance KEEP_LAST) Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: superpowers:subagent-driven-development. Steps use checkbox (`- [ ]`).

**Goal:** Make HISTORY `KEEP_LAST` depth apply per-instance on both the writer HistoryCache and the reader DCPS cache (DDS 1.4 §2.2.3.18), honor the configured HISTORY QoS (today ignored), and wire the GAP path (send + receive) so a reliable reader NACKing an evicted SN gets a GAP not silence (RTPS 2.5 §8.3.7.4).

**Architecture:** Build the per-instance machinery first and unit-test it at the engine level WHILE the DCPS writer still constructs a KEEP_ALL HistoryCache (so the integration suite stays green per task). Then activate (writer HC + reader cache honor QoS), which flips the default to the spec generic KEEP_LAST-1, and migrate the existing multi-sample/late-joiner tests to explicit KEEP_ALL in the SAME task so no task boundary is red.

**Tech Stack:** Common Lisp (SBCL + Clasp). `dds.rtps.history` (the HC + per-instance index), `dds.rtps.reliable` (writer-write / writer-on-acknack / reader-on-gap), `dds.disc` (publish-sample, %on-user-acknack GAP send, the reader datagram dispatch), `dds.dcps` (write-sample keyhash, %drain-one-sample reader depth), `dds.qos` (history-kind/depth — already present).

**Authoritative spec:** `docs/superpowers/specs/2026-06-16-wp-keeplast-perinstance-design.md` (the model + the 8 scenarios + the decisions). **Conventions:** `defun*` + `defstruct*` + full ftype (every param + return typed, FR-LANG-8); one-line code comments only (rationale in commit messages); cite the spec clause for any wire constant, verify against the existing GAP codec — never hardcode from memory; bounds-check the GAP parser even at `(safety 0)`; no reader conditionals outside `dds-pal/`; SBOM auto-staged by the pre-commit hook; **no AI-assistant / co-author / Generated-with attribution** in any repo file or commit; **NOT R6** (standard QoS — no default-off flag, no SBCL-only); both impls green (or a documented Clasp NFR-PORT gap); present each commit message for owner approval before committing.

## Verified grounding (file:line — from the design spec)
- `history.lisp:7-20` `cache-change` has `instance-key-hash` (16 octets, nullable). `history.lisp:123-140` `hc-add-change` KEEP_LAST evicts the GLOBAL lowest SN (`%hc-evict-oldest`); `history.lisp:25` flags per-instance as a follow-up. `history.lisp:46` `make-history-cache (kind depth ...)`.
- `reliable.lisp:122-132` `writer-write (writer payload)` → `%writer-add-bounded` with `(lambda (sn) (make-cache-change :sn :serialized-payload))`. `reliable.lisp:189-207` `writer-on-acknack` → `(values resends gaps)`. `reliable.lisp:317-326` `reader-on-gap` (EXISTS, unwired). `reliable.lisp:209-229` `writer-purge-acked`.
- `dataplane.lisp:1235` writer HC hard-coded `make-history-cache :keep-all 1`. `dataplane.lisp:1137-1167` `%on-user-acknack` `(declare (ignore gaps))` — GAP never sent; resends use the per-NACKing-reader destination (`%prefix-user-destination`). `message.lisp:353` `write-gap` (EXISTS). `message.lisp:364-375` `parse-gap-body` (EXISTS).
- `disc.lisp:950-972` reader datagram dispatch — NO `+submsg-gap+` case.
- `entities.lisp:427-442` `write-sample` (has the live sample + type-support). `entities.lisp:448` `%instance-handle ts sample` (HANDLE_NIL shared constant for unkeyed → no alloc). `entities.lisp:1049` `%drain-one-sample` computes `handle` per data sample + stores it in sample-info; `entities.lisp:527` `%resource-reject-reason` (the existing O(N) per-instance count — the reader cache shape to match). `qos.lisp:125` history defaults `:keep-last` depth 1.

## File structure
- **Modify:** `src/dds-rtps/history.lisp` (per-instance index + `%hc-remove-change` + per-instance eviction), `src/dds-rtps/reliable.lisp` (`writer-write` keyhash param; route purge/dispose removal through `%hc-remove-change`), `src/dds-disc/dataplane.lisp` (writer HC honors QoS; `publish-sample` keyhash param; `%on-user-acknack` GAP send), `src/dds-disc/disc.lisp` (reader `+submsg-gap+` dispatch), `src/dds-dcps/entities.lisp` (`write-sample` keyhash; reader per-instance drop in `%drain-one-sample`).
- **Create:** `docs/adr/0019-perinstance-keeplast.md`.
- **Test:** `src/dds-tests/integration-test.lisp` + `src/dds-tests/echo-test.lisp` (+ register in `run-all-tests`).
- **Docs:** ADR 0019, README, `docs/wiki/`, `docs/verification.csv`, `docs/provenance.md`. **Bench:** `bench/report/2026-06-16-wp-keeplast.md` (if the keyed-write path benches as changed).

---

# Phase A — HistoryCache per-instance KEEP_LAST eviction (engine-level; engine default unchanged → suite green)

### Task A1: per-instance index + `%hc-remove-change` + per-instance eviction
**Files:** Create `docs/adr/0019-perinstance-keeplast.md`; Modify `src/dds-rtps/history.lisp`, `src/dds-rtps/reliable.lisp`.
- [ ] **ADR 0019 (Proposed):** the per-instance KEEP_LAST model (writer HC honors QoS kind/depth; per-instance eviction; the default flip KEEP_ALL→KEEP_LAST-1 + migration; the keyhash threading param; the GAP send/receive activation; reader-side depth). Status finalized in Phase E. List consumers of the contract change (Task B1): `dds.disc:publish-sample`, `dds.rtps.reliable:writer-write`.
- [ ] **Failing tests** (engine-level, register in `run-all-tests`, match the existing history.lisp test style): `run-hc-perinstance-keeplast-test` — `(make-history-cache :keep-last 2)`; add 3 `:data` changes for instance A (distinct SNs, `:instance-key-hash` = a 16-octet A-handle) and 3 for instance B; after each add assert per-instance retention; final: the HC holds exactly the last 2 SNs of A AND the last 2 of B (4 changes), NOT a global last-2. `run-hc-keeplast-unkeyed-test` — changes with `:instance-key-hash nil` (or HANDLE_NIL) collapse to ONE instance → global last-`depth`. `run-hc-remove-change-consistency-test` — `%hc-remove-change` on an arbitrary SN removes it from BOTH `changes` and the per-instance index; the index has no orphaned SN; re-adding works.
- [ ] **Implement:** add `(instances (make-hash-table :test 'equalp) :type hash-table)` to the `history-cache` defstruct (`keyhash → list of SNs, oldest-first`; HANDLE_NIL/nil → a single shared bucket key). Add `%hc-remove-change (hc sn)`: look up the change, drop `sn` from `changes` AND from its instance bucket, decrement count. Rewrite the KEEP_LAST branch of `hc-add-change`: store the change, push its SN to the tail of `instances[keyhash]`; if that bucket's length > depth, `%hc-remove-change` the bucket's head (the instance's oldest). Route `%hc-evict-oldest` (global, now only the unkeyed/degenerate path), `writer-purge-acked`, and any dispose-removal through `%hc-remove-change` so the index never drifts. Keep `make-history-cache` signature unchanged (still `kind depth`). `defun*` + full ftype.
- [ ] **Run:** `run-hc-*` pass SBCL + Clasp. Full suite green both impls (the engine still constructs `:keep-all` at `dataplane.lisp:1235`, so integration is unaffected — confirm count unchanged from 211). `make gate-types` + `gate-hotpath` PASS.
- [ ] **Commit** (present message first): `feat(rtps): WP-KEEPLAST per-instance KEEP_LAST eviction in the HistoryCache — keyhash->SN index + single %hc-remove-change (DDS 1.4 §2.2.3.18) + ADR 0019`

---

# Phase B — keyhash on data changes (threading; inert under the KEEP_ALL engine → green)

### Task B1: thread the instance handle DCPS → publish-sample → writer-write → cache-change
**Files:** Modify `src/dds-rtps/reliable.lisp`, `src/dds-disc/dataplane.lisp`, `src/dds-dcps/entities.lisp`.
- [ ] **Failing test** `run-keeplast-keyhash-threaded-test` (integration): a keyed writer writes a sample; assert the change landed in the writer HC carries the correct `instance-key-hash` (= the type-support keyhash of the sample); an unkeyed writer's change carries HANDLE_NIL (the shared constant — assert `eq` to `+instance-handle-nil+`, proving no per-sample alloc).
- [ ] **Implement:** `writer-write` gains `&optional (key-hash nil)`, passed into the `make-cache-change` lambda as `:instance-key-hash key-hash` (and `%writer-add-bounded`'s builder threads it). `dds.disc:publish-sample` gains `&optional (key-hash nil)`, passed to `writer-write`. DCPS `write-sample` computes `(%instance-handle (topic-type-support (dw-topic dw)) sample)` and passes it to `publish-sample`. NIL default = byte-identical to today. Update ADR 0019's contract-change section. `defun*` + ftype on the changed signatures; one-line comments.
- [ ] **Run:** the test passes; full suite green both impls (still inert — the engine HC is keep-all so the populated keyhash is not evicted-on yet; count unchanged). `gate-types`/`gate-hotpath` PASS. **`make mem` PASS** — confirm the keyed-write keyhash does not regress the measured 0-alloc workload (if it does, add a 0-alloc `key-hash-<name>-into (sample buf)` codegen variant in `dsl.lisp` and reuse a per-change buffer; decide by the gate result, not assumption).
- [ ] **Commit:** `feat(rtps,disc,dcps): WP-KEEPLAST thread instance keyhash onto data CacheChanges (additive param, ADR 0019)`

---

# Phase C — the GAP, both directions (latent-bug fix; gaps only occur on a real hole → green)

### Task C1: send the GAP in `%on-user-acknack`
**Files:** Modify `src/dds-disc/dataplane.lisp`.
- [ ] **Failing test** `run-gap-send-on-missing-sn-test`: a RELIABLE writer whose HC is missing an SN (force it: a `:keep-all` writer with RESOURCE_LIMITS max_samples that evicts the lowest, OR purge-acked a low SN, then) receives an ACKNACK NACKing that SN → assert a GAP submessage is emitted to the NACKing reader (inspect the sent datagram / a send hook), covering exactly the missing SN(s).
- [ ] **Implement:** in `%on-user-acknack`, stop `(declare (ignore gaps))`; for the non-empty `gaps` SN list build a GAP via `dds.rtps.message:write-gap` (cite §8.3.7.4 + §9.4.5.6 in a one-line comment; reuse the existing builder — do not re-derive the layout) and send it to the NACKing reader using the same `%prefix-user-destination` path the resends use. Bounds/validity: build the SN-set from the gap list using the existing seqnum-set helpers.
- [ ] **Run:** test passes; full suite green both impls (the default keep-all-unlimited path produces no gaps, so existing tests are unaffected). Commit: `fix(disc): WP-KEEPLAST send the GAP that %on-user-acknack computed-but-ignored — reliable reader gets a GAP not silence (RTPS 2.5 §8.3.7.4)`

### Task C2: reader GAP reception (wire the existing handler)
**Files:** Modify `src/dds-disc/disc.lisp`.
- [ ] **Failing test** `run-reader-gap-reception-test`: a reader with a missing SN (writer-proxy) receives a GAP for it → assert the SN is marked `:gap` in the writer-proxy received table, the reader no longer NACKs it, and the ACK watermark advances (no hang); a subsequent HEARTBEAT does not re-trigger a NACK for the GAP'd SN.
- [ ] **Implement:** add a `((= id +submsg-gap+) ...)` case to the datagram dispatch (`disc.lisp:950-972`) that calls `dds.rtps.message:parse-gap-body` then `dds.rtps.reliable:reader-on-gap` for the matching user reader (mirror the HEARTBEAT/ACKNACK cases). Bounds-check the parsed GAP against the submessage body extent even at `(safety 0)`.
- [ ] **Run:** test passes; full suite green both impls. Commit: `feat(disc): WP-KEEPLAST wire reader +submsg-gap+ dispatch to the existing reader-on-gap (RTPS 2.5 §8.3.7.4)`

---

# Phase D — activate (honor QoS both sides) + flip default + migrate (atomic; the disruptive phase)

### Task D1: activate + migrate (one atomic task — ends green)
**Files:** Modify `src/dds-disc/dataplane.lisp` (writer HC from QoS), `src/dds-dcps/entities.lisp` (reader per-instance drop), plus the migrated tests/harnesses.
- [ ] **Step 1 — activate the writer:** replace `make-history-cache :keep-all 1` (`dataplane.lisp:1235`) with the writer's QoS `history-kind` + `history-depth`. (Trace the QoS to this construction point; pass kind+depth.)
- [ ] **Step 2 — activate the reader:** in `%drain-one-sample`, after computing `handle`, when the reader QoS is `:keep-last` and instance `handle` already holds `history-depth` samples in `dr-cache`, drop that instance's oldest (lowest-SN) cached-sample BEFORE appending (a lossy KEEP_LAST drop — distinct from the RESOURCE_LIMITS reject; retire the dropped sample's bookkeeping consistently). O(N) scan matching `%resource-reject-reason`.
- [ ] **Step 3 — run the suite + triage:** run the full suite both impls. The default is now KEEP_LAST-1. For EACH failure, classify: a multi-sample-then-read, late-joiner, burst-faster-than-drain, or HC-size-introspection test that depended on KEEP_ALL retention.
- [ ] **Step 4 — migrate:** set those entities (tests, `square-pub`, any interop harness) to explicit KEEP_ALL (or a sufficient depth) via QoS — the conformant fix, NOT reverting the default. Re-run until green both impls. Record the migrated set in the commit body + ADR 0019.
- [ ] **Commit** (present message — it will list the migrated tests): `feat(disc,dcps): WP-KEEPLAST honor QoS HISTORY (writer HC + reader cache) — default now spec KEEP_LAST-1; migrate retention-dependent tests to explicit KEEP_ALL (DDS 1.4 §2.2.3.18, ADR 0019)`

### Task D2: end-to-end per-instance scenarios (spec scenarios 1-7 on the activated path)
**Files:** `src/dds-tests/integration-test.lisp` (+ `run-all-tests`).
- [ ] `run-keeplast-writer-perinstance-e2e-test` (spec §1): KEEP_LAST depth 2 keyed writer; write 3×A + 3×B; assert the writer HC retains last 2 of A AND last 2 of B.
- [ ] `run-keeplast-interior-hole-gap-e2e-test` (spec §2): KEEP_LAST depth 1, keyed, RELIABLE; write A@1, B@2, B@3 (SN2 evicted, interior hole); a reader that missed SN2 NACKs → the writer sends a GAP for SN2 → the reader marks `:gap`, stops NACKing, the ACK advances (no hang). Use `*debug-drop-sample-numbers*` to create the miss if needed.
- [ ] `run-keeplast-firstsn-advance-test` (spec §3): KEEP_LAST depth 1; write A@1, A@2 (SN1 evicted); assert the HEARTBEAT firstSN advanced to SN2 and the reader does not NACK SN1.
- [ ] `run-keeplast-reader-perinstance-e2e-test` (spec §4): KEEP_LAST depth 2 reader; deliver 3×A + 3×B; assert `dr-cache` holds the last 2 of EACH instance.
- [ ] `run-keeplast-unkeyed-collapse-test` (spec §5) + `run-keeplast-keepall-regression-test` (spec §6): unkeyed KEEP_LAST = global last-N; a KEEP_ALL writer+reader behaves exactly as before activation.
- [ ] `run-keeplast-reliability-composition-test` (spec §7): purge-acked + per-instance eviction co-exist via `%hc-remove-change` (a fully-acked change purged; an over-depth change evicted; no orphaned index entry; no double-free).
- [ ] **Run:** all pass both impls; full suite green; report the new test count. Commit: `test(disc): WP-KEEPLAST end-to-end per-instance KEEP_LAST + interior-hole GAP + reliability-composition scenarios (DDS 1.4 §2.2.3.18, RTPS 2.5 §8.3.7.4)`

---

# Phase E — gates, bench, docs

### Task E1: full gate sweep + bench + docs
- [ ] **Gates:** `make build test corpus gate-types gate-hotpath fuzz mem` green both impls (or a documented Clasp NFR-PORT note). If the keyed-write path changed allocation, **bench** write throughput + bytes/sample before/after (FR-LANG-7) → `bench/report/2026-06-16-wp-keeplast.md` (honest; the keyhash + per-instance eviction cost).
- [ ] **Docs (§5.1 lockstep):** ADR 0019 final (as-built — the index, `%hc-remove-change`, the QoS-honor + flip + migrated set, the GAP send/receive, reader depth, the keyhash param). README (P2/P3 status: HISTORY KEEP_LAST is now per-instance both sides; GAP active). `docs/wiki/` (HISTORY behavior + the GAP + a worked KEEP_LAST-per-instance example). `docs/verification.csv` (the §2.2.3.18 + §8.3.7.4 rows + the test names). `docs/provenance.md` (no new external source — clean-room from OMG DDS 1.4 + DDSI-RTPS 2.5). Grep the repo for any now-false claim that HISTORY/GAP is global/unimplemented.
- [ ] **Commit:** `docs(qos): WP-KEEPLAST ADR 0019 final + README/wiki/verification + bench (DDS 1.4 §2.2.3.18, RTPS 2.5 §8.3.7.4, §5.1)`

---

## Self-review
- **Spec coverage:** writer HC honors QoS → D1; keyhash threading → B1; per-instance eviction index + %hc-remove-change → A1; interior-hole GAP send → C1; reader GAP reception → C2; reader per-instance → D1/D2; test migration → D1; the 8 scenarios → A1 (1,5 unit) + C1/C2 (GAP) + D2 (1-7 e2e) + B1 (keyhash) + E1 (mem). All covered.
- **Placeholder scan:** every task has concrete scenarios with exact QoS (kind+depth), exact writes (A@1/B@2/B@3), and exact assertions (last-2-of-A-AND-B, GAP for the named SN, firstSN advance). The one conditional (`key-hash-into` 0-alloc variant) is gated on the `make mem` result, not speculative.
- **Green-per-task:** A/B/C build + unit-test machinery while the engine stays KEEP_ALL (integration untouched). D1 is the single atomic activate+migrate (red→green within the task). No task boundary is left red.
- **Type/name consistency:** `%hc-remove-change (hc sn)` (A1) is the one removal path used by purge-acked/dispose (A1) and eviction (A1); `writer-write`/`publish-sample` `&optional key-hash` (B1) consumed by `write-sample` (B1); `reader-on-gap`/`parse-gap-body`/`write-gap` are the EXISTING symbols (grounded), only newly wired (C1/C2). Consistent A→E.
- **Binary gates:** conformance (per-instance retention both sides; GAP closes the interior-hole hole; no false-REJECT) is the gate D2 + C1/C2 prove; no-regression (KEEP_ALL byte-identical; the migrated suite green both impls) is D1's gate; 0-alloc re-verified at B1/E1.
- **Order:** A (eviction machinery) → B (keyhash feeds it) → C (GAP, independent latent fix) → D (activate + migrate, the flip) → E (gates/bench/docs). The disruptive flip is last among the code phases, after all machinery is proven in isolation.
