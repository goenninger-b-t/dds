# WP-DURABILITY-KEEPLAST-COMPACTION Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Bound per-instance retained sample count in the durability store under a DDS DURABILITY_SERVICE `KEEP_LAST(depth)` policy — keep only the newest `depth` `:data` records per instance (key-hash), compacting away older superseded ones — for both the file-store and the in-memory store, default `:keep-all` (byte-identical).

**Architecture:** The durability service is type-agnostic, so it reads the instance handle from the wire `PID_KEY_HASH`. That key-hash is parsed by `parse-data-body` but gated off for data-with-payload (hot-path alloc avoidance) and dropped before delivery. A node-gated capture flag is threaded down to the parse and the key-hash up to a per-sample disc-node table (mirroring the ADR 0028 logical-origin capture). The collect loop then stores `:data` under its instance; compaction (file-store on open / in-memory online on put) keeps the newest `depth` per non-NIL-key-hash instance.

**Tech Stack:** Common Lisp (SBCL + Clasp), `dds-rtps` (message parse), `dds-disc` (dataplane + disc), `dds-durability` (store + service), `dds-tests`, the `interop/` cross-DDS harness (RTI Connext 7.3.1 + Fast DDS 3.6.1), Python/tshark for the T0 spike.

## Global Constraints

- **Control-plane only / NFR-MEM:** the data-key-hash capture MUST be node-gated so regular DCPS readers are unaffected — no new per-sample alloc on the measured hot path. `gate-hotpath` (8 files) and `make mem` (0.0000) must stay green. The durability collect node opts in via a node slot; every other node is byte-identical.
- **`defun*`/`defstruct*`** + **full ftype** on every new/changed function (FR-LANG-8).
- **No wire constants from memory:** the key-hash / `PID_KEY_HASH` rule is RTPS 2.5 §9.6.4.8, already in `parse-inline-qos-key-status` — reuse it, do not re-encode.
- **Bounds-checked** parse — reuse the existing bounds-checked `parse-inline-qos-key-status`; do not add an unchecked path.
- **Clasp AND SBCL both validate, Clasp first.** No reader conditionals outside `dds-pal/`.
- **Default `:keep-all` is byte-identical to today;** never drop a still-relevant sample (safety > completeness). NIL-key-hash records are NEVER compacted.
- **No AI / assistant attribution** in any repo file; cite "the operating contract", never a filename.
- **Cross-restart key-epoch / DARE intact:** file-store compaction reuses `%rewrite-topic-log` (re-seals via the DARE envelope under the current epoch); no envelope/epoch change.

## File map

- `src/dds-rtps/message.lisp` — `parse-data-body`: add a `capture-data-key-hash` param gating line ~624.
- `src/dds-disc/disc.lisp` — line ~918: pass the node's capture flag to `parse-data-body`; forward the key-hash to the data handler.
- `src/dds-disc/dataplane.lisp` — the data-handler lambda (~1572), `%on-user-data` (~1357), `%deliver-user-sample` (~1318): thread the key-hash; add `%record-sample-key-hash` + the `sample-key-hashes` table + `node-sample-key-hash` accessor; a `disc-node` `capture-data-key-hash` slot.
- `src/dds-disc/disc.lisp` — `disc-node` struct: add `capture-data-key-hash` slot + `sample-key-hashes` slot; `add-local-reader`/`make-disc-node` option to set it.
- `src/dds-disc/packages.lisp` — export `node-sample-key-hash`.
- `src/dds-durability/spec.lisp` — `service-spec`: add `history-kind` + `history-depth`.
- `src/dds-durability/service.lisp` — `%build-disc-node` sets the collect node's `capture-data-key-hash`; `%collect-loop` stores data under `(node-sample-key-hash node key)`; plumb the depth to the store factory.
- `src/dds-durability/store-file.lisp` — `%compact-topic-records`: add the per-instance KEEP_LAST pass; `make-file-store` / the factory take the history policy.
- `src/dds-durability/store.lisp` — `%mem-put` + `make-memory-store`: online per-instance eviction under `:keep-last`.
- `src/dds-tests/durability-test.lisp` + `echo-test.lisp` + `packages.lisp` — new tests.
- `docs/adr/0029-durability-keeplast-compaction.md` (new); `README.md`, `docs/wiki/durability.md`, `docs/verification.csv`; `interop/durability-keeplast/` (T5).

---

### Task 0: Spike — `PID_KEY_HASH` on keyed `ShapeType` data (Connext + Fast DDS)

**Files:** Create `interop/durability-keeplast/spike/run-spike.sh` + `docs/superpowers/spikes/2026-06-21-keyhash-on-keyed-data.md`. No `src/` change (build-clean spike).

**Goal:** Determine, on the wire, whether RTI Connext 7.3.1 and Fast DDS 3.6.1 put `PID_KEY_HASH` (0x0070) inline on keyed `ShapeType` **data** samples (not just dispose/unregister), and the value. This gates the live per-instance DoD (T5).

- [ ] **Step 1: Capture keyed Shapes data.** Reuse an existing interop Shapes publisher (e.g. `interop/connext/shapes-pub` writing `Square` with a color key). Capture lo0 with tshark to a pcap.

```bash
# from repo root; mirrors interop/durability-coexist-dedup/run-coexist-both.sh's capture setup
mkdir -p interop/durability-keeplast/spike/captures
/Applications/Wireshark.app/Contents/MacOS/tshark -i lo0 -f "udp portrange 7400-7600" \
  -w interop/durability-keeplast/spike/captures/connext-keyed.pcap >/dev/null 2>&1 &
# start the Connext keyed Shapes publisher (writes several colors), let it run ~10s, stop both.
```

- [ ] **Step 2: Decode `PID_KEY_HASH` on DATA-with-payload.** Walk the inline-QoS of each DATA submessage (Q-bit set, has-payload) for PID 0x0070 (16-octet body). Report: does Connext put `PID_KEY_HASH` on keyed data? Same for Fast DDS. Record the value relationship (the key-hash for `ShapeType`, RTPS 2.5 §9.6.4.8: MD5 of the key CDR, or the key right-padded for keys ≤ 16 bytes).

- [ ] **Step 3: Write the finding** to `docs/superpowers/spikes/2026-06-21-keyhash-on-keyed-data.md`: per peer, `PID_KEY_HASH`-on-keyed-data present yes/no + the value form. **RE-PLAN CHECKPOINT:** if a peer omits it, T5's live per-instance DoD for that peer falls back to keep-all-safe + the in-process test is authoritative (document honestly, do not weaken a test). Controller confirms the finding before T1.

- [ ] **Step 4: Commit** (spike doc + harness; NO src):
```bash
git add interop/durability-keeplast/spike docs/superpowers/spikes/2026-06-21-keyhash-on-keyed-data.md
git commit -m "spike(durability): WP-DURABILITY-KEEPLAST-COMPACTION — PID_KEY_HASH on keyed ShapeType data, Connext + Fast DDS (M6/P5, ADR 0026 §10)"
```

---

### Task 1: Node-gated data key-hash capture

**Files:**
- Modify: `src/dds-rtps/message.lisp` (`parse-data-body` ~601-633)
- Modify: `src/dds-disc/disc.lisp` (`disc-node` struct; `parse-data-body` call ~918; `make-disc-node`/`add-local-reader` option)
- Modify: `src/dds-disc/dataplane.lisp` (data-handler lambda ~1572; `%on-user-data` ~1357; `%deliver-user-sample` ~1318; new `%record-sample-key-hash`; `node-sample-key-hash`)
- Modify: `src/dds-disc/packages.lisp`
- Test: `src/dds-tests/durability-test.lisp` (`run-durability-data-keyhash-capture-test`)

**Interfaces:**
- Consumes: `parse-data-body` returns `(values reader writer sn has-payload poff len key-p change-kind key-hash status-flags original-guid original-sn)` — key-hash at position 9, currently gated off for data-with-payload.
- Produces: `node-sample-key-hash (node key) → (or (simple-array (unsigned-byte 8) (16)) null)` — the captured wire `PID_KEY_HASH` of the `:data` sample at composite KEY (a `(wire-guid . sn)` cons), or NIL. Gated by the node's `capture-data-key-hash` slot (default NIL → byte-identical, no hot-path alloc).

- [ ] **Step 1: Write the failing test.** In `src/dds-tests/durability-test.lisp` (model on `run-durability-origin-accessor-test` two-node wiring): a writer publishes a keyed sample via `(dds.disc:publish-sample relay-node payload KH16)` (KH16 a 16-octet key-hash); a reader node **with `capture-data-key-hash` enabled** receives it; assert `(equalp (dds.disc:node-sample-key-hash rdr key) KH16)`. Second case: a reader with capture DISABLED (default) → `node-sample-key-hash` returns NIL (byte-identical). Use domain 80.

- [ ] **Step 2: Run it — expect FAIL** (`node-sample-key-hash` undefined):
```
./scripts/with-clasp.sh --eval '(ql:quickload :dds-tests :silent t)' --eval '(handler-case (progn (dds.tests:run-durability-data-keyhash-capture-test) (uiop:quit 0)) (error (e) (format t "~&FAIL ~a~%" e) (uiop:quit 1)))'
```
Expected: FAIL — `NODE-SAMPLE-KEY-HASH is undefined`.

- [ ] **Step 3: `parse-data-body` capture flag.** In `src/dds-rtps/message.lisp`, change `parse-data-body`'s lambda list to `(cursor flags octets-to-next &optional capture-data-key-hash)` (add the ftype `&optional t`), and line ~624 from `(parse-inline-qos-key-status cursor body-end (not has-payload))` to:
```lisp
(parse-inline-qos-key-status cursor body-end (or (not has-payload) capture-data-key-hash))
```
Default `capture-data-key-hash` NIL → `(not has-payload)` → byte-identical.

- [ ] **Step 4: `disc-node` slots.** In `src/dds-disc/disc.lisp` `disc-node` struct add two slots:
```lisp
  (capture-data-key-hash nil :type boolean) ; durability collect node opts in to materialize the wire PID_KEY_HASH on :data (control-plane); default NIL = byte-identical, no hot-path alloc
  (sample-key-hashes (make-hash-table :test 'equalp) :type hash-table) ; src GUID -> SN -> 16-octet wire key-hash of the :data sample (RTPS 2.5 §9.6.4.8), absent when not captured
```
Add a `make-disc-node` keyword `:capture-data-key-hash` (default NIL) setting the slot.

- [ ] **Step 5: Pass the flag + forward the key-hash at the call site.** In `src/dds-disc/disc.lisp` line ~918, change `(dds.rtps.message:parse-data-body c flags body-len)` to `(dds.rtps.message:parse-data-body c flags body-len (disc-node-capture-data-key-hash node))`, and where the parsed values are destructured, forward the key-hash (return position 9) into the data-handler call alongside `og os`. (Read the surrounding multiple-value-bind; add `kh` to the bound vars and to the handler invocation.)

- [ ] **Step 6: Thread the key-hash through the handler.** In `src/dds-disc/dataplane.lisp`: the data-handler lambda (~1572) gains a `kh` arg and passes it to `%on-user-data`; `%on-user-data` (~1357) gains an `&optional key-hash` param after `orig-sn` and passes it to `%deliver-user-sample`; `%deliver-user-sample` (~1318) gains a `key-hash` param and, inside the `with-lock`, after `%record-sample-origin`, calls `(%record-sample-key-hash node guid sn key-hash)`. Update each ftype to match.

- [ ] **Step 7: The setter + accessor.** In `src/dds-disc/dataplane.lisp`, near `%record-sample-origin`:
```lisp
(defun* %record-sample-key-hash (node wire-guid sn key-hash)
    (function (disc-node (simple-array (unsigned-byte 8) (16)) integer
              (or null (simple-array (unsigned-byte 8) (*)))) t)
  "Record the wire PID_KEY_HASH (RTPS 2.5 §9.6.4.8) of the :data sample stored under (WIRE-GUID, SN) when
   one was captured (a keyed sample whose peer sent it inline; the durability collect node opts in). NIL or
   non-16-octet -> store nothing (the store treats absent key-hash as 'unknown instance', never compacted).
   Caller holds the node lock. Control-plane (relay store)."
  (when (and key-hash (= 16 (length key-hash)))
    (setf (gethash sn (%inner-table (disc-node-sample-key-hashes node) wire-guid))
          (coerce key-hash '(simple-array (unsigned-byte 8) (16)))))
  t)

(defun* node-sample-key-hash (node key)
    (function (disc-node cons) (or null (simple-array (unsigned-byte 8) (16))))
  "The captured 16-octet wire PID_KEY_HASH (RTPS 2.5 §9.6.4.8) of the :data sample at composite KEY
   (a (GUID . SN) cons), or NIL when none was captured (capture not enabled, or the sample carried no
   inline PID_KEY_HASH). A durability relay uses THIS as the per-instance handle for KEEP_LAST compaction
   (ADR 0029)."
  (dds.pal:with-lock ((disc-node-lock node))
    (let ((inner (gethash (car key) (disc-node-sample-key-hashes node))))
      (and inner (gethash (cdr key) inner)))))
```
Export `#:node-sample-key-hash` in `src/dds-disc/packages.lisp`.

- [ ] **Step 8: Run it — expect PASS** (command from Step 2). Both impls (Clasp first).

- [ ] **Step 9: Register/export the test + gate + commit.** Export `#:run-durability-data-keyhash-capture-test`; add `("durability-data-keyhash-capture" . run-durability-data-keyhash-capture-test)` to `echo-test.lisp`. Then:
```
make test-clasp && make test-sbcl && make gate-hotpath && make gate-types && make mem
git add src/dds-rtps/message.lisp src/dds-disc/disc.lisp src/dds-disc/dataplane.lisp src/dds-disc/packages.lisp src/dds-tests/durability-test.lisp src/dds-tests/echo-test.lisp src/dds-tests/packages.lisp
git commit -m "feat(disc): WP-DURABILITY-KEEPLAST-COMPACTION — node-gated capture of the wire PID_KEY_HASH on :data (node-sample-key-hash; default off = byte-identical, no hot-path alloc) (M6/P5, ADR 0029)"
```
Expected: both impls green, `gate-hotpath` PASS, `gate-types` PASS, **`mem` 0.0000** (the capture is node-gated; the mem-test node does not enable it).

---

### Task 2: DURABILITY_SERVICE QoS + collect-loop stores the instance

**Files:**
- Modify: `src/dds-durability/spec.lisp` (`service-spec` struct + `make-service-spec`)
- Modify: `src/dds-durability/service.lisp` (`%build-disc-node` enables capture; `%collect-loop` data drain ~219-228; depth plumbed to the store factory)
- Test: `src/dds-tests/durability-test.lisp` (`run-durability-collect-keyhash-store-test`)

**Interfaces:**
- Consumes: `node-sample-key-hash` (Task 1); `make-disc-node :capture-data-key-hash`; `store-put (store topic writer-guid sn key-hash kind payload)`.
- Produces: `service-spec` with `history-kind` (`:keep-all` default | `:keep-last`) + `history-depth` (positive integer); the collect node captures the data key-hash and stores `:data` records under it.

- [ ] **Step 1: Write the failing test.** A durability service (in-memory) collects a keyed sample from a writer that sends `PID_KEY_HASH`; assert the stored `durable-record` for that data has `key-hash` = the wire key-hash (not NIL). Model on `run-durability-no-double-delivery-test`; domain 81; assert via `store-get-range` + `durable-record-key-hash`.

- [ ] **Step 2: Run — expect FAIL** (data record key-hash is NIL today).

- [ ] **Step 3: `service-spec` fields.** In `src/dds-durability/spec.lisp` add to the `service-spec` struct:
```lisp
  (history-kind  :keep-all :type (member :keep-all :keep-last)) ; DURABILITY_SERVICE history_kind (DDS 1.4 §2.2.3.5); :keep-all = no compaction (byte-identical)
  (history-depth 1 :type (integer 1))                            ; DURABILITY_SERVICE history_depth; used only for :keep-last
```
Add `:history-kind`/`:history-depth` keywords to `make-service-spec` (defaults `:keep-all` / `1`), with ftype updates.

- [ ] **Step 4: Collect node enables capture; collect loop stores the instance.** In `src/dds-durability/service.lisp` `%build-disc-node`, pass `:capture-data-key-hash t` to the collect reader's `make-disc-node` (the durability node opts in). In `%collect-loop` data drain, bind `(kh (dds.disc:node-sample-key-hash node key))` and pass `kh` (not `nil`) to `store-put`:
```lisp
(store-put store topic-name origin-guid origin-sn kh :data payload)
```
(Keep the origin-guid/origin-sn logical-origin resolution from ADR 0028 unchanged.)

- [ ] **Step 5: Run — expect PASS.** Both impls.

- [ ] **Step 6: Register/export + gate + commit.** `run-durability-collect-keyhash-store-test`. Then `make test-clasp && make test-sbcl && make gate-hotpath && make gate-types && make mem`; commit `feat(durability): WP-DURABILITY-KEEPLAST-COMPACTION — DURABILITY_SERVICE history QoS on service-spec (default :keep-all byte-identical) + collect-loop stores :data under its wire key-hash (M6/P5, ADR 0029)`.

---

### Task 3: File-store per-instance KEEP_LAST compaction

**Files:**
- Modify: `src/dds-durability/store-file.lisp` (`%compact-topic-records` ~345; `make-file-store` / the persistent factory take the history policy)
- Modify: `src/dds-durability/service.lisp` / `spec.lisp` — plumb `history-kind`/`history-depth` to the store factory
- Test: `src/dds-tests/durability-test.lisp` (`run-durability-keeplast-compaction-test`)

**Interfaces:**
- Consumes: `history-kind`/`history-depth` (Task 2); the existing `%compact-topic-records (records) → list` (settled/resurrection drop) and `%rewrite-topic-log`; `durable-record-key-hash`/`-sn`/`-kind`; `%record-guid-sn<`.
- Produces: `%compact-topic-records (records &optional history-kind history-depth)` — adds, under `:keep-last depth`, a per-instance newest-`depth` `:data` retention; `:keep-all` byte-identical.

- [ ] **Step 1: Write the failing test.** Build a list of `durable-record`s: one keyed instance K with 5 `:data` records (SN 1..5, same key-hash), plus a NIL-key-hash record, plus a settled instance (dispose+unregister). Call `(%compact-topic-records recs :keep-last 2)`. Assert: instance K keeps exactly its 2 highest SNs (4,5), drops 1..3; the NIL-key-hash record is kept; the settled instance is dropped (existing behavior); and `(%compact-topic-records recs :keep-all)` returns the settled-only result (byte-identical to the no-arg call). Use `dds.durability::%compact-topic-records` (internal) + `dds.durability::make-durable-record`.

- [ ] **Step 2: Run — expect FAIL** (compaction ignores depth today).

- [ ] **Step 3: Extend `%compact-topic-records`.** Add `&optional (history-kind :keep-all) (history-depth 1)`. After the existing settled-drop pass produces `kept`, when `history-kind` is `:keep-last`, run a per-instance pass over `kept`: group the `:data` records by `durable-record-key-hash` (skip NIL key-hash — never compacted), and within each non-NIL-key-hash instance keep only the `history-depth` records sorting highest by `%record-guid-sn<` (drop the older). Lifecycle records and NIL-key-hash records pass through untouched. Preserve append order in the output. `:keep-all` skips this pass (byte-identical).

- [ ] **Step 4: Run — expect PASS.** Both impls.

- [ ] **Step 5: Plumb the policy + cross-restart test.** Pass `history-kind`/`history-depth` from the `service-spec` to the file-store factory, and from the store-open compaction call to `%compact-topic-records`. Add `run-durability-keeplast-cross-restart-test`: write M samples for one instance to a file-store, close, reopen with `:keep-last D`, assert the reopened store holds D records for the instance (compaction-on-open ran), and the DARE envelope still decrypts (reuse the persistent-store test scaffolding from `run-durability-persistent-service-test`).

- [ ] **Step 6: Gate + commit.** `make test-clasp && make test-sbcl && make gate-hotpath && make gate-types && make mem && make fuzz`; commit `feat(durability): WP-DURABILITY-KEEPLAST-COMPACTION — file-store per-instance KEEP_LAST compaction-on-open (newest depth per non-NIL-key-hash instance; settled/resurrection + DARE intact) (M6/P5, ADR 0029)`.

---

### Task 4: In-memory online per-instance eviction

**Files:**
- Modify: `src/dds-durability/store.lisp` (`%mem-put` ~99; `make-memory-store`)
- Test: `src/dds-tests/durability-test.lisp` (`run-durability-keeplast-memory-test`)

**Interfaces:**
- Consumes: `history-kind`/`history-depth`; the in-memory inner table keyed by `(cons (coerce writer-guid 'list) sn)`; `durable-record-key-hash`/`-kind`/`-sn`.
- Produces: `make-memory-store (&key (max-samples 0) (history-kind :keep-all) (history-depth 1))`; under `:keep-last`, `%mem-put` evicts the oldest `:data` of an instance once it exceeds `history-depth`.

- [ ] **Step 1: Write the failing test.** Build a memory store with `:keep-last 2`; `store-put` 5 `:data` for one key-hash instance; assert `store-get-range` returns exactly 2 (the 2 highest SNs); a NIL-key-hash instance is never evicted; `:keep-all` keeps all 5 (regression).

- [ ] **Step 2: Run — expect FAIL.**

- [ ] **Step 3: Implement eviction.** `make-memory-store` takes `:history-kind`/`:history-depth` and passes them to `%mem-put` (via the closure). In `%mem-put`, after inserting a `:data` record under `:keep-last`, if its instance (non-NIL key-hash) now has more than `history-depth` `:data` records in the topic's inner table, remove the lowest-SN `:data` record(s) of that key-hash until `history-depth` remain. NIL-key-hash records and lifecycle records are never evicted. `:keep-all` skips eviction (byte-identical).

- [ ] **Step 4: Run — expect PASS.** Both impls.

- [ ] **Step 5: Gate + commit.** `make test-clasp && make test-sbcl && make gate-hotpath && make gate-types && make mem`; commit `feat(durability): WP-DURABILITY-KEEPLAST-COMPACTION — in-memory store online per-instance KEEP_LAST eviction (M6/P5, ADR 0029)`.

---

### Task 5: Capstone — ADR 0029 + docs + cross-DDS interop + final review

**Files:** Create `docs/adr/0029-durability-keeplast-compaction.md`; modify `README.md`, `docs/wiki/durability.md`, `docs/verification.csv`; create `interop/durability-keeplast/` (live harness).

- [ ] **Step 1: Cross-DDS interop (the per-feature DoD).** A Connext (and Fast DDS) publisher writes M samples per keyed `ShapeType` instance → our durability service (`:keep-last D`) stores with captured key-hashes → a late-joiner receives D-per-instance. Capture + analyze. If the T0 spike showed a peer omits `PID_KEY_HASH` on data, that direction falls back to keep-all-safe and is documented honestly (the in-process tests T3/T4 are authoritative). Commit the harness + captures.

- [ ] **Step 2: ADR 0029** (as-built: the type-agnostic key-hash dependency + the node-gated capture; the DURABILITY_SERVICE QoS; per-instance KEEP_LAST compaction [file-store on-open + in-memory online]; NIL-key-hash-never-compacted safety; settled/resurrection + DARE intact; the cross-DDS results; the spike finding; NO_KEY KEEP_LAST follow-on).

- [ ] **Step 3: Docs lockstep.** README P5 row; `docs/wiki/durability.md` (KEEP_LAST compaction + the `node-sample-key-hash` API + the DURABILITY_SERVICE QoS); `docs/verification.csv` append a clean 6-column `P5-KEEPLAST-COMPACTION` row (verify `python3 -c "import csv; rows=list(csv.reader(open('docs/verification.csv'))); print(len(rows[-1]))"` == 6).

- [ ] **Step 4: Full gate sweep both impls (Clasp first).**
```
make test-clasp && make test-sbcl && make gate-hotpath && make gate-types && make mem && make fuzz && make wire
```
Expected: both green (deterministic), gate-hotpath PASS, gate-types PASS, mem 0.0000, fuzz PASS, wire PASS.

- [ ] **Step 5: Commit the capstone**, then (controller, NOT this task) the final whole-branch review over `main..HEAD` → ONE fix wave → squash-merge presented for owner approval (HOLD PUSH).

---

## Self-review

**Spec coverage:** §4.1 DURABILITY_SERVICE QoS → T2. §4.2 disc-node key-hash capture → T1. §4.3 collect-loop stores instance → T2. §4.4 file-store per-instance compaction → T3. §4.5 in-memory eviction → T4. §4.6 cross-restart/DARE → T3 Step 5. §5 testing: unit (T1), store (T2), compaction (T3), memory (T4), cross-restart (T3.5), cross-DDS (T5.1), spike (T0). §7 risks (type-agnostic, NO_KEY, append-growth) → T0 spike + the NIL-never-compacted rule + documented follow-ons. All covered.

**Placeholder scan:** every code step shows the real change against the exact line; the only runtime-deferred values are the T0 spike's wire finding and T5's live N (inherent to live measurement). No "TBD"/"handle edge cases".

**Type consistency:** `node-sample-key-hash (node key) → (or null (simple-array (unsigned-byte 8) (16)))` defined in T1, consumed in T2. `%compact-topic-records (records &optional history-kind history-depth)` defined in T3, consistent with the T3 test call. `make-memory-store (&key max-samples history-kind history-depth)` in T4. `service-spec` `history-kind`/`history-depth` (T2) consumed by T3/T4. `parse-data-body`'s new `&optional capture-data-key-hash` (T1) matches the disc.lisp call site. `store-put`'s key-hash arg (existing) now receives `node-sample-key-hash` in T2.
