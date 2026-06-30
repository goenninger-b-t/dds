# Disk-backed PERSISTENT durability store + cross-restart key-epoch — Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Make the durability service's retained history survive a process/system restart while remaining encrypted at rest (no plaintext on disk), so a late-joiner appearing after a service restart still receives the retained, authenticated samples.

**Architecture:** A new `make-file-store` backend on the existing `durable-store` vtable (append-log-per-topic, replay + crash-recovery on open) sits UNDER the encrypted-store decorator, so disk holds only sealed bytes. The decorator gains a cross-restart **key-epoch**: a persisted `epochs.dat` table maps epoch-id → ML-KEM kem-ciphertext; each store-open re-derives prior epochs' DEKs and lazily mints a fresh epoch (fresh DEK + counter-from-0) on first put — making nonce reuse structurally impossible. Sealed bytes use **envelope v2** (`#x02 ∥ epoch-id ∥ nonce ∥ ct ∥ tag`). The PERSISTENT service tier composes file-store + encrypted-store + file-key-provider.

**Tech Stack:** Common Lisp (SBCL + Clasp), ASDF; the existing `dds-durability` + `dds-dare` systems; `dds.pal` (alloc-static/free-static, locks, file IO); OpenSSL ≥ 3.5 via the existing `dds-dare` CFFI (no new crypto). Disk = plain files via `uiop`/`with-open-file` (no new dependency).

## Global Constraints

(Every task implicitly includes these — from the operating contract, the design spec `docs/superpowers/specs/2026-06-20-durability-persistent-design.md`, ADR 0021/0025, and the memories.)

- **`defun*` for every function, `defstruct*` for every struct**, with FULL type declarations (`dds.lang`); `make gate-types` enforces full ftype coverage. Return types and slot `:type`s mandatory.
- **ALWAYS DARE-wrapped on disk — no plaintext-on-disk path, ever.** The file store stores OPAQUE sealed bytes; it never sees plaintext or keys. Fail-closed throughout: `open-payload` NIL / unknown epoch-id → DROP; OpenSSL < 3.5 / `dare-available-p` NIL → hard error, never a plaintext fallback.
- **Secrets in FOREIGN buffers via `dds.pal:alloc-static` / `dds.pal:free-static` — NEVER `static-vectors:make-static-vector` / `free-static-vector` directly** (a direct call re-triggers clasp#1793; see [[clasp-threading-gap]]). Zeroize (`fill 0`) before release.
- **Bounds-check every parser even at `(safety 0)`** (NFR-SEC-POSTURE): the file-frame parser (replay) and `open-payload` v2. A torn/short/oversized frame → recover or NIL, never OOB/crash. Fuzzed.
- **NO reader conditionals** (`#+sbcl`/`#+clasp`) outside `dds-pal/`. File IO + locks via `dds.pal` / `uiop` (impl-agnostic); a genuine Clasp gap is a runtime `(dds.pal:pal-impl-name)` skip, never a `#+`.
- **Clasp AND SBCL both validate, Clasp FIRST, deterministically** ([[clasp-sbcl-both-validate-clasp-first]]). Verify with `make test-clasp` then `make test-sbcl` (NOT a bare `sbcl --eval '(ql:quickload …)'` — no source registry). `make gate-types`, `make gate-hotpath`, `make mem` (0.0000 — the store is control-plane, off the CDR hot path), `make fuzz`, `make wire`.
- **No AI-assistant attribution** anywhere; cite "the operating contract", never the agent-config filename. No `Co-Authored-By`. **Docs lockstep** (ADR + wiki + README + verification.csv + provenance) at the capstone. **SBOM** auto-regenerates (no new dependency expected — plain-file IO).
- **Cross-DDS interop per feature** ([[cross-dds-interop-required-per-feature]]): verify vs BOTH RTI Connext 7.3.1 AND Fast DDS 3.6.1, the agent runs both peers live; test the wire-observable surface.
- **Branch `wp-durability-persistent`** (already created; the design spec committed `5b55861`). Autonomous commits within the branch; **HOLD PUSH** until owner's word; squash-merge presented for approval after the final whole-branch review.

---

## File Structure

```
src/dds-durability/store-file.lisp        NEW  — make-file-store (append-log-per-topic durable-store backend)
src/dds-durability/store-encrypted.lisp   MOD  — epoch-aware (epoch table, per-epoch DEK map, lazy mint, v2)
src/dds-durability/packages.lisp          MOD  — export make-file-store
src/dds-durability/spec.lisp              MOD  — PERSISTENT-tier store factory helper + dynamic-topic-add hook
src/dds-durability/service.lisp           MOD  — DURABILITY=PERSISTENT wiring, dynamic-topic-add, seen-set prune
src/dds-dare/envelope.lisp                MOD  — envelope v2 (epoch-id) seal-payload / open-payload
dds-durability.asd                        MOD  — add the store-file component
src/dds-tests/durability-test.lisp        MOD  — file-store, cross-restart, PERSISTENT-service tests
src/dds-tests/dare-test.lisp              MOD  — envelope v2 round-trip / tamper / v1-unchanged tests
src/dds-tests/pbt-test.lisp               MOD  — file-frame-parse + open-payload-v2 + crash-injection fuzz arms
src/dds-tests/{packages,echo-test}.lisp   MOD  — export + register new tests
interop/durability-persistent/            NEW  — cross-DDS restart-replay + TRANSIENT-tier coexistence harness
docs/adr/0026-durability-persistent.md    NEW  (Task 10)
docs/wiki/durability.md + README.md + docs/verification.csv + docs/provenance.md  MOD (Task 10)
```

---

## Task 1: `make-file-store` — append-log-per-topic durable-store backend

**Goal:** A `durable-store` (same 8-slot vtable) that persists records to disk and reloads them on open. Stores OPAQUE payload bytes (it does not know about DARE). Round-trip + reopen works; basic tail-recovery + fsync-on-close.

**Files:** Create `src/dds-durability/store-file.lisp`; Modify `dds-durability.asd` (add component after `store`), `src/dds-durability/packages.lisp` (export `make-file-store`), `src/dds-tests/durability-test.lisp`, `src/dds-tests/{packages,echo-test}.lisp`.

**Interfaces:**
- Consumes: the `durable-store` vtable (`%make-durable-store`, `durable-record`, `store-put`/`-get-range`/`-topics`/`-purge`/`-open`/`-close`/`-count` from `store.lisp`); `dds.pal:make-lock` / `with-lock`.
- Produces: `(make-file-store &key dir (max-samples 0)) → durable-store` (`:name :file`). Same put/get-range/topics/purge/open/close/count-fn contracts as `make-memory-store` (idempotent put on `(topic,guid,sn)`, get-range sorted by `(guid bytes, sn)`, `:rejected` when bounded-full). Internal frame helpers `%frame-record`/`%parse-frame`.

- [ ] **Step 1: Failing test** `run-durability-file-store-test` in `durability-test.lisp` (package `dds.tests`, `%check`): in a fresh temp dir, `make-file-store :dir tmp`; `store-open`; put 5 records across 2 topics (varying guid/sn/kind, payloads are arbitrary octet vectors); assert `get-range` round-trips each byte-exact + sorted; `topics`=2; `count`=5; a re-put of an existing `(guid,sn)` returns T and does not duplicate (`count` still 5); `store-close`. Then a SECOND `make-file-store :dir` on the SAME dir → `store-open` → `get-range` returns all 5 byte-exact (reload-from-disk). Clean up the temp dir. Use `%check`.
- [ ] **Step 2: Run, verify FAIL** (`make-file-store` undefined): `make test-sbcl 2>&1 | grep -E "file-store|undefined|FAIL"`.
- [ ] **Step 3: Implement** `store-file.lisp`. Per design spec §5: `D/topics/<topic-id>.log` (topic-id = lowercase hex of the topic UTF-8) + `D/topics.map`. Frame = `magic(2)=#xDA#x01 ∥ flags(1: bits 0-1 kind, bit 2 key-hash-present) ∥ writer-guid(16) ∥ sn(8 LE) ∥ [key-hash(16)] ∥ payload-len(4 LE) ∥ payload ∥ crc32(4 over the frame bytes before the crc)`. (Here "payload" is the record's `durable-record-payload` — opaque to the store.) In-memory index: `topic → hash-table keyed (guid-list . sn) → durable-record`, under a `dds.pal` lock (mirror `%mem-*` in store.lisp — reuse `%guid-list<` for the sort). `put`: append a framed record to the topic log (open the per-topic stream once, keep it in a `topic→stream` table), `finish-output`; update the index (idempotent skip if present; `:rejected` if `max-samples` exceeded). `get-range`/`topics`/`count`: from the index. `purge`: close+delete the topic log, drop the index entry, remove from `topics.map`. `open`: `ensure-directories-exist D/topics/`; for each `*.log`, replay frames into the index — validate magic+len-bounds+crc per frame; on a torn/short/bad-crc TRAILING frame, truncate the file at the last valid offset (`%truncate-file`) and stop that log; a non-trailing corruption → `error`. `close`: `finish-output`+`fsync`+close every stream (fsync via `dds.pal` if it exposes one, else `finish-output`+`(force-output)`; if no portable fsync exists yet, add `dds.pal:fsync-stream` in `dds-pal` — runtime, no `#+`). Implement a CRC-32 (IEEE) helper `%crc32 (octets start end) → (unsigned-byte 32)` in store-file.lisp (small table-driven; pin the polynomial 0xEDB88320 in a comment). All `defun*`-typed.
- [ ] **Step 4: Wire + register** — `dds-durability.asd` (`(:file "store-file")` after `"store"`); `packages.lisp` export `#:make-file-store`; `echo-test.lisp`/`packages.lisp` export + register `#:run-durability-file-store-test`.
- [ ] **Step 5: Run both impls + gates.** `make test-clasp` then `make test-sbcl` (file-store test green, count steady ≥ prior). `make gate-types 2>&1 | tail -1` PASS; `make mem 2>&1 | tail -3` 0.0000.
- [ ] **Step 6: Commit** `feat(durability): WP-DURABILITY-PERSISTENT — make-file-store append-log-per-topic backend (framed records, in-memory index, replay+tail-recovery on open, fsync-on-close) (M6/P5, ADR 0021 cap.7)`.

---

## Task 2: Envelope v2 — epoch-aware `seal-payload` / `open-payload`

**Goal:** Extend the DARE envelope with an epoch-id (the `#x01` version byte reserved this). v1 stays byte-identical; v2 carries the epoch-id, AAD-bound, fail-closed, bounds-checked.

**Files:** Modify `src/dds-dare/envelope.lisp`, `src/dds-tests/dare-test.lisp`, `src/dds-tests/{packages,echo-test}.lisp`.

**Interfaces:**
- Consumes: `aes-256-gcm-seal`/`-open`, the existing `+envelope-version+`/`+envelope-header-len+`/`+aes-gcm-nonce-len+`/`+aes-gcm-tag-len+`, `make-record-aad` (envelope.lisp).
- Produces: `(seal-payload-v2 dek epoch-id nonce aad plaintext) → (simple-array (unsigned-byte 8) (*))` = `#x02 ∥ epoch-id(4 LE) ∥ nonce(12) ∥ ct ∥ tag(16)`; `(open-payload-v2 dek-lookup sealed aad) → (or octets null)` where `dek-lookup` is `(function ((unsigned-byte 32)) (or null (simple-array (unsigned-byte 8) (*))))` returning the DEK for an epoch-id (NIL on unknown). The AAD passed to GCM is `aad ∥ epoch-id(4 LE)` (epoch-id bound). New constants `+envelope-version-v2+ = #x02`, `+envelope-epoch-len+ = 4`, `+envelope-v2-header-len+ = 1+4+12 = 17`.

- [ ] **Step 1: Failing test** `run-dare-envelope-v2-test` (`dare-test.lisp`): SKIP-clean if `(not (dds.dare:dare-available-p))`. Build a DEK (via `derive-dek` of a fixed shared secret), seal with `seal-payload-v2 dek 7 nonce aad pt`; assert the blob starts `#x02`, bytes 1-4 = epoch-id 7 LE, length = `1+4+12+len(pt)+16`; `open-payload-v2 (lambda (e) (if (= e 7) dek nil)) blob aad` round-trips to `pt`; a lookup returning NIL (unknown epoch) → NIL; a 1-bit flip in epoch-id/nonce/ct/tag → NIL; a changed AAD → NIL; a short blob (< 33) → NIL no error. Assert v1 `seal-payload`/`open-payload` STILL byte-identical for a baseline vector (regression). Use `%check`.
- [ ] **Step 2: Run, verify FAIL.**
- [ ] **Step 3: Implement** `seal-payload-v2`/`open-payload-v2` in `envelope.lisp` (DRY: factor the shared GCM-call + the `aad∥epoch` builder; v1 functions unchanged). `open-payload-v2` bounds-checks `(length sealed) >= +envelope-v2-header-len+ + +aes-gcm-tag-len+` and `version = #x02` BEFORE slicing (mandatory at `(safety 0)`); reads epoch-id (4 LE) → `dek-lookup`; NIL DEK → return NIL. Export both + the constants from `packages.lisp`.
- [ ] **Step 4: Run both impls + gate-types + mem.** Clasp first; mem 0.0000.
- [ ] **Step 5: Commit** `feat(dare): WP-DURABILITY-PERSISTENT — envelope v2 (epoch-id, AAD-bound, fail-closed, bounds-checked) for the cross-restart key-epoch; v1 byte-identical (M6/P5, ADR 0025 §5)`.

---

## Task 3: Epoch-aware encrypted-store (persisted epoch table + per-epoch DEK)

**Goal:** Make `make-encrypted-store` cross-restart-capable when given `:epoch-dir`: persist `epochs.dat`, re-derive prior epochs' DEKs on open, lazily mint a fresh epoch on first put, seal under the current epoch (v2), open each record by its epoch-id. Absent `:epoch-dir` → unchanged 3a v1 behavior.

**Files:** Modify `src/dds-durability/store-encrypted.lisp`, `src/dds-tests/dare-test.lisp` (or `durability-test.lisp`), test registration.

**Interfaces:**
- Consumes: Task-2 `seal-payload-v2`/`open-payload-v2`; `ml-kem-1024-encapsulate`/`key-provider-decapsulate`/`derive-dek`/`free-secret-octets` (dds.dare); `make-record-aad`; `dds.pal` lock + file IO; `%crc32` (move it to a shared spot or duplicate-free: expose `%crc32` from store-file via an internal package symbol, OR put `%crc32` in a small shared file both use — DRY, do not copy-paste).
- Produces: `(make-encrypted-store inner-store key-provider &key epoch-dir) → durable-store`. With `epoch-dir`: epoch-aware (v2). Without: the existing 3a behavior (v1). New internal: `%load-epoch-table`/`%append-epoch` (the `epochs.dat` codec: `epoch-id(4 LE) ∥ kem-ct-len(4 LE) ∥ kem-ct ∥ crc32(4)`), `%epoch-dek-map` (epoch-id → DEK foreign).

- [ ] **Step 1: Failing test** `run-dare-persistent-store-test` (SKIP-clean if not `dare-available-p`): in temp dirs `D` (store) + `K` (keys), `enc1 = (make-encrypted-store (make-file-store :dir D) (make-file-key-provider :dir K) :epoch-dir D)`; `store-open`; put N records; assert (a) `get-range` round-trips byte-exact; (b) the INNER file-store's on-disk frame payloads are SEALED (start `#x02`, ≠ plaintext) — confirm via a raw read of a `D/topics/*.log` OR via the inner store directly; (c) `epochs.dat` has exactly 1 epoch after one run with puts; `store-close`. Then `enc2` on the SAME `D`+`K` → `store-open` → `get-range` round-trips all N byte-exact (epoch-1 DEK re-derived); put M more → `epochs.dat` now has 2 epochs; `store-close`; `enc3` → both runs' records open byte-exact. A tampered on-disk sealed frame → `get-range` DROPS it (count−1, no error). Clean up. `%check`.
- [ ] **Step 2: Run, verify FAIL.**
- [ ] **Step 3: Implement** the epoch-aware paths in `store-encrypted.lisp`. On `make`/construction with `:epoch-dir`: `%load-epoch-table` → for each epoch `key-provider-decapsulate(kem-ct) → derive-dek` into a foreign DEK held in the `%epoch-dek-map` (current = NIL until first put). `put`: if no current epoch, MINT (`ml-kem-1024-encapsulate(recipient-pub)`, `%append-epoch`+fsync, `derive-dek`, set current epoch-id+DEK, counter 0); then `seal-payload-v2 current-dek current-epoch counter-nonce aad payload` → inner `store-put`. `get-range`: per record, `open-payload-v2 (lambda (e) (gethash e dek-map)) payload aad`; NIL → drop + hook. `close`: `free-secret-octets` every DEK in the map (+ current), `key-provider-close`. Without `:epoch-dir`: the existing v1 path verbatim (a clean branch; reuse `%encrypted-store-fresh-dek`). Keep the foreign-buffer secret discipline (PAL, never static-vectors directly).
- [ ] **Step 4: Run both impls + gate-types + mem.** Clasp first; mem 0.0000.
- [ ] **Step 5: Commit** `feat(durability): WP-DURABILITY-PERSISTENT — epoch-aware encrypted-store (persisted epochs.dat, per-epoch DEK, lazy mint on first put, v2 seal/open by epoch-id) — cross-restart re-open; nonce reuse structurally impossible (M6/P5, ADR 0025 §5/§10.1)`.

---

## Task 4: PERSISTENT service tier — restart → replay

**Goal:** Wire the secure file-store composition into the durability service as the PERSISTENT tier; on restart the service reloads the store and replays retained history to a late-joiner (no original writer present).

**Files:** Modify `src/dds-durability/spec.lisp` (a PERSISTENT-tier store-factory helper), `src/dds-durability/service.lisp` (DURABILITY=PERSISTENT handling), `src/dds-tests/durability-test.lisp`.

**Interfaces:**
- Consumes: Task-1 `make-file-store`, Task-3 `make-encrypted-store … :epoch-dir`, `make-file-key-provider`; the existing `make-service-spec :store`/`make-durability-service`/`service-start`/`service-stop` + the collect-reader/replay-writer machinery.
- Produces: `(make-persistent-store-factory &key dir key-dir) → (function () durable-store)` (a `:store` factory returning the composed secure file-store) in `spec.lisp`; the service uses it when the spec requests PERSISTENT.

- [ ] **Step 1: Failing test** `run-durability-persistent-service-test` (SKIP-clean if not `dare-available-p`): a `durability-service` whose spec `:store` = `(make-persistent-store-factory :dir D :key-dir K)`; an our-stack publisher writes N TRANSIENT_LOCAL/PERSISTENT samples; `service-stop` (simulating shutdown — the store persisted to `D`). Construct a FRESH service on the same `D`+`K` (simulating restart) + `service-start`; an our-stack late-joiner subscribes AFTER restart and receives all N retained samples byte-exact (decrypted-on-replay). Assert N delivered. Clean up. (This proves cross-restart persistence end-to-end in-process.)
- [ ] **Step 2: Run, verify FAIL.**
- [ ] **Step 3: Implement** `make-persistent-store-factory` in `spec.lisp` + the PERSISTENT-tier selection in `service.lisp`/`spec.lisp` (a spec field or qos-override selecting PERSISTENT → the file-backed factory; default unchanged = in-memory). Ensure `service-stop` `store-close`s (fsync) and `service-start` `store-open`s (replay) — wire store-open/close into the service lifecycle if not already.
- [ ] **Step 4: Run both impls + gates.** Clasp first; gate-types/mem(0.0000).
- [ ] **Step 5: Commit** `feat(durability): WP-DURABILITY-PERSISTENT — PERSISTENT service tier (secure file-store factory; restart reloads + replays retained history to a late-joiner) (M6/P5, ADR 0021 cap.1+7)`.

---

## Task 5: Cross-DDS transparency-after-restart (Connext + Fast DDS) — LIVE

**Goal:** The per-feature interop DoD: a DARE-wrapped PERSISTENT durability service, after a restart, delivers byte-correct retained samples to a LIVE foreign late-joiner — proving disk-at-rest encryption is wire-transparent across restart.

**Files:** Create `interop/durability-persistent/` (README + QoS profiles + captures); no `src/` change (reuse the durability-dare/durability-transient harness with the PERSISTENT factory).

- [ ] **Step 1:** Read `interop/durability-dare/README.md` + `interop/durability-transient/README.md` for the runbook. Build the driver: the service-start form uses `:store (make-persistent-store-factory :dir /tmp/dpersist-D :key-dir /tmp/dpersist-K)` + `:qos-overrides (:data-representation (:xcdr1) :peers (("127.0.0.1" . 7410)))`.
- [ ] **Step 2:** Leg 1 — Connext: kill stale DDS procs (`lsof -nP -iUDP:7400-7440`); start the PERSISTENT service; a Connext TL publisher writes ~N then exits; `service-stop` (store persisted); RESTART the service on the same dirs; a LATE Connext TL subscriber (starts after restart) receives the retained N byte-exact. Record count + first sample.
- [ ] **Step 3:** Leg 2 — Fast DDS: same with the Fast DDS shapes pub/sub + `fastdds-profiles.xml`.
- [ ] **Step 4:** Write `interop/durability-persistent/README.md` with the runbook + a live-results table (Leg | peer | retained-across-restart | late-joiner received | first sample) + wire evidence (firstSN=1, CDR_LE on the replay writer). Be HONEST about counts. If a peer is genuinely unavailable, document the deferral with the our-stack Task-4 test as the proof — but attempt both live. `git add interop/durability-persistent/`.
- [ ] **Step 5: Commit** `test(interop): WP-DURABILITY-PERSISTENT — cross-DDS transparency-after-restart (Connext + Fast DDS late-joiner receive DARE-at-rest retained history after a service restart) (M6/P5)`.

---

## Task 6: Crash-consistency hardening (group-commit fsync, crash-injection fuzz, compaction)

**Goal:** Harden durability: group-commit fsync per drain tick, a crash-injection fuzz arm proving torn-tail recovery, and compaction-on-open of superseded/dead records.

**Files:** Modify `src/dds-durability/store-file.lisp` (group-commit + compaction-on-open), `src/dds-tests/pbt-test.lisp` (crash-injection fuzz arm), `src/dds-tests/durability-test.lisp` (compaction test), test registration.

**Interfaces:**
- Consumes: Task-1 file-store internals (`%parse-frame`, `%truncate-file`, the per-topic streams).
- Produces: `(file-store-sync store) → t` (an explicit group-commit fsync the service calls per drain tick) OR an internal flush-on-tick; `%compact-topic-log` (rewrite a topic log keeping only live records).

- [ ] **Step 1: Failing test (a):** `run-durability-file-crash-test` — write K frames to a topic log via the file-store; CLOSE; CORRUPT the file by truncating it at a random offset inside the last frame (and a separate case: append random trailing bytes); reopen `make-file-store`+`store-open`; assert it recovers to the last fully-valid frame (count = the number of intact frames), no error, no OOB; a re-put + get-range still works. **(b)** `run-durability-compaction-test` — put 3 SNs of the same instance (KEEP_LAST-1) + a dispose; `store-close`; reopen; assert compaction-on-open kept only the live record(s); count reflects compaction.
- [ ] **Step 2:** Add a **crash-injection fuzz arm** to `run-pbt-tests` (`pbt-test.lisp`): generate a random sequence of valid frames + a randomly-corrupted tail (truncate / flip / append-garbage), write to a temp log, `store-open`-replay → recovers (count = intact-prefix), NEVER an error/OOB/crash; `(safety 0)` variant. Update the pbt summary line. `make fuzz` green.
- [ ] **Step 3: Run, verify the new tests FAIL** where behavior is missing.
- [ ] **Step 4: Implement** group-commit (`file-store-sync` flushing+fsyncing all dirty streams; the service calls it per collect-loop tick — wire in `service.lisp`'s `%collect-loop`) + `%compact-topic-log` (on `store-open`, when replaying, drop superseded-by-KEEP_LAST and disposed+unregistered records, then rewrite the log atomically: write to `<log>.tmp`, fsync, rename over `<log>`). Bounds/CRC unchanged.
- [ ] **Step 5: Run both impls + all gates.** Clasp first; `make gate-hotpath gate-types mem fuzz wire`; mem 0.0000.
- [ ] **Step 6: Commit** `feat(durability): WP-DURABILITY-PERSISTENT — crash-consistency hardening (group-commit fsync per drain tick, crash-injection fuzz arm, compaction-on-open via atomic rewrite) (M6/P5, NFR-SEC-POSTURE)`.

---

## Task 7: Carry-forward — collect-loop seen-set prune

**Goal:** Bound the unbounded `seen-data`/`seen-lc` dedup sets (the Phase-2 review's NFR-MEM item).

**Files:** Modify `src/dds-durability/service.lisp`, `src/dds-tests/durability-test.lisp`.

**Interfaces:**
- Consumes: the existing `%collect-loop` seen-set(s) + the per-origin dedup watermark (ADR 0024).
- Produces: a prune step in the collect loop (drop seen entries strictly below the per-origin contiguous watermark and/or older than store retention).

- [ ] **Step 1: Failing test** `run-durability-seen-prune-test` — drive the collect path with many samples from an origin such that the watermark advances; assert the seen-set size stays bounded (≤ a function of the reorder window, not of the total sample count) after the watermark advances. (Use `dds.durability::` internal access to inspect the set size.) `%check`.
- [ ] **Step 2: Run, verify FAIL.**
- [ ] **Step 3: Implement** the prune: after the watermark advances for an origin, remove seen entries below it; bound the reorder set at `*max-gap-range*` (already exists). Keep no-double-delivery invariant intact (prune only fully-subsumed entries).
- [ ] **Step 4: Run both impls + gates.** Clasp first; gate-types/mem(0.0000).
- [ ] **Step 5: Commit** `fix(durability): WP-DURABILITY-PERSISTENT — bound the collect-loop seen-data/seen-lc sets (prune below the per-origin watermark) — NFR-MEM (M6/P5, ADR 0024 carry-forward)`.

---

## Task 8: Carry-forward — dynamic-topic-add

**Goal:** Add a topic to a running durability service (a new disc-node + store partition) without a restart.

**Files:** Modify `src/dds-durability/service.lisp` (+ maybe `runner.lisp`), `src/dds-tests/durability-test.lisp`.

**Interfaces:**
- Consumes: the multi-topic machinery (N disc-nodes per service-start, one per topic — ADR 0024).
- Produces: `(service-add-topic service topic type-name) → t` — spins up a new disc-node + store partition for the topic on a running service.

- [ ] **Step 1: Failing test** `run-durability-dynamic-topic-test` — start a service with topic A; `service-add-topic` topic B; an our-stack publisher on B → late-joiner on B receives B's history (proving B was added live); A unaffected. `%check`.
- [ ] **Step 2: Run, verify FAIL.**
- [ ] **Step 3: Implement** `service-add-topic` (build a disc-node for the topic with a distinct GUID-prefix per the existing topic-sxhash scheme; add its store partition; start its collect/replay; register in the service's node list under the lock). Idempotent on an already-present topic.
- [ ] **Step 4: Run both impls + gates.** Clasp first; gate-types/mem(0.0000). (Clasp live-thread sub-tests may skip per [[clasp-threading-gap]] — document, do not `#+`.)
- [ ] **Step 5: Commit** `feat(durability): WP-DURABILITY-PERSISTENT — dynamic-topic-add to a running service (new disc-node + store partition, no restart) (M6/P5, ADR 0024 carry-forward)`.

---

## Task 9: Carry-forward — live TRANSIENT-tier coexistence (RTI PS) — LIVE

**Goal:** The deferred Phase-2 proof: with a PERSISTENT/TRANSIENT tier our service participates where RTI Persistence Service relays; the receiver-side OWI dedup gives exactly-once under dual relay.

**Files:** `interop/durability-persistent/coexistence/` (README + RTI PS config + captures); no `src/` change expected (reuse the dedup machinery + the PERSISTENT/TRANSIENT tier).

- [ ] **Step 1:** Read `interop/durability-dedup/coexistence/` (the Phase-2 CLOSED_WITH_FINDINGS notes — RTI PS relays TRANSIENT/PERSISTENT, not TRANSIENT_LOCAL). Configure a TRANSIENT (or PERSISTENT) topic so RTI PS relays it AND our service relays it.
- [ ] **Step 2:** Run live: a foreign publisher → both RTI PS and our service relay the same samples → a late-joiner receives EXACTLY-ONCE (the OWI dedup on the shared origin GUID+SN deduplicates the dual relay). Capture + count (no 2N double-delivery).
- [ ] **Step 3:** Write `interop/durability-persistent/coexistence/README.md` with the live result (exactly-once under dual relay, or an honest finding if RTI PS behavior still blocks it at this tier). `git add`.
- [ ] **Step 4: Commit** `test(interop): WP-DURABILITY-PERSISTENT — live TRANSIENT/PERSISTENT-tier coexistence vs RTI Persistence Service (dual-relay exactly-once via OWI dedup) (M6/P5, ADR 0024 carry-forward)`.

---

## Task 10: Capstone — ADR 0026 + docs + final review

**Goal:** Document the as-built; full gate sweep both impls; final whole-branch review; present the squash-merge (HOLD PUSH).

**Files:** `docs/adr/0026-durability-persistent.md` (NEW); `docs/wiki/durability.md` + `README.md` + `docs/verification.csv` + `docs/provenance.md` (MOD); `scripts/generate-sbom.py` only if a dependency changed (none expected).

- [ ] **Step 1: ADR 0026** — the as-built PERSISTENT architecture: the file-store (append-log-per-topic, framing, replay/recovery, group-commit, compaction); the cross-restart key-epoch (new-epoch-per-open, epochs.dat, envelope v2, per-epoch DEK, nonce-reuse-structurally-impossible); the PERSISTENT lifetime/retention; the crash-consistency model; the carry-forwards; the threat model (at-rest on disk now real); reference ADR 0021 cap.7 / 0025 §5/§10 + the design spec.
- [ ] **Step 2: Docs lockstep** — `docs/wiki/durability.md` (a PERSISTENT section + a worked persistent-store-factory example + the on-disk format + the OpenSSL ≥ 3.5 requirement); `README.md` P5 row (durability now has a disk-backed PERSISTENT tier, DARE-at-rest, cross-restart key-epoch); `docs/verification.csv` (a PERSISTENT row: cross-restart round-trip, no-plaintext-on-disk, crash-injection, live cross-DDS-after-restart, the carry-forwards); `docs/provenance.md` only if a new source was consulted.
- [ ] **Step 3: Full gate sweep both impls** — `make test-clasp`/`test-sbcl` (Clasp first, both deterministic), `make gate-hotpath gate-types mem fuzz wire` — all green; mem 0.0000.
- [ ] **Step 4: Final whole-branch review** (fresh reviewer, most capable model, over `main..wp-durability-persistent`): the crash-consistency (framing/recovery/fsync ordering — no torn read, no nonce reuse on recovery); the key-epoch correctness (every epoch a distinct DEK + counter-from-0; lazy mint; no cross-restart reuse); fail-closed (unknown-epoch/torn-frame/auth-fail → drop, never plaintext, never crash); secrets via the PAL (Clasp-deterministic); no-plaintext-on-disk; bounds/fuzz; NFR-MEM; no reader conditionals; docs/SBOM lockstep; no AI attribution. Fix findings (re-run the covering gate per fix).
- [ ] **Step 5: Commit** `docs(durability): WP-DURABILITY-PERSISTENT — ADR 0026 + wiki/README/verification; Phase-3b capstone (M6/P5, ADR 0021 cap.7)`; then present the squash-merge for owner approval (HOLD PUSH).

---

## Self-review (author checklist — completed)

- **Spec coverage:** §4 modules → file-store (T1), envelope v2 (T2), epoch-aware encrypted-store (T3), service wiring (T4). §5 on-disk format → T1 (framing/index/replay/recovery) + T6 (compaction). §6 key-epoch → T3 (epoch table, lazy mint, per-epoch DEK) + T2 (v2). §7 envelope v2 → T2. §8 PERSISTENT lifetime/retention → T4 + T6 (compaction). §9 crash-consistency → T6 (fsync/fuzz) + T1 (tail-recovery). §10 carry-forwards → T7 (seen-prune) + T8 (dynamic-topic) + T9 (coexistence). §12 testing → each task's tests + T5 (cross-DDS-after-restart) + T9 (coexistence). §13 VSD ordering → T1→T10. §14 out-of-scope → not built. The 6 spec slices map: core persistence = T1-T4; cross-DDS = T5; hardening = T6; carry-forwards = T7-T9; capstone = T10.
- **Placeholder scan:** no TBD/TODO; each task has concrete files, interfaces (signatures), failing-test contracts, implementation guidance pinned to the spec, run commands, and a commit message. (Per the established codebase plan style, implementation steps give exact signatures + test code + a precise contract referencing the design spec rather than a full transcription — the implementer is a capable subagent with the spec in hand.)
- **Type/name consistency:** `make-file-store` (T1) → composed in T3/T4; `seal-payload-v2`/`open-payload-v2` + `+envelope-version-v2+`/`+envelope-epoch-len+`/`+envelope-v2-header-len+` (T2) → used in T3; `make-encrypted-store … :epoch-dir` + `epochs.dat` codec (T3) → T4; `make-persistent-store-factory` (T4) → T5; `%crc32` shared (T1/T3) DRY-noted; `file-store-sync`/`%compact-topic-log` (T6); `service-add-topic` (T8). `dds.pal:alloc-static`/`free-static` (the clasp#1793-safe secret path) used wherever secrets are buffered.
- **Crypto-safety honesty:** no new KATs needed (the primitives are reused from 3a, already published-source-KAT'd); the new crypto surface is the v2 envelope (round-trip/tamper/bounds tested in T2) + the epoch table (cross-restart round-trip in T3). The nonce-reuse-impossible argument rests on new-epoch-per-open (T3) + the crash-injection test (T6).
