# Phase 2 Durability Dedup — Implementation Plan (dedup + multi-topic + dispose/unregister)

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Close the Phase-1 no-double-delivery gap — a TRANSIENT reader matched to multiple sources (original writer + relay, or two relays) receives each sample exactly once — via the standard RTPS `PID_ORIGINAL_WRITER_INFO (0x0061)` in relayed-DATA inline QoS + receiver-side max-SN dedup; plus multi-topic-per-service (N disc-nodes) and dispose/unregister capture+replay.

**Architecture:** Inert-by-default engine extensions (`write-data` gains optional inline-QoS from the `cache-change.inline-qos` slot; the DATA receive path extracts `PID_ORIGINAL_WRITER_INFO` and dedups by original-GUID max-SN) layered under the Phase-1 `dds-durability` service. The relay writer attaches the PID built from the store's recorded original `(GUID, SN)`. A multi-topic service holds N single-endpoint disc-nodes (one per topic). Absent the PID, every path is byte-identical to today.

**Tech Stack:** Common Lisp (SBCL + Clasp gated; AllegroCL where available), ASDF, the `dds-rtps` message codec + reliable engine, `dds-disc` data plane, the `dds-durability` system, tshark RTPS dissector + live RTI Persistence Service / Connext 7.3.1 / Fast DDS 3.6.1 for interop.

## Global Constraints

(Every task implicitly includes these — from the operating contract, `REQUIREMENTS.md`, the memory, ADR 0021/0022/0023, the spike, and the design spec.)

- **`defun*` for every function, `defstruct*` for every struct** (`dds.lang`, `src/dds-lang/lisp-lang-tools.lisp`): `(defun* name lambda-list (function (arg-types…) result-type) "docstring" body…)` — required-arg count matches the signature; docstring mandatory non-empty. `(defstruct* (name (:constructor make-name)) "docstring" (slot default :type type)…)` — every slot `:type`. `make gate-types` enforces full ftype coverage.
- **OMG-conformance is non-negotiable; a FALSE-REJECT / silent loss is the worst defect class.** The ONLY allowed extension is interop behavior ADDED ON TOP of conforming behavior. **Inert-by-default:** absent `PID_ORIGINAL_WRITER_INFO`, emit + receive are BYTE-IDENTICAL to today and SN tracking is unchanged. Dedup discards ONLY a true duplicate (`originalSN ≤ max` for the SAME `originalGUID`); a malformed/short PID body → treated as "no PID", never OOB, never a dropped fresh sample.
- **Wire constants are pinned from the clause + verified byte-exact**, never from memory. `PID_ORIGINAL_WRITER_INFO = 0x0061` (RTPS 2.5 §8.3.5.4, Table 9.12); body = `guidPrefix[12] + entityId[4] + SN.high[4](int32) + SN.low[4](uint32)`, **Little-Endian**, total 24 bytes; the param header is `pid(u16) + len(u16=24)`. Pin the byte-exact vector against the spike capture hex (design §5 / spike §3.2). DATA InlineQos (Q) flag = `+data-flag-inline-qos+ #x02` (RTPS 2.5 §9.4.5.4). ParameterList terminated by `+pid-sentinel+ #x0001`, 4-octet-aligned (§9.4.2.11).
- **Bounds-check every wire-facing parse**, even at `(safety 0)` (NFR-SEC-POSTURE) — the PID parser validates `paramLength == 24` and that the body fits within the submessage before reading; fuzzed.
- **NFR-MEM:** the dedup map is bounded by the number of distinct original GUIDs matched (not per-sample growth). `make mem` stays **0.0000** (the PID encode/parse is off the measured CDR codec hot path — it's on the relay/discovery path).
- **No hot-path CLOS / no per-sample heap alloc** on the measured codec path. The PID codec + dedup are control/relay plane.
- **No reader conditionals** (`#+sbcl`/`#+clasp`) outside `dds-pal/` (runtime `(dds.pal:pal-impl-name)` dispatch instead). **No AI-assistant attribution** anywhere (source, docs, ADR, commits, interop README); no `Co-Authored-By`.
- **Docs in lockstep** (§5.1): exported symbols get docstrings; touch the wiki/README/verification.csv in the capstone. **SBOM** auto-regenerates via the pre-commit hook — never hand-edit.
- **DoD per task:** compiles + tests green on SBCL AND Clasp (or a documented NFR-PORT gap); applicable gates green (`make test gate-hotpath gate-types mem fuzz wire`); commit references the WP id + requirement id. **Cross-DDS interop per feature** (Connext 7.3.1 + Fast DDS 3.6.1 + RTI Persistence Service, agent runs the live peers) — applies at Tasks 3 and 7.
- **Verification uses the make targets** (`make test-sbcl` / `make test-clasp` / `make gate-*` / `make wire`) — a bare `sbcl --eval "(ql:quickload :dds-tests)"` fails with "system not found" (no ASDF source registry).
- **Branch:** `wp-durability-dedup` (already created). Autonomous commits within the branch; **HOLD PUSH** until owner's word; squash-merge presented for approval after the final whole-branch review.

---

## File Structure

```
src/dds-rtps/message.lisp     MOD — +pid-original-writer-info+; encode-original-writer-info;
                                    parse-original-writer-info; extend write-data (optional inline-qos
                                    + Q-bit); extend parse-inline-qos-key-status (extract 0x0061);
                                    extend parse-data-body to return original-writer-info
src/dds-rtps/reliable.lisp    MOD — writer-write gains an optional inline-qos arg threaded to the
                                    cache-change; writer-proxy/reader gains an original-guid->max-sn
                                    dedup map + reader-on-data dedup gate
src/dds-rtps/packages.lisp    MOD — export the new symbols the tests/durability touch
src/dds-disc/dataplane.lisp   MOD — thread parsed original-writer-info from %on-user-data to the
                                    reader dedup; a relay publish path (publish-sample gains an
                                    original-(guid,sn) arg, or a sibling publish-relay-sample)
src/dds-disc/packages.lisp    MOD — export any new disc symbol the durability service needs
src/dds-durability/store.lisp MOD — durable-record already has kind; ensure lifecycle records storable
src/dds-durability/service.lisp MOD — relay emit attaches the PID; collect drains lifecycle changes;
                                    make-durability-service/service-start generalize to N disc-nodes
src/dds-durability/packages.lisp MOD — export any new durability symbol
src/dds-tests/durability-test.lisp MOD — dedup/multi-topic/dispose integration tests
src/dds-tests/rtps-test.lisp  MOD — PID byte-exact vector + encode/decode + dedup unit tests
src/dds-tests/pbt-test.lisp   MOD — PID-parse fuzz arm (safety-0)
src/dds-tests/packages.lisp + echo-test.lisp MOD — export + register new run-* tests
docs/adr/0024-durability-dedup.md NEW (Task 7)
docs/wiki/durability.md, README.md, docs/verification.csv MOD (Task 7)
interop/durability-dedup/     NEW (Tasks 3+7) — foreign late-joiner + RTI-PS-coexistence harness + captures
```

---

## Task 1: `PID_ORIGINAL_WRITER_INFO` codec (constant + encode + parse + byte-exact vector)

**Goal:** The standard PID codec — encode the 24-byte `OriginalWriterInfo` body and parse it — pinned byte-exact against the spike capture. No behavior change to any send/receive path yet.

**Files:** Modify `src/dds-rtps/message.lisp`, `src/dds-rtps/packages.lisp`; Test `src/dds-tests/rtps-test.lisp` (+ export/register).

**Interfaces:**
- Consumes: `dds.core.buffer` cursor API (`put-u16`/`put-octets`/`put-u8`/`get-u16`/etc.), `write-parameter`/`write-parameter-sentinel` (`message.lisp`), the existing `+pid-*+` constant style.
- Produces:
  - `+pid-original-writer-info+` = `#x0061` (defconstant, docstring citing RTPS 2.5 §8.3.5.4 + Table 9.12).
  - `(encode-original-writer-info guid sn)` → `(simple-array (unsigned-byte 8) (24))`. `guid` = `(simple-array (unsigned-byte 8) (16))` (12-byte prefix + 4-byte entityId), `sn` = `(integer 0)`. Body LE: guid[0..15] verbatim, then SN.high = `(ldb (byte 32 32) sn)` as int32 LE, SN.low = `(ldb (byte 32 0) sn)` as uint32 LE.
  - `(parse-original-writer-info octets off len)` → `(values guid sn)` or `(values nil nil)` if `len ≠ 24` or the body would overrun (bounds-checked). `guid` = a fresh 16-octet array, `sn` = reconstructed `(integer 0)`.
  - `(write-original-writer-info-parameter cursor guid sn)` → writes the full parameter (pid + len=24 + body) via `write-parameter` (so framing/alignment matches the existing emitter).

- [ ] **Step 1: Write the failing byte-exact test** in `src/dds-tests/rtps-test.lisp` (package `dds.tests`), using `%check`. Pin the vector to the spike capture (findings §3.2): original GUID prefix `01 01 66 f2 8f 4f 79 5f a0 8e cd a9`, entityId `80 00 00 02`, SN=1 → body bytes `01 01 66 f2 8f 4f 79 5f a0 8e cd a9 80 00 00 02 00 00 00 00 01 00 00 00`.
```lisp
(defun* run-original-writer-info-vector-test ()
    (function () t)
  "PID_ORIGINAL_WRITER_INFO (0x0061) byte-exact encode/decode vs the spike capture (RTPS 2.5 §8.3.5.4)."
  (let* ((guid (make-array 16 :element-type '(unsigned-byte 8)
                           :initial-contents '(#x01 #x01 #x66 #xf2 #x8f #x4f #x79 #x5f
                                               #xa0 #x8e #xcd #xa9 #x80 #x00 #x00 #x02)))
         (sn 1)
         (expect (make-array 24 :element-type '(unsigned-byte 8)
                             :initial-contents '(#x01 #x01 #x66 #xf2 #x8f #x4f #x79 #x5f
                                                 #xa0 #x8e #xcd #xa9 #x80 #x00 #x00 #x02
                                                 #x00 #x00 #x00 #x00 #x01 #x00 #x00 #x00)))
         (body (dds.rtps.message:encode-original-writer-info guid sn)))
    (%check :owi-encode (equalp body expect)
            (format nil "OriginalWriterInfo body mismatch: ~s vs ~s" body expect))
    (multiple-value-bind (g s) (dds.rtps.message:parse-original-writer-info body 0 24)
      (%check :owi-decode-guid (equalp g guid) "round-trip GUID mismatch")
      (%check :owi-decode-sn (eql s 1) "round-trip SN mismatch"))
    ;; large SN exercises the high word
    (let* ((big (+ (ash 1 33) 7))
           (b2 (dds.rtps.message:encode-original-writer-info guid big)))
      (multiple-value-bind (g s) (dds.rtps.message:parse-original-writer-info b2 0 24)
        (declare (ignore g))
        (%check :owi-bigsn (eql s big) "high-word SN round-trip mismatch")))
    ;; bounds: wrong length -> (nil nil), never an error/OOB
    (multiple-value-bind (g s) (dds.rtps.message:parse-original-writer-info body 0 20)
      (%check :owi-badlen (and (null g) (null s)) "len/=24 must yield (nil nil)"))
    t))
```
- [ ] **Step 2: Run it, verify FAIL** (`encode-original-writer-info` undefined): `make test-sbcl 2>&1 | grep -E "original-writer-info|undefined|FAIL"`.
- [ ] **Step 3: Implement** in `message.lisp`: the `defconstant`, `encode-original-writer-info` (build the 24-byte array — guid verbatim, SN split into LE int32 high + uint32 low), `parse-original-writer-info` (validate `len = 24` + `(+ off 24) <= (length octets)` → else `(values nil nil)`; read guid + SN), `write-original-writer-info-parameter` (via `write-parameter cursor +pid-original-writer-info+ body 0 24`). All `defun*`-typed. Export the four symbols from `src/dds-rtps/packages.lisp`.
- [ ] **Step 4: Run it, verify PASS** both impls + `make gate-types`. Register `run-original-writer-info-vector-test` in the `run-all-tests` alist (echo-test.lisp) + export from `src/dds-tests/packages.lisp`.
- [ ] **Step 5: Commit** `feat(rtps): WP-DURABILITY-DEDUP — PID_ORIGINAL_WRITER_INFO (0x0061) codec + byte-exact vector (M6/P5, RTPS 2.5 §8.3.5.4)`.

---

## Task 2: Outbound inline-QoS on `write-data` (Q-bit), inert by default

**Goal:** Extend the DATA emit path to carry optional inline QoS (set the Q-bit, write the parameter list before the payload) sourced from the `cache-change.inline-qos` slot; default nil → byte-identical wire.

**Files:** Modify `src/dds-rtps/message.lisp` (`write-data`), `src/dds-rtps/reliable.lisp` (thread `inline-qos` from the change into the DATA build + `writer-write` optional arg); Test `src/dds-tests/rtps-test.lisp`.

**Interfaces:**
- Consumes: `write-data` (current sig `(cursor reader-id writer-id writer-sn payload payload-off payload-len &key key)`), `write-parameter`/`write-parameter-sentinel`, `+data-flag-inline-qos+`, the cache-change emit site in `reliable.lisp`.
- Produces:
  - `write-data` gains `&key inline-qos` (`(or null (simple-array (unsigned-byte 8) (*)))`, default nil). When non-nil: OR `+data-flag-inline-qos+` into the flags, grow the submessage octetsToNextHeader by the (4-aligned) inline-QoS length, and write the inline-QoS bytes (a complete ParameterList INCLUDING its sentinel — the caller supplies a sentinel-terminated list) between the header and the payload. When nil: byte-identical to today (no Q-bit, no extra bytes).
  - `writer-write` gains `&optional (key-hash nil) (inline-qos nil)` → stored on the `cache-change` `inline-qos` slot; the DATA-build path passes `(cache-change-inline-qos change)` to `write-data :inline-qos`.

- [ ] **Step 1: Failing test** `run-data-inline-qos-emit-test` — build a DATA submessage two ways via the message codec into a buffer: (a) no inline-qos → assert the bytes equal the pre-change `write-data` output (Q-bit clear) — capture the baseline by calling `write-data` without the key; (b) with a 28-byte inline-qos blob (a PID_ORIGINAL_WRITER_INFO parameter + sentinel from Task 1's `write-original-writer-info-parameter` into a scratch cursor, then a sentinel) → assert the Q-bit (`+data-flag-inline-qos+`) is set in the emitted flags byte and the inline-QoS bytes appear before the payload. Parse it back with `parse-data-body` and assert the payload round-trips and `parse-data-body` reports inline-QoS present. Use `%check`.
- [ ] **Step 2: Run, verify FAIL** (`write-data` rejects `:inline-qos`).
- [ ] **Step 3: Implement** the `write-data` extension + the `reliable.lisp` threading (`writer-write` optional `inline-qos`, the DATA build reads `cache-change-inline-qos`). Keep the nil path byte-identical (do NOT change the no-inline-qos branch's header math). Export `writer-write` already exported; export nothing new unless needed.
- [ ] **Step 4: Run** both impls + `make gate-types` + **`make wire`** (the tshark gate MUST still pass — the default DATA path is unchanged; the new path, if exercised by a wire test, must dissect cleanly). Expected PASS. Confirm the existing wire/corpus tests are unchanged (byte-identical default).
- [ ] **Step 5: Commit** `feat(rtps): WP-DURABILITY-DEDUP — write-data optional inline-QoS + Q-bit (default nil = byte-identical); writer-write inline-qos arg (M6/P5, RTPS 2.5 §9.4.5.4)`.

---

## Task 3: Relay emit — service attaches PID_ORIGINAL_WRITER_INFO; foreign late-joiner receives it (cross-DDS leg A)

**Goal:** The durability service's replay writer attaches PID_ORIGINAL_WRITER_INFO (from the store's recorded original `(GUID, SN)`) to every relayed sample; a foreign Connext/Fast DDS late-joiner receives our relayed history with the PID byte-exact on the wire.

**Files:** Modify `src/dds-disc/dataplane.lisp` (a relay publish path — `publish-sample` gains `&key original-guid original-sn`, or a sibling `publish-relay-sample`; when given, it builds the PID via `write-original-writer-info-parameter` into the change's inline-qos), `src/dds-disc/packages.lisp`; `src/dds-durability/service.lisp` (the replay write passes the stored original GUID+SN). Test/interop: `interop/durability-dedup/`.

**Interfaces:**
- Consumes: Task-1 `encode-original-writer-info`/`write-original-writer-info-parameter`, Task-2 `write-data :inline-qos` + `writer-write inline-qos`, the store's `durable-record-writer-guid`/`-sn`, the Phase-1 replay path.
- Produces: a disc publish path that, given an original `(guid, sn)`, emits the relayed DATA with PID_ORIGINAL_WRITER_INFO inline QoS. The durability replay uses it for every stored record.

- [ ] **Step 1: Failing our-stack wire test** `run-relay-emit-test` — a durability service collects N samples from an our-stack publisher; on replay to a late-joiner, assert (via the message parser on the captured outbound bytes, or via a loopback reader that surfaces the parsed inline-QoS) that each relayed DATA carries PID_ORIGINAL_WRITER_INFO with the ORIGINAL writer's GUID + SN (not the relay writer's). Build on the Phase-1 `run-durability-transient-test` harness. `%check` the PID's GUID == the original publisher's GUID and SN == the original SN.
- [ ] **Step 2: Run, verify FAIL** (relay emits no PID).
- [ ] **Step 3: Implement** the disc relay publish path + wire the durability replay to pass each record's `(writer-guid, sn)`. Keep non-relay `publish-sample` byte-identical (the new args default nil → no PID).
- [ ] **Step 4: Run** both impls + `make gate-types mem` (mem 0.0000). Then the **cross-DDS leg A** (interop, agent runs the peers): a foreign Connext 7.3.1 + Fast DDS 3.6.1 late-joiner receives our relayed history after the original writer exits; `tshark -O rtps` shows `PID_ORIGINAL_WRITER_INFO` with the original GUID+SN byte-exact on our relayed DATA. Build `interop/durability-dedup/` mirroring `interop/durability-transient/`. Document legs + caveats.
- [ ] **Step 5: Commit** `feat(disc): WP-DURABILITY-DEDUP — relay writer emits PID_ORIGINAL_WRITER_INFO; foreign late-joiner receives it byte-exact, LIVE vs Connext 7.3.1 + Fast DDS 3.6.1 (M6/P5)`.

---

## Task 4: Receiver-side dedup — original-GUID max-SN gate (the headline no-double-delivery)

**Goal:** Our reader extracts PID_ORIGINAL_WRITER_INFO on inbound DATA and dedups by `max-received-SN[originalGUID]`, so a reader matched to BOTH the (alive) original writer AND a relay receives each sample exactly once. Inert when the PID is absent.

**Files:** Modify `src/dds-rtps/message.lisp` (extend `parse-inline-qos-key-status` → also return original-writer-info; extend `parse-data-body`'s return), `src/dds-rtps/reliable.lisp` (a `reader` dedup map + `reader-on-data` gate, or a `%reader-apply-original-writer-info` step), `src/dds-disc/dataplane.lisp` (`%on-user-data` threads the parsed original-writer-info to the dedup), packages. Test `src/dds-tests/rtps-test.lisp` + `durability-test.lisp`.

**Interfaces:**
- Consumes: Task-1 `parse-original-writer-info`; the existing `parse-inline-qos-key-status`/`parse-data-body`; `reader-on-data` (`(reader writer-id sn payload)`), `writer-proxy`.
- Produces:
  - `parse-inline-qos-key-status` (or a renamed/extended `parse-inline-qos`) additionally returns `(values … original-guid original-sn)` — nil/nil when PID absent. `parse-data-body` propagates them.
  - A per-reader `original-guid → max-sn` dedup map (a hash-table keyed by the 16-octet GUID via `equalp`, on the `rtps-reader`). A `(reader-dedup-accept-p reader original-guid original-sn)` → `boolean` (T = fresh/accept + updates max; NIL = duplicate/discard). PID-absent path never consults it.
  - `%on-user-data` discards the sample (does not deliver/store) when `reader-dedup-accept-p` returns NIL.

- [ ] **Step 1: Failing unit test** `run-original-writer-dedup-test` (rtps-test.lisp) — drive the dedup gate directly: same `originalGUID`, SNs 1,2,2,3 → accept,accept,DISCARD,accept; a different `originalGUID` is tracked independently; the PID-absent path (nil guid) never discards (normal per-writer SN tracking unaffected). Plus an integration test `run-durability-no-double-delivery-test` (durability-test.lisp): an original writer stays ALIVE while the service relays the same samples; a reader matched to both receives each sample EXACTLY ONCE (count == N, not 2N). Use `%check`.
- [ ] **Step 2: Run, verify FAIL** (no dedup map; reader receives duplicates → count 2N).
- [ ] **Step 3: Implement** the parser extension + the reader dedup map + the `%on-user-data` discard gate. Bounds-check the PID parse (Task 1 already returns nil/nil on bad len → treat as no-PID). Keep the PID-absent path byte-identical + SN tracking untouched.
- [ ] **Step 4: Run** both impls + `make gate-hotpath gate-types mem fuzz` (mem 0.0000; gate-hotpath clean — the dedup is control-plane). Expected PASS.
- [ ] **Step 5: Commit** `feat(rtps): WP-DURABILITY-DEDUP — receiver-side original-GUID max-SN dedup; no-double-delivery with a live original writer + relay (M6/P5, RTPS 2.5 §8.3.5.4)`.

---

## Task 5: Multi-topic service — N disc-nodes per service

**Goal:** A `durability-service` for a spec resolving to K `(topic . type)` pairs holds K single-endpoint disc-nodes (one per topic); collect/replay fan across them; the store is per-topic. K=1 byte-identical to Phase 1.

**Files:** Modify `src/dds-durability/service.lisp` (`make-durability-service`/`service-start`/`service-stop`/`service-alive-p` generalize from 1 node to a list of nodes; one collect loop per node), `src/dds-durability/packages.lisp`. Test `src/dds-tests/durability-test.lisp`.

**Interfaces:**
- Consumes: the Phase-1 single-node service internals; `service-spec-topics` (list of `(topic . type)` OR predicate); the store API.
- Produces: `durability-service` holds a `nodes` list (one disc-node + one collect thread per resolved topic), a shared store. `service-start` resolves the spec's topics to K concrete pairs, builds + starts K nodes, spawns K collect loops; `service-stop` joins+stops all K (join-before-stop-node per node — the Phase-1 ordering); `service-alive-p` T iff all node threads live. The single-topic path (K=1) is behavior-identical.

- [ ] **Step 1: Failing test** `run-durability-multitopic-test` — a service with topics `(("Square"."ShapeType") ("Circle"."ShapeType"))`; an our-stack publisher writes TRANSIENT_LOCAL samples to BOTH; assert the service collected both topics into the (per-topic) store and a late-joiner on EACH topic receives that topic's retained history; `service-stop` cleanly tears down all nodes (no warning — pristine). Use `%check`, bounded settle loops.
- [ ] **Step 2: Run, verify FAIL** (service handles one topic only).
- [ ] **Step 3: Implement** the N-node generalization. Resolve a predicate-topics spec to the concrete topics matched at start (document dynamic-add as deferred per design §6). Preserve the Phase-1 join-before-stop-node teardown PER node.
- [ ] **Step 4: Run** both impls + `make gate-types`. Confirm K=1 still passes the Phase-1 `run-durability-transient-test`. Expected PASS, pristine.
- [ ] **Step 5: Commit** `feat(durability): WP-DURABILITY-DEDUP — multi-topic service (N disc-nodes, one per topic) (M6/P5, ADR 0023)`.

---

## Task 6: Dispose/unregister capture + replay

**Goal:** The collect loop captures dispose/unregister lifecycle changes into the store; replay re-emits them (with PID_ORIGINAL_WRITER_INFO) so a late-joiner sees an instance was disposed/unregistered before it joined.

**Files:** Modify `src/dds-durability/service.lisp` (collect drains lifecycle changes; replay re-emits via `writer-lifecycle-change`), `src/dds-durability/store.lisp` (store + return lifecycle records with `kind`). Test `src/dds-tests/durability-test.lisp`.

**Interfaces:**
- Consumes: `dds.disc` `node-lifecycle-change` → `(kind key-hash status-flags writer-id source-guid)`, the `disc-node-on-lifecycle` hook (set it in `service-start`); `writer-lifecycle-change` (`(writer key-hash status-flags)`) for replay (extended in Task 3/4's emit path to also carry the PID); the `durable-record` `kind` field.
- Produces: the collect loop stores `:dispose`/`:unregister` records keyed by original `(writerGUID, SN, key-hash)`; replay emits them in original-SN order interleaved with data, with PID_ORIGINAL_WRITER_INFO attached (so they dedup identically).

- [ ] **Step 1: Failing test** `run-durability-dispose-replay-test` — an our-stack publisher writes N samples then DISPOSES an instance (via the DCPS/disc dispose path), then exits; the service collected the data + the dispose; a late-joiner receives the data history AND the dispose (assert the late-joiner observes the instance as NOT_ALIVE_DISPOSED, or — at the disc level — receives a lifecycle change of kind `:dispose` for that key). Use `%check`.
- [ ] **Step 2: Run, verify FAIL** (lifecycle changes not collected/replayed).
- [ ] **Step 3: Implement** the lifecycle capture (set `disc-node-on-lifecycle` in `service-start`; drain into the store) + the replay (re-emit stored lifecycle records via `writer-lifecycle-change`, ordered with data by original SN). Attach the PID on the lifecycle replay path too.
- [ ] **Step 4: Run** both impls + `make gate-types mem`. Expected PASS.
- [ ] **Step 5: Commit** `feat(durability): WP-DURABILITY-DEDUP — dispose/unregister capture + replay (late-joiner sees pre-join instance disposal) (M6/P5, DDS 1.4 §2.2.3.4)`.

---

## Task 7: Foreign-service coexistence (cross-DDS leg B) + capstone

**Goal:** The headline cross-DDS DoD — RTI Persistence Service AND our service relay the same TRANSIENT topic; a late-joiner matched to both receives NO duplicates (our `originalGUID` matches RTI's, so the receiver dedups across both). Plus ADR + docs + full gate sweep + final review.

**Files:** `interop/durability-dedup/` (RTI-PS-coexistence harness + captures); `docs/adr/0024-durability-dedup.md` (NEW); `docs/wiki/durability.md`, `README.md`, `docs/verification.csv` (MOD); `src/dds-tests/pbt-test.lisp` (PID-parse fuzz arm).

- [ ] **Step 1: PID-parse fuzz arm** — add a `parse-original-writer-info` / inline-QoS-parse arm to the fuzz suite (random/short/oversized PID bodies + random inline-QoS blobs → `(nil nil)` or a valid parse, never OOB, incl. a `(safety 0)` variant). `make fuzz` green.
- [ ] **Step 2: Cross-DDS leg B (coexistence), agent runs the live peers** — start RTI Persistence Service (`rtipersistenceservice -cfgName …`, the spike-proven config) AND our durability service on the same TRANSIENT `Square`/`ShapeType` topic on `lo0`; an original Connext publisher publishes then exits; a late-joining Connext subscriber matched to BOTH relays receives each sample EXACTLY ONCE. Capture with tshark; show both relays carry the same `PID_ORIGINAL_WRITER_INFO` `originalGUID` and the subscriber's received count == the published count (no doubling). Document in `interop/durability-dedup/README.md` with honest caveats (macOS lo0 quirk; the receiver-count proof).
- [ ] **Step 3: ADR 0024** — the as-built dedup architecture: the PID codec, the inert-by-default emit/receive, the dedup rule (max-SN per originalGUID), multi-topic (N nodes), dispose/unregister, the foreign-service coexistence result, and the deliberate non-goals (vendor SEDP PIDs not emitted; dynamic-topic-add deferred). Reference ADR 0021/0022/0023 + the spike.
- [ ] **Step 4: Docs lockstep** — `docs/wiki/durability.md` (dedup + multi-topic + dispose sections + a worked example), README P5 row update (dedup/coexistence now done; what remains = PERSISTENT slice), `docs/verification.csv` row update.
- [ ] **Step 5: Full gate sweep both impls** — `make test-sbcl`/`test-clasp` (≥ prior count), `make gate-hotpath gate-types mem fuzz wire` — all green; mem 0.0000.
- [ ] **Step 6: Final whole-branch review** (fresh reviewer, most capable model, over `main..wp-durability-dedup`): conformance (inert-by-default byte-identical; no false-reject; dedup discards only true duplicates), the byte-exact PID, NFR-MEM (bounded dedup map), NFR-SEC-POSTURE (bounds-checked PID parse), no reader conditionals, docs lockstep, no AI attribution. Fix findings (re-run the covering gate per fix).
- [ ] **Step 7: Commit** `docs(durability): WP-DURABILITY-DEDUP — ADR 0024 + wiki/README/verification + RTI-PS coexistence + PID fuzz; Phase-2 capstone (M6/P5)`; then present the squash-merge for owner approval (HOLD PUSH).

---

## Self-review (author checklist — completed)

- **Spec coverage:** §5 dedup emit→Task 3, receive→Task 4; §4 PID codec→Task 1, write-data inline-QoS→Task 2; §6 multi-topic→Task 5; §7 dispose/unregister→Task 6; §9 foreign coexistence + fuzz + gates→Task 7; §2 decisions (full scope, N-nodes, inline-QoS-from-cache-change) all reflected; §11 out-of-scope (PERSISTENT/DARE, dynamic-topic-add, vendor SEDP PIDs) preserved.
- **Placeholder scan:** no TBD/TODO; every code step shows real, signature-verified code or a precisely-bounded instruction; the byte-exact vector is pinned to the spike hex.
- **Type/name consistency:** `encode-original-writer-info`/`parse-original-writer-info`/`write-original-writer-info-parameter`/`+pid-original-writer-info+` consistent T1→T2→T3→T4; `write-data :inline-qos` + `writer-write` inline-qos arg consistent T2→T3; `reader-dedup-accept-p` + the original-guid→max-sn map consistent T4; the N-nodes service API (`service-start`/`-stop`/`-alive-p`) consistent T5→T6; `node-lifecycle-change`/`writer-lifecycle-change`/`durable-record` kind consistent T6.
- **Inert-by-default** is the spine: T2 (default nil byte-identical), T4 (PID-absent untouched) — both gated on `make wire`/existing tests unchanged.
