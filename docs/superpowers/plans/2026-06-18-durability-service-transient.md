# TRANSIENT Durability Service — Implementation Plan (Phase 1: slices 1–4)

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Deliver the embedded TRANSIENT durability service — a participant that collects durable samples, stores them (in-memory), and replays them to a late-joiner that discovers the topic AFTER the original writer is gone — with the multi-service runner, OTP-style supervisor, thread/subprocess execution, and the `durability-service-main` CLI.

**Architecture:** A new ASDF system `dds-durability` layered on `dds-dcps`/`dds-disc`/`dds-pal`. A `durable-store` closure-vtable (in-memory impl) holds collected samples keyed by original `(writerGUID, SN)`. A `durability-service` wraps a `disc-node` with a collecting reader (poll-drained into the store) and a replaying writer (publishes the store; the shipped reliable late-joiner machinery does the actual delivery). A `service-runner` starts N services in thread or subprocess mode; a `supervisor` restarts them one-for-one with a restart-intensity cap; `durability-service-main` is the CLI/env entrypoint reused as the subprocess body.

**Tech Stack:** Common Lisp (SBCL + Clasp gated; AllegroCL where available), ASDF, `dds.pal` threading, `uiop:launch-program` for subprocess mode, the existing `dds.disc` embedded-participant data plane, `dds.qos` QoS model.

## Phasing (read first)

This plan is **Phase 1 = spec slices 1–4** (Task 1 the spike; Tasks 2–10 the store + our-stack relay + runner/supervisor/CLI + an our-service→foreign-late-joiner interop leg). **Phase 1 deliberately adds NOTHING new to the wire** — it relays the *writer-is-gone* late-joiner case, which has a single source (our service) and needs no dedup.

**Phase 2 (spec slices 5–6) is a SEPARATE plan, authored after Task 1's spike pins the vendor virtual/persistence-GUID wire format and Phase 1 lands.** It adds the original-identity inline-QoS carrier, the no-double-delivery dedup (our-stack and foreign), and foreign-durability-service coexistence. The codebase today has NO `PID_PERSISTENCE_GUID`/`PID_GROUP_GUID`/sample-identity carrier (confirmed), so committing any such wire format before the spike would violate the spike-first decision.

## Global Constraints

(Every task implicitly includes these — from the operating contract, `REQUIREMENTS.md`, the memory, and ADR 0021/0022.)

- **`defun*` for every function, `defstruct*` for every struct** (owner directive; `dds.lang`, `src/dds-lang/lisp-lang-tools.lisp`). `defun*` = `(defun* name lambda-list (function (arg-types…) result-type) "docstring" body…)`; the signature's required-arg count must match; docstring mandatory non-empty. `defstruct*` = `(defstruct* (name (:constructor make-name)) "docstring" (slot default :type type)…)`; every slot needs `:type`.
- **Full type declarations** (REQUIREMENTS FR-LANG-8): every param typed, every function fully ftype-specified. `make gate-types` enforces it.
- **OMG-conformance is non-negotiable** (memory): never deviate from DDS 1.4 / DDSI-RTPS 2.5; the ONLY allowed extension is interop behavior ADDED ON TOP of conforming behavior, never replacing it. **A false-REJECT is the worst defect class.** DURABILITY defaults to VOLATILE → byte-identical wire when the service is absent.
- **No hot-path CLOS / no per-sample heap alloc** (NFR-CLOS/NFR-MEM): the durability service is a control-plane entity (NOT the measured CDR hot path), so CLOS-free is not required here, BUT store growth must be bounded (RESOURCE_LIMITS-style reject on a full store, never unbounded heap growth, never silent loss). `make mem` must stay 0.0000 on the CDR path (the service adds no per-sample CDR work).
- **Bounds-check every wire-facing / config-facing parse** (NFR-SEC-POSTURE), even at `(safety 0)`.
- **No reader conditionals** (`#+sbcl`/`#+clasp`) outside `dds-pal/`. Per-impl behavior goes through `dds.pal` or the `(dds.pal:pal-impl-name)` skip pattern in tests.
- **No AI-assistant attribution** anywhere in the repo (commits, ADRs, docs, source). Cite "the operating contract", never the agent-config filename. No `Co-Authored-By` trailer.
- **Docs in lockstep** (the operating contract §5.1): any exported symbol gets a docstring; touch the wiki/README/verification.csv in the same unit of work. **SBOM** auto-regenerates via the pre-commit hook (`make hooks` once per clone) — never hand-edit `sbom.spdx.json`.
- **DoD per task:** compiles + tests green on SBCL AND Clasp (or a documented NFR-PORT gap); applicable gates green (`make test gate-hotpath gate-types mem fuzz`); commit references the WP id + requirement id. **Cross-DDS interop per feature** (Connext 7.3.1 + Fast DDS 3.6.1, agent runs both live peers) — applies at the interop task (Task 9).
- **Branch:** `wp-durability-service-transient` (already created). Commits autonomous within the branch; **HOLD PUSH** until owner's word; squash-merge presented for approval after the final whole-branch review.

---

## File Structure

```
dds-durability.asd                         NEW  — the ASDF system (sibling of dds-shapes.asd)
src/dds-durability/packages.lisp           NEW  — defpackage net.goenninger.dds.durability (nick dds.durability)
src/dds-durability/store.lisp              NEW  — durable-store closure-vtable + make-memory-store
src/dds-durability/spec.lisp               NEW  — service-spec struct + topic-filter matching
src/dds-durability/service.lisp            NEW  — durability-service (collect + replay over a disc-node)
src/dds-durability/runner.lisp             NEW  — service-runner (registry; thread/subprocess start)
src/dds-durability/supervisor.lisp         NEW  — OTP-style one-for-one supervisor + restart-intensity
src/dds-durability/main.lisp               NEW  — durability-service-main CLI/env entrypoint
src/dds-tests/durability-test.lisp         NEW  — unit + integration tests; registered in run-all-tests
src/dds-tests/dds-tests.asd                MOD  — add "durability-test" component  (file is dds-tests.asd at root)
dds-tests.asd                              MOD  — add :depends-on "dds-durability" + the component
dds.asd                                    MOD  — add "dds-durability" to umbrella :depends-on
docs/adr/0023-durability-service-architecture.md   NEW (Task 10)
docs/wiki/durability.md                    NEW (Task 10)
docs/verification.csv                      MOD (Task 10)
README.md                                  MOD (Task 10)
interop/durability-transient/              NEW (Task 9) — foreign-late-joiner interop harness + README
docs/superpowers/spikes/2026-06-18-durability-virtual-guid-findings.md  NEW (Task 1)
```

Package skeleton (Task 2 creates it; later tasks extend the export list):

```lisp
(defpackage #:net.goenninger.dds.durability
  (:nicknames #:dds.durability)
  (:use #:common-lisp #:net.goenninger.dds.lang)
  (:documentation
   "DDS.DURABILITY — the embedded TRANSIENT durability/persistence service (ADR 0021 slice 2):
    collect durable samples, store them (pluggable), replay to late-joiners. DDS 1.4 §2.2.3.4.")
  (:export #:durable-store #:make-memory-store #:store-put #:store-get-range #:store-topics
           #:store-purge #:store-open #:store-close #:store-count
           #:service-spec #:make-service-spec #:service-spec-matches-p
           #:durability-service #:make-durability-service #:service-start #:service-stop #:service-alive-p
           #:service-runner #:make-service-runner #:runner-start #:runner-stop #:runner-status
           #:supervisor #:make-supervisor #:supervisor-start #:supervisor-stop
           #:durability-service-main #:*durability-error-hook*))
```

---

## Task 1: Spike — foreign durability-service tooling + virtual-GUID wire format

**Goal:** Determine what foreign durability tooling runs here and capture/identify the virtual-GUID dedup wire format that Phase 2 will implement. **Investigation only — produces a findings doc, NO production code.**

**Files:**
- Create: `docs/superpowers/spikes/2026-06-18-durability-virtual-guid-findings.md`
- Create (if captures taken): `interop/durability-transient/captures/spike-*.pcap`

**Interfaces:** Produces — a findings doc that Phase 2's plan consumes (the PID id(s), their layout, the dedup rule, and the tooling-availability verdict).

- [ ] **Step 1: Probe tooling availability.** Run, recording output in the findings doc:
  - `which rtipersistenceservice` and the Connext install (`$NDDSHOME` / `rtipkginstall` layout); try `rtipersistenceservice -help`.
  - Fast DDS persistence: confirm the SQLite/`TRANSIENT_LOCAL`+persistence plugin is buildable/runnable (`fastdds` tooling, the persistence example).
  - Verdict per peer: **runnable here / not runnable**.
- [ ] **Step 2: If runnable, capture durable replay.** Start a foreign durable publisher (TRANSIENT) + the foreign persistence service, let it collect, kill the original publisher, then start a foreign late-joining reader. Capture on `lo0` with `tcpdump`/`tshark`. Save the pcap.
- [ ] **Step 3: Identify the dedup carrier.** Dissect the relayed DATA submessages (`tshark -O rtps -r <pcap>`). Find the inline-QoS parameter that carries the ORIGINAL writer identity (RTI `PID_PERSISTENCE_GUID` ~0x8002, or `PID_GROUP_GUID`, or a vendor PID in the 0x8000+ range; Fast DDS equivalent). Record: the PID id, octet layout, and how the late-joiner uses it to dedup against the original writer. Clean-room: observe the wire only; never read RTI source.
- [ ] **Step 4: Write the findings doc.** Sections: tooling verdict (per peer); the captured PID(s) + byte layout + spec/clue citations; the dedup rule; whether inter-service coordination beyond the GUID is observable (and if not, the documented gap); a concrete recommendation for Phase 2's conformant-substrate + vendor-PID design. If tooling is NOT runnable, state it plainly and record the fallback (Phase 2 conformant-substrate designed from the OMG spec + the DDS-RTPS "GUID + SN" identity, vendor interop deferred with a documented assumption).
- [ ] **Step 5: Commit.**
```bash
git add docs/superpowers/spikes/2026-06-18-durability-virtual-guid-findings.md interop/durability-transient/captures 2>/dev/null
git commit -m "spike(durability): WP-DURABILITY-SERVICE-TRANSIENT — foreign virtual-GUID dedup wire format + tooling availability (M6/P5)"
```

---

## Task 2: `dds-durability` system + `durable-store` protocol + in-memory store

**Goal:** The ASDF system skeleton + the pluggable persistence vtable + an in-memory implementation, with store-conformance tests. No DDS yet.

**Files:**
- Create: `dds-durability.asd`, `src/dds-durability/packages.lisp`, `src/dds-durability/store.lisp`
- Create: `src/dds-tests/durability-test.lisp`
- Modify: `dds.asd` (umbrella `:depends-on`), `dds-tests.asd` (`:depends-on` + component), `src/dds-tests/packages.lisp` (export `#:run-durability-store-test`), `src/dds-tests/echo-test.lisp` (register in `run-all-tests` alist)

**Interfaces:**
- Consumes: `dds.lang:defun*`/`defstruct*`; `dds.pal:make-lock`/`with-lock`.
- Produces (the store vtable — Tasks 4/5 consume it):
  - `(make-memory-store &key (max-samples 0))` → `durable-store`. `max-samples 0` = unbounded.
  - `(store-put store topic writer-guid sn key-hash kind payload)` → `(or (eql t) (eql :rejected))`. `writer-guid` = `(simple-array (unsigned-byte 8) (16))`, `sn` = `(integer 0)`, `key-hash` = `(or null (simple-array (unsigned-byte 8) (16)))`, `kind` = `(member :data :dispose :unregister)`, `payload` = `(simple-array (unsigned-byte 8) (*))`. Idempotent on `(topic, writer-guid, sn)` (a re-collected retransmit is not double-stored). `:rejected` when a finite `max-samples` is full.
  - `(store-get-range store topic)` → a `list` of `durable-record` structs ordered by `(writer-guid, sn)`. (A `durable-record` is a `defstruct*` with slots `topic writer-guid sn key-hash kind payload`.)
  - `(store-topics store)` → list of topic strings with ≥1 record.
  - `(store-count store &optional topic)` → `(integer 0)` total or per-topic record count.
  - `(store-purge store topic)` → `(eql t)`; `(store-open store)`/`(store-close store)` → `(eql t)` (in-memory: no-ops returning T; the file/db plugs use them).

- [ ] **Step 1: Write the failing test** in `src/dds-tests/durability-test.lisp` (package `dds.tests`). Use the verified `%check` helper from `echo-test.lisp`.
```lisp
(defun* run-durability-store-test ()
    (function () t)
  "In-memory durable-store: put/get-range ordering, idempotent re-put, topic isolation, bounded reject."
  (let ((s (dds.durability:make-memory-store :max-samples 0))
        (g0 (make-array 16 :element-type '(unsigned-byte 8) :initial-element 0))
        (g1 (make-array 16 :element-type '(unsigned-byte 8) :initial-element 1))
        (p (lambda (b) (make-array (length b) :element-type '(unsigned-byte 8) :initial-contents b))))
    (%check :put1 (eq t (dds.durability:store-put s "A" g0 2 nil :data (funcall p '(2)))) "put sn2")
    (%check :put2 (eq t (dds.durability:store-put s "A" g0 1 nil :data (funcall p '(1)))) "put sn1")
    (%check :put-dup (eq t (dds.durability:store-put s "A" g0 1 nil :data (funcall p '(9)))) "re-put sn1 ok")
    (%check :count-dedup (= 2 (dds.durability:store-count s "A")) "re-put must not double-store")
    (let ((recs (dds.durability:store-get-range s "A")))
      (%check :order (and (= 1 (dds.durability:durable-record-sn (first recs)))
                          (= 2 (dds.durability:durable-record-sn (second recs)))) "get-range ordered by sn"))
    (dds.durability:store-put s "B" g1 1 nil :data (funcall p '(7)))
    (%check :topic-isolation (and (= 2 (dds.durability:store-count s "A"))
                                  (= 1 (dds.durability:store-count s "B"))) "topics isolated")
    (%check :topics (equal '("A" "B") (sort (copy-list (dds.durability:store-topics s)) #'string<)) "topics list")
    (let ((bs (dds.durability:make-memory-store :max-samples 1)))
      (dds.durability:store-put bs "A" g0 1 nil :data (funcall p '(1)))
      (%check :bounded (eq :rejected (dds.durability:store-put bs "A" g0 2 nil :data (funcall p '(2)))) "full store rejects"))
    t))
```
- [ ] **Step 2: Create `dds-durability.asd`** (sibling of `dds-shapes.asd`):
```lisp
;;;; L9 — the embedded TRANSIENT durability/persistence service (ADR 0021 slice 2).
(defsystem "dds-durability"
  :description "DDS.DURABILITY — embedded TRANSIENT durability service: collect, store, replay to late-joiners."
  :depends-on ("dds-core" "dds-pal" "dds-qos" "dds-types" "dds-disc" "dds-dcps")
  :pathname "src/dds-durability"
  :serial t
  :components ((:file "packages")
               (:file "store"))
  :in-order-to ((test-op (test-op "dds-tests"))))
```
- [ ] **Step 3: Create `packages.lisp`** with the `dds.durability` defpackage (export list from the File Structure section; for Task 2 you may export just the store symbols + the full list is fine — keep it complete).
- [ ] **Step 4: Implement `store.lisp`** — the `durable-record` `defstruct*`, the `durable-store` closure-vtable `defstruct*` (slots `put get-range topics purge open close count` each `(or null function)`, plus a `name` keyword slot), the public dispatch `defun*`s (one slot-read + `funcall`, mirroring `dds.xport:send`), and `make-memory-store`. In-memory backing: a `hash-table` topic→(`hash-table` (writer-guid-as-list . sn)→`durable-record`), guarded by a `dds.pal:make-lock`. `store-put` rejects when a finite `max-samples` would be exceeded; idempotent insert keyed by `(writer-guid, sn)`. `store-get-range` collects the topic's records and `sort`s by `(writer-guid, sn)`. Every function `defun*`-typed.
- [ ] **Step 5: Wire the system + register the test.** Add `"dds-durability"` to `dds.asd` and `dds-tests.asd` `:depends-on`; add `(:file "durability-test")` to `dds-tests.asd` `:components`; export `#:run-durability-store-test` from `src/dds-tests/packages.lisp`; add `("durability-store" . run-durability-store-test)` to the `run-all-tests` alist in `echo-test.lisp`.
- [ ] **Step 6: Run the test on both impls.**
```bash
sbcl --non-interactive --eval "(ql:quickload :dds-tests :silent t)" --eval "(uiop:quit (if (handler-case (dds.tests:run-durability-store-test) (error () nil)) 0 1))"
make test-clasp 2>&1 | grep -E "durability-store|tests: .* passed"
```
Expected: PASS both. Then `make gate-types` (the new defun*s ftype-clean) — PASS.
- [ ] **Step 7: Commit.**
```bash
git add dds-durability.asd src/dds-durability dds.asd dds-tests.asd src/dds-tests/packages.lisp src/dds-tests/echo-test.lisp src/dds-tests/durability-test.lisp
git commit -m "feat(durability): WP-DURABILITY-SERVICE-TRANSIENT — dds-durability system + durable-store vtable + in-memory store (M6/P5, ADR 0021)"
```

---

## Task 3: `service-spec` + topic-filter matching

**Goal:** The discrimination unit — `(domain, topic-filter)` — and a predicate that decides whether a discovered `(topic, type)` belongs to a service.

**Files:** Create `src/dds-durability/spec.lisp`; Modify `dds-durability.asd` (add component), `src/dds-tests/durability-test.lisp` (+ test), packages + alist as in Task 2.

**Interfaces:**
- Produces:
  - `(make-service-spec &key domain topics store mode qos-overrides name)` → `service-spec`. `domain` = `(integer 0)`; `topics` = either a `list` of `(topic . type)` conses OR a `function` predicate `(lambda (topic type) …)`; `store` = a 0-arg store factory `function` (default `(lambda () (make-memory-store))`); `mode` = `(member :thread :process)` (default `:thread`); `qos-overrides` = `plist` (default `nil`); `name` = `string`.
  - `(service-spec-matches-p spec topic type)` → `boolean`. A list `topics` matches by `string=` on both topic and type; a predicate `topics` is funcalled.
  - Accessors: `service-spec-domain`, `-topics`, `-store`, `-mode`, `-qos-overrides`, `-name`.

- [ ] **Step 1: Failing test** `run-durability-spec-test`:
```lisp
(defun* run-durability-spec-test ()
    (function () t)
  "service-spec topic-filter matching: explicit list and predicate forms."
  (let ((s1 (dds.durability:make-service-spec :domain 0 :topics '(("Square" . "ShapeType")) :name "shapes"))
        (s2 (dds.durability:make-service-spec :domain 0
              :topics (lambda (topic type) (declare (ignore type)) (eql 0 (search "Sensor" topic))) :name "sensors")))
    (%check :list-hit (dds.durability:service-spec-matches-p s1 "Square" "ShapeType") "list match")
    (%check :list-miss-type (not (dds.durability:service-spec-matches-p s1 "Square" "Other")) "type must match")
    (%check :list-miss-topic (not (dds.durability:service-spec-matches-p s1 "Circle" "ShapeType")) "topic must match")
    (%check :pred-hit (dds.durability:service-spec-matches-p s2 "SensorA" "X") "predicate match")
    (%check :pred-miss (not (dds.durability:service-spec-matches-p s2 "Square" "X")) "predicate miss")
    t))
```
- [ ] **Step 2: Run it, verify FAIL** (`make-service-spec` undefined).
- [ ] **Step 3: Implement `spec.lisp`** — the `service-spec` `defstruct*` + `make-service-spec` wrapper (defaults) + `service-spec-matches-p` (`etypecase` on `topics`: `list` → `assoc`/`string=`, `function` → `funcall`). All `defun*`-typed.
- [ ] **Step 4: Wire** (add `(:file "spec")` after `store` in `dds-durability.asd`; export `#:run-durability-spec-test`; alist entry).
- [ ] **Step 5: Run both impls + `make gate-types`.** Expected PASS.
- [ ] **Step 6: Commit** `feat(durability): WP-DURABILITY-SERVICE-TRANSIENT — service-spec + topic-filter matching (M6/P5)`.

---

## Task 4: `durability-service` — the collect path

**Goal:** A service that builds a `disc-node` with a collecting reader for a matched topic and drains every received sample (with its original `(writerGUID, SN)`) into the store on its own thread.

**Files:** Create `src/dds-durability/service.lisp`; Modify `dds-durability.asd`, `durability-test.lisp`, packages + alist.

**Interfaces:**
- Consumes: `dds.disc:make-disc-node`, `add-local-reader`, `enable-subscriber`, `start-node`, `stop-node`, `node-sample-sns`, `node-sample`, `node-sample-writer-guid`, `node-sample-key-sn` (verified signatures); `dds.qos:make-reader-qos`; `dds.pal:spawn`/`join`/`make-lock`; the store API (Task 2).
- Produces:
  - `(make-durability-service spec &key (store nil))` → `durability-service`. Uses `spec`'s store factory unless `store` is supplied (a shared store for tests). Holds the `service-spec`, a `durable-store`, a `disc-node`, a worker thread handle, and a `running` flag.
  - `(service-start service)` → `durability-service`: builds the node (domain from spec; a fixed durable collecting reader: `make-reader-qos :reliability :reliable :durability :transient-local :history-kind :keep-all`), starts it, and spawns the **collect loop** thread.
  - `(service-stop service)` → `(eql t)`: stops the loop, `stop-node`, joins the thread.
  - `(service-alive-p service)` → `boolean`.
  - `(durability-service-store service)` / `-node` / `-spec` accessors.
- **The collect loop:** poll `node-sample-sns`; for each not-yet-seen composite key, read `node-sample` (payload), `node-sample-writer-guid` (16-octet original GUID), `node-sample-key-sn` (original SN) and `store-put` under topic = the spec's first matched topic name (MVP: one topic per service node; multi-topic is a refinement noted below). Track seen keys in a local `hash-table` so a re-poll does not re-put. Sleep ~5 ms between polls. Run under a `with-sender-emit-guard`-style per-iteration `handler-case` (catch `error`, fire `*durability-error-hook*`, continue).

**MVP scoping note (write into the docstring):** Task 4 collects **one topic per service node** (the spec's first explicit `(topic . type)`; a predicate spec defaults its node topic from a `:primary-topic` override or signals at start if it cannot resolve a concrete topic — multi-topic-per-service is a documented Phase-1 follow-up). Capture is **DATA only**; `:dispose`/`:unregister` replay is a documented limitation (the poll API exposes payloads, not change-kind) — recorded in the ADR (Task 10).

- [ ] **Step 1: Failing test** `run-durability-collect-test` — an our-stack publisher writes 3 TRANSIENT_LOCAL samples to "Square"/"ShapeType" on a domain; a `durability-service` on the same domain collects them; assert the service's store has 3 records for "Square" with monotonically increasing SNs and the original writer GUID. (Build the publisher with the shapes/`run-publisher` call pattern — verified excerpt in the explore report — or a minimal `make-disc-node`+`add-local-writer`+`publish-sample`. Allow a bounded discovery+delivery settle loop, e.g. up to 5 s polling `store-count`.) Use a domain id unlikely to collide (e.g. 7).
- [ ] **Step 2: Run it, verify FAIL** (`make-durability-service` undefined).
- [ ] **Step 3: Implement `service.lisp`** collect path per the Interfaces. Define `*durability-error-hook*` (a `defparameter`, default a rate-limited WARN, bindable; mirror `dds.disc:*sender-emit-error-hook*`'s shape). All `defun*`-typed.
- [ ] **Step 4: Wire** (component, export `#:run-durability-collect-test` + `#:*durability-error-hook*`, alist).
- [ ] **Step 5: Run both impls.** Expected PASS (allow the settle loop). If Clasp discovery timing is flaky, widen the settle bound — do NOT skip (this is core, not ZC).
- [ ] **Step 6: Commit** `feat(durability): WP-DURABILITY-SERVICE-TRANSIENT — durability-service collect path (reader → store) (M6/P5)`.

---

## Task 5: `durability-service` — the replay path (the headline slice)

**Goal:** The service also owns a replaying writer; when a late-joiner is discovered, the service replays its store over the shipped reliable late-joiner machinery. The headline end-to-end: writer publishes N TRANSIENT, terminates; a late-joiner that starts AFTER the writer is gone receives all N from the service; a VOLATILE late-joiner receives none.

**Files:** Modify `src/dds-durability/service.lisp` (+ writer + replay), `durability-test.lisp` (+ integration test), packages + alist.

**Interfaces:**
- Consumes: `dds.disc:add-local-writer` (`:qos (make-writer-qos :durability :transient-local :history-kind :keep-all)`), `enable-publisher` (`:history-kind :keep-all`), `publish-sample`; the shipped late-joiner replay (`%writer-durability-init` fires from the match hook automatically — the service writer being TRANSIENT_LOCAL means a TL late-joiner pulls `firstSN`). The store API.
- Produces: `service-start` now also adds the writer + enables the publisher; a **replay step** seeds the writer's HistoryCache from the store. MVP replay model: the service `publish-sample`s every `store-get-range` record (ordered) into its writer's KEEP_ALL HistoryCache at start (after collecting) OR continuously as it collects (recommended: **publish-on-collect** — each collected sample is immediately re-published through the service writer, so the writer's HistoryCache mirrors the store and the existing TL retention + late-joiner replay deliver it). Document the choice in the docstring.

**Design note (conformance):** the service writer re-publishes under ITS OWN GUID + its OWN SNs. In the **writer-is-gone** scenario the original writer is absent, so the late-joiner has a single source (the service) — correct, no duplicates, **nothing new on the wire**. The no-double-delivery case (original writer still present) is Phase 2 (needs the virtual-GUID; see Phasing). Do NOT add any identity carrier here.

- [ ] **Step 1: Failing integration test** `run-durability-transient-test`:
  - On domain 7: a publisher node writes N=5 TRANSIENT_LOCAL "Square" samples, then `stop-node` (the writer is GONE).
  - A `durability-service` on domain 7 has been running and collected the 5 (poll `store-count` until 5 or timeout).
  - A late-joiner reader node (`make-reader-qos :reliability :reliable :durability :transient-local`) starts AFTER the publisher stopped; poll its `node-sample-sns` until 5 received or a ~6 s timeout. `%check` that all 5 arrived.
  - A second late-joiner with `:durability :volatile` starts; `%check` it receives 0 of the pre-join history within the window (the VOLATILE contrast).
- [ ] **Step 2: Run it, verify FAIL** (replay not implemented → late-joiner gets 0).
- [ ] **Step 3: Implement the replay** (publish-on-collect) in `service.lisp`. Ensure the service writer is TRANSIENT_LOCAL + KEEP_ALL so the shipped retention + `%writer-durability-init` replay path delivers to the TL late-joiner.
- [ ] **Step 4: Run both impls.** Expected PASS. This is the core value gate — widen timeouts rather than skip.
- [ ] **Step 5: Run the full sweep:** `make test` (SBCL+Clasp), `make gate-hotpath gate-types mem fuzz`. `mem` must stay 0.0000 (the service adds no CDR-path work). Expected all PASS.
- [ ] **Step 6: Commit** `feat(durability): WP-DURABILITY-SERVICE-TRANSIENT — replay path: late-joiner after writer-death gets retained history (M6/P5, DDS 1.4 §2.2.3.4)`.

---

## Task 6: `service-runner` + thread mode + spec matching

**Goal:** A runner that holds N service specs and starts each as a service in thread mode, with a registry (start/stop/status). The embedded library entity the host app holds (capability 1).

**Files:** Create `src/dds-durability/runner.lisp`; Modify `dds-durability.asd`, `durability-test.lisp`, packages + alist.

**Interfaces:**
- Produces:
  - `(make-service-runner specs)` → `service-runner`. `specs` = `list` of `service-spec`.
  - `(runner-start runner)` → `service-runner`: instantiates a `durability-service` per spec and `service-start`s each (thread mode in Task 6; `:process` deferred to Task 8 — a `:process` spec signals not-yet-wired here or is started in-thread with a logged note, finalized in Task 8).
  - `(runner-stop runner)` → `(eql t)`: stops all services.
  - `(runner-status runner)` → `list` of `(name . alive-p)` per service.
  - Accessor `service-runner-services` → the live `durability-service` list.

- [ ] **Step 1: Failing test** `run-durability-runner-test` — two specs on domain 7: spec-A topic "Square"/"ShapeType", spec-B topic "Circle"/"ShapeType". A publisher writes to both topics then stops; `runner-start`; assert each service's store collected its OWN topic only (topic isolation through the runner) and `runner-status` shows both alive. `runner-stop`; assert all stopped.
- [ ] **Step 2: Run, verify FAIL.**
- [ ] **Step 3: Implement `runner.lisp`.** All `defun*`-typed.
- [ ] **Step 4: Wire** (component, exports, alist).
- [ ] **Step 5: Run both impls + gate-types.** Expected PASS.
- [ ] **Step 6: Commit** `feat(durability): WP-DURABILITY-SERVICE-TRANSIENT — multi-service runner + thread mode (M6/P5, ADR 0021 cap. 1-2)`.

---

## Task 7: `supervisor` — OTP-style one-for-one + restart-intensity

**Goal:** Monitor each running service; on death, restart it; cap restarts (max R in T seconds) → shed + escalate via a hook (no infinite respawn of a poison pill).

**Files:** Create `src/dds-durability/supervisor.lisp`; Modify `dds-durability.asd`, `durability-test.lisp`, packages + alist.

**Interfaces:**
- Consumes: `service-alive-p`, `service-start`, `service-stop`; `dds.pal:spawn`/threading; `*durability-error-hook*`.
- Produces:
  - `(make-supervisor runner &key (max-restarts 3) (window-seconds 5) (poll-ms 50))` → `supervisor`. (`window-seconds` measured via `get-internal-real-time` — allowed in production code; NOT `dds.pal` restricted.)
  - `(supervisor-start supervisor)` → `supervisor`: spawns a watcher thread polling `service-alive-p` for each service; on a death, `service-start` a fresh service from the same spec, recording the restart timestamp; if restarts within `window-seconds` exceed `max-restarts`, mark the service SHED (stop restarting) and fire `*durability-error-hook*` with context `:supervisor-shed`.
  - `(supervisor-stop supervisor)` → `(eql t)`.
  - Accessor `supervisor-shed-p (supervisor name)` → `boolean`.

- [ ] **Step 1: Failing test** `run-durability-supervisor-test`:
  - Restart-intensity math as a PURE unit first (a helper `%restart-allowed-p` over a timestamp list + window + max) — assert allowed for 3-in-window, shed on the 4th.
  - Liveness restart: start a runner+supervisor with one service; forcibly stop the service's thread (`service-stop` its inner thread or set its running flag false); assert the supervisor restarts it (`service-alive-p` becomes true again within ~1 s).
  - Crash-loop shed: a spec whose `service-start` always dies immediately (inject via a store factory that signals, or a `:fault t` spec field) → assert `supervisor-shed-p` becomes true after `max-restarts` and the hook fired.
- [ ] **Step 2: Run, verify FAIL.**
- [ ] **Step 3: Implement `supervisor.lisp`** + the `%restart-allowed-p` pure helper. (Add a minimal fault-injection affordance to `durability-service`/`service-spec` — e.g. a `*durability-debug-start-fault*` special, inert NIL default — to make the crash-loop testable without real corruption. Document it inert.)
- [ ] **Step 4: Wire** (component, exports, alist).
- [ ] **Step 5: Run both impls.** Timing-sensitive parts: if Clasp threading is flaky (known intermittent SIGSEGV in Clasp CLOS error-signaling — memory `clasp-threading-gap`), the liveness/crash-loop sub-tests may `(dds.pal:pal-impl-name)`-skip on Clasp with a documented NFR-PORT note; the PURE restart-intensity math must run on both. Expected PASS (SBCL full; Clasp at least the pure math).
- [ ] **Step 6: Commit** `feat(durability): WP-DURABILITY-SERVICE-TRANSIENT — OTP-style supervisor (one-for-one + restart-intensity) (M6/P5, ADR 0021 cap. 4)`.

---

## Task 8: process mode + `durability-service-main` CLI/env entrypoint

**Goal:** `durability-service-main` reads config from CLI args + env, builds specs, runs the runner+supervisor — and is reused as the subprocess body when a spec's `mode` is `:process` (started via `uiop:launch-program`).

**Files:** Create `src/dds-durability/main.lisp`; Modify `dds-durability.asd`, `runner.lisp` (wire `:process` start), `durability-test.lisp`, packages + alist.

**Interfaces:**
- Consumes: `uiop:launch-program` (verified available via `uiop:run-program` usage), `uiop:getenv`, `uiop:command-line-arguments`; the runner + supervisor.
- Produces:
  - `(parse-durability-config &key argv env)` → `list` of `service-spec` (PURE, testable: precedence CLI > env > defaults). Config surface (MVP): `--domain N`, `--topic NAME:TYPE` (repeatable), `--mode thread|process`, `--max-restarts N`, `--window-seconds N`; env mirrors `DDS_DURABILITY_DOMAIN`, `DDS_DURABILITY_TOPICS` (comma list of `NAME:TYPE`), etc.
  - `(durability-service-main &key argv env (block t))` → runs `parse-durability-config` → `make-service-runner` → `runner-start` → `make-supervisor`/`supervisor-start`; when `block` t, blocks (the subprocess body); when nil, returns the `(runner . supervisor)` for embedding/tests.
  - In `runner-start`, a `:process` spec → `uiop:launch-program` of the host Lisp invoking `durability-service-main` with the spec serialized to CLI args (a documented invocation string built by a `%spec->argv` helper); the supervisor monitors process exit (`uiop:process-alive-p`).

- [ ] **Step 1: Failing test** `run-durability-config-test` — PURE config parsing: assert `--domain 7 --topic Square:ShapeType --topic Circle:ShapeType` yields one spec on domain 7 matching both topics; assert env `DDS_DURABILITY_TOPICS=Square:ShapeType` is read when no `--topic`; assert CLI overrides env for `--domain`. Bounds-check: a malformed `--topic Foo` (no `:TYPE`) → a clean error, never an OOB/crash (NFR-SEC-POSTURE). Fuzz the parser in `make fuzz` (Task 10 adds the fuzz arm; here a few hand cases).
- [ ] **Step 2: Run, verify FAIL.**
- [ ] **Step 3: Implement `main.lisp`** (parse + main) and wire `:process` in `runner.lisp` (`%spec->argv` + `uiop:launch-program`). All `defun*`-typed.
- [ ] **Step 4: Process-mode smoke test** `run-durability-process-smoke-test` (SBCL-gated; `(dds.pal:pal-impl-name)`-skip on Clasp with a documented note): launch ONE `:process` service via `uiop:launch-program` of `sbcl` running `durability-service-main`, publish to its topic from this image, then a late-joiner receives the replay; kill the subprocess; assert it was alive then reaped. If launching a full subprocess in CI is too heavy/flaky, downgrade to asserting `%spec->argv` round-trips through `parse-durability-config` (a deterministic unit proof that the subprocess WOULD start with the right config) + a manual-run note in the ADR. Choose the deterministic unit proof if the live subprocess is flaky — and `log`/document the downgrade (no silent cap).
- [ ] **Step 5: Run both impls.** Expected PASS (config parse on both; process smoke SBCL or the unit fallback).
- [ ] **Step 6: Commit** `feat(durability): WP-DURABILITY-SERVICE-TRANSIENT — durability-service-main CLI/env + subprocess process mode (M6/P5, ADR 0021 cap. 3,5)`.

---

## Task 9: Cross-DDS interop — foreign late-joiner receives our service's retained history

**Goal:** The per-feature cross-DDS DoD for Phase 1: a foreign Connext 7.3.1 AND Fast DDS 3.6.1 late-joining reader receives the retained history from OUR durability service after our original writer is gone. (No-double-delivery / foreign-service coexistence is Phase 2.)

**Files:** Create `interop/durability-transient/` (README + run scripts + QoS XML/profiles, mirroring `interop/durability-transient-local/`); captures committed.

**Interfaces:** Consumes the shipped harness pattern in `interop/durability-transient-local/`.

- [ ] **Step 1: Build the harness.** A runnable our-stack durability service (a `durability-service-main` invocation or a small `dds.shapes`-style driver) on a fixed domain/port for loopback; foreign TRANSIENT_LOCAL publisher (rtishapesdemo / Connext QoS XML + a Fast DDS profile) that publishes then exits; a foreign late-joining TRANSIENT_LOCAL subscriber.
- [ ] **Step 2: Run vs Connext 7.3.1.** Our service collects the foreign publisher's samples; the foreign publisher exits; a foreign late-joiner starts and receives the retained history from OUR service. Capture on `lo0` with `tshark`; verify our service's HEARTBEAT advertises the retained range and the late-joiner's NACK is answered by our retransmit. Record the decoded sample receipt (and the macOS `lo0` reverse-capture quirk if it applies, as the prior interop READMEs do — proof = decoded counts + ACKNACK progression).
- [ ] **Step 3: Run vs Fast DDS 3.6.1.** Same, both directions where capturable.
- [ ] **Step 4: Write `interop/durability-transient/README.md`** — the legs, the commands, the capture filenames, the conformance facts (retained range on the wire, retransmit on NACK), and any honest capture caveats. Commit captures.
- [ ] **Step 5: Commit** `test(interop): WP-DURABILITY-SERVICE-TRANSIENT — foreign late-joiner receives our service's retained history, LIVE vs Connext 7.3.1 + Fast DDS 3.6.1 (M6/P5)`.

---

## Task 10: Gates + docs capstone (Phase 1)

**Goal:** Full gate sweep both impls + docs in lockstep + the architecture ADR; then the final whole-branch review and the squash-merge presentation.

**Files:** Create `docs/adr/0023-durability-service-architecture.md`, `docs/wiki/durability.md`; Modify `README.md` (P5 row → durability service in progress), `docs/verification.csv` (+ a durability-service row), `docs/provenance.md` (if the spike read external material); fuzz arm in `durability-test.lisp` / `pbt-test.lisp` for the config parser.

- [ ] **Step 1: ADR 0023** — the as-built service architecture: the 6 capabilities' Phase-1 state, the `durable-store` vtable, the collect/replay model (publish-on-collect, writer-is-gone single-source = no new wire), the documented Phase-1 limitations (one-topic-per-service, DATA-only capture, in-memory loses state on process restart, dedup/no-double-delivery + foreign-service coexistence deferred to Phase 2 with the spike rationale), and the cross-DDS interop result. Reference ADR 0021/0022 + the spike findings doc.
- [ ] **Step 2: Fuzz the config parser** — add a `parse-durability-config` arm to the fuzz suite (random/malformed `--topic`/env strings → clean error or valid spec, never OOB, incl. a `(safety 0)` variant). `make fuzz` green.
- [ ] **Step 3: Docs lockstep** — `docs/wiki/durability.md` (API ref + a worked embedded-service example + the CLI usage), README P5 row update, verification.csv row, provenance if applicable.
- [ ] **Step 4: Full gate sweep both impls.**
```bash
make test       # SBCL+Clasp green (target ≥ prior 256 + the new durability tests)
make test-sbcl
make gate-hotpath gate-types mem fuzz wire
```
Expected: all PASS; `mem` 0.0000; `gate-types` clean (all new defun*s ftyped).
- [ ] **Step 5: Final whole-branch review** (`requesting-code-review` / a fresh reviewer over `main..wp-durability-service-transient`): conformance (no false-reject; VOLATILE default byte-identical), bounded store (NFR-MEM), bounds-checked config parse (NFR-SEC-POSTURE), thread/process lifecycle (no leaked threads/processes on stop; no UAF on restart), docstrings + docs lockstep, no AI attribution. Fix findings (each fix re-runs the relevant gate).
- [ ] **Step 6: Commit** `docs(durability): WP-DURABILITY-SERVICE-TRANSIENT — ADR 0023 + wiki/README/verification + config fuzz; Phase 1 capstone (M6/P5)`.
- [ ] **Step 7: Present the squash-merge** commit message for owner approval (HOLD PUSH). Do NOT push or merge without approval.

---

## Self-review (author checklist — completed)

- **Spec coverage:** §3 module layout → Tasks 2–8 (every unit has a task: store T2, spec T3, service T4–5, runner T6, supervisor T7, main/process T8). §4 collect/replay → T4/T5. §5 runner/supervisor/CLI/store → T2,T6,T7,T8. §6 error handling → `*durability-error-hook*` + per-iteration guards in T4/T7; bounded store T2; bounds-checked parse T8/T10. §7 testing → unit tests each task + integration T5 + supervisor T7 + cross-DDS T9 + gates T10. §8 slice ordering → Tasks 1(spike),2(store),3–5(relio),6–8(runner/sup/CLI); slices 5–6 explicitly Phase 2. §2 decisions (full-6, foreign-interop, subprocess, per-(domain+filter), spike-first) all reflected. §9 out-of-scope (DARE/PERSISTENT, retention timer, extra store plugs) preserved.
- **Spec-vs-codebase correction (recorded for the owner):** the no-double-delivery/dedup integration assertion the spec listed under slice-3 testing requires a wire identity carrier that does NOT exist in the codebase; per spike-first it moves to Phase 2. Phase 1's interop DoD is met via the writer-is-gone single-source foreign late-joiner (Task 9). This is the one deliberate sequencing change from the spec.
- **Placeholder scan:** no TBD/TODO; every code step shows real, signature-verified code or a precisely-bounded implementation instruction.
- **Type/name consistency:** store API names (`store-put`/`store-get-range`/`store-count`/`store-topics`/`store-purge`) consistent T2→T4/T5; `service-spec-matches-p`, `durability-service`/`service-start`/`service-stop`/`service-alive-p`, `service-runner`/`runner-start`/`runner-stop`/`runner-status`, `supervisor`/`supervisor-start`/`supervisor-stop`, `durability-service-main`/`parse-durability-config`, `*durability-error-hook*` all consistent across tasks and match the exported package symbols.
