# WP-DURABILITY-COEXIST-LIVE Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Carry the already-computed logical origin (`PID_ORIGINAL_WRITER_INFO`) through the disc-node data path so a durability relay collecting from a foreign OWI-stamping persistence service re-stamps the original publisher's origin, not the foreign relay's wire GUID — converging cross-vendor dual-relay dedup — and prove it both in-process and live.

**Architecture:** The receive path already derives `effective-guid`/`effective-sn` (OWI-when-present, else wire) and the receiver dedups on it; only the per-sample *store* keeps the wire sender. Persist + expose the effective origin (`node-sample-origin-guid`/`-sn`), then have `%collect-loop` re-stamp/store/dedup from it. Control-plane only (disc-node relay store), default/direct path byte-identical.

**Tech Stack:** Common Lisp (SBCL + Clasp), `dds-disc` (dataplane + disc struct), `dds-durability` (service collect loop), `dds-tests`, the `interop/durability-coexist-dedup` live harness + `analyze-capture.py` (Python 3, tshark/raw-byte RTPS parse), RTI Connext 7.3.1 + RTI Persistence Service 7.3.1.

## Global Constraints

- **Hot-path purity / NFR-MEM:** the change is control-plane (disc-node relay store, not the measured CDR hot path); `gate-hotpath` and `make mem` (0.0000) must stay unaffected. No per-sample alloc on the CDR hot path.
- **`defun*`/`defstruct*`** for every function/struct; **full ftype declarations** on every new function (FR-LANG-8).
- **No wire constants from memory:** the OWI layout is RTPS 2.5 §8.3.5.4, already in `parse-original-writer-info` — reuse it, never re-encode a constant.
- **Bounds-check** the OWI parse even at `(safety 0)` — already done in `parse-inline-qos`/`parse-original-writer-info`; reuse, do not re-implement (DRY).
- **Clasp AND SBCL both validate, Clasp first** (run `make test-clasp` before `make test-sbcl`).
- **No reader conditionals** (`#+sbcl`/`#+clasp`) outside `dds-pal/`.
- **No AI / assistant attribution** in any repo file; cite "the operating contract", never a filename.
- **Default config byte-identical:** direct samples carry no OWI → effective origin = wire; `:collect-durability` defaults to `:transient-local`.
- **Live-gated DoD:** the merge requires a captured live cross-vendor dual-relay exactly-once (both relays' wire OWI = the publisher's GUID; the late-joiner collapses two relay streams to exactly N). If the live capture proves unreliable despite the fix, escalate to the owner — do not silently downgrade the gate.

## File map

- `src/dds-disc/disc.lisp` — add the `sample-origins` slot to the disc-node struct (after `sample-writer-guids`, ~line 167).
- `src/dds-disc/dataplane.lisp` — add `%record-sample-origin` setter; call it in `%deliver-user-sample` + `%deliver-user-marker`; add `node-sample-origin-guid`/`node-sample-origin-sn` accessors.
- `src/dds-disc/packages.lisp` — export the two accessors (line 44).
- `src/dds-durability/service.lisp` — `%collect-loop` data drain resolves + uses the logical origin (~lines 218-228).
- `src/dds-tests/durability-test.lisp` — `run-durability-origin-accessor-test` (T1), `run-durability-collect-origin-convergence-test` (T2).
- `src/dds-tests/echo-test.lisp` + `src/dds-tests/packages.lisp` — register + export the two new tests.
- `interop/durability-persistent/coexistence/analyze-capture.py` — add `--assert-converged` mode.
- `interop/durability-coexist-dedup/{run-coexist-both.sh,driver-relay2.lisp,driver-our-reader.lisp,README.md}` — header flips + the converged-assertion call (T3/T4).
- `docs/adr/0028-durability-coexist-live.md` (new); `README.md`, `docs/wiki/durability.md`, `docs/verification.csv` (T4).

---

### Task 1: disc-node logical-origin capture + accessors

**Files:**
- Modify: `src/dds-disc/disc.lisp` (disc-node struct, after the `sample-writer-guids` slot ~line 167)
- Modify: `src/dds-disc/dataplane.lisp` (`%record-sample-origin` near `%inner-table` ~line 1188; calls in `%deliver-user-sample` ~1337-1339 and `%deliver-user-marker` ~1312-1314; accessors after `node-sample-writer-guid` ~line 1632)
- Modify: `src/dds-disc/packages.lisp` (line 44)
- Test: `src/dds-tests/durability-test.lisp` (`run-durability-origin-accessor-test`), registered in `echo-test.lisp` + exported in `packages.lisp`

**Interfaces:**
- Consumes: `%inner-table (outer guid) → hash-table` (creates an `eql` inner SN-table); `disc-node-sample-origins` (new slot accessor); `disc-node-lock`; `publish-relay-sample (node payload original-guid original-sn &optional key-hash)`; `publish-sample (node payload)`.
- Produces: `node-sample-origin-guid (node key) → (simple-array (unsigned-byte 8) (16))` and `node-sample-origin-sn (node key) → integer` — the logical origin (effective when an OWI was present on receive, else the wire guid/sn). `key` is a `(wire-guid . sn)` cons from `node-sample-sns`.

- [ ] **Step 1: Add the struct slot.** In `src/dds-disc/disc.lisp`, immediately after the `sample-writer-guids` slot (~line 167), add:

```lisp
  (sample-origins (make-hash-table :test 'equalp) :type hash-table) ; src GUID -> SN -> (effective-origin-GUID . effective-origin-SN): the PID_ORIGINAL_WRITER_INFO logical origin when the received sample was relayed (RTPS 2.5 §8.3.5.4), absent for a direct sample (then the wire GUID/SN IS the origin)
```

- [ ] **Step 2: Write the failing test.** In `src/dds-tests/durability-test.lisp`, add (model on `run-durability-no-double-delivery-test`'s wiring; reuse `%make-test-prefix`, `%make-small-payload`, `%check`):

```lisp
(defun* run-durability-origin-accessor-test ()
    (function () t)
  "node-sample-origin-guid/-sn surface the logical origin (RTPS 2.5 §8.3.5.4): a sample relayed with
   PID_ORIGINAL_WRITER_INFO reports the ORIGINAL writer's (GUID,SN), not the relaying wire sender; a
   direct sample (no OWI) reports the wire GUID/SN. Two-node loopback, domain 78."
  (let* ((relay-prefix (%make-test-prefix #xA1))
         (relay-node (dds.disc:make-disc-node :guid-prefix relay-prefix :domain 78
                                              :host "127.0.0.1" :port 0 :multicast nil))
         (rdr-prefix (%make-test-prefix #xB2))
         (rdr-node (dds.disc:make-disc-node :guid-prefix rdr-prefix :domain 78
                                            :host "127.0.0.1" :port 0 :multicast nil))
         (orig-guid (make-array 16 :element-type '(unsigned-byte 8) :initial-element #xC3))
         (orig-sn 41))
    (unwind-protect
         (progn
           (dds.disc:add-local-writer relay-node :topic "OSquare" :type "ShapeType"
                                      :qos (dds.qos:make-writer-qos :reliability :reliable
                                                                     :durability :transient-local))
           (dds.disc:enable-publisher relay-node :history-kind :keep-all)
           (dds.disc:start-node relay-node)
           (dds.disc:add-local-reader rdr-node :topic "OSquare" :type "ShapeType"
                                      :qos (dds.qos:make-reader-qos :reliability :reliable
                                                                     :durability :transient-local))
           (dds.disc:enable-subscriber rdr-node)
           (dds.disc:start-node rdr-node)
           (let ((rp (dds.disc:disc-node-port relay-node))
                 (sp (dds.disc:disc-node-port rdr-node)))
             (setf (dds.disc:disc-node-peers relay-node) (list (cons "127.0.0.1" sp)))
             (setf (dds.disc:disc-node-peers rdr-node)   (list (cons "127.0.0.1" rp))))
           (loop repeat 400
                 until (and (plusp (dds.disc:disc-node-matched-count relay-node))
                            (plusp (dds.disc:disc-node-matched-count rdr-node)))
                 do (dds.disc:announce-participant relay-node) (dds.disc:announce-endpoints relay-node)
                    (dds.disc:announce-participant rdr-node)   (dds.disc:announce-endpoints rdr-node)
                    (sleep 0.02))
           ;; (1) a RELAYED sample: publish with PID_ORIGINAL_WRITER_INFO = (orig-guid, orig-sn)
           (dds.disc:publish-relay-sample relay-node (%make-small-payload 7) orig-guid orig-sn)
           (loop repeat 200
                 until (plusp (dds.disc:node-sample-count rdr-node))
                 do (dds.disc:announce-participant relay-node) (dds.disc:announce-endpoints relay-node)
                    (sleep 0.02))
           (let ((key (first (dds.disc:node-sample-sns rdr-node))))
             (%check :origin-accessor-relayed-guid
                     (equalp (dds.disc:node-sample-origin-guid rdr-node key) orig-guid)
                     "a relayed sample must report the ORIGINAL writer GUID, not the wire sender")
             (%check :origin-accessor-relayed-sn
                     (= (dds.disc:node-sample-origin-sn rdr-node key) orig-sn)
                     "a relayed sample must report the ORIGINAL writer SN")
             (%check :origin-accessor-not-wire
                     (not (equalp (dds.disc:node-sample-origin-guid rdr-node key) (car key)))
                     "the relayed origin GUID must differ from the wire sender GUID in this test")))
      (ignore-errors (dds.disc:stop-node relay-node))
      (ignore-errors (dds.disc:stop-node rdr-node))))
  t)
```

- [ ] **Step 3: Run it — expect FAIL** (`node-sample-origin-guid` undefined / unexported):

```
./scripts/with-clasp.sh --eval '(ql:quickload :dds-tests :silent t)' --eval '(handler-case (progn (dds.tests:run-durability-origin-accessor-test) (uiop:quit 0)) (error (e) (format t "~&FAIL ~a~%" e) (uiop:quit 1)))'
```
Expected: FAIL — `The function DDS.DISC:NODE-SAMPLE-ORIGIN-GUID is undefined` (or unexported symbol read error).

- [ ] **Step 4: Add the setter.** In `src/dds-disc/dataplane.lisp`, immediately after `%inner-table` (~line 1188), add:

```lisp
(defun* %record-sample-origin (node wire-guid sn eff-guid eff-sn)
    (function (disc-node (simple-array (unsigned-byte 8) (16)) integer
              (simple-array (unsigned-byte 8) (16)) integer) t)
  "Record the logical origin (EFF-GUID . EFF-SN) for the sample stored under wire (WIRE-GUID, SN) — but
   ONLY when it differs from the wire identity, i.e. the sample arrived relayed with PID_ORIGINAL_WRITER_INFO
   (RTPS 2.5 §8.3.5.4). A direct sample stores nothing here (the wire GUID/SN IS the origin), so the common
   path stays byte-identical and allocation-free. Caller holds the node lock. Control-plane (relay store)."
  (when (or (not (equalp eff-guid wire-guid)) (/= eff-sn sn))
    (setf (gethash sn (%inner-table (disc-node-sample-origins node) wire-guid))
          (cons (copy-seq eff-guid) eff-sn)))
  t)
```

- [ ] **Step 5: Call it from both delivery sites.** In `%deliver-user-sample` (~line 1337-1339), inside the `with-lock`, after the three existing `setf`s, add `(%record-sample-origin node guid sn effective-guid effective-sn)`. Do the identical addition in `%deliver-user-marker` (~line 1312-1314). After (sample path shown):

```lisp
      (dds.pal:with-lock ((disc-node-lock node))
        (setf (gethash sn (%inner-table (disc-node-samples node) guid)) vec
              (gethash sn (%inner-table (disc-node-sample-writers node) guid)) writer-id
              (gethash sn (%inner-table (disc-node-sample-writer-guids node) guid)) guid)
        (%record-sample-origin node guid sn effective-guid effective-sn))
```

- [ ] **Step 6: Add the accessors.** In `src/dds-disc/dataplane.lisp`, after `node-sample-writer-guid` (~line 1632), add:

```lisp
(defun* node-sample-origin-guid (node key)
    (function (disc-node cons) (simple-array (unsigned-byte 8) (16)))
  "The LOGICAL ORIGIN GUID of the user sample at composite KEY (a (GUID . SN) cons): the original
   writer's GUID when the sample was relayed with PID_ORIGINAL_WRITER_INFO (RTPS 2.5 §8.3.5.4), else the
   wire sender GUID (= (car KEY)). Always defined. A durability relay re-stamps THIS as the OWI origin so
   a foreign persistence service's relayed copies converge with directly-collected copies (ADR 0028)."
  (dds.pal:with-lock ((disc-node-lock node))
    (let* ((inner (gethash (car key) (disc-node-sample-origins node)))
           (entry (and inner (gethash (cdr key) inner))))
      (if entry (car entry) (car key)))))

(defun* node-sample-origin-sn (node key)
    (function (disc-node cons) integer)
  "The LOGICAL ORIGIN SN of the user sample at composite KEY: the original writer's SN when relayed with
   PID_ORIGINAL_WRITER_INFO (RTPS 2.5 §8.3.5.4), else the wire SN (= (cdr KEY)). Pairs with
   node-sample-origin-guid."
  (dds.pal:with-lock ((disc-node-lock node))
    (let* ((inner (gethash (car key) (disc-node-sample-origins node)))
           (entry (and inner (gethash (cdr key) inner))))
      (if entry (cdr entry) (cdr key)))))
```

- [ ] **Step 7: Export.** In `src/dds-disc/packages.lisp` line 44, add `#:node-sample-origin-guid #:node-sample-origin-sn` to the export list (next to `#:node-sample-writer-guid`).

- [ ] **Step 8: Register + export the test.** In `src/dds-tests/packages.lisp`, export `#:run-durability-origin-accessor-test`. In `src/dds-tests/echo-test.lisp`, add `("durability-origin-accessor" . run-durability-origin-accessor-test)` to the alist.

- [ ] **Step 9: Run it — expect PASS** (command from Step 3). Expected: process exits 0, the three `%check`s pass.

- [ ] **Step 10: Gate + commit.**
```
make test-clasp && make test-sbcl && make gate-hotpath && make gate-types
git add src/dds-disc/disc.lisp src/dds-disc/dataplane.lisp src/dds-disc/packages.lisp src/dds-tests/durability-test.lisp src/dds-tests/echo-test.lisp src/dds-tests/packages.lisp
git commit -m "feat(disc): WP-DURABILITY-COEXIST-LIVE — capture+expose the per-sample logical origin (node-sample-origin-guid/-sn; OWI-when-relayed else wire) (M6/P5, ADR 0028)"
```
Expected: both impls green (test count +1), `gate-hotpath` PASS (the new slot/table is control-plane — assert it does not list a new hot-path file), `gate-types` PASS (+3 ftype'd defuns).

---

### Task 2: `%collect-loop` re-stamps/stores/dedups from the logical origin

**Files:**
- Modify: `src/dds-durability/service.lisp` (`%collect-loop` data drain, ~lines 219-228)
- Test: `src/dds-tests/durability-test.lisp` (`run-durability-collect-origin-convergence-test`), registered + exported

**Interfaces:**
- Consumes: `node-sample-origin-guid`/`node-sample-origin-sn` (Task 1); `store-put (store topic writer-guid sn key-hash kind payload)`; `publish-relay-sample (node payload original-guid original-sn &optional key-hash)`; the per-origin dedup helpers `%collect-seen-p`/`%collect-mark-seen!`; `store-get-range`/`durable-record-writer-guid`.
- Produces: a durability relay whose stored + re-stamped origin is the logical origin (so two wire senders carrying the same OWI origin converge to one stored origin).

- [ ] **Step 1: Write the failing test.** In `src/dds-tests/durability-test.lisp`, add (model on `run-durability-no-double-delivery-test`; a publisher node sends N direct, a foreign-relay node sends the SAME N with OWI = the publisher's GUID; assert the service store records exactly ONE origin = the publisher GUID, for BOTH arrival orders):

```lisp
(defun* %collect-origin-convergence-case (relay-first)
    (function (t) t)
  "One convergence case: publisher P (direct, no OWI) + foreign relay R (OWI = P's GUID) both feed the
   durability collect node N samples; RELAY-FIRST selects which writes first. The service store must end
   with exactly ONE distinct origin GUID == P's GUID (the logical origin), never R's wire GUID. Domain 79."
  (let* ((n 3)
         (svc-store (dds.durability:make-memory-store))
         (spec (dds.durability:make-service-spec
                :domain 79 :topics '(("CSquare" . "ShapeType")) :store (lambda () svc-store)
                :qos-overrides '(:collect-durability :transient) :name "collect-origin-convergence"))
         (svc (dds.durability:make-durability-service spec :store svc-store))
         (pub-node (dds.disc:make-disc-node :guid-prefix (%make-test-prefix #x1A) :domain 79
                                            :host "127.0.0.1" :port 0 :multicast nil))
         (relay-node (dds.disc:make-disc-node :guid-prefix (%make-test-prefix #x2B) :domain 79
                                              :host "127.0.0.1" :port 0 :multicast nil)))
    (unwind-protect
         (progn
           (dds.durability:service-start svc)
           (let* ((svc-node (dds.durability:durability-service-node svc))
                  (pub-guid (dds.disc:add-local-writer pub-node :topic "CSquare" :type "ShapeType"
                                                       :qos (dds.qos:make-writer-qos :reliability :reliable
                                                                                      :durability :transient))))
             (dds.disc:enable-publisher pub-node :history-kind :keep-all)
             (dds.disc:start-node pub-node)
             (dds.disc:add-local-writer relay-node :topic "CSquare" :type "ShapeType"
                                        :qos (dds.qos:make-writer-qos :reliability :reliable
                                                                       :durability :transient))
             (dds.disc:enable-publisher relay-node :history-kind :keep-all)
             (dds.disc:start-node relay-node)
             (let ((pp (dds.disc:disc-node-port pub-node))
                   (rp (dds.disc:disc-node-port relay-node))
                   (sp (dds.disc:disc-node-port svc-node)))
               (setf (dds.disc:disc-node-peers pub-node)   (list (cons "127.0.0.1" sp)))
               (setf (dds.disc:disc-node-peers relay-node) (list (cons "127.0.0.1" sp)))
               (setf (dds.disc:disc-node-peers svc-node)
                     (list (cons "127.0.0.1" pp) (cons "127.0.0.1" rp))))
             (loop repeat 400
                   until (>= (dds.disc:disc-node-matched-count svc-node) 2)
                   do (dds.disc:announce-participant pub-node) (dds.disc:announce-endpoints pub-node)
                      (dds.disc:announce-participant relay-node) (dds.disc:announce-endpoints relay-node)
                      (dds.disc:announce-participant svc-node) (dds.disc:announce-endpoints svc-node)
                      (sleep 0.02))
             (flet ((send-direct () (dotimes (i n) (dds.disc:publish-sample pub-node (%make-small-payload (1+ i)))))
                    (send-relay  () (dotimes (i n) (dds.disc:publish-relay-sample relay-node (%make-small-payload (1+ i))
                                                                                  pub-guid (1+ i)))))
               (if relay-first (progn (send-relay) (sleep 0.2) (send-direct))
                   (progn (send-direct) (sleep 0.2) (send-relay))))
             (loop repeat 200
                   do (dds.disc:announce-participant pub-node) (dds.disc:announce-endpoints pub-node)
                      (dds.disc:announce-participant relay-node) (dds.disc:announce-endpoints relay-node)
                      (dds.disc:announce-participant svc-node) (dds.disc:announce-endpoints svc-node)
                      (sleep 0.03))
             (let ((origins (remove-duplicates
                             (mapcar #'dds.durability:durable-record-writer-guid
                                     (dds.durability:store-get-range svc-store "CSquare"))
                             :test #'equalp)))
               (%check (if relay-first :converge-relay-first :converge-direct-first)
                       (and (= 1 (length origins)) (equalp (first origins) pub-guid))
                       (format nil "store must hold exactly ONE origin == the publisher GUID (relay-first=~a), got ~d origin(s)"
                               relay-first (length origins)))))
      (ignore-errors (dds.disc:stop-node pub-node))
      (ignore-errors (dds.disc:stop-node relay-node))
      (ignore-errors (dds.durability:service-stop svc))))
  t)

(defun* run-durability-collect-origin-convergence-test ()
    (function () t)
  "The fix's deterministic proof: a durability relay collecting the SAME logical sample from a direct
   publisher AND a foreign OWI-stamping relay converges on the publisher's logical origin regardless of
   arrival order (RTPS 2.5 §8.3.5.4, ADR 0028) — the data-path symmetry of the lifecycle drain's orig-guid."
  (%collect-origin-convergence-case t)     ; relay copy arrives first (the case that diverged before the fix)
  (%collect-origin-convergence-case nil)   ; direct copy arrives first
  t)
```

- [ ] **Step 2: Run it — expect FAIL** (relay-first records R's wire GUID, so 2 origins or the wrong one):
```
./scripts/with-clasp.sh --eval '(ql:quickload :dds-tests :silent t)' --eval '(handler-case (progn (dds.tests:run-durability-collect-origin-convergence-test) (uiop:quit 0)) (error (e) (format t "~&FAIL ~a~%" e) (uiop:quit 1)))'
```
Expected: FAIL on `:converge-relay-first` (store holds R's wire GUID, not the publisher's).

- [ ] **Step 3: Apply the fix.** In `src/dds-durability/service.lisp` `%collect-loop`, replace the data-drain block (~lines 219-228):

```lisp
            (dolist (key (dds.disc:node-sample-sns node))
              (let ((writer-guid (dds.disc:node-sample-writer-guid node key))
                    (sn (dds.disc:node-sample-key-sn key)))
                (when (and writer-guid
                           (not (%collect-seen-p origins-data writer-guid sn)))
                  (%collect-mark-seen! origins-data writer-guid sn)
                  (let ((payload (dds.disc:node-sample node key)))
                    (when payload
                      (store-put store topic-name writer-guid sn nil :data payload)
                      (dds.disc:publish-relay-sample node payload writer-guid sn))))))
```
with (resolve the LOGICAL origin once; dedup/store/re-stamp on it; `writer-guid` retained only as the presence guard):

```lisp
            (dolist (key (dds.disc:node-sample-sns node))
              (let* ((writer-guid (dds.disc:node-sample-writer-guid node key))
                     (origin-guid (dds.disc:node-sample-origin-guid node key))  ; logical origin (OWI else wire)
                     (origin-sn   (dds.disc:node-sample-origin-sn   node key)))
                (when (and writer-guid
                           (not (%collect-seen-p origins-data origin-guid origin-sn)))
                  (%collect-mark-seen! origins-data origin-guid origin-sn)
                  (let ((payload (dds.disc:node-sample node key)))
                    (when payload
                      (store-put store topic-name origin-guid origin-sn nil :data payload)
                      (dds.disc:publish-relay-sample node payload origin-guid origin-sn))))))
```

- [ ] **Step 4: Run it — expect PASS** (command from Step 2). Expected: exit 0; both arrival orders converge to one origin = the publisher GUID.

- [ ] **Step 5: Regressions.** Confirm the dedup/byte-identical behaviour is intact:
```
./scripts/with-clasp.sh --eval '(ql:quickload :dds-tests :silent t)' --eval '(handler-case (progn (dds.tests:run-durability-no-double-delivery-test) (dds.tests:run-durability-multi-relay-dedup-test) (dds.tests:run-durability-collect-tier-test) (dds.tests:run-durability-relay-tier-test) (uiop:quit 0)) (error (e) (format t "~&FAIL ~a~%" e) (uiop:quit 1)))'
```
Expected: exit 0 (no OWI on the direct path → origin = wire → byte-identical).

- [ ] **Step 6: Register + export + gate + commit.** Export `#:run-durability-collect-origin-convergence-test` in `src/dds-tests/packages.lisp`; add `("durability-collect-origin-convergence" . run-durability-collect-origin-convergence-test)` to `echo-test.lisp`. Then:
```
make test-clasp && make test-sbcl && make gate-hotpath && make gate-types && make mem
git add src/dds-durability/service.lisp src/dds-tests/durability-test.lisp src/dds-tests/echo-test.lisp src/dds-tests/packages.lisp
git commit -m "feat(durability): WP-DURABILITY-COEXIST-LIVE — %collect-loop re-stamps/stores/dedups from the logical origin so foreign-relay + direct copies converge, arrival-order-independent (M6/P5, ADR 0028)"
```
Expected: both impls green (test count +1), `gate-hotpath` PASS, `gate-types` PASS, `mem` 0.0000.

---

### Task 3: live cross-vendor capture (the live-gated merge gate)

**Files:**
- Modify: `interop/durability-persistent/coexistence/analyze-capture.py` (add `--assert-converged`)
- Modify: `interop/durability-coexist-dedup/run-coexist-both.sh` (call the assertion; refresh the FINDING header)
- Use: `interop/durability-coexist-dedup/{driver-relay2.lisp,driver-our-reader.lisp}` (already advertise the tiers)

**Interfaces:**
- Consumes: `data_submessages(path)` + the per-writer OWI-origin set logic already in `dedup_union`/`owi_dump`.
- Produces: `analyze-capture.py --assert-converged <pcap>` exits 0 iff ≥2 relays stamped OWI, their origin-GUID sets are EQUAL (converged to the publisher), and UNION == each relay's per-origin count (exactly-once); non-zero otherwise. The live captures `captures/coexist-dir-{a,b}.pcap` showing convergence.

- [ ] **Step 1: Add the assertion mode.** In `analyze-capture.py`, add a function (reuse the `per_writer` build from `dedup_union`):

```python
def assert_converged(path):
    "Live-gated check: >=2 relays stamped OWI AND their origin-GUID sets are identical (converged to the"
    " one publisher) AND the UNION of (GUID,SN) equals each relay's count (exactly-once). Exit 0 iff so."
    per_writer = collections.defaultdict(set)
    for E, src_prefix, wId, own_sn, qflag, iq, sub in data_submessages(path):
        if not (qflag and iq < len(sub)):
            continue
        q = iq
        while q + 4 <= len(sub):
            pid = struct.unpack_from(E + 'H', sub, q)[0]
            plen = struct.unpack_from(E + 'H', sub, q + 2)[0]
            val = sub[q + 4:q + 4 + plen]
            if pid == 0x0001:
                break
            if pid == 0x0061 and len(val) >= 24:
                oshi, oslo = struct.unpack_from(E + 'iI', val, 16)
                per_writer[wId].add((val[0:16].hex(), (oshi << 32) | oslo))
            q += 4 + plen
    relays = sorted(per_writer)
    if len(relays) < 2:
        print(f"NOT-CONVERGED: only {len(relays)} relay stamped OWI on this capture (need >=2).")
        return 1
    guid_sets = [frozenset(g for g, _ in per_writer[w]) for w in relays]
    union = set().union(*per_writer.values())
    converged = all(s == guid_sets[0] for s in guid_sets) and len(guid_sets[0]) == 1
    exactly_once = all(len(per_writer[w]) == len(union) for w in relays)
    pub = next(iter(guid_sets[0])) if guid_sets[0] else None
    print(f"relays={len(relays)} origin-GUID-sets={[sorted(s) for s in guid_sets]} "
          f"union(GUID,SN)={len(union)} converged={converged} exactly_once={exactly_once}")
    if converged and exactly_once:
        print(f"CONVERGED: both relays stamp OWI origin GUID {pub}; a dedup receiver delivers exactly "
              f"N={len(union)} (cross-vendor dual-relay exactly-once).")
        return 0
    print("NOT-CONVERGED: relay origin GUID sets differ or non-singleton (see --owi-dump).")
    return 1
```
And wire it in `__main__` (after the `--dedup-union` branch) with `sys.exit(assert_converged(...))`:
```python
    elif args and args[0] == '--assert-converged':
        sys.exit(assert_converged(args[1] if len(args) > 1 else 'captures/coexistence-transient.pcap'))
```

- [ ] **Step 2: Run the live harness, direction (a) — our-stack reader.**
```
DIR=a interop/durability-coexist-dedup/run-coexist-both.sh
```
Expected: `OUR-READER-RESULT` shows exactly N delivered (our `reader-dedup-accept-p` collapsing both relay streams); the per-relay analysis prints both relays' wire OWI = the publisher GUID.

- [ ] **Step 3: Assert convergence on the dir-(a) capture.**
```
python3 interop/durability-persistent/coexistence/analyze-capture.py --assert-converged interop/durability-coexist-dedup/captures/coexist-dir-a.pcap; echo "exit=$?"
```
Expected: `CONVERGED: both relays stamp OWI origin GUID <pub>; … exactly N`, `exit=0`. If `NOT-CONVERGED`, run `--owi-dump` to see which relay diverged and re-check the Task-2 fix took effect in `driver-relay2`'s service; if it is loopback discovery (a relay not matched), re-run; if it persistently fails despite the fix, STOP and escalate to the owner (do not downgrade the gate).

- [ ] **Step 4: Run direction (b) — Connext `shapes_sub` — and assert.**
```
DIR=b interop/durability-coexist-dedup/run-coexist-both.sh
python3 interop/durability-persistent/coexistence/analyze-capture.py --assert-converged interop/durability-coexist-dedup/captures/coexist-dir-b.pcap; echo "exit=$?"
```
Expected: the Connext subscriber tail shows exactly N received; `--assert-converged` exit=0.

- [ ] **Step 5: Refresh the harness header + add the assertion to the script.** In `run-coexist-both.sh`, after the existing analysis calls (~line 155), add:
```bash
  echo "--- converged-exactly-once assertion ($label) ---"
  python3 "$REPO/interop/durability-persistent/coexistence/analyze-capture.py" --assert-converged "$cap" \
    && echo "   CONVERGED ($label)" || echo "   NOT-CONVERGED ($label) — see --owi-dump"
```
And replace the `# FINDING (...)` block (~lines 12-18) with the captured result (both relays' wire OWI = the publisher GUID after ADR 0028; cross-vendor dual-relay exactly-once captured; cite ADR 0028 + the in-process convergence test).

- [ ] **Step 6: Commit (captures + analyzer + script).**
```
git add interop/durability-persistent/coexistence/analyze-capture.py interop/durability-coexist-dedup/run-coexist-both.sh interop/durability-coexist-dedup/captures/coexist-dir-a.pcap interop/durability-coexist-dedup/captures/coexist-dir-b.pcap
git commit -m "test(interop): WP-DURABILITY-COEXIST-LIVE — LIVE cross-vendor dual-relay exactly-once CAPTURED both directions (both relays' wire OWI = the publisher GUID; receiver collapses to exactly N); analyze-capture --assert-converged gate (M6/P5, ADR 0028)"
```
Expected: captures committed; the commit message states the actual N for each direction (fill from Steps 2/4).

---

### Task 4: capstone — ADR 0028 + docs lockstep + final review

**Files:**
- Create: `docs/adr/0028-durability-coexist-live.md`
- Modify: `docs/adr/0027-durability-coexist-dedup.md` (mark §follow-on 1 RESOLVED by ADR 0028), `README.md` (P5 row), `docs/wiki/durability.md`, `docs/verification.csv` (+`P5-COEXIST-LIVE` row), `interop/durability-coexist-dedup/{README.md,driver-our-reader.lisp,driver-relay2.lisp}` (flip "live not captured" → captured)

**Interfaces:** none (docs).

- [ ] **Step 1: Write ADR 0028.** As-built: the root cause (data-path stored the wire sender; the lifecycle path already used `orig-guid`); the fix (`node-sample-origin-guid`/`-sn` + `%collect-loop` re-stamps the logical origin; default byte-identical; control-plane); the live capture results (dir-a our reader N/N, dir-b Connext N/N, both relays' wire OWI = the publisher GUID); resolves ADR 0027 §follow-on 1; conformance (RTPS §8.3.5.4 relay transparency; honoring OWI consistent with ADR 0024 trust model); the §follow-on still open (coexistence with a PS that does NOT emit standard OWI on replay — ADR 0027 §follow-on 2).

- [ ] **Step 2: Docs lockstep.** ADR 0027 §follow-on 1 → "RESOLVED by ADR 0028"; README P5 row (cross-vendor dual-relay exactly-once now LIVE-captured); `docs/wiki/durability.md` (the coexistence section + the `node-sample-origin-guid`/`-sn` API + `:collect-durability` now complete); `docs/verification.csv` append a `P5-COEXIST-LIVE` row (6 columns, CSV-validated); flip the `interop/durability-coexist-dedup/README.md` + the two driver headers from "live not captured" to the captured figures.

- [ ] **Step 3: Full gate sweep both impls (Clasp first).**
```
make test-clasp && make test-sbcl && make gate-hotpath && make gate-types && make mem && make fuzz && make wire
```
Expected: test-clasp + test-sbcl both green (deterministic; +2 tests vs the branch base), `gate-hotpath` PASS, `gate-types` PASS, `mem` 0.0000, `fuzz` PASS, `wire` PASS.

- [ ] **Step 4: Commit the capstone.**
```
git add docs/adr/0028-durability-coexist-live.md docs/adr/0027-durability-coexist-dedup.md README.md docs/wiki/durability.md docs/verification.csv interop/durability-coexist-dedup/README.md interop/durability-coexist-dedup/driver-our-reader.lisp interop/durability-coexist-dedup/driver-relay2.lisp
git commit -m "docs(durability): WP-DURABILITY-COEXIST-LIVE capstone — ADR 0028 + flip the coexistence finding to LIVE-captured cross-vendor exactly-once across ADR 0027/README/wiki/verification/harness (M6/P5)"
```

- [ ] **Step 5: Final whole-branch review → squash-merge (controller, HOLD PUSH).** Run the final whole-branch review over `main..HEAD` (a fresh code-reviewer per the requesting-code-review template, most-capable model), adversarially verify each Critical/Important against the code, fix via ONE fix subagent, then present the squash-merge commit message for owner approval — **HOLD PUSH**.

---

## Self-review

**Spec coverage:** §1 root cause → Tasks 1-2 (capture + use). §4.1 disc-node capture → Task 1. §4.2 `%collect-loop` → Task 2. §4.3 harness + analyzer → Task 3. §6 testing: unit (T1 Step 2), convergence (T2 Step 1), regressions (T2 Step 5), LIVE gate (T3), all gates (T4 Step 3). §5 threat model → ADR 0028 (T4 Step 1). §7 decomposition → the four tasks. All covered.

**Placeholder scan:** every code/test step shows complete code; every command shows the exact invocation + expected output. The only values deferred to runtime are the live capture's actual N per direction (T3 Steps 2/4/6) — inherent to a live measurement, filled from the run, not a plan placeholder.

**Type consistency:** `node-sample-origin-guid (node key) → (simple-array (unsigned-byte 8) (16))` and `node-sample-origin-sn (node key) → integer` are defined identically in Task 1 (Steps 6) and consumed in Task 2 (Step 3) and the tests. `%record-sample-origin (node wire-guid sn eff-guid eff-sn)` matches its single call form. `store-put`/`publish-relay-sample` argument order matches their real signatures. The dedup key in `%collect-loop` switches from `(writer-guid sn)` to `(origin-guid origin-sn)` consistently across `%collect-seen-p`/`%collect-mark-seen!`/`store-put`/`publish-relay-sample`.
