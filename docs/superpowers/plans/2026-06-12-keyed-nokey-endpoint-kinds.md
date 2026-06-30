# Keyed / No-Key Endpoint Kinds Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** A no-key type (no `@key` members) announces RTPS entity kind `0x03` (writer) / `0x04` (reader) and matches/data-exchanges only with a no-key peer; a keyed type keeps `0x02`/`0x07` exactly as today; a keyed/no-key endpoint pair never matches — verified offline and against live Connext.

**Architecture:** Keyed-ness is a `type-support.keyed-p` flag set by `define-dds-type` from the `@key` members. `add-local-writer/reader` take `:keyed` (default T) and pick the entity-kind octet; the disc-node carries its actual user writer/reader entity-ids (defaulting to the keyed `0x102`/`0x107`) which the data plane reads in place of the fixed constants; `%match-remote-endpoint` requires keyed-ness agreement.

**Tech Stack:** Common Lisp (`defun*`/`defstruct*`, full ftype declarations), the `dds.types` type-support, `dds.disc` discovery + data plane, `dds.dcps` entities; the `interop/connext/` harness (NDDSHOME 7.3.1) + tshark for the live leg. Spec: `docs/superpowers/specs/2026-06-12-keyed-nokey-endpoint-kinds-design.md`.

---

## Standing rules (restate to every subagent)

1. **Never hardcode a wire constant from memory** — the RTPS entity kinds (writer WITH_KEY `0x02` / NO_KEY `0x03`; reader WITH_KEY `0x07` / NO_KEY `0x04`) are pinned from RTPS 2.5 §9.3.1.2 Table 9.1; cite the clause in a comment. (They already appear in `dataplane.lisp`'s `%reader-guid-p`/`%writer-guid-p` — confirm against the clause.)
2. **Back-compat is sacred.** `:keyed` and `type-support.keyed-p` default to **T**; a keyed type must yield byte-identical wire to today (`0x102`/`0x107`). The keyed ShapeType interop is the regression oracle (S1).
3. Lisp: `defun*`/`defstruct*` with full `(function (...) ...)` ftype declarations; docstrings on added/changed exported symbols; one-line comments; bounds-check any new network-facing read; no reader conditionals outside `dds-pal/`.
4. Suite green per task on SBCL (`make test-sbcl`, currently **102**); Clasp at each stage boundary (`GC_DONT_GC=1 make test-clasp`, one retry on the known flake clasp#1793). `make gate-types` + `make gate-hotpath` green.
5. **Every commit message is PRESENTED TO THE OWNER FOR APPROVAL before `git commit`.** No AI attribution; no AI-assistant attribution in any repo file; cite "the operating contract", never a config filename.
6. Docs in lockstep (operating contract §5.1): changed exported symbols update docstrings + `docs/wiki/` + `README.md` if status shifts; `docs/verification.csv` FR-RTPS per stage; `docs/provenance.md` for the live capture.

## Reference: the code you are extending

- **`src/dds-types/type-support.lisp:3`** — the `type-support` defstruct. Slots include name/type-name/extensibility/serialize/.../key-hash/typeobject. You add `keyed-p`.
- **`src/dds-gen/dsl.lisp`** — `define-dds-type` (line ~81): `parsed` members, `keys` = `(remove-if-not (lambda (m) (getf m :key)) parsed)` at line ~98, the `make-type-support` call at line ~188 (currently passes `:key-hash` when `keys`). You pass `:keyed-p`.
- **`src/dds-disc/disc.lisp`** — `disc-node` defstruct (line 15; slots `guid-prefix`, `local-writers`, `local-readers`, `user-writer`, `user-reader`, …); `add-local-writer` (line 214, builds the GUID with kind `#x02` via `%make-endpoint-guid prefix key #x02`); `add-local-reader` (line 230, kind `#x07`); `%match-remote-endpoint` (line 500, matches by topic-name + type-name). `%make-endpoint-guid` builds the 16-octet GUID (prefix + 3-octet key + kind octet).
- **`src/dds-disc/dataplane.lisp`** — `+user-writer-id+` `#x00000102` (line 19) / `+user-reader-id+` `#x00000107` (line 20); 11 use sites at lines 117, 127, 135, 144, 151, 197, 208, 212, 246, 255, 265 — all inside functions that take `node`. `%reader-guid-p` (line 58, kinds `0x04`/`0x07`), `%writer-guid-p` (line 63, kinds `0x02`/`0x03`).
- **`src/dds-dcps/entities.lisp`** — `create-datawriter`/`create-datareader` call `add-local-writer`/`add-local-reader`; they have the topic's `type-support` via `(topic-type-support topic)`.
- **Tests** — `src/dds-tests/` (data-plane round-trip tests exist — grep `run-dataplane` / `run-sedp` for the node-to-node UDP-loopback pattern); register new tests in `src/dds-tests/echo-test.lisp`.

---

## Stage S0 — offline mechanism

### Task 0.1: `keyed-p` on type-support, set by the DSL

**Files:**
- Modify: `src/dds-types/type-support.lisp` (slot), `src/dds-types/packages.lisp` (export `type-support-keyed-p`), `src/dds-gen/dsl.lisp` (set it)
- Test: a DSL test file (grep `define-dds-type` in `src/dds-tests/` to find where types are defined for tests; co-locate)

- [ ] **Step 1: Write the failing test** — a keyed type has `keyed-p` T, a no-key type has `keyed-p` NIL:

```lisp
(defun* run-keyed-p-test ()
    (function () t)
  "type-support-keyed-p is T for a type with a @key member, NIL for a keyless type."
  (dds.gen:define-dds-type kp-keyed-t (:extensibility :final)
    (id :i32 :key t) (v :i32))
  (dds.gen:define-dds-type kp-nokey-t (:extensibility :final)
    (a :i32) (b :i32))
  (assert (dds.types:type-support-keyed-p (dds.types:find-type-support "kp-keyed-t")))
  (assert (not (dds.types:type-support-keyed-p (dds.types:find-type-support "kp-nokey-t"))))
  t)
```

Confirm the registered NAME the DSL uses (it may downcase / keep the symbol name — check an existing `define-dds-type` test's `find-type-support` call for the exact name string). Register `("keyed-p" . run-keyed-p-test)` in `echo-test.lisp`.

- [ ] **Step 2: Run it, expect failure** (`make test-sbcl`): no `type-support-keyed-p`.

- [ ] **Step 3: Add the slot** to `type-support.lisp` (after `extensibility`):

```lisp
  (keyed-p t :type boolean)
```

Update the defstruct docstring to mention `keyed-p` (the WITH_KEY/NO_KEY TopicKind, default T). Export `type-support-keyed-p` from `packages.lisp` (`dds.types`).

- [ ] **Step 4: Set it in the DSL.** In `define-dds-type`'s `make-type-support` call (dsl.lisp ~188), add:

```lisp
             :keyed-p (and keys t)
```

(`keys` is already bound at line ~98.)

- [ ] **Step 5: Run it, expect pass** (`make test-sbcl` → 103).

- [ ] **Step 6: Commit** (present message):
```
feat(types): type-support keyed-p flag, set by define-dds-type (FR-RTPS)

A type with >=1 @key member is keyed; define-dds-type records it on the
type-support so discovery can pick the RTPS entity kind. Defaults T
(back-compat). Test keyed-p.
```

### Task 0.2: Entity-kind selection + the disc-node's data-plane ids

**Files:**
- Modify: `src/dds-disc/disc.lisp` (disc-node slots, add-local-writer/reader), `src/dds-disc/dataplane.lisp` (the 11 use sites)
- Test: `src/dds-tests/` (a new endpoint-kind test)

- [ ] **Step 1: Write the failing test** — keyed yields `0x02`/`0x07` announced + the node's ids `0x102`/`0x107`; no-key yields `0x03`/`0x04` + `0x103`/`0x104`:

```lisp
(defun* run-endpoint-kind-test ()
    (function () t)
  "add-local-writer/reader pick the RTPS entity kind from :keyed and set the node's
   data-plane user ids: keyed (default) -> writer 0x02/id 0x102, reader 0x07/id 0x107;
   no-key -> writer 0x03/id 0x103, reader 0x04/id 0x104."
  (let ((kn (dds.disc:make-disc-node :guid-prefix (%kn-prefix) :domain 0))
        (nn (dds.disc:make-disc-node :guid-prefix (%kn-prefix) :domain 0)))
    ;; keyed (default)
    (let ((w (dds.disc:add-local-writer kn :topic "T" :type "X"))
          (r (dds.disc:add-local-reader kn :topic "T" :type "X")))
      (assert (= #x02 (aref (dds.rtps.discovery:endpoint-data-guid w) 15)))
      (assert (= #x07 (aref (dds.rtps.discovery:endpoint-data-guid r) 15)))
      (assert (= #x00000102 (dds.disc:disc-node-user-writer-id kn)))
      (assert (= #x00000107 (dds.disc:disc-node-user-reader-id kn))))
    ;; no-key
    (let ((w (dds.disc:add-local-writer nn :topic "T" :type "X" :keyed nil))
          (r (dds.disc:add-local-reader nn :topic "T" :type "X" :keyed nil)))
      (assert (= #x03 (aref (dds.rtps.discovery:endpoint-data-guid w) 15)))
      (assert (= #x04 (aref (dds.rtps.discovery:endpoint-data-guid r) 15)))
      (assert (= #x00000103 (dds.disc:disc-node-user-writer-id nn)))
      (assert (= #x00000104 (dds.disc:disc-node-user-reader-id nn))))
    t))
```

Write `%kn-prefix` (a 12-octet prefix, mirror an existing test's helper — grep `%make-prefix`/`make-array 12` in the tests). Confirm `make-disc-node`, `disc-node-user-writer-id`, `disc-node-user-reader-id` are exported (the slots are added below; export the accessors). Register `("endpoint-kind" . run-endpoint-kind-test)`.

- [ ] **Step 2: Run it, expect failure** (no `:keyed` keyword, no `disc-node-user-writer-id`).

- [ ] **Step 3: Add the disc-node slots** (disc.lisp, in the defstruct after `user-reader`), defaulting to the keyed ids so existing nodes are unchanged:

```lisp
  (user-writer-id #x00000102 :type (unsigned-byte 32)) ; this node's user-data writer EntityId (kind reflects keyed-ness)
  (user-reader-id #x00000107 :type (unsigned-byte 32)) ; this node's user-data reader EntityId
```

Export `disc-node-user-writer-id` / `disc-node-user-reader-id` from `src/dds-disc/packages.lisp`.

- [ ] **Step 4: Add `:keyed` to add-local-writer** (disc.lisp:214). Replace the kind `#x02` and set the node id:

```lisp
(defun* add-local-writer (node &key (topic "") (type "")
                                   (reliability dds.rtps.discovery:+reliability-reliable+)
                                   (key 1) (keyed t) qos type-information)
    (function (disc-node &key (:topic string) (:type string) (:reliability integer) (:key (unsigned-byte 8)) (:keyed t) (:qos t) (:type-information t)) dds.rtps.discovery:endpoint-data)
  "Register a local publication (writer endpoint) on NODE. KEYED selects the RTPS entity
   kind (RTPS 2.5 §9.3.1.2): WITH_KEY 0x02 (default) or NO_KEY 0x03; a keyed remote reader
   will not match a no-key writer. Sets NODE's data-plane user-writer-id to the matching
   EntityId (kind in the low octet). TYPE-INFORMATION is the opaque XTypes TypeInformation."
  (let* ((kind (if keyed #x02 #x03))
         (ep (dds.rtps.discovery:make-endpoint-data
              :guid (%make-endpoint-guid (disc-node-guid-prefix node) key kind)
              :topic-name topic :type-name type :type-information type-information
              :qos (or qos (%qos-from-reliability reliability)))))
    (setf (disc-node-user-writer-id node) (logior (ash key 8) kind))
    (push ep (disc-node-local-writers node))
    ep))
```

- [ ] **Step 5: Add `:keyed` to add-local-reader** (disc.lisp:230) — kind `#x07` (keyed) / `#x04` (no-key):

```lisp
(defun* add-local-reader (node &key (topic "") (type "")
                                   (reliability dds.rtps.discovery:+reliability-best-effort+)
                                   (key 1) (keyed t) qos type-information)
    (function (disc-node &key (:topic string) (:type string) (:reliability integer) (:key (unsigned-byte 8)) (:keyed t) (:qos t) (:type-information t)) dds.rtps.discovery:endpoint-data)
  "Register a local subscription (reader endpoint) on NODE. KEYED selects the RTPS entity
   kind (RTPS 2.5 §9.3.1.2): WITH_KEY 0x07 (default) or NO_KEY 0x04. Sets NODE's data-plane
   user-reader-id to the matching EntityId. TYPE-INFORMATION is the opaque XTypes TypeInformation."
  (let* ((kind (if keyed #x07 #x04))
         (ep (dds.rtps.discovery:make-endpoint-data
              :guid (%make-endpoint-guid (disc-node-guid-prefix node) key kind)
              :topic-name topic :type-name type :type-information type-information
              :qos (or qos (%qos-from-reliability reliability)))))
    (setf (disc-node-user-reader-id node) (logior (ash key 8) kind))
    (push ep (disc-node-local-readers node))
    ep))
```

- [ ] **Step 6: Thread the node ids into the data plane** (dataplane.lisp). At EACH of the 11 use sites (lines 117/127/135/144/151/197/208/212/246/255/265), replace `+user-writer-id+` with `(disc-node-user-writer-id node)` and `+user-reader-id+` with `(disc-node-user-reader-id node)`. Every one of those functions takes `node`. Two sites are equality CHECKS (`(when (= wid +user-writer-id+) ...)` at 208/255) — those compare an inbound writer id to OUR writer id; replace with `(disc-node-user-writer-id node)` too (the inbound HEARTBEAT/ACKNACK targets our actual writer id). Keep the `+user-writer-id+`/`+user-reader-id+` constants defined (they remain the documented keyed defaults + the disc-node slot defaults). Verify by grep that no `+user-writer-id+`/`+user-reader-id+` bare reference remains in a send/route path (only the defconstants + the disc-node slot defaults).

- [ ] **Step 7: Run it, expect pass.** Then run the FULL suite — the existing keyed data-plane round-trip tests MUST still pass (they exercise the default keyed node → `0x102`/`0x107`, now via the node slots). `make test-sbcl` green.

- [ ] **Step 8: Commit** (present message):
```
feat(disc): per-endpoint keyed/no-key entity kinds + data-plane id threading (FR-RTPS)

add-local-writer/reader take :keyed (default T): writer kind 0x02/0x03,
reader 0x07/0x04 (RTPS 2.5 §9.3.1.2). The disc-node carries its actual
user writer/reader EntityId (kind reflecting keyed-ness, default 0x102/
0x107); the data-plane send/route paths read those instead of the fixed
constants, so a no-key endpoint speaks 0x103/0x104 and a keyed one is
byte-identical to before. Test endpoint-kind; keyed round-trip unchanged.
```

### Task 0.3: keyed-ness agreement at match time

**Files:** Modify `src/dds-disc/disc.lisp` (`%match-remote-endpoint`); Test: `src/dds-tests/`.

- [ ] **Step 1: Write the failing test** (two-node UDP loopback or the direct `%match-remote-endpoint` unit — mirror `run-sedp-type-gate-test`'s structure): a keyed local reader does NOT match a no-key remote writer, and a no-key local reader DOES match a no-key remote writer:

```lisp
(defun* run-keyed-match-test ()
    (function () t)
  "A keyed/no-key endpoint-kind disagreement is a silent non-match; same-kind matches."
  (let ((node (dds.disc:make-disc-node :guid-prefix (%kn-prefix) :domain 0)))
    (dds.disc:add-local-reader node :topic "T" :type "X")          ; keyed reader 0x07
    (let ((nokey-writer (%remote-endpoint (%kn-prefix2) "T" "X" #x03))  ; no-key remote writer
          (keyed-writer (%remote-endpoint (%kn-prefix2) "T" "X" #x02)))
      (assert (not (dds.disc::%match-remote-writer node nokey-writer)))  ; kind disagreement -> no match
      ;; switch the local reader to no-key and the no-key writer now matches
      (setf (dds.disc:disc-node-local-readers node) '())
      (dds.disc:add-local-reader node :topic "T" :type "X" :keyed nil)   ; no-key reader 0x04
      (assert (dds.disc::%match-remote-writer node nokey-writer))
      (assert (not (dds.disc::%match-remote-writer node keyed-writer)))  ; keyed writer vs no-key reader -> no match
      t)))
```

Write `%remote-endpoint prefix topic type writer-kind` building an `endpoint-data` whose GUID's kind octet = `writer-kind` (mirror how the existing match tests fabricate a remote endpoint — grep `%remote-endpoint`/`make-endpoint-data` in the tests; reuse if present). Register `("keyed-match" . run-keyed-match-test)`.

- [ ] **Step 2: Run it, expect failure** (the keyed reader currently matches the no-key writer — keyed-ness isn't checked).

- [ ] **Step 3: Add the guard** in `%match-remote-endpoint` (disc.lisp:500). After establishing the local endpoint and BEFORE recording the match, require keyed-ness agreement. The local writer-vs-remote-reader (and local-reader-vs-remote-writer) keyed-ness is read from the GUID kind octets: a writer is WITH_KEY iff kind `0x02` (vs `0x03`), a reader WITH_KEY iff kind `0x07` (vs `0x04`). Add a helper near the other GUID predicates (dataplane.lisp) and call it:

```lisp
(defun* %endpoint-keyed-p (guid)
    (function ((simple-array (unsigned-byte 8) (16))) t)
  "T iff the endpoint GUID's entity kind is a WITH_KEY user endpoint: writer 0x02 or
   reader 0x07 (vs NO_KEY writer 0x03 / reader 0x04) — RTPS 2.5 §9.3.1.2 Table 9.1."
  (let ((k (aref guid 15))) (or (= k #x02) (= k #x07))))
```

In `%match-remote-endpoint`, when a local endpoint and a remote endpoint would otherwise match on topic+type, add: if `(not (eq (%endpoint-keyed-p local-guid) (%endpoint-keyed-p remote-guid)))` then this is an endpoint-kind incompatibility → return without recording the match and WITHOUT setting `inconsistent` (a silent non-match, per the design). Place it so it does not affect the type-name-mismatch INCONSISTENT_TOPIC path (kind disagreement is a distinct, earlier, silent reject). Read the function body and insert the guard at the point where topic+type already agree.

- [ ] **Step 4: Run it, expect pass.** Full suite green (existing keyed matches are keyed-vs-keyed → agree → unaffected). `make test-sbcl`.

- [ ] **Step 5: Commit** (present message):
```
feat(disc): reject keyed/no-key endpoint-kind mismatches at match time (FR-RTPS)

%match-remote-endpoint now requires the local + remote endpoint keyed-ness
to agree (WITH_KEY writer 0x02/reader 0x07 vs NO_KEY 0x03/0x04, RTPS 2.5
§9.3.1.2) before recording a match; a disagreement is a silent non-match
(a fundamental endpoint-kind incompatibility below type consistency, not
INCONSISTENT_TOPIC). Test keyed-match; keyed-vs-keyed unaffected.
```

### Task 0.4: DCPS threading + a no-key test type + offline round-trip

**Files:** Modify `src/dds-dcps/entities.lisp` (`create-datawriter`/`create-datareader`); Test: `src/dds-tests/`.

- [ ] **Step 1: Thread keyed-p in DCPS.** In `create-datawriter` and `create-datareader` (entities.lisp), where they call `add-local-writer`/`add-local-reader`, pass `:keyed (dds.types:type-support-keyed-p (topic-type-support topic))`. (Find the exact `add-local-*` call sites; the topic is in scope as the writer/reader's topic.)

- [ ] **Step 2: Write the failing offline round-trip test** — a no-key DSL type, our no-key writer → our no-key reader over UDP loopback (mirror the existing `run-dataplane-test` / `run-dcps-*` node-to-node pattern; find it and copy its structure precisely):

```lisp
(defun* run-nokey-roundtrip-test ()
    (function () t)
  "A no-key type round-trips through the data plane: a no-key writer (0x03) and a no-key
   reader (0x04) on two nodes discover, match (same kind), and deliver a sample."
  ;; define a no-key type; create two participants; one no-key DataWriter, one no-key
  ;; DataReader on the same topic; spin discovery; write one sample; assert take returns it.
  ;; (Build from the existing run-dcps-roundtrip / run-dataplane-test harness — same nodes,
  ;;  same spin loop, same UDP loopback; the ONLY difference is the type has no @key so the
  ;;  endpoints come up 0x03/0x04.)
  ...)
```

Implement it by cloning the closest existing node-to-node DCPS round-trip test, swapping in a no-key type (`define-dds-type nokey-rt (:extensibility :final) (a :i32) (b :i32)`). Register `("nokey-roundtrip" . run-nokey-roundtrip-test)`.

- [ ] **Step 3: Run it, expect failure first** if the type/threading isn't wired, then **pass** after Step 1. Assert the delivered sample equals the written one AND (optionally, via the capture or the endpoint GUIDs) the endpoints are kind `0x03`/`0x04`.

- [ ] **Step 4: Full suite green** — the keyed DCPS round-trip tests still pass (keyed type → `0x102`/`0x107`). `make test-sbcl`.

- [ ] **Step 5: Clasp at the S0 boundary** — `GC_DONT_GC=1 make test-clasp` (one retry on the flake). `make gate-types gate-hotpath`.

- [ ] **Step 6: Commit** (present message):
```
feat(dcps): DataWriter/DataReader select endpoint kind from the type (FR-RTPS S0)

create-datawriter/datareader pass :keyed (type-support-keyed-p) into
add-local-*, so a keyless type's endpoints come up NO_KEY (0x03/0x04) and
a keyed type stays WITH_KEY. Offline node-to-node no-key round-trip green
(nokey-roundtrip); keyed round-trips unchanged. NN green SBCL+Clasp.
```

---

## Stage S1 — live Connext no-key

### Task 1.1: No-key Connext harness app

**Files:**
- Create: `interop/connext/nokey/` (IDL + pub/sub + Makefile, mirroring an existing `interop/connext/` app — e.g. `shapes-pub`/`shapes-sub`; read one for the build pattern, NDDSHOME/CONNEXTDDS_ARCH, the USER_QOS_PROFILES.xml single-iface pin)
- Modify: top-level `Makefile` (a `nokey-pub`/`nokey-sub` convenience target if the harness side needs one; the Connext side builds under `interop/connext/nokey/`)

- [ ] **Step 1: The IDL** — a keyless struct (NO `@key`), e.g.:

```idl
struct NoKeyData {
    long a;
    long b;
};
```

(`rtiddsgen` makes this a NO_KEY topic; Connext announces reader kind `0x04` / writer kind `0x03`.) Mirror the existing Connext app's IDL + generated-code + main structure (clean-room: this is OUR IDL; the generated rtiddsgen output is a build artifact, NOT copied into our `src/`).

- [ ] **Step 2: pub + sub mains** — minimal RELIABLE NoKeyData pub and sub, mirroring `interop/connext/shapes-{pub,sub}` exactly (same QoS, same single-iface profile, same logging). Build per the existing app's Makefile.

- [ ] **Step 3:** Our-side no-key harness entry — add a no-key publisher/subscriber to `src/dds-shapes/shapes.lisp` (or a small harness) using a no-key type, OR reuse the offline no-key type via a `make` target. Mirror `run-publisher`/`run-subscriber` but with the no-key type so our endpoints come up `0x03`/`0x04`. (Confirm the exact harness entry to add by reading the existing keyed `run-publisher`.)

- [ ] **Step 4: Commit** (present message):
```
feat(interop): no-key Connext harness (NoKeyData) + our no-key publisher/subscriber (FR-RTPS S1)

interop/connext/nokey/ (keyless NoKeyData IDL -> rtiddsgen RELIABLE pub/sub)
+ a no-key harness entry on our side, for the live no-key endpoint-kind
interop leg. No data run yet (next task).
```

### Task 1.2: Live no-key interop + keyed-not-regressed

**Files:** Modify `interop/connext/nokey/README.md` (run log) or `docs/provenance.md`; Create captures under `interop/connext/nokey/captures/`.

- [ ] **Step 1: Forward** — capture lo0 (`tshark -i lo0 --enable-protocol null --enable-protocol ip --enable-protocol udp -w nokey-forward.pcap`); Connext `nokey_pub` → our no-key sub. Expected: our sub receives the samples; tshark shows the user DATA on writer kind `0x03` / our reader `0x04`. (Environment per the standing notes: NDDSHOME=/Applications/rti_connext_dds-7.3.1, CONNEXTDDS_ARCH=arm64Darwin20clang12.0, DYLD_LIBRARY_PATH.)
- [ ] **Step 2: Reverse** — our no-key pub → Connext `nokey_sub`; expected delivery + tshark kind `0x03`/`0x04`. Archive `nokey-reverse.pcap`.
- [ ] **Step 3: Keyed-vs-no-key non-match (live)** — point a Connext KEYED reader (the existing keyed ShapeType sub, or a keyed NoKeyData variant) at our no-key writer (or vice versa) and confirm NO match (Connext logs no match; no data; our match table records none). Capture/log it.
- [ ] **Step 4: Keyed regression** — re-run the existing keyed ShapeType interop (`make square-pub`/`square-sub` ↔ Connext) and confirm it still works (the keyed path is byte-identical). Log it.
- [ ] **Step 5:** Any wire bug found in our stack → fix clause-cited, failing-test-first, suite green, separate commit. Archive all pcaps + logs; write the run notes into `interop/connext/nokey/README.md`.
- [ ] **Step 6: Clasp at the S1 boundary** (`GC_DONT_GC=1 make test-clasp`). **Commit** (present message):
```
feat(interop): live Connext no-key endpoint-kind interop (FR-RTPS S1)

Bidirectional no-key NoKeyData exchange with live Connext 7.3.1
(writer 0x03 / reader 0x04, tshark-validated; captures in
interop/connext/nokey/): forward Connext nokey_pub -> our no-key sub
(N samples) + reverse (M). A keyed-vs-no-key pair does NOT match live.
The keyed ShapeType interop re-run is unchanged (no regression).
```

---

## Stage S2 — closeout

### Task 2.1: Docs + verification + memory

**Files:** Modify `docs/verification.csv` (FR-RTPS), `docs/wiki/{discovery,dataplane}.md` (grep the actual page names), `README.md`, `docs/provenance.md`; memory.

- [ ] **Step 1:** `docs/verification.csv` FR-RTPS — the keyed-only residual is closed: per-type keyed/no-key endpoint kinds, offline + live Connext, cite the tests (`endpoint-kind`, `keyed-match`, `nokey-roundtrip`) + the live captures. Do not overclaim (multi-endpoint-per-participant is still out of scope).
- [ ] **Step 2:** Wiki (discovery + data-plane pages: the `:keyed` parameter, the entity-kind selection, the match-rejection) + `README.md` status if it lists the keyed-only residual.
- [ ] **Step 3:** `docs/provenance.md` — the live no-key capture (entity kinds confirmed on the wire vs RTPS 2.5 §9.3.1.2).
- [ ] **Step 4:** Full gates — `make build-sbcl test-sbcl gate-types gate-hotpath`; `GC_DONT_GC=1 make test-clasp`. Paste tails. **Commit** the closeout (present message).
- [ ] **Step 5:** Update the `dds-stack-position` memory: keyed/no-key residual closed; new HEAD; the sequence advances to feature 2 (liveliness/lease expiry). Push held for owner approval.

---

## Self-review notes (run; fixed inline)

- **Spec coverage:** spec §4 units → Task 0.1 (keyed-p), 0.2 (kind selection + node ids), 0.3 (match-rejection), 0.4 (DCPS threading + no-key type), 1.1/1.2 (interop type + live), 2.1 (closeout); §6 back-compat → the "keyed round-trips unchanged" assertion in 0.2/0.4 + the keyed regression in 1.2; §7 testing → the per-stage tests; §8 stages → S0/S1/S2.
- **Deliberate execution-time reads (not placeholders):** the exact registered type-name string the DSL uses (0.1 Step 1), the closest existing node-to-node round-trip test to clone (0.4 Step 2), the `%remote-endpoint`/`%kn-prefix` test helpers (reuse if present, else write — 0.2/0.3), the existing Connext app to mirror (1.1). Each names its source. The 0.4 Step 2 test body is a clone-and-swap of a named existing test — its structure is concrete (no-key type, same harness), the literal cloned code is read at execution.
- **Type consistency:** `type-support-keyed-p`, `:keyed`, `disc-node-user-writer-id`/`-reader-id`, `%endpoint-keyed-p` used consistently across tasks; the entity kinds (writer 0x02/0x03, reader 0x07/0x04) and ids (0x102/0x107 keyed, 0x103/0x104 no-key) consistent throughout; `%match-remote-endpoint`/`%match-remote-writer` are the existing names.
