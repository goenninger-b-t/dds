# DATA_FRAG Data-Plane + Fragment-Level Reliability + Connext Interop — Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Let DDS samples larger than one datagram flow reliably between this stack and RTI Connext 7.3.1 using RTPS DATA_FRAG with fragment-level reliability (HEARTBEAT_FRAG + NACK_FRAG).

**Architecture:** Bottom-up, four stages (one commit per task, `main` green throughout). Stage 1 adds the three missing wire codecs. Stage 2 adds the writer fragmentation + reader reassembly + the fragment reliability state machines, proven offline. Stage 3 wires them into the discovery data-plane and adds the `LargeData` DCPS type + harness. Stage 4 stands up the Connext oracle and reaches live bidirectional fragmented interop.

**Tech Stack:** Common Lisp (SBCL + Clasp), the in-repo RTPS/CDR stack, `static-vectors`/`cffi` PAL, tshark RTPS dissector, RTI Connext 7.3.1 + rtiddsgen.

**Spec:** `docs/superpowers/specs/2026-06-09-data-frag-dataplane-design.md`.

## Non-negotiable rules for every task (the operating contract)

- **Define every function with `defun*` and every struct with `defstruct*`** (`dds.lang`); never plain `defun`/`defstruct`. The package must `:use #:net.goenninger.dds.lang` (the RTPS/disc packages already do).
- **Never write a wire constant, field order, or octet layout from memory.** For each codec, open the cited RTPS 2.5 clause in `docs/specs/` (pdftotext the PDF), lay the fields out from the clause, and cite the clause in a one-line comment. The byte-exact *values* are locked against a live Connext capture in Stage 4 — Stage 1 tests prove write/parse internal consistency, Stage 4 proves wire-exactness.
- **Bounds-check every parser** against the submessage extent before trusting any wire length/offset, even at `(safety 0)`.
- **Comments are one line max**; longer rationale goes in the commit message.
- **After each task:** `make gate-types`, `make gate-hotpath`, and the relevant tests must be green on **SBCL and Clasp** before committing. Present the commit message for owner approval before committing (no Co-Authored-By trailer).
- **Run on this box:** SBCL via `./scripts/with-sbcl.sh`; Clasp via `./scripts/with-clasp.sh` (Clasp is installed but not on `PATH`).

## File structure

| File | Responsibility | Stage |
|---|---|---|
| `src/dds-rtps/message.lisp` (modify) | FragmentNumberSet + HEARTBEAT_FRAG + NACK_FRAG codecs (mirror the existing HEARTBEAT/ACKNACK/SequenceNumberSet codecs) | 1 |
| `src/dds-rtps/packages.lisp` (modify) | export the new codec symbols from `dds.rtps.message` | 1 |
| `src/dds-rtps/reliable.lisp` (modify) | writer fragmentation + packing, reader reassembly entry, HEARTBEAT_FRAG/NACK_FRAG state machines | 2 |
| `src/dds-rtps/packages.lisp` (modify) | export the new `dds.rtps.reliable` entry points | 2 |
| `src/dds-disc/dataplane.lisp` (modify) | dispatch routing for the three frag submessages; `%push-data` fragmentation; `%on-user-nackfrag` | 3 |
| `src/dds-tests/rtps-test.lisp` (modify) | codec round-trip + fuzz; offline reassembly + lossy tests | 1,2 |
| `src/dds-tests/echo-test.lisp` (modify) | register new tests in `run-all-tests` | 1,2,3 |
| `src/dds-tests/integration-test.lisp` (modify) | offline e2e LargeData over UDP | 3 |
| `src/dds-shapes/shapes.lisp` + `packages.lisp` (modify) | `large-data` type + `run-large-publisher`/`run-large-subscriber` | 3 |
| `Makefile` (modify) | `large-pub` / `large-sub` targets | 3 |
| `interop/connext/large-data/` (create) | `LargeData.idl`, pub/sub apps, QoS XML forcing fragmentation | 4 |
| `docs/verification.csv`, `docs/wiki/rtps-engine.md`, `README.md` (modify) | doc lockstep (§5.1) | 2,3,4 |

---

## STAGE 1 — Wire codecs

### Task 1.1: FragmentNumberSet codec

**Files:**
- Modify: `src/dds-rtps/message.lisp` (add after `read-sequence-number-set`, ~line 231)
- Test: `src/dds-tests/rtps-test.lisp`

**Clause to pin first:** open `docs/specs/` RTPS 2.5 **§9.4.2.8 FragmentNumberSet** and **§9.4.2.7 FragmentNumber**. A FragmentNumber is a 4-octet `unsigned long` (NOT the 8-octet SequenceNumber). FragmentNumberSet = `bitmapBase` (FragmentNumber, 4 octets) + `numBits` (unsigned long, 4) + `bitmap` (⌈numBits/32⌉ longs, MSB-first within each long, same convention as SequenceNumberSet). Confirm this layout against the clause before writing.

- [ ] **Step 1: Write the failing round-trip test**

In `src/dds-tests/rtps-test.lisp`, add:

```lisp
(defun* run-fragnum-set-test ()
    (function () t)
  "Test: FragmentNumberSet write/read round-trip + the membership bitmap (RTPS 2.5 §9.4.2.8)."
  (let* ((buf (dds.core.buffer:make-octet-buffer 64))
         (wc (dds.core.buffer:cursor buf :endianness :little))
         (bitmap (make-array 1 :element-type '(unsigned-byte 32) :initial-element 0)))
    ;; fragments {3,5} present, base 3, numbits 3  -> deltas 0 and 2 set
    (dds.rtps.message:fragnum-set-bit bitmap 0)
    (dds.rtps.message:fragnum-set-bit bitmap 2)
    (dds.rtps.message:write-fragment-number-set wc 3 3 bitmap)
    (let ((rc (dds.core.buffer:cursor buf :endianness :little)))
      (multiple-value-bind (base numbits bm) (dds.rtps.message:read-fragment-number-set rc)
        (%check :fns-base (= base 3) "FragmentNumberSet base round-trips")
        (%check :fns-numbits (= numbits 3) "FragmentNumberSet numBits round-trips")
        (%check :fns-members
                (and (dds.rtps.message:fragnum-set-member-p base numbits bm 3)
                     (not (dds.rtps.message:fragnum-set-member-p base numbits bm 4))
                     (dds.rtps.message:fragnum-set-member-p base numbits bm 5))
                "FragmentNumberSet membership: 3 and 5 present, 4 absent"))))
  ;; short buffer rejects
  (let* ((buf (dds.core.buffer:make-octet-buffer 4))
         (rc (dds.core.buffer:cursor buf :endianness :little)))
    (%check :fns-short (null (dds.rtps.message:read-fragment-number-set rc))
            "a sub-8-octet FragmentNumberSet rejects"))
  t)
```

- [ ] **Step 2: Register the test and run it to confirm it fails**

In `src/dds-tests/echo-test.lisp` `run-all-tests`, add after `("rtps-seqnum-bitmap" . run-rtps-seqnum-test)`:
```lisp
                 ("rtps-fragnum-set"         . run-fragnum-set-test)
```
Run: `./scripts/with-sbcl.sh --eval '(ql:quickload :dds-tests :silent t)' --eval '(dds.tests:run-all-tests)' --eval '(uiop:quit 0)'`
Expected: FAIL — `WRITE-FRAGMENT-NUMBER-SET` undefined.

- [ ] **Step 3: Implement the codec (mirror SequenceNumberSet)**

In `src/dds-rtps/message.lisp`, mirror `%seqnum-set-words` / `seqnum-set-bit` / `seqnum-set-member-p` / `write-sequence-number-set` / `read-sequence-number-set` (lines 183–231) but with a **4-octet** base. Note `+seqnum-set-max-bits+` = 256 already exists; reuse it (the same 256 bound applies, §9.4.2.8). FragmentNumbers are ≥ 1 (1-based), but the SET is delta-from-base so the same bitmap math applies:

```lisp
;;; FragmentNumberSet (RTPS 2.5 §9.4.2.8): bitmapBase (FragmentNumber, u32) + numBits
;;; + M=ceil(numBits/32) longs; same MSB-first delta bitmap as SequenceNumberSet.
(defun* fragnum-set-bit (bitmap delta)
    (function ((simple-array (unsigned-byte 32) (*)) (integer 0)) (unsigned-byte 32))
  "Set the bit for fragment-offset DELTA: word DELTA/32, bit (31 - DELTA%32) (§9.4.2.8)."
  (let ((w (floor delta 32)))
    (setf (aref bitmap w) (logior (aref bitmap w) (ash 1 (- 31 (mod delta 32)))))))

(defun* fragnum-set-member-p (base numbits bitmap fragnum)
    (function ((unsigned-byte 32) (unsigned-byte 32) (simple-array (unsigned-byte 32) (*)) (unsigned-byte 32)) t)
  "T iff FRAGNUM is in the FragmentNumberSet (§9.4.2.8 membership rule)."
  (let ((delta (- fragnum base)))
    (and (<= base fragnum) (< delta numbits)
         (logbitp (- 31 (mod delta 32)) (aref bitmap (floor delta 32))))))

(defun* write-fragment-number-set (cursor base numbits bitmap)
    (function (dds.core.buffer:cursor (unsigned-byte 32) (unsigned-byte 32) (simple-array (unsigned-byte 32) (*))) fixnum)
  "Write a FragmentNumberSet: bitmapBase (u32) + numBits + M longs (RTPS 2.5 §9.4.2.8)."
  (assert (<= numbits +seqnum-set-max-bits+))
  (dds.core.buffer:put-u32 cursor base)
  (dds.core.buffer:put-u32 cursor numbits)
  (dotimes (i (%seqnum-set-words numbits))
    (dds.core.buffer:put-u32 cursor (aref bitmap i)))
  (dds.core.buffer:cursor-position cursor))

(defun* read-fragment-number-set (cursor)
    (function (dds.core.buffer:cursor) t)
  "Parse a FragmentNumberSet. (values base numBits bitmap) or NIL on short buffer /
   numBits>256 (§9.4.2.8). Bounds-checked; never reads OOB."
  (when (< (%remaining cursor) 8) (return-from read-fragment-number-set nil))
  (let* ((base (dds.core.buffer:get-u32 cursor))
         (numbits (dds.core.buffer:get-u32 cursor)))
    (when (> numbits +seqnum-set-max-bits+) (return-from read-fragment-number-set nil))
    (let ((m (%seqnum-set-words numbits)))
      (when (< (%remaining cursor) (* m 4)) (return-from read-fragment-number-set nil))
      (let ((bitmap (make-array (max 1 m) :element-type '(unsigned-byte 32) :initial-element 0)))
        (dotimes (i m) (setf (aref bitmap i) (dds.core.buffer:get-u32 cursor)))
        (values base numbits bitmap)))))
```

- [ ] **Step 4: Export the symbols**

In `src/dds-rtps/packages.lisp`, in the `dds.rtps.message` package `:export`, add:
```lisp
           #:write-fragment-number-set #:read-fragment-number-set
           #:fragnum-set-bit #:fragnum-set-member-p
```

- [ ] **Step 5: Run the test to verify it passes (both impls)**

Run SBCL then Clasp (commands above / with-clasp.sh). Expected: `rtps-fragnum-set ... ok`.

- [ ] **Step 6: gate-types + commit**

```bash
make gate-types && make gate-hotpath
git add src/dds-rtps/message.lisp src/dds-rtps/packages.lisp src/dds-tests/rtps-test.lisp src/dds-tests/echo-test.lisp
# present message for approval, then:
git commit -m "feat(rtps): FragmentNumberSet codec (RTPS 2.5 §9.4.2.8)"
```

---

### Task 1.2: HEARTBEAT_FRAG codec

**Files:** Modify `src/dds-rtps/message.lisp` (after the GAP codec, ~line 340), `src/dds-rtps/packages.lisp`; Test `src/dds-tests/rtps-test.lisp`.

**Clause to pin first:** RTPS 2.5 **HEARTBEAT_FRAG** in `docs/specs/`. Body = readerId (EntityId 4) + writerId (EntityId 4) + writerSN (SequenceNumber 8) + lastFragmentNum (FragmentNumber u32, 4) + count (Count u32, 4) = **24 octets**. Confirm the field order and that there is no Final/Liveliness flag (only the E flag). The submessage kind `+submsg-heartbeat-frag+` (#x13) already exists.

- [ ] **Step 1: Write the failing round-trip test**

```lisp
(defun* run-heartbeat-frag-test ()
    (function () t)
  "Test: HEARTBEAT_FRAG write/parse round-trip (RTPS 2.5 HEARTBEAT_FRAG; body=24)."
  (let* ((buf (dds.core.buffer:make-octet-buffer 64))
         (wc (dds.core.buffer:cursor buf :endianness :little))
         (rid #x107) (wid #x102) (sn 7) (lastfrag 5) (count 3))
    (dds.rtps.message:write-heartbeat-frag wc rid wid sn lastfrag count)
    (let ((rc (dds.core.buffer:cursor buf :endianness :little)))
      (dds.rtps.message:dispatch-message
       rc (lambda (id flags cur body-len)
            (declare (ignore body-len))
            (%check :hbf-kind (= id dds.rtps.message:+submsg-heartbeat-frag+) "HEARTBEAT_FRAG kind")
            (multiple-value-bind (r w s lf c) (dds.rtps.message:parse-heartbeat-frag-body cur flags)
              (%check :hbf-fields
                      (and (= r rid) (= w wid) (= s sn) (= lf lastfrag) (= c count))
                      "HEARTBEAT_FRAG fields round-trip"))))))
  t)
```
(Confirm `dispatch-message`'s callback arity against `run-rtps-dispatch-test` in the same file; mirror its exact shape.)

- [ ] **Step 2: Register + run to confirm failure** — add `("rtps-heartbeat-frag" . run-heartbeat-frag-test)` to `run-all-tests`; run SBCL. Expected: FAIL (`WRITE-HEARTBEAT-FRAG` undefined).

- [ ] **Step 3: Implement (mirror `write-heartbeat`/`parse-heartbeat-body`, lines 257–285)**

```lisp
(defun* write-heartbeat-frag (cursor reader-id writer-id writer-sn last-fragment-num count)
    (function (dds.core.buffer:cursor (unsigned-byte 32) (unsigned-byte 32) integer (unsigned-byte 32) (unsigned-byte 32)) fixnum)
  "Write a HEARTBEAT_FRAG submessage. RTPS 2.5 HEARTBEAT_FRAG; body=24."
  (write-submessage-header cursor +submsg-heartbeat-frag+ (%e-flag cursor) 24)
  (write-entity-id cursor reader-id)
  (write-entity-id cursor writer-id)
  (write-sequence-number cursor writer-sn)
  (dds.core.buffer:put-u32 cursor last-fragment-num)
  (dds.core.buffer:put-u32 cursor (logand count #xFFFFFFFF))
  (dds.core.buffer:cursor-position cursor))

(defun* parse-heartbeat-frag-body (cursor flags)
    (function (dds.core.buffer:cursor (unsigned-byte 8)) t)
  "Parse a HEARTBEAT_FRAG body. (values reader-id writer-id writer-sn last-fragment-num
   count) or NIL on short buffer. RTPS 2.5 HEARTBEAT_FRAG."
  (declare (ignore flags))
  (when (< (%remaining cursor) 24) (return-from parse-heartbeat-frag-body nil))
  (let ((reader-id (read-entity-id cursor))
        (writer-id (read-entity-id cursor))
        (writer-sn (read-sequence-number cursor))
        (last-fragment-num (dds.core.buffer:get-u32 cursor))
        (count (dds.core.buffer:get-u32 cursor)))
    (values reader-id writer-id writer-sn last-fragment-num count)))
```

- [ ] **Step 4: Export** `#:write-heartbeat-frag #:parse-heartbeat-frag-body` from `dds.rtps.message`.
- [ ] **Step 5: Run SBCL + Clasp.** Expected: `rtps-heartbeat-frag ... ok`.
- [ ] **Step 6: gate-types + commit** — `feat(rtps): HEARTBEAT_FRAG codec`.

---

### Task 1.3: NACK_FRAG codec

**Files:** Modify `src/dds-rtps/message.lisp`, `src/dds-rtps/packages.lisp`; Test `src/dds-tests/rtps-test.lisp`.

**Clause to pin first:** RTPS 2.5 **NACK_FRAG** in `docs/specs/`. Body = readerId (4) + writerId (4) + writerSN (8) + fragmentNumberState (FragmentNumberSet, 8+4M) + count (Count u32, 4) = **24 + 4M**. Confirm the field order.

- [ ] **Step 1: Write the failing round-trip test** (mirror Task 1.2's shape; build a FragmentNumberSet with `fragnum-set-bit`, write `write-nack-frag`, dispatch + `parse-nack-frag-body`, assert reader/writer ids, sn, the recovered set members, and count).

- [ ] **Step 2: Register `("rtps-nack-frag" . run-nack-frag-test)` + run to confirm failure.**

- [ ] **Step 3: Implement (mirror `write-acknack`/`parse-acknack-body`, lines 287–311, swapping the SequenceNumberSet for the FragmentNumberSet from Task 1.1)**

```lisp
(defun* write-nack-frag (cursor reader-id writer-id writer-sn base numbits bitmap count)
    (function (dds.core.buffer:cursor (unsigned-byte 32) (unsigned-byte 32) integer (unsigned-byte 32) (unsigned-byte 32) (simple-array (unsigned-byte 32) (*)) (unsigned-byte 32)) fixnum)
  "Write a NACK_FRAG submessage. RTPS 2.5 NACK_FRAG; body=24+4*M."
  (write-submessage-header cursor +submsg-nack-frag+ (%e-flag cursor)
                           (+ 24 (* 4 (%seqnum-set-words numbits))))
  (write-entity-id cursor reader-id)
  (write-entity-id cursor writer-id)
  (write-sequence-number cursor writer-sn)
  (write-fragment-number-set cursor base numbits bitmap)
  (dds.core.buffer:put-u32 cursor (logand count #xFFFFFFFF))
  (dds.core.buffer:cursor-position cursor))

(defun* parse-nack-frag-body (cursor flags)
    (function (dds.core.buffer:cursor (unsigned-byte 8)) t)
  "Parse a NACK_FRAG body. (values reader-id writer-id writer-sn base numbits bitmap
   count) or NIL. RTPS 2.5 NACK_FRAG."
  (declare (ignore flags))
  (when (< (%remaining cursor) 16) (return-from parse-nack-frag-body nil))
  (let ((reader-id (read-entity-id cursor))
        (writer-id (read-entity-id cursor))
        (writer-sn (read-sequence-number cursor)))
    (multiple-value-bind (base numbits bitmap) (read-fragment-number-set cursor)
      (when (null base) (return-from parse-nack-frag-body nil))
      (when (< (%remaining cursor) 4) (return-from parse-nack-frag-body nil))
      (values reader-id writer-id writer-sn base numbits bitmap
              (dds.core.buffer:get-u32 cursor)))))
```

- [ ] **Step 4: Export** `#:write-nack-frag #:parse-nack-frag-body`.
- [ ] **Step 5: Run SBCL + Clasp.**
- [ ] **Step 6: gate-types + commit** — `feat(rtps): NACK_FRAG codec`.

---

### Task 1.4: Fuzz the new frag parsers

**Files:** Modify `src/dds-tests/pbt-test.lisp` (the parser fuzz lives there — see `gen-fuzz-buffers` / the existing submessage fuzz).

- [ ] **Step 1:** Read how the existing RTPS submessage parsers are fuzzed in `pbt-test.lisp` (random/truncated buffers fed to the parsers, asserting no OOB / no crash, NIL or a value).
- [ ] **Step 2:** Add `parse-heartbeat-frag-body`, `parse-nack-frag-body`, and `read-fragment-number-set` to that fuzz loop with the same harness.
- [ ] **Step 3:** Run `make fuzz` (SBCL) — expected: no condition raised across the fuzz iterations.
- [ ] **Step 4:** gate + commit — `test(rtps): fuzz HEARTBEAT_FRAG/NACK_FRAG/FragmentNumberSet parsers`.

---

## STAGE 2 — Reliable engine: fragmentation + reassembly + frag reliability

> Before starting Stage 2, **read `src/dds-rtps/reliable.lisp` in full** — you will integrate with `rtps-writer`, `rtps-reader`, `writer-proxy`, `reader-proxy`, `get-writer-proxy`, `writer-write`, `writer-data-list`, `reader-on-data`, `reader-on-heartbeat`, `reader-acknack`, `reader-complete-p`, `writer-on-acknack`, `writer-heartbeat`. Match their style and the `(unsigned-byte 32)`/`integer` conventions exactly.

### Task 2.1: Special variables + reassembly-entry struct

**Files:** Modify `src/dds-rtps/reliable.lisp` (top), `src/dds-rtps/packages.lisp`.

- [ ] **Step 1: Add the special vars (documented, spec-cited)**

```lisp
(defparameter *fragment-size* 1024
  "Outbound RTPS fragmentSize in octets (a uint16, <= 65535; RTPS 2.5 DATA_FRAG). A
   sample whose serialized size exceeds this is sent as DATA_FRAG submessages.")
(defparameter *max-reassembly-bytes* (* 4 1024 1024)
  "Reject an inbound DATA_FRAG sampleSize larger than this BEFORE allocating the
   reassembly buffer (resource-exhaustion guard, NFR-SEC-POSTURE).")
(defparameter *max-reassembly-fragments* 8192
  "Cap on the fragment count per reassembled sample (NFR-SEC-POSTURE).")
```

- [ ] **Step 2: Add the reassembly-entry struct (`defstruct*`, every slot typed)**

```lisp
(defstruct* (frag-reassembly (:constructor %make-frag-reassembly))
  "Reader-side reassembly state for one in-progress fragmented sample (RTPS 2.5
   §8.3.7.x): the declared total SAMPLE-SIZE and FRAGMENT-SIZE, the accumulating
   BUFFER, a RECEIVED bitmap (one bit per 1-based fragment), and the count received."
  (sample-size 0 :type (integer 0))
  (fragment-size 0 :type (integer 0))
  (total-fragments 0 :type (integer 0))
  (buffer (make-array 0 :element-type '(unsigned-byte 8)) :type (simple-array (unsigned-byte 8) (*)))
  (received (make-array 0 :element-type 'bit) :type (simple-array bit (*)))
  (received-count 0 :type (integer 0)))
```

- [ ] **Step 3:** Add a `reassembly` slot to the `writer-proxy` defstruct (the reader's per-remote-writer state): `(reassembly (make-hash-table :test 'eql) :type hash-table)` — maps writer-SN → `frag-reassembly`. (Confirm the proxy struct name the reader uses for remote writers; in `reader-on-data` it is `writer-proxy` via `get-writer-proxy`.)
- [ ] **Step 4:** Export `*fragment-size*`, `*max-reassembly-bytes*`, `*max-reassembly-fragments*` from `dds.rtps.reliable`.
- [ ] **Step 5:** Load on SBCL (`ql:quickload :dds`); expected: clean compile. gate-types. Commit — `feat(rtps): fragment-size/reassembly limits + reassembly-entry struct`.

### Task 2.2: Reader-side reassembly (`reader-on-data-frag`)

**Files:** Modify `src/dds-rtps/reliable.lisp`; Test `src/dds-tests/rtps-test.lisp`.

- [ ] **Step 1: Write the failing test** — fragment a known octet vector into pieces and feed them out of order to `reader-on-data-frag`; assert it returns the assembled vector (equal to the original) only after the last fragment, and NIL before; assert a sampleSize over `*max-reassembly-bytes*` is rejected (NIL, no allocation). Provide the full test body with a 3-fragment example over a 2500-octet payload at `*fragment-size*` 1024.

- [ ] **Step 2: Run — expected FAIL** (`reader-on-data-frag` undefined).

- [ ] **Step 3: Implement.** Signature and contract:

```lisp
(defun* reader-on-data-frag (reader writer-id sn fragment-starting-num fragments-in-submsg
                                    fragment-size sample-size payload)
    (function (rtps-reader (unsigned-byte 32) integer (unsigned-byte 32) (unsigned-byte 32)
               (unsigned-byte 32) (unsigned-byte 32) (array (unsigned-byte 8) (*)))
              (or null (simple-array (unsigned-byte 8) (*))))
  "Accept one DATA_FRAG submessage's fragment range for (WRITER-ID, SN). Reassembles
   into the per-(writer,sn) frag-reassembly; returns the complete SAMPLE-SIZE octet
   vector once all fragments have arrived, else NIL. Guards: rejects (NIL) a SAMPLE-SIZE
   over *MAX-REASSEMBLY-BYTES*, a fragment count over *MAX-REASSEMBLY-FRAGMENTS*, or a
   fragment range exceeding SAMPLE-SIZE. Duplicate fragments are idempotent.")
```
Algorithm: look up / create the `frag-reassembly` (compute `total-fragments` = ⌈sample-size/fragment-size⌉; on create, guard sample-size and total-fragments, allocate `buffer` and `received`); validate fragment-starting-num/fragments-in-submsg against total-fragments; for each fragment in the submessage, copy its slice of `payload` to `buffer[(fragnum-1)*fragment-size ...]` (the last fragment may be short) and set its received bit (increment count only on a fresh bit); when `received-count = total-fragments`, remove the entry and return `buffer`. Bounds-check `payload` length covers `fragments-in-submsg * fragment-size` (last submessage may be short).

- [ ] **Step 4: Run SBCL + Clasp — expected PASS.**
- [ ] **Step 5:** Export `#:reader-on-data-frag`; register the test; gate-types; commit — `feat(rtps): DATA_FRAG reader reassembly with resource guards`.

### Task 2.3: Reader NACK_FRAG generation (`reader-frag-acknack`)

**Files:** Modify `src/dds-rtps/reliable.lisp`; Test `src/dds-tests/rtps-test.lisp`.

- [ ] **Step 1: Failing test** — after partially feeding fragments for an SN (e.g. 1 and 3 of 5), call `reader-frag-acknack reader writer-id sn` and assert it returns `(values base numbits bitmap)` whose set members are exactly the missing fragment numbers {2,4,5}; and that for a fully-received (or unknown) SN it returns NIL.
- [ ] **Step 2: Run — expected FAIL.**
- [ ] **Step 3: Implement** `reader-frag-acknack (reader writer-id sn)` → `(values base numbits bitmap)` of missing 1-based fragment numbers from the `frag-reassembly` (base = first missing fragnum, numbits spanning to the last missing or `total-fragments`), or NIL if no entry / complete. Reuse `fragnum-set-bit`.
- [ ] **Step 4: Run SBCL + Clasp.**
- [ ] **Step 5:** Export; register test; gate; commit — `feat(rtps): reader NACK_FRAG generation for missing fragments`.

### Task 2.4: Writer fragmentation send-list (`writer-frag-list`)

**Files:** Modify `src/dds-rtps/reliable.lisp`; Test `src/dds-tests/rtps-test.lisp`.

- [ ] **Step 1: Failing test** — write a sample > `*fragment-size*` via `writer-write`, then call `writer-frag-list writer reader-id sn budget` and assert it yields a list of DATA_FRAG descriptors `(fragment-starting-num fragments-in-submsg fragment-size sample-size payload-start payload-len)` that (a) cover all fragments exactly once, (b) use constant `fragment-size` except a short final fragment, (c) pack ⌊budget/fragment-size⌋ fragments per submessage. Provide the full assertion for a 2500-octet sample, `*fragment-size*` 1024, budget 2048 → submessages [frags 1–2 (2048 B)], [frag 3 (452 B)].
- [ ] **Step 2: Run — expected FAIL.**
- [ ] **Step 3: Implement** `writer-frag-list (writer reader-id sn budget)`: read the CacheChange payload + size from the writer's HistoryCache for `sn`; compute total fragments; emit descriptors packing `max(1, floor(budget/fragment-size))` fragments per submessage, last submessage short. (This is a pure planner; the actual `write-data-frag` calls happen in Stage 3's `%push-data`.) Also implement `writer-frag-list-for (writer reader-id sn fragnum-set)` returning the same descriptors but only for the fragments named in a NACK_FRAG set (coalescing contiguous runs into submessages within budget) — used by the NACK_FRAG resend path.
- [ ] **Step 4: Run SBCL + Clasp.**
- [ ] **Step 5:** Export `#:writer-frag-list #:writer-frag-list-for`; register test; gate; commit — `feat(rtps): writer DATA_FRAG send-list + fragmentsInSubmessage packing`.

### Task 2.5: Writer HEARTBEAT_FRAG + NACK_FRAG response glue

**Files:** Modify `src/dds-rtps/reliable.lisp`; Test `src/dds-tests/rtps-test.lisp`.

- [ ] **Step 1: Failing test** — assert `writer-frag-heartbeat writer sn` returns `(values last-fragment-num count)` with `last-fragment-num` = total fragments for `sn` and a monotonically increasing count; assert `writer-on-nack-frag writer reader-id sn base numbits bitmap budget` returns the resend descriptor list for exactly the NACKed fragments (delegating to `writer-frag-list-for`).
- [ ] **Step 2: Run — expected FAIL.**
- [ ] **Step 3: Implement** `writer-frag-heartbeat` (count from a per-writer frag-HB counter) and `writer-on-nack-frag` (decode the set → `writer-frag-list-for`).
- [ ] **Step 4: Run SBCL + Clasp.**
- [ ] **Step 5:** Export; register test; gate; commit — `feat(rtps): writer HEARTBEAT_FRAG + NACK_FRAG resend planning`.

### Task 2.6: Offline our↔our large-sample round-trip

**Files:** Test `src/dds-tests/rtps-test.lisp`.

- [ ] **Step 1: Write the test** `run-frag-roundtrip-test`: a writer with a 2500-octet sample; drive `writer-frag-list` → for each descriptor call `write-data-frag` into a buffer, `dispatch-message` → `parse-data-frag-body` → `reader-on-data-frag`; assert the reader returns the original 2500 octets after the last fragment, byte-for-byte. Provide the full body wiring `write-data-frag`/`parse-data-frag-body` (already in `message.lisp`) to the Task 2.2/2.4 functions.
- [ ] **Step 2: Run — expected FAIL then implement nothing new** (this is integration of existing pieces; if it fails it reveals a wiring bug to fix in 2.2/2.4).
- [ ] **Step 3: Run SBCL + Clasp — expected PASS.**
- [ ] **Step 4:** Register `("rtps-frag-roundtrip" . run-frag-roundtrip-test)`; gate; commit — `test(rtps): offline DATA_FRAG large-sample round-trip`.

### Task 2.7: Lossy delivery + NACK_FRAG recovery test

**Files:** Test `src/dds-tests/rtps-test.lisp`.

- [ ] **Step 1: Write the test** `run-frag-lossy-test`: as 2.6 but **drop** fragments 2 and 4 on the first pass; deliver `writer-frag-heartbeat` → `reader-frag-acknack` (assert it names exactly {2,4}) → `writer-on-nack-frag` → deliver only those fragments → assert the sample completes and equals the original; assert no fragment outside {2,4} was resent.
- [ ] **Step 2: Run — expected FAIL until 2.3/2.5 are correct; fix as needed.**
- [ ] **Step 3: Run SBCL + Clasp — expected PASS.**
- [ ] **Step 4:** Register; gate; update `docs/verification.csv` FR-RTPS row (DATA_FRAG fragment reliability landed, offline); commit — `test(rtps): DATA_FRAG lossy delivery recovers via NACK_FRAG`.

---

## STAGE 3 — Data-plane wiring + DCPS type + offline e2e

> Before starting, **read `src/dds-disc/dataplane.lisp` in full** (esp. `%push-data`, `%on-user-acknack`, `publish-sample`, `%handle-datagram`/the dispatch callback, `%send-msg-buf`) and `disc.lisp`'s dispatch. Match the existing send/scratch-buffer discipline (`tx-msg`, `rx-tx-msg`, the node lock).

### Task 3.1: Dispatch routing for the three frag submessages

**Files:** Modify `src/dds-disc/dataplane.lisp` (the receive dispatch).

- [ ] **Step 1:** Read the existing dispatch that handles `+submsg-data+`/`+submsg-heartbeat+`/`+submsg-acknack+`/`+submsg-gap+` and the hooks (`on-data`, `on-heartbeat`, `on-acknack`).
- [ ] **Step 2:** Add branches: `+submsg-data-frag+` → `parse-data-frag-body` → `reader-on-data-frag` on the node's user reader; if it returns a complete payload, feed it to the existing `reader-on-data` + the `on-sample` hook exactly as the DATA branch does. `+submsg-heartbeat-frag+` → `parse-heartbeat-frag-body` → `reader-frag-acknack`; if it returns a set, send a NACK_FRAG (via a new `%send-nack-frag`). `+submsg-nack-frag+` → `parse-nack-frag-body` → `writer-on-nack-frag` → resend the descriptors as DATA_FRAGs.
- [ ] **Step 3:** Add `on-nack-frag` to the `disc-node` struct (`(or null function)`, mirror `on-acknack`) and install it in `enable-publisher`.
- [ ] **Step 4:** Load SBCL clean; gate-types; commit — `feat(disc): route DATA_FRAG/HEARTBEAT_FRAG/NACK_FRAG in the receiver`.

### Task 3.2: `%push-data` fragmentation path

**Files:** Modify `src/dds-disc/dataplane.lisp`.

- [ ] **Step 1:** In `publish-sample`/`%push-data`, after `writer-write`, branch on serialized size > `*fragment-size*`: instead of one DATA + HEARTBEAT, iterate `writer-frag-list` descriptors and emit each as a DATA_FRAG via `write-data-frag` into `tx-msg` (one datagram per submessage, respecting the 2048 budget = the packing budget), then a HEARTBEAT_FRAG (`write-heartbeat-frag` with `writer-frag-heartbeat`) to each peer. Keep the small-sample path unchanged.
- [ ] **Step 2:** Add `%send-nack-frag` (reader→writer) mirroring the ACKNACK send (compute under the node lock, send outside it, use `rx-tx-msg` on the receiver thread).
- [ ] **Step 3:** Load SBCL clean; gate-types; commit — `feat(disc): fragment large samples on send (DATA_FRAG + HEARTBEAT_FRAG)`.

### Task 3.3: `LargeData` type + harness

**Files:** Modify `src/dds-shapes/shapes.lisp`, `src/dds-shapes/packages.lisp`, `Makefile`.

- [ ] **Step 1:** Add `(dds.gen:define-dds-type large-data (:extensibility :final) (id :i32 :key t) (payload (:sequence :u8)))`. Export `large-data`, `make-large-data`, accessors.
- [ ] **Step 2:** Add `run-large-publisher`/`run-large-subscriber` mirroring `run-publisher`/`run-subscriber` but on topic `"LargeData"` type `"LargeData"`, with a `:size` arg controlling payload length (default e.g. 8000 octets).
- [ ] **Step 3:** Add `large-pub`/`large-sub` Makefile targets mirroring `square-pub`/`square-sub`.
- [ ] **Step 4:** Load `:dds-shapes` on SBCL clean; gate-types; commit — `feat(shapes): LargeData type + large-pub/large-sub harness`.

### Task 3.4: Offline e2e LargeData over UDP

**Files:** Test `src/dds-tests/integration-test.lisp`.

- [ ] **Step 1: Write `run-large-dataplane-test`** mirroring `run-typed-dataplane-test`: two participants (or the two-node loopback the e2e test uses), publish a `large-data` with an 8000-octet payload, spin, take, assert the received sample's `id` and `payload` equal the sent ones byte-for-byte (so fragmentation + reassembly + reliability worked over real UDP).
- [ ] **Step 2: Run — fix any data-plane wiring bugs surfaced.**
- [ ] **Step 3: Run SBCL + Clasp — expected PASS.**
- [ ] **Step 4:** Register `("large-dataplane-over-udp" . run-large-dataplane-test)`; `make wire` to tshark-validate the fragmented output; update `docs/wiki/rtps-engine.md` + `README.md` (DATA_FRAG data-plane landed); gate; commit — `test(disc): LargeData fragmented round-trip over UDP`.

---

## STAGE 4 — Live Connext interop

> This stage mirrors the M2 interop method. Build on the dev box: `NDDSHOME=/Applications/rti_connext_dds-7.3.1`, `CONNEXTDDS_ARCH=arm64Darwin20clang12.0`, `export DYLD_LIBRARY_PATH=$NDDSHOME/lib/$CONNEXTDDS_ARCH`. Capture with `tshark -r f.pcap --enable-protocol null --enable-protocol ip --enable-protocol udp -V` (lo0 = null). Same-host unicast routes over lo0.

### Task 4.1: Connext LargeData oracle

**Files:** Create `interop/connext/large-data/LargeData.idl`, pub/sub apps, `USER_QOS_PROFILES.xml`, `Makefile` (mirror `interop/connext/shapes-*`).

- [ ] **Step 1:** Write `LargeData.idl`: `struct LargeData { @key long id; sequence<octet> payload; };` (match our generated type — confirm the unbounded vs bounded sequence and the key against `rtiddsgen` output, recording it; recall ADR 0009's lesson that rtiddsgen may bound types).
- [ ] **Step 2:** Generate + build the Connext `large_pub`/`large_sub` apps (rtiddsgen, mirror the shapes apps).
- [ ] **Step 3:** In `USER_QOS_PROFILES.xml`, set the builtin UDPv4 transport `message_size_max` small (e.g. 1400) and `dds.transport.UDPv4.builtin` consistently so a multi-KB sample is fragmented by Connext on loopback. Pin our `*fragment-size*` to match.
- [ ] **Step 4:** Run `large_pub` and capture lo0; confirm via tshark that Connext emits DATA_FRAG (+ HEARTBEAT_FRAG). Commit — `test(interop): Connext LargeData oracle + fragmentation QoS`.

### Task 4.2: Lock Connext frag bytes as regression vectors

**Files:** Test `src/dds-tests/rtps-test.lisp`.

- [ ] **Step 1:** From the capture, extract one real DATA_FRAG, one HEARTBEAT_FRAG, and one NACK_FRAG submessage's octets.
- [ ] **Step 2:** Add byte-exact tests asserting our `parse-*-frag-body` decode the captured bytes to the expected fields, and that our `write-*` reproduce the captured bytes for the same inputs (the wire-exact gate the spec's DoD requires). Fix any field-order/size discrepancy in the Stage 1 codecs revealed here (this is why codecs were marked "pin from spec, confirm against capture").
- [ ] **Step 3:** Run SBCL + Clasp; commit — `test(rtps): lock Connext DATA_FRAG/HEARTBEAT_FRAG/NACK_FRAG byte vectors`.

### Task 4.3: Bidirectional live interop

- [ ] **Step 1: Connext→us:** `make large-sub` (ours) ↔ Connext `large_pub`; capture lo0; confirm our subscriber reassembles and delivers the full LargeData sample. Debug with `CONNEXT_VERBOSE=1` + STATUS_ALL as in M2. Suspect RTPS plumbing (frag numbering, EntityIds, NACK_FRAG routing) before type semantics.
- [ ] **Step 2: us→Connext:** `make large-pub` (ours) ↔ Connext `large_sub`; confirm Connext reassembles; force loss / confirm Connext's NACK_FRAG is answered by our writer (the `on-nack-frag` path).
- [ ] **Step 3:** Record results + any fix chain in `docs/verification.csv` (FR-IO / FR-RTPS) and `docs/MILESTONES.md`; update `README.md`/`docs/wiki/rtps-engine.md`. Commit each fix referencing the requirement id; final doc commit — `docs: DATA_FRAG bidirectional Connext interop achieved`.

---

## Self-review notes

- **Spec coverage:** §2 decisions → Stages all reflect fragment-level + Connext interop + LargeData + approach A + fragmentsInSubmessage>1 (Task 2.4 packing, Task 1.x codecs, Stage 4 interop). §6 special vars → Task 2.1. §7 guards → Task 2.2 (sample-size/fragment-count rejection, idempotent dup) + Stage-1 parser bounds + Task 1.4 fuzz. §8 DoD → Tasks 1.1–1.3 round-trip, 1.4 fuzz, 2.6 offline, 2.7 lossy, 3.4 `make wire`, 4.2 byte-exact vectors, 4.3 live interop.
- **Wire-exactness:** intentionally pinned from `docs/specs/` + a Connext capture (Stage 4 Task 4.2), not from memory — consistent with the operating contract. Stage-1 tests are write/parse round-trips; Task 4.2 is the byte-exact gate.
- **Type consistency:** codec names (`write/read-fragment-number-set`, `write/parse-heartbeat-frag`, `write/parse-nack-frag`, `fragnum-set-bit/-member-p`), engine names (`reader-on-data-frag`, `reader-frag-acknack`, `writer-frag-list`, `writer-frag-list-for`, `writer-frag-heartbeat`, `writer-on-nack-frag`), and the `frag-reassembly` struct are used consistently across tasks.
- **Open dependency to verify at execution:** the exact `writer-proxy`/HistoryCache accessors for reading a stored sample's payload+size in Task 2.4 — read `reliable.lisp`/`history.lisp` and use the real accessors.
