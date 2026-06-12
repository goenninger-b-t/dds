# Liveliness + Lease Expiry Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Prune a vanished participant within its SPDP `leaseDuration` (decrementing PUBLICATION/SUBSCRIPTION_MATCHED), and implement the mandatory RTPS §8.4.13 Writer Liveliness Protocol (BuiltinParticipantMessage endpoints + ParticipantMessageData) so matched DataWriters' liveliness is asserted + timed — firing LIVELINESS_CHANGED (reader) and LIVELINESS_LOST (writer) — verified live against Connext.

**Architecture:** Two halves on the existing caller-driven announce cadence (no new thread). S0: a per-participant last-seen stamp + `%lease-sweep` (in `announce-endpoints`) + a new `on-unmatch` disc-hook → DCPS decrements MATCHED. S1: a new `participant-message.lisp` builtin module (mirroring `typelookup-endpoints.lisp`) carrying ParticipantMessageData on the BuiltinParticipantMessage endpoints, with reader-side per-writer liveliness timing + writer-side assertion/LIVELINESS_LOST in DCPS.

**Tech Stack:** Common Lisp (`defun*`/`defstruct*`, full ftype declarations), `dds.disc` (discovery + builtin endpoints), `dds.rtps` (codec + entity ids), `dds.dcps` (statuses + listeners + API), `dds.qos` (LIVELINESS, exists); `interop/connext/` + tshark for the live leg. Spec: `docs/superpowers/specs/2026-06-12-liveliness-lease-expiry-design.md`.

---

## Standing rules (restate to every subagent)

1. **Never hardcode a wire constant from memory.** The BuiltinParticipantMessage EntityIds, the ParticipantMessageData layout + kind octets, and the builtin-endpoint-set bits are pinned from `docs/specs/rtps-2_5.pdf` (pdftotext) §8.4.13 + §9.3.2 (Table 9.4) + §9.6.x and **byte-verified against a live Connext 7.3.1 capture** before locking (the operating contract §4). Cite the clause in a comment. Conventional values below are a guide — confirm each.
2. **Bounds-check every ParticipantMessageData wire read FIRST** (NFR-SEC-POSTURE); a malformed message is dropped (NIL), never an error escape.
3. **No new thread.** The sweeps run from the existing announce cadence (`announce-endpoints`/`announce-participant`), beside `tl-sweep`. Table mutation under the node lock; hooks/listeners fired OUTSIDE the lock (the established discipline — see `%fire-match` / `tl-sweep`).
4. Lisp: `defun*`/`defstruct*` with full ftype declarations; docstrings on added/changed exported symbols; one-line comments; no reader conditionals outside `dds-pal/`.
5. Suite green per task on SBCL (`make test-sbcl`, currently **106**); Clasp at each stage boundary (`GC_DONT_GC=1 make test-clasp`, one retry on the known flake clasp#1793). `make gate-types` + `make gate-hotpath` green.
6. **Every commit message is PRESENTED TO THE OWNER FOR APPROVAL before `git commit`.** No AI attribution; no "Claude" in any repo file; cite "the operating contract".
7. Docs in lockstep (operating contract §5.1): changed exported symbols → docstrings + `docs/wiki/` + `README.md` if status shifts; `docs/verification.csv` FR-RTPS/FR-DCPS per stage; `docs/provenance.md` for the live capture.

## Reference: the code you are extending

- **`src/dds-disc/disc.lisp`**: `disc-node` defstruct (line 15; slots `discovered` (prefix→spdp-data), `discovered-writers`/`discovered-readers`, `matches`, `builtin-readers`, hook slots incl. `on-match` at line 79); `%record-participant` (line 407, stamps `discovered`); `%fire-match` (line 452, `(funcall (disc-node-on-match node) kind remote)`); `announce-endpoints` (line 366, calls `(tl-sweep node)` at the end); `announce-participant` (line 186); `%handle-datagram` (line 588, dispatches by writerId); `make-disc-node`/`start-node` (line ~665).
- **`src/dds-dcps/entities.lisp`**: DataReader/DataWriter CLOS classes (slots `pub-matched`/`sub-matched` at 59/73); `(setf (dds.disc:disc-node-on-match node) (lambda (kind remote) (%on-disc-match p kind remote)))` at line 192 — mirror for `on-unmatch`; `%bump-subscription-matched` at line 546 (the incf path — mirror for a decrement).
- **`src/dds-dcps/statuses.lisp`**: `subscription-matched-status` (line 71) / `publication-matched-status` (line 80) structs — the pattern for the liveliness statuses.
- **`src/dds-dcps/listeners.lisp`**: `on-liveliness-changed` (line 56) / `on-liveliness-lost` (line 74) generics already exist (no status structs yet).
- **`src/dds-qos/qos.lisp`**: `qos-liveliness` (kind `:automatic`/`:manual-by-participant`/`:manual-by-topic`, line 87) + `qos-liveliness-lease` (a `qos-duration`).
- **`src/dds-rtps/discovery.lisp`**: SPDP/SEDP EntityIds (lines 12–22); the builtin-endpoint-set bits `+be-tl-*+` (lines 26–32) + `+builtin-endpoint-set-default+` (line 34); the `spdp-data` struct (`leaseDuration` field, `builtin-endpoint-set`).
- **`src/dds-disc/typelookup-endpoints.lisp`**: the TEMPLATE for a new builtin endpoint pair — EntityId constants, a module file in `dds.disc`, per-remote reliable bookkeeping, a sweep on the announce cadence, hooked into `%handle-datagram` by writerId.
- **`src/dds-rtps/message.lisp`**: `write-heartbeat` `:liveliness` flag (line 297) — the MANUAL_BY_TOPIC substrate (out of scope; do not use here).
- **Tests**: `src/dds-tests/` — the two-node UDP-loopback discovery tests (grep `run-sedp-test`/`run-type-gate-test`/`typed-shape-over-udp` for the harness); register in `src/dds-tests/echo-test.lisp`.

---

## Stage S0 — participant lease expiry

### Task 0.1: last-seen stamp + `%lease-sweep` + `on-unmatch` hook (disc)

**Files:**
- Modify: `src/dds-disc/disc.lisp`, `src/dds-disc/packages.lisp` (export `disc-node-on-unmatch`)
- Test: `src/dds-tests/` (a new disc test)

- [ ] **Step 1: Write the failing test.** A discovered participant with a stale last-seen, holding a matched remote writer + reader, is pruned by `%lease-sweep`, and the `on-unmatch` hook fires once per removed match:

```lisp
(defun* run-lease-sweep-test ()
    (function () t)
  "%lease-sweep prunes a participant whose last-seen + leaseDuration < now: removes its
   discovered entry + its endpoints + matches + builtin-reader, and fires on-unmatch once
   per removed matched endpoint (direction . remote)."
  (let ((node (dds.disc:make-disc-node :guid-prefix (%kn-prefix) :domain 0))
        (unmatched '()))
    (unwind-protect
        (progn
          (setf (dds.disc:disc-node-on-unmatch node)
                (lambda (direction remote) (push (cons direction remote) unmatched)))
          ;; fabricate a discovered participant (prefix P2) with a stale last-seen + a matched remote writer
          (let* ((p2 (%kn-prefix2))
                 (spdp (%fake-spdp p2 :lease 1))                 ; 1-second lease
                 (rw (%remote-writer-ep p2 "T" "X" #x02)))       ; a matched remote writer under P2
            (dds.disc::%record-participant-at node spdp (- (dds.disc::%lease-now) 5))  ; last-seen 5s ago
            (dds.disc::%record-match node rw)
            (setf (gethash (copy-seq p2) (dds.disc:disc-node-discovered-writers node)) rw)
            (dds.disc::%lease-sweep node)
            (assert (zerop (hash-table-count (dds.disc:disc-node-discovered node))))   ; pruned
            (assert (zerop (hash-table-count (dds.disc::disc-node-matches node))))      ; match removed
            (assert (= 1 (length unmatched)))                                          ; hook fired once
            (assert (eq :remote-writer (car (first unmatched))))))
      (dds.disc:stop-node node))
    t))
```

Reuse the existing test helpers (`%kn-prefix`/`%kn-prefix2`/`%remote-writer-ep` from the keyed-match test; `%fake-spdp` — grep for an existing spdp-data fabricator, else write one). Register `("lease-sweep" . run-lease-sweep-test)`. The helpers `%record-participant-at` (a test-seam variant of `%record-participant` taking an explicit timestamp) and `%lease-now` are introduced in Step 3.

- [ ] **Step 2: Run it, expect failure** (no `disc-node-on-unmatch`, `%lease-sweep`, `%lease-now`).

- [ ] **Step 3: Implement.** Add to the `disc-node` defstruct: a last-seen hash and the unmatch hook:

```lisp
  (participant-last-seen (make-hash-table :test 'equalp) :type hash-table) ; remote GUID prefix -> internal-real-time
  (on-unmatch nil :type (or null function))
```

Add a clock helper + a stamping wrapper + the sweep:

```lisp
(defun* %lease-now ()
    (function () (integer 0))
  "Monotonic internal-real-time stamp for lease/liveliness bookkeeping."
  (get-internal-real-time))

(defun* %lease-stale-p (last-seen lease-seconds now)
    (function ((integer 0) (integer 0) (integer 0)) t)
  "T iff LAST-SEEN is older than LEASE-SECONDS before NOW (RTPS 2.5 §8.5.3.3.2 stale entry)."
  (> (- now last-seen) (* lease-seconds internal-time-units-per-second)))
```

Modify `%record-participant` (line 407) to also stamp `(setf (gethash (copy-seq prefix) (disc-node-participant-last-seen node)) (%lease-now))` under the node lock (and add the `%record-participant-at node spdp time` test seam that records with an explicit time). Add `%fire-unmatch`:

```lisp
(defun* %fire-unmatch (node direction remote)
    (function (disc-node keyword dds.rtps.discovery:endpoint-data) t)
  "Invoke the ON-UNMATCH hook (if installed) OUTSIDE the node lock for a REMOTE endpoint
   that was unmatched by participant-lease expiry (DIRECTION :remote-writer / :remote-reader)."
  (when (disc-node-on-unmatch node)
    (funcall (disc-node-on-unmatch node) direction remote)))
```

Add `%lease-sweep`:

```lisp
(defun* %lease-sweep (node)
    (function (disc-node) (eql t))
  "Prune every discovered participant whose SPDP last-seen is older than its announced
   leaseDuration (RTPS 2.5 §8.5.3.3.2): under the node lock remove its discovered entry,
   last-seen, every discovered-writers/readers endpoint + match + builtin-reader keyed by
   that 12-octet prefix, collecting the removed MATCHED endpoints; then fire on-unmatch per
   removed match OUTSIDE the lock. Idempotent (a re-announced participant re-adds)."
  (let ((removed '()))
    (dds.pal:with-lock ((disc-node-lock node))
      (let ((now (%lease-now)) (dead '()))
        (maphash (lambda (prefix spdp)
                   (let ((ls (gethash prefix (disc-node-participant-last-seen node))))
                     (when (and ls (%lease-stale-p ls (dds.rtps.discovery:spdp-data-lease-duration-seconds spdp) now))
                       (push prefix dead))))
                 (disc-node-discovered node))
        (dolist (prefix dead)
          (remhash prefix (disc-node-discovered node))
          (remhash prefix (disc-node-participant-last-seen node))
          (remhash prefix (disc-node-builtin-readers node))
          (%purge-prefix node prefix #'disc-node-discovered-writers)
          (%purge-prefix node prefix #'disc-node-discovered-readers)
          (%collect-and-remove-matches node prefix removed))))   ; pushes (direction . remote) onto REMOVED
    (dolist (dm removed) (%fire-unmatch node (car dm) (cdr dm)))
    t))
```

Write the two helpers `%purge-prefix node prefix accessor` (remhash every entry in the accessor's table whose GUID's first 12 octets = prefix) and `%collect-and-remove-matches node prefix removed-place` (for each match whose remote GUID prefix = prefix, classify direction via `%writer-guid-p`/`%reader-guid-p` from dataplane.lisp — a remote WRITER unmatched ⇒ `:remote-writer`, remote READER ⇒ `:remote-reader` — remhash it and push `(direction . remote)`). All under the already-held lock (factor so the lock is held once). Wire `(%lease-sweep node)` into `announce-endpoints` (line 366) right before/after `(tl-sweep node)`. Export `disc-node-on-unmatch` from packages.lisp.

- [ ] **Step 4: Run it, expect pass.** Full suite — existing discovery/match tests unaffected (no participant is stale in them; the sweep is a no-op without a stale entry). `make test-sbcl`.

- [ ] **Step 5: Commit** (present message):
```
feat(disc): participant-lease expiry sweep + on-unmatch hook (FR-RTPS S0)

%record-participant stamps a per-prefix last-seen; %lease-sweep (run from
announce-endpoints beside tl-sweep) prunes a participant whose SPDP last-seen
is older than its announced leaseDuration (RTPS 2.5 §8.5.3.3.2), removing its
discovered entry + endpoints + matches + builtin-reader under the node lock and
firing a new on-unmatch hook (direction . remote) per removed match outside the
lock. Idempotent. Test lease-sweep.
```

### Task 0.2: DCPS unmatch path — decrement MATCHED

**Files:** Modify `src/dds-dcps/entities.lisp`; Test: `src/dds-tests/`.

- [ ] **Step 1: Write the failing test** — a DCPS participant whose matched remote endpoint's participant leases out sees PUBLICATION/SUBSCRIPTION_MATCHED decrement + the listener fire. Build from the existing DCPS match test (grep `dcps-entity` / `%on-disc-match` test). Sketch:

```lisp
(defun* run-lease-unmatch-test ()
    (function () t)
  "When a matched remote participant leases out, the local DataReader's SUBSCRIPTION_MATCHED
   current_count decrements and on-subscription-matched fires with current_count_change -1."
  ;; create a participant + DataReader; simulate a match (drive %on-disc-match with a remote
  ;; writer) so current_count=1; then drive %on-disc-unmatch (:remote-writer remote) and assert
  ;; the reader's sub-matched current_count=0, current_count_change=-1, and the listener fired.
  ...)
```

(Clone the closest existing DCPS match test; install a counting listener.) Register `("lease-unmatch" . run-lease-unmatch-test)`.

- [ ] **Step 2: Run it, expect failure** (no `%on-disc-unmatch`).

- [ ] **Step 3: Implement.** Install the hook next to `on-match` (entities.lisp ~192):

```lisp
    (setf (dds.disc:disc-node-on-unmatch node)
          (lambda (direction remote) (%on-disc-unmatch p direction remote)))
```

Add `%on-disc-unmatch p direction remote`: find the local DataReader/DataWriter matched to `remote` (by topic/type, mirroring how `%on-disc-match` locates the local entity), and decrement its status:
- `:remote-writer` → the local DataReader's `sub-matched`: `(decf current-count)`, `current-count-change := -1` (and `total-count` unchanged — total is cumulative matches), fire `on-subscription-matched`. Add a `%unbump-subscription-matched` mirroring `%bump-subscription-matched` (line 546) but decrementing current-count + setting current-count-change -1.
- `:remote-reader` → the local DataWriter's `pub-matched`: the publication-matched mirror.

Fire the listener the same way `%bump-*` does (check for an installed listener; fire `on-subscription-matched`/`on-publication-matched`). Reset `current-count-change` on `get_*_status` read (the existing change-reset discipline — mirror it).

- [ ] **Step 4: Run it, expect pass.** Full suite green. `make test-sbcl`.

- [ ] **Step 5: Clasp at the S0 boundary** (`GC_DONT_GC=1 make test-clasp`). `make gate-types gate-hotpath`.

- [ ] **Step 6: Commit** (present message):
```
feat(dcps): decrement PUBLICATION/SUBSCRIPTION_MATCHED on participant lease expiry (FR-RTPS/FR-DCPS S0)

DCPS installs the disc on-unmatch hook: a matched remote endpoint removed by
participant-lease expiry decrements the local DataReader's SUBSCRIPTION_MATCHED
(remote writer) or DataWriter's PUBLICATION_MATCHED (remote reader) current_count
(change -1) and fires on-subscription-matched / on-publication-matched. Test
lease-unmatch. Closes the offline lease-expiry stage (S0).
```

---

## Stage S1 — Writer Liveliness Protocol (RTPS §8.4.13)

### Task 1.1: ParticipantMessageData codec + EntityIds + endpoint-set bits (rtps)

**Files:**
- Modify: `src/dds-rtps/discovery.lisp` (EntityIds + endpoint-set bits + the codec, or a new `src/dds-rtps/participant-message.lisp` if cleaner — match the file's existing organization), `src/dds-rtps/packages.lisp` (exports)
- Test: `src/dds-tests/`

- [ ] **Step 1: Pin the constants** from `docs/specs/rtps-2_5.pdf` (pdftotext) — §8.4.13.2 / §9.3.2 Table 9.4 for `ENTITYID_P2P_BUILTIN_PARTICIPANT_MESSAGE_WRITER`/`READER` (conventional `0x000200c2` / `0x000200c7` — confirm), §9.6.x for the kind octets (conventional `PARTICIPANT_MESSAGE_DATA_KIND_AUTOMATIC` = `{00 00 00 01}`, `_MANUAL_BY_PARTICIPANT` = `{00 00 00 02}` — confirm), and the `BUILTIN_PARTICIPANT_MESSAGE_DATA_WRITER`/`READER` bits in `PID_BUILTIN_ENDPOINT_SET` (Table 9.4, conventional `1<<10` / `1<<11` — confirm). Cite the clauses.

- [ ] **Step 2: Write the failing codec test** — round-trip + a locked byte vector (the `data` is the encapsulation + payload; for liveliness the spec writes the participant prefix + kind, `data` typically empty or impl-defined — pin the minimal conforming form):

```lisp
(defun* run-participant-message-codec-test ()
    (function () t)
  "ParticipantMessageData (RTPS 2.5 §8.4.13.4) round-trips: participantGuidPrefix(12) +
   kind(octet[4]) + data(sequence<octet>). The serialized bytes match a locked vector."
  (let* ((prefix (%kn-prefix))
         (pm (dds.rtps.discovery:make-participant-message
              :guid-prefix prefix
              :kind dds.rtps.discovery:+pmd-kind-automatic+
              :data (make-array 0 :element-type '(unsigned-byte 8))))
         (bytes (dds.rtps.discovery:serialize-participant-message pm))
         (back (dds.rtps.discovery:parse-participant-message bytes)))
    (assert (equalp prefix (dds.rtps.discovery:participant-message-guid-prefix back)))
    (assert (= dds.rtps.discovery:+pmd-kind-automatic+ (dds.rtps.discovery:participant-message-kind back)))
    t))
```

Register `("participant-message-codec" . run-participant-message-codec-test)`.

- [ ] **Step 3: Implement** the EntityId + kind + endpoint-set-bit constants, a `participant-message` struct (`guid-prefix`, `kind`, `data`), `serialize-participant-message` (CDR-encapsulated: the prefix octets + kind octets + the `data` sequence, length-prefixed; 4-aligned per CDR), and `parse-participant-message` (every read bounds-checked FIRST — NFR-SEC-POSTURE; NIL on truncation). Add the participant-message writer/reader bits to `+builtin-endpoint-set-default+` so our SPDP advertises the WLP. Export all from `dds.rtps.discovery`.

- [ ] **Step 4: Run it, expect pass.** `make test-sbcl`. **Step 5: Commit** (present message: "feat(rtps): ParticipantMessageData codec + BuiltinParticipantMessage EntityIds + endpoint-set bits (RTPS §8.4.13, FR-RTPS S1)").

### Task 1.2: the participant-message builtin endpoints + periodic assertion (disc)

**Files:**
- Create: `src/dds-disc/participant-message.lisp` (mirroring `typelookup-endpoints.lisp`), register it in the `dds-disc` ASDF system + package
- Modify: `src/dds-disc/disc.lisp` (dispatch hook + the assertion call in `announce-participant`/the cadence), `src/dds-disc/packages.lisp`
- Test: `src/dds-tests/`

- [ ] **Step 1: Write the failing two-node test** — node A with a local AUTOMATIC writer asserts liveliness via the WLP; node B receives the ParticipantMessageData and records A's liveliness:

```lisp
(defun* run-wlp-assert-test ()
    (function () t)
  "Node A with a local AUTOMATIC DataWriter asserts liveliness on the announce cadence via the
   BuiltinParticipantMessage endpoints; node B receives the ParticipantMessageData and records a
   liveliness stamp for A's prefix (AUTOMATIC kind)."
  ;; two nodes over UDP loopback (clone the run-sedp-test harness); A adds a local writer with an
  ;; AUTOMATIC liveliness QoS; spin; assert B's per-remote liveliness table has an AUTOMATIC stamp
  ;; for A's prefix newer than the run start.
  ...)
```

Register `("wlp-assert" . run-wlp-assert-test)`.

- [ ] **Step 2: Run it, expect failure.**

- [ ] **Step 3: Implement** `participant-message.lisp` mirroring the TypeLookup module: the writer/reader builtin endpoints (`+entityid-p2p-participant-message-writer/reader+`), per-remote reliable bookkeeping (same SEDP machinery — a HEARTBEAT answered by a final ACKNACK), an `assert-participant-liveliness node` that (if the node has ≥1 local AUTOMATIC writer) writes the AUTOMATIC ParticipantMessageData instance to discovered peers' metatraffic locators, and likewise a MANUAL_BY_PARTICIPANT instance when ≥1 such writer exists; and an inbound handler that records `(remote-prefix kind) -> %lease-now` in a new `disc-node-remote-liveliness` table. The disc-node gains: the participant-message writer/reader SN counters + the `remote-liveliness` table. Hook the inbound endpoint into `%handle-datagram` dispatch by writerId (mirror the TL dispatch). Call `assert-participant-liveliness` from `announce-participant` (the assertion rides the announce cadence; §8.4.13.5 requires faster-than-smallest-lease — for v1 the announce cadence is the rate, documented; a finer per-lease timer is a noted refinement). Export what the tests need.

- [ ] **Step 4: Run it, expect pass.** `make test-sbcl`. **Step 5: Commit** (present message: "feat(disc): BuiltinParticipantMessage endpoints + periodic liveliness assertion (RTPS §8.4.13.5, FR-RTPS S1)").

### Task 1.3: reader-side liveliness timing → LIVELINESS_CHANGED (disc + DCPS)

**Files:** Modify `src/dds-disc/disc.lisp` (the reader-side sweep + an `on-liveliness-changed` disc hook), `src/dds-dcps/{statuses,entities}.lisp`; Test: `src/dds-tests/`.

- [ ] **Step 1: Add the status struct** to `statuses.lisp` (mirroring subscription-matched-status):

```lisp
(defstruct* (liveliness-changed-status (:constructor make-liveliness-changed-status)
                                       (:copier copy-liveliness-changed-status))
  "DataReader LIVELINESS_CHANGED status (dds_rtf2_dcps.idl §..)."
  (alive-count 0 :type integer)
  (not-alive-count 0 :type integer)
  (alive-count-change 0 :type integer)
  (not-alive-count-change 0 :type integer)
  (last-publication-handle nil :type (or null (array (unsigned-byte 8) (*)))))
```

(Pin the IDL clause number.) Add a `liv-changed` slot to the DataReader class (entities.lisp, like `sub-matched`). Export the status accessors.

- [ ] **Step 2: Write the failing test** — node A asserts then STOPS; node B's `%liveliness-sweep` fires `on-liveliness-changed` (alive→not-alive) after A's writer lease:

```lisp
(defun* run-liveliness-changed-test ()
    (function () t)
  "After a matched remote AUTOMATIC writer stops asserting for longer than its LIVELINESS
   lease, the reader-side %liveliness-sweep fires on-liveliness-changed (alive_count_change -1,
   not_alive_count_change +1)."
  ...)
```

(Use a short LIVELINESS lease; drive the sweep directly after backdating the remote-liveliness stamp, like the lease-sweep test, to avoid a real wait.) Register `("liveliness-changed" . run-liveliness-changed-test)`.

- [ ] **Step 3: Run it, expect failure.**

- [ ] **Step 4: Implement** `%liveliness-sweep node` (called from the announce cadence beside `%lease-sweep`): for each matched remote writer, if its `(remote-prefix AUTOMATIC)` liveliness stamp (or a per-writer stamp refreshed also by inbound DATA from it) is older than the matched writer's LIVELINESS `lease_duration`, fire a new `on-liveliness-changed` disc hook `(remote-writer)` once (track an alive/not-alive flag per matched writer so it fires on transition, not every sweep). DCPS installs `on-liveliness-changed` → bump the local DataReader's `liv-changed` (alive_count -1, not_alive_count +1, the *_change fields) + fire the `on-liveliness-changed` listener. A subsequent assertion transitions back to alive (symmetric). Reset *_change on `get_liveliness_changed_status`.

- [ ] **Step 5: Run it, expect pass.** `make test-sbcl`. **Step 6: Commit** (present message: "feat(disc/dcps): reader-side liveliness timing -> LIVELINESS_CHANGED (RTPS §8.4.13, FR-DCPS S1)").

### Task 1.4: writer self-liveliness → LIVELINESS_LOST + `assert-liveliness` (DCPS)

**Files:** Modify `src/dds-dcps/{statuses,entities}.lisp`; Test: `src/dds-tests/`.

- [ ] **Step 1: Add `liveliness-lost-status`** to statuses.lisp:

```lisp
(defstruct* (liveliness-lost-status (:constructor make-liveliness-lost-status)
                                    (:copier copy-liveliness-lost-status))
  "DataWriter LIVELINESS_LOST status (dds_rtf2_dcps.idl §..)."
  (total-count 0 :type integer)
  (total-count-change 0 :type integer))
```

Add a `liv-lost` slot + a `last-assertion` timestamp slot to the DataWriter class. Export.

- [ ] **Step 2: Write the failing test** — a DataWriter with a short LIVELINESS lease and no assertion fires LIVELINESS_LOST; `assert-liveliness` resets it; a write also asserts:

```lisp
(defun* run-liveliness-lost-test ()
    (function () t)
  "A DataWriter whose last-assertion is older than its LIVELINESS lease fires LIVELINESS_LOST
   (total_count_change +1); dds.dcps:assert-liveliness (and a write) resets last-assertion so a
   subsequent sweep does not re-fire."
  ...)
```

Register `("liveliness-lost" . run-liveliness-lost-test)`.

- [ ] **Step 3: Run it, expect failure.**

- [ ] **Step 4: Implement.** `assert-liveliness writer` (exported DCPS API) stamps the writer's `last-assertion := %lease-now`; `write` also stamps it (MANUAL_BY_TOPIC semantics for the local timer — a write asserts). A `%liveliness-lost-sweep` (run from the DCPS spin / the same cadence) fires `LIVELINESS_LOST` on a writer whose `last-assertion + qos-liveliness-lease < now` (once per transition). For AUTOMATIC writers, the announce-cadence assertion (Task 1.2) stamps `last-assertion`, so they only go lost if the participant stops announcing — document this. (Wire the sweep where the node cadence is driven for DCPS participants — mirror how the DCPS layer drives `spin`/announce; if DCPS has no periodic driver, the sweep runs whenever the participant announces.)

- [ ] **Step 5: Run it, expect pass.** Full suite green. **Step 6: Clasp at the S1 boundary** (`GC_DONT_GC=1 make test-clasp`). `make gate-types gate-hotpath`. **Step 7: Commit** (present message: "feat(dcps): writer LIVELINESS_LOST + assert-liveliness API (DDS 1.4, FR-DCPS S1)").

---

## Stage S2 — closeout + live Connext

### Task 2.1: live Connext — participant kill-test + WLP liveliness round-trip

**Files:** Create `interop/connext/` run notes + captures; Modify `docs/provenance.md`.

- [ ] **Step 1: Participant kill-test.** Connext `shapes_pub` ↔ our `square-sub` (or `gated-sub`), with a SHORT lease (set our announced lease + read Connext's; use the shortest practical). Capture lo0; once matched (SUBSCRIPTION_MATCHED=1), `kill` the Connext process; confirm within ~leaseDuration our stack prunes it (`%lease-sweep`) and `SUBSCRIPTION_MATCHED` goes to 0 (log it). Mind the stale-process / firewall gotcha (the memory note: `lsof -nP -iUDP:7400-7420`, loopback-only `:peers`).
- [ ] **Step 2: WLP round-trip.** With Connext running, capture lo0 + confirm: (a) Connext emits ParticipantMessageData on `ENTITYID_P2P_BUILTIN_PARTICIPANT_MESSAGE_WRITER` (tshark; byte-validate against our codec — lock a real-Connext vector if it differs, fixing clause-cited); (b) our reader stays alive while Connext asserts and goes LIVELINESS_CHANGED not-alive when Connext's writer stops (e.g. a MANUAL writer that stops asserting, or kill); (c) our ParticipantMessageData is accepted by Connext (it does not drop our participant for liveliness). Archive captures.
- [ ] **Step 3:** Any wire mismatch → fix failing-locked-vector-test-first, clause-cited, suite green. Record the run notes + frame numbers in `interop/connext/` README + `docs/provenance.md`.

### Task 2.2: closeout

**Files:** Modify `docs/verification.csv` (FR-RTPS + FR-DCPS), `docs/wiki/{discovery,dcps}.md`, `README.md`, `docs/provenance.md`; memory.

- [ ] **Step 1:** `docs/verification.csv` — FR-RTPS: participant-lease expiry + the Writer Liveliness Protocol implemented + live-verified (cite the tests + captures); FR-DCPS: LIVELINESS_CHANGED/LIVELINESS_LOST + the MATCHED decrement. MANUAL_BY_TOPIC reaffirmed as a documented sub-gap. Do not overclaim.
- [ ] **Step 2:** Wiki (discovery: the WLP endpoints + lease sweep; dcps: the new statuses + `assert-liveliness`) + `README.md` status (P1/P2 liveliness now done). `docs/provenance.md` the Connext WLP vector.
- [ ] **Step 3:** Full gates — `make build-sbcl test-sbcl gate-types gate-hotpath`; `GC_DONT_GC=1 make test-clasp`. Paste tails. **Commit** the closeout (present message).
- [ ] **Step 4:** Update `dds-stack-position` memory: liveliness/lease expiry done; new HEAD; the sequence advances to feature 3 (writer-repair pacing). Push held for owner approval.

---

## Self-review notes (run; fixed inline)

- **Spec coverage:** spec §4 S0 (lease expiry) → Tasks 0.1/0.2; spec §4 S1 (WLP: codec → 1.1, builtin endpoints + assertion → 1.2, reader timing → 1.3, writer LIVELINESS_LOST → 1.4); §7 testing → the per-task offline tests + Task 2.1 live; §8 stages → S0/S1/S2; MANUAL_BY_TOPIC sub-gap → Task 2.2 Step 1.
- **Deliberate execution-time reads (not placeholders):** the RTPS EntityId/kind/endpoint-set-bit octets (1.1 Step 1, pinned from §8.4.13/§9.3.2/§9.6.x + Connext-verified — the conventional values are a labeled guide), the two-node test harness to clone (1.2/1.3, named: `run-sedp-test`), the existing DCPS match test to clone (0.2/1.3/1.4), the IDL clause numbers for the status structs. Each names its source.
- **Type consistency:** `disc-node-on-unmatch`, `%lease-sweep`, `%lease-now`, `%fire-unmatch`, `%on-disc-unmatch`, `participant-message`/`serialize-participant-message`/`parse-participant-message`, `+entityid-p2p-participant-message-writer/reader+`, `+pmd-kind-automatic+`, `disc-node-remote-liveliness`, `on-liveliness-changed`/`on-liveliness-lost` (disc hooks + DCPS), `liveliness-changed-status`/`liveliness-lost-status`, `assert-liveliness` — used consistently. The MATCHED decrement reuses the existing `sub-matched`/`pub-matched` slots + the change-reset discipline.
