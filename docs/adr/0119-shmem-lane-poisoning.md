# ADR 0119 — A corrupt SHMEM cursor is hostile input: validate before use, then poison the lane

- **Status:** Proposed. Implemented by WP-0.7 of `docs/plans/2026-10-03-sbcl-allegro-full-ok.md`; awaits
  owner review.
- **Date:** 2026-10-03
- **Requirement:** NFR-SEC-POSTURE (bounds-check every parser facing untrusted input, even at `(safety 0)`;
  the governing plan §2 counts a corrupt SHMEM cursor as hostile input), NFR-OBS (the event must be counted
  and queryable, not only printed), FR-XPORT-2 (the SHMEM transport and its UDP fallback), FR-LANG-7
  (before/after measurement for a hot-path change); the operating contract's no-conditions rule
- **Severity:** **out-of-bounds read** in the SHMEM receive path, on SBCL and AllegroCL. A corrupt read
  cursor faults the receiver (SIGBUS/SIGSEGV past the mapping). Separately, every *detected* corruption wedged
  the lane **silently and permanently** and pinned the receiver thread at full CPU. Reachable by any process
  that can write the receive segment (mode 0600, so the same uid) and by a local defect that corrupts a
  cursor (ADR 0109's multi-producer race was one).
- **Relates to:** ADR 0013 (the SHMEM transport), ADR 0081 (the measured RTI Connext shared-memory layout),
  ADR 0100 (fail-safe, not fail-stop, on a corrupt structure), ADR 0109 (single producer per lane)

---

## 1. The defect

`%lane-drain` (`src/dds-xport/shmem.lisp`) reads two cursors, `w` and `r`, and every record header from a
segment that another process can write. It did check the record **length** against the max-record bound
and the committed extent. It did not check the **position** it read that length from:

```lisp
(let* ((pos (mod r capacity))
       (len (cffi:mem-ref sap :uint32 (+ data pos))))   ; no alignment / extent test on POS
```

Valid records start 8-aligned. `%record-span` rounds every span up to 8, and `%ring-init` refuses a capacity
that is not a multiple of 8, so a conforming `r` is always a multiple of 8 and `pos + 4 <= capacity`. A
corrupt `r = capacity - 1` reads octets `capacity - 1 .. capacity + 2`, three of them past the lane. On the
**last** lane, those octets lie past the end of the mapping. The fault is measured in §7, on both
implementations.

The same function also took its geometry from the shared header: `(%ring-lane-count sap)` placed the data
window and `(%ring-max-record sap)` bounded the record length. A rewritten header therefore moved the window
past the mapping with no corrupt cursor needed. `%any-data-p` (the receiver's work predicate) walked a
header-supplied number of lane descriptors.

### The bail-outs were worse than they looked

The checks that *did* exist returned `T` and left `r` where it was:

```lisp
(when (> (- w r) capacity) (return-from %lane-drain t))
...
((or (> len maxr) (> (+ 4 len) (- capacity pos)) (> (%record-span len) (- w r)))
 (return-from %lane-drain t))
```

After that, nothing could make the lane progress: the same check fails on the next drain and on every one
after it. Because `w ≠ r` stays true, `%any-data-p` keeps returning true, so the receiver thread never
parks. It re-runs a drain that does nothing, at full CPU, for the lifetime of the transport. Nothing was
counted and nothing was logged. The datagram stream from that sender simply stopped, and the only visible
symptom was a busy core.

## 2. The decision

### 2.1 Validate before use

`%lane-drain` checks every value that can address memory before using it. Each failure has its own reason
keyword:

| check, in order | reason |
|---|---|
| `w < r` | `:cursor-regressed` |
| `w - r > capacity` | `:cursor-overrun` |
| `(logtest pos 7)`, before the length read | `:misaligned-cursor` |
| `(> (+ pos 4) capacity)`, before the length read | `:cursor-out-of-range` |
| skip marker whose pad `capacity - pos` exceeds `w - r` | `:skip-overruns-commit` |
| `len > capacity - 8`, or `4 + len > capacity - pos` | `:bad-record-length` |
| `span(len) > w - r` | `:record-overruns-commit` |

`:cursor-out-of-range` cannot fire while `pos` is 8-aligned and the capacity is a multiple of 8. It is kept
anyway because the plan names it (WP-0.7) and it costs one compare.

Lane count, capacity and the record bound (`capacity - 8`, the value `%ring-init` writes as max-record)
come from the receiver's own creation parameters, which are passed in. The shared header is no longer
consulted on the drain path. `%lane-drain` now returns `T` on a clean drain or the reason keyword. It only
detects; it does not decide what to do.

### 2.2 Poison the lane, and choose **quarantine**, not reset

`shmem-receive-drain` acts on a reason keyword (`%poison-lane`) in four steps:

1. **Flag.** The reason is stored in a receiver-local per-lane vector (`shmem-transport-lane-poison`). It is
   deliberately kept out of the segment: a quarantine flag that the peer under quarantine could clear would
   not be a quarantine.
2. **Count.** A per-lane corrupt-cursor counter is incremented (`shmem-transport-lane-corrupt-cursors`).
3. **Log once.** `*shmem-lane-poisoned-hook*` is called exactly once with `(segment-name lane reason count)`.
   The default writes one line to `*error-output*`. A signalling hook is swallowed, so it cannot kill the
   receiver thread.
4. **Quarantine.** The lane is never drained again for the transport's lifetime, and `%any-data-p` skips
   it, so the receiver parks normally.

The plan left the recovery choice open between **detach** (quarantine) and **reset** (`r := w`, resume).
This ADR takes quarantine, for four reasons:

- **A reset trusts the value that was just proven untrustworthy.** Setting `r := w` adopts the producer's
  `w`, and an inconsistent `w` is exactly what the check found. A misaligned `w` would put the reset lane
  back into `:misaligned-cursor` on the next record.
- **A reset turns one event into a flood.** A buggy or hostile producer keeps writing. Each pass would
  re-detect, reset and log, so the one-event property and the meaning of the counter are both lost. That
  can only be patched with rate limiting, which is more machinery to get wrong.
- **A reset races the producer.** The receiver would be writing a cursor the producer reads, in the middle
  of whatever the producer is doing. Quarantine writes nothing into the segment.
- **Quarantine already has a correct fallback, with no new code.** The poisoned lane's read cursor stops
  moving, so its ring fills, `%lane-enqueue` answers "does not fit", and `%shmem-send` returns `0`. That is
  the existing signal for the UDP fallback (ADR 0013). The sender keeps delivering over UDP, and a reliable
  writer repairs whatever was stranded in the ring through HEARTBEAT/ACKNACK. Nothing needs to tell the
  sender anything.

The cost of quarantine: SHMEM stays off for that one (sender, receiver) pair until the receiving
transport is closed. A legitimate sender whose cursor was hit by a local defect stays on UDP. That
outcome is degraded but correct, and it is visible in the counter. It is the same ranking ADR 0100
applied to a corrupt attach cache: stop using a structure known to be corrupt, keep delivering, and make
the event loud.

The counter is a counter rather than a flag, although under quarantine it is only ever 0 or 1 per lane. A
future re-arm policy (for example, re-arming when the sender re-claims the lane after a restart) can then
change its meaning without changing the API.

### 2.3 Store the read cursor on every exit

`r` used to be stored only on the normal exit. If `on-datagram` unwound (a malformed datagram signalling in
the RTPS parser, caught by the receiver thread's boundary handler), the drain was abandoned before the
store. That datagram, and every one before it in the batch, was then redelivered on every following drain,
indefinitely. The same wedge again, triggered this time by a well-formed ring carrying one bad datagram.

`%lane-drain` now advances `r` past a record **before** calling `on-datagram`. The record is already copied
into the sink at that point, so its ring slot is free. `r` is stored in an `unwind-protect` cleanup, so it
is written on the normal exit, on a poison exit (at the last good record boundary) and on an unwind. It is
still one store per drain call, as before, not one per record.

## 3. The sender side has the same class of bug

The send path reads the **destination's** segment, which its receiver owns and can rewrite:

- `%lane-enqueue` placed the data window with the destination header's lane count. A larger count moves the
  window past this process's mapping, which was sized from the *locator*. That is an out-of-bounds
  **write**. It now takes the locator's lane count.
- `%claim-lane` scanned the header's lane count of descriptors and **wrote** its token into the first free
  one. It now scans `(min locator-lane-count header-lane-count)`, which is always inside the mapping and
  never claims a lane the receiver does not drain.
- `%lane-enqueue` reduced a shared write cursor `w` modulo the capacity and wrote a 4-octet header there. A
  non-8-aligned `w` puts that header, or the skip marker, up to 3 octets past the lane. Such a `w` is now
  refused (`NIL`, "does not fit", so the send falls back to UDP) and nothing is written.
- `%lane-enqueue` and `%lane-drain` must agree on **one** record bound, or a conforming producer poisons its
  own lane. The enqueue accepted any `len` with `4 + len <= capacity`, i.e. up to `capacity - 4`, while the
  drain (§2.1) treats `len > capacity - 8` as `:bad-record-length`. A datagram of `capacity - 7` to
  `capacity - 4` octets (65 529 to 65 532 at the default capacity, and reachable whenever a sender's own
  capacity exceeds the destination's, because nothing on the send path enforces the destination's record
  bound) was therefore enqueued, then read as corrupt, and the lane was quarantined with a false
  "hostile input" log line. Before this ADR the same datagram wedged the lane silently. `%lane-enqueue` now
  refuses `len > capacity - 8` (`NIL`, UDP fallback), the same bound `%ring-init` writes as max-record
  and the drain enforces. `run-shmem-enqueue-test` pins it: on an empty 64-octet lane, `len` 58 is refused
  and the lane stays healthy; `len` 56 is accepted and drains cleanly. With the old bound restored, that
  test fails, and the old enqueue plus the new drain reproduce `:bad-record-length`.

## 4. Audit: the RTI Connext shared-memory reader

The plan asked for the RTI-SHMEM reader path (`src/dds-xport/rti-shmem.lisp`, ADR 0081) to be audited the
same way.

**`rti-shmem-read-record` does not have this bug.** Its record offset is
`ring-start + (mod (- cursor 68) modulus)`. It requires `ring-start <= offset < ring-end` before reading,
reads the 4-octet magic only when `ring-end - offset >= 4`, copies at most `min(length out, ring-end -
offset)` octets byte by byte, and checks `ring-end <= segment-size` against a kernel-corroborated segment
size. An unaligned cursor is not a hazard there, because every access is bounds-checked byte-addressed
arithmetic rather than an aligned-record assumption.

**What the audit did find is one level up, in the property plausibility check.**
`%rti-shmem-properties-plausible-p` checked each field on its own (positive, no larger than the segment),
but not the ring those fields describe. With `receive_buffer_size = message_size_max = count = 1`, every
field passes, and the ring modulus is `1 + 1 + 8 - 64 = -54`. Three consequences followed:

- `rti-shmem-ring-modulus` returned a value outside its declared `(unsigned-byte 32)` result type;
- `rti-shmem-record-offset` reduced the cursor modulo a negative number to a non-positive remainder, so the
  offset pointed **below** the ring start, into the control block (descriptor table, block B);
- `rti-shmem-write-record` checks only `offset + len <= segment-size`, so it would write a record **into the
  peer's control block**. A modulus of exactly 0 is also reachable, and is a division by zero.

The fix stays inside that function's own principle, *"the bounds are physical, not policy"*. A new
`%rti-shmem-ring-fits-p` requires:

- a **positive** modulus (closes the `1/1/1` control-block write and the division by zero);
- a ring start **inside** the segment (`ring-start < segment-size`);
- a modulus **no larger than** the segment (`modulus <= segment-size`), which also keeps
  `rti-shmem-ring-modulus` inside its declared `(unsigned-byte 32)`;
- `ring-start + modulus < 2^32`, so `rti-shmem-record-offset` stays inside its declared type as well.

Each is a physical fact about any ring a segment can hold. The arithmetic is done on plain integers, before
either helper is called, because the helpers' result types do not hold for hostile inputs.

The check deliberately does **not** require the ring to *end* inside the segment, although that looks just
as physical. Under the project's own measured formulas (ADR 0081 §5.0) the ring ends at
`rbs + msm + 176 + 16 * count`, and the segment is `rbs + msm + align8(240 + 15 * count)`. The slopes
differ, so from `count = 72` on the formulas put the ring end past the segment (8 octets at 72). The
measurements cover only `count` in {8, 16, 37, 64}, and at 64 the two coincide. Either the formulas are
incomplete above 64 or RTI's ring really does extend that way; without a live capture at `count >= 72` there
is no way to tell, and a ring-end bound on `rti-shmem-segment-properties`, which both the read and the write
path call, could reject a conformant peer. `rti-shmem-read-record` keeps its own per-record
`ring-end <= segment-size` check, so no read can leave the segment either way.

`run-rti-shmem-properties-test` gains three cases: (6) `1/1/1` is refused; (7) a ring that starts at the
segment end (`rbs = msm = 1`, `count = 482` in 4 096 octets, modulus 3 794) is refused by the ring-start
bound alone; (8) the `count = 72` geometry the formulas predict for a 4 096-octet segment
(`rbs = 2264`, `msm = 512`), whose ring formally ends at 4 104, is **accepted**.

Not changed: the write path's record extent is still bounded by `segment-size` rather than `ring-end`. The
measured layout (ADR 0081 §5.0) does not say whether RTI's own producer lets a record extend into the
`message_size_max` slack past the modulus. Tightening that without a live capture risks false-rejecting a
real peer, which is the worst defect class here. It is left for the next live validation against Connext,
as ADR 0081 requires for any change to that path.

## 5. Observability contract (NFR-OBS)

| symbol | contract |
|---|---|
| `shmem-lane-poisoned-p st lane` | `NIL` if healthy, else the reason keyword |
| `shmem-lane-corrupt-cursors st lane` | the lane's counter |
| `shmem-transport-poisoned-lanes st` | `(values total ((lane reason count) …))`, a fresh snapshot; **must be 0 / NIL after a healthy run** |
| `*shmem-lane-poisoned-hook*` | the log event, `(segment-name lane reason count)`, exactly once per poisoning |

These follow the queryable-snapshot pattern of `dds.pal:stuck-teardown-joins` and
`disc-node-stuck-receiver-teardowns`. The reads are lock-free word reads of slots that the single drain
thread writes.

## 6. Hot-path cost

`%lane-drain` and `%lane-enqueue` are in a gate-hotpath file. This ADR adds no allocation (the per-lane
vectors are allocated once, when the transport is created) and no signalling forms. Measured in an
interleaved A/B of the isolated ring primitives, in one process, against HEAD's functions compiled under
the same `defun*`. The full tables are in `bench/report/2026-10-03-shmem-lane-poison.md`:

- **SBCL:** +0 to +2 ns per record at one record per drain (inside the noise); **about +8 ns/record (+3 %)**
  at 64 records per drain. 0 B/record in both arms.
- **AllegroCL:** about **+13 ns/record (+1.2–1.3 %)** at both batch sizes, which is less than the
  run-to-run spread of either arm. AllegroCL's `bytes-consed` does not move for this workload, so no
  allocation number is claimed there; the per-record path gains no allocating form, and gate-hotpath passes.

A re-run of the final code with the committed harness (`bench/shmem-lane-ab/run.sh`) gives the same
picture: SBCL +1.6 ns (batch 1) and +4.5 ns (batch 64) per record, AllegroCL +24 ns (+2.2 %) and +11 ns
(+1.1 %). The end-to-end `make bench-shmem` before/after on SBCL is in the same report. Its run-to-run
spread (20–60 % on throughput, bimodal p50) is far larger than this cost, so it cannot resolve the change.

This is a correctness change with a measured cost. It is not an optimisation.

## 7. Verification — the regression test is falsified on both implementations

`shmem-lane-poison-page-end` (in `dds-tests`) builds a one-lane ring whose lane ends **exactly** at the end
of a one-page `shm-create` object, and drains through a second mapping of that object made at **two**
pages. The second page is past end-of-file, so any access to it raises SIGBUS. That is guaranteed on both
implementations and does not depend on what `mmap` happens to place next to the object. The pre-ADR body of
`%lane-drain`, run against this fixture:

| read cursor | HEAD `%lane-drain`, SBCL | HEAD, AllegroCL | ADR 0119 `%lane-drain`, both |
|---|---|---|---|
| `capacity - 1` | `bus error` | `Received signal number 7` (SIGBUS) | `:misaligned-cursor`, 0 delivered |
| `capacity - 2` | `bus error` | signal 7 | `:misaligned-cursor` |
| `capacity - 3` | `bus error` | signal 7 | `:misaligned-cursor` |

The test also has a positive control: a **valid** 4-octet record in the lane's last 8 octets, ending
exactly at end-of-file, is still delivered. So the fix does not simply refuse everything near the
boundary. It then drives every reason keyword in §2.1 that a single lane can produce.

`shmem-lane-poison-observable` asserts each observable property against a real two-lane transport: the
flag, the counter, the snapshot, **exactly one** hook event naming segment, lane and reason; no further
event or count on later drains; the work predicate ignoring the lane while its cursors still differ; the
neighbouring lane still delivering; and the poisoned lane's sender receiving `0` (the UDP-fallback answer)
once its ring fills.

The RTI-SHMEM ring-fit check is falsified as well. With `%rti-shmem-ring-fits-p` stubbed to `T`,
`run-rti-shmem-properties-test` fails on case 6 on both implementations. Case 8 is the converse: the
ring-end bound of an earlier draft of this ADR refused it (4 104 > 4 096), and the test now requires
acceptance.

The shared enqueue/drain record bound of §3 is falsified on SBCL: with the old enqueue bound restored,
`run-shmem-enqueue-test` fails at `:shmem-enq-bound-reject`, and the old enqueue of 58 octets into a
64-octet lane returns `T` and the drain then returns `:bad-record-length`.

## 8. Consequences

- `%lane-drain`, `%lane-enqueue`, `%claim-lane`, `%any-data-p`, `%rx-wait-for-work` and
  `%rx-spin-for-work` all take the trusted lane count, and `%lane-drain` returns a status. All are
  `%`-internal. Their only other callers are in-repo tests, updated in the same change. The frozen
  `dds.xport` transport record is unchanged.
- `shmem-receive-drain` keeps its signature and return value. It now drains only healthy lanes.
- A same-uid process can still deny SHMEM service to one of its own (sender, receiver) pairs by corrupting
  a cursor. It could already do that by many other means. What it can no longer do is fault the receiver,
  pin a core, or do either of those silently.
- **Not addressed (recorded):** the sender maps a destination at the size its *locator* claims, and
  `dds.pal:shm-attach` does not `fstat` the object. A locator that overstates the segment maps pages past
  end-of-file, and the first enqueue into them raises SIGBUS on the sending thread. Closing this needs an
  `fstat` in the PAL, whose `struct stat` layout must come from `/usr/include`, not from memory. That is a
  separate PAL change.
