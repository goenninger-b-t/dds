# ADR 0100 — The SHMEM attach cache is shared mutable state, and an internal bug is not a send failure

- **Status:** **Proposed**
- **Date:** 2026-07-30
- **Requirements at stake:** **FR-XPORT-2** (SHMEM transport), **NFR-STABILITY** (a data race on the send
  path), **NFR-DET**, **NFR-PORT** (the internal-bug predicate is per-implementation).
- **Relates to:** ADR 0067 (the resolved-once destination cache), ADR 0099 (the segment identity — the same
  function, one layer up), ADR 0064 (statuses, not conditions), WP-SHMEM-SEND-SELF-GUARD.
- **Owner directive, 2026-07-30:** *"do (a) + (c) with a before/after bench."*

---

## 1. The defect

`%attach-for` read and wrote the transport's `attach-cache` **with no lock**:

```lisp
(let ((cached (gethash name (shmem-transport-attach-cache st))))   ; UNLOCKED READ
  (when cached (return-from %attach-for (values cached nil))))
...
(setf (gethash name (shmem-transport-attach-cache st)) ...)        ; UNLOCKED WRITE
```

There is **one `shmem-transport` per node**, hence one table, and `%shmem-send` is reached from **four
threads**: the publishing thread, the async sender (`enable-async`), the receiver thread running the ACKNACK
repair (`%on-user-acknack` → `%send-changes-packed`), and the flow-control scheduler.

The docstring's *"off the hot path"* was true of the **attach** and false of the **lookup**: `%attach-for`
runs on **every** `%shmem-send`, so a per-datagram read races the first-send write to a new peer.

## 2. Two distinct harms, one of which is silent

**Corruption.** Concurrent `(setf gethash)` breaks SBCL's internal hash-table invariants. SBCL detects it:

```
failed AVER: (= HWM (HASH-TABLE-PAIRS-CAPACITY ...))
```

**A leaked segment attach.** Even without corruption, two threads racing the same *new* peer each run
`shm-attach` and one clobbers the other's entry. The loser's mapping is never detached and never freed —
which is exactly what the new test observes as *"got 2 distinct"*.

**And it was invisible.** `%send-raw-buf` wrapped the send in `(handler-case … (error (c)
(%note-shmem-send-fault node c) 0))`, so the whole thing became a quiet UDP fallback plus a counter nobody
asserted on. SHMEM degraded and **no test ever went red**. The only reason it surfaced at all is that a
`:shmem-send-fault` fires the same global hook a flaky test was counting.

## 3. The fix — (a) lock every access

`shmem-transport` gains an `attach-lock`; **every** access to `attach-cache` — the per-datagram lookup, the
fill, and teardown's `maphash`/`clrhash` — is taken under it. The attach and lane-claim stay *inside* the
lock so two threads racing the same new peer produce **one** segment attach and **one** lane claim.

**A double-checked unlocked fast read was considered and rejected.** A reader concurrent with the rehash
inside `(setf gethash)` is the same data race with a narrower window; "usually fine" is not a memory model.

## 4. The fix — (c) an internal bug is not a send failure

`dds.pal:internal-bug-p` (new, per-implementation: `sb-int:bug` on SBCL, `NIL` elsewhere — a documented
NFR-PORT gap that restores exactly the old behaviour) splits the guard:

| condition | response |
|---|---|
| ordinary error | `%note-shmem-send-fault` → counter + hook `:shmem-send-fault` → UDP fallback |
| `internal-bug-p` | `%note-shmem-internal-bug` → **dedicated counter**, **latch SHMEM off for the node**, hook `:shmem-internal-bug` → UDP fallback |

**Why they must differ.** An ordinary fault means *a peer's segment went away*: fall back, repair, carry on.
An internal-invariant violation means *a structure is already corrupt*, and the one response guaranteed to
make that worse is to keep using it. So the node **latches SHMEM off** and never consults a possibly-corrupt
cache again.

**Fail-safe, not fail-stop.** The datagram still falls back to UDP and the sender thread still survives —
signalling here would kill it, which the operating contract forbids and which is strictly worse. What changes
is that the event is *loud, separately countable, and stops further use of the suspect structure* instead of
being indistinguishable from a peer that simply left.

## 5. The measurement

**Isolated SHMEM send primitive**, 200 000 sends of a 64-octet datagram, 3 runs each, macOS/arm64:

| | ns/send | B/send |
|---|---|---|
| before (no lock) | 106.1 / 106.3 / 107.6 | 0.0000 |
| after (locked) | 124.2 / 124.4 / 124.6 | **0.0000** |

**+18 ns/send (~+17 %) on the primitive, and zero allocation.** That is the honest cost of the lock and it is
not hidden: it is one uncontended mutex acquire per datagram. In context it is small — the end-to-end sample
path is microseconds and `gate-mem` is unchanged — but it is a real cost paid to remove a real race, which is
the correct trade under the operating contract's ranking (correctness is a binary gate; performance is the
optimisation target).

**If that 18 ns is ever worth reclaiming**, the way is to stop calling `%attach-for` per datagram at all —
memoise the resolved `shmem-dest` on the locator the discovery layer already caches per peer (ADR 0067 does
the analogous thing for the SAP and lane), leaving the lock on the cold fill path only. That is a design
change, deliberately not bundled here.

## 6. The test, and its falsification

`run-shmem-attach-cache-race-test` drives the race directly: six threads resolve the same set of fresh
destination names through one transport simultaneously — precisely the first-send window — and it asserts
no thread errored, every thread got the **identical** dest object per name, and the cache holds exactly one
entry per name.

**Falsified, which is the only reason to believe it:**

| arm | result |
|---|---|
| lock removed, test unchanged | **5 of 8 FAILED** — *"all threads must share ONE dest … (got 2 distinct)"* |
| lock in place | **6 of 6 PASSED** |

⚠️ A data race is never *required* to manifest, so this test cannot prove absence. What it does is run the
race hard enough that a regression is likely to be caught, and assert the invariant — one dest per name, no
errors — that unsynchronised access cannot reliably maintain.

## 7. Consequences

- One less silent degradation mode: SHMEM no longer falls back to UDP because it quietly corrupted its own
  cache.
- One less leak: a contended first send no longer strands a segment mapping.
- **An implementation-internal bug is now a distinct, latched, separately-counted event** everywhere the
  SHMEM send guard runs — it can never again hide inside the routine-fallback counter.
- `dds.pal:internal-bug-p` is available to any other guard with the same shape. **A blanket `error` clause on
  a resilience guard should be read as a question: does this also swallow evidence that the process is
  already broken?**
- ⚠️ This does **not** close the second `async-emit-fault-survives` failure mode (`got 1` of 6, writer HC
  intact, both sides matched). That remains open and must not be assumed fixed.
