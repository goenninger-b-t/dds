# ADR 0109 — The SHMEM lane enqueue is single-producer, and the send path had many producers

- **Status:** Accepted
- **Date:** 2026-08-07
- **Requirement:** FR-XPORT-2 (shared-memory transport), FR-QOS (RELIABILITY), NFR-SEC-POSTURE
- **Severity:** conformance + data-integrity defect, **pre-existing**
- **Evidence:** `bench/report/2026-08-07-two-defects-under-concurrent-writes.md`

---

## 1. The defect

`%lane-enqueue` is, by its own docstring, a **single-producer** ring enqueue. It performs three separate,
non-atomic steps:

```lisp
(w (dds.pal:load-sap-u64 sap (+ base +lane-off-write+)))   ; 1. read the write cursor
...
(dds.pal:sap-copy-in sap (+ data pos 4) payload off len)   ; 2. write the record AT that position
(dds.pal:store-sap-u64 sap (+ base +lane-off-write+) (+ w span)))   ; 3. publish cursor + span
```

`%shmem-send` called it with **no mutual exclusion**, on the caller's thread. A lane is claimed per **sender
token**, and `%guid-token` derives that token from the participant's GUID prefix — so every thread of one
participant shares **one** lane. Two of them interleave as:

| | T1 | T2 |
|---|---|---|
| 1 | `w := W` | |
| 2 | | `w := W` |
| 3 | write record A at `pos(W)` | |
| 4 | | write record B at `pos(W)` — **destroys A** |
| 5 | `write := W + span(A)` | |
| 6 | | `write := W + span(B)` |

Consequences, all observed:

- **A datagram is silently destroyed.** Two records were written, the cursor advanced for one. Under
  RELIABLE this is a lost sample the repair machinery has no reason to resend — the writer believes it sent
  it, and the reader never learns it existed.
- **The consumer resumes mid-record.** When `span(A) ≠ span(B)` the published cursor lands inside a payload,
  so `%lane-drain` reads a length field out of message bytes. The reader then decodes a *datagram header*
  as a `SerializedPayload` — observed as `CDR codec error: unknown representation id #x5254`, and **`0x52
  0x54` is `RT`, the first two octets of the RTPS magic**.
- **The space check is computed from a stale pair.** `(> (+ (- w r) need) capacity)` uses a `w`/`r` another
  producer has already moved.

## 2. Why this was not a theoretical race

The sibling docstring on the attach cache already states the path "runs on **EVERY** `%shmem-send` from
**FOUR threads** (the publisher, the async sender, the receiver thread's ACKNACK repair, the flow
scheduler)". ADR 0100 locked the attach **cache** for exactly that reason and **left the enqueue itself
unlocked** — the shared mutable state one level down was not re-examined. Application threads calling
`write` on one `DataWriter` (DDS 1.4 §2.2.2.4.2.11 permits any number) add a fifth producer.

Cross-**process** single-producer is structural — one lane, one sender token. Cross-**thread** was assumed.

## 3. The decision

Serialise the enqueue with a lock on the **destination**:

```lisp
(dds.pal:with-lock ((shmem-dest-send-lock dest))
  (%lane-enqueue sap lane ...))
```

- **Per destination, not per transport.** `shmem-dest` is the resolved-once cache entry for one peer
  segment, and a sender holds exactly **one lane per destination** — so this is precisely the lane's
  granularity, and sends to *different* peers stay fully concurrent.
- **Not held across the wake.** The futex signal stays outside; the Dekker handshake with the receiver is
  unchanged, and no lock is held across a syscall.
- **No non-local exit crosses the lock** (ADR 0098): `%lane-enqueue`'s three `return-from`s are internal to
  it, and the lock wraps the *call*. `make gate-nlx` stays at 0.
- The docstring now states single-producer as a **caller obligation**, not an observation.

## 4. What was rejected

- **A multi-producer ring** (reserve-cursor + per-record commit flags). Correct, and a much larger change to
  a cross-process ABI with an untrusted consumer — for a lock that is uncontended in the common case.
- **A lane per sending thread.** Lanes are a fixed, shared, cross-process resource (8 per segment); threads
  are unbounded. It also changes what a lane *owner* means, which ADR 0099 pinned deliberately.

## 5. Cost

One uncontended lock acquire per SHMEM datagram. `gate-mem` all three arms must be unmoved — the lock is
a `defstruct` initform, one per destination, never per datagram.

## 6. Verification

- The 4-threads × 30-writes reproducer: **no corruption in 16 trials** across both transports, against
  1 corrupt run in 5 before.
- ⚠️ **This fix alone does NOT restore delivery** — measured 102/110/53/110/114/102 with it applied and the
  drain still a high-water. The second defect (ADR 0108) had to be fixed too; neither is sufficient alone,
  which is exactly why ADR 0108's first attempt appeared to do nothing.
- Full suites on SBCL + Clasp, `make gate-mem`, `make gate-nlx`, `make gate-hotpath`.
