# WP-ZEROCOPY — Zero-Copy-over-SHMEM (sample-pool + ref-passing) — design

**Goal (FR-PF-3).** A writer places samples in a SHMEM sample-pool it owns and transmits a small (~16-byte)
**reference** instead of the payload; a same-host reader maps the pool and reads the sample from the slot;
**loan/return** sample-pool ownership. v1 delivers the **mechanism** (pool + ref-passing + loan/return);
literal 0-copy *read-in-place* (no deserialize) arrives with WP-FLATDATA (FR-PF-4), which flips the slot to
a foreign layout the reader accesses via Offset accessors.

## R6 — PATENT GATE (the defining constraint)
FR-PF-3 mirrors RTI's patented Zero-Copy mechanism (REQUIREMENTS §NFR-IP; IMPLEMENTATION-PLAN R6). Owner
ruling: **build-now / gate-the-ship, engineering-first**. Therefore:
- **Default OFF.** A `*zerocopy-enabled*` special (default `nil`) gates ALL Zero-Copy paths. Unlike SHMEM
  (default-on), Zero-Copy ships **off** — it is **NOT cleared for ship pending counsel (R6)**; every
  Zero-Copy file/feature carries that marker (code header + ADR 0014 + `docs/provenance.md`).
- **Clean-room** from FR-PF-3 + the OMG spec only — **no RTI source/headers/`rtiddsgen` output**.
- **Engineering-first + provenance:** no patent-number research here (counsel owns the authoritative claim
  clearance before P4 ship). This spec records provenance + a general design-around-considerations note;
  counsel verifies before any `*zerocopy-enabled*`-on ship.

## Scope
- **v1 = BEST-EFFORT only**, the pool + ref-passing + explicit refcount loan/return mechanism. Win now:
  **large samples** cross as a 16-byte ref (the payload sits in the pool once; no payload copy into the
  transport, vs WP-SHMEM copying it into the ring) + the loan/return ownership + the reader deserializes
  straight from the SHMEM slot (no transport-buffer copy).
- **OUT of v1 (follow-ups):** RELIABLE Zero-Copy (slot lifetime vs the HistoryCache/ACK path); literal
  0-copy read-in-place (WP-FLATDATA); an app-facing explicit `get-loan`/`return-loan` write API (lands with
  FlatData, where the app builds the layout directly in the loan).

## Contract impact
- Builds on WP-SHMEM PAL primitives (`dds.pal:shm-create`/`attach`/`detach`/`destroy`/`shm-sap`,
  `pshared-mutex-init`/`lock`/`unlock`/`destroy`, `load`/`store-sap-u64`). **No new PAL surface expected**
  (the refcount is pshared-mutex-guarded — no foreign-SAP atomics, full Clasp parity).
- A new **SerializedPayload encapsulation id** for the zero-copy reference (pinned in ADR 0014, vendor
  range, NOT a spec clause — there is no standard RTPS zero-copy encapsulation).
- A new **ADR 0014** (the WP-ZEROCOPY feature + R6 markers + the encapsulation/flag constants).
- Module: `src/dds-xport/zerocopy-pool.lisp` (package `dds.xport.zerocopy`, the SHMEM sample-pool — a
  transport-adjacent abstraction beside `shmem.lisp`), + dataplane hooks in `src/dds-disc/dataplane.lisp`,
  + the encapsulation constant in `src/dds-rtps/message.lisp`, + a ZC-capable flag in SEDP
  (`src/dds-rtps/discovery.lisp`). Mirrors how WP-SHMEM integrated (pool abstraction in dds-xport;
  same-host integration in dds-disc).

## Architecture — the reference rides the existing DATA path
When `*zerocopy-enabled*` AND a matched reader is **same-host + ZC-capable** (SEDP-advertised), the writer
publishes a normal **reliable-or-best-effort DATA submessage whose SerializedPayload is the ~16-byte
zero-copy reference** (the new encapsulation id), instead of the serialized sample. It travels the existing
transport (UDP or the WP-SHMEM ring) through the **full RTPS machinery unchanged** (discovery, the DATA
path, history). The reader's `%handle-datagram`, on the zc-encapsulation, **resolves** the ref (maps the
pool, deserializes from the slot, releases) *before* delivering to the reader via the existing path. The
RTPS engine is otherwise untouched; with `*zerocopy-enabled*` nil the path is byte-for-byte the existing
serialized DATA. *(Rejected: a separate control channel — loses engine reuse.)*

## Sample-pool (per-writer SHMEM segment)
A per-writer SHMEM segment: a header (pshared mutex + freelist head + slot-count + slot-size) followed by
**K fixed-size slots**. Each slot: `{refcount:u32, generation:u32, len:u32, payload:slot-size}`. Built on
`dds.pal:shm-create`/`attach`. Slot-size = a configured max serialized sample size for the type (from
`RESOURCE_LIMITS`/type bound); K configurable. The segment name is derived from the writer GUID (the DATA's
source GUID — no extra advertisement; the reader derives it identically). `*zerocopy-default-slots*` /
`*zerocopy-default-slot-bytes*` shared constants (one definition, used by both pool creation and the
advertised geometry — the WP-SHMEM DRY lesson).

## Slot lifecycle — explicit pshared-mutex refcount (+ generation, + force-reclaim)
All slot-state transitions happen **under the pool's pshared mutex** (cross-process, Clasp parity; no
foreign-SAP atomics).
- **Writer publish:** lock; take a free slot from the freelist, OR if none, **force-reclaim the oldest
  published slot** (bound the pool + tolerate lost best-effort refs); **bump the slot's `generation`**
  (invalidates any in-flight ref to a reclaimed slot); set `len`; unlock; serialize the sample into the
  slot payload; lock; set `refcount = N` (N = #matched same-host ZC-capable readers); unlock; send the ref
  `{slot-index, generation}`. If N = 0 → no ZC (fall back to normal DATA). Pool fully saturated with
  in-read slots → RESOURCE_LIMITS → **fall back to normal serialized DATA** (no loss, no double-delivery).
- **Reader resolve:** map the writer pool (cached `shm-attach`); lock; **validate `slot.generation ==
  ref.generation`** (else stale/reclaimed → drop, no decrement) AND `slot-index < K` (untrusted ref bounds
  check, NFR-SEC-POSTURE); unlock; deserialize from the slot payload into the existing reader loan-pool
  struct; lock; **re-validate generation** (a force-reclaim during the read → mismatch → drop); else
  **decrement `refcount`; if 0 → return the slot to the freelist**; unlock; deliver the sample via the
  existing reader path.
- **Generation** is the single guard for every race: stale refs, force-reclaim mid-read, and untrusted
  cross-process refs all reduce to a generation/bounds mismatch → safe drop. Best-effort semantics: a lost
  ref or a force-reclaimed-mid-read sample is simply not delivered (acceptable for BEST_EFFORT).

## The 16-byte reference (encapsulation payload)
`{slot-index:u32, generation:u32, slot-bytes:u32, reserved:u32}` (16 octets, LE; exact layout pinned in
ADR 0014). The pool **segment name derives from the writer GUID**; `slot-bytes` lets the reader map with
the right geometry; `generation` validates the slot. Carried as the new zc encapsulation in the DATA's
SerializedPayload.

## Discovery
SEDP advertises a **ZC-capable** flag (a vendor PID or a bit, pinned in ADR 0014) so a writer only sends zc
refs to readers that understand them; a non-ZC / cross-host / cross-vendor reader gets normal serialized
DATA (fail-open). Same-host detection reuses the WP-SHMEM `host-uuid`.

## Safety / fallback / engine-untouched
- The zc reference is **untrusted cross-process input**: bounds-check slot-index + validate generation
  before any slot access, even at `(safety 0)` (NFR-SEC-POSTURE). The ref resolver is fuzzed.
- Every fallback (ZC off, no same-host ZC reader, pool exhausted, stale/invalid ref) → the normal
  serialized DATA path; **no loss, no double-delivery** (exactly one of {zc ref, serialized DATA} per
  sample, mirroring the WP-SHMEM `%send-raw-buf` discipline).
- With `*zerocopy-enabled*` nil: zero behavioural change (byte-identical to today).
- Teardown: the writer destroys its pool segment on stop (after the SHMEM receiver join, UAF rule).

## Hot-path purity & memory
The pool slots are `mmap` foreign/static memory (NFR-MEM). The writer serialize-into-slot and the reader
deserialize-from-slot are raw SAP access + the existing codecs — no per-sample CLOS, no GC-heap sample
buffers. The publish/resolve hooks stay slot-read + funcall (gate-hotpath). Large samples: 0 payload copies
into the transport (only the 16-byte ref crosses).

## Testing / acceptance
- Pool: loan/return, refcount → 0 frees, force-reclaim-oldest on exhaustion, generation bump invalidates a
  stale ref. Ref: encode/decode + **fuzz** (bad slot-index/generation → safe drop, no OOB).
- Reader-resolve round-trip (map → validate → deserialize → release); best-effort lost-ref → slot reclaimed
  (no leak); force-reclaim-mid-read → reader drops (generation).
- **Large-sample bench (FR-LANG-7):** ZC vs WP-SHMEM serialized — show the no-payload-copy win + bytes/sample.
- **2-process ZC exchange** (`make` harness, SBCL; Clasp/macOS uses the shm NFR-PORT gap → falls back).
- **Engine-untouched regression:** `*zerocopy-enabled*` nil → full suite byte-identical; on → no double-
  delivery, no UDP/SHMEM regression.
- Gates green SBCL+Clasp; behind the off-by-default flag throughout.

## Provenance + design-around considerations (engineering-first; counsel clears before ship)
Implemented clean-room from FR-PF-3 + the OMG DDSI-RTPS spec; no RTI source consulted. General design-around
considerations recorded for counsel (NOT legal advice; counsel does the authoritative claim analysis before
any `*zerocopy-enabled*`-on ship): the ref encoding/encapsulation, the pool/slot layout, the refcount/
generation lifecycle, and the segment-naming are this project's own; differences from RTI's mechanism (where
known from public DDS documentation, not RTI source) are noted in `docs/provenance.md`. **NOT cleared for
ship — pending counsel (R6).**

## Out of scope (explicit)
Reliable Zero-Copy; literal 0-copy read-in-place (WP-FLATDATA); app-facing explicit loan/return write API;
cross-vendor ZC interop (segment/encapsulation are ours — no standard RTPS zero-copy wire format).
