# ADR 0014 — WP-ZEROCOPY: Zero-Copy-over-SHMEM (best-effort v1)

- **Status:** Accepted (2026-06-14)
- **Deciders:** A0 (integrator)
- **Amends:** nothing frozen — purely additive; no existing interface symbol changed
- **Requires:** WP-SHMEM complete (ADR 0013, FR-XPORT-2); PAL shm/pshared-mutex primitives
- **Feature:** FR-PF-3 (Zero-Copy publication)

## R6 — PATENT GATE (defining constraint)

WP-ZEROCOPY mirrors RTI's patented Zero-Copy mechanism (REQUIREMENTS §NFR-IP, IMPLEMENTATION-PLAN R6).

**Owner ruling: build-now / gate-the-ship, engineering-first.**

- **Default OFF.** `*zerocopy-enabled*` (default `nil`) gates ALL Zero-Copy paths. Unlike SHMEM
  (default-on), Zero-Copy ships **OFF** — it is **NOT cleared for ship pending counsel (R6)**.
- Every WP-ZEROCOPY file carries the header: `;;;; NOT cleared for ship — pending counsel (R6); see ADR 0014.`
- **Clean-room** from FR-PF-3 + the OMG DDSI-RTPS spec only — **no RTI source/headers consulted**.
- Engineering-first + provenance: counsel does the authoritative claim clearance before any
  `*zerocopy-enabled*`-on ship. This ADR records provenance + design-around notes for counsel.

## Context

WP-SHMEM (ADR 0013) delivers a ring-based same-host transport where the serialized payload is copied
into the SHMEM ring. For large samples this copy dominates. WP-ZEROCOPY eliminates it: the writer
places the serialized sample **once** into a per-writer SHMEM sample-pool and transmits a compact
**~16-byte reference** instead of the payload. A same-host ZC-capable reader maps the pool and
deserializes directly from the slot — no payload copy into the transport layer.

The authoritative design spec is `docs/superpowers/specs/2026-06-14-wp-zerocopy-design.md`.

## Design (v1 — best-effort only)

### Overview

When `*zerocopy-enabled*` AND a matched reader is **same-host + ZC-capable** (SEDP-advertised):
the writer publishes a normal DATA submessage whose `SerializedPayload` is a 16-byte zero-copy
reference (the new `+zc-encapsulation-id+`), not the serialized sample. The reference travels the
existing RTPS machinery (discovery, DATA path, history) unchanged. A reader whose
`%handle-datagram` encounters `+zc-encapsulation-id+` resolves the reference (maps the pool,
deserializes from the slot, releases) before delivering via the existing path. A reader without ZC
sees an unknown representation id and ignores the sample (fail-open). With `*zerocopy-enabled*`
nil the path is byte-for-byte the existing serialized DATA.

### Per-writer SHMEM sample-pool

A per-writer SHMEM segment: a header (pshared mutex + freelist head + slot-count + slot-size)
followed by **K fixed-size slots**. Each slot: `{refcount:u32, generation:u32, len:u32,
_pad:u32, pubseq:u64, payload:slot-size}`. The `pubseq` u64 is a process-local monotonic
publish sequence used by the force-reclaim path to identify the oldest published slot; it sits
at slot-offset +16 (8-byte aligned). The stride is `header-bytes + round-up-8(slot-size)` so
every slot starts 8-aligned regardless of `slot-size`. Built on `dds.pal:shm-create`/`attach`.
Slot-size = a configured max serialized sample size for the type; K configurable. The segment
name derives from the writer GUID (the DATA's source GUID — no extra advertisement; the reader
derives it identically).

### Slot lifecycle — explicit pshared-mutex refcount + generation + force-reclaim

All slot-state transitions happen **under the pool's pshared mutex** (cross-process; no
foreign-SAP atomics — full Clasp parity).

- **Writer publish:** lock; take a free slot, OR if none, **force-reclaim the oldest published
  slot** (bounds the pool; tolerates lost best-effort refs); **bump `generation`** (invalidates
  any in-flight ref); set `len`; unlock; serialize into the slot payload; lock; set
  `refcount = N` (N = #matched same-host ZC-capable readers); unlock; send ref
  `{slot-index, generation}`. If N = 0 → fall back to normal DATA. Pool saturated → fall back
  to normal DATA (no loss, no double-delivery).
- **Reader resolve:** map the pool (cached `shm-attach`); lock; **validate `slot.generation ==
  ref.generation`** AND `slot-index < K` (bounds-check — untrusted cross-process ref,
  NFR-SEC-POSTURE); unlock; deserialize from the slot; lock; **re-validate generation** (force-
  reclaim mid-read → mismatch → drop); else **decrement `refcount`; if 0 → return slot to
  freelist**; unlock; deliver via the existing reader path.
- **Generation** is the single guard: stale refs, force-reclaim mid-read, and untrusted
  cross-process refs all reduce to a generation/bounds mismatch → safe drop. Best-effort
  semantics: a lost ref or a force-reclaimed-mid-read sample is simply not delivered.

### The 16-byte reference (encapsulation payload)

`{slot-index:u32, generation:u32, slot-bytes:u32, reserved:u32}` (16 octets, LE). Pool segment
name derives from the writer GUID; `slot-bytes` lets the reader map with the right geometry;
`generation` validates the slot. Carried as `+zc-encapsulation-id+` in the DATA SerializedPayload.

### Discovery — ZC-capable flag

SEDP advertises a ZC-capable flag via `+pid-zerocopy-capable+` so a writer only sends zc refs to
readers that understand them; a non-ZC / cross-host / cross-vendor reader gets normal serialized
DATA (fail-open). Same-host detection reuses the WP-SHMEM host-uuid.

## Pinned vendor constants (ours; NOT OMG spec clauses)

| Symbol | Value | Description |
|---|---|---|
| `+zc-encapsulation-id+` | `#x4B43` | SerializedPayload encapsulation id for a WP-ZEROCOPY 16-byte reference. Vendor-chosen; sits well outside the XTypes 1.3 Table 60 standard range (max `#x000b`). A reader without ZC sees an unknown representation id and ignores the sample (fail-open). |
| `+pid-zerocopy-capable+` | `#x8041` | Vendor SEDP PID (1 octet, 1 = endpoint understands WP-ZEROCOPY references). Adjacent to `+pid-shmem-host-uuid+` (`#x8040`). In the `0x8000` vendor-range; unknown-PID skip by cross-vendor peers is fail-open. |

Both values were verified against the full source tree before use: no existing constant uses
either value. They are pinned here, not derived from any spec clause.

## Consumers

- `src/dds-cdr/cdr.lisp` — `+zc-encapsulation-id+` (encapsulation constant)
- `src/dds-rtps/message.lisp` — `+pid-zerocopy-capable+` (SEDP PID)
- `src/dds-disc/disc.lisp` — `*zerocopy-enabled*` (master switch)
- `src/dds-xport/zerocopy-pool.lisp` (future, Task A2) — pool implementation

## Provenance

Implemented clean-room from FR-PF-3 + OMG DDSI-RTPS 2.5 spec; no RTI source, headers, or
`rtiddsgen` output consulted. General design-around considerations recorded for counsel (NOT legal
advice; counsel does the authoritative claim analysis before any `*zerocopy-enabled*`-on ship):
the ref encoding/encapsulation, the pool/slot layout, the refcount/generation lifecycle, and the
segment-naming are this project's own design. Provenance logged in `docs/provenance.md`.

**NOT cleared for ship — pending counsel (R6).**

## Safety / fallback / engine-untouched

- The zc reference is **untrusted cross-process input**: bounds-check slot-index + validate
  generation before any slot access, even at `(safety 0)` (NFR-SEC-POSTURE).
- Every fallback (ZC off, no same-host ZC reader, pool exhausted, stale/invalid ref) → the
  normal serialized DATA path; no loss, no double-delivery.
- With `*zerocopy-enabled*` nil: zero behavioural change (byte-identical to today).

## Hot-path purity & memory

Pool slots are `mmap` foreign/static memory (NFR-MEM). Publish/resolve hooks: slot-read + funcall
(gate-hotpath). Large samples: 0 payload copies into the transport (only the 16-byte ref crosses).

## Out of scope (v1)

Reliable Zero-Copy; literal 0-copy read-in-place (WP-FLATDATA, ADR 0015 — **update:** WP-FLATDATA shipped a
**safe SINGLE copy** ~830× RX win; **literal-0-copy is still deferred**, needs an engine-contract change, see
ADR 0015 *Phase D outcome*); app-facing explicit `get-loan`/`return-loan` write API; cross-vendor ZC interop.

## Consequences

- Three new exported symbols: `+zc-encapsulation-id+` (dds.cdr), `+pid-zerocopy-capable+`
  (dds.rtps.message), `*zerocopy-enabled*` (dds.disc). All default-off / additive.
- No existing interface symbol changed; no existing behaviour changed when `*zerocopy-enabled*`
  is nil (the default).
- `docs/verification.csv` FR-PF-3 row: open until the pool roundtrip test + large-sample bench pass.
- No migration burden: purely additive.

## Final design (as implemented) — Phases A–E

**Status: implemented best-effort v1; NOT cleared for ship — pending counsel (R6).** The as-built matches
the design above; this section records the concrete shape and the Phase E (bench + 2-process + docs) outcome.

### Pool layout (as built)

`src/dds-xport/zerocopy-pool.lisp` (`dds.xport.zerocopy`). A per-writer `mmap` foreign segment:
`{header | K slots}`. The **header** carries `magic + version + slot-count + slot-bytes + free-head + a
PTHREAD_PROCESS_SHARED mutex` (a `%zc-validate` magic/version guard rejects an ABI-mismatched attach).
Each **slot** is `{refcount:u32, generation:u32, len:u32, _pad:u32, pubseq:u64, payload:slot-bytes}` — the
`pubseq` u64 sits at slot-offset +16 (**8-byte aligned**) and the **stride is `header-bytes +
round-up-8(slot-bytes)`** so every slot starts 8-aligned regardless of `slot-bytes` (the alignment fix in
commit `59aafee`; test `zc-pool-align`). `K = +zerocopy-pool-slots+` = 32, `slot-bytes =
+zerocopy-pool-slot-bytes+` = 65536 (both pinned in `dds.disc`, used by BOTH the writer's `%zc-make-pool`
and the reader's attach geometry — single source of truth). While a slot is free its `len` field doubles as
the freelist link. All slot-state transitions are **under the header pshared mutex** — no foreign-SAP CAS, so
full Clasp parity at this layer.

### Reference encoding (as built)

`dds.cdr:encode-zc-reference` / `parse-zc-reference`. The SerializedPayload is **20 octets**: a 4-octet
encapsulation header (`+zc-encapsulation-id+` = `#x4B43` in NBO + a 2-octet options field = 0) followed by the
**16-octet reference body** `{slot-index:u32, generation:u32, slot-bytes:u32, reserved:u32}` in LE. The pool
segment name derives from the writer GUID (no extra advertisement — the reader derives it identically);
`slot-bytes` lets the reader map with the right geometry; `generation` validates the slot.

### refcount = 1 per reference (as built — corrected from the sketch)

The slot is loaned with **`refcount = 1`**, NOT the matched-reader count. A large `:data` sample is emitted to
a destination as a DATA with `readerId = UNKNOWN`, which that participant's receiver processes **once**
(`%on-user-data` → one `%zc-release`) regardless of how many co-located ZC reader endpoints it has. Refcount 1
therefore frees the slot after that single resolve; using the reader count would leak the slot when a
destination has >1 ZC reader (`%zc-ref-builder`, commit `a7c97dd`). `%zc-readers > 0` is used purely as the
engage **gate**, not as the refcount.

### Publish / resolve hooks — gated on the pool slot (as built)

- **Writer** (`src/dds-disc/dataplane.lisp`, `%push-data-buf` → `%send-changes-packed` →
  `%zc-change-item`): a `:data` change whose serialized payload is **strictly larger than
  `*zerocopy-min-payload-bytes*`** (default 1024) AND whose destination group has `%zc-readers > 0` is
  `%zc-loan`'d into the pool and sent as the 20-octet reference; `%zc-loan` NIL (pool saturated / payload >
  slot) falls back to normal DATA — **exactly one of {ref, full payload} per reader** (no double-delivery).
  Bumps `disc-node-zc-sends`.
- **Reader** (`%on-user-data` → `%zc-attach-pool` + `%zc-resolve` + `%zc-release`): an incoming
  SerializedPayload whose leading u16 is `+zc-encapsulation-id+` is resolved against the (cached) attached
  writer pool into a **fresh per-datagram vector** (no shared sink → thread-safe across the UDP + SHMEM
  receivers), then released; a non-ref payload returns `:not-a-ref` and takes the exact prior copy-and-deliver
  path. **Bounds + generation are checked before any slot access even at `(safety 0)`** (NFR-SEC-POSTURE); an
  invalid / forged / stale / force-reclaimed-mid-read ref reduces to a generation/bounds mismatch and is
  **dropped best-effort** (test `zc-resolve-drop`; the parser is fuzzed).
- **The gate is the POOL SLOT** (`disc-node-zc-pool`), not the `*zerocopy-enabled*` special — the receiver /
  WP-ASYNC sender threads cannot see a dynamic binding (mirrors `disc-node-shmem`). The pool exists iff
  `*zerocopy-enabled*` was `t` at `make-disc-node` AND SHMEM was available. `stop-node` JOINs every receiver
  **before** detaching attached pools + destroying/unlinking the writer pool (UAF rule).

### Threshold + best-effort-only (as built)

`*zerocopy-min-payload-bytes*` (default 1024) is the size gate: at/below it the sample is sent as normal DATA
(the small-sample path is the WP-SHMEM/batching target). v1 is **best-effort only**: a lost reference or a
force-reclaimed-mid-read sample is simply not delivered (reliable Zero-Copy — slot lifetime vs the ACK path —
is out of scope). With `*zerocopy-enabled*` nil (the default) the data path is **byte-identical to today**.

### Bench outcome (Phase E1 — `bench/report/2026-06-14-wp-zerocopy.md`)

`dds.bench:run-bench-zerocopy` (`make bench-zerocopy`) compares ZC vs serialized-SHMEM vs UDP at 4/16/64 KiB
(SBCL/macOS Apple M5). For LARGE same-host samples ZC is a clear **latency** win (≈2.5x–3.9x lower one-way
median vs UDP; up to **15.8x** vs the fragmented SHMEM path) and a **throughput** win that GROWS with size
(up to **9.9x** vs SHMEM at 64 KiB) — only a 16-byte reference crosses instead of the fragmented payload, so
there is no fragmentation/reassembly round-trip. The 512 B control row (below the threshold) correctly shows
`zc-sends = 0` (fell back to normal DATA). **Honest caveat (FR-LANG-7):** the v1 reader resolve over-allocates
a slot-sized (`+zerocopy-pool-slot-bytes+`) scratch sink per sample, so the per-sample *allocation* win only
materializes once the sample approaches the slot size (64 KiB); at 4/16 KiB ZC conses more than SHMEM. Sizing
the sink to the parsed `len` (cheap) and ultimately read-in-place (FlatData) turn the allocation win on at all
sizes. The bench asserts `disc-node-zc-sends` advanced on every above-threshold row, so the ZC columns are
proven to have crossed as a reference, not a payload.

### 2-process proof (Phase E2 — `scripts/zerocopy-roundtrip.sh`, `make zc-xproc`)

`dds.shapes:run-zc-xproc-pub` / `run-zc-xproc-sub` launch two **separate SBCL OS processes** that discover over
loopback UDP (deterministic domain-derived ports + `:peers`, no multicast) and exchange LARGE `LargeData`
samples. The publisher stores each in its SHMEM pool and sends only a 16-byte reference; the subscriber
resolves it from the writer's pool **cross-process** and verifies the payload byte-exact. PASS iff the sub
received ≥ threshold byte-exact AND the pub's `zc-sends > 0`. Confirmed PASS (`ZC-SUB-RECEIVED: 8`,
`ZC-PUB-SENDS: 24 / 24`) — proving the reference resolves across the OS-process boundary. SBCL only;
Clasp/macOS inherits the WP-SHMEM by-name-attach gap (ADR 0013) and the ZC tests pass-skip there.

### Tests / gates

`zc-ref-codec`, `zc-pool-init`, `zc-pool-loan`, `zc-pool-resolve`, `zc-pool-align`, `zc-sedp-flag`,
`zc-resolve-drop`, `zerocopy-end-to-end`, and `perftest-zerocopy-smoke` (174 green SBCL+Clasp; the SHMEM-gated
ones pass-skip on Clasp/macOS); `gate-types` + `gate-hotpath` PASS; the reference parser is fuzzed.

### Follow-ups (out of scope v1)

Reliable Zero-Copy (slot lifetime vs the ACK path); literal 0-copy **read-in-place** / FlatData (**update,
ADR 0015 Phase-D outcome:** WP-FLATDATA shipped a **safe SINGLE copy** — it removed the resolve-side sink
over-allocation the E1 bench surfaced, a ~830× RX win — but **literal-0-copy remains deferred**, needing an
engine-contract change); an app-facing explicit `get-loan` / `return-loan` write API; cross-vendor ZC interop.

**NOT cleared for ship — pending counsel (R6); see the R6 — PATENT GATE section above.**
