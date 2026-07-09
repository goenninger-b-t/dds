# WP-SECURITY-ZC-SHMEM-OVERLAY — confidential Zero-Copy/SHMEM for an ENCRYPT-tier writer (ADR 0051, FR-PF-3, FR-LANG-7, R6)

**NOT cleared for ship — pending counsel (R6); see ADR 0051 (+ ADR 0014/0038/0042).** The Zero-Copy/SHMEM
feature area carries the patent-review marker; `*zerocopy-enabled*` defaults NIL. This measures the **copy /
datagram / AEAD profile** of the new ENCRYPT-tier overlay ZC path against the path it replaces (the ADR 0036
Carry 10 gated-off serialize + ring path), which is the appropriate before/after measurement for a
transport-routing + in-slot-format change (FR-LANG-7). It is **not** a latency-harness claim — see *Honest
scope* below.

## Environment

| field | value |
|-------|-------|
| impl | SBCL 2.6.5-85913ede1 |
| host | goede012.local (arm64) |
| HEAD | f2b675b |
| date | 2026-07-09 |
| payload | 16384 octets (16 KiB) |
| governance | `metadata_protection` / `rtps_protection` = ENCRYPT, `data_protection` = NONE |

## Method (reproducible)

`scripts/with-sbcl.sh --load bench-overlay.lisp` drives the production write path in one image (the same
internals `run-zc-shmem-secured-overlay-test` Part B/C exercise), with `*zerocopy-enabled* = T` and an ENCRYPT
EntityCrypto KM installed as the `crypto-transform`:

1. Build a 16 KiB `:data` cache-change; call `%zc-change-item` (the single pool-loan chokepoint). For the
   overlay-eligible writer this takes the **overlay arm**: seal the payload into the per-writer scratch buffer
   as a `data_protection` `SecuredPayload` (`encode-serialized-payload-into`, ADR 0038), `%zc-loan` it into the
   pool slot, and emit a reference item.
2. Render the emitted reference item to bytes with `%msg-datagram` (RTPS header + the DATA submessage carrying
   the 20-octet ZC reference) and record its length.
3. Record the `disc-node-zc-sends` advance (proof a reference datagram — not the payload — crossed) and the
   `SecuredPayload` slot size (`44 + payload`).

The **gated-off** baseline is the current pre-overlay behaviour for the identical governance: `%zc-change-item`
returns NIL (ADR 0036 Carry 10), so the sample takes the normal serialize → SRTPS-wrap path and the **full
payload is carried in-band** through UDP or the SHMEM ring. Its transport datagram is therefore bounded below by
the 16384-octet payload plus RTPS/DATA/SRTPS framing (the payload cannot be elided without ZC), and `zc-sends`
does not advance.

## Measured — the transport datagram collapses from the full payload to a 64-octet reference

| metric | gated-off (today, ADR 0036 Carry 10) | overlay ZC (ADR 0051) |
|---|---|---|
| ZC taken (`zc-sends` advance / sample) | 0 (disabled) | **1** (measured) |
| transport datagram bytes / sample | ≥ 16384 payload + framing (full payload in-band) | **64** (measured — RTPS hdr + DATA submsg + 20-octet reference) |
| SHMEM-ring double-buffer of the payload | yes (serialize + ring copy of ~16.4 KiB) | no — one `%zc-loan` write of the 16428-octet slot |
| pool slot contents | n/a (no ZC) | 16428-octet **ciphertext** `SecuredPayload` (plaintext provably ABSENT — test Part B) |

The transport datagram drops from ≥ 16.4 KiB (the whole payload) to a **measured 64 octets** — a ≥ 256x smaller
datagram for a 16 KiB sample — because under ZC only the reference travels while the (now-ciphertext) payload
stays resident in the pool slot.

## Copy / AEAD profile per sample (FR-LANG-7 — the honest tradeoff)

| stage | gated-off (today) | overlay ZC (ADR 0051) |
|---|---|---|
| writer serialize | 1 pass (16384 B) | 1 pass (16384 B) |
| writer AEAD | SRTPS encrypt of the whole ~16.4 KiB datagram | 1 `SecuredPayload` seal of the 16384-B payload (zero-cons, ADR 0038) |
| writer payload copy into transport | SHMEM-ring double-buffer of the full datagram | 1 memcpy scratch→slot (same copy raw ZC already does) |
| reader AEAD | SRTPS decrypt of the whole ~16.4 KiB datagram | 1 `SecuredPayload` decode (copy-on-read) |
| reader payload materialization | ring drain + deserialize | copy-on-read decode + deserialize |

Net: the overlay pays the **same** one-AEAD-over-the-payload + one-writer-memcpy the raw ZC path already pays,
and **removes** the SHMEM-ring double-buffer of the full 16 KiB payload from the transport by sending a 64-octet
reference instead. The AEAD work is comparable either way (both seal/open ~16 KiB once). The literal-zero-copy
`flatdata-view` loan path is deliberately **not** available for overlay slots (a reader cannot consume ciphertext
in place) — the accepted "zero-copy → single-copy" floor for confidential SHMEM.

## The non-secured hot path is unchanged (zero-alloc)

`make gate-hotpath` is **PASS (8 files clean)**: the overlay adds no per-sample allocation to the non-secured
raw ZC path, which stays byte-identical and zero-alloc (a non-overlay reference keeps `reserved = 0`). The AEAD
seal itself is zero-cons per ADR 0038 (`encode-serialized-payload-into` = 0.0000 B/sample on SBCL).

## Honest scope (no overclaim)

- **A p50/p99 latency harness was NOT run.** There is no two-participant same-host SHMEM latency rig wired as a
  `make` target for this specific path, and standing this up was out of scope for the finishing task. The
  measurement above is the **deterministic copy / datagram / AEAD profile**, which is reproducible and is the
  correct before/after for a routing + in-slot-format change (the precedent is ADR 0038, whose `make bench` is
  `N/A` because the alloc/copy profile is the measurement).
- The numbers are **SBCL only**; on Clasp/macOS the ZC pool is not carved (the `shm_open` by-name-attach ABI
  gap, ADR 0013), so the overlay path and its measurement self-skip there exactly as the test's Part B/C/D do —
  the structural predicate (Part A) is portable and green on both impls.
- The 64-octet and 16428-octet figures are **measured** (`OVERLAY_REF_DATAGRAM_BYTES 64`,
  `SECUREDPAYLOAD_SLOT_BYTES 16428`, `OVERLAY_ZC_SENDS_ADVANCE 1`); the gated-off "≥ 16384 + framing" is the
  hard lower bound (the payload is carried in-band without ZC), not a fabricated point estimate.

Method entry: `scripts/with-sbcl.sh --load bench-overlay.lisp` (the driver reuses `%zc-change-item` /
`%msg-datagram` / `disc-node-zc-sends`, the same internals as `dds.disc:run-zc-shmem-secured-overlay-test`).
Impl: SBCL 2.6.5-85913ede1.
