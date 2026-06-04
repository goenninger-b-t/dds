# Provenance log (clean-room discipline — REQUIREMENTS NFR-IP)

Every external source consulted and its influence is recorded here. RTI Connext
artifacts are **behavioural references via interop only** — never source,
headers, or `rtiddsgen` output.

## M0 (2026-06-04)

- **OMG specifications** (DDS 1.4, DDSI-RTPS 2.5, XTypes 1.3, CDR) — the sole
  design source. No clause values memorized into code: CDR representation IDs,
  PIDs, EntityIds, and the keyhash rule are left TBD until pinned by byte-exact
  vectors / live captures (FR-CDR-3, FR-RTPS-9).
- **No RTI Connext source/headers/generated code consulted or copied.**
- **No Fast DDS / Cyclone / OpenDDS source read** during M0.

## M1 (2026-06-04)

Normative OMG specs added to `docs/specs/` (PDF + machine-readable) and read
directly to pin wire constants — the required clean-room source (CLAUDE.md §4):

- **XTypes 1.3 §7.4.3.4 Table 39 (ENC_HEADER)** — the 11 encapsulation
  representation identifiers (PLAIN_CDR=0x0000/01, PL_CDR=0x0002/03,
  PLAIN_CDR2=0x0010/11, PL_CDR2=0x0012/13, DELIMITED_CDR=0x0014/15, XML=0x0100).
  Confirmed my prior recollection (0x0006/0x0007) was **wrong** — pinned from the
  table, not memory. → `src/dds-cdr/cdr.lisp`.
- **XTypes 1.3 §7.4.3.4.1 (DHEADER)** and **§7.4.3.4.2 (EMHEADER1/LC/NEXTINT)** —
  `EMHEADER1=(M_FLAG<<31)+(LC<<28)+(MemberId&0x0fffffff)`, LC 0–7 semantics.
  → `src/dds-cdr/primitives.lisp`.
- **RTPS 2.5 §10.2** — `SerializedPayloadHeader` = 2-octet representation_identifier
  + 2-octet representation_options (sender 0); CDR alignment origin resets after
  the header. Cross-checked §10.3 Table 10.1. → cdr.lisp + cursor origin.
- Text extracted locally with `pdftotext` (poppler); no external service used.
- Still **no RTI/Fast DDS/Cyclone/OpenDDS source** consulted.

## Third-party runtime dependencies (licenses apply; not vendored yet)

| Dependency | Use | License |
|---|---|---|
| `static-vectors` | off-heap octet buffers (NFR-MEM) | MIT |
| `cffi` | FFI (sockets/SHMEM/crypto later) | MIT |
| `bordeaux-threads` | portable threads/locks | MIT |
| Quicklisp | dependency loading (dev) | — |
| Clasp `boehmprecise` | the M0 target implementation | LGPL-2.1 (runtime) |

Pinning/vendoring of hot-path dependencies (NFR-BUILD) is a tracked M1 follow-up.
