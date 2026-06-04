# Glossary

Authoritative abbreviations live in `REQUIREMENTS.md` §3. This file expands them
as the implementation introduces concrete artifacts.

- **PAL** — Platform Abstraction Layer (this project's L0); package `DDS.PAL`.
- **Arena** — static, startup-allocated, non-GC'd off-heap region sized by
  `*static-arena-bytes*`; all hot-path memory is carved from it.
- **type-support** — generated per-type function bundle (the manual vtable); a
  `defstruct` of function objects the engine funcalls per sample.
- **CacheChange** — pooled per-sample record in a HistoryCache.
- **XCDR1/XCDR2** — Extended CDR encoding versions; XCDR2 caps alignment at 4.
- **DHEADER / EMHEADER** — XCDR2 delimiter / member headers (appendable/mutable).
- **RxO** — Requested-offered QoS compatibility matching.
- **SPDP / SEDP** — Simple Participant / Endpoint Discovery Protocol.

Full DDS/RTPS term set: see the OMG specs and `REQUIREMENTS.md` §3.
