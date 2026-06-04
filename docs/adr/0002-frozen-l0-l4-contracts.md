# ADR 0002 — Frozen L0–L4 interface contracts (M0)

- **Status:** Accepted (2026-06-04)
- **Deciders:** A0 (integrator)
- **Relates to:** IMPLEMENTATION-PLAN §3.2, §7; CLAUDE.md §3 rule 1

## Context

CLAUDE.md §3 rule 1 forbids any parallel implementation fan-out before the M0
interface contracts are frozen. This ADR is the freeze record: the exported
symbol surface below is the contract every later work package codes against.
Changes require a superseding ADR enumerating every consumer + migration.

## Decision — frozen surfaces

**`DDS.PAL`** (L0, §7.6) — capability list: `alloc-static` `free-static`
`static-pointer` `static-length` `mem-ref-u8` `mem-set-u8`; `cas` `atomic-incf`
`fence`; `spawn` `join` `make-lock` `with-lock` `make-condvar` `condvar-wait`
`condvar-signal`; `monotonic-ns`; `gc-suggest` `with-gc-inhibited`;
`with-hot-optimizations`; conditions `pal-error` `pal-unimplemented`.

**`DDS.CORE.BUFFER`** (L1, §7.1, HOT PATH) — `octet-buffer` `make-octet-buffer`
`octet-buffer-vec` `octet-buffer-capacity` `buffer-sap`; `cursor` `cursor-buffer`
`cursor-position` `cursor-endianness` `cursor-reset` `align`;
`put-u8/16/32/64` `get-u8/16/32/64` `put-octets` `get-octets`; `buffer-overflow`.
Invariant: alignment origin is buffer position 0; codec offsets for the
encapsulation header. All ops bounds-checked at the boundary.

**`DDS.CORE.ARENA`** (L1, §7.7) — `*static-arena-bytes*`; `arena` `init-arena`
`teardown-arena` `arena-initialized-p` `arena-report`; `make-buffer-pool`
`pool-acquire` `pool-release` `pool-high-water` `pool-capacity` `pool-in-use`;
`arena-exhausted`. Invariant: budget read once at `init-arena`; `pool-acquire`
→ NIL is the exhaustion signal (RESOURCE_LIMITS), never a heap fallback.

**`DDS.CDR`** (L2, §7.2, HOT PATH) — `+representation-ids+` `extensibility-kind`
`representation-id-value` `make-encapsulation-header` `parse-encapsulation-header`
`cdr-not-implemented`. Representation 16-bit values are TBD until the M1
byte-exact corpus pins them (FR-CDR-3) — deliberately not memorized.

**`DDS.TYPES`** (L3, §7.3) — `type-support` (defstruct of function slots: the
manual vtable) with accessors `serialize` `deserialize` `serialized-size`
`key-hash` `typeobject` `typeidentifier` `sample-pool-alloc` `sample-pool-free`
`flatdata-offset` `flatdata-builder` `data-representation-mask`, plus `name`
`type-name` `extensibility`; registry `register-type` `find-type-support`
`registered-type-names`.

**`DDS.RTPS.HISTORY`** (L4, §7.4, HOT PATH) — `cache-change` (slots `kind`
`writer-guid` `sn` `instance-key-hash` `serialized-payload` `source-timestamp`
`inline-qos`); `history-cache` `make-history-cache`; `hc-add-change`
`hc-remove-change` `hc-get-change` `hc-min-seq` `hc-max-seq`
`hc-changes-for-reader`.

**`DDS.XPORT`** (L7, §7.5) — `transport` (defstruct; slots `kind` `send`
`receive-loop` `open-receive-resource` `close` `max-message-size`
`locator-kind`); `send` (dispatch-free); `make-mock-transport`.

## Consequences

- M2+ writes the writer/reader state machines, codecs, and discovery against
  these symbols; the mock transport + type-support let upper layers compile now.
- Hot-path packages (`dds.core.buffer`, `dds.cdr`, `dds.rtps.history`, future
  generated codecs) are enforced CLOS-free by `scripts/gate-hotpath.sh`.
- The TBD CDR representation values are the one knowingly-unfrozen detail; they
  land with the corpus, not from memory.
