# Common Lisp DDS — wiki

The API + use-case guide for **Common Lisp DDS** (the OMG DDS/RTPS/XCDR stack). Each page covers
one layer/feature area: what it's for, the public API (grounded in the source docstrings),
and worked examples (grounded in the verified test suite under `src/dds-tests/`).

> Maintained per **the operating contract §5.1**: kept in lockstep with the source on every change. If a
> page disagrees with a docstring, the docstring (and the in-repo spec it cites) wins —
> please fix the page. The project overview, scope, and status live in the top-level
> [`README.md`](../../README.md); the normative contracts are
> [`REQUIREMENTS.md`](../../REQUIREMENTS.md) and [`IMPLEMENTATION-PLAN.md`](../../IMPLEMENTATION-PLAN.md).

## Start here

- **[Getting started](getting-started.md)** — install, build, run the tests, and a
  publish/subscribe quickstart.

## By layer / feature

| Page | System(s) | What it covers |
|---|---|---|
| [Type system & code generation](type-system.md) | `dds-types`, `dds-gen` | `define-dds-type`, the `type-support` vtable, the XTypes model, assignability + `TYPE_CONSISTENCY_ENFORCEMENT`, TypeObject + EquivalenceHash, TypeInformation |
| [CDR codec, buffers & the arena](cdr-and-memory.md) | `dds-cdr`, `dds-core` | XCDR1/XCDR2 encode/decode, encapsulation headers, off-heap buffers/cursors, the static arena + pools, vendored MD5 |
| [QoS & RxO matching](qos.md) | `dds-qos` | the DDS 1.4 QoS policies, Requested/Offered compatibility, `TYPE_CONSISTENCY_ENFORCEMENT` |
| [DCPS — the DDS entity API](dcps.md) | `dds-dcps` | participants/topics/pub/sub/writers/readers, write/read/take, instances + SampleInfo, conditions/WaitSets, statuses/listeners, content-filtered topics, builtin topics |
| [RTPS engine](rtps-engine.md) | `dds-rtps` | submessage codec, the reliable + best-effort writer/reader, HistoryCache, HEARTBEAT/ACKNACK/GAP, SequenceNumberSet |
| [Discovery](discovery.md) | `dds-disc` | SPDP + SEDP over UDP, the `disc-node`, endpoint matching, the reliable data plane, `PID_TYPE_INFORMATION` |
| [Transports](transports.md) | `dds-xport`, `dds-pal` | the pluggable transport record, UDPv4, and the platform abstraction layer |
| [Interop with RTI Connext](interop.md) | `interop/connext`, `dds-shapes` | the Connext oracle/interop harness, the Shapes harness, tshark wire validation |

## Conventions used in the examples

- Package nicknames: `dds.gen`, `dds.types`, `dds.qos`, `dds.dcps`, `dds.cdr`,
  `dds.core.buffer`, `dds.core.arena`, `dds.rtps.*`, `dds.disc`, `dds.xport`, `dds.pal`.
- Load everything with `(ql:quickload :dds)` (control plane) or a specific system
  (`:dds-cdr`, `:dds-types`, …) for a narrower surface.
- Examples that talk over the network use UDP loopback on a domain id; two participants in
  one image is the normal test/demo pattern.
- Every example here is adapted from a test in `src/dds-tests/` that passes on SBCL + Clasp.

---

*This wiki is **generated** from `docs/wiki/` in the main repository and mirrored to the
GitHub Wiki by the `Publish Wiki` GitHub Action on every push. Edit the source pages under
`docs/wiki/` — changes made directly in the GitHub Wiki are overwritten on the next sync.*
