# ADR 0094 — DDS-RPC is out of scope for this release

- **Status:** **Accepted** — owner directive, 2026-07-28.
- **Date:** 2026-07-28
- **Requirements changed:** **FR-API-3** is demoted from **MUST** to **out of scope for this release**
  (deferred, not withdrawn). `[DDS-RPC] 1.0` stays in the normative-reference table as a *deferred* spec.
- **Relates to:** the P0–P7 conformance profiles (FR-API-3 sat outside them, which is part of why this is a
  clean cut); ADR 0021 (the durability service — the other scope call, decided the other way)

---

## 1. The decision

> **Owner, 2026-07-28:** *"Mark the DDS-RPC requirement as out-of-scope of this current NeoDDS release —
> The MVP doesn't need to contain this."*

Request/Reply and RPC over DDS ([DDS-RPC] 1.0) will **not** ship in this release. The requirement is
**deferred, not withdrawn**: the spec reference stays, and nothing in the architecture may preclude adding
it later (§4).

## 2. Why this is a clean cut

**DDS-RPC is a layer strictly above DCPS.** It is built from ordinary DataWriters, DataReaders and
correlated request/reply topics — it needs no wire-format change, no new RTPS submessage, no discovery
change, and no QoS the stack does not already have. Nothing below L9 depends on it, and no P0–P7
conformance profile contains it.

That is precisely what makes it deferrable without cost: an MVP that omits it is not a partial DDS, it is a
DDS without one optional layered pattern. The same is not true of, say, XTypes or the durability service —
which is why ADR 0021 decided the opposite way for the latter.

## 3. What this does NOT mean

- **It is not a statement that RPC is unimportant**, and it does not remove `[DDS-RPC]` from the normative
  references. A later release may take it up under this ADR's successor.
- **It does not touch the TypeLookup service**, whose builtin endpoints are request/reply *shaped* (XTypes
  1.3 Table 61) but are a discovery mechanism, not DDS-RPC. FR-TYPE-3 is unaffected.
- **It does not touch the Connext RPC interop item** on the work list other than to remove it from this
  release's plan — sourcing the spec (it is still not in `docs/specs/`) is now a prerequisite of whenever
  it is taken up, not of now.

## 4. The constraint that remains

**The architecture must not preclude it.** Concretely, that costs nothing today and is worth stating so a
future reader does not have to re-derive it: DDS-RPC needs correlated request/reply over ordinary
endpoints, which requires `SampleIdentity`-style correlation carried in inline QoS or the sample itself,
and a service-side dispatch over a topic pair. The stack already has everything that needs: user-defined
topics, reliable endpoints, inline QoS, `PID_ORIGINAL_WRITER_INFO`-style parameter plumbing, and a
generated type system. No current design decision blocks it.

## 5. Consumers of the change

- `REQUIREMENTS.md` — FR-API-3 demoted; the `[DDS-RPC]` normative-reference row annotated as deferred.
- `IMPLEMENTATION-PLAN.md` — the L9 layer description, the planned `dds-rpc/` module, and the
  WP-API/RPC/SPY/DOCS work-package acceptance line.
- `README.md` — the scope section and the L9 architecture line.

No source changes: none of this was implemented, which is the other reason the cut is clean.
