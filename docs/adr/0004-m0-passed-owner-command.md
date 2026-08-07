# ADR 0004 — M0 marked PASSED with AllegroCL exception (owner command)

- **Status:** Accepted (2026-06-04)
- **Decision authority:** **DG1SBG (owner), by explicit command.** Recorded by A0.
- **Updates:** ADR 0001, ADR 0003 (closes the M0 milestone they tracked toward)

## Context

The IMPLEMENTATION-PLAN §4 M0 exit gate reads "every ASDF system loads on all
three impls." Two of the three landed and are green (Clasp 2.7.0 boehmprecise,
SBCL 2.6.5); AllegroCL 11.0 (`alisp8`, on the NAS) is not yet wired.

## Decision

**M0 is marked PASSED, with a documented exception for AllegroCL.** This is **not
an A0 judgement** — the owner (DG1SBG) **explicitly commanded** that M0 be
considered passed with the AllegroCL carve-out on 2026-06-04. The owner is the
scope authority (REQUIREMENTS §0, §8) and is exercising that authority here to
override the three-impl exit gate to a **two-of-three** pass.

## What actually passed (evidence)

On Clasp + SBCL, via `make`:

| Gate | Clasp | SBCL |
|---|---|---|
| `build` (umbrella `dds` loads) | exit 0 | exit 0 |
| `test` (echo-over-mock-transport) | 1 passed | 1 passed |
| `gate-hotpath` | clean (impl-independent) | — |

Plus: frozen L0–L4 contracts (ADR 0002); real static-arena + off-heap
bounds-checked buffer/cursor; reader conditionals confined to `src/dds-pal/`.

## Exception & its closure

- **AllegroCL is deferred, not waived.** Wiring `pal-allegro.lisp` (`alisp8`) +
  `scripts/with-allegro.sh` remains a tracked follow-up. When it lands and goes
  green, M0's three-impl gate is retroactively fully satisfied; no re-decision is
  needed — this ADR pre-authorizes that closure.
- The DDS.PAL contract is unchanged, so adding Allegro is additive (ADR 0003).

## Consequences

- **M1 (P0 XCDR byte-exact + real PALs) starts now** per the owner's "proceed"
  command. M0→M1 gate is satisfied under this ADR.
- Any program-level "Connext-class (core)" acceptance (REQUIREMENTS §9) still
  requires SBCL **and** AllegroCL; this exception is scoped to the **M0
  milestone gate only**, not to final acceptance.

---

## Addendum, 2026-08-07 — AllegroCL is LIVE, and the port has started (4 of 40)

The tracked follow-up above is no longer blocked on availability. Owner, 2026-08-07: *"AllegroCL is live on
192.168.2.180 and also on 192.168.2.113."* Verified: **International Allegro CL Enterprise Edition 11.0,
64-bit Linux (x86-64) SMP**, at `/opt/common-lisp/allegrocl/11.0/alisp` on both hosts.

⚠️ It is **not on `PATH` for a non-login ssh shell** — a bare `ssh host 'alisp …'` answers
`command not found`, which reads like a missing installation. `ssh host 'bash -lc "alisp -q -batch -L …"'`
is the working form. Worth stating because the wrong conclusion here is "Allegro is not installed", and that
conclusion would re-defer this ADR indefinitely.

**What has landed:** `src/dds-pal/pal-allegro.lisp`, wired into `dds-pal.asd` as
`(:file "pal-allegro" :if-feature :allegro)`, implementing the four IEEE 754 conversions required by
ADR 0111 slice 1. They were **verified on the real implementation** against the identical byte-exact vectors
the SBCL arm asserts — including negative zero, denormals and the extremes — and agree bit-for-bit with the
SBCL and Clasp backends.

**What has not:** `:dds-pal` still does not load on AllegroCL. The contract exports **118** symbols; 66 are
implementation-independent (`pal-contract`, `pal-net`) and **40 are per-implementation**, so **36 remain**:
static memory (`alloc-static`, `free-static`, `static-pointer`, `static-length`, `static-sap+`,
`static-vector-p`), foreign SAP access (`load/store-sap-*`, `mem-ref/set-u8`), atomics and fences (`cas`,
`atomic-incf`, `cas-sap-u32/u64`, `atomic-incf-sap-u64`, `fence`), threads and locks (`make-lock`,
`with-lock`, `make-condvar`, `condvar-wait/signal/broadcast`, `join`), and platform miscellany
(`bytes-consed`, `gc-suggest`, `with-gc-inhibited`, `pal-impl-name`, `fsync-stream`, `fsync-directory`,
`install-signal-handler`, `register-image-restart-hook`, `internal-bug-p`).

That list is **bounded and enumerated, not open-ended** — Allegro has native answers for all of them
(`mp:`, `excl:`, `ff:`), and both `bordeaux-threads` and `cffi` ship Allegro backends the Clasp PAL already
routes through. It is a slice, not a milestone.

⛔ **Until it closes, the Definition of Done's "SBCL and AllegroCL" is met on SBCL + Clasp only**, and every
"done" recorded in this repository should be read that way. This addendum exists so that reading is
available at the ADR that granted the exception, rather than inferred from an absent build.

One portability fact found while probing, recorded because it can silently mis-size code:
**`most-positive-fixnum` is 2^60−1 on Allegro** — narrower than SBCL's 2^62−1 — so any bit-packing sized
against SBCL's fixnum can become a bignum there. (ADR 0108's drain window is unaffected: it stores raw
`(unsigned-byte 64)` words in a vector rather than packing into a fixnum.)
