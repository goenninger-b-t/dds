# DDS-Security Live Fast-DDS Cross-Vendor Interop — Design (M7 / P6, Slice 5, Fast-DDS half)

> Status: design, owner-approved 2026-06-28. Operating-contract workflow: brainstorm (this) → plan → subagent-driven implementation → final review → finish-branch (HOLD PUSH).

**WP:** `WP-DDS-SECURITY-FASTDDS-INTEROP` · **Milestone:** M7 / P6 · **Slice:** 5 (the Fast-DDS half of the P6 EXIT GATE) · **ADR:** 0037 (written at the capstone). Live RTI Connext-Security is **deferred to Slice 5b** (the RTI Security Plugins / `libnddssecurity` are not installed).

---

## 1. Goal

Achieve **live cross-vendor DDS-Security interop against a real Fast DDS-Security peer**: two participants — one ours, one Fast DDS v3.6.x with `SECURITY=ON` — sharing the same Identity-CA / Permissions-CA / Governance, complete the **full secure-discovery path in both directions**: plain SPDP bootstrap → §8.7 PKI-DH authentication → SharedSecret → crypto-token exchange (`:keyed`) → secure-SEDP endpoint match → protected user data exchanged byte-exact. This closes the **Fast-DDS half of the P6 exit gate**. Slice 4 reached bidirectional cross-vendor SPDP discovery; Slice 5 carries it through auth → keyed → data.

## 2. Scope (owner-approved 2026-06-28)

IN — the **Fast-DDS cross-vendor reconciliation campaign**:
- The **§9.3.4 `Property` `propagate`-byte fix** (the one confirmed blocker from Slice-4 T12): our codec serializes a `propagate` field per Property that Fast DDS omits, misaligning every DataHolder/token → auth REJECTs.
- The **downstream divergences** the live peer reveals, worked in discovery order. The *candidate* backlog (ADR-0036 Slice-5 carries, each confirmed-or-dropped by the live peer — not fixed speculatively): session_id base alignment vs Fast DDS `max()`, the SIGN GMAC AAD byte-span, SIGN 4-byte alignment, secure-SEDP/PVMS reliable HEARTBEAT/ACKNACK pull, metatraffic rtps-wrapping.

OUT (deferred to Slice 5b):
- **Live RTI Connext-Security** interop (plugins gated). The gate Slice 5 closes is "Fast-DDS-validated cross-vendor secure discovery," explicitly **not** "Connext-validated."
- The non-exit-gate ADR-0036 hardening carries (zero-alloc into-buffer AEAD; per-topic `metadata_protection` on user endpoints; `pvms-bootstrap-kms` pruning; the Slice-1 serialized-payload AAD divergence; ZC×rtps SHMEM cleartext) — unless the live peer forces one.

## 3. Non-negotiable constraints (operating contract)

- **Conformance is non-negotiable.** Every fix takes the OMG-spec-conformant path. Where Fast DDS genuinely diverges from the spec on a wire format that cannot be shimmed (endianness, field presence), match the peer **with decode-tolerance** where feasible (accept both forms so a spec-literal peer is never false-REJECTed); a **false REJECT is the worst defect class**.
- **Clean-room:** Fast DDS (Apache) + Cyclone (EPL) are readable for understanding, provenance-logged; **never read RTI Connext source**. Pin the OMG clause where obtainable; never assert a wire form from memory.
- **The our-to-our-green invariant:** every wire change MUST keep the our-to-our suite green on both impls (377/377 + corpus byte-exact + fuzz + gate-hotpath + gate-types + mem). The byte-exact corpus is regenerated with each conformant wire change; a change that cannot keep our-to-our byte-exact is a signal to stop and rethink, not to weaken a test.
- **Clasp AND SBCL both validate, Clasp first.**
- `defun*`/`defstruct*` + full `ftype` on every function; one-line comments; no reader conditionals outside `dds-pal/`.
- Docs in lockstep (ADR 0037 + wiki + README + verification.csv at the capstone); SBOM auto-regenerated; no AI-assistant attribution (cite "the operating contract §N").
- **HOLD PUSH:** within-WP commits autonomous; the squash-merge to `main` is presented for owner approval; push only on explicit "push".

## 4. Architecture — the reconciliation campaign

Slice 5 is a **campaign**, not a feature build: the deliverable is behavioral (the live path completes) and the work is **discovery-driven** (T12 confirmed only the `propagate` blocker; the rest are candidates the live peer confirms in an order we cannot fully predict — each fix unblocks the next).

- **T0 — spike / setup.** Rebuild/confirm the Fast DDS-Security peer (the T12 recipe in `interop/security-secure-discovery/`), re-establish the live harness + capture (tcpdump — tshark cannot dissect macOS `lo0`), and **pin the `propagate`-byte resolution**: the OMG §7.2.x / §9.3.4 clause if obtainable, corroborated against Fast DDS **and** Cyclone source; decide the **emit** form (spec-conformant) and whether genuine **decode-tolerance** is implementable (a trailing 4-byte field is not self-describing — if not cleanly tolerable, match the conformant form and verify Connext at 5b). Provenance-logged.
- **T1 — the propagate-byte fix (the one fully-specifiable task; slice-wide).** Per the §9.3.4 serialization pinned in T0 (almost certainly `name`+`value` only, `propagate` as a local include/exclude filter), fix the Property/DataHolder codec across `src/dds-security/auth/wire.lisp` + `identity.lisp` + `handshake.lisp` + the keyexchange crypto-tokens, **regenerate the entire token byte-corpus**, update ADR 0033's note. Decode parses the conformant form (+ decode-tolerance if T0 found it feasible). Our-to-our stays green.
- **T2…Tn — the discovery loop.** Repeat: run the live peer → diagnose the next REJECT/mismatch (capture + logs) → fix it conformant (corroborate spec + Fast DDS + Cyclone; shim-on-top only for a genuine vendor-vs-spec divergence) → regenerate any affected corpus → confirm our-to-our green → re-run. Each iteration is its own task + 2-stage review. The candidate backlog (§2) is the *likely* sequence; the live peer is the authority on which are real.
- **Capstone.** ADR 0037 (the campaign result: which divergences were real + how fixed; the green both-directions cross-vendor run; the residual; the Connext-5b deferral), wiki/README/verification.csv, the recorded captures, the final dual-impl gate sweep.

Each task ends with: our-to-our green (both impls) + the cross-vendor path advanced one stage (or the divergence documented as carried).

## 5. The `propagate`-byte fix (T1 detail)

§9.3.4 `Property` = `{name, value, propagate}`. T12 found our wire emits a 4-octet `propagate` field per Property; Fast DDS (and, by the T-RECONCILE pattern, Cyclone) serialize **`name`+`value` only** and use `propagate` as a local include/exclude filter. The conformant fix: serialize each propagated Property as `name`+`value` (omit `propagate=false` Properties entirely; do not emit the flag). This is load-bearing for every DataHolder (IdentityToken, the §8.7 handshake tokens, the §9.5 crypto tokens), so the corpus regen is wide. T0 pins the exact form + the decode posture before any code changes.

## 6. Verification & DoD

- **Headline (behavioral):** ours↔Fast DDS completes SPDP → §8.7 auth → SharedSecret → crypto-token exchange (`:keyed`) → secure-SEDP match → protected user data **byte-exact, both directions**, captured (tcpdump; tshark where it dissects) under `interop/security-secure-discovery/`.
- **Invariant:** the our-to-our suite green on both impls after every change (377/377 + corpus + fuzz + gate-hotpath + gate-types + mem).
- **Per-fix:** corroborated (spec + Fast DDS + Cyclone), conformant, no false-REJECT.
- **Honesty:** ADR 0037 + README + verification.csv state "Fast-DDS-validated cross-vendor secure discovery" — **not** "Connext-validated" (Slice 5b). No overclaim. Any intractable divergence is documented + carried, never faked.

## 7. Risks

- **Open-ended depth:** the discovery loop may surface divergences beyond the candidate backlog; each is handled in turn or carried. The campaign ends at "full path both directions" or a documented residual.
- **Fast-DDS-specific vs spec divergences:** some fixes may be Fast-DDS-shaped and need re-verification against Connext at 5b (noted per fix).
- **Environment:** the Fast DDS-Security build must succeed (T12 built v3.6.1 SECURITY=ON; rebuilds per the recorded recipe). If it regresses, T0 reports it.

## 8. ADR

ADR 0037 (`docs/adr/0037-dds-security-fastdds-interop.md`) at the capstone: the campaign result, the per-divergence conformant resolutions, the green cross-vendor run, the Connext-5b deferral, and any residual carries.
