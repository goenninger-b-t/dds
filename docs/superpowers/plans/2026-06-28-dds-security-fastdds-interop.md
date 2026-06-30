# DDS-Security Live Fast-DDS Cross-Vendor Interop — Implementation Plan (M7 / P6, Slice 5)

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development. Steps use checkbox (`- [ ]`) syntax. This is a **reconciliation campaign**: T0–T1 are fully specified; T2+ are corroborated-conditional divergence tasks driven by the live Fast DDS peer (fix → re-run → next), each ending with our-to-our green + the cross-vendor path advanced.

**Goal:** Make a real Fast DDS-Security peer and ours complete the full secure-discovery path both directions (SPDP → §8.7 auth → SharedSecret → crypto-token `:keyed` → secure-SEDP match → protected user data byte-exact) — the Fast-DDS half of the P6 exit gate.

**Architecture:** Spike + the one confirmed blocker fix (the §9.3.4 `propagate` byte) + a corroborated discovery loop over the ADR-0036 candidate divergences (each confirmed-or-dropped by the live peer), holding the our-to-our suite green on both impls throughout. Live Connext deferred to Slice 5b (RTI plugins gated).

**Tech Stack:** Common Lisp (SBCL + Clasp); the Slice-4 secure-discovery stack; the live Fast DDS v3.6.x SECURITY=ON peer + the harness in `interop/security-secure-discovery/`; tcpdump (tshark can't dissect macOS `lo0`); Fast DDS (Apache) + Cyclone (EPL) source for clean-room corroboration.

**Spec:** `docs/superpowers/specs/2026-06-28-dds-security-fastdds-interop-design.md` (read it).

## Global Constraints

- **Conformance non-negotiable; a false REJECT is the worst defect class.** Every fix takes the OMG-spec path; where Fast DDS genuinely diverges from the spec on an unshimmable wire format, match the peer **with decode-tolerance where feasible** (accept both forms).
- **Clean-room:** Fast DDS (Apache) + Cyclone (EPL) readable, provenance-logged in `docs/provenance.md`; **NEVER read RTI Connext source**. Pin the OMG clause where obtainable; never assert a wire form from memory.
- **OUR-TO-OUR-GREEN INVARIANT:** after every wire change, the our-to-our suite is green on BOTH impls — `make test-clasp` + `make test-sbcl` (377 baseline) + corpus byte-exact + `make fuzz` + `make gate-hotpath` + `make gate-types` + `make mem`. The byte-exact corpus is REGENERATED with each conformant wire change; never weaken a test to pass. A change that can't keep our-to-our byte-exact = stop and rethink.
- **Clasp AND SBCL both validate, Clasp first** (`scripts/with-clasp.sh` / `make *-clasp`). Known pre-existing flakes (VOLATILE-LATEJOINER-ZERO, keyed-flatdata-copy-behavior, no-double-delivery, durability-latejoiner) — re-run, don't chase (NFR-PORT).
- `defun*`/`defstruct*` + full `ftype` on every function; one-line comments; no reader conditionals outside `dds-pal/`; no AI/"Claude" attribution (cite "the operating contract §N"); SBOM auto (never hand-edit).
- **Live Connext is OUT (Slice 5b)** — the gate this closes is "Fast-DDS-validated," not "Connext-validated." No overclaim anywhere.
- **HOLD PUSH:** within-WP commits autonomous; the squash-merge to `main` is presented for owner approval; push only on explicit "push".

## File structure (the likely-touched set; the live peer confirms)

| File | Responsibility | Tasks |
|---|---|---|
| `interop/security-secure-discovery/` (harness) | Fast DDS-Security peer build/run + captures + the cross-vendor run scripts | T0, every T (re-run), T7 |
| `docs/superpowers/spikes/2026-06-28-dds-security-fastdds-interop.md` (new) | T0 findings: the peer build, the pinned propagate resolution, the live-baseline | T0 |
| `src/dds-security/auth/wire.lisp` | the §9.3.4 DataHolder / PropertySeq codec (the propagate byte) | T1 |
| `src/dds-security/auth/identity.lisp` | the IdentityToken Property serialization | T1 |
| `src/dds-security/auth/handshake.lisp` | the handshake-token Properties | T1 |
| `src/dds-security/auth/keyexchange.lisp` | the crypto-token DataHolder Properties | T1 |
| `src/dds-tests/security-auth-test.lisp` | the token byte-corpus (the hard-coded propagate bytes) | T1, T2+ |
| `src/dds-disc/volatile-secure.lisp` | `%pvms-role-session-id` (session_id base) | T2 (if confirmed) |
| `src/dds-security/crypto/submessage.lisp` | SIGN AAD span / 4-alignment | T3/T4 (if confirmed) |
| `src/dds-disc/secure-sedp.lisp` / `volatile-secure.lisp` | reliable HEARTBEAT/ACKNACK pull | T5 (if confirmed) |
| `src/dds-disc/dataplane.lisp` / `disc.lisp` | metatraffic rtps-wrapping | T6 (if confirmed) |
| `docs/adr/0037-dds-security-fastdds-interop.md` (new) + wiki/README/verification.csv | capstone | T7 |

---

### Task T0: Spike — Fast DDS-Security peer + live baseline + pin the propagate-byte

**Files:** the harness `interop/security-secure-discovery/`; the spike doc (new); `docs/provenance.md`.

**Produces:** a runnable Fast DDS-Security peer + a reproducible live cross-vendor run command; the pinned `propagate`-byte resolution (the conformant emit form + the decode posture) for T1; a recorded live baseline (the current failure point = the IdentityToken propagate misalignment).

- [ ] **Step 1: Rebuild/confirm the Fast DDS-Security peer.** Per the T12 recipe (in the existing spike `docs/superpowers/spikes/2026-06-27-dds-security-secure-discovery.md` + `interop/security-secure-discovery/fastdds/`), build/confirm Fast DDS v3.6.x with `-DSECURITY=ON`. Confirm the peer runs against our PKI (`interop/security-secure-discovery/pki/` + the `fastdds/` profile + S/MIME fixtures). If the build regressed, document the exact failure + fix the recipe.
- [ ] **Step 2: Reproduce the live baseline.** Run ours↔Fast DDS (the `run-fastdds-interop.sh` harness), capture with tcpdump, and confirm the current state: bidirectional SPDP discovery works; the §8.7 auth handshake REJECTs at the remote IdentityToken. Record the capture + the reject logs under `interop/security-secure-discovery/captures/`.
- [ ] **Step 3: Pin the `propagate`-byte resolution (clean-room).** Determine the conformant §9.3.4 `Property` serialization: read the OMG DDS-Security 1.1 clause (§7.2.x `Property_t` + the DataHolder/PropertySeq CDR) if obtainable; corroborate against Fast DDS (`include/fastdds/.../Property.hpp` + the CDR (de)serializer — the propagate flag is a local member, NOT serialized) AND Cyclone. Decide: (a) the EMIT form (almost certainly `name`+`value` only, with `propagate=false` Properties omitted from the seq), and (b) whether genuine DECODE-TOLERANCE is implementable (a trailing 4-byte field is not self-describing — if not, match the conformant form + flag "verify Connext at 5b"). Log every source in `docs/provenance.md`. NEVER read RTI source.
- [ ] **Step 4: Write the spike doc + commit.** `docs/superpowers/spikes/2026-06-28-dds-security-fastdds-interop.md`: the peer build result, the live baseline, the pinned propagate resolution + cites, the decode posture.
```
git add interop/security-secure-discovery/ docs/superpowers/spikes/2026-06-28-dds-security-fastdds-interop.md docs/provenance.md
git commit -m "spike(security): WP-DDS-SECURITY-FASTDDS-INTEROP T0 — Fast DDS-Security peer + live baseline (auth REJECT at IdentityToken propagate) + pin the §9.3.4 Property serialization (Fast-DDS/Cyclone-corroborated) (M7/P6 Slice 5)"
```

---

### Task T1: The §9.3.4 `Property` propagate-byte fix (slice-wide; the one confirmed blocker)

**Files:** `src/dds-security/auth/wire.lisp` (the DataHolder/PropertySeq codec), `identity.lisp`, `handshake.lisp`, `keyexchange.lisp`; `src/dds-tests/security-auth-test.lisp` (the token corpus).

**Interfaces — Consumes:** the T0-pinned emit form + decode posture. **Produces:** Property serialization that matches Fast DDS (and the spec) — no `propagate` byte on the wire — so cross-vendor auth advances past the IdentityToken.

- [ ] **Step 1: Update the corpus vectors to the conformant form (RED first).** In `security-auth-test.lisp`, change the hard-coded DataHolder/token byte vectors to the T0-pinned form (drop the `1 0 0 0 ; propagate+pad` per Property; `name`+`value` only). Run the byte-exact corpus test — it FAILS (the codec still emits the propagate byte).
- [ ] **Step 2: Fix the Property codec.** In `wire.lisp` (the `Property` serialize/parse inside the PropertySeq), stop emitting the `propagate` field; serialize `name`+`value` only, omitting `propagate=false` Properties from the seq. Update `identity.lisp` / `handshake.lisp` / `keyexchange.lisp` if they hand-roll any Property bytes. Decode parses `name`+`value` only (+ decode-tolerance if T0 found it feasible). Keep every parser bounds-checked + fail-closed.
- [ ] **Step 3: Run to GREEN our-to-our (both impls).** `make test-clasp` then `make test-sbcl` — the regenerated corpus + the round-trip + the existing auth/keyx e2es all pass (377). The our-to-our handshake/keyx still reach SharedSecret/`:keyed` (both ends use the new form). Fuzz the changed parsers.
- [ ] **Step 4: Re-run the live peer.** Run ours↔Fast DDS; confirm the auth handshake now advances PAST the IdentityToken (the propagate misalignment is gone). Capture the new failure point (the next divergence, if any) for T2. Record the capture.
- [ ] **Step 5: Commit.**
```
git commit -am "fix(security): WP-DDS-SECURITY-FASTDDS-INTEROP T1 — §9.3.4 Property serialization conformant (drop the propagate byte; name+value only; corpus regen, our-to-our green) -> cross-vendor auth advances past IdentityToken (M7/P6 Slice 5)"
```

---

### Tasks T2–T6: The discovery loop (corroborated-conditional divergence fixes)

> Each Tk: run the live peer → if it reveals the divergence below, fix it conformant (corroborate spec + Fast DDS + Cyclone, log provenance) → regenerate any affected corpus → confirm our-to-our green both impls → re-run the live peer → commit. **If the live peer does NOT exhibit the candidate divergence, document that in the report and skip the fix (no speculative change).** If the peer reveals a divergence NOT in this list, handle it as an inserted task with the same loop. The order below is the *likely* sequence (each fix may unblock the next); the live peer is the authority.

Per-task contract (all of T2–T6): **Files** = the likely file from the structure table + the corpus; **Step 1** run the live peer + diagnose (capture + logs); **Step 2** corroborate the conformant form (spec + Fast DDS + Cyclone, provenance); **Step 3** fix conformant (decode-tolerance where feasible; shim-on-top only for a genuine vendor-vs-spec divergence, never replacing); **Step 4** regenerate affected corpus + `make test-clasp`/`make test-sbcl` green (377) + fuzz the changed parser; **Step 5** re-run the live peer (path advanced) + commit `fix(security): WP-DDS-SECURITY-FASTDDS-INTEROP T<k> — <divergence> reconciled conformant vs Fast DDS; our-to-our green (M7/P6 Slice 5)`.

- [ ] **Task T2 — session_id base alignment** (`src/dds-disc/volatile-secure.lisp` `%pvms-role-session-id`). Candidate: our per-role PVMS `session_id` base (`#x80000000 | fold(winner)`) is our-implementation-choice; cross-vendor NO-REUSE + decode needs it to match Fast DDS's exact rule (`register_matched_remote_participant` `session_id = max(...) else -1`). Corroborate the exact operand; align our base so A(ours)↔B(Fast DDS) never share a (key, nonce) and each decodes the other's session_id. Decode already reads session_id from the wire, so functional decode may already work — the risk is nonce-reuse safety; verify.

- [ ] **Task T3 — SIGN GMAC AAD byte-span** (`src/dds-security/crypto/submessage.lisp`). Candidate: our SIGN AAD = the full original submessage; Fast DDS's auth-only AAD span may differ (`body_state`/`body_length`). Corroborate Fast DDS's exact AAD bytes for `encode_datawriter_submessage` SIGN; align ours so the GMAC verifies cross-vendor. (Only reached if the peer uses a SIGN tier; default Connext/Fast-DDS governance is often ENCRYPT — may not be exercised; document if so.)

- [ ] **Task T4 — SIGN 4-byte alignment** (`src/dds-security/crypto/submessage.lisp`). Candidate: Fast DDS re-aligns the SIGN body to 4; we write the original submessage verbatim. Corroborate; align if the peer requires it. (Same SIGN-tier caveat as T3.)

- [ ] **Task T5 — secure-SEDP / PVMS reliable HEARTBEAT/ACKNACK pull** (`src/dds-disc/secure-sedp.lisp`, `volatile-secure.lisp`). Candidate: our secure SEDP uses push+dedup (no receiver-side reliable pull); a reliable Fast DDS peer may need HEARTBEAT/ACKNACK to deliver the protected DiscoveredWriter/ReaderData. Corroborate Fast DDS's reliability expectation on the secure builtin endpoints; add the pull if the peer gaps without it (reuse the existing reliable engine).

- [ ] **Task T6 — metatraffic rtps-wrapping** (`src/dds-disc/dataplane.lisp`, `disc.lisp`). Candidate: we send secure-SEDP/PVMS metatraffic PLAIN; a strict Fast DDS `rtps_protection` peer may REJECT plain metatraffic from a keyed participant. Corroborate Fast DDS's behavior; if it rejects, wrap the metatraffic via the T4-Slice-4 `encode-rtps-message` (the ParticipantCrypto) — note PVMS stays exempt (bootstrap). (Only reached if the test governance sets `rtps_protection ≠ NONE`; the headline run may use `discovery_protection` only — pick the governance that exercises the full path.)

---

### Task T7: Capstone — ADR 0037, docs, the green cross-vendor run, final gate sweep

**Files:** `docs/adr/0037-dds-security-fastdds-interop.md` (new); `docs/wiki/security.md`; `README.md`; `docs/verification.csv`; `interop/security-secure-discovery/README.md`; `docs/provenance.md`.

- [ ] **Step 1: ADR 0037.** The campaign result: which candidate divergences were REAL vs not-exhibited; the conformant resolution of each (+ any decode-tolerance / shim-on-top); the green both-directions cross-vendor run (SPDP→auth→keyed→secure-SEDP→protected-data); the residual carries; the **Connext-5b deferral** (the gate closed is Fast-DDS-validated, NOT Connext-validated). Honest — no overclaim.
- [ ] **Step 2: Docs.** wiki §6sexto cross-vendor result; README P6 row (Slice 5 = Fast-DDS cross-vendor secure discovery achieved, live Connext = 5b); verification.csv P6-SEC-FASTDDS-INTEROP rows (the live run + each reconciled divergence); the interop README (the reproducible run + captures); provenance final.
- [ ] **Step 3: Final gate sweep (both impls, Clasp first).** `make build && make test-clasp && make test-sbcl && make corpus && make fuzz && make gate-hotpath && make gate-types && make bench && make mem` — all green; report counts. The live cross-vendor run recorded (captures committed).
- [ ] **Step 4: Commit.**
```
git commit -m "docs(security): WP-DDS-SECURITY-FASTDDS-INTEROP T7 — ADR 0037 + wiki/README/verification/provenance; the green live Fast DDS cross-vendor secure-discovery run recorded; final dual-impl gate sweep; Connext deferred to 5b (M7/P6 Slice 5 capstone)"
```

---

## Plan self-review

**Spec coverage:** §2 IN — the propagate-byte fix (T1), the candidate downstream divergences (T2–T6, corroborated-conditional), the live both-directions run (every Tk re-run + T7). §2 OUT — live Connext (5b, stated in T7 + Global Constraints); the non-exit-gate hardening carries (not pulled in unless the peer forces). §4 campaign structure = T0 spike + T1 + the T2–T6 loop + T7. §5 propagate detail = T1. §6 DoD = T7 + the per-task our-to-our-green + the live re-runs. All covered.

**Placeholder scan:** the T2–T6 tasks are intentionally corroborated-conditional (the spec mandates discovery-driven, not speculative) — each carries its concrete candidate, file, conformant approach, corroboration requirement, our-to-our-green check, and live re-run. This is the correct shape for a reconciliation campaign, not a placeholder. T0/T1 are fully concrete. ADR-at-capstone is the standard pattern.

**Type consistency:** the touched symbols (`%pvms-role-session-id`, `encode_datawriter_submessage` SIGN path, `encode-rtps-message`, the §9.3.4 Property codec) are the actual Slice-4 symbols; the corpus lives in `security-auth-test.lisp`. Consistent.

**Note for execution:** T2–T6 are diagnosis-then-fix tasks — the implementer runs the live peer first and only fixes a divergence the peer actually exhibits (documenting any candidate it does not). New divergences the peer reveals become inserted tasks with the same loop. The our-to-our-green invariant + clean-room corroboration bind every task.
