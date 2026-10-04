# ADR 0126 — The M0→M8 sequence was not followed; M2–M7 re-verification may run in parallel with M1

- **Status:** **Accepted** (2026-10-04). ADR 0124 §2 records the decision (owner decision **D9**,
  "approve"); this ADR records the deviation (§2) and bounds the exception that decision grants (§3.2). The
  deviation is a statement of fact from the repository history, not a decision.
- **Date:** 2026-10-04
- **Requirement:** the operating contract §3.4 ("one milestone at a time … do not begin a milestone until the
  prior milestone's exit gate passes") and §11 (the M0→M8 sequence); IMPLEMENTATION-PLAN §4 ("each milestone
  has a hard, demonstrable exit gate"); REQUIREMENTS §9 (program acceptance)
- **Work package:** WP-0.3(c) of `docs/plans/2026-10-03-sbcl-allegro-full-ok.md` (the governing plan); it
  enables plan Phase 5
- **Relates to:** ADR 0004 (M0 passed by owner command), ADR 0118 (Clasp withdrawn; M0 must be re-passed on
  SBCL and AllegroCL), ADR 0124 (owner decisions D1–D34; D9 here), ADR 0120 (transitional DoD), ADR 0127
  (exit-gate wording)

---

## 1. The rule

The operating contract says, in §3.4: "Follow the M0→M8 sequence. Do not begin a milestone until the prior
milestone's exit gate passes. Do not pull P4 performance work forward over P0–P2 correctness." Its §11 repeats
the sequence and ends "Start at M0. Do not jump ahead." IMPLEMENTATION-PLAN §4 gives each milestone a hard
exit gate.

## 2. What happened (from the repository history)

Every date below is the commit date of the first commit whose subject names that milestone or opens its
subsystem (`git log --reverse --date=short`):

| Milestone | Work began | First commit | Exit gate passed at the time? |
|---|---|---|---|
| M0 | 2026-06-04 | `25e4a00` "M0 foundation + M1 P0 XCDR codec (Clasp + SBCL)" | Declared PASSED the same day **by owner command** with an AllegroCL exception (ADR 0004). ADR 0118 later withdrew Clasp, so that pass covers SBCL only and M0 must be re-passed on SBCL and AllegroCL |
| M1 | 2026-06-04 | the same commit `25e4a00` | **No.** The deleted `docs/MILESTONES.md` (removed in `2160f22`, 2026-08-14) carried M1 as "IN PROGRESS" throughout, with the RTI byte-exact vectors as its open dependency |
| M2 | 2026-06-04 | `ca6f52d` "M2 increment 1 — RTPS Header/Submessage/EntityId codec" | M1 had not passed |
| M3 | 2026-06-05 | `b1e86a0` "M3 start — QoS policy model + RxO matching truth table" | M1, M2 had not passed |
| M4 | 2026-06-06 | `56a24a3` "M4 (first) — vendored MD5 … for XTypes hashing" | M1–M3 had not passed |
| M5 | 2026-06-13 | `8ce933b` "perftest/allocation harness opens M5/P4" | M1–M4 had not passed |
| M6 | 2026-06-18 | `5d2a375` "TRANSIENT_LOCAL durability + late-joiner … (M6/P5)" | M1–M5 had not passed |
| M7 | 2026-06-23 | `a364d11` "M7/P6 Slice 1: Cryptographic builtin plugin" | M1–M6 had not passed |

AllegroCL, a co-equal target (NFR-PORT), did not run at all until its PAL landed (ADR 0113, 2026-08-07) and
its build targets and launcher arrived (`b68a235`, 2026-08-14). Every exit gate from M0 on names AllegroCL.

The governing plan's evidence review (plan §1, "Milestones") rates the state on 2026-10-03 as: M0 passed by
owner command only; **M1 and M5 NOT MET; M2, M3, M4 and M6 PARTIAL; M7 claimed MET, but 0 of 22 logs are
committed.** No ADR recorded the departure from the sequence when it happened. The plan (§0 item 3) calls this
out: running M2–M7 work in parallel needs an owner-approved record, and the audit found the sequence broken
without one.

The departure was not idle: the parallel streams produced most of what exists, including live Connext
interop. It did produce what the rule is there to prevent. Work on M2–M7 rested on an M1 whose exit gate
(RTI byte-exact vectors in both endiannesses, a fuzzer clean for N hours, lossless round-trips on SBCL **and**
AllegroCL) was never shown to hold, so every later milestone inherits an unproven base. That is why plan
Phase 5 re-verifies M2–M7 rather than accepting their earlier claims.

## 3. Decision

### 3.1 The past deviation is recorded, not ratified

- Recording the deviation does **not** pass any milestone. As of this ADR, M0 is to be re-passed on SBCL and
  AllegroCL (ADR 0118 §3), and **no milestone M1–M7 counts as passed**. Each earlier "MET", "achieved" or
  "complete" in an ADR, a bench report, `README.md` or the deleted `MILESTONES.md` is a claim to re-verify
  against the exit gate as worded by ADR 0118 and ADR 0127, on both Lisps. Historical documents are not
  edited (governing plan §2); this ADR carries the correction.
- Code that landed out of sequence stays. Removing working code to restore an order would be rework with no
  gain in evidence.

### 3.2 D9: M2–M7 re-verification may run in parallel with M1 completion

Owner decision D9 (2026-10-04) approves, as the recorded exception to operating contract §3.4, that the
governing plan's **Phase 5 work for M2–M7** (re-verifying each exit gate and closing its gaps) runs in
parallel with **M1 completion** (WP-5.1 type system, WP-5.1b IDL front-end, WP-5.2 corpus). The exception is
bounded:

1. **Passing stays sequential.** Mk is declared passed only after M(k-1) is declared passed. Work can run in
   parallel; the declarations cannot.
2. **Evidence is fresh.** The evidence for Mk's exit is a run on the commit that declares Mk passed, and that
   commit must be at or after the commit that declared M(k-1) passed. A green run from before M(k-1) passed is
   a progress signal, not exit evidence, because an M1 change (a codec, a type-support field) can invalidate
   everything built on it.
3. **Contracts first.** Parallel work against an interface that M1 is still changing (`DDS.CDR`, the
   `type-support` shape) follows the contract-first rule: an M1 slice that changes a frozen contract needs its
   ADR before its consumers adapt (operating contract §3.1, governing plan §2).
4. **Scope.** The exception covers the plan's Phase 5 functional exits of M2–M7 and the Phase 4 interop lab
   they depend on. It does **not** cover M8 (out of scope, D26), and it does **not** pull the Phase 6
   performance work forward over P0–P2 correctness: Phase 6 keeps its place in the plan, except for the
   WP-6.0 measurement checkpoint that D7 needs.
5. **Expiry.** The exception lapses when M7's exit gate passes on both Lisps, or when the owner withdraws it.

### 3.3 Why the owner's approval is enough here

The rule being relaxed is the operating contract's, not REQUIREMENTS'. REQUIREMENTS states what must be met at
acceptance (§9), not the order in which the milestones are worked. A sequencing exception therefore does not
need a REQUIREMENTS amendment; it needs the owner's recorded approval, which D9 gives.

## 4. Consequences

- The operating contract's §3.4 and §11 wording is unchanged by this ADR. Whether §3.4 should point here as the
  recorded exception is one of the owner's pending edits (ADR 0124 §7).
- Plan Phase 5 may start M2–M7 rows while M1 rows are open; each milestone's exit is declared in order, on a
  fresh run, as §3.2 says. The release-candidate job (WP-5.14) collects that evidence per milestone.
- `README.md` keeps its profile table, but its status note points here: a profile marked "complete" or
  "MET" there is not a passed milestone until its exit gate is re-run under this ADR.
