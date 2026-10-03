# ADR 0118 — Clasp is withdrawn as a target; SBCL and AllegroCL are the two

- **Status:** Proposed — the decision itself is the **owner directive of 2026-10-03** ("Clasp is DROPPED as
  a target; targets are SBCL + AllegroCL"); this record of it awaits owner approval (plan decision D2).
- **Date:** 2026-10-03
- **Requirement:** NFR-PORT (REQUIREMENTS §7.2), NFR-BUILD (conditional compilation confined to the PAL),
  the operating contract §5 (Definition of Done) and §6 (per-implementation gate invocation)
- **Work packages:** WP-0.2 (this record), WP-0.4 (build and launchers), WP-0.5 (PAL and source), WP-0.12
  (gate-mem canary, gate-pal ban) of `docs/plans/2026-10-03-sbcl-allegro-full-ok.md`; WP-0.6, 0.13 and
  0.14 complete the removal in the tests, the documents and the interop runners
- **Supersedes (fully):** ADR 0001 (M0 baseline Clasp-first), ADR 0103 (the Clasp/macOS `shm_open` gap
  closed in C++)
- **Supersedes (partly):** ADR 0003, ADR 0004, ADR 0013, ADR 0104; REQUIREMENTS §7.2 NFR-PORT, §9 item 5,
  §11 open decision 7; IMPLEMENTATION-PLAN §3.1 role A3, §6.3, risk R5
- **Clasp recovery point:** tag **`clasp-last`** = `9ed69bc`, the last commit with Clasp development and the baseline of the governing plan. The commits after it, up to the parent of the commit that applies this ADR, carry the same Clasp files unchanged.

---

## 1. The decision

From 2026-10-03 the implementation targets are **SBCL and AllegroCL**, co-equal, both required. **Clasp is
not a target**: it is not built, not tested, not benched, not an interop leg, and no code path, launcher,
make target or reader conditional exists for it. Nothing is kept "in case": a branch that cannot run is a
branch that cannot be verified, and the operating contract does not accept unverified code as done.

The recovery point for Clasp support is tagged `clasp-last` (`9ed69bc`, 2026-08-14): the last commit with Clasp
development. The few commits after it, up to the parent of the commit that applies this ADR, carry the same
Clasp files byte-for-byte unchanged (`git diff clasp-last HEAD~ -- src/dds-pal/pal-clasp.lisp scripts/with-clasp.sh`
is empty), so the tag is a complete recovery point. Recovering it is
`git checkout clasp-last -- <path>`; nothing in this ADR depends on that ever happening.

## 2. Why

Three facts, each sufficient on its own.

1. **The Clasp evidence was weaker than the record claimed.** `dds.pal:bytes-consed` returned the literal
   `0` on Clasp, so every zero-allocation assertion that ran there passed **vacuously**. A probe run on
   2026-08-14 (clasp-boehmprecise-3.0.1-236) with Clasp's own byte-exact counter, `GCTOOLS:BYTES-ALLOCATED`,
   measured `AES-256-GCM-SEAL-INTO` at **3056 B/call** and `%ENCODE-SECURED-REGION-INTO` at **3366 B/call**,
   against a recorded "~0". The fix for the counter (and the per-thread GCM scratch it motivated) was parked
   unmerged in WP-0.1 and is discarded by this ADR; the finding is what survives, here (§5(d)).
2. **No Linux Clasp exists on the reference host.** Of the two candidates `with-clasp.sh` tried,
   `/opt/clasp/bin/clasp` is absent and the source-tree build resolves to a **Mach-O 64-bit arm64**
   executable (checked with `file -L` on 2026-10-03), so a bare `make test` with the old `LISP ?= $(CLASP)`
   could not run at all. The reference platform is Linux x86_64 (§4), and the plan's evidence comes from it.
3. **The owner directive of 2026-10-03.** Clasp was the most expensive leg per unit of evidence: a source
   build, unavailable on hosted CI (`gates.yml` already left it as a "human step"), with upstream defects
   (by-name foreign calls re-resolving through `dlsym` every call, `WITH-FOREIGN-OBJECT` as a real malloc,
   the variadic `shm_open` mode on Darwin arm64) that each cost a work package to route around.

## 3. Evidence rebaseline

Every existing record that says **"SBCL+Clasp"**, **"Clasp + SBCL"**, **"both impls"** or **"all three
implementations"** — in ADRs, `bench/report/`, `docs/verification.csv`, commit messages, test docstrings
and `captures/*-RESULT.md` — is from now on read as **SBCL-only evidence**. AllegroCL is unverified for
that item until an AllegroCL run says otherwise. In particular:

- **No Clasp result counts toward any milestone gate.** A gate that was passed "on Clasp and SBCL" stands
  on its SBCL run alone; if the SBCL run did not exist or did not cover the claim, the gate is not passed.
- **M0 must be re-passed.** ADR 0004 closed M0 by owner command on Clasp + SBCL with an AllegroCL
  exception. Its exit gate ("every ASDF system loads on all three impls") becomes "every ASDF system loads
  on SBCL and AllegroCL", which is re-run, not inherited.
- **Historical documents are not edited** (plan §2): ADR bodies, `bench/report/*`, `docs/superpowers/*`,
  `captures/*-RESULT.md` and provenance history lines keep their Clasp text. They are read through this
  section. A superseded ADR receives at most a one-line Status pointer to this one, applied on acceptance.

### Controlled Status vocabulary

So the rebaseline is visible in the matrix rather than only stated here:

| Where | Retired value | Replacement |
|---|---|---|
| `docs/verification.csv` Status | `done-clasp+sbcl` (8 rows) | `done-sbcl` — done, SBCL evidence only, AllegroCL not yet run (WP-0.13) |
| `docs/verification.csv` Notes | "Clasp+SBCL …", "both impls" | left as written (historical); the Status column carries the truth |
| ADR Status line of a superseded ADR | — | `Superseded by ADR 0118` or `Partly superseded by ADR 0118 (§N)` |

## 4. Platform and image matrix

| Platform | Implementation / image | Status |
|---|---|---|
| Linux x86_64 | SBCL (the host's `/usr/bin/sbcl` 2.2.9 and the latest release; CI floor per D12) | **REQUIRED** |
| Linux x86_64 | AllegroCL 11.0 `alisp` (ANSI case mode, 16-bit characters) | **REQUIRED** |
| Linux x86_64 | AllegroCL 11.0 `mlisp` (modern case mode; the operating contract §6 names it) | **OPEN — owner decision D1** |
| Linux x86_64 | AllegroCL 11.0 `alisp8` / `mlisp8` (8-bit character images) | **OPEN — owner decision D1** |
| macOS arm64 | SBCL | **OPEN — owner decision D1** (the code keeps its Darwin arms; nothing gates on them) |
| any | Clasp | **WITHDRAWN** (this ADR) |

This ADR **states D1 and does not decide it.** Until the owner decides, only the two REQUIRED rows gate
anything, and nothing may be claimed for an OPEN row without a run on it. The production image question
(REQUIREMENTS "which image runs in production") is part of D1.

## 5. Disposition list

**(a) Removed in this change (WP-0.4, 0.5, 0.12).**

| Item | Disposition |
|---|---|
| `src/dds-pal/pal-clasp.lisp` | `git rm`; dropped from `dds-pal.asd` |
| `scripts/with-clasp.sh` | `git rm` |
| Makefile `CLASP`, `build-clasp`, `test-clasp`, `bench-rtps-message-clasp` | deleted; `LISP ?= $(SBCL)`; `build-all` / `test-all` / `all` run SBCL and AllegroCL |
| `dds.pal::%global-symbol-pointer` Clasp branch | the function is now `(cffi:foreign-symbol-pointer name)` on every target |
| `dds.pal::*native-shm-open*` (Clasp `CORE:SYS-SHM-OPEN`) | deleted. glibc declares `int shm_open (const char *__name, int __oflag, mode_t __mode)` — **not variadic** — and `mode_t` is `__U32_TYPE` = `unsigned int` (`/usr/include/x86_64-linux-gnu/sys/mman.h:144`, `bits/typesizes.h:43`, `bits/types.h:112`), so a plain `:unsigned-int` call is correct for AllegroCL on Linux and SBCL's varargs form stays correct everywhere |
| `shm-create-mode-reliable-p` | T on SBCL everywhere and on non-SBCL Linux; NIL for non-SBCL on Darwin, whose `shm_open` IS variadic and which AllegroCL calls without the varargs form — a platform D1 has not admitted |
| `gate-mem.sh` `*clasp*` name match | replaced by an allocation **canary**: cons a known N bytes and FAIL if `dds.pal:bytes-consed` moves by less than N. Correctly refuses AllegroCL, whose counter is the constant 0, and any future image with the same defect, without naming one |
| `gate-pal.sh` | additionally bans `#+clasp`, `#-clasp` and `:clasp` in code **everywhere** in `src/`, including `src/dds-pal/` |
| Clasp mentions in `src/` comments and docstrings (outside `src/dds-tests/`) | reworded so each remains true: present-tense Clasp claims now name the AllegroCL behaviour they describe, or are stated as history with this ADR as the pointer |

**(b) Completed by later work packages.**

| Item | Owner WP |
|---|---|
| The 13 `:clasp` test branches; the key-wipe proof that ran only on Clasp | WP-0.6 |
| ~250 Clasp lines in `src/dds-tests/` docstrings | WP-0.13 |
| REQUIREMENTS, IMPLEMENTATION-PLAN, README, `docs/wiki/`, the 8 verification rows, SBOM, provenance | WP-0.13 (README and `docs/wiki/getting-started.md` launcher/target lines already updated here) |
| `run-kill15.sh`, `run-our2our.sh` and the security runners' second leg; `gates.yml` "CLASP NOT RUN" | WP-0.14 |
| Operating-contract edits (lines 9, 52, 58, 79, 96, 106, 116, 124 and the §6 invocations) | the owner (D2) |

**(c) Kept, on purpose.**

- The per-thread foreign scratch (`*thread-timespec*`, `*thread-atomic-cell*`, `*thread-sockaddr*`). It was
  motivated by Clasp costs, but it is also the zero-allocation path on SBCL and AllegroCL; its docstrings
  now say so. `*thread-atomic-cell*` currently has no consumer (AllegroCL's CAS uses a stack foreign cell)
  and is kept for the WP-1.14 pinned-octet work rather than churned twice.
- Cached libc function pointers (`*clock-gettime-fp*`, `*memcpy-fp*`, …). By-name calls cost a `dlsym` on
  some FFIs; caching costs nothing on any.
- `bench/report/*clasp*` and every historical measurement: history, read through §3.

**(d) Discarded, with the finding recorded.**

- The parked `pal-clasp.lisp` `bytes-consed` fix (`GCTOOLS:BYTES-ALLOCATED`). Finding: on Clasp the
  zero-allocation claims for the DARE and DDS-Security AEAD cores were **vacuous**; measured 3056 B/call
  (`AES-256-GCM-SEAL-INTO`) and 3366 B/call (`%ENCODE-SECURED-REGION-INTO`), mostly heap-allocated
  `WITH-POINTER-TO-VECTOR-DATA` / `WITH-FOREIGN-OBJECT` frames (439 + 439 + 176 B/call). Boehm's
  `GC_get_total_bytes` was no substitute: it advances in allocation blocks and read 0 for a single cons.
- The parked `with-gcm-scratch` / `*thread-gcm-scratch*` (no ADR, Clasp-only justification, sizes
  hard-coded, seal covered but not open). The need it named returns as `with-pinned-octets` in WP-1.14.

## 6. Consequences

- **The gate set gets stricter, not looser.** gate-mem can no longer be satisfied by a counter that does not
  move; `make gate-mem LISP=./scripts/with-allegro.sh` now **fails loudly**, which is the true statement
  about AllegroCL today (its `bytes-consed` is the constant 0; plan D7 and Phase 6 own closing it).
- **A missing Lisp is a failure, not a skip.** `make all` runs both required targets; each launcher exits
  127 when its binary is absent.
- **AllegroCL inherits every arm Clasp used to excuse.** The 19 known AllegroCL failures at the 2026-10-03
  baseline were already in those arms; deleting the Clasp branches changes no AllegroCL behaviour.
- **NFR-PORT's "MAY trail by one profile" allowance has no subject.** Both remaining targets are co-equal;
  a gap on either is a gap, recorded and owned, never a profile allowance.
