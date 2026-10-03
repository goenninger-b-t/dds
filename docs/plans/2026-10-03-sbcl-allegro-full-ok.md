# NeoDDS: plan to reach full OK on SBCL and AllegroCL, with Clasp dropped (revision 2)

**Baseline:** HEAD 9ed69bc (2026-08-14) plus the uncommitted working tree. **Host:** Linux x86_64. `/usr/bin/sbcl` is 2.2.9.debian; a 2.6.7 development build sits at `/opt/common-lisp/sbcl/bin` but is not on PATH. AllegroCL 11.0 ships `alisp`, `alisp8`, `mlisp` and `mlisp8`. OpenSSL is 3.0.13.

**Sources:** a full test and gate run on this host on 2026-10-03 (SBCL 646/646 with ~106 in-test skips; AllegroCL 627/646, 19 failed, hang at exit), a read-only evidence review of milestones, defects, process, the verification matrix and performance, and targeted AllegroCL reproduction runs. Log citations of the form `test-*.log:N` and `probes/*` refer to that run's local logs, which are not committed.

**What changed since revision 1:**
- The **work-package (WP) scope grew.** New WPs cover the IDL front-end, DynamicType/DynamicData, the security Logging and Data Tagging plugins, the full annotation set, NFR-PERF-9, the NFR-DET determinism soak, FR-LOG-3 source lines, the Allegro PAL gaps, NFR-MEM against ADR 0102, the hot-path gate scope, and the gaps the DCPS conformance mapping will expose.
- **Phase 0 no longer leaves `main` red.** OpenSSL 3.5 provisioning and the fail-closed loader move into Phase 0. A transitional DoD ADR adds a ratchet mode.
- **Phase-by-phase exit criteria were fixed.** Each phase's exit now tests only what that phase can actually deliver.
- **The estimate model was replaced.** Estimates are re-expressed in units that fit how this repo is built: one committer working in parallel streams.
- **Rejected or corrected review points** are listed in Appendix A.

---

## 0. Before the plan: the strongest case against the goal as stated

1. **"Full OK" on AllegroCL performance may not be achievable, and today it cannot even be measured.**
   - `dds.pal:bytes-consed` is the literal `0` (`src/dds-pal/pal-allegro.lisp:252-257`).
   - On Allegro, every `cffi:foreign-funcall-pointer` builds a new entry-vec (`cffi-allegro.lisp:294-305`). There are 164 such call sites outside the PAL.
   - This is **not** a per-impl budget question that an ADR "under NFR-PORT" can settle:
     - NFR-PORT makes SBCL and Allegro "co-equal first-class targets and the performance pacesetters" (`REQUIREMENTS.md:246`).
     - The M5 exit reads "NFR-PERF-1,4,5,6,7,8 met on SBCL+Allegro … 0 bytes/sample … on SBCL+Allegro" (`IMPLEMENTATION-PLAN.md:146`).
   - Any per-impl budget for Allegro is therefore a **REQUIREMENTS amendment**, covering §6, §7.2, §9 and the M5 exit. Choosing it means **full OK is not met for M5 on Allegro**. Owner decision D7, taken at checkpoint WP-6.0 with data in hand.
2. **"All dimensions" contains MUSTs that nobody has started.**
   - FR-TOOL-1 (MUST, `REQUIREMENTS.md:189`) requires an IDL 4.2 input. No IDL parser exists in `src/`.
   - FR-TYPE-6 (MUST, `:102`) requires DynamicType/DynamicData. `src/` contains no `dynamic-data` or `dynamic-type`.
   - FR-SEC-1 (`:177`, "MAY/MUST-if-P6") binds because P6 is in scope. It names Logging and Data Tagging plugins that do not exist.
   - FR-TYPE-1 (`:97`) needs `@hashid`, `@external` and `bit_bound`. `src/dds-gen/dsl.lisp` has zero hits for `:external`, `:hashid`, `:bit-bound` or `:optional`.
   - Each of these is either built or removed by an **owner-approved REQUIREMENTS amendment**. An ADR alone cannot remove it, because REQUIREMENTS takes precedence (operating contract §2).
3. **Sequencing.** Operating contract §3.4 says not to begin a milestone until the prior gate passes. M1 contains the type system plus the IDL front-end, which is the long pole. Running the M2–M7 re-verification in parallel needs an owner-approved ADR (D9). The audit already found the sequence was broken without one.
4. **SHOULD items.** "All dimensions" does not say whether SHOULDs count. Examples: FR-PF-6 multi-channel writers (`REQUIREMENTS.md:172`, SHOULD, yet an M6 deliverable at `IMPLEMENTATION-PLAN.md:149`), FR-XPORT-3/4/6, FR-API-2, FR-TOOL-2 and FR-DCPS-7. This is an explicit scope decision (D28). SHOULD-gated WPs are sized separately below.

---

## 1. Where things stand (verified facts only)

| Dimension | SBCL (Linux x86_64) | AllegroCL 11.0 | Evidence |
|---|---|---|---|
| `make test` | 646/646, but about 101 tests return early behind a bare SKIP while the summary prints "skipped: 0 — every test ran" | 627/646, 19 FAILED, then hung at exit with 10 live threads and was killed at 1654 s | test-sbcl.log:12107-12108; test-allegro.log:3772, 3837-3840 |
| Allegro failure causes (measured) | n/a | (1) waits of 0.075 s or less return immediately: 16 of the 19. (2) CFFI `:int` returns are not sign-extended. (3) A real OOB read in `%lane-drain`, on **both** Lisps. (4) TypeLookup hash order. With a sleep patch in the image the suite reaches **643/646 and 0 leaked threads**; the remaining 3 are TLS-INDEX-HIT, shmem-ring-drain-fuzz and rti-shmem SHMAT-FAILED | probes/full-sleeppatch.log, base19.log, exit2.log |
| `:clasp` skip branches | Skip only on Clasp | **Allegro already runs these arms.** Their failures are already counted among the 19, so deleting the branches changes nothing on Allegro | integration-test.lisp:7029, 7097, 7493; test-allegro.log:2937-2965 |
| `make corpus` | PASS (13 verified, 1 deferred) with `LISP=sbcl`. A bare `make corpus` FAILS because `LISP ?= $(CLASP)` (Makefile:15) runs a Mach-O binary | Never run | corpus.log |
| `gate-build` | Meaningful (ASDF `:error`) | Blind: ASDF's failure behaviour is `:warn` (`asdf.lisp:4919-4920`) | gate-build.sh:45-63 |
| `gate-mem` | PASS at COPY 449.6 / RETURN 257.1 / INTO 225.8 B/sample against a target of 0; about 14 % of x86_64 runs blow up 2–435× | Vacuous: the counter is 0, and gate-mem.sh:96-103 refuses only `*clasp*` | gate-mem.log; bench/mem-ceiling.txt:380-417 |
| Hot-path purity gate | Source-only. Scans 8 files plus generated output; dataplane.lisp, reliable.lisp and the delivery path in entities.lisp are not scanned. 13 `HOTPATH-ALLOC(TRACKED)` sites remain (message ×7, cdr/primitives ×3, history, runtime, zerocopy-pool) | Same | gate-hotpath.sh:39-49; grep |
| `gate-arena`, xproc, `bench` | PASS, SBCL only | Hard-wired to `with-sbcl.sh` | gate-arena.sh:30; Makefile:333-459 |
| `wire`, `interop` | Cannot run here: no tshark, Connext or Fast DDS, and the peers are Mach-O arm64 | Never an interop participant | wire-check.sh:22-41; gate-interop.sh:98-135 |
| Security / DARE | About 99–106 arms never executed on Linux (OpenSSL 0x300000D0 < 3.5) | Only `OpenSSL_version_num` has ever run | openssl-ffi.lisp:139-174 |
| Exits | — | `uiop:quit` hangs with a thread parked in a foreign call. It is used in production entry points: durability/main.lisp:562, 574, 587, 622, 652, 663; dds-log/service.lisp:146, 155; dds-shapes/shapes.lisp:170, 570, 631 | probes/exit2.log; grep |
| FR-LOG-3 source line | Always 0 | Always 0 | dds-log/macros.lisp:5-8 |
| Proposed but unaccepted ADRs | 0096, 0098, 0099 and 0100 have shipped mechanisms. 0111 is still Proposed, so its Float128 deferral is undecided | — | `grep Status docs/adr/0{096,098,099,100,111}*` |
| NFR-MEM vs ADR 0102 | REQUIREMENTS says "allocated once at startup" (`:173`, `:252`); ADR 0102 grows the arena in chunks. REQUIREMENTS never mentions 0102 | — | grep |
| CI | SBCL 2.2.9, OpenSSL 3.0, no interop, 4 gates not wired in | None | gates.yml:49-133 |
| Milestones | M0 passed by owner command only (ADR 0004). M1 and M5 NOT MET; M2, M3, M4 and M6 PARTIAL. M7 claimed MET, but 0 of 22 logs are committed | Nothing evidenced | audit (verified) |
| How the repo is built | One committer, 713 commits and 56 active days between 2026-06-01 and 2026-08-14. ADR 0111 slice 1 landed the same day as its ADR (c9f4996 and 3db49ff, both 2026-08-07) | — | `git shortlog -sn`; `git log` |

---

## 2. Rules that bind every work package

- **ADR before any contract change** (A0). ADRs are numbered from **0118**, in order.
- **Docs move with code** (operating contract §5.1): docstring, `docs/wiki/`, README, `docs/verification.csv`, and provenance whenever an external source was consulted. That includes the OpenSSL 3.5 build, the Wireshark build and the Fast DDS build.
- **SBOM** is regenerated by the pre-commit hook and never hand-edited. `generate-sbom.py` gains AllegroCL as a runtime component, the vendored OpenSSL 3.5 as a runtime FFI dependency, and Wireshark as a test tool.
- **Hot-path changes need a before/after report in `bench/report/`** (FR-LANG-7). This now applies to WP-0.7 (`%lane-drain`, a gate-hotpath file), 1.2, 1.3, 1.6, 1.10 (message.lisp codegen on Allegro), 1.14, 1.15, 1.17 (`CDR-GET-STRING`), 5.2 (BE cursor and encapsulation), 5.6 (CFT), and all of Phase 6.
- **No reader conditionals outside `src/dds-pal/`.** After ADR 0118, no `#+clasp`, `#-clasp` or `:clasp` remains anywhere in code. Comments are reworded too (WP-0.5).
- **No wire or OS constant is typed from memory.**
  - `CLOCK_MONOTONIC`, `TIMER_ABSTIME`, `EINTR`, `ETIMEDOUT` and the `shm_open` prototype come from `/usr/include` through a C probe.
  - The OSSL_PARAM layout comes from an `offsetof` probe against the 3.5 headers.
  - Content-filter PIDs come from the RTPS 2.5 §9.6 tables plus a live tshark decode.
  - Annotation ids come from XTypes 1.3 Table 21.
  - Logging and data-tag PIDs come from the DDS-Security spec tables.
- **Bounds-check every network-facing or shared-memory-facing parser.** A corrupt SHMEM cursor counts as hostile input (WP-0.7).
- **Historical documents are never edited:** ADR bodies, `bench/report/*`, `docs/superpowers/*`, `captures/*-RESULT.md` and provenance history lines. Superseded ADRs get only a one-line Status pointer.
- **Commits reference the WP id and the requirement id** (§7.8; 0 of the last 40 do today). No AI attribution in any commit, PR or repo file.
- **Skip control is one environment variable, fail-closed by default:** `DDS_TEST_ALLOW_SKIP=<cap,…>`. When set, the run prints "NOT A GATE RUN" and exits with a distinct code. `DDS_TESTS_FAIL_ON_SKIP` does not exist.

---

## 3. Staffing and estimation model

- **Who builds this:** the owner, working in parallel streams. Not a team of three. The 713 commits in 56 active days show high throughput. That history also contains retractions (2026-08-06/07 report retraction, ADR 0105 §8.6 NOT MET), so raw throughput is not the same as verified output.
- **Unit of estimate:** engineer-day equivalents (ed) of work content. This makes work packages comparable. **It does not set calendar time.** Calibration points: ADR 0111 slice 1 took under a day from ADR to green, but it was the simplest slice (floats). ADR 0095 spanned 3 calendar days.
- **What actually binds the calendar, in order:**
  1. owner decisions and ADR reviews: about 34 decisions and about 25 ADRs;
  2. external calendars: RTI licence (D17), Franz CI and redistribution terms (D13, D16), counsel (D20);
  3. machine time: fuzz soak, 24 h soaks per Lisp, perf runs on a quiet host, and a second GbE host (D22);
  4. first execution of never-run code, with failure waves in 1.18 and 1.15.
- **Calendar:** 4–9 months if decisions turn around within a week and RTI and Franz respond within a month. Confidence is **low**. Every procurement delay adds directly to the critical path. Engineering does not.

---

## 4. Phases

### Phase 0: stop the bleeding, honest harness, Clasp withdrawn, `main` stays green

**Goal:** a committed baseline in which a green run cannot hide a skip, a hang or the wrong libcrypto; Clasp is gone; the SHMEM OOB is closed; and **CI stays green throughout**, under the transitional ratchet of ADR 0120.

| WP | What | Concrete fix | ed | Conf |
|---|---|---|---|---|
| **0.1** Working-tree disposition | Split the 4 mixed changes | **Commit the CSV repair only.** Fix the 5 shifted rows (WT lines 29, 30, 58, 64, 109, where the Status column holds P2 ×4 and P5 ×1) and harden gate-verification to check the Status and Gate enums (gate-verification.sh:37-42), with a self-falsifier. **Fold** the `%skip` hunk (echo-test.lisp:16-29 plus 17 sites) into WP-0.10 rather than commit it. **Discard** the pal-clasp.lisp hunk, recording its finding (Clasp zero-alloc was vacuous; seal costs 3056 B/call) in ADR 0118 §(d). **Revert** `with-gcm-scratch` and `*thread-gcm-scratch*`: no ADR, a Clasp-only justification, seal covered but not open (primitives.lisp:605-608), sizes hard-coded. It comes back as `with-pinned-octets` in WP-1.14. The owner retires the 2026-08-14 decision explicitly. | 1–1.5 | H |
| **0.2** ADR 0118: Clasp withdrawn | Record the decision | Fully supersedes 0001 and 0103. Partly supersedes 0003, 0004 (M0 must be re-passed), 0013, 0104, NFR-PORT §7.2, §9 item 5, open decision 7, and IMPLEMENTATION-PLAN §3.1 A3, §6.3 and R5. Contents: evidence rebaseline (every "SBCL+Clasp" means SBCL-only); disposition list; platform and **image** matrix (D1); controlled Status vocabulary. `git tag clasp-last <sha>`. | 0.5–1 | H |
| **0.3** ADR housekeeping | DoD requires accepted ADRs | (a) Accept, reject or supersede 0096 (§5 needs an owner decision), 0098, 0099, 0100 and 0111. Accepting 0111 is where Float128's deferral becomes an actual decision (D32). (b) **ADR 0120, transitional DoD:** until the Phase 1 exit, the per-commit rule is "no new failures against a committed `test/baseline-<lisp>.txt`, and no new skip events against `test/skip-baseline-<lisp>.txt`". Every baseline entry names its owning WP. Baselines may only shrink, enforced by gate-verification. The rule expires at the Phase 1 exit; from then on it is zero/zero. Allegro is checked locally per commit (WP-3.8 schema) until WP-3.2 is live. (c) ADR recording the past deviation from the M0→M8 sequence (audit). | 1.5–3 | H |
| **0.4** Build and launcher | SBCL becomes the default | `LISP ?= $(SBCL)` (Makefile:15). `build-all`, `test-all` and `all` run SBCL and Allegro. Delete build-clasp, test-clasp and bench-rtps-message-clasp (Makefile:432-435). Fix the dds-pal.asd:10-12 comment. `git rm scripts/with-clasp.sh`. Fix comments in lisp-cache-env, with-sbcl and with-allegro. .gitignore:11. | 0.5 | H |
| **0.5** PAL and source Clasp removal | Remove Clasp code and **all** comment hits | `git rm src/dds-pal/pal-clasp.lisp`. pal-contract.lisp:165-166 becomes `(cffi:foreign-symbol-pointer name)`. Delete `*native-shm-open*` (pal-net.lisp:1116-1124). `shm-create-mode-reliable-p` returns NIL for non-SBCL on Darwin arm64, or that platform is declared out (D1). Verify the `shm_open` prototype from `/usr/include/x86_64-linux-gnu/sys/mman.h`. **Also reword** the hits the original list missed: dds-dare/key-provider.lisp (4), dds-disc/disc.lisp:25, dds-durability/store-encrypted.lisp:654, dds-pal/pal-sbcl.lisp:18, for example "no reader conditionals (operating contract §4)". Keep the per-thread scratch machinery and reword its docstrings. | 1–1.5 | H |
| **0.6** Tests | Delete the 13 `:clasp` branches, mechanically | Make the live arms unconditional. **No behavioural change on Allegro**: those arms already run and their failures are already in the baseline. Never rewrite as `(not :sbcl)`. **New coverage:** redesign the key-wipe proof (security-test.lisp:3029-3033, which today runs only on Clasp). Split zeroize into wipe-then-release, with a test-only read-back hook before release, on SBCL and Allegro. Rebase the cross-check at security-auth-test.lisp:2786-2844 to SBCL+Allegro. The ~250 docstring lines move to WP-0.13. | 1–1.5 | H |
| **0.7** SHMEM `%lane-drain` OOB (security, both Lisps) | Close the NFR-SEC-POSTURE violation **and** make it visible | Before the `mem-ref` at shmem.lisp:152-153: if `(logtest pos 7)` or `(> (+ pos 4) capacity)`, **poison the lane**. That means setting a poisoned flag, incrementing a per-lane corrupt-cursor counter exposed as an NFR-OBS status, emitting one log event, and detaching or resetting per an ADR. Today's bail-outs at :148 and :155 leave `r` unchanged, which wedges the lane silently forever. Valid records are 8-aligned (shmem.lisp:101-104) and capacity is a multiple of 8 (:60). Regression tests: the lane ends exactly at the end of a page-aligned `shm-create` mapping, so the over-read faults on SBCL too; and the poisoned state is asserted to be **observable**, not merely "no crash". Audit the RTI-SHMEM reader the same way. Hot path, so a bench is required. | 1–1.5 | H |
| **0.8** OpenSSL ≥ 3.5 (moved from 1.7) | Provision before the honesty switch | Build the latest 3.5.x LTS patch from the release tarball (verify SHA-256 and signature) into `/opt/openssl-3.5`. `scripts/openssl-env.sh` exports **only** `DDS_DARE_LIBCRYPTO`, **not** `LD_LIBRARY_PATH`, so peers, tshark and Allegro's `aclssl*.so` keep the system library. `offsetof` probe for the 40-byte OSSL_PARAM layout on x86_64 (openssl-ffi.lisp:43-48 was verified on arm64 only). Hosted CI: build once, cache with actions/cache keyed on version and SHA, export through `$GITHUB_ENV`. Bump docker/linux-amd64.Dockerfile:32-43 from 3.5.0 and add the checksum. Fix the SBOM's OpenSSL pin, which is the macOS 3.6.2 (generate-sbom.py:53). Provenance entry. | 1.5–2.5 | H |
| **0.9** Fail-closed libcrypto loader (moved from 1.8; ADR) | A wrong library is an error | If `DDS_DARE_LIBCRYPTO` is set but cannot be loaded, return a hard error, never the 3.0 fallback (openssl-ffi.lisp:75-76, 93-96). Add a PAL `dlsym`-on-handle, because CFFI ignores `:library` on both Lisps (cffi-sbcl.lisp:399-403, cffi-allegro.lisp:407-410). Check with `dladdr` that `OpenSSL_version_num` resolves inside the realpath. The preflight reads `/proc/self/maps` and **fails if more than one libcrypto is mapped**. Reason: ELF lookup for a `dlopen`ed object searches the global scope first, so with two copies loaded, the /opt copy's internal references can bind to the system copy (moderate-high confidence; the check makes it moot). Falsifier: preload the system 3.0 library and require a rejection. | 1.5–2.5 | M |
| **0.10** Harness honesty: one skip channel (ADR) | No hidden skips, in two steps | Add `(note-skip SITE CAPABILITY REASON)` per `*current-test*`, with no dedup and a closed vocabulary: `:openssl-pqc :libcrypto :alloc-counter :zc-sap-primitives :shm-attach-by-name :subprocess-mode :rx-store-pool`. The registry moves out of `dds.pal` into test support; production-file test bodies reach it through a hook. Convert the ~105 bare `SKIP` prints and the silent `(when sbcl …)` arms (secure-sedp:2036-2048, gen-test:890/930/944/969, security-test:514/1570/1710/2973, durability-test:6910, dataplane:5379). The summary prints FULL/PARTIAL/SKIPPED/FAILED. A capability preflight prints the OpenSSL version and path, checks that bytes-consed moves and that shm attach works. Add **gate-skip-lint**. Apply the same accounting to fuzz, mem and corpus (deferred counts as a skip). **Step 1 (report-only):** accounting is printed and the exit code is unchanged. **Step 2 (enforce):** lands in the same commit that enables 0.8 in hosted CI. Required-capability skips fail **unless listed in the ADR 0120 skip baseline**, so CI stays green while every remaining skip is named and owned. | 4–6 | M |
| **0.11** Exit that cannot hang, without losing cleanup (ADR) | Tests **and** production | `dds.pal:exit-process code` runs a registered **shutdown-hook chain** first: key wipe, SHMEM `shm_unlink`, store fsync, log flush, `finish-output`. Then a hard exit: Allegro `(excl:exit code :no-unwind t :quiet t)` (probes/exit2.log), SBCL the equivalent. Route **every** `uiop:quit` in `src/` through it (durability/main.lisp ×6, dds-log/service.lisp ×2, shapes.lisp ×3), plus the test-op, and lint against `uiop:quit` in src. `run-all-tests` lists live non-main threads and fails on any leaked `dds-*` thread. Wrap every Makefile Lisp call in `timeout --kill-after=60`. Test: SIGTERM a durability service, then assert the keys are wiped (via the 0.6 hook) and the segments unlinked, on both Lisps. | 2–3.5 | M |
| **0.12** gate-mem falsifier | Close the vacuous pass | Replace the `*clasp*` name match (gate-mem.sh:96-103) with a canary: cons a known N bytes and FAIL if the delta is below N. gate-pal bans `#[+-]clasp\|:clasp` in code everywhere, including dds-pal/. | 0.5 | H |
| **0.13** Specs, README, wiki, matrix, SBOM | Rebase the documents | Generate the edit list **mechanically** with `grep -n -i clasp` over REQUIREMENTS, IMPLEMENTATION-PLAN, README, docs/wiki and the operating-contract file. That includes REQUIREMENTS :249 (NFR-DET), :254 (NFR-MEM), :260 (NFR-CONC), and operating contract :9, :52, :58, :79, :96, :106, :116, :124. REQUIREMENTS changes first. Mark §6.3 and A3 "withdrawn (ADR 0118)". Draft the **NFR-MEM/FR-PF-7 against ADR 0102** amendment for D29. Re-status the 8 `done-clasp+sbcl` rows to `done-sbcl`. The README states only facts measured today. The ~250 test docstring lines say what is true after the Allegro run. SBOM gets AllegroCL (Franz Inc., version queried live, licence per D6). Append a provenance retirement line at docs/provenance.md:161. **Operating-contract edits, including the §6 Allegro invocation and the image choice (D1), are applied by the owner (D2).** | 3.5–5 | M |
| **0.14** Interop scripts and CI text | Clasp legs become Allegro legs | run-kill15.sh, run-our2our.sh, the security-access-control, auth-keyx and auth-discovery runners: second leg via with-allegro.sh, and a missing Lisp is a **FAIL**. gates.yml:18-20 and :33-38 (stale MD-E2E-P2-VIEW note, fixed by 4e642de), :127-133: the "not covered" list is computed and prints ALLEGROCL NOT RUN. | 1.5 | M |
| **0.15** Exit-gate wording ADR | Make every gate falsifiable | Pin: fuzz N (proposed 8 h per Lisp per release, 1 h nightly); **fuzz method** (D30: coverage-guided harness, or an ADR accepting PBT plus capture replay; shrinking is required either way); soak duration and netem profile (24 h; 1 % loss, 50 ± 10 ms, 0.5 % reorder, 0.1 % dup); the DCPS suite is clause-mapped in verification.csv; **the interop matrix is a checked-in file** (`interop/matrix.csv`: Lisp × peer × {BE, reliable, CFT, durability, evolution, frag, large-data, secure}) that gate-interop enforces; FR-CDR-8(a) is conditional on the Connext BE probe (WP-4.11); retract the "5 %" (ADR 0062:5, :358; bench report 2026-07-13:17-18) in favour of REQUIREMENTS.md:222-232. Needs D3, D4, D5, D28 and D30. | 1.5–2.5 | H |
| **0.16** Repo hygiene | Remove debris | `git rm` the root files `4294967232`, `452`, `64`, `7` (from a77fcb6) and delete the untracked `456 516 520 580 584`. `make clean` removes in-tree fasls. gate-build fails if any `src/**/*.fasl` exists. | 0.25–0.5 | H |

**Dependencies:**
- D1 and D2 before 0.2 and 0.13.
- 0.1 before 0.6, 0.10 and 0.13.
- 0.2 before 0.4–0.14.
- 0.3(b) before 0.10 step 2.
- 0.8 → 0.9 → 0.10 step 2.

**Risks:**
- The first enforced SBCL run against OpenSSL 3.5 will expose real failures in the ~99 never-run security arms. They go into the ADR 0120 baseline, each owned by WP-1.18. They are not hidden and not loosened.
- The baseline files can become a dumping ground. Mitigation: gate-verification enforces shrink-only, and the baselines expire at the Phase 1 exit.

**Exit criterion (Phase 0):**
```
git grep -nE '#[+-]clasp|:clasp' -- src '*.asd'                  # → no output
git ls-files | grep -iE 'pal-clasp|with-clasp'                   # → no output
git grep -n 'uiop:quit' -- src | grep -v dds-pal                  # → no output
git tag -l clasp-last                                             # → clasp-last
make gate-pal gate-verification gate-skip-lint gate-hotpath gate-nocond gate-types   # each PASS
make test LISP=./scripts/with-sbcl.sh; echo rc=$?                 # rc=0 under ADR 0120 ratchet;
      # preflight shows OpenSSL 3.5.x at /opt/openssl-3.5/…, "libcrypto mappings: 1"
# falsifiers (each must exit non-zero):
DDS_DARE_LIBCRYPTO=/nonexistent make test …                      # → hard error, rc≠0
LD_PRELOAD=/usr/lib/x86_64-linux-gnu/libcrypto.so.3 make test …   # → "2 libcrypto mappings", rc≠0
make gate-mem LISP=./scripts/with-allegro.sh                      # → "FAIL: allocation counter does not move"
gh run list --branch main --workflow gates.yml --limit 1          # → success (main never went red)
```
**Effort, Phase 0:** about **23–35 ed** (M).

---

### Phase 1: platform parity

**Goal:** the full unit suite on both Lisps with zero failures, zero skips, no hang and no leaked threads, with security/DARE executing. The ADR 0120 baselines are empty at the exit.

**Part 1A. Allegro to 646/646 passing (7.5–12 ed).** Order: 1.1 → 1.3 → 1.5 → 1.6, with 1.2 in parallel.

| WP | Fix | ed | Conf |
|---|---|---|---|
| **1.1** `dds.pal:sleep-seconds` (ADR) | **Allegro:** `clock_nanosleep(CLOCK_MONOTONIC, TIMER_ABSTIME, &deadline, NULL)` through `ff:def-foreign-call … :allow-gc :always`, with an absolute deadline computed from the cached `clock_gettime` into the per-thread timespec. It **returns the error number directly**, which matters because Allegro 11.0 reads errno as 0 after a failing call (pal-net.lisp:1016-1025). On EINTR, reissue with the same absolute deadline. Constants come from a C header probe. **SBCL:** `cl:sleep`. Mechanically replace the 480 sites. The lint is a **form walker** (or an expanded regex covering `(sleep `, `cl:sleep`, `#'sleep`, `'sleep`) that bans `sleep` outside dds-pal/. Optional Franz ticket with probes/cv4.lisp. | 2–3 | H |
| **1.2** Allegro condvar short waits (PAL only) | defstruct (mp-cv, generation). Waits ≥ 0.1 s or unbounded go native. Shorter waits poll the generation in ≤ 200 µs slices of 1.1. Returns a real woke-p (pal-contract.lisp:57; bt apiv1 always returns T). Bench idle CPU (dds-log/emit.lisp:143 spins a core today) and flow-pacing throughput. | 2–4 | H |
| **1.3** CFFI sign extension | `%sint32` sign-extends the low 32 bits; `%ssize` applies `(ldb (byte 64 0) n)` first (pal-net.lisp:350-357). Wrap or `defcfun`-ise about 15 sites: pal-net.lisp:779-793 (a udp-recv timeout currently delivers an 18446744073709551615-octet "datagram" to dds-xport/udp.lisp:142), 1194-1213, 1259, 1276, 1291, 1333-1385; dds-dare/primitives.lisp:1051, 1570; pal-allegro.lisp:330. Lint for unwrapped `:int`/`:long`. Allegro regression tests. Bench recvfrom and sendto. | 2–3 | H |
| **1.5** Deterministic TypeLookup index | Registration-sequence order in `%tl-hash-index` (typelookup.lisp:766-791). The test (integration-test.lisp:12765) asserts hash and octet equality, plus a determinism case. | 0.5 | H |
| **1.6** Bounded SHMEM park | `dds.pal:pshared-cond-timedwait` using `pthread_cond_timedwait` with a `pthread_condattr_setclock(CLOCK_MONOTONIC)` condattr. The return code carries the error, so no errno is needed. Loop on ETIMEDOUT and re-check `+stop-off+`. Used by shmem.lisp:684-702. Bench. | 1–1.5 | H |

**1A exit (honest):** `DDS_TEST_ALLOW_SKIP=alloc-counter,zc-sap-primitives,subprocess-mode make test LISP=./scripts/with-allegro.sh` gives 646 passed, 0 failed, 0 leaked threads, and exits with the **ALLOW_SKIP code (not 0)**. The skip report lists only those three capabilities. Security arms that fail on Allegro stay in the 0120 baseline and are owned by 1.18. This is not a gate pass.

**Part 1B. Toolchain (7–12.5 ed).**

| WP | Fix | ed | Conf |
|---|---|---|---|
| **1.9** Probe split (D8, ADR) | `crypto-available-p` (≥ 3.0 plus the needed EVP algorithms) for DDS-Security; `dare-pqc-available-p` (≥ 3.5 plus ML-KEM-1024) for DARE. identity.lisp:178-181 currently refuses authentication on stock 3.0. Both capabilities stay **required** for full OK. | 1–2 | M |
| **1.10** Allegro build cleanliness | Move forward-referenced constants and specials ahead of first use: `+PID-KEY-HASH+` (message.lisp:808/837 against :1070), `+RX-PREFIX-SLOTS+`, `*SECURED-POOL-CAPACITY*`, `*SECURED-POOL-HEADROOM*`, `*RX-STORE-POOL-ENABLED*`, `+RETCODE-OK+`, `+FD-ABC-FLATDATA-SIZE+`. bordeaux-threads per D10. sqlite3 bare-struct. Bench (Allegro codegen of message.lisp). | 1–1.5 | M |
| **1.11** One dependency root, fail on fallback | One committed dist pin (`ql-dist:install-dist …/2026-01-01/distinfo.txt :replace t`), or vendor/ for static-vectors and cffi (D11). **Launchers load exactly one Quicklisp root and FAIL on fallback.** with-allegro.sh currently tries `~/quicklisp` and then `/opt/common-lisp/quicklisp`, which hold cffi-20260101 and cffi-20231021 respectively. gate-quickload asserts the resolved cffi and static-vectors paths. The SBOM reads the same pin. **Prerequisite for 3.2.** | 2–3 | H |
| **1.12** SBCL latest + one prior | Official tarballs with sha256, selected via `SBCL_BIN`. The 2.6.7 dev build on this host can serve as an early smoke test. Re-bank mem-ceiling per version. 2.2.9 stays as an optional floor (D12). | 2 + 1–4 fallout | M |

**Part 1C. Real Allegro coverage (30–56 ed).**

| WP | Fix | ed | Conf |
|---|---|---|---|
| **1.13** Real `bytes-consed` on Allegro | `sys::gsgc-totalloc-bytes` (measured +16552 B per 1000 conses; empty window 64 B; probes/alloc2,3.lisp), minus a calibrated baseline, **excluding static allocation**. Validate against 1 cons, a 100-octet vector and a 16-octet foreign pointer. Pin the method in a docstring and a verification row. If imprecise, ask Franz for the supported API. | 2–3 | M |
| **1.14** Allegro direct-call FFI (ADR) | `ff:def-foreign-call :call-direct t` with an explicit `:release-heap` policy for recvfrom, sendto, clock_gettime, memcpy and `__atomic_*` (pal-allegro.lisp:149, 171). Route the 164 call sites outside the PAL through PAL entry points. **`with-pinned-octets`** (covering seal **and** open, sizes from dds-dare constants) replaces `with-pointer-to-vector-data` on heap AAD (primitives.lisp:462, 610), which does not pin on Allegro (cffi-allegro.lisp:128-138). A GC-stress KAT test must fail when pinning is removed. **atomic-cell:** probe `most-positive-fixnum`. Values at or above that box, and `excl::atomic-conditional-setf` compares with EQ, so the cell moves to foreign memory via `cas-sap-u64`, plus a large-value test. Bench before and after. | 8–15 | M |
| **1.15** Un-gate the `:sbcl` skips | 15 registered skips plus about 4 unregistered (dataplane.lisp:5471, 5553; durability-test.lisp:874; flatdata-zc-loan-stress) plus about 39 `(eq … :sbcl)` gates become capability checks (ADR 0064). Expect real ZC/FlatData bugs under Allegro lock fairness. Bench. | 3–6 | L |
| **1.16** Durability `:process` on Allegro | Prebuilt per-Lisp service image through a PAL entry point next to `lisp-eval-command` (ADR 0116). Remove the gate at runner.lisp:52. Licence: D13. | 3–5 | M |
| **1.17** Non-BMP strings on Allegro (ADR amending 0115/0117) | Surrogate-pair decode and encode in `CDR-GET-STRING`/`%MS-CHAR`; bounds stay in UTF-8 octets; lone surrogates are rejected. Two-topic purge test. **Valid only for 16-bit images.** If an `*8` image is in scope (D1), it needs its own policy. Bench. | 2–4 | M |
| **1.18** First real security/DARE run on both Lisps | Full suite, `make fuzz` (4 security fuzzers, pbt-test.lisp:990-1366) and `make mem` secure arm (gen-test.lisp:909-916). SBCL first, then Allegro. Empty the 0120 security baseline. Fix security-test.lisp:669 "DEFERRED". | 6–12 | L |
| **1.19** Allegro PAL "documented gaps" | Close each one, or downgrade its consumer by ADR, with a falsifier. **`static-vector-p`** cannot tell heap from foreign memory (pal-allegro.lisp:74-80), so the off-heap key proofs at security-test.lisp:2975-3013 are vacuous there; discriminate by address range or the static-vectors registry. **`internal-bug-p`** is NIL (:277-286), so the ADR 0100 latch at dataplane.lisp:502 is dead code. **`with-gc-inhibited`** is a `progn` (:265-270); prove no heap address crosses into C, or implement it. **TCP `recv`** cannot tell a reset from a timeout because errno is unreadable (pal-net.lisp:1016-1025); use `getsockopt(SO_ERROR)` or a return-code API. | 3–6 | M |
| **1.20** FR-LOG-3 source line | PAL capture of the source line for SBCL (`sb-c` source path / form-number to line at macroexpansion) and Allegro (source-file recording), tested against the FR-LOG-9 golden lines. dds-log/macros.lisp:5-8 currently emits 0. | 1–2 | M |
| **1.21** (conditional, D1) `mlisp` leg | Only if the owner puts modern-mode Allegro in scope: run the suite and gates under `mlisp`, and fix `intern`/`find-symbol`/`format ~A` case bugs. | 1–3 | L |

**Dependencies:**
- 1.1 → 1.2, 1.6.
- 0.8 → 0.9 → 1.18.
- 1.13 → 1.14 (to prove the effect).
- 1.1–1.3 → 1.15.
- 0.10 and 0.11 → all of Phase 1.

**Risks:**
- 1.14 is a large rewrite of a frozen-contract package.
- 1.18 is unbounded in principle.
- 1.13 may reveal heavy per-sample allocation on Allegro, which feeds D7.

**Exit criterion (Phase 1):** the ADR 0120 baselines are empty and deleted.
```
for L in ./scripts/with-sbcl.sh ./scripts/with-allegro.sh; do
  timeout --kill-after=60 3600 make test LISP=$L; echo rc=$?     # DDS_TEST_ALLOW_SKIP unset
done
# each: "N passed, 0 FAILED, 0 SKIPPED, 0 PARTIAL"; "leaked threads: 0"; rc=0
# preflight: OpenSSL 3.5.x, path /opt/openssl-3.5/lib64/libcrypto.so.3, mappings 1, alloc-counter OK
SBCL_BIN=<latest> make test …  and  SBCL_BIN=<prior> make test …    # both rc=0
make gate-sleep-lint gate-ffi-sign-lint gate-quickload                # PASS (form-walker lint)
```
**Effort, Phase 1:** about **45–81 ed** (L–M), including 1.21 if it is in scope.

---

### Phase 2: every §6 gate runnable and green on both Lisps

| WP | Fix | ed | Conf |
|---|---|---|---|
| **2.1** Lisp-parametric gates | Every runtime gate takes `LISP`: gate-arena.sh:25, 30; mem (Makefile:457-459); gate-quickload; corpus; fuzz; bench (Makefile:333-437). `*-all` variants. Translate `--non-interactive` for Allegro. Static lints run once. | 1–3 | H |
| **2.2** gate-build on Allegro | `:around` compile-op for **our** systems binding `uiop:*compile-file-failure-behaviour*` to `:error`. Impl-aware canary. D15. | 2–4 | H |
| **2.3** gate-mem on both Lisps, flakiness fixed | Ceilings keyed by impl, arch and version. Random domain id with unicast-only locators. Retransmit, empty-poll and pool counters. Min-of-N. Set the x86_64 RETURN ceiling. Characterise the 74126.2 B/sample INTO outlier. | 2–5 | M |
| **2.4** corpus on Allegro, plus cross-Lisp byte identity | `make corpus LISP=allegro`. `wire-all`: both Lisps write the pcap (mktemp, not tools/rtps-pcap.lisp:167's fixed path); the two pcaps must be byte-identical. | 0.5–1 | H |
| **2.5** tshark ≥ 4.6 on the host | Build with `-DBUILD_wireshark=OFF`; dumpcap capabilities; remove the hard-coded `sbcl` at wire-check.sh:41; provenance and SBOM (test tool). | 1–1.5 | M |
| **2.6** Fuzz soak, replay, shrinking | Time-bounded mode with a persisted crash corpus; **shrinking**; pcap reader that replays and mutates the 33+ committed captures. Method per D30. A coverage-guided CFFI harness, if chosen, costs +5–10 ed. | 5–9 | M |
| **2.7** Remaining static gates | Run gate-nlx and gate-drivers; document that static gates prove nothing impl-specific. | 0.5 | H |
| **2.8** Re-pass M0 on SBCL+Allegro | ADR closing ADR 0004 with evidence from both Lisps. | 0.5 | H |
| **2.9** Cross-process SHMEM/ZC on both Lisps | Parameterise shmem-roundtrip.sh:19 and zerocopy-roundtrip.sh:22 by Lisp; add SBCL↔Allegro pairings. | 1–2 | M |
| **2.10** Hot-path gate scope | Decide the REQUIREMENTS §11 item 1 package list (D33). Widen gate-hotpath.sh:39-49 to the per-sample engine paths (dds-disc/dataplane.lisp, dds-rtps/reliable.lisp, the dds-dcps/entities.lisp delivery path). Report the TRACKED count (13 today) per run; it must reach 0 in Phase 6. | 1.5–3 | M |
| **2.11** NFR-MEM at workload level | After D29 resolves REQUIREMENTS against ADR 0102: extend gate-arena so that at documented provisioning, **every hot-path pool is carved before the first sample**, steady state performs no `alloc-static` outside the arena, a fallback counter stays at 0, and high-water < `*static-arena-bytes*`. Close ADR 0095 §1 facts 3–5 (lazy per-pool carves; 64 KiB receive buffers outside the budget) or record them by ADR. Both Lisps. | 3–6 | M |

**Exit criterion (Phase 2):** for each Lisp, every line exits 0 with no `DDS_TEST_ALLOW_SKIP`.
```
make gate-build test corpus fuzz mem gate-mem gate-arena LISP=$L    # corpus = existing vectors;
                                                                    # the 1 deferred vector is the only
                                                                    # entry allowed in a corpus allowlist
                                                                    # owned by WP-5.2 (ADR 0120 extension)
make shmem-xproc zc-xproc LISP=$L   +  cross-Lisp pairings         # PASS
make wire-all                                                       # 0 Malformed, TypeLookup checks run, pcaps identical
make fuzz-soak N=1h LISP=$L                                         # 0 crashes, committed-capture replay included
make gate-hotpath                                                   # widened scope, TRACKED count printed
```
Corpus completeness, Connext-Linux replay and the soak belong to the Phase 5 exit.
**Effort, Phase 2:** about **18–36 ed** (M), plus 5–10 if D30 chooses coverage-guided fuzzing.

---

### Phase 3: CI that enforces both Lisps

| WP | Fix | ed | Conf |
|---|---|---|---|
| **3.1** Hosted SBCL matrix | Latest + prior SBCL (sha256, cached); OpenSSL 3.5 cached (from 0.8); fail-closed skips; add gate-quickload, gate-verification, gate-drivers, gate-nlx and gate-skip-lint; log artifacts. **tshark:** cache a Wireshark ≥ 4.6 build, or run `wire` only on the lab runner and list it as LAB in the computed "not covered" output. | 2.5–4 | M |
| **3.2** AllegroCL self-hosted runner | Ephemeral runner, unprivileged user, per-job container with Allegro mounted read-only and the licence outside GitHub. Per-job network namespace; serialised concurrency; fails 30 days before devel.lic expires (2027-06-15). **Depends on 1.11** (one dependency root). The repo was reported PUBLIC by `gh repo view` once; a later re-check failed, so **re-check before building on it**. | 2.5–4 | M |
| **3.3** Interop workflow (after Phase 4) | Nightly plus dispatch: wire-all → interop-sbcl → interop-allegro; logs and pcaps as artifacts. | 1–1.5 | M |
| **3.4** Recorded results; freshness rule | gate-interop writes `interop/results/<UTC>-<lisp>-<host>-<sha>.txt`. **Per commit, gate-verification only warns** and prints the age of the newest record. **Freshness fails** only in the scheduled check and the release-candidate job (5.14), so hosted CI does not go red by design on every engine commit. | 1–1.5 | M |
| **3.5** commit-msg hook | WP id plus requirement id. | 0.25 | H |
| **3.6** IMPLEMENTATION-PLAN §12 jobs | Nightly `gate-perf` on dedicated hardware, nightly `fuzz-soak`, weekly soak, and CI-published ADR log, verification matrix and interop matrix. | 1.5–3 | M |
| **3.7** Allegro gates merges | **Not** on `pull_request` (public repo, fork code on a self-hosted runner). Use a **merge queue**: the Allegro job runs on `merge_group`, whose code is queued by a maintainer, and is a required check. Branch protection requires both the SBCL and Allegro checks before merge, which satisfies "keep main green" (contract §8) and the two-Lisp DoD (§5). | 1–2 | M |
| **3.8** Fallback if Franz refuses CI use (D16) | A scheduled run on the owner's workstation writes **signed** result files in the 3.4 schema (sha, Lisp, image, gate table, log hashes). A lightweight hosted check verifies the signature and the sha, and serves as the required Allegro status. Every exit criterion that names `gates-allegro.yml` accepts either source. | 1–1.5 | M |

**Exit criterion:** on a merge to main, the SBCL matrix and the Allegro check (runner or signed record) both succeed on the same sha and are required in branch protection.
**Effort:** about **11–18 ed** (M), plus D16 calendar time.

---

### Phase 4: Linux interop lab (prerequisite for every M2–M7 exit and for Phase 6)

| WP | Fix | ed | Conf |
|---|---|---|---|
| **4.1** Connext 7.3.1 Linux x64 (D17) | Install at `/opt/rti_connext_dds-7.3.1`, outside Dropbox. Confirm the arch from `ls $NDDSHOME/lib`. Security Plugins built against OpenSSL 3. **perftest entitlement included** (Phase 6 needs it). Smoke test with rtiddsping and rtiddsspy. | 0.5–1 + RTI calendar | M |
| **4.2** Out-of-tree builds | Mach-O binaries pass the `-x` checks (gate-interop.sh:100, 103; with-fastdds.sh:10). Build under `interop/.build/$(uname -s)-$(uname -m)/`; `git rm --cached interop/fastdds/mutable/mutable_pub`; check ELF magic and that the binary runs. | 1.5–2 | H |
| **4.3** `scripts/interop-env.sh` | Per-OS NDDSHOME, arch, library path, tshark, interface and advertise address. Replace the macOS wiring (gate-interop.sh:98, 134-135, …; security-connext and fastdds runners; capture-corpus; shmem-layout). Peers get **their own** environment and never inherit our OpenSSL. | 2–3 | M |
| **4.4** Host-independent profiles | Template the four profiles pinned to 192.168.2.148, plus fastdds profiles-lan.xml:17. One LAN multicast leg; the rest on loopback with unicast. Track the gitignored profiles (.gitignore:51-52, 72-73, 87-88). | 1–1.5 | M |
| **4.5** Fast DDS 3.6.1 native | Submodules; foonathan → fastcdr → fastdds `-DSECURITY=ON -DCOMPILE_EXAMPLES=ON` into `/opt/fastdds-3.6.1-x64`; regenerate gen/; provenance. | 1–1.5 | H |
| **4.6** Either Lisp on our side | `OURLISP` across gate-interop.sh (22 sites) and the 29 runners; with-allegro.sh translates `--load` to `-L` (legs 15/16 at :475, 489); exits via `dds.pal:exit-process`. Targets interop-sbcl, interop-allegro and interop-all, plus cross-Lisp legs. | 1.5–2 | M |
| **4.7** Live tshark per leg | dumpcap per leg; wire-check predicates run on the capture; the encapsulation id comes from wire-check's Table-60 checks; pcaps feed 2.6. | 1.5–2 | M |
| **4.8** Security runners on Linux | `ldd libnddssecurity.so` precheck: FAIL, never skip. Secure, sign and datasign on both Lisps. | 1.5–2.5 | L |
| **4.9** (optional, D18) Linux NeoDDS ↔ Mac Connext over ssh | Interim cross-machine evidence only. | 1.5–2 | M |
| **4.10** First-green triage | Three runs per Lisp; defects go to their owners. Never loosen MIN_SAMPLES (gate-interop.sh:95). | 3–6 | L |
| **4.11** Connext big-endian probe | Can licensed Connext 7.3.1 on x86_64 emit big-endian XCDR1/2, through a typed serialize-to-buffer API or a representation or endianness knob? Unknown; low confidence. Running licensed Connext to produce vectors is not a clean-room violation, since the corpus already uses captures. **D4 is taken only if this fails**; the outcome goes into an ADR. | 0.5–1 | L |
| **4.12** Interop matrix enforced | `interop/matrix.csv` (from 0.15) is enforced by gate-interop: every cell PASS, explicitly marked out of scope by ADR, or the run FAILS. Add the missing **Fast DDS → us large-data** leg (gate-interop.sh:677 covers us → Fast DDS only) and enumerate the cross-Lisp legs per feature. | 1–2 | M |

**Exit criterion:**
```
make interop-all   # every non-ADR-excluded cell of interop/matrix.csv PASS for OURLISP=sbcl and =allegro,
                   # cross-Lisp cells PASS, per-leg live tshark 0 Malformed / 0 Unknown encapsulation,
                   # results files written. Only Connext-SHMEM cells may be excluded, and only by the
                   # D20 ADR; FlatData legs 17/18 stay IN (R6 is a ship gate, not a test gate).
```
**Effort:** about **15.5–25 ed** (L–M), plus 1.5–2 optional. **The calendar long pole is the RTI licence.**

---

### Phase 5: functional exit-gate gaps, M1 → M7

Runs in parallel with M1 completion **only with D9**. Everything is done on both Lisps, with ADRs, docs and vectors.

| Milestone | WP | Work | ed | Conf |
|---|---|---|---|---|
| **M1** | **5.1** Type system: ADR 0111 slices 2–7, `@optional`, **plus `@external`, `@hashid`, `bit_bound`** | Codec, DSL, type-support, serialized size, key hash, TypeObject (Minimal and Complete), assignability, PBT, and XCDR1/2 vectors in both endiannesses, per slice. Constants from XTypes 1.3 Tables 21/25/31, §7.3.1.x, §7.4.3.5, PID_EXTENDED (Fig. 24, p.126), cross-checked against Linux Connext captures. Slices: char/wchar/wstring 2–4; arrays 3–5; unions 6–10; maps 4–6; bitmask/bitset 3–5; typedef/modules 2–3; @optional 4–6; **@external, @hashid, bit_bound 5–9**; enum TypeObject TK_INT32 → TK_ENUM 2–3; vectors 3–5; assignability 4–8. Float128 only as D32 decides. | **40–69** | L |
| M1 | **5.1b** IDL 4.2 front-end (FR-TOOL-1, MUST) | Parser emitting `define-dds-type` (ADR 0111 §2.1, slice 8; spec acquired 2026-08-07). Accepted against the four `.idl` files in docs/specs plus every committed interop IDL. Off the hot path. The alternative is an owner REQUIREMENTS amendment (D27). The test-only scraper at gen-test.lisp:1305-1334 is not a substitute. | **15–30** | L |
| M1 | **5.2** Big-endian TX and oracles (ADR) | Writer endianness selector (entities.lisp:813; cdr.lisp:66-73). Oracles: Connext BE if 4.11 succeeds; otherwise an independent stack on s390x under qemu (check host-order serialisation first) plus foreign-decoder acceptance; tshark framing. Property test: equal length with fieldwise reversal. Clears the deferred corpus vector. Bench. | 5–10 | M |
| M1 | **5.3** Lossless round-trip and PAL conformance on Allegro, recorded | | 1–2 | M |
| **M2** | **5.4** Best-effort legs | RELIABILITY option on the Connext and Fast DDS Shapes peers (shapes_pub.cxx:39, shapes_sub.cxx:31, shapes_pub.cpp:66, shapes_sub.cpp:98) and `:reliability` on shapes.lisp:228, 454. Legs BE↔BE and RELIABLE→BE, plus a **negative** leg (BE writer with RELIABLE reader must not match; incompatible-QoS fires). tshark shows no HEARTBEAT/ACKNACK. | 1.5–2 | H |
| M2 | **5.5** Linux Connext replay in the fuzz soak | | 0.5–1 | M |
| **M3** | **5.6** Writer-side content filtering, CFT interop with **Connext and Fast DDS** | RTPS 2.5 §8.7.3 / §9.6.4.1; PIDs and the signature rule from the spec tables plus a live capture. Compile once per matched reader, evaluate per sample with no allocation, GAP filtered sequence numbers (reliable.lisp:1165-1203). Nested field names (filter.lisp:18-19). 4 Connext legs and 2–4 Fast DDS legs. Bench. | 12–21 | L |
| M3 | **5.7** DCPS conformance mapping and matrix normalisation | Every DDS 1.4 DCPS clause in P2 mapped to a named test. verification.csv gets one row per requirement with Status-SBCL, Status-Allegro and an evidence path; history goes to verification-log.csv; gate-verification enforces the enum and the evidence. About 45 IDs lack rows today, including FR-RTPS-6, FR-IO-1..4, FR-SEC-1/2, FR-TYPE-6, FR-LANG-2..7, FR-QOS-1/3/4, NFR-DET, NFR-CONC, NFR-OBS and NFR-BUILD. D19. | 6–11 | M |
| M3 | **5.7b** Implement what the mapping exposes (contingency) | Already known: `wait_for_acknowledgments` (0 hits in src); coherent sets beyond the QoS flag (qos.lisp:215); XML QoS profile loader FR-QOS-3 (0 hits); MultiTopic only if D28 includes it. | 10–25 | L |
| **M4** | **5.8** Type evolution against foreign peers | Appendable v1/v2; mutable add/remove/reorder plus @optional; a non-assignable variant that must be **rejected**; both directions; values and defaults asserted. TypeLookup leg B against stock Fast DDS, or an ADR. | 6–10 | M |
| M4 | **5.8b** DynamicType/DynamicData (FR-TYPE-6, MUST) | Reflective, off the hot path, over the TypeObject machinery, both Lisps. Rebase the FR-TOOL-2 spy (shapes.lisp:394) on it if D28 keeps that SHOULD. | 10–20 | L |
| **M5** | **5.9** ZC/FlatData interop and SHMEM scoping | FlatData legs 17/18 on Linux, both Lisps. ADR scoping Connext SHMEM out of "wire-compatible" unless counsel says otherwise (D20). Provenance for shmem-layout. | 2–4 | M |
| M5 | **5.10** LZ4 | Verify scope against FR-PF first; justify the dependency (§9); bench. | 4–8 | L |
| **M6** | **5.11** Bug #15 (16 KB stall), `make soak`, then the soak | Reproduce on both Lisps with DATA_FRAG/NACK_FRAG/HEARTBEAT_FRAG instrumentation; fix. **Create the `make soak` target** (none exists): netns + veth + netem (D21), 64 KB–4 MB samples, late joiners, own peers and Connext. Assert no reliable loss, arena high-water below budget, no wedge. Duration per the ADR, per Lisp. | 8–18 + 2× soak time | L |
| M6 | **5.12** Gate the manual durability scenarios | TRANSIENT and PERSISTENT against rtipersistenceservice and Fast DDS, data-representation, sender-resilience, log, typeobject-corpus, autodiscovery. Retire the Shapes-Demo GUI spikes. | 6–9 | L |
| M6 | **5.12b** (conditional, D28) Multi-channel writers (FR-PF-6, SHOULD; M6 deliverable at IMPLEMENTATION-PLAN.md:149) | Partition traffic by filter across locators/channels; interop leg if Connext supports it. Otherwise an owner REQUIREMENTS/plan amendment drops it. | 6–12 | L |
| **M7** | **5.13** Secure interop with committed evidence | Leg 20 plus sign and datasign on both Lisps on Linux; commit logs and pcaps (`interop/security-connext/.gitignore:1`), test PKI only; measure AES-GCM per-call allocation on both Lisps. | 4–8 | M |
| M7 | **5.13b** Security Logging and Data Tagging plugins (FR-SEC-1) | Builtin logging topic and data-tag PIDs from the DDS-Security spec tables; tests on both Lisps; a Connext leg if supported. Otherwise an owner amendment. | 6–12 | L |
| **Acceptance** | **5.14** Release-candidate job | All gates, every matrix cell, fuzz soak, durability soak, determinism soak, perf (Phase 6), on both Lisps. Evidence index maps every §4 clause to a committed artifact (MILESTONES.md was deleted in 2160f22). Interop freshness fails here (3.4). | 3–5 + machine time | M |

**Exit criterion:**
- Every IMPLEMENTATION-PLAN §4 clause, M0–M7, as reworded by ADRs 0118 and 0.15, has committed evidence for **both** Lisps in the evidence index.
- `make gate-verification` shows Status-SBCL = Status-Allegro = `verified` for every P0–P6 requirement row, and every SHOULD in scope per D28.
- `make corpus` has 0 deferred vectors.
- `make soak` passes on both Lisps.

**Effort:** about **143–274 ed** (L), plus 6–12 if FR-PF-6 is in scope. **Long poles:** 5.1 + 5.1b (55–99), 5.6, 5.7b, 5.8b, 5.11.

---

### Phase 6: performance and determinism (NFR-PERF-1..9, NFR-MEM, NFR-DET)

**Dependencies:** 4.1 (Connext Linux plus **perftest**) → 6.1. D17 covers the perftest entitlement. D22 (second GbE host) → 6.1 PERF-5. 1.13 and 1.14 → 6.3 and 6.5. **6.3 lands before 6.5 is judged:** Allegro latency is not assessed while per-sample allocation is still unresolved.

| WP | Work | ed | Conf |
|---|---|---|---|
| **6.0** Checkpoint (D7) | With 6.1 numbers in hand, the owner either keeps the targets on Allegro or **amends REQUIREMENTS §6, §7.2, §9 and the M5 exit**. The second choice is explicitly "full OK not met on Allegro for M5". | 0.5 | — |
| **6.1** Linux perftest harness against Connext perftest | UDP loopback with ≥ 10^6 samples; two-host GbE (PERF-5); SHMEM/ZC (PERF-6); FlatData (PERF-7); batching (PERF-4). Both Lisps, repeated runs with CIs. `make gate-perf` fails on a ratio regression. | 4–6 | M |
| **6.2** SBCL to 0 B/sample and TRACKED = 0 | Re-bisect the remaining ~224 B; ratchet each step with a bench report each time; the 13 TRACKED sites go to 0. | 10–25 | L |
| **6.3** Allegro to 0 B/sample | After 1.13 and 1.14; expect a different residue. | 10–20 | L |
| **6.4** SBCL to NFR-PERF-1/2/4/5 | p50 is borderline today (SHMEM 1.34–1.59×, UDP 256 B 1.33×); throughput and large data are real work. | 10–25 | L |
| **6.5** Allegro latency and throughput | Never measured. **The largest single risk.** | 15–40 | L |
| **6.6** NFR-PERF-3 tail | Measure and document, per REQUIREMENTS.md:292. | incl. | — |
| **6.7** NFR-PERF-9 discovery | 100 participants, within 2× of Connext (`REQUIREMENTS.md:232`). Multi-process harness via 1.16 / ADR 0116; Allegro seat and process limits per D13; part of `gate-perf`. | 3–6 | L |
| **6.8** NFR-DET determinism soak and gap report | IMPLEMENTATION-PLAN §8 24 h soak per Lisp: latency drift, GC frequency and pause times (Allegro gsgc pause instrumentation through the PAL), queue-depth stability. Publish the per-impl determinism gap against Connext (`REQUIREMENTS.md:249`). | 4–8 + 2×24 h | M |

**Exit criterion:**
```
make gate-perf LISP=…   # NFR-PERF-1,2,4–7,9 ratios met on both Lisps (or the D7 REQUIREMENTS amendment); -3 reported
make gate-mem  LISP=…   # COPY/RETURN/INTO 0.0 B/sample, ceilings 0; gate-hotpath TRACKED = 0
make soak-determinism LISP=…   # 24 h report committed; NFR-DET gap document published per Lisp
```
**Effort:** about **57–129 ed** (L).

---

## 5. Effort summary (ed of work content; calendar per §3)

| Phase | Low | High | Conf | Notes |
|---|---|---|---|---|
| 0 Housekeeping, honesty, OpenSSL, ADRs | 23 | 35 | M | Starts now; needs D1, D2, D29 draft |
| 1 Platform parity | 45 | 81 | L–M | 1A = 7.5–12; 1.14 and 1.18 are the unknowns |
| 2 Gates on both Lisps | 18 | 36 | M | +5–10 for coverage-guided fuzz (D30) |
| 3 CI | 11 | 18 | M | D16; fallback in 3.8 |
| 4 Linux interop lab | 15.5 | 25 | L–M | **RTI licence is the calendar pole** |
| 5 Exit-gate gaps M1–M7 | 143 | 274 | L | +6–12 if FR-PF-6 is in scope |
| 6 Performance and determinism | 57 | 129 | L | Allegro is the risk pole |
| **Total** | **≈ 310** | **≈ 600** | **L** | Conditionals add up to +11–22 more |

The total roughly doubles revision 1 (235–445), for three reasons: previously unplanned MUSTs (IDL, DynamicData, security plugins, annotations), the contingency for DCPS gaps, and NFR-PERF-9 plus NFR-DET.

**Critical path:** owner decisions (D1, D2, D5, D7, D9, D17, D27–D30) → Phase 0 → 1A → (1C ∥ Phase 4 once licensed ∥ 5.1/5.1b) → Phase 5 re-verification → 6.3 → 6.5 → 5.14. **The ranked long poles:**
1. Type system plus IDL (55–99).
2. Allegro perf and 0 B (25–60).
3. RTI licence (calendar).
4. Allegro FFI rewrite (1.14).
5. Bug #15 plus soaks.
6. Writer-side CFT.
7. Counsel for R6 (a ship gate).

---

## 6. Owner actions and decisions

| # | Decision / action | Recommendation | Blocks |
|---|---|---|---|
| D1 | Platform **and image** matrix: Linux x86_64 for both Lisps; macOS arm64 SBCL secondary? Allegro: `alisp` (ANSI, 16-bit) required; `mlisp` (operating contract §6 names it) required or out by ADR; `alisp8`/`mlisp8` out. What image runs in production (`REQUIREMENTS.md:283`)? | alisp required; mlisp per production use; `*8` out | 0.2, 0.5, 1.17, 1.21 |
| D2 | Approve ADR 0118 and the REQUIREMENTS/IMPLEMENTATION-PLAN edits; apply the operating-contract edits (lines 9, 52, 58, 79, 96, 106, 116, 124, and the §6 Allegro invocation) | Approve | 0.2, 0.13 |
| D3 | Fuzz N, soak duration, netem profile | 8 h per Lisp per release, 1 h nightly; 24 h soak | 0.15, 2.6, 5.11 |
| D4 | FR-CDR-8 BE oracle: independent implementation plus foreign acceptance, **only if WP-4.11 shows Connext cannot emit BE** | Decide after 4.11 | 5.2 |
| D5 | Confirm REQUIREMENTS.md:222-232 as the perf gate and retract ADR 0062's "5 %" | Confirm | 0.15, Phase 6 |
| D6 | SBOM licence for AllegroCL | LicenseRef-Franz-proprietary | 0.13 |
| D7 | Allegro perf and 0 B: keep the targets, or **amend REQUIREMENTS §6, §7.2, §9 and the M5 exit** (which means full OK is not met for M5 on Allegro) | Decide at 6.0 with data | Phase 6 |
| D8 | Must DDS-Security refuse to run without PQC? | Split the probe; both capabilities stay required | 1.9 |
| D9 | ADR allowing M2–M7 re-verification in parallel with M1 | Approve | Phase 5 |
| D10 | bordeaux-threads: pin apiv1 or migrate to bt2 | bt2 | 1.10 |
| D11 | Pinned dist vs vendored hot-path deps | Vendor static-vectors and cffi; pin the rest | 1.11 |
| D12 | SBCL 2.2.9 floor | Non-blocking job only | 1.12 |
| D13 | Franz: dumped durability/log service images (**runtime redistribution**, not only CI), extra processes, 100-participant runs | Ask Franz in writing | 1.16, 6.7 |
| D14 | Non-BMP policy (ADR 0117) | Surrogate pairs (16-bit images) | 1.17 |
| D15 | Our own style-warnings as build errors | Yes for "undeclared variable" | 2.2 |
| D16 | Does devel.lic (expires 2027-06-15) permit unattended CI and containers? Host as CI for a public repo? | Get written terms; fallback 3.8 | 3.2, 3.7 |
| D17 | Procure Connext 7.3.1 Linux x64: host, target, Security Plugins, **perftest**, a licence valid on this host and CI; stay on 7.3.1 | Buy | Phases 4 and 6 |
| D18 | Interim Linux NeoDDS ↔ Mac Connext as Allegro evidence | Yes, interim only | 4.9 |
| D19 | verification.csv split, 5-value enum, per-Lisp columns; are waivers allowed under full OK? | Approve; no waivers | 5.7 |
| D20 | R6 counsel and deadline; ADR scoping Connext SHMEM out of "wire-compatible" | Assign now; scope it out | P4 ship, 5.9 |
| D21 | CAP_NET_ADMIN for netns/netem | Grant | 5.11 |
| D22 | Second GbE host. verification.csv (row ~197, not re-verified here) records Allegro on 192.168.2.113 and .180; confirm which host is used for PERF-5 and CI placement | Provide | 6.1 |
| D23 | OpenSSL: vendored /opt build vs a trixie/Docker canonical platform | Vendored /opt | 0.8 |
| D24 | Apply for a real OMG VendorId (`#x01FF` is provisional, message.lisp:21) | Apply now | — |
| D25 | REQUIREMENTS §11 open items 1 (hot-path package list → D33), 3, 4, 6 (IDL → D27) | Decide explicitly | 0.13 |
| D26 | M8 stays out of scope | Confirm | — |
| **D27** | FR-TOOL-1 IDL front-end: build (5.1b) or amend REQUIREMENTS | Build | 5.1b |
| **D28** | Do SHOULDs count? FR-PF-6, FR-XPORT-3/4/6, FR-API-2, FR-TOOL-2, FR-DCPS-7, MultiTopic. Same question for FR-SEC-1 Logging/Tagging (MUST-if-P6) and FR-TYPE-6 (MUST): build or amend | List explicitly; MUSTs built | 5.7b, 5.8b, 5.12b, 5.13b |
| **D29** | NFR-MEM / FR-PF-7 ("allocated once at startup") vs ADR 0102 (chunked growth): amend REQUIREMENTS or revert the code | Amend REQUIREMENTS to "carved before first sample, bounded max, no steady-state growth", gated by 2.11 | 0.13, 2.11 |
| **D30** | Fuzz method: coverage-guided CFFI harness (IMPLEMENTATION-PLAN §8) or an ADR accepting PBT plus replay; shrinking either way | PBT plus replay plus shrinking now; coverage-guided before P6 ship | 0.15, 2.6 |
| **D31** | Approve the transitional DoD ADR 0120 (baseline ratchet, expiring at the Phase 1 exit) | Approve | 0.10 |
| **D32** | Accept, reject or supersede ADRs 0096 (§5), 0098, 0099, 0100, 0111 (including the Float128 deferral) | Decide | 0.3, 5.1 |
| **D33** | Hot-path package list (§11 item 1) | Include dataplane, reliable and the entities delivery path | 2.10 |
| **D34** | Allegro merge gating: merge queue with a runner, or signed-record fallback | Merge queue | 3.7 |

---

## 7. Definition of full OK: everything green on both Lisps

Setup, once per Lisp. For SBCL, run every block twice, once per matrix version.
```
# SBCL:    export LISP=./scripts/with-sbcl.sh SBCL_BIN=<latest>   (repeat with <prior>)
# Allegro: export LISP=./scripts/with-allegro.sh                  (+ mlisp if D1 says so)
# Both:    source scripts/openssl-env.sh ; unset DDS_TEST_ALLOW_SKIP ; no ADR 0120 baselines exist
```
Static gates (run once):
```
make gate-hotpath gate-types gate-pal gate-nocond gate-nlx gate-drivers gate-quickload \
     gate-verification gate-skip-lint gate-sleep-lint gate-ffi-sign-lint gate-quit-lint   # each PASS
git grep -nE '#[+-]clasp|:clasp' -- src '*.asd'                                            # → empty
```
Per Lisp, every line exits 0:
```
make gate-build   # canary falsified; 0 warnings from our systems
make test         # "N passed, 0 FAILED, 0 SKIPPED, 0 PARTIAL"; "leaked threads: 0"; libcrypto mappings 1
make corpus       # all vectors verified, LE+BE, all extensibility kinds and annotations, 0 deferred
make fuzz ; make fuzz-soak N=<ADR>   # 4 security fuzzers included; 0 crashes; Linux Connext replay; shrinking on
make mem ; make gate-mem             # codec 0 B/iter incl. secure arm; COPY/RETURN/INTO 0.0 B/sample; TRACKED 0
make gate-arena                      # workload-level: all pools carved pre-first-sample, fallback 0, high-water < budget
make shmem-xproc zc-xproc            # incl. cross-Lisp pairings
make gate-perf                       # NFR-PERF-1,2,4–7,9 met (or the D7 REQUIREMENTS amendment); -3 reported
make soak ; make soak-determinism    # ADR duration: no reliable loss, no wedge, bounded arena; NFR-DET report committed
```
Cross-Lisp and lab:
```
make wire-all      # tshark ≥4.6: 0 Malformed, TypeLookup checks run, SBCL/Allegro pcaps byte-identical
make interop-all   # every cell of interop/matrix.csv not excluded by ADR: BE (+ RxO negative), reliable, CFT
                   # (Connext + Fast DDS), evolution, frag/large-data both directions, durability, secure
                   # (secure/sign/datasign), cross-Lisp; live tshark per leg; results files fresh
```
CI and documents:
```
gh run list --branch main --limit 1 --workflow gates.yml          # success (SBCL latest+prior)
# Allegro: merge-queue check success on the same sha, OR a valid signed record for that sha (3.8)
gh run list --limit 1 --workflow interop.yml                      # success, ≤ 24 h old
make gate-verification   # every P0–P6 requirement (and every in-scope SHOULD per D28):
                         # Status-SBCL = Status-Allegro = verified, evidence path exists, no gap markers
make sbom && git diff --exit-code sbom.spdx.json                  # SBCL, AllegroCL, OpenSSL 3.5 listed
```
Feature MUSTs are proven by the suites above: the IDL front-end accepts the docs/specs and interop IDL corpus; DynamicData round-trips every corpus type; Logging and Data Tagging plugins have tests (and Connext legs where supported); FR-LOG-3 golden lines carry real line numbers.

---

## 8. Do this week

1. **Owner:** D1 (including the image), D2, D5, D9, D29, D31, D32, then D17 and D16 procurement and D23. These have the longest lead times.
2. **WP-0.1** (CSV only, revert gcm-scratch), **0.2** (ADR 0118), **0.7** (SHMEM OOB with lane poisoning: a live security defect on both Lisps).
3. **WP-0.8 + 0.9** (OpenSSL 3.5 vendored, fail-closed loader), then **0.10 step 1** (report-only accounting), so the true skip count is visible before any further "green" claim.
4. **WP-1.1** (`clock_nanosleep TIMER_ABSTIME`) **+ 1.3 + 1.5 + 1.6**, 7.5–12 ed with 1.2. This gets Allegro to 646/646 passing with only the 1C capabilities allow-listed, per the honest 1A exit. It does **not** make Allegro a gate pass yet.

---

## Appendix A: review notes (rejected or corrected review points)

- **Hot-path debt count (round 1, #14):** the review said 14 TRACKED allocations. A grep over src and gate-hotpath.log both give **13**. The scope-widening part was accepted.
- **FR-PF-6 (round 1, #5):** it is **SHOULD** (`REQUIREMENTS.md:172`), not MUST. It is handled as a D28 scope decision with a conditional WP (5.12b), not as an automatic requirement.
- **Production `uiop:quit` list (round 1, #9):** accepted, and the list was incomplete. dds-shapes/shapes.lisp:170, 570 and 631 were added.
- **Allegro job on `pull_request` (round 1, #18):** rejected for a public repo, because it runs fork code on a self-hosted runner holding a licence. Replaced with a `merge_group` merge queue (3.7) plus the signed-record fallback (3.8).
- **Legs 17/18 (round 2, #15):** the review implied D20/R6 could remove them from the Phase 4 exit. Rejected. R6 is a ship gate, and running interop tests is not shipping. Only Connext-SHMEM cells can be excluded, and only by the D20 ADR.
- **Estimation model (round 2, #14):** the calibration and staffing model were accepted (§3). Partly rejected: history does not make ed estimates "unchecks-able". The commit history contains retractions, so throughput is not verified output. ed stays as the unit of work content, and calendar time is driven by decisions and procurement.
- **Second host 192.168.2.113 (round 1, #26):** not re-verified in this revision. It is recorded as cited (verification.csv row ~197) under D22.
- **Repo visibility:** recorded as PUBLIC via `gh repo view` once; a later re-check failed, so 3.2 says to re-check before relying on it.
- Every other review point in both rounds was accepted as stated and is reflected in the WPs above.