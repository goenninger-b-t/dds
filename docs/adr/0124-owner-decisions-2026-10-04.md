# ADR 0124 — Owner decisions of 2026-10-04: the plan's D1–D34, five ADRs accepted, five more decided

- **Status:** **Accepted** — a record of owner decisions taken on 2026-10-04. One entry (D29, §2.3) is an
  **interpretation** of a terse directive; it is flagged as such so the owner can correct it.
- **Date:** 2026-10-04
- **Requirement:** the whole of REQUIREMENTS (§4 profiles, §5 FR-*, §6 NFR-PERF, §7 NFR-*, §9 acceptance,
  §11 open issues); the operating contract §2 (REQUIREMENTS takes precedence; a divergence is recorded),
  §3.4 (one milestone at a time) and §5 (Definition of Done: accepted ADRs)
- **Work package:** the decision-recording step that follows WP-0.11 of
  `docs/plans/2026-10-03-sbcl-allegro-full-ok.md` (the governing plan); it closes plan §6 and §8 item 1
- **Accepts:** ADR 0118, ADR 0119, ADR 0121, ADR 0122, ADR 0123 (§3); ADR 0096, ADR 0098, ADR 0099,
  ADR 0100, ADR 0111 (§5, plan decision D32)
- **Partly supersedes:** ADR 0062's reading of NFR-PERF-3 as "p99.99 within 5 % of Connext" (D5);
  ADR 0118 §4's three OPEN rows (D1)
- **Relates to:** ADR 0102 (chunked arena growth; D29), ADR 0120 (transitional DoD, reserved, not yet
  written; D31)

---

## 1. What was decided, and in what words

The owner's message of 2026-10-04, verbatim:

> "A commit always also means approbal to push. alisp only. Arena chunked growth up to a configured upper
> limit. On RTL we have a fixed arena size . Do all else as recommended."

Read against the governing plan:

- **"A commit always also means approval to push."** A process rule, not a plan decision: every commit
  made for this program is pushed to `main` in the same step. It changes nothing in the repository.
- **"alisp only."** Decision D1 (§2.1).
- **"Arena chunked growth up to a configured upper limit. On RTL we have a fixed arena size."** Decision
  D29 (§2.3). This is the one entry whose wording needed interpretation.
- **"Do all else as recommended."** Every other decision in plan §6 takes the recommendation in that
  table's *Recommendation* column. Where the recommendation was itself "decide later" (D4, D7) or
  "ask a third party" (D13, D16, D17, D20, D21, D22, D24), the decision stays open or becomes an owner
  action. §2.2 says which.

The owner also accepted ADRs 0118, 0119, 0121, 0122 and 0123 (§3), accepted the OpenSSL user prefix in
place of `/opt` (D23), and kept the operating-contract file out of scope for this change: **the owner
applies those edits himself** (§7).

## 2. The decisions, D1–D34

Each entry is one of four kinds:

- **Decided:** in force now.
- **Decided, applied by WP-x:** in force now; the code, gate or document change belongs to the named work
  package and has not landed yet.
- **Open:** the decision is deliberately deferred to a named point.
- **Owner action:** something only the owner can do outside the repository. It is listed in §6 and is
  not attempted here.

| # | Question (plan §6) | Outcome, 2026-10-04 | Kind | Where it lands |
|---|---|---|---|---|
| D1 | Platform and image matrix | **AllegroCL `alisp` only.** `mlisp`, `alisp8` and `mlisp8` are out of scope. macOS arm64 is not a target. Both Lisps: Linux x86_64. The production image question is answered by the same rule: `alisp` is the only AllegroCL image this program supports. | Decided | REQUIREMENTS §7.2 and §8; ADR 0118 §4 (Status pointer); README; `docs/wiki/getting-started.md`. §2.1 |
| D2 | Approve ADR 0118 and the REQUIREMENTS / IMPLEMENTATION-PLAN edits; apply the operating-contract edits | ADR 0118 accepted (§3). The REQUIREMENTS and IMPLEMENTATION-PLAN Clasp edits are already in the tree (WP-0.13). The operating-contract edits are **pending owner application** (§7) | Decided; partly pending owner | §3, §7 |
| D3 | Fuzz N, soak duration, netem profile | Fuzz **8 h per Lisp per release** plus **1 h nightly**; soak **24 h**; netem profile as WP-0.15 proposes (1 % loss, 50 ± 10 ms delay, 0.5 % reorder, 0.1 % duplication) | Decided, applied by WP-0.15 (exit-gate wording ADR), 2.6, 5.11 | — |
| D4 | FR-CDR-8 big-endian oracle | Decided **after WP-4.11** (the Connext big-endian probe), as recommended | Open until WP-4.11 | WP-5.2 |
| D5 | Confirm the perf gate; retract ADR 0062's "5 %" | **REQUIREMENTS §6 (the NFR-PERF table, `REQUIREMENTS.md` lines 222-232 at the time of the plan) is the performance gate.** ADR 0062's "NFR-PERF-3 (p99.99 within 5 % of Connext)" (its lines 5 and 358) is **retracted**; NFR-PERF-3 is "within 3×", measured and its gap documented (§9 item 3) | Decided | REQUIREMENTS §6 note; ADR 0062 forward note. History (`bench/report/2026-07-13-*`) is not edited |
| D6 | SBOM licence for AllegroCL | `LicenseRef-Franz-proprietary` | Decided (already applied: `scripts/generate-sbom.py`) | — |
| D7 | AllegroCL perf and 0 B/sample: keep the targets or amend REQUIREMENTS | Decided **at checkpoint WP-6.0 with data**, as recommended. Until then the targets stand unchanged | Open until WP-6.0 | Phase 6 |
| D8 | Must DDS-Security refuse to run without PQC? | **Split the probe**: `crypto-available-p` for DDS-Security, `dare-pqc-available-p` for DARE. **Both capabilities stay required** for full OK | Decided, applied by WP-1.9 | — |
| D9 | Parallel M2–M7 re-verification | **Approved.** This ADR is the record the operating contract §3.4 needs: the Phase 5 re-verification of M2–M7 may run in parallel with M1 completion. It does not let any milestone be declared passed before its predecessor's exit gate passes | Decided | Plan Phase 5 |
| D10 | bordeaux-threads apiv1 or bt2 | **Migrate to bt2** | Decided, applied by WP-1.10 | — |
| D11 | Dependency pinning | **Vendor `static-vectors` and `cffi`; pin the rest** | Decided, applied by WP-1.11 | — |
| D12 | SBCL 2.2.9 floor | Kept as a **non-blocking** CI job only | Decided, applied by WP-1.12 / 3.1 | — |
| D13 | Franz terms: dumped service images (runtime redistribution), extra processes, 100-participant runs | Ask Franz **in writing** | Owner action | §6 |
| D14 | Non-BMP characters on AllegroCL (ADR 0117) | **Surrogate pairs.** Valid because D1 leaves only the 16-bit `alisp` image in scope | Decided, applied by WP-1.17 (an ADR amending 0115/0117) | — |
| D15 | Our own style-warnings as build errors | **Yes, for "undeclared variable"** | Decided, applied by WP-2.2 | — |
| D16 | Does `devel.lic` permit unattended CI and containers? | Get **written terms** from Franz; fallback WP-3.8 (signed records) | Owner action | §6 |
| D17 | Procure Connext 7.3.1 Linux x64 | **Buy:** host and target, Security Plugins, **perftest**, a licence valid on this host and on CI; stay on 7.3.1 | Owner action | §6 |
| D18 | Interim Linux NeoDDS ↔ Mac Connext | **Allowed, as interim evidence only.** The Mac runs the Connext peer; it does not make macOS a target (D1) | Decided, applied by WP-4.9 | — |
| D19 | `docs/verification.csv` shape; waivers under full OK | **Split the file, a 5-value Status enum, per-Lisp Status columns, no waivers** | Decided, applied by WP-5.7. The current file keeps its shape until then | — |
| D20 | Counsel for R6 (FlatData / Zero-Copy patents); ADR scoping Connext SHMEM out of "wire-compatible" | Assign counsel now; scope Connext SHMEM out | Owner action (counsel); the scoping ADR is WP-5.9 | §6 |
| D21 | `CAP_NET_ADMIN` for netns / netem | Grant | Owner action | §6 |
| D22 | Second GbE host | Provide, and confirm which host runs PERF-5 and CI | Owner action | §6 |
| D23 | OpenSSL: vendored build or a canonical distro / Docker platform | **Vendored build. The user prefix `~/.local/opt/openssl-3.5` (`${DDS_OPENSSL_PREFIX:-$HOME/.local/opt/openssl-3.5}`, ADR 0123 §2.5) is accepted in place of `/opt/openssl-3.5`** | Decided (already applied by WP-0.8) | Plan paths updated |
| D24 | Real OMG VendorId | Apply now. `#x01FF` stays the documented provisional id (FR-RTPS-2, `src/dds-rtps/message.lisp`) until OMG assigns one | Owner action | §6; REQUIREMENTS §11 item 4 |
| D25 | REQUIREMENTS §11 open items 1, 3, 4, 6 | Items 1, 4 and 6 **decided explicitly**; item 3 **proposed, pending owner confirmation** (§4) | Decided (items 1, 4, 6); item 3 open pending owner | REQUIREMENTS §11 |
| D26 | M8 stays out of scope | **Confirmed.** P7 / M8 is out of scope for this release, except FR-TOOL-1 (a MUST, delivered under M1 per D27) and FR-TOOL-3 (the tshark wire harness, an M2 exit instrument) | Decided | REQUIREMENTS §4 P7; IMPLEMENTATION-PLAN M8; README |
| D27 | FR-TOOL-1 IDL front-end: build or amend | **Build** (WP-5.1b, an M1 deliverable). FR-TOOL-1 stays MUST | Decided, applied by WP-5.1b | REQUIREMENTS §11 item 6 |
| D28 | Do SHOULDs count? | **MUSTs are built. Every tagged SHOULD is classified blocking or backlog** (§2.2); the backlog does not block full OK. **FR-PF-6 stays an M6 deliverable.** FR-SEC-1 Logging / Data Tagging (MUST-if-P6) and FR-TYPE-6 (MUST) are MUSTs and are built (WP-5.13b, WP-5.8b) | Decided | REQUIREMENTS §0 (new list) |
| D29 | NFR-MEM / FR-PF-7 against ADR 0102 | **Chunked growth up to a configured maximum by default; on real-time Linux (RTL) the arena is fixed.** Interpretation in §2.3 | Decided, **interpretation flagged**; REQUIREMENTS text and code in the next work package | REQUIREMENTS FR-PF-7, NFR-MEM, §11 item 8 (next WP) |
| D30 | Fuzz method | **PBT plus capture replay plus shrinking now; coverage-guided before P6 ships** | Decided, applied by WP-0.15 / 2.6 | — |
| D31 | Transitional DoD ADR 0120 | **Approved**, in the form plan WP-0.3(b) specifies (baseline ratchet; baselines shrink-only; expires at the Phase 1 exit). ADR 0120 is not written yet; it carries this approval when it is | Decided; ADR text pending (WP-0.3(b)) | — |
| D32 | Accept, reject or supersede ADRs 0096, 0098, 0099, 0100, 0111 | **All five accepted**, with the reasons and the 0096 §5 choice in §5 | Decided | §5; the five Status lines |
| D33 | Hot-path package list (§11 item 1) | **Add** the per-sample engine paths: `src/dds-disc/dataplane.lisp`, `src/dds-rtps/reliable.lisp`, and the delivery path in `src/dds-dcps/entities.lisp` | Decided, gate widening applied by WP-2.10 | REQUIREMENTS NFR-CLOS and §11 item 1 |
| D34 | AllegroCL merge gating | **Merge queue** (`merge_group`) with a self-hosted runner; the signed-record fallback (WP-3.8) only if D16 refuses CI use | Decided, applied by WP-3.7 | — |

### 2.1 D1 in detail: what "alisp only" removes

- **WP-1.21** (the conditional `mlisp` leg) is dropped.
- **WP-1.17**'s surrogate-pair policy (D14) is complete: it was valid "only for 16-bit images", and
  `alisp` is the only image left.
- `scripts/with-allegro.sh` already defaults to `alisp` (`ALISP_BIN`). It does not yet **refuse** an
  `ALLEGRO_BIN` that names another image. That refusal is a launcher change and is not part of this
  documentation-only change (§8).
- The code keeps its Darwin arms (`shm-create-mode-reliable-p`, the `/proc/self/maps` skip in ADR 0123
  §2.3). They are code for a non-target: nothing gates on them, and no claim may be made for macOS arm64.
  Whether to delete them is a separate decision, not taken here.
- The operating contract's §6 AllegroCL invocation names `mlisp`; changing it to `alisp` is one of the
  owner's pending edits (§7).

### 2.2 D28 in detail: the SHOULD list

Every requirement tagged `(SHOULD)` in REQUIREMENTS §5 (thirteen of them), plus the optional and MAY items
the full-OK question touches. The rule applied: a SHOULD **blocks** full OK when it is already a milestone
deliverable or exit instrument, or when another clause effectively mandates it; otherwise it is
**backlog**. A backlog item keeps its REQUIREMENTS §0 meaning (a deviation needs an ADR); it just does not
gate full OK. The plan named eight items (FR-PF-6, FR-XPORT-3/4/6, FR-API-2, FR-TOOL-2, FR-DCPS-7,
MultiTopic); the others are classified here by the same rule so the exit criterion can be evaluated, and
that classification is this record's, stated so it can be checked.

| Requirement | Level | Disposition | Reason |
|---|---|---|---|
| FR-CDR-7 (generated per-type monomorphic codecs) | SHOULD | **Blocking** | The hot-path purity rule (REQUIREMENTS §1.3 item 1, NFR-CLOS) makes generated monomorphic codecs mandatory on the data path |
| FR-LANG-5 (no data-path consing) | SHOULD | **Blocking** | NFR-DET restates it as a MUST ("No data-path consing (FR-LANG-5)") |
| FR-DISC-4 (initial peers, unicast-only, participant index ranges) | SHOULD | **Blocking** | FR-DISC-5 says the initial-peers mechanism MUST cover the no-multicast LAN case; §8 calls unicast-only mode required for deployment realism |
| FR-PF-5 (LZ4 serialization-time compression) | SHOULD | **Blocking** | An M5 deliverable (IMPLEMENTATION-PLAN §4 M5) |
| FR-PF-6 (multi-channel DataWriter) | SHOULD | **Blocking** | An M6 deliverable (IMPLEMENTATION-PLAN §4 M6). WP-5.12b is no longer conditional |
| FR-TOOL-3 (tshark wire conformance harness) | SHOULD | **Blocking** | The M2 exit's instrument ("tshark-validated") |
| FR-LANG-1b (CLOS for the entity model) | SHOULD | **Not gating** | A design preference. Its dispatch-free fast-path entry is a MUST clause inside it and is verified as such (NFR-CLOS) |
| FR-XPORT-3 (UDPv6) | SHOULD | **Backlog** | Not a milestone deliverable; plan-named |
| FR-XPORT-4 (TCP, TCP-WAN) | SHOULD | **Backlog** | Not a milestone deliverable; plan-named |
| FR-XPORT-6 (`sendmmsg` / `recvmmsg`, scatter/gather) | SHOULD | **Backlog** | Not a milestone deliverable; plan-named |
| FR-API-2 (ISO C++ PSM-shaped API layer) | SHOULD | **Backlog** | Not a milestone deliverable; plan-named |
| FR-TOOL-2 (spy on DynamicData) | SHOULD | **Backlog** | P7 / M8, out of scope (D26); plan-named |
| FR-DCPS-7 (`write_w_timestamp`, `dispose`, `unregister_instance`, `lookup_instance`, `get_key_value`, coherent sets, `wait_for_acknowledgments`) | SHOULD | **Backlog** for the parts not yet built; what is built stays tested | Plan-named |
| MultiTopic (FR-DCPS-1) | optional (not a SHOULD) | **Backlog** | FR-DCPS-1 calls it optional |
| FR-DISC-5 (Cloud-Discovery-equivalent rendezvous) | MAY | **Not gating** | Deferred (REQUIREMENTS §13); its initial-peers clause is carried by FR-DISC-4 above |
| FR-TOOL-4 (monitoring / statistics export) | MAY | **Not gating** | P7 / M8, out of scope (D26) |

Untagged `(SHOULD)` clauses inside MUST requirements and the REQUIREMENTS §7 NFR sections (GC tuning hooks,
the arena report, thread-affinity controls, soak tests, a minimal dependency footprint, …) do not block
full OK by themselves; one blocks only where REQUIREMENTS §9, a milestone exit gate or a decision in this
record names it (for example D3's 24 h soak).

### 2.3 D29: the interpretation, flagged for owner correction

The directive is two sentences: *"Arena chunked growth up to a configured upper limit. On RTL we have a
fixed arena size."* It is implemented in the next work package, and read as follows. **This is an
interpretation; the owner may correct any line of it.**

- **RTL** means a real-time Linux deployment: a `PREEMPT_RT` kernel. The detection proposed is
  `/sys/kernel/realtime` reading `1`. That path and its semantics must be confirmed from the kernel
  source or documentation in the implementing work package, not from memory (operating contract §4).
- **Default (not RTL):** ADR 0102 stands. The arena's budget may grow in configured chunks
  (`*static-arena-growth-bytes*`) up to `*static-arena-max-bytes*`.
- **On RTL:** the arena is **fixed**. It is allocated once, at initialisation, at its full size, and growth
  is disabled (the maximum equals the initial size).
- **An explicit override:** a special, for example `*static-arena-mode*` with the values `:auto`,
  `:growable` and `:fixed`, read once at initialisation like `*static-arena-bytes*` and documented. `:auto`
  selects `:fixed` on RTL and `:growable` elsewhere.
- **Reaching the limit, in either mode, is RESOURCE_LIMITS** (reject or block, surfaced with a metric),
  **never a GC-heap fallback** (NFR-MEM, ADR 0101).
- REQUIREMENTS FR-PF-7, NFR-MEM and §11 item 8 are amended in that work package, and §11 item 8 is marked
  RESOLVED with the date there. This ADR does **not** edit that text.

## 3. ADRs accepted on 2026-10-04, and the pointers applied

| ADR | Subject | Status now |
|---|---|---|
| 0118 | Clasp withdrawn; SBCL and AllegroCL are the two targets | Accepted (2026-10-04). Its §4 OPEN rows are decided by D1 (§2.1): out of scope |
| 0119 | SHMEM lane poisoning (WP-0.7) | Accepted (2026-10-04) |
| 0121 | `exit-process` and the shutdown-hook chain (WP-0.11) | Accepted (2026-10-04) |
| 0122 | One skip channel, step 1, report-only (WP-0.10) | Accepted (2026-10-04); step 2 (enforcement) remains plan work |
| 0123 | Fail-closed libcrypto loader and the pinned OpenSSL 3.5.9 (WP-0.8, 0.9) | Accepted (2026-10-04). Its prefix deviation from the plan is accepted by D23 |

ADR 0118's header and §3 name the ADRs it supersedes and say a superseded ADR "receives at most a one-line
Status pointer to this one, applied on acceptance". Applied, one line each, bodies untouched:

| ADR | Pointer added to its Status line |
|---|---|
| 0001 (M0 baseline Clasp-first) | Superseded by ADR 0118 |
| 0103 (the Clasp/macOS `shm_open` gap closed in C++) | Superseded by ADR 0118 |
| 0003 (SBCL as the second target) | Partly superseded by ADR 0118 (§1, §3): the Clasp leg is withdrawn; its "Clasp + SBCL" evidence reads as SBCL-only |
| 0004 (M0 passed by owner command) | Partly superseded by ADR 0118 (§3): M0 must be re-passed on SBCL and AllegroCL |
| 0013 (PAL SHMEM and M1 atomics) | Partly superseded by ADR 0118 (§1, §5): its Clasp sections have no subject |
| 0104 (libc symbol pointer independent of the loaded CFFI) | Partly superseded by ADR 0118 (§5(a)): the Clasp branch of `%global-symbol-pointer` is removed |

ADRs 0119, 0121, 0122 and 0123 supersede nothing, so they add no pointers.

## 4. REQUIREMENTS §11 items decided under D25

| Item | Decision |
|---|---|
| 1. The hot-path package list | **Resolved (D33).** The NFR-CLOS list gains the per-sample engine paths: `dds-disc` dataplane, `dds-rtps` reliable, and the `dds-dcps` entities delivery path. `gate-hotpath` does not scan them yet; WP-2.10 widens it |
| 3. Hard real-time? | **Proposed, pending owner confirmation, not decided: no hard-real-time tail commitment.** NFR-PERF-3 would stay "measured and its gap documented" (§9 item 3), and the §6 note would stand: a node that needs hard-real-time tail parity is delegated to Connext Micro/Cert. Real-time Linux deployments would get a fixed arena (D29) as a determinism measure, not as a hard-real-time guarantee. **The owner did not state this.** D25's recommendation was only "decide explicitly", so "do all else as recommended" supplies no content for item 3; this proposal is inferred from the D29 directive plus the existing §6 and §9 text. The owner's RTL directive may instead point toward real-time ambitions; REQUIREMENTS §11 item 3 stays open until the owner confirms or replaces it |
| 4. VendorId | **Decided: apply to OMG now (D24, an owner action).** Until an id is assigned, `#x01FF` is the documented provisional development id (FR-RTPS-2) |
| 6. IDL compared with the s-expression DSL | **Resolved (D27).** Both: the s-expression DSL came first and exists; the IDL 4.2 front-end is built as an M1 deliverable (WP-5.1b) and emits `define-dds-type` forms (ADR 0111 §2.1) |

Item 3 stays open as a proposal pending owner confirmation. Item 5 (FlatData / Zero-Copy patent clearance) stays open as owner action D20. Item 8 (D29) is amended in
the next work package (§2.3).

## 5. D32: the five ADRs that shipped without acceptance

Each was read in full on 2026-10-04 and its shipped mechanism located in `src/`.

| ADR | Decision | Reason (one line) |
|---|---|---|
| 0096 | **Accept** (§1–§4 as written; §5 settled by ADR 0097) | The slot-return fix (`%zc-release-marker`, `src/dds-disc/dataplane.lisp`) closes a real silent pool leak, and its two-arm test shows it is neither too weak nor too strong |
| 0098 | **Accept** | The 16 B/call nesting cost was measured to the construct; `%lazy-carve-pool` and `make gate-nlx` (a form walker) keep it from coming back |
| 0099 | **Accept** | A POSIX shm name is host-global, so the domain must be in it; `seg-name-for-guid` takes the domain and the token now covers all 12 prefix octets, closing a shared-lane corruption hazard |
| 0100 | **Accept**, with the AllegroCL gap recorded | The attach cache was raced from four threads; the lock costs +18 ns/send at 0 B. `dds.pal:internal-bug-p` is NIL on AllegroCL, so the latch is dead code there; WP-1.19 owns closing it |
| 0111 | **Accept, Float128 deferred** | Type system before front-end is the right order and the slice plan stands; Float128 stays deferred because neither target has a 128-bit float (both map `long-float` to `double-float`). Its §5 "SBCL + Clasp" reads as SBCL and AllegroCL (ADR 0118 §3). Its note that `docs/specs/idl-4.1.pdf` is a misnamed duplicate stands; it is not acted on here |

**ADR 0096 §5, the concrete choice.** §5 left one question open: should a writer's reliability control
traffic (periodic HEARTBEAT, the late-joiner HEARTBEAT, the ACKNACK repair and its GAP) to a same-host SHMEM
peer take the DATA's SHMEM lane, or stay on UDP? ADR 0097 answered it on 2026-07-30 under an owner
directive ("put control traffic on the same lane as the DATA — that is non-negotiable"). That answer
shipped (`%prefix-shmem-dest` at the HEARTBEAT and repair call sites in `src/dds-disc/dataplane.lisp`) and
is tested (`ctl-lane-peer-is-shmem` in `src/dds-tests/integration-test.lisp`). **The choice is to keep it:
control traffic rides the DATA's lane.** It is also the least-risk option, for three reasons:

1. It is the code that runs and is tested today. Any other choice means a revert on the reliable path of
   every same-host writer.
2. Going back to UDP would bring back the ordering hazard §5 itself describes: a HEARTBEAT on UDP can
   overtake the DATA still unread in the SHMEM ring, so the reader NACKs samples it already holds.
3. ADR 0097 measured the shipped behaviour at 2249 → 800 writer datagrams for 400 samples. The regression
   it once exposed was a separate defect, fixed by ADR 0099, not one this choice introduced.

## 6. Owner actions (outside the repository, not attempted here)

| # | Action | Blocks |
|---|---|---|
| D13 | Written terms from Franz: dumped durability/log service images (runtime redistribution, not only CI), extra processes, 100-participant runs | WP-1.16, 6.7 |
| D16 | Written terms from Franz: does `devel.lic` (expires 2027-06-15) permit unattended CI and containers, and a host serving CI for a public repository? | WP-3.2, 3.7 (fallback WP-3.8) |
| D17 | Buy RTI Connext 7.3.1 for Linux x64: host and target, Security Plugins, perftest, a licence valid on this host and on CI | Phases 4 and 6 |
| D20 | Assign counsel and a deadline for R6 (FlatData / Zero-Copy patents) | P4 ship; WP-5.9 |
| D21 | Grant `CAP_NET_ADMIN` for netns / netem | WP-5.11 |
| D22 | Provide the second GbE host; confirm which host runs PERF-5 and CI | WP-6.1 |
| D24 | Apply to OMG for a real VendorId | REQUIREMENTS §11 item 4 |

## 7. Pending owner application: the operating-contract edits

The operating-contract file is outside this change; the owner edits it himself. The edits it needs:

- **From ADR 0118 (D2):** Clasp removed from the target list and the milestone text; the lines ADR 0118 §5(b)
  lists (9, 52, 58, 79, 96, 106, 116, 124) and the §6 per-implementation invocations.
- **From D1:** the §6 AllegroCL invocation names `alisp` (it names `mlisp` today).
- **From D29:** the §4 and §10 static-arena wording ("allocated once at startup") brought in line with the
  amended NFR-MEM once the next work package lands it.
- **From D9:** §3.4 / §11 ("do not begin a milestone until the prior milestone's exit gate passes") may
  point to this ADR as the recorded exception for the M2–M7 re-verification.

Until the owner applies them, REQUIREMENTS and this ADR govern wherever the two disagree (operating
contract §2: REQUIREMENTS wins).

## 8. Consequences

- **Nothing in `src/` changes.** This is a record. Every "applied by WP-x" entry is owed by that work
  package, and the plan's §6 table now carries a *Decided 2026-10-04* column so each one stays traceable.
- **Still open:** D4 (after WP-4.11), D7 (at WP-6.0), REQUIREMENTS §11 item 3 (a proposal pending owner
  confirmation, §4), §11 item 5 (D20), and §11 item 8 until the next work package lands D29. The D29
  interpretation (§2.3) is likewise flagged for owner correction.
- **Five ADRs that had shipped as Proposed are now Accepted**, so the Definition of Done's "accepted ADR"
  condition no longer fails on them. ADR 0120 is still unwritten; D31 approves it in advance.
- **The scope is narrower and stated:** one AllegroCL image, Linux x86_64 only, M8 out, and every tagged SHOULD
  classified as blocking or backlog (§2.2): six plan-named SHOULDs plus the optional MultiTopic in the
  backlog, six SHOULDs blocking. Each of these was an unstated assumption before; each is now a line someone can
  check.
- **Follow-ups this change does not make:** `scripts/with-allegro.sh` refusing a non-`alisp` image (D1);
  deleting the Darwin-only code arms (D1); rewording the docstring at `src/dds-pal/pal-net.lisp:1139`, which
  still says "ADR 0118 §4 leaves macOS to owner decision D1", to "macOS is not a target (ADR 0124, D1)" in
  the next work package that touches `src/` (it is a source file and this change is documentation-only);
  the D29 code and text (next work package).
