# ADR 0125 — The arena grows to a configured limit, and is fixed on real-time Linux

- **Status:** **Accepted** — implements owner decision D29 of 2026-10-04 (ADR 0124 §2.3). One part of it is
  an **interpretation** of the owner's wording (§2); it is flagged for the owner to confirm or correct.
- **Date:** 2026-10-04
- **Requirement:** **FR-PF-7**, **NFR-MEM**, NFR-DET, REQUIREMENTS §11 item 8 (resolved by this ADR);
  NFR-PORT (the kernel probe sits in the PAL); ADR 0064 (no conditions: an invalid setting is a reported
  status, not a signal)
- **Work package:** D29 of `docs/plans/2026-10-03-sbcl-allegro-full-ok.md` (§6 row D29, WP-0.13 "draft the
  NFR-MEM/FR-PF-7 against ADR 0102 amendment"); the workload-level half stays with WP-2.11
- **Amends:** ADR 0102 (chunked growth is now the *growable* mode, one of two)
- **Relates to:** ADR 0095 (the one process arena), ADR 0101 (exhaustion rejects), ADR 0124 (the decision
  record)

---

## 1. The decision, in the owner's words

> "Arena chunked growth up to a configured upper limit. On RTL we have a fixed arena size."

Two arena modes, chosen once at initialisation:

| mode | budget at init | growth | ceiling |
|---|---|---|---|
| `:growable` | `*static-arena-bytes*` | in `*static-arena-growth-bytes*` chunks, on a carve that does not fit | `*static-arena-max-bytes*` |
| `:fixed` | `*static-arena-bytes*`, reserved in full | none | `*static-arena-bytes*` |

The new special **`*static-arena-mode*`** selects one of them. Its values are `:auto` (the default),
`:growable` and `:fixed`. `:auto` resolves to `:fixed` on a real-time Linux kernel and to `:growable`
everywhere else. Like `*static-arena-bytes*` it is **read once**, when the process arena is created; later
rebinding has no effect until teardown.

**Reaching the ceiling is `:ARENA-EXHAUSTED` in both modes.** Under ADR 0101 that is a RESOURCE_LIMITS
reject. It is never a GC-heap fallback. The mode only decides where the ceiling is.

## 2. The interpretation, flagged for owner confirmation

The directive does not define "RTL" or "fixed arena size". This ADR reads them as follows. **Each line is
an interpretation, not something the owner said.**

1. **RTL = real-time Linux, meaning a kernel built with `CONFIG_PREEMPT_RT`.** It does not mean "runtime
   library" or a specific vendor distribution.
2. **"Fixed arena size" = the initial budget `*static-arena-bytes*`, reserved at init, never grown.**
   `*static-arena-max-bytes*` and `*static-arena-growth-bytes*` are ignored in `:fixed` mode. The other
   reading would make the fixed size `*static-arena-max-bytes*`, reserving the whole upper limit at init.
   This ADR does not take it, because REQUIREMENTS NFR-MEM names `*static-arena-bytes*` as "the
   authoritative knob". An operator who wants the larger figure sets `*static-arena-bytes*` to it.
3. **The default follows the kernel.** If the owner intended "fixed" only as a deployment choice and never
   automatic, the fix is a one-word change: set the default of `*static-arena-mode*` to `:growable`.
4. **An unknown mode value runs `:fixed`, with the reason `:invalid-mode` reported.** The stack raises no
   conditions (ADR 0064). Between the two modes, `:fixed` is the bounded one, so a typo cannot make a
   deployment grow when the operator meant it not to.

## 3. What "reserved in full at init" means here, said plainly

The arena is an **accounting budget, not a slab** (ADR 0102 §2). Each pool's static memory is its own
`dds.pal:alloc-static` region, allocated when that pool is carved. In `:fixed` mode the budget is set to
its final value at init and never changes afterwards. That is what is fixed.

`:fixed` does **not** reserve one contiguous block of `*static-arena-bytes*`, pre-fault it, or `mlock` it.
On a real-time kernel those measures would be worth having. They are not in scope here, because doing them
would turn the arena into a slab, and ADR 0102 §2 warns that a slab must not inherit growth without a new
safety argument. If the owner wants physical pre-reservation on real-time Linux, it is a separate ADR,
recorded in §8 as an open question.

The rest of the determinism story, "every hot-path pool is carved before the first sample", is WP-2.11's
gate. Some pools are still carved lazily on first use (ADR 0095 §1 facts 3–5). In `:fixed` mode such a
carve fits the fixed budget or is refused with RESOURCE_LIMITS. In `:growable` mode it may grow the
budget. WP-2.11 closes this or records it.

## 4. Detecting a real-time kernel — read from kernel source, not from memory

`dds.pal:real-time-kernel-p` returns `(values real-time-p source)` and checks two sources. Both were read
from kernel source on 2026-10-04:

1. **`/sys/kernel/realtime`.** This file is defined in `kernel/ksysfs.c` of the **PREEMPT_RT tree**
   (`git.kernel.org/…/rt/linux-stable-rt.git`; branches `v6.6-rt`, `v6.12-rt` and `v6.19.3-rt1` were
   checked). Under `#if defined(CONFIG_PREEMPT_RT)`, `realtime_show()` prints `"%d\n"` with the constant
   `1`, and `realtime_attr` is listed in `kernel_attrs[]` under `#ifdef CONFIG_PREEMPT_RT`. So the file
   exists only on an RT kernel, and it always reads `1`.

   ⚠️ **The attribute is not in mainline.** `kernel/ksysfs.c` on torvalds/linux master (7.3-rc5, fetched
   the same day) has no `realtime` attribute, although `CONFIG_PREEMPT_RT` itself has been mainline since
   v6.12. Detection through this one file, as ADR 0124 §2.3 proposed, would therefore report a mainline
   PREEMPT_RT kernel as not real-time. The proposal was incomplete, and source 2 closes the gap.
2. **The UTS version string**, read from `/proc/sys/kernel/version`. proc(5) documents this file, and it
   holds the same string `uname -v` prints. Mainline `init/Makefile:28-30` sets
   `preempt-flag-$(CONFIG_PREEMPT_RT) := PREEMPT_RT`. That line comes after the `PREEMPT` and
   `PREEMPT_DYNAMIC` lines, so on an RT kernel it is the value that stands. `:36-38` then builds
   `UTS_VERSION` as `#<version> <SMP> <preempt-flag> <timestamp>`, cut to 64 bytes. The probe looks for the
   whole whitespace-delimited token `PREEMPT_RT`, so `PREEMPT_RTX` does not match. `KBUILD_BUILD_VERSION`
   replaces only the version part of the string, not the flag.

Sources: `:sysfs-realtime`, `:uts-version`, `:not-real-time`, `:not-linux`. Both reads are capped at
`+rt-probe-max-chars+` (256) characters, and the tokeniser never indexes outside the string (operating
contract §4). Neither file needs a reader conditional. The probe lives in `src/dds-pal/pal-rt.lisp` so that
nothing above L0 reads `/sys` or `/proc` itself.

**This host:** Ubuntu 24.04, kernel `7.0.0-38-generic`. `/proc/sys/kernel/version` reads
`#38~24.04.4-Ubuntu SMP PREEMPT_DYNAMIC …`, and `/sys/kernel/realtime` does not exist. The probe returns
`NIL :NOT-REAL-TIME`, and `:auto` resolves to `:growable`, on SBCL and AllegroCL alike. **No real-time
kernel was available, so `:auto` → `:fixed` has been exercised only through fixtures:** the classifier on
fixture strings, and the live probe with `*rt-sysfs-path*` pointed at a fixture file. It has not been run on
a real PREEMPT_RT kernel.

## 5. The code

- `src/dds-pal/pal-rt.lisp` (new): `real-time-kernel-p`, the pure `classify-real-time-kernel`,
  `*rt-sysfs-path*`, `*rt-uts-version-path*` and `+rt-probe-max-chars+`. Exported from `dds.pal`.
- `src/dds-core/arena.lisp`:
  - `*static-arena-mode*`.
  - `resolve-arena-mode` returns `(values :growable|:fixed reason)`. The reason is `:configured`, the
    probe's source, or `:invalid-mode`.
  - `init-arena` takes `:mode` and `:growth-bytes`. In `:fixed` mode it sets the ceiling to the initial
    budget and the chunk to 0. Every size is clamped to `[0, most-positive-fixnum]` before it is stored in
    the arena's fixnum slots, so a bignum setting is reported by its effect, not by a type error (ADR 0064).
  - `%arena-grow-to-fit` refuses growth on a `:fixed` arena **before** it looks at the chunk or the
    ceiling. The guarantee therefore does not rest on `init-arena` having zeroed them.
  - New arena slots `mode`, `mode-reason` and `growth-bytes`. A sub-arena copies them from its parent for
    reporting only.
  - `arena-report` now carries `:mode`, `:mode-reason`, `:max-bytes`, `:growth-bytes` and `:growths`.
  - New `process-arena-status` returns the same plist without `:pools`, or NIL before the process arena
    exists. A status query does not create the arena.
  - `arena-report` and `process-arena-status` are **available on query**. Nothing in the stack logs them
    at startup (`dds-core` sits below the logging layer); an operator or monitoring hook reads them.
  - `process-arena` now creates the process arena under `*process-arena-lock*`. The unlocked lazy creation
    predates this ADR, but `:auto` puts two file reads inside that window, so two participants created
    concurrently on a cold process could each build an arena and one would be lost with its charges. The
    lock is taken on every call; the function runs once per participant/node creation, never per sample.
- **`*static-arena-growth-bytes*` is now read once, at init.** Before this change it was read at every
  growth. All three arena knobs now share the "read once" contract that NFR-MEM states for
  `*static-arena-bytes*`. Every existing test binds it before the arena is created, so none changed
  meaning.

**Hot path:** unchanged. `pool-acquire` and `pool-release` are untouched. The changed functions run when an
arena is created and on the carve-miss path, never per sample. So there is no bench report (operating
contract §5: a bench report is owed for a hot-path change).

## 6. Falsified, both ways

**`run-arena-mode-test`** (suite entry `arena-mode`) has eight arms:

| arm | what it checks |
|---|---|
| FIXED NEVER GROWS | Budget 4 KiB, chunk 1 MiB, max 8 MiB. A 256 KiB carve is refused, and budget and ceiling both stay at 4096. |
| FIXED GUARD (1b) | An arena marked `:fixed` that still carries a chunk and a high ceiling also refuses to grow. |
| CONTRAST | Same numbers under `:growable`: the carve grows and succeeds. |
| FIXED, SUB-ARENA | A carve through a sub-arena is refused, and the root does not grow. |
| FIXED STILL CARVES | Carves within the budget succeed; a carve past it is refused. |
| AUTO FOLLOWS THE KERNEL | `:auto` resolves to `:fixed` exactly when the probe says real-time, and the reason is the probe's source. |
| INVALID MODE | An unknown value resolves to `:fixed` with reason `:invalid-mode`. |
| OVERSIZE CLAMPED (6b) | A bignum budget, ceiling and chunk and a negative chunk build an arena clamped to `[0, most-positive-fixnum]`; nothing signals. |
| READ ONCE | Rebinding the special after init has no effect. `process-arena-status` is NIL before init and reports the mode chosen at init. |
| PAL CLASSIFIER | Every branch, including near-misses (`PREEMPT_RTX`, `PREEMPT_DYNAMIC`, sysfs `0`, sysfs `10`). Also the live probe on a fixture file, and the 256-character read cap. |

ADR 0102's `run-arena-growth-test` now pins `:growable` in all four arms. Without that, `:auto` would
resolve to `:fixed` on an RT host and two of its arms would fail for reasons unrelated to growth.

**`gate-arena`** has two new arms, and it now takes `LISP`:

- **ARM 6, FIXED NEVER GROWS.** A real participant pair runs on a forced-`:fixed` process arena. Afterwards
  budget = ceiling = initial and growths = 0, and a carve one byte larger than what is left is refused.
- **ARM 7, GROWABLE CEILING.** The contrast arm: a carve that fits the ceiling grows, and a carve past the
  ceiling is refused with the budget at or below the maximum.

**Mutants, run on SBCL:**

- `resolve-arena-mode` returning `:growable` for `:fixed`. `gate-arena` went **red** on all three ARM 6
  checks: budget grew to 75 497 472 B, growths 1, and the over-carve succeeded. `run-arena-mode-test`
  failed at `ARENA-MODE-FIXED-REFUSES`.
- The mode test removed from `%arena-grow-to-fit`. `run-arena-mode-test` failed at
  `ARENA-MODE-FIXED-GUARD`.

The source was restored after each mutant.

**Results observed on 2026-10-04, Linux x86_64:**

| run | result |
|---|---|
| SBCL suite (OpenSSL env) | 654 passed, 0 failed, 654 total; 0 threads leaked |
| AllegroCL `alisp` suite (OpenSSL env) | 637 passed, 17 failed, 654 total; 8 leaked `dds-*` threads |
| `gate-arena` SBCL | PASS, all arms |
| `gate-arena` AllegroCL | PASS, all arms |

The AllegroCL failures are the known baseline set: 15 short-wait timing tests, `TLS-INDEX-HIT` and the
rti-shmem `SHMAT-FAILED`. None is arena-related. The baseline was 635/653 with 18 failures, so one timing
test passed this run, and `arena-mode` passes on AllegroCL. `gate-arena` had previously been SBCL-only.

### 6a. Review fixes, and the evidence for them

A review of the first version found five low-severity points. Four were fixed and one was rejected:

- **Bignum settings signalled.** `init-arena` stored `bytes`, `max-bytes` and `growth-bytes` in fixnum
  slots unchecked, so a bignum setting raised a type error. That was against ADR 0064. The values are now
  clamped (§5). Arm 6b checks it. A mutant that removes the clamp turns the arm red on SBCL with the type
  error, and the restored source passes.
- **Unlocked lazy creation of the process arena.** Fixed with `*process-arena-lock*` (§5). No test forces
  the race deterministically; the lock is checked by reading the code and by the full suites.
- **Missing end-to-end evidence for the RTL default.** Recorded in the next paragraph.
- **"Startup arena report" wording.** No production code logs `arena-report`, so the docstring, this ADR
  and the wiki now say it is available on query.
- **Trailing whitespace.** The blank line in `udp-test.lisp` was fixed. The `verification.csv` report is
  rejected: the file uses CRLF line endings on every one of its lines, and `git diff --check` flags the
  `\r` on the added row. The row keeps the file's convention.

**The default an RTL host would get, run end to end (closest available substitute for a PREEMPT_RT run).**
The whole SBCL suite (OpenSSL env) was run with `*static-arena-mode*` set globally to `:fixed` and the
default 64 MiB `*static-arena-bytes*`, twice: once during review and once after the fixes above. Both
runs: 654/654, 0 leaked threads. Final process-arena status after the fixes:
`(:MODE :FIXED :MODE-REASON :CONFIGURED :BYTE-BUDGET 67108864 :BYTES-USED 1966842 :MAX-BYTES 67108864
:GROWTH-BYTES 0 :GROWTHS 0)`. The review run reported 1 901 335 bytes used. So the default fixed budget
holds the full suite with no growth and no refusal, at under 3 % of the budget. The UTS read path was also
checked directly, rather than inferred from a NIL result: `read-rt-probe-file` on
`/proc/sys/kernel/version` returns the real 64-character UTS string on SBCL and on AllegroCL `alisp`.

**Results after the review fixes, 2026-10-04, Linux x86_64:**

| run | result |
|---|---|
| SBCL suite (OpenSSL env) | 654 passed, 0 failed; 0 threads leaked |
| AllegroCL `alisp` suite (OpenSSL env) | 636 passed, 18 failed, 654 total (two runs, and the same count before arm 6b was added); 8 leaked `dds-*` threads; `arena-mode`, `arena-growth`, `arena-exhaustion` and `arena-scratch` ok |
| `gate-arena` SBCL / AllegroCL | PASS / PASS |
| `gate-build` SBCL / AllegroCL | PASS / PASS |
| `gate-mem` SBCL | Two PASS runs on the final tree: INTO 225.3 and 225.8 B/sample (ceiling 239), COPY 447.5 and 447.2 (ceiling 473). One earlier run read INTO 245.7 and failed; the A/B against the pre-fix `arena.lisp` (226.1 / 226.7) showed no difference, so that reading was a run-level outlier (the ADR 0062 quantum). |

The AllegroCL count equals the 18-failure baseline. Compared with the first run in §6, one timing test
fails where it passed before. Which test it is changes from run to run: `durability-microservice-reconnect-bare`
(`MS-RECONB-RECOVERS`) once, and `dcps-type-gate` (`TG4-TIMEOUT-MATCH`, a TypeLookup expiry with
`*typelookup-timeout*` 0 and a 50 ms sleep) twice. Neither touches the arena. Run alone, reconnect-bare
passed 3 of 3. `dcps-type-gate` fails in isolation with or without `*process-arena-lock*` (fresh images:
1 of 4 passed with the lock, 0 of 4 without), so that failure predates this change.

## 7. REQUIREMENTS amended

- **FR-PF-7** and **NFR-MEM** (§7.4) now describe the two modes, `*static-arena-mode*`, the read-once rule
  for all arena knobs, "every hot-path pool carved before the first sample" (gated by WP-2.11), and
  RESOURCE_LIMITS at the ceiling in either mode.
- **NFR-DET** (§7.3) refers to the budget rather than a fixed size.
- **§11 item 8** is marked **RESOLVED 2026-10-04**.

The operating contract's static-arena wording (its §4 and §10, "allocated once at startup") is an owner
edit (ADR 0124 §7) and is not touched here. Until the owner edits it, REQUIREMENTS governs (operating
contract §2).

## 8. Consequences and open points

- Off real-time Linux nothing changes by default: `:auto` resolves to `:growable`, which is ADR 0102.
- On a PREEMPT_RT kernel the default budget is fixed at 64 MiB (`*static-arena-bytes*`). A deployment that
  needs more must raise `*static-arena-bytes*`; raising `*static-arena-max-bytes*` has no effect there.
- **For the owner:**
  - Confirm or correct the four lines of §2.
  - Decide whether `:fixed` on real-time Linux should also physically pre-reserve, pre-fault or `mlock`
    the budget (§3). That would be a separate ADR, because it makes the arena a slab.
  - REQUIREMENTS §11 item 3 (hard real-time) stays open. This ADR is a determinism measure, not a
    hard-real-time guarantee.
- **Not verified:** a run on an actual PREEMPT_RT kernel (§4).
