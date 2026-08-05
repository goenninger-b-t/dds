# ADR 0103 — The Clasp/macOS `shm_open` gap closed in C++, not in a call form

- **Status:** **Accepted** — upstream fix landed, wired here, gap closed.
- **Date:** 2026-07-31
- **Requirements at stake:** **NFR-PORT** (three implementations, documented gaps only),
  **FR-XPORT-2** (shared-memory transport).
- **Relates to:** **ADR 0013** (which recorded this gap — this ADR closes it), ADR 0018 (Zero-Copy is
  SBCL-only *partly* because of it), ADR 0064 (gate on the **capability**, not the platform),
  the standing order **no gated tests — fix or delete**.

---

## 1. The gap

`shm_open(2)`'s third argument is **variadic**:

```c
int shm_open(const char *name, int oflag, ...);   /* mode_t when O_CREAT */
```

On Darwin/arm64 variadic arguments are passed **on the stack**, not in registers — the Apple ARM64 ABI
divergence. Clasp's CFFI passed the mode in a register, so `shm_open` read the mode from wherever the stack
happened to point. The mode landed as **garbage**, and because macOS fixes a shm object's permission bits
**at creation** (a later `fchmod` does not repair them), the object was frequently unopenable **by its own
creator**.

The SHMEM transport requires exactly that: the sender opens the **receiver's named segment**. So on
Clasp/macOS-arm64 the whole transport was unusable, `*shmem-enabled*` defaulted `NIL`, UDP carried
everything, and 31 SHMEM / Zero-Copy / loan tests pass-skipped.

## 2. Why the obvious fix was wrong — and stayed wrong for a year

The obvious fix is to use `cffi:foreign-funcall-varargs` on Clasp, as SBCL already does. It was tried on
**2026-07-14** and it *looked* like it worked. It did not. Measured over 30 create+reopen trials:

| call form | re-openable by name |
|---|---|
| plain `foreign-funcall` | 10/30 |
| `foreign-funcall-varargs` — *the "obvious fix"* | 0/30 |
| varargs, mode as `:int` | 10/30 |
| varargs + explicit `fchmod 0600` | 0/30 |

**None of them is correct.** The failure is not "the wrong call form" but "the mode is garbage", and a
*single* trial passes or fails on whether those random bits happened to include owner-rw. A one-shot probe
therefore "proves" whichever answer you went looking for. That is how this was nearly declared fixed.

The real conclusion was recorded instead: **no CFFI call form can fix this, because the defect is in how
Clasp lowers a variadic foreign call on one ABI.** The fix belonged upstream.

## 3. The fix: upstream, in C++

Clasp gained a native POSIX shared-memory layer (`src/core/shmem.cc`, `CORE:SYS-SHM-OPEN` and friends,
plus a Lisp ergonomics layer in `CLASP-POSIX`). The primitive is:

```c++
CL_DEFUN T_mv core__sys_shm_open(const string& name, int oflag, int mode) {
  int fd = ::shm_open(name.c_str(), oflag, (mode_t)mode);
  return Values(make_fixnum(fd), make_fixnum(fd < 0 ? errno : 0));
}
```

The variadic call is emitted by **clang**, which knows the Darwin/arm64 ABI. It is therefore correct **by
construction, on every ABI** — which is precisely the guarantee no call form expressible in CFFI could give.

`dds.pal::%shm-open-create` now routes through it on Clasp. The symbol is looked up with `find-symbol`
rather than read as `CORE:SYS-SHM-OPEN`, so this file still compiles on a Clasp predating the layer; there
the old call form is used and the capability predicate reports `NIL`.

## 4. The evidence

The **same 30-trial protocol** was re-run on the new image, with the three old call forms retained as
**controls** — because a measurement that cannot still detect failure proves nothing. Two independent runs:

| arm | run 1 | run 2 | verdict |
|---|---|---|---|
| plain `foreign-funcall` | 11/30 | 9/30 | control — still broken, reproduces the 2026-07-14 baseline |
| `foreign-funcall-varargs` | 8/30 | 6/30 | control — still broken |
| varargs, mode as `:int` | 10/30 | 10/30 | control — still broken |
| **`CORE:SYS-SHM-OPEN`** | **30/30** | **30/30** | **fixed** |

The controls are the point: they show the machine, the OS and the protocol are unchanged, so the candidate's
30/30 is attributable to the native binding and nothing else.

The mode was additionally observed **directly**, by `fstat`ing the created fd and reading `st_mode` (offset
derived by compiling `offsetof(struct stat, st_mode)` locally, not recalled). The native arm reports
**`0600` on every one of the 60 trials**; the control arms report scattered junk (`4011`, `7651`, `0211`, …).
That upgrades the result from *"the reopen succeeded"* to *"the requested value landed"* — the difference
between inferring a cause and observing it.

**Re-verified 2026-08-05 on the installed Clasp** (`/opt`-style prefix, `3.0.1-112-gc7faba5ec`, arm64), the
image the suite now runs on, same 30-trial protocol with the same three controls:

| arm | reopened | `st_mode` observed |
|---|---|---|
| plain `foreign-funcall` | 7/30 | scattered junk (`07311`, `03611`, `03151`, …) |
| `foreign-funcall-varargs` | 7/30 | junk |
| varargs, mode as `:int` | 8/30 | junk |
| **`CORE:SYS-SHM-OPEN`** | **30/30** | **`0600` on every trial** |

The reopen failures report `errno` **13 (EACCES)** — denied by the garbage mode, which is the mechanism §1
predicts, observed rather than assumed.

⚠️ **The first run of that re-verification reported `0/30` for ALL FOUR arms, including the native one.** The
probe was building shm names longer than macOS's 31-character `PSHMNAMLEN`, so every *create* failed with
`ENAMETOOLONG` and the arm scored zero. It reported a confident wrong answer instead of "could not measure" —
the same failure class §5 is about. **A probe must report why a trial failed, not just that it did**; the
corrected probe prints `errno` for every create and reopen failure, which is what made the second run
trustworthy.

## 5. Why the capability predicate is deliberately **not** a runtime probe

`DDS.PAL:SHM-CREATE-MODE-RELIABLE-P` reports the capability; `DDS.XPORT.SHMEM:SHM-ATTACH-BY-NAME-RELIABLE-P`
re-exports it to a package where reader conditionals are banned. Its sibling
`SYSV-SEM-SETVAL-RELIABLE-P` *probes* at runtime — create a semaphore, `SETVAL 42`, read it back, require 42
— and the natural instinct is to mirror that here.

**That would have been a bug.** SETVAL's failure is *deterministic*: the value silently does not change, so
one trial settles it. This failure is *random*: a broken image passes a single create+reopen trial **9–11
times in 30**, so a one-shot probe would report `T` on a broken image about a third of the time — the very
trap of §2, rebuilt inside the safety mechanism meant to catch it.

Requiring N consecutive successes would work, but buys nothing: when the answer is `T` the native binding
makes it `T` by construction, and a wrongly-`T` predicate makes 31 tests **fail loudly** instead of silently
pass-skipping. Loud is the safe direction to be wrong in. So each arm carries a *reason* instead of a probe:

| arm | reason |
|---|---|
| SBCL, any platform | `FOREIGN-FUNCALL-VARARGS`, verified correct |
| Clasp **with** `CORE:SYS-SHM-OPEN` | compiled C++ — correct by construction on every ABI |
| Clasp **without** it, not Darwin | varargs go in registers; a plain call is correct |
| Clasp **without** it, Darwin | the ADR 0013 gap — `NIL` |

**The generalisation worth keeping: a runtime probe is only valid when the failure it probes for is
deterministic. Against a random failure, a probe is not a weaker gate — it is a lie with a confidence
interval.**

## 6. The second copy of the judgement

`dds.disc:*shmem-enabled*` independently re-derived the platform test — literally a second copy of
`(not (and (eq (pal-impl-name) :clasp) (uiop:os-macosx-p)))` — instead of asking the transport.

Flipping the predicate alone would therefore have left the master switch `NIL`: the transport would report
itself usable while discovery still routed **every sample over UDP**. A green, silent, all-UDP run that no
test asserts against. It now asks `SHM-ATTACH-BY-NAME-RELIABLE-P` through a soft `find-symbol` reference
(dds-disc must still load when dds-xport.shmem is absent).

**Two copies of one capability judgement is one too many** — the second is found only when the first
changes, which is the worst possible moment.

## 7. What this does **not** close

- **`semctl(SETVAL)`** is variadic in the same way and has **no** native Clasp binding, so it stays broken on
  Clasp/macOS-arm64. It was already gated separately and honestly by `SYSV-SEM-SETVAL-RELIABLE-P`, which is
  why closing the shm gap does not silently expose it. It affects only the RTI-Connext SysV SHMEM interop
  path (ADR 0081), not the native transport.
- Of the dds-pal foreign calls, an audit found the variadic ones to be exactly `shm_open`, `semctl` and
  `open` — and both `open` sites pass `O_RDONLY` with **no** third argument, so they are the non-variadic
  2-argument form and were never at risk. Everything else is fixed-arity.
- ADR 0018's "Zero-Copy is SBCL-only" rests on **two** gaps: this one and foreign-SAP atomics. The atomics
  half is already closed (`cas-sap-u64` on Clasp is real hardware CAS via the C atomic runtime). With both
  underlying gaps gone, the residual `:sbcl` guards on the Zero-Copy/loan tests are candidates for removal —
  **a separate slice, to be established by running them, not by this argument.**

## 8. Consequences

- Clasp/macOS-arm64 gains the SHMEM transport: `*shmem-enabled*` now defaults `T` there.
- The **open owner call is resolved by the FIX branch**: the 31 platform skips needed neither a
  fix-in-this-repo nor a deletion — the upstream fix arrived. No coverage was traded away.
- **Measured, not argued:** the Clasp suite reports **629 passed, 0 FAILED** and
  **`skipped: 0 — every test ran`**, against the 31 named skips it printed before. The whole
  SHMEM / Zero-Copy / loan family now executes on Clasp/macOS-arm64.
  ⚠️ Honest residue: several tests still skip individual **arms** on Clasp (`dds.pal:bytes-consed` reads 0
  there, so allocation deltas are unmeasurable; two live-thread arms). Those are a different, pre-existing
  category that the whole-test skip registry does not count, and they are **not** closed by this ADR.
- ⚠️ **Reaching that result first required ADR 0104.** The Clasp image carrying `CORE:SYS-SHM-OPEN` is an
  *installed* Clasp, and an installed Clasp resolves `cffi:foreign-symbol-pointer` through a different CFFI
  copy that returns NIL for the default library — which killed the suite in the UDP receiver thread before
  any SHMEM test ran. The two are independent defects that surface together.
- `NFR-PORT`: the Clasp/macOS SHMEM gap recorded in ADR 0013 is **closed**. ADR 0013's gap sections are
  superseded by this ADR; its analysis of *why* the gap existed remains correct and worth reading.
