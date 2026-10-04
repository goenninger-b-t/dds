# ADR 0123 — A pinned libcrypto is the only libcrypto: fail-closed loading, symbols resolved in that file, one copy mapped

- **Status:** **Accepted** (2026-10-04, owner; recorded in ADR 0124; the user-prefix OpenSSL path is accepted
  by D23). Implemented by WP-0.8 and WP-0.9 of `docs/plans/2026-10-03-sbcl-allegro-full-ok.md`.
- **Date:** 2026-10-04
- **Requirement:** FR-SEC-2 (vetted crypto, no hand-rolling: the vetted library must be the one actually
  called), NFR-SEC-POSTURE (fail closed), NFR-TEST (a run must not report coverage of a library it did not
  use), NFR-PORT (the same rule on SBCL and AllegroCL), the operating contract §4 (no OS constant typed from
  memory) and §5.1 (docstrings)
- **Severity:** **the security suite could silently run against the wrong OpenSSL**. A
  `DDS_DARE_LIBCRYPTO` that pointed nowhere fell back to `libcrypto.so.3` (the system 3.0.13 on the
  reference host), and every OpenSSL symbol was looked up process-wide, so even a correctly loaded 3.5 file
  could answer with another copy's functions
- **Relates to:** ADR 0025 (DARE over OpenSSL ≥ 3.5), ADR 0038/0039 (saved-image pointer re-resolution),
  ADR 0064 (status values, no signals), ADR 0118 (Clasp withdrawn), ADR 0122 (skip accounting: the
  `:libcrypto` capability)

---

## 1. The defect

`src/dds-dare/openssl-ffi.lisp` chose and used libcrypto in three steps, and each could pick the wrong one.

1. **Fallback on a bad pin.** `%resolve-libcrypto-path` returned `$DDS_DARE_LIBCRYPTO` only when
   `probe-file` found it; otherwise it moved on to the Homebrew paths and then `%load-libcrypto` loaded
   `libcrypto.so.3` by name. A typo in the variable, a deleted build, or an unmounted prefix produced a run
   on the system library with no message at all.
2. **Lookup ignored the library.** Every symbol went through
   `(cffi:foreign-symbol-pointer NAME :library *libcrypto*)`. CFFI discards `:library` on both targets:
   `%foreign-symbol-pointer` declares `(ignore library)` and calls `sb-sys:find-foreign-symbol-address`
   on SBCL (`cffi-sbcl.lisp:399-403`) and `ff:get-entry-point` on AllegroCL (`cffi-allegro.lisp:407-410`),
   both read in the installed `cffi-20260101-git`. The lookup is process-wide, so it returns whichever
   definition the global scope finds first.
3. **Two copies are unsafe even with the right pointers.** A `dlopen`ed object's own references to
   exported symbols are bound through the global lookup scope before its local scope. With a system
   libcrypto in the global scope (`LD_PRELOAD`, or any earlier load), calls made *inside* the pinned 3.5
   copy can land in 3.0 (moderate-high confidence from the ELF lookup rules; the check in §2.3 makes it moot
   rather than relying on it).

The plan's evidence table recorded the consequence: on Linux about 99–106 security and DARE test arms had
never run, because the only libcrypto they ever saw was 3.0.13.

## 2. The decision

### 2.1 One candidate when pinned, and a status instead of a fallback

`DDS_DARE_LIBCRYPTO` non-empty makes that file the **only** candidate. If it does not exist or `dlopen`
refuses it, the load ends with status `:pinned-unloadable`; nothing else is tried. Unset or empty keeps the
old search (Homebrew realpaths, then `libcrypto.so.3`, `libcrypto.so`), and whatever it finds is verified
the same way.

The outcome is a **status**, not a signal. ADR 0064 forbids a Lisp condition here and the `gate-nocond`
ceiling is 0, and no sanctioned exempt class fits: a mistyped environment variable is an operator error,
not a can't-happen invariant (`FAILFAST`) and not a store boundary (`SECURITY-FAILCLOSED`). The "hard
error" is enforced where the status is read:

- `dds.dare:libcrypto-status` returns `(values STATUS PATH DETAIL PINNED-P)`.
  `STATUS` ∈ `:ok :absent :pinned-unloadable :symbol-missing :symbol-outside :multiple-libcrypto
  :maps-unreadable`. Everything except `:ok` and `:absent` is a **rejection**.
- On any rejection `*libcrypto*` stays NIL, every `%ossl-sym` box stays NIL, and the rejected handle is
  released with `dds.pal:dl-close`. `dare-available-p` answers `(values NIL REASON :libcrypto)`, with
  `REASON` naming the status, path and detail. Callers that gate on `dare-available-p` refuse on that answer.
- **A caller that does not gate is refused at the call, not crashed.** An empty box alone is not enough:
  the call site would hand NIL to `foreign-funcall-pointer`, which on SBCL is a jump through address 0, a
  memory fault that leaves the image's integrity in doubt (reproduced in review: a bad pin, then
  `(dds.dare:sha-384 #(0 0 0))`, gave `CORRUPTION WARNING … Memory fault at (nil)`). So `%ossl-sym` reads the
  box and, when it is empty, calls `%libcrypto-unavailable`, which signals an error naming the function and
  the loader status. That signal is in the existing `NOCOND(CRYPTO-FFI)` class (owner ruling 2026-07-19: an
  OpenSSL FFI fault that "cannot fire on valid input with a working provider", "a broken … OpenSSL"
  included), sits next to the ~96 rc/NULL checks of that class, and is contained the same way: a DARE
  store's open runs inside the durability runner's start boundary, which sheds the spec and makes
  `durability-service-main` exit 1 (`:service-start-failed`). A rejected library is exactly such a broken
  provider; the cost on an accepted library is one NIL test per call. The capability probes
  (`dare-available-p`, the test preflight) read the box with `%ossl-sym-or-nil` instead, because their job
  is to report a missing symbol, not to call it.
- The loader itself still never signals: choosing and verifying the library is control-plane code that
  reports through `libcrypto-status`, which is what this section's first paragraph rules.
- **The test harness fails the run before its first test** (`dds.tests:assert-libcrypto-preflight`, called
  by `run-all-tests` and by `run-with-skip-report` for `make fuzz`, `make mem`, `make corpus`). This holds in
  every skip mode, so a rejected library can never be read as "the security tests skipped".

### 2.2 Symbols resolved in the opened file (new PAL entries)

`src/dds-pal/pal-dl.lisp` adds, through CFFI and libc only (no reader conditional):

| symbol | what it does | source of truth |
|---|---|---|
| `dl-open path` | `dlopen(path, RTLD_NOW \| RTLD_LOCAL)` → `(values handle reason)` | `dlfcn.h:56`; `bits/dlfcn.h:25,38` |
| `dl-sym handle name` | `dlsym` on that handle: the object and its own dependencies only | `dlfcn.h:64` |
| `dl-close handle` | `dlclose`, for a handle that was opened and then rejected | `dlfcn.h:60` |
| `dl-object-path address` | `dladdr` → `dli_fname` | `dlfcn.h:88-98` |
| `real-path path` | `realpath(path, NULL)`, freed after copy | `stdlib.h:940` |
| `mapped-object-paths stem` | `(values paths readable-p required-p)`: distinct files in `/proc/self/maps` whose basename is a shared-object name of `stem` (`stem.so…`, `stem.<digit>…`, `stem.dylib`), so `libcrypto++.so` or `libcryptopp.so` do not count; `required-p` is T where procfs is part of the platform contract (Linux) | proc(5) |
| `parse-mapped-object-paths text stem` | the pure parser behind it, so the rule is testable | — |
| `+rtld-now+` `+rtld-local+` `+dl-info-size+` `+dl-info-fname-offset+` | the constants above | probe below |

The constants and the `Dl_info` layout were read from glibc 2.39's headers on the reference host and are
confirmed by `scripts/probes/dlfcn-layout.c`, which printed
`RTLD_NOW=2 RTLD_LOCAL=0 RTLD_NOLOAD=4 sizeof_Dl_info=32 dli_fname=0 dli_fbase=8 dli_sname=16 dli_saddr=24`.

`RTLD_LOCAL` keeps the pinned copy out of the global scope, so it cannot satisfy some *other* library's
references by accident. It does not stop glibc from reusing an already-loaded object with the same file
identity; that case is the same file, so it is harmless.

### 2.3 What "verified" means

`%verify-libcrypto` accepts a handle only when all of these hold, checked in this order:

1. `dl-sym handle "OpenSSL_version_num"` is non-NIL. Otherwise `:symbol-missing`: the file is not libcrypto.
2. `dladdr` on that address, through `real-path`, names the same file that was opened. Otherwise
   `:symbol-outside`.
3. `/proc/self/maps` lists **exactly one** libcrypto file, and it is that file. Otherwise
   `:multiple-libcrypto` (or `:symbol-outside` when the one mapped file is a different one). Whether an
   unreadable maps file is a rejection is the PAL's decision (`mapped-object-paths`' third value), not a
   `*features*` test in `dds-dare`: where procfs is required (Linux) it is `:maps-unreadable`; where it does
   not exist (macOS) the check is skipped and `DETAIL` says so; macOS is a secondary platform pending
   decision D1.

Any handle that fails these checks is released with `dl-close`, so a refused file does not stay mapped.

The harness preflight re-reads `/proc/self/maps` **at suite start**, so a second copy mapped after the
loader ran (by a later system load, say) also fails the run.

### 2.4 Restarted images

`%dare-reresolve-foreign-pointers` (the ADR 0038/0039 image-restart hook) now calls the same verified
`%load-libcrypto`, and it rewrites **every** box even when the reload is rejected, so a dumped image whose
pinned library vanished ends with NIL pointers rather than the dangling ones it carried.

### 2.5 Provisioning the pinned library (WP-0.8)

- `scripts/build-openssl.sh` builds **OpenSSL 3.5.9** (latest 3.5 LTS patch on 2026-10-04) from the release
  tarball into `${DDS_OPENSSL_PREFIX:-$HOME/.local/opt/openssl-3.5}`. The plan said `/opt/openssl-3.5`;
  `/opt` is not writable without root on the reference host, so the prefix is a user prefix and is
  configurable. Pins: SHA-256 `603f5602…59a` (published identically on GitHub and openssl.org) and the
  OpenPGP release certificate `B146 647E 45A7 B339 47AB 226B 2A2C 87D1 6169 2D40`. The script refuses a
  checksum mismatch, refuses a signature that fails or that was made by another primary key, and with
  `DDS_OPENSSL_REQUIRE_PGP=1` refuses when the signature cannot be checked at all. It is idempotent (a stamp
  file holds version and hash) and installs libraries, headers and `ssl/` only (`no-docs no-tests`).
- Because the prefix comes from the environment, the script **never deletes a directory it does not own**:
  an existing non-empty prefix without its stamp or provenance file stops the run before any download
  (a mistyped `DDS_OPENSSL_PREFIX=$HOME/.local` must not wipe a tree). It installs into a staging directory
  beside the prefix (`make DESTDIR=…`), swaps it in by rename, runs the self-checks on the swapped-in tree,
  and on a failed check removes it and renames the previous install back, so a failed upgrade never leaves
  a half-installed prefix.
- After installing, it compiles `scripts/probes/ossl-param-layout.c` against the new headers and refuses
  the install if `OSSL_PARAM` differs from the layout `%set-ossl-param-slot` writes. On Linux x86_64 the probe
  printed `sizeof=40 key=0 data_type=8 data=16 data_size=24 return_size=32 INTEGER=1 UNSIGNED_INTEGER=2
  UTF8_STRING=4 OCTET_STRING=5`, matching the arm64 values the code already used.
- `scripts/openssl-env.sh`, sourced, exports **only** `DDS_DARE_LIBCRYPTO` (the realpath of
  `lib64/libcrypto.so.3`). It does not touch `LD_LIBRARY_PATH`, so interop peers, tshark and AllegroCL's
  own SSL modules keep the system library. It fails (return 1) when the build is absent.
- `docker/linux-amd64.Dockerfile` is pinned to the same version and checksum and no longer sets
  `LD_LIBRARY_PATH`.

## 3. Contract change and consumers

This changes two frozen surfaces, so it needs this ADR (operating contract §5):

| surface | change | consumers and migration |
|---|---|---|
| `DDS.PAL` exports | added: `dl-open dl-sym dl-close dl-object-path real-path mapped-object-paths parse-mapped-object-paths +rtld-now+ +rtld-local+ +dl-info-size+ +dl-info-fname-offset+` | additive; first consumer `dds.dare`. No existing symbol changed. |
| `DDS.DARE` exports | added: `libcrypto-status` | additive; consumer: the test harness preflight. |
| `dds.dare::*libcrypto*` (internal) | was a CFFI `foreign-library` object; is now the raw `dlopen` handle | `src/dds-tests/test-support.lisp` was the only reader of `cffi:foreign-library-pathname` on it; it now reads `libcrypto-status`. |
| `dare-available-p` | unchanged signature; `REASON` now names the loader status when no libcrypto was accepted | none |
| every DARE / DDS-Security primitive that calls OpenSSL | with no accepted libcrypto, a call now signals the `CRYPTO-FFI` error from `%libcrypto-unavailable` instead of jumping through NULL | callers already handle that class (it is the same signal an OpenSSL rc/NULL failure raises); the durability runner's start boundary turns it into `:service-start-failed`. |

## 4. Falsifiers

Each was run on the reference host (SBCL 2.2.9) and must keep failing the right way:

| setup | required result |
|---|---|
| `DDS_DARE_LIBCRYPTO=/nonexistent/...` | status `:pinned-unloadable`; `make test` stops before the first test, rc ≠ 0 |
| `DDS_DARE_LIBCRYPTO=<libz>` | status `:symbol-missing` |
| pinned 3.5.9 plus `LD_PRELOAD=libcrypto.so.3` | status `:multiple-libcrypto` (2 mappings); `make test` stops, rc ≠ 0 |
| pinned 3.5.9 alone | status `:ok`, 1 mapping, `dare-available-p` T |
| `DDS_DARE_LIBCRYPTO=/nonexistent/...`, then a DARE primitive, the encrypted-store constructor and `durability-service-main --backend file` | each refuses (`sha-384` and the constructor with the `%libcrypto-unavailable` error, the service with `:service-start-failed`); no memory fault |

In the suite: `dare-libcrypto-loader` (in process: the maps counting rule on synthetic text, missing /
non-ELF / non-libcrypto pins rejected with no handle, dladdr against the wrong file rejected, the accepted
handle is the one in the `%ossl-sym` boxes) and `dare-libcrypto-preload-rejected` (a child Lisp under
`LD_PRELOAD=libcrypto.so.3` must report `:multiple-libcrypto` and exit 3). `LD_PRELOAD` is given a bare name
so ld.so resolves it by its standard search (ld.so(8)) and no system path is typed into the test. The
second test records an ADR 0122 `:libcrypto` skip when nothing is pinned, because then there is nothing to
defend. `dare-libcrypto-rejected-refuses` starts a child Lisp with a nonexistent pin and requires the three
refusals in the last row above and no `CORRUPTION WARNING` or memory-fault report in its output. It was
falsified by restoring the plain box read in `%ossl-sym`: the child then reported
`(:other "Unhandled memory fault at #x0.")` for both the primitive and the constructor, and the test failed.

## 5. What is NOT claimed

- **Not a security fix.** Running the suite against 3.5.9 makes the previously skipped arms execute for the
  first time. On SBCL none failed (§7); whatever fails on AllegroCL is listed in the WP-0.8/0.9 report and
  belongs to WP-1.18, neither fixed nor hidden here.
- **Not CI enforcement.** `.github/workflows/gates.yml` gains a build-and-cache step for the pinned OpenSSL
  behind the off-by-default switch `NEODDS_CI_OPENSSL35` (repository variable, or the `openssl35`
  workflow-dispatch input). Turning it on by default belongs with ADR 0122 step 2 and the ADR 0120 skip
  baseline, as the plan orders it (0.8 → 0.9 → 0.10 step 2); it has not yet run on a hosted runner.
- **Not a statement about the RTI or Fast DDS peers' libcrypto.** They are separate processes and keep
  whatever their own environment gives them.
- macOS: the single-copy check needs procfs and is skipped there, with the reason recorded in `DETAIL`.

## 6. Consequences

- A run's preflight now states which file it used and how many libcrypto files were mapped
  (`libcrypto loaded: ok <path> (pinned by DDS_DARE_LIBCRYPTO)`, `libcrypto mappings: 1: <path>`).
- A wrong or missing pinned library is a stopped run, never a quieter one.
- `dlsym` per symbol happens once at load (and once per image restart). The per-call path is one `svref`
  of a box plus one NIL test. `dds-dare` is not a designated hot-path file (`scripts/gate-hotpath.sh`) and
  the test adds no allocation, so no bench report is filed; the zero-allocation AEAD checks
  (`make mem`, the DARE `seal-into`/`open-into` arms) still pass.

## 7. Evidence (reference host, Linux x86_64, 2026-10-04)

| run | result |
|---|---|
| SBCL 2.2.9, `make test`, pinned 3.5.9 | 652 passed, 0 FAILED; coverage 652 FULL, 0 skip events; 0 leaked threads; rc 0 |
| SBCL 2.2.9, `make test`, unpinned (system 3.0.13) | 652 passed, 0 FAILED; 101 SKIPPED, 107 events (106 `:openssl-pqc`, 1 `:libcrypto` from the preload test) |
| SBCL, `make fuzz` / `make corpus` / `make mem`, pinned | rc 0 each; corpus keeps its one `:verified-elsewhere` deferral |
| SBCL, `make gate-build` (clean cache), `gate-mem`, `gate-arena` (pinned) | PASS each |
| SBCL, `DDS_DARE_LIBCRYPTO=/nonexistent/libcrypto.so.3 make test` | `LIBCRYPTO PREFLIGHT FAILED … pinned-unloadable`, no test run, rc 2 |
| SBCL, pinned + `LD_PRELOAD=libcrypto.so.3 make test` (also with the absolute system path) | `… multiple-libcrypto … 2 libcrypto mappings`, no test run, rc 2 |
| AllegroCL 11.0, `make test`, pinned | 634 passed, 18 FAILED; 0 `:openssl-pqc` events; the 18 are the same non-security set as the WP-0.10 run (timing waits, TypeLookup, RTI-SHMEM attach, `pvms-reliable-bootstrap`) plus its thread-leak entry; no DARE or security test failed. `:alloc-counter` events rise from 5 to 20 (15 PARTIAL), because the now-running security tests' zero-allocation arms cannot measure on AllegroCL (`bytes-consed` is 0 there; plan §0) |
| AllegroCL 11.0, `make test`, unpinned | 633 passed, 19 FAILED: the same 18 plus `durability-microservice-slow-drip-concurrent` (plain TCP, no crypto; 5 of 5 green when re-run in isolation, so recorded as intermittent rather than caused by this change) |

After review (the rejected-state refusal, the `dl-close` of a rejected handle, the PAL-owned procfs decision,
the stem-exact maps rule and the build script's ownership guard and staged swap):

| run | result |
|---|---|
| SBCL 2.2.9, `make test`, pinned 3.5.9 | 653 passed, 0 FAILED; coverage 653 FULL, 0 skip events; 0 leaked threads; rc 0 (653 = 652 + `dare-libcrypto-rejected-refuses`) |
| AllegroCL 11.0, `make test`, pinned | 636 passed, 17 FAILED; 0 `:openssl-pqc` and 0 `:libcrypto` events; the 17 are all in the known non-security baseline (the 18 of the earlier pinned run minus `dcps-type-gate`, which passed this time); the three loader tests and every DARE and security test pass |
| SBCL, `make mem`, pinned | rc 0; `aead-encode`, `aead-decode`, `aead-encode-live`, `aead-live-rx` 0 bytes/sample |
| SBCL and AllegroCL 11.0, the three loader tests run directly, pinned | all pass; the refusal child reports `(:pinned-unloadable :libcrypto :refused :refused :service-start-failed)` |
| SBCL, refusal test with `%ossl-sym` reverted to the plain box read | fails `REFUSE-NO-MEMORY-FAULT`: the child reports `(:other "Unhandled memory fault at #x0.")` |
| `build-openssl.sh` into a scratch prefix: fresh install; rerun; forced reinstall over an owned prefix; reinstall with a deliberately wrong expected layout | installed; no-op; replaced, no staging or backup left; refused and the previous install restored, rc 1 |
| `build-openssl.sh` with `DDS_OPENSSL_PREFIX` = a non-empty directory it did not create | refused before any download, rc 1, directory untouched |
| `gate-nocond`, `gate-pal`, `gate-hotpath`, `gate-types`, `gate-verification`, `gate-skip-lint`, `gate-quit-lint`, `gate-nlx` | rc 0 each; nocond production count 0 (the new signal is in the `CRYPTO-FFI` class) |

On SBCL the previously skipped DARE and DDS-Security arms all pass on 3.5.9. There is no security failure
to hand to WP-1.18 from this run.
