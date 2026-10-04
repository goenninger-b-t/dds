# ADR 0122 — One skip channel: every skip is named, charged to a test, and counted (step 1, report-only)

- **Status:** **Accepted** (2026-10-04, owner; recorded in ADR 0124). Step 1 implemented by WP-0.10 of
  `docs/plans/2026-10-03-sbcl-allegro-full-ok.md`. Step 2 (enforcement) is not part of this change.
- **Step 2:** ADR 0128 (`make test` enforces the ADR 0120 skip baseline; `DDS_TEST_ALLOW_SKIP`).
- **Date:** 2026-10-04
- **Requirement:** NFR-TEST (a pass count must not be wider than the coverage behind it), the operating
  contract §5 ("never mark work done with a red gate or a skipped interop/byte-exact check"), NFR-PORT (the
  same suite must say what it did NOT check on each implementation), FR-LANG-6 (docstrings)
- **Severity:** **coverage misreported**: on 2026-10-03 the SBCL suite printed `646 passed` and
  `skipped: 0 — every test ran` while about 100 tests had returned early behind a bare `SKIP` print
- **Relates to:** ADR 0064 (capabilities, not platforms; `dare-available-p` returns a status), ADR 0013
  (SHMEM by-name attach), ADR 0118 (Clasp withdrawn), ADR 0120 (transitional DoD and the skip baseline that
  step 2 needs; reserved, not written here), ADR 0121 (the run summary this extends)

---

## 1. The defect

A test that cannot run on a host (no OpenSSL 3.5, no allocation counter, no Zero-Copy SAP primitives on
this implementation) did one of three things, and none of them was counted:

1. **Printed and returned.** About 100 sites of the form
   `(format t "~&  [x] SKIP — OpenSSL >= 3.5 not available: ~a~%" reason) (return-from run-x-test t)`.
   The runner saw a normal return and printed `ok`.
2. **Called the registry, which deduplicated and dropped the capability.** `dds.pal:note-test-skip
   NAME REASON` kept one `(name . reason)` pair per name (`pushnew … :key #'car`). 33 sites used it, all for
   SHMEM attach-by-name; none fired on this host.
3. **Skipped silently.** An assertion inside `(when (eq (dds.pal:pal-impl-name) :sbcl) …)`, or written as
   `(or (not sbcl) …)` / `(or (zerop (dds.pal:bytes-consed)) …)`, passed on AllegroCL without measuring
   anything, with no output at all.

The run summary read only the registry of (2), so it printed `skipped: 0 — every test ran`.

## 2. The decision

### 2.1 One channel

`(dds.tests:note-skip SITE CAPABILITY REASON &key (scope :test))` is the only way a test reports a skip.

- **SITE** names what did not run (a test, or `test/arm`). **REASON** is the printed explanation.
- **CAPABILITY** must be a member of the closed vocabulary (§2.2), or `note-skip` signals an error, which
  fails the calling test.
- **SCOPE** is `:test` (the test returned without running: the default) or `:arm` (one assertion block was
  skipped, the rest ran).
- **Every call is one event.** No dedup: two calls are two events.
- **Each event is charged to the running test**, `dds.tests:*current-test*`, which `run-all-tests` sets with
  `setf` (not `let`) around each test, so a skip noted from a thread the test spawned is still charged to it.

Helpers built on it: `note-dare-skip` (capability from DARE itself, §2.3), `note-bench-skip` (a bench
harness: also writes the fact into its report file), `run-with-skip-report` (the accounting around a single
entry point, for `make fuzz`, `make mem` and `make corpus`).

**The registry moved out of `dds.pal`.** Test bodies that live in production files (`dds-xport/shmem.lisp`,
`dds-disc/secure-sedp.lisp`, `dataplane.lisp`, `volatile-secure.lisp`) load before the harness and cannot
name its package, so the PAL keeps one seam: `dds.pal:note-test-skip SITE CAPABILITY REASON &optional
(scope :test)` forwards to `dds.pal:*test-skip-hook*`, which the harness installs when it loads. With no hook
installed it writes the skip to `*error-output*`. `dds.pal:test-skips` and `dds.pal:reset-test-skips` are
removed; their only caller was the old summary.

### 2.2 The closed vocabulary

`dds.tests:*skip-capabilities*`. The governing plan fixed seven; this ADR adds three, each for a site that
no other capability describes truthfully.

| capability | means | today's gate |
|---|---|---|
| `:openssl-pqc` | a libcrypto is loaded but is older than 3.5.0 or cannot fetch ML-KEM-1024 | `dds.dare:dare-available-p` 3rd value |
| `:libcrypto` | no libcrypto could be loaded (or it lacks `OpenSSL_version_num`) | `dds.dare:dare-available-p` 3rd value |
| `:alloc-counter` | `dds.pal:bytes-consed` does not move, so an allocation assertion cannot be measured | `(zerop (bytes-consed))` or `pal-impl-name :sbcl` |
| `:zc-sap-primitives` | the Zero-Copy / FlatData SAP primitives are not cleared for this implementation | `pal-impl-name :sbcl` (until WP-1.15) |
| `:shm-attach-by-name` | a shm segment cannot be reliably re-opened by name | `shm-attach-by-name-reliable-p` |
| `:subprocess-mode` | the durability service's subprocess mode is unavailable | `pal-impl-name :sbcl` (`runner.lisp`) |
| `:rx-store-pool` | `dds.disc:*rx-store-pool-enabled*` is NIL | that variable |
| **`:static-vector-p`** (added) | `dds.pal:static-vector-p` cannot tell a GC-heap array from a static one, so "this key is NOT foreign-static" is vacuous | `pal-impl-name :sbcl` (`security-keymaterial-harden`, 4 arms) |
| **`:carve-refusal`** (added) | the host grants an absurd (2^48-octet) static carve, so an arm that needs the carve to fail cannot reach it | `secured-store-growth` arm 2 |
| **`:verified-elsewhere`** (added) | a gate does not check an artefact itself because another gate does | `dds.bench::*corpus-verified-elsewhere*` (`make corpus`) |

Why the additions are not folded into the seven: `:static-vector-p` is a PAL predicate's discrimination
power, not allocation counting (`bytes-consed` can move while `static-vector-p` still cannot discriminate,
and vice versa); `:carve-refusal` is a host memory policy (overcommit) that holds on both implementations.
Calling either `:alloc-counter` would make the table say something false. `:verified-elsewhere` is not a
host fact at all: the governing plan (row 0.10) says a gate's deferred check "counts as a skip", and
`make corpus` defers `logevent-connext.bin` to `make test` (`run-log-corpus-test`) because `dds-bench` does
not load `dds-log`. No host capability is missing there, so any of the seven would mislabel it. Any further
extension needs a justification here.

### 2.3 DARE says which capability it lacks

`dds.dare:dare-available-p` now returns a third value: NIL when available, else `:libcrypto` or
`:openssl-pqc` (§2.2). A two-value caller is unaffected. This is the one production API change, and it
exists so the classification is made where the facts are, not by parsing the reason string.

### 2.4 The accounting

`run-all-tests` prints, **before the first test**, a capability preflight:

```
preflight (ADR 0122): SBCL 2.2.9.debian on SBCL
  openssl:            UNAVAILABLE (openssl-pqc): OpenSSL version 0x300000D0 < 3.5.0 (0x30500000); version OpenSSL 3.0.13 30 Jan 2024 (0x300000D0)
  libcrypto loaded:   libcrypto.so.3
  libcrypto mapped:   /usr/lib/x86_64-linux-gnu/libcrypto.so.3
  alloc-counter:      moves (bytes-consed delta 65024 across a 4096-cons list)
  shm-attach-by-name: live probe works (ATTACHED); PAL declares reliable-p = T
  zc-sap-primitives:  enabled (tests gate on pal-impl-name :SBCL until WP-1.15)
  subprocess-mode:    enabled (dds-durability runner gates on pal-impl-name :SBCL)
  rx-store-pool:      dds.disc:*rx-store-pool-enabled* = T
```

"libcrypto mapped" is read from `/proc/self/maps`: the file the dynamic loader actually mapped, which a load
name like `libcrypto.so.3` does not tell. The version text is `OpenSSL_version(OPENSSL_VERSION)`;
`OPENSSL_VERSION` is 0, read from `/usr/include/openssl/crypto.h:153`. The shm line is a live
create + write + attach-by-name + read-back probe, printed next to what the PAL declares.

**After the last test** it prints, after the unchanged `tests: P passed, F FAILED, T total.` line:

- `coverage: F FULL, P PARTIAL, S SKIPPED, X FAILED of T test(s); E skip event(s).` per test: FAILED if it
  failed (whatever it skipped); SKIPPED if it noted any `:test`-scope skip; PARTIAL if it noted only `:arm`
  skips; FULL otherwise;
- a table, one row per capability (events, distinct tests, `:arm` events), then per capability that fired
  the tests it was charged to (`xN` = N events in that test), then any event noted outside a test.

`make fuzz`, `make mem` and `make corpus` run their entry point inside `run-with-skip-report` and print the
same preflight and accounting for that single entry point. `corpus-verify` reports each vector named in
`*corpus-verified-elsewhere*` as one `:arm` skip with capability `:verified-elsewhere`, through
`dds.pal:note-test-skip` (dds-bench loads before the harness); `make corpus` now loads `dds-tests` so the
hook is installed. A corpus mismatch is signalled inside the accounted run, so the coverage line says FAILED,
and still exits 1.

### 2.5 Step 1 is report-only

Nothing in this change alters an exit code. A skip is printed and counted; it does not fail a run.
**Step 2** (a later change, in the same commit that enables OpenSSL 3.5 in hosted CI, WP-0.8/0.9) makes a
skip of a required capability fail the run unless it is listed in the ADR 0120 skip baseline, and introduces
`DDS_TEST_ALLOW_SKIP`.

### 2.6 `make gate-skip-lint`

`scripts/gate-skip-lint.sh`. In scope: every file under `src/dds-tests/`, and, in every other file under
`src/` except `src/dds-pal/`, each top-level form that is a suite test body: a form named `run-…-test`, and
any form whose name is registered in the `run-all-tests` registry (`src/dds-tests/echo-test.lisp`, entries
`("name" . pkg:fn)`). The registry is the authority on what the suite runs; the name pattern alone missed
`dds.bench:run-bench-shmem-smoke` and `run-bench-zerocopy-smoke`, whose bare skip prints passed the first
version of this gate. It fails on:

1. an output call (`format` to anything but NIL, `write-line`, `write-string`, `princ`, `prin1`, `print`)
   whose string says skip / skipped / skipping / skips, pass-skip, "not measurable" or "not measured", in
   any case (a `format nil` assertion message is not a print);
2. a `note-skip` / `note-test-skip` / `note-bench-skip` call with no capability keyword on its first line, or
   with a keyword outside `*skip-capabilities*` (read from `test-support.lisp`), so an arm that never runs on
   this host still cannot carry a typo past the gate. Keywords inside strings are ignored.

The forms that implement the channel are exempt by name. The gate falsifies itself on every run: a scratch
tree with eight bare-print spellings, a `run-…-test` production-file body, a production-file function
that is not named `run-…-test` but is listed in a planted registry, an unknown capability, a capability on
the wrong line, and six near-misses (an assertion message, `skip-history`, `askip`, a comment, a keyword
inside a reason string, a non-test production form, a `dds-pal/` file). The scan must flag exactly the
thirteen planted lines.

## 3. What was converted

| kind | sites | capability |
|---|---|---|
| OpenSSL / AES-GCM early returns and arms (tests, production-file test bodies, fuzz arms, the interop peer) | 104 | `note-dare-skip` / `%note-dare-test-skip` → `:openssl-pqc` / `:libcrypto` |
| bare `[skip]` ZC/FlatData/loan-write prints (`echo-test`, `integration-test`, `dataplane`) | 20 | `:zc-sap-primitives` (17), `:shm-attach-by-name` (3) |
| existing `dds.pal:note-test-skip` calls, now with a capability | 33 | `:shm-attach-by-name` |
| `bytes-consed is 0` prints and silent `(when sbcl …)` / `(or (not sbcl) …)` / `(or (zerop (bytes-consed)) …)` arms | 19 | `:alloc-counter` (scope `:arm`) |
| silent `static-vector-p` arms (`security-keymaterial-harden`) | 4 | `:static-vector-p` |
| silent `(when sbcl …)` subprocess arm, process-smoke print | 2 | `:subprocess-mode` |
| silent SHMEM / ZC arms in property-based fuzz and `shmem-send-self-guard-no-regression` | 4 | `:shm-attach-by-name`, `:zc-sap-primitives` |
| `rx-store-pool` print | 1 | `:rx-store-pool` |
| `secured-store-growth` arm 2 print | 1 | `:carve-refusal` |
| bench report-stream skip lines (`run-bench-*`, `run-rtps-*-bench`) | 7 | `note-bench-skip` (5 `:shm-attach-by-name`, 2 DARE) |
| suite perftest smokes `dds.bench:run-bench-shmem-smoke`, `run-bench-zerocopy-smoke` (registered in `run-all-tests`) | 2 | `dds.pal:note-test-skip` → `:shm-attach-by-name` (the shmem smoke's gate, `dds.disc:*shmem-enabled*`, defaults to `shm-attach-by-name-reliable-p`) |
| `make corpus` deferred vector (`*corpus-verified-elsewhere*`) | 1 | `dds.pal:note-test-skip` → `:verified-elsewhere` (scope `:arm`) |

The stash `WP-0.1 parked 2026-10-03` (`stash@{0}`) carried draft conversions to a `%skip` helper at 21
sites (17 in `echo-test`, 1 in `integration-test`, 3 in `security-test`); each of those sites is converted
here, to `note-skip` with a capability, and the helper itself is not reused: it fed the deduplicating PAL
registry and named no capability.

**Not a skip, so not converted to one.** `idl-name-parity` printed `SKIPPED` when a committed IDL file was
unreadable or its type unregistered. Those are repository fixtures, not host capabilities: the test now
fails instead. Neither branch fired on either Lisp.

**Out of scope here.** The `(when sbcl-p …)` assertion arms inside the `run-bench-*` harnesses (`make bench`,
not part of the suite) are left as they are; their report-stream skip lines go through `note-bench-skip`.
The two perftest smokes that ARE suite tests (`run-bench-shmem-smoke`, `run-bench-zerocopy-smoke`) are
converted (table above).

## 4. Verification (Linux x86_64, 2026-10-04, OpenSSL 3.0.13 at `/usr/lib/x86_64-linux-gnu/libcrypto.so.3`)

**SBCL 2.2.9** (`timeout 900 make test LISP=./scripts/with-sbcl.sh`): rc 0, **650/650 passed**,
`threads: 0 leaked`.

```
coverage: 547 FULL, 3 PARTIAL, 100 SKIPPED, 0 FAILED of 650 test(s); 106 skip event(s).
  capability            events  tests  arms
  openssl-pqc              106    103     6
  (every other capability: 0)
```

The three PARTIAL tests are `property-based` (4 fuzz arms), `n-reader-s4-decode-tier` and
`durability-service-backend-select` (one DARE arm each). The 106 events match the ~105 bare `SKIP` lines the
plan counted on this host.

**AllegroCL 11.0** (`timeout 2400 make test LISP=./scripts/with-allegro.sh`): the Lisp exits by itself
(make rc 2), **632/650 passed, 18 FAILED**, plus `thread-leak-check` (8 `dds-*` threads, the same
attribution as ADR 0121 §7).

```
coverage: 504 FULL, 10 PARTIAL, 118 SKIPPED, 18 FAILED of 650 test(s); 142 skip event(s).
  capability            events  tests  arms
  openssl-pqc              106    103     6
  alloc-counter              5      5     5
  zc-sap-primitives         18     18     1
  subprocess-mode            2      2     1
  static-vector-p           11      1    11
  (libcrypto, shm-attach-by-name, rx-store-pool, carve-refusal: 0)
```

`alloc-counter`: `flatdata-zerocopy`, `flatdata-zc-loan-e2e`, `flatdata-zero-alloc`,
`durability-microservice-huge-declared`, `secured-submsg-exhaust-passthrough`. Most allocation arms sit in
DDS-Security tests, which return earlier on `:openssl-pqc`, so this count will grow once OpenSSL 3.5 is
provisioned (WP-0.8). `zc-sap-primitives`: 17 whole tests plus the `property-based` loan-acquire fuzz arm.
`static-vector-p`: `security-keymaterial-harden`, 11 events from 4 arms (one sits in an 8-iteration loop).

The 18 AllegroCL failures are a subset of the two WP-0.11 baseline runs (both 631/650): every one failed
there too; `dcps-read-status-reset` (the known ~9–10 % timing flake) and, in one of the two,
`pal-exit-process-subprocess` passed here. **No new failure on either Lisp.**

`make fuzz LISP=./scripts/with-sbcl.sh`: rc 0, `coverage: 0 FULL, 1 PARTIAL` (`pbt-fuzz x4`, the four DARE
fuzz arms). `make mem` (SBCL): rc 0, codec 0.0000 B/sample, `coverage: 0 FULL, 1 PARTIAL` (the `mem-secure`
arm). `make corpus LISP=./scripts/with-sbcl.sh`: rc 0, 13 vectors verified, 0 mismatches,
`coverage: 0 FULL, 1 PARTIAL` (one `:verified-elsewhere` event, `corpus/logevent-connext.bin`).

Gates on the final tree: `gate-skip-lint`, `gate-pal`, `gate-types`, `gate-nocond`, `gate-hotpath`,
`gate-quit-lint`, `gate-verification`, `gate-nlx` and `gate-build` (SBCL, clean fasl cache) PASS. Not a hot-path change (no file `gate-hotpath` scans was touched;
the PAL change is a test-only hook), so no bench note.

## 5. Consequences

- `dds.pal`: `note-test-skip` takes `(site capability reason &optional scope)`; `*test-skip-hook*` is new;
  `test-skips` and `reset-test-skips` are removed. All callers are updated in this change.
- `dds.dare:dare-available-p` returns a third value; two-value callers are unchanged.
- `dds.tests` exports `note-skip`, `note-dare-skip`, `note-bench-skip`, `*skip-capabilities*`,
  `*current-test*`, `skip-events`, `reset-skip-events`, `print-skip-report`, `capability-preflight`,
  `run-with-skip-report`.
- `make test`, `make fuzz`, `make mem` and `make corpus` print a preflight and the accounting; their exit
  codes are unchanged. `make corpus` now loads `dds-tests` (for the hook) instead of only `dds-bench`. `make gate-skip-lint` is new.
- The number that now describes a run is the `coverage:` line, not the `tests:` line.
