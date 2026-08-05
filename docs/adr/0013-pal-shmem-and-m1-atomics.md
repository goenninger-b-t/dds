# ADR 0013 — PAL extension for SHMEM transport + M1 atomics fast path

- **Status:** Accepted (2026-06-14)
- **Deciders:** A0 (integrator)
- **Amends:** ADR 0002 (the frozen L0 `DDS.PAL` contract, §7.6) — additive only, no existing
  symbol changed
- **Requires:** WP-SHMEM (FR-XPORT-2, REQUIREMENTS §6); M1 atomics fast path
  (IMPLEMENTATION-PLAN §7.6)

## Context

WP-SHMEM (FR-XPORT-2) needs the `dds.pal` contract extended in three directions:

1. **POSIX shared-memory segment primitives** — create, attach, detach, destroy a named
   POSIX shm segment; obtain its SAP and byte length (`shm-create`, `shm-attach`,
   `shm-detach`, `shm-destroy`, `shm-sap`, `shm-segment-size`).
2. **Cross-process named-semaphore primitives** — POSIX named semaphores for reader-wakeup
   without shared mutex/condvar (`sem-create`, `sem-open`, `sem-post`, `sem-wait`,
   `sem-close`, `sem-unlink`).
3. **M1 atomics fast path** — the ring-buffer and sequence-number operations in the SHMEM
   transport require true hardware atomics on raw foreign memory (SAPs). The current
   `cas`/`atomic-incf`/`fence` stubs (M0) signal `pal-unimplemented` or are no-ops:
   verified at `pal-sbcl.lisp:81-96` and `pal-clasp.lisp:102-117`.

The generic `cas`/`atomic-incf` stubs operate through a runtime `place-fn` indirection that
cannot be lowered to a single atomic instruction on a foreign pointer. A correct fast path
therefore needs **foreign-SAP-specific** forms that operate directly on a 64-bit cell
addressed by an `(sb-sys:system-area-pointer, byte-offset)` pair.

## Decision

### Atomics fast path

Introduce four SAP-targeted atomic primitives plus a real fence:

| Symbol | Semantics |
|---|---|
| `cas-sap-u64` | Compare-and-swap a 64-bit cell in foreign memory; returns old value |
| `atomic-incf-sap-u64` | Atomically add a delta to a 64-bit cell; returns new value |
| `load-sap-u64` | Atomic load of a 64-bit cell (at least `:acquire` ordering) |
| `store-sap-u64` | Atomic store to a 64-bit cell (at least `:release` ordering) |
| `fence` (real) | Issue a hardware fence for `:acquire`, `:release`, or `:full` |

The existing generic `cas` and `atomic-incf` stubs are **left in place** (no callers;
removing them would be an API break per ADR 0002); `fence` signature is unchanged but its
body becomes a real barrier instead of a no-op. *(Update, WP-PAL-ATOMICS / ADR 0041: the generic
`cas`/`atomic-incf` stubs are now CLOSED — implemented on both impls over a PAL `atomic-cell`
struct, whose compile-time-known slot place the native RMW macros can target, which the runtime
`place-fn` indirection this ADR describes could not. The SAP-targeted forms and the Clasp
foreign-atomic gap below are unaffected.)*

**Verified primitive mapping (probed facts):**

- **SBCL** — `sb-ext:cas` and `sb-ext:atomic-incf` applied to `(sb-sys:sap-ref-64 sap
  offset)` places compile and run correctly on SBCL 2.x; `sb-thread:barrier` with kinds
  `:read`, `:write`, `:memory` is present. A CFFI `foreign-pointer` on SBCL is an
  `sb-sys:system-area-pointer` (same underlying C pointer type), so the same SAP forms
  cover CFFI-obtained pointers.
- **Clasp** — `mp:cas` (macro), `mp:atomic-incf`, `mp:atomic-incf-explicit`, and `mp:fence`
  exist. Whether `mp:cas` can target a foreign-memory place on a Clasp `core:pointer` is
  confirmed by a later probe task (A4); if not, a documented NFR-PORT fallback applies:
  SHMEM transport SBCL-only on Clasp until upstream support lands.

### SHMEM segment and semaphore symbols

`shm-create`, `shm-attach`, `shm-detach`, `shm-destroy`, `shm-sap` map to
`shm_open`/`mmap`/`munmap`/`shm_unlink` (POSIX.1-2017 §3.254, §3.288). `shm-segment-size`
is the `defstruct*`-generated accessor for the size slot of the segment descriptor struct
introduced in Phase B. `sem-create`/`sem-open`/`sem-post`/`sem-wait`/`sem-close`/`sem-unlink`
map to `sem_open`/`sem_post`/`sem_wait`/`sem_close`/`sem_unlink` (POSIX.1-2017 §3.255).
All are CFFI thin wrappers; no external library dependency is introduced.

## Consumers

`dds.xport.shmem` only. PAL-layer edits are the exclusive domain of the A0 role per the
subagent rules (the operating contract §8).

## Provenance

All primitives are implemented from POSIX.1-2017, SBCL internals documentation, and Clasp
`mp:` package documentation. Nothing copied from any external implementation.

## Consequences

- `dds.pal` gains 12 new exported symbols (4 atomics + `fence` real body + 6 shm + 6 sem);
  the pre-existing `cas`/`atomic-incf`/`fence` symbols are unchanged at the API level.
- Phase A tasks (A1–A4) reserve the symbols and implement the two PAL back-ends; Phase B
  tasks build the transport on top.
- `docs/verification.csv` FR-XPORT-2 row: open until the SHMEM transport roundtrip test
  passes (Phase B exit gate).
- No migration burden: purely additive.

## Clasp status (A4 probe result, 2026-06-14) — NFR-PORT gap

The A4 probe resolved the open question in the "Verified primitive mapping" note above:
**Clasp cannot provide a correct hardware atomic over a raw foreign 64-bit cell.** Two
independent paths were probed and both fail:

1. `mp:cas` / `mp:atomic-incf` (and the `-explicit` variants) are *place-form* macros driven
   by an extensible atomic-expander table (`mp:define-atomic-expander` /
   `mp:get-atomic-expansion`). A `cffi:mem-ref` foreign place has no registered expander, so
   both raise a **compile-time** `NOT-ATOMIC` condition: *"Don't know how to atomically access
   the place (MEM-REF P UINT64 0)"*. Clasp's `mp:cas` on a known place (`svref`) lowers to
   `core:acas`, which takes a **Lisp array object + index**, not a pointer — there is no
   exported primitive that takes a SAP/address.
2. `core:acas` *does* operate on a `(unsigned-byte 64)` `static-vector` (foreign-backed,
   stable-address) and is full 64-bit width. But it is **silently incorrect for a bignum
   compare operand**: when the expected value exceeds `most-positive-fixnum` (≈ 2^62 on
   Clasp), the CAS returns the correct previous value yet **fails to perform the store**
   (e.g. CAS `2^64-1 -> 5` leaves memory at `2^64-1`). Ring tokens, sequence numbers, and
   `atomic-incf` counters routinely cross 2^62, and the ring uses `0` as the free-lane
   sentinel — a dropped store there corrupts the ring or livelocks the CAS-retry fetch-add.
   This is disqualifying; correctness is a binary gate.

**Decision:** on Clasp, `cas-sap-u64` and `atomic-incf-sap-u64` signal `pal-unimplemented`;
`load-sap-u64` / `store-sap-u64` are implemented via `cffi:mem-ref :uint64` (non-atomic R/W;
the load masks to unsigned because Clasp's `:uint64` mem-ref sign-extends a high-bit-set
word). The SHMEM lock-free ring is therefore **SBCL-only**; Clasp falls back to the UDP
transport (a later `*shmem-enabled*` guard performs the transport selection). The
`pal-sap-atomics` test keeps its `:sbcl`-only guard and skips cleanly on Clasp. Revisit when
Clasp gains a foreign-place atomic expander or fixes the `core:acas` bignum-compare store
(track upstream).

## Clasp shm-create (macOS) gap (2026-06-14) — NFR-PORT gap — ✅ **CLOSED 2026-07-31, see ADR 0103**

> **This section is superseded by [ADR 0103](0103-the-clasp-macos-shm-gap-closed-in-c-not-in-a-call-form.md).**
> The gap is closed: Clasp gained a **C++ binding of `shm_open`** (`CORE:SYS-SHM-OPEN`), whose variadic call is
> emitted by clang and is therefore correct on every ABI by construction. `dds.pal::%shm-open-create` routes
> through it, `shm-attach-by-name-reliable-p` is now `T` on Clasp/macOS-arm64, and the SHMEM / Zero-Copy /
> loan tests that used to pass-skip there run and pass. **The analysis below remains correct and is worth
> reading** — in particular its conclusion that *no CFFI call form* could fix this, which is exactly why the
> fix had to land upstream. The sibling `semctl(SETVAL)` variadic gap recorded elsewhere in this ADR is **not**
> closed and is still gated by `sysv-sem-setval-reliable-p`.

A second, independent Clasp/macOS-arm64 limitation surfaced while wiring `shm-create`
(`shm_open` with `O_CREAT|O_EXCL`). `shm_open`'s third argument, `mode_t`, is **variadic**
(`int shm_open(const char *, int, ...)`, POSIX.1-2017 §3.254). Passing it correctly is
ABI-sensitive on arm64.

**Probe result:** Clasp's CFFI cannot reliably pass the create `mode` argument on macOS
arm64 — **VERIFIED flaky at roughly 40% failure across `:uint`, `:int`, `:u32`, and `:long`
mode types** (a plain `cffi:foreign-funcall` with the mode appended). When the mode is
mispassed, the object is created with the wrong permissions and is subsequently
**unre-openable** by name (the cross-process path the SHMEM transport depends on). SBCL is
conformant on every platform via `cffi:foreign-funcall-varargs` (which marshals the variadic
tail onto the stack as the arm64 AAPCS variadic ABI requires). On Clasp/Linux the System V
arm64 register-vs-stack variadic rules differ and a plain `foreign-funcall` is **expected**
correct (to be verified later on a Linux host).

**Options considered:**

1. **Load-time C shim** — a tiny `pal-shm.c` (`int dds_shm_open_create(const char*, int)`
   that calls `shm_open(name, oflag, 0600)` with the mode fixed in C) compiled with
   `cc -shared` in an `eval-when` at load time and bound via `cffi:defcfun`. This works
   (the mode never crosses the FFI boundary) but introduces a **build-time `cc` dependency
   at image-load time**. **Rejected by the owner** (a C-toolchain-at-load requirement is not
   acceptable for this PAL).
2. **Take the gap (chosen).** Make `%shm-open-create` per-impl in `pal-net.lisp` — SBCL uses
   `foreign-funcall-varargs` (verified), Clasp uses a plain `foreign-funcall` (correct on
   Linux's register varargs ABI; unreliable on macOS arm64). Reader conditionals are
   permitted there because `pal-net.lisp` is inside `dds-pal/` (the operating contract §10).

**Decision:** take the gap. Consequences:

- **SBCL:** full SHMEM on every platform.
- **Clasp/macOS-arm64:** `shm-create` is unreliable → Clasp on macOS uses the **UDP
  transport**. This is a documented NFR-PORT gap, mirroring the Clasp threading and
  Clasp foreign-atomics gaps recorded above.
- **Clasp/Linux:** SHMEM is **expected** to work via the plain `foreign-funcall` register
  varargs path; **pending verification on a Linux host**.
- The `run-pal-shm-test` (`dds-tests`) asserts the real by-name attach + cross-mapping
  shared write/read on SBCL (every platform) and on Clasp/non-macOS, and **tolerates the
  attach failure only** when `(and (eq (dds.pal:pal-impl-name) :clasp) (uiop:os-macosx-p))`
  — a **runtime** check, not a reader conditional, because `dds-tests/` is outside
  `dds-pal/`. On the tolerated path the test still creates+maps+detaches cleanly and returns
  `T`; the `MAP_SHARED` second-mapping assertion stays unconditional (it works everywhere).

Revisit when Clasp's CFFI fixes variadic argument passing on macOS arm64, or once
Clasp/Linux SHMEM is verified on a Linux host.

## Final design (as implemented, 2026-06-14)

WP-SHMEM is complete; this section records the as-built decisions that differ from, or
firm up, the options sketched above. The full design narrative is
`docs/superpowers/specs/2026-06-14-wp-shmem-transport-design.md`; the measurement is
`bench/report/2026-06-14-wp-shmem.md`; the consuming transport is
`src/dds-xport/shmem.lisp` (package `dds.xport.shmem`).

- **Notification = an in-segment `PTHREAD_PROCESS_SHARED` mutex + condvar, NOT named
  semaphores.** The Decision above provisioned six `sem_*` primitives. They were **dropped**:
  `sem_open` cannot be driven from the Lisp runtime on macOS arm64 (its `mode`/`value` are
  variadic and are mispassed by CFFI/sb-alien, verified 2026-06-14). The shipped primitives
  are the non-variadic `pthread_*` set — `pshared-mutex-init`, `pshared-cond-init`,
  `pshared-lock`, `pshared-unlock`, `pshared-cond-wait`, `pshared-cond-signal`,
  `pshared-cond-broadcast`, `pshared-destroy` — which work from both SBCL and Clasp on macOS +
  Linux (libpthread is already linked, so no new dependency). The mutex/cond/`stop`/`parked`
  cells live at fixed cache-aligned offsets **inside** the receive segment, the notify block
  sized to the per-platform max pthread struct sizes so one layout serves both OSes.

- **Lane claim is mutex-guarded; the ring needs NO foreign-SAP CAS.** The shipped ring is
  multi-producer/single-consumer realised as **K per-sender SPSC lanes**, with the one-time
  per-(sender,receiver) lane claim serialized by the segment's pshared mutex — off the hot
  path. Consequently the SAP-targeted `cas-sap-u64`/`atomic-incf-sap-u64` (the A3/A4 atomics
  this ADR introduced) are **unused by the v1 ring**, which makes the Clasp foreign-atomics gap
  recorded above **irrelevant to SHMEM on Clasp/Linux**: the ring is at full SBCL+Clasp parity.
  The SAP atomics remain valid PAL primitives, kept for a future lock-free-MPSC ring. The
  `fence` (real M1 barrier) **is** used — release on the producer's cursor publish, acquire on
  the consumer's cursor load, full for the wakeup handshake.

- **Conditional (parked-flag) wakeup, Dekker StoreLoad.** Steady-state enqueue/drain are
  lock-free (aligned-u64 store/load + the real fence). The pshared mutex+cond is taken only to
  park/wake: the receiver publishes `parked = 1` under the mutex, full-fences, and re-checks the
  data predicate before `cond-wait`; the sender enqueues, full-fences, reads `parked`, and
  signals (a futex syscall) **only** when `parked = 1`. A busy (draining) receiver is therefore
  never futex-woken per message, and the StoreLoad handshake makes a skipped signal provably
  never a lost wakeup.

- **bordeaux-threads v2 atomics: considered and dropped.** They were not used: a heap
  `atomic-integer` object cannot live in the shared segment or be CAS'd cross-process. The
  cross-process state is raw foreign cells in the `mmap` region only.

- **Per-impl `shm_open` create + the Clasp/macOS gap stands** (see the "Clasp shm-create
  (macOS) gap" section above): `%shm-open-create` is per-impl in `pal-net.lisp` — SBCL uses
  `cffi:foreign-funcall-varargs` (correct every platform), Clasp uses a plain `foreign-funcall`
  (correct on Linux's register-varargs ABI, unreliable on macOS arm64). The owner rejected the
  load-time C shim. Net: **SBCL full SHMEM everywhere; Clasp/macOS uses UDP** (`*shmem-enabled*`
  defaults `NIL` there via `shm-attach-by-name-reliable-p`); **Clasp/Linux expected, pending a
  Linux host**.

- **Vendor constants (ours; pinned here, NOT OMG spec clauses).** The SHMEM `Locator_t` kind
  is `0x47420001` (`dds.rtps.discovery:+locator-kind-shmem+`) and the same-host UUID parameter
  is `PID_SHMEM_HOST_UUID = 0x8040` (`dds.rtps.message:+pid-shmem-host-uuid+`, in the `0x8000`
  vendor PID range; the host-uuid is the low 8 octets of the MD5 of the hostname). There is no
  standard RTPS SHMEM locator kind or wire format, so these are documented project values and
  cross-vendor SHMEM is out of scope; a peer ignoring an unknown kind falls back to UDP
  (fail-open).

- **Selection + fallback (engine untouched).** SHMEM is auto-selected for same-host **user
  DATA** only, when a peer shares the host-uuid AND advertised a SHMEM locator (the verdict is
  cached per remote in `dds.disc`, so steady-state send does one `gethash` and zero
  per-datagram allocation). UDP carries **all** discovery/metatraffic/HEARTBEAT/ACKNACK and
  every non-SHMEM case; a lane/ring-full enqueue rejects to a UDP fallback for that datagram
  (reliable sample repairs via HEARTBEAT/ACKNACK), never a GC-heap fallback. The transport plugs
  into the frozen `dds.xport:transport` record and feeds the same `%handle-datagram`, so the
  RTPS engine is unchanged.

- **Bench outcome.** SBCL/macOS (Apple M5): a clear **latency win** — 1.35x–1.94x lower one-way
  median than UDP loopback, with a lower worst-case tail; the SHMEM send path is **0
  bytes/sample** steady-state (ring is preallocated foreign/static, dest cached). End-to-end
  *reliable* throughput is **HEARTBEAT/ACKNACK-handshake + poll-granularity bound, not
  SHMEM-bound** (a direct send-path micro-bench isolates the conditional-wakeup at ~1.4x–1.8x
  raw send throughput); a lock-free-MPSC ring is the remaining transport follow-up.

- **Verification.** 165 tests green on SBCL (the ring unit tests, the transport + threaded
  receiver loopback, the in-process end-to-end integration over SHMEM, the contention stress
  test, the ring-record-parser fuzz, the real two-process `make shmem-xproc` round-trip, and
  `make bench-shmem`); `gate-types` (1043 defuns), `gate-hotpath`, `fuzz`, and `mem` green.

## Status update

**Accepted + implemented (2026-06-14).** The Decision's named-semaphore primitives are
superseded by the pshared mutex/cond above; everything else in the Decision shipped as written
(the SAP atomics + real fence + the six `shm-*` primitives, with the documented Clasp gaps).
`docs/verification.csv` FR-XPORT-2: the PAL/atomics row is `partial` (Clasp gaps), and the
transport row is `implemented`.

## SHMEM-send self-guard (as-built, 2026-06-18) — WP-SHMEM-SEND-SELF-GUARD

A follow-up hardening of the SHMEM **send** path, flagged as a deferred item in
WP-SENDER-ERROR-RESILIENCE / ADR 0016. The Final-design "Selection + fallback" note above
already mapped a SHMEM **lane/ring-full reject** (the enqueue *returns* 0) to a UDP fallback.
A **signalled** `%shmem-send` hard fault (segment detached, pshared error, bounds) is a
different outcome and, before this WP, propagated out of the user-data send (the
WP-SENDER-ERROR-RESILIENCE sender-thread guard caught it but *dropped* the datagram and relied
on reliability repair).

**As-built.** A signalled `%shmem-send` fault is now caught in **`%send-raw-buf` (`dds.disc`)**
— the production one-datagram send path — bumps the `disc-node` `shmem-send-faults` counter,
fires `*sender-emit-error-hook*` with context **`:shmem-send-fault`** (via
`%note-shmem-send-fault`, the hook call `ignore-errors`-guarded so a signalling hook cannot
break the send), and **falls back to UDP exactly like a return-0** — so the datagram still
delivers. The spec design is `docs/superpowers/specs/2026-06-18-wp-shmem-send-self-guard-design.md`.

**Layering rationale.** The hook (`*sender-emit-error-hook*`) lives in `dds.disc`; the SHMEM
`:send` lambda lives in `dds.xport` (a lower layer `dds.disc` depends on). Catching in the
`dds.xport` `:send` lambda would defeat the counter + hook (you cannot have both layers catch),
and reaching the hook from there would require an upward `dds.xport → dds.disc` dependency. So
the guard goes in `%send-raw-buf`, which already holds the SHMEM transport, the node, the
UDP-fallback dest, and the hook in scope — no layering inversion. The `dds.xport` SHMEM `:send`
lambda stays **unguarded** so it can signal up to `%send-raw-buf`.

**Fault-vs-lane-full distinction.** The `handler-case` fires **only on a signal**. A benign
lane-full (the SHMEM send *returns* 0) does **not** enter the handler → it takes the **silent**
UDP fallback with **no** counter bump and **no** hook fire. Only the hard-fault (signal) path is
counted/observed. Either way exactly one of {SHMEM, UDP} carries the datagram (no loss, no
double-delivery); a genuinely lost reliable sample is backstopped by HEARTBEAT/ACKNACK repair
(RTPS 2.5 §8.4.1).

**Test affordance.** `dds.xport.shmem:*debug-shmem-send-fault*` (special, default `NIL`,
exported) injects a synthetic `shmem-send-test-fault` at the top of `%shmem-send`; `NIL` =
byte-identical production, never wire-triggered (NFR-SEC-POSTURE). Proven by
`run-shmem-send-self-guard-test` (fault → UDP-fallback delivery + counter advanced + hook fired
`:shmem-send-fault` + `shmem-sends` did **not** advance) and `run-shmem-send-self-guard-no-regression-test`
(injector NIL → SHMEM still delivers, counter 0, hook silent; and an all-UDP `shmem-dest`-NIL
send unaffected — the latter leg on both impls).

**Conformance / scope.** FR-XPORT-2; SHMEM is standard, so this is **non-R6**. Local send-error
handling is implementation-defined (no RTPS clause governs it — same posture as
WP-SENDER-ERROR-RESILIENCE); a UDP-fallback delivery is **more** conformant than a drop (the
datagram is delivered, not lost). Off the measured CDR hot path — `make mem` stays `0.0000`, no
hot-path number moved, no bench warranted (FR-LANG-7). **Cross-DDS interop DoD** (owner directive
2026-06-17): minimal wire-observable surface — SHMEM is same-host **ours-to-ours**, a foreign
peer always gets UDP (`shmem-dest` is `NIL` for it → the guard is inert), so the cross-DDS surface
is **no-regression** vs RTI Connext 7.3.1 + Fast DDS 3.6.1 (`interop/shmem-send-self-guard/`); the
our-to-our fault→UDP-fallback unit test is the feature proof. `docs/verification.csv` FR-XPORT-2:
the transport row stays `implemented`; the self-guard rows are added.
