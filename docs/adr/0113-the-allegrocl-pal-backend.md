# ADR 0113 — The AllegroCL PAL backend

- **Status:** Accepted — **partial by design**: the 36 PAL-contract symbols are done and verified; the
  16 socket functions of `pal-net.lisp` are not (§5).
- **Date:** 2026-08-07
- **Requirement:** NFR-PORT, NFR-BUILD; the operating contract's Definition of Done ("compiles and unit
  tests pass on SBCL **and AllegroCL**")
- **Closes:** the follow-up ADR 0004 left open in 2026-06-04

---

## 1. Context

ADR 0004 marked M0 passed with an explicit AllegroCL exception, on the grounds that the implementation was
not wired in. It is now available — Allegro CL Enterprise 11.0, 64-bit Linux x86-64 SMP, on two hosts — so
the exception's premise is gone and the work is schedulable.

⚠️ **`alisp` is not on `PATH` for a non-login shell.** A bare `ssh host 'alisp …'` answers `command not
found`, which reads exactly like a missing installation and is how this ADR could be re-deferred forever.
`ssh host 'bash -lc "alisp -q -batch -L …"'` is the working form.

## 2. What the contract actually required

The PAL exports **118** symbols. **66** are implementation-independent (`pal-contract`, `pal-net`) and
**40** are per-implementation. Four (the IEEE 754 conversions) landed with ADR 0111 slice 1, leaving **36**.

## 3. The decision — reuse the portable route wherever Clasp already does

`cffi`, `bordeaux-threads` and `static-vectors` **all load on AllegroCL** (verified), and those are exactly
what the Clasp PAL routes through. So most of this backend is a mirror rather than an invention:

| group | AllegroCL |
|---|---|
| static memory, SAP pointer arithmetic | `static-vectors` + `cffi` — as Clasp |
| SAP typed access | `cffi:mem-ref` — as Clasp |
| **foreign atomics** | the C11 `__atomic_*` builtins via `%global-symbol-pointer` — as Clasp, **plus §4** |
| locks, condvar wait/signal, thread join | `bordeaux-threads` — as Clasp |
| condvar **broadcast** | `mp::condition-variable-broadcast`: this `bordeaux-threads` has **no** `condition-broadcast` at all (probed NIL), and signalling in a loop is a *different* operation, not an equivalent one — it cannot bound the number of waiters |
| Lisp-cell CAS / incf | `excl::atomic-conditional-setf` / `excl::incf-atomic` — §4 |
| fence | `mp::memory-barrier` (full barrier: stronger than `:acquire`/`:release`, never weaker) |
| signals, image restart | `excl::set-signal-handler`, `excl::*restart-init-function*` — §4 |
| `bytes-consed`, `internal-bug-p`, `static-vector-p` discrimination | documented NFR-PORT gaps, **identical to the ones Clasp already carries** |

## 4. The five places the implementations genuinely differ

Each was **probed on the real build**, not inferred. This is what the PAL exists to absorb.

1. **`libatomic` must be loaded explicitly.** `__atomic_compare_exchange_8/_4` and `__atomic_fetch_add_8`
   resolve to **NIL** in an Allegro image and to valid pointers after
   `(cffi:load-foreign-library "libatomic.so.1")`. Clasp gets them free because its runtime already links
   libatomic. Without this the SHMEM lane claim and the ZC refcount would fail at first call rather than at
   load — the worst place to find out.
2. **`cas` returns a boolean, not the previous value.** `excl::atomic-conditional-setf` is
   `(PLACE NEW-VAL OLD-VAL)` — new **before** old, the reverse of this contract's argument order — and
   answers T/NIL. On success the previous value *was* `old`; on failure the slot is re-read, and that
   re-read is **not atomic with the failed swap**. Sound for the only sanctioned use (a CAS retry loop,
   which re-reads and retries anyway), and the reason a non-`old` return means *retry*, never *the value is
   now exactly this*.
3. **`atomic-incf` returns the NEW value already.** `excl::incf-atomic` answers the new value (probed:
   9 + 3 ⇒ 12), where SBCL's `atomic-incf` answers the old and must be normalised. Opposite conventions,
   same contract.
4. **`*restart-init-function*` holds ONE function, not a list.** So the hook registration **chains** —
   previous first, then the new one. Overwriting would silently lose one subsystem's foreign-pointer
   re-resolve after an image restart.
5. **`most-positive-fixnum` is 2^60−1**, narrower than SBCL's 2^62−1. Any bit-packing sized against SBCL's
   fixnum can become a bignum here. (ADR 0108's drain window is unaffected — it stores raw
   `(unsigned-byte 64)` words in a vector rather than packing into a fixnum.)

## 5. ⛔ What is NOT done — `:dds-pal` still does not load on AllegroCL

`pal-net.lisp` is 1288 lines and 68 functions. Of those:

- **32 are pure CFFI** — `mmap`, POSIX and SysV shared memory, semaphores, the pshared mutex/condvar — and
  are expected to work unchanged.
- **20 need neither** — plain Lisp or `bordeaux-threads`.
- **16 are written against `SB-BSD-SOCKETS`**: `udp-open`, `udp-local-port`, `udp-send-to`, `udp-recv`,
  `udp-close`, `%setsockopt`, `%pal-reresolve-foreign-pointers`, `monotonic-ns`, and the seven `tcp-*`
  entries. **SBCL and Clasp both bundle that package; AllegroCL does not.**

So the honest state is: **the PAL contract is ported and verified; the socket layer is the next slice.**
AllegroCL has a native `socket:` package, and the alternative — direct BSD-socket syscalls through CFFI,
which the file already does for `mmap`/`shm` — would be implementation-independent and could eventually
retire the `sb-bsd-sockets` path everywhere. That is a design choice worth making deliberately rather than
inside this ADR.

⛔ **Until the socket slice lands, the Definition of Done's "SBCL and AllegroCL" is met on SBCL + Clasp
only**, and every "done" in this repository should be read that way. This ADR narrows that gap; it does not
close it, and saying otherwise would be the more comfortable and less true statement.

## 6. Verification

Compiled on the real implementation, then **every one of the 36 symbols exercised** by a smoke harness
against expected values — not merely loaded:

- static memory: allocate / length / `static-vector-p` / `mem-ref-u8` / `mem-set-u8` / free
- SAP access: u8, u16, u32, u64 round-trips including the **`#xFFFFFFFFFFFFFFFF` high-bit case** the
  unsigned mask exists for, and `static-sap+` offsetting
- **foreign atomics**: `cas-sap-u64` hit *and* miss with the stored value checked after each,
  `cas-sap-u32`, `atomic-incf-sap-u64`
- the atomic cell: `cas` hit, `cas` miss, `atomic-incf`
- `fence` in all three kinds
- locks, and a **real second thread** signalling a condition variable that the main thread waits on, then
  joined
- `pal-impl-name`, `bytes-consed`, `gc-suggest`, `with-gc-inhibited`, `internal-bug-p`, `fsync-stream`,
  `fsync-directory`
- the IEEE 754 conversions against the byte-exact vectors the SBCL arm asserts, negative zero built by
  multiplication

Result: **GREEN, 0 failures.**
