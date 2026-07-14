# ADR 0064 — No Lisp conditions in our code: thread `(values result status)`

- **Status:** **ACCEPTED — IN PROGRESS.** Slice 1 (the PAL network/SHMEM layer + its consumers) and
  slice 2 (the content-filter / query grammar) are landed. **305** production signalling forms remain,
  ratcheted to zero by `make gate-nocond`.
- **Date:** 2026-07-14
- **Requirements:** FR-LANG-8 (full type contracts), NFR-SEC-POSTURE (a network-facing failure must not
  unwind a receiver thread), the operating contract §4 / §10
- **Related:** ADR 0050 (the microservice `pal-timeout` this supersedes), ADR 0013 (the shm_open NFR-PORT
  gap, whose detection was previously a *condition*), ADR 0014 (the zero-copy pool attach)

## Directive

Owner directive, 2026-07-14, **non-negotiable**: **there are no exceptions in our code.** Not "few", not
"none on the hot path" (the original, narrower form, refined the same day) — **none, anywhere.** Every
failure is handled **at latest at the toplevel DDS API**, which returns a DDS `ReturnCode_t`. Nothing
escapes as a raw Lisp condition.

The **mechanism is owner-chosen and not open for substitution**: thread **`(values result status)`**.
**No non-local exits** — no `catch`/`throw`, no conditions, no restarts.

## Why (beyond the directive)

A signal is control flow that the type system cannot see. Three concrete costs, all of which this repo has
already paid:

1. **It unwinds a thread that must not unwind.** A malformed datagram signalling out of a receiver thread
   kills the thread and the node stops receiving — a remote DoS from one packet. The boundary
   `handler-case`s exist precisely because signals leak; the gate now *asserts* they are still there.
2. **It allocates.** `MAKE-CONDITION` showed up at 14.7 % of allocation in one (later invalidated) profile.
   The hot path must allocate zero bytes per sample (NFR-MEM).
3. **It hides in a predicate.** `dare-available-p` is *named* like a predicate and **signalled**, so seven
   `(unless (dare-available-p) ...skip...)` guards errored instead of skipping — fatal without OpenSSL ≥ 3.5.
   That bug is unrepresentable once the failure is a returned value.

## Decision

### The convention

A function that can fail returns two values and declares them:

```lisp
(defun* tcp-recv (socket buffer len)
    (function (t (simple-array (unsigned-byte 8) (*)) (integer 0))
              (values (or null (integer 0)) (or null keyword)))
  ...)
```

`(values result NIL)` on success; `(values NIL :some-keyword)` on failure. The status keyword names the
failure; it is not a message string and is not a condition object.

### The operators — `TRY` and `BAIL`, bound by `DEFUN*`

Hand-written propagation has a **silent** failure mode: *one* unchecked call swallows the status and hands
a `NIL` onward where a pointer was expected. With 333 sites to convert, that is not a hypothetical. So the
propagation is not hand-written. `DEFUN*` wraps every body in a `MACROLET` binding two operators
(`src/dds-lang/lisp-lang-tools.lisp`):

- **`(TRY form)`** — evaluate FORM. If its status is non-NIL, the **enclosing function immediately returns
  `(VALUES NIL status)`**, propagating unchanged. Otherwise TRY yields FORM's primary value.
- **`(BAIL status)`** — return `(VALUES NIL status)` from the enclosing function.

This makes checking the **default** and omission the **visible** thing. It costs nothing at runtime
(`multiple-value-bind` is stack-allocated; `gate-mem` is unchanged at 3560.2 B/sample across this change).

### Conditions from DEPENDENCIES

We do not control `sb-bsd-sockets`. A library condition is **contained at the lowest boundary that can see
it** and converted to a status there — never re-signalled, never allowed to unwind one of our callers. So
`tcp-send`/`tcp-recv` keep a `handler-case` around the library call and *return* `:SEND-FAILED` / `:EOF`.
That is rule 2, applied at the call rather than at the toplevel.

## Contract changes in this slice — every consumer

`dds.pal` (the PAL is a **frozen** M0 contract; this changes it):

| Symbol | Was | Now |
|---|---|---|
| `%setsockopt`, `udp-set-reuse-port`, `udp-join-multicast`, `%tcp-suppress-sigpipe`, `tcp-set-recv-timeout` | signalled | `(values t status)` — `:SETSOCKOPT-FAILED` |
| `udp-open`, `tcp-connect`, `tcp-accept` | signalled | `(values socket status)`; the half-open fd is **closed** before returning |
| `tcp-send` | signalled on a torn socket | `(values len status)` — `:SEND-FAILED` |
| `tcp-recv` | `NIL` = EOF, **signalled `PAL-TIMEOUT`** | `(values len status)` — `:EOF` vs `:TIMEOUT`, still distinct |
| `%mmap-shared`, `shm-create`, `shm-attach` | signalled | `(values seg status)` — `:SHM-OPEN-FAILED` / `:FTRUNCATE-FAILED` / `:MMAP-FAILED`; every failure path closes its fd |
| `pshared-mutex-init`, `pshared-cond-init` | signalled | `(values t status)` — `:MUTEX-INIT-FAILED` / `:COND-INIT-FAILED` |
| **`PAL-TIMEOUT`** | a condition class | **REMOVED** (superseding ADR 0050 §4.6). Its information is the `:TIMEOUT` status. |

Consumers migrated in the same commit:

- **`dds.xport.udp:make-udp-transport`** → `(values transport socket status)`.
- **`dds.xport.shmem`** — `%ring-init` → `(values t status)` (its `ASSERT` on ring geometry is now
  `:BAD-RING-GEOMETRY`); `make-shmem-transport` → `(values st status)`, detaching *and unlinking* the
  segment on a failed init; **`%attach-for` → `(values seg status)`, which fixes a real latent defect: an
  `shm-attach` failure used to signal OUT OF A SEND.** It is now the ordinary "0 octets sent" result and
  the caller falls back to UDP, which is what the send path already meant to do.
- **`dds.xport.zerocopy::%zc-init`** → `(values t status)`.
- **`dds.disc:make-disc-node`** → `(values node status)`. **Every failure path now releases the sockets and
  segments it had already opened** — previously an error mid-construction leaked an fd and an shm object.
  The `crypto-transform` + zero-copy exclusion (ADR 0031) is now `:CRYPTO-AND-ZEROCOPY-EXCLUSIVE`.
- **`dds.disc::%zc-attach-pool`** — the missing-peer-pool case was an `shm-attach` condition swallowed by
  `IGNORE-ERRORS`, **which also swallowed every other fault**. It is now the explicit `:SHM-OPEN-FAILED`
  status, cached as `:none`. A forged/stale source prefix is an *ordinary outcome*, not an error.
- **`dds.dcps:create-participant`** → `(values participant status)`. This is the toplevel API boundary.
  DDS 1.4 `create_participant` returns a NULL handle on failure, so the `NIL` primary value is the
  conformant shape; callers **must** check it.
- **`dds.durability` microservice** — `%ms-dial` / `%ms-ensure-connected` / `%ms-recv-body` /
  `%ms-recv-message` thread the status. `%ms-exchange` maps `:TIMEOUT` → `microservice-conn-lost` (the
  bounded reconnect) and `:EOF` → `microservice-conn-lost`, exactly as the `PAL-TIMEOUT` handler did.
  `%ms-serve-connection` ends the connection on `:TIMEOUT` just as it did on EOF — the disposition was
  already identical, and now it is also the same code path. Its `SERIOUS-CONDITION` backstop **stays**
  (defence in depth for a listener serving untrusted clients) until the store's own 38 sites are converted.

## Enforcement

`make gate-nocond` (self-falsifying — it plants an unmarked signalling form and asserts the scan rejects
it), in CI:

1. **Hot path: STRICT.** Every signalling form in a hot-path file must carry `; HOTPATH-COND(CLASS): reason`
   (`COLD` / `GUARD` / `TEST` / `TRACKED`). An unmarked one fails the build.
2. **The rest of `src/`: RATCHETED** via `bench/nocond-ceiling.txt`. **333 → 320** with this slice. Adding a
   condition fails the build; removing one fails it too *until you bank the lower number*. The ratchet only
   moves down. In-file `run-*-test` functions are excluded — an `ASSERT` there **is** the test's failure
   mechanism, not production control flow.
3. **The boundary handlers are asserted to exist**, so no refactor can quietly delete the receiver's
   `handler-case` and re-open the one-bad-datagram DoS.

## Slice 2 — the content-filter / query grammar (`src/dds-dcps/filter.lisp`, 15 -> 0)

The user-visible half of the rule. A `filter_expression` is **user input**, and `FILTER-ERROR` unwound
straight out of `create-contentfilteredtopic` / `create-querycondition` on a typo.

- The `FILTER-ERROR` **condition** becomes a **`FILTER-STATUS` struct** (`code` + `detail`). It is a struct
  and not a bare keyword *on purpose*: the expression is hand-written, so `:bad-parameter` with no reason
  is useless to the person who has to fix it. `code` is switchable; `detail` names the offending
  character / token / field.
- The recursive-descent helpers are `LABELS` **lexically inside** `compile-filter`, so `BAIL` returns from
  `compile-filter` itself — a failure ten levels deep in the descent needs no threading and **cannot be
  dropped by a caller that forgot to check**. The lexer helpers carry an extra result (the next input
  index), so they return `(values result status next-index)`: status stays in the conventional **second**
  position and the index rides third.
- **API boundary:** `create-contentfilteredtopic`, `set-cft-expression-parameters` and
  `create-querycondition` return `(values object :BAD-PARAMETER filter-status)` — the DDS `ReturnCode_t`
  *plus* the reason. **Nothing is registered on the participant/reader on failure**, and
  `set-cft-expression-parameters` now leaves the CFT **untouched** when the new parameters do not compile
  (the old code assigned the parameters slot *before* compiling, so a throwing compile left the CFT
  describing parameters it was not actually filtering by — a second latent defect found by the conversion).

## Order of the remaining work (shallow → deep)

`typelookup.lisp` (10) · `dsl.lisp` (10) · the durability stores
(`store-microservice` 38, `store-encrypted` 14, `store-sqlite` 9) · `secure-sedp.lisp` (19) ·
`pal-clasp.lisp` (10) · **`dds-dare/primitives.lisp` (96) LAST** — the OpenSSL FFI failure chains are the
biggest and deepest.

**Convert ONE FILE at a time; update EVERY caller; re-run the suite after EACH file. Never batch.**

## Consequences

- **Positive.** Two latent defects fell out of the conversion itself (the `shm-attach` signal inside a
  send; the fd/segment leak on a failed `make-disc-node`), and `%zc-attach-pool` stopped swallowing
  unrelated faults with `IGNORE-ERRORS`. Failure modes are now in the `ftype`, so the compiler sees them.
- **Negative.** Every fallible signature widens to `(values (or null x) (or null keyword))`, which is more
  verbose than a bare return type, and callers must destructure. `TRY` keeps that to one operator.
- **The hazard, stated plainly.** A missed check silently swallows a failure — a `NIL` where a pointer was
  expected. `TRY` is the mitigation, the per-file suite run is the net, and the type declarations are the
  backstop.
