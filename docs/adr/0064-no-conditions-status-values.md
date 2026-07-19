# ADR 0064 — No Lisp conditions in our code: thread `(values result status)`

- **Status:** **ACCEPTED — IN PROGRESS.** Landed: PAL network/SHMEM, content-filter grammar, TypeLookup
  serializers, the type-compiler DSL, the Clasp PAL, the IdentityToken + DataHolder parsers, mixed-kind
  governance, arena exhaustion, the DataHolder/`%dh-fail` wire parser, the durability config + microservice
  parsers, and the FIVE exempt classes (below). **202** production signalling forms remain, ratcheted to
  zero by `make gate-nocond`.

### The seven sanctioned exempt classes (each gate-falsified in the canary; a class is documentation for the reader — the reviewer/owner validates the choice)

| class | ruling | what it justifies |
|---|---|---|
| `NOCOND(MACRO)` | 2026-07-14 | a form reached ONLY at macroexpansion (fails the build) |
| `NOCOND(TEST)` | 2026-07-14 | a crash simulator armed by a debug special defaulting NIL, where the UNWIND is the mechanism under test |
| `NOCOND(GUARD)` | 2026-07-15 | a bounds/security check that CANNOT fire on valid input AND is contained at a named boundary (defense-in-depth) |
| `NOCOND(CONTRACT)` | 2026-07-15 | a developer-contract poison value: a `defstruct` slot default signalling `dds.lang:contract-violation` when a REQUIRED initarg is omitted, or an unpopulated vtable-slot lambda invoked — fires only on wrong construction/use, a bug caught first test |
| `NOCOND(BENCH)` | 2026-07-15 | a pure performance-benchmark-harness assertion (`src/dds-bench/`) — the bench's own failure mechanism, like a test assert; `dds-bench` IS our code (not wholesale-excluded like `dds-tests`) but is measurement scaffolding, not the DDS runtime |
| `NOCOND(SECURITY-FAILCLOSED)` | 2026-07-19 | a fail-closed SECURITY tamper/corruption refusal at a durability STORE boundary (a broken authentication chain — log-MAC anchor, tail anchor, epochs.mac, per-topic chain MAC — or mid-file corruption detected while OPENING a persisted store; ADR 0045/0050). The UNWIND is the security property: a tamper signal is unforgeable, whereas a status a caller forgot to check would re-admit a tampered store. Contained at the durability start boundary (asserted in gate check B) and mapped to a `ReturnCode_t`; cannot fire on an authentic store. |
| `NOCOND(WARN)` | 2026-07-19 | a `warn` DIAGNOSTIC that does not transfer control — `warn` prints and RETURNS, execution continues past it. Not a control-flow condition; logging that happens to use the condition system. Exempt only where no `handler-*` up the stack turns the warning into a non-local exit. |

The gate matches the sanctioned seven via one regex
(`NOCOND[(](MACRO|TEST|GUARD|CONTRACT|BENCH|SECURITY-FAILCLOSED|WARN)[)]`, literal parens via bracket
expressions to dodge awk's `-v` backslash-eating); an **unsanctioned `NOCOND(FOO)` is NOT exempt** (the
canary proves it still counts), so nobody invents a class the owner never ruled on.
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

## Slice 3b — the type compiler (`src/dds-gen/dsl.lisp`), and the ONE exempt class

`define-dds-type`'s ten sites are **two different things**, and the owner ruled on each (2026-07-14):

**(i) MACROEXPANSION-TIME — explicitly OK, and now an annotated exempt class `NOCOND(MACRO)`.**
Seven sites (`unsupported member type`, `:flatdata v1 requires fixed-size scalar members`, `only :final
extensibility`) fire while the macro EXPANDS: they reject a malformed type spec at **compile** time, i.e.
they fail the build. None of the three reasons for the rule can apply — there is no running program, so
such a form cannot unwind a thread, cannot allocate on a hot path, and cannot hide in a predicate. CL
offers no other way to reject a malformed macro form, and forcing it to a status would only move the
failure from build time to run time. `DEFUN*`/`DEFSTRUCT*`'s own `check-type`/`assert` are the same class.
`gate-nocond` now skips a signalling form carrying `; NOCOND(MACRO)` — and **falsifies that exemption**: a
canary proves the annotated forms are skipped, the bare one is still counted, and an in-file test's
`assert` stays excluded. (The first cut of that check went **red immediately**: the marker was used as an
awk *regex*, where `NOCOND(MACRO)` means "NOCOND" followed by the *group* `MACRO` — so it matched
`NOCONDMACRO` and never the real annotation. It is matched with `index()` as a literal now.)

**(ii) EMITTED INTO GENERATED CODE — a plain violation, exempt from nothing.** Owner: *"There MUST NEVER be
a condition emitted from a macro into code that runs at execution time."* Three sites sat inside the
backquote and were planted into every generated FlatData codec: the short-payload guards and the
non-transcodable-representation reject. They are gone. `deserialize-<name>-fd` /
`deserialize-into-<name>-fd` now return `(values sample status)` — `:SHORT-PAYLOAD` /
`:REPRESENTATION-NOT-SUPPORTED` — threaded through `%deserialize-payload` → `%deserialize-sample` →
`%drain-one-sample` / `%drain-one-secured`. The marker justifies **where the form runs, not who wrote it**:
annotate a form your macro *evaluates*; never one your macro *outputs*.

Three defects fell out of it:

- **A rejected payload LEAKED its FlatData buffer.** `deserialize-<name>-fd` allocates the sample buffer
  *before* validating the payload; the reject then unwound straight past the free. Every malformed or
  forged datagram leaked one buffer — a remote memory-exhaustion vector. The reject path frees it now.
- **A rejected SECURED payload leaked a decode-pool slot.** In `%drain-one-secured` the loan handle is
  pushed onto `dr-secured-loans` only on the delivery path, so a decode reject left the pinned pool slot
  with no owner to free it — a forged payload would starve the pool. It is returned now.
- **`(safety 0)` makes an unchecked status an OUT-OF-BOUNDS READ.** The FlatData Offset getters do not
  signal on a `NIL` sample — they read memory off `NIL` and hand back a garbage integer. The wrap fuzz
  caught this the moment the status was introduced: a caller that ignored the status and read the sample
  anyway turned a **rejected** short payload into an **accepted** one. This is the silent-swallow hazard
  made concrete, and it is why `TRY` exists.

Net RX behaviour is strictly better: a bad sample used to unwind to the receiver-thread boundary handler,
which discarded the **whole datagram** and every sample batched into it. One bad sample now costs one
sample, and the per-writer watermark still advances (an early return there would have left it unconsumed
and re-drained forever — caught in review).

## Slice 3c — the Clasp PAL: the gap was not real (`pal-clasp.lisp`, 10 -> 2)

Seven of the ten were `PAL-UNIMPLEMENTED` stubs (`load-sap-u8/u16/u32`, `store-sap-u8`, `cas-sap-u64/u32`,
`atomic-incf-sap-u64`) — a *capability* claim, not a control-flow one. Owner directive 2026-07-14: **Clasp
and SBCL MUST be equally fitted.** So they were not converted to statuses; the gap was CLOSED.

- **The loads/stores were never impossible.** `cffi:mem-ref` reads and writes a foreign cell on Clasp
  exactly as `sb-sys:sap-ref-N` does on SBCL — this very file's `LOAD-SAP-U64` already did precisely that.
- **Nor were the atomics.** ADR 0013 concluded "Clasp has no hardware atomic over a raw foreign cell". That
  is true of the *Lisp-side operators tried* (`mp:cas` rejects a `cffi:mem-ref` place as NOT-ATOMIC;
  `core:acas` silently drops a store whose compare operand exceeds `most-positive-fixnum`) but the
  conclusion did not follow. The **C atomic runtime is already linked into the Clasp image**:
  `__atomic_compare_exchange_8` / `_4` and `__atomic_fetch_add_8` resolve, are real hardware atomics
  (arm64 CASAL / x86 LOCK CMPXCHG), work on MAP_SHARED memory **across processes**, and take a plain
  pointer. MEASURED: the previous value is returned on both arms, a **full-width 2^64-1** operand
  round-trips (the exact case `core:acas` dropped), and **8 threads x 10 000 CAS-increments and fetch-adds
  lose nothing** (80 000/80 000). Cached function pointers (a by-name Clasp FFI call re-dlsyms, ~3.8 us) and
  a per-thread expected-operand cell (`*THREAD-ATOMIC-CELL*`; `WITH-FOREIGN-OBJECT` is a real ~3.3 us malloc
  on Clasp) keep it off the hot path's back.
- `run-pal-sap-atomics-test` was **gated SBCL-only**; it now runs on both impls and additionally asserts the
  full-width operand and the 8-thread contention (a CAS that is not really atomic passes every
  single-threaded check and fails only there). `PAL-UNIMPLEMENTED` is deleted. **A test that asserts a gap
  is a test that prevents the gap from being closed.**

### The part that is NOT closed — and how it nearly shipped as "fixed"

The *other* half of ADR 0013 — `shm_open`'s variadic `mode_t` on Clasp/macOS-arm64 — **is real**, and the
obvious fix (use `FOREIGN-FUNCALL-VARARGS` on Clasp too, exactly as SBCL does) **looked like it worked**: a
one-shot probe re-opened the segment by name. It was luck. Over 30 create+reopen trials:

| call form | re-openable by name |
|---|---|
| plain `foreign-funcall` (today's code) | **10/30** |
| `foreign-funcall-varargs` (the "fix") | **0/30** |
| varargs, mode as `:int` | 10/30 |
| varargs + explicit `fchmod 0600` | 0/30 |

The mode lands as **garbage**; a trial passes or fails on whether those bits happened to include owner-rw,
so a single probe "proves" whichever answer you want. macOS fixes the permission bits at creation, so there
is no Lisp-side repair. This is a Clasp CFFI variadic-ABI defect on Darwin/arm64 and it belongs upstream;
**Linux — the primary platform (§9) — passes variadic args in registers, so Clasp is fully fitted there.**
The measurement is recorded at both `dds.pal::%shm-open-create` and
`dds.xport.shmem:shm-attach-by-name-reliable-p` so nobody re-"fixes" it on a lucky run.

Consequently the zero-copy loan-write gate now asks for the **capability** (`shm-attach-by-name-reliable-p`)
instead of the **implementation name** (`(eq (pal-impl-name) :sbcl)`), so Clasp/Linux takes the loan-write
path exactly as SBCL does, and only Clasp/macOS-arm64 degrades.

## Slice — the durability microservice parser (`store-microservice.lisp`, 219 -> 202)

The reference-server backend's wire codec. A `MICROSERVICE-PROTOCOL-ERROR` unwound out of every
bounds-checked reader on a malformed datagram — from a peer, over TCP — exactly the network-facing unwind
the rule forbids. **17 of the file's 18 protocol-error sites become a status value**; the readers/decoders
return `(values result status)` and the two op boundaries handle it.

- **The readers, the UTF-8 validator, the frame/record/topic decoders, `%ms-recv-message`, and the
  server's `%ms-handle-request` are `defun*`s**, so they thread with `TRY`/`BAIL`. Status keywords name the
  failure: `:SHORT-MESSAGE` (a length exceeds the buffer extent), `:BAD-UTF8` (all seven Table-3-7
  well-formedness rejections, collapsed — a wire topic is not user-facing text that needs the granular
  reason a filter expression did), `:MALFORMED-FRAME`, `:COUNT-EXCEEDS-EXTENT`, `:BAD-BODY-LENGTH`,
  `:SHORT-FOLDED-PAYLOAD`, `:UNKNOWN-OP`, and the client encoder's `:TOPIC-TOO-LONG`.
- **`%ms-unfold-payload` returns four values** — `(values sealed status mac chain_seq)`. The status rides
  position 2 and the two extra results ride third/fourth, the same convention the filter-grammar lexer used
  for its next-index. Its one caller checks the position-2 status before touching the extras.
- **The `BUILD-FN` / `DECODE-FN` closures CANNOT use `TRY`/`BAIL`.** They are lambdas stored in the
  durable-store vtable struct and invoked long after `make-microservice-store` returns, so a `TRY` (which
  expands to `RETURN-FROM make-microservice-store`) would return into a dead extent. They thread the status
  **manually** with `MULTIPLE-VALUE-BIND`, and — the load-bearing part — a side-effecting decode-fn (the
  chained put / purge / delete / topic-rewrite that advance the client chain-MAC + put-index) checks the
  reader status **before** any mutation, so a torn response can never half-advance the chain state.
- **`%ms-call` is now fully status-based**: it checks BUILD-FN's status, then DECODE-FN's, and re-signals a
  single `MICROSERVICE-STORE-ERROR` (`clean-protocol`) for either. The `MICROSERVICE-CONN-LOST` reconnect
  handler **stays a condition** — the bounded single re-dial + idempotent retry is a genuine control-flow
  transfer, not a data value; it is a separate, harder slice. On the server, `%ms-serve-connection` drops
  the connection when `%ms-handle-request` returns a status, and its `SERIOUS-CONDITION` backstop **stays**,
  now guarding only inner-store faults, not the decoder.
- **One site is deliberately left.** `%ms-encode-open`'s `history-depth-exceeds-u32` guard sits on the
  `%ms-open` → `store-open` path, whose failure contract is the frozen durable-store vtable's, owned by the
  separate store-vtable slice. Converting it here is either net-zero churn (convert, then re-signal
  `store-error` at the `:open` lambda) or a ripple of `store-open`'s return contract out of this file, so
  the `microservice-protocol-error` condition class survives for that one guard (its docstring records the
  transitional state). This supersedes the relevant error-handling prose in ADR 0050 §4: the wire codec's
  `MICROSERVICE-PROTOCOL-ERROR` is now a status everywhere except that guard.

This also demonstrates the store-microservice file is **not** one atomic slice: the wire parser converted
with **zero change to the vtable methods' return contract** (they still signal `microservice-store-error`
on failure), so no consumer — `store-encrypted`, the reader, the service — saw a contract change. The fuzz
posture is preserved: the malformed-UTF-8 battery asserts a `:BAD-UTF8` status where it asserted a caught
condition, the over-cap-declared-length test asserts `:BAD-BODY-LENGTH`, and the server-survival +
client-symmetric legs (a garbled response still surfaces `MICROSERVICE-STORE-ERROR`) are unchanged.

## Slice — durability store tamper: two new classes + the durability start boundary (202 -> 181)

The durability stores refuse to open a **tampered / corrupted** persisted store (a broken authentication
chain or mid-file corruption; ADR 0045/0050) with a bare `error`. The owner ruled (2026-07-19) these
**keep the unwind** — a tamper signal is *unforgeable*, whereas a status a caller forgot to check would
re-admit a tampered store (the exact hazard this campaign caught twice: a dropped status re-admitted a
short/tampered payload). So they become the sixth exempt class, `NOCOND(SECURITY-FAILCLOSED)`, on the
strict condition that each is **contained at a boundary and mapped to a `ReturnCode_t`**. The `warn`
operational diagnostics — which print and *return*, transferring no control — become the seventh,
`NOCOND(WARN)`.

The boundary did not exist. The durability service has no `ReturnCode_t` keyword: its failure idiom is
OTP-style (`*durability-error-hook*` + supervisor crash/restart/shed) plus, at the process toplevel,
`uiop:quit N` (the config-parser slice already established `%durability-config-fail` → `uiop:quit 1` as
the process's ReturnCode). The **supervisor restart** path already caught `service-start` (`supervisor.lisp`),
but the **initial-start** path (`durability-service-main` → `runner-start` → `service-start` → `store-open`)
let a tamper unwind to the Lisp toplevel. This slice closes it, mirroring the two existing patterns:

- **`runner-start` gains a per-spec boundary handler** and returns `(VALUES RUNNER STATUS)` — a tamper (or
  any start failure) is caught, logged via `*durability-error-hook*`, the spec is **shed** (a
  partially-started service is reclaimed with `service-stop`, zeroizing its DEKs), and `STATUS` becomes
  `:SERVICE-START-FAILED`. Nothing escapes to the caller's thread.
- **`durability-service-main`** checks that status: a non-NIL status tears the started specs down
  (`runner-stop` — join + close + zeroize) and **fails closed with `uiop:quit 1`** (the exit code IS the
  ReturnCode_t), or returns it in the in-process (`block NIL`) path.
- **`%run-microservice-server`** wraps its startup (the DARE-blind inner store-open) in the same handler —
  `:SERVER-START-FAILED` → `uiop:quit 1` / NIL. Only startup is wrapped; the serve loop is unchanged.
- **Gate check B** now asserts both handlers exist (anchored on the `*durability-error-hook*` categories
  `:runner-start-failed` / `:server-start-failed`), so a refactor cannot silently delete them.

**21 sites annotated**: 17 `SECURITY-FAILCLOSED` (`store-encrypted` ×11, `store-sqlite` chain-break/mismatch/
downgrade ×3, `store-file` mid-file-corruption + downgrade ×2, `store-microservice` reopen chain-MAC ×1
— the guard deferred by the parser slice, decided here), 3 `WARN` (`store-encrypted`, `service`, `runner`),
1 `TEST` (the microservice forced-spawn-failure simulator). No tamper site's code changed — they stay bare
conditions; only their *containment* is now proven. **Deferred, values-conversions still owed** on this
cluster: the construction/config preconditions (`store-sqlite` requires-path/kind, `store-file` v3-frame,
`service` service-spec-shape, `runner` process-mode/argv0, `spec` ms-port).

## Contract change in this slice — every consumer

- **`runner-start`** `(function (service-runner) service-runner)` → `(function (service-runner) (values
  service-runner (or null keyword)))`. The added second value is `NIL` on full success or
  `:SERVICE-START-FAILED`. Sole non-test consumer: `durability-service-main` (`main.lisp`), updated to the
  fail-closed exit above. A second value is ignored by any caller that does not `multiple-value-bind` it, so
  the change is source-compatible for the in-image / test callers that treat the runner as before.

## Slice — encrypted store resource-exhaustion (181 -> 179)

The encrypted epoch backend's two TERMINAL resource limits — epoch-id space `2^32` (opens) and per-epoch
nonce counter `2^96` (puts) — signalled a bare `error` from the put path. `store-put` already had a
single-value rejection contract (`T` | `:REJECTED` for a bounded-full store), so these become a third
rejection keyword, **`:RESOURCE-LIMITS`**, on the primary value — no new convention, consistent with the
existing idiom. `%mint-current-epoch` (a `labels`-local fn) `return-from`s `:resource-limits`; the put
closure — a bare `lambda` with no block — is wrapped in `(block put …)` so it can `return-from put` the
status. Each site keeps a diagnostic `NOCOND(WARN)` (a terminal exhaustion should be loud; it was logged via
the old signal→handler path). `store-put`'s ftype widens to `(or (eql t) (eql :rejected)
(eql :resource-limits))`; a caller treats both non-`T` values as not-persisted, so the sole practical
consumer (the collect loop) is source-unchanged. The two limits are `2^32`/`2^96` — unreachable defence in
depth, so no test drives them; the value is that the failure mode is now in the type, not a stack unwind.

## Slice — `make-sqlite-store` construction precondition (179 -> 178)

The SQLite constructor's "requires `:path`" precondition was a lazy `error` deferred to first use (inside
`%ensure-db`). Owner ruling (2026-07-19): a construction precondition converts via a `make-*` returning
`(VALUES STORE STATUS)`. `make-sqlite-store` now bails **`:REQUIRES-PATH`** eagerly (`(unless path (bail
…))`, fail-fast, no deferred unwind) and its ftype widens to `(values (or null durable-store) (or null
keyword))`; the lazy `%ensure-db` check is deleted (`db-path` is now provably non-NIL). Both non-test callers
(`make-sqlite-store-factory`, `%make-server-inner`) always pass `:path`, so the added second value is `NIL`
and the primary value is unchanged — SBCL derives the nested `(make-encrypted-store (make-sqlite-store …))`
as a benign runtime check (`durable-store` ⊂ `(or null durable-store)`, not disjoint → no warning), so no
caller changes were needed. The sibling constructor precondition `make-microservice-store` "requires `:port`"
signals the *typed* `microservice-store-error` and is entangled with the deferred `conn-lost`/`store-error`
family, so it converts with that slice, not here.

**On the rest of the "construction/config preconditions".** Investigation reclassified them: `runner`
`process-mode`/`argv0` and `service` `service-spec-shape` are function-body preconditions inside
`%start-process-service` / `%service-topics`, both reached only from `service-start` → `runner-start`, whose
per-spec handler (the `SECURITY-FAILCLOSED` slice) already catches them at the boundary — converting them to
status is a `service-start` return-contract change (a separate cascade, not a leaf). `spec`'s `DPERSIST_*`
check sits in the store-factory *builder* (a factory-closure cascade). `store-sqlite`'s "unassigned kind" is
not a precondition at all — it is a read-path validation of a corrupt stored `kind` byte (a data-integrity
refusal on replay, closer to `SECURITY-FAILCLOSED`). Each is its own slice.

## Slice — process-mode start preconditions → status (178 -> 176)

`%start-process-service`'s two fail-fast preconditions — a `:process` spec whose store cannot cross the
subprocess boundary (`:PROCESS-MODE-NON-MEMORY-STORE`) and an unavailable `uiop:argv0` (`:NO-ARGV0`) —
signalled a bare `error` (caught at the `runner-start` boundary from the `SECURITY-FAILCLOSED` slice). They
now `(bail …)` a status; `%start-process-service` returns `(values (or null durability-service) (or null
keyword))`, and `runner-start` sheds the spec on a non-NIL status exactly as it does on a caught signal — the
`handler-case` stays for genuine signals (a failed `uiop:launch-program`). `*durability-error-hook*`'s first
parameter widens from `condition` to `(or condition keyword)` so the same per-spec rate-limited log serves a
caught condition and a converted status alike (the one test that binds the hook ignores that argument). The
B1 persistent-refuse test flips from asserting a signal to asserting the status (SBCL-only, as before).

## Slice — service-start topic-resolution precondition → status (176 -> 174)

`%service-topics` rejected a spec that yields no initial topic set — a non-cons list, or a predicate without
`:auto-discover` — with a bare `error` (caught at the `runner-start` boundary). It now `(bail …)`
`:MALFORMED-SPEC` / `:PREDICATE-TOPICS` and returns `(values list (or null keyword))`. This threads through
`service-start`, whose contract widens to `(values durability-service (or null keyword))` — the SERVICE stays
the primary value even on reject, so there is **no type ripple** and callers using the primary stay
source-compatible. The three production callers check the status: `runner-start` (thread branch) sheds the
spec exactly as it does a caught signal; the `%start-process-service` in-thread fallback propagates it; the
supervisor restart path logs + replaces (identical to its caught-signal clause) so the watcher references the
dead svc next cycle. The A3 `%service-topics` test flips its `errors-p` probe from a `handler-case` to
`(nth-value 1 …)`.

## Slice — make-microservice-store construction precondition → status (174 -> 173)

`make-microservice-store`'s "requires `:port`" precondition signalled `microservice-store-error` inside the
constructor. Per the construction-precondition ruling, it now `(bail :requires-port)` up front and returns
`(values (or null durable-store) (or null keyword))`. The conn dials **on demand** (`:sock nil` at
construction), so `:port` is a pure config check, not entangled with the `conn-lost` reconnect family. The
sole non-test caller (`make-microservice-store-factory`) always passes `:port`, feeding the primary value into
`make-encrypted-store` as a benign runtime check (no warning), so no caller change. This is the first of the
microservice family's three sub-slices; the `microservice-store-error` class stays for the non-reconnect
`store-error` signals (2-B) and the `conn-lost` reconnect state machine (2-C, the hardest).

## Slice — microservice reconnect + decode failures go status-based INTERNALLY (173 -> 165)

**Owner ruling (2026-07-19):** the microservice operation-failure family converts by EXPANDING the store vtable
contract to thread op-failure status (not an exempt class). This is the internal half. `%ms-exchange` signalled
`microservice-conn-lost` on a drop (send-fail / server-closed / recv-timeout) and `microservice-store-error` on a
non-ok status byte; the four decode-fns signalled store-error on a bad result byte. All become STATUS values:
`%ms-exchange` returns `(values (or null ms-reader) (or null keyword))` — `:CONN-LOST` / `:SERVER-ERROR`; the
decode-fns return `:BAD-PUT-RESULT` / `:BAD-DELETE-RESULT` / `:BAD-REWRITE-RESULT`. **`%ms-call`'s reconnect is
now a STATUS check** (`(when (eq status :conn-lost) (%ms-reconnect) (run))`), not a `handler-case` — the deliberate
control-transfer condition is gone; `run` checks `%ms-exchange`'s status BEFORE `decode-fn`, so a torn response
never decodes. The EXTERNAL contract is deliberately UNCHANGED: `%ms-open` re-signals `store-error` on an open
failure (store-open stays boundary-caught at `runner-start`, tamper parity), and `%ms-call`'s terminal
`clean-protocol` re-signals `store-error` for any residual status. So the client vtable still presents
`microservice-store-error`, the bounded-reconnect behaviour is byte-identical, and **no consumer or test changed**
(no test caught `conn-lost`/`store-error` directly). Commit B widens `store-put`/`get`/`delete` so the closures
RETURN the failure instead of re-signalling, and updates the collect-loop + server consumers.

## Order of the remaining work (shallow → deep)

**the durability store vtable — the tamper refusals are now `SECURITY-FAILCLOSED` (contained at the start
boundary); what remains is the VALUES conversions**: `store-microservice` `store-error`/`conn-lost` family
(the bounded reconnect state machine last), the construction/config preconditions listed above, and
`dds.pal:fsync-directory` (2 sites × 2 PALs, fail-closed on a failed dirent flush; its 9
callers are these stores). The backends migrate ONE AT A TIME — the vtable slots are closures, so a backend
still returning one value reads as `(values result NIL)` = success. Then `secure-sedp.lisp` (19) ·
**`dds-dare/primitives.lisp` (96) LAST** — the OpenSSL FFI failure chains are the biggest and deepest.

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
