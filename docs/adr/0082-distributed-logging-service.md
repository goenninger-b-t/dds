# ADR 0082 — distributed logging: a public log type, an emit path that cannot stall the application, and a collector service

- **Status:** Accepted
- **Date:** 2026-07-23
- **Requirements:** FR-LOG-1..9 (new, §5.14); FR-IO-1/2/4 (the type is a public wire contract); NFR-MEM, NFR-OBS
- **Spec:** RFC 5424 §6.2.1 (syslog severity numbering) · RFC 5424 §6 (the syslog message format the UDP sink emits) · ISO 8601-1:2019 (the timestamp rendering) · OMG XTypes 1.3 §7.2.2 (APPENDABLE extensibility) · DDS 1.4 §2.2.3 (RELIABILITY, HISTORY, RESOURCE_LIMITS)
- **Owner directive:** 2026-07-23 — a distributed logging service receiving log publications on a configurable domain with a predefined log DDS type, emitting structured JSON and text log files and feeding a log aggregation solution; a `dds.log` package and API with syslog levels and categories.
- **Owner decisions (2026-07-23):** publishers are **any vendor** — C, C++, our own stack; QoS is **RELIABLE KEEP_ALL behind a non-blocking queue with a worker thread that applies backpressure**; sinks are **configurable** (JSON file and/or RFC 5424 UDP syslog and/or HTTP bulk) with the **JSON produced by a replaceable formatter function**; **TRACE entry/exit belongs in slice 1**; wire type is **structured fields, `@appendable`**; queue overflow is **severity-graded shedding with reported drop counts**; the topic is **keyed on source identity**.

## 1. The problem

Logging in a distributed system is a data-distribution problem that everyone solves twice: once badly, with
files and `scp`, and once properly, with a bus. This stack *is* the bus. What is missing is a type every
language binding can publish, an emit path an application can afford to leave in production, and a collector
that renders the result into the formats operations teams already consume.

Three properties decide whether such a thing is used or switched off:

1. **It must never become the reason an application is slow.** A logging call that can block on a socket, a
   disk, or a slow collector converts an observability feature into an availability risk.
2. **It must not lie about loss.** Any bounded system drops under sufficient load. What separates a usable
   logger from an unusable one is that the drops are *counted*, *reported*, and *biased* — a flood of TRACE
   must never be the reason a CRIT is lost.
3. **The contract must be the type, not the text.** The five-field line is a *rendering*. If foreign
   publishers had to agree on a text format, every consumer would be a parser and every format change a
   breaking change.

## 2. Scope — this is an addition, recorded rather than assumed

`REQUIREMENTS.md` §1.2 puts the Connext *Professional* service suite out of scope, with the durability
service the single carved-out exception (ADR 0021). A logging service is a **second** exception, added by
owner directive on 2026-07-23. It is recorded here and in §1.2 and §5.14 of `REQUIREMENTS.md` rather than
absorbed silently, because "we quietly grew a service" is how a scope boundary stops meaning anything.

Note what it is *not*: this is **not** the DDS Security *Logging plugin* (FR-SEC-1, [SEC] §9.6), which is a
separate, security-audited channel for security events. The two may share a rendering later; they do not
share a topic, and this ADR does not claim the security requirement.

## 3. The wire type — `LogEvent`

Structured fields, `@appendable`, bounded throughout, keyed on source. The IDL lives at
`interop/log/DdsLog.idl` and is kept in lockstep with the `dds.gen:define-dds-type` form exactly as
`interop/perftest/PerfData.idl` is — the same discipline, for the same reason: a foreign publisher is
generated from the IDL, and a divergence between the two is a match failure nobody can see.

```idl
module dds { module log {

  // Severity values are the syslog numbering of RFC 5424 §6.2.1 Table 2, so the mapping to the UDP syslog
  // sink is the identity. TRACE extends the range below DEBUG; RFC 5424 defines 0..7 only.
  enum Severity { SEV_EMERG = 0, SEV_ALERT = 1, SEV_CRIT  = 2, SEV_ERR   = 3,
                  SEV_WARN  = 4, SEV_NOTICE= 5, SEV_INFO  = 6, SEV_DEBUG = 7,
                  SEV_TRACE = 8 };   // 0..7 verbatim from RFC 5424; 8 is this stack's extension

  enum EventKind { EV_MESSAGE, EV_ENTRY, EV_EXIT };

  @extensibility(APPENDABLE)
  struct LogEvent {
    @key string<64> host;        // node identity
    @key uint32     process;     // OS process id
    uint32          thread;      // informational
    uint64          sequence;    // per-source monotonic; gaps are visible loss
    int64           timestamp;   // UTC nanoseconds since the POSIX epoch
    Severity        severity;
    string<16>      category;    // "SUP", "MEM"
    string<128>     function;
    string<256>     file;
    uint32          line;
    EventKind       event_kind;
    uint64          elapsed_ns;  // EV_EXIT only; 0 otherwise
    boolean         truncated;   // message exceeded its bound
    string<1024>    message;
  };
}};
```

**The severity constants are read from RFC 5424 at implementation time and cited at the definition, never
typed from memory.** This project's most expensive bug class is a wire constant recalled rather than read
(§4 of ADR 0081 is one such retraction), and a severity table is exactly the shape of thing that feels too
familiar to check.

Four decisions in that struct are load-bearing:

- **`timestamp` is a field, not the DDS source timestamp.** A queue sits between the log call and `write()`,
  so the source timestamp records when the *worker* published, not when the event happened. Under load —
  precisely when timing matters — the two diverge by exactly the queueing delay.
- **`sequence` makes loss observable.** With per-source monotonic numbering, a collector can compute what it
  never received, independently of whatever the publisher's drop counters claim.
- **Bounds are permanent.** `@appendable` (XTypes 1.3 §7.2.2) lets fields be *added* compatibly; it does not
  let a string bound be *widened* compatibly. The bounds above are therefore a one-time contract. `message`
  is **1024**. Bounded strings are also what allows the emit path to render into a fixed buffer.
  `rtiddsgen` silently bounds an unbounded `string` at 255, which already made one of our types structurally
  incompatible with its Connext twin (ADR 0009) — unbounded is not an option here.
- **`event_kind` and `elapsed_ns` are fields, not prose.** "EXIT after 12 us" parsed back out of a message is
  not structured logging. This is why TRACE belongs in slice 1: adding these later is a wire change.

**Keyed on `(host, process)`** — one instance per logging process. That buys per-source ordering and history,
lets a dead process's instance be disposed and its resources reclaimed, and makes RESOURCE_LIMITS per-source,
so one runaway process cannot exhaust the collector's history for everybody else.

## 4. `dds.log` — the emit API

```lisp
(define-log-category :mem "MEM")          ; assigns a constant small integer id at load time

(log-notice :sup "supervisor up with ~d children" n)
(log-crit   :mem "Segmentation Fault encountered. ~a" detail)

(with-trace-scope (:mem)                   ; ENTRY on entry, EXIT + elapsed_ns on exit
  (do-work))
```

Nine macros, one per severity, plus `with-trace-scope`. Each expands to

```lisp
(when (level-enabled-p <constant-category-id> <constant-severity>)
  (%log-emit ...))
```

where `level-enabled-p` is one `aref` into a `(simple-array (unsigned-byte 8) (*))` **at a constant index**
followed by a comparison, declaimed `inline`. **Disabled costs one threshold check and allocates nothing**,
and `with-trace-scope` does not read the clock at all when TRACE is off for that category — the directive was
that leaving the macros in production costs a threshold check, and that is a measured test, not an assertion.

### 4.1 Capturing function, file and line — the one genuinely hard part

Common Lisp has no `__func__`/`__FILE__`/`__LINE__`. Two mechanisms, deliberately different in confidence:

- **Function name — exact, zero runtime cost.** `defun*` (which defines every function in this codebase)
  gains a `macrolet` that makes the enclosing definition's name available lexically. A macro expanded inside
  a `defun*` body reads it at macroexpansion time; outside one, a global fallback yields `NIL`. This touches
  a core macro in `dds.lang`, so it is additive and compile-time only, and it is called out here because
  every function in the system is affected by construction.
- **File and line — best effort, per implementation.** Source location is implementation-specific, so it
  lives behind a `dds.pal` macro and therefore in `dds-pal/` — the only place reader conditionals are
  permitted. Where an implementation cannot supply a line, it reports **0**, and that is a documented
  NFR-PORT gap rather than a silent zero.

### 4.2 What this API does *not* claim

**Enabled logging allocates**, because it formats. `dds.log` is not hot-path-pure; the RTPS data plane must
not call it except behind a level that is disabled by default. A zero-allocation *enabled* emit path (render
into an arena-backed fixed buffer with a restricted directive set) is a follow-on slice, and is not claimed
by slice 1. Stating this is cheaper than discovering it in a bench run.

## 5. The queue, the worker, and what "backpressure" actually means

```
log-<level> ──► bounded ring ──► worker thread ──► DataWriter (RELIABLE, KEEP_ALL)
   never blocks       │                                   │
                      └─ sheds by severity, counts it     └─ blocks HERE when history is full
```

Reliability is end-to-end. The queue absorbs backpressure. Overflow sheds by severity.

When the writer's KEEP_ALL history fills — a slow or absent collector — `write` blocks or refuses, and **the
worker** waits. The application never does. The ring then backs up and shedding begins from the bottom:
TRACE first, then DEBUG, then INFO, each with its own free-slot threshold; `EMERG`, `ALERT`, `CRIT` and `ERR`
are never shed while any slot remains. That is the entire point of grading — a burst of TRACE must not be
the reason a CRIT is lost.

**Every drop is counted per severity and REPORTED through the DDS status machinery** — a vendor status bit
clear of the OMG 0–14 range, a StatusCondition, a listener callback and a `get_*_status` snapshot — never
printed. A `format` to `*error-output*` is unconsumable by an application, untestable by a caller and
invisible in a service; that is a standing rule here (ADR 0080), and a logging subsystem announcing its own
failures by printing would be a particularly poor joke.

The service reuses the **same** queue between its DataReader and its sinks, so a slow HTTP sink cannot stall
reception. One abstraction, two uses.

## 6. The service

`src/dds-log/`, mirroring the durability service's proven shape (ADR 0021) rather than inventing a second
service idiom:

| file | responsibility |
|---|---|
| `event.lisp` | the `LogEvent` type, construction, truncation |
| `emit.lisp` | client API, category table, ring, worker, shedding, drop statuses |
| `formatter.lisp` | text and JSON renderers, as replaceable closures |
| `sink.lisp` | file / UDP-syslog / HTTP-bulk sinks, as replaceable closures |
| `service.lisp` | reader, per-sink queues and workers, lifecycle |
| `runner.lisp` | multi-service runner, `(values runner status)` |
| `supervisor.lisp` | OTP-style restart policy |
| `main.lisp` | `log-service-main` — `--flag`/env config, blocking mode, `uiop:quit` carrying the `ReturnCode_t` |

Configuration: domain, topic name, per-category level thresholds, queue depth and shed thresholds, and a
list of sinks each with its own options.

## 7. Rendering — formatters and sinks are functions

Both are **structs of closures**, the same vtable pattern the durability store uses, so "the emitted JSON
must be formattable by a formatter function" is satisfied literally: the formatter *is* a function, and
replacing it is a configuration change.

**Text format**, deduced from the owner's examples and pinned here:

```
2026-07-23T11:28:53.645329Z | NOTICE | SUP | gbt_sup_log() - gbttctools/src/core/l6/sup/sup.c:93 | supervisor up with 2 children
2026-07-23T11:20:13.501947Z | CRIT   | MEM | gbt_tc_core_mem_init() - gbttctools/src/src.c:1234 | Segmentation Fault encountered. …
```

Five ` | `-separated fields: ISO 8601 UTC with **six** fractional digits and a `Z`; severity **left-aligned in
6 columns**; category; `<function>() - <file>:<line>`; message. The 6-column severity is what fixes the
spelling: `NOTICE` is 6 characters and is the longest name that fits, so **`WARNING` is rendered `WARN`**.
Both example lines are golden test vectors (§8).

**JSON**: newline-delimited, one object per event — the framing logstash's `json_lines` codec expects, and
the framing `filebeat` and `vector` read unchanged. The escaper is hand-written: a log object is a fixed
shape, so this is a few dozen lines against a new runtime dependency and an SBOM entry, and §9 of the
operating contract requires every dependency be justified.

**UDP syslog** (follow-on slice) emits RFC 5424 with `PRI = facility*8 + severity`, which is free precisely
because §3 pinned the severity numbering to RFC 5424 rather than inventing one.

## 8. How it is proven

- **The owner's two example lines are golden vectors.** The text formatter is asserted byte-for-byte against
  them. That is a better oracle than any format this ADR could invent.
- **XCDR byte-exact corpus** for `LogEvent`, both endiannesses — mandatory for a public wire type (FR-CDR-8),
  and the thing that makes the IDL and the Lisp definition provably the same type.
- **Live interop legs**: a Connext publisher and a Fast DDS publisher feeding our service (FR-IO-1/2). Per the
  standing rule, a green Fast DDS run never substitutes for the Connext leg — Fast DDS is lenient and will
  accept payloads Connext rejects.
- **Falsified shedding test**: a full ring must drop TRACE and retain CRIT, and the test is shown red by
  removing the grading. A shedding policy nobody has watched fail is a shedding policy nobody has.
- **Measured zero-allocation disabled path**: the claim in §4 is a number from the allocation harness, not an
  adjective.
- **Loss accounting**: drop counters plus `sequence` gaps must agree in a deliberate overload run.

## 9. Slice ladder

1. **Slice 1 (MVP, vertical):** type + IDL + corpus · `dds.log` with categories, levels and
   `with-trace-scope` · ring, worker, severity shedding, drop statuses · service subscribing on a
   configurable domain · text and JSON file sinks · golden vectors · REQUIREMENTS/wiki/verification entries.
2. UDP syslog RFC 5424 sink.
3. HTTP bulk sink (batching, retry, partial failure).
4. Foreign-vendor interop legs wired into `make interop`.
5. Rotation and retention.
6. Zero-allocation *enabled* emit path.

## 10. Consequences and risks

- **The type is now a public contract.** Every bound and every field is frozen for foreign publishers.
  `@appendable` limits the damage to additions; it does not make widening a bound compatible.
- **`defun*` gains a `macrolet`.** Additive and compile-time only, but it is the macro every function in the
  system is defined with, so the change is reviewed as a core change, not a logging change.
- **Line numbers are not portable.** The PAL gives them where it can and 0 where it cannot; a missing line
  number must never be mistaken for line 0 of a real file.
- **A logging service can be a covert channel.** Log content crosses the bus; a deployment carrying sensitive
  data must apply DDS Security governance to the log topic exactly as to any other. This ADR does not make
  the log topic a security-audited channel, and must not be read as satisfying FR-SEC-1's Logging plugin.
- **Shedding is a policy, and policies age.** The thresholds are configuration, not constants, so an
  operator can retune without a rebuild.
