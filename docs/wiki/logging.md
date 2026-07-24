# Distributed logging service — `dds.log`

The logging service (ADR 0082, FR-LOG) is an in-scope exception to the "no Connext service suite" rule: a `LogEvent` wire type plus a collector that renders structured JSON, text, and aggregator output. This page tracks what has landed.

**Status: all nine FR-LOG requirements are met.** The `LogEvent` wire type, both collector-side formatters (text + JSON), the emit path (a logger), file/stream/function/**RFC 5424 UDP-syslog**/**HTTP-bulk** sinks, and a collector (`make-logger` → DDS → `make-log-collector` → sink); the per-severity macros + `with-trace-scope` over per-category thresholds (FR-LOG-3/4); the non-blocking async ring + worker + severity-graded shedding (FR-LOG-5/6); `log-service-main`, the CLI/env entrypoint; and `make-log-service-runner` + `make-log-supervisor`, which run several collectors concurrently under one process with OTP-style restart supervision (FR-LOG-7) — all verified in-process on both SBCL and Clasp (`run-log-pipeline-test`, `run-log-macros-test`, `run-log-async-test`, `run-log-service-test`, `run-log-syslog-test`, `run-log-http-test`, `run-log-runner-test`, `run-log-supervisor-test`). `logger-emit` is the underlying emit *primitive*; the ergonomic **per-severity macros with compile-time function capture and per-category thresholds (FR-LOG-3/4)**, the **non-blocking async ring + worker + severity-graded shedding (FR-LOG-5/6)**, and the **`log-service-main` CLI/env entrypoint (FR-LOG-7, single-service)** are landed too (see below). The **RFC 5424 UDP-syslog + HTTP-bulk sinks (FR-LOG-8)**, the **multi-service runner + OTP-style supervisor (FR-LOG-7)**, and the **overflow shed reporting — snapshot + status bit + push listener (FR-LOG-6)** are landed too (see below). **All nine FR-LOG requirements are met.** The remaining logging follow-ons are cross-cutting, not new FR-LOG features: byte-exact `LogEvent` corpus vectors + a Fast DDS publisher leg (interop), a WaitSet-attachable DDS `StatusCondition` on the writer (a strict-DDS nuance of FR-LOG-6), and a lock-free ring (a measured optimization).

## The `LogEvent` wire type

`LogEvent` (ADR 0082 §3) is `@appendable`, source-keyed on `(host, process)`, and bounded throughout. It is defined by a `dds.gen:define-dds-type` form in `src/dds-log/event.lisp` and kept in **lockstep** with `interop/log/DdsLog.idl` — a foreign publisher (Connext / Fast DDS) is generated from the IDL, and a divergence between the two is a match failure nobody can see (the same discipline `interop/perftest/common/PerfData.idl` follows). It is the first non-trivial user of the type compiler's slice-1 additions — bounded strings, enums, and `@appendable` (Tasks 1–3).

Four decisions in the struct are load-bearing (ADR 0082 §3): `timestamp` is a field, not the DDS source timestamp (a queue sits between the log call and `write()`); `seq` is per-source monotonic so a collector can compute loss independently of the publisher's drop counters; the bounds are a permanent contract (`@appendable` lets fields be *added* compatibly, not string bounds *widened*); and `event_kind`/`elapsed_ns` are fields, not prose parsed back out of a message.

### API reference — `dds.log`

- **`dds.log:log-event`** / **`dds.log:make-log-event`** / **`dds.log:log-event-p`** — the generated struct, its raw constructor, and its predicate. Accessors `log-event-{host,process,participant-uuid,host-ip,app-id,thread,seq,timestamp,severity,category,function,file,line,event-kind,elapsed-ns,truncated,message}`. `participant-uuid` (the DDS participant UUID), `host-ip` (the host machine IP — **IPv4 or IPv6**; the field is `string<46>` = `INET6_ADDRSTRLEN`, holding IPv4's max 15 chars and IPv6's max 45), and `app-id` (the application identity, supplied by the application) are per-source identity fixed once at logger creation and stamped on every event, so a collector renders the *originating* logger's identity even for a remote source (owner directives 2026-07-23 / 2026-07-24); in the text format they render directly after the timestamp. `severity` and `event-kind` accessors take/return a **keyword** (`:crit`, `:exit`); an undecodable wire value reads back as the raw `int32` (never an invented keyword). `serialize-log-event` / `deserialize-log-event` / `serialized-size-log-event` are the generated `@appendable` codecs (XCDR2 = `D_CDR2_LE 0x0009` + a DHEADER; XCDR1 = no DHEADER, rule 29).
- **`dds.log:build-log-event`** — the constructor a logging call should use. It **truncates** each bounded string to its octet bound rather than refusing it — a logging call must never fail because a value is long — and sets `truncated` **T** iff the *message* was truncated (the IDL semantics: "message exceeded its bound"). `host`/`category`/`function`/`file` truncate silently. All truncation is on a UTF-8 codepoint boundary.
- **`dds.log:truncate-utf8`** — `(string max-octets) → (values result truncated-p)`. Truncates to at most `max-octets` UTF-8 octets on a codepoint boundary (never mid-character, RFC 3629 §3). The per-character octet width is derived from the code point.
- **`dds.log:+severity-emerg+` … `+severity-trace+`** — the RFC 5424 §6.2.1 Table 2 syslog severity values (`emerg=0` … `debug=7`), plus `+severity-trace+ = 8`, this stack's extension below `DEBUG`. Pinning the numbering to RFC 5424 makes the UDP-syslog `PRI = facility*8 + severity` mapping the identity. **These are read from the RFC and cited at the definition, never recalled** — a severity table is exactly the shape of thing that feels too familiar to check.
- **`dds.log:severity-to-i32` / `severity-from-i32` / `event-kind-to-i32` / `event-kind-from-i32`** — the enum ↔ int32 converters. `-from-i32` returns `(values nil :unknown-enum-value)` for a value this build does not declare.
- **`dds.log:+log-event-{host,category,function,file,message}-bound+`** — the declared octet bounds (`message` is 1024).

### Example

```lisp
(let ((e (dds.log:build-log-event
          :host "node-1" :process 4242
          :participant-uuid "8b619879-4ffe-4fca-ad01-05b39d987dbc" :host-ip "192.168.2.148"
          :severity :crit :category "MEM"
          :function "gbt_tc_core_mem_init()" :file "gbttctools/src/src.c" :line 1234
          :event-kind :exit :elapsed-ns 12000 :message "Segmentation Fault encountered")))
  (assert (eq :crit (dds.log:log-event-severity e)))
  (assert (string= "192.168.2.148" (dds.log:log-event-host-ip e)))
  (assert (null (dds.log:log-event-truncated e))))   ; message fit its bound

;; A message past 1024 octets truncates (on a codepoint boundary) and sets the flag — never refused.
(let ((e (dds.log:build-log-event :message (make-string 2000 :initial-element #\x))))
  (assert (eq t (dds.log:log-event-truncated e)))
  (assert (= 1024 (length (dds.log:log-event-message e)))))
```

### Text format — `dds.log:format-log-event-text`

**`dds.log:format-log-event-text`** renders a `log-event` to the pinned eight ` | `-separated fields (ADR 0082 §7), extended per the owner directives of 2026-07-23 (UUID/IP) and 2026-07-24 (app id) to carry the source identity directly after the timestamp:

```
<ISO-8601-UTC.6frac Z> | <participant-uuid> | <host-ip> | <app-id> | <SEVER> | <category> | <function>() - <file>:<line> | <message>
```

Severity is left-aligned in 6 columns (so `WARNING` renders `WARN`, the longest name that fits being `NOTICE`); the timestamp is the event's `timestamp` field (POSIX-epoch nanoseconds) rendered ISO 8601 UTC with six fractional digits and a `Z`; the function field holds the bare name and the `()` is added by the formatter. The `participant-uuid`, `host-ip` (IPv4 or IPv6) and `app-id` come from the event fields, so the line reflects the originating logger even when a collector renders a remote source. It is the default text formatter *closure* (ADR 0082 §7 — a formatter is a function a config holds and can replace). It is asserted **byte-for-byte against the owner's two golden example lines** (ADR 0082 §8) in `run-log-event-test`.

```lisp
(dds.log:format-log-event-text
 (dds.log:build-log-event :timestamp <posix-ns> :participant-uuid "…" :host-ip "192.168.2.148"
                          :severity :crit :category "MEM" :function "gbt_tc_core_mem_init"
                          :file "gbttctools/src/src.c" :line 1234 :message "Segmentation Fault encountered"))
;; => "…Z | … | 192.168.2.148 | gbttctools | CRIT   | MEM | gbt_tc_core_mem_init() - gbttctools/src/src.c:1234 | Segmentation Fault encountered"
```

### JSON format — `dds.log:format-log-event-json`

**`dds.log:format-log-event-json`** renders a `log-event` as one JSON object (RFC 8259) — the *newline-delimited JSON* (`json_lines`) a collector's JSON sink emits, which logstash, filebeat and vector read unchanged. `timestamp` is the ISO 8601 UTC render; `severity` and `event_kind` are their lowercase names; `truncated` is a JSON boolean; the counters (`process`, `thread`, `seq`, `line`, `elapsed_ns`) are JSON numbers. The object carries **no trailing newline** — the sink adds the record separator. Every string field is escaped with a hand-written escaper (`%json-escape`, RFC 8259 §7: `\"` `\\` `\n` `\r` `\t` `\b` `\f`, `\u00XX` for any other control character; non-ASCII stays raw UTF-8), so a message containing a quote or a newline can never break the framing — a hand-written escaper against a fixed shape avoids a new runtime dependency and SBOM entry (operating contract §9). It is the default JSON formatter *closure* (ADR 0082 §7).

```lisp
(dds.log:format-log-event-json
 (dds.log:build-log-event :host "node-1" :process 4242 :app-id "gbttctools"
                          :severity :err :event-kind :exit :seq 7 :message "he said \"hi\""))
;; => {"timestamp":"…Z","host":"node-1","process":4242,"participant_uuid":"…","host_ip":"…",
;;     "app_id":"gbttctools","thread":0,"seq":7,"severity":"err","category":"…","function":"…",
;;     "file":"…","line":0,"event_kind":"exit","elapsed_ns":0,"truncated":false,
;;     "message":"he said \"hi\""}
```

### The end-to-end pipeline — logger → DDS → collector → sink

The emit slice wires the wire type and formatters into a working pipeline (ADR 0082 §5/§6): a **logger** publishes `LogEvent` samples; a **collector** subscribes, drains them, and pushes each through its **sinks**.

**`dds.log:make-logger`** creates a producer and **detects the per-source identity once, now** (owner directives 2026-07-23/24): `host` = the given value or the machine name; `participant_uuid` = the participant's 12-octet RTPS GUID prefix (DDSI-RTPS 2.5 §8.2.4.2) rendered as 24 lowercase hex chars; `host_ip` = the given value or the participant's advertised address (IPv4 **or** IPv6 — the address at which DDS reaches this participant); `process` = the OS pid (`getpid`); `app_id` = the given application identity. It **borrows** a participant you pass (the embedded-library case) or **creates and owns** one on a domain/advertise-address. **`dds.log:logger-emit`** stamps that identity + the next per-logger `seq` + a realtime-nanosecond timestamp onto a `build-log-event` and publishes it; it returns the write status (`:ok` / `:timeout` / …), never a signalled condition — a logging call must not fail. **`dds.log:logger-spin`** drives one discovery/delivery cycle when the logger owns its participant; **`dds.log:close-logger`** deletes an owned participant.

**`dds.log:make-log-collector`** creates a consumer subscribed to the same topic/type, holding a list of sinks. **`dds.log:collector-drain`** takes all available samples and pushes each valid one through every sink (returns the count drained — the unit a test drives directly); **`dds.log:collector-run`** is the bounded drain loop; **`dds.log:close-log-collector`** closes the sinks and deletes an owned participant.

Both the writer and the reader use **`KEEP_ALL` history, not the `KEEP_LAST`-1 default**: every record for one `(host, process)` source is a *distinct* event, and `KEEP_LAST`-1 would coalesce same-key samples and silently drop all but the latest — a log must never lose records.

A **sink** is a replaceable closure pair (ADR 0082 §7): `dds.log:make-file-sink` appends each event to a file as one formatter-rendered record per line (pass `:formatter #'format-log-event-json` for JSON-lines); `dds.log:make-stream-sink` writes to any open character stream (borrows it — the service's console sink); `dds.log:make-udp-syslog-sink` sends each event as an **RFC 5424 syslog UDP datagram** (`format-log-event-syslog`, PRI = facility·8 + severity — our severity *is* the RFC 5424 numbering — so rsyslog/syslog-ng ingest it directly); `dds.log:make-http-bulk-sink` **batches** events and POSTs each batch as one HTTP/1.1 request (the ND-JSON / Elasticsearch `_bulk` / Loki-push shape; best-effort, connect-per-flush); `dds.log:make-function-sink` wraps any per-event handler (an in-memory collector, a metrics counter, a custom emitter). Swapping a sink or its formatter is a configuration change, never a collector change.

```lisp
(let* ((sink      (dds.log:make-file-sink "/var/log/app.jsonl" :formatter #'dds.log:format-log-event-json))
       (collector (dds.log:make-log-collector :domain 7 :sinks (list sink)))
       (logger    (dds.log:make-logger :domain 7 :app-id "gbttctools")))   ; host/uuid/ip/pid auto-detected
  (dds.log:logger-emit logger :severity :notice :category "SUP" :function "gbt_sup_log"
                              :message "supervisor up with 2 children")
  (dds.log:collector-run collector :seconds 1)       ; drains the published events into the sink
  (dds.log:close-logger logger)
  (dds.log:close-log-collector collector))
```

The producer's participant exposes its identity through two public DCPS accessors added for this slice — `dds.dcps:participant-guid-prefix` (the 12-octet GUID prefix) and `dds.dcps:participant-advertise-address` (the advertised IPv4/IPv6 address) — and the pid comes from `dds.pal:process-id` (POSIX `getpid`, impl-agnostic).

### The ergonomic macro API — per-severity macros, categories, `with-trace-scope`

`logger-emit` is the primitive; the everyday API is **one macro per severity** (FR-LOG-3): `log-emerg`, `log-alert`, `log-crit`, `log-err`, `log-warn`, `log-notice`, `log-info`, `log-debug`, `log-trace`. Each is `(log-<sev> logger category control &rest format-args)` — `control` is a `format` control string (with no args it is the literal message, no `format` call). The **function name is captured at compile time** from the enclosing `defun*` (via `dds.lang:current-function-name`, a local `macrolet` the `defun*` establishes), the **file** best-effort from `*compile-file-truename*`; the **line is 0** — a documented NFR-PORT gap (per-impl source-line capture is a follow-on), never a silent zero.

Every call site belongs to a **category** (a registered keyword: `:gen :sup :mem :net :disc :sec :qos :xport :app`) with an **independent threshold** (FR-LOG-4). A message at severity *L* in category *C* is emitted iff *L* ≤ the category's threshold. Defaults are `+severity-info+` — **`EMERG`…`INFO` emit; `DEBUG` and `TRACE` are off by default**. `set-log-threshold` / `get-log-threshold` tune a category at runtime. Because the category is a literal keyword, its index and name are resolved at macroexpansion, so a **disabled level costs one `aref` at a constant index plus a comparison and allocates nothing** — the `format` that builds the message sits inside the threshold gate. The RTPS data plane may therefore hold `log-debug`/`log-trace` calls behind their default-off levels at negligible cost.

**`with-trace-scope`** brackets a body with `TRACE` `:entry`/`:exit` events (the exit carrying elapsed nanoseconds) **only when `TRACE` is enabled for the category** — when it is off (the default), the body runs and **the clock is never read** (FR-LOG-4). It always returns the body's value.

```lisp
(defun* gbt-sup-start (logger)          ; the function name "gbt-sup-start" is captured at compile time
    (function (dds.log:logger) t)
  "..."
  (dds.log:log-notice logger :sup "supervisor up with ~d children" 2)   ; emitted (INFO threshold)
  (dds.log:log-debug  logger :sup "child pids ~a" (list 41 42))          ; NOT emitted (DEBUG off) — no format runs
  (dds.log:with-trace-scope (logger :sup)                               ; silent unless :sup TRACE is on
    (do-startup-work))
  t)

(dds.log:set-log-threshold :sup dds.log:+severity-debug+)   ; now :sup DEBUG (and above) emit
```

### Non-blocking emit — the async ring (`make-logger :async t`)

By default the logger is synchronous: `logger-emit` writes on the caller's thread and the app pumps `logger-spin`. Passing **`:async t`** switches on the FR-LOG-5/6 path: `logger-emit` **enqueues** on a bounded ring (default `+log-default-ring-capacity+` = 1024) and returns immediately — **it never waits for the DDS write**. A **worker thread** owns the participant: it spins it (discovery + reliable delivery) and drains the ring, writing each queued event. Because only the worker touches the participant, there is no write/spin race, and `logger-spin` becomes a harmless no-op.

On overflow the ring **sheds by severity** (FR-LOG-6): each severity has an occupancy **watermark**, and an event is dropped when the ring is at or above its watermark. `EMERG`/`ALERT`/`CRIT`/`ERR` have watermark = capacity, so they are **never shed while a slot remains**; the lower severities shed earlier — `TRACE` at 25 % full, `DEBUG` at 50 %, `INFO` at 70 % — keeping the upper slots for high-severity records. A shed event still **advances the seq**, so the loss shows up as a gap the collector can detect.

Drops are **reported, never printed** (FR-LOG-6), through the logger-scoped status machinery: a `get_*_status`-style **snapshot** — `logger-shed-counts`, per-severity counts indexed by RFC 5424 number; a **vendor status bit** `+log-shed-status+` (bit 24, clear of the OMG 0–14 status range) surfaced as a **changed flag** (`logger-shed-status-changed-p`, cleared by `logger-reset-shed-status` — the read-then-reset shape); and a **push listener** — `logger-set-shed-listener` installs a callback fired (outside the lock) as `(fn severity-number cumulative-count)` on each shed. (A WaitSet-attachable DDS `StatusCondition` on the logger's writer — the logger is not itself a DCPS entity — is a follow-on nuance.) `close-logger` stops and joins the worker (draining the ring's remainder) before deleting the participant.

```lisp
(let ((logger (dds.log:make-logger :domain 7 :app-id "gbttctools" :async t)))
  (dds.log:log-info logger :sup "started")   ; enqueue; the worker writes it — the caller never blocks
  ;; ... run ...
  (let ((sheds (dds.log:logger-shed-counts logger)))   ; per-severity drop snapshot (all zero if none)
    (declare (ignore sheds)))
  (dds.log:close-logger logger))             ; stops + joins the worker, then tears down
```

The lock-based ring is the correct-and-simple first cut, with a lock-free variant a measured optimization later.

### Running it as a service — `log-service-main`

**`dds.log:log-service-main`** is the CLI/env entrypoint that runs the collector as a service (FR-LOG-7). It parses config, builds a collector with one sink, and drains received `LogEvent`s until `SIGTERM`/`SIGINT`, then tears down and exits — the exit code is the `ReturnCode_t`. Config (CLI overrides env overrides default):

| option | env | default |
|---|---|---|
| `--domain N` | `DDS_LOG_DOMAIN` | `0` |
| `--file PATH` | `DDS_LOG_FILE` | *(none → console/stdout sink)* |
| `--format text\|json` | `DDS_LOG_FORMAT` | `text` |

`--help`/`-h` prints usage. A bad option (non-numeric domain, unknown format) is a **returned status** — `parse-log-service-config` returns `(values nil :bad-parameter)`, and `log-service-main` prints usage to standard error and exits non-zero; nothing signals (ADR 0064). Keyword arguments make it testable in-process: `:block nil` returns `(values collector status)` (or `:help`) instead of installing a signal handler and looping, and `:seconds N` bounds a `:block t` run.

```lisp
;; from a shell:  log-service-main --domain 7 --file /var/log/app.jsonl --format json
;; in-process (tests): build the collector without daemonizing, drive it yourself
(multiple-value-bind (collector status)
    (dds.log:log-service-main :block nil :argv '("--domain" "7" "--format" "json"))
  (unless status
    (dds.log:collector-run collector :seconds 5)
    (dds.log:close-log-collector collector)))
```

The sink is chosen from `--file`: a `make-file-sink` (owns the file) when a path is given, else a `make-stream-sink` over `*standard-output*` (the console sink — a new sink that *borrows* a stream, flushing but not closing it).

For running **several collectors under one process**, `dds.log:make-log-service-runner` takes a list of collectors it will own; `log-runner-start` spawns one drain thread per collector, and `log-runner-stop` joins them all and closes every collector. Each collector's participant is touched only by its own drain thread, so N collectors run without cross-thread races.

```lisp
(let ((runner (dds.log:make-log-service-runner
               (list (dds.log:make-log-collector :domain 7 :sinks (list sink-a))
                     (dds.log:make-log-collector :domain 8 :sinks (list sink-b))))))
  (dds.log:log-runner-start runner)   ; a drain thread per collector
  ;; ... run ...
  (dds.log:log-runner-stop runner))   ; joins the threads, closes the collectors
```

`dds.log:make-log-supervisor` wraps a runner with an **OTP-style one-for-one supervisor**: `log-supervisor-start` starts the runner and a monitor thread that polls each drain thread's liveness (via `dds.pal:live-threads` membership) and **restarts a dead one** — unless the restart intensity (`:max-restarts` deaths within `:window-seconds`) is exceeded, in which case that collector is **shed** (given up). `log-supervisor-stop` stops the monitor *before* the runner, so no restart races the collector teardown. Collectors are condition-free, so a drain thread never dies on its own — this is defense-in-depth for an out-of-our-control death (a signal, a foreign crash); `run-log-supervisor-test` exercises it through a fault-injection hook.

```lisp
(let ((sup (dds.log:make-log-supervisor runner :max-restarts 3 :window-seconds 5)))
  (dds.log:log-supervisor-start sup)   ; runs the collectors + restarts any that die
  ;; ... run ...
  (dds.log:log-supervisor-stop sup))   ; stops the monitor, then the runner
```

### Interop status (inherited TypeObject notes)

The type exercises two TypeObject paths that were flagged as debt in Tasks 1–2 and have since been checked against a live Connext peer (direction: our reader ← foreign writer):

- `message` is bound **1024 > 255**, so it emits **`TI_STRING8_LARGE`** — confirmed to interoperate against a Connext `string<1024>` writer (`interop/string-large/`).
- the `severity`/`event_kind` enum members emit **`TK_INT32`**, not `TK_ENUM` (the serializer cannot yet emit a `MinimalEnumeratedType`) — Connext **coerces** `TK_ENUM ↔ TK_INT32` under its default `ALLOW_TYPE_COERCION`, in both directions (`interop/enum-typeobject/`).

Still open: byte-exact `LogEvent` corpus vectors and the live Connext/Fast DDS **publisher** legs feeding our reader (FR-IO-1/2) — the next slice.

See also: [Type system & code generation](type-system.md) for the `define-dds-type` DSL this is built on, and [CDR codec, buffers & the arena](cdr-and-memory.md) for the UTF-8 string codec.
