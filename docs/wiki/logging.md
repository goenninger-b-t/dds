# Distributed logging service — `dds.log`

The logging service (ADR 0082, FR-LOG) is an in-scope exception to the "no Connext service suite" rule: a `LogEvent` wire type plus a collector that renders structured JSON, text, and aggregator output. This page tracks what has landed.

**Status: the thin end-to-end pipeline is landed** — the `LogEvent` wire type, both collector-side formatters (text + JSON), and the emit path (a logger), a file sink, and a collector: `make-logger` → DDS → `make-log-collector` → sink, verified in-process on both SBCL and Clasp (`run-log-pipeline-test`). `logger-emit` is the underlying emit *primitive* (an explicit call taking severity/category/message and the source fields as arguments); the ergonomic **per-severity macros with compile-time function/file/line capture and per-category thresholds (FR-LOG-3/4)**, the **non-blocking ring + severity-graded shedding (FR-LOG-5/6)**, the RFC 5424 UDP-syslog and HTTP-bulk sinks, the multi-service runner, the OTP-style supervisor, and the `log-service-main` CLI are follow-on slices (ADR 0082 §9). This page grows with them.

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

A **sink** is a replaceable closure pair (ADR 0082 §7): `dds.log:make-file-sink` appends each event to a file as one formatter-rendered record per line (pass `:formatter #'format-log-event-json` for JSON-lines); `dds.log:make-function-sink` wraps any per-event handler (an in-memory collector, a metrics counter, a custom emitter). Swapping a sink or its formatter is a configuration change, never a collector change.

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

### Interop status (inherited TypeObject notes)

The type exercises two TypeObject paths that were flagged as debt in Tasks 1–2 and have since been checked against a live Connext peer (direction: our reader ← foreign writer):

- `message` is bound **1024 > 255**, so it emits **`TI_STRING8_LARGE`** — confirmed to interoperate against a Connext `string<1024>` writer (`interop/string-large/`).
- the `severity`/`event_kind` enum members emit **`TK_INT32`**, not `TK_ENUM` (the serializer cannot yet emit a `MinimalEnumeratedType`) — Connext **coerces** `TK_ENUM ↔ TK_INT32` under its default `ALLOW_TYPE_COERCION`, in both directions (`interop/enum-typeobject/`).

Still open: byte-exact `LogEvent` corpus vectors and the live Connext/Fast DDS **publisher** legs feeding our reader (FR-IO-1/2) — the next slice.

See also: [Type system & code generation](type-system.md) for the `define-dds-type` DSL this is built on, and [CDR codec, buffers & the arena](cdr-and-memory.md) for the UTF-8 string codec.
