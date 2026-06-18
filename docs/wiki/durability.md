# Durability — TRANSIENT_LOCAL and the TRANSIENT Durability Service

This page covers the DDS DURABILITY QoS implementation in this stack: TRANSIENT_LOCAL
writer-side retention + late-joiner replay (fully conformant, P5/M6), and the embedded TRANSIENT
durability service (Phase 1, in-memory, writer-is-gone scenario). See also ADR 0022 and ADR 0023.

---

## 1. DURABILITY QoS overview (DDS 1.4 §2.2.3.4)

| Kind | Retention | Who keeps it |
|---|---|---|
| VOLATILE | None — samples are not retained | — |
| TRANSIENT_LOCAL | Writer keeps its HistoryCache for its own lifetime | Writer itself |
| TRANSIENT | Samples outlive the writer (in-memory service) | Durability service |
| PERSISTENT | Samples survive process + system restart (disk) | Durability service (Phase 3) |

The DURABILITY default is VOLATILE. Every behavior below is inert unless a non-VOLATILE durability
is explicitly requested.

---

## 2. TRANSIENT_LOCAL — writer-side retention + late-joiner replay

### 2.1 How it works

A TRANSIENT_LOCAL DataWriter retains its HistoryCache for its own lifetime:

- **VOLATILE writer:** full-ACK purge as before — the history is bounded by the slowest reader's ACK.
- **TRANSIENT_LOCAL / TRANSIENT / PERSISTENT writer:** no full-ACK purge. The cache is
  HISTORY-bounded (KEEP_LAST per-instance eviction) or RESOURCE_LIMITS-bounded (KEEP_ALL).

At match time, if BOTH the writer AND the matched reader are TRANSIENT_LOCAL (or stricter):

1. The writer side (`%writer-durability-init`) initializes the new reader's ReaderProxy
   `UNSENT-BASE = firstSN` (the writer's minimum retained sequence number) and sends a prompt
   HEARTBEAT `[firstSN, lastSN]`. The existing reliable push/retransmit machinery delivers
   the full pre-join history to that reader.
2. The reader side (`%reader-durability-init` + a one-shot skip-history latch) marks the matched
   writer's WriterProxy as SKIP-HISTORY if the **local reader is VOLATILE** and the **matched
   writer is a retaining writer** (TRANSIENT_LOCAL/TRANSIENT/PERSISTENT). On the first HEARTBEAT,
   a SKIP-HISTORY proxy advances its `firstSN` to `lastSN+1` so the reader skips the writer's
   pre-match history and NACKs only future gaps. The skip is latched so it applies exactly once.

A TRANSIENT_LOCAL reader matched to a retaining writer leaves SKIP-HISTORY NIL → NACKs the full
retained history → receives it.

No new transport path. The replay rides the existing StatefulWriter push / HEARTBEAT / ACKNACK /
retransmit (RTPS 2.5 §8.4.2.2).

### 2.2 `durability-finalize` — opt-in "no more late-joiners"

```lisp
(dds.dcps:durability-finalize data-writer)
```

Sets a per-writer FINALIZED flag. A finalized non-VOLATILE writer reverts to VOLATILE-style
full-ACK purge: the retained history is released once all current readers ACK; samples published
afterward behave VOLATILE. Monotonic (no un-finalize), idempotent, a no-op for a VOLATILE writer.
This is a non-standard extension on top of the conformant default.

### 2.3 Known edge — VOLATILE-reader ↔ TL-writer match-window race

For a VOLATILE reader matched to a TL writer, the skip floor is applied on the FIRST HEARTBEAT.
There is a narrow window between match and that HEARTBEAT in which a newly-written LIVE sample's
HEARTBEAT could arrive before its DATA, causing the reader to set the skip floor above the just-
published sample. This only affects the VOLATILE-reader↔TL-writer combination (not the TL↔TL path
or VOLATILE↔VOLATILE). Deferred; the race-free fix is a per-reader join-floor captured at match
time. See ADR 0022 §Known edges.

---

## 3. TRANSIENT durability service — API reference

The durability service (`dds-durability` ASDF system) is an **embedded library entity** (ADR 0021).
Load it by depending on `:dds-durability` in your system.

### 3.1 Durable store

```lisp
;; Construct an in-memory store (Phase-1 implementation)
;; MAX-SAMPLES 0 = unbounded; positive = total-record cap (store-put returns :rejected when full)
(dds.durability:make-memory-store &key (max-samples 0))   ; → durable-store

;; Dispatch functions
(dds.durability:store-put    store topic writer-guid sn key-hash kind payload)   ; → T | :REJECTED
(dds.durability:store-get-range store topic)   ; → list of durable-record
(dds.durability:store-topics store)            ; → list of topic strings
(dds.durability:store-purge  store topic)      ; → T
(dds.durability:store-count  store &optional topic)  ; → (integer 0)
(dds.durability:store-open   store)            ; → T
(dds.durability:store-close  store)            ; → T
```

`store-put` is idempotent on `(topic, writer-guid, sn)`. Records sorted by `(writer-guid, sn)` in
`store-get-range`. The store vtable is extensible — a file-backed or database-backed implementation
slots in by replacing the function slots (Phase 2/3 follow-up).

### 3.2 Service specification

```lisp
;; Construct a service spec
(dds.durability:make-service-spec
  &key (domain 0)
       topics          ; list of (topic-string . type-string) conses, or a (lambda (topic type) …) predicate
       (store (lambda () (make-memory-store)))
       (mode :thread)  ; :thread | :process
       (qos-overrides nil)  ; plist: :data-representation, :peers, :multicast
       (name ""))      ; → service-spec

;; Test if a (topic, type) pair matches the spec's filter
(dds.durability:service-spec-matches-p spec topic type)  ; → boolean
```

### 3.3 Durability service (collect + replay)

```lisp
;; Construct (not yet started)
(dds.durability:make-durability-service spec &key store)  ; → durability-service

;; Start — binds port, spawns collect-loop thread, starts replay writer
(dds.durability:service-start  service)   ; → service
;; Stop — signals loop, stops node, joins thread (idempotent)
(dds.durability:service-stop   service)   ; → T
;; Liveness probe
(dds.durability:service-alive-p service)  ; → boolean

;; Error hook — bind to observe collect-loop errors
;; signature: (condition context count) → T
;; context: :collect-loop | :supervisor-shed | :supervisor-restart-failed
(dds.durability:*durability-error-hook*)
```

### 3.4 Multi-service runner

```lisp
;; Construct a runner from a list of specs
(dds.durability:make-service-runner specs)   ; → service-runner

;; Start all services (double-start is a no-op)
(dds.durability:runner-start runner)  ; → runner
;; Stop all services; nulls the services list; runner may be restarted after stop
(dds.durability:runner-stop  runner)  ; → T
;; (name . alive-p) pairs for each service
(dds.durability:runner-status runner)  ; → list
```

### 3.5 OTP-style supervisor

```lisp
;; Construct a supervisor for RUNNER
(dds.durability:make-supervisor runner
  &key (max-restarts 3)    ; cap: at most MAX-RESTARTS in WINDOW-SECONDS
       (window-seconds 5)
       (poll-ms 50))       ; → supervisor

;; Start/stop the watcher thread
(dds.durability:supervisor-start supervisor)   ; → supervisor
(dds.durability:supervisor-stop  supervisor)   ; → T

;; T iff the named service has been shed (restart-intensity exceeded)
(dds.durability:supervisor-shed-p supervisor name)  ; → boolean
```

Restart semantics are OTP permanent: any service termination (crash or deliberate `service-stop`)
triggers a restart until the intensity cap sheds the service. To stop a supervised service
permanently, stop the supervisor or the runner.

### 3.6 CLI/env entrypoint

```lisp
;; PURE parse (no I/O): argv list + env alist or 1-arg fn
;; Returns (values specs max-restarts window-seconds)
;; Signals DURABILITY-CONFIG-ERROR on malformed input (explicit, safety-level-independent)
(dds.durability:parse-durability-config &key (argv '()) (env '()))

;; Main entrypoint (subprocess body or embedded start)
;; ARGV defaults to UIOP:COMMAND-LINE-ARGUMENTS when NIL
;; BLOCK T = loop until killed; NIL = return (cons runner sup)
(dds.durability:durability-service-main &key argv env (block t))
```

CLI flags: `--domain N`, `--topic NAME:TYPE`, `--mode thread|process`,
`--max-restarts N`, `--window-seconds N`, `--name S`.

Env vars: `DDS_DURABILITY_DOMAIN`, `DDS_DURABILITY_TOPICS` (comma-separated `NAME:TYPE`),
`DDS_DURABILITY_MODE`, `DDS_DURABILITY_NAME`.

Config precedence: CLI > env > defaults.

---

## 4. Worked example — embedded TRANSIENT durability service

This example starts a service that collects TRANSIENT samples from "Square/ShapeType" on domain 7,
lets an application write TL samples, then shows a late-joiner receiving them after the original
writer is gone. All on loopback, in-process `:thread` mode.

```lisp
(require :dds-durability)

;;; Build the store + spec
(defparameter *store*
  (dds.durability:make-memory-store :max-samples 10000))

(defparameter *spec*
  (dds.durability:make-service-spec
   :domain 7
   :topics '(("Square" . "ShapeType"))
   :store (lambda () *store*)
   :mode :thread
   :name "my-durability-service"))

;;; Build and start the runner + supervisor
(defparameter *runner* (dds.durability:make-service-runner (list *spec*)))
(defparameter *sup*    (dds.durability:make-supervisor *runner*
                                                       :max-restarts 5
                                                       :window-seconds 10))
(dds.durability:runner-start *runner*)
(dds.durability:supervisor-start *sup*)

;;; Check status
(dds.durability:runner-status *runner*)
;; => (("my-durability-service" . T))

;;; ... application publishes TL samples to domain 7 "Square/ShapeType" ...
;;; ... original publisher exits ...
;;; ... late-joiner reader joins domain 7 "Square/ShapeType" ...
;;; The service replays the retained history to the late-joiner.

;;; Inspect the store
(dds.durability:store-count *store* "Square")
;; => N   (number of retained records)

(dds.durability:store-topics *store*)
;; => ("Square")

;;; Teardown
(dds.durability:supervisor-stop *sup*)
(dds.durability:runner-stop *runner*)
```

### QoS overrides for foreign-peer interop

To interoperate with Connext / Fast DDS peers that default to XCDR1, supply a
`:data-representation` override so the replay writer advertises XCDR1 in SEDP:

```lisp
(dds.durability:make-service-spec
 :domain 0
 :topics '(("Square" . "ShapeType"))
 :qos-overrides '(:data-representation (:xcdr1)
                  :peers (("127.0.0.1" . 7400)))
 :name "interop-service")
```

---

## 5. `durability-service-main` CLI reference

Invoke as a subprocess (or directly for testing):

```
sbcl --dynamic-space-size 512 \
     --eval '(require :asdf)' \
     --eval '(asdf:load-system :dds-durability)' \
     --eval '(dds.durability:durability-service-main
              :argv (list "--domain" "0"
                          "--topic" "Square:ShapeType"
                          "--mode" "thread"
                          "--max-restarts" "5"
                          "--window-seconds" "10"
                          "--name" "my-service"))'
```

Or via env (all flags have env equivalents):

```
DDS_DURABILITY_DOMAIN=0 \
DDS_DURABILITY_TOPICS="Square:ShapeType,Circle:ShapeType" \
DDS_DURABILITY_MODE=thread \
DDS_DURABILITY_NAME=my-service \
sbcl --eval '(require :asdf)' \
     --eval '(asdf:load-system :dds-durability)' \
     --eval '(dds.durability:durability-service-main)'
```

---

## 6. Phase-1 limitations

- **Writer-is-gone scenario only.** No-double-delivery (original writer alive + service both
  matched) is Phase 2 (`PID_ORIGINAL_WRITER_INFO 0x0061` inline QoS carrier; spike confirmed in
  `docs/superpowers/spikes/2026-06-18-durability-virtual-guid-findings.md`).
- **One topic per service node.** Multi-topic-per-service is Phase 2.
- **DATA-kind capture only.** Dispose/unregister replay is Phase 2.
- **In-memory store.** State is lost on process restart. Disk-backed + CNSA-2.0 DARE is Phase 3.
- **`:process` mode is SBCL-only** (runtime fallback to in-thread on other impls).

See ADR 0023 §Phase-1 limitations for the full record.

---

## 7. Cross-references

- ADR 0021 — Durability service scope decision (owner directive 2026-06-18)
- ADR 0022 — TRANSIENT_LOCAL as-built behavior (writer-side retention + late-joiner replay)
- ADR 0023 — TRANSIENT durability service Phase-1 architecture
- `docs/superpowers/spikes/2026-06-18-durability-virtual-guid-findings.md` — PID_ORIGINAL_WRITER_INFO spike
- `interop/durability-transient/` — cross-DDS interop captures and README
- `src/dds-durability/` — service implementation (store / spec / service / runner / supervisor / main)
- `src/dds-tests/durability-test.lisp` — unit + integration tests
