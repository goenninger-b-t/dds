# Durability — TRANSIENT_LOCAL, the TRANSIENT/PERSISTENT Durability Service, and DARE

This page covers the DDS DURABILITY QoS implementation in this stack: TRANSIENT_LOCAL writer-side
retention + late-joiner replay (fully conformant, P5/M6, §2); the embedded durability service with
its in-memory TRANSIENT tier (§3–§6) and dedup/no-double-delivery (§6); always-on CNSA-2.0
Data-At-Rest Encryption (DARE, §7); and the **disk-backed PERSISTENT tier** that survives a
process/system restart, always DARE-wrapped with a cross-restart key-epoch (§8). See also ADR 0022,
0023, 0024, 0025 and 0026.

---

## 1. DURABILITY QoS overview (DDS 1.4 §2.2.3.4)

| Kind | Retention | Who keeps it |
|---|---|---|
| VOLATILE | None — samples are not retained | — |
| TRANSIENT_LOCAL | Writer keeps its HistoryCache for its own lifetime | Writer itself |
| TRANSIENT | Samples outlive the writer (in-memory service) | Durability service |
| PERSISTENT | Samples survive process + system restart (disk) | Durability service (Phase 3b — landed, §8) |

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

**Match-gate (RTPS 2.5 §8.4.10.1).** The reader answers a user HEARTBEAT — and emits the
history-requesting ACKNACK / NACK_FRAG — only for a **matched** writer (`%guid-matched-p`). A user
HEARTBEAT that arrives before the reader has processed the writer's SEDP publication is **dropped**
(it would otherwise create the WriterProxy with SKIP-HISTORY un-armed and NACK the full pre-join
history to the static peer — a VOLATILE reader would wrongly pull it); the writer's next periodic
HEARTBEAT re-arrives after the match, when the durability baseline above is armed. The symmetric
writer-side window is closed the same way: a newly-matched reader's ReaderProxy is future-only-based
(`UNSENT-BASE = lastSN+1`) before the reader becomes a push destination, so a concurrent publish
racing the match cannot replay pre-join history; the TRANSIENT_LOCAL replay then refines it to
`firstSN`. (ADR 0043.)

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

### 2.3 N durable writers per participant (different topics)

A single participant may hold multiple RETAINING-durability (TRANSIENT_LOCAL / TRANSIENT /
PERSISTENT) DataWriters on **distinct** topics; each replays its OWN retained pre-join history to a
matched late reader — its own `firstSN` base and its own prompt HEARTBEAT under its own GUID
(WP-N-ENDPOINT-S2B, ADR 0048 §14). The match-time priming resolves the matched local writer by the
remote reader's topic (`%on-disc-match` → `%participant-writer-for-topic`) and threads it through the
proxy-base rewind (`%writer-durability-init` / `%prearm-writer-future-base`), the prompt HEARTBEAT
(bound via `*emit-writer*` so its writerId is that writer's EntityId), and the full-ACK purge — so
each durable writer is primed off its OWN HistoryCache, never the participant's primary writer. The
retained-history replay reuses the per-writer retransmit path (the writerId-routed ACKNACK repair).
`durability-finalize` is per-writer: finalizing one durable writer never releases a sibling's
retained history. A single durable writer is byte-identical (the matched writer IS the primary).
Same-topic durable multi-writer is SUPPORTED (Slice 2c-2, WP-N-ENDPOINT-2C2-WRITERS, ADR 0048 §16): two+
TRANSIENT_LOCAL writers on the SAME topic each replay their OWN retained history to a late reader. The match
hook threads the matched-LOCAL writer EntityId (`%fire-match` → `%on-disc-match`) and fires per-(local,remote)
pair, so `%writer-durability-init`/`%prearm` prime EACH matched writer off ITS OWN HistoryCache. Fence C in
`add-local-writer` (the former `%same-topic-durable-writer-conflict-p` guard, ADR 0048 §14.3a) is LIFTED.

### 2.4 Known edge — VOLATILE-reader ↔ TL-writer match-window race

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
(dds.durability:store-put    store topic writer-guid sn key-hash kind payload)   ; → T | :REJECTED | :RESOURCE-LIMITS
(dds.durability:store-get-range store topic)   ; → list of durable-record
(dds.durability:store-topics store)            ; → list of topic strings
(dds.durability:store-purge  store topic)      ; → T
(dds.durability:store-count  store &optional topic)  ; → (integer 0)
(dds.durability:store-open   store &optional history-kind history-depth)  ; → T
(dds.durability:store-close  store)            ; → T
```

`store-put` is idempotent on `(topic, writer-guid, sn)`. Records sorted by `(writer-guid, sn)` in
`store-get-range`. The store vtable is extensible — a file-backed or database-backed implementation
slots in by replacing the function slots (Phase 2/3 follow-up).

`store-open` accepts optional `history-kind` (`:keep-all` | `:keep-last`) and `history-depth`
(positive integer) arguments. When supplied they override the store's factory-time defaults
and drive compaction-on-open (file-store) or online eviction (in-memory store) for the lifetime
of that open. `service-start` calls `store-open` with the service-spec's `history-kind` and
`history-depth`, making the service-spec the single functional policy source in service mode
(ADR 0029, DDS 1.4 §2.2.3.5).

### 3.2 Service specification

```lisp
;; Construct a service spec
(dds.durability:make-service-spec
  &key (domain 0)
       topics          ; list of (topic-string . type-string) conses, or a (lambda (topic type) …) predicate
       (store (lambda () (make-memory-store)))
       (mode :thread)  ; :thread | :process
       (qos-overrides nil)  ; plist: :data-representation, :peers, :multicast
       (history-kind  :keep-all) ; DURABILITY_SERVICE history_kind: :keep-all | :keep-last (DDS 1.4 §2.2.3.5)
       (history-depth 1)         ; KEEP_LAST depth bound per non-NIL-key-hash instance (integer >= 1)
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
;; signature: (reason context count) → T   ; reason: a caught condition, or a status keyword (ADR 0064)
;; context: :collect-loop | :supervisor-shed | :supervisor-restart-failed
;;          | :runner-start-failed | :server-start-failed   ; a spec / server store-open failed at start
(dds.durability:*durability-error-hook*)
```

### 3.4 Multi-service runner

```lisp
;; Construct a runner from a list of specs
(dds.durability:make-service-runner specs)   ; → service-runner

;; Start all services (double-start is a no-op)
;; → (values runner status): status NIL on success, or :service-start-failed if a spec failed to
;;   start (e.g. a tampered store refused to open, ADR 0045). The failed spec is caught + shed at this
;;   boundary (never unwinds); the toplevel maps a non-NIL status to a fail-closed non-zero exit.
(dds.durability:runner-start runner)  ; → (values runner status)
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

;; PURE parse of the microservice-SERVER mode (--backend server; ADR 0050 §4.8) -> a SERVER-CONFIG
(dds.durability:parse-durability-server-config &key (argv '()) (env '()))

;; The full usage/help text (both modes); printed on --help/-h
(dds.durability:durability-usage)

;; Main entrypoint (subprocess body or embedded start)
;; ARGV defaults to UIOP:COMMAND-LINE-ARGUMENTS when NIL
;; BLOCK T = loop until killed; NIL = return (cons runner sup) [service] / the server [--backend server]
(dds.durability:durability-service-main &key argv env (block t))
```

**Default mode (durability SERVICE)** — CLI flags: `--domain N`, `--topic NAME:TYPE`,
`--mode thread|process`, `--max-restarts N`, `--window-seconds N`, `--name S`.
Env vars: `DDS_DURABILITY_DOMAIN`, `DDS_DURABILITY_TOPICS` (comma-separated `NAME:TYPE`),
`DDS_DURABILITY_MODE`, `DDS_DURABILITY_NAME`.

**Service persistence backend (`--backend {file|sqlite|microservice}`, ADR 0050 §4.9, semantics A)** —
selects the durability SERVICE's OWN client-side persistence store (wired to the shared
`make-durability-store-factory`; see §5.3). CLI flags: `--backend file|sqlite|microservice`,
`--dir DIR` (**required** for `--backend file|sqlite` — the durable store dir, no temp fallback; for
`--backend microservice` the client-local DARE epoch-dir, default `<tmp>/dds-durability/`),
`--key-dir DIR` (ML-KEM-1024 key dir; default `DIR/keys/`),
`--ms-host HOST` (default `127.0.0.1`) and `--ms-port PORT` (**required** for `--backend microservice`).
Env: `DDS_DURABILITY_{BACKEND,DIR,KEY_DIR,MS_HOST,MS_PORT}`. **When `--backend` is omitted the service keeps
its in-memory default — no behavior change.** The value `server` is **reserved** for the SERVER mode below
(semantics B); the two `--backend` roles never collide (`%durability-server-mode-p` intercepts `server`
before the service parser). A bad value → a clean `durability-config-error` naming
`{file|sqlite|microservice|server}`.

**Microservice SERVER mode (`--backend server`, ADR 0050 §4.8, semantics B)** — run the DARE-blind
persistent key-value server durability clients connect to as their microservice backend. CLI flags:
`--host HOST` (default `127.0.0.1`), `--port PORT` (**required**), `--inner-backend file|sqlite`
(default `file`), `--inner-dir DIR` (**required**), `--max-connections N` (default 64),
`--recv-timeout SECONDS` (default 30). Env: `DDS_DURABILITY_BACKEND=server` +
`DDS_DURABILITY_{HOST,PORT,INNER_BACKEND,INNER_DIR,MAX_CONNECTIONS,RECV_TIMEOUT}`. See §5.2 and §8.10.8.

Config precedence: CLI > env > defaults. `--help` / `-h` prints the usage for both modes.

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

### 5.1 Signal-driven graceful shutdown (WP-GRACEFUL-FFI-TEARDOWN, ADR 0030)

When `:block t` (the default), `durability-service-main` installs a **SIGTERM/SIGINT handler**
via `dds.pal:install-signal-handler` and blocks until the handler fires.  On receipt:

```
supervisor-stop   ; no more restarts
runner-stop       ; service-stop each service = join collect threads THEN store-close
                  ; store-close:  fsync + free DARE DEKs + free static arena
uiop:quit 0       ; no live foreign pointer at this point
```

The handler sets a flag (`*durability-shutdown-requested*`); all teardown runs in the blocking
Lisp thread, never in the signal context.

**PAL primitive:** `dds.pal:install-signal-handler signals callback → t`

- `signals` — list of `(member :term :int)`
- `callback` — 0-arg fn; must be minimal (set a flag / wake a thread; never do teardown inline)

Implementations:
- **SBCL** — `sb-sys:enable-interrupt` for `sb-unix:sigterm` / `sb-unix:sigint`.
- **Clasp** — `mp:service-interrupt :around` methods on `core:sigterm` / `core:sigint`;
  dispatched via an alist guarded by `*signal-handler-lock*`.

No reader conditional escapes `dds-pal/`.

**Live proof:** `interop/graceful-shutdown/run-kill15.sh` — launches a PERSISTENT (DARE/file)
service on both Clasp and SBCL, sends `kill -15`, and asserts: status 0, no SIGBUS.
Result (2026-06-22): **both impls clean exit, no SIGBUS** (ADR 0026 §10 item 3 RESOLVED).

### 5.2 Microservice SERVER mode (`--backend server`, ADR 0050 §4.8)

Run the DARE-blind persistent microservice **server** — the KV server durability clients connect to as
their microservice backend (§8.10) — as a first-class CLI entrypoint (semantics B: run the server, *not*
select a client-side persistence backend):

```
sbcl --eval '(require :asdf)' \
     --eval '(asdf:load-system :dds-durability)' \
     --eval '(dds.durability:durability-service-main
              :argv (list "--backend" "server"
                          "--port" "8080"
                          "--inner-backend" "file"        ; or "sqlite"
                          "--inner-dir" "/var/lib/dds/ms-inner/"))'
# logs:  MS-SERVER-LISTENING port=8080 — durability microservice server listening (inner: file /var/lib/dds/ms-inner/, host 127.0.0.1)
# on SIGTERM/SIGINT:  MS-SERVER-STOPPED port=8080 — durability microservice server stopped cleanly
```

Or via env (`DDS_DURABILITY_BACKEND=server` + the `DDS_DURABILITY_{HOST,PORT,INNER_BACKEND,INNER_DIR,MAX_CONNECTIONS,RECV_TIMEOUT}` set).
`--port` and `--inner-dir` are **required**; a missing/bad flag prints a clean `durability-config-error`, never a crash.
The server is **DARE-blind**: the inner store is a **plain** `make-file-store` / `make-sqlite-store` opened
`KEEP_ALL` with **no DARE key** — it holds only opaque frames; the connecting clients hold the DARE keys +
the log-MAC chain (§8.10.2) and own retention. Clients point `make-microservice-store-factory :host :port`
at it. The whole server-run lifecycle (build inner → listen → block-until-signal → clean stop) is the
**shared `%run-microservice-server` helper** that `interop/durability-persistent/driver-ms-server.lisp`
also calls (DRY). Stop is the clean §4.8 `tcp-shutdown` wake (§8.10.7): no hang, no leaked thread/socket.
The default (no `--backend server`) durability SERVICE mode is unchanged.

---

### 5.3 Service persistence backend (`--backend {file|sqlite|microservice}`, ADR 0050 §4.9, semantics A)

Select the durability **SERVICE**'s OWN client-side persistence store at the command line (semantics A: pick
the store the service persists to — distinct from the semantics-B `--backend server` which *runs* a server).
The flag wires to the shared `make-durability-store-factory` dispatch (§8.10 / spec.lisp) — the CLI does not
reimplement backend selection:

```
# file backend (encrypted append-log on disk):
durability-service-main --backend file   --dir /var/lib/dds/durability/ --topic Square:ShapeType

# sqlite backend (encrypted SQLite DB on disk):
durability-service-main --backend sqlite --dir /var/lib/dds/durability/ --topic Square:ShapeType

# microservice backend (persist to a remote DARE-blind server — see §5.2 for running one):
durability-service-main --backend microservice --ms-host 10.0.0.7 --ms-port 8080 \
                        --dir /var/lib/dds/durability/ --topic Square:ShapeType
```

- `--dir DIR` is **required** for `--backend file|sqlite` — the durable on-disk store dir. A PERSISTENT
  backend must name its dir; there is **no `<tmp>` fallback** (a silent temp-dir default would lose
  "persistent" data a reboot / tmpreaper clears — omitting `--dir` is a clean `durability-config-error`
  naming the flag, mirroring the SERVER mode's required `--inner-dir`). For `--backend microservice`, `--dir`
  is the CLIENT-LOCAL DARE epoch-dir (the durable records live on the remote server) and defaults to
  `<tmp>/dds-durability/`. `--key-dir DIR` (the ML-KEM-1024 keypair) defaults to `DIR/keys/`. Both file/sqlite
  stores are always DARE-encrypted at rest (the store dir's 0700 perms are enforced fail-closed); the
  microservice backend seals **client-side** (the remote server holds only opaque ciphertext, §8.10).
- `--backend microservice` **requires** `--ms-port` (the remote server to connect to); `--ms-host` defaults to
  `127.0.0.1`. These are the same coordinates the interop drivers pass via `DPERSIST_MS_HOST`/`DPERSIST_MS_PORT`.
- Every flag has a `DDS_DURABILITY_*` env equivalent (`DDS_DURABILITY_{BACKEND,DIR,KEY_DIR,MS_HOST,MS_PORT}`);
  precedence CLI > env > defaults.
- **Reconciliation with `--backend server` (semantics B).** `--backend` carries two roles: a **MODE** (the
  reserved value `server` → run the microservice SERVER, §5.2) and a **BACKEND VALUE**
  (`file|sqlite|microservice` → the service's persistence). `%durability-server-mode-p` intercepts `server`
  **before** the service parser, so `--backend server` keeps its §5.2 meaning and the three backend values
  reach the service. A bad value → a clean `durability-config-error` naming `{file|sqlite|microservice|server}`.
- **Omitting `--backend` keeps the in-memory default** — no behavior change for any existing invocation.

---

## 6. Phase-2 — dedup / no-double-delivery, multi-topic, dispose/unregister (WP-DURABILITY-DEDUP)

Phase 2 (WP-DURABILITY-DEDUP) resolves the principal Phase-1 limitations:

### 6.1 No-double-delivery via PID_ORIGINAL_WRITER_INFO (RTPS 2.5 §8.3.5.4)

The relay writer attaches `PID_ORIGINAL_WRITER_INFO (PID 0x0061)` as inline-QoS on every
relayed DATA submessage, carrying the **original writer's GUID and sequence number** (not the
relay writer's). This lets a receiver deduplicate across multiple relay sources without
inter-relay coordination — the receiver tracks the highest delivered `(originalGUID, SN)` pair
per originating writer.

The receiver-side dedup state is a per-origGUID **contiguous watermark + bounded reorder set**
(ADR 0024): `LO` = highest contiguously delivered SN; `ABOVE` = out-of-order set bounded by
`*max-gap-range*` (65536 entries). In-order traffic keeps `ABOVE` empty (O(1)/GUID). Late-joiner
replay of low historical SNs is handled correctly: the watermark starts at 0 for a fresh GUID,
so low SNs (1–10) are accepted even if high live SNs (50+) were already delivered.

```lisp
;; Check whether a relayed sample should be accepted (returns T) or dropped (returns NIL).
;; Called once per relayed DATA submessage on the receiving reader.
(dds.rtps.reliable:reader-dedup-accept-p reader original-guid original-sn)
```

Wire: every relayed user-data DATA submessage carries `PID_ORIGINAL_WRITER_INFO`; the inline-QoS
block is 32 octets (PID_ORIGINAL_WRITER_INFO 28 + PID_SENTINEL 4). Non-relay DATA (direct
writers, discovery) is byte-identical to before — the PID is not emitted. The `write-data` and
`writer-write` inline-QoS path is opt-in (nil by default).

### 6.2 Multi-topic service (N disc-nodes)

`make-service-spec` accepts a list of `(topic . type)` conses or a predicate. At `service-start`
time the service spawns **one disc-node per topic**, each with its own collect+replay entity pair
and its own store partition. Topics are isolated at the store level.

```lisp
(dds.durability:make-service-spec
 :domain 0
 :topics '(("Square" . "ShapeType") ("Circle" . "ShapeType"))
 :name "multi-topic-service")
```

Topics may be fixed at construction time, or added to a running service: dynamic topic-add landed
in Phase 3b (`service-add-topic`, §8.1).

### 6.3 Dispose/unregister capture + replay

The collecting reader captures lifecycle changes — dispose (`STATUS_INFO = 0x01`) and
unregister (`STATUS_INFO = 0x02`) — as `durable-record` entries with `kind = :disposed` or
`kind = :unregistered`. The replay writer re-emits these lifecycle records carrying
`PID_ORIGINAL_WRITER_INFO`, so a late-joining reader receives the instance lifecycle events in
the correct relative order (DATA → dispose/unregister, ordered by original SN per writer GUID).

### 6.4 Foreign-service coexistence

When both our durability service and RTI Persistence Service relay the same TRANSIENT topic,
a late-joiner matched to both receives each sample exactly once — because both relays emit
`PID_ORIGINAL_WRITER_INFO` with the same original-writer GUID + SN, and the receiver's
dedup map identifies them as the same sample. No inter-relay coordination is required.

**This is LIVE-captured as of WP-DURABILITY-COEXIST-LIVE (ADR 0028, 2026-06-21).** The
`:collect-durability :transient` qos-override ensures our collect path records the OWI logical
origin (the publisher's GUID) when RTI PS's OWI-stamped replay arrives, so both relays converge
on the same `(origin-GUID, SN)` regardless of arrival order. See `dds.disc:node-sample-origin-guid`
/ `node-sample-origin-sn` and §8.6.

Cross-DDS interop legs:
- **Leg A** — Connext 7.3.1 pub → our service → Connext late-joiner: 190 samples received,
  every relayed DATA carries `PID_ORIGINAL_WRITER_INFO` byte-exact.
- **Leg B** — Fast DDS 3.6.1 pub → our service → Fast DDS late-joiner: 465 samples received
  (service held 265 Connext + 100 Fast DDS history), two distinct original-GUID streams both
  carrying `PID_ORIGINAL_WRITER_INFO`.
- **Leg C** — RTI PS + our service both alive (CLOSED_WITH_FINDINGS, 2026-06-19). RTI Persistence
  Service v7.3.1 does NOT relay TRANSIENT_LOCAL data — it only handles TRANSIENT (and PERSISTENT)
  durability. For a TRANSIENT_LOCAL topic RTI PS is inert as a relay; our service collected and
  replayed correctly. The prior ~3558 additive count was entirely from our service's accumulated
  history across multiple test runs (different publisher GUIDs), not from RTI PS. Task-8 correctly
  adds `PID_SERVICE_KIND (0x8003) = PERSISTENCE_SERVICE_QOS` to our relay writer's SEDP endpoint
  announcement (spike-confirmed SEDP placement, not SPDP). Phase 3b got RTI PS running + relaying at
  the TRANSIENT tier (resolving this blocker). WP-DURABILITY-COEXIST-DEDUP (ADR 0027) later showed RTI PS
  DOES emit the standard `PID_ORIGINAL_WRITER_INFO` on its retained-history **replay** to a late-joiner
  (the earlier wire-dialect reading was its live-forward path only), so cross-vendor dedup works on the
  standard path with no vendor PID — see §8.6. See `interop/durability-dedup/coexistence/README.md`.

See `interop/durability-dedup/README.md` for wire evidence and `ADR 0024` for the dedup architecture.

### 6.5 Remaining Phase-2 limitations

- **Seen-set prune:** LANDED in Phase 3b — the collect-loop seen-set is bounded to
  O(live-origins × `*max-gap-range*`) (§8, ADR 0026).
- **In-memory store** was the Phase-2 default; the disk-backed PERSISTENT tier (always DARE-wrapped,
  survives restart) LANDED in Phase 3b — see §8.
- **`:process` mode is SBCL-only** (runtime fallback to in-thread on other impls); the CLI conveys
  only the in-memory TRANSIENT tier — it does **not** serialize a file/DARE store factory. A
  `:process`-mode spec configured for the PERSISTENT tier now **fails fast** (`%start-process-service`
  signals before launch) rather than silently running the in-memory tier — use `:thread` mode for the
  PERSISTENT tier (§8.7).
- **Dynamic topic-add to a running service** LANDED in Phase 3b (`service-add-topic`, §8.1).

See ADR 0023 + ADR 0024 for the full boundary.

## 6.6 Worked example — no-double-delivery with PID_ORIGINAL_WRITER_INFO

The following shows how to confirm no-double-delivery is active in a mixed relay scenario.
The key observable: the relay writer's DATA submessages carry `PID_ORIGINAL_WRITER_INFO`
with the original writer's GUID + SN (not the relay's).

```lisp
;;; Start a durability service on domain 0, topic Square/ShapeType
(defparameter *spec*
  (dds.durability:make-service-spec
   :domain 0
   :topics '(("Square" . "ShapeType"))
   :name "relay-service"))

(defparameter *runner* (dds.durability:make-service-runner (list *spec*)))
(dds.durability:runner-start *runner*)

;;; The service collects live samples. When the original writer exits, the
;;; service replays its retained history to any late-joining TL reader.
;;; Each replayed DATA carries PID_ORIGINAL_WRITER_INFO (0x0061) inline-QoS:
;;;   guidPrefix[12] = original writer's GUID prefix
;;;   entityId[4]    = original writer's EntityId
;;;   SN.high[4]     = 0 (for SN <= 2^32)
;;;   SN.low[4]      = original SN (LE)
;;;
;;; A Connext or Fast DDS late-joiner with dedup enabled will receive each
;;; sample exactly once even if RTI Persistence Service is also relaying.

(dds.durability:runner-stop *runner*)
```

tshark one-liner to verify the PID is on the wire:
```sh
tshark -i lo0 -T json -x -f "udp" \
  | python3 -c "import sys,json; d=json.load(sys.stdin);
[print(f['_source']['layers'].get('rtps.param.id','')) for f in d]" \
  | grep -c "0x0061"
```

---

## 7. DARE — always-on CNSA-2.0 Data-At-Rest Encryption (Phase 3a, WP-DURABILITY-DARE)

Phase 3a (ADR 0021 **capability 7**, ADR 0025) adds an **always-on CNSA-2.0 Data-At-Rest
Encryption** layer over the durable store, so persisted samples are never held in plaintext. It is
a **`durable-store` decorator** (`make-encrypted-store`) — it wraps any inner store and is built and
proven over the in-memory store in 3a; the disk-backed store (slice 3b) plugs underneath the same
decorator so disk holds only sealed bytes.

### 7.1 The envelope (KEM-DEM)

The decorator implements the NIST envelope-encryption pattern with the CNSA-2.0 suite (the new
`dds-dare` system):

- **Key establishment:** ML-KEM-1024 (FIPS-203, post-quantum) — on store open, the decorator
  encapsulates to the key-provider's recipient public key → `(kem-ciphertext, shared-secret)`, then
  derives **`DEK = HKDF-SHA384(shared-secret, info="dds-dare/dek/v1")`** (a 256-bit AES key). On open
  the provider decapsulates with the private key to re-derive the same DEK.
- **Per-record sealing:** AES-256-GCM (FIPS-197 / NIST SP 800-38D) under the DEK, with a **per-store
  96-bit counter nonce** and **AAD = `topic ∥ writer-guid ∥ sn ∥ kind`** (authenticated, not
  encrypted — the inner store indexes/replays by these). The on-store bytes are
  `version(1) ∥ nonce(12) ∥ ciphertext ∥ tag(16)`.
- **Fail-closed:** opening a tampered, wrong-key, short, or wrong-AAD blob returns NIL — never
  plaintext. `store-get-range` **drops** a record that fails to open (counts it, fires
  `dds.durability:*dare-error-hook*`).

For the in-memory TRANSIENT tier (v1, no `:epoch-dir`) only the CDR payload is encrypted; the record
metadata stays cleartext-authenticated. The **disk-backed PERSISTENT tier now also seals the metadata**
(topic/GUID/SN/kind/key-hash) — see §8.9 (WP-DURABILITY-METADATA-CONF-3c). **DARE is at-rest only — it
adds nothing to the wire** (data-in-transit is the separate P6 DDS-Security work).

### 7.2 Secure-store factory — worked example

`make-service-spec` takes a `:store` slot (a 0-arg factory). To get an always-on encrypted store,
wrap the inner store in the decorator backed by a file key-provider:

```lisp
(require :dds-durability)   ; pulls in dds-dare

(defparameter *keydir* (uiop:ensure-directory-pathname "/var/lib/dds-dare/keys"))

(defparameter *spec*
  (dds.durability:make-service-spec
   :domain 0
   :topics '(("Square" . "ShapeType"))
   ;; the ONLY delta vs a plain service: the store factory wraps the inner store in DARE
   :store (lambda ()
            (dds.durability:make-encrypted-store
             (dds.durability:make-memory-store)
             (dds.dare:make-file-key-provider :dir *keydir*)))
   :name "secure-durability-service"))

(defparameter *runner* (dds.durability:make-service-runner (list *spec*)))
(dds.durability:runner-start *runner*)
;; samples collected by the service are now SEALED in the store and OPENED on replay;
;; a late-joiner receives byte-correct plaintext — DARE is transparent to the relay path.
(dds.durability:runner-stop *runner*)
```

- `dds.durability:make-encrypted-store inner-store key-provider` — seals on `store-put`, opens on
  `store-get-range`, delegates `topics`/`purge`/`count`/`open`/`close` to the inner store. On
  construction it opens the provider, ML-KEM-1024-encapsulates, derives the DEK, and frees the
  transient shared secret. The DEK is a foreign-backed secret (a `static-vector`, zeroized+freed on
  `store-close`).
- `dds.dare:make-file-key-provider :dir DIR` — an ML-KEM-1024 keypair in `DIR/ml-kem-1024.{pub,key}`,
  generated on first open (perms enforced **0600 file / 0700 dir** and checked at open — a
  group/other-readable or unverifiable key **refuses to load**, fail-closed) and loaded thereafter.
  Decapsulation is internal, so the raw private key never leaves the provider — the **KMS hook
  point** (an HSM/cloud-KMS backend supplies different vtable closures).

### 7.3 Deployment requirement — OpenSSL ≥ 3.5

DARE uses **OpenSSL ≥ 3.5** (`libcrypto`) for all three CNSA-2.0 algorithms — **ML-KEM landed in the
3.5 LTS**, so this is a **hard runtime requirement**. It is checked at startup
(`dds.dare:dare-available-p`); if OpenSSL is absent, below 3.5, or ML-KEM-1024 is not fetchable, DARE
signals `dds.dare:dare-unavailable` — a **hard error, never a silent plaintext fallback**. On macOS
the bindings resolve the real homebrew `libcrypto` explicitly (a `$DDS_DARE_LIBCRYPTO` env override is
honoured first) to avoid binding the system LibreSSL, which lacks ML-KEM; on Linux they fall back to
`libcrypto.so.3`. No hand-rolled crypto (FR-SEC-2); OpenSSL is SBOM-pinned and recorded in
`docs/provenance.md`.

**Dumped-image (`save-lisp-and-die`) contract.** DARE caches every `libcrypto` function pointer (the
`%ossl-sym` boxes) plus the `EVP_aes_256_gcm()` cipher singleton. Those pointers are resolved once at
load and would go **stale across a dumped image** — on restart the shared library is re-mapped at a new
address, so a naively cached pointer would dangle and the first AEAD/X.509 call would crash. DARE closes
this by resolving through **re-resolvable boxes** and registering an **image-restart hook**
(`%dare-reresolve-foreign-pointers`) via the portable PAL seam `dds.pal:register-image-restart-hook`
(SBCL `sb-ext:*init-hooks*`, Clasp `core:*initialize-hooks*`), which re-opens `libcrypto` and
re-resolves every cached pointer on startup. So a **delivered durability-service executable** built with
`save-lisp-and-die` re-resolves crypto automatically on launch — no action required by the operator.

### 7.4 Scope & follow-ons

DARE 3a protects **stored payloads** (confidentiality + integrity + authenticity; tampering is
detected and fails closed). The MUST follow-ons (ADR 0025 §10): **3b** disk-backed PERSISTENT store +
the cross-restart key-epoch the `version` byte reserves; **3c** metadata confidentiality; in-RAM
plaintext minimization (with an honest pure-Lisp feasibility caveat); and **P6** DDS-Security for
in-transit confidentiality.

---

## 8. PERSISTENT — disk-backed durability + cross-restart key-epoch (Phase 3b, WP-DURABILITY-PERSISTENT)

Phase 3b (ADR 0021 **capability 7** / ADR 0025 §10, ADR 0026) adds a **disk-backed PERSISTENT
tier**: the durability service's retained history **survives a process AND system restart** (DDS 1.4
§2.2.3.4) while remaining **encrypted at rest — no plaintext on disk, ever**. A late-joiner appearing
*after* the service (and the original writer) has restarted still receives the retained,
authenticated samples.

It is built on the **existing `durable-store` vtable**: a new file-store backend
(`make-file-store`) plugs underneath the **same** DARE decorator from §7, so disk holds only sealed
bytes from its first byte. A persisted **key-epoch** lets each prior run's DEK be re-derived on
reopen **without ever reusing an AES-GCM nonce across runs**.

### 8.1 The PERSISTENT-tier store factory — worked example

`make-persistent-store-factory` returns the 0-arg `:store` factory the service spec expects; it
composes the file store + the file key-provider + the epoch-aware encrypted-store for you:

```lisp
(require :dds-durability)   ; pulls in dds-dare

(defparameter *store-dir* (uiop:ensure-directory-pathname "/var/lib/dds-dare/store"))
(defparameter *key-dir*   (uiop:ensure-directory-pathname "/var/lib/dds-dare/keys"))

(defparameter *spec*
  (dds.durability:make-service-spec
   :domain 0
   :topics '(("Square" . "ShapeType"))
   ;; the PERSISTENT tier: a disk-backed, always-DARE-wrapped store with a cross-restart key-epoch
   :store (dds.durability:make-persistent-store-factory
           :dir          *store-dir*    ; D — sealed topic logs + epochs.dat live here
           :key-dir      *key-dir*      ; K — the ML-KEM-1024 keypair lives here
           :history-kind :keep-last     ; optional: bound per-instance :data on each open
           :history-depth 10)           ; keep the newest 10 :data per instance (default: :keep-all)
   :name "persistent-durability-service"))

(defparameter *runner* (dds.durability:make-service-runner (list *spec*)))
(dds.durability:runner-start *runner*)   ; store-opens: reload logs + re-derive prior-epoch DEKs,
                                         ; then seed the replay writer's history from disk
;; ... samples collected by the service are SEALED to disk; the process may exit/crash ...
;; ... on a later start the service reloads + decrypts them; a late-joiner gets the retained history ...
(dds.durability:runner-stop *runner*)    ; store-closes: group-commit fsync + free every epoch DEK
```

`make-persistent-store-factory` is equivalent to the explicit composition
`(make-encrypted-store (make-file-store :dir D :history-kind … :history-depth …) (make-file-key-provider :dir K) :epoch-dir D)` — the
encrypted-store seals → the file store writes only sealed bytes under `D`; the encrypted-store owns
`D/epochs.dat`; the key-provider owns `K/ml-kem-1024.{key,pub}`.

To add a topic to an **already-running** service without a restart:

```lisp
(dds.durability:service-add-topic service "Circle" "ShapeType")
;; => (values T node)   ; idempotent by topic name — a duplicate add returns (values NIL NIL)
```

#### 8.1.1 Discovery-driven auto-serve (opt-in `:auto-discover`)

`service-add-topic` is the **API-driven** half of dynamic-topic-add — you name the topic. The
**discovery-driven** half lets a service watch the domain and auto-serve topics **as their writers appear**,
with no `add-topic` call and no restart. It is **opt-in** and the default is byte-identical:

```lisp
(defparameter *spec*
  (dds.durability:make-service-spec
   :domain 0
   :topics '()                                  ; empty start-list is OK under :auto-discover
   :auto-discover t                             ; opt in
   :auto-discover-filter "Sensor*"              ; NIL = every topic; a function = predicate over the
                                                ; topic-NAME; a string = a simple name glob (trailing * = prefix)
   :name "auto"))
(defparameter *svc* (dds.durability:make-durability-service *spec*))
(dds.durability:service-start *svc*)            ; also spins a bare SPDP/SEDP discovery node + a poll thread
;; ... a remote publisher announces a NEW topic "SensorTemp" ...
;; the service auto-adds it (reusing service-add-topic), collects it, and replays it to TL late-joiners:
(dds.durability:service-serves-topic-p *svc* "SensorTemp")   ; => T   (auto-served; "Motor42" would be NIL)
(dds.durability:service-stop *svc*)             ; tears down the poll thread + discovery node (no leak)
```

- **How.** When `:auto-discover` is set, `service-start` builds ONE **bare** `disc-node` (SPDP/SEDP only, no
  user endpoints) — it discovers *every* remote participant's published topics. A poll thread (interval
  `*durability-auto-discover-interval*`, default 0.25 s) scans the discovered **writers** and, for each
  topic that is not yet served **and** passes `:auto-discover-filter`, calls the ordinary
  `service-add-topic` (idempotent-by-name, so repeated discovery and races are harmless). Only WRITERS are
  served (a reader-only topic carries no data).
- **The filter is the guard.** Without it, `:auto-discover` would spin up a collect node for **every** topic
  on the domain. `NIL` = match-all (use only on a quiet domain); prefer a predicate or `"Prefix*"` glob.
- **No type registration.** The service stores/relays **opaque CDR bytes**; SEDP already carries the topic-
  and type-NAME strings, so an arbitrary discovered type is served verbatim — no XTypes/TypeLookup needed.
- **Default off.** `:auto-discover` NIL (the default) spawns **no** discovery node and **no** poll thread;
  `service-start` / `service-stop` and the fixed start-list behavior show **no observable change** from prior
  releases (behaviorally identical — the off path adds only vacuous, unobservable work).
- **Stop discards runtime state.** `service-stop` clears the served-topic registry, so a dynamically-added
  topic (API or auto-discover) does not survive into a same-object restart as a `service-serves-topic-p`
  false positive; a fixed start-list re-registers on the next `service-start` (its registry is byte-identical
  after the restart), and runtime additions are re-done (auto-discover re-discovers; the API caller re-adds).
- Introspect with `durability-service-discovery-node` and `service-serves-topic-p`. See ADR 0026 (Phase-2b).

### 8.2 On-disk format (append-log-per-topic)

- `D/topics/<topic-id>.log` — one append-only log per topic (`<topic-id>` = lowercase hex of the
  topic UTF-8 bytes; a `D/topics.map` records the readable name).
- Each record is a framed entry. The **second byte is the frame format version** (the reader
  dispatches per-frame, so one log may mix legacy and current frames):
  - **v3 (written when the keyed MAC chain is active — the encrypted/epoch store)** — the v2 layout
    plus a **32-byte keyed chain MAC** between the payload and the trailing frame CRC:
    `… ∥ payload-len(4 LE) ∥ header-crc32(4 LE) ∥ payload ∥ **chain-mac(32)** ∥ frame-crc32(4 LE)`.
    The MAC is `HMAC-SHA-256(logmac-key, prev-chain-MAC ∥ frame-prefix)`, chaining each frame to its
    predecessor so interior delete/reorder/substitution/insertion is tamper-evident at store-open
    (ADR 0045; see §8.5).
  - **v2 (written when no chain is active — the plaintext file store)** — `magic(1)=DA ∥ version(1)=02
    ∥ flags(1) ∥ writer-guid(16) ∥ sn(8 LE) ∥ [key-hash(16) if keyed] ∥ payload-len(4 LE) ∥
    **header-crc32(4 LE)** ∥ payload ∥ frame-crc32(4 LE)`. The **header CRC** (over `magic..payload-len`)
    is validated **before** `payload-len` is trusted, so a corrupt length is detected as corruption
    (fail loud) instead of masquerading as a torn tail (ADR 0026 §10.9).
  - **v1 (legacy, read-only)** — `magic(1)=DA ∥ version(1)=01 ∥ … ∥ payload-len(4 LE) ∥ payload ∥
    frame-crc32(4 LE)` (no header CRC). The reader still reads it for back-compat.
  `flags` encodes the record kind (`:data`/`:dispose`/`:unregister`) + key-hash-present; both CRC32s
  use the reflected polynomial `0xEDB88320` (torn-write / length-corruption integrity checks, **not**
  the security primitive — a CRC an adversary can recompute is not a MAC). **Tamper-evidence** is the
  GCM tag (per-frame payload+metadata authenticity) **plus** the v3 keyed chain (record-sequence
  integrity — §8.5). The **`payload` is the encrypted-store's opaque sealed blob** (which itself
  carries the epoch-id); the file store never parses or decrypts it.
- `D/epochs.dat` — an append-only epoch table; each entry is
  `epoch-id(4 LE) ∥ kem-ct-len(4 LE) ∥ ML-KEM-ciphertext ∥ crc32(4)`.
- An **in-memory index** (`topic → ((guid . sn) → frame)`) is rebuilt on open; `put` is idempotent
  on `(topic, writer-guid, sn)`; `get-range` is sorted by `(writer-guid, sn)`.

### 8.3 Cross-restart key-epoch (new-epoch-per-open)

The 3a encrypted-store derives a *fresh* DEK per open and discards the ML-KEM ciphertext, so disk
records from a prior run could not be reopened. 3b adds a persisted **key-epoch**:

- **On open**, the store loads `epochs.dat` and, for each epoch, asks the key-provider to
  decapsulate its stored ML-KEM ciphertext → re-derive that epoch's DEK (held foreign), building an
  `epoch-id → DEK` map. Open does **not** mint an epoch (a read-only restart adds none).
- **On the first `put` of a run**, a **new epoch** is minted lazily: a fresh ML-KEM encapsulation →
  a fresh DEK (derived *before* the epoch is appended), the epoch entry is appended to `epochs.dat`
  and **fsync'd before the first record references it**. Its nonce counter starts at 0.
- Each record's **envelope v2** blob is `#x02 ∥ epoch-id(4 LE) ∥ nonce(12) ∥ ciphertext ∥ tag(16)`
  — the epoch-id **and** the cleartext frame metadata (topic ∥ writer-guid ∥ sn ∥ kind ∥ key-hash)
  are **AAD-bound**, so a disk-write adversary that flips any of them (e.g. a record's key-hash, to
  mis-route an instance's lifecycle) fails the GCM tag ⇒ fail-closed drop. On read, the decorator
  resolves the DEK by the record's epoch-id (an unknown epoch-id ⇒ fail-closed drop) and AES-256-GCM-opens.
- **Why nonce reuse is structurally impossible:** every run mints a **distinct epoch ⇒ a distinct
  DEK with its own counter-from-0 nonce space**, so no two runs ever share a `(DEK, nonce)` pair —
  regardless of crash timing, and with **no counter-resume to get wrong**. (The epoch table grows
  by one ~1.6 KB entry per open; retirement of very-old empty epochs is a follow-on.)

### 8.4 Crash-consistency

- **Group-commit fsync** per collect-drain tick (`dds.pal:fsync-stream`): a crash loses at most the
  current sub-tick's not-yet-synced records. The encrypted-store delegates the fsync to the inner
  file store, so the production DARE-wrapped config is genuinely synced. A fsync the OS reports as
  failed (`fdatasync` → −1) is **surfaced via `*durability-error-hook*`, never silently treated as
  durable** (fail-closed, NFR-SEC-POSTURE).
- Append-only files + CRC/length framing ⇒ a **torn trailing frame** (a crash mid-append) is
  detected and **truncated on open** (recover); a **mid-file corruption** **fails the open loudly**
  (it could mask tampering — recovery only truncates a torn *tail*). A declared frame/epoch length
  above a sanity cap (`+frame-max-payload+` / `+epochs-max-ctlen+`) is treated as `:corrupt` (fail
  loud), so a gross length-field corruption can never masquerade as a torn tail and silently truncate.
- **Ordering invariant:** `epochs.dat` is fsync'd before any topic-log record references the new
  epoch, so every record's epoch-id resolves after a crash.
- **Compaction-on-open** runs two passes. Pass 1 (unconditional, order-aware): drops a key-hash
  only when both a `:dispose` and an `:unregister` tombstone are present AND the instance's
  **final** record is itself a tombstone — a legally **resurrected** instance (a `:data` written
  after the teardown) is never dropped. Records with NIL key-hash (NO_KEY topics) are never
  dropped. Pass 2 (KEEP_LAST only, ADR 0029 §File-store compaction): for each non-NIL-key-hash
  instance, keeps only the newest `HISTORY-DEPTH` `:data` records (sorted by `(writer-guid, sn)`,
  ascending); lifecycle records pass through untouched. This bounds per-instance growth across
  restarts without breaking resurrection-safety. `:keep-all` (default) skips pass 2
  (byte-identical to prior behavior). The rewrite is via an atomic rename.
- The crash path is fuzzed (random truncation/garbage/mid-file corruption of logs + `epochs.dat`,
  including a `(safety 0)` arm): open recovers with no crash/OOB/mis-decode and no nonce reuse.
- **Parent-directory fsync:** after every create/rename of a directory entry — a new log file,
  `epochs.dat` creation, the compaction rename, a recovery truncate rename, and the `topics.map`
  write — the containing directory is fsync'd via `dds.pal:fsync-directory` (`open(dir,O_RDONLY) +
  fsync + close`), so the dirent survives a power loss (POSIX requires fsyncing the directory, not
  just the file contents). The PAL seam is impl-agnostic (identical CFFI body on SBCL and Clasp; on
  macOS `fsync` on a directory fd is valid).

### 8.5 Keyed MAC'd log chain — whole-record tamper-evidence (ADR 0045)

The GCM tag authenticates each frame's payload + metadata **in isolation** — it does not authenticate
the record **sequence**, so a disk-write adversary could delete, reorder, substitute, or insert whole
records undetectably (a CRC is not a MAC — an adversary recomputes it). The **keyed running MAC chain**
closes that gap for the **encrypted/epoch (keyed) store**:

- **Chain construction.** Each v3 frame carries `MAC_i = HMAC-SHA-256(logmac-key, chain_{i-1} ∥
  frame_i[0..mac-offset))`, where `chain_{i-1}` is the previous frame's MAC and `chain_0` is a
  per-topic keyed seed `HMAC(logmac-key, "dds-dare/logmac/seed/v1" ∥ topic)`. Store-open replay
  recomputes the chain in on-disk order; any mismatch → `:corrupt` → the open **fails loud**
  (same fail-direction as a mid-file CRC). The per-topic seed also binds each topic's chain to its
  identity, so swapping another topic's valid log into this topic's file is caught.
- **Cross-restart-stable key.** `new-epoch-per-open` rotates the DEK every restart, so the log-MAC
  key cannot be a DEK. It is derived from a **stable** secret: a dedicated ML-KEM **anchor ciphertext**
  (`D/logmac.anchor`, minted once) whose **decapsulation is deterministic** (FIPS-203) ⇒ the same
  secret every restart ⇒ `HKDF-SHA384(info="dds-dare/logmac/v1")` yields the same 32-byte key, while
  it stays secret (only the recipient private key can decapsulate it). The key is foreign-backed and
  zeroized on close, like the DEK. Because the key is epoch-independent and replay restores each
  topic's running tail MAC, the chain is **continuous across epochs/restarts** — a restart boundary
  is not a free break point (epoch *N+1*'s first frame chains from epoch *N*'s last).
- **Keyed-store-only, fail-closed on key absence.** The plaintext `make-file-store` gets **no key** and
  writes v2. A v3 (chain-expected) frame encountered **without** the key oracle — a bare store, or the
  **wrong** key — fails the open loudly; verification is never silently skipped.
- **Downgrade defense.** A per-frame MAC alone would be bypassable by rewriting **every** v3 frame back
  to a keyless-valid v2 frame (strip the MAC, fix both CRCs) — a byte-valid v2 log needing no key. The
  `logmac.anchor` file is the store's **chain commitment** (minted lazily on the first v3 put, so
  *anchor present ⟺ a v3 frame was written*): a chain-committed topic whose **non-empty** log replays
  to **zero** v3 frames **fails the open**, enforced **before** any compaction rewrite could launder
  it. Enforcement is **per-topic** (each topic is its own log); to migrate a legacy **multi-topic** v2
  store without false-rejecting a *dormant* legacy topic, the anchor also carries an **authenticated
  grandfather set** — the topic-ids that were non-empty legacy logs at mint time — which are exempt
  from the downgrade check (a topic is chain-required iff *anchor present* **and** *not grandfathered*).
  The set is MAC-authenticated under the log-MAC key so a disk adversary can't forge/extend it; the
  anchor is written once (crash-safe, no migration burst). Every born-chained topic (created after the
  anchor is minted) is fully protected; a legacy Batch-B v2 store is never false-rejected. Caveat: the
  grandfather set is enumerated from the mint-time on-disk logs, which are untrusted — an adversary who
  pre-seeds fake v2 logs before mint gets them authenticated as exempt (no more capability than deleting
  the anchor outright), closed only by the deferred sealed high-water anchor.
- **Sealed high-water tail anchor (whole-tail truncation / whole-topic drop / whole-store rollback —
  FILE + SQLite tiers, ADR 0045 §7.1).** The running chain provably cannot detect truncation of a valid *prefix*
  (the shorter log is itself a valid chain), so a **separable** store-level anchor commits the expected
  tail. At **clean close** the decorator seals, per chained topic, `{N = v3-frame count, M_N = the
  running chain-MAC after N frames}` plus the **topic-SET**, MAC'd under the log-MAC key
  (`HMAC-SHA-256(logmac-key, "dds-dare/logmac/tail/v1" ∥ set)` — the same keyed construction as the
  grandfather anchor, a fresh domain label, no new crypto) into a **separate, mutable `D/logmac.tail`**
  (fsync'd; never extends the write-once `logmac.anchor`). The anchor protects the **at-rest
  (clean-closed)** state — NOT the mutating in-session log: authorized ops shrink the physical chain
  mid-session (the KEEP_LAST **physical reclaim** `%reclaim-deleted-topic` ⇒ `%rewrite-topic-log`, active
  for the file inner store, and settled-instance compaction re-emit **fewer** re-seeded frames), and two
  files can't be updated atomically. So at **open** the decorator **verifies** the at-rest anchor (detects
  an OFFLINE truncation) and then **INVALIDATES it (deletes `logmac.tail`, dir-fsync'd) BEFORE** store-open's
  sweep / the session's puts mutate the log; it is **re-sealed at the next clean close** over the final
  state. Verify per sealed topic: the chain must reach ≥ `N` v3 frames with running MAC at `N` == `M_N`
  (**CLEAN**); a chain ending on a clean boundary below `N` is **`:truncated`** (whole-tail truncation /
  whole-topic drop [absent log] / whole-store rollback ⇒ **fail-closed**); a divergent prefix MAC is
  **`:diverged`**. This makes an authorized reclaim-shrink + a **crash** (no clean re-seal) reopen **clean**
  (no stale anchor to false-reject / brick — the never-cleanly-closed path), while an offline truncation of
  the clean-closed state is still detected (verify ran first). An honest torn TRAILING frame is tolerated
  (clean). With invalidate-at-open a present `logmac.tail` always describes an unmutated at-rest log, so the
  prefix-containment "may extend past `N`" tolerance is currently **vestigial** (harmless; reserved for a
  future periodic-seal — strict `count==N ∧ MAC==M_N` would be equivalent today). The decorator↔store
  boundary is a **read-only additive seam** (`store-chain-tails` for the seal, `store-verify-chain-prefix`
  for the open check; NIL-fallback like `store-sync`). The **SQLite tier** FILLS that seam
  (WP-DURABILITY-TAIL-ANCHOR-SQLITE — `make-sqlite-store` walks its `mac`/`chain_seq` rows via the shared
  `%sqlite-chain-walk` at the SAME `{N, M_N}` contract; `N` is the chained-**row count**, `M_N` the tail
  row's MAC. The authorized reclaim there is the Sliver-3a `store-delete` ⇒ `%sqlite-recompute-topic`
  shrink, and the backend-agnostic invalidate-at-open gives it the same reclaim-shrink+crash **CLEAN**
  no-false-reject for free). The **microservice tier** also FILLS the seam (WP-DURABILITY-TAIL-ANCHOR-MS)
  **CLIENT-SIDE**: `store-chain-tails` reads the client's own `chain-macs`/`chain-seqs` (`N` = the
  `chain_seq`-count, `M_N` = the tail MAC), keyed by the **client's own chained topic-hashes — NOT the
  server's `store-topics`**; `store-verify-chain-prefix` fetches the topic's records from the server
  (connect-on-demand, since verify runs before store-open connects) and re-walks to ordinal `N` via an
  extracted read-only `%ms-chain-walk` (the microservice analogue of `%sqlite-chain-walk`; `%ms-verify-chain`
  refactored onto it). `logmac.tail` lives on the CLIENT-LOCAL epoch-dir (the server is DARE-blind), so
  there is **no server or protocol change and no new crypto**. Because the anchor's topic-SET is the
  **client-trusted** enumeration, a malicious server that omits a whole topic is still verified (fetch 0 →
  `:truncated`) — closing the Slice-3b whole-topic-drop-by-a-malicious-server gap. **All three tiers now
  fill the seam.**
- **Sealed `epochs.dat` MAC (offline ct-tamper / rollback / reorder — ADR 0045 §7.2, WP-DURABILITY-EPOCHS-MAC).**
  `D/epochs.dat` (the DARE per-epoch KEM-ciphertext table) was **entry-CRC-only**; because the CRC is
  **unkeyed**, an offline disk adversary could flip a stored kem-ct **and recompute that entry's CRC** →
  undetected → the wrong shared-secret decapsulates → the wrong DEK → a fail-closed decrypt-failure (an
  **availability** brick / tamper-evidence gap); rollback and reorder were likewise unauthenticated. A
  **keyed MAC over `epochs.dat`** now closes this. The MAC key `k_epochs = HKDF-SHA384(ss, info="dds-dare/epochs/v1")`
  is the **THIRD sibling** off the anchor shared secret (alongside the log-MAC key and k_meta) — it
  **cannot** derive from any per-epoch DEK (the DEKs **are** the contents of `epochs.dat`, circular), so
  `%mint-logmac-anchor` / `%load-logmac-anchor` now derive + return all three keys from the same `ss`. At
  **clean close** the decorator seals the canonical image `version ∥ count ∥ [epoch-id ∥ ctlen ∥ ct ∥ crc]*`
  over the entries **sorted by epoch-id ascending** (reusing `%frame-epoch-entry`, so each entry is
  byte-identical to on-disk), MAC'd `HMAC-SHA-256(k_epochs, "dds-dare/logmac/epochs/v1" ∥ signed)` (the
  same `%hmac-labeled` construction as the grandfather/tail anchors, a fresh label, **no new crypto**) into
  a **separate, mutable `D/epochs.mac`** (fsync'd; `%read-epochs-mac` bounds-checks every offset even at
  `(safety 0)`). At **open** (after `epochs.dat`'s torn-tail truncate-recovery has run, guarded on `k_epochs`
  non-NIL) it verifies by **prefix-containment**, forward-tolerant: absent ⇒ CLEAN; a `.mac` MAC mismatch ⇒
  fail-closed; with `N` = the committed count, `< N` entries ⇒ **`:truncated`** (rollback/truncation), the
  first-`N` (ascending) whose canonical image differs ⇒ **`:diverged`** (ct-tamper / reorder), and a table
  with **≥ `N`** whose first-`N` match ⇒ **CLEAN** (the extra entries are a forward 1-ahead crash-append —
  a strict whole-table-equality check would BRICK it and is rejected). **Unlike the §7.1 tail anchor there
  is NO invalidate-at-open**: `epochs.dat` is append-only and never authorized-shrinks, so the only at-open
  divergence is the forward crash-append (accepted CLEAN) — simpler than the tail anchor. A test-only
  `*durability-debug-skip-epochs-seal*` knob (mirrors `*durability-debug-skip-tail-seal*`; inert by default)
  exercises that no-false-reject path. **Residuals:** the **unsealed suffix** — epochs minted after the last
  clean close are unauthenticated until the next re-seal (inherent to seal-at-close, the security complement
  of the forward tolerance): an adversary may tamper/append entries beyond the sealed `N` undetected, with
  damage bounded to fail-closed decrypt-failures of the records referencing those suffix epochs (never
  plaintext; the sealed prefix stays protected) — and whole-file **deletion** of `epochs.dat`/`epochs.mac`
  (the shared deletion residual, same class as anchor/tail deletion; its sharpest form is **laundering**:
  delete `epochs.mac`, tamper the table, and let the next clean close re-seal over the tampered table).
  Nonce-reuse confidentiality is not at risk (each
  mint encapsulates a FRESH ciphertext even on id reuse) — this is integrity/availability, not confidentiality.
- **Detected:** interior record **delete / reorder / substitution (even with both CRCs recomputed) /
  insertion**, **full-log v3→v2 downgrade** of any born-chained topic, and — for **ALL THREE tiers (FILE +
  SQLite + microservice)** — **whole-tail truncation / whole-topic drop / whole-store rollback** (the sealed
  high-water anchor above, **against an adversary who truncates the log but does not also delete
  `logmac.tail`**; on the microservice tier the whole-topic drop is a malicious server omitting a topic).
  **Deferred residuals (ADR 0045 §7):** the honest-torn-disguise (a truncation that leaves a trailing
  *partial* frame is byte-indistinguishable from a real crash, so it is tolerated); **`logmac.tail`
  deletion** — the anchor is a mutable, non-write-once file, so an adversary who truncates the log **and
  deletes `logmac.tail`** opens clean (byte-indistinguishable from a legitimate never-cleanly-closed store;
  the **same residual class as anchor-deletion, §7 item 3a** — it cannot be closed by requiring the tail
  file's presence without false-rejecting every legitimately never-closed store; invalidate-at-open widens
  the legitimate-absent window to any open session, same class); on the **microservice tier** the KEEP_LAST
  physical-reclaim re-MAC is now done (WP-DURABILITY-MS-RECLAIM-REMAC, §8.10.3 — the `:delete` re-MACs the
  survivors + replaces the server's opaque frames via `+ms-op-topic-rewrite+`, so a reclaim reopens CLEAN);
  the ms `:purge` **also** clears the client chain head, mirroring the local tiers, so an authorized purge
  + clean close + reopen opens CLEAN — a false-reject the anchor would otherwise introduce, fixed here); the combined anchor-deletion-plus-full-downgrade
  vector and a full rollback of a *grandfathered* legacy topic; and whole-file **deletion** of `epochs.dat`
  (the sealed `epochs.dat` MAC itself is now CLOSED — see the §7.2 bullet above). Cost is off the
  sample hot path (one HMAC per put / per frame at open; one HMAC over the tail set per close; one HMAC over
  the epoch table per close). Verified by
  `run-durability-mac-chain-test` (round-trip; v1/v2/v3 read; the four interior tampers with a non-vacuous
  control; the v3→v2 downgrade fails loud while a v3-tail migration log opens; **multi-topic legacy
  coexistence**; cross-restart; key-absent/wrong-key; **torn-tail clean + whole-frame tail truncation now
  DETECTED**) and `run-durability-tail-anchor-test` (**crash-append CLEAN** + **authorized reclaim-shrink +
  crash reopens CLEAN** [the two no-false-reject / no-brick cases, the second with a non-vacuous
  log-shrank guard]; **whole-topic-drop / anchor-tamper / whole-store-rollback DETECTED**; never-cleanly-closed
  opens clean). The **SQLite tier** anchor is verified by `run-durability-sqlite-tail-anchor-test`
  (**tail-truncation RED→GREEN**, **whole-topic-drop DETECTED**, anchor-tamper, **:diverged DETECTED** [a
  rollback to a DIFFERENT self-valid snapshot with running-MAC@N ≠ M_N — the running per-row chain passes it,
  only the anchor catches it], cross-restart byte-exact, **F1 reclaim-shrink-crash CLEAN** with a non-vacuous
  log-shrank guard AND a self-contained RED [`*durability-debug-skip-tail-invalidate*` → the same sequence
  BRICKS, proving the invalidate is load-bearing], and a **purge+reput+reopen CLEAN** no-false-reject arm — all
  tampered via DIRECT SQL). NO-FALSE-REJECT FIX (both local tiers): `store-purge` now clears the in-memory running
  chain head so a reput to a purged topic re-seeds from the per-topic head (previously the reput chained from
  the stale pre-purge tail and the next open's re-seeded verify false-rejected the first frame — a brick).
  The **microservice tier** anchor is verified by `run-durability-microservice-tail-anchor-test`
  (**tail-truncation RED→GREEN** [a malicious server drops the tail record, injected into the server's inner
  between sessions], **whole-topic-drop-by-server RED→GREEN** [the headline — a malicious server omits a whole
  topic; the sealed topic-SET still lists it → verify fetches 0 → `:truncated`; the RED control deletes
  `logmac.tail` and shows the server-omitted topic is silently lost], an **authorized purge + CLEAN close +
  reopen → CLEAN** arm [the introduced-brick guard — the CONTRAST to the malicious drop: an authorized client
  purge clears the client chain head so no stale entry is sealed; RED without the `:purge` fix bricks
  `:truncated`], **anchor-tamper DETECTED**, **cross-restart byte-exact** across a server restart over a
  persistent file inner, and **F1 reclaim-shrink-crash CLEAN** + a self-contained **RED-brick** via
  `*durability-debug-skip-tail-invalidate*`). F1 uses an authorized PURGE as the shrink (which leaves a valid
  chain); the KEEP_LAST reclaim shrink itself is covered by its own test now that the ms `:delete` re-MACs the
  survivors (WP-DURABILITY-MS-RECLAIM-REMAC, §8.10.3 — `run-durability-microservice-keep-last-reclaim-test`). The
  ms `:purge` now clears the client chain head (mirroring file/SQLite), fixing the anchor's introduced brick AND
  the pre-existing purge+reput-same-session brick. The sealed high-water tail anchor is now complete across ALL
  THREE tiers. The **sealed `epochs.dat` MAC** (§7.2) is verified by `run-durability-epochs-mac-test`
  (**tamper-ct RED→GREEN** [flip a stored kem-ct + recompute its per-entry CRC — the unkeyed CRC path still
  accepts it, only the keyed `epochs.mac` catches it `:diverged`], **rollback DETECTED** [`:truncated`] with a
  **forward-append CONTROL**, **reorder DETECTED** [swap the two kem-ct payloads + fix both CRCs ⇒ `:diverged`],
  **`epochs.mac`-forge DETECTED**, **cross-restart CLEAN**, the **1-ahead crash-append CLEAN** no-false-reject
  [`*durability-debug-skip-epochs-seal*`], and **torn-tail CRC-recovery still verifies**).

### 8.6 Deployment requirement — OpenSSL ≥ 3.5

The PERSISTENT tier is **always DARE-wrapped**, so the §7.3 deployment requirement applies in full:
**OpenSSL ≥ 3.5 (`libcrypto`) is a hard runtime requirement** (ML-KEM landed in the 3.5 LTS),
checked at startup (`dds.dare:dare-available-p`); if it is absent/below 3.5/ML-KEM-less, the service
signals `dds.dare:dare-unavailable` — a **hard error, never a silent plaintext-on-disk path**. The
file store itself adds no new dependency (plain-file IO). `dds.pal:fsync-stream` is an **NFR-PORT
split**: SBCL issues a true `fdatasync(2)`; **Clasp falls back to `finish-output`** (no stream-fd
`fdatasync` exposed here), so the SBCL path carries the production OS-level durability guarantee.

### 8.6 Cross-DDS transparency-after-restart + cross-vendor dual-relay exactly-once

**Transparency-after-restart is LIVE vs both peers** (`interop/durability-persistent/`, 2026-06-20,
a GENUINE 2-process restart sharing the same disk `D` + key `K`): process 1 sealed N samples to disk
then exited; a fresh process 2 reloaded + decrypted the same N on reopen; a late-joining foreign TL
subscriber received exactly N byte-correct — **Connext 7.3.1: 458 sealed → 458 reloaded → 458
received**; **Fast DDS 3.6.1: 186 → 186 → 186**. Both captures match the plain-store transient wire
**byte-for-byte** (replay EntityId `0x00000102`, `firstAvailableSeqNumber=1` held on every HEARTBEAT,
`CDR_LE`, NACK→retransmit). Direct disk inspection confirmed only sealed ciphertext on disk
throughout — DARE-at-rest is real, yet wire-transparent after restart.

**RTI Persistence Service coexistence — LIVE exactly-once CAPTURED (WP-DURABILITY-COEXIST-LIVE,
ADR 0028, 2026-06-21).** Background: WP-DURABILITY-COEXIST-DEDUP (ADR 0027) showed RTI PS v7.3.1
emits the standard `PID_ORIGINAL_WRITER_INFO (0x0061)` — the publisher's real `(GUID, SN)` — on its
**retained-history replay**, so cross-vendor dedup works on the standard path. The residual ADR 0027
follow-on was the origin **divergence** observed on our collect side: our relay was storing the **wire
sender** GUID, not the OWI logical origin, so when RTI PS's relay won an arrival race the stored GUID
was RTI PS's relay GUID (`0x80000002`), not the publisher — and dedup keyed on a different origin.

**Fix (WP-DURABILITY-COEXIST-LIVE Tasks 1–2):** per-sample logical-origin capture in `disc-node`:

```lisp
;; After an on-data callback, look up the OWI logical origin (or the wire guid/sn if no OWI).
(dds.disc:node-sample-origin-guid node key)  ; → (simple-array (unsigned-byte 8) (16))
(dds.disc:node-sample-origin-sn   node key)  ; → integer
;; key = (writer-guid . sn) as stored in the disc-node sample maps
```

`%collect-loop` now keys `store-put` + dedup on these logical-origin values. The default/direct path
(no OWI → effective = wire) is byte-identical. Mirrors the lifecycle drain precedent (`orig-guid`).

**Live capture results (both directions converged on FIRST attempt):**

| Direction | Receiver | N | RTI PS OWI origin GUID | Our relay OWI origin GUID | UNION | Naïve 2-relay sum |
|---|---|---|---|---|---|---|
| dir-a | our-stack reader | **545** | `0101642e5f4294116dd106b480000002` | same | 545 | 1090 |
| dir-b | Connext `shapes_sub` | **550** | `01017344014e53c9630ac19e80000002` | same | 550 | 1100 |

Both relays stamp `PID_ORIGINAL_WRITER_INFO` with the **same** publisher GUID (EntityId kind `0x02`,
USER_DEFINED) in both directions. `analyze-capture.py --assert-converged` exits 0 on both committed
captures (`interop/durability-coexist-dedup/captures/coexist-dir-{a,b}.pcap`).

**In-process convergence proof:** `run-durability-collect-origin-convergence-test` shows convergence
for both arrival orders (direct-first, relay-first) without a live run.

**ADR 0027 §follow-on 1 is RESOLVED** by ADR 0028. The still-open follow-on is ADR 0027 §follow-on 2:
coexistence with a persistence service that does NOT emit standard OWI on its replay.

### 8.7 Scope & follow-ons

PERSISTENT 3b protects **stored payloads on disk**: **confidentiality** (sealed) + **per-record
authenticity** of the payload AND its AAD-bound metadata (topic/guid/sn/kind/key-hash) — any flipped
byte fails the GCM tag, fail-closed — and it survives restart. It provides **record-sequence
integrity** via the keyed v3 MAC chain (§8.5): interior delete/reorder/substitution/insertion are
tamper-evident at store-open. It **also seals the record metadata** (topic/GUID/SN/kind/key-hash) at
rest — see §8.9 (WP-DURABILITY-METADATA-CONF-3c). For **ALL THREE tiers (FILE + SQLite + microservice)** it now
also detects **malicious whole-tail truncation / whole-topic drop / whole-store rollback** via the sealed
high-water tail anchor (§8.5, ADR 0045 §7.1); the anchor is complete across every durability tier. The follow-ons
(ADR 0026 §10 / ADR 0025 §10): cross-vendor coexistence dedup **(RESOLVED — ADR 0027: RTI PS uses
standard OWI on its retained-history replay, so no vendor PID is needed; the configurable
`:relay-durability`/`:collect-durability` tiers landed; ADR 0027 §follow-on 1 RESOLVED — ADR 0028:
live exactly-once captured dir-a N=545, dir-b N=550)**;
**KEEP_LAST-superseded compaction** **(RESOLVED — ADR 0029: `%compact-topic-records` pass 2 keeps newest
`HISTORY-DEPTH` `:data` records per non-NIL-key-hash instance on every `store-open`; `make-file-store`
and `make-persistent-store-factory` accept `:history-kind`/`:history-depth` as factory defaults;
`make-service-spec` carries `history-kind`/`history-depth` fields; `service-start` passes them to
`store-open` — making the service-spec the single functional policy source in service mode;
in-memory store applies online eviction on `store-put`; DARE intact; fuzz green; ADR 0029)**;
**online/threshold compaction (RESOLVED — SQLite per-put eviction = Sliver 1 §8.8.2; file-store
threshold-triggered mid-run rewrite = Sliver 2 §8.8.3, `*compaction-superseded-threshold*`; ADR 0029 §10.1)**;
**per-frame header integrity (RESOLVED — WP-DURABILITY-HARDENING-BATCH: on-disk frame v2 adds a
header CRC over `magic..payload-len`, so a sub-cap length corruption is caught loud instead of
mis-parsed as a torn tail; version-dispatched reader still reads v1; ADR 0026 §10.9)**;
**parent-directory fsync (RESOLVED — WP-DURABILITY-HARDENING-BATCH: `dds.pal:fsync-directory` after
every new-file / `epochs.dat` / compaction-rename / truncate-rename / `topics.map` dirent; ADR 0026
§10.10)**;
**`:process`-mode PERSISTENT (RESOLVED — WP-DURABILITY-HARDENING-BATCH: fail-fast — a `:process` spec
with a non-memory store signals before launch instead of silently running the in-memory tier; use
`:thread` mode for the PERSISTENT tier; ADR 0026 §10.11)**;
**store dir `D` 0700 enforcement (RESOLVED — WP-DURABILITY-HARDENING-BATCH: `store-open` enforces
0700 on `D` exactly as the key dir `K`, shared helper; ADR 0026 §10.12)**;
**log-level at-rest integrity — keyed MAC'd log chain (RESOLVED — WP-DURABILITY-MAC-LOG-CHAIN,
ADR 0045: v3 frames carry an HMAC-SHA-256 chain keyed by a cross-restart-stable anchor-derived key;
interior delete/reorder/substitution/insertion tamper-evident at store-open, fail-closed; keyed-store-
only; **whole-tail truncation / whole-topic drop / whole-store rollback now RESOLVED for ALL THREE tiers (FILE +
SQLite + microservice) by the sealed high-water tail anchor — WP-DURABILITY-TAIL-ANCHOR-{FILE,SQLITE,MS}, ADR
0045 §7.1** (against a truncate-but-not-`logmac.tail`-delete adversary; verify-then-invalidate at open so an
authorized reclaim-shrink + crash never false-rejects); `logmac.tail`-deletion + `epochs.dat` MAC remain deferred
residuals, §8.5)**;
**graceful FFI teardown on signal (RESOLVED — ADR 0030, 2026-06-22; `kill -15` exits cleanly
status 0, no SIGBUS, both impls; see §5.1)**;
epoch-table retirement; **3c metadata confidentiality (RESOLVED — §8.9, WP-DURABILITY-METADATA-CONF-3c)**;
in-RAM plaintext minimization
(honest pure-Lisp feasibility caveat); **P6** DDS-Security in-transit; and db/microservice
persistence backends (**db backend RESOLVED — §8.8, ADR 0049: `make-sqlite-store` on the same
vtable, config-selected via `make-sqlite-store-factory`**).

### 8.8 SQLite persistence backend (ADR 0049)

The `durable-store` vtable (`store.lisp:18-32`) **is the stable, fixed backend contract**: a
`defstruct` of function slots (`put`/`get-range`/`topics`/`purge`/`open`/`close`/`count-fn`/`sync`/
`set-chain-mac-fn`/`delete`) behind the public `store-*` dispatchers. Every backend fills the **same**
vtable unchanged; selection is the 0-arg store-factory closure on the service-spec. `make-sqlite-store`
adds a **second on-disk backend** implementing that vtable — it does **not** fork or extend it. (The
`delete` slot is the newest **additive** member — physical reclaim, Sliver 3a §8.8.4 — with the same
NIL-fallback binding as `sync`/`set-chain-mac-fn`: a backend may implement it or leave it NIL.)

**Config-selection is a one-line factory swap.** `make-sqlite-store-factory` mirrors
`make-persistent-store-factory` exactly — the only change is `make-sqlite-store` in place of
`make-file-store`, wrapped by the **same** DARE decorator:

```lisp
(dds.durability:make-service-spec
  :domain 0
  :topics '(("Square" . "ShapeType"))
  :store (dds.durability:make-sqlite-store-factory     ; <- the only change vs the file tier
          :dir     #p"/var/lib/dds/durability/"        ; DB + epochs.dat + logmac.anchor
          :key-dir #p"/var/lib/dds/keys/"))            ; ML-KEM keypair (0700/0600, fail-closed)
```

The composed store is `(make-encrypted-store (make-sqlite-store :path DIR/durability.sqlite3 …)
(make-file-key-provider :dir K) :epoch-dir DIR)` — the SQLite store holds only **opaque sealed**
payload bytes (it has zero crypto knowledge; the decorator seals the payload and delegates
topics/purge/count/open/close/sync to it).

**Schema** — one row per retained sample, keyed by `(topic, writer_guid, sn)`:

```
CREATE TABLE record (topic TEXT, writer_guid BLOB, sn BLOB, key_hash BLOB, kind INTEGER,
                     payload BLOB, mac BLOB, chain_seq INTEGER,   -- mac/chain_seq: v3 MAC chain (§8.8.1)
                     PRIMARY KEY (topic, writer_guid, sn));
CREATE INDEX idx_topic_order ON record(topic, writer_guid, sn);
```

**The u64-SN choice.** DDS sequence numbers are unsigned 64-bit with no bound; SQLite `INTEGER` is
**signed** 64-bit, so an SN ≥ 2^63 would sort negative (a silent reorder — the worst class of
durability defect). SN is therefore stored as an **8-byte big-endian BLOB** (lexicographic == numeric
u64 order, full range, no bound — matching the no-limit file/memory contract). `get-range` still
sorts in Lisp via the shared `%record-guid-sn<`, so the returned order is **byte-exact identical** to
the memory + file backends regardless of SQL collation.

**Vtable semantics.** `put` = existence-check → T (idempotent) / bounded-full → `:rejected` /
`INSERT OR IGNORE` (the same three-branch `cond` as the other stores). `open` is the
**restart-recovery** entry point: a fresh `make-sqlite-store` on an existing DB path replays all prior
rows (SQLite reopens the file), enforces 0700 on the DB dir (cleartext metadata, as the file store
does), then runs compaction-on-open via the shared `%compact-topic-records`. Under `:keep-last` the
store ALSO evicts superseded rows **online on each put** (§8.8.2), so a continuously-open store stays
bounded without a reopen. `sync`/`close` do a
`PRAGMA wal_checkpoint(FULL)` durability barrier (journal mode WAL, `synchronous=FULL`; durability is
off the per-sample hot path, so maximum safety over throughput). `set-chain-mac-fn` is **LIVE** — the
per-row keyed MAC chain is at parity with the file store (§8.8.1).

**Dependency.** `cl-sqlite` (ASDF `sqlite`, CFFI over `libsqlite3`) — impl-agnostic, loads +
round-trips identically on Clasp and SBCL (no reader conditionals). Transitive: `iterate`; native:
`libsqlite3` (SBOM + provenance recorded).

**Follow-ons:** encrypted-tier physical reclaim — **RESOLVED, both backends, continuously-open + cross-restart
(SQLite online Sliver 3a §8.8.4; file `:delete` Sliver 3b §8.8.5; compaction-on-open cross-restart sweep
Sliver 3c §8.8.6)**;
plus whole-topic-deletion residual and dynamic-topic parity. (SQLite online compaction = Sliver 1,
RESOLVED §8.8.2; file-store runtime/threshold compaction = Sliver 2, RESOLVED §8.8.3; metadata-3c
confidentiality = RESOLVED §8.9.)

#### 8.8.1 SQLite per-row keyed MAC chain (WP-SQLITE-MAC-CHAIN, ADR 0049 §9 / ADR 0045 §9)

The SQLite backend is at tamper-evidence **parity** with the file store's v3 keyed HMAC chain (§8.5).
When the encrypted decorator installs the log-MAC oracle (`store-set-chain-mac-fn`), each put writes a
32-octet chain MAC into the `mac` column and `store-open` verifies every topic's chain (fail-closed)
**before** compaction, so tamper cannot be laundered by the compacting `DELETE`. The MAC is
**byte-identical** to the file store: it reuses `%frame-record-versioned`/`%chain-seed`/`%chain-mac` so
a MAC over a record is the same whichever backend wrote it, and the same anchor/oracle/grandfather
machinery. Two SQLite-specifics:

- **Chain order is an explicit `chain_seq INTEGER`** (per-topic `MAX+1` on put), NOT rowid — robust
  against SQLite reusing a rowid after a compacting `DELETE`. Verification/recompute is
  `ORDER BY chain_seq ASC`.
- **Chain-recompute-on-compaction (no-false-reject).** A KEEP_LAST compacting `DELETE` breaks the chain
  over the survivors, so after any compacting delete the surviving rows are re-MAC'd as a fresh chain
  (re-seed, re-MAC in order, rewrite `mac` + dense `chain_seq`), mirroring `%rewrite-topic-log`. A
  KEEP_LAST MAC-chained SQLite store therefore reopens clean any number of times.

Downgrade defense (a non-empty non-grandfathered topic with zero chained rows fails the open) and the
grandfather exemption (a legacy multi-topic store's dormant topics coexist without a false-REJECT) hold
exactly as for the file store; the grandfather enumeration is **backend-dispatched** (`%store-grandfather-ids`)
so each backend's ids key identically to its own downgrade lookup — the file store keeps its raw-tid
log-dir scan (robust to a lost `topics.map`), SQLite maps real topic names via `%topic->id`. A
**NIL-oracle** bare `make-sqlite-store` writes NULL `mac`/`chain_seq` and skips verification —
byte-behaviorally unchanged. All ADR 0045 §7 residuals (malicious whole-tail truncation, `epochs.dat`
MAC, anchor-deletion full-downgrade, and whole-topic deletion) apply equally to the SQLite backend —
its sealed-high-water-anchor seam (`store-chain-tails`/`store-verify-chain-prefix`) is still NIL, so
whole-tail truncation / whole-topic deletion / whole-store rollback stay open here even though they are
now CLOSED for the FILE tier (WP-DURABILITY-TAIL-ANCHOR-FILE, ADR 0045 §7.1). Test:
`run-durability-sqlite-mac-chain-test` (tamper via DIRECT SQL: UPDATE payload/mac, DELETE, REORDER;
downgrade; KEEP_LAST reopen-repeatedly; epoch-boundary; grandfather; NIL-oracle regression).

#### 8.8.2 SQLite online per-instance KEEP_LAST eviction (WP-DURABILITY-COMPACTION-SQLITE, Sliver 1)

Compaction-on-open alone leaves a **continuously-open** KEEP_LAST store growing unboundedly between
reopens (ADR 0029 context). Sliver 1 adds **runtime DELETE-on-put**, mirroring the memory store's
`%mem-evict-instance` (ADR 0049 §10). After the `INSERT OR IGNORE`, when the effective policy is
`:keep-last` AND `kind = :data` AND `key-hash` is non-NIL, `%sqlite-evict-instance` DELETEs the lowest-
`(writer-guid, sn)` `:data` rows of that instance until at most DEPTH remain. `:keep-all` does no online
eviction; NIL-key-hash streams and lifecycle (`:dispose`/`:unregister`) rows are never depth-evicted;
idempotent re-puts skip it.

**Ordering nuance (honest).** The drop-candidates sort by `%record-guid-sn<` (writer-guid, then sn),
matching the FILE store's `%compact-topic-records` pass 2 — **not** the memory store, whose
`%mem-evict-instance` drops by PURE sn (ignoring guid). They diverge ONLY for a single instance (one
key-hash) fed by MULTIPLE writer GUIDs; the SQLite/file order is the self-consistent one (it matches
`get-range`'s ordering), and the memory store is the pre-existing outlier.

**Cost (honest).** The eviction SELECT + DELETE(s) are scoped to the instance
(`WHERE topic=? AND key_hash=? AND kind=?`; at most DEPTH+1 rows at put time). For a **bare** `:keep-last`
store (no chain — the realistic online path) the whole put is **O(instance)**, meeting the at-scale
intent. When a chain oracle IS installed, `%sqlite-recompute-topic` re-MACs the WHOLE topic (O(topic)
HMACs + UPDATEs) on every superseding put — under sustained writes that is effectively **O(topic) per
put**; this appears only for keyed + `:keep-last` + real key-hash (not a standard factory — the 3c tier
opens the inner store `:keep-all` with a NIL inner key-hash, so its inner online eviction never fires). A
batched/threshold re-MAC is a Sliver-2/3 hardening. **Not O(instance) unconditionally.**

**Re-MAC after eviction (the load-bearing point) + crash-atomicity.** The ADR 0045 chain covers the
surviving rows in `chain_seq` order; an online DELETE that does NOT recompute leaves survivors carrying
MACs chained over deleted predecessors → a **clean store false-rejects on the next open**. So when a
keyed store actually deletes, the topic's chain is recomputed over the survivors via
`%sqlite-recompute-topic` (the same machinery `%compact-on-open` uses after its DELETEs), and the running
chain-MAC is updated to the new tail. A bare (NIL-oracle) store has no chain and skips it. **The
DELETE(s) + the re-MAC are wrapped in a single `sqlite:with-transaction`** at BOTH sites — the online
`:put` evict AND the pre-existing on-open `%compact-on-open` (whose DELETE-then-recompute was previously
un-transacted under SQLite autocommit, so a crash between the committed DELETE and the recompute left a
survivor dangling → a false-reject of a clean store; this shipped and is reachable via the 3c tier's
on-open pass-1 settled compaction). A crash before COMMIT rolls the DELETE back → the store is at its
pre-eviction state → reopen verifies clean. Under WAL + `synchronous=FULL` that is one fsync at COMMIT
(fewer than N per-statement), single-connection under the store lock, no nesting. The durable-store
**vtable is unchanged** (internal to `:put` / `:open`); reuses `%record-guid-sn<`, the on-open compaction
DELETE, and `%sqlite-recompute-topic` (DRY). Tests: `run-durability-sqlite-keeplast-online-test` (bounded
growth to DEPTH without reopen — RED at count=6 with eviction disabled; newest-D survive byte-exact; two
instances independent; NIL-key-hash never evicted; lifecycle kept; KEEP_ALL unaffected; never-exceeds-D
unchanged), `run-durability-sqlite-online-chain-test` (online eviction re-MACs survivors → fresh reopen
verifies clean + get-range returns newest DEPTH; pure-Lisp MAC oracle, both impls, no OpenSSL), and
`run-durability-sqlite-crash-consistency-test` (fault injected between the DELETE and the re-MAC at both
sites → the txn rolls back → fresh reopen verifies clean + recovers the pre-eviction set; RED-proven as a
`SQCC-OPEN-RECOVERS` false-reject when the on-open transaction is neutralized). Sliver 2 (file-store
runtime/threshold compaction) is RESOLVED (§8.8.3); Sliver 3a (encrypted-tier physical reclaim, SQLite
online case) is RESOLVED (§8.8.4); Sliver 3b (file backend `:delete`, §8.8.5) + Sliver 3c (compaction-on-open
cross-restart sweep, §8.8.6) are RESOLVED — the encrypted-reclaim story is CLOSED (both backends,
continuously-open + cross-restart).

#### 8.8.3 File-store runtime/threshold compaction (WP-DURABILITY-COMPACTION-FILE, Sliver 2)

Compaction-on-open alone leaves a **continuously-open** KEEP_LAST **file** store growing unboundedly
between reopens (ADR 0029 context — its `:put` is pure append). The file store is **APPEND-ONLY** and
cannot delete-in-place, so — unlike the SQLite per-put DELETE of §8.8.2 — it compacts in **BATCHES**:

- **O(1)-per-put supersede counter.** A `:keep-last` `:data` put with a non-NIL key-hash bumps a
  per-instance `:data` tally; when it exceeds depth `D` the put supersedes an older record and bumps a
  per-topic pending counter. No per-put whole-topic scan.
- **Threshold-triggered mid-run rewrite.** On crossing **`*compaction-superseded-threshold*`** (a new,
  docstring'd, tunable special variable, default **128**) the store runs `%compact-topic-records`
  (pass-1 settled + pass-2 KEEP_LAST, **identical** to on-open) + the **existing** atomic
  `%rewrite-topic-log` for that topic **mid-run** (no close/open cycle), then prunes the in-memory index
  + counters to the survivors and resets the counter. The on-disk log stays bounded to
  **`live-count + threshold`** records; the amortized O(topic) rewrite is spread over ~threshold puts.
- **Crash-atomicity is INHERITED — no new transaction machinery.** `%rewrite-topic-log` already writes
  `<log>.tmp`, fsyncs, and atomic-renames over the original (re-emitting a fresh v3 MAC chain). A crash
  during the mid-run rewrite leaves **either** the old log **or** the new log, never torn (contrast
  Sliver 1, which had to wrap SQLite's autocommit DELETEs in a transaction). The append fd is
  **closed + re-pointed** around the rewrite so no stale fd appends to the renamed-away log (a data-loss
  guard); the running chain MAC is carried to the rewrite's fresh tail. Crash recovery discards orphaned
  `<tid>.tmp.log` files (an un-renamed temp is uncommitted; the original log is authoritative).
- **Same exemptions.** KEEP_ALL does no threshold compaction; NIL-key-hash + lifecycle records are never
  depth-evicted; a below-threshold store's append path is byte-identical (no rewrite fires). The
  durable-store **vtable is unchanged** (internal to `make-file-store`; the file store's own physical
  `store-delete` slot lands in Sliver **3b**, §8.8.5).
- **Logical read view = exactly D.** The physical batching holds up to `D + threshold` records per
  instance between rewrites, so — to keep the exported `store-get-range` / per-topic `store-count`
  contract identical to the memory + SQLite backends (whose online eviction returns the logical newest-D
  view) — the file store applies the shared **pass-2 `%keep-last-latest`** on **read** under `:keep-last`
  (sorted by `%record-guid-sn<`, then newest-D `:data` per instance); per-topic `store-count` is that
  view's length (total `store-count` stays the physical record count, matching the decorator). It is
  **depth-only** — the bare backends never drop settled instances on read — so `:keep-all` returns the
  raw sorted view (byte-identical) and lifecycle records survive until the next open. The physical log
  stays batched-bounded. The encrypted decorator runs its own both-pass compaction on top of its
  `:keep-all` + NIL-key inner store (pass-1 a no-op there), so this read view neither double-compacts nor
  regresses it.

**Settled-instance-churn residual — RESOLVED (WP-DURABILITY-SETTLED-RECLAIM, TRIGGER-ONLY settle trigger):**
`super-pending` originally tracked only `:data` supersession, so an adversarial workload of endless DISTINCT
settling instances (register → write-once → dispose → unregister, a NEW key-hash each, never re-touched)
stayed within depth D, never bumped the counter, and a continuously-open log grew without bound (pass-1
reclaimed the settled tombstones only on the next `store-open`). The `:put` path now folds every keyed put
into a per-instance `settle-tally` and, on the **SETTLE transition** — the *exact* pass-1 predicate (a
`:dispose` AND an `:unregister` both seen AND the final record a tombstone; order-aware, so a resurrecting
`:data` un-settles it) — charges that instance's **reclaimable frame count** into the SAME `super-pending`,
firing the **SAME** unchanged atomic `%rewrite-topic-log` (pass-1 reclaims the settle). Only the *counting*
is new — the rewrite / chain-MAC re-seed / `tmp+fsync+rename` crash-atomicity path is untouched — so the
settle predicate equals pass-1 exactly (a **live** instance is never false-reclaimed; a settle-then-reregister
keeps its resurrected data) and a settle-triggered compaction reopens on a valid re-seeded chain / rolls back
on a mid-compaction crash. The on-disk frame count **and** the in-memory index now stay bounded (~ threshold)
under settling churn. The shared `settle-tally` / `%settle-tally-fold` (in `store.lisp`) is reused by the
encrypted decorator's RAM window reclaim (§8.9, ADR 0025 §10.3), so the settle predicate is defined once.

**Settle-tally count-exactness (WP-DURABILITY-SETTLE-COUNT-EXACT):** as first shipped the settle charged the
instance's *entire* frame count into `super-pending`, while the KEEP_LAST supersession path had *already*
charged +1 per superseded `:data` frame of that instance. For an instance FIRST superseded THEN settled, the
overlapping superseded `:data` frames were counted **twice**, so the threshold was crossed slightly **early** —
a marginally-more-frequent rewrite (a **safe over-count**: earlier compaction, tighter log, never data loss).
The count is now **exact**: the `settle-tally` carries a `superseded` field the supersession path increments in
lockstep with its `super-pending` charge, and the settle contributes only `frames − superseded`, so each
reclaimable frame is charged **exactly once** (both fields reset on charge, so a resurrect → re-settle re-counts
cleanly). The settle **predicate**, the pass-1 reclaim, and the rewrite / chain-MAC path are **unchanged** —
only the count arithmetic changed. Pure churn (`≤ D` `:data`, no supersession) has no overlap, so it was already
exact and is untouched (the bounded-on-disk headline stays green). Proven by
`run-durability-settle-count-exact-test`.

Tests: `run-durability-file-threshold-compaction-test` (bounded growth to `<= D + threshold` WITHOUT a
reopen — RED pre-Sliver-2 = N=40; newest-D survive byte-exact; boundary → get-range = exactly D;
below-threshold never rewrites; KEEP_ALL grows to N; two instances bounded, no loss),
`run-durability-file-online-chain-test` (the mid-run rewrite re-emits a fresh v3 chain + re-points the
running MAC → a fresh keyed store reopens clean + returns newest D byte-exact; the newest samples,
appended after a mid-run rewrite, are not lost to a stale fd), and
`run-durability-file-crash-consistency-test` (fault via `*durability-debug-file-rewrite-fault*` after the
tmp fsync, before the rename → the original log is intact → fresh reopen verifies the chain clean +
keeps the newest D, no data loss, no false-reject; a pure-Lisp MAC oracle → both impls, no OpenSSL).
The settled-instance-churn trigger is proven by `run-durability-settled-reclaim-test`: (A) bounded-on-disk
RED→GREEN (N=50 distinct settling instances continuously open → on-disk + index bounded to ~ threshold;
RED = 3N via `*durability-debug-disable-settle-trigger*`); (B) no-false-reclaim (a live data-only instance
and a settle-then-reregister instance both survive a settle-triggered compaction, get-range correct);
(C) chain-MAC + crash-fault (a settle-triggered compaction of a keyed store reopens clean, and a fault
mid-settle-compaction rolls back to the intact original log — no data loss). Settle-count-exactness is
proven by `run-durability-settle-count-exact-test`: (A) count-exact RED→GREEN — a superseded-then-settled
instance's `super-pending` reaches exactly 7 (= all its frames, pinned by the threshold-7-fires /
threshold-8-does-not pair) where the pre-fix double-count 11 fired **early** at threshold 8 (RED via
`*durability-debug-double-count-settle*`); (B) no-under-count at scale — K superseded-then-settled instances
stay bounded on disk (the exact trigger still fires, so the residual stays closed); (C) pure churn is
identical under the exact fix and the double-count.

#### 8.8.4 Encrypted-tier physical reclaim (WP-DURABILITY-ENCRECLAIM-SQLITE, Sliver 3a)

The 3c encrypted decorator (§8.9) opens its inner store **KEEP_ALL** and puts a NIL key-hash + a
per-SAMPLE guid-surrogate + `sn'=0`, so the inner store has no instance identity and its own KEEP_LAST
eviction never fires: superseded blobs were compacted **logically** at `store-get-range` but **physically
retained** until `store-purge` (the inner `store-count nil` grew to N). Sliver 3a physically reclaims them
for the **continuously-open SQLite** encrypted tier via three additive pieces:

- **Additive `store-delete` vtable slot** (`store.lisp`) — `store-delete (store topic writer-guid sn) →
  t | :unsupported`, per-record delete-by-**primary-key** (NOT evict-instance: the decorator knows the
  exact prior surrogate to reclaim). It is the EXACT NIL-fallback binding of `store-sync` /
  `store-set-chain-mac-fn`: a NIL slot returns `:unsupported` and the decorator falls back to logical-only
  (byte-identical to pre-3a). **SQLite and memory implement it (3a); the file store implements it as of
  Sliver 3b** (§8.8.5); a slotless backend still gets the `:unsupported` fallback. An additive slot on the
  stable vtable, not a fork.
- **Thin SQLite `:delete`** — the `DELETE FROM record WHERE topic=? AND writer_guid=? AND sn=?` + the
  `%sqlite-recompute-topic` survivor re-MAC of Sliver 1 (§8.8.2), wrapped in **ONE** `sqlite:with-
  transaction` so it is **internally atomic**: a crash between the DELETE and the re-MAC rolls back, so a
  clean chained store never false-rejects on reopen (the Sliver-1 hazard, closed by the txn). Reuses the
  Sliver-1 machinery (DRY).
- **Decorator online prior-surrogate window** — because the surrogate is per-SAMPLE, the decorator
  remembers each instance's `(topic-hash, real-key-hash) → {(real-guid, real-sn, surrogate)}` (bounded by
  the effective depth `D` = `eff-hd` from `store-open`). On each `:keep-last` `:data` put with a non-NIL
  key-hash, when the window exceeds `D` it physically deletes the entries **smallest by `%record-guid-sn<`**
  — writer-guid bytes ascending, THEN sn, the SAME order as the logical `%keep-last-latest`
  (`store-delete inner topic-hash surrogate 0`) — and rewrites the window to the newest `D`. **Ordering by
  `(guid, sn)` (NOT pure SN, NOT oldest-arrived) is the no-data-loss crux**: KEEP_LAST keeps the newest `D`
  by `%record-guid-sn<`, so the physical set equals the logical newest-D `%compact-topic-records` view
  **EXACTLY for ALL cases** — a single instance fed by MULTIPLE writer GUIDs (a pure-sn drop keeps the wrong
  survivor when the min-sn sample sits on the higher writer-guid — a get-range divergence) and an
  out-of-order writer (arrival ≠ SN order). The append is **dedup'd on the deterministic surrogate**, so an
  idempotent re-put of an already-tracked `(guid, sn)` — which `store-put` no-ops physically
  (`INSERT OR IGNORE`) — never double-counts and evicts a LIVE newest-D row. The window is cleared on
  `store-close` / `store-open` and per-topic on `store-purge` (bounds decorator RAM; prevents a stale
  window from mis-evicting a later same-instance write). Settled-instance-churn residual — **RESOLVED**
  (WP-DURABILITY-SETTLED-RECLAIM): the decorator sees the REAL kind/key-hash (the inner store sees only
  `:data` surrogates), so its `:put` folds every keyed put into a per-instance `settle-tally` and, on the
  SETTLE transition (the **shared** pass-1-equal `%settle-tally-fold`, the SAME detector the file settle
  trigger uses, §8.8.3 / ADR 0029 §10.1), `remhash`es the instance's window (and tally) — mirroring the
  `store-purge` clearing, so a later re-registration seeds a fresh window and is never mis-evicted.
  `instance-windows` now stays bounded to live + in-flight instances under settling churn; proven by
  `run-durability-encrypted-physical-reclaim-test` case (10) (RED→GREEN via
  `*durability-debug-disable-settle-trigger*`, observed via `*durability-debug-window-count-hook*`).

The inner `store-count nil` now **converges to Σ D per instance** instead of N. The **put+delete PAIR is
deliberately NON-atomic** — a LOWER bar than Sliver 1/2: a crash between the decorator's put and its
`store-delete` leaks the prior blob (physically retained, still logically compacted at get-range) and
**self-heals on the next delete** — a space leak, never a false-reject. `KEEP_ALL` deletes nothing (the
window guard requires `:keep-last`).

**Delivered next (3b, 3c — both AS-BUILT):** the **file backend `:delete`** (append-log mark-superseded +
threshold rewrite) is Sliver **3b** (§8.8.5); the **compaction-on-open sweep** of a prior session's ≤D
cross-restart leftovers (3a/3b's online window bounds only the continuously-open case) is Sliver **3c**
(§8.8.6) — the encrypted-reclaim story is now CLOSED for both backends.

Tests: `run-durability-store-delete-slot-test` (the additive slot + NIL-fallback binding — memory/SQLite/file
delete a keyed row + return T; a slotless vtable returns `:unsupported`; impl-agnostic, no OpenSSL), and
`run-durability-encrypted-physical-reclaim-test` (continuously-open encrypted SQLite `:keep-last 2`, N=6 one
instance → inner physical `store-count nil` = **2**, RED pre-3a = 6; get-range = newest D byte-exact; two
instances each bounded to D; an **out-of-order** writer's newest-D survive; a **multi-writer** single instance
→ the SQLite and file physical-reclaim get-ranges agree EXACTLY [`(guid,sn)` drop, not pure SN — RED kept the
wrong survivor]; an **idempotent re-put** never deletes a live newest-D row [surrogate-dedup'd append — RED
lost sn1]; **`store-purge`** clears the window so a later lower-SN write is not mis-evicted [RED mis-evicted
it]; reopen VERIFIES the v3 chain clean + newest-D; a fault between put and delete leaks + get-range stays
newest-D + self-heals + reopens clean; KEEP_ALL deletes nothing).

#### 8.8.5 Encrypted-tier physical reclaim, FILE backend (WP-DURABILITY-ENCRECLAIM-FILE, Sliver 3b)

Sliver 3a added the `store-delete` slot + the decorator window, but the file store had no `:delete` slot, so
`store-delete` returned `:unsupported`, the decorator skipped physical reclaim, and the encrypted **file**
tier stayed logical-only (its on-disk log grew to N). Sliver 3b implements the file `:delete` slot so the
continuously-open encrypted file tier physically reclaims too. **The key difference from SQLite:** the file
log is append-only (cannot delete-in-place) AND the inner file store is opened **KEEP_ALL** with NIL-key-hash
surrogates, so the Sliver-2 own-KEEP_LAST threshold counter (§8.8.3) never fires — the file `:delete` needs
its OWN mark-superseded + reclaim path:

- **(1) Immediate in-memory remhash** — `store-delete (topic-hash, surrogate, sn=0)` remhashes the surrogate
  row `(%record-key surrogate 0)` from the in-memory index at once, so `store-count nil` + the index reflect
  the logical removal immediately.
- **(2) Per-topic `pending-delete` set** — the surrogate key joins a NEW per-topic IN-MEMORY set whose SIZE
  is the O(1) reclaim trigger (the inner KEEP_ALL store's own KEEP_LAST counter never bumps here — NIL
  key-hash, so `store-delete` needs its own trigger). `remhash` returns T only for a live row, so an
  absent/double delete never inflates the set.
- **(3) Threshold rewrite EXCLUDING pending-delete** — crossing `*compaction-superseded-threshold*` runs a
  `%rewrite-topic-log` variant (a shared `%compact-topic-log` core, DRY with §8.8.3) that replays the log
  **excluding the pending-delete surrogate keys** (in addition to the existing `%compact-topic-records`
  settled pass), then clears the set. It reuses the **SAME Sliver-2 atomic tmp+fsync+rename** rewrite
  (re-emitting a fresh v3 MAC chain) and **PRESERVES the append-fd close-before-rewrite / reopen-after guard**
  (a stale fd appending to the renamed-away log = data loss). **No new crash-atomicity machinery** — the
  atomicity is inherited.

The continuously-open encrypted file tier's on-disk log is thus bounded to **≤ (D + threshold)** per instance
instead of growing to N (RED pre-3b = N: file `:unsupported` → decorator skips). The decorator's `%win-entry<`
`(guid,sn)`-ordered drop + surrogate-dedup + window lifecycle (§8.8.4) are unchanged — the file backend
inherits them, so a multi-writer instance's file get-range equals SQLite's exactly and an idempotent re-put
never loses a live row. The **bare (non-encrypted) file store's Sliver-2 KEEP_LAST path is unchanged** (the
slot exists but only the decorator drives it); a **KEEP_ALL** encrypted file tier deletes nothing (on-disk ==
N — the window guard requires `:keep-last`).

**Crash lower-bar (parity with 3a — a self-healing SPACE leak, never a false-reject or loss):** the
`pending-delete` set is IN-MEMORY (empty on reopen). A crash DURING the reclaim rewrite leaves the original
log intact (rename is the commit point; the orphan `<tid>.tmp.log` is discarded on open), the chain verifies,
the newest D survive. A crash BETWEEN the in-mem remhash and the batched rewrite reappears the surrogate on
reopen (the remhash was in-memory only) — but `store-get-range` still logically compacts it (correct reads,
newest-D) and the chain verifies. A same-session rewrite fault self-heals on the next put (the `pending-delete`
set stays armed — the rewrite faulted before the clear — so the next `store-delete` retries). The
**cross-restart** leftovers a fresh post-reopen window never re-deletes are reclaimed by the
compaction-on-open sweep (Sliver **3c**, §8.8.6 — RESOLVED, both backends).

Test: `run-durability-file-encrypted-physical-reclaim-test` (continuously-open encrypted **file**
`:keep-last 2`, N=20 one instance, no close → the inner ON-DISK v3-frame count [`%file-store-log-count` on the
`%enc-topic-tid` basename, log-MAC oracle from the anchor] stays **≤ D+threshold**, NOT 20 [RED pre-3b = 20];
the in-memory physical count converges to D; get-range = newest D byte-exact; reopen VERIFIES the v3 chain
clean + newest-D; a reclaim-rewrite fault [`*durability-debug-file-rewrite-fault*`] propagates → reopen on a
consistent log + chain verifies + no loss; a remhash/rewrite cross-restart split reappears the surrogate but
get-range stays newest-D [self-healing, 3c sweeps the leftover]; a continuously-open fault self-heals on the
next put; KEEP_ALL deletes nothing [on-disk == N]; multi-writer + idempotent parity with the decorator window).

#### 8.8.6 Encrypted-tier physical reclaim, CROSS-RESTART (WP-DURABILITY-ENCRECLAIM-SWEEP, Sliver 3c)

3a/3b bound the **continuously-open** case (the online prior-surrogate window physically evicts superseded
blobs on put). But `instance-windows` is IN-RAM and clrhash'd on `store-open` (bounds decorator RAM +
prevents a stale window mis-evicting a later write), so after a **RESTART** the fresh window does not know a
prior session's ≤D newest survivors per instance: post-restart online eviction (which tracks only THIS-session
puts) never evicts them and they leak until the next restart — across K restarts a hammered instance
accumulates **~K·D** physical rows. Sliver 3c adds a **decorator compaction-on-open SWEEP** at the END of the
`:open` lambda (after the DEK reload + the `instance-windows` clrhash), for `:keep-last` only and only once
`k_meta` is resident:

- for each inner topic-hash (`store-topics inner`), **decrypt its surrogate rows** — REUSING the get-range
  decrypt (`open-payload-v2` over the epoch-DEK map + `%open-meta-frame`), with the AEAD AAD (the topic-hash
  bytes) recovered from the on-disk topic-hash hex via `%meta-unhex`, since the plaintext topic name is
  off-disk cross-restart;
- **group the `:data` records by their REAL key-hash** (the instance);
- via the SAME `%trim-window-to-depth` the online evict now shares, **`store-delete` the leftovers beyond
  newest-D AND SEED `instance-windows` with the surviving newest-D** (same `(real-guid, real-sn, surrogate)`
  entry shape, same `%win-entry<` writer-guid-then-sn order).

**The window-seed is the crux.** Without it the fresh window stays empty and the next same-instance put cannot
evict the prior survivors (they leak); WITH it the next higher-SN put pushes the seeded window to D+1 and
evicts the oldest survivor, so **cross-restart physical converges to D exactly like the continuously-open
case** (SQLite = ~D in the DB; file = D in the in-mem index, ≤ D+threshold on disk). The sweep is off the hot
path (once per open, control-plane — it decrypts the whole store once, the same cost the first get-range would
incur), reuses `store-delete` (a `:unsupported` backend skips the reclaim but is still seeded — the guard
remains), re-MACs the survivors (SQLite atomic DELETE + re-MAC / file atomic reclaim rewrite) so the chain
**verifies clean after the sweep**, and is **idempotent** (an already-≤D store finds nothing beyond-D → no
deletes, no churn). A `:keep-all` reopen runs no sweep (retains all). **No vtable/wire change** — 3c reuses
the `store-delete` slot + the decrypt path + the window. This CLOSES the encrypted-tier physical-reclaim
residual for **both backends, continuously-open AND cross-restart**.

Tests: `run-durability-encrypted-cross-restart-sweep-test` (SQLite) and
`run-durability-file-encrypted-cross-restart-sweep-test` (file). Each writes 6 to one instance, closes,
reopens, ×K=4 cycles → the inner physical count stays **~D=2**, NOT ~K·D. RED is proven in-suite by the
test-only `*durability-debug-disable-open-sweep*` switch: sweep-disabled the physical count STRICTLY
accumulates ((2 4 6 8) across the 4 restart cycles; file on-disk likewise), sweep-enabled it stays bounded
((2 2 2 2); file on-disk ≤ D+threshold). Also: re-opening a leaked (pre-3c) store WITH the sweep reclaims it
to D; window-seeded continued post-restart writes (no close) stay D (RED without the seed = leak); get-range
post-sweep = newest D by real SN byte-exact; reopen-after-sweep verifies the chain clean. A dedicated
**multi-writer cross-restart** case (one instance fed by two writer GUIDs A\<B) locks that the sweep groups by
real key-hash and keeps the `(guid,sn)`-newest-D via `%win-entry<` (`B·3,B·6`), NOT the pure-SN `A·5,B·6`.

**Benign residual (FILE only, topics.map-dependent, NOT introduced by 3c):** the file sweep recovers each
topic-hash AAD from `store-topics` (the file store's `id-map`, rebuilt from `topics.map` on reopen). On a clean
write→close→reopen (what 3c targets — every test) it always persists. If `topics.map` were LOST, `store-topics`
falls back to the double-hex `tid`, so `%meta-unhex(tid)` yields the wrong AAD, the GCM tag fails, and the sweep
silently does not reclaim that topic — a bounded space non-reclaim, **no data loss, no false-reject, no crash**
(the unhex is bounds-safe; `store-get-range` still serves that topic via the caller's real topic name). An
orthogonal `topics.map`-durability failure mode; **SQLite is immune** (topic persisted in the DB column).

### 8.9 At-rest metadata confidentiality (Phase 3c, WP-DURABILITY-METADATA-CONF-3c)

The PERSISTENT tier (file AND SQLite, via `make-encrypted-store` with `:epoch-dir`) seals the record
**metadata** — topic, writer-GUID, sequence number, kind, key-hash — not just the payload. **No
cleartext topic name, GUID, SN, or key-hash touches disk**: not in log filenames, `topics.map`, frame
headers, the SQLite `topic`/`writer_guid`/`sn`/`key_hash` columns, or the raw file/DB bytes.

How it works (decorator-level, both backends; the bare inner stores are unchanged):

- **k_meta** — a cross-restart-stable key derived (`dds.dare:derive-meta-key`, HKDF-SHA384, distinct
  `"dds-dare/meta/v1"` info label) as a **sibling of the ADR-0045 log-MAC key** from the SAME
  deterministic ML-KEM decapsulation of the persisted `logmac.anchor`. A fresh process re-derives it
  identically and re-locates + decrypts the sealed metadata. No new key file or anchor.
- **topic-hash** = `HMAC-SHA-256(k_meta, 0x01 ∥ UTF-8(topic))` (hex) — the encrypted/independent index.
  It replaces the plaintext topic id as the file log basename / `topics.map` key / SQLite `topic`
  column, so `store-get-range(topic)` re-hashes the query and still locates records by topic equality
  while the topic NAME never touches disk.
- **Sealed metadata frame** — `guid ∥ sn ∥ kind ∥ [key-hash] ∥ payload` is sealed together under the
  per-epoch DEK, AAD = the topic-hash bytes; the metadata is thus GCM-authenticated inside the
  ciphertext (subsuming the earlier cleartext-key-hash AAD binding).
- **Surrogates** — the inner store sees only a topic-hash, a deterministic 16-byte guid-surrogate
  `HMAC(k_meta, 0x02 ∥ guid ∥ sn)[0..16)` (unique per (guid,sn) ⇒ idempotent dedup preserved), `sn'=0`,
  NIL key-hash, `kind=:data`.
- **Decrypt-then-sort** — the inner store runs KEEP_ALL; `store-get-range` decrypts, recovers the real
  metadata, sorts by real `(guid,sn)`, and applies the effective KEEP_LAST / settled-drop policy passed
  to `store-open`. Per-topic `store-count` is the same logical count. The v3 MAC chain (§8.5) is
  keyed on the topic-hash and covers the sealed frame unchanged.

**Residuals (accepted):** *topic-equality linkability* (same topic ⇒ same hash — a keyed index must be
deterministic to locate records; value-confidentiality is met, unlinkability is not claimed);
*physical space* (superseded blobs are compacted logically for correct reads but not physically
reclaimed until `store-purge`); *`store-topics` cross-restart* (names come from an in-session reverse
map — after restart only this-session topics are enumerable; records are still located by topic-hash).
Tests: `run-dare-metadata-conf-3c-test` (both backends), the extended `run-dare-persistent-store-test`
/ `run-durability-sqlite-dare-test` no-plaintext scans, `run-dare-keyhash-aad-test`. See ADR 0025 §10.3.

---

## 8.10 MICROSERVICE persistence backend — a durable-store proxied over TCP (ADR 0050)

The fourth pluggable persistence tier (ADR 0021 capability 6, after memory / file / SQLite) puts the
records in a **separate process** reached over TCP. It is the same `durable-store` vtable, *remoted*: a
**client** store fills every slot by proxying the call to a **reference server** holding an inner store.

```lisp
;; server: an opaque proxy over an inner store (memory in Slice 1); port 0 = ephemeral
(let* ((srv  (dds.durability:make-microservice-server :port 0))
       (port (dds.durability:microservice-server-port srv))
       (s    (dds.durability:make-microservice-store :host "127.0.0.1" :port port)))
  (dds.durability:store-open s)                                  ; connects + opens the inner store
  (dds.durability:store-put s "Square" guid 1 nil :data payload) ; -> T (or :rejected)
  (dds.durability:store-get-range s "Square")                    ; -> records, (guid,sn)-ordered, byte-exact
  (dds.durability:store-close s)                                 ; ends the session, closes the socket
  (dds.durability:microservice-server-stop srv))                 ; clean thread join + socket close, no leak
```

**PAL TCP primitives (the enabler).** `dds.pal:tcp-connect / tcp-listen / tcp-accept / tcp-local-port /
tcp-send / tcp-recv / tcp-close` — native `sb-bsd-sockets` **stream** sockets, the same substrate as the
UDP primitives (SBCL contrib + Clasp bundled, **no new dependency, no usocket**). A TCP stream is a byte
pipe, not message-framed, so two loops are load-bearing: `tcp-send` loops over short writes; `tcp-recv`
loops over partial reads until the full frame is assembled (a large payload splits across TCP segments —
a partial read is normal, not EOF), returning `NIL` only on genuine peer-close. On Darwin each socket
sets `SO_NOSIGPIPE` so a write to a dead peer is a catchable `SOCKET-ERROR`, not a SIGPIPE (identical
clean behaviour on both impls). No reader conditionals outside `dds-pal/`.

**The wire protocol.** Length-prefixed request/response over one connection (little-endian):
`u32 body-len | u8 op-code | payload` and `u32 body-len | u8 status | payload`. Ops: `put`=1,
`get-range`=2, `topics`=3, `purge`=4, `count`=5, `open`=6, `close`=7, `delete`=9. A topic is a
`u16`-length UTF-8 field; a record REUSES the **file-store frame format verbatim** (`%frame-record` /
`%parse-frame`) — no new record format is invented. Every length and count is bounds-checked against the
buffer extent before it is trusted (NFR-SEC-POSTURE): a malformed message raises a clean condition
(server drops the connection; client signals `microservice-store-error`), never an OOB access or a hang.

**Opaque proxy + DARE composition (Slice 2, built).** The server is **DARE-blind** — it decodes each op
and dispatches to its inner store's public dispatcher with zero crypto knowledge. Confidentiality
composes the other way: `make-encrypted-store` layers OVER the client store unchanged (the proxy carries
sealed bytes), realised by **`make-microservice-store-factory`** — the exact sibling of
`make-sqlite-store-factory` / `make-persistent-store-factory`, with `make-microservice-store` in the
inner slot and **no server change**:

```lisp
;; config-select the encrypted tier whose persistence is a REMOTE microservice; all DARE state is LOCAL
:store (dds.durability:make-microservice-store-factory
        :host "127.0.0.1" :port server-port   ; the opaque inner: the remote server
        :epoch-dir #p"/var/lib/dds/epochs/"    ; LOCAL: epochs.dat + logmac.anchor (client-side)
        :key-dir   #p"/var/lib/dds/keys/")     ; LOCAL: the ML-KEM-1024 keypair (client-side)
;; == (make-encrypted-store (make-microservice-store :host ... :port ...)
;;                          (make-file-key-provider :dir key-dir) :epoch-dir epoch-dir)
```

The client **seals + MACs locally**; the ML-KEM anchor, `epochs.dat`, the log-MAC anchor, and `k_meta`
all live in the local `epoch-dir`/`key-dir`, so the remote server stores **only opaque ciphertext**: a
hex topic-hash, a 16-byte GUID surrogate, `sn = 0`, a NIL key-hash, and the sealed blob — never a
plaintext topic name / GUID / SN / key-hash / payload, and never a key. The `:sync` slot is **NIL**
(group-commit sync is a local-store concern); the `:set-chain-mac-fn` slot is **LIVE** (Slice 3b, §8.10.2):
the decorator installs its log-MAC oracle into the client-side store, arming the client-side v3 chain-MAC
over the remote tier — a malicious server that **drops / reorders / tampers** sealed frames is detected
fail-closed on open (file/SQLite parity), the 32-byte MAC + `chain_seq` folded into the opaque payload the
DARE-blind server stores verbatim (server + wire protocol unchanged). Independently, **per-record DARE-GCM
authenticates each record** (an attacker cannot read, forge, or alter a frame's contents). The
`:chain-tails-fn`/`:verify-chain-prefix-fn` seam slots are **ALSO LIVE** (WP-DURABILITY-TAIL-ANCHOR-MS, §8.5),
filled CLIENT-SIDE: the sealed high-water tail anchor now closes **tail-truncation of a valid prefix AND
whole-topic-drop-by-a-malicious-server** — the latter because the decorator verifies the CLIENT-TRUSTED sealed
topic-SET (from the client's `logmac.tail`), not the server's `store-topics`, so a server omitting a topic is
still verified (fetch 0 → `:truncated` → fail-closed). A bare `microservice-store`
(no decorator to install the oracle) leaves the chain uninstalled and seals no anchor — memory-parity, Slice 1 unchanged. Unlike
the file/sqlite factories, the inner tier's HISTORY policy is not a factory argument — it is the SERVER's,
applied at server-start (§8.10.1); the client's `store-open` policy is a confirm/no-op at this shared,
server-owned tier.

### 8.10.1 Server-owned PERSISTENT inner + cross-restart + config-env (Slice 3a, built)

Slice 1/2 held the inner in memory; **Slice 3a makes the microservice a REAL persistence backend.** The
server OWNS its inner store's lifecycle — correct for a persistence tier that OUTLIVES individual client
sessions:

- **open@server-start (replay).** `make-microservice-server` opens the inner **once** at start (new
  `:history-kind`/`:history-depth` args; NIL = defer to the inner's factory default). A persistent
  `make-file-store` / `make-sqlite-store` inner **replays from disk** (recovers prior history); a memory
  inner opens empty.
- **close@server-stop (fsync).** `microservice-server-stop` is the sole point that closes the inner
  (`store-close` → fsync). A client connect/disconnect never closes it.
- **client-open = policy-confirm (not re-replay).** `+ms-op-open` no longer re-opens the inner: a second
  `store-open` on a file/SQLite inner would re-replay the whole log per client session (wasteful; the file
  store's re-open also rebuilds its append streams). The handler still bounds-validates the `hk`/`depth`
  payload, then acknowledges. The shared tier's history policy is set once at server-start.
- **client-close = session-end (not inner-close).** So multiple client sessions against one server see the
  same persisted store (`client2` after `client1`'s puts + close sees `client1`'s records).

**Cross-restart recovery** (the point of the slice): server1 (inner on disk `D`) collects the client's
puts + fsyncs on stop; server2 (a fresh inner on the SAME `D`) replays on start; a reconnecting client's
`store-get-range` recovers the records byte-exact + `(guid,sn)`-ordered + counted — for BOTH a file inner
and a SQLite inner. A **memory** inner recovers 0 (the RED — no persistence). **DARE-wrapped**
(`make-microservice-store-factory` over a server file inner): the server persists **opaque sealed frames**
to `D`, and a client with the SAME LOCAL epoch-dir re-derives the prior epoch DEK and `store-get-range`
**decrypts + recovers the real records** — while an on-disk scan of `D`'s logs confirms only ciphertext
(the plaintext topic / GUID / SN / payload are absent). The server never sees plaintext across the restart.

**Config-env seam.** `make-durability-store-factory` is the single backend-dispatch the durability-persistent
drivers share (DRY):

```lisp
;; driver-collect / driver-serve dispatch on DPERSIST_BACKEND (file [default] | sqlite | microservice)
:store (dds.durability:make-durability-store-factory
        backend                         ; "microservice" -> the REMOTE client tier
        :dir dir :key-dir key-dir        ; CLIENT-LOCAL DARE epoch-dir / key-dir (all backends)
        :ms-host ms-host :ms-port ms-port) ; the operator-run reference server (DPERSIST_MS_HOST/PORT)
```

`DPERSIST_BACKEND=microservice` + `DPERSIST_MS_HOST` (default 127.0.0.1) + `DPERSIST_MS_PORT` select the
remote client tier; the remote server is a separate process the operator runs. `"sqlite"` /
`"file"` (default) still select their local factories. Every branch yields the same
`encrypted-store(inner)` 0-arg closure the service-spec `:store` slot consumes.

**HISTORY-QoS OWNERSHIP — the decorator owns retention; server-side HISTORY-QoS is DESCOPED
(WP-DURABILITY-MS-RECONNECT).** The microservice inner tier's retention policy is **SERVER-configured**
(`make-microservice-server` `:history-kind`/`:history-depth`) and is deliberately **not** forwarded from the
client/service HISTORY QoS over the wire — and that forwarding is **not required; it is descoped as MOOT and,
under DARE, WRONG.** Under the always-on DARE production composition the **encrypted-store DECORATOR owns
retention CLIENT-SIDE**: it always opens the inner **KEEP_ALL**, LOGICALLY compacts newest-D on `get-range`
(`%compact-topic-records`), and PHYSICALLY reclaims a keyed KEEP_LAST put's superseded surrogate
(`%evict-prior-surrogates` → the §8.10.3 chained `store-delete` → `+ms-op-topic-rewrite+` survivor re-MAC —
delivered + TESTED KEEP_LAST-through-microservice). The reference **server MUST stay KEEP_ALL**: server-side
HISTORY-QoS is **INERT** under DARE (the decorator seals with key-hash NIL, so the inner's per-instance
KEEP_LAST never triggers) **AND WRONG** (a server eviction of a chained record would break the client's
`%ms-verify-chain` → `:mismatch` → brick). Matching the reference server to a KEEP_LAST QoS is not merely
unnecessary, it is **AGAINST the decorator's model.** The bare non-DARE microservice path (no decorator) is
not a production composition; HISTORY-QoS-over-the-wire forwarding is therefore **descoped**.

**Scope.** Slice 1 (built) = connect-on-open, round-trip byte-exact + `(guid,sn)`-ordered, large
multi-segment payloads, torn-read fails cleanly, both impls. Slice 2 (built) = the
`make-microservice-store-factory` DARE-wrap + the no-plaintext-at-server proof + round-trip through DARE,
both impls, zero server change. **Slice 3a (built) = server-owned persistent inner (open@start-replay /
close@stop-fsync) + cross-restart recovery (bare file+SQLite GREEN, memory RED; DARE-wrapped opaque-on-disk
+ client-side decrypt) + server-owned multi-session lifecycle + the `DPERSIST_BACKEND=microservice`
config-env seam, both impls.** **Slice 3b (built, §8.10.2) = the client-side v3 chain-MAC over the remote
tier: drop/reorder/tamper detected fail-closed on open, server + wire protocol byte-identical.**
**Slice 3c-1 (built, §8.10.4) = bounded client reconnect + idempotent retry (WP-DURABILITY-MS-RECONNECT):**
the conn-cell becomes an `ms-conn` struct (host/port/sock), a dropped connection (server restart / network
blip) triggers a **bounded single reconnect** (close+clear+re-dial-once+retry-once — no unbounded loop / no
hang) instead of a permanent brick, and the send-side raw-error wart becomes the one clean
`microservice-store-error`; every op is idempotent so a byte-identical retry cannot dup/lose/corrupt.
Client-side only, zero server/wire change. Deferred: multi-client / read-idle timeout / chunked large
`get-range` / DoS-hardening / the CLI `--backend` / the live 2-process interop (Slice 3c).
**Descoped:** HISTORY-QoS-over-the-wire forwarding (the decorator owns retention; the server stays KEEP_ALL —
above). See ADR 0050.

Every wire length/count is bounds-checked and the topic UTF-8 is well-formedness-validated (Unicode
Table 3-7 / RFC 3629) before `code-char`, so a malformed message raises a clean `microservice-protocol-
error` (never an out-of-range `code-char` TYPE-ERROR); a `serious-condition` backstop in the per-connection
serve loop means a single bad message drops that connection and the serve thread keeps accepting.

Tests: `run-pal-tcp-loopback-test` (PAL TCP round-trip), `run-durability-microservice-test` (the slice:
2 topics, distinct guids/sns/kinds/key-hashes, empty + 100 KB payloads, counts, idempotent re-put no-op,
delete, purge), `run-durability-microservice-large-test` (500 KB multi-segment byte-exact),
`run-durability-microservice-torn-test` (clean failure on peer-close), `run-durability-microservice-fuzz-test`
(malformed-UTF-8 topics → protocol-error + the serve thread SURVIVES + a subsequent valid client succeeds;
a garbled server response → a clean client `microservice-store-error`). Slice 2:
`run-durability-microservice-factory-test` (the factory composes `encrypted-store` over
`microservice-store`, name `:encrypted-persistent`; DARE-free, always runs) and
`run-durability-microservice-dare-test` (no-plaintext-at-server: topic `"Square"` / GUID / SN / payload
ALL absent from a byte-scan of the server's inner records, a RED bare store leaking all four; plus
round-trip through DARE byte-exact + ordered + idempotent re-put + count — skips if OpenSSL < 3.5). Slice
3a: `run-durability-microservice-cross-restart-test` (bare file + SQLite inner GREEN recover 5 across a
restart, memory inner RED recovers 0), `run-durability-microservice-dare-cross-restart-test` (DARE-wrapped:
on-disk frames at the server are ciphertext, client with the same local epoch-dir decrypts + recovers real
records byte-exact across the restart — skips if OpenSSL < 3.5), `run-durability-microservice-lifecycle-test`
(server-owned inner survives client sessions: client2 sees client1's records), `run-durability-microservice-
config-env-test` (DPERSIST_BACKEND=microservice selects the microservice factory structurally). Slice 3b:
`run-durability-microservice-remote-chain-test` (malicious-server DROP/TAMPER/REORDER each fail-closed on
open + a RED bare-store-undetected contrast + tail-truncation/whole-topic-drop now DETECTED via the tail anchor
+ round-trip/cross-restart through the chain + NIL-oracle regression — skips if OpenSSL < 3.5). The sealed
high-water tail anchor for this tier (WP-DURABILITY-TAIL-ANCHOR-MS, §8.5) is verified by
`run-durability-microservice-tail-anchor-test`. Slice 3c-1 (WP-DURABILITY-MS-RECONNECT):
`run-durability-microservice-reconnect-test` (DARE-wrapped **reconnect-after-restart** on a fixed port over a
file inner + **idempotent-retry** chain-verify-on-reopen — RED without the fix is a permanent brick; skips if
OpenSSL < 3.5) and `run-durability-microservice-reconnect-bare-test` (**bare reconnect-after-restart** +
**send-side-error-clean** + **no-infinite-loop** [down server fails bounded] + **bare-delete-tolerates-rejected**;
always runs) + `run-durability-microservice-reconnect-exhausted-test` + `run-durability-microservice-reconnect-
seal-test` (§8.10.4 Fix 1/A/B). Both impls, Clasp first; suite 489 → 493 → 494 → 498 → **503**.

### 8.10.2 Client-side remote-tier chain-MAC — detecting a malicious server (Slice 3b, built)

Slice 2 sealed each frame (confidentiality); **Slice 3b makes a malicious/compromised remote server's
DROP / REORDER / TAMPER of sealed frames tamper-EVIDENT** — file/SQLite parity — with **zero server change
and zero wire-protocol change**. The encrypted-store decorator installs its log-MAC oracle into the
**client-side** `microservice-store` (same process, `store-set-chain-mac-fn`); only the 32-byte MAC *output*
ever ships:

- **On put**, the client computes the ADR-0045 v3 chain MAC over the **unwrapped** sealed frame (the reused
  `%frame-record-versioned`, chained from a per-topic running-MAC table seeded by `%chain-seed`) and FOLDs
  `sealed' = sealed ∥ mac(32) ∥ chain_seq(u64 LE)` into the payload. The DARE-blind server stores `sealed'`
  **opaque** — a slightly-longer blob it never parses. `chain_seq` is mandatory: the server returns get-range
  in `(guid,sn)` order (≠ chain order), so the client stamps the chain order in and re-sorts by it to verify
  (as SQLite needs an explicit `chain_seq` column). An idempotent re-put does not advance the chain (a
  client-side `(guid,sn)` index, the microservice analogue of the file store's in-memory index).
- **On get-range**, the client STRIPS the 40-byte suffix (bounds-checked — a short payload from a malicious
  server fails cleanly, never OOB), returns `payload = sealed` to the decorator (transparent), and VERIFIES
  the topic's chain (re-seed, recompute each MAC, `equalp`-compare — a near-verbatim port of
  `%sqlite-verify-topic`).
- **On open**, a fail-closed verify pass get-range-verifies **every** topic before any read (file/SQLite
  parity); a tampered chain fails the open loudly.

```lisp
;; A DARE-wrapped microservice store now DETECTS a malicious server that drops/reorders/tampers frames:
(let ((store (funcall (dds.durability:make-microservice-store-factory
                       :host "127.0.0.1" :port port :epoch-dir base :key-dir kdir))))
  (dds.durability:store-open store)                       ; verify-on-open: fails loud if the server tampered
  (dds.durability:store-get-range store "Square"))        ; strips the fold + re-verifies the chain per topic
```

**Detected:** interior DROP (gap → prev-MAC mismatch), REORDER (order-dependent HMAC + `chain_seq` swap),
TAMPER/SUBSTITUTE/INSERT (recompute fails; DARE-GCM also fails on unseal). **NOT detected (the SAME residual
as file/SQLite, deferred to the ADR 0045 §7 sealed high-water anchor):** tail-truncation of a valid prefix
and — the topic-granularity version — whole-topic-drop (a server omitting a topic from `store-topics` is
never verified). No new crypto, no new dependency; the server code is byte-identical. The chain engages only
under the encrypted-store; a bare `microservice-store` is memory-parity (Slice 1 unchanged).

### 8.10.3 KEEP_LAST reclaim re-MAC over the wire (Slice 3d, built — ADR 0050 §4.4)

A KEEP_LAST **encrypted** microservice store used to **BRICK** on physical eviction. When the decorator's
online reclaim (`%evict-prior-surrogates` ⇒ `store-delete`) removed a superseded surrogate, the microservice
`:delete` was a **bare server proxy** — it deleted the record server-side but never re-MAC'd the surviving
client chain (unlike the file tier's `%rewrite-topic-log` and SQLite's `%sqlite-recompute-topic`, which
re-seed + re-MAC the survivors after a compacting delete). The survivors' stored **folded MACs went stale**
(they chained over the deleted predecessor) → the next open's `%ms-verify-chain` re-seeded and hit
`:mismatch` → **the store refused to open**. Reachable by KEEP_LAST-1 + two superseding puts of one instance.

**The fix** — the chained `:delete` becomes the microservice analogue of SQLite's `:delete = DELETE +
%sqlite-recompute-topic`. It re-chains the survivors client-side and pushes the result to the server via a new
whole-topic-rewrite op:

1. **get-range** the topic's current folded records over the wire; **drop** the deleted `(guid,sn)`.
2. **re-chain** the survivors (`%ms-rechain-survivors`): re-seed `%chain-seed`, re-walk in `chain_seq` order
   recomputing each MAC via the reused `%frame-record-versioned`, re-fold with a **dense** `chain_seq 0..M-1`
   — mirroring `%rewrite-topic-log` / `%sqlite-recompute-topic` exactly, so the next open recomputes
   byte-identical MACs and reopens CLEAN.
3. **update** the client chain state (`chain-macs`/`chain-seqs`/`put-index`).
4. **ship** the re-folded survivors in ONE `+ms-op-topic-rewrite+` op (op-code 8); the DARE-blind server
   **replaces** the topic's opaque frames (it never parses the mac/chain_seq riding inside the payload).

The server-side replace is **atomic** via a new additive NIL-fallback `store-replace-topic` vtable slot (same
binding as `store-delete` / `sync`): the default **memory** inner uses `store-purge` + bulk `store-put`
(trivially atomic in-process); a **file** inner reuses the atomic `%rewrite-topic-log` (tmp + fsync + rename); a
**SQLite** inner uses a single transaction (DELETE topic + INSERT survivors). A partial topic would brick the
re-MAC'd chain, so the swap is all-or-nothing. **No new crypto** (reuses `%chain-seed` /
`%frame-record-versioned` / `%ms-fold-payload`), no new dependency.

```lisp
;; A KEEP_LAST encrypted microservice store now survives a physical reclaim and reopens CLEAN:
(let ((s (funcall (dds.durability:make-microservice-store-factory
                   :host "127.0.0.1" :port port :epoch-dir base :key-dir kdir))))
  (dds.durability:store-open s :keep-last 1)
  (dds.durability:store-put s "T" guid 1 key-hash :data p1)
  (dds.durability:store-put s "T" guid 2 key-hash :data p2)   ; supersede → reclaim → re-MAC + topic-rewrite
  (dds.durability:store-close s))
;; reopen: the re-MAC'd survivor chain verifies → CLEAN, newest-D recovered byte-exact
```

Verified by `run-durability-microservice-keep-last-reclaim-test`: **brick-repro → CLEAN** (+ a self-contained
**RED** via `*durability-debug-ms-skip-reclaim-remac*` that bricks on reopen, proving the re-MAC is
load-bearing), **server DARE-blind** (a folded opaque blob > 40 bytes, no plaintext at the server), **sustained
tamper-evidence** (byte-tamper / survivor-drop / whole-topic-drop over the re-chained survivors each caught
fail-closed), **cross-restart** over a persistent file inner (byte-exact), and **crash-fault mid-replace**
(a crash before the atomic rename rolls back → reopen CLEAN with the pre-reclaim records intact). Skips if
OpenSSL < 3.5.

### 8.10.4 Bounded client reconnect + idempotent retry (Slice 3c-1, built — ADR 0050 §4.5)

Slices 1–3d connected once at open and **never reconnected**: on a dropped connection (server restart /
network blip) the dead socket **stayed in the conn-cell**, so every later op re-failed against the corpse —
any server restart **permanently bricked** the client store (the opposite of a *restartable* central store).
A **send-side wart** compounded it: `tcp-send` signals a plain error, but `%ms-call` translated only
`microservice-protocol-error`, so a send-side drop **escaped as a raw generic error**. WP-DURABILITY-MS-RECONNECT
fixes both, **client-side only — zero server / wire-protocol change** (the reference server holds **zero
per-session state**: `+ms-op-open` is a policy-confirm no-op, `+ms-op-close` an ack, so re-establishment is
just a re-dial).

- **The conn-cell becomes a struct.** `ms-conn` (`defstruct*`) carries **host + port + sock** so `%ms-call` /
  `%ms-exchange` can re-dial (host/port previously lived only in the open/fetch closures). Access stays under
  the store lock.
- **Bounded single reconnect.** `%ms-exchange` translates BOTH drop signals — a failed send (the wart) and a
  server-closed read (`%ms-recv-message` NIL) — to **`microservice-conn-lost`** (a *subtype* of
  `microservice-store-error`, so existing handlers still catch it, but distinguishable). On that, `%ms-call`
  closes+clears the dead socket, **re-dials ONCE** (short bounded backoff then `tcp-connect`), and **retries
  the op ONCE**. A second consecutive drop, or a failed re-dial (server still down → fast `ECONNREFUSED`),
  surfaces a clean `microservice-store-error` — a **bounded** single reconnect, never an unbounded loop or a
  hang.
- **Idempotent-retry safety.** The retry re-runs build+decode, safe because every op is idempotent AND advances
  client chain/put-index state **only after a confirmed response**: `put` recomputes a byte-identical folded
  frame the server INSERT-OR-IGNOREs (even if the original succeeded but its response was lost); the chained
  delete / topic-rewrite replaces the **same survivor set**; the bare `:delete` now **tolerates
  `+ms-result-rejected+`** (the record is gone = the goal). The single-retry path does NOT re-run chain
  verification mid-session.
- **Double-failure (exhausted-retry) + availability — Fix 1 + Fix 2 (they interact; newly reachable because
  the session now SURVIVES a drop).** *Fix 1:* if a chained put's original AND its retry both drop while the
  server APPLIED the record, the client chain stays unadvanced while the server holds it — a naive next put of
  the same topic would chain from the seed again → **two `chain_seq`-0 records** → the next open fails-closed
  (`chain MAC mismatch`) → a **false-reject brick of honest data**. A per-store **STALE-TOPICS** set fixes it:
  an exhausted chain-mutating op marks its topic STALE, and the next chained mutation FORCE-re-syncs the client
  chain state from the server (`%ms-resync-if-stale` — get-range + clear-then-verify, so a purged topic stays
  cleared) before chaining, so it chains from ground truth → **no fork, no brick**. *Fix 2:* `%ms-reconnect`
  leaving `sock` NIL used to make a store TERMINAL ("store is not open") on the next op, so an op *during* an
  outage permanently disabled the store; `ms-conn` now distinguishes **DROPPED** (re-dial-able) from **CLOSED**
  (terminal, set by `%ms-close`) and never-opened, so an op-during-outage RE-DIALS and recovers when the server
  returns. Fixing Fix 2 alone would widen Fix 1's collision, so the stale-resync is required alongside it.
- **Fix A — the clean-close seal never commits a stale/diverged `(N, M_N)` (a pre-existing worst-class brick).**
  An apply-then-ack-lost **purge** or **topic-rewrite** followed by a clean close (no further mutation on that
  topic) used to seal the topic's stale tail — `:chain-tails-fn` ignored the stale set — so the next open's
  tail-anchor prefix-verify **bricked HONEST data** (`:truncated` for a purge → 0 server records;
  `:truncated`/`:diverged` for a rewrite-shrink). `%ms-reseal-stale-topics` now runs in the seal path: it
  **resyncs** each stale topic from the server (a clean close ⇒ reachable → the correct tail, a purged topic
  drops out) and **falls back to skipping** it (head dropped) if it can't be resync'd — so no diverged value is
  ever sealed. The exhausted-**put**+close flavor was already clean (prefix-containment tolerates forward
  growth); only purge/rewrite-shrink needed this.
- **Fix B (introduced nit) — same-object close→reopen.** `%ms-dial` clears `closed-p` on a successful dial, so
  a close→reopen of the same encrypted(microservice) store object works (the decorator's pre-open tail-anchor
  probe dials and is no longer refused by the `closed-p` guard).

```lisp
;; A DARE microservice store survives a server restart on the SAME port — the next op reconnects transparently:
(dds.durability:store-open store)                                  ; connects to server1
(dds.durability:store-put store "Square" ga 1 kha :data pa)        ; stored on server1's file inner (disk D)
(dds.durability:microservice-server-stop srv1)                     ; server1 down (D fsync'd)
;; server2 on the SAME port + SAME D (replays A) …
(dds.durability:store-put store "Square" gb 2 khb :data pb)        ; RECONNECTS to server2 + SUCCEEDS (was: brick)
;; reopen a fresh client → the v3 chain verifies CLEAN, A+B present exactly once (idempotent)
```

Verified by `run-durability-microservice-reconnect-test` (DARE-wrapped: **reconnect-after-restart** +
**idempotent-retry** chain-verify-on-reopen — RED without the fix is a permanent brick; skips if OpenSSL < 3.5),
`run-durability-microservice-reconnect-exhausted-test` (DARE-wrapped: **EXHAUSTED-RETRY-NO-FORK** — a chained
put whose retry exhausts while the server applied it, then a 2nd put → the stale-resync fires → reopen CLEAN;
**RED via the skip-stale-resync knob → fork → brick**), `run-durability-microservice-reconnect-seal-test`
(DARE-wrapped: **SEAL-RESYNC-OR-SKIP** [Fix A — an apply-then-ack-lost purge + clean close → reopen CLEAN;
**RED → the stale tail is sealed → reopen bricks `:truncated`**] + **same-object-close→reopen** [Fix B]), and
`run-durability-microservice-reconnect-bare-test` (**bare reconnect-after-restart** + **send-side-error-clean**
+ **no-infinite-loop** [a down server fails in bounded time] + **bare-delete-tolerates-rejected** +
**op-during-outage-recovers** [Fix 2; **RED via the skip-redial knob → terminal**]; always runs). No new crypto,
no new dependency. HISTORY-QoS-over-the-wire forwarding is **descoped** in this WP (the decorator owns
retention; the server stays KEEP_ALL — see §8.10.1 and ADR 0050 §4.2).

---

### 8.10.5 Server DoS-hardening — read/idle timeout + incremental allocation + accept backoff (Slice 3c-2, built — ADR 0050 §4.6)

Slice 3c-1 made the **client** survive a dropped connection; Slice 3c-2 (WP-DURABILITY-MS-DOS) hardens the
**server** (and the shared reader, which also protects the client) against a malicious/abusive peer. Three
holes are closed — **no wire-protocol change, no new crypto, no new dependency**:

- **Read/idle timeout (the worst hole — a slow-loris hung the SERIAL server forever).** `tcp-recv` used to
  block indefinitely, so a client that sent the 4-byte length header then STALLED parked the single serve
  thread **forever** and **denied every other client**. A new PAL primitive
  **`dds.pal:tcp-set-recv-timeout (sock seconds)`** (`setsockopt(SO_RCVTIMEO)`, a 16-byte `struct timeval`,
  portable across SBCL + Clasp — the `SO_RCVTIMEO` optname is OS-specific, an `#+darwin`/`#-darwin` constant
  inside `dds-pal` like the existing socket-option constants, never an impl conditional) arms an idle
  deadline; `tcp-recv` returns a distinct **status `:timeout`** as its second value when the deadline fires
  (`socket-receive` returns `n=NIL` on a timeout vs `n=0` on a clean close — identical on both impls — so a
  timeout is never confused with `:eof` or data). *(This was a signalled `pal-timeout` condition until
  ADR 0064 — no Lisp conditions in our code — which replaced it with the status value; the three outcomes
  stay exactly as distinguishable, with no stack unwind.)* The **server** arms it on each accepted socket
  (`make-microservice-server :recv-timeout`, default 30 s), so a stalled recv returns `:timeout`, the serve
  loop **drops** that connection, and the accept loop **survives to serve the next client**. The **client** arms it on its
  connection (`make-microservice-store :recv-timeout`), so a stalled/half-open server surfaces as a clean
  `microservice-conn-lost` → the §8.10.4 reconnect path, never an infinite hang.
- **Incremental body allocation (amplification guard).** `%ms-recv-message` used to allocate the **declared**
  body length up front, so a 4-byte header declaring 256 MiB (`+ms-max-message+`) forced a 256 MiB allocation
  *before any body byte arrived*. `%ms-recv-body` now reads the body **incrementally** — the accumulator
  starts at 64 KiB and grows geometrically (capped at the declared length) **only as bytes actually arrive**,
  so allocated memory stays ≤ ~2× the bytes received. The `+ms-max-message+` **hard cap is kept** (an over-cap
  declare is rejected immediately, before any allocation). Because the reader is shared, it also caps a
  malicious server's huge-declared *response* against the client.
- **Accept-loop backoff (no hot-spin).** A persistent `tcp-accept` failure (fd exhaustion / EMFILE) used to
  spin the CPU. The serve loop now counts consecutive failures and applies `%ms-accept-backoff`: a bounded
  50 ms sleep then retry below the threshold, a logged stop past it. A successful accept resets the count, so
  a transient failure is non-fatal.

```lisp
;; A slow-loris (header then stall) no longer denies the serial server; a subsequent client is served:
(let* ((srv (dds.durability:make-microservice-server :port 0 :recv-timeout 1))   ; short idle timeout
       (port (dds.durability:microservice-server-port srv))
       (loris (dds.pal:tcp-connect "127.0.0.1" port)))
  (dds.pal:tcp-send loris (dds.tests::octets 64 0 0 0) 4)   ; declare a 64-byte body, send nothing (stall)
  (let ((s (dds.durability:make-microservice-store :host "127.0.0.1" :port port :recv-timeout 5)))
    (dds.durability:store-open s)
    (dds.durability:store-put s "ok" g 1 nil :data p)       ; SERVED — the server dropped the loris after ~1 s
    (dds.durability:store-close s))
  (dds.durability:microservice-server-stop srv))
```

Verified by `run-durability-microservice-slow-loris-test` (**RE-TARGETED for the multi-client server, §8.10.6**:
under the Slice-3c-3 per-connection-thread server a slow-loris no longer denies anyone regardless of the
timeout, so this test now proves the timeout's remaining role — RED with the timeout DISABLED the parked
slow-loris's cap slot is NOT reclaimed; GREEN with a 1 s timeout it is DROPPED + its slot RECLAIMED, and a
subsequent client is served), `run-durability-microservice-huge-declared-test` (over-cap rejected before alloc; a huge at-cap
declare with no body times out via the incremental reader and allocates **<< the declared length** — a
numeric bound on SBCL, a behavioral no-hang/no-OOM proof on Clasp), `run-durability-microservice-client-
timeout-test` (a stalling server → the client recv-timeout → clean `microservice-store-error`, bounded), and
`run-durability-microservice-accept-backoff-test` (the `%ms-accept-backoff` decision + a fault-injected
backoff-then-recover); the fuzz gate (`run-durability-microservice-fuzz-test`) is extended with slow-loris +
over-cap arms. Both impls green identically, Clasp first (Suite 503 → 507). The timeouts default to 30 s and
are configurable; `NIL` disables (the pre-hardening blocking behavior).

### 8.10.6 Server multi-client concurrency (Slice 3c-3, built — ADR 0050 §4.7)

Slices 1–3c-2 served clients **serially** (one accept+serve thread, each connection to EOF before the next).
Slice 3c-3 (WP-DURABILITY-MS-MULTICLIENT) serves **concurrent clients in parallel — SERVER-ONLY, zero client
/ wire change**:

- **Per-connection serve threads.** `%ms-serve-loop` spawns a dedicated thread (`dds.pal:spawn` →
  `%ms-serve-connection-in-thread`) per accepted connection and immediately loops — a slow client parks only
  its own thread.
- **Lock-guarded connection registry.** The single `conn-cell` becomes a list of `ms-conn-slot {conn, thread}`
  under `reg-lock`. `microservice-server-stop` joins the accept loop first (no new slot after), then drains
  the registry — closing every connection (waking a parked recv) and **joining every serve thread** — then
  closes the listener and, LAST, the inner store (no in-flight inner op races the close). A serve thread
  self-removes its slot on close, freeing its slot promptly.
- **Max-connections cap.** `make-microservice-server :max-connections` (default 64) bounds the concurrent
  serve threads: past the cap a newly accepted connection is **rejected** (closed) — no unbounded thread
  growth (a connection-flood DoS guard); a slot frees on any close, so the cap recovers.

**The load-bearing correctness — every server-side shared mutable state is locked.** The inner store is
internally locked per op (each `%ms-handle-request` op is exactly ONE inner call over fresh per-request
buffers); the registry + live count are under `reg-lock`; per-connection buffers are per-thread. **THE
critical fix** was the memory `store-replace-topic`: the NIL-fallback purge + bulk-put is **two separate
locked ops**, atomic *only* under a serial server — under concurrency a `get-range` interleaving between them
sees a **partial / empty topic**. The memory store now supplies a native `:replace-topic-fn`
(`%mem-replace-topic`) that holds the store lock **across** the clear + bulk re-insert as ONE critical
section, so no concurrent op ever observes a partial topic. (The file tmp+rename and the SQLite single
transaction were already atomic *and* serialize under their per-store lock.)

```lisp
;; the server serves concurrent clients in parallel; a slow client parks only its OWN thread
(let* ((srv  (dds.durability:make-microservice-server :port 0 :max-connections 64))
       (port (dds.durability:microservice-server-port srv)))
  ;; N clients on N threads, each its own connection, mixed ops to shared + per-client topics -> all correct
  (dds.durability:microservice-server-stop srv))   ; closes + joins every serve thread, no leak/hang
```

Verified by `run-durability-mem-replace-atomicity-test` (the memory-replace RED→GREEN: a barrier lands a
concurrent `get-range` at the swap midpoint — non-atomic reads an EMPTY partial, atomic blocks + reads the
full post topic), `run-durability-microservice-concurrent-clients-test` (headline: N clients × mixed ops ×
rounds → byte-exact, no loss / dup / cross-client corruption), `run-durability-microservice-stop-closes-all-test`
(N live connections drained + joined, no leak/hang), `run-durability-microservice-max-connections-test` (cap
reject → existing-connection-works → close → recover), and `run-durability-microservice-slow-drip-concurrent-test`
(a stalled client parks its own thread while a concurrent client is served — the §8.10.5 slow-drip residual
**structurally fixed**). Both impls green identically, Clasp first (Suite **507 → 512**; SBCL is the
race-correctness oracle).

### 8.10.7 Live 2-process interop + a server entrypoint + `tcp-shutdown` clean stop-wake (Slice 3c-4, the CAPSTONE — ADR 0050 §4.8)

Slices 1–3c-3 were exercised in ONE Lisp image. Slice 3c-4 (WP-DURABILITY-MS-2PROCESS) exercises the backend
**across REAL OS PROCESSES**, and closes the last cross-cutting defect (**N-A**) in the stop path.

- **`dds.pal:tcp-shutdown (sock &optional direction)`** — `shutdown(2)` `SHUT_RDWR` (constant `2`, identical
  on Darwin + Linux, no reader conditional). It portably **WAKES a thread blocked in `recv`** on BOTH OSes
  (a cross-thread `tcp-close` does NOT reliably wake a foreign `recv` on Linux) AND does **not free the fd**.
  `microservice-server-stop`'s registry drain now `tcp-shutdown`s each live connection to WAKE its serve
  thread; the **serve thread (the socket owner) then does the SINGLE `tcp-close`** in its own unwind. stop
  shuts down → wakes → joins; the owner closes once — closing **both** the Linux-no-wake **stall** AND the
  stop-vs-serve **double-close TOCTOU**. Both stop's shutdown pass and the owner's close run **under
  `reg-lock`** (mutually exclusive), which closes the narrow stale-fd window where a spontaneously-closing
  owner's fd could be read mid-close + shut down after reuse; the JOINS stay OUTSIDE `reg-lock`, so the
  lifecycle is still deadlock-free (shutdown-under-lock → release → join-outside-lock → listener + inner
  LAST). Verified by `run-durability-microservice-stop-wakes-test` (both impls, bounded): N serve threads
  blocked in `recv` with `:recv-timeout NIL` (so only the wake can unblock them) → stop (run under a 10 s
  **watchdog** so a wake regression fails RED, never hangs the suite) returns promptly + drains to 0 + every
  thread exits clean.
- **A server entrypoint + a live 2-process harness.** `interop/durability-persistent/driver-ms-server.lisp`
  runs a reference server as its own process (over a DARE-blind persistent `make-file-store` inner opened
  `KEEP_ALL`, block-until-`SIGTERM`); `driver-ms-client.lisp` is a small put / get-range / reconnect client
  built via the SAME `make-durability-store-factory "microservice"` seam the DDS drivers use;
  `run-microservice.sh` is a BOUNDED harness (every wait deadline-capped, all PIDs + the temp tree cleaned in
  a trap, non-zero on failure) proving **LEG 1** a PUT client process → a GET client process recovers
  **byte-exact across processes**, and **LEG 2** a server-process RESTART (same port + inner dir, v2 replays
  the fsync'd frames) with a mid-session **client reconnect (Slice 1) + persistent byte-exact recovery**.

```sh
# live 2-process proof (server process + client processes); BOUNDED, self-cleaning, non-zero on failure
interop/durability-persistent/run-microservice.sh    # LEG 1 PUT->GET + LEG 2 restart+reconnect, ALL LEGS PASS
```

The server is **DARE-BLIND** (it stores only opaque sealed frames; the client holds the DARE key + the
log-MAC chain in its LOCAL epoch-dir/key-dir). An operator-runnable `main.lisp --backend server` CLI mode was
a clean **follow-on** this slice — now **built** (§8.10.8). Both impls green identically, Clasp first
(Suite **513 → 514**).

### 8.10.8 The operator server CLI entrypoint — `durability-service-main --backend server` (WP-DURABILITY-MS-SERVER-CLI, ADR 0050 §4.9)

The §8.10.7 follow-on, resolved: the DARE-blind microservice **server** is now operator-runnable as a
**first-class CLI entrypoint** (semantics B — run the KV server clients connect to, *not* select a
client-side persistence backend). `durability-service-main` gains a second mode, **additively** — the
default durability SERVICE mode is byte-for-byte unchanged.

```
# run the server an operator hosts; clients point make-microservice-store-factory :host :port at it
durability-service-main --backend server --port 8080 --inner-backend file --inner-dir /var/lib/dds/ms-inner/
```

- **Discriminator + PURE sibling parser.** `--backend server` (or env `DDS_DURABILITY_BACKEND=server`)
  selects server mode (scanned before `parse-durability-config`, so the service parser is untouched);
  `parse-durability-server-config` walks `--host` / `--port` (**required**) / `--inner-backend file|sqlite`
  / `--inner-dir` (**required**) / `--max-connections` / `--recv-timeout` (+ `DDS_DURABILITY_*` env
  equivalents, precedence CLI > env > defaults) into a `server-config`, mirroring the existing `%parse-argv`
  flag-loop + `%config-error` idiom (no new CLI-arg library). Bad/missing args → a clean
  `durability-config-error` (explicit, `(safety 0)`-independent); `--help` / `-h` prints `durability-usage`
  (both modes). See §5.2.
- **The DRY shared lifecycle.** `%run-microservice-server` runs the whole server lifecycle — build the
  **DARE-BLIND** persistent inner (`make-file-store` / `make-sqlite-store` on `--inner-dir`, `KEEP_ALL`, **no
  DARE key**) → `make-microservice-server` → log `MS-SERVER-LISTENING` → install the SIGTERM/SIGINT handler →
  block → `microservice-server-stop` (the §8.10.7 clean `tcp-shutdown` wake) → log `MS-SERVER-STOPPED` →
  `uiop:quit 0` — and is called by BOTH the CLI mode AND `interop/durability-persistent/driver-ms-server.lisp`
  (updated to call it: no duplicated body). `:block nil` returns the running server (in-process/testing).
- **Gates (both impls, Clasp first, Suite 519 → 522).** `durability-server-mode-cli` (STARTS + client
  round-trip byte-exact + CLEAN stop), `durability-server-mode-restart` (PERSISTENT + clean-stop + RESTART
  on the same port + inner dir via the CLI → byte-exact recovery), `durability-server-mode-config` (the full
  CLI parse + defaults + env + CLI>env + the bad-args battery + the SERVICE-mode-unchanged discriminator +
  `durability-usage`). `run-microservice.sh` gains **LEG 3** (SBCL-only, bounded): the
  `driver-ms-server-cli.lisp` server launched through the CLI entrypoint persists across a live 2-process
  stop+restart — GET byte-exact, ALL LEGS PASS. No wire/crypto/dependency change; no reader conditionals
  outside `dds-pal`.

---

## 9. Cross-references

- ADR 0021 — Durability service scope decision (owner directive 2026-06-18; cap. 7 = always-on DARE)
- ADR 0022 — TRANSIENT_LOCAL as-built behavior (writer-side retention + late-joiner replay)
- ADR 0023 — TRANSIENT durability service Phase-1 architecture
- ADR 0024 — Dedup map architecture (watermark + bounded reorder set)
- ADR 0025 — DARE: CNSA-2.0 Data-At-Rest Encryption (the KEM-DEM envelope, key-provider, fail-closed, secret handling)
- ADR 0026 — Disk-backed PERSISTENT store + cross-restart key-epoch (file-store framing/recovery, envelope v2, group-commit, compaction, the coexistence finding)
- ADR 0027 — Cross-vendor coexistence dedup: RTI PS uses standard OWI on replay; `:relay-durability`/`:collect-durability` tiers; honest live status; §follow-on 1 resolved by ADR 0028
- ADR 0028 — Cross-vendor dual-relay exactly-once: live-captured convergence via logical-origin capture (dir-a N=545, dir-b N=550; resolves ADR 0027 §follow-on 1)
- ADR 0029 — Per-instance KEEP_LAST compaction in the durability service (DDS 1.4 §2.2.3.5; file-store compaction-on-open + in-memory online eviction; service-spec via store-open; Connext M=302→2, Fast DDS M=134→2)
- ADR 0030 — Graceful FFI teardown on SIGTERM/SIGINT (`dds.pal:install-signal-handler`; orderly drain supervisor-stop → runner-stop → store-close → uiop:quit 0; `kill -15` clean exit both impls; resolves ADR 0026 §10 item 3)
- ADR 0049 — Durability SQLite persistence backend (`make-sqlite-store` / `make-sqlite-store-factory` on the fixed `durable-store` vtable; SN as big-endian BLOB; DARE-wrapped; §8.8; resolves the "db persistence backend" follow-on)
- ADR 0050 — Durability MICROSERVICE persistence backend (`make-microservice-store` client + `make-microservice-server` reference server on the fixed `durable-store` vtable, proxied over native PAL TCP; reuses the file-store frame format; opaque DARE-blind proxy; §8.10; ADR 0021 cap. 6 — the last pluggable-persistence tier)
- `docs/superpowers/specs/2026-06-19-durability-dare-design.md` — the DARE design spec
- `docs/superpowers/specs/2026-06-20-durability-persistent-design.md` — the PERSISTENT design spec
- `docs/superpowers/spikes/2026-06-18-durability-virtual-guid-findings.md` — PID_ORIGINAL_WRITER_INFO spike
- `docs/superpowers/spikes/2026-06-20-rti-vendor-origin-findings.md` — RTI PS uses standard OWI on replay (ADR 0027 spike)
- `interop/durability-transient/` — cross-DDS interop captures and README
- `interop/durability-dedup/` — PID_ORIGINAL_WRITER_INFO cross-DDS legs + coexistence captures
- `interop/durability-dare/` — DARE cross-DDS transparency captures (Connext 352 / Fast DDS 152)
- `interop/durability-persistent/` — PERSISTENT transparency-after-restart (Connext 458 / Fast DDS 186) + the RTI-PS coexistence finding
- `interop/durability-coexist-dedup/` — live dual-relay coexistence harness; captures dir-a (N=545) + dir-b (N=550); `analyze-capture.py --assert-converged`
- `interop/durability-keeplast/` — KEEP_LAST restart-seed cross-DDS harness (Leg 1 Connext M=302→D=2, Leg 2 Fast DDS M=134→D=2); `spike/` — `PID_KEY_HASH` presence confirmations (767 Connext + 362 Fast DDS)
- `interop/graceful-shutdown/` — `kill -15` clean-exit harness (`driver.lisp` + `run-kill15.sh`); both Clasp and SBCL: status 0, no SIGBUS (ADR 0030)
- `src/dds-disc/disc.lisp` — `sample-origins` struct slot; `capture-data-key-hash` slot (KEEP_LAST, ADR 0029); `sample-key-hashes` table; `src/dds-disc/dataplane.lisp` — `node-sample-origin-guid` / `node-sample-origin-sn` (logical-origin accessors) + `%record-sample-origin` setter; `node-sample-key-hash (node key)` → captured `PID_KEY_HASH (0x0070)` per `(writer-guid . sn)` (ADR 0029)
- `src/dds-durability/` — service implementation (store / store-file / store-sqlite / store-microservice / spec / service / runner / supervisor / main / store-encrypted)
- `src/dds-dare/` — DARE crypto (openssl-ffi / primitives / envelope / key-provider)
- `src/dds-pal/pal-{sbcl,clasp}.lisp` — `fsync-stream` (group-commit; NFR-PORT split: SBCL `fdatasync(2)` / Clasp `finish-output`)
- `src/dds-tests/durability-test.lisp` — unit + integration tests (incl. `run-durability-no-double-delivery-test`, `run-durability-multitopic-test`, `run-durability-dispose-replay-test`, `run-durability-file-recovery-test`, `run-dare-*`, `run-durability-collect-origin-convergence-test`, `run-durability-keeplast-compaction-test`, `run-durability-keeplast-cross-restart-test`, `run-durability-keeplast-service-spec-policy-test`, `run-durability-keeplast-memory-test`)
- `src/dds-tests/pbt-test.lisp` — PID-parse fuzz arm (`fuzz-original-writer-info-parse`) + DARE open-path fuzz arm (`fuzz-dare-open-payload`) + the PERSISTENT crash-injection arm, NFR-SEC-POSTURE
