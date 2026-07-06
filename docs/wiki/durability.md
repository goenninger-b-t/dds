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

Only the CDR payload is encrypted; record metadata stays cleartext-authenticated (metadata
confidentiality is a MUST follow-on, ADR 0025 §10). **DARE is at-rest only — it adds nothing to the
wire** (data-in-transit is the separate P6 DDS-Security work).

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
- **Detected:** interior record **delete / reorder / substitution (even with both CRCs recomputed) /
  insertion**, and **full-log v3→v2 downgrade** of any born-chained topic. **Deferred residuals (ADR
  0045 §7):** a bare chain **cannot** detect **whole-tail truncation** of a valid prefix (the shorter
  log is itself a valid chain) — honest torn tails still truncate-recover; detecting *malicious* tail
  truncation, the combined anchor-deletion-plus-full-downgrade vector, or a full rollback of a
  *grandfathered* legacy topic, needs a separable **sealed high-water anchor** (documented, deferred).
  The `epochs.dat` MAC is likewise deferred. Cost is off the sample hot path (one HMAC per put / per
  frame at open). Verified by `run-durability-mac-chain-test` (round-trip; v1/v2/v3 read; the four
  interior tampers with a non-vacuous control; the v3→v2 downgrade fails loud while a v3-tail migration
  log opens; **multi-topic legacy coexistence — a dormant legacy topic opens while a born-chained topic
  verifies and its downgrade fails**; cross-restart; key-absent/wrong-key; torn-tail + its residual).

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
tamper-evident at store-open. It does **not** yet detect **malicious whole-tail truncation** (the
deferred sealed-anchor residual, ADR 0045 §7) nor provide metadata **confidentiality** (metadata is
cleartext on disk). The follow-ons
(ADR 0026 §10 / ADR 0025 §10): cross-vendor coexistence dedup **(RESOLVED — ADR 0027: RTI PS uses
standard OWI on its retained-history replay, so no vendor PID is needed; the configurable
`:relay-durability`/`:collect-durability` tiers landed; ADR 0027 §follow-on 1 RESOLVED — ADR 0028:
live exactly-once captured dir-a N=545, dir-b N=550)**;
**KEEP_LAST-superseded compaction** **(RESOLVED — ADR 0029: `%compact-topic-records` pass 2 keeps newest
`HISTORY-DEPTH` `:data` records per non-NIL-key-hash instance on every `store-open`; `make-file-store`
and `make-persistent-store-factory` accept `:history-kind`/`:history-depth` as factory defaults;
`make-service-spec` carries `history-kind`/`history-depth` fields; `service-start` passes them to
`store-open` — making the service-spec the single functional policy source in service mode;
in-memory store applies online eviction on `store-put`; DARE intact; fuzz green; ADR 0029)**; online/threshold compaction;
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
only; malicious whole-tail truncation + `epochs.dat` MAC deferred residuals, §8.5)**;
**graceful FFI teardown on signal (RESOLVED — ADR 0030, 2026-06-22; `kill -15` exits cleanly
status 0, no SIGBUS, both impls; see §5.1)**;
epoch-table retirement; **3c** metadata confidentiality; in-RAM plaintext minimization
(honest pure-Lisp feasibility caveat); **P6** DDS-Security in-transit; and db/microservice
persistence backends (**db backend RESOLVED — §8.8, ADR 0049: `make-sqlite-store` on the same
vtable, config-selected via `make-sqlite-store-factory`**).

### 8.8 SQLite persistence backend (ADR 0049)

The `durable-store` vtable (`store.lisp:18-32`) **is the stable, fixed backend contract**: a
`defstruct` of function slots (`put`/`get-range`/`topics`/`purge`/`open`/`close`/`count-fn`/`sync`/
`set-chain-mac-fn`) behind the public `store-*` dispatchers. Every backend fills the **same** vtable
unchanged; selection is the 0-arg store-factory closure on the service-spec. `make-sqlite-store`
adds a **second on-disk backend** implementing that vtable — it does **not** fork or extend it.

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
                     payload BLOB, PRIMARY KEY (topic, writer_guid, sn));
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
does), then runs compaction-on-open via the shared `%compact-topic-records`. `sync`/`close` do a
`PRAGMA wal_checkpoint(FULL)` durability barrier (journal mode WAL, `synchronous=FULL`; durability is
off the per-sample hot path, so maximum safety over throughput). `set-chain-mac-fn` is intentionally
**NIL** — the per-row keyed MAC chain (the ADR 0045 analogue) is a documented follow-on; the slot
no-ops, so the store composes cleanly with the encrypted decorator's v2 epoch mode.

**Dependency.** `cl-sqlite` (ASDF `sqlite`, CFFI over `libsqlite3`) — impl-agnostic, loads +
round-trips identically on Clasp and SBCL (no reader conditionals). Transitive: `iterate`; native:
`libsqlite3` (SBOM + provenance recorded).

**Follow-ons (deferred):** per-row keyed MAC chain (ADR 0045 analogue); incremental/SQL-side
compaction at scale; metadata-3c confidentiality; dynamic-topic parity.

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
- `src/dds-durability/` — service implementation (store / store-file / store-sqlite / spec / service / runner / supervisor / main / store-encrypted)
- `src/dds-dare/` — DARE crypto (openssl-ffi / primitives / envelope / key-provider)
- `src/dds-pal/pal-{sbcl,clasp}.lisp` — `fsync-stream` (group-commit; NFR-PORT split: SBCL `fdatasync(2)` / Clasp `finish-output`)
- `src/dds-tests/durability-test.lisp` — unit + integration tests (incl. `run-durability-no-double-delivery-test`, `run-durability-multitopic-test`, `run-durability-dispose-replay-test`, `run-durability-file-recovery-test`, `run-dare-*`, `run-durability-collect-origin-convergence-test`, `run-durability-keeplast-compaction-test`, `run-durability-keeplast-cross-restart-test`, `run-durability-keeplast-service-spec-policy-test`, `run-durability-keeplast-memory-test`)
- `src/dds-tests/pbt-test.lisp` — PID-parse fuzz arm (`fuzz-original-writer-info-parse`) + DARE open-path fuzz arm (`fuzz-dare-open-payload`) + the PERSISTENT crash-injection arm, NFR-SEC-POSTURE
