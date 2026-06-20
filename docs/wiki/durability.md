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

**Limitation:** topics are fixed at construction time. Dynamic topic-add to a running service is
a follow-up.

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
  announcement (spike-confirmed SEDP placement, not SPDP). A true dual-relay coexistence live proof
  with RTI PS requires a TRANSIENT topic (Phase 3). See `interop/durability-dedup/coexistence/README.md`.

See `interop/durability-dedup/README.md` for wire evidence and `ADR 0024` for the dedup architecture.

### 6.5 Remaining Phase-2 limitations

- **Seen-set prune deferred:** dedup-map entries per GUID are control-plane and bounded (ADR 0024);
  a GC of stale-GUID entries is a follow-up.
- **In-memory store only.** State is lost on process restart. Disk-backed + CNSA-2.0 DARE is Phase 3.
- **`:process` mode is SBCL-only** (runtime fallback to in-thread on other impls).
- **Dynamic topic-add to a running service** is deferred.

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

### 7.4 Scope & follow-ons

DARE 3a protects **stored payloads** (confidentiality + integrity + authenticity; tampering is
detected and fails closed). The MUST follow-ons (ADR 0025 §10): **3b** disk-backed PERSISTENT store +
the cross-restart key-epoch the `version` byte reserves; **3c** metadata confidentiality; in-RAM
plaintext minimization (with an honest pure-Lisp feasibility caveat); and **P6** DDS-Security for
in-transit confidentiality.

---

## 8. Cross-references

- ADR 0021 — Durability service scope decision (owner directive 2026-06-18; cap. 7 = always-on DARE)
- ADR 0022 — TRANSIENT_LOCAL as-built behavior (writer-side retention + late-joiner replay)
- ADR 0023 — TRANSIENT durability service Phase-1 architecture
- ADR 0024 — Dedup map architecture (watermark + bounded reorder set)
- ADR 0025 — DARE: CNSA-2.0 Data-At-Rest Encryption (the KEM-DEM envelope, key-provider, fail-closed, secret handling)
- `docs/superpowers/specs/2026-06-19-durability-dare-design.md` — the DARE design spec
- `docs/superpowers/spikes/2026-06-18-durability-virtual-guid-findings.md` — PID_ORIGINAL_WRITER_INFO spike
- `interop/durability-transient/` — cross-DDS interop captures and README
- `interop/durability-dedup/` — PID_ORIGINAL_WRITER_INFO cross-DDS legs + coexistence captures
- `interop/durability-dare/` — DARE cross-DDS transparency captures (Connext 352 / Fast DDS 152)
- `src/dds-durability/` — service implementation (store / spec / service / runner / supervisor / main / store-encrypted)
- `src/dds-dare/` — DARE crypto (openssl-ffi / primitives / envelope / key-provider)
- `src/dds-tests/durability-test.lisp` — unit + integration tests (incl. `run-durability-no-double-delivery-test`, `run-durability-multitopic-test`, `run-durability-dispose-replay-test`, `run-dare-*`)
- `src/dds-tests/pbt-test.lisp` — PID-parse fuzz arm (`fuzz-original-writer-info-parse`) + DARE open-path fuzz arm (`fuzz-dare-open-payload`), NFR-SEC-POSTURE
