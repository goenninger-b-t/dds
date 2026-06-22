# KEEP_LAST per-instance compaction — cross-DDS restart-seed proof (WP-DURABILITY-KEEPLAST-COMPACTION, M6/P5)

The per-feature interop Definition-of-Done gate for **KEEP_LAST(D) per-instance compaction**
(ADR 0029): after a genuine **process restart** over a PERSISTENT file-store opened with
`:history-kind :keep-last :history-depth D`, the on-disk store is compacted to the D newest
samples per non-NIL-key-hash instance, and a late-joining foreign subscriber receives exactly
D, not the original M written.

**Status: both legs LIVE-verified in-session (2026-06-22).** Captures under `captures/`.

| Leg | Peer | Collected M (proc 1) | After KEEP_LAST 2 compaction (proc 2) | Late-joiner received |
|---|---|---|---|---|
| **1** | **Connext 7.3.1** | **302** | **2** | **2** |
| **2** | **Fast DDS 3.6.1** | **134** | **2** | **2** |

Both late-joiners received exactly D=2 samples for the GREEN Square instance after the
process restart — not M.

## The KEEP_LAST-via-restart-seed scenario (read before running)

KEEP_LAST manifests to a late-joiner **via the file-store compaction-on-open on a process
restart**, NOT via the live-late-joiner path. This is a documented nuance, not a defect:

- **Live-late-joiner (same running service):** receives ALL M. The replay writer is
  KEEP_ALL + publish-on-collect (as built). A reader that connects while the collecting
  process is still running sees the full unreduced history from the replay writer's cache.
  KEEP_ALL-replay is the correct as-built phase-1 durability behavior.
- **Restart-seed late-joiner (this scenario):** receives D. When a fresh process opens the
  same file-store with `:history-kind :keep-last :history-depth D`, `store-open` runs
  compaction-on-open before `%seed-relay-from-store`. Compaction discards all but the D
  newest `:data` records per non-NIL-key-hash instance; `%seed-relay-from-store` then
  seeds the replay writer's KEEP_ALL cache with only those D records. A subsequently-joined
  reader gets D.

The in-process unit tests (`run-durability-keeplast-compaction-test`,
`run-durability-keeplast-cross-restart-test`, `run-durability-keeplast-service-spec-policy-test`,
`run-durability-keeplast-memory-test`) are the deterministic proof; this harness adds
cross-vendor (Connext + Fast DDS) confirmation of the scenario end-to-end.

Per-instance KEEP_LAST compaction targets instances with a **non-NIL key-hash** in the store
record. Connext and Fast DDS both emit `PID_KEY_HASH` (0x0070, RTPS 2.5 §9.6.4.8) on
DATA-with-payload samples **when there is a matched reader** (confirmed by the spike captures
in `spike/captures/connext-pub-sub-matched.pcap` and `spike/captures/fastdds-pub-sub-matched.pcap`).
Our service's collecting reader is matched to the foreign publisher, so the key-hash is
captured on every collected sample and stored in the `durable-record` key-hash field,
enabling per-instance compaction.

Samples without a key-hash (NIL) — the case when the service starts before the publisher
and the early samples arrive before the reader-writer match — are treated as a single
un-keyed instance and survive compaction untouched (**conservative: no samples lost**). The
matched-collect pattern (this harness: service starts first, then the publisher) ensures
key-hashes are captured from the first matched sample.

## The restart scenario step-by-step

The store is produced by `(make-persistent-store-factory :dir D :key-dir K :history-kind
:keep-last :history-depth 2)` wired via `make-service-spec :history-kind :keep-last
:history-depth 2`. Two genuine SBCL processes share the disk dirs `D` + `K`:

1. **Process 1 (`driver-collect.lisp`):** starts a PERSISTENT service on `D`+`K` with
   `:keep-last 2`. A foreign (Connext or Fast DDS) TRANSIENT_LOCAL publisher writes M
   samples on `Square`/`ShapeType` (one color = one keyed instance). The service's collect
   reader matches the publisher, captures the wire key-hash on each sample, and seals each
   record (DARE-encrypted with ML-KEM-1024 KEM + AES-256-GCM DEK) to the per-topic log in
   `D/topics/`. At `DKL_SECS`, `service-stop` → `store-close` → **fsync** the sealed log +
   `epochs.dat` to `D`, and the process **EXITS**.
   - The on-disk log holds M sealed records (the raw collection count, unreduced).
   - Process 1 prints `DKL-SVC1-COLLECTED Square=M` before exiting.
2. **Process 2 (`driver-serve.lisp`):** a **FRESH** SBCL process opens the **SAME** `D`+`K`
   with the same `:keep-last 2` spec. `service-start` → `store-open` with `:keep-last 2`:
   - The file-store replays the on-disk log → decrypts each record (re-derives per-epoch
     DEKs from `epochs.dat` via the ML-KEM-1024 private key in `K`).
   - **Compaction-on-open (`%compact-topic-records`)**: for the GREEN instance (with
     non-NIL key-hash), keeps only the 2 newest `:data` records; rewrites the log.
   - `store-open` returns: the in-memory table has D=2 records.
   - `%seed-relay-from-store` seeds the replay writer's TRANSIENT_LOCAL KEEP_ALL cache
     with those 2 records.
   - Process 2 prints `DKL-SVC2-RELOADED-AND-COMPACTED Square=2` + compaction-verified.
3. **Late-joining foreign subscriber** (starts AFTER proc 2 is up): receives D=2 for GREEN,
   not M. The original publisher and process 1 have both exited; the subscriber can only
   receive from process 2's D=2 seeded cache.

## Wire evidence (replay direction)

The service's replay writer is RTPS EntityId `0x00000102`.

### Leg 1 (`leg1-keeplast-connext.pcap`, 158 KB)

- Our replay writer (`0x00000102`) emitted **306 DATA** (SNs 1–302, some retransmits),
  covering the M=302 collected samples that were sent before compaction (the capture starts
  at tshark launch and includes the original collect exchange). After restart, proc2's seeded
  replay writer sends **2 DATA** to the late-joining Connext sub.
- The late-joining Connext subscriber printed:
  ```
  [connext-sub] #1 color=GREEN x=17 y=152 size=30
  [connext-sub] #2 color=GREEN x=20 y=154 size=30
  [connext-sub] received 2 sample(s).
  ```
- These 2 coordinates are the **2 newest** (highest-SN) positions from the 302-sample
  animation — the 2 samples that `compaction-on-open` kept. M=302 were written; exactly
  D=2 delivered after restart.

### Leg 2 (`leg2-keeplast-fastdds.pcap`, 82 KB)

- Our replay writer emitted **138 DATA** (SNs 1–134, some retransmits), M=134 collected.
  After restart, proc2's seeded cache delivers 2 to the late-joining Fast DDS sub.
- The late-joining Fast DDS subscriber printed:
  ```
  [shapes_sub] 1: color=GREEN x=82 y=74 size=30
  [shapes_sub] 2: color=GREEN x=83 y=81 size=30
  [shapes_sub] done, received 2
  ```
- Again the 2 newest (highest-SN) coordinates from the Fast DDS animation — D=2 after
  compacting M=134.

## The KEEP_LAST-via-restart vs KEEP_ALL-live nuance (accurate claim boundary)

This is documented explicitly here because the live observation (same-process late-joiner
gets M) might otherwise appear to contradict the claimed KEEP_LAST behavior:

| Scenario | Late-joiner gets | Why |
|---|---|---|
| Live late-joiner (proc 1 still running, no restart) | M (all collected) | Replay writer is KEEP_ALL+publish-on-collect; its cache = full history |
| Restart-seed (proc 2, compaction-on-open) | D | compaction-on-open reduced the on-disk log to D; %seed-relay-from-store seeded with D |

KEEP_LAST **does not retroactively evict** the live replay writer's cache. It only bounds
what is seeded from the on-disk store into a **fresh** process's replay writer cache.
Replay-writer KEEP_LAST (reducing the live cache) is a documented follow-on per ADR 0029 §10.

## Foreign-peer configuration

- `USER_QOS_PROFILES.xml` — Connext loopback (`allow_interfaces=127.0.0.1`, UDPv4) +
  TRANSIENT_LOCAL / RELIABLE / KEEP_ALL / unlimited resource-limits on writer & reader QoS.
  Run the Connext binaries from the `interop/durability-keeplast/` directory so they load
  this file from cwd.
- `fastdds-profiles.xml` — Fast DDS loopback-only (`interfaceWhiteList=127.0.0.1`, UDPv4).
  Copied to `interop/fastdds/shapes/profiles.xml` before each leg. The `DURABILITY=transient_local`
  env gate in `shapes_pub.cpp`/`shapes_sub.cpp` sets TL+KEEP_ALL QoS.

**FIRST: kill any stale DDS process on the discovery ports** (`lsof -nP -iUDP:7400-7440`).

## Run commands

```sh
export NDDSHOME=/Applications/rti_connext_dds-7.3.1
export CONNEXTDDS_ARCH=arm64Darwin20clang12.0
export DYLD_LIBRARY_PATH=$NDDSHOME/lib/$CONNEXTDDS_ARCH
# from repo root
```

### Leg 1 — Connext TL pub → M collected → restart (KEEP_LAST 2) → late Connext TL sub

```sh
rm -rf /tmp/dkl-D /tmp/dkl-K

# (optional) Capture
WIRESHARK_CONFIG_DIR=$(mktemp -d) /Applications/Wireshark.app/Contents/MacOS/tshark \
  -i lo0 -f "udp portrange 7400-7700" \
  -w interop/durability-keeplast/captures/leg1-keeplast-connext.pcap &

# PROCESS 1 — collect + persist + exit
DKL_DIR=/tmp/dkl-D DKL_KEYDIR=/tmp/dkl-K DKL_SECS=35 DKL_DEPTH=2 \
  ./scripts/with-sbcl.sh --load interop/durability-keeplast/driver-collect.lisp
# (wait for DKL-SVC1-STARTED, then start the publisher)

# Connext TL publisher (~20s)
cd interop/durability-keeplast
stdbuf -oL ../connext/shapes-pub/shapes_pub 0 GREEN &
PUB=$!; sleep 20; kill $PUB
# proc1 auto-stops at DKL_SECS: prints DKL-SVC1-COLLECTED Square=M

# PROCESS 2 — fresh process: reload + KEEP_LAST compaction + serve
DKL_DIR=/tmp/dkl-D DKL_KEYDIR=/tmp/dkl-K DKL_SECS=60 DKL_DEPTH=2 \
  ./scripts/with-sbcl.sh --load interop/durability-keeplast/driver-serve.lisp
# prints DKL-SVC2-RELOADED-AND-COMPACTED Square=2  (D=2, not M)

# LATE-JOINING Connext TL subscriber (starts AFTER proc2 is up)
stdbuf -oL ../connext/shapes-sub/shapes_sub 0 30
# prints "received 2 sample(s)" — the KEEP_LAST-current 2, not all M
```

### Leg 2 — Fast DDS TL pub → M collected → restart (KEEP_LAST 2) → late Fast DDS TL sub

```sh
rm -rf /tmp/dkl-D /tmp/dkl-K
cp interop/durability-keeplast/fastdds-profiles.xml interop/fastdds/shapes/profiles.xml

# Capture + PROCESS 1 (driver-collect, DKL_SECS=30) as in Leg 1, then:
DURABILITY=transient_local ./scripts/with-fastdds.sh bash -c \
  'cd interop/fastdds/shapes && stdbuf -oL ./shapes_pub GREEN 200'   # 200 samples

# PROCESS 2 (driver-serve, DKL_SECS=60), then the LATE Fast DDS TL subscriber:
DURABILITY=transient_local ./scripts/with-fastdds.sh bash -c \
  'cd interop/fastdds/shapes && stdbuf -oL ./shapes_sub 25'
# prints "done, received 2" — D=2 via KEEP_LAST restart-seed
```

Or run both legs with the provided script:

```sh
interop/durability-keeplast/run-interop.sh
```

## Live results (2026-06-22, this host, lo0)

| Leg | Peer | M collected (proc 1) | Compacted to (proc 2 store-open) | Late-joiner received | Correct (D=2)? |
|---|---|---|---|---|---|
| **1** | **Connext 7.3.1** | **302** | **2** | **2** | **YES** |
| **2** | **Fast DDS 3.6.1** | **134** | **2** | **2** | **YES** |

Proc 2 printed `DKL-SVC2-KEEPL-COMPACTION-VERIFIED: store holds exactly D=2 records` for
both legs — confirming compaction-on-open ran before the subscriber connected.

## Authoritative in-process proof (cross-reference)

The deterministic in-process tests for this feature (all pass SBCL + Clasp; Clasp validated first):
- `run-durability-keeplast-compaction-test` — unit test for `%compact-topic-records` KEEP_LAST.
- `run-durability-keeplast-cross-restart-test` — write M records, reopen with `:keep-last D`,
  assert D records remain + DARE decrypt succeeds (the same mechanism as this harness, in-process).
- `run-durability-keeplast-service-spec-policy-test` — end-to-end: `service-start` wires the
  `service-spec` KEEP_LAST policy through to `store-open` compaction-on-open.
- `run-durability-keeplast-memory-test` — in-memory store KEEP_LAST online eviction.

This cross-DDS harness is the cross-vendor (Connext + Fast DDS) confirmation on top of those proofs.

## Clean-room / provenance

Clean-room: the foreign peers are the committed `interop/connext/shapes-*` and
`interop/fastdds/shapes` harnesses configured for TRANSIENT_LOCAL via QoS XML (Connext) and
the C++ `DURABILITY` env gate (Fast DDS). No RTI / Fast DDS source is copied. The KEEP_LAST
compaction design is pinned from DDS 1.4 §2.2.3.5 (DURABILITY_SERVICE QoS history_kind /
history_depth); the file-store compaction-on-open from `%compact-topic-records` in
`src/dds-durability/store-file.lisp` (ADR 0029).

## Files

- `driver-collect.lisp` — process 1: start PERSISTENT service, collect M, stop (fsync), exit.
- `driver-serve.lisp` — process 2: fresh process, KEEP_LAST D compaction-on-open, serve.
- `run-interop.sh` — end-to-end script running both legs sequentially.
- `USER_QOS_PROFILES.xml` — Connext loopback + TRANSIENT_LOCAL/KEEP_ALL/RELIABLE profile.
- `fastdds-profiles.xml` — Fast DDS loopback-only profile.
- `captures/leg1-keeplast-connext.pcap` — lo0 capture, proc 1+2 → Connext late sub.
- `captures/leg2-keeplast-fastdds.pcap` — lo0 capture, proc 1+2 → Fast DDS late sub.
- `spike/` — prior wire investigation (PID_KEY_HASH presence on matched pub-sub).
