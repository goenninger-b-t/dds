# PERSISTENT durability service — cross-DDS transparency AFTER A PROCESS RESTART (WP-DURABILITY-PERSISTENT, M6/P5)

The per-feature interop Definition-of-Done gate (owner directive 2026-06-17: every feature verifies
interop with **both** RTI Connext **and** eProsima Fast DDS) for the **PERSISTENT** durability tier
(ADR 0021 capability 1 + 7): a disk-backed, **DARE-at-rest-encrypted** durable store that, after a
genuine **process restart**, reloads + decrypts its retained history and replays it to a LIVE foreign
TRANSIENT_LOCAL late-joiner — **byte-correct**.

This extends the transparency claim of `interop/durability-dare/` across a **2-process boundary**: the
samples are not just sealed at rest, they are sealed to disk, the holding process exits, a fresh process
re-opens the same on-disk store + keypair, decrypts, and the foreign late-joiner receives the same bytes.

**Status: both legs LIVE-verified in-session (2026-06-20), both peers.** Captures under `captures/`.

| Leg | Peer | Collected + sealed to disk (proc 1) | Reloaded + decrypted (proc 2) | Late-joiner received after restart | First sample received | Capture |
|---|---|---|---|---|---|---|
| **1** | **Connext** | 458 | **458** | **458** | `#1 x=53 y=52` (publisher's animation origin; publisher dead + proc 1 exited) | `captures/leg1-restart-connext.pcap` |
| **2** | **Fast DDS** | 186 | **186** | **186** | `#1 x=50 y=50` (publisher's animation origin; service collected from sample 1) | `captures/leg2-restart-fastdds.pcap` |

Both late-joiners received the full retained history **from a process that was started AFTER the data was
sealed to disk and the collecting process had exited** — data that existed only as **AES-256-GCM
ciphertext on disk** between the two processes. Nothing on the wire differed from the plain-store
transient run (same replay-writer EntityId, same `firstSN=1` retention signal, same `CDR_LE`).

## The restart scenario (the new bit vs `durability-dare`)

The store is the PERSISTENT composition produced by
`(dds.durability:make-persistent-store-factory :dir D :key-dir K)` — it composes **file-store**
(append-only per-topic logs + `topics.map`) ⊕ **encrypted-store** (epoch-aware DARE: per-epoch
HKDF-SHA384 DEK + AES-256-GCM, 96-bit counter nonce, `epochs.dat`) ⊕ **file-key-provider**
(ML-KEM-1024 keypair in K). The proof is a genuine **2-PROCESS** restart sharing the disk dirs `D` + `K`:

1. **Process 1 (SBCL, `driver-collect.lisp`):** start a PERSISTENT service on `D` + `K` with the same two
   `:qos-overrides` the transient runbook uses (`:data-representation (:xcdr1)` +
   `:peers (("127.0.0.1" . 7410))`). A foreign (Connext, then Fast DDS) TRANSIENT_LOCAL publisher writes
   N samples on `Square`/`ShapeType`; the service's collecting reader matches it, and **seals each sample
   to disk** (the on-disk topic log grows as ciphertext; `epochs.dat` is minted on the first put). Then
   `service-stop` → `store-close` → **fsync** the sealed log + `epochs.dat` to `D`, and the process
   **EXITS**.
2. **Process 2 (SBCL, fresh process, `driver-serve.lisp`):** start a NEW PERSISTENT service on the SAME
   `D` + `K`. `service-start` → `store-open` re-derives the prior epoch DEKs from `epochs.dat` (via the
   ML-KEM-1024 private key in `K`), **decrypts + replays the sealed records**, and
   `%seed-relay-from-store` seeds the replay writer's TRANSIENT_LOCAL/KEEP_ALL history. A foreign
   **LATE-JOINING** TL subscriber that starts AFTER process 2 is up must receive the retained N samples
   byte-correct — proving cross-PROCESS persistence + cross-DDS wire transparency of the DARE-at-rest
   store.

This is distinct from `interop/durability-dare/` (single-process, in-memory store wrapped in DARE):
here the data crosses a real process boundary as **ciphertext on disk**.

## DARE-at-rest verification (the held copy is sealed)

Inspected directly on the persisted `D` after process 1 exited, before process 2 started:

- The per-topic log `D/topics/537175617265.log` (`537175617265` = hex ASCII `"Square"`) contains **no
  plaintext** `GREEN` color string and **no** plaintext ShapeType coordinates — only an append-frame
  header (`da01 0001 …`) followed by ciphertext.
- A 4 KB sample of the log body exhibits all **256 distinct byte values** (maximal entropy, consistent
  with AES-256-GCM output).
- `D/epochs.dat` (1580 B) holds the sealed epoch-DEK envelope; the ML-KEM-1024 private key
  `K/ml-kem-1024.key` (3168 B) is enforced `0600`, the public key `K/ml-kem-1024.pub` is 1568 B.

Process 2 then reported `SVC2-RELOADED-FROM-DISK Square=N (decrypted on reopen)` for each leg — proving
the on-disk ciphertext was successfully re-keyed and decrypted by a **fresh** process.

## The drivers (2 processes, shared disk dirs)

`make-service-spec` takes a `:store` slot — a 0-arg factory. For PERSISTENT it is
`make-persistent-store-factory` (`src/dds-durability/spec.lisp`). Two committed driver forms:

- **`driver-collect.lisp`** (process 1): start → collect for `DPERSIST_SECS` → print `SVC1-COLLECTED
  Square=N` → `service-stop` (fsync) → `uiop:quit`.
- **`driver-serve.lisp`** (process 2): start (reload+decrypt) → print `SVC2-RELOADED-FROM-DISK Square=N`
  → serve for `DPERSIST_SECS` → `service-stop` → `uiop:quit`.

Both read env vars `DPERSIST_DIR` (= D), `DPERSIST_KEYDIR` (= K), `DPERSIST_SECS`, and both build the
spec with the SAME store factory + the two `:qos-overrides`:

- `:data-representation (:xcdr1)` — the replay writer advertises `[XCDR1]` in SEDP so Connext/Fast DDS
  XCDR1-only `ShapeType` readers match (without it the SEDP RxO fails: offered `[XCDR2]` vs required
  `[XCDR1]`). The forwarded/retained payload bytes are opaque (collected as-is from the original writer).
- `:peers (("127.0.0.1" . 7410))` — unicast SPDP peer: the domain-0 participant-0 well-known SPDP unicast
  port (RTPS 2.5 §9.6.1.1: PB+DG×0+d1+PG×0 = 7400+10 = 7410). The collect loop also re-announces SPDP +
  SEDP every ~1.5 s so foreign participants that start after the service can discover it.

Everything else (the foreign QoS profiles, ports, kill-stale-procs-first, the publish window, the
late-joiner) is **identical** to the `interop/durability-transient/` and `interop/durability-dare/`
runbooks. Read `interop/durability-transient/README.md` for the full annotated rationale.

## Foreign-peer configuration

Copied verbatim from `interop/durability-dare/` so this harness is self-contained:

- `USER_QOS_PROFILES.xml` — Connext loopback (`allow_interfaces=127.0.0.1`, UDPv4) + TRANSIENT_LOCAL /
  RELIABLE / KEEP_ALL / unlimited resource-limits on writer & reader QoS. Run the Connext binaries from
  THIS directory so they load it from cwd.
- `fastdds-profiles.xml` — Fast DDS loopback-only (`interfaceWhiteList=127.0.0.1`, UDPv4). Copy to
  `interop/fastdds/shapes/profiles.xml` (byte-identical to the already-committed copy there); the
  `DURABILITY=transient_local` env gate in `shapes_pub.cpp`/`shapes_sub.cpp` sets the TL+KEEP_ALL QoS.

**FIRST: kill any stale DDS process on the discovery ports** (`lsof -nP -iUDP:7400-7440`).

## Run commands

```sh
export NDDSHOME=/Applications/rti_connext_dds-7.3.1
export CONNEXTDDS_ARCH=arm64Darwin20clang12.0
export DYLD_LIBRARY_PATH=$NDDSHOME/lib/$CONNEXTDDS_ARCH
# from repo root; D and K are shared between the two processes
```

### Leg 1 — Connext TL pub → seal to disk → proc 1 EXITS → restart (proc 2) → late Connext TL sub

```sh
rm -rf /tmp/dpersist-D /tmp/dpersist-K          # fresh keypair + store for this leg

# 1) Capture (the process-2 replay direction)
WIRESHARK_CONFIG_DIR=$(mktemp -d) /Applications/Wireshark.app/Contents/MacOS/tshark \
  -i lo0 -f "udp portrange 7400-7700" \
  -w interop/durability-persistent/captures/leg1-restart-connext.pcap &

# 2) PROCESS 1 — collect + seal to disk + exit (DPERSIST_SECS must outlast the publisher)
DPERSIST_DIR=/tmp/dpersist-D DPERSIST_KEYDIR=/tmp/dpersist-K DPERSIST_SECS=40 \
  ./scripts/with-sbcl.sh --load interop/durability-persistent/driver-collect.lisp
# (wait for "SVC1-STARTED", then start the publisher)

# 3) Connext TL publisher (from this dir for the TL+loopback profile; ~25 s then kill)
cd interop/durability-persistent
stdbuf -oL ../connext/shapes-pub/shapes_pub 0 GREEN &
PUB=$!; sleep 25; kill $PUB
# proc 1 then auto-stops at DPERSIST_SECS: "SVC1-COLLECTED Square=N", "SVC1-STOPPED-AND-PERSISTED", exit

# 4) PROCESS 2 — fresh process: reload + decrypt + serve
DPERSIST_DIR=/tmp/dpersist-D DPERSIST_KEYDIR=/tmp/dpersist-K DPERSIST_SECS=60 \
  ./scripts/with-sbcl.sh --load interop/durability-persistent/driver-serve.lisp
# prints "SVC2-RELOADED-FROM-DISK Square=N (decrypted on reopen)", "SVC2-STARTED"

# 5) LATE-JOINING Connext TL subscriber (starts AFTER proc 2 is up)
stdbuf -oL ../connext/shapes-sub/shapes_sub 0 25
```

### Leg 2 — Fast DDS TL pub → seal to disk → proc 1 EXITS → restart (proc 2) → late Fast DDS TL sub

```sh
rm -rf /tmp/dpersist-D /tmp/dpersist-K          # fresh keypair + store for this leg
cp interop/durability-persistent/fastdds-profiles.xml interop/fastdds/shapes/profiles.xml

# Capture + PROCESS 1 (driver-collect, DPERSIST_SECS=40) as in Leg 1, then:
DURABILITY=transient_local ./scripts/with-fastdds.sh bash -c \
  'cd interop/fastdds/shapes && stdbuf -oL ./shapes_pub GREEN 200'   # ~20 s, 200 samples

# PROCESS 2 (driver-serve, DPERSIST_SECS=60), then the LATE Fast DDS TL subscriber:
DURABILITY=transient_local ./scripts/with-fastdds.sh bash -c \
  'cd interop/fastdds/shapes && stdbuf -oL ./shapes_sub 25'
```

## Live results (2026-06-20, this host, lo0)

See the table at the top. Per-leg notes:

**Leg 1 (Connext):** process 1 collected and sealed **458** samples to disk; process 2 (a fresh SBCL)
reported `SVC2-RELOADED-FROM-DISK Square=458 (decrypted on reopen)`; the late-joining Connext TL
subscriber received exactly **458** in its 25 s window, `received 458 sample(s)`, running continuously
from the publisher's animation origin `x=53 y=52` (= start `50+3, 50+2`) to `x=20 y=54`. The original
publisher had exited and process 1 had exited before the subscriber started — the subscriber could only
have obtained these from process 2's decrypted-on-reload store.

**Leg 2 (Fast DDS):** process 1 collected and sealed **186** samples (the service's collecting reader
matched the Fast DDS writer a few hundred ms into the 200-sample run; the first ~14 publisher samples
preceded the SEDP match and were not collected — the service can only persist what it collected).
Process 2 reported `SVC2-RELOADED-FROM-DISK Square=186 (decrypted on reopen)`; the late Fast DDS TL
subscriber received exactly **186** (`done, received 186`), `#1 x=50 y=50` (the publisher's origin)
through `#186 x=135 y=145`. Byte-correct after a cross-process decrypt.

## Wire evidence (replay direction)

The service's replay writer is RTPS EntityId `0x00000102`. The wire surface is **identical** to the
plain-store transient and the in-memory-DARE cases — the proof that PERSISTENT + DARE are at-rest-only
and add zero wire-observable surface. (Submessage figures are parsed directly from the captured RTPS
bytes; see the tshark note below.)

### Leg 1 (`leg1-restart-connext.pcap`, 787 frames)

- **`firstSN = 1` on ALL 520 HEARTBEATs** from `0x00000102`; `lastSN` climbs to **458**. `firstSN` never
  advances — the TRANSIENT_LOCAL KEEP_ALL retention signal (a VOLATILE writer would advance it).
- **`CDR_LE (0x0001)` on all 916 DATA** from `0x00000102` (payload prefix `00 01 00 00 …` = CDR_LE
  encapsulation + options), confirming the `:data-representation (:xcdr1)` override is active and DARE +
  disk persistence introduce no representation change.
- Submessage totals: 1062 DATA / 546 HEARTBEAT / 83 ACKNACK / 36 GAP — the full reliable late-joiner
  repair exchange.

### Leg 2 (`leg2-restart-fastdds.pcap`, 744 frames)

- **`firstSN = 1` on ALL 445 HEARTBEATs** from `0x00000102`; `lastSN` reaches **186** (= the
  collected/delivered count).
- **`CDR_LE (0x0001)` on all 558 DATA** from `0x00000102`.
- Submessage totals: 753 DATA / 480 HEARTBEAT / 92 ACKNACK / 26 GAP / 26 INFO_DST_VENDOR (Fast DDS
  vendor submessage 0x80).

Both captures match the `interop/durability-transient/` and `interop/durability-dare/` evidence (same
EntityId, `firstSN=1` held forever, `CDR_LE`, NACK→retransmit repair). **The DARE-at-rest, disk-backed
PERSISTENT store is transparent on the wire, even across a process restart.**

## tshark / macOS lo0 capture note

The captures are valid loopback pcapng (DLT_NULL / "NULL/Loopback"); `tcpdump -r` reads every frame
correctly (e.g. `127.0.0.1.58256 > 127.0.0.1.7410: UDP` carrying the `RTPS` magic + version `0205`).
The Wireshark **tshark 4.6.6** on this host does not dissect DLT_NULL loopback captures (it stops at the
frame layer — `frame.protocols` empty — the documented macOS lo0 BPF/DLT quirk also noted in
`interop/durability-transient/README.md`). The RTPS submessage figures above were therefore parsed
**directly from the captured packet bytes** (strip the 4-byte DLT_NULL address-family header → raw IPv4
→ UDP → RTPS submessage walk), which is more precise than relying on the dissector. The committed
`.pcap` files are the raw captures; reproduce the parse with `tcpdump -r <pcap> -nn` plus a submessage
walk over the RTPS payloads.

The load-bearing collection proof is, as in the transient runbook, the **decoded receipt** at the
late-joining subscriber (the `received N` lines above) together with the replay writer's HEARTBEAT
`lastSeqNumber` matching that count — not the foreign→service capture direction, which is under-captured
on lo0.

## Authoritative in-process proof (cross-reference)

The authoritative cross-restart proof is the in-process unit test
`dds.tests:run-durability-persistent-service-test` (`src/dds-tests/durability-test.lisp`; suite key
`"durability-persistent-service"`). It writes N TL samples, `service-stop`s (sealing to a temp disk
store), then starts a **fresh** service on the same dirs (simulating restart) and asserts a same-stack TL
late-joiner receives all N **byte-exact** (`:persistent-svc-payload-exact` checks every payload
`equalp` its original — N zero-bufs or duplicates fail). It **passes on SBCL and Clasp** (Clasp
validated first per the operating contract); re-run on SBCL during this interop session:
`PERSISTENT-RESTART-TEST-RESULT: T`. This live cross-DDS harness adds the foreign-peer (Connext +
Fast DDS) confirmation on top of that in-process proof.

Per the design spec §8, this cross-DDS check is "light by nature": DARE + disk persistence add **no
wire surface**; the cryptographic substance is the published NIST/IETF Known-Answer Tests in the
`dds-dare` suite (FIPS-180-4 SHA-384, RFC-5869 HKDF, NIST SP800-38D GCM TC16, C2SP/CCTV ML-KEM-1024 —
never self-generated), plus the in-process restart test above.

## Clean-room / provenance

Clean-room: the foreign peers are the committed `interop/connext/shapes-*` and `interop/fastdds/shapes`
harnesses configured for TRANSIENT_LOCAL via QoS XML (Connext) and the C++ `DURABILITY` env gate
(Fast DDS). No RTI / Fast DDS source is copied. Connext `rtiddsgen` output is build-time + git-ignored;
Fast DDS `fastddsgen` output under `interop/fastdds/shapes/gen/` is committed verbatim (Apache-2.0;
`docs/provenance.md`). The PERSISTENT/DARE design is pinned from CNSA-2.0 + the cited FIPS/NIST/IETF
standards (ADR 0021 cap. 1+7, ADR 0025); the durability/late-joiner service semantics from DDS 1.4
§2.2.3.4 and RTPS 2.5 §8.4.2.2.

## Files

- `driver-collect.lisp` — process 1: start PERSISTENT service, collect + seal to disk, stop (fsync), exit.
- `driver-serve.lisp` — process 2: fresh process, reload + decrypt from disk, serve the late-joiner.
- `USER_QOS_PROFILES.xml` — Connext loopback + TRANSIENT_LOCAL/KEEP_ALL/RELIABLE profile.
- `fastdds-profiles.xml` — Fast DDS loopback-only profile (copy to `interop/fastdds/shapes/profiles.xml`).
- `captures/leg1-restart-connext.pcap` — proc 2 (post-restart) → late Connext TL reader; `firstSN=1`, CDR_LE, NACK→retransmit.
- `captures/leg2-restart-fastdds.pcap` — proc 2 (post-restart) → late Fast DDS TL reader; `firstSN=1`, CDR_LE, NACK→retransmit.
