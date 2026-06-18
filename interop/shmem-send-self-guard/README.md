# SHMEM-send self-guard — cross-DDS no-regression interop (WP-SHMEM-SEND-SELF-GUARD, FR-XPORT-2)

The per-feature interop Definition-of-Done gate (owner directive 2026-06-17: every feature verifies
interop with **both** RTI Connext **and** eProsima Fast DDS) for the SHMEM-send self-guard. The feature
(Tasks 1+2) catches a **signalled** `%shmem-send` hard fault (segment detached / pshared error / bounds)
in `%send-raw-buf` (`dds.disc`), bumps `disc-node-shmem-send-faults`, fires `*sender-emit-error-hook*`
(context `:shmem-send-fault`), and falls back to the **existing UDP send** so the datagram still delivers —
instead of the fault propagating out of the user-data send.

## HONEST framing — what this interop does and does NOT prove (minimal wire surface)

**SHMEM is same-host ours-to-ours.** A peer is sent bulk user DATA over SHMEM only when it shares this
node's `host-uuid` (same physical host) **and** advertised our vendor SHMEM `Locator_t` — i.e. it is one of
*our* participants. **A foreign peer (RTI Connext / Fast DDS) never qualifies**: it does not advertise our
SHMEM locator, so `%shmem-dest` resolves to `NIL` and every datagram to it goes over **UDP**. The self-guard
sits on the SHMEM branch of `%send-raw-buf`, which a foreign-bound datagram never enters — **the guard is
structurally inert for a foreign peer.**

Therefore this WP has **no new wire-observable cross-DDS surface**, and the cross-DDS leg is **no-regression**:

> Our publisher delivers byte-identically to a live foreign peer, **unaffected by this WP** (the SHMEM-send
> self-guard never triggers for a foreign UDP dest).

The actual **feature proof** is the **our-to-our** unit test (a same-host SHMEM pair, the fault injected, the
datagram delivered via the UDP fallback + the counter advanced + the hook fired) — `run-shmem-send-self-guard-test`,
green on **SBCL + Clasp**. A same-host SHMEM path is not a wire-interop surface, so it cannot be a cross-DDS
test; the cross-DDS leg shows no-regression of the UDP path a foreign peer uses — and, in the run recorded
under **Live results** below, that path **actually delivered**: with the self-guard compiled in, a live RTI
Connext 7.3.1 subscriber received 24 samples and a live Fast DDS 3.6.1 subscriber received 29 (the reliable
return path establishing both ways), our user DATA byte-valid + 0-malformed.

| Unit test (`src/dds-tests/integration-test.lisp`, green SBCL + Clasp) | Proves |
|---|---|
| `run-shmem-send-self-guard-test` | The feature: a same-host SHMEM pair, `*debug-shmem-send-fault*` armed → the reader STILL receives via the UDP fallback, `disc-node-shmem-send-faults` advanced (≥1), the hook fired with context `:shmem-send-fault`, and `disc-node-shmem-sends` did **not** advance (it went UDP, not SHMEM). |
| `run-shmem-send-self-guard-no-regression-test` | Injector `NIL` → a same-host pair still delivers over SHMEM (`shmem-sends` advances, counter 0, hook silent — the no-fault path takes SHMEM, **not** the fallback); **and** an all-UDP (`shmem-dest` NIL) send is byte-unaffected by the guard (this leg runs on **both** impls). |

The fault-vs-lane-full distinction (the `handler-case` fires only on a **signal**; a benign lane-full *returns*
0 and takes the silent UDP fallback with no counter/hook) is part of `run-shmem-send-self-guard-test` +
`run-shmem-send-self-guard-no-regression-test` above.

## The harness

Our side is the standard Shapes publisher `dds.shapes:run-publisher` (the canonical RTI `ShapeType` on topic
`Square`, the simplest committed interop type — the same type the `interop/connext/shapes-sub` and
`interop/fastdds/shapes` reliable subscribers expect). `*shmem-enabled*` is its default; against a foreign peer
it is moot (the peer never advertises our SHMEM locator, so the user DATA goes UDP regardless). No new
publisher knob is added by this WP — the cross-DDS surface is no-regression, so the existing
`ASYNC=t TYPE=canonical … ADVERTISE=127.0.0.1 PEERS=…` recipe is reused verbatim.

`USER_QOS_PROFILES.xml` here pins Connext **loopback-only** (`allow_interfaces=127.0.0.1`, UDPv4 only) so the
shapes_sub binds + advertises only `lo0` (sidesteps the macOS "network interfaces can change" participant-index
init failure of a stale pinned LAN interface, and the macOS app-firewall). Mirrors
`interop/keyed-flatdata/connext/USER_QOS_PROFILES.xml`. Capture-only aid; **not built or run by CI**. The Fast
DDS side uses the committed `interop/fastdds/shapes/profiles.xml` (`interfaceWhiteList` `127.0.0.1`).

**FIRST: kill any stale DDS process on the discovery ports** (`lsof -nP -iUDP | grep 74`) — a leftover binds
participant index 1 and the unicast SPDP misses index 0.

Capture with a clean `WIRESHARK_CONFIG_DIR=$(mktemp -d)` (this host's default Wireshark profile disables the
lo0 dissectors).

### Connext leg (RTI Connext 7.3.1)

The committed `interop/connext/shapes-sub/shapes_sub` (reliable `ShapeType`/`Square`), run from **this**
directory so it loads the loopback `USER_QOS_PROFILES.xml` from cwd:

```sh
export NDDSHOME=/Applications/rti_connext_dds-7.3.1
export DYLD_LIBRARY_PATH=$NDDSHOME/lib/arm64Darwin20clang12.0
WIRESHARK_CONFIG_DIR=$(mktemp -d) /Applications/Wireshark.app/Contents/MacOS/tshark \
  -i lo0 -f "udp portrange 7400-7600" -w captures/connext-noregression.pcap &
( cd interop/shmem-send-self-guard && ../connext/shapes-sub/shapes_sub 0 70 )   # domain, seconds
# then, in another shell, the publisher line below
```

### Fast DDS leg (eProsima Fast DDS 3.6.1)

The committed `interop/fastdds/shapes/shapes_sub`, run via `scripts/with-fastdds.sh`:

```sh
WIRESHARK_CONFIG_DIR=$(mktemp -d) /Applications/Wireshark.app/Contents/MacOS/tshark \
  -i lo0 -f "udp portrange 7400-7600" -w captures/fastdds-noregression.pcap &
./scripts/with-fastdds.sh bash -c 'cd interop/fastdds/shapes && ./shapes_sub 70'
# then, in another shell, the publisher line below
```

### The publisher line (both legs)

Run **directly** (not via `make`, so the SBCL recompile delay does not shift the discovery timing). `:async t`
enables the pre-publish match-wait + the bounded reliable drain (needed for the loopback reliable exchange).
`:data-representation :xcdr1` is **required for receipt** here: the committed RTI/eProsima `ShapeType` reader is
`@final` fixed-size and advertises `[XCDR1]`-only (it elides the default-valued `PID_DATA_REPRESENTATION`), so
our **default `:xcdr2` writer is a TRUE RxO incompatibility** (received 0 — the spec-mandated reject, *not* a
flake), exactly as `interop/data-representation/README.md` establishes. `:xcdr1` (`PLAIN_CDR_LE 0x0001` on the
wire) matches their reader and is the leg that actually delivers. The self-guard is identical either way (it
sits on the SHMEM branch, which a foreign UDP dest never enters):

```sh
./scripts/with-sbcl.sh --non-interactive \
  --eval '(asdf:load-system :dds-shapes)' \
  --eval '(dds.shapes::run-publisher :domain 0 :type :canonical :color "GREEN" :count 30 :rate 3 :async t \
             :history-kind :keep-all :advertise-address "127.0.0.1" :peers "127.0.0.1:7410" \
             :data-representation :xcdr1)' \
  --eval '(uiop:quit 0)'
```

## Live results (2026-06-18, this host, lo0)

**Result: NO-REGRESSION CONFIRMED AND FOREIGN-PEER RECEIPT ACHIEVED — with the self-guard compiled in, a live
RTI Connext 7.3.1 subscriber received 24 samples and a live Fast DDS 3.6.1 subscriber received 29 samples,
correctly decoded, the reliable foreign→us return path establishing both ways (ACKNACKs back to our writer).**

This **supersedes** the first attempt in this session (which reported 0 received). The 0 was substantially the
**XCDR2-vs-XCDR1 RxO incompatibility**, not (only) a loopback flake: the foreign `ShapeType` reader advertises
`[XCDR1]`-only, so our **default `:xcdr2` writer truly does not match it** — exactly the contrast
`interop/data-representation/README.md` proved (0 received on `[XCDR2]` vs 37/49 on `[XCDR1]`). Re-running the
publisher with `:data-representation :xcdr1` (`PLAIN_CDR_LE 0x0001` on the wire — the representation their
reader accepts) delivered to both peers.

### The receipt run (`:data-representation :xcdr1`, the guard compiled in)

| Leg | Peer reported receipt | Our writer's reliable return | Our user DATA on the wire (writer `0x00000102`) | Malformed (our user DATA) |
|---|---|---|---|---|
| **Connext 7.3.1** (`captures/connext-receipt.pcap`) | **`[connext-sub] received 24 sample(s).`** — `color=GREEN … size=30`, coordinates animating exactly as we emit | `ACKNACKs received=22` | `CDR_LE (0x0001)` (our offered XCDR1), all on `127.0.0.1` | **0** |
| **Fast DDS 3.6.1** (`captures/fastdds-receipt.pcap`) | **`[shapes_sub] done, received 29`** — `color=BLUE … size=30`, animating | `ACKNACKs received=25` | `CDR_LE (0x0001)`, all on `127.0.0.1` | **0** |

So with the SHMEM-send self-guard in the build, our publisher matches, the reliable handshake completes
(ACKNACKs return), and both foreign subscribers receive and correctly decode our user DATA — the guard is
**transparent** to the foreign UDP path (as it must be: a foreign peer's `%shmem-dest` is `NIL`, so the guarded
SHMEM branch is never entered for a foreign-bound datagram). **0 malformed frames on our user DATA** (writer
`0x00000102`) in either capture.

### The earlier no-regression-only captures (first attempt, default `:xcdr2`)

`captures/connext-noregression.pcap` and `captures/fastdds-noregression.pcap` are the **first-attempt** runs
(default `:xcdr2`): they prove our emitted wire bytes are byte-valid XCDR2-LE and 0-malformed, but the peers
received 0 (the `[XCDR1]`-only RxO reject above). They are retained as the **wire-no-regression** evidence for
the default representation; the `*-receipt.pcap` captures are the **delivered** runs.

| Leg | Our user DATA on the wire (writer `0x00000102`) | Malformed (our user DATA) | Decoded payload |
|---|---|---|---|
| **Connext** (`captures/connext-noregression.pcap`) | 452 `DATA` submessages, `CDR2_LE (0x0007)` (default XCDR2-LE) | **0** | `06000000 475245454e… 35000000 34000000 1e000000` = `"GREEN"` + x=53 y=52 size=30 |
| **Fast DDS** (`captures/fastdds-noregression.pcap`) | 100 `DATA` submessages, `CDR2_LE (0x0007)` | **0** | `05000000 424c5545… 35000000 34000000 1e000000` = `"BLUE"` + x=53 y=52 size=30 |

**Benign tshark artifact (not ours):** the `[Malformed Packet]` frames in the captures are **SEDP DATA(w)**
(`ENTITYID_BUILTIN_PUBLICATIONS_WRITER 0x000003c2`) carrying `PID_TYPE_INFORMATION (0x0075)` — the RTI-legacy
TypeObject sub-TLV that tshark's RTPS heuristic dissector mis-parses (the same artifact noted in
`interop/data-representation/README.md`). In `connext-receipt.pcap` all 7 malformed frames are these SEDP
TypeObject frames; our **user DATA** (writer `0x00000102`) is **0 malformed** in every capture.

### Verdict

The cross-DDS no-regression DoD is **met, and now strengthened to live foreign-peer receipt**: with the
self-guard compiled in, both RTI Connext and Fast DDS receive our reliable user DATA byte-correctly (24 / 29
samples, the reliable return path establishing), and our emitted bytes are byte-valid + 0-malformed. The
our-to-our fault→UDP-fallback unit test (`run-shmem-send-self-guard-test`, green SBCL + Clasp) remains the
actual feature proof (SHMEM is same-host ours-to-ours, not a wire-interop surface).

The Fast DDS leg also runs in the **owner's environment** (the canonical Fast DDS oracle); the harness +
captures are committed for the owner to reproduce.

## Files

- `USER_QOS_PROFILES.xml` — the Connext loopback-only profile (capture-only aid; not CI).
- `captures/connext-receipt.pcap` — the lo0 capture of the **delivered** Connext leg (`:xcdr1`): 43 `CDR_LE
  (0x0001)` user-DATA frames, our user writer `0x00000102` 0-malformed, Connext received 24; the 7 malformed
  frames are the benign SEDP `PID_TYPE_INFORMATION (0x0075)` TypeObject artifact.
- `captures/fastdds-receipt.pcap` — the lo0 capture of the **delivered** Fast DDS leg (`:xcdr1`): 42 `CDR_LE
  (0x0001)` user-DATA frames, our user writer `0x00000102` 0-malformed, Fast DDS received 29.
- `captures/connext-noregression.pcap` — the first-attempt Connext leg (default `:xcdr2`): our user DATA
  byte-valid `CDR2_LE (0x0007)` + 0 malformed, but received 0 (the `[XCDR1]`-only RxO reject). Wire-no-regression
  evidence for the default representation.
- `captures/fastdds-noregression.pcap` — the first-attempt Fast DDS leg (default `:xcdr2`): our user DATA
  byte-valid + 0 malformed, received 0 (same RxO reject); match=YES.
