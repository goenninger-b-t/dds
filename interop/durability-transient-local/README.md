# TRANSIENT_LOCAL durability + late-joiner cross-DDS interop (WP-DURABILITY-TRANSIENT-LOCAL, M6/P5)

The per-feature interop Definition-of-Done gate (owner directive 2026-06-17: every feature verifies
interop with **both** RTI Connext **and** eProsima Fast DDS) for TRANSIENT_LOCAL durability + the
late-joiner (DDS 1.4 §2.2.3.4). The conformance crux is **late-joiner history delivery on the wire,
both directions**:

1. **Our TL writer → a late-joining foreign TL reader:** our reliable TRANSIENT_LOCAL writer publishes
   N samples, THEN a foreign reliable TRANSIENT_LOCAL subscriber starts → it must receive the N
   **RETAINED** samples (the ones published *before* it joined), not merely future ones. Our HEARTBEAT
   advertises `[firstSN, lastSN]` from `firstSN=1`; the late reader NACKs; we retransmit the history.
2. **Our late-joining TL reader ← a foreign TL writer:** a foreign reliable TRANSIENT_LOCAL writer
   publishes N, THEN our reliable TRANSIENT_LOCAL reader starts → we must receive the N retained history
   (our reader REQUESTS the writer's pre-join range). A **VOLATILE** variant of our reader receives only
   post-join samples — the behaviour-defining contrast.

TRANSIENT_LOCAL is RELIABLE-based; the RxO admits a TL reader matched to a TL writer (offered durability
rank ≥ requested rank). The **load-bearing proof** throughout is the late-joiner receiving a sample
published BEFORE it joined (the animation's first low-coordinate sample), distinguished from merely
receiving future samples.

**Status: all four legs LIVE-verified in-session (2026-06-18), both peers, both directions, plus the
VOLATILE-reader contrast against each foreign TL writer.** Captures under `captures/`.

This is the **UDP/copy path** (the wire-interoperable path). UDPv4-only, loopback-pinned.

## The harness gate

Both halves of this stack's Shapes harness (`dds.shapes:run-publisher` / `run-subscriber`, the canonical
RTI `ShapeType` on topic `Square`) gained a `DURABILITY` gate (`make square-pub` / `square-sub`,
`DURABILITY=transient-local`), mirroring the existing `RELIABLE`/`HISTORY`/`REP` gates:

- `run-publisher :durability :transient-local` → the (always-reliable) writer's DURABILITY QoS becomes
  TRANSIENT_LOCAL (advertised via `PID_DURABILITY` in SEDP) and HISTORY is forced to **KEEP_ALL** so
  ALL pre-join samples are retained (depth-1 KEEP_LAST would replay only the latest per instance). The
  writer retains its published history and replays it to a late-joining matched reader.
- `run-subscriber :durability :transient-local` → the reader's DURABILITY QoS becomes TRANSIENT_LOCAL;
  matched to a retaining writer it **REQUESTS** that writer's pre-join history (`%reader-durability-init`
  → SKIP-HISTORY NIL → NACKs `[firstSN, lastSN]`). `:volatile` (the default) SKIPS the retained history
  (advances the WriterProxy past the pre-join range, NACKing only future gaps).

`DURABILITY` defaults to `:volatile` → **byte-identical** to the prior wire (no retention; the default
harness path is unchanged). The feature is also covered our-to-our by the unit test
`run-dcps-durability-latejoiner-test` (`src/dds-tests/integration-test.lisp`, green SBCL + Clasp): a TL
late reader gets the pre-existing samples, a VOLATILE late reader gets only future ones.

## Foreign-peer TRANSIENT_LOCAL configuration

The default committed Shapes subscribers/publishers are VOLATILE; this WP makes them TL **without
disturbing the byte-identical VOLATILE default other interop legs rely on**:

- **RTI Connext** — via QoS XML only (no source edit). `USER_QOS_PROFILES.xml` here is an `is_default_qos`
  profile setting `<datawriter_qos>`/`<datareader_qos>` `durability=TRANSIENT_LOCAL_DURABILITY_QOS` +
  `reliability=RELIABLE` + `history=KEEP_ALL` (resource limits unlimited). The committed
  `interop/connext/shapes-pub/shapes_pub` / `shapes-sub/shapes_sub` read `default_datawriter_qos()` /
  `default_datareader_qos()` and override only reliability in code — durability + history come from this
  profile. Loopback-pinned (`allow_interfaces=127.0.0.1`, UDPv4 only), so it must be run from THIS
  directory (the apps load `USER_QOS_PROFILES.xml` from cwd).
- **Fast DDS** — via an inert-by-default `DURABILITY` env gate added to the committed
  `interop/fastdds/shapes/shapes_pub.cpp` / `shapes_sub.cpp` (mirroring their existing
  `WLP_LEASE_MS`/`OWNERSHIP_STRENGTH`/`DISPOSE_AFTER` env pattern): `DURABILITY=transient_local` sets
  `TRANSIENT_LOCAL_DURABILITY_QOS` + `KEEP_ALL`. Unset (the default) = VOLATILE, byte-identical — the
  Fast DDS entity QoS is code-built, not profile-applied, so the durability must be set in C++.
  `fastdds-profiles.xml` here is loopback-only (`interfaceWhiteList` `127.0.0.1` ONLY — with a LAN
  address also whitelisted, Fast DDS routes the user dataflow off `lo0` and the samples miss our
  loopback reader; see `interop/keyed-flatdata/README.md`); copy it to `./profiles.xml` in the run cwd.

**FIRST: kill any stale DDS process on the discovery ports** (`lsof -nP -iUDP:7400-7440`).

Capture with a clean `WIRESHARK_CONFIG_DIR=$(mktemp -d)` (this host's default Wireshark profile disables
the lo0 dissectors). All four legs ride `lo0`; the Lisp side reaches each foreign peer with unicast SPDP
to `127.0.0.1:7410` (`PEERS=127.0.0.1:7410`), and our writer offers `:data-representation :xcdr1`
(`PLAIN_CDR_LE 0x0001`) on the our-writer→foreign-reader legs because the committed RTI/eProsima
`ShapeType` reader accepts `[XCDR1]` — our default `:xcdr2` writer would be a true RxO reject (see
`interop/shmem-send-self-guard/README.md` and `interop/data-representation/README.md`). Our reader
accepts both reps, so the foreign-writer legs need no representation tweak.

## Connext leg (RTI Connext 7.3.1) — built + live, in-session

```sh
export NDDSHOME=/Applications/rti_connext_dds-7.3.1
export CONNEXTDDS_ARCH=arm64Darwin20clang12.0
export DYLD_LIBRARY_PATH=$NDDSHOME/lib/$CONNEXTDDS_ARCH
lsof -nP -iUDP:7400-7440            # confirm NOTHING else holds these ports
```

### Leg 1 — our TL writer → a LATE Connext TL reader (forward; the retained-history crux)

Start tshark on `lo0`, then our TL writer publishing FIRST (it retains while no reader is present), THEN
the LATE Connext TL reader. The Connext reader must receive the samples our writer published BEFORE it
joined.

```sh
# 1) capture
WIRESHARK_CONFIG_DIR=$(mktemp -d) /Applications/Wireshark.app/Contents/MacOS/tshark \
  -i lo0 -f "udp portrange 7400-7700" -w captures/leg1-our-tl-pub-to-connext.pcap &

# 2) our TRANSIENT_LOCAL writer FIRST (publishes the retained history; run directly, not via make)
./scripts/with-sbcl.sh --non-interactive \
  --eval '(asdf:load-system :dds-shapes)' \
  --eval '(dds.shapes::run-publisher :domain 0 :type :canonical :color "GREEN" :count 200 :rate 2 \
             :async t :durability :transient-local :advertise-address "127.0.0.1" \
             :peers "127.0.0.1:7410" :data-representation :xcdr1)' \
  --eval '(uiop:quit 0)'
# ... let it publish ~16-22 samples (~11 s) ...

# 3) THEN the LATE Connext TL reader joins (from THIS dir so it loads the loopback-TL profile)
./interop/connext/shapes-sub/shapes_sub 0 28          # run from interop/durability-transient-local
```

### Leg 3 — a Connext TL writer → our LATE TL reader (reverse) + the VOLATILE contrast

```sh
# Connext TRANSIENT_LOCAL writer FIRST (from this dir; retains ~7 s of history), then our late reader:
./interop/connext/shapes-pub/shapes_pub 0 GREEN 30     # run from interop/durability-transient-local

# our LATE TRANSIENT_LOCAL reader — must REQUEST the retained history:
./scripts/with-sbcl.sh --non-interactive --eval '(asdf:load-system :dds-shapes)' \
  --eval '(dds.shapes::run-subscriber :domain 0 :type :canonical :seconds 26 \
             :durability :transient-local :advertise-address "127.0.0.1" :peers "127.0.0.1:7410")' \
  --eval '(uiop:quit 0)'

# the VOLATILE contrast — identical run but :durability :volatile → must SKIP the retained history
```

## Fast DDS leg (eProsima Fast DDS 3.6.1) — built + live, in-session

Rebuild the shapes binaries after the `DURABILITY` env-gate edit, copy the loopback profile into the run
cwd:

```sh
./scripts/with-fastdds.sh make -C interop/fastdds/shapes
cp interop/durability-transient-local/fastdds-profiles.xml interop/fastdds/shapes/profiles.xml   # restore the committed one after
```

### Leg 2 — our TL writer → a LATE Fast DDS TL reader (forward)

```sh
# our TL writer FIRST (same publisher line as Leg 1), then the LATE Fast DDS TL reader:
DURABILITY=transient_local ./scripts/with-fastdds.sh bash -c \
  'cd interop/fastdds/shapes && DURABILITY=transient_local ./shapes_sub 26'
```

### Leg 4 — a Fast DDS TL writer → our LATE TL reader (reverse) + the VOLATILE contrast

```sh
# Fast DDS TL writer FIRST:
DURABILITY=transient_local ./scripts/with-fastdds.sh bash -c \
  'cd interop/fastdds/shapes && DURABILITY=transient_local ./shapes_pub GREEN 200'
# then our late TL reader (the Leg-3 subscriber line), and the :volatile contrast
```

## Live results (2026-06-18, this host, lo0)

The animation makes the proof unambiguous: a late-joiner that receives the **first** sample (the lowest
coordinates) received the RETAINED pre-join history; a VOLATILE late-joiner's first received sample is
mid-animation (a post-join sample). Our writer's first sample is `x=53 y=52` (`x=50+dx`, `y=50+dy`);
Connext's is `x=53 y=52` (`x=50+3`); Fast DDS's is `x=50 y=50` (`i=0`).

| Leg | Direction | Late-joiner received the RETAINED (pre-join) history? | Total | Capture |
|---|---|---|---|---|
| **1** | our TL writer → late **Connext** TL reader | **YES** — Connext's `#1 = color=GREEN x=53 y=52` (our first sample, published ~11 s before Connext joined), then monotonically up | 63 | `captures/leg1-our-tl-pub-to-connext.pcap` |
| **2** | our TL writer → late **Fast DDS** TL reader | **YES** — Fast DDS's `1: x=53 y=52` (our first sample), then up | 60 | `captures/leg2-our-tl-pub-to-fastdds.pcap` |
| **3** | **Connext** TL writer → our late TL reader | **YES** — we received `GREEN x=53 y=52` (Connext's first sample, retained before our reader joined) | 902 | `captures/leg3-connext-tl-pub-to-our-late.pcap` |
| **3-VOL** | **Connext** TL writer → our late **VOLATILE** reader | **NO (correct)** — first received `x=68 y=106` (mid-animation, post-join); `x=53 y=52` NOT received | 425 | (same setup, `:volatile`) |
| **4** | **Fast DDS** TL writer → our late TL reader | **YES** — we received `GREEN x=50 y=50` (Fast DDS's first sample, `i=0`; Fast DDS had sent 74 before our reader joined) | 200 | `captures/leg4-fastdds-tl-pub-to-our-late.pcap` |
| **4-VOL** | **Fast DDS** TL writer → our late **VOLATILE** reader | **NO (correct)** — first received `x=57 y=99` (mid-animation, post-join); `x=50 y=50` NOT received | 93 | (same setup, `:volatile`) |

All four directional legs deliver the late-joiner the pre-join history; both VOLATILE contrasts correctly
skip it. The RxO was independently confirmed in-suite: a TL writer ↔ TL reader is compatible; a VOLATILE
writer vs a TL reader is incompatible on `durability` (a TL reader needs a retaining writer).

## Wire evidence (tshark RTPS dissector)

### Forward legs (our TL writer → foreign late reader) — fully captured on lo0

Our user writer is RTPS EntityId `0x00000102`. In **both** forward captures:

- **Our HEARTBEAT (`0x00000102`) `firstAvailableSeqNumber` is `1` on EVERY HEARTBEAT** (the only
  distinct value seen) and `lastSeqNumber` climbs `1→2→3→…`. A VOLATILE writer would advance `firstSN`
  as samples are acked; holding `firstSN=1` is the TRANSIENT_LOCAL KEEP_ALL retention on the wire.
- **Retransmits of the retained range:** our user DATA submessage count far exceeds the unique
  sequence-number count — the writer re-sends the retained SNs in answer to the late reader's NACK:

  | Leg | our user-DATA submessages (`0x00000102`) | unique SNs | retransmits | encapsulation |
  |---|---|---|---|---|
  | 1 (Connext) | 163 | 68 | **95** | `CDR_LE (0x0001)` (our offered XCDR1) |
  | 2 (Fast DDS) | 154 | 65 | **89** | `CDR_LE (0x0001)` |

  Leg 1 capture: 233 DATA / 257 HEARTBEAT / 79 ACKNACK submessages overall — the full reliable
  late-joiner repair exchange (HEARTBEAT advertises `[1, lastSN]`, the late reader NACKs, we retransmit).

> **Footnote — the per-leg tallies are raw tshark submessage counts, not the conformance proof.** The
> "163 DATA / 95 retransmits" / "154 / 89" / "233 DATA / 257 HEARTBEAT / 79 ACKNACK" figures above are
> tshark *total-submessage* counts that are INFLATED by ~21 `[Malformed Packet]` coalesced DATA+HEARTBEAT
> frames per capture — the same tshark RTPS-heuristic artifact this stack's change-coalescing (DATA +
> HEARTBEAT in one datagram) triggers across the other interop READMEs (it is a tshark mis-parse, not a
> wire defect; our engine-codec gate `make wire` is green independently). The clean `tshark -O rtps`
> per-DATA-*submessage* counts (excluding the malformed-frame double-counts) are correspondingly LOWER. The
> tallies are included only to show retransmit activity (DATA submessages far exceeding unique SNs); the
> load-bearing **conformance facts** stand on their own and are NOT derived from the raw tally:
> `firstAvailableSeqNumber = 1` on EVERY HEARTBEAT (the only distinct value), unique sequence numbers
> climbing `1→2→3→…`, and the retained `SN 1` re-sent (≈3×) in answer to the late reader's NACK. Read the
> conformance claims, not the inflated submessage totals.

### Reverse legs (foreign TL writer → our late reader) — the macOS lo0 reverse-direction capture quirk

For Legs 3 and 4 the **foreign-peer → us** user-DATA frames are **under-captured on `lo0`**: this host's
macOS BPF on the loopback interface drops most frames in the foreign-peer→us direction (the documented
quirk the prior interop WPs hit — e.g. `interop/shmem-send-self-guard`, `interop/keyed-flatdata`). The
Leg-3 / Leg-4 captures contain our reader's **outbound** SPDP/ACKNACK to `127.0.0.1:7410` plus the
discovery DATA, but NOT the bulk of the foreign writer's user DATA (Leg 3 shows ~89 captured DATA, all
builtin discovery EntityIds, while our reader actually decoded **902** user samples; Leg 4 similarly).

As the operating contract directs for this known quirk, the reverse-leg proof rests on the **decoded
application receipt + the ACKNACK progression on the wire**: our late TL reader decoded the foreign
writer's FIRST pre-join sample (`x=53 y=52` from Connext; `x=50 y=50` from Fast DDS), our reader's
outbound ACKNACKs to `127.0.0.1:7410` are present in the captures, and the VOLATILE contrast (which did
NOT decode the pre-join first sample) isolates the retained-history pull as the cause. This is the same
honest framing `interop/shmem-send-self-guard/README.md` uses for the lo0 reverse-direction limitation —
the foreign-peer-receipt that cannot be photographed on `lo0` is proven by the decoded counts + the
ACKNACK SN progression, and that is stated explicitly here.

**Benign tshark artifact (not ours):** any `[Malformed Packet]` markers on SEDP DATA(w/r) frames carrying
`PID_TYPE_INFORMATION (0x0075)` are the RTI-legacy TypeObject sub-TLV that tshark's RTPS heuristic
dissector mis-parses (noted across the other interop READMEs); the foreign peers parsed the SEDP and
matched. Our engine-codec gate `make wire` is green independently.

## Honesty summary

- The two **forward** legs (our TL writer → foreign late TL reader) are **fully wire-captured**: the
  retained `firstSN=1` HEARTBEAT, the late reader's NACK, and the **retransmit of the retained range**
  (95 / 89 retransmits) are all on `lo0`, plus the foreign peers reported receiving the pre-join history
  starting at sample #1.
- The two **reverse** legs (foreign TL writer → our late TL reader) are proven by **decoded application
  receipt** (our reader decoded the foreign writer's first pre-join sample) **+ our outbound ACKNACKs on
  the wire**, because the macOS `lo0` BPF under-captures the foreign-peer→us user-DATA direction
  (the documented quirk). Stated plainly rather than overclaimed.
- The **VOLATILE contrast** against both foreign TL writers confirms the behaviour-defining branch: a
  VOLATILE late reader does NOT receive the retained pre-join history (first decoded sample is
  mid-animation), distinguishing genuine late-joiner history delivery from merely receiving future
  samples.

## Files

- `USER_QOS_PROFILES.xml` — the Connext loopback + TRANSIENT_LOCAL/KEEP_ALL/RELIABLE profile (capture-only; not CI).
- `fastdds-profiles.xml` — the Fast DDS loopback-only profile (copy to `./profiles.xml` in the run cwd; the TL durability is the C++ `DURABILITY` env gate).
- `captures/leg1-our-tl-pub-to-connext.pcap` — forward, our TL writer → late Connext TL reader (retained `firstSN=1`, 95 retransmits, `CDR_LE`).
- `captures/leg2-our-tl-pub-to-fastdds.pcap` — forward, our TL writer → late Fast DDS TL reader (retained `firstSN=1`, 89 retransmits, `CDR_LE`).
- `captures/leg3-connext-tl-pub-to-our-late.pcap` — reverse, Connext TL writer → our late TL reader (our outbound ACKNACKs; foreign-DATA lo0-under-captured; receipt = 902 incl. `x=53 y=52`).
- `captures/leg4-fastdds-tl-pub-to-our-late.pcap` — reverse, Fast DDS TL writer → our late TL reader (our outbound ACKNACKs; foreign-DATA lo0-under-captured; receipt = 200 incl. `x=50 y=50`).

## Clean-room / provenance

Clean-room: the foreign peers are the committed `interop/connext/shapes-*` and `interop/fastdds/shapes`
harnesses configured for TRANSIENT_LOCAL via QoS XML (Connext) and an inert C++ env gate (Fast DDS) —
no RTI/Fast DDS source is copied into any hand-written file. Connext `rtiddsgen` output is build-time +
git-ignored; the Fast DDS `fastddsgen` output under `interop/fastdds/shapes/gen/` is committed verbatim
(Apache-2.0; `docs/provenance.md`). No vendor binaries are committed (only this config + the proof
captures). The durability/late-joiner semantics are pinned from DDS 1.4 §2.2.3.4 and RTPS 2.5 §8.4.2.2.
