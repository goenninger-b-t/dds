# large-data — Connext LargeData pub/sub (DATA_FRAG oracle)

Builds **two** binaries against one generated type (the shared `common.mk` handles
multi-app dirs via `APPS`):

```sh
make
./large_sub 0 20 &          # domain, seconds (0 = forever)
./large_pub 0 8000 15       # domain, payload octets, count (0 = forever)
```

Topic `LargeData`, type `LargeData` (`@final`; `@key long id`; unbounded
`sequence<octet> payload`) — matching this stack's `large-data`
(`src/dds-shapes/shapes.lisp`) and its `make large-pub` / `make large-sub` harness.
The payload pattern is `(i*7) mod 256`; the subscriber verifies it octet-by-octet.

## What the QoS forces (USER_QOS_PROFILES.xml)

- **UDPv4 only** (no SHMEM — two same-host Connext apps would otherwise exchange
  nothing visible on `lo0`), pinned to one interface like the shapes profiles.
- **`message_size_max = 1400`** on the builtin UDPv4 transport, so an 8000-octet
  sample cannot fit one datagram: Connext emits **DATA_FRAG** (observed: 7 fragments
  per sample, `fragmentSize=1288`, `sampleSize=8012`).
- **Asynchronous publish mode** on the default datawriter: Connext *refuses* reliable
  fragmented data on a synchronous writer
  (`COMMENDFacade_canSampleBeSent: Reliable fragmented data requires asynchronous writer`).

Observed on the RTI↔RTI loopback wire: DATA_FRAG (0x16) + plain HEARTBEAT/ACKNACK;
**no HEARTBEAT_FRAG / NACK_FRAG** (lossless loopback gives the reader no reason to
NACK_FRAG, and Connext heartbeats the fragmented sample with ordinary HEARTBEAT).

**fragmentSize decision (recorded):** Connext's observed `fragmentSize` is **1288**;
this stack's `*fragment-size*` stays **1024** (`src/dds-rtps/reliable.lisp`) and is
*not* pinned to match. Pinning is unnecessary because each RTPS writer chooses its own
fragmentSize and the reader reassembles from the wire's own `fragmentSize`/`sampleSize`
fields, so the two sides never need to agree; what must hold is that each side's emitted
datagrams fit the peer's `message_size_max` (1400), which 1024 + RTPS overhead does.

## rtiddsgen vs the unbounded sequence (recorded decision)

`rtiddsgen` 4.3.1 **silently bounds** the unbounded `sequence<octet>` at **100**
(`rti::core::bounded_sequence<uint8_t, 100L>`) — the same trap as the ShapeType
string-255 finding (ADR 0009). The Makefile therefore passes **`-unboundedSupport`**,
which maps it to a true unbounded `std::vector<uint8_t>` so 8000-octet payloads work.
Bounded vs unbounded does not change the XCDR wire payload, only the TypeObject;
name-based/structural matching absorbs that for this harness.

## Capturing the fragmented wire (no sudo needed on this box)

```sh
tcpdump -i lo0 -w largedata.pcap udp &
./large_sub 0 20 & ./large_pub 0 8000 15
tshark -r largedata.pcap --enable-protocol null --enable-protocol ip \
       --enable-protocol udp -Y "rtps.sm.id == 0x16" -V | less
```

The saved capture (git-ignored) is the byte-vector source for locking this stack's
DATA_FRAG encoder against Connext.

## Live our-stack <-> Connext captures (2026-06-10, Task 4.3 — all git-ignored, PRESERVE)

| pcap | run | contents |
|---|---|---|
| `step1b-connext-to-us.pcap` | Connext `large_pub` -> our `make large-sub` | 105 Connext DATA_FRAGs (15 samples x 7 frags, fragmentSize 1288); our ACKNACKs to writer `0x80000002`; Connext `wait_for_acknowledgments` completed |
| `step2-us-to-connext.pcap` | our `make large-pub` -> Connext `large_sub` | our 8x1024 DATA_FRAG pushes (1112-B datagrams < message_size_max 1400) + HEARTBEAT_FRAG + HEARTBEAT; Connext ACKNACKs; 25/25 `payload-len=8000 pattern=OK` |
| `step3-nackfrag.pcap` | forced loss: our pub with `DROP=3` (fragment 3 withheld) | **Connext-emitted NACK_FRAG vectors** — frames 149, 166, 170, 180, 190, 200, 212, 224, 244, 256, 268, 288 (one per writerSN 1-12, each `bitmapBase=3 numBits=1`); our exact-fragment resends (e.g. frames 152, 171, 174); 12/12 samples recovered `pattern=OK` |

Connext emitted **no HEARTBEAT_FRAG in any run** — it announces fragmented samples with a
plain HEARTBEAT and relies on the reader's NACK_FRAG; our stack's HEARTBEAT_FRAG after each
fragmented push is accepted. `step3-nackfrag.pcap` is therefore the only NACK_FRAG
byte-vector source (the lossless RTI<->RTI `largedata.pcap` contains neither submessage).
