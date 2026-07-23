# Shapes interop harness — Square / ShapeType

A standalone publisher and subscriber for the OMG **Shapes** demo type, built on
the participant data plane (`dds-disc`) and the generated-type codec (`dds-gen`).
It discovers peers over **multicast SPDP**, matches the `Square` topic over SEDP,
and exchanges `ShapeType` samples **reliably**. It is meant to interoperate with
RTI **`rtishapesdemo`**, eProsima Fast DDS `ShapesDemo`, or Eclipse Cyclone — and
it doubles as a cross-process self-test.

## The type

Two payload types, selected with `TYPE=canonical|tagged` (topic `Square` for both):

```idl
// TYPE=canonical — the EXACT RTI ShapeType (interop with rtishapesdemo / DDSSpy)
struct ShapeType {            // @final
  @key string<128> color;     // "BLUE", "RED", ...
  long x; long y; long shapesize;
};

// TYPE=tagged (default) — same + stream id / ordering (harness<->harness only)
struct TaggedShape {          // @final
  @key string<128> color; long x; long y; long shapesize;
  string uuid;                // per-PUBLISHER identity (RFC-4122 v4), constant per stream
  unsigned long seq;          // per-SAMPLE counter 1,2,3,... (ordering / loss detection)
};
```

In `tagged` mode each publisher mints one `uuid` at startup and stamps every sample
with that uuid + an incrementing `seq`; the subscriber prints both and flags any
per-uuid gap (`[sub] GAP from <uuid>: expected seq N, got M`). The two trailing
fields **diverge from RTI's canonical `ShapeType`**, so a stock `rtishapesdemo`
reader rejects them — use `TYPE=canonical` for RTI interop (no source edit needed).

Because both are `@final` with only 32-bit + string members, their XCDR1
(`PLAIN_CDR`) and XCDR2 (`PLAIN_CDR2`) byte layouts are identical; the subscriber
accepts CDR_LE/BE and CDR2_LE/BE.

## Run it

Two terminals, same machine (loopback — the default):

```bash
make square-sub SECONDS=0        # terminal 1: prints received Squares until Ctrl-C
make square-pub                  # terminal 2: publishes an animated BLUE Square
# overrides:  make square-pub DOMAIN=2 COLOR=RED ADVERTISE=192.168.2.148
```

`square-sub` runs for `SECONDS` (default **20**) and then exits; pass `SECONDS=0` to watch until
Ctrl-C, as above. The bound matters when scripting a capture: a backgrounded subscriber that ran
forever would outlive its capture and hold the DDS sockets, hanging the next run.

**Type toggle (`TYPE=canonical|tagged`, default `tagged`).** `tagged` carries the
extra `uuid`/`seq` (harness↔harness). `canonical` publishes the **exact** RTI
`ShapeType` (color/x/y/shapesize only) — use it for interop with `rtishapesdemo` /
DDSSpy:

```bash
make square-pub TYPE=canonical ADVERTISE=<your-LAN-ip>   # RTI-compatible payload
make square-sub TYPE=canonical                           # to read RTI's Squares
```
The publisher and subscriber must use the **same** `TYPE` to talk to each other.

Both run until Ctrl-C. Verified cross-process result: a 200-sample run delivers
**200/200** shapes reliably (no loss) between two separate processes.

Direct invocation (e.g. bounded for scripting):

```bash
./scripts/with-sbcl.sh \
  --eval '(asdf:load-system :dds-shapes)' \
  --eval '(dds.shapes:run-publisher :domain 0 :color "GREEN" :rate 25 :count 200)' \
  --eval '(uiop:quit 0)'
# run-subscriber takes :domain :seconds :advertise-address
```

## Diagnosing discovery (`make square-spy`)

Before chasing data, see what the stack actually extracts from each participant's
SPDP announcement — its advertised locator lists and the destination we resolve:

```bash
make square-spy DOMAIN=0          # prints each discovered participant, Ctrl-C to stop
```

Sample output (against another harness participant):

```
[spy] participant 4742501d2fcded0000000000
        vendor=00.00 version=2.5 lease=100s endpoints=#x0000043F
        default-unicast:     UDPv4 127.0.0.1:51296
        metatraffic-unicast: UDPv4 127.0.0.1:51296
        -> resolved data destination: 127.0.0.1:51296
```

Run it while RTI DDSSpy (or rtishapesdemo) is up: a non-UDPv4 entry shows as
`kind=#x.. port=..`, a placeholder as `UDPv4 0.0.0.0:..`, and the resolved line
tells you whether we found a routable address (or `NONE` — meaning RTI advertised
only shmem/0.0.0.0 on your box, so you'd need `allow_interfaces`/UDPv4 enabled on
the RTI side). This is the fastest way to tell *why* interop isn't flowing.

## Against RTI Shapes Demo

1. Start `rtishapesdemo`, set its **domain** to match `DOMAIN` (default 0).
2. To **see my shapes**: in `rtishapesdemo` *Subscribe* to `Square`; run
   `make square-pub`. A moving square should appear.
3. To **receive RTI's shapes**: in `rtishapesdemo` *Publish* a `Square`; run
   `make square-sub`. Each update prints as `[sub] Square <color> x=.. y=.. size=..`.

### Caveats — read before expecting it to "just work"

Same-host loopback is the easy case; talking to a real Connext install has wrinkles:

- **Advertised address.** The participant advertises its unicast locator as
  `127.0.0.1` by default. If Connext runs on a different host/interface it cannot
  reach `127.0.0.1` — set `make square-pub ADVERTISE=<this-host-ip>` and ensure
  both ends share an L2 multicast-capable network. On one host with Connext bound
  to loopback, the default is fine.
- **Multicast interface.** SPDP is sent/joined on the default interface via
  `INADDR_ANY`. On multi-homed hosts the OS may pick the wrong NIC; pin the route
  or run both on loopback.
- **No liveliness / WriterLiveliness yet.** The harness re-announces SPDP+SEDP
  every ~1.5 s, which is enough for discovery, but it does not yet send the
  builtin ParticipantMessage (liveliness) datagrams some Connext QoS expects.
- **One socket, best-effort routing.** v1 shares a single UDP socket for
  metatraffic + user data and routes user DATA to each discovered participant's
  default-unicast locator. It is not the full RTPS locator/port matrix.
- **`color` is the key but instance lifecycle is minimal** (no dispose/unregister).
- **Sample table grows** (KEEP_ALL, unbounded) over a long subscriber run.

These are tracked toward the full M2 Connext interop gate. What **is** already
proven: the wire format itself — `make wire` validates every submessage shape
(SPDP/SEDP/DATA/HEARTBEAT/ACKNACK) against the Wireshark/tshark RTPS dissector, the
same oracle used for Connext interop (see `docs/provenance.md`). The harness above
is the necessary front half (my bytes on the wire); a live Connext handshake is the
remaining verification, and it needs a Connext install outside this repo.
