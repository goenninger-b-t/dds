# No-key endpoint-kinds interop (RTI Connext 7.3.1)

Live proof for the keyed/no-key endpoint-kinds feature. The OFFLINE mechanism is
complete and in the green suite (`make test-sbcl`, test `nokey-roundtrip`): a type's
keyed-ness drives the RTPS entity kind — writer WITH_KEY `0x02` / NO_KEY `0x03`, reader
WITH_KEY `0x07` / NO_KEY `0x04` (RTPS 2.5 §9.3.1.2 Table 9.1) — threaded through
`add-local-writer`/`add-local-reader` (`:keyed`), the disc-node user ids, and DCPS, with
a match-time keyed-ness guard (a keyed/no-key pair silently does not match,
`integration-test.lisp` `endpoint-kind-match`).

> **LIVE Connext interop ACHIEVED both directions (2026-06-12, same host, lo0).** See
> "Live results" below. The earlier same-host failure was an environment artifact (a
> stale process holding the discovery port plus the macOS LAN-UDP firewall gate), not a
> NO_KEY protocol defect: Connext matches our NO_KEY writer `…0x00000103` and reader
> `…0x00000104` by topic + type name alone.

This directory adds the Connext oracle: a **keyless** `NoKeyData` IDL and `nokey_pub` /
`nokey_sub`, built like the keyed `shapes-pub`/`shapes-sub` apps (clean-room: our IDL,
`rtiddsgen` output produced at build time and git-ignored). The registered type name is
pinned to `nokey-data` via the 3-arg `Topic(participant, "NoKeyTopic", "nokey-data")`
constructor so it is byte-identical to this stack's registered type-name; discovery
matches on topic name + type name.

## Build & run (LOOPBACK — the proven recipe)

`USER_QOS_PROFILES.xml` is pinned **loopback-only** (`allow_interfaces=127.0.0.1`) and
the Lisp side reaches Connext with **unicast SPDP to `127.0.0.1:7410`** (`PEERS=`).
Everything rides `lo0`, which sidesteps the macOS LAN-UDP firewall gate for the freshly
built `nokey_pub`/`nokey_sub` (those binaries are absent from the firewall allow list,
unlike the long-approved `shapes_pub`/`shapes_sub`; loopback is exempt).

**FIRST: kill any stale DDS process holding domain-0 discovery ports** — a leftover
`shapes_pub`/`sbcl` on `7400`/`7410` forces Connext to a different participant index
(`7412`) so the unicast SPDP misses it, and two Connext instances then discover each
other and mask the real exchange. Check with `lsof -nP -iUDP:7400-7420`.

```sh
export NDDSHOME=/Applications/rti_connext_dds-7.3.1
export CONNEXTDDS_ARCH=arm64Darwin20clang12.0
export DYLD_LIBRARY_PATH=$NDDSHOME/lib/$CONNEXTDDS_ARCH
make                                 # builds nokey_pub + nokey_sub
lsof -nP -iUDP:7400-7420             # confirm NOTHING else holds these ports

# forward leg (Connext -> this stack), Connext binds 7410:
./nokey_pub 0 0                      # domain, count (0 = forever)
make -C ../../.. nokey-sub DOMAIN=0 SECONDS=45 ADVERTISE=127.0.0.1 PEERS=127.0.0.1:7410

# reverse leg (this stack -> Connext), Connext sub binds 7410:
./nokey_sub 0 0                      # domain, seconds (0 = forever)
make -C ../../.. nokey-pub DOMAIN=0 COUNT=0 ADVERTISE=127.0.0.1 PEERS=127.0.0.1:7410
```

`captures/` archives the resolved-run pcaps + run logs (`nokey-{fwd,rev}-loopback-*`).
The shipped profile is loopback-only; for a
genuine two-host run, set `allow_interfaces` to the host UDPv4 address on each side,
approve the binaries in the firewall, and drop `PEERS`.

## Live results (2026-06-12, this host: en7 = 192.168.2.148; loopback on lo0)

Both directions matched and delivered on loopback (captures + verbose logs under
`captures/nokey-{fwd,rev}-loopback-*`):

| Leg | Setup | Result |
|---|---|---|
| Forward | Connext `nokey_pub` -> our `nokey-sub` (`PEERS=127.0.0.1:7410`) | **`MATCHED 1`, received 147/150** (first 3 pre-date the match under VOLATILE) |
| Reverse | our `nokey-pub` (`PEERS=127.0.0.1:7410`) -> Connext `nokey_sub` | our pub `matched=1`; **Connext received 159/160** (first pre-dates the match) |
| Keyed-vs-no-key non-match | offline (`integration-test.lisp` `endpoint-kind-match`) | PASS in suite |
| Keyed regression (DCPS) | Connext `shapes_pub` -> our `gated-sub` | PASS — `matched=1`, 465 samples |

**The NO_KEY wire kinds are confirmed correct AND accepted by Connext** (from the
`CONNEXT_VERBOSE=1` logs in `captures/`):

- Reverse, Connext matches our writer:
  `MATCH | Remote unkeyed user datawriter (GUID: 0x47420132,0x6CD6ED00,…:0x00000103)
  matched with local unkeyed user datareader (GUID: …:0x80000004)` — our writer EntityId
  **`0x00000103` (kind `0x03` = NO_KEY writer**, RTPS 2.5 §9.3.1.2) against Connext's
  NO_KEY reader (kind nibble `0x04`). Connext also logs
  `TypeObject not received (topic: 'NoKeyTopic', type: 'nokey-data')` — it matches on
  **topic + type name alone**, no XTypes assignability needed.
- Forward, Connext's own writer is `…:0x80000003` ("Local unkeyed user datawriter … for
  topic NoKeyTopic", kind `0x03`); our NO_KEY reader (`0x04`) matched it and took 147
  samples.

So this stack's NO_KEY endpoints come up with the spec-correct kinds and interoperate
with Connext both directions.

## Root cause of the earlier failure (RESOLVED — not a NO_KEY bug)

The first attempt reported `matched=0` both legs and the verbose log showed "Connext
never advances past SPDP for our `4742…` prefix." That conclusion was wrong; it was an
**environment artifact**, isolated wire-first:

1. **Stale process on the discovery port.** A leftover keyed `shapes_pub` held
   `127.0.0.1:7410` (and a stale `sbcl` held `7400`). Connext's `nokey_pub` then bound
   participant **index 1 (`7412`)**, so our unicast SPDP to `127.0.0.1:7410` reached the
   wrong (stale) participant; the two Connext instances discovered each other and the
   phantom `0x0101…` assertions masqueraded as "Connext ignores us." Verbose evidence:
   `FAILED TO BIND | Invalid port 7410` and `Discovered new remote participant
   0x0101DCD1,…` (a Connext prefix, never our `4742…`).
2. **The macOS LAN-UDP firewall** would independently block LAN-sourced UDP to the fresh,
   unapproved `nokey_pub`/`nokey_sub` (the same gate the Fast DDS leg B hit). The
   loopback-only profile + `PEERS=127.0.0.1:7410` sidesteps it.

After killing the stale processes and running entirely on loopback, **both legs match and
deliver** (table above). The fix is harness/environment only: a `:peers` unicast-SPDP
passthrough was added to the DCPS no-key harness (`create-participant :peers`,
`run-nokey-{publisher,subscriber} :peers`, Makefile `PEERS=`) and the profile pinned to
`127.0.0.1`. No protocol/code change to the NO_KEY mechanism was needed; the suite stays
**106 green** (`make test-sbcl`).
