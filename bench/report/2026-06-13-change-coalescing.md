# Change coalescing — datagram (sendto) count bench

Date: 2026-06-13
Requirement: FR-RTPS-COALESCE (RTPS 2.5 §8.3.4 multi-submessage Message), FR-LANG-7
Scope: reliable user-data writer push + ACKNACK-retransmit paths (src/dds-disc/dataplane.lisp)

## The change
Each publish sent two datagrams (a DATA, then a separate HEARTBEAT); an ACKNACK retransmit of K changes
sent K datagrams — one `dds.xport:send` (≈ one `sendto`) per submessage. `%send-packed` now packs
multiple small DATA (and dispose/unregister DATA) submessages plus the trailing HEARTBEAT into one RTPS
Message per datagram, up to `min(*coalesce-datagram-budget* (1400), capacity−64)`, flushing and moving
the overflowing submessage behind the shared header when the budget is reached. Large (DATA_FRAG)
samples are unchanged (one datagram per fragment group). The receiver is unchanged — `dispatch-message`
already loops over every submessage in a datagram.

## Measurement method
Offline: bind `*datagram-sink*` to capture every outgoing datagram, run `%push-data`, re-parse each
captured datagram with `dispatch-message` and count submessages (tests `coalesce-pack`,
`coalesce-split`). The "before" count equals the submessage count (the old path emitted one datagram per
submessage).

## Result (datagrams sent ≈ sendto syscalls)

| scenario | submessages | before (1 datagram/submsg) | after | reduction |
| -------- | ----------- | -------------------------- | ----- | --------- |
| steady-state publish (1 small sample + HB) | 2 | 2 | 1 | 2× |
| burst push of 10 small samples + HB (`coalesce-pack`, measured) | 11 | 11 | 1 | 11× |
| same burst, budget lowered to 200 (`coalesce-split`, measured) | 11 | 11 | 2–3 | ~4× |
| burst of 10 near-fragment (1000 B) samples + HB (`coalesce-large-pack`, measured) | 11 | 11 | 10 | 1.1× |
| ACKNACK retransmit of K small changes (no HB) | K | K | ceil(bytes/budget) ≈ 1 | K× |

`coalesce-pack` asserts the 11 submessages re-parse from a single datagram within budget; `coalesce-split`
asserts the budget-forced split preserves all 11 submessages, each datagram ≤ budget; `coalesce-large-pack`
asserts near-`*fragment-size*` payloads pack WITHOUT overflowing the 2048-octet send buffer (the packer
flushes before writing a submessage that would not fit — every datagram ≤ budget and ≤ capacity).
Large-sample (DATA_FRAG) datagram count is unchanged (verified by `large-data-over-udp`).

## Conformance / interop
A DATA followed by a HEARTBEAT in one Message is ordinary RTPS (§8.3.4); no PID / EntityId / encapsulation
constant changed. The shared RTPS Header (§9.4.4) is reused verbatim per datagram. All UDP-loopback
regression tests green (reliable-data-over-udp, large-data-over-udp, lost-final-sample-repair,
dispose-over-udp, dispose-reliable-repair).

## Live wire confirmation (lo0, our square-pub vs Fast DDS shapes_sub)
Capture `interop/fastdds/captures/coalescing-data-heartbeat-lo0.pcap`, dissected with the standard
Wireshark/tshark RTPS dissector. Our publisher (vendorId 0x01FF) emitted 8 user-data samples; each is ONE
UDP datagram carrying TWO submessages — `DATA (0x15)` then `HEARTBEAT (0x07)`, both writerEntityId
0x00000102 — i.e. DATA+HEARTBEAT coalesced (8 datagrams for 8 samples, vs 16 one-per-submessage before):

```
frame 8  udp→7410  rtps.sm.id = 0x15,0x07   DATA(writer 0x102, SN 1) + HEARTBEAT(0x102, 1..1)
frames 9-15                    0x15,0x07     SN 2..8, each DATA+HEARTBEAT in one datagram
```

The standard dissector parses both submessages cleanly, confirming the coalesced datagram is well-formed
RTPS (§8.3.4) — the same framing Connext/Fast DDS emit and parse.

**Foreign-peer end-to-end delivery CONFIRMED.** With discovery given time to complete (a longer run),
our square-pub → Fast DDS shapes_sub on loopback delivers **299/300 coalesced samples** (ACKNACKs
climbing 22→210); the publisher resolves Fast DDS's `PID_DEFAULT_UNICAST_LOCATOR` 127.0.0.1:7411 and
sends the coalesced DATA+HEARTBEAT there. The initial "received 0" was a harness-timing artifact
(`count=8 ÷ rate=30` exited the publisher in ~0.27 s, before discovery) plus a static-`:peers`
user-data wart — both addressed (see `docs/superpowers/specs/2026-06-13-push-spdp-peer-isolation-design.md`:
the SPDP bootstrap peer is no longer used as a user-data destination once a reader is matched).

## Gates
143 tests pass on SBCL and Clasp (was 140; +`coalesce-pack` +`coalesce-split` +`coalesce-large-pack`).
gate-types PASS (925 ftype'd defuns). gate-hotpath PASS (5 hot-path files clean — this L5/L6 bridge file
is not a measured hot path).
