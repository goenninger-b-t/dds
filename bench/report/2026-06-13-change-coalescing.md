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

## Gates
143 tests pass on SBCL and Clasp (was 140; +`coalesce-pack` +`coalesce-split` +`coalesce-large-pack`).
gate-types PASS (925 ftype'd defuns). gate-hotpath PASS (5 hot-path files clean — this L5/L6 bridge file
is not a measured hot path).
