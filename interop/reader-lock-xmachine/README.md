# Cross-machine live evidence for the reliable-reader lock (ADR 0085)

Two real machines, one LAN, our stack on both ends, reliable Shapes over UDPv4. The point of this leg is
not vendor interop (that is `make interop`) — it is that the **receive path exercised here is exactly the
one ADR 0085 fixes**: a node's receiver threads driving one `rtps-reader`, delivering into the re-landed RX
store-copy pool, across a real network rather than loopback.

| | |
|---|---|
| macOS | `192.168.2.148`, SBCL, arm64 |
| Linux | `192.168.2.180` (`goedews01`), SBCL 2.2.9, x86_64 |
| Domain | 7 (disjoint from the suites' 60/100–143 and 151–203) |
| Type | `tagged` Shapes, RELIABLE |

## Direction A — macOS publisher → Linux subscriber

`mac-pub-to-linux.log` / `linux-sub-from-mac.log`

```
[pub] stopped after 400 samples; ACKNACKs received=349 (uuid=67c411b2-…)
samples received: 348 · distinct seqs: 348 · duplicate seqs: 0
```

## Direction B — Linux publisher → macOS subscriber

`mac-sub-from-linux.log`

```
[pub] stopped after 400 samples; ACKNACKs received=388 (uuid=585df1a8-…)
samples received: 341 · distinct seqs: 341 · duplicate seqs: 0
```

## What this asserts

**ZERO DUPLICATE SEQUENCE NUMBERS IN EITHER DIRECTION.** That is the property the unsynchronized reader
broke: `reader-dedup-accept-p` is a seen-test-then-mark, and two receiver threads racing it both returned T
for the same `(GUID, SN)` — measured, in the unit regression, at 503/519/502 accepts for 500 SNs. Here the
same check runs against live cross-machine traffic and every sequence number is delivered exactly once
(RTPS 2.5 §8.3.5.4).

The received counts are below 400 by design: the subscriber is VOLATILE and joins after the publisher has
started, so pre-match samples are not requested. Contiguity from first-received to 400 is what matters, and
`ACKNACKs received` shows the reliable channel running throughout.
