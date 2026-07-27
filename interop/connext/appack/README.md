# APP-ACK capture harness (ADR 0090)

Application acknowledgment has **no OMG clause** — an exhaustive search of `docs/specs/rtps-2_5.pdf` and
`rtps-2_5-xmi.xml` returns zero occurrences, and the DCPS IDL has only `wait_for_acknowledgments`, which
is protocol-level. There is therefore no specification to implement from and no vector to check against:
**this capture is the specification.**

## What is here

| file | what it is |
|---|---|
| `appack_pub.cxx` / `appack_sub.cxx` | a Connext pub/sub pair, written here against RTI's **public API** (clean-room: no RTI source, headers or `rtiddsgen` output is read into `src/` or committed) |
| `USER_QOS_PROFILES.xml` | forces loopback UDPv4 (Connext prefers SHMEM same-host, which never reaches the wire) and turns on `APPLICATION_AUTO_ACKNOWLEDGMENT_MODE` on **both** sides |
| `captures/appack-connext-7.3.1.pcap` | the captured exchange: 5 samples → **5 APP_ACK + 5 APP_ACK_CONF** |
| `captures/rtpsscan.py` | enumerates RTPS submessages straight from the pcap, independently of any dissector |
| `captures/appack_decode.py` | decodes the APP_ACK bodies **and self-checks the layout** |
| `captures/appack-decoded.txt` | the decode, committed so the finding is reviewable without rerunning anything |
| `captures/sedpscan.py` | dumps the SEDP publication/subscription vendor ParameterIds from a capture |
| `captures/acknowledgment-kind-pids.txt` | the **three-run experiment that identified PID 0x800b** as `acknowledgment_kind`, committed for the same reason — reviewable without Connext installed |

## Why `APPLICATION_AUTO` and not `APPLICATION_EXPLICIT`

AUTO acknowledges when the subscriber accesses the sample via an ordinary `read`/`take`, so the peer
needs **no vendor-extension API call** and nothing about the C++ binding has to be assumed. The wire
exchange is the same mechanism either way, which keeps the only thing under test the wire itself.

## Why the decoder self-checks

The layout was a hypothesis assembled from Wireshark's dissector **field names** (`tshark -G fields`,
metadata only — no dissector source read or adapted) plus the ordinary RTPS submessage prologue. It is
believed **only because it consumes every body exactly** — no leftover octets, no overrun, 10/10. A layout
that merely looks plausible on one sample is how wire bugs ship.

## Reproducing

```sh
export NDDSHOME=/Applications/rti_connext_dds-7.3.1 CONNEXTDDS_ARCH=arm64Darwin20clang12.0
make
# terminal 1
./appack_sub 129 20
# terminal 2 (start a loopback capture first)
./appack_pub 129 5 16
python3 captures/appack_decode.py <your.pcap>   # classic pcap; use editcap -F pcap if pcapng
```

`tshark` on macOS did **not** dissect these DLT_NULL loopback frames (it reports them as raw `Packet NN`),
which is why the scanners above parse the framing directly rather than relying on it.

## The QoS is on the wire too — PID 0x800b (slice A3b)

`acknowledgment_kind` is propagated in SEDP under RTI vendor ParameterId **0x800b**, a `u32`, on **both**
the publication and the subscription record, and **omitted at `PROTOCOL`**. That was established by running
this harness **three times** with only that one value changed and comparing the ParameterLists:

```sh
# edit USER_QOS_PROFILES.xml, then for each setting:
tcpdump -i lo0 -s 0 -w run.pcap udp &     # classic pcap; no editcap needed
./appack_sub 130 12 & sleep 3; ./appack_pub 130 3 16
python3 captures/sedpscan.py run.pcap
```

`0x800b` was the only field that moved — absent under `PROTOCOL`, `1` under `APPLICATION_AUTO`, `3` under
`APPLICATION_EXPLICIT` — matching RTI's published enumeration order. Full output in
`captures/acknowledgment-kind-pids.txt`.

**Why it had to be measured.** Slice A3a's RxO gate checks this policy by equality, and a policy neither
side can see cannot be checked: before this was wired, every discovered endpoint read as `PROTOCOL` and an
application-acknowledgment pair could never match at all.

## Still unpinned

`intervalFlags`: only two values were provoked (`0x0000` on the newly acknowledged SN, `0x0100` on the
coalesced run of previously reported ones). Its encoding **must not be guessed** — more cases are needed
(explicit mode, attached response data, a gap in the acknowledged range) before any encoder emits it.
