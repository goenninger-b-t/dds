# T9protected live cross-vendor result — WP-DDS-SECURITY-FASTDDS-INTEROP (M7/P6 Slice 5)

`bash interop/security-secure-discovery/run-fastdds-interop.sh secure 45` — our stack ↔ a SECURITY=ON
eProsima Fast DDS peer, both directions, **GOV=secure** (the DoD governance: discovery_protection=ENCRYPT,
liveliness=SIGN, rtps_protection=ENCRYPT, metadata=ENCRYPT, data=ENCRYPT). This iteration adds the three
T9-diagnosed fixes (secure-SEDP reliability HEARTBEAT/ACKNACK demux + NACK-pull, NO_KEY keyed-ness, USER
DW/DR CryptoToken re-exchange at endpoint-match time). Captures: `ssd-secure-{ours2fast,fast2ours}-{ours,
fastdds}.log` (+ `.pcapng`, gitignored — tshark cannot dissect the macOS lo0 link layer; diagnosis rests on
the logs + Fast DDS source + our decoded bytes).

## The advance: USER ENDPOINTS NOW MATCH BOTH DIRECTIONS (was matched=0 in T8sedp)

| | T8sedp (before) | T9protected (after) |
|---|---|---|
| our side `:keyed` | KEYED both | KEYED both (`ever-keyed=T`, `states=...=KEYED`) |
| our user-endpoint **match** | **0 / none** | **matched=1 BOTH directions** (`peak-matched=1`) — stable across the whole window |
| Fast DDS matches our endpoint | no | **YES** — `Publisher matched.` (fast2ours); `decode_datawriter_submessage` on our data (ours2fast) = it matched our writer |
| protected user DATA flows | none | **not yet either direction** (`peak-samples=0` both) — the next blocker |

Before T9 the secure-SEDP DiscoveredWriter/ReaderData never reached the peer reliably and our user tokens
carried a symmetric-assumed dest key, so the user endpoints never matched. The T9 reliability pull
(`%send-secure-builtin-heartbeats` + the HEARTBEAT/ACKNACK demux) + the match-time DW/DR token re-exchange
(`cm-on-endpoint-match`, dest = the real matched-remote GUID) close that gap: the user endpoints MATCH both
ways.

## REMAINING blocker (next iteration): the user-DATA protection layer (rtps_protection SRTPS + user-writer EntityCrypto)

Reached for the FIRST time now that the endpoints match (no user data flowed before, so this layer was never
exercised cross-vendor). Fast DDS error histogram (ANSI stripped):

- **ours2fast** (our PUB → Fast DDS SUB): `89× Key material not found -> Function decode_datawriter_submessage`
  (Fast DDS receives our protected user DATA submessages but has no installed EntityCrypto for our user
  WRITER → cannot decode) + `8× Not valid SecureDataTag submessage id -> Function decode_rtps_message`
  (its rtps_protection/SRTPS whole-message decode rejects some of our datagrams).
- **fast2ours** (Fast DDS PUB → our SUB): `Publisher matched.`, Fast DDS sent 91 samples, **we decoded 0**
  (`peak-samples=0`) — symmetric: we do not apply Fast DDS's user-writer EntityCrypto / decode its
  rtps-protected user data.

### Best hypothesis + next conformant step

The per-endpoint **DatawriterCryptoToken** that delivers the user-writer's §9.5.2 EntityCrypto is not being
APPLIED by the peer for the data decode, and/or the **rtps_protection (SRTPS, §8.5.1.10-.12)** wrap on the
user-data datagram diverges from Fast DDS's `decode_rtps_message` (the `Not valid SecureDataTag` =
SRTPS_POSTFIX/SecureDataTag framing). The two symptoms may be linked: if our PVMS datagram carrying the
user-writer token is itself SRTPS-rejected, Fast DDS never installs the key → `Key material not found`. Next
step (a fresh diagnose→corroborate→fix loop, CLEAN-ROOM vs Fast DDS `AESGCMGMAC_Transform::decode_rtps_message`
+ the `*_handles_.find(destination_endpoint_key)` user-token application path; RTI never read): (1) confirm
whether our match-time user DatawriterCryptoToken reaches AND applies at Fast DDS (vs being dropped at the
SRTPS layer); (2) byte-align our user-data SRTPS_PREFIX/SEC_BODY/SRTPS_POSTFIX with what `decode_rtps_message`
expects; (3) verify our inbound decode of Fast DDS's rtps-protected user data + its user-writer EntityCrypto.
This is the user-DATA tier (T10/rtps_protection), distinct from the T9 secure-DISCOVERY reliability + match
this iteration delivers. Connext-Security live remains the Slice-5b exit gate (RTI Security Plugins absent).

## our-to-our (binding invariant) — GREEN both impls with the new reliability branches active

- **SBCL**: `make test-sbcl` = **377 passed** (deterministic); the four secure-discovery e2es
  (keyed/protected/protected-sign/origin-auth) + PVMS reliable/fail-closed pass with
  `%send-secure-builtin-heartbeats` + the HEARTBEAT/ACKNACK demux compiled in and FIRING (the protected e2es
  are mutually keyed with protected topics, so the announce-cadence heartbeats + the ACKNACK-pull execute).
- **Clasp** (`GC_DONT_GC=1 make test-clasp`, the documented Boehm-race workaround): all secure e2es pass in
  isolation — keyed, protected (4/5), protected-sign (3/3), origin-auth, pvms-reliable, pvms-fail-closed,
  crypto-manager. The full-suite abort is only the documented NFR-PORT `[SDP-SEC-PREFIX-ON-WIRE]` live-socket
  flake (wanders between protected/protected-sign, ~20%, 100% green on SBCL) — re-run/isolation-verified, not
  a regression. gate-hotpath (8 files) / gate-types (2039 defuns) / fuzz / mem (0.0000 bytes/sample) PASS.

## Nonce-safety (named risk — same class as the Slice-4 T8 bug): PASS

The new encrypt sites under the secure-SEDP-WRITER EntityCrypto KM (`%send-secure-builtin-heartbeats`
HEARTBEAT + the ACKNACK-driven `%send-secure-endpoint` DATA resend) plus the ACKNACK under the READER KM all
funnel through `encode-data{writer,reader}-submessage` → `%encode-secured-submessage` → `%km-next-iv-suffix`,
which claims+increments a per-KM monotonic counter under `KM-IV-COUNTER-LOCK` (atomic). `cm-encode-entity-km`
returns the stable registered KM singleton (no per-call copy → the counter never resets). So every send under
one KM — including the announce-thread DATA+HEARTBEAT racing the receiver-thread ACKNACK-resend on the same
0xC2 writer KM — draws a DISTINCT iv_suffix → distinct (key, nonce). The ACKNACK rides the independent 0xC7
reader KM. No (key, nonce) reuse is possible.
