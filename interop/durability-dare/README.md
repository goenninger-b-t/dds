# DARE-encrypted durability service — foreign late-joiner cross-DDS interop (WP-DURABILITY-DARE, M6/P5)

The per-feature interop Definition-of-Done gate (owner directive 2026-06-17: every feature verifies
interop with **both** RTI Connext **and** eProsima Fast DDS) for **Data-At-Rest Encryption (DARE)** of the
embedded durability service's store (ADR 0021 capability 7, ADR 0025).

This is a **transparency** check, not a new wire feature. It is the exact same writer-gone late-joiner
scenario as `interop/durability-transient/`, run with one difference: the service's durable store is
wrapped in a DARE-encrypted-store decorator. The claim being proved is that **DARE adds zero
wire-observable surface**.

**Status: both legs LIVE-verified in-session (2026-06-19), both peers.** Captures under `captures/`.

## The transparency claim

DARE seals payloads **in the store** on `store-put` (ML-KEM-1024 KEM-DEM envelope: HKDF-SHA384 DEK +
AES-256-GCM, per-store 96-bit counter nonce) and **opens** them on `store-get-range`. The durability
service's replay writer publishes the **opened plaintext** samples — exactly the bytes it would publish
with a plain in-memory store. Therefore:

- A foreign TRANSIENT_LOCAL late-joiner receives **byte-correct** retained samples whether or not the
  store underneath is encrypted.
- The wire encapsulation, the SEDP advertisement, the HEARTBEAT retention signal, and the DATA payload
  bytes are **identical** to the plain-store transient case.
- **DARE is at-rest only.** It protects the persisted/held copy of the data; it is not data-in-transit
  protection and adds nothing to (and removes nothing from) the wire. Data-in-transit is the separate
  P6 DDS-Security work, out of scope for this WP.

This makes the cross-DDS check "light by nature" (design spec §8): the cryptographic substance is the
NIST KATs (FIPS-180-4 SHA-384, NIST SP800-38D GCM TC16, C2SP/CCTV ML-KEM-1024) exercised by the unit
tests, plus the in-process transparency test. This harness adds the **live foreign-peer confirmation**
that the encrypted store changes nothing a Connext or Fast DDS peer can observe.

## The ONLY delta vs `interop/durability-transient/`: the store factory

`make-service-spec` takes a `:store` slot — a 0-arg factory (`src/dds-durability/spec.lisp`; default
`(lambda () (make-memory-store))`). For DARE the factory wraps the memory store in an encrypted-store
decorator backed by a file key-provider:

```lisp
(asdf:load-system :dds-durability)   ; pulls in dds-dare
(let* ((keydir (uiop:ensure-directory-pathname "/tmp/dare-interop-keys"))
       (spec (dds.durability:make-service-spec
               :domain 0
               :topics '(("Square" . "ShapeType"))
               :store (lambda () (dds.durability:make-encrypted-store
                                   (dds.durability:make-memory-store)
                                   (dds.dare:make-file-key-provider :dir keydir)))
               :qos-overrides '(:data-representation (:xcdr1)
                                 :peers (("127.0.0.1" . 7410)))
               :name "dsvc-dare-interop"))
       (svc (dds.durability:make-durability-service spec)))
  (dds.durability:service-start svc)
  (format t "~%SVC-STARTED~%") (force-output)
  (loop (sleep 60)))
```

- `dds.durability:make-encrypted-store` / `make-memory-store` — exported from `dds.durability`
  (`src/dds-durability/packages.lisp`). On construction the decorator opens the key-provider,
  ML-KEM-1024-encapsulates the recipient public key, derives the DEK, and frees the transient shared
  secret. Every `store-put` seals; every `store-get-range` opens (auth/tamper failure DROPS the record).
- `dds.dare:make-file-key-provider :dir KEYDIR` — exported from `dds.dare`
  (`src/dds-dare/key-provider.lisp`). On first open it runs `ml-kem-1024-keygen`, writes
  `ml-kem-1024.pub` (1568 B) + `ml-kem-1024.key` (3168 B, perms enforced 0600), and on later opens loads
  them (refusing a private key looser than 0600). Each run with a fresh `:dir` generates a fresh keypair.

Everything else — the two `qos-overrides` (`:data-representation (:xcdr1)` so XCDR1-only ShapeType
readers match; `:peers (("127.0.0.1" . 7410))` unicast SPDP to the domain-0 well-known port), the
periodic SPDP/SEDP re-announcement, the foreign QoS profiles, ports, kill-stale-procs-first, the ~8 s
init wait, the ~15 s publish window, the late-joiner — is **identical** to the
`interop/durability-transient/` runbook. Read that README for the full annotated rationale.

## Foreign-peer configuration

Copied verbatim from `interop/durability-transient/` so this harness is self-contained:

- `USER_QOS_PROFILES.xml` — Connext loopback (`allow_interfaces=127.0.0.1`, UDPv4) + TRANSIENT_LOCAL /
  RELIABLE / KEEP_ALL / unlimited resource-limits on writer & reader QoS. Run the Connext binaries from
  this directory so they load it from cwd.
- `fastdds-profiles.xml` — Fast DDS loopback-only (`interfaceWhiteList=127.0.0.1`, UDPv4). Copy to
  `interop/fastdds/shapes/profiles.xml` (it is byte-identical to the already-committed copy there); the
  `DURABILITY=transient_local` env gate in `shapes_pub.cpp`/`shapes_sub.cpp` sets the TL+KEEP_ALL QoS.

**FIRST: kill any stale DDS process on the discovery ports** (`lsof -nP -iUDP:7400-7440`).

## Run commands

```sh
export NDDSHOME=/Applications/rti_connext_dds-7.3.1
export CONNEXTDDS_ARCH=arm64Darwin20clang12.0
export DYLD_LIBRARY_PATH=$NDDSHOME/lib/$CONNEXTDDS_ARCH
# from repo root
```

### Leg 1 — Connext TL publisher publishes → exits → DARE service → late Connext TL subscriber

```sh
# 1) Capture
WIRESHARK_CONFIG_DIR=$(mktemp -d) /Applications/Wireshark.app/Contents/MacOS/tshark \
  -i lo0 -f "udp portrange 7400-7700" \
  -w interop/durability-dare/captures/leg1-our-svc-to-connext-late.pcap &

# 2) DARE-wrapped service (the driver form above; fresh keydir; re-announces SPDP every 1.5 s)
./scripts/with-sbcl.sh --eval '(asdf:load-system :dds-durability)' --eval "<driver form, :store = encrypted-store>" &
# ...wait ~8 s for service init (incl. ML-KEM-1024 keygen on first run)...

# 3) Connext TL publisher (from this dir for the TL+loopback profile; ~15 s then kill)
cd interop/durability-dare
stdbuf -oL ../connext/shapes-pub/shapes_pub 0 GREEN &
PUB_PID=$!; sleep 15; kill $PUB_PID
# ...wait ~4 s for service to settle...

# 4) LATE-JOINING Connext TL subscriber (starts after the publisher is dead)
stdbuf -oL ../connext/shapes-sub/shapes_sub 0 20
```

### Leg 2 — Fast DDS TL publisher publishes → exits → DARE service → late Fast DDS TL subscriber

```sh
# Restart the DARE service (fresh keydir). Copy the loopback-only Fast DDS profile:
cp interop/durability-dare/fastdds-profiles.xml interop/fastdds/shapes/profiles.xml

# Fast DDS TL publisher (~15 s then kill):
DURABILITY=transient_local ./scripts/with-fastdds.sh bash -c \
  'cd interop/fastdds/shapes && stdbuf -oL ./shapes_pub GREEN 200' &
PUB_PID=$!; sleep 15; kill $PUB_PID

# LATE-JOINING Fast DDS TL subscriber:
DURABILITY=transient_local ./scripts/with-fastdds.sh bash -c \
  'cd interop/fastdds/shapes && stdbuf -oL ./shapes_sub 20'
```

## Live results (2026-06-19, this host, lo0)

| Leg | Peer | Retained by service | Late-joiner received | First sample received | Capture |
|---|---|---|---|---|---|
| **1** | **Connext** | 403 | **352** | `#1 x=206 y=154` (published before the subscriber joined; the publisher was already dead) | `captures/leg1-our-svc-to-connext-late.pcap` |
| **2** | **Fast DDS** | 152 | **152** | `#1 x=78 y=146` (orig sample #29; service matched ~3 s into the 15 s window; all collected delivered) | `captures/leg2-our-svc-to-fastdds-late.pcap` |

Both late-joining subscribers received samples the original publisher had sent **before** they joined and
**before** the publisher exited — samples they could only have received from the service's retained store.
With DARE, that store held the samples **encrypted at rest**; the service opened them on get-range and
the late-joiners received them **byte-correct**. Nothing on the wire differed from the plain-store
transient run.

**Leg 1 note:** the Connext late-joiner received 352 samples. The service's HEARTBEAT advertised
`lastSeqNumber` up to 403; the 20-second subscriber window decoded 352 before being stopped. The
animation cycles (the shape bounces), and the full retained range is delivered from sequence 1 (the
`firstSN=1` HEARTBEAT signal below) — the late-joiner sees the continuous animation, not a
mid-animation slice, confirming full pre-join history.

**Leg 2 note:** the Fast DDS publisher sent 152 samples in the 15-second window; the late-joiner
received exactly 152 (last received `#152 x=101 y=107` = the publisher's last sent `152 x=101 y=107`).
The first **received** sample `x=78 y=146` is original sequence #29: the service's collecting reader
matched the Fast DDS writer ~3 s after the publisher started, so the first ~28 samples were published
before the service matched and were therefore not collected. The service can only replay what it
collected — 152 collected, 152 sealed-then-opened, 152 delivered. (This first-sample value is
byte-identical to the plain-store transient Leg 2, i.e. the encrypted store changed nothing.)

## Wire evidence (tshark RTPS dissector)

The service's replay writer is RTPS EntityId `0x00000102`. The wire surface is **identical** to the
plain-store transient case — the proof that DARE is at-rest-only.

### Leg 1 capture (`leg1-our-svc-to-connext-late.pcap`)

- **`firstAvailableSeqNumber: 1` on EVERY HEARTBEAT** from `0x00000102` (60 HEARTBEATs hold at the
  steady state `firstSN=1 lastSN=403`; `lastSeqNumber` climbs `9 → 84 → … → 403`). `firstSN` never
  advances — the TRANSIENT_LOCAL KEEP_ALL retention signal.
- **`CDR_LE (0x0001)` on all 806 DATA submessages** from `0x00000102` — XCDR1 little-endian, confirming
  the `:data-representation (:xcdr1)` override is active and DARE introduces no representation change.
- Submessage totals: 1152 DATA / 542 HEARTBEAT / 222 ACKNACK / 70 INFO_TS / 8 INFO_DST — the full
  reliable late-joiner repair exchange.

### Leg 2 capture (`leg2-our-svc-to-fastdds-late.pcap`)

- **`firstAvailableSeqNumber: 1` on EVERY HEARTBEAT** from `0x00000102` (222 HEARTBEATs, **zero** with
  `firstSN ≠ 1`); `lastSeqNumber` reaches 152 (= the collected/delivered count).
- **`CDR_LE (0x0001)` on all 304 DATA submessages** from `0x00000102`.
- Submessage totals: 535 DATA / 271 HEARTBEAT / 118 ACKNACK / 23 INFO_TS / 23 INFO_DST_VENDOR.

Both captures match the `interop/durability-transient/` evidence (same EntityId, `firstSN=1` held
forever, `CDR_LE`, NACK→retransmit repair). **The encrypted store is transparent on the wire.**

## macOS lo0 reverse-direction capture note

As documented in `interop/durability-transient/README.md`, the **foreign publisher → our service**
user-DATA direction is under-captured on lo0 (the macOS BPF loopback quirk). The load-bearing collection
proof is therefore the **decoded receipt** at the late-joining subscriber (application-level, shown
above) plus the service replay writer's HEARTBEAT `lastSeqNumber` matching the delivered count — not the
foreign→us capture direction. The captures above are the service's outbound replay (our `0x00000102` →
the foreign late-joiner), which is the direction that proves transparency.

## In-process conformance proof (cross-reference)

The authoritative in-process transparency proof is the unit test
`dds.tests:run-dare-service-transparency-test` (`src/dds-tests/durability-test.lisp`; suite key
`"dare-service-transparency"` in `src/dds-tests/echo-test.lisp`). It drives a DARE-wrapped service
end-to-end in one process and asserts a same-stack late-joiner receives the retained samples. It
**passes on SBCL and Clasp** (Clasp validated first per the operating contract). It was re-run on SBCL
during this interop session: `DARE-TRANSPARENCY-TEST-RESULT: T`. This live cross-DDS harness adds the
foreign-peer (Connext + Fast DDS) confirmation on top of that in-process proof.

The cryptographic correctness of the seal/open primitives themselves is proved separately by the
published NIST/IETF Known-Answer Tests in the `dds-dare` test suite (FIPS-180-4 SHA-384, RFC-5869
HKDF, NIST SP800-38D GCM TC16, C2SP/CCTV ML-KEM-1024) — never self-generated vectors.

## Clean-room / provenance

Clean-room: the foreign peers are the committed `interop/connext/shapes-*` and `interop/fastdds/shapes`
harnesses configured for TRANSIENT_LOCAL via QoS XML (Connext) and the C++ `DURABILITY` env gate
(Fast DDS). No RTI / Fast DDS source is copied. Connext `rtiddsgen` output is build-time + git-ignored;
Fast DDS `fastddsgen` output under `interop/fastdds/shapes/gen/` is committed verbatim (Apache-2.0;
`docs/provenance.md`). The DARE design is pinned from CNSA-2.0 + the cited FIPS/NIST/IETF standards
(ADR 0021 cap.7, ADR 0025); the durability/late-joiner service semantics from DDS 1.4 §2.2.3.4 and
RTPS 2.5 §8.4.2.2.

## Files

- `USER_QOS_PROFILES.xml` — Connext loopback + TRANSIENT_LOCAL/KEEP_ALL/RELIABLE profile.
- `fastdds-profiles.xml` — Fast DDS loopback-only profile (copy to `interop/fastdds/shapes/profiles.xml`).
- `captures/leg1-our-svc-to-connext-late.pcap` — DARE service → late Connext TL reader; `firstSN=1`, CDR_LE, NACK→retransmit.
- `captures/leg2-our-svc-to-fastdds-late.pcap` — DARE service → late Fast DDS TL reader; `firstSN=1`, CDR_LE, NACK→retransmit.
