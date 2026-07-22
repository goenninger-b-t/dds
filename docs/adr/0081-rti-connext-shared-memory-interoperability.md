# ADR 0081 — interoperating with RTI Connext over shared memory

- **Status:** Accepted
- **Date:** 2026-07-22
- **Requirements:** FR-IO, FR-DISC, FR-XPORT, NFR-IP, NFR-SEC-POSTURE
- **Spec:** DDSI-RTPS 2.5 §7.5 / Clause 9 (UDP/IP is the only transport PSM the standard defines — every
  shared-memory locator kind is therefore vendor-defined), §8.3.2.6 `Locator_t`
- **Owner directive:** 2026-07-22 — "fully interoperable with RTI Connext over SHMEM is a non-negotiable
  requirement with **highest priority** and therefore **supersedes other directives**"; then "take publicly
  available header files and use publicly available documentation"; then "Start with the locator and take it
  from there."
- **Supersedes on one point:** the addressing constants recorded in `docs/provenance.md` under the slice-1
  entry were **wrong** and are corrected here (§4).

## 1. The problem

RTPS defines exactly one transport PSM: UDP/IP. Shared memory is vendor territory. RTI Connext's default
`transport_builtin` mask is `UDPv4 | SHMEM`, and on a single host SHMEM is the transport it actually prefers
— roughly 7 µs against 19 µs for UDP on this hardware. A peer configured `mask = SHMEM` publishes user data
over shared memory only. Without SHMEM interoperability such a peer is discovered, type/QoS-matched, and
then never exchanges a sample (which is precisely the failure ADR 0080 now refuses and reports).

## 2. What RTI publishes, and what it does not

Their shipped public headers and shipped API documentation specify **how to find a segment**:

- `NDDS_TRANSPORT_CLASSID_SHMEM = 0x01000000` — the locator kind (`transport_common_user.h`).
- `NDDS_TRANSPORT_SHMEM_ADDRESS_BIT_COUNT = -96` — 96 significant address bits (`transport_shmem.h:118`).
- The port→key mapping *fields*, with their defaults (`transport_shmem.h:50-66`, `:194-199`).
- `MESSAGE_SIZE_MAX_DEFAULT 65536`, `RECEIVED_MESSAGE_COUNT_MAX_DEFAULT 64`,
  `RECEIVE_BUFFER_SIZE_DEFAULT = message_size_max/4 * count`, `CLASS_NAME "shmem"`.
- The `shmemUUID` field and, verbatim, the co-location test (`transport_shmem.h:89-96`):
  > *"UUID used to check the reachability of a shmem locator received through discovery. After attaching to a
  > shmem segment, we will check that the UUID in the header matches the one in the received locator. If it
  > matches, that means that we are on the same machine than the target locator and that communication is
  > possible through shmem."*

They do **not** publish what is *inside* the segment: no header byte layout, no property-block format, no
ring structure, no head/tail semantics, no framing, no synchronisation protocol. The header names five
internal protocol revisions (`MAJOR_BEFORE_BUG_14240_FIX` … `MAJOR_AFTER_ROBUST_PTHREAD_MUTEX`) without
specifying any of them.

Note the consequence of the quoted test: **even same-host detection requires reading the segment header.**
There is no published way to answer "is this peer on my machine" from the locator alone.

## 3. Decision — the route

Three routes were identified and put to the owner explicitly before any of them was built:

| | route | segment format needed? | cost |
|---|---|---|---|
| A | Drive RTI's own SHMEM plugin through their published `NDDS_Transport_Plugin` C API (`transport_interface.h`; `NDDS_Transport_Shmem_newI` is an exported symbol of `libnddscore.dylib`) | no | our SHMEM-interop path requires the RTI runtime present |
| B | Ship a C transport plugin implementing *our* format, loaded into Connext via the documented `dds.transport.load_plugins` + `<PREFIX>.library`/`.create_function` (how RTI's own LBRTPS/ZRTPS add-ons load) | no | every Connext peer must be configured and deployed with it |
| C | Reconstruct RTI's segment format by observation | yes | brittle across their `VERSION_MAJOR` revisions |

**The owner chose route C** (2026-07-22), after the trade-offs above were stated. Routes A and B remain
available and are recorded here so the choice can be revisited without re-deriving the analysis — in
particular, route A is the fallback if a `VERSION_MAJOR` bump invalidates the reconstruction.

**Method.** Facts are established by *controlled variation*, not by reading a hexdump and guessing: a
documented property is set to a distinctive value through Connext's own QoS, and the segment is diffed. A
field is only recorded as identified when a chosen value appears where predicted. Everything below is
labelled with how it was established.

## 4. Addressing — CORRECTED

The slice-1 provenance entry recorded "segment key `0x800000 + port`, mutex/semaphore keys `0xb00000 + port`".
**That is wrong.** `transport_shmem.h` declares the fields in the order
`segmentKey{Offset,Factor}`, `semaphoreKey{Offset,Factor}`, `mutexKey{Offset,Factor}` (`:50-66`) and the
default initializer supplies `0x400000,1, 0x800000,1, 0xB00000,1` (`:194-199`) — a 1:1 positional match:

| resource | key |
|---|---|
| segment | **`0x400000 + port`** |
| semaphore | `0x800000 + port` |
| mutex | `0xB00000 + port` |

Confirmed three independent ways: the header's field order; live `ipcs` output against a running Connext
participant (`0x00401cf2`/`0x00801cf2`/`0x00b01cf2` for port 7410); and by *predicting* the keys for six
further domains before starting a peer on each and finding exactly the predicted keys.

The mechanism on macOS is **System V IPC** (`shmget`/`semget`), not POSIX `shm_open`.

`port` is the ordinary RTPS port, so the standard mapping applies unchanged:
`PB + DG*domain + d1 + PG*participant_index` for metatraffic, `d3` for user traffic.

## 5. Segment layout — as measured

Little-endian, `arm64Darwin20clang12.0`, Connext 7.3.1, shmem protocol `majorVersion` 2.

| offset | width | content | how established |
|---|---|---|---|
| `0x00` | u32 | segment size − 16 | observed, two configurations |
| `0x04` | u32 | creator pid | **proven** — matches `ipcs` cpid across runs |
| `0x08` | u32 | the segment key | **proven** — tracked the key across six domains |
| `0x0c` | u32 | segment size, exact | **proven** — matched `ipcs` segsz in both configurations |
| `0x10` | u32 | magic `0xce444453` (`"SDD"`,`0xce`) | observed, invariant |
| `0x14` | u32 | shmem protocol `majorVersion` = 2 | matches the documented `VERSION_MAJOR_DEFAULT` |
| `0x18` | u32 | 40 | observed, invariant, unexplained |
| `0x20` | u32 | segment size − 16 (again) | observed |
| **`0x24`** | 16 B | **`shmemUUID`** — 12 significant octets then 4 zero, same shape as the locator address | **proven** — byte-identical to the SPDP-advertised locator of the same participant |
| `0x40` | u32 | an offset near the end; varies with the property block | not identified |
| `0x44`,`0x48`,`0x4c` | u32 | 56, 112, 168 (stride 56) | observed, invariant |
| `0x50` | u32 | consistent with `176 + 8 * received_message_count_max` | two data points (688 @64, 472 @37); needs a third |
| `0x54` | u32 | 4 | observed, invariant |
| **`0x58`** | u32 | **`receive_buffer_size`** | **proven by variation** — set 777216, read 777216 |
| **`0x5c`** | u32 | **`message_size_max`** | **proven by variation** — set 20480, read 20480 |
| **`0x60`** | u32 | **`received_message_count_max`** | **proven by variation** — set 37, read 37 |

Segment size is a function of the property block: 1115312 for the (1048576, 65536, 64) default and 798496
for (777216, 20480, 37). Two points do not determine the formula; not yet derived.

### 5.0 The ring — partially measured (slice 5 in progress, NOT implemented)

Observed from a live Connext 7.3.1 `rtiddsping` publisher/subscriber pair exchanging over shared memory, by
searching the subscriber's user-data segment for the RTPS magic (`52 54 50 53`, RTPS 2.5 §8.3.3.1.1) — a
known needle again, rather than guesswork.

**Established by direct observation:**

- **Records are complete RTPS datagrams stored VERBATIM**, beginning with the `RTPS` magic and parsing
  cleanly: version `02 05`, vendorId `01 01` (RTI), a 12-octet GUID prefix, then ordinary submessages
  (`INFO_DST` `0x0e`, `HEARTBEAT` `0x08`, `INFO_TS` `0x09`, `DATA` `0x15`). **This is the important one:**
  once the ring can be read, the datagrams inside need no special decoding — the existing RTPS parser
  handles them unchanged.
- Records are **packed contiguously and 8-byte aligned** — one record ended at `0x32c` and the next began
  at `0x330`. Consecutive small records sat at a 64-byte stride.
- **Two control blocks 56 bytes apart**, at `0x78` and `0xb0`, matching the 56/112/168 stride already logged
  at `0x44`/`0x48`/`0x4c`. Each holds several byte positions followed by several equal counters.
- **Those positions are absolute byte offsets pointing 20 octets INTO a record** — i.e. just past the
  20-octet RTPS header. Verified at two independent positions: 5316 and 5380 both landed on an `INFO_TS`
  submessage, and `RTPS` sat exactly 20 octets earlier at `0x14b0` and `0x14f0`.
- At the moment of observation the two blocks' positions differed by **exactly one record stride** (5380 vs
  5316 = 64) and their counters by **exactly one** (19 vs 18) — the shape of a producer/consumer pair with a
  single unconsumed record.
- `0x50` held 688 = `176 + 8 * received_message_count_max`, consistent with an 8-byte-per-entry table at 176
  and the ring beginning at 688.

**NOT established, and not to be guessed at:** which block is the producer and which the consumer; whether
688 is in fact the ring base; wraparound behaviour at the end of the buffer; whether an explicit per-record
length exists at all (an RTPS message is self-delimiting via `octetsToNextHeader`, so one may not be needed);
and the synchronisation protocol — the semaphore and mutex keys are known (§4) but their use is unexamined.

### 5.1 The address is per-HOST, and that is what makes it usable

The 12 significant octets were **byte-identical across unrelated processes on different domains**
(`shapes_pub` on domain 0 and `rtiddsping` on domain 7 both advertised
`7d ea 36 2b 3f ac 8e 00 95 6a 49 52`). It identifies the host, not the process — which is exactly what the
co-location test requires. Slice 1's `rti-shmem-locator-host-id` is therefore correctly *named*; RTI's own
name for the field is `shmemUUID`.

### 5.2 The `host_id` property, and why it is a side road

`dds.transport.shmem.builtin.host_id` is documented as *"Host ID used to generate the shared memory
transport network address"*, type unsigned integer, default 0. Sweeping it on a fixed domain gives an exact
mapping: **the low 12 bits only, rendered as four octal digits, one digit per octet, in address bytes 2–5**.

| host_id | | address bytes 2–5 |
|---|---|---|
| 255 | `0o377` | `00 03 07 07` |
| 256 | `0o400` | `00 04 00 00` |
| 65535 | `&0xFFF` = `0o7777` | `07 07 07 07` |
| 65536 | `&0xFFF` = 0 | `00 00 00 00` |

The rule was fitted on a boundary sweep and then **retrodicted two earlier runs exactly**
(`16909060 & 0xFFF` = 772 = `0o1404` → `01 04 00 04`; `3735928559 & 0xFFF` = 3823 = `0o7357` →
`07 03 05 07`), six data points for six.

**This is a side road.** The default address (bytes > 7) does not use this encoding, so the explicit-`host_id`
path and the default path are different generators, and real deployments use the default. It is recorded
because it proves the address is *generated*, and because a peer that sets `host_id` will produce an address
we must still match.

## 6. Slice ladder

1. **Locator recognition** — landed, `75804c6`. `+locator-kind-rti-shmem+`, `rti-shmem-locator-p`,
   `rti-shmem-locator-host-id`, `locator-kind-name`; wired into ADR 0080's `UNADDRESSABLE_PEER` so a refusal
   names the transport instead of printing a number.
2. **Segment layout** — measured; §4 and §5 above. Harness `interop/connext/shmem-layout/`.
3. **Same-host detection** — landed. `dds.xport.rti-shmem:rti-shmem-same-host-p` computes `0x400000 + port`,
   attaches read-only via a new System V surface in `dds-pal/` (`sysv-shm-attach-readonly` / `-create` /
   `-detach` / `-destroy` / `-sap`, one CFFI implementation serving SBCL and Clasp), verifies magic and
   `majorVersion`, and compares the 12 octets at `0x24` against the locator's address.

   It reports **four** outcomes rather than a boolean, because a boolean would merge "that peer is
   elsewhere" with "I could not tell": `(T NIL)` same host · `(NIL NIL)` well-formed but another host, which
   is ordinary and not an error · `(NIL :no-such-segment)` · `(NIL :not-an-rti-shmem-segment)` ·
   `(NIL :unvalidated-shmem-protocol-version)`.

   `run-rti-shmem-recognition-test` drives all five against a synthetic segment it builds itself, so no
   Connext is needed and the failure modes are reachable at all. **Both falsifications were run and went
   red:** deleting the `majorVersion` refusal makes an unmeasured revision report `T` — a confident wrong
   answer, which is precisely what §7 requires be impossible — and short-circuiting the UUID comparison
   makes a foreign host report `T`.

   **Live-validated** against a running Connext 7.3.1 `shapes_pub` (domain 0): its advertised UUID answers
   `T` at both its metatraffic port 7412 and its user port 7413; a wrong UUID at the same live port answers
   `(NIL NIL)`; and the real UUID at a port with no segment answers `(NIL :no-such-segment)`.
4. **Property block** — landed. `rti-shmem-segment-properties` reads `receive_buffer_size`,
   `message_size_max` and `received_message_count_max` plus the segment's own size, and
   `rti-shmem-datagram-fits-p` answers whether a datagram is within what a receiver can carry in one
   message — the shared-memory analogue of the emitted-datagram-size contract of ADR 0079.

   **Every length is corroborated before it is believed.** The size the segment states about itself is a
   number written by another process, so it is re-attached at that size and the kernel decides; a segment
   overstating its extent is refused rather than becoming a bound that later sizes a buffer. The remaining
   plausibility checks are **physical, never policy** — a buffer cannot exceed the segment holding it — so a
   peer legitimately configured with a large `message_size_max` cannot be false-rejected.

   `run-rti-shmem-properties-test` drives exact read-back, the fits/does-not-fit boundary, and three
   refusals. **Falsified:** removing the kernel corroboration makes a segment claiming twice its real size
   return a properties struct carrying the lie. **Live-validated** against a running Connext 7.3.1
   participant, where all three properties equal RTI's own published defaults (1048576 / 65536 / 64) and the
   segment size matches `ipcs` exactly.
5. Ring and framing — **partially measured, not implemented.** Geometry and record format are in §5.0;
   the producer/consumer roles, wraparound and synchronisation are still open. No code reads the ring yet.
6. Receive a real RTPS datagram from Connext over shared memory.
7. Transmit.

## 7. Consequences and risks

- **Version brittleness is the standing risk of route C.** The reconstruction is valid for shmem protocol
  `majorVersion` 2 on Connext 7.3.1. `0x14` carries that version, so an implementation **must refuse a
  segment whose `majorVersion` it was not validated against** rather than misparse it. Route A (§3) is the
  fallback if that becomes untenable.
- **Everything network-facing stays bounds-checked** (NFR-SEC-POSTURE). A shared memory segment written by
  another process is untrusted input exactly like a datagram: every offset and length read from the segment
  is validated against the mapped extent before use, at `(safety 0)` too.
- Attaching is **read-only** (`SHM_RDONLY`) for detection. Nothing in slices 1–3 writes to an RTI segment.
- The measurements are host- and build-specific where noted (`arm64Darwin20clang12.0`). The Linux leg has
  not been measured; CI/Linux is the oracle for anything platform-shaped and this must be re-measured there.
