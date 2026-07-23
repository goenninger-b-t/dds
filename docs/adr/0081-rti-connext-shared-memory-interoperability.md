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
| `0x50` | u32 | **`176 + 8 * received_message_count_max`** — the ring-base candidate | **predicted then confirmed** — 240 predicted for count 8, 240 observed (688 @64) |
| `0x54` | u32 | 4 | observed, invariant |
| **`0x58`** | u32 | **`receive_buffer_size`** | **proven by variation** — set 777216, read 777216 |
| **`0x5c`** | u32 | **`message_size_max`** | **proven by variation** — set 20480, read 20480 |
| **`0x60`** | u32 | **`received_message_count_max`** | **proven by variation** — set 37, read 37 |

Segment size is a function of the property block and fits
`receive_buffer_size + message_size_max + align8(240 + 15 * count)` across all three measured
configurations: (1048576, 65536, 64) → 1115312 exactly, (2048, 2048, 8) → 4456 exactly, and
(777216, 20480, 37) → 798496 with one 8-byte rounding. Three points and a rounding is a fit, not a proof.

### 5.0 The ring — fully measured (slice 5); read by code (slice 6), writer specced (slice 7)

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
- **Those positions sat 20 octets into a record** — i.e. just past the 20-octet RTPS header — at two
  independent positions: 5316 and 5380 both landed on an `INFO_TS` submessage, with `RTPS` exactly 20 octets
  earlier at `0x14b0` and `0x14f0`. ⚠️ **They are NOT absolute offsets**, as the running total below shows;
  they coincided with offsets only because that 1 MiB ring had not yet wrapped.
- At the moment of observation the two blocks' positions differed by **exactly one record stride** (5380 vs
  5316 = 64) and their counters by **exactly one** (19 vs 18) — the shape of a producer/consumer pair with a
  single unconsumed record.
- `0x50` held 688 = `176 + 8 * received_message_count_max`, consistent with an 8-byte-per-entry table at 176
  and the ring beginning at 688.

**The producer/consumer split is WITHIN each block, not between the two.** Established by stopping the
reader rather than reasoning about it: `SIGSTOP` the subscriber so it cannot consume, let the publisher keep
sending, and see which fields still move (`interop/connext/shmem-layout/ring-roles.sh`). Reading the first
eight u32s of a block at offset *B*:

| field | while the consumer is stopped | role |
|---|---|---|
| *B*+`0x00` | advances by 64 — one record stride — per message | **producer** position |
| *B*+`0x04`, `0x08`, `0x0c` | frozen | **consumer** positions |
| *B*+`0x10` | advances, always *B*+`0x00` plus 4 | **producer** |
| *B*+`0x14`, `0x18` | frozen | **consumer** counters |
| *B*+`0x1c` | advances by exactly 1 per message | **producer** message count |

On `SIGCONT` every field converges as the consumer drains the backlog. **This corrects the reading of the
static snapshot in the paragraph above** — a single sample showed block A one record ahead of block B and
invited the conclusion that A produced and B consumed. It does not: both blocks carry both roles, and A
tracks B at a constant +64 in every position and +1 in every counter at all times. That constant offset
between the two blocks is observed and **remains unexplained**.

**Shrinking the ring through QoS (`interop/connext/shmem-layout/ring-wrap.sh`) added three results and one
useful failure.**

- **`0x50 = 176 + 8 * received_message_count_max` — predicted, then confirmed.** With
  `received_message_count_max` = 8 the value 240 was predicted before the run and 240 was observed (it was
  688 at the default 64). A relationship that predicts correctly is worth more than one fitted to two points.
- **The counter at *B*+`0x1c` WRAPS — it is an index, not a running total.** At `count_max` = 8 it cycled
  0,1,…,8,0,1,… At the default 64 it had only reached ~21 during observation and merely looked monotonic.
  This corroborates the 8-byte-per-entry descriptor table of `received_message_count_max` entries at 176,
  and **corrects the "producer message count" wording in the table above**: it advances by one per message
  and wraps at `count_max`.
- **Segment size fits `receive_buffer_size + message_size_max + align8(240 + 15 * count)`** across all three
  measured configurations: (1048576, 65536, 64) → 1115312 exactly; (2048, 2048, 8) → 4456 exactly;
  (777216, 20480, 37) → 795 rounds to 800, giving 798496. A three-point fit with one rounding, so recorded
  as consistent-with rather than proven.
- **The ring is SOLVED for geometry.** Diffing whole-segment snapshots against the cursor
  (`interop/connext/shmem-layout/ring-extent.sh`) gives the write offset of each record directly, because
  the bytes that changed *are* the record just written. Across 54 consecutive samples the offset was exactly
  `cursor + 236`, and at the wrap it fell from 4336 to **304** where an unwrapped value would have been
  4400 — a difference of exactly 4096. The whole run, wrap included, fits

      offset = 304 + ((cursor - 68) mod 4096)

  `2 * receive_buffer_size` is **ruled out** — four configurations with `receive_buffer_size` and
  `message_size_max` unequal all have `2 * receive_buffer_size` **exceeding the whole segment**, which the
  ring cannot.

  🔴 **BUT THE MODULUS IS *NOT* `receive_buffer_size + message_size_max`, and an earlier revision of this
  ADR wrongly said it was.** A second wrap at `received_message_count_max` = 16, with `receive_buffer_size`
  and `message_size_max` unchanged at 2048 each, gave a **different modulus**:

  | `count` | ring start | modulus | `rbs + msm` |
  |---|---|---|---|
  | 8 | 304 | 4096 | 4096 |
  | 16 | **368** | **4160** | 4096 |

  Same `rbs + msm`, different modulus, so the modulus depends on `count` as well. The 4096 of the first run
  was a coincidence of that configuration. **Ring start is `240 + 8 * count`** — equivalently the value at
  `0x50` plus 64 — confirmed at both points, and it also refutes *both* candidates the previous revision
  offered (`176 + 16 * count` predicts 432, `size - ring_length - 56` predicts 424; the measurement is 368).

  **The mapping is now complete, with every parameter varied INDEPENDENTLY before anything was asserted** —
  the discipline the correction above demanded:

      offset      = ring_start + ((cursor - 68) mod M)
      ring_start  = 240 + 8 * received_message_count_max          (= the value at 0x50, plus 64)
      M           = receive_buffer_size + message_size_max + 8 * received_message_count_max - 64

  | `rbs` | `msm` | `count` | M observed | formula | what was varied |
  |---|---|---|---|---|---|
  | 2048 | 2048 | 8 | 4096 | 4096 | baseline |
  | 2048 | 2048 | 16 | **4160** | 4160 | `count` alone |
  | 4096 | 2048 | 8 | **6144** | 6144 | `receive_buffer_size` alone |
  | 4096 | 4096 | 8 | **8192** | 8192 | `message_size_max` alone |

  Each of the last three moved exactly one parameter from the baseline, so each coefficient is measured
  rather than assumed — and the last two rows were **predicted before the run**, along with their segment
  sizes (6504, 8552) and ring starts (304, 304), all of which landed. The additive constant 68 is invariant
  across all four.
- **The segment-size formula is confirmed, not fitted.** `receive_buffer_size + message_size_max +
  align8(240 + 15 * received_message_count_max)` was used to PREDICT four new configurations before
  measuring them, and all four landed exactly: (4096, 2048, 8) → 6504, (8192, 2048, 8) → 10600,
  (4096, 2048, 16) → 6624, (16384, 4096, 8) → 20840. Seven configurations total. `0x50` likewise predicted
  240, 240, 304, 240 and read back 240, 240, 304, 240.
- **The cursor is a CUMULATIVE BYTE COUNT, not an offset into the segment — and this falsifies the claim
  above that "those positions are absolute byte offsets".** Run long enough (90 samples), the producer
  position climbed monotonically to **6084 in a segment of 4456**. A number larger than the segment cannot
  be an offset into it, so no further experiment is needed for the negative. The earlier reading held only
  by coincidence: in the 1 MiB default ring the running total had not yet exceeded the segment size, so
  cursor−20 happened to land on the `RTPS` magic. **The ring offset must therefore be derived from the
  cursor** — by a modulus not yet determined — and `RTPS` at cursor−20 is true only before the first wrap.

- **The per-record framing is `align8(datagram_length)` — validated against a live peer, not assumed.** A
  writer must advance the producer cursor by a record's footprint; slice 7a used `align8(len)` and this
  measures whether that is what RTI does. With `perf_pinger`'s variable payload over shared memory, all
  records in a run are one size, so the gap between consecutive `RTPS` magics *is* the footprint. Across five
  payloads the stride equals `align8(D)` exactly, where `D` is the true datagram length read from the RTPS
  submessages (`D = 92 + payload` for this type):

  | payload | D | align8(D) | measured stride |
  |---|---|---|---|
  | 40 | 132 | 136 | 136 |
  | 100 | 192 | 192 | 192 |
  | 200 | 292 | 296 | 296 |
  | 400 | 492 | 496 | 496 |
  | 800 | 892 | 896 | 896 |

  So the slice-7a advance is not merely self-consistent — it is byte-for-byte what RTI does. (`perf_pinger`
  fills its payload with a counting pattern, so the record's true end is visible; `rtiddsping`'s fixed size
  could not have shown the relationship.)

⚠️ **`message_size_max` has a floor set by discovery.** At 1024 the participant's own SPDP announcement
(1020 octets) no longer fit and discovery failed outright — Connext logs
`MIGGenerator_addData:... message size max ... too small for propagating the participant discovery
information`. Anything we advertise for our own segment must clear that, or nothing will discover us.

**Synchronisation — the semaphore is a WAKEUP LATCH, not a message counter.** Every segment is accompanied
by two System V semaphore sets (§4), each holding a single semaphore. Read statically
(`interop/connext/shmem-layout/semprobe.c`, `semctl` GET* queries only, which read and never modify) the
first sits at 0 with one process blocked waiting for it to increase, and the second at 1 with no waiters —
which *looks* exactly like a counting "data available" semaphore plus a binary mutex. That reading is wrong,
and `ring-sync.sh` shows it by stopping the consumer:

| state | `0x800000+port` value | waiters |
|---|---|---|
| consumer parked, nothing pending | 0 | 1 |
| **consumer SIGSTOPped, 10 messages produced** | **1** | 0 |
| consumer resumed, backlog drained | 0 | 1 |

A counting semaphore would have reached 10. It reaches 1 and stays there, so the producer posts once and does
not stack while the flag is already raised; the consumer wakes, drains **everything** using the ring cursors,
and re-parks. **The pending-message count lives in the cursors, not the semaphore** — consistent with the
cursors being the authority for everything else.

**The mutex at `0xB00000+port` IS taken on the data path — now measured, not inferred.** Observing it at
rest proved nothing, so `semwatch.c` polls `GETVAL` in a tight loop (~7.6M samples/s) while four publishers
drive one subscriber at ~170 messages/s:

| semaphore | resting | caught off-resting | value range | waiters seen |
|---|---|---|---|---|
| `0x800000+port` (control) | 0 | 49091 / 62.0M = 0.079 % | 0..1 | 1 |
| **`0xB00000+port` (mutex)** | 1 | **2190 / 61.0M = 0.0036 %** | **0..1** | **1** |

The control matters: the data semaphore is *known* to change, so catching it proves the instrument can see a
transition at all — without it, "never caught" would be indistinguishable from "sampled too slowly". The
mutex was caught **held** 2190 times, and another process was observed **blocked** on it, so it is both used
and contended. A 0.0036 % duty cycle at ~170 messages/s puts the critical section around **210 ns per
message**, consistent with a few cursor updates.

The same run re-confirms the wakeup latch independently and at 170× the earlier traffic: across 62 million
samples the data semaphore **never exceeded 1**.

**The producer protocol — the syscall ORDER, traced directly.** State observation gives *what* changed,
never the *order* of the calls that changed it. That needed syscall tracing, which macOS SIP blocks in the
`syscall` provider but not in the **`pid`** provider against a third-party process — with the catch that
`copyin` is disabled there under SIP, so the `sembuf` (op/flag bits) cannot be read, only the scalar register
arguments (`semid`, `semctl` command and value). Those suffice for the order.
`interop/connext/shmem-layout/trace-semop.d` traced `rtiddsping` for ~20 identical message cycles. Each
cycle, the producer does exactly:

1. `semop(mutex 131092, take)` — lock,
2. write the record and advance the producer cursor under the lock (~2 µs held),
3. `semop(mutex 131092, release)` — unlock,
4. `semctl(data-sem 131093, SETVAL, 1)` — raise "data available", ~5 µs **after** the unlock.

Three facts fall out, and they change how a writer must be built:

- **The wake is `semctl(SETVAL, 1)`, not `semop(+1)`.** `SETVAL` is idempotent, which is exactly why the
  latch never climbs past 1 (§ above): repeated raises while it is already 1 leave it at 1, where `+1` would
  accumulate. `val=1` was read directly off the register on every cycle, not inferred. A writer of ours must
  signal the same way — raise the flag with `SETVAL 1`, never `semop`.
- **The post follows the unlock.** Write under the lock, release, *then* signal — so the woken consumer does
  not immediately contend on a still-held lock.
- **The consumer never takes the mutex.** In the whole trace the subscriber touches only the data semaphore;
  it never appears on `131092`. So the mutex serialises **multiple producers** against each other, not
  producer against consumer — and the consumer reads locklessly via the cursor, exactly as this stack's own
  reader (`rti-shmem-read-record`, slice 6b) already does. A writer must take the mutex to coordinate with
  RTI's own senders; a reader correctly does not.

What SIP kept out of reach is the `sem_flg` bits — specifically whether the mutex take sets `SEM_UNDO`. That
is not left to inference: a writer of ours will set `SEM_UNDO` on its mutex take regardless, so that a crash
of our process cannot leave RTI's ring mutex locked forever. Using it is strictly safer whether or not RTI
does, so the unmeasured bit does not gate correctness.

**`0x44`/`0x48`/`0x4c` = 56, 112, 168 are offsets from `0x40`**, giving `0x78`, `0xb0` and `0xe8`: two
control blocks (A = producer at `0x78`, B = consumer at `0xb0`, confirmed by A leading B by exactly one
record) and a **descriptor table** at `0xe8`, not a third block.

**The descriptor table holds one `(-datagram_length, 0)` entry per record, indexed by the wrapping counter.**
At rest it reads `-64, 0` repeating (the empty/idle value); under traffic it fills one entry per record,
tracking the counter. Each entry is the **exact** RTPS datagram length, negated — measured `-292` for a
payload-200 record whose datagram is 292 bytes, while the *cursor* advanced by `align8(292) = 296`. So the
two are distinct: the ring is packed at the 8-byte-aligned stride, and the table records each record's true
length for the consumer. rtiddsping hid the distinction because `align8(64) = 64`.

**This makes slice 7a's writer state-incomplete for a live write, though its framing is right.** Per record
the producer updates, besides writing the record: block A's position fields and its counter, and it appends
`(-D, 0)` to the descriptor table at the counter's slot. Slice 7a updates only the cursor at `0x78`. Which of
these RTI's *consumer* actually reads — and therefore which a written record must carry to be accepted — is
still unproven (this stack's reader needs none of them), but the descriptor table plainly encodes per-record
lengths, so a live-write writer should maintain it. That is the concrete remaining work for 7b, now named
down to specific fields rather than "the framing".

**The producer's complete per-record write-set — mapped by stopping the consumer.** With the consumer
`SIGSTOP`ped so only the producer moves, each control block splits cleanly into producer-written and
consumer-written `u32`s (both blocks share the same shape):

| field | block A (`0x78`) | block B (`0xb0`) | moves when only the producer runs? |
|---|---|---|---|
| position | idx 0, 4 (`0x78`, `0x88`) | idx 0, 4 (`0xb0`, `0xc0`) | **yes — producer** |
| counter | idx 7 (`0x94`) | idx 7 (`0xcc`) | **yes — producer** |
| the rest | idx 1,2,3,5,6 | idx 1,2,3,5,6 | no — consumer-owned, frozen |

Block A leads block B by exactly one record throughout (A a head, B a tail; the reason for two is
unexplained but both are producer-maintained). So per record the producer writes the record, advances
`A.{0,4}` and `B.{0,4}` to the new positions, bumps `A.7` and `B.7`, and appends `(-D, 0)` to the descriptor
table at the counter slot. **That is the full set slice 7b's writer must replicate** — slice 7a writes one of
these seven fields (`0x78`) plus the record. What is still unproven is which subset RTI's *consumer* reads to
*accept* a record; a live write should replicate all of it and be validated against a throwaway participant.

⚠️ **A methodological note worth keeping.** An attempt to compare the blocks under one publisher versus four
found no segment at all in the four-publisher case: the port scan only covered participant indices 0 and 1,
and five participants occupy 0 through 4. The run failed for a reason that had nothing to do with the
question being asked — which is its own hazard, because a scan that silently finds nothing looks exactly
like a system with nothing to find.

**The `semop` sequence is the one remaining unmeasured piece, and it is NOT blocked by the platform.** An
earlier revision recorded it as likely unobservable on macOS because SIP blocks syscall tracing. That was
asserted without being tested, and testing it says otherwise: `dtrace` and `dtruss` are both installed. What
they need is **root**, which the reconstruction has no business acquiring for itself — so
`interop/connext/shmem-layout/trace-semop.d` is provided ready to run:

    sudo dtrace -qs interop/connext/shmem-layout/trace-semop.d

with a Connext pair exchanging over shared memory. It prints `sem_num`/`sem_op`/`sem_flg` per call, which
gives the ordering directly — whether the data semaphore is posted before or after the mutex is released,
and whether `IPC_NOWAIT` is what produces the observed post-once-do-not-stack behaviour.

State observation cannot answer this: cursors, semaphore values and segment bytes reveal *what* changed,
never the *order* of the calls that changed them.

**The two control blocks are NOT per-sender.** Comparing one publisher against three (with the participant
index scanned across its full range, which an earlier attempt failed to do):

| publishers | samples received | A@`0x78` counter | B@`0xb0` counter | A − B |
|---|---|---|---|---|
| 1 | 17 | 18 | **17** | +64 bytes, +1 |
| 3 | 51 | 54 | **53** | +64 bytes, +1 |

The offset between the blocks is **invariant to the number of senders**, so they do not partition senders.
B's counter tracks records actually taken — exactly the 17 samples in the first run, and 53 against 51
samples in the second, the excess being protocol records (heartbeats and the like) that are also records in
the ring. **A sits exactly one record ahead of B at all times**, which is the shape of a (next, current)
pair rather than two independent structures.

**Within a block, fields 2–4 sit above fields 0–1 by exactly 4 bytes per SENDER** — swept over 1, 2, 4 and
6 publishers and matching 4, 8, 16 and 24 exactly. Over the same sweep A − B stayed at +64 bytes and +1
counter throughout, so the per-sender quantity lives *inside* a block while the A/B relationship does not
depend on it at all. Four points, one parameter varied, prediction matching at each — this one is a result,
not the two-point lead it started as.

**Still NOT established, and not to be guessed at:** what the A/B one-record offset MEANS (the shape is
clear — a (next, current) pair — but the purpose is not); the `sem_flg` bits (SIP-blocked; handled by using
`SEM_UNDO` defensively rather than by observing RTI) (and whether the
56/112/168 stride implies a third); the meaning of the two position families four bytes apart; whether 688
is the ring base — it is the value at `0x50`, equals `176 + 8 * received_message_count_max`, and one baseline
producer position of 708 sits exactly 20 octets above it, but that is suggestive, not proof; wraparound
behaviour; whether an explicit per-record length exists at all (an RTPS message is self-delimiting via
`octetsToNextHeader`, so one may not be needed); and the synchronisation protocol — the semaphore and mutex
keys are known (§4) but their use is unexamined. Only 8 of the 14 u32s in each 56-byte block have been read.

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
5. Ring, framing and synchronisation — **fully measured** (§5.0): record format, geometry with every
   coefficient independently varied, the wakeup-latch signalling, and the producer protocol (take mutex →
   write → release → `semctl(SETVAL,1)`) traced directly. The consumer is lockless; the mutex serialises
   producers.
6. **Receive** — (a) landed: the ring address arithmetic as code, tested against the nine measured
   (cursor → offset) pairs rather than against a second copy of the formula. (b) landed:
   `rti-shmem-read-record` copies the record the producer cursor designates out of a live ring, refusing
   with `:not-an-rtps-record` rather than handing on a torn or mislocated read. **Live-validated against a
   Connext 7.3.1 ring**, returning datagrams that parse as RTPS 2.5, vendorId `0x0101`, `INFO_TS` first —
   the first RTPS datagram this stack has read out of an RTI shared-memory segment.

   ⚠️ It is an **observer, not a receive path**: it takes no lock. The mutex is measured as real and
   contended, so a delivery path must honour it, and that needs the `semop` ordering (still unmeasured).
   The magic check is what makes the unlocked read safe to use — refusal instead of corruption.
7. **Transmit.**
   - (a) landed. A System V *semaphore* PAL surface (`sysv-sem-open`/`-create`/`-op`/`-setval`/`-getval`/
     `-destroy`, and `sysv-shm-attach-readwrite`) plus `rti-shmem-write-record`, which follows the measured
     protocol: take the ring mutex with `SEM_UNDO`, write the record at the producer cursor and advance it,
     release, then raise the data flag with `semctl SETVAL 1`. `run-rti-shmem-write-roundtrip-test` builds a
     real RTI-shaped receiver (segment + mutex set + data set) and proves the write and read paths are
     inverses through actual System V objects — two records, so the 8-byte-aligned advance is exercised, not
     just placement; the data flag is confirmed raised and the mutex confirmed released. Falsified two ways
     (remove the wake → the flag-raised check fails; drop the advance → the second record fails to read
     back). `SETVAL` is gated on `dds.pal:sysv-sem-setval-reliable-p`: on Clasp/macOS-arm64 its variadic
     value mispasses (ADR 0013), so the writer *refuses* with `:setval-unavailable` rather than landing an
     un-signalled record; SBCL (both platforms) and Clasp/Linux are unaffected. 582/582 both impls on macOS,
     582/582 SBCL on Linux where `SEM_UNDO` and `SETVAL` were both confirmed to work.
   - (b) **code done; live validation deferred.** `rti-shmem-write-record` now writes the *full* producer
     control state under the lock (`%rti-shmem-publish-record`): block A (head) and block B (tail) positions
     and counters, and the `(-datagram_length, 0)` descriptor entry — the complete write-set measured in
     §5.0, not just the cursor. `run-rti-shmem-write-roundtrip-test` verifies every field (A leads B by one
     footprint, both counters bump, the descriptor is the negated length) and that write/read remain
     inverses; falsifying the descriptor sign or the counter bump turns it red. Two facts stay unvalidated
     against a **live** peer — the descriptor slot index (counter mod count_max) and the initial counter
     relationship — and a live write is the one action that corrupts rather than misreads if wrong, so it
     was done against a **throwaway** subscriber, never a production peer.
   - (c) **live result: the write executes but RTI's consumer does NOT yet accept it.** Against a throwaway
     `rtiddsping` subscriber (publisher stopped so the ring was drained), the writer wrote a real captured
     record cleanly — no crash — and advanced the producer fields exactly (head `388 → 452` = +align8(64),
     the `0x88` field, and the producer counter `6 → 7`). But the consumer did **not** drain it: the consumer
     position and counter stayed put (`idx1` = 388, consumer counter = 6, against producer counter 7 — one
     unconsumed record). **So the synthetic round-trip passing was not sufficient for interop**, which is the
     result the live test existed to find. It also localises the fault: in the drained BEFORE state the two
     producer position fields differ — `idx0 = 388`, `idx4 = 392` (a `+4` relationship) — but the writer set
     *both* to the new head, collapsing it; `idx4` was mapped as a duplicate of the head from the
     consumer-stopped run, where they happened to read equal.
   - (d) **`idx4` corrected, then confirmed on a clean live run.** `idx4 = idx0 + 4` at rest (nine
     snapshots; the sole `+8` reading was a contaminated run where the publisher's real binary outlived a
     wrapper-only kill and kept writing). A clean throwaway-subscriber run — publisher's process group killed
     and verified dead first — showed the drained BEFORE at `idx0=516, idx4=520` (+4) and the write advancing
     the head by exactly +64. Fix stands.
   - (e) **descriptor slot corrected — off by one, measured on that same clean run.** The live producer's
     table showed counter 6 → slots 0–4 filled, counter 8 → slots 0–6: the record taking the counter from
     `C` to `C+1` fills slot `C-1`, not `C`. `%rti-shmem-publish-record` wrote slot `a-cnt`; it now writes
     `a-cnt - 1` (RTI's counter is 1 on a fresh ring, so `a-cnt >= 1` and this never underflows in practice),
     and the synthetic test initialises the counter to 1 so the first record lands in slot 0. Falsifying it —
     reverting to slot `a-cnt` — turns the test red.
   - **Still open: acceptance.** With `idx4` right but the slot off by one, the clean run's consumer did not
     advance (`idx1`/`idx5` unchanged) — it read the descriptor from the empty slot 7. The slot fix is the
     data-confirmed reason and the next thing to live-retest; whether it is the *last* fix is only knowable
     by re-running `live-write-retest.sh` and watching the consumer counter advance.

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
