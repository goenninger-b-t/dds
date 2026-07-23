# RTI Connext shared-memory segment layout — observation harness

Reproduces every measured claim in **ADR 0081 §4–§5**. Nothing here is part of `make interop`; these are
measurement instruments, not pass/fail legs. Read ADR 0081 first — it states what was established, how, and
what is deliberately *not* claimed.

`shmprobe` attaches **read-only** (`SHM_RDONLY`). It never writes to a segment.

## Build

```sh
make
```

## 1. The key mappings (ADR 0081 §4)

With any Connext participant running on domain `D` at participant index `i`, the metatraffic port is
`7400 + 250*D + 10 + 2*i`, and:

| resource | key |
|---|---|
| segment | `0x400000 + port` |
| semaphore | `0x800000 + port` |
| mutex | `0xB00000 + port` |

```sh
ipcs -m | grep 0x0040     # segments
ipcs -s | grep -E '0x0080|0x00b0'   # semaphores and mutexes
```

For domain 0, participant 0 that is `0x00401cf2`, `0x00801cf2`, `0x00b01cf2`.

## 2. The segment header (ADR 0081 §5)

```sh
./shmprobe 401cf2 stat
./shmprobe 401cf2 dump 0 112
```

Cross-check the `shmemUUID` at offset `0x24` against what the same participant advertises over SPDP — that
equality is RTI's own documented co-location test:

```sh
./shmprobe 401cf2 dump 0x24 12
./shmprobe 401cf2 find 7DEA362B3FAC8E00956A4952    # substitute the address from the locator
```

## 3. The property block, by controlled variation

The three fields at `0x58`/`0x5c`/`0x60` were identified by setting them to distinctive values and
observing them appear. To repeat that:

```sh
export NDDSHOME=/Applications/rti_connext_dds-7.3.1
export DYLD_LIBRARY_PATH="$NDDSHOME/lib/$CONNEXTDDS_ARCH:$DYLD_LIBRARY_PATH"
$NDDSHOME/bin/rtiddsping -domainId 8 -publisher -verbosity 2 \
    -qosFile ./hostid-qos.xml -qosProfile HostIdLib::H_NONE
# then, from another shell:
./shmprobe 4024c2 dump 0 112
```

`H_NONE` sets `received_message_count_max=37`, `receive_buffer_size=777216`,
`parent.message_size_max=20480`; expect `37`, `777216`, `20480` at `0x60`, `0x58`, `0x5c`.

> **Trap.** Do **not** name the profile file `USER_QOS_PROFILES.xml` in the working directory. Connext
> auto-loads that name *and* `-qosFile` loads it again; the duplicate profile makes the parse fail, the QoS
> silently reverts to defaults, and the run looks like a negative result. Verbosity 2 shows the parse error.

## 4. The `host_id` sweep (ADR 0081 §5.2)

```sh
./sweep-hostid.sh 0 1 2 3 255 256 257 65535 65536
```

Each run holds the three buffer properties constant and uses one fixed domain, so `host_id` is the only
variable. Expect the low 12 bits of `host_id` rendered as four octal digits, one per octet, in address
bytes 2–5.

## 5. The ring — geometry and synchronisation (ADR 0081 §5.0)

```sh
./ring-roles.sh     # SIGSTOP the subscriber -> which control-block fields are the producer's
./ring-extent.sh    # diff whole-segment snapshots against the cursor -> (cursor, write-offset) pairs
./ring-wrap.sh      # shrink the ring through QoS so it wraps in a couple of minutes
./ring-sync.sh      # SIGSTOP the subscriber -> is the semaphore a counter or a latch?
./semprobe 801cf4   # semaphore  0x800000+port : value + blocked-waiter counts
./semprobe b01cf4   # mutex      0xB00000+port
./semwatch b01cf4 8 # poll one semaphore flat out for 8s — catches a sub-microsecond critical section
```

**Pair every absence-claim with a positive control.** `semwatch` on the mutex only means something if the
same instrument, in the same run, catches the data semaphore — which is known to change. Without that,
"never caught it held" is indistinguishable from "sampled too slowly". That control is what turned the
mutex from inferred into measured.

All four scripts work the same way: **drive the system to a boundary rather than sample it working.**
Stopping the consumer is what separated the producer fields from the consumer fields, and what showed the
semaphore is a wakeup latch rather than a message counter. Shrinking the ring through QoS is what made
wraparound reachable, and varying one property at a time is what pinned each coefficient of the modulus.
Four claims in this ADR were wrong before that discipline was applied consistently — sampling steady state
and generalising is how each of them happened.

`semprobe` issues only `semctl` GET* queries, which read and never modify, so a live peer is not perturbed.

## 6. The `semop` sequence — needs root, so it is yours to run

State observation gave the cursors, the semaphore values and the ring bytes, but it can never give the
*order* of the calls that changed them. This is what supplied it (ADR 0081 §5.0): take the mutex, write the
record and advance the cursor under the lock, release, then raise the data flag with `semctl(SETVAL, 1)`
— the wake follows the unlock, and it is a `SETVAL`, not a `semop(+1)`, which is why the latch never climbs
past 1.

```sh
rtiddsping -domainId 50 -subscriber &
rtiddsping -domainId 50 -publisher -sendPeriod 0.5 &
sudo dtrace -qs trace-semop.d
```

`dtrace` is installed; it needs root, which is the only reason this is a script rather than a result.
Each line prints `sem_num`/`sem_op`/`sem_flg`, which answers directly whether the data semaphore is posted
before or after the mutex is released, and whether `IPC_NOWAIT` (0x800 on Darwin) is what produces the
post-once-do-not-stack behaviour measured in §5. Correlate `semid` against `ipcs -s`: `0x800000+port` is
the data semaphore, `0xB00000+port` the mutex.

## 7. Writing into a live ring (ADR 0081 §6 slice 7)

Everything above reads. These two write, so they run **only** against a throwaway pair on their own domain,
and only ever from your shell — a wrong field here corrupts a running peer instead of merely misreading it.

```sh
DOM=70 ./live-write-retest.sh        # ring-level:        does RTI's consumer DRAIN what we wrote?
DOM=78 ./live-userdata-retest.sh     # application-level: does RTI's SUBSCRIBER count the sample?
```

Both stage the pair, **`SIGSTOP` the publisher** and write while it is frozen. Freezing rather than killing
is not a detail: a killed publisher makes RTI's consumer unmatch it, after which it will not consume from
that source however correct the record is — three live runs were spent before that was named. The
publisher is signalled by *process group*, because `rtiddsping` is a shell wrapper around the real binary.

`ring-records.lisp` does the record work for both, using this stack's own RTPS parser rather than a second
hand-rolled decoder. Four modes, chosen by `RTI_MODE`:

| mode | what it does | touches shared memory |
|---|---|---|
| `analyze` | parse a captured record (`RTI_HEX`) and say what it is | no |
| `selftest` | twelve checks on the parse/patch path, three of them falsifications | no |
| `replay` | write a captured record verbatim | yes, one write |
| `inject` | re-issue the newest user sample at `SN + 1` | yes, one write |

Run the off-line ones anywhere, with no Connext present:

```sh
RTI_MODE=selftest RTI_HEX=/tmp/rt-record.hex ../../../scripts/with-sbcl.sh --non-interactive \
    --load ./ring-records.lisp
```

**Why `inject` exists at all.** A replayed record is a *duplicate*: everything still in the ring has already
been delivered, so RTPS drops it before the application (§8.4.13.2, §8.4.12). `replay` can therefore only
ever answer the ring-level question. `inject` rewrites `writerSN` to the reader's next expected value, which
is the one property a verbatim replay can never have.

**The control is what makes the result mean anything.** `live-userdata-retest.sh` requires the subscriber's
`issue received` counter to stand still for two seconds *while the publisher is frozen* before it writes. If
the counter moves then, the freeze did not take and the run aborts — otherwise a still-running publisher
would be indistinguishable from success.

## Hygiene

System V segments outlive the process that created them. Remove the ones a probe run created, and leave
everyone else's alone:

```sh
ipcs -m
ipcrm -m <id>
```
