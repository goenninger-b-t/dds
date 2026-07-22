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
```

All four scripts work the same way: **drive the system to a boundary rather than sample it working.**
Stopping the consumer is what separated the producer fields from the consumer fields, and what showed the
semaphore is a wakeup latch rather than a message counter. Shrinking the ring through QoS is what made
wraparound reachable, and varying one property at a time is what pinned each coefficient of the modulus.
Four claims in this ADR were wrong before that discipline was applied consistently — sampling steady state
and generalising is how each of them happened.

`semprobe` issues only `semctl` GET* queries, which read and never modify, so a live peer is not perturbed.

## Hygiene

System V segments outlive the process that created them. Remove the ones a probe run created, and leave
everyone else's alone:

```sh
ipcs -m
ipcrm -m <id>
```
