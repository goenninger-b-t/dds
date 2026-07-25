# deadline — cross-vendor DEADLINE / REQUESTED_DEADLINE_MISSED (DDS 1.4 §2.2.3.7, §2.2.4.1)

A Connext `ShapeType` writer that publishes at a steady rate and then **deliberately stops**, so a
peer's `REQUESTED_DEADLINE_MISSED` must start climbing.

```sh
export NDDSHOME=/Applications/rti_connext_dds-7.3.1 CONNEXTDDS_ARCH=arm64Darwin20clang12.0
make                                                  # -> deadline_pub (+ RTI dylib symlinks)
./deadline_pub 22 1000 8 30                           # domain, offered-deadline-ms, samples, seconds
# ours, in another terminal (port = PB + DG*domain + d1 = 7400 + 250*22 + 10):
run-deadline-subscriber :domain 22 :deadline-ms 2000 \
  :advertise-address "127.0.0.1" :peers "127.0.0.1:12910"
```

## Two things this harness gets right, both learned the hard way

**The writer waits for a MATCH before its first write.** It is VOLATILE with the default KEEP_LAST
history, so anything written before the reader matches is simply gone. Without the wait the peer
reports *zero samples and zero deadline misses* — which reads exactly like a broken deadline
implementation rather than the ordinary late-joiner rule.

**It stays alive and matched after going quiet.** Exiting would unmatch the endpoint, and an
unmatched reader has no deadline to miss, so the status would never fire.

## Why `USER_QOS_PROFILES.xml` is here

Connext's *default* transport configuration does not meet this stack's DCPS participant on this
machine — the reader never even processes the SEDP announcement (`%match-remote-endpoint` is never
called). Pinning the peer to loopback with an explicit initial peer, the same profile the
`interop/appendable` peers use, makes it match immediately. This is a harness/transport fact, not a
protocol one; the RxO decision itself then reports **DEADLINE RxO compatible**.

`offered <= requested` is the rule (§2.2.3.7): the writer offers 1000 ms, the reader requests
2000 ms, so they match and the reader's clock decides.

## Clean-room (NFR-IP)

Committed: the driver, the Makefile, this README, the QoS profile. **Not** committed: `rtiddsgen`
output, the binary, the RTI dylib symlinks — all generated at build time and git-ignored.
