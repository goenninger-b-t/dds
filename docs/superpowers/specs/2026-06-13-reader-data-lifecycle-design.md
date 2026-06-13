# READER_DATA_LIFECYCLE (autopurge) — design

**Goal:** Implement the READER_DATA_LIFECYCLE QoS (DDS 1.4 §2.2.3.22): a DataReader purges a
NOT_ALIVE instance's cached samples + resources after a configurable delay.
- `autopurge_nowriter_samples_delay` (Duration_t, **default INFINITE**): purge a
  NOT_ALIVE_NO_WRITERS instance's samples this long after it went no-writers.
- `autopurge_disposed_samples_delay` (Duration_t, **default INFINITE**): purge a
  NOT_ALIVE_DISPOSED instance's samples this long after it was disposed.

Both default INFINITE → **no purging by default** (default is a no-op; non-regression is trivial).
Reader-local QoS: NOT advertised in SEDP, NOT RxO-checked.

## Current state
- The reader's per-instance `instance-rec` (src/dds-dcps/entities.lisp) has
  `state` (:alive/:not-alive-disposed/:not-alive-no-writers) + the writers-set; `dr-cache` holds
  cached-samples; `dr-instance-recs` / `dr-instances` track instances. The DCPS `spin` drives the
  announce cadence + the writer-liveliness sweep.
- `%lease-now` (dds.disc::) is the monotonic clock used by the lease/liveliness sweeps.
- QoS slots for READER_DATA_LIFECYCLE do NOT exist (check qos.lisp).

## Design
**A. QoS.** Add `autopurge-nowriter-samples-delay` + `autopurge-disposed-samples-delay` (qos-duration,
default `+duration-infinite+`) to the reader qos (`make-reader-qos`). Reader-local, not SEDP/RxO.

**B. Per-instance NOT_ALIVE timestamp.** `instance-rec` gains `not-alive-since` (an internal-time
stamp, or nil when ALIVE). Set it when the instance transitions ALIVE→NOT_ALIVE (in
`%drain-one-lifecycle` / `%on-writer-vanished`); clear it (nil) on revival to ALIVE
(`%reader-revive-instance`).

**C. Purge sweep.** `%autopurge-sweep dr` (run on the DCPS `spin` cadence, beside the existing
sweeps): for each NOT_ALIVE instance, if its applicable delay is finite AND
`now - not-alive-since >= delay` (disposed → autopurge_disposed_samples_delay; no-writers →
autopurge_nowriter_samples_delay), PURGE: remove that instance's entries from `dr-cache`, the
`instance-rec`, the `dr-instances` view-state entry, and the per-writer drained watermark / sample
maps as needed so the instance is fully forgotten (a fresh sample later starts a NEW instance,
view-state NEW). INFINITE delay → never purge (the common default). Lock discipline: mutate on the
user/spin thread (the same thread that owns dr-cache), never the receiver thread.

## Tests
- Default INFINITE: a disposed/no-writers instance is NEVER purged (samples stay in cache) — the
  no-op default.
- Finite disposed delay: dispose an instance, backdate its not-alive-since past the delay, run the
  sweep → its cached samples + instance-rec are gone; a NEW sample for the same key starts a fresh
  ALIVE instance (view-state NEW, generation counts reset).
- Finite no-writers delay: same via the no-writers path.
- A still-ALIVE instance is never purged; a NOT_ALIVE instance within its delay is not purged.
- Regression: all instance-lifecycle + dataplane tests green (default INFINITE = no behaviour change).

## Out of scope
`autopurge_disposed_samples_delay` interaction with KEEP_LAST history depth nuances; purging
individual read samples vs whole instances (purge whole NOT_ALIVE instance, per §2.2.3.22); the
writer-side already-done autodispose (item 2).
