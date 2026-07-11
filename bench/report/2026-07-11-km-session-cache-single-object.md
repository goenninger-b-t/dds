# KM session-key cache: single-object publication — before/after (ADR 0059)

**Change.** The KM session-key caches published their discriminant and their derived key in **separate
slots**. Two threads missing concurrently with different `session_id`s could interleave their stores and
leave the KM advertising id `S1` next to `key(S2)`; a later hit on `S1` then returns the **wrong key**
(fail-closed — a wrong key cannot forge a GCM tag, so the datagram drops — but a *silent* drop). ADR 0059
publishes `(discriminant, key)` as **one immutable `session-cache` object** with a single store, so a
reader sees either the old pair or the new pair, never a mix.

This is on the per-sample AEAD path (every `encode`/`decode-serialized-payload`, every submessage and
SRTPS wrap resolves its session key here), so it needs a number.

**Method.** SBCL. The cache **hit** path in isolation (3 000 000 iterations, warm), and a full 256-byte
AEAD seal for context (200 000 iterations). *Before* = `4a1fb08` (the two-slot publication), measured by
stashing the change; *after* = this WP. Same image, same run.

| | before (2 slots) | after (1 object) | delta |
|---|---|---|---|
| session-key cache **hit** | 6.6 ns/op | 7.8 ns/op | **+1.2 ns** |
| full 256 B AEAD seal (context) | 752.1 ns/op | 749.1 ns/op | −3.0 ns (noise) |

**Reading it honestly.** The lookup itself got ~1.2 ns slower — one extra indirection, since the key is
now reached through the cache object rather than from its own slot. That is a real ~18 % regression *on
the lookup*, and a **0.16 %** cost on the operation the lookup exists to serve: the cache hit is ~1 % of
the AEAD call it feeds. The measured end-to-end seal is unchanged within noise.

**Verdict: accepted.** 1.2 ns per sample buys the removal of a *reachable* concurrency hazard — not a
theoretical one. `start-node` runs up to **three** receiver threads (unicast UDP, multicast UDP, SHMEM)
that all feed `%handle-datagram` and can decode datagrams from the same peer under the same participant
KM, while `session_id` is read **off the wire** and can therefore vary per datagram. The old design was
safe only because conformant peers happen to use a fixed `session_id` — an accident, not an invariant. It
also discharges the ADR 0038(a)/0039(d) forward requirement, which would otherwise have obliged a future
`rtps_protection` rekeying WP to harden this itself.
