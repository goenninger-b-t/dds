# The ACKNACK path rebuilt the matched-reader set on every sample

**NFR-MEM / FR-PF-7 · arm64 (Apple silicon), SBCL · `make gate-mem`, 60000 samples, own process per arm**

| | before | after | delta |
|---|---|---|---|
| COPY | 1389.3 | **1329.2** / 1329.4 / 1328.1 | **−60.1** |
| RETURN | 1183.8 | **1120.3** / 1117.5 / 1121.7 | **−63.5** |

Ceilings lowered **1420 → 1360** (COPY) and **1215 → 1155** (RETURN). x86_64 keeps its dash.

## The defect

`%matched-reader-keys` returns the 16-octet GUIDs of every matched **reliable** remote reader — the key
set `writer-purge-acked` takes the minimum acked-base over. It ran on **every inbound ACKNACK**, roughly
once per sample, and rebuilt from scratch:

```lisp
(loop for remote in (%matched-endpoints node)          ; node lock + a fresh cons per matched endpoint
      for guid = (dds.rtps.discovery:endpoint-data-guid remote)
      for q = (dds.rtps.discovery:endpoint-data-qos remote)
      when (and (%reader-guid-p guid) q (eq (dds.qos:qos-reliability q) :reliable))
        collect (copy-seq guid))                        ; + 32 B per reader + a cons per key
```

**The value changes only on match, unmatch or prune** — a discovery event, not a data event. Rebuilding it
per sample is the same defect shape as ADR 0087 (the TX key-hash scratch) and ADR 0088 (the proxy-key
GUID): a *discovery-stable* value recomputed on a *per-sample* path.

It also took the node lock on the receiver thread once per sample to do it.

## The fix

Memoized on the node, on the invalidation seam that already exists for exactly this class. The sibling
destination memos — `match-dest-cache` (`%match-destinations-prefixed`) and `reader-push-cache`
(`%reader-push-targets`) — are dropped wholesale by `%invalidate-dest-cache`, which every match / unmatch /
prune already calls, and whose docstring says in as many words: *"If you add a mutation of
%matched-endpoints … call this from it."* This value's input **is** the matched-endpoint set, a subset of
theirs, so it shares both the seam and its generation guard rather than inventing a second one.

Three details, each of them load-bearing:

- **`:NONE` is the miss sentinel, not `NIL`.** `NIL` — no matched reliable reader — is a legitimate value
  that must be cached too, and it is the value on the whole pre-match path.
- **The store is guarded by the generation.** `%matched-endpoints` takes the node lock itself, so an
  unmatch can land between the cache miss and the store. Caching a value resolved across an invalidation
  would be permanent. This mirrors `%match-destinations-prefixed` exactly.
- **The SPDP locator-update invalidation is over-eager for this value and deliberately left that way.** A
  locator change cannot alter the key set, so the extra drop is wasted work — on a path that runs at
  discovery rate. Special-casing it would buy nothing and would introduce the possibility of
  under-invalidating, and *a stale key set is silent data loss or an unbounded history*: a departed reader
  still pinning the purge watermark, or a live one no longer holding it.

The returned list is now **shared**, so callers must treat it and its GUIDs as read-only — all five do
(they only ever loop over it, or test it with `consp`). Handing the same arrays to `get-reader-proxy`
repeatedly is safe by **its** contract, which is explicit about it: a lookup does not retain the key and a
create copies it (`%retained-endpoint-key`, ADR 0088). And safe again by this one: an entry is built once
per invalidation and never mutated.

## Why the win is bigger than the probe said

The receive-pipeline bisect attributed ~49 B/sample to this call inside `%on-user-acknack`. The measured
end-to-end win is **−60 / −63**, because `%matched-reader-keys` has **four** hot-path callers, not one —
the ACKNACK purge, the app-ack purge and its unacked count, and the `consp` liveness test. This is the
third time this session that the window under-reported a win: rank with the windows, **size with the gate**.

## Verification

SBCL 623/623, Clasp 623/623, `gate-hotpath` PASS, `gate-nocond` PASS, `gate-mem` PASS with both ceilings
lowered.

## Session position

Three slices, all measured end-to-end:

| | start | now | total |
|---|---|---|---|
| COPY | 1550.0 | **1329.2** | **−220.8 (−14.2 %)** |
| RETURN | 1342.2 | **1120.3** | **−221.9 (−16.5 %)** |
