# WP-KEEPLAST — writer-side per-instance KEEP_LAST HISTORY-machinery cost (FR-LANG-7)

Drives dds.rtps.history:hc-add-change directly (the unit WP-KEEPLAST modified) so the measurement isolates the HISTORY add path, not the transport/serialization path. Clock: dds.pal:monotonic-ns (~us, amortised over 1000000 samples). GC bytes/sample: dds.pal:bytes-consed delta / samples (SBCL-exact; Clasp reports 0 — a documented NFR-PORT gap, so SBCL is the record). The cache-change cons is held INSIDE every measured loop (pre-existing — history.lisp:25 flags pooling as a follow-up); the keyhash allocation is measured on its own line. HONESTY CAVEAT (FR-LANG-7): KEEP_ALL and KEEP_LAST differ in RETENTION (KEEP_ALL retains all 1000000 changes — its change-table grows + rehashes; KEEP_LAST evicts to dep*instances), so the KEEP_ALL-vs-KEEP_LAST byte delta is dominated by retention, NOT machinery. The clean isolation of the per-instance machinery is KEEP_LAST keyed vs KEEP_LAST unkeyed (same kind, same retention — only the per-instance index/bucketing differs) plus the keyhash line; both are reported below.

Parameters: samples=1000000, instances=100, KEEP_LAST depth=2 (samples spread round-robin so each instance bucket overflows depth and the per-instance evict fires).

**Regression this bench surfaced + fixed (Task E1):** the WP's `%hc-store` originally appended to the per-instance index UNCONDITIONALLY via `nconc` (an O(bucket-length) tail-walk). For KEEP_ALL the index bucket is never evicted, so it grew unbounded → O(N) per insert = **O(N²) total** on the KEEP_ALL write path (a regression vs pre-WP O(1)). FIX: the per-instance index is the KEEP_LAST eviction mechanism, so `%hc-index-append`/`%hc-index-drop` now no-op for KEEP_ALL — KEEP_ALL is the O(1) change-table insert it was pre-WP (measured below: KEEP_ALL ns/sample is now FLAT across N, ~70 ns/sample at any size, vs ~3.6/7.3/14.1 us/sample climbing at N=10k/20k/40k before the fix).

## HistoryCache add-path cost per mode

| mode | writer samples/s | ns/sample | GC bytes/samp |
|------|------------------|-----------|---------------|
| KEEP_ALL keyed (prior default behavior)   |     15014790 |       66.6 |         186 |
| KEEP_LAST keyed (NEW per-instance machinery) |      3282348 |      304.7 |          96 |
| KEEP_ALL unkeyed                           |     13721374 |       72.9 |         186 |
| KEEP_LAST unkeyed (global collapse)        |      8895294 |      112.4 |          96 |

## The keyhash derivation (keyed KEEP_LAST writes only — DCPS %instance-handle)

| operation | ns/sample | GC bytes/samp |
|-----------|-----------|---------------|
| fresh 16-octet keyhash (`make-array 16`) |       11.9 |          32 |

## What WP-KEEPLAST costs on the write path (honest — FR-LANG-7)

- **The per-instance index/bucketing (KEEP_LAST keyed vs KEEP_LAST unkeyed — SAME kind, SAME retention):** +0 GC bytes/sample, +192.2 ns/sample (keyed 304.7 - unkeyed 112.4 ns/sample). This is the CLEAN isolation of the per-instance machinery: both evict at depth, both cons one cache-change/sample, both hold dep*instances vs dep*1 changes — the difference is the keyed case's EQUALP hashing of 16-octet keys across 100 buckets vs the unkeyed case's single :unkeyed-keyword bucket. The index append + per-instance evict add ~0 STEADY-STATE GC bytes/sample (the bucket conses are freed on evict; the residual cost is the equalp hash time).
- **The keyhash a keyed KEEP_LAST writer adds (DCPS %instance-handle, ABOVE the HC):** 32 GC bytes/sample (the 16-octet handle + its array header) + 11.9 ns/sample — this is the headline per-sample allocation the WP adds for a KEYED KEEP_LAST writer. A KEEP_ALL writer derives NO handle (it threads NIL — %writer-keeplast-p gates it), and an unkeyed type reuses the shared +instance-handle-nil+ (0 bytes/sample).
- **KEEP_ALL is unchanged (O(1), no index):** the KEEP_ALL keyed and KEEP_ALL unkeyed rows match (keyhash NIL either way), and after the Task-E1 fix the KEEP_ALL add keeps NO per-instance index at all (the index is the KEEP_LAST eviction mechanism; %hc-index-append/-drop no-op for KEEP_ALL) — so KEEP_ALL is the same O(1) change-table insert it was pre-WP. (Its higher GC bytes/sample here vs KEEP_LAST is RETENTION: KEEP_ALL retains all 1000000 changes so its change-table grows + rehashes, while KEEP_LAST evicts to 200 — NOT machinery.)
- **Unkeyed collapses to global:** KEEP_LAST unkeyed routes every change to one shared bucket (= a correct global KEEP_LAST), so it pays the index + evict but NO keyhash.

NO `0-cost`/`free` claim: a KEYED KEEP_LAST writer adds a real ~32-byte/sample keyhash (the dominant add) + the per-instance index cons (freed on evict, ~0 steady-state bytes); KEEP_ALL and the unkeyed path are unchanged. The reader-side per-instance drop (`%reader-keeplast-drop-oldest`, an O(N) dr-cache scan per over-depth sample) is a SEPARATE cost, not measured here (it matches the pre-existing RESOURCE_LIMITS reject scan; a per-instance reader index is a noted follow-up, ADR 0019).
