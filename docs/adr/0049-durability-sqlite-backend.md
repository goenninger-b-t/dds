# ADR 0049 — Durability SQLite persistence backend (a second store implementing the fixed vtable)

Status: Accepted
Date: 2026-07-06
Work package: WP-DURABILITY-SQLITE (owner large-arch sequence item 4)
Relates to: ADR 0021 (pluggable persistence vtable), ADR 0025/0026 (DARE at-rest, file store), ADR 0045 (log-MAC chain — a documented follow-on for SQLite)

## 1. Context

The durability service already carries two backends behind one abstraction: an in-memory store
and an append-log-per-topic file store. Both are constructed behind the **`durable-store` vtable**
(`src/dds-durability/store.lisp:18-32`) — a `defstruct` of function slots (`put`, `get-range`,
`topics`, `purge`, `open`, `close`, `count-fn`, `sync`, `set-chain-mac-fn`) with public dispatch
functions (`store-put` … `store-sync`). Backend selection is a **0-arg store-factory closure** on
the service-spec (`spec.lisp:14`, consumed at `service.lisp:78`); e.g. `make-persistent-store-factory`
composes `make-encrypted-store` over `make-file-store`.

The owner's directive (large-arch item 4) is that the persistence backend MUST stay **pluggable via
a FIXED API**, config-selectable, so other backends plug in identically. This ADR adds a **SQLite**
backend that **implements the vtable UNCHANGED** — it does not fork or extend it — and documents the
vtable as the stable backend contract that every future backend fills the same way.

## 2. Decision

Add `make-sqlite-store` (fills every vtable slot with the exact documented contract, reusing the
shared `durable-record`, `%kind->int`/`%int->kind`, `%record-guid-sn<`, `%compact-topic-records`,
and the file store's bounded-count logic) and `make-sqlite-store-factory` (mirrors
`make-persistent-store-factory` — the ONLY change is `make-sqlite-store` in place of
`make-file-store`, wrapped by `make-encrypted-store` for always-on at-rest encryption).

The `durable-store` struct and its dispatch contracts are **NOT touched**. The vtable IS the fixed
backend API; SQLite is a second implementation of it, config-selected exactly like the file store.

Dependency: `cl-sqlite` (ASDF system `sqlite`, CFFI over `libsqlite3`), in the Quicklisp 2026-01-01
dist. It is impl-agnostic CFFI (loads + round-trips identically on Clasp and SBCL — verified as the
mandatory first step), so it needs **no reader conditionals** outside `dds-pal/`. Transitive dep:
`iterate`; native runtime: `libsqlite3` (3.51.0 verified).

## 3. Schema

```
CREATE TABLE record (topic TEXT NOT NULL, writer_guid BLOB NOT NULL, sn BLOB NOT NULL,
                     key_hash BLOB, kind INTEGER NOT NULL, payload BLOB NOT NULL,
                     mac BLOB, chain_seq INTEGER,           -- v3 keyed MAC chain (§9, ADR 0045)
                     PRIMARY KEY (topic, writer_guid, sn));
CREATE INDEX idx_topic_order ON record(topic, writer_guid, sn);
```

One row per retained sample, keyed by (topic, writer-guid, sn) — the same identity the memory/file
stores dedup on. `kind` is the shared 2-bit `%kind->int`/`%int->kind` encoding. `payload` and
`key_hash` are opaque blobs (the store is DARE-unaware; the encrypted decorator seals the payload).

## 4. The u64-SN crux (why SN is a big-endian BLOB, not an INTEGER)

DDS sequence numbers are **unsigned 64-bit**; the file/memory stores impose **no** SN bound. SQLite's
`INTEGER` is **signed 64-bit**: a real DDS SN at or beyond 2^63 would be stored as a negative value
and would sort BEFORE small SNs — a silent reorder, which for a durability store is the worst class
of defect (a persistence backend that silently reorders a durable sample). Two options were on the
table: (a) signed INTEGER with an enforced `sn < 2^63` guard, or (b) an 8-byte **big-endian BLOB**.

Decision: **big-endian 8-byte BLOB.** Lexicographic BLOB comparison (memcmp) equals numeric u64 order
across the FULL unsigned range with **no bound**, matching the no-limit file-store contract exactly,
and with no guard to forget. The signed-INTEGER option was rejected because it imposes an artificial
2^63 ceiling the other backends do not have.

Ordering is not left to SQL, regardless: `get-range` fetches the topic's rows and **sorts in Lisp via
the shared `%record-guid-sn<`** (the same function the memory + file backends use), so the returned
order is **byte-exact identical** to the other backends independent of any SQLite collation question.
The BE-BLOB choice keeps the PRIMARY KEY correct and a SQL `ORDER BY sn` correct too, but the
authoritative order is the one shared definition (DRY).

## 5. Vtable slot mapping

- `put` — existence check → T (idempotent on (topic,writer-guid,sn)); else bounded-full → `:rejected`;
  else `INSERT OR IGNORE`. Same three-branch `cond` as the memory/file stores.
- `get-range` — `SELECT … WHERE topic=?`, build `durable-record`s, `sort … #'%record-guid-sn<`.
- `topics` — `SELECT DISTINCT topic`.
- `purge` — `DELETE FROM record WHERE topic=?`.
- `open` — **restart-recovery entry point**: (re)connect to the DB file (prior rows queryable for
  free), enforce/assert 0700 on the DB directory (the cleartext topic/guid/sn/kind metadata dir, as
  the file store does), then apply compaction-on-open (`%compact-topic-records` per topic with the
  effective policy — caller override wins over factory default — DELETE'ing dropped rows).
- `close` — `PRAGMA wal_checkpoint(FULL)` then disconnect (barrier + release).
- `count-fn` — `SELECT COUNT(*) [WHERE topic=?]`.
- `sync` — `PRAGMA wal_checkpoint(FULL)` (group-commit durability barrier; failure PROPAGATES,
  fail-closed). Journal mode is WAL, `synchronous=FULL` (durability is off the per-sample hot path,
  so maximum safety is preferred over throughput).
- `set-chain-mac-fn` — **LIVE** (WP-SQLITE-MAC-CHAIN, §9). Installs the log-MAC oracle + downgrade
  flag + grandfather set; puts write a per-row v3 chain MAC (byte-identical to the file store) into
  the `mac` column and `store-open` verifies the chain (before compaction, fail-closed). A NIL oracle
  = bare store with NULL `mac`/`chain_seq` columns (byte-behaviorally unchanged).

## 6. DARE composition (always-on at-rest encryption)

`make-encrypted-store` is a decorator over ANY inner store: it seals only the payload, delegates
`topics`/`purge`/`count`/`open`/`close`/`sync` to the inner store, and writes sealed opaque bytes
into the inner store's payload column. So `make-sqlite-store` needs **zero** crypto knowledge — it
stores opaque payload bytes exactly like the file store. `make-sqlite-store-factory` composes
`make-encrypted-store(make-sqlite-store(:path DIR/db), make-file-key-provider(:dir KEY-DIR),
:epoch-dir DIR)`. The DB file, `epochs.dat`, and `logmac.anchor` coexist in DIR.

## 7. Follow-ons (explicitly deferred)

- **Per-row keyed MAC chain (ADR 0045 analogue).** ✅ **RESOLVED — WP-SQLITE-MAC-CHAIN (§9).**
  `set-chain-mac-fn` is now LIVE; the SQLite backend is at tamper-evidence parity with the file
  store's v3 keyed HMAC chain. See §9 for the as-built.
- **Compaction at scale.** ✅ **Sliver 1 RESOLVED — WP-DURABILITY-COMPACTION-SQLITE (§10):** the
  SQLite store now evicts KEEP_LAST-superseded rows ONLINE on every put, so a continuously-open store
  stays bounded WITHOUT a close/open cycle. **Deferred:** Sliver 2 = file-store online/threshold
  compaction (the file store still compacts only on open); Sliver 3 = encrypted-tier physical reclaim +
  the whole-topic-deletion residual (§9). Compaction-on-open is unchanged (restart-recovery path).
- **Metadata-3c / dynamic-topic parity.** Any file-store-specific metadata follow-ons apply equally.

## 8. Consequences

- A second, transactional, indexed persistence backend, config-selected with a one-line factory swap,
  proving the vtable is a genuine pluggable seam (the owner binding).
- Both impls (Clasp first, then SBCL) load `:sqlite` and pass the full contract suite identically.
- No hot-path impact (durability is off the per-sample wire path); no reader conditionals added; SBOM
  gains `sqlite` + `iterate` + native `libsqlite3`; provenance records the clean-room dependency use.

## 9. As-built — WP-SQLITE-MAC-CHAIN (per-row keyed MAC chain, ADR 0045 parity)

Closes the §7 deferral. `set-chain-mac-fn` is now filled; a MAC-chained SQLite store is
byte-for-byte MAC-compatible with the file store and fails closed on tamper at `store-open`.

- **Schema.** Two nullable columns added to `record` (idempotent `ALTER TABLE ADD COLUMN` migrates a
  pre-chain DB): `mac BLOB` (32-octet HMAC-SHA-256 chain MAC, NULL for legacy/pre-chain rows) and
  `chain_seq INTEGER` (the explicit per-topic chain order). The anchor stays as `DIR/logmac.anchor`.
- **Byte-identical MAC (maximal reuse).** The MAC over a row reuses `%frame-record-versioned` to build
  the canonical v3 frame and takes its 32-byte MAC, chained by `%chain-seed`/`%chain-mac` — the SAME
  helpers the file store uses. A MAC computed by either backend over the same record is identical. The
  store holds only the HMAC oracle closure, never the log-MAC key.
- **Chain order = explicit `chain_seq`, not rowid.** `chain_seq` is assigned per-topic `MAX+1` on put
  and is robust against SQLite's rowid reuse after a `DELETE`. Per-topic verification/recompute is
  `ORDER BY chain_seq ASC, rowid ASC`.
- **Verify BEFORE compaction (fail-closed).** `store-open` verifies every topic's chain (recompute
  each row's expected MAC over `running ∥ frame-prefix`, compare to the stored `mac`) BEFORE
  `%compact-on-open`, so tamper can never be laundered by the compacting `DELETE`. Any
  mismatch/gap/reorder, or a `NULL`-mac row after a chained row, signals. Downgrade defense: a
  non-empty non-grandfathered topic with zero chained rows signals (the v3→v2 keyless downgrade).
- **Chain-recompute-on-compaction (the no-false-reject invariant).** `%compact-on-open` deletes
  KEEP_LAST-superseded rows, which breaks the chain over the survivors. After any compacting delete
  the surviving rows are re-MAC'd as a fresh chain (re-seed, re-MAC in `chain_seq` order, rewrite
  `mac` + dense `chain_seq`), mirroring the file store's `%rewrite-topic-log`. A KEEP_LAST MAC-chained
  store therefore reopens clean any number of times.
- **Grandfather enumerator (backend-dispatched, DRY).** The mint-time grandfather set is chosen by
  `%store-grandfather-ids` so each backend's ids key IDENTICALLY to its own downgrade-check lookup: the
  FILE store keeps its original raw-tid log-dir scan (`%enumerate-nonempty-topic-ids` — the log
  filenames ARE the tids, robust to a lost `topics.map` where a topic name degrades to the raw tid and
  a `%topic->id` round-trip would double-encode → a false-REJECT), while SQLite (and memory) map real
  topic NAMES via `(mapcar #'%topic->id (store-topics inner-store))` (matching their `%topic->id(name)`
  verify key). So a legacy multi-topic store on EITHER backend grandfathers its dormant topics without a
  false-REJECT; a fresh store's set is empty ⇒ full protection. (An earlier fully-shared
  `store-topics`→`%topic->id` lift regressed the file store's map-less fallback; the dispatch restores
  the exact pre-lift file semantics — guarded by `run-durability-mac-chain-test` case 8.)
- **Residual — whole-topic deletion.** Dropping every row of a topic (so it no longer exists at open)
  is the topic-granularity form of the ADR 0045 §7 whole-tail-truncation residual and joins the shared
  residual list (whole-tail truncation, `epochs.dat` MAC, anchor-deletion + full downgrade). It closes
  only with the deferred separable **sealed high-water anchor** — a chain-design property identical for
  the file and SQLite backends, not a storage bug.
- **NIL-oracle unchanged.** A bare `make-sqlite-store` (no oracle) writes `NULL` `mac`/`chain_seq` and
  skips verification — byte-behaviorally identical to the pre-chain backend.
- **Tests / gates.** `run-durability-sqlite-mac-chain-test` (tamper via DIRECT SQL: UPDATE
  payload/mac, DELETE row, REORDER via chain_seq swap; downgrade; KEEP_LAST reopen-repeatedly
  no-false-reject; epoch-boundary; grandfather; NIL-oracle regression). Both impls 454 passed (Clasp
  first, then SBCL), identical. No new dependency (HMAC is `dds.dare`). No hot-path impact.

## 10. As-built — WP-DURABILITY-COMPACTION-SQLITE (online per-instance KEEP_LAST eviction, Sliver 1)

Closes the §7 "compaction at scale" deferral for the SQLite backend. Before this, only the memory store
compacted KEEP_LAST online (`%mem-evict-instance`, on every put); the SQLite `:put` was INSERT-only and
compacted superseded rows ONLY at `store-open`, so a continuously-open KEEP_LAST store grew unboundedly
between reopens (ADR 0029 context). Sliver 1 adds runtime DELETE-on-put, mirroring the memory store.

- **Trigger (identical guard to `%mem-put`).** After the `INSERT OR IGNORE`, when the effective policy
  is `:keep-last` AND `kind = :data` AND `key-hash` is non-NIL, `%sqlite-evict-instance` DELETEs the
  lowest-`(writer-guid, sn)` `:data` rows of that instance until at most DEPTH remain. Idempotent
  re-puts return early (no eviction). `:keep-all` does NO online eviction (bounded only by
  `:max-samples`). NIL-key-hash streams and lifecycle (`:dispose`/`:unregister`) rows are never
  depth-evicted — same KEEP_LAST intent as the memory store. **Ordering nuance (honest):** the SQLite
  drop-candidates sort by `%record-guid-sn<` (writer-guid, then sn), which matches the FILE store's
  `%compact-topic-records` pass 2 — NOT the memory store, whose `%mem-evict-instance` drops by PURE sn
  (ignoring guid). The two diverge ONLY for a single instance (one key-hash) fed by MULTIPLE writer GUIDs;
  the SQLite/file order is the self-consistent choice (it matches `get-range`'s ordering), and the memory
  store is the pre-existing outlier.
- **Cost — O(instance) for a bare store; O(topic) re-MAC per superseding put when a chain oracle is
  installed (honest).** The eviction SELECT + DELETE(s) are scoped to the instance
  (`WHERE topic=? AND key_hash=? AND kind=?`); a continuously-evicted KEEP_LAST instance holds at most
  DEPTH+1 `:data` rows at put time. For a **bare** `:keep-last` store (no chain — the realistic online
  path) the whole put is therefore **O(instance)**, meeting the at-scale intent. But when a chain oracle
  IS installed, `%sqlite-recompute-topic` re-MACs the WHOLE topic (O(topic) HMACs + O(topic) UPDATEs) on
  every superseding put — under sustained same-instance writes every put supersedes, so the keyed online
  path is effectively **O(topic) per put**. This blow-up appears only for keyed + `:keep-last` + real
  key-hash (not a standard factory: the 3c encrypted tier opens the inner store `:keep-all` with a NIL
  inner key-hash, so its inner online eviction never fires). A batched/threshold re-MAC (amortize the
  topic re-MAC over many evictions) is a Sliver-2/3 hardening, paired with the crash-atomic transaction
  below. **Do not claim O(instance) unconditionally.**
- **Re-MAC after eviction (the load-bearing correctness point) + crash-atomicity.** The ADR 0045 chain
  covers the surviving rows in `chain_seq` order; an online DELETE that does NOT recompute leaves
  survivors carrying MACs chained over deleted predecessors → a CLEAN store FALSE-REJECTS on the next
  open. So when a keyed store (`cmf-cell` set) actually deletes, the topic's chain is recomputed over the
  survivors via `%sqlite-recompute-topic` — the SAME machinery `%compact-on-open` uses after its DELETEs —
  and the running chain-MAC (`chain-macs[topic]`) is updated to the new tail. A bare (NIL-oracle) store
  has no chain and skips the recompute. **The DELETE(s) + the re-MAC are wrapped in a SINGLE
  `sqlite:with-transaction`** at BOTH sites — the online `:put` evict AND the pre-existing on-open
  `%compact-on-open` (whose DELETE-then-recompute was previously un-transacted under SQLite autocommit, so
  a crash between the committed DELETE and the recompute would have left a survivor dangling → a
  false-reject of a clean store; this shipped and is reachable via the 3c tier's on-open pass-1 settled
  compaction). A crash before COMMIT rolls the DELETE back → the store is at its pre-eviction state
  (all rows present, chain intact) → reopen verifies clean. Under WAL + `synchronous=FULL` the
  transaction is one fsync at COMMIT (also FEWER than N per-statement fsyncs), single-connection under the
  store lock, no nesting. Reuses `%record-guid-sn<`, the on-open compaction DELETE, and
  `%sqlite-recompute-topic` (DRY); the durable-store vtable is UNCHANGED (internal to `:put` / `:open`).
- **Tests / gates.** `run-durability-sqlite-keeplast-online-test` (bounded growth to DEPTH WITHOUT
  reopen — proven RED at count=6 with eviction disabled; newest-D survive byte-exact; two instances
  independent; NIL-key-hash never evicted; lifecycle rows kept; KEEP_ALL unaffected; never-exceeds-D
  unchanged), `run-durability-sqlite-online-chain-test` (online eviction re-MACs the survivors → a fresh
  store reopening the same DB VERIFIES clean and get-range returns the newest DEPTH), and
  `run-durability-sqlite-crash-consistency-test` (fault injected via `*durability-debug-compact-fault*`
  AFTER the compacting DELETE, BEFORE the re-MAC, inside the txn: at BOTH the on-open and online sites the
  DELETE rolls back so a fresh reopen VERIFIES clean + recovers the pre-eviction set — proven RED as a
  `SQCC-OPEN-RECOVERS` false-reject when the on-open transaction is neutralized). The chain tests use a
  deterministic pure-Lisp MAC oracle so they run on both impls without OpenSSL. Both impls 473 passed
  (Clasp first, then SBCL), identical. No new dependency. No hot-path impact. Sliver 2 (file-store
  online/threshold compaction, and the batched/threshold re-MAC to amortize the O(topic) keyed cost) and
  Sliver 3 (encrypted-tier physical reclaim + whole-topic-deletion residual) follow.
