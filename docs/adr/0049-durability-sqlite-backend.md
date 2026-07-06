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
- `set-chain-mac-fn` — intentionally **absent** (NIL). `store-set-chain-mac-fn` no-ops when a store
  has no chain seam, so the SQLite store composes cleanly with the encrypted decorator's v2 epoch
  mode. The per-row keyed MAC chain for SQLite is an explicit follow-on (see §7).

## 6. DARE composition (always-on at-rest encryption)

`make-encrypted-store` is a decorator over ANY inner store: it seals only the payload, delegates
`topics`/`purge`/`count`/`open`/`close`/`sync` to the inner store, and writes sealed opaque bytes
into the inner store's payload column. So `make-sqlite-store` needs **zero** crypto knowledge — it
stores opaque payload bytes exactly like the file store. `make-sqlite-store-factory` composes
`make-encrypted-store(make-sqlite-store(:path DIR/db), make-file-key-provider(:dir KEY-DIR),
:epoch-dir DIR)`. The DB file, `epochs.dat`, and `logmac.anchor` coexist in DIR.

## 7. Follow-ons (explicitly deferred)

- **Per-row keyed MAC chain (ADR 0045 analogue).** The file store has a v3 HMAC chain making interior
  delete/reorder/substitution/insertion tamper-evident. The SQLite store leaves `set-chain-mac-fn`
  NIL for this slice; a per-row MAC chain (a `mac` column chained by rowid, verified on open) is the
  direct follow-on. Until then the encrypted decorator's per-record GCM tag still authenticates each
  row's payload+metadata in isolation (no cross-row chaining).
- **Compaction at scale.** Compaction-on-open loads each topic's rows to run `%compact-topic-records`.
  For very large stores an incremental/SQL-side compaction is a follow-on; the current approach is
  chosen for exact parity with the file store and is cheap off the hot path.
- **Metadata-3c / dynamic-topic parity.** Any file-store-specific metadata follow-ons apply equally.

## 8. Consequences

- A second, transactional, indexed persistence backend, config-selected with a one-line factory swap,
  proving the vtable is a genuine pluggable seam (the owner binding).
- Both impls (Clasp first, then SBCL) load `:sqlite` and pass the full contract suite identically.
- No hot-path impact (durability is off the per-sample wire path); no reader conditionals added; SBOM
  gains `sqlite` + `iterate` + native `libsqlite3`; provenance records the clean-room dependency use.
