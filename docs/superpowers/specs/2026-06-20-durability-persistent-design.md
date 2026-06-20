# Design — Disk-backed PERSISTENT durability store + cross-restart key-epoch (M6/P5, Phase 3b)

- **Date:** 2026-06-20
- **Status:** Design (brainstormed) — under owner review before the implementation plan.
- **Scope:** the disk-backed PERSISTENT slice of the durability service (ADR 0021 cap. 7, §10.1 of the
  DARE design): a file-backed `durable-store` surviving process/system restart, ALWAYS DARE-wrapped (no
  plaintext on disk), with a cross-restart **key-epoch** so nonce reuse is structurally impossible;
  PERSISTENT per-writer lifetime semantics; crash-consistency hardened; plus the folded Phase-2
  carry-forwards (live TRANSIENT-tier coexistence, dynamic-topic-add, collect-loop seen-set prune).
- **Relates to:** ADR 0021 (durability service scope + cap. 7); ADR 0023 (Phase-1 service); ADR 0024
  (Phase-2 dedup); ADR 0025 (DARE — §5 nonce discipline / the `version`-byte reservation, §10 roadmap);
  the durable-store vtable (`src/dds-durability/store.lisp`); the encrypted-store decorator
  (`src/dds-durability/store-encrypted.lisp`); the DARE envelope (`src/dds-dare/envelope.lisp`).
- **Standards:** OMG DDS 1.4 §2.2.3.4 (DURABILITY = PERSISTENT; per-instance/per-writer lifetime);
  inherited DARE/CNSA-2.0 (FIPS-203 ML-KEM-1024, SP 800-38D AES-256-GCM, SP 800-56C/RFC 5869 HKDF-SHA384).

## 1. Goal

Capability 7 / §10.1: make the durability service's retained history **survive a restart** while remaining
**encrypted at rest** (no plaintext on disk, ever), so a late-joiner that appears AFTER the service (and the
original writer) has restarted still receives the retained, authenticated samples. The cryptographic crux:
the 3a encrypted-store derives a *fresh* DEK per open and discards the ML-KEM ciphertext, so disk records
written in a prior run cannot be reopened. 3b adds a persisted **key-epoch** that re-derives each prior
run's DEK from a stored kem-ciphertext — without ever reusing an AES-GCM nonce across runs.

## 2. Owner decisions (brainstorm, 2026-06-20)

1. **Scope = broad, one WP:** core persistence + crash-consistency hardening + the Phase-2 carry-forwards,
   VSD-sequenced internally (core end-to-end first, then hardening, then carry-forwards).
2. **fsync = group-commit per drain tick:** append the batch the collect loop drains each ~5 ms poll, then a
   single fsync per tick. A crash loses at most the current sub-tick's not-yet-synced records.
3. **On-disk format = append-log-per-topic.**
4. **Key-epoch = new-epoch-per-open** (persisted epoch table; envelope v2 carries an AAD-bound epoch-id;
   per-epoch DEK derived on open via the key-provider).

## 3. Engine facts grounding the design (code survey)

- `durable-store` is an 8-slot closure vtable (`store.lisp:18-28`): `name put get-range topics purge open
  close count-fn`; `durable-record` = `topic writer-guid(16) sn key-hash(0|16) kind(:data/:dispose/
  :unregister) payload`. `store-put` is idempotent on `(topic, writer-guid, sn)` and returns `:rejected`
  when a bounded store is full. A decorator wraps an inner store (the encrypted-store pattern).
- `make-memory-store` is the only backend today. `make-encrypted-store` seals on `put` / opens on
  `get-range`; all secret material is held in foreign buffers via `dds.pal:alloc-static`/`free-static`
  (Clasp-deterministic, clasp#1793 avoided — ADR 0025).
- DARE envelope v1 (`envelope.lisp`): `version(1)=#x01 ∥ nonce(12) ∥ ciphertext ∥ tag(16)`. The version byte
  was reserved (ADR 0025 §5) for the 3b key-epoch.
- The service is control-plane: a reliable/TL collecting reader poll-drained into the store + a replay
  writer (PUBLISH-ON-COLLECT). The service-spec selects the store via a 0-arg `:store` factory
  (`spec.lisp`; default `make-memory-store`).

## 4. Architecture & module layout

A new file-store backend on the existing vtable + an epoch-aware extension to the encrypted-store; the
PERSISTENT tier composes them. **No durable-store vtable change.**

| Unit | File | Responsibility |
|---|---|---|
| File store backend | `src/dds-durability/store-file.lisp` (NEW) | `make-file-store :dir` — append-log-per-topic `durable-store`; replay + crash-recovery on open; group-commit fsync; idempotent put; get-range/topics/purge/count over an in-memory index. Stores OPAQUE sealed bytes (it never sees plaintext or keys). |
| Envelope v2 | `src/dds-dare/envelope.lisp` (MOD) | `seal-payload`/`open-payload` gain an epoch-aware v2 form: `#x02 ∥ epoch-id(4 LE) ∥ nonce(12) ∥ ct ∥ tag(16)`, epoch-id AAD-bound. v1 (#x01) unchanged. |
| Epoch-aware encrypted-store | `src/dds-durability/store-encrypted.lisp` (MOD) | when given `:epoch-dir`, persist an epoch table (`epochs.dat`), mint a new epoch per open, hold an epoch→DEK map, seal under the current epoch, open by the record's epoch-id. Absent `:epoch-dir` → unchanged 3a v1 behavior (in-memory tier). |
| PERSISTENT service wiring | `src/dds-durability/{spec,service}.lisp` (MOD) | the PERSISTENT-tier `:store` factory `(make-encrypted-store (make-file-store :dir D) (make-file-key-provider :dir K) :epoch-dir D)`; DURABILITY=PERSISTENT handling; dynamic-topic-add; collect-loop seen-set prune. |

PERSISTENT composition: `(make-encrypted-store (make-file-store :dir D) (make-file-key-provider :dir K)
:epoch-dir D)` — the encrypted-store seals → the file store writes only sealed bytes under `D`; the
encrypted-store owns `D/epochs.dat`; the key-provider owns `K/ml-kem-1024.{key,pub}`.

## 5. On-disk format (append-log-per-topic)

- `D/topics/<topic-id>.log` — one append-only log per topic. `<topic-id>` = lowercase hex of the topic's
  UTF-8 bytes (filesystem-safe, deterministic, collision-free, reversible); a `D/topics.map` records
  `topic-id → topic-name` for readability/inspection.
- **Record frame:** `magic(2)=#xDA #x01 ∥ flags(1) ∥ writer-guid(16) ∥ sn(8 LE) ∥ [key-hash(16) if flag]
  ∥ sealed-len(4 LE) ∥ sealed-bytes ∥ crc32(4 over the frame body)`. `flags` encodes `kind`
  (:data/:dispose/:unregister) + key-hash-present. `sealed-bytes` is the encrypted-store's opaque v2 blob
  (which itself carries the epoch-id). The file store does NOT parse the sealed bytes.
- **In-memory index (rebuilt on open):** `topic → ((guid . sn) → frame-ref)`; `frame-ref` holds the sealed
  bytes (or a file offset + lazy read). put = idempotent insert (skip if `(guid,sn)` present). get-range =
  index values sorted by `(guid bytes ascending, sn ascending)` (reuse `%guid-list<`). topics = index keys
  with ≥1 live record. purge = delete the topic log + drop the index entry. count = index size.
- **Replay + recovery on open:** read each log frame-by-frame; validate `magic` + `sealed-len` bounds +
  `crc32`; a torn/invalid trailing frame (short read, bad crc, bad length) → **truncate the file at the last
  valid frame offset** and stop (crash recovery). A mid-file corruption (not just trailing) → fail the open
  loudly (do not silently skip — that could hide tampering); recovery only truncates a torn *tail*.

## 6. Cross-restart key-epoch (new-epoch-per-open)

- `D/epochs.dat` — append-only epoch table; entry = `epoch-id(4 LE) ∥ kem-ct-len(4 LE) ∥ kem-ct ∥ crc32(4)`.
  `kem-ct` is the ML-KEM-1024 ciphertext (1568 B) for that epoch.
- **On store-open:** load `epochs.dat` (replay + tail-truncate-recover like a topic log); for each epoch,
  `key-provider-decapsulate(kem-ct) → shared-secret → derive-dek → DEK` (held foreign per epoch); build an
  `epoch-id → DEK` map. (Open does NOT mint — a read-only/replay-only restart adds no epoch.)
- **Mint the CURRENT epoch lazily — on the first `put` of this run:** `ml-kem-1024-encapsulate(recipient-
  public-key) → (kem-ct, ss); DEK_new = derive-dek(ss)`; append `{new-epoch-id → kem-ct}` to `epochs.dat`
  and **fsync it before writing the record that references it**. The minted epoch becomes CURRENT; its
  nonce counter starts at 0. `new-epoch-id = max(existing)+1` (4 bytes ⇒ 2^32 opens; assert-guard on
  overflow).
- **put:** seal the payload under the CURRENT epoch's DEK + the next counter nonce; the v2 blob records the
  current epoch-id.
- **get-range / open:** `open-payload` reads the record's epoch-id, looks up its DEK in the map (unknown
  epoch-id ⇒ NIL ⇒ fail-closed drop), then `aes-256-gcm-open`.
- **On close:** zeroize + free every epoch DEK (via `free-secret-octets`); `key-provider-close`.
- **Why reuse is structurally impossible:** every run mints a distinct epoch ⇒ a distinct DEK with its own
  counter-from-0 nonce space. No two runs ever share a `(DEK, nonce)` pair, regardless of crash timing —
  there is no counter-resume to get wrong (the rejected alternative). The epoch table grows by one entry per
  open (bounded by restart count; ~1.6 KB/epoch; a compaction/retire policy for very-old epochs with no live
  records is a follow-on).

## 7. Envelope v2

- `seal-payload` (epoch-aware): `#x02 ∥ epoch-id(4 LE) ∥ nonce(12) ∥ ciphertext ∥ tag(16)`. The AAD passed
  to AES-256-GCM additionally binds the epoch-id (defence-in-depth; a swapped epoch-id already selects the
  wrong DEK ⇒ tag mismatch ⇒ NIL).
- `open-payload` (epoch-aware): bounds-check (`len ≥ 1+4+12+16`); read version; `#x02` ⇒ read epoch-id +
  nonce + ct + tag, resolve DEK by epoch-id (NIL on miss), `aes-256-gcm-open`. The `#x01` path is unchanged
  for the in-memory tier. Bounds-checked even at `(safety 0)`; fuzzed (NFR-SEC-POSTURE).
- The decorator selects v1 vs v2 by whether it is epoch-aware (`:epoch-dir` present). v2's epoch-id is read
  by the decorator (which holds the DEK map) — the file store stays oblivious.

## 8. PERSISTENT lifetime & retention

- PERSISTENT (DDS 1.4 §2.2.3.4) survives service AND system restart (the files persist). On PERSISTENT-tier
  `service-start`, the store opens → replays logs → the replay writer delivers retained history to
  late-joiners with no original writer present (as in the TRANSIENT service, but the store outlived a
  restart).
- **Retention:** bounded `max-samples` (per the existing store; `:rejected` when full) + per-instance
  KEEP_LAST depth (supersede older SNs of the same instance key) + dispose/unregister tombstones (already
  modeled as `:dispose`/`:unregister` records). Lifespan-QoS expiry is a follow-on.
- **Compaction:** superseded (KEEP_LAST) and dispose+unregister-then-settled records are dead; a compaction
  pass rewrites a topic log keeping only live records. MVP: compaction-on-open (replay drops superseded/dead
  before building the index, then rewrites the log) + `purge` deletes the file. Online/threshold compaction
  during a long run is a follow-on within the WP.

## 9. Crash-consistency

- Group-commit fsync per drain tick (after the tick's batch of appends). Append-only files + no in-place
  mutation ⇒ crash-safe by construction.
- CRC32 + length framing ⇒ a torn trailing frame is detected and truncated on open; the store never reads a
  partial record.
- **Ordering invariant:** `epochs.dat` is fsync'd before any topic-log record references the new epoch, so
  every record's epoch-id always resolves after a crash. `epochs.dat` entries are themselves CRC-framed +
  tail-recoverable.
- **Crash-injection test:** truncate topic logs and `epochs.dat` at random offsets ⇒ open recovers to the
  last valid frame, no crash/OOB, no mis-decode, and (critically) no nonce reuse (a recovered-then-reopened
  store mints a fresh epoch). `(safety 0)` variant.

## 10. Phase-2 carry-forwards (folded into this WP)

- **Live TRANSIENT-tier coexistence:** RTI Persistence Service relays at the TRANSIENT/PERSISTENT tier (not
  TRANSIENT_LOCAL — the ADR-0024 finding). With a PERSISTENT tier our service can participate where RTI PS
  relays, making the deferred live dual-relay coexistence proof exercisable. An interop leg (our service +
  RTI PS both relaying the same TRANSIENT/PERSISTENT topic; the receiver-side OWI dedup gives exactly-once).
- **Dynamic-topic-add:** add a topic to a running service (a new disc-node + store partition) without a
  restart; the existing multi-topic machinery (N disc-nodes) extended with an add-topic entrypoint.
- **Collect-loop seen-set prune:** bound the unbounded `seen-data`/`seen-lc` dedup sets (the Phase-2 review's
  NFR-MEM item) — prune entries below the per-origin watermark / older than store retention.

## 11. Error handling

- Fail-closed throughout (inherited): `open-payload` NIL ⇒ drop; unknown epoch-id ⇒ drop; DARE-unavailable /
  OpenSSL < 3.5 ⇒ hard startup error (NEVER a plaintext-on-disk path). File-IO errors are surfaced, not
  swallowed; a torn trailing record ⇒ truncate-recover (not a crash); a mid-file corruption ⇒ fail the open
  loudly. The store dir `D` perms are enforced 0700 (like the key dir).

## 12. Testing strategy

- **Cross-restart round-trip:** write N records → `store-close` → a fresh `make-file-store`/encrypted-store
  on the same dir → `store-open` (re-derives prior epochs' DEKs) → `get-range` opens all N byte-exact.
- **New-epoch-per-open:** two opens ⇒ two entries in `epochs.dat`; run-1 records readable in run-2 (epoch-1
  DEK derived), run-2 records under epoch-2; assert distinct epoch-ids and distinct DEKs.
- **No plaintext on disk:** the topic-log bytes for a record are sealed (the sealed region starts `#x02`,
  ≠ the plaintext).
- **Crash-injection fuzz:** random truncation of logs + `epochs.dat` ⇒ open recovers, no crash/OOB/mis-decode
  (`(safety 0)`).
- **PERSISTENT service (our-stack + cross-DDS):** write N → kill+restart the service (new process) →
  a late-joiner receives the retained history. Cross-DDS transparency-after-restart vs LIVE Connext 7.3.1 +
  Fast DDS 3.6.1 (per the per-feature DoD).
- **Carry-forwards:** live TRANSIENT-tier coexistence interop; dynamic-topic-add unit + interop; seen-set
  prune bound test.
- **Gates:** SBCL + Clasp (both deterministic — file IO + static-vectors via the PAL); `gate-hotpath`,
  `gate-types`, `mem` (0.0000 — the store is control-plane), `fuzz`, `wire`.

## 13. Vertical-slice implementation ordering (within this WP)

1. **file-store backend** (append-log-per-topic, framing, replay + tail-recovery, index, group-commit) —
   tested NON-DARE first (raw records survive a close/reopen).
2. **envelope v2 + epoch-aware encrypted-store** (epoch table, per-epoch DEK map, seal/open by epoch-id) +
   cross-restart round-trip + no-plaintext-on-disk tests.
3. **PERSISTENT service wiring** (the secure file-store factory, DURABILITY=PERSISTENT, restart→replay) +
   our-stack restart test + cross-DDS transparency-after-restart (Connext + Fast DDS).
4. **crash-consistency hardening** (fsync discipline, crash-injection fuzz, compaction-on-open).
5. **Phase-2 carry-forwards** (live TRANSIENT-tier coexistence, dynamic-topic-add, seen-set prune).
6. **capstone** (ADR 0026, wiki/README/verification, SBOM/provenance unchanged-but-checked, final
   whole-branch review → squash-merge presented for approval, HOLD PUSH).

Each slice: implement → review(s) → gates → autonomous branch commits → final whole-branch review →
squash-merge presented for approval, push held.

## 14. Out of scope (genuinely — follow-ons)

- Metadata confidentiality (3c — seal topic/GUID/SN/kind, needs an encrypted index); in-RAM plaintext
  minimization (bounded — full goal needs OS/HW support); DDS-Security in-transit (P6/M7); db / microservice
  persistence backends (ADR 0021 lists them; **file** is the 3b backend, on the same vtable so a db backend
  drops in later); epoch-table retirement/compaction for very-old epochs with no live records.

## 15. Tunable defaults (owner may adjust in review)

The core design above is decided; these are configuration defaults, not blockers:
- **topic-id encoding** = lowercase hex of the topic UTF-8 (decided, §5) + a `topics.map`.
- **compaction** = on-open for the MVP (§8); online/threshold compaction = a follow-on within the WP.
- **retention** = bounded `max-samples` + per-instance KEEP_LAST depth; lifespan-QoS expiry = follow-on.
