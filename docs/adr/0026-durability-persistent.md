# ADR 0026 — Disk-backed PERSISTENT durability store + cross-restart key-epoch

- **Status:** Accepted (M6/P5; WP-DURABILITY-PERSISTENT Phase 3b, 2026-06-20)
- **Relates to:** ADR 0021 (durability service scope — **capability 7 = always-on CNSA-2.0 DARE**);
  ADR 0023 (Phase-1 TRANSIENT service); ADR 0024 (Phase-2 dedup); ADR 0025 (DARE — **§5 nonce
  discipline / the `version`-byte reservation**, **§10 MUST-follow-on roadmap = the disk-backed
  PERSISTENT follow-on**);
  `docs/superpowers/specs/2026-06-20-durability-persistent-design.md` (design spec, the
  architecture this ADR records as-built); FR-SEC-2 (vetted native crypto, no hand-rolling);
  NFR-SEC-POSTURE (bounds-checked untrusted parse, fail-closed); NFR-MEM (foreign/static secret
  buffers); NFR-PORT (documented per-impl gaps).
- **Standards:** OMG DDS 1.4 §2.2.3.4 (DURABILITY = PERSISTENT — samples outlive the writer AND
  survive process/system restart; per-instance/per-writer lifetime); inherited DARE/CNSA-2.0
  (FIPS-203 ML-KEM-1024, NIST SP 800-38D AES-256-GCM, FIPS-180-4 SHA-384, RFC 5869 / SP 800-56C
  Rev 2 HKDF-SHA384).

## Context

ADR 0021 capability 7 / ADR 0025 §10 require the durability service's retained history to
**survive a restart** while remaining **encrypted at rest** — no plaintext on disk, ever — so a
late-joiner appearing AFTER the service (and the original writer) has restarted still receives the
retained, authenticated samples. Phase 3a (ADR 0025) built and proved the DARE envelope + key
management as a `durable-store` **decorator** over the in-memory store; "at rest" was not literal
for RAM. The cryptographic crux for disk is that 3a derives a **fresh DEK per open** and discards
the ML-KEM ciphertext, so records written in a prior run cannot be reopened. 3b plugs a file-backed
store underneath the same decorator (disk holds only sealed bytes from its first byte) and adds a
persisted **key-epoch** that re-derives each prior run's DEK — **without ever reusing an AES-GCM
nonce across runs**.

The owner scope (brainstorm 2026-06-20) was **broad, one WP, VSD-sequenced**: core persistence,
crash-consistency hardening, and the folded Phase-2 carry-forwards (live TRANSIENT-tier
coexistence, dynamic-topic-add, collect-loop seen-set prune). Owner decisions: fsync =
group-commit per drain tick; on-disk = append-log-per-topic; key-epoch = new-epoch-per-open
(persisted epoch table, envelope v2 AAD-bound epoch-id, per-epoch DEK derived on open via the
key-provider).

The durability service is control-plane (a ~5 ms collect-poll loop) and **off the measured CDR hot
path**, so blocking file IO and OpenSSL FFI do not violate the static-arena hot-path rule —
`make mem` stays 0.0000 bytes/sample.

## Decision — as-built architecture

A new file-store backend on the **existing 8-slot `durable-store` closure vtable** + an epoch-aware
extension to the encrypted-store + the `:sync` group-commit slot; the PERSISTENT tier composes
them. **No `durable-store` vtable widening** beyond the `:sync` slot needed for group-commit.

### Module layout

| Unit | File | Responsibility |
|---|---|---|
| File store backend | `src/dds-durability/store-file.lisp` (NEW) | `make-file-store :dir` — append-log-per-topic `durable-store`; framed records; replay + crash-recovery on open; group-commit fsync; idempotent put; get-range/topics/purge/count over an in-memory index; compaction-on-open. Stores OPAQUE sealed bytes (it never sees plaintext or keys). |
| Envelope v2 | `src/dds-dare/envelope.lisp` (MOD) | `seal-payload-v2` / `open-payload-v2` — the epoch-aware form `#x02 ∥ epoch-id(4 LE) ∥ nonce(12) ∥ ct ∥ tag(16)`, epoch-id AAD-bound. v1 (`#x01`) BYTE-IDENTICAL. |
| Epoch-aware encrypted-store | `src/dds-durability/store-encrypted.lisp` (MOD) | given `:epoch-dir`, persist an epoch table (`epochs.dat`), mint a new epoch per open, hold an epoch→DEK map, seal under the current epoch, open by the record's epoch-id; `:sync` slot delegates group-commit to the inner store. Absent `:epoch-dir` → unchanged 3a v1 behaviour (the in-memory tier). |
| Group-commit fsync | `src/dds-pal/pal-{sbcl,clasp}.lisp` (MOD) | `dds.pal:fsync-stream` — SBCL `fdatasync(2)` via CFFI; Clasp `finish-output` (NFR-PORT, see Consequences). |
| PERSISTENT service wiring | `src/dds-durability/{spec,service}.lisp` (MOD) | `make-persistent-store-factory`; `service-start` store-opens (reload + epoch-DEK-load), `service-stop` store-closes (fsync + free); `%seed-relay-from-store` seeds the replay writer's TL/KEEP_ALL history from the store on start; `service-add-topic`; the collect-loop seen-set prune. |

**PERSISTENT composition.** `make-persistent-store-factory` builds
`(make-encrypted-store (make-file-store :dir D) (make-file-key-provider :dir K) :epoch-dir D)` — the
encrypted-store seals → the file store writes only sealed bytes under `D`; the encrypted-store owns
`D/epochs.dat`; the key-provider owns `K/ml-kem-1024.{key,pub}`.

### File-store on-disk format (append-log-per-topic)

- `D/topics/<topic-id>.log` — one append-only log per topic. `<topic-id>` = lowercase hex of the
  topic's UTF-8 bytes (filesystem-safe, deterministic, collision-free, reversible); a
  `D/topics.map` records `topic-id → topic-name` for readability/inspection.
- **Record frame:** `magic(2)=#xDA #x01 ∥ flags(1) ∥ writer-guid(16) ∥ sn(8 LE) ∥
  [key-hash(16) if the flag is set] ∥ payload-len(4 LE) ∥ payload ∥ crc32(4 over the frame body)`.
  `flags` encodes `kind` (`:data`/`:dispose`/`:unregister`) + key-hash-present. `payload` is the
  encrypted-store's OPAQUE v2 blob (which itself carries the epoch-id); **the file store does NOT
  parse the sealed bytes**. The CRC32 uses the standard reflected polynomial **`0xEDB88320`** (an
  integrity check on the frame, not a security primitive — tamper detection is the GCM tag).
- **In-memory index (rebuilt on open):** `topic → ((guid . sn) → frame)`. `put` = idempotent insert
  (skip if `(guid,sn)` present). `get-range` = index values sorted by `(guid bytes ascending,
  sn ascending)` (reusing the engine's `%guid-list<`). `topics` = index keys with ≥1 live record.
  `purge` = delete the topic log + drop the index entry. `count` = index size.
- **Replay + recovery on open:** `%parse-frame` reads each log frame-by-frame and returns
  `:ok` / `:short` / `:corrupt`. The frame `kind` is validated BEFORE the CRC; an invalid kind ⇒
  `:corrupt`. A **torn / short TRAILING frame** (a partial write from a crash mid-append) ⇒
  **truncate the file at the last valid frame offset + recover** (`store-open` continues). A
  **mid-file corruption** (a `:corrupt` frame that is not the trailing one) ⇒ **fail the open
  loudly** — recovery only truncates a torn *tail*; a mid-file CRC failure could mask tampering and
  must not be silently skipped. A declared `payload-len` above the `+frame-max-payload+` sanity cap
  is `:corrupt` (checked BEFORE the length-vs-buffer test), so a gross length-field corruption fails
  loud rather than masquerading as a torn tail and silently truncating live data (NFR-SEC-POSTURE
  resource guard; `epochs.dat` `kem-ct-len` gets the same cap via `+epochs-max-ctlen+`). Residual: a
  tail-region length corruption that stays under the cap is still indistinguishable from a torn tail
  (per-frame header integrity is a §10 follow-on). (`run-durability-file-recovery-test` discriminates
  torn-tail-recovers / mid-file-errors / over-cap-plen-errors; `run-dare-epochs-recovery-test` covers
  `epochs.dat`.)

### Cross-restart key-epoch (new-epoch-per-open) — the security crux

- `D/epochs.dat` — append-only epoch table; entry = `epoch-id(4 LE) ∥ kem-ct-len(4 LE) ∥
  kem-ct ∥ crc32(4)`. `kem-ct` is the ML-KEM-1024 ciphertext (1568 B) for that epoch (CRC-framed +
  tail-recoverable like a topic log).
- **On store-open:** load `epochs.dat`; for each epoch,
  `key-provider-decapsulate(kem-ct) → shared-secret → derive-dek → DEK` (held foreign per epoch);
  build an `epoch-id → DEK` map. **Open does NOT mint** — a read-only/replay-only restart adds no
  epoch.
- **Mint the CURRENT epoch lazily — on the first `put` of this run.** Order matters and is the
  as-built (a review fix, see Consequences): `ml-kem-1024-encapsulate(recipient-public-key) →
  (kem-ct, ss); DEK_new = derive-dek(ss)` is computed **BEFORE** the epoch entry is appended
  (deriving the DEK before append guarantees no half-minted epoch-id is referenced by a record).
  Append `{new-epoch-id → kem-ct}` to `epochs.dat` and **fsync it before writing the record that
  references it**. The minted epoch becomes CURRENT; its nonce counter starts at 0.
  `new-epoch-id = max(existing)+1` (4 bytes ⇒ 2^32 opens; an assert-guard on overflow).
- **put:** seal the payload under the CURRENT epoch's DEK + the next counter nonce; the v2 blob
  records the current epoch-id.
- **get-range / open:** `open-payload-v2` reads the record's epoch-id, looks up its DEK in the map
  (unknown epoch-id ⇒ NIL ⇒ **fail-closed drop**), then `aes-256-gcm-open`.
- **On close:** zeroize + free every epoch DEK (`free-secret-octets`); `key-provider-close`.
- **Why nonce reuse is structurally impossible.** Every run mints a **distinct epoch ⇒ a distinct
  DEK with its own counter-from-0 nonce space**. No two runs ever share a `(DEK, nonce)` pair,
  regardless of crash timing — there is **no counter-resume to get wrong** (the rejected
  alternative). This holds even after a crash-recovery truncation: a recovered-then-reopened store
  mints a fresh epoch. The epoch table grows by one entry per open (~1.6 KB/epoch, bounded by
  restart count; epoch-table retirement for very-old epochs with no live records is a §10
  follow-on). Mechanical security assertions (cross-run DEK distinctness, intra-epoch nonce
  distinctness, kem-ciphertext distinctness) are part of the test suite.

### Envelope v2

- `seal-payload-v2`: `#x02 ∥ epoch-id(4 LE) ∥ nonce(12) ∥ ciphertext ∥ tag(16)`. The AAD passed to
  AES-256-GCM additionally binds the epoch-id (`%append-epoch-aad-bytes`, used symmetrically by
  seal and open — **defence-in-depth**: a swapped epoch-id already selects the wrong DEK ⇒ tag
  mismatch ⇒ NIL, and the epoch-id is *also* inside the AEAD, proven by the
  `:v2-epoch-aad-binding` discriminator — seal under epoch 7, patch the header to 8, decrypt with
  the SAME DEK ⇒ GCM still fails, so the epoch IS authenticated). The decorator's per-record AAD
  (`%record-aad-v2`) additionally binds the **cleartext frame metadata** — `topic ∥ writer-guid ∥
  sn ∥ kind ∥ key-hash` — so a disk-write adversary who flips a record's key-hash (which the file
  store writes in the clear, CRC-only, to route the instance) and fixes the trivial CRC still fails
  the GCM tag ⇒ fail-closed drop (`run-dare-keyhash-aad-test`); key-hash was previously outside the
  AEAD (a final-review fix, see Consequences).
- `open-payload-v2`: bounds-check (`len ≥ 1+4+12+16`); read version; `#x02` ⇒ read epoch-id +
  nonce + ct + tag, resolve the DEK by epoch-id (NIL on miss), `aes-256-gcm-open`. The `#x01` path
  is unchanged for the in-memory tier. **Bounds-checked even at `(safety 0)`** (explicit manual
  checks, safety-independent); fuzzed (NFR-SEC-POSTURE — the crash-injection arm).
- The decorator selects v1 vs v2 by whether it is epoch-aware (`:epoch-dir` present). v2's
  epoch-id is read by the decorator (which holds the DEK map) — the file store stays oblivious.

### PERSISTENT lifetime, retention & compaction

- PERSISTENT (DDS 1.4 §2.2.3.4) survives service **AND** system restart (the files persist). On
  PERSISTENT-tier `service-start`, the store opens → replays the logs → `%seed-relay-from-store`
  seeds the replay writer's TL/KEEP_ALL HistoryCache from the store (publish-on-collect only fires
  for LIVE traffic, so a restart with no live publisher needs the explicit seed). The existing TL
  late-joiner machinery (ADR 0022) then delivers the retained history to a post-restart
  late-joiner with no original writer present (as in the TRANSIENT service, but the store outlived
  a restart). The seed is **all-delivered**: during seeding there is no matched reader yet ⇒ no
  backpressure ⇒ the replay writer's TL cache is unbounded ⇒ every seeded record is cached (a
  `:timeout` was proven structurally impossible during seeding, and `:timeout`/errors are surfaced
  via `*durability-error-hook*`, never silently dropped — a review fix, see Consequences).
- **Retention:** bounded `max-samples` (per the existing store; `:rejected` when full) +
  dispose/unregister tombstones (modeled as `:dispose`/`:unregister` records). Per-instance
  KEEP_LAST-superseded compaction (dropping older SNs of an instance) and Lifespan-QoS expiry are
  §10 follow-ons — the store does not yet supersede an instance's older SNs.
- **Compaction-on-open (CONSERVATIVE).** On open, before building the index, the replay drops dead
  records and rewrites the topic log keeping only live records, via an **atomic rewrite**
  (`uiop:rename-file-overwriting-target`). The MVP compaction is **deliberately conservative and
  order-aware**: it drops a key-hash only when BOTH a `:dispose` and an `:unregister` tombstone are
  present AND the instance's **final** record (in append order) is itself a tombstone — so a legally
  **resurrected** instance (a `:data` written after the teardown) is **never** dropped, and a live
  record is **never** dropped (`run-durability-compaction-test` + `run-durability-resurrection-compaction-test`
  guard this; the earlier order-insensitive set-membership form dropped a resurrected instance — a
  final-review fix, see Consequences). KEEP_LAST-superseded and online/threshold compaction during a
  long run are §10 follow-ons.

### Crash-consistency

- **Group-commit fsync per drain tick.** The collect loop appends the batch it drains each ~5 ms
  poll, then issues a **single fsync per tick** via the generic `store-sync` (`:sync` vtable slot)
  → `dds.pal:fsync-stream`. A crash loses at most the current sub-tick's not-yet-synced records.
  **The encrypted-store decorator delegates `store-sync` to the inner file store** — so the
  production DARE-wrapped PERSISTENT config (encrypted-store over file-store) IS fsynced (the chain
  `encrypted-store → store-sync → file-store fsync` was a review fix; the missing delegation would
  have meant the DARE config never fsynced = data loss, see Consequences). The delegation is
  regression-guarded (`run-durability-sync-delegation-test`). A fsync the OS reports as failed
  (`fdatasync` → −1) is **surfaced via `*durability-error-hook*`, not silently swallowed** — un-synced
  data is never reported durable (fail-closed; a final-review fix).
- Append-only files + no in-place mutation ⇒ crash-safe by construction. CRC32 + length framing ⇒
  a torn trailing frame is detected and truncated on open; the store never reads a partial record.
- **Ordering invariant:** `epochs.dat` is fsync'd before any topic-log record references the new
  epoch, so every record's epoch-id always resolves after a crash. `epochs.dat` entries are
  themselves CRC-framed + tail-recoverable. **Caveat:** file *contents* are `fdatasync`'d, but the
  *containing directory* is not — a newly-created log / `epochs.dat` / the compaction rename relies
  on the parent-directory entry, whose durability across a power loss needs a directory fsync (a §10
  follow-on), so this invariant's "resolves after a crash" assumes the directory entry survived.
- **Crash-injection fuzz** (NFR-SEC-POSTURE, a `(safety 0)` arm): random tail-truncation /
  garbage-append / mid-file corruption of topic logs and `epochs.dat` ⇒ open recovers to the last
  valid frame, **no crash / no OOB / no mis-decode**, and (critically) **no nonce reuse** (a
  recovered-then-reopened store mints a fresh epoch).

### Phase-2 carry-forwards (folded into this WP)

- **Collect-loop seen-set prune.** The Phase-2 dedup `seen-data`/`seen-lc` sets were unbounded
  (the Phase-2 review's NFR-MEM item). They are now bounded to **O(live-origins ×
  `*max-gap-range*`)** vs O(total-samples): a per-origin LO watermark + a capped above-watermark
  set (mirroring the receiver-side dedup of ADR 0024). The lifecycle dedup key `(car . cdr)` is
  semantically identical to the old flat `GUID.SN`; no-double-delivery and no-false-reject are
  preserved (proven by `:prune-lc-no-double` + `:prune-shed-readmission`).
- **Dynamic-topic-add.** `service-add-topic` adds a topic to a running service — a new disc-node
  (reusing `%build-disc-node`, DRY) + a store partition + its own collect/replay pair, **under the
  service lock**; returns `(values t node)` (or `(values nil nil)` if already present).
  **Idempotency is by TOPIC NAME** — a per-service `equal` hash-table populated at `service-start`
  + `add-topic`, time-stable and O(1), with a **TOCTOU-guarded final-lock re-check** (an earlier
  idempotency-by-time-varying-prefix scheme double-added across a 1-second boundary — a review fix,
  see Consequences).

### Fail-closed everywhere (binding, NFR-SEC-POSTURE)

- `open-payload-v2` returns **NIL — never plaintext, never partial** — on a short blob, a wrong
  version byte, an unknown epoch-id, or any AES-GCM authentication failure. The decorator's
  `get-range` **drops** an un-openable record (counts it, fires `*dare-error-hook*`).
- A torn **trailing** record ⇒ truncate-recover (not a crash); a **mid-file** corruption ⇒ fail the
  open loudly.
- **DARE-unavailable / OpenSSL < 3.5 ⇒ a hard startup error (`dare-unavailable`), NEVER a
  plaintext-on-disk path** (the arena-exhaustion principle: no silent downgrade).
- The **key dir `K`** perms are enforced (0700 dir / 0600 key file, checked at open, fail-CLOSED on
  loose or unverifiable perms — inherited from the 3a key-provider). The **store dir `D`** holds only
  DARE-sealed payloads (payload confidentiality does not depend on `D`'s perms); enforcing 0700 on
  `D` to additionally shield the cleartext frame metadata is a §10 follow-on (the file store does not
  yet chmod `D`).
- **All secret material — every per-epoch DEK, the shared secret, the ML-KEM private key — lives in
  foreign-backed buffers via `dds.pal:alloc-static` / `dds.pal:free-static`** (NEVER
  `static-vectors:free-static-vector` directly), zeroized + freed at end-of-life. This is the
  clasp#1793-safe secret path (see Consequences); the structural no-DEK-double-free / no-UAF /
  no-leak property is verified by three lifecycle traces in review.

## Threat model & scope

PERSISTENT DARE gives **confidentiality of stored payloads** + **per-record authenticity** of the
payload AND its AAD-bound metadata (topic / GUID / SN / kind / key-hash) on disk, against an adversary
with read/write access to the store's files. **At-rest-on-disk is now REAL** (not the 3a RAM proving
ground) — direct disk inspection in the cross-DDS interop confirmed the topic logs hold only
full-entropy ciphertext (no plaintext), alongside `epochs.dat` and the 0600 ML-KEM key, yet the wire
after restart is byte-for-byte the plain-store transient shape. A flipped disk byte in any sealed
payload or AAD-bound field (incl. the cleartext-on-disk key-hash) is detected by the GCM tag + AAD and
**fails closed**; an unknown epoch-id, a torn frame, or an over-cap length fails closed. The
cryptographic set is **exactly the CNSA-2.0 suite** (AES-256-GCM, ML-KEM-1024, SHA-384, HKDF-SHA384)
with **no hand-rolled crypto** (FR-SEC-2). It does **NOT** provide **log-level integrity** — a
disk-write adversary can delete, reorder, or truncate whole records undetectably (there is no MAC'd
log chain) — nor metadata **confidentiality** (metadata is cleartext on disk), nor protect in-RAM
plaintext or data in transit. All recorded §10 follow-ons.

## Conformance

- **Cross-restart round-trip:** write N → `store-close` → a fresh `make-file-store`/encrypted-store
  on the same dir → `store-open` (re-derives prior epochs' DEKs) → `get-range` opens all N
  byte-exact.
- **New-epoch-per-open:** two opens ⇒ two `epochs.dat` entries; run-1 records readable in run-2
  (epoch-1 DEK derived), run-2 records under epoch-2; distinct epoch-ids and distinct DEKs asserted.
- **No plaintext on disk:** the topic-log frame payload for a record starts `#x02` (the v2 version
  byte), ≠ the plaintext.
- **Recovery:** `run-durability-file-recovery-test` — torn-tail recovers, mid-file errors, an
  over-cap `payload-len` errors (`+frame-max-payload+`); `run-dare-epochs-recovery-test` — `epochs.dat`
  torn-tail recovers, mid-file + over-cap `kem-ct-len` error.
- **Crash-injection fuzz** (`(safety 0)`): random truncation of logs + `epochs.dat` ⇒ open
  recovers, no crash/OOB/mis-decode, no nonce reuse.
- **Group-commit / compaction:** the `store-sync` chain reaches the file store under the DARE
  decorator (`run-durability-sync-delegation-test`); a live record survives compaction AND a
  resurrected instance survives (`run-durability-resurrection-compaction-test`); `:sync` is fsync'd
  per drain tick (fail-closed on a failed `fdatasync`).
- **Metadata authenticity:** a disk-tampered key-hash (the byte flipped, the frame CRC fixed) is
  dropped by the AEAD on read (`run-dare-keyhash-aad-test`) — the key-hash is AAD-bound.
- **PERSISTENT service (our-stack + cross-DDS, the per-feature DoD).** An in-process restart test
  re-greens on SBCL. The **LIVE cross-DDS transparency-after-restart** (`interop/durability-persistent/`,
  2026-06-20, both peers, a GENUINE 2-PROCESS restart sharing the same disk `D` + key `K`):
  process 1 sealed N samples to disk then exited; a fresh process 2 reloaded + decrypted the same
  N on reopen (`SVC2-RELOADED-FROM-DISK`); a late-joining foreign TL subscriber received exactly
  N byte-correct — **Connext 7.3.1: 458 sealed → 458 reloaded → 458 received**; **Fast DDS 3.6.1:
  186 → 186 → 186**. Both captures match the plain-store transient wire **byte-for-byte** (replay
  EntityId `0x00000102`, `firstAvailableSeqNumber=1` held on every HEARTBEAT, `CDR_LE (0x0001)` on
  all DATA, NACK→retransmit repair). The disk held only sealed bytes throughout (direct inspection).
- **Carry-forwards:** the seen-set prune bound (`:prune-lc-no-double`, `:prune-shed-readmission`);
  dynamic-topic-add (unit + a live SBCL sub-test; Clasp pass-skips the live-sub arm, NFR-PORT).
- **RTI Persistence Service coexistence — a DOCUMENTED FINDING (`interop/durability-persistent/coexistence/`).**
  This is **stronger than Phase-2**: we got RTI Persistence Service v7.3.1 to **RUN + RELAY at the
  TRANSIENT tier** (resolving the Phase-2 blocker — RTI PS was inert for TRANSIENT_LOCAL, ADR 0024),
  both relays live simultaneously across 4 runs. **The finding:** standard-OWI dual-relay
  exactly-once is **not cross-vendor-exercisable** against RTI PS, because RTI PS stamps
  `PID_KEY_HASH (0x0070)` + **ZERO** `PID_ORIGINAL_WRITER_INFO (0x0061)` — it conveys origin
  identity via its **vendor `PID_ENTITY_VIRTUAL_GUID`**, NOT the OMG-standard OWI our dedup keys on.
  Our relay (`0x00000102`) emits OWI byte-correct (534/534); RTI PS (`0x80000002`) does not. This
  is a **wire-dialect mismatch (RTI proprietary origin-id vs OMG OWI), NOT a code defect** —
  standard-OWI is the conformant choice (the OMG-conformance directive: a vendor interop behaviour
  goes ON TOP of, never replaces, conformant behaviour). The **authoritative no-double-delivery
  proof is the in-process `dds.tests:run-durability-no-double-delivery-test`** (re-greened on SBCL).
  Recognizing RTI's `PID_ENTITY_VIRTUAL_GUID` in coexistence dedup is a §10 follow-on
  (Connext-interop-on-top-of-standard).
- **Gates:** SBCL + Clasp (both deterministic — file IO + secrets via the PAL); `gate-hotpath`,
  `gate-types`, `mem` (0.0000 — the store is control-plane), `fuzz`, `wire` — all green.

## Consequences

- **NFR-MEM:** `make mem` stays **0.0000 bytes/sample** — the store and crypto are control-plane,
  off the measured CDR hot path. No bench warranted (no hot-path change).
- **Clasp determinism via the PAL (clasp#1793 avoided).** Per-epoch DEKs and all secret buffers are
  allocated/released through `dds.pal:alloc-static` / `dds.pal:free-static` (the same secret path
  3a established), never `static-vectors:free-static-vector` directly — on Clasp `free-static`
  recycles into a lock-guarded zero-on-reuse pool and never the interior-pointer `GC_FREE` that
  corrupts the Boehm heap (clasp#1793). The store + crypto validate **deterministically on both
  SBCL and Clasp**.
- **`dds.pal:fsync-stream` is an NFR-PORT split.** SBCL issues a true `fdatasync(2)` via CFFI on
  the stream's fd. **Clasp falls back to `finish-output`** (a documented NFR-PORT gap — Clasp does
  not expose a stream fd for `fdatasync` here), so the Clasp durability validation proves the
  group-commit *path* and recovery logic but not the OS-level disk-flush barrier; the SBCL path is
  the production durability guarantee. This is the only PERSISTENT NFR-PORT gap; the dynamic-topic
  live-sub arm also pass-skips on Clasp (timing).
- **No new external dependency.** The file store is plain-file IO (no new `:depends-on`; the only
  `.asd` change is the new `store-file` component). DARE's OpenSSL ≥ 3.5 is the inherited hard
  runtime requirement (ML-KEM landed in the 3.5 LTS; `dare-available-p` hard-errors if absent —
  never a plaintext fallback). The SBOM dependency set is unchanged.
- **Review findings fixed during the WP** (the as-built incorporates them): the encrypted-store
  `:sync` delegation (the production DARE config would otherwise never fsync = data loss); the lazy
  mint's derive-DEK-before-append ordering; the seed-relay `:timeout`/error path surfaced via the
  hook (not silently swallowed); dynamic-topic idempotency-by-name (an idempotency-by-time-varying-
  prefix scheme double-added across a 1 s boundary, TOCTOU-guarded); the torn-vs-corrupt frame
  classification (`%parse-frame` → `:ok`/`:short`/`:corrupt`, kind validated before CRC) +
  recovery tests; the crash-injection fuzz arm made strict (a vacuous-pass was caught); the atomic
  compaction rewrite + a live-record-survives-compaction test; mechanical security assertions
  (cross-run DEK distinctness, intra-epoch nonce distinctness).
- **Final whole-branch review (pre-merge) additionally fixed** (the as-built incorporates them):
  the interior-`plen`/`ctlen` masquerade (an over-cap length is now `:corrupt`, not a silent
  torn-tail truncation, + the mandatory NFR-SEC-POSTURE resource cap); **order-aware compaction** (a
  legally resurrected instance is no longer dropped); **key-hash bound into the v2 AAD** (a
  disk-tampered key-hash now fails closed — it was previously CRC-only); `%append-epoch` now
  `fdatasync`s `epochs.dat` (the ordering invariant is real on the SBCL path, not merely
  page-cache-flushed); **fail-closed fsync** (a failed `fdatasync` is surfaced via the error hook,
  not swallowed); the **supervisor restart path now closes the dead instance's store** (no leaked
  file handles / un-zeroized DEKs on a supervised PERSISTENT restart — a regression this WP's
  store-open-on-start would otherwise have introduced); a `+max-nonce-counter+` guard and a
  `%load-epoch-deks` `unwind-protect` (no partial-load DEK leak). New regression tests:
  `run-durability-resurrection-compaction-test`, `run-durability-sync-delegation-test`,
  `run-dare-keyhash-aad-test`, `run-dare-epochs-recovery-test`, + a plen-over-cap recovery arm and
  an `epochs.dat` crash-injection fuzz arm.
- **Gates:** `make test` (SBCL + Clasp, both deterministic), `gate-hotpath`, `gate-types`, `mem`
  (0.0000), `fuzz`, `wire` — all green on both impls.

## §10 — Follow-on roadmap (recorded, NOT built in 3b)

Per the ADR 0025 §10 MUST-roadmap (owner directive 2026-06-19) and the design spec §14, each its
own vertical slice:

1. **Cross-vendor coexistence dedup recognizing RTI's `PID_ENTITY_VIRTUAL_GUID`** — so a live
   dual-relay-exactly-once proof with RTI Persistence Service becomes exercisable (a
   Connext-interop behaviour ON TOP of the conformant standard-OWI dedup; the documented coexistence
   finding above).
2. **KEEP_LAST-superseded compaction + online/threshold compaction** — the current compaction is
   conservatively dispose+unregister-then-settled-only; superseded-SN reclamation and long-run
   online compaction are deferred.
3. **Graceful FFI teardown on signal** — a **benign** SIGBUS in a non-Lisp thread was observed on
   `kill -15` during shutdown (cosmetic, post-run, in the FFI teardown of a process being killed);
   a clean signal-handled teardown is a follow-on.
4. **Epoch-table retirement** — compaction/retire of very-old epochs with no live records (the
   table grows by one ~1.6 KB entry per open).
5. **(3c) Metadata confidentiality** — seal the record metadata (topic/GUID/SN/kind), not just the
   payload; needs an encrypted/independent index (the current AAD-cleartext model forfeits this).
6. **In-RAM plaintext minimization** — bounded; full RAM-plaintext confidentiality is not
   achievable in pure Lisp without OS/HW support (confidence the full goal is reachable as-is:
   **low**); the key material is already foreign-buffered + zeroized.
7. **(M7/P6) DDS-Security — in-transit / wire confidentiality + the five DDS-Security plugins** —
   the whole P6 milestone (the relay emits standard plaintext DDS samples on the wire).
8. **db / microservice persistence backends** — ADR 0021 lists them; **file** is the 3b backend, on
   the same `durable-store` vtable so a db backend drops in later.
9. **Per-frame header integrity + log-level at-rest integrity** — the sanity cap closes gross length
   corruption, but a tail-region length corruption under the cap is still indistinguishable from a
   torn tail, and a disk-write adversary can delete/reorder/truncate whole records undetectably; a
   per-frame header CRC + a MAC'd log chain (or a sealed/independent index) closes both.
10. **Parent-directory fsync** — file *contents* are `fdatasync`'d but the containing directory is
    not; durable directory entries for newly-created logs / `epochs.dat` and the compaction rename
    across a power loss need a `dds.pal:fsync-directory` (SBCL dir-fd `fsync`; Clasp documented gap).
11. **`:process`-mode PERSISTENT** — `%spec->argv` does not serialize the store factory, so a
    `:process`-mode spec silently runs the in-memory tier; serialize the store config across the CLI
    (or fail-fast). Use `:thread` mode for the PERSISTENT tier until then.
12. **Store dir `D` 0700 enforcement** — perms are enforced on the key dir `K`; enforcing 0700 on `D`
    to shield the cleartext frame metadata is deferred (payload confidentiality is DARE, perms-independent).

## References

- ADR 0021 — Durability service scope + capability 7 (always-on CNSA-2.0 DARE)
- ADR 0023 — TRANSIENT durability service Phase-1 architecture
- ADR 0024 — Phase-2 dedup (PID_ORIGINAL_WRITER_INFO + bounded watermark) + the coexistence carry-forward
- ADR 0025 — DARE: CNSA-2.0 Data-At-Rest Encryption (§5 nonce discipline / `version`-byte reservation, §10 roadmap)
- `docs/superpowers/specs/2026-06-20-durability-persistent-design.md` — the PERSISTENT design spec
- `src/dds-durability/store-file.lisp` — the file-store backend (framing / index / replay / recovery / compaction)
- `src/dds-durability/store-encrypted.lisp` — epoch-aware encrypted-store (epoch table, per-epoch DEK map, `:sync`)
- `src/dds-dare/envelope.lisp` — `seal-payload-v2` / `open-payload-v2` (envelope v2)
- `src/dds-durability/{spec,service}.lisp` — `make-persistent-store-factory`, `%seed-relay-from-store`, `service-add-topic`, the seen-set prune
- `src/dds-pal/pal-{sbcl,clasp}.lisp` — `dds.pal:fsync-stream` (group-commit; NFR-PORT split)
- `src/dds-tests/durability-test.lisp` — `run-durability-file-recovery-test`, the cross-restart/no-plaintext/persistent-service tests, `run-durability-no-double-delivery-test`
- `src/dds-tests/pbt-test.lisp` — the crash-injection fuzz arm (NFR-SEC-POSTURE)
- `interop/durability-persistent/` — live cross-DDS transparency-after-restart (Connext 458 / Fast DDS 186) + the RTI-PS coexistence finding
- `docs/wiki/durability.md` §8 — PERSISTENT user documentation + the `make-persistent-store-factory` example
