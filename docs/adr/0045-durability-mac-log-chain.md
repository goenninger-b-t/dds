# ADR 0045 — Durability at-rest MAC'd log chain (keyed whole-record tamper-evidence)

Status: Accepted
Date: 2026-07-04
Work package: WP-DURABILITY-MAC-LOG-CHAIN (feature follow-on #2 of 4; resolves the ADR 0026 §10.9 open follow-on)
Supersedes/updates: ADR 0026 §10.9 (the "MAC'd log chain" follow-on is now RESOLVED, with two residuals left explicitly deferred — see §7)

## 1. Context

Batch B (ADR 0026 §10.9) added a per-frame **CRC-32** to the durability file-store frame
(format v2: a header CRC over `magic..payload-len` plus the trailing whole-frame CRC). A CRC
detects **accidental** corruption. It is **not** a MAC: a disk-write adversary who edits a frame
and recomputes its CRC is undetected, and — the specific §10.9 gap — whole records can be
**deleted, reordered, substituted, or inserted** in the on-disk log undetectably.

For the encrypted/epoch store the AES-256-GCM tag already authenticates each frame's *payload*
plus its metadata (topic/guid/sn/kind/key-hash/epoch-id, via `%record-aad-v2`), so per-frame
authenticity exists. But there is **no chaining across frames**, so record-level
delete/reorder/insertion across the log is invisible: GCM authenticates each frame in isolation,
never the *sequence*.

This ADR adds a **keyed running MAC chain** over the per-topic frame sequence that binds each
frame to its predecessor, making interior delete/reorder/substitution/insertion **tamper-evident
at store-open** (fail-closed, exactly like a mid-file CRC `:corrupt`).

## 2. Threat model

In scope (what this WP detects and rejects, at store-open, fail-closed):

- **Interior record DELETE** — remove a whole frame from the middle of a topic log.
- **Record REORDER** — swap the on-disk order of two frames.
- **Record SUBSTITUTION** — replace a frame's bytes (metadata and/or sealed payload), *even if
  the adversary recomputes that frame's CRC-32* to defeat the Batch-B CRC gate.
- **Record INSERTION** — splice a forged/replayed frame into the middle of the sequence.

Adversary model: a disk-write adversary who can read and rewrite the on-disk log arbitrarily and
recompute any CRC-32, but does **not** hold the recipient's ML-KEM-1024 private key (kept inside
the key-provider; never exposed — the KMS/HSM hook, ADR 0021 cap.7). Without that key the
adversary cannot compute the keyed HMAC, so cannot forge a valid chain link.

Out of scope (documented residuals, deferred — see §7):

- **Whole-tail truncation of a valid prefix.** A bare running chain provably cannot detect it: the
  shorter log is itself a valid chain. Detecting it needs an external **sealed high-water anchor**.
- **Cross-store / whole-file replacement of an *older* valid store snapshot.** Same anchor
  territory (a store-level sealed high-water, not a per-frame link).

Explicitly not re-solved (already covered elsewhere): payload confidentiality (GCM), payload
authenticity (GCM tag), accidental corruption (CRC-32). The chain adds **sequence integrity**.

## 3. Scope decisions (pinned)

1. **Keyed-store-only.** The chain is a capability of a store that *has* a key: the
   encrypted/epoch store (`%make-epoch-encrypted-store`, which owns the per-epoch DEKs and the
   cross-restart-stable ML-KEM recipient keypair via the key-provider). The bare plaintext
   `make-file-store` gets **no key parameter** — that is a new deployment mode, out of scope. When
   no key is present the feature is simply absent: the CRC-only v2 framing stays.

2. **Fail-explicit / fail-closed on key absence.** The per-frame version byte *is* the capability
   flag: a v3 frame carries a MAC and therefore **demands** verification. A bare file store (no
   MAC oracle installed) that encounters a v3 frame fails loud (`:corrupt`) — it never
   silently skips verification. A store opened with the *wrong* key derives the wrong log-MAC key
   and every v3 link mismatches → fail loud.

   **Downgrade defense (§3.2, enforced — closes the full-log v3→v2 rollback).** Per-frame v3 demands
   are not enough on their own: a disk-writer inside the threat model can rewrite **every** v3 frame
   of a topic log back to a keyless-valid v2 frame (version byte → `0x02`, strip the 32-byte MAC,
   recompute the header CRC and frame CRC — all keyless), producing a byte-valid v2 log that needs no
   key and over which records can then be freely deleted/reordered/duplicated. Because the chain is
   only "started" once a v3 frame is seen, a **fully** downgraded log would otherwise replay with zero
   verification and open clean (and a subsequent compaction could even re-emit the tampered set as a
   fresh valid v3 chain, laundering it). The **`logmac.anchor` file is the store's chain commitment**;
   a **CHAIN-REQUIRED** guard rejects, at store-open, any committed topic log that has been rolled
   back to zero v3 frames — enforced **inside `%replay-log`, before the caller's compaction rewrite**,
   so a downgrade can never be laundered. Equivalently: the highest-offset frame of a chain-required
   non-empty log must be v3 (a v2/v1 frame *after* a v3 frame is already rejected mid-replay, so a v3
   tail proves the chain is active).

   The commitment is minted **lazily on the first v3 put** (mirroring the epoch mint), so *anchor
   present ⟺ ≥1 v3 frame was written* — a legacy Batch-B v2 store opened read-only never mints an
   anchor and always opens; its first write commits it.

   **Multi-topic correctness — the grandfather set.** The commitment is store-global (one anchor), but
   the enforcement is **per-topic** (each topic is its own log). A durability service puts many topics
   in one store, so a naive store-global `CHAIN-REQUIRED` flag would false-REJECT a **dormant legacy
   topic**: legacy store with topics *A* and *B* both all-v2, no anchor; a write to *B* mints the
   anchor and chains *B*, leaving *A* untouched all-v2; the next open would then reject *A* (non-empty,
   zero v3 frames) — a terminal false-reject of an untampered legacy log. Making the flag per-topic by
   *inferring* "chain-required iff this topic has a v3 frame" would re-open the bypass per-topic (a
   fully-downgraded topic has zero v3 frames ⇒ inferred not-required ⇒ opens). Instead the anchor
   records, at mint time, an **authenticated grandfather set**: the topic-ids of every **non-empty**
   topic log present when the anchor is minted (all legacy v1/v2, since anchor-absent ⇒ no v3 written
   yet). A topic is CHAIN-REQUIRED iff (anchor present) **and** (its topic-id is **not** grandfathered).
   Dormant legacy topic *A* is grandfathered ⇒ opens (no false-reject); born-chained topic *B* (created
   after the anchor, or the topic that triggered the mint but had no prior log) is not grandfathered ⇒
   a downgrade of *B* still fails. The set is **authenticated** by an HMAC over it under the log-MAC
   key (the anchor's signed format, §4.6), so a disk adversary cannot forge/extend it to exempt a born-chained topic;
   a mismatch fails the open. **Crash-safe:** the anchor (with its grandfather set) is written **once**
   at mint and never updated — no migration burst, no per-topic anchor rewrite, so an interrupted
   first-v3-put leaves either no anchor (retry mints it) or the anchor with the triggering topic still
   in the grandfather set (it had a prior non-empty log) / its new log empty (nothing to reject) — never
   a terminal false-reject. The narrow residual (a *grandfathered* topic later chained can be downgraded
   back to v2 and still open) is documented in §7.3.

3. **Fail-direction parity with Batch-B.** A chain break mid-log (MAC mismatch, or a non-v3 frame
   after the chain has started) → `:corrupt` → store-open signals loudly, same direction as the
   mid-file CRC path. An *honest* short trailing frame → `:short` → truncate-recover (unchanged),
   subject to the §7 tail-truncation residual.

4. **The chain covers metadata + linkage, not a redundant second full-payload MAC.** There is
   exactly one MAC per frame (the chain link). Its input is `prev-chain-MAC ∥ frame-prefix`, where
   the frame-prefix is every byte of the frame before the MAC field — i.e. magic, version, flags,
   guid, sn, key-hash, payload-len, header-CRC, and the (already-GCM-sealed) payload. Because the
   store-open verifier has no DEK, covering the sealed-payload bytes lets the chain detect payload
   substitution at open **without** decrypting; it is not a second independent payload MAC.

## 4. Design

### 4.1 Format v3 (per-frame version byte, mirrors the v1→v2 discipline)

```
v2: magic(1) version(1)=0x02 flags(1) guid(16) sn(8) [kh(16)] plen(4) hdr-crc(4) payload            frame-crc(4)
v3: magic(1) version(1)=0x03 flags(1) guid(16) sn(8) [kh(16)] plen(4) hdr-crc(4) payload  MAC(32)    frame-crc(4)
```

- `+frame-version-v3+` = `0x03`, alongside v1 (`0x01`) / v2 (`0x02`).
- The 32-byte MAC field sits immediately after the payload and before the trailing frame-CRC. The
  header-CRC and frame-CRC **stay** (CRC = accidental-corruption detection; MAC = tamper-evidence).
- The frame-CRC now covers through the MAC field, so accidental corruption of the MAC bytes is
  caught as `:corrupt` by the CRC just like any other frame byte; deliberate MAC forgery is caught
  by the keyed HMAC.
- **Reader reads v1/v2/v3** per-frame (`%parse-frame` dispatches on the version byte; mixed logs
  are legal — a pre-upgrade v2 prefix followed by v3 frames). **Writer writes v3 only when the
  chain is active** (a MAC oracle is installed); otherwise it writes v2, byte-identical to Batch-B.

### 4.2 The MAC primitive and the chain link

Reuse the existing DDS-Security session-key MAC, **no new dependency, no hand-rolled MAC**:
`dds.dare:hmac-sha256` (HMAC-SHA-256, FIPS 198-1). The per-frame chain MAC is

```
MAC_i = HMAC-SHA256( logmac-key , chain_{i-1} ∥ frame_i[0 .. mac-offset) )
chain_i = MAC_i                                (the running state fed to frame i+1)
chain_0 = seed(topic)                          (the per-topic keyed head)
seed(topic) = HMAC-SHA256( logmac-key , "dds-dare/logmac/seed/v1" ∥ utf8(topic) )
```

`frame_i[0 .. mac-offset)` is the whole frame prefix up to (excluding) the MAC field. Verify at
store-open recomputes `MAC_i` for each v3 frame in on-disk order and compares to the stored field;
any mismatch → `:corrupt` (loud). The per-topic **seed binds the chain head to the topic identity
and the key**, so a whole-file swap of topic B's valid log into topic A's filename is also caught
(A's replay seeds from `seed(A)`, but the frames were MAC'd under `seed(B)`).

The MAC-oracle closure the file store receives is `λ(data) → hmac-sha256(logmac-key, data)` — the
file store assembles `prev ∥ prefix` and calls it, and computes seeds the same way. **The file
store never sees the log-MAC key bytes**, only this closure; the key stays in the decorator. This
is the "keyed-verify callback the decorator supplies" seam of ADR 0026 §10.9, realised as a
`durable-store` vtable slot (`set-chain-mac-fn`) the decorator installs *before* it drives the
inner `store-open`, so the inner replay verifies with the key already in hand.

### 4.3 Log-MAC key derivation that survives new-epoch-per-open restart

The epoch store mints a fresh per-epoch DEK on every open (new-epoch-per-open, ADR 0025 §5), so
the DEK is **not** stable across restarts and cannot key the chain. The log-MAC key must be derived
from a **cross-restart-stable secret**. The only secret stable across restarts is the recipient's
ML-KEM-1024 private key, held inside the key-provider and never exposed.

We anchor to it **without exposing it**, using the deterministic nature of ML-KEM decapsulation:

- At first open of a chain store we mint a dedicated **log-MAC anchor**: `ml-kem-1024-encapsulate(
  recipient-public-key) → (anchor-ct, anchor-ss)`; we persist `anchor-ct` in `EPOCH-DIR/logmac.anchor`
  (framed with a CRC, fsynced) and discard the mint-time `anchor-ss`.
- On **every** open (including the minting one, for a single code path) we read `anchor-ct`,
  `key-provider-decapsulate(anchor-ct) → anchor-ss`, and derive
  `logmac-key = HKDF-SHA384(ikm=anchor-ss, salt=∅, info="dds-dare/logmac/v1", L=32)`.

**Why it survives restart (high confidence):** FIPS-203 ML-KEM **decapsulation is deterministic**
in `(private-key, ciphertext)` — decapsulation draws no randomness (only *encapsulation* is
randomised). A fixed persisted `anchor-ct` therefore decapsulates to the **same** `anchor-ss` on
every run, so `logmac-key` is identical across restarts, while remaining secret (only the private
key can decapsulate it). The HKDF `info` label `"dds-dare/logmac/v1"` is a fresh domain separator,
distinct from the DEK's `"dds-dare/dek/v1"`, so the log-MAC key is cryptographically independent of
every DEK. `logmac-key` is a **foreign-backed secret buffer** (like the DEK), held for the store
lifetime and **zeroized + freed on close** (`free-secret-octets`); `anchor-ss` is freed as soon as
the key is derived.

### 4.4 Cross-epoch linkage (a restart is not a free break point)

The chain is **continuous per topic across epochs/restarts** — it is *not* reset per epoch —
precisely because (a) `logmac-key` is epoch-independent and stable (§4.3) and (b) store-open replay
restores each topic's running chain state to its persisted tail MAC before any new put. The first
frame appended in epoch *N+1* for a topic therefore chains from the last frame written in epoch *N*
(`chain_i = MAC` of the prior on-disk frame, whatever epoch wrote it). The restart boundary carries
no chain discontinuity an adversary could exploit; the "bind each epoch's chain-head to the prior
epoch's chain-tail" requirement is satisfied structurally by the continuous append chain, with no
separate per-epoch chaining mechanism and **no** new `epochs.dat` MAC (the cross-epoch linkage
rides the frame chain; `epochs.dat` stays entry-CRC-only per the Batch-B §10.9 note).

### 4.5 Compaction-on-open stays chain-correct

Compaction-on-open (settled-instance drop; optional KEEP_LAST) rewrites a topic log. When the chain
is active the rewrite re-emits **v3 frames with a freshly recomputed chain** (re-seed from
`seed(topic)`, re-MAC each kept record in on-disk order) and records the new tail MAC. This is an
authorized local operation (the store holds the key); an adversary without the key cannot forge
such a rewrite. Without an active chain the rewrite is byte-identical v2 (unchanged).

### 4.6 Anchor file format (`D/logmac.anchor`)

```
version(1)=0x01 ∥ ctlen(4 LE) ∥ kem-ct ∥ gf-count(4 LE) ∥ [ idlen(4 LE) ∥ topic-id-bytes ]{gf-count}
  ∥ gf-mac(32) ∥ crc32(4)
```

`kem-ct` is the log-MAC ML-KEM ciphertext (its deterministic decapsulation yields the stable log-MAC
key, §4.3). The grandfather entries are the exempt legacy topic-ids (§3.2). `gf-mac =
HMAC-SHA-256(log-MAC-key, "dds-dare/logmac/gf/v1" ∥ signed-region)` where the **signed region** is the
whole prefix before `gf-mac` (version … grandfather entries) — this authenticates both the kem-ct and
the grandfather set under the log-MAC key (the adversary cannot forge/extend the set, or swap the
kem-ct, without the recipient private key). `crc32` is accidental-corruption detection over everything
before it. On load, the store decapsulates → derives the key → **re-computes and checks `gf-mac`**
before trusting the set (mismatch ⇒ fail the open). The anchor is minted once and never rewritten
(§3.2 crash-safety); a corrupt/forged anchor signals (fail loud — a lost/garbled key marker must never
silently disable verification, unlike the torn-tail-recoverable `epochs.dat`).

## 5. Consequences

- Interior delete/reorder/substitution/insertion of records in a keyed durability log are now
  **tamper-evident at store-open**, fail-closed, on both SBCL and Clasp identically (the crypto is
  CFFI/OpenSSL, impl-agnostic).
- Per-put cost: one HMAC-SHA-256 over (32 + frame-prefix) bytes; per-open cost: one HMAC per v3
  frame during replay. Both are **off the sample hot path** (durability store put/open are not the
  RTPS per-sample path); no bench gate applies (ADR 0026 §10.9, this WP's brief).
- 32 extra bytes per v3 frame on disk.
- Back-compat: v1/v2 logs still read; a store upgraded in place writes v3 going forward and reads
  its own v2 prefix.

## 6. Alternatives considered

- **Derive the log-MAC key from a per-epoch DEK** — rejected: DEKs rotate every open, so the chain
  would not verify across restarts.
- **Derive from the recipient *public* key** — rejected: the public key is not secret; an adversary
  holds it and could forge the MAC.
- **A separate second full-payload MAC per record** — rejected as redundant with the GCM tag
  (§3.4); the single chain link covers the frame prefix instead.
- **A per-epoch chain reset with an explicit cross-epoch link field** — rejected as more mechanism
  than the continuous append chain, which achieves the same binding for free (§4.4).
- **MAC `epochs.dat`** — rejected: the cross-epoch linkage rides the frame chain; `epochs.dat`
  keeps the entry-CRC-only scheme (its ordering invariant already prevents orphaned epochs).

## 7. Residuals (explicitly deferred — do not build in this WP)

1. **Whole-tail truncation detection.** A bare running chain **cannot** detect truncation of a
   valid prefix — the shorter log verifies clean. Detecting it requires an external, independently
   **sealed high-water anchor**: a per-topic authenticated tail-marker recording the expected chain
   head (last MAC) + record count, written/sealed such that rolling the log back to an earlier valid
   prefix contradicts the anchor. That anchor is a **separable** mechanism (a store-level sealed
   index, not a per-frame link) and is deferred. **v1 therefore detects delete/reorder/substitution/
   insertion of INTERIOR records but not honest-prefix tail truncation.** The honest short-tail case
   still truncate-recovers (parity with Batch-B); malicious tail truncation is indistinguishable
   from it without the anchor.
2. **`epochs.dat` MAC** — deferred (kept entry-CRC-only; §6).
3. **Anchor deletion + full downgrade, and downgrade of a grandfathered topic.** The `logmac.anchor`
   file is the chain commitment (§3.2). Two transition-class residuals remain, both requiring a
   full-control disk adversary to remove/exploit an out-of-band commitment:
   (a) An adversary who **deletes the anchor** *and* downgrades every v3 frame to keyless v2 produces a
   state **byte-indistinguishable** from a legitimate fresh/legacy-v2 migration, so it opens in
   migration mode. (The weaker vectors are already closed: deleting the anchor while **keeping** v3
   frames fails the open — key-absent at replay; downgrading frames while **keeping** the anchor fails
   the open — §3.2.)
   (b) A topic that was **grandfathered** at mint time (a legacy v2 topic exempt from the downgrade
   check) but has since been written v3 can be **downgraded back to v2 and still open** — the exemption
   is fixed at mint and does not "upgrade" when the topic later chains. This is strictly narrower than
   (a): the topic's *present* v3 frames are still MAC-verified (tamper of those is caught); only a
   *full* rollback of that specific grandfathered topic to zero v3 frames evades the downgrade check.
   (c) The grandfather set is enumerated from the **mint-time on-disk topic logs**, which are untrusted
   under the raw-disk threat model: during the pre-mint (migration) window a disk adversary can create
   fake non-empty v2 logs for topics it intends to later downgrade, so those topic-ids get honestly
   *authenticated into the anchor* as exempt (a confused-deputy on the signer's input — the gf-mac is
   not forged, §5). This grants **no capability beyond (a)**: an adversary able to pre-seed logs before
   mint can instead just delete the anchor and downgrade the whole store; pre-seeding is strictly ≤ that,
   only stealthier (the anchor stays valid). It closes with the same deferred sealed anchor.
   Both close only with the same **separable sealed high-water anchor** as residual (1) — an
   independently-authenticated per-topic tail-marker whose absence/rollback is itself detectable — so
   they are deferred with it, not separately built. Every **born-chained** topic (created after mint,
   never in the grandfather set) is fully protected; the grandfather set itself reflects untrusted
   mint-time on-disk state and is closed only by the deferred sealed anchor — so a "fresh" store is
   fully protected only insofar as no logs were pre-seeded before its anchor was minted.
4. **Non-constant-time MAC compare (M3, accepted).** The chain-MAC equality check is `equalp`, not
   constant-time. Acceptable: verification runs only at local store-open with no remote timing oracle
   (a mismatch yields only a fail-closed open, no feedback loop). A trivial future hardening if the
   open surface ever becomes remotely observable.

All are recorded here and cross-referenced from ADR 0026 §10.9 so the remaining surface is explicit.

## 8. Verification

`run-durability-mac-chain-test` (durability-test) — round-trip clean; v1/v2 back-compat +
mixed-version read; interior DELETE / REORDER / SUBSTITUTE / INSERT each fail-closed with a
non-vacuous clean control (SUBSTITUTE and the cross-restart tamper mutate a **payload** byte past
the header-CRC coverage and recompute **both** CRCs, so the keyed MAC — not a CRC — is the gate that
fires); **full-log v3→v2 downgrade fails the open (§3.2, the C1 regression)** while a mixed
v2-prefix+v3-tail migration log still opens; **multi-topic legacy coexistence — a dormant legacy-v2
topic (grandfathered) reopens clean while a born-chained topic verifies and a downgrade of it still
fails (§3.2, the multi-topic false-reject regression)**; cross-restart (epoch-boundary) chain verifies +
cross-boundary tamper caught; key-absent (bare store) and wrong-key both fail-closed; honest
torn-tail still truncate-recovers. Plus the full DARE/durability integrity suite regression on
both impls (Clasp first).
