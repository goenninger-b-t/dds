# Security — DDS-Security Cryptographic plugin (serialized-payload protection)

This page covers the `dds-security` system: the DDS-Security 1.1 **Cryptographic plugin**,
Slice 1 (serialized-payload protection, §9.5.3.3).  Slice 1 (landed 2026-06-22, ADR 0031)
provides the on-the-wire **SecuredPayload** (de)serializer, the **session-key KDF**, the
**`key-material`** bundle, and the **`encode-serialized-payload`** / **`decode-serialized-payload`**
round-trip wired into the `disc-node` send and receive paths.  It reuses the CNSA-2.0 crypto
primitives from the [`dds-dare`](durability.md) system (OpenSSL >= 3.5) — no hand-rolled
crypto.  Every wire constant is cited from the §9.5.3.3 spec clause and the T0 spike
(`docs/superpowers/spikes/2026-06-22-dds-security-payload-wire.md`), never from memory.

DDS-Security is **gated (P6)** and additive: nothing here is on the measured CDR hot path,
and the plaintext path is **byte-identical** to before until a `crypto-transform` is
explicitly set on a `disc-node` (the default is `nil`).

---

## 1. The SecuredPayload wire format (DDS-Security 1.1 §9.5.3.3)

Serialized-payload protection (§9.5.3.3.4.4 `encode_serialized_data`) replaces the DATA
submessage's serialized payload with:

```
SecuredPayload = SecureDataHeader (20 bytes)
              || crypto_content   (4-byte uint32 length prefix + ciphertext)
              || SecureDataTag    (20 bytes, for receiver_specific_macs_count = 0)
```

### 1.1 SecureDataHeader (§9.5.3.3.1, 20 bytes)

| Offset | Width | Field | Notes |
|---|---|---|---|
| 0 | 4 | `transformation_kind` | `octet[4]`; AES256-GCM = `{0x00,0x00,0x00,0x04}` (Table 69) |
| 4 | 4 | `transformation_key_id` | `octet[4]`; the sender's key id (opaque) |
| 8 | 4 | `session_id` | `octet[4]`; random per session |
| 12 | 8 | `init_vector_suffix` | `octet[8]`; random per session |

The 20-byte SecureDataHeader is serialized as the §9.5.3.3.1 CryptoHeader on the wire, but the AES-GCM
**AAD is EMPTY** (Fast-DDS-faithful: `serialize_SecureDataBody`'s ENCRYPT branch sets no AAD; reconciled in
WP-DDS-SECURITY-FASTDDS-INTEROP T10, see ADR 0031 addendum). Header integrity is provided WITHOUT folding the
header into the AAD: decode applies the `find_key` check (wire `transformation_kind` + `transformation_key_id`
must equal the KeyMaterial's, else fail-closed), and `session_id`/`init_vector_suffix` derive the session key +
nonce (tamper → GCM auth fail). The 12-byte GCM **nonce** is `session_id (4) || init_vector_suffix (8)`
(§9.5.3.3.4.3). (Earlier slices folded the 20-byte header in as AAD; that changed the GCM tag bytes only — the
serialized field values are byte-identical.)

### 1.2 crypto_content (§9.5.3.3.4.4) and SecureDataTag (§9.5.3.3.3)

`crypto_content` is a `sequence<octet>`: a `uint32` length prefix (**BIG-ENDIAN**, §9.5.3.3.4.4 — forced
independent of the surrounding little-endian RTPS stream, Fast-DDS/Cyclone-aligned; T-RECONCILE) followed
by the ciphertext (its length equals the plaintext length — AES-GCM does not expand).  `SecureDataTag` for
serialized-payload protection without origin-authentication is `common_mac (16)` (the
128-bit GCM tag) `|| receiver_specific_macs_count (uint32 BIG-ENDIAN, = 0)`.

### 1.3 CDR encapsulation header — the decision

The serializer emits the **spec-minimal bare SecuredPayload** (no 4-byte CDR encapsulation
header before the SecureDataHeader).  The spec does not mandate one, and whether Connext
prepends one inside the DATA serialized-payload field is implementation-defined and
currently **unconfirmed** — the live Connext-Security capture was blocked (the RTI Security
Plugins add-on is not installed; spike §1).  A live Connext byte-compare to settle it is
the **deferred follow-on** (Slice 5).  The header, if ever present, is never part of the
AAD or the plaintext.

---

## 2. The API (`dds.security`)

### 2.1 Wire layer

| Symbol | Contract |
|---|---|
| `+transformation-kind-aes256-gcm+` | The `octet[4]` `{0,0,0,4}` constant (§9.5.3.3.1 Table 69) |
| `serialize-secured-payload (kind key-id session-id iv-suffix ciphertext tag)` | Build the bare SecuredPayload octet vector |
| `parse-secured-payload (octets)` | `(values kind key-id session-id iv-suffix ciphertext tag)`; bounds-checked, fail-closed |
| `derive-session-key (master-key master-salt session-id)` | The 32-byte AES-256 session key (§9.5.3.3.4.2) |

`parse-secured-payload` **bounds-checks every field read before allocating**: a too-short
input, or a declared `crypto_content.length` that overflows the buffer, signals
`secured-payload-malformed` — never an out-of-bounds read or a partial parse
(NFR-SEC-POSTURE), and the consistency check gates the result allocation so a hostile
`0xffffffff` length cannot exhaust the heap.  This holds even at `(safety 0)`.

### 2.2 KeyMaterial

`key-material` is a `defstruct*` (§9.5.2 `CryptoTransformKeyMaterial_DH`):

| Slot | Type | Role |
|---|---|---|
| `transformation-kind` | `(simple-array (unsigned-byte 8) (*))` | `octet[4]` algorithm selector (public, on wire) |
| `master-salt` | foreign/static `(unsigned-byte 8)` | **SECRET** — 32 bytes mixed into the session-key KDF |
| `sender-key-id` | `(simple-array (unsigned-byte 8) (*))` | 4 bytes placed in SecureDataHeader `transformation_key_id` (public) |
| `master-sender-key` | foreign/static `(unsigned-byte 8)` | **SECRET** — 32-byte HMAC key for the KDF |
| `master-receiver-specific-key` | foreign/static `(unsigned-byte 8)` | **SECRET** — 32-byte origin-auth (§9.5.3.3.4.3) receiver key |
| `iv-counter` | `(unsigned-byte 64)` | monotonic counter for structural nonce uniqueness |
| `iv-counter-lock` | opaque | guards `iv-counter` against concurrent encoders |
| `zeroized` | `boolean` | fail-closed marker set by `zeroize-key-material` (see §2.4) |

**`make-test-key-material`** returns a fresh `key-material` with fixed, published,
non-secret constants.  It is the **MVP scaffold for offline testing only** — NOT for
production use.  The Slice-2 Auth handshake replaces it with per-writer KEM-derived keys.

Single-instance constraint: at most **one** `key-material` instance from
`make-test-key-material` may encode at a time.  Two instances sharing the same master
key start `iv-counter` at 0 and will produce colliding AES-GCM nonces (catastrophic).
Slice-2 Auth resolves this by giving each writer a unique derived key.

### 2.4 Secret hygiene — foreign/static MASTER slots + zeroize-on-teardown (ADR 0034)

The KeyMaterial's three MASTER secret byte slots (`master-salt`, `master-sender-key`,
`master-receiver-specific-key`) live in **foreign/static** memory (off the GC heap, non-moved,
SAP-addressable) via `dds.dare:octets->secret` — the Lisp-vector companion to the ADR 0025 /
ADR 0032 `free-secret-octets` secret discipline.  `make-key-material` hardens these master slots
at construction.  A moving GC can no longer copy the master secrets, freed heap cannot linger with
them, and they can be reliably wiped (operating contract NFR-MEM / CNSA-2.0 data-at-rest).

The derived §9.5.3.3.4.2/.4.3 session-key caches (`cached-session-key`, `cached-recv-session-key`,
`cached-recv-master-key`) are **ephemeral plain GC-heap** vectors — re-derivable per `session_id`
from the master secrets, short-lived, GC-reclaimed; they are **not** long-lived secrets-at-rest.
They are deliberately NOT foreign-static: a fresh foreign-static copy per `session_id` would
**unboundedly leak** un-wiped key buffers when a peer rotates `session_id` (the derivation runs
before the GCM auth check, so it is reachable pre-auth), and free-on-replace would be a
use-after-free of the lock-free-shared slot handed to a concurrent GCM open.  GC-heap is the
correct representation: ephemeral, re-derivable, GC-safe, no leak.

**`zeroize-key-material (km)`** is the single teardown choke: it wipes-then-frees the three MASTER
slots and **drops** (nils; GC reclaims — no wipe/free needed) the ephemeral heap caches, and is
**idempotent + fail-closed** (a `zeroized` marker is set first, so a second call — or a dedup
re-walk — is a no-op and a torn-down KM reads as unusable).  It MUST run only when the data path is
**quiesced**.  Every free path funnels through it: the crypto-manager's `all-kms` roster (which
covers even re-key-orphaned KMs — never freed mid-run, so no live resolver ever touches freed key
bytes) is walked by `cm-teardown` from `delete-participant` after `stop-node` joins the receiver
thread; the disc-node's PVMS bootstrap KeyMaterials are wiped in `stop-node`.

**Remote-KM drop-on-unmatch (ADR-0034 MINOR-4).**  When a remote participant leases out, `%lease-sweep`
fires `disc-node-on-participant-lost` → `cm-forget-remote-participant`, which DROPS that peer's
KeyMaterials from the four ACTIVE lookup registries (`remote-participant-crypto`, `remote-entity-crypto`,
`key-id-index`, `remote-key-id-entity`) — so a lost peer's keys are unresolvable (fail-closed) and a
peer-churning participant's data-path tables stay **bounded** — and **wipes their master secrets in place**
(`wipe-key-material-secrets`: fill-0, no free) for prompt hygiene.  The KM handle is deliberately KEPT in
`all-kms` so the foreign-static buffers are freed **exactly once at the quiesced teardown** — freeing on
lease-out would use-after-free a concurrent in-flight decode (a lease-expired peer's delayed/replayed
datagram resolved before the drop): the **no-mid-run-free** invariant. `wipe-key-material-secrets` does NOT
set the `zeroized` marker, so `cm-teardown` still performs the free.

The **PVMS bootstrap KMs** (the disc-layer §9.5.3.1 `disc-node-pvms-bootstrap-kms`, prefix→KM) get the same
peer-loss treatment: `%lease-sweep` also calls `%prune-pvms-bootstrap-km`, which drops the lost peer's bootstrap
KM from the active table (unresolvable → fail-closed, bounded), wipes its secrets in place, and parks the handle
on `disc-node-retired-pvms-kms` so the foreign (KxKey/KxSalt-derived) free stays at the quiesced `stop-node`
teardown — freeing on lease-out would UAF a concurrent `%on-volatile-secure` decode.

As **defense-in-depth** the entry points that read the freed master secrets — `%km-session-key-at`,
`%km-receiver-session-key-at`, `km-receiver-descriptor-list` — check the `zeroized` marker first and
signal `key-material-zeroized-error` on a torn-down KM (a single flag check off the zero-alloc hit
path), so a zeroized KM cannot use-after-free its freed master buffers; `km-receiver-descriptor-list`
signals rather than returning NIL, since a NIL descriptor would be a fail-OPEN origin-auth bypass.

This is a **storage-representation** change only — every byte-exact corpus, the NIST AES-GCM KAT, and
the KDF round-trips are unchanged, and `make mem` stays `0.0000` (the static allocation is at keying,
the derived-cache miss is a GC-heap alloc off the steady-state hot path, and the session-key HIT path
is a plain slot load).  Proven by `run-security-keymaterial-harden-test` (green on SBCL + Clasp),
which sweeps many distinct `session_id`s to prove no per-`session_id` foreign leak.  Off-heap
discrimination is SBCL-precise (`sb-ext:heap-allocated-p`); Clasp/Boehm is non-moving, so on Clasp
`dds.pal:static-vector-p` is by-design permissive and the zeroize **wipe** is the master-slot
hardening evidence (see the per-impl `static-vector-p` docstrings; NFR-PORT).

### 2.3 Encode / decode

| Symbol | Contract |
|---|---|
| `encode-serialized-payload (km plaintext)` | AES256-GCM-seal PLAINTEXT under KM; return a `SecuredPayload` octet vector |
| `decode-serialized-payload (km secured-octets)` | Parse + AES256-GCM-open; return plaintext or `NIL` (fail-closed on any error) |

`decode-serialized-payload` is **fail-closed**: it returns NIL — never plaintext, never
partial, never an unhandled condition — on any parse error, malformed blob, or GCM
authentication failure (wrong key, tampered ciphertext/tag/AAD).  This holds at
`(safety 0)`.

---

## 3. The `disc-node` `crypto-transform` slot

The `disc-node` struct has a `crypto-transform` slot:

```
(crypto-transform nil :type t)
; DDS-Security §9.5.3.3 Slice-1: key-material; NIL = security OFF, byte-identical (ADR 0031)
```

- **NIL (default):** security is OFF.  The send and receive paths are **byte-identical**
  to before — the `when` check is the only overhead.
- **A `key-material` instance:** security is ON for this node.  Outgoing samples are
  AES256-GCM-sealed before `writer-write`; incoming `SecuredPayload` blobs are decrypted
  on arrival (fail-closed drop on NIL).

### 3.1 Setting `crypto-transform` at node construction

```lisp
;; Create a shared key-material (one instance; shared by all nodes that should talk to each other)
(let* ((shared-km (dds.security:make-test-key-material))

       ;; Publisher: encodes every sample before wire emission
       (pub-node (dds.disc:make-disc-node
                  :guid-prefix pub-prefix :domain 83
                  :host "127.0.0.1" :port 0 :multicast nil
                  :crypto-transform shared-km))

       ;; Subscriber: decodes on receive -> plaintext delivered
       (sub-node (dds.disc:make-disc-node
                  :guid-prefix sub-prefix :domain 83
                  :host "127.0.0.1" :port 0 :multicast nil
                  :crypto-transform shared-km))

       ;; Plain node: no crypto-transform -> receives the raw SecuredPayload ciphertext
       (plain-node (dds.disc:make-disc-node
                    :guid-prefix plain-prefix :domain 83
                    :host "127.0.0.1" :port 0 :multicast nil)))
  ...)
```

All three nodes discover each other normally via SPDP/SEDP — security does not change
the discovery wire format in Slice 1 (`metadata_protection_kind=NONE`).  The DATA
submessage's serialized payload region carries the `SecuredPayload` blob instead of the
plaintext CDR payload.  A node without `crypto-transform` receives the raw ciphertext
bytes (beginning with `#(0 0 0 4)` = AES256-GCM `transformation_kind`).

### 3.2 What the wire looks like

For a plaintext payload `#(S Q U A R E SP 0x01)`:

- `pub-node` calls `encode-serialized-payload` → a 60-byte `SecuredPayload` blob
  (`SecureDataHeader(20) || uint32_LE_length(4) || AES256-GCM-ciphertext(8) || common_mac(16) ||
  rsm_count(4)`).
- The DATA submessage's serialized-payload region carries those 60 bytes.
- `sub-node` receives the blob, calls `decode-serialized-payload` → gets back the 8-byte
  plaintext.
- `plain-node` receives the blob, has no `crypto-transform` → delivers the 60-byte
  ciphertext blob directly to the application.

### 3.3 Zero-alloc secured receive — the decode loan (WP-DDS-SECURITY-ZEROALLOC-AEAD T5b/T5d; ADR 0038)

By default a secured receive decodes into a **freshly allocated** plaintext vector
(`decode-serialized-payload`) — one GC-heap allocation per sample.  A reader can opt into a
**zero-alloc** decode by becoming **loan-capable**:

```lisp
(dds.disc:enable-subscriber sub-node)
(dds.disc:set-secured-loan-capable sub-node t)   ; decode into a pooled buffer; deliver a loan
(dds.disc:start-node sub-node)
```

When loan-capable, the receiver thread decodes each `SecuredPayload` with
`decode-serialized-payload-into` straight into a buffer drawn from a per-node **decode pool**
(a fixed pool carved once from a static arena, sized `*secured-pool-capacity* +
*secured-pool-headroom*` buffers of `*secured-payload-max-bytes*` octets) and stores a
`secured-loan-handle` — **not** a plaintext vector — in the samples store.  The steady-state
decode path therefore allocates **zero** bytes per sample for the plaintext.  The loan
**delivery wrapper** is pooled too: the `secured-loan-handle` itself is drawn from a per-node
**handle freelist** (recycled on return, never re-allocated), the outstanding-loan **registry**
is a fixed vector with O(1) swap-remove (no per-loan cons), and `node-take-loaned` fills a
**reused** result vector (no per-take list cons).  Enabling `data_protection` on the receive
side therefore adds **0.0000 B/sample** over the non-secured baseline — matching the encode side.

The pooled buffer's lifetime is tied to a **loan registry**, not the store.  This changes the
secured-reader read contract — the app **must** read through the loan API and **return** every
loan.  Every loan **release** purges the sample's metadata from **all** parallel per-`(guid,sn)`
tables at a single choke (`%purge-secured-sample` — `samples` / `sample-writers` /
`sample-writer-guids` / `sample-origins` / `sample-key-hashes`), so a never-drained secured stream
cannot grow those tables unbounded (WP-SECURED-STORE-GROWTH).  `node-take-loaned` returns
`(values VEC COUNT)`; read `VEC[0, COUNT)` in place and hand `VEC` + `COUNT` back to
`node-return-loan`:

```lisp
(multiple-value-bind (data count) (dds.disc:node-take-loaned sub-node)   ; (values reused-VEC COUNT)
  (dotimes (i count)
    (let ((v (aref data i)))
      (when (dds.disc:secured-loan-handle-p v)                ; a bare vector (arena-carve-fail) has no loan — test first
        (let ((len   (dds.disc:secured-loan-handle-len v))
              (bytes (dds.disc:secured-loan-bytes v)))         ; read the plaintext IN PLACE over [0, len) — no copy
          (use-plaintext bytes len)))))
  (dds.disc:node-return-loan sub-node data count))              ; obligation: return every loan taken
```

`VEC` is the node's **reused** scratch buffer (single-consumer: the node's one user reader) and
the next `node-take-loaned` clobbers it, so it must be consumed and returned before the next
take.  `node-return-loan` returns each buffer to the pool, **recycles** the handle to the
freelist (fully dissociated: `buffer → nil`, guid/sn cleared, so a stale reference cannot alias
a new sample), and purges the sample's `(guid,sn)` entry from every parallel store table
(identity-guarded — only when this handle still occupies the slot, so a deduped duplicate never
evicts the original) so the buffer is never re-read after release (no use-after-free, no
wrong-bytes) and no table leaks the released metadata.  It is idempotent / double-return-safe (a returned
handle is skipped) — but a handle **must not be retained or reused after it is returned** (a
returned handle may be recycled for a new sample; use-after-return is a caller-contract
violation, memory-safe within the arena but undefined).  `stop-node` calls
`node-return-all-loans` before tearing the arena down, so a forgotten loan never leaks foreign
memory at shutdown.

Fail-closed semantics are preserved: a decode failure drops the sample and releases its buffer
(no leak); **pool exhaustion** (every buffer loaned out) drops the surplus sample, bumps
`disc-node-decode-pool-rejects` (a `SAMPLE_REJECTED` counter), and leaves the sample
un-acknowledged so the writer applies backpressure — **never** a silent GC-heap fallback.  A
leaked loan therefore degrades gracefully (the pool eventually rejects) rather than wedging.

The **arena-carve-fail** fallback is bounded too (WP-SECURED-STORE-GROWTH).  If the decode pool
cannot be carved (the static arena is exhausted at the first secured receive), the reader stays
loan-capable but stores **bare** plaintext vectors — which carry no loan, so `node-return-loan`
can never purge them.  To stop a never-drained carve-fail stream from growing the heap unbounded,
the undrained carve-fail store is **capped** at the same working-set budget the pool would have
used (`*secured-pool-capacity* + *secured-pool-headroom*`): at the cap it **fails closed** — drops
the sample, bumps `disc-node-decode-pool-rejects`, leaves it un-acked (writer backpressure),
exactly as pool exhaustion does — never a GC-silent unbounded store.  (The carve itself catches a
`storage-condition` off-heap OOM too, so it always degrades to this bounded fallback rather than
propagating.)

A reader that does **not** call `set-secured-loan-capable` (the default), and any non-secured
reader, keeps the allocating-decode → bare-vector path **byte-identical** to before.

### 3.4 Zero-alloc secured send + the shared foundation (WP-DDS-SECURITY-ZEROALLOC-AEAD, ADR 0038)

With the decode loan (§3.3) on the receive side and a matching **encode payload pool** on the send
side, the whole **`data_protection` (serialized-payload) AEAD tier is zero GC-heap-alloc per sample on
the LIVE secured path** — encode *and* decode.  `make mem` gained security-ON arms
(`aead-encode` / `aead-decode` / `aead-encode-live` / `aead-live-pub` / `aead-live-rx`, all **0.0000** on
SBCL) so the gate now **covers the security path** (it previously ran a security-OFF CDR workload only).

**Send side (the encode payload pool).**  When `data_protection` is engaged, `publish-sample` seals each
sample with `encode-serialized-payload-into` into a buffer drawn from a per-writer pool (carved from the
disc-node static arena, torn down at `stop-node`); the `cache-change` owns the pooled buffer and it is
returned to the pool only when the change is evicted **and** its send-refcount has dropped to zero (so a
retransmit / async / batch thunk that captured the payload by reference has finished copying it into the
datagram first).  The pool is **lazily provisioned** on the first secured publish, because the crypto keys
are installed *after* `enable-publisher` on the live DDS-Security handshake path.  Exhaustion → the writer
`:timeout` / `RETCODE_TIMEOUT` backpressure (RESOURCE_LIMITS), **never** a GC-heap fallback.

**The shared foundation** (reused by Slice 2 for the other tiers): an **into-buffer OpenSSL AEAD FFI**
(`dds.dare:aes-256-gcm-seal-into` / `-open-into`, writing ciphertext / tag / plaintext through the
caller's static-vector SAP — NIST-KAT byte-identical to the allocating entries) built on a new,
non-boxing PAL primitive **`dds.pal:static-sap+`**; a per-`key-material` **session-key cache** (the §4
KDF is derived **once** per `(master, salt, session_id)` and reused — no per-sample HMAC — published
barrier-safe via `dds.pal:fence`); and the **into-buffer codec core** `encode/decode-serialized-payload-into`,
over which the allocating `encode/decode-serialized-payload` entries (§2.3) are now thin wrappers.  Because
the wrappers delegate to the core, the byte-exact corpus proves the core's wire output is
**byte-identical** — no corpus was regenerated.

**Scope.**  Slice 1 (this section) delivered the **`data_protection` tier + the shared foundation**.  The
submessage (`metadata_protection`) and whole-RTPS (`rtps_protection`, the ~2.2 KB/datagram) AEAD tiers **reuse**
this foundation in **Slice 2** (§3.5) — as of **2026-07-02 all three AEAD tiers are zero-alloc** on the common
path, and **origin authentication** (receiver-specific MACs) is now zero-alloc too (§3.6, WP-SECURITY-ORIGIN-AUTH-
ZEROALLOC, ADR 0039 residual (a) closed).  See ADR 0038 for the Slice-1 per-component before→after and ADR 0039 for
Slice 2.

### 3.5 Zero-alloc secured submessage + whole-RTPS — Slice 2 (WP-DDS-SECURITY-ZEROALLOC-AEAD Slice 2, ADR 0039)

Slice 2 extends the §3.4 foundation to the other two AEAD tiers, so **all three tiers are now zero GC-heap-alloc
per sample** on the live secured path — send **and** receive:

- **submessage (`metadata_protection`, §8.5.1.7-.9)** — the `SEC_PREFIX`(0x31) / `SEC_BODY`(0x30) /
  `SEC_POSTFIX`(0x32) bracket around each user submessage;
- **whole-RTPS (`rtps_protection`, §8.5.1.10-.12)** — the `SRTPS_PREFIX`(0x33) / `SRTPS_POSTFIX`(0x34) sandwich
  around the whole post-header datagram (the ~2.2 KB/datagram dominant cost).

Both go through one shared **into-buffer codec core** `%encode/%decode-secured-region-into` (over which the
allocating entries — and the six `encode/decode-{datawriter,datareader,rtps}-{sub,}message-into` twins — are now
thin wrappers, so the byte-exact corpus proves the core's wire is byte-identical). It reuses the §3.4 into-buffer FFI
extended with an **AAD-region** arm (`aes-256-gcm-{seal,open}-into` gained `&optional aad-off aad-len`): a SIGN
(integrity-only) GMAC over a sub-range of the datagram now needs **no** verbatim-region `subseq` (SIGN
decode-into 49.14 → 0.0000 B/call).

**The five per-node scratch pools.**  The dataplane wraps/unwraps borrow from five foreign/static pools on the
`disc-node` (all lazy-carved on the first secured send/receive — zero static memory when no secured traffic occurs —
each a per-thread-distinct acquire/release via the one DRY `%with-scratch` macro, torn down at `stop-node`; capacity
`*srtps-send-scratch-capacity*`, default 8, over the ≤3 receiver threads + the concurrent sender threads):

| Pool | Role |
|---|---|
| `send-scratch` | SRTPS wrap output (`%maybe-wrap-srtps`) — replaces a per-call `alloc-static (+ len 8192)` + a `[20,len)` subseq |
| `submsg-scratch` | multi-bracket submessage wrap output (`%maybe-wrap-user-submessages`) — replaces a per-datagram `make-octet-buffer` + per-submessage subseq |
| `secure-rx` | decode OUTPUT (SRTPS unwrap / submessage re-dispatch), a **distinct buffer per concurrent decode** |
| `bracket-rx` | decode INPUT — the `SEC` bracket sub-region copy (replaces a per-`SEC_PREFIX` `make-array`) |
| `key-id-rx` | the 4-octet `transformation_key_id` scratch for the `equalp` key_id resolvers (replaces a per-datagram subseq) |

The send wrap reads the plaintext from the reused `tx-msg`, writes the (larger: ENCRYPT +56 B / SIGN +48 B) bracket
into a **separate** pooled scratch, then `replace`s it back in place — no in-place aliasing.  `secure-rx` /
`bracket-rx` are distinct pools so a decode never reads its input from the buffer it is writing its output into, and
each concurrent receiver thread borrows its **own** buffer (the Slice-2 review caught and fixed a shared-RX-buffer
race here).  The USER `metadata_protection` RECEIVE path (`%on-user-secure-submessage`) decodes the recovered
submessage into a `secure-rx` buffer, synthesizes its 20-octet RTPS Header **zero-alloc** via the raw-offset
`dds.rtps.message:write-header-into` (the cursor-based `write-header` consed ~49 B/sample — a residual the
`meta-recv` defense-in-depth `make mem` arm, which now drives the REAL `%on-secure-submessage` dispatcher, surfaced
and closed; WP-ADR-SMALL-CARRIES C2), then re-dispatches through the normal receive path.

**Exhaustion is fail-closed, never a GC fallback.**  A drained send/`submsg-scratch` pool → the required wrap returns
`NIL` (a `RESOURCE_LIMITS` drop); a drained `bracket-rx` pool → the metadata datagram is dropped and re-delivered on
release.  The drop lands only on reliable/retried paths (reliable PVMS + secure-SEDP, ACKNACK-repairable), never on
the best-effort plain-DATA path.  A subtlety worth noting: `%maybe-wrap-user-submessages` runs a **zero-alloc
pre-scan** when the scratch is unavailable, so a pass-through datagram that needs no protection (all `INFO_*`
submessages) is **not** dropped on exhaustion — the pre-scan shares its protectability predicate with the wrap loop
(DRY), so the two cannot disagree.

**No new app-facing contract.**  These two tiers are transparent dataplane wraps — the application publishes and
receives exactly as before; the pools are internal to the `disc-node`.  The inner `data_protection` payload of a
recovered submessage still uses the §3.3 secured-read loan on a loan-capable reader.

**Scope (Slice 2).**  Slice 2 made the common empty-receivers ENCRYPT/SIGN path of both tiers zero-alloc.  **Origin
authentication** (receiver-specific MACs, `..._WITH_ORIGIN_AUTHENTICATION`, §9.5.3.3.4.3) was left as the deferred
allocating fallback (ADR 0039 residual (a)) — now **closed** in §3.6.  Of the non-tier ZA-1 residuals, **ZC ×
`rtps_protection` SHMEM cleartext is now closed in §3.7**; the rest (key-material foreign-hardening, saved-image
FFI-pointer re-resolve, PAL atomics stubs) are unchanged/open.  See ADR 0039 for the Slice-2 per-component
before→after (SRTPS send 196.56 → 0.00; metadata send 196-213 → 0; metadata RX decode 98 → 0) and the residual carries.

### 3.6 Zero-alloc origin authentication — receiver-specific MACs (WP-SECURITY-ORIGIN-AUTH-ZEROALLOC, ADR 0039 residual (a))

The `..._WITH_ORIGIN_AUTHENTICATION` tier (§9.5.3.3.4.3) — a per-matched-receiver GMAC over the `common_mac` under
each receiver's own key, emitted into the CryptoFooter `receiver_specific_macs` and verified by the target receiver —
is now **zero GC-heap alloc/sample on the live secured path, send AND receive**, completing the zero-alloc AEAD story
(all three tiers + origin-auth).  The wire is **byte-identical** to the allocating path (the T3 `128`/`120`
origin-auth corpus stays green **unchanged**), and the receiver-MAC gate is unchanged (a bad/absent MAC still
fails-closed to a drop).

- **Receiver-session-key cache** (`%km-receiver-session-key-at`, `key-material.lisp`) — the §9.5.3.3.4.3 receiver key
  `HMAC-SHA256(master_receiver_specific_key, 'SessionReceiverKey' ‖ master_salt ‖ session_id)` is derived **once per
  `(receiver_specific_key_id, session_id)`** and reused, the exact parallel of the common `%km-session-key-at` cache:
  single-slot, lock-free hit, fence-published (release on write / acquire on read) so a weak-memory reader sees the
  published key; a torn read re-derives or fail-closes — never a wrong-key bypass.
- **Encode** (`%put-receiver-macs-into`) — each 20-octet `{key_id ‖ GMAC}` footer entry is written **by raw offset**:
  the `key_id` copied in place, the GMAC written straight into the footer via `aes-256-gcm-seal-into` with `pt-len 0`
  (the T1 GMAC-into) over the **in-place** `common_mac` (AAD) under the **in-place** `session_id ‖ iv_suffix` nonce.
  No `%km-nonce`, no `subseq`, no `mapcar`/list conses, no allocating `aes-256-gcm-seal`.
- **Decode** (`%verify-receiver-mac-into`) — the CryptoFooter is located **by offset** from the `postfix-off` the
  `-into` decode returns; this receiver's entry is found by a by-offset `key_id` compare and its GMAC is verified
  **in place** via `aes-256-gcm-open-into` with `ct-len 0` (EVP's constant-time tag compare against the wire mac), so
  nothing is materialized.  The public `-into` decode entries take optional `:my-receiver-key-id` / `:my-receiver-key`;
  `disc.lisp`'s SRTPS RX now routes origin-auth through the pooled zero-alloc path (no allocating
  `decode-rtps-message` fallback except on arena-exhausted pool-carve failure).
- **Receiver-descriptor resolver — the LIVE-path residual, closed** (`km-receiver-descriptor{-list}`,
  `key-material.lisp`). The transform above is zero-alloc, but the `dds.dcps` origin-auth resolvers that FEED it —
  `cm-rtps-encode-receivers` / `cm-rtps-decode-receiver` (per datagram) and the secure-SEDP pair — still consed the
  `(list (cons receiver_specific_key_id . master_receiver_specific_key))` descriptor **per call** (SEND `(list (cons
  …))` = 32.10 B/datagram, RECV `(cons …)` = 16.05 B/datagram on SBCL). That list is now **memoized on the
  `key-material`** — one `cached-receiver-descriptor-list` slot, built once from the IMMUTABLE receiver fields,
  cache-probed first so the hit path is a pure slot load + ACQUIRE fence (release-fence-published on the one-time cold
  build), returned by all four resolvers. Invalidation is structural: re-keying mints a NEW `key-material` (fresh
  cache) and participant loss drops the KM — a stale descriptor is impossible, the same `%km-session-key-at`
  invalidation model. Pure control-plane caching (same descriptor content per datagram; wire unchanged). **SEND 32.10
  → 0.00, RECV 16.05 → 0.00 B/datagram.**
- **Proof (live-path)** — the `make mem` `oauth-send` / `oauth-recv` arms now **drive the real memoized resolver**
  (`dds.security:km-receiver-descriptor{-list}`, the exact call the installed `cm-rtps-*-receiver{s}` make) INSIDE the
  measured window — not a pre-built stub list — so they measure the **live origin-auth datagram path (resolver +
  transform)** and still report **`delta 0.0000 B/sample`** over the common empty-receivers baseline on SBCL (Clasp
  smokes, `bytes-consed` 0). The first cold-cache fill amortizes off the window; the reported 0.0000 is warmed
  steady-state (the `%km-session-key-at` convention). `run-security-origin-auth-test` block (4) round-trips the
  `-into` verify entries (right key recovers byte-exact; wrong/absent key → NIL; no key → common_mac alone) and
  `run-security-crypto-manager-test` drives the T10 `cm-rtps-*` resolvers through the memoized path, so the mem arms
  are **non-vacuous**.

### 3.7 No cleartext payload in SHMEM for a secured writer — the Zero-Copy governance gate (ADR 0036 Carry 10)

Zero-Copy over shared memory (`*zerocopy-enabled*`, FR-PF-3) publishes a large sample by copying its serialized
payload **once** into a per-writer SHMEM sample-pool and transmitting only a **16-byte reference** in the DATA
submessage.  The datagram-tier security transforms — `rtps_protection` (§8.5.1.10-.12, whole-RTPS) and
`metadata_protection` (§8.5.1.7-.9, user-submessage) — are applied in `%send-raw-buf` to the **datagram** at send
time, *after* the payload is already in the pool.  With Zero-Copy that datagram carries only the reference, so those
transforms would wrap the **reference**, leaving the actual user payload sitting in shared memory **in the clear** —
a co-resident participant mapping the segment could recover plaintext that governance requires be confidential on the
wire.  (`data_protection`, §9.4.1.2.4, is different: it is applied at serialize time in `publish-sample`, so the pool
receives the already-transformed SecuredPayload — ciphertext for ENCRYPT — and is never *less* protected than the
wire at the payload tier.)

The fix is **fail-closed** and gates purely on the writer's governance.  `%zc-payload-wire-protected-p`
(`src/dds-disc/dataplane.lisp`) is T when the writer's `rtps_protection_kind` **or** `metadata_protection_kind`
(`disc-node-rtps-protection-kind` / `disc-node-user-submessage-protection-kind`) is ≠ `:none`.  When it is T,
`%zc-change-item` returns NIL — **the raw Zero-Copy path is disabled** and the sample is emitted as a normal DATA
whose datagram `%send-raw-buf` protects (submessage + SRTPS wrap) over UDP **or the SHMEM ring** (the ring send wraps
the whole datagram in place *before* transmission, so it never leaks — only the out-of-band Zero-Copy pool did).  The
reader receives and decrypts the sample exactly as on the non-Zero-Copy path.  You cannot both zero-copy *and*
encrypt the same in-place buffer, so a secured writer trades the raw-pool optimization for confidentiality — the
bounded, clearly-secure choice.

A **non-secured** writer (both kinds `:none`, the default — no governance, or every kind NONE) is completely
untouched: the predicate is NIL, so Zero-Copy/SHMEM keeps full performance, byte-identical and zero-alloc.  This is a
transport-routing gate, **not a codec change** — the wire is byte-identical and every byte-exact security corpus +
NIST KAT is unchanged.  `run-zc-shmem-secured-cleartext-test` proves it: Part A (deterministic, both impls) checks the
predicate and that `%zc-change-item` returns NIL under `rtps_protection` and under `metadata_protection`; Part B
(where SHMEM is available) inspects the **live pool segment** and asserts the secured payload is provably **absent**
while a non-secured control's marker **is** present (non-vacuous).

---

## 4. The session-key KDF (DDS-Security 1.1 §9.5.3.3.4.2)

```
session_key = HMAC-SHA256(master_sender_key,
                          "SessionKey" || master_salt || session_id)
```

There is **no trailing counter**: Fast DDS `compute_sessionkey` and Cyclone `crypto_calculate_session_key`
both hash exactly `id_string ‖ master_salt ‖ session_id` (corroborated clean-room; T-RECONCILE, 2026-06-27 —
an earlier `"0001"` counter was removed reconciling to the wire oracle, see `docs/provenance.md`).
This is **HMAC-SHA256** (§9.5.3.3.4.2) — *not* the HKDF-SHA384 used by
`dds-dare` for the DARE key derivation.  The primitive is `dds.dare:hmac-sha256` (a
one-shot OpenSSL `EVP_Q_mac` over the existing handle-based libcrypto resolution; the
foreign key buffer is zeroized before free).

```lisp
(dds.security:derive-session-key master-sender-key master-salt session-id)   ; => 32-octet key
```

---

## 5. Conformance and the honest interop picture

`run-security-secured-payload-corpus-test` checks:

- (a) A **byte-exact** 48-octet `SecuredPayload` corpus;
- (b) Parse round-trips all six fields;
- (c) Fail-closed on truncated (lengths 0, 1, 19, 20, 24, 43) and over-declared inputs;
- (d) `hmac-sha256` against the **RFC 4231 §4.3 HMAC-SHA-256 Test Case 2** published
  vector (genuine independent conformance, never a self-generated vector);
- (e) The `derive-session-key` composition against an independently-assembled HMAC input.

`run-security-payload-fuzz-test` exercises 2081 adversarial inputs through
`decode-serialized-payload` — confirming no OOB read, crash, or partial parse under
`(safety 0)`.

`run-security-encrypted-pubsub-test` proves the disc-node integration end-to-end
(plaintext delivered to the subscribing node, SecuredPayload ciphertext on the wire to
the plain node).

**Cross-vendor interop is an honest three-level picture** — see
`interop/security-crypto/README.md` and ADR 0031 §cross-vendor-deferral.  The
summary: structural + KAT conformance is proven; a live Connext-Security byte-compare
is **deferred** (Slice 5, the P6 exit gate).

### 5.1 Known limitation — `data_protection=SIGN` (payload tier) is not implemented

The serialized-payload `data_protection` gate (`%publish-…` / `%deliver-user-sample`) is
**`NONE`-vs-non-`NONE`**: a non-NONE kind routes into the ENCRYPT-only crypto-transform.
**Supported `data_protection` tiers: `NONE` + `ENCRYPT`.**  A `data=SIGN` topic — a
serialized-payload GMAC sub-tier that would authenticate the *visible* payload without
encrypting it — is **not yet implemented** (`transform.lisp` implements ENCRYPT-only for the
payload tier); routing it through the ENCRYPT transform would over-encrypt the payload, so a
`data=SIGN` peer would read garbage / false-REJECT.  This is why the `governance-sign` SIGN
tier uses `data=NONE` (the visible payload is already authenticated at the submessage tier by
`metadata_protection`=SIGN, §8.5.1.9).  `data_protection`=SIGN at the payload tier is **future
work** (ADR 0040 §Slice-5c review follow-ons; ADR 0037 carry #3).

---

## 6. Authentication plugin — Slice 2a (DDS-Security 1.1 §8.7, §9.3)

Slice 2a (landed 2026-06-24, WP-DDS-SECURITY-AUTH-2A, ADR 0032) delivers the
DDS-Security 1.1 **`DDS:Auth:PKI-DH`** builtin Authentication plugin — the foundation that
ultimately replaces the Slice-1 pre-shared test key with keys derived from a proper
mutual-authentication handshake.

**Scope of Slice 2a:** PKI identity load + the complete §8.7.2.4 three-message PKI-DH
handshake (Request → Reply → Final) → a `SharedSecret`, our-to-our, both §9.3 suites.  No
live discovery, no key derivation into `key-material` — those are Slices 2b and 2c.

### 6.1 The §8.7.2.4 three-message handshake

Two participants mutually authenticate via X.509 certificates and a Diffie-Hellman ephemeral
key exchange:

1. **Request** (requester → replier):  requester's cert (`c.id`), its ephemeral DH public key
   (`dh1`, SubjectPublicKeyInfo DER), a 32-byte nonce (`challenge1`), and a SHA-256 hash of
   the requester's `c.*` properties (`hash_c1`).
2. **Reply** (replier → requester):  replier's cert and ephemeral key (`dh2`), `challenge2`,
   `hash_c2`, echoes of `hash_c1` / `dh1` / `challenge1`, and a **digital signature**
   (`Sign2`) over a CDR big-endian `BinaryPropertySeq` of
   `hash_c2 ∥ challenge2 ∥ dh2 ∥ challenge1 ∥ dh1 ∥ hash_c1` (§9.3.2.2).
   The requester verifies the replier's cert chain + `Sign2`.
3. **Final** (requester → replier):  echoes of all fields + a **digital signature** (`Sign1`)
   over `hash_c1 ∥ challenge1 ∥ dh1 ∥ challenge2 ∥ dh2 ∥ hash_c2` (§9.3.2.3).
   The replier verifies `Sign1`.
4. Both sides independently compute **`SharedSecret = SHA-256(ECDH-or-FFDH-agreed-value)`**
   (§9.3.3).

Both participants reach `:authenticated` with byte-equal `SharedSecret`.

### 6.2 The two §9.3 suites

| Suite | `kagree_algo` | `dsign_algo` | Cert kind |
|---|---|---|---|
| `+suite-ecdh+` | `"ECDH+prime256v1-CEUM"` | `"ECDSA-SHA256"` | EC P-256 |
| `+suite-ffdh+` | `"DH+MODP-2048-256"` | `"RSASSA-PSS-SHA256"` | RSA-2048 |

Suite selection is via `select-auth-suite (local-cert-kind remote-cert-kind)` (§9.3.2):
both EC → `+suite-ecdh+`; both RSA → `+suite-ffdh+`; mismatched → NIL → reject.
`select-auth-suite` is implemented and tested; wiring it into the discovery entry points is a
Slice 2b item.

### 6.3 The API (`dds.security`, Slice 2a)

```lisp
;;; PKI identity

(validate-local-identity ca-pem cert-pem key-pem guid)
  ;; -> (values identity-handle nil) | (values nil reason-string)
  ;; Load + chain-verify the local participant identity from PEM octet vectors.
  ;; GUID: 16-octet array used for the §8.7.2.4 role ordering.

(validate-remote-identity local remote-identity-token)
  ;; -> (values :ok :requester nil) | (values :ok :replier nil) | (values :rejected role reason)
  ;; Parse the remote IdentityToken; decide local role (§8.7.2.4 GUID lexicographic ordering).

(identity-token handle)      ; -> IdentityToken CDR LE octet vector (§8.7.2.2 / §9.3.1)
(free-identity-handle handle)

;;; Suites and selection

+suite-ecdh+        ; ECDH+prime256v1-CEUM / ECDSA-SHA256 / SHA-256 (DDS-Security 1.1 §9.3)
+suite-ffdh+        ; DH+MODP-2048-256 / RSASSA-PSS-SHA256 / SHA-256 (§9.3 / RFC 3526 §3)
(select-auth-suite local-cert-kind remote-cert-kind)
  ;; -> auth-suite | nil
  ;; :ec  + :ec  -> +suite-ecdh+
  ;; :rsa + :rsa -> +suite-ffdh+
  ;; mixed       -> NIL (§9.3.2; handshake must reject)

;;; Handshake state machine

(begin-handshake-request local remote suite)
  ;; -> (values request-token-octets handshake-handle)
  ;; Initiate the handshake as the requester (local GUID < remote GUID per §8.7.2.4).

(begin-handshake-reply local remote request-token-octets suite)
  ;; -> (values reply-token-octets handshake-handle) | (values nil nil)
  ;; Process the Request token as the replier; verify peer cert chain + hash_c1.

(process-handshake handle incoming-token-octets)
  ;; -> (values next-token-or-nil status)
  ;; status: :continue | :authenticated | :rejected
  ;; Requester (:awaiting-reply): processes Reply -> produces Final; state -> :authenticated.
  ;; Replier (:awaiting-final): processes Final; state -> :authenticated. No further token.

;;; SharedSecret access

(handshake-shared-secret handle)            ; -> shared-secret-handle | nil
(shared-secret-bytes shared-secret-handle)  ; -> (simple-array (unsigned-byte 8) (32))
(free-shared-secret-handle handle)          ; -> t  (zeroizes + frees the foreign buffer)
(free-handshake-handle handle)              ; -> t
```

### 6.4 A worked our-to-our example (EC suite)

```lisp
(let* ((ca-pem   (uiop:read-file-string "interop/security-auth/pki/ca/ca-cert.pem"))
       (cert-a   (uiop:read-file-string "interop/security-auth/pki/participant_ec/identity_cert.pem"))
       (key-a    (uiop:read-file-string "interop/security-auth/pki/participant_ec/identity_key.pem"))
       (cert-b   (uiop:read-file-string "interop/security-auth/pki/participant_ec_b/identity_cert.pem"))
       (key-b    (uiop:read-file-string "interop/security-auth/pki/participant_ec_b/identity_key.pem"))
       (to-pem   (lambda (s)
                   (map '(simple-array (unsigned-byte 8) (*)) #'char-code s)))
       (guid-a   (make-array 16 :element-type '(unsigned-byte 8)
                                :initial-contents '(1 2 3 4 5 6 7 8 9 10 11 12 13 14 15 16)))
       (guid-b   (make-array 16 :element-type '(unsigned-byte 8)
                                :initial-contents '(200 2 3 4 5 6 7 8 9 10 11 12 13 14 15 16))))

  ;; 1. Load and validate local identities
  (multiple-value-bind (id-a err-a)
      (dds.security:validate-local-identity (funcall to-pem ca-pem)
                                             (funcall to-pem cert-a)
                                             (funcall to-pem key-a) guid-a)
    (assert (not (null id-a)) () (format nil "id-a failed: ~a" err-a))
    (multiple-value-bind (id-b err-b)
        (dds.security:validate-local-identity (funcall to-pem ca-pem)
                                               (funcall to-pem cert-b)
                                               (funcall to-pem key-b) guid-b)
      (assert (not (null id-b)) () (format nil "id-b failed: ~a" err-b))

      ;; 2. Validate remote identity — determine roles (GUID ordering)
      ;; guid-a (1,2,...) < guid-b (200,2,...), so A is :requester, B is :replier.

      ;; 3. Requester sends HandshakeRequestMessageToken
      (multiple-value-bind (req-tok req-hdl)
          (dds.security:begin-handshake-request id-a id-b dds.security:+suite-ecdh+)

        ;; 4. Replier processes Request, sends HandshakeReplyMessageToken
        (multiple-value-bind (rep-tok rep-hdl)
            (dds.security:begin-handshake-reply id-b id-a req-tok dds.security:+suite-ecdh+)
          (assert (not (null rep-tok)) () "reply nil")

          ;; 5. Requester processes Reply, sends HandshakeFinalMessageToken
          (multiple-value-bind (final-tok req-status)
              (dds.security:process-handshake req-hdl rep-tok)
            (assert (eq req-status :continue) () (format nil "req status ~a" req-status))

            ;; 6. Replier processes Final, both sides now :authenticated
            (multiple-value-bind (nil-tok rep-status)
                (dds.security:process-handshake rep-hdl final-tok)
              (assert (eq rep-status :authenticated) () "rep not :authenticated")
              (assert (null nil-tok) () "rep returned unexpected token")
              (assert (eq (dds.security:handshake-handle-state req-hdl) :authenticated))

              ;; 7. Both SharedSecrets are byte-equal
              (let ((ss-req (dds.security:handshake-shared-secret req-hdl))
                    (ss-rep (dds.security:handshake-shared-secret rep-hdl)))
                (assert (equalp (dds.security:shared-secret-bytes ss-req)
                                (dds.security:shared-secret-bytes ss-rep))
                        () "SharedSecrets not byte-equal")
                (format t "~&SharedSecret (32 bytes): ~{~2,'0x~}~%"
                        (coerce (dds.security:shared-secret-bytes ss-req) 'list)))

              ;; 8. Clean up all foreign resources
              (dds.security:free-handshake-handle req-hdl)
              (dds.security:free-handshake-handle rep-hdl)))
          (dds.security:free-identity-handle id-a)
          (dds.security:free-identity-handle id-b))))))
```

Replace `+suite-ecdh+` with `+suite-ffdh+` and the RSA participant fixtures for the FFDH
suite.  The API is identical; only the suite parameter changes.

### 6.5 Published KATs

| KAT | Source | Test |
|---|---|---|
| SHA-256(`""`) | NIST FIPS 180-4 | `run-auth-sha256-kat` |
| ECDH P-256 shared secret | RFC 5903 §8.1 (Group 19 / P-256) | `run-auth-ecdsa-kat` |
| ECDSA-P256/SHA-256 deterministic (`"sample"`) | RFC 6979 §A.2.5 | `run-auth-ecdsa-kat` |
| RSA-PSS-SHA256-saltlen32 (empty msg, valid sig) | Wycheproof rsa_pss_2048_sha256_mgf1_32 tcId 1 | `run-auth-rsa-pss-kat` |
| RSA-PSS-SHA256 invalid-sig rejection | Wycheproof rsa_pss_2048_sha256_mgf1_32 tcId 62 | `run-auth-rsa-pss-kat` |
| FFDH MODP-2048 commutativity | self-consistency round-trip (no published oracle available) | `run-auth-ffdh-kat` |

The FFDH KAT is a self-consistency commutativity proof — no published MODP-2048 shared-secret
test vector was located (NIST CAVP KAS-FFC does not cover OpenSSL `EVP_PKEY`-level MODP-2048).
This is documented honestly; cross-vendor FFDH byte-equality is a Slice 5 verification item.

### 6.6 The honest interop posture

Three levels, as in Slice 1:

1. **Our-to-our mutual authentication + byte-equal SharedSecret** (achieved): both ECDH and
   FFDH suites complete the full three-message handshake; both sides reach `:authenticated`
   with identical SharedSecret values.  Tested by `run-auth-handshake-ecdh-test` and
   `run-auth-handshake-rsa-test`.

2. **Cryptographic primitive conformance** (achieved, by published KAT): ECDH P-256, ECDSA-SHA256,
   RSA-PSS-SHA256 (saltlen=32), and SHA-256 each produce byte-identical output to any conformant
   implementation, proven by RFC 5903, RFC 6979, Wycheproof, and NIST FIPS 180-4 vectors.

3. **Live cross-vendor PKI-DH authentication interop** (DEFERRED to Slice 5 — NOT achieved):
   the RTI Connext Security Plugins are not installed.  Several internal details are
   self-consistent (our-to-our) but unverified against a live Connext peer:
   - The internal-token-vs-CDR-DataHolder wire mapping (Slice 2b item).
   - CDR-BE BinaryPropertySeq alignment for hash_c1/hash_c2/signature inputs.
   - FFDH dh1/dh2 SPKI-DER encoding vs Connext.
   - RSA-PSS saltlen=32 vs Connext's convention.

   **Do NOT interpret this section as "cross-vendor authentication interop verified."**

---

## 6bis. Authentication plugin — Slice 2b-i: wire transport (DDS-Security 1.1 §7.4.4, §9.3.4)

Slice 2b-i (landed 2026-06-25, WP-DDS-SECURITY-AUTH-2BI, ADR 0033) puts the Slice 2a
in-process handshake tokens on the real wire, completing the PSM transport layer.

### 6bis.1 SPDP IdentityToken (§8.7.2.2 / §9.3.1 / RTPS 2.5 §9.4.1.3)

`spdp-data` gains an `identity-token-octets` slot (type `(or (simple-array (unsigned-byte 8) (*)) null)`,
default NIL).  When set:

- `serialize-spdp-data` emits `PID_IDENTITY_TOKEN` (PID 0x1001, DDS-Security 1.1
  §9.4.1.3) carrying the CDR-LE `DataHolder` bytes of the participant's `IdentityToken`.
- The `builtin-endpoint-set` is ORed with bits 22 (`+be-participant-stateless-writer+`)
  and 23 (`+be-participant-stateless-reader+`) per DDS-Security 1.1 §7.4.6.1 Table 29.
- `parse-spdp-data` reads and stores the `identity-token-octets` when PID 0x1001 is
  present; silently skips it when absent (conformant receivers must skip unknown optional
  PIDs per RTPS 2.5 §9.6.2.2.2).

**Default-OFF:** when `identity-token-octets` is NIL the serialized SPDP is byte-identical
to the pre-security wire — no extra PID, no extra bits.

**Don't-break-plain:** plain Connext or Fast DDS receivers skip PID 0x1001 silently
(optional bit set per §9.4.1.3) and ignore PSM bits 22/23 (RTPS 2.5 §8.5.3.1).
See `interop/security-auth-discovery/README.md` for the full environment-limited outcome.

### 6bis.2 The §9.3.4 DataHolder + §7.4.4 ParticipantGenericMessage codec (`dds.security`)

Handshake tokens travel as CDR-LE `DataHolder` blobs inside a
`ParticipantGenericMessage` (`ParticipantStatelessMessage`) envelope.

| Symbol | Contract |
|---|---|
| `handshake-token->dataholder (token)` | Serialize a `handshake-token` struct (Slice 2a) to CDR-LE `DataHolder` octets (§9.3.4): class_id string + `PropertySeq(count=0)` + `BinaryPropertySeq` |
| `dataholder->handshake-token (octets)` | Parse CDR-LE `DataHolder` octets back to a `handshake-token`; bounds-checked, fail-closed (NIL on any malformed/truncated/over-declared input) |
| `make-generic-message (&key ...)` | Serialize a `ParticipantGenericMessage` envelope as CDR-LE: 2×`MessageIdentity`(24) + 3×`GUID_t`(16) + `message_class_id`(CDR-LE string) + `DataHolderSeq`(u32-LE count + `DataHolder*`) |
| `parse-generic-message (octets)` | Parse a CDR-LE envelope; returns 9 values (source-guid sn related-guid related-sn dest-participant-guid dest-endpoint-guid source-endpoint-guid message-class-id dataholder-list) or all NIL on malformed |
| `+auth-message-class-id+` | `"dds.sec.auth"` (the `message_class_id` for all handshake tokens; DDS-Security 1.1 §7.4.4 / §9.3) |

**Endianness split:** the PSM wire (`DataHolder` + `ParticipantGenericMessage`) is
CDR-LE.  The Slice 2a hash/signature inputs (`BinaryPropertySeq` for `hash_c1`,
`hash_c2`, `Sign1`, `Sign2`) remain CDR-BE per §9.3.2 — the BE bytes are carried
verbatim as raw octets inside the LE DataHolder value field.  The two serializations
are distinct and never mixed.

### 6bis.3 PSM endpoints (`dds.disc` / `dds.rtps.discovery`)

| Symbol | Value | Source |
|---|---|---|
| `+entityid-participant-stateless-writer+` | `0x000201C3` | DDS-Security 1.1 §9.5.1.3 Table 40 |
| `+entityid-participant-stateless-reader+` | `0x000201C4` | DDS-Security 1.1 §9.5.1.3 Table 40 |
| `+be-participant-stateless-writer+` | bit 22 | DDS-Security 1.1 §7.4.6.1 Table 29 |
| `+be-participant-stateless-reader+` | bit 23 | DDS-Security 1.1 §7.4.6.1 Table 29 |

`disc-node` gains:
- `%send-stateless-message (node dest-prefix envelope-octets)` — wraps the CDR-LE
  envelope in a DATA submessage and sends unicast to the PSM reader EntityId port.
- `on-stateless-message` slot — a closure called by the receiver thread with
  `(node src-prefix envelope-octets)` when a PSM DATA arrives.  **As of Slice 2b-ii
  (Decision 1) the hook receives the RAW `ParticipantGenericMessage` envelope octets**
  (only the payload buffer-extent is bounds-checked in `dds-disc`); `dds-disc` stays
  crypto/format-agnostic and the consumer (the auth manager) does `parse-generic-message`
  and dispatches by `message_class_id` — because both the handshake (`dds.sec.auth`) and the
  crypto-token (`dds.sec.participant_crypto_tokens`) messages share this one endpoint with
  different `DataHolder`s, so a pre-parse to a `handshake-token` in `dds-disc` would silently
  drop crypto-token messages.

### 6bis.4 A worked end-to-end example (our-to-our, EC suite)

As of Slice 2b-ii the hook delivers the **raw envelope octets** (Decision 1); the `%on-*`
helpers below first `parse-generic-message` the envelope, take the first `DataHolder`, and
`dataholder->handshake-token` it before driving the handshake (`%psm-envelope->token-octets`
in the test does exactly this).  Most callers should instead just configure an identity on
the participant (§6ter) and let the auth manager drive all of this.

```lisp
;; Node-A and Node-B both carry an IdentityToken in their SPDP.
(let* ((node-a (dds.disc:make-disc-node
                :guid-prefix prefix-a :host "127.0.0.1" :port 0
                :identity-token-octets (dds.security:identity-token id-a)
                :on-stateless-message
                (lambda (node src-prefix envelope)
                  (declare (ignore src-prefix))
                  ;; A's callback: receives Reply -> process-handshake -> send Final
                  (%on-a-reply node envelope state))))
       (node-b (dds.disc:make-disc-node
                :guid-prefix prefix-b :host "127.0.0.1" :port 0
                :identity-token-octets (dds.security:identity-token id-b)
                :on-stateless-message
                (lambda (node src-prefix envelope)
                  (declare (ignore src-prefix))
                  ;; B's callback: receives Request -> begin-handshake-reply -> send Reply;
                  ;;                receives Final  -> process-handshake -> :authenticated
                  (%on-b-request-or-final node envelope state)))))
  ;; 1. SPDP discovery (real UDP loopback).
  (dds.disc:start-node node-a)
  (dds.disc:start-node node-b)
  ;; 2. Initiate handshake from A (requester, GUID-A < GUID-B per §8.7.2.4).
  (multiple-value-bind (req-octets req-hdl)
      (dds.security:begin-handshake-request id-a id-b dds.security:+suite-ecdh+)
    (let ((req-tok (dds.security::%parse-token req-octets)))
      ;; 3. Serialize to DataHolder, wrap in PSM envelope, send.
      (dds.disc:%send-stateless-message
        node-a prefix-b
        (dds.security:make-generic-message
          :source-guid src-ep-a :sequence-number 1
          :related-guid zero-guid :related-sn 0
          :dest-participant-guid dest-part-b
          :dest-endpoint-guid dst-ep-b :source-endpoint-guid src-ep-a
          :message-class-id dds.security:+auth-message-class-id+
          :dataholders (list (dds.security:handshake-token->dataholder req-tok)))))
    ;; 4-6 happen via callbacks; poll for completion.
    (loop until (both-authenticated-p state) do (sleep 0.02))
    ;; 7. Both SharedSecrets are byte-equal.
    (assert (equalp (wire-hs-state-a-ss state) (wire-hs-state-b-ss state)))))
```

See `run-auth-handshake-over-wire-test` in
`src/dds-tests/security-auth-test.lisp` for the full working test.

### 6bis.5 The honest interop posture for Slice 2b-i

**Level 1 — Our-to-our handshake over the real UDP wire (ACHIEVED)**
Both nodes reach `:authenticated` with byte-equal `SharedSecret`.  Proven by
`run-auth-handshake-over-wire-test` (Clasp 329 + SBCL 329, Clasp first).

**Level 2 — Don't-break-plain (ENVIRONMENT-LIMITED)**
The in-process portable guard (`run-auth-spdp-identity-token-test` arm b) proves the
DEFAULT-OFF path is byte-identical.  RTPS 2.5 §9.6.2.2.2 requires conformant peers to
silently skip unknown optional PIDs; RTPS 2.5 §8.5.3.1 requires ignoring unknown
endpoint bits.  A live plain-peer session is environment-limited (see
`interop/security-auth-discovery/README.md`).

**Level 3 — Live Connext-Security authentication interop (DEFERRED to Slice 5)**
The RTI Security Plugins are not installed.  The DataHolder byte-match vs Connext,
CDR-BE alignment of hash inputs, FFDH SPKI-DER encoding, and RSA-PSS saltlen are
self-consistent (our-to-our) but unverified against a live Connext peer.

**Do NOT interpret this section as "cross-vendor authentication interop verified."**

---

## 6ter. Authentication MANAGER — Slice 2b-ii + 2c (discovery integration + key exchange)

Slice 2b-ii + 2c (landed 2026-06-26, WP-DDS-SECURITY-AUTH-KEYX, ADR 0034 at the capstone)
adds the orchestrator that finally *uses* the handshake automatically: a security-enabled
participant authenticates every discovered security-enabled peer over the PSM wire, exchanges
per-writer key material, and **gates endpoint matching strictly on authentication**.

### 6ter.1 Where it lives

The **auth manager** is `src/dds-dcps/auth-manager.lisp`, mirroring the FR-TYPE-4 type-gate
(`type-gate.lisp`).  It sits in the DCPS layer because it needs BOTH `dds-security` (handshake +
key exchange) AND `dds-disc` (hooks, send, matching); `dds-disc` stays crypto-free.  Per-participant
state hangs off the `domain-participant` (`dp-auth-state`, analogous to `dp-type-gate-state`);
per-remote state (`auth-remote`, keyed by 12-octet GUID prefix) lives in the disc-node's
manager-owned `disc-node-auth-state` table.

### 6ter.2 Turning it on

```lisp
(let ((id (dds.security:validate-local-identity ca-pem cert-pem key-pem guid)))
  ;; a security-enabled participant: advertises its IdentityToken in SPDP + installs the manager
  (dds.dcps:create-participant :domain 0 :identity id))
```

`create-participant :identity <identity-handle>` sets the node's `identity-token-octets` (so SPDP
advertises `PID_IDENTITY_TOKEN` + the PSM bits) and calls `%install-auth-manager`, which installs
three disc-node hooks: `on-participant-discovered` (the requester trigger / replier pre-stash),
`on-stateless-message` (the raw-envelope handshake + key-material dispatcher), and `auth-gate`
(the strict §7.3 endpoint-match verdict).  With **no** `:identity`, `dp-auth-state` stays NIL and
the participant is the byte-identical plain path.

### 6ter.3 The `auth-remote` state machine (§8.7 / §9.5)

| State | Meaning |
|---|---|
| `:none` | discovered + validated; role/suite recorded; no handshake yet |
| `:handshaking` | an in-flight §8.7.2.4 handshake (handle non-NIL) |
| `:authenticated` | handshake complete (SharedSecret); KxKey derived + our CryptoTokens sent; remote KeyMaterial NOT yet installed |
| `:keyed` | authenticated AND the remote writer KeyMaterial installed → endpoint matching resumed |
| `:rejected` | terminal refusal (malformed/untrusted remote, unsupported/mismatched algo, bad handshake) |

The **role** (`:requester` / `:replier`) is decided from the **real RTPS participant GUID prefixes**
(§8.7.2.4 lexicographic order) — deterministic and complementary on both peers — not from
`validate-remote-identity`'s T1 cert-sn-hash stand-in (which is used only for the `:ok`/`:rejected`
verdict).

**§9.3.2.1 authenticated GUID + `c.pdata` (Slice 5, cross-vendor).** A security-enabled participant
announces the **DDS-Security 1.1 §9.3.2.1 authenticated GUID**: GUID-prefix octet 0 has bit-0 = 1 and
octets 0-5 carry the first 47 bits of `SHA-256(identity-cert subject name)` (octets 6-11 keep an
impl-defined uniqueness tail); the EntityId is `ENTITYID_PARTICIPANT`. `validate-local-identity` derives
it (`%adjust-guid-prefix`, byte-for-byte the Fast DDS `adjust_participant_key` layout) and
`create-participant` announces it. The same 16-octet GUID is carried in the handshake `c.pdata` as a
**big-endian RTPS ParameterList** (`PID_PARTICIPANT_GUID` + `PID_SENTINEL`, **no** encapsulation header —
`%build-c-pdata`). A conformant replier (e.g. Fast DDS) re-derives and validates these 48 bits before it
will reply, so a non-adjusted GUID or the old 4-octet stub `c.pdata` is silently rejected. Because the §8.7
handshake rides the **best-effort** ParticipantStatelessMessage and the cert-derived role can make the
requester the later-joining peer, the requester **retransmits** its request on each SPDP re-announce while
still `:awaiting-reply`, and a replier re-sends its stored reply (`auth-remote` `last-sent`) on a duplicate
request.

**Cross-vendor PSM wire reconciliations (Slice 5).** Three further conformance details a strict peer (Fast
DDS) enforces but our own receiver was blind to (so they were invisible our-to-our):
- **PSM writer sequence number >= 1.** The ParticipantStatelessMessage DATA carries a monotonic
  `psm-writer-sn` from 1, not 0 — a conformant reader rejects writerSN <= 0 ("bad sequence Number", RTPS 2.5
  §8.3.5.4/§8.4.2) at the RTPS layer, before the security layer.
- **`source_endpoint_key` / `destination_endpoint_key` = GUID_UNKNOWN.** The participant-to-participant
  handshake message leaves both endpoint keys unknown (§7.4.4); a peer DROPS a message whose
  `source_endpoint_key` is set.
- **DataHolder octet-vector 4-byte alignment.** Each wire `BinaryProperty` value is padded to the next
  4-byte boundary (the DataHolder sits at a 4-aligned stream offset). The §8.7 hash/Sign `BinaryPropertySeq`
  is the SEPARATE, UNpadded serialization — the two must never be conflated.
- **`c.id` is the PEM certificate, not DER (T3).** The §9.3.2.1 identity credential carried in the handshake
  `c.id` BinaryProperty is the **PEM** certificate (`-----BEGIN CERTIFICATE-----`), produced by
  `dds.dare:x509-to-pem` (PEM_write_bio_X509) — a conformant replier loads it with `PEM_read_bio_X509_AUX`
  and otherwise warns "Cannot load certificate" and sends no reply. Decode is tolerant
  (`dds.dare:x509-load-cert-auto`: PEM then DER) so no legacy DER peer is false-rejected. The §8.7 hash_c is
  computed over the transmitted c.id bytes on both sides, so it matches independent of the encoding.
- **Requester drops out-of-role tokens (T3).** Per §8.7.2.4 the requester's state machine processes ONLY the
  HandshakeReply: `%am-drive-handshake` drops any non-Reply token while `:awaiting-reply` (e.g. a stray /
  duplicate / peer-emitted `+Req`) instead of feeding it to `%process-reply`, which would reject on the
  class_id mismatch and latch `:rejected` — discarding the genuine Reply. Symmetric to the replier's
  duplicate-request guard.

### 6ter.4 The three design decisions

1. **One stateless endpoint, two message kinds (Decision 1).** The handshake and the crypto-token
   messages arrive on the SAME PSM endpoint with DIFFERENT `DataHolder`s.  `%on-stateless-message`
   now delivers the RAW envelope octets; the manager does `parse-generic-message`, reads
   `message_class_id`, and dispatches: `dds.sec.auth` → handshake; `dds.sec.participant_crypto_tokens`
   → install the remote KeyMaterial.  (Before, `dds-disc` pre-parsed a `handshake-token`, which
   silently dropped crypto-token messages.)
2. **Suite selection encapsulates the unsupported-algo NIL (Decision 2).**
   `select-suite-for-identities (local-identity remote-id-token-octets)` derives both cert kinds via
   the internal `%cert-algo->kind` and returns NIL — meaning *reject this remote* — when EITHER algo
   is unsupported or the suites mismatch, else the selected `auth-suite`.  This keeps the NIL handling
   where `%cert-algo->kind` lives, so the manager never passes NIL to `select-auth-suite` (whose ftype
   is `(member :ec :rsa)`).
3. **Local identity wiring (Decision 3).** The manager holds the local `identity-handle` (with the
   private key) — the disc-node holds only the IdentityToken octets.  `create-participant :identity`
   plumbs it; `%install-auth-manager (p identity-handle)` stores it in `dp-auth-state`.

### 6ter.5 The strict auth-gate (§7.3)

Consulted as the SECOND sequential gate after the type-gate returns `:compatible` (in
`%match-remote-endpoint`), outside the node lock.  Strict authenticated-only matching
(`allow_unauthenticated = FALSE`, the conformant default):

- local **not** security-enabled (`dp-auth-state` NIL) → `:compatible` (security off, unchanged);
- remote `:keyed` → `:compatible`;
- remote `:handshaking` / `:authenticated` (in flight) → `:pending` (park; resumed on `:keyed`);
- remote has NO `auth-remote` (a plain peer, no IdentityToken) OR `:rejected` / `:none` →
  `:incompatible` (strict refuse).

### 6ter.6 Key exchange (§9.5.2 / §9.5.3)

On reaching `:authenticated`, each side derives the §9.5.3 **KxKey** from the SharedSecret +
challenges (`derive-kx-key`, T2 — KxKey held in a `dds.pal` foreign buffer), generates its §9.5.2
per-writer **KeyMaterial** (`generate-writer-key-material`, T3), and sends it **KxKey-encrypted**
over PSM (`make-crypto-token-message`, T3).  The peer decrypts + installs it
(`parse-crypto-token-message`, fail-closed: a bad KxKey or any tamper → no install).  When both
authenticated AND the remote KeyMaterial is installed → `:keyed` → `resume-parked-matches`.  PSM is
best-effort with no resend this slice (the reliable `ParticipantVolatileMessageSecure` endpoint is a
Slice-5 carry); a crypto-token that arrives before the local KxKey exists is buffered and drained on
authentication.

### 6ter.7 The honest interop posture for Slice 2b-ii + 2c

**Level 1 — Our-to-our discovery → authenticate → key exchange → strict-gated match → encrypted DATA (ACHIEVED)**
Two security-enabled participants authenticate on SPDP discovery, exchange conformant
KxKey-encrypted §9.5.2 key material, and both reach `auth-remote` `:keyed` with the other's writer
KeyMaterial installed.  A security-enabled participant strictly refuses an unauthenticated peer
(`run-auth-secured-refuses-plain-test`, non-vacuous via plain↔plain control).  Encrypted pub/sub
round-trip with the exchanged keys proven by `run-auth-encrypted-pubsub-keyx-test` (ciphertext on
wire: plaintext absent + header `#(0 0 0 4)` per §9.5.3.3.1; plaintext delivered to subscriber).
337 tests Clasp + SBCL (Clasp first; non-vacuous — NOT `:keyed` before the exchange completes).

**Level 2 — Don't-break-plain (ACHIEVED)** A participant with no `:identity` is byte-identical to
the pre-security plain path; `run-auth-plain-byte-identical-test` confirms 8-byte `"PLAINDAT"` is
delivered exactly.  A security-enabled participant strictly refuses an unauthenticated peer.

**Level 3 — Live Connext-Security interop (DEFERRED to Slice 5)** The RTI Security Plugins are not
installed.  The §9.5.2 KeyMaterial framing, the KxKey-AEAD wrap, and the reliable Volatile endpoint
are self-consistent (our-to-our) but unverified against a live Connext peer (see ADR 0034).

---

## 6quarter. Key-exchange API reference and worked example

### 6quarter.1 The §9.5.3 KxKey/KxSalt API (`dds.security`)

| Symbol | Contract |
|---|---|
| `derive-kx-key (shared-secret challenge1 challenge2)` | Derive the §9.5.3 KxKey; returns a `kx-key-handle` (foreign buffer). challenge1 = initiator nonce, challenge2 = responder nonce. |
| `derive-kx-salt (shared-secret challenge1 challenge2)` | Derive the §9.5.3 KxSalt; same signature. Challenge inputs are SWAPPED between KxKey and KxSalt by spec design. |
| `kx-key-bytes (handle)` | Return the 32-byte foreign-backed buffer; do not retain past `free-kx-key`. |
| `free-kx-key (handle)` | Zeroize and free the foreign buffer. Idempotent; NIL is a no-op. Every handle from `derive-kx-key`/`derive-kx-salt` must be freed here. |
| `+kxkey-label+` | ASCII `"key exchange key"` (16 bytes, §9.5.3, hex `6b65792065786368616e6765206b6579`). |
| `+kxsalt-label+` | ASCII `"keyexchange salt"` (16 bytes, §9.5.3, hex `6b657965786368616e67652073616c74`). |

KDF construction (§9.5.3; two-step HMAC-SHA256, no HKDF; pinned from the T0 spike §2.4 /
Fast DDS corroboration):

```
KxKey = HMAC-SHA256(key = SHA-256(challenge_2 || "+kxkey-label+" || challenge_1),
                    data = shared_secret)
KxSalt = HMAC-SHA256(key = SHA-256(challenge_1 || "+kxsalt-label+" || challenge_2),
                     data = shared_secret)
```

All inputs are 32-byte vectors.  Both functions signal `secured-payload-malformed` on
wrong-length inputs (fail-closed, NFR-SEC-POSTURE).

### 6quarter.2 The §9.5.2 KeyMaterial + CryptoToken API (`dds.security`)

| Symbol | Contract |
|---|---|
| `generate-writer-key-material (writer-guid)` | Generate a fresh §9.5.2 AES256-GCM `key-material` for the 16-octet `writer-guid` (random master-salt + master-sender-key via `dds.dare:random-bytes`; sender-key-id derived from GUID bytes 0–3). |
| `serialize-crypto-token (km kx-key)` | Serialize `km` as a KxKey-AEAD-wrapped CDR-LE `DataHolder` blob: nonce(12) ∥ AES256-GCM-seal(88-byte KeyMaterial CDR, key=kx-key) ∥ tag(16) = 116 bytes. Fail-closed on AEAD error. |
| `parse-crypto-token (octets kx-key)` | Parse + authenticate a KxKey-wrapped `DataHolder` blob → `key-material` or `NIL` (fail-closed on wrong key, tamper, malformed input). |
| `make-crypto-token-message (km kx-key src-guid dest-guid)` | Build a §7.4.4 `ParticipantGenericMessage` carrying one `CryptoToken` DataHolder (class_id `"dds.sec.participant_crypto_tokens"`). |
| `parse-crypto-token-message (octets kx-key)` | Parse a `ParticipantGenericMessage` + unwrap the single CryptoToken → `key-material` or `NIL`. Enforces exactly-1-DataHolder cap (spike §6.3). |
| `+participant-crypto-tokens-class-id+` | `"dds.sec.participant_crypto_tokens"` (§7.4.4; spike §7). |
| `+crypto-token-class-id+` | `"DDS:Crypto:AES_GCM_GMAC"` (§9.5; spike §7). |
| `+crypto-keymat-prop-name+` | `"dds.cryp.keymat"` (§9.5; spike §7). |

### 6quarter.3 The `crypto-keys` per-writer resolver (`dds.security`)

`crypto-keys` is a `defstruct*` (§9.5.3.3.4 encode/decode direction, T6):

| Symbol | Contract |
|---|---|
| `make-crypto-keys :encode-key-fn F :decode-key-fn G` | Construct a per-writer key resolver. Both functions are required (error default). |
| `crypto-keys-encode-key-fn (ck)` | The encode closure: `(local-writer-guid) -> (or key-material null)` — resolves the local writer's KeyMaterial for outgoing samples. |
| `crypto-keys-decode-key-fn (ck)` | The decode closure: `(remote-writer-guid) -> (or key-material null)` — resolves the remote writer's KeyMaterial for incoming samples. |

Both closures return `NIL` when no key is installed; callers are fail-closed (sample
dropped, no plaintext on the secured path).  The resolver is installed on
`disc-node-crypto-transform` BEFORE `resume-parked-matches` fires.

### 6quarter.4 The `select-suite-for-identities` encapsulation (`dds.security`)

```lisp
(select-suite-for-identities local-identity remote-id-token-octets)
  ;; -> auth-suite | nil
  ;; Derive both cert kinds from the dds.cert.algo property of the local identity and
  ;; the remote IdentityToken octets via %cert-algo->kind, then call select-auth-suite.
  ;; Returns NIL — meaning REJECT the remote — when either algo is unsupported or the
  ;; cert kinds yield no common suite.
```

This keeps the `nil`-handling co-located with `%cert-algo->kind`, so the manager never
passes `nil` to `select-auth-suite` (whose ftype constrains both arguments to
`(member :ec :rsa)` per §9.3.2).

### 6quarter.5 New `disc-node` security extension slots (`dds.disc`)

| Exported accessor | Slot type | Contract |
|---|---|---|
| `disc-node-on-participant-discovered` | `(or null function)` | Called `(node prefix spdp)` outside the node lock on the first SPDP arrival from a security-capable (IdentityToken-carrying) remote (DDS-Security 1.1 §7.3.4). NIL = ignored. |
| `disc-node-auth-gate` | `(or null function)` | Called `(node remote local)` as the second sequential gate after the type-gate in `%match-remote-endpoint`; returns `:compatible` / `:incompatible` / `:pending` (§7.3). NIL = security off → `:compatible`. |
| `disc-node-auth-state` | `hash-table` (EQUALP) | Manager-owned per-participant auth state table; keyed by 12-octet GUID prefix → opaque `auth-remote` record (DDS-Security 1.1 §7.3). |

### 6quarter.6 `%install-auth-manager` (`dds.dcps`)

```lisp
(%install-auth-manager p identity-handle)
  ;; -> domain-participant
  ;; Create P's DDS-Security §8.7 auth-manager state (holding IDENTITY-HANDLE — the local
  ;; identity with the private key) and install its three hooks on P's disc-node:
  ;; ON-PARTICIPANT-DISCOVERED, ON-STATELESS-MESSAGE, and AUTH-GATE.
  ;; Called by create-participant :identity; not normally called directly.
```

### 6quarter.7 A worked end-to-end example — authenticated encrypted pub/sub

```lisp
(let* ((ca-oct   (map '(simple-array (unsigned-byte 8) (*)) #'char-code
                      (uiop:read-file-string
                       "interop/security-auth/pki/ca/ca-cert.pem")))
       (cert-a-oct (map '(simple-array (unsigned-byte 8) (*)) #'char-code
                        (uiop:read-file-string
                         "interop/security-auth/pki/participant_ec/identity_cert.pem")))
       (key-a-oct  (map '(simple-array (unsigned-byte 8) (*)) #'char-code
                        (uiop:read-file-string
                         "interop/security-auth/pki/participant_ec/identity_key.pem")))
       (cert-b-oct (map '(simple-array (unsigned-byte 8) (*)) #'char-code
                        (uiop:read-file-string
                         "interop/security-auth/pki/participant_ec_b/identity_cert.pem")))
       (key-b-oct  (map '(simple-array (unsigned-byte 8) (*)) #'char-code
                        (uiop:read-file-string
                         "interop/security-auth/pki/participant_ec_b/identity_key.pem"))))

  ;; 1. Load and validate local identities
  (multiple-value-bind (id-a err-a)
      (dds.security:validate-local-identity ca-oct cert-a-oct key-a-oct
        (make-array 16 :element-type '(unsigned-byte 8)
                       :initial-contents '(1 2 3 4 5 6 7 8 9 10 11 12 13 14 15 16)))
    (assert id-a () (format nil "id-a: ~a" err-a))
    (multiple-value-bind (id-b err-b)
        (dds.security:validate-local-identity ca-oct cert-b-oct key-b-oct
          (make-array 16 :element-type '(unsigned-byte 8)
                         :initial-contents '(200 2 3 4 5 6 7 8 9 10 11 12 13 14 15 16)))
      (assert id-b () (format nil "id-b: ~a" err-b))

      ;; 2. Create security-enabled participants.
      ;;    create-participant :identity sets the SPDP IdentityToken + installs the auth manager.
      (let ((p-a (dds.dcps:create-participant :domain 99 :identity id-a))
            (p-b (dds.dcps:create-participant :domain 99 :identity id-b)))

        ;; 3. Wire peers, announce topics + types.
        ;;    The auth manager fires automatically on SPDP discovery:
        ;;      on-participant-discovered -> handshake -> SharedSecret -> KxKey ->
        ;;      generate-writer-key-material -> serialize-crypto-token -> PSM send ->
        ;;      parse-crypto-token-message on the peer -> install remote-km -> :keyed ->
        ;;      resume-parked-matches -> endpoint match.
        (dds.disc:add-peer (dp-node p-a) "127.0.0.1")
        (dds.disc:add-peer (dp-node p-b) "127.0.0.1")

        ;; 4. Wait for both to reach :keyed.
        ;;    The auth gate parks any endpoint match until :keyed; resume fires automatically.
        (let ((keyed nil))
          (dotimes (i 300)
            (let ((ms-a (dp-auth-state p-a)))
              (when (and ms-a
                         (some (lambda (ar)
                                 (eq (dds.dcps::auth-remote-state ar) :keyed))
                               (alexandria:hash-table-values
                                (dds.disc:disc-node-auth-state (dp-node p-a)))))
                (setf keyed t)
                (return)))
            (sleep 0.02))
          (assert keyed () "participants did not reach :keyed within 6s"))

        ;; 5. Publish known plaintext from A; B receives it decrypted.
        ;;    The crypto-transform slot is now a crypto-keys resolver (not make-test-key-material).
        ;;    A's publish-sample: encode-key-fn(A-writer-guid) -> km -> encode-serialized-payload.
        ;;    B's %deliver-user-sample: decode-key-fn(A-writer-guid) -> km -> decode-serialized-payload.
        (let ((plaintext #(#x4b #x45 #x59 #x58 #x44 #x41 #x54 #x41))) ; "KEYXDATA"
          (dds.disc:publish-sample (dp-node p-a) plaintext)
          ;; ... poll for receipt on p-b, then assert received = plaintext ...
          )

        ;; 6. Cleanup.
        (dds.dcps:delete-participant p-a)
        (dds.dcps:delete-participant p-b)))))
```

See `run-auth-encrypted-pubsub-keyx-test` in `src/dds-tests/security-auth-test.lisp` for
the full working test, including the ciphertext-on-wire assertions (plaintext absent,
header bytes `#(0 0 0 4)` = AES256-GCM `transformation_kind` per §9.5.3.3.1 Table 69).

### 6quarter.8 The honest interop posture (complete picture, ADR 0034)

| Item | Status |
|---|---|
| Our-to-our: auth → key exchange → strict gate → encrypted DATA | **ACHIEVED** (337 tests Clasp + SBCL) |
| Don't-break-plain (byte-identical plain path) | **ACHIEVED** (`run-auth-plain-byte-identical-test`) |
| Strict refusal of unauthenticated peers | **ACHIEVED** (`run-auth-secured-refuses-plain-test`) |
| KxKey-AEAD wrap nonce/AAD vs Connext | **NEEDS-VERIFICATION** (Slice 5) |
| §9.5.2 KeyMaterial CDR framing vs Connext | **NEEDS-VERIFICATION** (Slice 5) |
| KeyMaterial master-key/salt in foreign buffers | **HARDENING-GAP** (control-plane; follow-on) |
| Reliable `ParticipantVolatileMessageSecure` endpoint | **DEFERRED** (Slice 5) |
| RTPS/submessage protection | **DEFERRED** (later slice) |
| Live Connext-Security interop | **DEFERRED** (Slice 5 = the P6 exit gate) |

See ADR 0034 (`docs/adr/0034-dds-security-auth-keyx.md`) for the full analysis.

---

## 6quinque. AccessControl plugin — Slice 3 (DDS-Security 1.1 §8.4, §9.4)

Slice 3 (landed 2026-06-26, WP-DDS-SECURITY-ACCESS-CONTROL, ADR 0035) delivers the
DDS-Security 1.1 **`DDS:Access:Permissions`** builtin AccessControl plugin — the policy layer
that decides *what* an authenticated participant is allowed to do.

**Scope of Slice 3:** CMS-verify the signed Governance + Permissions documents (signed by a
Permissions CA) via OpenSSL; parse the XML; enforce allow/deny at the three §8.4 check points
(participant creation, local DataWriter/DataReader creation, remote endpoint matching), our-to-our.

### 6quinque.1 The two document types (§9.4.1)

**Governance** (`governance.xml`, signed as `governance.p7s`) is a per-domain policy document.
The subset parsed by this slice:

| Element | Parsed field | Effect |
|---|---|---|
| `allow_unauthenticated_participants` | `governance-allow-unauthenticated` | Enforced upstream by the Slice-2 auth-gate |
| `enable_join_access_control` | `governance-enable-join-ac` | Gates `check_create_participant` |
| `topic_rule/topic_expression` | First element of each `topic-rules` entry | Matched by `%topic-match-p` |
| `enable_read_access_control` | `(cadr rule)` | Gates `check_remote_datawriter` / `check_create_datareader` |
| `enable_write_access_control` | `(cddr rule)` | Gates `check_remote_datareader` / `check_create_datawriter` |

**Permissions** (`permissions.xml`, signed as `permissions.p7s`) is a per-participant policy
document.  One `<grant>` per participant subject name; each grant contains ordered
`<allow_rule>` / `<deny_rule>` elements with `<publish>` / `<subscribe>` operations and
`<topics>` lists.

### 6quinque.2 CMS signature verification (`dds.dare:cms-verify`)

```lisp
(dds.dare:cms-verify signed-octets ca-store)
  ;; -> (or (simple-array (unsigned-byte 8) (*)) null)
  ;; Verify a Permissions-CA-signed document in SIGNED-OCTETS against CA-STORE (an X509_STORE*
  ;; from dds.dare:x509-load-ca). Returns the verified plaintext bytes; NIL on any failure
  ;; (fail-closed). Decode-tolerant of BOTH §9.4.1.1 container forms (RFC 5652 + RFC 5751):
  ;;   (1) bare-PEM CMS  (-----BEGIN PKCS7-----, embedded)        PEM_read_bio_CMS, flags=0
  ;;   (2) MIME multipart/signed S/MIME (detached + text/plain)   SMIME_read_CMS + CMS_TEXT
  ;; Form (1) is tried first (byte-identical to the prior PEM-only path); form (2) is the
  ;; fallback so a cross-vendor c.perm and any S/MIME-signed document validate. Both chain-verify
  ;; against CA-STORE. DDS-Security 1.1 §9.4.1.1.
```

`cms-verify` is fail-closed: any parse error, chain failure, or signature mismatch → NIL.
No hand-rolled crypto (FR-SEC-2): all CMS parsing and verification is via OpenSSL. The dual-form
tolerance (WP-DDS-SECURITY-FASTDDS-INTEROP T6) lets the SAME participant consume the bare-PEM `.p7s`
our-to-our fixtures AND the MIME `.smime` form Fast DDS emits/reads as the §9.3.2.1 handshake c.perm.

### 6quinque.3 The data model (`dds.security`)

| Symbol | Type | Contract |
|---|---|---|
| `governance` | `defstruct*` | §9.4.1.2.3 data model: `allow-unauthenticated`, `enable-join-ac`, `topic-rules` (list of `(expr . (read-ac . write-ac))`) |
| `parse-governance (octets)` | `(or governance null)` | Parse §9.4.1.2.3 XML from OCTETS; NIL on malformed input |
| `governance-topic-rule (gov topic-name)` | `(values boolean boolean)` | First-matching topic_rule for TOPIC-NAME; `(nil nil)` if none |
| `permissions` | `defstruct*` | §9.4.1.3.2 grant data model: `subject-name`, `not-before`, `not-after`, `default` (`:allow` / `:deny`), `rules` |
| `parse-permissions (octets)` | `(or list null)` | Parse §9.4.1.3.2 XML; return list of `permissions` structs (one per `<grant>`); NIL on malformed |
| `permissions-allow-publish-p (perms topic-name)` | `boolean` | T if PERMS grants publish on TOPIC-NAME (first-match-wins, §9.4.1.3.2.10) |
| `permissions-allow-subscribe-p (perms topic-name)` | `boolean` | T if PERMS grants subscribe on TOPIC-NAME (first-match-wins, §9.4.1.3.2.10) |

### 6quinque.4 The §8.4 check predicates (`dds.security`)

| Symbol | Contract |
|---|---|
| `access-handle` | §8.4 plugin handle: owns the Permissions CA `X509_STORE*` + parsed docs + full grant-list |
| `validate-local-permissions (pca-oct gov-oct perm-oct local-subject)` | §8.4.2.1: CMS-verify both docs vs PCA; parse; select local grant; return `access-handle` or NIL |
| `validate-remote-permissions (ah remote-perm-oct remote-subject)` | §8.4.2.2: CMS-verify vs AH's CA; parse; select remote grant; return `permissions` or NIL |
| `free-access-handle (ah)` | Release the Permissions CA `X509_STORE*` owned by AH |
| `check-create-participant (ah)` | §8.4.2.3: T when join-AC is off or local permissions bound |
| `check-create-datawriter (ah topic)` | §8.4.2.4: Governance write-AC toggle + local Permissions publish check |
| `check-create-datareader (ah topic)` | §8.4.2.5: Governance read-AC toggle + local Permissions subscribe check |
| `check-remote-datawriter (ah remote-perms topic)` | §8.4.2.7: local Governance read-AC toggle + remote Permissions publish check |
| `check-remote-datareader (ah remote-perms topic)` | §8.4.2.8: local Governance write-AC toggle + remote Permissions subscribe check |

The **Table 32 toggle semantics** (§9.4.1.2.3): `enable_read_access_control` gates both
`check_create_datareader` (local subscribe creation) and `check_remote_datawriter` (the local
read path vets the remote publisher); `enable_write_access_control` gates both
`check_create_datawriter` and `check_remote_datareader`.

### 6quinque.5 Turning it on (`dds.dcps`)

```lisp
(let* ((to-oct (lambda (s) (map '(simple-array (unsigned-byte 8) (*)) #'char-code s)))
       (ca-pca-oct  (funcall to-oct (uiop:read-file-string "pki/pca-cert.pem")))
       (gov-oct     (funcall to-oct (uiop:read-file-string "pki/governance.p7s")))
       (perm-oct    (funcall to-oct (uiop:read-file-string "pki/permissions.p7s")))
       ;; identity already validated (see §6ter.2)
       (local-subj  (dds.dare:x509-subject-name (dds.security::identity-handle-cert id)))
       ;; CMS-verify both docs, parse, select local grant
       (ah          (dds.security:validate-local-permissions ca-pca-oct gov-oct perm-oct local-subj))
       ;; create participant with identity (auth-gate) then install access control
       (p           (dds.dcps:create-participant :domain 0 :identity id)))
  (dds.dcps::%install-access-control p ah)
  ...)
```

`%install-access-control (p access-handle)` stores the `access-handle` in `dp-access-state`
and wires the permissions-gate closure on the disc-node.  With **no** `access-handle`
installed, `dp-access-state` stays NIL and the participant is the byte-identical plain path
(all gate calls return `:compatible` unconditionally).

### 6quinque.6 A worked allow/deny example

```lisp
;;; Governance fixture: enable_read_access_control=true, enable_write_access_control=true, topic="*"
;;; Permissions fixture (EC grant): allow publish+subscribe "Square"; deny publish+subscribe "Circle"; default DENY

(let* ((xml   (map '(simple-array (unsigned-byte 8) (*)) #'char-code
                   (uiop:read-file-string "pki/permissions.xml")))
       (perms (dds.security:parse-permissions xml))
       (grant (find "/CN=TestParticipantEC/O=DDS-Test/C=DE" perms
                    :key #'dds.security:permissions-subject-name :test #'string=)))

  ;; "Square" — first allow_rule matches:
  (assert (dds.security:permissions-allow-publish-p   grant "Square") () "Square pub must be allowed")
  (assert (dds.security:permissions-allow-subscribe-p grant "Square") () "Square sub must be allowed")

  ;; "Circle" — first deny_rule matches:
  (assert (not (dds.security:permissions-allow-publish-p   grant "Circle")) () "Circle pub must be denied")
  (assert (not (dds.security:permissions-allow-subscribe-p grant "Circle")) () "Circle sub must be denied")

  ;; "Triangle" — no rule, default DENY:
  (assert (not (dds.security:permissions-allow-publish-p   grant "Triangle")) () "Triangle -> default DENY")

  ;; Wildcard "Sq*" would also match "Square":
  (assert (dds.security::%topic-match-p "Sq*" "Square") () "prefix wildcard match"))
```

End-to-end (full gate ladder, our-to-our): a `"Square"` writer on participant A matches a
`"Square"` reader on participant B (allow rule fires at the permissions-gate → `:compatible`).
A `"Circle"` writer on participant A does NOT match a `"Circle"` reader on participant B
even though both reach `auth-remote` `:keyed` (deny rule fires → `:incompatible`).  Proven
by `run-access-control-allow-deny-test` (NON-VACUOUS: `sq-b matched-count >= 1` AND
`ci-b matched-count = 0`; identical identities, QoS, and auth; only the topic name differs).

### 6quinque.7 The honest interop posture for Slice 3

**Level 1 — Our-to-our: authenticate + AccessControl allow/deny enforced (ACHIEVED)**
Two security-enabled participants with signed Governance + Permissions authenticate (Slice-2
auth path → both reach `:keyed`), then the permissions-gate enforces the topic-level policy:
an allowed topic matches and communicates; a denied topic is refused (`:incompatible`).
`run-access-control-local-deny-test` proves `check_create_datawriter` enforcement.
349 tests Clasp + SBCL (Clasp first; non-vacuous — both reach `:keyed` before the deny fires;
the ONLY variable is the topic name).

**Level 2 — Default-OFF (ACHIEVED)** A participant with no Governance/Permissions has
`dp-access-state=NIL`; the permissions-gate returns `:compatible` unconditionally; the participant
is byte-identical to the pre-Slice-3 plain path.  Confirmed by `run-access-control-default-off-test`.

**Level 3 — Live cross-vendor AccessControl interop (Slice 5, IN PROGRESS)** The per-participant
`c.perm`-in-handshake exchange is now WIRED and Fast-DDS-validated (WP-DDS-SECURITY-FASTDDS-INTEROP
T6): the participant emits its configured signed Permissions document as the §9.3.2.1 c.perm, and
`cms-verify` is decode-tolerant of both signed-document forms (bare PEM-PKCS7 and MIME-wrapped
S/MIME), so Fast DDS's `validate_remote_permissions` (`SMIME_read_PKCS7` + `PKCS7_verify(PKCS7_TEXT)`)
accepts our permissions — the prior "Cannot read as PKCS7" reject is resolved in the live run. Live
Connext-Security (RTI Security Plugins not installed) remains DEFERRED to the Slice-5 5b sub-gate. See
ADR 0035; the cross-vendor campaign is captured in `interop/security-secure-discovery/captures/`.

---

## 6sexto. Secure discovery — Slice 4 (DDS-Security 1.1 §7.3.7, §7.4.5, §9.5)

Slice 4 (landed 2026-06-28, WP-DDS-SECURITY-SECURE-DISCOVERY, ADR 0036) protects the builtin
discovery traffic and the whole user-data RTPS datagram between matched secure participants,
governed by the Governance protection-kind policy.  It is effectively the entire §8.5
Cryptographic plugin beyond Slice-1's serialized-payload protection: **submessage protection**
(§8.5.1.7-.9), **whole-RTPS-message protection** (§8.5.1.10-.12), **origin authentication** (the
receiver-specific MAC, §9.5.3.3.4.3), a reliable **ParticipantVolatileMessageSecure** endpoint
carrying the crypto-token exchange, the **Governance protection-kind model**, and the wiring of
the **secure builtin discovery endpoints** (secure SEDP, secure participant-message, secure SPDP).

**Three structural choices** (ADR 0036): (1) the new tiers are *additive* — Slice-1's byte-exact
`crypto.lisp`/`transform.lisp` is untouched and now delegates to a shared
`crypto/crypto-header.lisp` codec (DRY); (2) a dedicated `crypto-manager` (`src/dds-dcps/`),
parallel to `auth-manager`, owns the §8.5 ParticipantCrypto/EntityCrypto registries + the token
exchange; (3) the reliable PVMS endpoint *reuses* the M2 reliable writer/reader engine.

**What is protected, and when:** plain SPDP + the PSM handshake stay clear (the auth bootstrap;
rtps-protection-exempt); PVMS is submessage-protected with a SharedSecret-derived key; once a pair
is `:keyed`, the user data plane is whole-RTPS-wrapped (`rtps_protection_kind`), protected topics'
SEDP rides secure SEDP only (`discovery_protection_kind`), WLP rides secure participant-message
(`liveliness_protection_kind`), and a secure SPDP re-announce rides the discovery tier.
**Security-OFF is byte-identical** (no governance, or every kind = NONE → no secure bits, NIL
crypto resolvers, the plain wire unchanged — the false-REJECT guard).

**Building blocks** (each its own sub-section below; the numbering follows the build order, not the
reading order):

| Topic | Increment | Sub-section |
|---|---|---|
| Origin authentication (submessage tier) — §9.5.3.3.4.3 | T3 | §6sexto.1 |
| Whole-RTPS-message protection (SRTPS) — §8.5.1.10-.12 | T4 | §6sexto.2 |
| Reliable ParticipantVolatileMessageSecure (PVMS) — §9.5.3.1 | T7 | §6sexto.3 |
| Origin-auth for the builtin secure endpoints | T-ORIGINAUTH | §6sexto.4 |
| `rtps_protection` engagement on the live data path | T10 | §6sexto.5 |
| Secure participant-message (liveliness) + secure SPDP | T11 | §6sexto.6 |
| Governance protection-kind model (the knobs) — §9.4.1.2 | T5 | §6sexto.7 |
| The crypto-manager + crypto-token exchange + `:keyed` promotion | T6, T8 | §6sexto.8 |
| Secure SEDP wiring + the worked secure-discovery example | T9 | §6sexto.9 |

(Submessage protection itself — `encode/decode-datawriter-submessage` and the datareader twins,
SIGN + ENCRYPT, §8.5.1.7-.9 — is T2; the shared region engine it introduces backs §6sexto.1, .2,
.5, .6, .9.  Whole-RTPS-message protection is T4 (§6sexto.2), not T2.)

**Honest interop posture (read this before claiming anything).**  Our-to-our is **complete**: two
secure participants authenticate, exchange crypto tokens over reliable PVMS, reach `:keyed`,
announce protected topics only over secure SEDP, match, and exchange data protected at all three
tiers with origin authentication where governance requires it (§6sexto.9).  **Live Fast
DDS-Security is PARTIAL:** a SECURITY=ON Fast DDS v3.6.1 peer was built on our PKI and bidirectional
SPDP discovery achieved, with four conformant wire/config fixes — but the §8.7 auth handshake is
**REJECTED** at the remote IdentityToken (the propagate-byte divergence, ADR 0036 Carry 1), so
**no cross-vendor `auth → keyed → secure-SEDP → protected data` was achieved**.  **Live RTI
Connext-Security is static only** (Security Plugins absent).  The full cross-vendor path + live
Connext is **Slice 5 — the P6 exit gate**.  See §6sexto.9, ADR 0036, and
`interop/security-secure-discovery/README.md`.  **Do NOT interpret this section as "cross-vendor
secure discovery verified."**

T0 (landed 2026-06-27) pinned the wire constants; the §7.3.7 shared CryptoHeader/CryptoContent/
CryptoFooter codec is T1, §8.5.1.7-.9 submessage protection (SIGN+ENCRYPT) is T2, §9.5.3.3.4.3
origin authentication is T3 (§6sexto.1), and §8.5.1.10-.12 whole-RTPS-message protection (SRTPS) is
T4 (§6sexto.2).

**`src/dds-rtps/discovery.lisp`** (`dds.rtps.discovery`) — kept with the other builtin EntityIds (DRY):
secure builtin EntityIds (`+entityid-*+`) for the secure SEDP/SPDP endpoints and the PVMS/PSM
endpoints (§7.4.5 / §9.5.1.3 Table 40); and the §7.4.6.1 BuiltinEndpointSet security bits 16–27
(`+be-*+`) for secure-discovery capability advertisement in SPDP participant data (Table 28).

**`src/dds-security/crypto/constants.lisp`** (`dds.security`): the §7.3.7 security submessage kinds
(`+submessage-sec-body+` SEC_BODY / `+submessage-sec-prefix+` SEC_PREFIX /
`+submessage-sec-postfix+` SEC_POSTFIX / `+submessage-srtps-prefix+` SRTPS_PREFIX /
`+submessage-srtps-postfix+` SRTPS_POSTFIX); the §9.5.3.3.4.3 receiver-specific session-key KDF
label `+kdf-label-session-receiver-key+` (`"SessionReceiverKey"`); and the §9.4.1.2
ProtectionKind/BasicProtectionKind keyword enums (`+protection-kinds+` / `+basic-protection-kinds+`)
plus the XSD-token alist `+protection-kind-xsd-strings+`.  The crypto-token `message_class_ids`
(`dds.sec.{participant,datawriter,datareader}_crypto_tokens`:
`+gm-participant-crypto-tokens+` / `+gm-datawriter-crypto-tokens+` / `+gm-datareader-crypto-tokens+`)
are pinned in `src/dds-security/auth/keyexchange.lisp` (§7.4.4 / §9.5.2.2 — see the DRY header
comment in `constants.lisp`).

Pinned-values table, spec-clause citations, and dual Fast-DDS/Connext corroboration:
`docs/superpowers/spikes/2026-06-27-dds-security-secure-discovery.md`.

### 6sexto.1 Origin authentication (T3, DDS-Security 1.1 §9.5.3.3.4.3)

The `*_WITH_ORIGIN_AUTHENTICATION` protection kinds add, on top of the common_mac, a
**per-matched-receiver MAC** so a receiver can prove the message was authored by the holder of the
writer's per-receiver key (not merely by some group-key holder). The CryptoFooter then carries
`receiver_specific_macs_count` + one `{receiver_mac_key_id (4) , receiver_mac (16)}` entry per receiver;
the SEC_POSTFIX `octetsToNextHeader` grows from 20 to `20 + 20*count`. The seal (ciphertext +
common_mac) is unchanged from plain SIGN/ENCRYPT — origin-auth only appends to the footer.

Two derivations (both `dds.security`, `crypto/submessage.lisp`):

- **`derive-receiver-specific-session-key (master-receiver-specific-key master-salt session-id)
  → (octets 32)`** —
  `HMAC-SHA256(master_receiver_specific_key, "SessionReceiverKey" ‖ master_salt ‖ session_id)` (no
  trailing counter — Fast-DDS/Cyclone-aligned; T-RECONCILE).
  The receiver analogue of `derive-session-key`; both share the one framing helper
  (`%derive-labeled-session-key`, `crypto.lisp`), differing only in the KDF label
  (`+kdf-label-session-receiver-key+` vs `+session-key-id-string+`).
- **`compute-receiver-specific-mac (recv-session-key nonce common-mac) → (octets 16)`** —
  a pure GMAC: `AES-256-GCM(recv_session_key, nonce, AAD = common_mac, plaintext = empty) → tag`. The
  `nonce` is **the same 12-octet init vector (`session_id ‖ iv_suffix`) the common_mac was sealed with**
  (corroborated against Fast DDS `AESGCMGMAC_Transform.cpp`; see `docs/provenance.md`).

The encode/decode API (`encode-/decode-datawriter-submessage` and the datareader twins) gains:

- **encode `&key receivers`** — a list of `(receiver-key-id . master-receiver-specific-key)` conses
  (4- and 32-octet vectors). After the seal, one GMAC over the common_mac is emitted per receiver into
  the footer. Empty (the default) ⇒ plain SIGN/ENCRYPT (`receiver_specific_macs_count = 0`).
- **decode `&key my-receiver-key-id my-receiver-key`** — when set, after the common_mac verifies the
  decoder MUST also find this receiver's footer entry (by `my-receiver-key-id`), recompute its GMAC under
  `my-receiver-key`, and **constant-time** compare; an absent entry or a mismatch fails-closed to `NIL`
  **even though the common_mac is valid**. Both `NIL` (the default) ⇒ origin-auth not expected (the
  common_mac alone governs; backward-compatible).

`generate-writer-key-material` gains **`&key origin-auth`**: with it, the returned KeyMaterial carries a
random non-zero `receiver_specific_key_id` + `master_receiver_specific_key` (§9.5.2 Table 65); without it
(the default) those stay all-zero (participant-level, no origin-auth).

Worked example (datawriter, ENCRYPT, two receivers; decode as receiver #2):

```lisp
(let* ((km    (dds.security:make-test-key-material))
       (sub   <plain RTPS submessage octets>)
       (r1    (cons kid1 master-recv-key-1))        ; 4-octet key-id . 32-octet master key
       (r2    (cons kid2 master-recv-key-2))
       (blob  (dds.security:encode-datawriter-submessage km :encrypt sub :receivers (list r1 r2))))
  ;; receiver #2 with its key recovers the plaintext:
  (dds.security:decode-datawriter-submessage km blob
                                             :my-receiver-key-id kid2 :my-receiver-key master-recv-key-2)
  ;; a WRONG receiver key -> NIL though the common_mac is valid (origin-auth gates):
  (dds.security:decode-datawriter-submessage km blob :my-receiver-key-id kid2 :my-receiver-key wrong-key)
  ;; origin-auth OFF on the SAME bytes -> the plaintext, on the common_mac alone:
  (dds.security:decode-datawriter-submessage km blob))
```

**Honest interop posture (T3).** Self-consistent (our encode ↔ our decode) and byte-reproducible across
SBCL + Clasp; corpus + property-fuzz (hostile/oversized `receiver_specific_macs_count` is capped by T1
before any allocation, fail-closed). The two foundational cross-vendor divergences are now **RESOLVED**
(T-RECONCILE, 2026-06-27): the session-key KDF drops the `"0001"` counter Fast DDS omits, and the footer
`receiver_specific_macs_count` (plus the `crypto_content` length sibling found in the audit) is BIG-ENDIAN —
both corroborated clean-room against Fast DDS AND Eclipse Cyclone DDS. See `docs/provenance.md`
(M7/P6 T-RECONCILE). The remaining open T12 item is the SIGN inter-submessage 4-octet re-alignment (§6sexto.2).

### 6sexto.2 Whole-RTPS-message protection (T4, DDS-Security 1.1 §8.5.1.10-.12)

Where the submessage tier (T2/T3) protects ONE submessage, the RTPS tier protects the **entire submessage
STREAM** of a datagram — everything AFTER the 20-octet RTPS Header — keyed by the per-participant
**ParticipantCrypto KeyMaterial** (the `rtps_protection_kind` governance setting selects whether a
participant applies it). It is the SAME AES-GCM-GMAC mechanism over the SHARED
`%encode-secured-region` / `%decode-secured-region` engine (DRY, no copy-paste); only three things differ:
the bracket submessage ids are **`SRTPS_PREFIX` (0x33) / `SRTPS_POSTFIX` (0x34)** (not SEC_PREFIX/SEC_POSTFIX);
the protected unit is the whole stream; and on SIGN the verbatim body is located by **walking** the stream
to the trailing `SRTPS_POSTFIX` (the stream is multi-submessage). The caller keeps / re-prepends the RTPS
Header — the transform operates only on the submessage stream.

Framing (identical to the submessage tier, only the kinds change):

```
ENCRYPT:  SRTPS_PREFIX(0x33) ‖ CryptoHeader{kind=AES256_GCM}  ‖ SEC_BODY(0x30) ‖ len ‖ ciphertext ‖ SRTPS_POSTFIX(0x34) ‖ CryptoFooter
SIGN:     SRTPS_PREFIX(0x33) ‖ CryptoHeader{kind=AES256_GMAC} ‖ <original submessage stream VERBATIM>   ‖ SRTPS_POSTFIX(0x34) ‖ CryptoFooter
```

The API (`dds.security`, `crypto/rtps-message.lisp`):

- **`encode-rtps-message (km kind submessages-octets &key receivers) → (or octets null)`** — `kind` ∈
  `(:sign :encrypt)`; `submessages-octets` is the stream after the RTPS Header; returns the
  `SRTPS_PREFIX ‖ <body> ‖ SRTPS_POSTFIX` octets. `:receivers` enables origin authentication exactly as in
  §6sexto.1 (the footer carries one receiver MAC each).
- **`decode-rtps-message (km srtps-octets &key my-receiver-key-id my-receiver-key) → (or octets null)`** —
  recovers the original stream, or `NIL` on any failure (fail-closed). The wire
  `CryptoHeader.transformation_kind` selects ENCRYPT (open the SEC_BODY ciphertext under empty AAD) vs SIGN
  (verify the GMAC over the verbatim stream, located by walking to `SRTPS_POSTFIX`). The optional receiver
  keys gate origin authentication as in §6sexto.1; both `NIL` (the default §8.5.1.12 2-arg contract) ⇒ the
  common_mac alone governs.

These are consumed by the send / `%handle-datagram` paths at T10. The SIGN decode-locate (walk to the
trailing `SRTPS_POSTFIX`) is corroborated clean-room against Fast DDS `decode_rtps_message`; see
`docs/provenance.md` (M7/P6 T4).

Worked example (whole-RTPS, SIGN, our-to-our round-trip):

```lisp
(let* ((km   (dds.security:make-test-key-material))    ; the ParticipantCrypto KeyMaterial
       (subs <the datagram's submessage stream, after the 20-octet RTPS Header>)
       (srtps (dds.security:encode-rtps-message km :sign subs)))   ; SRTPS_PREFIX ‖ stream ‖ SRTPS_POSTFIX
  ;; the caller keeps the RTPS Header and sends Header ‖ srtps; the peer strips the Header and:
  (dds.security:decode-rtps-message km srtps))                      ; => subs (byte-exact), or NIL
```

**Honest interop posture (T4).** Self-consistent (our encode ↔ our decode) and byte-reproducible across
SBCL + Clasp; corpus (byte-exact 100-octet ENCRYPT + 92-octet SIGN vectors), round-trip, negatives, and
property-fuzz (adversarial SRTPS brackets + hostile `rsm_count` hitting the T1 cap, prod + `(safety 0)`,
fail-closed). The shared-foundation divergences (the KDF `"0001"` counter and the footer-count /
`crypto_content`-length endianness) are now **RESOLVED** (T-RECONCILE, see §6sexto.1) —
Fast-DDS/Cyclone-aligned. One T4-specific item remains open for live interop (T12): Fast DDS re-aligns each
walked submessage to 4 octets, where our verbatim write/walk does not (a non-issue for our-to-our and for
the 4-aligned normal case). See `docs/provenance.md` (M7/P6 T4, T-RECONCILE).

### 6sexto.3 Reliable ParticipantVolatileMessageSecure (PVMS) endpoint (T7, DDS-Security 1.1 §7.4.5 / §9.5.3.1)

The **ParticipantVolatileMessageSecure** builtin endpoint (writer `0xff0202c3` / reader `0xff0202c4`, bits
24/25) is the **reliable, VOLATILE** carrier for the crypto-token exchange between two authenticated
participants. It is *reliable* (HEARTBEAT/ACKNACK repair) and *volatile* (KEEP_ALL, **no durability** — a
late joiner does **not** replay old tokens). Its own traffic is **submessage-protected (ENCRYPT)** with a
KeyMaterial derived **directly from the authenticated SharedSecret** — no token exchange is needed for the
endpoint that carries the tokens (§9.5.3.1). T7 delivers this reliable, protected transport plus the
bootstrap-key derivation; the actual crypto-token payloads + the `:authenticated → :keyed` promotion ride on
top of it (T8).

**The bootstrap key (`%pvms-derive-bootstrap-km`, `dds.disc`).** The PVMS protection KeyMaterial is Fast
DDS's *Participant2ParticipantKxKeyMaterial* (corroborated clean-room against `AESGCMGMAC_KeyFactory.cpp
register_matched_remote_participant`, see `docs/provenance.md` M7/P6 T7):

```
master_salt       = derive-kx-salt(shared_secret, challenge1, challenge2)   ; KxSalt, §9.5.3
master_sender_key = derive-kx-key (shared_secret, challenge1, challenge2)   ; KxKey,  §9.5.3
sender_key_id     = #(0 0 0 0)
transformation_kind = AES256-GCM {0 0 0 4}
```

It REUSES the already-pinned §9.5.3 `derive-kx-key`/`derive-kx-salt` KDFs (the SAME primitive the KEYX tier
uses to *wrap* tokens) — here their outputs become the §9.5.2 `key-material` of the volatile endpoint, which
plugs straight into `encode/decode-datawriter-submessage`. The protection-kind is **ENCRYPT** (Fast DDS
marks the endpoint `IS_SUBMESSAGE_ENCRYPTED`).

**API (`dds.disc`).**

| Symbol | Contract |
|---|---|
| `(%pvms-derive-bootstrap-km shared-secret challenge1 challenge2)` → `key-material` | The §9.5.3.1 SharedSecret-derived bootstrap KeyMaterial (above). Inputs 32 octets each. |
| `(enable-volatile-secure node &key on-volatile-secure)` → `node` | Give NODE the reliable VOLATILE PVMS writer + reader (reusing the M2 reliable engine) and install the receiver hook. |
| `(set-pvms-bootstrap-km node prefix km)` → `km` | Install the per-matched-remote bootstrap KM (keyed by the remote 12-octet GUID prefix); the auth/crypto manager calls this at `:authenticated`. |
| `(%send-volatile-secure node dest-prefix payload-octets)` → `t` | Reliably send PAYLOAD-OCTETS (an opaque crypto-token `ParticipantGenericMessage`) to DEST-PREFIX, submessage-protected (ENCRYPT) with its bootstrap KM; ACKNACK-repairable. |
| `(%on-volatile-secure node src-prefix submessage-octets)` → `t` | Decode the SEC_PREFIX…SEC_POSTFIX bracket with SRC-PREFIX's bootstrap KM, then deliver the recovered payload to the `on-volatile-secure` hook exactly once (fail-closed on any error). |
| `disc-node-on-volatile-secure` | The receiver hook slot `(node src-prefix payload-octets) → t` (mirrors `on-stateless-message`). |

`%handle-datagram` now routes a `SEC_PREFIX` (0x31) submessage to `%on-volatile-secure`, and a clear PVMS
HEARTBEAT/ACKNACK to the reliable-repair handlers. **Fail-closed (NFR-SEC-POSTURE):** a missing KM, an
undecryptable/malformed/tampered bracket, or a wrong-EntityId inner DATA is a silent drop — never a signal
out of the receiver thread, never plaintext on a failure.

**Worked example (our-to-our, reliable repair).**

```lisp
(let* ((a (dds.disc:make-disc-node :guid-prefix pa :host "127.0.0.1" :port 0))
       (b (dds.disc:make-disc-node :guid-prefix pb :host "127.0.0.1" :port 0)))
  ;; ... SPDP-discover a<->b, then once :authenticated both sides know shared_secret/challenges:
  (dds.disc:enable-volatile-secure a)
  (dds.disc:enable-volatile-secure b
    :on-volatile-secure (lambda (node src payload) (declare (ignore node src)) (handle-token payload)))
  ;; symmetric per-pair bootstrap KM (both derive identical bytes from the same SharedSecret + challenges)
  (dds.disc:set-pvms-bootstrap-km a pb (dds.disc::%pvms-derive-bootstrap-km ss c1 c2))
  (dds.disc:set-pvms-bootstrap-km b pa (dds.disc::%pvms-derive-bootstrap-km ss c1 c2))
  (dds.disc:%send-volatile-secure a pb token-octets))   ; B's hook fires once, after HEARTBEAT/ACKNACK repair if any DATA was lost
```

**Tests.** `run-volatile-secure-reliable-test` (drop every PVMS DATA while a flag is set → B stays empty;
clear it → the HEARTBEAT/ACKNACK loop repairs the gap → B delivers EXACTLY once, bytes equal) and
`run-volatile-secure-fail-closed-test` (B installs a WRONG bootstrap KM → B never delivers; non-vacuous).
Both green on SBCL + Clasp.

**Carry (T8) — bidirectional nonce uniqueness.** The bootstrap KM is symmetric across the pair; with the
Slice-1 fixed (all-zeros) `session_id`, two sides encoding under the shared key from `iv-counter` 0 would
collide AES-GCM nonces. T7 traffic is one-directional per exchange (no collision); the bidirectional token
exchange (T8) must give the two roles disjoint nonce spaces (distinct `session_id`s or iv ranges), exactly
as Fast DDS sets a distinct `Session.session_id` per remote crypto. See `docs/provenance.md` (M7/P6 T7).

The full per-symbol API reference will be completed at the Slice 4 capstone.

### 6sexto.4 Origin authentication for the builtin secure endpoints (T-ORIGINAUTH, §9.5.3.3.4.3)

The origin-auth CODEC (§6sexto.1) is wired into the builtin **secure-SEDP** endpoints, so a governance
`discovery_protection_kind = SIGN_WITH_ORIGIN_AUTHENTICATION` / `ENCRYPT_WITH_ORIGIN_AUTHENTICATION` now adds a
per-receiver MAC to each protected `DiscoveredWriter/ReaderData` (T9 previously fail-closed-REFUSED this tier;
that refusal is removed).

**Key model (implemented exactly; corroborated against Fast DDS `serialize_SecureDataTag`).** The
receiver-specific MAC uses the **RECEIVER's** key. For the secure-SEDP tier the receiving endpoint is the
matched secure-SEDP **READER** (publications writer `0xff0003c2` ↔ reader `0xff0003c7`; subscriptions writer
`0xff0004c2` ↔ reader `0xff0004c7`). So only the secure-SEDP **readers** are minted with a receiver-specific
key; sender A GMACs the common_mac under the matched-remote reader's `master_receiver_specific_key` (received in
that reader's crypto token) tagged with its `receiver_specific_key_id`, and receiver B verifies the entry tagged
with its OWN reader's id under its OWN key. The writer encodes under the matched reader's key, never its own.

**Token CDR (the 120-byte form).** `%serialize-km-cdr` / `%parse-km-cdr` (`dds.security`, `auth/keyexchange.lisp`)
now carry the populated receiver-specific fields: an all-zero `receiver_specific_key_id` ⇒ the 88-byte
no-origin-auth CDR (byte-identical to before); a non-zero id ⇒ the 120-byte form (`+ pad(3) + len(0x20) +
master_receiver_specific_key(32)`), keyed on the same `has_specific_key` discriminator Fast DDS uses
(`KeyMaterialCDRSerialize` L432-454; see `docs/provenance.md` M7/P6 T-ORIGINAUTH). So the matched-remote
EntityCrypto the crypto token installs retains the remote reader's receiver key.

**Wiring (cross-layer closures on the `disc-node`, the T9 pattern).** Driven from governance by
`%install-access-control` (`protection-kind-base` yields the base kind + the origin-auth flag onto
`disc-node-secure-sedp-origin-auth`). The crypto-manager (`src/dds-dcps/crypto-manager.lisp`) mints the
secure-SEDP readers with `:origin-auth t` and installs two resolvers:

- **`disc-node-secure-sedp-encode-receivers (writer-entity-id remote-prefix)`** → the matched-remote reader's
  `((receiver_specific_key_id . master_receiver_specific_key))` for `encode-datawriter-submessage :receivers`;
  `NIL` (⇒ plain SIGN/ENCRYPT) when origin-auth is off or the remote reader is not yet keyed.
- **`disc-node-secure-sedp-decode-receiver-km (transformation_key_id)`** → the LOCAL receiving reader's
  `(receiver_specific_key_id . master_receiver_specific_key)` for `decode-datawriter-submessage`'s
  `my-receiver-key-id`/`my-receiver-key`; `NIL` ⇒ the common_mac alone governs. The channel (pub vs sub) is
  resolved by mapping the wire `transformation_key_id` → the remote writer's entity-id (the crypto-manager
  `remote-key-id-entity` index) → the corresponding local reader.
- **`disc-node-secure-sedp-decode-sender-entity (transformation_key_id)`** → the EXPECTED remote sender
  entity-id the key_id was registered under (`cm-remote-entity-for-key-id`, the `remote-key-id-entity` index —
  submessage-substitution defense, §8.5.1.9 / §9.5.2 Table 65). `%on-secure-builtin` DROPS a writer-sourced
  inner DATA/HEARTBEAT whose recovered `writerId` does not equal this entity (a bracket keyed under one
  endpoint's EntityCrypto but claiming another's writerId) — fail-closed. `NIL` (unknown key_id / no resolver)
  skips the cross-check ⇒ no false-REJECT; in the live keyed path the inner writerId always equals it (each
  EntityCrypto is registered under its own endpoint's key_id). Test `run-secure-builtin-sender-crosscheck-test`.

**Tests.** `run-secure-discovery-origin-auth-test` (full e2e: two participants under
`ENCRYPT_WITH_ORIGIN_AUTHENTICATION` reach `:keyed`, exchange the 120-byte receiver KeyMaterial, and B matches A's
protected writer with a verified per-receiver MAC — `'Square'` never in cleartext);
`run-secure-sedp-origin-auth-roundtrip-test` (disc-level wiring: correct receiver key → match) and the
**non-vacuous** `run-secure-sedp-origin-auth-tamper-test` (the WRONG receiver key, same key_id → B NEVER matches
**even though the common_mac is valid** — the receiver-MAC gates beyond the common_mac, fail-closed);
`run-auth-keymaterial-origin-auth-cdr` (the 120-byte CDR round-trip + the byte-identical 88-byte carry). All
green SBCL + Clasp. SIGN/ENCRYPT (non-origin-auth) + security-OFF remain byte-identical.

### 6sexto.5 `rtps_protection` engagement on the live data path (T10, §8.5.1.10-.12)

The whole-RTPS-message codec of §6sexto.2 is now **engaged** on the live send / receive path for the **user
data plane** (the hot path). Once two participants are `:keyed`, every user-data datagram A sends to B (DATA,
HEARTBEAT, ACKNACK, GAP, DATA_FRAG/NACK_FRAG) is wrapped `RTPS-Header ‖ SRTPS_PREFIX ‖ SEC_BODY ‖
SRTPS_POSTFIX`, keyed by A's per-pair **ParticipantCrypto** (the common_mac under A's sender key; under an
`*_WITH_ORIGIN_AUTHENTICATION` governance kind, an additional per-receiver MAC under B's ParticipantCrypto
receiver key, §9.5.3.3.4.3). B resolves A's ParticipantCrypto by the datagram's source GUID-prefix, decrypts,
and re-dispatches the recovered submessage stream. **Bootstrap SPDP** (multicast, via `%send-paramlist`,
never through the wrap chokepoint) and the **PSM auth handshake** (sent pre-keying) are EXEMPT.

- **Send** (`dataplane.lisp`): `%send-raw-buf` takes an optional `dest-prefix`; when non-NIL,
  `%maybe-wrap-srtps` calls the node's `rtps-protection-encode` resolver — installed by the crypto-manager —
  which returns the local ParticipantCrypto + kind + receivers iff governance `rtps_protection_kind ≠ NONE`
  **and** the destination is `:keyed` (its ParticipantCrypto is held). The wrap is done **in place** in the
  thread's own scratch buffer (the RTPS Header `[0,20)` kept verbatim; `[20,…)` overwritten with the SRTPS
  bracket) — no fresh per-datagram message-sized array. A required-but-failed wrap **drops** (fail-closed).
  `dest-prefix` NIL (every builtin/discovery/bootstrap send) ⇒ the plain path, byte-identical.
- **Receive** (`disc.lisp` `%handle-datagram`): when the first submessage is `SRTPS_PREFIX` (0x33) and the
  crypto-manager installed the `rtps-protection-decode` resolver, resolve the remote ParticipantCrypto by the
  source prefix, `decode-rtps-message`, overwrite `[20,…)` in place with the recovered stream, and re-dispatch
  (recurse — the recovered first submessage is never SRTPS, so no further recursion). An unknown/not-keyed
  source, an undecryptable / forged / origin-auth-failed bracket → a silent **drop** (never dispatch
  unverified submessages; NFR-SEC-POSTURE).
- **Receive-side ENFORCEMENT** (`disc.lisp` `%handle-datagram`, `%rtps-protection-required-from`): the receive
  complement of the wrap. When the datagram is **NOT** SRTPS-wrapped **and** the node's governance requires
  `rtps_protection` (`disc-node-rtps-protection-kind ≠ NONE`) **and** the source participant is `:keyed` (its
  ParticipantCrypto resolves through the decode resolver), **every USER-plane submessage** is a **forgeable
  injection** (anyone can spoof a keyed peer's source GUID-prefix on a plain datagram, no key) and is **dropped
  fail-closed** before it reaches any user reader / writer or its reliable state. This covers both the user data
  (**DATA / DATA_FRAG**, discriminated by `%user-writer-entityid-p`: kind `0x02`/`0x03` vs builtin `0xc?`) **and
  the user reliability-control submessages** — the **HEARTBEAT / ACKNACK / GAP / HEARTBEAT_FRAG / NACK_FRAG**
  user fall-through branches, each gated on `(not enforce-rtps)`. Without this, a forged plain **GAP** would mark
  user SNs `:gap` (silent sample suppression), a forged plain **ACKNACK** would advance the acked-base and purge
  unacked HistoryCache changes the real reader never got (permanent data loss), and a forged plain **HEARTBEAT**
  would corrupt the reader-proxy / reflect a NACK storm. **Builtin metatraffic is exempt** (it is intentionally
  plain in this slice — the T12 carry — so SPDP / SEDP / PSM / PVMS / participant-message / TypeLookup are never
  dropped): builtin DATA is discriminated by writerId, and **builtin reliability** (SEDP / TypeLookup HEARTBEAT,
  TypeLookup / PVMS ACKNACK / HEARTBEAT) is routed to its builtin handlers in the clauses **before** the gated
  user fall-through, so it still processes (no false-REJECT). No false-REJECT of legitimate user traffic either:
  user traffic flows only after `:keyed`, and a legitimate keyed-rtps peer always SRTPS-wraps it, so a plain
  user-plane submessage from such a peer cannot legitimately occur. The post-SRTPS-decode re-dispatch suppresses
  the enforcement (the inner plaintext is already authenticated). `NONE` governance / not-keyed source ⇒
  enforcement off, byte-identical delivery.
- **Governance → node** (`access-control.lisp`): `%install-access-control` reads `governance-rtps-protection`
  and `protection-kind-base` and sets `disc-node-rtps-protection-kind` (`:sign`|`:encrypt`) +
  `-origin-auth`; the crypto-manager mints the local ParticipantCrypto **with** a receiver-specific key under
  an origin-auth kind. `NONE` leaves both default ⇒ the data path is plain, byte-identical.

Scope: T10 wraps the **user data plane** (the hot path). The builtin **metatraffic** (secure SEDP, PVMS,
plain SEDP, liveliness, TypeLookup) flows plain — the secure-SEDP tier already carries its own §8.5.1.7-.9
submessage protection — so the existing secure-discovery e2es stay green (and now exercise the new
wrap/unwrap: their protected Square sample crosses SRTPS-wrapped and is decoded byte-exact at B). Wrapping
the builtin metatraffic too is a documented follow-on (ADR 0026 §10 / verification deferral).

**Hot path (NFR-MEM).** The send/receive **buffer is reused in place** (no per-datagram message-sized array).
The residual per-datagram heap is the codec's `→octets` return + the AEAD intermediates (the inherited T4
carry) plus one plain-region `subseq` — measured in `bench/report/2026-06-28-wp-secure-discovery-t10.md`
(ENCRYPT, 256-octet stream: T10-send ≈ T4-encode + ~270 bytes/datagram; T10-recv ≈ T4-decode + ~340
bytes/datagram; OpenSSL-FFI dominates the ~5 µs/op). `make mem` (the gated CDR serialize/deserialize hot
path) stays **0 bytes/sample** — T10 does not touch it. A fully zero-alloc SRTPS path needs an into-buffer
AEAD codec (a `dds.dare`/`dds.security` rewrite) and is the documented follow-on.

**Tests.** `run-rtps-protection-test` (disc-level, deterministic): the SPDP/PSM exemption (NIL dest-prefix
stays plain), engagement (a `:keyed`-dest send is SRTPS on the wire + the payload never in cleartext),
decode+dispatch byte-exact, the **non-vacuous** wrong-ParticipantCrypto drop, and origin-auth (correct
receiver key delivers; the WRONG receiver key, same id, drops though the common_mac is valid). The full
participant e2e is `run-secure-discovery-protected-test` / `-origin-auth-test` (their `:sdp-rtps-wrapped`
assertion proves the Square sample is SRTPS on the wire and B decoded it). `run-rtps-protection-enforce-test`
covers the **receive-side enforcement** for user **DATA** (a forged plain user-DATA spoofing a keyed peer's
prefix is dropped; **non-vacuous**: the same plain user-DATA is delivered when the source is not keyed and when
governance `rtps_protection` is NONE; and plain builtin SPDP metatraffic from the keyed peer is still processed
— no false-REJECT). `run-rtps-protection-enforce-reliability-test` extends that to the user **reliability-control**
submessages: for each of HEARTBEAT / ACKNACK / GAP / HEARTBEAT_FRAG / NACK_FRAG a forged plain submessage
spoofing the keyed peer's prefix is dropped (its user handler never fires → no reliable-state mutation), with
the same two **non-vacuous** controls (delivered from a not-keyed source, and under `rtps_protection` NONE), plus
a **no-false-REJECT** check that a plain builtin SEDP HEARTBEAT from the keyed peer is still processed (routed to
`%on-builtin-heartbeat`, advancing the ack counter, never reaching the user gate). The participant-tier
origin-auth resolvers (`cm-rtps-encode-receivers` /
`cm-rtps-decode-receiver`) are driven directly in `run-security-crypto-manager-test` (a wrong participant
receiver key fails the receiver-MAC though the common_mac is valid). All green SBCL + Clasp.

### 6sexto.6 Secure participant-message (liveliness) + secure SPDP re-announce (T11, §7.4.5 / §8.4.1.6)

The last two secure builtin endpoint tiers, built the SAME way as secure SEDP (§6sexto.9): a plaintext DATA
submessage wrapped in the T2 submessage-protection codec under a per-endpoint **EntityCrypto**, dispatched
inbound by the wire `transformation_key_id`. Both **reuse the generic secure-builtin resolvers** — the
`disc-node-secure-sedp-{encode,decode}-km` / `-{encode-receivers,decode-receiver-km}` closures resolve **any**
registered secure builtin entity by EntityId / key_id, not just SEDP — so the crypto-manager change is just
registering four more EntityCryptos (`%cm-local-token-entities` now exchanges the secure participant-message
writer+reader `0xff0200c2/c7` and the secure SPDP writer+reader `0xff0101c2/c7` alongside the secure SEDP set).

- **Secure participant-message** (Writer Liveliness Protocol, bits 20/21). When governance
  `liveliness_protection_kind ≠ NONE` (`%install-access-control` → `disc-node-secure-pm-protection-kind` +
  `-origin-auth`), `assert-participant-liveliness` routes **every** WLP assertion through
  `%announce-secure-liveliness`: the same `ParticipantMessageData` payload as plain WLP, over the secure
  `BuiltinParticipantMessageSecureWriter` (`0xff0200c2`), submessage-protected per the kind, to the
  `:authenticated` peers **only** — and plain WLP is **fully suppressed** (a confidential liveliness assertion
  never rides plain, mirroring the secure-SEDP off-plain partition). The reader path is the **existing**
  `%on-participant-message`, keyed by the verified datagram source prefix (anti-spoof). A tampered assertion
  fails the MAC and is dropped (never asserts liveliness).
- **Secure SPDP re-announce** (bits 26/27, `DISC_BUILTIN_ENDPOINT_PARTICIPANT_SECURE_*`). The plain SPDP keeps
  bootstrapping (it carries the Identity/Permissions tokens a peer authenticates with); `announce-participant`
  **additionally** calls `%announce-secure-spdp`, which re-announces the same `ParticipantBuiltinTopicData` over
  the secure `SPDPbuiltinParticipantSecureWriter` (`0xff0101c2`) submessage-protected. It rides the **discovery**
  protection tier — gated on `disc-node-discovery-protected-topic-p` (= discovery protection active) and protected
  per `disc-node-secure-sedp-protection-kind` (the same governance `discovery_protection_kind` as secure SEDP) —
  so no separate SPDP protection slot is needed. The reader path is `%record-participant`.
- **SEC_PREFIX disambiguation extended.** The same submessage id (0x31) now carries PVMS (T7), secure SEDP (T9),
  AND secure participant-message + secure SPDP (T11). `%on-secure-submessage` resolves the EntityCrypto by
  `transformation_key_id` (PVMS's all-zero bootstrap key_id never lands in the index → it still falls through to
  the PVMS handler) and hands the bracket to `%on-secure-builtin`, which **decodes once then routes by the
  recovered inner writerId** to SEDP-match / liveliness / record-participant — each verifying its own writerId,
  any other → drop fail-closed.
- **Origin-auth honored for both** (`*_WITH_ORIGIN_AUTHENTICATION`, §9.5.3.3.4.3). The writer→reader pairing
  (`%secure-sedp-reader-for-writer`) and the per-entity receiver-key minting (`%cm-entity-origin-auth`) were
  extended to the PM + SPDP pairs, so the existing receiver-specific-MAC encode/decode resolvers cover all three
  tiers; the PM reader rides the **liveliness** tier flag, the SEDP + SPDP readers the **discovery** tier flag.
- **SPDP advertisement.** `%node-spdp-data` ORs bits 20/21 when `%secure-pm-active-p`, and bits 26/27 (alongside
  the secure SEDP bits 16-19) when discovery protection is active. **Security-OFF is byte-identical**: no
  governance ⇒ no secure bits, plain WLP + plain SPDP exactly as before.

**Tests** (disc-level, deterministic, manually-installed EntityCryptos): `run-secure-participant-message-test`
(SIGN WLP over `0xff0200`, B detects liveliness, a SEC_PREFIX bracket is emitted),
`run-secure-participant-message-tamper-test` (a clean assertion records liveliness — non-vacuous — a
one-octet-flipped copy fails the MAC and is dropped), `run-secure-pm-origin-auth-roundtrip-test` /
`-tamper-test` (correct receiver key detects; the WRONG key, same id, never detects though the common_mac is
valid), and `run-secure-spdp-reannounce-test` (a plain node advertises no bits 26/27 but an armed node does;
plain SPDP still bootstraps; a SEC_PREFIX re-announce is emitted; a FRESH peer that saw no plain SPDP registers
the participant from the protected re-announce alone). All green SBCL + Clasp.

### 6sexto.7 Governance protection-kind model — the knobs (T5, DDS-Security 1.1 §9.4.1.2)

The Slice-3 `governance` struct (§6quinque.3) gains the protection-kind policy that drives every tier above.
Two keyword enums (`dds.security`, `crypto/constants.lisp`), pinned in T0 from `dds_governance.xsd`:

| Constant | Values | Used by |
|---|---|---|
| `+protection-kinds+` | `(:none :sign :encrypt :sign-with-origin-auth :encrypt-with-origin-auth)` — the 5-value `ProtectionKind` | the domain-rule kinds |
| `+basic-protection-kinds+` | `(:none :sign :encrypt)` — the 3-value `BasicProtectionKind` | the per-topic kinds |
| `+protection-kind-xsd-strings+` | keyword ↔ XSD token alist (`:encrypt`↔`ENCRYPT`, `:sign-with-origin-auth`↔`SIGN_WITH_ORIGIN_AUTHENTICATION`, …) | the parser (reverse lookup) |

The struct fields + accessors:

| Field (governance) | Tier | Accessor |
|---|---|---|
| `discovery_protection_kind` (domain rule, `ProtectionKind`) | secure SEDP + secure SPDP | `governance-discovery-protection` |
| `liveliness_protection_kind` (domain rule, `ProtectionKind`) | secure participant-message (WLP) | `governance-liveliness-protection` |
| `rtps_protection_kind` (domain rule, `ProtectionKind`) | whole-RTPS user data plane | `governance-rtps-protection` |
| `enable_discovery_protection` / `enable_liveliness_protection` (topic rule, bool) | per-topic gate | `topic-discovery-protected-p` |
| `metadata_protection_kind` / `data_protection_kind` (topic rule, `BasicProtectionKind`) | per-topic submessage / payload | `topic-metadata-protection` / `topic-data-protection` (participant default `governance-effective-{metadata,data}-protection`; per-topic refine `%refine-user-protection`) |

`protection-kind-base (kind) → (values base origin-auth-p)` maps a `ProtectionKind` to its base
(`:sign` | `:encrypt`) + an origin-auth flag, so the announce/encode paths honour SIGN vs ENCRYPT vs
origin-auth **from governance** (never hard-coded — the T9 fix).

**Per-topic selectivity — fail-closed participant default + per-topic refine (both `metadata_protection` and
`data_protection`).**  `metadata_protection` (the user-DATA submessage tier, `user-submessage-protection-kind`)
and `data_protection` (the serialized-payload tier, `user-data-protection-kind`) are resolved per-topic. At
`create-participant`, `%install-access-control` stamps the participant-level default to the **MOST-PROTECTIVE**
kind over ALL topic rules — `governance-effective-metadata-protection` / `governance-effective-data-protection`
(both `%governance-effective-basic-protection`, max `:encrypt > :sign > :none`) — a **fail-closed fallback** so a
first-rule `NONE` can never downgrade below a later protected rule (no false-ACCEPT). It also installs the
per-topic resolvers (`disc-node-topic-{metadata,data}-protection-resolver`); every `add-local-{writer,reader}`
then calls `%refine-user-protection`, which resolves the endpoint's ACTUAL per-topic kind
(`topic-metadata-protection` / `topic-data-protection`), so a genuine `metadata`/`data=NONE` topic stays `NONE`
(no false-REJECT). No governance → resolvers NIL, slots at default → byte-identical to the pre-security path.

**Fail-closed parse (the T5 review-caught Critical).** The protection-kind elements are **REQUIRED** by the
XSD and Fast DDS REJECTS them absent, so `%ac-node-protection-kind` returns NIL on a missing element →
`parse-governance` aborts to NIL (it does **not** substitute a default).  A valid-but-wrong-tier token (e.g. a
5-value `SIGN_WITH_ORIGIN_AUTHENTICATION` in a 3-value per-topic field) also aborts to NIL.  The struct
initforms are **constructor defaults, NOT spec defaults** (so documented).  Worked governance excerpt:

```xml
<domain_rule>
  <domains><id>0</id></domains>
  <discovery_protection_kind>ENCRYPT</discovery_protection_kind>
  <liveliness_protection_kind>SIGN</liveliness_protection_kind>
  <rtps_protection_kind>ENCRYPT</rtps_protection_kind>
  <topic_access_rules><topic_rule>
    <topic_expression>Square</topic_expression>
    <enable_discovery_protection>true</enable_discovery_protection>
    <metadata_protection_kind>ENCRYPT</metadata_protection_kind>
    <data_protection_kind>ENCRYPT</data_protection_kind>
  </topic_rule></topic_access_rules>
</domain_rule>
```

(`governance-none.{xml,p7s}` in `interop/security-secure-discovery/pki/` is the NONE/NONE/NONE baseline — the
security-OFF byte-identical guard.)

### 6sexto.8 The crypto-manager + crypto-token exchange + `:keyed` promotion (T6, T8)

`src/dds-dcps/crypto-manager.lisp` is the Cryptographic-plugin analogue of the Slice-2 `auth-manager`.  It
owns four registries behind one manager lock and an O(1) `transformation_key_id` → KeyMaterial index:

- **ParticipantCrypto** — the local participant's master KeyMaterial (for `rtps_protection`) + per matched
  remote the remote's ParticipantCrypto KeyMaterial (keyed by 12-octet GUID prefix).
- **EntityCrypto** — one KeyMaterial per local secure builtin endpoint + per matched-remote endpoint.

Four resolvers (every miss → NIL, fail-closed):

| Resolver | Direction | Used by |
|---|---|---|
| `cm-encode-participant-km` | LOCAL, for an outgoing datagram | rtps_protection encode (T10) |
| `cm-decode-participant-km` | REMOTE, by source GUID-prefix | rtps_protection decode (T10) |
| `cm-encode-entity-km` | LOCAL, by entity-id | secure SEDP / PM / SPDP encode (T9, T11) |
| `cm-decode-entity-km-by-key-id` | REMOTE, by the wire `transformation_key_id` | secure SEDP / PM / SPDP decode (T9, T11) |

`generate-key-material` mints a fresh §9.5.2 KeyMaterial (random `master_salt` + `master_sender_key` + a
NON-ZERO `sender_key_id`); with `:origin-auth t` it also mints a random NON-ZERO `receiver_specific_key_id`
(resample-if-zero — zero is the spec "origin-auth disabled" sentinel) + `master_receiver_specific_key`
(§6sexto.4).  `generate-writer-key-material` delegates to it (DRY).

**The `:authenticated → :keyed` promotion.**  At `:authenticated`, `cm-on-authenticated` registers the local
ParticipantCrypto + builtin EntityCryptos and sends the Participant / DataWriter / DataReader crypto tokens
over **reliable PVMS** (§6sexto.3) — replacing Slice-2c's interim best-effort PSM path.  KEYX's per-writer
KeyMaterial was migrated PSM → PVMS (under `dds.sec.datawriter_crypto_tokens`); PSM is now handshake-only.
`cm-on-crypto-token` installs each remote token; `%cm-try-promote` advances `auth-remote` to `:keyed` **only**
when the ParticipantCrypto + the secure-SEDP pub-W + the secure-SEDP sub-R are all installed.  Adding the four
PM/SPDP tokens to the local token set does **not** widen that precondition, so keying never hangs against a
liveliness-unprotected peer.  The crypto-token DataHolders ride as plaintext inside the PVMS-protected
submessages; a malformed token drops, no promote (fail-closed).

**Nonce disjointness (the T8 crux).**  The PVMS bootstrap KM is symmetric and the codec's non-PVMS tiers use a
fixed `session_id`, so a bidirectional exchange would reuse AES-GCM nonces.  `%pvms-role-session-id` gives each
role a distinct non-zero `session_id` (winner = lexicographically-greater GUID prefix → `base-1`, loser →
`base`; `base = #x80000000 | fold(winner)`) → distinct keys **and** disjoint nonce spaces both directions; an
on-wire guard parses the actual encoded `session_id` so a revert fails loudly.  `run-secure-discovery-keyed-test`
asserts the two roles' `session_id`s DIFFER and are non-zero.

### 6sexto.9 Secure SEDP wiring + the worked secure-discovery example (T9)

This is the headline of the slice: protected topics are discovered **only** over the secure SEDP endpoints
(publications writer `0xff0003c2` / reader `0xff0003c7`, subscriptions `0xff0004c2` / `0xff0004c7`), never over
plain SEDP — otherwise an outsider reads the topology.

**Cross-layer wiring (the closure pattern; `dds-disc` stays crypto-free).**  The crypto-manager + access-control
install closures onto the `disc-node`: encode = the LOCAL EntityCrypto by entity-id; decode = the REMOTE
EntityCrypto by the wire `transformation_key_id`; a governance-gated protected-topic predicate
(`topic-discovery-protected-p`).  `dds-disc` calls the installed closures and never imports `dds-dcps`.

- **`announce-endpoints` partitions** by `topic-discovery-protected-p`: a protected topic's `DiscoveredWriter/
  ReaderData` flows ONLY over secure SEDP, submessage-protected (per `discovery_protection_kind` via
  `protection-kind-base`), to the `:authenticated` peers — and is left OFF plain SEDP.  The SPDP
  `BuiltinEndpointSet` carries bits 16-19 only when discovery is protected.  Matching is gated on `:keyed`;
  every decode is fail-closed.
- **SIGN vs ENCRYPT honoured from governance.**  Under `SIGN` the topic is visible inside the SEC_BODY bracket
  (authenticity only); under `ENCRYPT` it is ciphertext.  The decode side is kind-agnostic (it reads the wire
  `transformation_kind`).
- **SEC_PREFIX disambiguation** (§6sexto.6): the single 0x31 id is resolved by `transformation_key_id` — the
  PVMS bootstrap key's all-zero `sender_key_id` falls through to PVMS; a non-zero id in the index routes to the
  secure-builtin handler, which decodes once then routes by the recovered inner `writerId`.

A worked end-to-end secure-discovery example (our-to-our, ENCRYPT discovery + RTPS protection):

```lisp
;;; Each participant: a Slice-2 identity + a signed Governance whose domain rule sets
;;; discovery_protection_kind=ENCRYPT, rtps_protection_kind=ENCRYPT, and enable_discovery_protection
;;; on the protected topic (see §6sexto.7).  validate-local-permissions returns the access-handle.
(let ((p-a (dds.dcps:create-participant :domain 0 :identity id-a))
      (p-b (dds.dcps:create-participant :domain 0 :identity id-b)))
  (dds.dcps::%install-access-control p-a ah-a)   ; governance -> disc-node protection-kind slots
  (dds.dcps::%install-access-control p-b ah-b)   ; + the crypto-manager mints/installs the closures
  (dds.disc:add-peer (dp-node p-a) "127.0.0.1")
  (dds.disc:add-peer (dp-node p-b) "127.0.0.1")

  ;; 1. plain SPDP bootstraps -> §8.7 PKI-DH over plain PSM -> :authenticated
  ;; 2. crypto tokens exchanged over RELIABLE PVMS -> both reach auth-remote :keyed (§6sexto.8)
  ;; 3. the protected topic is announced ONLY over secure SEDP (0xff0003/0xff0004), ENCRYPT-wrapped
  ;; 4. endpoints match (gated on :keyed); user data flows whole-RTPS-wrapped (SRTPS, §6sexto.5)
  (loop repeat 300 until (both-keyed-p p-a p-b) do (sleep 0.02))

  ;; 5. Publish "Square" from A; B receives the plaintext; the topic name is NEVER in cleartext
  ;;    on the wire (secure SEDP is ENCRYPT) and the user datagram is SRTPS-wrapped.
  (dds.disc:publish-sample (dp-node p-a) #(#x53 #x71 #x75 #x61 #x72 #x65)) ; "Square"
  ;; ... poll for receipt on p-b, assert received = plaintext ...
  (dds.dcps:delete-participant p-a)
  (dds.dcps:delete-participant p-b))
```

`run-secure-discovery-protected-test` is the full participant e2e (ENCRYPT): two participants reach `:keyed`,
the protected topic matches over secure SEDP, the Square sample crosses SRTPS-wrapped and is decoded byte-exact
at B, the topic name is asserted **absent** from the cleartext, and a plain peer is refused **non-vacuously**.
`run-secure-discovery-origin-auth-test` is the `ENCRYPT_WITH_ORIGIN_AUTHENTICATION` variant (§6sexto.4).

**Honest cross-vendor posture.**  The above is our-to-our complete.  Cross-vendor against a live Fast DDS peer
(Slice-5 campaign), the path now reaches **`:keyed` BOTH directions**: the §8.7 PKI-DH handshake COMPLETES,
permissions VALIDATE (c.perm = the S/MIME credential), and the §8.5.2 PVMS ParticipantCryptoToken exchange
COMPLETES — our side promotes to `:keyed` and Fast DDS's reliable PVMS reader acks all our tokens.  The two
final PVMS divergences reconciled (T7-PVMS): the KeyMaterial CDR parser now accepts `transformation_kind`
AES256_GMAC `{0,0,0,3}` (Fast DDS's ParticipantKeyMaterial uses it; §9.5.2.1.1 Table 70 — our whitelist had
omitted it), and the PVMS HEARTBEAT/ACKNACK are now submessage-ENCRYPT-protected (Fast DDS protects ALL
submessages on a protected endpoint and drops clear ones; `%on-volatile-secure` demuxes the decoded inner
DATA/HEARTBEAT/ACKNACK).  **Not yet** cross-vendor protected DATA: the residual blocker is the user-endpoint
SEDP match (Fast DDS does not initiate the plain-SEDP/EDP exchange with us post-keying — a SEDP-layer issue
distinct from the PVMS exchange).  Live RTI Connext is static only (Slice-5b exit gate).  See the
"Cross-vendor secure-discovery interop status" section below, ADR 0036 (the numbered Slice-5 carries),
`docs/provenance.md` (T7-PVMS), and `interop/security-secure-discovery/README.md`.

---

## 7. Roadmap (M7/P6)

| Slice | Description | Status |
|---|---|---|
| **1** | Crypto plugin: AES256-GCM `SecuredPayload` + session-key KDF + `disc-node` integration (ADR 0031) | **LANDED** |
| **2a** | Authentication plugin: PKI identity + §8.7.2.4 PKI-DH handshake → SharedSecret, both §9.3 suites, our-to-our (ADR 0032) | **LANDED** |
| **2b-i** | Wire transport: SPDP IdentityToken + PSM endpoints + DataHolder/envelope codec + our-to-our handshake over UDP (ADR 0033) | **LANDED** |
| **2b-ii** | Discovery integration: on-participant-discovered hook + auth manager (`%install-auth-manager`) + per-participant `dp-auth-state` + strict endpoint-match auth-gate + `select-suite-for-identities` (ADR 0034 at capstone) | **LANDED** |
| **2c** | Crypto key-exchange: §9.5.3 KxKey + §9.5.2 per-writer KeyMaterial exchanged over PSM, installed per remote (ADR 0034 at capstone) | **LANDED** |
| **3** | AccessControl plugin (§8.4 / §9.4): CMS-verify signed Governance + Permissions, topic-level allow/deny at all three §8.4 check points, our-to-our (ADR 0035) | **LANDED** |
| **4** | Secure discovery (§7.3.7 / §8.5): submessage + whole-RTPS protection, origin-auth, reliable PVMS, governance protection-kinds, secure builtin endpoints — **our-to-our complete**; live Fast DDS = bidirectional SPDP discovery + 4 conformant fixes (auth blocked at the propagate-byte divergence) (ADR 0036) | **LANDED** |
| 5 | Cross-vendor `auth → keyed → data` — the slice-wide propagate-byte fix + the downstream divergences; **live Fast DDS-Security protected user DATA both directions COMPLETE** (WP-DDS-SECURITY-FASTDDS-INTEROP, ADR 0037) | **LANDED** |
| **5b** | **Live RTI Connext 7.3.1 both directions** — the §8.7.2.3 AuthRequestMessageToken sub-protocol (challenge-binding) + §7.4.3.3 monotonic PSM `sequence_number` unblock the full-participant handshake; protected user DATA flows BOTH ways ours↔live Connext (the P6 exit gate) (ADR 0040) | **LANDED — DoD reached 2026-07-02** |

## Cross-vendor secure-discovery interop status (Slice 4 T12, live Fast DDS-Security)

A SECURITY=ON Fast DDS v3.6.1 peer was built and run live against our stack (`interop/security-secure-discovery/README.md`).
**Achieved cross-vendor:** the SECURITY=ON build, bidirectional SPDP discovery, and Fast DDS full init against
this repo's reused PKI. Four wire/config divergences were fixed conformantly (our-to-our green, both impls):
the PSM SerializedPayload encapsulation header (RTPS 2.5 §10.2), the governance `<domain_access_rules>` root
(dropped the non-conformant `<policies>` wrapper), serialization-insensitive subject-DN matching, and the Fast
DDS multipart/signed S/MIME container.

New API from this work:
- **`dds.security:permissions-grant-for (subject grants)`** — the single subject-binding site for local + remote
  permissions, matching by `%dn-equal` (OpenSSL-oneline vs RFC2253 serialization-insensitive; DDS-Security
  §9.4.1.3), so cross-vendor DN forms interoperate without false-REJECT. `%dn-normalize` is RFC2253 §2-3 aware:
  it splits RDNs only on UNESCAPED separators, un-escapes values (`\c` + `\XX` hex) to canonical form, upcases the
  attribute TYPE (case-insensitive) while keeping the VALUE case-sensitive, and FAIL-CLOSES to `:malformed` on any
  malformed RDN (no unescaped `=`, empty type, bad escape) — an ambiguous/malformed DN NEVER authorizes, not even
  against an identical malformed grant (no false-ACCEPT). Regression-covered by `run-security-dn-match-test`.
- **`dds.dcps:create-participant :port`** — bind+advertise a fixed metatraffic unicast port so a foreign peer
  can `initialPeers` us over loopback (the macOS multi-NIC cross-vendor reachability pattern).

**Primary residual (handshake blocker, Slice 5 / dedicated WP):** our Token `Property`/`BinaryProperty` codec
serializes a 4-octet `propagate` field per property that Fast DDS does NOT put on the wire (`propagate` is a
local include-filter) — misaligning every cross-vendor token, so the §8.7 auth handshake is REJECTED at the
remote IdentityToken. The conformant fix (drop the propagate field + regenerate the token byte-exact corpus) is
slice-wide. The downstream candidates (session_id base, GMAC AAD span, SIGN 4-alignment, reliable-pull,
metatraffic rtps-wrapping) sit behind the handshake and remain Slice-5 carries.

## Cross-vendor secure-discovery interop status (Slice 5, live Fast DDS-Security — through T10)

The dedicated WP-DDS-SECURITY-FASTDDS-INTEROP campaign (T0–T10) carried the cross-vendor path well past the
Slice-4 handshake blocker. The §8.7 PKI-DH handshake now **succeeds** against the live SECURITY=ON Fast DDS
v3.6.1 peer (the propagate-field + credential + dh-point + c.perm S/MIME reconciliations, T2–T6), the reliable
PVMS crypto-token exchange completes, secure SEDP delivers the protected DiscoveredWriter/ReaderData, and the
user endpoints **match both directions** keyed (T7–T9). T10 adds the user-DATA protection tier:

- **Slice-1 serialized-payload AAD reconciled to EMPTY** (Fast-DDS-faithful; ADR 0031 addendum). Shipped-tier
  wire change: GCM **tag** bytes differ, serialized fields byte-identical; integrity via `find_key` + nonce.
- **KeyMaterial advertised kind** GMAC `{0,0,0,3}` (SIGN) vs GCM `{0,0,0,4}` (ENCRYPT) — a peer's `find_key`
  matches on `transformation_kind` AND `sender_key_id`, so the advertised kind must equal the tier's wire kind.
- **User-DATA submessage protection (metadata_protection, §8.5.1.7-.9)** — when governance
  `metadata_protection_kind != NONE`, each user-plane submessage is individually SEC_PREFIX…SEC_POSTFIX-wrapped
  under the local user endpoint's EntityCrypto (writer DATA/HEARTBEAT/GAP; reader ACKNACK), INSIDE the
  rtps_protection SRTPS wrap. The §8.3.4 4-octet alignment lives in the **SEC_BODY CryptoContent container**
  (pad after the ciphertext, `octetsToNextHeader = (|ct|+4+3)&~3`, Fast DDS `serialize_SecureDataBody`) — the
  plaintext is NEVER padded, so the recovered submessage reflects its TRUE length and a data_protection payload
  round-trips (T10 review). New `dds.disc` `disc-node` slots: `disc-node-user-submessage-protection-kind` /
  `-encode` / `-decode`; receive routes a USER-key_id SEC_PREFIX bracket to `%on-user-secure-submessage`,
  decode-and-re-dispatch, fail-closed. Under a required `rtps_protection`, a BARE (non-SRTPS-wrapped) user
  bracket is DROPPED (§8.5.1.10-.12 enforcement); the legitimate post-SRTPS re-dispatch is delivered.

**Live result (`run-fastdds-interop.sh secure 45`, GOV=secure): PROTECTED USER DATA flows BOTH directions** (the
Slice-5 DoD). ours2fast — Fast DDS RECEIVED 8/8 of our rtps+metadata+data-protected `HelloWorld` (`'Hello world
from Lisp' index 0..7 RECEIVED`); fast2ours — our subscriber decodes 88 of Fast DDS's protected user DATA.
Closing the reverse direction (T11reverse) took two conformant reconciliations in dependency order:

- **data-representation QoS at the match (upstream of all crypto).** Fast DDS's `@extensibility(APPENDABLE)`
  HelloWorld DataReader runs the default DataReaderQos = empty DATA_REPRESENTATION = XCDR1; an XCDR2-only writer
  is INCOMPATIBLE (DDS-XTypes 1.3 Table 7.57, `EDP::checkDataRepresentationQos`), so Fast DDS rejected our writer
  in `valid_matching` BEFORE any crypto — the persistent `No key material yet → lookup_reader` warnings were
  benign builtin noise (present identically in the working fast2ours direction). The interop peer's user writer
  now offers XCDR1 (PLAIN_CDR), the symmetric resolution Fast DDS needs (harness-only; our XCDR2 default is
  per-spec, unchanged).
- **data_protection SecureDataTag 4-byte alignment.** Fast DDS `serialize_SecureDataTag` aligns the
  `receiver_specific_macs` count to 4 relative to the SecuredPayload start (after the common_mac), so a
  SecuredPayload is always 4-aligned; our serializer omitted the pad and a non-4-aligned ciphertext made Fast DDS
  `decode_serialized_payload` mis-read the tag length. `serialize/parse-crypto-footer` +
  `serialize/parse-secured-payload` now `align` the count to 4 — a NO-OP for the submessage/whole-RTPS brackets
  (already 4-aligned) and the secured-payload corpus (byte-exact, unchanged), adding the pad only for a bare
  SecuredPayload with non-4-aligned ciphertext.

**Live Connext-Security remains the Slice-5b P6 exit gate** (RTI Security Plugins absent). Captures + honest
writeup: `interop/security-secure-discovery/captures/` (`T11reverse-RESULT.md`).

## Cross-vendor Connext-Security interop status (Slice 5b — live RTI Connext 7.3.1, DoD REACHED 2026-07-02; ADR 0040)

**Protected user DATA now flows BOTH directions ours↔live RTI Connext 7.3.1** (GOV=secure, all-ENCRYPT), the
P6 exit gate. The forward direction (ours→Connext) was already live-verified in Phase 4 (Connext decodes 8/8 of
our AEAD-protected `HelloWorld`). The reverse direction (a FULL Connext participant → ours) was blocked at the
§8.7 PKI-DH handshake by a spec-optional sub-protocol a full participant (unlike `rtiddsspy`) requires — now
implemented conformantly:

- **§8.7.2.3 AuthRequestMessageToken (challenge-binding / anti-replay).** On discovering a secured remote, a
  participant mints a 256-bit `future_challenge` nonce (once per remote, stable) and sends it in an
  AuthRequestMessageToken (`message_class_id` `dds.sec.auth_request`, DataHolder `class_id`
  `DDS:Auth:PKI-DH:1.0+AuthReq`, binary property `future_challenge`). It then PRECOMMITS its handshake
  challenge to that nonce byte-for-byte: the requester's `challenge1` == its own `future_challenge`; the
  replier's `challenge2` == its own `future_challenge`. A full replier VERIFIES the request's `challenge1` ==
  the requester's advertised `future_challenge` (and, as requester, the reply's `challenge2` == the replier's)
  — a mismatch is a replayed/forged handshake and is REJECTED fail-closed (`equalp`, no hashing; the
  OpenDDS/OMG `challenges_match` `memcmp`). The sub-protocol is **§8.7.2.3-OPTIONAL**: a peer that sends no
  auth_request (Fast DDS v3.6.1) leaves the expected nonce NIL and the binding check is SKIPPED — absence must
  NOT false-reject a conformant peer, but PRESENCE (Connext) is honored and bound. Derived clean-room from the
  OMG clauses + OpenDDS `AuthenticationBuiltInImpl.cpp` (no RTI source read; `docs/provenance.md`).
- **§7.4.3.3 monotonic PSM `message_identity.sequence_number`.** Was hardcoded `0` (a §7.4.3.3 violation) — a
  strict Connext stateless reader deduped our retransmits. Now one monotonic per-participant counter shared
  across the auth_request + all three handshake tokens (`source_guid` = the participant GUID; first value 1).

**Live result (`interop/security-connext/run-connext-interop.sh secure 20`, repeatable):**
- **reverse (Connext=publisher → ours=subscriber):** ours `keyed=T matched=1 samples>0` decoding Connext's
  GOV=secure AEAD `HelloWorld` content (`"Hello world from Connext"`), `RESULT: PASS` — no post-auth
  reconciliation was needed (session_id/AAD/KeyMaterial/secure-SEDP/SRTPS all decoded cleanly once the handshake
  completed; the spec-faithful `future_challenge` property name is exactly what Connext reads).
- **forward (ours→Connext):** still 8/8 — `rtiddsspy` logs 8× `New data … topic="HelloWorldTopic"`; the residual
  `DecryptFinal` errors are the benign participant-metatraffic (`0x000001C1`), not the user-data topic.

**Regression:** ours↔ours (auth/handshake/keyx + secure-SEDP + PVMS + access-manager) green on **both** SBCL and
Clasp; the byte-exact token/handshake/crypto corpora + KATs are UNCHANGED (this is a protocol-flow addition, no
emitted codec changed). ours↔Fast-DDS: GOV=secure protected user DATA still flows BOTH directions; the
handshake still reaches `:keyed` (Fast DDS silently discards our unknown `dds.sec.auth_request`, verified
against `SecurityManager.cpp`), byte-identical to the pre-WP baseline. The live decode is the oracle (tshark
cannot dissect the macOS `lo0` NULL link layer). Captures: `interop/security-connext/captures/`.

### Slice-5b follow-ons (WP-SLICE5B-FOLLOWONS B1/B2/B3, 2026-07-03; ADR 0040 / 0037)

- **B1 — GOV=none reverse now LIVE-covered.** `run-connext-interop.sh none 20` connext2ours (Connext full
  publisher → ours=sub) reports `discovered=1 matched=1 samples=38 decoded=38 RESULT: PASS`, decoding Connext's
  GOV=none (plain, authenticated+authorized) `HelloWorld` (`"Hello world from Connext"`), state `AUTHENTICATED`.
  `ever-keyed=NIL` is CORRECT at GOV=none: the endpoint match fires at `:authenticated` because
  `governance-any-protection-p` is NIL and Connext exchanges no ParticipantCryptoToken (§8.4.2.9 — keying is a
  precondition only for PROTECTED endpoints). No GOV=none-specific reverse divergence; no reconciliation needed.
  GOV=none is now complete both directions (ADR 0040 carry #1 resolved).
- **B2 — forged-`auth_request` availability hardening.** The `future_challenge` binding rides the UNAUTHENTICATED
  ParticipantStatelessMessage channel, so a forged `dds.sec.auth_request` could poison the stored nonce and
  false-REJECT a legitimate peer (an availability DoS). Two fail-closed guards in `src/dds-dcps/auth-manager.lisp`
  close it with NO false-ACCEPT: (a) the stored remote `future_challenge` is **LATCHED first-write-wins** per
  remote (`%am-store-remote-future-challenge`) — a legit peer's nonce is stable across retransmits, and a later
  CONFLICTING auth_request is IGNORED (closes the forged-LATER-overwrite variant); (b) at the bind site
  (`%am-effective-expected-challenge`) a stored nonce that MISMATCHES the handshake challenge **DOWNGRADES to
  Sign-only** instead of hard-REJECT (closes the forged-FIRST variant), so a forged auth_request never
  false-rejects a legit peer. The strict handshake-API binding is UNCHANGED (still fail-closed on a supplied
  mismatch); the un-poisonable challenge ECHO checks + §8.7 cert-chain + Sign1/Sign2 still fully decide, so the
  downgrade only ever falls back to the same absence path a spec-literal Fast DDS peer already takes — never a
  false-ACCEPT. Proven by `run-auth-forged-request-hardening-test` (both impls): inject a spurious auth_request
  then a legit handshake → STILL `:authenticated`; the strict API with the poisoned nonce still rejects. The
  live ours↔Connext GOV=secure both-directions handshake still completes after the change (ADR 0040 carry #2).
- **B3 — ADR-0037 residual carries status-reconciled vs Connext.** See the reconciliation table in ADR 0037:
  live-Connext, Zero-Copy×`rtps_protection` SHMEM cleartext, KeyMaterial master slots → foreign/static, and the
  zero-alloc-AEAD send path are RESOLVED; builtin-endpoint keying vs Connext is VALIDATED by the live interop;
  the SIGN-tier GMAC AAD span (live gate was all-ENCRYPT) is RESOLVED (Slice 5c). **WP-SECURITY-CARRIES-BATCH
  (2026-07-03) closed the 0xC2→0xC7 DRY** (one shared `dds.rtps.discovery:builtin-complementary-eid` +
  `secure-builtin-writer-eid-p`, byte-identical), metadata_protection per-topic selectivity, the
  `%on-secure-builtin` inner-writerId cross-check, the `all-kms`/PVMS peer-loss prune, the
  secure-builtin-ACKNACK count unit test (`run-secure-builtin-acknack-count-test`), and the `%dn-normalize` /
  `%dn-equal` RFC2253 §2-3 subject-name edges (unescaped-separator split + value un-escape + fail-closed on
  malformed, `run-security-dn-match-test`). All ADR-0037/0040 residual carries are now closed.
