# ADR 0050 — Durability MICROSERVICE persistence backend (a durable-store proxied over TCP)

Status: Accepted
Date: 2026-07-07
Work package: WP-DURABILITY-MICROSERVICE-1 (Slice 1) + WP-DURABILITY-MICROSERVICE-2 (Slice 2 — DARE-wrap) + WP-DURABILITY-MICROSERVICE-3A (Slice 3a — server-owned persistent inner + cross-restart + config-env seam) + WP-DURABILITY-MICROSERVICE-3B (Slice 3b — client-side remote-tier chain-MAC) + WP-DURABILITY-TAIL-ANCHOR-MS (sealed high-water tail anchor) + WP-DURABILITY-MS-RECLAIM-REMAC (Slice 3d — KEEP_LAST reclaim re-MAC over the wire, §4.4) + WP-DURABILITY-MS-RECONNECT (Slice 3c-1 — bounded client reconnect + idempotent retry, §4.5; HISTORY-QoS-over-the-wire descope, §4.2/§7) + WP-DURABILITY-MS-DOS (Slice 3c-2 — server DoS-hardening: read/idle timeout, incremental body allocation, accept-loop backoff, §4.6) + WP-DURABILITY-MS-MULTICLIENT (Slice 3c-3 — server multi-client concurrency: per-connection serve threads, a lock-guarded connection registry + a max-connections cap, and an ATOMIC memory `store-replace-topic`, §4.7) (ADR 0021 capability 6 — the last of the owner's pluggable persistence tiers: file / db / MICROSERVICE — composed with capability 7, the always-on DARE)
Relates to: ADR 0021 (pluggable persistence vtable), ADR 0026 (file store, DARE at-rest), ADR 0045 (log-MAC chain), ADR 0049 (SQLite backend — the sibling "second implementation of the fixed vtable")

## 1. Context

The durability service carries pluggable persistence behind ONE abstraction — the **`durable-store`
vtable** (`src/dds-durability/store.lisp:18-35`), a `defstruct` of function slots (`put`, `get-range`,
`topics`, `purge`, `open`, `close`, `count-fn`, `sync`, `set-chain-mac-fn`, `delete`) with public
dispatch functions (`store-put` … `store-delete`). Three backends already fill it: memory, an
append-log-per-topic file store, and SQLite (ADR 0049). ADR 0021 names a fourth owner-mandated tier —
a **microservice** backend — the last unbuilt of the seven durability capabilities.

A microservice backend means the durable-store's records live in a **separate process** reached over a
network transport, so persistence can be centralised, shared, or independently operated. The vtable is
already the right seam: a client store fills every slot by **remoting** the call, and the server is any
process that speaks the wire protocol and holds an inner durable-store.

## 2. Decision

Add a **client** `make-microservice-store` (fills the vtable by proxying each op over ONE TCP
connection) and a **reference server** `make-microservice-server` (accepts connections and dispatches
each decoded op to an inner durable-store — memory in this slice). The `durable-store` struct and its
dispatch contracts are **NOT touched**: the microservice-store IS a drop-in durable-store, exactly like
the file and SQLite backends.

This ADR records **Slice 1** — the thinnest demonstrable end-to-end vertical slice (operating contract:
vertical-slice-driven). Scope and the deferred slices are in §7.

### 2.1 PAL TCP primitives (the enabler)

There was no TCP in the stack (only UDP). Slice 1 adds native **TCPv4 stream** sockets to the PAL
(`dds.pal:tcp-connect / tcp-listen / tcp-accept / tcp-local-port / tcp-send / tcp-recv / tcp-close`),
built on the **same `sb-bsd-sockets` substrate** as the existing UDP primitives (native on SBCL contrib
+ Clasp bundled — **no new dependency, no usocket**). Two loops are load-bearing because a stream is a
byte pipe, not message-framed:

- **`tcp-send`** loops over short writes until all `len` octets are accepted (a stream socket may
  accept fewer than requested).
- **`tcp-recv`** loops over partial reads until `len` octets are assembled (one frame may split across
  many TCP segments; a partial read is normal, **not** end-of-stream). It returns `NIL` on
  EOF / peer-close / connection-reset before `len` bytes arrive — the single uniform "connection gone"
  signal. `socket-receive` / `socket-send` write/read at `buffer[0]` with no offset argument (verified
  on both impls), so the destination offset is honoured in Lisp (a `subseq` on send, a scratch+`replace`
  on a genuine split — the common single-read case allocates nothing extra).

**SIGPIPE:** on Darwin each stream socket sets `SO_NOSIGPIPE`, so a write to a dead peer returns EPIPE
(a catchable `SOCKET-ERROR`) rather than raising SIGPIPE. This also keeps **Clasp off its
signal→CLOS-condition path** (the known Clasp multithreaded-signal fragility), so BOTH impls take the
identical clean EPIPE→SOCKET-ERROR path on a torn connection. Linux runtimes ignore SIGPIPE
process-wide already, so the option is Darwin-only (an OS reader conditional, permitted inside
`dds-pal/`, mirroring the existing UDP socket-option block).

### 2.2 The wire protocol

A minimal length-prefixed request/response over the single stream (all integers little-endian):

```
REQUEST:  u32 body-len | u8 op-code | op-payload      (body-len = |op-code| + |op-payload|)
RESPONSE: u32 body-len | u8 status  | resp-payload     (status 0 = ok; body-len = |status| + |payload|)
```

Op-codes: `put`=1, `get-range`=2, `topics`=3, `purge`=4, `count`=5, `open`=6, `close`=7, `delete`=9.
A topic is `[u16 len | UTF-8 bytes]`; a record is `[u32 frame-len | frame bytes]`.

**The record wire encoding REUSES the file-store frame format verbatim** — `%frame-record` /
`%frame-record-versioned` to serialize and `%parse-frame` to deserialize (`store-file.lisp:224-385`).
No new record format is invented. The v2 frame omits the topic (it is a file-store basename), so the
topic travels as a separate `u16`-length UTF-8 field (`%string->utf8` + a bounds-checked inverse
decoder). The little-endian integer helpers (`%put-u32-le` / `%get-u32-le` / `%get-u64-le`) and the
kind codec (`%kind->int` / `%int->kind`) are the file store's, reused (DRY).

### 2.3 The opaque-proxy server

`make-microservice-server` binds `HOST:PORT` (port 0 → ephemeral; read the assigned port with
`microservice-server-port`), spawns one accept/serve thread (`dds.pal:spawn`), and serves one client at
a time inline: read a request → decode → **dispatch to the inner store's public dispatcher**
(`store-put` … `store-delete`) → encode the response → send. The server is a **DUMB opaque proxy** — it
understands NO DARE/MAC; it just relays the vtable op to its inner store. `microservice-server-stop`
sets a stop flag, **closes the in-flight connection** (unblocking a serve thread parked in `recv`),
makes a throwaway **self-connection** (unblocking a serve thread parked in `accept` — closing the
listener alone does not portably unblock `accept`), joins the thread, and closes the listener + inner
store. Clean start→stop: no thread leak, no lingering socket.

## 3. Bounds-checking (NFR-SEC-POSTURE, operating contract §4)

Both peers decode network bytes (the server decodes requests, the client decodes responses), so every
length and count is validated against the buffer extent **before** it is trusted. A bounded `ms-reader`
cursor (`buf`/`pos`/`end`) checks it has the bytes before each read and signals
`microservice-protocol-error` on overrun rather than indexing out of bounds; the declared body-length is
refused against a `+ms-max-message+` cap (256 MiB) **before** any buffer is allocated (resource guard);
record/topic counts are bounded against the remaining buffer so a corrupt count cannot spin; each
embedded frame is bracketed by a transport `frame-len` and then re-validated by `%parse-frame`'s own
`:short`/`:corrupt` guards. **The topic UTF-8 field is well-formedness-validated** (`%ms-utf8->string`
enforces the Unicode Table 3-7 / RFC 3629 §4 byte ranges — rejecting standalone/over-range continuation
bytes, overlong encodings, surrogates `#xD800-#xDFFF`, and scalars `> #x10FFFF`) **before `code-char`**,
so a malformed topic raises `microservice-protocol-error` rather than an uncaught `TYPE-ERROR` from an
out-of-range `code-char` (the fuzz gate found this: a lead byte `>= #xF5` had assembled a scalar past
`#x10FFFF`). **Defense in depth:** `%ms-serve-connection` wraps the whole per-connection loop in a
`serious-condition` backstop, so ANY per-connection fault (a decode error, a torn send) drops THAT
connection and the accept loop keeps accepting — a single malformed message can never kill the serve
thread or wedge the listener. On the client side a malformed *response* is re-signalled as
`microservice-store-error` (one clean client-facing error type). So a malformed message can only raise a
clean, caught condition — never an OOB access, an uncaught `TYPE-ERROR`, a crash, or a hang. The
fuzz/survival gate proves it: a battery of malformed-UTF-8 topics drop their connections and the server
survives (a subsequent valid client round-trips); the torn-read gate proves peer-close → `tcp-recv NIL`
→ clean client failure.

## 4. DARE composition (memory-tier slot parity)

`make-microservice-store` fills `put / get-range / topics / purge / open / close / count-fn / delete`
and **leaves `sync` and `set-chain-mac-fn` NIL — memory-tier parity, exactly as `make-memory-store`**.
The client cannot ship a secret-holding chain-MAC closure over TCP, so the cross-frame keyed log-MAC
chain (ADR 0045) is absent, documented, at this tier. At-rest confidentiality composes the **other**
way: `make-encrypted-store` layers OVER the microservice-store unchanged (the opaque proxy carries
sealed bytes end-to-end; per-record DARE-GCM still authenticates each record) — this is Slice 2. Because
the server is DARE-blind, encryption is a pure client-side decorator over the vtable, needing zero
server changes.

### 4.1 Slice 2 — the DARE-wrapping factory (WP-DURABILITY-MICROSERVICE-2, BUILT)

Slice 2 realises §4 with **one addition and no server change**: `make-microservice-store-factory`
(`store-microservice.lisp`), the exact sibling of `make-sqlite-store-factory` /
`make-persistent-store-factory`. It returns the 0-arg store factory
`(lambda () (make-encrypted-store (make-microservice-store :host H :port P)
(make-file-key-provider :dir KEY-DIR) :epoch-dir EPOCH-DIR))` — the ONLY change from the sqlite/file
siblings is `make-microservice-store` in the inner slot, because the `durable-store` vtable is the fixed
backend contract every tier fills unchanged. Pass it as the `:store` argument to `make-service-spec` to
config-select the encrypted tier whose persistence is a **remote** microservice (the same 0-arg-closure
seam the service-spec `:store` slot consumes; `:process` mode does not carry a factory across the
subprocess boundary — use `:thread`).

**All DARE state is client-side, off the wire.** The ML-KEM-1024 anchor + private key (KEY-DIR),
`epochs.dat`, the log-MAC anchor, and `k_meta` all live in the **local** EPOCH-DIR / KEY-DIR, and the
`encrypted-store` decorator seals every record BEFORE it reaches `make-microservice-store` (which is the
opaque inner store). Concretely (`store-encrypted.lisp:903`) each put hands the inner tier only
`(store-put inner th guid* 0 nil :data sealed)` — a **hex topic-hash** `th`, a **16-byte GUID surrogate**
`guid*`, **sn = 0**, a **NIL key-hash**, kind `:data`, and the **sealed blob**. So the remote
microservice server (an inner memory store in the tests) holds **only opaque ciphertext + surrogates**,
never a plaintext topic name / writer-GUID / SN / key-hash / payload, and never any key.

**One structural difference from the sqlite/file siblings:** the inner tier's HISTORY policy is **not** a
construction argument of the factory (`make-microservice-store` takes none; the factory's argument list is
`&key host port epoch-dir key-dir`), whereas the file/sqlite factories bake it into their local inner-store
constructor. **In Slice 2 the policy travelled to the remote inner store at `store-open`; Slice 3a's
server-owned-lifecycle refactor changed this** — the inner is now opened ONCE at server-start with the
SERVER's configured `:history-kind`/`:history-depth` and a per-client `store-open` is a policy-confirm no-op
(§4.2), so the client/service HISTORY QoS is **no longer forwarded** to the remote inner (see the §4.2
known-limitation + the Slice-3c policy-forwarding item in §7). The authoritative statement of the
history-policy semantics is §4.2, not this Slice-2 paragraph.

In Slice 2 the chain-MAC oracle install (`store-set-chain-mac-fn`) was a documented **no-op** (the
`:set-chain-mac-fn` slot NIL); **Slice 3b (§4.3) makes it LIVE** — the client-side v3 chain now arms over the
remote tier. Independently of the chain, **per-record DARE-GCM authenticates each frame** (confidentiality +
per-record integrity: an attacker cannot read, forge, or alter a frame's decrypted contents — GCM + the AAD
+ the HMAC surrogate binding prevent that, and reorder-within-a-topic is neutralized post-decrypt because the
client re-sorts by the decrypted `(guid, sn)`).

**Integrity residual — REMOTE-UNTRUSTED-STORE threat (RESOLVED for drop/reorder/tamper in Slice 3b, §4.3).**
What per-record GCM alone left unprotected is the **completeness and ordering of the record sequence**: a
malicious/compromised *remote* server can silently **drop, reorder, or tamper** sealed records. This is NOT
the memory-store story: for `make-memory-store` the store is **intra-process**, so an adversary able to tamper
already holds the keys and the absent chain is moot; a microservice store sits **across a trust boundary** and
is precisely the untrusted-storage adversary the cross-frame chain was built to catch — and the file/SQLite
tiers, facing the identical on-disk-tamper threat, carry the chain (ADR 0045). **Slice 3b (§4.3) closes this
for drop / reorder / tamper**: the client computes the ADR-0045 v3 chain-MAC locally and folds the 32-byte
MAC + a chain_seq into the opaque payload the DARE-blind server stores verbatim, and the reopening client
re-verifies every topic fail-closed on open. **These former residuals are now CLOSED (WP-DURABILITY-TAIL-
ANCHOR-MS, ADR 0045 §7.1):** the client-side sealed high-water tail anchor detects TAIL-TRUNCATION of a valid
prefix AND WHOLE-TOPIC-DROP-BY-A-MALICIOUS-SERVER — the latter because the decorator verifies the CLIENT-
TRUSTED sealed topic-SET (from the client's `logmac.tail`), not the server's `store-topics`, so a server
omitting a topic still gets verified (fetch 0 → `:truncated`). See §4.3. A secondary at-rest metadata residual for the
remote case: beyond the (documented 3c) topic-hash linkability + per-topic-hash record counts, a remote server
additionally observes **live access-pattern timing** (put/get op arrival) — the standard opaque-proxy tradeoff.

### 4.2 Slice 3a — server-owned PERSISTENT inner + cross-restart + config-env (WP-DURABILITY-MICROSERVICE-3A, BUILT)

Slice 1/2 held the inner in *memory*; a persistence backend that cannot survive a restart is incomplete.
Slice 3a makes the reference server a **real persistence backend**.

**Server-owned inner lifecycle.** The server now OWNS its inner store's lifecycle — correct for a
persistence tier that OUTLIVES individual client sessions. `make-microservice-server` opens the inner
**ONCE at server-start** (with new `:history-kind` / `:history-depth` args, NIL = defer to the inner's
factory default): a persistent `make-file-store` / `make-sqlite-store` inner **REPLAYS from disk**
(recovering prior history), a memory inner opens empty. It is closed **ONCE at server-stop** (already the
case in Slice 1: `microservice-server-stop` → `store-close` → fsync). The two per-client op handlers change
to match:

- **`+ms-op-open+` is a POLICY-CONFIRM no-op** (`%ms-handle-request`): a per-client `store-open` no longer
  re-opens the inner. A second `store-open` on a file/SQLite inner would **re-replay the whole log per
  client session** (wasteful; and the file store's re-open rebuilds/leaks its append streams) — and the
  shared server-owned tier's history policy is an operator/server property set at server-start, not a
  per-client one. The handler still DECODES the `hk`/`depth` payload (so a malformed open is bounds-rejected
  and drops the connection), then just acknowledges. **Chosen semantics, documented:** open-at-server-start
  with the server's configured policy; client-open = policy-confirm/no-op. (The alternative — first-client
  open drives, subsequent idempotent — is strictly worse for a persistent inner: it either re-replays or
  needs a vtable set-policy slot the fixed contract forbids.)
- **`+ms-op-close+` ends only the client SESSION** (unchanged from Slice 1: acknowledge, do NOT close the
  inner). So multiple client sessions against one server see the SAME persisted store, and the inner
  survives every client connect/disconnect until the server stops.

**Cross-restart recovery (the point).** A persistent inner on disk `D` survives a server restart: server1
(inner on `D`) collects the client's puts + fsyncs on stop; server2 (a FRESH inner on the SAME `D`) replays
`D` on start; a client reconnecting to server2 + `store-get-range` recovers the records byte-exact +
(guid,sn)-ordered + counted. Proven for BOTH a file inner AND a SQLite inner. **RED:** a memory inner (no
shared disk) recovers 0 — proving the persistence is real. For the **DARE-wrapped** composition
`make-encrypted-store(make-microservice-store(server file inner))`, the server persists the **OPAQUE sealed
frames** to `D` (server2 recovers opaque); the client's DARE state (`epochs.dat` + the ML-KEM key) is
**client-side** in the LOCAL epoch-dir / key-dir and persists there, so a client with the SAME local
epoch-dir re-derives the prior epoch DEK and `store-get-range` **decrypts + recovers the REAL records
byte-exact** — while an on-disk scan of `D`'s topic logs confirms the persisted frames are **ciphertext**
(the plaintext topic / GUID / SN / payload needles are absent). The server never sees plaintext across the
restart.

**The config-env seam.** `make-durability-store-factory backend &key dir key-dir ms-host ms-port …`
(`spec.lisp`) is the single backend-dispatch seam the durability-persistent drivers share (DRY — replacing
the `(if (string-equal backend "sqlite") …)` that was copy-pasted across `driver-collect` /
`driver-serve`). `"sqlite"` → `make-sqlite-store-factory`; `"microservice"` →
`make-microservice-store-factory` (the REMOTE client tier — `:ms-host`/`:ms-port` address the operator-run
reference server, while `dir`/`key-dir` stay the CLIENT-LOCAL DARE epoch-dir/key-dir; port REQUIRED);
anything else → `make-persistent-store-factory` (the file default). `interop/durability-persistent/driver-
collect.lisp` + `driver-serve.lisp` now read `DPERSIST_BACKEND` (`file`|`sqlite`|`microservice`) +
`DPERSIST_MS_HOST` (default 127.0.0.1) + `DPERSIST_MS_PORT` and dispatch through it. The remote server is a
separate process the operator runs; the driver is the durability **client**. (The `main.lisp` CLI
`--backend` remains a Slice-3 follow-on — the driver-env path suffices.) The full live 2-process
microservice interop is optional this slice; the config-env is proven structurally (the factory builds
`encrypted-store(microservice-store)`, name `:encrypted-persistent`).

**HISTORY-POLICY OWNERSHIP — the decorator owns retention; server-side HISTORY-QoS is DESCOPED (was the
Slice-3a "known limitation", now corrected by WP-DURABILITY-MS-RECLAIM-REMAC + WP-DURABILITY-MS-RECONNECT).**
The microservice inner tier's retention policy is **SERVER-configured** (`make-microservice-server`
`:history-kind`/`:history-depth`, applied at server-start) and is deliberately **NOT forwarded from the
client/service HISTORY QoS over the wire** — and, contrary to the earlier Slice-3a framing, that forwarding
is **NOT REQUIRED; it is descoped as MOOT and, under DARE, WRONG.** Under the always-on DARE production
composition `make-encrypted-store(make-microservice-store(…))` the **encrypted-store DECORATOR owns retention
end-to-end**: it ALWAYS opens the inner **KEEP_ALL** (`store-encrypted.lisp:1343-1344` — "it cannot
order/interpret the hashed surrogates"), LOGICALLY compacts newest-D on get-range (`%compact-topic-records`,
`store-encrypted.lisp:1186`) and PHYSICALLY reclaims a keyed KEEP_LAST put's superseded surrogate
(`%evict-prior-surrogates` `:1279-1280` → the §4.4 chained `store-delete` → `+ms-op-topic-rewrite+` survivor
re-MAC) — **delivered and TESTED KEEP_LAST-through-microservice** (`run-durability-microservice-keep-last-
reclaim-test`: newest-D + physical-1 reclaim + cross-restart). The reference **server MUST stay KEEP_ALL**:
server-side HISTORY-QoS is **INERT** under DARE (the decorator seals with **key-hash NIL**,
`store-encrypted.lisp:1272`, so the inner's per-instance KEEP_LAST never triggers) **AND WRONG** (a
server-side eviction of a chained record would break the client's `%ms-verify-chain` → `:mismatch` → **brick**).
So matching the reference server to a KEEP_LAST HISTORY QoS is not merely unnecessary, it is **AGAINST the
decorator's model.** The **bare non-DARE microservice path** (no decorator) is not a production composition;
HISTORY-QoS-over-the-wire forwarding is therefore **descoped**. (All in-process tests use keep-all and pass;
the earlier "over-retention on the live 2-process path" concern is resolved by the decorator owning retention
CLIENT-SIDE, independent of the server's policy.)

**Deferred beyond 3a:** the client-side v3 chain-MAC over the remote tier (**Slice 3b** — remote-untrusted-
store sequence integrity, §4.1); multi-client concurrency / chunked large get-range / DoS-hardening
(**Slice 3c**). Graceful reconnect is now **BUILT** (§4.5, WP-DURABILITY-MS-RECONNECT); HISTORY-QoS-over-the-
wire forwarding is **DESCOPED** (the decorator owns retention, above). The DARE crypto + the bounds-checked
wire parser are unchanged.

### 4.3 Slice 3b — client-side remote-tier chain-MAC (WP-DURABILITY-MICROSERVICE-3B, BUILT)

Slice 3b closes the §4.1 remote-untrusted-store residual for **drop / reorder / tamper**, reaching
file/SQLite tamper-evidence parity — with **zero server change and zero wire-protocol change**.

**Client-side compute, fold into the opaque payload.** The "a secret chain-MAC closure can't ship over TCP"
rationale for the NIL slot was a red herring: the encrypted-store decorator installs its log-MAC oracle into
the **client-side** `microservice-store` object (same process, via `store-set-chain-mac-fn`); only the 32-byte
MAC *output* ever ships. `make-microservice-store` now fills the (previously NIL) `:set-chain-mac-fn` slot —
**filling an existing vtable slot, not a vtable change.** With the oracle installed:

- **On put** (below the decorator, over the surrogate record `(th, guid*, 0, nil, :data, sealed)`): the client
  computes the v3 chain MAC over the **unwrapped** sealed frame via the REUSED `%frame-record-versioned`
  (prev = the per-topic running-MAC table, seeded by `%chain-seed` for the first frame), then FOLDs
  `sealed' = sealed ∥ mac(32) ∥ chain_seq(u64 LE)` and ships it through the **unchanged** put op. The server
  stores `sealed'` OPAQUE — a slightly-longer blob it never parses. The running MAC + a per-topic monotonic
  `chain_seq` counter advance (a port of the file store's `chain-macs` table). **`chain_seq` is MANDATORY**:
  the server's get-range sorts by `(guid, sn)` (`%record-guid-sn<`) ≠ append/chain order, so the client stamps
  the chain order into the payload and re-sorts by it to re-verify (the same reason SQLite needs an explicit
  `chain_seq` column). An idempotent re-put (the client's own `(guid, sn)` index — the microservice analogue of
  the file store's in-memory index) does NOT advance the chain, so a re-delivered sample cannot double-link it.
- **On get-range**: the client STRIPS the last 40 bytes (bounds-checked — a `< 40`-byte payload from a malicious
  server fails cleanly, never OOB, operating contract §4), recovers `sealed` + mac + chain_seq, returns the
  record with `payload = sealed` to the decorator (transparent — the decorator sees only `sealed`, as before),
  and VERIFIES the topic's chain (sort by chain_seq, re-seed via `%chain-seed`, recompute each expected MAC via
  `%frame-record-versioned`, equalp-compare — a near-verbatim port of `%sqlite-verify-topic`).
- **On open**: a fail-closed-on-OPEN verify pass (file/SQLite parity) get-range-verifies EVERY topic before any
  read; a tampered chain FAILS the open loudly. The oracle is installed before `store-open` (the decorator's
  sequence), so the pass has the key.

**Server stays DARE-blind + byte-identical.** The mac + chain_seq ride folded inside the opaque payload; the
put/get-range ops and the frame format are unchanged (the wire frame is still a v2 frame whose payload happens
to be `sealed'`). No server code changed. The chain engages **only** under the encrypted-store (which installs
the oracle); a bare `microservice-store` leaves the slot installed-but-uninstalled → no chain, memory-parity,
Slice 1 unchanged.

**Detected (fail-closed on open, = file/SQLite):** interior DROP (a gap → the next record's prev-MAC
mismatches), REORDER (order-dependent HMAC + chain_seq swap breaks the recompute), TAMPER/SUBSTITUTE/INSERT
(recompute fails; and DARE-GCM independently fails on unseal).

**NOW DETECTED (WP-DURABILITY-TAIL-ANCHOR-MS, ADR 0045 §7.1 — the two Slice-3b residuals are CLOSED).**
`make-microservice-store` now FILLS the sealed high-water tail-anchor seam (`store-chain-tails` /
`store-verify-chain-prefix`) **CLIENT-SIDE**, so the decorator seals `logmac.tail` (on the client-local
epoch-dir) at clean close and verifies it at open. This closes **TAIL-TRUNCATION of a valid prefix** (the
prefix-containment `count < N → :truncated` fails-closed) and — the microservice-specific headline —
**WHOLE-TOPIC-DROP-BY-A-MALICIOUS-SERVER.** The former gap was that the client enumerates topics via the
server's `store-topics`, which a malicious server could omit. The tail anchor closes it because
`%verify-tail-anchor` iterates the **CLIENT-TRUSTED sealed topic-SET** (from the client's `logmac.tail`),
NOT the server's list: a server that omits a topic still triggers `store-verify-chain-prefix` for it → the
fetch returns 0 records → `:truncated` → fail-closed. The seam reuses the client-side chain state
(`chain-macs`/`chain-seqs`) and an extracted read-only `%ms-chain-walk` (DRY with `%ms-verify-chain`); the
server is DARE-blind (no server/protocol change, no new crypto). **Introduced-brick fix:** filling the seam
surfaced a NEW false-reject — the microservice `:purge` shipped the purge to the server but did NOT clear the
client-side chain head, so `store-chain-tails` kept sealing a STALE `(N, M_N)` for the purged topic → the next
open fetched 0 records for it → `:truncated` → **brick** (reachable by a plain put+purge+clean-close+reopen at
KEEP_ALL). Fixed by clearing the client chain head (`chain-macs`/`chain-seqs`/`put-index`) in the ms `:purge`
seam, mirroring the file/SQLite `:purge` fixes — which also closes the pre-existing purge+reput-same-session
brick for this tier. **Former limitation (RESOLVED in Slice 3d, §4.4):** the microservice `:delete` was a plain
server proxy that did NOT re-MAC surviving frames (unlike the file store's `%rewrite-topic-log` / SQLite's
`%sqlite-recompute-topic`), so a KEEP_LAST physical reclaim broke the client-side chain on the next open
**independent of the anchor** (a pre-existing Slice-3b limitation). The F1 invalidate-at-open inheritance is
therefore proven (in the tail-anchor test) with an authorized PURGE shrink (which leaves a valid chain); the
KEEP_LAST reclaim itself is now covered by its own test (§4.4).

**No legacy (un-folded) migration path (a false-reject on upgrade — honest parity with the file/SQLite v2→v3
migration docs).** The fold is UNVERSIONED (no per-record fold-version marker), so a pre-Slice-3b
DARE-microservice store — whose server holds un-folded records but whose client already minted a
`logmac.anchor` (`%ensure-logmac` mints it unconditionally) — would, reopened under 3b, install the oracle,
run the open verify pass, strip 40 real sealed bytes from each un-folded record, and MAC-mismatch →
**false-reject a legitimate store** (or a < 40-byte record → protocol-error). This edge is closed only by
re-creating the store under 3b. Severity is negligible in practice — the microservice backend is new and
unreleased (Slices 1–3b all landed in one session; no persisted pre-3b microservice store exists, and the
tests use fresh dirs) — but it is a false-reject (the worst class), so it is stated here for honesty. A
future fold-version byte would restore a migration path if a pre-3b store ever needed reading.

Both impls green identically, Clasp first: `durability-microservice-remote-chain` (malicious-server DROP /
TAMPER / REORDER each fail-closed on open with a RED bare-store-undetected contrast; tail-truncation +
whole-topic-drop now DETECTED via the tail anchor; round-trip byte-exact through the chain with the inner
holding the folded blob; cross-restart over a persistent file inner re-verifies clean; NIL-oracle bare
round-trip) and `durability-microservice-tail-anchor` (WP-DURABILITY-TAIL-ANCHOR-MS: tail-truncation +
whole-topic-drop-by-server RED→GREEN, anchor-tamper, cross-restart byte-exact, F1 reclaim-shrink-crash clean
+ RED-brick via the skip-invalidate knob). The DARE-dependent arms SKIP if OpenSSL < 3.5.

### 4.4 Slice 3d — KEEP_LAST reclaim re-MAC over the wire (WP-DURABILITY-MS-RECLAIM-REMAC, BUILT)

Slice 3d resolves the §4.3 KEEP_LAST-reclaim brick. A KEEP_LAST **encrypted** microservice store **bricked on
physical eviction**: the decorator's online reclaim (`%evict-prior-surrogates` → `store-delete`) removed a
superseded surrogate, but the microservice `:delete` was a **bare server proxy** — it deleted the record
server-side and never re-MAC'd the surviving client chain (unlike the file tier's `%rewrite-topic-log` and
SQLite's `%sqlite-recompute-topic`, which re-seed + re-walk + re-MAC the survivors after a compacting delete).
So the survivors' stored **folded MACs went stale** (they chained over the deleted predecessor) → the next
open's `%ms-verify-chain` re-seeded and hit `:mismatch` → **BRICK** (the store refused to open; data
inaccessible). Reachable by the minimal KEEP_LAST-1 + two superseding puts of one instance.

**Why the naive fixes fail.** A *local-only* re-MAC is insufficient — on open, `%ms-verify-chain` **overwrites**
the client chain from the server's authoritative records, so the server's stale stored MACs win → still bricks.
A naive *re-put* of a survivor is ignored — the server's `store-put` is idempotent INSERT-OR-IGNORE by
`(guid,sn)`, so the stale folded blob stays. **The server's stored frames MUST be replaced.**

**The fix — a whole-topic-rewrite wire op.** A new `+ms-op-topic-rewrite+ = 8` op (op-code 8 was free):
request payload `topic(u16-len UTF-8) ∥ u32 count ∥ count × record-frame` (reusing `%ms-put-string` /
`%ms-put-frame`; the count is bounded against the buffer extent and each `%rd-frame` is bounds-checked on
decode — network-facing, no OOB, operating contract §4). The chained `:delete` becomes the microservice
analogue of SQLite's `:delete = DELETE + %sqlite-recompute-topic`:

1. **get-range** the topic's current folded records over the wire (`%ms-fetch-tuples`).
2. **drop** the deleted `(guid,sn)` from the survivor set.
3. **re-chain** the survivors client-side (`%ms-delete-rechain` → `%ms-rechain-survivors`): re-seed from the
   per-topic keyed head (`%chain-seed`), re-walk in `chain_seq` order recomputing each MAC over the canonical
   v3 frame via the REUSED `%frame-record-versioned`, re-fold via `%ms-fold-payload` with a **DENSE** `chain_seq`
   `0..M-1` — **mirroring `%rewrite-topic-log` / `%sqlite-recompute-topic` exactly**, so the next open's
   `%ms-verify-chain` (the SAME `%ms-chain-walk`, the SAME seed) recomputes byte-identical MACs and reopens
   CLEAN.
4. **update** the client chain state (`chain-macs`/`chain-seqs`/`put-index`) to the re-chained state, so a
   continued put, the sealed tail anchor, and the next open all see the fresh chain.
5. **ship** the re-folded survivors in ONE `+ms-op-topic-rewrite+` op.

**Server-side — DARE-blind atomic replace.** The `+ms-op-topic-rewrite+` branch decodes the OPAQUE frames
(`%rd-frame`; the mac/chain_seq ride *inside* each payload, never parsed) and swaps the topic via a **new
additive NIL-fallback `store-replace-topic` vtable slot** (the same binding as `store-delete` / `sync`):

- **memory inner** (the default + all in-process tests): the NIL-fallback `store-purge` + bulk `store-put` —
  **trivially atomic** (the server serves one request at a time; no crash-persistence).
- **persistent file inner**: the slot reuses the atomic `%rewrite-topic-log` (tmp + fsync + rename — the
  `*durability-debug-file-rewrite-fault*` seam gives crash-before-commit **rollback**).
- **persistent SQLite inner**: the slot uses a single transaction (DELETE topic + INSERT survivors —
  `*durability-debug-compact-fault*` rollback).

A partial topic would brick the re-MAC'd chain, so the replace is **all-or-nothing**. The server never installs
a chain oracle (it is DARE-blind); a bare inner writes byte-identical v2 frames with the fold riding as opaque
payload bytes. **No new crypto** (reuses `%chain-seed` / `%frame-record-versioned` / `%ms-fold-payload`; KATs
unchanged), no new dependency, no reader conditionals outside `dds-pal`.

**Tests** — `run-durability-microservice-keep-last-reclaim-test` (DARE-wrapped, skip if OpenSSL < 3.5): (1)
**brick-repro → CLEAN** (KEEP_LAST-1, 2 superseding puts → reclaim → reopen CLEAN + newest-D byte-exact + a 2nd
reopen stays clean = tail-anchor composition) + **(1-RED)** `*durability-debug-ms-skip-reclaim-remac*` T → the
same reclaim **BRICKS** (proving `%ms-delete-rechain` is load-bearing); (2) **server DARE-blind** (the survivor
is a folded opaque blob > 40 bytes; the plaintext never appears in the server inner); (3) **sustained
tamper-evidence** (KEEP_LAST-2, 3 puts → 2 re-chained survivors → byte-tamper / survivor-drop / whole-topic-drop
each caught fail-closed); (4) **cross-restart** (a persistent file inner replays the re-MAC'd rewrite across a
server restart → CLEAN + byte-exact); (5) **crash-fault mid-replace** (the file-rewrite fault → rollback →
reopen CLEAN, no partial-topic brick). `run-durability-microservice-remote-chain-test` also gains a reclaim +
whole-topic-drop-still-detected arm. Both impls **497 → 498 passed** (Clasp first, then SBCL; DARE available so
all arms executed, not skipped), identical.

### 4.5 Slice 3c-1 — bounded client reconnect + idempotent retry (WP-DURABILITY-MS-RECONNECT, BUILT)

Slice 1–3d connected once at open and **never reconnected**: on a dropped connection (server restart /
network blip) the dead socket **stayed in the conn-cell**, so every later op re-failed against the corpse —
a durability tier whose whole point is a **restartable central store** was permanently bricked by any server
restart. A **send-side wart** compounded it: `tcp-send` signals a plain error, but `%ms-call`'s handler
translated only `microservice-protocol-error`, so a send-side drop **escaped as a raw generic error**,
violating the one-clean-error contract. Slice 3c-1 fixes both, **client-side only — zero wire-protocol change,
zero server change** (the reference server already holds **zero per-session state**: `+ms-op-open` is a
policy-confirm no-op, `+ms-op-close` an ack, so re-establishment is just a re-dial).

**The conn-cell becomes a struct.** The bare `(sock)` cons is replaced by a small `ms-conn` `defstruct*`
carrying **`host` + `port` + `sock`** (the dial coordinates, set once at store construction), so `%ms-call` /
`%ms-exchange` can RE-DIAL — the host/port previously lived only in the `:open`/fetch closures and never
reached `%ms-call`. Access stays under the store lock (unchanged discipline).

**Bounded single reconnect + idempotent retry.** `%ms-exchange` translates BOTH drop signals — a failed send
(the wart) and a server-closed read (`%ms-recv-message` NIL) — to a new **`microservice-conn-lost`** (a
**subtype** of `microservice-store-error`, so existing handlers still catch it, but distinguishable). On
`microservice-conn-lost`, `%ms-call` **closes+clears** the dead socket, **re-dials ONCE** (`%ms-reconnect`:
one short bounded backoff then `tcp-connect host:port`), and **retries the op ONCE**. A second consecutive
drop, or a failed re-dial (server still down → fast `ECONNREFUSED`), surfaces a clean `microservice-store-error`
— a **bounded** single reconnect, never an unbounded loop or a hang (the full read-idle timeout that turns a
blocked-mid-response read into a conn-lost is now BUILT in §4.6; here the re-dial to a down port fails
fast). A non-drop server error (bad status) is **not**
retried.

**Idempotent-retry safety (the correctness crux).** The retry re-invokes both `build-fn` and `decode-fn`,
which is safe because every op is idempotent AND advances client chain/put-index state **only in `decode-fn`
after a confirmed response**:

- **put** — chain state (`chain-macs`/`chain-seqs`/`put-index`) advances post-confirm, so a retry recomputes
  the **byte-identical** folded frame (same `prev`/`seq`) and re-ships it; the server INSERT-OR-IGNOREs by
  `(guid,sn)` (`store.lisp:241`). Even if the original put **succeeded but its response was lost**, the retry
  re-sends, the server ignores the dup, returns success, and the client advances exactly once.
- **chained delete / topic-rewrite** (`%ms-delete-rechain`) — the fetch is read-only; the rewrite replaces the
  **same survivor set** (idempotent); state advances post-confirm. The 2-step is safe to retry whole (the
  decorator's lock serializes it), and each `%ms-call` inside also reconnects independently.
- **purge** — idempotent; **count/get-range/topics** — read-only.
- **bare `:delete`** — a retry after the record is already gone must **tolerate `+ms-result-rejected+`** (the
  record is gone = the delete's goal); the decode now treats a post-delete rejected as success (T) instead of
  a false "bad delete result". (In practice the standard memory/file/SQLite inners return T on an absent
  delete, so a delete-retry gets `+ms-result-t+`; `+ms-result-rejected+` on a delete arises **only** from an
  inner with **no `:delete` slot** — `store-delete` → `:unsupported` → the server maps it to rejected. The
  tolerance is a defensive idempotency hardening, proven by a test that forces the rejected path.)
- The **single-retry** path does NOT re-run chain verification (the client chain state is authoritative for
  a retry-succeeds). The **double-failure** (exhausted-retry) is the exception — see below.

**Double-failure (exhausted-retry) + availability (Fix 1 + Fix 2, they interact).** The single-retry safety
above covers the retry-SUCCEEDS leg. Two follow-on findings (adversarial review) — both **newly reachable
BECAUSE the session now survives a drop** (on the pre-fix base, a dropped socket bricked the store, masking
them) — are fixed together:

- **Fix 1 — exhausted-retry chain divergence → later-open false-reject brick (the worst class).** If a
  *chained* put's original AND its reconnect-retry both drop while the server APPLIED the record (an
  apply-then-ack window), the client chain state stays **unadvanced** while the server holds the record. The
  session survives (the whole point of the WP), so the next put of the same topic chains from the **seed**
  again → **two records claim `chain_seq` 0** → the next open's `%ms-verify-chain` (or the sealed tail anchor,
  `:diverged`) **fails-closed on honest data** — a permanent false-reject **brick**, violating ADR 0045's
  no-false-reject invariant. **Fix:** a per-store **STALE-TOPICS** set — when `%ms-call` exhausts for a
  chain-mutating op (chained put / topic-rewrite / oracle-purge), the topic is marked STALE; before the next
  chained mutation of a stale topic, `%ms-resync-if-stale` FORCE-re-syncs the client chain state from the
  server (`%ms-resync-topic`: get-range + **clear-then**-`%ms-verify-chain`, so a purged/empty topic stays
  cleared) — re-learning whether the exhausted op was applied (server has it → `chain-seqs` advances; server
  empty → stays 0). The next mutation then chains from **ground truth** → no fork → no brick, regardless of
  the exhausted op's fate. The re-sync is DEFERRED to the next chained op (at exhaustion time the server is
  unreachable); it reuses `%ms-get-range-verified`'s machinery (no wire change, no new crypto). This is the
  one **targeted** mid-session re-verify — the common single-retry path still does not re-verify.
- **Fix 2 — op-during-outage recovery (availability; interacts with Fix 1).** `%ms-reconnect` leaves `sock`
  NIL on a failed re-dial. Before Fix 2, `%ms-call` then refused **every** later op ("store is not open")
  with no re-dial — TERMINAL: an op *during* an outage (the common case under write load) permanently
  disabled the store even after the server returned. **Fix:** `ms-conn` distinguishes **DROPPED**
  (`sock` NIL but `ever-connected-p` — the connection was established then dropped) from **CLOSED** (`closed-p`,
  set only by `%ms-close`) and **never-opened**. `%ms-call` RE-DIALS once from the DROPPED state on the next
  op (bounded), so an op-during-outage recovers when the server returns; only an explicitly-closed or
  never-opened store is terminal. **Why both together:** Fix 2 *widens* Fix 1 — once ops re-dial from
  dropped-NIL, the server-restart flavor of the Fix-1 collision becomes reachable, so Fix 1's stale-topic
  re-sync MUST be in place.
- **Fix A — seal never commits a stale/diverged `(N, M_N)` (a pre-existing worst-class brick closed cheaply
  by the stale-topics machinery).** An apply-then-ack-lost **PURGE** or **TOPIC-REWRITE** followed by a clean
  close with NO further chained mutation on that topic sealed a **stale** `(N, M_N)` — `:chain-tails-fn`
  ignored `stale-topics`. The next open's tail-anchor prefix-verify then **bricked HONEST data** (`:truncated`
  for a purge-applied → 0 server records; `:truncated`/`:diverged` for a rewrite-applied shrink below the
  sealed N). Reachable at BASE (a single ack-lost drop, no reconnect — the exhausted-PUT+close flavor is CLEAN
  because prefix-containment tolerates forward growth, so only purge/rewrite-**shrink** needed this). **Fix:**
  `%ms-reseal-stale-topics` runs in `:chain-tails-fn` BEFORE the seal maphash — for each STALE topic it PREFERS
  to `%ms-resync-topic` from the server (a clean close means the server is reachable → the correct `(N, M_N)`,
  with a purged topic clearing its head → not sealed), and FALLS BACK to SKIPPING the topic from the seal (its
  head dropped) if it can't be resync'd (server unreachable, or a genuine tamper). Either way **no
  stale/diverged value is ever sealed → no false-reject brick**; the narrow protection gap heals at the
  topic's next successful mutation + re-seal (a genuine tamper is still caught by store-open's own verify).
  Non-stale topics are untouched (`store-chain-tails` byte-identical for them).
- **Fix B (introduced NIT) — same-object close→reopen.** With a sealed anchor, a close→reopen of the SAME
  encrypted(microservice) store object failed loudly: the decorator runs `%verify-tail-anchor` (its `%ms-fetch-
  tuples` probe) BEFORE `store-open`, and the probe's `%ms-call` was refused by the `closed-p` guard because
  `%ms-open`'s `closed-p` clear ran too late for the pre-open probe. **Fix:** `%ms-dial` clears `closed-p` (a
  successful dial re-establishes the connection → the store is usable), so the pre-open probe's dial re-arms
  the store. (Latent in shipped flows — the tests reopen a fresh store object — but now covered by a test.)

**Tests** (`run-durability-microservice-reconnect-test`, DARE-wrapped, skip if OpenSSL < 3.5;
`run-durability-microservice-reconnect-bare-test`, bare, always runs; `run-durability-microservice-reconnect-
exhausted-test` + `run-durability-microservice-reconnect-seal-test`, DARE-wrapped): **RECONNECT-AFTER-RESTART**
(encrypted, a file inner on the SAME disk + SAME port across a `microservice-server-stop`/restart — put across
the drop reconnects + succeeds; **RED without the fix: permanent brick**); **RECONNECT-RETRY-IDEMPOTENT** (put
across the drop → stored ONCE + the chain verifies CLEAN on the next open); **EXHAUSTED-RETRY-NO-FORK** (Fix 1 —
a chained put whose retry EXHAUSTS while the server applied it, then a 2nd put on the topic → the stale-resync
fires → reopen CLEAN + count 2; **RED via `*durability-debug-ms-skip-stale-resync*`: R2 forks → reopen bricks**,
driven by `*durability-debug-ms-force-recv-drop*`); **SEAL-RESYNC-OR-SKIP** (Fix A — an apply-then-ack-lost
PURGE + clean close → reopen CLEAN; **RED via `*...-skip-stale-resync*`: the stale `(N, M_N)` is sealed → reopen
bricks `:truncated`**); **SAME-OBJECT-CLOSE-REOPEN** (Fix B); **OP-DURING-OUTAGE-RECOVERS** (Fix 2 — a
down-server op fails cleanly, then after restart the next op re-dials + succeeds; **RED via
`*durability-debug-ms-skip-redial-dropped*`: terminal 'store is not open'**); **BARE RECONNECT-AFTER-RESTART**;
**SEND-SIDE-ERROR-CLEAN**; **NO-INFINITE-LOOP** (a down server fails in bounded time, no hang);
**BARE-DELETE-RETRY-TOLERATES-REJECTED**. Both impls **502 → 503 passed** (Clasp first, then SBCL; DARE
available so all arms executed), identical; gate-hotpath + gate-types PASS; SBOM unchanged. No new crypto, no
new dependency, no reader conditionals outside `dds-pal`.

### 4.6 Slice 3c-2 — server DoS-hardening: read/idle timeout + incremental allocation + accept backoff (WP-DURABILITY-MS-DOS, BUILT)

Slice 3c-1 made the client survive a dropped connection, but the SERVER (and the shared reader, which also
protects the client) still had **three concrete holes against a malicious/abusive peer**, the worst of which
denied *every* client. Slice 3c-2 closes all three — **no wire-protocol change, no new crypto, no new
dependency**.

**Gap (a) — read/idle timeout (the worst hole: a slow-loris hangs the SERIAL server forever).** `tcp-recv`
had **no timeout** — it blocked indefinitely. A slow-loris that connects and sends the 4-byte length header
then STALLS parks the serve thread in `%ms-recv-message` **forever**; because the server is serial (one
accept+serve thread), one stalled socket **denied every other client** until server-stop. A malicious server
could equally stall the client's `tcp-recv`. **Fix, three parts:**

1. **New PAL prim `dds.pal:tcp-set-recv-timeout (sock seconds)`** → `setsockopt(SO_RCVTIMEO)` with a 16-byte
   `struct timeval` (tv_sec 8 LE ∥ tv_usec-as-4-LE ∥ 4 pad — one encoding valid for BOTH the Darwin int32
   tv_usec *and* the Linux long tv_usec, verified). **Portable across SBCL + Clasp**: it reuses the existing
   `%setsockopt`/`sb-bsd-sockets` layer, and `+so-rcvtimeo+` is **OS**-specific (Darwin `#x1006` / Linux `20`)
   — an `#+darwin`/`#-darwin` constant like the `SO_REUSEPORT`/`SO_NOSIGPIPE` ones already in `pal-net.lisp`,
   **never** an impl (`#+sbcl`/`#+clasp`) conditional, so the one-allowed-place rule holds. `tcp-recv` was
   wired to make a timeout a **DISTINCT catchable outcome**: an empirical probe on BOTH impls showed
   `sb-bsd-sockets:socket-receive` returns **`n=0` on a clean peer-close** but **`n=NIL` on an SO_RCVTIMEO
   timeout** — identical on SBCL and Clasp — so `tcp-recv` now splits them: `n=NIL` → signals **`pal-timeout`**
   (a new `pal-error` subtype), `n=0` → returns NIL (clean EOF, unchanged), `n>0` → data. A socket with **no**
   timeout armed is byte-for-byte unchanged (still blocks, still NIL on close).
2. **Server read-deadline** — `make-microservice-server :recv-timeout` (default `+ms-default-recv-timeout+` =
   30 s; NIL disables) is armed on each accepted socket **inside** `%ms-serve-connection`'s `handler-case`. A
   stalled recv trips `pal-timeout`, which the existing **`serious-condition` backstop** catches → the
   connection is DROPPED → the accept loop **survives** and serves the next client. The slow-loris no longer
   denies anyone.
3. **Client read-deadline** — `make-microservice-store :recv-timeout` (same default) is armed at every dial
   (`%ms-dial`, so a reconnect re-arms the fresh socket). A stalled server surfaces in `%ms-exchange` as a
   clean **`microservice-conn-lost`** (`pal-timeout` translated) → the §4.5 bounded reconnect+retry path,
   never an infinite hang. (This also closes the Slice-1 review's *loopback-shaped boundedness* nit — a
   half-open peer can no longer block the client's `tcp-recv` forever.)

**Gap (b) — one-shot allocation amplification.** `%ms-recv-message` allocated the **declared** body length
up-front, so a 4-byte header declaring 256 MiB (the `+ms-max-message+` cap) forced a 256 MiB allocation
**before any body byte arrived** — a trickle of tiny requests each declaring 256 MiB = memory amplification.
**Fix:** the body is now read **incrementally** (`%ms-recv-body`) — the accumulator starts at
`min(body-len, +ms-recv-chunk+)` (64 KiB) and **grows geometrically, capped at body-len, only as bytes
actually arrive**, so allocated memory stays ≤ ~2× the bytes received. The `+ms-max-message+` **hard cap is
kept** (an over-cap declare is still rejected immediately, before any allocation). This is in the **shared**
reader, so it also caps a malicious server's huge-declared *response* against the client. (Measured: a
declared 256 MiB body with no data allocated **~3.6 MiB** on SBCL — 72× under the declared length, well below
the cap/4 test threshold — vs the ≥256 MiB the old code forced.)

**Gap (c) — accept-loop hot-spin.** The serve loop's `(t nil)` arm swallowed an accept failure and
immediately re-looped, so a persistent accept failure (fd exhaustion / EMFILE) became a **tight CPU spin**.
**Fix:** the loop counts consecutive accept failures and applies the pure `%ms-accept-backoff` policy —
**`:retry`** (sleep the bounded `*ms-accept-backoff-seconds*` = 50 ms then re-accept) below
`+ms-accept-max-fails+` = 128, **`:stop`** (end the loop with a log) past it. A successful accept resets the
count, so a transient failure stays non-fatal. No hot-spin, no silent infinite retry.

**Bounds-checking intact.** The incremental reader still validates every length/offset against the cap and
the buffer extent (operating contract §4); the DoS guards (max-message cap, read timeout, incremental alloc,
accept backoff) **are** the §4 resource-exhaustion guards. `defun*`/full ftypes throughout; DRY (the timeout
prim reuses `%setsockopt`; the shared reader protects both sides).

### 4.7 Slice 3c-3 — server multi-client concurrency (WP-DURABILITY-MS-MULTICLIENT, BUILT)

Slices 1–3c-2 left the server strictly **SERIAL**: one accept+serve thread served each connection to
completion (`%ms-serve-connection` looping to EOF) before accepting the next. A slow / stalled client parked
that single thread; the Slice-3c-2 read-timeout stopped it denying *forever*, but a client was still served
one-at-a-time. Slice 3c-3 makes the server serve **concurrent clients in parallel — SERVER-ONLY, zero
client / wire-protocol change** (the client chain state is client-side and unchanged).

**Per-connection serve threads + a locked registry.** `%ms-serve-loop` now **spawns a dedicated serve
thread** (`dds.pal:spawn` → `%ms-serve-connection-in-thread`) for each accepted connection and immediately
loops to accept the next — so a slow client parks only **its own** thread. The single Slice-1 `conn-cell` is
replaced by a **lock-guarded connection registry** (`reg-cell` = a list of `ms-conn-slot {conn, thread}`,
guarded by `reg-lock`). `microservice-server-stop` sets the stop flag, wakes + **joins the accept-loop
thread first** (so no new slot is added after), then **drains the registry** — closing every live connection
(waking any serve thread parked in recv) and **joining every serve thread** — before closing the listener
and, LAST, the inner store (so no in-flight inner op races the close). A serve thread **self-removes** its
slot (under `reg-lock`) when its connection closes, freeing its cap slot promptly. The registration is
**race-free**: the reserve-and-spawn runs *under* `reg-lock`, so a serve thread cannot self-remove (nor stop
drain) before its slot's `thread` is stored.

**Connection cap.** `make-microservice-server :max-connections` (default `+ms-default-max-connections+` = 64)
bounds the concurrent serve threads: under `reg-lock`, if the live count (`(length (car reg-cell))`, read
under the lock — no separate counter to drift) has reached the cap a newly accepted connection is
**REJECTED** (closed immediately) — a connection flood cannot grow threads unbounded (operating contract §4).
A slot frees the moment any connection closes, so the cap **recovers**.

**The load-bearing correctness — every server-side shared mutable state is locked.** The concurrency
audit (the enumeration the review demanded):

1. **The inner store** — shared across serve threads; every op handler dispatches to an **internally-locked**
   inner op (memory `%mem-*` under one lock; file / SQLite under their own lock [+ SQLite transaction]).
   Each `%ms-handle-request` op is exactly ONE inner call, over fresh per-request buffers — no server-side
   unlocked access to inner internals, no cross-op read-modify-write in a handler.
2. **THE critical fix — `store-replace-topic` atomicity.** The memory inner's `store-replace-topic` was the
   NIL-fallback **purge + bulk-put — two SEPARATE locked ops**, atomic *only because the server was serial*.
   Under concurrency a `get-range` interleaving between the purge and the re-put sees a **partial / empty
   topic** → a corrupt / short read (for the client chain verify, a spurious mismatch or data loss). Slice
   3c-3 gives the memory store a native **`:replace-topic-fn` that holds its lock ACROSS the clear + bulk
   re-insert as ONE critical section** (`%mem-replace-topic`, reusing `%mem-put-unlocked` per record, DRY),
   so no concurrent op ever observes a partial topic. (The file `%rewrite-topic-log` tmp+rename and the
   SQLite single transaction were **already** atomic *and* serialize under their per-store lock — confirmed;
   only the memory tier had the two-op window.) This is proven RED→GREEN by
   `run-durability-mem-replace-atomicity-test`: a debug barrier lands a concurrent `get-range` at the swap
   midpoint — non-atomic (`*durability-debug-mem-replace-nonatomic*` T) it reads an EMPTY partial (RED);
   atomic (default) it blocks on the held lock and reads the full post topic (GREEN).
3. **The registry + live count** — every add / remove / drain / count under `reg-lock`.
4. **Per-connection state** — the `ms-conn-slot`, the `ms-reader`, the `%ms-buf` accumulator, the received
   body — all per-thread / freshly allocated; no two serve threads share a connection or a buffer.
5. **Stop vs a mid-op serve thread** — a clean shutdown (close-to-wake + join, inner closed LAST): an
   in-flight inner op (atomic) completes before its thread exits; no half-write to a persistent inner.

**The slow-drip residual (§7) is STRUCTURALLY FIXED** — a stalled client parks only its own serve thread; a
concurrent client is served in parallel, the service is not denied
(`run-durability-microservice-slow-drip-concurrent-test`, with the server read-timeout NIL, so it isolates
the structural fix from the DoS timeout). The read-timeout's remaining multi-client role is to **reclaim** a
parked slow-loris's thread + cap slot (`run-durability-microservice-slow-loris-test`, re-targeted from
"denies → served" to "slot not-reclaimed → reclaimed").

**Portable + clean-room.** `dds.pal:spawn` / `join` / `make-lock` / `with-lock` only (the reader
conditionals stay in `dds-pal`); no new crypto, no new dependency, `defun*` / full ftypes, DRY, bounds-checks
intact. Five new tests (headline concurrent-clients-correct, memory-replace-atomicity RED→GREEN,
stop-closes-all, max-connections-cap, slow-drip-parks-own-thread); both impls green **identically, Clasp
first: Suite 507 → 512** (SBCL is the race-correctness oracle; Clasp threading held — no NFR-PORT flake this
slice).

**Tests** (all bare-transport, always run — the hardening is below DARE):
- **`run-durability-microservice-slow-loris-test`** (headline, RED→GREEN in one test): RED (server
  `:recv-timeout` NIL) — a slow-loris parks the serial serve thread and a spawned subsequent client is
  **DENIED** (bounded 2 s wait, `done` never set); GREEN (server `:recv-timeout 1`) — the read-timeout drops
  the loris and the subsequent client is **SERVED**. Standalone confirmation: `served=NIL` (RED) vs `served=T`
  (GREEN).
- **`run-durability-microservice-huge-declared-test`**: an over-cap declare is rejected as a protocol error
  before any allocation; a huge (at-cap) declare with no body **times out** via the incremental reader (no
  infinite block / OOM — behavioral proof on both impls) and allocates **<< the declared length** (numeric
  proof where the impl exposes a consing counter — SBCL; Clasp `bytes-consed`=0, a documented NFR-PORT gap, so
  the numeric bound is runtime-gated on `(plusp (bytes-consed))`, **not** a reader conditional).
- **`run-durability-microservice-client-timeout-test`**: a stalling server → the client recv-timeout →
  `conn-lost` → reconnect → retry → clean `microservice-store-error`, **bounded** (asserted < 10 s), no hang.
- **`run-durability-microservice-accept-backoff-test`**: UNIT — `%ms-accept-backoff` returns `:retry` below
  the threshold and `:stop` past it, and the pause is positive+bounded; FAULT-INJECTION — 3 forced accept
  failures (`*durability-debug-ms-force-accept-fail*`, set GLOBALLY so the serve thread sees it) drive the
  backoff path then the loop **recovers** and serves a round-trip (transient failure non-fatal).
- **`run-durability-microservice-fuzz-test`** EXTENDED with a slow-loris arm (a header then stall → server
  read-timeout drop, serve thread survives) and an over-cap arm (protocol-error drop, serve thread survives),
  then a valid client round-trips.

Both impls **503 → 507 passed** (Clasp first, then SBCL), identical; gate-hotpath (8 files clean) +
gate-types (2594 ftype'd) PASS; SBOM unchanged. No new crypto, no new dependency, no reader conditionals
outside `dds-pal`.

## 5. Files

- `src/dds-pal/pal-contract.lisp` — export the `tcp-*` block; **Slice 3c-2 (§4.6):** add `pal-timeout`
  condition + `tcp-set-recv-timeout` to the exports.
- `src/dds-pal/pal-net.lisp` — the seven TCP primitives + Darwin `SO_NOSIGPIPE`, mirroring the UDP block.
  **Slice 3c-2 (§4.6):** `+so-rcvtimeo+` OS constant, `tcp-set-recv-timeout` (SO_RCVTIMEO struct-timeval), and
  `tcp-recv` split so a timeout (`n=NIL`) signals `pal-timeout` distinct from a clean EOF (`n=0` → NIL).
- `src/dds-durability/store-microservice.lisp` — the protocol, `make-microservice-store` (client),
  `make-microservice-server` / `microservice-server-port` / `microservice-server-stop` (server), and
  **Slice 2** `make-microservice-store-factory` (the DARE-wrapping factory — forward-references
  `make-encrypted-store` exactly as `make-sqlite-store-factory` does). **Slice 3a:**
  `make-microservice-server` gains `:history-kind`/`:history-depth` + opens the inner at server-start;
  `+ms-op-open` becomes a policy-confirm no-op. **Slice 3b:** `make-microservice-store` fills the
  `:set-chain-mac-fn` slot (client-side remote-tier v3 chain-MAC) + the fold/strip/verify helpers
  (`%ms-fold-payload` / `%ms-unfold-payload` / `%ms-verify-chain` / `%ms-decode-strip-verify` /
  `%ms-get-range-verified`) reusing the file/SQLite chain crypto (`%frame-record-versioned` / `%chain-seed`);
  the server functions are byte-identical. **Slice 3d (§4.4):** the chained `:delete` becomes
  `%ms-delete-rechain` (get-range + drop + `%ms-rechain-survivors` re-MAC + `+ms-op-topic-rewrite+` op),
  the server gains the `+ms-op-topic-rewrite+` opaque-replace branch, and `*durability-debug-ms-skip-reclaim-remac*`
  is the RED knob. **Slice 3c-1 (§4.5):** the conn-cell becomes an `ms-conn` `defstruct*`
  (host/port/sock + `ever-connected-p` + `closed-p`) + the `%ms-dial` (clears `closed-p` on a successful dial
  — Fix B) / `%ms-ensure-connected` / `%ms-reconnect` / `%ms-resync-topic` / `%ms-resync-if-stale` /
  `%ms-reseal-stale-topics` helpers + the `microservice-conn-lost` condition + `*ms-reconnect-backoff-seconds*`
  + the `stale-topics` set; `%ms-exchange` translates send/recv drops to `microservice-conn-lost`, `%ms-call`
  does the bounded reconnect+retry-once **and re-dials from the DROPPED state (Fix 2)**, the chained put /
  purge / `%ms-delete-rechain` **mark stale on exhaustion + re-sync before the next mutation (Fix 1)**, the
  `:chain-tails-fn` seal **resyncs-or-skips stale topics (Fix A)** so no diverged `(N, M_N)` is committed, and
  the bare `:delete` tolerates `+ms-result-rejected+`. Five test-only knobs
  (`*durability-debug-ms-force-recv-drop*` [+ `*...-drop-op*`] / `*...-skip-stale-resync*` /
  `*...-skip-redial-dropped*`). The factory docstring's HISTORY-QoS "known limitation" is rewritten to the
  **descope** (the decorator owns retention; server stays KEEP_ALL). Client-side only — server byte-identical.
  **Slice 3c-2 (§4.6):** the DoS hardening — `+ms-default-recv-timeout+` / `+ms-recv-chunk+` /
  `+ms-accept-max-fails+` constants + `*ms-accept-backoff-seconds*` / `*durability-debug-ms-force-accept-fail*`
  params; `%ms-recv-body` (incremental body read) replaces the one-shot alloc in `%ms-recv-message`; the
  `ms-conn` + server structs gain a `recv-timeout` slot (`%ms-dial` / `make-microservice-store` client-side,
  `%ms-serve-connection` / `make-microservice-server` server-side); `%ms-exchange` translates `pal-timeout`
  → `microservice-conn-lost`; `%ms-serve-loop` gains the `%ms-accept-backoff` policy + backoff sleep.
  **Slice 3c-3 (§4.7):** the multi-client server — the `+ms-default-max-connections+` constant + an
  `ms-conn-slot` `defstruct*`; the server struct swaps the single `conn-cell` for a lock-guarded registry
  (`reg-cell` + `reg-lock`) + a `max-connections` cap; `%ms-serve-loop` now spawns `%ms-serve-connection-in-thread`
  per accepted connection (race-free reserve-and-spawn under `reg-lock` + the cap reject) instead of serving
  inline; `microservice-server-stop` joins the accept loop then drains the registry (close-to-wake + join
  every serve thread, inner closed LAST). Server-only, client + wire byte-identical.
- `src/dds-durability/store.lisp` — **Slice 3d** the additive NIL-fallback `store-replace-topic` dispatcher
  + `replace-topic-fn` vtable slot (the fallback is `store-purge` + bulk `store-put`). **Slice 3c-3 (§4.7):**
  the memory store now SUPPLIES `:replace-topic-fn` — `%mem-replace-topic` holds the store lock ACROSS the
  clear + bulk re-insert (ONE critical section, reusing the extracted lock-free `%mem-put-unlocked`, DRY), so
  a concurrent multi-client op never sees a partial topic (the serial-era purge+bulk-put window is closed);
  `*durability-debug-mem-replace-nonatomic*` / `*-barrier*` are the RED/GREEN test knobs.
- `src/dds-durability/store-file.lisp` — **Slice 3d** the atomic `:replace-topic-fn` slot (reuses
  `%rewrite-topic-log` tmp+fsync+rename + index/counter rebuild).
- `src/dds-durability/store-sqlite.lisp` — **Slice 3d** the atomic `:replace-topic-fn` slot (a single
  transaction: DELETE topic + INSERT survivors).
- `src/dds-durability/spec.lisp` — **Slice 3a** `make-durability-store-factory` (the shared
  backend-dispatch seam: file / sqlite / microservice).
- `src/dds-durability/packages.lisp` — export the new symbols (Slice 2 adds
  `make-microservice-store-factory`; Slice 3a adds `make-durability-store-factory`; Slice 3d adds
  `store-replace-topic`).
- `interop/durability-persistent/driver-collect.lisp` + `driver-serve.lisp` — **Slice 3a** wire
  `DPERSIST_BACKEND` (`file`|`sqlite`|`microservice`) + `DPERSIST_MS_HOST`/`DPERSIST_MS_PORT` through the
  shared dispatch.
- `dds-durability.asd` — `(:file "store-microservice")` after `store-sqlite`.
- `src/dds-tests/durability-test.lisp` — Slice 1: `run-pal-tcp-loopback-test`,
  `run-durability-microservice-test`, `run-durability-microservice-large-test`,
  `run-durability-microservice-torn-test`, `run-durability-microservice-fuzz-test`. Slice 2:
  `run-durability-microservice-factory-test` (structural composition, DARE-free) +
  `run-durability-microservice-dare-test` (no-plaintext-at-server GREEN/RED + round-trip-through-DARE;
  skips if OpenSSL < 3.5), with the `%tms-flatten-store` inner-record byte-scan helper. **Slice 3a:**
  `run-durability-microservice-cross-restart-test` (bare file + sqlite GREEN, memory RED),
  `run-durability-microservice-dare-cross-restart-test` (DARE-wrapped on-disk-ciphertext + decrypt-recover;
  skips if OpenSSL < 3.5), `run-durability-microservice-lifecycle-test` (server-owned multi-session),
  `run-durability-microservice-config-env-test` (structural), with the shared `%tms-put-2topic-fixture` /
  `%tms-verify-2topic-fixture` / `%tms-bare-cross-restart-arm` helpers. **Slice 3b:**
  `run-durability-microservice-remote-chain-test` (malicious-server DROP/TAMPER/REORDER detection + RED
  bare-store contrast + tail-truncation/whole-topic-drop residuals + round-trip/cross-restart through the
  chain + NIL-oracle regression; skips if OpenSSL < 3.5). **Slice 3d:**
  `run-durability-microservice-keep-last-reclaim-test` (brick-repro → CLEAN + RED knob + server-DARE-blind +
  sustained tamper-evidence + cross-restart re-MAC + crash-fault-mid-replace rollback; skips if OpenSSL < 3.5),
  and `run-durability-microservice-remote-chain-test` gains a reclaim + whole-topic-drop-still-detected arm.
  **Slice 3c-1 (§4.5):** `run-durability-microservice-reconnect-test` (DARE-wrapped reconnect-after-restart +
  idempotent-retry-chain-verify; skips if OpenSSL < 3.5) + `run-durability-microservice-reconnect-bare-test`
  (bare reconnect-after-restart + send-side-error-clean + no-infinite-loop + bare-delete-tolerates-rejected;
  always runs) — the fixed-port restart via ephemeral-then-reuse (SO_REUSEADDR).
  **Slice 3c-2 (§4.6):** `run-durability-microservice-slow-loris-test` (RED-denied → GREEN-served),
  `run-durability-microservice-huge-declared-test` (over-cap reject + at-cap incremental-read timeout +
  bounded alloc), `run-durability-microservice-client-timeout-test` (stalling server → clean conn-lost,
  bounded), `run-durability-microservice-accept-backoff-test` (unit decision + fault-injected recover) — all
  bare-transport, always run; plus the slow-loris + over-cap arms added to `run-durability-microservice-fuzz-test`.
  **Slice 3c-3 (§4.7):** the multi-client suite — `run-durability-mem-replace-atomicity-test`
  (the memory-replace RED→GREEN via the barrier knob), `run-durability-microservice-concurrent-clients-test`
  (headline: N clients × mixed ops × rounds → byte-exact, no loss/dup/corruption),
  `run-durability-microservice-stop-closes-all-test` (N live conns → drained + joined, no leak/hang),
  `run-durability-microservice-max-connections-test` (cap reject → existing-works → close → recover), and
  `run-durability-microservice-slow-drip-concurrent-test` (a stalled client parks its own thread, a concurrent
  client is served); the `%tms-wait-until` / `%tms-live-conns` bounded-probe helpers; and
  `run-durability-microservice-slow-loris-test` is **re-targeted** from "denies → served" (serial) to
  "slot not-reclaimed → reclaimed" (multi-client).
- `src/dds-pal/pal-net.lisp` / `pal-contract.lisp` — **Slice 3c-2** the `tcp-set-recv-timeout` prim +
  `pal-timeout` condition + the `tcp-recv` timeout/EOF split (see §4.6 / the §5 PAL entries above).
  **Slice 3c-3 nit:** the `tcp-recv` docstring is corrected — `n=NIL` is a timeout OR an EINTR-interrupted
  receive, both conservatively classified `pal-timeout` (identical disposition: drop / reconnect).

## 6. Consequences

- The vtable is confirmed as the stable backend API: a FOURTH backend fills it with zero vtable change,
  and a *remote* one at that — the abstraction survives a process boundary.
- No new dependency (`sb-bsd-sockets` is the baseline UDP substrate); the SBOM is unchanged.
- Both impls green identically, Clasp first: `pal-tcp-loopback`, `durability-microservice` (round-trip
  byte-exact + (guid,sn)-ordered + counts + idempotent re-put no-op + delete + purge),
  `durability-microservice-large` (500 KB multi-segment byte-exact), `durability-microservice-torn`
  (clean failure on peer-close), `durability-microservice-fuzz` (malformed-UTF-8 topics drop their
  connection + the serve thread survives + a subsequent valid client succeeds; garbled server response →
  clean client error). Suite 482 → 487.
- **Slice 2 (WP-DURABILITY-MICROSERVICE-2):** the composition capability 6 × capability 7 proves out with
  a client-side factory and **zero server change**. Both impls green identically, Clasp first:
  `durability-microservice-factory` (the factory composes `encrypted-store` OVER `microservice-store`,
  name `:encrypted-persistent`; DARE-free, always runs) and `durability-microservice-dare` (**no plaintext
  at the server** — with `encrypted-store(microservice-store(inner memory))`, a put of plaintext topic
  `"Square"` + a distinctive GUID/SN/payload leaves the server holding only a hex topic-hash, a GUID
  surrogate, sn = 0, and sealed ciphertext, with the topic name / GUID bytes / SN bytes / payload bytes
  ALL absent from a full byte-scan of the server's inner records; a RED bare `microservice-store` leaks
  all four; **round-trip through DARE** recovers the real topic/GUID/SN/kind/key-hash/payload byte-exact +
  (guid,sn)-ordered + idempotent re-put + logical count). Suite 487 → 489.
- **Slice 3a (WP-DURABILITY-MICROSERVICE-3A):** the microservice becomes a REAL persistence backend — the
  server OWNS a persistent (file/SQLite) inner (open@server-start replaying from disk, close@server-stop
  fsyncing), cross-restart recovery proves out (bare file + SQLite GREEN, memory RED; DARE-wrapped with
  opaque-on-disk + client-side decrypt), multi-session server-owned lifecycle holds, and the
  `DPERSIST_BACKEND=microservice` config-env seam (`make-durability-store-factory`) is wired into both
  drivers. **Zero vtable change; zero wire-protocol change** (the `+ms-op-open`/`+ms-op-close` *semantics*
  shift to server-owned, the bytes are identical). Both impls green identically, Clasp first: Suite 489 →
  493 (`durability-microservice-cross-restart`, `durability-microservice-dare-cross-restart`,
  `durability-microservice-lifecycle`, `durability-microservice-config-env`).
- **Slice 3b (WP-DURABILITY-MICROSERVICE-3B):** the client-side v3 chain-MAC over the remote tier closes the
  §4.1 remote-untrusted-store residual for **drop / reorder / tamper** (file/SQLite tamper-evidence parity) —
  the client computes the ADR-0045 chain locally and FOLDS the MAC + chain_seq into the opaque payload, so the
  server + wire protocol are **byte-identical** (the mac/chain_seq the server never parses). Fills the existing
  `:set-chain-mac-fn` slot (no vtable change); reuses `%frame-record-versioned`/`%chain-seed`/the
  `%sqlite-verify-topic` shape (no new crypto, no new dep). Verify-on-open is fail-closed. Residual (deferred,
  = file/SQLite): tail-truncation + whole-topic-drop → ADR 0045 §7 anchor. Both impls green identically, Clasp
  first: Suite 493 → 494 (`durability-microservice-remote-chain`).
- **Slice 3c-1 (WP-DURABILITY-MS-RECONNECT):** the client no longer bricks on a dropped connection — a server
  restart / network blip triggers a **bounded single reconnect + idempotent retry** (§4.5), the send-side
  raw-error wart is translated to the one clean `microservice-store-error`, an **exhausted-retry marks the
  topic stale + re-syncs before the next chained mutation** (Fix 1: no chain fork → no false-reject brick), an
  **op-during-outage re-dials** from the DROPPED state (Fix 2: no terminal "store is not open"), the **clean-
  close seal resyncs-or-skips stale topics** (Fix A: an apply-then-ack-lost purge/rewrite never seals a
  diverged `(N, M_N)` → no later-open false-reject brick — a pre-existing worst-class bug closed cheaply), and
  a **same-object close→reopen works** (Fix B). **Client-side only; zero server / wire-protocol change** (the
  server holds zero per-session state). HISTORY-QoS-over-the-wire forwarding is **descoped** (the decorator owns
  retention; the server stays KEEP_ALL — §4.2/§7). Both impls green identically, Clasp first: Suite 499 → 503
  (`durability-microservice-reconnect`, `...-bare`, `...-exhausted`, `...-seal`).
- **Slice 3c-2 (WP-DURABILITY-MS-DOS):** the server (and the shared reader, which also protects the client) is
  hardened against a malicious/abusive peer — a **read/idle timeout** (new PAL `tcp-set-recv-timeout` /
  `SO_RCVTIMEO` → `pal-timeout`, portable both impls, reader-conditionals inside `dds-pal` only) so a
  **slow-loris no longer denies the serial server** (it is dropped and the accept loop serves the next
  client) and a stalled server surfaces as a clean client `conn-lost` (the §4.5 reconnect); **incremental body
  allocation** so a huge *declared* length no longer forces a huge up-front alloc (amplification guard,
  measured ~3.6 MiB for a declared 256 MiB); and an **accept-loop backoff** so a persistent accept failure
  backs off instead of hot-spinning. The `+ms-max-message+` hard cap is kept. **No wire-protocol change, no new
  crypto, no new dependency.** Configurable timeouts (`make-microservice-server` / `make-microservice-store`
  `:recv-timeout`, default 30 s). Both impls green identically, Clasp first: Suite 503 → 507
  (`durability-microservice-slow-loris`, `...-huge-declared`, `...-client-timeout`, `...-accept-backoff`; +
  the fuzz gate extended). Headline (as of Slice 3c-2): with the timeout DISABLED a slow-loris denied a
  subsequent client on the SERIAL server. **(Superseded by Slice 3c-3, §4.7:** the server is now multi-client,
  so a slow-loris no longer denies anyone regardless of the timeout — the read-timeout's role becomes
  RECLAIMING the parked slot, and the slow-loris test is re-targeted accordingly.)
- **Slice 3c-3 (WP-DURABILITY-MS-MULTICLIENT):** the server serves **concurrent clients in parallel** —
  per-connection serve threads + a lock-guarded connection registry (drained + joined on stop, no leak/hang)
  + a `:max-connections` cap (default 64; a flood is rejected, not unbounded thread growth). The load-bearing
  fix is the memory `store-replace-topic` **atomicity** (one lock hold across clear+refill; the serial-era
  two-op purge+bulk-put window is closed) — proven RED→GREEN. Every server-side shared mutable state is
  locked (inner store internally-locked per op + the now-atomic replace; the registry under `reg-lock`;
  per-connection buffers are per-thread). The §7 slow-drip residual is **structurally fixed** (a stalled
  client parks its own thread). Server-only — client + wire byte-identical; no new crypto / dependency. Both
  impls green identically, Clasp first: **Suite 507 → 512** (`durability-mem-replace-atomicity`,
  `...-concurrent-clients`, `...-stop-closes-all`, `...-max-connections`, `...-slow-drip-concurrent`). SBCL is
  the race oracle; Clasp threading held (no NFR-PORT flake this slice).

## 7. Scope — Slice 1 and the deferred slices

**Slice 1 (built):** PAL TCP prims; the length-prefixed protocol reusing the file-store frame;
the client vtable-fill (connect-on-open, memory-tier `sync`/`set-chain-mac-fn` NIL); the reference
opaque-proxy server over an inner memory store; round-trip byte-exact + ordered + large multi-segment +
torn-read, both impls.

**Slice 2 (built, §4.1):** `make-microservice-store-factory` = `make-encrypted-store` OVER the
microservice-store (the server stays a DARE-blind opaque proxy; zero server change) — the client seals +
MACs locally, the remote server stores only opaque ciphertext; the no-plaintext-at-server proof + the
round-trip-through-DARE byte-exactness, both impls.

**Slice 3a (built, §4.2):** the server OWNS a PERSISTENT (file/SQLite) inner (open@server-start replaying
from disk, close@server-stop fsync); `+ms-op-open` = policy-confirm no-op, `+ms-op-close` = session-end;
cross-restart recovery proven bare (file + SQLite GREEN, memory RED) + DARE-wrapped (opaque-on-disk at the
server, client-side decrypt); server-owned multi-session lifecycle; the `DPERSIST_BACKEND=microservice`
config-env seam (`make-durability-store-factory`) in both durability-persistent drivers.

**Slice 3b (built, §4.3):** the client-side v3 chain-MAC over the remote tier — the client computes the
ADR-0045 keyed log-MAC chain locally (fills the `:set-chain-mac-fn` slot) and FOLDS the 32-byte MAC +
`chain_seq` into the opaque payload the DARE-blind server stores/returns verbatim (server + wire protocol
byte-identical); get-range strips + verifies, open verifies every topic fail-closed. Closes the §4.1
drop/reorder/tamper residual (file/SQLite parity). Residual (deferred, = file/SQLite): tail-truncation of a
valid prefix + whole-topic-drop → the ADR 0045 §7 sealed high-water anchor + a per-topic-set commitment.

**Slice 3d (built, §4.4):** the KEEP_LAST reclaim re-MAC over the wire — the chained `:delete` re-chains the
survivors client-side (mirroring `%rewrite-topic-log` / `%sqlite-recompute-topic`) and replaces the server's
opaque frames via a new `+ms-op-topic-rewrite+` op + an additive NIL-fallback `store-replace-topic` vtable slot
(memory purge+bulk-put; file/SQLite atomic tmp+rename / transaction). A KEEP_LAST encrypted microservice store
now reopens CLEAN through a physical reclaim; the server stays DARE-blind; tamper-evidence + the tail anchor
still hold over the re-chained survivors.

**Slice 3c-1 (built, §4.5):** bounded client reconnect + idempotent retry — the conn-cell becomes an
`ms-conn` struct carrying host/port/sock; a dropped connection (server restart / network blip) triggers a
BOUNDED single reconnect (close+clear+re-dial-once+retry-once, no unbounded loop / no hang) instead of the
Slice-1 permanent brick; the send-side raw-error wart is translated to the one clean `microservice-store-error`
(via `microservice-conn-lost`, a store-error subtype); every op is idempotent so a byte-identical retry cannot
dup/lose/corrupt (put INSERT-OR-IGNORE + post-confirm chain advance; topic-rewrite same-survivor replace; bare
delete tolerates `+ms-result-rejected+`). Client-side only, zero server / wire change (the server holds zero
per-session state).

**Slice 3c-3 (built, §4.7):** server multi-client concurrency — `%ms-serve-loop` spawns a per-connection
serve thread (`%ms-serve-connection-in-thread`) and immediately loops, so concurrent clients are served in
parallel; the single `conn-cell` becomes a lock-guarded registry (`reg-cell` + `reg-lock`) that
`microservice-server-stop` drains (close-to-wake + join every serve thread, inner closed LAST); a
`:max-connections` cap (default 64) rejects a connection flood. The load-bearing correctness is that EVERY
server-side shared mutable state is locked — the critical fix being the memory `store-replace-topic`
**atomicity** (a native `:replace-topic-fn` holding the store lock across clear+refill, replacing the
serial-era two-op purge+bulk-put that a concurrent `get-range` could catch mid-swap). Server-only — client +
wire byte-identical; no new crypto / dependency. This **structurally fixes the slow-drip residual** below (a
stalled client now parks only its own thread). Both impls green identically, Clasp first: Suite 507 → 512.

**Descoped:**
- **Slice 3c — HISTORY QoS over the wire (DESCOPED — MOOT under DARE, and WRONG).** Forwarding the
  client/service HISTORY QoS (`history-kind`/`depth`) to the remote inner is **not required** and is
  **descoped**: under the always-on DARE production composition the **encrypted-store decorator owns retention
  CLIENT-SIDE** — it opens the inner KEEP_ALL, logically compacts newest-D on get-range, and physically
  reclaims a keyed KEEP_LAST put's superseded surrogate via the §4.4 `store-delete`→`+ms-op-topic-rewrite+`
  survivor re-MAC (delivered + TESTED KEEP_LAST-through-microservice). The server MUST stay KEEP_ALL:
  server-side HISTORY-QoS is INERT under DARE (key-hash NIL) and WRONG (a server eviction of a chained record
  bricks the client `%ms-verify-chain`). The bare non-DARE path is not a production composition. (This
  supersedes the earlier Slice-3a "REQUIRED" framing; see §4.2.)

**Deferred:**
- **Slice 3c — remaining production posture.** Framing for very large `get-range` responses beyond the
  single-message `+ms-max-message+` ceiling (chunked/streamed); the `main.lisp` CLI `--backend` (the
  driver-env path already suffices); the full live 2-process microservice cross-DDS interop run. (**Multi-client
  concurrency** is now **BUILT** — §4.7, WP-DURABILITY-MS-MULTICLIENT; the per-connection **read-idle timeout**
  a blocked-mid-response read lacked is **BUILT** — §4.6.)
- **Slice 3c — DoS hardening (BUILT, §4.6, WP-DURABILITY-MS-DOS).** The three Slice-1 residuals are now closed:
  (a) the **read/idle timeout** — `%ms-recv-message` no longer parks the serial serve thread on a slow-loris;
  a stalled recv trips `pal-timeout` (via the new `tcp-set-recv-timeout` / `SO_RCVTIMEO` PAL prim) and the
  connection is dropped so the accept loop serves the next client (and the client side surfaces a clean
  `conn-lost` → reconnect); (b) the **one-shot allocation** — `%ms-recv-body` grows the body buffer as bytes
  arrive (the `+ms-max-message+` cap still rejects an over-cap declare up front), so a huge *declared* length
  no longer forces a huge allocation (the amplification is closed); (c) the **accept-loop hot-spin** — a
  persistent accept failure now backs off (`%ms-accept-backoff`) instead of spinning. Configurable timeouts,
  both impls, reader-conditionals inside `dds-pal` only.
