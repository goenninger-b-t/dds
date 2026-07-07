# ADR 0050 — Durability MICROSERVICE persistence backend (a durable-store proxied over TCP)

Status: Accepted
Date: 2026-07-07
Work package: WP-DURABILITY-MICROSERVICE-1 (Slice 1) + WP-DURABILITY-MICROSERVICE-2 (Slice 2 — DARE-wrap) + WP-DURABILITY-MICROSERVICE-3A (Slice 3a — server-owned persistent inner + cross-restart + config-env seam) (ADR 0021 capability 6 — the last of the owner's pluggable persistence tiers: file / db / MICROSERVICE — composed with capability 7, the always-on DARE)
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

The chain-MAC oracle install (`store-set-chain-mac-fn`, driven by the decorator on open + first put) is a
documented **no-op** at the microservice tier (the `:set-chain-mac-fn` slot is NIL — the same slot profile
as `make-memory-store`), so the cross-frame keyed log-MAC chain (ADR 0045) is absent there; **per-record
DARE-GCM still authenticates each frame** (confidentiality + per-record integrity: an attacker cannot read,
forge, or alter a frame's decrypted contents — GCM + the AAD + the HMAC surrogate binding prevent that, and
reorder is neutralized because the client re-sorts by the decrypted `(guid, sn)`).

**Integrity residual — REMOTE-UNTRUSTED-STORE threat (Slice-3 mitigation required, not merely optional).**
What the absent chain leaves unprotected is the **completeness and freshness of the record sequence**: a
malicious or compromised *remote* microservice server can silently **drop, truncate, or roll back (serve
stale)** sealed records, undetected — a late-joiner fed by this tier could receive a silently-truncated
history. This is NOT byte-for-byte the memory-store story, and it must not be sold as such: for
`make-memory-store` the store is **intra-process**, so an adversary able to tamper with it already holds the
keys and the absent chain is moot; a microservice store sits **across a trust boundary** and is precisely
the untrusted-storage adversary the cross-frame chain was built to catch — and the **file/SQLite tiers, which
face the identical on-disk-tamper threat, DO carry the chain** (`store-set-chain-mac-fn`, ADR 0045). So the
microservice tier currently ships memory-tier sequence-integrity for a file-tier-or-worse threat model. The
confidentiality goal of this slice (no plaintext at the server) is fully met and comprehensively tested; the
**client-side v3 chain-MAC over the microservice tier is a Slice-3 requirement** (compute the ADR-0045 chain
locally in the decorator and ship the 32-byte MAC as an extra opaque field the server stores blindly, keeping
the server a dumb KV proxy) that closes the drop/truncate/rollback gap for a production remote deployment. A
secondary at-rest metadata residual for the remote case: beyond the (documented 3c) topic-hash linkability +
per-topic-hash record counts, a remote server additionally observes **live access-pattern timing** (put/get
op arrival) — the standard opaque-proxy tradeoff, noted here for the remote threat model.

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

**KNOWN LIMITATION (HISTORY QoS not forwarded — a Slice-3c gap for the live path).** The microservice
inner tier's retention policy is **SERVER-configured** (`make-microservice-server`
`:history-kind`/`:history-depth`, applied at server-start), **NOT forwarded from the client/service HISTORY
QoS over the wire**: the shared dispatch's microservice branch does not pass `history-kind`/`depth` (unlike
the sqlite/file branches), and `+ms-op-open` decodes them only to bounds-validate, then discards. So a
durability service configured e.g. KEEP_LAST 5 against a **default keep-all** reference server
**OVER-RETAINS** — a late joiner receives full history instead of newest-D per instance (a silent DDS
DURABILITY_SERVICE/HISTORY QoS gap; **over-retention, NOT data-loss/false-reject**). The operator MUST
configure the reference server's `:history-kind`/`:history-depth` to match the service's HISTORY QoS. This
only bites the deferred **live 2-process** path (all in-process tests use keep-all and pass). **Forwarding
the policy over the wire (so the service's HISTORY QoS drives the remote inner's retention) + a
KEEP_LAST-through-microservice test are a REQUIRED Slice-3c item** (§7) — a durability service that silently
ignores HISTORY QoS on a backend is a real QoS gap for the live path.

**Deferred beyond 3a:** the client-side v3 chain-MAC over the remote tier (**Slice 3b** — remote-untrusted-
store sequence integrity, §4.1); HISTORY-QoS-over-the-wire forwarding (**Slice 3c**, REQUIRED — the
known-limitation above); graceful reconnect / multi-client concurrency / chunked large get-range /
DoS-hardening (**Slice 3c**). The DARE crypto + the bounds-checked wire parser are unchanged.

## 5. Files

- `src/dds-pal/pal-contract.lisp` — export the `tcp-*` block.
- `src/dds-pal/pal-net.lisp` — the seven TCP primitives + Darwin `SO_NOSIGPIPE`, mirroring the UDP block.
- `src/dds-durability/store-microservice.lisp` — the protocol, `make-microservice-store` (client),
  `make-microservice-server` / `microservice-server-port` / `microservice-server-stop` (server), and
  **Slice 2** `make-microservice-store-factory` (the DARE-wrapping factory — forward-references
  `make-encrypted-store` exactly as `make-sqlite-store-factory` does). **Slice 3a:**
  `make-microservice-server` gains `:history-kind`/`:history-depth` + opens the inner at server-start;
  `+ms-op-open` becomes a policy-confirm no-op.
- `src/dds-durability/spec.lisp` — **Slice 3a** `make-durability-store-factory` (the shared
  backend-dispatch seam: file / sqlite / microservice).
- `src/dds-durability/packages.lisp` — export the new symbols (Slice 2 adds
  `make-microservice-store-factory`; Slice 3a adds `make-durability-store-factory`).
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
  `%tms-verify-2topic-fixture` / `%tms-bare-cross-restart-arm` helpers.

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

**Deferred:**
- **Slice 3b — remote-untrusted-store sequence integrity (client-side v3 chain-MAC).** Close the §4.1
  drop/truncate/rollback gap: compute the ADR-0045 cross-frame keyed log-MAC chain **client-side** in the
  decorator and ship the 32-byte MAC as an extra opaque field the microservice server stores blindly
  (keeping the server a dumb DARE-blind KV proxy), giving the remote tier the same sequence tamper-evidence
  the file/SQLite tiers already have. Required for a production remote deployment against a malicious server
  — not merely optional (the memory-parity analogy does not carry across the trust boundary).
- **Slice 3c — HISTORY QoS over the wire (REQUIRED, the §4.2 known-limitation).** Forward the
  client/service HISTORY QoS (`history-kind`/`depth`) to the remote inner so the service's DURABILITY_SERVICE
  HISTORY drives the remote retention (today it is SERVER-configured only, and a client KEEP_LAST vs a
  keep-all server silently OVER-RETAINS on the live path); add a KEEP_LAST-through-microservice test. Not
  optional — a durability backend that silently ignores HISTORY QoS is a real QoS gap for the live path.
- **Slice 3c — remaining production posture.** Graceful reconnect / error-recovery (Slice 1 surfaces a lost
  server as a clean `microservice-store-error` and connects-on-open with no retry); multi-client concurrency
  (the server serves one client at a time); framing for very large `get-range` responses beyond the
  single-message `+ms-max-message+` ceiling (chunked/streamed); the `main.lisp` CLI `--backend` (the
  driver-env path already suffices); the full live 2-process microservice cross-DDS interop run.
- **Slice 3c — DoS hardening (bounded, not a spin, in Slice 1; documented).** `%ms-recv-message` allocates
  the body buffer from the *declared* length before the body arrives, so a peer declaring up to the
  256 MiB `+ms-max-message+` cap forces a large one-shot allocation on a 4-byte header (an amplification),
  and a never-completing partial send parks the serve thread (a slow-loris — bounded + blocking, *not* a
  spin; the cap correctly defeats the multi-GB case, and the per-connection `serious-condition` backstop
  means one stuck connection cannot corrupt others). Slice 3 hardens this with incremental allocation (grow
  the body buffer as bytes arrive) and a per-connection read-idle timeout, consistent with the error/DoS
  posture already deferred here.
