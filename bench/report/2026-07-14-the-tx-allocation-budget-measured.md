# The TX allocation budget, measured — and "zero-alloc TX" is 1136 B/sample of it

> ## ⚠️ CORRECTION (2026-07-14) — THE PER-SITE NUMBERS BELOW ARE INFLATED. USE `gate-mem` AS THE ORACLE.
>
> **Ground truth:** `%reader-routes-for` measured **328 B/sample** with the harness below. Memoizing it —
> eliminating essentially all of it (it is called **2.00×/sample** and the memo hits **100 %**; the cache is
> never invalidated in steady state) — moved the real total by **88 B** (3648 → 3560, per `gate-mem`).
>
> The true cost was therefore ~48 B/call: a `copy-list` (16 B) + a pair cons + a list cons. **The harness
> over-reported it by ~3.5×.**
>
> **I do not know the mechanism, and I am not going to invent one.** My first guess — that the wrapper's
> `&rest`/`apply` consed an argument list — is **DISPROVEN**: the exact harness shape measures **0.0 B/call**
> (1-value and 2-value callees alike). I published that guess as a correction before testing the real shape,
> which is precisely the error this note exists to warn about.
>
> **What holds:** the **TOTALS** are sound (3648 B/sample measured with no wrappers, reproduced by
> `gate-mem`). The **per-site numbers rank candidates but do not size them.** Any claimed win must be
> confirmed end-to-end by `gate-mem` before it is believed.
>
> Third instrument to mislead on this task, after `sb-sprof`'s byte attribution (twice, ADR 0062). The rule
> gains a corollary: *size with a `bytes-consed` delta — then verify the delta against `gate-mem`, because
> the delta can be wrong too.*

**Date:** 2026-07-14 · **task #29 / ADR 0062 (NFR-MEM)** · SBCL 2.6.5, arm64 Darwin
Two participants in ONE process, **payload = 0** (the FIXED per-sample overhead, which is what dominates),
n = 3000, `bytes-consed` deltas around each callee. **Not `sb-sprof`** — ADR 0062 records two occasions where
its byte attribution was flatly wrong (`dispatch-message` profiled 8.2 %, was worth 84 B; `call-with-mutex`
profiled 12.4 %, and `dds.pal:with-lock` measures 0.0 B/acquisition).

## The budget

Total round-trip **3648 B/sample** (whole process, includes the receiver threads).

```
publish-sample-into              1136 B/sample     <- shipped as "WP-8.T1 zero-alloc TX" (c89aae0)
publish-sample                   1136
  %push-one-writer-changes        743
    %send-changes-packed          349              <- the per-send datagram PLAN
    %capture-push-groups          197
      %match-destinations-prefixed 87
      %reader-push-targets         22
  writer-write                    196              <- the cache-change struct
%write-key-hash                   175              <- the generated type-support keyhash
%sample-serializer-into            22              <- the serializer closure
%deadline-touch-writer              0
assert-liveliness                   0
realtime-ns                         0
hc-add-change                       0              <- the payload POOL genuinely works
writer-acquire-payload-buffer       0              <-   "        "         "      "
--------------------------------------------------
TX (write-sample, user thread)  ~1300 B/sample
receiver threads + engine       ~2350 B/sample     (the larger half — NOT yet drilled)
```

**The arena pooling that `c89aae0` shipped is real and it works** — `hc-add-change` and
`writer-acquire-payload-buffer` both measure **0**. It removed the *payload* allocation and left everything
around it. That is why "zero-alloc TX" was recorded as done while `write-sample` still allocates 1.3 KB with
**nothing to serialize**.

## What each item actually is (read before touching any of them)

1. **`%send-changes-packed` — 349 B. A per-sample datagram PLAN of closures.**
   `%changes-datagram-plan` returns, per its own docstring, *"a list of (BUILD-THUNK . SHMEM-DEST), each
   BUILD-THUNK a lambda (buf) -> octet-length"*. So every write conses a plan list, a `(cons (cons host port)
   plan)`, `%pack-plan`'s `groups`/`cur` lists, and one **closure per submessage**. The plan-then-execute
   split exists so the eager flush and the one-datagram-at-a-time step are byte-identical *by construction* —
   which is a real property, and any fast path MUST preserve it. The common case is **one small change + an
   optional HEARTBEAT to one destination**; that case can be built and sent directly with no plan and no
   closures. **Byte-identical wire is the gate; `make corpus` + the tshark `wire` gate + interop must all
   stay green.**

2. **`%capture-push-groups` — 197 B.** Builds a `%zc-push-group` struct + lists per destination per send, for
   the **Zero-Copy multi-destination refcount** machinery (ADR 0047) — which is *off by default*
   (`*zerocopy-enabled*` NIL) and "NOT cleared for ship — pending counsel". This is the **same class** as
   `312db1b` ("stop building two hash tables per write for a Zero-Copy feature that is not in use"). A
   ZC-disabled fast path is the obvious move. Careful: `writer-capture-unsent` (advancing unsent-base +
   taking send-refs) is needed **regardless** and must not be skipped.

3. **`writer-write` — 196 B.** The `cache-change` struct. Pooling it is a **design change**, not a local
   edit: a change is retained until ACKed, so the reliable protocol owns its lifetime.

4. **`%write-key-hash` — 175 B.** The generated type-support keyhash, computed only for a **KEEP_LAST**
   writer (a KEEP_ALL writer never evicts per-instance, so it needs none — that path is already 0-alloc). The
   16-octet handle is ~32 B of this; the rest is a scratch buffer inside generated code. The handle is
   **RETAINED** (on the cache-change for KEEP_LAST eviction, and in the instance record), so pooling it
   touches the **FROZEN type-support contract** — ADR first (ADR 0062 §5).

## The other half, also measured — RX + the drain

Same method. The three top-level buckets account for the whole 3648 B:

| bucket | B/sample | share |
|---|---|---|
| **RX `%handle-datagram`** (receiver thread) | **1420** | 39 % |
| **TX `write-sample`** (user thread) | 1376 | 38 % |
| **USER `%drain`** (the take path) | 808 | 22 % |

Inside RX:

```
RX %handle-datagram              1420
  dispatch-message               1027
    %on-user-data                 393
      %deliver-user-sample        349
    %on-user-heartbeat            393      <- a CONTROL message costs as much as the DATA
    %on-user-acknack              175
  %reader-routes-for              328      <- THE SINGLE BIGGEST RX ITEM
  %source-guid                    131
  reader-acknack                   22
  reader-on-data                    0      <- the reliable reader itself is clean
USER %drain                       808
  %deserialize-sample             218
```

**`%on-user-heartbeat` costs as much as `%on-user-data` (393 B each).** The reliable protocol's *control*
path allocates as much as the data path — that is not where anyone would have looked.

**`%reader-routes-for` — 328 B — is the single biggest RX item, and the cause is one line:**

```lisp
(let ((ids (with-lock (copy-list (gethash writer-guid (disc-node-reader-routes node))))))
  (if ids (loop for rid in ids
                for r = (%user-reader-for node rid)
                when r collect (cons rid r))   ; fresh list + fresh cons per route, EVERY call
          ...))
```

A `copy-list` plus a freshly-consed pair list on **every** data / heartbeat / gap handler call — for a value
that changes only on match/unmatch.

**It memoizes — but do NOT rush it.** The invalidation points are several (`route-add` disc.lisp:716, the
route-prune disc.lisp:887, `%purge-prefix` on `disc-node-reader-routes` in two places, and the
lease/dispose prune), and a **stale route is silent mis-delivery** — data lost, or delivered to a dead
reader. That is a correctness hazard, not a perf one. Memoize it with the invalidation driven from the
choke points that already exist (`%fire-unmatch` is now the single unmatch funnel; ADR 0063 §3), and gate it
on the live re-match repro (`scratchpad/responder.lisp` + `rematch.lisp`), not just the unit suite.

`%source-guid` (131 B) allocates a fresh 16-octet GUID several times per datagram. **CAUTION:** an earlier
audit established that its result IS retained (it is the key for the reader-proxy, the sample store, and the
instance tables), so it cannot simply be turned into a shared scratch buffer.

## Guardrail

`make gate-mem` now ratchets this number (`bench/mem-ceiling.txt`, currently 3800). It fails on a regression
**and** on an improvement that does not lower the ceiling — so every step here must bank its win.
