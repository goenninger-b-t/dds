# The receive path rebuilt the source GUID three times per sample

**NFR-MEM / FR-PF-7 · arm64 (Apple silicon), SBCL · `make gate-mem`, 60000 samples, own process per arm**

| | before | after | delta |
|---|---|---|---|
| COPY | 1329.2 | **1232.0** / 1228.5 / 1232.5 | **−97.2** |
| RETURN | 1120.3 | **1017.8** / 1023.8 / 1021.6 | **−102.5** |

Ceilings lowered **1360 → 1265** (COPY) and **1155 → 1055** (RETURN). x86_64 keeps its dash.

## The defect

`%source-guid` assembles the 16-octet source GUID from the datagram's header prefix and a submessage's
EntityId — a `make-array` of 16 octets, **32 B** with its SBCL header. On the receive path it ran three
times for every sample:

| site | what it built |
|---|---|
| `%on-user-data` | `eff-guid`, the logical-origin key for the dedup gate |
| `%deliver-user-sample` | `guid` — **the same (prefix, writer) the caller had just built** |
| `%on-user-heartbeat` | `wguid`, to look up the matched writer's route |

The second is the sharpest: on the direct path `eff-guid` and `guid` are the same sixteen bytes, built
twice, one line apart in the call chain, and both kept.

**This is the defect ADR 0088 already fixed on the writer's control path** — a GUID built per ACKNACK
purely to index a table — at a fraction of this volume.

## The fix, and why a cache rather than a scratch

A per-receiver-thread **write-once cache**: 16 direct-mapped slots indexed by the EntityId folded against
the prefix's last octet. A hit validates the slot against `(prefix, writer-id)` — **EntityId first, because
that is what differs between two endpoints of one peer, so a wrong slot is rejected in four comparisons**
— and returns the cached array. A miss or a collision allocates exactly as before and stores it.

It cannot be a reused scratch buffer, and the reason is the same one ADR 0088 settled on principle. **The
GUID is retained by design, everywhere:** the reliable reader-proxy key, the outer key of the two-level
(source-GUID → SN) sample store, the dedup gate's logical origin, the ZC loan handle, and — since ADR 0090
A3b — `SampleInfo.publication_handle`, which **aliases it into the application**. A recycled mutable buffer
would make every one of those name whichever peer sent the next datagram.

So a slot is only ever **replaced, never written into**, and an evicted peer's next datagram mints a new
equal array. Two samples from one writer now **share** one GUID object where they previously held equal
copies — sound for exactly that reason, and it is what makes the redundant second build disappear on its
own rather than by a special case.

## Reaching the delivery path without widening every hook

The cache lives on the per-receiver `rx-context` (with the cursor and prefix cache from the earlier
slices), and `%handle-datagram` binds it to `*rx-context*` per datagram — **the same mechanism and the same
dynamic extent as `*rx-source-timestamp*`**, which this very function already binds per datagram and
`%deliver-user-sample` already reads. A dynamic binding is per-thread by construction, costs no heap, and
does not push an argument through every data-plane hook signature.

Off the receiver thread `*rx-context*` is `NIL` and `%source-guid-cached` **is** `%source-guid`, allocation
for allocation — so the durability replay and the value-level tests are byte-identical.

Twelve call sites moved: the three per-sample ones above, plus the lifecycle, ZC-marker, GAP, DATA_FRAG and
HEARTBEAT_FRAG hooks, several of which called `%source-guid` two or three times in one body.

## Verification

SBCL 623/623, Clasp 623/623, `gate-hotpath` PASS, `gate-nocond` PASS, `gate-mem` PASS with both ceilings
lowered. Predicted 96 B/sample (3 × 32); measured **−97.2 / −102.5** — the RETURN arm goes slightly further
because the rarely-hit handlers were double-building too.

## Session position

Four slices, every one measured end-to-end:

| | start | now | total |
|---|---|---|---|
| COPY | 1550.0 | **1232.0** | **−318.0 (−20.5 %)** |
| RETURN | 1342.2 | **1017.8** | **−324.4 (−24.2 %)** |

The receive pipeline was 688 B/sample when the bisect started and is now under 330. What remains there, in
order: the ACKNACK emit `%send-msg-buf` (~98), `writer-purge-acked` (~56), `parse-acknack-body`'s
SequenceNumberSet bitmap (~55), `reader-on-heartbeat` (~29), the peers list (~23). **The TX write path
(~426 B/sample) is now the largest single block in the whole measurement and has not been touched this
session.** Neither has the arena half of the directive.
