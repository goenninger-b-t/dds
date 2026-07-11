# ZC overlay: is the `-into-sap` direct seal worth it? — measured 2026-07-11

**Question.** ADR 0051 deferred follow-on 2 proposes an into-SAP AEAD variant that would seal the
serialized payload **straight into the SHMEM pool slot**, eliminating the one writer-side
scratch→slot memcpy the overlay currently performs. Before rewriting the sealing primitive (the most
security-critical code we have) to write through raw SAP stores into shared memory, measure what the
memcpy actually costs.

**Method.** The overlay send path is: `encode-serialized-payload-into` (one AEAD pass over the
payload, writing the §9.5.3.3 SecuredPayload into a pooled static scratch) followed by `%zc-loan`
copying those sealed bytes into the pool slot. The optimization can remove **only the second step**.
So: time the seal, and time a copy of the *sealed length*, at representative ZC payload sizes
(`*zerocopy-min-payload-bytes*` gates ZC to large payloads). ENCRYPT tier (AES-256-GCM), SBCL,
2000 iterations each, warm.

| payload (B) | seal µs/op | memcpy µs/op | memcpy share of seal+copy |
|---|---|---|---|
| 4 096 | 6.689 | 0.178 | **2.6 %** |
| 16 384 | 22.864 | 1.080 | **4.5 %** |
| 65 536 | 94.251 | 3.373 | **3.5 %** |

**Result.** The AEAD pass dominates the copy by roughly **25×**. The memcpy the optimization would
remove is **2.6–4.5 %** of the overlay's send cost — and that is its *ceiling*, since a direct seal
still pays the full AEAD pass.

**Decision — the deferral is CLOSED as declined (ADR 0058).** A ~3 % gain on an opt-in edge path
(ENCRYPT/SIGN + Zero-Copy + SHMEM) does not justify:

- forking or rewriting `encode-serialized-payload-into` — the single sealing primitive every
  `data_protection` tier depends on — onto a second, SAP-writing code path (duplicated §9.5.3.3
  framing arithmetic is precisely where crypto bugs hide), and
- sealing **into shared memory**, so the slot transiently holds partially-written AEAD state. The
  ADR-0042 acquire/commit generation protocol does keep that invisible to a lock-free reader (the
  generation is published only after the write), but it is new exposure for a 3 % return.

**What would change the answer.** The ratio is what makes this a bad trade, not the idea. If the
AEAD ever stops dominating — hardware crypto offload, a DMA/accelerator path, or a tier that does far
less work per byte — re-run this bench. If `memcpy share` ever exceeds ~20 %, the direct seal is worth
reconsidering.
