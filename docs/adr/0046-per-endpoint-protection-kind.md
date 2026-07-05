# ADR 0046 — Per-role protection kind: fix the cross-role SecuredPayload/metadata downgrade (false-ACCEPT)

- **Status:** Accepted (M7/P6; WP-SECURITY-PER-ENDPOINT-PROTECTION-KIND, 2026-07-05)
- **Relates to:** ADR 0040 (Slice-5c review follow-on 1 — the participant-default + per-topic `%refine-user-protection` resolver this ADR completes for the cross-role case); ADR 0037 / ADR 0031 (the serialized-payload SecuredPayload codec and metadata_protection submessage tier this gates); NFR-SEC-POSTURE (fail-closed, **a false-REJECT is the worst defect class** — so the fix is per-role, NOT most-protective-monotonic, which would over-protect a NONE role); NFR-PORT (Clasp + SBCL both validate, Clasp first; no reader conditionals outside `dds-pal/`).
- **Standards:** OMG DDS-Security 1.1 §9.4.1.2.4 (per-topic `data_protection_kind` / `metadata_protection_kind` — a writer and a reader on DIFFERENT topics get DIFFERENT rules); §9.5 (EntityCrypto keying — the writer EntityId and reader EntityId are distinct crypto entities, each with its own KeyMaterial).

---

## Context

The prior fix (ADR 0040 Slice-5c review follow-on 1) closed the *participant-default* downgrade: `%install-access-control` stamps the MOST-PROTECTIVE kind over all topic rules, and `add-local-{writer,reader}` REFINE that to the endpoint's ACTUAL per-topic kind via a resolver. That is correct for a **single endpoint**. It left a residual: the writer and the reader **share one participant-global protection-kind pair** on the disc-node — `disc-node-user-data-protection-kind` + `disc-node-user-submessage-protection-kind`. `%refine-user-protection` and `%set-user-metadata-protection` MUTATE those shared slots on *every* add-local — **last-write-wins**.

A code probe found this is a REAL, reachable, fail-closed defect via the public DCPS API. Governance: `Circle` `data_protection=ENCRYPT`, `Square` `data_protection=NONE`.

1. `create-datawriter(Circle)` → live `user-writer` = Circle; shared slot := `:encrypt`.
2. `create-datareader(Square)` → refine sets the SHARED slot := `:none` (Square is NONE), but leaves `user-writer` = Circle **live and publishable**.
3. `circle_writer.write(sample)` → `publish-sample`'s SecuredPayload gate reads the shared slot, sees `:none`, **skips the SecuredPayload transform → the payload is emitted PLAINTEXT on the ENCRYPT Circle topic** = a silent protection downgrade / **false-ACCEPT**.

RED proof (current code, `publish-sample` driven end-to-end with OpenSSL): the Circle ENCRYPT writer emits the plaintext `01 02 03 04 05 06 07 08` VERBATIM after the Square NONE reader is added. The same last-write-wins path downgrades `user-submessage-protection-kind` (metadata_protection) for the Circle writer's user submessages.

The writer and reader are DIFFERENT EntityIds (`user-writer-id` vs `user-reader-id`) → they mint DIFFERENT EntityCrypto KeyMaterials (§9.5); independent per-role kinds are fully representable. The single-KM limitation (ADR 0040) is `data`-vs-`metadata` on ONE endpoint, NOT writer-vs-reader.

**Masked case (out of scope, unchanged):** two WRITERS (or two readers) — the second `enable-publisher` replaces the single engine writer, so the first is not independently publishable (the documented one-writer-per-node v1). Supporting N concurrently-live user writers/readers each with an independent kind is the larger multi-endpoint refactor — a documented follow-on, not built here.

---

## Decision

**Resolve and CACHE each role's protection kind from ITS OWN topic, into PER-ROLE disc-node fields — never a shared slot either role mutates.** Four new fields:

- `user-writer-data-protection-kind` / `user-writer-submessage-protection-kind`
- `user-reader-data-protection-kind` / `user-reader-submessage-protection-kind`

Defaults mirror the old shared slots (`:unset` data, `:none` submessage) so the no-governance / direct-KM / keyed-pubsub paths are byte-identical.

1. **Per-role resolve at enable time (cached, no per-sample resolve).** `%refine-user-protection` gains a ROLE argument; `add-local-writer` refines the WRITER fields from the writer's topic, `add-local-reader` the READER fields from the reader's topic. `%set-user-metadata-protection` (DCPS create path) is likewise role-scoped. Adding a reader NEVER changes the writer's fields, and vice versa.
2. **Publish uses the WRITER's kind.** `publish-sample`'s SecuredPayload gate reads `user-writer-data-protection-kind` (the live single `user-writer`'s cached kind), never the shared slot.
3. **Receive/reader uses the READER's kind.** `%deliver-user-sample`'s SecuredPayload DECODE gate reads `user-reader-data-protection-kind`.
4. **Submessage protection is per-role at the resolver.** `disc-node-user-submessage-encode` (called per submessage with `writer-p`) returns the WRITER's submessage kind for a writer-sourced submessage (DATA), the READER's for a reader-sourced one (ACKNACK/NACK_FRAG). A NONE role → the resolver declines → the submessage rides plain (no over-protection).
5. **Crypto KM per role.** `%cm-entity-protection-kind` derives the km kind from the role that owns the EntityId — `user-writer-id` → the writer's kinds, `user-reader-id` → the reader's — so the writer's km is ENCRYPT and the reader's km is NONE independently.
6. **Shared slots kept as a MOST-PROTECTIVE MAX (monotonic, never a downgrade) for the participant-scope consumers only.** The refine/set functions maintain `disc-node-user-{data,submessage}-protection-kind` = `max(writer, reader)` (rank `:encrypt`>`:sign`>`:none`>`:unset`). Those slots now feed ONLY the datagram-level fast-skip gate (`%maybe-wrap-user-submessages`), the prescan, and the Zero-Copy/loan-write wire-protection guards — all of which are participant-scope decisions where a MAX is conservative and fail-closed (it can never skip a wrap or admit plaintext into a pool when ANY live role is protected; the actual per-submessage/per-endpoint action is decided per-role by items 2–5). A MAX here can only ever OVER-conservatively fall back a Zero-Copy fast path to the byte-identical normal send — never a wire change, never a false-REJECT.

## Fail-closed invariants (all hold)

1. **No false-ACCEPT (the fix):** a writer on a protected topic ALWAYS emits protected — `publish-sample` reads the writer's OWN cached kind, immune to any reader/endpoint the participant later adds.
2. **No silent downgrade:** no later endpoint can lower a live endpoint's kind (per-role fields are role-private; the shared MAX is monotonic).
3. **No false-REJECT / no over-protection:** a genuine NONE-topic writer still emits PLAIN, and a NONE-topic reader rides plain — each role uses ITS topic's kind. This is precisely why the fix is **per-role, not most-protective-monotonic on the effective kind**: a monotonic effective kind would force-protect the NONE role (a false-REJECT / interop break with a peer expecting plain on that topic).
4. **Mixed-kind guard preserved:** the install-time reject of `data`≠`metadata` non-NONE on ONE endpoint (`governance-mixed-nonnone-kind-conflict`, ADR 0040) is orthogonal (a per-endpoint constraint) and unchanged.

## Wire / performance

When protection IS engaged, the emitted bytes for a given (endpoint, topic, kind) are BYTE-IDENTICAL to what the correct kind produced before — this ADR changes WHICH kind a role uses, not the transform. NONE paths stay plain. Corpora / KATs / goldens untouched. The publish gate reads a cached per-role slot (one slot read, no per-sample resolve/alloc/CLOS) — hot path unchanged; no bench.

## Scope boundary

This fixes the CROSS-ROLE (one live user writer + one live user reader) downgrade. The full multi-endpoint model — N concurrently-live user writers/readers each with an independent kind and its own engine writer — remains a separate, larger architectural WP (documented follow-on).

## Consequences

- Positive: the false-ACCEPT is eliminated by construction; the writer's protection is decoupled from reader churn; per-role EntityCrypto keying is exact.
- Neutral: four new disc-node slots + a role argument threaded through two refine functions; the shared slots remain for participant-scope consumers, now monotonic.
- Tests: `run-security-data-protection-downgrade-test` / `run-security-metadata-protection-downgrade-test` rewritten to exercise the CROSS-ROLE publish (RED on the old shared-slot logic, GREEN after) + a no-over-protection arm (NONE writer + later ENCRYPT reader → writer still PLAIN). `run-security-mixed-kind-reject-test` unchanged.
