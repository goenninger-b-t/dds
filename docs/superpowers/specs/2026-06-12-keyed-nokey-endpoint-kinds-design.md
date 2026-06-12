# Per-type keyed / no-key endpoint kinds

- **Date:** 2026-06-12
- **Status:** Design — approved for planning.
- **Area:** L3 type system (`src/dds-types`, `src/dds-gen`), L5 discovery (`src/dds-disc/{disc,dataplane}.lisp`), L6 DCPS (`src/dds-dcps/entities.lisp`), `dds-tests`, `interop/connext/`
- **Requirements:** FR-RTPS (RTPS entity kinds — the keyed-only residual); FR-IO-1 (Connext interop); the operating contract §4 (the wire is the oracle).

## 1. Goal & scope

The stack is **keyed-only**: `add-local-writer` hardcodes RTPS entity kind `0x02` (user writer WITH key), `add-local-reader` `0x07` (user reader WITH key), and the data plane (`dataplane.lisp`) routes via the fixed `+user-writer-id+` `0x00000102` / `+user-reader-id+` `0x00000107`. A no-key type (no `@key` members) must instead announce writer kind `0x03` / reader kind `0x04` so it matches a no-key peer (and a keyed/no-key pair does **not** match). This feature derives the entity kind from the type's keyed-ness and threads it through discovery + the data plane, verified offline and against live Connext.

In scope: keyed-ness derivation from the type; entity-kind selection in `add-local-writer/reader`; the data-plane entity-ids becoming the endpoint's actual ids; the keyed/no-key match-rejection rule; a no-key test type; a no-key Connext interop app + live verification.

Out of scope (unchanged): multi-endpoint-per-participant (still one writer + one reader per participant); the entity KEY portion (`000001`) stays fixed; content-filter/QoS interactions beyond the kind octet.

## 2. Decisions (locked during brainstorming, owner-approved)

1. **Approach A** — derive keyed-ness from a new `type-support` `keyed-p` flag (set by `define-dds-type` from the `@key` members), `:keyed` parameter on `add-local-*`, the disc-node stores its actual user writer/reader entity-ids for the data plane. Rejected: (B) passing a raw kind octet at every call site (duplicates the 0x02/0x03 detail into DCPS + the harness; the type-support is the single source of truth), (C) always announcing both keyed + no-key endpoint sets (YAGNI, announces phantom endpoints).
2. **Matching rule** — a keyed/no-key disagreement is a **silent non-match**, NOT INCONSISTENT_TOPIC (a fundamental endpoint-kind incompatibility; the existing `%reader-guid-p`/`%writer-guid-p` predicates already distinguish the octets).
3. **Back-compat** — `:keyed` defaults to **T** everywhere, so every existing caller and the keyed ShapeType path is byte-identical; the data-plane id threading preserves `0x102`/`0x107` exactly for keyed types.
4. **Verification = offline + live Connext** (owner pick over offline-only / keyed-regression-only): a no-key Connext app proves the wire.

## 3. Normative anchors (pin from the specs at implementation time; cite the clause in code)

- **RTPS 2.5 §9.3.1.2 (Table 9.1, EntityId / entityKind octet):** application-defined writer WITH_KEY `0x02` / NO_KEY `0x03`; reader WITH_KEY `0x07` / NO_KEY `0x04`. (The values already in `dataplane.lisp`'s predicates — confirm against the clause.)
- **DDS 1.4 / RTPS:** a writer and reader match only when their TopicKind (WITH_KEY vs NO_KEY) agrees, alongside topic name + type + RxO QoS. Keyed-ness is a property of the type (has `@key`).

## 4. Architecture & components

Six small units (each a clear responsibility; most are a few lines):

1. **Keyed-ness on the type (`src/dds-gen/dsl.lisp`, `src/dds-types`):** `type-support` gains a `keyed-p` boolean slot; `define-dds-type` sets it true iff the type has ≥1 `@key` member (the DSL already enumerates keys for `%key-max-size`). Exposed as `type-support-keyed-p`. (A type whose keyed-ness can't be determined defaults to keyed — the current behavior — so nothing regresses.)
2. **Entity-kind selection (`src/dds-disc/disc.lisp`):** `add-local-writer`/`add-local-reader` gain `:keyed` (default T). Writer kind = `keyed ? #x02 : #x03`; reader kind = `keyed ? #x07 : #x04`. The entity KEY (`000001`) is unchanged. The returned endpoint-data carries the selected GUID.
3. **Data-plane ids (`src/dds-disc/{disc,dataplane}.lisp`):** the disc-node stores its actual local user writer-id and reader-id (derived from the local endpoint's keyed-ness at `add-local-*` time). The data-plane send/ACKNACK/HEARTBEAT paths read those node fields instead of the fixed `+user-writer-id+`/`+user-reader-id+`. The constants remain as the keyed defaults (and document the kinds); a keyed type yields exactly `0x102`/`0x107`.
4. **Match-rejection (`src/dds-disc/disc.lisp` `%match-remote-endpoint`):** before recording a match, require the local and remote endpoint keyed-ness to agree (writer kind `0x02`↔reader kind `0x07` keyed; `0x03`↔`0x04` no-key — i.e. the writer's WITH/NO_KEY must equal the reader's). A disagreement → no match (return without recording, no INCONSISTENT_TOPIC). Keyed-ness read from the GUID entity-kind octet via small predicates (reuse/extend `%reader-guid-p`/`%writer-guid-p`).
5. **DCPS threading (`src/dds-dcps/entities.lisp`):** `create-datawriter`/`create-datareader` pass `:keyed (type-support-keyed-p (topic-type-support topic))` into `add-local-*`.
6. **Test + interop types:** a no-key DSL test type (a struct with no `@key`) for the offline round-trip + match-rejection; a no-key Connext IDL + app under `interop/connext/` for the live leg.

## 5. Data flow

Type (`@key` or not) → `type-support.keyed-p` (set by `define-dds-type`) → DCPS `create-datawriter/reader` → `add-local-writer/reader :keyed` → entity-kind octet in the SEDP-announced GUID **and** the disc-node's data-plane writer/reader id. A remote endpoint's keyed-ness is read from its announced GUID's entity-kind octet; `%match-remote-endpoint` matches only when keyed-ness agrees (in addition to topic + type + RxO). The data plane sends/ACKNACKs/HEARTBEATs under the node's actual ids, so a no-key endpoint speaks `0x03`/`0x04` on the wire and a keyed one speaks `0x102`/`0x107` exactly as today.

## 6. Error handling & back-compat

- **Default keyed.** `:keyed` defaults T; `type-support-keyed-p` defaults T when undeterminable. Every existing call site, the keyed ShapeType harness, and the keyed Connext interop are byte-identical (verified by the unchanged keyed live interop in S1).
- **No silent mis-route.** The data-plane ids must reflect the announced kind exactly; a mismatch between the announced GUID kind and the data-plane id would break the peer's HEARTBEAT/ACKNACK routing (the M2 lesson). A test asserts the keyed type still yields `0x102`/`0x107` and the no-key type yields `0x103`/`0x104`.
- **Match-rejection is a non-event, not an error.** A keyed/no-key pair simply never matches — no INCONSISTENT_TOPIC, no listener fired (the kinds are incompatible at the RTPS layer, below type consistency).

## 7. Testing

- **Offline (S0):** a no-key DSL type round-trips our-writer → our-reader (node-to-node UDP loopback, like the existing data-plane tests) with kind `0x03`/`0x04` on the wire; a keyed local endpoint does NOT match a no-key remote (and vice versa); the keyed type still yields `0x102`/`0x107` (no regression). Suite green SBCL per task, Clasp at the stage boundary.
- **Live Connext (S1):** a no-key Connext app (new `interop/connext/` subdir + IDL) ↔ our no-key endpoints: forward Connext no-key pub → our no-key sub and reverse, samples delivered, tshark-validated kind `0x03`/`0x04` on the wire; a keyed-vs-no-key non-match proven live (a Connext keyed reader does not match our no-key writer); the existing keyed ShapeType interop re-run green (no regression). Captures archived.
- **Gates:** `make gate-types` + `make gate-hotpath` green (these paths are control-plane; the kind octet is set at endpoint creation, not per sample).
- Docs (verification.csv FR-RTPS, wiki, README, provenance) in lockstep.

## 8. Stages (commit boundaries)

- **S0 — offline mechanism.** `keyed-p` on type-support + `define-dds-type`; `:keyed` kind selection in `add-local-*`; the node's data-plane id threading; the `%match-remote-endpoint` keyed-ness guard; DCPS threading; a no-key test type. Tests: no-key node-to-node round-trip, keyed/no-key non-match, keyed-id-unchanged. Exit: offline no-key works, keyed not regressed, suite green SBCL+Clasp.
- **S1 — live Connext no-key.** Build a no-key Connext app (IDL + pub/sub) under `interop/connext/`; verify bidirectional no-key round-trip (tshark kind `0x03`/`0x04`) + a keyed-vs-no-key live non-match + the keyed ShapeType regression re-run. Captures archived; any wire bug fixed clause-cited with a regression test. Exit: live no-key interop both directions, keyed not regressed.
- **S2 — closeout.** verification.csv FR-RTPS (keyed-only residual closed), wiki (discovery/dataplane pages), README, provenance, memory. Exit: docs lockstep; full gates green.

## 9. Definition of Done

A no-key type is announced with entity kind `0x03` (writer) / `0x04` (reader) and round-trips both our-stack (node-to-node) and live Connext 7.3.1 in both directions; a keyed/no-key endpoint pair does not match (proven offline and live); the existing keyed ShapeType interop is not regressed; the keyed path still yields `0x102`/`0x107` exactly. Suite green on SBCL and Clasp; gate-types + gate-hotpath green. Docs in lockstep.
