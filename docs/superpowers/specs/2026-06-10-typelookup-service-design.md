# XTypes TypeLookup service with assignability-gated matching + Connext interop

- **Date:** 2026-06-10
- **Status:** Design — approved for planning
- **Area:** L3 type system (service-type codecs, MinimalTypeObject deserializer), L5 discovery (builtin request/reply endpoints, match gating), interop harness
- **Requirements:** FR-TYPE-3 (TypeLookup service), FR-TYPE-4 (assignability / TYPE_CONSISTENCY_ENFORCEMENT at match time), FR-IO-1 (Connext interop), NFR-SEC-POSTURE (bounds + resource guards), the operating contract §4 (the wire is the oracle) and §6 (gates)

## 1. Goal & scope

Implement the XTypes 1.3 **built-in TypeLookup service** (§7.6.3.3): four builtin request/reply endpoints through which a DomainParticipant serves the `TypeObject`s of its announced types (`getTypes`) and their dependencies (`getTypeDependencies`), and queries peers for unknown remote types. The retrieved `MinimalTypeObject` feeds **real structural assignability that gates endpoint matching** when type information exists; matching falls back to today's name-based behavior when it does not.

In scope:
- XCDR2 codecs for `TypeLookup_Request` / `TypeLookup_Reply` and their constituent types (`RequestHeader`, `SampleIdentity`, the call/return unions, the MUTABLE in/out structs).
- A **MinimalTypeObject deserializer** (`parse-minimal-type-object`) — the inverse of the existing serializer — producing our `minimal-struct-type` model.
- The four builtin endpoints (XTypes 1.3 Table 61 EntityIds) on the disc-node, server and client sides, with reply correlation and timeout.
- Match-time gating: assignability + `TYPE_CONSISTENCY_ENFORCEMENT` decide the match when a TypeObject is available (retrieved or cached); INCONSISTENT_TOPIC on rejection.
- Live bidirectional interop with RTI Connext 7.3.1.

Out of scope (recorded, not designed-out): serving/parsing EK_COMPLETE TypeObjects (minimal only in v1); continuation-point batching beyond single-batch replies; SCC/cyclic types (the DSL is acyclic); a general dds-rpc layer (FR-API-3 later — the reply-correlation code is shaped to be liftable); DynamicData.

## 2. Decisions (locked during brainstorming)

1. **Bidirectional v1** — we answer Connext's requests AND query Connext, consuming the reply into assignability (the M4 exit-gate wording).
2. **Gate when info exists** — assignability + TYPE_CONSISTENCY_ENFORCEMENT gate the match when the peer's TypeObject is available; name-based fallback when type info is absent, unparseable (`:unsupported`), or the lookup times out. Never block on absence.
3. **DoD = Connext-only, both directions** (owner decision; the open-source-peer fallback was declined). Stage 0 probes Connext's actual behavior first so an unmeetable gate surfaces immediately.
4. **Probe-first staging (approach A)** — announce the endpoint bits and capture Connext's reaction before writing codecs; pin codecs to the captured bytes.

## 3. Normative anchors (pin from `docs/specs/xtypes-1_3.pdf` at implementation time; cite the clause)

- Endpoints + EntityIds (Table 61): request writer `{00,03,00}c3`, request reader `{00,03,00}c4`, reply writer `{00,03,01}c3`, reply reader `{00,03,01}c4`.
- Endpoint QoS (§7.6.3.3.3): RELIABLE, KEEP_ALL, VOLATILE.
- `availableBuiltinEndpoints` bits (Table 62): request writer `1<<12`, request reader `1<<13`, reply writer `1<<14`, reply reader `1<<15` — added to our SPDP `PID_BUILTIN_ENDPOINT_SET`.
- Operation ids: `TypeLookup_getTypes_HashId = 0x018252d3`, `TypeLookup_getDependencies_HashId = 0x05aafb31`.
- Service types (§7.6.3.3.2/.3): MUTABLE in/out structs, `TypeLookup_Call`/`TypeLookup_Return` unions, `RequestHeader{requestId: SampleIdentity, instanceName: string<255>}`, `ReplyHeader{relatedRequestId, remoteEx}`.
- Instance name (§7.6.3.3.4): `"dds.builtin.TOS." + <participant GUID in lowercase hex>` — **the spec's own example is internally inconsistent about the length ("16-character" vs the example's 15 chars vs a 32-hex-char GUID); pin the exact string from the Stage-0 Connext capture, tolerate liberally on receive.**
- A participant implementing the service shall answer for any TypeIdentifier it announced in TypeInformation (§7.6.3.3.4) — guaranteed by construction via the registry index.

## 4. Architecture & components (stage = commit boundary)

**Stage 0 — live probe (no codecs).** Add the four Table 62 bits to our announced builtin endpoint set (we already emit `PID_TYPE_INFORMATION` in SEDP, b2a). Run against live Connext (shapes or large-data harness), capture lo0 + the LAN iface: (a) does Connext begin emitting `PID_TYPE_INFORMATION` (0x0075) to us — the ADR 0009 hypothesis that RTI withholds it from peers that don't announce the service? (b) does Connext issue `TypeLookup_Request`s toward our (announced, not-yet-implemented) request reader? Capture preserved; any inbound request's bytes become the Stage-1 oracle. **If Connext shows no TypeLookup traffic in either direction under any provocation, STOP and report to the owner — the Connext-only DoD is then unmeetable from our side.** Possible finding either way: if 0x0075 appears, the provisional EquivalenceHash gets its live oracle (ADR 0009 reopening — compare and record).

**Stage 1 — service-type codecs (`src/dds-types/typelookup.lisp`, package `dds.types`).** Hand-rolled XCDR2 codecs (the DSL has no union support; same hand-rolled pattern as discovery data): serialize/parse for `TypeLookup_Request` and `TypeLookup_Reply`, including `SampleIdentity` (GUID + SN), `RequestHeader`, both unions, both MUTABLE in/out structs (EMHEADER members, unknown-member skip), and the `TypeIdentifierTypeObjectPair` / `TypeIdentifierWithSize` sequences. Encapsulation pinned from the capture (expected PL_CDR2/D_CDR2 LE family). Byte-exact vs any Stage-0-captured request; bounds-checked; added to the fuzz target.

**Stage 2 — MinimalTypeObject deserializer (`src/dds-types/typeobject-cdr.lisp`).** `parse-minimal-type-object` (octets → `minimal-struct-type` | `:unsupported`): TK_STRUCTURE with the member kinds our model covers (primitives, string, plain sequences, nested EK_MINIMAL hash refs); DHEADER-driven, tolerant of appendable extra bytes, bounds-checked, `*max-type-object-bytes*`-guarded. Any TypeObject kind outside the model → `:unsupported` (downstream treats as no-type-info; never an error). Property test: `parse ∘ serialize ≡ identity` over generated types incl. nested structs.

**Stage 3 — service engine (`src/dds-disc/typelookup.lisp`, package `dds.disc`).**
- *Registry index:* equivalence-hash → type-support, built at type registration (hash via the existing `equivalence-hash`); answers both operations.
- *Server:* `%handle-datagram` dispatch branch for the TL request writer EntityId → per-remote reliable builtin reader (reusing the M2 `builtin-readers` machinery) → parse request → `getTypes`: look up each EK_MINIMAL hash, reply `TypeIdentifierTypeObjectPair`s (serialized via `minimal-type-object-octets`; `complete_to_minimal` empty — minimal-only v1); `getTypeDependencies`: walk member TIs collecting hash-kind deps + serialized sizes, single batch, empty `continuation_point`. Reply unicast via the TL reply writer, `relatedRequestId` = request's `SampleIdentity`, `REMOTE_EX_OK`; unknown union discriminator → `REMOTE_EX_UNKNOWN_OPERATION`.
- *Client:* `getTypes([H])` unicast to the announcing participant's request reader; pending table SN → parked-match + deadline; replies correlated by `relatedRequestId` on the TL reply reader; expiry swept by the existing announce/spin loop.

**Stage 4 — match gating.** A `type-gate` hook on the disc-node (installed by the dds-types-aware layer, the ADR 0008/0009 hook pattern): at SEDP match with remote TypeInformation hash H — H = ours → compatible; cached model for H → assess now; else park the match + fire the client request. Assessment = `struct-assignable-from` + the reader's `TYPE_CONSISTENCY_ENFORCEMENT` QoS; reject → no match + INCONSISTENT_TOPIC; timeout / no TypeInformation / `:unsupported` → name-based match (today's behavior). **Nested types:** equal nested member hashes short-circuit (hash equality ⇒ type equality); a differing nested hash whose TypeObject is needed for the verdict triggers a follow-up `getTypes` for the unresolved hashes within the same parked-match window, bounded by `*typelookup-max-depth*` (default 4 rounds); depth exhausted → name-based fallback for that match. Per-node H → model cache, bounded. The advisory LB fingerprint (`entity-type-compat`) stays unchanged.

**Stage 5 — live bidirectional Connext gate.** Connext resolves our type through our server (verified via its STATUS_ALL log + capture of its request and our reply); we resolve + gate on a Connext type through its server. Captured request/reply byte vectors locked as regression tests; docs/verification updated.

## 5. Data flow

**Server:** datagram → dispatch (writerId `0x000300C3`) → builtin reader → `parse-type-lookup-request` → instanceName targets us or empty (tolerant; wire-pinned) → operation → registry index → `serialize-type-lookup-reply` → reply writer → requester.

**Client:** SEDP match, unknown hash H → park match → `getTypes([H])` → … peer reply → correlate SN → `parse-minimal-type-object` → cache → gate (assignability + enforcement QoS) → complete/reject parked match. Timeout → name-match fallback. Cache hit or H = local hash → no round-trip.

## 6. Special variables (new; documented + spec-cited per the contract §5.1)

- `*typelookup-timeout*` — seconds to wait for a TypeLookup reply before falling back to name-based matching. Default **3**.
- `*max-typelookup-request-ids*` — max `type_ids` accepted in one inbound request. Default **32**.
- `*max-typelookup-pending*` — max in-flight client requests. Default **64**.
- `*max-typeobject-cache-entries*` — bound on the per-node hash→model cache. Default **256**.
- `*typelookup-max-depth*` — max follow-up `getTypes` rounds for unresolved nested hashes per match. Default **4**.
- (Reuses the existing `*max-type-object-bytes*` for inbound TypeObject size.)

## 7. Error handling & security (NFR-SEC-POSTURE)

- Every new parser bounds-checks lengths/offsets against the payload extent, even at `(safety 0)`; MUTABLE parsing skips unknown EMHEADER members (vendor extensions are expected and legal).
- Guards applied **before** allocation: request id count, reply/TypeObject octets, pending count, cache size.
- Malformed request → drop, no reply (no amplification); malformed/late/unknown-SN reply → drop (pending entry expires); non-empty inbound `continuation_point` → full single-batch reply with empty continuation out (documented v1 behavior).
- All allocation is control-plane (discovery-time) heap, same posture as SEDP; the per-sample hot path is untouched (`gate-hotpath` green by construction).
- All new parsers added to `make fuzz`.

## 8. Testing & Definition of Done

- **Codec round-trips + byte-exact vectors** from the Stage-0/Stage-5 captures (Connext's request and reply, and ours), fuzz green.
- **Deserializer property test** (`parse ∘ serialize ≡ identity`) + a real Connext-returned TypeObject locked as a vector.
- **Server unit test:** canned request octets → expected reply octets.
- **Offline two-node integration:** B matches A's type via TypeLookup and gates correctly; a deliberately incompatible type is rejected with INCONSISTENT_TOPIC; a timeout falls back to name-match.
- **Live Connext 7.3.1, both directions (the DoD):** Connext consumes our server; we consume Connext's server and gate on the result.
- **Gates:** full suite green SBCL + Clasp; gate-types; gate-hotpath; fuzz; `make wire`.
- Record whether Connext emits `PID_TYPE_INFORMATION` once we announce the service bits, and whether its minimal EquivalenceHash matches our provisional serializer output (ADR 0009 follow-up either way).

## 9. Staged implementation (commit per stage; main green throughout)

0. Probe: announce Table 62 bits + capture Connext's reaction (+ record findings; STOP-gate if Connext shows no TypeLookup behavior at all).
1. Service-type codecs + fuzz + capture-pinned vectors.
2. MinimalTypeObject deserializer + property/vector tests.
3. Service engine (registry index, server, client, pending table) + offline tests.
4. Match gating (type-gate hook, cache, nested follow-up, INCONSISTENT_TOPIC, fallbacks) + offline integration tests.
5. Live bidirectional Connext interop (fix what the wire reveals) + locked vectors + docs.

## 10. Risks & open questions

- **Connext may never exercise one or both directions** (vendor policy toward foreign-vendor services). Mitigated by the Stage-0 probe and its explicit STOP-gate back to the owner; the DoD is owner-locked to Connext-only, so this is the schedule risk, not a silent-failure risk.
- **Connext may request EK_COMPLETE TypeObjects** (RTI tooling prefers complete). v1 serves minimal only; if the probe shows complete-only requests, surface to the owner (scope decision: complete support is a large addition).
- **Instance-name format ambiguity** (spec text self-contradicts): pin from the capture; tolerate on receive.
- **Encapsulation/encoding quirks** in the service types (FastDDS↔RTI TypeLookup interop has a documented history of such bugs): mitigated by pinning to captured bytes, not just the spec.
- **Our provisional EquivalenceHash may be wrong** (ADR 0009): if Connext starts sending TypeInformation, the comparison is finally live — a mismatch means fixing the serializer to the oracle (a *good* outcome: byte-exactness restored where it was previously unverifiable).
