# Type system & code generation (L3)

This page covers **L3**, the type layer: the `dds.gen:define-dds-type` s-expr DSL, the `dds.types:type-support` manual vtable + registry, the in-memory XTypes structural model (TypeIdentifier / Minimal struct TypeObject / NameHash), structural assignability + `TYPE_CONSISTENCY_ENFORCEMENT`, the XCDR2 TypeObject serializer + EquivalenceHash, and the TypeInformation codec. L3 is the **linchpin of the no-CLOS-on-the-hot-path strategy**: `define-dds-type` is a build-time macro that emits a `defstruct` plus monomorphic, fully `ftype`-declared serialize/deserialize/serialized-size functions and registers a `type-support` — a plain `defstruct` of closures. The engine's hot path funcalls those slots and never sees the concrete sample type or any `defgeneric`/`defmethod` dispatch. The control-plane pieces (the XTypes model, assignability, the TypeObject/TypeInformation codecs) are also CLOS-free `defstruct` + monomorphic functions, but they run off the hot path.

See also: [CDR codec, buffers & the arena](cdr-and-memory.md) for the codecs and the `cursor`/arena the generated code drives, [QoS & RxO matching](qos.md) for the `TYPE_CONSISTENCY_ENFORCEMENT` policy carrier, [DCPS — the DDS entity API](dcps.md) for where types are registered with topics, and [Interop with RTI Connext](interop.md) for the live-peer oracles (the TypeObject/TypeInformation hash bytes are now locked against live Fast DDS 3.6.1; Connext never emits the minimal hash).

## API reference

### Code generation — `dds.gen`

- **`dds.gen:define-dds-type`** — macro; defines a DDS topic type `NAME` from an s-expr spec. `OPTIONS` is a plist (`:extensibility`, default `:final`, also `:appendable` and `:mutable`). Each member is `(slot-name member-type &key key id must-understand)`, where `member-type` is a primitive keyword, `(:string N)` for a bounded string, `(:enum NAME)` for a previously-defined enum, `(:sequence element)`, or the name of a previously-defined dds type (nested struct). Emits a `defstruct`, `ftype`-declared `serialize-`/`deserialize-`/`serialized-size-` monomorphic functions (plus an internal `%ssize-` position-threading helper and a `deserialize-into-` in-place variant), a 16-octet key-hash for keyed types, and a registered `type-support`. A `(:string N)` member additionally emits the constant `+NAME-SLOT-BOUND+` and the checked setter `set-NAME-SLOT`.

- **`dds.gen:define-dds-enum`** — macro; defines the DDS enumerated type `NAME` from literals `(keyword value)`. Emits `NAME-TO-I32` and `NAME-FROM-I32`, each returning `(values result status)` with status `:unknown-enum-value` for an input this build does not declare, plus the codec pair `(:enum NAME)` members are wired to. Rejects at macroexpansion: no literals, a malformed literal, a duplicate keyword, and a duplicate *value* (two literals sharing a value would make the wire ambiguous — the receiver could not say which was meant).

The DSL recognizes these member-type keywords (from `*dds-type-map*`): `:bool`, `:byte` (alias `:octet`), `:u8`, `:u16`, `:u32`, `:u64`, `:i8`, `:i16`, `:i32`, `:i64`, `:string`. `:u8`/`:i8` are the numeric 8-bit integers (`TK_UINT8`/`TK_INT8`); `:byte`/`:octet` is the opaque octet (`TK_BYTE`, IDL `octet`) — all three share the one-octet wire codec but carry distinct XTypes kinds (model an IDL `sequence<octet>` with `:byte`). A `(:sequence element)` member takes one of those keywords as its fixed-size primitive element (variable-size sequence elements, e.g. sequences of strings, are not supported in v1). `:extensibility` accepts `:final`, `:appendable` and `:mutable`; `@key` is restricted to scalar/string members. `:id` (`@id`) and `:must-understand` (`@must_understand`) are per-member wire properties that matter for `:mutable` — see §1.4.

**Bounded strings — `(:string N)`.** `:string` alone is the unbounded IDL `string`; `(:string N)` is IDL `string<N>`. The bound is part of the *type*, not a local check (DDS-XTypes 1.3 §7.3.1.2.1), so a bounded and an unbounded string are structurally different types that do not match — which is why the bound must reach the TypeObject. A `(:string N)` member is emitted as `dds.types:string8-type-identifier` with bound `N` rather than the unbounded `primitive-type-identifier`; that is the identifier a foreign `rtiddsgen`-generated peer compares its own `string<N>` against (ADR 0009 is the defect from getting this wrong). The wire codec is unchanged — a bounded string serializes exactly like an unbounded one — so adding a bound is byte-neutral, and `N` counts **octets, not characters** (ADR 0083: strings are UTF-8, and one character can occupy four octets). The generated `set-NAME-SLOT` measures with `dds.cdr:utf8-octet-length` and returns `(values nil :string-bound-exceeded)` rather than truncating or signalling; the plain `defstruct` accessor remains and is unchecked, so the hot path keeps direct slot access. Bounds are a permanent part of a published type — widening one is a type change, so choose `N` deliberately.

### The type-support vtable + registry — `dds.types`

- **`dds.types:type-support`** / **`dds.types:make-type-support`** / **`dds.types:type-support-p`** — the per-type manual vtable the engine funcalls per sample: a `defstruct` of function objects plus the type name, extensibility, structural TypeObject/TypeIdentifier, and data-representation mask. The hot path sees only this struct.
- **`dds.types:type-support-name`** / **`dds.types:type-support-type-name`** — the registry key / qualified type name.
- **`dds.types:type-support-extensibility`** — `:final` / `:appendable` / `:mutable`.
- **`dds.types:type-support-keyed-p`** — the RTPS TopicKind (DDSI-RTPS 2.5 §8.2.4.2): `T` = WITH_KEY (the type has at least one `@key` member), `NIL` = NO_KEY. Set by `define-dds-type`; defaults `T` for back-compat. Lets discovery pick the RTPS entity kind.
- **`dds.types:type-support-serialize`** / **`dds.types:type-support-deserialize`** / **`dds.types:type-support-serialized-size`** — the codec closures (sample × cursor → sample; cursor → sample; sample → byte count).
- **`dds.types:type-support-key-hash`** — the 16-octet keyhash closure, or `nil` for a keyless type.
- **`dds.types:type-support-typeobject`** / **`dds.types:type-support-typeidentifier`** — the structural Minimal struct TypeObject and the type's own TypeIdentifier.
- **`dds.types:type-support-sample-pool-alloc`** / **`dds.types:type-support-sample-pool-free`** — loan / return a pre-allocated sample for zero-per-sample-allocation deserialize.
- **`dds.types:type-support-flatdata-offset`** / **`dds.types:type-support-flatdata-builder`** — FlatData hooks (FR-PF-4, ADR 0015; **NOT cleared for ship — R6, patent-gated**). For a FINAL fixed-size `:flatdata t` type, `-flatdata-offset` holds a `dds.types:flatdata-layout` (size + per-field compile-time XCDR2 byte offsets + Offset accessor functions); the in-memory layout *equals* the wire, so `serialize-<name>-fd` is an identity block-copy (0-alloc TX, byte-exact vs the classic serializer), `deserialize-into-<name>-fd` copies into a loaned buffer (0-alloc RX inner path), and the `<name>-<field>-fd` Offset accessors read/modify in place (0-alloc for fixnum-range fields). The honest costs (TX 0, engine non-ZC RX vtable ~80 vs ~128 classic — 0 per-field decode but one buffer/sample, **not** 0-alloc; FlatData-over-ZC RX a safe single copy ~830x below the WP-ZEROCOPY-v1 sink+re-copy — **not** literal-0-copy) are in `bench/report/2026-06-14-wp-flatdata.md` (`make bench-flatdata`); the untrusted wrap/read paths are fuzzed (`make fuzz`, incl. a `(safety 0)` arm — the length/encap guard is an explicit manual check, hence safety-independent). **FlatData v1 is FINAL fixed-size scalar; keyed FlatData (fixed-size scalar `@key`) is supported** (WP-KEYED-FLATDATA, 2026-06-17): a keyed `:flatdata t` type emits a buffer-reading keyhash `key-hash-<name>-fd` (byte-identical to the spec/struct keyhash, RTPS 2.5 §9.6.4.8) wired into `type-support-key-hash`, lighting up real per-key loan handles, NEW/NOT_NEW view-state, dispose/unregister, and the per-instance KEEP_LAST drop on both paths — see [§8](#8-flatdata--flatdata-t-offset-accessors-final-fixed-size-r6-not-cleared-for-ship); a **variable-size / string `@key` member is still a compile-time error** (FlatData v1 fixed-size). **Literal-0-copy RX is now delivered** (WP-FLATDATA-ZC-LOAN, ADR 0017): a `:flatdata t` reader created with `dds.disc:*zerocopy-enabled*` on is *loan-capable* — the disc receiver thread stores the unresolved ZC reference (no copy; the slot is held via the writer's refcount), and the DCPS **loan API** `dds.dcps:take-loaned` / `read-loaned` hands the app a `dds.types:flatdata-view` whose `<name>-<field>-fd` accessors read **directly off the writer's SHMEM slot — literal 0 intra-host copies**; `dds.dcps:return-loan` releases the slot (idempotent / double-return-safe), and reader-close returns any outstanding loan (no leaked refcount). See [Examples §8](#8-flatdata--flatdata-t-offset-accessors-final-fixed-size-r6-not-cleared-for-ship). **Deferred follow-ups:** `-flatdata-builder` (variable-size/mutable/string/sequence/nested FlatData, incl. variable-size/string `@key`); the app-facing ZC loan-**write** API (the remaining TX app→slot copy). *(Keyed FlatData for fixed-size scalar `@key` and RELIABLE-ZC-loan are now done — WP-KEYED-FLATDATA / WP-RELIABLE-ZC.)*
- **`dds.types:type-support-data-representation-mask`** — the accepted data-representation mask.
- **`dds.types:type-support-field-accessors`** — `(field-name-string . unary-accessor)` per scalar/string member, for content filters / query conditions (off the hot path).
- **`dds.types:register-type`** — register a `type-support` under its `name`; returns it.
- **`dds.types:find-type-support`** — look up the `type-support` registered under a name, or `nil`.
- **`dds.types:registered-type-names`** — list of all registered type names.

### Sample pool (zero-per-sample allocation) — `dds.types`

- **`dds.types:sample-pool`** / **`dds.types:make-sample-pool`** — a fixed-capacity freelist of pre-allocated sample structs, carved once at registration: a reader loans a struct, deserializes into it, and returns it. `make-sample-pool` takes a constructor thunk and a capacity.
- **`dds.types:sample-pool-acquire`** — pop a pre-allocated sample; `nil` on exhaustion (caller applies `RESOURCE_LIMITS`).
- **`dds.types:sample-pool-release`** — return a loaned sample to the pool.

### XTypes structural model — TypeIdentifier (`dds.types`)

- **`dds.types:type-identifier`** / **`dds.types:type-identifier-p`** — the structural in-memory XTypes TypeIdentifier struct: a discriminant kind octet, a string/collection bound (0 = unbounded), a collection element TI, a 14-octet EquivalenceHash (or `nil` when pending), and the in-memory referenced struct an `EK_*` kind resolves to.
- **`dds.types:type-identifier-kind`** / **`dds.types:type-identifier-bound`** / **`dds.types:type-identifier-element`** / **`dds.types:type-identifier-hash`** / **`dds.types:type-identifier-referenced`** — accessors for those slots.
- **`dds.types:primitive-type-identifier`** — the TypeIdentifier for a primitive / string DSL member keyword. `:i8`/`:u8` map to the distinct numeric `TK_INT8` (0x0C) / `TK_UINT8` (0x0D) of XTypes 1.3; `:byte` (alias `:octet`) maps to `TK_BYTE` (0x02, IDL `octet`); `:string` is an unbounded `STRING8`.
- **`dds.types:string8-type-identifier`** — a narrow-string (`STRING8`) TypeIdentifier with an optional bound (0 = unbounded). Selects `TI_STRING8_SMALL` for a bound `≤255` (SBound) and `TI_STRING8_LARGE` for `>255` (LBound) per the idl §56-70 threshold, mirroring the `%get-/%put-type-identifier` wire model.
- **`dds.types:sequence-type-identifier`** — a plain-sequence TypeIdentifier with a given element TI and bound (0 = unbounded).
- **`dds.types:hash-type-identifier`** — a hash-defined TypeIdentifier (`EK_MINIMAL`/`EK_COMPLETE`); takes `:hash` (the 14-octet EquivalenceHash, or `nil` when pending) and `:referenced` (the in-memory struct it resolves to, letting assignability recurse ahead of the deferred hash).
- **`dds.types:type-identifier=`** — structural equality of two TypeIdentifiers (same kind + bound, recursively-equal element, equal EquivalenceHash, same referenced struct by identity).

### XTypes structural model — Minimal struct TypeObject (`dds.types`)

- **`dds.types:member-name-hash`** — NameHash = first 4 octets of `MD5(UTF-8 name without NUL)` (e.g. `"color"` → `70 dd a5 df`).
- **`dds.types:minimal-struct-member`** / **`dds.types:make-struct-member`** — a member of a Minimal struct type: IDL name + member id + member TypeIdentifier + key/optional/must-understand flags + the NameHash. `make-struct-member` takes `name id type-identifier &key key-p optional-p must-understand-p` and computes the NameHash from the name.
- **`dds.types:minimal-struct-member-name`** / **`-id`** / **`-type-identifier`** / **`-key-p`** / **`-optional-p`** / **`-must-understand-p`** / **`-name-hash`** — member accessors.
- **`dds.types:minimal-struct-type`** / **`dds.types:make-minimal-struct-type`** — a Minimal struct TypeObject in structural form: the qualified type name, extensibility, and the member list in member order.
- **`dds.types:minimal-struct-type-name`** / **`-extensibility`** / **`-members`** — accessors.

### Assignability + `TYPE_CONSISTENCY_ENFORCEMENT` (`dds.types`)

- **`dds.types:assignability-options`** / **`dds.types:make-assignability-options`** — the four `TypeConsistencyEnforcement` fields that modulate is-assignable-from under `ALLOW_TYPE_COERCION`. Spec defaults: bounds ignored, member names enforced, type widening permitted.
- **`dds.types:assignability-options-ignore-sequence-bounds`** / **`-ignore-string-bounds`** / **`-ignore-member-names`** / **`-prevent-type-widening`** — accessors for those fields.
- **`dds.types:default-assignability-options`** — a fresh options struct carrying the XTypes §7.6.3.4.1 defaults.
- **`dds.types:ti-assignable-from`** — `T1` is-assignable-from `T2` at the TypeIdentifier level (primitives by same kind; narrow strings under the bound rule; plain sequences when the element is strongly-assignable and the bound rule holds; nested structs by recursion). Unmodeled or mismatched kinds are not assignable.
- **`dds.types:strongly-assignable-from`** — assignable-from **and** `T2` is a delimited type (required for collection elements and aggregated key members).
- **`dds.types:struct-assignable-from`** — `STRUCTURE_TYPE` is-assignable-from (Table 19): same extensibility; name/id correspondence; ≥1 corresponding member; KeyErased member-type assignability; must_understand and key members present in both; key sub-bounds; the FINAL/APPENDABLE/MUTABLE member-matching rules; and `prevent_type_widening`.
- **`dds.types:member-names-agree-p`** — the member-name identity behind the Table 19 name↔id correspondence: when **both** members carry a 4-octet NameHash it is compared (`equalp`) — a Minimal TypeObject erases names and carries only `MinimalMemberDetail.name_hash` (XTypes 1.3 §7.2.2.4.4.4.5: `MD5(UTF-8 name)[0:4]`) — and the string names are compared only when either hash is absent. This makes a wire-parsed (name-erased) model comparable against a locally built one; `ignore_member_names` still skips the correspondence entirely.
- **`dds.types:ti-equivalent-p`** — structural MINIMAL-equivalence of two TypeIdentifiers (a verifiable stand-in for the deferred EquivalenceHash equality).
- **`dds.types:struct-equivalent-p`** — structural MINIMAL-equivalence of two struct TypeObjects (same extensibility, member count, and pairwise id/`@key`/`@optional`/member-type; member **names are not compared** — MINIMAL erases them).
- **`dds.types:enforce-type-consistency`** — the `TypeConsistencyEnforcement` Step-1 decision: under `:allow-type-coercion` the reader-type must be is-assignable-from the writer-type (taking the four options into account); under `:disallow-type-coercion` the two types must be MINIMAL-equivalent. Returns `T` iff consistent.

> This relation now **gates endpoint matching**: every DCPS `DomainParticipant` installs an
> assignability gate that fetches a mismatching peer's Minimal TypeObject via TypeLookup and
> decides the SEDP match with `enforce-type-consistency` under the reader's
> `TYPE_CONSISTENCY_ENFORCEMENT` — see [DCPS](dcps.md), "Assignability-gated matching" (FR-TYPE-4).

### XCDR2 TypeObject serializer + EquivalenceHash (`dds.types`)

- **`dds.types:minimal-type-object-octets`** — the canonical XCDR2 little-endian serialization of the `EK_MINIMAL` TypeObject for a struct, **with no encapsulation header** — the buffer the EquivalenceHash is computed over.
- **`dds.types:equivalence-hash`** — `EquivalenceHash(S)` = first 14 octets of `MD5` of the serialized MinimalTypeObject (XTypes §7.3.4.9.1); nested struct members recurse to the referenced struct's hash. **Externally confirmed** vs live Fast DDS 3.6.1 for the exercised path: for the identical ShapeType IDL its announced `EK_MINIMAL` hash and `typeobject_serialized_size` (87) match ours byte-for-byte (test `fastdds-type-information-vector`, locked from `interop/fastdds/captures/s1-forward-lo0.pcap` frame 236).
- **`dds.types:parse-minimal-type-object`** — the exact inverse of `minimal-type-object-octets`: parse serialized `EK_MINIMAL` TypeObject octets (e.g. received via TypeLookup) back into a `minimal-struct-type` for assignability. Returns `:unsupported` for any kind outside the modeled subset (an `EK_COMPLETE` discriminator, a non-`TK_STRUCTURE` payload, a non-`TK_NONE` base, an unmodeled member TypeIdentifier) and for input over `*max-type-object-bytes*`; `NIL` on malformed/truncated input (network-facing: every read is bounds-checked). Plain-sequence member TypeIdentifiers — which the serializer cannot emit yet — parse per the IDL (`PlainSequenceSElemDefn`/`-L-`, xtypes-1_3_typeobject.idl §181-197). The parsed model carries name `""` (Minimal erases names), the wire NameHashes, and member `EK_*` hashes with `referenced` = `NIL`, and re-serializes byte-identically.
- **`dds.types:complete-to-minimal-type-object`** — reconstruct the MINIMAL struct model from a serialized `EK_COMPLETE` TypeObject, per the XTypes 1.3 §7.6.3.3.4.2 latitude: a getTypes server asked for a MINIMAL TypeIdentifier may answer with the COMPLETE TypeObject plus the `complete_to_minimal` mapping, and the receiver reconstructs. Takes the TypeObject octets and that mapping (an alist `((complete-hash . minimal-hash) …)`, used to remap `EK_COMPLETE` TypeIdentifiers — member-level and plain-collection elements alike). The returned `minimal-struct-type` keeps the real type + member names (Minimal serialization includes neither, so `equivalence-hash` / `minimal-type-object-octets` are unaffected); member NameHashes are recomputed from the names (§7.3.4.5); `@optional` detail members ride as `<is_present>` booleans (§7.4.3.5.2). `:unsupported` outside the modeled subset (non-struct, non-`TK_NONE` base, a present type annotation, an unmodeled or unmappable member/element TypeIdentifier — fail-open, never a model the assignability gate could mis-handle), `NIL` on malformed input (every read bounds-checked). Proven live: the locked Fast DDS 3.6.1 getTypes reply reconstructs to a MinimalTypeObject **byte-identical to our own ShapeType's** and re-hashes to the queried EK_MINIMAL hash (test `fastdds-typelookup-reply-vector`, FR-IO-2 S4).

### TypeInformation codec (`dds.types`)

- **`dds.types:serialize-type-information`** — serialize the TypeInformation for a struct (minimal only) as the octets carried in `PID_TYPE_INFORMATION` (a MUTABLE struct DHEADER + the `@id(0x1001)` minimal member + its TypeIdentifierWithDependencies).
- **`dds.types:deserialize-type-information-hash`** — parse a serialized TypeInformation and return its minimal `EK_MINIMAL` TypeIdentifier's 14-octet EquivalenceHash (the value endpoint matching needs). Accepts both mutable-member framings of XTypes §7.4.3.4.2: `LC=4` (explicit NEXTINT length — our emission) and `LC>=5` (NEXTINT reused as the member's leading DHEADER — the Fast DDS 3.6.1 emission, proven by the locked live vector in test `fastdds-type-information-vector`).

### Built-in TypeLookup service request/reply codecs (`dds.types`)

The XTypes 1.3 §7.6.3.3 built-in TypeLookup service types, `TypeLookup_Request { dds::rpc::RequestHeader header; TypeLookup_Call data; }` and `TypeLookup_Reply { header; TypeLookup_Return return; }`, serialized as XCDR2 little-endian with the `CDR2_LE` encapsulation and no top-level DHEADER: the spec IDL leaves the top-level types unannotated (the §7.3.1.2.1.8 default would be appendable), but the implemented convention — Fast DDS, the designated live oracle, pins them `@final`, and the Wireshark/tshark RTPS dissector expects exactly that — is FINAL; the `TypeLookup_Call`/`Return`/`Result` unions are default-appendable (a DHEADER before each discriminator) and the MUTABLE `*_In`/`*_Out` members use `EMHEADER1 LC=5`, NEXTINT doubling as the value's leading UInt32 per serialization rule (22) (§7.4.3.5.3). No Connext oracle exists for this protocol (ADR 0010); the emitted bytes are frozen as self-pinned regression vectors (test `typelookup-vectors`), the tshark dissector decodes both payloads field-by-field with zero disagreements (`make wire` gates two TL frames), and the framing is now **PEER-CONFIRMED in both directions** by the live Fast DDS 3.6.1 exchanges (FR-IO-2 S4, 2026-06-12 — the CONFIRM-VS-PEER walk in `interop/fastdds/README.md`): leg A (our client vs their server) had our request — 24-char prefix-hex `instanceName` included — accepted (`REMOTE_EX_OK`), with their reply locked as the regression vector in test `fastdds-typelookup-reply-vector`, which surfaced the §7.6.3.3.4.2 COMPLETE-TypeObject + `complete_to_minimal` answer shape now consumed via `complete-to-minimal-type-object` (see above and [Interop](interop.md)); the leg B-patched diagnostic (their stock TypeLookup client vs our server, reachable only by bypassing their SEDP vendor gate in a local non-stock build) had their client consume our getTypeDependencies **and** getTypes replies and build its DynamicType from our MINIMAL TypeObject, then take 600/600 RELIABLE samples. Still self-pinned only: a live non-OK reply (the Return-arm omission) and non-`CDR2_LE` encapsulations. Note: the §7.6.3.3.3 IDL names the reply header `dds::rpc::RequestHeader` — a spec editorial defect; the codec uses the `ReplyHeader` copied from DDS-RPC in §7.6.3.3.2 (`relatedRequestId` + `remoteEx`), the only header that can carry the remote exception code.

- **`dds.types:serialize-type-lookup-request`** — serialize a request: `:writer-guid` (16 octets), `:sn` (request SequenceNumber), `:instance-name` (`string<255>`), `:operation` (`:get-types` | `:get-deps`), `:type-ids` (list of 14-octet EquivalenceHashes, sent as `EK_MINIMAL` TypeIdentifiers), `:continuation` (optional `sequence<octet,32>` continuation point, `:get-deps` only). Returns a fresh octet vector including the 4-octet encapsulation header.
- **`dds.types:parse-type-lookup-request`** — parse a serialized request to `(values operation type-ids writer-guid sn instance-name continuation)`; `:unknown` for an unrecognized union discriminator; `NIL` on any malformed or truncated input (network-facing — every read is bounds-checked, and an unknown mutable member with the must-understand flag set rejects the sample per §7.2.2.4.4.4.6).
- **`dds.types:serialize-type-lookup-reply`** — serialize a reply: `:related-guid`/`:related-sn` (the request's SampleIdentity, echoed as `relatedRequestId`), `:remote-ex` (`:ok` | `:unsupported` | `:invalid-argument` | `:out-of-resources` | `:unknown-operation` | `:unknown-exception`, the §7.6.3.3.2 `RemoteExceptionCode_t` in declaration order 0–5), `:operation` (`:get-types` | `:get-deps`, required for `:ok`), `:pairs` (list of `(hash . typeobject-octets)` `TypeIdentifierTypeObjectPair`s, `:get-types`), `:dependencies` (list of `(hash . size)` `TypeIdentfierWithSize` [sic — the IDL's own spelling] entries, `:get-deps`), `:continuation` (optional, `:get-deps`). For any non-`:ok` `:remote-ex` the `TypeLookup_Return` is omitted entirely (DDS-RPC signals failure via `remoteEx`; the Return union has no default arm; the FINAL reply simply ends after the header). `:writer-guid` is accepted for call-site symmetry but not serialized — the ReplyHeader carries no replier identity.
- **`dds.types:parse-type-lookup-reply`** — parse a serialized reply to `(values operation result related-guid related-sn remote-ex continuation c2m)`: `result` is the pairs list for `:get-types` or the `(hash . size)` list for `:get-deps`; `c2m` is the `:get-types` `complete_to_minimal` alist `((complete-hash . minimal-hash) …)` a server sends when it answers a MINIMAL query with COMPLETE TypeObjects (XTypes 1.3 §7.6.3.3.4.2 — the live Fast DDS 3.6.1 answer shape, locked in test `fastdds-typelookup-reply-vector`); `:unknown` for an unrecognized Return discriminator; `operation` `NIL` with the header values still returned for a non-OK header-only reply; `NIL` on any malformed or truncated input (every read bounds-checked; sequence counts pre-checked against the enclosing DHEADER extent before allocation; per-pair TypeObject extents bounded by `*max-type-object-bytes*`).
- **`dds.types:+tl-gettypes-hash+`** / **`dds.types:+tl-getdeps-hash+`** — the `TypeLookup_Call`/`TypeLookup_Return` union discriminators `TypeLookup_getTypes_HashId` `#x018252d3` and `TypeLookup_getDependencies_HashId` `#x05aafb31` (§7.6.3.3.3, derived via the §7.3.1.2.1.1 `@hashid` rule).

#### TypeLookup hash index + pure server core

The transport-free server half of the service: pure functions over the type registry, called by the builtin TypeLookup endpoints (see [Discovery](discovery.md)) (§7.6.3.3.4: a participant shall answer getTypes / getTypeDependencies for any TypeIdentifier it announced).

- **`dds.types:find-type-support-by-hash`** — the registered `type-support` whose minimal EquivalenceHash equals the given hash (first 14 octets compared), or `NIL`. Backed by a memoized `(hash . name)` index over the registry, rebuilt whenever a `register-type` call bumps the registry generation counter (so re-registering an existing name invalidates it too); types whose TypeObject cannot serialize (e.g. sequence member TypeIdentifiers pending oracle confirmation) are skipped, never signalled.
- **`dds.types:type-lookup-respond`** — answer one inbound serialized `TypeLookup_Request` with serialized `TypeLookup_Reply` octets, or `NIL` to drop (malformed input, or more `type_ids` than `*max-typelookup-request-ids*`). The reply's `relatedRequestId` echoes the request's writer GUID + SN (§7.6.3.3.2). `getTypes` answers `(hash . typeobject-octets)` pairs for the hashes found locally — unknown hashes are silently omitted, so an all-unknown request still answers `REMOTE_EX_OK` with zero pairs; `getTypeDependencies` answers the nested-struct dependency closure of each found type, deduped by hash, as `(hash . typeobject-serialized-size)` entries with an always-empty continuation point (v1 serves the full set in one reply); an unrecognized `TypeLookup_Call` discriminator answers `REMOTE_EX_UNKNOWN_OPERATION` with no `TypeLookup_Return` arm.
- **`dds.types:*max-typelookup-request-ids*`** — special variable, default `32`: the maximum `type_ids` accepted in one inbound request before it is dropped unanswered (resource-exhaustion guard, NFR-SEC-POSTURE).

### Exported constants (`dds.types`)

TypeKind octets: **`+tk-boolean+`**, **`+tk-byte+`**, **`+tk-int8+`**, **`+tk-uint8+`**, **`+tk-int16+`**, **`+tk-int32+`**, **`+tk-int64+`**, **`+tk-uint16+`**, **`+tk-uint32+`**, **`+tk-uint64+`**, **`+tk-string8+`**, **`+tk-structure+`**, **`+tk-sequence+`**. EquivalenceKind octets: **`+ek-minimal+`**, **`+ek-complete+`**. TypeIdentifierKind octets: **`+ti-string8-small+`**, **`+ti-string8-large+`**, **`+ti-plain-sequence-small+`**.

## Examples

Each example below is adapted from a passing test in `src/dds-tests/`. The control-plane examples (assignability, TypeObject, TypeInformation) need only `(ql:quickload :dds-types)` plus the generated types; the round-trip example also drives the arena/buffer layer.

### 1. Define a type and round-trip it through the generated codec

`define-dds-type` emits the struct, the codecs, and the registered `type-support` at macroexpansion time. Here a 3-member final struct is serialized and deserialized via the generated functions, and its `serialized-size` is checked against the bytes written (adapted from `run-generated-type-test` in `src/dds-tests/gen-test.lisp`).

```lisp
(dds.gen:define-dds-type gsample (:extensibility :final)
  (id :i32 :key t)
  (ts :i64)
  (label :string))

(let* ((arena (dds.core.arena:init-arena :bytes (* 64 1024)))
       (pool  (dds.core.arena:make-buffer-pool arena 512 2))
       (s     (make-gsample :id -42 :ts 9999999999 :label "gen"))
       (b     (dds.core.arena:pool-acquire pool))
       (wc    (dds.core.buffer:cursor b :endianness :little)))
  (serialize-gsample s wc :xcdr2)
  (let* ((wrote (dds.core.buffer:cursor-position wc))
         (rc    (dds.core.buffer:cursor b :endianness :little))
         (q     (deserialize-gsample rc :xcdr2)))
    (assert (and (= (gsample-id q) -42)
                 (= (gsample-ts q) 9999999999)
                 (string= (gsample-label q) "gen")))
    (assert (= wrote (serialized-size-gsample s :xcdr2)))
    (dds.core.arena:pool-release pool b))
  (dds.core.arena:teardown-arena arena))
```

### 1.1 Bounded strings — `(:string N)`

A bounded member declares IDL `string<N>`. Two things come out of it, and they do different jobs: the **TypeObject bound**, which is what a foreign peer matches against, and the **checked setter**, which is what stops an over-long value reaching the wire. Neither substitutes for the other (adapted from `run-bounded-string-test` in `src/dds-tests/echo-test.lisp`).

```lisp
(dds.gen:define-dds-type bounded-str-t (:extensibility :final)
  (id :i32 :key t)
  (name (:string 8)))                       ; IDL: string<8> name;

;; 1. The bound is part of the TYPE — it reaches the TypeObject a peer matches against.
(let* ((ts (dds.types:find-type-support "bounded-str-t"))
       (m  (second (dds.types:minimal-struct-type-members
                    (dds.types:type-support-typeobject ts)))))
  (assert (= 8 (dds.types:type-identifier-bound
                (dds.types:minimal-struct-member-type-identifier m)))))

;; 2. The checked setter refuses an over-long value instead of truncating or signalling.
(let ((s (make-bounded-str-t :id 1 :name "12345678")))   ; 8 octets: at the bound, fine
  (assert (= +bounded-str-t-name-bound+ 8))
  (multiple-value-bind (ok status) (set-bounded-str-t-name s "123456789")
    (assert (null ok))
    (assert (eq status :string-bound-exceeded)))
  (assert (string= (bounded-str-t-name s) "12345678"))   ; a refused set changes nothing
  (assert (eq t (set-bounded-str-t-name s "abc")))
  ;; OCTETS, not characters: eight 2-octet characters are 16 octets and are refused.
  (assert (null (set-bounded-str-t-name s (make-string 8 :initial-element (code-char #xE4))))))
```

The last assertion is the whole point of measuring in octets: a bound that counted characters would let a 16-octet value past a bound of 8 and overflow the peer's `char[9]` buffer — the exact overflow the bound exists to prevent.

### 1.2 Enum members — `(:enum NAME)`

The wire representation is `int32` (DDS-XTypes 1.3 §7.3.1.2.1 gives an enumeration a default bit bound of 32), and the value on the wire is the **declared constant, never the literal's ordinal position** — so the values are written out rather than inferred (adapted from `run-gen-enum-test` in `src/dds-tests/gen-test.lisp`).

```lisp
(dds.gen:define-dds-enum genum-hue (:red 0) (:green 3) (:blue 7))   ; gapped on purpose

(dds.gen:define-dds-type genum-t (:extensibility :final)
  (id :i32 :key t)
  (hue (:enum genum-hue)))

(assert (eql 7 (genum-hue-to-i32 :blue)))      ; the declared value, not the ordinal 2
(assert (eq :green (genum-hue-from-i32 3)))

;; An input this build does not declare is REPORTED, never invented.
(multiple-value-bind (kw status) (genum-hue-from-i32 42)
  (assert (null kw))
  (assert (eq status :unknown-enum-value)))
```

**What happens to a value we do not know.** A peer built from a newer revision of the type will send literals this build has never heard of. The member's slot admits either a declared literal *or* a raw `int32`, and an undecodable value is kept **verbatim**: it never becomes a neighbouring keyword, and re-serializing the sample emits exactly what arrived, so relaying cannot fabricate a value the sender never sent. The slot's declared type is `(or (member ...declared literals...) (signed-byte 32))`, which is also what stops an *undeclared keyword* ever reaching the wire — the type system refuses it rather than a runtime check.

> **Known gap.** The member's TypeObject TypeIdentifier is **`TK_INT32`**, not a real XTypes enum. The structural model has `minimal-enumerated-type` / `enumerated-type-identifier`, but the TypeObject *serializer* cannot emit one — `equivalence-hash` accepts only a `minimal-struct-type`, so an `EK_MINIMAL` TypeIdentifier referencing an enum hits `%put-type-identifier`'s "no EquivalenceHash" branch. Emitting a real `MinimalEnumeratedType` means new, **oracle-sensitive** bytes, which is exactly why sequence-member TypeIdentifiers deliberately error today rather than guess. Consequence: a peer whose IDL declares this member as an `enum` presents `TK_ENUM` while we present `TK_INT32` — structurally different types, the same defect class as ADR 0009. The wire bytes are identical; only structural matching is affected. This is **debt, not the target**, and it is pinned by the `enum-typeobject-is-int32-known-gap` assertion so it cannot change unnoticed.

### 1.3 `:appendable` — adding a member without breaking existing readers

DDS-XTypes 1.3 §7.4.3.5 rule **(30)**: under XCDR2 an APPENDABLE type is `DHEADER(O):UInt32` followed by the members *as if FINAL*. Rule **(29)**: under XCDR1 it is serialized **exactly as FINAL — no DHEADER** (§7.4.2 says the same in prose). The DHEADER carries the size of what follows, excluding itself (§7.4.3.4.1) — adapted from `run-gen-appendable-test`.

```lisp
(dds.gen:define-dds-type appendable-v1 (:extensibility :appendable)
  (a :i32 :key t)
  (b :i32))

(dds.gen:define-dds-type appendable-v2 (:extensibility :appendable)
  (a :i32 :key t)
  (b :i32)
  (c :i32))                                  ; v2 = v1 + one appended member

;; A v1 reader reads a v2 sample: shared members decode, the appended one is SKIPPED —
;; the reader stops at the DHEADER's extent instead of walking into member c.
;; A v2 reader reads a v1 sample: member c was never sent, so it keeps its default.
```

**The encapsulation id changes with extensibility, not just the encoding version.** Table 60 (§7.6.3.1.2): `FINAL`+v2+LE is `CDR2_LE` **0x0007**, but `APPENDABLE`+v2+LE is `D_CDR2_LE` **0x0009**. The label and the framing must agree — `0x0007` tells a conformant peer there is *no* DHEADER, so it would read the DHEADER's four octets as the first member. The TX id is therefore selected from the type's extensibility, and RX accepts `0x0008`/`0x0009` and maps them to the XCDR2 codec; rejecting them would be a false-REJECT of a conformant peer. Under XCDR1 both extensibilities map to `CDR_LE` 0x0001, per rule (29).

The DHEADER is wire data and is bounds-checked against the buffer extent before it is trusted. That check is defense in depth rather than the sole guard — every member read is independently bounds-checked — so it earns its place by failing *fast*, before any attacker-controlled member is parsed against a bogus extent.

`:final` types are untouched by all of this and stay **byte-identical** (`make corpus` is the guard).

### 1.4 `:mutable` — adding, removing *and* reordering members

APPENDABLE only lets a type grow at the end. MUTABLE gives every member its own header carrying a
**member id**, so a peer can add, remove or reorder members and both sides still match up — members are
located by id, never by position. It costs a header per member on the wire and an id dispatch per member
on decode; that is inherent to the kind and is a per-type choice, not a default (ADR 0086).

```lisp
(dds.gen:define-dds-type mut-v1 (:extensibility :mutable)
  (a :i32 :key t)                      ; id 0 — ids default to declaration order
  (b :u16)                             ; id 1
  (label :string)                      ; id 2
  (t-ns :i64))                         ; id 3

(dds.gen:define-dds-type mut-v2 (:extensibility :mutable)
  (t-ns :i64 :id 3)                    ; declared in a DIFFERENT order, same ids
  (label :string :id 2)
  (a :i32 :id 0 :key t)
  (extra :i32 :id 7)                   ; new member, unknown to a v1 reader
  (b :u16 :id 1))

;; A v1 reader reads a v2 sample: the shared members decode BY ID whatever order they
;; arrive in, and unknown id 7 is SKIPPED using its header's own length — never its type,
;; which a v1 reader does not have.
;; A v2 reader reads a v1 sample: `extra` was never sent, so it keeps its default.
;; An absent member is normal in MUTABLE, not an error.
```

**`:id` is the wire contract.** It defaults to declaration order and goes into the TypeObject, so
*reordering* members of a mutable type is safe but *renumbering* them is not. Duplicates are rejected at
macroexpansion — two members sharing an id would have the second silently overwrite the first on decode.

**`:name` is the member's WIRE name**, defaulting to the downcased slot name — and you need it more
often than you would guess. IDL spells identifiers with `_` where Lisp uses `-`, so a slot `t-ns`
renders `"t-ns"` while the IDL member is `t_ns`. Type assignability matches members by **NameHash**, so
that single character makes an otherwise identical type *inconsistent* with the peer's:

```lisp
(t-ns :i64 :id 3 :name "t_ns")     ; the IDL spelling, not the Lisp one
```

The failure mode is what makes this worth knowing: not an error, but a **silent non-match**. The live
Connext MUTABLE leg hit exactly this — Connext matched our writer while our gate refused its reader, a
one-sided match visible only as `matched=0` and a single `INCOMPATIBLE — legacy-TypeObject
assignability` line. Before `:name` existed, **no type with an underscore in a member name could
interoperate**, and nothing said so. Duplicates are rejected at macroexpansion, for the same reason
duplicate `:id`s are. Set `dds.dcps:*type-compat-log*` to a stream to see the gate's verdicts and, on a
reject, both models side by side.

**`:must-understand t`** (`@must_understand`) marks a member a peer may not quietly ignore. If it does not
recognise the id, it must discard the **entire sample** rather than deliver a partial one
(§7.4.1.2.1) — reported as the status `:unknown-must-understand-member`, never signalled (ADR 0064).
Without the flag the same unknown member is simply skipped. That single bit is the whole difference.

**Two framings, chosen at runtime by the representation.** Under XCDR2 (rules (21)–(22)) it is a DHEADER
over members each prefixed by `EMHEADER1`; under XCDR1 (rules (23)–(25)) it is a PL_CDR parameter list,
each member 4-aligned with its alignment origin reset (`PUSH(ORIGIN=0)`), closed by `PID_LIST_END`. Both
are emitted, because a stock foreign reader may request either — and emitting XCDR2 framing under an
XCDR1 encapsulation id would be silently wrong bytes rather than a visible failure. Table 60 labels them
`PL_CDR2_LE` **0x000b** and `PL_CDR_LE` **0x0003**, and RX accepts both.

**Both RTI Connext and Fast DDS send `@mutable` as PL_CDR (XCDR1), not PL_CDR2.** The committed vectors
`corpus/xcdr2/mutabledata-{connext,fastdds}.bin` are both stamped `0x0003`. So the XCDR1 leg is the one
that actually carries MUTABLE to either vendor, which is why both encodings are emitted rather than XCDR2
alone; a type that refused XCDR1 would interoperate with nothing while every local test still passed.
It also means the XCDR2 length-code choice has **no live peer behind it** — see below.

**And the two vendors do not agree with each other.** For the same sample they differ in three fields:
Connext pads a parameter's declared length to a multiple of 4 (`4` for a 2-octet `short`, `12` for a
10-octet string) and sets FLAG_MUST_UNDERSTAND on the terminator (`0x7F02`); Fast DDS declares the exact
`ssize` (`2`, `10`) and writes a bare `0x3F02`. Rules (24)/(25) say `M.value.ssize` — the Fast DDS
reading; a PL_CDR list is also the RTPS ParameterList of RTPS 2.5 §9.4.2.11 where lengths are
4-multiples — the Connext reading. **No encoder can be byte-exact against both**: ours matches Connext,
the strict oracle, as a deliberate choice. What holds for either is that we *decode* their framing, and
that is gated — the Fast DDS vector is decode-verified rather than byte-compared (ADR 0086 §A7).

Traps worth knowing, all pinned by `run-gen-mutable-test` and `make corpus` (ADR 0086 §A1/§A3/§A5):

- Length codes 5–7 make NEXTINT double as the member's own leading length, so a member's extent is
  `4 + width×NEXTINT`, not `NEXTINT`.
- **Parameter id 1 is a member, not a list terminator** for a user-defined type — the id-1 terminator
  belongs to Simple Discovery types, which give up member id 1 to buy it.
- Under XCDR1 a parameter's **declared length is rounded up to a multiple of 4** (a 2-octet `short`
  declares 4), and the list terminator is **`0x7F02`** — PID_LIST_END with must-understand — not the bare
  `0x3F02` that rule (23)'s "PID_SENTINEL" suggests. Neither is visible to a round-trip test; both were
  found by the external vector.

### 2. Drive the type purely through the registered `type-support` vtable

The engine never calls `serialize-gsample` by name — it funcalls the `type-support` slots. This is the hot-path surface (adapted from `run-generated-type-test`).

```lisp
(let* ((ts (dds.types:find-type-support "gsample"))         ; registered by define-dds-type
       (arena (dds.core.arena:init-arena :bytes (* 64 1024)))
       (pool  (dds.core.arena:make-buffer-pool arena 512 1))
       (s     (make-gsample :id 7 :ts 1 :label "gen"))
       (b     (dds.core.arena:pool-acquire pool))
       (wc    (dds.core.buffer:cursor b :endianness :little)))
  (assert (dds.types:type-support-p ts))
  (funcall (dds.types:type-support-serialize ts) s wc :xcdr2)
  (let* ((rc (dds.core.buffer:cursor b :endianness :little))
         (q  (funcall (dds.types:type-support-deserialize ts) rc :xcdr2)))
    (assert (string= "gen" (gsample-label q))))
  (dds.core.arena:pool-release pool b)
  (dds.core.arena:teardown-arena arena))
```

### 3. Inspect the structural Minimal TypeObject built for a type

`define-dds-type` also builds a Minimal struct TypeObject into the `type-support`: member TypeIdentifiers, `@key` flags, and byte-exact NameHashes (adapted from `run-xtypes-model-test` in `src/dds-tests/integration-test.lisp`). `shape-type` is the keyed `(color :string :key t)(x :i32)(y :i32)(shapesize :i32)` type used across the suite.

```lisp
(let* ((ts      (dds.types:find-type-support "shape-type"))
       (to      (dds.types:type-support-typeobject ts))
       (members (dds.types:minimal-struct-type-members to)))
  (flet ((m (name) (find name members
                         :key #'dds.types:minimal-struct-member-name :test #'string=)))
    (assert (string= "shape-type" (dds.types:minimal-struct-type-name to)))
    (assert (eq :final (dds.types:minimal-struct-type-extensibility to)))
    (assert (dds.types:minimal-struct-member-key-p (m "color")))
    (assert (= dds.types:+ti-string8-small+
               (dds.types:type-identifier-kind
                (dds.types:minimal-struct-member-type-identifier (m "color")))))
    (assert (= dds.types:+tk-int32+
               (dds.types:type-identifier-kind
                (dds.types:minimal-struct-member-type-identifier (m "x")))))
    ;; NameHash("color") = MD5("color")[0:4] = 70 dd a5 df
    (assert (equalp (dds.types:minimal-struct-member-name-hash (m "color"))
                    (make-array 4 :element-type '(unsigned-byte 8)
                                  :initial-contents '(#x70 #xdd #xa5 #xdf))))))
```

### 4. Check assignability + the enforcement decision

The is-assignable-from relation is pure structural logic over hand-built TypeObjects. This shows APPENDABLE truncation (the spec's Coordinate2D/3D case), `prevent_type_widening`, and the `enforce-type-consistency` Step-1 decision under both kinds (adapted from `run-assignability-test`).

```lisp
(labels ((i32 () (dds.types:primitive-type-identifier :i32))
         (mem (name id ti) (dds.types:make-struct-member name id ti))
         (sty (ext &rest members)
           (dds.types:make-minimal-struct-type :extensibility ext :members members))
         (asg (a b o) (and (dds.types:struct-assignable-from a b o) t)))
  (let ((opts (dds.types:default-assignability-options))
        (pw   (dds.types:make-assignability-options :prevent-type-widening t))
        (p2   (sty :appendable (mem "x" 0 (i32)) (mem "y" 1 (i32))))
        (p3   (sty :appendable (mem "x" 0 (i32)) (mem "y" 1 (i32)) (mem "z" 2 (i32)))))
    ;; APPENDABLE truncation is assignable both ways by default
    (assert (and (asg p2 p3 opts) (asg p3 p2 opts)))
    ;; prevent_type_widening blocks a wider T2 from building a narrower T1
    (assert (and (not (asg p2 p3 pw)) (asg p3 p2 pw)))
    ;; enforcement Step 1: ALLOW coercion = reader assignable-from writer
    (assert (dds.types:enforce-type-consistency p2 p3 :kind :allow-type-coercion))
    ;; DISALLOW coercion requires structural (MINIMAL) equivalence
    (assert (not (dds.types:enforce-type-consistency p2 p3 :kind :disallow-type-coercion)))))
```

### 5. Serialize a TypeObject and compute its EquivalenceHash

`minimal-type-object-octets` produces the canonical XCDR2-LE bytes (no encapsulation header) and `equivalence-hash` is `MD5(...)[0:14]`. The 1-member `struct pt { long x; }` has a hand-derived spec golden; nested-struct members recurse; **sequence members error cleanly** pending the Connext oracle (adapted from `run-typeobject-cdr-test`). `parse-minimal-type-object` inverts the serialization: `(dds.types:parse-minimal-type-object (dds.types:minimal-type-object-octets pt))` yields a structurally equal model that re-serializes to the same octets (`run-typeobject-parse-test` proves this byte-exactly for the shape-type, nested-struct, and flag-variety models, and fuzzes the parser in the pbt suite).

```lisp
(let ((pt (dds.types:make-minimal-struct-type
           :name "pt" :extensibility :final
           :members (list (dds.types:make-struct-member
                           "x" 0 (dds.types:primitive-type-identifier :i32)))))
      (golden (make-array 39 :element-type '(unsigned-byte 8)
                :initial-contents
                '(#x23 0 0 0 #xf1 #x51 #x01 0 #x01 0 0 0 0 0 0 0
                  #x13 0 0 0 #x01 0 0 0 #x0b 0 0 0 0 0 0 0
                  #x01 0 #x04 #x9d #xd4 #xe4 #x61))))
  (assert (equalp golden (dds.types:minimal-type-object-octets pt)))
  (assert (= 14 (length (dds.types:equivalence-hash pt))))
  ;; nested-struct types hash by recursion into the referenced TypeObject
  (let ((seg (dds.types:type-support-typeobject (dds.types:find-type-support "gseg"))))
    (assert (= 14 (length (dds.types:equivalence-hash seg)))))
  ;; a sequence member errors cleanly (pending oracle confirmation)
  (let ((seq (dds.types:type-support-typeobject (dds.types:find-type-support "gseq"))))
    (assert (handler-case (progn (dds.types:minimal-type-object-octets seq) nil)
              (error () t)))))
```

### 6. Round-trip TypeInformation (PID_TYPE_INFORMATION foundation)

The TypeInformation carried in the SEDP builtin-topic data lets a peer learn a type's EquivalenceHash without the full TypeObject. Serialize it, then recover the minimal EquivalenceHash; a type with a nested dependency carries a larger payload (adapted from `run-type-information-test`). `gseg` depends on `gpoint`; `dcps-msg` is a flat type.

```lisp
(flet ((to (name) (dds.types:type-support-typeobject (dds.types:find-type-support name))))
  (let* ((mto  (to "dcps-msg"))
         (info (dds.types:serialize-type-information mto)))
    ;; the round-trip recovers exactly the type's EquivalenceHash
    (assert (equalp (dds.types:deserialize-type-information-hash info)
                    (dds.types:equivalence-hash mto)))
    (assert (equalp info (dds.types:serialize-type-information mto))))   ; deterministic
  (let ((ginfo (dds.types:serialize-type-information (to "gseg"))))
    (assert (equalp (dds.types:deserialize-type-information-hash ginfo)
                    (dds.types:equivalence-hash (to "gseg"))))
    ;; a nested dependency makes the TypeInformation strictly larger
    (assert (> (length ginfo)
               (length (dds.types:serialize-type-information (to "dcps-msg")))))))
```

### 7. Round-trip a TypeLookup_Request (built-in TypeLookup service)

A getTypes request names the wanted types by their 14-octet EquivalenceHashes; the parse returns the operation, the hashes, and the DDS-RPC request header fields (adapted from `run-typelookup-request-test` in `src/dds-tests/xtypes-test.lisp`).

```lisp
(let* ((guid (make-array 16 :element-type '(unsigned-byte 8) :initial-element 7))
       (hash (dds.types:equivalence-hash
              (dds.types:type-support-typeobject (dds.types:find-type-support "dcps-msg"))))
       (octets (dds.types:serialize-type-lookup-request
                :writer-guid guid :sn 5 :instance-name "dds.builtin.TOS.x"
                :operation :get-types :type-ids (list hash))))
  (multiple-value-bind (op ids wguid sn iname)
      (dds.types:parse-type-lookup-request octets)
    (assert (eq op :get-types))
    (assert (equalp (first ids) hash))
    (assert (and (equalp wguid guid) (= sn 5) (string= iname "dds.builtin.TOS.x"))))
  ;; truncated / malformed input rejects with NIL, never an error
  (assert (null (dds.types:parse-type-lookup-request (subseq octets 0 7)))))
```

The matching getTypes reply carries `TypeIdentifierTypeObjectPair`s — each the hash plus the verbatim `minimal-type-object-octets` — under the request's SampleIdentity (adapted from `run-typelookup-reply-test`):

```lisp
(let* ((rg (make-array 16 :element-type '(unsigned-byte 8) :initial-element 9))
       (ts (dds.types:type-support-typeobject (dds.types:find-type-support "dcps-msg")))
       (to (dds.types:minimal-type-object-octets ts))
       (hash (dds.types:equivalence-hash ts))
       (octets (dds.types:serialize-type-lookup-reply
                :related-guid rg :related-sn 5
                :operation :get-types :remote-ex :ok
                :pairs (list (cons hash to)))))
  (multiple-value-bind (op pairs rguid rsn remote-ex)
      (dds.types:parse-type-lookup-reply octets)
    (assert (eq op :get-types))
    (assert (and (equalp (car (first pairs)) hash) (equalp (cdr (first pairs)) to)))
    (assert (and (equalp rguid rg) (= rsn 5) (eq remote-ex :ok)))))
```

### 8. FlatData — `:flatdata t` Offset accessors (FINAL fixed-size; R6, NOT cleared for ship)

> **NOT cleared for ship — pending counsel (R6, patent-gated); see ADR 0015.** Per-type opt-in via `:flatdata t`; the default codegen path is untouched.

For a **FINAL fixed-size scalar** type annotated `:flatdata t`, the in-memory sample **is** the XCDR2-LE SerializedPayload (`[4-octet encap header][PLAIN_CDR2-LE body]`). The compiler emits compile-time-constant **Offset accessors** `<name>-<field>-fd` (get/`setf`, raw read/write at `4 + offset`), a `make-<name>-flatdata` constructor, and `+<name>-flatdata-size+`. `serialize` is an **identity block-copy** (0-alloc TX), so the buffer the accessors mutate is byte-identical to the engine's classic serialize of an equal struct (adapted from `run-flatdata-accessor-test` in `src/dds-tests/echo-test.lisp`):

```lisp
(dds.gen:define-dds-type fd-abc (:flatdata t)   ; FINAL, fixed-size scalars (NO_KEY here; keyed FlatData -> §8.1)
  (a :u8) (b :u32) (c :u64))                     ; u8@0, u32@4 (3-byte pad), u64@8 -> +fd-abc-flatdata-size+ = 20

(let ((fd (make-fd-abc-flatdata)))               ; a foreign buffer == the full SerializedPayload (header written once)
  (setf (fd-abc-a-fd fd) 200                      ; Offset SET: write each field in place, 0-alloc
        (fd-abc-b-fd fd) 3000000000
        (fd-abc-c-fd fd) 12345678901234567890)
  (assert (= (fd-abc-a-fd fd) 200))               ; Offset GET: read in place, 0-alloc for fixnum-range fields
  ;; the buffer IS the wire: byte-identical to the engine's classic serialize of an equal struct
  (let* ((ts   (dds.types:find-type-support "fd-abc"))
         (wire (dds.dcps::%serialize-sample ts fd))                  ; FlatData identity TX (block-copy)
         (classic (dds.dcps::%serialize-sample ts (make-fd-abc :a 200 :b 3000000000 :c 12345678901234567890))))
    (assert (equalp wire classic)))                                  ; in-memory == wire, proven against the oracle
  (dds.pal:free-static (dds.core.buffer:octet-buffer-vec fd)))
```

**Composed with Zero-Copy — literal-0-copy RX via the loan API (WP-FLATDATA-ZC-LOAN, ADR 0017):** a `:flatdata t` DataReader created while `dds.disc:*zerocopy-enabled*` is on is **loan-capable** — the disc receiver thread stores the **unresolved** 16-byte ZC reference (no copy; the slot stays loaned via the writer's `refcount = matched-readers`, set at `%zc-loan`), and the DCPS **loan API** hands the app a `dds.types:flatdata-view` over the **live writer slot**. Reading fields via the same `<name>-<field>-fd` accessors then reads **directly off the writer's SHMEM slot SAP — literal 0 intra-host copies** (the accessor dispatches owned-buffer vs `flatdata-view` on one predicted struct-type branch; the view path is byte-exact to the aref read). The slot is held by the writer's refcount from `%zc-loan` → the receiver-thread store (no release) → `take-loaned`'s `%zc-acquire-for-read` (no refcount inc) → the app's reads → `return-loan`'s `%zc-release` (the 1→0 edge frees it); **force-reclaim skips `refcount>0` slots**, so a loaned slot can never be overwritten under the app's read (no use-after-free). A leaked loan pins a slot and the writer's pool gracefully falls back to non-ZC (no wedge); reader-close (`delete-participant`) returns every outstanding loan before detaching the pool (no leaked refcount):

```lisp
(let ((dds.disc:*shmem-enabled* t) (dds.disc:*zerocopy-enabled* t))   ; arm ZC (default OFF, R6); same-host
  ;; ... two participants on one host; a FlatData topic "fd-abc"; the writer publishes fd over Zero-Copy ...
  (multiple-value-bind (samples loans) (dds.dcps:take-loaned dr)       ; borrow the samples by reference
    (let ((view (first samples)))                                       ; a dds.types:flatdata-view (NOT a copy)
      (assert (dds.types:flatdata-view-p view))
      (= (fd-abc-a-fd view) 200))                                       ; 0-copy field read straight off the writer's slot
    (dds.dcps:return-loan dr loans)))                                   ; release the slot (idempotent; reader-close also returns)
```

For a **non-loan-capable** reader (ZC on but the type is *not* `:flatdata`) the receiver thread keeps the shipped resolve-copy-release path: it resolves the slot **in place into one exact-length owned vector** (`%zc-resolve-fresh`) — a **safe single copy** out of SHMEM, **~830× less RX allocation** than the WP-ZEROCOPY-v1 sink+re-copy (`make bench-flatdata`) — then releases the slot immediately. With `*zerocopy-enabled*` OFF or a non-FlatData reader the disc + DCPS paths are **byte-identical** to before. **Honest costs (FR-LANG-7, `make bench-flatdata-zc-loan` → `bench/report/2026-06-16-wp-flatdata-zc-loan.md`):** the literal-0-copy loan RX eliminates the per-sample **owned delivery vector** — the headline RX GC bytes/sample drops to the **bare pool-mutex acquire (~32 B/sample, payload-independent)** vs the FlatData+ZC v1 single-copy **~79** (mutex + the ~47-octet owned vector) and the WP-ZEROCOPY-v1 sink+re-copy **~65551** (the progression **65551 → 79 → 32**); the `flatdata-view` is recycled from a per-reader freelist (no per-sample GC view alloc). This is **not free** — the loan API ADDS the explicit `%zc-acquire-for-read` + `%zc-release` calls (each takes the pool mutex) + the app's `return-loan` **obligation** (a leaked loan pins a slot until the writer's pool gracefully falls back to non-ZC); the full loan+return cycle is ~96 B/sample. TX serialize is 0 GC-bytes/sample but the TX path still has one app→slot copy at `%zc-loan` (the loan-**write** API is the follow-up); the untrusted wrap **and** the literal-0-copy loan-acquire path are fuzzed including `(safety 0)` arms (forged slot/generation/recorded-len ⇒ NIL or a slot-clamped view, never an OOB). The concurrency lifetime safety property (no UAF / no torn read / no refcount leak with a concurrent writer churning the pool while a loan is held) is proven by a real-thread stress test. **Deferred follow-ups:** the loan-**write** API (the remaining TX copy); the Builder + variable-size/string/sequence/nested FlatData (incl. variable-size/string `@key`); Clasp ZC (NFR-PORT gap). *(RELIABLE-ZC-loan and keyed FlatData for fixed-size scalar `@key` are now done — see §8.1.)*

### 8.1 Keyed FlatData — fixed-size scalar `@key` (WP-KEYED-FLATDATA, FR-PF-4 + FR-TYPE-5; R6, NOT cleared for ship)

A `:flatdata t` type may carry **fixed-size scalar `@key` members** (WP-KEYED-FLATDATA, 2026-06-17 — this closes the FlatData v1 NO_KEY deviation, ADR 0015). The original NO_KEY restriction existed because the spec keyhash `key-hash-<name>` reads a **struct** sample via slot accessors, and a FlatData sample has no struct — it is the octet buffer. The fix is a **buffer-reading keyhash** `key-hash-<name>-fd (sample)` (the `sample` is the FlatData octet-buffer **or** a `flatdata-view`) that reuses the struct keyhash's exact serialization — the `@key` members in member order to a **big-endian XCDR2 cursor**, the **≤16-octet → zero-padded-direct / >16-octet → MD5** rule (**RTPS 2.5 §9.6.4.8**) — sourcing each value from the `<name>-<field>-fd` Offset accessor instead of the struct slot. It is therefore **byte-identical to the struct keyhash** for the same key values, so a keyed FlatData instance's identity equals what a non-FlatData peer computes (the conformance crux). Wiring it into `type-support` (`:keyed-p t` + `:key-hash #'key-hash-<name>-fd`) lights up the existing keyed machinery: real per-key loan handles, NEW/NOT_NEW view-state, per-instance KEEP_LAST (copy **and** ZC loan path), and dispose/unregister by sample. A **variable-size / string `@key` member is still a compile-time error** (FlatData v1 fixed-size scalar).

The `-fd` keyhash is **off the measured CDR hot path** (computed only for keyed FlatData) — `make mem` stays 0.0000; no new bench is warranted (FR-LANG-7). Worked example (the `≤16`-octet direct path; adapted from `run-keyed-flatdata-keyhash-test` in `src/dds-tests/rtps-test.lisp`):

```lisp
(dds.gen:define-dds-type keyed-fd-i32 (:flatdata t)   ; FINAL fixed-size scalar, ONE i32 @key
  (k :i32 :key t) (v :i32))                            ; +keyed-fd-i32-flatdata-size+ = 12 (4 encap + i32 k @4 + i32 v @8 -> 8 body)

(let ((b (make-keyed-fd-i32-flatdata)))                ; a foreign buffer == the full SerializedPayload
  (setf (keyed-fd-i32-k-fd b) #x01020304               ; Offset SET the @key field in place (0-alloc)
        (keyed-fd-i32-v-fd b) #x7f7f7f7f)
  ;; the 16-octet keyhash = the i32 key BIG-ENDIAN, zero-padded to 16 (<=16 -> direct, RTPS 2.5 §9.6.4.8):
  (assert (equalp (key-hash-keyed-fd-i32-fd b)
                  #(#x01 #x02 #x03 #x04 0 0 0 0 0 0 0 0 0 0 0 0)))
  ;; and it is byte-identical to the STRUCT keyhash for the same key value (the conformance crux):
  (assert (equalp (key-hash-keyed-fd-i32-fd b)
                  (key-hash-keyed-fd-i32 (make-keyed-fd-i32 :k #x01020304 :v 0))))
  (dds.pal:free-static (dds.core.buffer:octet-buffer-vec b)))
```

A key holder wider than 16 octets takes the **MD5 path** instead — e.g. a type with three `i64` `@key` members (24 octets) yields `MD5` of the 24-octet big-endian XCDR2 key holder, again byte-identical to the struct keyhash (the `>16` arm of `run-keyed-flatdata-keyhash-test`). With the keyhash wired, a keyed FlatData app reads per-key instance handles in SampleInfo, sees NEW for a first-seen key and NOT_NEW for a repeat, gets per-instance KEEP_LAST, and disposes/unregisters an instance by passing the FlatData buffer to `dispose`/`unregister` (the keyhash reads it). **Cross-DDS interop F1 (per-feature DoD 2026-06-17, [`interop/keyed-flatdata/`](../../interop/keyed-flatdata/)): CONNEXT 7.3.1 + FAST DDS 3.6.1 LIVE PASS, BOTH DIRECTIONS.** Beyond the offline byte-exactness (vs the spec rule, vs our own struct keyhash, and vs an independently-derived conformant-peer keyhash in `keyed-flat-interop-keyhash`), the keyhash/instance-identity is **confirmed live on the wire**: our keyed FlatData publisher → RTI Connext 7.3.1 and Fast DDS 3.6.1 subscribers that each grouped the samples into the correct per-key instances with a **byte-identical keyhash**, and our dispose-by-key resolved to the right instance. The **forward leg** (a foreign publisher → our `:flatdata t` subscriber) is **now PASS via the transcode** (WP-FLATDATA-XCDR-TRANSCODE, 2026-06-17): a conformant peer defaults to XCDR1 (`PLAIN_CDR_LE` 0x0001 on the wire), and the reader **transcodes** the foreign representation into its canonical XCDR2-LE buffer (see §8.2 *The foreign-representation transcode model* below) instead of rejecting it — this closes the earlier forward-leg false-REJECT (the reader used to read only `PLAIN_CDR2_LE` 0x0007). See [Interop](interop.md).

### 8.2 The foreign-representation transcode model (WP-FLATDATA-XCDR-TRANSCODE, FR-PF-4; R6, NOT cleared for ship)

A FlatData type's canonical sample buffer is `PLAIN_CDR2_LE` (`0x0007`). Originally the reader read **only** that representation and **rejected** any other RTPS encapsulation id (false-REJECT-safe — it dropped, never mis-read). A conformant RTI Connext / Fast DDS peer, however, defaults to **XCDR1** (the wire shows `PLAIN_CDR_LE` `0x0001`), so a foreign publisher → our `:flatdata t` subscriber matched but every sample was rejected. WP-FLATDATA-XCDR-TRANSCODE makes the FlatData reader read **any standard representation** by transcoding it into the canonical buffer. The SerializedPayload rep-id (`dds.cdr:+representation-ids+`, **DDS-XTypes 1.3 §7.6.3.1.2** — read from the table, never hardcoded) selects one of three branches in `deserialize-into-<name>-fd`:

| Rep-id | Representation | Branch |
|---|---|---|
| `0x0007` PLAIN_CDR2_LE | XCDR2 little-endian (canonical) | **native read-in-place** (0-copy/0-alloc) — unchanged |
| `0x0000` PLAIN_CDR_BE | XCDR1 big-endian | **transcode** (mode `:xcdr1`, cursor `:big`) |
| `0x0001` PLAIN_CDR_LE | XCDR1 little-endian | **transcode** (mode `:xcdr1`, cursor `:little`) |
| `0x0006` PLAIN_CDR2_BE | XCDR2 big-endian | **transcode** (mode `:xcdr2`, cursor `:big`) |
| PL_CDR(2) / DELIMITED_CDR / XML | (not expected for a FINAL fixed-size PLAIN type) | **clean reject** (false-REJECT-safe) — unchanged |

**The transcode reuses the sibling struct codec (no new codec; DRY).** A FlatData type *also* emits the classic `deserialize-<name>` / `serialize-<name>` struct codecs (kept for interop / non-FlatData use), and the struct decoder already accepts both `mode :xcdr1` / `:xcdr2` with an endianness-aware cursor. So the transcode is: **decode** the foreign body via `deserialize-<name>` (mode + cursor endianness from the rep-id) into a `<name>` struct, then **re-serialize that struct XCDR2-LE** via the existing `serialize-<name>` into the reader's canonical FlatData octet-buffer. The result is the canonical XCDR2-LE buffer the `<name>-<field>-fd` accessors and `key-hash-<name>-fd` read — so keyhash, per-key instance, view-state, and KEEP_LAST compose identically to a native sample (the transcode runs **before** the keyhash derivation).

**Why decode-then-reserialize, not a pure byte-swap.** XCDR1 caps alignment at 8 and XCDR2 at 4 (**DDS-XTypes 1.3 §7.4**), so an 8-byte scalar sits at a *different offset* under the two encodings (e.g. `[i8, i64]` is 16 octets under XCDR1 vs 12 under XCDR2). The transcode is therefore a **re-align + byte-swap**, which routing through the struct decode + the XCDR2-LE re-serialize handles naturally — a byte-swap alone would be wrong.

**Cost + safety.** The native `0x0007` path is unchanged (read-in-place); the transcode is the **foreign-representation FALLBACK** (it allocs the decode + the re-serialize) — **off the measured CDR hot path**, so `make mem` stays **0.0000** and no hot-path number changes (no bench warranted). The foreign payload is **untrusted**: the struct decode bounds-checks every field against the body extent (even at `(safety 0)` — NFR-SEC-POSTURE), and the re-serialize writes exactly the `+<name>-flatdata-size+` layout into the fixed buffer (no overflow); a malformed/short foreign payload → a clean reject, never an OOB. The transcode + native + reject paths are covered by the offline oracle tests `flatdata-transcode-{xcdr1be,xcdr1le,xcdr2be,native,rejects-pl}` (the `-fd` accessors and `key-hash-<name>-fd` equal the native sample's, including the i64-`@key` XCDR1↔XCDR2 re-alignment) and the foreign-rep transcode fuzz arm (`make fuzz`, prod + `(safety 0)`). It benefits **all** FlatData types — keyed and unkeyed — since it is a reader *representation* fix. **Separate follow-up:** advertising the reader's accepted reps via `PID_DATA_REPRESENTATION` (0x0073) in SEDP + RxO matching (a general DATA_REPRESENTATION QoS feature for all types) would let a peer PREFER XCDR2 and skip the transcode; with the transcode the false-REJECT is closed without it.

## Notes / status

This is mid-M4 (P3 XTypes), built **verifiable-first**: anything checkable offline against the spec's own worked examples is landed and tested; anything that needs a conformant peer to lock the exact wire bytes is built but flagged PROVISIONAL.

- **The generator (v1) is deliberately narrow.** `define-dds-type` accepts `:final` and `:appendable`; `:mutable` framing for *generated* types is a later increment (needs per-member EMHEADER/NEXTINT — note that the assignability relation already handles all three extensibility kinds for hand-built TypeObjects). A `:flatdata` type must be `:final`: its in-memory layout *is* the wire, so a DHEADER in front of it would break the identity block-copy the mechanism rests on. `@key` is restricted to scalar/string members. Sequence members must have a fixed-size primitive element; sequences of strings/variable-size elements are rejected. **Enum members `(:enum NAME)` are accepted** (wire = `int32`), but carry `TK_INT32` in the TypeObject rather than a real `TK_ENUM` — see the known-gap note in [Example 1.2](#12-enum-members--enum-name). An enum member is rejected in a `:flatdata t` type: the slot holds a keyword while a FlatData Offset accessor reads the raw field, so the two would disagree about what the member is. **Bounded strings `(:string N)` are accepted** and emit `TI_STRING8_SMALL` + the SBound octet — the same field the externally-confirmed path already exercises (it carries `0` for an unbounded string), so only the *value* is new, not the framing; a bound **> 255** selects the `TI_STRING8_LARGE` LBound `UInt32` form instead, which **no live peer has yet exercised** — treat a `(:string N)` with `N > 255` as PROVISIONAL until an oracle confirms it. A nested-struct member must reference a previously-defined dds type (define-before-use; the DSL is acyclic).

- **The TypeObject serializer + EquivalenceHash are EXTERNALLY CONFIRMED for the exercised path** (live Fast DDS 3.6.1, an independent conformant peer — Connext never emits the minimal hash, ADR 0009). For the identical ShapeType IDL, Fast DDS's SEDP `PID_TYPE_INFORMATION` announces `EK_MINIMAL` hash `bf e2 a6 2e d8 11 ac 46 3c 40 c9 7d 30 ee` with `typeobject_serialized_size` 87 — byte-identical to ours; that 92-octet parameter value is locked as a regression vector (test `fastdds-type-information-vector`, from `interop/fastdds/captures/s1-forward-lo0.pcap` frames 236/237). MD5 equality pins the **whole** 87-octet MinimalTypeObject serialization, so the three formerly-provisional byte-level choices are confirmed for this path: (1) the hash is over the raw TypeObject XCDR2-LE bytes with **no** 4-byte encapsulation header; (2) `struct_flags` carries the extensibility bit only (minimal-masked); (3) `member_flags` is `TRY_CONSTRUCT=DISCARD` OR'd with `@optional`/`@must_understand`/`@key`. The exercised path is a FINAL struct with `i32` + unbounded `string8` members; PROVISIONAL now narrows to the unexercised serialization-VM edges — unions, MUTABLE structs, the `TK_NONE` base framing under the hash, sequence-member TypeIdentifiers, and nested-dependency hashes.

- **Sequence-member TypeObject serialization errors cleanly.** Plain-collection element flags / `EK_BOTH` / `@external` framing for sequence elements are the most oracle-sensitive, so `%put-type-identifier` signals an `error` for a sequence member rather than emit unconfirmed bytes (see Example 5). The structural model and assignability still handle sequences fully; only their *TypeObject serialization* is gated.

- **The TypeInformation codec is externally confirmed on the inbound side and spec-legal on the outbound side.** The parser consumes a real foreign-vendor value: live Fast DDS 3.6.1 frames the mutable members with `EMHEADER1 LC=5` (NEXTINT reused as the member's leading DHEADER, XTypes §7.4.3.4.2) and carries **both** the minimal (`0x1001`) and complete (`0x1002`) members with `dependent_typeid_count` −1; `deserialize-type-information-hash` recovers the `EK_MINIMAL` hash from it (test `fastdds-type-information-vector` — the parser originally accepted only our own `LC=4` framing and was fixed failing-test-first). Our emission stays minimal-only with `LC=4` (explicit NEXTINT length) and insertion-order dependents — spec-legal, and live Fast DDS consumed it (S1/S2 census). It round-trips offline and rides the SEDP endpoint ParameterList as `PID_TYPE_INFORMATION`; match-time use is **gated, never hash-equality-enforced**: equal EquivalenceHashes are only a fast path, differing hashes fall through to the TypeLookup-fed assignability gate (see [DCPS](dcps.md)) — hash inequality alone never rejects a peer (ADR 0009).

- **`enforce-type-consistency` implements Step 1 only.** It is the TypeObject-present assignability/equivalence decision (XTypes §7.6.3.4.2). Step 2 — the type-name fallback and `force_type_validation` when no TypeObject is on the wire — is a DCPS match-time concern. The `TYPE_CONSISTENCY_ENFORCEMENT` QoS policy carrier itself lives in `dds.qos` (see [QoS](qos.md)); its spec defaults are exercised in `run-assignability-test`.

- **Assignability coverage is exactly the modeled kinds.** Primitives, narrow strings, plain sequences, (nested) structs, enumerated types (`enum-assignable-from`, XTypes §7.2.4.4.7 Table 18 — a same-NameHash/different-value pair is the only provable reject; literals present on one side only are uncertain and fail open), and **plain arrays** (`ti-array-p` branch of `ti-assignable-from`, XTypes §7.2.4.4.6 Table 17 — arrays are not resizable, so **identical** fixed dimensions are required plus a strongly-assignable element; a differing size or element kind is a provable reject; multi-dimensional arrays are a decode gap and fail open) — the kinds the generator can construct and therefore test. Union / bitmask / map / alias assignability awaits their type model and is conservatively non-assignable today. SCC / cyclic types (§7.3.4.9.2) are out of scope because the DSL is acyclic.

- **Inbound RTI `PID_TYPE_OBJECT_LB` inflate (`inflate-type-object-lb`, ADR 0009).** RTI Connext advertises a type on the wire via the **vendor** parameter `PID_TYPE_OBJECT_LB` (0x8021) — a ZLIB-compressed **complete** TypeObject — and (for small types) **never** the minimal-hash `PID_TYPE_INFORMATION`. So the minimal-hash match path is unreachable against Connext; the "required path" is to consume that complete TypeObject. `inflate-type-object-lb` is the first piece: it parses the RTI vendor header (`compression_class_id`/`uncompressed_length`/`compressed_length`, reverse-engineered from the live Connext wire, clean-room) and ZLIB-inflates the payload (`chipz`, pure-Lisp), with every length bounds-checked and `uncompressed_length` capped by `*max-type-object-bytes*` (NFR-SEC-POSTURE). Validated byte-exact against a real Connext ShapeType capture (540 octets).
  - **The inflated payload is RTI's *proprietary legacy* TypeObject** (a vendor "TypeLibrary" binary), **not** the OMG `CompleteTypeObject` — and this Connext sends no `PID_TYPE_OBJECT` (0x0072) or `PID_TYPE_INFORMATION` (0x0075) for small types, so no spec-conformant type representation is on the wire. A full structural parse is therefore a large RTI-format reverse-engineering effort (deferred, robustness-only — interop already works via type-name + QoS matching).
  - **In its place, a lightweight type *fingerprint*** (`type-object-strings`, `type-object-mentions-all-p`) extracts the literal names RTI embeds (type name + multi-octet member names + dependent type names) for a heuristic type-aware match / diagnostics — coarse on purpose (1-octet member names and the structure are not recovered).
  - **A structural reverse-engineering path is now underway (ADR 0009, clean-room).** `tokenize-legacy-type-object` walks the inflated legacy TypeObject into an `lto-node` TLV tree (two known TAG words separate nested nodes from opaque header/hash bytes; every read bounds-checked and depth/element/string-bounded — NFR-SEC-POSTURE), and `parse-legacy-type-object` folds that tree into a `minimal-struct-type` **skeleton**: the struct type name, the member names, and the 0-based declaration-order member ids. The node-to-model mapping is derived only from captured bytes + the `C_Shape` / `C_Shape3` (member counting + appended id) / `C_Shape4` (id is positional, not stable across a reorder) differential experiments (`docs/provenance.md`, the `interop/connext/typeobject-corpus` corpus). It MIRRORS `parse-minimal-type-object`'s discipline — a struct on success, `:unsupported` for a tree carrying no recognizable struct shape, `NIL` for input that does not tokenize. **Primitive member types are now decoded** (`%lto-member-type-identifier`): the primitive kind is the u16 at the member node's `VALUE-START+8`, mapped via `*lto-primitive-kind-keyword*` from RTI's own kind enumeration (which differs from the XTypes `TK_*` octets — e.g. RTI long=5 vs `TK_INT32`=4, char=0x0C vs `TK_CHAR8`=0x10) to a `primitive-type-identifier`; established clean-room by the `C_ShapeP_<prim>` corpus differential (each retypes member `x`). **String member types and the `@key` flag are now decoded too**: a string member's node carries kind `0x13` at `VALUE-START+8` plus an 8-octet type-hash at `+16` that references a string-definition node (`+lto-code-string-def+`, CODE 8); `%lto-find-string-bound` follows the hash to that node and reads the bound as a u32 from its `+lto-code-string-bound+` (CODE 200) child, building a `STRING8` `type-identifier` via `string8-type-identifier`. The bound is **always** a u32 on RTI's wire (255 is RTI's default for an unbounded `string`, 32 / 300 for `string<32>`/`string<300>`); the XTypes small (`≤255`) / large (`>255`) split is applied only when our in-memory TI is built. The member's `@key` flag is the u32 at the member node's `VALUE-START+0` (1 for the key member, 0 otherwise), set on `minimal-struct-member-key-p` (`%lto-member-key-p`). Both were established clean-room by the `C_ShapeS32` / `C_ShapeS300` / `C_ShapeNoKey` corpus differentials. So the base `C_Shape` now parses with `color` as a `STRING8` bound 255 (`@key`), and `x`/`y`/`shapesize` as non-key `TK_INT32`. **Struct extensibility is now decoded too** (`%lto-struct-extensibility`): the flag is the u16 at the struct-definition node's first `CODE 0` child's `VALUE-START+0`, mapped via `*lto-extensibility-keyword*` from RTI's own enumeration (`@appendable`=0, `@final`=1, `@mutable`=2 — which coincides with the XTypes `IS_*` struct-flag bits only for `:final`) to `:final`/`:appendable`/`:mutable`; an unknown flag value fails open to `:final` (the strictest extensibility for assignability gating). Established clean-room by the `C_ShapeAppend` / `C_ShapeMutable` corpus differentials (member encoding was byte-identical across all three — `@mutable` did not change the scalar/string member layout). **Sequence-of-primitive member types are now decoded too** (`%lto-sequence-type-identifier`, Stage 3 Task 3.1): a sequence member's node carries kind `0x12` (18) at `VALUE-START+8` plus an 8-octet type-hash at `+16` that references a sequence-definition node (`+lto-code-sequence-def+`, CODE 7 — vs CODE 8 for strings) via the *same* hash-reference mechanism strings use (`%lto-find-def-node`, refactored out of the string path so both share it — DRY). That node's `+lto-code-sequence-element+` (CODE 100) child holds the element type-kind as a u16 in RTI's own primitive enum (octet 2 / long 5), and its `+lto-code-string-bound+` (CODE 200, shared with strings) child holds the sequence bound as a u32; the decoder builds a `sequence-type-identifier` over a `primitive-type-identifier` element with that bound. RTI emits bound **100** for an *unbounded* sequence (the `C_Seq` `sequence<octet>` capture; mirroring the 255 default for unbounded strings — recorded as `+lto-sequence-default-bound+`, documentation only, the decoder reads the wire bound). Established clean-room by the `C_Seq` (`sequence<octet>`) / `C_SeqL` (`sequence<long,10>`) / `C_SeqL100` (`sequence<long,100>`) corpus differentials. A sequence whose **element** is itself a string, a nested aggregate, or another sequence is a Stage-3.2 gap: the element kind is non-primitive, so the member `type-identifier` stays `NIL` and parsing continues (fail-open). **Nested-struct (aggregate) member types are now decoded too** (`%lto-nested-type-identifier`, Stage 3 Task 3.2): a legacy TypeObject is a **TypeLibrary** — publishing `C_Nested` makes RTI emit the nested `C_Inner`'s definition as a *sibling* top-level struct-definition node (`+lto-code-struct+`, CODE 9) in the same TypeObject (the outer struct comes first in pre-order). A nested-struct member's node carries kind `0x16` (22) at `VALUE-START+8` plus the *same* 8-octet type-hash at `+16` (strings use `0x13`/CODE 8, sequences `0x12`/CODE 7, nested struct `0x16`/CODE 9) referencing that sibling def; the shared `%lto-find-def-node` resolves it with `def-code = +lto-code-struct+` unchanged. The resolver parses the referenced def into a `minimal-struct-type` and wraps it in an `EK_MINIMAL` `hash-type-identifier` whose `referenced` slot is the parsed nested model — exactly the shape `struct-assignable-from` and the TypeLookup gate recurse into. The struct-node→model fold is the shared `%lto-parse-struct-node` helper, called by **both** the top-level parse entry and the nested resolver, so nesting recurses naturally (DRY). Recursion is bounded by `*lto-max-type-depth*` (16) **and** a visited-hash set keyed by the member's hash@+16: a self- or mutually-referential reference fails open (member `type-identifier` `NIL`) at depth 1, so a hostile cyclic TypeObject **terminates, never hangs** (NFR-SEC-POSTURE). Established clean-room by the `C_Nested` / `C_Nested2` corpus differentials. This extends the flat-struct parse to **names / ids / primitives / strings / keys / extensibility / sequence-of-primitive / nested-struct decoded (nested structs recurse through assignability); sequence-of-{string,struct,sequence} and the remaining Stage-4 aggregates (union/typedef/map/multi-dim array) remain undecoded** (enum and single-dimension array now decode — Stage 4). **The degrading policy is now explicit (Task 4.1).** A member that *declares* a type the model cannot represent — an unmapped member-kind word (bitmask), a non-modelable union (default member / non-primitive discriminator-or-member / multi-label case), a multi-dimensional array, an unresolvable hash, a sequence/array-of-aggregate, or an over-depth/cyclic nested struct — degrades the **whole** `parse-legacy-type-object` to `:unsupported` (fail-open to name-match) rather than emitting a partial `minimal-struct-type` with a `NIL`-`type-identifier` member that the Stage-5 gate could mis-handle. Concretely, in `%lto-parse-struct-node`, when a member has a kind word present (`%lto-member-has-kind-p`) but `%lto-member-type-identifier` returns `NIL`, the parse returns `:unsupported`. **Enums** were originally the worked degrade case; **enum members now decode structurally (Task S0.3, 2026-06-12)** into a real `EK_MINIMAL` enumerated `type-identifier` and are no longer in the degrade tier. An enum member's node carries kind `0x0E` (14) at `VALUE-START+8` plus the *same* 8-octet type-hash at `+16` (strings `0x13`/CODE 8, sequences `0x12`/CODE 7, nested structs `0x16`/CODE 9, enum `0x0E`/CODE 5) referencing an enum-definition node (`+lto-code-enum-def+`, CODE 5); the shared `%lto-find-def-node` resolves it. That node's `+lto-code-enum-bitbound+` (CODE 100) child holds the storage bit-bound (u32, 32 for a default enum), and its `+lto-code-enum-literals+` (CODE 101) child holds the literal list: `count:u32`, then per literal `value:u32` + a length-prefixed NUL-padded literal **name** (the same string framing `%lto-read-name` decodes). `%lto-enum-type-identifier` folds this into a `minimal-enumerated-type` (`make-minimal-enumerated-type`) wrapped in an `EK_MINIMAL` `enumerated-type-identifier`. Because the wire carries literal **names**, each literal is built with `make-enum-literal name value` so its NameHash (MD5(name)[0:4]) matches a locally-built model's — and `enum-assignable-from` (XTypes §7.2.4.4.7 Table 18) gates by NameHash: a same-name/different-value pair is the only provable reject. (CODE 100/101 collide with the sequence-element / struct-member-list codes but are disambiguated by parent code — read only via the resolved enum-def, so no collision.) The bit-bound, literal layout, and enum-def CODE 5 were pinned clean-room by the `C_Enum` (`@key long id; SomeEnum{RED,GREEN,BLUE} e`) corpus differential (`docs/provenance.md` 2026-06-12), cross-checked against the IDL ground truth RED=0/GREEN=1/BLUE=2. An enum is **not** silently decoded to its underlying integer (which would widen an enum to `long` and let an enum-vs-`long` mismatch pass the gate). The parsed `minimal-struct-type` is the SAME struct type the generator builds, so it feeds `struct-assignable-from` (see [assignability](#assignability)) unchanged: `lto-assignability` proves a locally-built model for the captured `C_Shape` is assignable both directions from the parsed wire model (compatible → `T`), while an incompatible local (a retyped or dropped member) is rejected (→ `NIL`); `lto-parse-nested` proves the same recursion through a **nested** member — a nested-compatible local `C_Nested` is assignable (→ `T`) and a nested-incompatible local (the inner `C_Inner.a`/`.b` retyped) is rejected (→ `NIL`). **Union and array members now decode structurally (Tasks 2.3 / 1.3).** **Union members now decode (`%lto-union-type-identifier`, Task 2.3, 2026-06-12)** into a real `EK_MINIMAL` union `type-identifier` and are no longer in the degrade tier. A union member's node carries kind **`0x15` (21)** at `VALUE-START+8` plus the *same* 8-octet type-hash at `+16` (strings `0x13`/CODE 8, sequences `0x12`/CODE 7, nested structs `0x16`/CODE 9, enum `0x0E`/CODE 5, array `0x11`/CODE 3, union `0x15`/CODE 10) referencing a union-definition node (`+lto-code-union-def+`, CODE 10); the shared `%lto-find-def-node` resolves it. That node's `+lto-code-union-cases+` (CODE 100) cases-container child holds `count:u32` (the discriminator + members) then, per entry, a named CODE-0 node (its discriminator/member type-kind a u16 at `VALUE-START+8`) immediately followed by a CODE-100 label-list child (`count:u32` then `count` labels, each i32). The **first** named entry is the discriminator (empty label list); every later named entry is a member carrying a single case label. `%lto-union-type-identifier` folds this into a `minimal-union-type` (`make-minimal-union-type` — discriminator TI + a `make-union-member` per case) wrapped in a `union-type-identifier`. Because the wire carries member **names**, each member is built with `make-union-member name labels ti default-p` so its NameHash matches a locally-built model's — and `union-assignable-from` (XTypes §7.2.4.4.8 Table 19 UNION_TYPE row) gates by **shared case label**: two members selected by a common label whose types are not assignable is the provable reject. The decoder models a **PRIMITIVE discriminator + per-case PRIMITIVE members only**; a default member, a non-primitive discriminator/member, or a multi-label case (`label count ≠ 1` — the encoding is unverified by the `C_Union` capture) fails open to `NIL` → member unmodelable → whole parse `:unsupported`. (CODE 100 collides with the sequence/array-element + enum-bitbound codes, but is disambiguated by parent code — read only via the resolved union-def.) Union-def CODE 10 + cases-container/label-list CODE 100 + the label count/value layout were pinned clean-room by the `C_Union` (`@key long id; SomeUnion switch(long){case 0: long a; case 1: double b} u`, 608 octets inflated) differential (`docs/provenance.md` 2026-06-12), cross-checked against the IDL ground truth (discriminator `long`→`i32`; case 0 → `a` `i32`; case 1 → `b` `f64`). Decoding a union into its `minimal-union-type` also required extending `ti-delimited-p`: a union is self-delimiting iff its discriminator **and** every member type are delimited (a sound, verifiable condition — a FINAL union of delimited members is bounded by discriminator + selected member), removing the false-reject the earlier conservative "union = NOT delimited" default produced for a union member inside a FINAL struct. The live `C_Union` capture now parses to a `minimal-struct-type` whose `u` member is a union TI (disc `i32`; `{0}`→`a` `i32`; `{1}`→`b` `f64`), driving `struct-assignable-from`: a matching local is assignable both ways, a local where case 0's member type changes `long`→`double` is rejected, and re-running the compatible case proves no false-reject. **Array members now decode (`%lto-array-type-identifier`, Task 1.3, 2026-06-12).** An array member's node carries kind **`0x11` (17)** at `VALUE-START+8` plus the *same* 8-octet type-hash at `+16` (strings `0x13`/CODE 8, sequences `0x12`/CODE 7, nested structs `0x16`/CODE 9, enum `0x0E`/CODE 5, array `0x11`/CODE 3) referencing an array-definition node (`+lto-code-array-def+`, CODE 3); the shared `%lto-find-def-node` resolves it. That node's `+lto-code-array-element+` (CODE 100) child holds the element type-kind as a u16 in RTI's own primitive enum (long 5 → `i32`, mapped via `*lto-primitive-kind-keyword*`), and its `+lto-code-array-dims+` (CODE 200) child holds the dimension list: `count:u32` then `count` bounds (each u32). The decoder accepts **only a single fixed dimension** — `count = 1` *and* the child value extent exactly 8 octets (4 count + 4 one bound) — and builds an `array-type-identifier` over the primitive element with that size; a **multi-dimensional** array (`count ≠ 1`) or a non-primitive element fails open to `NIL` → member unmodelable → whole parse `:unsupported` (the in-memory model is single-dimension, primitive-element only). (CODE 100 collides with the sequence-element / enum-bitbound codes and CODE 200 with the string/sequence-bound code, but all are disambiguated by parent code — read only via the resolved array-def.) The live `C_Array` capture (`@key long id; long arr[4]`, 416 octets inflated) now parses to a `minimal-struct-type` whose `arr` member is a plain-array TI (element `i32`, size 4), driving `struct-assignable-from`: a matching local (`i32` × 4) is assignable both ways, a local with `arr[5]` (size) or short `arr[4]` (element kind) is rejected, and re-running the compatible case proves no false-reject. Array-def CODE 3 + element-kind CODE 100 + dimension CODE 200 (count+bounds) were pinned clean-room by the `C_Array` differential (`docs/provenance.md` 2026-06-12), cross-checked against the IDL ground truth (element `long`→`i32`, one dimension, size 4). **Bitmask** is a gap: `rtiddsgen 4.3.1` rejects the `bitmask` keyword; the gap is recorded in `docs/provenance.md`. The known member-kind table (all at member node `VALUE-START+8`, little-endian u16): primitives `0x01`–`0x0C`, enum `0x0E` (decodes), array `0x11` (decodes), sequence `0x12`, string `0x13`, union `0x15` (decodes), nested struct `0x16`, bitmask (gap — not capturable with `rtiddsgen 4.3.1`). Tested against the locked `C_Union` (structural parse) and `C_Array` (structural parse) captures in `lto-parse-aggregates-unsupported`, with the full union-TI proof in `lto-union-assignability` and the full array-TI proof in `lto-array-assignability`. Tested against the locked live Connext `C_Shape` (`lto-parse-shape`), ten `C_ShapeP_<prim>` captures (`lto-parse-primitives`), four string/`@key` captures (`lto-parse-strings-keys`), the `@final`/`@appendable`/`@mutable` extensibility captures (`lto-parse-extensibility`), three sequence captures (`lto-parse-sequence`), the `C_Nested`/`C_Nested2` nested captures (`lto-parse-nested`), the assignability proof (`lto-assignability`), the live `C_Enum` capture parsing structurally (`lto-parse-enum`) and its enum-member assignability proof (`lto-enum-assignability` — the `e` member decodes to a `SomeEnum{RED=0,GREEN=1,BLUE=2}` enum TI, a matching local is assignable both ways, a local that changes BLUE's value is rejected, and re-running the compatible case proves no false-reject), the degrading policy itself (`lto-unmodelable-unsupported`, now driven by an over-depth nested-struct member under `*lto-max-type-depth*` 0), the union/array aggregates (`lto-parse-aggregates-unsupported`), the union-member assignability proof (`lto-union-assignability` — the `u` member decodes to a `SomeUnion` union TI [disc `i32`; `{0}`→`a` `i32`; `{1}`→`b` `f64`], a matching local is assignable both ways, a local where case 0's member type changes `long`→`double` is rejected, and re-running the compatible case proves no false-reject), and the array-member assignability proof (`lto-array-assignability` — the `arr` member decodes to an `i32` × 4 plain-array TI, a matching local is assignable both ways, `arr[5]`/short-`arr[4]` locals are rejected, and re-running the compatible case proves no false-reject). **102 tests green SBCL + Clasp — enum, array and union members gate structurally; remaining degrade tier (bitmask-gap/map/typedef + sequence/array-of-aggregate + multi-dim array + over-depth/cyclic nested + non-primitive/multi-label/default union) verifiably fails open to `:unsupported`:** the Stage-5 gate falls open to name-match and never sees a partial model with a `NIL`-TI member. **The parser now drives a LIVE Connext type-gate (Stage 6, 2026-06-11, ADR 0011 — completes ADR 0010):** wired into the DCPS assignability gate (Stage 5), `parse-legacy-type-object` was exercised against a **live RTI Connext 7.3.1** writer via the DCPS-level gated subscriber `dds.shapes:run-gated-subscriber` (`make gated-sub`) — a structurally-compatible local `C_Shape` gated `:compatible` (matched, C_Shape samples delivered); a structurally-incompatible local (`shapesize` long→`i64`) gated `:incompatible` (INCONSISTENT_TOPIC, no data); and the compatible peer was never false-rejected on a re-run. See [DCPS → Assignability-gated matching](dcps.md) and [Interop](interop.md) for the run + evidence.
  - **Match-time advisory verdict (`assess-type-object-lb`, `type-support-fingerprint-names`).** The fingerprint is applied against the *local* type: `type-support-fingerprint-names` lists the local struct's ≥2-octet member names (the struct type name is excluded — peers like Connext spell it `ShapeType` where a local registration says `shape-type`), and `assess-type-object-lb` checks whether the peer's inflated TypeObject mentions all of them, returning one of `:names-present` / `:names-absent` (with the missing names) / `:no-type-object` / `:inflate-failed` / `:not-assessable`. It is **purely advisory** — a heuristic confirmation/diagnostic, **never** a match gate (the peer already matched on topic + type name, and a missing name is inconclusive against RTI's legacy TypeObject). The DCPS layer records the verdict per matched DataReader/DataWriter for inspection and can log it; see [DCPS](dcps.md). Tested against the real Connext ShapeType LB (`xtypes-type-compat-soft`, `dcps-type-compat`).
- **The built-in TypeLookup service is complete offline (FR-TYPE-3, ADR 0010).** The `TypeLookup_Request` **and** `TypeLookup_Reply` XCDR2 codecs are in (see the API section above). Connext does not implement this protocol, so the byte-level choices (FINAL top level with `CDR2_LE` per the Fast DDS `@final` convention, flat DDS-RPC headers, default-appendable `Call`/`Return`/`Result` unions with DHEADERs, `LC=5` mutable members, the §7.6.3.3.2 `ReplyHeader` over the §7.6.3.3.3 IDL's `RequestHeader` misprint, the omitted `TypeLookup_Return` on a non-OK `remoteEx`) are frozen as self-pinned regression vectors (test `typelookup-vectors`), cross-checked field-by-field by the tshark RTPS dissector (zero disagreements; `make wire` gates two TL frames), and the getTypes reply leg is now **confirmed live vs Fast DDS 3.6.1** (FR-IO-2 S4 leg A, 2026-06-12, test `fastdds-typelookup-reply-vector`): the conformant answer keys the COMPLETE TypeObject by its EK_COMPLETE TypeIdentifier and adds the `complete_to_minimal` mapping (§7.6.3.3.4.2), which the client reconstructs via `complete-to-minimal-type-object` — the discovery client (`%on-tl-reply`) delivers `(minimal-hash . minimal-octets)` pairs only when the reconstruction's own EquivalenceHash matches the mapping (else the pair drops, fail-open). The transport-free server core is also in (`find-type-support-by-hash` + `type-lookup-respond`, see the API section above). The four built-in endpoints, the discovery `type-gate` hook, and the match-time gate that feeds a `parse-minimal-type-object` result into `struct-assignable-from` are all in — see [Discovery](discovery.md) and [DCPS](dcps.md).
- **Deferred entirely (not yet present):** DynamicData (runtime-typed sample access without a generated struct). Today every type is generated ahead of time via `define-dds-type`.
