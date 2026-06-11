# Type system & code generation (L3)

This page covers **L3**, the type layer: the `dds.gen:define-dds-type` s-expr DSL, the `dds.types:type-support` manual vtable + registry, the in-memory XTypes structural model (TypeIdentifier / Minimal struct TypeObject / NameHash), structural assignability + `TYPE_CONSISTENCY_ENFORCEMENT`, the XCDR2 TypeObject serializer + EquivalenceHash, and the TypeInformation codec. L3 is the **linchpin of the no-CLOS-on-the-hot-path strategy**: `define-dds-type` is a build-time macro that emits a `defstruct` plus monomorphic, fully `ftype`-declared serialize/deserialize/serialized-size functions and registers a `type-support` — a plain `defstruct` of closures. The engine's hot path funcalls those slots and never sees the concrete sample type or any `defgeneric`/`defmethod` dispatch. The control-plane pieces (the XTypes model, assignability, the TypeObject/TypeInformation codecs) are also CLOS-free `defstruct` + monomorphic functions, but they run off the hot path.

See also: [CDR codec, buffers & the arena](cdr-and-memory.md) for the codecs and the `cursor`/arena the generated code drives, [QoS & RxO matching](qos.md) for the `TYPE_CONSISTENCY_ENFORCEMENT` policy carrier, [DCPS — the DDS entity API](dcps.md) for where types are registered with topics, and [Interop with RTI Connext](interop.md) for the Connext oracle that the PROVISIONAL TypeObject/TypeInformation bytes are pending against.

## API reference

### Code generation — `dds.gen`

- **`dds.gen:define-dds-type`** — macro; defines a DDS topic type `NAME` from an s-expr spec. `OPTIONS` is a plist (only `:extensibility`, default `:final`, in v1). Each member is `(slot-name member-type &key key)`, where `member-type` is a primitive keyword, `(:sequence element)`, or the name of a previously-defined dds type (nested struct). Emits a `defstruct`, `ftype`-declared `serialize-`/`deserialize-`/`serialized-size-` monomorphic functions (plus an internal `%ssize-` position-threading helper and a `deserialize-into-` in-place variant), a 16-octet key-hash for keyed types, and a registered `type-support`.

The DSL recognizes these member-type keywords (from `*dds-type-map*`): `:bool`, `:u8`, `:u16`, `:u32`, `:u64`, `:i8`, `:i16`, `:i32`, `:i64`, `:string`. A `(:sequence element)` member takes one of those keywords as its fixed-size primitive element (variable-size sequence elements, e.g. sequences of strings, are not supported in v1). v1 restricts `:extensibility` to `:final` and `@key` to scalar/string members.

### The type-support vtable + registry — `dds.types`

- **`dds.types:type-support`** / **`dds.types:make-type-support`** / **`dds.types:type-support-p`** — the per-type manual vtable the engine funcalls per sample: a `defstruct` of function objects plus the type name, extensibility, structural TypeObject/TypeIdentifier, and data-representation mask. The hot path sees only this struct.
- **`dds.types:type-support-name`** / **`dds.types:type-support-type-name`** — the registry key / qualified type name.
- **`dds.types:type-support-extensibility`** — `:final` / `:appendable` / `:mutable`.
- **`dds.types:type-support-serialize`** / **`dds.types:type-support-deserialize`** / **`dds.types:type-support-serialized-size`** — the codec closures (sample × cursor → sample; cursor → sample; sample → byte count).
- **`dds.types:type-support-key-hash`** — the 16-octet keyhash closure, or `nil` for a keyless type.
- **`dds.types:type-support-typeobject`** / **`dds.types:type-support-typeidentifier`** — the structural Minimal struct TypeObject and the type's own TypeIdentifier.
- **`dds.types:type-support-sample-pool-alloc`** / **`dds.types:type-support-sample-pool-free`** — loan / return a pre-allocated sample for zero-per-sample-allocation deserialize.
- **`dds.types:type-support-flatdata-offset`** / **`dds.types:type-support-flatdata-builder`** — FlatData hooks (P4).
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
- **`dds.types:primitive-type-identifier`** — the TypeIdentifier for a primitive / string DSL member keyword. `:u8`/`:i8` map to `TK_BYTE` (XTypes 1.3 has no distinct 8-bit int kind); `:string` is an unbounded `STRING8`.
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
- **`dds.types:equivalence-hash`** — `EquivalenceHash(S)` = first 14 octets of `MD5` of the serialized MinimalTypeObject (XTypes §7.3.4.9.1); nested struct members recurse to the referenced struct's hash.
- **`dds.types:parse-minimal-type-object`** — the exact inverse of `minimal-type-object-octets`: parse serialized `EK_MINIMAL` TypeObject octets (e.g. received via TypeLookup) back into a `minimal-struct-type` for assignability. Returns `:unsupported` for any kind outside the modeled subset (an `EK_COMPLETE` discriminator, a non-`TK_STRUCTURE` payload, a non-`TK_NONE` base, an unmodeled member TypeIdentifier) and for input over `*max-type-object-bytes*`; `NIL` on malformed/truncated input (network-facing: every read is bounds-checked). Plain-sequence member TypeIdentifiers — which the serializer cannot emit yet — parse per the IDL (`PlainSequenceSElemDefn`/`-L-`, xtypes-1_3_typeobject.idl §181-197). The parsed model carries name `""` (Minimal erases names), the wire NameHashes, and member `EK_*` hashes with `referenced` = `NIL`, and re-serializes byte-identically.

### TypeInformation codec (`dds.types`)

- **`dds.types:serialize-type-information`** — serialize the TypeInformation for a struct (minimal only) as the octets carried in `PID_TYPE_INFORMATION` (a MUTABLE struct DHEADER + the `@id(0x1001)` minimal member + its TypeIdentifierWithDependencies).
- **`dds.types:deserialize-type-information-hash`** — parse a serialized TypeInformation and return its minimal `EK_MINIMAL` TypeIdentifier's 14-octet EquivalenceHash (the value endpoint matching needs).

### Built-in TypeLookup service request/reply codecs (`dds.types`)

The XTypes 1.3 §7.6.3.3 built-in TypeLookup service types, `TypeLookup_Request { dds::rpc::RequestHeader header; TypeLookup_Call data; }` and `TypeLookup_Reply { header; TypeLookup_Return return; }`, serialized as XCDR2 little-endian with the `CDR2_LE` encapsulation and no top-level DHEADER: the spec IDL leaves the top-level types unannotated (the §7.3.1.2.1.8 default would be appendable), but the implemented convention — Fast DDS, the designated live oracle, pins them `@final`, and the Wireshark/tshark RTPS dissector expects exactly that — is FINAL; the `TypeLookup_Call`/`Return`/`Result` unions are default-appendable (a DHEADER before each discriminator) and the MUTABLE `*_In`/`*_Out` members use `EMHEADER1 LC=5`, NEXTINT doubling as the value's leading UInt32 per serialization rule (22) (§7.4.3.5.3). No Connext oracle exists for this protocol (ADR 0010); the emitted bytes are frozen as self-pinned regression vectors (test `typelookup-vectors`), the tshark dissector decodes both payloads field-by-field with zero disagreements (`make wire` gates two TL frames), and `CONFIRM-VS-PEER` markers remain pending a live Fast DDS capture. Note: the §7.6.3.3.3 IDL names the reply header `dds::rpc::RequestHeader` — a spec editorial defect; the codec uses the `ReplyHeader` copied from DDS-RPC in §7.6.3.3.2 (`relatedRequestId` + `remoteEx`), the only header that can carry the remote exception code.

- **`dds.types:serialize-type-lookup-request`** — serialize a request: `:writer-guid` (16 octets), `:sn` (request SequenceNumber), `:instance-name` (`string<255>`), `:operation` (`:get-types` | `:get-deps`), `:type-ids` (list of 14-octet EquivalenceHashes, sent as `EK_MINIMAL` TypeIdentifiers), `:continuation` (optional `sequence<octet,32>` continuation point, `:get-deps` only). Returns a fresh octet vector including the 4-octet encapsulation header.
- **`dds.types:parse-type-lookup-request`** — parse a serialized request to `(values operation type-ids writer-guid sn instance-name continuation)`; `:unknown` for an unrecognized union discriminator; `NIL` on any malformed or truncated input (network-facing — every read is bounds-checked, and an unknown mutable member with the must-understand flag set rejects the sample per §7.2.2.4.4.4.6).
- **`dds.types:serialize-type-lookup-reply`** — serialize a reply: `:related-guid`/`:related-sn` (the request's SampleIdentity, echoed as `relatedRequestId`), `:remote-ex` (`:ok` | `:unsupported` | `:invalid-argument` | `:out-of-resources` | `:unknown-operation` | `:unknown-exception`, the §7.6.3.3.2 `RemoteExceptionCode_t` in declaration order 0–5), `:operation` (`:get-types` | `:get-deps`, required for `:ok`), `:pairs` (list of `(hash . typeobject-octets)` `TypeIdentifierTypeObjectPair`s, `:get-types`), `:dependencies` (list of `(hash . size)` `TypeIdentfierWithSize` [sic — the IDL's own spelling] entries, `:get-deps`), `:continuation` (optional, `:get-deps`). For any non-`:ok` `:remote-ex` the `TypeLookup_Return` is omitted entirely (DDS-RPC signals failure via `remoteEx`; the Return union has no default arm; the FINAL reply simply ends after the header). `:writer-guid` is accepted for call-site symmetry but not serialized — the ReplyHeader carries no replier identity.
- **`dds.types:parse-type-lookup-reply`** — parse a serialized reply to `(values operation result related-guid related-sn remote-ex continuation)`: `result` is the pairs list for `:get-types` or the `(hash . size)` list for `:get-deps`; `:unknown` for an unrecognized Return discriminator; `operation` `NIL` with the header values still returned for a non-OK header-only reply; `NIL` on any malformed or truncated input (every read bounds-checked; sequence counts pre-checked against the enclosing DHEADER extent before allocation; per-pair TypeObject extents bounded by `*max-type-object-bytes*`).
- **`dds.types:+tl-gettypes-hash+`** / **`dds.types:+tl-getdeps-hash+`** — the `TypeLookup_Call`/`TypeLookup_Return` union discriminators `TypeLookup_getTypes_HashId` `#x018252d3` and `TypeLookup_getDependencies_HashId` `#x05aafb31` (§7.6.3.3.3, derived via the §7.3.1.2.1.1 `@hashid` rule).

#### TypeLookup hash index + pure server core

The transport-free server half of the service: pure functions over the type registry, called by the builtin TypeLookup endpoints (see [Discovery](discovery.md)) (§7.6.3.3.4: a participant shall answer getTypes / getTypeDependencies for any TypeIdentifier it announced).

- **`dds.types:find-type-support-by-hash`** — the registered `type-support` whose minimal EquivalenceHash equals the given hash (first 14 octets compared), or `NIL`. Backed by a memoized `(hash . name)` index over the registry, rebuilt whenever a `register-type` call bumps the registry generation counter (so re-registering an existing name invalidates it too); types whose TypeObject cannot serialize (e.g. sequence member TypeIdentifiers pending oracle confirmation) are skipped, never signalled.
- **`dds.types:type-lookup-respond`** — answer one inbound serialized `TypeLookup_Request` with serialized `TypeLookup_Reply` octets, or `NIL` to drop (malformed input, or more `type_ids` than `*max-typelookup-request-ids*`). The reply's `relatedRequestId` echoes the request's writer GUID + SN (§7.6.3.3.2). `getTypes` answers `(hash . typeobject-octets)` pairs for the hashes found locally — unknown hashes are silently omitted, so an all-unknown request still answers `REMOTE_EX_OK` with zero pairs; `getTypeDependencies` answers the nested-struct dependency closure of each found type, deduped by hash, as `(hash . typeobject-serialized-size)` entries with an always-empty continuation point (v1 serves the full set in one reply); an unrecognized `TypeLookup_Call` discriminator answers `REMOTE_EX_UNKNOWN_OPERATION` with no `TypeLookup_Return` arm.
- **`dds.types:*max-typelookup-request-ids*`** — special variable, default `32`: the maximum `type_ids` accepted in one inbound request before it is dropped unanswered (resource-exhaustion guard, NFR-SEC-POSTURE).

### Exported constants (`dds.types`)

TypeKind octets: **`+tk-boolean+`**, **`+tk-byte+`**, **`+tk-int16+`**, **`+tk-int32+`**, **`+tk-int64+`**, **`+tk-uint16+`**, **`+tk-uint32+`**, **`+tk-uint64+`**, **`+tk-string8+`**, **`+tk-structure+`**, **`+tk-sequence+`**. EquivalenceKind octets: **`+ek-minimal+`**, **`+ek-complete+`**. TypeIdentifierKind octets: **`+ti-string8-small+`**, **`+ti-string8-large+`**, **`+ti-plain-sequence-small+`**.

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

## Notes / status

This is mid-M4 (P3 XTypes), built **verifiable-first**: anything checkable offline against the spec's own worked examples is landed and tested; anything that needs a conformant peer to lock the exact wire bytes is built but flagged PROVISIONAL.

- **The generator (v1) is deliberately narrow.** Only `:final` extensibility is accepted by `define-dds-type` (appendable/mutable framing for *generated* types is a later increment — note that the assignability relation already handles all three extensibility kinds for hand-built TypeObjects). `@key` is restricted to scalar/string members. Sequence members must have a fixed-size primitive element; sequences of strings/variable-size elements are rejected. A nested-struct member must reference a previously-defined dds type (define-before-use; the DSL is acyclic).

- **The TypeObject serializer + EquivalenceHash are PROVISIONAL pending a Connext oracle** (owner decision 2026-06-06, "build now, confirm vs Connext"). The framing is faithful to the XTypes §7.4.3.5.3 serialization VM and the §7.3.4.9.1 hash rule, and the 1-member `struct pt { long x; }` golden is byte-exact against a hand-derivation — but three byte-level choices are spec-faithful yet unconfirmed against a conformant peer, and are the single points to flip when reference vectors arrive: (1) the hash is over the raw TypeObject XCDR2-LE bytes with **no** 4-byte encapsulation header; (2) `struct_flags` carries the extensibility bit only (minimal-masked); (3) `member_flags` is `TRY_CONSTRUCT=DISCARD` OR'd with `@optional`/`@must_understand`/`@key`. The `shape-type` hash in the test (`bf e2 a6 2e d8 11 ac 46 3c 40 c9 7d 30 ee`) is an explicitly PROVISIONAL **self-consistency** vector, not a Connext-locked one.

- **Sequence-member TypeObject serialization errors cleanly.** Plain-collection element flags / `EK_BOTH` / `@external` framing for sequence elements are the most oracle-sensitive, so `%put-type-identifier` signals an `error` for a sequence member rather than emit unconfirmed bytes (see Example 5). The structural model and assignability still handle sequences fully; only their *TypeObject serialization* is gated.

- **The TypeInformation codec is PROVISIONAL like the TypeObject serializer.** It is minimal-only (the `complete` member is omitted, which MUTABLE permits), the mutable member uses `LC=4` (explicit NEXTINT length), and dependent ordering is insertion order — all to be confirmed against Connext. It round-trips offline and rides the SEDP endpoint ParameterList as `PID_TYPE_INFORMATION`; match-time use is **gated, never hash-equality-enforced**: equal EquivalenceHashes are only a fast path, differing hashes fall through to the TypeLookup-fed assignability gate (see [DCPS](dcps.md)) — hash inequality alone never rejects a peer (ADR 0009).

- **`enforce-type-consistency` implements Step 1 only.** It is the TypeObject-present assignability/equivalence decision (XTypes §7.6.3.4.2). Step 2 — the type-name fallback and `force_type_validation` when no TypeObject is on the wire — is a DCPS match-time concern. The `TYPE_CONSISTENCY_ENFORCEMENT` QoS policy carrier itself lives in `dds.qos` (see [QoS](qos.md)); its spec defaults are exercised in `run-assignability-test`.

- **Assignability coverage is exactly the modeled kinds.** Primitives, narrow strings, plain sequences, and (nested) structs — the kinds the generator can construct and therefore test. Union / enum / bitmask / array / map / alias assignability awaits their type model and is conservatively non-assignable today. SCC / cyclic types (§7.3.4.9.2) are out of scope because the DSL is acyclic.

- **Inbound RTI `PID_TYPE_OBJECT_LB` inflate (`inflate-type-object-lb`, ADR 0009).** RTI Connext advertises a type on the wire via the **vendor** parameter `PID_TYPE_OBJECT_LB` (0x8021) — a ZLIB-compressed **complete** TypeObject — and (for small types) **never** the minimal-hash `PID_TYPE_INFORMATION`. So the minimal-hash match path is unreachable against Connext; the "required path" is to consume that complete TypeObject. `inflate-type-object-lb` is the first piece: it parses the RTI vendor header (`compression_class_id`/`uncompressed_length`/`compressed_length`, reverse-engineered from the live Connext wire, clean-room) and ZLIB-inflates the payload (`chipz`, pure-Lisp), with every length bounds-checked and `uncompressed_length` capped by `*max-type-object-bytes*` (NFR-SEC-POSTURE). Validated byte-exact against a real Connext ShapeType capture (540 octets).
  - **The inflated payload is RTI's *proprietary legacy* TypeObject** (a vendor "TypeLibrary" binary), **not** the OMG `CompleteTypeObject` — and this Connext sends no `PID_TYPE_OBJECT` (0x0072) or `PID_TYPE_INFORMATION` (0x0075) for small types, so no spec-conformant type representation is on the wire. A full structural parse is therefore a large RTI-format reverse-engineering effort (deferred, robustness-only — interop already works via type-name + QoS matching).
  - **In its place, a lightweight type *fingerprint*** (`type-object-strings`, `type-object-mentions-all-p`) extracts the literal names RTI embeds (type name + multi-octet member names + dependent type names) for a heuristic type-aware match / diagnostics — coarse on purpose (1-octet member names and the structure are not recovered).
  - **A structural reverse-engineering path is now underway (ADR 0009, clean-room).** `tokenize-legacy-type-object` walks the inflated legacy TypeObject into an `lto-node` TLV tree (two known TAG words separate nested nodes from opaque header/hash bytes; every read bounds-checked and depth/element/string-bounded — NFR-SEC-POSTURE), and `parse-legacy-type-object` folds that tree into a `minimal-struct-type` **skeleton**: the struct type name, the member names, and the 0-based declaration-order member ids. The node-to-model mapping is derived only from captured bytes + the `C_Shape` / `C_Shape3` (member counting + appended id) / `C_Shape4` (id is positional, not stable across a reorder) differential experiments (`docs/provenance.md`, the `interop/connext/typeobject-corpus` corpus). It MIRRORS `parse-minimal-type-object`'s discipline — a struct on success, `:unsupported` for a tree carrying no recognizable struct shape, `NIL` for input that does not tokenize. **Primitive member types are now decoded** (`%lto-member-type-identifier`): the primitive kind is the u16 at the member node's `VALUE-START+8`, mapped via `*lto-primitive-kind-keyword*` from RTI's own kind enumeration (which differs from the XTypes `TK_*` octets — e.g. RTI long=5 vs `TK_INT32`=4, char=0x0C vs `TK_CHAR8`=0x10) to a `primitive-type-identifier`; established clean-room by the `C_ShapeP_<prim>` corpus differential (each retypes member `x`). **String member types and the `@key` flag are now decoded too**: a string member's node carries kind `0x13` at `VALUE-START+8` plus an 8-octet type-hash at `+16` that references a string-definition node (`+lto-code-string-def+`, CODE 8); `%lto-find-string-bound` follows the hash to that node and reads the bound as a u32 from its `+lto-code-string-bound+` (CODE 200) child, building a `STRING8` `type-identifier` via `string8-type-identifier`. The bound is **always** a u32 on RTI's wire (255 is RTI's default for an unbounded `string`, 32 / 300 for `string<32>`/`string<300>`); the XTypes small (`≤255`) / large (`>255`) split is applied only when our in-memory TI is built. The member's `@key` flag is the u32 at the member node's `VALUE-START+0` (1 for the key member, 0 otherwise), set on `minimal-struct-member-key-p` (`%lto-member-key-p`). Both were established clean-room by the `C_ShapeS32` / `C_ShapeS300` / `C_ShapeNoKey` corpus differentials. So the base `C_Shape` now parses with `color` as a `STRING8` bound 255 (`@key`), and `x`/`y`/`shapesize` as non-key `TK_INT32`. **Struct extensibility is now decoded too** (`%lto-struct-extensibility`): the flag is the u16 at the struct-definition node's first `CODE 0` child's `VALUE-START+0`, mapped via `*lto-extensibility-keyword*` from RTI's own enumeration (`@appendable`=0, `@final`=1, `@mutable`=2 — which coincides with the XTypes `IS_*` struct-flag bits only for `:final`) to `:final`/`:appendable`/`:mutable`; an unknown flag value fails open to `:final` (the strictest extensibility for assignability gating). Established clean-room by the `C_ShapeAppend` / `C_ShapeMutable` corpus differentials (member encoding was byte-identical across all three — `@mutable` did not change the scalar/string member layout). **Sequence-of-primitive member types are now decoded too** (`%lto-sequence-type-identifier`, Stage 3 Task 3.1): a sequence member's node carries kind `0x12` (18) at `VALUE-START+8` plus an 8-octet type-hash at `+16` that references a sequence-definition node (`+lto-code-sequence-def+`, CODE 7 — vs CODE 8 for strings) via the *same* hash-reference mechanism strings use (`%lto-find-def-node`, refactored out of the string path so both share it — DRY). That node's `+lto-code-sequence-element+` (CODE 100) child holds the element type-kind as a u16 in RTI's own primitive enum (octet 2 / long 5), and its `+lto-code-string-bound+` (CODE 200, shared with strings) child holds the sequence bound as a u32; the decoder builds a `sequence-type-identifier` over a `primitive-type-identifier` element with that bound. RTI emits bound **100** for an *unbounded* sequence (the `C_Seq` `sequence<octet>` capture; mirroring the 255 default for unbounded strings — recorded as `+lto-sequence-default-bound+`, documentation only, the decoder reads the wire bound). Established clean-room by the `C_Seq` (`sequence<octet>`) / `C_SeqL` (`sequence<long,10>`) / `C_SeqL100` (`sequence<long,100>`) corpus differentials. A sequence whose **element** is itself a string, a nested aggregate, or another sequence is a Stage-3.2 gap: the element kind is non-primitive, so the member `type-identifier` stays `NIL` and parsing continues (fail-open). **Nested-struct (aggregate) member types are now decoded too** (`%lto-nested-type-identifier`, Stage 3 Task 3.2): a legacy TypeObject is a **TypeLibrary** — publishing `C_Nested` makes RTI emit the nested `C_Inner`'s definition as a *sibling* top-level struct-definition node (`+lto-code-struct+`, CODE 9) in the same TypeObject (the outer struct comes first in pre-order). A nested-struct member's node carries kind `0x16` (22) at `VALUE-START+8` plus the *same* 8-octet type-hash at `+16` (strings use `0x13`/CODE 8, sequences `0x12`/CODE 7, nested struct `0x16`/CODE 9) referencing that sibling def; the shared `%lto-find-def-node` resolves it with `def-code = +lto-code-struct+` unchanged. The resolver parses the referenced def into a `minimal-struct-type` and wraps it in an `EK_MINIMAL` `hash-type-identifier` whose `referenced` slot is the parsed nested model — exactly the shape `struct-assignable-from` and the TypeLookup gate recurse into. The struct-node→model fold is the shared `%lto-parse-struct-node` helper, called by **both** the top-level parse entry and the nested resolver, so nesting recurses naturally (DRY). Recursion is bounded by `*lto-max-type-depth*` (16) **and** a visited-hash set keyed by the member's hash@+16: a self- or mutually-referential reference fails open (member `type-identifier` `NIL`) at depth 1, so a hostile cyclic TypeObject **terminates, never hangs** (NFR-SEC-POSTURE). Established clean-room by the `C_Nested` / `C_Nested2` corpus differentials. This extends the flat-struct parse to **names / ids / primitives / strings / keys / extensibility / sequence-of-primitive / nested-struct decoded (nested structs recurse through assignability); sequence-of-{string,struct,sequence} and Stage-4 aggregates (union/enum/array/typedef) remain undecoded** (Stage 4). The parsed `minimal-struct-type` is the SAME struct type the generator builds, so it feeds `struct-assignable-from` (see [assignability](#assignability)) unchanged: `lto-assignability` proves a locally-built model for the captured `C_Shape` is assignable both directions from the parsed wire model (compatible → `T`), while an incompatible local (a retyped or dropped member) is rejected (→ `NIL`); `lto-parse-nested` proves the same recursion through a **nested** member — a nested-compatible local `C_Nested` is assignable (→ `T`) and a nested-incompatible local (the inner `C_Inner.a`/`.b` retyped) is rejected (→ `NIL`). Tested against the locked live Connext `C_Shape` (`lto-parse-shape`), ten `C_ShapeP_<prim>` captures (`lto-parse-primitives`), four string/`@key` captures (`lto-parse-strings-keys`), the `@final`/`@appendable`/`@mutable` extensibility captures (`lto-parse-extensibility`), three sequence captures (`lto-parse-sequence`), the `C_Nested`/`C_Nested2` nested captures (`lto-parse-nested`), and the assignability proof (`lto-assignability`).
  - **Match-time advisory verdict (`assess-type-object-lb`, `type-support-fingerprint-names`).** The fingerprint is applied against the *local* type: `type-support-fingerprint-names` lists the local struct's ≥2-octet member names (the struct type name is excluded — peers like Connext spell it `ShapeType` where a local registration says `shape-type`), and `assess-type-object-lb` checks whether the peer's inflated TypeObject mentions all of them, returning one of `:names-present` / `:names-absent` (with the missing names) / `:no-type-object` / `:inflate-failed` / `:not-assessable`. It is **purely advisory** — a heuristic confirmation/diagnostic, **never** a match gate (the peer already matched on topic + type name, and a missing name is inconclusive against RTI's legacy TypeObject). The DCPS layer records the verdict per matched DataReader/DataWriter for inspection and can log it; see [DCPS](dcps.md). Tested against the real Connext ShapeType LB (`xtypes-type-compat-soft`, `dcps-type-compat`).
- **The built-in TypeLookup service is complete offline (FR-TYPE-3, ADR 0010).** The `TypeLookup_Request` **and** `TypeLookup_Reply` XCDR2 codecs are in (see the API section above). Connext does not implement this protocol, so the byte-level choices (FINAL top level with `CDR2_LE` per the Fast DDS `@final` convention, flat DDS-RPC headers, default-appendable `Call`/`Return`/`Result` unions with DHEADERs, `LC=5` mutable members, the §7.6.3.3.2 `ReplyHeader` over the §7.6.3.3.3 IDL's `RequestHeader` misprint, the omitted `TypeLookup_Return` on a non-OK `remoteEx`) are frozen as self-pinned regression vectors (test `typelookup-vectors`), cross-checked field-by-field by the tshark RTPS dissector (zero disagreements; `make wire` gates two TL frames), and marked `CONFIRM-VS-PEER` until a live Fast DDS capture is available. The transport-free server core is also in (`find-type-support-by-hash` + `type-lookup-respond`, see the API section above). The four built-in endpoints, the discovery `type-gate` hook, and the match-time gate that feeds a `parse-minimal-type-object` result into `struct-assignable-from` are all in — see [Discovery](discovery.md) and [DCPS](dcps.md).
- **Deferred entirely (not yet present):** DynamicData (runtime-typed sample access without a generated struct). Today every type is generated ahead of time via `define-dds-type`.
