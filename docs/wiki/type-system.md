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
- **`dds.types:ti-equivalent-p`** — structural MINIMAL-equivalence of two TypeIdentifiers (a verifiable stand-in for the deferred EquivalenceHash equality).
- **`dds.types:struct-equivalent-p`** — structural MINIMAL-equivalence of two struct TypeObjects (same extensibility, member count, and pairwise id/`@key`/`@optional`/member-type; member **names are not compared** — MINIMAL erases them).
- **`dds.types:enforce-type-consistency`** — the `TypeConsistencyEnforcement` Step-1 decision: under `:allow-type-coercion` the reader-type must be is-assignable-from the writer-type (taking the four options into account); under `:disallow-type-coercion` the two types must be MINIMAL-equivalent. Returns `T` iff consistent.

### XCDR2 TypeObject serializer + EquivalenceHash (`dds.types`)

- **`dds.types:minimal-type-object-octets`** — the canonical XCDR2 little-endian serialization of the `EK_MINIMAL` TypeObject for a struct, **with no encapsulation header** — the buffer the EquivalenceHash is computed over.
- **`dds.types:equivalence-hash`** — `EquivalenceHash(S)` = first 14 octets of `MD5` of the serialized MinimalTypeObject (XTypes §7.3.4.9.1); nested struct members recurse to the referenced struct's hash.

### TypeInformation codec (`dds.types`)

- **`dds.types:serialize-type-information`** — serialize the TypeInformation for a struct (minimal only) as the octets carried in `PID_TYPE_INFORMATION` (a MUTABLE struct DHEADER + the `@id(0x1001)` minimal member + its TypeIdentifierWithDependencies).
- **`dds.types:deserialize-type-information-hash`** — parse a serialized TypeInformation and return its minimal `EK_MINIMAL` TypeIdentifier's 14-octet EquivalenceHash (the value endpoint matching needs).

### Exported constants (`dds.types`)

TypeKind octets: **`+tk-boolean+`**, **`+tk-byte+`**, **`+tk-int16+`**, **`+tk-int32+`**, **`+tk-int64+`**, **`+tk-uint16+`**, **`+tk-uint32+`**, **`+tk-uint64+`**, **`+tk-string8+`**, **`+tk-structure+`**, **`+tk-sequence+`**. EquivalenceKind octets: **`+ek-minimal+`**, **`+ek-complete+`**. TypeIdentifierKind octets: **`+ti-string8-small+`**, **`+ti-plain-sequence-small+`**.

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

`minimal-type-object-octets` produces the canonical XCDR2-LE bytes (no encapsulation header) and `equivalence-hash` is `MD5(...)[0:14]`. The 1-member `struct pt { long x; }` has a hand-derived spec golden; nested-struct members recurse; **sequence members error cleanly** pending the Connext oracle (adapted from `run-typeobject-cdr-test`).

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

## Notes / status

This is mid-M4 (P3 XTypes), built **verifiable-first**: anything checkable offline against the spec's own worked examples is landed and tested; anything that needs a conformant peer to lock the exact wire bytes is built but flagged PROVISIONAL.

- **The generator (v1) is deliberately narrow.** Only `:final` extensibility is accepted by `define-dds-type` (appendable/mutable framing for *generated* types is a later increment — note that the assignability relation already handles all three extensibility kinds for hand-built TypeObjects). `@key` is restricted to scalar/string members. Sequence members must have a fixed-size primitive element; sequences of strings/variable-size elements are rejected. A nested-struct member must reference a previously-defined dds type (define-before-use; the DSL is acyclic).

- **The TypeObject serializer + EquivalenceHash are PROVISIONAL pending a Connext oracle** (owner decision 2026-06-06, "build now, confirm vs Connext"). The framing is faithful to the XTypes §7.4.3.5.3 serialization VM and the §7.3.4.9.1 hash rule, and the 1-member `struct pt { long x; }` golden is byte-exact against a hand-derivation — but three byte-level choices are spec-faithful yet unconfirmed against a conformant peer, and are the single points to flip when reference vectors arrive: (1) the hash is over the raw TypeObject XCDR2-LE bytes with **no** 4-byte encapsulation header; (2) `struct_flags` carries the extensibility bit only (minimal-masked); (3) `member_flags` is `TRY_CONSTRUCT=DISCARD` OR'd with `@optional`/`@must_understand`/`@key`. The `shape-type` hash in the test (`bf e2 a6 2e d8 11 ac 46 3c 40 c9 7d 30 ee`) is an explicitly PROVISIONAL **self-consistency** vector, not a Connext-locked one.

- **Sequence-member TypeObject serialization errors cleanly.** Plain-collection element flags / `EK_BOTH` / `@external` framing for sequence elements are the most oracle-sensitive, so `%put-type-identifier` signals an `error` for a sequence member rather than emit unconfirmed bytes (see Example 5). The structural model and assignability still handle sequences fully; only their *TypeObject serialization* is gated.

- **The TypeInformation codec is PROVISIONAL like the TypeObject serializer.** It is minimal-only (the `complete` member is omitted, which MUTABLE permits), the mutable member uses `LC=4` (explicit NEXTINT length), and dependent ordering is insertion order — all to be confirmed against Connext. It round-trips offline and already rides the SEDP endpoint ParameterList as `PID_TYPE_INFORMATION` (emit only); **match enforcement is deferred** until the EquivalenceHash is Connext-confirmed.

- **`enforce-type-consistency` implements Step 1 only.** It is the TypeObject-present assignability/equivalence decision (XTypes §7.6.3.4.2). Step 2 — the type-name fallback and `force_type_validation` when no TypeObject is on the wire — is a DCPS match-time concern. The `TYPE_CONSISTENCY_ENFORCEMENT` QoS policy carrier itself lives in `dds.qos` (see [QoS](qos.md)); its spec defaults are exercised in `run-assignability-test`.

- **Assignability coverage is exactly the modeled kinds.** Primitives, narrow strings, plain sequences, and (nested) structs — the kinds the generator can construct and therefore test. Union / enum / bitmask / array / map / alias assignability awaits their type model and is conservatively non-assignable today. SCC / cyclic types (§7.3.4.9.2) are out of scope because the DSL is acyclic.

- **Inbound RTI `PID_TYPE_OBJECT_LB` inflate (`inflate-type-object-lb`, ADR 0009).** RTI Connext advertises a type on the wire via the **vendor** parameter `PID_TYPE_OBJECT_LB` (0x8021) — a ZLIB-compressed **complete** TypeObject — and (for small types) **never** the minimal-hash `PID_TYPE_INFORMATION`. So the minimal-hash match path is unreachable against Connext; the "required path" is to consume that complete TypeObject. `inflate-type-object-lb` is the first piece: it parses the RTI vendor header (`compression_class_id`/`uncompressed_length`/`compressed_length`, reverse-engineered from the live Connext wire, clean-room) and ZLIB-inflates the payload (`chipz`, pure-Lisp), with every length bounds-checked and `uncompressed_length` capped by `*max-type-object-bytes*` (NFR-SEC-POSTURE). Parsing the inflated complete TypeObject into the structural model, and wiring it into SEDP match-time assignability, are the next increments.
- **Deferred entirely (not yet present):** TypeLookup (the request/reply service to fetch a full TypeObject by TypeIdentifier) and DynamicData (runtime-typed sample access without a generated struct). Today every type is generated ahead of time via `define-dds-type`.
