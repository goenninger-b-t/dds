# CDR codec, buffers & the arena

This page covers the two foundational layers of the stack: the **L2 CDR codec**
(`dds-cdr`) and the **L1 core runtime** (`dds-core` — off-heap buffers/cursors, the
static arena + pools, and the vendored MD5). The CDR codec is the *foundational
serialization* every higher layer (RTPS, discovery, DCPS) is built on; the arena
and buffers are the *hot-path memory model* that lets the steady state allocate
**0 bytes/sample**. Two disciplines govern everything here: **"the wire is the
oracle"** — wire constants and encodings are pinned by byte-exact reference vectors,
never typed from memory — and **0 bytes/sample** — hot-path memory comes from a
startup-allocated, non-GC'd arena, never the GC heap.

> **Hot path.** `dds.cdr` and `dds.core.buffer` are hot-path packages: `defstruct`
> plus monomorphic functions only, **no CLOS** (no `defclass`/`defgeneric`/`defmethod`),
> and no per-sample allocation. This is enforced by the `gate-hotpath` CI gate. The
> codec is deliberately not generic-function based — the type compiler emits concrete
> per-type `serialize-T` / `deserialize-T` functions that call these primitives
> directly. `dds.core.arena` and `dds.core.md5` are control-plane (provisioning and
> type registration), not measured hot paths.

Every parser here is bounds-checked at the buffer boundary (NFR-SEC-POSTURE), so
malformed wire data signals `buffer-overflow` rather than reading out of bounds.

See also: [Type system & code generation](type-system.md) (the generated codecs that
call these primitives) and the [RTPS engine](rtps-engine.md) (the first consumer of
the serialized payload).

---

## API reference

All symbols below are exported. Examples use the package nicknames `dds.cdr`,
`dds.core.buffer`, `dds.core.arena`, and `dds.core.md5`.

### Encapsulation (`dds.cdr`)

The 4-octet RTPS `SerializedPayloadHeader` and the representation-identifier table.

| Symbol | Description |
|---|---|
| `dds.cdr:+representation-ids+` | Alist of `(name . 16-bit value)` encapsulation representation identifiers, sourced from the normative DDS-XTypes 1.3 §7.6 Table 60 (e.g. `:plain-cdr-le` = `#x0001`, `:plain-cdr2-le` = `#x0007`, `:pl-cdr2-be` = `#x000a`), dissector-confirmed. |
| `dds.cdr:representation-id` | Accessor naming convention for a representation entry (`representation-id-value` / `representation-id-name`). |
| `dds.cdr:representation-id-value` | 16-bit wire value for a representation keyword (XTypes 1.3 §7.6 Table 60); errors on an unknown name. |
| `dds.cdr:representation-id-name` | Inverse: the keyword for a 16-bit value, or `NIL` if unrecognised. |
| `dds.cdr:make-encapsulation-header` | Write the 4-octet header (2-octet identifier in network order + 2-octet options, initially 0) and reset the cursor's CDR alignment origin to the byte after it (RTPS 2.5 §10.2). The options pad bits are backpatched later by `finalize-encapsulation-options`. Returns the cursor. |
| `dds.cdr:finalize-encapsulation-options` | After the body is serialized, backpatch the encapsulation options field: set the low 2 bits of the second options byte to the trailing-padding count (0..3) the payload needs to reach the next 4-byte boundary, so the receiver can find the exact payload end (DDS-XTypes 1.3 §7.6.3.1.2). The clause is universal — its normative example sets the bits on PLAIN_CDR (XCDR1) — so this applies to every CDR representation; only the non-CDR XML representation is skipped. Allocation-free one-octet in-place patch. |
| `dds.cdr:parse-encapsulation-header` | Read and validate the 4-octet header, reset the alignment origin past it, and return `(values representation-keyword options pad)` where `pad` is the trailing-padding count from the options low 2 bits (DDS-XTypes 1.3 §7.6.3.1.2 — the receiver interprets it to find the exact payload end); a non-zero options value from a conformant peer is tolerated, never rejected. Bounds-checked. |
| `dds.cdr:extensibility-kind` | Type `(member :final :appendable :mutable)` — the XTypes extensibility kinds. |
| `dds.cdr:cdr-not-implemented` | Condition signalled for an unknown or unsupported encapsulation **representation** (`cdr.lisp` — by name and by id). It no longer has anything to do with strings; the string signaller went with the Latin-1 codec. |

### Primitives (`dds.cdr`)

Mode-aware primitive encode/decode. Every op takes the trailing `mode` argument
(`:xcdr1` or `:xcdr2`); alignment is applied per mode (see the alignment cap below).

| Symbol | Description |
|---|---|
| `dds.cdr:cdr-mode` | Type `(member :xcdr1 :xcdr2)`. `:xcdr1` is classic CDR (align up to 8); `:xcdr2` caps alignment at 4 (FR-CDR-2). |
| `dds.cdr:cdr-align` | Align a cursor to N bytes, capped by the mode's maximum alignment. |
| `dds.cdr:cdr-size-align` | Round a *position* up to the mode-capped N-byte boundary; the size-path analogue of `cdr-align`, used by generated `serialized-size` functions (FR-CDR-5). |
| `dds.cdr:cdr-put-u8` / `cdr-get-u8` | Write/read a u8 (no alignment; `mode` ignored). |
| `dds.cdr:cdr-put-u16` / `cdr-get-u16` | Write/read a u16 with mode-aware 2-byte alignment. |
| `dds.cdr:cdr-put-u32` / `cdr-get-u32` | Write/read a u32 with mode-aware 4-byte alignment. |
| `dds.cdr:cdr-put-u64` / `cdr-get-u64` | Write/read a u64 with mode-capped alignment (8 for XCDR1, 4 for XCDR2). |
| `dds.cdr:cdr-put-i8` / `cdr-get-i8` | Two's-complement i8. |
| `dds.cdr:cdr-put-i16` / `cdr-get-i16` | Two's-complement i16. |
| `dds.cdr:cdr-put-i32` / `cdr-get-i32` | Two's-complement i32. |
| `dds.cdr:cdr-put-i64` / `cdr-get-i64` | Two's-complement i64. |
| `dds.cdr:cdr-put-bool` / `cdr-get-bool` | Boolean as one octet (write `1`/`0`; read non-zero as true). |
| `dds.cdr:cdr-put-enum` / `cdr-get-enum` | Enum as a 32-bit value (bit_bound refinement is a later increment). |

### Sequences & strings (`dds.cdr`)

| Symbol | Description |
|---|---|
| `dds.cdr:cdr-put-string` / `cdr-get-string` | String as 4-byte length (**including** the NUL) + **UTF-8** octets + NUL (FR-CDR-1; RFC 3629 §3). The prefix counts OCTETS, not characters. `cdr-get-string` returns **`(values string status)`** — `:malformed-utf8` for ill-formed input, with `""` as the primary value so a generated deserializer assigning into a `string`-declared slot cannot be handed NIL. It pre-validates the wire length against the remaining buffer extent **before** allocating (signalling `dds.core.buffer:buffer-overflow` on a hostile length) and bounds every octet it decodes by that same extent (NFR-SEC-POSTURE); the pooled zero-alloc deserialize path is a tracked follow-up. |
| `dds.cdr:utf8-octet-length` | Octets a string occupies as UTF-8, excluding the NUL. **This — never `cl:length` — is what an IDL `string<N>` bound and any buffer sizing must use.** |
| `dds.cdr:cdr-put-sequence` / `cdr-get-sequence` | Sequence as 4-byte element count + elements; each element is written/read via a supplied `elem-writer`/`elem-reader` closure called as `(funcall fn cursor element mode)` / `(funcall fn cursor mode)`. `cdr-get-sequence` pre-validates the wire count against the remaining buffer extent (every CDR element is at least 1 octet) **before** allocating the result vector, signalling `buffer-overflow` on a hostile count (NFR-SEC-POSTURE). It allocates an **unspecialized** `simple-vector` (element-type `T`) — see the typed variant below, and prefer it on any data path. |
| `dds.cdr:cdr-get-sequence-typed` *(c elem-reader mode element-type)* | As `cdr-get-sequence`, but allocates a vector **specialized to ELEMENT-TYPE**. This is what the generated codecs call: the DSL type map knows each element's Lisp type at macroexpansion, so the specialization is a compile-time constant at every call site. **Why it matters:** an untyped `(make-array n)` is one machine word (**8 B**) per element regardless of element type, so a 256-octet `sequence<octet>` cost ~2 KB of heap to carry 256 B of data (8× the payload), a 63 KB one cost ~504 KB. Specialized, they cost 272 B and 63 KB. This was the largest allocation on the DCPS receive path, and it is also an **8× memory-amplification** an attacker could drive: `check-room` bounds the element *count* against the buffer extent, but each counted element was costing 8 B (NFR-SEC-POSTURE). Amplification is now 1×. |

### XCDR2 framing (`dds.cdr`)

DHEADER and the mutable-member EMHEADER1, the byte-exact framing primitives for
DELIMITED / MUTABLE serialization (XTypes 1.3 §7.4.3.4).

| Symbol | Description |
|---|---|
| `dds.cdr:cdr-put-dheader` / `cdr-get-dheader` | DHEADER = UInt32 serialized size of the object that follows, 4-byte aligned (XTypes 1.3 §7.4.3.4.1). |
| `dds.cdr:emheader1-encode` | EMHEADER1 = `(M_FLAG<<31) | (LC<<28) | (MemberId & 0x0fffffff)` (§7.4.3.4.2). Args: `must-understand`, `lc`, `member-id`. |
| `dds.cdr:emheader1-decode` | Inverse of `emheader1-encode`: returns `(values must-understand lc member-id)`. |
| `dds.cdr:lc-for-length` | Length code (0/1/2/3) for a member of N bytes when N ∈ {1,2,4,8}; else `NIL` (the case that needs NEXTINT, LC 4–7) (§7.4.3.4.2). |

### Arena & pools (`dds.core.arena`)

The startup-allocated, non-GC'd byte budget and the fixed-capacity buffer pools
carved from it (NFR-MEM).

| Symbol | Description |
|---|---|
| `dds.core.arena:*static-arena-bytes*` | Master off-heap byte budget for all hot-path memory. Read **once** at `init-arena` (defaults to 64 MiB); rebinding afterwards has no effect until teardown. |
| `dds.core.arena:arena` | The arena struct: a static off-heap region with a fixed byte budget; pools are carved from it. |
| `dds.core.arena:init-arena` | One-shot constructor `(&key (bytes *static-arena-bytes*))`. Reads the budget once and returns a fresh arena. |
| `dds.core.arena:teardown-arena` | Free every pool's static buffers and mark the arena uninitialized. |
| `dds.core.arena:arena-initialized-p` | True while the arena is live (between `init-arena` and `teardown-arena`). |
| `dds.core.arena:arena-report` | Plist of byte budget, bytes used, and per-pool reserved sizes / high-water, for startup logging (NFR-OBS). |
| `dds.core.arena:make-buffer-pool` | `(arena element-bytes capacity)` — carve a fixed-capacity pool of `capacity` octet-buffers of `element-bytes` each, pre-allocated once. Signals `arena-exhausted` if the request exceeds the remaining budget. |
| `dds.core.arena:pool-acquire` | Pop a buffer from the pool. **Returns `NIL` on exhaustion** — the caller applies RESOURCE_LIMITS, never a GC-heap fallback. |
| `dds.core.arena:pool-release` | Return a buffer to the pool. |
| `dds.core.arena:pool-capacity` | Fixed number of buffers the pool was provisioned with. |
| `dds.core.arena:pool-in-use` | Number of buffers currently checked out. |
| `dds.core.arena:pool-high-water` | Peak in-use count seen for the pool (budget tracking). |
| `dds.core.arena:arena-exhausted` | Condition raised at provisioning time when a pool would exceed the budget. |

### Buffers & cursors (`dds.core.buffer`)

Off-heap octet buffers with stable foreign addresses, and the read/write cursor that
carries endianness and the alignment origin. **Hot path.**

| Symbol | Description |
|---|---|
| `dds.core.buffer:octet-buffer` | Off-heap octet buffer (PAL-backed, stable foreign address) of fixed capacity — the unit of hot-path serialization memory. |
| `dds.core.buffer:make-octet-buffer` | Allocate an N-octet off-heap buffer with a stable address. |
| `dds.core.buffer:octet-buffer-over` | Wrap an **existing** octet vector as an `octet-buffer` (no static allocation, no copy) — for building/parsing a small message in a caller-owned (e.g. GC-heap) buffer when no stable foreign address is needed. Not for syscall/SHMEM buffers (use `make-octet-buffer`). |
| `dds.core.buffer:octet-buffer-vec` | The backing `(simple-array (unsigned-byte 8))`. |
| `dds.core.buffer:octet-buffer-capacity` | Fixed capacity in octets. |
| `dds.core.buffer:buffer-sap` | Raw foreign pointer to the buffer, for syscalls / SHMEM. |
| `dds.core.buffer:cursor` | Constructor `(buffer &key (endianness :little))` — a cursor at position 0, alignment origin 0. |
| `dds.core.buffer:cursor-buffer` | The cursor's underlying octet-buffer. |
| `dds.core.buffer:cursor-position` | Current byte position. |
| `dds.core.buffer:cursor-endianness` | Current endianness (`:little`/`:big`). |
| `dds.core.buffer:cursor-origin` | Current alignment origin (alignment is computed relative to this). |
| `dds.core.buffer:cursor-set-origin` | Set the alignment origin to the current position — used after writing the 4-byte encapsulation header so CDR alignment resets per RTPS 2.5 §10.2. |
| `dds.core.buffer:cursor-set-endianness` | Set the endianness — used by the receive loop after reading a Submessage header's E flag (RTPS 2.5 §9.4.5.1.2). |
| `dds.core.buffer:cursor-set-position` | Set the position (bounds-checked against capacity). |
| `dds.core.buffer:cursor-reset` | Reset position to 0 and origin to 0. |
| `dds.core.buffer:align` | Advance to the next N-byte boundary relative to the origin (N ∈ {1,2,4,8}), zero-filling padding. |
| `dds.core.buffer:put-u8` … `put-u64` / `get-u8` … `get-u64` | Raw 1/2/4/8-octet writes/reads in cursor endianness, bounds-checked. (The mode-aware alignment lives one layer up in `dds.cdr`.) |
| `dds.core.buffer:put-octets` / `get-octets` | Bulk copy LEN octets between the buffer and an external array at a given offset, bounds-checked. |
| `dds.core.buffer:buffer-overflow` | Condition signalled when an op would read/write past the buffer extent. |

### MD5 (`dds.core.md5`)

| Symbol | Description |
|---|---|
| `dds.core.md5:md5` | MD5 digest (RFC 1321) of an octet array — returns a fresh 16-octet vector. Vendored clean-room. Used as a content/identity hash only (XTypes EquivalenceHash/NameHash, the >16-byte DDS keyhash); **not** a DDS-Security primitive. |

---

## Examples

Every block below is adapted from a passing test in `src/dds-tests/echo-test.lisp`.
Load the codec with `(ql:quickload :dds-cdr)` (it pulls in `dds-core`), or run the
whole suite with `(asdf:test-system :dds-tests)`.

### 1. Encapsulation header + a byte-exact primitive write

Write the 4-octet `SerializedPayloadHeader`, confirm its exact bytes, and check that
the alignment origin was reset to position 4 (RTPS 2.5 §10.2). Then write `i32 = 1`
little-endian and confirm the wire bytes. (From `run-byte-exact-test`.)

```lisp
(let* ((arena (dds.core.arena:init-arena :bytes (* 64 1024)))
       (pool  (dds.core.arena:make-buffer-pool arena 64 6))
       (c     (dds.core.buffer:cursor (dds.core.arena:pool-acquire pool)
                                      :endianness :little)))
  ;; PLAIN_CDR2_LE -> identifier 0x0007, options 0 (XTypes 1.3 §7.6 Table 60)
  (dds.cdr:make-encapsulation-header c :plain-cdr2-le)
  (assert (equal '(#x00 #x07 #x00 #x00)
                 (loop with v = (dds.core.buffer:octet-buffer-vec
                                 (dds.core.buffer:cursor-buffer c))
                       for i below 4 collect (aref v i))))
  (assert (= 4 (dds.core.buffer:cursor-origin c)))      ; origin reset past the header

  ;; one i32 = 1, little-endian -> 01 00 00 00
  (let ((c2 (dds.core.buffer:cursor (dds.core.arena:pool-acquire pool)
                                    :endianness :little)))
    (dds.cdr:cdr-put-i32 c2 1 :xcdr2)
    (assert (equal '(#x01 #x00 #x00 #x00)
                   (loop with v = (dds.core.buffer:octet-buffer-vec
                                   (dds.core.buffer:cursor-buffer c2))
                         for i below 4 collect (aref v i)))))
  (dds.core.arena:teardown-arena arena))
```

### 2. Struct-shaped round-trip in both XCDR modes (the alignment divergence)

A struct with an `i32` followed by an `i64` is the canonical XCDR1-vs-XCDR2 case: the
`i64` lands at a 4-aligned-but-not-8-aligned offset, so **XCDR1 pads to 8 and XCDR2
does not** — the two encodings *must* differ in length. The codec here is hand-written
in exactly the shape the type compiler emits. (From `run-codec-roundtrip-test`; the
test asserts only `len1 ≠ len2`, not fixed lengths.)

```lisp
(defstruct (tsample (:constructor make-tsample))
  (id 0 :type (signed-byte 32))
  (ts 0 :type (signed-byte 64))
  (label "" :type string))

(defun serialize-tsample (p c mode)
  (dds.cdr:cdr-put-i32    c (tsample-id p)    mode)
  (dds.cdr:cdr-put-i64    c (tsample-ts p)    mode)
  (dds.cdr:cdr-put-string c (tsample-label p) mode))

(defun deserialize-tsample (c mode)
  (make-tsample :id    (dds.cdr:cdr-get-i32    c mode)
                :ts    (dds.cdr:cdr-get-i64    c mode)
                :label (dds.cdr:cdr-get-string c mode)))

(let* ((arena (dds.core.arena:init-arena :bytes (* 256 1024)))
       (pool  (dds.core.arena:make-buffer-pool arena 512 4))
       (p     (make-tsample :id -7 :ts -1234567890123 :label "shape")))
  (flet ((round-trip (mode)
           (let* ((b  (dds.core.arena:pool-acquire pool))
                  (wc (dds.core.buffer:cursor b :endianness :little)))
             (serialize-tsample p wc mode)
             (let ((len (dds.core.buffer:cursor-position wc))
                   (rc  (dds.core.buffer:cursor b :endianness :little)))
               (multiple-value-prog1 (values (deserialize-tsample rc mode) len)
                 (dds.core.arena:pool-release pool b))))))
    (multiple-value-bind (q1 len1) (round-trip :xcdr1)
      (multiple-value-bind (q2 len2) (round-trip :xcdr2)
        (assert (= (tsample-ts p) (tsample-ts q1)))   ; XCDR1 identity
        (assert (= (tsample-ts p) (tsample-ts q2)))   ; XCDR2 identity
        (assert (/= len1 len2)))))                     ; the 8-byte member forces divergence
  (dds.core.arena:teardown-arena arena))
```

### 3. Origin-relative XCDR1 8-byte alignment

XCDR1 8-byte alignment is computed relative to the **post-header origin**, not buffer
position 0. After a big-endian `PLAIN_CDR_BE` header (origin → 4), a `u8` (→ 5), then
an `i64`: alignment-to-8 relative to origin lands at position 12, and the 8 i64 bytes
end at position 20. (From `run-byte-exact-test`.)

```lisp
(let* ((arena (dds.core.arena:init-arena :bytes (* 64 1024)))
       (pool  (dds.core.arena:make-buffer-pool arena 64 1))
       (c     (dds.core.buffer:cursor (dds.core.arena:pool-acquire pool)
                                      :endianness :big)))
  (dds.cdr:make-encapsulation-header c :plain-cdr-be)   ; origin -> 4, pos 4
  (dds.cdr:cdr-put-u8  c 9 :xcdr1)                       ; pos 5
  (dds.cdr:cdr-put-i64 c 1 :xcdr1)                       ; align-8 rel origin -> 12, +8 -> 20
  (assert (= 20 (dds.core.buffer:cursor-position c)))
  (dds.core.arena:teardown-arena arena))
```

### 4. Arena + pool acquire / release (0 bytes/sample)

Provision a pool once, acquire a buffer, use it, release it, and confirm zero leaks
via the in-use and high-water counters. Steady-state `pool-acquire` / `pool-release`
is index manipulation with no allocation; `pool-acquire` returning `NIL` is the
exhaustion signal. (Adapted from `run-echo-test`.)

```lisp
(let* ((arena   (dds.core.arena:init-arena :bytes (* 256 1024)))
       (pool    (dds.core.arena:make-buffer-pool arena 256 8))
       (payload (make-array 8 :element-type '(unsigned-byte 8)
                              :initial-contents '(68 68 83 45 69 67 72 79)))  ; "DDS-ECHO"
       (sbuf    (dds.core.arena:pool-acquire pool)))
  (assert sbuf)                                          ; NIL would mean exhaustion
  (let ((wc (dds.core.buffer:cursor sbuf :endianness :little)))
    (dds.core.buffer:put-octets wc payload 0 (length payload)))
  (dds.core.arena:pool-release pool sbuf)
  (assert (zerop (dds.core.arena:pool-in-use pool)))     ; no leak
  (assert (= 1 (dds.core.arena:pool-high-water pool)))   ; peaked at 1 buffer
  (dds.core.arena:teardown-arena arena))
```

### 5. MD5 content hash

The vendored MD5 is verified byte-exact against the RFC 1321 test suite and the XTypes
NameHash example: `MD5("color")[0:4]` = `70 dd a5 df`. (From `run-md5-test`.)

```lisp
(flet ((ascii (s) (map '(simple-array (unsigned-byte 8) (*)) #'char-code s)))
  ;; RFC 1321 vector: MD5("abc") = 900150983cd24fb0d6963f7d28e17f72
  (assert (equalp (dds.core.md5:md5 (ascii "abc"))
                  #(#x90 #x01 #x50 #x98 #x3c #xd2 #x4f #xb0
                    #xd6 #x96 #x3f #x7d #x28 #xe1 #x7f #x72)))
  ;; XTypes NameHash example: first 4 octets of MD5("color")
  (assert (equalp (subseq (dds.core.md5:md5 (ascii "color")) 0 4)
                  #(#x70 #xdd #xa5 #xdf))))
```

---

## Notes / status

- **Byte-exact corpus is seeded, not complete.** The byte-exact vectors that ship today
  are *spec-sourced* (encapsulation IDs from XTypes 1.3 §7.6 Table 60, EMHEADER1 from
  §7.4.3.4.2, alignment/origin from RTPS 2.5 §10.2) and dissector-confirmed. The **full
  RTI Connext byte-exact payload corpus** (FR-CDR-8) is the interop follow-up — see
  [Interop with RTI Connext](interop.md).
- **XCDR2 4-byte alignment cap (FR-CDR-2).** In `:xcdr2`, all alignment is capped at 4,
  so 8-byte members are only 4-aligned — this is why a struct with an `i64` after an
  `i32` serializes to a different length than under `:xcdr1`. Don't assume 8-byte
  alignment in XCDR2.
- **Strings are UTF-8** (RFC 3629 §3), which is what IDL and XTypes mean by `string`. The length
  prefix counts **octets**, not characters — the two coincide only for ASCII, and a caller sizing a
  buffer for a string member must use `dds.cdr:utf8-octet-length`, never `cl:length`. The decoder
  **refuses** ill-formed input with `:malformed-utf8` rather than repairing it: over-long forms
  (`C0 AF` decodes to `/` in two octets, the classic filter bypass), surrogates, code points above
  U+10FFFF, truncated sequences, and bad continuation octets. Substituting U+FFFD would hand the
  caller a string indistinguishable from one the peer actually sent.
  ASCII encodes byte-identically to the previous Latin-1 codec, so existing corpus vectors are
  unaffected; what changed is that U+0080..U+00FF now takes two octets, which is the fix — the single
  octet the old codec emitted was decoded as a malformed sequence by every conformant peer.
- **An OCTET sequence is copied in BULK, never element-by-element** (`cdr-put-octet-sequence` /
  `cdr-get-octet-sequence`, which the generated codecs emit for `:u8`/`:byte`/`:octet`). The generic
  per-element path funcalls a closure **once per octet** — measured **~12 ns/octet, perfectly linear**:
  204 802 ns to serialize a 16 KB payload, versus **2 616 ns** in bulk. It was the dominant cost in the whole
  DDS round trip. `:i8` keeps the generic path (signed elements need per-element two's-complement
  conversion). Wire-identical: an octet has alignment 1, so there is no inter-element padding to reproduce.
- **A sequence's serialized SIZE is computed in closed form, never by looping** (`define-dds-type` codegen).
  The size function runs on **every write**; looping `cdr-size-align` once per element cost **~107 µs for a
  16 KB sequence — to compute an integer**. Every supported element type has `(size MOD effective-align) = 0`,
  so: align once, then add `n × size`. (Verified identical to the old loop over 64 000 combinations.)
- **A decoded sequence is SPECIALIZED to its element type** (`cdr-get-sequence-typed`, which the
  generated codecs call for non-octet elements). An untyped `simple-vector` costs 8 B per element whatever
  the element is — 8× amplification for an octet sequence, both as steady-state garbage and as an
  attacker-drivable allocation multiplier. Never decode a sequence into an untyped vector on a data path.
- **`cdr-get-string` / `cdr-get-sequence` allocate — but only after extent validation.**
  The deserialize side currently allocates the result string/vector, and the
  wire-supplied length/count is validated against the remaining buffer extent *before*
  that allocation (a hostile `0xFFFFFFFF` length signals `buffer-overflow` instead of
  exhausting the heap, NFR-SEC-POSTURE). The pooled, zero-alloc deserialize path is a
  tracked M1-perf follow-up (FR-LANG-5 / NFR-DET); the *serialize* side and pool
  acquire/release are already allocation-free.
- **DELIMITED / MUTABLE struct serialization is incremental.** `cdr-put-dheader`,
  `emheader1-encode`, and `lc-for-length` are the pinned, byte-exact framing primitives;
  the full DELIMITED/MUTABLE struct walk that composes them is a later increment. The
  generated `serialize-T` functions that drive them live in
  [Type system & code generation](type-system.md).
- **`enum` is fixed 32-bit.** `bit_bound` refinement of enum width is deferred.
- **MD5 is not a security primitive.** It is a content/identity hash for XTypes hashes
  and the >16-byte keyhash only. The DDS-Security profile (FR-SEC-2) mandates vetted
  native crypto, which this is not.
