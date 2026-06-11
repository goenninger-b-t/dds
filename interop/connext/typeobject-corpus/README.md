# typeobject-corpus — the legacy-TypeObject capture corpus (Connext side)

Puts a Connext corpus type on the wire so its SEDP `DATA(w)` — carrying RTI's
**proprietary legacy TypeObject** (the inflated `PID_TYPE_OBJECT_LB` / `0x8021`) — can be
captured by this stack's `make corpus-capture` subscriber and reverse-engineered into a
parser. Clean-room (NFR-IP): the C++ app mirrors our own `../typeobject-probe`; rtiddsgen
output is git-ignored and never committed; no RTI source is read to decode anything.

`C_Shape` is the **base** type: it reproduces `ShapeType` (`../common/ShapeType.idl`) so its
captured legacy TypeObject cross-checks against the already-locked `%connext-shape-type-lb`,
proving the capture pipeline is faithful before later tasks add more types.

## Build

```sh
export NDDSHOME=/Applications/rti_connext_dds-7.3.1
export CONNEXTDDS_ARCH=arm64Darwin20clang12.0
export DYLD_LIBRARY_PATH=$NDDSHOME/lib/$CONNEXTDDS_ARCH
make                 # rtiddsgen + build corpus_pub
```

`corpus_pub` is a single-process matched writer+reader (the `typeobject-probe` pattern, so
SEDP definitely fires), with topic and type name selected by argv so the ONE binary serves
every corpus type:

```sh
./corpus_pub <domain> <topic> <typename>     # e.g. ./corpus_pub 0 Square C_Shape
```

For THIS task only `C_Shape` exists in `Corpus.idl`; the argv dispatch in `corpus_pub.cxx`
is built so later tasks append a struct to `Corpus.idl`, add one dispatch arm, and rebuild —
no new binary.

## Capture cross-check (the deliverable)

Run `corpus_pub` and this stack's subscriber simultaneously on loopback (no sudo):

```sh
# terminal 1 (from this dir, with the env above so DYLD finds the RTI libs):
./corpus_pub 0 Square C_Shape

# terminal 2 (repo root):
make corpus-capture TOPIC=Square TYPE=C_Shape SECONDS=25
```

The subscriber prints the captured `PID_TYPE_OBJECT_LB` as a Lisp byte vector and exits.

### Addressing (why the QoS allows both interfaces)

`make corpus-capture` (`run-corpus-capture-subscriber`) advertises its unicast metatraffic
locator as **127.0.0.1** but egresses its multicast SPDP (`239.255.0.1`) on **en7**
(192.168.2.148 — the box's default multicast route). So `USER_QOS_PROFILES.xml` pins
Connext to UDPv4 on **both** `192.168.2.148` (to receive our multicast SPDP and discover us)
**and** `127.0.0.1` (to send unicast SEDP `DATA(w)` to our advertised locator, which our
`0.0.0.0`-bound socket receives). SHMEM is dropped; multicast SPDP stays enabled. This
mirrors the proven `shapes-pub` / `large-data` interop profiles, plus loopback.

## rtiddsgen vs the unbounded `string` (recorded finding)

`Corpus.idl` declares `@key string color` (unbounded). `rtiddsgen` 4.3.1 maps the C++ member
to an unbounded `std::string`, but the generated **typecode bounds the string at 255**:

```
Corpus.cxx: C_Shape_g_tc_color_string = initialize_string_typecode((255L));
```

i.e. RTI's default unbounded-string bound is **255**, exactly the `string_255_character`
token that surfaces in the captured legacy TypeObject below (and matches the ShapeType /
ADR 0009 finding). No `-unboundedSupport` flag is needed for this corpus: the bound changes
the TypeObject, not the XCDR wire payload, and name/structural matching absorbs it.

## C_Shape base capture, 2026-06-11

Captured live (Connext `corpus_pub 0 Square C_Shape` ↔ `make corpus-capture TOPIC=Square
TYPE=C_Shape`, loopback). This is the verbatim `PID_TYPE_OBJECT_LB` byte vector our
subscriber returned — **232 octets**; bytes 0..3 are the CDR-LE length header and bytes
12.. are a zlib stream (`78 DA …`), the compressed legacy TypeObject:

```lisp
;; C_Shape base capture, 2026-06-11 (232 octets)
(1 0 0 0 24 2 0 0 219 0 0 0 120 218 99 172 231 96 0 129 55 140 12 12 76 96 22 11 131 24 144
 100 4 138 115 2 105 23 70 8 27 4 100 64 226 96 89 6 134 106 110 249 25 103 138 117 223 130
 100 156 227 131 51 18 11 82 193 234 24 193 38 64 0 136 159 130 198 79 5 217 5 21 131 153
 171 2 54 23 2 132 161 116 197 85 159 52 75 166 45 149 108 64 118 114 126 78 126 17 84 61
 178 249 76 245 8 51 68 96 118 0 49 43 16 130 252 82 65 164 30 38 36 61 149 4 244 200 64
 197 152 161 122 184 128 116 49 200 247 197 153 85 169 56 244 194 48 72 84 24 170 6 100 90
 9 82 24 232 128 221 33 140 226 119 81 144 217 37 69 153 121 233 241 70 166 166 241 201 25
 137 69 137 201 37 169 69 12 88 236 65 14 107 30 32 76 133 202 128 196 79 64 197 255 35 185
 7 166 95 0 136 197 160 102 192 226 20 36 15 0 9 35 54 22 0)
```

Cross-check (this stack, no external dissector):

```
(dds.types:inflate-type-object-lb <vec>)  => non-NIL, inflate-len = 536
(dds.types:type-object-strings <inflated>) =>
   ("C_Shape" "Lf9" "color" "shapesize" "Lf9" "string_255_character")
```

`C_Shape`, `color`, `shapesize` all present (the fingerprint), and `string_255_character`
confirms the 255 default string bound above. (`x`/`y` are single-char member names below the
`type-object-strings` min-length-3 filter; expected.) Later parser tasks embed this vector.

## Differential variants (member id / member counting)

`Corpus.idl` also carries three differential siblings of `C_Shape`, each capturable via the
same `corpus_pub <domain> Square <typename>` ↔ `make corpus-capture` flow:

- `C_Shape2` — `color` renamed to `colour` (localizes the member-name string).
- `C_Shape3` — `C_Shape` + a 5th member `long w`. Proves the member-list container's first
  value word is the **member count** and that an appended member takes the next sequential id
  (`color 0, x 1, y 2, shapesize 3, w 4`).
- `C_Shape4` — `C_Shape` with `x` moved ahead of the `@key color`. Proves the member id is
  **positional** (the 0-based declaration index): `x 0, color 1, y 2, shapesize 3`.

Captured vectors + the full analysis are in `docs/provenance.md` (2026-06-11); they drive
`dds.types:parse-legacy-type-object` (the struct-skeleton interpreter, Task 2.1).

### `C_ShapeP_<prim>` — primitive member type-kind (Task 2.2)

Ten more siblings, each C_Shape with member `x` retyped to one primitive:
`C_ShapeP_{short,ushort,ulong,longlong,ulonglong,octet,float,double,boolean,char}`. Diffing
each against the base C_Shape localizes the primitive type-kind to member x's node at
`VALUE-START+8` (a u16) and reveals RTI's OWN kind enumeration (boolean 1, octet 2, short 3,
ushort 4, long 5, ulong 6, longlong 7, ulonglong 8, float 9, double 0x0A, char 0x0C — which
DIFFERS from the XTypes TK_* octets). Captured vectors + the full RTI-kind→`+tk-*+` table are
in `docs/provenance.md` (2026-06-11); they drive `%lto-member-type-identifier`. `int8`/`uint8`
are not captured (corpus uses `octet`); per RTI's Extensible Types Guide they map to `octet`
(kind 2) — recorded there as a fail-open gap.

### `C_ShapeS32` / `C_ShapeS300` / `C_ShapeNoKey` — string bound + `@key` flag (Task 2.3)

Three more siblings: `C_ShapeS32` (`color` is `string<32>`), `C_ShapeS300` (`string<300>`,
bound > 255), and `C_ShapeNoKey` (`color` is a plain `string`, `@key` moved to `long x`). The
string member's node carries kind `0x13` at `VALUE-START+8` plus an 8-octet type-hash at `+16`
that references a string-definition node (`CODE 8`); that node's `CODE 200` child holds the bound
as a u32 (255 default-unbounded / 32 / 300 — **always** a u32, the small/large split is ours).
The `@key` flag is the u32 at the member node's `VALUE-START+0` (1 key / 0 non-key). Captured
vectors + the full analysis are in `docs/provenance.md` (2026-06-11); they drive
`%lto-member-type-identifier` (string arm) + `%lto-member-key-p`. Only the `char`-element narrow
`string` was exercised; `wstring` / a non-default element are an untested gap. NOTE: on macOS the
RTI dylibs use `@loader_path` install names and SIP strips `DYLD_LIBRARY_PATH`, so symlink
`libnddscpp2.dylib` / `libnddsc.dylib` / `libnddscore.dylib` from `$NDDSHOME/lib/$CONNEXTDDS_ARCH`
next to `corpus_pub` before running (git-ignored, like all build artifacts).

### `C_ShapeAppend` / `C_ShapeMutable` — struct extensibility (Task 2.4)

Two more siblings: `C_ShapeAppend` (`@appendable struct`) and `C_ShapeMutable` (`@mutable struct`),
members otherwise identical to the base `@final` `C_Shape`. The extensibility flag is the u16 at the
struct-definition node (`CODE 9`)'s **first `CODE 0` child's `VALUE-START+0`** — RTI's own enum
(`@appendable`=0, `@final`=1, `@mutable`=2), which coincides with the XTypes `IS_*` struct-flag bits
only for `:final`. The member encoding was **byte-identical** across all three (these scalar/string
members do not change layout under `@mutable`). Captured vectors + the full analysis are in
`docs/provenance.md` (2026-06-11); they drive `%lto-struct-extensibility`, completing the tier-1
flat-struct parse (names / ids / primitives / strings / keys / extensibility) that feeds
`struct-assignable-from`.

### `C_Seq` / `C_SeqL` / `C_SeqL100` — sequence member element + bound (Task 3.1)

Three more siblings, each a struct with `@key long id` plus one sequence member `payload`: `C_Seq`
(`sequence<octet>`, matching the LargeData shape — unbounded), `C_SeqL` (`sequence<long, 10>`), and
`C_SeqL100` (`sequence<long, 100>`). The sequence member's node carries kind `0x12` (18) at
`VALUE-START+8` plus an 8-octet type-hash at `+16` that references a sequence-definition node
(`CODE 7`, vs `CODE 8` for strings); that node's `CODE 100` child holds the element type-kind (u16,
RTI's primitive enum: octet 2 / long 5) and its `CODE 200` child the bound as a u32. The unbounded
`C_Seq` emits bound **100** (RTI's default unbounded-sequence bound, mirroring 255 for strings; the
internal type name `sequence_100_Byte` confirms it); `C_SeqL`/`C_SeqL100` give 10/100. Captured vectors
+ the full analysis are in `docs/provenance.md` (2026-06-11); they drive `%lto-sequence-type-identifier`.
Only sequence-of-PRIMITIVE was exercised; sequence-of-{string,struct,sequence} is a Task-3.2 gap
(the member TI stays NIL, fail-open). NOTE: on macOS symlink the RTI dylibs next to `corpus_pub` (SIP
strips `DYLD_LIBRARY_PATH`), as for the string-bound experiments.

### `C_Nested` / `C_Nested2` — nested-struct member + recursion (Task 3.2)

Two more siblings: `C_Nested` (`@key long id; C_Inner inner`) and `C_Nested2` (a 2nd `C_Inner
inner2`); `C_Inner` is `@final struct { long a; long b; }`. Publishing `C_Nested` makes RTI emit
`C_Inner`'s definition as a **TypeLibrary sibling** in the SAME legacy TypeObject — the outer
`C_Nested` `CODE 9` struct-def FIRST, `C_Inner`'s `CODE 9` def after it. The nested member's node
carries kind `0x16` (22) at `VALUE-START+8` (strings `0x13`, sequences `0x12`, nested struct
`0x16`) plus the same 8-octet type-hash at `+16`, referencing `C_Inner`'s `CODE 9` def (whose
`CODE 0` child echoes that hash at `VALUE-START+8`) — the SAME hash-reference mechanism, just a
different def-node CODE. The decoder resolves the def (shared `%lto-find-def-node`, def-code 9),
parses it via the shared `%lto-parse-struct-node` (so nesting recurses), and attaches it as an
EK_MINIMAL `hash-type-identifier`'s `referenced` — the shape `struct-assignable-from` / the
TypeLookup gate recurse into. Bounded by `*lto-max-type-depth*` + a visited-hash cycle guard (a
hostile self-/mutually-referential TypeObject terminates, never hangs); `C_Nested2`'s two members
sharing one `C_Inner` def confirm a legitimate repeated reference is not over-blocked. Captured
vectors + the full analysis are in `docs/provenance.md` (2026-06-11); they drive
`%lto-nested-type-identifier`. Sequence-of-aggregate + Stage-4 aggregates (union/enum/array/typedef)
stay a gap (member TI NIL, fail-open). NOTE: on macOS symlink the RTI dylibs next to `corpus_pub`
(SIP strips `DYLD_LIBRARY_PATH`), as for the earlier experiments.

### `C_Enum` — enum member-kind + the degrading policy (Task 4.1)

One more sibling: `C_Enum` (`@key long id; SomeEnum e`) with `enum SomeEnum { RED, GREEN, BLUE }`.
The enum member `e` carries member-kind **`0x0E` (14)** at `VALUE-START+8` (primitives `1`–`0x0C`,
string `0x13`, sequence `0x12`, nested struct `0x16`, **enum `0x0E`**). The inflated capture's
fingerprint strings are `("C_Enum" "SomeEnum" "RED" "GREEN" "BLUE")`. **Decision (the operating
contract, Task 4.1):** our assignability model (`src/dds-types/assignability.lisp`) has **no enum
TypeIdentifier** — it models only primitives / narrow strings / plain sequences / structs and treats
enum as conservatively non-assignable. Per the rule "never emit a TI assignability will mis-handle",
an enum member is therefore **unmodelable** and `parse-legacy-type-object` degrades the WHOLE type to
**`:unsupported`** (fail-open to name-match), recorded as a gap (decode-as-int is unlocked the day
assignability gains an enum TI). This is the **degrading policy**: any member that declares a type the
model cannot represent (an unmapped kind, an unresolvable hash, an over-depth/cyclic nested struct)
makes the whole parse `:unsupported`, so the Stage-5 gate never sees a partial model with a NIL-TI
member. Captured vector + analysis in `docs/provenance.md` (2026-06-11). NOTE: on macOS symlink the
RTI dylibs next to `corpus_pub` (SIP strips `DYLD_LIBRARY_PATH`), as for the earlier experiments.

### `C_Union` / `C_Array` — union/array member-kinds, degrading tier (Task 4.2)

Two more siblings: `C_Union` (`@key long id; SomeUnion u` with `union SomeUnion switch(long) { case
0: long a; case 1: double b; }`) and `C_Array` (`@key long id; long arr[4]`). The captures
confirm: union member `u` carries member-kind **`0x15` (21)** at `VALUE-START+8`; array member `arr`
carries member-kind **`0x11` (17)** at `VALUE-START+8`. Neither value is in `*lto-primitive-kind-keyword*`
(range `1`–`0x0C`) or any other mapped arm, so `%lto-member-type-identifier` returns `NIL`; the
Task-4.1 policy flip fires → `:unsupported` (fail-open). No guard was added to `%lto-member-type-identifier`
(no kind collision). **Bitmask** (`bitmask SomeBits { FLAG_A, FLAG_B, FLAG_C }`) was attempted but
**NOT CAPTURABLE**: `rtiddsgen 4.3.1` rejects the `bitmask` keyword with `"mismatched input 'bitmask'
expecting EOF"` (IDL4 construct, unsupported by this version) — gap recorded in `docs/provenance.md`
(2026-06-11). A newer `rtiddsgen` can add that capture. Captured vectors + analysis in
`docs/provenance.md` (2026-06-11). **Degrading tier complete**: all non-{primitive,string,sequence,
struct} constructs (enum `0x0E`, union `0x15`, array `0x11`, bitmask gap) verifiably fail open to
`:unsupported` (test `lto-parse-aggregates-unsupported`). 90 tests green SBCL.

## Live type-gating acceptance test, 2026-06-11 (Task 6.1, ADR 0011 — completes ADR 0010)

`corpus_pub` is also the live peer for the FR-TYPE-4 **type-gate** acceptance test: it both
publishes a legacy TypeObject on SEDP **and writes one C_Shape sample/second**, so our gated
subscriber discovers it, the gate fires on the real `PID_TYPE_OBJECT_LB`, and (when compatible)
samples are delivered. Our side is the DCPS-level gated subscriber `make gated-sub` (the
standalone `make square-sub` is a bare `dds.disc` node with no gate; only a DCPS participant
installs the gate). Addressing is unchanged from `make corpus-capture` (this dir's
`USER_QOS_PROFILES.xml`).

```sh
# terminal 1 (this dir, RTI env + dylib symlinks):
./corpus_pub 0 Square C_Shape

# terminal 2 (repo root) — Step 1 COMPATIBLE: local type matches C_Shape
make gated-sub TOPIC=Square TYPENAME=C_Shape LOCALTYPE=shape-type     SECONDS=25
# Step 2 INCOMPATIBLE: local `shapesize` retyped long->i64 (not assignable)
make gated-sub TOPIC=Square TYPENAME=C_Shape LOCALTYPE=shape-mismatch SECONDS=25
# Step 3 NO-FALSE-REJECT: re-run Step 1 — still matches + delivers
```

Observed (verbatim gate verdict + match + sample counts):

```
# Step 1 (compatible):
; type-gate[Square/C_Shape]: COMPATIBLE — legacy-TypeObject assignability
[gated-sub] MATCHED 1 remote endpoint(s) (gate verdict :compatible).
[gated-sub] stopped: received 25 sample(s); matched=1; INCONSISTENT_TOPIC total=0.

# Step 2 (incompatible — the key proof):
; type-gate[Square/C_Shape]: INCOMPATIBLE — legacy-TypeObject assignability
[gated-sub] stopped: received 0 sample(s); matched=0; INCONSISTENT_TOPIC total=1.

# Step 3 (re-run compatible — cardinal no-false-reject):
; type-gate[Square/C_Shape]: COMPATIBLE — legacy-TypeObject assignability
[gated-sub] stopped: received 20 sample(s); matched=1; INCONSISTENT_TOPIC total=0.
```

The gate parsed Connext's live 232-octet `PID_TYPE_OBJECT_LB` (536 inflated, fingerprint
`C_Shape`/`color`/`shapesize`, cross-checked live by `make corpus-capture`), ran the real
`struct-assignable-from`, and decided the match accordingly. A reliable RTPS reader buffers
wire samples regardless of the DDS match verdict, so after an `:incompatible` verdict
`run-gated-subscriber` guards the drain (a wrong-type wire sample is logged + skipped, never
fatal; `SUBSCRIPTION_MATCHED` stays 0). Full analysis: `docs/adr/0011-*.md`.

## Files

`Corpus.idl`, `corpus_pub.cxx`, `USER_QOS_PROFILES.xml`, `Makefile`, `README.md` are the
committed sources. `Corpus.{hpp,cxx}`, `CorpusPlugin.{hpp,cxx}`, `corpus_pub`, `*.o`,
`.gen.stamp`, and any `*.pcap`/`*.out` are rtiddsgen output / build artifacts — git-ignored,
never committed.
