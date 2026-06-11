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

## Files

`Corpus.idl`, `corpus_pub.cxx`, `USER_QOS_PROFILES.xml`, `Makefile`, `README.md` are the
committed sources. `Corpus.{hpp,cxx}`, `CorpusPlugin.{hpp,cxx}`, `corpus_pub`, `*.o`,
`.gen.stamp`, and any `*.pcap`/`*.out` are rtiddsgen output / build artifacts — git-ignored,
never committed.
