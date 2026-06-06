# cdr-capture — byte-exact XCDR payload reference (FR-CDR-8)

Publishes one fixed sample `ShapeType{color="RED", x=1, y=2, shapesize=3}` and decodes it
locally, so you can capture the exact serialized payload Connext puts on the wire.

```sh
make
./cdr_capture 0
# in another terminal:
tshark -i lo -O rtps -V | grep -A20 serializedData      # lo0 on macOS
```

Expected XCDR body (after the 4-byte encapsulation header), little-endian:

```
04 00 00 00  52 45 44 00  01 00 00 00  02 00 00 00  03 00 00 00
\---len=4--/  \--R E D \0/  \---x=1---/  \---y=2---/  \--size=3--/
```

This is exactly what this stack's generated `serialize-shape-type` emits for the same
sample. Connext may stamp the encapsulation id `CDR_LE` (`00 01`) where this stack uses
`CDR2_LE` (`00 07`); for this `@final` 32-bit/string type the **body is identical** (no
8-byte members, no DHEADER), so the bodies must match byte-for-byte. Any divergence is a
real CDR bug to file against `src/dds-cdr/`.
