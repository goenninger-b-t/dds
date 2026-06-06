# typeobject-probe — the EquivalenceHash / TypeObject oracle

Puts a Connext `ShapeType` writer+reader on the wire and idles, so its SEDP announcement
(with `PID_TYPE_INFORMATION`) can be captured and compared to this stack's **provisional**
serializer output.

```sh
make            # needs NDDSHOME + CONNEXTDDS_ARCH (see ../README.md)
./typeobject_probe 0            # domain 0
```

While it runs, capture the discovery traffic:
```sh
tshark -i lo  -O rtps -V | grep -A60 'PID_TYPE_INFORMATION'    # Linux  (lo0 on macOS)
# or: rtiddsspy -domainId 0 -printSample
```

**Compare** the dissected `TypeIdentifier` (EK_MINIMAL) hash and the serialized TypeObject
length against ours:

```
ShapeType  (@final; @key unbounded string color; long x,y,shapesize; ids 0..3)
ours: EquivalenceHash = BF E2 A6 2E D8 11 AC 46 3C 40 C9 7D 30 EE
ours: TypeObject      = 87 bytes (no encapsulation header)
```

- **Match** → our `typeobject-cdr.lisp` is byte-correct; the `xtypes-typeobject-cdr`
  regression vector locks, and `(b2b)` hash-based match enforcement can be enabled.
- **Differ** → the diff isolates one of three one-line knobs in `typeobject-cdr.lisp`:
  the no-encapsulation-header choice, `%struct-type-flag`, or `%member-flag`
  (TRY_CONSTRUCT / @must_understand bits). Send me the bytes and I'll correct + re-lock.
