# shapes-pub — Connext publishes ShapeType (interop OUT)

```sh
make
./shapes_pub 0 BLUE 30      # domain, color, shapesize
```

Verify this stack receives Connext's samples (FR-IO-1, writer→reader):

```sh
# in this repo, on the same domain:
make square-sub             # our subscriber should print incoming BLUE squares
```

Reliable QoS, topic "Square", type "ShapeType" — matching this stack's `make square-pub/sub`
and RTI `rtishapesdemo`. Validate the wire with `tshark -O rtps` if a sample fails to arrive.
