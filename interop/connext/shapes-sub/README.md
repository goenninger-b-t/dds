# shapes-sub — Connext subscribes to ShapeType (interop IN)

```sh
make
./shapes_sub 0          # domain (0); optional 2nd arg = seconds to run (0 = forever)
```

Publish from this stack and confirm Connext decodes our samples (FR-IO-1, FR-CDR-8):

```sh
# in this repo, on the same domain:
make square-pub COLOR=GREEN     # our publisher
# -> shapes_sub should print: color=GREEN x=.. y=.. size=..
```

Correct field values here prove this stack's XCDR2 payload and reliable RTPS data plane are
wire-correct for Connext. If samples never arrive, check `tshark -O rtps` for the SEDP match
and the DATA submessage.
