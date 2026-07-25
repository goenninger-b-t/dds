# mutable — the MUTABLE byte-exact reference vector (FR-CDR-8, ADR 0086)

Publishes one fixed `@mutable` sample so the exact SerializedPayload RTI Connext puts **on the wire**
can be committed as a reference vector. `make corpus` then requires our own encoder to reproduce it
byte for byte.

```sh
export NDDSHOME=/Applications/rti_connext_dds-7.3.1
export CONNEXTDDS_ARCH=arm64Darwin20clang12.0            # ls $NDDSHOME/lib
make
# the RTI libs are installed with an @loader_path install name, which DYLD_LIBRARY_PATH cannot
# satisfy, so symlink them next to the binary (same fix as interop/perftest/connext):
for l in libnddscpp2 libnddsc libnddscore; do ln -sf "$NDDSHOME/lib/$CONNEXTDDS_ARCH/$l.dylib" .; done

# terminal 1 — our capturing subscriber (writes corpus/xcdr2/mutabledata-connext.bin):
sbcl --non-interactive --eval '(asdf:load-system :dds-bench)' \
     --eval '(dds.bench:mutable-corpus-capture :domain 62 :advertise-address "192.168.2.148" :seconds 50)'
# terminal 2 — the Connext writer (Connext pins to the LAN interface, hence :advertise-address):
./mutable_pub 62
```

## What the vector settled

ADR 0086 expected this to arbitrate a *length code*. It arbitrated something more basic.

**Connext 7.3.1 sends an `@mutable` type as `PL_CDR` (XCDR1, encapsulation `0x0003`)** — not the
`PL_CDR2` (`0x000b`) this stack sends by default. So XTypes 1.3 rules (23)–(25), the parameter-list
framing, are what actually carry MUTABLE to Connext, and the rules (21)–(22) length-code question does
not arise on this wire at all.

The captured 72 octets then corrected three things in our XCDR1 encoder, each hand-derived from the
clause and each looking right:

| | our first reading | the wire |
|---|---|---|
| parameter length | `M.value.ssize` exactly (2 for a `short`, 10 for a 10-octet string) | rounded **up to a multiple of 4** (4 and 12), pad octets emitted |
| list terminator | `0x3F02` — rule (23) says only "PID_SENTINEL" | **`0x7F02`** — Table 34 marks PID_LIST_END must-understand |
| encoding | PL_CDR2 by default | **PL_CDR** |

None of the three is visible to a round-trip test: our decoder masks the terminator's flags off before
comparing, and it skips by the declared length whether or not that length is padded. Only an external
encoder shows them, which is exactly the argument in `corpus-verify`'s docstring.

## Clean-room (NFR-IP)

Committed here: the IDL, this hand-written driver, the Makefile, this README. **Not** committed: any
`rtiddsgen` output — it is generated at build time and git-ignored (`interop/connext/.gitignore`), as
is the `mutable_pub` binary and the dylib symlinks. What the corpus keeps is the resulting **octets**,
which are the OMG-specified encoding rather than RTI's expression of it. See `docs/provenance.md` §M4.
