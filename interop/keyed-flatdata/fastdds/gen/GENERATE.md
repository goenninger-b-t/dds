# Generate the Fast DDS type support for KeyedFlat (owner step)

This directory holds the **fastddsgen output for `../../KeyedFlat.idl`, committed verbatim**
(Apache-2.0 output of the pinned generator — same convention as
`interop/fastdds/shapes/gen/`; record the generator pin + licence in
`docs/provenance.md`). It could not be produced in the build session that authored this
harness because the Fast DDS toolchain (`FASTDDSGEN`) lives only in the owner's
environment (`scripts/with-fastdds.sh`), not in CI/the build sandbox.

Generate it once (Fast-DDS-Gen v4.3.0 per `interop/fastdds/README.md`):

```sh
cd interop/keyed-flatdata/fastdds
../../../scripts/with-fastdds.sh bash -c '"$FASTDDSGEN" -replace -d gen ../KeyedFlat.idl'
```

This emits (mirroring `interop/fastdds/shapes/gen/`):

```
KeyedFlat.hpp                 the C++ type
KeyedFlatCdrAux.hpp / .ipp    the (X)CDR (de)serialization
KeyedFlatPubSubTypes.hpp/.cxx the TypeSupport (KeyedFlatPubSubType, registers type name "KeyedFlat")
KeyedFlatTypeObjectSupport.*  the XTypes TypeObject/TypeInformation support
```

`keyed_flat_pub.cpp` / `keyed_flat_sub.cpp` include `gen/KeyedFlatPubSubTypes.hpp` and
construct `KeyedFlatPubSubType()`. After generating, `git add interop/keyed-flatdata/fastdds/gen`
and delete this placeholder, then build + run per `../../README.md` ("Fast DDS leg").
