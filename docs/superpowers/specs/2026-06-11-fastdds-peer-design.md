# Fast DDS open peer: FR-IO-2 interop + TypeLookup / EquivalenceHash oracle

- **Date:** 2026-06-11
- **Status:** **COMPLETE (2026-06-12)** — all stages S0–S5 implemented; FR-IO-2 met (ADR 0012; the leg-B reply direction is non-stock-only, see the ADR). Was: Design — approved for planning.
- **Area:** interop harness (new `interop/fastdds/`), external toolchain (Fast DDS source build), L3 type system + L5 discovery only if live testing exposes bugs (fixes per the normal per-task flow)
- **Requirements:** FR-IO-2 (wire-interoperate with ≥1 of Fast DDS / Cyclone DDS / OpenDDS), FR-TYPE-2/3 (the PROVISIONAL MinimalTypeObject serializer + EquivalenceHash and TypeInformation codec gain their first external oracle), FR-TYPE-3 (TypeLookup live leg deferred by ADR 0010), NFR-IP (clean-room: Fast DDS is Apache-2.0 — read, never copy), the operating contract §4 (the wire is the oracle) and §6 (gates)

## 1. Goal & scope

Stand up **eProsima Fast DDS 3.6.1** (latest stable at design time; includes the CVE-2026-22591 fix) as a native peer on the macOS dev box and use it for three things, in dependency order:

1. **FR-IO-2 closed** — bidirectional reliable ShapeType data exchange between our stack and stock Fast DDS, tshark-validated, mirroring the M2 Connext exit-gate discipline (forward peer→us and reverse us→peer, sample counts logged, pcaps archived).
2. **EquivalenceHash externally confirmed** — for a bound-aligned ShapeType, the minimal EquivalenceHash our serializer computes equals the EK_MINIMAL hash Fast DDS emits in `PID_TYPE_INFORMATION` (0x0075). This is the first external confirmation of the §7.3.4.9.1 hash and the §7.4.3.5.3 serialization VM reading (ADR 0009 left it unconfirmable against Connext, which never emits 0x0075).
3. **TypeLookup live-confirmed** (closes the ADR 0010 deferred leg) — both directions: (a) our getTypes client queries the Fast DDS server, the returned TypeObject parses and re-hashes to the queried hash; (b) Fast DDS consumes our service traffic (its type-driven endpoint matching completes against our participant). Every CONFIRM-VS-PEER annotation in the TypeLookup codecs is checked against Fast DDS's actual bytes; the self-pinned regression vectors become peer-confirmed (re-pinned only where the peer disagrees and the spec clause sides with the peer).

Fast DDS was chosen over Cyclone/OpenDDS because it is the one open peer that implements the standard TypeLookup service (ADR 0010; tshark's TL dissection mirrors Fast DDS).

## 2. Decisions (locked during brainstorming, owner-approved)

1. **Scope = full FR-IO-2 + TypeLookup oracle**, staged shapes-first (owner pick over a TL-only or shapes-only cut).
2. **Native source build** on macOS (owner pick over Docker — Docker-on-mac NAT breaks RTPS multicast to the host — and over the Java-free XML-dynamic-types route, which would put reverse-engineering risk inside the oracle).
3. **Harness mirrors `interop/connext/`** (owner pick over stock eProsima examples / ShapesDemo GUI): our canonical ShapeType IDL → fastddsgen-generated C++ + thin pub/sub mains; scriptable, repeatable, type-aligned.
4. **Toolchain location:** `~/gbt Dropbox/gbt/projects/fastdds/` — the Clasp sibling convention (owner approved §2 as presented, including this location).
5. Fast DDS is a **test peer, not a code dependency**: no SBOM entry; version pins, commit hashes, and licenses recorded in `docs/provenance.md`.

## 3. External toolchain (outside the repo)

Under `~/gbt Dropbox/gbt/projects/fastdds/`:

- Pinned-tag clones of **foonathan_memory_vendor**, **Fast CDR**, and **Fast-DDS v3.6.1** (exact dependency tags per the v3.6.1 release notes / versions table — read at install time, not from memory), CMake-built into one local install prefix (`.../fastdds/install`). No `/usr/local` pollution.
- **fastddsgen** (the release matching Fast DDS 3.6.x) + a JDK via `brew install openjdk` (fastddsgen is the only Java consumer).
- Fallback: if v3.6.1 does not build on this macOS 26 host, step back one minor release at a time; record the pin actually used.
- Everything recorded in `docs/provenance.md`: repo URLs, tags, commit hashes, licenses (Apache-2.0), and the clean-room note (Fast DDS source may be read for understanding; copying imports its license; the harness C++ is written fresh; fastddsgen-generated files are recorded as generated artifacts with the generator version).

## 4. Repo harness (`interop/fastdds/`)

Mirrors `interop/connext/`:

- **`ShapeType.idl`** — the canonical shape, bound-aligned with our local model: `@key string<B> color; long x; long y; long shapesize;` with `@final` extensibility. **B and the local model's bound must denote the same nominal type on both sides** — the rtiddsgen lesson (it silently bounds "unbounded" at 255, making the committed 87-byte hash describe a different type) is the known trap. The exact bound (and whether the local `dds-shapes` type or a new bound-pinned variant is used) is pinned at implementation time from the XTypes string-bound encoding clause + the first Fast DDS capture; the design constraint is only: *both sides hash the same nominal type*.
- **fastddsgen-generated type support** (committed, provenance-noted) + thin **`shapes_pub.cpp` / `shapes_sub.cpp`** mains: stock DDS API usage, TypeLookup client+server explicitly enabled in participant QoS (not left to defaults), sample logging compatible with the Connext harness's run discipline.
- **Transport profile XML**: UDPv4-only, single interface — Fast DDS defaults include SHMEM, and the Connext round proved same-host SHMEM bypasses lo0 capture; the profile keeps every byte observable.
- **`Makefile` targets** (repo top level, like the Connext ones): build the harness, run pub/sub legs, run the capture census.
- **`README.md`** with build/run commands, environment (install prefix, `DYLD_LIBRARY_PATH`), raw run logs, and the pcap inventory.
- A small env helper (modeled on `scripts/with-clasp.sh`) pinning the install prefix so make targets work from a fresh shell.

## 5. Stages (stage = commit boundary; SBCL suite per task, Clasp at stage boundaries; commit messages presented for owner approval)

- **S0 — toolchain.** Build + install the pinned toolchain; generate + commit the harness skeleton (IDL, generated code, mains, profile, Makefile targets, README); provenance entry. Exit: harness binaries build and run standalone (pub and sub see each other Fast DDS↔Fast DDS on lo0).
- **S1 — discovery census.** Run Fast DDS against our stack; capture SPDP/SEDP both ways. Establish from the wire: does it emit 0x0075 (and with what TypeInformation framing), which TypeLookup endpoints/builtin-mask bits it announces, its instanceName string, and whether our SPDP/SEDP parses cleanly (vendor-id quirks, unknown PIDs). Exit: mutual participant + endpoint discovery, both directions, capture archived.
- **S2 — data plane (FR-IO-2 DoD).** Forward Fast DDS pub → our sub; reverse our pub → Fast DDS sub; RELIABLE; sample counts + tshark validation; any bug found in our stack fixed clause-cited with a regression test (the M2/DATA_FRAG experience says expect some). Exit: bidirectional reliable exchange, logged + archived.
- **S3 — EquivalenceHash oracle.** Compare Fast DDS's emitted EK_MINIMAL hash for the bound-aligned ShapeType against ours. Match → remove the PROVISIONAL caveat for the exercised path (FINAL struct, i32, string) in `docs/verification.csv`; mismatch → a real serializer bug, fixed clause-first, then re-compared. Exit: hashes equal, recorded.
- **S4 — TypeLookup live.** Our client getTypes against their server (returned TypeObject parses + re-hashes); their consumption of our request/reply traffic (their type-resolved match completes). Walk the CONFIRM-VS-PEER list — instanceName length, ReplyHeader remoteEx placement, EMHEADER1 LC=5 (rule 22), non-OK-omits-Return framing, top-level @final ⇒ CDR2_LE 0x0007 — against their bytes; re-pin vectors only where the clause sides with the peer. Exit: both directions proven, vectors peer-confirmed.
- **S5 — closeout.** `docs/verification.csv` (FR-IO-2 pass; FR-TYPE-2/3 caveats updated), `docs/wiki/` + `README.md`, `docs/provenance.md` final pins, a closing ADR (ADR 0010's deferred leg resolved; records hash verdict + any framing re-pins), memory update.

## 6. Error handling & risks

- **Hash mismatch (S3) is a finding, not a failure.** ShapeType exercises only the FINAL-struct + primitives + string path of the serialization VM; a mismatch on that narrow path means our bytes are wrong — fix in `typeobject-cdr.lisp` clause-cited. The uncertain edges (APPENDABLE-union DHEADER, FINAL-union disc, MUTABLE-empty structs, TK_NONE base) remain unexercised and keep their caveats.
- **Framing divergence (S4):** resolved exactly like the tshark round — spec clause first; if the clause genuinely supports the peer, fix + re-pin; if the peer deviates from the clause, record the deviation in provenance and keep our clause-true bytes (tolerate-liberally on receive).
- **Fast DDS knobs:** TypeLookup client/server and type propagation are set explicitly in the harness participant QoS; no reliance on version-dependent defaults. S1's census records what the defaults actually were.
- **Same-host networking:** UDPv4-only single-interface profile from the start (SHMEM and multi-iface ambiguity caused real losses in the Connext round).
- **Build failure:** fall back one minor release; record the actual pin.
- **Vendor differences in SPDP/SEDP parsing:** any Fast DDS PID or framing our discovery stack mishandles is a real FR-IO-2 bug — bounds-checked fix + regression vector, never a harness workaround.

## 7. Testing

- The offline suite (91 green SBCL + Clasp) stays green on every commit; `make gate-types`/`gate-hotpath` unaffected (harness is C++; any Lisp fixes follow the normal gates).
- Every byte re-pinned in S3/S4 lands as/updates a locked regression vector test.
- Live legs are reproducible: make targets + README commands + archived pcaps and logs, exactly like `interop/connext/typeobject-corpus/`.
- Clasp run at stage boundaries (`GC_DONT_GC=1`, one retry on the known intermittent abort).

## 8. Out of scope (recorded, not designed-out)

- Cyclone DDS / OpenDDS as additional peers (FR-IO-2 needs ≥1).
- Exercising the unexercised serialization-VM edges (unions, MUTABLE structs, nested-dependency hashes) against Fast DDS — follow-on once the ShapeType path is confirmed.
- DATA_FRAG / large-data interop with Fast DDS (proven against Connext; re-proving here is optional follow-on).
- Content-filter / QoS-matrix interop beyond what RELIABLE shapes exercises.
- CI automation of the live legs (manual, documented runs — same status as the Connext legs).
