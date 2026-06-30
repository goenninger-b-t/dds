# Fast DDS Peer (FR-IO-2 + TypeLookup/EquivalenceHash Oracle) Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Stand up eProsima Fast DDS 3.6.1 as a native macOS peer; prove bidirectional reliable ShapeType interop (FR-IO-2), confirm the minimal EquivalenceHash externally, and live-confirm the TypeLookup service both directions (closes the ADR 0010 deferred leg).

**Architecture:** Pinned source-built Fast DDS toolchain outside the repo (`~/gbt Dropbox/gbt/projects/fastdds/`); a new `interop/fastdds/` harness mirroring `interop/connext/` (canonical ShapeType IDL → fastddsgen C++ + thin pub/sub mains + UDPv4-only profile); staged live legs S1→S4 with every byte validated by tshark and archived. Spec: `docs/superpowers/specs/2026-06-11-fastdds-peer-design.md`.

**Tech Stack:** Fast DDS 3.6.1 + Fast CDR + foonathan_memory_vendor (CMake, clang++), fastddsgen (JDK via brew openjdk), tshark 4.6.6, our SBCL/Clasp stack (`dds.shapes` harness, `dds.disc` TypeLookup endpoints, `dds.types` equivalence-hash).

---

## Standing rules (restate to every subagent)

1. **Clean-room:** Fast DDS is Apache-2.0 — its source/examples MAY be read for understanding (record what was consulted in `docs/provenance.md`); NEVER copy its code into our `src/`. The harness C++ in `interop/fastdds/` is written fresh; fastddsgen-generated files are committed and provenance-noted as generated artifacts. Never read RTI source or the GPL Wireshark dissector source.
2. **Never hardcode a wire constant from memory** — pin from the spec clause (`docs/specs/`, pdftotext) or a capture; cite the clause in a comment.
3. **Every commit message is PRESENTED TO THE OWNER FOR APPROVAL before `git commit` runs.** No Co-Authored-By / AI attribution anywhere. No AI-assistant attribution in any repo file.
4. Lisp changes: `defun*`/`defstruct*` (dds.lang) with full type declarations; docstrings + `docs/wiki/` + `README.md` in lockstep (§5.1); bounds-check every network-facing read (NFR-SEC-POSTURE); no reader conditionals outside `dds-pal/`.
5. Suite green per task on SBCL (`make test` or the targeted asdf test op); Clasp at stage boundaries via `scripts/with-clasp.sh` with `GC_DONT_GC=1`, one retry on the known intermittent abort.
6. Any divergence between our bytes and Fast DDS's is resolved **spec-clause-first**: if the clause sides with the peer, fix ours + re-pin the vector (test first); if the peer deviates, record it in `docs/provenance.md` and keep our clause-true bytes (tolerate on receive).
7. The live runs need captures: `tshark -i lo0 --enable-protocol null --enable-protocol ip --enable-protocol udp -w <file>.pcap` (this host's Wireshark profile disables those dissectors by default; lo0 capture needs no sudo — frgo ∈ access_bpf). Same-host unicast routes over lo0; multicast SPDP may ride en7 — capture both when in doubt.

## Environment constants

- Toolchain root: `~/gbt Dropbox/gbt/projects/fastdds/` (sibling of `projects/clasp`; quote the space in shell: `"$HOME/gbt Dropbox/gbt/projects/fastdds"`).
- Install prefix: `"$HOME/gbt Dropbox/gbt/projects/fastdds/install"` — referred to as `$FASTDDS_PREFIX` below.
- Repo root: `~/gbt Dropbox/gbt/projects/hofvarpnir` — referred to as `$REPO`.
- Our harness announces topic **"Square"**, type **"ShapeType"** (`src/dds-shapes/shapes.lisp:128,259`); the canonical payload codec is `:type :canonical` on `run-publisher`/`run-subscriber` (make `square-pub`/`square-sub` with `TYPE=canonical`).
- Our canonical model: `shape-type` = `@key string color; long x; long y; long shapesize;` FINAL — and our `:string` builds an **unbounded** STRING8 TypeIdentifier (bound 0, `src/dds-types/xtypes.lisp:63-78`), so the IDL below uses plain unbounded `string`. (The rtiddsgen silently-bounds-at-255 trap is RTI-specific; S3 verifies from the wire that fastddsgen keeps bound 0.)

---

## Stage S0 — toolchain + harness skeleton

### Task 0.1: Install the JDK (fastddsgen's only consumer)

**Files:** none (system state; recorded in provenance at Task 0.5)

- [x] **Step 1: Install**

```bash
brew install openjdk
```

- [x] **Step 2: Make it visible and verify**

brew prints a caveat about symlinking; follow it (typically):

```bash
sudo ln -sfn /opt/homebrew/opt/openjdk/libexec/openjdk.jdk /Library/Java/JavaVirtualMachines/openjdk.jdk
java -version
```

Expected: `openjdk version "2x.y"` (any JDK ≥ 11 satisfies fastddsgen). If `sudo` is unavailable in this session, instead export `PATH="/opt/homebrew/opt/openjdk/bin:$PATH"` in the build shell and note that in `scripts/with-fastdds.sh` (Task 0.5).

### Task 0.2: Clone pinned sources + brew build deps

**Files:** creates `"$HOME/gbt Dropbox/gbt/projects/fastdds/{src,install}"`

- [x] **Step 1: Brew dependencies** (per the official "Mac OS installation from sources" page — read it at <https://fast-dds.docs.eprosima.com/en/stable/installation/sources/sources_mac.html> before running; adjust if it lists more):

```bash
brew install asio tinyxml2 openssl@3
```

- [x] **Step 2: Clone Fast-DDS at the pin and read its dependency manifest**

```bash
mkdir -p "$HOME/gbt Dropbox/gbt/projects/fastdds/src"
cd "$HOME/gbt Dropbox/gbt/projects/fastdds/src"
git clone --branch v3.6.1 --depth 1 https://github.com/eProsima/Fast-DDS.git fastdds
cat fastdds/fastdds.repos
```

`fastdds.repos` names the exact matching tags for `eProsima/foonathan_memory_vendor` and `eProsima/Fast-CDR`. **Use those tags** in the next step (do not guess). Record all three (repo, tag, commit hash after clone) for Task 0.5's provenance entry.

- [x] **Step 3: Clone the two dependencies at the manifest tags**

```bash
git clone --branch <tag-from-fastdds.repos> --depth 1 https://github.com/eProsima/foonathan_memory_vendor.git
git clone --branch <tag-from-fastdds.repos> --depth 1 https://github.com/eProsima/Fast-CDR.git fastcdr
git -C foonathan_memory_vendor rev-parse HEAD; git -C fastcdr rev-parse HEAD; git -C fastdds rev-parse HEAD
```

(The `<tag-from-fastdds.repos>` placeholders are resolved by Step 2's output at execution time — this is a deliberate read-the-manifest step, not a plan gap; v3.6.1's manifest is authoritative over anything written here.)

- [x] **Step 4 (fallback only — never triggered; v3.6.1 built clean, pin recorded):** if v3.6.1 later fails to compile on this macOS 26 host (Task 0.3), retry one minor back (v3.5.x latest patch, then v3.4.x), each time re-reading that tag's `fastdds.repos`. Record the pin actually used.

### Task 0.3: CMake-build the toolchain into one prefix

**Files:** populates `$FASTDDS_PREFIX`

- [x] **Step 1: Build in dependency order**

```bash
export FASTDDS_PREFIX="$HOME/gbt Dropbox/gbt/projects/fastdds/install"
cd "$HOME/gbt Dropbox/gbt/projects/fastdds/src"
for d in foonathan_memory_vendor fastcdr fastdds; do
  cmake -S "$d" -B "$d/build" -DCMAKE_INSTALL_PREFIX="$FASTDDS_PREFIX" \
        -DCMAKE_BUILD_TYPE=Release -DCMAKE_PREFIX_PATH="$FASTDDS_PREFIX;/opt/homebrew/opt/openssl@3" \
        -DBUILD_SHARED_LIBS=ON
  cmake --build "$d/build" -j 8 --target install
done
```

- [x] **Step 2: Verify**

```bash
ls "$FASTDDS_PREFIX/lib" | grep -E 'fastdds|fastcdr'
```

Expected: `libfastcdr.dylib`, `libfastdds.dylib` (plus versioned symlinks). If the fastdds configure step reports a missing dependency the docs page mentions, brew-install it and re-run; record any addition for provenance.

### Task 0.4: Build fastddsgen

**Files:** creates `"$HOME/gbt Dropbox/gbt/projects/fastdds/src/fastddsgen"`

- [x] **Step 1: Clone + gradle-build.** The Fast-DDS-Gen release matching Fast DDS 3.6.x is named in the same docs "versions/dependencies" table (<https://fast-dds.docs.eprosima.com/en/stable/notes/versions.html>) — read it, use that tag:

```bash
cd "$HOME/gbt Dropbox/gbt/projects/fastdds/src"
git clone --branch <matching-tag> --depth 1 https://github.com/eProsima/Fast-DDS-Gen.git fastddsgen
cd fastddsgen && ./gradlew assemble
```

- [x] **Step 2: Verify**

```bash
./scripts/fastddsgen -version
```

Expected: the pinned version string. Record repo/tag/commit for provenance.

### Task 0.5: Env helper + provenance + first commit

**Files:**
- Create: `$REPO/scripts/with-fastdds.sh`
- Modify: `$REPO/docs/provenance.md`

- [x] **Step 1: Write `scripts/with-fastdds.sh`** (modeled on `scripts/with-clasp.sh`):

```bash
#!/usr/bin/env bash
# FR-IO-2 Fast DDS toolchain env: pins the pinned-source install prefix and the
# dylib path, then execs the given command (default: a shell). See
# interop/fastdds/README.md for the pin and docs/provenance.md for provenance.
set -euo pipefail

FASTDDS_PREFIX="${FASTDDS_PREFIX:-$HOME/gbt Dropbox/gbt/projects/fastdds/install}"
FASTDDSGEN="${FASTDDSGEN:-$HOME/gbt Dropbox/gbt/projects/fastdds/src/fastddsgen/scripts/fastddsgen}"

if [[ ! -d "$FASTDDS_PREFIX/lib" ]]; then
  echo "with-fastdds: install prefix not found: $FASTDDS_PREFIX" >&2
  exit 127
fi

export FASTDDS_PREFIX FASTDDSGEN
export DYLD_LIBRARY_PATH="$FASTDDS_PREFIX/lib${DYLD_LIBRARY_PATH:+:$DYLD_LIBRARY_PATH}"
export PATH="/opt/homebrew/opt/openjdk/bin:$PATH"

exec "${@:-$SHELL}"
```

```bash
chmod +x "$REPO/scripts/with-fastdds.sh"
```

(macOS SIP strips `DYLD_LIBRARY_PATH` across protected binaries — the Connext harness hit this; if the harness apps fail to find the dylibs at Task 0.7, link them with `-Wl,-rpath,"$FASTDDS_PREFIX/lib"` — the harness Makefile in Task 0.6 already does — and the env var becomes belt-and-suspenders.)

- [x] **Step 2: Provenance entry** — append to `docs/provenance.md` a dated section: Fast DDS toolchain (test peer, NOT a code dependency, no SBOM entry): the three repos + fastddsgen with URLs, tags, commit hashes, Apache-2.0 license; the brew packages (openjdk, asio, tinyxml2, openssl@3); the clean-room note (read-only consultation of Fast DDS examples/headers for harness API usage; no code copied into `src/`); the docs pages consulted.

- [x] **Step 3: Commit (present message to owner first):**

```
chore(interop): pin + build the Fast DDS 3.6.1 toolchain (FR-IO-2 peer)

scripts/with-fastdds.sh pins the out-of-repo install prefix
(projects/fastdds sibling convention) + dylib path; docs/provenance.md
records repos/tags/commits/licenses (Apache-2.0; test peer, not a code
dependency - no SBOM entry) and the brew deps. Per the design spec
docs/superpowers/specs/2026-06-11-fastdds-peer-design.md S0.
```

### Task 0.6: `interop/fastdds/` harness skeleton

**Files:**
- Create: `$REPO/interop/fastdds/Makefile`
- Create: `$REPO/interop/fastdds/README.md`
- Create: `$REPO/interop/fastdds/shapes/Makefile`
- Create: `$REPO/interop/fastdds/shapes/ShapeType.idl`
- Create: `$REPO/interop/fastdds/shapes/shapes_pub.cpp`
- Create: `$REPO/interop/fastdds/shapes/shapes_sub.cpp`
- Create: `$REPO/interop/fastdds/shapes/profiles.xml`
- Create (generated): `$REPO/interop/fastdds/shapes/gen/` (fastddsgen output, committed)
- Modify: `$REPO/interop/connext/Makefile` — nothing; instead Modify: `$REPO/Makefile` (top level, add `fastdds-*` targets, Step 7)

- [x] **Step 1: The IDL** — `interop/fastdds/shapes/ShapeType.idl`. Bound-aligned with our model (unbounded string ⇒ bound 0; FINAL):

```idl
@final
struct ShapeType
{
    @key string color;
    long x;
    long y;
    long shapesize;
};
```

- [x] **Step 2: Generate type support**

```bash
cd "$REPO/interop/fastdds/shapes"
"$REPO/scripts/with-fastdds.sh" bash -c '"$FASTDDSGEN" -replace -d gen ShapeType.idl'
ls gen
```

Expected: `ShapeType.hpp`, `ShapeTypePubSubTypes.{cxx,hpp}`, `ShapeTypeTypeObjectSupport.{cxx,hpp}`, `ShapeTypeCdrAux.{hpp,ipp}` (names per fastddsgen 4.x; whatever it emits is committed verbatim).

- [x] **Step 3: `profiles.xml`** — UDPv4-only (no SHMEM — keep every byte capturable on lo0; the Connext same-host lesson), explicit TypeLookup client+server. **The `interfaceWhiteList` IP is per-machine — same convention as `interop/connext/`'s USER_QOS_PROFILES.xml (currently 192.168.2.148; EDIT per machine):**

```xml
<?xml version="1.0" encoding="UTF-8"?>
<!-- FR-IO-2 harness profile: UDPv4 only (observable on lo0/en*), TypeLookup
     client+server explicitly on. interfaceWhiteList: EDIT per machine. -->
<dds xmlns="http://www.eprosima.com/XMLSchemas/fastDDS_Profiles">
  <profiles>
    <transport_descriptors>
      <transport_descriptor>
        <transport_id>udp_only</transport_id>
        <type>UDPv4</type>
        <interfaceWhiteList>
          <address>192.168.2.148</address>
          <address>127.0.0.1</address>
        </interfaceWhiteList>
      </transport_descriptor>
    </transport_descriptors>
    <participant profile_name="fastdds_interop" is_default_profile="true">
      <rtps>
        <useBuiltinTransports>false</useBuiltinTransports>
        <userTransports>
          <transport_id>udp_only</transport_id>
        </userTransports>
        <builtin>
          <typelookup_config>
            <use_client>true</use_client>
            <use_server>true</use_server>
          </typelookup_config>
        </builtin>
      </rtps>
    </participant>
  </profiles>
</dds>
```

If the XSD rejects an element name (3.6 schema drift), reconcile against `$FASTDDS_PREFIX/share/fastdds/fastdds_profiles.xsd` and the pinned tree's `examples/` XMLs (reading allowed; note in provenance). The participant QoS knobs in C++ (Step 4) are the fallback if the XML path proves unreliable.

- [x] **Step 4: `shapes_pub.cpp`** — stock 3.x API (structure verified against the pinned tree's `examples/cpp/hello_world/`; reconcile any drift against the installed headers, never copy):

```cpp
// FR-IO-2 Fast DDS peer publisher: RELIABLE ShapeType on topic "Square".
// Usage: shapes_pub [color] [count]   (count 0 = forever)
#include <chrono>
#include <cstdlib>
#include <iostream>
#include <thread>

#include <fastdds/dds/domain/DomainParticipant.hpp>
#include <fastdds/dds/domain/DomainParticipantFactory.hpp>
#include <fastdds/dds/publisher/DataWriter.hpp>
#include <fastdds/dds/publisher/DataWriterListener.hpp>
#include <fastdds/dds/publisher/Publisher.hpp>
#include <fastdds/dds/topic/TypeSupport.hpp>

#include "gen/ShapeTypePubSubTypes.hpp"

using namespace eprosima::fastdds::dds;

class MatchListener : public DataWriterListener
{
public:
    void on_publication_matched(DataWriter*, const PublicationMatchedStatus& info) override
    {
        std::cout << "[shapes_pub] matched change: " << info.current_count_change
                  << " total: " << info.current_count << std::endl;
    }
};

int main(int argc, char** argv)
{
    const char* color = (argc > 1) ? argv[1] : "GREEN";
    const long count = (argc > 2) ? std::atol(argv[2]) : 0;

    auto* factory = DomainParticipantFactory::get_instance();
    factory->load_XML_profiles_file("profiles.xml");
    DomainParticipant* participant =
        factory->create_participant_with_default_profile(nullptr, StatusMask::none());
    if (participant == nullptr)
    {
        std::cerr << "[shapes_pub] participant creation failed" << std::endl;
        return 1;
    }

    TypeSupport type(new ShapeTypePubSubType());
    type.register_type(participant);

    Topic* topic = participant->create_topic("Square", type.get_type_name(), TOPIC_QOS_DEFAULT);
    Publisher* publisher = participant->create_publisher(PUBLISHER_QOS_DEFAULT, nullptr);

    DataWriterQos wqos = DATAWRITER_QOS_DEFAULT;
    wqos.reliability().kind = RELIABLE_RELIABILITY_QOS;
    MatchListener listener;
    DataWriter* writer = publisher->create_datawriter(topic, wqos, &listener, StatusMask::all());
    if (writer == nullptr)
    {
        std::cerr << "[shapes_pub] writer creation failed" << std::endl;
        return 1;
    }

    ShapeType sample;
    sample.color(color);
    sample.shapesize(30);
    long sent = 0;
    for (long i = 0; count == 0 || i < count; ++i)
    {
        sample.x(50 + (i % 100));
        sample.y(50 + ((i * 7) % 100));
        if (RETCODE_OK == writer->write(&sample))
        {
            ++sent;
            std::cout << "[shapes_pub] sent " << sent << " x=" << sample.x()
                      << " y=" << sample.y() << std::endl;
        }
        std::this_thread::sleep_for(std::chrono::milliseconds(100));
    }
    std::cout << "[shapes_pub] done, sent " << sent << std::endl;
    DomainParticipantFactory::get_instance()->delete_participant(participant);
    return 0;
}
```

- [x] **Step 5: `shapes_sub.cpp`** — same skeleton, reader side:

```cpp
// FR-IO-2 Fast DDS peer subscriber: RELIABLE ShapeType on topic "Square".
// Usage: shapes_sub [seconds]   (0 = forever)
#include <chrono>
#include <cstdlib>
#include <iostream>
#include <thread>

#include <fastdds/dds/domain/DomainParticipant.hpp>
#include <fastdds/dds/domain/DomainParticipantFactory.hpp>
#include <fastdds/dds/subscriber/DataReader.hpp>
#include <fastdds/dds/subscriber/DataReaderListener.hpp>
#include <fastdds/dds/subscriber/SampleInfo.hpp>
#include <fastdds/dds/subscriber/Subscriber.hpp>
#include <fastdds/dds/topic/TypeSupport.hpp>

#include "gen/ShapeTypePubSubTypes.hpp"

using namespace eprosima::fastdds::dds;

class ShapeListener : public DataReaderListener
{
public:
    long received = 0;

    void on_subscription_matched(DataReader*, const SubscriptionMatchedStatus& info) override
    {
        std::cout << "[shapes_sub] matched change: " << info.current_count_change
                  << " total: " << info.current_count << std::endl;
    }

    void on_data_available(DataReader* reader) override
    {
        ShapeType sample;
        SampleInfo info;
        while (RETCODE_OK == reader->take_next_sample(&sample, &info))
        {
            if (info.valid_data)
            {
                ++received;
                std::cout << "[shapes_sub] " << received << ": color=" << sample.color()
                          << " x=" << sample.x() << " y=" << sample.y()
                          << " size=" << sample.shapesize() << std::endl;
            }
        }
    }
};

int main(int argc, char** argv)
{
    const long seconds = (argc > 1) ? std::atol(argv[1]) : 0;

    auto* factory = DomainParticipantFactory::get_instance();
    factory->load_XML_profiles_file("profiles.xml");
    DomainParticipant* participant =
        factory->create_participant_with_default_profile(nullptr, StatusMask::none());
    if (participant == nullptr)
    {
        std::cerr << "[shapes_sub] participant creation failed" << std::endl;
        return 1;
    }

    TypeSupport type(new ShapeTypePubSubType());
    type.register_type(participant);

    Topic* topic = participant->create_topic("Square", type.get_type_name(), TOPIC_QOS_DEFAULT);
    Subscriber* subscriber = participant->create_subscriber(SUBSCRIBER_QOS_DEFAULT, nullptr);

    DataReaderQos rqos = DATAREADER_QOS_DEFAULT;
    rqos.reliability().kind = RELIABLE_RELIABILITY_QOS;
    ShapeListener listener;
    DataReader* reader = subscriber->create_datareader(topic, rqos, &listener, StatusMask::all());
    if (reader == nullptr)
    {
        std::cerr << "[shapes_sub] reader creation failed" << std::endl;
        return 1;
    }

    if (seconds == 0)
    {
        for (;;) std::this_thread::sleep_for(std::chrono::seconds(1));
    }
    std::this_thread::sleep_for(std::chrono::seconds(seconds));
    std::cout << "[shapes_sub] done, received " << listener.received << std::endl;
    DomainParticipantFactory::get_instance()->delete_participant(participant);
    return 0;
}
```

- [x] **Step 6: Harness Makefiles.** `interop/fastdds/shapes/Makefile`:

```make
# Fast DDS shapes harness. Needs FASTDDS_PREFIX (use scripts/with-fastdds.sh).
CXX      ?= clang++
CXXFLAGS ?= -std=c++17 -O2 -Wall
INC       = -I"$(FASTDDS_PREFIX)/include" -Igen
LIBS      = -L"$(FASTDDS_PREFIX)/lib" -lfastdds -lfastcdr \
            -Wl,-rpath,"$(FASTDDS_PREFIX)/lib"
GEN_SRCS  = $(wildcard gen/*.cxx)

all: shapes_pub shapes_sub

shapes_pub: shapes_pub.cpp $(GEN_SRCS)
	$(CXX) $(CXXFLAGS) $(INC) -o $@ $^ $(LIBS)

shapes_sub: shapes_sub.cpp $(GEN_SRCS)
	$(CXX) $(CXXFLAGS) $(INC) -o $@ $^ $(LIBS)

clean:
	rm -f shapes_pub shapes_sub
```

`interop/fastdds/Makefile` (mirrors `interop/connext/Makefile`):

```make
# Build every Fast DDS harness app (each lives in its own subdir).
# Requires FASTDDS_PREFIX (see README.md / scripts/with-fastdds.sh).

APPS := shapes

.PHONY: all clean $(APPS)

all: $(APPS)

$(APPS):
	$(MAKE) -C $@

clean:
	@for d in $(APPS); do $(MAKE) -C $$d clean; done
```

- [x] **Step 7: Build + top-level targets.** Build:

```bash
"$REPO/scripts/with-fastdds.sh" make -C "$REPO/interop/fastdds"
```

Expected: `shapes_pub` + `shapes_sub` binaries. Compile errors here mean 3.6 API drift from this plan's draft — reconcile against `$FASTDDS_PREFIX/include/fastdds/` headers and the pinned `examples/cpp/hello_world/` (read-only; provenance). Then add to `$REPO/Makefile` (next to the `square-*` targets, same style):

```make
# Fast DDS interop peers (interop/fastdds/README.md). FASTDDS_PREFIX via with-fastdds.sh.
fastdds-pub:
	./scripts/with-fastdds.sh bash -c 'cd interop/fastdds/shapes && ./shapes_pub $(COLOR) $(COUNT)'

fastdds-sub:
	./scripts/with-fastdds.sh bash -c 'cd interop/fastdds/shapes && ./shapes_sub $(SECONDS)'
```

(plus `fastdds-pub fastdds-sub` on the existing `.PHONY` line).

- [x] **Step 8: README.** `interop/fastdds/README.md`: the pin (versions + commit hashes), build commands, run commands (make targets + direct), the profiles.xml EDIT-per-machine note, the capture command from "Standing rules" — structure mirroring `interop/connext/README.md`.

### Task 0.7: Fast DDS ↔ Fast DDS smoke test (S0 exit gate)

- [x] **Step 1: Two terminals (or backgrounded), same host:**

```bash
make fastdds-sub SECONDS=15 &
sleep 2 && make fastdds-pub COLOR=GREEN COUNT=50
```

Expected: pub logs `matched change: 1`; sub logs `matched change: 1` then `color=GREEN ...` lines; on exit `received` ≥ 40.

- [x] **Step 2: Record the smoke-run output in `interop/fastdds/README.md`.**

- [x] **Step 3: Commit (present message to owner first):**

```
feat(interop): Fast DDS shapes harness skeleton (FR-IO-2 S0)

interop/fastdds/: canonical ShapeType.idl (unbounded @key string color +
3x long, @final - bound-aligned with our STRING8-bound-0 model) ->
fastddsgen type support (committed, provenance-noted) + thin RELIABLE
pub/sub mains + UDPv4-only profile (TypeLookup client+server explicit) +
Makefiles + README. Fast DDS<->Fast DDS lo0 smoke green. Top-level
fastdds-pub/fastdds-sub targets. Refs FR-IO-2.
```

---

## Stage S1 — discovery census

### Task 1.1: Capture + census both directions

**Files:**
- Modify: `$REPO/interop/fastdds/README.md` (census findings)
- Create: `$REPO/interop/fastdds/captures/s1-census-lo0.pcap` (+ `-en7` if multicast rides there)

- [x] **Step 1: Capture our stack + their pub.** Terminal A capture (`tshark -i lo0 ... -w interop/fastdds/captures/s1-census-lo0.pcap`); Terminal B `make square-sub TYPE=canonical DOMAIN=0 ADVERTISE=127.0.0.1`; Terminal C `make fastdds-pub COUNT=100`. Run ~30 s. If no SPDP meets, capture en7 too and check whether Fast DDS multicasts only on the whitelisted iface — adjust `profiles.xml` whitelist (127.0.0.1 first) until both sides see each other's SPDP.

- [x] **Step 2: Census from the pcap** (tshark `-O RTPS` / `-T fields`). Record in the README, each with frame numbers:
  - their VendorId;
  - `PID_TYPE_INFORMATION` (0x0075) present in their SEDP? (expected yes — this is the S3 input);
  - their `PID_BUILTIN_ENDPOINT_SET` TypeLookup bits (Table 62 bits 12–15);
  - TypeLookup endpoints announced/used; any immediate `TypeLookup_Request` toward us, and its `instanceName` string verbatim (the §7.6.3.3.4 self-contradiction — this is a CONFIRM-VS-PEER item, settle it here if traffic appears);
  - whether OUR SEDP/SPDP parse of their announcements is clean: run `make square-sub` with a fresh eye on warnings/errors; any unknown-PID skip is fine, any parse error is a bug.
- [x] **Step 3: Reverse: their sub + our pub.** `make fastdds-sub SECONDS=30` + `make square-pub TYPE=canonical COLOR=BLUE`; census what they make of OUR announcements (does their participant complain? does a match attempt appear in their `matched change:` log even if data fails?).
- [x] **Step 4: Bug protocol.** Any parse failure in our stack = a real FR-IO-2 bug: extract the offending bytes from the pcap into a locked vector, write the failing test in `dds-tests` FIRST, fix bounds-checked + clause-cited, suite green, separate commit (message presented). Mirror the M2 6-bug-chain discipline.
- [x] **Step 5: Commit census (present message to owner first):**

```
docs(interop): Fast DDS discovery census (FR-IO-2 S1)

SPDP/SEDP both directions vs Fast DDS 3.6.1: vendor id, 0x0075
TypeInformation presence/framing, Table-62 TypeLookup bits, instanceName
observed on the wire; captures archived under interop/fastdds/captures/.
[+ note any parse fixes landed as separate commits]
```

(Stage boundary: run the Clasp suite once — `GC_DONT_GC=1 scripts/with-clasp.sh ...` per `make test-clasp` convention.)

---

## Stage S2 — data plane (FR-IO-2 DoD)

### Task 2.1: Forward leg — Fast DDS pub → our sub

- [x] **Step 1:** Capture running; `make square-sub TYPE=canonical` + `make fastdds-pub COUNT=100`. Expected: our sub prints ≥ 90 `color=GREEN` shapes; their pub logs `matched change: 1`.
- [x] **Step 2:** tshark-validate the data path (DATA submessages decode as ShapeType, HEARTBEAT/ACKNACK flowing — reliable, not best-effort fallback).
- [x] **Step 3:** On failure, debug from the wire per the M2 lesson: suspect RTPS plumbing (SEDP defaults/QoS-RxO, EntityId kinds, inline QoS, ACKNACK routing) before type matters; every fix = failing-test-first separate commit.

### Task 2.2: Reverse leg — our pub → Fast DDS sub

- [x] **Step 1:** `make fastdds-sub SECONDS=30` + `make square-pub TYPE=canonical COLOR=BLUE`. Expected: their sub prints `color=BLUE` lines, count ≥ ~25 (30 s at our publisher rate), clean reliable session in the pcap (they ACKNACK our writer).
- [x] **Step 2:** Same wire-first debug protocol on failure.

### Task 2.3: Archive + commit (S2 exit gate = FR-IO-2 DoD)

- [x] **Step 1:** Archive both pcaps under `interop/fastdds/captures/` (`s2-forward-lo0.pcap`, `s2-reverse-lo0.pcap`); paste run logs + counts into the README.
- [x] **Step 2:** Clasp suite at the stage boundary.
- [x] **Step 3: Commit (present message to owner first):**

```
feat(interop): bidirectional reliable ShapeType exchange with Fast DDS
3.6.1 - FR-IO-2 DoD met (S2)

Forward fastdds shapes_pub -> our square-sub (N/100 samples) + reverse
our square-pub -> fastdds shapes_sub (M samples), RELIABLE, tshark-
validated; captures + logs in interop/fastdds/. Refs FR-IO-2.
[+ reference any fix commits in the chain]
```

---

## Stage S3 — EquivalenceHash oracle

### Task 3.1: Extract theirs, compute ours, compare

**Files:**
- Modify: `$REPO/interop/fastdds/README.md`

- [x] **Step 1: Their hash.** From the S1/S2 SEDP capture, extract the EK_MINIMAL EquivalenceHash inside their `PID_TYPE_INFORMATION` for ShapeType (tshark RTPS tree, or our own parser: `dds.types:deserialize-type-information-hash` over the raw 0x0075 value pulled from the pcap — the corpus-capture harness `run-corpus-capture-subscriber` already snapshots SEDP parameters and can be reused with `:topic "Square" :type "ShapeType"`).
- [x] **Step 2: Our hash.**

```bash
cd "$REPO" && sbcl --non-interactive \
  --eval '(asdf:load-system :dds-shapes)' \
  --eval '(format t "~{~2,(quote 0)x~^ ~}~%" (coerce (dds.types:equivalence-hash (dds.types:type-support-typeobject (dds.types:find-type-support "ShapeType"))) (quote list)))'
```

(Adjust the accessor chain to the actual exported API — `equivalence-hash` is `src/dds-types/typeobject-cdr.lisp:207`; the type-support registry lookup is whatever `find-type-support-by-hash`'s index uses, `src/dds-types/typelookup.lisp:706` shows `(equivalence-hash to)` over registry entries. If a one-liner is awkward, add a tiny exported helper `dds.types:registered-equivalence-hash (name)` — defun*, docstring, test — as part of this task.)
- [x] **Step 3: Compare.** 14 octets, byte-for-byte.
  - **Equal:** record both hex strings + the pcap frame in the README and `docs/provenance.md`. This is the external confirmation ADR 0009 declared unobtainable from Connext.
  - **Unequal:** a real bug in our serializer or in the bound alignment. Diff structurally first: dump their TypeObject via a `getTypes` query (S4 machinery, or tshark's decode of their TL reply if traffic exists), compare member-by-member against ours (`serialize-type-object` bytes). Fix clause-first in `src/dds-types/typeobject-cdr.lisp` (§7.3.4.9.1 hash, §7.4.3.5.3 VM), failing-byte-vector test FIRST, then re-run the comparison. If the difference is the *type* (e.g. fastddsgen bounds the string after all), fix the IDL/model alignment instead and re-run — the design constraint is both sides hash the same nominal type.

### Task 3.2: Verification + commit

- [x] **Step 1:** `docs/verification.csv`: FR-TYPE-2/3 cells — remove PROVISIONAL for the exercised path (FINAL struct + i32 + unbounded string8), state "EquivalenceHash externally confirmed vs Fast DDS 3.6.1 <date>, frame N"; unexercised edges (unions, MUTABLE, TK_NONE base, nested deps) keep their caveats.
- [x] **Step 2:** Wiki lockstep: `docs/wiki/type-system.md` hash section gains the confirmation note; `README.md` status line if it mentions PROVISIONAL.
- [x] **Step 3: Commit (present message to owner first):**

```
feat(types): minimal EquivalenceHash externally confirmed vs Fast DDS
3.6.1 (S3)

Their SEDP PID_TYPE_INFORMATION EK_MINIMAL hash for the bound-aligned
ShapeType equals ours byte-for-byte [or: chain of serializer fixes, each
clause-cited]. verification.csv FR-TYPE-2/3 PROVISIONAL caveat narrowed
to the unexercised VM edges. Refs FR-TYPE-2/3, ADR 0009/0010.
```

---

## Stage S4 — TypeLookup live, both directions

### Task 4.1: Our client → their server (probe entry point)

**Files:**
- Modify: `$REPO/src/dds-shapes/shapes.lisp` (new `run-typelookup-probe`)
- Modify: `$REPO/src/dds-shapes/packages.lisp` (export)
- Modify: `$REPO/Makefile` (target `fastdds-tl-probe`)
- Modify: `$REPO/docs/wiki/` interop/shapes page + `README.md` (docs lockstep)

- [x] **Step 1: Write `run-typelookup-probe`** (harness entry, same style/no-unit-test precedent as `run-subscriber`; the underlying `type-lookup-query` machinery is already covered offline by `typelookup-endpoints`):

```lisp
(defun* run-typelookup-probe (&key (domain 0) (seconds 15) (advertise-address "127.0.0.1"))
    (function (&key (:domain (integer 0)) (:seconds (integer 1)) (:advertise-address string)) t)
  "FR-IO-2 S4 probe: discover one remote participant on DOMAIN, take the
   EquivalenceHash from its SEDP PID_TYPE_INFORMATION (0x0075), issue a
   TypeLookup getTypes toward it (XTypes 1.3 §7.6.3.3), and report whether the
   returned TypeObject parses (parse-minimal-type-object) and re-hashes
   (equivalence-hash) to the queried hash. Prints PASS/FAIL lines; returns T on
   PASS. SECONDS bounds discovery + reply wait."
  ...)
```

Body sketch (the executor writes it against the existing APIs — all already exported/used by `run-gated-subscriber` and the `typelookup-endpoints` test): make a disc-node with multicast + `advertise-address` (mirror `run-subscriber`'s node setup), `spin` until a remote endpoint on topic "Square" carries `type-information`, `deserialize-type-information-hash` it, `dds.disc:type-lookup-query` toward the remote prefix with a continuation that `parse-minimal-type-object`s the returned octets and compares `equivalence-hash` of the parse against the queried hash, wait (condvar or sleep-poll) up to SECONDS, print and return the verdict. Full type declarations; bounds already inside the called codecs.
- [x] **Step 2:** Makefile target:

```make
fastdds-tl-probe:
	$(SBCL) --eval '(asdf:load-system :dds-shapes)' \
	        --eval '(uiop:symbol-call :dds.shapes :run-typelookup-probe :domain $(DOMAIN) :seconds $(SECONDS) :advertise-address "$(ADVERTISE)")' \
	        --eval '(uiop:quit 0)'
```

- [x] **Step 3:** Suite green on SBCL (no new offline test, but nothing may break); docstring/wiki/README lockstep for the new exported symbol.

### Task 4.2: Live leg A — our getTypes against their server

- [x] **Step 1:** Capture running; `make fastdds-pub COUNT=1000` + `make fastdds-tl-probe SECONDS=20`. Expected: probe prints PASS (reply parsed; re-hash equal); pcap shows our `TypeLookup_Request` and their reply on the Table-61 endpoints.
- [x] **Step 2:** Archive `s4-ourclient-lo0.pcap`; README log.
- [x] **Step 3:** On FAIL: tshark-decode both frames; clause-first protocol (Standing rule 6); each fix = failing vector test first, separate commit.

### Task 4.3: Live leg B — their client consumes our service

**Files:**
- Create: `$REPO/interop/fastdds/type_probe/Makefile`
- Create: `$REPO/interop/fastdds/type_probe/type_probe.cpp`
- Modify: `$REPO/interop/fastdds/Makefile` (add `type_probe` to APPS), `$REPO/Makefile` (target `fastdds-type-probe`)

- [x] **Step 1: `type_probe.cpp`** — a *type-blind* Fast DDS app (does NOT link the generated ShapeType): DomainParticipant with the same profile, a `DomainParticipantListener` whose `on_data_writer_discovery` pulls the remote `type_information` from the discovered builtin data, asks the `ITypeObjectRegistry` for the TypeObject (this is what makes THEIR TypeLookup client send getTypes to OUR server), builds the type via `DynamicTypeBuilderFactory::create_type_w_type_object(...)`, registers it, creates a RELIABLE DataReader on "Square", and logs received samples generically via `DynamicData`. Exact 3.6 API per the docs use-case "Remote type discovery and endpoint matching" and the pinned tree's XTypes examples (read-only; provenance). Draft skeleton to reconcile:

```cpp
// FR-IO-2 S4 leg B: type-blind Fast DDS probe - learns ShapeType from OUR
// participant via ITS TypeLookup client against OUR TypeLookup server, then
// subscribes and prints samples. No generated ShapeType code linked.
// Usage: type_probe [seconds]
#include <iostream>

#include <fastdds/dds/domain/DomainParticipant.hpp>
#include <fastdds/dds/domain/DomainParticipantFactory.hpp>
#include <fastdds/dds/domain/DomainParticipantListener.hpp>
#include <fastdds/dds/subscriber/DataReader.hpp>
#include <fastdds/dds/subscriber/DataReaderListener.hpp>
#include <fastdds/dds/xtypes/dynamic_types/DynamicData.hpp>
#include <fastdds/dds/xtypes/dynamic_types/DynamicTypeBuilderFactory.hpp>
#include <fastdds/dds/xtypes/utils.hpp>

using namespace eprosima::fastdds::dds;

// on_data_writer_discovery: if info.type_information is valid, resolve the
// TypeObject via DomainParticipantFactory::get_instance()->type_object_registry()
// .get_type_object(...) (triggers the TypeLookup client toward the remote server),
// then DynamicTypeBuilderFactory::get_instance()->create_type_w_type_object(to)
// ->build(), wrap in DynamicPubSubType, register, signal main to create the
// reader. Main: reader with RELIABLE QoS on "Square"; on_data_available prints
// the DynamicData JSON (json_serialize). Reconcile exact signatures against the
// pinned 3.6 headers + docs use-case before compiling.
```

- [x] **Step 2:** Build via the harness Makefile pattern (same INC/LIBS as `shapes/Makefile`); add the `fastdds-type-probe` top-level target (same `with-fastdds.sh` style, arg `SECONDS`).
- [x] **Step 3: Live run:** capture; `make square-pub TYPE=canonical COLOR=RED` + `make fastdds-type-probe SECONDS=30`. Expected: pcap shows THEIR `TypeLookup_Request` (getTypes) hitting OUR request reader and OUR reply; their probe then matches and prints RED samples — proof they consumed our reply end-to-end.
- [x] **Step 4:** Archive `s4-theirclient-lo0.pcap`; README log. On failure where their request arrives but our reply never satisfies them: tshark field-diff our reply vs their leg-A reply; clause-first protocol per divergence.

### Task 4.4: CONFIRM-VS-PEER walk + vector re-pins + commit (S4 exit gate)

**Files:**
- Modify: `$REPO/interop/fastdds/README.md` (the walk table)
- Possibly modify: `$REPO/src/dds-types/typelookup.lisp` + the `typelookup-vectors`/`typelookup-request`/`typelookup-reply` tests (re-pins)
- Modify: `$REPO/docs/provenance.md`

- [x] **Step 1:** From the leg-A/leg-B pcaps build the walk table — for each CONFIRM-VS-PEER item, our reading vs their bytes vs the clause:
  1. `instanceName` exact string + length (§7.6.3.3.4's self-contradiction);
  2. ReplyHeader `remoteEx` placement (reply-only, our ADR'd reading of the §7.6.3.3.3 IDL defect);
  3. mutable-member EMHEADER1 LC=5 / NEXTINT-doubles-as-length (rule 22);
  4. non-OK reply omits the Return arm entirely;
  5. top-level @final ⇒ CDR2_LE 0x0007 encapsulation (no top-level DHEADER);
  6. union DHEADERs on Call/Return/Result.
- [x] **Step 2:** Where their bytes differ AND the clause sides with them: failing vector test first, fix codec, re-pin `typelookup-vectors`, suite green. Where they deviate from the clause: provenance note + receive-tolerance check (our parser must already accept it — if not, that's a fix with its own test).
- [x] **Step 3:** Clasp suite at the stage boundary.
- [x] **Step 4: Commit (present message to owner first):**

```
feat(disc/types): TypeLookup service live-confirmed vs Fast DDS 3.6.1
both directions (S4, closes the ADR 0010 deferred leg)

Leg A: run-typelookup-probe getTypes -> their server; reply parses +
re-hashes to the queried EquivalenceHash. Leg B: their type-blind
type_probe learns ShapeType from OUR TypeLookup server and receives our
samples. CONFIRM-VS-PEER walk table in interop/fastdds/README.md
[+ list re-pins or "zero divergences"]. Captures archived. Refs
FR-TYPE-3, FR-IO-2.
```

---

## Stage S5 — closeout

### Task 5.1: Docs, ADR, verification, memory

**Files:**
- Modify: `$REPO/docs/verification.csv` (FR-IO-2 → pass with the S2 evidence; FR-TYPE-3 TypeLookup live leg done)
- Create: `$REPO/docs/adr/0012-fastdds-peer-fr-io-2.md`
- Modify: `$REPO/docs/wiki/` (interop page: Fast DDS section with run commands; type-system page already touched in S3)
- Modify: `$REPO/README.md` (status: FR-IO-2 met, second vendor)
- Modify: `$REPO/docs/provenance.md` (final pins, consultations)

- [x] **Step 1:** ADR 0012: status accepted; context (ADR 0010 deferred the live leg; FR-IO-2 open), decision (Fast DDS 3.6.1 native peer), results (S2 counts, S3 hash verdict, S4 walk outcomes incl. any re-pins), consequences (TypeLookup vectors now peer-confirmed; remaining unexercised VM edges listed; Cyclone/OpenDDS still optional).
- [x] **Step 2:** verification.csv + wiki + README updated in lockstep; `make build test gate-hotpath gate-types wire` all green on SBCL; Clasp suite once more.
- [ ] **Step 3 (pending owner approval of the message): Commit (present message to owner first):**

```
docs: FR-IO-2 closeout - Fast DDS 3.6.1 peer (ADR 0012)

verification.csv: FR-IO-2 pass (bidirectional reliable shapes, S2);
FR-TYPE-3 TypeLookup live legs done (S4); FR-TYPE-2/3 hash confirmed
(S3). ADR 0012 records the feature; wiki interop page + README status
updated; provenance final pins.
```

- [ ] **Step 4 (pending):** Push after owner approval of the whole feature; verify the Publish Wiki action goes green.
- [ ] **Step 5 (pending):** Update the `dds-stack-position` memory file: feature complete, new HEAD, next candidates (legacy-parser aggregate gaps; Clasp re-baseline; keyed/no-key endpoint kinds; Cyclone/OpenDDS optional third vendor).

---

## Self-review notes (run, fixed inline)

- **Spec coverage:** S0–S5 all mapped (spec §5 ↔ Tasks 0.x–5.1); spec §4 risks each have a home (build fallback Task 0.2 Step 4; knobs in profiles.xml; SHMEM excluded; hash-mismatch protocol Task 3.1; framing protocol Standing rule 6 + Task 4.4; SPDP/SEDP bug protocol Task 1.1 Step 4).
- **Deliberate execution-time reads (not placeholders):** dependency tags from `fastdds.repos` (Task 0.2), the fastddsgen tag from the versions table (Task 0.4), 3.6 API reconciliation against pinned headers/examples (Tasks 0.6/4.3), the exact registry-lookup accessor for the hash one-liner (Task 3.1 Step 2, with the named fallback helper). Each names its authoritative source.
- **Type consistency:** `run-typelookup-probe` signature consistent between Task 4.1 and the Makefile target; `equivalence-hash`/`parse-minimal-type-object`/`type-lookup-query`/`deserialize-type-information-hash` all verified to exist at the cited files; topic/type names "Square"/"ShapeType" consistent throughout.
