# XTypes TypeLookup Service Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Bidirectional XTypes 1.3 built-in TypeLookup service (§7.6.3.3) — we serve our types' TypeObjects to peers and retrieve peers' TypeObjects, feeding assignability-gated endpoint matching — live against RTI Connext 7.3.1.

**Architecture:** Probe-first, six stages (commit per task, `main` green throughout). Stage 0 announces the service bits and captures Connext's reaction (STOP-gate). Stage 1 adds the service-type codecs, Stage 2 the MinimalTypeObject deserializer, Stage 3 the four builtin endpoints + server/client engine, Stage 4 the match gating, Stage 5 the live bidirectional Connext gate.

**Tech Stack:** Common Lisp (SBCL + Clasp), the in-repo XCDR2/RTPS/discovery stack, tshark RTPS dissector, RTI Connext 7.3.1.

**Spec:** `docs/superpowers/specs/2026-06-10-typelookup-service-design.md`.

## Non-negotiable rules for every task (the operating contract)

- **`defun*`/`defstruct*` for everything** (`dds.lang`), every parameter typed, full ftype.
- **Never write a wire constant/field order/octet layout from memory.** Open the cited clause in `docs/specs/xtypes-1_3.pdf` (pdftotext) / `xtypes-1_3_typeobject.idl` / `rtps-2_5.pdf` first; cite it in a one-line comment. Where the spec is ambiguous (instance-name length, union extensibility defaults, encapsulation id), the Stage-0/Stage-5 capture decides; mark such choices `CONFIRM-VS-CAPTURE` in a comment until locked.
- **Bounds-check every parser** against the payload extent before trusting wire data, even at `(safety 0)`.
- **Comments one line max**; rationale goes in commit messages. No AI attribution anywhere.
- **After each task:** `make gate-types && make gate-hotpath` + the relevant tests green on **SBCL and Clasp** (`./scripts/with-sbcl.sh` / `./scripts/with-clasp.sh`; Clasp is not on PATH; one re-run allowed on the known condvar flake). Present the commit message for owner approval before committing (no Co-Authored-By).
- **Suite baseline:** 71 tests green at plan time; each task states its expected new count.
- Run Lisp tests: `./scripts/with-sbcl.sh --eval '(ql:quickload :dds-tests :silent t)' --eval '(dds.tests:run-all-tests)' --eval '(uiop:quit 0)'`.
- Connext env (three separate exports): `export NDDSHOME=/Applications/rti_connext_dds-7.3.1` then `export CONNEXTDDS_ARCH=arm64Darwin20clang12.0` then `export DYLD_LIBRARY_PATH=$NDDSHOME/lib/$CONNEXTDDS_ARCH`. Capture without sudo: `tcpdump -i lo0 -w f.pcap udp &`. Decode: `tshark -r f.pcap --enable-protocol null --enable-protocol ip --enable-protocol udp -V` (lo0 = null link; this host's Wireshark profile disables core dissectors). Same-host unicast rides lo0; multicast SPDP rides the LAN iface (capture `en7` too when discovery is in question).

## File structure

| File | Responsibility | Stage |
|---|---|---|
| `src/dds-rtps/discovery.lisp` (modify) | TypeLookup `availableBuiltinEndpoints` bit constants; announce mask | 0 |
| `src/dds-types/typelookup.lisp` (create) | TypeLookup_Request/Reply codecs + hash→type-support index + pure server core | 1,3 |
| `src/dds-types/typeobject-cdr.lisp` (modify) | `parse-minimal-type-object` (deserializer) | 2 |
| `src/dds-types/packages.lisp` (modify) | exports per stage | 1,2,3 |
| `src/dds-disc/typelookup-endpoints.lisp` (create) | the four builtin endpoints: dispatch handlers, send paths, pending table, timeout sweep | 3 |
| `src/dds-disc/disc.lisp` (modify) | dispatch branches; `type-gate` hook + parked matches; announce-loop sweep call | 3,4 |
| `src/dds-disc/packages.lisp`, `dds-disc.asd` (modify) | new file + exports | 3 |
| `src/dds-dcps/entities.lisp` (modify) | install the type-gate (assignability + TYPE_CONSISTENCY_ENFORCEMENT + INCONSISTENT_TOPIC) | 4 |
| `src/dds-tests/{xtypes,integration,rtps}-test.lisp`, `echo-test.lisp`, `pbt-test.lisp` (modify) | tests + fuzz + registrations | 1–5 |
| `docs/wiki/{xtypes,discovery}.md`, `README.md`, `docs/verification.csv`, `docs/MILESTONES.md` (modify) | docs lockstep (§5.1) | each |
| `interop/connext/README.md` (modify) | probe + interop findings | 0,5 |

---

## STAGE 0 — Live probe (STOP-gate)

### Task 0.1: Announce the TypeLookup endpoint bits + probe Connext

**Files:** Modify `src/dds-rtps/discovery.lisp` (constants ~line 11 region, announce values at :262/:286), `src/dds-disc/disc.lisp:146`; findings to `interop/connext/README.md` + `docs/verification.csv`.

**Clause to pin first:** XTypes 1.3 **Table 62** (§7.6.3.3.4): request writer `1<<12`, request reader `1<<13`, reply writer `1<<14`, reply reader `1<<15`. RTPS 2.5 Table 9.4 for the existing bits (the current `#x0000043F`).

- [ ] **Step 1:** In `src/dds-rtps/discovery.lisp`, after the existing EntityId constants, add (values from Table 62, cite it):

```lisp
;;; XTypes 1.3 Table 62: TypeLookup service bits in availableBuiltinEndpoints.
(defconstant +be-tl-request-writer+ (ash 1 12))
(defconstant +be-tl-request-reader+ (ash 1 13))
(defconstant +be-tl-reply-writer+ (ash 1 14))
(defconstant +be-tl-reply-reader+ (ash 1 15))
(defconstant +builtin-endpoint-set-default+
  (logior #x0000043F +be-tl-request-writer+ +be-tl-request-reader+
          +be-tl-reply-writer+ +be-tl-reply-reader+))
```

with a docstring on `+builtin-endpoint-set-default+` (it is API-visible) citing RTPS 2.5 Table 9.4 + XTypes Table 62. Export the five constants from `dds.rtps.discovery`.

- [ ] **Step 2:** Replace the literal `#x0000043F` at `src/dds-disc/disc.lisp:146` (in `%node-spdp-data`) and in `src/dds-rtps/discovery.lisp:262` + the `:286` self-test assertion with `+builtin-endpoint-set-default+`.
- [ ] **Step 3:** Suite (71 expected green, SBCL + Clasp), gates.
- [ ] **Step 4: Probe run.** From `interop/connext/shapes-sub/`: start capture on lo0 AND en7 (`tcpdump -i en7 -w /tmp/tl-probe-en7.pcap udp &`), run `CONNEXT_VERBOSE=1 ./shapes_sub 0` against our `make square-pub` for ~30 s, stop. Repeat with `shapes_pub` vs our `make square-sub`. Inspect:
  - `tshark ... -Y "rtps.param.id == 0x0075"` — does Connext's SEDP now carry PID_TYPE_INFORMATION? If yes, extract its TypeInformation octets and compare the minimal hash against `(dds.types:equivalence-hash (dds.types:type-support-typeobject (dds.types:find-type-support "ShapeType")))` — the ADR 0009 oracle reopening; record match/mismatch (a mismatch is Stage-5 work to fix the serializer, do NOT fix here).
  - `tshark ... -Y "rtps.sm.wrEntityId == 0x000300c3 || rtps.sm.rdEntityId == 0x000300c4 || rtps.sm.wrEntityId == 0x000301c3"` — any TypeLookup traffic from Connext (requests toward us, HEARTBEATs from its reply writer, ACKNACKs)?
  - Save any pcap containing TypeLookup submessages or 0x0075 as `interop/connext/tl-probe-<n>.pcap` (git-ignored; extend `.gitignore` if the pattern is not covered).
- [ ] **Step 5: STOP-gate.** If NO TypeLookup-related reaction at all (no 0x0075, no requests, no TL endpoint announcements from Connext — also check Connext's own SPDP `availableBuiltinEndpoints` for bits 12–15): STOP, write the findings to `interop/connext/README.md`, and report to the owner that the Connext-only DoD needs a decision. Otherwise record findings (which directions Connext exercises, the exact request bytes if any, its instanceName string, encapsulation id) and continue.
- [ ] **Step 6:** Update `interop/connext/README.md` (probe findings section) + `docs/verification.csv` FR-TYPE-3 row (probe done, findings). Gates; commit — `feat(disc): announce TypeLookup builtin endpoints (XTypes 1.3 Table 62) + Connext probe findings`.

---

## STAGE 1 — Service-type codecs (`src/dds-types/typelookup.lisp`, package `dds.types`)

> Before starting: read `src/dds-types/typeobject-cdr.lisp` in full — reuse its idioms (`%dheader-begin`/`%dheader-end`, `dds.cdr:cdr-align`/`cdr-put-u32`/`emheader1-encode`/`emheader1-decode`, XCDR2-LE cursors over `dds.core.buffer`). Read the Stage-0 capture findings; where they pin a framing choice, follow the wire and cite both.

**Clauses to pin first:** XTypes 1.3 §7.6.3.3.2/.3 (type definitions: `SampleIdentity` = GUID (16 octets) + SequenceNumber (high i32 + low u32); `RequestHeader` = SampleIdentity + `string<255> instanceName`; `ReplyHeader` = SampleIdentity + `RemoteExceptionCode_t` enum i32; the two MUTABLE in/out structs; the two `switch(long)` unions with discriminators `0x018252d3`/`0x05aafb31`); §7.6.3.3.4 instance name; the XCDR2 encapsulation-identifier table (§7.6.2.1.2) for the top-level SerializedPayload header (`CONFIRM-VS-CAPTURE`: spec default for the unannotated `@RPCRequestType` structs is APPENDABLE ⇒ D_CDR2; Connext's actual choice wins).

### Task 1.1: Request codec (`serialize-type-lookup-request` / `parse-type-lookup-request`)

**Files:** Create `src/dds-types/typelookup.lisp` (+ add to `dds-types.asd` after `typeobject-cdr`); modify `src/dds-types/packages.lisp`; test in `src/dds-tests/xtypes-test.lisp`.

- [ ] **Step 1: Failing round-trip test** (register as `("typelookup-request" . run-typelookup-request-test)` in `echo-test.lisp`):

```lisp
(defun* run-typelookup-request-test ()
    (function () t)
  "Test: TypeLookup_Request getTypes serialize/parse round-trip (XTypes 1.3 §7.6.3.3)."
  (let* ((guid (make-array 16 :element-type '(unsigned-byte 8) :initial-element 7))
         (h1 (make-array 14 :element-type '(unsigned-byte 8) :initial-element #xAA))
         (octets (dds.types:serialize-type-lookup-request
                  :writer-guid guid :sn 5 :instance-name "dds.builtin.TOS.x"
                  :operation :get-types :type-ids (list h1))))
    (multiple-value-bind (op ids wguid sn iname)
        (dds.types:parse-type-lookup-request octets)
      (%check :tlreq-op (eq op :get-types) "operation discriminator round-trips")
      (%check :tlreq-ids (and (= 1 (length ids)) (equalp (first ids) h1)) "type_ids round-trip")
      (%check :tlreq-hdr (and (equalp wguid guid) (= sn 5) (string= iname "dds.builtin.TOS.x"))
              "RequestHeader round-trips"))
    (%check :tlreq-short (null (dds.types:parse-type-lookup-request
                                (subseq octets 0 7)))
            "truncated request rejects (NIL)"))
  t)
```

- [ ] **Step 2: Run — expected FAIL** (function undefined).
- [ ] **Step 3: Implement.** Layout (outermost first; every level bounds-checked; framing comments cite the clause + `CONFIRM-VS-CAPTURE` where applicable):
  - 4-octet encapsulation header (id from §7.6.2.1.2 table per the APPENDABLE default, LE; options 0) — then XCDR2 alignment origin per FR-CDR-3.
  - `TypeLookup_Request` (APPENDABLE ⇒ DHEADER): `RequestHeader` = 16-octet GUID + SN (i32 high, u32 low) + string (u32 len + octets + NUL); then `TypeLookup_Call` union = i32 discriminator (`+tl-gettypes-hash+ #x018252d3` / `+tl-getdeps-hash+ #x05aafb31`, cite §7.6.3.3.3) + arm.
  - `TypeLookup_getTypes_In` (MUTABLE ⇒ DHEADER + EMHEADER members, mirror `serialize-type-information`'s member framing): member id 1 (`@hashid` of `type_ids` — compute per the @hashid rule §7.3.1.2.1.1 at implementation time from the IDL member name, cite the computed value) = `sequence<TypeIdentifier>`: DHEADER (non-primitive seq, rule 12) + u32 count + each TypeIdentifier (reuse the framing of `%put-type-identifier`: for v1 requests the ids are EK_MINIMAL disc + 14-octet hash).
  - `getTypeDependencies_In` adds member `continuation_point` (`sequence<octet,32>`: u32 count + octets); parse accepts it, serialize emits empty.
  - Parse returns `(values operation-keyword id-list writer-guid sn instance-name continuation)` or NIL on any bounds/shape violation; unknown union discriminator → `(values :unknown ...)`; unknown MUTABLE members skipped via EMHEADER length (must-understand-clear only; a set M_FLAG on an unknown member → NIL, cite §7.2.2.4.4.4).
- [ ] **Step 4:** Export `#:serialize-type-lookup-request #:parse-type-lookup-request` + the two operation-id constants. Run SBCL + Clasp (72 expected).
- [ ] **Step 5:** Gates; commit — `feat(types): TypeLookup_Request XCDR2 codec (XTypes 1.3 §7.6.3.3)`.

### Task 1.2: Reply codec (`serialize-type-lookup-reply` / `parse-type-lookup-reply`)

**Files:** Modify `src/dds-types/typelookup.lisp`, `packages.lisp`; test in `xtypes-test.lisp`.

- [ ] **Step 1: Failing round-trip test** `run-typelookup-reply-test` (register it): build a reply carrying one `TypeIdentifierTypeObjectPair` whose TypeObject octets are `(dds.types:minimal-type-object-octets <shape-type model>)`; assert `(values op pairs related-guid related-sn remote-ex)` round-trip, where each pair is `(hash . typeobject-octets)`; assert truncation → NIL; assert a `REMOTE_EX_UNKNOWN_OPERATION` reply round-trips with empty pairs.
- [ ] **Step 2: FAIL.**
- [ ] **Step 3: Implement** mirroring Task 1.1: `ReplyHeader` = SampleIdentity + i32 remoteEx (enum values from §7.6.3.3.2 in declaration order 0–5, cite); `TypeLookup_Return` union (same discriminators) + `getTypes_Result` union (`switch(long)` on DDS_RETCODE_OK = 0, cite the DDS return-code table) + MUTABLE `getTypes_Out`: member `types` = sequence of `TypeIdentifierTypeObjectPair` (each: TypeIdentifier + TypeObject, both already-serialized octet runs; pair framing from `xtypes-1_3_typeobject.idl`, cite), member `complete_to_minimal` emitted empty. `getTypeDependencies_Out` = `sequence<TypeIdentifierWithSize>` (reuse the `%put-type-id-with-size` framing) + empty continuation.
- [ ] **Step 4:** Export; run SBCL + Clasp (73 expected). If Stage 0 captured a real Connext request/reply: add byte-exact assertions now (decode the captured octets; reproduce them) in the same test, provenance-documented.
- [ ] **Step 5:** Gates; commit — `feat(types): TypeLookup_Reply XCDR2 codec`.

### Task 1.3: Fuzz the new parsers

**Files:** Modify `src/dds-tests/pbt-test.lisp` (mirror how `parse-data-frag-body` etc. were added to the fuzz loop).

- [ ] **Step 1:** Add `parse-type-lookup-request` + `parse-type-lookup-reply` to the existing random/truncated-buffer fuzz harness (no condition, NIL or values, no OOB).
- [ ] **Step 2:** `make fuzz` clean on SBCL.
- [ ] **Step 3:** Gates; commit — `test(types): fuzz TypeLookup request/reply parsers`.

---

## STAGE 2 — MinimalTypeObject deserializer

### Task 2.1: `parse-minimal-type-object`

**Files:** Modify `src/dds-types/typeobject-cdr.lisp`, `packages.lisp`; test in `src/dds-tests/xtypes-test.lisp`.

- [ ] **Step 1: Failing property test** `run-typeobject-parse-test` (register it): for each of `"ShapeType"` and the nested test type used by `xtypes-typeobject-cdr` (read that test for its model), assert `(dds.types:parse-minimal-type-object (dds.types:minimal-type-object-octets m))` returns a `minimal-struct-type` that is structurally equal to `m`: same name-independent shape — extensibility, member count, and per-member `(id flags-relevant key-p optional-p must-understand-p name-hash ti-kind ti-bound ti-hash)` (write a `%struct-model-equal-p` helper; the parsed model has `referenced = NIL` for hash members — compare hashes). Assert `:unsupported` for: a TypeObject whose discriminator is EK_COMPLETE, a union TypeObject (hand-build 3 octets `DHEADER + EK_MINIMAL + TK_UNION...` truncated is fine — must be `:unsupported` or NIL, never an error), and octets longer than `dds.types:*max-type-object-bytes*`. Assert truncation at several offsets → NIL (loop offsets 0..len-1, no condition).
- [ ] **Step 2: FAIL.**
- [ ] **Step 3: Implement** as the exact inverse of `%put-type-object`/`%put-minimal-struct-type`/`%put-common-struct-member` (read them; same clause citations):

```lisp
(defun* parse-minimal-type-object (octets)
    (function ((simple-array (unsigned-byte 8) (*)))
              (or null minimal-struct-type (member :unsupported)))
  "Parse a serialized EK_MINIMAL TypeObject into a minimal-struct-type, :UNSUPPORTED for
   any kind outside the modeled subset (non-struct, EK_COMPLETE, unmodeled member TIs),
   NIL on malformed/truncated input. Inverse of MINIMAL-TYPE-OBJECT-OCTETS (§7.3.4.5)."
  ...)
```

  Walk: guard `(> (length octets) *max-type-object-bytes*)` → NIL; TypeObject DHEADER (bounds-check against octet length); disc octet ≠ `+ek-minimal+` → `:unsupported`; TK octet ≠ `+tk-structure+` → `:unsupported`; struct_flags u16 → extensibility (inverse of `%struct-type-flag`; unknown bits beyond the mask ignored); header DHEADER → skip its extent (tolerates base-type content we don't model only if TK_NONE, else `:unsupported`); member-seq DHEADER + count (guard count ≤ 4096) → per member: DHEADER (skip-to-end after parsing — APPENDABLE tolerance), id u32, flags u16 → key/optional/must-understand booleans, TypeIdentifier (inverse of `%put-type-identifier`: primitive kinds, STRING8 small/large, EK_MINIMAL/EK_COMPLETE → `hash-type-identifier` with the 14 octets, plain sequence kinds → `sequence-type-identifier` parsing the `PlainSequenceSElemDefn`/`LElemDefn` framing pinned from `xtypes-1_3_typeobject.idl` — note the serializer cannot yet EMIT these; parsing them is required because Connext types may carry them; any other kind → `:unsupported` for the whole parse), then the 4-octet NameHash. Member name strings are not present in Minimal (NameHash only) — construct members via `make-struct-member` with `:name NIL`-equivalent (check its signature; if name is required, pass `""` and the parsed name-hash explicitly — read `xtypes.lisp:124` first).
- [ ] **Step 4:** Export `#:parse-minimal-type-object`; run SBCL + Clasp (74 expected); add both parsers to the fuzz loop (`pbt-test.lisp`) and run `make fuzz`.
- [ ] **Step 5:** Gates; commit — `feat(types): MinimalTypeObject deserializer (inverse of the XCDR2 serializer)`.

---

## STAGE 3 — Service engine

> Before starting: read `src/dds-disc/disc.lisp` in full (esp. `%handle-datagram` :502, `%builtin-reader-nl` :268, `%builtin-acknack-values`/`%builtin-on-data`, `%send-paramlist` :148, `announce-endpoints` :332, the node lock discipline: compute under lock, send outside) and `src/dds-disc/dataplane.lisp` (`%send-msg-buf`, tx-msg/rx-tx-msg use). Match those idioms exactly.

### Task 3.1: Hash index + pure server core (`src/dds-types/typelookup.lisp`)

- [ ] **Step 1: Failing test** `run-typelookup-server-test` (register): after `(dds.shapes::ensure-types)`-equivalent (read how tests get ShapeType registered — mirror an existing xtypes test), assert `(dds.types:find-type-support-by-hash (dds.types:equivalence-hash (dds.types:type-support-typeobject (dds.types:find-type-support "ShapeType"))))` returns the ShapeType type-support; assert a registered type whose TypeObject cannot serialize (e.g. `"LargeData"`, sequence member) is absent from the index without error; assert `dds.types:type-lookup-respond` on a serialized getTypes request for the ShapeType hash returns reply octets that `parse-type-lookup-reply` decodes to one pair whose TypeObject octets equal `minimal-type-object-octets`; unknown hash → `REMOTE_EX_OK` with zero pairs; `:unknown` operation → `REMOTE_EX_UNKNOWN_OPERATION`; > `*max-typelookup-request-ids*` ids → NIL (drop).
- [ ] **Step 2: FAIL.**
- [ ] **Step 3: Implement** in `typelookup.lisp`:

```lisp
(defparameter *max-typelookup-request-ids* 32
  "Max type_ids accepted in one inbound TypeLookup request (NFR-SEC-POSTURE).")

(defun* find-type-support-by-hash (hash)
    (function ((simple-array (unsigned-byte 8) (*))) t)
  "The registered type-support whose minimal EquivalenceHash equals HASH, or NIL.
   Types whose TypeObject cannot serialize yet (unsupported member TIs) are skipped.")
```

  Implementation walks `*type-registry*` computing `equivalence-hash` inside `handler-case` (skip on error), with a small memo (alist hash↔name, invalidated by registry size change — keep simple). `type-lookup-respond (request-octets) → (or null octets)`: parse, guard, dispatch on operation: `:get-types` → pairs for known hashes; `:get-deps` → `%collect-dependencies` of the found model mapped to `TypeIdentifierWithSize`; build the reply with `relatedRequestId` = the request's `(writer-guid . sn)` and our instance name passed in by the caller. Pure: no sockets, no node.
- [ ] **Step 4:** Export; run (75 expected); gates; commit — `feat(types): TypeLookup hash index + pure server core (answers getTypes/getTypeDependencies)`.

### Task 3.2: Builtin endpoints on the disc-node (`src/dds-disc/typelookup-endpoints.lisp`)

**Files:** Create the file (add to `dds-disc.asd` after `dataplane`), modify `src/dds-disc/disc.lisp` (dispatch + struct slots), `src/dds-disc/packages.lisp`.

**Clause to pin first:** Table 61 EntityIds. Define in this file:

```lisp
;;; XTypes 1.3 Table 61: TypeLookup service builtin EntityIds.
(defconstant +entityid-tl-req-writer+ #x000300c3)
(defconstant +entityid-tl-req-reader+ #x000300c4)
(defconstant +entityid-tl-reply-writer+ #x000301c3)
(defconstant +entityid-tl-reply-reader+ #x000301c4)
```

- [ ] **Step 1:** Add to the `disc-node` struct (typed, defaulted): `tl-pending` (hash-table eql: SN → `tl-pending-entry`), `tl-req-sn` / `tl-reply-sn` (integer 1), `tl-sent` (list of `(sn . octets)`, bounded — the reliable resend store for our reply writer), and the special vars `*typelookup-timeout*` 3, `*max-typelookup-pending*` 64 (docstrings citing the spec §7.6.3.3.3 QoS: RELIABLE/KEEP_ALL/VOLATILE — VOLATILE means the bounded resend store may drop acked/old entries).

```lisp
(defstruct* (tl-pending-entry (:constructor %make-tl-pending-entry))
  "One in-flight TypeLookup client request: the queried hash set, the remote prefix,
   a continuation called with (hash -> typeobject-octets alist | NIL on timeout),
   and the monotonic deadline."
  (hashes '() :type list)
  (prefix (make-array 12 :element-type '(unsigned-byte 8)) :type (simple-array (unsigned-byte 8) (12)))
  (continuation nil :type (or null function))
  (deadline 0 :type integer))
```

- [ ] **Step 2: Server inbound.** In `%handle-datagram`'s DATA dispatch, branch `writerId = +entityid-tl-req-writer+`: feed the per-remote builtin reliable reader (mirror the SEDP branch + `%builtin-on-data`), then `dds.types:type-lookup-respond` on the payload (strip the encapsulation handling inside the codec); a non-NIL reply is sent via `%send-tl-reply` (new: mirrors `%send-paramlist`'s build-under-lock/send-outside discipline, writer `+entityid-tl-reply-writer+`, reader `+entityid-tl-req... reply-reader+` of the requester, next `tl-reply-sn`, store in `tl-sent`, follow with a HEARTBEAT mirroring `%send-endpoint`'s). ACKNACKs arriving for `+entityid-tl-reply-writer+` → resend from `tl-sent` (mirror the SEDP writer's ACKNACK answer path — find it via `%on-builtin...`/`announce-endpoints` reading).
- [ ] **Step 3: Client.** `type-lookup-query (node prefix hashes continuation)`: guard `*max-typelookup-pending*`; build request octets (instance name `"dds.builtin.TOS."` + the target participant's GUID hex per §7.6.3.3.4 — `CONFIRM-VS-CAPTURE` for length; lowercase, no 0x), send DATA via writer `+entityid-tl-req-writer+` to the remote's metatraffic locator (`%remote-metatraffic`), record `tl-pending`. Inbound branch `writerId = +entityid-tl-reply-writer+`: parse reply, correlate `related-sn` in `tl-pending` (drop unknown), call the continuation with the pairs alist, remove entry. `tl-sweep (node now)`: expire entries past deadline calling continuation with NIL — invoke from the `announce-endpoints` loop (read where periodic work runs; add the call there).
- [ ] **Step 4: Failing offline test** `run-typelookup-endpoints-test` (in `integration-test.lisp`, mirror `run-dataplane-test`'s two-node setup): node A registers ShapeType (announced via its SEDP), node B `type-lookup-query`s A for the ShapeType hash; spin both; assert B's continuation received one pair whose octets parse (via `parse-minimal-type-object`) to a model with the same equivalence-hash; assert a query for an unknown hash yields zero pairs (not timeout); assert a query to a dead prefix times out → continuation called with NIL within `*typelookup-timeout*` + one sweep period.
- [ ] **Step 5:** Run SBCL + Clasp (76 expected); `make wire` (our TL submessages must dissect cleanly in tshark); gates; commit — `feat(disc): TypeLookup builtin request/reply endpoints (XTypes 1.3 Table 61, FR-TYPE-3)`.

---

## STAGE 4 — Match gating

### Task 4.1: `type-gate` hook + parked matches (`src/dds-disc/disc.lisp`)

- [ ] **Step 1:** Add to `disc-node`: `type-gate` (`(or null function)`) — called as `(funcall gate node remote local)` before `%record-match` in BOTH `%match-remote-writer` (:462) and `%match-remote-reader`; returns `:compatible` (proceed), `:incompatible` (treat as INCONSISTENT_TOPIC: fire `%record-inconsistent`/`%fire-inconsistent`), or `:pending` (park: push `remote` onto a new `parked-matches` list slot + return without matching). `resume-parked-matches (node)`: re-run `%match-remote-*` for parked entries (called by the gate installer when a verdict arrives); NIL gate (default) ⇒ today's behavior exactly.
- [ ] **Step 2: Failing test** (in `integration-test.lisp`): install a gate returning `:incompatible` → assert no match + the inconsistent-topic callback fired; a gate returning `:pending` then, after `resume-parked-matches` with the gate now `:compatible` → assert the match completes. Pure disc-level, no DCPS.
- [ ] **Step 3:** Run (77 expected); gates; commit — `feat(disc): type-gate hook + parked matches on the SEDP match path`.

### Task 4.2: DCPS installs the assignability gate (`src/dds-dcps/entities.lisp`)

> Read `%assess-and-record-type-compat` (:456) and the participant-creation site that installs disc-node hooks first; mirror that installation pattern. Read `src/dds-types/assignability.lisp` exports (`struct-assignable-from`, `assignability-options`, the TYPE_CONSISTENCY_ENFORCEMENT QoS slots in `dds.qos`).

- [ ] **Step 1: Failing tests** (in `dcps-test`-style file where `dcps-type-compat` lives; register): (a) two participants, same topic, structurally compatible types with DIFFERENT names... (names must match for SEDP topic matching — instead: same type name, same shape ⇒ equal hashes ⇒ `:compatible` fast path, match completes, no query); (b) same type name, locally-different member layout (define a second DSL type registered under the same wire name in the remote node — mirror how `dcps-type-compat` builds mismatched types) ⇒ hashes differ ⇒ gate queries via TypeLookup ⇒ assignability fails ⇒ INCONSISTENT_TOPIC status set + no match; (c) remote announces no TypeInformation ⇒ name-based match (gate returns `:compatible` immediately); (d) remote hash unknown + TypeLookup times out (point the query at a non-answering node) ⇒ match completes after the timeout (name fallback).
- [ ] **Step 2: FAIL.**
- [ ] **Step 3: Implement** the gate function installed at participant enable: on `:pending`-capable logic per the spec §4 Stage 4 — local hash equal → `:compatible`; cache hit → assess; else `type-lookup-query` + `:pending`, continuation: parse → cache (`*max-typeobject-cache-entries*` 256, simple FIFO eviction) → assess → store verdict → `resume-parked-matches`. Assess = `struct-assignable-from` with options from the reader's TYPE_CONSISTENCY_ENFORCEMENT QoS (read how `dds.qos` exposes it); `:unsupported`/parse-NIL/timeout → `:compatible` (name fallback, log via the existing `*type-compat-log*`). Nested unresolved hashes: collect the hash-kind member TIs of the parsed remote model with no cache entry; if non-empty and depth < `*typelookup-max-depth*` (new var, default 4), issue a follow-up query for them before assessing; depth exhausted → name fallback.
- [ ] **Step 4:** Run SBCL + Clasp (81 expected: 4 new); gates; `make mem` (no hot-path impact); commit — `feat(dcps): assignability-gated matching via TypeLookup (FR-TYPE-4, TYPE_CONSISTENCY_ENFORCEMENT)`.

---

## STAGE 5 — Live bidirectional Connext gate

### Task 5.1: Connext consumes our server

- [ ] **Step 1:** `make square-pub` (ours) ↔ `CONNEXT_VERBOSE=1 rtiddsspy` (in `$NDDSHOME/bin`) AND/OR `shapes_sub`; capture lo0. Acceptance: Connext issues `TypeLookup_Request` to us (capture shows DATA to `0x000300c4`), our reply DATA from `0x000301c3` follows, no RTI error logged, and — the end-to-end proof — **rtiddsspy prints our ShapeType samples with decoded fields** (spy needs the TypeObject; name-matching alone cannot decode). If Connext never queries despite the Stage-0 findings, re-check our SPDP bits + its STATUS_ALL log before concluding; record whatever the wire shows.
- [ ] **Step 2:** Lock the captured Connext request as a byte-exact vector test (decode + our `parse-type-lookup-request` field assertions; mirror `connext-data-frag-vector`'s provenance style), and our accepted reply bytes as the encode pin. Fix any codec discrepancy revealed (clause-cited).
- [ ] **Step 3:** Suite + gates; commit — `test(interop): Connext consumes our TypeLookup server (vectors locked)`.

### Task 5.2: We consume Connext's server + gate on the result

- [ ] **Step 1:** Run our `make square-sub` against a Connext writer whose type forces a hash difference: `rtishapesdemo` (its ShapeType has `string<128> color` — different bound ⇒ different minimal hash) or a variant `ShapeTypeB128.idl` oracle app if the demo is unavailable. Acceptance: our gate queries Connext (capture: our DATA to its `0x000300c4`), Connext replies, our deserializer parses its TypeObject, assignability (with `ignore-string-bounds` default per §7.6.3.4.1) passes, match completes, samples flow. Then the negative: a deliberately incompatible Connext type (e.g. an IDL with `x` as `double`) under the same names ⇒ our INCONSISTENT_TOPIC fires and no samples are taken.
- [ ] **Step 2:** Lock Connext's reply (its TypeObject for ShapeType!) as a vector; **compare Connext's announced minimal hash against our serializer's hash for the same type definition** — record match/mismatch in `docs/verification.csv`; a mismatch means fixing the PROVISIONAL serializer choices (typeobject-cdr.lisp header comment lists the three flip-points) to the oracle, re-running the suite, and updating the committed `BF E2 ...` regression vector with the oracle-confirmed value (this closes ADR 0009's open question).
- [ ] **Step 3:** Suite SBCL + Clasp + all gates + `make fuzz wire`; commit — `test(interop): we consume Connext's TypeLookup server; assignability gates live (FR-TYPE-3/4, FR-IO-1)`.

### Task 5.3: Docs + verification closeout

- [ ] **Step 1:** Update `docs/verification.csv` (FR-TYPE-3 done, FR-TYPE-4 gated-live, FR-IO row), `docs/MILESTONES.md` (M4 progress), `README.md` (status), `docs/wiki/xtypes.md` + `docs/wiki/discovery.md` (all new exported symbols + special vars: `*typelookup-timeout*`, `*max-typelookup-request-ids*`, `*max-typelookup-pending*`, `*max-typeobject-cache-entries*`, `*typelookup-max-depth*`, the endpoint/bit constants, `parse-minimal-type-object`, the codec entry points, `type-lookup-query`, `find-type-support-by-hash`), `interop/connext/README.md` (findings incl. the EquivalenceHash oracle outcome).
- [ ] **Step 2:** Commit — `docs: TypeLookup service complete — bidirectional live Connext type discovery (FR-TYPE-3, FR-TYPE-4)`.

---

## Self-review notes

- **Spec coverage:** design §4 Stage 0→Task 0.1 (incl. STOP-gate + ADR 0009 hash check); Stage 1→Tasks 1.1–1.3; Stage 2→Task 2.1 (incl. `:unsupported`, guards, sequence-TI parse); Stage 3→Tasks 3.1–3.2 (registry index, pure server, four endpoints, pending table, sweep); Stage 4→Tasks 4.1–4.2 (hook, park/resume, cache, nested follow-up via `*typelookup-max-depth*`, INCONSISTENT_TOPIC, fallbacks); Stage 5→Tasks 5.1–5.3 (both directions, vectors, hash-oracle closeout, docs). §6 special vars all appear; §7 guards in Tasks 1.1/2.1/3.1/3.2/4.2.
- **Known execution-time confirmations** (flagged in-task, not placeholders): the `@hashid` member ids for the MUTABLE in/out members (compute per §7.3.1.2.1.1 from the IDL names at implementation, cite values); the encapsulation identifier; the instance-name GUID length; `make-struct-member`'s name parameter shape; where the announce loop runs the sweep. Each task names the file/line to read first.
- **Type consistency:** codec names (`serialize/parse-type-lookup-request/-reply`), engine names (`find-type-support-by-hash`, `type-lookup-respond`, `type-lookup-query`, `tl-sweep`, `resume-parked-matches`), constants (`+entityid-tl-*+`, `+be-tl-*+`, `+tl-gettypes-hash+`/`+tl-getdeps-hash+`), and the `tl-pending-entry` struct are used consistently across tasks.
- **Serving-scope boundary (recorded):** types whose TypeObject serializer errors (sequence-member TIs, e.g. LargeData) are skipped by the hash index until sequence-TI emission is oracle-confirmed; the live gate uses ShapeType, which serializes today.
