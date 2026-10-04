# ADR 0127 — Exit-gate wording: every milestone exit names a number, a method and a file

- **Status:** **Accepted** (2026-10-04). The values in §2–§5 are owner decisions D3, D5 and D30 of 2026-10-04
  (ADR 0124 §2, "as recommended"); §6 is the matrix those decisions and plan WP-0.15 call for; §7 records D4
  as still open. Three values this ADR adds where neither the plan nor the decisions gave one (the per-input
  fuzz time bound in §3.3, the floor for the measured soak loss and duplication in §4.2 and the soak no-wedge
  window in §4.3) are marked **this ADR's choice** so the owner can change them.
- **Date:** 2026-10-04
- **Requirement:** IMPLEMENTATION-PLAN §4 (the M0–M7 exit gates), §8 (testing strategy), §12 (CI);
  REQUIREMENTS §6 (NFR-PERF), §7.7 NFR-TEST, §7.8 NFR-SEC-POSTURE, §9 (acceptance), FR-CDR-8, FR-IO-3,
  FR-DCPS-*; the operating contract §5 ("never mark work done with a red gate or a skipped interop/byte-exact
  check")
- **Work package:** WP-0.15 of `docs/plans/2026-10-03-sbcl-allegro-full-ok.md` (the governing plan)
- **Partly supersedes:** ADR 0062's reading of NFR-PERF-3 as "p99.99 within 5 % of Connext" (already
  retracted by the forward note ADR 0124 placed on ADR 0062; this ADR is the gate-side record, §5)
- **Relates to:** ADR 0118 (Clasp withdrawn; every exit reads "SBCL and AllegroCL"), ADR 0120 (transitional
  DoD), ADR 0122 (skip accounting: a deferred check counts as a skip), ADR 0124 (D3, D4, D5, D28, D30),
  ADR 0126 (exits are declared in order on fresh evidence)

---

## 1. The defect

Several exit gates in IMPLEMENTATION-PLAN §4 could not fail, because they named no number, no method or no
artefact:

| Exit | Wording | What was missing |
|---|---|---|
| M1 | "CDR fuzzer runs clean for N hours" | N; what "clean" means; which fuzzer |
| M2 | "no parser crashes under the fuzzer with real Connext traffic replayed" | how long; which captures |
| M3 | "DCPS conformance suite green" | which suite: none is defined |
| M2–M7 | "interop-validated", "interoperates with a compliant peer", "secure interop with a Connext …" | which legs, both Lisps or one, where the result is kept |
| M6 | "large-data + lossy-network soak passes" | duration, loss profile, pass condition; no `make soak` exists |
| M5 | "NFR-PERF-1,4,5,6,7,8 met" | was read against a stricter "5 %" figure (ADR 0062) that REQUIREMENTS never set |
| M1 | "XCDR byte-exact vs. RTI-generated vectors" in both endiannesses (FR-CDR-8) | whether Connext can produce big-endian vectors at all is unknown |

A gate with a free parameter is passed by whatever value the run happened to use. This ADR fixes each value.

## 2. Scope rule for every exit (D28, ADR 0118)

- Every exit gate is read as **SBCL and AllegroCL `alisp`**, Linux x86_64 (ADR 0118, ADR 0124 D1). SBCL means
  the pinned latest and one prior release (WP-1.12); the 2.2.9 floor is a non-blocking job (D12).
- An exit is evaluated against the **MUSTs and the blocking SHOULDs** of ADR 0124 §2.2. A backlog SHOULD never
  blocks an exit and never counts toward one.
- A skipped check is not a passed check (operating contract §5, ADR 0122): an exit run reports
  `0 SKIPPED, 0 PARTIAL`, or the exit is not passed. The ADR 0120 baselines are a per-commit device; **no exit
  is declared while either baseline is non-empty**.

## 3. Fuzzing (D3, D30)

### 3.1 Duration

| Run | Duration | Where | What it gates |
|---|---|---|---|
| Release / exit run | **8 h per Lisp** (SBCL and AllegroCL each run their own 8 h) | the release-candidate job (WP-5.14), on the commit being declared | the M1 exit ("N hours" = 8 h), the M2 exit's replay clause, REQUIREMENTS §9 item 4 |
| Nightly | **1 h per Lisp** | the nightly `fuzz-soak` job (WP-3.6) | nothing by itself: a regression signal; a nightly crash is a defect with an owner |

### 3.2 Method (D30)

**Now (from this ADR until P6 ships):** property-based testing **plus** replay-and-mutation of committed
captures, **with shrinking**:

- Generators cover the CDR decoder (XCDR1 and XCDR2, every extensibility kind the codec ships) and every RTPS
  submessage parser, plus the four security fuzzers (the plan §7 list: `make fuzz` includes them).
- Every committed capture under `interop/*/captures/` is replayed byte-for-byte and then mutated (WP-2.6).
  Captures from Linux Connext 7.3.1 join the set when the lab exists (WP-5.5); until then the existing
  captures are the replay set, and the M2 exit's "real Connext traffic replayed" clause is met only when
  Linux Connext captures are in it.
- **Shrinking is required:** every failing input is reduced to a minimal reproducer, committed to the crash
  corpus as a regression vector, and replayed by every later run. Each run records its seed.

**Before P6 ships:** a **coverage-guided** harness (AFL/libFuzzer-style through CFFI, as IMPLEMENTATION-PLAN
§8 and REQUIREMENTS §10's NFR-SEC-POSTURE row describe) is added, and its 8 h-per-Lisp run joins the release
run of any release that contains P6. Until then the PBT-plus-replay method is the accepted fuzz method for
every exit (D30); REQUIREMENTS §10's "AFL/libfuzzer-style" row is satisfied at that point, not before.

### 3.3 What "clean" means

A fuzz run is clean when, over the whole run, on each Lisp:

1. **no crash:** no memory fault (SIGSEGV, SIGBUS), no foreign-memory read outside a buffer's extent, no
   abort of the Lisp;
2. **no escaped condition:** every parser entry point returns a status for malformed input and never signals
   past its boundary (ADR 0064);
3. **no hang:** no single input takes longer than **1 s** wall-clock to process (**this ADR's choice**; the
   harness enforces it per input and reports the slowest input);
4. **guards hold:** no resource-exhaustion guard (maximum fragments, reassembly bytes, instances) is exceeded;
5. **accounting:** the ADR 0122 report shows `0 SKIPPED, 0 PARTIAL` (every fuzzer arm ran).

## 4. Soak (D3)

### 4.1 Duration and scope

**24 h per Lisp** on the commit being declared. It gates the **M6 exit** ("large-data + lossy-network soak
passes"). It runs over a network namespace pair joined by a veth link (WP-5.11; needs `CAP_NET_ADMIN`, owner
action D21), with 64 KB–4 MB samples, late joiners, and both our own peers and Connext (once the lab exists,
Phase 4).

The **determinism soak** (NFR-DET, WP-6.8) is a separate 24 h run per Lisp. It reports latency drift, GC
frequency and pause times and queue-depth stability; it gates NFR-DET's gap report, not M6.

### 4.2 Network profile

Applied to **each** veth end, so each direction sees the profile (netem shapes egress only):

| Impairment | netem parameter |
|---|---|
| loss | 1 % (random) |
| delay | 50 ms, jitter 10 ms, **`distribution normal`** (named explicitly; see below) |
| reorder | 0.5 % (the parameter; the effective reorder rate is higher, see below) |
| duplication | 0.1 % |

As a `tc` command, in the syntax of `tc-netem(8)` as installed on the reference host
(`/usr/share/man/man8/tc-netem.8.gz`, iproute2 6.1.0; `reorder` requires a `delay`, which is present; the
`normal` table is `/usr/lib/x86_64-linux-gnu/tc/normal.dist`, shipped by the `iproute2` package):

```
tc qdisc add dev <veth> root netem delay 50ms 10ms distribution normal loss random 1% duplicate 0.1% reorder 0.5%
```

**The distribution is named, not defaulted.** `tc-netem(8)` says the default distribution is Normal. Whether
that holds when no table is loaded depends on the tc and kernel versions (moderate confidence that a kernel
with no table falls back to a uniform spread; not verified on this host, which lacks `CAP_NET_ADMIN`, D21).
Naming `distribution normal` makes the question moot.

**The jitter reorders packets on its own (accepted as part of the profile).** With a jitter and netem's
default internal queue, each packet is released at its own randomly drawn send time, so two packets sent
closer together than the spread of the jitter can swap. At soak data rates the effective reorder rate is
therefore set mostly by the jitter, and is well above the 0.5 % `reorder` parameter (moderate confidence;
this is documented netem behaviour, but the man page on this host does not state it). This ADR **accepts**
that: reordering beyond 0.5 % makes the soak harsher for the reliable protocol, never easier, and the pass
condition (§4.3) does not depend on the reorder rate. The `reorder 0.5%` parameter stays, so that some
packets bypass the delay entirely (the `tc-netem(8)` reorder semantics) even at low rates. A configuration
that keeps order under jitter (a child `pfifo` queue under netem, or a `rate`) is **not** pinned: it would have
to be verified on the soak host's kernel first, and nothing would be gained for the gate.

**The soak report records what happened on the wire, not only what was configured.** It records the output
of `tc qdisc show` and `tc -s qdisc show` (netem's own drop and duplicate counters) for both ends at start and
end, **and** the loss, duplication and reorder rates measured from a capture on each veth end (or from the
RTPS sequence numbers seen by the receiving side). The measured rates, not the parameters, are the evidence
of the profile that ran. A run whose measured loss is below 0.5 % or whose measured duplication is below
0.05 % (half of each parameter, **this ADR's choice**) did not apply the profile and does not count.

### 4.3 Pass condition

On each Lisp, over 24 h:

1. **no reliable loss:** every sample written by a RELIABLE writer is delivered exactly once and in order to
   every matched RELIABLE reader whose history depth and resource limits retain it, late joiners included as
   their DURABILITY QoS requires;
2. **no wedge:** no 60 s window in which a matched reader with samples outstanding receives none (**this ADR's
   choice**);
3. **bounded memory:** static-arena high-water below the configured budget (`*static-arena-bytes*`, or
   `*static-arena-max-bytes*` in growable mode, ADR 0125); zero GC-heap fallbacks; every RESOURCE_LIMITS
   rejection counted and reported;
4. **clean end:** no leaked `dds-*` thread and no stuck teardown join at the end (ADR 0121, ADR 0092).

## 5. Performance (D5)

- **REQUIREMENTS §6 (the NFR-PERF table) is the performance gate.** Its bands are ratios to RTI Connext on
  identical hardware, operating system and transport, p50 unless a row says otherwise.
- The **M5 exit** reads: NFR-PERF-1, 4, 5, 6, 7 and 8 within their bands on SBCL and on AllegroCL, measured by
  the perftest-equivalent harness against Connext's own perftest (owner action D17 provides the entitlement;
  NFR-PERF-5 needs the second GbE host, owner action D22). Whether AllegroCL keeps the same bands is owner
  decision D7, taken at WP-6.0 with data; until then the bands stand as written.
- **NFR-PERF-3** (p99.99 / max) is "within 3×", and REQUIREMENTS §9 item 3 judges it as **measured and its gap
  documented**, not necessarily met.
- **The "5 %" figure is retracted for every gate purpose.** It appears in ADR 0062 (its Requirements line and
  the Consequences bullet "NFR-PERF-3 (p99.99 within 5 %) remains blocked on this and only this") and in two
  bench reports of 2026-07-13: `bench/report/2026-07-13-connext-ratio-table-current.md` ("The 5 % mandate
  (≤1.05×) is **still not met**") and `bench/report/2026-07-13-clock-and-udp-floor.md` ("the 5 % mandate",
  "The 5 % budget on a 7 µs floor"). REQUIREMENTS never set it. Those documents are history and are not
  edited; this ADR and the forward note on ADR 0062 are the correction. No report, ADR or gate may cite 5 %
  as a target.

## 6. The interop matrix

### 6.1 The file

`interop/matrix.csv` is the interop gate's definition. Columns `Lisp,Peer,Feature,Direction,Status,Evidence,
Notes`:

- **Lisp:** `sbcl`, `allegro` (our side).
- **Peer:** `connext-7.3.1`, `fastdds-3.6.1`, and `neodds-allegro` for the cross-Lisp leg (written once, from
  the SBCL side; its two directions cover SBCL→AllegroCL and AllegroCL→SBCL).
- **Feature:** `be` (best effort, including the RxO-negative case: an incompatible QoS must not match and must
  raise the incompatible-QoS statuses), `reliable`, `cft` (writer- and reader-side), `durability`,
  `evolution` (XTypes), `frag`, `large-data`, `secure` (encrypt, sign and datasign governance variants) and
  `flatdata`, for every peer; plus `shmem` (same-host shared memory, Zero-Copy included) for Connext and the
  cross-Lisp leg. Fast DDS gets no `shmem` cell: its shared-memory transport is its own, and no requirement
  claims it.
- **Direction:** `out` (we write, the peer reads) and `in` (the peer writes, we read).
- **Status:** `NOT-RUN`, `PASS`, `FAIL` or `EXCLUDED`. A `PASS` or `FAIL` cell names its evidence (the
  committed results file or capture of that leg), and the file must exist. An `EXCLUDED` cell names the ADR
  that excludes it.

That is **96 cells**, all `NOT-RUN` today: the Linux lab does not exist yet (Phase 4), and earlier live
legs ran on a macOS host, which is not a target (D1) and whose results are SBCL-only at best (ADR 0118 §3).

### 6.2 The rules

- **A cell is never dropped.** It is `PASS`, `FAIL`, `NOT-RUN` or `EXCLUDED` by an ADR. `make
  gate-verification` checks the file's completeness and shape now (`scripts/interop-matrix.py`, which proves
  itself able to fail on a dropped, duplicated, unknown, evidence-less or ADR-less cell, and on each
  violation of the next rule).
- **Only Connext `shmem` cells may be excluded**, and only by the scoping ADR of owner decision D20 (WP-5.9).
  The check enforces both halves: `EXCLUDED` on any other (peer, feature) is rejected, and the ADR named in
  Notes must exist as `docs/adr/NNNN-*.md`.
  `flatdata` cells stay in: the patent question (R6) is a ship gate, not a test gate.
- **Enforcement is WP-4.12:** `make interop` (and `interop-all`) fails unless every cell is `PASS` or
  `EXCLUDED`, with a live tshark check per leg (WP-4.7). Until WP-4.12 lands, the file is the definition and
  the checklist, not yet the gate.

### 6.3 Which cells each exit needs

| Exit | Cells that must be `PASS` (both Lisps, both directions) |
|---|---|
| M2 | `be` and `reliable` with Connext (the Shapes exchange), tshark-validated per leg; the cross-Lisp `be` and `reliable` cells |
| M3 | `cft` with Connext (writer- and reader-side), and the RxO-negative case inside `be` |
| M4 | `evolution` with Connext (through its legacy TypeObject announcement, ADR 0010) and with Fast DDS (the standard TypeLookup service) |
| M5 | `frag`, `large-data`, `flatdata`, and `shmem` where not excluded by the D20 ADR |
| M6 | `durability` |
| M7 | `secure` with Connext on a shared governance/permissions set |
| Acceptance (WP-5.14) | every cell not excluded by an ADR |

## 7. FR-CDR-8 (a): big-endian vectors are conditional on WP-4.11 (D4 open)

FR-CDR-8 (MUST) requires byte-exact conformance against (a) RTI-generated reference vectors and (b) the
XTypes worked examples, **both endiannesses**, all extensibility kinds. Every XCDR vector committed under
`corpus/xcdr2/` today is little-endian: their encapsulation identifiers (the first two octets) are `0x0001`,
`0x0003` or `0x0007`, the `_LE` entries of `+representation-ids+` in `src/dds-cdr/cdr.lisp` (XTypes 1.3
§7.6 Table 60, as that docstring cites it); none carries a `_BE` identifier (read 2026-10-04 with `od`). Whether licensed Connext
7.3.1 on x86_64 can emit big-endian XCDR1/XCDR2 at all is unknown (plan WP-4.11, low confidence).

- The M1 exit's clause (a) is read as written for little-endian now.
- For big-endian, clause (a) is **conditional on WP-4.11**: if the probe shows Connext can emit big-endian
  vectors, they are generated and the clause applies as written. If it cannot, owner decision **D4** (still
  open, ADR 0124) is taken then: the recommended alternative is an independent implementation plus foreign
  acceptance as the big-endian oracle, recorded in its own ADR. Because FR-CDR-8 is a MUST in REQUIREMENTS,
  that alternative also needs a REQUIREMENTS amendment approved by the owner; an ADR alone cannot relax it
  (operating contract §2).
- Until one of the two happens, the M1 exit **cannot be declared** on the big-endian half of clause (a).
  Clause (b) (XTypes worked examples) is not affected.

## 8. Other exits, made concrete

| Exit | Read as |
|---|---|
| M0 | Every ASDF system loads with `make gate-build` on SBCL and AllegroCL (ADR 0118 §3), plus the mock echo test |
| M1 | `make corpus` verifies every vector, LE and BE (§7), all extensibility kinds, 0 deferred; §3's 8 h fuzz run clean on each Lisp; generated types round-trip on both Lisps; the IDL front-end acceptance of IMPLEMENTATION-PLAN §4 M1 |
| M3 | "DCPS conformance suite green" = every DDS 1.4 DCPS clause in profile P2 is mapped to at least one named test in `docs/verification.csv` (WP-5.7, in the D19 shape: per-Lisp Status columns, evidence paths), and every mapped test passes on both Lisps; an unmapped clause fails the exit. Plus §6.3's M3 cells |
| M6 | §4's 24 h soak on each Lisp, plus §6.3's M6 cells |
| M5, M7 | §5 and §6.3 |

## 9. Consequences

- IMPLEMENTATION-PLAN §4 keeps its wording; each exit it states is read through this ADR. A pointer to this
  ADR is added under the §4 heading.
- `interop/matrix.csv` and `scripts/interop-matrix.py` are new; `make gate-verification` runs the check.
- Work packages that implement what this ADR pins: WP-2.6 (fuzz soak, replay, shrinking), WP-3.6 (nightly
  fuzz, weekly soak), WP-4.7 / WP-4.12 (per-leg tshark, matrix enforcement), WP-4.11 (big-endian probe),
  WP-5.7 (DCPS clause mapping), WP-5.11 (`make soak`), WP-5.14 (release-candidate job), WP-6.8 (determinism
  soak).
- The three values marked as this ADR's choice (1 s per fuzz input, the half-parameter floor for the measured
  soak loss and duplication, 60 s no-wedge window) can be changed by the owner without reopening the rest.
