# Reverse WLP direction (+ PID_LIVELINESS) — implementation plan

> **For agentic workers:** REQUIRED SUB-SKILL: superpowers:subagent-driven-development.

**Goal:** Prove Fast DDS accepts our `ParticipantMessageData` via the strong MANUAL_BY_PARTICIPANT
proof — which requires our SEDP to advertise `PID_LIVELINESS` (0x001b).

**Spec:** `docs/superpowers/specs/2026-06-12-reverse-wlp-pid-liveliness-design.md`.

---

### Task A: PID_LIVELINESS emit + parse in SEDP (conformance, Lisp)

**Files:** `src/dds-rtps/message.lisp` (constant), `src/dds-rtps/discovery.lisp` (serialize/parse
endpoint-data), `src/dds-tests/rtps-test.lisp` (locked vector), `src/dds-tests/echo-test.lisp`.

- [ ] **A1 — failing locked-vector test.** In `rtps-test.lisp` add `run-pid-liveliness-test`:
  build endpoint-data for a writer whose qos is `(:liveliness :manual-by-participant
  :liveliness-lease {5,0})`, serialize, and assert the PID_LIVELINESS parameter bytes are
  `1b 00 0c 00  01 00 00 00  05 00 00 00 00 00 00 00` (id 0x001b, len 12, kind LE=1
  MANUAL_BY_PARTICIPANT, lease sec=5 i32 LE, nanosec=0 u32 LE). ALSO assert the
  Fast-DDS-oracle AUTOMATIC+1s vector `1b 00 0c 00 00 00 00 00 01 00 00 00 00 00 00 00` parses
  back to `:automatic` lease {1,0}. Register `pid-liveliness` in `echo-test.lisp`.
- [ ] **A2 — run, expect fail.**
- [ ] **A3 — constant.** Add `+pid-liveliness+` `#x001b` to `message.lisp` with a docstring
  citing the clause (verify 0x001b from `docs/specs/` — RTPS PID table / DDS PSM; do NOT trust
  memory). Export if the constants are exported.
- [ ] **A4 — serialize.** In `serialize-endpoint-data` (`discovery.lisp`), after PID_DURABILITY,
  emit PID_LIVELINESS len 12: `(liveliness-rank kind)` as u32 LE, then lease `sec` as u32 LE,
  then lease `nanosec` as u32 LE — from `(qos-liveliness qos)` / `(qos-liveliness-lease qos)`.
  Use the existing `dds.qos:liveliness-rank`. Only the writer (publication) role needs the
  offered liveliness; emit for both roles (a reader's requested liveliness is also valid SEDP) —
  match how reliability/durability are emitted for both. One-line comment citing the clause.
- [ ] **A5 — parse.** In `parse-endpoint-data`, on `+pid-liveliness+` read kind(u32 LE)→keyword
  (0→:automatic 1→:manual-by-participant 2→:manual-by-topic) + lease {sec,nanosec} and set them
  on the endpoint's qos (`setf qos-liveliness` / `qos-liveliness-lease`). Bounds-check the 12
  bytes before reading (NFR-SEC-POSTURE; ignore the PID if length ≠ 12). Reuse the role-seeded
  qos default the parser already builds.
- [ ] **A6 — green + gates.** `make test-sbcl`, `make gate-types`, `make gate-hotpath`,
  `GC_DONT_GC=1 make test-clasp`. CRITICAL REGRESSION CHECK: the existing SEDP/data-plane tests
  (`run-sedp-test`, reliability, the DCPS match tests) MUST stay green — emitting PID_LIVELINESS
  for default writers (AUTOMATIC + infinite) must not break any existing RxO match (a default
  reader requests AUTOMATIC+infinite; offered infinite ≤ requested infinite → still compatible).
  If anything regresses, STOP and report.

### Task B: thread finite-lease liveliness through run-publisher (Lisp harness)

**Files:** `src/dds-shapes/shapes.lisp`, `src/dds-shapes/packages.lisp` (if signature exported),
`Makefile`.

- [ ] **B1.** `run-publisher` gains `&key (liveliness :automatic) (liveliness-lease-seconds 0)`;
  when `liveliness-lease-seconds > 0` build `:qos (dds.qos:make-qos :reliability :reliable
  :liveliness liveliness :liveliness-lease (dds.qos:make-qos-duration liveliness-lease-seconds 0))`
  and pass to `add-local-writer`; else keep current default. Full `defun*` ftype updated.
  Docstring notes the liveliness options.
- [ ] **B2.** Makefile `square-pub` gains `LIVELINESS=` / `LEASE=` passthrough (default unset →
  current behaviour). One-line.
- [ ] **B3.** `make test-sbcl` green (no test asserts the harness default changed).

### Task C: Fast DDS shapes_sub — reader liveliness QoS + on_liveliness_changed (C++)

**Files:** `interop/fastdds/shapes/shapes_sub.cpp`.

- [ ] **C1.** Env-gated (`SUB_LIVELINESS_LEASE_MS`, off by default → current behaviour): set
  `rqos.liveliness().kind = MANUAL_BY_PARTICIPANT_LIVELINESS_QOS` + `lease_duration =
  Duration_t(ms/1000, (ms%1000)*1e6)`; add an `on_liveliness_changed` override to the listener
  logging `alive_count`/`not_alive_count` + the `*_change`. One-line comments. Recompile via the
  shapes Makefile (`./scripts/with-fastdds.sh ... make shapes_sub`). Confirm it builds.

### Task D: live strong proof (controller-driven, not a subagent)

- [ ] **D1.** Loopback recipe: `make square-pub LIVELINESS=manual-by-participant LEASE=5
  PEERS=127.0.0.1:7410 COUNT=0` ↔ `SUB_LIVELINESS_LEASE_MS=10000 ./shapes_sub 30` with
  `WIRESHARK_CONFIG_DIR=/tmp/wscfg tshark -i lo0 ...` capturing. Confirm Fast DDS logs
  `on_liveliness_changed alive` (matched + our MANUAL assertion accepted). Then kill our
  publisher; confirm `not_alive` (our assertions stopped). Capture shows our
  ParticipantMessageData DATA (writer 0x000200c2, kind MANUAL) from our prefix + Fast DDS ACKNACK.
- [ ] **D2.** Archive the capture (`interop/fastdds/captures/`, the committed-evidence exception);
  provenance entry; `docs/verification.csv` (note Fast DDS accepts our emission); wiki + README;
  memory. If Fast DDS rejects/ignores (e.g. a vendor gate like the TypeLookup leg), record the
  finding honestly and fall back to the wire-level ACKNACK evidence.

**Two reviews per Lisp task (A, B); C reviewed for C++ quality; D is the live oracle.**
