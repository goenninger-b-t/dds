# Send-side submessage coalescing — plan

Design: `docs/superpowers/specs/2026-06-13-change-coalescing-design.md`.
All in `src/dds-disc/dataplane.lisp` (internal `%`-helpers; no exported contract, no ADR). One commit.

## Steps

1. **Factor the raw send.** Extract `%send-raw-buf(node, buf, len, host, port)` (the `dds.xport:send`
   tail of `%send-msg-buf`); `%send-msg-buf` calls it. Add `*datagram-sink*` (default NIL; test capture)
   honored in `%send-raw-buf`.
2. **Packer.** Add `*coalesce-datagram-budget*` (1400, documented: avoid IP fragmentation) and
   `%send-packed(node, buf, host, port, builders)` (header once; append; flush+move on overflow; final
   flush) per the design.
3. **Builders + helper.** Add `%small-change-p(ch)`, `%data-builder(node, ch)`,
   `%heartbeat-builder(node, first, last, count)`, and `%send-changes-packed(node, buf, changes, host,
   port, hb)`. Remove the now-unused `%send-change`.
4. **Rewire.** `%push-data` → `%send-changes-packed` with the HEARTBEAT builder per destination;
   `%on-user-acknack` → `%send-changes-packed` (hb nil) to the resolved/fallback peer(s).
5. **Tests** (`src/dds-tests/integration-test.lisp` + register in `echo-test.lisp`): `coalesce-pack`,
   `coalesce-split` using `*datagram-sink*` + `dispatch-message` to parse captured datagrams.
6. **Gates + bench + docs.** `make test` SBCL + Clasp; gate-types; gate-hotpath. Bench report.
   verification.csv: extend FR-RTPS-ADDR or add FR-RTPS-COALESCE. Two reviews. Present commit.

## Verification end-to-end
- SBCL + Clasp suites green (≥ 140 + 2 new).
- gate-types, gate-hotpath green.
- `coalesce-pack`: 11 submessages → 1 datagram (parsed back, ≤ budget). `coalesce-split`: total
  preserved across ≥2 datagrams, each ≤ budget.
- All UDP-loopback dataplane regression tests green.
- `bench/report/2026-06-13-change-coalescing.md` committed.
- Update `dds-stack-position` / `dds-feature-backlog` memories: item 4 DONE.
