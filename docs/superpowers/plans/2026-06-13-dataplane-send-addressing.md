# User data-plane send addressing — plan

Design: `docs/superpowers/specs/2026-06-13-dataplane-send-addressing-design.md`.
All changes in `src/dds-disc/dataplane.lisp` (internal `%`-helpers; no exported contract, no ADR).
Two independent reviewed commits.

## Shared helper (lands with Commit A)

`%prefix-user-destination(node, prefix)` → `(or null cons)`: user-plane twin of `%remote-metatraffic`
(disc.lisp:367). `gethash prefix (disc-node-discovered node)` under `disc-node-lock` → `%usable-destination`,
returning the `(host . port)` only when port > 0.

## Commit A — ACKNACK retransmit to the NACKing reader only (Fix 1)

1. Add `%prefix-user-destination`.
2. In `%on-user-acknack` (dataplane.lisp:421): replace the `(%match-destinations node t)` resend loop
   with `(or (and dest (list dest)) (%match-destinations node t))` where
   `dest = (%prefix-user-destination node src-prefix)`. Update the docstring to cite the single-reader
   addressing (RTPS 2.5 §8.4.2.2; src-prefix §9.4.4).
3. Tests (`src/dds-tests/`): `%prefix-user-destination` resolve + nil; a two-reader ACKNACK-addressing
   test asserting the resolved destination is the NACKing reader's.
4. Gates: `make test` SBCL + Clasp; gate-types; gate-hotpath. Bench row.
5. Present commit message for approval.

## Commit B — per-destination push grouping + union-send-once (Fix 2)

1. Rewrite `%reader-push-targets` (dataplane.lisp:181): build a destination→guids map (alist keyed by
   `(host . port)` equal), pushing each matched reader's full GUID into its destination's group; the
   static-PEERS fallback adds one group per peer carrying the local `user-reader-id`. Return
   `((host . port) guid…)` groups.
2. Rewrite `%push-data` (dataplane.lisp:207) destination loop: for each group, `writer-unsent-list` per
   co-located GUID (advances each watermark), merge changes by SN (dedup, ascending), `%send-change`
   the merged set once, then one `%send-user-heartbeat`.
3. Add a small `%merge-changes-by-sn` helper (ascending, dedup by `cache-change-sn`) — only if the
   merge is non-trivial; for the common shared-base case the lists are identical so a single
   `remove-duplicates :key sn` over the concatenation suffices.
4. Tests: `%reader-push-targets` returns one group with two GUIDs for co-located readers; both
   watermarks advance after a push; no history re-push on the next write.
5. Gates + bench row + verification.csv / docs-wiki + provenance touch if needed.
6. Present commit message for approval.

## Verification end-to-end

- `make test` (SBCL) + `make test-clasp` green, count ≥ 138 (+ new tests).
- `make gate-types`, `make gate-hotpath` green.
- Optional live re-confirm: existing UDP-loopback repair tests prove Fix 1 doesn't break recovery.
- `bench/report/2026-06-13-dataplane-send-addressing.md` committed.
- Update `dds-stack-position` / `dds-feature-backlog` memories: residue sub-follow-ups CLOSED.
