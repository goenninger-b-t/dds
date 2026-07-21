# ADR 0069 — the ZC-loan KEEP_LAST drop must evict a copy-path sample, not only a loan view (github#1)

- **Status:** Accepted
- **Date:** 2026-07-20
- **Requirements:** FR-DCPS-4 (instance lifecycle / KEEP_LAST), FR-PF-3/4 (Zero-Copy loan), NFR-MEM (slot leak), NFR-TEST
- **Relates to:** ADR 0017 (FlatData ZC loan), ADR 0038 (secured loan — the sibling that was already correct)
- **Fixes:** github#1 (the `keyed-flatdata-loan-keeplast` full-suite flake)
- **Contract touched:** none (an internal correctness fix in `%reader-keeplast-drop-oldest-loan`)

## Symptom

`run-keyed-flatdata-loan-keeplast-test` failed intermittently under full-suite load, never in isolation.
A KEEP_LAST depth-2 keyed ZC-loan reader over 2 instances is expected to hold 4 samples (2 per instance).
Two observed failures:

- `dr-cache = 6` — the per-instance drop fired **0 times** (the original report);
- `dr-cache = 4` but `dr-loans = 3` — one loan seemingly over-released (the 2026-07-20 recurrence).

Because it needed concurrent scheduling pressure, it was tracked, not fixed, across several sessions —
with an explicit note not to ship a speculative fix that might mask an unverified Zero-Copy bug.

## Root cause (reproduced, not guessed)

The bug was found by systematic reproduction, not inspection. A harness replayed the test's exact loan
sequence under injected GC pressure and, after each drain, dumped every cached sample's SN, instance
handle, and — critically — whether its `data` was a `flatdata-view` (a ZC loan) or a plain struct (a
copy). The dump was unambiguous:

```
dr-cache=5 A=3 B=2
sn1 v#xA1 kindA loan-  slotNIL genNIL   <- a1: COPY-path sample (no slot, not in dr-loans)
sn3 v#xA2 kindA loanL  slot1            <- a2: ZC loan
sn5 v#xA3 kindA loanL  slot3            <- a3: ZC loan
```

Instance A kept **three** samples; `a1` was never evicted.

**The mechanism is a delivery-path MIX, not a refcount or handle race.** A FlatData reader's ZC-loan
capability arms slightly after the endpoint matches. A sample delivered in that window falls back to the
**copy path** — a legitimate, designed degrade (ADR 0017): its cached `data` is a deserialized struct, not
a `flatdata-view`, and it is not registered in `dr-loans`. So one instance can legitimately hold *both*
copy-path and loan-path samples.

When a later ZC loan (`a3`) arrives, `%drain-one-loan` calls `%reader-keeplast-drop-oldest-loan`, which
picks the instance's oldest sample (`a1`, the copy) and evicts it via `return-loan`. But `return-loan`
tears down **only** a `flatdata-view` or a secured handle — handed a plain copy struct, both branches miss
and it **silently returns without deleting the sample from `dr-cache`**. The eviction is skipped and
`dr-cache` grows past KEEP_LAST depth.

- `dr-cache = 6` is the case where **both** instances' oldest were copies (two skipped drops).
- `dr-cache = 4 / dr-loans = 3` is a partial mix (one skipped copy drop shifting the loan counts).

The secured sibling `%reader-keeplast-drop-oldest-secured` never had this bug: it already dispatches —
`(if (secured-loan-handle-p loan) (return-loan …) (delete oldest …))`. The plain ZC-loan drop simply
lacked the equivalent branch.

## Decision

`%reader-keeplast-drop-oldest-loan` dispatches on the evicted datum, mirroring the secured path:

```lisp
(let ((data (cached-sample-data oldest)))
  (if (dds.types:flatdata-view-p data)
      (return-loan dr (list data))                                ; ZC loan: full teardown (release slot + drop dr-loans + recycle)
      (setf (dr-cache dr) (delete oldest (dr-cache dr) :test #'eq))))  ; copy-path fallback: plain drop (private heap, nothing to release)
```

A copy sample's `data` is private heap memory, so a plain `dr-cache` delete is the correct and complete
eviction — there is no slot to release and no `dr-loans` entry to drop. The loan branch is unchanged, so
the pure-loan path (every existing green run) is byte-for-byte as before.

The copy fallback itself is **not** treated as the bug: early copy delivery is a legitimate degrade that
also occurs under real network conditions, so the drop must handle a mixed instance — "prevent copies"
would be the wrong fix.

## Verification

- **Deterministic regression test** (`run-keyed-flatdata-loan-mixed-copy-drop-test`, added): hand-builds a
  depth-2 instance holding a copy `SN1` + a loan-view `SN3` and drives the drop directly — no network, no
  threads, no ZC/SHMEM, so it runs on **every** implementation and fails **100 %** before the fix. It was
  **falsified** (reverted the fix → `KFDMC-COPY-EVICTED` fails; restored → passes).
- **Load reproduction**: the GC-pressure harness reproduced the end-state failure at iterations 10, 22 and
  50 before the fix; **200/200 clean** after it.
- 572/572 both impls (SBCL + Clasp), clean-cache builds self-falsified; gate-hotpath / gate-types /
  gate-nocond / gate-pal / corpus / gate-mem / mem / fuzz all green. `gate-mem` unchanged (2402.7 — the
  fix is off the measured perf-data path).

## Consequences

- github#1 is fixed at the root. The instrumentation added in the prior commit (the shared
  `%kfdkl-cache-dump` on both assertions) remains — it is what would have made the very first CI
  recurrence diagnosable, and it now guards the regression.
- **A latent gap remains, out of scope here and worth its own investigation:** `%reader-instance-oldest`
  applies `RELEASABLE-ONLY t` uniformly on the loan path, so a `:read` copy sample in a mixed instance is
  still not chosen as the drop target (a copy is always safe to drop regardless of read-state — only an
  app-held *view* is UAF-unsafe). No reproduction exercises this (the failing scenario's copy is always
  `:not-read` at drop time), so it is noted, not fixed, keeping this change to one root cause.
