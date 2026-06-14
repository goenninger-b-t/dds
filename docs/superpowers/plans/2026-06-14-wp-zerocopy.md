# WP-ZEROCOPY — Zero-Copy-over-SHMEM (best-effort v1) — Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** A writer places the serialized sample in a per-writer SHMEM sample-pool and transmits a ~16-byte reference (a new encapsulation) instead of the payload; a same-host ZC-capable reader maps the pool, reads the slot's payload, deserializes it, and releases the slot — best-effort, behind an off-by-default flag.

**Architecture:** ZC operates on the already-serialized SerializedPayload at the transport seam: `publish-sample` (writer) stores the payload in a SHMEM pool slot + sends a zc-encapsulated 16-byte ref over the existing DATA path; `%handle-datagram` (reader) resolves the ref → the slot's payload → the existing `on-data` (deserialize) path. Slot lifetime = explicit pshared-mutex refcount + generation guard + force-reclaim-on-exhaustion. The RTPS engine + DCPS codecs are untouched; with the flag off the path is byte-identical.

**Tech Stack:** Common Lisp (SBCL + Clasp), the WP-SHMEM PAL (`dds.pal:shm-*`/`pshared-*`/`load`/`store-sap-u64`), `dds-cdr` encapsulation headers, the dataplane (`dds-disc`), SEDP (`dds-rtps/discovery`).

**Authoritative spec:** `docs/superpowers/specs/2026-06-14-wp-zerocopy-design.md`.

## R6 — every task obeys this
**Default-OFF** (`dds.disc:*zerocopy-enabled*`, default `nil`) gates ALL ZC paths. Every new file carries a header line: `;;;; NOT cleared for ship — pending counsel (R6); see ADR 0014.` Clean-room from FR-PF-3 + the OMG spec — no RTI source. Commit messages cite FR-PF-3 + R6, no AI attribution. The flag must NOT be turned on by default in any task.

## Conventions (operating contract)
`defun*` + full function-type every fn; `defstruct*` every struct; ONE-LINE code comments (detail in commit messages); bounds-check the untrusted ref even at `(safety 0)`; reader conditionals only inside `dds-pal/`; SBOM auto-staged; FR-LANG-7 before/after bench for the hot-path change; docs in lockstep (§5.1). Commit autonomously with each task's message (pre-approved); do NOT pause for approval.

## Verified grounding
- WP-SHMEM PAL (done, on main): `dds.pal:shm-create(name size)`→shm-segment / `shm-attach` / `shm-detach` / `shm-destroy(name)` / `shm-sap(seg)`; `pshared-mutex-init(sap off)` / `pshared-lock`/`pshared-unlock`/`pshared-destroy(sap moff coff)`; `load-sap-u64(sap off)` / `store-sap-u64(sap off v)`; `(cffi:mem-ref sap :uint32 off)` for u32. shm name = `dds.xport.shmem:seg-name-for-guid(guid)`. host-uuid via `dds.disc` (MD5 of hostname) + the SHMEM `*shmem-enabled*` pattern.
- `dds.cdr:+representation-ids+` (alist name→u16, DDS-XTypes 1.3 Table 60), `representation-id-value`/`-name`, `make-encapsulation-header(cursor representation &optional options)`, `parse-encapsulation-header`. A SerializedPayload = `[representation-id:u16][options:u16][body]`.
- Writer: `dds.disc::publish-sample(node payload)` (dataplane.lisp:532) — payload is the full serialized SerializedPayload (octet-buffer/vector); calls `writer-write` (HistoryCache) + the push.
- Reader: `%handle-datagram` (disc.lisp ~820-870) parses DATA, extracts `[poff,plen)`, and for user data calls `(disc-node-on-data node)` with the payload region. ZC resolve inserts here, before `on-data`.
- SEDP: `dds.rtps.discovery` endpoint-data + serialize/parse (the WP-SHMEM E1 added `+pid-shmem-host-uuid+` + a SHMEM locator the same way — mirror it for the ZC-capable flag).
- `%shmem-dest` / `%send-raw-buf` (dataplane.lisp) — the same-host selection + single-transport discipline to mirror for `%zc-dest`.

## File structure
- **Create** `src/dds-xport/zerocopy-pool.lisp` (pkg `dds.xport.zerocopy`): the SHMEM sample-pool (segment layout, loan/store/publish/resolve/release, refcount+generation+force-reclaim). One responsibility: the pool data structure over a SAP.
- **Modify** `src/dds-cdr/cdr.lisp` (+ `packages.lisp`): the zc vendor encapsulation id constant + a `zc-reference` encode/decode (the 16-byte ref body).
- **Modify** `src/dds-rtps/discovery.lisp` (+ `message.lisp`, `packages.lisp`): the SEDP ZC-capable flag (a vendor PID), serialize/parse (fail-open).
- **Modify** `src/dds-disc/disc.lisp`: `*zerocopy-enabled*`, the per-node ZC pool slot + creation (when enabled), the `%zc-dest` resolver, the `%handle-datagram` resolve hook, teardown.
- **Modify** `src/dds-disc/dataplane.lisp`: the `publish-sample` ZC hook (pool-store + ref).
- **Modify** `src/dds-tests/echo-test.lisp` / `integration-test.lisp` / `pbt-test.lisp`: tests + fuzz. `src/dds-bench/perftest.lisp` + `Makefile`: ZC bench + 2-proc harness. `docs/adr/0014-*.md`, `docs/wiki/transports.md`, `README.md`, `docs/verification.csv`, `docs/provenance.md`: docs.
- `dds-xport.asd`: add `(:file "zerocopy-pool")` after `shmem`.

## Shared layout constants (define once in Task B1)
```
ZC segment: [ Header(64): magic u32 | version u32 | slot-count u32 | slot-bytes u32 | freelist-head u32
              | pad ; pthread mutex @64 (reserve 64) ] then slot-count slots @128.
Slot i @ (128 + i*(SLOT-HDR + slot-bytes)): [refcount u32 @+0 | generation u32 @+4 | len u32 @+8
              | publish-seq u64 @+16 (for force-reclaim "oldest") | pad to SLOT-HDR=32 | payload slot-bytes].
16-byte reference (SerializedPayload body after the encapsulation header):
  [slot-index u32 | generation u32 | slot-bytes u32 | reserved u32].
All u32/u64 LE; refcount/generation/freelist mutated only under the pshared mutex (Clasp parity, no CAS).
```

---

# Phase A — constants, flag, ADR 0014

### Task A1: ADR 0014 + *zerocopy-enabled* + the zc encapsulation id + SEDP ZC PID
**Files:** Create `docs/adr/0014-zerocopy-over-shmem.md`; Modify `src/dds-cdr/cdr.lisp` + `src/dds-cdr/packages.lisp`, `src/dds-rtps/message.lisp` + its packages, `src/dds-disc/disc.lisp` + `src/dds-disc/packages.lisp`.

- [ ] **Step 1: ADR 0014.** Match `docs/adr/0013-*.md` style. Record: WP-ZEROCOPY best-effort v1 (FR-PF-3); **R6 build-now/gate-ship, default-OFF, NOT-cleared-for-ship pending counsel**; the design (pool + 16-byte ref over a new encapsulation + pshared-mutex refcount + generation + force-reclaim); the pinned vendor constants (zc encapsulation id `#x4B43` "KC", SEDP `+pid-zerocopy-capable+ #x8041` — vendor range, ours, NOT a spec clause); clean-room provenance. (The exact values are pinned HERE.)
- [ ] **Step 2: zc encapsulation id** in `cdr.lisp` (beside `+representation-ids+`):
```lisp
(defconstant +zc-encapsulation-id+ #x4B43
  "Vendor SerializedPayload encapsulation id for a WP-ZEROCOPY 16-byte reference (ADR 0014; ours, NOT a
   spec clause). A reader without ZC sees an unknown representation id and ignores the sample (fail-open).")
```
   Export it from `dds-cdr` packages. (Do NOT add it to `+representation-ids+` — keep it distinct so normal CDR paths never select it.)
- [ ] **Step 3: SEDP ZC-capable PID** in `message.lisp`: `(defconstant +pid-zerocopy-capable+ #x8041 "Vendor PID: 1 = endpoint understands WP-ZEROCOPY refs (ADR 0014).")`. Export it.
- [ ] **Step 4: the flag** in `disc.lisp` (beside `*shmem-enabled*`):
```lisp
(defvar *zerocopy-enabled* nil
  "WP-ZEROCOPY master switch (FR-PF-3). DEFAULT NIL — Zero-Copy is patent-gated (R6) and NOT cleared for
   ship pending counsel; it never engages unless explicitly enabled. When T (and SHMEM is available + a
   matched reader is same-host + ZC-capable) the writer sends a 16-byte reference instead of the payload.")
```
   Export `*zerocopy-enabled*` from `dds.disc`.
- [ ] **Step 5:** build both impls (`ql:quickload :dds`), confirm clean load. **Commit:** `docs(xport): ADR 0014 + WP-ZEROCOPY constants + *zerocopy-enabled* (default-off, R6) (FR-PF-3)`

---

# Phase B — the SHMEM sample-pool (`src/dds-xport/zerocopy-pool.lisp`)

### Task B1: pool segment layout + create/attach + slot accessors
**Files:** Create `src/dds-xport/zerocopy-pool.lisp` (+ `packages.lisp` `dds.xport.zerocopy`), `dds-xport.asd`; Test `echo-test.lisp`.

- [ ] **Step 1: package + asd.** Add `dds.xport.zerocopy` (mirror `dds.xport.shmem` defpackage); `(:file "zerocopy-pool")` after `(:file "shmem")` in `dds-xport.asd`.
- [ ] **Step 2: failing test** `run-zc-pool-init-test` (register `("zc-pool-init" . run-zc-pool-init-test)`):
```lisp
(defun* run-zc-pool-init-test ()
    (function () (eql t))
  "Init a ZC pool in a foreign buffer; validate magic/version; slot-count + slot-bytes round-trip; all slots free."
  (let* ((slots 4) (sbytes 256) (m (dds.pal:alloc-static (dds.xport.zerocopy::%zc-bytes slots sbytes))))
    (unwind-protect
         (let ((sap (dds.pal:static-pointer m)))
           (dds.xport.zerocopy::%zc-init sap slots sbytes)
           (%check :valid (dds.xport.zerocopy::%zc-validate sap) "fresh pool validates")
           (%check :count (= slots (dds.xport.zerocopy::%zc-slot-count sap)) "slot-count round-trips")
           (%check :free (= slots (dds.xport.zerocopy::%zc-free-count sap)) "all slots free")
           (dds.pal:pshared-destroy sap dds.xport.zerocopy::+zc-mutex-off+ dds.xport.zerocopy::+zc-mutex-off+)
           t)
      (dds.pal:free-static m))))
```
- [ ] **Step 3: implement** the header file `zerocopy-pool.lisp`:
```lisp
;;;; L8 — WP-ZEROCOPY SHMEM sample-pool (FR-PF-3). Per-writer pool of fixed-size slots holding serialized
;;;; SerializedPayloads; the writer publishes a 16-byte reference instead of copying the payload.
;;;; NOT cleared for ship — pending counsel (R6); see ADR 0014. Clean-room from FR-PF-3 + the OMG spec.
(in-package #:dds.xport.zerocopy)

(defconstant +zc-magic+ #x5A434F31 "Pool ABI magic 'ZCO1' (ours; not a wire constant).")
(defconstant +zc-version+ 1)
(defconstant +zc-off-magic+ 0) (defconstant +zc-off-version+ 4) (defconstant +zc-off-slot-count+ 8)
(defconstant +zc-off-slot-bytes+ 12) (defconstant +zc-off-free-head+ 16)
(defconstant +zc-mutex-off+ 64)
(defconstant +zc-slots-off+ 128)
(defconstant +zc-slot-hdr+ 32)
(defconstant +zc-slot-off-refcount+ 0) (defconstant +zc-slot-off-generation+ 4)
(defconstant +zc-slot-off-len+ 8) (defconstant +zc-slot-off-pubseq+ 16)
(defconstant +zc-free-end+ #xFFFFFFFF "Freelist terminator (no next free slot).")

(defun* %zc-slot-stride (slot-bytes) (function ((integer 1)) (integer 1)) (+ +zc-slot-hdr+ slot-bytes))
(defun* %zc-bytes (slot-count slot-bytes)
    (function ((integer 1) (integer 1)) (integer 1))
  "Total pool segment size."
  (+ +zc-slots-off+ (* slot-count (%zc-slot-stride slot-bytes))))
(defun* %zc-slot-off (sap i)
    (function (t (integer 0)) (integer 0))
  (+ +zc-slots-off+ (* i (%zc-slot-stride (%zc-slot-bytes sap)))))
(defun* %zc-slot-count (sap) (function (t) (unsigned-byte 32)) (cffi:mem-ref sap :uint32 +zc-off-slot-count+))
(defun* %zc-slot-bytes (sap) (function (t) (unsigned-byte 32)) (cffi:mem-ref sap :uint32 +zc-off-slot-bytes+))

(defun* %zc-init (sap slot-count slot-bytes)
    (function (t (integer 1) (integer 1)) t)
  "Initialise the header + pshared mutex; thread all slots onto the freelist (slot i -> i+1, last -> END);
   zero refcount/generation. Creator-only."
  (setf (cffi:mem-ref sap :uint32 +zc-off-magic+) +zc-magic+
        (cffi:mem-ref sap :uint32 +zc-off-version+) +zc-version+
        (cffi:mem-ref sap :uint32 +zc-off-slot-count+) slot-count
        (cffi:mem-ref sap :uint32 +zc-off-slot-bytes+) slot-bytes
        (cffi:mem-ref sap :uint32 +zc-off-free-head+) 0)
  (dds.pal:pshared-mutex-init sap +zc-mutex-off+)
  (dotimes (i slot-count t)
    (let ((b (%zc-slot-off sap i)))
      (setf (cffi:mem-ref sap :uint32 (+ b +zc-slot-off-refcount+)) 0
            (cffi:mem-ref sap :uint32 (+ b +zc-slot-off-generation+)) 0
            ;; freelist next pointer is overlaid on the len field while free
            (cffi:mem-ref sap :uint32 (+ b +zc-slot-off-len+)) (if (= i (1- slot-count)) +zc-free-end+ (1+ i)))
      (dds.pal:store-sap-u64 sap (+ b +zc-slot-off-pubseq+) 0))))

(defun* %zc-validate (sap)
    (function (t) t)
  (and (= +zc-magic+ (cffi:mem-ref sap :uint32 +zc-off-magic+))
       (= +zc-version+ (cffi:mem-ref sap :uint32 +zc-off-version+))))

(defun* %zc-free-count (sap)
    (function (t) (integer 0))
  "Count free slots by walking the freelist (test/debug; not hot path)."
  (let ((n 0) (cur (cffi:mem-ref sap :uint32 +zc-off-free-head+)))
    (loop until (= cur +zc-free-end+) do (incf n)
          (setf cur (cffi:mem-ref sap :uint32 (+ (%zc-slot-off sap cur) +zc-slot-off-len+))))
    n))
```
   (Export `make-zc-pool`/etc. incrementally; `%`-internals reached via `::` from tests.)
- [ ] **Step 4: run** `run-zc-pool-init-test` SBCL+Clasp → `T`. Full suite no regression. **Commit:** `feat(xport): WP-ZEROCOPY SHMEM pool layout + init (R6, FR-PF-3)`

### Task B2: loan (free or force-reclaim-oldest) + publish + release (refcount under the mutex)
**Files:** Modify `zerocopy-pool.lisp`; Test `echo-test.lisp`.

- [ ] **Step 1: failing test** `run-zc-pool-loan-test` (register): loan all slots (freelist drains); the next loan force-reclaims the oldest (lowest pubseq) and bumps its generation; publish sets refcount; release decrements → 0 frees + returns to freelist; a release with a stale generation is a no-op.
```lisp
(defun* run-zc-pool-loan-test ()
    (function () (eql t))
  (let* ((slots 2) (sbytes 64) (m (dds.pal:alloc-static (dds.xport.zerocopy::%zc-bytes slots sbytes))))
    (unwind-protect
         (let ((sap (dds.pal:static-pointer m)) (pay (octets 1 2 3)))
           (dds.xport.zerocopy::%zc-init sap slots sbytes)
           (multiple-value-bind (i0 g0) (dds.xport.zerocopy::%zc-loan sap pay 0 3 1) ; 1 reader
             (declare (ignore g0))
             (multiple-value-bind (i1 g1) (dds.xport.zerocopy::%zc-loan sap pay 0 3 1)
               (declare (ignore g1))
               (%check :two (and i0 i1 (/= i0 i1)) "two distinct slots loaned")
               (multiple-value-bind (i2 g2) (dds.xport.zerocopy::%zc-loan sap pay 0 3 1) ; pool full -> force-reclaim oldest (i0)
                 (%check :reclaim (eql i2 i0) "force-reclaims the oldest slot")
                 (%check :gen-bumped (> g2 0) "generation bumped on reclaim")
                 (%check :release0 (dds.xport.zerocopy::%zc-release sap i1 g1) "release valid generation succeeds")
                 (%check :stale (not (dds.xport.zerocopy::%zc-release sap i0 0)) "release with stale generation is a no-op")
                 t)))
           )
      (dds.pal:free-static m))))
```
   (Adjust the exact `%zc-loan` return signature `(values slot-index generation)` to what you implement; keep the test asserting: distinct slots, force-reclaim-oldest, generation bump, valid-release-frees, stale-release-noops.)
- [ ] **Step 2: implement** under the pshared mutex (all freelist/refcount/generation mutations):
```lisp
(defvar *zc-pubseq* 0 "Process-local monotonic publish sequence for force-reclaim 'oldest' ordering.")

(defun* %zc-loan (sap payload off len readers)
    (function (t (simple-array (unsigned-byte 8) (*)) (integer 0) (integer 0) (integer 0))
              (values (or null (integer 0)) (unsigned-byte 32)))
  "Loan a slot for a PAYLOAD of LEN octets to READERS consumers: take a free slot, else force-reclaim the
   oldest published slot (lowest pubseq) to bound the pool + tolerate lost best-effort refs. Bump the slot's
   generation, copy the payload in, set refcount=READERS. Returns (values slot-index generation), or
   (values NIL 0) if LEN > slot-bytes. Single producer per pool (the owning writer)."
  (when (> len (%zc-slot-bytes sap)) (return-from %zc-loan (values nil 0)))
  (dds.pal:pshared-lock sap +zc-mutex-off+)
  (unwind-protect
       (let ((i (%zc-take-free-or-reclaim sap)))
         (let* ((b (%zc-slot-off sap i))
                (g (logand (1+ (cffi:mem-ref sap :uint32 (+ b +zc-slot-off-generation+))) #xFFFFFFFF)))
           (setf (cffi:mem-ref sap :uint32 (+ b +zc-slot-off-generation+)) g
                 (cffi:mem-ref sap :uint32 (+ b +zc-slot-off-len+)) len
                 (cffi:mem-ref sap :uint32 (+ b +zc-slot-off-refcount+)) readers)
           (dds.pal:store-sap-u64 sap (+ b +zc-slot-off-pubseq+) (incf *zc-pubseq*))
           (dotimes (k len) (setf (cffi:mem-ref sap :uint8 (+ b +zc-slot-hdr+ k)) (aref payload (+ off k))))
           (values i g)))
    (dds.pal:pshared-unlock sap +zc-mutex-off+)))

(defun* %zc-take-free-or-reclaim (sap)
    (function (t) (integer 0))
  "CALLER HOLDS THE MUTEX. Pop the freelist head; if empty, pick the published slot with the lowest pubseq
   (oldest) and detach it (its generation bump by the caller invalidates any in-flight ref to it)."
  (let ((head (cffi:mem-ref sap +zc-off-free-head+ :uint32)))
    (if (/= head +zc-free-end+)
        (progn (setf (cffi:mem-ref sap :uint32 +zc-off-free-head+)
                     (cffi:mem-ref sap :uint32 (+ (%zc-slot-off sap head) +zc-slot-off-len+)))
               head)
        (let ((oldest 0) (oldest-seq (dds.pal:load-sap-u64 sap (+ (%zc-slot-off sap 0) +zc-slot-off-pubseq+))))
          (dotimes (i (%zc-slot-count sap))
            (let ((s (dds.pal:load-sap-u64 sap (+ (%zc-slot-off sap i) +zc-slot-off-pubseq+))))
              (when (< s oldest-seq) (setf oldest i oldest-seq s))))
          oldest))))

(defun* %zc-release (sap slot-index generation)
    (function (t (integer 0) (unsigned-byte 32)) t)
  "A reader released slot SLOT-INDEX it read at GENERATION: validate (bounds + generation match), decrement
   refcount; at 0 push the slot back onto the freelist. Returns T if the release applied, NIL if stale/OOB
   (no-op — best-effort: a lost/forced-reclaimed ref). CALLER need not hold the mutex (taken here)."
  (when (>= slot-index (%zc-slot-count sap)) (return-from %zc-release nil))
  (dds.pal:pshared-lock sap +zc-mutex-off+)
  (unwind-protect
       (let ((b (%zc-slot-off sap slot-index)))
         (cond ((/= generation (cffi:mem-ref sap :uint32 (+ b +zc-slot-off-generation+))) nil) ; stale -> no-op
               (t (let ((rc (cffi:mem-ref sap :uint32 (+ b +zc-slot-off-refcount+))))
                    (when (plusp rc)
                      (setf (cffi:mem-ref sap :uint32 (+ b +zc-slot-off-refcount+)) (1- rc))
                      (when (= 1 rc) ; was 1 -> now 0 -> free it
                        (setf (cffi:mem-ref sap :uint32 (+ b +zc-slot-off-len+))
                              (cffi:mem-ref sap :uint32 +zc-off-free-head+)
                              (cffi:mem-ref sap :uint32 +zc-off-free-head+) slot-index)))
                    t))))
    (dds.pal:pshared-unlock sap +zc-mutex-off+)))
```
   *(NOTE: the `len` field is overloaded as the freelist "next" pointer while a slot is free, and as the payload length while published — a slot is never both. Document this one-line. Confirm `cffi:mem-ref` arg order `(sap type offset)` vs `(sap offset)` against the existing shmem.lisp usage and match it exactly.)*
- [ ] **Step 3: run** SBCL+Clasp → `T`; full suite no regression. **Commit:** `feat(xport): WP-ZEROCOPY pool loan/publish/release — refcount + generation + force-reclaim (R6, FR-PF-3)`

### Task B3: resolve (reader reads a slot's payload) + bounds/generation guard
**Files:** Modify `zerocopy-pool.lisp`; Test `echo-test.lisp` + fuzz in `pbt-test.lisp`.

- [ ] **Step 1: failing test** `run-zc-pool-resolve-test`: loan a payload, resolve (slot,generation) → copies the payload out into a sink + returns its len; a wrong generation or OOB slot → returns NIL (no copy, no OOB). Plus register a `fuzz-zc-resolve` in `run-pbt-tests` feeding random (slot,generation,bytes) → never OOB/error.
- [ ] **Step 2: implement:**
```lisp
(defun* %zc-resolve (sap slot-index generation sink)
    (function (t (integer 0) (unsigned-byte 32) (simple-array (unsigned-byte 8) (*))) (or null (integer 0)))
  "Reader: if SLOT-INDEX is in range AND its generation == GENERATION, copy the slot's LEN payload octets
   into SINK (capacity must be >= slot-bytes) and return LEN; else NIL (stale/forced-reclaimed/OOB ref —
   untrusted cross-process input, NFR-SEC-POSTURE: never OOB). Validates under the mutex; copies out under it
   (short — the writer can't force-reclaim a slot a reader holds the mutex on)."
  (when (>= slot-index (%zc-slot-count sap)) (return-from %zc-resolve nil))
  (dds.pal:pshared-lock sap +zc-mutex-off+)
  (unwind-protect
       (let ((b (%zc-slot-off sap slot-index)))
         (when (= generation (cffi:mem-ref sap :uint32 (+ b +zc-slot-off-generation+)))
           (let ((len (min (cffi:mem-ref sap :uint32 (+ b +zc-slot-off-len+)) (%zc-slot-bytes sap))))
             (dotimes (k len) (setf (aref sink k) (cffi:mem-ref sap :uint8 (+ b +zc-slot-hdr+ k))))
             len)))
    (dds.pal:pshared-unlock sap +zc-mutex-off+)))
```
   *(Resolve copies the slot payload OUT (one copy, into the reader sink) then the reader deserializes from the sink via the existing on-data path. This is the "deserialize-from-SHMEM" v1 — WP-FLATDATA later removes this copy by reading in place. The copy-under-mutex keeps the slot stable vs force-reclaim; `min` caps len defensively.)*
- [ ] **Step 3: run** + `make fuzz` → PASS (resolver never OOBs on garbage). Full suite green. **Commit:** `feat(xport): WP-ZEROCOPY pool resolve + bounds/generation guard + fuzz (NFR-SEC-POSTURE, R6)`

---

# Phase C — the zc reference codec (`src/dds-cdr/cdr.lisp`)

### Task C1: encode/decode the 16-byte zc reference with its encapsulation header
**Files:** Modify `src/dds-cdr/cdr.lisp` + packages; Test `echo-test.lisp`.

- [ ] **Step 1: failing test** `run-zc-ref-codec-test`: `encode-zc-reference` into a buffer produces `[+zc-encapsulation-id+ :u16][options:u16][slot:u32][gen:u32][slot-bytes:u32][reserved:u32]` (4 + 16 = 20 octets); `parse-zc-reference` round-trips (returns slot, gen, slot-bytes) and returns NIL for a non-zc encapsulation id (so the reader cheaply distinguishes zc from normal payloads).
- [ ] **Step 2: implement** `encode-zc-reference(cursor slot generation slot-bytes)` (write the encapsulation header via `make-encapsulation-header` is keyed by name — instead write the raw `+zc-encapsulation-id+` u16 + 0 options + the three u32s) and `parse-zc-reference(buf off len)` → `(values slot generation slot-bytes)` or NIL if the first u16 != `+zc-encapsulation-id+` or `len < 20`. Export both.
- [ ] **Step 3: run** SBCL+Clasp → `T`. **Commit:** `feat(cdr): WP-ZEROCOPY 16-byte reference codec + encapsulation id (R6, FR-PF-3)`

---

# Phase D — discovery + writer/reader integration (`dds-rtps`, `dds-disc`)

### Task D1: SEDP ZC-capable flag (advertise + parse, fail-open)
**Files:** Modify `src/dds-rtps/discovery.lisp` (+ endpoint-data, serialize/parse); Test `echo-test.lisp`.
- [ ] Mirror WP-SHMEM E1's `+pid-shmem-host-uuid+` pattern: add a `zerocopy-capable` boolean slot to `endpoint-data`; in the SEDP serializer emit `+pid-zerocopy-capable+` = 1 octet (1) when the local endpoint is ZC-capable (`*zerocopy-enabled*` + SHMEM available); in the parser read it (fail-open: absent/garbage → nil). Test `run-zc-sedp-flag-test`: round-trip an endpoint-data with the flag; absent → nil. Both impls. **Commit:** `feat(rtps): SEDP zerocopy-capable flag — fail-open (R6, FR-PF-3)`

### Task D2: node ZC pool + %zc-dest + writer publish hook
**Files:** Modify `src/dds-disc/disc.lisp` (node slot, creation, %zc-dest, teardown), `src/dds-disc/dataplane.lisp` (publish-sample hook); Test `integration-test.lisp`.
- [ ] **Step 1:** `disc-node` gains a `zc-pool` slot (a `dds.xport.zerocopy` pool handle + its shm-segment) + a `zc-sends` counter. In `make-disc-node`, when `(and *zerocopy-enabled* (disc-node-shmem node))`, create the ZC pool segment (name = `seg-name-for-guid` of the node guid + a "-zc" suffix; size from the shared `*zerocopy-default-slots*`/`*zerocopy-default-slot-bytes*`). Teardown in `stop-node` (after the receiver join; `pshared-destroy` + `shm-destroy`).
- [ ] **Step 2: `%zc-dest`** (dataplane.lisp, mirror `%shmem-dest`): given a matched reader's prefix, return the count of same-host + ZC-capable readers for this writer's data (a peer qualifies iff `*zerocopy-enabled*` + our zc-pool set + the remote's SPDP host-uuid == ours + the remote endpoint advertised `zerocopy-capable`). 0 → no ZC.
- [ ] **Step 3: publish-sample hook** (dataplane.lisp:532). Before the normal serialized push, if `(plusp (%zc-readers node))` (≥1 same-host ZC reader) AND the payload is large enough to benefit: `%zc-loan` the pool with the full `payload` (readers = the ZC-reader count); `encode-zc-reference` into a small scratch buffer; `writer-write` + push THAT zc-ref payload instead; `(incf (disc-node-zc-sends node))`. On `%zc-loan` returning NIL (payload > slot-bytes) → fall through to the normal serialized push (no loss). Exactly one of {zc-ref, serialized payload} is published.
- [ ] **Step 4: integration test** `run-zerocopy-end-to-end-test` (mirror `run-shmem-end-to-end-test`, guard SBCL): two nodes, same host, both `*zerocopy-enabled*` t; after match, publish N samples; assert the reader receives N (resolved via ZC) AND `zc-sends` advanced AND the pool slots return (free-count recovers). **Commit:** `feat(disc): WP-ZEROCOPY writer pool-store + ref-publish + %zc-dest selection (R6, FR-PF-3)`

### Task D3: reader resolve hook in %handle-datagram
**Files:** Modify `src/dds-disc/disc.lisp` (the user-data → on-data branch ~868).
- [ ] Before calling `(disc-node-on-data node)` with the user payload `[poff,plen)`: `parse-zc-reference` on the payload; if it IS a zc reference → derive the writer's ZC pool name from the DATA source GUID, `shm-attach` it (cached per source GUID), `%zc-resolve` into a per-node zc-sink buffer, `%zc-release` the slot, and call `on-data` with the RESOLVED payload region (the slot's serialized SerializedPayload) instead of the ref. A failed resolve (stale/OOB/attach-fail) → drop (best-effort). Else (normal payload) → existing `on-data` path unchanged. The reader sends its ACK as before — but note v1 is BEST-EFFORT, so this rides the best-effort path; reliable ZC is out of v1.
- [ ] Test: `run-zerocopy-end-to-end-test` (D2) now exercises this end-to-end. Add `run-zc-resolve-drop-test`: a zc-ref to a non-existent/garbage slot → reader drops, no crash. **Commit:** `feat(disc): WP-ZEROCOPY reader resolve hook in %handle-datagram — drop on bad ref (R6, NFR-SEC-POSTURE)`

---

# Phase E — bench, 2-process, docs

### Task E1: large-sample ZC vs SHMEM bench (FR-LANG-7)
**Files:** Modify `src/dds-bench/perftest.lisp` + `Makefile`; report `bench/report/2026-06-14-wp-zerocopy.md`.
- [ ] Add `run-bench-zerocopy` (reuse the latency/throughput harness with `*zerocopy-enabled*` t, LARGE payloads where the no-payload-copy win shows). Compare ZC vs SHMEM vs UDP for large samples: latency, throughput, bytes/sample (the transport-copy elimination). Assert `zc-sends` advanced. `make bench-zerocopy` → the report. Honest interpretation (the v1 win is large-sample transport-copy elimination; true 0-copy awaits FlatData). **Commit:** `bench(xport): WP-ZEROCOPY large-sample vs SHMEM/UDP + report (FR-LANG-7, R6)`

### Task E2: real 2-process ZC round-trip
**Files:** entry points in `src/dds-shapes/shapes.lisp` (mirror `run-shmem-xproc-*`), `scripts/zerocopy-roundtrip.sh`, `Makefile` `zc-xproc`.
- [ ] Two SBCL processes, `*zerocopy-enabled*` t, same host; pub sends N large samples (ZC), sub receives + asserts; pub prints `ZC-PUB-SENDS`, sub prints `ZC-SUB-RECEIVED`. `make zc-xproc` → PASS (sub received + pub zc-sends > 0). **Commit:** `test(xport): real 2-process WP-ZEROCOPY round-trip (R6, FR-PF-3)`

### Task E3: docs + verification + ADR 0014 finalize + provenance
**Files:** `docs/wiki/transports.md`, `README.md`, `docs/verification.csv` (FR-PF-3 row), `docs/adr/0014-*.md` (finalize), `docs/provenance.md`.
- [ ] Document the ZC transport (default-OFF, R6 NOT-cleared-for-ship, the mechanism, the large-sample win, the FlatData follow-up for true 0-copy, the best-effort-only v1, the Clasp/macOS gap inherited from SHMEM). verification.csv FR-PF-3 → partial (best-effort v1, behind flag, NOT-shippable-pending-counsel). provenance: clean-room from FR-PF-3 + OMG; the design-around-considerations note for counsel. **Commit:** `docs(xport): WP-ZEROCOPY wiki + README + verification + ADR 0014 + provenance (R6, §5.1)`

---

## Self-review
- **Spec coverage:** pool→B; refcount+generation+force-reclaim→B2; ref+encapsulation→A2/C1; writer pool-store+ref→D2; reader resolve→D3; SEDP flag→A3/D1; default-off flag→A4; safety/fuzz→B3/D3; bench→E1; 2-proc→E2; docs/provenance/R6→A1/E3; engine-untouched→D2/D3 (flag-off path unchanged) + E1 regression. All covered.
- **Placeholder scan:** every step has real code or a concrete mirror target (the D tasks mirror the verified WP-SHMEM `%shmem-dest`/`%send-raw-buf`/E1 patterns — repeat the shape, don't hand-wave). The two contingent spots (exact `cffi:mem-ref` arg order; the `%zc-loan` return arity) carry explicit "match the existing usage" instructions.
- **Type consistency:** `%zc-init`/`%zc-loan`/`%zc-release`/`%zc-resolve`/`%zc-slot-off`/`%zc-bytes` + constants `+zc-*+` used consistently; the ref is `(slot generation slot-bytes)` in C1, D2, D3; `*zerocopy-enabled*` + `zc-pool`/`zc-sends` consistent across D.
- **R6:** default-off flag (A4) gates every path; NOT-cleared-for-ship marker in every new file header; clean-room + provenance (A1/E3); no path turns the flag on by default.
- **Open risk:** the resolve copies the slot payload out (one copy) — v1 is "deserialize-from-SHMEM", not literal 0-copy; that's the documented FlatData follow-up. Best-effort only; reliable ZC deferred. `cffi:mem-ref` arg-order must be confirmed against shmem.lisp at B1 (flagged).
