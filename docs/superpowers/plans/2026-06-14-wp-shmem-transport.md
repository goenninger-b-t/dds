# WP-SHMEM — shared-memory intra-host transport — Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** A same-host RTPS transport that delivers the identical serialized datagrams through a shared-memory ring instead of a UDP socket, auto-selected when both peers are on one host, with UDP as the fallback — the patent-clean foundation WP-ZEROCOPY (FR-PF-3) will build on.

**Architecture:** Per-receiver shared-memory segment (`mmap`) holding a header + K per-sender SPSC lanes; lock-free steady-state enqueue/drain (aligned 64-bit cursors + real acquire/release fences), one-time lane claim via foreign-SAP CAS; cross-process wake via a named POSIX semaphore (blocking wait + stop-flag/post-to-wake shutdown). It plugs into the **frozen** `dds.xport:transport` record, so the RTPS engine and `%handle-datagram` are untouched. A vendor-specific SHMEM `Locator_t` is advertised beside the UDP locator in SPDP; peers select SHMEM only when they share a host-uuid.

**Tech Stack:** Common Lisp (SBCL primary + Clasp), CFFI (`shm_open`/`mmap`/`sem_*` via `foreign-funcall`, mirroring `src/dds-pal/pal-net.lisp`), `sb-ext:cas`/`sb-thread:barrier` (SBCL, verified) and `mp:cas`/`mp:fence` (Clasp), the hand-rolled test harness (`%check` in `src/dds-tests/echo-test.lisp`), `dds-bench` (`src/dds-bench/perftest.lisp`).

**Authoritative spec:** `docs/superpowers/specs/2026-06-14-wp-shmem-transport-design.md`. **Conventions (operating contract):** every fn = `defun*` with a full function-type; every struct = `defstruct*`; one-line code comments only (detail goes in commit messages); no hardcoded wire constants from memory (cite the clause); bounds-check all foreign/shared-memory reads even at `(safety 0)`; no `#+sbcl`/`#+clasp` outside `dds-pal/`; SBOM auto-staged by the pre-commit hook; **present each commit message for approval; never add AI attribution.**

---

## Verified facts this plan rests on (probed, not assumed)
- `cas`/`atomic-incf` are M0 stubs that **signal `pal-unimplemented`**; `fence` is a **no-op ignoring `:kind`** — `pal-sbcl.lisp:81-96`, `pal-clasp.lisp:102-117`.
- **SBCL:** `(sb-ext:cas (sb-sys:sap-ref-64 sap off) old new)` and `(sb-ext:atomic-incf (sb-sys:sap-ref-64 sap off))` **compile + run**; `sb-thread:barrier (:read)/(:write)/(:memory)` present. CFFI foreign pointers on SBCL **are** `sb-sys:system-area-pointer`, usable directly with `sap-ref-*`.
- **Clasp:** `mp:cas` (macro), `mp:atomic-incf`/`-explicit`, `mp:fence` (fn) exist; foreign-place atomicity is confirmed by a probe task (Task A4) with a documented NFR-PORT fallback.
- Transport record: `src/dds-xport/transport.lisp:3-14` (function slots; engine-agnostic). UDP mirror: `src/dds-xport/udp.lisp:14-43` (`make-udp-transport` → `(values transport socket)`), receiver `udp.lisp:91-109`.
- disc-node transport slot `disc.lisp:50-51`; transport creation `disc.lisp:138-152`; receiver spawn `disc.lisp:833-847`; `%handle-datagram` `disc.lisp:751-752` `(function (disc-node octet-buffer (integer 0)) t)`.
- Locator struct `discovery.lisp:109-115`; `write-locator`/`read-locator` `discovery.lisp:70-77`; `+locator-kind-udpv4+ 1` `discovery.lisp:8`; SPDP serialize `discovery.lisp:181-193`; PIDs `message.lisp:689-692`; SPDP parse `discovery.lisp:221-232`. GUID prefix `entities.lisp:204-214` (no host-id today).
- PAL files: `pal-contract.lisp` (package+exports), `pal-clasp`/`pal-sbcl` (`:if-feature`), `pal-net.lisp` (shared CFFI). CFFI is a `dds-pal` dep. Test registry alist `echo-test.lisp:293-451`; `%check` `echo-test.lisp:3-14`. Bench `perftest.lisp:76-192`; `make bench` Makefile:160-163.

## Shared layout constants (every ring task references these — define once in Task C1)
```
HEADER:   off 0  magic u32 (#x53484D31 "SHM1") | 4 version u32 (1) | 8 lane-count u32
          | 12 capacity u32 (per-lane ring bytes) | 16 max-record u32 | 20 pad u32
HEADER-SIZE = 64 (cache line)         LANE-DESC-SIZE = 64 (cache line, no false sharing)
LANE DESC i @ (HEADER-SIZE + i*LANE-DESC-SIZE): +0 owner-token u64 | +8 write-cursor u64
          | +16 read-cursor u64 | +24..63 pad
RING DATA i @ (HEADER-SIZE + lane-count*LANE-DESC-SIZE + i*capacity), `capacity` bytes
Record in ring: [len u32][payload len bytes], whole span rounded UP to 8 bytes.
Cursors are MONOTONIC byte counters; ring position = cursor mod capacity.
Wrap: if a record's span won't fit contiguously before capacity end, writer emits a
SKIP marker (len = #xFFFFFFFF) and advances the cursor to the next capacity boundary.
capacity is a multiple of 8 so a 4-byte len always fits at any 8-aligned position.
```

---

# Phase A — PAL M1 atomics (real `fence` + foreign-SAP CAS/incf)  [ADR 0013]

### Task A1: ADR 0013 + reserve the new `dds.pal` exports

**Files:**
- Create: `docs/adr/0013-pal-shmem-and-m1-atomics.md`
- Modify: `src/dds-pal/pal-contract.lisp` (`:export` list, after `#:cas #:atomic-incf #:fence`)

- [ ] **Step 1: Write the ADR.** Content: WP-SHMEM extends the M0-frozen `dds.pal` contract with (a) SHMEM segment primitives, (b) named-semaphore primitives, (c) the M1 atomics fast path. Record that the M0 `cas`/`atomic-incf` `place-fn` form cannot be atomic, so the real atomics are **foreign-SAP-specific** (`cas-sap-u64`, `atomic-incf-sap-u64`, `load-sap-u64`, `store-sap-u64`) plus a real `fence`. List the SBCL/Clasp primitives (verified table from the spec). Consumer: `dds.xport.shmem` only. Decision: keep the unusable generic `cas`/`atomic-incf` stubs in place (no caller) to avoid an API break; new code uses the `-sap-u64` forms.

- [ ] **Step 2: Add exports.** In `pal-contract.lisp`, extend the atomics export line:
```lisp
 ;; atomics (M1: real fence + foreign-SAP 64-bit atomics for cross-process rings)
 #:cas #:atomic-incf #:fence
 #:cas-sap-u64 #:atomic-incf-sap-u64 #:load-sap-u64 #:store-sap-u64
 ;; shared memory segments + cross-process named semaphores (FR-XPORT-2)
 #:shm-create #:shm-attach #:shm-detach #:shm-destroy #:shm-sap #:shm-segment-size
 #:sem-create #:sem-open #:sem-post #:sem-wait #:sem-close #:sem-unlink
```

- [ ] **Step 3: Build to confirm exports resolve** (no defs yet → only the package compiles).
Run: `./scripts/with-sbcl.sh --eval '(ql:quickload :dds-pal :silent t)' --eval '(uiop:quit 0)'`
Expected: loads (exported-but-undefined symbols are legal until called).

- [ ] **Step 4: Commit.**
```bash
git add docs/adr/0013-pal-shmem-and-m1-atomics.md src/dds-pal/pal-contract.lisp
git commit -m "$(printf 'docs(pal): ADR 0013 — SHMEM + M1 atomics PAL extension (FR-XPORT-2)\n\nReserve dds.pal exports for foreign-SAP atomics + SHMEM segment/semaphore primitives.')"
```

### Task A2: real `fence` (both impls)

**Files:**
- Modify: `src/dds-pal/pal-sbcl.lisp:93-96`, `src/dds-pal/pal-clasp.lisp:114-117`
- Test: `src/dds-tests/echo-test.lisp` (new `run-pal-fence-test`, registered)

- [ ] **Step 1: Write the failing test.** Add to `echo-test.lisp` and register `("pal-fence" . run-pal-fence-test)` in the alist (`echo-test.lisp:293-451`):
```lisp
(defun* run-pal-fence-test ()
    (function () (eql t))
  "fence must accept :acquire/:release/:full and return without error (real barrier, not the M0 no-op)."
  (dolist (k '(:acquire :release :full) t)
    (dds.pal:fence k)))
```
- [ ] **Step 2: Run, expect PASS-but-meaningless** (the no-op already returns). Run: `./scripts/with-sbcl.sh --eval '(ql:quickload :dds-tests :silent t)' --eval '(princ (dds.tests::run-pal-fence-test))' --eval '(uiop:quit 0)'` Expected: `T` (this test guards the contract, not the barrier emission — the real proof is the cross-process ring test in Task C/F).
- [ ] **Step 3: Implement SBCL.** Replace `pal-sbcl.lisp:93-96`:
```lisp
(defun* fence (&optional (kind :full))
    (function (&optional t) (values))
  "Real memory barrier (M1). :acquire = load barrier, :release = store barrier, :full = full."
  (ecase kind
    (:acquire (sb-thread:barrier (:read)))
    (:release (sb-thread:barrier (:write)))
    (:full    (sb-thread:barrier (:memory))))
  (values))
```
- [ ] **Step 4: Implement Clasp.** Replace `pal-clasp.lisp:114-117`:
```lisp
(defun* fence (&optional (kind :full))
    (function (&optional t) (values))
  "Real memory barrier (M1) via mp:fence. Clasp's fence is a full barrier; kind is advisory."
  (declare (ignore kind))
  (mp:fence)
  (values))
```
- [ ] **Step 5: Run both.** Run: `./scripts/with-sbcl.sh ...run-pal-fence-test` and `GC_DONT_GC=1 ./scripts/with-clasp.sh ...run-pal-fence-test` Expected: `T` both.
- [ ] **Step 6: Commit.** `feat(pal): real memory fence (sb-thread:barrier / mp:fence), replacing the M0 no-op (FR-XPORT-2)`

### Task A3: foreign-SAP 64-bit atomics — SBCL

**Files:** Modify `src/dds-pal/pal-sbcl.lisp` (after `fence`); Test `echo-test.lisp` (`run-pal-sap-atomics-test`).

- [ ] **Step 1: Failing test** (register `("pal-sap-atomics" . run-pal-sap-atomics-test)`):
```lisp
(defun* run-pal-sap-atomics-test ()
    (function () (eql t))
  "cas-sap-u64 / atomic-incf-sap-u64 / load/store on a foreign 8-byte region behave atomically (single-thread correctness)."
  (let ((m (dds.pal:alloc-static 16)))
    (unwind-protect
         (let ((sap (dds.pal:static-pointer m)))
           (dds.pal:store-sap-u64 sap 0 0)
           (%check :cas-ok   (= 0 (dds.pal:cas-sap-u64 sap 0 0 42)) "cas returns prev")
           (%check :cas-set  (= 42 (dds.pal:load-sap-u64 sap 0)) "cas stored new")
           (%check :cas-fail (= 42 (dds.pal:cas-sap-u64 sap 0 0 99)) "cas mismatch returns prev")
           (%check :cas-nochg (= 42 (dds.pal:load-sap-u64 sap 0)) "cas mismatch no write")
           (%check :incf (= 47 (dds.pal:atomic-incf-sap-u64 sap 0 5)) "incf returns new")
           t)
      (dds.pal:free-static m))))
```
*(Note: `static-pointer` returns the same kind of SAP CFFI yields; `alloc-static` memory is 8-aligned.)*
- [ ] **Step 2: Run, expect FAIL** (`pal-unimplemented`/undefined). Run as in A2.
- [ ] **Step 3: Implement SBCL:**
```lisp
(defun* load-sap-u64 (sap offset)
    (function (t (integer 0)) (unsigned-byte 64))
  "Aligned 64-bit read of the foreign location at SAP+OFFSET (bytes)."
  (sb-sys:sap-ref-64 sap offset))
(defun* store-sap-u64 (sap offset value)
    (function (t (integer 0) (unsigned-byte 64)) (unsigned-byte 64))
  "Aligned 64-bit write of VALUE at SAP+OFFSET (bytes)."
  (setf (sb-sys:sap-ref-64 sap offset) value))
(defun* cas-sap-u64 (sap offset old new)
    (function (t (integer 0) (unsigned-byte 64) (unsigned-byte 64)) (unsigned-byte 64))
  "Atomic compare-and-swap of the u64 at SAP+OFFSET; returns the PREVIOUS value (= OLD on success)."
  (sb-ext:cas (sb-sys:sap-ref-64 sap offset) old new))
(defun* atomic-incf-sap-u64 (sap offset delta)
    (function (t (integer 0) (unsigned-byte 64)) (unsigned-byte 64))
  "Atomically add DELTA to the u64 at SAP+OFFSET; returns the NEW value."
  (+ delta (sb-ext:atomic-incf (sb-sys:sap-ref-64 sap offset) delta)))
```
- [ ] **Step 4: Run, expect PASS** on SBCL.
- [ ] **Step 5: Commit.** `feat(pal): foreign-SAP 64-bit atomics for SBCL (sb-ext:cas/atomic-incf on sap-ref-64) (FR-XPORT-2)`

### Task A4: foreign-SAP 64-bit atomics — Clasp (probe-first, NFR-PORT fallback)

**Files:** Modify `src/dds-pal/pal-clasp.lisp`; Test reuses `run-pal-sap-atomics-test`.

- [ ] **Step 1: Probe** whether `mp:cas`/`mp:atomic-incf` target a foreign place. Run:
```
GC_DONT_GC=1 ./scripts/with-clasp.sh --eval '(ql:quickload :cffi :silent t)' \
  --eval '(let ((m (static-vectors:make-static-vector 16 :element-type (quote (unsigned-byte 8)))))
            (let ((p (static-vectors:static-vector-pointer m)))
              (handler-case (progn (setf (cffi:mem-ref p :uint64 0) 0)
                                   (mp:cas (cffi:mem-ref p :uint64 0) 0 7)
                                   (format t "CLASP-FOREIGN-CAS: OK ~a~%" (cffi:mem-ref p :uint64 0)))
                (error (e) (format t "CLASP-FOREIGN-CAS: FAIL ~a~%" (type-of e))))))' \
  --eval '(uiop:quit 0)'
```
- [ ] **Step 2a: If the probe prints `OK 7`** — implement with CFFI places:
```lisp
(defun* load-sap-u64 (sap offset)
    (function (t (integer 0)) (unsigned-byte 64))
  (cffi:mem-ref sap :uint64 offset))
(defun* store-sap-u64 (sap offset value)
    (function (t (integer 0) (unsigned-byte 64)) (unsigned-byte 64))
  (setf (cffi:mem-ref sap :uint64 offset) value))
(defun* cas-sap-u64 (sap offset old new)
    (function (t (integer 0) (unsigned-byte 64) (unsigned-byte 64)) (unsigned-byte 64))
  (mp:cas (cffi:mem-ref sap :uint64 offset) old new))
(defun* atomic-incf-sap-u64 (sap offset delta)
    (function (t (integer 0) (unsigned-byte 64)) (unsigned-byte 64))
  (mp:atomic-incf (cffi:mem-ref sap :uint64 offset) delta))
```
*(Adjust the `mp:cas`/`mp:atomic-incf` return-value convention to match the probe: if `mp:cas` returns a boolean rather than the prev value, wrap it — read prev, cas, return prev — and if `mp:atomic-incf` returns the old value, return `(+ delta old)`. Verify against the probe output before finalizing.)*
- [ ] **Step 2b: If the probe FAILS** — implement `load`/`store` via `cffi:mem-ref` (non-atomic R/W are fine for header/cursor *reads*) and make `cas-sap-u64`/`atomic-incf-sap-u64` **signal `pal-unimplemented`**, then record an **NFR-PORT gap**: WP-SHMEM's lock-free lane path is SBCL-only; Clasp uses the UDP transport (the SHMEM transport simply isn't constructed on Clasp — see Task E2 guard). Note the gap in `docs/verification.csv` and the ADR. This mirrors the existing Clasp NFR-PORT latitude.
- [ ] **Step 3: Run** `run-pal-sap-atomics-test` on Clasp (expect PASS if 2a; expect the test to be skipped/guarded if 2b).
- [ ] **Step 4: Commit.** `feat(pal): foreign-SAP 64-bit atomics for Clasp via mp:cas/mp:atomic-incf (or documented NFR-PORT gap) (FR-XPORT-2)`

---

# Phase B — PAL SHMEM segment + named-semaphore primitives (shared CFFI in `pal-net.lisp`)

### Task B1: SHMEM segment primitives

**Files:** Modify `src/dds-pal/pal-net.lisp` (append; it is the shared, no-reader-conditional CFFI file loaded for both impls); Test `echo-test.lisp` (`run-pal-shm-test`).

- [ ] **Step 1: Failing test** (register `("pal-shm" . run-pal-shm-test)`):
```lisp
(defun* run-pal-shm-test ()
    (function () (eql t))
  "Create a segment, write a u32 through one mapping, attach a SECOND mapping by name, read it back, destroy."
  (let* ((name "/dds-test-shm-b1") (size 4096))
    (ignore-errors (dds.pal:shm-destroy name))     ; reclaim a stale leftover
    (let ((seg (dds.pal:shm-create name size)))
      (unwind-protect
           (let ((seg2 (dds.pal:shm-attach name size)))
             (unwind-protect
                  (progn
                    (setf (cffi:mem-ref (dds.pal:shm-sap seg) :uint32 0) #xCAFEF00D)
                    (%check :shm-shared (= #xCAFEF00D (cffi:mem-ref (dds.pal:shm-sap seg2) :uint32 0))
                            "second mapping sees the first's write")
                    t)
               (dds.pal:shm-detach seg2)))
        (dds.pal:shm-detach seg)
        (dds.pal:shm-destroy name)))))
```
- [ ] **Step 2: Run, expect FAIL** (undefined).
- [ ] **Step 3: Implement** in `pal-net.lisp` (mirror the `#+darwin`/`#-darwin` constant pattern at `pal-net.lisp:25-38`):
```lisp
;; open(2)/mmap(2) flag values are OS-specific (Darwin vs Linux), not impl-specific.
#+darwin (progn (defconstant +o-creat+ #x0200) (defconstant +o-excl+ #x0800))
#-darwin (progn (defconstant +o-creat+ #x40)   (defconstant +o-excl+ #x80))
(defconstant +o-rdwr+ 2)
(defconstant +prot-rw+ 3)            ; PROT_READ|PROT_WRITE (1|2), same on Darwin+Linux
(defconstant +map-shared+ 1)         ; same on Darwin+Linux
(defconstant +map-failed-addr+ (1- (ash 1 64)))   ; mmap returns (void*)-1 on failure (LP64)

(defstruct* shm-segment
  "A mapped POSIX shared-memory object: NAME (e.g. \"/dds...\"), FD, foreign SAP, byte SIZE."
  (name "" :type string) (fd -1 :type fixnum) (sap nil :type t) (size 0 :type (integer 0)))

(defun* %mmap-shared (fd size)
    (function (fixnum (integer 1)) t)
  "mmap SIZE bytes of FD shared R/W; signal on MAP_FAILED. Returns the foreign SAP."
  (let ((p (cffi:foreign-funcall "mmap" :pointer (cffi:null-pointer) :unsigned-long size
                                 :int +prot-rw+ :int +map-shared+ :int fd :long 0 :pointer)))
    (when (= (cffi:pointer-address p) +map-failed-addr+) (error "mmap failed (size=~a)" size))
    p))

(defun* shm-create (name size)
    (function (string (integer 1)) shm-segment)
  "Create+map an exclusive POSIX shm object NAME of SIZE bytes (shm_open O_CREAT|O_EXCL,
   ftruncate, mmap MAP_SHARED). A stale leftover (EEXIST) is unlinked and recreated."
  (let ((fd (cffi:foreign-funcall "shm_open" :string name
                                  :int (logior +o-creat+ +o-excl+ +o-rdwr+) :unsigned-int #o600 :int)))
    (when (minusp fd)
      (cffi:foreign-funcall "shm_unlink" :string name :int)    ; reclaim a crashed peer's segment
      (setf fd (cffi:foreign-funcall "shm_open" :string name
                                     :int (logior +o-creat+ +o-excl+ +o-rdwr+) :unsigned-int #o600 :int)))
    (when (minusp fd) (error "shm_open(create ~a) failed" name))
    (when (minusp (cffi:foreign-funcall "ftruncate" :int fd :long size :int))
      (cffi:foreign-funcall "close" :int fd :int) (error "ftruncate(~a) failed" name))
    (handler-case (make-shm-segment :name name :fd fd :sap (%mmap-shared fd size) :size size)
      (error (e) (cffi:foreign-funcall "close" :int fd :int) (error e)))))

(defun* shm-attach (name size)
    (function (string (integer 1)) shm-segment)
  "Open+map an EXISTING shm object NAME of SIZE bytes (shm_open O_RDWR, mmap)."
  (let ((fd (cffi:foreign-funcall "shm_open" :string name :int +o-rdwr+ :unsigned-int #o600 :int)))
    (when (minusp fd) (error "shm_open(attach ~a) failed" name))
    (handler-case (make-shm-segment :name name :fd fd :sap (%mmap-shared fd size) :size size)
      (error (e) (cffi:foreign-funcall "close" :int fd :int) (error e)))))

(defun* shm-sap (segment) (function (shm-segment) t) "Foreign SAP base of SEGMENT." (shm-segment-sap segment))
(defun* shm-detach (segment)
    (function (shm-segment) t)
  "munmap + close SEGMENT (does not unlink the name)."
  (cffi:foreign-funcall "munmap" :pointer (shm-segment-sap segment) :unsigned-long (shm-segment-size segment) :int)
  (cffi:foreign-funcall "close" :int (shm-segment-fd segment) :int))
(defun* shm-destroy (name) (function (string) t) "shm_unlink NAME." (cffi:foreign-funcall "shm_unlink" :string name :int))
```
- [ ] **Step 4: Run on SBCL + Clasp, expect PASS.** (Clasp needs `GC_DONT_GC=1`.)
- [ ] **Step 5: Commit.** `feat(pal): POSIX shared-memory segment primitives (shm_open/ftruncate/mmap) (FR-XPORT-2)`

### Task B2: named-semaphore primitives

**Files:** Modify `src/dds-pal/pal-net.lisp` (append); Test `echo-test.lisp` (`run-pal-sem-test`).

- [ ] **Step 1: Failing test** (register `("pal-sem" . run-pal-sem-test)`):
```lisp
(defun* run-pal-sem-test ()
    (function () (eql t))
  "Create a named semaphore, post then wait (must not block), clean up."
  (let ((name "/dds-test-sem-b2"))
    (ignore-errors (dds.pal:sem-unlink name))
    (let ((s (dds.pal:sem-create name 0)))
      (unwind-protect
           (progn (dds.pal:sem-post s) (dds.pal:sem-wait s) t)  ; posted once -> wait returns
        (dds.pal:sem-close s) (dds.pal:sem-unlink name)))))
```
- [ ] **Step 2: Run, expect FAIL.**
- [ ] **Step 3: Implement** in `pal-net.lisp`:
```lisp
(defconstant +sem-failed-addr+ (1- (ash 1 64)))   ; sem_open returns (sem_t*)-1 on failure

(defun* sem-create (name initial)
    (function (string (integer 0)) t)
  "Create an exclusive named POSIX semaphore NAME with INITIAL count; reclaim a stale leftover."
  (let ((s (cffi:foreign-funcall "sem_open" :string name :int (logior +o-creat+ +o-excl+)
                                 :unsigned-int #o600 :unsigned-int initial :pointer)))
    (when (= (cffi:pointer-address s) +sem-failed-addr+)
      (cffi:foreign-funcall "sem_unlink" :string name :int)
      (setf s (cffi:foreign-funcall "sem_open" :string name :int (logior +o-creat+ +o-excl+)
                                    :unsigned-int #o600 :unsigned-int initial :pointer)))
    (when (= (cffi:pointer-address s) +sem-failed-addr+) (error "sem_open(create ~a) failed" name))
    s))
(defun* sem-open (name)
    (function (string) t)
  "Open an EXISTING named POSIX semaphore NAME."
  (let ((s (cffi:foreign-funcall "sem_open" :string name :int 0 :pointer)))
    (when (= (cffi:pointer-address s) +sem-failed-addr+) (error "sem_open(open ~a) failed" name))
    s))
(defun* sem-post (sem) (function (t) t) "Increment SEM (wake one waiter)." (cffi:foreign-funcall "sem_post" :pointer sem :int))
(defun* sem-wait (sem) (function (t) t) "Block until SEM > 0 then decrement." (cffi:foreign-funcall "sem_wait" :pointer sem :int))
(defun* sem-close (sem) (function (t) t) "Close this process's handle to SEM." (cffi:foreign-funcall "sem_close" :pointer sem :int))
(defun* sem-unlink (name) (function (string) t) "Remove the named semaphore NAME." (cffi:foreign-funcall "sem_unlink" :string name :int))
```
- [ ] **Step 4: Run SBCL + Clasp, expect PASS.**
- [ ] **Step 5: Commit.** `feat(pal): named POSIX semaphore primitives (sem_open/post/wait/unlink) (FR-XPORT-2)`

---

# Phase C — the SHMEM ring (pure logic over a SAP; `src/dds-xport/shmem.lisp`)

### Task C1: package, layout constants, init/attach header

**Files:** Modify `src/dds-xport/packages.lisp` (add `dds.xport.shmem`), `dds-xport.asd` (add `(:file "shmem")` after `udp`); Create `src/dds-xport/shmem.lisp`; Test `echo-test.lisp` (`run-shmem-ring-init-test`).

- [ ] **Step 1: Add the package** to `src/dds-xport/packages.lisp` (mirror the `dds.xport.udp` defpackage), exporting (incrementally) `make-shmem-transport shmem-locator make-shmem-locator shmem-locator-name shmem-locator-host-uuid start-shmem-receiver run-shmem-transport-test run-shmem-receiver-test` plus the internal helpers needed by tests.
- [ ] **Step 2: Add `(:file "shmem")`** to `dds-xport.asd` after `(:file "udp")`. (dds-xport already pulls `dds.pal` transitively via dds-core.)
- [ ] **Step 3: Failing test** (register `("shmem-ring-init" . run-shmem-ring-init-test)`):
```lisp
(defun* run-shmem-ring-init-test ()
    (function () (eql t))
  "Init a ring header in a foreign buffer; attach validates magic/version; lane count/capacity round-trip."
  (let* ((lanes 4) (cap 4096)
         (bytes (dds.xport.shmem::%segment-bytes lanes cap))
         (m (dds.pal:alloc-static bytes)))
    (unwind-protect
         (let ((sap (dds.pal:static-pointer m)))
           (dds.xport.shmem::%ring-init sap lanes cap)
           (%check :magic-ok (dds.xport.shmem::%ring-validate sap) "validate passes on a fresh ring")
           (%check :lanes (= lanes (dds.xport.shmem::%ring-lane-count sap)) "lane count round-trips")
           (%check :cap (= cap (dds.xport.shmem::%ring-capacity sap)) "capacity round-trips")
           t)
      (dds.pal:free-static m))))
```
- [ ] **Step 4: Implement** `src/dds-xport/shmem.lisp` header (constants + helpers):
```lisp
;;;; L7 — POSIX shared-memory intra-host transport (FR-XPORT-2). Wraps the frozen
;;;; DDS.XPORT transport record around DDS.PAL SHMEM segments + named semaphores +
;;;; foreign-SAP atomics. Per-receiver segment: header + K per-sender SPSC lanes.
(in-package #:dds.xport.shmem)

(defconstant +shm-magic+ #x53484D31 "Ring ABI magic 'SHM1' (this project's own; not a wire constant).")
(defconstant +shm-version+ 1)
(defconstant +header-size+ 64)        ; cache line
(defconstant +lane-desc-size+ 64)     ; cache line, avoids head/tail false sharing
(defconstant +off-magic+ 0) (defconstant +off-version+ 4) (defconstant +off-lane-count+ 8)
(defconstant +off-capacity+ 12) (defconstant +off-max-record+ 16)
(defconstant +lane-off-owner+ 0) (defconstant +lane-off-write+ 8) (defconstant +lane-off-read+ 16)
(defconstant +skip-marker+ #xFFFFFFFF "Ring record len meaning 'pad to capacity boundary'.")

(defun* %segment-bytes (lane-count capacity)
    (function ((integer 1) (integer 8)) (integer 1))
  "Total segment size: header + lane descriptors + per-lane ring data."
  (+ +header-size+ (* lane-count +lane-desc-size+) (* lane-count capacity)))
(defun* %lane-desc-off (i) (function ((integer 0)) (integer 0)) (+ +header-size+ (* i +lane-desc-size+)))
(defun* %lane-data-off (lane-count i capacity)
    (function ((integer 1) (integer 0) (integer 8)) (integer 0))
  (+ +header-size+ (* lane-count +lane-desc-size+) (* i capacity)))
(defun* %ring-lane-count (sap) (function (t) (unsigned-byte 32)) (cffi:mem-ref sap :uint32 +off-lane-count+))
(defun* %ring-capacity (sap) (function (t) (unsigned-byte 32)) (cffi:mem-ref sap :uint32 +off-capacity+))
(defun* %ring-max-record (sap) (function (t) (unsigned-byte 32)) (cffi:mem-ref sap :uint32 +off-max-record+))

(defun* %ring-init (sap lane-count capacity)
    (function (t (integer 1) (integer 8)) t)
  "Initialise the header + zero all lane cursors/owners. CAPACITY must be a multiple of 8."
  (assert (zerop (mod capacity 8)))
  (setf (cffi:mem-ref sap :uint32 +off-magic+) +shm-magic+
        (cffi:mem-ref sap :uint32 +off-version+) +shm-version+
        (cffi:mem-ref sap :uint32 +off-lane-count+) lane-count
        (cffi:mem-ref sap :uint32 +off-capacity+) capacity
        (cffi:mem-ref sap :uint32 +off-max-record+) (- capacity 8))
  (dotimes (i lane-count t)
    (let ((b (%lane-desc-off i)))
      (dds.pal:store-sap-u64 sap (+ b +lane-off-owner+) 0)
      (dds.pal:store-sap-u64 sap (+ b +lane-off-write+) 0)
      (dds.pal:store-sap-u64 sap (+ b +lane-off-read+) 0))))

(defun* %ring-validate (sap)
    (function (t) t)
  "T iff SAP holds a ring of the expected magic + version (ABI guard on attach)."
  (and (= +shm-magic+ (cffi:mem-ref sap :uint32 +off-magic+))
       (= +shm-version+ (cffi:mem-ref sap :uint32 +off-version+))))
```
- [ ] **Step 5: Run SBCL + Clasp, expect PASS.**
- [ ] **Step 6: Commit.** `feat(xport): SHMEM ring header layout + init/validate (FR-XPORT-2)`

### Task C2: lane claim (one-time foreign CAS)

**Files:** Modify `src/dds-xport/shmem.lisp`; Test `echo-test.lisp` (`run-shmem-lane-claim-test`).

- [ ] **Step 1: Failing test** (register `("shmem-lane-claim" . run-shmem-lane-claim-test)`):
```lisp
(defun* run-shmem-lane-claim-test ()
    (function () (eql t))
  "Two distinct tokens claim two distinct lanes; a full ring returns NIL; re-claim of the same token is idempotent."
  (let* ((lanes 2) (cap 4096) (m (dds.pal:alloc-static (dds.xport.shmem::%segment-bytes lanes cap))))
    (unwind-protect
         (let ((sap (dds.pal:static-pointer m)))
           (dds.xport.shmem::%ring-init sap lanes cap)
           (let ((a (dds.xport.shmem::%claim-lane sap #xA11CE))
                 (b (dds.xport.shmem::%claim-lane sap #xB0B)))
             (%check :two-lanes (and a b (/= a b)) "two tokens get two distinct lanes")
             (%check :idem (= a (dds.xport.shmem::%claim-lane sap #xA11CE)) "same token re-finds its lane")
             (%check :full (null (dds.xport.shmem::%claim-lane sap #xC0FFEE)) "third token: ring full -> NIL")
             t))
      (dds.pal:free-static m))))
```
- [ ] **Step 2: Run, expect FAIL.**
- [ ] **Step 3: Implement:**
```lisp
(defun* %claim-lane (sap token)
    (function (t (unsigned-byte 64)) (or null (integer 0)))
  "Claim a lane for TOKEN (a nonzero per-sender id): return this token's existing lane index, else
   CAS TOKEN into a free (owner=0) lane and return it, else NIL (all lanes taken). One-time, off the
   hot path. TOKEN must be nonzero (0 marks a free lane)."
  (let ((n (%ring-lane-count sap)))
    (dotimes (i n)                                  ; already mine?
      (when (= token (dds.pal:load-sap-u64 sap (+ (%lane-desc-off i) +lane-off-owner+))) (return-from %claim-lane i)))
    (dotimes (i n nil)                              ; claim a free one
      (let ((o (+ (%lane-desc-off i) +lane-off-owner+)))
        (when (and (zerop (dds.pal:load-sap-u64 sap o))
                   (zerop (dds.pal:cas-sap-u64 sap o 0 token)))   ; prev 0 => we won
          (return-from %claim-lane i))))))
```
- [ ] **Step 4: Run SBCL (+ Clasp if Task A4 took 2a), expect PASS.**
- [ ] **Step 5: Commit.** `feat(xport): SHMEM per-sender lane claim via foreign CAS (FR-XPORT-2)`

### Task C3: enqueue (SPSC producer, release-published)

**Files:** Modify `src/dds-xport/shmem.lisp`; Test `echo-test.lisp` (`run-shmem-enqueue-test`).

- [ ] **Step 1: Failing test** (register `("shmem-enqueue" . run-shmem-enqueue-test)`):
```lisp
(defun* run-shmem-enqueue-test ()
    (function () (eql t))
  "Enqueue advances write-cursor by the 8-rounded record span; a too-large record is rejected; full ring rejects."
  (let* ((lanes 1) (cap 64) (m (dds.pal:alloc-static (dds.xport.shmem::%segment-bytes lanes cap)))
         (payload (octets 1 2 3 4 5)))
    (unwind-protect
         (let ((sap (dds.pal:static-pointer m)))
           (dds.xport.shmem::%ring-init sap lanes cap)
           (%check :ok (dds.xport.shmem::%lane-enqueue sap 0 cap payload 0 5) "5-byte record fits")
           (%check :cursor (= 16 (dds.pal:load-sap-u64 sap (+ (dds.xport.shmem::%lane-desc-off 0) 8)))
                   "write-cursor = round8(4+5) = 16")
           (%check :toobig (null (dds.xport.shmem::%lane-enqueue sap 0 cap payload 0 (- cap 4)))
                   "record > max-record rejected")
           t))
      (dds.pal:free-static m))))
```
- [ ] **Step 2: Run, expect FAIL.**
- [ ] **Step 3: Implement:**
```lisp
(defun* %record-span (len) (function ((integer 0)) (integer 8))
  "Bytes a [len][payload] record occupies, the 4-byte header included, rounded up to 8."
  (logand (+ 4 len 7) (lognot 7)))

(defun* %lane-enqueue (sap lane capacity payload off len)
    (function (t (integer 0) (integer 8) (simple-array (unsigned-byte 8) (*)) (integer 0) (integer 0)) t)
  "Single-producer enqueue of PAYLOAD[off,off+len) as one ring record into LANE. Returns T on success,
   NIL if it does not fit (caller maps NIL to RESOURCE_LIMITS / UDP fallback). Publishes the new
   write-cursor with a RELEASE fence so the consumer's ACQUIRE load sees the payload."
  (when (> (+ 4 len) capacity) (return-from %lane-enqueue nil))      ; never representable
  (let* ((base (%lane-desc-off lane))
         (data (%lane-data-off (%ring-lane-count sap) lane capacity))
         (w (dds.pal:load-sap-u64 sap (+ base +lane-off-write+)))
         (r (dds.pal:load-sap-u64 sap (+ base +lane-off-read+)))
         (span (%record-span len))
         (pos (mod w capacity))
         (tail (- capacity pos)))
    ;; if the record can't sit contiguously before the end, a SKIP consumes the tail first
    (let ((need (if (< tail span) (+ tail span) span)))
      (when (> (+ (- w r) need) capacity) (return-from %lane-enqueue nil)))   ; not enough free space
    (when (< tail span)
      (setf (cffi:mem-ref sap :uint32 (+ data pos)) +skip-marker+)
      (incf w tail) (setf pos 0))
    (setf (cffi:mem-ref sap :uint32 (+ data pos)) len)
    (dotimes (i len) (setf (cffi:mem-ref sap :uint8 (+ data pos 4 i)) (aref payload (+ off i))))
    (dds.pal:fence :release)                                        ; payload visible before the cursor
    (dds.pal:store-sap-u64 sap (+ base +lane-off-write+) (+ w span))
    t))
```
- [ ] **Step 4: Run SBCL + Clasp, expect PASS.**
- [ ] **Step 5: Commit.** `feat(xport): SHMEM lane enqueue (release-published, wrap-via-skip, full-rejects) (FR-XPORT-2)`

### Task C4: drain (SPSC consumer, acquire-loaded, bounds-checked)

**Files:** Modify `src/dds-xport/shmem.lisp`; Test `echo-test.lisp` (`run-shmem-drain-test`).

- [ ] **Step 1: Failing test** (register `("shmem-drain" . run-shmem-drain-test)`):
```lisp
(defun* run-shmem-drain-test ()
    (function () (eql t))
  "Enqueue 2 records then drain: callback sees both payloads in order; cursor catches up; wrap survives."
  (let* ((lanes 1) (cap 64) (m (dds.pal:alloc-static (dds.xport.shmem::%segment-bytes lanes cap)))
         (got '()) (sink (dds.core.buffer:make-octet-buffer cap)))
    (unwind-protect
         (let ((sap (dds.pal:static-pointer m)))
           (dds.xport.shmem::%ring-init sap lanes cap)
           (dds.xport.shmem::%lane-enqueue sap 0 cap (octets 9 9 9) 0 3)
           (dds.xport.shmem::%lane-enqueue sap 0 cap (octets 7 7) 0 2)
           (dds.xport.shmem::%lane-drain sap 0 cap sink
             (lambda (buf size) (push (cons size (aref (dds.core.buffer:octet-buffer-vec buf) 0)) got)))
           (%check :two (= 2 (length got)) "both records delivered")
           (%check :order (equal '(3 . 9) (car (last got))) "first record first")
           t))
      (dds.pal:free-static m))))
```
- [ ] **Step 2: Run, expect FAIL.**
- [ ] **Step 3: Implement** (bounds-check every `len` — the ring is written by another process, an untrusted parser surface, NFR-SEC-POSTURE):
```lisp
(defun* %lane-drain (sap lane capacity sink on-datagram)
    (function (t (integer 0) (integer 8) dds.core.buffer:octet-buffer function) t)
  "Single-consumer drain of LANE: ACQUIRE-load the producer's write-cursor, then read every committed
   record up to it, copy each into SINK and call (ON-DATAGRAM SINK size). Bounds-check every length
   against max-record and the committed extent before trusting it. Advances read-cursor. Returns T."
  (let* ((base (%lane-desc-off lane))
         (data (%lane-data-off (%ring-lane-count sap) lane capacity))
         (maxr (%ring-max-record sap))
         (w (dds.pal:load-sap-u64 sap (+ base +lane-off-write+))))
    (dds.pal:fence :acquire)                                        ; see payloads behind the cursor
    (let ((r (dds.pal:load-sap-u64 sap (+ base +lane-off-read+)))
          (vec (dds.core.buffer:octet-buffer-vec sink)))
      (loop while (< r w) do
        (let* ((pos (mod r capacity))
               (len (cffi:mem-ref sap :uint32 (+ data pos))))
          (cond
            ((= len +skip-marker+) (incf r (- capacity pos)))       ; padding to boundary
            ((or (> len maxr) (> (+ 4 len) (- capacity pos)) (> (%record-span len) (- w r)))
             (return-from %lane-drain t))                           ; malformed -> stop, never OOB
            (t (dotimes (i len) (setf (aref vec i) (cffi:mem-ref sap :uint8 (+ data pos 4 i))))
               (funcall on-datagram sink len)
               (incf r (%record-span len))))))
      (dds.pal:store-sap-u64 sap (+ base +lane-off-read+) r)
      t)))
```
- [ ] **Step 4: Run SBCL + Clasp, expect PASS.**
- [ ] **Step 5: Commit.** `feat(xport): SHMEM lane drain (acquire-loaded, bounds-checked, wrap-aware) (FR-XPORT-2)`

---

# Phase D — the SHMEM transport record

### Task D1: `make-shmem-transport` + loopback test

**Files:** Modify `src/dds-xport/shmem.lisp`; Test `echo-test.lisp` (`run-shmem-transport-test`, registered).

- [ ] **Step 1: Failing test** (mirror `run-udp-transport-test` `udp.lisp:58-89`; register `("shmem-transport" . dds.xport.shmem:run-shmem-transport-test)`):
```lisp
(defun* run-shmem-transport-test ()
    (function () (eql t))
  "Transport-level SHMEM loopback in one image: a receiver segment; a sender attaches by locator,
   SENDs 4 octets; drain delivers them. Mirrors run-udp-transport-test."
  (let ((rx (make-shmem-transport :participant-guid (octets 1 1 1 1 1 1 1 1 1 1 1 1) :host-uuid 7)))
    (unwind-protect
         (let* ((tx (make-shmem-transport :participant-guid (octets 2 2 2 2 2 2 2 2 2 2 2 2) :host-uuid 7))
                (loc (shmem-transport-locator rx))
                (out (dds.core.buffer:make-octet-buffer 64)) (got '())
                (c (dds.core.buffer:cursor out)))
           (unwind-protect
                (progn
                  (dds.core.buffer:put-u8 c #xDE) (dds.core.buffer:put-u8 c #xAD)
                  (dds.core.buffer:put-u8 c #xBE) (dds.core.buffer:put-u8 c #xEF)
                  (dds.xport:send (shmem-transport-transport tx) loc out 0 4)
                  (shmem-receive-drain rx (lambda (buf size) (push (cons size (aref (dds.core.buffer:octet-buffer-vec buf) 0)) got)))
                  (%check :got (equal '(4 . #xDE) (car got)) "4 octets round-trip over SHMEM")
                  t)
             (shmem-transport-close tx)))
      (shmem-transport-close rx))))
```
*(This task introduces small accessors `shmem-transport-transport`, `shmem-transport-locator`, `shmem-receive-drain`, `shmem-transport-close` around a `shmem-transport` struct bundling the segment + semaphore + transport record — the SHMEM analogue of UDP returning the socket as a 2nd value, since the frozen record has no slot for them.)*
- [ ] **Step 2: Run, expect FAIL.**
- [ ] **Step 3: Implement** the `shmem-transport` struct + constructor (mirror `make-udp-transport` `udp.lisp:14-43`):
```lisp
(defstruct* shmem-locator
  "Destination for a SHMEM send: the receiver's segment NAME + its HOST-UUID (same-host gate)."
  (name "" :type string) (host-uuid 0 :type (unsigned-byte 64)) (lane-count 0 :type (integer 0)) (capacity 8 :type (integer 8)))

(defstruct* shmem-transport
  "Owns a participant's SHMEM receive segment + notify semaphore + the frozen transport record, plus a
   per-sender attach cache (name -> shm-segment) and this sender's nonzero lane token."
  (transport nil :type (or null dds.xport:transport))
  (segment nil :type t) (sem nil :type t) (name "" :type string)
  (host-uuid 0 :type (unsigned-byte 64)) (lane-count 8 :type (integer 1)) (capacity 65536 :type (integer 8))
  (token 0 :type (unsigned-byte 64))
  (attach-cache (make-hash-table :test 'equal) :type hash-table)
  (sink nil :type t))

(defun* %guid-token (guid) (function ((simple-array (unsigned-byte 8) (12))) (unsigned-byte 64))
  "A nonzero 64-bit per-sender token from the low 8 GUID-prefix octets (0 reserved for 'free lane')."
  (let ((v 0)) (dotimes (i 8) (setf v (logior (ash v 8) (aref guid i)))) (if (zerop v) 1 v)))
(defun* %seg-name (guid) (function ((simple-array (unsigned-byte 8) (12))) string)
  "Segment name '/dds' + 10 hex of the GUID prefix (macOS ~31-char shm-name cap)."
  (format nil "/dds~(~10,'0x~)" (%guid-token guid)))

(defun* make-shmem-transport (&key participant-guid (host-uuid 0) (lane-count 8) (capacity 65536))
    (function (&key (:participant-guid (simple-array (unsigned-byte 8) (12))) (:host-uuid (unsigned-byte 64))
               (:lane-count (integer 1)) (:capacity (integer 8))) shmem-transport)
  "Create this participant's receive segment + notify semaphore and a transport record whose SEND
   attaches to the destination segment and enqueues; CAPACITY is per-lane ring bytes (multiple of 8)."
  (let* ((name (%seg-name participant-guid)) (token (%guid-token participant-guid))
         (seg (progn (ignore-errors (dds.pal:shm-destroy name))
                     (dds.pal:shm-create name (%segment-bytes lane-count capacity))))
         (sem (progn (ignore-errors (dds.pal:sem-unlink name)) (dds.pal:sem-create name 0)))
         (st (make-shmem-transport-struct :segment seg :sem sem :name name :host-uuid host-uuid
                                          :lane-count lane-count :capacity capacity :token token
                                          :sink (dds.core.buffer:make-octet-buffer capacity))))
    (%ring-init (dds.pal:shm-sap seg) lane-count capacity)
    (setf (shmem-transport-transport st)
          (dds.xport:make-transport
           :kind :shmem :locator-kind :shmem :max-message-size (- capacity 8)
           :send (lambda (locator buffer off len) (declare (ignore off)) (%shmem-send st locator buffer len))
           :receive-loop (lambda () (values))
           :open-receive-resource (lambda (&rest a) (declare (ignore a)) (shmem-transport-locator st))
           :close (lambda () (shmem-transport-close st))))
    st))
```
*(Rename the auto-generated constructor to `make-shmem-transport-struct` via `(:constructor make-shmem-transport-struct)` on the defstruct so the public `make-shmem-transport` fn name is free.)*
- [ ] **Step 4: Implement** `%shmem-send`, `shmem-transport-locator`, `shmem-receive-drain`, `shmem-transport-close`:
```lisp
(defun* %attach-for (st locator)
    (function (shmem-transport shmem-locator) t)
  "Cached shm-segment for LOCATOR's destination (attach once per name; off the hot path)."
  (or (gethash (shmem-locator-name locator) (shmem-transport-attach-cache st))
      (setf (gethash (shmem-locator-name locator) (shmem-transport-attach-cache st))
            (dds.pal:shm-attach (shmem-locator-name locator)
                                (%segment-bytes (shmem-locator-lane-count locator) (shmem-locator-capacity locator))))))
(defun* %shmem-send (st locator buffer len)
    (function (shmem-transport shmem-locator dds.core.buffer:octet-buffer (integer 0)) (integer 0))
  "Attach to LOCATOR's segment, claim/lookup our lane, enqueue LEN octets, post the notify semaphore.
   Returns LEN on success, 0 on lane-full/claim-fail (caller falls back to UDP / RESOURCE_LIMITS)."
  (let* ((dest (%attach-for st locator)) (sap (dds.pal:shm-sap dest))
         (lane (%claim-lane sap (shmem-transport-token st))))
    (if (and lane (%lane-enqueue sap lane (shmem-locator-capacity locator)
                                 (dds.core.buffer:octet-buffer-vec buffer) 0 len))
        (progn (dds.pal:sem-post (%dest-sem st locator)) len)
        0)))
(defun* %dest-sem (st locator)
    (function (shmem-transport shmem-locator) t)
  "Cached open handle to the destination's notify semaphore (keyed by name)."
  (let ((k (concatenate 'string "sem:" (shmem-locator-name locator))))
    (or (gethash k (shmem-transport-attach-cache st))
        (setf (gethash k (shmem-transport-attach-cache st)) (dds.pal:sem-open (shmem-locator-name locator))))))
(defun* shmem-transport-locator (st)
    (function (shmem-transport) shmem-locator)
  "The locator a peer uses to send to ST."
  (make-shmem-locator :name (shmem-transport-name st) :host-uuid (shmem-transport-host-uuid st)
                      :lane-count (shmem-transport-lane-count st) :capacity (shmem-transport-capacity st)))
(defun* shmem-receive-drain (st on-datagram)
    (function (shmem-transport function) t)
  "Drain ALL lanes of ST's receive segment once, calling ON-DATAGRAM per record (test/loop helper)."
  (let ((sap (dds.pal:shm-sap (shmem-transport-segment st))))
    (dotimes (i (shmem-transport-lane-count st) t)
      (%lane-drain sap i (shmem-transport-capacity st) (shmem-transport-sink st) on-datagram))))
(defun* shmem-transport-close (st)
    (function (shmem-transport) t)
  "Detach all attached segments + close opened sems, then detach + destroy + unlink our own."
  (maphash (lambda (k v) (if (and (>= (length k) 4) (string= "sem:" k :end2 4))
                             (dds.pal:sem-close v) (dds.pal:shm-detach v)))
           (shmem-transport-attach-cache st))
  (dds.pal:shm-detach (shmem-transport-segment st)) (dds.pal:shm-destroy (shmem-transport-name st))
  (dds.pal:sem-close (shmem-transport-sem st)) (dds.pal:sem-unlink (shmem-transport-name st)) t)
```
- [ ] **Step 5: Run SBCL, expect PASS** (Clasp only if Task A4 took 2a; else this test is SBCL-only per the NFR-PORT gate).
- [ ] **Step 6: Commit.** `feat(xport): make-shmem-transport + loopback (engine-untouched via the transport record) (FR-XPORT-2)`

### Task D2: receiver thread (sem-wait + drain; stop-flag/post-to-wake)

**Files:** Modify `src/dds-xport/shmem.lisp`; Test `echo-test.lisp` (`run-shmem-receiver-test`, mirror `run-udp-receiver-test` `udp.lisp:111-136`).

- [ ] **Step 1: Failing test** (register `("shmem-receiver-thread" . dds.xport.shmem:run-shmem-receiver-test)`): spawn `start-shmem-receiver` on `rx`, `send` from `tx`, assert the background callback records the datagram within a bounded wait, then `stop-shmem-receiver`.
```lisp
(defun* run-shmem-receiver-test ()
    (function () (eql t))
  "A background thread blocks on the notify semaphore, drains, and delivers a datagram; clean stop."
  (let ((rx (make-shmem-transport :participant-guid (octets 3 3 3 3 3 3 3 3 3 3 3 3) :host-uuid 7)) (received nil))
    (unwind-protect
         (let ((tx (make-shmem-transport :participant-guid (octets 4 4 4 4 4 4 4 4 4 4 4 4) :host-uuid 7))
               (ob (dds.core.buffer:make-octet-buffer 16)))
           (unwind-protect
                (progn
                  (start-shmem-receiver rx (lambda (buf size) (setf received (cons size (aref (dds.core.buffer:octet-buffer-vec buf) 0)))))
                  (let ((c (dds.core.buffer:cursor ob))) (dds.core.buffer:put-u8 c #x55) (dds.core.buffer:put-u8 c #x66))
                  (dds.xport:send (shmem-transport-transport tx) (shmem-transport-locator rx) ob 0 2)
                  (loop repeat 100 until received do (sleep 0.02))
                  (%check :got received "receiver thread delivered a datagram")
                  (%check :size (= 2 (car received)) "right size")
                  t)
             (stop-shmem-receiver rx) (shmem-transport-close tx)))
      (shmem-transport-close rx))))
```
- [ ] **Step 2: Run, expect FAIL.**
- [ ] **Step 3: Implement** (add `stop` + `rx-thread` slots to `shmem-transport`; mirror `start-udp-receiver` `udp.lisp:91-109` and the WP-ASYNC stop-flag+signal teardown):
```lisp
(defun* start-shmem-receiver (st on-datagram)
    (function (shmem-transport function) t)
  "Spawn a thread that blocks on ST's notify semaphore, drains ALL lanes, and calls ON-DATAGRAM per
   record. Clean shutdown: stop-shmem-receiver sets the stop flag and posts the semaphore to wake it."
  (setf (shmem-transport-stop st) nil)
  (setf (shmem-transport-rx-thread st)
        (dds.pal:spawn
         (lambda ()
           (loop
             (dds.pal:sem-wait (shmem-transport-sem st))
             (when (shmem-transport-stop st) (return))
             (handler-case (shmem-receive-drain st on-datagram) (error () nil))))
         :name "dds-shmem-rx")))
(defun* stop-shmem-receiver (st)
    (function (shmem-transport) t)
  "Signal the receive thread to exit and JOIN it before any segment teardown (no UAF)."
  (when (shmem-transport-rx-thread st)
    (setf (shmem-transport-stop st) t) (dds.pal:sem-post (shmem-transport-sem st))
    (dds.pal:join (shmem-transport-rx-thread st)) (setf (shmem-transport-rx-thread st) nil))
  t)
```
*(Update `shmem-transport-close` to call `stop-shmem-receiver` first.)*
- [ ] **Step 4: Run SBCL, expect PASS.**
- [ ] **Step 5: Commit.** `feat(xport): SHMEM receiver thread (sem-wait drain, join-before-teardown) (FR-XPORT-2)`

---

# Phase E — locator + discovery integration

### Task E1: SHMEM locator kind + host-uuid + SPDP advertise/parse

**Files:** Modify `src/dds-rtps/discovery.lisp` (locator-kind constant + spdp-data host-uuid slot + serialize/parse), `src/dds-rtps/message.lisp` (vendor PIDs); Test `echo-test.lisp` (`run-shmem-locator-test`).

- [ ] **Step 1: Failing test** (register `("shmem-locator" . run-shmem-locator-test)`): build an SPDP with a SHMEM locator + host-uuid, serialize, parse, assert round-trip; assert a peer with a different host-uuid is NOT same-host.
- [ ] **Step 2: Run, expect FAIL.**
- [ ] **Step 3: Implement constants** in `discovery.lisp` (beside `+locator-kind-udpv4+` at line 8) and `message.lisp` (beside the vendor PID `+pid-type-object-lb+ #x8021` near `message.lisp:689`):
```lisp
;; discovery.lisp — vendor-specific, ours-only; no standard RTPS SHMEM kind exists (ADR 0013).
;; Cross-vendor peers see an unknown kind and ignore the locator (fail-open) -> UDP.
(defconstant +locator-kind-shmem+ #x47420001 "Vendor SHMEM locator kind (GB|1); ours-to-ours only (ADR 0013).")
;; message.lisp — vendor PIDs (high bit set, RTPS 2.5 §9.6.2.2.1 vendor space)
(defconstant +pid-shmem-host-uuid+ #x8040 "Vendor PID: 8-octet same-host UUID (ADR 0013).")
```
Add a `host-uuid` slot to `spdp-data` (`discovery.lisp:138-151`), write it as a `PID_SHMEM_HOST_UUID` parameter + a SHMEM `Locator_t` (reuse `write-locator`, encoding the segment-name hash into the 16-octet address) in `serialize-spdp-data` (`discovery.lisp:181-193`), and parse both in the SPDP parse `cond` (`discovery.lisp:221-232`). The SHMEM locator's `port`/`address` carry the `(lane-count, capacity)` + name-hash so a peer can `shm-attach` without a side channel.
- [ ] **Step 4: Run SBCL + Clasp, expect PASS** (pure serialization — impl-independent).
- [ ] **Step 5: Commit.** `feat(rtps): advertise a vendor SHMEM locator + host-uuid in SPDP (FR-XPORT-2, ADR 0013)`

### Task E2: disc-node SHMEM transport + same-host selection + integration test

**Files:** Modify `src/dds-disc/disc.lisp` (create the SHMEM transport beside UDP `disc.lisp:138-152`; same-host send selection; advertise the SHMEM locator; guard SHMEM off when Task A4 = 2b/Clasp); Test `integration-test.lisp` (`run-shmem-end-to-end-test`).

- [ ] **Step 1: Failing test** — mirror the two-node UDP integration setup (`integration-test.lisp:114-170`) but assert delivery travels over SHMEM: both nodes share a host-uuid; after match, `publish-sample` on the writer; the reader's `node-sample-count` reaches N; assert the SHMEM transport's send counter advanced (add a debug counter) and UDP user-data did not. Register in the integration runner.
- [ ] **Step 2: Run, expect FAIL.**
- [ ] **Step 3: Implement** in `disc.lisp`: add a `shmem` slot to `disc-node`; in `make-disc-node`, when SHMEM is available (SBCL, or Clasp-2a) and enabled, also `make-shmem-transport` and advertise its locator + host-uuid in SPDP; in the user-data send path (where `%reader-push-targets` resolves destinations), when a matched remote reader's participant advertised a SHMEM locator **with the same host-uuid**, send via the SHMEM transport; else the existing UDP path. Discovery/SEDP/HEARTBEAT/ACKNACK stay on UDP (only bulk user data takes SHMEM in v1; simplest correct split). Guard: a `*shmem-enabled*` special (default `t` on SBCL, `nil` if Task A4 = 2b) so Clasp cleanly uses UDP.
- [ ] **Step 4: Run SBCL, expect PASS;** run the full suite on SBCL + Clasp to confirm no regression (Clasp uses UDP).
- [ ] **Step 5: Commit.** `feat(disc): select the SHMEM transport for same-host user data, UDP fallback (FR-XPORT-2)`

---

# Phase F — cross-process proof, fuzz, bench, docs

### Task F1: real two-process cross-process test

**Files:** Create `scripts/shmem-roundtrip.sh` (launch two SBCL processes like the `square-pub`/`square-sub` Makefile pattern `Makefile:84-92`); add `shmem-pub`/`shmem-sub` entry points to `src/dds-shapes/shapes.lisp` (or a tiny `src/dds-tests/shmem-proc.lisp`); Makefile target `shmem-xproc`.

- [ ] **Step 1:** Add `run-shmem-sub`/`run-shmem-pub` (two nodes, SHMEM-enabled, same host-uuid; pub writes N samples, sub prints the received count + exits nonzero on shortfall). **Step 2:** `scripts/shmem-roundtrip.sh` starts the sub, waits, starts the pub, asserts the sub received ≥ threshold. **Step 3:** Run `make shmem-xproc`; expect "received N/N". **Step 4:** Commit `test(xport): real cross-process SHMEM round-trip (two OS processes) (FR-XPORT-2)`.

### Task F2: fuzz the ring record parser

**Files:** Modify the PBT suite (`dds.tests:run-pbt-tests`, invoked by `make fuzz` `Makefile:75-77`).

- [ ] **Step 1:** Add a generator that fills a lane's ring data with random bytes + random cursors and calls `%lane-drain`, asserting it never reads out of bounds and always terminates (malformed `len`, `+skip-marker+` at the boundary, `len > max-record`, cursor games). **Step 2:** Run `make fuzz`; expect no crash/OOB. **Step 3:** Commit `test(xport): fuzz the SHMEM ring parser (untrusted cross-process input) (NFR-SEC-POSTURE)`.

### Task F3: SHMEM-vs-UDP benchmark + report

**Files:** Modify `src/dds-bench/perftest.lisp` (add `run-shmem-latency`/`run-shmem-throughput` mirroring `run-latency`/`run-throughput` `perftest.lisp:76-130` but with SHMEM-enabled nodes); Makefile `bench-shmem`; report `bench/report/2026-06-14-wp-shmem.md`.

- [ ] **Step 1:** Add the SHMEM bench variants (reuse the rendezvous + percentile helpers; flip the nodes to SHMEM). **Step 2:** `make bench-shmem > bench/report/2026-06-14-wp-shmem.md`; record p50/p99/p99.99 + bytes/sample vs the UDP-loopback baseline; confirm **0 bytes/sample** steady-state and NFR-PERF-6 (large-sample latency ≤ 1.5× the mmap floor). **Step 3:** Commit `bench(xport): SHMEM vs UDP-loopback latency/throughput + report (NFR-PERF-6, FR-LANG-7)`.

### Task F4: docs + verification + gates + finalize ADR

**Files:** `docs/wiki/transports.md` (or the transport page) + `README.md` (status/architecture), `docs/verification.csv` (FR-XPORT-2 row), `docs/provenance.md` (none copied — clean-room note), finalize `docs/adr/0013-*.md`.

- [ ] **Step 1:** Docstrings already on every exported symbol (done per task). Update the wiki transport page (API + a worked SHMEM example), README transport status, and the verification matrix (FR-XPORT-2 → implemented SBCL; Clasp per A4 outcome). **Step 2:** Run the full gate set: `make build-all test-all gate-hotpath gate-types fuzz mem bench-shmem` (Allegro = documented NFR-PORT gap). **Step 3:** Confirm all green; the SHMEM `send` is slot-read+funcall (gate-hotpath) and 0-alloc steady-state (mem). **Step 4:** Commit `docs(xport): WP-SHMEM wiki + README + verification + ADR 0013 finalize (FR-XPORT-2)`.

---

## Self-review (run before handing to execution)
- **Spec coverage:** §scope→F3 bench/F1 xproc; §PAL surface→A2-A4,B1-B2; §ring layout→C1; §concurrency→A2-A4,C2-C4; §send/receive→D1-D2; §discovery→E1-E2; §safety/backpressure→C3-C4 (reject),C4/F2 (bounds/fuzz),D2 (join-before-teardown); §hot-path→F4 gates; §testing→C-D-E-F. All covered.
- **Type consistency:** cursor ops `dds.pal:{load,store,cas-sap,atomic-incf-sap}-u64`; ring helpers `%lane-enqueue`/`%lane-drain`/`%claim-lane`/`%record-span`; transport `make-shmem-transport`→`shmem-transport` (struct ctor renamed `make-shmem-transport-struct`); `shmem-locator` fields name/host-uuid/lane-count/capacity used identically in D1/E1/E2.
- **No placeholders:** every code step has real content; the two genuinely contingent points (Clasp foreign atomics A4; exact SPDP locator address packing E1) carry concrete code + an explicit decision rule, not a TODO.
- **Open risks:** Clasp foreign-place atomics (A4 → NFR-PORT gap if unsupported); macOS shm name length (handled: 10-hex name); macOS `ftruncate`-once (handled: truncate before first mmap).
