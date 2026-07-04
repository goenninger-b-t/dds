;;;; NOT cleared for ship — pending counsel (R6); see ADR 0014.
;;;; L8 — WP-ZEROCOPY SHMEM sample-pool (FR-PF-3): per-writer pool of fixed-size slots holding serialized
;;;; SerializedPayloads; the writer publishes a 16-byte reference instead of copying the payload. Clean-room.
(in-package #:dds.xport.zerocopy)

(defconstant +zc-magic+ #x5A434F31 "Pool ABI magic 'ZCO1' (ours; not a wire constant).")
(defconstant +zc-version+ 1 "WP-ZEROCOPY pool ABI version stamped in the header (attach-time guard).")
(defconstant +zc-off-magic+ 0 "Header byte offset of the u32 ABI magic.")
(defconstant +zc-off-version+ 4 "Header byte offset of the u32 ABI version.")
(defconstant +zc-off-slot-count+ 8 "Header byte offset of the u32 slot count K.")
(defconstant +zc-off-slot-bytes+ 12 "Header byte offset of the u32 per-slot payload capacity.")
(defconstant +zc-off-free-head+ 16 "Unused since the freelist was dropped (WP-ZC-LOAN-LOCKFREE, ADR 0018); was the u32 freelist-head offset.")
(defconstant +zc-mutex-off+ 64 "Byte offset of the pool's PTHREAD_PROCESS_SHARED mutex (guards all slot state).")
(defconstant +zc-slots-off+ 128 "Byte offset where the K slots begin (after header + mutex region).")
(defconstant +zc-slot-hdr+ 32 "Per-slot header bytes preceding the slot payload.")
(defconstant +zc-slot-off-refcount+ 0 "Within-slot offset of the u32 refcount.")
(defconstant +zc-slot-off-generation+ 4 "Within-slot offset of the u32 generation (the single race guard).")
(defconstant +zc-slot-off-len+ 8 "Within-slot offset of the u32 payload length (no longer overlays a freelist 'next' — freelist dropped, WP-ZC-LOAN-LOCKFREE, ADR 0018).")
(defconstant +zc-slot-off-pubseq+ 16 "Within-slot offset of the u64 publish sequence (force-reclaim 'oldest' ordering).")
(defconstant +zc-free-end+ #xFFFFFFFF "Unused since the freelist was dropped (WP-ZC-LOAN-LOCKFREE, ADR 0018); was the freelist terminator.")

(defun* %zc-slot-stride (slot-bytes)
    (function ((integer 1)) (integer 1))
  "Per-slot byte stride: header + payload rounded UP to an 8-byte multiple so every slot (hence its u64
   pubseq) is 8-aligned for dds.pal:load/store-sap-u64. The header still records the unrounded slot-bytes
   (the usable/advertised payload capacity); the rounding is interior padding."
  (+ +zc-slot-hdr+ (* 8 (ceiling slot-bytes 8))))
(defun* %zc-bytes (slot-count slot-bytes)
    (function ((integer 1) (integer 1)) (integer 1))
  "Total pool segment size for SLOT-COUNT slots of SLOT-BYTES payload each."
  (+ +zc-slots-off+ (* slot-count (%zc-slot-stride slot-bytes))))
(defun* %zc-slot-count (sap)
    (function (t) (unsigned-byte 32))
  "Slot count K read from the pool header at SAP."
  (cffi:mem-ref sap :uint32 +zc-off-slot-count+))
(defun* %zc-slot-bytes (sap)
    (function (t) (unsigned-byte 32))
  "Per-slot payload capacity read from the pool header at SAP."
  (cffi:mem-ref sap :uint32 +zc-off-slot-bytes+))
(defun* %zc-slot-off (sap i)
    (function (t (integer 0)) (integer 0))
  "Byte offset of slot I's header within the segment at SAP."
  (+ +zc-slots-off+ (* i (%zc-slot-stride (%zc-slot-bytes sap)))))

(defun* %zc-init (sap slot-count slot-bytes)
    (function (t (integer 1) (integer 1)) t)
  "Initialise header + pshared mutex; zero every slot's refcount/generation/len/pubseq. Creator-only.
   WP-ZC-LOAN-LOCKFREE (R6, ADR 0018; NOT cleared for ship — pending counsel): the freelist is DROPPED — a
   slot is reclaimable iff its refcount==0, so init builds no freelist head and the LEN field no longer
   overlays a freelist 'next' (it is just the payload length, initialised 0)."
  (setf (cffi:mem-ref sap :uint32 +zc-off-magic+) +zc-magic+
        (cffi:mem-ref sap :uint32 +zc-off-version+) +zc-version+
        (cffi:mem-ref sap :uint32 +zc-off-slot-count+) slot-count
        (cffi:mem-ref sap :uint32 +zc-off-slot-bytes+) slot-bytes)
  (dds.pal:pshared-mutex-init sap +zc-mutex-off+)
  (dotimes (i slot-count t)
    (let ((b (%zc-slot-off sap i)))
      (setf (cffi:mem-ref sap :uint32 (+ b +zc-slot-off-refcount+)) 0
            (cffi:mem-ref sap :uint32 (+ b +zc-slot-off-generation+)) 0
            (cffi:mem-ref sap :uint32 (+ b +zc-slot-off-len+)) 0)
      (dds.pal:store-sap-u64 sap (+ b +zc-slot-off-pubseq+) 0))))

(defun* %zc-validate (sap)
    (function (t) t)
  "T iff SAP holds a pool with the expected magic + version (attach-time ABI guard)."
  (and (= +zc-magic+ (cffi:mem-ref sap :uint32 +zc-off-magic+))
       (= +zc-version+ (cffi:mem-ref sap :uint32 +zc-off-version+))))

(defun* %zc-destroy (sap)
    (function (t) t)
  "Destroy the pool's pshared mutex (creator, after any consumer joined). The pool has only a mutex (no
   cond); pass the mutex offset for both pshared-destroy args so pthread_cond_destroy is a no-op on the
   same region."
  (dds.pal:pshared-destroy sap +zc-mutex-off+ +zc-mutex-off+))

(defun* %zc-free-count (sap)
    (function (t) (integer 0))
  "Count the reclaimable (refcount==0) slots (test/debug; not hot path). WP-ZC-LOAN-LOCKFREE (ADR 0018): the
   freelist was dropped, so 'free' now means 'reclaimable' = refcount==0 (a released slot is reclaimable, a
   held slot is not, a double-release does not change the count) — behaviorally identical to the old
   freelist-walk for every WP-ZEROCOPY assertion."
  (let ((n 0))
    (dotimes (i (%zc-slot-count sap) n)
      (when (zerop (cffi:mem-ref sap :uint32 (+ (%zc-slot-off sap i) +zc-slot-off-refcount+))) (incf n)))))

(defvar *zc-pubseq* 0 "Process-local monotonic publish sequence for force-reclaim 'oldest' ordering.")

(defun* %zc-take-free-or-reclaim (sap)
    (function (t) (or null (integer 0)))
  "CALLER HOLDS THE MUTEX. Scan for the lowest-pubseq (oldest) slot AMONG THOSE WITH refcount==0 and return
   it — the caller's generation bump then invalidates any in-flight ref to that now-reused slot.
   WP-ZC-LOAN-LOCKFREE (R6, ADR 0018; NOT cleared for ship — pending counsel): the freelist is DROPPED, so
   this ALWAYS scans (the writer's loan is O(slots), amortized — the freelist's O(1) pop is gone), and a slot
   is reclaimable iff refcount==0. WP-FLATDATA-ZC-LOAN safety contract (ADR 0017): a loaned slot has
   refcount>0 (the writer's %zc-loan set refcount=readers and a reader-loan holds it until %zc-release), so
   it is NEVER a reclaim candidate — it can never be overwritten under the app's read. Returns the slot
   index, or NIL when every slot is loaned (refcount>0, none reclaimable) ⇒ %zc-loan returns NIL ⇒ the
   writer falls back to non-ZC for that sample (lost-tolerant, never blocks)."
  (let ((oldest nil) (oldest-seq 0))
    (dotimes (i (%zc-slot-count sap) oldest)
      (let ((b (%zc-slot-off sap i)))
        (when (zerop (cffi:mem-ref sap :uint32 (+ b +zc-slot-off-refcount+)))
          (let ((s (dds.pal:load-sap-u64 sap (+ b +zc-slot-off-pubseq+))))
            (when (or (null oldest) (< s oldest-seq)) (setf oldest i oldest-seq s))))))))

(defun* %zc-loan-acquire (sap len readers)
    (function (t (integer 0) (integer 0)) (values (or null (integer 0)) (integer 0) (unsigned-byte 32)))
  "WP-FLATDATA-LOAN-WRITE (FR-PF-4, R6, ADR 0042; NOT cleared for ship — pending counsel). The slot-BOOKKEEPING
   half of %zc-loan WITHOUT the copy: reject LEN > slot-bytes; take the pool mutex; %zc-take-free-or-reclaim the
   oldest UNLOANED (refcount==0) slot; set len/refcount=READERS/pubseq; COMPUTE the next generation g=(old+1) but
   DO NOT store it; release the mutex. Returns (values SLOT PAYLOAD-BASE GENERATION) — PAYLOAD-BASE is the slot's
   payload byte offset within the segment (slot-off + +zc-slot-hdr+) for the writer to dds.pal:store-sap-u8 its
   sample straight into, GENERATION is g to hand to %zc-loan-commit — or (values NIL 0 0) if LEN > slot-bytes OR
   every slot is loaned (saturation ⇒ the caller degrades to non-ZC / a heap sample, never blocks).
   ORDERING CONTRACT (ADR 0042 §2): the generation g is stored ONLY at commit, AFTER the writer's field writes +
   a release fence — so a lock-free reader (%zc-acquire-for-read) can NEVER observe the slot mid-write (before
   commit the stored generation is the OLD value, and the ref carrying g is emitted only after commit). The slot
   is protected from reclaim/steal between acquire and commit because refcount=READERS>0 and %zc-take-free-or-
   reclaim only selects refcount==0 slots. An ABORTED loan (%zc-loan-abort) restores refcount=0 without ever
   storing g, so it is invisible to every reader."
  (when (> len (%zc-slot-bytes sap)) (return-from %zc-loan-acquire (values nil 0 0)))
  (dds.pal:pshared-lock sap +zc-mutex-off+)
  (unwind-protect
       (let ((i (%zc-take-free-or-reclaim sap)))
         (if (null i)
             (values nil 0 0)
             (let* ((b (%zc-slot-off sap i))
                    (g (logand (1+ (cffi:mem-ref sap :uint32 (+ b +zc-slot-off-generation+))) #xFFFFFFFF)))
               (setf (cffi:mem-ref sap :uint32 (+ b +zc-slot-off-len+)) len
                     (cffi:mem-ref sap :uint32 (+ b +zc-slot-off-refcount+)) readers)
               (dds.pal:store-sap-u64 sap (+ b +zc-slot-off-pubseq+) (incf *zc-pubseq*))
               (values i (+ b +zc-slot-hdr+) g))))
    (dds.pal:pshared-unlock sap +zc-mutex-off+)))

(defun* %zc-loan-commit (sap slot-index generation)
    (function (t (integer 0) (unsigned-byte 32)) t)
  "WP-FLATDATA-LOAN-WRITE (FR-PF-4, R6, ADR 0042; NOT cleared for ship — pending counsel). The PUBLICATION tail
   of %zc-loan: dds.pal:fence :release (publishes the writer's field writes + len/refcount/pubseq), then store
   the slot GENERATION LAST — the single RELEASE point that publishes the fully-written slot to a future
   lock-free reader (the generation is the release/acquire sync variable, mirroring %zc-loan / the WP-SHMEM ring
   cursor). NO mutex: once %zc-loan-acquire set refcount>0 only THIS writer touches the slot, so the store's
   cross-process visibility comes from the fence + generation-store, not the mutex (identical to the reader's
   lock-free %zc-release; ADR 0018/0042 §2). GENERATION is the value %zc-loan-acquire returned for this slot."
  (let ((b (%zc-slot-off sap slot-index)))
    (dds.pal:fence :release)
    (setf (cffi:mem-ref sap :uint32 (+ b +zc-slot-off-generation+)) generation))
  t)

(defun* %zc-loan-abort (sap slot-index)
    (function (t (integer 0)) t)
  "WP-FLATDATA-LOAN-WRITE (FR-PF-4, R6, ADR 0042; NOT cleared for ship — pending counsel). Release an ACQUIRED
   but UNCOMMITTED loan: under the pool mutex set refcount=0 so the slot is reclaimable again — WITHOUT storing a
   generation, so no new generation is ever published (ADR 0042 §2). Because a ref bearing the acquire's would-be
   generation is emitted only at commit → send, no reader can ever present it; a future loan on this slot
   recomputes old+1 and stores it only on ITS commit. Hence abort is invisible to every reader (pure best-effort
   discard) and idempotent-safe at the DCPS layer. The mutex prevents a torn refcount read vs a concurrent
   %zc-take-free-or-reclaim scan."
  (when (< slot-index (%zc-slot-count sap))
    (dds.pal:pshared-lock sap +zc-mutex-off+)
    (unwind-protect
         (setf (cffi:mem-ref sap :uint32 (+ (%zc-slot-off sap slot-index) +zc-slot-off-refcount+)) 0)
      (dds.pal:pshared-unlock sap +zc-mutex-off+)))
  t)

(defun* %zc-loan (sap payload off len readers)
    (function (t (simple-array (unsigned-byte 8) (*)) (integer 0) (integer 0) (integer 0))
              (values (or null (integer 0)) (unsigned-byte 32)))
  "Single-producer (the owning writer): loan a slot for PAYLOAD[off,off+len) to READERS consumers. Since
   WP-FLATDATA-LOAN-WRITE (ADR 0042) this is the byte-behaviour-identical COMPOSITION of the three loan
   primitives — %zc-loan-acquire (pick+stamp the slot), COPY THE PAYLOAD IN at the returned payload base, then
   %zc-loan-commit (release-fence + generation store LAST) — NOT a sibling copy (DRY). Returns (values slot-index
   generation), or (values NIL 0) if LEN > slot-bytes OR every slot is loaned ⇒ the writer falls back to non-ZC
   for that sample. Same return values, same slot contents, same generation sequence as before the split; only
   the mutex hold DURATION shrinks (the copy now runs outside the mutex — not observable behaviour).
   ORDERING (WP-ZC-LOAN-LOCKFREE, R6, ADR 0018/0042; NOT cleared for ship — pending counsel): the payload is
   written FIRST; then dds.pal:fence :release publishes it (+ len/refcount/pubseq set at acquire); then the
   generation store is the LAST write — the single RELEASE point that publishes the whole slot to a future
   lock-free reader. A reader that acquire-loads the new generation is guaranteed to see the payload-before
   stores (no torn read)."
  (multiple-value-bind (i base g) (%zc-loan-acquire sap len readers)
    (if (null i)
        (values nil 0)
        (progn
          (dotimes (k len) (setf (cffi:mem-ref sap :uint8 (+ base k)) (aref payload (+ off k))))
          (%zc-loan-commit sap i g)
          (values i g)))))

(defun* %zc-release (sap slot-index generation)
    (function (t (integer 0) (unsigned-byte 32)) t)
  "A reader returning a loan on slot SLOT-INDEX it read at GENERATION (the loan-return half of
   %zc-acquire-for-read). LOCK-FREE cas-sap-u32 ATOMIC DECREMENT OF THE REFCOUNT SUB-FIELD (WP-ZC-LOAN-LOCKFREE
   Phase B, R6, ADR 0018; NOT cleared for ship — pending counsel): NO mutex ⇒ 0 GC-heap bytes per release. T if
   the decrement applied, NIL if stale/OOB. A slot becomes reclaimable simply by reaching refcount==0 (the
   writer's next scan finds the lowest-pubseq refcount==0 slot; the freelist is DROPPED).
   DIRECT u32-REFCOUNT CAS (0-alloc AT ANY GENERATION): the refcount (u32 @+0) is CASed DIRECTLY — the combined
   (generation<<32)|refcount u64 is NEVER materialised, so nothing boxes a bignum once a slot's generation grows
   past most-positive-fixnum/2^32 (~2^30). All refcount arithmetic stays (unsigned-byte 32) ⇒ fixnum ⇒ literal
   0-alloc regardless of generation. The generation (u32 @+4) is read ONCE up front for the stale-ref check and
   then NEVER touched (the CAS contends only on the refcount cell @+0); it is preserved by construction.
   GENERATION GUARD (separate u32 read, not a sync point): a held slot's generation is STABLE while refcount>0
   (force-reclaim/loan only reclaim refcount==0 slots, so a slot we hold a count on CANNOT be reclaimed +
   generation-rebumped mid-release), so a separate u32 read of the generation can't race the writer — it is the
   stale/forged-ref check, and a mismatch (the slot was already reclaimed) returns NIL with NO decrement (never
   touch a slot we no longer own). The CAS loop then only contends on the refcount (multiple readers of the same
   slot each decrement; the loop re-reads + re-CASes; bounded):
     gen0 := load-u32 generation@+4
     gen0 /= GENERATION -> NIL   (stale / reclaimed, no decrement)
     loop: rc := load-u32 refcount@+0
           rc = 0  -> T          (already 0 -> double-return no-op, NO underflow / wrap)
           CAS(refcount: rc -> rc-1) succeeds -> T ; else retry
   MEMORY-ORDERING HANDSHAKE (the binary gate, UNCHANGED): dds.pal:cas-sap-u32 is sb-ext:cas (arm64 CASAL — a
   32-bit FULL barrier, the same acquire+release ordering the u64 CAS had), so the reader's prior payload reads
   HAPPEN-BEFORE the refcount reaches 0; the writer's force-reclaim/loan only reclaims refcount==0 slots ⇒ it can
   NEVER overwrite a slot a reader is still reading (no UAF / torn read).
   IDEMPOTENT / DOUBLE-RETURN-SAFE (WP-FLATDATA-ZC-LOAN safety contract, ADR 0017): the (plusp rc) guard means a
   SECOND release of an already-refcount==0 slot (matching generation) is a validated no-op — the refcount stays
   0, never decrements below 0 / wraps to ~4e9. A generation mismatch (the slot was reclaimed + generation-
   rebumped) is likewise a no-op. Hence a double return-loan of the same view, and a reader-close returning an
   already-returned loan, are both safe; best-effort tolerates a lost / force-reclaimed ref."
  (when (>= slot-index (%zc-slot-count sap)) (return-from %zc-release nil))
  (let ((b (%zc-slot-off sap slot-index)))
    (unless (= generation (dds.pal:load-sap-u32 sap (+ b +zc-slot-off-generation+))) (return-from %zc-release nil))
    (loop
      (let ((rc (dds.pal:load-sap-u32 sap (+ b +zc-slot-off-refcount+))))
        (when (zerop rc) (return t))
        (when (= rc (dds.pal:cas-sap-u32 sap (+ b +zc-slot-off-refcount+) rc (1- rc))) (return t))))))

(defun* %zc-pin (sap slot-index generation)
    (function (t (integer 0) (unsigned-byte 32)) t)
  "WP-ACKED-SLOT-PINNING (FR-PF-4, R6, ADR 0044; NOT cleared for ship — pending counsel). Add ONE extra
   refcount hold — the TX PIN — to slot SLOT-INDEX at GENERATION: a lock-free cas-sap-u32 ATOMIC INCREMENT of
   the refcount sub-field, the exact dual of %zc-release's decrement. T if applied, NIL if stale/OOB or the
   slot is already free (refcount==0 — a dead slot is never pinned). The pin is a DISTINCT hold from the
   armed/delivery refcount (%zc-loan-acquire's readers count) so a reader's return-loan (%zc-release) cannot
   free the slot before the writer's ACK-release; whichever of the two holds reaches refcount 0 LAST frees the
   slot (ADR 0044 §4). GENERATION GUARD: a held slot's generation is STABLE while refcount>0 (force-reclaim only
   reclaims refcount==0), so the up-front generation read is the stale-ref check — a mismatch (already reclaimed)
   returns NIL with NO increment. The CAS loop contends only on the refcount cell @+0 (never materialises the
   combined u64 — 0-alloc at any generation), mirroring %zc-release:
     gen0 /= GENERATION -> NIL   (stale / reclaimed, no increment)
     loop: rc := load-u32 refcount@+0
           rc = 0  -> NIL        (dead slot, never pin)
           CAS(refcount: rc -> rc+1) succeeds -> T ; else retry
   MEMORY-ORDERING: dds.pal:cas-sap-u32 is a full-barrier RMW (arm64 CASAL), the same handshake %zc-release
   uses. Called by the TX publish path AFTER %zc-loan-commit (the slot is committed + still held at refcount>=1),
   so it can never race a reader that has not yet been handed the ref. Idempotent-unsafe by design (each pin is
   released by exactly one %zc-release under a one-shot state flag, ADR 0044 §4.2)."
  (when (>= slot-index (%zc-slot-count sap)) (return-from %zc-pin nil))
  (let ((b (%zc-slot-off sap slot-index)))
    (unless (= generation (dds.pal:load-sap-u32 sap (+ b +zc-slot-off-generation+))) (return-from %zc-pin nil))
    (loop
      (let ((rc (dds.pal:load-sap-u32 sap (+ b +zc-slot-off-refcount+))))
        (when (zerop rc) (return nil))
        (when (= rc (dds.pal:cas-sap-u32 sap (+ b +zc-slot-off-refcount+) rc (1+ rc))) (return t))))))

(defun* %zc-slot-payload-len (sap slot-index generation)
    (function (t (integer 0) (unsigned-byte 32)) (or null (unsigned-byte 32)))
  "CALLER HOLDS THE MUTEX. The slot's recorded payload length CLAMPED to slot-bytes (so a forged on-wire
   LEN can never make a caller read past the fixed slot allocation — NFR-SEC-POSTURE), or NIL if SLOT-INDEX
   is out of range or its generation != GENERATION (stale / force-reclaimed). The clamp is the OOB-safe
   bound: a slot is a fixed slot-bytes region, so min(recorded-len, slot-bytes) is always in-bounds."
  (when (>= slot-index (%zc-slot-count sap)) (return-from %zc-slot-payload-len nil))
  (let ((b (%zc-slot-off sap slot-index)))
    (when (= generation (cffi:mem-ref sap :uint32 (+ b +zc-slot-off-generation+)))
      (min (cffi:mem-ref sap :uint32 (+ b +zc-slot-off-len+)) (%zc-slot-bytes sap)))))

(defun* %zc-acquire-for-read (sap slot-index generation)
    (function (t (integer 0) (unsigned-byte 32))
              (values (or null t) &optional (integer 0) (unsigned-byte 32) (unsigned-byte 32) (integer 0)))
  "Reader, the literal-0-copy loan acquire (WP-FLATDATA-ZC-LOAN Task C1, FR-PF-3/4, R6, ADR 0017; NOT cleared
   for ship — pending counsel). LOCK-FREE FENCED READ (WP-ZC-LOAN-LOCKFREE Phase B, R6, ADR 0018; NOT cleared
   for ship — pending counsel): NO mutex, NO copy ⇒ 0 GC-heap bytes per acquire. Validate SLOT-INDEX in range,
   then ACQUIRE-LOAD the generation, then dds.pal:fence :acquire, then validate generation == GENERATION (the
   single race guard — a stale ref whose slot was force-reclaimed + generation-rebumped ⇒ the loan FAILS), then
   read LEN + return a slot-view handle (values POOL-SAP SLOT-INDEX GENERATION PAYLOAD-LEN PAYLOAD-BASE) WITHOUT
   COPYING — the app reads fields straight off the slot via the SAP-mode FlatData accessors (literal 0 intra-host
   copies). PAYLOAD-LEN is the recorded LEN CLAMPED to slot-bytes (min), so a forged on-wire LEN can never expose
   a read past the fixed slot allocation (NFR-SEC-POSTURE, OOB-safe even at (safety 0)); PAYLOAD-BASE is the
   slot's payload byte offset within the segment (slot-off + +zc-slot-hdr+) for dds.pal:load-sap-u* reads at
   SAP+PAYLOAD-BASE+field-offset. Returns NIL (single value) on any validation failure (stale / force-reclaimed /
   OOB) — best-effort: the caller drops the sample.
   MEMORY-ORDERING HANDSHAKE (the binary gate): the ORDER is load-coherent — read the generation FIRST, THEN the
   acquire-fence, THEN the dependent LEN/payload reads. The generation acquire-load + dds.pal:fence :acquire
   (SBCL sb-thread:barrier(:read)) PAIRS-WITH the writer's dds.pal:fence :release + generation-store-LAST in
   %zc-loan (the generation is the release/acquire sync variable, mirroring the WP-SHMEM ring cursor handshake):
   when this reader observes the new generation, the payload (+ len) the writer wrote-before the release is
   guaranteed visible — no torn read. A stale/forged ref ⇒ generation mismatch ⇒ NIL before any payload read.
   REFCOUNT MODEL (precise): the writer's %zc-loan SET refcount = matched-readers and stamps the slot; THIS
   reader's count is already pre-allocated within that initial refcount, so the loan is held by that existing
   count from %zc-loan through the disc-receiver store, this acquire, and the app's reads — until the reader's
   %zc-release decrements it. %zc-acquire-for-read therefore does NOT increment the refcount (incrementing would
   double-count this reader and leak the slot). The slot cannot be force-reclaimed while held because
   %zc-take-free-or-reclaim only reclaims refcount==0 slots; %zc-release at the 1->0 edge frees it back. (No
   mutual exclusion is needed: a held slot's generation/len/payload are STABLE while refcount>0, so the acquire
   needs only cross-process VISIBILITY, which the generation sync variable + the fence pair provide.)"
  (when (>= slot-index (%zc-slot-count sap)) (return-from %zc-acquire-for-read nil))
  (let* ((b (%zc-slot-off sap slot-index))
         (g (dds.pal:load-sap-u32 sap (+ b +zc-slot-off-generation+))))
    (dds.pal:fence :acquire)
    (when (= g generation)
      (let ((len (min (dds.pal:load-sap-u32 sap (+ b +zc-slot-off-len+)) (%zc-slot-bytes sap))))
        (values sap slot-index generation len (+ b +zc-slot-hdr+))))))

(defun* %zc-resolve-into (sap slot-index generation dst dst-off)
    (function (t (integer 0) (unsigned-byte 32) (simple-array (unsigned-byte 8) (*)) (integer 0))
              (or null (integer 0)))
  "Reader, the 0-EXTRA-ALLOC resolve (WP-FLATDATA-over-ZC, FR-PF-3/4): under the mutex, if SLOT-INDEX is in
   range AND its generation == GENERATION, copy the slot's payload octets into DST starting at DST-OFF and
   return the number copied; else NIL (stale/reclaimed/OOB ref — untrusted cross-process input). The copy
   length is min(slot recorded-LEN, slot-bytes, room in DST after DST-OFF), so it NEVER reads past the fixed
   slot allocation NOR writes past DST even on a forged LEN or an undersized DST (bounds-checked even at
   (safety 0), NFR-SEC-POSTURE). DST is a CALLER-OWNED Lisp array (e.g. the per-datagram delivery vector);
   the copy-under-mutex keeps the slot stable vs a concurrent force-reclaim, and because the bytes land in
   DST the caller may %zc-release the slot immediately — no cross-process lifetime spans the app read. Unlike
   %zc-resolve, DST need only hold the PAYLOAD (not the full slot-bytes), so the reader needs no slot-sized
   scratch sink."
  (dds.pal:pshared-lock sap +zc-mutex-off+)
  (unwind-protect
       (let ((len (%zc-slot-payload-len sap slot-index generation)))
         (when len
           (let* ((b (%zc-slot-off sap slot-index))
                  (room (max 0 (- (length dst) dst-off)))
                  (n (min len room)))
             (dotimes (k n n) (setf (aref dst (+ dst-off k)) (cffi:mem-ref sap :uint8 (+ b +zc-slot-hdr+ k)))))))
    (dds.pal:pshared-unlock sap +zc-mutex-off+)))

(defun* %zc-resolve (sap slot-index generation sink)
    (function (t (integer 0) (unsigned-byte 32) (simple-array (unsigned-byte 8) (*))) (or null (integer 0)))
  "Reader: under the mutex, if SLOT-INDEX in range AND its generation == GENERATION, copy the slot's LEN
   payload octets into SINK (capacity >= slot-bytes) and return LEN; else NIL (stale/reclaimed/OOB ref —
   untrusted cross-process input, NFR-SEC-POSTURE: never OOB). The copy-under-mutex keeps the slot stable
   vs a concurrent force-reclaim. Thin wrapper over %zc-resolve-into at DST-OFF 0 (DRY)."
  (%zc-resolve-into sap slot-index generation sink 0))

(defun* %zc-resolve-fresh (sap slot-index generation)
    (function (t (integer 0) (unsigned-byte 32)) (or null (simple-array (unsigned-byte 8) (*))))
  "Reader, the single-copy resolve (WP-FLATDATA-over-ZC, FR-PF-3/4): under ONE mutex acquisition, validate
   SLOT-INDEX + generation, allocate a delivery vector sized to the slot's CLAMPED payload length (NOT the
   full slot-bytes — so the reader needs no slot-sized scratch sink and re-copy), copy the payload into it,
   and return it; NIL on a stale/reclaimed/OOB ref. The single under-mutex copy is the only intra-host copy
   on this RX path (the slot is read in place straight into the owned vector — the WP-ZEROCOPY v1
   resolve-into-sink-then-re-copy is gone). Because the bytes land in a CALLER-OWNED Lisp vector, the caller
   releases the slot immediately on return: no cross-process slot lifetime spans the app's later read, so no
   use-after-free. The copy length is min(recorded-LEN, slot-bytes) — never past the fixed slot allocation
   even on a forged on-wire LEN (NFR-SEC-POSTURE)."
  (when (>= slot-index (%zc-slot-count sap)) (return-from %zc-resolve-fresh nil))
  (dds.pal:pshared-lock sap +zc-mutex-off+)
  (unwind-protect
       (let ((len (%zc-slot-payload-len sap slot-index generation)))
         (when len
           (let ((vec (make-array len :element-type '(unsigned-byte 8)))
                 (b (%zc-slot-off sap slot-index)))
             (dotimes (k len vec) (setf (aref vec k) (cffi:mem-ref sap :uint8 (+ b +zc-slot-hdr+ k)))))))
    (dds.pal:pshared-unlock sap +zc-mutex-off+)))
