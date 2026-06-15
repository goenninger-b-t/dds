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
(defconstant +zc-off-free-head+ 16 "Header byte offset of the u32 freelist head (slot index, or +zc-free-end+).")
(defconstant +zc-mutex-off+ 64 "Byte offset of the pool's PTHREAD_PROCESS_SHARED mutex (guards all slot state).")
(defconstant +zc-slots-off+ 128 "Byte offset where the K slots begin (after header + mutex region).")
(defconstant +zc-slot-hdr+ 32 "Per-slot header bytes preceding the slot payload.")
(defconstant +zc-slot-off-refcount+ 0 "Within-slot offset of the u32 refcount.")
(defconstant +zc-slot-off-generation+ 4 "Within-slot offset of the u32 generation (the single race guard).")
(defconstant +zc-slot-off-len+ 8 "Within-slot offset of the u32 payload length; overlays the freelist 'next' while free.")
(defconstant +zc-slot-off-pubseq+ 16 "Within-slot offset of the u64 publish sequence (force-reclaim 'oldest' ordering).")
(defconstant +zc-free-end+ #xFFFFFFFF "Freelist terminator (no next free slot).")

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
  "Initialise header + pshared mutex; thread all slots onto the freelist (the LEN field overlays the
   freelist 'next' pointer while a slot is free); zero refcount/generation/pubseq. Creator-only."
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
            (cffi:mem-ref sap :uint32 (+ b +zc-slot-off-len+)) (if (= i (1- slot-count)) +zc-free-end+ (1+ i)))
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
  "Walk the freelist counting free slots (test/debug; not hot path)."
  (let ((n 0) (cur (cffi:mem-ref sap :uint32 +zc-off-free-head+)))
    (loop until (= cur +zc-free-end+) do (incf n)
          (setf cur (cffi:mem-ref sap :uint32 (+ (%zc-slot-off sap cur) +zc-slot-off-len+))))
    n))

(defvar *zc-pubseq* 0 "Process-local monotonic publish sequence for force-reclaim 'oldest' ordering.")

(defun* %zc-take-free-or-reclaim (sap)
    (function (t) (integer 0))
  "CALLER HOLDS THE MUTEX. Pop the freelist head; if empty, pick + detach the published slot with the
   lowest pubseq (oldest) — the caller's generation bump then invalidates any in-flight ref to it."
  (let ((head (cffi:mem-ref sap :uint32 +zc-off-free-head+)))
    (if (/= head +zc-free-end+)
        (progn (setf (cffi:mem-ref sap :uint32 +zc-off-free-head+)
                     (cffi:mem-ref sap :uint32 (+ (%zc-slot-off sap head) +zc-slot-off-len+)))
               head)
        (let ((oldest 0) (oldest-seq (dds.pal:load-sap-u64 sap (+ (%zc-slot-off sap 0) +zc-slot-off-pubseq+))))
          (dotimes (i (%zc-slot-count sap) oldest)
            (let ((s (dds.pal:load-sap-u64 sap (+ (%zc-slot-off sap i) +zc-slot-off-pubseq+))))
              (when (< s oldest-seq) (setf oldest i oldest-seq s))))))))

(defun* %zc-loan (sap payload off len readers)
    (function (t (simple-array (unsigned-byte 8) (*)) (integer 0) (integer 0) (integer 0))
              (values (or null (integer 0)) (unsigned-byte 32)))
  "Single-producer (the owning writer): loan a slot for PAYLOAD[off,off+len) to READERS consumers. Take a
   free slot, else force-reclaim the oldest. Bump the slot generation, copy the payload in, set
   refcount=READERS, stamp pubseq. Returns (values slot-index generation), or (values NIL 0) if LEN >
   slot-bytes."
  (when (> len (%zc-slot-bytes sap)) (return-from %zc-loan (values nil 0)))
  (dds.pal:pshared-lock sap +zc-mutex-off+)
  (unwind-protect
       (let* ((i (%zc-take-free-or-reclaim sap))
              (b (%zc-slot-off sap i))
              (g (logand (1+ (cffi:mem-ref sap :uint32 (+ b +zc-slot-off-generation+))) #xFFFFFFFF)))
         (setf (cffi:mem-ref sap :uint32 (+ b +zc-slot-off-generation+)) g
               (cffi:mem-ref sap :uint32 (+ b +zc-slot-off-len+)) len
               (cffi:mem-ref sap :uint32 (+ b +zc-slot-off-refcount+)) readers)
         (dds.pal:store-sap-u64 sap (+ b +zc-slot-off-pubseq+) (incf *zc-pubseq*))
         (dotimes (k len) (setf (cffi:mem-ref sap :uint8 (+ b +zc-slot-hdr+ k)) (aref payload (+ off k))))
         (values i g))
    (dds.pal:pshared-unlock sap +zc-mutex-off+)))

(defun* %zc-release (sap slot-index generation)
    (function (t (integer 0) (unsigned-byte 32)) t)
  "A reader releasing slot SLOT-INDEX it read at GENERATION: under the mutex, validate bounds + generation,
   decrement refcount; at 0 push the slot onto the freelist (LEN overlays 'next'). T if applied, NIL if
   stale/OOB (no-op — best-effort tolerates a lost/forced-reclaimed ref)."
  (when (>= slot-index (%zc-slot-count sap)) (return-from %zc-release nil))
  (dds.pal:pshared-lock sap +zc-mutex-off+)
  (unwind-protect
       (let ((b (%zc-slot-off sap slot-index)))
         (cond ((/= generation (cffi:mem-ref sap :uint32 (+ b +zc-slot-off-generation+))) nil)
               (t (let ((rc (cffi:mem-ref sap :uint32 (+ b +zc-slot-off-refcount+))))
                    (when (plusp rc)
                      (setf (cffi:mem-ref sap :uint32 (+ b +zc-slot-off-refcount+)) (1- rc))
                      (when (= 1 rc)
                        (setf (cffi:mem-ref sap :uint32 (+ b +zc-slot-off-len+))
                              (cffi:mem-ref sap :uint32 +zc-off-free-head+)
                              (cffi:mem-ref sap :uint32 +zc-off-free-head+) slot-index)))
                    t))))
    (dds.pal:pshared-unlock sap +zc-mutex-off+)))

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
