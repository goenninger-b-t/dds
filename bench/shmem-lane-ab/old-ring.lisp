;; The BEFORE arm of the ADR 0119 / WP-0.7 ring-primitive A/B (bench/report/2026-10-03-shmem-lane-poison.md).
;; %lane-enqueue and %lane-drain exactly as they stood at commit 78895e0 (before ADR 0119), renamed
;; OLD-LANE-ENQUEUE / OLD-LANE-DRAIN so both arms can be timed interleaved in one process. Only the names
;; differ from that commit (checked with diff). Benchmark fixture: not part of any ASDF system, never loaded
;; by the stack. The pre-fix drain contains the out-of-bounds read ADR 0119 §1 describes; use it for timing
;; only, on a well-formed ring.
(in-package #:dds.xport.shmem)
(defun* old-lane-enqueue (sap lane capacity payload off len)
    (function (t (integer 0) (integer 8) (simple-array (unsigned-byte 8) (*)) (integer 0) (integer 0)) t)
  "Single-producer enqueue of PAYLOAD[off,off+len) as one ring record into LANE. T on success, NIL if it
   does not fit (caller maps NIL to RESOURCE_LIMITS / UDP fallback). Publishes the advanced write-cursor
   with a RELEASE fence so the consumer's ACQUIRE load sees the payload.

   ⛔ SINGLE-PRODUCER IS A PRECONDITION THE CALLER MUST ENFORCE, not a property of the deployment (ADR
   0109). Read-cursor, memcpy and cursor-publish are three separate steps with no atomicity between them,
   so two threads on ONE lane resolve the same position and the second overwrites the first. %SHMEM-SEND
   holds SHMEM-DEST-SEND-LOCK across this call for exactly that reason. Cross-PROCESS single-producer is
   structural — a lane is owned by one sender token (%claim-lane) — but a sender is many THREADS."
  (when (> (+ 4 len) capacity) (return-from old-lane-enqueue nil))
  (let* ((base (%lane-desc-off lane))
         (data (%lane-data-off (%ring-lane-count sap) lane capacity))
         (w (dds.pal:load-sap-u64 sap (+ base +lane-off-write+)))
         (r (dds.pal:load-sap-u64 sap (+ base +lane-off-read+)))
         (span (%record-span len))
         (pos (mod w capacity))
         (tail (- capacity pos)))
    (let ((need (if (< tail span) (+ tail span) span)))
      (when (> (+ (- w r) need) capacity) (return-from old-lane-enqueue nil)))
    (when (< tail span)
      (setf (cffi:mem-ref sap :uint32 (+ data pos)) +skip-marker+)
      (incf w tail) (setf pos 0))
    (setf (cffi:mem-ref sap :uint32 (+ data pos)) len)
    (dds.pal:sap-copy-in sap (+ data pos 4) payload off len)   ; BULK memcpy, was one mem-ref per OCTET
    (dds.pal:fence :release)
    (dds.pal:store-sap-u64 sap (+ base +lane-off-write+) (+ w span))
    t))

(defun* old-lane-drain (sap lane capacity sink on-datagram)
    (function (t (integer 0) (integer 8) dds.core.buffer:octet-buffer function) t)
  "Single-consumer drain of LANE: ACQUIRE-load the producer's write-cursor, read every committed record up
   to it, copy each into SINK and call (ON-DATAGRAM SINK size), advance read-cursor. Bounds-check every
   len against max-record + the committed extent before trusting it (untrusted cross-process input).
   SINK capacity must be >= the ring max-record (caller contract; allocated once, off the hot path)."
  (let* ((base (%lane-desc-off lane))
         (data (%lane-data-off (%ring-lane-count sap) lane capacity))
         (maxr (%ring-max-record sap))
         (w (dds.pal:load-sap-u64 sap (+ base +lane-off-write+))))
    (dds.pal:fence :acquire)
    (let ((r (dds.pal:load-sap-u64 sap (+ base +lane-off-read+)))
          (vec (dds.core.buffer:octet-buffer-vec sink)))
      ;; w is cross-process/untrusted; a conforming producer never has w-r > capacity (NFR-SEC-POSTURE).
      (when (> (- w r) capacity) (return-from old-lane-drain t))
      (loop while (< r w) do
        (let* ((pos (mod r capacity))
               (len (cffi:mem-ref sap :uint32 (+ data pos))))
          (cond
            ((= len +skip-marker+) (incf r (- capacity pos)))
            ((or (> len maxr) (> (+ 4 len) (- capacity pos)) (> (%record-span len) (- w r)))
             (return-from old-lane-drain t))
            (t (dds.pal:sap-copy-out sap (+ data pos 4) vec 0 len)   ; BULK memcpy, was one mem-ref per OCTET
               (funcall on-datagram sink len)
               (incf r (%record-span len))))))
      (dds.pal:store-sap-u64 sap (+ base +lane-off-read+) r)
      t)))

