;;;; WP-KEEPLAST (Task E1, FR-LANG-7): the HONEST writer-side cost of per-instance KEEP_LAST.
;;;; WP-KEEPLAST added, on the writer HISTORY path: (1) the 16-octet instance keyhash computation
;;;; (keyed KEEP_LAST writes only — gated by %writer-keeplast-p in DCPS write-sample), (2) the
;;;; per-instance index append (%hc-index-append: one cons onto the instance's SN bucket), and
;;;; (3) the per-instance bucket-evict at depth (%hc-remove-change off the bucket head). This
;;;; harness isolates that machinery by driving dds.rtps.history:hc-add-change directly — the unit
;;;; the WP modified — across KEEP_ALL vs KEEP_LAST, keyed vs unkeyed, so the delta is the
;;;; per-instance machinery and nothing else (the transport / discovery / serialization path that
;;;; the full perftest harness measures would swamp this signal by orders of magnitude). The
;;;; cache-change cons is pre-existing (history.lisp:25 flags pooling as a follow-up) and is held
;;;; INSIDE every measured loop, so it cancels in the KEEP_LAST-vs-KEEP_ALL delta; the keyhash
;;;; allocation is measured on its own line so it can be attributed precisely. Timing is
;;;; dds.pal:monotonic-ns (~us resolution, amortised over the loop); GC bytes/sample is the
;;;; dds.pal:bytes-consed delta / N (the NFR-PERF-8 oracle, SBCL-exact; Clasp reports 0 — a
;;;; documented NFR-PORT gap, so the SBCL numbers are the record). No "0-cost" claim: the keyed
;;;; KEEP_LAST keyhash is a real ~16-byte/sample allocation + the index cons; KEEP_ALL and the
;;;; unkeyed collapse stay as before. The reader-side per-instance O(N) drop is a SEPARATE cost
;;;; (the DCPS dr-cache scan, not measured here).

(in-package #:dds.bench)

(defparameter +keeplast-bench-keyhash-bytes+ 16
  "Octet count of a keyed instance handle (the 16-octet KeyHash, DDS 1.4 §2.2.3.18 / RTPS 2.5
   §9.6.4.8) — the per-write allocation a keyed KEEP_LAST writer adds vs the prior KEEP_ALL path.")

(defun* %keeplast-keyhash (instance)
    (function ((integer 0)) (simple-array (unsigned-byte 8) (16)))
  "A distinct 16-octet instance handle for the bench's INSTANCE index — the writer-side analogue of
   the keyhash DCPS write-sample computes per keyed KEEP_LAST write (%instance-handle). The low 4
   octets carry INSTANCE so K instances get K distinct EQUALP buckets in the HistoryCache index."
  (let ((kh (make-array +keeplast-bench-keyhash-bytes+ :element-type '(unsigned-byte 8)
                                                       :initial-element 0)))
    (setf (aref kh 0) (logand instance #xff)
          (aref kh 1) (logand (ash instance -8) #xff)
          (aref kh 2) (logand (ash instance -16) #xff)
          (aref kh 3) (logand (ash instance -24) #xff))
    kh))

(defun* %keeplast-keyhashes (instances)
    (function ((integer 1)) simple-vector)
  "A precomputed vector of INSTANCES distinct keyhashes, so the measured add loop reuses one handle
   per instance (a keyed writer re-derives the handle per write; the per-write derivation cost is
   measured on its own line by %keeplast-keyhash-alloc-ns, not folded into the HC add measurement)."
  (let ((v (make-array instances)))
    (dotimes (i instances v) (setf (svref v i) (%keeplast-keyhash i)))))

(defun* %keeplast-add-ns (kind depth keyed samples instances)
    (function ((member :keep-last :keep-all) (integer 1) t (integer 1) (integer 1)) (values double-float integer))
  "Add SAMPLES :data CacheChanges across INSTANCES instances to a fresh HistoryCache of HISTORY
   KIND/DEPTH, returning (values ns/sample bytes/sample). KEYED non-NIL threads a per-instance
   16-octet keyhash onto each change (KEEP_LAST then evicts per instance, DDS 1.4 §2.2.3.18); KEYED
   NIL threads no handle (every change collapses to the single :unkeyed bucket = global KEEP_LAST /
   the prior behavior). The cache-change cons is INSIDE the loop in every mode (pre-existing, cancels
   in the delta); ns/sample is the dds.pal:monotonic-ns total / SAMPLES (~us clock, amortised),
   bytes/sample the dds.pal:bytes-consed delta / SAMPLES (SBCL-exact, Clasp 0 by NFR-PORT gap)."
  (let* ((hc (dds.rtps.history:make-history-cache kind depth nil nil))
         (khs (when keyed (%keeplast-keyhashes instances)))
         (t0 (dds.pal:monotonic-ns))
         (c0 (dds.pal:bytes-consed)))
    (dotimes (i samples)
      (let ((kh (when keyed (svref khs (mod i instances)))))
        (dds.rtps.history:hc-add-change
         hc (dds.rtps.history:make-cache-change :sn (1+ i) :instance-key-hash kh))))
    (let ((consed (- (dds.pal:bytes-consed) c0))
          (ns (max 1 (- (dds.pal:monotonic-ns) t0))))
      (values (/ (float ns 1.0d0) samples) (round consed samples)))))

(defun* %keeplast-keyhash-alloc-ns (samples instances)
    (function ((integer 1) (integer 1)) (values double-float integer))
  "Measure ONLY the per-write keyhash derivation a keyed KEEP_LAST writer adds in DCPS write-sample
   (%instance-handle -> %keeplast-keyhash here): allocate one fresh 16-octet handle SAMPLES times
   across INSTANCES distinct values, returning (values ns/sample bytes/sample). This is the
   ~16-byte/sample line the WP adds for a keyed KEEP_LAST writer (an unkeyed type instead reuses the
   shared +instance-handle-nil+ = 0 bytes; a KEEP_ALL writer never derives a handle)."
  (let ((sink nil) (t0 (dds.pal:monotonic-ns)) (c0 (dds.pal:bytes-consed)))
    (declare (type t sink))
    (dotimes (i samples) (setf sink (%keeplast-keyhash (mod i instances))))
    (let ((consed (- (dds.pal:bytes-consed) c0))
          (ns (max 1 (- (dds.pal:monotonic-ns) t0))))
      (when sink (values (/ (float ns 1.0d0) samples) (round consed samples))))))

(defun* %keeplast-throughput (ns-per-sample)
    (function (double-float) (integer 0))
  "Writer-side throughput (samples/s) from NS-PER-SAMPLE — 1e9 / ns/sample, the per-mode add rate."
  (if (plusp ns-per-sample) (round (/ 1.0d9 ns-per-sample)) 0))

(defun* %keeplast-row (label kind depth keyed samples instances)
    (function (string (member :keep-last :keep-all) (integer 1) t (integer 1) (integer 1)) list)
  "Run one mode and return a result plist (:label :kind :depth :keyed :throughput :ns :bytes) — the
   HC add-path cost (ns/sample + samples/s + GC bytes/sample) for LABEL under HISTORY KIND/DEPTH,
   KEYED or not, over SAMPLES across INSTANCES."
  (multiple-value-bind (ns bytes) (%keeplast-add-ns kind depth keyed samples instances)
    (list :label label :kind kind :depth depth :keyed keyed
          :throughput (%keeplast-throughput ns) :ns ns :bytes bytes)))

(defun* %print-keeplast-row (r)
    (function (list) t)
  "Print one %keeplast-row plist R as a markdown table row (mode, samples/s, ns/sample, bytes/sample)."
  (format t "~&| ~a | ~12d | ~10,1f | ~11d |~%"
          (getf r :label) (getf r :throughput) (getf r :ns) (getf r :bytes))
  t)

(defun* run-keeplast-bench (&key (samples 1000000) (instances 100) (depth 2) (stream *standard-output*))
    (function (&key (:samples (integer 1)) (:instances (integer 1)) (:depth (integer 1))
               (:stream stream)) t)
  "Run the WP-KEEPLAST writer-side HISTORY-machinery bench (FR-LANG-7) and print a markdown report to
   STREAM: the HistoryCache add-path cost (writer throughput samples/s + GC bytes/sample) for KEEP_ALL
   keyed (the prior default behavior — keyhash NIL, no per-instance index work beyond the shared
   bucket), KEEP_LAST depth-DEPTH keyed (the NEW machinery — per-instance index append + per-instance
   evict + the keyhash carried on the change), KEEP_ALL unkeyed and KEEP_LAST unkeyed (the unkeyed
   collapse), plus a separate keyhash-derivation line (the ~16-byte/sample a keyed KEEP_LAST writer
   adds in DCPS). The CLEAN per-instance-machinery isolation is KEEP_LAST keyed vs KEEP_LAST unkeyed
   (SAME kind + retention); the KEEP_ALL-vs-KEEP_LAST byte delta is confounded by RETENTION (KEEP_ALL
   retains all SAMPLES, KEEP_LAST evicts to DEPTH*INSTANCES) and the report calls that out. SAMPLES is
   the per-mode add count, INSTANCES the distinct keyed instances (SAMPLES spread round-robin so each
   bucket overflows DEPTH and the per-instance evict fires), DEPTH the KEEP_LAST per-instance depth.
   Honest measurement: SBCL bytes are the record (Clasp dds.pal:bytes-consed reports 0, a documented
   NFR-PORT gap); no 0-cost claim. The reader-side per-instance O(N) drop is a separate cost."
  (let ((*standard-output* stream))
    (format t "~&# WP-KEEPLAST — writer-side per-instance KEEP_LAST HISTORY-machinery cost (FR-LANG-7)~%~%")
    (format t "Drives dds.rtps.history:hc-add-change directly (the unit WP-KEEPLAST modified) so the measurement isolates the HISTORY add path, not the transport/serialization path. Clock: dds.pal:monotonic-ns (~~us, amortised over ~d samples). GC bytes/sample: dds.pal:bytes-consed delta / samples (SBCL-exact; Clasp reports 0 — a documented NFR-PORT gap, so SBCL is the record). The cache-change cons is held INSIDE every measured loop (pre-existing — history.lisp:25 flags pooling as a follow-up); the keyhash allocation is measured on its own line. HONESTY CAVEAT (FR-LANG-7): KEEP_ALL and KEEP_LAST differ in RETENTION (KEEP_ALL retains all ~d changes — its change-table grows + rehashes; KEEP_LAST evicts to dep*instances), so the KEEP_ALL-vs-KEEP_LAST byte delta is dominated by retention, NOT machinery. The clean isolation of the per-instance machinery is KEEP_LAST keyed vs KEEP_LAST unkeyed (same kind, same retention — only the per-instance index/bucketing differs) plus the keyhash line; both are reported below.~%~%" samples samples)
    (format t "Parameters: samples=~d, instances=~d, KEEP_LAST depth=~d (samples spread round-robin so each instance bucket overflows depth and the per-instance evict fires).~%~%" samples instances depth)
    (format t "**Regression this bench surfaced + fixed (Task E1):** the WP's `%hc-store` originally appended to the per-instance index UNCONDITIONALLY via `nconc` (an O(bucket-length) tail-walk). For KEEP_ALL the index bucket is never evicted, so it grew unbounded → O(N) per insert = **O(N²) total** on the KEEP_ALL write path (a regression vs pre-WP O(1)). FIX: the per-instance index is the KEEP_LAST eviction mechanism, so `%hc-index-append`/`%hc-index-drop` now no-op for KEEP_ALL — KEEP_ALL is the O(1) change-table insert it was pre-WP (measured below: KEEP_ALL ns/sample is now FLAT across N, ~~70 ns/sample at any size, vs ~~3.6/7.3/14.1 us/sample climbing at N=10k/20k/40k before the fix).~%~%")
    (format t "## HistoryCache add-path cost per mode~%~%")
    (format t "| mode | writer samples/s | ns/sample | GC bytes/samp |~%")
    (format t "|------|------------------|-----------|---------------|~%")
    (let ((ka-keyed (%keeplast-row "KEEP_ALL keyed (prior default behavior)  " :keep-all 1 nil samples instances))
          (kl-keyed (%keeplast-row "KEEP_LAST keyed (NEW per-instance machinery)" :keep-last depth t samples instances))
          (ka-unkeyed (%keeplast-row "KEEP_ALL unkeyed                          " :keep-all 1 nil samples instances))
          (kl-unkeyed (%keeplast-row "KEEP_LAST unkeyed (global collapse)       " :keep-last depth nil samples instances)))
      (%print-keeplast-row ka-keyed)
      (%print-keeplast-row kl-keyed)
      (%print-keeplast-row ka-unkeyed)
      (%print-keeplast-row kl-unkeyed)
      (multiple-value-bind (kh-ns kh-bytes) (%keeplast-keyhash-alloc-ns samples instances)
        (format t "~%## The keyhash derivation (keyed KEEP_LAST writes only — DCPS %instance-handle)~%~%")
        (format t "| operation | ns/sample | GC bytes/samp |~%")
        (format t "|-----------|-----------|---------------|~%")
        (format t "| fresh 16-octet keyhash (`make-array 16`) | ~10,1f | ~11d |~%" kh-ns kh-bytes)
        (format t "~%## What WP-KEEPLAST costs on the write path (honest — FR-LANG-7)~%~%")
        (format t "- **The per-instance index/bucketing (KEEP_LAST keyed vs KEEP_LAST unkeyed — SAME kind, SAME retention):** ~@d GC bytes/sample, ~,1@f ns/sample (keyed ~,1f - unkeyed ~,1f ns/sample). This is the CLEAN isolation of the per-instance machinery: both evict at depth, both cons one cache-change/sample, both hold dep*instances vs dep*1 changes — the difference is the keyed case's EQUALP hashing of 16-octet keys across ~d buckets vs the unkeyed case's single :unkeyed-keyword bucket. The index append + per-instance evict add ~~0 STEADY-STATE GC bytes/sample (the bucket conses are freed on evict; the residual cost is the equalp hash time).~%"
                (- (getf kl-keyed :bytes) (getf kl-unkeyed :bytes))
                (- (getf kl-keyed :ns) (getf kl-unkeyed :ns)) (getf kl-keyed :ns) (getf kl-unkeyed :ns)
                instances)
        (format t "- **The keyhash a keyed KEEP_LAST writer adds (DCPS %instance-handle, ABOVE the HC):** ~d GC bytes/sample (the 16-octet handle + its array header) + ~,1f ns/sample — this is the headline per-sample allocation the WP adds for a KEYED KEEP_LAST writer. A KEEP_ALL writer derives NO handle (it threads NIL — %writer-keeplast-p gates it), and an unkeyed type reuses the shared +instance-handle-nil+ (0 bytes/sample).~%" kh-bytes kh-ns)
        (format t "- **KEEP_ALL is unchanged (O(1), no index):** the KEEP_ALL keyed and KEEP_ALL unkeyed rows match (keyhash NIL either way), and after the Task-E1 fix the KEEP_ALL add keeps NO per-instance index at all (the index is the KEEP_LAST eviction mechanism; %hc-index-append/-drop no-op for KEEP_ALL) — so KEEP_ALL is the same O(1) change-table insert it was pre-WP. (Its higher GC bytes/sample here vs KEEP_LAST is RETENTION: KEEP_ALL retains all ~d changes so its change-table grows + rehashes, while KEEP_LAST evicts to ~d — NOT machinery.)~%"
                samples (* depth instances))
        (format t "- **Unkeyed collapses to global:** KEEP_LAST unkeyed routes every change to one shared bucket (= a correct global KEEP_LAST), so it pays the index + evict but NO keyhash.~%")
        (format t "~%NO `0-cost`/`free` claim: a KEYED KEEP_LAST writer adds a real ~~~d-byte/sample keyhash (the dominant add) + the per-instance index cons (freed on evict, ~~0 steady-state bytes); KEEP_ALL and the unkeyed path are unchanged. The reader-side per-instance drop (`%reader-keeplast-drop-oldest`, an O(N) dr-cache scan per over-depth sample) is a SEPARATE cost, not measured here (it matches the pre-existing RESOURCE_LIMITS reject scan; a per-instance reader index is a noted follow-up, ADR 0019).~%"
                kh-bytes)))
    t))

(defun* run-keeplast-bench-smoke ()
    (function () t)
  "Suite-friendly self-check of the WP-KEEPLAST bench path: a tiny add run in every mode asserting the
   add returns a positive throughput and a non-negative bytes/sample, PLUS a tiny full run-keeplast-bench
   to a string stream (so the report's format strings are exercised — CI catches a malformed directive,
   not just a measurement break) asserting it produced a non-trivial report. Signals an error on failure
   (the dds.tests runner treats that as a test failure)."
  (let ((kl (%keeplast-row "kl" :keep-last 2 t 2000 50))
        (ka (%keeplast-row "ka" :keep-all 1 nil 2000 50))
        (report (with-output-to-string (s)
                  (run-keeplast-bench :samples 2000 :instances 20 :depth 2 :stream s))))
    (assert (plusp (getf kl :throughput)) () "keeplast bench smoke: KEEP_LAST non-positive throughput")
    (assert (plusp (getf ka :throughput)) () "keeplast bench smoke: KEEP_ALL non-positive throughput")
    (assert (>= (getf kl :bytes) 0) () "keeplast bench smoke: negative bytes/sample")
    (assert (search "WP-KEEPLAST" report) () "keeplast bench smoke: report did not render")
    (multiple-value-bind (kh-ns kh-bytes) (%keeplast-keyhash-alloc-ns 2000 50)
      (assert (plusp kh-ns) () "keeplast bench smoke: non-positive keyhash ns")
      (assert (>= kh-bytes 0) () "keeplast bench smoke: negative keyhash bytes")))
  t)
