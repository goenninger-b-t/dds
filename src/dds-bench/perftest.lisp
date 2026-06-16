;;;; WP-PERFTEST (M5/P4): latency PING/PONG, throughput, and per-sample allocation over the
;;;; participant data plane (dds.disc) on UDP loopback. One-way latency is RTT/2 from a single
;;;; in-flight ping echoed by a second in-process node, timed with the PAL monotonic clock
;;;; (dds.pal:monotonic-ns); bytes/sample is the dds.pal:bytes-consed delta over the measured
;;;; loop (NFR-PERF-8 oracle, SBCL-exact; Clasp reports 0 — a documented NFR-PORT gap). This is
;;;; a baseline harness: it reports the CURRENT numbers so the P4 features (batching, async,
;;;; zero-copy, FlatData) have a measured before/after (FR-LANG-7). Clock resolution is the PAL
;;;; clock's (currently microseconds via get-internal-real-time); a higher-resolution PAL clock
;;;; is a separate enhancement. The disc-layer receive cache grows for the run (no take here),
;;;; so keep SAMPLES * PAYLOAD-BYTES bounded — addressed in a later WP-PERFTEST increment.

(in-package #:dds.bench)

(defparameter +reliable+ dds.rtps.discovery:+reliability-reliable+
  "Shorthand for the RELIABLE reliability-kind constant used by the harness endpoints.")

(defstruct* (rendezvous (:constructor %make-rendezvous))
  "Single-in-flight PING/PONG handoff between the pinger's main thread (waits) and its receiver
   thread (stamps RECV-NS + signals on the echoed pong). GOT guards against a lost wakeup."
  (lock (dds.pal:make-lock) :type t)
  (cv (dds.pal:make-condvar) :type t)
  (recv-ns 0 :type integer)
  (got nil :type t))

(defun* %prefix (b)
    (function ((unsigned-byte 8)) (simple-array (unsigned-byte 8) (12)))
  "A 12-octet GUID prefix of constant octet B (a distinct per-node value for the harness)."
  (make-array 12 :element-type '(unsigned-byte 8) :initial-element b))

(defun* %payload (n)
    (function ((integer 1)) (simple-array (unsigned-byte 8) (*)))
  "An N-octet opaque serialized payload (the harness transfers raw octets — no type-support)."
  (let ((v (make-array n :element-type '(unsigned-byte 8))))
    (dotimes (i n v) (setf (aref v i) (logand i #xff)))))

(defun* %connect (a b min-matches)
    (function (dds.disc:disc-node dds.disc:disc-node (integer 1)) t)
  "Wire two started in-process nodes over UDP loopback by :peers, then drive SPDP + SEDP until each
   side has at least MIN-MATCHES matched remote endpoints (1 for a one-way writer/reader, 2 for the
   bidirectional PING/PONG). Errors on a discovery/match timeout rather than hanging."
  (setf (dds.disc::disc-node-peers a) (list (cons "127.0.0.1" (dds.disc:disc-node-port b)))
        (dds.disc::disc-node-peers b) (list (cons "127.0.0.1" (dds.disc:disc-node-port a))))
  (dds.disc:announce-participant a) (dds.disc:announce-participant b)
  (loop repeat 300
        until (and (plusp (dds.disc:disc-node-discovered-count a))
                   (plusp (dds.disc:disc-node-discovered-count b)))
        do (sleep 0.01))
  (dds.disc:announce-endpoints a) (dds.disc:announce-endpoints b)
  (loop repeat 300
        until (and (>= (dds.disc:disc-node-matched-count a) min-matches)
                   (>= (dds.disc:disc-node-matched-count b) min-matches))
        do (sleep 0.01))
  (unless (and (>= (dds.disc:disc-node-matched-count a) min-matches)
               (>= (dds.disc:disc-node-matched-count b) min-matches))
    (error "perftest: nodes failed to match (a=~d b=~d, need ~d)"
           (dds.disc:disc-node-matched-count a) (dds.disc:disc-node-matched-count b) min-matches))
  t)

(defun* %drain-cache (node)
    (function (dds.disc:disc-node) t)
  "Clear NODE's polling sample cache (the disc-layer receive store) under the node lock, so a long run
   measures STEADY-STATE per-sample cost rather than unbounded cache accumulation (the cache stores
   every sample with no take). The reliable reader proxy's received-SN set is separate and untouched,
   so reliability is unaffected; this only empties the app-facing poll store."
  (dds.pal:with-lock ((dds.disc::disc-node-lock node))
    (clrhash (dds.disc::disc-node-samples node))
    (clrhash (dds.disc::disc-node-sample-writers node))
    (clrhash (dds.disc::disc-node-sample-writer-guids node)))
  t)

(defun* %pct (sorted frac)
    (function ((simple-array fixnum (*)) (real 0 1)) fixnum)
  "The FRAC quantile (0..1) of the ascending SORTED vector by nearest-rank."
  (aref sorted (min (1- (length sorted)) (floor (* frac (length sorted))))))

(defun* %shmem-transport-p (transport)
    (function (keyword) t)
  "T iff TRANSPORT routes user DATA over the SHMEM data plane (:shmem OR :zerocopy), NIL for :udp — the
   bench's transport switch. Both bench nodes run in ONE process (same host-uuid), so with *shmem-enabled*
   T (its default on SBCL and Clasp/Linux) the user-DATA push auto-routes over shared memory (%shmem-dest);
   rebinding it NIL forces the all-UDP baseline. :zerocopy also rides SHMEM (the ZC pool is a SHMEM segment,
   the ref still crosses over the SHMEM transport). NOT a wire constant — a local transport switch (WP-SHMEM)."
  (ecase transport (:udp nil) (:shmem t) (:zerocopy t)))

(defun* %zerocopy-transport-p (transport)
    (function (keyword) t)
  "T iff TRANSPORT selects WP-ZEROCOPY (:zerocopy), NIL for :udp/:shmem — the bench's zero-copy switch.
   When T the bench binds dds.disc:*zerocopy-enabled* T around make-disc-node so each node builds its
   per-writer SHMEM sample-pool; a large same-host sample (> *zerocopy-min-payload-bytes*) then crosses as
   a 16-byte reference instead of the serialized payload (FR-PF-3, ADR 0014). NOT a wire constant.
   NOT cleared for ship — pending counsel (R6)."
  (ecase transport (:udp nil) (:shmem nil) (:zerocopy t)))

(defun* %assert-shmem-sends (transport node label)
    (function (keyword dds.disc:disc-node string) t)
  "On the :shmem transport, assert NODE actually routed user DATA over shared memory (disc-node-shmem-sends
   advanced past 0) — so the bench PROVES it measured SHMEM, not a silent UDP fallback (FR-LANG-7). A no-op
   on :udp. Signals an error naming LABEL otherwise (e.g. *shmem-enabled* NIL, or the platform SHMEM gate)."
  (when (%shmem-transport-p transport)
    (assert (plusp (dds.disc::disc-node-shmem-sends node)) ()
            "WP-SHMEM bench: ~a routed 0 datagrams over SHMEM (shmem-sends=0) — SHMEM did not engage"
            label))
  t)

(defun* %assert-zc-sends (transport node label payload-bytes)
    (function (keyword dds.disc:disc-node string (integer 1)) t)
  "On the :zerocopy transport AND a PAYLOAD-BYTES strictly above dds.disc:*zerocopy-min-payload-bytes*,
   assert NODE actually published references (disc-node-zc-sends advanced past 0) — so the bench PROVES the
   large-sample path used a ZC reference, not a fragmented payload (FR-LANG-7, R6). A no-op on :udp/:shmem
   AND on a sub-threshold payload (where ZC correctly does NOT engage — the control case). Signals an error
   naming LABEL otherwise (e.g. *zerocopy-enabled* NIL or the SHMEM gate suppressed ZC for a large sample)."
  (when (and (%zerocopy-transport-p transport)
             (> payload-bytes dds.disc:*zerocopy-min-payload-bytes*))
    (assert (plusp (dds.disc::disc-node-zc-sends node)) ()
            "WP-ZEROCOPY bench: ~a published 0 zero-copy references (zc-sends=0) — ZC did not engage" label))
  t)

(defun* run-latency (&key (samples 10000) (payload-bytes 64) (warmup 500) (transport :udp))
    (function (&key (:samples (integer 1)) (:payload-bytes (integer 1)) (:warmup (integer 0))
               (:transport (member :udp :shmem :zerocopy))) list)
  "Measure one-way PING/PONG latency over the TRANSPORT data plane (:udp loopback baseline, default; :shmem
   same-host shared memory, WP-SHMEM; or :zerocopy same-host ZC reference passing, WP-ZEROCOPY/FR-PF-3): a
   pinger node writes a PAYLOAD-BYTES sample on topic PerfPing; an echoer node echoes a pong on PerfPong;
   one-way = RTT/2. Both nodes are in-process (same host-uuid), so on :shmem/:zerocopy the user DATA routes
   over shared memory; :udp rebinds dds.disc:*shmem-enabled* NIL to force UDP; :zerocopy additionally binds
   dds.disc:*zerocopy-enabled* T so a large sample (> *zerocopy-min-payload-bytes*) crosses as a 16-byte
   reference. After WARMUP throwaway round-trips, time SAMPLES of them and the bytes consed across the whole
   path; on :shmem assert each node's shmem-sends advanced, on :zerocopy assert zc-sends advanced (proof the
   measured path engaged, FR-LANG-7). Returns a plist: :samples :payload-bytes :transport :p50 :p99 :p9999
   :max :min :mean :bytes-per-sample :shmem-sends :zc-sends (latency values are ONE-WAY nanoseconds)."
  (let* ((dds.disc:*shmem-enabled* (%shmem-transport-p transport))
         (dds.disc:*zerocopy-enabled* (%zerocopy-transport-p transport))
         (p (dds.disc:make-disc-node :guid-prefix (%prefix #x70) :host "127.0.0.1" :port 0))
         (e (dds.disc:make-disc-node :guid-prefix (%prefix #x71) :host "127.0.0.1" :port 0))
         (rv (%make-rendezvous))
         (ping (%payload payload-bytes))
         (pong (%payload payload-bytes))
         (rtts (make-array samples :element-type 'fixnum :fill-pointer 0)))
    (unwind-protect
         (progn
           (dds.disc:add-local-writer p :topic "PerfPing" :type "perf")
           (dds.disc:add-local-reader p :topic "PerfPong" :type "perf" :reliability +reliable+)
           (dds.disc:enable-publisher p :history-kind :keep-all) (dds.disc:enable-subscriber p)   ; KEEP_ALL: a latency bench measures delivery, not history (ADR 0019)
           (dds.disc:add-local-reader e :topic "PerfPing" :type "perf" :reliability +reliable+)
           (dds.disc:add-local-writer e :topic "PerfPong" :type "perf")
           (dds.disc:enable-subscriber e) (dds.disc:enable-publisher e :history-kind :keep-all)   ; KEEP_ALL: the pong writer likewise (ADR 0019)
           (setf (dds.disc:disc-node-on-sample e)
                 (lambda () (dds.disc:publish-sample e pong)))
           (setf (dds.disc:disc-node-on-sample p)
                 (lambda ()
                   (dds.pal:with-lock ((rendezvous-lock rv))
                     (setf (rendezvous-recv-ns rv) (dds.pal:monotonic-ns) (rendezvous-got rv) t)
                     (dds.pal:condvar-signal (rendezvous-cv rv)))))
           (dds.disc:start-node p) (dds.disc:start-node e)
           (%connect p e 2)
           (flet ((one ()
                    (dds.pal:with-lock ((rendezvous-lock rv)) (setf (rendezvous-got rv) nil))
                    (let ((t0 (dds.pal:monotonic-ns)))
                      (dds.disc:publish-sample p ping)
                      (dds.pal:with-lock ((rendezvous-lock rv))
                        (loop with tries of-type fixnum = 0
                              until (rendezvous-got rv)
                              do (dds.pal:condvar-wait (rendezvous-cv rv) (rendezvous-lock rv) 1.0)
                                 (when (>= (incf tries) 5)
                                   (error "perftest: pong not received within 5 s (reliable stall?)"))))
                      (- (rendezvous-recv-ns rv) t0))))
             (dotimes (i warmup) (one) (%drain-cache p) (%drain-cache e))
             (let ((before (dds.pal:bytes-consed)) (shmem0 (dds.disc::disc-node-shmem-sends p))
                   (zc0 (dds.disc::disc-node-zc-sends p)))
               (dotimes (i samples) (vector-push (one) rtts) (%drain-cache p) (%drain-cache e))
               (%assert-shmem-sends transport p "pinger") (%assert-shmem-sends transport e "echoer")
               (%assert-zc-sends transport p "pinger" payload-bytes)
               (let* ((consed (- (dds.pal:bytes-consed) before))
                      (oneway (make-array samples :element-type 'fixnum)))
                 (dotimes (i samples) (setf (aref oneway i) (ash (aref rtts i) -1)))
                 (sort oneway #'<)
                 (list :samples samples :payload-bytes payload-bytes :transport transport
                       :p50 (%pct oneway 0.50) :p99 (%pct oneway 0.99)
                       :p9999 (%pct oneway 0.9999) :max (aref oneway (1- samples))
                       :min (aref oneway 0)
                       :mean (round (/ (loop for x across oneway sum x) samples))
                       :bytes-per-sample (round (/ consed samples))
                       :shmem-sends (- (dds.disc::disc-node-shmem-sends p) shmem0)
                       :zc-sends (- (dds.disc::disc-node-zc-sends p) zc0))))))
      (dds.disc:stop-node p) (dds.disc:stop-node e))))

(defun* run-throughput (&key (samples 20000) (payload-bytes 64) (batch 1) (transport :udp))
    (function (&key (:samples (integer 1)) (:payload-bytes (integer 1)) (:batch (integer 1))
               (:transport (member :udp :shmem :zerocopy))) list)
  "Measure one-way throughput over the TRANSPORT data plane (:udp loopback baseline, default; :shmem
   same-host shared memory, WP-SHMEM; or :zerocopy same-host ZC reference passing, WP-ZEROCOPY/FR-PF-3): a
   writer node blasts SAMPLES of a PAYLOAD-BYTES sample on topic PerfThru as fast as write() returns; a
   reader node counts delivery. Both nodes are in-process (same host-uuid), so on :shmem/:zerocopy the user
   DATA routes over shared memory; :udp rebinds dds.disc:*shmem-enabled* NIL to force UDP; :zerocopy binds
   dds.disc:*zerocopy-enabled* T so a large sample (> *zerocopy-min-payload-bytes*) crosses as a 16-byte
   reference rather than a fragmented payload. BATCH > 1 enables WP-BATCH write-side batching (flush every
   BATCH samples). On :shmem assert the writer's shmem-sends advanced, on :zerocopy assert zc-sends advanced
   (proof the measured path engaged, FR-LANG-7). Returns a plist: :samples :payload-bytes :batch :transport
   :received :send-samples-per-s :delivered-samples-per-s :send-mbps :bytes-per-sample :shmem-sends :zc-sends."
  (let* ((dds.disc:*shmem-enabled* (%shmem-transport-p transport))
         (dds.disc:*zerocopy-enabled* (%zerocopy-transport-p transport))
         (p (dds.disc:make-disc-node :guid-prefix (%prefix #x72) :host "127.0.0.1" :port 0
                                     :batch-max-samples batch))
         (e (dds.disc:make-disc-node :guid-prefix (%prefix #x73) :host "127.0.0.1" :port 0))
         (payload (%payload payload-bytes)))
    (unwind-protect
         (progn
           (dds.disc:add-local-writer p :topic "PerfThru" :type "perf")
           (dds.disc:enable-publisher p :history-kind :keep-all)   ; KEEP_ALL: throughput delivers all `samples` (ADR 0019)
           (dds.disc:add-local-reader e :topic "PerfThru" :type "perf" :reliability +reliable+)
           (dds.disc:enable-subscriber e)
           (dds.disc:start-node p) (dds.disc:start-node e)
           (%connect p e 1)
           (let ((t0 (dds.pal:monotonic-ns)) (consed0 (dds.pal:bytes-consed)))
             (dotimes (i samples) (dds.disc:publish-sample p payload))
             (dds.disc:flush-batch p)             ; drain the final partial batch
             (let ((send-ns (max 1 (- (dds.pal:monotonic-ns) t0)))
                   (consed (- (dds.pal:bytes-consed) consed0)))
               (loop repeat 2000 until (>= (dds.disc:node-sample-count e) samples) do (sleep 0.005))
               (%assert-shmem-sends transport p "writer") (%assert-zc-sends transport p "writer" payload-bytes)
               (let* ((recv-ns (max 1 (- (dds.pal:monotonic-ns) t0)))
                      (received (dds.disc:node-sample-count e)))
                 (list :samples samples :payload-bytes payload-bytes :batch batch :transport transport
                       :received received
                       :bytes-per-sample (round (/ consed samples))
                       :zc-sends (dds.disc::disc-node-zc-sends p)
                       :send-samples-per-s (round (/ samples (/ send-ns 1.0d9)))
                       :delivered-samples-per-s (round (/ received (/ recv-ns 1.0d9)))
                       :send-mbps (/ (round (/ (* samples payload-bytes 8) (/ send-ns 1.0d9))) 1.0d6)
                       :shmem-sends (dds.disc::disc-node-shmem-sends p))))))
      (dds.disc:stop-node p) (dds.disc:stop-node e))))

(defun* %print-latency (r)
    (function (list) t)
  "Print one run-latency plist R as a markdown table row group (one-way ns + bytes/sample)."
  (format t "~&| ~5d B | ~8d | ~8d | ~8d | ~8d | ~8d | ~8d | ~10d |~%"
          (getf r :payload-bytes) (getf r :samples)
          (getf r :p50) (getf r :p99) (getf r :p9999) (getf r :max) (getf r :mean)
          (getf r :bytes-per-sample))
  t)

(defun* run-bench (&key (latency-samples 10000) (throughput-samples 20000))
    (function (&key (:latency-samples (integer 1)) (:throughput-samples (integer 1))) t)
  "Run the baseline perftest scenarios (latency sweep + throughput) and print a markdown report to
   *standard-output* (NFR-PERF / FR-LANG-7). Captured into bench/report/ by the make bench target."
  (format t "~&# dds-bench baseline — participant data plane over UDP loopback~%~%")
  (format t "Clock: dds.pal:monotonic-ns (~~us resolution). bytes/sample: dds.pal:bytes-consed delta over the measured loop (whole path, all threads; SBCL-exact).~%~%")
  (format t "## One-way latency (ns; RTT/2, single in-flight)~%~%")
  (format t "| payload | samples |      p50 |      p99 |   p99.99 |      max |     mean | bytes/samp |~%")
  (format t "|---------|---------|----------|----------|----------|----------|----------|------------|~%")
  (dolist (sz '(16 64 256))
    (%print-latency (run-latency :samples latency-samples :payload-bytes sz :warmup 500)))
  (format t "~%## Throughput (one-way; batch N = WP-BATCH write-side batching)~%~%")
  (format t "| payload | batch | samples | received | send samples/s | send Mbps |~%")
  (format t "|---------|-------|---------|----------|----------------|-----------|~%")
  (dolist (spec '((64 . 1) (64 . 100) (1024 . 1)))
    (let ((r (run-throughput :samples throughput-samples :payload-bytes (car spec) :batch (cdr spec))))
      (format t "| ~5d B | ~5d | ~7d | ~8d | ~14d | ~9,1f |~%"
              (getf r :payload-bytes) (getf r :batch) (getf r :samples) (getf r :received)
              (getf r :send-samples-per-s) (getf r :send-mbps))))
  (format t "~%Note: bytes/sample > 0 reflects the v1 data plane (per-sample heap copies, documented); the P4 features drive it toward the NFR-PERF-8 0-alloc target measured here.~%")
  t)

(defun* %speedup (baseline candidate)
    (function (real real) double-float)
  "BASELINE/CANDIDATE as a double — a latency SPEEDUP factor (>1 = CANDIDATE is faster), or 0.0 when
   CANDIDATE is non-positive (the SHMEM-vs-UDP delta column; honest 0.0 rather than a divide-by-zero)."
  (if (plusp candidate) (/ (float baseline 1.0d0) (float candidate 1.0d0)) 0.0d0))

(defun* %ratio (candidate baseline)
    (function (real real) double-float)
  "CANDIDATE/BASELINE as a double — a throughput RATIO (>1 = CANDIDATE delivers more), or 0.0 when
   BASELINE is non-positive (the SHMEM-vs-UDP throughput delta column)."
  (if (plusp baseline) (/ (float candidate 1.0d0) (float baseline 1.0d0)) 0.0d0))

(defun* %print-latency-cmp (u s)
    (function (list list) t)
  "Print one SHMEM-vs-UDP latency comparison row from the UDP plist U and the SHMEM plist S (same payload
   size): UDP p50/p99/max, SHMEM p50/p99/max (one-way ns), the p50 speedup factor, and SHMEM bytes/sample
   (the 0-alloc evidence, NFR-PERF-8)."
  (format t "~&| ~5d B | ~8d | ~8d | ~8d | ~8d | ~8d | ~8d | ~7,2fx | ~10d |~%"
          (getf u :payload-bytes)
          (getf u :p50) (getf u :p99) (getf u :max)
          (getf s :p50) (getf s :p99) (getf s :max)
          (%speedup (getf u :p50) (getf s :p50))
          (getf s :bytes-per-sample))
  t)

(defun* %print-throughput-cmp (u s)
    (function (list list) t)
  "Print one SHMEM-vs-UDP throughput comparison row from the UDP plist U and the SHMEM plist S (same payload
   + batch): UDP/SHMEM send samples-per-s and Mbps, plus the samples-per-s ratio (>1 = SHMEM faster)."
  (format t "~&| ~5d B | ~5d | ~14d | ~9,1f | ~14d | ~9,1f | ~7,2fx |~%"
          (getf u :payload-bytes) (getf u :batch)
          (getf u :send-samples-per-s) (getf u :send-mbps)
          (getf s :send-samples-per-s) (getf s :send-mbps)
          (%ratio (getf s :send-samples-per-s) (getf u :send-samples-per-s)))
  t)

(defparameter +bench-shmem-latency-sizes+ '(16 64 256 1024)
  "Payload sizes (octets) the WP-SHMEM latency comparison sweeps — small (where the SHMEM mutex/condvar
   per-message overhead is most visible) up to 1 KB (where the per-byte copy cost grows).")

(defparameter +bench-shmem-throughput-specs+ '((64 . 1) (64 . 100) (256 . 1) (1024 . 1))
  "(PAYLOAD-BYTES . BATCH) cases the WP-SHMEM throughput comparison sweeps (BATCH = WP-BATCH write-side
   batching; batch 100 amortizes per-datagram overhead over the same transport).")

(defun* run-bench-shmem (&key (latency-samples 10000) (throughput-samples 20000))
    (function (&key (:latency-samples (integer 1)) (:throughput-samples (integer 1))) t)
  "Run the perftest latency + throughput scenarios over BOTH transports — UDP loopback (the baseline) and
   same-host SHMEM (WP-SHMEM) — for the same payload sizes, and print a markdown comparison report to
   *standard-output* quantifying the SHMEM-vs-UDP delta (NFR-PERF-6, FR-LANG-7). Captured into bench/report/
   by the make bench-shmem target. Each :shmem run asserts disc-node-shmem-sends advanced, so the SHMEM
   columns are PROVEN to have traversed shared memory, not a silent UDP fallback. bytes/sample is the
   NFR-PERF-8 0-alloc oracle (SBCL-exact; Clasp reports 0 — a documented NFR-PORT gap, so on Clasp the
   bytes/sample column is uninformative)."
  (format t "~&# dds-bench — SHMEM vs UDP-loopback (WP-SHMEM)~%~%")
  (format t "Both bench nodes run in ONE process (same host-uuid), so with dds.disc:*shmem-enabled* T the user-DATA push auto-routes over shared memory; the UDP rows rebind it NIL to force the loopback baseline. Clock: dds.pal:monotonic-ns (~~us resolution). bytes/sample: dds.pal:bytes-consed delta over the measured loop (whole path, all threads; SBCL-exact, Clasp=0). Each SHMEM run is asserted to have advanced disc-node-shmem-sends (proof it measured SHMEM, not UDP).~%~%")
  (format t "## One-way latency — SHMEM vs UDP (ns; RTT/2, single in-flight)~%~%")
  (format t "| payload |  UDP p50 |  UDP p99 |  UDP max | SHM p50 | SHM p99 | SHM max | p50 spdup | SHM b/samp |~%")
  (format t "|---------|----------|----------|----------|---------|---------|---------|-----------|------------|~%")
  (dolist (sz +bench-shmem-latency-sizes+)
    (let ((u (run-latency :samples latency-samples :payload-bytes sz :warmup 500 :transport :udp))
          (s (run-latency :samples latency-samples :payload-bytes sz :warmup 500 :transport :shmem)))
      (%print-latency-cmp u s)))
  (format t "~%## Throughput — SHMEM vs UDP (one-way; batch N = WP-BATCH write-side batching)~%~%")
  (format t "| payload | batch | UDP samples/s | UDP Mbps | SHM samples/s | SHM Mbps | spr ratio |~%")
  (format t "|---------|-------|---------------|----------|---------------|----------|-----------|~%")
  (dolist (spec +bench-shmem-throughput-specs+)
    (let ((u (run-throughput :samples throughput-samples :payload-bytes (car spec) :batch (cdr spec) :transport :udp))
          (s (run-throughput :samples throughput-samples :payload-bytes (car spec) :batch (cdr spec) :transport :shmem)))
      (%print-throughput-cmp u s)))
  (format t "~%Legend: p50 spdup = UDP-p50 / SHMEM-p50 (>1 = SHMEM faster). spr ratio = SHMEM-send-samples/s / UDP (>1 = SHMEM faster). SHM b/samp is the SHMEM bytes-consed/sample (NFR-PERF-8; ~~0 = the steady path allocates nothing; Clasp reports 0 by gap).~%")
  t)

;;;; ---- WP-ZEROCOPY large-sample bench (FR-PF-3, FR-LANG-7; NOT cleared for ship — pending counsel R6) ----

(defparameter +bench-zerocopy-latency-sizes+ '(512 4096 16384 65536)
  "Payload sizes (octets) the WP-ZEROCOPY latency comparison sweeps. 512 B is a control BELOW
   *zerocopy-min-payload-bytes* (1024) — ZC must NOT engage there (zc-sends=0, fallback to normal DATA), so
   that row shows the threshold is honoured; 4/16/64 KiB are above it, where eliminating the payload copy
   (only a 16-byte reference crosses the transport) is expected to pay off. NOT a wire constant.")

(defparameter +bench-zerocopy-throughput-sizes+ '(4096 16384 65536)
  "Payload sizes (octets) the WP-ZEROCOPY throughput comparison sweeps — all above
   *zerocopy-min-payload-bytes*. NOT a wire constant.")

(defparameter +bench-zerocopy-throughput-byte-budget+ (* 24 1024 1024)
  "Per-run byte budget for the WP-ZEROCOPY throughput sweep. run-throughput does NOT drain the disc-layer
   receive cache (nor the reliable writer history), so each run retains ~SAMPLES * PAYLOAD-BYTES on the
   heap; the sample count per size is BUDGET / PAYLOAD-BYTES (floored, min 200) to keep that bounded (the
   1 GB SBCL heap must hold the writer history + the reader cache + retransmit scratch simultaneously).
   Honest-measurement note: a smaller-but-stable per-sample throughput figure, NOT a sustained-rate
   benchmark. NOT a wire constant.")

(defun* %zc-throughput-samples (payload-bytes)
    (function ((integer 1)) (integer 1))
  "Sample count for one WP-ZEROCOPY throughput row at PAYLOAD-BYTES: the byte budget divided by the payload
   size (min 200), so the un-drained receive cache + writer history stay bounded across the payload sweep."
  (max 200 (floor +bench-zerocopy-throughput-byte-budget+ payload-bytes)))

(defun* %print-latency-cmp3 (u s z)
    (function (list list list) t)
  "Print one 3-way WP-ZEROCOPY latency row from the UDP plist U, SHMEM plist S and ZEROCOPY plist Z (same
   payload size): each transport's p50/p99 (one-way ns) + bytes/sample, the ZC-vs-SHMEM p50 speedup, and the
   ZC zc-sends count (>0 proves the row crossed as a reference; 0 = below threshold, fell back to DATA)."
  (format t "~&| ~6d B | ~8d | ~8d | ~10d | ~8d | ~8d | ~10d | ~8d | ~8d | ~10d | ~8,2fx | ~8d |~%"
          (getf u :payload-bytes)
          (getf u :p50) (getf u :p99) (getf u :bytes-per-sample)
          (getf s :p50) (getf s :p99) (getf s :bytes-per-sample)
          (getf z :p50) (getf z :p99) (getf z :bytes-per-sample)
          (%speedup (getf s :p50) (getf z :p50))
          (getf z :zc-sends))
  t)

(defun* %print-throughput-cmp3 (u s z)
    (function (list list list) t)
  "Print one 3-way WP-ZEROCOPY throughput row from the UDP plist U, SHMEM plist S and ZEROCOPY plist Z (same
   payload size): each transport's send samples/s + bytes/sample, the ZC-vs-SHMEM samples/s ratio, and the
   ZC zc-sends count (the proof the large samples crossed as references)."
  (format t "~&| ~6d B | ~7d | ~12d | ~10d | ~12d | ~10d | ~12d | ~10d | ~8,2fx | ~8d |~%"
          (getf u :payload-bytes) (getf u :samples)
          (getf u :send-samples-per-s) (getf u :bytes-per-sample)
          (getf s :send-samples-per-s) (getf s :bytes-per-sample)
          (getf z :send-samples-per-s) (getf z :bytes-per-sample)
          (%ratio (getf z :send-samples-per-s) (getf s :send-samples-per-s))
          (getf z :zc-sends))
  t)

(defun* run-bench-zerocopy (&key (latency-samples 2000) (throughput-samples nil))
    (function (&key (:latency-samples (integer 1)) (:throughput-samples (or null (integer 1)))) t)
  "Run the perftest latency + throughput scenarios over THREE transports — UDP loopback, same-host SHMEM
   (serialized payload), and same-host WP-ZEROCOPY (16-byte reference) — at LARGE payloads (4/16/64 KiB,
   above *zerocopy-min-payload-bytes*), and print a markdown comparison report to *standard-output*
   quantifying the ZC-vs-SHMEM-vs-UDP delta (FR-PF-3, FR-LANG-7). Captured into bench/report/ by the make
   bench-zerocopy target. Each :zerocopy run ASSERTS disc-node-zc-sends advanced, so the ZC columns are
   PROVEN to have crossed as a reference, not a fragmented payload (else the run errors). The expectation is
   the no-payload-copy win shows at LARGE sizes; the 512 B control row (below the threshold) demonstrates ZC
   correctly does NOT engage (zc-sends=0). LATENCY-SAMPLES defaults small (large samples are slow per
   round-trip); THROUGHPUT-SAMPLES NIL (the default) scales the per-size count to a fixed byte budget
   (%zc-throughput-samples — the receive cache is not drained), else forces that fixed count for every size.
   NOT cleared for ship — pending counsel (R6)."
  (flet ((thr-n (size) (or throughput-samples (%zc-throughput-samples size))))
    (format t "~&# dds-bench — WP-ZEROCOPY vs SHMEM vs UDP-loopback (FR-PF-3, large samples)~%~%")
    (format t "NOT cleared for ship — pending counsel (R6); see ADR 0014. dds.disc:*zerocopy-enabled* is default OFF.~%~%")
    (format t "All three transports run as 2 in-process participants (same host-uuid). UDP rebinds dds.disc:*shmem-enabled* NIL; SHMEM routes the serialized payload over shared memory; ZEROCOPY additionally binds dds.disc:*zerocopy-enabled* T so a sample LARGER than *zerocopy-min-payload-bytes* (1024) crosses as a 16-byte SHMEM-pool reference, not the payload. Clock: dds.pal:monotonic-ns (~~us). bytes/sample: dds.pal:bytes-consed delta over the measured loop (whole path; SBCL-exact, Clasp=0 by NFR-PORT gap). Each ZEROCOPY run is asserted to have advanced disc-node-zc-sends (a reference crossed, not a payload).~%~%")
    (format t "## One-way latency — ZC vs SHMEM vs UDP (ns; RTT/2, single in-flight, N=~d)~%~%" latency-samples)
    (format t "| payload |  UDP p50 |  UDP p99 |  UDP b/samp | SHM p50 | SHM p99 | SHM b/samp |  ZC p50 |  ZC p99 |  ZC b/samp | ZC/SHM p50 | zc-sends |~%")
    (format t "|---------|----------|----------|-------------|---------|---------|------------|---------|---------|------------|------------|----------|~%")
    (dolist (sz +bench-zerocopy-latency-sizes+)
      (let ((u (run-latency :samples latency-samples :payload-bytes sz :warmup 50 :transport :udp))
            (s (run-latency :samples latency-samples :payload-bytes sz :warmup 50 :transport :shmem))
            (z (run-latency :samples latency-samples :payload-bytes sz :warmup 50 :transport :zerocopy)))
        (%print-latency-cmp3 u s z)))
    (format t "~%## Throughput — ZC vs SHMEM vs UDP (one-way, batch 1; N scaled to a ~d MiB/run byte budget)~%~%"
            (floor +bench-zerocopy-throughput-byte-budget+ (* 1024 1024)))
    (format t "| payload |       N | UDP samples/s | UDP b/samp | SHM samples/s | SHM b/samp |  ZC samples/s |  ZC b/samp | ZC/SHM spr | zc-sends |~%")
    (format t "|---------|---------|---------------|------------|---------------|------------|---------------|------------|------------|----------|~%")
    (dolist (sz +bench-zerocopy-throughput-sizes+)
      (let* ((n (thr-n sz))
             (u (run-throughput :samples n :payload-bytes sz :transport :udp))
             (s (run-throughput :samples n :payload-bytes sz :transport :shmem))
             (z (run-throughput :samples n :payload-bytes sz :transport :zerocopy)))
        (%print-throughput-cmp3 u s z)))
    (format t "~%Legend: ZC/SHM p50 = SHMEM-p50 / ZC-p50 (>1 = ZC lower latency than serialized SHMEM). ZC/SHM spr = ZC-send-samples/s / SHMEM (>1 = ZC higher throughput). b/samp = bytes-consed/sample on that transport's path (the transport-copy elimination shows as a LOWER ZC b/samp at large sizes — only the 20-byte reference crosses, not the payload). zc-sends>0 proves the row used a reference; the 512 B control sits below the threshold so zc-sends=0 there (fell back to normal DATA — by design).~%")
    t))

(defun* run-bench-smoke ()
    (function () t)
  "Suite-friendly self-check: a tiny latency + throughput run; asserts every sample round-trips,
   latency is positive, and throughput delivers all samples — so CI catches harness breakage without
   a long run. Signals an error on failure (the dds.tests runner treats that as a test failure)."
  (let ((lat (run-latency :samples 30 :payload-bytes 32 :warmup 5))
        (thr (run-throughput :samples 50 :payload-bytes 32)))
    (assert (= 30 (getf lat :samples)) () "latency smoke: wrong sample count")
    (assert (plusp (getf lat :p50)) () "latency smoke: non-positive p50 latency")
    (assert (>= (getf lat :max) (getf lat :min)) () "latency smoke: max < min")
    (assert (>= (getf thr :received) 50) () "throughput smoke: not all samples delivered (~d/50)"
            (getf thr :received))
    t))

(defun* run-bench-shmem-smoke ()
    (function () t)
  "Suite-friendly self-check of the WP-SHMEM bench path: a tiny :shmem latency + throughput run, asserting
   every sample round-trips AND that disc-node-shmem-sends advanced (so CI catches a SHMEM-routing
   regression — the bench measuring UDP while claiming SHMEM — without a long run). Pass-SKIPS where SHMEM
   is off (dds.disc:*shmem-enabled* NIL, e.g. Clasp/macOS per ADR 0013) so it never false-fails on a platform
   with no usable SHMEM. Signals an error on failure (the dds.tests runner treats that as a test failure)."
  (if (not dds.disc:*shmem-enabled*)
      (format t "(SHMEM off on this platform — skipped) ")
      (let ((lat (run-latency :samples 30 :payload-bytes 32 :warmup 5 :transport :shmem))
            (thr (run-throughput :samples 50 :payload-bytes 32 :transport :shmem)))
        (assert (plusp (getf lat :p50)) () "shmem latency smoke: non-positive p50 latency")
        (assert (plusp (getf lat :shmem-sends)) () "shmem latency smoke: shmem-sends did not advance (UDP, not SHMEM)")
        (assert (>= (getf thr :received) 50) () "shmem throughput smoke: not all samples delivered (~d/50)"
                (getf thr :received))
        (assert (plusp (getf thr :shmem-sends)) () "shmem throughput smoke: shmem-sends did not advance (UDP, not SHMEM)")))
  t)

(defun* run-bench-zerocopy-smoke ()
    (function () t)
  "Suite-friendly self-check of the WP-ZEROCOPY bench path (FR-PF-3; NOT cleared for ship — pending counsel
   R6): a tiny :zerocopy latency + throughput run at a payload ABOVE *zerocopy-min-payload-bytes*, asserting
   every sample round-trips byte-exact AND that disc-node-zc-sends advanced (so CI catches a ZC-routing
   regression — the bench fragmenting the payload while claiming a reference crossed — without a long run).
   Pass-SKIPS where SHMEM is not reliably by-name-attachable (Clasp/macOS per ADR 0013) so it never
   false-fails on a platform with no usable SHMEM pool. Signals an error on failure."
  (if (not (dds.xport.shmem:shm-attach-by-name-reliable-p))
      (format t "(SHMEM by-name attach unreliable on this platform — ZC bench skipped) ")
      (let ((lat (run-latency :samples 20 :payload-bytes 2048 :warmup 5 :transport :zerocopy))
            (thr (run-throughput :samples 30 :payload-bytes 2048 :transport :zerocopy)))
        (assert (plusp (getf lat :p50)) () "zc latency smoke: non-positive p50 latency")
        (assert (plusp (getf lat :zc-sends)) () "zc latency smoke: zc-sends did not advance (payload crossed, not a reference)")
        (assert (>= (getf thr :received) 30) () "zc throughput smoke: not all samples delivered (~d/30)"
                (getf thr :received))
        (assert (plusp (getf thr :zc-sends)) () "zc throughput smoke: zc-sends did not advance (payload crossed, not a reference)")))
  t)
