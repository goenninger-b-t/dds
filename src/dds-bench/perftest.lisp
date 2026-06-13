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

(defun* run-latency (&key (samples 10000) (payload-bytes 64) (warmup 500))
    (function (&key (:samples (integer 1)) (:payload-bytes (integer 1)) (:warmup (integer 0))) list)
  "Measure one-way PING/PONG latency over UDP loopback: a pinger node writes a PAYLOAD-BYTES sample on
   topic PerfPing; an echoer node echoes a pong on PerfPong; one-way = RTT/2. After WARMUP throwaway
   round-trips, time SAMPLES of them and the bytes consed across the whole path. Returns a plist:
   :samples :payload-bytes :p50 :p99 :p9999 :max :min :mean :bytes-per-sample (latency values are
   ONE-WAY nanoseconds)."
  (let* ((p (dds.disc:make-disc-node :guid-prefix (%prefix #x70) :host "127.0.0.1" :port 0))
         (e (dds.disc:make-disc-node :guid-prefix (%prefix #x71) :host "127.0.0.1" :port 0))
         (rv (%make-rendezvous))
         (ping (%payload payload-bytes))
         (pong (%payload payload-bytes))
         (rtts (make-array samples :element-type 'fixnum :fill-pointer 0)))
    (unwind-protect
         (progn
           (dds.disc:add-local-writer p :topic "PerfPing" :type "perf")
           (dds.disc:add-local-reader p :topic "PerfPong" :type "perf" :reliability +reliable+)
           (dds.disc:enable-publisher p) (dds.disc:enable-subscriber p)
           (dds.disc:add-local-reader e :topic "PerfPing" :type "perf" :reliability +reliable+)
           (dds.disc:add-local-writer e :topic "PerfPong" :type "perf")
           (dds.disc:enable-subscriber e) (dds.disc:enable-publisher e)
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
             (let ((before (dds.pal:bytes-consed)))
               (dotimes (i samples) (vector-push (one) rtts) (%drain-cache p) (%drain-cache e))
               (let* ((consed (- (dds.pal:bytes-consed) before))
                      (oneway (make-array samples :element-type 'fixnum)))
                 (dotimes (i samples) (setf (aref oneway i) (ash (aref rtts i) -1)))
                 (sort oneway #'<)
                 (list :samples samples :payload-bytes payload-bytes
                       :p50 (%pct oneway 0.50) :p99 (%pct oneway 0.99)
                       :p9999 (%pct oneway 0.9999) :max (aref oneway (1- samples))
                       :min (aref oneway 0)
                       :mean (round (/ (loop for x across oneway sum x) samples))
                       :bytes-per-sample (round (/ consed samples)))))))
      (dds.disc:stop-node p) (dds.disc:stop-node e))))

(defun* run-throughput (&key (samples 20000) (payload-bytes 64))
    (function (&key (:samples (integer 1)) (:payload-bytes (integer 1))) list)
  "Measure one-way throughput over UDP loopback: a writer node blasts SAMPLES of a PAYLOAD-BYTES sample
   on topic PerfThru as fast as write() returns; a reader node counts delivery. Returns a plist:
   :samples :payload-bytes :received :send-samples-per-s :delivered-samples-per-s :send-mbps."
  (let* ((p (dds.disc:make-disc-node :guid-prefix (%prefix #x72) :host "127.0.0.1" :port 0))
         (e (dds.disc:make-disc-node :guid-prefix (%prefix #x73) :host "127.0.0.1" :port 0))
         (payload (%payload payload-bytes)))
    (unwind-protect
         (progn
           (dds.disc:add-local-writer p :topic "PerfThru" :type "perf")
           (dds.disc:enable-publisher p)
           (dds.disc:add-local-reader e :topic "PerfThru" :type "perf" :reliability +reliable+)
           (dds.disc:enable-subscriber e)
           (dds.disc:start-node p) (dds.disc:start-node e)
           (%connect p e 1)
           (let ((t0 (dds.pal:monotonic-ns)))
             (dotimes (i samples) (dds.disc:publish-sample p payload))
             (let ((send-ns (max 1 (- (dds.pal:monotonic-ns) t0))))
               (loop repeat 2000 until (>= (dds.disc:node-sample-count e) samples) do (sleep 0.005))
               (let* ((recv-ns (max 1 (- (dds.pal:monotonic-ns) t0)))
                      (received (dds.disc:node-sample-count e)))
                 (list :samples samples :payload-bytes payload-bytes :received received
                       :send-samples-per-s (round (/ samples (/ send-ns 1.0d9)))
                       :delivered-samples-per-s (round (/ received (/ recv-ns 1.0d9)))
                       :send-mbps (/ (round (/ (* samples payload-bytes 8) (/ send-ns 1.0d9))) 1.0d6))))))
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
  (format t "~%## Throughput (one-way)~%~%")
  (format t "| payload | samples | received | send samples/s | delivered samples/s | send Mbps |~%")
  (format t "|---------|---------|----------|----------------|---------------------|-----------|~%")
  (dolist (sz '(64 1024))
    (let ((r (run-throughput :samples throughput-samples :payload-bytes sz)))
      (format t "| ~5d B | ~7d | ~8d | ~14d | ~19d | ~9,1f |~%"
              (getf r :payload-bytes) (getf r :samples) (getf r :received)
              (getf r :send-samples-per-s) (getf r :delivered-samples-per-s) (getf r :send-mbps))))
  (format t "~%Note: bytes/sample > 0 reflects the v1 data plane (per-sample heap copies, documented); the P4 features drive it toward the NFR-PERF-8 0-alloc target measured here.~%")
  t)

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
