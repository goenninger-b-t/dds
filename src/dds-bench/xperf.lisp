;;;; WP-CONFORMANCE-AND-PARITY WP-1 — the CROSS-STACK parity harness (NFR-PERF-1..9).
;;;;
;;;; WHY THIS EXISTS. Every NFR-PERF target in REQUIREMENTS §7 is a RATIO against RTI Connext on identical
;;;; hardware ("within 1.5x of Connext" etc.), and that side-by-side run was never done: perftest.lisp
;;;; measures an IN-PROCESS pair at the dds.disc engine layer with PRE-SERIALIZED payloads. Two things make
;;;; those numbers uncomparable to a foreign stack:
;;;;   1. in-process — no real wire, no second process, no foreign peer can substitute for either end;
;;;;   2. engine-layer — dds.disc:publish-sample takes octets that are ALREADY serialized, so the measured
;;;;      path EXCLUDES type-support serialization. Connext's DataWriter::write includes it. Comparing the
;;;;      two would FLATTER US, which is worse than not measuring at all.
;;;; So this harness measures the DCPS path (create-datawriter + write-sample on a typed sample -> the codec
;;;; runs) across REAL processes, and its peer is interchangeable: ours, Connext, or Fast DDS. Same topic,
;;;; same type, same QoS, same payload ladder, same wait strategy (a listener on both sides), same clock,
;;;; same percentile rule. That is what makes the ratio honest.
;;;;
;;;; PROTOCOL (deliberately trivial, so any stack can implement it in a few lines):
;;;;   pinger    --PerfPing--> responder     responder --PerfPong--> pinger
;;;; The pinger stamps t0, writes ONE sample, waits for the echo, records RTT; one-way := RTT/2. Single
;;;; in-flight (no pipelining) — the definition of a latency measurement. The responder echoes verbatim.

(in-package #:dds.bench)

;;; The shared wire type. `id` is the @key; `data` carries the payload ladder (a sequence, so ONE type
;;; serves every size — the length prefix + memcpy is the same shape in every stack). The IDL equivalent
;;; the foreign peers are generated from is interop/perftest/PerfData.idl — keep the two in lockstep.
(dds.gen:define-dds-type perf-data (:extensibility :final)
  (id :i32 :key t)
  ;; :OCTET, not :U8 — they are DIFFERENT XTypes kinds (TK_BYTE vs TK_UINT8) and are NOT assignable.
  ;; PerfData.idl declares `sequence<octet, 65536>`, so :u8 here made our type genuinely incompatible with
  ;; the Connext peer's: the type gate rejected the match (correctly), and every ours<->Connext leg of this
  ;; harness silently failed to match. Same wire bytes, different declared type — which is exactly the
  ;; distinction the gate exists to enforce.
  (data (:sequence :octet)))

(defstruct* (echo-rv (:constructor %make-echo-rv))
  "Single-in-flight PING/PONG handoff between the pinger's main thread (waits) and the receiver thread that
   delivers the echo. RECV-NS is stamped the moment the pong lands; GOT guards a lost wakeup. Mirrors the
   in-process harness's rendezvous so the two report the same quantity."
  (lock (dds.pal:make-lock "echo-rv") :type t)
  (cv (dds.pal:make-condvar) :type t)
  (recv-ns 0 :type integer)
  (got nil :type t))

(defclass echo-responder-listener (dds.dcps:data-reader-listener)
  ((writer :initarg :writer :reader erl-writer))
  (:documentation "Responder side: on DATA_AVAILABLE, take every sample and echo it back VERBATIM on
   PerfPong. A listener (not a poll loop) so the wait strategy matches the foreign peers' — a busy-poll on
   one side and a listener on the other would measure the poll interval, not the stack."))

(defclass echo-pinger-listener (dds.dcps:data-reader-listener)
  ((rv :initarg :rv :reader epl-rv))
  (:documentation "Pinger side: on DATA_AVAILABLE, stamp the arrival time and wake the measuring thread."))

(defmethod dds.dcps:on-data-available ((l echo-responder-listener) reader)
  (dolist (cs (dds.dcps:take-samples reader))
    (let ((info (dds.dcps:cached-sample-info cs)))
      (when (dds.dcps:sample-info-valid-data info)
        (dds.dcps:write-sample (erl-writer l) (dds.dcps:cached-sample-data cs))))))

(defmethod dds.dcps:on-data-available ((l echo-pinger-listener) reader)
  (let ((rv (epl-rv l)))
    (dolist (cs (dds.dcps:take-samples reader))
      (declare (ignore cs))
      (dds.pal:with-lock ((echo-rv-lock rv))
        (setf (echo-rv-recv-ns rv) (dds.pal:monotonic-ns)
              (echo-rv-got rv) t)
        (dds.pal:condvar-signal (echo-rv-cv rv))))))

(defun* %perf-payload (n)
    (function ((integer 0)) (simple-array (unsigned-byte 8) (*)))
  "An N-octet payload for the `data` sequence (deterministic contents; the values are irrelevant to the
   measurement, only the LENGTH is)."
  (let ((v (make-array n :element-type '(unsigned-byte 8))))
    (dotimes (i n v) (setf (aref v i) (logand i #xff)))))

(defun* %perf-participant (domain advertise peers)
    (function ((integer 0) string (or null string)) t)
  "An AUTONOMOUS participant for the parity harness (WP-DCPS-API-COMPLETION S7): discovery runs on the
   announcer thread, so the measuring loop never calls spin and the measurement is not polluted by
   app-driven discovery work. ADVERTISE/PEERS carry the documented cross-vendor reachability gotchas
   (Connext is pinned to the LAN interface; the Fast DDS profile is loopback-only, so it needs a unicast
   SPDP peer at 127.0.0.1:7410) — see interop/autodiscovery/README.md."
  ;; CREATE-PARTICIPANT's :PEERS is a LIST of (host . port); parse the harness STRING first (a raw string
  ;; would die with a TYPE-ERROR before discovery — the cross-vendor peer path had NEVER run otherwise).
  (multiple-value-bind (peer-list peer-status) (dds.disc:parse-peers peers)
    (when peer-status
      (error "xperf: malformed --peers ~s: ~a" peers peer-status))   ; NOCOND(BENCH): harness CLI-arg validation
    (dds.dcps:create-participant :domain domain :autonomous t
                                 :advertise-address advertise
                                 :peers peer-list)))

(defun* run-echo-responder (&key (domain 0) (seconds 60) (advertise-address "127.0.0.1") (peers nil)
                                 (data-representation :xcdr2) (history-kind :keep-all))
    (function (&key (:domain (integer 0)) (:seconds (integer 1)) (:advertise-address string)
                    (:peers (or null string)) (:data-representation (member :xcdr2 :xcdr1))
                    (:history-kind (member :keep-all :keep-last)))
              t)
  "The RESPONDER half of the cross-stack parity harness: subscribe PerfPing, echo every sample VERBATIM on
   PerfPong, for SECONDS. Interchangeable with the Connext / Fast DDS responders (same topics, same type,
   same QoS) — that interchangeability is the whole point: it lets ours-vs-Connext be measured with the
   pinger held constant. Prints the echo count so a run that silently matched nothing is obvious."
  (let* ((ts (dds.types:find-type-support "perf-data"))
         (p (%perf-participant domain advertise-address peers)))
    (unwind-protect
         (let* ((tp-in (dds.dcps:create-topic p "PerfPing" "PerfData" ts))
                (tp-out (dds.dcps:create-topic p "PerfPong" "PerfData" ts))
                (pub (dds.dcps:create-publisher p))
                (sub (dds.dcps:create-subscriber p))
                (dw (dds.dcps:create-datawriter
                     pub tp-out :qos (dds.qos:make-writer-qos
                                      :reliability :reliable :history-kind history-kind :history-depth 1
                                      :data-representation (list data-representation))))
                (dr (dds.dcps:create-datareader
                     sub tp-in :qos (dds.qos:make-reader-qos
                                     :reliability :reliable :history-kind history-kind :history-depth 1
                                     :data-representation (list data-representation)))))
           (dds.dcps:set-reader-listener dr (make-instance 'echo-responder-listener :writer dw)
                                         '(:data-available))
           (format t "~&[echo-responder] PerfPing -> PerfPong, domain=~d rep=~(~a~). Waiting ~d s.~%"
                   domain data-representation seconds)
           (finish-output)
           (sleep seconds)
           (format t "~&[echo-responder] done (matched writers=~d).~%" (dds.dcps:matched-count p))
           (finish-output))
      (dds.dcps:delete-participant p)))
  t)

(defun* run-echo-pinger (&key (domain 0) (samples 10000) (payload-bytes 64) (warmup 1000)
                              (advertise-address "127.0.0.1") (peers nil) (label "ours")
                              (data-representation :xcdr2) (match-timeout 30) (history-kind :keep-all))
    (function (&key (:domain (integer 0)) (:samples (integer 1)) (:payload-bytes (integer 0))
                    (:warmup (integer 0)) (:advertise-address string) (:peers (or null string))
                    (:label string) (:data-representation (member :xcdr2 :xcdr1))
                    (:match-timeout (integer 1)) (:history-kind (member :keep-all :keep-last)))
              list)
  "The PINGER half: write ONE PAYLOAD-BYTES sample on PerfPing, wait for the echo on PerfPong, record the
   RTT; one-way := RTT/2. Single in-flight — no pipelining, which is what makes this a LATENCY number and
   not a throughput number in disguise. After WARMUP discarded round-trips, time SAMPLES of them.

   The measured path is the DCPS path (write-sample -> the generated codec serializes -> the engine sends),
   so it includes type-support serialization exactly as Connext's DataWriter::write does. The responder may
   be ours, Connext, or Fast DDS — hold the pinger constant and swap the peer, and the ratio is the answer
   NFR-PERF-1..3 asks for.

   Returns a plist :label :payload-bytes :samples :p50 :p99 :p9999 :max :min :mean :bytes-per-sample
   (one-way NANOSECONDS). Errors rather than hanging if the peer never matches or the echo stalls — a bench
   that silently reports the numbers of a run that never talked to anyone is worse than no bench."
  (let* ((ts (dds.types:find-type-support "perf-data"))
         (p (%perf-participant domain advertise-address peers))
         (rv (%make-echo-rv))
         (rtts (make-array samples :element-type 'fixnum :fill-pointer 0)))
    (unwind-protect
         (let* ((tp-out (dds.dcps:create-topic p "PerfPing" "PerfData" ts))
                (tp-in (dds.dcps:create-topic p "PerfPong" "PerfData" ts))
                (pub (dds.dcps:create-publisher p))
                (sub (dds.dcps:create-subscriber p))
                (dw (dds.dcps:create-datawriter
                     pub tp-out :qos (dds.qos:make-writer-qos
                                      :reliability :reliable :history-kind history-kind :history-depth 1
                                      :data-representation (list data-representation))))
                (dr (dds.dcps:create-datareader
                     sub tp-in :qos (dds.qos:make-reader-qos
                                     :reliability :reliable :history-kind history-kind :history-depth 1
                                     :data-representation (list data-representation))))
                (sample (make-perf-data :id 1 :data (%perf-payload payload-bytes))))
           (dds.dcps:set-reader-listener dr (make-instance 'echo-pinger-listener :rv rv)
                                         '(:data-available))
           ;; Both endpoints must match the peer's before a single measurement is taken.
           (loop with deadline = (+ (get-universal-time) match-timeout)
                 until (>= (dds.dcps:matched-count p) 2)
                 do (when (> (get-universal-time) deadline)
                      (error "echo-pinger: peer did not match within ~d s (matched=~d, expected 2 — is the ~
                              responder running, and are ADVERTISE/PEERS right for this vendor?)"
                             match-timeout (dds.dcps:matched-count p)))
                    (sleep 0.05))
           (flet ((one ()
                    (dds.pal:with-lock ((echo-rv-lock rv)) (setf (echo-rv-got rv) nil))
                    (let ((t0 (dds.pal:monotonic-ns)))
                      (dds.dcps:write-sample dw sample)
                      (dds.pal:with-lock ((echo-rv-lock rv))
                        (loop with tries of-type fixnum = 0
                              until (echo-rv-got rv)
                              do (dds.pal:condvar-wait (echo-rv-cv rv) (echo-rv-lock rv) 1.0d0)
                                 (when (>= (incf tries) 5)
                                   (error "echo-pinger: no echo within 5 s (peer died / reliable stall?)"))))
                      (- (echo-rv-recv-ns rv) t0))))
             (dotimes (i warmup) (one))
             (let ((before (dds.pal:bytes-consed)))
               (dotimes (i samples) (vector-push (one) rtts))
               (let* ((consed (- (dds.pal:bytes-consed) before))
                      (oneway (make-array samples :element-type 'fixnum)))
                 (dotimes (i samples) (setf (aref oneway i) (ash (aref rtts i) -1)))   ; one-way := RTT/2
                 (sort oneway #'<)
                 (let ((r (list :label label :payload-bytes payload-bytes :samples samples
                                :p50 (%pct oneway 0.50) :p99 (%pct oneway 0.99)
                                :p9999 (%pct oneway 0.9999) :max (aref oneway (1- samples))
                                :min (aref oneway 0)
                                :mean (round (/ (loop for x across oneway sum x) samples))
                                :bytes-per-sample (round (/ consed samples)))))
                   (format t "~&| ~10a | ~7d | ~9d | ~9d | ~9d | ~9d | ~10d |~%"
                           label payload-bytes (getf r :p50) (getf r :p99) (getf r :p9999)
                           (getf r :max) (getf r :bytes-per-sample))
                   (finish-output)
                   r)))))
      (dds.dcps:delete-participant p))))

(defun* run-echo-ladder (&key (domain 0) (samples 10000) (warmup 1000)
                              (advertise-address "127.0.0.1") (peers nil) (label "ours")
                              (data-representation :xcdr2))
    (function (&key (:domain (integer 0)) (:samples (integer 1)) (:warmup (integer 0))
                    (:advertise-address string) (:peers (or null string)) (:label string)
                    (:data-representation (member :xcdr2 :xcdr1)))
              list)
  "Run the pinger across the payload LADDER (32 B / 256 B / 1 KB / 4 KB / 16 KB / 64 KB — the NFR-PERF-1
   'small sample' band through the NFR-PERF-5 'large sample' band) against whatever responder is up, and
   print the table. One-way nanoseconds. Returns the list of per-size plists."
  (format t "~&| ~10a | ~7a | ~9a | ~9a | ~9a | ~9a | ~10a |~%"
          "stack" "payload" "p50 (ns)" "p99 (ns)" "p99.99" "max (ns)" "bytes/samp")
  (format t "|~12a|~9a|~11a|~11a|~11a|~11a|~12a|~%"
          "------------" "---------" "-----------" "-----------" "-----------" "-----------" "------------")
  (finish-output)
  (loop for n in '(32 256 1024 4096 16384 65536)
        collect (run-echo-pinger :domain domain :samples samples :payload-bytes n :warmup warmup
                                 :advertise-address advertise-address :peers peers :label label
                                 :data-representation data-representation)))

(defun* mem-per-sample (&key (domain 7) (samples 60000) (warmup 500) (payload-bytes 0))
    (function (&key (:domain (integer 0)) (:samples (integer 1)) (:warmup (integer 0))
                    (:payload-bytes (integer 0)))
              double-float)
  "END-TO-END steady-state heap allocation, in BYTES PER SAMPLE, for the DCPS path a real application
   uses: write-sample -> the engine/transport -> the receiver thread -> take-samples. This is the number
   NFR-MEM (0 bytes/sample) actually constrains, and the one that drives the peer's GC pause — the ~10 ms
   latency tail is a GC in the PEER, caused by exactly this garbage (ADR 0062).

   It is deliberately NOT what `run-mem-test` measures. That measures the CODEC in isolation
   (serialize/deserialize/AEAD) and correctly reports ~0 B/iter — which is why `make mem` was green while
   the live path allocated thousands of bytes per sample. A gate is only as honest as its workload.

   TWO participants in ONE process: a node IGNORES ITS OWN SPDP announcements, so a writer and reader in
   the SAME participant would never match. They talk over the loopback transport, so the receiver-thread
   allocation is included — `bytes-consed` is whole-process, which is the point (the GC does not care
   which thread made the garbage).

   PAYLOAD-BYTES defaults to 0 to measure the FIXED per-sample overhead, which is what dominates: at zero
   payload the path still allocates thousands of bytes, so the payload copy is not the problem.

   SBCL only in practice — `dds.pal:bytes-consed` returns 0 on Clasp, so a Clasp run measures nothing.
   Callers must gate on that (scripts/gate-mem.sh does).

   SAMPLES DEFAULTS TO 60000, AND THE SIZE OF IT IS THE POINT. The measured window contains a FIXED per-run
   allocation of about 65 KB that occurs a small, VARYING number of times (0-3), so it lands on the result as
   a quantum of 65700/SAMPLES bytes per sample. At the original 3000 that quantum was ~22 B and ONE UNCHANGED
   ARM measured 1791 / 1813 / 1835 / 1857 across runs — a ~65 B spread, WIDER than a typical optimisation
   slice's win (~35 B), so no single run could resolve one and even a min-of-N was not a stable floor. The
   quantum is per RUN, not per sample, so it shrinks as 1/SAMPLES; measured reproducibility of one arm:

     SAMPLES    3000        30000       60000
     spread     ~65 B       ~3 B        ~0.4 B     (within one back-to-back batch)

   Across a whole session, where the box's own state drifts, 60000 holds to about 3 B (observed 1847.9 /
   1850.0 / 1850.9 on identical code) — so size a CEILING from the session-scale number, not the batch one.
   60000 costs about 18 s and makes the instrument sharp enough to size any win this project still has left.
   Lowering it re-blunts the gate; raising it further changes the absolute number slightly (the workload is
   not perfectly scale-free: 3000 -> 30000 -> 60000 reads 1857 -> 1854 -> 1849 on identical code), so a
   change to SAMPLES is a RE-BASELINE of bench/mem-ceiling.txt for BOTH architectures, not a free knob."
  (let* ((ts (dds.types:find-type-support "perf-data"))
         (pw (dds.dcps:create-participant :domain domain :autonomous t :advertise-address "127.0.0.1"))
         (pr (dds.dcps:create-participant :domain domain :autonomous t :advertise-address "127.0.0.1")))
    (unwind-protect
         (let* ((tw (dds.dcps:create-topic pw "PerfPing" "PerfData" ts))
                (tr (dds.dcps:create-topic pr "PerfPing" "PerfData" ts))
                (dw (dds.dcps:create-datawriter
                     (dds.dcps:create-publisher pw) tw
                     :qos (dds.qos:make-writer-qos :reliability :reliable
                                                   :history-kind :keep-last :history-depth 1)))
                (dr (dds.dcps:create-datareader
                     (dds.dcps:create-subscriber pr) tr
                     :qos (dds.qos:make-reader-qos :reliability :reliable
                                                   :history-kind :keep-last :history-depth 1)))
                (sample (make-perf-data :id 1 :data (%perf-payload payload-bytes))))
           (loop with deadline = (+ (get-universal-time) 30)
                 until (and (plusp (dds.dcps:matched-count pw)) (plusp (dds.dcps:matched-count pr)))
                 do (when (> (get-universal-time) deadline)   ; NOCOND(BENCH): pure perf-harness precondition — a measurement that never matched is the bench's own failure
                      (error "mem-per-sample: the two participants never matched — a measurement that ~
                              never talked to anyone is worse than no measurement"))
                    (sleep 0.05))
           (flet ((cycle ()
                    (dds.dcps:write-sample dw sample)
                    (loop repeat 200 until (dds.dcps:take-samples dr) do (sleep 0.0002))))
             (dotimes (i warmup) (cycle))
             (let ((before (dds.pal:bytes-consed)))
               (dotimes (i samples) (cycle))
               (/ (coerce (- (dds.pal:bytes-consed) before) 'double-float)
                  (coerce samples 'double-float)))))
      (progn (dds.dcps:delete-participant pw)
             (dds.dcps:delete-participant pr)))))
