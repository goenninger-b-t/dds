;;;; The logger — the emit side of the distributed logging service (ADR 0082 §5, FR-LOG). Detects the
;;;; per-source identity ONCE at creation (host, participant_uuid, host_ip, process) and stamps it — plus
;;;; a per-logger monotonic seq and a realtime timestamp — on every event, which it publishes as a
;;;; LogEvent DataWriter sample. This slice is the thin synchronous emit path; the non-blocking ring +
;;;; worker + severity-graded shedding + drop counters (ADR 0082 §5) are a follow-on slice.

(in-package #:net.goenninger.dds.log)

(defparameter *log-topic-name* "DdsLog"
  "Default DDS topic name for LogEvent samples (ADR 0082 §3). Pinned to the interop leg's topic
   (interop/log/) so our logger and collector interoperate on the wire with a Connext
   dds::log::LogEvent publisher/subscriber. Override per make-logger / make-log-collector call.")

(defparameter *log-type-name* "dds::log::LogEvent"
  "Default registered type name for LogEvent (ADR 0082 §3): the fully-qualified IDL scoped name a
   foreign peer registers (interop/log/DdsLog.idl, module dds::log). Matches the interop leg so a
   Connext peer's TypeObject lookup resolves against ours. Override per call.")

(defstruct* (logger (:constructor %make-logger))
  "A logging-service producer handle (ADR 0082 §5). Holds the LogEvent DataWriter, the per-source
   identity detected once at creation (host, participant_uuid, host_ip, process, app_id — stamped on
   every event), the monotonic per-logger seq counter, and the emit lock. In ASYNC mode (make-logger
   :async t, FR-LOG-5/6) it also holds a bounded ring + a worker thread that drains it (writes queued
   events + spins the participant), the per-severity overflow watermarks, and the per-severity shed
   counters. Created by make-logger, released by close-logger."
  (participant nil :type t)
  (writer nil :type t)
  (owns-participant nil :type boolean)
  (host "" :type string)
  (participant-uuid "" :type string)
  (host-ip "" :type string)
  (app-id "" :type string)
  (process 0 :type (unsigned-byte 32))
  (seq 0 :type (unsigned-byte 64))
  (lock nil :type t)
  ;; async ring (FR-LOG-5/6); all nil/0 in the default SYNCHRONOUS mode
  (async-p nil :type boolean)
  (ring nil :type (or null simple-vector))
  (capacity 0 :type (integer 0))
  (head 0 :type (integer 0))
  (tail 0 :type (integer 0))
  (count 0 :type (integer 0))
  (condvar nil :type t)
  (worker nil :type t)
  (running nil :type boolean)
  (drop-counts nil :type (or null (simple-array (unsigned-byte 64) (9))))
  (watermarks nil :type (or null (simple-array (unsigned-byte 32) (9))))
  ;; shed reporting (FR-LOG-6): a status-changed flag (the vendor status bit +log-shed-status+) + an
  ;; optional listener fired on each shed. The per-severity counts are drop-counts (logger-shed-counts).
  (shed-status-changed nil :type boolean)
  (shed-listener nil :type (or null function)))

(defun* %guid-prefix->uuid (prefix)
    (function ((simple-array (unsigned-byte 8) (12))) string)
  "Render the 12-octet RTPS GUID prefix as 24 lowercase hex characters — the participant's stable,
   network-unique identity string for the LogEvent participant_uuid (ADR 0082 §3). NOT the 16-octet
   RFC 4122 layout: RTPS identifies a participant by its 12-octet GUID prefix (DDSI-RTPS 2.5 §8.2.4.2),
   so the honest, reversible identifier is those 12 octets in hex (24 chars, well within the string<40>
   bound), never a fabricated 16-octet UUID."
  (let ((s (make-string 24))
        (digits "0123456789abcdef"))
    (declare (type simple-string s))
    (dotimes (i 12)
      (let ((byte (aref prefix i)))
        (setf (char s (* 2 i)) (char digits (ldb (byte 4 4) byte))
              (char s (1+ (* 2 i))) (char digits (ldb (byte 4 0) byte)))))
    s))

(defconstant +log-default-ring-capacity+ 1024
  "Default bounded-ring capacity for an async logger (make-logger :async t, FR-LOG-5): the number of
   LogEvents the ring holds between the emit call and the worker thread. Overflow sheds by severity
   (FR-LOG-6), so this bounds the buffering — not a hard limit on throughput.")

(defconstant +log-shed-status+ #x01000000
  "The vendor status bit for logging-service OVERFLOW SHED (FR-LOG-6) — bit 24, deliberately clear of
   the OMG communication-status range (DDS 1.4 §2.3.2 defines statuses at bits 0..14). Set in the
   logger's status-changed flag whenever an event is shed on ring overflow; the per-severity counts are
   the logger-shed-counts snapshot, and a shed-listener is the push notification. This is the
   logger-scoped status machinery (the logger is not a DCPS entity); a WaitSet-attachable DDS
   StatusCondition on the logger's writer is a follow-on.")

(defparameter *log-severity-order*
  #(:emerg :alert :crit :err :warn :notice :info :debug :trace)
  "The severity keywords in RFC 5424 numeric order — index = severity number (0=EMERG .. 8=TRACE).
   logger-emit maps a severity keyword to its number (position here) to index the ring watermarks and
   shed counters; an unknown keyword falls back to +severity-info+ (6).")

(defun* %compute-watermarks (capacity)
    (function ((integer 1)) (simple-array (unsigned-byte 32) (9)))
  "The per-severity ring OCCUPANCY watermarks for a ring of CAPACITY (FR-LOG-6): an event at severity S
   is SHED when the ring's occupancy is >= watermark[S]. EMERG..ERR (0..3) = CAPACITY, so they are shed
   only when NO slot remains (\"never shed while a slot remains\"); the lower severities shed earlier, so
   TRACE (>= 25% full) sheds first, then DEBUG (50%), then INFO (70%), NOTICE (80%), WARN (90%) — keeping
   the upper slots for higher-severity events. Each graded watermark is clamped >= 1 so it is never
   degenerate at a tiny capacity. Integer math only (no floats)."
  (let ((w (make-array 9 :element-type '(unsigned-byte 32))))
    (dotimes (i 4) (setf (aref w i) capacity))                    ; EMERG ALERT CRIT ERR: full-only
    (setf (aref w 4) (max 1 (floor (* capacity 90) 100))          ; WARN
          (aref w 5) (max 1 (floor (* capacity 80) 100))          ; NOTICE
          (aref w 6) (max 1 (floor (* capacity 70) 100))          ; INFO
          (aref w 7) (max 1 (floor (* capacity 50) 100))          ; DEBUG
          (aref w 8) (max 1 (floor (* capacity 25) 100)))         ; TRACE
    w))

(defun* %log-severity-number (severity)
    (function (keyword) (integer 0 8))
  "SEVERITY's RFC 5424 number (0=EMERG .. 8=TRACE) via *log-severity-order*; +severity-info+ for an
   unknown keyword. Used to index the ring watermarks and shed counters."
  (or (position severity *log-severity-order*) +severity-info+))

(defun* %logger-drain-ring (logger)
    (function (logger) t)
  "Worker side: dequeue and write EVERY currently-queued LogEvent. The dequeue is under the ring lock
   (brief); the DDS write-sample is OUTSIDE the lock, so an emitter can enqueue while the worker writes.
   Returns when the ring is empty."
  (loop
    (let ((event (dds.pal:with-lock ((logger-lock logger))
                   (when (plusp (logger-count logger))
                     (let ((e (svref (logger-ring logger) (logger-head logger))))
                       (setf (svref (logger-ring logger) (logger-head logger)) nil
                             (logger-head logger) (mod (1+ (logger-head logger)) (logger-capacity logger)))
                       (decf (logger-count logger))
                       e)))))
      (if event
          (dds.dcps:write-sample (logger-writer logger) event)
          (return t)))))

(defun* %logger-worker-loop (logger)
    (function (logger) t)
  "The async logger worker-thread body (FR-LOG-5): spin the participant (discovery + reliable delivery),
   drain the ring (write queued events), then wait on the condvar with a short timeout — so it wakes
   immediately on a new event (condvar-signal) yet still ticks periodically to keep spinning when idle —
   until close-logger clears RUNNING. On exit it drains once more, flushing events enqueued during
   shutdown. The participant is touched ONLY here, so there is no write/spin race with the app thread."
  (loop while (logger-running logger)
        do (dds.dcps:spin (logger-participant logger))
           (%logger-drain-ring logger)
           (dds.pal:with-lock ((logger-lock logger))
             (when (and (logger-running logger) (zerop (logger-count logger)))
               (dds.pal:condvar-wait (logger-condvar logger) (logger-lock logger) 0.05))))
  (%logger-drain-ring logger)
  t)

(defun* %logger-stop-worker (logger)
    (function (logger) t)
  "Stop + JOIN the async worker (idempotent; a no-op for a sync logger with no worker): clear RUNNING
   and signal the condvar under the lock (so a waiting worker wakes and sees the flag), then join the
   thread. After this the ring is quiescent and no worker touches the participant — so close-logger may
   delete it safely."
  (let ((w (logger-worker logger)))
    (when w
      (dds.pal:with-lock ((logger-lock logger))
        (setf (logger-running logger) nil)
        (dds.pal:condvar-signal (logger-condvar logger)))
      (dds.pal:join w)
      (setf (logger-worker logger) nil)))
  t)

(defun* logger-shed-counts (logger)
    (function (logger) (simple-array (unsigned-byte 64) (9)))
  "A SNAPSHOT copy of LOGGER's per-severity shed (dropped-on-overflow) counters, indexed by RFC 5424
   severity number (0=EMERG .. 8=TRACE) — the get_*_status-style query of FR-LOG-6's overflow reporting,
   REPORTED not printed. All zero in sync mode (no ring, no shedding). Copied under the lock so a
   concurrent emitter's increment cannot tear the read. The StatusCondition + listener push (the rest of
   the DDS status machinery) is a follow-on; this is the queryable snapshot."
  (let ((snap (make-array 9 :element-type '(unsigned-byte 64) :initial-element 0)))
    (dds.pal:with-lock ((logger-lock logger))
      (when (logger-drop-counts logger)
        (dotimes (i 9) (setf (aref snap i) (aref (logger-drop-counts logger) i)))))
    snap))

(defun* logger-shed-status-changed-p (logger)
    (function (logger) boolean)
  "T iff the logging-service SHED status (+log-shed-status+, FR-LOG-6) has changed — i.e. an event has
   been shed on ring overflow since the last logger-reset-shed-status. The changed-bit half of the DDS
   status shape (query the per-severity counts with logger-shed-counts)."
  (logger-shed-status-changed logger))

(defun* logger-reset-shed-status (logger)
    (function (logger) (eql t))
  "Clear LOGGER's shed status-changed flag (the get_*_status read-then-reset semantics, DDS 1.4
   §2.2.4.1). The per-severity counts (logger-shed-counts) are cumulative and are NOT reset."
  (dds.pal:with-lock ((logger-lock logger))
    (setf (logger-shed-status-changed logger) nil))
  t)

(defun* logger-set-shed-listener (logger fn)
    (function (logger (or null function)) t)
  "Install FN as LOGGER's shed listener (FR-LOG-6 push), or NIL to remove it. FN is called (OUTSIDE the
   logger lock) as (funcall FN severity-number cumulative-count) on each shed — severity-number is the
   RFC 5424 number (0=EMERG..8=TRACE) of the shed event, cumulative-count its running per-severity drop
   total. Keep FN lightweight: it runs on the emitting thread's shed path. Reported, never printed."
  (setf (logger-shed-listener logger) fn))

(defun* make-logger (&key participant (domain 0) (advertise-address "127.0.0.1") (app-id "")
                          host host-ip (topic-name *log-topic-name*) (type-name *log-type-name*)
                          (reliability :reliable) (async nil) (ring-capacity +log-default-ring-capacity+))
    (function (&key (:participant (or null net.goenninger.dds.dcps:domain-participant))
                    (:domain (integer 0)) (:advertise-address string) (:app-id string)
                    (:host (or null string)) (:host-ip (or null string)) (:topic-name string)
                    (:type-name string) (:reliability keyword) (:async t) (:ring-capacity (integer 1)))
              logger)
  "Create a logger, detecting the per-source identity ONCE now (ADR 0082 §3; owner directives
   2026-07-23 UUID/IP, 2026-07-24 app-id): host = HOST or the machine name; participant_uuid = the
   participant's GUID prefix as 24 hex chars; host_ip = HOST-IP or the participant's advertised address
   (IPv4 or IPv6 — the address at which DDS reaches this participant); process = getpid; app_id =
   APP-ID. Borrows PARTICIPANT when given (the embedded-library case — the app's own participant), else
   creates one on DOMAIN/ADVERTISE-ADDRESS and OWNS it (close-logger deletes only an owned one).
   Publishes on TOPIC-NAME/TYPE-NAME (default the interop names, so a Connext collector interoperates).
   ASYNC (default NIL = synchronous): when T, logger-emit ENQUEUES on a bounded ring of RING-CAPACITY
   (default +log-default-ring-capacity+) drained by a worker thread that spins the participant and writes
   the events — so the emit call never waits for the DDS write (FR-LOG-5), and ring overflow sheds by
   severity (FR-LOG-6). In async mode the worker drives the participant, so logger-spin is a no-op."
  (let* ((ts (dds.types:find-type-support "log-event"))
         (own (null participant))
         (p (or participant
                (dds.dcps:create-participant :domain domain :advertise-address advertise-address)))
         (tp (dds.dcps:create-topic p topic-name type-name ts))
         (pub (dds.dcps:create-publisher p))
         ;; KEEP_ALL, not the KEEP_LAST-1 default: every log record for one (host, process) source is a
         ;; DISTINCT event (distinct seq/timestamp/message). KEEP_LAST-1 would coalesce same-key samples
         ;; and drop all but the latest — a log must never lose records (ADR 0082). Reliable + KEEP_ALL
         ;; also retains each sample for retransmission. Backpressure on a full history (severity-graded
         ;; shedding, ADR 0082 §5) is a follow-on slice.
         (dw (dds.dcps:create-datawriter pub tp
               :qos (dds.qos:make-writer-qos :reliability reliability :history-kind :keep-all))))
    (let ((logger (%make-logger
                   :participant p :writer dw :owns-participant own
                   :host (or host (machine-instance))
                   :participant-uuid (%guid-prefix->uuid (dds.dcps:participant-guid-prefix p))
                   :host-ip (or host-ip (dds.dcps:participant-advertise-address p))
                   :app-id app-id
                   :process (dds.pal:process-id)
                   :lock (dds.pal:make-lock "dds-logger")
                   :async-p async
                   :capacity (if async ring-capacity 0)
                   :ring (when async (make-array ring-capacity :initial-element nil))
                   :watermarks (when async (%compute-watermarks ring-capacity))
                   :drop-counts (when async (make-array 9 :element-type '(unsigned-byte 64)
                                                          :initial-element 0))
                   :condvar (when async (dds.pal:make-condvar))
                   :running async)))
      ;; the worker starts AFTER the struct exists (it references LOGGER); the participant is created
      ;; above on THIS thread and thereafter touched only by the worker (spin + write) — no race.
      (when async
        (setf (logger-worker logger)
              (dds.pal:spawn (lambda () (%logger-worker-loop logger)) :name "dds-log-worker")))
      logger)))

(defun* logger-emit (logger &key (severity :info) (message "") (category "") (function "")
                            (file "") (line 0) (event-kind :message) (elapsed-ns 0) (thread 0))
    (function (logger &key (:severity keyword) (:message string) (:category string) (:function string)
                      (:file string) (:line (unsigned-byte 32)) (:event-kind keyword)
                      (:elapsed-ns (unsigned-byte 64)) (:thread (unsigned-byte 32)))
              (member :ok :shed :timeout :not-enabled :bad-parameter))
  "Emit one log event: stamp LOGGER's detected identity, the next per-logger seq, and a realtime
   nanosecond timestamp onto a LogEvent built from the call arguments (build-log-event truncates
   over-bound strings — a log call never fails on a long value). Never signals a condition — always a
   status.
   SYNC mode: build + write on the caller's thread; returns the write-sample status.
   ASYNC mode (make-logger :async t, FR-LOG-5/6): the seq ALWAYS advances (so a shed shows as a gap the
   collector can see), then — if the ring's occupancy is >= SEVERITY's watermark — the event is SHED
   (drop counted, returns :shed, nothing built), else it is built and ENQUEUED (returns :ok, the worker
   writes it; the caller never waits for the DDS write). Both modes hold LOGGER's lock only briefly (the
   async lock never spans the DDS write)."
  (flet ((%build (seq)
           (build-log-event
            :host (logger-host logger) :process (logger-process logger)
            :participant-uuid (logger-participant-uuid logger) :host-ip (logger-host-ip logger)
            :app-id (logger-app-id logger) :thread thread
            :seq seq :timestamp (dds.pal:realtime-ns)
            :severity severity :category category :function function :file file :line line
            :event-kind event-kind :elapsed-ns elapsed-ns :message message)))
    (if (logger-async-p logger)
        (let ((shed-sev nil) (shed-count 0) (result nil))
          (dds.pal:with-lock ((logger-lock logger))
            (let ((seq (logger-seq logger))
                  (sev (%log-severity-number severity)))
              (incf (logger-seq logger))                                 ; seq advances even on shed
              (if (>= (logger-count logger) (aref (logger-watermarks logger) sev))
                  (progn                                                 ; SHED (FR-LOG-6)
                    (incf (aref (logger-drop-counts logger) sev))
                    (setf (logger-shed-status-changed logger) t          ; the +log-shed-status+ bit
                          shed-sev sev
                          shed-count (aref (logger-drop-counts logger) sev)
                          result :shed))
                  (progn                                                 ; enqueue
                    (setf (svref (logger-ring logger) (logger-tail logger)) (%build seq)
                          (logger-tail logger) (mod (1+ (logger-tail logger)) (logger-capacity logger)))
                    (incf (logger-count logger))
                    (dds.pal:condvar-signal (logger-condvar logger))
                    (setf result :ok)))))
          ;; fire the shed listener OUTSIDE the lock (never call app code holding the lock) — the push
          ;; of FR-LOG-6's overflow reporting; the counts are also queryable via logger-shed-counts.
          (when (and shed-sev (logger-shed-listener logger))
            (funcall (logger-shed-listener logger) shed-sev shed-count))
          result)
        (dds.pal:with-lock ((logger-lock logger))
          (let ((seq (logger-seq logger)))
            (incf (logger-seq logger))
            (dds.dcps:write-sample (logger-writer logger) (%build seq)))))))

(defun* logger-spin (logger)
    (function (logger) t)
  "Drive one discovery + delivery cycle on LOGGER's participant (dds.dcps:spin): announce SPDP/SEDP and
   run reliable retransmit. An app that let make-logger CREATE a SYNC participant calls this periodically;
   an app that PASSED its own participant spins that participant itself. In ASYNC mode the worker thread
   drives spin, so this is a NO-OP (calling it is harmless)."
  (unless (logger-async-p logger)
    (dds.dcps:spin (logger-participant logger)))
  t)

(defun* close-logger (logger)
    (function (logger) (eql t))
  "Release LOGGER. In ASYNC mode first STOPS + JOINS the worker (which drains the ring's remaining
   events on the way out), so no worker thread touches the participant during teardown. Then deletes the
   participant ONLY if the logger created it (a borrowed participant is the app's to delete). Deleting
   the participant stops its engine and joins its threads, so a process can exit cleanly."
  (%logger-stop-worker logger)   ; no-op for a sync logger (no worker)
  (when (logger-owns-participant logger)
    (dds.dcps:delete-participant (logger-participant logger)))
  t)
