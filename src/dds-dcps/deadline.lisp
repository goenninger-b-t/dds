;;;; WP-DCPS-API-COMPLETION S4 — the DEADLINE monitor + the DEADLINE_MISSED fires.
;;;; CONTROL-PLANE (not the measured hot path): a per-participant background thread over a
;;;; next-expiry scan of armed per-instance timers realizes the DDS 1.4 DEADLINE QoS
;;;; (§2.2.3.7) — OFFERED_DEADLINE_MISSED on a DataWriter, REQUESTED_DEADLINE_MISSED on a
;;;; DataReader (dds_rtf2_dcps.idl §131-141). Every miss fires through the ONE %notify-status
;;;; chokepoint (S0) so it flows to the bitmask + StatusCondition + the S3 listener hierarchy —
;;;; no parallel notification path. The DEFAULT (DURATION_INFINITE) DEADLINE arms NO timer, so a
;;;; non-deadline participant never even creates the monitor thread and its write/receive path is
;;;; byte-identical + 0-alloc (NFR-MEM): %deadline-touch returns before touching the monitor.

(in-package #:dds.dcps)

;; Forward-declared: %deadline-loop (the thread body, spawned by %endpoint-ensure-monitor) and the
;; two miss fires it calls are defined below their callers in this file.
(declaim (ftype (function (t t) t) %fire-offered-deadline-missed %fire-requested-deadline-missed))
(declaim (ftype (function (t) t) %deadline-loop))

;;; ---- The armed-timer registry + the monitor thread ----

(defstruct* (deadline-timer (:constructor %make-deadline-timer))
  "One armed per-instance DEADLINE timer (DDS 1.4 §2.2.3.7). ENDPOINT is the DataWriter (KIND
   :offered) or DataReader (KIND :requested); HANDLE is the 16-octet instance handle; PERIOD is the
   DEADLINE period in internal-time-units; EXPIRY is the next-expiry stamp (internal-time-units),
   the ONLY mutable field — rearmed on each write/received-sample (%deadline-touch) and re-armed one
   period ahead each time the monitor fires the miss. The struct is created ONCE per (endpoint,
   instance) and reused across every subsequent write/sample (NFR-MEM: no per-sample cons)."
  (endpoint nil :type t)
  (handle nil :type t)
  (kind :offered :type (member :offered :requested :app-ack))   ; ADR 0090 A4: :APP-ACK is a per-WRITER timer (HANDLE is the keyword :app-ack, which cannot collide with a 16-octet instance handle in this equalp table), not per-instance — the acknowledgment watchdog rides this wheel rather than spawning a second thread
  (period 1 :type (integer 1))
  (expiry 0 :type (integer 0)))

(defstruct* (deadline-monitor (:constructor %make-deadline-monitor))
  "The per-participant DEADLINE monitor: a background thread (THREAD) that waits on CV until the
   earliest armed timer's EXPIRY, then fires every expired timer's miss (DDS 1.4 §2.2.3.7). LOCK
   guards TIMERS (the armed set) + each timer's EXPIRY + RUNNING; CV wakes the thread when a new
   timer is armed or on stop. Lazily created + started on the first finite-DEADLINE arm and stopped
   + JOINED on delete-participant (no strand). TIMERS is a flat list scanned for the next expiry —
   the degenerate sorted next-expiry structure; a heap is a future optimization (control plane)."
  (lock (dds.pal:make-lock "deadline-monitor") :type t)
  (cv (dds.pal:make-condvar) :type t)
  (timers '() :type list)
  (thread nil :type t)
  (running nil :type boolean))

;;; ---- endpoint helpers (DataWriter | DataReader) ----

(defun* %endpoint-participant (endpoint)
    (function (t) domain-participant)
  "The DomainParticipant containing ENDPOINT (a DataWriter or DataReader) — the owner of the
   deadline monitor thread the endpoint's timers live on."
  (typecase endpoint
    (data-writer (pub-participant (dw-publisher endpoint)))
    (data-reader (sub-participant (dr-subscriber endpoint)))))

(defun* %endpoint-deadline-kind (endpoint)
    (function (t) (member :offered :requested))
  "The DEADLINE flavour ENDPOINT tracks: a DataWriter offers (OFFERED_DEADLINE_MISSED), a
   DataReader requests (REQUESTED_DEADLINE_MISSED) — DDS 1.4 §2.2.3.7."
  (typecase endpoint (data-writer :offered) (data-reader :requested)))

(defun* %endpoint-deadline-table (endpoint)
    (function (t) (or null hash-table))
  "ENDPOINT's handle -> deadline-timer table (its per-instance timer slots), or NIL when none has
   been armed yet (the DURATION_INFINITE common case never creates it)."
  (typecase endpoint
    (data-writer (dw-deadline-timers endpoint))
    (data-reader (dr-deadline-timers endpoint))))

(defun* %endpoint-ensure-deadline-table (endpoint)
    (function (t) hash-table)
  "ENDPOINT's handle -> deadline-timer table, creating it (equalp-keyed) on first use — a
   user-thread-owned map (same discipline as dw-instances / dr-instance-recs)."
  (or (%endpoint-deadline-table endpoint)
      (typecase endpoint
        (data-writer (setf (dw-deadline-timers endpoint) (make-hash-table :test 'equalp)))
        (data-reader (setf (dr-deadline-timers endpoint) (make-hash-table :test 'equalp))))))

(defun* %deadline-period-units (dur)
    (function (dds.qos:qos-duration) (or null (integer 1)))
  "The DEADLINE period DUR as internal-time-units, or NIL when it is DURATION_INFINITE (the default,
   DDS 1.4 §2.2.3.7 — never arms a timer, never fires) or non-positive. Mirrors the liveliness
   sweep's DURATION_INFINITE test (sec 0x7fffffff)."
  (if (>= (dds.qos:qos-duration-sec dur) #x7fffffff)
      nil
      (let ((u (+ (* (dds.qos:qos-duration-sec dur) internal-time-units-per-second)
                  (round (* (dds.qos:qos-duration-nanosec dur) internal-time-units-per-second)
                         1000000000))))
        (when (plusp u) u))))

(defun* %endpoint-deadline-period-units (endpoint)
    (function (t) (or null (integer 1)))
  "ENDPOINT's finite DEADLINE period in internal-time-units, or NIL when the DEADLINE is INFINITE /
   the QoS is absent (the byte-identical, 0-alloc non-deadline path returns here before any monitor
   interaction)."
  (let ((qos (entity-qos endpoint)))
    (when (typep qos 'dds.qos:qos)
      (%deadline-period-units (dds.qos:qos-deadline qos)))))

;;; ---- lazy monitor start ----

(defun* %endpoint-ensure-monitor (endpoint)
    (function (t) deadline-monitor)
  "The DEADLINE monitor of ENDPOINT's participant, creating + STARTING its background thread the
   first time any finite DEADLINE arms a timer (DDS 1.4 §2.2.3.7). Guarded by the participant's
   deadline-lock so concurrent first-arms create exactly one monitor. A non-deadline participant
   never reaches here, so its monitor thread is never spawned."
  (let ((p (%endpoint-participant endpoint)))
    (dds.pal:with-lock ((dp-deadline-lock p))
      (or (dp-deadline-monitor p)
          (let ((mon (%make-deadline-monitor)))
            (setf (deadline-monitor-running mon) t)
            (setf (deadline-monitor-thread mon)
                  (dds.pal:spawn (lambda () (%deadline-loop mon)) :name "dds-deadline"))
            (setf (dp-deadline-monitor p) mon)
            mon)))))

;;; ---- arm / rearm (user thread: write-sample / %drain-one-sample) ----

(defun* %deadline-arm-or-rearm (endpoint handle period &optional (kind (%endpoint-deadline-kind endpoint)))
    (function (t t (integer 1) &optional keyword) t)
  "Arm — or, for an already-tracked instance, REARM (0-alloc: reuse the per-instance timer slot,
   just push EXPIRY one period ahead) — ENDPOINT's per-instance DEADLINE for HANDLE (DDS 1.4
   §2.2.3.7). EXPIRY is mutated under the monitor lock (the monitor thread reads it). Since the new
   expiry is strictly later than any pending one, a rearm never needs to wake the monitor; a fresh
   arm signals the CV so the monitor re-evaluates its next-expiry wait."
  (let* ((tbl (%endpoint-ensure-deadline-table endpoint))
         (existing (gethash handle tbl)))
    (if existing
        (let ((mon (dp-deadline-monitor (%endpoint-participant endpoint))))
          (when mon
            (dds.pal:with-lock ((deadline-monitor-lock mon))
              (setf (deadline-timer-expiry existing) (+ (%lease-now) period)))))
        (let ((mon (%endpoint-ensure-monitor endpoint))
              (tm (%make-deadline-timer :endpoint endpoint :handle handle
                                        :kind kind
                                        :period period :expiry (+ (%lease-now) period))))
          (setf (gethash handle tbl) tm)
          (dds.pal:with-lock ((deadline-monitor-lock mon))
            (push tm (deadline-monitor-timers mon)))
          (dds.pal:condvar-signal (deadline-monitor-cv mon)))))
  t)

(defun* %deadline-touch (endpoint handle)
    (function (t t) t)
  "(Re)arm ENDPOINT's per-instance DEADLINE for the known instance HANDLE (the DataReader entry, on
   sample delivery). A no-op — and 0-alloc, no monitor interaction — when the DEADLINE is INFINITE
   (the default) or the QoS is absent (DDS 1.4 §2.2.3.7)."
  (let ((period (%endpoint-deadline-period-units endpoint)))
    (when period (%deadline-arm-or-rearm endpoint handle period)))
  t)

(defun* %deadline-touch-writer (dw kh sample)
    (function (data-writer t t) t)
  "(Re)arm DW's per-instance OFFERED DEADLINE for SAMPLE's instance (the DataWriter entry, on write).
   A no-op — and 0-alloc, no keyhash computed, no monitor interaction — when the DEADLINE is INFINITE
   (the default): the period check runs FIRST so the byte-identical non-deadline write path never
   computes an instance handle. When finite, reuses the KEEP_LAST keyhash KH if the writer already
   computed one, else computes the instance handle (unavoidable for per-instance DEADLINE tracking)."
  (let ((period (%endpoint-deadline-period-units dw)))
    (when period
      (%deadline-arm-or-rearm
       dw (or kh (%instance-handle (topic-type-support (dw-topic dw)) sample)) period)))
  t)

;;; ---- disarm (user thread: purge / delete) ----

(defun* %deadline-disarm-instance (endpoint handle)
    (function (t t) t)
  "Disarm ENDPOINT's per-instance DEADLINE timer for HANDLE (a purged/forgotten instance no longer
   tracks a deadline, DDS 1.4 §2.2.3.22/§2.2.3.7): drop it from the endpoint's table + the monitor's
   armed set. A no-op when no timer is armed for HANDLE."
  (let ((tbl (%endpoint-deadline-table endpoint)))
    (when tbl
      (let ((tm (gethash handle tbl)))
        (when tm
          (remhash handle tbl)
          (let ((mon (dp-deadline-monitor (%endpoint-participant endpoint))))
            (when mon
              (dds.pal:with-lock ((deadline-monitor-lock mon))
                (setf (deadline-monitor-timers mon)
                      (delete tm (deadline-monitor-timers mon))))))))))
  t)

(defun* %deadline-disarm-endpoint (endpoint)
    (function (t) t)
  "Disarm ALL of ENDPOINT's per-instance DEADLINE timers (on delete_datawriter/delete_datareader):
   remove every one of its timers from the monitor's armed set, then clear the endpoint's table."
  (let ((tbl (%endpoint-deadline-table endpoint)))
    (when tbl
      (let ((mon (dp-deadline-monitor (%endpoint-participant endpoint))))
        (when mon
          (dds.pal:with-lock ((deadline-monitor-lock mon))
            (maphash (lambda (h tm)
                       (declare (ignore h))
                       (setf (deadline-monitor-timers mon)
                             (delete tm (deadline-monitor-timers mon))))
                     tbl))))
      (clrhash tbl)))
  t)

(defun* %deadline-monitor-stop (p)
    (function (domain-participant) (values t (or null keyword)))
  "Stop + JOIN participant P's DEADLINE monitor thread (on delete-participant), then forget it — the
   clean-shutdown discipline (no strand, no use-after-free: the thread is joined BEFORE the node/
   buffers are torn down). Sets RUNNING NIL and signals the CV UNDER the monitor lock (so a thread
   about to wait sees the flag — no lost wakeup), then joins BOUNDED. Null-safe + idempotent (a
   participant that never armed a DEADLINE has no monitor).

   Returns (values T NIL) when the monitor is provably gone, (values NIL :TIMEOUT) when it is not.
   ⚠️ THE STATUS GATES DELETE-PARTICIPANT'S TEARDOWN (ADR 0092). The monitor fires misses through
   %NOTIFY-STATUS, which takes entity status locks and invokes APPLICATION listener callbacks — and an
   on_offered_deadline_missed callback may legitimately WRITE, reaching the node's send buffers. So a
   monitor that cannot be proven stopped must not have those buffers freed under it. On :TIMEOUT the
   monitor slot is NOT cleared, so a later delete re-attempts the join rather than forgetting the thread."
  (let ((mon (dp-deadline-monitor p)))
    (when mon
      (dds.pal:with-lock ((deadline-monitor-lock mon))
        (setf (deadline-monitor-running mon) nil)
        (dds.pal:condvar-signal (deadline-monitor-cv mon)))
      (let ((th (deadline-monitor-thread mon)))
        (when th
          (multiple-value-bind (r status) (dds.pal:join-bounded th :dcps-deadline-monitor)
            (declare (ignore r))
            (when status (return-from %deadline-monitor-stop (values nil status))))))
      (setf (dp-deadline-monitor p) nil)))
  (values t nil))

;;; ---- the monitor loop + the misses (background thread) ----

(defun* %deadline-loop (mon)
    (function (deadline-monitor) t)
  "The DEADLINE monitor thread body (DDS 1.4 §2.2.3.7). Under the monitor lock: collect every timer
   whose EXPIRY has passed (re-arming each one period ahead so a persistently-silent instance fires
   once per elapsed period), and compute the earliest un-expired EXPIRY. If any expired, release the
   lock and fire their misses through %notify-status (which takes the entity status lock — so it must
   run OUTSIDE the monitor lock). Otherwise wait on the CV until the earliest expiry (or forever when
   the armed set is empty), re-checking on every wake (a new arm signals, spurious wakes re-scan).
   Exits when RUNNING goes NIL (delete-participant)."
  (loop named outer do
    (let ((expired '()))
      (dds.pal:with-lock ((deadline-monitor-lock mon))
        (loop named inner do
          (unless (deadline-monitor-running mon) (return-from outer t))
          (let ((now (%lease-now)) (earliest nil))
            (dolist (tm (deadline-monitor-timers mon))
              (cond ((>= now (deadline-timer-expiry tm))
                     (push tm expired)
                     (setf (deadline-timer-expiry tm) (+ now (deadline-timer-period tm))))
                    ((or (null earliest) (< (deadline-timer-expiry tm) earliest))
                     (setf earliest (deadline-timer-expiry tm)))))
            (when expired (return-from inner))
            (dds.pal:condvar-wait
             (deadline-monitor-cv mon) (deadline-monitor-lock mon)
             (when earliest
               (max 0.005d0 (/ (- earliest now)
                               (float internal-time-units-per-second 1d0))))))))
      (dolist (tm expired)
        (ecase (deadline-timer-kind tm)
          (:offered (%fire-offered-deadline-missed (deadline-timer-endpoint tm)
                                                   (deadline-timer-handle tm)))
          (:requested (%fire-requested-deadline-missed (deadline-timer-endpoint tm)
                                                       (deadline-timer-handle tm)))
          ;; ADR 0090 A4: the acknowledgment watchdog. REPORTS AND NEVER PURGES — releasing the samples
          ;; here would discard data no application processed, which is the false ack ADR 0090 forbids.
          (:app-ack (%fire-application-acknowledgment-overdue (deadline-timer-endpoint tm))))))))

(defun* %fire-offered-deadline-missed (dw handle)
    (function (data-writer t) t)
  "Fire DW's OFFERED_DEADLINE_MISSED for instance HANDLE through the %notify-status chokepoint (DDS
   1.4 §2.2.3.7, dds_rtf2_dcps.idl §131-135): total_count++ (monotonic), total_count_change +1,
   last_instance_handle := HANDLE; sets the bitmask bit + triggers the StatusCondition + delivers
   on_offered_deadline_missed to the most-specific enabled listener up the hierarchy (S3)."
  (%notify-status dw +status-offered-deadline-missed+ :offered-deadline-missed
   (lambda ()
     (let ((s (dw-off-deadline dw)))
       (incf (offered-deadline-missed-status-total-count s))
       (incf (offered-deadline-missed-status-total-count-change s))
       (setf (offered-deadline-missed-status-last-instance-handle s) handle)
       (values t (copy-offered-deadline-missed-status s)
               (lambda () (setf (offered-deadline-missed-status-total-count-change s) 0))))))
  t)

(defun* %fire-requested-deadline-missed (dr handle)
    (function (data-reader t) t)
  "Fire DR's REQUESTED_DEADLINE_MISSED for instance HANDLE through the %notify-status chokepoint (DDS
   1.4 §2.2.3.7, dds_rtf2_dcps.idl §137-141): total_count++ (monotonic), total_count_change +1,
   last_instance_handle := HANDLE; sets the bitmask bit + triggers the StatusCondition + delivers
   on_requested_deadline_missed to the most-specific enabled listener up the hierarchy (S3)."
  (%notify-status dr +status-requested-deadline-missed+ :requested-deadline-missed
   (lambda ()
     (let ((s (dr-req-deadline dr)))
       (incf (requested-deadline-missed-status-total-count s))
       (incf (requested-deadline-missed-status-total-count-change s))
       (setf (requested-deadline-missed-status-last-instance-handle s) handle)
       (values t (copy-requested-deadline-missed-status s)
               (lambda () (setf (requested-deadline-missed-status-total-count-change s) 0))))))
  t)
