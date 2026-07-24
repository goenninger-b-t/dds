;;;; The log collector — the receive side of the distributed logging service (ADR 0082 §6, FR-LOG).
;;;; Subscribes to LogEvent, drains received samples, and pushes each through its configured sinks.
;;;; This slice is the synchronous drain (collector-drain + a bounded collector-run loop); the
;;;; multi-service runner, the OTP-style supervisor and the log-service-main CLI are follow-on slices.

(in-package #:net.goenninger.dds.log)

(defstruct* (log-collector (:constructor %make-log-collector))
  "A logging-service consumer (ADR 0082 §6): a LogEvent DataReader plus the sinks each received event
   is pushed to, and a running received-count. Created by make-log-collector, drained by
   collector-drain / collector-run, released by close-log-collector."
  (participant nil :type t)
  (reader nil :type t)
  (owns-participant nil :type boolean)
  (sinks '() :type list)
  (received 0 :type (unsigned-byte 64)))

(defun* make-log-collector (&key participant (domain 0) (advertise-address "127.0.0.1")
                                 (sinks '()) (topic-name *log-topic-name*) (type-name *log-type-name*)
                                 (reliability :reliable))
    (function (&key (:participant (or null net.goenninger.dds.dcps:domain-participant))
                    (:domain (integer 0)) (:advertise-address string) (:sinks list)
                    (:topic-name string) (:type-name string) (:reliability keyword))
              log-collector)
  "Create a collector subscribed to TOPIC-NAME/TYPE-NAME (default the interop names, so it reads a
   Connext dds::log::LogEvent publisher on the wire). Borrows PARTICIPANT when given, else creates and
   OWNS one on DOMAIN/ADVERTISE-ADDRESS (close-log-collector deletes only an owned one). SINKS is the
   list of log-sinks each received event is pushed to (in order)."
  (let* ((ts (dds.types:find-type-support "log-event"))
         (own (null participant))
         (p (or participant
                (dds.dcps:create-participant :domain domain :advertise-address advertise-address)))
         (tp (dds.dcps:create-topic p topic-name type-name ts))
         (sub (dds.dcps:create-subscriber p))
         ;; KEEP_ALL, not the KEEP_LAST-1 default: distinct log records share the (host, process) key, so
         ;; a KEEP_LAST-1 reader would retain only the latest per source and silently drop the rest. A log
         ;; collector must keep every received record until it is drained (ADR 0082).
         (dr (dds.dcps:create-datareader sub tp
               :qos (dds.qos:make-reader-qos :reliability reliability :history-kind :keep-all))))
    (%make-log-collector :participant p :reader dr :owns-participant own :sinks sinks)))

(defun* collector-drain (collector)
    (function (log-collector) (unsigned-byte 32))
  "Spin the participant once, take all currently-available LogEvent samples, and push each one that
   carries valid data through every sink (in order). Returns the number of events drained this call —
   the deterministic step a run loop repeats and a test drives directly. Samples without valid data
   (dispose/unregister notifications) advance no sink and are not counted."
  (dds.dcps:spin (log-collector-participant collector))
  (let ((n 0))
    (declare (type (unsigned-byte 32) n))
    (dolist (cs (dds.dcps:take-samples (log-collector-reader collector)))
      (let ((info (dds.dcps:cached-sample-info cs)))
        (when (dds.dcps:sample-info-valid-data info)
          (let ((event (dds.dcps:cached-sample-data cs)))
            (incf n)
            (incf (log-collector-received collector))
            (dolist (sink (log-collector-sinks collector))
              (sink-emit sink event))))))
    n))

(defun* collector-run (collector &key (seconds 0) (idle-sleep 0.02))
    (function (log-collector &key (:seconds real) (:idle-sleep real)) (unsigned-byte 64))
  "Run the drain loop for SECONDS wall-clock (0 = until the caller interrupts), sleeping IDLE-SLEEP
   seconds between drains. Returns the total events received over the run. This is the plain service
   main loop; the supervised, signal-terminated form (log-service-main) is a follow-on slice."
  (let ((start (get-internal-real-time)))
    (loop
      (collector-drain collector)
      (when (and (plusp seconds)
                 (>= (/ (- (get-internal-real-time) start) internal-time-units-per-second) seconds))
        (return))
      (sleep idle-sleep)))
  (log-collector-received collector))

(defun* close-log-collector (collector)
    (function (log-collector) (eql t))
  "Release COLLECTOR: close every sink, then delete the participant IF the collector created it (a
   borrowed participant is the app's to delete). Deleting the participant joins its receiver thread, so
   the process exits cleanly."
  (dolist (sink (log-collector-sinks collector)) (close-sink sink))
  (when (log-collector-owns-participant collector)
    (dds.dcps:delete-participant (log-collector-participant collector)))
  t)
