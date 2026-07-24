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
   every event), the monotonic per-logger seq counter, and the emit lock. Created by make-logger,
   released by close-logger."
  (participant nil :type t)
  (writer nil :type t)
  (owns-participant nil :type boolean)
  (host "" :type string)
  (participant-uuid "" :type string)
  (host-ip "" :type string)
  (app-id "" :type string)
  (process 0 :type (unsigned-byte 32))
  (seq 0 :type (unsigned-byte 64))
  (lock nil :type t))

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

(defun* make-logger (&key participant (domain 0) (advertise-address "127.0.0.1") (app-id "")
                          host host-ip (topic-name *log-topic-name*) (type-name *log-type-name*)
                          (reliability :reliable))
    (function (&key (:participant (or null net.goenninger.dds.dcps:domain-participant))
                    (:domain (integer 0)) (:advertise-address string) (:app-id string)
                    (:host (or null string)) (:host-ip (or null string)) (:topic-name string)
                    (:type-name string) (:reliability keyword))
              logger)
  "Create a logger, detecting the per-source identity ONCE now (ADR 0082 §3; owner directives
   2026-07-23 UUID/IP, 2026-07-24 app-id): host = HOST or the machine name; participant_uuid = the
   participant's GUID prefix as 24 hex chars; host_ip = HOST-IP or the participant's advertised address
   (IPv4 or IPv6 — the address at which DDS reaches this participant); process = getpid; app_id =
   APP-ID. Borrows PARTICIPANT when given (the embedded-library case — the app's own participant), else
   creates one on DOMAIN/ADVERTISE-ADDRESS and OWNS it (close-logger deletes only an owned one).
   Publishes on TOPIC-NAME/TYPE-NAME (default the interop names, so a Connext collector interoperates)."
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
    (%make-logger
     :participant p :writer dw :owns-participant own
     :host (or host (machine-instance))
     :participant-uuid (%guid-prefix->uuid (dds.dcps:participant-guid-prefix p))
     :host-ip (or host-ip (dds.dcps:participant-advertise-address p))
     :app-id app-id
     :process (dds.pal:process-id)
     :lock (dds.pal:make-lock "dds-logger"))))

(defun* logger-emit (logger &key (severity :info) (message "") (category "") (function "")
                            (file "") (line 0) (event-kind :message) (elapsed-ns 0) (thread 0))
    (function (logger &key (:severity keyword) (:message string) (:category string) (:function string)
                      (:file string) (:line (unsigned-byte 32)) (:event-kind keyword)
                      (:elapsed-ns (unsigned-byte 64)) (:thread (unsigned-byte 32)))
              (member :ok :timeout :not-enabled :bad-parameter))
  "Emit one log event: stamp LOGGER's detected identity, the next per-logger seq, and a realtime
   nanosecond timestamp onto a LogEvent built from the call arguments (build-log-event, which truncates
   over-bound strings — a log call never fails on a long value), and publish it on LOGGER's DataWriter.
   Returns the write-sample status (:ok / :timeout / :not-enabled / :bad-parameter — a status, never a
   signalled condition). Serialized by LOGGER's lock so concurrent emitters get distinct monotonic seq
   values; this lock is off the DDS hot path (this is the app-facing call). The non-blocking ring +
   worker that removes even this lock from the caller is a follow-on slice."
  (dds.pal:with-lock ((logger-lock logger))
    (let ((e (build-log-event
              :host (logger-host logger) :process (logger-process logger)
              :participant-uuid (logger-participant-uuid logger) :host-ip (logger-host-ip logger)
              :app-id (logger-app-id logger) :thread thread
              :seq (logger-seq logger) :timestamp (dds.pal:realtime-ns)
              :severity severity :category category :function function :file file :line line
              :event-kind event-kind :elapsed-ns elapsed-ns :message message)))
      (incf (logger-seq logger))
      (dds.dcps:write-sample (logger-writer logger) e))))

(defun* logger-spin (logger)
    (function (logger) t)
  "Drive one discovery + delivery cycle on LOGGER's participant (dds.dcps:spin): announce SPDP/SEDP and
   run reliable retransmit. An app that let make-logger CREATE the participant calls this periodically;
   an app that PASSED its own participant spins that participant itself, making this redundant. The
   autonomous background-announcer variant (spin driven by a thread) is a follow-on slice."
  (dds.dcps:spin (logger-participant logger)))

(defun* close-logger (logger)
    (function (logger) (eql t))
  "Release LOGGER. Deletes the participant ONLY if the logger created it (a borrowed participant is the
   app's to delete). Deleting the participant stops its engine and joins its threads, so a process can
   exit cleanly — a live receiver thread races process teardown otherwise."
  (when (logger-owns-participant logger)
    (dds.dcps:delete-participant (logger-participant logger)))
  t)
