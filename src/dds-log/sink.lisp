;;;; Sinks for the log collector (ADR 0082 §7): a sink is a replaceable pair of closures — a WRITE that
;;;; consumes one log-event and a CLOSE that releases the sink's resource. Swapping a sink (or its
;;;; formatter) is a configuration change, never a collector change. This slice ships the file sink
;;;; (append newline-delimited formatted records to a file); the RFC 5424 UDP-syslog and HTTP-bulk
;;;; sinks are follow-on slices.

(in-package #:net.goenninger.dds.log)

(defstruct* (log-sink (:constructor %make-log-sink))
  "A collector output sink (ADR 0082 §7): WRITE consumes one log-event (typically format-then-emit),
   CLOSE releases the sink's resource. A sink is a replaceable closure pair, so a config swaps output
   (file / syslog / http) or format (text / JSON) without touching the collector."
  (write (lambda (event) (declare (ignore event)) nil) :type function)
  (close (lambda () nil) :type function))

(defun* make-function-sink (fn &key (close (lambda () nil)))
    (function (function &key (:close function)) log-sink)
  "A sink whose write closure is FN (called with each log-event) and whose close closure is CLOSE
   (default a no-op). The general adapter (ADR 0082 §7): wrap any per-event handler — an in-memory
   collector, a metrics counter, a custom formatter-then-emitter — as a sink without a dedicated
   constructor. make-file-sink is the file specialization of this idea."
  (%make-log-sink :write fn :close close))

(defun* sink-emit (sink event)
    (function (log-sink log-event) t)
  "Push EVENT through SINK's write closure."
  (funcall (log-sink-write sink) event))

(defun* close-sink (sink)
    (function (log-sink) t)
  "Release SINK via its close closure."
  (funcall (log-sink-close sink)))

(defun* make-file-sink (path &key (formatter #'format-log-event-text) (if-exists :append))
    (function (t &key (:formatter function) (:if-exists keyword)) log-sink)
  "A sink that appends each event to the file at PATH as one FORMATTER-rendered record per line
   (newline-delimited — the framing a text log or a json_lines consumer reads). FORMATTER defaults to
   the text formatter; pass #'format-log-event-json for a JSON-lines file. IF-EXISTS governs an
   existing file (:append the default, :supersede to truncate). The file is opened once here (UTF-8, the
   LogEvent string encoding) and closed by close-sink; each record is written then force-output, so a
   crash loses at most the in-flight line."
  (let ((stream (open path :direction :output :if-exists if-exists :if-does-not-exist :create
                           :element-type 'character :external-format :utf-8)))
    (%make-log-sink
     :write (lambda (event)
              (write-string (funcall formatter event) stream)
              (write-char #\Newline stream)
              (force-output stream))
     :close (lambda () (close stream)))))
