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

(defun* make-stream-sink (stream &key (formatter #'format-log-event-text))
    (function (t &key (:formatter function)) log-sink)
  "A sink that writes each event to the character STREAM as one FORMATTER-rendered record per line
   (newline-delimited), force-output after each so nothing lingers unflushed. The stream is BORROWED —
   close-sink finish-outputs but does NOT close it (unlike make-file-sink, which owns its file). Use for
   *standard-output*/*error-output* or any already-open stream (the log service's default console sink)."
  (%make-log-sink
   :write (lambda (event)
            (write-string (funcall formatter event) stream)
            (write-char #\Newline stream)
            (force-output stream))
   :close (lambda () (finish-output stream))))

(defun* make-file-sink (path &key (formatter #'format-log-event-text) (if-exists :append))
    (function (t &key (:formatter function) (:if-exists keyword)) log-sink)
  "A sink that appends each event to the file at PATH as one FORMATTER-rendered record per line
   (newline-delimited — the framing a text log or a json_lines consumer reads). FORMATTER defaults to
   the text formatter; pass #'format-log-event-json for a JSON-lines file. IF-EXISTS governs an
   existing file (:append the default, :supersede to truncate). The file is opened once here (UTF-8, the
   LogEvent string encoding); the per-record write is make-stream-sink's (shared, DRY), but close-sink
   CLOSES the file (this sink OWNS it). Each record is written then force-output, so a crash loses at
   most the in-flight line."
  (let* ((stream (open path :direction :output :if-exists if-exists :if-does-not-exist :create
                            :element-type 'character :external-format :utf-8))
         (inner (make-stream-sink stream :formatter formatter)))
    (%make-log-sink :write (log-sink-write inner)
                    :close (lambda () (close stream)))))

(defun* make-udp-syslog-sink (host port &key (facility 1))
    (function (string (integer 0 65535) &key (:facility (integer 0 23))) log-sink)
  "A sink that sends each event to an RFC 5424 syslog collector at HOST:PORT over UDP — one datagram per
   event, the line rendered by format-log-event-syslog with FACILITY (default 1, user-level). Opens a UDP
   socket here (closed by close-sink); the datagram is the raw UTF-8 octets of the syslog line
   (dds.cdr:string-to-utf8-octets), which rsyslog/syslog-ng ingest directly. UDP syslog (RFC 5426) is
   fire-and-forget — a lost datagram is not retransmitted; the reliable leg is the DDS path INTO the
   collector, and the collector->syslog hop is best-effort by syslog's own design (ADR 0082 §7, FR-LOG-8)."
  (multiple-value-bind (socket status) (dds.pal:udp-open)
    (declare (ignore status))
    (%make-log-sink
     :write (lambda (event)
              (let ((octets (dds.cdr:string-to-utf8-octets
                             (format-log-event-syslog event :facility facility))))
                (dds.pal:udp-send-to socket octets (length octets) host port)))
     :close (lambda () (dds.pal:udp-close socket)))))

(defun* %http-bulk-flush (host port path content-type lines)
    (function (string (integer 0 65535) string string list) t)
  "POST the accumulated LINES (newest-first) as ONE HTTP/1.1 bulk request to http://HOST:PORT/PATH — the
   body is the lines newline-delimited in chronological order (the ND-JSON / Elasticsearch _bulk / Loki
   push shape). Best-effort FIRE-AND-FORGET: sends the request then closes; a failed tcp-connect silently
   drops the batch (a logging sink must NOT fail the collector), and the HTTP response is not read
   (mirrors UDP-syslog's best-effort — the reliable leg is the DDS path INTO the collector). Reading the
   response, a persistent connection, and a reader<->sink queue so a slow endpoint cannot stall reception
   are follow-ons. No conditions."
  (when lines
    (let* ((crlf (coerce (list #\Return #\Newline) 'string))
           (body (format nil "~{~a~%~}" (reverse lines)))
           (req (concatenate 'string
                             "POST " path " HTTP/1.1" crlf
                             "Host: " host ":" (princ-to-string port) crlf
                             "Content-Type: " content-type crlf
                             "Content-Length: " (princ-to-string (dds.cdr:utf8-octet-length body)) crlf
                             "Connection: close" crlf crlf
                             body))
           (octets (dds.cdr:string-to-utf8-octets req)))
      (multiple-value-bind (socket status) (dds.pal:tcp-connect host port)
        (unless status
          (dds.pal:tcp-send socket octets (length octets))
          (dds.pal:tcp-close socket)))))
  t)

(defun* make-http-bulk-sink (host port path &key (formatter #'format-log-event-json) (batch-size 32)
                                             (content-type "application/x-ndjson"))
    (function (string (integer 0 65535) t &key (:formatter function) (:batch-size (integer 1))
                      (:content-type string))
              log-sink)
  "A sink that POSTs BATCHES of FORMATTER-rendered records to http://HOST:PORT/PATH (ADR 0082 §7,
   FR-LOG-8). Events accumulate; each BATCH-SIZE events flush as one HTTP/1.1 POST (%http-bulk-flush,
   newline-delimited body — the ND-JSON / _bulk / Loki-push shape); close-sink flushes the remainder.
   FORMATTER defaults to the JSON formatter (pass #'format-log-event-text for plain text). CONTENT-TYPE
   labels the body. Best-effort (see %http-bulk-flush): connects per flush, fire-and-forget. The batch is
   a single-writer accumulator (one collector drain thread), so it needs no lock."
  (let ((batch '()) (count 0))
    (%make-log-sink
     :write (lambda (event)
              (push (funcall formatter event) batch)
              (incf count)
              (when (>= count batch-size)
                (%http-bulk-flush host port path content-type batch)
                (setf batch '() count 0)))
     :close (lambda ()
              (%http-bulk-flush host port path content-type batch)
              (setf batch '() count 0)))))
