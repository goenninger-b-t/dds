;;;; Text formatter for LogEvent (ADR 0082 §7). Renders a LOG-EVENT to the pinned seven-field text
;;;; line. A formatter is a function (the "replaceable closure" of ADR 0082 §7): a config holds one
;;;; and swapping it is a configuration change. This is the collector-side rendering; it is off the
;;;; measured hot path.

(in-package #:net.goenninger.dds.log)

(defconstant +posix-epoch-in-universal+ 2208988800
  "Seconds between the CL universal-time epoch (1900-01-01T00:00:00 UTC) and the POSIX epoch
   (1970-01-01T00:00:00 UTC): (encode-universal-time 0 0 0 1 1 1970 0). LogEvent timestamps are
   POSIX-epoch nanoseconds; adding this converts to universal time for decode-universal-time.")

(defun* %iso8601-utc (nanos)
    (function ((signed-byte 64)) string)
  "Render POSIX-epoch NANOS (int64 UTC nanoseconds) as ISO 8601 UTC with six fractional digits and a
   trailing Z: YYYY-MM-DDTHH:MM:SS.ffffffZ (ADR 0082 §7; ISO 8601-1:2019). FLOOR splits seconds from
   the sub-second remainder so a pre-epoch (negative) timestamp still renders a well-formed instant."
  (multiple-value-bind (sec frac) (floor nanos 1000000000)
    (let ((micros (floor frac 1000)))
      (multiple-value-bind (s mi h d mo y)
          (decode-universal-time (+ sec +posix-epoch-in-universal+) 0)
        (format nil "~4,'0d-~2,'0d-~2,'0dT~2,'0d:~2,'0d:~2,'0d.~6,'0dZ" y mo d h mi s micros)))))

(defun* %severity-name (severity)
    (function (t) string)
  "The uppercase syslog name of SEVERITY for rendering: a keyword (:crit -> CRIT) is its name
   upcased; a raw int32 (what an undecodable wire value decodes to) renders SEV<n>. Every declared
   name fits the six-column field (NOTICE, six chars, is the longest — which is why WARNING renders
   WARN: the enum literal is SEV_WARN, ADR 0082 §7)."
  (if (keywordp severity)
      (string-upcase (symbol-name severity))
      (format nil "SEV~a" severity)))

(defun* %event-kind-name (event-kind)
    (function (t) string)
  "The name of EVENT-KIND for rendering: a keyword (:exit -> EXIT) is its name upcased; a raw int32
   (an undecodable wire value) renders EK<n>."
  (if (keywordp event-kind)
      (string-upcase (symbol-name event-kind))
      (format nil "EK~a" event-kind)))

(defun* format-log-event-text (event)
    (function (log-event) string)
  "Render EVENT to the pinned eight-field text line (ADR 0082 §7):
     <ISO-8601-UTC.6frac Z> | <participant-uuid> | <host-ip> | <app-id> | <SEVER> | <category> | <function>() - <file>:<line> | <message>
   Fields join with ` | `; severity is left-aligned in six columns; the participant UUID, host IP and
   app id (the source identity given/detected once at logger creation) render directly after the
   timestamp so a collector shows the ORIGINATING logger's identity even for a remote source. The
   function field holds the bare name; the `()` is added here. This function is the default text
   formatter closure."
  (format nil "~a | ~a | ~a | ~a | ~6a | ~a | ~a() - ~a:~d | ~a"
          (%iso8601-utc (log-event-timestamp event))
          (log-event-participant-uuid event)
          (log-event-host-ip event)
          (log-event-app-id event)
          (%severity-name (log-event-severity event))
          (log-event-category event)
          (log-event-function event)
          (log-event-file event)
          (log-event-line event)
          (log-event-message event)))

(defun* %json-escape (string)
    (function (string) string)
  "Escape STRING for a JSON string literal (RFC 8259 §7): the two mandatory escapes (\\\" and \\\\),
   the short escapes for the control characters that have them (\\n \\r \\t \\b \\f), and \\u00XX for
   any other control character below U+0020. Non-ASCII is left as raw UTF-8, which RFC 8259 permits.
   A log object is a fixed shape, so a hand-written escaper is a few dozen lines against a new runtime
   dependency + SBOM entry (operating contract §9)."
  (with-output-to-string (s)
    (loop for c across string
          for code = (char-code c)
          do (cond ((char= c #\") (write-string "\\\"" s))
                   ((char= c #\\) (write-string "\\\\" s))
                   ((char= c #\Newline) (write-string "\\n" s))
                   ((char= c #\Return) (write-string "\\r" s))
                   ((char= c #\Tab) (write-string "\\t" s))
                   ((char= c #\Backspace) (write-string "\\b" s))
                   ((char= c #\Page) (write-string "\\f" s))
                   ((< code #x20) (format s "\\u~4,'0x" code))
                   (t (write-char c s))))))

(defun* format-log-event-json (event)
    (function (log-event) string)
  "Render EVENT as one JSON object (RFC 8259), the newline-delimited-JSON a collector's JSON sink
   emits (ADR 0082 §7) — the framing logstash's `json_lines` codec, filebeat, and vector read
   unchanged. `timestamp` is the ISO 8601 UTC render (µs precision); `severity` and `event_kind` are
   their lowercase names; `truncated` is a JSON boolean; the counters are JSON numbers. The object
   carries no trailing newline — the sink adds the record separator. This is the default JSON
   formatter closure (ADR 0082 §7 — a formatter is a function a config holds and can replace)."
  (format nil
          "{\"timestamp\":\"~a\",\"host\":\"~a\",\"process\":~d,\"participant_uuid\":\"~a\",~
           \"host_ip\":\"~a\",\"app_id\":\"~a\",\"thread\":~d,\"seq\":~d,\"severity\":\"~a\",~
           \"category\":\"~a\",\"function\":\"~a\",\"file\":\"~a\",\"line\":~d,\"event_kind\":\"~a\",~
           \"elapsed_ns\":~d,\"truncated\":~:[false~;true~],\"message\":\"~a\"}"
          (%iso8601-utc (log-event-timestamp event))
          (%json-escape (log-event-host event))
          (log-event-process event)
          (%json-escape (log-event-participant-uuid event))
          (%json-escape (log-event-host-ip event))
          (%json-escape (log-event-app-id event))
          (log-event-thread event)
          (log-event-seq event)
          (string-downcase (%severity-name (log-event-severity event)))
          (%json-escape (log-event-category event))
          (%json-escape (log-event-function event))
          (%json-escape (log-event-file event))
          (log-event-line event)
          (string-downcase (%event-kind-name (log-event-event-kind event)))
          (log-event-elapsed-ns event)
          (log-event-truncated event)
          (%json-escape (log-event-message event))))
