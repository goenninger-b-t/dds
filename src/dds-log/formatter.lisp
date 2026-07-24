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
