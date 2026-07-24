;;;; L?/service — the distributed logging service wire type (ADR 0082 §3, FR-LOG).
;;;; The LogEvent type + severity/event-kind enums + the truncating constructor. This slice is the
;;;; type only (ADR 0082 §9 slice ladder Task 4); the emit path, formatters, sinks, service, runner,
;;;; supervisor and CLI are follow-on slices.

(defpackage #:net.goenninger.dds.log
  (:nicknames #:dds.log)
  (:use #:common-lisp #:net.goenninger.dds.lang)
  (:documentation
   "Distributed logging service (ADR 0082, FR-LOG). This slice: the LogEvent wire type — an
    @appendable, source-keyed, bounded structured-logging record kept in lockstep with
    interop/log/DdsLog.idl — plus its Severity/EventKind enums, the RFC 5424 §6.2.1 severity
    constants, and build-log-event, which truncates over-bound strings rather than refusing them
    (a logging call must never fail).")
  (:export
   ;; the type + generated surface (dds.gen:define-dds-type)
   #:log-event #:make-log-event #:log-event-p
   #:log-event-host #:log-event-process #:log-event-participant-uuid #:log-event-host-ip
   #:log-event-app-id #:log-event-thread #:log-event-seq
   #:log-event-timestamp #:log-event-severity #:log-event-category #:log-event-function
   #:log-event-file #:log-event-line #:log-event-event-kind #:log-event-elapsed-ns
   #:log-event-truncated #:log-event-message
   #:serialize-log-event #:deserialize-log-event #:serialized-size-log-event
   ;; enum converters (dds.gen:define-dds-enum)
   #:severity-to-i32 #:severity-from-i32 #:event-kind-to-i32 #:event-kind-from-i32
   ;; RFC 5424 §6.2.1 severity constants (numeric syslog values)
   #:+severity-emerg+ #:+severity-alert+ #:+severity-crit+ #:+severity-err+
   #:+severity-warn+ #:+severity-notice+ #:+severity-info+ #:+severity-debug+ #:+severity-trace+
   ;; bounds
   #:+log-event-host-bound+ #:+log-event-participant-uuid-bound+ #:+log-event-host-ip-bound+
   #:+log-event-app-id-bound+ #:+log-event-category-bound+ #:+log-event-function-bound+
   #:+log-event-file-bound+ #:+log-event-message-bound+
   ;; construction + truncation
   #:build-log-event #:truncate-utf8
   ;; formatters (ADR 0082 §7) — the default text- and JSON-rendering closures
   #:format-log-event-text #:format-log-event-json
   ;; wire-name defaults (topic + registered type; pinned to the interop leg)
   #:*log-topic-name* #:*log-type-name*
   ;; the logger — emit side (ADR 0082 §5)
   #:logger #:logger-p #:make-logger #:logger-emit #:logger-spin #:close-logger
   #:logger-host #:logger-participant-uuid #:logger-host-ip #:logger-app-id
   #:logger-process #:logger-seq
   ;; sinks (ADR 0082 §7) — replaceable closure pairs
   #:log-sink #:log-sink-p #:sink-emit #:close-sink #:make-file-sink #:make-function-sink
   ;; the collector — receive side (ADR 0082 §6)
   #:log-collector #:log-collector-p #:make-log-collector
   #:collector-drain #:collector-run #:close-log-collector #:log-collector-received
   ;; the ergonomic macro API (ADR 0082 §5, FR-LOG-3/4) — per-severity macros + trace scope
   #:log-emerg #:log-alert #:log-crit #:log-err #:log-warn #:log-notice #:log-info
   #:log-debug #:log-trace #:with-trace-scope
   ;; categories + per-category thresholds
   #:*log-category-list* #:*log-thresholds* #:set-log-threshold #:get-log-threshold))
