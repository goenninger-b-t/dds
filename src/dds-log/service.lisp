;;;; The log collector as a runnable SERVICE (ADR 0082 §6/§7, FR-LOG-7): log-service-main, the CLI/env
;;;; entrypoint that builds a collector + a sink from config and drains until SIGTERM/SIGINT, returning a
;;;; ReturnCode_t. Config errors are RETURNED statuses, never signalled (ADR 0064). This slice is the
;;;; SINGLE-service entrypoint; the multi-service runner + OTP-style supervisor (the durability-service
;;;; shape, FR-LOG-7) are follow-on slices.

(in-package #:net.goenninger.dds.log)

(defvar *log-service-shutdown-requested* nil
  "Set T by the SIGTERM/SIGINT handler log-service-main installs (BLOCK mode); the drain loop polls it
   and exits, so the service tears down gracefully rather than dying on a signal-killed thread.")

(defstruct* (log-service-config (:constructor %make-log-service-config))
  "Parsed log-service configuration (FR-LOG-7): the DDS DOMAIN, the output FILE (NIL = the console
   sink over standard output), the FORMAT (:text | :json), and the TOPIC-NAME/TYPE-NAME to subscribe on
   (default the interop names). Produced by parse-log-service-config, consumed by log-service-main."
  (domain 0 :type (integer 0 232))
  (file nil :type (or null string))
  (format :text :type keyword)
  (topic-name *log-topic-name* :type string)
  (type-name *log-type-name* :type string))

(defun* %log-env-get (env name)
    (function ((or list function) string) (or null string))
  "The value of env var NAME from ENV (an alist of (NAME . VALUE) strings, or a 1-arg function), else
   NIL. Mirrors the durability service's %env-get, so the log service reads config from an injected env
   in tests and from the real environment in production."
  (etypecase env
    (list (let ((p (assoc name env :test #'string=))) (and p (cdr p))))
    (function (funcall env name))))

(defun* %log-argv-flag (argv flag)
    (function (list string) (or null string))
  "The token following FLAG in ARGV (\"--domain\" \"7\" -> \"7\"), or NIL when FLAG is absent or has no
   following token. A plain forward scan — the log service's small fixed flag set needs no more."
  (let ((tail (member flag argv :test #'string=)))
    (and (consp tail) (consp (cdr tail)) (cadr tail))))

(defun* %log-config-value (argv env flag env-var)
    (function (list (or list function) string string) (or null string))
  "Config value with CLI > env precedence: the --FLAG value from ARGV, else ENV-VAR from ENV, else NIL."
  (or (%log-argv-flag argv flag) (%log-env-get env env-var)))

(defun* %log-parse-format (s)
    (function ((or null string)) (values (or null keyword) (or null keyword)))
  "Parse a format string to :text / :json, (values nil nil) when absent (caller defaults), or
   (values nil :bad-parameter) for an unknown value. Non-signalling (ADR 0064)."
  (cond ((null s) (values nil nil))
        ((string-equal s "text") (values :text nil))
        ((string-equal s "json") (values :json nil))
        (t (values nil :bad-parameter))))

(defun* %log-parse-domain (s)
    (function ((or null string)) (values (or null (integer 0 232)) (or null keyword)))
  "Parse a domain string to a valid DDS domain id 0..232 (DDSI-RTPS 2.5 §9.6.1.1), (values nil nil)
   when absent, or (values nil :bad-parameter) if present but not a WHOLE valid domain id. The second
   value of parse-integer (:junk-allowed) must equal the length, so \"7x\" is rejected. Non-signalling."
  (if (null s)
      (values nil nil)
      (multiple-value-bind (n pos) (parse-integer s :junk-allowed t)
        (if (and n (= pos (length s)) (<= 0 n 232))
            (values n nil)
            (values nil :bad-parameter)))))

(defun* parse-log-service-config (&key (argv '()) (env '()))
    (function (&key (:argv list) (:env (or list function)))
              (values (or null log-service-config) (or null keyword)))
  "Parse CLI ARGV + ENV into (values config NIL), or (values NIL status) on bad input — RETURNED, never
   signalled (ADR 0064; log-service-main prints usage and exits non-zero). Options (CLI > env > default):
   --domain N / DDS_LOG_DOMAIN (default 0); --file PATH / DDS_LOG_FILE (default: the console sink);
   --format text|json / DDS_LOG_FORMAT (default text)."
  (multiple-value-bind (domain d-status)
      (%log-parse-domain (%log-config-value argv env "--domain" "DDS_LOG_DOMAIN"))
    (when d-status (return-from parse-log-service-config (values nil d-status)))
    (multiple-value-bind (format f-status)
        (%log-parse-format (%log-config-value argv env "--format" "DDS_LOG_FORMAT"))
      (when f-status (return-from parse-log-service-config (values nil f-status)))
      (values (%make-log-service-config
               :domain (or domain 0)
               :file (%log-config-value argv env "--file" "DDS_LOG_FILE")
               :format (or format :text))
              nil))))

(defun* %log-service-formatter (format)
    (function (keyword) function)
  "The formatter closure for FORMAT (:json -> the JSON formatter, else the text formatter)."
  (if (eq format :json) #'format-log-event-json #'format-log-event-text))

(defun* make-service-collector (config)
    (function (log-service-config) log-collector)
  "Build the collector CONFIG describes: make-log-collector on CONFIG's domain/topic/type with ONE sink
   — a file sink (make-file-sink, which owns the file) when CONFIG has a FILE, else a console sink
   (make-stream-sink over *standard-output*) — rendered by CONFIG's formatter. Exposed so an in-process
   caller can build the same collector log-service-main runs."
  (let* ((formatter (%log-service-formatter (log-service-config-format config)))
         (sink (if (log-service-config-file config)
                   (make-file-sink (log-service-config-file config) :formatter formatter)
                   (make-stream-sink *standard-output* :formatter formatter))))
    (make-log-collector :domain (log-service-config-domain config)
                        :topic-name (log-service-config-topic-name config)
                        :type-name (log-service-config-type-name config)
                        :sinks (list sink))))

(defun* log-service-usage ()
    (function () string)
  "The log-service-main usage text (FR-LOG-7)."
  (format nil "usage: log-service-main [--domain N] [--file PATH] [--format text|json] [--help]~%~
               ~2tenv: DDS_LOG_DOMAIN, DDS_LOG_FILE, DDS_LOG_FORMAT (CLI overrides env)~%~
               ~2t--file omitted: log records are written to standard output~%"))

(defun* %log-service-help-requested-p (argv)
    (function (list) t)
  "T iff ARGV requests help (--help / -h)."
  (or (member "--help" argv :test #'string=) (member "-h" argv :test #'string=)))

(defun* %log-service-run-until-shutdown (collector seconds)
    (function (log-collector real) t)
  "Drain COLLECTOR until *log-service-shutdown-requested* (set by the signal handler) or, when SECONDS
   > 0, until SECONDS elapse (the test bound). The service main loop body."
  (let ((start (get-internal-real-time)))
    (loop until *log-service-shutdown-requested*
          do (collector-drain collector)
             (when (and (plusp seconds)
                        (>= (/ (- (get-internal-real-time) start) internal-time-units-per-second) seconds))
               (return))
             (sleep 0.05))))

(defun* log-service-main (&key argv (env '()) (block t) (seconds 0))
    (function (&key (:argv (or null list)) (:env (or list function)) (:block t) (:seconds real)) t)
  "CLI/env entrypoint for the log collector service (FR-LOG-7). ARGV defaults to
   uiop:command-line-arguments. Parses config (parse-log-service-config), builds the collector + sink
   (make-service-collector), and drains received LogEvents into the sink.
   BLOCK T (the daemon/subprocess body): installs a SIGTERM/SIGINT handler that requests shutdown, runs
   the drain loop until the signal (or SECONDS, when > 0), tears the collector down, and uiop:quit 0 —
   or, on a config error, prints usage to *error-output* and uiop:quit 1 (the exit code IS the
   ReturnCode_t; ADR 0064, nothing unwinds to the Lisp toplevel).
   BLOCK NIL (in-process callers/tests): returns (values collector NIL) — the built collector, which the
   caller drains (collector-run / collector-drain) and closes — or (values NIL status) on a config
   error, or :help on --help.
   SECONDS > 0 bounds the BLOCK-mode run (tests); 0 = until signalled."
  (let ((effective-argv (or argv (uiop:command-line-arguments))))
    (cond
      ((%log-service-help-requested-p effective-argv)
       (write-string (log-service-usage) *standard-output*)
       (finish-output *standard-output*)
       (if block (uiop:quit 0) :help))
      (t
       (multiple-value-bind (config status)
           (parse-log-service-config :argv effective-argv :env env)
         (if status
             (progn
               (format *error-output* "log-service: bad configuration (~a)~%~a"
                       status (log-service-usage))
               (finish-output *error-output*)
               (if block (uiop:quit 1) (values nil status)))
             (let ((collector (make-service-collector config)))
               (if block
                   (progn
                     (setf *log-service-shutdown-requested* nil)
                     (dds.pal:install-signal-handler
                      '(:term :int) (lambda () (setf *log-service-shutdown-requested* t)))
                     (%log-service-run-until-shutdown collector seconds)
                     (close-log-collector collector)
                     (uiop:quit 0))
                   (values collector nil)))))))))
