;;;; Log-service entrypoint test (ADR 0082 §6/§7, FR-LOG-7). Two parts: (a) parse-log-service-config —
;;;; CLI > env > default precedence, and bad input RETURNED as a status (never signalled, ADR 0064);
;;;; (b) log-service-main :block nil builds a collector whose file sink drains a logger's LogEvents —
;;;; the service run in-process, proving the CLI entrypoint collects end to end.
(in-package #:dds.tests)

(defun* run-log-service-test ()
    (function () t)
  "Test: the runnable log service (ADR 0082 §6/§7, FR-LOG-7) — config parsing + the collector it builds."
  ;; ---- (a) config parsing: precedence + defaults + returned-status on bad input ----
  (multiple-value-bind (cfg status)
      (dds.log:parse-log-service-config :argv '("--domain" "7" "--format" "json" "--file" "/tmp/x.log"))
    (%check :logsvc-argv
            (and (null status) cfg
                 (= (dds.log:log-service-config-domain cfg) 7)
                 (eq (dds.log:log-service-config-format cfg) :json)
                 (string= (dds.log:log-service-config-file cfg) "/tmp/x.log"))
            (format nil "argv config must parse; got status ~s cfg ~s" status cfg)))
  (multiple-value-bind (cfg status)
      (dds.log:parse-log-service-config :env '(("DDS_LOG_DOMAIN" . "5") ("DDS_LOG_FORMAT" . "text")))
    (%check :logsvc-env
            (and (null status) cfg (= (dds.log:log-service-config-domain cfg) 5)
                 (eq (dds.log:log-service-config-format cfg) :text)
                 (null (dds.log:log-service-config-file cfg)))
            (format nil "env config must parse (file default NIL = console); got ~s ~s" status cfg)))
  (multiple-value-bind (cfg status)
      (dds.log:parse-log-service-config :argv '("--domain" "7")
                                        :env '(("DDS_LOG_DOMAIN" . "5")))
    (%check :logsvc-precedence (and (null status) (= (dds.log:log-service-config-domain cfg) 7))
            "CLI --domain must override env DDS_LOG_DOMAIN"))
  (multiple-value-bind (cfg status) (dds.log:parse-log-service-config)
    (%check :logsvc-defaults
            (and (null status) (= (dds.log:log-service-config-domain cfg) 0)
                 (eq (dds.log:log-service-config-format cfg) :text)
                 (null (dds.log:log-service-config-file cfg)))
            "no config -> domain 0, text, console"))
  (%check :logsvc-bad-domain
          (eq :bad-parameter (nth-value 1 (dds.log:parse-log-service-config :argv '("--domain" "abc"))))
          "a non-numeric --domain must RETURN :bad-parameter, not signal")
  (%check :logsvc-junk-domain
          (eq :bad-parameter (nth-value 1 (dds.log:parse-log-service-config :argv '("--domain" "7x"))))
          "a partly-numeric --domain (7x) must be rejected")
  (%check :logsvc-bad-format
          (eq :bad-parameter (nth-value 1 (dds.log:parse-log-service-config :argv '("--format" "xml"))))
          "an unknown --format must RETURN :bad-parameter")
  (%check :logsvc-help (eq :help (dds.log:log-service-main :argv '("--help") :block nil))
          "--help (block nil) must return :help")
  ;; ---- (b) log-service-main :block nil builds a collector; a logger feeds it; the file sink records ----
  (let* ((domain (test-domain +td-log-service+))
         (path (%log-temp-path "service"))
         (logger (dds.log:make-logger :domain domain :app-id "gbttctools")))
    (unwind-protect
         (multiple-value-bind (collector status)
             (dds.log:log-service-main :block nil
                                       :argv (list "--domain" (format nil "~d" domain)
                                                   "--file" (namestring path) "--format" "text"))
           (%check :logsvc-built (and (null status) collector) "log-service-main :block nil must build a collector")
           (unwind-protect
                (progn
                  (loop repeat 400
                        until (and (plusp (dds.dcps:matched-count (dds.log::logger-participant logger)))
                                   (plusp (dds.dcps:matched-count (dds.log::log-collector-participant collector))))
                        do (dds.log:logger-spin logger) (dds.log:collector-drain collector) (sleep 0.02))
                  (dds.log:logger-emit logger :severity :notice :category "SUP" :message "service line one")
                  (dds.log:logger-emit logger :severity :crit :category "MEM" :message "service line two")
                  (loop repeat 400 until (>= (dds.log:log-collector-received collector) 2)
                        do (dds.log:logger-spin logger) (dds.log:collector-drain collector) (sleep 0.02))
                  (%check :logsvc-received (>= (dds.log:log-collector-received collector) 2)
                          (format nil "the service collector must receive both events; got ~d"
                                  (dds.log:log-collector-received collector))))
             (dds.log:close-log-collector collector))   ; closes the file sink -> flushes + closes the file
           ;; the file the service wrote must hold both records.
           (let ((lines (with-open-file (in path :external-format :utf-8 :if-does-not-exist nil)
                          (when in (loop for l = (read-line in nil nil) while l collect l)))))
             (%check :logsvc-file
                     (and lines (>= (length lines) 2)
                          (find-if (lambda (l) (search "service line one" l)) lines)
                          (find-if (lambda (l) (search "service line two" l)) lines))
                     (format nil "the service's file sink must record both events; got ~s" lines))))
      (dds.log:close-logger logger)
      (ignore-errors (delete-file path))))
  t)
