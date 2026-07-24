;;;; Logging-service pipeline test (ADR 0082 §5/§6, log-service emit slice). Two parts:
;;;;  A. the file sink in isolation (no DDS): emit events through make-file-sink, reopen the file,
;;;;     assert one formatted record per line.
;;;;  B. the full end-to-end pipeline: make-logger -> DDS -> make-log-collector -> sink, in-process on
;;;;     an isolated domain, asserting the identity make-logger DETECTED (participant_uuid from the GUID
;;;;     prefix, host_ip, app_id) survives the wire and appears in the collector-rendered line.
(in-package #:dds.tests)

(defun* %log-temp-path (tag)
    (function (string) t)
  "A process-unique temp file path under the system temp dir, named with TAG + the pid — so a
   parallel test process never collides, and unwind-protect can delete it."
  (merge-pathnames (format nil "dds-log-~a-~d.log" tag (dds.pal:process-id))
                   (uiop:temporary-directory)))

(defun* run-log-pipeline-test ()
    (function () t)
  "Test: the logging-service emit pipeline (ADR 0082 §5/§6). Part A drives make-file-sink directly and
   reads the file back (one formatted record per line, newline-delimited). Part B runs the full
   in-process pipeline — make-logger publishes LogEvents that make-log-collector drains into an
   in-memory sink — and asserts the per-source identity make-logger DETECTED once at creation
   (participant_uuid = 24-hex GUID prefix, the given host_ip and app_id) is stamped on every event and
   survives the @appendable wire round-trip into the collector-rendered text line."
  ;; ---- Part A: the file sink, in isolation (no DDS) ----
  (let ((path (%log-temp-path "filesink")))
    (unwind-protect
         (let ((sink (dds.log:make-file-sink path :if-exists :supersede)))
           (dds.log:sink-emit sink (dds.log:build-log-event :severity :info :category "A"
                                                            :function "f" :message "first line"))
           (dds.log:sink-emit sink (dds.log:build-log-event :severity :crit :category "B"
                                                            :function "g" :message "second line"))
           (dds.log:close-sink sink)
           (let ((lines (with-open-file (in path :external-format :utf-8)
                          (loop for l = (read-line in nil nil) while l collect l))))
             (%check :logpipe-file-count (= 2 (length lines))
                     (format nil "file sink must write one record per event; got ~d line(s)" (length lines)))
             (%check :logpipe-file-content
                     (and (search "first line" (first lines)) (search "INFO" (first lines))
                          (search "second line" (second lines)) (search "CRIT" (second lines)))
                     (format nil "file sink records must carry the formatted events; got ~s" lines))))
      (ignore-errors (delete-file path))))
  ;; ---- Part B: the full in-process logger -> DDS -> collector -> sink pipeline ----
  (let* ((domain (test-domain +td-log-pipeline+))
         (captured '())
         (sink (dds.log:make-function-sink
                (lambda (event) (push (dds.log:format-log-event-text event) captured))))
         (logger (dds.log:make-logger :domain domain :app-id "gbttctools" :host-ip "192.168.2.148"))
         (collector (dds.log:make-log-collector :domain domain :sinks (list sink))))
    (unwind-protect
         (progn
           ;; identity is DETECTED at creation: participant_uuid = 24 hex chars, host_ip/app_id as given.
           (%check :logpipe-uuid-detected
                   (and (= 24 (length (dds.log:logger-participant-uuid logger)))
                        (every (lambda (c) (digit-char-p c 16)) (dds.log:logger-participant-uuid logger)))
                   (format nil "participant_uuid must be 24 hex chars from the GUID prefix; got ~s"
                           (dds.log:logger-participant-uuid logger)))
           (%check :logpipe-identity-given
                   (and (string= (dds.log:logger-host-ip logger) "192.168.2.148")
                        (string= (dds.log:logger-app-id logger) "gbttctools"))
                   "host_ip and app_id must be the values given to make-logger")
           ;; discovery: pump both participants until the writer<->reader match forms.
           (loop repeat 400
                 until (and (plusp (dds.dcps:matched-count (dds.log::logger-participant logger)))
                            (plusp (dds.dcps:matched-count (dds.log::log-collector-participant collector))))
                 do (dds.log:logger-spin logger) (dds.log:collector-drain collector) (sleep 0.02))
           (%check :logpipe-matched
                   (and (plusp (dds.dcps:matched-count (dds.log::logger-participant logger)))
                        (plusp (dds.dcps:matched-count (dds.log::log-collector-participant collector))))
                   "logger writer and collector reader must match in-process")
           ;; emit three events AFTER the match (reliable delivery covers post-match samples).
           (dds.log:logger-emit logger :severity :notice :category "SUP" :function "gbt_sup_log"
                                       :message "supervisor up with 2 children")
           (dds.log:logger-emit logger :severity :crit :category "MEM" :function "gbt_mem_init"
                                       :message "Segmentation Fault encountered")
           (dds.log:logger-emit logger :severity :warn :category "DISK" :function "gbt_disk"
                                       :message "disk 90%")
           ;; drain until all three arrive (reliable, so they will) or the safety bound elapses.
           (loop repeat 400
                 until (>= (dds.log:log-collector-received collector) 3)
                 do (dds.log:logger-spin logger) (dds.log:collector-drain collector) (sleep 0.02))
           (%check :logpipe-received (>= (dds.log:log-collector-received collector) 3)
                   (format nil "collector must receive all 3 emitted events; got ~d"
                           (dds.log:log-collector-received collector)))
           ;; the identity + message survived the wire into the collector-rendered line.
           (let ((sup-line (find-if (lambda (l) (search "supervisor up with 2 children" l)) captured)))
             (%check :logpipe-identity-on-wire
                     (and sup-line
                          (search (dds.log:logger-participant-uuid logger) sup-line)
                          (search "192.168.2.148" sup-line)
                          (search "gbttctools" sup-line)
                          (search "NOTICE" sup-line))
                     (format nil "the received line must carry the detected identity + severity; got ~s"
                             sup-line))))
      (dds.log:close-logger logger)
      (dds.log:close-log-collector collector)))
  t)
