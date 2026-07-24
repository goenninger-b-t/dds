;;;; Multi-service-runner test (ADR 0082 §6/§7, FR-LOG-7). Runs TWO log collectors concurrently under one
;;;; runner — one on domain D, one on D+1, each fed by its own async logger — and asserts each collector
;;;; drains ONLY its own domain's events (concurrent operation + per-domain isolation), then that
;;;; log-runner-stop joins all drain threads and closes the collectors cleanly (no thread leak).
(in-package #:dds.tests)

(defun* run-log-runner-test ()
    (function () t)
  "Test: the FR-LOG-7 multi-service runner — N collectors, one process, clean lifecycle."
  (let* ((d1 (test-domain +td-log-runner+))
         (d2 (1+ d1))
         (cap1 '()) (cap2 '())
         (c1 (dds.log:make-log-collector
              :domain d1 :sinks (list (dds.log:make-function-sink
                                       (lambda (e) (push (dds.log:log-event-message e) cap1))))))
         (c2 (dds.log:make-log-collector
              :domain d2 :sinks (list (dds.log:make-function-sink
                                       (lambda (e) (push (dds.log:log-event-message e) cap2))))))
         (runner (dds.log:make-log-service-runner (list c1 c2)))
         (lg1 (dds.log:make-logger :domain d1 :app-id "gbttctools" :async t))
         (lg2 (dds.log:make-logger :domain d2 :app-id "gbttctools" :async t)))
    (unwind-protect
         (progn
           (dds.log:log-runner-start runner)   ; a drain thread per collector; loggers' workers drive the pub side
           (dds.log:logger-emit lg1 :severity :notice :category "SUP" :message "from-one")
           (dds.log:logger-emit lg2 :severity :notice :category "SUP" :message "from-two")
           ;; both collectors run in their own threads; wait until each has its own event.
           (loop repeat 500
                 until (and (member "from-one" cap1 :test #'string=)
                            (member "from-two" cap2 :test #'string=))
                 do (sleep 0.02))
           (%check :runner-c1-got-own (member "from-one" cap1 :test #'string=)
                   (format nil "collector 1 (domain ~d) must receive its logger's event; cap1=~s" d1 cap1))
           (%check :runner-c2-got-own (member "from-two" cap2 :test #'string=)
                   (format nil "collector 2 (domain ~d) must receive its logger's event; cap2=~s" d2 cap2))
           (%check :runner-isolation
                   (and (not (member "from-two" cap1 :test #'string=))
                        (not (member "from-one" cap2 :test #'string=)))
                   (format nil "each collector must drain ONLY its own domain (cap1=~s cap2=~s)" cap1 cap2)))
      (dds.log:close-logger lg1)
      (dds.log:close-logger lg2)
      (dds.log:log-runner-stop runner)))   ; joins both drain threads + closes both collectors
  t)
