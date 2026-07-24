;;;; RFC 5424 UDP-syslog sink test (ADR 0082 §7, FR-LOG-8). Two parts: (a) format-log-event-syslog —
;;;; the RFC 5424 §6 wire shape (<PRI>1 TIMESTAMP HOSTNAME APP-NAME PROCID MSGID SD MSG), PRI = facility*8
;;;; + severity clamped 0..7, NILVALUE '-' for empty fields; (b) make-udp-syslog-sink actually SENDS the
;;;; datagram — a receiver thread on a loopback socket gets the exact UTF-8 octets the sink emitted.
(in-package #:dds.tests)

(defun* run-log-syslog-test ()
    (function () t)
  "Test: the RFC 5424 UDP-syslog formatter + sink (ADR 0082 §7, FR-LOG-8)."
  ;; ---- (a) format-log-event-syslog: RFC 5424 §6 shape + PRI + NILVALUE ----
  (let ((crit (dds.log:format-log-event-syslog
               (dds.log:build-log-event :severity :crit :host "node-1" :app-id "gbttctools"
                                        :process 42 :category "MEM" :function "gbt_mem"
                                        :file "src.c" :line 12 :message "out of memory")
               :facility 1)))
    (%check :syslog-pri
            (and (eql 0 (search "<10>1 " crit))       ; facility 1 * 8 + CRIT(2) = 10, VERSION 1
                 (search " node-1 gbttctools 42 MEM - " crit)   ; HOSTNAME APP-NAME PROCID MSGID SD(-)
                 (search "gbt_mem() - src.c:12 out of memory" crit))
            (format nil "RFC 5424 CRIT line wrong; got ~s" crit)))
  (%check :syslog-trace-clamp
          (eql 0 (search "<15>1 "   ; facility 1 * 8 + min(7,TRACE=8) = 15 (no PRI value 8 exists)
                         (dds.log:format-log-event-syslog
                          (dds.log:build-log-event :severity :trace :message "t") :facility 1)))
          "TRACE severity must clamp to 7 in the PRI (facility 1 -> <15>)")
  (%check :syslog-nilvalue
          (search " - - 0 - - " (dds.log:format-log-event-syslog   ; empty host/app/category/function
                                  (dds.log:build-log-event :severity :info) :facility 1))
          "empty HEADER fields must render as the RFC 5424 NILVALUE '-'")
  ;; ---- (b) make-udp-syslog-sink SENDS the datagram (loopback receiver thread) ----
  (let* ((rx (dds.pal:udp-open :port 0))
         (port (dds.pal:udp-local-port rx))
         (buf (make-array 2048 :element-type '(unsigned-byte 8)))
         (got nil)
         (thread (dds.pal:spawn
                  (lambda ()
                    (multiple-value-bind (size status) (dds.pal:udp-recv rx buf 2048)
                      (when (and (null status) (plusp size)) (setf got (subseq buf 0 size)))))
                  :name "syslog-rx")))
    (unwind-protect
         (let* ((event (dds.log:build-log-event :severity :warn :host "node-1" :app-id "gbttctools"
                                                :category "DISK" :message "disk 90%"))
                (expect (dds.cdr:string-to-utf8-octets
                         (dds.log:format-log-event-syslog event :facility 1)))
                (sink (dds.log:make-udp-syslog-sink "127.0.0.1" port :facility 1)))
           (dds.log:sink-emit sink event)
           (loop repeat 300 until got do (sleep 0.01))
           (dds.log:close-sink sink)
           (%check :syslog-datagram
                   (and got (equalp got expect))
                   (format nil "the sink must send the exact RFC 5424 UTF-8 datagram; got ~a bytes"
                           (and got (length got)))))
      (dds.pal:udp-close rx)   ; unblocks a still-waiting recv (status :closed) so the thread exits
      (dds.pal:join thread)))
  t)
