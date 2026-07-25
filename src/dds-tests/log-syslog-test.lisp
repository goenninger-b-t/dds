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
         ;; PAL-STATIC, not a GC-heap array (NFR-MEM): udp-recv hands the kernel a raw pointer, so a heap
         ;; buffer the GC may relocate means recvfrom(2) writes a datagram over unrelated live objects.
         ;; udp-recv now REFUSES the raw path for a non-static buffer, so a heap array here would silently
         ;; stop exercising the production recvfrom path as well as being wrong.
         (buf (dds.pal:alloc-static 2048))
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
      (dds.pal:join thread)
      (dds.pal:free-static buf)))   ; after the join — the receiver thread is the only other user
  t)

(defun* run-log-http-test ()
    (function () t)
  "Test (ADR 0082 §7, FR-LOG-8): make-http-bulk-sink batches events and POSTs them as one HTTP/1.1
   request. A loopback TCP server thread accepts the connection and reads the request until the sink
   closes (EOF); the received bytes must be a well-formed bulk POST carrying both records."
  (let* ((listener (dds.pal:tcp-listen "127.0.0.1" 0))
         (port (dds.pal:tcp-local-port listener))
         (got nil)
         (server (dds.pal:spawn
                  (lambda ()
                    (multiple-value-bind (conn cstatus) (dds.pal:tcp-accept listener)
                      (unless cstatus
                        ;; tcp-recv reads EXACTLY len bytes (length-prefixed framing) — HTTP has no
                        ;; upfront length, so read one byte at a time until the sink closes (EOF).
                        (let ((acc (make-array 0 :element-type '(unsigned-byte 8) :adjustable t :fill-pointer 0))
                              (b (make-array 1 :element-type '(unsigned-byte 8))))
                          (loop
                            (multiple-value-bind (size status) (dds.pal:tcp-recv conn b 1)
                              (when (or status (null size)) (return))   ; EOF / timeout -> request complete
                              (vector-push-extend (aref b 0) acc)))
                          (setf got acc)
                          (dds.pal:tcp-close conn)))))
                  :name "http-server")))
    (unwind-protect
         (let ((sink (dds.log:make-http-bulk-sink "127.0.0.1" port "/ingest" :batch-size 2)))
           (dds.log:sink-emit sink (dds.log:build-log-event :severity :info :message "http-one"))
           (dds.log:sink-emit sink (dds.log:build-log-event :severity :info :message "http-two"))  ; batch full -> POST
           (loop repeat 400 until got do (sleep 0.01))
           (dds.log:close-sink sink)
           (%check :http-post
                   (let ((s (and got (map 'string #'code-char got))))
                     (and s (eql 0 (search "POST /ingest HTTP/1.1" s))
                          (search "Content-Type: application/x-ndjson" s)
                          (search "Content-Length: " s)
                          (search "http-one" s) (search "http-two" s)))
                   (format nil "the bulk sink must POST both records; got ~a bytes"
                           (and got (length got)))))
      (dds.pal:tcp-close listener)   ; unblock a still-waiting accept so the server thread exits
      (dds.pal:join server)))
  t)
