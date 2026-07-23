;;;; LogEvent type tests (ADR 0082 §3, log-service Task 4). Round-trip every field through the
;;;; generated codec; over-bound message truncates with the flag set; severity = RFC 5424 §6.2.1.
(in-package #:dds.tests)

(defun* run-log-event-test ()
    (function () t)
  "Test: the LogEvent wire type (ADR 0082 §3). (1) the severity constants equal RFC 5424 §6.2.1;
   (2) every field round-trips through the generated @appendable codec; (3) a message longer than
   its 1024-octet bound is TRUNCATED with `truncated` set T — not refused, not silently cut — on a
   UTF-8 codepoint boundary."
  ;; 1. severity constants are the RFC 5424 §6.2.1 syslog values (+ TRACE=8 extension).
  (%check :log-sev-consts
          (and (= dds.log:+severity-emerg+ 0) (= dds.log:+severity-alert+ 1)
               (= dds.log:+severity-crit+ 2) (= dds.log:+severity-err+ 3)
               (= dds.log:+severity-warn+ 4) (= dds.log:+severity-notice+ 5)
               (= dds.log:+severity-info+ 6) (= dds.log:+severity-debug+ 7)
               (= dds.log:+severity-trace+ 8))
          "severity constants must equal RFC 5424 §6.2.1 Table 2 values (0..7) + TRACE=8")
  ;; 2. every field round-trips through the generated @appendable serialize/deserialize.
  (let* ((arena (dds.core.arena:init-arena :bytes (* 128 1024)))
         (pool (dds.core.arena:make-buffer-pool arena 2048 2))
         (e (dds.log:build-log-event :host "node-1" :process 4242
                                     :participant-uuid "8b619879-4ffe-4fca-ad01-05b39d987dbc"
                                     :host-ip "192.168.2.148" :thread 7 :seq 99
                                     :timestamp -123456789 :severity :crit :category "MEM"
                                     :function "gbt_init()" :file "src/core.c" :line 1234
                                     :event-kind :exit :elapsed-ns 12000 :message "hello")))
    (let* ((b (dds.core.arena:pool-acquire pool))
           (wc (dds.core.buffer:cursor b :endianness :little)))
      (dds.log:serialize-log-event e wc :xcdr2)
      (%check :log-size (= (dds.core.buffer:cursor-position wc)
                           (dds.log:serialized-size-log-event e :xcdr2))
              "serialized-size must equal the bytes written (DHEADER included)")
      (let* ((rc (dds.core.buffer:cursor b :endianness :little))
             (q (dds.log:deserialize-log-event rc :xcdr2)))
        (%check :log-roundtrip
                (and (string= (dds.log:log-event-host q) "node-1")
                     (= (dds.log:log-event-process q) 4242)
                     (string= (dds.log:log-event-participant-uuid q) "8b619879-4ffe-4fca-ad01-05b39d987dbc")
                     (string= (dds.log:log-event-host-ip q) "192.168.2.148")
                     (= (dds.log:log-event-thread q) 7)
                     (= (dds.log:log-event-seq q) 99)
                     (= (dds.log:log-event-timestamp q) -123456789)
                     (eq (dds.log:log-event-severity q) :crit)
                     (string= (dds.log:log-event-category q) "MEM")
                     (string= (dds.log:log-event-function q) "gbt_init()")
                     (string= (dds.log:log-event-file q) "src/core.c")
                     (= (dds.log:log-event-line q) 1234)
                     (eq (dds.log:log-event-event-kind q) :exit)
                     (= (dds.log:log-event-elapsed-ns q) 12000)
                     (null (dds.log:log-event-truncated q))
                     (string= (dds.log:log-event-message q) "hello"))
                "every LogEvent field must round-trip through the generated codec"))
      (dds.core.arena:pool-release pool b))
    (dds.core.arena:teardown-arena arena))
  ;; 3. a message over the 1024-octet bound is TRUNCATED with the flag, not refused, not empty.
  (let* ((long (make-string 2000 :initial-element #\x))
         (e (dds.log:build-log-event :message long)))
    (%check :log-truncated-flag (eq t (dds.log:log-event-truncated e))
            "an over-bound message must set truncated=T")
    (%check :log-truncated-bound (<= (dds.cdr:utf8-octet-length (dds.log:log-event-message e))
                                     dds.log:+log-event-message-bound+)
            "the truncated message must fit the octet bound")
    (%check :log-truncated-kept (= 1024 (length (dds.log:log-event-message e)))
            "2000 ASCII chars truncate to exactly 1024 (not refused, not silently emptied)"))
  ;; 4. truncation stops on a UTF-8 codepoint boundary, never mid-character.
  (multiple-value-bind (s trunc)
      (dds.log:truncate-utf8 (make-string 10 :initial-element (code-char #xE9)) 5)
    ;; each U+00E9 is 2 octets; 5 octets admits 2 chars (4 octets); a 3rd would reach 6 > 5.
    (%check :log-truncate-codepoint
            (and trunc (= 2 (length s)) (= 4 (dds.cdr:utf8-octet-length s)))
            "truncation must stop on a codepoint boundary (2 two-octet chars = 4 <= 5, never 5)"))
  t)
