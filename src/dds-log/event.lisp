;;;; LogEvent — the distributed logging service wire type (ADR 0082 §3). Kept in lockstep with
;;;; interop/log/DdsLog.idl. @appendable, source-keyed on (host, process), bounded throughout.

(in-package #:net.goenninger.dds.log)

;;; Severity is the syslog numbering of RFC 5424 §6.2.1 Table 2, verbatim for 0..7, so the mapping to
;;; a UDP syslog sink (PRI = facility*8 + severity) is the identity. TRACE (8) is this stack's
;;; extension below DEBUG; RFC 5424 defines 0..7 only. Read from the RFC, cited here, never recalled.
(defconstant +severity-emerg+  0 "Emergency: system is unusable (RFC 5424 §6.2.1 Table 2).")
(defconstant +severity-alert+  1 "Alert: action must be taken immediately (RFC 5424 §6.2.1 Table 2).")
(defconstant +severity-crit+   2 "Critical: critical conditions (RFC 5424 §6.2.1 Table 2).")
(defconstant +severity-err+    3 "Error: error conditions (RFC 5424 §6.2.1 Table 2).")
(defconstant +severity-warn+   4 "Warning: warning conditions (RFC 5424 §6.2.1 Table 2).")
(defconstant +severity-notice+ 5 "Notice: normal but significant condition (RFC 5424 §6.2.1 Table 2).")
(defconstant +severity-info+   6 "Informational: informational messages (RFC 5424 §6.2.1 Table 2).")
(defconstant +severity-debug+  7 "Debug: debug-level messages (RFC 5424 §6.2.1 Table 2).")
(defconstant +severity-trace+  8
  "Trace: this stack's extension below DEBUG. RFC 5424 §6.2.1 defines 0..7 only; 8 continues the
   numbering downward so the syslog PRI mapping stays the identity for 0..7.")

;;; The severity enum: the KEYWORD is the accessor/wire interface (log-event-severity), the codec
;;; writes the int32. An unknown wire value decodes to the raw int32, never an invented keyword.
(dds.gen:define-dds-enum severity
  (:emerg 0) (:alert 1) (:crit 2) (:err 3) (:warn 4) (:notice 5) (:info 6) (:debug 7) (:trace 8))

(dds.gen:define-dds-enum event-kind
  (:message 0) (:entry 1) (:exit 2))

(dds.gen:define-dds-type log-event (:extensibility :appendable)
  (host (:string 64) :key t)
  (process :u32 :key t)
  ;; Per-source identity detected once at logger creation and stamped on every event, so a collector
  ;; renders the ORIGINATING logger's identity even for a remote source (owner directive 2026-07-23).
  ;; participant-uuid: the DDS participant's network-unique identity. make-logger stamps the 12-octet
  ;; RTPS GUID prefix (DDSI-RTPS 2.5 §8.2.4.2) as 24 lowercase hex chars; the bound is 40 so a
  ;; 36-char RFC 4122 UUID from another producer also fits (both are accepted values of this field).
  ;; host-ip: the host machine IP address, IPv4 OR IPv6 — a string bounded at 46, which is
  ;; INET6_ADDRSTRLEN: it holds IPv4 (max "255.255.255.255", 15) and the longest textual IPv6 (the
  ;; IPv4-mapped "ffff:ffff:ffff:ffff:ffff:ffff:255.255.255.255", 45). A scoped/zone address
  ;; (fe80::1%eth0) is a routing detail a host-identity field does not carry; use a routable address.
  (participant-uuid (:string 40))
  (host-ip (:string 46))
  ;; app-id: the application identity string, given at logger creation (owner directive 2026-07-24).
  ;; A wire field for the same reason as participant-uuid/host-ip — a collector renders the
  ;; ORIGINATING application even for a remote source.
  (app-id (:string 128))
  (thread :u32)
  ;; `seq`, not `sequence`: `sequence` is an IDL reserved word (the collection type), so a foreign
  ;; publisher cannot be generated from an IDL with a member named `sequence` (rtiddsgen rejects it).
  (seq :u64)
  (timestamp :i64)
  (severity (:enum severity))
  (category (:string 16))
  (function (:string 128))
  (file (:string 256))
  (line :u32)
  (event-kind (:enum event-kind))
  (elapsed-ns :u64)
  (truncated :bool)
  (message (:string 1024)))

(defun* truncate-utf8 (string max-octets)
    (function (string (integer 0)) (values string t))
  "Truncate STRING to at most MAX-OCTETS UTF-8 octets on a CODEPOINT boundary (never mid-character,
   RFC 3629 §3), returning (values result truncated-p). The per-character octet width is derived from
   the code point — <U+0080 = 1, <U+0800 = 2, <U+10000 = 3, else 4 — so the result is always
   well-formed UTF-8 and its octet length is <= MAX-OCTETS. A logging call truncates rather than
   fails, so a runaway string never blocks a log."
  (if (<= (dds.cdr:utf8-octet-length string) max-octets)
      (values string nil)
      (let ((octets 0) (end 0))
        (declare (type (integer 0) octets end))
        (dotimes (i (length string))
          (let* ((cp (char-code (char string i)))
                 (n (cond ((< cp #x80) 1) ((< cp #x800) 2) ((< cp #x10000) 3) (t 4))))
            (when (> (+ octets n) max-octets) (return))
            (incf octets n)
            (setf end (1+ i))))
        (values (subseq string 0 end) t))))

(defun* build-log-event (&key (host "") (process 0) (participant-uuid "") (host-ip "") (app-id "")
                              (thread 0) (seq 0) (timestamp 0)
                              (severity :info) (category "") (function "") (file "") (line 0)
                              (event-kind :message) (elapsed-ns 0) (message ""))
    (function (&key (:host string) (:process (unsigned-byte 32)) (:participant-uuid string)
                    (:host-ip string) (:app-id string) (:thread (unsigned-byte 32))
                    (:seq (unsigned-byte 64)) (:timestamp (signed-byte 64)) (:severity keyword)
                    (:category string) (:function string) (:file string) (:line (unsigned-byte 32))
                    (:event-kind keyword) (:elapsed-ns (unsigned-byte 64)) (:message string))
              log-event)
  "Construct a LOG-EVENT, TRUNCATING each bounded string to its octet bound rather than refusing it —
   a logging call must never fail because a value is long. `truncated` is set T iff MESSAGE was
   truncated (the IDL semantics: 'message exceeded its bound'); the other bounded fields (host,
   participant-uuid, host-ip, app-id, category, function, file) truncate silently. All truncation is
   on a UTF-8 codepoint boundary (truncate-utf8). PARTICIPANT-UUID, HOST-IP and APP-ID are the
   per-source identity the logger detects/receives once at creation and passes on every call (owner
   directives 2026-07-23/24)."
  (multiple-value-bind (msg msg-truncated) (truncate-utf8 message +log-event-message-bound+)
    (make-log-event
     :host (values (truncate-utf8 host +log-event-host-bound+))
     :process process
     :participant-uuid (values (truncate-utf8 participant-uuid +log-event-participant-uuid-bound+))
     :host-ip (values (truncate-utf8 host-ip +log-event-host-ip-bound+))
     :app-id (values (truncate-utf8 app-id +log-event-app-id-bound+))
     :thread thread :seq seq :timestamp timestamp
     :severity severity
     :category (values (truncate-utf8 category +log-event-category-bound+))
     :function (values (truncate-utf8 function +log-event-function-bound+))
     :file (values (truncate-utf8 file +log-event-file-bound+))
     :line line :event-kind event-kind :elapsed-ns elapsed-ns
     :truncated msg-truncated :message msg)))
