;;;; LogEvent cross-DDS interop subscriber — NeoDDS reader side (ADR 0082 §3, FR-IO).
;;;;
;;;; A committed replacement for the earlier scratch runner: loads :dds-log and subscribes with a
;;;; make-log-collector on topic "DdsLog" / type "dds::log::LogEvent" (the interop names), printing every
;;;; decoded LogEvent. The SIGNAL IS THE SAMPLE COUNT: to receive reliable user DATA the reader must be
;;;; matched to the foreign writer, so samples>0 proves the @appendable LogEvent decoded end to end
;;;; across the vendor boundary. Drives both legs (Connext log_pub, Fast DDS log_pub).
;;;;
;;;; Run (Connext):   NDDSHOME=... ./log_pub 0 80   then
;;;;   ./scripts/with-sbcl.sh --load interop/log/log_sub.lisp
;;;; Run (Fast DDS):  ./scripts/with-fastdds.sh bash -c '(cd interop/fastdds/log && ./log_pub 0 80)' then
;;;;   ./scripts/with-sbcl.sh --load interop/log/log_sub.lisp
(asdf:load-system :dds-log)
(in-package :dds.log)

(defun run-log-sub (&key (domain 0) (seconds 30) (advertise-address "127.0.0.1")
                         (peers "127.0.0.1:7410,127.0.0.1:7412,127.0.0.1:7414,127.0.0.1:7416"))
  ;; A loopback-pinned Fast DDS peer (interfaceWhiteList 127.0.0.1) is not reachable by multicast here,
  ;; so discover it by UNICAST SPDP to its metatraffic ports (domain 0 participant 0..3 = 7410/12/14/16).
  ;; make-log-collector has no :peers, so create the participant with peers and BORROW it via :participant.
  (let* ((seen 0)
         (participant (dds.dcps:create-participant :domain domain :advertise-address advertise-address
                                                   :peers (dds.disc:parse-peers peers)))
         (sink (make-function-sink
                (lambda (e)
                  (incf seen)
                  (format t "~&[log-sub] #~d ~a~%" seen (format-log-event-text e))
                  (format t "~&           host=~s pid=~d uuid=~s ip=~s appid=~s seq=~d sev=~a cat=~s ek=~a trunc=~a~%"
                          (log-event-host e) (log-event-process e) (log-event-participant-uuid e)
                          (log-event-host-ip e) (log-event-app-id e) (log-event-seq e)
                          (log-event-severity e) (log-event-category e) (log-event-event-kind e)
                          (log-event-truncated e)))))
         (collector (make-log-collector :participant participant :sinks (list sink))))
    (setf dds.dcps:*type-compat-log* *standard-output*)
    (format t "~&[log-sub] DdsLog/dds::log::LogEvent domain=~d advertise=~a — waiting for a foreign @appendable writer.~%"
            domain advertise-address)
    (let ((start (get-internal-real-time))
          (p (log-collector-participant collector))
          (last-d -1) (last-m -1))
      (loop
        (collector-drain collector)
        (let ((d (dds.dcps:discovered-count p)) (m (dds.dcps:matched-count p)))
          (when (or (/= d last-d) (/= m last-m))
            (format t "~&[log-sub] discovered=~d matched=~d~%" d m)
            (setf last-d d last-m m)))
        (when (> (/ (- (get-internal-real-time) start) internal-time-units-per-second) seconds)
          (return))
        (sleep 0.05)))
    (format t "~&[log-sub] DONE. samples=~d.~%" seen)
    (format t "~&[log-sub] VERDICT: ~:[NO DATA — our reader received nothing from the foreign LogEvent writer~;INTEROPERATES — the foreign @appendable dds::log::LogEvent writer matched our reader; every field decoded~]~%"
            (plusp seen))
    (close-log-collector collector)
    (dds.dcps:delete-participant participant)))   ; borrowed -> close-log-collector didn't delete it

(run-log-sub :domain 0 :seconds (or (ignore-errors (parse-integer (uiop:getenv "SECONDS"))) 30)
             :advertise-address (or (uiop:getenv "ADVERTISE") "127.0.0.1"))
(uiop:quit 0)
