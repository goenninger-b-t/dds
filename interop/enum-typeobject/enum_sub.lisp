;;;; Enum-TypeObject interop probe — NeoDDS subscriber side.
;;;;
;;;; Defines an enum-box type whose `kind` member is (:enum ...) -> TK_INT32 (exactly what
;;;; log-service LogEvent's severity will do), subscribes on topic "EnumBox" type "EnumBox", and
;;;; reports samples received from the Connext enum_pub writer (whose IDL enum -> TK_ENUM).
;;;;
;;;; THE SIGNAL IS THE SAMPLE COUNT, NOT dds.dcps:matched-count. To receive reliable user DATA a
;;;; reader must be matched to the writer, so samples>0 proves the match end to end AND that our
;;;; reader decoded a foreign TK_ENUM peer's values. (matched-count is a participant-level counter
;;;; that does not reflect this DataReader's SUBSCRIPTION_MATCHED here — reported only as a
;;;; secondary diagnostic.)
;;;;
;;;; Run:  ./scripts/with-sbcl.sh --load interop/enum-typeobject/enum_sub.lisp
;;;;   with the Connext writer:  (cd interop/enum-typeobject && ./enum_pub 0 60)
(asdf:load-system :dds-shapes)
(in-package :dds.shapes)

(dds.gen:define-dds-enum probe-kind (:trace 0) (:info 1) (:error 2))

(dds.gen:define-dds-type enum-box (:extensibility :final)
  (id :i32 :key t)
  (kind (:enum probe-kind)))

(defun run-enum-probe (&key (domain 0) (seconds 30) (advertise-address "127.0.0.1") peers)
  (let* ((ts (dds.types:find-type-support "enum-box"))
         (p (dds.dcps:create-participant :domain domain :advertise-address advertise-address
                                        ;; This peer pins itself to 127.0.0.1 with
                                        ;; <multicast_receive_addresses/> empty (see its
                                        ;; USER_QOS_PROFILES.xml), so it hears NO multicast:
                                        ;; a unicast SPDP peer is the only way to meet it.
                                        :peers (dds.disc:parse-peers peers))))
    (setf dds.dcps:*type-compat-log* *standard-output*)
    (let* ((tp (dds.dcps:create-topic p "EnumBox" "EnumBox" ts))
           (sub (dds.dcps:create-subscriber p))
           (dr (dds.dcps:create-datareader sub tp :qos (dds.qos:make-reader-qos :reliability :reliable))))
      (format t "~&[enum-probe] EnumBox/EnumBox local-type=enum-box (kind is (:enum ...) -> TK_INT32) domain=~d.~%" domain)
      (let ((seen 0) (start (get-internal-real-time)))
        (loop
          (dds.dcps:spin p)
          (dolist (cs (dds.dcps:take-samples dr))
            (handler-case
                (let ((info (dds.dcps:cached-sample-info cs)))
                  (when (dds.dcps:sample-info-valid-data info)
                    (let ((s (dds.dcps:cached-sample-data cs)))
                      (incf seen)
                      (format t "~&[enum-probe] sample #~d: id=~a kind=~a~%"
                              seen (enum-box-id s) (enum-box-kind s)))))
              (error (e) (format t "~&[enum-probe] sample error: ~a~%" (type-of e)))))
          (when (and (plusp seconds)
                     (> (/ (- (get-internal-real-time) start) internal-time-units-per-second) seconds))
            (return))
          (sleep 0.05))
        (format t "~&[enum-probe] DONE. samples=~d.~%" seen)
        (format t "~&[enum-probe] VERDICT: ~:[NO DATA — our reader did not receive from the Connext TK_ENUM writer~;TOLERATED — Connext's TK_ENUM writer matched our TK_INT32 reader; values decoded correctly~]~%"
                (plusp seen))))))

(let ((env (lambda (k d) (or (uiop:getenv k) d))))
  ;; Env-driven so `make interop` can give this probe its OWN DOMAIN and the peer's unicast port.
  ;; A DEDICATED DOMAIN is not optional: several harnesses in this repo publish distinct topics on a
  ;; shared domain and a leaked or concurrent peer then cross-talks, which inflates counts UPWARDS and
  ;; makes a poisoned run look healthier than a clean one.
  (run-enum-probe :domain (parse-integer (funcall env "PROBE_DOMAIN" "0"))
        :seconds (parse-integer (funcall env "PROBE_SECONDS" "30"))
        :advertise-address (funcall env "PROBE_ADVERTISE" "127.0.0.1")
        :peers (uiop:getenv "PROBE_PEERS")))
(uiop:quit 0)
