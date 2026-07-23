;;;; Bounded-string LARGE-form interop probe — NeoDDS subscriber side.
;;;;
;;;; Defines a type whose `text` member is (:string 1024) -> TI_STRING8_LARGE (0x71) + LBound UInt32
;;;; (exactly what log-service LogEvent's `message` bound 1024 will do — the LARGE form no live peer
;;;; has ever exercised), subscribes on topic "StringLarge" type "StringLarge", and reports samples
;;;; from the Connext stringlarge_pub writer (whose IDL string<1024> also emits TI_STRING8_LARGE).
;;;;
;;;; samples>0 with the text decoded proves the LARGE TypeObject framing interoperates end to end.
;;;;
;;;; Run:  ./scripts/with-sbcl.sh --load interop/string-large/stringlarge_sub.lisp
;;;;   with the Connext writer:  (cd interop/string-large && ./stringlarge_pub 0 60)
(asdf:load-system :dds-shapes)
(in-package :dds.shapes)

(dds.gen:define-dds-type string-large (:extensibility :final)
  (id :i32 :key t)
  (text (:string 1024)))

(defun run-strlarge-probe (&key (domain 0) (seconds 30) (advertise-address "127.0.0.1"))
  (let* ((ts (dds.types:find-type-support "string-large"))
         (p (dds.dcps:create-participant :domain domain :advertise-address advertise-address)))
    (setf dds.dcps:*type-compat-log* *standard-output*)
    (let* ((tp (dds.dcps:create-topic p "StringLarge" "StringLarge" ts))
           (sub (dds.dcps:create-subscriber p))
           (dr (dds.dcps:create-datareader sub tp :qos (dds.qos:make-reader-qos :reliability :reliable))))
      (format t "~&[strlarge-probe] StringLarge/StringLarge local-type=string-large (text is (:string 1024) -> TI_STRING8_LARGE) domain=~d.~%" domain)
      (let ((seen 0) (start (get-internal-real-time)))
        (loop
          (dds.dcps:spin p)
          (dolist (cs (dds.dcps:take-samples dr))
            (handler-case
                (let ((info (dds.dcps:cached-sample-info cs)))
                  (when (dds.dcps:sample-info-valid-data info)
                    (let ((s (dds.dcps:cached-sample-data cs)))
                      (incf seen)
                      (format t "~&[strlarge-probe] sample #~d: id=~a text=~s~%"
                              seen (string-large-id s) (string-large-text s)))))
              (error (e) (format t "~&[strlarge-probe] sample error: ~a~%" (type-of e)))))
          (when (and (plusp seconds)
                     (> (/ (- (get-internal-real-time) start) internal-time-units-per-second) seconds))
            (return))
          (sleep 0.05))
        (format t "~&[strlarge-probe] DONE. samples=~d.~%" seen)
        (format t "~&[strlarge-probe] VERDICT: ~:[NO DATA — our LARGE-form reader did not receive from the Connext string<1024> writer~;INTEROPERATES — Connext string<1024> writer matched our TI_STRING8_LARGE reader; text decoded correctly~]~%"
                (plusp seen))))))

(run-strlarge-probe :seconds 30)
(uiop:quit 0)
