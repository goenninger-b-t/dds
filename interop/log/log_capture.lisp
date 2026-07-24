;;;; LogEvent byte-exact corpus capture (ADR 0082 §3, FR-CDR-8 / FR-IO). Captures ONE raw LogEvent
;;;; SerializedPayload a foreign @appendable writer put ON THE WIRE (off our receive path, exactly like
;;;; dds.bench:corpus-capture), then round-trips it through OUR codec — deserialize -> re-serialize — and
;;;; writes the vector only if the result is BYTE-EXACT. That proves our @appendable ENCODER matches the
;;;; foreign encoder (the corpus of perfdata is @final, so this is the first @appendable-DHEADER vector).
;;;;
;;;; Run against the Connext writer (interop/log/log_pub 0 400) or Fast DDS (interop/fastdds/log/log_pub):
;;;;   ./scripts/with-sbcl.sh --load interop/log/log_capture.lisp
(asdf:load-system :dds-log)
(in-package :dds.log)

(defun run-capture (&key (domain 0) (advertise-address "127.0.0.1") (seconds 20)
                         (peers "127.0.0.1:7410,127.0.0.1:7412,127.0.0.1:7414,127.0.0.1:7416")
                         (path "corpus/xcdr2/logevent-connext.bin"))
  (let* ((ts (dds.types:find-type-support "log-event"))
         (captured nil)
         (orig (symbol-function 'dds.disc::%deliver-user-sample)))
    (setf (fdefinition 'dds.disc::%deliver-user-sample)
          (lambda (node writer-id sn vec &rest r)
            (when (and (not captured) (typep vec '(array (unsigned-byte 8) (*))) (> (length vec) 20))
              (setf captured (copy-seq vec)))
            (apply orig node writer-id sn vec r)))
    (let* ((participant (dds.dcps:create-participant :domain domain :advertise-address advertise-address
                                                     :peers (dds.disc:parse-peers peers)))
           (collector (make-log-collector :participant participant :sinks '()))
           (start (get-internal-real-time)))
      (loop
        (collector-drain collector)
        (when (or captured (> (/ (- (get-internal-real-time) start) internal-time-units-per-second) seconds))
          (return))
        (sleep 0.05))
      (setf (fdefinition 'dds.disc::%deliver-user-sample) orig)
      (if captured
          ;; reserialize in the SAME representation the foreign writer chose (its encap id): a stock
          ;; @appendable writer picks XCDR1 (0x0001, no DHEADER, rule 29) when our reader accepts it, not
          ;; XCDR2 (0x0009). Byte-exactness must compare like reps.
          (let* ((encap (logior (ash (aref captured 0) 8) (aref captured 1)))
                 (rep (if (<= encap 1) :xcdr1 :xcdr2))
                 (e (dds.dcps::%deserialize-sample ts captured))
                 (got (dds.dcps::%serialize-sample ts e rep)))
            (format t "~&[capture] wire representation = ~a (encap 0x~4,'0x)~%" rep encap)
            (format t "~&[capture] captured ~d octets, encap=0x~2,'0x~2,'0x options=0x~2,'0x~2,'0x~%"
                    (length captured) (aref captured 1) (aref captured 0) (aref captured 3) (aref captured 2))
            (if (equalp got captured)
                (progn
                  (format t "~&[capture] ROUND-TRIP BYTE-EXACT (~d octets) — our @appendable encoder == the foreign wire.~%"
                          (length got))
                  (ensure-directories-exist path)
                  (with-open-file (out path :direction :output :element-type '(unsigned-byte 8)
                                            :if-exists :supersede :if-does-not-exist :create)
                    (write-sequence captured out))
                  (format t "~&[capture] wrote ~a~%" path))
                (format t "~&[capture] ROUND-TRIP MISMATCH: ours ~d octets vs wire ~d — NOT written.~%    wire: ~a~%    ours: ~a~%"
                        (length got) (length captured)
                        (subseq captured 0 (min 40 (length captured))) (subseq got 0 (min 40 (length got))))))
          (format t "~&[capture] NO SAMPLE CAPTURED — no foreign LogEvent writer discovered.~%"))
      (close-log-collector collector)
      (dds.dcps:delete-participant participant))))

(run-capture :seconds 20 :path (or (uiop:getenv "CORPUS_PATH") "corpus/xcdr2/logevent-connext.bin"))
(uiop:quit 0)
