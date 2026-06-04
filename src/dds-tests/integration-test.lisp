(in-package #:dds.tests)

;;; End-to-end offline integration (the strongest proof short of Connext interop):
;;; a generated-type sample is serialized to a SerializedPayload, framed in an RTPS
;;; DATA message, sent over a REAL UDP loopback socket, received, dispatched, the
;;; payload deserialized, and the reliable reader records the change. This wires
;;; together the type compiler, CDR/encapsulation, the submessage codec + dispatch
;;; loop, the UDP transport, and the reliable engine.

(declaim (ftype (function () t) run-end-to-end-test))
(defun run-end-to-end-test ()
  (let* ((wid #x00000102)
         (rid dds.rtps.message:+entityid-participant+)
         (sample (make-gsample :id 1234567 :ts -98765432101 :label "shapes"))
         (writer (dds.rtps.reliable:make-rtps-writer
                  :hc (dds.rtps.history:make-history-cache :keep-all 1 nil nil)))
         (reader (dds.rtps.reliable:make-rtps-reader)))
    (multiple-value-bind (rx-tr rx-sock) (dds.xport.udp:make-udp-transport :host "127.0.0.1" :port 0)
      (declare (ignore rx-tr))
      (multiple-value-bind (tx-tr tx-sock) (dds.xport.udp:make-udp-transport :host "127.0.0.1" :port 0)
        (unwind-protect
            (let ((rx-port (dds.xport.udp:udp-transport-local-port rx-sock))
                  (msg-buf (dds.core.buffer:make-octet-buffer 512))
                  (pl-buf (dds.core.buffer:make-octet-buffer 256))
                  (in-buf (dds.core.buffer:make-octet-buffer 512))
                  (prefix (make-array 12 :element-type '(unsigned-byte 8) :initial-element 7))
                  (got nil))
              ;; SerializedPayload = encapsulation header (PLAIN_CDR2_LE) + gsample body
              (let ((pc (dds.core.buffer:cursor pl-buf :endianness :little)))
                (dds.cdr:make-encapsulation-header pc :plain-cdr2-le)
                (serialize-gsample sample pc :xcdr2)
                (let ((pl-len (dds.core.buffer:cursor-position pc)))
                  (dds.rtps.reliable:writer-write writer pl-buf)
                  (let ((mc (dds.core.buffer:cursor msg-buf :endianness :little)))
                    (dds.rtps.message:write-header mc prefix :vendor 0)
                    (dds.rtps.message:write-data mc rid wid 1
                                                 (dds.core.buffer:octet-buffer-vec pl-buf) 0 pl-len)
                    (dds.xport:send tx-tr
                                    (dds.xport.udp:make-udp-locator :host "127.0.0.1" :port rx-port)
                                    msg-buf 0 (dds.core.buffer:cursor-position mc)))))
              (sleep 0.2)
              (multiple-value-bind (size a p) (dds.xport.udp:udp-transport-recv rx-sock in-buf)
                (declare (ignore a p))
                (%check :e2e-received (> size 0) "no datagram received over UDP"))
              (let ((rc (dds.core.buffer:cursor in-buf :endianness :little)))
                (dds.rtps.message:dispatch-message
                 rc (lambda (id flags cur body-len)
                      (when (= id dds.rtps.message:+submsg-data+)
                        (multiple-value-bind (r w sn has off len key)
                            (dds.rtps.message:parse-data-body cur flags body-len)
                          (declare (ignore r len key))
                          (when has
                            (let ((vc (dds.core.buffer:cursor in-buf :endianness :little)))
                              (dds.core.buffer:cursor-set-position vc off)
                              (dds.cdr:parse-encapsulation-header vc)
                              (setf got (deserialize-gsample vc :xcdr2)))
                            (dds.rtps.reliable:reader-on-data reader w sn got)))))))
              (%check :e2e-deserialized (and got t) "DATA payload not deserialized")
              (%check :e2e-sample
                      (and (= (gsample-id got) 1234567)
                           (= (gsample-ts got) -98765432101)
                           (string= (gsample-label got) "shapes"))
                      "sample did not survive the full wire path")
              (dds.rtps.reliable:reader-on-heartbeat reader wid 1 1)
              (%check :e2e-reliable (dds.rtps.reliable:reader-complete-p reader wid)
                      "reliable reader did not record the change")
              t)
          (dds.pal:udp-close rx-sock)
          (dds.pal:udp-close tx-sock))))))
