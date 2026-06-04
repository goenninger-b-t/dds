(in-package #:dds.tests)

;;; Native UDPv4 PAL loopback (FR-XPORT-1): bind a receiver, send a datagram from
;;; a second socket to 127.0.0.1:<rx-port>, receive it, verify the octets. Uses
;;; each implementation's own sb-bsd-sockets; no portability library.

(declaim (ftype (function () t) run-udp-loopback-test))
(defun run-udp-loopback-test ()
  (let ((rx (dds.pal:udp-open :host "127.0.0.1" :port 0)))
    (unwind-protect
        (let ((tx (dds.pal:udp-open :host "127.0.0.1" :port 0))
              (out (make-array 4 :element-type '(unsigned-byte 8)
                                 :initial-contents '(#xde #xad #xbe #xef)))
              (in (make-array 16 :element-type '(unsigned-byte 8))))
          (unwind-protect
              (let ((port (dds.pal:udp-local-port rx)))
                (dds.pal:udp-send-to tx out 4 "127.0.0.1" port)
                (sleep 0.2)
                (multiple-value-bind (n addr sport) (dds.pal:udp-recv rx in 4)
                  (declare (ignore addr sport))
                  (%check :udp-loopback
                          (and (= n 4) (= (aref in 0) #xde) (= (aref in 3) #xef))
                          "UDP loopback datagram round-trip")))
            (dds.pal:udp-close tx)))
      (dds.pal:udp-close rx))
    t))
