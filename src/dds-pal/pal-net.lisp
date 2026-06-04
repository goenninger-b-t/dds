;;;; DDS.PAL — native UDPv4 sockets (FR-XPORT-1). Uses sb-bsd-sockets, which both
;;;; SBCL (contrib, required in pal-sbcl) and Clasp (bundled) provide natively —
;;;; each implementation's own socket interface, NOT a portability library. This
;;;; file carries no reader conditionals; it is loaded after the per-impl PALs so
;;;; the SB-BSD-SOCKETS package is present. The CLOS in sb-bsd-sockets is control
;;;; plane (socket setup); a raw sendmmsg/recvmmsg fast path is a later perf step.

(in-package #:dds.pal)

(declaim (ftype (function (string) (simple-array (unsigned-byte 8) (4))) %parse-ipv4))
(defun %parse-ipv4 (host)
  "Parse a dotted-quad string into a 4-octet address vector."
  (let ((v (make-array 4 :element-type '(unsigned-byte 8)))
        (start 0))
    (dotimes (i 4 v)
      (let ((dot (position #\. host :start start)))
        (setf (aref v i) (parse-integer host :start start :end dot)
              start (if dot (1+ dot) (length host)))))))

(declaim (ftype (function (&key (:host string) (:port (integer 0 65535))) t) udp-open))
(defun udp-open (&key (host "0.0.0.0") (port 0))
  "Open a UDPv4 socket bound to HOST:PORT (port 0 = ephemeral). Returns the socket."
  (let ((s (make-instance 'sb-bsd-sockets:inet-socket :type :datagram :protocol :udp)))
    (sb-bsd-sockets:socket-bind s (%parse-ipv4 host) port)
    s))

(declaim (ftype (function (t) (integer 0 65535)) udp-local-port))
(defun udp-local-port (socket)
  "The bound local port of SOCKET."
  (nth-value 1 (sb-bsd-sockets:socket-name socket)))

(declaim (ftype (function (t (simple-array (unsigned-byte 8) (*)) (integer 0) string (integer 0 65535)) t) udp-send-to))
(defun udp-send-to (socket buffer length host port)
  "Send LENGTH octets of BUFFER from SOCKET to HOST:PORT."
  (sb-bsd-sockets:socket-send socket buffer length :address (list (%parse-ipv4 host) port)))

(declaim (ftype (function (t (simple-array (unsigned-byte 8) (*)) (integer 0)) t) udp-recv))
(defun udp-recv (socket buffer length)
  "Block until a datagram arrives; return (values size sender-address sender-port).
   Used from a dedicated receiver thread."
  (multiple-value-bind (buf size addr port) (sb-bsd-sockets:socket-receive socket buffer length)
    (declare (ignore buf))
    (values size addr port)))

(declaim (ftype (function (t) t) udp-close))
(defun udp-close (socket)
  "Close SOCKET."
  (sb-bsd-sockets:socket-close socket))
