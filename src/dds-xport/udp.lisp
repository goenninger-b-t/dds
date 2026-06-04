;;;; L7 — UDPv4 transport (FR-XPORT-1). Wraps the frozen DDS.XPORT transport
;;;; record around the native UDP socket layer in DDS.PAL. Adding a transport =
;;;; constructing one record; the RTPS engine is untouched (FR-XPORT-5). The raw
;;;; PAL socket has no slot in the frozen record, so make-udp-transport returns it
;;;; as a second value and the send/close closures capture it.

(in-package #:dds.xport.udp)

(defstruct udp-locator
  "Destination address for a UDPv4 send: dotted-quad HOST and PORT."
  (host "127.0.0.1" :type string)
  (port 0 :type (unsigned-byte 16)))

(declaim (ftype (function (&key (:host string) (:port (unsigned-byte 16))) (values dds.xport:transport t)) make-udp-transport))
(defun make-udp-transport (&key (host "0.0.0.0") (port 0))
  "Open a UDPv4 socket bound to HOST:PORT and wrap it in a transport record.
   SEND assumes OFF is 0 for v1 (whole-buffer datagram from index 0). Returns
   (values transport socket); the socket has no slot in the frozen record."
  (let ((socket (dds.pal:udp-open :host host :port port)))
    (values
     (dds.xport::%make-transport ; internal constructor: %make-transport is not exported (v1)
      :kind :udpv4
      :locator-kind :udpv4
      :max-message-size 65507
      :send (lambda (locator buffer off len)
              (declare (ignore off))
              (dds.pal:udp-send-to socket
                                   (dds.core.buffer:octet-buffer-vec buffer)
                                   len
                                   (udp-locator-host locator)
                                   (udp-locator-port locator))
              len)
      :receive-loop (lambda () (values))
      :open-receive-resource (lambda (&rest args) (declare (ignore args)) (values))
      :close (lambda () (dds.pal:udp-close socket)))
     socket)))

(declaim (ftype (function (t) (integer 0 65535)) udp-transport-local-port))
(defun udp-transport-local-port (socket)
  "The bound local port of the UDP SOCKET."
  (dds.pal:udp-local-port socket))

(declaim (ftype (function (t dds.core.buffer:octet-buffer) (values (integer 0) t t)) udp-transport-recv))
(defun udp-transport-recv (socket buffer)
  "Block until a datagram arrives; read it into BUFFER up to its capacity.
   Returns (values size sender-address sender-port)."
  (dds.pal:udp-recv socket
                    (dds.core.buffer:octet-buffer-vec buffer)
                    (dds.core.buffer:octet-buffer-capacity buffer)))

(declaim (ftype (function () (eql t)) run-udp-transport-test))
(defun run-udp-transport-test ()
  "Transport-level UDP loopback: sender SEND -> receiver recv on 127.0.0.1.
   Sends 4 known octets and asserts they round-trip. Returns T."
  (multiple-value-bind (rx-transport rx-socket) (make-udp-transport :host "127.0.0.1" :port 0)
    (declare (ignore rx-transport))
    (multiple-value-bind (tx-transport tx-socket) (make-udp-transport :host "127.0.0.1" :port 0)
      (unwind-protect
           (let* ((rx-port (udp-transport-local-port rx-socket))
                  (out-buffer (dds.core.buffer:make-octet-buffer 64))
                  (in-buffer (dds.core.buffer:make-octet-buffer 64))
                  (c (dds.core.buffer:cursor out-buffer)))
             (dds.core.buffer:put-u8 c #xDE)
             (dds.core.buffer:put-u8 c #xAD)
             (dds.core.buffer:put-u8 c #xBE)
             (dds.core.buffer:put-u8 c #xEF)
             (assert (= 4 (dds.core.buffer:cursor-position c)))
             (dds.xport:send tx-transport
                             (make-udp-locator :host "127.0.0.1" :port rx-port)
                             out-buffer 0 4)
             (sleep 0.2)
             (multiple-value-bind (size addr senderport) (udp-transport-recv rx-socket in-buffer)
               (declare (ignore addr senderport))
               (assert (= 4 size))
               (let ((v (dds.core.buffer:octet-buffer-vec in-buffer)))
                 (assert (= #xDE (aref v 0)))
                 (assert (= #xAD (aref v 1)))
                 (assert (= #xBE (aref v 2)))
                 (assert (= #xEF (aref v 3)))))
             t)
        (dds.pal:udp-close rx-socket)
        (dds.pal:udp-close tx-socket)))))
