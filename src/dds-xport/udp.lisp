;;;; L7 — UDPv4 transport (FR-XPORT-1). Wraps the frozen DDS.XPORT transport
;;;; record around the native UDP socket layer in DDS.PAL. Adding a transport =
;;;; constructing one record; the RTPS engine is untouched (FR-XPORT-5). The raw
;;;; PAL socket has no slot in the frozen record, so make-udp-transport returns it
;;;; as a second value and the send/close closures capture it.

(in-package #:dds.xport.udp)

(defstruct* udp-locator
  "Destination address for a UDPv4 send: dotted-quad HOST and PORT."
  (host "127.0.0.1" :type string)
  (port 0 :type (unsigned-byte 16)))

(defun* make-udp-transport (&key (host "0.0.0.0") (port 0))
    (function (&key (:host string) (:port (unsigned-byte 16)))
              (values (or null dds.xport:transport) t (or null keyword)))
  "Open a UDPv4 socket bound to HOST:PORT and wrap it in a transport record.
   SEND assumes OFF is 0 for v1 (whole-buffer datagram from index 0). Returns
   (values transport socket NIL); the socket has no slot in the frozen record.
   On a PAL open failure returns (values NIL NIL status) — the caller must not proceed with a NIL
   transport (operating contract: failures are threaded, never signalled)."
  (multiple-value-bind (socket status) (dds.pal:udp-open :host host :port port)
    (when status (return-from make-udp-transport (values nil nil status)))
    (values
     (dds.xport:make-transport
      :kind :udpv4
      :locator-kind :udpv4
      :max-message-size 65507
      :send (lambda (locator buffer off len)
              (declare (ignore off))
              ;; UDP is best-effort: a sendto failure to one destination (an
              ;; unreachable/stale/placeholder locator, e.g. a foreign participant
              ;; advertising 0.0.0.0 or a down interface) must NOT be fatal — drop
              ;; the datagram; the reliable layer recovers via HEARTBEAT/ACKNACK.
              (handler-case
                  (progn
                    (dds.pal:udp-send-to socket
                                         (dds.core.buffer:octet-buffer-vec buffer)
                                         len
                                         (udp-locator-host locator)
                                         (udp-locator-port locator))
                    len)
                (error () 0)))
      :receive-loop (lambda () (values))
      :open-receive-resource (lambda (&rest args) (declare (ignore args)) (values))
      :close (lambda () (dds.pal:udp-close socket)))
     socket
     nil)))

(defun* udp-transport-local-port (socket)
    (function (t) (integer 0 65535))
  "The bound local port of the UDP SOCKET."
  (dds.pal:udp-local-port socket))

(defun* udp-transport-recv (socket buffer)
    (function (t dds.core.buffer:octet-buffer) (values (integer 0) t t))
  "Block until a datagram arrives; read it into BUFFER up to its capacity.
   Returns (values size sender-address sender-port)."
  (dds.pal:udp-recv socket
                    (dds.core.buffer:octet-buffer-vec buffer)
                    (dds.core.buffer:octet-buffer-capacity buffer)))

(defun* run-udp-transport-test ()
    (function () (eql t))
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

(defun* start-udp-receiver (socket on-datagram)
    (function (t function) t)
  "Spawn a thread that blocks on SOCKET, receiving each datagram into a 64 KiB
   octet-buffer and calling (ON-DATAGRAM buffer size). The thread exits when the socket is closed —
   dds.pal:udp-close SHUTS THE SOCKET DOWN before closing it, which is what actually wakes this thread:
   on Linux close(2) alone does NOT unblock a parked recvfrom, so without the shutdown this thread stays
   blocked forever and stop-node's join never returns (NFR-PORT; see udp-close). Returns the thread
   (FR-XPORT-5)."
  (dds.pal:spawn
   (lambda ()
     (let ((buf (dds.core.buffer:make-octet-buffer 65507)))
       (unwind-protect
            (loop
              (let ((size (handler-case
                              (nth-value 0 (dds.pal:udp-recv socket
                                                             (dds.core.buffer:octet-buffer-vec buf) 65507))
                            (error () (return)))))   ; socket closed / recv error -> exit thread
                ;; one malformed or unexpected datagram must not kill the receiver
                (handler-case (funcall on-datagram buf size)
                  (error () nil))))
         (dds.pal:free-static (dds.core.buffer:octet-buffer-vec buf)))))
   :name "dds-udp-rx"))

(defun* run-udp-receiver-test ()
    (function () (eql t))
  "Receiver-thread loopback: a background thread receives a datagram and records
   it; assert it arrives within a bounded wait. Returns T."
  (multiple-value-bind (rx-tr rx-sock) (make-udp-transport :host "127.0.0.1" :port 0)
    (declare (ignore rx-tr))
    (multiple-value-bind (tx-tr tx-sock) (make-udp-transport :host "127.0.0.1" :port 0)
      (let ((received nil))
        (unwind-protect
            (progn
              (start-udp-receiver
               rx-sock (lambda (buf size)
                         (setf received (cons size (aref (dds.core.buffer:octet-buffer-vec buf) 0)))))
              (let ((ob (dds.core.buffer:make-octet-buffer 16))
                    (port (udp-transport-local-port rx-sock)))
                (let ((c (dds.core.buffer:cursor ob)))
                  (dds.core.buffer:put-u8 c #x55)
                  (dds.core.buffer:put-u8 c #x66))
                (dds.xport:send tx-tr (make-udp-locator :host "127.0.0.1" :port port) ob 0 2))
              (loop repeat 100 until received do (sleep 0.02))
              (assert received () "receiver thread did not deliver a datagram")
              (assert (= 2 (car received)) () "wrong datagram size")
              (assert (= #x55 (cdr received)) () "wrong datagram byte")
              t)
          (dds.pal:udp-close tx-sock)
          (dds.pal:udp-close rx-sock))))))
