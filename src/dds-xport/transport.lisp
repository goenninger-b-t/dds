(in-package #:dds.xport)

(defstruct (transport (:constructor %make-transport))
  (kind :mock)
  (send nil :type (or null function))
  (receive-loop nil :type (or null function))
  (open-receive-resource nil :type (or null function))
  (close nil :type (or null function))
  (max-message-size 65507 :type fixnum)
  (locator-kind :mock))

(declaim (ftype (function (transport t t (integer 0) (integer 0)) t) send))
(declaim (ftype (function (&key (:on-receive function) (:max-message-size fixnum)) transport) make-mock-transport))

(declaim (inline send))
(defun send (transport locator buffer off len)
  "Dispatch-free per-packet send: one slot read + funcall (FR-XPORT-5)."
  (funcall (transport-send transport) locator buffer off len))

(defun make-mock-transport (&key on-receive (max-message-size 65507))
  "Synchronous loopback transport: SEND hands the octets straight to ON-RECEIVE,
   which is called as (buffer off len). Deterministic; used by the M0 echo test."
  (declare (type function on-receive))
  (%make-transport
   :kind :mock
   :max-message-size max-message-size
   :locator-kind :mock
   :send (lambda (locator buffer off len)
           (declare (ignore locator))
           (funcall on-receive buffer off len)
           len)
   :receive-loop (lambda () (values))
   :open-receive-resource (lambda (&rest args) (declare (ignore args)) (values))
   :close (lambda () (values))))
