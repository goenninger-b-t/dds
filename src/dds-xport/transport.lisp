(in-package #:dds.xport)

(defstruct (transport (:constructor %make-transport))
  "Pluggable transport record (IMPLEMENTATION-PLAN §7.5, FR-XPORT-5): the per-packet
   SEND and lifecycle operations are stored function slots, so the latency path stays
   dispatch-free. Adding a transport = constructing one record; the RTPS engine is
   untouched. Use make-transport / make-mock-transport, not %make-transport directly."
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

(declaim (ftype (function (&key (:kind t) (:send (or null function)) (:receive-loop (or null function)) (:open-receive-resource (or null function)) (:close (or null function)) (:max-message-size fixnum) (:locator-kind t)) transport) make-transport))
(defun make-transport (&key (kind :mock) send receive-loop open-receive-resource
                            close (max-message-size 65507) (locator-kind :mock))
  "Public constructor for a pluggable transport record (FR-XPORT-5). Adding a
   transport = constructing one of these; the RTPS engine is untouched."
  (%make-transport :kind kind :send send :receive-loop receive-loop
                   :open-receive-resource open-receive-resource :close close
                   :max-message-size max-message-size :locator-kind locator-kind))

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
