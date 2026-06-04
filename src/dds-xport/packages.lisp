;;;; L7 — Transports. The transport record (IMPLEMENTATION-PLAN §7.5) is a plain
;;;; defstruct whose per-packet SEND slot is a stored function, so the latency
;;;; path stays dispatch-free even if the transport object is configured via CLOS.

(defpackage #:net.goenninger.dds.xport
  (:nicknames #:dds.xport)
  (:use #:common-lisp)
  (:documentation
   "Pluggable transport record (IMPLEMENTATION-PLAN §7.5). Adding a transport =
    constructing one record; the RTPS engine is untouched (FR-XPORT-5). M0 ships
    the record shape + a synchronous loopback mock used by the echo exit test.")
  (:export #:transport #:transport-p #:transport-kind
           #:transport-send #:transport-receive-loop
           #:transport-open-receive-resource #:transport-close
           #:transport-max-message-size #:transport-locator-kind
           #:send #:make-transport #:make-mock-transport))

(defpackage #:net.goenninger.dds.xport.udp
  (:nicknames #:dds.xport.udp)
  (:use #:common-lisp)
  (:documentation
   "UDPv4 transport (ADR 0006): wraps the frozen DDS.XPORT transport record
    around the native DDS.PAL UDP socket layer. make-udp-transport returns the
    raw PAL socket as a second value since the record has no slot for it.")
  (:export #:make-udp-transport #:udp-locator #:make-udp-locator
           #:udp-locator-host #:udp-locator-port
           #:udp-transport-local-port #:udp-transport-recv
           #:start-udp-receiver
           #:run-udp-transport-test #:run-udp-receiver-test))
