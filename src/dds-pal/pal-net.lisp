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

;; Socket-option ABI constants are OS-specific (numeric values differ between
;; Darwin and Linux), not implementation-specific — hence OS reader conditionals,
;; not impl ones. Used for options sb-bsd-sockets does not expose: SO_REUSEPORT
;; (share the SPDP multicast port across same-host participants), IP_ADD_MEMBERSHIP
;; + IP_MULTICAST_LOOP (RTPS 2.5 §9.6.1.1 multicast discovery).
#+darwin
(progn
  (defconstant +sol-socket+ #xffff)
  (defconstant +so-reuseport+ #x0200)
  (defconstant +ipproto-ip+ 0)
  (defconstant +ip-add-membership+ 12)
  (defconstant +ip-multicast-loop+ 11))
#-darwin
(progn
  (defconstant +sol-socket+ 1)
  (defconstant +so-reuseport+ 15)
  (defconstant +ipproto-ip+ 0)
  (defconstant +ip-add-membership+ 35)
  (defconstant +ip-multicast-loop+ 34))

(declaim (ftype (function (t fixnum fixnum list) t) %setsockopt))
(defun %setsockopt (socket level opt bytes)
  "Raw setsockopt(fd, LEVEL, OPT, BYTES) via CFFI for options sb-bsd-sockets does
   not expose. BYTES is the option value as a list of octets. Signals on failure."
  (let ((fd (sb-bsd-sockets:socket-file-descriptor socket))
        (n (length bytes)))
    (cffi:with-foreign-object (p :uint8 n)
      (loop for i from 0 for b in bytes do (setf (cffi:mem-aref p :uint8 i) b))
      (let ((rc (cffi:foreign-funcall "setsockopt" :int fd :int level :int opt
                                      :pointer p :uint n :int)))
        (unless (zerop rc) (error "setsockopt(level=~a opt=~a) failed rc=~a" level opt rc))
        rc))))

(declaim (ftype (function (t) t) udp-set-reuse-port))
(defun udp-set-reuse-port (socket)
  "Enable SO_REUSEPORT so multiple participants on one host can share the SPDP
   multicast port. Must be called before bind."
  (%setsockopt socket +sol-socket+ +so-reuseport+ '(1 0 0 0)))

(declaim (ftype (function (&key (:host string) (:port (integer 0 65535)) (:reuse-port t)) t) udp-open))
(defun udp-open (&key (host "0.0.0.0") (port 0) reuse-port)
  "Open a UDPv4 socket bound to HOST:PORT (port 0 = ephemeral). REUSE-PORT enables
   SO_REUSEPORT before bind (shared multicast port). Returns the socket."
  (let ((s (make-instance 'sb-bsd-sockets:inet-socket :type :datagram :protocol :udp)))
    (setf (sb-bsd-sockets:sockopt-reuse-address s) t)
    (when reuse-port (udp-set-reuse-port s))
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

(declaim (ftype (function (t string) t) udp-join-multicast))
(defun udp-join-multicast (socket group)
  "Join the IPv4 multicast GROUP (dotted-quad) on the default interface and enable
   loopback (RTPS 2.5 §9.6.1.1). ip_mreq = imr_multiaddr(group) + imr_interface
   (INADDR_ANY). The socket must already be bound to the multicast port."
  (let ((g (%parse-ipv4 group)))
    (%setsockopt socket +ipproto-ip+ +ip-add-membership+
                 (list (aref g 0) (aref g 1) (aref g 2) (aref g 3) 0 0 0 0))
    (%setsockopt socket +ipproto-ip+ +ip-multicast-loop+ '(1))))

(declaim (ftype (function (t) t) udp-close))
(defun udp-close (socket)
  "Close SOCKET."
  (sb-bsd-sockets:socket-close socket))
