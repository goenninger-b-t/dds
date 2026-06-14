;;;; DDS.PAL — native UDPv4 sockets (FR-XPORT-1). Uses sb-bsd-sockets, which both
;;;; SBCL (contrib, required in pal-sbcl) and Clasp (bundled) provide natively —
;;;; each implementation's own socket interface, NOT a portability library. This
;;;; file carries no reader conditionals; it is loaded after the per-impl PALs so
;;;; the SB-BSD-SOCKETS package is present. The CLOS in sb-bsd-sockets is control
;;;; plane (socket setup); a raw sendmmsg/recvmmsg fast path is a later perf step.

(in-package #:dds.pal)

(defun* %parse-ipv4 (host)
    (function (string) (simple-array (unsigned-byte 8) (4)))
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

(defun* %setsockopt (socket level opt bytes)
    (function (t fixnum fixnum list) t)
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

(defun* udp-set-reuse-port (socket)
    (function (t) t)
  "Enable SO_REUSEPORT so multiple participants on one host can share the SPDP
   multicast port. Must be called before bind."
  (%setsockopt socket +sol-socket+ +so-reuseport+ '(1 0 0 0)))

(defun* udp-open (&key (host "0.0.0.0") (port 0) reuse-port)
    (function (&key (:host string) (:port (integer 0 65535)) (:reuse-port t)) t)
  "Open a UDPv4 socket bound to HOST:PORT (port 0 = ephemeral). REUSE-PORT enables
   SO_REUSEPORT before bind (shared multicast port). Returns the socket."
  (let ((s (make-instance 'sb-bsd-sockets:inet-socket :type :datagram :protocol :udp)))
    (setf (sb-bsd-sockets:sockopt-reuse-address s) t)
    (when reuse-port (udp-set-reuse-port s))
    (sb-bsd-sockets:socket-bind s (%parse-ipv4 host) port)
    s))

(defun* udp-local-port (socket)
    (function (t) (integer 0 65535))
  "The bound local port of SOCKET."
  (nth-value 1 (sb-bsd-sockets:socket-name socket)))

(defun* udp-send-to (socket buffer length host port)
    (function (t (simple-array (unsigned-byte 8) (*)) (integer 0) string (integer 0 65535)) t)
  "Send LENGTH octets of BUFFER from SOCKET to HOST:PORT."
  (sb-bsd-sockets:socket-send socket buffer length :address (list (%parse-ipv4 host) port)))

(defun* udp-recv (socket buffer length)
    (function (t (simple-array (unsigned-byte 8) (*)) (integer 0)) t)
  "Block until a datagram arrives; return (values size sender-address sender-port).
   Used from a dedicated receiver thread."
  (multiple-value-bind (buf size addr port) (sb-bsd-sockets:socket-receive socket buffer length)
    (declare (ignore buf))
    (values size addr port)))

(defun* udp-join-multicast (socket group)
    (function (t string) t)
  "Join the IPv4 multicast GROUP (dotted-quad) on the default interface and enable
   loopback (RTPS 2.5 §9.6.1.1). ip_mreq = imr_multiaddr(group) + imr_interface
   (INADDR_ANY). The socket must already be bound to the multicast port."
  (let ((g (%parse-ipv4 group)))
    (%setsockopt socket +ipproto-ip+ +ip-add-membership+
                 (list (aref g 0) (aref g 1) (aref g 2) (aref g 3) 0 0 0 0))
    (%setsockopt socket +ipproto-ip+ +ip-multicast-loop+ '(1))))

(defun* udp-close (socket)
    (function (t) t)
  "Close SOCKET."
  (sb-bsd-sockets:socket-close socket))

;; POSIX shared-memory segment primitives (FR-XPORT-2). open(2)/mmap(2) flag values
;; are OS-specific (Darwin vs Linux), not implementation-specific — hence OS reader
;; conditionals, not impl ones, mirroring the socket-option block above. off_t/size_t
;; are 64-bit on Darwin+Linux LP64; mode_t is 32-bit (passed via :unsigned-int).
#+darwin (progn (defconstant +o-creat+ #x0200) (defconstant +o-excl+ #x0800))
#-darwin (progn (defconstant +o-creat+ #x40)   (defconstant +o-excl+ #x80))
(defconstant +o-rdwr+ 2)
(defconstant +prot-rw+ 3)            ; PROT_READ|PROT_WRITE (1|2), same on Darwin+Linux
(defconstant +map-shared+ 1)         ; same on Darwin+Linux
(defconstant +map-failed-addr+ (1- (ash 1 64)))   ; mmap returns (void*)-1 on failure (LP64)

(defstruct* shm-segment
  "A mapped POSIX shared-memory object: NAME (e.g. \"/dds...\"), FD, foreign SAP, byte SIZE."
  (name "" :type string) (fd -1 :type fixnum) (sap nil :type t) (size 0 :type (integer 0)))

(defun* %mmap-shared (fd size)
    (function (fixnum (integer 1)) t)
  "mmap SIZE bytes of FD shared R/W; signal on MAP_FAILED. Returns the foreign SAP."
  (let ((p (cffi:foreign-funcall "mmap" :pointer (cffi:null-pointer) :unsigned-long size
                                 :int +prot-rw+ :int +map-shared+ :int fd :long 0 :pointer)))
    (when (= (cffi:pointer-address p) +map-failed-addr+) (error "mmap failed (size=~a)" size))
    p))

(defun* %shm-open-create (name)
    (function (string) fixnum)
  "shm_open O_CREAT|O_EXCL|O_RDWR, mode 0600. The variadic mode's ABI differs per impl on arm64.
   SBCL: foreign-funcall-varargs (stack — verified correct). Clasp: plain foreign-funcall (correct on
   Linux's register varargs ABI; UNRELIABLE on macOS arm64 — see the NFR-PORT gap, ADR 0013). Reader
   conditionals are permitted inside dds-pal/."
  #+sbcl (cffi:foreign-funcall-varargs "shm_open" (:string name :int (logior +o-creat+ +o-excl+ +o-rdwr+)) :unsigned-int #o600 :int)
  #-sbcl (cffi:foreign-funcall "shm_open" :string name :int (logior +o-creat+ +o-excl+ +o-rdwr+) :unsigned-int #o600 :int))

(defun* shm-create (name size)
    (function (string (integer 1)) shm-segment)
  "Create+map an exclusive POSIX shm object NAME of SIZE bytes (shm_open O_CREAT|O_EXCL,
   ftruncate, mmap MAP_SHARED). A stale leftover (EEXIST) is unlinked and recreated."
  (let ((fd (%shm-open-create name)))
    (when (minusp fd)
      (cffi:foreign-funcall "shm_unlink" :string name :int)
      (setf fd (%shm-open-create name)))
    (when (minusp fd) (error "shm_open(create ~a) failed" name))
    (when (minusp (cffi:foreign-funcall "ftruncate" :int fd :long size :int))
      (cffi:foreign-funcall "close" :int fd :int) (error "ftruncate(~a) failed" name))
    (handler-case (make-shm-segment :name name :fd fd :sap (%mmap-shared fd size) :size size)
      (error (e) (cffi:foreign-funcall "close" :int fd :int) (error e)))))

(defun* shm-attach (name size)
    (function (string (integer 1)) shm-segment)
  "Open+map an EXISTING shm object NAME of SIZE bytes (shm_open O_RDWR, mmap).
   No mode arg: the 2-arg open is non-variadic -> plain cffi:foreign-funcall."
  (let ((fd (cffi:foreign-funcall "shm_open" :string name :int +o-rdwr+ :int)))
    (when (minusp fd) (error "shm_open(attach ~a) failed" name))
    (handler-case (make-shm-segment :name name :fd fd :sap (%mmap-shared fd size) :size size)
      (error (e) (cffi:foreign-funcall "close" :int fd :int) (error e)))))

(defun* shm-sap (segment) (function (shm-segment) t) "Foreign SAP base of SEGMENT." (shm-segment-sap segment))

(defun* shm-detach (segment)
    (function (shm-segment) t)
  "munmap + close SEGMENT (does not unlink the name)."
  (cffi:foreign-funcall "munmap" :pointer (shm-segment-sap segment) :unsigned-long (shm-segment-size segment) :int)
  (cffi:foreign-funcall "close" :int (shm-segment-fd segment) :int))

(defun* shm-destroy (name) (function (string) t) "shm_unlink NAME." (cffi:foreign-funcall "shm_unlink" :string name :int))

;; Cross-process PTHREAD_PROCESS_SHARED mutex+condvar primitives (FR-XPORT-2), living in a
;; shared segment for in-band notification. Replaces named POSIX semaphores: sem_open is
;; undrivable from the Lisp runtime on macOS arm64 (variadic mode/value mispassed), whereas
;; every pthread_* below is NON-variadic -> plain foreign-funcall works on macOS + Linux,
;; and libpthread is already linked (no new dependency).
(defconstant +pthread-process-shared+ 1)   ; PTHREAD_PROCESS_SHARED, same on macOS + Linux

(defun* %ptr+ (sap offset)
    (function (t (integer 0)) t)
  "Foreign pointer at SAP + OFFSET bytes."
  (cffi:inc-pointer sap offset))

(defun* pshared-mutex-init (sap offset)
    (function (t (integer 0)) t)
  "Initialise a PTHREAD_PROCESS_SHARED mutex at SAP+OFFSET (creator only)."
  (cffi:with-foreign-object (ma :char 16)
    (cffi:foreign-funcall "pthread_mutexattr_init" :pointer ma :int)
    (cffi:foreign-funcall "pthread_mutexattr_setpshared" :pointer ma :int +pthread-process-shared+ :int)
    (let ((rc (cffi:foreign-funcall "pthread_mutex_init" :pointer (%ptr+ sap offset) :pointer ma :int)))
      (cffi:foreign-funcall "pthread_mutexattr_destroy" :pointer ma :int)
      (unless (zerop rc) (error "pthread_mutex_init failed rc=~a" rc))
      t)))

(defun* pshared-cond-init (sap offset)
    (function (t (integer 0)) t)
  "Initialise a PTHREAD_PROCESS_SHARED condition variable at SAP+OFFSET (creator only)."
  (cffi:with-foreign-object (ca :char 16)
    (cffi:foreign-funcall "pthread_condattr_init" :pointer ca :int)
    (cffi:foreign-funcall "pthread_condattr_setpshared" :pointer ca :int +pthread-process-shared+ :int)
    (let ((rc (cffi:foreign-funcall "pthread_cond_init" :pointer (%ptr+ sap offset) :pointer ca :int)))
      (cffi:foreign-funcall "pthread_condattr_destroy" :pointer ca :int)
      (unless (zerop rc) (error "pthread_cond_init failed rc=~a" rc))
      t)))

(defun* pshared-lock (sap offset)
    (function (t (integer 0)) t)
  "Lock the PROCESS_SHARED mutex at SAP+OFFSET."
  (cffi:foreign-funcall "pthread_mutex_lock" :pointer (%ptr+ sap offset) :int))
(defun* pshared-unlock (sap offset)
    (function (t (integer 0)) t)
  "Unlock the PROCESS_SHARED mutex at SAP+OFFSET."
  (cffi:foreign-funcall "pthread_mutex_unlock" :pointer (%ptr+ sap offset) :int))
(defun* pshared-cond-wait (sap cond-offset mutex-offset)
    (function (t (integer 0) (integer 0)) t)
  "Atomically release the mutex at SAP+MUTEX-OFFSET and wait on the cond at SAP+COND-OFFSET; re-locks on wake."
  (cffi:foreign-funcall "pthread_cond_wait" :pointer (%ptr+ sap cond-offset) :pointer (%ptr+ sap mutex-offset) :int))
(defun* pshared-cond-signal (sap offset)
    (function (t (integer 0)) t)
  "Wake one waiter on the cond at SAP+OFFSET."
  (cffi:foreign-funcall "pthread_cond_signal" :pointer (%ptr+ sap offset) :int))
(defun* pshared-cond-broadcast (sap offset)
    (function (t (integer 0)) t)
  "Wake all waiters on the cond at SAP+OFFSET."
  (cffi:foreign-funcall "pthread_cond_broadcast" :pointer (%ptr+ sap offset) :int))
(defun* pshared-destroy (sap mutex-offset cond-offset)
    (function (t (integer 0) (integer 0)) t)
  "Destroy the cond + mutex (creator, after the receive thread is joined)."
  (cffi:foreign-funcall "pthread_cond_destroy" :pointer (%ptr+ sap cond-offset) :int)
  (cffi:foreign-funcall "pthread_mutex_destroy" :pointer (%ptr+ sap mutex-offset) :int))
