;;;; DDS.PAL — native UDPv4 sockets (FR-XPORT-1). Uses sb-bsd-sockets, which both
;;;; SBCL (contrib, required in pal-sbcl) and Clasp (bundled) provide natively —
;;;; each implementation's own socket interface, NOT a portability library. This
;;;; file carries no reader conditionals; it is loaded after the per-impl PALs so
;;;; the SB-BSD-SOCKETS package is present. The CLOS in sb-bsd-sockets is control
;;;; plane (socket setup); a raw sendmmsg/recvmmsg fast path is a later perf step.

(in-package #:dds.pal)

;;; ---- wall clock (source_timestamp) ----
;; clock_gettime is impl-agnostic via CFFI (loaded for both SBCL + Clasp). CLOCK_REALTIME = 0 and struct
;; timespec { time_t tv_sec; long tv_nsec } is 16 octets (tv_sec@0, tv_nsec@8) on both Linux x86-64 and
;; macOS arm64 — the two 64-bit targets — so there is no per-impl divergence to confine.

(cffi:defcfun ("clock_gettime" %clock-gettime) :int (clk-id :int) (tp :pointer))

(defun* realtime-ns ()
    (function () integer)
  "Wall-clock time in NANOSECONDS since the Unix epoch (clock_gettime CLOCK_REALTIME) — the DDS
   source_timestamp source (DDS 1.4 Time_t; RTPS 2.5 §9.3.2.1 / §9.4.5.9 INFO_TS). Reads the 16-octet
   struct timespec (tv_sec@0, tv_nsec@8, both 64-bit on the supported targets). Falls back to the
   1-second (get-universal-time) clock if the syscall fails, so it never signals."
  (cffi:with-foreign-object (tp :uint8 16)
    (if (zerop (%clock-gettime 0 tp))
        (+ (* (cffi:mem-ref tp :int64 0) 1000000000) (cffi:mem-ref tp :int64 8))
        (* (- (get-universal-time) 2208988800) 1000000000))))

;;; ---- thread introspection (control-plane; lifecycle assertions, never the hot path) ----

(defun* live-threads ()
    (function () list)
  "Every thread currently alive in this image (bordeaux-threads:all-threads — portable, so this lives in
   the SHARED PAL file with no reader conditional, alongside SPAWN/JOIN which are the same call on both
   implementations). Control-plane ONLY: the thread-lifecycle gates assert that a create/enable/delete cycle
   leaves the thread set exactly as it found it (no leaked background thread). Never called on the hot path."
  (bordeaux-threads:all-threads))

(defun* thread-name (thread)
    (function (t) string)
  "THREAD's name, as given to SPAWN (bordeaux-threads:thread-name). Control-plane only: lets a lifecycle
   assertion name the specific background thread it expects to be gone (e.g. \"dds-autodiscovery\")."
  (bordeaux-threads:thread-name thread))

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
  (defconstant +so-rcvtimeo+ #x1006)
  (defconstant +ipproto-ip+ 0)
  (defconstant +ip-add-membership+ 12)
  (defconstant +ip-multicast-loop+ 11))
#-darwin
(progn
  (defconstant +sol-socket+ 1)
  (defconstant +so-reuseport+ 15)
  (defconstant +so-rcvtimeo+ 20)
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

;; TCPv4 stream sockets (FR-XPORT-1). Same sb-bsd-sockets substrate as UDP above (native on SBCL
;; contrib + Clasp bundled); no reader conditionals except the OS-specific SO_NOSIGPIPE below.
;; A stream is a byte pipe, NOT message-framed: tcp-send loops over short writes and tcp-recv loops
;; until LEN bytes are assembled (a large frame splits across segments). socket-send / socket-receive
;; write/read at buffer[0] with no offset arg (verified both impls), so the continuation reads/writes
;; go through a subseq / scratch+replace — the destination offset is honoured in Lisp.

;; SO_NOSIGPIPE (Darwin, SOL_SOCKET=#xffff optname=#x1022): a write to a peer that has closed returns
;; EPIPE (-> a catchable SOCKET-ERROR) instead of raising SIGPIPE. On Darwin this also keeps Clasp off
;; its signal->CLOS-condition path (the known Clasp multithreaded-signal fragility), so BOTH impls take
;; the identical clean EPIPE->SOCKET-ERROR path on a torn connection. Linux runtimes ignore SIGPIPE
;; process-wide already (SBCL + Clasp), so the option is Darwin-only.
#+darwin (defconstant +so-nosigpipe+ #x1022 "Darwin SO_NOSIGPIPE optname (suppress SIGPIPE on a dead peer).")

(defun* %tcp-suppress-sigpipe (socket)
    (function (t) t)
  "Route a write-to-closed-peer to EPIPE (SOCKET-ERROR) rather than SIGPIPE. Darwin: SO_NOSIGPIPE;
   elsewhere a no-op (the runtime ignores SIGPIPE process-wide)."
  (declare (ignorable socket))
  #+darwin (%setsockopt socket +sol-socket+ +so-nosigpipe+ '(1 0 0 0))
  t)

(defun* tcp-connect (host port)
    (function (string (integer 0 65535)) t)
  "Open a TCPv4 stream socket connected to HOST:PORT. Returns the connected socket."
  (let ((s (make-instance 'sb-bsd-sockets:inet-socket :type :stream :protocol :tcp)))
    (%tcp-suppress-sigpipe s)
    (sb-bsd-sockets:socket-connect s (%parse-ipv4 host) port)
    s))

(defun* tcp-listen (host port &key (backlog 8))
    (function (string (integer 0 65535) &key (:backlog (integer 1))) t)
  "Open a listening TCPv4 stream socket bound to HOST:PORT (port 0 = ephemeral), SO_REUSEADDR set,
   with the given accept BACKLOG. Returns the listener socket (use tcp-local-port to read an ephemeral
   port, tcp-accept to take connections)."
  (let ((s (make-instance 'sb-bsd-sockets:inet-socket :type :stream :protocol :tcp)))
    (setf (sb-bsd-sockets:sockopt-reuse-address s) t)
    (sb-bsd-sockets:socket-bind s (%parse-ipv4 host) port)
    (sb-bsd-sockets:socket-listen s backlog)
    s))

(defun* tcp-accept (listener)
    (function (t) t)
  "Block until a client connects to LISTENER; return the connected stream socket (SIGPIPE suppressed)."
  (let ((s (sb-bsd-sockets:socket-accept listener)))
    (%tcp-suppress-sigpipe s)
    s))

(defun* tcp-local-port (listener)
    (function (t) (integer 0 65535))
  "The bound local port of LISTENER (read an ephemeral port after a port-0 bind)."
  (nth-value 1 (sb-bsd-sockets:socket-name listener)))

(defun* tcp-set-recv-timeout (socket seconds)
    (function (t (real 0)) t)
  "Arm SO_RCVTIMEO on stream SOCKET so a blocking tcp-recv that makes no progress for SECONDS raises a
   PAL-TIMEOUT (a DISTINCT catchable outcome, not a clean-EOF NIL and not data) instead of blocking
   forever — the read/idle DoS guard for the durability microservice (ADR 0050 §4.6, operating contract
   §4). SECONDS 0 clears the timeout (block indefinitely, the default). The option value is a 16-byte
   struct timeval: tv_sec as 8 little-endian octets, then tv_usec (< 10^6, so < 2^32) as 4 little-endian
   octets + 4 zero octets — a layout valid for BOTH the Darwin int32 tv_usec (offset 8, 4 tail-pad bytes)
   AND the Linux long tv_usec (offset 8, 8 bytes), so ONE encoding is portable across OSes. SO_RCVTIMEO
   optname is OS-specific (+so-rcvtimeo+: Darwin #x1006 / Linux 20), like the SO_REUSEPORT constants above
   — never impl-specific, so this carries no #+sbcl/#+clasp conditional. Reuses %setsockopt (DRY)."
  (let* ((sec (floor seconds))
         (usec (floor (* (- seconds sec) 1000000))))
    (%setsockopt socket +sol-socket+ +so-rcvtimeo+
                 (list (ldb (byte 8 0) sec)  (ldb (byte 8 8) sec)  (ldb (byte 8 16) sec) (ldb (byte 8 24) sec)
                       (ldb (byte 8 32) sec) (ldb (byte 8 40) sec) (ldb (byte 8 48) sec) (ldb (byte 8 56) sec)
                       (ldb (byte 8 0) usec) (ldb (byte 8 8) usec) (ldb (byte 8 16) usec) (ldb (byte 8 24) usec)
                       0 0 0 0))
    t))

(defun* tcp-send (socket buffer len)
    (function (t (simple-array (unsigned-byte 8) (*)) (integer 0)) (integer 0))
  "Send exactly LEN octets of BUFFER[0..LEN) over stream SOCKET, looping over short writes (a stream
   socket may accept fewer than requested). Returns LEN. Signals on a failed / zero-progress write
   (peer reset) — the socket-level error is contained here, never leaked to callers as a raw
   sb-bsd-sockets condition."
  (let ((sent 0))
    (declare (type (integer 0) sent))
    (handler-case
        (loop while (< sent len)
              do (let ((n (if (zerop sent)
                              (sb-bsd-sockets:socket-send socket buffer len)
                              (sb-bsd-sockets:socket-send socket (subseq buffer sent len) (- len sent)))))
                   (when (or (null n) (zerop n))
                     (error "dds.pal: tcp-send made no progress (sent ~d of ~d)" sent len))
                   (incf sent n)))
      (sb-bsd-sockets:socket-error (e)
        (error "dds.pal: tcp-send failed on stream socket: ~a" e)))
    len))

(defun* tcp-recv (socket buffer len)
    (function (t (simple-array (unsigned-byte 8) (*)) (integer 0)) (or null (integer 0)))
  "Receive exactly LEN octets into BUFFER[0..LEN) from stream SOCKET, looping over partial reads until
   the full frame is assembled (TCP is a byte stream — one frame may split across segments; a partial
   read is normal, NOT end-of-stream). Returns LEN, or NIL on EOF / peer-close / connection-reset
   before LEN bytes arrive (a torn or short read = the connection dropped). If SOCKET has a recv timeout
   armed (tcp-set-recv-timeout) and no data arrives within the deadline, SIGNALS PAL-TIMEOUT — a DISTINCT
   catchable outcome, NOT confused with a clean EOF (NIL): sb-bsd-sockets:socket-receive returns n=0 on a
   clean peer-close but n=NIL on an SO_RCVTIMEO timeout OR an EINTR-interrupted receive (verified identical
   on SBCL + Clasp), so this splits them. EINTR is thus CONSERVATIVELY classified as a timeout (n=NIL ⟸
   timeout OR EINTR) — the disposition is identical either way (drop / reconnect), so folding the rare
   interrupted-syscall case into PAL-TIMEOUT is safe and keeps the branch minimal. BUFFER must hold >= LEN
   octets. The first read lands straight in BUFFER; only a genuine split allocates one scratch buffer."
  (when (zerop len) (return-from tcp-recv 0))
  (let ((got 0) (scratch nil))
    (declare (type (integer 0) got))
    (flet ((step-outcome (n)          ; n>0 = data; n=0 = clean EOF -> NIL; n=NIL = SO_RCVTIMEO -> PAL-TIMEOUT
             (cond ((null n) (error 'pal-timeout :op 'tcp-recv))
                   ((zerop n) (return-from tcp-recv nil)))))
      (handler-case
          (loop while (< got len)
                do (if (zerop got)
                       (multiple-value-bind (b n) (sb-bsd-sockets:socket-receive socket buffer len)
                         (declare (ignore b))
                         (step-outcome n)
                         (setf got n))
                       (progn
                         (unless scratch
                           (setf scratch (make-array (- len got) :element-type '(unsigned-byte 8))))
                         (multiple-value-bind (b n) (sb-bsd-sockets:socket-receive socket scratch (- len got))
                           (declare (ignore b))
                           (step-outcome n)
                           (replace buffer scratch :start1 got :end1 (+ got n) :end2 n)
                           (incf got n)))))
        (sb-bsd-sockets:socket-error () (return-from tcp-recv nil))))
    len))

;; shutdown(2) SHUT_RDWR (disable BOTH directions of a connected stream socket). The value 2 is IDENTICAL
;; on Darwin (sys/socket.h) and Linux (bits/socket.h) — a POSIX/OS ABI constant, NOT impl-specific — so it
;; carries NO #+sbcl/#+clasp conditional (verified against both OS headers: SHUT_RD 0 / SHUT_WR 1 /
;; SHUT_RDWR 2 on each). Raw foreign-funcall like %setsockopt above (sb-bsd-sockets exposes no portable
;; shutdown across both impls); the fd comes from socket-file-descriptor, native on SBCL contrib + Clasp.
(defconstant +shut-rdwr+ 2
  "shutdown(2) SHUT_RDWR: disable both directions. Value 2 on Darwin + Linux (verified vs sys/socket.h).")

(defun* tcp-shutdown (socket &optional (direction +shut-rdwr+))
    (function (t &optional fixnum) t)
  "shutdown(2) stream SOCKET in DIRECTION (default +shut-rdwr+ = both directions). WAKES a thread blocked
   in tcp-recv on SOCKET on BOTH Darwin + Linux (portably — unlike tcp-close, which does not reliably
   unblock a foreign recv on Linux) and does NOT release the fd — so, unlike close, it never ITSELF orphans
   or reuses the fd. This is the cross-thread WAKE the durability microservice-server-stop sends a parked
   serve thread so the thread's OWN unwind does the single tcp-close (stop shuts down; the socket owner
   closes exactly once — no double-close TOCTOU). CAVEAT: the fd is read here via socket-file-descriptor, so
   if this is called CONCURRENTLY with the socket owner's tcp-close of the SAME socket, that read can be
   stale (mid-close: after close(2), before the impl writes fd=-1) and shutdown could then land on a
   just-freed/reused fd. tcp-shutdown does not itself serialize that — the CALLER must (microservice-server-
   stop shuts down + the owner closes both UNDER the registry lock, so the two are mutually exclusive; ADR
   0050 §4.8). Ignores the syscall return: a shutdown on an already-closed / already-shutdown /
   never-connected socket is a harmless no-op (callers wrap it in ignore-errors regardless)."
  (cffi:foreign-funcall "shutdown" :int (sb-bsd-sockets:socket-file-descriptor socket)
                        :int direction :int)
  t)

(defun* tcp-close (socket)
    (function (t) t)
  "Close stream SOCKET."
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
