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

;;; ---- monotonic clock (latency measurement + every RTPS timer deadline) ----
;; ONE clock, ONE code path, BOTH implementations (owner directive 2026-07-13: Clasp uses the CFFI clock too).
;; Two Clasp-specific costs had to be root-caused first — see *clock-gettime-fp* and *thread-timespec*.

(defparameter *clock-monotonic-id*
  (if (member :darwin *features*) 4 1)
  "clock_gettime(2) clk_id of the finest-grained MONOTONIC clock on this OS, chosen by MEASURED RESOLUTION,
   not by name — 4 = CLOCK_MONOTONIC_RAW on macOS, 1 = CLOCK_MONOTONIC on Linux (values read from the
   platform headers, verified against the installed SDK; never from memory).

   Picking by name is silently wrong in BOTH directions. macOS deliberately coarsens CLOCK_MONOTONIC (id 6)
   to a 1 us tick — useless for profiling a ~22 us path — while its RAW clock ticks at 41 ns. On Linux id 6 is
   CLOCK_MONOTONIC_COARSE (~ms) and the call SUCCEEDS, so a measurement taken with it is quantised into
   nonsense while still looking healthy; Linux's CLOCK_MONOTONIC (id 1) is the ns-resolution vDSO fast path.
   Computed from *FEATURES* rather than a reader conditional so this shared PAL file stays conditional-free.")

(defparameter *clock-gettime-fp*
  (cffi:foreign-symbol-pointer "clock_gettime")
  "The RESOLVED clock_gettime function pointer, looked up ONCE at load.

   WP-PERF, and this is a Clasp defect worth naming: calling a foreign function BY NAME on Clasp re-resolves
   the symbol on EVERY call. Measured on this machine — clock_gettime by name 4230 ns/call, and even a bare
   getpid() by name 4824 ns/call, versus 379 ns through a pre-resolved pointer. ~3.8 us of every by-name
   Clasp FFI call is dlsym. SBCL does not have this problem (13 ns either way), so it is invisible unless you
   measure Clasp. Every hot foreign call in this codebase must go through a cached pointer like this one.")

(defvar *thread-timespec* nil
  "A per-thread, pre-allocated 16-octet foreign `struct timespec` scratch for MONOTONIC-NS, bound by SPAWN
   for every PAL-created thread (receiver, sender, flow-control, liveliness, ...); NIL in a thread the PAL
   did not create, which then falls back to a per-call WITH-FOREIGN-OBJECT.

   WP-PERF, the second Clasp defect: WITH-FOREIGN-OBJECT is a real malloc on Clasp — measured 3790 ns/call
   for clock read + per-call buffer vs 518 ns with the buffer hoisted, i.e. ~3.3 us of foreign malloc EVERY
   call. (On SBCL it is stack-allocated and free: 12 ns either way.) The buffer must therefore be reused —
   but it CANNOT simply be a global, because the receiver thread and the user thread read the clock
   concurrently and would tear each other's timespec, corrupting a timestamp. Per-thread is the fix that is
   both fast and race-free.")

(defun* monotonic-ns ()
    (function () integer)
  "Monotonic time in NANOSECONDS (clock_gettime, *clock-monotonic-id*) — the timebase for every latency
   measurement and RTPS timer deadline. Reads the 16-octet struct timespec (tv_sec@0, tv_nsec@8, both 64-bit
   on the supported targets) into this thread's pre-allocated scratch. Falls back to the scaled
   internal-real-time clock if the syscall fails, so it never signals.

   Replaces the M0 (get-internal-real-time) implementation on BOTH impls. On SBCL that clock had ONE
   MICROSECOND of resolution (internal-time-units-per-second = 1e6), so every latency figure this project
   published was quantised to 1 us per timestamp — which is exactly why they all landed on multiples of 500 ns
   after RTT/2 — and segment-level profiling of a path whose segments are single microseconds was IMPOSSIBLE,
   not merely noisy. The PAL's own M1 note promised this fast path and it had never landed.

   Measured cost/resolution: SBCL 12 ns/call, 41 ns tick. Clasp 0.5 us/call, 41 ns tick — SAME clock, same
   resolution, but Clasp cannot reach SBCL's cost: after removing the per-call dlsym (*clock-gettime-fp*) and
   the per-call foreign malloc (*thread-timespec*), the ~0.5 us residual is Clasp's libffi dynamic dispatch,
   for which CFFI provides no direct-call compiler macro on Clasp (verified: COMPILER-MACRO-FUNCTION is NIL
   for FOREIGN-FUNCALL and FOREIGN-FUNCALL-POINTER there). That residual is upstream and not ours to remove.
   It is affordable because MONOTONIC-NS is NOT on the per-sample path — it serves blocking-wait deadlines,
   the flow-controller token bucket (opt-in async writers) and shmem stress loops."
  (flet ((read-clock (tp)
           (if (zerop (the (signed-byte 32)
                           (cffi:foreign-funcall-pointer
                            *clock-gettime-fp* () :int *clock-monotonic-id* :pointer tp :int)))
               (+ (* (cffi:mem-ref tp :int64 0) 1000000000) (cffi:mem-ref tp :int64 8))
               (truncate (* (get-internal-real-time)
                            (/ 1000000000 internal-time-units-per-second))))))
    (let ((tp *thread-timespec*))
      (if tp
          (read-clock tp)
          (cffi:with-foreign-object (tp2 :uint8 16) (read-clock tp2))))))

(defun* call-with-thread-clock (fn)
    (function (function) t)
  "Run FN with this thread's MONOTONIC-NS scratch timespec allocated and bound, freeing it on exit. SPAWN
   wraps every PAL thread in this; a non-PAL thread (the user's own) may wrap itself to get the fast clock
   path — the bench/profiling harness does exactly that."
  (let ((tp (cffi:foreign-alloc :uint8 :count 16)))
    (unwind-protect (let ((*thread-timespec* tp)) (funcall fn))
      (cffi:foreign-free tp))))

;;; ---- bulk octet copy to/from a foreign SAP (shared-memory rings, syscall buffers) ----

(defparameter *memcpy-fp*
  (cffi:foreign-symbol-pointer "memcpy")
  "The RESOLVED memcpy pointer, looked up ONCE at load. Cached for the same reason as *clock-gettime-fp*:
   a by-NAME foreign call on Clasp re-resolves the symbol every call (~3.8 us of dlsym). Every hot foreign
   call in this codebase goes through a cached pointer.")

(defun* sap-copy-in (sap offset vec voff len)
    (function (t (integer 0) (simple-array (unsigned-byte 8) (*)) (integer 0) (integer 0)) t)
  "Copy LEN octets from VEC[VOFF..] into the foreign region at SAP+OFFSET, in BULK (memcpy) when VEC is
   ALLOC-STATIC-backed (foreign, SAP-addressable), else element-wise.

   WP-PERF: the SHMEM ring wrote its payload into shared memory ONE BYTE AT A TIME through
   (setf (cffi:mem-ref sap :uint8 ...)) — ~11 ns/octet, the identical defect class the CDR codec had, in a
   different file. That was ~2.8 us of every 256 B %shmem-send. The element-wise branch is retained only for
   a GC-heap source vector (the unit tests pass one); every production payload is arena/static-backed, so it
   takes the memcpy."
  (if (static-vector-p vec)
      (cffi:foreign-funcall-pointer
       *memcpy-fp* () :pointer (cffi:inc-pointer sap offset)
       :pointer (cffi:inc-pointer (static-pointer vec) voff) :size len :pointer)
      (dotimes (i len) (setf (cffi:mem-ref sap :uint8 (+ offset i)) (aref vec (+ voff i)))))
  t)

(defun* sap-copy-out (sap offset vec voff len)
    (function (t (integer 0) (simple-array (unsigned-byte 8) (*)) (integer 0) (integer 0)) t)
  "Copy LEN octets from the foreign region at SAP+OFFSET into VEC[VOFF..], in BULK (memcpy) when VEC is
   ALLOC-STATIC-backed, else element-wise. The receive twin of SAP-COPY-IN — the SHMEM drain read its
   records out of shared memory one byte at a time for the same ~11 ns/octet."
  (if (static-vector-p vec)
      (cffi:foreign-funcall-pointer
       *memcpy-fp* () :pointer (cffi:inc-pointer (static-pointer vec) voff)
       :pointer (cffi:inc-pointer sap offset) :size len :pointer)
      (dotimes (i len) (setf (aref vec (+ voff i)) (cffi:mem-ref sap :uint8 (+ offset i)))))
  t)

(defun* spawn (fn &key name)
    (function (function &key (:name (or null string))) t)
  "Spawn a thread running FN, named NAME (default \"dds\"). Returns the thread. Identical on both impls
   (bordeaux-threads), so it lives here rather than being duplicated per-impl. The body runs inside
   CALL-WITH-THREAD-CLOCK so every PAL thread gets MONOTONIC-NS's pre-allocated per-thread timespec — without
   it, a clock read on a Clasp thread pays a ~3.3 us foreign malloc (see *thread-timespec*)."
  (bordeaux-threads:make-thread (lambda () (call-with-thread-clock fn)) :name (or name "dds")))

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

;; tcp-shutdown is defined below (same sb-bsd-sockets substrate); forward-declared so udp-close can use it.
(declaim (ftype (function (t &optional fixnum) t) tcp-shutdown))

(defun* udp-close (socket)
    (function (t) t)
  "Close SOCKET — SHUTTING IT DOWN FIRST (NFR-PORT).

   On LINUX, close(2) does NOT reliably unblock a thread parked in recvfrom(2) on this socket. Our UDP /
   multicast / SHMEM receiver threads park exactly there, and start-udp-receiver's contract was 'the thread
   exits when the socket is closed (udp-recv then signals)' — which is TRUE ON DARWIN AND FALSE ON LINUX.
   So stop-node closed the sockets and then JOINED the receiver threads, which were still blocked in
   recvfrom, and the join NEVER RETURNED: delete-participant hung, and THE STACK COULD NOT SHUT DOWN ON
   LINUX AT ALL — the platform the operating contract calls primary (§9).

   shutdown(2) DOES wake a blocked recv, portably, on both Darwin and Linux. THIS REPO ALREADY KNEW THAT and
   says so in tcp-shutdown's own docstring, added for the durability microservice server — the UDP path
   simply never got the same treatment.

   Found by CI on Linux (traced: ENTER stop-node -> the goodbye completes -> no LEAVE). NO LOCAL macOS RUN
   COULD EVER HAVE SEEN IT, and there was no CI until this week."
  (ignore-errors (tcp-shutdown socket))      ; wake any thread parked in udp-recv, THEN release the fd
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
