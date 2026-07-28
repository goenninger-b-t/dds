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

(defvar *thread-atomic-cell* nil
  "A per-thread, pre-allocated 8-octet foreign cell holding the EXPECTED operand of a compare-and-swap,
   bound by SPAWN for every PAL-created thread; NIL in a thread the PAL did not create, which then falls
   back to a per-call WITH-FOREIGN-OBJECT.

   Needed only by the Clasp PAL, whose CAS goes through the C atomic runtime (__atomic_compare_exchange_N),
   and that ABI takes EXPECTED **by pointer** — it writes the actual value back on failure. A per-call
   foreign cell would therefore put a WITH-FOREIGN-OBJECT on the CAS retry loop, which on Clasp is a real
   malloc (~3.3 us/call — the same defect that motivated *THREAD-TIMESPEC*), and CAS sits in the SHMEM lane
   claim and the zero-copy refcount, i.e. the hot path. Per-thread is the fix that is both fast and
   race-free: two threads CASing concurrently must not share one EXPECTED cell or they tear each other's
   operand. Carved out of the SAME allocation as *THREAD-TIMESPEC* (one foreign-alloc per thread).")

(defvar *thread-sockaddr* nil
  "A per-thread, pre-allocated 16-octet foreign `struct sockaddr_in` destination scratch for
   UDP-SEND-TO's raw-sendto(2) path, bound by SPAWN for every PAL-created thread; NIL in a thread the
   PAL did not create, which then falls back to a per-call WITH-FOREIGN-OBJECT.

   WP-PERF (NFR-MEM): the sb-bsd-sockets SOCKET-SEND path allocated 360 B on EVERY datagram — ~262 B of
   it the four PARSE-INTEGER calls inside %PARSE-IPV4 re-parsing the dotted-quad destination STRING per
   send, the rest SOCKET-SEND's own keyword/generic-dispatch/alien-sockaddr overhead. One ACKNACK rides
   this path per received sample, so it was ~12 % of the whole measured per-sample allocation budget
   (ADR 0062). Filling a pre-allocated 16-octet block costs nothing and allocates nothing.

   Per-THREAD, not global, for the same reason as *THREAD-TIMESPEC*: several threads send on one socket
   concurrently (each receiver thread answers HEARTBEATs while the user thread announces), and a torn
   destination address is SILENT MIS-DELIVERY — a datagram to the wrong peer, not a crash. Carved out of
   the SAME allocation as *THREAD-TIMESPEC* / *THREAD-ATOMIC-CELL* (one foreign-alloc per thread).")

(defun* call-with-thread-clock (fn)
    (function (function) t)
  "Run FN with this thread's per-thread foreign scratch allocated and bound, freeing it on exit: the
   MONOTONIC-NS timespec (*THREAD-TIMESPEC*, 16 octets), the CAS expected-operand cell
   (*THREAD-ATOMIC-CELL*, 8 octets) and the UDP-SEND-TO destination sockaddr (*THREAD-SOCKADDR*,
   16 octets) are carved from ONE 40-octet allocation. SPAWN wraps every PAL thread in this; a non-PAL
   thread (the user's own) may wrap itself to get the fast clock + CAS + send paths — the bench/profiling
   harness does exactly that. The timespec occupies [0,16), the CAS cell [16,24) and the sockaddr [24,40);
   every one is at least 4-aligned because foreign-alloc returns at least 16-byte-aligned memory."
  (let ((tp (cffi:foreign-alloc :uint8 :count 40)))
    (unwind-protect (let ((*thread-timespec* tp)
                          (*thread-atomic-cell* (cffi:inc-pointer tp 16))
                          (*thread-sockaddr* (cffi:inc-pointer tp 24)))
                      (funcall fn))
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

(defun* process-id ()
    (function () (unsigned-byte 32))
  "This process's OS process id (POSIX getpid(2), IEEE Std 1003.1). A CFFI foreign call to the POSIX
   symbol, so it is implementation-agnostic and needs no reader conditional (getpid never fails and
   takes no argument). Masked to 32 bits for the LogEvent `process` key (ADR 0082 §3), so logged
   samples key per originating process; a pid_t is well within 32 bits on the supported targets."
  (logand (cffi:foreign-funcall "getpid" :int) #xffffffff))

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
    (function (t fixnum fixnum list) (values (or null fixnum) (or null keyword)))
  "Raw setsockopt(fd, LEVEL, OPT, BYTES) via CFFI for options sb-bsd-sockets does not expose. BYTES is
   the option value as a list of octets. Returns (values rc NIL) on success, (values NIL :SETSOCKOPT-FAILED)
   on a non-zero return — it NEVER signals (operating contract: no Lisp conditions in our code; a failure
   is a status value threaded to the caller, never a stack unwind)."
  (let ((fd (sb-bsd-sockets:socket-file-descriptor socket))
        (n (length bytes)))
    (cffi:with-foreign-object (p :uint8 n)
      (loop for i from 0 for b in bytes do (setf (cffi:mem-aref p :uint8 i) b))
      (let ((rc (cffi:foreign-funcall "setsockopt" :int fd :int level :int opt
                                      :pointer p :uint n :int)))
        (if (zerop rc) (values rc nil) (bail :setsockopt-failed))))))

(defun* udp-set-reuse-port (socket)
    (function (t) (values t (or null keyword)))
  "Enable SO_REUSEPORT so multiple participants on one host can share the SPDP multicast port. Must be
   called before bind. Returns (values T NIL), or (values NIL :SETSOCKOPT-FAILED) if the option is refused."
  (try (%setsockopt socket +sol-socket+ +so-reuseport+ '(1 0 0 0)))
  (values t nil))

;; tcp-set-recv-timeout is defined below (same sb-bsd-sockets substrate); forward-declared so the UDP
;; receive timeout can delegate to it rather than re-encode struct timeval a second time (DRY).
(declaim (ftype (function (t (real 0)) (values t (or null keyword))) tcp-set-recv-timeout))

(defparameter *join-timeout-seconds* 5
  "Deadline for a TEARDOWN join (dds.pal:join-bounded). NIL waits forever — the pre-fix behaviour.")

(defvar *stuck-teardown-lock* (make-lock "dds-stuck-teardown")
  "Guards *STUCK-TEARDOWN-JOINS*. Teardown-cold — never taken on a per-sample path, so a plain mutex here
   costs the hot path nothing (NFR-MEM/FR-LANG-0 are unaffected).")

(defvar *stuck-teardown-joins* nil
  "THE REPORT: every teardown wait that hit its deadline, as an alist of (SITE . COUNT) keyed by the SITE
   keyword its waiter passed. Read it with DDS.PAL:STUCK-TEARDOWN-JOINS — never directly, the read must
   take *STUCK-TEARDOWN-LOCK*.

   ⚠️ IT MUST BE EMPTY AFTER A HEALTHY RUN. A non-NIL entry means a thread outlived its deadline, so
   whatever that wait GUARDED — a FREE-STATIC, a SHM-DETACH, a STORE-CLOSE, a DELETE-PARTICIPANT — was
   deliberately SKIPPED and the resource LEAKED. That is the intended outcome (a bounded leak beats a
   use-after-free on a live thread), but it is a defect report, not a normal condition. This is the
   REPORTED-not-printed form the operating contract requires: a queryable snapshot, like
   DDS.LOG:LOGGER-SHED-COUNTS and DDS.DISC:DISC-NODE-STUCK-RECEIVER-TEARDOWNS.")

(defun* note-stuck-teardown (site)
    (function (keyword) (eql t))
  "Record ONE teardown wait at SITE that hit its deadline, incrementing SITE's count in
   *STUCK-TEARDOWN-JOINS*. Called by JOIN-BOUNDED on :TIMEOUT, and directly by the bounded waits that are
   NOT joins — the flow-controller per-node EMIT BARRIER — so every deadline in the codebase reports
   through ONE counter and no call site can forget to. Returns T."
  (with-lock (*stuck-teardown-lock*)
    (let ((cell (assoc site *stuck-teardown-joins* :test #'eq)))
      (if cell
          (setf (cdr cell) (1+ (cdr cell)))
          (push (cons site 1) *stuck-teardown-joins*))))
  t)

(defun* stuck-teardown-joins ()
    (function () (values (integer 0) list))
  "SNAPSHOT of the teardown-deadline report: (VALUES TOTAL ALIST), where TOTAL is the number of waits that
   hit their deadline across the whole process and ALIST is a FRESH copy of the per-SITE (SITE . COUNT)
   breakdown. TOTAL is 0 and ALIST NIL in a healthy run — a non-zero TOTAL means a resource was leaked on
   purpose rather than freed under a still-live thread (see *STUCK-TEARDOWN-JOINS*). Copied under the lock
   so a concurrent teardown's increment cannot tear the read."
  (with-lock (*stuck-teardown-lock*)
    (let ((snap (copy-alist *stuck-teardown-joins*)))
      (values (reduce #'+ snap :key #'cdr :initial-value 0) snap))))

(defun* reset-stuck-teardown-joins ()
    (function () (eql t))
  "Clear the teardown-deadline report so a subsequent STUCK-TEARDOWN-JOINS measures only what follows.
   For tests that deliberately provoke a deadline (the falsification of JOIN-BOUNDED) and for a long-lived
   service that has consumed the report; production teardown never calls it."
  (with-lock (*stuck-teardown-lock*) (setf *stuck-teardown-joins* nil))
  t)

(defun* join-bounded (thread &optional (site :unspecified) (timeout *join-timeout-seconds*))
    (function (t &optional keyword (or null (real 0))) (values t (or null keyword)))
  "JOIN THREAD, but give up after TIMEOUT seconds: (values result NIL) if it finished, (values NIL :TIMEOUT)
   if it did not. NIL TIMEOUT is an unbounded join (dds.pal:join). SITE names the call site for the
   deadline REPORT — on :TIMEOUT this calls NOTE-STUCK-TEARDOWN, so the failure is counted where it is
   DETECTED and a caller cannot silently drop it by ignoring the status value. SITE precedes TIMEOUT in the
   lambda list because every teardown supplies a site name and almost none overrides the deadline.

   ⚠️ WHY A BOUNDED JOIN IS NECESSARY AND A BOUNDED RECEIVE IS NOT SUFFICIENT. A UDP receiver already parked
   in recvfrom(2) when another thread closes its fd is NOT rescued by SO_RCVTIMEO — observed directly:
   `#<INET-SOCKET fd: -1>` still inside UDP-RECV minutes later, while a freshly-opened socket with the same
   option returns in 0.256 s. shutdown(2) does not rescue it either on macOS (ENOTCONN on an unconnected
   UDP socket). So teardown CANNOT be made to depend on the receiver noticing anything: the only thing that
   terminates it unconditionally is refusing to wait forever.

   ⚠️ A TIMED-OUT JOIN MUST NOT BE TREATED AS SUCCESS. The joins in stop-node exist to guarantee no receiver
   is still touching a buffer before it is freed. On :TIMEOUT the caller MUST skip those frees and LEAK —
   a leaked buffer is bounded and harmless, a use-after-free on a live receiver thread is neither. This is
   the same ranking the ZC refcount code already applies (an under-count is worse than a leak).

   Portable by polling THREAD-ALIVE-P rather than an impl-specific timed join, so it carries no reader
   conditional (NFR-PORT)."
  (if (null timeout)
      (values (join thread) nil)
      (let ((deadline (+ (get-internal-real-time)
                         (* timeout internal-time-units-per-second))))
        (loop
          (unless (bordeaux-threads:thread-alive-p thread)
            (return (values (ignore-errors (join thread)) nil)))
          (when (> (get-internal-real-time) deadline)
            (note-stuck-teardown site)   ; REPORT at the point of DETECTION — a caller cannot drop it
            (return (values nil :timeout)))
          (sleep 0.005)))))

(defparameter *udp-receive-timeout-seconds* 0.25
  "Receive timeout armed on every UDP socket so a parked recvfrom(2) cannot outlive its socket.
   0 disables it (restoring the pre-fix teardown race). Read once per socket, at udp-open.")

(defun* udp-set-receive-timeout (socket &optional (seconds *udp-receive-timeout-seconds*))
    (function (t &optional (real 0)) (values t (or null keyword)))
  "Arm SO_RCVTIMEO on datagram SOCKET (delegates to TCP-SET-RECV-TIMEOUT — same option, same portable
   struct timeval encoding, so this adds no second copy of that reasoning).

   ⚠️ THIS IS WHAT MAKES TEARDOWN TERMINATE, and it replaces a per-OS syscall side-effect with something
   that does not vary. UDP-CLOSE shuts the socket down before closing it and its docstring claimed the
   receiver 'exits when the socket is closed — TRUE ON DARWIN'. THAT CLAIM IS FALSE: shutdown(2) on an
   UNCONNECTED UDP socket fails ENOTCONN on macOS/BSD and wakes nothing (the ignore-errors swallows it), so
   a receiver already inside recvfrom when close lands stays parked FOREVER on a closed fd — observed as
   `#<INET-SOCKET fd: -1>` in a live backtrace, with STOP-NODE's unbounded join blocked behind it at 0.0%
   CPU and the whole suite hung. INTERMITTENT, because it needs the thread to be inside the syscall at that
   moment.

   With a bounded receive the loop wakes within SECONDS, calls udp-recv again on the now-closed fd, and
   takes the ordinary closed-socket exit — termination no longer depends on whether shutdown(2) happens to
   work for this OS and socket kind. Cost: 1/SECONDS idle wakeups per receiver thread, off the data path (a
   datagram still returns immediately). A timeout surfaces as a negative size, which START-UDP-RECEIVER
   already treats as transient and retries, so no caller changes."
  (tcp-set-recv-timeout socket seconds))

(defun* udp-open (&key (host "0.0.0.0") (port 0) reuse-port)
    (function (&key (:host string) (:port (integer 0 65535)) (:reuse-port t)) (values t (or null keyword)))
  "Open a UDPv4 socket bound to HOST:PORT (port 0 = ephemeral). REUSE-PORT enables SO_REUSEPORT before
   bind (shared multicast port). Returns (values socket NIL), or (values NIL :SETSOCKOPT-FAILED) if
   SO_REUSEPORT is refused — in which case the half-open socket is CLOSED before returning, so a failed
   open leaks no file descriptor."
  (let ((s (make-instance 'sb-bsd-sockets:inet-socket :type :datagram :protocol :udp)))
    (setf (sb-bsd-sockets:sockopt-reuse-address s) t)
    (when reuse-port
      (multiple-value-bind (ok status) (udp-set-reuse-port s)
        (declare (ignore ok))
        (when status
          (sb-bsd-sockets:socket-close s)
          (bail status))))
    (sb-bsd-sockets:socket-bind s (%parse-ipv4 host) port)
    ;; Bounded receive so a parked recvfrom cannot outlive the socket — see udp-set-receive-timeout.
    ;; Best-effort: a platform refusing SO_RCVTIMEO still works, it just reverts to the old teardown race.
    (multiple-value-bind (ok status) (udp-set-receive-timeout s) (declare (ignore ok status)) nil)
    (values s nil)))

(defun* udp-local-port (socket)
    (function (t) (integer 0 65535))
  "The bound local port of SOCKET."
  (nth-value 1 (sb-bsd-sockets:socket-name socket)))

;;; ---- raw sendto(2) datagram fast path (NFR-MEM: zero allocation per datagram) ----

(defparameter *sendto-fp*
  (cffi:foreign-symbol-pointer "sendto")
  "The RESOLVED sendto(2) function pointer, looked up ONCE at load — never by name per call.
   Same rule, and same reason, as *CLOCK-GETTIME-FP*: a by-name foreign call re-resolves the symbol
   through dlsym on EVERY call on Clasp (~3.8 us measured), and this one sits on the ACKNACK /
   discovery-announce send path.")

(defparameter *recvfrom-fp*
  (cffi:foreign-symbol-pointer "recvfrom")
  "The RESOLVED recvfrom(2) function pointer, looked up ONCE at load. Same rule and reason as
   *SENDTO-FP*: never resolve a foreign symbol by name on a datagram path. Used by UDP-RECV.")

(defparameter *null-sap*
  (cffi:null-pointer)
  "The NULL foreign pointer, boxed ONCE at load — recvfrom's src_addr/addrlen when the sender address
   is not wanted. Address 0 is reload-stable, so unlike *SENDTO-FP* / *RECVFROM-FP* it needs no
   image-restart re-resolution (the same carve-out dds.dare makes for its *%NULL-PTR*).")

(defconstant +sockaddr-in-bytes+ 16
  "sizeof(struct sockaddr_in) — 16 octets on both supported targets. Layouts, read from the platform
   headers (never reconstructed from memory), differ ONLY in the first two octets:

     Darwin (MacOSX.sdk/usr/include/netinet/in.h, sys/socket.h AF_INET = 2):
       sin_len(u8)@0=16  sin_family(u8)@1=AF_INET  sin_port(u16 net)@2  sin_addr(u32 net)@4  sin_zero[8]@8
     Linux/glibc (POSIX 1003.1 <netinet/in.h>) — no sin_len, sin_family is a 2-octet host-order field:
       sin_family(u16 host)@0=AF_INET             sin_port(u16 net)@2  sin_addr(u32 net)@4  sin_zero[8]@8

   Everything from sin_port on is identical, and both fields from sin_port on are NETWORK byte order.
   A WRONG prefix does not corrupt memory: the kernel rejects the family and sendto(2) returns -1, so
   the datagram is dropped LOUDLY (the loopback delivery assertion in the PAL udp test fails). CI/Linux
   is the oracle for the non-Darwin branch — macOS cannot see it.")

(defparameter *sockaddr-in-prefix-0*
  (if (member :darwin *features*) +sockaddr-in-bytes+ 2)
  "Octet 0 of a struct sockaddr_in: BSD's sin_len (= 16), or the low octet of Linux's little-endian
   2-octet sin_family (AF_INET = 2). Computed from *FEATURES* rather than a reader conditional so this
   shared PAL file stays conditional-free (the *CLOCK-MONOTONIC-ID* pattern). 64-bit little-endian only
   (REQUIREMENTS §8).")

(defparameter *sockaddr-in-prefix-1*
  (if (member :darwin *features*) 2 0)
  "Octet 1 of a struct sockaddr_in: BSD's sin_family (AF_INET = 2), or the high octet of Linux's
   little-endian 2-octet sin_family (0). See *SOCKADDR-IN-PREFIX-0*.")

(defvar *udp-raw-sendto* t
  "T (the default): UDP-SEND-TO builds its destination in a pre-allocated foreign sockaddr and calls
   sendto(2) directly — zero allocation per datagram. NIL: the original sb-bsd-sockets SOCKET-SEND
   path, which allocates ~360 B per datagram.

   The datagram BYTES ON THE WIRE are identical either way; only the syscall wrapper differs. Kept as
   the A/B lever for the NFR-MEM measurement (ADR 0062 requires every allocation change to be sized by
   a flag A/B against `make gate-mem`) and as an escape hatch should a platform's struct sockaddr_in
   layout differ from the two documented at +SOCKADDR-IN-BYTES+.")

(defun* %fill-sockaddr-in (sa host port)
    (function (t string (integer 0 65535)) t)
  "Fill the 16-octet foreign struct sockaddr_in at SA with dotted-quad HOST and PORT, ALLOCATING
   NOTHING. Replaces (list (%parse-ipv4 host) port), whose four PARSE-INTEGER calls cons ~262 B per
   send; the digits are accumulated in a fixnum instead.

   TOTAL AND BOUNDED (NFR-SEC-POSTURE): HOST derives from a peer's advertised locator, i.e. from wire
   data, so the walk NEVER writes outside sin_addr's four octets [4,8) — the octet index is capped at 4
   and each accumulated value is masked to 8 bits. A malformed HOST therefore yields some well-formed
   address whose datagram simply goes nowhere (UDP is best-effort and the reliable layer recovers), and
   can never corrupt the block or the memory after it."
  (setf (cffi:mem-ref sa :uint8 0) *sockaddr-in-prefix-0*
        (cffi:mem-ref sa :uint8 1) *sockaddr-in-prefix-1*
        (cffi:mem-ref sa :uint8 2) (ldb (byte 8 8) port)      ; sin_port, network byte order
        (cffi:mem-ref sa :uint8 3) (ldb (byte 8 0) port))
  (let ((acc 0) (octet 0) (n (length host)))
    (declare (type fixnum acc n) (type (integer 0 4) octet))
    (dotimes (i n)
      (let ((ch (char host i)))
        (cond ((char= ch #\.)
               (when (< octet 4)
                 (setf (cffi:mem-ref sa :uint8 (+ 4 octet)) (logand acc #xff))
                 (incf octet))
               (setf acc 0))
              (t (setf acc (+ (* acc 10) (logand (- (char-code ch) 48) #xff)))))))
    (when (< octet 4)
      (setf (cffi:mem-ref sa :uint8 (+ 4 octet)) (logand acc #xff))
      (incf octet))
    (loop while (< octet 4)                                   ; a short HOST leaves the rest zero
          do (setf (cffi:mem-ref sa :uint8 (+ 4 octet)) 0) (incf octet)))
  (dotimes (i 8) (setf (cffi:mem-ref sa :uint8 (+ 8 i)) 0))   ; sin_zero
  t)

(defun* udp-send-to (socket buffer length host port)
    (function (t (simple-array (unsigned-byte 8) (*)) (integer 0) string (integer 0 65535)) t)
  "Send LENGTH octets of BUFFER from SOCKET to HOST:PORT. Returns sendto(2)'s value — the octet count
   sent, or NEGATIVE on failure. UDP is best-effort: a failed send (an unreachable / stale / 0.0.0.0
   placeholder locator, a down interface) is DROPPED by the caller, never fatal, and the reliable layer
   recovers via HEARTBEAT/ACKNACK.

   BUFFER SHOULD be PAL-static (DDS.PAL:ALLOC-STATIC), and the raw path is now TAKEN ONLY IF IT IS —
   the STATIC-VECTOR-P test above is the enforcement, not a comment. NFR-MEM is explicit that any buffer
   addressed by a pointer/SAP is foreign/static and never a plain heap array: SBCL's and AllegroCL's GCs
   MOVE objects, so a heap vector's SAP can be invalidated underneath the syscall and the kernel then
   reads whatever now occupies that address — wrong bytes on the wire, and heap contents disclosed to a
   remote peer. That was NOT hypothetical: DDS.LOG:MAKE-UDP-SYSLOG-SINK passed the freshly-consed UTF-8
   octets of each syslog line straight through here (found by an audit of STATIC-POINTER's callers).
   A heap BUFFER now takes the SOCKET-SEND path, which is GC-safe, instead. This mirrors SAP-COPY-OUT,
   which has always chosen memcpy-vs-element-wise on exactly this predicate. The hot dataplane
   (DDS.XPORT.UDP:MAKE-UDP-TRANSPORT) passes an octet-buffer vec, PAL-backed by construction, so it keeps
   the raw path with no behaviour change; the cost is one predicate per datagram.

   Set *UDP-RAW-SENDTO* to NIL to force the sb-bsd-sockets SOCKET-SEND path; the wire bytes are identical."
  (if (and *udp-raw-sendto* (static-vector-p buffer))   ; NFR-MEM: the raw path is taken ONLY for a genuinely static buffer — see below
      (flet ((send (sa)
               (%fill-sockaddr-in sa host port)
               (cffi:foreign-funcall-pointer
                *sendto-fp* ()
                :int (sb-bsd-sockets:socket-file-descriptor socket)
                :pointer (static-pointer buffer)
                :unsigned-long length
                :int 0                                        ; flags
                :pointer sa
                :unsigned-int +sockaddr-in-bytes+
                :long)))
        (let ((sa *thread-sockaddr*))
          (if sa
              (send sa)
              (cffi:with-foreign-object (sa2 :uint8 +sockaddr-in-bytes+) (send sa2)))))
      (sb-bsd-sockets:socket-send socket buffer length :address (list (%parse-ipv4 host) port))))

(defun* %pal-reresolve-foreign-pointers ()
    (function () (eql t))
  "Re-resolve every libc foreign-symbol pointer this file caches at load time, after an image restart.
   A dumped core CANNOT carry a live foreign address across save-lisp-and-die — the symbol is re-linked
   at startup, so a pointer captured before the dump dangles, and the first call through it is undefined
   behaviour rather than a clean failure. Mirrors dds.dare's %DARE-RERESOLVE-FOREIGN-POINTERS, so any
   build that dumps a core (a delivered durability-service executable) re-resolves libc on startup.

   *CLOCK-GETTIME-FP* predates this hook and carried the identical exposure with no hook at all; it is
   covered here rather than growing a second one-off. *NULL-SAP* is address 0 and is reload-stable, so
   it is intentionally left alone. Idempotent — re-resolving a live pointer is a no-op."
  (setf *clock-gettime-fp* (cffi:foreign-symbol-pointer "clock_gettime")
        *sendto-fp* (cffi:foreign-symbol-pointer "sendto")
        *recvfrom-fp* (cffi:foreign-symbol-pointer "recvfrom"))
  t)

(eval-when (:load-toplevel :execute)
  (register-image-restart-hook '%pal-reresolve-foreign-pointers))

(defvar *udp-raw-recvfrom* t
  "T (the default): UDP-RECV calls recvfrom(2) directly with src_addr = NULL — zero allocation per
   datagram received, and NO sender address is reported. NIL: the original sb-bsd-sockets
   SOCKET-RECEIVE path, which allocates ~305 B per datagram, most of it building a sender sockaddr
   and converting it to a Lisp address.

   NOTHING IN THE STACK USES THE SENDER ADDRESS. RTPS identifies a source by the GuidPrefix in the
   message header, never by IP (RTPS 2.5 §8.3.3); START-UDP-RECEIVER takes only (nth-value 0 ...) and
   the two remaining callers both (declare (ignore addr senderport)). Reporting it cost a sockaddr,
   an address conversion and a generic-function dispatch on every datagram we receive.

   A/B lever for the NFR-MEM measurement (ADR 0062) and escape hatch, as *UDP-RAW-SENDTO* is.")

(defun* udp-recv (socket buffer length)
    (function (t (simple-array (unsigned-byte 8) (*)) (integer 0)) t)
  "Block until a datagram arrives; return (values SIZE STATUS). Used from a dedicated receiver thread.
   The SENDER ADDRESS IS NOT REPORTED — see *UDP-RAW-RECVFROM* for why nothing needs it.

   STATUS is :CLOSED when the socket has been closed and the receiver loop must EXIT; NIL otherwise.
   A NEGATIVE size with a NIL status is a TRANSIENT failure and the loop must simply receive again.

   THE DISTINCTION IS LOAD-BEARING AND CI FOUND IT THE HARD WAY. recvfrom(2) reports a closed socket by
   RETURNING -1, where SOCKET-RECEIVE reported it by SIGNALLING — but -1 ALSO means EINTR, and on Linux
   SBCL stops threads for GC with a signal, so a blocked recvfrom is interrupted routinely. Treating
   every -1 as 'closed' therefore KILLED RECEIVER THREADS MID-RUN under GC pressure: green on macOS,
   red on Linux. SOCKET-RECEIVE hid this by retrying EINTR internally.
   The precise test is the SOCKET, not the return value: SOCKET-CLOSE resets the descriptor slot to -1
   on BOTH implementations (verified, not assumed), so fd < 0 means closed and nothing else. That is
   also what makes this safe against fd reuse — the socket object never hands back a recycled
   descriptor belonging to some other socket.

   A ZERO size is NOT an exit condition either: a zero-length UDP datagram is legal, so treating it as
   end-of-stream would let any peer kill a receiver thread by sending one (NFR-SEC-POSTURE). On Linux a
   shutdown(2)-woken recvfrom also returns 0, indistinguishable from that; UDP-CLOSE closes the socket
   immediately after shutting it down, so the fd goes to -1 and the next call reports :CLOSED.

   On the *UDP-RAW-RECVFROM* NIL path a closed socket still SIGNALS (SOCKET-RECEIVE's behaviour), so
   STATUS is always NIL there and the caller's handler is what ends the loop.

   BUFFER SHOULD be PAL-static (DDS.PAL:ALLOC-STATIC), and the raw path is TAKEN ONLY IF IT IS — the
   STATIC-VECTOR-P test above enforces it (see UDP-SEND-TO for the full rationale). This direction is the
   DANGEROUS one: the kernel WRITES up to LENGTH octets through the raw pointer, so a GC-heap buffer whose
   address the GC has since invalidated means recvfrom(2) scribbles a whole datagram over unrelated live
   Lisp objects — heap corruption that surfaces later as a GC fault far from its cause. A heap BUFFER now
   takes the GC-safe SOCKET-RECEIVE path instead (NFR-MEM)."
  (if (and *udp-raw-recvfrom* (static-vector-p buffer))   ; NFR-MEM: the raw path is taken ONLY for a genuinely static buffer — see udp-send-to
      (let ((n (cffi:foreign-funcall-pointer
                *recvfrom-fp* ()
                :int (sb-bsd-sockets:socket-file-descriptor socket)
                :pointer (static-pointer buffer)
                :unsigned-long length
                :int 0                                      ; flags
                :pointer *null-sap*                         ; src_addr — sender not wanted
                :pointer *null-sap*                         ; addrlen
                :long)))
        (if (and (minusp n) (minusp (sb-bsd-sockets:socket-file-descriptor socket)))
            (values n :closed)                              ; fd reset to -1 => really closed
            (values n nil)))                                ; EINTR and friends => receive again
      (multiple-value-bind (buf size) (sb-bsd-sockets:socket-receive socket buffer length)
        (declare (ignore buf))
        (values size nil))))

(defun* udp-join-multicast (socket group)
    (function (t string) (values t (or null keyword)))
  "Join the IPv4 multicast GROUP (dotted-quad) on the default interface and enable loopback
   (RTPS 2.5 §9.6.1.1). ip_mreq = imr_multiaddr(group) + imr_interface (INADDR_ANY). The socket must
   already be bound to the multicast port. Returns (values T NIL), or (values NIL :SETSOCKOPT-FAILED) if
   either the membership or the loopback option is refused (a node that cannot join the SPDP group cannot
   discover anyone — the caller must surface it, not proceed deaf)."
  (let ((g (%parse-ipv4 group)))
    (try (%setsockopt socket +ipproto-ip+ +ip-add-membership+
                      (list (aref g 0) (aref g 1) (aref g 2) (aref g 3) 0 0 0 0)))
    (try (%setsockopt socket +ipproto-ip+ +ip-multicast-loop+ '(1)))
    (values t nil)))

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

   ⚠️ CORRECTED 2026-07-27 — THE 'TRUE ON DARWIN' ABOVE IS FALSE, and believing it cost an investigation.
   shutdown(2) on an UNCONNECTED UDP socket fails ENOTCONN on macOS/BSD and wakes NOTHING; the ignore-errors
   below swallows that. A receiver already inside recvfrom when close lands stays parked FOREVER on a closed
   fd — caught in a live backtrace as `#<INET-SOCKET fd: -1>` with stop-node's join blocked behind it at
   0.0% CPU. Darwin is RACY here, not correct. Termination no longer relies on this at all: every UDP socket
   is opened with a bounded receive (udp-set-receive-timeout), so the loop wakes and exits regardless of
   what shutdown(2) did. The shutdown stays because it IS the fast path on Linux.

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
    (function (t) (values t (or null keyword)))
  "Route a write-to-closed-peer to EPIPE (SOCKET-ERROR) rather than SIGPIPE. Darwin: SO_NOSIGPIPE;
   elsewhere a no-op (the runtime ignores SIGPIPE process-wide). Returns (values T NIL) or
   (values NIL :SETSOCKOPT-FAILED)."
  (declare (ignorable socket))
  #+darwin (try (%setsockopt socket +sol-socket+ +so-nosigpipe+ '(1 0 0 0)))
  (values t nil))

(defun* tcp-connect (host port)
    (function (string (integer 0 65535)) (values t (or null keyword)))
  "Open a TCPv4 stream socket connected to HOST:PORT. Returns (values socket NIL), or
   (values NIL :SETSOCKOPT-FAILED) if SIGPIPE suppression is refused (the socket is closed first, so a
   failed connect leaks no fd)."
  (let ((s (make-instance 'sb-bsd-sockets:inet-socket :type :stream :protocol :tcp)))
    (multiple-value-bind (ok status) (%tcp-suppress-sigpipe s)
      (declare (ignore ok))
      (when status (sb-bsd-sockets:socket-close s) (bail status)))
    (sb-bsd-sockets:socket-connect s (%parse-ipv4 host) port)
    (values s nil)))

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
    (function (t) (values t (or null keyword)))
  "Block until a client connects to LISTENER; return (values connected-socket NIL) with SIGPIPE
   suppressed, or (values NIL :SETSOCKOPT-FAILED) if the suppression is refused (the accepted socket is
   closed first, so a failed accept leaks no fd)."
  (let ((s (sb-bsd-sockets:socket-accept listener)))
    (multiple-value-bind (ok status) (%tcp-suppress-sigpipe s)
      (declare (ignore ok))
      (when status (sb-bsd-sockets:socket-close s) (bail status)))
    (values s nil)))

(defun* tcp-local-port (listener)
    (function (t) (integer 0 65535))
  "The bound local port of LISTENER (read an ephemeral port after a port-0 bind)."
  (nth-value 1 (sb-bsd-sockets:socket-name listener)))

(defun* tcp-set-recv-timeout (socket seconds)
    (function (t (real 0)) (values t (or null keyword)))
  "Arm SO_RCVTIMEO on stream SOCKET so a blocking tcp-recv that makes no progress for SECONDS returns the
   status :TIMEOUT (a DISTINCT outcome, not a clean-EOF :EOF and not data) instead of blocking forever —
   the read/idle DoS guard for the durability microservice (ADR 0050 §4.6, operating contract
   §4). SECONDS 0 clears the timeout (block indefinitely, the default). Returns (values T NIL) or
   (values NIL :SETSOCKOPT-FAILED). The option value is a 16-byte
   struct timeval: tv_sec as 8 little-endian octets, then tv_usec (< 10^6, so < 2^32) as 4 little-endian
   octets + 4 zero octets — a layout valid for BOTH the Darwin int32 tv_usec (offset 8, 4 tail-pad bytes)
   AND the Linux long tv_usec (offset 8, 8 bytes), so ONE encoding is portable across OSes. SO_RCVTIMEO
   optname is OS-specific (+so-rcvtimeo+: Darwin #x1006 / Linux 20), like the SO_REUSEPORT constants above
   — never impl-specific, so this carries no #+sbcl/#+clasp conditional. Reuses %setsockopt (DRY)."
  (let* ((sec (floor seconds))
         (usec (floor (* (- seconds sec) 1000000))))
    (try (%setsockopt socket +sol-socket+ +so-rcvtimeo+
                      (list (ldb (byte 8 0) sec)  (ldb (byte 8 8) sec)  (ldb (byte 8 16) sec) (ldb (byte 8 24) sec)
                            (ldb (byte 8 32) sec) (ldb (byte 8 40) sec) (ldb (byte 8 48) sec) (ldb (byte 8 56) sec)
                            (ldb (byte 8 0) usec) (ldb (byte 8 8) usec) (ldb (byte 8 16) usec) (ldb (byte 8 24) usec)
                            0 0 0 0)))
    (values t nil)))

(defun* tcp-send (socket buffer len)
    (function (t (simple-array (unsigned-byte 8) (*)) (integer 0))
              (values (or null (integer 0)) (or null keyword)))
  "Send exactly LEN octets of BUFFER[0..LEN) over stream SOCKET, looping over short writes (a stream
   socket may accept fewer than requested). Returns (values LEN NIL) on success, or
   (values NIL :SEND-FAILED) on a torn socket — a peer reset, or a write that makes ZERO progress.

   NEVER signals. The sb-bsd-sockets SOCKET-ERROR is a LIBRARY condition raised beneath us; it is caught
   HERE, at the lowest boundary that can see it, and turned into a status value — which is rule 2 of the
   no-conditions contract (a condition from a dependency is contained at the call, never re-signalled and
   never allowed to unwind a caller's stack). Callers distinguish a torn connection from a short send by
   the status, not by a handler."
  (let ((sent 0))
    (declare (type (integer 0) sent))
    (handler-case
        (loop while (< sent len)
              do (let ((n (if (zerop sent)
                              (sb-bsd-sockets:socket-send socket buffer len)
                              (sb-bsd-sockets:socket-send socket (subseq buffer sent len) (- len sent)))))
                   (when (or (null n) (zerop n))
                     (bail :send-failed))                       ; no progress: the peer is gone
                   (incf sent n)))
      (sb-bsd-sockets:socket-error () (bail :send-failed)))
    (values len nil)))

(defun* tcp-recv (socket buffer len)
    (function (t (simple-array (unsigned-byte 8) (*)) (integer 0))
              (values (or null (integer 0)) (or null keyword)))
  "Receive exactly LEN octets into BUFFER[0..LEN) from stream SOCKET, looping over partial reads until
   the full frame is assembled (TCP is a byte stream — one frame may split across segments; a partial
   read is normal, NOT end-of-stream).

   THREE OUTCOMES, and they are DISTINCT — the caller MUST NOT confuse them:
     (values LEN NIL)      the full frame arrived.
     (values NIL :EOF)     EOF / peer-close / connection-reset before LEN bytes (the connection dropped).
     (values NIL :TIMEOUT) SOCKET has a recv timeout armed (tcp-set-recv-timeout) and no data arrived
                           within the deadline — a STALLED peer, not a closed one.

   sb-bsd-sockets:socket-receive returns n=0 on a clean peer-close but n=NIL on an SO_RCVTIMEO timeout OR
   an EINTR-interrupted receive (verified identical on SBCL + Clasp), which is what lets this split :EOF
   from :TIMEOUT. EINTR is CONSERVATIVELY classified as :TIMEOUT (n=NIL ⟸ timeout OR EINTR) — the
   disposition is identical either way (drop / reconnect), so folding the rare interrupted-syscall case in
   is safe and keeps the branch minimal. This was a PAL-TIMEOUT condition until the no-conditions rule;
   the status value carries exactly the same information with no stack unwind (the sb-bsd-sockets
   SOCKET-ERROR is a library condition, contained here and mapped to :EOF — rule 2).

   BUFFER must hold >= LEN octets. The first read lands straight in BUFFER; only a genuine split allocates
   one scratch buffer."
  (when (zerop len) (return-from tcp-recv (values 0 nil)))
  (let ((got 0) (scratch nil))
    (declare (type (integer 0) got))
    (flet ((step-outcome (n)          ; n>0 = data; n=0 = clean EOF; n=NIL = SO_RCVTIMEO/EINTR
             (cond ((null n) (bail :timeout))
                   ((zerop n) (bail :eof)))))
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
        (sb-bsd-sockets:socket-error () (bail :eof))))
    (values len nil)))

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
    (function (fixnum (integer 1)) (values t (or null keyword)))
  "mmap SIZE bytes of FD shared R/W. Returns (values sap NIL), or (values NIL :MMAP-FAILED) on
   MAP_FAILED — never signals."
  (let ((p (cffi:foreign-funcall "mmap" :pointer (cffi:null-pointer) :unsigned-long size
                                 :int +prot-rw+ :int +map-shared+ :int fd :long 0 :pointer)))
    (when (= (cffi:pointer-address p) +map-failed-addr+) (bail :mmap-failed))
    (values p nil)))

(defun* %shm-open-create (name)
    (function (string) fixnum)
  "shm_open O_CREAT|O_EXCL|O_RDWR, mode 0600. The variadic mode's ABI differs per impl on arm64.
   SBCL: foreign-funcall-varargs (stack — verified correct). Clasp: plain foreign-funcall (correct on
   Linux's register varargs ABI; UNRELIABLE on macOS arm64 — the NFR-PORT gap, ADR 0013). Reader
   conditionals are permitted inside dds-pal/.

   ⚠️ THE macOS-arm64 GAP IS REAL AND IT IS NOT A WRONG CALL FORM — MEASURED, 2026-07-14, because the
   obvious 'fix' (just use FOREIGN-FUNCALL-VARARGS on Clasp too, as SBCL does) LOOKS like it works. It does
   not. Over 30 create+reopen trials on Clasp/macOS-arm64, the object was re-openable by name:

       plain foreign-funcall .......... 10/30
       foreign-funcall-varargs ......... 0/30   <- the 'obvious fix'
       varargs, mode as :int ........... 10/30
       varargs + explicit fchmod 0600 ... 0/30

   NONE of them is correct; the mode lands as GARBAGE, and a single trial passes or fails by whether those
   garbage bits happened to include owner-rw. A one-shot probe therefore 'proves' whichever answer you want
   — which is exactly how this was nearly declared fixed. The permission bits are fixed at creation on
   macOS (fchmod afterwards does not repair them), so there is no Lisp-side repair either. This is a Clasp
   CFFI variadic-ABI defect on Darwin/arm64 and it belongs upstream. Linux (the primary platform, operating
   contract §9) passes variadic args in registers, so plain foreign-funcall is correct there and Clasp is
   fully fitted."
  #+sbcl (cffi:foreign-funcall-varargs "shm_open" (:string name :int (logior +o-creat+ +o-excl+ +o-rdwr+)) :unsigned-int #o600 :int)
  #-sbcl (cffi:foreign-funcall "shm_open" :string name :int (logior +o-creat+ +o-excl+ +o-rdwr+) :unsigned-int #o600 :int))

(defun* shm-create (name size)
    (function (string (integer 1)) (values (or null shm-segment) (or null keyword)))
  "Create+map an exclusive POSIX shm object NAME of SIZE bytes (shm_open O_CREAT|O_EXCL, ftruncate,
   mmap MAP_SHARED). A stale leftover (EEXIST) is unlinked and recreated. Returns (values segment NIL),
   or (values NIL status) with status :SHM-OPEN-FAILED / :FTRUNCATE-FAILED / :MMAP-FAILED. Never signals.
   EVERY failure path CLOSES the fd it opened before returning — a failed create leaks no descriptor."
  (let ((fd (%shm-open-create name)))
    (when (minusp fd)
      (cffi:foreign-funcall "shm_unlink" :string name :int)
      (setf fd (%shm-open-create name)))
    (when (minusp fd) (bail :shm-open-failed))
    (when (minusp (cffi:foreign-funcall "ftruncate" :int fd :long size :int))
      (cffi:foreign-funcall "close" :int fd :int)
      (bail :ftruncate-failed))
    (multiple-value-bind (sap status) (%mmap-shared fd size)
      (when status (cffi:foreign-funcall "close" :int fd :int) (bail status))
      (values (make-shm-segment :name name :fd fd :sap sap :size size) nil))))

(defun* shm-attach (name size)
    (function (string (integer 1)) (values (or null shm-segment) (or null keyword)))
  "Open+map an EXISTING shm object NAME of SIZE bytes (shm_open O_RDWR, mmap). No mode arg: the 2-arg
   open is non-variadic -> plain cffi:foreign-funcall. Returns (values segment NIL), or (values NIL status)
   with status :SHM-OPEN-FAILED (no such segment — the ordinary case for a stale/forged peer name, which
   the zero-copy reader treats as 'no pool', never a crash) or :MMAP-FAILED. Never signals; the fd is
   closed on the mmap failure path."
  (let ((fd (cffi:foreign-funcall "shm_open" :string name :int +o-rdwr+ :int)))
    (when (minusp fd) (bail :shm-open-failed))
    (multiple-value-bind (sap status) (%mmap-shared fd size)
      (when status (cffi:foreign-funcall "close" :int fd :int) (bail status))
      (values (make-shm-segment :name name :fd fd :sap sap :size size) nil))))

(defun* shm-sap (segment) (function (shm-segment) t) "Foreign SAP base of SEGMENT." (shm-segment-sap segment))

(defun* shm-detach (segment)
    (function (shm-segment) t)
  "munmap + close SEGMENT (does not unlink the name)."
  (cffi:foreign-funcall "munmap" :pointer (shm-segment-sap segment) :unsigned-long (shm-segment-size segment) :int)
  (cffi:foreign-funcall "close" :int (shm-segment-fd segment) :int))

(defun* shm-destroy (name) (function (string) t) "shm_unlink NAME." (cffi:foreign-funcall "shm_unlink" :string name :int))

;; System V shared-memory primitives (FR-XPORT-2, ADR 0081). A SECOND, distinct mechanism from the
;; POSIX shm_open/mmap objects above, needed because RTI Connext's shared-memory transport uses SysV
;; shmget/shmat and names a segment by an INTEGER KEY derived from the RTPS port (segment 0x400000+port),
;; not by a filesystem-like name. Values verified from sys/shm.h + sys/ipc.h on BOTH Darwin and Linux and
;; found IDENTICAL on both, so unlike the open(2) flags above these need no OS reader conditional.
(defconstant +shm-rdonly+ #o010000 "SHM_RDONLY — shmat(2) attaches read-only. sys/shm.h, Darwin + Linux.")
(defconstant +ipc-creat+  #o001000 "IPC_CREAT — shmget(2) creates the segment if KEY does not exist. sys/ipc.h, Darwin + Linux.")
(defconstant +ipc-excl+   #o002000 "IPC_EXCL — with IPC_CREAT, shmget(2) fails if KEY already exists. sys/ipc.h, Darwin + Linux.")
(defconstant +ipc-rmid+   0        "IPC_RMID — shmctl(2) marks the segment destroyed. sys/ipc.h, Darwin + Linux.")

(defstruct* sysv-shm-segment
  "An attached System V shared-memory segment: integer KEY, kernel ID, foreign SAP, attached byte SIZE."
  (key 0 :type (unsigned-byte 31)) (id -1 :type fixnum) (sap nil :type t) (size 0 :type (integer 0)))

(defun* sysv-shm-attach-readonly (key least-bytes)
    (function ((unsigned-byte 31) (integer 1)) (values (or null sysv-shm-segment) (or null keyword)))
  "Attach READ-ONLY to the EXISTING System V segment named KEY, which must be at least LEAST-BYTES long.
   Returns (values segment NIL), or (values NIL status) with status :NO-SUCH-SEGMENT (no segment for KEY,
   or it is SHORTER than LEAST-BYTES) or :SHMAT-FAILED. Never signals.

   ⚠️ LEAST-BYTES IS THE BOUNDS CHECK, AND THE KERNEL ENFORCES IT. shmget(2) returns EINVAL when a segment
   exists for KEY but is smaller than the requested size, so passing the number of bytes we intend to read
   makes a too-short segment fail to attach at all. That is deliberate, and it is why this does NOT call
   shmctl(IPC_STAT): `struct shmid_ds` has a DIFFERENT layout on Darwin and Linux, so marshalling it would
   be an OS-specific struct definition AND a second source of truth for the extent. A segment written by
   another process is untrusted input exactly like a datagram (NFR-SEC-POSTURE); this makes the extent a
   precondition of attaching rather than something a caller can forget to verify.

   Read-only means a malformed or hostile segment cannot be corrupted BY US, and the mapping faults on any
   accidental write. The caller must still bounds-check every offset it reads against SIZE."
  (let ((id (cffi:foreign-funcall "shmget" :int key :unsigned-long least-bytes :int 0 :int)))
    (when (minusp id) (bail :no-such-segment))
    (let ((p (cffi:foreign-funcall "shmat" :int id :pointer (cffi:null-pointer) :int +shm-rdonly+ :pointer)))
      (when (= (cffi:pointer-address p) +map-failed-addr+) (bail :shmat-failed))
      (values (make-sysv-shm-segment :key key :id id :sap p :size least-bytes) nil))))

(defun* sysv-shm-attach-readwrite (key least-bytes)
    (function ((unsigned-byte 31) (integer 1)) (values (or null sysv-shm-segment) (or null keyword)))
  "Attach READ-WRITE to the EXISTING System V segment named KEY, at least LEAST-BYTES long. Returns
   (values segment NIL), or (values NIL status) with :NO-SUCH-SEGMENT (absent or shorter than LEAST-BYTES —
   the kernel enforces the extent exactly as in SYSV-SHM-ATTACH-READONLY) or :SHMAT-FAILED. Never signals.

   ⚠️ THIS MAPS ANOTHER PROCESS'S MEMORY WRITABLE. It exists for the one case that requires it — writing a
   record into an RTI Connext receiver's ring (ADR 0081 §5.0, the transmit path) — and its use must be
   bracketed by that ring's mutex, because writing outside the lock races RTI's own senders. Everything that
   only READS an RTI segment uses SYSV-SHM-ATTACH-READONLY instead, so an accidental write faults rather than
   corrupting a live peer."
  (let ((id (cffi:foreign-funcall "shmget" :int key :unsigned-long least-bytes :int 0 :int)))
    (when (minusp id) (bail :no-such-segment))
    (let ((p (cffi:foreign-funcall "shmat" :int id :pointer (cffi:null-pointer) :int 0 :pointer)))
      (when (= (cffi:pointer-address p) +map-failed-addr+) (bail :shmat-failed))
      (values (make-sysv-shm-segment :key key :id id :sap p :size least-bytes) nil))))

(defun* sysv-shm-create (key size)
    (function ((unsigned-byte 31) (integer 1)) (values (or null sysv-shm-segment) (or null keyword)))
  "Create an EXCLUSIVE System V segment named KEY of SIZE bytes (shmget IPC_CREAT|IPC_EXCL, mode 0600) and
   attach it read-write. Returns (values segment NIL), or (values NIL status) with status :SHMGET-FAILED
   (KEY already exists, or a resource limit) or :SHMAT-FAILED. Never signals.

   Mode is 0600 — owner only. A System V segment OUTLIVES the process that created it, so a caller is
   responsible for SYSV-SHM-DESTROY; a leaked segment holds its key and makes the next create fail EEXIST."
  (let ((id (cffi:foreign-funcall "shmget" :int key :unsigned-long size
                                  :int (logior +ipc-creat+ +ipc-excl+ #o600) :int)))
    (when (minusp id) (bail :shmget-failed))
    (let ((p (cffi:foreign-funcall "shmat" :int id :pointer (cffi:null-pointer) :int 0 :pointer)))
      (when (= (cffi:pointer-address p) +map-failed-addr+) (bail :shmat-failed))
      (values (make-sysv-shm-segment :key key :id id :sap p :size size) nil))))

(defun* sysv-shm-sap (segment) (function (sysv-shm-segment) t) "Foreign SAP base of SEGMENT."
  (sysv-shm-segment-sap segment))

(defun* sysv-shm-detach (segment)
    (function (sysv-shm-segment) t)
  "shmdt SEGMENT. Does NOT destroy it — the segment survives until SYSV-SHM-DESTROY, by design: we attach
   to segments owned by other processes and must never remove them."
  (cffi:foreign-funcall "shmdt" :pointer (sysv-shm-segment-sap segment) :int))

(defun* sysv-shm-destroy (segment)
    (function (sysv-shm-segment) t)
  "shmctl(IPC_RMID) SEGMENT — mark it destroyed so it goes away once the last process detaches. Call this
   only for a segment WE created; removing another process's segment would break it."
  (cffi:foreign-funcall "shmctl" :int (sysv-shm-segment-id segment) :int +ipc-rmid+
                        :pointer (cffi:null-pointer) :int))

;; System V SEMAPHORE primitives (FR-XPORT-2, ADR 0081) — the sibling of the shared-memory surface above,
;; needed to interoperate with RTI Connext's shared-memory ring, which is guarded by a SysV semaphore mutex
;; and woken by a SysV semaphore data flag (measured, ADR 0081 §5.0: producer takes the mutex, writes,
;; releases, then raises the data flag with semctl SETVAL 1). SEM_UNDO is identical on Darwin and Linux, but
;; the semctl command NUMBERS differ — SETVAL/GETVAL are 8/5 on Darwin and 16/12 on Linux — so those alone
;; need an OS reader conditional (permitted inside dds-pal/), like the open(2) flags above. Values read from
;; sys/sem.h on both, and SETVAL=8 cross-checked against a live Connext semctl via dtrace.
(defconstant +sem-undo+ #x1000 "SEM_UNDO — semop(2) reverses this adjustment if the process exits without undoing it. sys/sem.h, Darwin (010000) + Linux (0x1000), identical.")
#+darwin (progn (defconstant +sem-setval+ 8)  (defconstant +sem-getval+ 5))
#-darwin (progn (defconstant +sem-setval+ 16) (defconstant +sem-getval+ 12))

(defstruct* sysv-sem-set
  "An opened System V semaphore set: integer KEY and kernel ID."
  (key 0 :type (unsigned-byte 31)) (id -1 :type fixnum))

(defun* sysv-sem-open (key)
    (function ((unsigned-byte 31)) (values (or null sysv-sem-set) (or null keyword)))
  "Open the EXISTING System V semaphore set named KEY (semget with nsems 0, which never creates). Returns
   (values set NIL), or (values NIL :NO-SUCH-SEMAPHORE) — the ordinary answer when no such set exists.
   Never signals. Used to reach the mutex/data semaphores of an RTI Connext receiver we intend to write to."
  (let ((id (cffi:foreign-funcall "semget" :int key :int 0 :int 0 :int)))
    (when (minusp id) (bail :no-such-semaphore))
    (values (make-sysv-sem-set :key key :id id) nil)))

(defun* sysv-sem-create (key nsems)
    (function ((unsigned-byte 31) (integer 1 32)) (values (or null sysv-sem-set) (or null keyword)))
  "Create an EXCLUSIVE System V semaphore set named KEY with NSEMS semaphores (semget IPC_CREAT|IPC_EXCL,
   mode 0600). Returns (values set NIL), or (values NIL :SEMGET-FAILED) when KEY already exists or a limit is
   hit. Never signals. A SysV set OUTLIVES its creator, so the caller is responsible for SYSV-SEM-DESTROY."
  (let ((id (cffi:foreign-funcall "semget" :int key :int nsems :int (logior +ipc-creat+ +ipc-excl+ #o600) :int)))
    (when (minusp id) (bail :semget-failed))
    (values (make-sysv-sem-set :key key :id id) nil)))

(defun* sysv-sem-op (set semnum delta undo-p)
    (function (sysv-sem-set (unsigned-byte 16) (integer -32768 32767) t) (values t (or null keyword)))
  "One semop(2) on SET's semaphore SEMNUM: add DELTA (negative takes/waits — blocking until the value can
   absorb it; positive posts/releases), with SEM_UNDO iff UNDO-P. Returns (values T NIL), or
   (values NIL :SEMOP-FAILED). Never signals.

   The struct sembuf is {unsigned short sem_num; short sem_op; short sem_flg} — the same 6-byte packed
   layout on Darwin and Linux, built here in a foreign object; sem_op is the only non-variadic path in this
   surface, so a plain foreign-funcall is correct on every platform.

   SEM_UNDO on the mutex TAKE is why a writer of ours cannot deadlock RTI's receiver: if our process dies
   while holding the ring mutex, the kernel reverses the take (ADR 0081 §5.0)."
  (cffi:with-foreign-object (sb :short 3)
    (setf (cffi:mem-aref sb :unsigned-short 0) semnum
          (cffi:mem-aref sb :short 1) delta
          (cffi:mem-aref sb :short 2) (if undo-p +sem-undo+ 0))
    (if (minusp (cffi:foreign-funcall "semop" :int (sysv-sem-set-id set) :pointer sb :unsigned-long 1 :int))
        (bail :semop-failed)
        (values t nil))))

(defun* sysv-sem-setval (set semnum value)
    (function (sysv-sem-set (unsigned-byte 16) (unsigned-byte 31)) (values t (or null keyword)))
  "Set SET's semaphore SEMNUM to VALUE (semctl SETVAL) — the idempotent wake RTI's producer uses to raise
   its data-available flag (measured value 1, ADR 0081 §5.0). Returns (values T NIL), or
   (values NIL :SEMCTL-FAILED). Never signals.

   semctl is VARIADIC in its value argument, so it has the same Darwin-arm64 hazard as shm_open's mode: a
   plain foreign-funcall passes the value in a register where the stack-based variadic ABI expects it. SBCL
   uses FOREIGN-FUNCALL-VARARGS (stack, correct); Clasp uses a plain call (correct on Linux's register
   varargs, the documented NFR-PORT gap on Darwin-arm64, ADR 0013). Reader conditionals permitted here."
  (if (minusp #+sbcl (cffi:foreign-funcall-varargs "semctl" (:int (sysv-sem-set-id set) :int semnum :int +sem-setval+) :int value :int)
              #-sbcl (cffi:foreign-funcall "semctl" :int (sysv-sem-set-id set) :int semnum :int +sem-setval+ :int value :int))
      (bail :semctl-failed)
      (values t nil)))

(defun* sysv-sem-getval (set semnum)
    (function (sysv-sem-set (unsigned-byte 16)) (values (or null (unsigned-byte 31)) (or null keyword)))
  "Read SET's semaphore SEMNUM value (semctl GETVAL — no variadic argument, so a plain foreign-funcall is
   correct everywhere). Returns (values value NIL), or (values NIL :SEMCTL-FAILED). Never signals."
  (let ((v (cffi:foreign-funcall "semctl" :int (sysv-sem-set-id set) :int semnum :int +sem-getval+ :int)))
    (if (minusp v) (bail :semctl-failed) (values v nil))))

(defun* sysv-sem-destroy (set)
    (function (sysv-sem-set) t)
  "semctl(IPC_RMID) SET — remove the semaphore set. Call only for a set WE created; removing RTI's would
   break its ring."
  (cffi:foreign-funcall "semctl" :int (sysv-sem-set-id set) :int 0 :int +ipc-rmid+ :int))

(defun* sysv-sem-setval-reliable-p ()
    (function () t)
  "T iff semctl(SETVAL) actually sets the value on this implementation+platform. FALSE on Clasp/macOS-arm64,
   whose CFFI mispasses semctl's variadic value the same way it mispasses shm_open's mode (ADR 0013) — there
   SETVAL silently no-ops, which would leave an RTI receiver un-woken and, worse, block a subsequent take on
   an un-raised semaphore forever. A runtime PROBE, not a reader conditional: create a fresh IPC_PRIVATE set,
   SETVAL 42, read it back, and require 42. Never touches another process's semaphore; never blocks (GETVAL
   only). The RTI-SHMEM writer and its test gate on this, exactly as the SHMEM transport gates on
   SHM-ATTACH-BY-NAME-RELIABLE-P."
  (multiple-value-bind (set st) (sysv-sem-create 0 1)   ; IPC_PRIVATE (key 0) — always a fresh anonymous set
    (if st
        nil
        (unwind-protect
             (progn (sysv-sem-setval set 0 42)
                    (multiple-value-bind (v gst) (sysv-sem-getval set 0)
                      (and (null gst) (eql v 42))))
          (sysv-sem-destroy set)))))

;; Cross-process PTHREAD_PROCESS_SHARED mutex+condvar primitives (FR-XPORT-2), living in a
;; shared segment for in-band notification. Replaces named POSIX semaphores: sem_open is
;; undrivable from the Lisp runtime on macOS arm64 (variadic mode/value mispassed), whereas
;; every pthread_* below is NON-variadic -> plain foreign-funcall works on macOS + Linux,
;; and libpthread is already linked (no new dependency).
(defconstant +pthread-process-shared+ 1)   ; PTHREAD_PROCESS_SHARED, same on macOS + Linux

(declaim (inline %ptr+))   ; MEASURED: without this a lock+unlock pair costs 31.85 B/iteration and a SHMEM sample ~82 B — see below
(defun* %ptr+ (sap offset)
    (function (t (integer 0)) t)
  "Foreign pointer at SAP + OFFSET bytes.

   ⚠️ INLINE IS LOAD-BEARING, NOT A MICRO-OPTIMISATION. Out of line this function must RETURN a foreign
   pointer, and on SBCL that means BOXING a system-area-pointer — 16 heap bytes on EVERY pshared operation.
   Measured directly: a PSHARED-LOCK + PSHARED-UNLOCK pair allocated 31.85 B/iteration (two boxes) while a
   LOAD-SAP-U64 on the same SAP allocated 0.00. Every SHMEM datagram takes at least a lock/unlock pair on
   the receive side and a lock/signal/unlock on a parked send, which is where the SHMEM transport's measured
   +82 B/sample over pure UDP came from. Inlined, the pointer arithmetic folds into the foreign call's
   argument and never materialises a boxed SAP at all."
  (cffi:inc-pointer sap offset))

(defun* pshared-mutex-init (sap offset)
    (function (t (integer 0)) (values t (or null keyword)))
  "Initialise a PTHREAD_PROCESS_SHARED mutex at SAP+OFFSET (creator only). Returns (values T NIL), or
   (values NIL :MUTEX-INIT-FAILED) on a non-zero pthread_mutex_init return. The attr is destroyed on BOTH
   paths (no leak on failure)."
  (cffi:with-foreign-object (ma :char 16)
    (cffi:foreign-funcall "pthread_mutexattr_init" :pointer ma :int)
    (cffi:foreign-funcall "pthread_mutexattr_setpshared" :pointer ma :int +pthread-process-shared+ :int)
    (let ((rc (cffi:foreign-funcall "pthread_mutex_init" :pointer (%ptr+ sap offset) :pointer ma :int)))
      (cffi:foreign-funcall "pthread_mutexattr_destroy" :pointer ma :int)
      (unless (zerop rc) (bail :mutex-init-failed))
      (values t nil))))

(defun* pshared-cond-init (sap offset)
    (function (t (integer 0)) (values t (or null keyword)))
  "Initialise a PTHREAD_PROCESS_SHARED condition variable at SAP+OFFSET (creator only). Returns
   (values T NIL), or (values NIL :COND-INIT-FAILED). The attr is destroyed on BOTH paths."
  (cffi:with-foreign-object (ca :char 16)
    (cffi:foreign-funcall "pthread_condattr_init" :pointer ca :int)
    (cffi:foreign-funcall "pthread_condattr_setpshared" :pointer ca :int +pthread-process-shared+ :int)
    (let ((rc (cffi:foreign-funcall "pthread_cond_init" :pointer (%ptr+ sap offset) :pointer ca :int)))
      (cffi:foreign-funcall "pthread_condattr_destroy" :pointer ca :int)
      (unless (zerop rc) (bail :cond-init-failed))
      (values t nil))))

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
