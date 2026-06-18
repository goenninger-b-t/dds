;;;; L7 — POSIX shared-memory intra-host transport ring (FR-XPORT-2). Per-receiver segment: header +
;;;; notify block (pshared mutex+cond) + K per-sender SPSC lanes. No foreign CAS (mutex-guarded claim).
(in-package #:dds.xport.shmem)

(defconstant +shm-magic+ #x53484D31 "Ring ABI magic 'SHM1' (this project's own; not a wire constant).")
(defconstant +shm-version+ 1)
(defconstant +off-magic+ 0) (defconstant +off-version+ 4) (defconstant +off-lane-count+ 8)
(defconstant +off-capacity+ 12) (defconstant +off-max-record+ 16)
(defconstant +mutex-off+ 64) (defconstant +cond-off+ 128) (defconstant +stop-off+ 192)
(defconstant +parked-off+ 200 "Receiver-parked flag (u64) in the [192,256) notify region after stop@192, before lanes@256: 1 = the receiver is blocked in pshared-cond-wait, 0 = it is draining/running. The sender signals the cond ONLY when this reads 1 (skips a wasted futex wake when the receiver is busy). Set/cleared strictly under the pshared mutex; read by the sender after a full fence (the StoreLoad pattern that makes the skip lost-wakeup-free).")
(defconstant +lanes-off+ 256)
(defconstant +lane-desc-size+ 64)
(defconstant +lane-off-owner+ 0) (defconstant +lane-off-write+ 8) (defconstant +lane-off-read+ 16)
(defconstant +skip-marker+ #xFFFFFFFF "Ring record len meaning 'pad to the capacity boundary'.")

(define-condition shmem-send-test-fault (error) ()
  (:report (lambda (c s) (declare (ignore c)) (format s "synthetic %shmem-send hard fault (test only)")))
  (:documentation "Test-only synthetic %SHMEM-SEND hard fault, injected by *DEBUG-SHMEM-SEND-FAULT* to exercise
   the %SEND-RAW-BUF self-guard -> UDP fallback (WP-SHMEM-SEND-SELF-GUARD, FR-XPORT-2). Never signalled in
   production (*DEBUG-SHMEM-SEND-FAULT* defaults NIL)."))

(defparameter *debug-shmem-send-fault* nil
  "Test affordance (inert when NIL): when non-NIL, %SHMEM-SEND signals SHMEM-SEND-TEST-FAULT before doing any
   work — exercises the %SEND-RAW-BUF self-guard (which catches the signal, bumps DISC-NODE-SHMEM-SEND-FAULTS,
   fires *SENDER-EMIT-ERROR-HOOK* with context :SHMEM-SEND-FAULT, and falls back to UDP). Production default NIL
   = byte-identical wire, zero effect. Never set in production. (WP-SHMEM-SEND-SELF-GUARD, FR-XPORT-2.)")

(defun* %segment-bytes (lane-count capacity)
    (function ((integer 1) (integer 8)) (integer 1))
  "Total segment size: header+notify block, lane descriptors, per-lane ring data."
  (+ +lanes-off+ (* lane-count +lane-desc-size+) (* lane-count capacity)))
(defun* %lane-desc-off (i)
    (function ((integer 0)) (integer 0))
  "Byte offset of lane I's descriptor block."
  (+ +lanes-off+ (* i +lane-desc-size+)))
(defun* %lane-data-off (lane-count i capacity)
    (function ((integer 1) (integer 0) (integer 8)) (integer 0))
  "Byte offset of lane I's ring-data region (descriptors precede the data area)."
  (+ +lanes-off+ (* lane-count +lane-desc-size+) (* i capacity)))
(defun* %ring-lane-count (sap)
    (function (t) (unsigned-byte 32))
  "Lane count read from the segment header at SAP."
  (cffi:mem-ref sap :uint32 +off-lane-count+))
(defun* %ring-capacity (sap)
    (function (t) (unsigned-byte 32))
  "Per-lane ring capacity (bytes) read from the segment header at SAP."
  (cffi:mem-ref sap :uint32 +off-capacity+))
(defun* %ring-max-record (sap)
    (function (t) (unsigned-byte 32))
  "Largest record payload+header the ring accepts, read from the header at SAP."
  (cffi:mem-ref sap :uint32 +off-max-record+))

(defun* %ring-init (sap lane-count capacity)
    (function (t (integer 1) (integer 8)) t)
  "Initialise header + the pshared notify block (mutex/cond/stop) + zero every lane cursor/owner.
   CAPACITY must be a multiple of 8. Creator-only."
  (assert (zerop (mod capacity 8)))
  (setf (cffi:mem-ref sap :uint32 +off-magic+) +shm-magic+
        (cffi:mem-ref sap :uint32 +off-version+) +shm-version+
        (cffi:mem-ref sap :uint32 +off-lane-count+) lane-count
        (cffi:mem-ref sap :uint32 +off-capacity+) capacity
        (cffi:mem-ref sap :uint32 +off-max-record+) (- capacity 8))
  (dds.pal:pshared-mutex-init sap +mutex-off+)
  (dds.pal:pshared-cond-init sap +cond-off+)
  (dds.pal:store-sap-u64 sap +stop-off+ 0)
  (dds.pal:store-sap-u64 sap +parked-off+ 0)
  (dotimes (i lane-count t)
    (let ((b (%lane-desc-off i)))
      (dds.pal:store-sap-u64 sap (+ b +lane-off-owner+) 0)
      (dds.pal:store-sap-u64 sap (+ b +lane-off-write+) 0)
      (dds.pal:store-sap-u64 sap (+ b +lane-off-read+) 0))))

(defun* %ring-validate (sap)
    (function (t) t)
  "T iff SAP holds a ring with the expected magic + version (ABI guard on attach)."
  (and (= +shm-magic+ (cffi:mem-ref sap :uint32 +off-magic+))
       (= +shm-version+ (cffi:mem-ref sap :uint32 +off-version+))))

(defun* %claim-lane (sap token)
    (function (t (unsigned-byte 64)) (or null (integer 0)))
  "Claim a lane for TOKEN (a nonzero per-sender id) under the segment's pshared mutex: return TOKEN's
   existing lane (reuse), else the first free lane (owner=0) after claiming it, else NIL (all taken).
   One-time, off the hot path — the mutex (not a CAS) serializes concurrent claimers. TOKEN must be
   nonzero (0 marks a free lane)."
  (dds.pal:pshared-lock sap +mutex-off+)
  (unwind-protect
       (let ((n (%ring-lane-count sap)) (free nil))
         (dotimes (i n)
           (let ((o (dds.pal:load-sap-u64 sap (+ (%lane-desc-off i) +lane-off-owner+))))
             (when (= o token) (return-from %claim-lane i))
             (when (and (null free) (zerop o)) (setf free i))))
         (when free
           (dds.pal:store-sap-u64 sap (+ (%lane-desc-off free) +lane-off-owner+) token)
           free))
    (dds.pal:pshared-unlock sap +mutex-off+)))

(defun* %record-span (len)
    (function ((integer 0)) (integer 8))
  "Bytes a [len][payload] record occupies (4-byte header included), rounded up to 8."
  (logand (+ 4 len 7) (lognot 7)))

(defun* %lane-enqueue (sap lane capacity payload off len)
    (function (t (integer 0) (integer 8) (simple-array (unsigned-byte 8) (*)) (integer 0) (integer 0)) t)
  "Single-producer enqueue of PAYLOAD[off,off+len) as one ring record into LANE. T on success, NIL if it
   does not fit (caller maps NIL to RESOURCE_LIMITS / UDP fallback). Publishes the advanced write-cursor
   with a RELEASE fence so the consumer's ACQUIRE load sees the payload."
  (when (> (+ 4 len) capacity) (return-from %lane-enqueue nil))
  (let* ((base (%lane-desc-off lane))
         (data (%lane-data-off (%ring-lane-count sap) lane capacity))
         (w (dds.pal:load-sap-u64 sap (+ base +lane-off-write+)))
         (r (dds.pal:load-sap-u64 sap (+ base +lane-off-read+)))
         (span (%record-span len))
         (pos (mod w capacity))
         (tail (- capacity pos)))
    (let ((need (if (< tail span) (+ tail span) span)))
      (when (> (+ (- w r) need) capacity) (return-from %lane-enqueue nil)))
    (when (< tail span)
      (setf (cffi:mem-ref sap :uint32 (+ data pos)) +skip-marker+)
      (incf w tail) (setf pos 0))
    (setf (cffi:mem-ref sap :uint32 (+ data pos)) len)
    (dotimes (i len) (setf (cffi:mem-ref sap :uint8 (+ data pos 4 i)) (aref payload (+ off i))))
    (dds.pal:fence :release)
    (dds.pal:store-sap-u64 sap (+ base +lane-off-write+) (+ w span))
    t))

(defun* %lane-drain (sap lane capacity sink on-datagram)
    (function (t (integer 0) (integer 8) dds.core.buffer:octet-buffer function) t)
  "Single-consumer drain of LANE: ACQUIRE-load the producer's write-cursor, read every committed record up
   to it, copy each into SINK and call (ON-DATAGRAM SINK size), advance read-cursor. Bounds-check every
   len against max-record + the committed extent before trusting it (untrusted cross-process input).
   SINK capacity must be >= the ring max-record (caller contract; allocated once, off the hot path)."
  (let* ((base (%lane-desc-off lane))
         (data (%lane-data-off (%ring-lane-count sap) lane capacity))
         (maxr (%ring-max-record sap))
         (w (dds.pal:load-sap-u64 sap (+ base +lane-off-write+))))
    (dds.pal:fence :acquire)
    (let ((r (dds.pal:load-sap-u64 sap (+ base +lane-off-read+)))
          (vec (dds.core.buffer:octet-buffer-vec sink)))
      ;; w is cross-process/untrusted; a conforming producer never has w-r > capacity (NFR-SEC-POSTURE).
      (when (> (- w r) capacity) (return-from %lane-drain t))
      (loop while (< r w) do
        (let* ((pos (mod r capacity))
               (len (cffi:mem-ref sap :uint32 (+ data pos))))
          (cond
            ((= len +skip-marker+) (incf r (- capacity pos)))
            ((or (> len maxr) (> (+ 4 len) (- capacity pos)) (> (%record-span len) (- w r)))
             (return-from %lane-drain t))
            (t (dotimes (i len) (setf (aref vec i) (cffi:mem-ref sap :uint8 (+ data pos 4 i))))
               (funcall on-datagram sink len)
               (incf r (%record-span len))))))
      (dds.pal:store-sap-u64 sap (+ base +lane-off-read+) r)
      t)))

;;;; D1 — make-shmem-transport: the frozen DDS.XPORT transport record wrapped around a
;;;; per-participant receive segment. SEND attaches (once, cached) to the destination
;;;; segment and enqueues; the engine is untouched (FR-XPORT-5). The raw segment + lane
;;;; token + attach cache have no slot in the frozen record, so they live on this struct.

(defstruct* shmem-locator
  "Destination for a SHMEM send: the receiver segment NAME + same-host HOST-UUID + ring geometry."
  (name "" :type string) (host-uuid 0 :type (unsigned-byte 64)) (lane-count 1 :type (integer 1)) (capacity 8 :type (integer 8)))

(defstruct* (shmem-transport (:constructor %make-shmem-transport))
  "Owns a participant's SHMEM receive segment + the frozen transport record + a per-sender attach cache
   (name -> shm-segment) + this sender's nonzero lane token + a drain SINK + the receiver thread."
  (transport nil :type (or null dds.xport:transport))
  (segment nil :type t) (name "" :type string) (host-uuid 0 :type (unsigned-byte 64))
  (lane-count 8 :type (integer 1)) (capacity 65536 :type (integer 8)) (token 0 :type (unsigned-byte 64))
  (attach-cache (make-hash-table :test 'equal) :type hash-table) (sink nil :type t) (rx-thread nil :type t))

(defun* %guid-token (guid)
    (function ((simple-array (unsigned-byte 8) (12))) (unsigned-byte 64))
  "A nonzero 64-bit per-sender token from the low 8 GUID-prefix octets (0 is the free-lane marker)."
  (let ((v 0)) (dotimes (i 8) (setf v (logior (ash v 8) (aref guid i)))) (if (zerop v) 1 v)))

(defun* %seg-name (guid)
    (function ((simple-array (unsigned-byte 8) (12))) string)
  "Segment name '/dds' + 10 hex of the token (macOS ~31-char shm-name cap)."
  (format nil "/dds~(~10,'0x~)" (%guid-token guid)))

(defun* seg-name-for-guid (guid)
    (function ((simple-array (unsigned-byte 8) (12))) string)
  "Public alias for the deterministic receive-segment name a peer's 12-octet GUID prefix maps to
   (RTPS 2.5 §9.4.4 + this transport's %seg-name): a SENDER derives the destination segment name from the
   remote participant's prefix (FR-XPORT-2), so the discovery layer addresses a same-host SHMEM peer with
   make-shmem-locator :name (seg-name-for-guid remote-prefix) without reaching the %-internal."
  (%seg-name guid))

(defun* make-shmem-transport (&key participant-guid (host-uuid 0) (lane-count 8) (capacity 65536))
    (function (&key (:participant-guid (simple-array (unsigned-byte 8) (12))) (:host-uuid (unsigned-byte 64))
               (:lane-count (integer 1)) (:capacity (integer 8))) shmem-transport)
  "Create this participant's SHMEM receive segment (+ ring + pshared notify block) and a transport record
   whose SEND attaches to the destination segment and enqueues. CAPACITY is per-lane ring bytes (mult of 8)."
  (let* ((name (%seg-name participant-guid)) (token (%guid-token participant-guid))
         (seg (progn (ignore-errors (dds.pal:shm-destroy name))
                     (dds.pal:shm-create name (%segment-bytes lane-count capacity))))
         (st (%make-shmem-transport :segment seg :name name :host-uuid host-uuid :lane-count lane-count
                                    :capacity capacity :token token
                                    :sink (dds.core.buffer:make-octet-buffer capacity))))
    (%ring-init (dds.pal:shm-sap seg) lane-count capacity)
    (setf (shmem-transport-transport st)
          (dds.xport:make-transport
           :kind :shmem :locator-kind :shmem :max-message-size (- capacity 8)
           :send (lambda (locator buffer off len) (declare (ignore off)) (%shmem-send st locator buffer len))
           :receive-loop (lambda () (values))
           :open-receive-resource (lambda (&rest a) (declare (ignore a)) (shmem-transport-locator st))
           :close (lambda () (shmem-transport-close st))))
    st))

(defun* shmem-transport-locator (st)
    (function (shmem-transport) shmem-locator)
  "The locator a peer uses to send to ST."
  (make-shmem-locator :name (shmem-transport-name st) :host-uuid (shmem-transport-host-uuid st)
                      :lane-count (shmem-transport-lane-count st) :capacity (shmem-transport-capacity st)))

(defun* %attach-for (st locator)
    (function (shmem-transport shmem-locator) t)
  "Cached shm-segment for LOCATOR's destination (attach once per name; off the hot path)."
  (or (gethash (shmem-locator-name locator) (shmem-transport-attach-cache st))
      (setf (gethash (shmem-locator-name locator) (shmem-transport-attach-cache st))
            (dds.pal:shm-attach (shmem-locator-name locator)
                                (%segment-bytes (shmem-locator-lane-count locator) (shmem-locator-capacity locator))))))

(defun* %shmem-send (st locator buffer len)
    (function (shmem-transport shmem-locator dds.core.buffer:octet-buffer (integer 0)) (integer 0))
  "Attach to LOCATOR's segment, claim/lookup our lane, enqueue LEN octets, then CONDITIONALLY wake the
   receiver: signal the dest cond ONLY if the receiver is parked. Returns LEN on success, 0 on
   lane-full/claim-fail (caller falls back to UDP / RESOURCE_LIMITS). The enqueue published the
   write-cursor with a RELEASE fence; a FULL fence here orders that store before the parked load (the
   StoreLoad half of the Dekker handshake with the receiver — the receiver publishes parked=1 then
   full-fences then re-checks the data, so at least one side observes the other: a skipped signal means
   the busy receiver WILL see this datagram on its next predicate check, never a lost wakeup). The
   lock+signal (a futex syscall) is taken ONLY for a parked receiver, so a tight blast into a draining
   receiver does no per-message futex wake — the WP-SHMEM throughput fix (FR-XPORT-2)."
  (when *debug-shmem-send-fault* (error 'shmem-send-test-fault))   ; test affordance: inert when NIL (byte-identical production)
  (let* ((dest (%attach-for st locator)) (sap (dds.pal:shm-sap dest))
         (lane (%claim-lane sap (shmem-transport-token st))))
    (if (and lane (%lane-enqueue sap lane (shmem-locator-capacity locator)
                                 (dds.core.buffer:octet-buffer-vec buffer) 0 len))
        (progn
          (dds.pal:fence :full)                          ; order the enqueue's cursor store before the parked load (StoreLoad)
          (when (= 1 (dds.pal:load-sap-u64 sap +parked-off+))   ; wake ONLY a parked receiver; skip the futex for a busy one
            (dds.pal:pshared-lock sap +mutex-off+)
            (dds.pal:pshared-cond-signal sap +cond-off+)
            (dds.pal:pshared-unlock sap +mutex-off+))
          len)
        0)))

(defun* shmem-receive-drain (st on-datagram)
    (function (shmem-transport function) t)
  "Drain ALL lanes of ST's OWN receive segment once, calling ON-DATAGRAM per record."
  (let ((sap (dds.pal:shm-sap (shmem-transport-segment st))))
    (dotimes (i (shmem-transport-lane-count st) t)
      (%lane-drain sap i (shmem-transport-capacity st) (shmem-transport-sink st) on-datagram))))

(defun* shmem-transport-close (st)
    (function (shmem-transport) t)
  "Stop the receiver (if any), destroy the pshared objects, detach all attached + own segments, unlink own."
  (stop-shmem-receiver st)
  (let ((sap (dds.pal:shm-sap (shmem-transport-segment st))))
    (dds.pal:pshared-destroy sap +mutex-off+ +cond-off+))
  (maphash (lambda (k v) (declare (ignore k)) (ignore-errors (dds.pal:shm-detach v))) (shmem-transport-attach-cache st))
  (clrhash (shmem-transport-attach-cache st))
  (dds.pal:shm-detach (shmem-transport-segment st))
  (dds.pal:shm-destroy (shmem-transport-name st))
  t)

(defun* shm-attach-by-name-reliable-p ()
    (function () t)
  "T except on Clasp/macOS-arm64, whose plain cffi:foreign-funcall mispasses shm_open's variadic mode_t so a
   created object is unre-openable by name (NFR-PORT gap, ADR 0013). The SHMEM transport REQUIRES by-name
   attach (the sender opens the receiver's named segment), so its loopback tests pass-skip where this is NIL.
   SBCL is conformant on every platform; Clasp on Linux uses the register varargs ABI and is conformant.
   Runtime check (NOT a reader conditional): dds-xport is outside dds-pal."
  (not (and (eq (dds.pal:pal-impl-name) :clasp) (uiop:os-macosx-p))))

(defun* %test-guid (b)
    (function ((unsigned-byte 8)) (simple-array (unsigned-byte 8) (12)))
  "A 12-octet GUID-prefix of constant byte B (test fixture)."
  (make-array 12 :element-type '(unsigned-byte 8) :initial-element b))

(defun* run-shmem-transport-test ()
    (function () (eql t))
  "Transport-level SHMEM loopback in one image: tx SEND -> rx OWN-segment drain.
   tx and rx are distinct participants (distinct guids, same host); asserts 4 octets round-trip.
   Pass-skips on the Clasp/macOS-arm64 by-name-attach gap (ADR 0013)."
  (unless (shm-attach-by-name-reliable-p) (return-from run-shmem-transport-test t))
  (let ((rx (make-shmem-transport :participant-guid (%test-guid 1) :host-uuid 7))
        (tx (make-shmem-transport :participant-guid (%test-guid 2) :host-uuid 7)))
    (unwind-protect
         (let ((buf (dds.core.buffer:make-octet-buffer 64)) (got nil)
               (c nil))
           (setf c (dds.core.buffer:cursor buf))
           (dds.core.buffer:put-u8 c #xDE) (dds.core.buffer:put-u8 c #xAD)
           (dds.core.buffer:put-u8 c #xBE) (dds.core.buffer:put-u8 c #xEF)
           (assert (= 4 (dds.xport:send (shmem-transport-transport tx)
                                        (shmem-transport-locator rx) buf 0 4))
                   () "SHMEM send must enqueue 4 octets and return 4")
           (shmem-receive-drain
            rx (lambda (s size) (setf got (cons size (aref (dds.core.buffer:octet-buffer-vec s) 0)))))
           (assert got () "SHMEM drain delivered nothing")
           (assert (equal '(4 . #xDE) got) () "SHMEM round-trip mismatch: ~s (want (4 . 222))" got)
           t)
      (shmem-transport-close tx)
      (shmem-transport-close rx))))

;;;; D2 — the receiver thread: block on the segment's pshared cond until a lane has data (or stop),
;;;; then drain ALL lanes. The predicate is re-checked under the mutex (no lost wakeup): the sender
;;;; publishes the write-cursor with a RELEASE fence BEFORE it acquires the mutex to signal, so a
;;;; receiver holding the mutex sees the data. Shutdown sets stop + broadcasts, then JOINs the
;;;; thread BEFORE any segment teardown (no use-after-free).

(defun* %any-data-p (sap)
    (function (t) t)
  "T iff any lane has unread data (write-cursor != read-cursor). Checked under the pshared mutex."
  (let ((n (%ring-lane-count sap)))
    (dotimes (i n nil)
      (let ((b (%lane-desc-off i)))
        (when (/= (dds.pal:load-sap-u64 sap (+ b +lane-off-write+))
                  (dds.pal:load-sap-u64 sap (+ b +lane-off-read+)))
          (return t))))))

(defun* %rx-wait-for-work (sap)
    (function (t) t)
  "Receiver inner wait (CALLER HOLDS the mutex): block on the pshared cond until a lane has data or stop,
   using the parked flag for the conditional-wakeup handshake. Sets parked=1 + a FULL fence + RE-CHECKS
   the predicate BEFORE waiting (the Dekker StoreLoad pair with %shmem-send's full-fenced parked load):
   if a producer enqueued (or stop was set) between the first predicate check and publishing parked, the
   re-check observes it and returns WITHOUT waiting, so the sender's skipped signal is never lost. parked
   is cleared to 0 on every exit (raced-out OR woken) so a later send re-arms it. Returns T iff stop is set."
  (loop
    (when (= 1 (dds.pal:load-sap-u64 sap +stop-off+)) (return t))
    (when (%any-data-p sap) (return nil))
    (dds.pal:store-sap-u64 sap +parked-off+ 1)
    (dds.pal:fence :full)                                ; order parked=1 store before the data/stop re-load (StoreLoad)
    (cond
      ((= 1 (dds.pal:load-sap-u64 sap +stop-off+))       ; stop raced in after we armed parked
       (dds.pal:store-sap-u64 sap +parked-off+ 0) (return t))
      ((%any-data-p sap)                                 ; a producer enqueued after we armed parked: drain, don't wait
       (dds.pal:store-sap-u64 sap +parked-off+ 0) (return nil))
      (t (dds.pal:pshared-cond-wait sap +cond-off+ +mutex-off+)   ; truly idle: block (parked stays 1)
         (dds.pal:store-sap-u64 sap +parked-off+ 0)))))   ; woken (signal/broadcast/spurious): unpark, loop re-checks

(defun* start-shmem-receiver (st on-datagram)
    (function (shmem-transport function) t)
  "Spawn a thread: block on the pshared cond until a lane has data (or stop), then drain ALL lanes and call
   ON-DATAGRAM per record. The wait uses the conditional-wakeup parked flag (%rx-wait-for-work) so a busy
   sender skips the futex wake while this thread is draining. Clean shutdown: stop-shmem-receiver sets stop
   + broadcasts (regardless of parked) to wake it."
  (let ((sap (dds.pal:shm-sap (shmem-transport-segment st))))
    (dds.pal:store-sap-u64 sap +stop-off+ 0)
    (dds.pal:store-sap-u64 sap +parked-off+ 0)
    (setf (shmem-transport-rx-thread st)
          (dds.pal:spawn
           (lambda ()
             (loop
               (dds.pal:pshared-lock sap +mutex-off+)
               (let ((stop (%rx-wait-for-work sap)))
                 (dds.pal:pshared-unlock sap +mutex-off+)
                 (when stop (return))
                 (handler-case (shmem-receive-drain st on-datagram) (error () nil)))))
           :name "dds-shmem-rx"))))

(defun* stop-shmem-receiver (st)
    (function (shmem-transport) t)
  "Signal the receive thread to exit and JOIN it before any segment teardown (no UAF)."
  (when (shmem-transport-rx-thread st)
    (let ((sap (dds.pal:shm-sap (shmem-transport-segment st))))
      (dds.pal:store-sap-u64 sap +stop-off+ 1)
      (dds.pal:pshared-lock sap +mutex-off+)
      (dds.pal:pshared-cond-broadcast sap +cond-off+)
      (dds.pal:pshared-unlock sap +mutex-off+))
    (dds.pal:join (shmem-transport-rx-thread st))
    (setf (shmem-transport-rx-thread st) nil))
  t)

(defun* run-shmem-receiver-test ()
    (function () (eql t))
  "SHMEM receiver-thread loopback: a background thread cond-waits, drains, and records a datagram;
   assert it arrives within a bounded wait. Returns T. Pass-skips on the Clasp/macOS-arm64
   by-name-attach gap (ADR 0013); on Clasp the receiver thread also needs GC_DONT_GC=1."
  (unless (shm-attach-by-name-reliable-p) (return-from run-shmem-receiver-test t))
  (let ((rx (make-shmem-transport :participant-guid (%test-guid 3) :host-uuid 7))
        (tx (make-shmem-transport :participant-guid (%test-guid 4) :host-uuid 7))
        (received nil))
    (unwind-protect
         (progn
           (start-shmem-receiver
            rx (lambda (buf size)
                 (setf received (cons size (aref (dds.core.buffer:octet-buffer-vec buf) 0)))))
           (let ((ob (dds.core.buffer:make-octet-buffer 16)) (c nil))
             (setf c (dds.core.buffer:cursor ob))
             (dds.core.buffer:put-u8 c #x55) (dds.core.buffer:put-u8 c #x66)
             (dds.xport:send (shmem-transport-transport tx) (shmem-transport-locator rx) ob 0 2))
           (loop repeat 100 until received do (sleep 0.02))
           (assert received () "SHMEM receiver thread did not deliver a datagram")
           (assert (= 2 (car received)) () "SHMEM wrong datagram size")
           (assert (= #x55 (cdr received)) () "SHMEM wrong datagram byte")
           t)
      (stop-shmem-receiver rx)
      (shmem-transport-close tx)
      (shmem-transport-close rx))))

(defun* %stress-send-all (tx loc count deadline-ns)
    (function (shmem-transport shmem-locator (integer 1) (unsigned-byte 64)) t)
  "Sender-thread body: send COUNT distinct 4-octet payloads (the running index) over TX to LOC, RETRYING a
   transient lane-full (send returns 0) with a tiny back-off until it succeeds or DEADLINE-NS passes — so a
   busy receiver applies backpressure but NO payload is dropped (the stress test asserts K*M delivered).
   Each send drives the conditional-wakeup path (%shmem-send): the only way K*M does not arrive is a lost
   wakeup or a hang, which the watchdog turns into a shortfall rather than an infinite block."
  (let ((ob (dds.core.buffer:make-octet-buffer 16)))
    (dotimes (i count t)
      (let ((c (dds.core.buffer:cursor ob)))
        (dds.core.buffer:put-u8 c (logand i #xff)) (dds.core.buffer:put-u8 c (logand (ash i -8) #xff))
        (dds.core.buffer:put-u8 c #xA5) (dds.core.buffer:put-u8 c #x5A))
      (loop until (plusp (dds.xport:send (shmem-transport-transport tx) loc ob 0 4))
            do (when (> (dds.pal:monotonic-ns) deadline-ns) (return-from %stress-send-all nil))
               (sleep 0.0002)))))

(defun* run-shmem-stress-test (&key (senders 4) (per-sender 5000) (deadline-seconds 30))
    (function (&key (:senders (integer 1)) (:per-sender (integer 1)) (:deadline-seconds (integer 1))) (eql t))
  "Conditional-wakeup contention stress (FR-XPORT-2): one receiver segment + its receiver thread, plus
   SENDERS in-process sender threads each %shmem-sending PER-SENDER distinct small payloads through claimed
   lanes; assert the receiver delivers EXACTLY senders*per-sender records within DEADLINE-SECONDS. A lost
   wakeup (the hazard of %shmem-send skipping the signal when parked=0) surfaces as a delivered-count
   SHORTFALL or a hang — the watchdog deadline turns a hang into a failed assertion rather than an infinite
   block. Pass-skips on the Clasp/macOS-arm64 by-name-attach gap (ADR 0013); on Clasp the receiver thread
   also needs GC_DONT_GC=1. Each sender uses a distinct GUID (distinct lane token), so they exercise the
   per-lane SPSC rings concurrently against the single shared notify block."
  (unless (shm-attach-by-name-reliable-p) (return-from run-shmem-stress-test t))
  (let* ((total (* senders per-sender))
         (count-lock (dds.pal:make-lock "shmem-stress"))
         (delivered 0)
         (rx (make-shmem-transport :participant-guid (%test-guid 20) :host-uuid 7 :lane-count senders))
         (txs (loop for k from 0 below senders
                    collect (make-shmem-transport :participant-guid (%test-guid (+ 21 k)) :host-uuid 7)))
         (loc (shmem-transport-locator rx)))
    (unwind-protect
         (progn
           (start-shmem-receiver
            rx (lambda (buf size) (declare (ignore buf size))
                 (dds.pal:with-lock (count-lock) (incf delivered))))
           (let* ((deadline (+ (dds.pal:monotonic-ns) (* deadline-seconds 1000000000)))
                  (threads (loop for tx in txs
                                 collect (dds.pal:spawn
                                          (let ((tx tx)) (lambda () (%stress-send-all tx loc per-sender deadline)))
                                          :name "shmem-stress-tx"))))
             (dolist (th threads) (dds.pal:join th))
             (loop until (or (>= (dds.pal:with-lock (count-lock) delivered) total)
                             (> (dds.pal:monotonic-ns) deadline))
                   do (sleep 0.005))
             (let ((got (dds.pal:with-lock (count-lock) delivered)))
               (assert (= got total) ()
                       "SHMEM stress: delivered ~d of ~d (senders=~d x per-sender=~d) — lost wakeup or hang"
                       got total senders per-sender))
             t))
      (stop-shmem-receiver rx)
      (dolist (tx txs) (shmem-transport-close tx))
      (shmem-transport-close rx))))
