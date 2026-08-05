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
    (function (t (integer 1) (integer 8)) (values t (or null keyword)))
  "Initialise header + the pshared notify block (mutex/cond/stop) + zero every lane cursor/owner.
   CAPACITY must be a multiple of 8 (:BAD-RING-GEOMETRY otherwise). Creator-only. Returns (values T NIL),
   or (values NIL status) — :BAD-RING-GEOMETRY / :MUTEX-INIT-FAILED / :COND-INIT-FAILED. Never signals:
   the geometry check was an ASSERT, which unwound the caller's stack; it is now a status value like every
   other failure in this stack."
  (unless (zerop (mod capacity 8)) (bail :bad-ring-geometry))
  (setf (cffi:mem-ref sap :uint32 +off-magic+) +shm-magic+
        (cffi:mem-ref sap :uint32 +off-version+) +shm-version+
        (cffi:mem-ref sap :uint32 +off-lane-count+) lane-count
        (cffi:mem-ref sap :uint32 +off-capacity+) capacity
        (cffi:mem-ref sap :uint32 +off-max-record+) (- capacity 8))
  (try (dds.pal:pshared-mutex-init sap +mutex-off+))
  (try (dds.pal:pshared-cond-init sap +cond-off+))
  (dds.pal:store-sap-u64 sap +stop-off+ 0)
  (dds.pal:store-sap-u64 sap +parked-off+ 0)
  (dotimes (i lane-count)
    (let ((b (%lane-desc-off i)))
      (dds.pal:store-sap-u64 sap (+ b +lane-off-owner+) 0)
      (dds.pal:store-sap-u64 sap (+ b +lane-off-write+) 0)
      (dds.pal:store-sap-u64 sap (+ b +lane-off-read+) 0)))
  (values t nil))

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
    (dds.pal:sap-copy-in sap (+ data pos 4) payload off len)   ; BULK memcpy, was one mem-ref per OCTET
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
            (t (dds.pal:sap-copy-out sap (+ data pos 4) vec 0 len)   ; BULK memcpy, was one mem-ref per OCTET
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
  (attach-cache (make-hash-table :test 'equal) :type hash-table) (sink nil :type t) (rx-thread nil :type t)   ; HOTPATH-ALLOC(COLD): defstruct initform — one table per transport, not per datagram
  ;; ADR 0100: ATTACH-CACHE is reached from FOUR threads (publisher, async sender, the receiver thread's
  ;; ACKNACK repair, the flow scheduler) on EVERY %shmem-send. Every access — read AND write — is taken under
  ;; this lock. An unsynchronised (setf gethash) corrupted the table, which SBCL reported as
  ;; `failed AVER: (= HWM (HASH-TABLE-PAIRS-CAPACITY ...))`.
  (attach-lock (dds.pal:make-lock "shmem-attach-cache") :type t))   ; HOTPATH-ALLOC(COLD): defstruct initform — one lock per transport

(defun* %guid-token (guid)
    (function ((simple-array (unsigned-byte 8) (12))) (unsigned-byte 64))
  "A nonzero 64-bit per-sender token over ALL TWELVE GUID-prefix octets, FNV-1a 64 (0 is the free-lane
   marker, so a zero hash folds to 1). Cold: computed once per segment create / per peer resolve, never
   per datagram — the send path reads the memoized SHMEM-TRANSPORT-TOKEN slot.

   ADR 0099 §3: this previously folded only octets 0..7, narrowing a 12-octet identifier to 8. Two
   participants whose prefixes differed ONLY in octets 8..11 then produced the SAME token, and that
   collides TWICE OVER — the same segment NAME, and the same LANE OWNER in %claim-lane, which returns an
   existing lane on (= owner token). Two distinct senders would share one lane in the receiver's ring,
   which is a corruption hazard, not merely a lost optimisation. FNV-1a is chosen for being trivially
   correct over 12 octets, not for cryptographic strength: nothing here is adversarial — a peer that wants
   to disrupt a segment it can already open needs no hash collision to do it."
  (let ((h 14695981039346656037))                                        ; FNV-1a 64 offset basis
    (declare (type (unsigned-byte 64) h))
    (dotimes (i 12)
      (setf h (ldb (byte 64 0) (* (logxor h (aref guid i)) 1099511628211))))   ; xor-then-multiply by the FNV 64 prime
    (if (zerop h) 1 h)))

(defun* %seg-name (guid domain)
    (function ((simple-array (unsigned-byte 8) (12)) (integer 0)) string)
  "Segment name '/dds' + the token in hex + 'd' + the DOMAIN id in hex. Length: 4 + up to 16 + 1 + up to 4
   = 25, leaving room for the ZC pool's 'z' suffix (26) under the macOS ~31-char shm-name cap."
  (format nil "/dds~(~x~)d~(~x~)" (%guid-token guid) domain))   ; HOTPATH-ALLOC(COLD): segment name, built once at segment create/open

(defun* seg-name-for-guid (guid domain)
    (function ((simple-array (unsigned-byte 8) (12)) (integer 0)) string)
  "Public alias for the deterministic receive-segment name a peer's 12-octet GUID prefix maps to IN DOMAIN
   (RTPS 2.5 §9.4.4 + this transport's %seg-name): a SENDER derives the destination segment name from the
   remote participant's prefix (FR-XPORT-2), so the discovery layer addresses a same-host SHMEM peer with
   make-shmem-locator :name (seg-name-for-guid remote-prefix domain) without reaching the %-internal.

   DOMAIN IS PART OF THE SEGMENT IDENTITY, and must be (owner directive, ADR 0099). A shm name is a
   PROCESS-GLOBAL OS object, not a domain-scoped one: without the domain, two participants that share a
   GuidPrefix in DIFFERENT DDS domains resolve to the SAME segment and cross-talk, and unlike UDP — where
   the domain's own port range separates them — nothing else keeps them apart. DDS 1.4 §2.2.1.2.2: a domain
   is an isolation boundary; a transport that ignores it is not implementing the boundary.

   The token folds ALL TWELVE prefix octets (%guid-token, FNV-1a 64), so the name distinguishes every
   (domain, participant) pair — the octet-0..7 narrowing ADR 0099 §3 recorded is closed."
  (%seg-name guid domain))

(defun* %make-shmem-transport-record (seg name host-uuid lane-count capacity token)
    (function (t string (unsigned-byte 64) (integer 1) (integer 8) (unsigned-byte 64))
              (values shmem-transport null))
  "Wrap the CREATED + INITIALISED segment SEG in the shmem-transport + the frozen dds.xport transport
   record. Split out of make-shmem-transport so that function's failure paths (which must detach SEG) stay
   readable; it is never called with a half-initialised segment. Always succeeds — returns (values st NIL)
   so it composes with the status-threading convention."
  (let ((st (%make-shmem-transport :segment seg :name name :host-uuid host-uuid :lane-count lane-count
                                   :capacity capacity :token token
                                   :sink (dds.core.buffer:make-octet-buffer capacity))))
    (setf (shmem-transport-transport st)
          (dds.xport:make-transport
           :kind :shmem :locator-kind :shmem :max-message-size (- capacity 8)
           :send (lambda (locator buffer off len) (declare (ignore off)) (%shmem-send st locator buffer len))
           :receive-loop (lambda () (values))
           :open-receive-resource (lambda (&rest a) (declare (ignore a)) (shmem-transport-locator st))
           :close (lambda () (shmem-transport-close st))))
    (values st nil)))

(defun* make-shmem-transport (&key participant-guid (domain 0) (host-uuid 0) (lane-count 8) (capacity 65536))
    (function (&key (:participant-guid (simple-array (unsigned-byte 8) (12))) (:domain (integer 0))
               (:host-uuid (unsigned-byte 64))
               (:lane-count (integer 1)) (:capacity (integer 8)))
              (values (or null shmem-transport) (or null keyword)))
  "Create this participant's SHMEM receive segment (+ ring + pshared notify block) and a transport record
   whose SEND attaches to the destination segment and enqueues. CAPACITY is per-lane ring bytes (mult of 8).
   Returns (values transport NIL), or (values NIL status) if the segment cannot be created/mapped or the
   ring cannot be initialised (the segment is detached AND unlinked again on that path — a failed transport
   leaves no mapped, half-initialised shm object behind for a peer to attach to)."
  (let* ((name (%seg-name participant-guid domain)) (token (%guid-token participant-guid)))
    (dds.pal:shm-destroy name)                       ; drop a stale leftover of the same name (no-op if absent)
    (multiple-value-bind (seg status) (dds.pal:shm-create name (%segment-bytes lane-count capacity))
      (when status (bail status))
      (multiple-value-bind (ok init-status) (%ring-init (dds.pal:shm-sap seg) lane-count capacity)
        (declare (ignore ok))
        (when init-status (dds.pal:shm-detach seg) (dds.pal:shm-destroy name) (bail init-status)))
      (%make-shmem-transport-record seg name host-uuid lane-count capacity token))))

(defun* shmem-transport-locator (st)
    (function (shmem-transport) shmem-locator)
  "The locator a peer uses to send to ST."
  (make-shmem-locator :name (shmem-transport-name st) :host-uuid (shmem-transport-host-uuid st)
                      :lane-count (shmem-transport-lane-count st) :capacity (shmem-transport-capacity st)))

(defvar *shmem-dest-cache* t
  "T (the default): %SHMEM-SEND reads the destination SAP and lane from the resolved SHMEM-DEST cached
   beside the attach (ADR 0067). NIL: re-derive both on every datagram — SHM-SAP plus a %CLAIM-LANE that
   takes the segment's pshared mutex, scans every lane descriptor and runs an unwind-protect.

   The RING BYTES are identical either way; only how the sender finds its lane differs. Kept as the A/B
   lever the NFR-MEM measurement requires (ADR 0062) and as an escape hatch — a WRONG cached lane is
   SILENT MIS-DELIVERY into another sender's ring, so the flag exists to isolate it instantly.")

(defstruct* (shmem-dest (:constructor %make-shmem-dest))
  "A RESOLVED SHMEM destination: the attached SEGMENT, its mapped SAP, and the LANE this sender holds in
   it. Resolved once per destination name and cached in SHMEM-TRANSPORT-ATTACH-CACHE (HOT PATH).

   WP-PERF (NFR-MEM, ADR 0067): %SHMEM-SEND used to re-derive both on EVERY datagram — SHM-SAP (which
   boxes a pointer) and %CLAIM-LANE, whose own docstring says 'one-time, off the hot path' but which was
   taking the segment's pshared MUTEX, scanning every lane descriptor and running an UNWIND-PROTECT per
   send. All three have the SAME LIFETIME as the attach itself, so caching them in one cell adds no new
   invalidation surface: they go stale together, exactly where the attach already did.

   LANE is NIL until claimed. A claim can legitimately fail (every lane taken), and that must stay
   RETRYABLE — the segment is still cached (we hold the mapping and must detach it at close, so dropping
   it would leak), while the NIL lane makes the next send re-attempt the claim."
  (segment nil :type t)
  (sap nil :type t)
  (lane nil :type (or null (integer 0))))

(defun* %attach-for (st locator)
    (function (shmem-transport shmem-locator) (values t (or null keyword)))
  "Cached SHMEM-DEST for LOCATOR's destination (attach + lane-claim once per name; off the hot path).
   Returns (values shmem-dest NIL), or (values NIL status) if the destination segment cannot be attached
   — a peer that died between advertising its locator and this send. That used to be an shm-attach
   CONDITION unwinding OUT OF A SEND; it is now a status, and %shmem-send turns it into the ordinary
   0-octets-sent result (the caller falls back to UDP), which is what the send path already meant to do.
   A failed attach is NOT cached: the peer may come back.

   ADR 0100: EVERY access to ATTACH-CACHE is under ATTACH-LOCK, the lookup included. This function runs on
   EVERY %shmem-send and from FOUR threads, so the per-datagram READ raced the first-send WRITE to a new
   peer; on SBCL that corrupted the table and surfaced as `failed AVER: (= HWM ...)`. A double-checked
   unlocked fast read would NOT be safe here — a reader concurrent with the rehash inside (setf gethash) is
   the same data race, merely a narrower window. The attach + lane-claim stay inside the lock so two threads
   racing the same new peer produce ONE segment attach and ONE lane claim, not two."
  (dds.pal:with-lock ((shmem-transport-attach-lock st))
    (let ((cached (gethash (shmem-locator-name locator) (shmem-transport-attach-cache st))))
      (if cached
          (values cached nil)
          (let* ((seg (try (dds.pal:shm-attach
                            (shmem-locator-name locator)
                            (%segment-bytes (shmem-locator-lane-count locator)
                                            (shmem-locator-capacity locator)))))
                 (sap (dds.pal:shm-sap seg)))
            (values (setf (gethash (shmem-locator-name locator) (shmem-transport-attach-cache st))
                          (%make-shmem-dest :segment seg :sap sap
                                            :lane (%claim-lane sap (shmem-transport-token st))))
                    nil))))))

(defun* %shmem-send (st locator buffer len)
    (function (shmem-transport shmem-locator dds.core.buffer:octet-buffer (integer 0)) (integer 0))
  "Attach to LOCATOR's segment, claim/lookup our lane, enqueue LEN octets, then CONDITIONALLY wake the
   receiver: signal the dest cond ONLY if the receiver is parked. Returns LEN on success, 0 on
   attach-fail (the peer's segment is gone) / lane-full / claim-fail — in every one of those the caller
   falls back to UDP / RESOURCE_LIMITS. The enqueue published the
   write-cursor with a RELEASE fence; a FULL fence here orders that store before the parked load (the
   StoreLoad half of the Dekker handshake with the receiver — the receiver publishes parked=1 then
   full-fences then re-checks the data, so at least one side observes the other: a skipped signal means
   the busy receiver WILL see this datagram on its next predicate check, never a lost wakeup). The
   lock+signal (a futex syscall) is taken ONLY for a parked receiver, so a tight blast into a draining
   receiver does no per-message futex wake — the WP-SHMEM throughput fix (FR-XPORT-2)."
  (when *debug-shmem-send-fault* (error 'shmem-send-test-fault))   ; test affordance: inert when NIL (byte-identical production)   ; HOTPATH-COND(TEST): fault injection, armed only by *debug-shmem-send-fault*
  (multiple-value-bind (dest attach-status) (%attach-for st locator)
    (when attach-status (return-from %shmem-send 0))   ; peer segment gone: 0 sent = the caller falls back to UDP
    ;; Resolved-once SAP + lane (ADR 0067). An unclaimed lane stays retryable: the setf re-stores NIL.
    (let* ((sap (if *shmem-dest-cache* (shmem-dest-sap dest) (dds.pal:shm-sap (shmem-dest-segment dest))))
           (lane (if *shmem-dest-cache*
                     (or (shmem-dest-lane dest)
                         (setf (shmem-dest-lane dest) (%claim-lane sap (shmem-transport-token st))))
                     (%claim-lane sap (shmem-transport-token st)))))
      (if (and lane (%lane-enqueue sap lane (shmem-locator-capacity locator)
                                   (dds.core.buffer:octet-buffer-vec buffer) 0 len))
          (progn
            (dds.pal:fence :full)                          ; order the enqueue's cursor store before the parked load (StoreLoad)
            (when (= 1 (dds.pal:load-sap-u64 sap +parked-off+))   ; wake ONLY a parked receiver; skip the futex for a busy one
              (dds.pal:pshared-lock sap +mutex-off+)
              (dds.pal:pshared-cond-signal sap +cond-off+)
              (dds.pal:pshared-unlock sap +mutex-off+))
            len)
          0))))

(defun* shmem-receive-drain (st on-datagram)
    (function (shmem-transport function) t)
  "Drain ALL lanes of ST's OWN receive segment once, calling ON-DATAGRAM per record."
  (let ((sap (dds.pal:shm-sap (shmem-transport-segment st))))
    (dotimes (i (shmem-transport-lane-count st) t)
      (%lane-drain sap i (shmem-transport-capacity st) (shmem-transport-sink st) on-datagram))))

(defun* shmem-transport-close (st)
    (function (shmem-transport) (values t (or null keyword)))
  "Stop the receiver (if any), destroy the pshared objects, detach all attached + own segments, unlink own.
   Returns (values T NIL) on a complete teardown, (values NIL :TIMEOUT) when the receiver could not be
   proven stopped — in which case the OWN segment is DELIBERATELY LEAKED, see below.

   ⚠️ THE OWN-SEGMENT TEARDOWN IS GATED ON THE RECEIVER JOIN. The receiver parks in PSHARED-COND-WAIT on a
   mutex+condvar that live INSIDE this segment, so PSHARED-DESTROY + SHM-DETACH + SHM-DESTROY under a still-
   parked receiver destroy a synchronisation object a live thread is blocked inside and unmap its stack's
   view of it — a SIGSEGV in foreign code, not a recoverable error. On :TIMEOUT those three steps are
   SKIPPED and the segment leaks (bounded, reported via dds.pal:stuck-teardown-joins). The ATTACH-CACHE
   detaches still run: those are the SENDER-side destination segments of OTHER participants, which this
   transport's receive loop never touches (it drains only its OWN segment), so releasing them races nothing."
  (multiple-value-bind (ok status) (stop-shmem-receiver st)
    (declare (ignore ok))
    (dds.pal:with-lock ((shmem-transport-attach-lock st))   ; ADR 0100: teardown walks the same table the senders fill
      (maphash (lambda (k v) (declare (ignore k)) (ignore-errors (dds.pal:shm-detach (shmem-dest-segment v))))
               (shmem-transport-attach-cache st))
      (clrhash (shmem-transport-attach-cache st)))
    (when status (return-from shmem-transport-close (values nil status)))
    (let ((sap (dds.pal:shm-sap (shmem-transport-segment st))))
      (dds.pal:pshared-destroy sap +mutex-off+ +cond-off+))
    (dds.pal:shm-detach (shmem-transport-segment st))
    (dds.pal:shm-destroy (shmem-transport-name st)))
  (values t nil))

(defun* shm-attach-by-name-reliable-p ()
    (function () t)
  "T iff a segment this process creates is re-openable BY NAME, which the SHMEM transport requires because
   the sender opens the receiver's named segment. Where this is NIL the transport's tests pass-skip.

   Asks the PAL for the CAPABILITY rather than testing the platform (ADR 0064): the reliability of
   shm_open's variadic mode_t is an implementation+ABI fact that belongs to dds-pal, and dds-xport is
   outside dds-pal, where reader conditionals are banned. DDS.PAL:SHM-CREATE-MODE-RELIABLE-P carries the
   per-arm reasoning.

   ⚠️ DO NOT 'FIX' A NIL HERE BY SWITCHING THE CFFI CALL FORM. It was tried (2026-07-14) and it looked like
   it worked. Over 30 create+reopen trials on Clasp/macOS-arm64: plain foreign-funcall 10/30,
   foreign-funcall-varargs 0/30, varargs-as-:int 10/30, varargs+fchmod 0/30. The mode lands as GARBAGE and a
   single trial passes or fails on whether those bits happened to include owner-rw — so a one-shot probe
   'proves' whichever answer you want. The fix was upstream in Clasp and landed 2026-07-31 as a C++ binding
   of shm_open, so Clasp/macOS-arm64 is now fully fitted. See dds.pal::%shm-open-create and ADR 0103."
  (dds.pal:shm-create-mode-reliable-p))

(defun* %test-guid (b)
    (function ((unsigned-byte 8)) (simple-array (unsigned-byte 8) (12)))
  "A 12-octet GUID-prefix of constant byte B (test fixture)."
  (make-array 12 :element-type '(unsigned-byte 8) :initial-element b))   ; HOTPATH-ALLOC(TEST): test fixture

(defun* run-shmem-transport-test ()
    (function () (eql t))
  "Transport-level SHMEM loopback in one image: tx SEND -> rx OWN-segment drain.
   tx and rx are distinct participants (distinct guids, same host); asserts 4 octets round-trip.
   Pass-skips on the Clasp/macOS-arm64 by-name-attach gap (ADR 0013)."
  (unless (shm-attach-by-name-reliable-p)
    (dds.pal:note-test-skip "run-shmem-transport-test" "shm-attach-by-name unreliable on this platform (ADR 0013)")
    (return-from run-shmem-transport-test t))
  (let ((rx (make-shmem-transport :participant-guid (%test-guid 1) :host-uuid 7))
        (tx (make-shmem-transport :participant-guid (%test-guid 2) :host-uuid 7)))
    (unwind-protect
         (let ((buf (dds.core.buffer:make-octet-buffer 64)) (got nil)
               (c nil))
           (setf c (dds.core.buffer:cursor buf))
           (dds.core.buffer:put-u8 c #xDE) (dds.core.buffer:put-u8 c #xAD)
           (dds.core.buffer:put-u8 c #xBE) (dds.core.buffer:put-u8 c #xEF)
           (assert (= 4 (dds.xport:send (shmem-transport-transport tx)   ; HOTPATH-COND(TEST): in-file self-test
                                        (shmem-transport-locator rx) buf 0 4))
                   () "SHMEM send must enqueue 4 octets and return 4")
           (shmem-receive-drain
            rx (lambda (s size) (setf got (cons size (aref (dds.core.buffer:octet-buffer-vec s) 0)))))
           (assert got () "SHMEM drain delivered nothing")   ; HOTPATH-COND(TEST): in-file self-test
           (assert (equal '(4 . #xDE) got) () "SHMEM round-trip mismatch: ~s (want (4 . 222))" got)   ; HOTPATH-COND(TEST): in-file self-test
           t)
      (shmem-transport-close tx)
      (shmem-transport-close rx))))

(defun* run-shmem-attach-cache-race-test ()
    (function () (eql t))
  "ADR 0100: EVERY access to a transport's ATTACH-CACHE is under ATTACH-LOCK.

   THE DEFECT THIS PINS. %attach-for did an UNLOCKED gethash followed by an UNLOCKED (setf gethash), and it
   runs on EVERY %shmem-send from FOUR threads (the publisher, the async sender, the receiver thread's
   ACKNACK repair, the flow scheduler). Concurrent mutation corrupted the table; SBCL caught its own
   invariant going down — `failed AVER: (= HWM (HASH-TABLE-PAIRS-CAPACITY ...))` — and %send-raw-buf's
   self-guard SILENTLY absorbed it into a UDP fallback, so SHMEM degraded with nothing ever going red.

   THE TEST DRIVES THE RACE DIRECTLY rather than hoping a delivery test trips it: N threads all resolve the
   SAME set of fresh destination names through ONE transport at once, which is exactly the first-send window
   where a reader raced the filling write. It asserts (1) no thread saw an error, (2) every thread got the
   SAME dest object per name — proof the fill happened exactly once and no thread observed a torn table —
   and (3) the cache holds exactly one entry per name.

   ⚠️ It cannot assert 'the old code fails': a data race is not required to manifest. What it CAN do is run
   the race hard enough that a regression is likely to be caught, and assert the INVARIANT (one dest per
   name, no errors) that unsynchronised access cannot reliably maintain.

   Pass-skips on the Clasp/macOS-arm64 by-name-attach gap (ADR 0013)."
  (unless (shm-attach-by-name-reliable-p)
    (dds.pal:note-test-skip "run-shmem-attach-cache-race-test" "shm-attach-by-name unreliable on this platform (ADR 0013)")
    (return-from run-shmem-attach-cache-race-test t))
  (let ((rxs (loop for i from 40 below 46
                   collect (make-shmem-transport :participant-guid (%test-guid i) :host-uuid 7)))
        (tx (make-shmem-transport :participant-guid (%test-guid 47) :host-uuid 7)))
    (unwind-protect
         (let* ((locs (mapcar #'shmem-transport-locator rxs))   ; HOTPATH-ALLOC(TEST): in-file self-test setup, not a send path
                (threads 6)
                (lock (dds.pal:make-lock "race-results"))
                (results '()) (errors '()))
           (let ((ts (loop repeat threads
                           collect (dds.pal:spawn
                                    (lambda ()
                                      (let ((mine '()))
                                        (handler-case
                                            (dolist (l locs)
                                              (multiple-value-bind (dest status) (%attach-for tx l)
                                                (push (cons (shmem-locator-name l) (or dest status)) mine)))
                                          (error (c) (dds.pal:with-lock (lock) (push c errors))))   ; HOTPATH-COND(TEST): the race under test would signal here
                                        (dds.pal:with-lock (lock) (push mine results))))
                                    :name "attach-race"))))
             (dolist (th ts) (dds.pal:join th)))
           (assert (null errors) () "no thread may see an error resolving the attach cache; got ~a" errors)   ; HOTPATH-COND(TEST): in-file self-test
           (assert (= threads (length results)) () "every thread must report")   ; HOTPATH-COND(TEST): in-file self-test
           ;; every thread must have obtained the IDENTICAL dest object for each name (filled exactly once)
           (dolist (l locs)
             (let* ((name (shmem-locator-name l))
                    (seen (mapcar (lambda (r) (cdr (assoc name r :test #'string=))) results)))   ; HOTPATH-ALLOC(TEST): in-file self-test assertion
               (assert (every (lambda (d) (eq d (first seen))) seen) ()   ; HOTPATH-COND(TEST): in-file self-test
                       "all threads must share ONE dest for ~a (got ~a distinct)"
                       name (length (remove-duplicates seen)))))
           (assert (= (length locs) (hash-table-count (shmem-transport-attach-cache tx))) ()   ; HOTPATH-COND(TEST): in-file self-test
                   "the cache must hold exactly one entry per name (~a names, ~a entries)"
                   (length locs) (hash-table-count (shmem-transport-attach-cache tx))))
      (shmem-transport-close tx)
      (dolist (rx rxs) (shmem-transport-close rx))))
  t)

(defun* run-shmem-dest-cache-test ()
    (function () (eql t))
  "ADR 0067: the resolved-once destination cache must never send a sender into the WRONG LANE.

   A stale or shared lane is SILENT MIS-DELIVERY — two senders writing the same ring lane interleave and
   corrupt each other's records rather than failing — so this asserts the invariant directly instead of
   trusting delivery alone. TWO senders drive the SAME receiver, repeatedly:

     1. each sender's cached lane is CLAIMED (non-NIL) and STABLE across many sends (the memo is used,
        not silently re-claimed every time);
     2. the two senders hold DISTINCT lanes (no cross-sender clobber);
     3. the memo AGREES WITH THE AUTHORITY — a fresh %CLAIM-LANE for that token returns the cached lane
        (this is what would go red if the cache ever drifted from the ring's own ownership table);
     4. every record from both senders arrives with its own payload intact.

   Pass-skips on the Clasp/macOS-arm64 by-name-attach gap (ADR 0013)."
  (unless (shm-attach-by-name-reliable-p)
    (dds.pal:note-test-skip "run-shmem-dest-cache-test" "shm-attach-by-name unreliable on this platform (ADR 0013)")
    (return-from run-shmem-dest-cache-test t))
  (let ((rx (make-shmem-transport :participant-guid (%test-guid 11) :host-uuid 7))
        (a (make-shmem-transport :participant-guid (%test-guid 12) :host-uuid 7))
        (b (make-shmem-transport :participant-guid (%test-guid 13) :host-uuid 7)))
    (unwind-protect
         (let ((buf (dds.core.buffer:make-octet-buffer 64))
               (loc (shmem-transport-locator rx))
               (seen '()) (lane-a nil) (lane-b nil))
           (flet ((send1 (st tag)
                    (let ((c (dds.core.buffer:cursor buf)))
                      (dotimes (i 4) (dds.core.buffer:put-u8 c tag)))
                    (dds.xport:send (shmem-transport-transport st) loc buf 0 4))
                  (lane-of (st)
                    (shmem-dest-lane (gethash (shmem-locator-name loc)
                                              (shmem-transport-attach-cache st)))))
             (send1 a #xA1) (send1 b #xB2)
             (setf lane-a (lane-of a) lane-b (lane-of b))
             (assert (and lane-a lane-b) () "both senders must hold a claimed lane")   ; HOTPATH-COND(TEST): in-file self-test
             (assert (/= lane-a lane-b) () "two senders must hold DISTINCT lanes (~a vs ~a)" lane-a lane-b)   ; HOTPATH-COND(TEST): in-file self-test
             (dotimes (i 12) (send1 a #xA1) (send1 b #xB2))
             (assert (and (eql lane-a (lane-of a)) (eql lane-b (lane-of b))) ()   ; HOTPATH-COND(TEST): in-file self-test
                     "a cached lane must be STABLE across sends")
             ;; the memo must agree with the ring's own ownership table, not merely be self-consistent
             (let ((sap (dds.pal:shm-sap (shmem-dest-segment
                                          (gethash (shmem-locator-name loc)
                                                   (shmem-transport-attach-cache a))))))
               (assert (eql lane-a (%claim-lane sap (shmem-transport-token a))) ()   ; HOTPATH-COND(TEST): in-file self-test
                       "the cached lane must equal a fresh %claim-lane for the same token"))
             (shmem-receive-drain
              rx (lambda (s size)
                   (push (cons size (aref (dds.core.buffer:octet-buffer-vec s) 0)) seen)))
             (assert (= 26 (length seen)) () "want 26 records, got ~a" (length seen))   ; HOTPATH-COND(TEST): in-file self-test
             (assert (= 13 (count #xA1 seen :key #'cdr)) () "sender A's records must arrive intact")   ; HOTPATH-COND(TEST): in-file self-test
             (assert (= 13 (count #xB2 seen :key #'cdr)) () "sender B's records must arrive intact")   ; HOTPATH-COND(TEST): in-file self-test
             t))
      (shmem-transport-close a)
      (shmem-transport-close b)
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

(defun* %env-spin-iterations (default)
    (function ((integer 0)) (integer 0))
  "Effective spin budget at load: the DDS_SHMEM_RX_SPIN_ITERATIONS environment variable when it parses to a
   non-negative integer, else DEFAULT. Lets a deployment tune (or disable, with 0) the SHMEM receiver's
   spin WITHOUT a code change or a rebuild — the same configurability rule the send-path buffer sizes follow."
  (let ((raw (uiop:getenv "DDS_SHMEM_RX_SPIN_ITERATIONS")))
    (or (and raw (ignore-errors
                  (let ((n (parse-integer (string-trim " " raw))))
                    (and (>= n 0) n))))
        default)))

(defparameter *shmem-rx-spin-iterations* (%env-spin-iterations 1000)
  "LATENCY vs CPU: how many times the SHMEM receiver re-checks its lanes BEFORE it takes the mutex and parks
   on the pshared condvar. **Default 1000** (owner directive 2026-07-13). 0 = park immediately (the
   historical behaviour). Overridable at deployment with the DDS_SHMEM_RX_SPIN_ITERATIONS environment
   variable, and settable at runtime — the spin budget is re-read on every wait, so it can be retuned on a
   live node.

   WHY. Parking costs a cross-process futex round trip: the sender must issue a pthread_cond_signal (macOS
   __psynch_cvsignal) AND the receiver must then be SCHEDULED onto a core before it can even look at the
   data. Measured: ~6 us of the ~16 us 256 B one-way, and __psynch_cvsignal was the single largest item in
   the responder's CPU profile (30%). It is also the whole of our distance to Connext: on UDP we are 1.33x of
   Connext, on SHMEM 2.34x — Connext extracts 2.76x from shared memory where we extract only 1.57x
   (bench/report/2026-07-13-the-gap-is-our-shmem.md). A receiver still spinning when the datagram lands skips
   BOTH halves of the wake — and costs the SENDER nothing either, because %shmem-send only takes the mutex
   and signals when parked=1.

   MEASURED (256 B one-way p50 / responder CPU over the same run):
     spin      0 -> 19 125 ns / 0.76 s     (park immediately)
     spin    500 -> 12 270 ns / 0.98 s
     spin   1000 -> the default: essentially all of the win, bounded cost
     spin   5000 -> 11 791 ns / 0.93 s
     spin  50000 -> 11 750 ns / 0.95 s     (no worse than 500 — see below)
   19.1 -> 11.8 us, a 7.3 us cut that matches the measured wake, saturating by ~500 iterations. It takes the
   SHMEM ratio against Connext from 2.34x to 1.68x.

   THE CPU COST IS BOUNDED, and the intuition that a spin 'burns a core' is WRONG here: the spin EXITS the
   instant data lands, and a genuinely idle receiver still exhausts its budget and PARKS — then stays parked
   until signalled. It therefore runs once per wake, not continuously, which is why 50 000 iterations cost no
   more CPU than 500. Measured overhead is +29% CPU on the receiver for a 39% latency cut. Set 0 to restore
   the pure blocking behaviour on a CPU-constrained node.

   Iterations, not nanoseconds, deliberately: a time-based spin must read the clock every turn, and
   MONOTONIC-NS costs ~633 ns on Clasp (libffi) — the clock read would dominate the spin itself.")

(defun* %rx-spin-for-work (sap)
    (function (t) t)
  "Spin up to *SHMEM-RX-SPIN-ITERATIONS* times waiting for a lane to fill, WITHOUT holding the pshared mutex
   and WITHOUT arming the parked flag. Returns :DATA if a lane filled, :STOP if teardown was signalled, or
   NIL if the spin budget ran out (the caller then takes the mutex and parks).

   OUTSIDE THE MUTEX — that placement is the whole point, and getting it wrong is what sank the first
   attempt. Spinning INSIDE %rx-wait-for-work (which runs with the mutex HELD) starves stop-shmem-receiver,
   which needs that same mutex to broadcast: latency went 7x WORSE and a long spin HUNG on teardown. Here the
   mutex is free throughout, so teardown proceeds immediately — and STOP is re-checked every iteration, so
   this loop exits promptly regardless of the budget.

   Race-free by construction: parked stays 0 for the whole spin, and %shmem-send enqueues into a LOCK-FREE
   lane and only takes the mutex + signals when it observes parked=1. A spinning receiver therefore cannot
   miss a datagram (it polls the lanes directly) and cannot block a sender."
  (loop repeat *shmem-rx-spin-iterations*
        do (when (= 1 (dds.pal:load-sap-u64 sap +stop-off+)) (return-from %rx-spin-for-work :stop))
           (when (%any-data-p sap) (return-from %rx-spin-for-work :data)))
  nil)

(defun* start-shmem-receiver (st on-datagram)
    (function (shmem-transport function) t)
  "Spawn a thread: block on the pshared cond until a lane has data (or stop), then drain ALL lanes and call
   ON-DATAGRAM per record. The wait uses the conditional-wakeup parked flag (%rx-wait-for-work) so a busy
   sender skips the futex wake while this thread is draining. Clean shutdown: stop-shmem-receiver sets stop
   + broadcasts (regardless of parked) to wake it.

   Optionally SPINS first (%rx-spin-for-work, *shmem-rx-spin-iterations*, default 0 = off) — outside the
   mutex, so a spinning receiver never blocks teardown. A spin that finds data skips the park entirely, and
   with it the cross-process wake that is our whole remaining distance to Connext on this transport."
  (let ((sap (dds.pal:shm-sap (shmem-transport-segment st))))
    (dds.pal:store-sap-u64 sap +stop-off+ 0)
    (dds.pal:store-sap-u64 sap +parked-off+ 0)
    (setf (shmem-transport-rx-thread st)
          (dds.pal:spawn
           (lambda ()
             (loop
               (let ((spun (%rx-spin-for-work sap)))          ; NO mutex held here
                 (when (eq spun :stop) (return))
                 (unless (eq spun :data)                      ; spin budget exhausted (or 0): park
                   (dds.pal:pshared-lock sap +mutex-off+)
                   (let ((stop (%rx-wait-for-work sap)))
                     (dds.pal:pshared-unlock sap +mutex-off+)
                     (when stop (return)))))
               (handler-case (shmem-receive-drain st on-datagram) (error () nil))))
           :name "dds-shmem-rx"))))

(defun* stop-shmem-receiver (st)
    (function (shmem-transport) (values t (or null keyword)))
  "Signal the receive thread to exit and JOIN it — BOUNDED — before any segment teardown (no UAF).
   Returns (values T NIL) when the receiver is PROVABLY gone, (values NIL :TIMEOUT) when it is not.

   ⚠️ THE STATUS IS LOAD-BEARING, NOT ADVISORY. This receiver parks in PSHARED-COND-WAIT on a condvar that
   lives INSIDE the shared-memory segment. If it is still parked, SHMEM-TRANSPORT-CLOSE's PSHARED-DESTROY /
   SHM-DETACH / SHM-DESTROY unmap the very memory it is blocked on — not a leak but a SIGSEGV in a foreign
   wait, and on Linux an unlinked segment other processes still need. So on :TIMEOUT the caller MUST skip
   that teardown and LEAK the segment. Same ranking as STOP-NODE (ADR 0091): a bounded leak beats
   destroying an object a live thread is blocked inside.

   The stop protocol below (store stop=1, lock, broadcast, unlock) LOOKS sufficient — but so did UDP's
   close-then-join, which hung forever on a receiver already inside the syscall. A wait that cannot be
   proven to terminate is bounded and REPORTED (dds.pal:stuck-teardown-joins), never trusted."
  (when (shmem-transport-rx-thread st)
    (let ((sap (dds.pal:shm-sap (shmem-transport-segment st))))
      (dds.pal:store-sap-u64 sap +stop-off+ 1)
      (dds.pal:pshared-lock sap +mutex-off+)
      (dds.pal:pshared-cond-broadcast sap +cond-off+)
      (dds.pal:pshared-unlock sap +mutex-off+))
    (multiple-value-bind (r status)
        (dds.pal:join-bounded (shmem-transport-rx-thread st) :shmem-receiver)
      (declare (ignore r))
      (when status (return-from stop-shmem-receiver (values nil status)))
      (setf (shmem-transport-rx-thread st) nil)))
  (values t nil))

(defun* run-shmem-receiver-test ()
    (function () (eql t))
  "SHMEM receiver-thread loopback: a background thread cond-waits, drains, and records a datagram;
   assert it arrives within a bounded wait. Returns T. Pass-skips on the Clasp/macOS-arm64
   by-name-attach gap (ADR 0013); on Clasp the receiver thread also needs GC_DONT_GC=1."
  (unless (shm-attach-by-name-reliable-p)
    (dds.pal:note-test-skip "run-shmem-receiver-test" "shm-attach-by-name unreliable on this platform (ADR 0013)")
    (return-from run-shmem-receiver-test t))
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
           (assert received () "SHMEM receiver thread did not deliver a datagram")   ; HOTPATH-COND(TEST): in-file self-test
           (assert (= 2 (car received)) () "SHMEM wrong datagram size")   ; HOTPATH-COND(TEST): in-file self-test
           (assert (= #x55 (cdr received)) () "SHMEM wrong datagram byte")   ; HOTPATH-COND(TEST): in-file self-test
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
  (unless (shm-attach-by-name-reliable-p)
    (dds.pal:note-test-skip "run-shmem-stress-test" "shm-attach-by-name unreliable on this platform (ADR 0013)")
    (return-from run-shmem-stress-test t))
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
             ;; the senders bound themselves by DEADLINE-SECONDS, so the join deadline must exceed it — a
             ;; blanket 5 s bound here would fail a HEALTHY run rather than catch a hung one
             (dolist (th threads) (dds.pal:join-bounded th :shmem-stress-tx (+ deadline-seconds 30)))
             (loop until (or (>= (dds.pal:with-lock (count-lock) delivered) total)
                             (> (dds.pal:monotonic-ns) deadline))
                   do (sleep 0.005))
             (let ((got (dds.pal:with-lock (count-lock) delivered)))
               (assert (= got total) ()   ; HOTPATH-COND(TEST): in-file self-test
                       "SHMEM stress: delivered ~d of ~d (senders=~d x per-sender=~d) — lost wakeup or hang"
                       got total senders per-sender))
             t))
      (stop-shmem-receiver rx)
      (dolist (tx txs) (shmem-transport-close tx))
      (shmem-transport-close rx))))
