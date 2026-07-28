(in-package #:dds.rtps.reliable)

;;;; Stateful reliable writer/reader protocol logic (RTPS 2.5 §8.4). Operates on
;;;; submessage field VALUES (not bytes) so the state machines are directly
;;;; testable; the byte/transport wiring is a later increment. CLOS-free; the
;;;; consing here (per-reader proxies, resend lists) is a documented v1 concern.

(defparameter *fragment-size* 1024
  "Outbound RTPS fragmentSize in octets (uint16, <=65535; RTPS 2.5 §9.4.5.5 DATA_FRAG). A sample whose
   serialized size exceeds this is sent as DATA_FRAG submessages.

   THIS IS AN INTEROP CONTRACT, NOT A TUNING KNOB (ADR 0079). RTPS 2.5 §8.4.14.1 requires it to be FIXED for
   a given Writer and IDENTICAL for all remote Readers — fragment numbers are the wire identity of byte
   ranges (reassembly offset is (fragmentStartingNum-1) * fragmentSize), so a NackFrag naming fragment 3
   must mean the same bytes to every reader. The spec explicitly forbids re-deriving it for newly discovered
   Readers, and it must be set by 'the transport with the smallest maximum message size' across ALL
   transports available to the Writer — NOT merely those reaching the currently known peers.

   WHY 1024. Our smallest transport is UDPv4 across an Ethernet path: MTU 1500 - 20 IPv4 - 8 UDP = 1472
   octets of payload. One fragment costs 56 octets of framing (20 RTPS header + 4 submessage header + 32
   DATA_FRAG fields, see write-data-frag), so the MTU ceiling is 1416 and *coalesce-datagram-budget* (1400)
   tightens it to 1344. 1024 is chosen under that with deliberate headroom for IPv6 (40-octet header), VLAN
   tags, tunnelled/VPN paths with a reduced effective MTU, and the DDS-Security SEC_PREFIX/SEC_POSTFIX
   wrapping that grows every protected submessage. Measured: 1024 yields a 1080-octet RTPS datagram, 1108 on
   the wire.

   The previous default of 63000 made a multi-KB sample ride UNFRAGMENTED in a single oversized datagram,
   which a peer whose UDPv4 transport is MTU-bounded silently discards, and which any real 1500-MTU path
   must IP-fragment. Live proof: RTI Connext with the ordinary message_size_max=1400 received ZERO of our
   8000-octet samples at 63000. Large-sample THROUGHPUT is recovered where the spec puts it — per transport,
   by concatenating as many fragments as a transport can accommodate (%pack-budget) — not by a fragment size
   the network cannot carry.")

(defparameter *max-reassembly-bytes* (* 4 1024 1024)
  "Reject an inbound DATA_FRAG sampleSize larger than this BEFORE allocating the reassembly buffer (resource-exhaustion guard, NFR-SEC-POSTURE).")

(defparameter *max-reassembly-fragments* 8192
  "Cap on the fragment count per reassembled sample (NFR-SEC-POSTURE).")

(defparameter *max-gap-range* 65536
  "Cap on the contiguous [gapStart, base) span a single inbound GAP may mark irrelevant, BEFORE
   iterating it — gapStart/base are wire-controlled 64-bit values and last-sn is itself set from
   inbound HEARTBEATs, so neither bounds the loop; an unclamped span is a CPU+memory DoS
   (resource-exhaustion guard, NFR-SEC-POSTURE; RTPS 2.5 §8.3.7.4). A legitimately larger evicted
   run is recovered across subsequent GAP/HEARTBEAT rounds (firstSN compaction), so capping is loss-free.")

(defparameter *max-dedup-origins* 256
  "Cap on the number of distinct ORIGINAL-WRITER GUIDs a reader will track dedup state for
   (resource-exhaustion guard, NFR-SEC-POSTURE; RTPS 2.5 §8.3.5.4).

   The key is wire-supplied — it is the GUID inside PID_ORIGINAL_WRITER_INFO in a DATA's inline QoS — so
   without a cap any peer able to send us a DATA can mint unbounded dedup-origins simply by varying it,
   each carrying its own out-of-order window. Uncapped that is an unbounded memory DoS keyed by attacker
   data, which is exactly the class NFR-SEC-POSTURE requires be guarded.

   AT THE CAP A NEW ORIGIN IS REFUSED, AND ITS SAMPLES ARE ACCEPTED UNTRACKED — never dropped. Refusing
   to track costs at worst a duplicate delivery if that origin also retransmits; refusing to DELIVER would
   be silent loss, and a false reject is the worse failure. Existing origins are never evicted to make
   room: evicting a tracked origin's watermark would risk double-delivering everything it had already
   dedup'd, the same reasoning ADR 0024 §10.2 settled for the durability service's origin cap.
   Refusals are COUNTED and readable via READER-DEDUP-ORIGINS-REFUSED (reported, never printed).")

;;; ---- Writer side (§8.4.2): one ReaderProxy per matched reader ----

(defstruct* (reader-proxy (:constructor make-reader-proxy))
  "Writer-side proxy for one matched reader (RTPS 2.5 §8.4.2). Two distinct
   watermarks (RTPS 2.5 §8.4.2.2): ACKED-BASE is the reader's ACKNOWLEDGED watermark
   (it has acknowledged all SN < acked-base; advanced only by ACKNACK); UNSENT-BASE
   is the UNSENT watermark = 1 + highestSentChangeSN (next_unsent_change pushes the
   change at UNSENT-BASE once, then advances it). Push pacing keys off UNSENT-BASE;
   ACKNACK-driven repair (requested_changes) is independent of it."
  (acked-base 1 :type integer)             ; reader has acknowledged all SN < acked-base
  (unsent-base 1 :type integer)            ; 1 + highestSentChangeSN; changes >= this are unsent
  ;; ADR 0090 A3c: the APPLICATION watermark — the reader's application has acknowledged all SN <
  ;; APP-ACKED-BASE. INDEPENDENT of ACKED-BASE and never derived from it (ADR 0090 §7 Q1): a sample can be
  ;; protocol-acked and not yet app-acked, NEVER the reverse, so the two must be tracked separately and the
  ;; purge takes the MINIMUM. Advanced only by writer-on-app-ack, i.e. only by an APP_ACK the reader sent.
  ;; It stays at 1 for a reader that never app-acks, which is what pins a purge that is gated on it — the
  ;; whole point of the feature, and why the gate is per-writer QoS rather than unconditional.
  (app-acked-base 1 :type integer))

(defstruct* (rtps-writer (:constructor make-rtps-writer))
  "Stateful reliable RTPS writer (RTPS 2.5 §8.4.2): a HistoryCache, the last SN
   written, the HEARTBEAT count, a reader-id -> ReaderProxy table, and a LOCK serializing all access to
   the HistoryCache + proxies — the disc layer drives the writer from TWO threads (publish on the caller
   thread; ACKNACK/purge on the receiver thread), so every public writer op below takes the lock.
   SPACE-CV + MAX-BLOCKING-NS implement DDS-standard block-up-to-max_blocking_time backpressure
   (WP-ASYNC-FLOW, FR-PF-2/FR-QOS, ADR 0016): on a FULL KEEP_ALL cache (RESOURCE_LIMITS max_samples)
   writer-write/writer-lifecycle-change block on SPACE-CV — paired with LOCK — for up to MAX-BLOCKING-NS
   ns (RELIABILITY.max_blocking_time), then return :timeout (RETCODE_TIMEOUT) with the cache intact;
   SPACE-CV is broadcast whenever the cache shrinks — a KEEP_ALL cache shrinks only on the ACKNACK purge
   (writer-purge-acked, the slowest reader having ACKed), so that is the in-steady-state space signal;
   controller teardown also signals so a blocked publish reaches its TIMEOUT (%writer-signal-space). MAX-BLOCKING-NS NIL ⇒ no
   blocking (the cache bound is then never reached for an unlimited cache; the degenerate 0 ⇒ immediate
   :timeout when full). The bound applies to ALL changes (data + dispose/unregister) — RTPS 2.5 §8.4.2.2
   gives every change a SN, so the cache occupancy is consistent across kinds (ADR 0016 §Backpressure).
   FINALIZED (durability-finalize, DDS 1.4 §2.2.3.4; the OPT-IN extension ON TOP of the conformant default,
   NIL = standard TRANSIENT_LOCAL) when T makes writer-purge-acked treat a TRANSIENT_LOCAL writer as
   VOLATILE — re-enabling the full-ACK purge so the retained late-joiner history is RELEASED once all current
   readers ACK; monotonic (set once by writer-finalize-durability, never cleared in v1).

   ACKED-WATERMARK + REPLACED-UNACKED are the two engine facts the vendor RELIABLE_WRITER_CACHE_CHANGED
   status is derived from (ADR 0089). ACKED-WATERMARK is min(acked-base) over the CURRENTLY MATCHED readers
   — the writer-global acknowledged watermark, maintained by writer-purge-acked whether or not it goes on
   to purge, so it stays true for a TRANSIENT_LOCAL writer that retains everything. REPLACED-UNACKED counts
   changes that KEEP_LAST overwrote while they were still BELOW that watermark's reach, i.e. samples the
   application wrote that no longer exist and were never acknowledged by every matched reader. It is the
   one number in the whole status that names actual data loss."
  (hc nil :type (or null dds.rtps.history:history-cache))  ; a HistoryCache
  (entityid 0 :type (unsigned-byte 32))   ; WP-N-ENDPOINT-S1 (ADR 0048): this writer's own RTPS EntityId (RTPS 2.5 §9.3.1.2); the send fan-out stamps it so each local DataWriter's DATA/HEARTBEAT carry its OWN GUID (0 = unset, the pre-S1 default)
  (last-sn 0 :type integer)
  (hb-count 0 :type integer)
  (proxies (make-hash-table :test 'equalp) :type hash-table)   ; reader key (opaque, equalp) -> reader-proxy
  (key-cache nil :type (or null simple-vector))   ; ADR 0088: bounded WRITE-ONCE cache of 16-octet remote-reader GUIDs, so the per-datagram control path (ACKNACK) looks a proxy up without building a fresh key; entries are never mutated in place, so a concurrent reader sees a whole valid GUID or NIL and %writer-lookup-key's byte-compare decides — a race can only MISS, never return a wrong key (NFR-MEM)
  (frag-hb-count 0 :type integer)   ; HEARTBEAT_FRAG Count, separate from hb-count
  (lock (dds.pal:make-lock) :type t)
  (space-cv (dds.pal:make-condvar) :type t)   ; signalled (under LOCK) when the cache shrinks; writer-write waits on it when full (ADR 0016 §Backpressure)
  (max-blocking-ns nil :type (or null (integer 0)))   ; RELIABILITY.max_blocking_time in ns; NIL = never block (unlimited cache)
  (finalized nil :type boolean)   ; durability-finalize (DDS 1.4 §2.2.3.4 extension): a TL writer reverts to the VOLATILE full-ACK purge
  (acked-watermark 1 :type integer)      ; ADR 0089: min(acked-base) over matched readers; 1 = nothing acknowledged yet
  (replaced-unacked 0 :type integer))    ; ADR 0089: monotonic count of KEEP_LAST evictions of a not-fully-acked change

(defmacro %with-writer-lock ((writer) &body body)
  "Serialize BODY's access to WRITER's HistoryCache + proxies (publish thread vs receiver thread). The
   guarded public ops never call one another, so the non-recursive lock cannot self-deadlock; the internal
   helpers (get-reader-proxy, %changes-from) run only inside a held lock."
  `(dds.pal:with-lock ((rtps-writer-lock ,writer)) ,@body))

(defun* %writer-blockable-p (writer)
    (function (rtps-writer) t)
  "T iff a publisher CAN EVER be blocked on WRITER's SPACE-CV — i.e. the cache is a BOUNDED KEEP_ALL
   (max_samples set) AND max_blocking_time is set. That is EXACTLY the condition under which
   %writer-add-bounded condvar-waits; if it is false, no thread can be waiting on SPACE-CV, ever."
  (let ((hc (rtps-writer-hc writer)))
    (and (eq (dds.rtps.history:hc-kind hc) :keep-all)
         (dds.rtps.history:hc-max-samples hc)
         (rtps-writer-max-blocking-ns writer)
         t)))

(defun* %writer-signal-space (writer)
    (function (rtps-writer) t)
  "Broadcast WRITER's SPACE-CV under the writer LOCK — wake every writer-write/writer-lifecycle-change
   blocked waiting for the bounded KEEP_ALL cache to drop below max_samples (WP-ASYNC-FLOW backpressure,
   ADR 0016 §Backpressure). Call AFTER any operation that frees cache space: the ACKNACK purge
   (writer-purge-acked — a KEEP_ALL cache shrinks only when the slowest reader ACKs, RTPS 2.5 §8.4.1) and
   controller teardown. condvar-BROADCAST (not signal): several publishers may be blocked, and one freed slot
   may admit exactly one — each re-checks the count on wake (a no-progress waker re-blocks until its
   deadline).

   WP-PERF: NO-OP unless a waiter can exist (%writer-blockable-p). This is called from the ACKNACK purge, so
   it ran ONCE PER SAMPLE on the receiver thread — and on the DEFAULT (unlimited / KEEP_LAST) writer NOBODY
   CAN EVER BE WAITING on SPACE-CV, so it was taking the writer lock and issuing a pthread_cond_broadcast per
   sample to wake nobody. macOS traps into __psynch_cvsignal regardless of whether a waiter exists — that
   symbol was the SINGLE LARGEST item in the responder's CPU profile under a live echo (30%). Guarding it
   removes one lock round-trip and one kernel wake from every sample on the default path; the bounded-KEEP_ALL
   backpressure path is unaffected (its waiters are exactly the case the guard admits)."
  (when (%writer-blockable-p writer)
    (%with-writer-lock (writer)
      (dds.pal:condvar-broadcast (rtps-writer-space-cv writer))))
  t)

(defun* %writer-add-bounded (writer make-change)
    (function (rtps-writer function) (values (or integer (eql :timeout)) t))
  "Add the change produced by the thunk MAKE-CHANGE (given the freshly-bumped SN) to WRITER's HistoryCache
   under the writer LOCK, applying DDS-standard block-up-to-max_blocking_time backpressure (WP-ASYNC-FLOW,
   FR-PF-2/FR-QOS, ADR 0016 §Backpressure). Shared core of writer-write + writer-lifecycle-change (DRY).

   Returns (values SN CHANGE) — the CHANGE second value only because withholding it was expensive: it was
   already in hand here, and writer-write got it out through a MUTABLE variable captured by MAKE-CHANGE,
   which on SBCL costs a heap value cell per write on top of the closure (NFR-MEM). On :timeout both are
   the timeout sentinel and NIL, as before.

   For a BOUNDED cache (KEEP_ALL with a finite max_samples): when full (count >= max_samples) and
   MAX-BLOCKING-NS is set, BLOCK on SPACE-CV — which RELEASES the writer LOCK while waiting, so the purge
   path can take the LOCK to free space + %writer-signal-space — until either the count drops below
   max_samples (space freed) or the deadline (now + MAX-BLOCKING-NS) passes. After the wait (or with
   MAX-BLOCKING-NS NIL ⇒ no wait, or MAX-BLOCKING-NS 0 ⇒ no wait), a single re-check: if the cache is STILL
   full, return :timeout (RETCODE_TIMEOUT) WITHOUT bumping the SN or adding the change (the cache is left
   intact). So a bounded full cache ALWAYS yields :timeout (never a silent hc-add-change rejection that would
   consume an SN without storing — the SN is bumped only after room is confirmed, so the reliable SN stream
   has no holes). For an UNLIMITED (max_samples NIL) or KEEP_LAST cache there is no bound: bump the SN, add,
   return it — the prior behaviour, byte-identical (the default path is unchanged).

   LOCK ordering: the only lock held across the wait is the writer LOCK, released by condvar-wait; the
   freeing thread (the ACKNACK purge, writer-purge-acked, on the receiver thread — NOT the paced scheduler,
   which is send-only and never purges a KEEP_ALL cache) takes the same LOCK to purge + signal, so there is
   no lock-ordering cycle (ADR 0016 §Backpressure)."
  (%with-writer-lock (writer)
    (let* ((hc (rtps-writer-hc writer))
           (max-samples (dds.rtps.history:hc-max-samples hc))
           (bounded (and (eq (dds.rtps.history:hc-kind hc) :keep-all) max-samples))
           (block-ns (rtps-writer-max-blocking-ns writer)))
      (when bounded
        (when block-ns                                   ; block up to max_blocking_time for a free slot
          (let ((deadline (+ (dds.pal:monotonic-ns) block-ns)))
            (loop while (>= (dds.rtps.history:hc-change-count hc) max-samples)
                  for remaining = (- deadline (dds.pal:monotonic-ns))
                  while (plusp remaining)
                  do (dds.pal:condvar-wait (rtps-writer-space-cv writer) (rtps-writer-lock writer)
                                           (/ remaining 1000000000.0d0)))))
        (when (>= (dds.rtps.history:hc-change-count hc) max-samples)   ; still full (deadline passed / no blocking): reject, NO SN consumed
          (return-from %writer-add-bounded (values :timeout nil))))
      (let* ((sn (incf (rtps-writer-last-sn writer)))                  ; room confirmed (or unlimited / KEEP_LAST)
             (change (funcall make-change sn))
             (evicted (nth-value 1 (dds.rtps.history:hc-add-change hc change))))
        ;; ADR 0089: a KEEP_LAST eviction at or above the acked watermark destroyed data no reader has.
        (when (and evicted (>= (the integer evicted) (rtps-writer-acked-watermark writer)))
          (incf (rtps-writer-replaced-unacked writer)))
        (values sn change)))))

(defun* %retained-endpoint-key (key)
    (function (t) t)
  "KEY, COPIED if it is a sequence — the private key a proxy table RETAINS (ADR 0088, NFR-MEM).

   The proxy tables are the only structures that outlive the call holding the caller's key; every other
   use of an endpoint key is a transient lookup. Copying HERE, at the single point of retention, is what
   makes it SAFE BY CONSTRUCTION for a caller to pass a reused or cached buffer — rather than safe by an
   audit of every present and future caller, which is the durability objection ADR 0062 §6 raised against
   a shared scratch. Without it a reused caller buffer would BE the live hash key: the next datagram
   mutates it in place, the proxy becomes unfindable, a fresh one is created, and the writer's acked-base
   SILENTLY stops advancing — no crash, no error, just reliability quietly ceasing to work.

   Cost is one COPY-SEQ per endpoint per process lifetime (measured: 1 creation per 3000 samples against
   9901 lookups). An integer — the value-level tests' key — has nothing to alias and passes through."
  (if (typep key 'sequence) (copy-seq key) key))

(defconstant +key-cache-size+ 4
  "How many remote-endpoint GUIDs a writer caches for the control-path proxy lookup (ADR 0088). BOUNDED
   on purpose: the number of remote readers is chosen by the PEERS, so an unbounded cache would be a
   remote-drivable growth path (NFR-SEC-POSTURE). A writer with more than this many matched readers
   simply misses more often and falls back to building a key — slower, never wrong.")

(defun* %guid-names-endpoint-p (guid src-prefix entity-id)
    (function ((simple-array (unsigned-byte 8) (16)) (simple-array (unsigned-byte 8) (12))
               (unsigned-byte 32))
              boolean)
  "Does the 16-octet GUID name exactly the endpoint (SRC-PREFIX, ENTITY-ID)? The full 16-octet identity
   test (RTPS 2.5 §9.4.4 / §9.3.1.2: GUID = GuidPrefix ++ EntityId), allocation-free.

   THIS COMPARISON IS THE WHOLE SAFETY ARGUMENT of the key cache (ADR 0088). It is not a hint or a hash
   check to be skipped on the fast path: a cache hit is believed ONLY because these 16 octets matched, so
   a stale, half-published or wrong-slot entry can never be mistaken for the right one. Weakening this to
   a fingerprint would reintroduce a collision class whose symptom is the WRONG ReaderProxy — silently
   mis-attributed reliability state, not a crash."
  (and (dotimes (i 12 t) (unless (= (aref guid i) (aref src-prefix i)) (return nil)))
       (= (aref guid 12) (ldb (byte 8 24) entity-id))
       (= (aref guid 13) (ldb (byte 8 16) entity-id))
       (= (aref guid 14) (ldb (byte 8 8) entity-id))
       (= (aref guid 15) (ldb (byte 8 0) entity-id))
       t))

(defun* %build-endpoint-guid (src-prefix entity-id)
    (function ((simple-array (unsigned-byte 8) (12)) (unsigned-byte 32))
              (simple-array (unsigned-byte 8) (16)))
  "A fresh 16-octet GUID = SRC-PREFIX ++ ENTITY-ID (RTPS 2.5 §9.4.4 / §9.3.1.2). The miss path of
   WRITER-LOOKUP-KEY builds its own key rather than taking a builder callback: a closure over the prefix
   and id would allocate ON EVERY CALL, including cache HITS, which silently trades one 32-octet
   allocation for another and wins nothing (measured — the first cut of ADR 0088 did exactly this and
   moved gate-mem by +1.6 B, i.e. not at all)."
  (let ((g (make-array 16 :element-type '(unsigned-byte 8))))
    (replace g src-prefix :end2 12)
    (setf (aref g 12) (ldb (byte 8 24) entity-id) (aref g 13) (ldb (byte 8 16) entity-id)
          (aref g 14) (ldb (byte 8 8) entity-id)  (aref g 15) (ldb (byte 8 0) entity-id))
    g))

(defun* writer-lookup-key (writer src-prefix entity-id)
    (function (rtps-writer (simple-array (unsigned-byte 8) (12)) (unsigned-byte 32))
              (simple-array (unsigned-byte 8) (16)))
  "The 16-octet GUID naming remote endpoint (SRC-PREFIX, ENTITY-ID), from WRITER's bounded key cache when
   it is already there, else built by %BUILD-ENDPOINT-GUID and remembered (ADR 0088, NFR-MEM). The disc layer's
   control path (an inbound ACKNACK, ~1 per sample) calls this instead of constructing a fresh GUID per
   datagram purely to index the proxy table.

   SAFE BY CONSTRUCTION, not by audit — the property the owner chose this design for:
   1. A cache entry is WRITTEN ONCE, as a whole array, and NEVER MUTATED afterwards. So nothing that is
      handed a cached GUID can observe it change underneath — including the proxy table, which may retain
      it (and copies it anyway, %retained-endpoint-key). Contrast a shared scratch buffer, whose safety
      depends on every present and future consumer copying before it retains (ADR 0062 §6).
   2. A hit is believed only after %guid-names-endpoint-p matches all 16 octets, so a wrong or partially
      published entry is REJECTED, not used.
   3. Therefore this needs NO lock even though several receiver threads may call it for one writer
      concurrently: slot reads/writes of whole arrays do not tear, and any interleaving loses at worst
      the memo (a MISS -> rebuild), never correctness. Two threads racing to fill a slot store
      EQUALP-identical arrays.

   Returns a GUID the caller may retain or hand on. Allocates only on a miss."
  (let ((cache (or (rtps-writer-key-cache writer)
                   (setf (rtps-writer-key-cache writer)
                         (make-array +key-cache-size+ :initial-element nil)))))
    (dotimes (i +key-cache-size+)
      (let ((g (svref cache i)))
        (when (and g (%guid-names-endpoint-p g src-prefix entity-id))
          (return-from writer-lookup-key g))))
    (let ((fresh (%build-endpoint-guid src-prefix entity-id)))
      ;; Replacement is indexed by the entity-id so a steady set of remote readers keeps stable slots;
      ;; a collision just overwrites, which costs a later miss and never a wrong answer.
      (setf (svref cache (mod entity-id +key-cache-size+)) fresh)
      fresh)))

(defun* get-reader-proxy (writer reader-id)
    (function (rtps-writer t) reader-proxy)
  "The ReaderProxy for the matched reader named by the opaque per-endpoint key READER-ID, created on
   first use. The key is treated only as an equalp hash key (the disc layer passes the remote reader's
   full 16-octet GUID; the value-level tests pass an integer): a SequenceNumber is unique only within
   one writer GUID (RTPS 2.5 §8.3.5.4), so each remote reader's watermarks are kept independent.

   READER-ID IS NOT RETAINED ON A LOOKUP, AND IS COPIED WHEN IT IS (%retained-endpoint-key, ADR 0088):
   the stored key is a private copy, so a caller MAY pass a reused/cached buffer. This is the contract
   the GUID cache in %writer-lookup-key relies on."
  (or (gethash reader-id (rtps-writer-proxies writer))
      (setf (gethash (%retained-endpoint-key reader-id) (rtps-writer-proxies writer))
            (make-reader-proxy))))

(defun* writer-unmatch-reader (writer reader-id)
    (function (rtps-writer t) boolean)
  "Drop the ReaderProxy for the remote reader named by READER-ID — the writer-side UNMATCH (RTPS 2.5
   §8.4.7.1: a Writer removes the ReaderProxy of a Reader it is no longer matched with). Returns T iff a
   proxy was actually removed. Idempotent.

   THERE WAS NO REMOVAL PATH AT ALL (ADR 0063). RTPS-WRITER-PROXIES was create-on-first-use
   (GET-READER-PROXY) and read — never REMHASHed, on any trigger: not on unmatch, not on lease expiry, not
   on participant delete. Two consequences:

   1. AN UNBOUNDED LEAK. Every remote reader a writer ever matched stayed in the table forever. A peer that
      reconnects N times leaves N proxies (a fresh GUID each time), and nothing ever reclaims them.

   2. A STALE WATERMARK. WRITER-PURGE-ACKED purges below min(acked-base) over the readers it is GIVEN. A
      departed reader's proxy is a watermark frozen at the moment it left, so if it is ever consulted again
      the KEEP_ALL history cannot purge past it. (The purge is driven from the DISC match set, so the
      prompt-dispose prune already keeps the departed reader OUT of that set — which is what actually fixed
      the ADR 0063 stall. This closes the leak the same prune should have closed in the engine.)

   Called from the disc layer's single unmatch choke point (%fire-unmatch), so it runs on EVERY departure
   trigger — graceful dispose AND lease expiry AND an endpoint-level unmatch — and cannot drift from them."
  (%with-writer-lock (writer)
    (remhash reader-id (rtps-writer-proxies writer))))

(defun* writer-write (writer payload &optional (key-hash nil) (inline-qos nil)
                                               (pooled-buffer nil) (pooled-len nil)
                                               (zc-slot nil) (zc-gen 0)
                                               (zc-pinned nil) (zc-len nil))
    (function (rtps-writer (or null (array (unsigned-byte 8) (*)))
               &optional (or null (array (unsigned-byte 8) (*)))
                         (or null (simple-array (unsigned-byte 8) (*)))
                         (or null dds.core.buffer:octet-buffer)
                         (or null (integer 0))
                         (or null (integer 0))
                         (unsigned-byte 32)
                         t
                         (or null (integer 0)))
              (values (or integer (eql :timeout)) (or null dds.rtps.history:cache-change)))
  "Add a new :data change to the writer's HistoryCache; return its sequence number, OR the :timeout sentinel
   (RETCODE_TIMEOUT) if a FULL KEEP_ALL cache (RESOURCE_LIMITS max_samples) did not free a slot within the
   writer's max_blocking_time (RELIABILITY.max_blocking_time) — DDS-standard block-up-to-max_blocking_time
   backpressure (WP-ASYNC-FLOW, FR-PF-2/FR-QOS, ADR 0016 §Backpressure; see %writer-add-bounded). For a
   writer with no finite max_samples (the default, KEEP_ALL/unlimited or KEEP_LAST) this NEVER blocks and
   NEVER returns :timeout — byte-identical to the prior behaviour. On :timeout the cache is left intact and
   NO sequence number is consumed (the reliable SN stream stays hole-free). KEY-HASH (WP-KEEPLAST, ADR 0019,
   DDS 1.4 §2.2.3.18) is the sample's 16-octet instance handle recorded on the change for per-instance
   KEEP_LAST eviction; NIL (the default) keeps the change's instance-key-hash unset — byte-identical to before.
   INLINE-QOS (WP-DURABILITY-DEDUP, RTPS 2.5 §9.4.5.4 / §9.4.2.11): a complete PID_SENTINEL-terminated
   ParameterList octet vector stored on the change's inline-qos slot; the small-DATA emit path (dataplane.lisp
   %data-builder) passes it to write-data :inline-qos; the DATA_FRAG path (%sample-plan) does NOT carry
   inline-QoS (RTPS 2.5 §9.4.5.5 makes it optional; relay samples are always small, never fragment).
   NIL (the default) → no Q-bit, no extra bytes — byte-identical to the prior behaviour.
   POOLED-BUFFER / POOLED-LEN (WP-DDS-SECURITY-ZEROALLOC-AEAD T5a; default NIL = not pooled, byte-identical):
   when set, PAYLOAD is the oversized fixed VEC of POOLED-BUFFER (a payload-pool buffer encoded in place by the
   data_protection publish path) and POOLED-LEN is its true secured-payload length — recorded on the change so
   the eviction/ref-drop pool-release gate (hc-try-release-pooled) can return the buffer and every send-path
   length read (cache-change-payload-len) uses the true length, not the oversized capacity. On a :timeout the
   change is NOT added, so the CALLER (publish-sample) returns the acquired buffer to the pool directly.
   ZC-SLOT / ZC-GEN (WP-FLATDATA-LOAN-WRITE, FR-PF-4, R6, ADR 0042; default NIL = no slot, byte-identical): a
   non-NIL ZC-SLOT arms the change with the PRE-COMMITTED Zero-Copy pool slot loan-write already wrote the
   sample into (refcount=1 held) — the change is BORN :armed under the writer lock, so a concurrent capture can
   never observe a half-armed change; the send site (%zc-change-item) may then emit the slot's 20-octet ref ONCE
   (writer-zc-claim) instead of loaning a fresh slot from PAYLOAD. Returns (values SN-or-:timeout CHANGE) — the
   CHANGE second value (NIL on :timeout) lets the caller register an armed change for the leak-safety sweep.
   ZC-PINNED / ZC-LEN (WP-ACKED-SLOT-PINNING, FR-PF-4, R6, ADR 0044; default NIL = byte-identical): when ZC-PINNED
   the change is born with the TX PIN hold engaged and NO retained SERIALIZED-PAYLOAD (PAYLOAD is NIL) — the
   committed slot stays live until the full-ACK purge, and retransmit / non-ZC / extra-ZC sends read it on demand;
   ZC-LEN records the true serialized length so the send-path length reads work without a retained payload. The
   pin hold is released (once) by hc-try-release-pinned at the change-removal choke (ADR 0044 §4)."
  ;; NFR-MEM: an flet declared DYNAMIC-EXTENT, not a lambda (ADR 0072). %writer-add-bounded funcalls
  ;; MAKE-CHANGE once, under the writer lock, and stores it nowhere — a pure downward funarg — so this
  ;; stack-allocates. As a heap lambda it captured ELEVEN variables (~104 B/write), and the CHANGE it
  ;; smuggled out was a closed-over MUTABLE variable, which costs a heap value cell of its own on SBCL.
  ;; %writer-add-bounded now RETURNS the change, so the mutable capture is gone rather than made cheaper.
  (flet ((%make-data-change (sn)
           (dds.rtps.history:hc-data-change   ; TASK-3 (ADR 0077): draw+fill from the writer's change-freelist (zero per-sample struct alloc once warm), else fresh
            (rtps-writer-hc writer) sn payload key-hash inline-qos
            pooled-buffer pooled-len zc-slot zc-gen zc-pinned zc-len)))
    (declare (dynamic-extent #'%make-data-change))
    (%writer-add-bounded writer #'%make-data-change)))

(defun* writer-zc-claim (writer change)
    (function (rtps-writer dds.rtps.history:cache-change) boolean)
  "WP-FLATDATA-LOAN-WRITE (FR-PF-4, R6, ADR 0042; NOT cleared for ship — pending counsel). ONE-SHOT claim of
   CHANGE's pre-committed Zero-Copy slot for ref emission: under WRITER's lock, :armed -> :consumed and T; any
   other state (NIL / already consumed / released) -> NIL with no transition. The lock serializes the claim
   against a concurrent emit on another thread (initial push vs ACKNACK retransmit), so the slot's single
   refcount is spent on EXACTLY ONE emitted ref — a retransmit of a consumed change falls back to the retained
   payload, never double-emitting the slot."
  (%with-writer-lock (writer)
    (and (eq (dds.rtps.history:cache-change-zc-state change) :armed)
         (progn (setf (dds.rtps.history:cache-change-zc-state change) :consumed) t))))

(defun* writer-zc-unarm (writer change)
    (function (rtps-writer dds.rtps.history:cache-change) boolean)
  "WP-FLATDATA-LOAN-WRITE (FR-PF-4, R6, ADR 0042; NOT cleared for ship — pending counsel). ONE-SHOT disarm of
   CHANGE's pre-committed Zero-Copy slot: under WRITER's lock, :armed -> :released and T (the CALLER must then
   %zc-release the slot exactly once — refcount 1 -> 0, reclaimable); any other state -> NIL, no release owed.
   Fired by the send-site fallback decision (gate active / no ZC readers — the slot will never be emitted from
   this decision on) and by the push-pass / teardown leak sweeps (ADR 0042 lifecycle)."
  (%with-writer-lock (writer)
    (and (eq (dds.rtps.history:cache-change-zc-state change) :armed)
         (progn (setf (dds.rtps.history:cache-change-zc-state change) :released) t))))

(defun* writer-lifecycle-change (writer key-hash status-flags &optional (inline-qos nil) (source-timestamp 0))
    (function (rtps-writer (simple-array (unsigned-byte 8) (*)) (unsigned-byte 8)
               &optional (or null (simple-array (unsigned-byte 8) (*))) integer)
              (or integer (eql :timeout)))
  "Add a dispose/unregister change for the instance named by KEY-HASH (16 octets) to the
   writer's HistoryCache and return its sequence number (RTPS 2.5 §9.6.4.9), OR the :timeout sentinel
   (RETCODE_TIMEOUT) under the SAME block-up-to-max_blocking_time backpressure as writer-write — a
   lifecycle change occupies a real SN (RTPS 2.5 §8.4.2.2) so it counts toward the cache bound and is
   treated CONSISTENTLY with a DATA write (ADR 0016 §Backpressure; the bound applies to all changes).
   STATUS-FLAGS is the StatusInfo_t flag octet; the change KIND (:dispose/:unregister) is derived from it
   (status-info->kind). INLINE-QOS (optional, default NIL): a PID_SENTINEL-terminated ParameterList
   vector attached to the change (e.g. PID_ORIGINAL_WRITER_INFO for relay, RTPS 2.5 §9.4.5.4);
   NIL = no Q-bit, byte-identical to prior behaviour. The change carries NO serializedPayload —
   the instance is identified by its key hash — yet is reliably ordered and ACKNACK-repairable
   like any DATA. For a writer with no finite max_samples this never blocks and never returns
   :timeout (byte-identical to before)."
  ;; VALUES truncates %writer-add-bounded's second value (the change): a lifecycle change's SN is this
  ;; function's whole documented contract, and the caller never wants the change itself.
  (values
   (%writer-add-bounded
    writer (lambda (sn) (dds.rtps.history:hc-lifecycle-change   ; TASK-3 (ADR 0077): draw+fill from the writer's change-freelist, else fresh
                         (rtps-writer-hc writer) sn (dds.rtps.message:status-info->kind status-flags)
                         key-hash status-flags inline-qos source-timestamp)))))   ; S5.T4: INFO_TS on dispose/unregister_w_timestamp

(defun* writer-heartbeat (writer)
    (function (rtps-writer) (values integer integer integer))
  "Return (values firstSN lastSN count) for a HEARTBEAT (RTPS 2.5 §8.3.7.5)."
  (%with-writer-lock (writer)
    (values (or (dds.rtps.history:hc-min-seq (rtps-writer-hc writer)) 1)
            (or (dds.rtps.history:hc-max-seq (rtps-writer-hc writer)) 0)
            (incf (rtps-writer-hb-count writer)))))

(defun* %changes-from (writer base)
    (function (rtps-writer integer) list)
  "The writer's HistoryCache CacheChanges with SN >= BASE, in SN order. The element is the
   CacheChange itself (carrying KIND, SN, payload, key-hash, status-info) so the send path
   can dispatch :data vs :dispose/:unregister (RTPS 2.5 §8.4.2.2 / §9.6.4.9).

   WP-PERF: asks the cache for the RANGE directly (hc-changes-from) instead of taking the whole sorted change
   list and filtering it down to this suffix. The old form maphash'd + STABLE-SORTed the ENTIRE history cache
   on every write — over half the measured send path — to then discard the ACKed prefix."
  (dds.rtps.history:hc-changes-from (rtps-writer-hc writer) base))

(defun* writer-data-list (writer reader-id)
    (function (rtps-writer t) list)
  "Changes not yet acked by READER-ID (the opaque per-reader key), as a list of CacheChanges in SN order."
  (%with-writer-lock (writer)
    (%changes-from writer (reader-proxy-acked-base (get-reader-proxy writer reader-id)))))

(defun* %unsent-for-key (writer reader-id)
    (function (rtps-writer t) list)
  "INTERNAL (the CALLER must hold the writer LOCK): the UNSENT CacheChanges for READER-ID with SN >= the
   reader's UNSENT-BASE in SN order, advancing UNSENT-BASE past the highest collected so each change pushes
   EXACTLY ONCE (RTPS 2.5 §8.4.2.2). Shared lock-free core of writer-unsent-list and writer-capture-unsent
   (DRY) — kept private because it mutates the proxy watermark, which is only correct under the held lock."
  (let* ((proxy (get-reader-proxy writer reader-id))
         (changes (%changes-from writer (reader-proxy-unsent-base proxy))))
    (when changes
      (setf (reader-proxy-unsent-base proxy)
            (1+ (dds.rtps.history:cache-change-sn (first (last changes))))))
    changes))

(defun* writer-unsent-list (writer reader-id)
    (function (rtps-writer t) list)
  "The UNSENT changes for READER-ID (the opaque per-reader key; next_unsent_change, RTPS 2.5 §8.4.2.2): the
   CacheChanges with SN >= the reader's UNSENT-BASE, in SN order. On a non-empty result the
   UNSENT-BASE watermark is advanced past the highest SN collected, so each change is pushed
   EXACTLY ONCE in pushMode (§8.4.2.2). Lost/late changes are recovered via the ACKNACK repair
   path (writer-on-acknack), not by re-pushing. Each element is the CacheChange (KIND/SN/
   payload/key-hash/status-info) so a :dispose/:unregister is pushed as a no-payload DATA. Does NOT
   acquire a send-ref (the inspection/value-level API); the send path uses writer-capture-unsent."
  (%with-writer-lock (writer)
    (%unsent-for-key writer reader-id)))

(defun* writer-capture-unsent (writer reader-ids)
    (function (rtps-writer list) list)
  "The send-path UNSENT capture: under ONE writer-LOCK acquisition, the SN-deduplicated union of the UNSENT
   changes to push to the readers READER-IDS (the opaque per-reader keys of one destination), in SN order,
   advancing EACH reader's UNSENT-BASE (so a sample co-located readers share is pushed once yet send-once
   accounted per reader, RTPS 2.5 §8.4.2.2 / §8.3.5.4) — AND, atomically with that read, ACQUIRING a send-ref
   on each returned change (incrementing SEND-REFCOUNT, the operating contract §4 release-safety). Acquiring
   UNDER THE SAME LOCK as the unsent read closes the recycle race: a concurrent eviction (KEEP_LAST
   supersession on a co-publishing thread, or the ACKNACK purge on the receiver thread) takes the same lock
   and sees SEND-REFCOUNT > 0, so it cannot return a captured payload's pooled buffer before the send copies
   it (T5a). The CALLER MUST release each returned change exactly once (writer-release-change-refs) AFTER the
   datagram(s) carrying it have been emitted (copied) — synchronously after the emit loop (initial/ACKNACK
   push) or on plan drain (the paced/async deferred path). For one reader-id this is writer-unsent-list +
   one acquire (the common single-reader destination); the dedup makes the multi-reader union idempotent.
   SINGLE-READER FAST PATH: a one-reader destination skips the merge/sort/O(M²)-dedup entirely — %unsent-for-key
   already returns the changes in ascending SN order with no duplicates, so it is returned directly after one
   acquire per change (O(M)); only a multi-reader destination pays the union dedup + sort. Load-bearing once the
   payload is pooled; behaviorally neutral today (the GC pins the payload)."
  (%with-writer-lock (writer)
    (if (and reader-ids (null (cdr reader-ids)))
        (let ((changes (%unsent-for-key writer (car reader-ids))))   ; single reader: already SN-ascending, no dups
          (dolist (ch changes) (incf (dds.rtps.history:cache-change-send-refcount ch)))   ; acquire each, atomic with the read
          changes)
        (let ((merged '()))
          (dolist (k reader-ids)
            (dolist (ch (%unsent-for-key writer k))
              (unless (member (dds.rtps.history:cache-change-sn ch) merged
                              :key #'dds.rtps.history:cache-change-sn :test #'=)
                (push ch merged))))
          (dolist (ch merged) (incf (dds.rtps.history:cache-change-send-refcount ch)))   ; acquire each unique change ONCE, atomic with the read
          (sort merged #'< :key #'dds.rtps.history:cache-change-sn)))))

(defun* writer-acquire-sample (writer sn)
    (function (rtps-writer integer) (or null dds.rtps.history:cache-change))
  "Capture the writer's CacheChange at SN for a (cross-thread) RETRANSMIT send: under the writer LOCK, look it
   up and — if present — ACQUIRE a send-ref (increment SEND-REFCOUNT) atomically with the lookup, returning the
   change; NIL if SN is no longer in the HistoryCache (evicted/purged). The atomic lookup+acquire closes the
   recycle race for the NACK_FRAG retransmit path (%on-user-nack-frag, the receiver thread) exactly as
   writer-capture-unsent does for the push path: a concurrent KEEP_LAST supersession or ACKNACK purge sees
   SEND-REFCOUNT > 0 and cannot recycle SN's pooled payload while the retransmit thunks still copy it (T5a).
   The CALLER MUST writer-release-change-ref the returned change after the retransmit datagrams are emitted.
   Behaviorally neutral today (the GC pins the payload); load-bearing once the payload is pooled."
  (%with-writer-lock (writer)
    (let ((ch (dds.rtps.history:hc-get-change (rtps-writer-hc writer) sn)))
      (when ch
        (incf (dds.rtps.history:cache-change-send-refcount ch))
        ch))))

(defun* writer-release-change-ref (writer change)
    (function (rtps-writer dds.rtps.history:cache-change) (integer 0))
  "Release ONE send-ref on CHANGE (decrement SEND-REFCOUNT, FLOORED at 0) under the writer LOCK; return the new
   count. The release half of writer-acquire-sample / writer-capture-unsent (the operating contract §4
   release-safety): call AFTER the send that copied CHANGE's payload into its datagram(s) has completed. The
   floor makes a double-release a validated no-op (never an underflow), mirroring the ZC loan-return idempotency.
   Under the SAME lock as acquire + the eviction's CACHE-CHANGE-RELEASABLE-P check, so the 1->0 edge is the
   point a pooled buffer becomes eligible for pool-release: on reaching 0 this calls hc-try-release-pooled, which
   returns the buffer to the pool IFF the change was ALREADY evicted (the deferred-release half of the operating
   contract §4; inert for a non-pooled or still-live change — byte-identical, T5a)."
  (%with-writer-lock (writer)
    (let ((rc (dds.rtps.history:cache-change-send-refcount change)))
      (setf (dds.rtps.history:cache-change-send-refcount change) (if (plusp rc) (1- rc) 0))
      (dds.rtps.history:hc-try-release-pooled (rtps-writer-hc writer) change)   ; deferred pool-release on the last ref drop of an evicted pooled change (T5a)
      (dds.rtps.history:hc-try-release-pinned (rtps-writer-hc writer) change)   ; deferred pin-release on the last ref drop of an evicted pinned change (ADR 0044 I1)
      (dds.rtps.history:hc-try-recycle-change (rtps-writer-hc writer) change)   ; TASK-3 (ADR 0077): deferred struct-recycle on the last ref drop of an evicted change
      (dds.rtps.history:cache-change-send-refcount change))))

(defun* writer-release-change-refs (writer changes)
    (function (rtps-writer list) t)
  "Release one send-ref on EACH change in CHANGES (the list writer-capture-unsent returned) under ONE writer-LOCK
   acquisition — the release half of the push/retransmit capture (the operating contract §4 release-safety). Each
   decrement is floored at 0 (a double-release is a no-op). Call AFTER the captured changes' datagrams are emitted
   (the synchronous emit loop, or the paced/async plan drain). A NIL/empty list releases nothing (idempotent). On
   a change reaching refcount 0 this calls hc-try-release-pooled, returning its pooled buffer to the pool IFF it
   was ALREADY evicted (the deferred-release half of the operating contract §4; inert for non-pooled, T5a)."
  (%with-writer-lock (writer)
    (let ((hc (rtps-writer-hc writer)))
      (dolist (ch changes t)
        (let ((rc (dds.rtps.history:cache-change-send-refcount ch)))
          (setf (dds.rtps.history:cache-change-send-refcount ch) (if (plusp rc) (1- rc) 0)))
        (dds.rtps.history:hc-try-release-pooled hc ch)   ; deferred pool-release on the last ref drop of an evicted pooled change (T5a)
        (dds.rtps.history:hc-try-release-pinned hc ch)   ; deferred pin-release on the last ref drop of an evicted pinned change (ADR 0044 I1)
        (dds.rtps.history:hc-try-recycle-change hc ch)))))   ; TASK-3 (ADR 0077): deferred struct-recycle on the last ref drop of an evicted change

(defun* writer-acquire-payload-buffer (writer)
    (function (rtps-writer) t)
  "Acquire ONE secured-payload buffer from WRITER's HistoryCache PAYLOAD-POOL under the writer LOCK
   (WP-DDS-SECURITY-ZEROALLOC-AEAD T5a) — so the pool's free-list is mutated under the SAME lock that guards
   SEND-REFCOUNT + the eviction/ref-drop pool-release (hc-try-release-pooled), never torn by a concurrent
   release. Returns the octet-buffer, or NIL when the pool is EXHAUSTED (the caller, publish-sample, routes NIL
   to RESOURCE_LIMITS backpressure — NEVER a GC-heap fallback) OR when no pool is provisioned (security off /
   not a pooled writer — the caller then takes the allocating path; distinguish the two via
   history-cache-payload-pool). Does NOT create a change: the caller encodes into the buffer with
   encode-serialized-payload-into, then threads it onto the change via writer-write (releasing it on a :timeout
   with writer-release-payload-buffer). No allocation."
  (%with-writer-lock (writer)
    (let ((pool (dds.rtps.history:history-cache-payload-pool (rtps-writer-hc writer))))
      (when pool (dds.core.arena:pool-acquire pool)))))

(defun* writer-release-payload-buffer (writer buffer)
    (function (rtps-writer t) t)
  "Return BUFFER (a writer-acquire-payload-buffer result) DIRECTLY to WRITER's PAYLOAD-POOL under the writer
   LOCK — for the FAILURE paths where it was acquired but NEVER attached to a stored change: an oversize-payload
   reject, or a full-cache :timeout from writer-write (the change was not added). This keeps a rejected secured
   publish from leaking a pool slot. A NIL BUFFER or no pool is a no-op. NOT for a CHANGE-OWNED buffer — that is
   released only through the eviction/ref-drop gate (hc-try-release-pooled); the two paths are mutually exclusive
   (a buffer is either change-owned or returned here, never both), so there is no double-release
   (WP-DDS-SECURITY-ZEROALLOC-AEAD T5a). No allocation."
  (when buffer
    (%with-writer-lock (writer)
      (let ((pool (dds.rtps.history:history-cache-payload-pool (rtps-writer-hc writer))))
        (when pool (dds.core.arena:pool-release pool buffer)))))
  t)

(defun* writer-ensure-payload-pool (writer provision-fn)
    (function (rtps-writer function) t)
  "Install a secured-payload encode pool onto WRITER's HistoryCache UNDER THE WRITER LOCK iff none exists yet,
   carving it via PROVISION-FN — the thread-safe, idempotent lazy provisioning point for the LIVE DDS-Security
   handshake, where the crypto keys (and hence the need to pool the encode buffer) are installed AFTER
   enable-publisher, so the first secured publish must carve the pool (WP-DDS-SECURITY-ZEROALLOC-AEAD T5a).
   PROVISION-FN is a thunk of the HistoryCache returning a fresh dds.core.arena:buffer-pool (sized by the caller
   from the HC's HISTORY/RESOURCE_LIMITS), or NIL when no pool could be carved (e.g. the arena has no room).
   Returns the resulting pool, or NIL when none was carved — the caller then takes the allocating encode path
   (byte-identical + correct), never an error and never a GC-silent claim. The carve runs at most ONCE (a no-op
   once a pool exists), under the SAME lock that guards acquire/release/eviction, so a concurrent first publish
   provisions exactly once. Off the steady state (first publish only), so steady publish stays zero-alloc."
  (%with-writer-lock (writer)
    (let ((hc (rtps-writer-hc writer)))
      (or (dds.rtps.history:history-cache-payload-pool hc)
          (let ((pool (funcall provision-fn hc)))
            (when pool
              (setf (dds.rtps.history:history-cache-payload-pool hc) pool))
            pool)))))

(defun* writer-on-acknack (writer reader-id base numbits bitmap &optional (acquire-refs nil))
    (function (rtps-writer t integer (unsigned-byte 32) (simple-array (unsigned-byte 32) (*)) &optional t)
              (values list list))
  "Process an ACKNACK from READER-ID (the opaque per-reader key; RTPS 2.5 §8.3.7.1). Confirm SN < BASE, then
   for each NACKed SN (bit set in BITMAP) return a resend if present, else a GAP.
   Returns (values data-resends gap-sns), data-resends a list of CacheChanges (so the
   resend path dispatches :data vs :dispose/:unregister exactly as the initial push).
   ACQUIRE-REFS (default NIL = the prior behaviour, byte-identical — the value-level/test callers): when T,
   ACQUIRE a send-ref on each resend (increment SEND-REFCOUNT) ATOMICALLY under this same lock as it is read
   from the HistoryCache (the operating contract §4 release-safety) — so a concurrent eviction cannot recycle
   a resent payload's pooled buffer before the retransmit copies it (T5a). The send-path callers (%on-user-acknack,
   %pvms-on-acknack) pass T and MUST writer-release-change-refs the returned resends after emitting them; a
   caller that only inspects the resends (no deferred/cross-thread send) leaves it NIL. Behaviorally neutral
   today (the GC pins the payload)."
  (%with-writer-lock (writer)
    (let ((proxy (get-reader-proxy writer reader-id))
          (resends '())
          (gaps '()))
      (setf (reader-proxy-acked-base proxy) (max (reader-proxy-acked-base proxy) base))
      (dotimes (i numbits)
        (when (dds.rtps.message:seqnum-set-bit-p bitmap i)
          (let* ((sn (+ base i))
                 (ch (dds.rtps.history:hc-get-change (rtps-writer-hc writer) sn)))
            (if ch
                (progn (when acquire-refs (incf (dds.rtps.history:cache-change-send-refcount ch)))   ; acquire atomic with the read (release-safety)
                       (push ch resends))
                (push sn gaps)))))
      (values (nreverse resends) (nreverse gaps)))))

(defun* writer-purge-acked (writer reader-keys &optional (durability :volatile) (application-ack nil))
    (function (rtps-writer list &optional (member :volatile :transient-local :transient :persistent) t)
              (integer 0))
  "Drop from the writer's HistoryCache every change that EVERY matched reader has acknowledged — SN below
   the minimum acked-base over READER-KEYS' proxies (RTPS 2.5 §8.4.1: VOLATILE writer history is bounded
   by the slowest reader's ack), via hc-purge-below which routes each removal through the index-consistent
   single removal path (so a purge keeps the per-instance KEEP_LAST index in step, ADR 0019). Each key's
   proxy is created with acked-base 1 if absent, so a matched reader that has not yet ACKed holds the
   watermark at 1 and NOTHING is purged until it acks. A NACKed sample is not fully-acked (acked-base has
   not passed it), so it is never purged — reliable repair is unaffected and no GAP is needed. Returns the
   number of changes purged; a no-op (0) when READER-KEYS is empty (no matched reader -> keep everything,
   bounded only by RESOURCE_LIMITS). When changes ARE purged
   (the cache shrank), broadcast SPACE-CV so a writer-write/writer-lifecycle-change blocked on a full
   KEEP_ALL cache wakes — this is the ACKNACK purge half of the WP-ASYNC-FLOW space-available signal (ADR
   0016 §Backpressure); the signal is sent AFTER the writer LOCK is released (the non-recursive LOCK).

   DURABILITY (DDS 1.4 §2.2.3.4; default :VOLATILE = the prior behavior, byte-identical) gates the
   full-ACK purge: a :VOLATILE writer purges as above (history bounded by the slowest reader's ack); a
   :TRANSIENT-LOCAL writer does NOT full-ACK-purge — it RETAINS its acked history for late-joiners (a
   no-op 0), bounded instead by HISTORY (the per-instance KEEP_LAST eviction in hc-add-change still
   evicts, and a KEEP_ALL cache by RESOURCE_LIMITS), so it is HISTORY-bounded, not ACK-bounded, and
   retained for the writer's lifetime. :TRANSIENT/:PERSISTENT need a durability service (out of scope) —
   treated here like :TRANSIENT-LOCAL (retain), never silently purging more than the conformant default.

   The FINALIZED flag (durability-finalize, the OPT-IN extension ON TOP of the conformant default; set via
   writer-finalize-durability) OVERRIDES the retain for a non-VOLATILE writer: a FINALIZED writer purges
   exactly as :VOLATILE — the retained late-joiner history is RELEASED once all current readers ACK (the
   owner has declared no more late-joiners expected). So the purge runs iff there is a matched reader AND
   the writer is :VOLATILE OR FINALIZED; an un-finalized TRANSIENT_LOCAL writer still purges NOTHING.

   ADR 0089 moved the acked-watermark computation ABOVE that durability gate, so an un-finalized
   TRANSIENT_LOCAL writer now takes the writer lock (to read its readers' proxies) where it previously
   returned 0 without one. Its PURGE behaviour is unchanged; only the watermark is newly recorded, and it
   has to be — that writer retains everything, so it purges nothing from which its send-window occupancy
   could otherwise be derived, and reporting its stored history as 'unacknowledged' is exactly the defect
   ADR 0089 §4.3 fixes. With no matched readers the function still returns 0 without taking the lock."
  (if (null reader-keys)
      0
      (let ((purged (%with-writer-lock (writer)
                      (let* ((base (loop for k in reader-keys
                                         minimize (reader-proxy-acked-base (get-reader-proxy writer k))))
                             ;; ADR 0090 A3c: under an APPLICATION acknowledgment kind a change is purgeable
                             ;; only once BOTH watermarks have passed it. The MIN of the two is taken rather
                             ;; than the application one alone: they are independent by design (§7 Q1 — a
                             ;; sample can be protocol-acked and not yet app-acked, never the reverse), and
                             ;; min() is correct under either ordering, so nothing here depends on an
                             ;; invariant a remote peer could violate. NIL (the :PROTOCOL default and every
                             ;; pre-existing caller) leaves PURGE-BASE = BASE, byte-identical.
                             ;;
                             ;; ⚠️ IT IS A SEPARATE BINDING FROM BASE ON PURPOSE. ADR 0089's acked-watermark
                             ;; below is the PROTOCOL send window, and RELIABLE_WRITER_CACHE_CHANGED reports
                             ;; it; folding the application watermark into it would silently redefine that
                             ;; status to mean something else for exactly the writers that enabled app-ack.
                             ;; The application-level occupancy has its own accessor, writer-app-unacked-count.
                             (purge-base (if application-ack
                                             (loop for k in reader-keys
                                                   for p = (get-reader-proxy writer k)
                                                   minimize (min (reader-proxy-acked-base p)
                                                                 (reader-proxy-app-acked-base p)))
                                             base)))
                        ;; ADR 0089: record the watermark BEFORE the durability gate. It is what makes the
                        ;; unacked count and the replaced-unacked count true for a TRANSIENT_LOCAL writer,
                        ;; which retains its whole history and so purges nothing to derive them from.
                        (setf (rtps-writer-acked-watermark writer) base)
                        (if (and (not (eq durability :volatile)) (not (rtps-writer-finalized writer)))
                            0
                            (dds.rtps.history:hc-purge-below (rtps-writer-hc writer) purge-base))))))
        (when (plusp purged) (%writer-signal-space writer))   ; the cache shrank: wake any blocked writer-write
        purged)))

(defun* writer-on-app-ack (writer reader-key intervals)
    (function (rtps-writer t list) integer)
  "Apply an APP_ACK from the reader keyed by READER-KEY (ADR 0090 A3c): advance that ReaderProxy's
   APPLICATION watermark to just past the CONTIGUOUS acknowledged run starting at 1. INTERVALS is the
   decoded list of (FIRST-SN . LAST-SN) conses the message named. Returns the proxy's new APP-ACKED-BASE.

   ⚠️ ONLY THE CONTIGUOUS PREFIX ADVANCES THE WATERMARK, AND THAT IS THE SAFETY PROPERTY. An APP_ACK may
   name disjoint ranges — the reader's application is free to acknowledge out of order — but a watermark is
   by definition 'everything below this'. Taking the maximum named sequence number instead would declare
   every hole beneath it acknowledged, and the writer would then purge samples the application never
   processed: THE FALSE ACK ADR 0090 IS WRITTEN AROUND, manufactured by the writer rather than the reader.
   So a gap stops the advance, the samples above it stay retained, and a later APP_ACK naming the missing
   run closes it (the reader re-reports cumulatively, which is exactly what the capture shows RTI doing).

   MONOTONIC: the watermark never retreats, so a stale, duplicated or reordered APP_ACK cannot un-acknowledge
   anything. Lock-guarded — this runs on a receiver thread while the caller thread publishes."
  (%with-writer-lock (writer)
    (let ((proxy (get-reader-proxy writer reader-key)))
      (let ((base (reader-proxy-app-acked-base proxy)))
        ;; Sweep repeatedly: the intervals are not required to arrive sorted, so one pass could stop at a
        ;; gap a later interval fills. Bounded by the interval count (itself capped by the parser).
        (loop for advanced = nil
              do (dolist (iv intervals)
                   (when (and (<= (car iv) base) (>= (cdr iv) base))
                     (setf base (1+ (cdr iv)) advanced t)))
              while advanced)
        (setf (reader-proxy-app-acked-base proxy) (max base (reader-proxy-app-acked-base proxy)))))))

(defun* writer-app-unacked-count (writer reader-keys)
    (function (rtps-writer list) (integer 0))
  "The number of changes WRITER has written that are not yet APPLICATION-acknowledged by every matched
   reader in READER-KEYS — last-SN minus the minimum APP-ACKED-BASE, clamped at 0. The application-level
   twin of WRITER-UNACKED-COUNT, and it is the number that matters under an APPLICATION acknowledgment
   kind: the protocol count can be zero while the application has processed nothing. Returns 0 when no
   reader is matched (nothing is owed to nobody)."
  (if (null reader-keys)
      0
      (%with-writer-lock (writer)
        (let ((base (loop for k in reader-keys
                          minimize (reader-proxy-app-acked-base (get-reader-proxy writer k)))))
          (max 0 (- (rtps-writer-last-sn writer) base -1))))))

(defun* writer-app-laggard (writer reader-keys)
    (function (rtps-writer list) t)
  "The reader in READER-KEYS whose APPLICATION watermark is LOWEST — the one holding this writer's history
   back — as (values READER-KEY APP-ACKED-BASE), or (values NIL NIL) when READER-KEYS is empty.

   IT NAMES A READER BECAUSE A COUNT CANNOT BE ACTED ON. 'Seven samples are overdue' tells an operator
   there is a problem; 'reader G has acknowledged nothing since sequence number 3' tells them WHERE it is.
   Ties resolve to the FIRST key at the lowest base — arbitrary but stable, and with several equally-stuck
   readers any of them is a correct answer to 'who is holding this up'."
  (if (null reader-keys)
      (values nil nil)
      (%with-writer-lock (writer)
        (let ((best nil) (best-base nil))
          (dolist (k reader-keys (values best best-base))
            (let ((b (reader-proxy-app-acked-base (get-reader-proxy writer k))))
              (when (or (null best-base) (< b best-base))
                (setf best k best-base b))))))))

(defun* writer-unacked-count (writer)
    (function (rtps-writer) (integer 0))
  "The number of changes WRITER has written that are NOT YET acknowledged by every matched reader — the
   occupancy of its send window (ADR 0089), = last-SN - acked-watermark + 1, clamped at 0. O(1): both terms
   are maintained incrementally (the watermark by writer-purge-acked on every ACKNACK), so the vendor
   RELIABLE_WRITER_CACHE_CHANGED status costs no scan of the HistoryCache.

   NOT the same as HC-CHANGE-COUNT, which is every change the cache STORES. The two coincide only for a
   VOLATILE writer that has just purged; they diverge for a TRANSIENT_LOCAL writer (which RETAINS its acked
   history for late-joiners, so its stored count is the whole history and its unacked count may be zero) and
   whenever no reader has yet ACKed. Reporting the stored count as 'unacknowledged' would tell a
   TRANSIENT_LOCAL application it has unbounded backpressure while it in fact has none."
  (%with-writer-lock (writer)
    (max 0 (- (rtps-writer-last-sn writer) (rtps-writer-acked-watermark writer) -1))))

(defun* writer-finalize-durability (writer)
    (function (rtps-writer) (eql t))
  "Mark WRITER FINALIZED (DDS 1.4 §2.2.3.4; the OPT-IN extension ON TOP of the conformant default — the
   owner declares 'no more late-joiners expected'). A FINALIZED TRANSIENT_LOCAL writer reverts to the
   VOLATILE-style full-ACK purge: writer-purge-acked then RELEASES the retained late-joiner history once all
   current readers ACK (see writer-purge-acked's FINALIZED gate), and any sample published afterwards behaves
   VOLATILE (purged on full-ACK). MONOTONIC — set once, never cleared in v1 (a repeat call is idempotent).
   Default off ⇒ standard TRANSIENT_LOCAL (retain for the writer's lifetime). Lock-guarded (the receiver
   thread purges; this runs on the caller thread). The standard places per-writer TRANSIENT/PERSISTENT
   lifetime control in the durability SERVICE — out of scope for this WP (the follow-on service milestone)."
  (%with-writer-lock (writer)
    (setf (rtps-writer-finalized writer) t))
  t)

(defun* init-reader-proxy-base (writer reader-id base)
    (function (rtps-writer t integer) reader-proxy)
  "Initialize the UNSENT-BASE watermark of the ReaderProxy for the matched reader keyed by the opaque
   READER-ID (creating the proxy on first use), and return it — the durability-aware late-joiner proxy
   init (DDS 1.4 §2.2.3.4, RTPS 2.5 §8.4.2.2). The disc layer calls this once at match time: for a
   TRANSIENT_LOCAL writer matched by a TRANSIENT_LOCAL reader BASE = firstSN (hc-min-seq) so the existing
   push (writer-unsent-list) replays the ENTIRE retained history; otherwise BASE = lastSN+1 (future-only,
   the effective pre-WP behavior). Sets ONLY unsent-base (the push watermark); acked-base stays at its
   default 1 so the ACKNACK-driven repair watermark is untouched (RTPS 2.5 §8.4.2.2 keeps the two
   independent). The proxy is keyed by the reader's GUID (each remote reader's watermarks are independent,
   §8.3.5.4)."
  (%with-writer-lock (writer)
    (let ((proxy (get-reader-proxy writer reader-id)))
      (setf (reader-proxy-unsent-base proxy) base)
      proxy)))

;;; ---- Reader side (§8.4.10): one WriterProxy per matched writer ----

(defstruct* (frag-reassembly (:constructor %make-frag-reassembly))
  "Reader-side reassembly state for one in-progress fragmented sample (RTPS 2.5 §9.4.5.5): declared total SAMPLE-SIZE and FRAGMENT-SIZE, accumulating BUFFER, a RECEIVED bitmap (one bit per 1-based fragment), and the count received."
  (sample-size 0 :type (integer 0))
  (fragment-size 0 :type (integer 0))
  (total-fragments 0 :type (integer 0))
  (buffer (make-array 0 :element-type '(unsigned-byte 8)) :type (simple-array (unsigned-byte 8) (*)))
  (received (make-array 0 :element-type 'bit) :type (simple-array bit (*)))
  (received-count 0 :type (integer 0)))

(defstruct* (writer-proxy (:constructor make-writer-proxy))
  "Reader-side proxy for one matched writer (RTPS 2.5 §8.4.10). RECEIVED maps SN ->
   T (received) | :gap — a PRESENCE marker only (the engine checks presence for ACKNACK/complete/gap;
   the application is delivered from the wire, not from here), so no payload is retained. FIRST-SN/LAST-SN
   bound the available range from HEARTBEAT; entries below FIRST-SN are compacted away as the writer
   purges its acked history (reader-on-heartbeat). REASSEMBLY maps SN -> frag-reassembly for in-progress
   DATA_FRAG samples. SKIP-HISTORY (the durability gate, DDS 1.4 §2.2.3.4): when T, the FIRST HEARTBEAT
   advances FIRST-SN to lastSN+1 so the reader SKIPS the writer's advertised pre-match history (NACKing only
   future gaps); NIL (the default, byte-identical to before) requests the full advertised range. The disc
   layer sets the flag from durability (%reader-durability-init: T for a VOLATILE reader matched a retaining
   writer); the reliable engine here is policy-agnostic and just applies it. DURABILITY-APPLIED-P latches the
   one-shot application so a later HEARTBEAT never re-skips live samples."
  ;; ⚠️ EVERY TABLE ON THIS STRUCT IS GUARDED BY THE OWNING RTPS-READER'S LOCK (ADR 0085) and MUST NOT be
  ;; mutated off-lock. A node runs up to THREE receiver threads — unicast UDP, multicast UDP, SHMEM — that
  ;; all feed %handle-datagram, so two colliding PUTHASHes meeting an internal rehash would publish a
  ;; half-built vector that the collector then walks as a live object: heap corruption, not a lost entry.
  ;; The accessors are exported for single-threaded tests and read-only inspection, NOT for off-lock writes.
  (received (make-hash-table :test 'eql) :type hash-table)   ; SN -> T (received) | :gap (presence only)
  (first-sn 1 :type integer)
  (last-sn 0 :type integer)                ; available range from HEARTBEAT
  (skip-history nil :type boolean)         ; durability gate: VOLATILE skips pre-match history (DDS §2.2.3.4)
  (durability-applied-p nil :type boolean) ; latch: the skip is applied once, on the first HEARTBEAT
  (reassembly (make-hash-table :test 'eql) :type hash-table)   ; SN -> frag-reassembly; same reader-lock rule as RECEIVED
  (acknack-bitmap (make-array (ceiling dds.rtps.message:+seqnum-set-max-bits+ 32)
                              :element-type '(unsigned-byte 32) :initial-element 0)
                  :type (simple-array (unsigned-byte 32) (*)))) ; reusable ACKNACK NACK-bitmap scratch (256-bit cap = 8 words, RTPS 2.5 §9.4.2.6), opt-in via reader-acknack REUSE-BITMAP on the lock-free user path — single-mutator, same receiver-thread discipline as RECEIVED (NFR-MEM)

(defstruct* (dedup-origin (:constructor %make-dedup-origin))
  "Per-original-GUID dedup state: the contiguous low-watermark LO, plus a fixed CIRCULAR BIT WINDOW
   covering the out-of-order sequence numbers in (LO, LO+WINDOW]. RTPS 2.5 §8.3.5.4. NFR-MEM,
   NFR-SEC-POSTURE. Mutated from the receiver threads via reader-dedup-accept-p, under the READER LOCK
   (ADR 0085).

   WHY A BIT WINDOW AND NOT A HASH SET. The set of delivered-but-not-yet-contiguous SNs was an EQL hash
   table capped at *max-gap-range* entries, and the cap was enforced by shedding the highest entry —
   found with a full (loop for k being each hash-key of above maximize k) ON EVERY CALL once at cap. At
   the shipped cap of 65536 that is a 65536-key scan per sample, MEASURED AT ~146 us/call, and it is
   REMOTE-DRIVABLE: this path is entered for any sample carrying PID_ORIGINAL_WRITER_INFO, whose GUID and
   SN come off the wire, so a peer that streams SNs above the watermark saturates a receiver thread. The
   window replaces both the scan and the shed with O(1) bit operations and bounds the state at
   WINDOW bits (8 KB at 65536) instead of up to 65536 hash entries.

   INDEXING. Bit (mod SN WINDOW). The live window spans at most WINDOW consecutive SNs, so that mapping is
   injective across it; bits are cleared as LO advances through them, and an SN beyond LO+WINDOW is never
   recorded, so no stale bit can alias a later SN.

   BITS IS ALLOCATED LAZILY and IN-ORDER TRAFFIC NEVER ALLOCATES IT: SN = LO+1 just advances LO. MARKED is
   the number of set bits, which lets the watermark advance stop immediately when nothing is pending.
   WINDOW is frozen per origin at creation, so rebinding *max-gap-range* mid-stream cannot reindex a live
   window (the tests bind it; production does not)."
  (lo 0 :type integer)
  (window 0 :type fixnum)
  (bits nil :type (or null (simple-array bit (*))))
  (marked 0 :type fixnum))

(defstruct* (rtps-reader (:constructor make-rtps-reader))
  "Stateful reliable RTPS reader (RTPS 2.5 §8.4.10): an opaque-writer-key -> WriterProxy table
   plus an original-GUID dedup map for relay-forwarded samples (§8.3.5.4)."
  ;; THE READER LOCK (ADR 0085). The "single receiver thread per proxy" discipline the reader-side
  ;; docstrings used to assume DOES NOT HOLD: a node runs up to THREE receiver threads (unicast UDP,
  ;; multicast UDP, SHMEM) that all feed %handle-datagram and land here. Every reader entry point below
  ;; takes this lock, which buys both properties that were missing:
  ;;   - MEMORY safety. These are plain hash tables; two colliding PUTHASHes meeting an internal rehash
  ;;     publish a half-built vector that the collector then walks as a live object (heap corruption).
  ;;   - ATOMICITY of the compound read-modify-writes, which a merely thread-safe table cannot give:
  ;;     (or (gethash k) (setf (gethash k) ...)) in get-writer-proxy, the seen-then-mark in
  ;;     reader-dedup-accept-p, the (when (> sn last-sn) (setf last-sn sn)) in reader-on-data. Interleaved,
  ;;     those lose a proxy (its received-SN markers vanish -> spurious NACKs), lose a dedup-origin, or
  ;;     accept the same (GUID,SN) twice -> DOUBLE DELIVERY, breaking exactly-once (RTPS 2.5 §8.3.5.4).
  ;; Per-impl synchronized tables were measured as an alternative for the first property and REJECTED: with
  ;; every entry point already locked they add a redundant inner lock per operation and cost 4x more
  ;; (+150 ns/sample vs +31 ns/sample; bench/report/2026-07-24-reliable-reader-lock.md).
  ;; The lock is a LEAF: this layer (L4) cannot call back into the disc layer, so it can never nest inside
  ;; another of our locks and has no ordering hazard. Entry points take it; the %-prefixed cores assume it.
  (lock (dds.pal:make-lock "rtps-reader") :type t)
  (proxies  (make-hash-table :test 'equalp) :type hash-table)   ; writer key (opaque, equalp) -> writer-proxy
  (dedup-map (make-hash-table :test 'equalp) :type hash-table)  ; original-GUID[16] -> dedup-origin, capped at *max-dedup-origins*
  (dedup-origins-refused 0 :type (integer 0)))                  ; NFR-SEC-POSTURE: new origins refused at the cap (accepted untracked, never dropped)

(defun* writer-proxy-armed-p (reader writer-id)
    (function (rtps-reader t) boolean)
  "T iff a WriterProxy for WRITER-ID already EXISTS on READER — i.e. the reader-side durability baseline for
   that writer has been ARMED (init-writer-proxy-durability creates the proxy at match time, before the first
   HEARTBEAT). Does NOT create one, so it is a pure test. Lets the disc layer detect the ADR 0043 residual
   window — a HEARTBEAT for a writer that is already MATCHED but whose baseline is not yet armed — instead of
   silently lazily-creating a proxy with skip-history NIL and pulling a retaining writer's pre-match history
   into a VOLATILE reader (ADR 0059). Takes the reader lock (a receiver thread may be creating a proxy)."
  (dds.pal:with-lock ((rtps-reader-lock reader))
    (and (nth-value 1 (gethash writer-id (rtps-reader-proxies reader))) t)))

(defun* %get-writer-proxy (reader writer-id)
    (function (rtps-reader t) writer-proxy)
  "GET-WRITER-PROXY's body. CALLER HOLDS THE READER LOCK — which is what makes the get-or-create ATOMIC.
   Unlocked, two receiver threads racing the same new writer both miss, both construct, and both SETF: one
   proxy is silently dropped along with every received-SN marker recorded into it, so the reader NACKs
   samples it already holds (RTPS 2.5 §8.3.5.4).

   WRITER-ID IS NOT RETAINED ON A LOOKUP, AND IS COPIED WHEN IT IS — the reader-side twin of
   GET-READER-PROXY's contract (%retained-endpoint-key, ADR 0088); see there for why the copy is
   load-bearing rather than defensive."
  (or (gethash writer-id (rtps-reader-proxies reader))
      (setf (gethash (%retained-endpoint-key writer-id) (rtps-reader-proxies reader))
            (make-writer-proxy))))

(defun* get-writer-proxy (reader writer-id)
    (function (rtps-reader t) writer-proxy)
  "The WriterProxy for the matched writer named by the opaque per-endpoint key WRITER-ID, created on
   first use. The key is treated only as an equalp hash key (the disc layer passes the remote writer's
   full 16-octet GUID; the value-level tests pass an integer): a SequenceNumber is unique only within
   one writer GUID (RTPS 2.5 §8.3.5.4), so two writers sharing EntityId 0x102 on different participants
   get independent received-SN sets / HEARTBEAT ranges / ACKNACK / GAP / reassembly state.

   Takes the reader lock. The other reader entry points already hold it and call %GET-WRITER-PROXY."
  (dds.pal:with-lock ((rtps-reader-lock reader))
    (%get-writer-proxy reader writer-id)))

(defun* %dedup-advance (origin)
    (function (dedup-origin) (values))
  "Advance ORIGIN's contiguous watermark LO through every consecutive SN already marked in the window,
   clearing each bit as it is absorbed. CALLER HOLDS THE READER LOCK.

   Amortised O(1): a bit is cleared at most once per time it is set, and the loop stops the instant either
   nothing is pending (MARKED zero — the in-order case, where it does not even look at the window) or the
   next SN is not marked. Clearing on absorption is also what keeps the circular index safe: a bit for an
   SN at or below LO never survives to alias an SN one window higher."
  (let ((bits (dedup-origin-bits origin)))
    (when bits
      (let ((window (dedup-origin-window origin)))
        (loop while (plusp (dedup-origin-marked origin))
              for nxt = (1+ (dedup-origin-lo origin))
              for i = (mod nxt window)
              while (= 1 (sbit bits i))
              do (setf (sbit bits i) 0)
                 (decf (dedup-origin-marked origin))
                 (setf (dedup-origin-lo origin) nxt)))))
  (values))

(defun* reader-dedup-accept-p (reader original-guid original-sn)
    (function (rtps-reader (or null (simple-array (unsigned-byte 8) (16))) (or null integer)) boolean)
  "Original-GUID per-SN dedup gate for relay-forwarded samples (RTPS 2.5 §8.3.5.4).
   Returns T (accept + record) when ORIGINAL-GUID is nil (PID absent — normal non-relayed path,
   never consults the map) or (ORIGINAL-GUID, ORIGINAL-SN) not yet seen; returns NIL (duplicate,
   discard) when this exact (GUID, SN) pair was already delivered. Per-GUID contiguous-watermark
   design: LO is the highest SN advanced through contiguously (every SN <= LO is known-delivered), and
   a fixed CIRCULAR BIT WINDOW records the out-of-order SNs in (LO, LO+WINDOW] not yet compacted into
   LO (see DEDUP-ORIGIN). Every step is O(1): test a bit, set a bit, advance LO through the contiguous
   run it just completed. In-order traffic touches no window at all — LO simply advances, and the
   window is never even allocated (NFR-MEM).

   AN SN BEYOND LO+WINDOW IS ACCEPTED BUT NOT RECORDED. That is the bounded residual, and it is the same
   one the previous shed-the-highest cap had: if such an SN re-arrives it is a benign DUPLICATE. LO is
   never advanced past an un-arrived SN, so SILENT LOSS CANNOT OCCUR — which is the direction that
   matters, a false reject being the worst outcome here.
   INERT when ORIGINAL-GUID is nil.

   TAKES THE READER LOCK, and the whole seen-test-then-mark must be inside it: this is a check-then-act, so
   two receiver threads handed the SAME (GUID,SN) — which happens whenever a writer reaches us over two
   transports — can both find it unseen and both return T, delivering the sample TWICE and breaking the
   exactly-once guarantee this function exists to provide (§8.3.5.4)."
  (if (null original-guid)
      t                                                   ; no PID -> normal path, always accept
      (dds.pal:with-lock ((rtps-reader-lock reader))
       (let* ((outer (rtps-reader-dedup-map reader))
              (origin (or (gethash original-guid outer)
                          ;; NFR-SEC-POSTURE: the GUID is wire-supplied, so the origin count is capped.
                          ;; At the cap a NEW origin is refused and its sample is ACCEPTED UNTRACKED —
                          ;; a possible duplicate, never a silent drop (see *max-dedup-origins*).
                          (if (>= (hash-table-count outer) *max-dedup-origins*)
                              (progn (incf (rtps-reader-dedup-origins-refused reader))
                                     (return-from reader-dedup-accept-p t))
                              (let ((o (%make-dedup-origin :window *max-gap-range*)))   ; frozen per origin: a later rebind must not reindex a live window
                                (setf (gethash original-guid outer) o)
                                o))))
              (window (dedup-origin-window origin))
              (lo (dedup-origin-lo origin)))
         (cond
           ((<= original-sn lo) nil)                     ; below watermark: already delivered
           ((= original-sn (1+ lo))                      ; IN-ORDER: no window touched, none allocated
            (setf (dedup-origin-lo origin) original-sn)
            (%dedup-advance origin)
            t)
           ((> original-sn (+ lo window)) t)             ; beyond the window: accept, do NOT record (bounded residual = a benign duplicate on re-arrival, never loss)
           (t
            (let* ((bits (or (dedup-origin-bits origin)
                             (setf (dedup-origin-bits origin)
                                   (make-array window :element-type 'bit :initial-element 0))))
                   (i (mod original-sn window)))
              (cond
                ((= 1 (sbit bits i)) nil)                ; already delivered
                (t
                 (setf (sbit bits i) 1)
                 (incf (dedup-origin-marked origin))
                 (%dedup-advance origin)
                 t)))))))))

(defun* reader-dedup-origins-refused (reader)
    (function (rtps-reader) (integer 0))
  "How many NEW original-writer origins READER has refused to track because *max-dedup-origins* was
   already reached (NFR-SEC-POSTURE). A non-zero value means either a genuinely large relay fan-in — raise
   the cap — or a peer minting origin GUIDs; either way the samples were DELIVERED, only untracked, so the
   observable risk is a duplicate rather than loss. A snapshot to be read, never printed: the same
   reported-not-printed shape as the pool reject counters."
  (dds.pal:with-lock ((rtps-reader-lock reader))
    (rtps-reader-dedup-origins-refused reader)))

(defun* reader-on-data (reader writer-id sn payload)
    (function (rtps-reader t integer (array (unsigned-byte 8) (*))) t)
  "Accept a DATA. Idempotent (duplicate SN re-marks — dedup); tracks the highest SN seen. Records only a
   PRESENCE marker (T), not PAYLOAD — the application is delivered the sample from the wire, and the engine
   only needs SN presence for ACKNACK/complete/gap, so no per-sample payload is retained (the PAYLOAD
   argument is kept for the call contract but not stored).

   TAKES THE READER LOCK: the LAST-SN update is a read-compare-write that two receiver threads can
   interleave into a lost update (the highest SN seen goes backwards), and the get-or-create it rides on
   must be atomic (see %GET-WRITER-PROXY)."
  (declare (ignore payload))
  (dds.pal:with-lock ((rtps-reader-lock reader))
    (let ((proxy (%get-writer-proxy reader writer-id)))
      (setf (gethash sn (writer-proxy-received proxy)) t)
      (when (> sn (writer-proxy-last-sn proxy)) (setf (writer-proxy-last-sn proxy) sn))
      t)))

(defun* reader-on-heartbeat (reader writer-id first-sn last-sn)
    (function (rtps-reader t integer integer) t)
  "Update the available range [firstSN, lastSN] (RTPS 2.5 §8.3.7.5). firstSN is tracked MONOTONICALLY
   non-decreasing (a writer's firstSN only advances as it purges acked history, never decreases — a
   reordered stale HEARTBEAT must not lower it). When firstSN advances, COMPACT the received table: drop
   markers below it (the writer purged those fully-acked samples, and reader-acknack/complete-p iterate
   [firstSN, lastSN] so they are unreachable) — bounding received to the live window, not O(history).

   The durability gate (DDS 1.4 §2.2.3.4): on the FIRST HEARTBEAT from this writer, if the proxy is marked
   SKIP-HISTORY (set at match time by init-writer-proxy-durability — the disc layer marks it for a VOLATILE
   reader matched a retaining writer), advance firstSN to lastSN+1 so the reader SKIPS the writer's
   advertised pre-match history (it then NACKs only future gaps). The skip is LATCHED (durability-applied-p)
   so it applies exactly once — a later HEARTBEAT (the writer published new samples) never re-skips them.
   With SKIP-HISTORY NIL (the default) this is byte-identical to before: the reader keeps firstSN and
   requests the full advertised range. Takes the reader lock (the one-shot latch + the firstSN/lastSN
   advance + the RECEIVED compaction must be one atomic step against a concurrent receiver thread)."
  (dds.pal:with-lock ((rtps-reader-lock reader))
   (let* ((proxy (%get-writer-proxy reader writer-id))
         (skip-floor (if (and (writer-proxy-skip-history proxy)
                              (not (writer-proxy-durability-applied-p proxy)))
                         (1+ last-sn)                      ; VOLATILE: skip the pre-match history
                         (writer-proxy-first-sn proxy)))
         (new-first (max (writer-proxy-first-sn proxy) first-sn skip-floor)))
    (setf (writer-proxy-durability-applied-p proxy) t)    ; one-shot: never re-skip a later HEARTBEAT
    (setf (writer-proxy-last-sn proxy) (max (writer-proxy-last-sn proxy) last-sn))
    (when (> new-first (writer-proxy-first-sn proxy))
      (setf (writer-proxy-first-sn proxy) new-first)
      (let ((received (writer-proxy-received proxy)) (drop '()))
        (maphash (lambda (sn v) (declare (ignore v)) (when (< sn new-first) (push sn drop))) received)
        (dolist (sn drop) (remhash sn received))))
    t)))

(defun* init-writer-proxy-durability (reader writer-id skip-history)
    (function (rtps-reader t boolean) writer-proxy)
  "Record the reader-side durability decision for the matched writer keyed by the opaque WRITER-ID
   (creating the WriterProxy on first use), and return it — the reader-side history-request gate (DDS 1.4
   §2.2.3.4, RTPS 2.5 §8.4.2.2). The disc layer (%reader-durability-init) calls this once at match time,
   BEFORE the first HEARTBEAT: SKIP-HISTORY T (the disc gate marks it for a VOLATILE reader matched a
   retaining writer) makes the first HEARTBEAT skip the writer's advertised pre-match history
   (reader-on-heartbeat advances firstSN to lastSN+1, NACKing only future gaps); SKIP-HISTORY NIL leaves the
   default full-range request (byte-identical to before this WP). Resets the one-shot latch so a re-match
   re-arms the decision. The proxy is keyed by the writer's GUID (each matched writer's gate is independent,
   §8.3.5.4). Takes the reader lock."
  (dds.pal:with-lock ((rtps-reader-lock reader))
    (let ((proxy (%get-writer-proxy reader writer-id)))
      (setf (writer-proxy-skip-history proxy) skip-history)
      (setf (writer-proxy-durability-applied-p proxy) nil)   ; re-arm on (re)match
      proxy)))

(defun* reader-acknack (reader writer-id &optional reuse-bitmap)
    (function (rtps-reader t &optional t) (values integer (unsigned-byte 32) (simple-array (unsigned-byte 32) (*))))
  "Compute an ACKNACK (RTPS 2.5 §8.3.7.1): (values base numBits bitmap). BASE is
   the lowest unreceived SN in [first, last] (or last+1 if none); the bitmap NACKs
   the unreceived SNs in [base, last] (capped at 256). REUSE-BITMAP (default NIL):
   NIL allocates a fresh bitmap — the ONLY safe choice when the returned bitmap is
   serialized after any lock is released or a second same-proxy reader-acknack may
   interleave (the builtin/secure/test callers). NON-NIL returns the proxy's REUSED
   acknack-bitmap scratch (zero per-ACKNACK alloc, NFR-MEM) — sound ONLY when the
   caller serializes it synchronously before any concurrent same-proxy recall; the
   lock-free user HEARTBEAT path (%on-user-heartbeat) does exactly that under the
   single-receiver-thread-per-proxy discipline (the same that lets RECEIVED be a
   lock-free hash). write-sequence-number-set reads exactly ceil(numBits/32) words,
   so the reused scratch's tail is never serialized.

   TAKES THE READER LOCK. The single-receiver-thread-per-proxy discipline the paragraph above appeals to
   DOES NOT HOLD — a node runs up to three receiver threads — so the RECEIVED scan that builds BASE and the
   bitmap has to be atomic against a concurrent reader-on-data/on-gap or the ACKNACK reports a range that
   was never simultaneously true."
  (dds.pal:with-lock ((rtps-reader-lock reader))
   (let* ((proxy (%get-writer-proxy reader writer-id))
         (first (writer-proxy-first-sn proxy))
         (last (writer-proxy-last-sn proxy))
         (received (writer-proxy-received proxy))
         (base (loop for sn from first to last
                     unless (gethash sn received) return sn
                     finally (return (1+ last))))
         (numbits (max 0 (min 256 (- (1+ last) base))))
         (bitmap (if reuse-bitmap
                     (let ((s (writer-proxy-acknack-bitmap proxy)))
                       (fill s 0 :end (ceiling numbits 32))   ; zero only the M words this ACKNACK sets/serializes
                       s)
                     (make-array (max 1 (ceiling numbits 32))
                                 :element-type '(unsigned-byte 32) :initial-element 0))))
    (loop for sn from base below (+ base numbits)
          unless (gethash sn received)
            do (dds.rtps.message:seqnum-set-bit bitmap (- sn base)))
    (values base numbits bitmap))))

(defun* reader-on-gap (reader writer-id gap-start base numbits bitmap)
    (function (rtps-reader t integer integer (unsigned-byte 32) (simple-array (unsigned-byte 32) (*)))
              (integer 0))
  "Mark GAPped SNs as irrelevant so they do not block the ack (RTPS 2.5 §8.3.7.4):
   the range [gapStart, base-1] plus the SNs listed in the bitmap. The contiguous range is LOWER-clamped
   to the proxy's first-sn (marking below the live window is pointless) and its iteration is HARD-capped at
   *max-gap-range* SNs — gapStart/base are wire-controlled 64-bit values and last-sn is itself set from
   inbound HEARTBEATs, so NEITHER bounds the loop; the cap (independent of any wire value) is the
   resource-exhaustion guard against a 2^60-span CPU+memory DoS (NFR-SEC-POSTURE; RTPS 2.5 §8.3.7.4). A
   legitimately larger evicted run is recovered over subsequent GAP/HEARTBEAT rounds (firstSN compaction),
   so the cap is loss-free. The bitmap loop is already bounded (numBits<=256, <=256 inserts).

   Returns the count of NEWLY-lost samples (DDS 1.4 §2.2.4.1 SAMPLE_LOST): an SN that transitions from
   never-seen (no marker) to :gap is a sample the writer declared permanently gone that the reader never
   received (a KEEP_LAST overwrite / RESOURCE_LIMITS eviction, ADR 0019). An already-RECEIVED SN (marker T)
   is PRESERVED (never clobbered to :gap, never counted — it was delivered) and an already-:gap SN is not
   re-counted. Because this engine content-filters READER-SIDE (never emits writer-side filter GAPs), every
   inbound GAP is a genuine purge/eviction, so the count is exact; the lower-clamp to first-sn keeps a
   durability-skipped pre-match range (which is intentionally not-wanted, not lost) out of the tally. The
   disc layer (%on-user-gap) fires SAMPLE_LOST with this count via the on-sample-lost hook.
   Takes the reader lock: the read-then-mark in %MARK-GAP is a check-then-act, so a concurrent
   reader-on-data could otherwise have its T marker clobbered to :gap and the loss double-counted."
  (dds.pal:with-lock ((rtps-reader-lock reader))
   (let* ((proxy (%get-writer-proxy reader writer-id))
         (received (writer-proxy-received proxy))
         (lo (max gap-start (writer-proxy-first-sn proxy)))         ; don't mark below the proxy window
         (hi (min base (+ lo *max-gap-range*)))                     ; HARD cap — independent of wire last-sn
         (lost 0))
    (flet ((%mark-gap (sn)                                          ; :gap unless already RECEIVED; count a fresh loss
             (let ((cur (gethash sn received)))
               (unless (eq cur t)
                 (unless (eq cur :gap) (incf lost))
                 (setf (gethash sn received) :gap)))))
      (loop for sn from lo below hi do (%mark-gap sn))
      (dotimes (i numbits)                                          ; bitmap is already bounded (numBits<=256)
        (when (dds.rtps.message:seqnum-set-bit-p bitmap i)
          (%mark-gap (+ base i)))))
    lost)))

(defun* reader-suppress-sn (reader writer-id sn)
    (function (rtps-reader t integer) t)
  "Mark exactly one SN from WRITER-ID as locally IRRELEVANT — a GAP-equivalent presence marker (:gap, RTPS 2.5
   §8.3.7.4) — so reader-acknack no longer NACKs it and reader-complete-p counts it, WITHOUT delivering it.
   The secured receive path calls this ONLY after a bounded run of KM-PRESENT decode failures of a sample that
   can never become decodable (persistent AES-GCM tag failure / key mismatch): the reader locally decides the
   sample is unrepairable and stops the reliable writer's otherwise-UNBOUNDED retransmission of it (ADR 0031
   limitation 1). It NEVER runs while the key material is still absent (the key-exchange race must keep
   self-healing). Marks the ONE named SN and does NOT touch last-sn, so a genuinely-missing LOWER SN still NACKs
   (no head-of-line suppression) and a forged high SN cannot inflate the ACKNACK range. Receiver-thread-only, the
   same locking discipline as reader-on-data (the reader lock). Idempotent (a re-mark is a no-op)."
  (dds.pal:with-lock ((rtps-reader-lock reader))
    (let ((proxy (%get-writer-proxy reader writer-id)))
      (setf (gethash sn (writer-proxy-received proxy)) :gap)
      t)))

(defun* reader-complete-p (reader writer-id)
    (function (rtps-reader t) t)
  "T iff every SN in the available range [first, last] has been received or GAPped. Takes the reader lock
   so the range and the scan over it are one consistent snapshot."
  (dds.pal:with-lock ((rtps-reader-lock reader))
    (let* ((proxy (%get-writer-proxy reader writer-id))
           (received (writer-proxy-received proxy)))
      (loop for sn from (writer-proxy-first-sn proxy) to (writer-proxy-last-sn proxy)
            always (gethash sn received)))))

(defun* reader-on-data-frag (reader writer-id sn fragment-starting-num fragments-in-submsg
                                    fragment-size sample-size payload)
    (function (rtps-reader t integer (unsigned-byte 32) (unsigned-byte 32)
               (unsigned-byte 32) (unsigned-byte 32) (array (unsigned-byte 8) (*)))
              (or null (simple-array (unsigned-byte 8) (*))))
  "Accept one DATA_FRAG submessage's fragment range for (WRITER-ID, SN). Reassembles into the
   per-(writer,sn) frag-reassembly; returns the complete SAMPLE-SIZE octet vector once all
   fragments have arrived, else NIL. Guards (NFR-SEC-POSTURE): rejects (NIL) a zero/over-limit
   SAMPLE-SIZE (> *max-reassembly-bytes*), a fragment count over *max-reassembly-fragments*, a
   zero FRAGMENT-SIZE, or a fragment range exceeding the sample; a sample whose declared
   fragment/sample size changes mid-stream is dropped. Duplicate fragments are idempotent.
   RTPS 2.5 §8.3.8.3 / §9.4.5.5."
  (when (or (zerop fragment-size) (zerop sample-size) (> sample-size *max-reassembly-bytes*))
    (return-from reader-on-data-frag nil))
  (let ((total (ceiling sample-size fragment-size)))
    (when (> total *max-reassembly-fragments*) (return-from reader-on-data-frag nil))
    (when (or (< fragment-starting-num 1) (zerop fragments-in-submsg)
              (> (+ fragment-starting-num fragments-in-submsg -1) total))
      (return-from reader-on-data-frag nil))
    (dds.pal:with-lock ((rtps-reader-lock reader))   ; the get-or-create of ENTRY and the fragment-count update are check-then-act; two receiver threads would build two reassembly buffers and lose fragments into the dropped one
     (let* ((proxy (%get-writer-proxy reader writer-id))
           (table (writer-proxy-reassembly proxy))
           (entry (or (gethash sn table)
                      (setf (gethash sn table)
                            (%make-frag-reassembly
                             :sample-size sample-size :fragment-size fragment-size
                             :total-fragments total
                             :buffer (make-array sample-size :element-type '(unsigned-byte 8))
                             :received (make-array total :element-type 'bit :initial-element 0))))))
      (when (or (/= (frag-reassembly-sample-size entry) sample-size)
                (/= (frag-reassembly-fragment-size entry) fragment-size))
        (remhash sn table)
        (return-from reader-on-data-frag nil))
      (let ((buf (frag-reassembly-buffer entry))
            (rcv (frag-reassembly-received entry)))
        (dotimes (k fragments-in-submsg)
          (let* ((fnum (+ fragment-starting-num k))
                 (dst (* (1- fnum) fragment-size))
                 (this (min fragment-size (- sample-size dst)))
                 (src (* k fragment-size)))
            (when (<= (+ src this) (length payload))
              (replace buf payload :start1 dst :end1 (+ dst this) :start2 src :end2 (+ src this))
              (when (zerop (sbit rcv (1- fnum)))
                (setf (sbit rcv (1- fnum)) 1)
                (incf (frag-reassembly-received-count entry))))))
        (when (= (frag-reassembly-received-count entry) total)
          (remhash sn table)
          buf))))))

(defun* reader-frag-acknack (reader writer-id sn)
    (function (rtps-reader t integer) t)
  "Compute a NACK_FRAG fragment set for the in-progress reassembly of (WRITER-ID, SN):
   (values base numBits bitmap) naming the 1-based fragment numbers NOT yet received, or
   NIL if there is no such reassembly (unknown or already complete). The window
   [base, base+numBits) is capped at 256 fragments per NACK_FRAG (§9.4.2.8). RTPS 2.5 §8.3.7.2.
   Takes the reader lock so the RECEIVED bitset is a consistent snapshot against a concurrent
   reader-on-data-frag (otherwise the NACK can name fragments that arrived while it was being built)."
  (dds.pal:with-lock ((rtps-reader-lock reader))
   (let* ((proxy (%get-writer-proxy reader writer-id))
         (entry (gethash sn (writer-proxy-reassembly proxy))))
    (when (null entry) (return-from reader-frag-acknack nil))
    (let* ((rcv (frag-reassembly-received entry))
           (total (frag-reassembly-total-fragments entry))
           (first-missing (loop for f from 1 to total
                                when (zerop (sbit rcv (1- f))) return f)))
      (when (null first-missing) (return-from reader-frag-acknack nil))
      (let* ((base first-missing)
             (last-missing (loop for f from total downto base
                                 when (zerop (sbit rcv (1- f))) return f))
             (numbits (min 256 (1+ (- last-missing base))))
             (words (ceiling numbits 32))
             (bitmap (make-array (max 1 words) :element-type '(unsigned-byte 32) :initial-element 0)))
        (loop for f from base below (+ base numbits)
              when (zerop (sbit rcv (1- f)))
                do (dds.rtps.message:fragnum-set-bit bitmap (- f base)))
        (values base numbits bitmap))))))

;;; ---- Writer-side fragmentation planners (RTPS 2.5 §8.3.8.3) ----

(defun* writer-frag-heartbeat (writer sn)
    (function (rtps-writer integer) t)
  "Compute a HEARTBEAT_FRAG for the sample at SN: (values last-fragment-num count) where
   last-fragment-num is the sample's total fragment count at *fragment-size* and count is the
   writer's monotonically increasing HEARTBEAT_FRAG counter; NIL if SN is absent/empty.
   RTPS 2.5 §8.3.7.5 (fragment variant)."
  (%with-writer-lock (writer)
    (let ((ch (dds.rtps.history:hc-get-change (rtps-writer-hc writer) sn)))
      (when (null ch) (return-from writer-frag-heartbeat nil))
      (let ((payload (dds.rtps.history:cache-change-serialized-payload ch)))
        (when (null payload) (return-from writer-frag-heartbeat nil))
        (values (ceiling (dds.rtps.history:cache-change-payload-len ch) *fragment-size*)   ; TRUE length, not the oversized pooled vec (T5a)
                (incf (rtps-writer-frag-hb-count writer)))))))

(defun* writer-on-nack-frag (writer sn base numbits bitmap)
    (function (rtps-writer integer (unsigned-byte 32) (unsigned-byte 32) (simple-array (unsigned-byte 32) (*))) list)
  "Plan the DATA_FRAG resends for a NACK_FRAG naming missing fragments of the sample at SN:
   the writer-frag-plan-for descriptors over SN's payload, or NIL if SN is absent/empty.
   RTPS 2.5 §8.3.8.x."
  (%with-writer-lock (writer)
    (let ((ch (dds.rtps.history:hc-get-change (rtps-writer-hc writer) sn)))
      (when (null ch) (return-from writer-on-nack-frag nil))
      (let ((payload (dds.rtps.history:cache-change-serialized-payload ch)))
        (when (null payload) (return-from writer-on-nack-frag nil))
        (writer-frag-plan-for (dds.rtps.history:cache-change-payload-len ch)   ; TRUE length, not the oversized pooled vec (T5a)
                              *fragment-size* base numbits bitmap)))))

(defun* writer-sample-payload (writer sn)
    (function (rtps-writer integer) (or null (array (unsigned-byte 8) (*))))
  "The stored SerializedPayload octets for the writer's sample SN, or NIL if absent."
  (%with-writer-lock (writer)
    (let ((ch (dds.rtps.history:hc-get-change (rtps-writer-hc writer) sn)))
      (and ch (dds.rtps.history:cache-change-serialized-payload ch)))))

(defun* writer-frag-plan (sample-size fragment-size budget)
    (function ((unsigned-byte 32) (unsigned-byte 32) (integer 1)) list)
  "Plan the DATA_FRAG submessages for a SAMPLE-SIZE-octet sample at FRAGMENT-SIZE, packing as
   many whole fragments as fit BUDGET octets per submessage (>=1). Returns a list of
   (fragment-starting-num fragments-in-submsg payload-offset payload-length) in fragment order;
   the final fragment of the sample may be short. fragmentSize is constant across the sample
   (RTPS 2.5 §8.3.8.3)."
  (let ((total (ceiling sample-size fragment-size))
        (per (max 1 (floor budget fragment-size)))
        (out '()))
    (loop for fstart from 1 to total by per
          for fcount = (min per (1+ (- total fstart)))
          for off = (* (1- fstart) fragment-size)
          for len = (min (* fcount fragment-size) (- sample-size off))
          do (push (list fstart fcount off len) out))
    (nreverse out)))

(defun* writer-frag-plan-for (sample-size fragment-size base numbits bitmap)
    (function ((unsigned-byte 32) (unsigned-byte 32) (unsigned-byte 32) (unsigned-byte 32)
               (simple-array (unsigned-byte 32) (*))) list)
  "Plan DATA_FRAG submessages re-sending ONLY the fragments named in a NACK_FRAG
   FragmentNumberSet (BASE/NUMBITS/BITMAP); one fragment per submessage. Returns
   (fragment-starting-num fragments-in-submsg payload-offset payload-length) descriptors in
   fragment order; the final fragment may be short. RTPS 2.5 §8.3.8.3."
  (let ((total (ceiling sample-size fragment-size))
        (out '()))
    (loop for f from base below (+ base numbits)
          when (and (<= 1 f total) (dds.rtps.message:fragnum-set-member-p base numbits bitmap f))
            do (let* ((off (* (1- f) fragment-size))
                      (len (min fragment-size (- sample-size off))))
                 (push (list f 1 off len) out)))
    (nreverse out)))

;;; ---- APP-ACK reader-side state (RTI VENDOR EXTENSION, ADR 0090 slice A3b) ----
;;;
;;; THERE IS NO SPEC CLAUSE. Application acknowledgment appears nowhere in RTPS 2.5, so — exactly as for
;;; the codec in dds.rtps.message — the citations here are to the ADR 0090 CAPTURE of a live RTI Connext
;;; 7.3.1 exchange, not to a clause. The behaviour reproduced below is the one the capture shows: the
;;; reader sends a CUMULATIVE picture each time — the run of sequence numbers it has already reported,
;;; plus the newly acknowledged one as a SEPARATE interval — and a monotone COUNT that mirrors ACKNACK's.
;;;
;;; ⚠️ A FALSE ACK IS WORSE THAN NO ACK. For most of this stack a false REJECT is the worst outcome; here
;;; it is inverted, because a writer that believes a sample acknowledged may PURGE it and report success.
;;; Every operation below therefore resolves an ambiguous case to "not yet acknowledged": an SN the
;;; application never accessed is REFUSED rather than acked, a run that will not fit the interval cap is
;;; DROPPED rather than widened, and nothing ever merges an unacknowledged SN into an acknowledged run.

(defconstant +app-ack-flags-newly-acked+ #x0000
  "The intervalFlags value RTI Connext puts on the interval carrying the JUST-acknowledged sequence number
   (ADR 0090 capture). THIS RECORDS AN OBSERVATION, NOT A DECODED MEANING: the intervalFlags encoding is
   not pinned — only two values have ever been provoked — so this constant says where RTI placed this
   value, and claims nothing about what the bits mean. See dds.rtps.message:write-app-ack.")

(defconstant +app-ack-flags-previously-reported+ #x0100
  "The intervalFlags value RTI Connext puts on the coalesced run of sequence numbers it has ALREADY
   reported in an earlier APP_ACK (ADR 0090 capture). Same caveat as +app-ack-flags-newly-acked+: an
   observation of placement, not an interpretation of the bits.")

(defstruct* (app-ack-state (:constructor make-app-ack-state))
  "Reader-side application-acknowledgment state for ONE matched remote writer (ADR 0090 slice A3b): which
   of that writer's sequence numbers the application has accessed, which it has acknowledged, and which of
   those have already been carried in an APP_ACK. Owned by the DCPS DataReader (NOT by writer-proxy):
   two same-topic DataReaders SHARE one engine writer-proxy (ADR 0048 WP-N-ENDPOINT) but acknowledge
   INDEPENDENTLY, so per-proxy state would let one reader's acknowledgment speak for the other — a false
   ack, the one failure this feature must never produce.

   ACCESSED, REPORTED and PENDING are each an ASCENDING, DISJOINT, NON-ADJACENT list of (FIRST . LAST)
   conses — a run list, not a per-SN set. In-order traffic (the overwhelmingly common case) collapses to
   ONE cons per list however many samples pass through, so the state is O(1) in the sample count and grows
   only with the number of HOLES the application leaves.

     ACCESSED  read/taken by the application but not yet acknowledged — the ONLY SNs acknowledge-sample
               and acknowledge-all may act on. A sample the application never saw is not acknowledgeable
               at any price.
     PENDING   acknowledged since the last APP_ACK; carried with +app-ack-flags-newly-acked+.
     REPORTED  already carried in an earlier APP_ACK; re-sent cumulatively with
               +app-ack-flags-previously-reported+, which is what the capture shows RTI doing.

   COUNT is the monotone per-(reader, writer) APP_ACK counter, mirroring ACKNACK's (RTPS 2.5 §8.3.7.1),
   which the writer echoes in APP_ACK_CONF."
  (accessed '() :type list)
  (reported '() :type list)
  (pending '() :type list)
  (count 0 :type (unsigned-byte 32)))

(defun* %runs-member-p (runs sn)
    (function (list integer) t)
  "T if SN falls inside one of the (FIRST . LAST) runs in RUNS."
  (dolist (r runs nil)
    (when (and (<= (car r) sn) (<= sn (cdr r))) (return t))))

(defun* %runs-add (runs sn)
    (function (list integer) list)
  "RUNS with SN inserted, keeping the list ASCENDING, DISJOINT and COALESCED across adjacency. Returns a
   FRESH list; RUNS is not mutated (a caller may be holding the old value for the wire it is building)."
  (when (%runs-member-p runs sn) (return-from %runs-add runs))
  (let ((out '()) (lo sn) (hi sn) (placed nil))
    (dolist (r runs)
      (cond
        (placed (push r out))
        ;; entirely below the new SN and not adjacent to it -> keep as is
        ((< (1+ (cdr r)) sn) (push r out))
        ;; adjacent below / adjacent above / spanning -> absorb into the growing run
        ((<= (car r) (1+ hi)) (setf lo (min lo (car r)) hi (max hi (cdr r))))
        (t (push (cons lo hi) out) (push r out) (setf placed t))))
    (unless placed (push (cons lo hi) out))
    (nreverse out)))

(defun* %runs-remove (runs sn)
    (function (list integer) list)
  "RUNS with SN removed, splitting the containing run if SN is interior. Returns a FRESH list."
  (let ((out '()))
    (dolist (r runs)
      (cond
        ((or (< sn (car r)) (> sn (cdr r))) (push r out))
        (t (when (< (car r) sn) (push (cons (car r) (1- sn)) out))
           (when (< sn (cdr r)) (push (cons (1+ sn) (cdr r)) out)))))
    (nreverse out)))

(defun* %runs-merge (a b)
    (function (list list) list)
  "The union of two run lists, ascending, disjoint and coalesced across adjacency. Returns FRESH conses;
   neither input is mutated.

   MERGES RUN BY RUN, NOT SEQUENCE NUMBER BY SEQUENCE NUMBER, and the difference is not cosmetic: a run
   spans an arbitrary range, so folding one in by walking its members costs O(range) — linear in the
   number of samples the application has read — where merging the runs themselves is linear in the number
   of RUNS, which the interval cap bounds. An acknowledge-all after a million in-order samples is one run,
   and must cost one comparison rather than a million."
  (let ((all (sort (append (copy-list a) (copy-list b)) #'< :key #'car))
        (out '()))
    (dolist (r all)
      (let ((top (first out)))
        ;; TOP is always a cons this loop built, never one of the inputs, so widening it in place is safe.
        (if (and top (<= (car r) (1+ (cdr top))))
            (setf (cdr top) (max (cdr top) (cdr r)))
            (push (cons (car r) (cdr r)) out))))
    (nreverse out)))

(defun* app-ack-note-accessed (state sn)
    (function (app-ack-state integer) t)
  "Record that the application has READ or TAKEN the writer's sample SN, making it eligible for a later
   acknowledge-sample / acknowledge-all (ADR 0090 A3b). IDEMPOTENT, and a NO-OP for an SN already
   acknowledged — re-reading a sample the application has already acknowledged must not resurrect it as
   newly acknowledgeable, which would re-emit it on the wire forever. Returns T if the SN was newly
   recorded."
  (when (or (%runs-member-p (app-ack-state-reported state) sn)
            (%runs-member-p (app-ack-state-pending state) sn)
            (%runs-member-p (app-ack-state-accessed state) sn))
    (return-from app-ack-note-accessed nil))
  (setf (app-ack-state-accessed state) (%runs-add (app-ack-state-accessed state) sn))
  t)

(defun* app-ack-acknowledge (state sn)
    (function (app-ack-state integer) t)
  "Acknowledge the writer's sample SN on the application's behalf. Returns :ACKNOWLEDGED if it moved from
   accessed to pending, :ALREADY if it was acknowledged before (idempotent — the DDS API must not punish a
   double acknowledge), or :NOT-ACCESSED if the application never read or took it.

   :NOT-ACCESSED IS THE SAFETY CASE AND IT REFUSES. The caller holds a SampleInfo, which it can only have
   obtained from a read/take — but a fabricated, stale or cross-reader one would otherwise acknowledge a
   sample this reader's application never saw, and the writer would then be entitled to purge it. Under
   ADR 0090's design principle every ambiguous case resolves to 'not yet acknowledged', so an SN that is
   not on the accessed list is refused, never acknowledged on faith."
  (cond
    ((or (%runs-member-p (app-ack-state-reported state) sn)
         (%runs-member-p (app-ack-state-pending state) sn))
     :already)
    ((not (%runs-member-p (app-ack-state-accessed state) sn)) :not-accessed)
    (t (setf (app-ack-state-accessed state) (%runs-remove (app-ack-state-accessed state) sn)
             (app-ack-state-pending state) (%runs-add (app-ack-state-pending state) sn))
       :acknowledged)))

(defun* app-ack-acknowledge-all (state)
    (function (app-ack-state) (integer 0))
  "Acknowledge every sample of this writer the application has ACCESSED and not yet acknowledged. Returns
   the number of sequence numbers moved.

   ACCESSED, NOT RECEIVED — and that distinction is the whole feature. Acknowledging everything the READER
   holds would acknowledge samples sitting undelivered in its cache, i.e. exactly the samples APP-ACK
   exists to keep the writer from purging (DDS 1.4 has no such notion at all; RTI's acknowledge_all
   likewise acknowledges previously ACCESSED samples)."
  (let ((moved 0))
    (dolist (r (app-ack-state-accessed state))
      (incf moved (1+ (- (cdr r) (car r)))))
    (setf (app-ack-state-pending state)
          (%runs-merge (app-ack-state-pending state) (app-ack-state-accessed state))
          (app-ack-state-accessed state) '())
    moved))

(defun* app-ack-intervals (state)
    (function (app-ack-state) list)
  "The interval list for the NEXT APP_ACK, in dds.rtps.message:write-app-ack's shape —
   ((FIRST-SN LAST-SN INTERVAL-FLAGS PAYLOAD) ...) with PAYLOAD always NIL (response_data is not in this
   slice) — or NIL when nothing is pending and there is therefore nothing to send. PURE: computes without
   committing, so a caller that fails to send has not lost the distinction.

   REPORTED AND PENDING RUNS ARE NEVER MERGED, even when adjacent. The capture is explicit on this: RTI's
   third APP_ACK carries [1,2] previously-reported and [3,3] newly-acked as TWO intervals rather than one
   [1,3] — so a merge would emit octets RTI never emits, and the corpus round trip would catch it.

   THE RESULT IS SORTED ASCENDING BY FIRST-SN rather than emitted reported-then-pending. In the in-order
   case those are the same list (every reported SN is below the new one), so this reproduces the capture
   byte for byte; out of order they differ, and ascending is the only ordering ever OBSERVED on the wire.
   Emitting a descending interval list would be inventing wire.

   CAPPED AT dds.rtps.message:+app-ack-max-intervals+, the same bound our own parser enforces, so we never
   emit a message we would ourselves reject. Over the cap, PREVIOUSLY-REPORTED runs are dropped LOWEST
   FIRST; if that is still not enough (a pathological application acknowledging 1024+ disjoint runs before
   any emission), the lowest PENDING runs go too. Both are the safe direction — an omitted interval leaves
   the writer believing those samples are NOT YET acknowledged, so it retains them.

   ⚠️ THE ONE COST OF THAT, STATED PLAINLY: a dropped pending run is folded into REPORTED by app-ack-commit
   regardless, so app-ack-acknowledge will answer :ALREADY for it while the writer was never told. That is
   a STALL (the writer retains a sample the application is done with), never a false ack, and it takes
   1024+ holes to reach. The alternative — an uncapped interval list — is an unbounded, remote-influenced
   message, which NFR-SEC-POSTURE forbids and our own parser would reject on arrival."
  (when (null (app-ack-state-pending state)) (return-from app-ack-intervals nil))
  (let ((all '()))
    (dolist (r (app-ack-state-reported state))
      (push (list (car r) (cdr r) +app-ack-flags-previously-reported+ nil) all))
    (dolist (r (app-ack-state-pending state))
      (push (list (car r) (cdr r) +app-ack-flags-newly-acked+ nil) all))
    (setf all (sort (nreverse all) #'< :key #'first))
    ;; TWO LINEAR PASSES, not a remove-the-worst loop. The list is ASCENDING, so the first OVER
    ;; previously-reported entries ARE the lowest ones and NTHCDR drops the lowest remaining — no repeated
    ;; LENGTH/FIND/REMOVE scan. The distinction matters here specifically: how many runs there are depends
    ;; on which samples the network delivered and in what order, so a quadratic guard is remotely-driveable
    ;; CPU (NFR-SEC-POSTURE), which is the same defect family as an uncapped loop bound.
    (let ((over (- (length all) dds.rtps.message:+app-ack-max-intervals+)))
      (when (plusp over)
        (let ((keep '()))
          (dolist (iv all)
            (if (and (plusp over) (= (third iv) +app-ack-flags-previously-reported+))
                (decf over)
                (push iv keep)))
          (setf all (nreverse keep)))
        (when (plusp over) (setf all (nthcdr over all)))))
    all))

(defun* app-ack-commit (state)
    (function (app-ack-state) (unsigned-byte 32))
  "Fold the pending runs into the reported set and return the APP_ACK COUNT to stamp on the message just
   built. Call AFTER app-ack-intervals, once the message is on its way.

   COMMITTING BEFORE THE SEND IS ACKNOWLEDGED IS DELIBERATE AND SAFE. If the datagram is lost, those SNs
   are reported in the NEXT APP_ACK as previously-reported rather than newly-acked — a different
   intervalFlags value on an interval that still names them, so the writer still learns they are
   acknowledged. Nothing is dropped; only the flag differs, and this stack does not interpret that flag.

   The reported set is bounded at dds.rtps.message:+app-ack-max-intervals+ runs by dropping the LOWEST
   (oldest, already-reported) ones — the same safe direction app-ack-intervals uses, and the reason a
   pathologically hole-punching application cannot grow this state without limit (NFR-SEC-POSTURE)."
  (setf (app-ack-state-reported state)
        (%runs-merge (app-ack-state-reported state) (app-ack-state-pending state))
        (app-ack-state-pending state) '())
  (let ((over (- (length (app-ack-state-reported state))
                 dds.rtps.message:+app-ack-max-intervals+)))
    (when (plusp over)
      (setf (app-ack-state-reported state) (nthcdr over (app-ack-state-reported state)))))
  (setf (app-ack-state-count state)
        (logand (1+ (app-ack-state-count state)) #xFFFFFFFF)))
