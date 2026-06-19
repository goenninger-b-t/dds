(in-package #:dds.rtps.reliable)

;;;; Stateful reliable writer/reader protocol logic (RTPS 2.5 §8.4). Operates on
;;;; submessage field VALUES (not bytes) so the state machines are directly
;;;; testable; the byte/transport wiring is a later increment. CLOS-free; the
;;;; consing here (per-reader proxies, resend lists) is a documented v1 concern.

(defparameter *fragment-size* 1024
  "Outbound RTPS fragmentSize in octets (uint16, <=65535; RTPS 2.5 §9.4.5.5 DATA_FRAG). A sample whose serialized size exceeds this is sent as DATA_FRAG submessages.")

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

;;; ---- Writer side (§8.4.2): one ReaderProxy per matched reader ----

(defstruct* (reader-proxy (:constructor make-reader-proxy))
  "Writer-side proxy for one matched reader (RTPS 2.5 §8.4.2). Two distinct
   watermarks (RTPS 2.5 §8.4.2.2): ACKED-BASE is the reader's ACKNOWLEDGED watermark
   (it has acknowledged all SN < acked-base; advanced only by ACKNACK); UNSENT-BASE
   is the UNSENT watermark = 1 + highestSentChangeSN (next_unsent_change pushes the
   change at UNSENT-BASE once, then advances it). Push pacing keys off UNSENT-BASE;
   ACKNACK-driven repair (requested_changes) is independent of it."
  (acked-base 1 :type integer)             ; reader has acknowledged all SN < acked-base
  (unsent-base 1 :type integer))           ; 1 + highestSentChangeSN; changes >= this are unsent

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
   readers ACK; monotonic (set once by writer-finalize-durability, never cleared in v1)."
  (hc nil :type (or null dds.rtps.history:history-cache))  ; a HistoryCache
  (last-sn 0 :type integer)
  (hb-count 0 :type integer)
  (proxies (make-hash-table :test 'equalp) :type hash-table)   ; reader key (opaque, equalp) -> reader-proxy
  (frag-hb-count 0 :type integer)   ; HEARTBEAT_FRAG Count, separate from hb-count
  (lock (dds.pal:make-lock) :type t)
  (space-cv (dds.pal:make-condvar) :type t)   ; signalled (under LOCK) when the cache shrinks; writer-write waits on it when full (ADR 0016 §Backpressure)
  (max-blocking-ns nil :type (or null (integer 0)))   ; RELIABILITY.max_blocking_time in ns; NIL = never block (unlimited cache)
  (finalized nil :type boolean))   ; durability-finalize (DDS 1.4 §2.2.3.4 extension): a TL writer reverts to the VOLATILE full-ACK purge

(defmacro %with-writer-lock ((writer) &body body)
  "Serialize BODY's access to WRITER's HistoryCache + proxies (publish thread vs receiver thread). The
   guarded public ops never call one another, so the non-recursive lock cannot self-deadlock; the internal
   helpers (get-reader-proxy, %changes-from) run only inside a held lock."
  `(dds.pal:with-lock ((rtps-writer-lock ,writer)) ,@body))

(defun* %writer-signal-space (writer)
    (function (rtps-writer) t)
  "Broadcast WRITER's SPACE-CV under the writer LOCK — wake every writer-write/writer-lifecycle-change
   blocked waiting for the bounded KEEP_ALL cache to drop below max_samples (WP-ASYNC-FLOW backpressure,
   ADR 0016 §Backpressure). Call AFTER any operation that frees cache space: the ACKNACK purge
   (writer-purge-acked — a KEEP_ALL cache shrinks only when the slowest reader ACKs, RTPS 2.5 §8.4.1) and
   controller teardown. condvar-BROADCAST (not signal): several publishers may be blocked, and one freed slot
   may admit exactly one — each re-checks the count on wake (a no-progress waker re-blocks until its
   deadline). A no-op (signals nobody) when no writer is blocked. Safe to call when MAX-BLOCKING-NS is NIL
   (no waiter ever exists)."
  (%with-writer-lock (writer)
    (dds.pal:condvar-broadcast (rtps-writer-space-cv writer)))
  t)

(defun* %writer-add-bounded (writer make-change)
    (function (rtps-writer function) (or integer (eql :timeout)))
  "Add the change produced by the thunk MAKE-CHANGE (given the freshly-bumped SN) to WRITER's HistoryCache
   under the writer LOCK, applying DDS-standard block-up-to-max_blocking_time backpressure (WP-ASYNC-FLOW,
   FR-PF-2/FR-QOS, ADR 0016 §Backpressure). Shared core of writer-write + writer-lifecycle-change (DRY).

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
          (return-from %writer-add-bounded :timeout)))
      (let ((sn (incf (rtps-writer-last-sn writer))))                  ; room confirmed (or unlimited / KEEP_LAST)
        (dds.rtps.history:hc-add-change hc (funcall make-change sn))
        sn))))

(defun* get-reader-proxy (writer reader-id)
    (function (rtps-writer t) reader-proxy)
  "The ReaderProxy for the matched reader named by the opaque per-endpoint key READER-ID, created on
   first use. The key is treated only as an equalp hash key (the disc layer passes the remote reader's
   full 16-octet GUID; the value-level tests pass an integer): a SequenceNumber is unique only within
   one writer GUID (RTPS 2.5 §8.3.5.4), so each remote reader's watermarks are kept independent."
  (or (gethash reader-id (rtps-writer-proxies writer))
      (setf (gethash reader-id (rtps-writer-proxies writer)) (make-reader-proxy))))

(defun* writer-write (writer payload &optional (key-hash nil) (inline-qos nil))
    (function (rtps-writer (array (unsigned-byte 8) (*))
               &optional (or null (array (unsigned-byte 8) (*)))
                         (or null (simple-array (unsigned-byte 8) (*))))
              (or integer (eql :timeout)))
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
   NIL (the default) → no Q-bit, no extra bytes — byte-identical to the prior behaviour."
  (%writer-add-bounded
   writer (lambda (sn) (dds.rtps.history:make-cache-change
                        :sn sn :serialized-payload payload :instance-key-hash key-hash
                        :inline-qos inline-qos))))

(defun* writer-lifecycle-change (writer key-hash status-flags &optional (inline-qos nil))
    (function (rtps-writer (simple-array (unsigned-byte 8) (*)) (unsigned-byte 8)
               &optional (or null (simple-array (unsigned-byte 8) (*))))
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
  (%writer-add-bounded
   writer (lambda (sn) (dds.rtps.history:make-cache-change
                        :sn sn :kind (dds.rtps.message:status-info->kind status-flags)
                        :instance-key-hash key-hash :status-info status-flags
                        :inline-qos inline-qos))))

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
   can dispatch :data vs :dispose/:unregister (RTPS 2.5 §8.4.2.2 / §9.6.4.9)."
  (loop for ch in (dds.rtps.history:hc-changes-for-reader (rtps-writer-hc writer) nil)
        when (>= (dds.rtps.history:cache-change-sn ch) base)
          collect ch))

(defun* writer-data-list (writer reader-id)
    (function (rtps-writer t) list)
  "Changes not yet acked by READER-ID (the opaque per-reader key), as a list of CacheChanges in SN order."
  (%with-writer-lock (writer)
    (%changes-from writer (reader-proxy-acked-base (get-reader-proxy writer reader-id)))))

(defun* writer-unsent-list (writer reader-id)
    (function (rtps-writer t) list)
  "The UNSENT changes for READER-ID (the opaque per-reader key; next_unsent_change, RTPS 2.5 §8.4.2.2): the
   CacheChanges with SN >= the reader's UNSENT-BASE, in SN order. On a non-empty result the
   UNSENT-BASE watermark is advanced past the highest SN collected, so each change is pushed
   EXACTLY ONCE in pushMode (§8.4.2.2). Lost/late changes are recovered via the ACKNACK repair
   path (writer-on-acknack), not by re-pushing. Each element is the CacheChange (KIND/SN/
   payload/key-hash/status-info) so a :dispose/:unregister is pushed as a no-payload DATA."
  (%with-writer-lock (writer)
    (let* ((proxy (get-reader-proxy writer reader-id))
           (changes (%changes-from writer (reader-proxy-unsent-base proxy))))
      (when changes
        (setf (reader-proxy-unsent-base proxy)
              (1+ (dds.rtps.history:cache-change-sn (first (last changes))))))
      changes)))

(defun* writer-on-acknack (writer reader-id base numbits bitmap)
    (function (rtps-writer t integer (unsigned-byte 32) (simple-array (unsigned-byte 32) (*))) (values list list))
  "Process an ACKNACK from READER-ID (the opaque per-reader key; RTPS 2.5 §8.3.7.1). Confirm SN < BASE, then
   for each NACKed SN (bit set in BITMAP) return a resend if present, else a GAP.
   Returns (values data-resends gap-sns), data-resends a list of CacheChanges (so the
   resend path dispatches :data vs :dispose/:unregister exactly as the initial push)."
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
                (push ch resends)
                (push sn gaps)))))
      (values (nreverse resends) (nreverse gaps)))))

(defun* writer-purge-acked (writer reader-keys &optional (durability :volatile))
    (function (rtps-writer list &optional (member :volatile :transient-local :transient :persistent))
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
   the writer is :VOLATILE OR FINALIZED; an un-finalized TRANSIENT_LOCAL writer is byte-identical to before."
  (if (or (null reader-keys)
          (and (not (eq durability :volatile)) (not (rtps-writer-finalized writer))))
      0
      (let ((purged (%with-writer-lock (writer)
                      (dds.rtps.history:hc-purge-below
                       (rtps-writer-hc writer)
                       (loop for k in reader-keys
                             minimize (reader-proxy-acked-base (get-reader-proxy writer k)))))))
        (when (plusp purged) (%writer-signal-space writer))   ; the cache shrank: wake any blocked writer-write
        purged)))

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
  (received (make-hash-table :test 'eql) :type hash-table)   ; SN -> T (received) | :gap (presence only)
  (first-sn 1 :type integer)
  (last-sn 0 :type integer)                ; available range from HEARTBEAT
  (skip-history nil :type boolean)         ; durability gate: VOLATILE skips pre-match history (DDS §2.2.3.4)
  (durability-applied-p nil :type boolean) ; latch: the skip is applied once, on the first HEARTBEAT
  (reassembly (make-hash-table :test 'eql) :type hash-table)) ; SN -> frag-reassembly

(defstruct* (dedup-origin (:constructor %make-dedup-origin))
  "Per-original-GUID dedup state: contiguous low-watermark LO + bounded out-of-order set ABOVE.
   In-order traffic keeps ABOVE EMPTY (LO just advances), O(1)/GUID. NFR-MEM. RTPS 2.5 §8.3.5.4."
  (lo 0 :type integer)
  (above (make-hash-table :test 'eql) :type hash-table))

(defstruct* (rtps-reader (:constructor make-rtps-reader))
  "Stateful reliable RTPS reader (RTPS 2.5 §8.4.10): an opaque-writer-key -> WriterProxy table
   plus an original-GUID dedup map for relay-forwarded samples (§8.3.5.4)."
  (proxies  (make-hash-table :test 'equalp) :type hash-table)   ; writer key (opaque, equalp) -> writer-proxy
  (dedup-map (make-hash-table :test 'equalp) :type hash-table)) ; original-GUID[16] -> dedup-origin

(defun* get-writer-proxy (reader writer-id)
    (function (rtps-reader t) writer-proxy)
  "The WriterProxy for the matched writer named by the opaque per-endpoint key WRITER-ID, created on
   first use. The key is treated only as an equalp hash key (the disc layer passes the remote writer's
   full 16-octet GUID; the value-level tests pass an integer): a SequenceNumber is unique only within
   one writer GUID (RTPS 2.5 §8.3.5.4), so two writers sharing EntityId 0x102 on different participants
   get independent received-SN sets / HEARTBEAT ranges / ACKNACK / GAP / reassembly state."
  (or (gethash writer-id (rtps-reader-proxies reader))
      (setf (gethash writer-id (rtps-reader-proxies reader)) (make-writer-proxy))))

(defun* reader-dedup-accept-p (reader original-guid original-sn)
    (function (rtps-reader (or null (simple-array (unsigned-byte 8) (16))) (or null integer)) boolean)
  "Original-GUID per-SN dedup gate for relay-forwarded samples (RTPS 2.5 §8.3.5.4).
   Returns T (accept + record) when ORIGINAL-GUID is nil (PID absent — normal non-relayed path,
   never consults the map) or (ORIGINAL-GUID, ORIGINAL-SN) not yet seen; returns NIL (duplicate,
   discard) when this exact (GUID, SN) pair was already delivered. Per-GUID contiguous-watermark
   design: LO is the highest SN advanced through contiguously (every SN <= LO is known-delivered);
   ABOVE is the bounded out-of-order set for SNs > LO not yet compacted into LO. In-order traffic
   keeps ABOVE EMPTY — LO just advances, O(1)/GUID (NFR-MEM). At the *max-gap-range* cap, the
   HIGHEST entry in ABOVE is shed (never LO is advanced past an un-arrived SN) — the only residual
   is a benign duplicate if that high out-of-order SN re-arrives; silent loss cannot occur.
   INERT when ORIGINAL-GUID is nil."
  (if (null original-guid)
      t                                                   ; no PID -> normal path, always accept
      (let* ((outer (rtps-reader-dedup-map reader))
             (origin (or (gethash original-guid outer)
                         (let ((o (%make-dedup-origin)))
                           (setf (gethash original-guid outer) o)
                           o)))
             (lo (dedup-origin-lo origin))
             (above (dedup-origin-above origin)))
        (cond
          ((<= original-sn lo) nil)                      ; below watermark: already delivered
          ((gethash original-sn above) nil)              ; in out-of-order set: already delivered
          (t                                             ; ACCEPT
           (setf (gethash original-sn above) t)
           ;; NFR-MEM cap: shed the HIGHEST entry so lo never skips an un-arrived gap SN;
           ;; if the shed SN re-arrives it becomes a benign duplicate (never silent loss)
           (when (> (hash-table-count above) *max-gap-range*)
             (let ((max-sn (loop for k being each hash-key of above maximize k)))
               (remhash max-sn above)))
           ;; advance watermark through the contiguous prefix in ABOVE
           (loop while (gethash (1+ (dedup-origin-lo origin)) above)
                 do (remhash (1+ (dedup-origin-lo origin)) above)
                    (incf (dedup-origin-lo origin)))
           t)))))

(defun* reader-on-data (reader writer-id sn payload)
    (function (rtps-reader t integer (array (unsigned-byte 8) (*))) t)
  "Accept a DATA. Idempotent (duplicate SN re-marks — dedup); tracks the highest SN seen. Records only a
   PRESENCE marker (T), not PAYLOAD — the application is delivered the sample from the wire, and the engine
   only needs SN presence for ACKNACK/complete/gap, so no per-sample payload is retained (the PAYLOAD
   argument is kept for the call contract but not stored)."
  (declare (ignore payload))
  (let ((proxy (get-writer-proxy reader writer-id)))
    (setf (gethash sn (writer-proxy-received proxy)) t)
    (when (> sn (writer-proxy-last-sn proxy)) (setf (writer-proxy-last-sn proxy) sn))
    t))

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
   requests the full advertised range."
  (let* ((proxy (get-writer-proxy reader writer-id))
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
    t))

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
   §8.3.5.4)."
  (let ((proxy (get-writer-proxy reader writer-id)))
    (setf (writer-proxy-skip-history proxy) skip-history)
    (setf (writer-proxy-durability-applied-p proxy) nil)   ; re-arm on (re)match
    proxy))

(defun* reader-acknack (reader writer-id)
    (function (rtps-reader t) (values integer (unsigned-byte 32) (simple-array (unsigned-byte 32) (*))))
  "Compute an ACKNACK (RTPS 2.5 §8.3.7.1): (values base numBits bitmap). BASE is
   the lowest unreceived SN in [first, last] (or last+1 if none); the bitmap NACKs
   the unreceived SNs in [base, last] (capped at 256)."
  (let* ((proxy (get-writer-proxy reader writer-id))
         (first (writer-proxy-first-sn proxy))
         (last (writer-proxy-last-sn proxy))
         (received (writer-proxy-received proxy))
         (base (loop for sn from first to last
                     unless (gethash sn received) return sn
                     finally (return (1+ last))))
         (numbits (max 0 (min 256 (- (1+ last) base))))
         (bitmap (make-array (max 1 (ceiling numbits 32))
                             :element-type '(unsigned-byte 32) :initial-element 0)))
    (loop for sn from base below (+ base numbits)
          unless (gethash sn received)
            do (dds.rtps.message:seqnum-set-bit bitmap (- sn base)))
    (values base numbits bitmap)))

(defun* reader-on-gap (reader writer-id gap-start base numbits bitmap)
    (function (rtps-reader t integer integer (unsigned-byte 32) (simple-array (unsigned-byte 32) (*))) t)
  "Mark GAPped SNs as irrelevant so they do not block the ack (RTPS 2.5 §8.3.7.4):
   the range [gapStart, base-1] plus the SNs listed in the bitmap. The contiguous range is LOWER-clamped
   to the proxy's first-sn (marking below the live window is pointless) and its iteration is HARD-capped at
   *max-gap-range* SNs — gapStart/base are wire-controlled 64-bit values and last-sn is itself set from
   inbound HEARTBEATs, so NEITHER bounds the loop; the cap (independent of any wire value) is the
   resource-exhaustion guard against a 2^60-span CPU+memory DoS (NFR-SEC-POSTURE; RTPS 2.5 §8.3.7.4). A
   legitimately larger evicted run is recovered over subsequent GAP/HEARTBEAT rounds (firstSN compaction),
   so the cap is loss-free. The bitmap loop is already bounded (numBits<=256, <=256 inserts)."
  (let* ((proxy (get-writer-proxy reader writer-id))
         (received (writer-proxy-received proxy))
         (lo (max gap-start (writer-proxy-first-sn proxy)))         ; don't mark below the proxy window
         (hi (min base (+ lo *max-gap-range*))))                    ; HARD cap — independent of wire last-sn
    (loop for sn from lo below hi do (setf (gethash sn received) :gap))
    (dotimes (i numbits)                                            ; bitmap is already bounded (numBits<=256)
      (when (dds.rtps.message:seqnum-set-bit-p bitmap i)
        (setf (gethash (+ base i) received) :gap)))
    t))

(defun* reader-complete-p (reader writer-id)
    (function (rtps-reader t) t)
  "T iff every SN in the available range [first, last] has been received or GAPped."
  (let* ((proxy (get-writer-proxy reader writer-id))
         (received (writer-proxy-received proxy)))
    (loop for sn from (writer-proxy-first-sn proxy) to (writer-proxy-last-sn proxy)
          always (gethash sn received))))

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
    (let* ((proxy (get-writer-proxy reader writer-id))
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
          buf)))))

(defun* reader-frag-acknack (reader writer-id sn)
    (function (rtps-reader t integer) t)
  "Compute a NACK_FRAG fragment set for the in-progress reassembly of (WRITER-ID, SN):
   (values base numBits bitmap) naming the 1-based fragment numbers NOT yet received, or
   NIL if there is no such reassembly (unknown or already complete). The window
   [base, base+numBits) is capped at 256 fragments per NACK_FRAG (§9.4.2.8). RTPS 2.5 §8.3.7.2."
  (let* ((proxy (get-writer-proxy reader writer-id))
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
        (values base numbits bitmap)))))

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
        (values (ceiling (length payload) *fragment-size*)
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
        (writer-frag-plan-for (length payload) *fragment-size* base numbits bitmap)))))

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
