(in-package #:dds.rtps.history)

(define-condition history-not-implemented (error)
  ((what :initarg :what :reader history-not-implemented-what))
  (:report (lambda (c s) (format s "HistoryCache: ~a" (history-not-implemented-what c)))))

(defstruct* (cache-change (:constructor make-cache-change))
  "An RTPS CacheChange (IMPLEMENTATION-PLAN §7.4): the pooled per-sample record held
   in a HistoryCache — change KIND (:data/:dispose/:unregister), writer GUID,
   sequence number, instance key hash, serialized payload, STATUS-INFO flags
   (StatusInfo_t for a dispose/unregister, RTPS 2.5 §9.6.4.9), source timestamp,
   and inline QoS.

   SEND-REFCOUNT (release-safety, the operating contract §4) counts the in-flight or deferred
   sends that still reference SERIALIZED-PAYLOAD BY REFERENCE (a captured send build-thunk that
   has not yet copied the payload into a datagram — initial/paced push, ACKNACK/NACK_FRAG
   retransmit). It is mutated ONLY under the owning writer's lock (acquire atomically with the
   capture-read, release after the copy) and is read by CACHE-CHANGE-RELEASABLE-P. Today it is a
   behaviorally-neutral no-op safety net (the GC pins the payload vector); it becomes load-bearing
   when the payload is a POOLED buffer — eviction must defer the buffer's pool-release until
   SEND-REFCOUNT reaches 0 so a recycled buffer can never be overwritten while a captured thunk
   still has to copy it (WP-DDS-SECURITY-ZEROALLOC-AEAD T5a).

   POOLED-PAYLOAD (WP-DDS-SECURITY-ZEROALLOC-AEAD T5a, the operating contract §4): on the data_protection
   publish path the SERIALIZED-PAYLOAD is NOT a fresh length-exact vector but the (oversized, fixed-size) VEC
   of POOLED-BUFFER, a buffer drawn from the HistoryCache's payload-pool and encoded in place — so a secured
   publish allocates no per-sample payload. The TRUE secured-payload length is POOLED-LEN (the codec total
   44+N+pad ≤ the buffer capacity); EVERY send-path length read goes through CACHE-CHANGE-PAYLOAD-LEN, never
   (length SERIALIZED-PAYLOAD), so the buffer's garbage tail beyond POOLED-LEN never reaches the wire. EVICTED
   is set by %hc-remove-change when the change leaves the cache; it gates the deferred pool-release
   (hc-try-release-pooled): the buffer returns to the pool only once the change is EVICTED *and* SEND-REFCOUNT
   is 0. POOLED-BUFFER NIL (the default, all non-secured + dispose/unregister changes) ⇒ no pooling: payload-len
   falls back to (length serialized-payload) and the release machinery is inert — byte-identical to before."
  (kind :data :type (member :data :dispose :unregister))
  (writer-guid nil :type (or null (array (unsigned-byte 8) (*))))
  (sn 0 :type (integer 0))
  (instance-key-hash nil :type (or null (array (unsigned-byte 8) (*))))
  (serialized-payload nil :type (or null (array (unsigned-byte 8) (*))))  ; SerializedPayload octets (a POOLED buffer's VEC when pooled-buffer is set, T5a)
  (status-info 0 :type (unsigned-byte 8))                                 ; StatusInfo_t flags (RTPS 2.5 §9.6.4.9)
  (source-timestamp 0 :type integer)
  (inline-qos nil :type (or null (array (unsigned-byte 8) (*))))          ; serialized inline-QoS ParameterList
  (send-refcount 0 :type (integer 0))                                     ; in-flight/deferred send references (operating contract §4 release-safety; mutated only under the owning writer's lock)
  (pooled-buffer nil :type (or null dds.core.buffer:octet-buffer))        ; T5a: the pool buffer this change owns (NIL = not pooled, byte-identical)
  (pooled-len nil :type (or null (integer 0)))                            ; T5a: true secured-payload length within the oversized pooled vec (NIL = not pooled)
  (evicted nil :type boolean)                                             ; T5a: change has left the cache — gates the deferred pooled-buffer release (mutated only under the owning writer's lock)
  ;; WP-FLATDATA-LOAN-WRITE (FR-PF-4, R6, ADR 0042; NOT cleared for ship — pending counsel): the PRE-COMMITTED
  ;; Zero-Copy pool slot this change's payload already sits in (loan-write wrote the sample straight into the
  ;; slot; refcount=1 held). ZC-STATE lifecycle — mutated ONLY under the owning writer's lock (writer-zc-claim /
  ;; writer-zc-unarm): NIL (no slot, the default — byte-identical everywhere), :ARMED (slot committed + held, the
  ;; send site may emit its ref ONCE), :CONSUMED (the single ref was emitted; the refcount now belongs to the
  ;; resolving reader; a retransmit falls back to the retained payload), :RELEASED (the send-site fallback
  ;; decision / sweep %zc-released the slot; the retained payload serves every send). ZC-SLOT -1 = none.
  (zc-slot -1 :type fixnum)                                               ; ADR 0042: pre-committed pool slot index (-1 = none)
  (zc-generation 0 :type (unsigned-byte 32))                              ; ADR 0042: the slot's committed generation
  (zc-state nil :type (member nil :armed :consumed :released))            ; ADR 0042: one-shot slot lifecycle (under the writer lock)
  ;; WP-ACKED-SLOT-PINNING (FR-PF-4, R6, ADR 0044): the TX PIN hold — a SECOND, distinct refcount contribution on
  ;; ZC-SLOT (over the armed/delivery hold) that keeps the committed slot LIVE until every matched reliable reader
  ;; ACKs, so retransmit / non-ZC / extra-ZC sends read the slot ON DEMAND instead of a per-write retained payload.
  ;; ZC-PINNED T = the pin hold is currently held; flipped T->NIL EXACTLY ONCE (under the writer lock) by
  ;; hc-try-release-pinned at the change-removal choke, which then %zc-releases it. ZC-LEN = the pinned change's
  ;; TRUE serialized length (SERIALIZED-PAYLOAD is NIL until an on-demand read materialises it) so cache-change-
  ;; payload-len + the ZC size gate work without touching the slot. Both NIL/0 for a non-pinned change (byte- and
  ;; alloc-identical). NOT cleared for ship — pending counsel (R6).
  (zc-pinned nil :type boolean)                                          ; ADR 0044: the TX pin hold is held (one-shot, under the writer lock)
  (zc-len nil :type (or null (integer 0))))                              ; ADR 0044: true serialized length of a pinned change (serialized-payload NIL until resolved)

(defun* cache-change-releasable-p (change)
    (function (cache-change) boolean)
  "T iff CHANGE has NO outstanding in-flight/deferred send reference (SEND-REFCOUNT = 0) — the gate a
   pooled-payload eviction (the operating contract §4 release-safety) consults before returning CHANGE's
   serialized-payload buffer to its pool: releasable means no captured send build-thunk still has to copy
   the payload, so the buffer can be recycled without corrupting the wire. MUST be read under the owning
   writer's lock (the same lock SEND-REFCOUNT is mutated under) so the 0-check does not race a concurrent
   acquire/release. Behaviorally inert until the payload is pooled (today the GC pins it); load-bearing in
   WP-DDS-SECURITY-ZEROALLOC-AEAD T5a. No allocation (a fixnum-slot ZEROP), hot-path-safe."
  (zerop (cache-change-send-refcount change)))

(declaim (inline cache-change-payload-len))
(defun* cache-change-payload-len (change)
    (function (cache-change) (integer 0))
  "The EFFECTIVE serialized-payload length of CHANGE: POOLED-LEN (the true secured-payload length) when CHANGE
   is POOLED (its serialized-payload is the oversized fixed VEC of a pool buffer, T5a), else (length
   SERIALIZED-PAYLOAD), else 0 for a no-payload change. EVERY send-path length read (DATA size, fragment count,
   NACK_FRAG plan) MUST use this instead of (length SERIALIZED-PAYLOAD) so a pooled buffer's garbage tail beyond
   the true length is never put on the wire (WP-DDS-SECURITY-ZEROALLOC-AEAD T5a). For a non-pooled change this is
   exactly (length serialized-payload) — byte-identical. No allocation (a slot read + length), hot-path-safe."
  (let ((pl (cache-change-pooled-len change)))
    (cond (pl pl)
          ((cache-change-serialized-payload change) (length (cache-change-serialized-payload change)))
          ((cache-change-zc-len change))                ; WP-ACKED-SLOT-PINNING: a pinned change carries its true length (payload NIL until resolved, ADR 0044)
          (t 0))))

;;;; HistoryCache (FR-RTPS-5): a change store honouring HISTORY (KEEP_LAST depth /
;;;; KEEP_ALL) and RESOURCE_LIMITS (max_samples). v1 keys changes by sequence
;;;; number in a hash-table; a secondary keyhash->SN index applies KEEP_LAST depth
;;;; PER INSTANCE (DDS 1.4 §2.2.3.18). A pooled, zero-alloc store + non-consing
;;;; iteration and LIFESPAN expiry are tracked follow-ups.

(defstruct* (history-cache (:constructor %make-history-cache))
  "A HistoryCache (FR-RTPS-5): a change store honouring HISTORY (KIND :keep-last with
   DEPTH / :keep-all) and RESOURCE_LIMITS (MAX-SAMPLES; nil = unlimited). CHANGES keys
   changes by sequence number; INSTANCES is the per-instance KEEP_LAST index — instance
   keyhash (EQUALP) -> that instance's stored SNs oldest-first (DDS 1.4 §2.2.3.18: KEEP_LAST
   keeps the last DEPTH values per instance). A NIL / HANDLE_NIL keyhash collapses to one
   shared bucket (global KEEP_LAST). The index is maintained for KEEP_LAST ONLY (its sole
   consumer is per-instance eviction); a KEEP_ALL cache keeps it empty (an O(1) change-table
   insert, never evicted per-instance). Build via MAKE-HISTORY-CACHE."
  (kind :keep-last :type (member :keep-last :keep-all))
  (depth 1 :type (integer 1))
  (max-samples nil :type (or null (integer 0)))                                  ; resource limit; nil = unlimited
  (type-support nil :type (or null dds.types:type-support))
  (changes (make-hash-table :test 'eql) :type hash-table)   ; HOTPATH-ALLOC(COLD): defstruct initform — one table per HistoryCache, not per sample
  (instances (make-hash-table :test 'equalp) :type hash-table)                   ; keyhash -> SNs oldest-first (per-instance KEEP_LAST, §2.2.3.18)   ; HOTPATH-ALLOC(COLD): defstruct initform — one table per HistoryCache, not per sample
  (count 0 :type (integer 0))
  ;; WP-PERF: the stored SN extent, maintained INCREMENTALLY at the two chokepoints (%hc-store / %hc-remove-change)
  ;; so hc-min-seq / hc-max-seq are O(1) reads instead of a full maphash SCAN of the change table. They are read on
  ;; the WRITE path (the reliable writer's firstSN/lastSN for every HEARTBEAT), so the scan made a write O(stored) —
  ;; quadratic for any writer whose history is non-trivial (a slow/bursty reader, KEEP_ALL, a repair backlog). A
  ;; profile of write-sample put 80% of its CPU in these two functions. SNs are FIXNUM-typed here (RTPS 2.5 §8.3.5.4
  ;; SequenceNumber_t is 64-bit; a 62-bit fixnum bounds it at 4.6e18 — 146,000 years at 1M samples/s), which also
  ;; takes the comparisons off SBCL's generic-arithmetic path (TWO-ARG-< / TWO-ARG-> dominated the profile's SELF time).
  (min-seq 0 :type fixnum)          ; 0 = empty (a valid SN is >= 1, RTPS 2.5 §8.3.5.4)
  (max-seq 0 :type fixnum)
  (payload-pool nil :type (or null dds.core.arena:buffer-pool))                   ; T5a: data_protection secured-payload pool (NIL = no pooling, byte-identical); buffers acquired+released ONLY under the owning writer's lock
  (zc-release-fn nil :type (or null function))                                    ; WP-ACKED-SLOT-PINNING (ADR 0044): opaque (lambda (slot generation)) the disc layer installs to %zc-release a pinned change's TX slot at the change-removal choke; NIL = no pinning (layering: history must not depend on dds.xport.zerocopy, so the release is a funcall'd closure, mirroring payload-pool)
  (change-freelist '() :type list))                                               ; TASK-3 (ADR 0077): recycled cache-change STRUCTS (non-ZC / non-pooled / non-pinned only), drawn by hc-data-change/-lifecycle-change and returned by hc-try-recycle-change at the release gate (evicted + send-refcount 0) — zero per-sample struct alloc on the common write path once warm; mutated ONLY under the owning writer's lock (NFR-MEM)

(defun* %resolve-max-samples (resource-limits)
    (function (t) t)
  "Extract a max_samples integer from RESOURCE-LIMITS (an integer, a plist with
   :max-samples, or NIL = unlimited)."
  (cond ((integerp resource-limits) resource-limits)
        ((consp resource-limits) (getf resource-limits :max-samples))
        (t nil)))

(defun* make-history-cache (kind depth resource-limits type-support)
    (function ((member :keep-last :keep-all) (integer 1) t t) history-cache)
  "Create a HistoryCache with HISTORY (KIND/DEPTH) and RESOURCE_LIMITS."
  (%make-history-cache :kind kind :depth depth
                       :max-samples (%resolve-max-samples resource-limits)
                       :type-support type-support))

(defun* hc-change-count (hc)
    (function (history-cache) (integer 0))
  "The number of changes currently stored in the HistoryCache HC."
  (history-cache-count hc))

(defun* hc-kind (hc)
    (function (history-cache) (member :keep-last :keep-all))
  "The HISTORY kind of the HistoryCache HC (:keep-last or :keep-all). Read by the reliable writer's
   backpressure path to decide whether the cache is bound by max_samples (KEEP_ALL, ADR 0016 §Backpressure)."
  (history-cache-kind hc))

(defun* hc-max-samples (hc)
    (function (history-cache) (or null (integer 0)))
  "The RESOURCE_LIMITS max_samples bound of the HistoryCache HC (NIL = unlimited). Read by the reliable
   writer's block-up-to-max_blocking_time backpressure path (ADR 0016 §Backpressure)."
  (history-cache-max-samples hc))

(defun* hc-depth (hc)
    (function (history-cache) (integer 1))
  "The HISTORY KEEP_LAST DEPTH of the HistoryCache HC (DDS 1.4 §2.2.3.18; meaningful for KEEP_LAST, ignored
   by KEEP_ALL). Read by the lazy secured-payload-pool provisioning (%ensure-secured-payload-pool) to size the
   encode pool from the HC's own HISTORY when crypto keys are installed AFTER enable-publisher via the live
   DDS-Security handshake (WP-DDS-SECURITY-ZEROALLOC-AEAD T5a)."
  (history-cache-depth hc))

(defun* hc-get-change (hc seqnum)
    (function (history-cache integer) t)
  "Return the CacheChange with SEQNUM, or NIL."
  (values (gethash seqnum (history-cache-changes hc))))

(defun* %hc-bucket-key (key-hash)
    (function (t) t)
  "The per-instance index bucket key for a change's INSTANCE-KEY-HASH. A NIL or all-zero
   HANDLE_NIL collapses to one canonical :UNKEYED bucket (the single-instance/global KEEP_LAST
   case, DDS 1.4 §2.2.3.18); any other 16-octet handle is its own bucket (EQUALP-compared)."
  (if (or (null key-hash) (every #'zerop key-hash)) :unkeyed key-hash))

(defun* %hc-index-append (hc sn change)
    (function (history-cache integer cache-change) t)
  "Append SN to its instance bucket tail (SNs arrive monotonically per writer, so the bucket
   stays oldest-first) in the per-instance KEEP_LAST index (DDS 1.4 §2.2.3.18). KEEP_LAST-ONLY:
   the index serves per-instance eviction, which only KEEP_LAST performs; a KEEP_ALL cache never
   evicts per-instance, so it keeps NO index — an O(1) change-table insert, unchanged from pre-WP
   (a KEEP_ALL bucket would otherwise grow unbounded and the tail-append would be O(N) = O(N²) total).
   The append walks the bucket tail, which under KEEP_LAST is bounded by DEPTH (O(depth))."
  (when (eq (history-cache-kind hc) :keep-last)
    (let ((key (%hc-bucket-key (cache-change-instance-key-hash change))))
      (setf (gethash key (history-cache-instances hc))
            (nconc (gethash key (history-cache-instances hc)) (list sn)))))
  t)

(defun* %hc-index-drop (hc sn change)
    (function (history-cache integer cache-change) t)
  "Drop SN from its instance bucket in the per-instance index; remove the bucket when it empties
   so a re-created instance starts fresh (no orphaned SN inflating a later depth check). KEEP_LAST-ONLY
   (mirrors %hc-index-append): a KEEP_ALL cache keeps no index, so its purge/dispose removals never
   touch it (an O(1) change-table-only removal, unchanged from pre-WP)."
  (when (eq (history-cache-kind hc) :keep-last)
    (let* ((key (%hc-bucket-key (cache-change-instance-key-hash change)))
           (rest (delete sn (gethash key (history-cache-instances hc)))))
      (if rest
          (setf (gethash key (history-cache-instances hc)) rest)
          (remhash key (history-cache-instances hc)))))
  t)

(defun* hc-try-release-pooled (hc change)
    (function (history-cache cache-change) t)
  "Return CHANGE's pooled secured-payload buffer to HC's PAYLOAD-POOL iff the release is DUE — the SINGLE
   refcount-gated pool-release predicate of the operating contract §4 release-safety (WP-DDS-SECURITY-ZEROALLOC-AEAD
   T5a), called from BOTH triggers that can make a buffer due: the eviction choke (%hc-remove-change) and the
   last send-ref drop (writer-release-change-ref / -refs). The buffer is released ONLY when ALL three hold: CHANGE
   OWNS a pooled buffer (POOLED-BUFFER non-nil), CHANGE has been EVICTED from the cache, and CHANGE has NO
   outstanding send-ref (CACHE-CHANGE-RELEASABLE-P, SEND-REFCOUNT 0). So a buffer is never recycled while it is
   still live in the cache (a future send may capture it) nor while an in-flight/deferred send still has to copy
   it (recycling then would corrupt the wire); a buffer EVICTED while referenced is released exactly once, on the
   last ref drop. Clears POOLED-BUFFER after release so a second call is a validated no-op (idempotent, mirroring
   the floored ref-release). Inert when PAYLOAD-POOL is nil or CHANGE is not pooled — byte-identical to before.
   MUST run under the owning writer's lock (the same lock SEND-REFCOUNT + EVICTED are mutated under) so the
   three-way due-check cannot race a concurrent acquire/release/eviction. No allocation, hot-path-safe."
  (let ((pool (history-cache-payload-pool hc))
        (buf (cache-change-pooled-buffer change)))
    (when (and pool buf
               (cache-change-evicted change)
               (cache-change-releasable-p change))
      (dds.core.arena:pool-release pool buf)
      (setf (cache-change-pooled-buffer change) nil)))
  t)

(defun* hc-try-release-pinned (hc change)
    (function (history-cache cache-change) t)
  "WP-ACKED-SLOT-PINNING (FR-PF-4, R6, ADR 0044; NOT cleared for ship — pending counsel). Release CHANGE's TX
   PIN hold on its Zero-Copy slot iff the release is DUE — the ONE-SHOT, refcount-gated pin-release predicate, the
   exact STRUCTURAL SIBLING of hc-try-release-pooled: released ONLY when ALL of (i) CHANGE is ZC-PINNED, (ii) HC
   has a ZC-RELEASE-FN installed (a pinning writer), (iii) CHANGE has been EVICTED from the cache, and (iv) CHANGE
   has NO outstanding send-ref (CACHE-CHANGE-RELEASABLE-P, SEND-REFCOUNT 0). Conditions (iii)+(iv) are the SAME
   defer-gate the pooled path uses and are load-bearing for the SAME reason: a captured send build-thunk may still
   RESOLVE the pinned slot BY REFERENCE (%ensure-change-payload reads the live slot), so the pin — which keeps the
   slot's generation frozen + refcount>0 — must OUTLIVE any in-flight/deferred send-ref, or the slot could be
   reclaimed + generation-bumped under a concurrent resolve (a stale resolve then returns NIL — a best-effort
   dropped datagram, never wrong bytes; but the pin must not race it, ADR 0044 §5). So a change EVICTED while
   send-referenced DEFERS its pin release to the LAST send-ref drop, exactly like the pooled buffer: this is
   retried from BOTH triggers that can make it due — the eviction choke (%hc-remove-change, which sets EVICTED) and
   the last send-ref drop (writer-release-change-ref / -refs). On a due release, flip ZC-PINNED T->NIL (so a second
   call is a validated no-op — idempotent, mirroring the floored ref-release) and funcall the release-fn with
   (ZC-SLOT, ZC-GENERATION), which %zc-releases the pin hold (refcount--, one of the two distinct holds — whichever
   reaches 0 LAST frees the slot) and decrements the live pin budget. Fires for the full-ACK purge, the KEEP_LAST
   early eviction, and dispose — every drop site — exactly once (ADR 0044 §4.4). MUST run under the owning writer's
   lock (the same lock ZC-STATE + EVICTED + SEND-REFCOUNT are mutated under) so the due-check cannot race a
   concurrent acquire/release/eviction; the release-fn itself takes NO lock (a lock-free %zc-release + an
   atomic-cell decrement), so there is no lock-ordering hazard. Inert (no-op) when the change is not pinned or no
   release-fn is installed — byte- and behaviour-identical to before."
  (when (and (cache-change-zc-pinned change)
             (history-cache-zc-release-fn hc)
             (cache-change-evicted change)
             (cache-change-releasable-p change))
    (setf (cache-change-zc-pinned change) nil)
    (funcall (history-cache-zc-release-fn hc)
             (cache-change-zc-slot change) (cache-change-zc-generation change)))
  t)

(defun* %reset-cache-change (c)
    (function (cache-change) cache-change)
  "Reset EVERY slot of C to its make-cache-change default, so a recycled struct (hc-take-change) is
   indistinguishable from a fresh one before the fill-helper sets the sample's slots (TASK-3, ADR 0077). This
   MUST list all 17 slots — a missed slot would carry stale state (e.g. a stale EVICTED, ZC-SLOT, or
   SEND-REFCOUNT) into the next change and corrupt it. Kept adjacent to the defstruct so the two stay in sync."
  (setf (cache-change-kind c) :data
        (cache-change-writer-guid c) nil
        (cache-change-sn c) 0
        (cache-change-instance-key-hash c) nil
        (cache-change-serialized-payload c) nil
        (cache-change-status-info c) 0
        (cache-change-source-timestamp c) 0
        (cache-change-inline-qos c) nil
        (cache-change-send-refcount c) 0
        (cache-change-pooled-buffer c) nil
        (cache-change-pooled-len c) nil
        (cache-change-evicted c) nil
        (cache-change-zc-slot c) -1
        (cache-change-zc-generation c) 0
        (cache-change-zc-state c) nil
        (cache-change-zc-pinned c) nil
        (cache-change-zc-len c) nil)
  c)

(defun* hc-take-change (hc)
    (function (history-cache) cache-change)
  "A cache-change to fill for a new sample: pop one from HC's change-freelist and reset it to defaults if any,
   else allocate fresh (TASK-3, ADR 0077 — zero per-sample struct alloc once the freelist warms). The
   fill-helper (hc-data-change / hc-lifecycle-change) then sets the sample's slots. MUST run under the owning
   writer's lock (the freelist is writer-owned)."
  (let ((c (pop (history-cache-change-freelist hc))))
    (if c (%reset-cache-change c) (make-cache-change))))

(defparameter *hc-change-freelist-cap* 64
  "Upper bound on a HistoryCache's recycled cache-change freelist (TASK-3, ADR 0077): a change due for recycle
   past the cap is left to the GC rather than pooled, so a burst (a deep KEEP_ALL backlog draining at once)
   cannot grow the freelist without bound. 64 comfortably covers KEEP_LAST + a typical KEEP_ALL working set;
   pinned to no spec constant (a local pooling policy).")

(defun* hc-try-recycle-change (hc change)
    (function (history-cache cache-change) t)
  "Return CHANGE to HC's change-freelist for reuse iff the recycle is DUE — the struct-pool sibling of
   hc-try-release-pooled/-pinned (TASK-3, ADR 0077, NFR-MEM), called from the SAME two triggers (the eviction
   choke %hc-remove-change and the last send-ref drop writer-release-change-ref/-refs). Recycled ONLY when ALL
   hold: CHANGE is EVICTED, has NO outstanding send-ref (releasable-p, SEND-REFCOUNT 0), is NOT ZC-armed /
   pooled / pinned (a ZC-armed change is ALSO held by the disc leak-sweep, a pooled change by its payload-pool,
   a pinned change by its slot — references BEYOND send-refcount, so those keep allocating), and the freelist is
   below its cap. Clears EVICTED on push so a second call from the other trigger is a validated no-op (the
   struct is now freelist-owned; hc-take-change resets it fully before reuse). MUST run under the owning
   writer's lock (the same lock EVICTED + SEND-REFCOUNT + the freelist are mutated under). No allocation."
  (when (and (cache-change-evicted change)
             (cache-change-releasable-p change)
             (< (cache-change-zc-slot change) 0)          ; not ZC-armed (no disc leak-sweep retention)
             (null (cache-change-pooled-buffer change))   ; not payload-pooled
             (not (cache-change-zc-pinned change))        ; not slot-pinned
             (< (length (history-cache-change-freelist hc)) *hc-change-freelist-cap*))
    (setf (cache-change-evicted change) nil)              ; idempotency: freelist-owned now -> the gate cannot re-fire
    (push change (history-cache-change-freelist hc)))
  t)

(defun* hc-data-change (hc sn payload key-hash inline-qos pooled-buffer pooled-len zc-slot zc-gen zc-pinned zc-len)
    (function (history-cache (integer 0) (or null (array (unsigned-byte 8) (*)))
              (or null (array (unsigned-byte 8) (*))) (or null (simple-array (unsigned-byte 8) (*)))
              (or null dds.core.buffer:octet-buffer) (or null (integer 0)) (or null (integer 0))
              (unsigned-byte 32) t (or null (integer 0)))
              cache-change)
  "A filled :data cache-change (SN + PAYLOAD + key/qos/pool/ZC slots), drawn from HC's change-freelist when one
   is available (TASK-3, ADR 0077 — zero per-sample struct alloc on the common write path), else fresh. Because
   hc-take-change fully resets a recycled struct, the result is byte-for-byte identical to the make-cache-change
   this replaced (KIND :data, writer-guid/status-info/source-timestamp at their defaults). MUST run under the
   owning writer's lock."
  (let ((c (hc-take-change hc)))
    (setf (cache-change-sn c) sn
          (cache-change-serialized-payload c) payload
          (cache-change-instance-key-hash c) key-hash
          (cache-change-inline-qos c) inline-qos
          (cache-change-pooled-buffer c) pooled-buffer
          (cache-change-pooled-len c) pooled-len
          (cache-change-zc-slot c) (or zc-slot -1)
          (cache-change-zc-generation c) zc-gen
          (cache-change-zc-state c) (and zc-slot :armed)
          (cache-change-zc-pinned c) (and zc-pinned t)
          (cache-change-zc-len c) zc-len)
    c))

(defun* hc-lifecycle-change (hc sn kind key-hash status-info inline-qos source-timestamp)
    (function (history-cache (integer 0) (member :data :dispose :unregister)
              (simple-array (unsigned-byte 8) (*)) (unsigned-byte 8)
              (or null (simple-array (unsigned-byte 8) (*))) integer)
              cache-change)
  "A filled dispose/unregister cache-change (no serializedPayload — the instance is identified by KEY-HASH),
   drawn from HC's change-freelist when available (TASK-3, ADR 0077), else fresh. Byte-for-byte identical to the
   make-cache-change it replaced. MUST run under the owning writer's lock."
  (let ((c (hc-take-change hc)))
    (setf (cache-change-sn c) sn
          (cache-change-kind c) kind
          (cache-change-instance-key-hash c) key-hash
          (cache-change-status-info c) status-info
          (cache-change-inline-qos c) inline-qos
          (cache-change-source-timestamp c) source-timestamp)
    c))

(declaim (ftype (function (history-cache fixnum) t) %hc-extent-dropped))   ; defined below; the removal choke maintains the O(1) SN extent

(defun* %hc-remove-change (hc seqnum)
    (function (history-cache integer) t)
  "The single change-removal path: drop SEQNUM from BOTH the change table and its per-instance
   index bucket, decrementing the count, so the two never drift (ADR 0019). Return T if one was
   present. Used by KEEP_LAST eviction, the full-ACK purge (writer-purge-acked), and dispose. For a POOLED
   secured-payload change (T5a) this is the eviction trigger of the operating contract §4 release-safety: it marks
   the change EVICTED and calls hc-try-release-pooled, which returns the buffer to the pool NOW iff no send still
   references it (SEND-REFCOUNT 0), otherwise DEFERS the release to the last ref drop. Inert for a non-pooled
   change — byte-identical."
  (let ((change (gethash seqnum (history-cache-changes hc))))
    (when change
      (remhash seqnum (history-cache-changes hc))
      (%hc-index-drop hc seqnum change)
      (decf (history-cache-count hc))
      (%hc-extent-dropped hc (the fixnum seqnum))   ; O(1) unless the removed SN WAS an endpoint (then one rescan)
      (setf (cache-change-evicted change) t)   ; gate the (possibly deferred) pooled-buffer release
      (hc-try-release-pooled hc change)         ; release NOW if releasable, else defer to the last send-ref drop (T5a)
      (hc-try-release-pinned hc change)         ; WP-ACKED-SLOT-PINNING: release the TX pin hold on a pinned change (one-shot, ADR 0044)
      (hc-try-recycle-change hc change)         ; TASK-3 (ADR 0077): recycle the struct NOW if releasable, else defer to the last send-ref drop
      t)))

(defun* hc-remove-change (hc seqnum)
    (function (history-cache integer) t)
  "Remove the change with SEQNUM; return T if one was present. Routes through %HC-REMOVE-CHANGE so
   the per-instance index stays consistent with the change table (ADR 0019)."
  (%hc-remove-change hc seqnum))

(defun* hc-purge-below (hc base)
    (function (history-cache integer) (integer 0))
  "Remove every change with SN < BASE (fully acknowledged + done); return the number removed. O(stored),
   no sort — bounds a KEEP_ALL writer history once all matched readers have ACKed past BASE (RTPS 2.5
   §8.4.1). Routes each removal through %HC-REMOVE-CHANGE so the per-instance index stays consistent (ADR
   0019). The HEARTBEAT firstSN (hc-min-seq) then advances past the purged range."
  (let ((removed '()))
    (maphash (lambda (sn ch) (declare (ignore ch)) (when (< sn base) (push sn removed)))
             (history-cache-changes hc))
    (dolist (sn removed (length removed))
      (%hc-remove-change hc sn))))

(defun* %hc-rescan-extent (hc)
    (function (history-cache) t)
  "Recompute the stored-SN extent by a full scan — the SLOW path, taken ONLY when the change just removed
   was itself the current min or max (so the extent genuinely has to be re-derived). Every other removal,
   and every insert, keeps the extent in O(1). An empty cache resets to 0/0."
  (let ((min 0) (max 0))
    (declare (type fixnum min max))
    (maphash (lambda (sn ch)
               (declare (ignore ch) (type fixnum sn))
               (when (or (zerop min) (< sn min)) (setf min sn))
               (when (> sn max) (setf max sn)))
             (history-cache-changes hc))
    (setf (history-cache-min-seq hc) min
          (history-cache-max-seq hc) max))
  t)

(defun* %hc-extent-dropped (hc sn)
    (function (history-cache fixnum) t)
  "Maintain the stored-SN extent after SN was removed. O(1) in the common case: a purge removes the LOWEST
   SNs (hc-purge-below) and KEEP_LAST evicts the oldest, so the removed SN is usually the min — and the new
   min is not knowable without a scan, so we rescan only then. A removal from the interior touches neither
   endpoint and costs nothing."
  (cond ((zerop (history-cache-count hc))            ; emptied
         (setf (history-cache-min-seq hc) 0 (history-cache-max-seq hc) 0))
        ((or (= sn (history-cache-min-seq hc))
             (= sn (history-cache-max-seq hc)))
         (%hc-rescan-extent hc)))
  t)

(defun* hc-min-seq (hc)
    (function (history-cache) t)
  "Lowest sequence number present, or NIL if empty. O(1) — read from the incrementally-maintained extent
   (was a full maphash scan; it is called on the WRITE path for every HEARTBEAT's firstSN)."
  (let ((n (history-cache-min-seq hc)))
    (if (zerop n) nil n)))

(defun* hc-max-seq (hc)
    (function (history-cache) t)
  "Highest sequence number present, or NIL if empty. O(1) — read from the incrementally-maintained extent
   (was a full maphash scan; it is called on the WRITE path for every HEARTBEAT's lastSN)."
  (let ((n (history-cache-max-seq hc)))
    (if (zerop n) nil n)))

(defun* %hc-store (hc sn change)
    (function (history-cache integer cache-change) (integer 0))
  "Insert CHANGE under sequence number SN into the change table, bumping the count, and append SN to
   its per-instance index bucket (KEEP_LAST only — %hc-index-append no-ops for KEEP_ALL); returns
   the new count."
  (setf (gethash sn (history-cache-changes hc)) change)
  (%hc-index-append hc sn change)
  (let ((n (the fixnum sn)))                       ; O(1) extent maintenance (see the min-seq/max-seq slot comment)
    (when (or (zerop (history-cache-min-seq hc)) (< n (history-cache-min-seq hc)))
      (setf (history-cache-min-seq hc) n))
    (when (> n (history-cache-max-seq hc))
      (setf (history-cache-max-seq hc) n)))
  (incf (history-cache-count hc)))

(defun* hc-add-change (hc change)
    (function (history-cache cache-change) (values symbol (or null integer)))
  "Add CHANGE, enforcing HISTORY + RESOURCE_LIMITS (FR-RTPS-5). Returns :OK,
   :DUPLICATE (SN already present), or :REJECTED-RESOURCE-LIMITS (KEEP_ALL at
   max_samples). KEEP_LAST keeps the last DEPTH values PER INSTANCE (DDS 1.4 §2.2.3.18):
   when CHANGE's instance is at depth, its OWN oldest SN is evicted (a NIL/HANDLE_NIL
   keyhash collapses to one bucket = global KEEP_LAST).

   The SECOND value is the SN this add EVICTED, or NIL if it evicted nothing (ADR 0089). Only the
   KEEP_LAST branch can evict. It is returned rather than counted here because whether an eviction
   destroyed UNACKNOWLEDGED data is a WRITER question — it depends on the acked watermark across matched
   readers, which a HistoryCache has no view of — and because this file is hot-path (NFR-MEM): an extra
   value costs nothing, whereas a callback or a status reference here would put allocation and
   cross-layer coupling on the per-sample write path. Callers reading a single value are unaffected."
  (let ((sn (cache-change-sn change)))
    (cond
      ((nth-value 1 (gethash sn (history-cache-changes hc))) (values :duplicate nil))
      ((eq (history-cache-kind hc) :keep-last)
       (%hc-store hc sn change)
       (let ((bucket (gethash (%hc-bucket-key (cache-change-instance-key-hash change))
                              (history-cache-instances hc)))
             (evicted nil))
         (when (> (length bucket) (history-cache-depth hc))
           (setf evicted (first bucket))
           (%hc-remove-change hc evicted))                       ; evict this instance's oldest, not the global oldest
         (values :ok evicted)))
      (t
       (if (and (history-cache-max-samples hc)
                (>= (history-cache-count hc) (history-cache-max-samples hc)))
           (values :rejected-resource-limits nil)
           (progn (%hc-store hc sn change) (values :ok nil)))))))

(defun* hc-changes-from (hc base)
    (function (history-cache integer) list)
  "The cache changes with SN >= BASE, in ascending SN order. THE SEND-PATH QUERY — this is what the reliable
   writer actually asks for on every push (%changes-from), and it is O(changes-to-send), normally ONE.

   WP-PERF: it replaces (a full maphash of the cache) + (a STABLE-SORT of the whole change list) + (a filter
   down to the suffix), which ran on EVERY WRITE. The sampling profile of write-sample was unambiguous —
   HC-CHANGES-FOR-READER 14% self, STABLE-SORT-LIST 52.8% CUMULATIVE, plus MERGE-LISTS*, generic < and
   TWO-ARG-< — together over half the send path, sorting the entire history cache in order to take a suffix
   of it. Under RELIABLE/KEEP_ALL the cache grows until the reader ACKs, so the sort grew with it: the same
   class of defect as the receive-side quadratic drain (46aa047) — re-deriving sorted state from scratch on
   every operation.

   The changes are stored under a monotone SN (RTPS 2.5 SS8.3.5.4), and the [min-seq, max-seq] extent is
   maintained incrementally, so ascending order needs no sort at all: walk the extent DOWNWARD from max-seq
   and PUSH, which yields ascending order directly. Holes (KEEP_LAST eviction) cost one failed GETHASH each
   and cons nothing. Starting at (max BASE min-seq) means an ACKed prefix is never even visited."
  (let ((hi (history-cache-max-seq hc)))
    (when (zerop hi) (return-from hc-changes-from '()))          ; empty cache (0 = empty; a valid SN is >= 1)
    (let ((lo (max base (history-cache-min-seq hc)))
          (tbl (history-cache-changes hc))
          (out '()))
      (loop for sn of-type fixnum from hi downto lo              ; downward + push => ascending, no sort
            do (let ((ch (gethash sn tbl)))
                 (when ch (push ch out))))
      out)))

(defun* hc-changes-for-reader (hc reader-proxy)
    (function (history-cache t) list)
  "ALL cache changes in ascending SN order. v1 ignores READER-PROXY; the per-reader changes-for-reader
   filtering lives in the reliable writer.

   NOT ON THE SEND PATH — the send path wants HC-CHANGES-FROM (a suffix), and using this for it meant sorting
   the whole cache on every write. This whole-cache form is retained for the tests/tools that genuinely want
   every change. Same result, expressed as the full-extent case of the range query (DRY, no second sort)."
  (declare (ignore reader-proxy))
  (hc-changes-from hc (let ((n (history-cache-min-seq hc))) (if (zerop n) 0 n))))
