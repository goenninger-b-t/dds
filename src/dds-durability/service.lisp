(in-package #:dds.durability)

;;; Task 4+5 — durability-service collect + replay path (ADR 0021 slice 2, WP-DURABILITY-SERVICE-TRANSIENT).
;;; Replay model: publish-on-collect.  Each sample the collect loop stores is IMMEDIATELY re-published
;;; through the service's own TRANSIENT_LOCAL KEEP_ALL writer.  That writer's HistoryCache mirrors the
;;; store; the existing TL retention + late-joiner replay machinery (%writer-durability-init, HEARTBEAT /
;;; ACKNACK retransmit) delivers the full pre-join history to any subsequently-discovered TL reader,
;;; even after the ORIGINAL writer is gone.  The service writer publishes under ITS OWN GUID + SNs;
;;; no new wire format is required.  The no-double-delivery case (original writer still alive) is
;;; Phase 2 (virtual-GUID / identity carrier) — do NOT implement here.
;;; MVP scope (Phase 1):
;;;   - ONE topic per service node: the spec's first explicit (topic . type) cons.
;;;     Multi-topic-per-service is a documented Phase-1 follow-up.
;;;   - DATA-kind samples only; :dispose/:unregister capture is a documented limitation
;;;     (the poll API exposes payloads, not change-kind).
;;;   - A predicate-only spec with no concrete (topic . type) signals at service-start.

;;; --- fault injection (test-only, inert by default) ---

(defparameter *durability-debug-start-fault* nil
  "Test-only fault injector. NIL (default) = inert; byte-identical behavior.
   When non-NIL, SERVICE-START raises a condition immediately after building the disc node,
   simulating a service that dies on startup (used by the crash-loop shed sub-test). Never set
   in production code.")

;;; --- error hook ---

(defun* %durability-error-count-p (n)
    (function ((integer 1)) t)
  "T iff N is a positive power of ten: rate-limits the default error hook to O(log n) lines."
  (loop for x of-type (integer 1) = n then (truncate x 10)
        when (= x 1) return t
        when (plusp (mod x 10)) return nil))

(defun* %default-durability-error-hook (condition context count)
    (function (condition t (integer 1)) t)
  "Default *DURABILITY-ERROR-HOOK*: clockless rate-limited WARN to *ERROR-OUTPUT* when COUNT is
   a power of ten (1, 10, 100, …). Mirrors the shape of dds.disc::%default-sender-emit-error-hook."
  (when (%durability-error-count-p count)
    (warn "dds.durability collect loop (~a) error #~d: ~a" context count condition))   ; NOCOND(WARN): rate-limited diagnostic; returns normally, no control transfer
  t)

(defparameter *durability-error-hook* #'%default-durability-error-hook
  "Funcallable (CONDITION CONTEXT COUNT) invoked when the collect loop's per-iteration
   handler-case catches an ERROR. CONTEXT tags the call site (keyword); COUNT is the
   running error tally (>= 1). Runs on the collect thread — MUST NOT block. A signalling
   hook is itself swallowed (ignore-errors). Bind to observe collect-loop errors.
   Default = %DEFAULT-DURABILITY-ERROR-HOOK.")

;;; --- discovery-driven auto-serve poll cadence (ADR 0026 dynamic-topic-add Phase-2b) ---

(defparameter *durability-auto-discover-interval* 0.25
  "Seconds the :auto-discover discovery-poll thread sleeps between scans of the discovery node's
   discovered-writers list (control-plane, off the wire hot path). Read once per iteration; lower for
   snappier auto-serve reactivity, higher to reduce idle wakeups. Only consulted when a service-spec has
   AUTO-DISCOVER set — the default fixed-set service spawns no poll thread and never reads it.")

;;; --- durability-service struct ---

(defstruct* (durability-service (:constructor %make-durability-service))
  "Embedded TRANSIENT durability collect service (ADR 0021 slice 2, Phase 2).
   Owns K disc-nodes (one per resolved topic in SPEC); each node has a reliable
   TRANSIENT_LOCAL KEEP_ALL collecting reader + a replay writer + a dedicated collect thread.
   NODES is a list of (node . thread) pairs (K=1 is byte-identical to Phase 1).
   NODE and THREAD are kept for backward compat (process-mode proxy in runner.lisp) and
   single-arity accessor callers; they mirror the first element of NODES after service-start.
   TOPIC-NAMES is an :equal hash-table of registered topic-name strings; guards idempotency in
   service-add-topic by name (time-stable) rather than by the time-varying GUID prefix.
   DISCOVERY-NODE + DISCOVERY-THREAD are populated ONLY when (service-spec-auto-discover spec): a bare
   discovery disc-node (SPDP/SEDP, no user endpoints) and the poll thread that scans it and auto-adds
   matching unconfigured topics via service-add-topic. Both NIL for a fixed-set service (no observable change when off)."
  (spec        nil :type (or null service-spec))
  (store       nil :type (or null durable-store))
  (node        nil :type t)
  (thread      nil :type t)
  (nodes       nil :type list)
  (topic-names (make-hash-table :test #'equal) :type hash-table)
  (lock        (dds.pal:make-lock "dds-durability-service") :type t)
  (running     nil :type t)
  ;; :auto-discover only (NIL for a fixed-set service, no observable change when off): a bare SPDP/SEDP discovery node +
  ;; its poll thread, spun at service-start and torn down at service-stop (ADR 0026 dynamic-topic Phase-2b)
  (discovery-node   nil :type t)
  (discovery-thread nil :type t))


;;; --- construction ---

(defun* make-durability-service (spec &key store)
    (function (service-spec &key (:store (or null durable-store))) durability-service)
  "Construct a DURABILITY-SERVICE for SPEC. STORE overrides the spec's store factory
   (pass a shared store in tests); when NIL the factory (service-spec-store spec) is called.
   The service is not started until SERVICE-START is called."
  (let ((s (or store (funcall (service-spec-store spec)))))
    (%make-durability-service :spec spec :store s)))

;;; --- topic resolution ---

(defun* %service-topics (spec)
    (function (service-spec) list)
  "Return the list of (topic-name . type-name) conses to build INITIAL nodes for.
   List form: returns the explicit list directly (must be non-empty unless :auto-discover).
   Predicate form: error UNLESS :auto-discover — a predicate cannot enumerate concrete topics at start
   time; supply an explicit (topic . type) list, or set :auto-discover so discovery drives the adds.
   Empty list: error UNLESS :auto-discover — at least one (topic . type) is required.
   :auto-discover (ADR 0026 Phase-2b) relaxes the non-empty/predicate rejection: an empty or predicate
   start-list returns '() (serve nothing initially; the discovery poll auto-adds matching topics). A
   non-empty concrete list is still honored as the initial set. A non-empty MALFORMED list (not conses)
   still errors even under :auto-discover. When :auto-discover is NIL (default) there is no observable change (the added branch is dead when off)."
  (let ((f    (service-spec-topics spec))
        (auto (service-spec-auto-discover spec)))
    (etypecase f
      (list
       (cond
         ((and (consp f) (consp (car f))) f)   ; valid non-empty concrete start-list
         ((and auto (null f)) '())              ; :auto-discover + empty: serve nothing initially
         (t (error "dds.durability: service-spec has no explicit (topic . type) cons — ~
                    at least one concrete (topic . type) is required"))))
      (function
       (cond
         (auto '())                             ; :auto-discover + predicate: no initial nodes; discovery drives adds
         (t (error "dds.durability: service-spec topics is a predicate — cannot enumerate ~
                    concrete topics at service-start (supply an explicit (topic . type) list; ~
                    dynamic topic-add after start is a documented deferral per design §6)")))))))

;;; --- GUID prefix for the collect node ---

(defun* %collect-node-prefix (spec &optional topic-name)
    (function (service-spec &optional (or null string)) (simple-array (unsigned-byte 8) (12)))
  "Build a 12-byte GUID prefix for one collect node: 'DS' + spec-name hash XOR topic hash + wall clock.
   TOPIC-NAME is mixed in so two nodes in the same multi-topic service get distinct prefixes.
   The wall-clock component makes the prefix TIME-VARYING: do NOT use for idempotency checks.
   Demo-grade (not vetted UUID)."
  (let ((p (make-array 12 :element-type '(unsigned-byte 8) :initial-element 0))
        (clk (get-universal-time))
        (nh  (logxor (sxhash (service-spec-name spec))
                     (if topic-name (sxhash topic-name) 0))))
    (setf (aref p 0) #x44 (aref p 1) #x53)           ; 'D' 'S'
    (loop for i from 2 below 6
          do (setf (aref p i) (logand (ash nh (* -8 (- i 2))) #xff)))
    (loop for i from 6 below 12
          do (setf (aref p i) (logand (ash clk (* -8 (- i 6))) #xff)))
    p))

;;; --- per-origin collect dedup (bounded watermark, mirrors ADR 0024) ---
;;;
;;; Each seen-origins table maps GUID (equalp) -> (cons LO ABOVE-HT) where LO is the
;;; contiguous high-water SN (every SN <= LO is known-delivered) and ABOVE-HT maps
;;; integer SN -> T for out-of-order entries above LO.  Bounded: ABOVE-HT grows at most
;;; *max-gap-range* entries per GUID; pruning after watermark advance keeps memory O(live
;;; origins * *max-gap-range*), not O(total samples delivered).

(defparameter *max-collect-origins* 4096
  "NFR-MEM resource limit (ADR 0024 §non-goals, ADR 0025 §10.2): the maximum number of DISTINCT
   origin GUIDs tracked in one collect seen-set. The per-SN growth per origin is already bounded
   (LO watermark + *max-gap-range* above-set); this bounds the number of ORIGIN ENTRIES, whose
   growth over a long-lived service (each departed writer leaves a per-GUID entry) was the residual
   unbounded dimension. AT CAP, a sample from a NEW (untracked) origin is REFUSED (RESOURCE_LIMITS
   fail-closed backpressure — not stored, not relayed) rather than EVICTING a tracked origin's LO
   watermark: eviction is UNSAFE here because a later late-joining relay can replay the evicted
   origin's OLD samples, and a forgotten watermark would re-admit them = double-delivery regression
   (the ADR 0024 dedup trap). A tracked origin is ALWAYS admitted, so no watermark is ever lost.
   Generous default; raise it if a deployment legitimately has more concurrent origins.")

(defun* %make-collect-origins ()
    (function () hash-table)
  "Return a fresh per-origin dedup table (GUID equalp -> (lo . above-ht))."
  (make-hash-table :test #'equalp))

(defun* %collect-admit-p (origins guid)
    (function (hash-table (simple-array (unsigned-byte 8) (*))) t)
  "T iff a sample from origin GUID may be admitted into ORIGINS. A GUID that ALREADY has an entry
   (tracked origin) is always admitted (its watermark is intact). A NEW origin is admitted only
   while the table is below *MAX-COLLECT-ORIGINS*. NIL only for a NEW origin at cap — the caller
   then REFUSES the sample (fail-closed) rather than evicting a tracked origin's LO watermark,
   which would risk double-delivery on a later relay replay (ADR 0024 dedup trap / §10.2)."
  (or (nth-value 1 (gethash guid origins))
      (< (hash-table-count origins) *max-collect-origins*)))

(defun* %collect-seen-p (origins guid sn)
    (function (hash-table (simple-array (unsigned-byte 8) (*)) integer) t)
  "T iff (GUID SN) is already delivered per ORIGINS (below or equal to watermark, or in above-set)."
  (let ((entry (gethash guid origins)))
    (and entry
         (or (<= sn (car entry))
             (if (gethash sn (cdr entry)) t nil)))))

(defun* %collect-mark-seen! (origins guid sn)
    (function (hash-table (simple-array (unsigned-byte 8) (*)) integer) integer)
  "Record (GUID SN) as delivered in ORIGINS; advance watermark LO through the contiguous
   prefix; prune all ABOVE-HT entries <= new LO so the set stays bounded.
   At-cap (above-ht count > *max-gap-range*) drops the highest above-ht entry to enforce
   the bound — benign for the high out-of-order entry (if it re-arrives it is re-admitted);
   lo never advances past an un-arrived SN so silent loss cannot occur (ADR 0024 §Decision).
   Returns the updated LO for GUID after compaction."
  (let* ((entry (or (gethash guid origins)
                    (let ((e (cons 0 (make-hash-table :test #'eql))))
                      (setf (gethash guid origins) e)
                      e)))
         (lo   (car entry))
         (above (cdr entry)))
    ;; add to above-set if above watermark (never insert <= lo)
    (when (> sn lo)
      (setf (gethash sn above) t))
    ;; at-cap: shed the highest above-set entry (NFR-MEM hard bound)
    (when (> (hash-table-count above) dds.rtps.reliable:*max-gap-range*)
      (let ((hi-key (let ((m lo))
                      (maphash (lambda (k _) (declare (ignore _)) (when (> k m) (setf m k))) above)
                      m)))
        (remhash hi-key above)))
    ;; advance watermark through the contiguous run
    (loop while (gethash (1+ lo) above)
          do (incf lo)
             (remhash lo above))
    (setf (car entry) lo)
    ;; prune any residual below-lo entries from above-set
    (when (plusp lo)
      (maphash (lambda (k _)
                 (declare (ignore _))
                 (when (<= k lo)
                   (remhash k above)))
               above))
    lo))

(defun* %collect-origins-above-size (origins)
    (function (hash-table) integer)
  "Return the total number of entries in all ABOVE-HT tables across all origins in ORIGINS.
   Used by the test harness to assert boundedness (must stay <= *max-gap-range* + small constant)."
  (let ((total 0))
    (maphash (lambda (_ entry)
               (declare (ignore _))
               (incf total (hash-table-count (cdr entry))))
             origins)
    total))

;;; --- collect loop ---

(defun* %collect-loop (svc node topic-name)
    (function (durability-service t string) t)
  "Collect + replay thread body for one disc-node / topic pair.
   Polls NODE for new (GUID . SN) data + lifecycle keys, drains each into the store, and
   IMMEDIATELY re-publishes through the service writer (publish-on-collect model). Lifecycle
   changes (:dispose/:unregister) are stored with their kind and re-emitted via
   publish-relay-lifecycle with PID_ORIGINAL_WRITER_INFO. Tracks seen keys per-origin-GUID
   with a bounded watermark (ADR 0024 carry-forward, NFR-MEM).
   Sleeps ~5 ms between polls. Re-announces SPDP + SEDP every ~1.5 s (RTPS 2.5 §8.5.3.3).
   Wraps each iteration in handler-case so a transient error fires *DURABILITY-ERROR-HOOK*."
  (let ((origins-data (%make-collect-origins))
        (origins-lc   (%make-collect-origins))
        (error-count 0)
        (store (durability-service-store svc))
        (last-announce 0))
    (loop
      (unless (dds.pal:with-lock ((durability-service-lock svc))
                (durability-service-running svc))
        (return))
      (handler-case
          (let ((now (get-internal-real-time)))
            (when (> (- now last-announce)
                     (round (* 1.5 internal-time-units-per-second)))
              (dds.disc:announce-participant node)
              (dds.disc:announce-endpoints node)
              (setf last-announce now))
            ;; drain data samples — dedup/store/relay on the LOGICAL origin (OWI else wire)
            (dolist (key (dds.disc:node-sample-sns node))
              (let* ((writer-guid (dds.disc:node-sample-writer-guid node key))
                     (origin-guid (dds.disc:node-sample-origin-guid node key))  ; logical origin (OWI else wire)
                     (origin-sn   (dds.disc:node-sample-origin-sn   node key)))
                (when (and writer-guid
                           (not (%collect-seen-p origins-data origin-guid origin-sn))
                           ;; at cap, a NEW origin is refused (fail-closed) — never evict a tracked
                           ;; origin's watermark (would risk double-delivery, ADR 0024 §10.2)
                           (%collect-admit-p origins-data origin-guid))
                  (%collect-mark-seen! origins-data origin-guid origin-sn)
                  (let ((payload (dds.disc:node-sample node key)))
                    (when payload
                      (let ((kh (dds.disc:node-sample-key-hash node key))) ; wire PID_KEY_HASH (RTPS 2.5 §9.6.4.8)
                        (store-put store topic-name origin-guid origin-sn kh :data payload)
                        (dds.disc:publish-relay-sample node payload origin-guid origin-sn)))))))
            ;; drain lifecycle changes (dispose / unregister)
            ;; key = (writer-guid . sn); dedup on (writer-guid, sn) via origins-lc watermark
            (dolist (key (dds.disc:node-lifecycle-sns node))
              (let* ((key-guid (car key))
                     (key-sn  (cdr key)))
                (when (and (not (%collect-seen-p origins-lc key-guid key-sn))
                           (%collect-admit-p origins-lc key-guid)) ; cap origins-lc too (ADR 0024 §10.2)
                  (%collect-mark-seen! origins-lc key-guid key-sn)
                  (let ((lc (dds.disc:node-lifecycle-change node key)))
                    (when lc
                      (let* ((kind         (first  lc))
                             (key-hash     (second lc))
                             (status-flags (third  lc))
                             (orig-guid    (fifth  lc))
                             (orig-sn      key-sn)
                             (kh16 (if (and key-hash
                                            (= 16 (length key-hash)))
                                       (coerce key-hash '(simple-array (unsigned-byte 8) (16)))
                                       (make-array 16 :element-type '(unsigned-byte 8)
                                                      :initial-element 0))))
                        (store-put store topic-name orig-guid orig-sn kh16 kind
                                   (make-array 0 :element-type '(unsigned-byte 8)))
                        (dds.disc:publish-relay-lifecycle
                         node kh16 status-flags orig-guid orig-sn))))))))
        (error (c)
          (let ((n (incf error-count)))
            (ignore-errors
             (funcall *durability-error-hook* c :collect-loop n)))))
      ;; group-commit: fsync all open log streams once per drain tick. A sync failure is SURFACED
      ;; via the error hook (not silently swallowed) so a failing disk is observable; the thread
      ;; survives (a transient fsync error must not kill the collect loop) — fail-closed + alive.
      (handler-case (store-sync store)
        (error (c)
          (let ((n (incf error-count)))
            (ignore-errors (funcall *durability-error-hook* c :group-commit n)))))
      (sleep 0.005)))
  t)

;;; --- pre-seed the replay writer from the store on restart ---

(defun* %seed-relay-from-store (node store topic-name)
    (function (dds.disc:disc-node durable-store string) t)
  "Pre-publish all existing records for TOPIC-NAME from STORE through NODE's replay writer.
   Called during service-start after store-open so retained history (e.g. from a prior
   run on disk) populates the TL+KEEP_ALL writer's cache before any late-joiner connects.
   No-op when the store has no records for the topic. The in-memory store is always empty
   at this point, so this is a true no-op for the TRANSIENT tier (byte-identical).
   :timeout from publish-relay-sample/publish-relay-lifecycle: structurally impossible at
   realistic seed volumes. The replay writer is TL+KEEP_ALL with no resource limit on its
   HistoryCache, and during seed-relay there is no matched reader yet so no RTPS sends
   occur — data goes directly into the local history cache without any socket interaction.
   A socket-send timeout cannot trigger without a connected reader, and cache capacity is
   unbounded (KEEP_ALL). The :timeout handler here is a backstop for unforeseen conditions;
   it has never been observed in testing and is not expected to occur. Any other ERROR is
   also routed to *durability-error-hook*."
  (let ((error-count 0))
    (dolist (r (store-get-range store topic-name))
      (let ((result
             (handler-case
                 (if (eq (durable-record-kind r) :data)
                     (dds.disc:publish-relay-sample node
                                                    (durable-record-payload r)
                                                    (durable-record-writer-guid r)
                                                    (durable-record-sn r))
                     (let* ((kh   (or (durable-record-key-hash r)
                                      (make-array 16 :element-type '(unsigned-byte 8)
                                                     :initial-element 0)))
                            (kh16 (coerce kh '(simple-array (unsigned-byte 8) (16))))
                            (sf   (ecase (durable-record-kind r)
                                    (:dispose     1)
                                    (:unregister  2))))
                       (dds.disc:publish-relay-lifecycle node kh16 sf
                                                         (durable-record-writer-guid r)
                                                         (durable-record-sn r))))
               (error (c)
                 c))))
        ;; :timeout = not cached (writer-write rejected); error = unexpected fault — both reported
        (when (or (eq result :timeout) (typep result 'error))
          (let ((n (incf error-count)))
            (ignore-errors
             (funcall *durability-error-hook*
                      (if (typep result 'error)
                          result
                          (make-condition 'simple-error
                                          :format-control "seed-relay :timeout (sn=~d topic=~a)"
                                          :format-arguments (list (durable-record-sn r) topic-name)))
                      :seed-relay n)))))))
  t)

;;; --- service-start ---

(defun* %build-disc-node (spec topic-name type-name)
    (function (service-spec string string) t)
  "Build, configure, and start one disc-node for TOPIC-NAME/TYPE-NAME within SPEC.
   Installs the on-match hook for TL late-joiner replay initialization.
   Honors :relay-durability and :collect-durability from (service-spec-qos-overrides spec): each
   :transient-local (default, byte-identical to prior behavior) or :transient (opt-in for cross-vendor
   coexistence). :collect-durability :transient makes the collect reader pull a foreign persistence
   service's OWI-stamped TRANSIENT replay so its OWI logical origin is recorded and its copies collapse
   against directly-collected samples, instead of double-recording under the foreign relay's wire GUID
   (cross-vendor coexistence, ADR 0026 §10). Returns the started node."
  (let* ((domain (service-spec-domain spec))
         (overrides (service-spec-qos-overrides spec))
         (dr-override       (getf overrides :data-representation))
         (relay-dur         (or (getf overrides :relay-durability) :transient-local))
         (collect-dur       (or (getf overrides :collect-durability) :transient-local))
         (peers-override    (getf overrides :peers))
         (mcast-override    (getf overrides :multicast))
         (node (dds.disc:make-disc-node
                :guid-prefix (%collect-node-prefix spec topic-name)
                :domain domain
                :host "127.0.0.1"
                :port 0
                :peers (or peers-override '())
                :multicast mcast-override
                :capture-data-key-hash t)))
    (let ((relay-ep
           (dds.disc:add-local-writer node
                                      :topic topic-name
                                      :type type-name
                                      :qos (apply #'dds.qos:make-writer-qos
                                                  (append (when dr-override
                                                            (list :data-representation dr-override))
                                                          (list :reliability :reliable
                                                                :durability relay-dur))))))
      ;; PID_SERVICE_KIND (0x8003) = PERSISTENCE_SERVICE: gates Connext receiver-side
      ;; PID_ORIGINAL_WRITER_INFO dedup (ADR 0024 Task 8; spike 2026-06-18).
      (setf (dds.rtps.discovery:endpoint-data-service-kind relay-ep)
            dds.rtps.message:+service-kind-persistence+))
    (dds.disc:enable-publisher node :history-kind :keep-all)
    (dds.disc:add-local-reader node
                               :topic topic-name
                               :type type-name
                               :qos (dds.qos:make-reader-qos
                                     :reliability :reliable
                                     :durability collect-dur
                                     :history-kind :keep-all))
    (dds.disc:enable-subscriber node)
    (setf (dds.disc:disc-node-on-match node)
          (lambda (kind remote local-eid)
            (declare (ignore local-eid))   ; the service holds one replay writer per topic (N=1 resolution)
            (when (eq kind :remote-reader)
              (dds.disc:%writer-durability-init
               node
               (copy-seq (dds.rtps.discovery:endpoint-data-guid remote))
               (dds.qos:qos-durability (dds.rtps.discovery:endpoint-data-qos remote))))))
    (dds.disc:start-node node)
    node))

(declaim (ftype (function (durability-service) t) %service-start-auto-discover))

(defun* service-start (service)
    (function (durability-service) durability-service)
  "Resolve the spec's topics to K concrete (topic . type) pairs, then for each pair build a
   disc-node (collect reader reliable/TL/keep-all + replay writer) and spawn a collect-loop
   thread.  K=1 is byte-identical to Phase 1.  All K nodes share the same STORE.
   QoS overrides from (service-spec-qos-overrides spec):
     :data-representation <list>  — governs SEDP RxO advertisement; payload forwarded opaque.
     :relay-durability <keyword>  — DURABILITY for the relay writer; :transient-local (default,
                                    byte-identical) or :transient (opt-in for cross-vendor).
     :collect-durability <keyword> — DURABILITY for the collect reader; :transient-local (default,
                                    byte-identical) or :transient (opt-in: pull a foreign persistence
                                    service's OWI-stamped TRANSIENT replay so its origin converges).
     :peers <list-of-(host . port)> — initial unicast SPDP peers; default none.
     :multicast <boolean>         — when T enables multicast SPDP socket; default NIL.
   *DURABILITY-DEBUG-START-FAULT* when non-NIL: after building the first node, signals an
   error simulating startup failure (test-only fault injector; inert by default).
   Note: concurrent-start re-entrancy is guarded at the runner level (runner-start in runner.lisp);
   calling service-start concurrently on the same service instance is a caller error."
  (let* ((spec   (durability-service-spec service))
         (topics (%service-topics spec))
         (nodes  '()))
    ;; open the store: for file-backed tiers this replays logs + re-derives epoch DEKs;
    ;; pass the DURABILITY_SERVICE history QoS from the spec so service-spec is the single
    ;; functional source of compaction policy (DDS 1.4 §2.2.3.5, ADR 0029).
    (store-open (durability-service-store service)
                (service-spec-history-kind spec)
                (service-spec-history-depth spec))
    (dds.pal:with-lock ((durability-service-lock service))
      (setf (durability-service-running service) t)
      ;; register all initial topic names so service-add-topic idempotency check covers them
      (dolist (pair topics)
        (setf (gethash (car pair) (durability-service-topic-names service)) t)))
    (dolist (pair topics)
      (let* ((topic-name (car pair))
             (type-name  (cdr pair))
             (node       (%build-disc-node spec topic-name type-name)))
        ;; pre-seed the replay writer with any records already in the store
        (%seed-relay-from-store node (durability-service-store service) topic-name)
        ;; fault injector fires after the first node is built (test-only)
        (when *durability-debug-start-fault*
          (dds.pal:with-lock ((durability-service-lock service))
            (setf (durability-service-running service) nil))
          (ignore-errors (dds.disc:stop-node node))
          ;; NOCOND(TEST): inert in production; the UNWIND aborts service-start mid-way — the mechanism under test
          (error "dds.durability: *durability-debug-start-fault* is non-NIL — simulated startup failure"))
        (let ((th (dds.pal:spawn
                   (let ((n node) (tn topic-name))
                     (lambda () (%collect-loop service n tn)))
                   :name (format nil "dds-durability-collect(~a)" topic-name))))
          (push (cons node th) nodes))))
    (let ((ordered (nreverse nodes)))
      (dds.pal:with-lock ((durability-service-lock service))
        (setf (durability-service-nodes service) ordered)
        ;; mirror first pair into legacy node/thread slots for backward compat
        (setf (durability-service-node   service) (caar ordered))
        (setf (durability-service-thread service) (cdar ordered))))
    ;; opt-in (default NIL, no observable change when off): spin the bare discovery node + poll thread
    (%service-start-auto-discover service)
    service))

;;; --- service-stop ---

(defun* service-stop (service)
    (function (durability-service) (eql t))
  "Signal all collect loops to stop; for each node: JOIN its collect thread THEN stop-node.
   The join precedes stop-node per node so each loop has fully exited before its socket is
   closed (avoids getsockname EBADF on a final in-flight poll). Idempotent.
   Also handles the process-mode proxy case (single thread in the legacy THREAD slot).
   :auto-discover teardown (ADR 0026 Phase-2b): the discovery poll thread is JOINED and its bare
   discovery node STOPPED FIRST — before the collect-node list is snapshotted — so no in-flight
   auto-add can push a new (node . thread) pair after the snapshot (no leak). Both steps are guarded,
   so for a fixed-set service (discovery slots NIL) they are no-ops and the teardown has no observable
   change when off.
   TOPIC-NAMES is cleared (clrhash) at the end of teardown: stop discards ALL running state, so a
   dynamically-added topic (via service-add-topic or :auto-discover) does not survive as a stale entry
   into the next service-start on the SAME object — which would otherwise make a re-add a no-op and
   leave service-serves-topic-p a FALSE POSITIVE (a served topic with no rebuilt collect node). A fixed
   service-start re-registers its start-list names, so the fixed-set case is byte-identical after the
   next start (same topic-names contents); runtime additions are re-done on restart (:auto-discover
   re-discovers + re-adds; the explicit API caller must re-add — the correct 'stop discards runtime state')."
  (let ((node-pairs nil) (legacy-th nil) (disc-node nil) (disc-th nil))
    (dds.pal:with-lock ((durability-service-lock service))
      (setf (durability-service-running service) nil)
      ;; grab + clear the discovery slots under the same lock that flips RUNNING
      (setf disc-node (durability-service-discovery-node service))
      (setf disc-th   (durability-service-discovery-thread service))
      (setf (durability-service-discovery-node   service) nil)
      (setf (durability-service-discovery-thread service) nil))
    ;; join the poll thread FIRST (it reads RUNNING each tick -> exits), so no further service-add-topic
    ;; fires; only then is the collect-node list stable to snapshot below
    (when disc-th   (ignore-errors (dds.pal:join disc-th)))
    (when disc-node (ignore-errors (dds.disc:stop-node disc-node)))
    (dds.pal:with-lock ((durability-service-lock service))
      (setf node-pairs (durability-service-nodes service))
      (setf (durability-service-nodes service) nil)
      ;; process-mode proxy stores monitor thread in the legacy thread slot only
      (unless node-pairs
        (setf legacy-th (durability-service-thread service))
        (setf (durability-service-thread service) nil)))
    (if node-pairs
        ;; thread-mode: join+stop per node pair in order
        (dolist (pair node-pairs)
          (let ((th   (cdr pair))
                (node (car pair)))
            (when th   (ignore-errors (dds.pal:join th)))
            (when node (ignore-errors (dds.disc:stop-node node)))))
        ;; process-mode proxy: just join the monitor thread
        (when legacy-th
          (ignore-errors (dds.pal:join legacy-th))))
    (dds.pal:with-lock ((durability-service-lock service))
      (setf (durability-service-thread service) nil)
      ;; discard running topic registry: start rebuilds from the spec (fixed start-list re-registers ->
      ;; byte-identical after the next start; runtime adds are re-done). Prevents a stale entry making a
      ;; post-restart re-add a no-op with a serves-topic-p false-positive (no rebuilt collect node).
      (clrhash (durability-service-topic-names service)))
    ;; close the store: for file-backed tiers this fsyncs logs + frees epoch DEKs
    (ignore-errors (store-close (durability-service-store service))))
  t)

;;; --- service-alive-p ---

(defun* service-alive-p (service)
    (function (durability-service) boolean)
  "T iff the running flag is set and every collect-loop thread is live.
   For thread-mode multi-topic: all K threads in NODES must be non-nil.
   For the process-mode proxy: the single THREAD slot must be non-nil.
   For an :auto-discover service the poll thread must also be live; an :auto-discover service with an
   EMPTY start-list (zero collect nodes) is alive iff its poll thread is. When DISCOVERY-NODE is NIL
   (a fixed-set service) the two added discovery clauses are vacuously true, so there is no observable change when off."
  (dds.pal:with-lock ((durability-service-lock service))
    (and (durability-service-running service)
         ;; A: all collect threads live (vacuously T when there are no collect nodes)
         (let ((pairs (durability-service-nodes service)))
           (if pairs (every (lambda (p) (if (cdr p) t nil)) pairs) t))
         ;; B: the poll thread is live iff :auto-discover (vacuously T for a fixed-set service)
         (if (durability-service-discovery-node service)
             (if (durability-service-discovery-thread service) t nil) t)
         ;; C: a running service must be backed by SOME live thread — collect nodes, the poll thread, or
         ;; the process-mode proxy (identical to the prior legacy-thread fallback when discovery is off)
         (cond
           ((durability-service-nodes service) t)
           ((durability-service-discovery-node service) t)
           (t (if (durability-service-thread service) t nil))))))

;;; --- service-serves-topic-p ---

(defun* service-serves-topic-p (service topic-name)
    (function (durability-service string) boolean)
  "T iff SERVICE currently serves TOPIC-NAME — i.e. TOPIC-NAME is registered in the service's
   topic-name set (a collect node exists or is being built for it). Checked UNDER the service lock, so it
   is safe to call from any thread concurrently with the collect / discovery-poll threads (which mutate the
   set under the same lock). Covers start-list topics and dynamically added ones alike (an explicit
   service-add-topic or an :auto-discover auto-add). The primary consumer is observability / tests."
  (dds.pal:with-lock ((durability-service-lock service))
    (if (gethash topic-name (durability-service-topic-names service)) t nil)))

;;; --- service-add-topic ---

(defun* service-add-topic (service topic-name type-name)
    (function (durability-service string string) (values (eql t) (or null t)))
  "Add TOPIC-NAME/TYPE-NAME to a RUNNING SERVICE without a restart.
   Idempotent by TOPIC-NAME (string=, time-stable) — a duplicate call returns (values T NIL).
   On a fresh add: builds a new disc-node via %BUILD-DISC-NODE, pre-seeds from the store,
   spawns a collect-loop thread, and registers the (node . thread) pair under the lock.
   Returns (values T <new-node>) so callers can use the node without re-deriving the prefix.
   TOCTOU-safe: checks under the first lock, builds outside it (I/O), then re-checks under
   the final lock before push — if the topic appeared concurrently the just-built node is
   stopped and NIL is returned as the node value.
   The collect thread reads RUNNING under the lock on every iteration, so service-stop
   correctly drains and joins the new thread along with all pre-existing ones.
   Caller error: calling on a stopped service (RUNNING=NIL) is undefined — do not."
  (let* ((spec (durability-service-spec service)))
    ;; first check: fast path under lock — O(1) hash lookup
    (dds.pal:with-lock ((durability-service-lock service))
      (when (gethash topic-name (durability-service-topic-names service))
        (return-from service-add-topic (values t nil))))
    ;; build + start the new disc-node (outside the lock: I/O + socket bind)
    (let ((node (%build-disc-node spec topic-name type-name)))
      ;; pre-seed from existing store records (idempotent for empty store)
      (%seed-relay-from-store node (durability-service-store service) topic-name)
      (let ((th (dds.pal:spawn
                 (let ((n node) (tn topic-name))
                   (lambda () (%collect-loop service n tn)))
                 :name (format nil "dds-durability-collect(~a)" topic-name))))
        ;; TOCTOU re-check: register only if topic still absent (concurrent add wins)
        (dds.pal:with-lock ((durability-service-lock service))
          (when (gethash topic-name (durability-service-topic-names service))
            ;; concurrent add won; stop the just-built node and discard it
            (ignore-errors (dds.disc:stop-node node))
            (return-from service-add-topic (values t nil)))
          (setf (gethash topic-name (durability-service-topic-names service)) t)
          (push (cons node th) (durability-service-nodes service)))
        (values t node)))))

;;; --- discovery-driven auto-serve (ADR 0026 dynamic-topic-add, Phase-2b) ---
;;;
;;; Opt-in (:auto-discover): a bare SPDP/SEDP discovery node + a poll thread that auto-adds any
;;; newly-discovered remote WRITER topic (passing the filter) via the existing SERVICE-ADD-TOPIC.
;;; DRY: the actual node/store/relay build is SERVICE-ADD-TOPIC verbatim — the new code below is only
;;; the filter, the bare node, the poll, and (in service-start/service-stop) the lifecycle. The default
;;; (no :auto-discover) never reaches any of this, so the fixed-set path has no observable change when off.

(defun* %auto-discover-match-p (filter topic-name)
    (function ((or null function string) string) t)
  "T iff TOPIC-NAME passes the :auto-discover FILTER. NIL = match-all (the default under :auto-discover).
   A function is a predicate (funcall filter topic-name) -> generalized boolean. A string is a simple name
   glob: a lone TRAILING #\\* matches any suffix (prefix match — e.g. \"Dyn*\" matches \"DynX\"/\"Dyn\");
   otherwise an exact string= match. For richer POSIX fnmatch semantics pass a function predicate."
  (etypecase filter
    (null t)
    (function (if (funcall filter topic-name) t nil))
    (string
     (let ((plen (length filter)))
       (if (and (plusp plen) (char= #\* (char filter (1- plen))))
           (let ((pn (1- plen)))                       ; compare the pre-#\* prefix against the name head
             (and (>= (length topic-name) pn)
                  (string= filter topic-name :end1 pn :end2 pn)))
           (string= filter topic-name))))))

(defun* %auto-discover-pending (filter candidates)
    (function ((or null function string) list) list)
  "Pure: from CANDIDATES ((topic-name . type-name) conses) keep those passing FILTER
   (%auto-discover-match-p), de-duplicated BY topic-name (first type-name wins), original order preserved.
   Skips malformed / empty-topic entries. Does NOT consult the service's served set — SERVICE-ADD-TOPIC is
   idempotent-by-name (an already-served topic is an O(1) no-op there), so leaving the served-skip to it
   keeps this a side-effect-free, unit-testable selection core (the FILTER + IDEMPOTENT gates test it directly)."
  (let ((seen (make-hash-table :test #'equal)) (out '()))
    (dolist (c candidates (nreverse out))
      (let ((topic (car c)) (type (cdr c)))
        (when (and (stringp topic) (stringp type) (plusp (length topic))
                   (not (gethash topic seen))
                   (%auto-discover-match-p filter topic))
          (setf (gethash topic seen) t)
          (push c out))))))

(defun* %discovered-topic-types (node)
    (function (t) list)
  "Snapshot the discovery NODE's discovered remote PUBLICATIONS as (topic-name . type-name) conses.
   WRITERS only — a reader-only topic carries no data to persist (react to writers per the brief). Only
   the topic-NAME + type-NAME strings are needed (SEDP carries both); the payload is stored/relayed opaque,
   so NO type registration is required to serve an arbitrary discovered type. Skips empty-topic entries."
  (let ((out '()))
    (dolist (ep (dds.disc:disc-node-discovered-writers-list node) (nreverse out))
      (let ((topic (dds.rtps.discovery:endpoint-data-topic-name ep))
            (type  (dds.rtps.discovery:endpoint-data-type-name ep)))
        (when (and (stringp topic) (stringp type) (plusp (length topic)))
          (push (cons topic type) out))))))

(defun* %build-discovery-node (spec)
    (function (service-spec) t)
  "Build + start a BARE discovery disc-node for SPEC: SPDP/SEDP discovery ONLY, NO user endpoints, so its
   receiver records EVERY remote participant's published topics into disc-node-discovered-writers (the
   'sees all topics' feed the per-topic collect nodes lack). Honors the spec's domain + the :peers /
   :multicast qos-overrides (same reach as the collect nodes). Returns the started node."
  (let* ((overrides (service-spec-qos-overrides spec))
         (node (dds.disc:make-disc-node
                :guid-prefix (%collect-node-prefix spec "*auto-discover*")   ; distinct from any collect node's prefix
                :domain (service-spec-domain spec)
                :host "127.0.0.1"
                :port 0
                :peers (or (getf overrides :peers) '())
                :multicast (getf overrides :multicast))))
    (dds.disc:start-node node)
    node))

(defun* %discovery-poll-once (service node)
    (function (durability-service t) t)
  "Run ONE discovery scan cycle: for each discovered remote WRITER whose topic passes the service's
   :auto-discover-filter, call the existing SERVICE-ADD-TOPIC (idempotent-by-name + TOCTOU-guarded, so
   repeated discovery / a race is harmless — an already-served topic short-circuits before any node is
   built). The poll thread calls this each tick; tests call it directly for deterministic assertions."
  (let* ((spec   (durability-service-spec service))
         (filter (service-spec-auto-discover-filter spec)))
    (dolist (pair (%auto-discover-pending filter (%discovered-topic-types node)))
      (service-add-topic service (car pair) (cdr pair))))
  t)

(defun* %discovery-poll-loop (service node)
    (function (durability-service t) t)
  "Discovery-driven auto-serve poll-thread body (ADR 0026 Phase-2b), mirroring %collect-loop's shape:
   reads RUNNING under the lock each iteration (so service-stop drains + joins it), re-announces NODE's
   SPDP + SEDP every ~1.5 s (RTPS 2.5 §8.5.3.3) so peers keep discovering the bare node, then runs one
   %discovery-poll-once scan. Sleeps *durability-auto-discover-interval* between ticks. Each iteration is
   wrapped in handler-case so a transient error fires *durability-error-hook* and the thread survives."
  (let ((error-count 0) (last-announce 0))
    (loop
      (unless (dds.pal:with-lock ((durability-service-lock service))
                (durability-service-running service))
        (return))
      (handler-case
          (let ((now (get-internal-real-time)))
            (when (> (- now last-announce)
                     (round (* 1.5 internal-time-units-per-second)))
              (dds.disc:announce-participant node)
              (dds.disc:announce-endpoints node)
              (setf last-announce now))
            (%discovery-poll-once service node))
        (error (c)
          (let ((n (incf error-count)))
            (ignore-errors (funcall *durability-error-hook* c :discovery-poll n)))))
      (sleep *durability-auto-discover-interval*)))
  t)

(defun* %service-start-auto-discover (service)
    (function (durability-service) t)
  "When (service-spec-auto-discover spec): build the bare discovery node, spawn the poll thread, and
   record both under the service lock. A NO-OP returning T for a fixed-set service — so the default
   service-start tail has no observable change when off. Called after RUNNING is already T and the collect nodes are up."
  (let ((spec (durability-service-spec service)))
    (when (service-spec-auto-discover spec)
      (let* ((node (%build-discovery-node spec))
             (th   (dds.pal:spawn
                    (let ((n node)) (lambda () (%discovery-poll-loop service n)))
                    :name (format nil "dds-durability-auto-discover(~a)" (service-spec-name spec)))))
        (dds.pal:with-lock ((durability-service-lock service))
          (setf (durability-service-discovery-node   service) node)
          (setf (durability-service-discovery-thread service) th)))))
  t)
