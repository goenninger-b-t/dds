;;;; DCPS assignability gate on the discovery TYPE-GATE hook (M4 Task 4.2, FR-TYPE-4).
;;;; Completes gated matching: when a discovered remote endpoint advertises
;;;; PID_TYPE_INFORMATION, the gate compares EquivalenceHashes, fetches the remote
;;;; Minimal TypeObject via the TypeLookup service on a mismatch (XTypes 1.3
;;;; §7.6.3.3.3), resolves nested EK_MINIMAL member hashes with bounded follow-up
;;;; queries, and decides the match with is-assignable-from under the READER side's
;;;; TYPE_CONSISTENCY_ENFORCEMENT (§7.6.3.4.2 Step 1). Every unassessable case —
;;;; no/malformed TypeInformation, no local TypeObject, an unknown hash, a TypeLookup
;;;; timeout, depth exhaustion — falls back to today's name-based matching
;;;; (:compatible, logged), never to a rejection. Control-plane: per-decision heap
;;;; allocation is acceptable; both caches are bounded (NFR-SEC-POSTURE). The gate
;;;; and the TypeLookup continuations run OUTSIDE the node lock per the documented
;;;; dds.disc contracts.

(in-package #:dds.dcps)

(defparameter *max-typeobject-cache-entries* 256
  "Cap on parsed remote Minimal TypeObjects (and on recorded per-remote gate
   verdicts) each DomainParticipant's type-gate retains, FIFO-evicted at the cap.
   A resource-exhaustion guard (NFR-SEC-POSTURE): wire-driven tables never grow
   unbounded. Read at insertion time.")

(defparameter *typelookup-max-depth* 4
  "Maximum nested-type TypeLookup follow-up rounds the type-gate issues while
   resolving a remote TypeObject's EK_MINIMAL member hashes (one getTypes per round,
   XTypes 1.3 §7.6.3.3.3) before it gives up and falls back to name-based matching
   (:compatible, logged). Bounds both wire traffic and recursion (NFR-SEC-POSTURE).")

(defstruct* (type-gate-state (:constructor %make-type-gate-state))
  "Per-participant state behind the FR-TYPE-4 assignability gate. CACHE maps a
   14-octet EquivalenceHash (EQUALP) to its parsed minimal-struct-type; VERDICTS maps
   a remote 16-octet endpoint GUID to its recorded :compatible/:incompatible verdict
   (the post-resume gate re-run replays it instead of re-querying); both are
   FIFO-bounded by *MAX-TYPEOBJECT-CACHE-ENTRIES* via their *-FIFO key lists.
   INFLIGHT marks hashes with an outstanding TypeLookup query (dedupes concurrent
   gates). QUERIES counts issued getTypes requests (diagnostic). LOCK guards all of
   it across the receiver + announce/app threads; never held across a TypeLookup call."
  (lock (dds.pal:make-lock "type-gate") :type t)
  (cache (make-hash-table :test 'equalp) :type hash-table)
  (cache-fifo '() :type list)
  (verdicts (make-hash-table :test 'equalp) :type hash-table)
  (verdict-fifo '() :type list)
  (inflight (make-hash-table :test 'equalp) :type hash-table)
  (queries 0 :type (integer 0)))

(defun* %hash-key14 (h)
    (function ((array (unsigned-byte 8) (*))) (simple-array (unsigned-byte 8) (*)))
  "Normalize H to exactly the 14-octet EquivalenceHash form (XTypes 1.3 §7.3.4.9.1)
   used as the EQUALP cache key: returned as-is when already simple + 14 octets,
   else copied/zero-padded to 14."
  (if (and (typep h '(simple-array (unsigned-byte 8) (*))) (= (length h) 14))
      h
      (let ((out (make-array 14 :element-type '(unsigned-byte 8) :initial-element 0)))
        ;; REPLACE itself bounds the copy by both sequences' lengths
        (replace out h)
        out)))

(defun* %bounded-put (table fifo key value cap)
    (function (hash-table list t t (integer 1)) list)
  "Insert KEY -> VALUE into TABLE with FIFO eviction at CAP entries; returns the
   updated newest-first FIFO key list (caller stores it back). Re-inserting an
   existing key replaces the value without growing. CALLER HOLDS the gate lock."
  (if (nth-value 1 (gethash key table))
      (progn (setf (gethash key table) value) fifo)
      (progn
        (setf (gethash key table) value)
        (push key fifo)
        (when (> (hash-table-count table) cap)
          (let ((last2 (last fifo 2)))
            (remhash (car (last last2)) table)
            (if (cdr last2) (setf (cdr last2) nil) (setf fifo nil))))
        fifo)))

(defun* %remote-writer-p (remote)
    (function (dds.rtps.discovery:endpoint-data) t)
  "T iff REMOTE is a writer endpoint, decided by its GUID's entityKind octet:
   the low six bits encode the entity kind — Writer (with/no key) = 0x02/0x03,
   Reader (no/with key) = 0x04/0x07 — while the two MSBs only distinguish
   user/builtin/vendor entities (RTPS 2.5 §9.3.1.2 Table 9.1). This recovers the
   match direction the TYPE-GATE contract does not pass explicitly."
  (and (member (logand (aref (dds.rtps.discovery:endpoint-data-guid remote) 15) #x3f)
               '(#x02 #x03))
       t))

(defun* %remote-guid-prefix (remote)
    (function (dds.rtps.discovery:endpoint-data) (simple-array (unsigned-byte 8) (12)))
  "The remote participant's 12-octet GUID prefix — the first 12 octets of the
   endpoint GUID (GUID_t = GuidPrefix_t + EntityId_t, RTPS 2.5 §9.3.1.2) — i.e. the
   participant whose TypeLookup service the gate queries."
  (let ((p (make-array 12 :element-type '(unsigned-byte 8))))
    (replace p (dds.rtps.discovery:endpoint-data-guid remote) :end2 12)
    p))

(defun* %tg-log (remote verdict reason)
    (function (dds.rtps.discovery:endpoint-data keyword (or null string)) t)
  "One diagnostic line per recorded gate verdict (or notable gate event, e.g. the
   global-registry type-support fallback) to *TYPE-COMPAT-LOG* when set (the same
   opt-in diagnostics stream the ADR 0009 advisory uses); NIL stream = silent."
  (when *type-compat-log*
    (format *type-compat-log* "~&; type-gate[~a/~a]: ~a~@[ — ~a~]~%"
            (dds.rtps.discovery:endpoint-data-topic-name remote)
            (dds.rtps.discovery:endpoint-data-type-name remote)
            verdict reason))
  t)

(defun* %gate-local-type-support (p local)
    (function (domain-participant dds.rtps.discovery:endpoint-data) t)
  "The type-support behind the LOCAL endpoint: the participant's Topic registered
   under the endpoint's topic name (each participant may bind the same wire type
   name to a different local type), falling back to the global registry under the
   endpoint's type name. NIL when neither resolves (the gate then cannot assess)."
  (let ((tp (%find-topic p (dds.rtps.discovery:endpoint-data-topic-name local))))
    (if tp
        (topic-type-support tp)
        (progn
          (%tg-log local :note "no local Topic for the endpoint's topic name; using the global type registry")
          (dds.types:find-type-support (dds.rtps.discovery:endpoint-data-type-name local))))))

(defun* %reader-side-tce (remote local)
    (function (dds.rtps.discovery:endpoint-data dds.rtps.discovery:endpoint-data)
              dds.qos:type-consistency-enforcement)
  "The READER side's TYPE_CONSISTENCY_ENFORCEMENT (the policy applies to DataReaders
   only, XTypes 1.3 §7.6.3.4): LOCAL's QoS when REMOTE is a writer, else REMOTE's.
   The policy is not carried in our SEDP ParameterList yet, so a remote reader's
   parsed QoS holds the §7.6.3.4.1 defaults — the writer side then assesses with
   default options (documented gap until the policy rides DCPSSubscription)."
  (dds.qos:qos-type-consistency
   (dds.rtps.discovery:endpoint-data-qos (if (%remote-writer-p remote) local remote))))

(defun* %gate-record-verdict (state remote verdict reason)
    (function (type-gate-state dds.rtps.discovery:endpoint-data
               (member :compatible :incompatible) (or null string))
              (member :compatible :incompatible))
  "Record VERDICT for REMOTE (keyed by its 16-octet GUID, FIFO-bounded) so the
   post-resume gate re-run replays it instead of re-querying; log it; return it."
  (dds.pal:with-lock ((type-gate-state-lock state))
    (setf (type-gate-state-verdict-fifo state)
          (%bounded-put (type-gate-state-verdicts state)
                        (type-gate-state-verdict-fifo state)
                        (copy-seq (dds.rtps.discovery:endpoint-data-guid remote))
                        verdict *max-typeobject-cache-entries*)))
  (%tg-log remote verdict reason)
  verdict)

(defun* %gate-assess (remote local local-to remote-model)
    (function (dds.rtps.discovery:endpoint-data dds.rtps.discovery:endpoint-data
               dds.types:minimal-struct-type dds.types:minimal-struct-type)
              (member :compatible :incompatible))
  "The assignability verdict for a fully-resolved pair: the reader-side type must be
   is-assignable-from the writer-side type under the reader's
   TYPE_CONSISTENCY_ENFORCEMENT (XTypes 1.3 §7.6.3.4.2 Step 1, via
   dds.types:enforce-type-consistency). Direction comes from REMOTE's GUID entityKind
   (%REMOTE-WRITER-P): a remote writer makes LOCAL the reader, and vice versa."
  (let* ((tce (%reader-side-tce remote local))
         (remote-writer-p (%remote-writer-p remote))
         (reader-model (if remote-writer-p local-to remote-model))
         (writer-model (if remote-writer-p remote-model local-to)))
    (if (dds.types:enforce-type-consistency
         reader-model writer-model
         :kind (dds.qos:type-consistency-enforcement-kind tce)
         :ignore-sequence-bounds (dds.qos:type-consistency-enforcement-ignore-sequence-bounds tce)
         :ignore-string-bounds (dds.qos:type-consistency-enforcement-ignore-string-bounds tce)
         :ignore-member-names (dds.qos:type-consistency-enforcement-ignore-member-names tce)
         :prevent-type-widening (dds.qos:type-consistency-enforcement-prevent-type-widening tce))
        :compatible
        :incompatible)))

(defun* %resolve-nested (model cache visited)
    (function (dds.types:minimal-struct-type hash-table list) (values list t))
  "Attach cached parsed models as the REFERENCED of MODEL's unresolved EK_MINIMAL /
   EK_COMPLETE member TypeIdentifiers (a wire-parsed model carries only the 14-octet
   hash, REFERENCED = NIL — so ti-assignable-from could not recurse), recursing into
   each attachment. Returns (values MISSING BAD-P): MISSING = hash keys not yet in
   CACHE (follow-up query targets); BAD-P = T on a hash-less unresolved member or a
   hash cycle in VISITED (hostile input — our types are acyclic), making the model
   unassessable. Attachment is idempotent (cache entries are keyed by hash). CALLER
   HOLDS the gate lock."
  ;; visited/missing stay tiny (*typelookup-max-depth* rounds x member counts), so EQUALP list scans are fine
  (let ((missing '()) (badp nil))
    (dolist (m (dds.types:minimal-struct-type-members model) (values missing badp))
      (let ((ti (dds.types:minimal-struct-member-type-identifier m)))
        (when (and ti (member (dds.types:type-identifier-kind ti)
                              (list dds.types:+ek-minimal+ dds.types:+ek-complete+)))
          (let ((h (dds.types:type-identifier-hash ti)))
            (if (or (null h) (< (length h) 14))
                (unless (typep (dds.types:type-identifier-referenced ti)
                               'dds.types:minimal-struct-type)
                  (setf badp t))
                (let ((key (%hash-key14 h)))
                  (if (member key visited :test #'equalp)
                      (setf badp t)
                      (let ((sub (gethash key cache)))
                        (if (null sub)
                            (pushnew key missing :test #'equalp)
                            (progn
                              (unless (typep (dds.types:type-identifier-referenced ti)
                                             'dds.types:minimal-struct-type)
                                (setf (dds.types:type-identifier-referenced ti) sub))
                              (multiple-value-bind (mm bb)
                                  (%resolve-nested sub cache (cons key visited))
                                (setf missing (union mm missing :test #'equalp)
                                      badp (or badp bb)))))))))))))))

;; %gate-decide and %gate-query are mutually recursive via the query continuation.
(declaim (ftype (function (domain-participant dds.disc:disc-node type-gate-state
                           dds.rtps.discovery:endpoint-data dds.rtps.discovery:endpoint-data
                           dds.types:minimal-struct-type
                           (simple-array (unsigned-byte 8) (*)) list (integer 0))
                          (member :pending))
                %gate-query))

(defun* %gate-decide (p node state remote local local-to key depth)
    (function (domain-participant dds.disc:disc-node type-gate-state
               dds.rtps.discovery:endpoint-data dds.rtps.discovery:endpoint-data
               dds.types:minimal-struct-type (simple-array (unsigned-byte 8) (*)) (integer 0))
              (member :compatible :incompatible :pending))
  "Decide REMOTE's verdict from the cached model under hash KEY: resolve its nested
   member hashes from the cache (%RESOLVE-NESTED), assess when fully resolved, or —
   while DEPTH < *TYPELOOKUP-MAX-DEPTH* — issue one follow-up getTypes for the
   still-missing hashes (deduped against in-flight queries) and stay :pending —
   the in-flight queries' continuation re-runs this decision when the reply lands.
   An unavailable model, an unresolvable/cyclic nesting, or an exhausted depth
   records the name-based fallback :compatible (logged)."
  (let ((model nil) (missing '()) (badp nil) (to-query '()))
    (dds.pal:with-lock ((type-gate-state-lock state))
      (setf model (gethash key (type-gate-state-cache state)))
      (when model
        (multiple-value-setq (missing badp)
          (%resolve-nested model (type-gate-state-cache state) (list key)))
        ;; dedupe against queries already in flight (a parked re-run must not re-ask)
        (setf to-query (remove-if (lambda (h) (gethash h (type-gate-state-inflight state)))
                                  missing))))
    (cond
      ((null model)
       (%gate-record-verdict state remote :compatible "remote TypeObject unavailable"))
      (badp
       (%gate-record-verdict state remote :compatible "unresolvable nested TypeIdentifier"))
      ((null missing)
       (%gate-record-verdict state remote (%gate-assess remote local local-to model) nil))
      ((null to-query) :pending)   ; every missing hash already has a query in flight
      ((>= depth *typelookup-max-depth*)
       (%gate-record-verdict state remote :compatible "TypeLookup depth exhausted"))
      (t (%gate-query p node state remote local local-to key to-query (1+ depth))))))

(defun* %gate-continuation (p node state remote local local-to key hashes depth pairs okp)
    (function (domain-participant dds.disc:disc-node type-gate-state
               dds.rtps.discovery:endpoint-data dds.rtps.discovery:endpoint-data
               dds.types:minimal-struct-type (simple-array (unsigned-byte 8) (*))
               list (integer 0) list t)
              t)
  "TypeLookup continuation (runs OUTSIDE the node lock per the type-lookup-query
   contract): clear the in-flight marks for HASHES, cache each returned pair's parsed
   model (FIFO-bounded; unparseable/:unsupported payloads are dropped, leaving the
   honest fallback to %GATE-DECIDE), decide, then resume the parked match decisions.
   When the decide stays :pending (nested follow-ups in flight) that resume is
   premature but harmless: parked gates re-park and the inner continuation resumes again."
  (dds.pal:with-lock ((type-gate-state-lock state))
    (dolist (h hashes) (remhash h (type-gate-state-inflight state)))
    (when okp
      (dolist (pair pairs)
        (let ((m (and (consp pair) (cdr pair)
                      (dds.types:parse-minimal-type-object (cdr pair)))))
          (when (typep m 'dds.types:minimal-struct-type)
            (setf (type-gate-state-cache-fifo state)
                  (%bounded-put (type-gate-state-cache state)
                                (type-gate-state-cache-fifo state)
                                (%hash-key14 (car pair)) m
                                *max-typeobject-cache-entries*)))))))
  (if okp
      (%gate-decide p node state remote local local-to key depth)
      (%gate-record-verdict state remote :compatible "TypeLookup timeout/failure"))
  (dds.disc:resume-parked-matches node)
  t)

(defun* %gate-query (p node state remote local local-to key hashes depth)
    (function (domain-participant dds.disc:disc-node type-gate-state
               dds.rtps.discovery:endpoint-data dds.rtps.discovery:endpoint-data
               dds.types:minimal-struct-type (simple-array (unsigned-byte 8) (*))
               list (integer 0))
              (member :pending))
  "Issue one getTypes toward REMOTE's participant (its GUID prefix) for HASHES,
   marking them in flight, and return :pending — the SAME parked match decision
   waits; the continuation caches the reply, recurses through %GATE-DECIDE, and
   resumes. The state lock is NEVER held across the type-lookup-query call (its
   cap-rejection path invokes the continuation synchronously)."
  (dds.pal:with-lock ((type-gate-state-lock state))
    (incf (type-gate-state-queries state))
    (dolist (h hashes) (setf (gethash h (type-gate-state-inflight state)) t)))
  (dds.disc:type-lookup-query
   node (%remote-guid-prefix remote) hashes
   (lambda (pairs okp)
     (%gate-continuation p node state remote local local-to key hashes depth pairs okp)))
  :pending)

(defun* %participant-type-gate (p node remote local)
    (function (domain-participant dds.disc:disc-node
               dds.rtps.discovery:endpoint-data dds.rtps.discovery:endpoint-data)
              (member :compatible :incompatible :pending))
  "The FR-TYPE-4 assignability gate installed on P's disc-node TYPE-GATE hook (both
   match directions, receiver thread, OUTSIDE the node lock). Verdict ladder:
   no remote TypeInformation -> :compatible (name-based, the pre-XTypes behavior);
   a recorded verdict for this remote GUID replays (the post-resume re-run);
   malformed TypeInformation / no local TypeObject / a local hash failure ->
   :compatible (cannot assess, logged); equal EquivalenceHashes -> :compatible
   (fast path, no wire traffic); a cached remote model -> assess now; the remote
   participant not yet SPDP-discovered -> :pending without querying (the SEDP
   re-announce re-runs the gate once its locator is known); else one getTypes toward
   the remote participant (deduped per hash) -> :pending until the reply, a timeout,
   or the depth bound decides it."
  (let ((state (dp-type-gate-state p))
        (ti-octets (dds.rtps.discovery:endpoint-data-type-information remote)))
    (block gate
      (when (or (null state) (null ti-octets)) (return-from gate :compatible))
      (let ((v (dds.pal:with-lock ((type-gate-state-lock state))
                 (gethash (dds.rtps.discovery:endpoint-data-guid remote)
                          (type-gate-state-verdicts state)))))
        (when v (return-from gate v)))
      (let ((h (handler-case (dds.types:deserialize-type-information-hash ti-octets)
                 (error () nil))))
        (unless h
          (%tg-log remote :compatible "malformed TypeInformation")
          (return-from gate :compatible))
        (let* ((ts (%gate-local-type-support p local))
               (local-to (and (typep ts 'dds.types:type-support)
                              (dds.types:type-support-typeobject ts))))
          (unless (typep local-to 'dds.types:minimal-struct-type)
            (return-from gate :compatible))   ; no local TypeObject -> cannot assess
          (let ((lh (handler-case (dds.types:equivalence-hash local-to) (error () nil))))
            (unless lh (return-from gate :compatible))   ; local hash unserializable
            (let ((key (%hash-key14 h)))
              (when (equalp key (%hash-key14 lh))
                (return-from gate :compatible))   ; identical types, no lookup needed
              (multiple-value-bind (hit inflightp)
                  (dds.pal:with-lock ((type-gate-state-lock state))
                    (values (nth-value 1 (gethash key (type-gate-state-cache state)))
                            (nth-value 1 (gethash key (type-gate-state-inflight state)))))
                (cond
                  (hit (%gate-decide p node state remote local local-to key 0))
                  (inflightp :pending)   ; another gate already asked for this hash
                  ;; SEDP can outrun SPDP: stay :pending (no unsendable query); the re-announce re-runs the gate
                  ((not (member (%remote-guid-prefix remote)
                                (dds.disc:disc-node-discovered-prefixes node)
                                :test #'equalp))
                   :pending)
                  (t (%gate-query p node state remote local local-to key (list key) 0)))))))))))

(defun* %install-type-gate (p)
    (function (domain-participant) domain-participant)
  "Create P's type-gate state and install %PARTICIPANT-TYPE-GATE on its disc-node
   TYPE-GATE hook (FR-TYPE-4 gated matching). Installed for every participant —
   harmless when no peer advertises PID_TYPE_INFORMATION (the first ladder rung
   answers :compatible). Returns P."
  (setf (dp-type-gate-state p) (%make-type-gate-state))
  (setf (dds.disc:disc-node-type-gate (dp-node p))
        (lambda (node remote local) (%participant-type-gate p node remote local)))
  p)
