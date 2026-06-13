;;;; L5/L6 bridge — user data plane over UDP (FR-RTPS-*, FR-DDS-*). Wires the
;;;; value-level reliable writer/reader state machines (dds.rtps.reliable) to the
;;;; UDP transport: a publisher serializes a sample into a DATA submessage and
;;;; sends it plus a HEARTBEAT to its peers; the subscriber stores the DATA and
;;;; answers the HEARTBEAT with an ACKNACK; the publisher retransmits any NACKed
;;;; change. For v1 the user/metatraffic share one socket (routing is by
;;;; EntityId), peers double as the data destination, and the SerializedPayload is
;;;; opaque bytes (a generated-type codec is the follow-up). The reliable handshake
;;;; runs in the receiver thread, so its sends use the node's separate rx-tx-msg
;;;; buffer (publish runs on the caller thread and uses tx-msg) — no shared buffer
;;;; across threads. This file is NOT a measured hot path (per-sample heap copies
;;;; here are a documented v1 concern; the gated hot-path files are untouched).

(in-package #:dds.disc)

;; User-defined EntityIds: entityKey[3] << 8 | entityKind (RTPS 2.5 §9.3.1.2).
;; ShapeType is keyed (color), so the endpoints are WITH-KEY kinds (0x02 / 0x07) —
;; a no-key writer on a keyed topic is what RTI is fed otherwise.
(defconstant +user-writer-id+ #x00000102)   ; key 000001, kind 02 (user writer WITH key)
(defconstant +user-reader-id+ #x00000107)   ; key 000001, kind 07 (user reader WITH key)
;; These MUST equal the EntityIds that add-local-writer/add-local-reader announce via
;; SEDP (key 1, kinds 0x02/0x07): a peer matches the announced endpoint and routes its
;; HEARTBEAT/ACKNACK by that EntityId, so the data-plane endpoint must carry the same id.

(defparameter *datagram-sink* nil
  "Test/bench affordance (default NIL = off): when bound to a function, %SEND-RAW-BUF calls it with a
   fresh octet-vector copy of each outgoing datagram (buf[0..LEN]) BEFORE sending — so a test can
   capture and re-parse coalesced datagrams (count submessages, assert ≤ budget). The real send still
   happens. The copy is allocated only while the sink is bound, so there is no production cost. Never
   set in production.")

(defun* %send-raw-buf (node buf len host port)
    (function (disc-node dds.core.buffer:octet-buffer (integer 0) string (unsigned-byte 16)) t)
  "Send the first LEN octets of BUF (a complete RTPS message) to HOST:PORT over the node's transport —
   the raw one-datagram send shared by %SEND-MSG-BUF and the %SEND-PACKED coalescer (one dds.xport:send
   = one sendto). Hands a copy to *DATAGRAM-SINK* first when that test hook is bound."
  (when *datagram-sink*
    (funcall *datagram-sink* (subseq (dds.core.buffer:octet-buffer-vec buf) 0 len)))
  (dds.xport:send (disc-node-transport node)
                  (dds.xport.udp:make-udp-locator :host host :port port)
                  buf 0 len))

(defun* %send-msg-buf (node buf build-fn host port)
    (function (disc-node dds.core.buffer:octet-buffer function string (unsigned-byte 16)) t)
  "Build an RTPS message (Header + whatever BUILD-FN writes on the cursor) into BUF
   and send it to HOST:PORT. BUF selects the thread's scratch message buffer."
  (let ((mc (dds.core.buffer:cursor buf :endianness :little)))
    (dds.rtps.message:write-header mc (disc-node-guid-prefix node))
    (funcall build-fn mc)
    (%send-raw-buf node buf (dds.core.buffer:cursor-position mc) host port)))

(defparameter *coalesce-datagram-budget* 1400
  "Soft upper bound (octets) on a coalesced RTPS datagram built by %SEND-PACKED. Default 1400 keeps the
   UDP datagram under the common Ethernet path MTU (1500 − 20 IPv4 − 8 UDP = 1472) so a coalesced
   message is not IP-fragmented (the real hazard of over-large datagrams). The effective budget is
   min(this, buffer-capacity − 64). A single submessage larger than the budget is still sent (alone in
   its datagram), never truncated. Tunable; pinned to no spec constant (a local batching policy, not a
   wire field).")

(defun* %send-packed (node buf host port items)
    (function (disc-node dds.core.buffer:octet-buffer string (unsigned-byte 16) list) t)
  "Coalesce ITEMS — each a (SIZE . BUILD-FN) where BUILD-FN writes exactly ONE submessage of at most
   SIZE octets — into as few RTPS datagrams as fit the budget, one shared Header per datagram (RTPS 2.5
   §8.3.4 / §9.4.4), and send each to HOST:PORT. Before writing a submessage that would push a non-empty
   datagram past min(*COALESCE-DATAGRAM-BUDGET*, capacity−64), the current datagram is FLUSHED first
   (then the header — never overwritten — is reused), so the cursor never exceeds the budget (≪ buffer
   capacity): no buffer overflow on legitimate input. A submessage whose body does not end on a 4-octet
   boundary (RTPS 2.5 §8.3.4 requires submessages to start 32-bit-aligned) cannot be followed by another
   in the same datagram, so it is flushed as its datagram's last — a no-op for this stack (every DATA
   payload is XCDR-padded to 4, dispose=52, HEARTBEAT=28, all aligned), a graceful degrade otherwise.
   Cuts the sendto count from one-per-submessage to ceil(total/budget). NIL ITEMS sends nothing."
  (when items
    (let* ((budget (min *coalesce-datagram-budget*
                        (- (dds.core.buffer:octet-buffer-capacity buf) 64)))
           (mc (dds.core.buffer:cursor buf :endianness :little)))
      (dds.rtps.message:write-header mc (disc-node-guid-prefix node))
      (let ((hdr-end (dds.core.buffer:cursor-position mc)))
        (flet ((flush () (%send-raw-buf node buf (dds.core.buffer:cursor-position mc) host port)
                 (dds.core.buffer:cursor-set-position mc hdr-end)))
          (dolist (item items)
            (when (and (> (dds.core.buffer:cursor-position mc) hdr-end)
                       (> (+ (dds.core.buffer:cursor-position mc) (car item)) budget))
              (flush))                                   ; would overflow the datagram: send what we have first
            (funcall (cdr item) mc)                      ; write the submessage into the (possibly fresh) datagram
            (when (plusp (mod (dds.core.buffer:cursor-position mc) 4))
              (flush)))                                  ; non-4-aligned end: must be this datagram's last submessage
          (when (> (dds.core.buffer:cursor-position mc) hdr-end)
            (flush)))))))

(defun* %usable-destination (p)
    (function (dds.rtps.discovery:spdp-data) t)
  "A sendable (host . port) for user traffic to participant P, selected from its
   advertised locator LISTS: a routable UDPv4 default-unicast locator (host+port
   from that locator); else — if every default-unicast locator is non-routable — a
   routable metatraffic ADDRESS paired with a default-unicast PORT (same host, user
   port). NIL if none is usable. Foreign stacks (RTI) advertise several locators
   including 0.0.0.0 placeholders; this picks one that can actually be reached."
  (let* ((dlocs (dds.rtps.discovery:spdp-data-default-unicast-locators p))
         (mlocs (dds.rtps.discovery:spdp-data-metatraffic-unicast-locators p))
         (d (dds.rtps.discovery:usable-udpv4-locator dlocs))
         (m (dds.rtps.discovery:usable-udpv4-locator mlocs)))
    (cond
      (d (cons (dds.rtps.discovery:locator-ipv4-string d)
               (%locator-port (dds.rtps.discovery:locator-port d))))
      ((and m dlocs)
       (cons (dds.rtps.discovery:locator-ipv4-string m)
             (%locator-port (dds.rtps.discovery:locator-port (first dlocs)))))
      (t nil))))

(defun* %prefix-user-destination (node prefix)
    (function (disc-node (simple-array (unsigned-byte 8) (12))) (or null cons))
  "User-plane (host . port) for participant PREFIX, or NIL — the user-traffic twin of
   %REMOTE-METATRAFFIC (disc.lisp): look up the discovered SPDP record for the 12-octet GUID-prefix
   (RTPS 2.5 §9.4.4) and resolve its sendable default-unicast destination via %USABLE-DESTINATION.
   NIL when PREFIX is undiscovered or resolves to no usable (port>0) destination. Lets an inbound
   submessage (e.g. an ACKNACK) be answered at the originating participant ALONE instead of every
   matched peer."
  (let ((spdp (dds.pal:with-lock ((disc-node-lock node))
                (gethash prefix (disc-node-discovered node)))))
    (when spdp
      (let ((hp (%usable-destination spdp)))
        (when (and hp (plusp (cdr hp))) hp)))))

(defun* %reader-guid-p (guid)
    (function ((simple-array (unsigned-byte 8) (16))) t)
  "T iff the GUID's entity kind is a user reader (0x04 no-key / 0x07 with-key)."
  (let ((k (aref guid 15))) (or (= k #x04) (= k #x07))))

(defun* %writer-guid-p (guid)
    (function ((simple-array (unsigned-byte 8) (16))) t)
  "T iff the GUID's entity kind is a user writer (0x02 with-key / 0x03 no-key)."
  (let ((k (aref guid 15))) (or (= k #x02) (= k #x03))))

(defun* %endpoint-keyed-p (guid)
    (function ((simple-array (unsigned-byte 8) (16))) t)
  "T iff the endpoint GUID's entity kind is a WITH_KEY user endpoint: writer 0x02 or
   reader 0x07 (vs NO_KEY writer 0x03 / reader 0x04) — RTPS 2.5 §9.3.1.2 Table 9.1."
  (let ((k (aref guid 15))) (or (= k #x02) (= k #x07))))

(defun* %user-writer-entityid-p (entity-id)
    (function ((unsigned-byte 32)) t)
  "T iff ENTITY-ID's kind is an application-defined writer (0x02 with-key / 0x03 no-key) —
   a user-data writer, not a builtin (kind 0xc2). Lets the reader ACKNACK ANY matched
   remote writer's HEARTBEAT, not only a writer sharing this stack's local EntityId
   convention (a peer such as RTI Connext picks its own writer EntityIds)."
  (let ((k (logand entity-id #xff))) (or (= k #x02) (= k #x03))))

(defun* %matched-endpoints (node)
    (function (disc-node) list)
  "Snapshot of the remote endpoints matched to one of NODE's local endpoints."
  (dds.pal:with-lock ((disc-node-lock node))
    (loop for v being the hash-values of (disc-node-matches node) collect v)))

(defun* %match-destinations (node want-readers)
    (function (disc-node t) list)
  "User-traffic (host . port) destinations gated on MATCHING: the union of static
   PEERS and the participants holding a matched remote endpoint of the wanted kind —
   readers (WANT-READERS t) for a writer's DATA/HEARTBEAT, writers (nil) for a
   reader's ACKNACK. RxO-incompatible / topic-mismatched peers never match, so they
   receive nothing (FR-QOS-2: RxO now blocks delivery, not just the match)."
  (let ((dests (copy-list (disc-node-peers node)))
        (parts (%discovered-participants node)))
    (dolist (remote (%matched-endpoints node) dests)
      (let ((guid (dds.rtps.discovery:endpoint-data-guid remote)))
        (when (if want-readers (%reader-guid-p guid) (%writer-guid-p guid))
          (let ((spdp (find (subseq guid 0 12) parts
                            :key #'dds.rtps.discovery:spdp-data-guid-prefix :test #'equalp)))
            (when spdp
              (let ((hp (%usable-destination spdp)))
                (when (and hp (plusp (cdr hp)))
                  (pushnew hp dests :test #'equal))))))))))

(defparameter *debug-drop-fragment-numbers* nil
  "Debug-only fragment-loss injection (default NIL = off): a list of 1-based fragment
   numbers that %SEND-SAMPLE silently SKIPS when fragmenting a sample into DATA_FRAGs
   (both the initial push and sample-level ACKNACK retransmits). NACK_FRAG-driven
   resends (%ON-USER-NACK-FRAG) are NOT filtered, so the only recovery path for a
   dropped fragment is the peer's NACK_FRAG — proving fragment-level reliability
   against a live peer (RTPS 2.5 §8.3.8.12 NackFrag). Never set in production.")

(defparameter *debug-drop-sample-numbers* nil
  "Debug-only whole-sample-loss injection (default NIL = off): a list of sequence numbers whose
   non-fragmented DATA %SEND-SAMPLE silently SKIPS, proving lost-final-sample recovery via the
   periodic HEARTBEAT (RTPS 2.5 §8.4.2.2). Never set in production.")

(defun* %small-change-p (change)
    (function (dds.rtps.history:cache-change) t)
  "T iff CHANGE is a single-submessage (packable) change: a no-payload dispose/unregister (always
   small) or a :data sample whose serializedPayload fits one DATA submessage (≤ *fragment-size*, so it
   is NOT fragmented into a DATA_FRAG series). Large samples are sent individually by %send-sample."
  (or (not (eq (dds.rtps.history:cache-change-kind change) :data))
      (<= (length (dds.rtps.history:cache-change-serialized-payload change))
          dds.rtps.reliable:*fragment-size*)))

(defun* %data-builder (node change)
    (function (disc-node dds.rtps.history:cache-change) cons)
  "A (SIZE . BUILD-FN) packable item for the SMALL CHANGE (for %send-packed), dispatching on KIND (RTPS
   2.5 §9.4.5.4): a :data change writes one DATA (write-data, D-flag, no inlineQos — byte-identical to
   %send-sample's small branch), SIZE = 4 submsg-header + 20 body-prefix + payload; a :dispose/:unregister
   writes one no-payload DATA (write-data-dispose, flags E+Q, inlineQos PID_KEY_HASH + PID_STATUS_INFO,
   §9.6.4.9), SIZE = 4 + 52. SIZE is the exact submessage length — the fit bound %send-packed checks
   before writing so the datagram never overflows the buffer."
  (let ((sn (dds.rtps.history:cache-change-sn change))
        (wid (disc-node-user-writer-id node)))
    (if (eq (dds.rtps.history:cache-change-kind change) :data)
        (let ((pl (dds.rtps.history:cache-change-serialized-payload change)))
          (cons (+ 24 (length pl))
                (lambda (mc) (dds.rtps.message:write-data
                              mc dds.rtps.message:+entityid-unknown+ wid sn pl 0 (length pl)))))
        (let ((kh (dds.rtps.history:cache-change-instance-key-hash change))
              (si (dds.rtps.history:cache-change-status-info change)))
          (cons 56
                (lambda (mc) (dds.rtps.message:write-data-dispose
                              mc dds.rtps.message:+entityid-unknown+ wid sn kh si)))))))

(defun* %heartbeat-builder (node first last count)
    (function (disc-node integer integer integer) cons)
  "A (SIZE . BUILD-FN) packable item for one NON-FINAL user-writer HEARTBEAT (FIRST,LAST,COUNT) —
   readerId UNKNOWN, FinalFlag NOT_SET so it solicits an ACKNACK (RTPS 2.5 §8.3.7.5 / §8.4.9.2.7);
   mirrors %send-user-heartbeat. SIZE = 4 submsg-header + 28 body."
  (let ((wid (disc-node-user-writer-id node)))
    (cons 32
          (lambda (mc) (dds.rtps.message:write-heartbeat
                        mc dds.rtps.message:+entityid-unknown+ wid first last count :final nil)))))

(defun* %send-changes-packed (node buf changes host port hb)
    (function (disc-node dds.core.buffer:octet-buffer list string (unsigned-byte 16) (or null cons)) t)
  "Send CHANGES (+ optional trailing HEARTBEAT item HB, a (SIZE . BUILD-FN)) to HOST:PORT, coalescing the
   small ones into as few datagrams as fit the budget (%send-packed): collect a %data-builder item per
   SMALL change (a SN in *DEBUG-DROP-SAMPLE-NUMBERS* is skipped — loss injection preserved), send each
   LARGE change individually via %send-sample (already one datagram per fragment group), append HB, then
   pack. This is the shared writer push/retransmit emit path (RTPS 2.5 §8.3.4 §8.4.2.2)."
  (let ((items '()))
    (dolist (change changes)
      (let ((sn (dds.rtps.history:cache-change-sn change)))
        (cond
          ((and *debug-drop-sample-numbers* (member sn *debug-drop-sample-numbers*)))
          ((%small-change-p change) (push (%data-builder node change) items))
          (t (%send-sample node buf sn
                           (dds.rtps.history:cache-change-serialized-payload change) host port)))))
    (when hb (push hb items))
    (%send-packed node buf host port (nreverse items))))

(defun* %send-sample (node buf sn pl host port)
    (function (disc-node dds.core.buffer:octet-buffer integer (simple-array (unsigned-byte 8) (*)) string (unsigned-byte 16)) t)
  "Send sample (SN, PL) to HOST:PORT: one DATA submessage if PL fits *fragment-size*, else a
   series of DATA_FRAG submessages (packing as many fragments as fit the datagram) followed by
   a HEARTBEAT_FRAG. Uses BUF (tx-msg or rx-tx-msg) as the scratch message buffer. A submessage
   containing a fragment named in *DEBUG-DROP-FRAGMENT-NUMBERS* is skipped, and a non-fragmented
   DATA whose SN is in *DEBUG-DROP-SAMPLE-NUMBERS* is skipped (loss injection)."
  (let ((size (length pl)))
    (if (<= size dds.rtps.reliable:*fragment-size*)
        (unless (and *debug-drop-sample-numbers* (member sn *debug-drop-sample-numbers*))
          (%send-msg-buf node buf
                         (lambda (mc) (dds.rtps.message:write-data
                                       mc dds.rtps.message:+entityid-unknown+ (disc-node-user-writer-id node) sn pl 0 size))
                         host port))
        (let ((budget (- (dds.core.buffer:octet-buffer-capacity buf) 64)))
          (dolist (desc (dds.rtps.reliable:writer-frag-plan size dds.rtps.reliable:*fragment-size* budget))
            (destructuring-bind (fstart fcount off len) desc
              (unless (and *debug-drop-fragment-numbers*
                           (loop for f from fstart below (+ fstart fcount)
                                   thereis (member f *debug-drop-fragment-numbers*)))
                (%send-msg-buf node buf
                               (lambda (mc) (dds.rtps.message:write-data-frag
                                             mc dds.rtps.message:+entityid-unknown+ (disc-node-user-writer-id node) sn size
                                             fstart fcount dds.rtps.reliable:*fragment-size* pl off len))
                               host port))))
          (multiple-value-bind (lastfrag cnt)
              (dds.rtps.reliable:writer-frag-heartbeat (disc-node-user-writer node) sn)
            (when lastfrag
              (%send-msg-buf node buf
                             (lambda (mc) (dds.rtps.message:write-heartbeat-frag
                                           mc dds.rtps.message:+entityid-unknown+ (disc-node-user-writer-id node) sn lastfrag cnt))
                             host port)))))))

(defun* %send-user-heartbeat (node buf first last count host port)
    (function (disc-node dds.core.buffer:octet-buffer integer integer integer string (unsigned-byte 16)) t)
  "Send one NON-FINAL user-writer HEARTBEAT (FIRST,LAST,COUNT) to HOST:PORT (RTPS 2.5 §8.3.7.5;
   readerId = ENTITYID_UNKNOWN, FinalFlag NOT_SET per the Reliable StatefulWriter T7 transition §8.4.9.2.7),
   prompting the reader to ACKNACK. BUF selects the thread's scratch message buffer."
  (%send-msg-buf node buf
                 (lambda (mc)
                   (dds.rtps.message:write-heartbeat
                    mc dds.rtps.message:+entityid-unknown+ (disc-node-user-writer-id node) first last count :final nil))
                 host port))

(defun* %reader-push-targets (node)
    (function (disc-node) list)
  "Per matched-reader DESTINATION, a ((host . port) READER-KEY…) group for the writer push path: the
   keys are the FULL 16-octet GUIDs of EVERY matched reader resolving to that (host . port) (RTPS 2.5
   §8.3.5.4 — a SN is unique only within one writer GUID, and the corresponding ACKNACK keys by the
   same remote reader GUID, %on-user-acknack). Two DataReaders in one remote participant share a
   unicast destination — a DATA with readerId UNKNOWN reaches both — so they are grouped, not deduped
   away: the push sends the union to the destination ONCE while advancing EACH reader's unsent-base
   (%merge-unsent, %push-data), keeping every co-located reader's send-once accounting honest. Falls
   back to the union of static PEERS, each carrying this node's local reader-id, when no matched reader
   endpoint resolves to a destination (the discovery-less test path)."
  (let ((groups '())   ; alist: (host . port) -> list of matched reader GUID keys at that destination
        (parts (%discovered-participants node)))
    (dolist (remote (%matched-endpoints node))
      (let ((guid (dds.rtps.discovery:endpoint-data-guid remote)))
        (when (%reader-guid-p guid)
          (let ((spdp (find (subseq guid 0 12) parts
                            :key #'dds.rtps.discovery:spdp-data-guid-prefix :test #'equalp)))
            (when spdp
              (let ((hp (%usable-destination spdp)))
                (when (and hp (plusp (cdr hp)))
                  (let ((cell (assoc hp groups :test #'equal)))
                    (if cell
                        (pushnew (copy-seq guid) (cdr cell) :test #'equalp)
                        (push (list hp (copy-seq guid)) groups))))))))))
    (dolist (peer (disc-node-peers node))
      (unless (assoc peer groups :test #'equal)
        (push (list peer (disc-node-user-reader-id node)) groups)))
    groups))

(defun* %merge-unsent (writer keys)
    (function (dds.rtps.reliable:rtps-writer list) list)
  "The UNSENT CacheChanges to push ONCE to a destination shared by the readers KEYS, in ascending SN
   order. For the common single-reader destination this is exactly writer-unsent-list (no merge, no
   extra alloc — byte-identical to the prior path). For co-located readers it calls writer-unsent-list
   for EACH key — advancing EACH reader's unsent-base watermark so none re-pushes history on a later
   write (RTPS 2.5 §8.4.2.2) — and returns the SN-deduplicated union (the lower-base set when joins are
   staggered); one datagram per change reaches every reader at the destination via readerId UNKNOWN
   (§8.3.5.4)."
  (if (null (cdr keys))
      (dds.rtps.reliable:writer-unsent-list writer (car keys))
      (let ((merged '()))
        (dolist (k keys)
          (dolist (ch (dds.rtps.reliable:writer-unsent-list writer k))
            (let ((sn (dds.rtps.history:cache-change-sn ch)))
              (unless (find sn merged :key #'dds.rtps.history:cache-change-sn :test #'=)
                (push ch merged)))))
        (sort merged #'< :key #'dds.rtps.history:cache-change-sn))))

(defun* %push-data (node)
    (function (disc-node) t)
  "Writer side: send each UNSENT change ONCE as a DATA (or DATA_FRAG series for large samples)
   submessage, COALESCED with the trailing HEARTBEAT into as few datagrams as fit the budget
   (%send-changes-packed, RTPS 2.5 §8.3.4/§8.4.2.2; caller thread, uses tx-msg) — to each matched-reader
   DESTINATION. The unsent-base watermark is kept PER matched reader (keyed by its full GUID, §8.3.5.4);
   %merge-unsent advances every reader sharing a destination and sends their union to that destination
   once (so two DataReaders in one participant both get send-once accounting, not just the first). Lost
   or late changes are repaired only via the reader's ACKNACK (%on-user-acknack), not by re-pushing the
   whole unacked history."
  (let ((writer (disc-node-user-writer node)))
    (multiple-value-bind (first last count) (dds.rtps.reliable:writer-heartbeat writer)
      (dolist (group (%reader-push-targets node))   ; DATA + HEARTBEAT -> each matched-reader destination
        (%send-changes-packed node (disc-node-tx-msg node)
                              (%merge-unsent writer (cdr group)) (caar group) (cdar group)
                              (%heartbeat-builder node first last count))))))

(defun* %push-heartbeat (node)
    (function (disc-node) (eql t))
  "Writer side: send a PERIODIC standalone non-final HEARTBEAT (no new DATA) to each matched
   reader on the announce cadence (RTPS 2.5 §8.4.2.2: a reliable Writer must periodically inform
   each matching reliable Reader of the availability of a sample; Reliable StatefulWriter T7
   transition §8.4.9.2.7). This closes the lost-final-sample edge: when a reliable writer's final sample's
   DATA was lost and no further write follows, nothing else re-prompts the reader to NACK, so the
   gap is never repaired; the periodic HEARTBEAT keeps reliability live and triggers the ACKNACK
   repair path. Non-final (FinalFlag NOT_SET) so it solicits an ACKNACK. A no-op on an empty
   HistoryCache (LAST < FIRST), no user writer, or no matched readers (uses tx-msg, caller thread)."
  (let ((w (disc-node-user-writer node)))
    (when w
      (multiple-value-bind (first last count) (dds.rtps.reliable:writer-heartbeat w)
        (when (>= last first)
          (dolist (peer (%match-destinations node t))
            (%send-user-heartbeat node (disc-node-tx-msg node) first last count (car peer) (cdr peer)))))))
  t)

(defun* publish-sample (node payload)
    (function (disc-node (simple-array (unsigned-byte 8) (*))) (eql t))
  "Publish PAYLOAD (an opaque SerializedPayload) on the node's user writer: add it
   to the writer HistoryCache, then push DATA + HEARTBEAT to peers (FR-RTPS-8)."
  (dds.rtps.reliable:writer-write (disc-node-user-writer node) payload)
  (%push-data node)
  t)

(defun* %dispose-or-unregister (node key-hash status-flags)
    (function (disc-node (simple-array (unsigned-byte 8) (16)) (unsigned-byte 8)) integer)
  "Writer side: add a dispose/unregister change for the instance named by KEY-HASH (16 octets)
   to the user writer's HistoryCache (writer-lifecycle-change, deriving the KIND from
   STATUS-FLAGS), then push DATA + HEARTBEAT to peers exactly like publish-sample — so the
   lifecycle DATA is sent AND reliably ACKNACK-repairable (RTPS 2.5 §8.4.2.2 / §9.6.4.9).
   Returns the change's sequence number."
  (let ((sn (dds.rtps.reliable:writer-lifecycle-change (disc-node-user-writer node) key-hash status-flags)))
    (%push-data node)
    sn))

(defun* dispose-instance (node key-hash)
    (function (disc-node (simple-array (unsigned-byte 8) (16))) integer)
  "Dispose the instance named by KEY-HASH on NODE's user writer (DDS 1.4 §2.2.2.4.2.10): emit a
   no-payload dispose DATA (StatusInfo Disposed, RTPS 2.5 §9.6.4.9) over the reliable engine.
   Returns the change SN. Mirrors publish-sample so the dispose is reliably repairable."
  (%dispose-or-unregister node key-hash dds.rtps.message:+statusinfo-disposed+))

(defun* unregister-instance (node key-hash &optional (autodispose t))
    (function (disc-node (simple-array (unsigned-byte 8) (16)) &optional t) integer)
  "Unregister the instance named by KEY-HASH on NODE's user writer (DDS 1.4 §2.2.2.4.2.7): emit a
   no-payload unregister DATA over the reliable engine. When AUTODISPOSE is true (the
   WRITER_DATA_LIFECYCLE default, DDS 1.4 §2.2.3.21) the StatusInfo is Disposed|Unregistered (the
   unregister also disposes the instance, behaviour identical to a dispose before the unregister);
   when false it is Unregistered only (RTPS 2.5 §9.6.4.9). Returns the change SN. Mirrors
   publish-sample so the unregister is reliably repairable."
  (%dispose-or-unregister
   node key-hash
   (if autodispose
       (logior dds.rtps.message:+statusinfo-unregistered+ dds.rtps.message:+statusinfo-disposed+)
       dds.rtps.message:+statusinfo-unregistered+)))

(defun* %source-guid (src-prefix writer-id)
    (function ((simple-array (unsigned-byte 8) (12)) (unsigned-byte 32)) (simple-array (unsigned-byte 8) (16)))
  "Assemble the 16-octet source GUID from the datagram's RTPS-header SRC-PREFIX (§9.4.4) and the
   DATA submessage's WRITER-ID EntityId (§9.3.1.2) — the key for EXCLUSIVE ownership arbitration."
  (let ((g (make-array 16 :element-type '(unsigned-byte 8))))
    (replace g src-prefix :end2 12)
    (setf (aref g 12) (ldb (byte 8 24) writer-id) (aref g 13) (ldb (byte 8 16) writer-id)
          (aref g 14) (ldb (byte 8 8) writer-id) (aref g 15) (ldb (byte 8 0) writer-id))
    g))

(defun* %on-user-lifecycle (node writer-id sn kind key-hash status-flags src-prefix)
    (function (disc-node (unsigned-byte 32) integer (member :dispose :unregister) t (unsigned-byte 8)
              (simple-array (unsigned-byte 8) (12))) t)
  "Reader side: a no-payload dispose/unregister DATA arrived from WRITER-ID at SRC-PREFIX (RTPS 2.5
   §9.6.4.9). Feed its SN to the reliable reader (so the ACKNACK/HEARTBEAT bookkeeping treats it as a
   real change), record (KIND KEY-HASH STATUS-FLAGS WRITER-ID SOURCE-GUID) by SN — the full 16-octet
   source GUID (§9.4.4 prefix + EntityId) lets S2 owner-clear target the EXACT disposing writer (DDS
   1.4 §2.2.3.9.2; an EntityId alone aliases writers sharing 0x102 across participants) — then fire the
   DCPS-facing lifecycle-event callback OUTSIDE the node lock (mirrors %deliver-user-sample). Gated on
   a matched user writer EntityId."
  (when (and (disc-node-user-reader node) (%user-writer-entityid-p writer-id))
    (let ((guid (%source-guid src-prefix writer-id)))
      (dds.rtps.reliable:reader-on-data (disc-node-user-reader node) guid sn
                                        (make-array 0 :element-type '(unsigned-byte 8)))
      (dds.pal:with-lock ((disc-node-lock node))
        ;; 2-level (source-GUID -> SN) keying mirrors the data store: a SequenceNumber is unique only
        ;; within one writer GUID (RTPS 2.5 §8.3.5.4), so two writers sharing EntityId 0x102 on different
        ;; participants disposing different instances at the SAME SN do not clobber each other.
        (setf (gethash sn (%inner-table (disc-node-lifecycle-changes node) guid))
              (list kind key-hash status-flags writer-id guid))))
    (when (disc-node-on-lifecycle-event node)
      (funcall (disc-node-on-lifecycle-event node) writer-id sn kind key-hash status-flags)))
  t)

(defun* node-lifecycle-change (node key)
    (function (disc-node cons) t)
  "The received lifecycle change for composite KEY (a (GUID . SN) cons, see node-lifecycle-sns) as
   (kind key-hash status-flags writer-id source-guid), or NIL. Lets a subscriber observe that a
   dispose/unregister DATA was received and classified (S1), and lets the user-thread S2 consumer
   (%drain) recover the originating writer (EntityId to drop it from the instance's writers-set on an
   :unregister, DDS 1.4 §2.2.2.5.1.3; full 16-octet SOURCE-GUID to clear ownership of only the exact
   disposing writer, §2.2.3.9.2). Keyed by GUID then SN (§8.3.5.4) so two writers sharing EntityId 0x102
   never alias in the SN space."
  (dds.pal:with-lock ((disc-node-lock node))
    (let ((inner (gethash (car key) (disc-node-lifecycle-changes node))))
      (and inner (gethash (cdr key) inner)))))

(defun* node-lifecycle-change-by-sn (node sn)
    (function (disc-node integer) t)
  "The lifecycle change of ANY received dispose/unregister whose RTPS SN equals SN, or NIL. A
   single-writer convenience (the store is keyed by GUID then SN, §8.3.5.4) — for tests/diagnostics
   that know only the SN, mirroring node-sample-by-sn."
  (dds.pal:with-lock ((disc-node-lock node))
    (loop for inner being the hash-values of (disc-node-lifecycle-changes node)
          thereis (gethash sn inner))))

(defun* node-lifecycle-count (node)
    (function (disc-node) (integer 0))
  "Number of distinct dispose/unregister lifecycle DATAs the subscriber has received (S1), summed over
   every writer's inner SN map."
  (dds.pal:with-lock ((disc-node-lock node))
    (let ((n 0))
      (maphash (lambda (g inner) (declare (ignore g)) (incf n (hash-table-count inner)))
               (disc-node-lifecycle-changes node))
      n)))

(defun* node-lifecycle-sns (node)
    (function (disc-node) list)
  "Composite (GUID . SN) cons keys of the dispose/unregister lifecycle DATAs received so far (unordered).
   Lets the user-thread S2 consumer (%drain) drain newly-classified lifecycle changes the same way
   node-sample-sns drains data samples — per writer GUID, without assuming SNs start at 1 (Connext may
   not) and without aliasing two writers sharing EntityId 0x102 (§8.3.5.4). The cons is built here on
   the user thread, not on the per-change receive path (NFR-MEM)."
  (dds.pal:with-lock ((disc-node-lock node))
    (let ((keys '()))
      (maphash (lambda (guid inner)
                 (loop for sn being the hash-keys of inner do (push (cons guid sn) keys)))
               (disc-node-lifecycle-changes node))
      keys)))

(defun* %inner-table (outer guid)
    (function (hash-table (simple-array (unsigned-byte 8) (16))) hash-table)
  "The per-writer inner SN->value table for 16-octet GUID in OUTER, created on first use (RTPS 2.5
   §8.3.5.4: a SequenceNumber is unique only within one writer GUID, so each writer GUID owns an
   independent eql-keyed SN map; no per-sample composite-key allocation)."
  (or (gethash guid outer)
      (setf (gethash (copy-seq guid) outer) (make-hash-table :test 'eql))))

(defun* %deliver-user-sample (node writer-id sn vec src-prefix)
    (function (disc-node (unsigned-byte 32) integer (simple-array (unsigned-byte 8) (*))
              (simple-array (unsigned-byte 8) (12))) t)
  "Feed a complete user sample VEC (SN from WRITER-ID at SRC-PREFIX) to the reliable reader, record it
   under the 2-level (source-GUID -> SN) store (payload + writer EntityId for the S2 writers-set + full
   source GUID for S1 EXCLUSIVE ownership arbitration), then fire ON-SAMPLE outside the node lock
   (DATA_AVAILABLE + WaitSet wake). Two-level keying by GUID then SN avoids a per-sample composite-key
   alloc (NFR-MEM) and stops two writers sharing EntityId 0x102 from aliasing in the SN space
   (§8.3.5.4); ONE %source-guid per sample is reused for the reliable-reader proxy key AND the three inner tables."
  (let ((guid (%source-guid src-prefix writer-id)))
    (dds.rtps.reliable:reader-on-data (disc-node-user-reader node) guid sn vec)
    (dds.pal:with-lock ((disc-node-lock node))
      (setf (gethash sn (%inner-table (disc-node-samples node) guid)) vec
            (gethash sn (%inner-table (disc-node-sample-writers node) guid)) writer-id
            (gethash sn (%inner-table (disc-node-sample-writer-guids node) guid)) guid)))
  (when (disc-node-on-sample node) (funcall (disc-node-on-sample node)))
  t)

(defun* %on-user-data (node writer-id sn buf poff plen src-prefix)
    (function (disc-node (unsigned-byte 32) integer dds.core.buffer:octet-buffer (integer 0) (integer 0)
              (simple-array (unsigned-byte 8) (12))) t)
  "Reader side: copy the [poff,plen) SerializedPayload out of the receive buffer and deliver it
   (dedup/reorder, store by SN, fire ON-SAMPLE outside the node lock — no lock-order inversion)."
  (let ((vec (make-array plen :element-type '(unsigned-byte 8))))
    (replace vec (dds.core.buffer:octet-buffer-vec buf) :start2 poff :end2 (+ poff plen))
    (%deliver-user-sample node writer-id sn vec src-prefix)))

(defun* %on-user-heartbeat (node c flags src-prefix)
    (function (disc-node dds.core.buffer:cursor (unsigned-byte 8) (simple-array (unsigned-byte 8) (12))) t)
  "Reader side: apply the HEARTBEAT's available range, then answer with an ACKNACK
   (acking received SNs, NACKing the rest) to each peer (uses rx-tx-msg). The reliable reader-proxy is
   keyed by the remote writer's FULL 16-octet GUID (SRC-PREFIX + WID, §9.4.4 / §9.3.1.2) so two writers
   sharing EntityId 0x102 across participants keep independent received-SN / ACKNACK state (§8.3.5.4)."
  (multiple-value-bind (rid wid first last count finalp livep)
      (dds.rtps.message:parse-heartbeat-body c flags)
    (declare (ignore rid count finalp livep))
    (when (and (disc-node-user-reader node) (%user-writer-entityid-p wid))
      (let ((reader (disc-node-user-reader node))
            (wguid (%source-guid src-prefix wid)))
        (dds.rtps.reliable:reader-on-heartbeat reader wguid first last)
        (multiple-value-bind (base numbits bitmap) (dds.rtps.reliable:reader-acknack reader wguid)
          (let ((cnt (incf (disc-node-ack-count node))))
            (dolist (peer (%match-destinations node nil))   ; ACKNACK -> matched writers
              (%send-msg-buf node (disc-node-rx-tx-msg node)
                             (lambda (mc)
                               ;; writerEntityId = the REMOTE writer's id (WID), so the peer
                               ;; routes the ACKNACK to its writer (not our local convention).
                               (dds.rtps.message:write-acknack
                                mc (disc-node-user-reader-id node) wid base numbits bitmap cnt :final t))
                             (car peer) (cdr peer))))))))
  t)

(defun* %on-user-acknack (node c flags src-prefix)
    (function (disc-node dds.core.buffer:cursor (unsigned-byte 8) (simple-array (unsigned-byte 8) (12))) t)
  "Writer side: on an ACKNACK, retransmit each NACKed change as a DATA submessage to the ONE reader
   that NACKed (uses rx-tx-msg). GAPs are not needed (KEEP_ALL never drops). The reader-proxy is keyed
   by the REMOTE reader's FULL 16-octet GUID (SRC-PREFIX + the ACKNACK's reader EntityId RID, §9.4.4 /
   §9.3.1.2) — the SAME key %push-data uses for that reader — so two readers sharing EntityId 0x107
   across participants advance independent acked-base watermarks (§8.3.5.4). The resend goes ONLY to the
   ACKNACKing participant's destination, resolved from SRC-PREFIX (a NACK is from exactly one reader, so
   fanning the resend out to every matched reader is pure over-send — harmless under KEEP_ALL but
   wasteful); falls back to every matched reader only when the prefix is undiscovered (the
   discovery-less test path)."
  (multiple-value-bind (rid wid base numbits bitmap count finalp)
      (dds.rtps.message:parse-acknack-body c flags)
    (declare (ignore count finalp))
    (when (= wid (disc-node-user-writer-id node))
      (incf (disc-node-acks-in node))   ; a matched reader (incl. RTI) acked our writer
      (multiple-value-bind (resends gaps)
          (dds.rtps.reliable:writer-on-acknack (disc-node-user-writer node)
                                               (%source-guid src-prefix rid) base numbits bitmap)
        (declare (ignore gaps))
        (let* ((dest (%prefix-user-destination node src-prefix))
               (peers (if dest (list dest) (%match-destinations node t))))
          (dolist (peer peers)   ; retransmit DATA(_FRAG) / dispose -> the NACKing reader (coalesced, no HB)
            (%send-changes-packed node (disc-node-rx-tx-msg node) resends (car peer) (cdr peer) nil))))))
  t)

(defun* %on-user-data-frag (node c flags body-len buf src-prefix)
    (function (disc-node dds.core.buffer:cursor (unsigned-byte 8) (integer 0) dds.core.buffer:octet-buffer
              (simple-array (unsigned-byte 8) (12))) t)
  "Reader side: accept a DATA_FRAG, reassemble; on the final fragment deliver the complete sample."
  (multiple-value-bind (rdr wtr sn ssize fstart frags fsize poff plen keyp)
      (dds.rtps.message:parse-data-frag-body c flags body-len)
    (declare (ignore rdr keyp))
    (when (and (disc-node-user-reader node) (%user-writer-entityid-p wtr))
      (let ((region (make-array plen :element-type '(unsigned-byte 8)))
            (wguid (%source-guid src-prefix wtr)))
        (replace region (dds.core.buffer:octet-buffer-vec buf) :start2 poff :end2 (+ poff plen))
        (let ((done (dds.rtps.reliable:reader-on-data-frag
                     (disc-node-user-reader node) wguid sn fstart frags fsize ssize region)))
          (when done (%deliver-user-sample node wtr sn done src-prefix))))))
  t)

(defun* %on-user-heartbeat-frag (node c flags src-prefix)
    (function (disc-node dds.core.buffer:cursor (unsigned-byte 8) (simple-array (unsigned-byte 8) (12))) t)
  "Reader side: on a HEARTBEAT_FRAG, NACK_FRAG the still-missing fragments to matched writers. The
   reassembly proxy is keyed by the remote writer's FULL 16-octet GUID (SRC-PREFIX + WID, §9.4.4 /
   §9.3.1.2) so two writers sharing EntityId 0x102 keep independent reassembly state (§8.3.5.4)."
  (multiple-value-bind (rid wid sn lastfrag count) (dds.rtps.message:parse-heartbeat-frag-body c flags)
    (declare (ignore rid lastfrag count))
    (when (and (disc-node-user-reader node) (%user-writer-entityid-p wid))
      (multiple-value-bind (base numbits bitmap)
          (dds.rtps.reliable:reader-frag-acknack (disc-node-user-reader node) (%source-guid src-prefix wid) sn)
        (when base
          (let ((cnt (incf (disc-node-ack-count node))))
            (dolist (peer (%match-destinations node nil))
              (%send-msg-buf node (disc-node-rx-tx-msg node)
                             (lambda (mc) (dds.rtps.message:write-nack-frag
                                           mc (disc-node-user-reader-id node) wid sn base numbits bitmap cnt))
                             (car peer) (cdr peer))))))))
  t)

(defun* %on-user-nack-frag (node c flags)
    (function (disc-node dds.core.buffer:cursor (unsigned-byte 8)) t)
  "Writer side: on a NACK_FRAG, resend exactly the named fragments as DATA_FRAGs to matched readers."
  (multiple-value-bind (rid wid sn base numbits bitmap count) (dds.rtps.message:parse-nack-frag-body c flags)
    (declare (ignore rid count))
    (when (= wid (disc-node-user-writer-id node))
      (let ((descs (dds.rtps.reliable:writer-on-nack-frag (disc-node-user-writer node) sn base numbits bitmap))
            (pl (dds.rtps.reliable:writer-sample-payload (disc-node-user-writer node) sn)))
        (when (and descs pl)
          (let ((size (length pl)))
            (dolist (peer (%match-destinations node t))
              (dolist (desc descs)
                (destructuring-bind (fstart fcount off len) desc
                  (%send-msg-buf node (disc-node-rx-tx-msg node)
                                 (lambda (mc) (dds.rtps.message:write-data-frag
                                               mc dds.rtps.message:+entityid-unknown+ (disc-node-user-writer-id node) sn size
                                               fstart fcount dds.rtps.reliable:*fragment-size* pl off len))
                                 (car peer) (cdr peer)))))))))
    t))

(defun* enable-publisher (node)
    (function (disc-node) disc-node)
  "Give NODE a reliable user writer (KEEP_ALL) and install the writer-side data-
   plane hooks (retransmit on ACKNACK; resend named fragments on NACK_FRAG). Call after add-local-writer."
  (setf (disc-node-user-writer node)
        (dds.rtps.reliable:make-rtps-writer
         :hc (dds.rtps.history:make-history-cache :keep-all 1 nil nil)))
  (setf (disc-node-on-acknack node) (lambda (c flags src-prefix) (%on-user-acknack node c flags src-prefix)))
  (setf (disc-node-on-nack-frag node) (lambda (c flags) (%on-user-nack-frag node c flags)))
  node)

(defun* enable-subscriber (node)
    (function (disc-node) disc-node)
  "Give NODE a reliable user reader and install the reader-side data-plane hooks (store DATA,
   ACKNACK on HEARTBEAT, reassemble DATA_FRAG, NACK_FRAG on HEARTBEAT_FRAG). Call after add-local-reader."
  (setf (disc-node-user-reader node) (dds.rtps.reliable:make-rtps-reader))
  (setf (disc-node-on-data node)
        (lambda (wid sn buf poff plen src-prefix) (%on-user-data node wid sn buf poff plen src-prefix)))
  (setf (disc-node-on-lifecycle node)
        (lambda (wid sn kind kh sf src-prefix) (%on-user-lifecycle node wid sn kind kh sf src-prefix)))
  (setf (disc-node-on-heartbeat node)
        (lambda (c flags src-prefix) (%on-user-heartbeat node c flags src-prefix)))
  (setf (disc-node-on-data-frag node)
        (lambda (c flags body-len buf src-prefix) (%on-user-data-frag node c flags body-len buf src-prefix)))
  (setf (disc-node-on-heartbeat-frag node)
        (lambda (c flags src-prefix) (%on-user-heartbeat-frag node c flags src-prefix)))
  node)

(defun* node-sample-count (node)
    (function (disc-node) (integer 0))
  "Number of distinct user samples the subscriber has received (summed over every writer's inner
   SN map)."
  (dds.pal:with-lock ((disc-node-lock node))
    (let ((n 0))
      (maphash (lambda (g inner) (declare (ignore g)) (incf n (hash-table-count inner)))
               (disc-node-samples node))
      n)))

(defun* node-sample-key-sn (key)
    (function (cons) integer)
  "Recover the raw RTPS SequenceNumber from a (GUID . SN) composite sample KEY (§8.3.5.4)."
  (cdr key))

(defun* node-sample (node key)
    (function (disc-node cons) t)
  "The received payload for composite sample KEY (a (GUID . SN) cons, see node-sample-sns), or NIL."
  (dds.pal:with-lock ((disc-node-lock node))
    (let ((inner (gethash (car key) (disc-node-samples node))))
      (and inner (gethash (cdr key) inner)))))

(defun* node-sample-by-sn (node sn)
    (function (disc-node integer) t)
  "The payload of ANY received user sample whose RTPS SN equals SN, or NIL. A single-writer convenience
   (the sample store is keyed by GUID then SN, §8.3.5.4) — for tests/diagnostics that know only the SN."
  (dds.pal:with-lock ((disc-node-lock node))
    (loop for inner being the hash-values of (disc-node-samples node)
          thereis (gethash sn inner))))

(defun* node-sample-sns (node)
    (function (disc-node) list)
  "Composite (GUID . SN) cons keys of the user samples received so far (unordered). Lets a subscriber
   drain new samples per writer without assuming SNs start at 1 (Connext may not) and without aliasing
   two writers that share EntityId 0x102 (§8.3.5.4). The cons is built here on the user thread, not on
   the per-sample receive path (NFR-MEM)."
  (dds.pal:with-lock ((disc-node-lock node))
    (let ((keys '()))
      (maphash (lambda (guid inner)
                 (loop for sn being the hash-keys of inner do (push (cons guid sn) keys)))
               (disc-node-samples node))
      keys)))

(defun* node-sample-writer (node key)
    (function (disc-node cons) t)
  "The remote writer EntityId that wrote the user sample at composite KEY (a (GUID . SN) cons), or NIL.
   Lets the DCPS reader register which writer keeps an instance alive (the writers-set,
   DDS 1.4 §2.2.2.5.1.3) so a writer vanishing can transition the instance NOT_ALIVE_NO_WRITERS."
  (dds.pal:with-lock ((disc-node-lock node))
    (let ((inner (gethash (car key) (disc-node-sample-writers node))))
      (and inner (gethash (cdr key) inner)))))

(defun* node-sample-writer-guid (node key)
    (function (disc-node cons) t)
  "The FULL 16-octet source GUID (RTPS-header prefix + DATA writer EntityId, §9.3.1.2) that wrote the
   user sample at composite KEY (a (GUID . SN) cons), or NIL. The key for EXCLUSIVE ownership
   arbitration (DDS 1.4 §2.2.3.9.2): two writers on different participants share an EntityId, so the
   GUID — not the EntityId — distinguishes them when selecting the highest-strength owner of an
   instance."
  (dds.pal:with-lock ((disc-node-lock node))
    (let ((inner (gethash (car key) (disc-node-sample-writer-guids node))))
      (and inner (gethash (cdr key) inner)))))

(defun* matched-writer-ownership (node guid)
    (function (disc-node (simple-array (unsigned-byte 8) (16))) (values t t))
  "The (values OWNERSHIP-KIND OWNERSHIP-STRENGTH) of the matched remote writer with 16-octet GUID,
   read from its endpoint-data QoS in NODE's matches table (the SEDP-carried OwnershipQosPolicy +
   OwnershipStrengthQosPolicy, RTPS 2.5 §8.5.4 / DDS 1.4 §2.2.3.9-.10). (values NIL NIL) when GUID is
   not (or no longer) matched — the writer vanished; the caller treats that as not-the-owner."
  (let ((ep (dds.pal:with-lock ((disc-node-lock node))
              (gethash guid (disc-node-matches node)))))
    (if ep
        (let ((q (dds.rtps.discovery:endpoint-data-qos ep)))
          (values (dds.qos:qos-ownership q) (dds.qos:qos-ownership-strength q)))
        (values nil nil))))

(defun* node-discovered-participants (node)
    (function (disc-node) list)
  "Snapshot of the SPDP data for every participant NODE has discovered (diagnostic)."
  (%discovered-participants node))

(defun* resolved-destination (p)
    (function (dds.rtps.discovery:spdp-data) t)
  "The (host . port) this stack would send user data to for participant P (its
   resolved routable locator), or NIL — exactly what the data plane uses. Diagnostic."
  (%usable-destination p))

(defun* node-acks-in (node)
    (function (disc-node) integer)
  "Count of ACKNACKs received for this node's user writer — i.e. how many times a
   matched reader (incl. a foreign one like RTI) acknowledged our data. >0 proves a
   remote reliable reader is actually receiving our samples. Diagnostic."
  (disc-node-acks-in node))

(defun* run-dataplane-test ()
    (function () (eql t))
  "Full stack over UDP: two participants discover (SPDP) and match (SEDP), then the
   publisher sends a user sample the subscriber receives reliably (DATA + HEARTBEAT
   -> ACKNACK). Asserts the exact payload bytes arrive within a bounded wait. The
   reliable protocol makes this robust to UDP reorder/loss (FR-RTPS-8)."
  (let* ((p1 (make-array 12 :element-type '(unsigned-byte 8)
                         :initial-contents '(1 1 1 1 1 1 1 1 1 1 1 1)))
         (p2 (make-array 12 :element-type '(unsigned-byte 8)
                         :initial-contents '(2 2 2 2 2 2 2 2 2 2 2 2)))
         (node1 (make-disc-node :guid-prefix p1 :host "127.0.0.1" :port 0))
         (node2 (make-disc-node :guid-prefix p2 :host "127.0.0.1" :port 0))
         (payload (make-array 8 :element-type '(unsigned-byte 8)
                              :initial-contents '(#xDE #xAD #xBE #xEF #x01 #x02 #x03 #x04))))
    (unwind-protect
         (progn
           (add-local-writer node1 :topic "Square" :type "ShapeType"
                                   :reliability dds.rtps.discovery:+reliability-reliable+)
           (enable-publisher node1)
           (add-local-reader node2 :topic "Square" :type "ShapeType"
                                   :reliability dds.rtps.discovery:+reliability-reliable+)
           (enable-subscriber node2)
           (setf (disc-node-peers node1) (list (cons "127.0.0.1" (disc-node-port node2))))
           (setf (disc-node-peers node2) (list (cons "127.0.0.1" (disc-node-port node1))))
           (start-node node1)
           (start-node node2)
           (announce-participant node1)
           (announce-participant node2)
           (loop repeat 100
                 until (and (plusp (disc-node-discovered-count node1))
                            (plusp (disc-node-discovered-count node2)))
                 do (sleep 0.02))
           (announce-endpoints node1)
           (announce-endpoints node2)
           (loop repeat 100
                 until (and (plusp (disc-node-matched-count node1))
                            (plusp (disc-node-matched-count node2)))
                 do (sleep 0.02))
           (assert (and (plusp (disc-node-matched-count node1))
                        (plusp (disc-node-matched-count node2)))
                   () "endpoints did not match before publish")
           (publish-sample node1 payload)
           (loop repeat 150 until (plusp (node-sample-count node2)) do (sleep 0.02))
           (assert (plusp (node-sample-count node2)) ()
                   "subscriber never received the sample over UDP")
           (assert (equalp (node-sample-by-sn node2 1) payload) ()
                   "subscriber received the wrong payload bytes")
           t)
      (stop-node node1)
      (stop-node node2))))

(defun* run-dispose-dataplane-test ()
    (function () (eql t))
  "Full stack over UDP, instance lifecycle S1 (writer side): two participants discover (SPDP) +
   match (SEDP); A publishes a sample, then dispose-instance on a 16-octet key-hash. B receives the
   ALIVE sample, then a no-payload dispose DATA that parse-data-body classifies :dispose carrying
   A's exact key-hash + StatusInfo Disposed (RTPS 2.5 §9.6.4.9). B's instance-state handling is S2;
   here the wire is asserted received + classified. The unregister case is exercised too."
  (let* ((p1 (make-array 12 :element-type '(unsigned-byte 8)
                         :initial-contents '(1 1 1 1 1 1 1 1 1 1 1 1)))
         (p2 (make-array 12 :element-type '(unsigned-byte 8)
                         :initial-contents '(2 2 2 2 2 2 2 2 2 2 2 2)))
         (node1 (make-disc-node :guid-prefix p1 :host "127.0.0.1" :port 0))
         (node2 (make-disc-node :guid-prefix p2 :host "127.0.0.1" :port 0))
         (payload (make-array 8 :element-type '(unsigned-byte 8)
                              :initial-contents '(#xDE #xAD #xBE #xEF #x01 #x02 #x03 #x04)))
         (kh (make-array 16 :element-type '(unsigned-byte 8)
                         :initial-contents '(#xca #xc2 #x17 #xc3 #x18 #x36 #x3f #x8e
                                             #xf1 #x16 #x0e #xee #xde #xf9 #xe8 #x86))))
    (unwind-protect
         (progn
           (add-local-writer node1 :topic "Square" :type "ShapeType"
                                   :reliability dds.rtps.discovery:+reliability-reliable+)
           (enable-publisher node1)
           (add-local-reader node2 :topic "Square" :type "ShapeType"
                                   :reliability dds.rtps.discovery:+reliability-reliable+)
           (enable-subscriber node2)
           (setf (disc-node-peers node1) (list (cons "127.0.0.1" (disc-node-port node2))))
           (setf (disc-node-peers node2) (list (cons "127.0.0.1" (disc-node-port node1))))
           (start-node node1)
           (start-node node2)
           (announce-participant node1)
           (announce-participant node2)
           (loop repeat 100
                 until (and (plusp (disc-node-discovered-count node1))
                            (plusp (disc-node-discovered-count node2)))
                 do (sleep 0.02))
           (announce-endpoints node1)
           (announce-endpoints node2)
           (loop repeat 100
                 until (and (plusp (disc-node-matched-count node1))
                            (plusp (disc-node-matched-count node2)))
                 do (sleep 0.02))
           (assert (and (plusp (disc-node-matched-count node1))
                        (plusp (disc-node-matched-count node2)))
                   () "endpoints did not match before publish")
           (publish-sample node1 payload)              ; SN 1 = ALIVE sample
           (loop repeat 150 until (plusp (node-sample-count node2)) do (sleep 0.02))
           (assert (equalp (node-sample-by-sn node2 1) payload) () "subscriber missed the ALIVE sample")
           (dispose-instance node1 kh)                 ; SN 2 = dispose DATA
           (loop repeat 150 until (node-lifecycle-change-by-sn node2 2) do (sleep 0.02))
           (let ((lc (node-lifecycle-change-by-sn node2 2)))
             (assert lc () "subscriber never received the dispose DATA over UDP")
             (assert (eq (first lc) :dispose) () "dispose DATA not classified :dispose")
             (assert (equalp (second lc) kh) () "dispose DATA carried the wrong key-hash")
             (assert (= (third lc) dds.rtps.message:+statusinfo-disposed+) ()
                     "dispose DATA carried the wrong StatusInfo flags"))
           (unregister-instance node1 kh)              ; SN 3 = unregister DATA
           (loop repeat 150 until (node-lifecycle-change-by-sn node2 3) do (sleep 0.02))
           (let ((lc (node-lifecycle-change-by-sn node2 3)))
             (assert lc () "subscriber never received the unregister DATA over UDP")
             (assert (eq (first lc) :unregister) () "unregister DATA not classified :unregister"))
           t)
      (stop-node node1)
      (stop-node node2))))

(defun* run-dispose-repair-test ()
    (function () (eql t))
  "Reliability of a lifecycle change S1: A's dispose DATA is dropped on send
   (*debug-drop-sample-numbers* on its SN), then the drop is cleared with NO further write; A's
   periodic HEARTBEAT prompts B to NACK the gap, A resends the dispose via write-data-dispose, B
   recovers — asserted within a BOUNDED number of iterations. Proves a dispose/unregister occupies a
   real SN and rides the same ACKNACK/HEARTBEAT repair path as an ALIVE DATA (RTPS 2.5 §8.4.2.2)."
  (let* ((p1 (make-array 12 :element-type '(unsigned-byte 8)
                         :initial-contents '(1 1 1 1 1 1 1 1 1 1 1 1)))
         (p2 (make-array 12 :element-type '(unsigned-byte 8)
                         :initial-contents '(2 2 2 2 2 2 2 2 2 2 2 2)))
         (node1 (make-disc-node :guid-prefix p1 :host "127.0.0.1" :port 0))
         (node2 (make-disc-node :guid-prefix p2 :host "127.0.0.1" :port 0))
         (payload (make-array 8 :element-type '(unsigned-byte 8)
                              :initial-contents '(#xCA #xFE #xBA #xBE #x05 #x06 #x07 #x08)))
         (kh (make-array 16 :element-type '(unsigned-byte 8)
                         :initial-contents '(#xca #xc2 #x17 #xc3 #x18 #x36 #x3f #x8e
                                             #xf1 #x16 #x0e #xee #xde #xf9 #xe8 #x86))))
    (unwind-protect
         (progn
           (add-local-writer node1 :topic "Square" :type "ShapeType"
                                   :reliability dds.rtps.discovery:+reliability-reliable+)
           (enable-publisher node1)
           (add-local-reader node2 :topic "Square" :type "ShapeType"
                                   :reliability dds.rtps.discovery:+reliability-reliable+)
           (enable-subscriber node2)
           (setf (disc-node-peers node1) (list (cons "127.0.0.1" (disc-node-port node2))))
           (setf (disc-node-peers node2) (list (cons "127.0.0.1" (disc-node-port node1))))
           (start-node node1)
           (start-node node2)
           (announce-participant node1)
           (announce-participant node2)
           (loop repeat 100
                 until (and (plusp (disc-node-discovered-count node1))
                            (plusp (disc-node-discovered-count node2)))
                 do (sleep 0.02))
           (announce-endpoints node1)
           (announce-endpoints node2)
           (loop repeat 100
                 until (and (plusp (disc-node-matched-count node1))
                            (plusp (disc-node-matched-count node2)))
                 do (sleep 0.02))
           (assert (and (plusp (disc-node-matched-count node1))
                        (plusp (disc-node-matched-count node2)))
                   () "endpoints did not match before publish")
           (publish-sample node1 payload)             ; SN 1 ALIVE sample
           (loop repeat 100 until (plusp (node-sample-count node2)) do (sleep 0.02))
           (assert (plusp (node-sample-count node2)) () "ALIVE sample never arrived")
           (setf *debug-drop-sample-numbers* (list 2))  ; drop the dispose DATA (SN 2) on every thread
           (dispose-instance node1 kh)
           (sleep 0.1)
           (assert (null (node-lifecycle-change-by-sn node2 2)) ()
                   "drop hook failed: B received the dropped dispose DATA")
           (setf *debug-drop-sample-numbers* nil)        ; clear; do NOT dispose again
           (loop repeat 40                               ; BOUNDED: drive A's HB cadence
                 until (node-lifecycle-change-by-sn node2 2)
                 do (announce-endpoints node1) (sleep 0.02))
           (let ((lc (node-lifecycle-change-by-sn node2 2)))
             (assert lc () "lost dispose never recovered via the periodic HEARTBEAT")
             (assert (and (eq (first lc) :dispose) (equalp (second lc) kh)) ()
                     "recovered dispose has the wrong kind/key-hash"))
           t)
      (setf *debug-drop-sample-numbers* nil)
      (stop-node node1)
      (stop-node node2))))

(defun* run-large-dataplane-test ()
    (function () (eql t))
  "Full stack over UDP with a sample LARGER than *fragment-size*: two participants discover
   (SPDP) and match (SEDP), then the publisher sends a 4000-octet user sample. The writer
   fragments it into DATA_FRAG submessages + a HEARTBEAT_FRAG; the subscriber reassembles it
   and delivers a byte-exact copy. Proves send-side fragmentation + receive-side reassembly +
   NACK_FRAG recovery over real UDP loopback (RTPS 2.5 §9.4.5.5)."
  (let* ((p1 (make-array 12 :element-type '(unsigned-byte 8)
                         :initial-contents '(1 1 1 1 1 1 1 1 1 1 1 1)))
         (p2 (make-array 12 :element-type '(unsigned-byte 8)
                         :initial-contents '(2 2 2 2 2 2 2 2 2 2 2 2)))
         (node1 (make-disc-node :guid-prefix p1 :host "127.0.0.1" :port 0))
         (node2 (make-disc-node :guid-prefix p2 :host "127.0.0.1" :port 0))
         (payload (make-array 4000 :element-type '(unsigned-byte 8))))
    (dotimes (i 4000) (setf (aref payload i) (logand (* i 7) #xff)))
    (unwind-protect
         (progn
           (add-local-writer node1 :topic "Square" :type "ShapeType"
                                   :reliability dds.rtps.discovery:+reliability-reliable+)
           (enable-publisher node1)
           (add-local-reader node2 :topic "Square" :type "ShapeType"
                                   :reliability dds.rtps.discovery:+reliability-reliable+)
           (enable-subscriber node2)
           (setf (disc-node-peers node1) (list (cons "127.0.0.1" (disc-node-port node2))))
           (setf (disc-node-peers node2) (list (cons "127.0.0.1" (disc-node-port node1))))
           (start-node node1)
           (start-node node2)
           (announce-participant node1)
           (announce-participant node2)
           (loop repeat 100
                 until (and (plusp (disc-node-discovered-count node1))
                            (plusp (disc-node-discovered-count node2)))
                 do (sleep 0.02))
           (announce-endpoints node1)
           (announce-endpoints node2)
           (loop repeat 100
                 until (and (plusp (disc-node-matched-count node1))
                            (plusp (disc-node-matched-count node2)))
                 do (sleep 0.02))
           (assert (and (plusp (disc-node-matched-count node1))
                        (plusp (disc-node-matched-count node2)))
                   () "endpoints did not match before publish")
           (publish-sample node1 payload)
           (loop repeat 150 until (plusp (node-sample-count node2)) do (sleep 0.02))
           (assert (plusp (node-sample-count node2)) ()
                   "subscriber never received the fragmented sample over UDP")
           (assert (equalp (node-sample-by-sn node2 1) payload) ()
                   "subscriber received the wrong reassembled payload bytes")
           t)
      (stop-node node1)
      (stop-node node2))))

(defun* run-lost-final-sample-test ()
    (function () (eql t))
  "Reliability edge: a reliable writer's FINAL sample's DATA is lost and there is no
   subsequent write, so nothing re-prompts the reader to NACK — only the periodic
   standalone HEARTBEAT keeps reliability live and triggers recovery (RTPS 2.5
   §8.4.2.2: a reliable Writer must periodically inform each matching reliable Reader
   of the availability of a sample). Two participants discover (SPDP) + match (SEDP);
   *debug-drop-sample-numbers* drops the ONE published sample's DATA on send; the drop
   is then cleared but NO further sample is published; A's announce cadence then emits
   the periodic non-final HEARTBEAT, B NACKs the gap, A resends, B recovers — asserted
   within a BOUNDED number of iterations (no unbounded wait)."
  (let* ((p1 (make-array 12 :element-type '(unsigned-byte 8)
                         :initial-contents '(1 1 1 1 1 1 1 1 1 1 1 1)))
         (p2 (make-array 12 :element-type '(unsigned-byte 8)
                         :initial-contents '(2 2 2 2 2 2 2 2 2 2 2 2)))
         (node1 (make-disc-node :guid-prefix p1 :host "127.0.0.1" :port 0))
         (node2 (make-disc-node :guid-prefix p2 :host "127.0.0.1" :port 0))
         (payload (make-array 8 :element-type '(unsigned-byte 8)
                              :initial-contents '(#xCA #xFE #xBA #xBE #x05 #x06 #x07 #x08))))
    (unwind-protect
         (progn
           (add-local-writer node1 :topic "Square" :type "ShapeType"
                                   :reliability dds.rtps.discovery:+reliability-reliable+)
           (enable-publisher node1)
           (add-local-reader node2 :topic "Square" :type "ShapeType"
                                   :reliability dds.rtps.discovery:+reliability-reliable+)
           (enable-subscriber node2)
           (setf (disc-node-peers node1) (list (cons "127.0.0.1" (disc-node-port node2))))
           (setf (disc-node-peers node2) (list (cons "127.0.0.1" (disc-node-port node1))))
           (start-node node1)
           (start-node node2)
           (announce-participant node1)
           (announce-participant node2)
           (loop repeat 100
                 until (and (plusp (disc-node-discovered-count node1))
                            (plusp (disc-node-discovered-count node2)))
                 do (sleep 0.02))
           (announce-endpoints node1)
           (announce-endpoints node2)
           (loop repeat 100
                 until (and (plusp (disc-node-matched-count node1))
                            (plusp (disc-node-matched-count node2)))
                 do (sleep 0.02))
           (assert (and (plusp (disc-node-matched-count node1))
                        (plusp (disc-node-matched-count node2)))
                   () "endpoints did not match before publish")
           (setf *debug-drop-sample-numbers* (list 1))     ; drop on EVERY thread (incl. resend)
           (publish-sample node1 payload)                  ; DATA dropped; HEARTBEAT prompts NACK
           (sleep 0.1)                                     ; NACK-resend also dropped -> still gone
           (assert (zerop (node-sample-count node2)) ()
                   "drop hook failed: B received the dropped sample's DATA")
           (setf *debug-drop-sample-numbers* nil)          ; clear; do NOT publish again
           (loop repeat 40                                 ; BOUNDED: drive A's HB cadence
                 until (plusp (node-sample-count node2))
                 do (announce-endpoints node1) (sleep 0.02))
           (assert (plusp (node-sample-count node2)) ()
                   "lost final sample never recovered via the periodic HEARTBEAT")
           (assert (equalp (node-sample-by-sn node2 1) payload) ()
                   "recovered sample has the wrong payload bytes")
           t)
      (setf *debug-drop-sample-numbers* nil)
      (stop-node node1)
      (stop-node node2))))

(defun* run-locator-filter-test ()
    (function () (eql t))
  "Locator-list selection + foreign-participant robustness (regression for the
   EHOSTUNREACH crash vs RTI DDSSpy, which advertises several locators incl.
   0.0.0.0): %usable-destination (1) picks a routable default-unicast locator,
   skipping a 0.0.0.0 entry; (2) falls back to a routable metatraffic ADDRESS + a
   default-unicast PORT when every default-unicast locator is non-routable; (3)
   yields NIL when nothing is routable; (4) a UDP send to 0.0.0.0 is non-fatal."
  (flet ((loc (a b c d port)
           (dds.rtps.discovery:make-locator
            :kind dds.rtps.discovery:+locator-kind-udpv4+ :port port
            :address (dds.rtps.discovery:make-ipv4-locator
                      (make-array 4 :element-type '(unsigned-byte 8)
                                  :initial-contents (list a b c d)))))
         (sd (du mt)
           (dds.rtps.discovery:make-spdp-data :default-unicast-locators du
                                              :metatraffic-unicast-locators mt)))
    (assert (equal (%usable-destination (sd (list (loc 0 0 0 0 7411) (loc 192 168 1 7 7411)) '()))
                   '("192.168.1.7" . 7411))
            () "must pick the routable default-unicast locator, skipping 0.0.0.0")
    (assert (equal (%usable-destination (sd (list (loc 0 0 0 0 7411)) (list (loc 192 168 1 7 7410))))
                   '("192.168.1.7" . 7411))
            () "must fall back to metatraffic address + default-unicast port")
    (assert (null (%usable-destination (sd (list (loc 0 0 0 0 7411)) (list (loc 0 0 0 0 7410)))))
            () "all-0.0.0.0 must yield NIL, not a bad destination")
    (multiple-value-bind (tr sock) (dds.xport.udp:make-udp-transport :host "127.0.0.1" :port 0)
      (unwind-protect
           (let ((buf (dds.core.buffer:make-octet-buffer 16)))
             (dds.xport:send tr (dds.xport.udp:make-udp-locator :host "0.0.0.0" :port 7411) buf 0 1)
             (dds.pal:free-static (dds.core.buffer:octet-buffer-vec buf)))
        (dds.pal:udp-close sock)))
    t))
