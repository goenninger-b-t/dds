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

(defun* %send-raw-buf (node buf len host port &optional shmem-dest)
    (function (disc-node dds.core.buffer:octet-buffer (integer 0) string (unsigned-byte 16) &optional t) t)
  "Send the first LEN octets of BUF (a complete RTPS message) as ONE datagram — the raw one-datagram send
   shared by %SEND-MSG-BUF and the %SEND-PACKED coalescer (one dds.xport:send = one sendto). When
   SHMEM-DEST (a dds.xport.shmem:shmem-locator) is supplied, the datagram goes over SHARED MEMORY to that
   same-host peer (FR-XPORT-2); if the SHMEM send returns 0 (lane full / claim fail) it FALLS BACK to the
   UDP send to HOST:PORT (no loss, no double-delivery — exactly one of the two carries it). With SHMEM-DEST
   NIL (every discovery/HB/ACKNACK caller, and every cross-host data send) the path is the original UDP send,
   byte-for-byte unchanged. Hands a copy to *DATAGRAM-SINK* first when that test hook is bound."
  (when *datagram-sink*
    (funcall *datagram-sink* (subseq (dds.core.buffer:octet-buffer-vec buf) 0 len)))
  (when (and shmem-dest (disc-node-shmem node))
    (when (plusp (dds.xport:send (dds.xport.shmem:shmem-transport-transport (disc-node-shmem node))
                                 shmem-dest buf 0 len))
      (incf (disc-node-shmem-sends node))
      (return-from %send-raw-buf t)))   ; delivered over SHMEM: do NOT also UDP-send (no double-delivery)
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

(defun* %pack-budget (buf)
    (function (dds.core.buffer:octet-buffer) (integer 0))
  "The effective coalescing budget for BUF: min(*COALESCE-DATAGRAM-BUDGET*, capacity−64) — the per-datagram
   octet ceiling %PACK-PLAN partitions to (RTPS 2.5 §8.3.4). Factored so the plan and the build agree on it."
  (min *coalesce-datagram-budget* (- (dds.core.buffer:octet-buffer-capacity buf) 64)))

(defun* %pack-plan (items budget)
    (function (list (integer 0)) list)
  "Partition ITEMS — each a (SIZE . BUILD-FN) packable submessage of at most SIZE octets — into the ORDERED
   list of per-datagram item groups %SEND-PACKED would flush at BUDGET (RTPS 2.5 §8.3.4): a fresh group is
   started before a submessage that would push the current (non-empty) group past BUDGET, and a submessage
   whose SIZE is not a multiple of 4 forces a group boundary after it (RTPS 2.5 §8.3.4 requires the next
   submessage to start 32-bit-aligned). Pure (no I/O, no cursor) — the boundary decision depends only on the
   SIZE sequence and BUDGET, so the partition is identical whether the caller sends eagerly (%SEND-PACKED) or
   one group at a time (the per-datagram step), making the two byte-identical by construction. NIL ITEMS ->
   NIL (no datagram)."
  (let ((groups '()) (cur '()) (used 0))
    (dolist (item items)
      (when (and cur (> (+ used (car item)) budget))
        (push (nreverse cur) groups) (setf cur '() used 0))   ; would overflow: close the current group
      (push item cur) (incf used (car item))
      (when (plusp (mod (car item) 4))
        (push (nreverse cur) groups) (setf cur '() used 0)))   ; non-4-aligned: must be this datagram's last
    (when cur (push (nreverse cur) groups))
    (nreverse groups)))

(defun* %build-packed-datagram (node buf group)
    (function (disc-node dds.core.buffer:octet-buffer list) (integer 0))
  "Build ONE coalesced RTPS datagram for the item GROUP (a %PACK-PLAN sublist) into BUF — one shared Header
   (RTPS 2.5 §8.3.4 / §9.4.4) then each item's submessage in order — and return its octet length. No I/O: the
   send is the caller's (so the per-datagram step can build-then-send, accounting tokens on the returned
   length before sending). The byte-exact body shared by %SEND-PACKED and %EMIT-NEXT-DATAGRAM."
  (let ((mc (dds.core.buffer:cursor buf :endianness :little)))
    (dds.rtps.message:write-header mc (disc-node-guid-prefix node))
    (dolist (item group)
      (funcall (cdr item) mc))
    (dds.core.buffer:cursor-position mc)))

(defun* %send-packed (node buf host port items &optional shmem-dest)
    (function (disc-node dds.core.buffer:octet-buffer string (unsigned-byte 16) list &optional t) t)
  "Coalesce ITEMS — each a (SIZE . BUILD-FN) where BUILD-FN writes exactly ONE submessage of at most
   SIZE octets — into as few RTPS datagrams as fit the budget, one shared Header per datagram (RTPS 2.5
   §8.3.4 / §9.4.4), and send each to HOST:PORT. The datagram partition is %PACK-PLAN (a fresh datagram is
   started before a submessage that would push a non-empty datagram past min(*COALESCE-DATAGRAM-BUDGET*,
   capacity−64), so the cursor never exceeds the budget ≪ buffer capacity: no buffer overflow on legitimate
   input; a submessage whose body does not end on a 4-octet boundary, RTPS 2.5 §8.3.4 requires the next to
   start 32-bit-aligned, is the last in its datagram — a no-op for this stack: every DATA payload is
   XCDR-padded to 4, dispose=52, HEARTBEAT=28, all aligned, a graceful degrade otherwise); each group is then
   built (%BUILD-PACKED-DATAGRAM) and sent. Cuts the sendto count from one-per-submessage to
   ceil(total/budget). NIL ITEMS sends nothing. SHMEM-DEST (a shmem-locator, default NIL) routes every
   datagram over shared memory with UDP fallback (%send-raw-buf, FR-XPORT-2); NIL keeps the original all-UDP
   path."
  (dolist (group (%pack-plan items (%pack-budget buf)))
    (%send-raw-buf node buf (%build-packed-datagram node buf group) host port shmem-dest)))

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

(defun* %shmem-wire-locator (spdp)
    (function (dds.rtps.discovery:spdp-data) t)
  "The first SHMEM Locator_t (kind +locator-kind-shmem+) a peer advertised in its default-unicast
   locators (FR-XPORT-2 / E1 make-shmem-locator-wire), or NIL — proves the peer offers a SHMEM receive
   segment. The ring geometry (lane-count, capacity) rides in the locator: address[0..3]=lane-count,
   port=capacity."
  (find dds.rtps.discovery:+locator-kind-shmem+
        (dds.rtps.discovery:spdp-data-default-unicast-locators spdp)
        :key #'dds.rtps.discovery:locator-kind :test #'=))

(defun* %resolve-shmem-dest (node prefix)
    (function (disc-node (simple-array (unsigned-byte 8) (12))) t)
  "Resolve participant PREFIX's SHMEM destination from the discovered SPDP record, or NIL. CALLER HOLDS
   the node lock. A peer qualifies iff the discovered remote advertised the SAME host-uuid as this node
   (same physical host, RTPS-level so a hostname collision degrades to a failed attach + UDP fallback,
   never data loss), AND it advertised a SHMEM locator (so a receive segment exists). The destination NAME
   is derived deterministically from PREFIX (seg-name-for-guid, RTPS 2.5 §9.4.4) and the ring geometry
   from the wire locator (lane-count from its address, capacity from its port). Off the hot path — called
   only on a %shmem-dest cache miss (once per peer)."
  (let ((spdp (gethash prefix (disc-node-discovered node))))
    (when (and spdp
               (plusp (dds.rtps.discovery:spdp-data-host-uuid spdp))
               (= (dds.rtps.discovery:spdp-data-host-uuid spdp) (disc-node-host-uuid node)))
      (let ((wl (%shmem-wire-locator spdp)))
        (when wl
          (dds.xport.shmem:make-shmem-locator
           :name (dds.xport.shmem:seg-name-for-guid prefix)
           :host-uuid (disc-node-host-uuid node)
           :lane-count (dds.rtps.discovery:shmem-locator-wire-lane-count wl)
           :capacity (dds.rtps.discovery:locator-port wl)))))))

(defun* %shmem-dest (node prefix)
    (function (disc-node (simple-array (unsigned-byte 8) (12))) t)
  "A dds.xport.shmem:shmem-locator addressing participant PREFIX's receive segment iff PREFIX is a
   SAME-HOST SHMEM peer reachable over shared memory, else NIL (caller then uses UDP). A peer qualifies
   iff: SHMEM is on for this node (the shmem slot is set — which already encodes *shmem-enabled* + the
   platform gate), AND the discovered remote advertised the SAME host-uuid as this node, AND it advertised
   a SHMEM locator. MEMOIZED per remote prefix (FR-XPORT-2 / FR-LANG-7): the resolved locator (or the
   sentinel :none for 'not a SHMEM peer') is cached in shmem-dest-cache, so the steady-state send does ONE
   cheap gethash and NO per-datagram make-shmem-locator allocation or full re-resolve (the prior cost the
   WP-SHMEM bench charged at ~800-2000 bytes/sample). The cache is read + filled under the node lock and is
   invalidated when PREFIX's SPDP is re-recorded (%record-participant) or it leases out (%lease-sweep), so a
   changed or removed peer never sends to a stale locator."
  (when (disc-node-shmem node)
    (dds.pal:with-lock ((disc-node-lock node))
      (let ((cached (gethash prefix (disc-node-shmem-dest-cache node))))
        (cond
          ((eq cached :none) nil)               ; memoized non-SHMEM peer: skip the resolve, UDP
          (cached cached)                        ; memoized live shmem-locator: reuse, no alloc
          (t (let ((resolved (%resolve-shmem-dest node prefix)))
               (setf (gethash (copy-seq prefix) (disc-node-shmem-dest-cache node))
                     (or resolved :none))        ; cache the verdict (:none for not-a-peer) keyed by an owned copy
               resolved)))))))

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

(defun* %matched-reader-keys (node)
    (function (disc-node) list)
  "The full 16-octet GUIDs of every matched RELIABLE remote user READER — the writer-proxy keys for
   purge-on-full-ACK (writer-purge-acked). Identical keys to the ones %on-user-acknack advances
   (%source-guid src-prefix rid = the reader's GUID, RTPS 2.5 §9.4.4 / §8.3.5.4), so the purge watermark
   is the min acked-base across every matched RELIABLE reader (a not-yet-ACKed reliable reader's proxy
   reads acked-base 1 and holds the watermark — nothing purged until it acks). A BEST_EFFORT reader is
   EXCLUDED: it never ACKNACKs (its proxy would pin the watermark at 1 forever, disabling the purge) and
   the writer owes it no retransmit (best-effort = no delivery guarantee, §2.2.3.13), so purging samples
   it never acked is correct."
  (loop for remote in (%matched-endpoints node)
        for guid = (dds.rtps.discovery:endpoint-data-guid remote)
        for q = (dds.rtps.discovery:endpoint-data-qos remote)
        when (and (%reader-guid-p guid) q (eq (dds.qos:qos-reliability q) :reliable))
          collect (copy-seq guid)))

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

(defun* %zc-change-item (node change zc-readers)
    (function (disc-node dds.rtps.history:cache-change (integer 0)) (or null cons))
  "WP-ZEROCOPY (FR-PF-3, ADR 0014): if CHANGE is a :data sample whose serialized payload is LARGER than
   *zerocopy-min-payload-bytes* AND ZC-READERS (same-host ZC-capable readers at this destination) > 0,
   loan the payload into the writer pool and return a (SIZE . BUILD-FN) DATA item carrying the 16-byte
   reference (%zc-ref-builder). NIL when not ZC-eligible OR the pool is saturated — the caller then emits
   the FULL serialized payload (no loss, exactly one of {ref, payload} per reader). ZC-READERS is used
   only as a >0 GATE; the slot refcount is 1 (this ref reaches ONE destination, resolved ONCE there —
   see %zc-ref-builder). NOT cleared for ship — pending counsel (R6)."
  (when (and (plusp zc-readers)
             (eq (dds.rtps.history:cache-change-kind change) :data))
    (let ((pl (dds.rtps.history:cache-change-serialized-payload change)))
      (when (> (length pl) *zerocopy-min-payload-bytes*)
        (%zc-ref-builder node (dds.rtps.history:cache-change-sn change) pl 0 (length pl) 1)))))

(defun* %msg-datagram (node build-fn)
    (function (disc-node function) function)
  "Wrap a submessage BUILD-FN (writing onto a cursor after the Header) as a ONE-DATAGRAM build-thunk
   (lambda (buf) -> octet-length): write the RTPS Header (RTPS 2.5 §8.3.4) then BUILD-FN, return the
   cursor length. No I/O — the byte-exact twin of %SEND-MSG-BUF's build half, so the per-datagram step
   builds the identical bytes %SEND-MSG-BUF would, then sends them itself."
  (lambda (buf)
    (let ((mc (dds.core.buffer:cursor buf :endianness :little)))
      (dds.rtps.message:write-header mc (disc-node-guid-prefix node))
      (funcall build-fn mc)
      (dds.core.buffer:cursor-position mc))))

(defun* %sample-plan (node sn pl budget)
    (function (disc-node integer (simple-array (unsigned-byte 8) (*)) (integer 1)) list)
  "The ORDERED list of one-datagram build-thunks (each lambda (buf) -> octet-length) for sample (SN, PL):
   one DATA datagram if PL fits *fragment-size*, else a DATA_FRAG series (packing as many fragments as fit
   BUDGET per datagram, RTPS 2.5 §9.4.5.5) followed by a HEARTBEAT_FRAG. Loss injection is applied HERE,
   identically to the prior inline %send-sample: a small DATA whose SN is in *DEBUG-DROP-SAMPLE-NUMBERS* and
   a DATA_FRAG submessage covering a fragment in *DEBUG-DROP-FRAGMENT-NUMBERS* are omitted (no thunk). The
   HEARTBEAT_FRAG count side-effect (writer-frag-heartbeat increments a counter) runs ONCE here — exactly as
   the prior flush-all ran it once — and the captured (lastfrag count) close over the thunk, so stepping is
   byte-identical and does not double-count. No I/O: the step builds+sends each thunk."
  (let ((size (length pl))
        (wid (disc-node-user-writer-id node)))
    (if (<= size dds.rtps.reliable:*fragment-size*)
        (if (and *debug-drop-sample-numbers* (member sn *debug-drop-sample-numbers*))
            '()
            (list (%msg-datagram node
                                 (lambda (mc) (dds.rtps.message:write-data
                                               mc dds.rtps.message:+entityid-unknown+ wid sn pl 0 size)))))
        (let ((thunks '()))
          (dolist (desc (dds.rtps.reliable:writer-frag-plan size dds.rtps.reliable:*fragment-size* budget))
            (destructuring-bind (fstart fcount off len) desc
              (unless (and *debug-drop-fragment-numbers*
                           (loop for f from fstart below (+ fstart fcount)
                                   thereis (member f *debug-drop-fragment-numbers*)))
                (push (%msg-datagram node
                                     (lambda (mc) (dds.rtps.message:write-data-frag
                                                   mc dds.rtps.message:+entityid-unknown+ wid sn size
                                                   fstart fcount dds.rtps.reliable:*fragment-size* pl off len)))
                      thunks))))
          (multiple-value-bind (lastfrag cnt)
              (dds.rtps.reliable:writer-frag-heartbeat (disc-node-user-writer node) sn)
            (when lastfrag
              (push (%msg-datagram node
                                   (lambda (mc) (dds.rtps.message:write-heartbeat-frag
                                                 mc dds.rtps.message:+entityid-unknown+ wid sn lastfrag cnt)))
                    thunks)))
          (nreverse thunks)))))

(defun* %changes-datagram-plan (node buf changes hb shmem-dest zc-readers)
    (function (disc-node dds.core.buffer:octet-buffer list (or null cons) t (integer 0)) list)
  "The ORDERED per-datagram send-plan for pushing CHANGES (+ optional trailing HEARTBEAT item HB) to ONE
   destination: a list of (BUILD-THUNK . SHMEM-DEST), each BUILD-THUNK a lambda (buf) -> octet-length that
   builds exactly ONE datagram. The order, and each datagram's bytes, are IDENTICAL to the prior flush-all
   %send-changes-packed: every LARGE change's DATA_FRAG datagrams (%sample-plan, in CHANGES order, UDP only
   in v1 -> SHMEM-DEST NIL) come FIRST, then the coalesced small-:data / ZC-ref items + HB packed into ≤budget
   datagrams (%pack-plan + %build-packed-datagram, carrying SHMEM-DEST). Loss injection, ZC substitution
   (ZC-READERS > 0, WP-ZEROCOPY FR-PF-3 — exactly one of {ref, payload} per reader), and the HEARTBEAT_FRAG
   count side-effect all happen here, once, exactly as before — so consuming this plan one datagram at a time
   (the step) is byte-identical to flush-all by construction. Pure of I/O; BUF supplies only the packing
   budget (%pack-budget)."
  (let ((frag-plans '()) (items '()) (budget (%pack-budget buf)))
    (dolist (change changes)
      (let ((sn (dds.rtps.history:cache-change-sn change))
            (zc nil))
        (cond
          ((and *debug-drop-sample-numbers* (member sn *debug-drop-sample-numbers*)))
          ((setf zc (%zc-change-item node change zc-readers)) (push zc items))   ; WP-ZEROCOPY: ref, not payload
          ((%small-change-p change) (push (%data-builder node change) items))
          (t (dolist (thunk (%sample-plan node sn (dds.rtps.history:cache-change-serialized-payload change)
                                          (- (dds.core.buffer:octet-buffer-capacity buf) 64)))
               (push (cons thunk nil) frag-plans))))))   ; large samples: UDP only (v1), one datagram per thunk
    (when hb (push hb items))
    (let ((packed (loop for group in (%pack-plan (nreverse items) budget)
                        collect (cons (let ((g group)) (lambda (buf) (%build-packed-datagram node buf g)))
                                      shmem-dest))))
      (nconc (nreverse frag-plans) packed))))

(defun* %emit-next-datagram (node buf state)
    (function (disc-node dds.core.buffer:octet-buffer list) (values (integer 0) t list))
  "The per-datagram STEP (WP-ASYNC-FLOW core, FR-PF-2): build the NEXT single datagram of STATE into BUF and
   send it, returning (values BYTES-SENT MORE-REMAIN-P NEW-STATE). STATE is a list of (BUILD-THUNK . SHMEM-DEST)
   plan entries with the destination (HOST . PORT) consed on its head — i.e. ((HOST . PORT) . PLAN); NEW-STATE
   carries the SAME head with PLAN's tail, so threading it across calls walks the plan one datagram at a time.
   MORE-REMAIN-P is NIL once the plan is exhausted. Build-then-send by construction: the thunk builds the
   datagram into BUF and reports its length (the exact token cost the Phase-C scheduler acquires) BEFORE the
   %send-raw-buf — so a scheduler can build, acquire(length), then send the already-built buffer. An empty/
   exhausted STATE sends nothing and returns (values 0 NIL STATE). Flow control is wire-invisible: this only
   changes WHEN a datagram is sent, never its bytes (ADR 0016)."
  (let ((dest (car state)) (plan (cdr state)))
    (if (null plan)
        (values 0 nil state)
        (let* ((entry (car plan))
               (len (funcall (car entry) buf)))
          (%send-raw-buf node buf len (car dest) (cdr dest) (cdr entry))
          (values len (and (cdr plan) t) (cons dest (cdr plan)))))))

(defun* %send-changes-packed (node buf changes host port hb &optional shmem-dest (zc-readers 0))
    (function (disc-node dds.core.buffer:octet-buffer list string (unsigned-byte 16) (or null cons) &optional t (integer 0)) t)
  "Send CHANGES (+ optional trailing HEARTBEAT item HB, a (SIZE . BUILD-FN)) to HOST:PORT, coalescing the
   small ones into as few datagrams as fit the budget: this is now the per-datagram STEP run to completion —
   build the %changes-datagram-plan once, then %emit-next-datagram in a loop until no datagram remains. The
   plan emits every LARGE change's DATA_FRAG series first (one datagram per fragment group, UDP only in v1),
   then the coalesced small-:data / ZC-ref items + HB; so the wire bytes are byte-IDENTICAL to the prior
   flush-all (the loop is the same datagram sequence, now stepped). The shared writer push/retransmit emit
   path (RTPS 2.5 §8.3.4 §8.4.2.2). When SHMEM-DEST is supplied the COALESCED small-sample datagrams go over
   shared memory with UDP fallback (FR-XPORT-2); large fragmented samples stay on UDP in v1 (the bulk
   small-sample path is the SHMEM throughput target). NIL SHMEM-DEST is the original all-UDP behaviour,
   byte-for-byte. ZC-READERS > 0 (WP-ZEROCOPY, FR-PF-3) substitutes a 16-byte reference for a large :data
   sample's payload at THIS destination (%zc-change-item) instead of fragmenting it — exactly one of
   {ref, full payload} reaches each reader (no double-delivery); ZC-READERS 0 (the default, and always when
   *zerocopy-enabled* is nil) is the existing path verbatim."
  (let ((state (cons (cons host port)
                     (%changes-datagram-plan node buf changes hb shmem-dest zc-readers))))
    (loop while (cdr state)   ; (cdr state) = the remaining datagram plan; NIL when exhausted
          do (setf state (nth-value 2 (%emit-next-datagram node buf state))))
    t))

(defun* %send-sample (node buf sn pl host port)
    (function (disc-node dds.core.buffer:octet-buffer integer (simple-array (unsigned-byte 8) (*)) string (unsigned-byte 16)) t)
  "Send sample (SN, PL) to HOST:PORT: one DATA submessage if PL fits *fragment-size*, else a
   series of DATA_FRAG submessages (packing as many fragments as fit the datagram) followed by
   a HEARTBEAT_FRAG. Now the %sample-plan datagram thunks built+sent in order (byte-identical to the prior
   inline emit). Uses BUF (tx-msg or rx-tx-msg) as the scratch message buffer. A submessage containing a
   fragment named in *DEBUG-DROP-FRAGMENT-NUMBERS* is skipped, and a non-fragmented DATA whose SN is in
   *DEBUG-DROP-SAMPLE-NUMBERS* is skipped (loss injection)."
  (dolist (thunk (%sample-plan node sn pl (- (dds.core.buffer:octet-buffer-capacity buf) 64)))
    (%send-raw-buf node buf (funcall thunk buf) host port)))

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

(defun* %send-user-gap (node buf reader-id gap-sns host port)
    (function (disc-node dds.core.buffer:octet-buffer (unsigned-byte 32) cons string (unsigned-byte 16)) t)
  "Send ONE GAP to HOST:PORT declaring every SN in the non-empty GAP-SNS list irrelevant (RTPS 2.5 §8.3.7.4 /
   §9.4.5.6): readerId = the NACKing reader's EntityId READER-ID, writerId = this user writer's EntityId. The
   SequenceNumberSet is built by seqnum-set-from-sns (shared MSB-first layout) and gapStart = its base, so the
   [gapStart, base) contiguous-prefix range is empty and the set is EXACTLY the bitmapped SNs. The gap SNs all
   came from ONE inbound ACKNACK's SequenceNumberSet, so they fit one 256-SN window. BUF selects the thread's
   scratch message buffer; mirrors %send-user-heartbeat (single-submessage send via %send-msg-buf)."
  (multiple-value-bind (base numbits bitmap) (dds.rtps.message:seqnum-set-from-sns gap-sns)
    (%send-msg-buf node buf
                   (lambda (mc)
                     (dds.rtps.message:write-gap
                      mc reader-id (disc-node-user-writer-id node) base base numbits bitmap))
                   host port)))

(defun* %reader-push-targets (node)
    (function (disc-node) list)
  "Per matched-reader DESTINATION, a ((host . port) READER-KEY…) group for the writer push path: the
   keys are the FULL 16-octet GUIDs of EVERY matched reader resolving to that (host . port) (RTPS 2.5
   §8.3.5.4 — a SN is unique only within one writer GUID, and the corresponding ACKNACK keys by the
   same remote reader GUID, %on-user-acknack). Two DataReaders in one remote participant share a
   unicast destination — a DATA with readerId UNKNOWN reaches both — so they are grouped, not deduped
   away: the push sends the union to the destination ONCE while advancing EACH reader's unsent-base
   (%merge-unsent, %push-data), keeping every co-located reader's send-once accounting honest. Falls
   back to the static PEERS (each carrying this node's local reader-id) ONLY when NO matched reader
   resolved to a destination (the discovery-less test path) — a :peers entry is an SPDP metatraffic
   BOOTSTRAP locator (FR-DISC-4), not a user-data destination, so once a real reader is matched its
   DEFAULT_UNICAST locator (§9.6.1.4) is the destination and the SPDP peer is NOT also blasted with user
   DATA (which a foreign peer binds on a different port from its user-data locator)."
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
    (when (null groups)   ; discovery-less ONLY: a :peers entry is an SPDP bootstrap locator, not a user-data dest
      (dolist (peer (disc-node-peers node))
        (unless (assoc peer groups :test #'equal)   ; dedup duplicate :peers entries
          (push (list peer (disc-node-user-reader-id node)) groups))))
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

(defun* %group-shmem-dest (node group)
    (function (disc-node cons) t)
  "The SHMEM destination for a %reader-push-targets GROUP, or NIL — resolves the remote participant prefix
   from the group's reader keys (the first 12 octets of any matched-reader GUID at that destination, RTPS
   2.5 §9.3.1.2 / §8.3.5.4; every reader in one group shares a unicast (host . port), hence one participant
   prefix) and asks %shmem-dest whether that participant is a same-host SHMEM peer (FR-XPORT-2). NIL for the
   discovery-less PEERS fallback group (its key is this node's own reader-id, not a remote GUID) — those
   stay UDP."
  (let ((k (first (cdr group))))   ; a 16-octet GUID for a real matched reader; a u32 reader-id for the PEERS fallback
    (when (typep k '(simple-array (unsigned-byte 8) (16)))
      (%shmem-dest node (subseq k 0 12)))))

(defun* %reader-zc-capable-p (node reader-guid)
    (function (disc-node (simple-array (unsigned-byte 8) (16))) t)
  "T iff the matched remote reader with 16-octet READER-GUID is BOTH same-host SHMEM-reachable (its
   participant is a %shmem-dest peer — host-uuid match + a SHMEM receive segment) AND advertised
   PID_ZEROCOPY_CAPABLE in SEDP (WP-ZEROCOPY, FR-PF-3, ADR 0014). The endpoint-data is read from the
   matches table; off the hot path (called once per push group, not per sample). NIL on any miss."
  (let ((ep (dds.pal:with-lock ((disc-node-lock node))
              (gethash reader-guid (disc-node-matches node)))))
    (and ep
         (dds.rtps.discovery:endpoint-data-zerocopy-capable ep)
         (%shmem-dest node (subseq reader-guid 0 12))
         t)))

(defun* %zc-readers (node targets)
    (function (disc-node list) (integer 0))
  "WP-ZEROCOPY (FR-PF-3, ADR 0014): the count of reader keys in TARGETS (a %reader-push-targets group's
   cdr — 16-octet matched-reader GUIDs) that are same-host AND ZC-capable, when this node has a writer
   pool (the pool exists iff *zerocopy-enabled* was set at make-disc-node — gate on the SLOT, not the
   special, since the WP-ASYNC sender thread that also pushes cannot see a dynamic binding). 0 disables
   zero-copy for the group (the writer sends normal DATA — the no-double-delivery fallback), so the
   flag-off (no-pool) path is untouched."
  (if (disc-node-zc-pool node)
      (count-if (lambda (k)
                  (and (typep k '(simple-array (unsigned-byte 8) (16)))
                       (%reader-zc-capable-p node k)))
                targets)
      0))

(defun* %encode-zc-ref-vec (slot generation slot-bytes)
    (function ((unsigned-byte 32) (unsigned-byte 32) (unsigned-byte 32)) (simple-array (unsigned-byte 8) (20)))
  "Encode a 20-octet WP-ZEROCOPY SerializedPayload reference (encode-zc-reference) into a fresh vector.
   The 20-byte alloc is negligible against the large-sample payload copy it REPLACES; this file is not a
   measured hot path (the gated hot-path files are untouched). ADR 0014, FR-PF-3."
  (let* ((v (make-array 20 :element-type '(unsigned-byte 8)))
         (c (dds.core.buffer:cursor (dds.core.buffer:octet-buffer-over v) :endianness :little)))
    (dds.cdr:encode-zc-reference c slot generation slot-bytes)
    v))

(defun* %zc-ref-builder (node sn payload off len resolves)
    (function (disc-node integer (simple-array (unsigned-byte 8) (*)) (integer 0) (integer 0) (integer 1))
              (or null cons))
  "WP-ZEROCOPY (FR-PF-3, ADR 0014): loan PAYLOAD[off,off+len) into this node's writer pool with refcount
   RESOLVES (the number of times the slot will be resolved+released), and return a (SIZE . BUILD-FN)
   packable DATA item (SN) whose SerializedPayload is the resulting 20-octet zero-copy reference — drop-in
   for %data-builder so the ref rides the existing coalesced DATA path. Returns NIL if the pool is
   saturated / the payload exceeds a slot (%zc-loan NIL) so the caller falls back to the full serialized
   payload (no loss, no double-delivery). RESOLVES is ONE here: this ref is emitted to a SINGLE
   destination and a DATA with readerId UNKNOWN is processed ONCE by that participant's receiver
   (%on-user-data -> one %zc-release), regardless of how many reader endpoints are co-located there — so
   refcount 1 frees the slot after that single resolve (refcount = the matched-reader COUNT would leak the
   slot when a destination has >1 ZC reader endpoint). Bumps zc-sends. WP-FLATDATA-over-ZC (FR-PF-4, ADR
   0015): for a FlatData type the published PAYLOAD already IS the FlatData SerializedPayload (the type's
   serialize=IDENTITY block-copy ran once in %serialize-sample), so loaning it here is %zc-loan's single
   app-buffer->slot copy with NO per-field re-serialize — there is no second serialization on the FlatData
   TX path. (That remaining app->slot copy is the documented v1 limitation; a loan-write API that writes
   the sample straight into the slot is the explicit follow-up — out of scope here. The Phase-D 0-copy win
   is on RX.) NOT cleared for ship — counsel (R6)."
  (multiple-value-bind (slot gen)
      (dds.xport.zerocopy::%zc-loan (disc-node-zc-pool-sap node) payload off len resolves)
    (when slot
      (incf (disc-node-zc-sends node))
      (let ((ref (%encode-zc-ref-vec slot gen +zerocopy-pool-slot-bytes+))
            (wid (disc-node-user-writer-id node)))
        (cons (+ 24 (length ref))   ; mirrors %data-builder's small-:data SIZE (4 hdr + 20 body-prefix + payload)
              (lambda (mc) (dds.rtps.message:write-data
                            mc dds.rtps.message:+entityid-unknown+ wid sn ref 0 (length ref))))))))

(defun* %push-data-buf (node buf)
    (function (disc-node dds.core.buffer:octet-buffer) t)
  "Writer side: send each UNSENT change ONCE as a DATA (or DATA_FRAG series for large samples)
   submessage, COALESCED with the trailing HEARTBEAT into as few datagrams as fit the budget
   (%send-changes-packed, RTPS 2.5 §8.3.4/§8.4.2.2), to each matched-reader DESTINATION, using BUF as the
   scratch message buffer (tx-msg on the caller thread; async-tx-msg on the WP-ASYNC sender thread — each
   thread owns its buffer). The unsent-base watermark is kept PER matched reader (keyed by its full GUID,
   §8.3.5.4); %merge-unsent advances every reader sharing a destination and sends their union once. Lost
   or late changes are repaired only via the reader's ACKNACK (%on-user-acknack). When a destination is a
   same-host SHMEM peer (%group-shmem-dest) the coalesced small-sample datagrams take shared memory with
   UDP fallback (FR-XPORT-2); the reader's ACKNACK return path is UDP (%on-user-heartbeat, untouched).
   When the destination's readers are same-host ZC-capable (%zc-readers > 0, WP-ZEROCOPY FR-PF-3) a large
   :data sample crosses as a 16-byte reference instead of a fragmented payload; ZC off -> 0 -> untouched."
  (let ((writer (disc-node-user-writer node)))
    (multiple-value-bind (first last count) (dds.rtps.reliable:writer-heartbeat writer)
      (dolist (group (%reader-push-targets node))   ; DATA + HEARTBEAT -> each matched-reader destination
        (%send-changes-packed node buf
                              (%merge-unsent writer (cdr group)) (caar group) (cdar group)
                              (%heartbeat-builder node first last count)
                              (%group-shmem-dest node group)
                              (%zc-readers node (cdr group)))))))

(defun* %push-data (node)
    (function (disc-node) t)
  "Push unsent changes on the caller thread using tx-msg (the synchronous send path)."
  (%push-data-buf node (disc-node-tx-msg node)))

(defun* %node-datagram-plan (node buf)
    (function (disc-node dds.core.buffer:octet-buffer) list)
  "The FULL per-datagram send-plan for the node's user writer across ALL its matched-reader destinations —
   a flat list of ((HOST . PORT) BUILD-THUNK . SHMEM-DEST) entries, in the SAME order, with the SAME datagram
   bytes, that %push-data-buf's flush-all would send (it walks %reader-push-targets in the same order and
   each group's plan is %changes-datagram-plan). The unsent watermark is captured ONCE here (%merge-unsent
   advances each reader's unsent-base exactly as flush-all does) — so the scheduler must build this plan once
   and then step it, never rebuild mid-drain (that would re-read an already-advanced watermark and send
   nothing). The seam the Phase-C FlowController scheduler drives: build the plan (capturing the unsent set),
   then for each entry build into a scratch buffer (the thunk reports the token cost = datagram length),
   acquire that many tokens, and send — one datagram per RR step. BUF supplies only the packing budget."
  (let ((writer (disc-node-user-writer node))
        (plan '()))
    (multiple-value-bind (first last count) (dds.rtps.reliable:writer-heartbeat writer)
      (dolist (group (%reader-push-targets node))
        (let ((dest (car group)))
          (dolist (entry (%changes-datagram-plan node buf (%merge-unsent writer (cdr group))
                                                  (%heartbeat-builder node first last count)
                                                  (%group-shmem-dest node group)
                                                  (%zc-readers node (cdr group))))
            (push (cons dest entry) plan)))))   ; ((host . port) . (thunk . shmem-dest))
    (nreverse plan)))

(defun* %emit-plan-entry (node buf entry &optional before-send)
    (function (disc-node dds.core.buffer:octet-buffer cons &optional (or null function)) (integer 0))
  "Build ONE node-plan ENTRY — a ((HOST . PORT) BUILD-THUNK . SHMEM-DEST) from %node-datagram-plan — into BUF
   (the thunk writes the datagram and returns its octet length) and send it, returning the length. The
   build-then-send SEAM for the Phase-C FlowController scheduler: BEFORE-SEND, when supplied, is called with
   the just-built datagram's LENGTH AFTER the build but BEFORE the %send-raw-buf — so the scheduler interposes
   its token acquire(length) there (build → acquire → send), the built datagram simply held in BUF across any
   deficit wait, never rebuilt. This is the single place that knows the entry cons-shape (DRY): %flow-step-emit
   passes no BEFORE-SEND (build+send); the scheduler passes its acquire hook."
  (let* ((dest (car entry)) (thunk (cadr entry)) (shmem-dest (cddr entry))
         (len (funcall thunk buf)))
    (when before-send (funcall before-send len))
    (%send-raw-buf node buf len (car dest) (cdr dest) shmem-dest)
    len))

(defun* %flow-step-emit (node buf)
    (function (disc-node dds.core.buffer:octet-buffer) (values (integer 0) t))
  "WP-ASYNC-FLOW node-level STEP entry (FR-PF-2): build + send the NEXT single datagram for NODE's user writer
   across its matched-reader push-targets, returning (values BYTES-SENT MORE-REMAIN-P). The first call (when
   flow-step-state is NIL) snapshots the whole-node datagram plan (%node-datagram-plan, capturing the unsent
   set ONCE — the watermark is advanced here, not per step); each call thereafter emits exactly ONE datagram
   (%emit-plan-entry) from the cached plan and advances it; when the plan drains, flow-step-state is cleared so
   the next call re-snapshots any newly-unsent changes. MORE-REMAIN-P is T while the current plan still holds
   datagrams. The Phase-C FlowController scheduler drives the same plan but interposes a token acquire between
   build and send via %emit-plan-entry's BEFORE-SEND seam. Returns (values 0 NIL) when there is nothing to
   send. Wire-invisible: pacing changes only WHEN a datagram is sent (ADR 0016). BUF is the caller thread's
   scratch buffer."
  (when (null (disc-node-flow-step-state node))
    (setf (disc-node-flow-step-state node) (%node-datagram-plan node buf)))
  (let ((plan (disc-node-flow-step-state node)))
    (if (null plan)
        (progn (setf (disc-node-flow-step-state node) nil) (values 0 nil))
        (let ((len (%emit-plan-entry node buf (car plan))))
          (setf (disc-node-flow-step-state node) (cdr plan))
          (values len (and (cdr plan) t))))))

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

(defun* %async-signal (node)
    (function (disc-node) t)
  "WP-ASYNC: mark work pending and wake the sender thread (the reliable unsent-list IS the queue; the
   sender flushes ALL unsent on wake). Guarded by async-lock."
  (dds.pal:with-lock ((disc-node-async-lock node))
    (setf (disc-node-async-pending node) t)
    (dds.pal:condvar-signal (disc-node-async-cv node)))
  t)

(defun* %async-sender-loop (node)
    (function (disc-node) t)
  "WP-ASYNC sender thread (FR-PF-2): wait for a publish/dispose signal (or shutdown), then flush ALL
   unsent changes on the node's OWN async-tx-msg buffer (%push-data-buf). The async-lock is RELEASED
   before the send (which takes the reliable writer lock) so there is no nested-lock deadlock; the 0.5 s
   wait timeout means a missed signal cannot wedge shutdown. On async-stop, drains a final flush + exits."
  (loop
    (let ((stop nil))
      (dds.pal:with-lock ((disc-node-async-lock node))
        (loop until (or (disc-node-async-stop node) (disc-node-async-pending node))
              do (dds.pal:condvar-wait (disc-node-async-cv node) (disc-node-async-lock node) 0.5))
        (setf stop (disc-node-async-stop node)
              (disc-node-async-pending node) nil))
      (when (disc-node-user-writer node)
        (%push-data-buf node (disc-node-async-tx-msg node)))
      (when stop (return))))
  t)

(defun* enable-async (node)
    (function (disc-node) disc-node)
  "WP-ASYNC (FR-PF-2): give NODE a background SENDER thread so publish-sample returns without blocking on
   the socket. Idempotent. The sender owns its own async-tx-msg scratch buffer (the app thread keeps
   tx-msg, the receiver keeps rx-tx-msg). Call after enable-publisher; stop-node joins + drains it. With
   async on, publish/dispose SIGNAL the sender (the flush-all is adaptive batching); batch-max-samples is
   superseded."
  (unless (disc-node-async-thread node)
    (setf (disc-node-async-tx-msg node) (dds.core.buffer:make-octet-buffer 2048)
          (disc-node-async-stop node) nil
          (disc-node-async-pending node) nil
          (disc-node-async-thread node)
          (dds.pal:spawn (lambda () (%async-sender-loop node)) :name "dds-async-sender")))
  node)

(defun* flush-batch (node)
    (function (disc-node) (eql t))
  "WP-BATCH time/explicit trigger (FR-PF-1): if any batched samples are pending, push them now (coalesced)
   and reset the pending counter. A no-op when nothing is pending. Called on the announce cadence (so a
   partial batch is never stranded) and on stop-node. In WP-ASYNC mode the sender thread does the push, so
   this just signals it."
  (when (plusp (disc-node-batch-pending node))
    (setf (disc-node-batch-pending node) 0)
    (if (disc-node-async-thread node) (%async-signal node) (%push-data node)))
  t)

(defun* publish-sample (node payload &optional (key-hash nil))
    (function (disc-node (simple-array (unsigned-byte 8) (*)) &optional (or null (array (unsigned-byte 8) (*))))
              (or (eql t) (eql :timeout)))
  "Publish PAYLOAD (an opaque SerializedPayload) on the node's user writer: add it to the writer
   HistoryCache, then push DATA + HEARTBEAT to peers (FR-RTPS-8). Returns T normally, or the :timeout
   sentinel (RETCODE_TIMEOUT) if the writer's cache was full and block-up-to-max_blocking_time elapsed
   without freeing a slot — WP-ASYNC-FLOW backpressure (FR-PF-2/FR-QOS, ADR 0016 §Backpressure; only a
   writer enable-publisher'd with a finite :max-samples + :max-blocking-ns can return :timeout, so the
   default path is byte-identical). On :timeout the change was NOT added, so nothing is pushed/signalled
   and no flow/batch state advances (the cache is intact). With WP-BATCH (batch-max-samples > 1,
   FR-PF-1/NFR-PERF-4) the push is DEFERRED — the write accumulates and the batch flushes only when
   batch-max-samples have accumulated (size trigger) or flush-batch fires (time/cadence trigger), so N
   small samples go out coalesced in few datagrams with one amortized HEARTBEAT. Default
   batch-max-samples=1 flushes every write (unchanged behaviour). With WP-ASYNC (enable-async, FR-PF-2)
   the write returns immediately after signalling the sender thread, which does the push off the caller
   thread (the sender's flush-all is adaptive batching, superseding batch-max-samples). With WP-ASYNC-FLOW
   (a flow-controller associated, FR-PF-2, ADR 0016) the write returns immediately after marking the writer
   pending + signalling the controller, whose scheduler thread does the RATE-PACED push off the caller
   thread (an associated controller supersedes both batch and the per-node async sender for that writer).
   KEY-HASH (WP-KEEPLAST, ADR 0019, DDS 1.4 §2.2.3.18) is the sample's 16-octet instance handle threaded
   onto the data CacheChange (writer-write) for per-instance KEEP_LAST eviction; NIL (default) is unchanged."
  (when (eq :timeout (dds.rtps.reliable:writer-write (disc-node-user-writer node) payload key-hash))
    (return-from publish-sample :timeout))   ; full bounded cache, max_blocking_time elapsed: nothing added, nothing to push
  (cond
    ((disc-node-flow-controller node) (%flow-signal (disc-node-flow-controller node) node))   ; WP-ASYNC-FLOW: paced async send
    ((disc-node-async-thread node) (%async-signal node))   ; WP-ASYNC: hand off to the sender thread
    ((>= (incf (disc-node-batch-pending node)) (disc-node-batch-max-samples node)) (flush-batch node))
    (t nil))   ; batch size trigger not reached: defer to the next flush (cadence or fill)
  t)

(defun* %dispose-or-unregister (node key-hash status-flags)
    (function (disc-node (simple-array (unsigned-byte 8) (16)) (unsigned-byte 8)) (or integer (eql :timeout)))
  "Writer side: add a dispose/unregister change for the instance named by KEY-HASH (16 octets)
   to the user writer's HistoryCache (writer-lifecycle-change, deriving the KIND from
   STATUS-FLAGS), then push DATA + HEARTBEAT to peers exactly like publish-sample — so the
   lifecycle DATA is sent AND reliably ACKNACK-repairable (RTPS 2.5 §8.4.2.2 / §9.6.4.9).
   Returns the change's sequence number, OR the :timeout sentinel (RETCODE_TIMEOUT) if the bounded cache
   was full and block-up-to-max_blocking_time elapsed (WP-ASYNC-FLOW backpressure, ADR 0016 §Backpressure;
   a lifecycle change occupies a SN so it is bounded CONSISTENTLY with a DATA write). On :timeout nothing
   was added, so nothing is flushed/pushed/signalled (the batch pacer is left untouched). A lifecycle change
   is NEVER batch-delayed: it pushes immediately, which also flushes any pending batched data first (sent in
   SN order, so a dispose never overtakes its instance's batched samples). With a flow-controller associated
   (WP-ASYNC-FLOW, ADR 0016) it goes through the same paced async path as publish-sample — the lifecycle
   DATA is rate-shaped with the writer's data, in SN order, by the controller thread."
  (let ((sn (dds.rtps.reliable:writer-lifecycle-change (disc-node-user-writer node) key-hash status-flags)))
    (when (eq sn :timeout) (return-from %dispose-or-unregister :timeout))   ; full bounded cache: nothing added, nothing to push
    (setf (disc-node-batch-pending node) 0)   ; the push flushes the pending batch too (data SN < dispose SN)
    (cond
      ((disc-node-flow-controller node) (%flow-signal (disc-node-flow-controller node) node))   ; WP-ASYNC-FLOW: paced async send
      ((disc-node-async-thread node) (%async-signal node))
      (t (%push-data node)))
    sn))

(defun* dispose-instance (node key-hash)
    (function (disc-node (simple-array (unsigned-byte 8) (16))) (or integer (eql :timeout)))
  "Dispose the instance named by KEY-HASH on NODE's user writer (DDS 1.4 §2.2.2.4.2.10): emit a
   no-payload dispose DATA (StatusInfo Disposed, RTPS 2.5 §9.6.4.9) over the reliable engine.
   Returns the change SN, or :timeout (RETCODE_TIMEOUT) under the same block-up-to-max_blocking_time
   backpressure as publish-sample (ADR 0016 §Backpressure; only with a finite bounded cache). Mirrors
   publish-sample so the dispose is reliably repairable."
  (%dispose-or-unregister node key-hash dds.rtps.message:+statusinfo-disposed+))

(defun* unregister-instance (node key-hash &optional (autodispose t))
    (function (disc-node (simple-array (unsigned-byte 8) (16)) &optional t) (or integer (eql :timeout)))
  "Unregister the instance named by KEY-HASH on NODE's user writer (DDS 1.4 §2.2.2.4.2.7): emit a
   no-payload unregister DATA over the reliable engine. When AUTODISPOSE is true (the
   WRITER_DATA_LIFECYCLE default, DDS 1.4 §2.2.3.21) the StatusInfo is Disposed|Unregistered (the
   unregister also disposes the instance, behaviour identical to a dispose before the unregister);
   when false it is Unregistered only (RTPS 2.5 §9.6.4.9). Returns the change SN, or :timeout
   (RETCODE_TIMEOUT) under the same block-up-to-max_blocking_time backpressure as publish-sample
   (ADR 0016 §Backpressure; only with a finite bounded cache). Mirrors
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

;;;; NOT cleared for ship — pending counsel (R6); see ADR 0017.
(defstruct* (zc-loan-marker (:constructor %make-zc-loan-marker))
  "WP-FLATDATA-ZC-LOAN unresolved ZC-ref marker (FR-PF-3/4, R6, ADR 0017): the receiver thread stores THIS
   (not a resolved/copied octet-vector) in disc-node-samples for a zc-loan-capable reader, so the slot stays
   loaned (no copy, no %zc-release on the receiver thread) until DCPS take-loaned acquires + return-loan
   releases it. POOL-SAP is the reader-side attached pool base SAP, SLOT-INDEX + GENERATION the loan handle,
   LEN the wire-declared payload length (re-validated against the slot at acquire). Distinguishable from a
   normal resolved-bytes sample (a simple-array) by ZC-LOAN-MARKER-P, so %drain knows to acquire-for-read vs
   deserialize-normally. NOT cleared for ship — pending counsel (R6)."
  (pool-sap nil :type t) (slot-index 0 :type (integer 0))
  (generation 0 :type (unsigned-byte 32)) (len 0 :type (integer 0)))

(defun* set-zc-loan-capable (node capable)
    (function (disc-node t) t)
  "WP-FLATDATA-ZC-LOAN wiring (FR-PF-3/4, R6, ADR 0017): mark NODE's local user reader loan-capable (CAPABLE
   non-NIL) or not. DCPS calls this on a :flatdata-topic reader created while *zerocopy-enabled* is on, so the
   receiver thread defers ZC resolution (stores the unresolved marker, holds the slot) and DCPS take-loaned /
   return-loan owns the slot lifetime. Default NIL leaves the shipped resolve-copy-release path byte-unchanged.
   NOT cleared for ship — pending counsel (R6)."
  (setf (disc-node-zc-loan-capable node) capable))

(defun* %zc-attach-pool (node src-prefix)
    (function (disc-node (simple-array (unsigned-byte 8) (12))) t)
  "WP-ZEROCOPY reader side (FR-PF-3, ADR 0014): the mapped base SAP of the writer pool published by the
   participant at SRC-PREFIX, or NIL if the pool cannot be opened (a forged/stale source prefix derives a
   deterministic %zc-pool-name that simply does not exist -> shm-attach errors -> cached as :none, dropped
   — never a crash). MEMOIZED per source prefix under zc-attach-lock (attach once per remote writer; two
   receiver threads racing the first attach for one writer are serialized). The attach SIZE uses the
   SHARED geometry constants (+zerocopy-pool-slots+ / +zerocopy-pool-slot-bytes+), NOT a wire-supplied
   value, so an untrusted ref can never size the mapping (NFR-SEC-POSTURE)."
  (dds.pal:with-lock ((disc-node-zc-attach-lock node))
    (let ((cached (gethash src-prefix (disc-node-zc-attach-cache node))))
      (cond
        ((eq cached :none) nil)
        (cached (dds.pal:shm-sap cached))
        (t (let ((seg (ignore-errors
                       (dds.pal:shm-attach (%zc-pool-name src-prefix)
                                           (dds.xport.zerocopy::%zc-bytes
                                            +zerocopy-pool-slots+ +zerocopy-pool-slot-bytes+)))))
             (setf (gethash (copy-seq src-prefix) (disc-node-zc-attach-cache node)) (or seg :none))
             (and seg
                  (dds.xport.zerocopy::%zc-validate (dds.pal:shm-sap seg))   ; ABI magic/version guard
                  (dds.pal:shm-sap seg))))))))

(defun* %zc-try-resolve (node buf poff plen src-prefix)
    (function (disc-node dds.core.buffer:octet-buffer (integer 0) (integer 0)
              (simple-array (unsigned-byte 8) (12))) t)
  "WP-ZEROCOPY / WP-FLATDATA reader side (FR-PF-3/4, ADR 0014/0015; NOT cleared for ship — pending counsel
   R6): test the DATA SerializedPayload at BUF[poff,poff+plen) for a 16-byte zero-copy reference. Returns
   :NOT-A-REF for a normal payload (the caller delivers it unchanged); a fresh (simple-array (unsigned-byte 8))
   holding the RESOLVED serialized payload on a valid ref; or NIL when it IS a ref but resolution fails
   (stale/forced-reclaimed/OOB/attach-fail) — best-effort DROP, no delivery, no crash. READ-THEN-RELEASE
   lifetime (the Phase-D crux): the resolved payload is read IN PLACE from the writer's SHMEM pool slot
   straight into a fresh exact-length node-OWNED vector under the slot mutex (%zc-resolve-fresh — a SINGLE
   intra-host copy; the WP-ZEROCOPY v1 resolve-into-slot-sized-sink-then-re-copy is gone), then the slot is
   %zc-released IMMEDIATELY. The slot's cross-process lifetime therefore ends here and never spans the app's
   later (other-thread, %drain/read) access — so a writer force-reclaim cannot corrupt a delivered sample
   (no cross-process use-after-free). A literal-0-copy SHMEM VIEW handed to the reader is NOT done in v1 and
   would be unsafe here: this stack delivers samples into an async store read on another thread with no
   slot-aware release hook, and an octet-buffer cannot wrap a raw foreign SAP (the FlatData accessors need a
   Lisp simple-array) — see ADR 0015. The ref is UNTRUSTED cross-process input: parse-zc-reference
   bounds-checks the payload region and %zc-resolve-fresh clamps the copy to the fixed slot-bytes + validates
   generation against the slot header (NFR-SEC-POSTURE: never OOB into SHMEM)."
  (multiple-value-bind (slot gen slot-bytes)
      (dds.cdr:parse-zc-reference (dds.core.buffer:octet-buffer-vec buf) poff plen)
    (declare (ignore slot-bytes))
    (if (null slot)
        :not-a-ref
        (let ((sap (%zc-attach-pool node src-prefix)))
          (when sap
            ;; READ-THEN-RELEASE (the WP-FLATDATA-over-ZC single-copy RX path): %zc-resolve-fresh reads the
            ;; slot IN PLACE straight into a freshly-allocated, exact-payload-length owned vector under one
            ;; mutex acquisition (no slot-sized scratch sink + re-copy, as WP-ZEROCOPY v1 did), then we
            ;; %zc-release the slot IMMEDIATELY. The payload now lives in a node-owned Lisp vector, so the
            ;; slot's cross-process lifetime ends here and does NOT span the app's later (other-thread,
            ;; %drain) read — no cross-process use-after-free. The copy is clamped to the fixed slot-bytes,
            ;; never OOB into SHMEM (NFR-SEC-POSTURE).
            (let ((vec (dds.xport.zerocopy::%zc-resolve-fresh sap slot gen)))
              (dds.xport.zerocopy::%zc-release sap slot gen)   ; release now: bytes already copied into the owned VEC
              vec))))))

(defun* %zc-defer (node buf poff plen src-prefix)
    (function (disc-node dds.core.buffer:octet-buffer (integer 0) (integer 0)
              (simple-array (unsigned-byte 8) (12))) t)
  "WP-FLATDATA-ZC-LOAN reader side, the LOAN-CAPABLE branch (FR-PF-3/4, R6, ADR 0017; NOT cleared for ship —
   pending counsel): test the DATA SerializedPayload at BUF[poff,poff+plen) for a 16-byte zero-copy reference.
   Returns :NOT-A-REF for a normal payload (the caller copies+delivers it unchanged); a ZC-LOAN-MARKER (pool-sap
   + slot + generation + len) on a valid ref WITHOUT resolving/copying/releasing — the slot stays loaned via the
   writer's refcount so the app reads it in place through DCPS take-loaned (literal 0 intra-host copies); or NIL
   when it IS a ref but the writer pool cannot be attached (forged/stale src-prefix) — best-effort DROP. This is
   the Phase-D defer: unlike %zc-try-resolve (which read-then-RELEASEs on the receiver thread), the slot's
   cross-process lifetime is HANDED to DCPS — the receiver thread does NOT release it (releasing here would free
   the slot before the app's later read = use-after-free). The ref is UNTRUSTED: parse-zc-reference bounds-checks
   the payload region; the attach SIZE uses the fixed pool geometry, never a wire value; %zc-acquire-for-read
   re-validates the slot + generation + len at acquire (NFR-SEC-POSTURE)."
  (multiple-value-bind (slot gen slot-bytes)
      (dds.cdr:parse-zc-reference (dds.core.buffer:octet-buffer-vec buf) poff plen)
    (if (null slot)
        :not-a-ref
        (let ((sap (%zc-attach-pool node src-prefix)))
          (when sap
            ;; LEN here is the ref's advisory slot-capacity; %zc-acquire-for-read re-derives the AUTHORITATIVE
            ;; clamped payload length from the slot header at acquire, so a forged wire LEN cannot widen a read.
            (%make-zc-loan-marker :pool-sap sap :slot-index slot :generation gen :len slot-bytes))))))

(defun* %deliver-user-marker (node writer-id sn marker src-prefix)
    (function (disc-node (unsigned-byte 32) integer zc-loan-marker
              (simple-array (unsigned-byte 8) (12))) t)
  "WP-FLATDATA-ZC-LOAN (R6, ADR 0017): store the UNRESOLVED ZC-LOAN-MARKER as the sample value (mirrors
   %deliver-user-sample, but the value is the marker, not an octet-vector). The reliable-reader proxy is still
   fed the marker as the change so ACKNACK/HEARTBEAT bookkeeping advances; the 2-level (source-GUID -> SN) store
   keeps the marker so DCPS %drain can acquire-for-read it. ON-SAMPLE fires outside the node lock. NOT cleared
   for ship — pending counsel (R6)."
  (let ((guid (%source-guid src-prefix writer-id)))
    (dds.rtps.reliable:reader-on-data (disc-node-user-reader node) guid sn
                                      (make-array 0 :element-type '(unsigned-byte 8)))
    (dds.pal:with-lock ((disc-node-lock node))
      (setf (gethash sn (%inner-table (disc-node-samples node) guid)) marker
            (gethash sn (%inner-table (disc-node-sample-writers node) guid)) writer-id
            (gethash sn (%inner-table (disc-node-sample-writer-guids node) guid)) guid)))
  (when (disc-node-on-sample node) (funcall (disc-node-on-sample node)))
  t)

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
  "Reader side: deliver the DATA SerializedPayload at BUF[poff,poff+plen). WP-ZEROCOPY (FR-PF-3, ADR
   0014): when this node has a ZC pool (which exists iff *zerocopy-enabled* was set at make-disc-node —
   the gate is the SLOT, not the special, because this runs on the receiver thread where a dynamic
   binding is invisible), FIRST test the payload for a 16-byte zero-copy reference (%zc-try-resolve) — a
   valid ref is resolved from the writer pool to the real serialized payload (then delivered exactly as a
   normal sample); an INVALID ref (stale/forced/OOB/attach-fail) is DROPPED best-effort (no delivery, no
   crash); a normal payload (:not-a-ref) takes the existing copy-and-deliver path verbatim. With ZC off
   (no pool) the ref test is skipped entirely — byte-identical to today (dedup/reorder, store by SN, fire
   ON-SAMPLE outside the node lock — no lock-order inversion).
   WP-FLATDATA-ZC-LOAN (FR-PF-3/4, R6, ADR 0017; NOT cleared for ship — pending counsel): when this node's
   local reader is ZC-LOAN-CAPABLE (DCPS marked it — a :flatdata topic + ZC armed), a valid ref is stored as an
   UNRESOLVED ZC-LOAN-MARKER (%zc-defer) and NOT released — the slot stays loaned via the writer's refcount so
   DCPS take-loaned reads it in place (literal 0 intra-host copies) and return-loan releases it; releasing here
   would free the slot before the app's later read (use-after-free). A non-loan-capable reader keeps the shipped
   resolve-copy-release path (%zc-try-resolve), byte-unchanged."
  (let ((zc (cond
              ((null (disc-node-zc-pool node)) :not-a-ref)         ; the pool's existence == ZC armed at make-disc-node (slot, not the special: this runs on the receiver thread, where a dynamic binding of *zerocopy-enabled* is invisible — mirrors disc-node-shmem); ZC off -> never inspected -> normal path
              ((disc-node-zc-loan-capable node)                    ; loan-capable: DEFER (store unresolved marker, hold the slot)
               (%zc-defer node buf poff plen src-prefix))
              (t (%zc-try-resolve node buf poff plen src-prefix))))) ; shipped path: resolve-copy-release
    (cond
      ((null zc))                                                   ; armed + ref present but defer/resolve FAILED -> drop (best-effort)
      ((eq zc :not-a-ref)                                           ; normal payload (or ZC off): existing path, byte-identical
       (let ((vec (make-array plen :element-type '(unsigned-byte 8))))
         (replace vec (dds.core.buffer:octet-buffer-vec buf) :start2 poff :end2 (+ poff plen))
         (%deliver-user-sample node writer-id sn vec src-prefix)))
      ((zc-loan-marker-p zc) (%deliver-user-marker node writer-id sn zc src-prefix)) ; loan-capable: the unresolved marker
      (t (%deliver-user-sample node writer-id sn zc src-prefix)))   ; resolved ZC payload (non-loan-capable)
    t))

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

(defun* %on-user-gap (node c flags src-prefix)
    (function (disc-node dds.core.buffer:cursor (unsigned-byte 8) (simple-array (unsigned-byte 8) (12))) t)
  "Reader side: a GAP from a matched remote writer marks the SNs it declares irrelevant — the half-open range
   [gapStart, base) plus the bitmap'd SNs — as :gap in the reliable reader's writer-proxy (reader-on-gap), so a
   reliable reader stops NACKing an evicted/unrepairable SN forever and its ack watermark advances (RTPS 2.5
   §8.3.7.4 / §9.4.5.6). parse-gap-body bounds-checks the SequenceNumberSet against the body extent (numBits<=256,
   the M bitmap words fit) BEFORE this trusts it (NFR-SEC-POSTURE) — returns NIL on a short/malformed GAP, which
   this drops. The reader-proxy is keyed by the remote writer's FULL 16-octet GUID (SRC-PREFIX + the GAP's WID,
   §9.4.4 / §9.3.1.2) — the SAME key %on-user-heartbeat / %deliver-user-sample use — so two writers sharing
   EntityId 0x102 across participants keep independent received-SN state (§8.3.5.4). Gated on a matched user
   writer EntityId; mirrors %on-user-heartbeat."
  (multiple-value-bind (rid wid gap-start base numbits bitmap) (dds.rtps.message:parse-gap-body c flags)
    (declare (ignore rid))
    (when (and base (disc-node-user-reader node) (%user-writer-entityid-p wid))
      (dds.rtps.reliable:reader-on-gap (disc-node-user-reader node) (%source-guid src-prefix wid)
                                       gap-start base numbits bitmap)))
  t)

(defun* %on-user-acknack (node c flags src-prefix)
    (function (disc-node dds.core.buffer:cursor (unsigned-byte 8) (simple-array (unsigned-byte 8) (12))) t)
  "Writer side: on an ACKNACK, retransmit each NACKed change PRESENT in the HistoryCache as a DATA submessage
   to the ONE reader that NACKed (uses rx-tx-msg); for each NACKed SN the HC NO LONGER HOLDS (a per-instance
   KEEP_LAST eviction or a RESOURCE_LIMITS drop left the hole, ADR 0019) send ONE GAP marking those SNs
   irrelevant (RTPS 2.5 §8.3.7.4 / §9.4.5.6) so the reliable reader advances past the unrepairable SN instead
   of NACKing it forever; then purge the HistoryCache of changes ALL matched readers have acked
   (writer-purge-acked, §8.4.1). The default unlimited KEEP_ALL writer never evicts, so writer-on-acknack
   returns an EMPTY gaps list and NO GAP is sent (a fully-acked change is purged, never GAPped). The
   reader-proxy is keyed by the REMOTE reader's FULL 16-octet GUID (SRC-PREFIX + the ACKNACK's reader EntityId
   RID, §9.4.4 / §9.3.1.2) — the SAME key %push-data uses for that reader — so two readers sharing EntityId
   0x107 across participants advance independent acked-base watermarks (§8.3.5.4). The resend AND the GAP go
   ONLY to the ACKNACKing participant's destination, resolved from SRC-PREFIX (a NACK is from exactly one
   reader, so fanning out to every matched reader is pure over-send); falls back to every matched reader only
   when the prefix is undiscovered (the discovery-less test path)."
  (multiple-value-bind (rid wid base numbits bitmap count finalp)
      (dds.rtps.message:parse-acknack-body c flags)
    (declare (ignore count finalp))
    (when (= wid (disc-node-user-writer-id node))
      (incf (disc-node-acks-in node))   ; a matched reader (incl. RTI) acked our writer
      (multiple-value-bind (resends gaps)
          (dds.rtps.reliable:writer-on-acknack (disc-node-user-writer node)
                                               (%source-guid src-prefix rid) base numbits bitmap)
        (let* ((dest (%prefix-user-destination node src-prefix))
               (peers (if dest (list dest) (%match-destinations node t))))
          (dolist (peer peers)   ; retransmit present DATA(_FRAG)/dispose, then GAP the missing -> the NACKing reader
            (%send-changes-packed node (disc-node-rx-tx-msg node) resends (car peer) (cdr peer) nil)
            (when gaps (%send-user-gap node (disc-node-rx-tx-msg node) rid gaps (car peer) (cdr peer)))))
        ;; the ACKNACK advanced this reader's acked-base -> purge HistoryCache changes ALL matched readers
        ;; have now acknowledged (RTPS 2.5 §8.4.1), bounding the KEEP_ALL writer history. NACKed (resent)
        ;; changes are not fully acked, so they are never purged.
        (dds.rtps.reliable:writer-purge-acked (disc-node-user-writer node) (%matched-reader-keys node)))))
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

(defun* enable-publisher (node &key max-samples (max-blocking-ns nil)
                                    (history-kind :keep-last) (history-depth 1))
    (function (disc-node &key (:max-samples (or null (integer 1))) (:max-blocking-ns (or null (integer 0)))
                              (:history-kind (member :keep-last :keep-all)) (:history-depth (integer 1)))
              disc-node)
  "Give NODE a reliable user writer honoring its HISTORY QoS and install the writer-side data-plane hooks
   (retransmit on ACKNACK; resend named fragments on NACK_FRAG). Call after add-local-writer. HISTORY-KIND /
   HISTORY-DEPTH (DDS 1.4 §2.2.3.18; defaulting to the spec generic default KEEP_LAST depth 1) size the writer
   HistoryCache: KEEP_LAST retains the last HISTORY-DEPTH changes PER INSTANCE for late-joiner/retransmit;
   KEEP_ALL ignores depth and retains-until-acked, bounded only by RESOURCE_LIMITS (the prior behavior — pass
   :keep-all to preserve it byte-identically). MAX-SAMPLES (RESOURCE_LIMITS max_samples; NIL = unlimited)
   bounds the HistoryCache; MAX-BLOCKING-NS (RELIABILITY.max_blocking_time in ns; NIL = never block) makes
   publish-sample / dispose / unregister BLOCK up to that long on a FULL bounded cache, then return
   RETCODE_TIMEOUT — DDS-standard block-up-to-max_blocking_time backpressure (WP-ASYNC-FLOW, FR-PF-2/FR-QOS,
   ADR 0016 §Backpressure; pairs with a flow-controller, which paces the drain so a bounded cache + bounded
   block keeps the backlog bounded). With MAX-SAMPLES NIL the cache never fills, so MAX-BLOCKING-NS has no
   effect (the bound is the trigger). NOTE (ADR 0019): one engine writer per disc-node is shared by all of a
   publisher's DataWriters, so the HC honors the HISTORY QoS of the DataWriter that (re)enabled the publisher —
   a pre-existing one-writer-per-node limitation, not introduced here."
  (setf (disc-node-user-writer node)
        (dds.rtps.reliable:make-rtps-writer
         :hc (dds.rtps.history:make-history-cache history-kind history-depth max-samples nil)
         :max-blocking-ns max-blocking-ns))
  (setf (disc-node-on-acknack node) (lambda (c flags src-prefix) (%on-user-acknack node c flags src-prefix)))
  (setf (disc-node-on-nack-frag node) (lambda (c flags) (%on-user-nack-frag node c flags)))
  node)

(defun* enable-subscriber (node)
    (function (disc-node) disc-node)
  "Give NODE a reliable user reader and install the reader-side data-plane hooks (store DATA, ACKNACK on
   HEARTBEAT, mark GAP'd SNs irrelevant on GAP, reassemble DATA_FRAG, NACK_FRAG on HEARTBEAT_FRAG). Call after
   add-local-reader."
  (setf (disc-node-user-reader node) (dds.rtps.reliable:make-rtps-reader))
  (setf (disc-node-on-data node)
        (lambda (wid sn buf poff plen src-prefix) (%on-user-data node wid sn buf poff plen src-prefix)))
  (setf (disc-node-on-lifecycle node)
        (lambda (wid sn kind kh sf src-prefix) (%on-user-lifecycle node wid sn kind kh sf src-prefix)))
  (setf (disc-node-on-heartbeat node)
        (lambda (c flags src-prefix) (%on-user-heartbeat node c flags src-prefix)))
  (setf (disc-node-on-gap node)
        (lambda (c flags src-prefix) (%on-user-gap node c flags src-prefix)))
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
