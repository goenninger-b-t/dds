;;;; L5 — SPDP + SEDP discovery over UDP (FR-DISC-1/4). A disc-node owns a
;;;; metatraffic UDPv4 socket and a background receiver thread. SPDP: it announces
;;;; its SPDPdiscoveredParticipantData to its unicast peers and records the
;;;; participants it learns from inbound SPDP. SEDP: it announces its local
;;;; publication/subscription endpoints to discovered participants and records the
;;;; remote endpoints that satisfy RxO matching against its local ones. The wire
;;;; codecs + builtin EntityIds are pinned from docs/specs in DDS.RTPS.*; nothing
;;;; here is memorized. Discovery is control-plane: all serialization reuses two
;;;; per-node scratch buffers (allocated once, freed in stop-node) so repeated
;;;; announces allocate zero foreign memory (NFR-MEM). Single announce thread
;;;; assumed. Multicast still deferred.

(in-package #:dds.disc)

(defstruct* (disc-node (:constructor %make-disc-node))
  "A minimal RTPS participant for discovery. SOCKET/TRANSPORT carry metatraffic;
   PEERS are unicast SPDP targets; DISCOVERED maps a remote 12-octet GUID prefix
   to its SPDP data; LOCAL-WRITERS/LOCAL-READERS are this node's endpoints; MATCHES
   maps a remote 16-octet endpoint GUID to the remote endpoint-data that matched a
   local endpoint; INCOMPAT maps a remote GUID whose topic+type agreed but whose QoS
   failed RxO (drives OFFERED/REQUESTED_INCOMPATIBLE_QOS). LOCK guards DISCOVERED +
   MATCHES + INCOMPAT + PARKED-MATCHES plus the TypeLookup service state (TL-PENDING,
   TL-REQ-SN, TL-REPLY-SN, TL-SENT) across the receiver thread. ON-MATCH /
   ON-INCOMPATIBLE-QOS / ON-SAMPLE are optional control-plane hooks the DCPS layer
   installs to surface matched/incompatible events and newly-arrived user data to the
   application (DDS statuses, listeners, and the condvar-driven WaitSet wake); each
   match/incompatible hook fires once per remote endpoint, ON-SAMPLE once per stored
   user sample. TYPE-GATE is an optional type-compatibility gate consulted OUTSIDE
   the lock (user code, like the ON-* hooks) as (funcall gate node remote local) —
   REMOTE + LOCAL are dds.rtps.discovery:endpoint-data — before a match is recorded
   in EITHER direction; verdicts: :compatible (record + fire as usual), :incompatible
   (routed to the INCONSISTENT_TOPIC path, like a type-name mismatch), :pending (the
   (direction . remote) decision is parked on PARKED-MATCHES, deduped by remote GUID,
   until resume-parked-matches re-runs it); a NIL gate (default) behaves exactly as
   :compatible. TX-PAYLOAD/TX-MSG are the reused announce scratch buffers."
  (guid-prefix (make-array 12 :element-type '(unsigned-byte 8) :initial-element 0)
               :type (simple-array (unsigned-byte 8) (12)))
  (domain 0 :type (integer 0))
  (advertise-address "127.0.0.1" :type string)
  (socket nil :type t)
  (transport nil :type (or null dds.xport:transport))
  (spdp-sn 0 :type integer)
  (sedp-sn 0 :type integer)
  (peers '() :type list)
  (discovered (make-hash-table :test 'equalp) :type hash-table)
  (matches (make-hash-table :test 'equalp) :type hash-table)
  (incompat (make-hash-table :test 'equalp) :type hash-table)
  (inconsistent (make-hash-table :test 'equalp) :type hash-table)
  (parked-matches '() :type list) ; (direction . remote endpoint-data), TYPE-GATE :pending; stale snapshots are pre-empted by SEDP re-announce

  (discovered-writers (make-hash-table :test 'equalp) :type hash-table) ; all remote publications
  (discovered-readers (make-hash-table :test 'equalp) :type hash-table) ; all remote subscriptions
  (local-writers '() :type list)
  (local-readers '() :type list)
  (lock (dds.pal:make-lock "disc-node") :type t)
  (tx-payload nil :type (or null dds.core.buffer:octet-buffer))
  (tx-msg nil :type (or null dds.core.buffer:octet-buffer))
  (rx-tx-msg nil :type (or null dds.core.buffer:octet-buffer))
  (user-writer nil :type (or null dds.rtps.reliable:rtps-writer))
  (user-reader nil :type (or null dds.rtps.reliable:rtps-reader))
  (samples (make-hash-table :test 'eql) :type hash-table)
  (ack-count 0 :type integer)
  (acks-in 0 :type integer)
  (builtin-readers (make-hash-table :test 'equalp) :type hash-table) ; remote 12-octet prefix -> reliable SEDP reader
  ;; TypeLookup service endpoint state (typelookup-endpoints.lisp, XTypes 1.3 §7.6.3.3)
  (tl-pending (make-hash-table :test 'eql) :type hash-table) ; request SN -> tl-pending-entry
  (tl-req-sn 1 :type integer)
  (tl-reply-sn 1 :type integer)
  (tl-sent '() :type list) ; reply writer resend store: newest-first (sn . reply-octets)

  (on-data nil :type (or null function))
  (on-heartbeat nil :type (or null function))
  (on-acknack nil :type (or null function))
  (on-data-frag nil :type (or null function))
  (on-heartbeat-frag nil :type (or null function))
  (on-nack-frag nil :type (or null function))
  (on-match nil :type (or null function))
  (type-gate nil :type (or null function))
  (on-incompatible-qos nil :type (or null function))
  (on-inconsistent-topic nil :type (or null function))
  (on-sample nil :type (or null function))
  (mcast-socket nil :type t)
  (mcast-rx-thread nil :type t)
  (rx-thread nil :type t))

(defparameter +spdp-multicast-group+ "239.255.0.1"
  "Well-known SPDP DefaultMulticastLocator address (RTPS 2.5 §9.6.1.1): all
   participants announce + listen on UDPv4 239.255.0.1 : spdp-multicast-port.")

(defun* make-disc-node (&key (guid-prefix (make-array 12 :element-type '(unsigned-byte 8)
                                                     :initial-element 0))
                            (domain 0) (host "127.0.0.1") (port 0) (peers '()) multicast
                            (advertise-address "127.0.0.1"))
    (function (&key (:guid-prefix (simple-array (unsigned-byte 8) (12))) (:domain (integer 0)) (:host string) (:port (unsigned-byte 16)) (:peers list) (:multicast t) (:advertise-address string)) disc-node)
  "Open a metatraffic UDPv4 socket bound to HOST:PORT and build a discovery node.
   PEERS is a list of (host-string . port) the node announces SPDP to (FR-DISC-4).
   MULTICAST opens a second socket bound to the SPDP multicast port and joins the
   well-known group, so the node also discovers peers via multicast (FR-DISC-3)."
  ;; In multicast mode bind the unicast socket to 0.0.0.0: a loopback-bound socket
  ;; cannot egress to a multicast group (EADDRNOTAVAIL), and 0.0.0.0 still receives
  ;; unicast SEDP addressed to 127.0.0.1:port.
  (multiple-value-bind (tr sock)
      (dds.xport.udp:make-udp-transport :host (if multicast "0.0.0.0" host) :port port)
    (let ((node (%make-disc-node :guid-prefix guid-prefix :domain domain
                                 :advertise-address advertise-address
                                 :socket sock :transport tr :peers peers
                                 :tx-payload (dds.core.buffer:make-octet-buffer 512)
                                 :tx-msg (dds.core.buffer:make-octet-buffer 2048)
                                 :rx-tx-msg (dds.core.buffer:make-octet-buffer 2048))))
      (when multicast
        (let ((ms (dds.pal:udp-open :host "0.0.0.0"
                                    :port (dds.rtps.message:spdp-multicast-port domain)
                                    :reuse-port t)))
          (dds.pal:udp-join-multicast ms +spdp-multicast-group+)
          (setf (disc-node-mcast-socket node) ms)))
      node)))

(defun* disc-node-port (node)
    (function (disc-node) (integer 0 65535))
  "The bound metatraffic UDP port of NODE."
  (dds.xport.udp:udp-transport-local-port (disc-node-socket node)))

(defun* %locator-port (p)
    (function ((unsigned-byte 32)) (unsigned-byte 16))
  "Narrow a wire Locator port (u32) to the UDP port range (u16)."
  (ldb (byte 16 0) p))

(defun* %make-endpoint-guid (prefix key kind)
    (function ((simple-array (unsigned-byte 8) (12)) (unsigned-byte 8) (unsigned-byte 8)) (simple-array (unsigned-byte 8) (16)))
  "GUID_t = 12-octet participant PREFIX + 4-octet entity id (00 00 KEY KIND),
   RTPS 2.5 §9.3.1.2."
  (let ((g (make-array 16 :element-type '(unsigned-byte 8) :initial-element 0)))
    (replace g prefix :start1 0 :end1 12)
    (setf (aref g 14) key (aref g 15) kind)
    g))

(defun* %ipv4-octets (host)
    (function (string) (simple-array (unsigned-byte 8) (4)))
  "Parse a dotted-quad 'a.b.c.d' string into a 4-octet vector."
  (let ((v (make-array 4 :element-type '(unsigned-byte 8))) (start 0))
    (dotimes (i 4 v)
      (let ((dot (position #\. host :start start)))
        (setf (aref v i) (parse-integer host :start start :end dot)
              start (if dot (1+ dot) (length host)))))))

(defun* %node-spdp-data (node)
    (function (disc-node) dds.rtps.discovery:spdp-data)
  "Build NODE's SPDPdiscoveredParticipantData: its GUID prefix + a unicast locator
   at <advertise-address>:<bound port> (default 127.0.0.1), protocol version 2.5."
  (let* ((addr (dds.rtps.discovery:make-ipv4-locator
                (%ipv4-octets (disc-node-advertise-address node))))
         (port (disc-node-port node))
         (loc (dds.rtps.discovery:make-locator
               :kind dds.rtps.discovery:+locator-kind-udpv4+ :port port :address addr)))
    (dds.rtps.discovery:make-spdp-data
     :guid-prefix (disc-node-guid-prefix node)
     :version-major 2 :version-minor 5
     :vendor-id dds.rtps.message:*vendor-id*
     :default-unicast-locators (list loc)
     :metatraffic-unicast-locators (list loc)
     :lease-duration-seconds 100
     :builtin-endpoint-set dds.rtps.discovery:+builtin-endpoint-set-default+)))

(defun* %send-paramlist (node reader-id writer-id sn serialize-fn host port)
    (function (disc-node (unsigned-byte 32) (unsigned-byte 32) integer function string (unsigned-byte 16)) t)
  "Build a PL_CDR_LE SerializedPayload by calling SERIALIZE-FN on a fresh cursor
   over the node's reusable payload buffer, wrap it in a DATA submessage
   (READER-ID/WRITER-ID/SN) in the node's reusable message buffer, and send it to
   HOST:PORT. Reuses per-node scratch buffers — single announce thread assumed."
  (let* ((pl (disc-node-tx-payload node))
         (pc (dds.core.buffer:cursor pl :endianness :little)))
    (dds.cdr:make-encapsulation-header pc :pl-cdr-le)
    (funcall serialize-fn pc)
    (let* ((pl-len (dds.core.buffer:cursor-position pc))
           (pl-vec (dds.core.buffer:octet-buffer-vec pl))
           (msg (disc-node-tx-msg node))
           (mc (dds.core.buffer:cursor msg :endianness :little)))
      (dds.rtps.message:write-header mc (disc-node-guid-prefix node))
      (dds.rtps.message:write-data mc reader-id writer-id sn pl-vec 0 pl-len)
      (dds.xport:send (disc-node-transport node)
                      (dds.xport.udp:make-udp-locator :host host :port port)
                      msg 0 (dds.core.buffer:cursor-position mc)))))

(defun* announce-participant (node)
    (function (disc-node) (eql t))
  "Announce NODE's SPDPdiscoveredParticipantData (writer = SPDP builtin participant
   writer) to every unicast peer (FR-DISC-1/4) and, if multicast is enabled, to the
   well-known SPDP multicast group (FR-DISC-3). The SPDP data advertises the node's
   unicast metatraffic locator, so SEDP comes back unicast either way."
  (incf (disc-node-spdp-sn node))
  (let ((sn (disc-node-spdp-sn node))
        (data (%node-spdp-data node)))
    (flet ((send-spdp (host port)
             (%send-paramlist node
                              dds.rtps.discovery:+entityid-spdp-reader+
                              dds.rtps.discovery:+entityid-spdp-writer+
                              sn
                              (lambda (c) (dds.rtps.discovery:serialize-spdp-data c data))
                              host port)))
      (dolist (peer (disc-node-peers node))
        (send-spdp (car peer) (cdr peer)))
      (when (disc-node-mcast-socket node)
        (send-spdp +spdp-multicast-group+
                   (dds.rtps.message:spdp-multicast-port (disc-node-domain node))))))
  t)

(defun* %qos-from-reliability (reliability)
    (function (integer) dds.qos:qos)
  "Build a QoS from a legacy wire reliability constant (back-compat for callers that
   pass :reliability rather than a full :qos)."
  (dds.qos:make-qos :reliability (if (>= reliability dds.rtps.discovery:+reliability-reliable+)
                                     :reliable :best-effort)))

(defun* add-local-writer (node &key (topic "") (type "")
                                   (reliability dds.rtps.discovery:+reliability-reliable+)
                                   (key 1) qos type-information)
    (function (disc-node &key (:topic string) (:type string) (:reliability integer) (:key (unsigned-byte 8)) (:qos t) (:type-information t)) dds.rtps.discovery:endpoint-data)
  "Register a local publication (writer endpoint) on NODE with QOS (or a QoS derived from
   the legacy :reliability constant). TYPE-INFORMATION is the opaque serialized XTypes
   TypeInformation for PID_TYPE_INFORMATION. announce-endpoints sends it via SEDP.
   Entity kind 0x02 (writer WITH key): the data plane is keyed (matching the keyed reader
   kind 0x07), and a keyed remote reader (RTI Connext) will not match a no-key writer."
  (let ((ep (dds.rtps.discovery:make-endpoint-data
             :guid (%make-endpoint-guid (disc-node-guid-prefix node) key #x02)
             :topic-name topic :type-name type :type-information type-information
             :qos (or qos (%qos-from-reliability reliability)))))
    (push ep (disc-node-local-writers node))
    ep))

(defun* add-local-reader (node &key (topic "") (type "")
                                   (reliability dds.rtps.discovery:+reliability-best-effort+)
                                   (key 1) qos type-information)
    (function (disc-node &key (:topic string) (:type string) (:reliability integer) (:key (unsigned-byte 8)) (:qos t) (:type-information t)) dds.rtps.discovery:endpoint-data)
  "Register a local subscription (reader endpoint) on NODE with QOS (or a QoS derived from
   the legacy :reliability constant). TYPE-INFORMATION is the opaque serialized XTypes
   TypeInformation for PID_TYPE_INFORMATION. announce-endpoints sends it via SEDP."
  (let ((ep (dds.rtps.discovery:make-endpoint-data
             :guid (%make-endpoint-guid (disc-node-guid-prefix node) key #x07)
             :topic-name topic :type-name type :type-information type-information
             :qos (or qos (%qos-from-reliability reliability)))))
    (push ep (disc-node-local-readers node))
    ep))

(defun* %discovered-participants (node)
    (function (disc-node) list)
  "Snapshot the discovered participants' SPDP data (lock-guarded)."
  (dds.pal:with-lock ((disc-node-lock node))
    (loop for v being the hash-values of (disc-node-discovered node) collect v)))

(defun* %send-endpoint (node reader-id writer-id ep sn host port)
    (function (disc-node (unsigned-byte 32) (unsigned-byte 32) dds.rtps.discovery:endpoint-data integer string (unsigned-byte 16)) t)
  "Announce one local endpoint EP via a SEDP DATA submessage to HOST:PORT with the STABLE
   per-writer sequence number SN. Re-announcing an endpoint RESENDS the same SN (a
   retransmission), never a fresh one: a remote RELIABLE SEDP reader cannot deliver any
   sample while an earlier SN is missing, so an ever-incrementing SN plus one lost push
   would gap it permanently (RTPS 2.5 §8.5.4 — each endpoint is one writer sample)."
  (%send-paramlist node reader-id writer-id sn
                   (lambda (c) (dds.rtps.discovery:serialize-endpoint-data c ep))
                   host port))

;;; ---- Reliable builtin (SEDP) discovery: ACKNACK remote builtin writers so a
;;; reliable peer (e.g. RTI Connext) pushes its SEDP DATA(w)/(r). A remote builtin
;;; writer (pub 0x...03c2 / sub 0x...04c2) is RELIABLE; without an ACKNACK it never
;;; sends its endpoint data. Builtin writers share their EntityId across participants,
;;; so SN state is tracked per remote participant (12-octet source GUID prefix).

(defun* %sedp-reader-id-for (writer-id)
    (function ((unsigned-byte 32)) (or null (unsigned-byte 32)))
  "The local SEDP reader EntityId matching a remote builtin SEDP writer WRITER-ID
   (publications/subscriptions), or NIL if WRITER-ID is not a builtin SEDP writer."
  (cond ((= writer-id dds.rtps.discovery:+entityid-sedp-pub-writer+)
         dds.rtps.discovery:+entityid-sedp-pub-reader+)
        ((= writer-id dds.rtps.discovery:+entityid-sedp-sub-writer+)
         dds.rtps.discovery:+entityid-sedp-sub-reader+)
        (t nil)))

(defun* %source-prefix (buf)
    (function (dds.core.buffer:octet-buffer) (simple-array (unsigned-byte 8) (12)))
  "The 12-octet source GUID prefix from the RTPS header of datagram BUF (offset 8; §9.4.4)."
  (let ((p (make-array 12 :element-type '(unsigned-byte 8))))
    (replace p (dds.core.buffer:octet-buffer-vec buf) :start2 8 :end2 20)
    p))

;; TypeLookup endpoint handlers: defined in typelookup-endpoints.lisp (loaded after this file).
(declaim (ftype (function ((unsigned-byte 32)) t) %tl-writer-p)
         (ftype (function ((unsigned-byte 32)) (or null (unsigned-byte 32))) %tl-reader-id-for)
         (ftype (function (disc-node (simple-array (unsigned-byte 8) (12)) (unsigned-byte 32) integer dds.core.buffer:octet-buffer (integer 0) (integer 0)) t) %on-tl-data)
         (ftype (function (disc-node (simple-array (unsigned-byte 8) (12)) dds.core.buffer:cursor (unsigned-byte 8)) t) %on-tl-acknack)
         (ftype (function (disc-node) (eql t)) tl-sweep))

(defun* %builtin-reader-nl (node prefix)
    (function (disc-node (simple-array (unsigned-byte 8) (12))) t)
  "Get/create the per-remote reliable SEDP reader for PREFIX. CALLER HOLDS the node lock."
  (or (gethash prefix (disc-node-builtin-readers node))
      (setf (gethash (copy-seq prefix) (disc-node-builtin-readers node))
            (dds.rtps.reliable:make-rtps-reader))))

(defun* %builtin-acknack-values (node prefix wid &optional hb-first hb-last)
    (function (disc-node (simple-array (unsigned-byte 8) (12)) (unsigned-byte 32) &optional (or null integer) (or null integer)) (values integer (unsigned-byte 32) (simple-array (unsigned-byte 32) (*)) (unsigned-byte 32)))
  "Under the node lock: optionally apply a HEARTBEAT range [HB-FIRST, HB-LAST] to the
   per-remote SEDP reader for WID, then compute its ACKNACK. Returns (values base numbits
   bitmap count). BITMAP is freshly allocated so it is safe to use outside the lock."
  (dds.pal:with-lock ((disc-node-lock node))
    (let ((reader (%builtin-reader-nl node prefix)))
      (when (and hb-first hb-last)
        (dds.rtps.reliable:reader-on-heartbeat reader wid hb-first hb-last))
      (multiple-value-bind (base numbits bitmap) (dds.rtps.reliable:reader-acknack reader wid)
        (values base numbits bitmap (incf (disc-node-ack-count node)))))))

(defun* %builtin-on-data (node prefix wid sn)
    (function (disc-node (simple-array (unsigned-byte 8) (12)) (unsigned-byte 32) integer) t)
  "Under the node lock: record a received builtin SEDP DATA SN from remote PREFIX's
   writer WID so the next ACKNACK advances past it (stops the reliable retransmit)."
  (dds.pal:with-lock ((disc-node-lock node))
    (dds.rtps.reliable:reader-on-data (%builtin-reader-nl node prefix) wid sn
                                       #.(make-array 0 :element-type '(unsigned-byte 8)))))

(defun* %remote-metatraffic (node prefix)
    (function (disc-node (simple-array (unsigned-byte 8) (12))) (or null cons))
  "The (host . port) of participant PREFIX's metatraffic unicast locator, or NIL."
  (let ((spdp (dds.pal:with-lock ((disc-node-lock node))
                (gethash prefix (disc-node-discovered node)))))
    (when spdp
      (let ((loc (dds.rtps.discovery:usable-udpv4-locator
                  (dds.rtps.discovery:spdp-data-metatraffic-unicast-locators spdp))))
        (when loc
          (let ((port (%locator-port (dds.rtps.discovery:locator-port loc))))
            (when (plusp port)
              (cons (dds.rtps.discovery:locator-ipv4-string loc) port))))))))

(defun* %send-acknack (node buf reader-id writer-id base numbits bitmap count final host port)
    (function (disc-node dds.core.buffer:octet-buffer (unsigned-byte 32) (unsigned-byte 32) integer (unsigned-byte 32) (simple-array (unsigned-byte 32) (*)) (unsigned-byte 32) t string (unsigned-byte 16)) t)
  "Build an RTPS message (Header + ACKNACK) into BUF and send it to HOST:PORT. BUF is the
   caller-thread scratch buffer (tx-msg on the announce thread, rx-tx-msg on the receiver)."
  (let ((mc (dds.core.buffer:cursor buf :endianness :little)))
    (dds.rtps.message:write-header mc (disc-node-guid-prefix node))
    (dds.rtps.message:write-acknack mc reader-id writer-id base numbits bitmap count :final final)
    (dds.xport:send (disc-node-transport node)
                    (dds.xport.udp:make-udp-locator :host host :port port)
                    buf 0 (dds.core.buffer:cursor-position mc))))

(defun* %on-builtin-heartbeat (node prefix rid wid first last)
    (function (disc-node (simple-array (unsigned-byte 8) (12)) (unsigned-byte 32) (unsigned-byte 32) integer integer) t)
  "Receiver-thread: a HEARTBEAT from remote PREFIX's builtin writer WID (SEDP or
   TypeLookup). Apply its range, then ACKNACK from our matching builtin reader RID to
   that participant's metatraffic locator to pull what is missing. Uses the
   receiver-thread rx-tx-msg buffer."
  (let ((hp (%remote-metatraffic node prefix)))
    (when hp
      (multiple-value-bind (base numbits bitmap count)
          (%builtin-acknack-values node prefix wid first last)
        (%send-acknack node (disc-node-rx-tx-msg node) rid wid base numbits bitmap count
                       t (car hp) (cdr hp))))))

(defun* announce-endpoints (node)
    (function (disc-node) (eql t))
  "Send NODE's local publications (SEDP publications writer) and subscriptions
   (SEDP subscriptions writer) to every discovered participant's metatraffic
   unicast locator (RTPS 2.5 §8.5.4). Also drives tl-sweep, expiring overdue
   TypeLookup queries on the periodic announce cadence."
  (dolist (p (%discovered-participants node))
    (let ((loc (dds.rtps.discovery:usable-udpv4-locator
                (dds.rtps.discovery:spdp-data-metatraffic-unicast-locators p))))
      (when loc
        (let ((host (dds.rtps.discovery:locator-ipv4-string loc))
              (port (%locator-port (dds.rtps.discovery:locator-port loc))))
          ;; STABLE per-writer SNs: reverse -> add-order (oldest first); each endpoint's
          ;; 1-based add-order index is its fixed SN, unchanged as later endpoints are
          ;; pushed on. The publications (0x3c2) and subscriptions (0x4c2) writers each
          ;; have their own 1-based SN space.
          (loop for w in (reverse (disc-node-local-writers node)) for wsn from 1 do
            (%send-endpoint node
                            dds.rtps.discovery:+entityid-sedp-pub-reader+
                            dds.rtps.discovery:+entityid-sedp-pub-writer+
                            w wsn host port))
          (loop for r in (reverse (disc-node-local-readers node)) for rsn from 1 do
            (%send-endpoint node
                            dds.rtps.discovery:+entityid-sedp-sub-reader+
                            dds.rtps.discovery:+entityid-sedp-sub-writer+
                            r rsn host port))
          ;; Pre-emptive ACKNACK to the peer's reliable builtin SEDP writers so it
          ;; pushes its publication/subscription endpoint data (RTPS 2.5 §8.4.10.4).
          ;; non-final -> solicit a HEARTBEAT; the per-remote reader advances the ACK
          ;; as the SEDP arrives, so this stops soliciting once endpoints are in.
          (let ((prefix (dds.rtps.discovery:spdp-data-guid-prefix p)))
            (dolist (wid (list dds.rtps.discovery:+entityid-sedp-pub-writer+
                               dds.rtps.discovery:+entityid-sedp-sub-writer+))
              (multiple-value-bind (base numbits bitmap count)
                  (%builtin-acknack-values node prefix wid)
                (%send-acknack node (disc-node-tx-msg node)
                               (%sedp-reader-id-for wid) wid base numbits bitmap count
                               nil host port))))))))
  (tl-sweep node)
  t)

(defun* %record-participant (node spdp)
    (function (disc-node dds.rtps.discovery:spdp-data) t)
  "Record a discovered participant (its SPDP data) keyed by GUID prefix, ignoring
   this node's own announcements (loopback echo / self in peers)."
  (let ((prefix (dds.rtps.discovery:spdp-data-guid-prefix spdp)))
    (unless (equalp prefix (disc-node-guid-prefix node))
      (dds.pal:with-lock ((disc-node-lock node))
        (setf (gethash (copy-seq prefix) (disc-node-discovered node)) spdp)))))

(defun* %record-match (node remote)
    (function (disc-node dds.rtps.discovery:endpoint-data) boolean)
  "Record a matched REMOTE endpoint keyed by its 16-octet GUID (lock-guarded). Returns
   T only the FIRST time REMOTE is recorded (so a MATCHED status fires once, not once
   per re-announce); NIL if REMOTE was already matched."
  (dds.pal:with-lock ((disc-node-lock node))
    (let ((key (copy-seq (dds.rtps.discovery:endpoint-data-guid remote))))
      (if (nth-value 1 (gethash key (disc-node-matches node)))
          nil
          (progn (setf (gethash key (disc-node-matches node)) remote) t)))))

(defun* %record-incompat (node remote)
    (function (disc-node dds.rtps.discovery:endpoint-data) boolean)
  "Record REMOTE as RxO-incompatible (topic+type matched, QoS failed), keyed by its
   GUID (lock-guarded). Returns T only the first time, so INCOMPATIBLE_QOS fires once
   per remote endpoint, not once per re-announce."
  (dds.pal:with-lock ((disc-node-lock node))
    (let ((key (copy-seq (dds.rtps.discovery:endpoint-data-guid remote))))
      (if (nth-value 1 (gethash key (disc-node-incompat node)))
          nil
          (progn (setf (gethash key (disc-node-incompat node)) remote) t)))))

(defun* %record-inconsistent (node remote)
    (function (disc-node dds.rtps.discovery:endpoint-data) boolean)
  "Record REMOTE as an inconsistent-topic source (same topic name as a local endpoint,
   different type name), keyed by its GUID. Returns T only the first time, so
   INCONSISTENT_TOPIC fires once per remote endpoint."
  (dds.pal:with-lock ((disc-node-lock node))
    (let ((key (copy-seq (dds.rtps.discovery:endpoint-data-guid remote))))
      (if (nth-value 1 (gethash key (disc-node-inconsistent node)))
          nil
          (progn (setf (gethash key (disc-node-inconsistent node)) remote) t)))))

(defun* %fire-match (node kind remote)
    (function (disc-node keyword dds.rtps.discovery:endpoint-data) t)
  "Invoke the ON-MATCH hook (if installed) once for a newly-matched REMOTE endpoint."
  (when (disc-node-on-match node)
    (funcall (disc-node-on-match node) kind remote)))

(defun* %fire-inconsistent (node topic-name)
    (function (disc-node string) t)
  "Invoke the ON-INCONSISTENT-TOPIC hook (if installed) for a newly-detected topic-name
   collision (same name, different type) — drives INCONSISTENT_TOPIC (FR-DCPS-3)."
  (when (disc-node-on-inconsistent-topic node)
    (funcall (disc-node-on-inconsistent-topic node) topic-name)))

(defun* %fire-incompat (node kind remote bad)
    (function (disc-node keyword dds.rtps.discovery:endpoint-data list) t)
  "Invoke the ON-INCOMPATIBLE-QOS hook (if installed) for a newly-detected RxO
   incompatibility, passing the failing-policy keyword list BAD (FR-QOS-2 / FR-DCPS-3)."
  (when (disc-node-on-incompatible-qos node)
    (funcall (disc-node-on-incompatible-qos node) kind remote bad)))

(defun* %record-discovered (table remote)
    (function (hash-table dds.rtps.discovery:endpoint-data) t)
  "Record a discovered remote endpoint REMOTE in TABLE keyed by its 16-octet GUID
   (lock-free; TABLE is guarded by the caller). Latest data wins; used by the builtin-
   topic readers (FR-DCPS-6) to surface ALL discovered endpoints, matched or not."
  (setf (gethash (copy-seq (dds.rtps.discovery:endpoint-data-guid remote)) table) remote))

(defun* disc-node-discovered-writers-list (node)
    (function (disc-node) list)
  "Snapshot of every discovered remote publication (endpoint-data), lock-guarded."
  (dds.pal:with-lock ((disc-node-lock node))
    (loop for v being the hash-values of (disc-node-discovered-writers node) collect v)))

(defun* disc-node-discovered-readers-list (node)
    (function (disc-node) list)
  "Snapshot of every discovered remote subscription (endpoint-data), lock-guarded."
  (dds.pal:with-lock ((disc-node-lock node))
    (loop for v being the hash-values of (disc-node-discovered-readers node) collect v)))

(defun* %consult-type-gate (node remote local)
    (function (disc-node dds.rtps.discovery:endpoint-data dds.rtps.discovery:endpoint-data) t)
  "Ask the TYPE-GATE hook for a type-compatibility verdict on the (REMOTE, LOCAL)
   endpoint pair. Called OUTSIDE the node lock on the receiver thread (the gate is
   user code, like the ON-* hooks — see %fire-match). A NIL gate — and any verdict
   other than :incompatible / :pending — proceeds as :compatible."
  (let ((gate (disc-node-type-gate node)))
    (if gate (funcall gate node remote local) :compatible)))

(defun* %park-match (node direction remote)
    (function (disc-node (member :remote-writer :remote-reader) dds.rtps.discovery:endpoint-data) (eql t))
  "Park a TYPE-GATE :pending match decision as (DIRECTION . REMOTE) (lock-guarded),
   deduped by the remote 16-octet GUID; resume-parked-matches re-runs it. A parked
   REMOTE snapshot may go stale, but a fresh SEDP re-announcement re-runs the match
   through the normal path anyway (pre-emption), so resume callers need no refresh."
  (dds.pal:with-lock ((disc-node-lock node))
    (let ((guid (dds.rtps.discovery:endpoint-data-guid remote)))
      (unless (member guid (disc-node-parked-matches node)
                      :key (lambda (e) (dds.rtps.discovery:endpoint-data-guid (cdr e)))
                      :test #'equalp)
        (push (cons direction remote) (disc-node-parked-matches node)))))
  t)

(defun* %match-remote-endpoint (node remote direction)
    (function (disc-node dds.rtps.discovery:endpoint-data (member :remote-writer :remote-reader)) (eql t))
  "Test discovered REMOTE against each local endpoint of the opposite kind (DIRECTION
   :remote-writer -> local readers; :remote-reader -> local writers). On the first
   RxO-compatible local, consult the TYPE-GATE: :compatible (or no gate) records +
   announces the match; :incompatible joins the INCONSISTENT_TOPIC path; :pending
   parks the decision for resume-parked-matches. Else, against a local on the SAME
   topic name: a different type name is an INCONSISTENT_TOPIC; a matching type whose
   QoS failed RxO is OFFERED/REQUESTED_INCOMPATIBLE_QOS (failing policies)."
  (let ((incompat nil) (inconsistent nil) (writer-p (eq direction :remote-writer)))
    (dolist (local (if writer-p (disc-node-local-readers node) (disc-node-local-writers node)))
      (multiple-value-bind (ok bad)
          (if writer-p
              ;; endpoint-match-p wants writer-data first: REMOTE is the writer here
              (dds.rtps.discovery:endpoint-match-p remote local)
              ;; LOCAL is the writer here (REMOTE is a reader); writer-data still first
              (dds.rtps.discovery:endpoint-match-p local remote))
        (cond
          (ok (case (%consult-type-gate node remote local)
                (:incompatible
                 (setf inconsistent (dds.rtps.discovery:endpoint-data-topic-name local)))
                (:pending
                 (%park-match node direction remote)
                 ;; deliberately short-circuits the incompat/inconsistent bookkeeping below
                 (return-from %match-remote-endpoint t))
                (t (when (%record-match node remote) (%fire-match node direction remote))
                   (return-from %match-remote-endpoint t))))
          ((string= (dds.rtps.discovery:endpoint-data-topic-name remote)
                    (dds.rtps.discovery:endpoint-data-topic-name local))
           (if (string= (dds.rtps.discovery:endpoint-data-type-name remote)
                        (dds.rtps.discovery:endpoint-data-type-name local))
               (setf incompat bad)
               (setf inconsistent (dds.rtps.discovery:endpoint-data-topic-name local)))))))
    (cond
      ((and incompat (%record-incompat node remote))
       (%fire-incompat node direction remote incompat))
      ((and inconsistent (%record-inconsistent node remote))
       (%fire-inconsistent node inconsistent))))
  t)

(defun* %match-remote-writer (node remote)
    (function (disc-node dds.rtps.discovery:endpoint-data) (eql t))
  "REMOTE is a discovered publication: match it against the local readers (:remote-writer)."
  (%match-remote-endpoint node remote :remote-writer))

(defun* %match-remote-reader (node remote)
    (function (disc-node dds.rtps.discovery:endpoint-data) (eql t))
  "REMOTE is a discovered subscription: match it against the local writers (:remote-reader)."
  (%match-remote-endpoint node remote :remote-reader))

(defun* resume-parked-matches (node)
    (function (disc-node) (eql t))
  "Re-run every parked (TYPE-GATE :pending) match decision: take + clear the parked
   list under the node lock, then outside the lock re-run the SEDP match for each
   entry — the gate is consulted again; a still-:pending verdict re-parks the entry
   (still deduped by remote GUID). Call once the gate installer has a verdict (e.g.
   a TypeLookup reply arrived)."
  (let ((parked (dds.pal:with-lock ((disc-node-lock node))
                  (shiftf (disc-node-parked-matches node) '()))))
    (dolist (entry parked)
      (%match-remote-endpoint node (cdr entry) (car entry))))
  t)

(defun* disc-node-parked-count (node)
    (function (disc-node) (integer 0))
  "Number of parked (TYPE-GATE :pending) match decisions awaiting resume-parked-matches
   (lock-guarded; diagnostic)."
  (dds.pal:with-lock ((disc-node-lock node))
    (length (disc-node-parked-matches node))))

(defun* %handle-datagram (node buf size)
    (function (disc-node dds.core.buffer:octet-buffer (integer 0)) t)
  "Dispatch an inbound datagram (bounded by SIZE). DATA is routed by writerId: SPDP
   -> record participant; SEDP publications/subscriptions -> match; any other DATA
   plus HEARTBEAT/ACKNACK -> the installed data-plane hooks (nil = ignore). The
   discovery SerializedPayloads are ParameterLists (encap header + list); a user
   DATA payload is opaque bytes handed to the on-data hook as a [poff,plen) region."
  (let ((cursor (dds.core.buffer:cursor buf :endianness :little))
        (src-prefix (%source-prefix buf)))
    (dds.rtps.message:dispatch-message
     cursor
     (lambda (id flags c body-len)
       (cond
         ((= id dds.rtps.message:+submsg-data+)
          (multiple-value-bind (rdr wtr sn has-payload poff plen keyp)
              (dds.rtps.message:parse-data-body c flags body-len)
            (declare (ignore rdr keyp))
            (when has-payload
              (cond
                ((= wtr dds.rtps.discovery:+entityid-spdp-writer+)
                 (let ((pc (dds.core.buffer:cursor buf :endianness :little)))
                   (dds.core.buffer:cursor-set-position pc poff)
                   (dds.cdr:parse-encapsulation-header pc)
                   (let ((spdp (dds.rtps.discovery:parse-spdp-data pc)))
                     (when spdp (%record-participant node spdp)))))
                ((= wtr dds.rtps.discovery:+entityid-sedp-pub-writer+)
                 (let ((pc (dds.core.buffer:cursor buf :endianness :little)))
                   (dds.core.buffer:cursor-set-position pc poff)
                   (dds.cdr:parse-encapsulation-header pc)
                   (let ((ep (dds.rtps.discovery:parse-endpoint-data pc :writer)))
                     (when ep
                       (dds.pal:with-lock ((disc-node-lock node))
                         (%record-discovered (disc-node-discovered-writers node) ep))
                       (%match-remote-writer node ep))
                     (%builtin-on-data node src-prefix wtr sn))))
                ((= wtr dds.rtps.discovery:+entityid-sedp-sub-writer+)
                 (let ((pc (dds.core.buffer:cursor buf :endianness :little)))
                   (dds.core.buffer:cursor-set-position pc poff)
                   (dds.cdr:parse-encapsulation-header pc)
                   (let ((ep (dds.rtps.discovery:parse-endpoint-data pc :reader)))
                     (when ep
                       (dds.pal:with-lock ((disc-node-lock node))
                         (%record-discovered (disc-node-discovered-readers node) ep))
                       (%match-remote-reader node ep))
                     (%builtin-on-data node src-prefix wtr sn))))
                ((%tl-writer-p wtr)
                 (%on-tl-data node src-prefix wtr sn buf poff plen))
                ((disc-node-on-data node)
                 (funcall (disc-node-on-data node) wtr sn buf poff plen))))))
         ((= id dds.rtps.message:+submsg-heartbeat+)
          (let ((pos (dds.core.buffer:cursor-position c)))
            (multiple-value-bind (rid wid first last hcount hfinal hlive)
                (dds.rtps.message:parse-heartbeat-body c flags)
              (declare (ignore rid hcount hfinal hlive))
              (let ((bid (or (%sedp-reader-id-for wid) (%tl-reader-id-for wid))))
                (cond
                  (bid (%on-builtin-heartbeat node src-prefix bid wid first last))
                  ((disc-node-on-heartbeat node)
                   (dds.core.buffer:cursor-set-position c pos)
                   (funcall (disc-node-on-heartbeat node) c flags)))))))
         ((= id dds.rtps.message:+submsg-acknack+)
          (let ((pos (dds.core.buffer:cursor-position c)))
            (unless (%on-tl-acknack node src-prefix c flags)
              (when (disc-node-on-acknack node)
                (dds.core.buffer:cursor-set-position c pos)
                (funcall (disc-node-on-acknack node) c flags)))))
         ((and (= id dds.rtps.message:+submsg-data-frag+) (disc-node-on-data-frag node))
          (funcall (disc-node-on-data-frag node) c flags body-len buf))
         ((and (= id dds.rtps.message:+submsg-heartbeat-frag+) (disc-node-on-heartbeat-frag node))
          (funcall (disc-node-on-heartbeat-frag node) c flags))
         ((and (= id dds.rtps.message:+submsg-nack-frag+) (disc-node-on-nack-frag node))
          (funcall (disc-node-on-nack-frag node) c flags))))
     size)
    t))

(defun* start-node (node)
    (function (disc-node) disc-node)
  "Spawn the background receiver thread(s) that process inbound datagrams for NODE:
   the unicast metatraffic socket always, plus the multicast socket if enabled.
   Both feed the same %handle-datagram. Returns NODE."
  (setf (disc-node-rx-thread node)
        (dds.xport.udp:start-udp-receiver
         (disc-node-socket node)
         (lambda (buf size) (%handle-datagram node buf size))))
  (when (disc-node-mcast-socket node)
    (setf (disc-node-mcast-rx-thread node)
          (dds.xport.udp:start-udp-receiver
           (disc-node-mcast-socket node)
           (lambda (buf size) (%handle-datagram node buf size)))))
  node)

(defun* stop-node (node)
    (function (disc-node) (eql t))
  "Close NODE's socket(s) (terminating its receiver thread(s)) and free the reusable
   announce scratch buffers. Idempotent."
  (dds.pal:udp-close (disc-node-socket node))
  (when (disc-node-mcast-socket node)
    (dds.pal:udp-close (disc-node-mcast-socket node))
    (setf (disc-node-mcast-socket node) nil))
  (when (disc-node-tx-payload node)
    (dds.pal:free-static (dds.core.buffer:octet-buffer-vec (disc-node-tx-payload node)))
    (setf (disc-node-tx-payload node) nil))
  (when (disc-node-tx-msg node)
    (dds.pal:free-static (dds.core.buffer:octet-buffer-vec (disc-node-tx-msg node)))
    (setf (disc-node-tx-msg node) nil))
  (when (disc-node-rx-tx-msg node)
    (dds.pal:free-static (dds.core.buffer:octet-buffer-vec (disc-node-rx-tx-msg node)))
    (setf (disc-node-rx-tx-msg node) nil))
  t)

(defun* disc-node-discovered-count (node)
    (function (disc-node) (integer 0))
  "Number of remote participants NODE has discovered."
  (dds.pal:with-lock ((disc-node-lock node))
    (hash-table-count (disc-node-discovered node))))

(defun* disc-node-discovered-prefixes (node)
    (function (disc-node) list)
  "List of the 12-octet GUID prefixes NODE has discovered."
  (dds.pal:with-lock ((disc-node-lock node))
    (loop for k being the hash-keys of (disc-node-discovered node) collect k)))

(defun* disc-node-matched-count (node)
    (function (disc-node) (integer 0))
  "Number of remote endpoints that matched one of NODE's local endpoints."
  (dds.pal:with-lock ((disc-node-lock node))
    (hash-table-count (disc-node-matches node))))

(defun* disc-node-matched-topics (node)
    (function (disc-node) list)
  "Topic names of the remote endpoints NODE has matched."
  (dds.pal:with-lock ((disc-node-lock node))
    (loop for v being the hash-values of (disc-node-matches node)
          collect (dds.rtps.discovery:endpoint-data-topic-name v))))

(defun* run-spdp-discovery-test ()
    (function () (eql t))
  "Two participants on 127.0.0.1, each carrying the other as a unicast peer. Both
   announce SPDP; assert each discovers the other's GUID prefix within a bounded
   wait. Exercises announce -> datagram -> receiver thread -> dispatch -> parse
   SPDP -> record (FR-DISC-1/4)."
  (let* ((p1 (make-array 12 :element-type '(unsigned-byte 8)
                         :initial-contents '(1 1 1 1 1 1 1 1 1 1 1 1)))
         (p2 (make-array 12 :element-type '(unsigned-byte 8)
                         :initial-contents '(2 2 2 2 2 2 2 2 2 2 2 2)))
         (node1 (make-disc-node :guid-prefix p1 :host "127.0.0.1" :port 0))
         (node2 (make-disc-node :guid-prefix p2 :host "127.0.0.1" :port 0)))
    (unwind-protect
         (progn
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
           (assert (plusp (disc-node-discovered-count node1)) ()
                   "node1 did not discover node2 over SPDP/UDP")
           (assert (plusp (disc-node-discovered-count node2)) ()
                   "node2 did not discover node1 over SPDP/UDP")
           (assert (member p2 (disc-node-discovered-prefixes node1) :test #'equalp) ()
                   "node1 recorded the wrong GUID prefix")
           (assert (member p1 (disc-node-discovered-prefixes node2) :test #'equalp) ()
                   "node2 recorded the wrong GUID prefix")
           t)
      (stop-node node1)
      (stop-node node2))))

(defun* run-sedp-discovery-test ()
    (function () (eql t))
  "Full discovery handshake over UDP: two participants on 127.0.0.1 first discover
   each other via SPDP, then exchange endpoints via SEDP. node1 offers a RELIABLE
   writer on (Square, ShapeType); node2 requests a BEST_EFFORT reader on the same
   topic/type. Assert each records the other as a match (RxO compatible: offered
   RELIABLE >= requested BEST_EFFORT) within a bounded wait (FR-DISC-1/4, FR-QOS-2)."
  (let* ((p1 (make-array 12 :element-type '(unsigned-byte 8)
                         :initial-contents '(1 1 1 1 1 1 1 1 1 1 1 1)))
         (p2 (make-array 12 :element-type '(unsigned-byte 8)
                         :initial-contents '(2 2 2 2 2 2 2 2 2 2 2 2)))
         (node1 (make-disc-node :guid-prefix p1 :host "127.0.0.1" :port 0))
         (node2 (make-disc-node :guid-prefix p2 :host "127.0.0.1" :port 0)))
    (unwind-protect
         (progn
           (add-local-writer node1 :topic "Square" :type "ShapeType"
                                   :reliability dds.rtps.discovery:+reliability-reliable+)
           (add-local-reader node2 :topic "Square" :type "ShapeType"
                                   :reliability dds.rtps.discovery:+reliability-best-effort+)
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
           (assert (and (plusp (disc-node-discovered-count node1))
                        (plusp (disc-node-discovered-count node2)))
                   () "SPDP did not complete before SEDP")
           (announce-endpoints node1)
           (announce-endpoints node2)
           (loop repeat 100
                 until (and (plusp (disc-node-matched-count node1))
                            (plusp (disc-node-matched-count node2)))
                 do (sleep 0.02))
           (assert (plusp (disc-node-matched-count node2)) ()
                   "node2's reader did not match node1's writer over SEDP/UDP")
           (assert (plusp (disc-node-matched-count node1)) ()
                   "node1's writer did not match node2's reader over SEDP/UDP")
           (assert (member "Square" (disc-node-matched-topics node1) :test #'string=) ()
                   "node1 matched the wrong topic")
           (assert (member "Square" (disc-node-matched-topics node2) :test #'string=) ()
                   "node2 matched the wrong topic")
           t)
      (stop-node node1)
      (stop-node node2))))

(defun* run-mcast-discovery-test ()
    (function () (eql t))
  "Two participants with NO unicast peers discover each other purely via multicast
   SPDP (well-known group 239.255.0.1 : spdp-multicast-port, RTPS 2.5 §9.6.1.1),
   then match endpoints via unicast SEDP routed to the multicast-discovered unicast
   locators. Proves discovery works with zero initial-peer configuration (FR-DISC-3)."
  (let* ((p1 (make-array 12 :element-type '(unsigned-byte 8)
                         :initial-contents '(1 1 1 1 1 1 1 1 1 1 1 1)))
         (p2 (make-array 12 :element-type '(unsigned-byte 8)
                         :initial-contents '(2 2 2 2 2 2 2 2 2 2 2 2)))
         (node1 (make-disc-node :guid-prefix p1 :host "127.0.0.1" :port 0 :multicast t))
         (node2 (make-disc-node :guid-prefix p2 :host "127.0.0.1" :port 0 :multicast t)))
    (unwind-protect
         (progn
           (add-local-writer node1 :topic "Square" :type "ShapeType"
                                   :reliability dds.rtps.discovery:+reliability-reliable+)
           (add-local-reader node2 :topic "Square" :type "ShapeType"
                                   :reliability dds.rtps.discovery:+reliability-best-effort+)
           (start-node node1)
           (start-node node2)
           (announce-participant node1)
           (announce-participant node2)
           (loop repeat 150
                 until (and (member p2 (disc-node-discovered-prefixes node1) :test #'equalp)
                            (member p1 (disc-node-discovered-prefixes node2) :test #'equalp))
                 do (sleep 0.02))
           (assert (member p2 (disc-node-discovered-prefixes node1) :test #'equalp) ()
                   "node1 did not discover node2 via multicast SPDP")
           (assert (member p1 (disc-node-discovered-prefixes node2) :test #'equalp) ()
                   "node2 did not discover node1 via multicast SPDP")
           (announce-endpoints node1)
           (announce-endpoints node2)
           (loop repeat 100
                 until (and (plusp (disc-node-matched-count node1))
                            (plusp (disc-node-matched-count node2)))
                 do (sleep 0.02))
           (assert (plusp (disc-node-matched-count node1)) ()
                   "node1 did not match node2's endpoint after multicast discovery")
           (assert (plusp (disc-node-matched-count node2)) ()
                   "node2 did not match node1's endpoint after multicast discovery")
           t)
      (stop-node node1)
      (stop-node node2))))
