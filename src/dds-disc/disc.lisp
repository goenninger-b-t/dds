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

(defstruct (disc-node (:constructor %make-disc-node))
  "A minimal RTPS participant for discovery. SOCKET/TRANSPORT carry metatraffic;
   PEERS are unicast SPDP targets; DISCOVERED maps a remote 12-octet GUID prefix
   to its SPDP data; LOCAL-WRITERS/LOCAL-READERS are this node's endpoints; MATCHES
   maps a remote 16-octet endpoint GUID to the remote endpoint-data that matched a
   local endpoint. LOCK guards DISCOVERED + MATCHES across the receiver thread.
   TX-PAYLOAD/TX-MSG are the reused announce scratch buffers."
  (guid-prefix (make-array 12 :element-type '(unsigned-byte 8) :initial-element 0)
               :type (simple-array (unsigned-byte 8) (12)))
  (domain 0 :type (integer 0))
  (advertise-address "127.0.0.1" :type string)
  (socket nil)
  (transport nil)
  (spdp-sn 0 :type integer)
  (sedp-sn 0 :type integer)
  (peers '() :type list)
  (discovered (make-hash-table :test 'equalp) :type hash-table)
  (matches (make-hash-table :test 'equalp) :type hash-table)
  (local-writers '() :type list)
  (local-readers '() :type list)
  (lock (dds.pal:make-lock "disc-node"))
  (tx-payload nil :type (or null dds.core.buffer:octet-buffer))
  (tx-msg nil :type (or null dds.core.buffer:octet-buffer))
  (rx-tx-msg nil :type (or null dds.core.buffer:octet-buffer))
  (user-writer nil)
  (user-reader nil)
  (samples (make-hash-table :test 'eql) :type hash-table)
  (ack-count 0 :type integer)
  (acks-in 0 :type integer)
  (on-data nil :type (or null function))
  (on-heartbeat nil :type (or null function))
  (on-acknack nil :type (or null function))
  (mcast-socket nil)
  (mcast-rx-thread nil)
  (rx-thread nil))

;; Well-known SPDP DefaultMulticastLocator address (RTPS 2.5 §9.6.1.1): all
;; participants announce + listen on UDPv4 239.255.0.1 : spdp-multicast-port.
(defparameter +spdp-multicast-group+ "239.255.0.1")

(declaim (ftype (function (&key (:guid-prefix (simple-array (unsigned-byte 8) (12))) (:domain (integer 0)) (:host string) (:port (unsigned-byte 16)) (:peers list) (:multicast t) (:advertise-address string)) disc-node) make-disc-node))
(defun make-disc-node (&key (guid-prefix (make-array 12 :element-type '(unsigned-byte 8)
                                                     :initial-element 0))
                            (domain 0) (host "127.0.0.1") (port 0) (peers '()) multicast
                            (advertise-address "127.0.0.1"))
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

(declaim (ftype (function (disc-node) (integer 0 65535)) disc-node-port))
(defun disc-node-port (node)
  "The bound metatraffic UDP port of NODE."
  (dds.xport.udp:udp-transport-local-port (disc-node-socket node)))

(declaim (ftype (function ((unsigned-byte 32)) (unsigned-byte 16)) %locator-port))
(defun %locator-port (p)
  "Narrow a wire Locator port (u32) to the UDP port range (u16)."
  (ldb (byte 16 0) p))

(declaim (ftype (function ((simple-array (unsigned-byte 8) (12)) (unsigned-byte 8) (unsigned-byte 8)) (simple-array (unsigned-byte 8) (16))) %make-endpoint-guid))
(defun %make-endpoint-guid (prefix key kind)
  "GUID_t = 12-octet participant PREFIX + 4-octet entity id (00 00 KEY KIND),
   RTPS 2.5 §9.3.1.2."
  (let ((g (make-array 16 :element-type '(unsigned-byte 8) :initial-element 0)))
    (replace g prefix :start1 0 :end1 12)
    (setf (aref g 14) key (aref g 15) kind)
    g))

(declaim (ftype (function (string) (simple-array (unsigned-byte 8) (4))) %ipv4-octets))
(defun %ipv4-octets (host)
  "Parse a dotted-quad 'a.b.c.d' string into a 4-octet vector."
  (let ((v (make-array 4 :element-type '(unsigned-byte 8))) (start 0))
    (dotimes (i 4 v)
      (let ((dot (position #\. host :start start)))
        (setf (aref v i) (parse-integer host :start start :end dot)
              start (if dot (1+ dot) (length host)))))))

(declaim (ftype (function (disc-node) dds.rtps.discovery:spdp-data) %node-spdp-data))
(defun %node-spdp-data (node)
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
     :builtin-endpoint-set #x0000043F)))

(declaim (ftype (function (disc-node (unsigned-byte 32) (unsigned-byte 32) integer function string (unsigned-byte 16)) t) %send-paramlist))
(defun %send-paramlist (node reader-id writer-id sn serialize-fn host port)
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

(declaim (ftype (function (disc-node) (eql t)) announce-participant))
(defun announce-participant (node)
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

(declaim (ftype (function (disc-node &key (:topic string) (:type string) (:reliability integer) (:key (unsigned-byte 8))) dds.rtps.discovery:endpoint-data) add-local-writer))
(defun add-local-writer (node &key (topic "") (type "")
                                   (reliability dds.rtps.discovery:+reliability-reliable+)
                                   (key 1))
  "Register a local publication (writer endpoint) on NODE; announce-endpoints
   sends it via SEDP to discovered participants. Returns the endpoint-data."
  (let ((ep (dds.rtps.discovery:make-endpoint-data
             :guid (%make-endpoint-guid (disc-node-guid-prefix node) key #x03)
             :topic-name topic :type-name type :reliability-kind reliability)))
    (push ep (disc-node-local-writers node))
    ep))

(declaim (ftype (function (disc-node &key (:topic string) (:type string) (:reliability integer) (:key (unsigned-byte 8))) dds.rtps.discovery:endpoint-data) add-local-reader))
(defun add-local-reader (node &key (topic "") (type "")
                                   (reliability dds.rtps.discovery:+reliability-best-effort+)
                                   (key 1))
  "Register a local subscription (reader endpoint) on NODE; announce-endpoints
   sends it via SEDP to discovered participants. Returns the endpoint-data."
  (let ((ep (dds.rtps.discovery:make-endpoint-data
             :guid (%make-endpoint-guid (disc-node-guid-prefix node) key #x07)
             :topic-name topic :type-name type :reliability-kind reliability)))
    (push ep (disc-node-local-readers node))
    ep))

(declaim (ftype (function (disc-node) list) %discovered-participants))
(defun %discovered-participants (node)
  "Snapshot the discovered participants' SPDP data (lock-guarded)."
  (dds.pal:with-lock ((disc-node-lock node))
    (loop for v being the hash-values of (disc-node-discovered node) collect v)))

(declaim (ftype (function (disc-node (unsigned-byte 32) (unsigned-byte 32) dds.rtps.discovery:endpoint-data string (unsigned-byte 16)) t) %send-endpoint))
(defun %send-endpoint (node reader-id writer-id ep host port)
  "Announce one local endpoint EP via a SEDP DATA submessage to HOST:PORT."
  (incf (disc-node-sedp-sn node))
  (%send-paramlist node reader-id writer-id (disc-node-sedp-sn node)
                   (lambda (c) (dds.rtps.discovery:serialize-endpoint-data c ep))
                   host port))

(declaim (ftype (function (disc-node) (eql t)) announce-endpoints))
(defun announce-endpoints (node)
  "Send NODE's local publications (SEDP publications writer) and subscriptions
   (SEDP subscriptions writer) to every discovered participant's metatraffic
   unicast locator (RTPS 2.5 §8.5.4)."
  (dolist (p (%discovered-participants node))
    (let ((loc (dds.rtps.discovery:usable-udpv4-locator
                (dds.rtps.discovery:spdp-data-metatraffic-unicast-locators p))))
      (when loc
        (let ((host (dds.rtps.discovery:locator-ipv4-string loc))
              (port (%locator-port (dds.rtps.discovery:locator-port loc))))
          (dolist (w (disc-node-local-writers node))
            (%send-endpoint node
                            dds.rtps.discovery:+entityid-sedp-pub-reader+
                            dds.rtps.discovery:+entityid-sedp-pub-writer+
                            w host port))
          (dolist (r (disc-node-local-readers node))
            (%send-endpoint node
                            dds.rtps.discovery:+entityid-sedp-sub-reader+
                            dds.rtps.discovery:+entityid-sedp-sub-writer+
                            r host port))))))
  t)

(declaim (ftype (function (disc-node dds.rtps.discovery:spdp-data) t) %record-participant))
(defun %record-participant (node spdp)
  "Record a discovered participant (its SPDP data) keyed by GUID prefix, ignoring
   this node's own announcements (loopback echo / self in peers)."
  (let ((prefix (dds.rtps.discovery:spdp-data-guid-prefix spdp)))
    (unless (equalp prefix (disc-node-guid-prefix node))
      (dds.pal:with-lock ((disc-node-lock node))
        (setf (gethash (copy-seq prefix) (disc-node-discovered node)) spdp)))))

(declaim (ftype (function (disc-node dds.rtps.discovery:endpoint-data) t) %record-match))
(defun %record-match (node remote)
  "Record a matched REMOTE endpoint keyed by its 16-octet GUID (lock-guarded)."
  (dds.pal:with-lock ((disc-node-lock node))
    (setf (gethash (copy-seq (dds.rtps.discovery:endpoint-data-guid remote))
                   (disc-node-matches node))
          remote)))

(declaim (ftype (function (disc-node dds.rtps.discovery:endpoint-data) t) %match-remote-writer))
(defun %match-remote-writer (node remote)
  "REMOTE is a discovered publication; record a match if any local reader's RxO is
   compatible (offered >= requested)."
  (dolist (lr (disc-node-local-readers node))
    (when (dds.rtps.discovery:endpoint-match-p remote lr)
      (%record-match node remote)
      (return))))

(declaim (ftype (function (disc-node dds.rtps.discovery:endpoint-data) t) %match-remote-reader))
(defun %match-remote-reader (node remote)
  "REMOTE is a discovered subscription; record a match if any local writer's RxO is
   compatible (offered >= requested)."
  (dolist (lw (disc-node-local-writers node))
    (when (dds.rtps.discovery:endpoint-match-p lw remote)
      (%record-match node remote)
      (return))))

(declaim (ftype (function (disc-node dds.core.buffer:octet-buffer (integer 0)) t) %handle-datagram))
(defun %handle-datagram (node buf size)
  "Dispatch an inbound datagram (bounded by SIZE). DATA is routed by writerId: SPDP
   -> record participant; SEDP publications/subscriptions -> match; any other DATA
   plus HEARTBEAT/ACKNACK -> the installed data-plane hooks (nil = ignore). The
   discovery SerializedPayloads are ParameterLists (encap header + list); a user
   DATA payload is opaque bytes handed to the on-data hook as a [poff,plen) region."
  (let ((cursor (dds.core.buffer:cursor buf :endianness :little)))
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
                   (let ((ep (dds.rtps.discovery:parse-endpoint-data pc)))
                     (when ep (%match-remote-writer node ep)))))
                ((= wtr dds.rtps.discovery:+entityid-sedp-sub-writer+)
                 (let ((pc (dds.core.buffer:cursor buf :endianness :little)))
                   (dds.core.buffer:cursor-set-position pc poff)
                   (dds.cdr:parse-encapsulation-header pc)
                   (let ((ep (dds.rtps.discovery:parse-endpoint-data pc)))
                     (when ep (%match-remote-reader node ep)))))
                ((disc-node-on-data node)
                 (funcall (disc-node-on-data node) wtr sn buf poff plen))))))
         ((and (= id dds.rtps.message:+submsg-heartbeat+) (disc-node-on-heartbeat node))
          (funcall (disc-node-on-heartbeat node) c flags))
         ((and (= id dds.rtps.message:+submsg-acknack+) (disc-node-on-acknack node))
          (funcall (disc-node-on-acknack node) c flags))))
     size)
    t))

(declaim (ftype (function (disc-node) disc-node) start-node))
(defun start-node (node)
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

(declaim (ftype (function (disc-node) (eql t)) stop-node))
(defun stop-node (node)
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

(declaim (ftype (function (disc-node) (integer 0)) disc-node-discovered-count))
(defun disc-node-discovered-count (node)
  "Number of remote participants NODE has discovered."
  (dds.pal:with-lock ((disc-node-lock node))
    (hash-table-count (disc-node-discovered node))))

(declaim (ftype (function (disc-node) list) disc-node-discovered-prefixes))
(defun disc-node-discovered-prefixes (node)
  "List of the 12-octet GUID prefixes NODE has discovered."
  (dds.pal:with-lock ((disc-node-lock node))
    (loop for k being the hash-keys of (disc-node-discovered node) collect k)))

(declaim (ftype (function (disc-node) (integer 0)) disc-node-matched-count))
(defun disc-node-matched-count (node)
  "Number of remote endpoints that matched one of NODE's local endpoints."
  (dds.pal:with-lock ((disc-node-lock node))
    (hash-table-count (disc-node-matches node))))

(declaim (ftype (function (disc-node) list) disc-node-matched-topics))
(defun disc-node-matched-topics (node)
  "Topic names of the remote endpoints NODE has matched."
  (dds.pal:with-lock ((disc-node-lock node))
    (loop for v being the hash-values of (disc-node-matches node)
          collect (dds.rtps.discovery:endpoint-data-topic-name v))))

(declaim (ftype (function () (eql t)) run-spdp-discovery-test))
(defun run-spdp-discovery-test ()
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

(declaim (ftype (function () (eql t)) run-sedp-discovery-test))
(defun run-sedp-discovery-test ()
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

(declaim (ftype (function () (eql t)) run-mcast-discovery-test))
(defun run-mcast-discovery-test ()
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
