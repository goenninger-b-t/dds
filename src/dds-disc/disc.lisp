;;;; L5 — SPDP participant discovery over UDP (FR-DISC-1/4). A disc-node owns a
;;;; metatraffic UDPv4 socket and a background receiver thread; it announces its
;;;; SPDPdiscoveredParticipantData (a PL_CDR_LE SerializedPayload inside a DATA
;;;; submessage, writerId = the SPDP builtin participant writer) to its unicast
;;;; peers, and records the participants it discovers from inbound SPDP. The SPDP
;;;; wire codec + builtin EntityIds are pinned from docs/specs in DDS.RTPS.*;
;;;; nothing here is memorized. Multicast + SEDP are later increments.

(in-package #:dds.disc)

(defstruct (disc-node (:constructor %make-disc-node))
  "A minimal RTPS participant for discovery: a metatraffic UDP socket/transport,
   the unicast PEERS to announce to, and the table of DISCOVERED participants
   keyed by a 12-octet GUID prefix. LOCK guards DISCOVERED across the receiver
   thread and callers."
  (guid-prefix (make-array 12 :element-type '(unsigned-byte 8) :initial-element 0)
               :type (simple-array (unsigned-byte 8) (12)))
  (domain 0 :type (integer 0))
  (socket nil)
  (transport nil)
  (spdp-sn 0 :type integer)
  (peers '() :type list)
  (discovered (make-hash-table :test 'equalp) :type hash-table)
  (lock (dds.pal:make-lock "disc-node"))
  (rx-thread nil))

(declaim (ftype (function (&key (:guid-prefix (simple-array (unsigned-byte 8) (12))) (:domain (integer 0)) (:host string) (:port (unsigned-byte 16)) (:peers list)) disc-node) make-disc-node))
(defun make-disc-node (&key (guid-prefix (make-array 12 :element-type '(unsigned-byte 8)
                                                     :initial-element 0))
                            (domain 0) (host "127.0.0.1") (port 0) (peers '()))
  "Open a metatraffic UDPv4 socket bound to HOST:PORT and build a discovery node.
   PEERS is a list of (host-string . port) the node announces SPDP to (FR-DISC-4)."
  (multiple-value-bind (tr sock) (dds.xport.udp:make-udp-transport :host host :port port)
    (%make-disc-node :guid-prefix guid-prefix :domain domain
                     :socket sock :transport tr :peers peers)))

(declaim (ftype (function (disc-node) (integer 0 65535)) disc-node-port))
(defun disc-node-port (node)
  "The bound metatraffic UDP port of NODE."
  (dds.xport.udp:udp-transport-local-port (disc-node-socket node)))

(declaim (ftype (function (disc-node) dds.rtps.discovery:spdp-data) %node-spdp-data))
(defun %node-spdp-data (node)
  "Build NODE's SPDPdiscoveredParticipantData: its GUID prefix + one metatraffic
   unicast locator at 127.0.0.1:<bound port>, protocol version 2.5."
  (let ((addr (dds.rtps.discovery:make-ipv4-locator
               (make-array 4 :element-type '(unsigned-byte 8)
                           :initial-contents '(127 0 0 1))))
        (port (disc-node-port node)))
    (dds.rtps.discovery:make-spdp-data
     :guid-prefix (disc-node-guid-prefix node)
     :version-major 2 :version-minor 5
     :vendor-id dds.rtps.message:*vendor-id*
     :default-unicast-kind dds.rtps.discovery:+locator-kind-udpv4+
     :default-unicast-port port
     :default-unicast-address addr
     :metatraffic-unicast-kind dds.rtps.discovery:+locator-kind-udpv4+
     :metatraffic-unicast-port port
     :metatraffic-unicast-address addr
     :lease-duration-seconds 100
     :builtin-endpoint-set #x0000043F)))

(declaim (ftype (function (disc-node) (eql t)) announce-participant))
(defun announce-participant (node)
  "Serialize NODE's SPDP data as a PL_CDR_LE SerializedPayload, wrap it in a DATA
   submessage (writer = SPDP builtin participant writer) inside an RTPS message,
   and send it to every peer (FR-DISC-1, unicast initial peers per FR-DISC-4)."
  (let* ((pl (dds.core.buffer:make-octet-buffer 512))
         (pc (dds.core.buffer:cursor pl :endianness :little)))
    (dds.cdr:make-encapsulation-header pc :pl-cdr-le)
    (dds.rtps.discovery:serialize-spdp-data pc (%node-spdp-data node))
    (let* ((pl-len (dds.core.buffer:cursor-position pc))
           (pl-vec (dds.core.buffer:octet-buffer-vec pl))
           (msg (dds.core.buffer:make-octet-buffer 1024))
           (mc (dds.core.buffer:cursor msg :endianness :little)))
      (dds.rtps.message:write-header mc (disc-node-guid-prefix node))
      (incf (disc-node-spdp-sn node))
      (dds.rtps.message:write-data mc
                                   dds.rtps.discovery:+entityid-spdp-reader+
                                   dds.rtps.discovery:+entityid-spdp-writer+
                                   (disc-node-spdp-sn node)
                                   pl-vec 0 pl-len)
      (let ((msg-len (dds.core.buffer:cursor-position mc)))
        (dolist (peer (disc-node-peers node))
          (dds.xport:send (disc-node-transport node)
                          (dds.xport.udp:make-udp-locator :host (car peer) :port (cdr peer))
                          msg 0 msg-len)))
      t)))

(declaim (ftype (function (disc-node dds.rtps.discovery:spdp-data) t) %record-participant))
(defun %record-participant (node spdp)
  "Record a discovered participant (its SPDP data) keyed by GUID prefix, ignoring
   this node's own announcements (loopback echo / self in peers)."
  (let ((prefix (dds.rtps.discovery:spdp-data-guid-prefix spdp)))
    (unless (equalp prefix (disc-node-guid-prefix node))
      (dds.pal:with-lock ((disc-node-lock node))
        (setf (gethash (copy-seq prefix) (disc-node-discovered node)) spdp)))))

(declaim (ftype (function (disc-node dds.core.buffer:octet-buffer (integer 0)) t) %handle-datagram))
(defun %handle-datagram (node buf size)
  "Dispatch an inbound datagram (bounded by SIZE); for an SPDP DATA submessage,
   parse the SerializedPayload (encapsulation header + SPDP ParameterList) and
   record the discovered participant. Everything else is ignored for now."
  (let ((cursor (dds.core.buffer:cursor buf :endianness :little)))
    (dds.rtps.message:dispatch-message
     cursor
     (lambda (id flags c body-len)
       (when (= id dds.rtps.message:+submsg-data+)
         (multiple-value-bind (rdr wtr sn has-payload poff plen keyp)
             (dds.rtps.message:parse-data-body c flags body-len)
           (declare (ignore rdr sn plen keyp))
           (when (and has-payload
                      (= wtr dds.rtps.discovery:+entityid-spdp-writer+))
             (let ((pc (dds.core.buffer:cursor buf :endianness :little)))
               (dds.core.buffer:cursor-set-position pc poff)
               (dds.cdr:parse-encapsulation-header pc)
               (let ((spdp (dds.rtps.discovery:parse-spdp-data pc)))
                 (when spdp (%record-participant node spdp))))))))
     size)
    t))

(declaim (ftype (function (disc-node) disc-node) start-node))
(defun start-node (node)
  "Spawn the background receiver thread that processes inbound datagrams for NODE
   (SPDP records discovered participants). Returns NODE."
  (setf (disc-node-rx-thread node)
        (dds.xport.udp:start-udp-receiver
         (disc-node-socket node)
         (lambda (buf size) (%handle-datagram node buf size))))
  node)

(declaim (ftype (function (disc-node) (eql t)) stop-node))
(defun stop-node (node)
  "Close NODE's socket, which unblocks udp-recv and terminates the receiver
   thread."
  (dds.pal:udp-close (disc-node-socket node))
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

(declaim (ftype (function () (eql t)) run-spdp-discovery-test))
(defun run-spdp-discovery-test ()
  "Two participants on 127.0.0.1, each carrying the other as a unicast peer. Both
   announce SPDP; assert each discovers the other's GUID prefix within a bounded
   wait. Exercises the full discovery-over-UDP path: announce -> datagram ->
   receiver thread -> dispatch -> parse SPDP -> record (FR-DISC-1/4)."
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
