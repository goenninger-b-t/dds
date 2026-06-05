;;;; Wire-oracle generator: build representative RTPS messages with the PROJECT
;;;; codecs and write them to a DLT_RAW pcap so the canonical Wireshark/tshark RTPS
;;;; dissector can validate them — the same dissector used for Connext interop. This
;;;; is a necessary (not sufficient) condition for M2: if the reference dissector
;;;; rejects or mis-parses our bytes, no Connext peer would accept them either.
;;;; Not part of asdf:test-system (needs the external tshark). Run via scripts/wire-check.sh.

(require :asdf)
(push (truename ".") asdf:*central-registry*)
(asdf:load-system :dds-disc)

(in-package :cl-user)

(defparameter *packets* '())   ; list of (dst-port . rtps-byte-vector)

(defun emit (dst-port vec len)
  (push (cons dst-port (subseq vec 0 len)) *packets*))

(defun prefix12 (fill)
  (make-array 12 :element-type '(unsigned-byte 8) :initial-element fill))

(defun build-spdp ()
  "Header + DATA(SPDP) carrying a PL_CDR_LE SPDPdiscoveredParticipantData."
  (let* ((pl (dds.core.buffer:make-octet-buffer 512))
         (pc (dds.core.buffer:cursor pl :endianness :little))
         (addr (dds.rtps.discovery:make-ipv4-locator
                (make-array 4 :element-type '(unsigned-byte 8) :initial-contents '(127 0 0 1))))
         (data (dds.rtps.discovery:make-spdp-data
                :guid-prefix (prefix12 #x11) :version-major 2 :version-minor 5 :vendor-id #x010f
                :default-unicast-locators (list (dds.rtps.discovery:make-locator :kind 1 :port 7411 :address addr))
                :metatraffic-unicast-locators (list (dds.rtps.discovery:make-locator :kind 1 :port 7410 :address addr))
                :lease-duration-seconds 100 :builtin-endpoint-set #x0000043f)))
    (dds.cdr:make-encapsulation-header pc :pl-cdr-le)
    (dds.rtps.discovery:serialize-spdp-data pc data)
    (let* ((pl-len (dds.core.buffer:cursor-position pc))
           (msg (dds.core.buffer:make-octet-buffer 1024))
           (mc (dds.core.buffer:cursor msg :endianness :little)))
      (dds.rtps.message:write-header mc (prefix12 #x11))
      (dds.rtps.message:write-data mc dds.rtps.discovery:+entityid-spdp-reader+
                                   dds.rtps.discovery:+entityid-spdp-writer+ 1
                                   (dds.core.buffer:octet-buffer-vec pl) 0 pl-len)
      (emit 7400 (dds.core.buffer:octet-buffer-vec msg) (dds.core.buffer:cursor-position mc)))))

(defun build-sedp ()
  "Header + DATA(SEDP publications) carrying a PL_CDR_LE DiscoveredWriterData."
  (let* ((pl (dds.core.buffer:make-octet-buffer 512))
         (pc (dds.core.buffer:cursor pl :endianness :little))
         (guid (make-array 16 :element-type '(unsigned-byte 8)
                           :initial-contents '(#x11 #x11 #x11 #x11 #x11 #x11 #x11 #x11 #x11 #x11 #x11 #x11 0 0 1 3)))
         (ep (dds.rtps.discovery:make-endpoint-data
              :guid guid :topic-name "Square" :type-name "ShapeType"
              :reliability-kind dds.rtps.discovery:+reliability-reliable+)))
    (dds.cdr:make-encapsulation-header pc :pl-cdr-le)
    (dds.rtps.discovery:serialize-endpoint-data pc ep)
    (let* ((pl-len (dds.core.buffer:cursor-position pc))
           (msg (dds.core.buffer:make-octet-buffer 1024))
           (mc (dds.core.buffer:cursor msg :endianness :little)))
      (dds.rtps.message:write-header mc (prefix12 #x11))
      (dds.rtps.message:write-data mc dds.rtps.discovery:+entityid-sedp-pub-reader+
                                   dds.rtps.discovery:+entityid-sedp-pub-writer+ 1
                                   (dds.core.buffer:octet-buffer-vec pl) 0 pl-len)
      (emit 7411 (dds.core.buffer:octet-buffer-vec msg) (dds.core.buffer:cursor-position mc)))))

(defun build-data+heartbeat ()
  "Header + user DATA (PLAIN_CDR2_LE serializedPayload) + HEARTBEAT, one message."
  (let* ((pl (dds.core.buffer:make-octet-buffer 64))
         (pc (dds.core.buffer:cursor pl :endianness :little)))
    (dds.cdr:make-encapsulation-header pc :plain-cdr2-le)
    (dds.cdr:cdr-put-i32 pc 100 :xcdr2)
    (dds.cdr:cdr-put-i32 pc 150 :xcdr2)
    (let* ((pl-len (dds.core.buffer:cursor-position pc))
           (msg (dds.core.buffer:make-octet-buffer 512))
           (mc (dds.core.buffer:cursor msg :endianness :little)))
      (dds.rtps.message:write-header mc (prefix12 #x22))
      (dds.rtps.message:write-data mc #x00000204 #x00000103 7
                                   (dds.core.buffer:octet-buffer-vec pl) 0 pl-len)
      (dds.rtps.message:write-heartbeat mc #x00000204 #x00000103 1 7 1 :final nil)
      (emit 7413 (dds.core.buffer:octet-buffer-vec msg) (dds.core.buffer:cursor-position mc)))))

(defun build-acknack ()
  "Header + ACKNACK with a SequenceNumberSet NACKing SN 3 and 5 in [1,8]."
  (let* ((msg (dds.core.buffer:make-octet-buffer 256))
         (mc (dds.core.buffer:cursor msg :endianness :little))
         (bitmap (make-array 1 :element-type '(unsigned-byte 32) :initial-element 0)))
    (dds.rtps.message:seqnum-set-bit bitmap 2)        ; SN base+2 = 3
    (dds.rtps.message:seqnum-set-bit bitmap 4)        ; SN base+4 = 5
    (dds.rtps.message:write-header mc (prefix12 #x22))
    (dds.rtps.message:write-acknack mc #x00000204 #x00000103 1 6 bitmap 1 :final t)
    (emit 7413 (dds.core.buffer:octet-buffer-vec msg) (dds.core.buffer:cursor-position mc))))

;;; ---- DLT_RAW pcap framing (IPv4 + UDP, checksums 0; tshark dissects regardless) ----

(defun write-pcap (path packets)
  (let* ((total (reduce #'+ packets :key (lambda (p) (+ 24 16 0)) :initial-value 24)) ; rough; recompute below
         (out (make-array (max 4096 (* 4 total)) :element-type '(unsigned-byte 8) :initial-element 0))
         (i 0))
    (declare (ignore total))
    (labels ((p8 (b) (setf (aref out i) (logand b #xff)) (incf i))
             (le16 (v) (p8 (ldb (byte 8 0) v)) (p8 (ldb (byte 8 8) v)))
             (le32 (v) (p8 (ldb (byte 8 0) v)) (p8 (ldb (byte 8 8) v)) (p8 (ldb (byte 8 16) v)) (p8 (ldb (byte 8 24) v)))
             (be16 (v) (p8 (ldb (byte 8 8) v)) (p8 (ldb (byte 8 0) v))))
      ;; global header: magic, ver 2.4, zone 0, sig 0, snaplen 65535, linktype 1
      ;; (LINKTYPE_ETHERNET — universally decoded; DLT_RAW proved flaky in tshark).
      (le32 #xa1b2c3d4) (le16 2) (le16 4) (le32 0) (le32 0) (le32 65535) (le32 1)
      (dolist (pkt (reverse packets))
        (let* ((port (car pkt)) (rtps (cdr pkt))
               (rlen (length rtps)) (ulen (+ 8 rlen)) (iplen (+ 20 ulen))
               (caplen (+ 14 iplen)))   ; + Ethernet header
          ;; record header
          (le32 0) (le32 0) (le32 caplen) (le32 caplen)
          ;; Ethernet II: dst MAC, src MAC (locally-administered), ethertype IPv4
          (p8 #x02)(p8 0)(p8 0)(p8 0)(p8 0)(p8 1)
          (p8 #x02)(p8 0)(p8 0)(p8 0)(p8 0)(p8 2)
          (p8 #x08)(p8 0)
          ;; IPv4
          (p8 #x45) (p8 0) (be16 iplen) (be16 0) (be16 0) (p8 64) (p8 17) (be16 0)
          (p8 127)(p8 0)(p8 0)(p8 1) (p8 127)(p8 0)(p8 0)(p8 1)
          ;; UDP  src=dst=port
          (be16 port) (be16 port) (be16 ulen) (be16 0)
          (loop for b across rtps do (p8 b)))))
    (with-open-file (s path :direction :output :element-type '(unsigned-byte 8) :if-exists :supersede)
      (write-sequence (subseq out 0 i) s))
    (format t "WROTE ~a (~d packets, ~d bytes)~%" path (length packets) i)))

(build-spdp)
(build-sedp)
(build-data+heartbeat)
(build-acknack)
(write-pcap "/tmp/rtps_wire.pcap" *packets*)
