(in-package #:dds.tests)

;;; M2 increment 1: RTPS Message Header + SubmessageHeader + EntityId byte-exact
;;; against RTPS 2.5 (§9.4.4 / §9.4.5.1 / §9.3.1.2). The wire-layer analogue of
;;; the byte-exact CDR corpus; values pinned from docs/specs, not memory.

(defun* run-rtps-wire-test ()
    (function () t)
  "Test: RTPS message header + submessage byte-exactness against spec-pinned vectors."
  (let* ((arena (dds.core.arena:init-arena :bytes (* 64 1024)))
         (pool (dds.core.arena:make-buffer-pool arena 64 1))
         (prefix (make-array 12 :element-type '(unsigned-byte 8)
                                :initial-contents '(1 2 3 4 5 6 7 8 9 10 11 12)))
         (buf (dds.core.arena:pool-acquire pool))
         (c (dds.core.buffer:cursor buf :endianness :little)))
    ;; RTPS Header byte-exactness (§9.4.4): 'RTPS' 2 5 vendor=0 prefix[12]
    (dds.rtps.message:write-header c prefix :vendor 0)
    (%check :rtps-header-bytes
            (equal '(#x52 #x54 #x50 #x53 2 5 0 0 1 2 3 4 5 6 7 8 9 10 11 12)
                   (%first-bytes buf 20))
            "RTPS header bytes")
    (dds.core.buffer:cursor-reset c)
    (multiple-value-bind (major minor vendor pfx) (dds.rtps.message:parse-header c)
      (%check :rtps-header-parse
              (and (= major 2) (= minor 5) (= vendor 0) (equalp pfx prefix))
              "RTPS header parse"))
    ;; SubmessageHeader (§9.4.5.1): DATA(0x15), E=little, octetsToNextHeader=16
    (dds.core.buffer:cursor-reset c)
    (dds.rtps.message:write-submessage-header
     c dds.rtps.message:+submsg-data+ dds.rtps.message:+flag-endianness+ 16)
    (%check :submsg-bytes
            (equal '(#x15 #x01 #x10 #x00) (%first-bytes buf 4))
            "submessage header bytes")
    (dds.core.buffer:cursor-reset c)
    (multiple-value-bind (id flags octets le) (dds.rtps.message:parse-submessage-header c)
      (%check :submsg-parse (and (= id #x15) (= flags #x01) (= octets 16) le)
              "submessage header parse"))
    ;; EntityId (§9.3.1.2): ENTITYID_PARTICIPANT = 0x000001c1 -> 00 00 01 c1
    (dds.core.buffer:cursor-reset c)
    (dds.rtps.message:write-entity-id c dds.rtps.message:+entityid-participant+)
    (%check :entityid-bytes
            (equal '(#x00 #x00 #x01 #xc1) (%first-bytes buf 4))
            "ENTITYID_PARTICIPANT bytes")
    (dds.core.buffer:cursor-reset c)
    (%check :entityid-parse (= #x000001c1 (dds.rtps.message:read-entity-id c))
            "EntityId parse")
    ;; bounds-check: a 3-octet buffer must not parse a submessage header (no OOB)
    (let* ((b2 (dds.core.arena:make-buffer-pool arena 3 1))
           (sb (dds.core.arena:pool-acquire b2))
           (sc (dds.core.buffer:cursor sb :endianness :little)))
      (%check :submsg-bounds (null (dds.rtps.message:parse-submessage-header sc))
              "short buffer must yield NIL, not OOB"))
    (dds.core.arena:pool-release pool buf)
    (dds.core.arena:teardown-arena arena)
    t))

;;; DATA submessage byte-exact + parse (RTPS 2.5 §9.4.5.4, base form, Q=0).

(defun* run-rtps-data-test ()
    (function () t)
  "Test: RTPS DATA submessage write/parse round-trip, including inline-QoS handling."
  (let* ((arena (dds.core.arena:init-arena :bytes (* 64 1024)))
         (pool (dds.core.arena:make-buffer-pool arena 128 1))
         (buf (dds.core.arena:pool-acquire pool))
         (c (dds.core.buffer:cursor buf :endianness :little))
         (rid dds.rtps.message:+entityid-participant+)
         (wid dds.rtps.message:+entityid-unknown+)
         ;; an 8-octet fake serializedPayload: PLAIN_CDR2_LE header + i32=42
         (payload (make-array 8 :element-type '(unsigned-byte 8)
                                :initial-contents '(0 #x11 0 0 #x2a 0 0 0))))
    (dds.rtps.message:write-data c rid wid 5 payload 0 8)
    ;; full 32-octet byte image: header(4) + extra/oti(4) + reader(4) + writer(4)
    ;;                          + writerSN(8) + payload(8)
    (%check :data-bytes
            (equal '(#x15 #x05 #x1c 0   0 0 #x10 0   0 0 1 #xc1   0 0 0 0
                     0 0 0 0 5 0 0 0   0 #x11 0 0 #x2a 0 0 0)
                   (%first-bytes buf 32))
            "DATA submessage bytes")
    (dds.core.buffer:cursor-reset c)
    (multiple-value-bind (id flags octets le) (dds.rtps.message:parse-submessage-header c)
      (declare (ignore le))
      (%check :data-hdr (and (= id #x15) (= flags #x05) (= octets 28)) "DATA header")
      (multiple-value-bind (r w sn has off len key)
          (dds.rtps.message:parse-data-body c flags octets)
        (%check :data-body
                (and (= r rid) (= w wid) (= sn 5) has (= off 24) (= len 8) (not key))
                "DATA body parse")
        ;; the payload region must equal what we wrote
        (%check :data-payload
                (equal '(0 #x11 0 0 #x2a 0 0 0)
                       (loop for i from off below (+ off len)
                             collect (aref (dds.core.buffer:octet-buffer-vec buf) i)))
                "DATA payload region")))
    (dds.core.arena:pool-release pool buf)
    (dds.core.arena:teardown-arena arena)
    t))

;;; DATA_FRAG codec + reassembly (RTPS 2.5 §9.4.5.5): write/parse each fragment, then
;;; reassemble byte-exact; plus spec-validity (fragmentStartingNum=0) rejection.

(defun* run-rtps-data-frag-test ()
    (function () t)
  "Test: RTPS DATA_FRAG submessage write/parse round-trip (RTPS 2.5 §9.4.5.5)."
  (let* ((arena (dds.core.arena:init-arena :bytes (* 64 1024)))
         (pool (dds.core.arena:make-buffer-pool arena 256 1))
         (rid dds.rtps.message:+entityid-unknown+)
         (wid #x00000102)
         (sample-size 100)
         (frag-size 30)
         (payload (make-array sample-size :element-type '(unsigned-byte 8))))
    (dotimes (i sample-size) (setf (aref payload i) (logand (* i 7) #xff)))
    (let ((reassembled (make-array sample-size :element-type '(unsigned-byte 8) :initial-element 0))
          (nfrags (ceiling sample-size frag-size))
          (ok t))
      (loop for fnum from 1 to nfrags
            for off = (* (1- fnum) frag-size)
            for len = (min frag-size (- sample-size off))
            do (let* ((buf (dds.core.arena:pool-acquire pool))
                      (c (dds.core.buffer:cursor buf :endianness :little)))
                 (dds.rtps.message:write-data-frag c rid wid 9 sample-size fnum 1 frag-size payload off len)
                 (dds.core.buffer:cursor-reset c)
                 (multiple-value-bind (id flags octets le) (dds.rtps.message:parse-submessage-header c)
                   (declare (ignore le))
                   (unless (= id dds.rtps.message:+submsg-data-frag+) (setf ok nil))
                   (multiple-value-bind (r w sn ssize fstart frags fsize poff plen keyp)
                       (dds.rtps.message:parse-data-frag-body c flags octets)
                     (declare (ignore r w keyp))
                     (unless (and (= sn 9) (= ssize sample-size) (= fstart fnum) (= frags 1)
                                  (= fsize frag-size) (= plen len))
                       (setf ok nil))
                     (replace reassembled (dds.core.buffer:octet-buffer-vec buf)
                              :start1 (* (1- fstart) fsize) :start2 poff :end2 (+ poff plen))))
                 (dds.core.arena:pool-release pool buf)))
      (%check :data-frag-reassembly (and ok (equalp reassembled payload))
              "DATA_FRAG fragment/reassemble byte-exact")
      (let* ((buf (dds.core.arena:pool-acquire pool))
             (c (dds.core.buffer:cursor buf :endianness :little)))
        (dds.rtps.message:write-data-frag c rid wid 9 sample-size 1 1 frag-size payload 0 frag-size)
        ;; fragmentStartingNum is at buffer offset 24 (hdr4 + extra/oti4 + rid4 + wid4 + sn8)
        (fill (dds.core.buffer:octet-buffer-vec buf) 0 :start 24 :end 28)
        (dds.core.buffer:cursor-reset c)
        (multiple-value-bind (id flags octets le) (dds.rtps.message:parse-submessage-header c)
          (declare (ignore id le))
          (%check :data-frag-validity
                  (null (dds.rtps.message:parse-data-frag-body c flags octets))
                  "DATA_FRAG with fragmentStartingNum=0 must reject"))
        (dds.core.arena:pool-release pool buf)))
    (dds.core.arena:teardown-arena arena)
    t))

;;; Real RTI Connext 7.3.1 DATA_FRAG wire vector (RTPS 2.5 §9.4.5.5): the final
;;; (7th) fragment of LargeData sample writerSN=2, locked byte-exact in BOTH
;;; directions. The NACK_FRAG vector is locked below (step3-nackfrag.pcap frame 149).
;;; HEARTBEAT_FRAG is N/A: Connext 7.3.1 never emitted one in any run — it
;;; heartbeats fragmented samples with plain HEARTBEAT.

(defun* %connext-data-frag-vector ()
    (function () (simple-array (unsigned-byte 8) (*)))
  "The live RTI Connext 7.3.1 DATA_FRAG submessage (320 octets) from frame 101 of
   interop/connext/large-data/largedata.pcap (captured 2026-06-10): flags=0x01 (E),
   octetsToNextHeader=316, writerId 0x80000002, writerSN=2, fragmentStartingNum=7,
   fragmentsInSubmessage=1, fragmentSize=1288, sampleSize=8012, 284-octet payload."
  (%hex-octets
   (concatenate 'string
    "16013c0100001c00000000008000000200000000020000000700000001000805"
    "4c1f0000fc030a11181f262d343b424950575e656c737a81888f969da4abb2b9"
    "c0c7ced5dce3eaf1f8ff060d141b222930373e454c535a61686f767d848b9299"
    "a0a7aeb5bcc3cad1d8dfe6edf4fb020910171e252c333a41484f565d646b7279"
    "80878e959ca3aab1b8bfc6cdd4dbe2e9f0f7fe050c131a21282f363d444b5259"
    "60676e757c838a91989fa6adb4bbc2c9d0d7dee5ecf3fa01080f161d242b3239"
    "40474e555c636a71787f868d949ba2a9b0b7bec5ccd3dae1e8eff6fd040b1219"
    "20272e353c434a51585f666d747b828990979ea5acb3bac1c8cfd6dde4ebf2f9"
    "00070e151c232a31383f464d545b626970777e858c939aa1a8afb6bdc4cbd2d9"
    "e0e7eef5fc030a11181f262d343b424950575e656c737a81888f969da4abb2b9")))

(defun* run-connext-data-frag-vector-test ()
    (function () t)
  "Test: byte-exact DATA_FRAG regression vector from a real Connext 7.3.1 capture
   (largedata.pcap frame 101, tshark-dissected): decode recovers every dissected
   field + the fragment payload, encode reproduces the submessage byte-for-byte."
  (let* ((vec (%connext-data-frag-vector))
         (arena (dds.core.arena:init-arena :bytes (* 64 1024)))
         (pool (dds.core.arena:make-buffer-pool arena 512 2)))
    ;; decode: the captured octets must parse to the tshark-dissected field values
    (let* ((buf (dds.core.arena:pool-acquire pool))
           (c (dds.core.buffer:cursor buf :endianness :little)))
      (replace (dds.core.buffer:octet-buffer-vec buf) vec)
      (multiple-value-bind (id flags octets le) (dds.rtps.message:parse-submessage-header c)
        (%check :connext-frag-hdr
                (and (= id dds.rtps.message:+submsg-data-frag+) (= flags #x01)
                     (= octets 316) le)
                "captured DATA_FRAG header: id=0x16, flags=0x01 (E), octetsToNextHeader=316")
        (multiple-value-bind (r w sn ssize fstart frags fsize poff plen keyp)
            (dds.rtps.message:parse-data-frag-body c flags octets)
          (%check :connext-frag-body
                  (and (= r dds.rtps.message:+entityid-unknown+) (= w #x80000002)
                       (= sn 2) (= ssize 8012) (= fstart 7) (= frags 1)
                       (= fsize 1288) (= poff 36) (= plen 284) (not keyp))
                  "captured DATA_FRAG body: dissected field values")
          (%check :connext-frag-payload
                  (and (= poff 36) (= (+ poff plen) (length vec)))
                  "captured DATA_FRAG payload offset/extent (content locked by the encode check)")))
      (dds.core.arena:pool-release pool buf))
    ;; encode: write-data-frag with the same inputs must reproduce the capture
    (let* ((buf (dds.core.arena:pool-acquire pool))
           (c (dds.core.buffer:cursor buf :endianness :little))
           (payload (subseq vec 36)))
      (dds.rtps.message:write-data-frag c dds.rtps.message:+entityid-unknown+
                                        #x80000002 2 8012 7 1 1288 payload 0 284)
      (%check :connext-frag-encode
              (and (= (dds.core.buffer:cursor-position c) (length vec))
                   (loop for i below (length vec)
                         always (= (aref (dds.core.buffer:octet-buffer-vec buf) i)
                                   (aref vec i))))
              "write-data-frag reproduces the captured submessage byte-for-byte")
      (dds.core.arena:pool-release pool buf))
    (dds.core.arena:teardown-arena arena)
    t))

;;; Real RTI Connext 7.3.1 NACK_FRAG wire vector (RTPS 2.5 §9.4.5.14): emitted by
;;; Connext's reliable reader after our writer withheld fragment 3 of writerSN=1.

(defun* %connext-nack-frag-vector ()
    (function () (simple-array (unsigned-byte 8) (*)))
  "The live RTI Connext 7.3.1 NACK_FRAG submessage (36 octets) from frame 149 of
   interop/connext/large-data/step3-nackfrag.pcap (captured 2026-06-10): flags=0x01 (E),
   octetsToNextHeader=32, readerId 0x80000007, writerId 0x00000102, writerSN=1,
   fragmentNumberState bitmapBase=3 numBits=1 (exactly fragment 3 missing), count=1."
  (%hex-octets
   (concatenate 'string
    "12012000800000070000010200000000010000000300000001000000"
    "ffffff8301000000")))

(defun* run-connext-nack-frag-vector-test ()
    (function () t)
  "Test: byte-exact NACK_FRAG regression vector from a real Connext 7.3.1 capture
   (step3-nackfrag.pcap frame 149, tshark-dissected): decode recovers every dissected
   field, encode from the parsed fields reproduces the submessage byte-for-byte."
  (let* ((vec (%connext-nack-frag-vector))
         (arena (dds.core.arena:init-arena :bytes (* 64 1024)))
         (pool (dds.core.arena:make-buffer-pool arena 64 2)))
    ;; decode: the captured octets must parse to the tshark-dissected field values
    (let* ((buf (dds.core.arena:pool-acquire pool))
           (c (dds.core.buffer:cursor buf :endianness :little)))
      (replace (dds.core.buffer:octet-buffer-vec buf) vec)
      (multiple-value-bind (id flags octets le) (dds.rtps.message:parse-submessage-header c)
        (%check :connext-nf-hdr
                (and (= id dds.rtps.message:+submsg-nack-frag+) (= flags #x01)
                     (= octets 32) le)
                "captured NACK_FRAG header: id=0x12, flags=0x01 (E), octetsToNextHeader=32")
        (multiple-value-bind (r w sn base numbits bitmap count)
            (dds.rtps.message:parse-nack-frag-body c flags)
          (%check :connext-nf-body
                  (and (= r #x80000007) (= w #x00000102) (= sn 1)
                       (= base 3) (= numbits 1) (= count 1))
                  "captured NACK_FRAG body: dissected field values")
          (%check :connext-nf-set
                  (and (dds.rtps.message:fragnum-set-member-p base numbits bitmap 3)
                       (not (dds.rtps.message:fragnum-set-member-p base numbits bitmap 2))
                       (not (dds.rtps.message:fragnum-set-member-p base numbits bitmap 4)))
                  "captured NACK_FRAG set: 3 member; 2 below base, 4 beyond numBits (range-excluded)")
          ;; encode: write-nack-frag from the parsed fields must reproduce the capture
          ;; (the parsed bitmap word 0x83ffffff keeps Connext's insignificant pad bits past numBits, §9.4.2.8)
          (let* ((buf2 (dds.core.arena:pool-acquire pool))
                 (c2 (dds.core.buffer:cursor buf2 :endianness :little)))
            (dds.rtps.message:write-nack-frag c2 r w sn base numbits bitmap count)
            (%check :connext-nf-encode
                    (and (= (dds.core.buffer:cursor-position c2) (length vec))
                         (loop for i below (length vec)
                               always (= (aref (dds.core.buffer:octet-buffer-vec buf2) i)
                                         (aref vec i))))
                    "write-nack-frag reproduces the captured submessage byte-for-byte")
            (dds.core.arena:pool-release pool buf2))))
      (dds.core.arena:pool-release pool buf))
    (dds.core.arena:teardown-arena arena)
    t))

;;; RTPS message framing: build Header + DATA + HEARTBEAT into one buffer, then
;;; dispatch-message walks the submessages back out (RTPS 2.5 §8.3.4 / §9.4.5).

(defun* run-rtps-dispatch-test ()
    (function () t)
  "Test: RTPS message dispatch routes each submessage to its handler."
  (let* ((arena (dds.core.arena:init-arena :bytes (* 64 1024)))
         (pool (dds.core.arena:make-buffer-pool arena 256 1))
         (buf (dds.core.arena:pool-acquire pool))
         (c (dds.core.buffer:cursor buf :endianness :little))
         (prefix (make-array 12 :element-type '(unsigned-byte 8) :initial-element 0))
         (rid dds.rtps.message:+entityid-participant+)
         (wid dds.rtps.message:+entityid-unknown+)
         (payload (make-array 8 :element-type '(unsigned-byte 8)
                                :initial-contents '(0 #x11 0 0 #x2a 0 0 0))))
    (dds.rtps.message:write-header c prefix :vendor 0)
    (dds.rtps.message:write-data c rid wid 7 payload 0 8)
    (dds.rtps.message:write-heartbeat c rid wid 1 7 1 :final t)
    (dds.core.buffer:cursor-reset c)
    (let ((seen '()))
      (let ((ok (dds.rtps.message:dispatch-message
                 c (lambda (id flags cur body-len)
                     (cond
                       ((= id dds.rtps.message:+submsg-data+)
                        (multiple-value-bind (r w sn) (dds.rtps.message:parse-data-body cur flags body-len)
                          (declare (ignore r w))
                          (push (list :data sn) seen)))
                       ((= id dds.rtps.message:+submsg-heartbeat+)
                        (multiple-value-bind (r w first) (dds.rtps.message:parse-heartbeat-body cur flags)
                          (declare (ignore r w))
                          (push (list :heartbeat first) seen))))))))
        (%check :dispatch-ok ok "message dispatch returned T")
        (%check :dispatch-seen (equal '((:data 7) (:heartbeat 1)) (nreverse seen))
                "DATA then HEARTBEAT dispatched in order")))
    (dds.core.arena:pool-release pool buf)
    (dds.core.arena:teardown-arena arena)
    t))

;;; ParameterList (PID) codec byte-exact + round-trip (RTPS 2.5 §9.4.2.11) and the
;;; RTPS port-mapping formula (§9.6.1.1).

(defun* run-paramlist-test ()
    (function () t)
  "Test: ParameterList write/parse round-trip, including the PID_SENTINEL terminator."
  (let* ((arena (dds.core.arena:init-arena :bytes (* 64 1024)))
         (pool (dds.core.arena:make-buffer-pool arena 128 1))
         (buf (dds.core.arena:pool-acquire pool))
         (c (dds.core.buffer:cursor buf :endianness :little))
         (val (make-array 1 :element-type '(unsigned-byte 8) :initial-contents '(#x54)))) ; "T"
    ;; one parameter PID_TOPIC_NAME (0x0005), value "T" padded to 4, then sentinel
    (dds.rtps.message:write-parameter c dds.rtps.message:+pid-topic-name+ val 0 1)
    (dds.rtps.message:write-parameter-sentinel c)
    (%check :pl-bytes
            (equal '(#x05 #x00 #x04 #x00 #x54 #x00 #x00 #x00 #x01 #x00 #x00 #x00)
                   (%first-bytes buf 12))
            "ParameterList bytes (PID 0x0005 len 4 'T' + SENTINEL)")
    ;; parse it back
    (dds.core.buffer:cursor-reset c)
    (let ((seen '()))
      (let ((ok (dds.rtps.message:parse-parameter-list
                 c (lambda (pid cur len)
                     (push (list pid (dds.core.buffer:get-u8 cur) len) seen)))))
        (%check :pl-parse (and ok (equal (list (list dds.rtps.message:+pid-topic-name+ #x54 4))
                                         (nreverse seen)))
                "ParameterList parse round-trip")))
    ;; bounds: a 2-octet buffer cannot hold a Parameter header -> NIL
    (let* ((b2 (dds.core.arena:make-buffer-pool arena 2 1))
           (sb (dds.core.arena:pool-acquire b2))
           (sc (dds.core.buffer:cursor sb :endianness :little)))
      (%check :pl-bounds (null (dds.rtps.message:parse-parameter-list sc (lambda (p c l) (declare (ignore p c l)))))
              "short ParameterList -> NIL"))
    (dds.core.arena:pool-release pool buf)
    (dds.core.arena:teardown-arena arena)
    t))

(defun* run-participant-message-codec-test ()
    (function () t)
  "ParticipantMessageData (RTPS 2.5 §8.4.13.4 / §9.6.3.2) round-trips:
   participantGuidPrefix(12) + kind(octet[4]) + data(sequence<octet>); the bare CDR
   struct (no encapsulation header) matches a locked vector. kind is octet[4] raw
   (endianness-independent, AUTOMATIC = {0,0,0,1}); the data-length sequence count is
   the only endianness-sensitive field and is written PLAIN_CDR little-endian."
  (let* ((prefix (make-array 12 :element-type '(unsigned-byte 8)
                             :initial-contents '(1 2 3 4 5 6 7 8 9 10 11 12)))
         (pm (dds.rtps.discovery:make-participant-message
              :guid-prefix prefix :kind dds.rtps.discovery:+pmd-kind-automatic+
              :data (make-array 0 :element-type '(unsigned-byte 8))))
         (bytes (dds.rtps.discovery:serialize-participant-message pm))
         (back (dds.rtps.discovery:parse-participant-message bytes)))
    (%check :pm-parse back "parse-participant-message returned NIL")
    (%check :pm-prefix (equalp prefix (dds.rtps.discovery:participant-message-guid-prefix back)) "prefix")
    (%check :pm-kind (= dds.rtps.discovery:+pmd-kind-automatic+ (dds.rtps.discovery:participant-message-kind back)) "kind")
    (%check :pm-data (= 0 (length (dds.rtps.discovery:participant-message-data back))) "empty data")
    ;; locked vector: prefix(12) + kind {0,0,0,1} + data.length u32 0 = 20 octets, no encapsulation
    (%check :pm-vector (equalp bytes (octets 1 2 3 4 5 6 7 8 9 10 11 12  0 0 0 1  0 0 0 0)) "byte-exact")
    ;; non-empty data: 3 octets -> length 3 (LE u32) + 3 octets, no trailing pad (final member, XCDR §10.2)
    (let* ((d3 (octets #xAA #xBB #xCC))
           (pm3 (dds.rtps.discovery:make-participant-message
                 :guid-prefix prefix :kind dds.rtps.discovery:+pmd-kind-manual-by-participant+ :data d3))
           (b3 (dds.rtps.discovery:serialize-participant-message pm3))
           (back3 (dds.rtps.discovery:parse-participant-message b3)))
      (%check :pm3-kind (= dds.rtps.discovery:+pmd-kind-manual-by-participant+
                           (dds.rtps.discovery:participant-message-kind back3)) "manual kind")
      (%check :pm3-data (equalp d3 (dds.rtps.discovery:participant-message-data back3)) "3-octet data round-trip")
      (%check :pm3-vector
              (equalp b3 (octets 1 2 3 4 5 6 7 8 9 10 11 12  0 0 0 2  3 0 0 0  #xAA #xBB #xCC))
              "byte-exact 3-octet data"))
    ;; bounds: truncation before the full header -> NIL, never OOB (NFR-SEC-POSTURE)
    (%check :pm-trunc (null (dds.rtps.discovery:parse-participant-message (octets 1 2 3 4 5)))
            "truncated -> NIL")
    ;; bounds: a data.length larger than the remaining buffer -> NIL
    (%check :pm-overlen
            (null (dds.rtps.discovery:parse-participant-message
                   (octets 1 2 3 4 5 6 7 8 9 10 11 12  0 0 0 1  0 0 0 99)))
            "over-long data.length -> NIL")
    t))

(defun* run-fastdds-participant-message-test ()
    (function () t)
  "Interop byte-validation of ParticipantMessageData against the CONFORMANT peer eProsima
   Fast DDS 3.6.1 (RTPS 2.5 §8.4.13.4 / §9.6.3.2). The locked vector is the bare CDR struct
   captured live from a Fast DDS BuiltinParticipantMessageWriter (EntityId 0x000200c2) DATA
   submessage — interop/fastdds/captures/wlp-participant-message-lo0.pcap frame 89, an
   AUTOMATIC liveliness assertion (kind {0,0,0,1}, empty data) under a finite-lease writer.
   Confirms our parser decodes the conformant peer's bytes AND our serializer reproduces them
   byte-exact. RTI Connext does NOT emit standard ParticipantMessageData (proprietary
   NDDSPING), so this was the deferred conformant-peer path; see docs/provenance.md."
  (let* ((prefix (make-array 12 :element-type '(unsigned-byte 8)
                  :initial-contents '(#x01 #x0f #x3a #xf1 #x63 #x67 #xed #x4d 0 0 0 0)))
         ;; Fast DDS frame 89 bare struct (after the PLAIN_CDR_LE header): prefix(12) + kind{0,0,0,1} + len 0
         (wire (octets #x01 #x0f #x3a #xf1 #x63 #x67 #xed #x4d 0 0 0 0  0 0 0 1  0 0 0 0))
         (back (dds.rtps.discovery:parse-participant-message wire)))
    (%check :fdds-pm-parse back "parse of Fast DDS ParticipantMessageData returned NIL")
    (%check :fdds-pm-prefix (equalp prefix (dds.rtps.discovery:participant-message-guid-prefix back)) "guidPrefix")
    (%check :fdds-pm-kind (= dds.rtps.discovery:+pmd-kind-automatic+
                             (dds.rtps.discovery:participant-message-kind back)) "AUTOMATIC kind")
    (%check :fdds-pm-data (zerop (length (dds.rtps.discovery:participant-message-data back)))
            "empty data (liveliness assertion carries none)")
    (let* ((pm (dds.rtps.discovery:make-participant-message
                :guid-prefix prefix :kind dds.rtps.discovery:+pmd-kind-automatic+
                :data (make-array 0 :element-type '(unsigned-byte 8))))
           (ours (dds.rtps.discovery:serialize-participant-message pm)))
      (%check :fdds-pm-serialize-exact (equalp ours wire)
              "our serializer must reproduce the Fast DDS wire bytes byte-exact"))
    (%check :fdds-pm-roundtrip (equalp wire (dds.rtps.discovery:serialize-participant-message back))
            "parse then re-serialize of the Fast DDS bytes must close byte-exact")
    t))

(defun* run-port-mapping-test ()
    (function () t)
  "Test: the RTPS well-known port-mapping formulas (RTPS 2.5 §9.6.1.1)."
  (%check :port-spdp-mc (and (= 7400 (dds.rtps.message:spdp-multicast-port 0))
                             (= 7650 (dds.rtps.message:spdp-multicast-port 1)))
          "SPDP multicast port")
  (%check :port-spdp-uc (and (= 7410 (dds.rtps.message:spdp-unicast-port 0 0))
                             (= 7412 (dds.rtps.message:spdp-unicast-port 0 1)))
          "SPDP unicast port")
  (%check :port-user-mc (= 7401 (dds.rtps.message:user-multicast-port 0)) "user multicast port")
  (%check :port-user-uc (and (= 7411 (dds.rtps.message:user-unicast-port 0 0))
                             (= 7413 (dds.rtps.message:user-unicast-port 0 1)))
          "user unicast port")
  t)

;;; HistoryCache: HISTORY (KEEP_LAST/KEEP_ALL) + RESOURCE_LIMITS (FR-RTPS-5).

(defun* run-history-test ()
    (function () t)
  "Test: HistoryCache HISTORY + RESOURCE_LIMITS behaviour (KEEP_LAST/KEEP_ALL)."
  (flet ((mk (sn) (dds.rtps.history:make-cache-change :sn sn)))
    ;; KEEP_LAST depth 3: adding 1..4 evicts SN 1
    (let ((hc (dds.rtps.history:make-history-cache :keep-last 3 nil nil)))
      (dolist (sn '(1 2 3 4)) (dds.rtps.history:hc-add-change hc (mk sn)))
      (%check :kl-count (= 3 (dds.rtps.history:hc-change-count hc)) "KEEP_LAST count")
      (%check :kl-evict (null (dds.rtps.history:hc-get-change hc 1)) "KEEP_LAST evicted SN1")
      (%check :kl-keep (dds.rtps.history:hc-get-change hc 4) "KEEP_LAST kept SN4")
      (%check :kl-min (= 2 (dds.rtps.history:hc-min-seq hc)) "KEEP_LAST min")
      (%check :kl-max (= 4 (dds.rtps.history:hc-max-seq hc)) "KEEP_LAST max")
      (%check :kl-sorted
              (equal '(2 3 4) (mapcar #'dds.rtps.history:cache-change-sn
                                      (dds.rtps.history:hc-changes-for-reader hc nil)))
              "changes-for-reader ascending SN"))
    ;; KEEP_ALL with max_samples=2: 3rd add rejected; duplicate detected
    (let ((hc (dds.rtps.history:make-history-cache :keep-all 1 2 nil)))
      (%check :ka-1 (eq :ok (dds.rtps.history:hc-add-change hc (mk 1))) "KEEP_ALL add 1")
      (%check :ka-2 (eq :ok (dds.rtps.history:hc-add-change hc (mk 2))) "KEEP_ALL add 2")
      (%check :ka-rej (eq :rejected-resource-limits (dds.rtps.history:hc-add-change hc (mk 3)))
              "KEEP_ALL rejects at max_samples")
      (%check :ka-dup (eq :duplicate (dds.rtps.history:hc-add-change hc (mk 1))) "duplicate SN")
      (%check :ka-rm (and (dds.rtps.history:hc-remove-change hc 1)
                          (= 1 (dds.rtps.history:hc-change-count hc)))
              "remove decrements count"))
    t))

;;; Reliable writer/reader: eventual delivery through a lossy/reorder/dup channel
;;; (RTPS 2.5 §8.4; NFR-TEST reliability suite). Deterministic loss pattern that
;;; clears by round 3, so convergence is guaranteed and the loop is bounded.

(defun* run-reliability-test ()
    (function () t)
  "Test: the reliable writer/reader HEARTBEAT/ACKNACK delivery state machine."
  (let* ((writer (dds.rtps.reliable:make-rtps-writer
                  :hc (dds.rtps.history:make-history-cache :keep-all 1 nil nil)))
         (reader (dds.rtps.reliable:make-rtps-reader))
         (wid 1) (rid 2) (n 10))
    (dotimes (i n) (dds.rtps.reliable:writer-write
                    writer (map '(simple-array (unsigned-byte 8) (*)) #'char-code (format nil "m~d" (1+ i)))))
    (labels ((deliver (sn payload round)
               (when (or (>= round 3) (zerop (logand 1 (+ (* sn 7) (* round 13)))))
                 (dds.rtps.reliable:reader-on-data reader wid sn payload))))
      ;; initial blast: reversed (reorder) + a duplicate delivery of SN 1
      (deliver 1 (map '(simple-array (unsigned-byte 8) (*)) #'char-code "m1") 0)
      (dolist (ch (reverse (dds.rtps.reliable:writer-data-list writer rid)))
        (deliver (dds.rtps.history:cache-change-sn ch)
                 (dds.rtps.history:cache-change-serialized-payload ch) 0))
      (let ((done nil))
        (dotimes (round 8)
          (multiple-value-bind (first last count) (dds.rtps.reliable:writer-heartbeat writer)
            (declare (ignore count))
            (dds.rtps.reliable:reader-on-heartbeat reader wid first last))
          (when (dds.rtps.reliable:reader-complete-p reader wid) (setf done t) (return))
          (multiple-value-bind (base numbits bitmap) (dds.rtps.reliable:reader-acknack reader wid)
            (multiple-value-bind (resends gaps)
                (dds.rtps.reliable:writer-on-acknack writer rid base numbits bitmap)
              (declare (ignore gaps))
              (dolist (ch resends)
                (deliver (dds.rtps.history:cache-change-sn ch)
                         (dds.rtps.history:cache-change-serialized-payload ch) (1+ round))))))
        (when (dds.rtps.reliable:reader-complete-p reader wid) (setf done t))
        (%check :reliable-converged done "reliable delivery did not converge")
        (let ((recv (dds.rtps.reliable:writer-proxy-received
                     (dds.rtps.reliable:get-writer-proxy reader wid))))
          (%check :reliable-all (loop for sn from 1 to n always (gethash sn recv))
                  "reader missing SNs after convergence"))))
    t))

;;; GAP: a reader NACKing evicted samples gets a GAP for them and a resend for the
;;; samples still in the HistoryCache (RTPS 2.5 §8.3.7.4).

(defun* run-gap-handling-test ()
    (function () t)
  "Test: reliable reader GAP handling and SequenceNumberSet bitmap edges."
  (let* ((writer (dds.rtps.reliable:make-rtps-writer
                  :hc (dds.rtps.history:make-history-cache :keep-last 2 nil nil)))
         (reader (dds.rtps.reliable:make-rtps-reader))
         (wid 1) (rid 2))
    (dotimes (i 5) (dds.rtps.reliable:writer-write              ; hc holds 4,5
                    writer (map '(simple-array (unsigned-byte 8) (*)) #'char-code (format nil "m~d" (1+ i)))))
    (dds.rtps.reliable:reader-on-heartbeat reader wid 1 5)        ; reader still thinks [1,5] avail
    (multiple-value-bind (base numbits bitmap) (dds.rtps.reliable:reader-acknack reader wid)
      (%check :gap-acknack (and (= base 1) (= numbits 5)) "reader NACKs all of [1,5]")
      (multiple-value-bind (resends gaps)
          (dds.rtps.reliable:writer-on-acknack writer rid base numbits bitmap)
        (%check :gap-resends (equal '(4 5) (mapcar #'dds.rtps.history:cache-change-sn resends))
                "present SNs resent")
        (%check :gap-gaps (equal '(1 2 3) gaps) "evicted SNs gapped")
        (dolist (ch resends)
          (dds.rtps.reliable:reader-on-data reader wid
                                            (dds.rtps.history:cache-change-sn ch)
                                            (dds.rtps.history:cache-change-serialized-payload ch)))
        (dds.rtps.reliable:reader-on-gap
         reader wid 1 4 0 (make-array 1 :element-type '(unsigned-byte 32) :initial-element 0))
        (%check :gap-complete (dds.rtps.reliable:reader-complete-p reader wid)
                "reader complete after GAP(1..3) + DATA(4,5)")))
    t))

;;; Send-once writer push: the writer pushes UNSENT changes once (RTPS 2.5 §8.4.2.2,
;;; next_unsent_change / unsent_changes) and repairs ONLY requested_changes on ACKNACK.
;;; Regression for the O(N^2) DATA storm where the whole unacked history was re-pushed
;;; on every write; the ACKNACK-driven repair path is independent of unsent-base.

(defun* run-writer-pushonce-test ()
    (function () t)
  "Test: writer-unsent-list pushes each change exactly once (RTPS 2.5 §8.4.2.2); the
   total DATA pushed over N pre-ACKNACK writes is N (send-once), not N(N+1)/2; and the
   ACKNACK repair path (writer-on-acknack) still resends exactly the NACKed SNs."
  (flet ((mk-writer ()
           (dds.rtps.reliable:make-rtps-writer
            :hc (dds.rtps.history:make-history-cache :keep-all 1 nil nil)))
         (pl (k) (map '(simple-array (unsigned-byte 8) (*)) #'char-code (format nil "m~d" k))))
    (let ((rid 2))
      ;; (a) send-once: sum of unsent-list lengths over 100 writes = 100 (each change once)
      (let ((w (mk-writer)) (sum 0))
        (dotimes (k 100)
          (dds.rtps.reliable:writer-write w (pl (1+ k)))
          (incf sum (length (dds.rtps.reliable:writer-unsent-list w rid))))
        (%check :pushonce-sent-once (= sum 100)
                "writer-unsent-list must push each of 100 changes exactly once (sum=100)")
        ;; (c) repair-intact: unsent-base is now 101; an ACKNACK NACKing {3,50} resends exactly those
        (let ((base 3) (numbits 48)
              (bitmap (make-array 2 :element-type '(unsigned-byte 32) :initial-element 0)))
          (dds.rtps.message:seqnum-set-bit bitmap 0)    ; SN 3 (delta 0)
          (dds.rtps.message:seqnum-set-bit bitmap 47)   ; SN 50 (delta 47)
          (multiple-value-bind (resends gaps)
              (dds.rtps.reliable:writer-on-acknack w rid base numbits bitmap)
            (declare (ignore gaps))
            (%check :pushonce-repair-sns
                    (equal '(3 50) (mapcar #'dds.rtps.history:cache-change-sn resends))
                    "ACKNACK repair resends exactly the NACKed SNs {3,50}, independent of unsent-base")
            (%check :pushonce-repair-payloads
                    (and (equalp (dds.rtps.history:cache-change-serialized-payload (first resends)) (pl 3))
                         (equalp (dds.rtps.history:cache-change-serialized-payload (second resends)) (pl 50)))
                    "ACKNACK repair resends the {3,50} payloads byte-exact"))))
      ;; (b) before-baseline: writer-data-list (whole unacked history) sums to 5050 = N(N+1)/2
      (let ((w (mk-writer)) (sum 0))
        (dotimes (k 100)
          (dds.rtps.reliable:writer-write w (pl (1+ k)))
          (incf sum (length (dds.rtps.reliable:writer-data-list w rid))))
        (%check :pushonce-before-baseline (= sum 5050)
                "writer-data-list (unchanged) re-collects the whole unacked history: sum=5050"))))
  t)

;;; HEARTBEAT / ACKNACK / GAP submessage round-trips (RTPS 2.5 §9.4.5.7/.3/.6).
;;; Writes a complete submessage, re-reads the SubmessageHeader, then the body.

(defun* run-rtps-submessage-test ()
    (function () t)
  "Test: individual RTPS submessage codecs (HEARTBEAT/ACKNACK/GAP/INFO_*)."
  (let* ((arena (dds.core.arena:init-arena :bytes (* 64 1024)))
         (pool (dds.core.arena:make-buffer-pool arena 128 1))
         (buf (dds.core.arena:pool-acquire pool))
         (c (dds.core.buffer:cursor buf :endianness :little))
         (rid dds.rtps.message:+entityid-participant+)
         (wid dds.rtps.message:+entityid-unknown+)
         (bm (make-array 1 :element-type '(unsigned-byte 32) :initial-element 0)))
    (dds.rtps.message:seqnum-set-bit bm 0)            ; offset 0 (= base) in set
    ;; HEARTBEAT: header (id 0x07, flags E|F) + body 28; octetsToNextHeader=28
    (dds.rtps.message:write-heartbeat c rid wid 1 10 7 :final t)
    (dds.core.buffer:cursor-reset c)
    (multiple-value-bind (id flags octets le) (dds.rtps.message:parse-submessage-header c)
      (%check :hb-hdr (and (= id #x07) (= flags #x03) (= octets 28) le) "HEARTBEAT header")
      (multiple-value-bind (r w f l count fin liv) (dds.rtps.message:parse-heartbeat-body c flags)
        (%check :hb-body
                (and (= r rid) (= w wid) (= f 1) (= l 10) (= count 7) fin (not liv))
                "HEARTBEAT body round-trip")))
    ;; ACKNACK: readerSNState base=5 numBits=1 (offset 0 set), count=3, final
    (dds.core.buffer:cursor-reset c)
    (dds.rtps.message:write-acknack c rid wid 5 1 bm 3 :final t)
    (dds.core.buffer:cursor-reset c)
    (multiple-value-bind (id flags octets le) (dds.rtps.message:parse-submessage-header c)
      (declare (ignore le))
      (%check :an-hdr (and (= id #x06) (= octets 28)) "ACKNACK header") ; 24+4*1
      (multiple-value-bind (r w base nb b count fin) (dds.rtps.message:parse-acknack-body c flags)
        (%check :an-body
                (and (= r rid) (= w wid) (= base 5) (= nb 1) (= (aref b 0) #x80000000)
                     (= count 3) fin)
                "ACKNACK body round-trip")))
    ;; GAP: gapStart=2 gapList base=4 numBits=1
    (dds.core.buffer:cursor-reset c)
    (dds.rtps.message:write-gap c rid wid 2 4 1 bm)
    (dds.core.buffer:cursor-reset c)
    (multiple-value-bind (id flags octets le) (dds.rtps.message:parse-submessage-header c)
      (declare (ignore le))
      (%check :gap-hdr (and (= id #x08) (= octets 32)) "GAP header") ; 28+4*1
      (multiple-value-bind (r w gstart base nb b) (dds.rtps.message:parse-gap-body c flags)
        (%check :gap-body
                (and (= r rid) (= w wid) (= gstart 2) (= base 4) (= nb 1) (= (aref b 0) #x80000000))
                "GAP body round-trip")))
    (dds.core.arena:pool-release pool buf)
    (dds.core.arena:teardown-arena arena)
    t))

;;; SequenceNumber + SequenceNumberSet byte-exact + exhaustive bitmap boundaries
;;; (RTPS 2.5 §9.3.2.10 / §9.4.2.6) — the classic off-by-one source (FR-RTPS-7, R4).

(defun* run-rtps-seqnum-test ()
    (function () t)
  "Test: SequenceNumber + SequenceNumberSet bitmap encode/decode edge cases."
  (let* ((arena (dds.core.arena:init-arena :bytes (* 64 1024)))
         (pool (dds.core.arena:make-buffer-pool arena 64 1))
         (buf (dds.core.arena:pool-acquire pool))
         (c (dds.core.buffer:cursor buf :endianness :little)))
    ;; SequenceNumber: 1 -> high 0, low 1 (LE)
    (dds.rtps.message:write-sequence-number c 1)
    (%check :seqnum-bytes (equal '(0 0 0 0 1 0 0 0) (%first-bytes buf 8)) "seqnum=1 LE bytes")
    (dds.core.buffer:cursor-reset c)
    (%check :seqnum-rt (= 1 (dds.rtps.message:read-sequence-number c)) "seqnum=1 round-trip")
    (dds.core.buffer:cursor-reset c)
    (dds.rtps.message:write-sequence-number c #x123456789A)
    (dds.core.buffer:cursor-reset c)
    (%check :seqnum-large (= #x123456789A (dds.rtps.message:read-sequence-number c))
            "large seqnum round-trip")
    ;; SEQUENCENUMBER_UNKNOWN = {high=-1, low=0}
    (dds.core.buffer:cursor-reset c)
    (dds.rtps.message:write-sequence-number c dds.rtps.message:+sequence-number-unknown+)
    (%check :seqnum-unknown-bytes
            (equal '(#xff #xff #xff #xff 0 0 0 0) (%first-bytes buf 8)) "UNKNOWN bytes")
    (dds.core.buffer:cursor-reset c)
    (%check :seqnum-unknown-rt
            (= dds.rtps.message:+sequence-number-unknown+ (dds.rtps.message:read-sequence-number c))
            "UNKNOWN round-trip")
    ;; SequenceNumberSet spec example "1234/12:00110" (offsets 2,3 set)
    (let ((bm (make-array 1 :element-type '(unsigned-byte 32) :initial-element 0)))
      (dds.rtps.message:seqnum-set-bit bm 2)
      (dds.rtps.message:seqnum-set-bit bm 3)
      (%check :snset-bitmap (= #x30000000 (aref bm 0)) "1234/12 bitmap word")
      (dds.core.buffer:cursor-reset c)
      (dds.rtps.message:write-sequence-number-set c 1234 12 bm)
      (%check :snset-bytes
              (equal '(0 0 0 0 #xd2 4 0 0 #x0c 0 0 0 0 0 0 #x30) (%first-bytes buf 16))
              "1234/12 SequenceNumberSet LE bytes")
      (%check :snset-member
              (and (dds.rtps.message:seqnum-set-member-p 1234 12 bm 1236)
                   (dds.rtps.message:seqnum-set-member-p 1234 12 bm 1237)
                   (not (dds.rtps.message:seqnum-set-member-p 1234 12 bm 1234))
                   (not (dds.rtps.message:seqnum-set-member-p 1234 12 bm 1238)))
              "1234/12 membership"))
    (dds.core.buffer:cursor-reset c)
    (multiple-value-bind (base numbits bm2) (dds.rtps.message:read-sequence-number-set c)
      (%check :snset-parse (and (= base 1234) (= numbits 12) (= (aref bm2 0) #x30000000))
              "SequenceNumberSet parse"))
    ;; off-by-one boundaries: offset 0 -> bit31 word0; 31 -> bit0 word0; 32 -> bit31 word1
    (let ((bm (make-array 2 :element-type '(unsigned-byte 32) :initial-element 0)))
      (dds.rtps.message:seqnum-set-bit bm 0)
      (dds.rtps.message:seqnum-set-bit bm 31)
      (dds.rtps.message:seqnum-set-bit bm 32)
      (%check :snset-boundaries
              (and (= (aref bm 0) (logior #x80000000 1)) (= (aref bm 1) #x80000000))
              "bitmap word/bit boundaries"))
    ;; bounds: an 8-octet buffer cannot hold a SequenceNumberSet -> NIL, no OOB
    (let* ((b2 (dds.core.arena:make-buffer-pool arena 8 1))
           (sb (dds.core.arena:pool-acquire b2))
           (sc (dds.core.buffer:cursor sb :endianness :little)))
      (%check :snset-bounds (null (dds.rtps.message:read-sequence-number-set sc))
              "short buffer -> NIL"))
    (dds.core.arena:pool-release pool buf)
    (dds.core.arena:teardown-arena arena)
    t))

(defun* run-fragnum-set-test ()
    (function () t)
  "Test: FragmentNumberSet write/read round-trip + the membership bitmap (RTPS 2.5 §9.4.2.8)."
  (let* ((buf (dds.core.buffer:make-octet-buffer 64))
         (wc (dds.core.buffer:cursor buf :endianness :little))
         (bitmap (make-array 1 :element-type '(unsigned-byte 32) :initial-element 0)))
    (dds.rtps.message:fragnum-set-bit bitmap 0)
    (dds.rtps.message:fragnum-set-bit bitmap 2)
    (dds.rtps.message:write-fragment-number-set wc 3 3 bitmap)
    (let ((rc (dds.core.buffer:cursor buf :endianness :little)))
      (multiple-value-bind (base numbits bm) (dds.rtps.message:read-fragment-number-set rc)
        (%check :fns-base (= base 3) "FragmentNumberSet base round-trips")
        (%check :fns-numbits (= numbits 3) "FragmentNumberSet numBits round-trips")
        (%check :fns-members
                (and (dds.rtps.message:fragnum-set-member-p base numbits bm 3)
                     (not (dds.rtps.message:fragnum-set-member-p base numbits bm 4))
                     (dds.rtps.message:fragnum-set-member-p base numbits bm 5))
                "FragmentNumberSet membership: 3 and 5 present, 4 absent"))))
  (let* ((buf (dds.core.buffer:make-octet-buffer 4))
         (rc (dds.core.buffer:cursor buf :endianness :little)))
    (%check :fns-short (null (dds.rtps.message:read-fragment-number-set rc))
            "a sub-8-octet FragmentNumberSet rejects"))
  t)

;;; HEARTBEAT_FRAG round-trip (RTPS 2.5 §9.4.5.8): 24-octet body, only E flag.

(defun* run-heartbeat-frag-test ()
    (function () t)
  "Test: HEARTBEAT_FRAG write/parse round-trip (RTPS 2.5 §9.4.5.8; body=24)."
  ;; round-trip: write then parse back
  (let* ((buf (dds.core.buffer:make-octet-buffer 64))
         (c (dds.core.buffer:cursor buf :endianness :little))
         (rid #x107) (wid #x102) (sn 7) (lastfrag 5) (count 3))
    (dds.rtps.message:write-heartbeat-frag c rid wid sn lastfrag count)
    (dds.core.buffer:cursor-reset c)
    (multiple-value-bind (id flags octets le) (dds.rtps.message:parse-submessage-header c)
      (declare (ignore le))
      (%check :hbf-kind (= id dds.rtps.message:+submsg-heartbeat-frag+) "HEARTBEAT_FRAG kind")
      (%check :hbf-octets (= octets 24) "HEARTBEAT_FRAG body length 24")
      (multiple-value-bind (r w s lf cnt) (dds.rtps.message:parse-heartbeat-frag-body c flags)
        (%check :hbf-fields
                (and (= r rid) (= w wid) (= s sn) (= lf lastfrag) (= cnt count))
                "HEARTBEAT_FRAG fields round-trip"))))
  ;; bounds: a sub-24-octet buffer must yield NIL
  (let* ((buf (dds.core.buffer:make-octet-buffer 10))
         (c (dds.core.buffer:cursor buf :endianness :little)))
    (%check :hbf-short (null (dds.rtps.message:parse-heartbeat-frag-body c 0))
            "a sub-24-octet HEARTBEAT_FRAG body rejects"))
  t)

;;; Reader-side DATA_FRAG fragment reassembly (RTPS 2.5 §8.3.8.3 / §9.4.5.5).
;;; Out-of-order delivery, oversize-sampleSize rejection (NFR-SEC-POSTURE).

(defun* run-reassembly-test ()
    (function () t)
  "Test: reader-on-data-frag reassembles out-of-order fragments into the original sample,
   returns NIL until complete, and rejects an oversize sampleSize (NFR-SEC-POSTURE)."
  (let* ((reader (dds.rtps.reliable:make-rtps-reader))
         (wid 1) (sn 7) (fsize 1024) (ssize 2500)
         (orig (make-array ssize :element-type '(unsigned-byte 8))))
    (dotimes (i ssize) (setf (aref orig i) (logand (* i 7) #xff)))
    (flet ((frag (fnum)
             (let* ((off (* (1- fnum) fsize)) (len (min fsize (- ssize off))))
               (subseq orig off (+ off len)))))
      (%check :rsm-partial1
              (null (dds.rtps.reliable:reader-on-data-frag reader wid sn 3 1 fsize ssize (frag 3)))
              "incomplete after fragment 3 of 3")
      (%check :rsm-partial2
              (null (dds.rtps.reliable:reader-on-data-frag reader wid sn 1 1 fsize ssize (frag 1)))
              "incomplete after fragment 1")
      (let ((done (dds.rtps.reliable:reader-on-data-frag reader wid sn 2 1 fsize ssize (frag 2))))
        (%check :rsm-complete (and done (equalp done orig))
                "complete + byte-exact after the final fragment"))))
  (let ((r2 (dds.rtps.reliable:make-rtps-reader)))
    (%check :rsm-oversize
            (null (dds.rtps.reliable:reader-on-data-frag
                   r2 1 1 1 1 1024 (1+ dds.rtps.reliable:*max-reassembly-bytes*)
                   (make-array 1024 :element-type '(unsigned-byte 8))))
            "sampleSize over *max-reassembly-bytes* rejects without allocating"))
  t)

;;; reader-frag-acknack: compute NACK_FRAG fragment set for missing fragments (RTPS 2.5 §8.3.7.2).

(defun* run-frag-acknack-test ()
    (function () t)
  "Test: reader-frag-acknack names exactly the missing fragment numbers, NIL when complete/unknown."
  (let* ((reader (dds.rtps.reliable:make-rtps-reader))
         (wid 1) (sn 9) (fsize 100) (ssize 500)   ; 5 fragments
         (orig (make-array ssize :element-type '(unsigned-byte 8) :initial-element 7)))
    (flet ((frag (fnum)
             (let* ((off (* (1- fnum) fsize)) (len (min fsize (- ssize off))))
               (subseq orig off (+ off len)))))
      (dds.rtps.reliable:reader-on-data-frag reader wid sn 1 1 fsize ssize (frag 1))
      (dds.rtps.reliable:reader-on-data-frag reader wid sn 3 1 fsize ssize (frag 3))
      (multiple-value-bind (base numbits bitmap) (dds.rtps.reliable:reader-frag-acknack reader wid sn)
        (%check :rfa-missing
                (and base
                     (dds.rtps.message:fragnum-set-member-p base numbits bitmap 2)
                     (dds.rtps.message:fragnum-set-member-p base numbits bitmap 4)
                     (dds.rtps.message:fragnum-set-member-p base numbits bitmap 5)
                     (not (dds.rtps.message:fragnum-set-member-p base numbits bitmap 1))
                     (not (dds.rtps.message:fragnum-set-member-p base numbits bitmap 3)))
                "NACK_FRAG names exactly the missing fragments {2,4,5}"))
      (%check :rfa-unknown (null (dds.rtps.reliable:reader-frag-acknack reader wid 999))
              "unknown SN yields NIL")))
  (let ((r2 (dds.rtps.reliable:make-rtps-reader)) (fs 100) (ss 200))   ; 2 fragments, fully delivered
    (let ((src (make-array ss :element-type '(unsigned-byte 8) :initial-element 3)))
      (flet ((fr (fnum) (let* ((off (* (1- fnum) fs)) (len (min fs (- ss off))))
                          (subseq src off (+ off len)))))
        (dds.rtps.reliable:reader-on-data-frag r2 1 5 1 1 fs ss (fr 1))
        (dds.rtps.reliable:reader-on-data-frag r2 1 5 2 1 fs ss (fr 2))))
    (%check :rfa-complete (null (dds.rtps.reliable:reader-frag-acknack r2 1 5))
            "a fully-received sample yields NIL (entry already removed)"))
  t)

;;; Writer-side fragmentation planner (RTPS 2.5 §8.3.8.3).

(defun* run-frag-plan-test ()
    (function () t)
  "Test: writer-frag-plan packs fragments per budget and covers the sample; writer-frag-plan-for
   re-plans exactly the NACKed fragments (RTPS 2.5 §8.3.8.3)."
  (let ((plan (dds.rtps.reliable:writer-frag-plan 2500 1024 2048)))
    (%check :wfp-count (= 2 (length plan)) "two submessages for 2500B @1024, budget 2048")
    (destructuring-bind ((f1 c1 o1 l1) (f2 c2 o2 l2)) plan
      (%check :wfp-s1 (and (= f1 1) (= c1 2) (= o1 0) (= l1 2048)) "submsg1: frags 1-2, 2048B")
      (%check :wfp-s2 (and (= f2 3) (= c2 1) (= o2 2048) (= l2 452)) "submsg2: frag 3, 452B")))
  (let ((plan (dds.rtps.reliable:writer-frag-plan 2500 1024 1024)))
    (%check :wfp-perfrag (= 3 (length plan)) "budget=fragment-size -> one fragment per submessage"))
  (let ((bitmap (make-array 1 :element-type '(unsigned-byte 32) :initial-element 0)))
    (dds.rtps.message:fragnum-set-bit bitmap 0)   ; frag 2 (base 2, delta 0)
    (dds.rtps.message:fragnum-set-bit bitmap 2)   ; frag 4 (delta 2)
    (let ((plan (dds.rtps.reliable:writer-frag-plan-for 500 100 2 3 bitmap)))
      (%check :wfpf (equal '((2 1 100 100) (4 1 300 100)) plan)
              "NACK resend plans exactly frags 2 and 4, one per submessage")))
  t)

;;; writer-frag-heartbeat + writer-on-nack-frag: glue writer to HEARTBEAT_FRAG/NACK_FRAG.

(defun* run-writer-frag-glue-test ()
    (function () t)
  "Test: writer-frag-heartbeat reports the sample's fragment count + a rising count;
   writer-on-nack-frag plans the DATA_FRAG resends for exactly the NACKed fragments."
  (let* ((dds.rtps.reliable:*fragment-size* 1024)
         (writer (dds.rtps.reliable:make-rtps-writer
                  :hc (dds.rtps.history:make-history-cache :keep-all 1 nil nil)))
         (payload (make-array 2500 :element-type '(unsigned-byte 8) :initial-element 9))
         (sn (dds.rtps.reliable:writer-write writer payload)))   ; 3 fragments @1024
    (multiple-value-bind (lastfrag c1) (dds.rtps.reliable:writer-frag-heartbeat writer sn)
      (%check :wfh-last (= lastfrag 3) "HEARTBEAT_FRAG lastFragmentNum = 3 for 2500B@1024")
      (multiple-value-bind (lastfrag2 c2) (dds.rtps.reliable:writer-frag-heartbeat writer sn)
        (declare (ignore lastfrag2))
        (%check :wfh-count (> c2 c1) "HEARTBEAT_FRAG count increases")))
    (let ((bitmap (make-array 1 :element-type '(unsigned-byte 32) :initial-element 0)))
      (dds.rtps.message:fragnum-set-bit bitmap 0)   ; frag 2 (base 2, delta 0)
      (%check :wonf (equal '((2 1 1024 1024)) (dds.rtps.reliable:writer-on-nack-frag writer sn 2 1 bitmap))
              "NACK_FRAG for frag 2 resends one DATA_FRAG (frag 2, off 1024, len 1024)")))
  t)

;;; Offline integration: fragment a large sample and reassemble byte-exact using the
;;; real codec + planner + reassembly (RTPS 2.5 §9.4.5.5 / §8.3.8.3).

(defun* run-frag-roundtrip-test ()
    (function () t)
  "Test: a large sample fragmented via writer-frag-plan + write-data-frag round-trips through
   parse-data-frag-body + reader-on-data-frag to the byte-exact original (RTPS 2.5 §9.4.5.5)."
  (let* ((dds.rtps.reliable:*fragment-size* 1024)
         (fsize 1024) (budget 2048) (ssize 2500)
         (wid #x102) (rid #x107) (sn 1)
         (reader (dds.rtps.reliable:make-rtps-reader))
         (orig (make-array ssize :element-type '(unsigned-byte 8)))
         (done nil))
    (dotimes (i ssize) (setf (aref orig i) (logand (* i 7) #xff)))
    (dolist (desc (dds.rtps.reliable:writer-frag-plan ssize fsize budget))
      (destructuring-bind (fstart fcount off len) desc
        (let* ((buf (dds.core.buffer:make-octet-buffer 4096))
               (wc (dds.core.buffer:cursor buf :endianness :little)))
          (dds.rtps.message:write-data-frag wc rid wid sn ssize fstart fcount fsize orig off len)
          (dds.core.buffer:cursor-reset wc)
          (multiple-value-bind (id flags octets le) (dds.rtps.message:parse-submessage-header wc)
            (declare (ignore id le))
            (multiple-value-bind (r w psn pssize pfstart pfrags pfsize poff plen keyp)
                (dds.rtps.message:parse-data-frag-body wc flags octets)
              (declare (ignore r keyp))
              (let ((region (subseq (dds.core.buffer:octet-buffer-vec buf) poff (+ poff plen))))
                (setf done (dds.rtps.reliable:reader-on-data-frag
                            reader w psn pfstart pfrags pfsize pssize region))))))))
    (%check :frt-complete (and done (equalp done orig))
            "fragmented large sample reassembles byte-exact our-writer -> our-reader"))
  t)

;;; Lossy-delivery integration: fragment transfer with deliberate drops recovers via NACK_FRAG.

(defun* run-frag-lossy-test ()
    (function () t)
  "Test: a lost-fragment transfer recovers via NACK_FRAG — the reader NACKs exactly the dropped
   fragments, the writer resends only those, and the sample completes (RTPS 2.5 §8.3.8)."
  (let* ((dds.rtps.reliable:*fragment-size* 100)
         (fsize 100) (ssize 500) (wid #x102) (rid #x107)
         (writer (dds.rtps.reliable:make-rtps-writer
                  :hc (dds.rtps.history:make-history-cache :keep-all 1 nil nil)))
         (reader (dds.rtps.reliable:make-rtps-reader))
         (orig (make-array ssize :element-type '(unsigned-byte 8)))
         (dropped '(2 4)))
    (dotimes (i ssize) (setf (aref orig i) (logand (* i 3) #xff)))
    (let ((sn (dds.rtps.reliable:writer-write writer orig)))
      (flet ((deliver (desc)
               (destructuring-bind (fstart fcount off len) desc
                 (let* ((buf (dds.core.buffer:make-octet-buffer 256))
                        (wc (dds.core.buffer:cursor buf :endianness :little)))
                   (dds.rtps.message:write-data-frag wc rid wid sn ssize fstart fcount fsize orig off len)
                   (dds.core.buffer:cursor-reset wc)
                   (multiple-value-bind (id flags octets le) (dds.rtps.message:parse-submessage-header wc)
                     (declare (ignore id le))
                     (multiple-value-bind (r w psn pssize pfstart pfrags pfsize poff plen keyp)
                         (dds.rtps.message:parse-data-frag-body wc flags octets)
                       (declare (ignore r keyp))
                       (dds.rtps.reliable:reader-on-data-frag
                        reader w psn pfstart pfrags pfsize pssize
                        (subseq (dds.core.buffer:octet-buffer-vec buf) poff (+ poff plen)))))))))
        (dolist (desc (dds.rtps.reliable:writer-frag-plan ssize fsize fsize))
          (unless (member (first desc) dropped) (deliver desc)))
        (multiple-value-bind (base numbits bitmap) (dds.rtps.reliable:reader-frag-acknack reader wid sn)
          (%check :lossy-nack
                  (and base
                       (dds.rtps.message:fragnum-set-member-p base numbits bitmap 2)
                       (dds.rtps.message:fragnum-set-member-p base numbits bitmap 4)
                       (not (dds.rtps.message:fragnum-set-member-p base numbits bitmap 1))
                       (not (dds.rtps.message:fragnum-set-member-p base numbits bitmap 3))
                       (not (dds.rtps.message:fragnum-set-member-p base numbits bitmap 5)))
                  "reader NACK_FRAG names exactly the dropped fragments {2,4}")
          (let ((resends (dds.rtps.reliable:writer-on-nack-frag writer sn base numbits bitmap)))
            (%check :lossy-resend-set (equal '(2 4) (mapcar #'first resends))
                    "writer resends exactly fragments 2 and 4, nothing else")
            (let ((done nil))
              (dolist (desc resends) (setf done (deliver desc)))
              (%check :lossy-complete (and done (equalp done orig))
                      "sample completes byte-exact after the NACK_FRAG resend")))))))
  t)

;;; NACK_FRAG round-trip (RTPS 2.5 §9.4.5.14): 28+4*M body, only E flag.

(defun* run-nack-frag-test ()
    (function () t)
  "Test: NACK_FRAG write/parse round-trip incl. FragmentNumberSet (RTPS 2.5 §9.4.5.14)."
  (let* ((buf (dds.core.buffer:make-octet-buffer 64))
         (c (dds.core.buffer:cursor buf :endianness :little))
         (rid #x107) (wid #x102) (sn 9) (count 4)
         (bitmap (make-array 1 :element-type '(unsigned-byte 32) :initial-element 0)))
    ;; missing fragments {2,4}: base 2, numbits 3, deltas 0 and 2
    (dds.rtps.message:fragnum-set-bit bitmap 0)
    (dds.rtps.message:fragnum-set-bit bitmap 2)
    (dds.rtps.message:write-nack-frag c rid wid sn 2 3 bitmap count)
    (dds.core.buffer:cursor-reset c)
    (multiple-value-bind (id flags octets le) (dds.rtps.message:parse-submessage-header c)
      (declare (ignore le))
      (%check :nf-kind (= id dds.rtps.message:+submsg-nack-frag+) "NACK_FRAG kind")
      (%check :nf-octets (= octets 32) "NACK_FRAG body length 28+4*1=32")
      (multiple-value-bind (r w s base numbits bm cnt) (dds.rtps.message:parse-nack-frag-body c flags)
        (declare (ignore octets))
        (%check :nf-fields (and (= r rid) (= w wid) (= s sn) (= cnt count)) "NACK_FRAG scalar fields")
        (%check :nf-set
                (and (dds.rtps.message:fragnum-set-member-p base numbits bm 2)
                     (not (dds.rtps.message:fragnum-set-member-p base numbits bm 3))
                     (dds.rtps.message:fragnum-set-member-p base numbits bm 4))
                "NACK_FRAG fragment set: 2 and 4 missing, 3 not"))))
  (let* ((buf (dds.core.buffer:make-octet-buffer 8))
         (c (dds.core.buffer:cursor buf :endianness :little)))
    (%check :nf-short (null (dds.rtps.message:parse-nack-frag-body c 0))
            "a sub-16-octet NACK_FRAG body rejects"))
  t)

;;; PID_LIVELINESS (RTPS 2.5 Table 9.18 §9.6.2.2: PID_LIVELINESS = 0x001b ->
;;; LivelinessQosPolicy {kind; Duration_t lease_duration}; DDS 1.4 DCPS PSM
;;; LivelinessQosPolicyKind {AUTOMATIC=0, MANUAL_BY_PARTICIPANT=1, MANUAL_BY_TOPIC=2},
;;; Duration_t {long sec; unsigned long nanosec}). Vectors pinned from the spec + a
;;; live Fast DDS oracle, never memory.

(defun* %subseq-present-p (vec sub end)
    (function ((simple-array (unsigned-byte 8) (*)) list (integer 0)) t)
  "T if the octet list SUB appears as a contiguous subsequence of VEC[0,END) (test diagnostic)."
  (let ((s (make-array (length sub) :element-type '(unsigned-byte 8) :initial-contents sub)))
    (and (search s vec :end2 end) t)))

(defun* run-pid-liveliness-test ()
    (function () t)
  "SEDP advertises PID_LIVELINESS (RTPS 2.5 Table 9.18 §9.6.2.2 / DDS 1.4 PSM): a writer
   qos {:manual-by-participant, lease {5,0}} serializes byte-exact to
   1b 00 0c 00 / 01 00 00 00 / 05 00 00 00 / 00 00 00 00 (kind LE then Duration_t LE).
   The Fast DDS oracle AUTOMATIC+1s parameter parses to {:automatic, lease {1,0}}.
   A PID_LIVELINESS whose length /= 12 is ignored, never read OOB (NFR-SEC-POSTURE)."
  ;; serialize: writer liveliness MANUAL_BY_PARTICIPANT(1) + lease {5,0} -> 16 octets present.
  (let* ((ep (dds.rtps.discovery:make-endpoint-data
              :topic-name "Square" :type-name "ShapeType"
              :qos (dds.qos:make-qos :reliability :reliable
                                     :liveliness :manual-by-participant
                                     :liveliness-lease (dds.qos:make-qos-duration 5 0))))
         (buf (dds.core.buffer:make-octet-buffer 512))
         (c (dds.core.buffer:cursor buf :endianness :little)))
    (let ((end (dds.rtps.discovery:serialize-endpoint-data c ep)))
      (%check :liv-emit
              (%subseq-present-p (dds.core.buffer:octet-buffer-vec buf)
                                 '(#x1b #x00 #x0c #x00  #x01 #x00 #x00 #x00
                                   #x05 #x00 #x00 #x00  #x00 #x00 #x00 #x00)
                                 end)
              "serialized SEDP contains PID_LIVELINESS {MANUAL_BY_PARTICIPANT, {5,0}}")))
  ;; parse: a Fast DDS oracle AUTOMATIC(0)+1s parameter inside a minimal valid endpoint-data.
  (let* ((buf (dds.core.buffer:make-octet-buffer 512))
         (out (dds.core.buffer:cursor buf :endianness :little))
         (guid (make-array 16 :element-type '(unsigned-byte 8) :initial-element 7))
         (topic (octets #x07 #x00 #x00 #x00 #x53 #x71 #x72 #x00)) ; CDR string "Sqr"
         (liv (octets #x00 #x00 #x00 #x00  #x01 #x00 #x00 #x00  #x00 #x00 #x00 #x00)))
    (dds.rtps.message:write-parameter out dds.rtps.message:+pid-endpoint-guid+ guid 0 16)
    (dds.rtps.message:write-parameter out dds.rtps.message:+pid-topic-name+ topic 0 8)
    (dds.rtps.message:write-parameter out dds.rtps.message:+pid-type-name+ topic 0 8)
    (dds.rtps.message:write-parameter out dds.rtps.message:+pid-liveliness+ liv 0 12)
    (dds.rtps.message:write-parameter-sentinel out)
    (let ((back (dds.rtps.discovery:parse-endpoint-data
                 (dds.core.buffer:cursor buf :endianness :little) :writer)))
      (%check :liv-parse back "parse-endpoint-data with PID_LIVELINESS returned NIL")
      (%check :liv-kind (eq :automatic (dds.qos:qos-liveliness (dds.rtps.discovery:endpoint-data-qos back)))
              "Fast DDS oracle liveliness kind parses AUTOMATIC")
      (let ((lease (dds.qos:qos-liveliness-lease (dds.rtps.discovery:endpoint-data-qos back))))
        (%check :liv-lease (and (= 1 (dds.qos:qos-duration-sec lease))
                                (= 0 (dds.qos:qos-duration-nanosec lease)))
                "Fast DDS oracle lease parses {1,0}"))))
  ;; bounds: a PID_LIVELINESS with length /= 12 is ignored, never OOB; defaults survive.
  (let* ((buf (dds.core.buffer:make-octet-buffer 512))
         (out (dds.core.buffer:cursor buf :endianness :little))
         (guid (make-array 16 :element-type '(unsigned-byte 8) :initial-element 7))
         (topic (octets #x07 #x00 #x00 #x00 #x53 #x71 #x72 #x00))
         (short (octets #x02 #x00 #x00 #x00))) ; len 4, not 12
    (dds.rtps.message:write-parameter out dds.rtps.message:+pid-endpoint-guid+ guid 0 16)
    (dds.rtps.message:write-parameter out dds.rtps.message:+pid-topic-name+ topic 0 8)
    (dds.rtps.message:write-parameter out dds.rtps.message:+pid-type-name+ topic 0 8)
    (dds.rtps.message:write-parameter out dds.rtps.message:+pid-liveliness+ short 0 4)
    (dds.rtps.message:write-parameter-sentinel out)
    (let ((back (dds.rtps.discovery:parse-endpoint-data
                 (dds.core.buffer:cursor buf :endianness :little) :writer)))
      (%check :liv-short back "short-length PID_LIVELINESS must not crash the parse")
      (%check :liv-short-default
              (eq :automatic (dds.qos:qos-liveliness (dds.rtps.discovery:endpoint-data-qos back)))
              "short-length PID_LIVELINESS is ignored, liveliness keeps its default")))
  ;; wire-fraction: an INFINITE lease emits the RTPS Duration_t infinite fraction
  ;; 0xffffffff, NOT the DCPS nanosec sentinel 0x7fffffff (DDSI-RTPS 2.5 §9.3.2). The
  ;; DCPS sentinel on the wire reads as a finite ~0.5 s lease on a conformant peer and
  ;; breaks the RxO liveliness match (Fast DDS forward-leg regression, ADR/provenance).
  (let* ((ep (dds.rtps.discovery:make-endpoint-data
              :topic-name "Square" :type-name "ShapeType"
              :qos (dds.qos:make-qos :reliability :reliable :liveliness :automatic
                                     :liveliness-lease dds.qos:+duration-infinite+)))
         (buf (dds.core.buffer:make-octet-buffer 512))
         (c (dds.core.buffer:cursor buf :endianness :little)))
    (let ((end (dds.rtps.discovery:serialize-endpoint-data c ep)))
      (%check :liv-infinite-wire
              (%subseq-present-p (dds.core.buffer:octet-buffer-vec buf)
                                 '(#x1b #x00 #x0c #x00  #x00 #x00 #x00 #x00
                                   #xff #xff #xff #x7f  #xff #xff #xff #xff)
                                 end)
              "INFINITE lease emits PID_LIVELINESS {AUTOMATIC, sec 0x7fffffff, fraction 0xffffffff}"))
    ;; roundtrip: the wire fraction 0xffffffff parses back to the DCPS nanosec 0x7fffffff.
    (let ((back (dds.rtps.discovery:parse-endpoint-data
                 (dds.core.buffer:cursor buf :endianness :little) :writer)))
      (let ((lease (dds.qos:qos-liveliness-lease (dds.rtps.discovery:endpoint-data-qos back))))
        (%check :liv-infinite-roundtrip
                (and (= #x7fffffff (dds.qos:qos-duration-sec lease))
                     (= #x7fffffff (dds.qos:qos-duration-nanosec lease)))
                "INFINITE lease roundtrips back to DCPS {0x7fffffff, 0x7fffffff}"))))
  t)

(defun* run-ownership-codec-test ()
    (function () t)
  "SEDP advertises OWNERSHIP (RTPS 2.5 Table 9.18 §9.6.2.2): PID_OWNERSHIP (0x001f, len 4,
   OwnershipQosPolicyKind u32 LE: SHARED=0, EXCLUSIVE=1) and, for a WRITER only,
   PID_OWNERSHIP_STRENGTH (0x0006, len 4, long value u32 LE) — strength is in DataWriterQos,
   NOT DataReaderQos (DDS 1.4 dds_rtf2_dcps.idl §2.2.3.9/.10). The oracle is eProsima Fast DDS
   3.6.1, interop/fastdds/captures/ownership-sedp-lo0.pcap frame 64: a writer {EXCLUSIVE,
   strength 17} serializes byte-exact to 1f 00 04 00 / 01 00 00 00 / 06 00 04 00 / 11 00 00 00.
   A :shared writer emits PID_OWNERSHIP kind 0; a READER emits PID_OWNERSHIP but no STRENGTH;
   a length /= 4 is ignored, never read OOB, and never REJECTs the kind (NFR-SEC-POSTURE / FR-QOS-2)."
  ;; serialize: an EXCLUSIVE writer with strength 17 -> the 16 exact oracle octets present.
  (let* ((ep (dds.rtps.discovery:make-endpoint-data
              :role :writer :topic-name "Square" :type-name "ShapeType"
              :qos (dds.qos:make-writer-qos :ownership :exclusive :ownership-strength 17)))
         (buf (dds.core.buffer:make-octet-buffer 512))
         (c (dds.core.buffer:cursor buf :endianness :little)))
    (let ((end (dds.rtps.discovery:serialize-endpoint-data c ep)))
      (%check :own-emit-kind
              (%subseq-present-p (dds.core.buffer:octet-buffer-vec buf)
                                 '(#x1f #x00 #x04 #x00  #x01 #x00 #x00 #x00) end)
              "writer SEDP contains PID_OWNERSHIP {EXCLUSIVE}")
      (%check :own-emit-strength
              (%subseq-present-p (dds.core.buffer:octet-buffer-vec buf)
                                 '(#x06 #x00 #x04 #x00  #x11 #x00 #x00 #x00) end)
              "writer SEDP contains PID_OWNERSHIP_STRENGTH {17}")))
  ;; serialize: a SHARED writer -> PID_OWNERSHIP kind 0.
  (let* ((ep (dds.rtps.discovery:make-endpoint-data
              :role :writer :topic-name "Square" :type-name "ShapeType"
              :qos (dds.qos:make-writer-qos :ownership :shared)))
         (buf (dds.core.buffer:make-octet-buffer 512))
         (c (dds.core.buffer:cursor buf :endianness :little)))
    (let ((end (dds.rtps.discovery:serialize-endpoint-data c ep)))
      (%check :own-emit-shared
              (%subseq-present-p (dds.core.buffer:octet-buffer-vec buf)
                                 '(#x1f #x00 #x04 #x00  #x00 #x00 #x00 #x00) end)
              "shared writer SEDP contains PID_OWNERSHIP {SHARED}")))
  ;; serialize: a READER emits PID_OWNERSHIP but NEVER PID_OWNERSHIP_STRENGTH (writer-only).
  (let* ((ep (dds.rtps.discovery:make-endpoint-data
              :role :reader :topic-name "Square" :type-name "ShapeType"
              :qos (dds.qos:make-reader-qos :ownership :exclusive :ownership-strength 17)))
         (buf (dds.core.buffer:make-octet-buffer 512))
         (c (dds.core.buffer:cursor buf :endianness :little)))
    (let ((end (dds.rtps.discovery:serialize-endpoint-data c ep)))
      (%check :own-reader-kind
              (%subseq-present-p (dds.core.buffer:octet-buffer-vec buf)
                                 '(#x1f #x00 #x04 #x00  #x01 #x00 #x00 #x00) end)
              "reader SEDP contains PID_OWNERSHIP {EXCLUSIVE}")
      (%check :own-reader-no-strength
              (not (%subseq-present-p (dds.core.buffer:octet-buffer-vec buf)
                                      '(#x06 #x00 #x04 #x00) end))
              "reader SEDP must NOT contain PID_OWNERSHIP_STRENGTH (writer-only, DataWriterQos)")))
  ;; parse: the EXACT 16 oracle octets parse to qos :exclusive + strength 17.
  (let* ((buf (dds.core.buffer:make-octet-buffer 512))
         (out (dds.core.buffer:cursor buf :endianness :little))
         (guid (make-array 16 :element-type '(unsigned-byte 8) :initial-element 7))
         (topic (octets #x07 #x00 #x00 #x00 #x53 #x71 #x72 #x00)) ; CDR string "Sqr"
         (own (octets #x01 #x00 #x00 #x00))                       ; EXCLUSIVE
         (strength (octets #x11 #x00 #x00 #x00)))                 ; 17
    (dds.rtps.message:write-parameter out dds.rtps.message:+pid-endpoint-guid+ guid 0 16)
    (dds.rtps.message:write-parameter out dds.rtps.message:+pid-topic-name+ topic 0 8)
    (dds.rtps.message:write-parameter out dds.rtps.message:+pid-type-name+ topic 0 8)
    (dds.rtps.message:write-parameter out dds.rtps.message:+pid-ownership+ own 0 4)
    (dds.rtps.message:write-parameter out dds.rtps.message:+pid-ownership-strength+ strength 0 4)
    (dds.rtps.message:write-parameter-sentinel out)
    (let ((back (dds.rtps.discovery:parse-endpoint-data
                 (dds.core.buffer:cursor buf :endianness :little) :writer)))
      (%check :own-parse back "parse-endpoint-data with PID_OWNERSHIP returned NIL")
      (%check :own-parse-kind
              (eq :exclusive (dds.qos:qos-ownership (dds.rtps.discovery:endpoint-data-qos back)))
              "oracle PID_OWNERSHIP parses :exclusive")
      (%check :own-parse-strength
              (= 17 (dds.qos:qos-ownership-strength (dds.rtps.discovery:endpoint-data-qos back)))
              "oracle PID_OWNERSHIP_STRENGTH parses 17")))
  ;; bounds: a PID_OWNERSHIP whose declared length /= 4 (here 8) is ignored, never OOB; the
  ;; kind keeps :shared and the parse does not REJECT (NFR-SEC-POSTURE / FR-QOS-2).
  (let* ((buf (dds.core.buffer:make-octet-buffer 512))
         (out (dds.core.buffer:cursor buf :endianness :little))
         (guid (make-array 16 :element-type '(unsigned-byte 8) :initial-element 7))
         (topic (octets #x07 #x00 #x00 #x00 #x53 #x71 #x72 #x00))
         (wrong (octets #x01 #x00 #x00 #x00  #xff #xff #xff #xff)))   ; len 8, not 4
    (dds.rtps.message:write-parameter out dds.rtps.message:+pid-endpoint-guid+ guid 0 16)
    (dds.rtps.message:write-parameter out dds.rtps.message:+pid-topic-name+ topic 0 8)
    (dds.rtps.message:write-parameter out dds.rtps.message:+pid-type-name+ topic 0 8)
    (dds.rtps.message:write-parameter out dds.rtps.message:+pid-ownership+ wrong 0 8)
    (dds.rtps.message:write-parameter-sentinel out)
    (let ((back (dds.rtps.discovery:parse-endpoint-data
                 (dds.core.buffer:cursor buf :endianness :little) :reader)))
      (%check :own-short back "wrong-length PID_OWNERSHIP must not crash the parse")
      (%check :own-short-default
              (eq :shared (dds.qos:qos-ownership (dds.rtps.discovery:endpoint-data-qos back)))
              "wrong-length PID_OWNERSHIP is ignored, ownership keeps its default :shared")))
  t)

;;; Instance-lifecycle wire codec (RTPS 2.5 §9.6.4.9): a dispose/unregister rides a DATA
;;; submessage with flags E+Q only (no serialized payload); the instance is named by
;;; PID_KEY_HASH and the lifecycle transition by PID_STATUS_INFO (StatusInfo_t octet[4],
;;; last octet flags F|U|D). The oracle is eProsima Fast DDS 3.6.1 (the conformant peer),
;;; interop/fastdds/captures/instance-dispose-lo0.pcap frame 91 (dispose) / 113 (unregister-
;;; of-already-disposed). Vectors locked from those captures, never memory.

(defun* %dispose-key-hash ()
    (function () (simple-array (unsigned-byte 8) (*)))
  "The 16-octet instance KeyHash from the Fast DDS oracle dispose DATA (frame 91)."
  (octets #xca #xc2 #x17 #xc3 #x18 #x36 #x3f #x8e #xf1 #x16 #x0e #xee #xde #xf9 #xe8 #x86))

(defun* run-status-info-codec-test ()
    (function () t)
  "Test: PID_STATUS_INFO + PID_KEY_HASH inlineQos codec for instance dispose/unregister,
   byte-exact against the Fast DDS oracle (RTPS 2.5 §9.6.4.9). Builds the ParameterList,
   asserts the bytes, parses it back, derives the change-kind, byte-validates the exact
   oracle vectors, and exercises the bounds/over-long path (NFR-SEC-POSTURE)."
  (let* ((kh (%dispose-key-hash))
         (buf (dds.core.buffer:make-octet-buffer 256))
         (c (dds.core.buffer:cursor buf :endianness :little)))
    ;; emit the dispose inlineQos: PID_KEY_HASH(16) + PID_STATUS_INFO(4, Disposed) + SENTINEL
    (let ((plen (dds.rtps.message:write-status-info-inline-qos
                 c kh dds.rtps.message:+statusinfo-disposed+)))
      (%check :si-dispose-bytes
              (equal '(#x70 #x00 #x10 #x00  #xca #xc2 #x17 #xc3 #x18 #x36 #x3f #x8e
                       #xf1 #x16 #x0e #xee #xde #xf9 #xe8 #x86
                       #x71 #x00 #x04 #x00  #x00 #x00 #x00 #x01  #x01 #x00 #x00 #x00)
                     (%first-bytes buf plen))
              "dispose inlineQos ParameterList bytes (key-hash + StatusInfo Disposed)"))
    ;; parse it back -> key-hash + StatusInfo flags (Disposed)
    (let ((pc (dds.core.buffer:cursor buf :endianness :little)))
      (multiple-value-bind (gkh flags)
          (dds.rtps.message:parse-inline-qos-key-status
           pc (dds.core.buffer:octet-buffer-capacity buf))
        (%check :si-dispose-parse
                (and (equalp kh gkh) (= flags dds.rtps.message:+statusinfo-disposed+))
                "parse dispose inlineQos -> key-hash + Disposed")
        (%check :si-dispose-kind
                (eq :dispose (dds.rtps.message:status-info->kind flags))
                "Disposed flag derives change-kind :dispose")))
    ;; unregister (StatusInfo 00 00 00 02)
    (let* ((buf2 (dds.core.buffer:make-octet-buffer 256))
           (c2 (dds.core.buffer:cursor buf2 :endianness :little)))
      (dds.rtps.message:write-status-info-inline-qos
       c2 kh dds.rtps.message:+statusinfo-unregistered+)
      (let ((pc (dds.core.buffer:cursor buf2 :endianness :little)))
        (multiple-value-bind (gkh flags)
            (dds.rtps.message:parse-inline-qos-key-status
             pc (dds.core.buffer:octet-buffer-capacity buf2))
          (%check :si-unreg-parse
                  (and (equalp kh gkh) (= flags dds.rtps.message:+statusinfo-unregistered+))
                  "parse unregister inlineQos -> key-hash + Unregistered")
          (%check :si-unreg-kind
                  (eq :unregister (dds.rtps.message:status-info->kind flags))
                  "Unregistered flag derives change-kind :unregister"))))
    ;; the byte-exact oracle vector (Fast DDS frame 91): the exact 32-octet inlineQos
    ;; ParameterList off the wire must parse to :dispose + that key-hash (S0.2 interop).
    (let* ((oracle (octets #x70 #x00 #x10 #x00  #xca #xc2 #x17 #xc3 #x18 #x36 #x3f #x8e
                           #xf1 #x16 #x0e #xee #xde #xf9 #xe8 #x86
                           #x71 #x00 #x04 #x00  #x00 #x00 #x00 #x01  #x01 #x00 #x00 #x00))
           (ob (dds.core.buffer:make-octet-buffer 64))
           (oc (dds.core.buffer:cursor ob :endianness :little)))
      (dds.core.buffer:put-octets oc oracle 0 (length oracle))
      (let ((pc (dds.core.buffer:cursor ob :endianness :little)))
        (multiple-value-bind (gkh flags)
            (dds.rtps.message:parse-inline-qos-key-status pc (length oracle))
          (%check :si-oracle
                  (and (equalp (%dispose-key-hash) gkh)
                       (eq :dispose (dds.rtps.message:status-info->kind flags)))
                  "Fast DDS oracle dispose inlineQos parses byte-exact -> :dispose + key-hash"))))
    ;; the unregister-of-already-disposed oracle vector (frame 113): StatusInfo D|U = 0x03;
    ;; the Unregistered bit dominates the derivation -> :unregister.
    (let* ((oracle3 (octets #x70 #x00 #x10 #x00  #xca #xc2 #x17 #xc3 #x18 #x36 #x3f #x8e
                            #xf1 #x16 #x0e #xee #xde #xf9 #xe8 #x86
                            #x71 #x00 #x04 #x00  #x00 #x00 #x00 #x03  #x01 #x00 #x00 #x00))
           (ob (dds.core.buffer:make-octet-buffer 64))
           (oc (dds.core.buffer:cursor ob :endianness :little)))
      (dds.core.buffer:put-octets oc oracle3 0 (length oracle3))
      (let ((pc (dds.core.buffer:cursor ob :endianness :little)))
        (multiple-value-bind (gkh flags)
            (dds.rtps.message:parse-inline-qos-key-status pc (length oracle3))
          (declare (ignore gkh))
          (%check :si-oracle3
                  (and (= flags 3) (eq :unregister (dds.rtps.message:status-info->kind flags)))
                  "Fast DDS unregister-of-disposed (StatusInfo 0x03) derives :unregister"))))
    ;; bounds: an over-long PID_STATUS_INFO length must be rejected, never read OOB.
    (let* ((bad (octets #x71 #x00 #xff #x00  #x00 #x00 #x00 #x01))
           (ob (dds.core.buffer:make-octet-buffer 64))
           (oc (dds.core.buffer:cursor ob :endianness :little)))
      (dds.core.buffer:put-octets oc bad 0 (length bad))
      (let ((pc (dds.core.buffer:cursor ob :endianness :little)))
        (multiple-value-bind (gkh flags)
            (dds.rtps.message:parse-inline-qos-key-status pc (length bad))
          (%check :si-overlong
                  (and (null gkh) (zerop flags))
                  "over-long PID_STATUS_INFO -> NIL key-hash, no flags, no OOB")))))
  ;; the full dispose DATA submessage: flags E+Q, no payload, inlineQos = key-hash + status.
  (let* ((buf (dds.core.buffer:make-octet-buffer 256))
         (c (dds.core.buffer:cursor buf :endianness :little))
         (rid #x00000107) (wid #x00000102) (kh (%dispose-key-hash)))
    (dds.rtps.message:write-data-dispose
     c rid wid 6 kh dds.rtps.message:+statusinfo-disposed+)
    (dds.core.buffer:cursor-reset c)
    (multiple-value-bind (id flags octets le) (dds.rtps.message:parse-submessage-header c)
      (declare (ignore le))
      (%check :si-data-hdr
              (and (= id dds.rtps.message:+submsg-data+)
                   (= flags (logior dds.rtps.message:+flag-endianness+
                                    dds.rtps.message:+data-flag-inline-qos+)))
              "dispose DATA header: E+Q only, D clear, K clear")
      (multiple-value-bind (r w sn has off len keyp kind gkh sflags)
          (dds.rtps.message:parse-data-body c flags octets)
        (declare (ignore off len))
        (%check :si-data-parse
                (and (= r rid) (= w wid) (= sn 6) (not has) (not keyp)
                     (eq kind :dispose) (equalp kh gkh)
                     (= sflags dds.rtps.message:+statusinfo-disposed+))
                "dispose DATA parses: no payload, :dispose, key-hash + Disposed surfaced"))))
  t)

(defun* run-lifecycle-change-list-test ()
    (function () t)
  "Test (instance-lifecycle S1, writer side): writer-lifecycle-change adds a no-payload
   dispose/unregister CacheChange that flows through the kind-aware send list. Asserts: (1) the
   change derives KIND from StatusInfo and carries the key-hash + status-info, no payload, on a
   real SN; (2) writer-unsent-list returns the CacheChange (not a payload cell) and advances the
   unsent watermark EXACTLY ONCE (send-once, RTPS 2.5 §8.4.2.2); (3) writer-on-acknack repairs the
   dispose by SN, returning the same CacheChange; (4) re-emitting the dispose DATA from the
   returned change is byte-exact vs the S0 codec (no payload, :dispose, key-hash + Disposed)."
  (let* ((w (dds.rtps.reliable:make-rtps-writer
             :hc (dds.rtps.history:make-history-cache :keep-all 1 nil nil)))
         (rid 2)
         (kh (%dispose-key-hash))
         (data-pl (octets 1 2 3 4)))
    ;; SN 1 = ALIVE data, SN 2 = dispose
    (dds.rtps.reliable:writer-write w data-pl)
    (let ((dsn (dds.rtps.reliable:writer-lifecycle-change
                w kh dds.rtps.message:+statusinfo-disposed+)))
      (%check :lc-sn (= dsn 2) "lifecycle change occupies the next real SN")
      ;; (1)+(2): unsent-list returns CacheChanges; the dispose is :dispose with key-hash/status, no payload
      (let ((unsent (dds.rtps.reliable:writer-unsent-list w rid)))
        (%check :lc-unsent-count (= (length unsent) 2) "both changes pushed once")
        (let ((dc (second unsent)))
          (%check :lc-kind (eq (dds.rtps.history:cache-change-kind dc) :dispose)
                  "dispose change KIND derived from StatusInfo")
          (%check :lc-keyhash (equalp (dds.rtps.history:cache-change-instance-key-hash dc) kh)
                  "dispose change carries the 16-octet key-hash")
          (%check :lc-status (= (dds.rtps.history:cache-change-status-info dc)
                                dds.rtps.message:+statusinfo-disposed+)
                  "dispose change carries StatusInfo Disposed")
          (%check :lc-nopayload (null (dds.rtps.history:cache-change-serialized-payload dc))
                  "dispose change carries NO serializedPayload"))
        ;; send-once: a second unsent-list is empty (watermark advanced past SN 2)
        (%check :lc-sendonce (null (dds.rtps.reliable:writer-unsent-list w rid))
                "unsent watermark advanced once: nothing left to push"))
      ;; (3): ACKNACK NACKing SN 2 repairs the dispose, returning the same CacheChange
      (let ((bm (make-array 1 :element-type '(unsigned-byte 32) :initial-element 0)))
        (dds.rtps.message:seqnum-set-bit bm 0)             ; base 2, delta 0 = SN 2
        (multiple-value-bind (resends gaps)
            (dds.rtps.reliable:writer-on-acknack w rid 2 1 bm)
          (declare (ignore gaps))
          (%check :lc-repair-count (= (length resends) 1) "ACKNACK repairs exactly SN 2")
          (let ((rc (first resends)))
            (%check :lc-repair-kind (eq (dds.rtps.history:cache-change-kind rc) :dispose)
                    "repaired change is the :dispose CacheChange")
            ;; (4): re-emit the dispose DATA from the repaired change -> byte-exact S0 form
            (let* ((buf (dds.core.buffer:make-octet-buffer 256))
                   (c (dds.core.buffer:cursor buf :endianness :little)))
              (dds.rtps.message:write-data-dispose
               c #x00000107 #x00000102 (dds.rtps.history:cache-change-sn rc)
               (dds.rtps.history:cache-change-instance-key-hash rc)
               (dds.rtps.history:cache-change-status-info rc))
              (dds.core.buffer:cursor-reset c)
              (multiple-value-bind (id flags octets le) (dds.rtps.message:parse-submessage-header c)
                (declare (ignore le))
                (%check :lc-emit-hdr
                        (and (= id dds.rtps.message:+submsg-data+)
                             (= flags (logior dds.rtps.message:+flag-endianness+
                                              dds.rtps.message:+data-flag-inline-qos+)))
                        "repaired dispose DATA header: E+Q only")
                (multiple-value-bind (r wq sn has off len keyp kind gkh sflags)
                    (dds.rtps.message:parse-data-body c flags octets)
                  (declare (ignore r wq off len))
                  (%check :lc-emit-body
                          (and (= sn 2) (not has) (not keyp) (eq kind :dispose)
                               (equalp kh gkh) (= sflags dds.rtps.message:+statusinfo-disposed+))
                          "repaired dispose DATA: no payload, :dispose, key-hash + Disposed")))))))))
  t)
