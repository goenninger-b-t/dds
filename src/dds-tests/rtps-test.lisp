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

;;; Per-instance KEEP_LAST eviction (DDS 1.4 §2.2.3.18: "keep the last depth values FOR EACH
;;; instance"). A keyed KEEP_LAST-N cache must retain the last N of EACH key, not a global last-N
;;; (which would starve a slow-writing key). The HistoryCache is constructed KEEP_LAST directly
;;; here; the engine writer still builds KEEP_ALL (a later WP-KEEPLAST task activates QoS), so this
;;; exercises the eviction machinery at the engine level (ADR 0019, Phase A).

(defun* %keeplast-handle (lastbyte)
    (function ((unsigned-byte 8)) (simple-array (unsigned-byte 8) (16)))
  "A 16-octet instance key hash distinguished by LASTBYTE — a per-instance handle for the
   per-instance KEEP_LAST tests (the shape DCPS computes per keyed sample; 0 = HANDLE_NIL)."
  (let ((h (make-array 16 :element-type '(unsigned-byte 8) :initial-element 0)))
    (setf (aref h 15) lastbyte)
    h))

(defun* run-hc-perinstance-keeplast-test ()
    (function () t)
  "Test: KEEP_LAST depth applies PER INSTANCE (DDS 1.4 §2.2.3.18). A keyed KEEP_LAST-2 cache fed 3
   changes for instance A and 3 for instance B retains exactly the last 2 of A AND the last 2 of B
   (4 total) — NOT a global last-2 (which would hold only B's last 2 and starve A)."
  (let ((hc (dds.rtps.history:make-history-cache :keep-last 2 nil nil))
        (a (%keeplast-handle 1))
        (b (%keeplast-handle 2)))
    (flet ((add (sn h)
             (dds.rtps.history:hc-add-change
              hc (dds.rtps.history:make-cache-change :sn sn :instance-key-hash h)))
           (have (sn) (dds.rtps.history:hc-get-change hc sn)))
      ;; interleaved writes: A@1 B@2 A@3 B@4 A@5 B@6 (A = odd SNs, B = even SNs)
      (add 1 a) (add 2 b) (add 3 a) (add 4 b) (add 5 a) (add 6 b)
      (%check :kl-pi-count (= 4 (dds.rtps.history:hc-change-count hc))
              "per-instance KEEP_LAST-2 over 2 instances holds 4 changes (2 per instance)")
      (%check :kl-pi-a-kept (and (have 3) (have 5)) "instance A keeps its last 2 (SN 3,5)")
      (%check :kl-pi-a-evicted (null (have 1)) "instance A's oldest (SN 1) is evicted")
      (%check :kl-pi-b-kept (and (have 4) (have 6)) "instance B keeps its last 2 (SN 4,6)")
      (%check :kl-pi-b-evicted (null (have 2)) "instance B's oldest (SN 2) is evicted")
      (%check :kl-pi-not-global
              (and (have 3) (null (have 1)))
              "NOT a global last-2: A's SN3 survives though it is below B's retained SN4/6")))
  t)

(defun* run-hc-keeplast-unkeyed-test ()
    (function () t)
  "Test: unkeyed changes (instance-key-hash NIL or HANDLE_NIL) collapse to ONE instance bucket, so
   KEEP_LAST is the global last-depth (DDS 1.4 §2.2.3.18 degenerate single-instance case). A NIL
   keyhash and the all-zero HANDLE_NIL must share the SAME bucket."
  (let ((handle-nil (%keeplast-handle 0)))           ; all-zero 16-octet HANDLE_NIL
    ;; (a) NIL keyhash: 4 adds to a KEEP_LAST-2 cache -> global last-2
    (let ((hc (dds.rtps.history:make-history-cache :keep-last 2 nil nil)))
      (dolist (sn '(1 2 3 4))
        (dds.rtps.history:hc-add-change hc (dds.rtps.history:make-cache-change :sn sn)))
      (%check :kl-unkeyed-count (= 2 (dds.rtps.history:hc-change-count hc))
              "NIL-keyhash KEEP_LAST-2 collapses to one instance -> global last-2")
      (%check :kl-unkeyed-kept (and (dds.rtps.history:hc-get-change hc 3)
                                    (dds.rtps.history:hc-get-change hc 4))
              "global last-2 (SN 3,4) retained")
      (%check :kl-unkeyed-evicted (and (null (dds.rtps.history:hc-get-change hc 1))
                                       (null (dds.rtps.history:hc-get-change hc 2)))
              "globally-oldest (SN 1,2) evicted"))
    ;; (b) NIL and HANDLE_NIL share ONE bucket: 2 NIL + 2 HANDLE_NIL, depth 2 -> 2 retained total
    (let ((hc (dds.rtps.history:make-history-cache :keep-last 2 nil nil)))
      (dds.rtps.history:hc-add-change hc (dds.rtps.history:make-cache-change :sn 1))
      (dds.rtps.history:hc-add-change hc (dds.rtps.history:make-cache-change :sn 2 :instance-key-hash handle-nil))
      (dds.rtps.history:hc-add-change hc (dds.rtps.history:make-cache-change :sn 3))
      (dds.rtps.history:hc-add-change hc (dds.rtps.history:make-cache-change :sn 4 :instance-key-hash handle-nil))
      (%check :kl-nil-handlenil-one-bucket (= 2 (dds.rtps.history:hc-change-count hc))
              "NIL and all-zero HANDLE_NIL share one bucket -> depth-2 keeps only 2 total")
      (%check :kl-nil-handlenil-kept (and (dds.rtps.history:hc-get-change hc 3)
                                          (dds.rtps.history:hc-get-change hc 4))
              "the last 2 across the shared bucket (SN 3,4) retained")))
  t)

(defun* run-hc-remove-change-consistency-test ()
    (function () t)
  "Test: a removal updates BOTH the change table AND the per-instance index — no orphaned SN is left
   in an instance bucket, the count decrements, and re-adding the same instance works (ADR 0019: a
   single removal path so changes + instances never drift)."
  (let ((hc (dds.rtps.history:make-history-cache :keep-all 1 nil nil))
        (a (%keeplast-handle 1)))
    (flet ((add (sn h)
             (dds.rtps.history:hc-add-change
              hc (dds.rtps.history:make-cache-change :sn sn :instance-key-hash h))))
      (add 10 a) (add 11 a) (add 12 a)
      (%check :rmc-before (= 3 (dds.rtps.history:hc-change-count hc)) "3 changes for instance A added")
      ;; remove an arbitrary (interior) SN
      (%check :rmc-removed (dds.rtps.history:hc-remove-change hc 11) "hc-remove-change reports SN 11 present")
      (%check :rmc-count (= 2 (dds.rtps.history:hc-change-count hc)) "count decremented to 2")
      (%check :rmc-gone (null (dds.rtps.history:hc-get-change hc 11)) "SN 11 gone from the change table")
      (%check :rmc-others (and (dds.rtps.history:hc-get-change hc 10)
                               (dds.rtps.history:hc-get-change hc 12))
              "SN 10 and 12 untouched")
      ;; the index has no orphaned SN 11: switch this cache to KEEP_LAST-1 semantics by re-adding
      ;; into A and confirming eviction sees the true bucket (the removed SN must not count toward depth)
      (let ((kl (dds.rtps.history:make-history-cache :keep-last 1 nil nil)))
        (dds.rtps.history:hc-add-change kl (dds.rtps.history:make-cache-change :sn 20 :instance-key-hash a))
        (dds.rtps.history:hc-remove-change kl 20)             ; index for A must now be empty, not orphaned
        (%check :rmc-empty-after (zerop (dds.rtps.history:hc-change-count kl)) "KEEP_LAST cache empty after removing its only change")
        (dds.rtps.history:hc-add-change kl (dds.rtps.history:make-cache-change :sn 21 :instance-key-hash a))
        (dds.rtps.history:hc-add-change kl (dds.rtps.history:make-cache-change :sn 22 :instance-key-hash a))
        (%check :rmc-readd-evicts (and (= 1 (dds.rtps.history:hc-change-count kl))
                                       (dds.rtps.history:hc-get-change kl 22)
                                       (null (dds.rtps.history:hc-get-change kl 21)))
                "re-adding into A after a clean remove evicts correctly (no orphaned SN inflated the bucket)"))))
  t)

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

;;; T5a-pre release-safety: cache-change SEND-REFCOUNT acquire/release across the capture/emit sites.
;;; A captured (in-flight or deferred) send holds the change NON-releasable; the send's completion
;;; (copy-into-datagram, then release) makes it releasable again. Behaviorally neutral today (the GC pins
;;; the payload); the gate (cache-change-releasable-p) is what T5a's eviction consults before recycling a
;;; POOLED payload buffer. Value-level (no sockets) so it is deterministic + identical on both impls.

(defun* run-cache-change-send-refcount-test ()
    (function () t)
  "Test (operating contract §4 release-safety): cache-change SEND-REFCOUNT acquire/release — a change is NOT
   releasable while a send referencing it is pending/in-flight and BECOMES releasable after the send completes.
   Part A synchronous push capture (writer-capture-unsent + writer-release-change-refs); Part B a DEFERRED
   (paced/async) snapshot that HOLDS the ref across emit steps until the plan drains; Part C the multi-reader
   eviction-vs-retransmit interleaving — a change EVICTED while reader B's NACK-retransmit still holds it stays
   NON-releasable (so T5a defers its pooled-buffer release) until the in-flight send drops the ref."
  ;; -- Part A: synchronous push capture holds the ref; release frees it; double-release floors at 0 --
  (let* ((writer (dds.rtps.reliable:make-rtps-writer
                  :hc (dds.rtps.history:make-history-cache :keep-all 1 nil nil)))
         (rid 7))
    (dds.rtps.reliable:writer-write writer (octets 1 1 1 1))
    (dds.rtps.reliable:writer-write writer (octets 2 2 2 2))
    (let ((ch1 (dds.rtps.history:hc-get-change (dds.rtps.reliable:rtps-writer-hc writer) 1))
          (ch2 (dds.rtps.history:hc-get-change (dds.rtps.reliable:rtps-writer-hc writer) 2)))
      (%check :refc-fresh-releasable
              (and (dds.rtps.history:cache-change-releasable-p ch1)
                   (dds.rtps.history:cache-change-releasable-p ch2))
              "a freshly written change has SEND-REFCOUNT 0 (releasable)")
      (let ((captured (dds.rtps.reliable:writer-capture-unsent writer (list rid))))
        (%check :refc-captured-2 (= 2 (length captured)) "capture returns both unsent changes")
        (%check :refc-captured-held
                (and (not (dds.rtps.history:cache-change-releasable-p ch1))
                     (not (dds.rtps.history:cache-change-releasable-p ch2))
                     (= 1 (dds.rtps.history:cache-change-send-refcount ch1)))
                "a captured (in-flight) change is NOT releasable (refcount 1) — the eviction gate would defer here")
        (dds.rtps.reliable:writer-release-change-refs writer captured)
        (%check :refc-released
                (and (dds.rtps.history:cache-change-releasable-p ch1)
                     (dds.rtps.history:cache-change-releasable-p ch2))
                "after the send copied + released, the change is releasable again"))
      (dds.rtps.reliable:writer-release-change-ref writer ch1)   ; redundant release
      (%check :refc-double-release-floored
              (and (dds.rtps.history:cache-change-releasable-p ch1)
                   (zerop (dds.rtps.history:cache-change-send-refcount ch1)))
              "a redundant release floors at 0 (no underflow / wrap)")))
  ;; -- Part B: a DEFERRED (paced/async) snapshot holds the ref across every emit step until the plan drains --
  (let* ((writer (dds.rtps.reliable:make-rtps-writer
                  :hc (dds.rtps.history:make-history-cache :keep-all 1 nil nil)))
         (rid 9))
    (dotimes (i 3) (dds.rtps.reliable:writer-write writer (octets (1+ i) 0 0 0)))
    (let* ((captured (dds.rtps.reliable:writer-capture-unsent writer (list rid)))   ; snapshot acquires (= %node-datagram-plan)
           (steps (length captured)))
      (%check :refc-deferred-snapshot-held
              (every (lambda (c) (not (dds.rtps.history:cache-change-releasable-p c))) captured)
              "the deferred snapshot holds a send-ref on every captured change")
      (dotimes (s (max 0 (1- steps)))   ; step the plan one datagram at a time: the ref is HELD across every step
        (declare (ignorable s))
        (%check :refc-deferred-mid-held
                (every (lambda (c) (not (dds.rtps.history:cache-change-releasable-p c))) captured)
                "mid-drain: a captured change stays NON-releasable until the plan FULLY drains"))
      (dds.rtps.reliable:writer-release-change-refs writer captured)   ; drain complete (= %flow-step-advance)
      (%check :refc-deferred-drained
              (every #'dds.rtps.history:cache-change-releasable-p captured)
              "on plan drain, every captured change becomes releasable")))
  ;; -- Part C: multi-reader eviction-vs-retransmit — B's in-flight NACK-retransmit ref survives eviction --
  (let* ((writer (dds.rtps.reliable:make-rtps-writer
                  :hc (dds.rtps.history:make-history-cache :keep-all 4 nil nil)))
         (rkey-b 200)
         (nack (make-array 1 :element-type '(unsigned-byte 32) :initial-element 0)))
    (dds.rtps.reliable:writer-write writer (octets 1 1 1 1))
    (dds.rtps.reliable:writer-write writer (octets 2 2 2 2))
    (dds.rtps.message:seqnum-set-bit nack 0)   ; NACK SN 1 (bit 0 at base 1)
    (multiple-value-bind (resends gaps) (dds.rtps.reliable:writer-on-acknack writer rkey-b 1 1 nack t)
      (declare (ignore gaps))
      (%check :refc-nack-captured (= 1 (length resends)) "B's NACK of SN1 yields one (ref-held) resend")
      (let ((ch1 (first resends)))
        (%check :refc-nack-held (not (dds.rtps.history:cache-change-releasable-p ch1))
                "B's in-flight NACK-retransmit holds SN1 NON-releasable")
        ;; concurrently SN1 is EVICTED from the HC (a co-publishing thread's KEEP_LAST supersession / purge):
        ;; it is gone from the cache, but the refcount (the T5a pool-release gate) is still 1 -> NOT releasable,
        ;; so T5a DEFERS returning SN1's pooled buffer to the pool (no recycle while B's thunk has not copied it)
        (dds.rtps.history:hc-remove-change (dds.rtps.reliable:rtps-writer-hc writer) 1)
        (%check :refc-evicted-not-releasable
                (and (null (dds.rtps.history:hc-get-change (dds.rtps.reliable:rtps-writer-hc writer) 1))
                     (not (dds.rtps.history:cache-change-releasable-p ch1)))
                "a change EVICTED while a retransmit holds it is gone from the HC yet NON-releasable (release deferred)")
        (dds.rtps.reliable:writer-release-change-ref writer ch1)   ; B's retransmit copied + completed
        (%check :refc-evicted-then-released (dds.rtps.history:cache-change-releasable-p ch1)
                "once the in-flight retransmit drops its ref, the evicted change is releasable (pool-release fires)"))))
  t)

(defun* run-cache-change-recycle-test ()
    (function () t)
  "Test (TASK-3, ADR 0077): the cache-change STRUCT recycle rides the SAME send-refcount+evicted gate as the
   pooled-buffer release. An evicted, send-ref-FREE, non-ZC/pooled/pinned change is returned to the
   HistoryCache change-freelist and REUSED (eq) — fully reset — by the next write; but a change EVICTED while
   still send-referenced is NOT recycled until the last ref drops (else a retransmit would read a reused struct)."
  (let* ((writer (dds.rtps.reliable:make-rtps-writer
                  :hc (dds.rtps.history:make-history-cache :keep-all 8 nil nil)))
         (hc (dds.rtps.reliable:rtps-writer-hc writer))
         (rid 3))
    ;; -- reuse: an evicted, unreferenced change recycles and the next write reuses it (eq), fully reset --
    (dds.rtps.reliable:writer-lifecycle-change writer (make-array 16 :element-type '(unsigned-byte 8) :initial-element #xab) 2)   ; a :dispose change (status-info 2) so a stale-slot leak would show
    (let ((ch1 (dds.rtps.history:hc-get-change hc 1)))
      (dds.rtps.history:hc-remove-change hc 1)   ; evict, send-refcount 0 -> recycle NOW
      (%check :recy-freelisted
              (and (member ch1 (dds.rtps.history::history-cache-change-freelist hc)) t)
              "an evicted, send-ref-free change is on the change-freelist")
      (dds.rtps.reliable:writer-write writer (octets 2 2 2 2))   ; :data write should draw ch1 from the freelist
      (let ((ch2 (dds.rtps.history:hc-get-change hc 2)))
        (%check :recy-reused-eq (eq ch1 ch2) "the next write REUSES the recycled struct (eq), no fresh alloc")
        (%check :recy-reset
                (and (= 2 (dds.rtps.history:cache-change-sn ch2))
                     (eq :data (dds.rtps.history:cache-change-kind ch2))   ; was :dispose in its prior life
                     (zerop (dds.rtps.history:cache-change-status-info ch2))   ; was 2 in its prior life
                     (null (dds.rtps.history:cache-change-evicted ch2))
                     (zerop (dds.rtps.history:cache-change-send-refcount ch2)))
                "the reused struct is FULLY reset (SN 2, kind :data, status 0, evicted NIL, refcount 0)")
        ;; -- safety: a change EVICTED while send-referenced is NOT recycled until the ref drops --
        (let ((captured (dds.rtps.reliable:writer-capture-unsent writer (list rid))))
          (%check :recy-captured-held
                  (not (dds.rtps.history:cache-change-releasable-p ch2))
                  "capture holds a send-ref on the change (refcount 1)")
          (dds.rtps.history:hc-remove-change hc 2)   ; evict WHILE send-referenced
          (%check :recy-deferred-not-freelisted
                  (not (member ch2 (dds.rtps.history::history-cache-change-freelist hc)))
                  "a change evicted while send-referenced is NOT recycled (deferred, so a retransmit is safe)")
          (dds.rtps.reliable:writer-release-change-refs writer captured)   ; last ref drops -> recycle now
          (%check :recy-deferred-then-freelisted
                  (and (member ch2 (dds.rtps.history::history-cache-change-freelist hc)) t)
                  "on the last send-ref drop, the evicted change is finally recycled")))))
  t)

(defun* run-secured-encode-pool-balance-test ()
    (function () t)
  "Test (WP-DDS-SECURITY-ZEROALLOC-AEAD T5a): the encode payload pool + the refcount-gated DEFERRED pool-release.
   A writer whose HistoryCache carries a payload-pool: a pooled change holds its buffer while LIVE in the cache;
   on eviction (%hc-remove-change) the buffer returns to the pool IFF no send still references it (SEND-REFCOUNT 0),
   else the release is DEFERRED to the LAST send-ref drop. Asserts, across EVERY real send-path capture/release
   shape (sync push = capture-unsent/release-change-refs; deferred async drain = the same held across steps;
   ACKNACK retransmit = on-acknack acquire-refs/release-change-refs; NACK_FRAG retransmit = acquire-sample/
   release-change-ref), that after the send completes AND the change is evicted, the cache-change refcount is 0
   AND its pooled buffer has returned to the pool (pool-in-use back to baseline) — making the T5a-pre refcount
   load-bearing-and-proven. Value-level (no sockets / no OpenSSL — it tests the BUFFER LIFECYCLE, the codec is
   covered by the corpus + e2e), deterministic, identical on both impls. A recycle-while-referenced (corruption)
   shows as an early pool-in-use drop; a never-released buffer (leak) shows as pool-in-use not returning."
  (macrolet ((with-pooled-writer ((writer pool kind depth) &body body)
               `(let* ((arena (dds.core.arena:init-arena :bytes (* 2048 16)))
                       (,pool (dds.core.arena:make-buffer-pool arena 2048 8))
                       (,writer (dds.rtps.reliable:make-rtps-writer
                                 :hc (dds.rtps.history:make-history-cache ,kind ,depth nil nil))))
                  (setf (dds.rtps.history:history-cache-payload-pool (dds.rtps.reliable:rtps-writer-hc ,writer)) ,pool)
                  (flet ((pub (n)   ; mimic publish-sample: acquire a pooled buffer + writer-write it onto the change
                           (let ((buf (dds.rtps.reliable:writer-acquire-payload-buffer ,writer)))
                             (dds.rtps.reliable:writer-write ,writer (dds.core.buffer:octet-buffer-vec buf) nil nil buf n)
                             buf)))
                    (declare (ignorable #'pub))
                    (unwind-protect (progn ,@body) (dds.core.arena:teardown-arena arena))))))
    ;; -- Part A: a LIVE pooled change holds its buffer; a completed send does NOT release it; KEEP_LAST evict does --
    (with-pooled-writer (writer pool :keep-last 1)
      (%check :pool-a-baseline (zerop (dds.core.arena:pool-in-use pool)) "the pool starts empty")
      (pub 100)
      (%check :pool-a-live-held (= 1 (dds.core.arena:pool-in-use pool))
              "a LIVE (un-evicted) pooled change holds its buffer out of the pool")
      (let ((cap (dds.rtps.reliable:writer-capture-unsent writer (list 1))))   ; a sync push captures + releases
        (dds.rtps.reliable:writer-release-change-refs writer cap))
      (%check :pool-a-live-after-send (= 1 (dds.core.arena:pool-in-use pool))
              "a COMPLETED send on a still-LIVE change does NOT release its pooled buffer (only eviction does)")
      (pub 200)   ; KEEP_LAST depth 1: SN2 supersedes + evicts SN1 (refcount 0) -> SN1's buffer returns NOW
      (%check :pool-a-keeplast-evict (= 1 (dds.core.arena:pool-in-use pool))
              "KEEP_LAST supersession evicts the prior change and returns its buffer immediately (1 live held)"))
    ;; -- Part B: sync/async push — a change EVICTED while a send-ref is held DEFERS its release to the last drop --
    (with-pooled-writer (writer pool :keep-all 4)
      (pub 10) (pub 20)
      (%check :pool-b-two (= 2 (dds.core.arena:pool-in-use pool)) "two live pooled changes hold two buffers")
      (let ((cap (dds.rtps.reliable:writer-capture-unsent writer (list 1))))   ; snapshot acquires a ref on both
        (%check :pool-b-captured (= 2 (length cap)) "capture returns both unsent changes")
        (dds.rtps.history:hc-remove-change (dds.rtps.reliable:rtps-writer-hc writer) 1)   ; evict SN1 while its ref is held
        (%check :pool-b-deferred (= 2 (dds.core.arena:pool-in-use pool))
                "a change evicted while a send-ref is held does NOT recycle its buffer (release DEFERRED — no wire corruption)")
        (dds.rtps.reliable:writer-release-change-refs writer cap)   ; drain: last ref drop on the evicted SN1
        (%check :pool-b-deferred-fired (= 1 (dds.core.arena:pool-in-use pool))
                "on the LAST send-ref drop the EVICTED change's buffer returns; the still-LIVE change keeps its buffer")))
    ;; -- Part C: ACKNACK retransmit capture/release balances (evict-while-retransmitting -> deferred release) --
    (with-pooled-writer (writer pool :keep-all 4)
      (let ((rkey 5) (nack (make-array 1 :element-type '(unsigned-byte 32) :initial-element 0)))
        (pub 30)
        (dds.rtps.message:seqnum-set-bit nack 0)   ; NACK SN1
        (multiple-value-bind (resends gaps) (dds.rtps.reliable:writer-on-acknack writer rkey 1 1 nack t)
          (declare (ignore gaps))
          (%check :pool-c-acknack-cap (= 1 (length resends)) "ACKNACK of SN1 yields one ref-held resend")
          (dds.rtps.history:hc-remove-change (dds.rtps.reliable:rtps-writer-hc writer) 1)
          (%check :pool-c-acknack-deferred (= 1 (dds.core.arena:pool-in-use pool))
                  "SN1 evicted while the ACKNACK retransmit holds it -> buffer deferred")
          (dds.rtps.reliable:writer-release-change-refs writer resends)
          (%check :pool-c-acknack-released (zerop (dds.core.arena:pool-in-use pool))
                  "the ACKNACK retransmit drop releases the evicted buffer (refcount 0 + evicted -> pool-in-use baseline)"))))
    ;; -- Part D: NACK_FRAG retransmit capture/release balances (acquire-sample / release-change-ref) --
    (with-pooled-writer (writer pool :keep-all 4)
      (pub 40)
      (let ((ch (dds.rtps.reliable:writer-acquire-sample writer 1)))
        (%check :pool-d-nackfrag-cap (and ch (not (dds.rtps.history:cache-change-releasable-p ch)))
                "acquire-sample (NACK_FRAG path) holds SN1 non-releasable")
        (dds.rtps.history:hc-remove-change (dds.rtps.reliable:rtps-writer-hc writer) 1)
        (%check :pool-d-nackfrag-deferred (= 1 (dds.core.arena:pool-in-use pool))
                "SN1 evicted while the NACK_FRAG retransmit holds it -> buffer deferred")
        (dds.rtps.reliable:writer-release-change-ref writer ch)
        (%check :pool-d-nackfrag-released (zerop (dds.core.arena:pool-in-use pool))
                "the NACK_FRAG retransmit drop releases the evicted buffer (pool-in-use baseline)"))))
  t)

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

;;; Multi-writer SN-aliasing independence (RTPS 2.5 §8.3.5.4: a SequenceNumber is unique
;;; only within one writer GUID). ONE reader, TWO writer proxy keys (full 16-octet GUIDs
;;; that SHARE the user-writer EntityId tail 0x102 but differ in prefix); each delivers
;;; SN 1..5 with a DIFFERENT gap. The two writer-proxies' received sets / HEARTBEAT ranges
;;; / ACKNACKs MUST be independent — writer A's gap must not appear in writer B's ACKNACK.

(defun* %aliasing-writer-guid (lastbyte)
    (function ((unsigned-byte 8)) (simple-array (unsigned-byte 8) (16)))
  "A 16-octet remote writer GUID: a per-participant prefix varied by LASTBYTE, then the
   user-data writer EntityId 0x00000102 tail (RTPS 2.5 §9.3.1.2) — two such GUIDs ALIAS on
   the EntityId but differ on the GUID, the case §8.3.5.4 distinguishes."
  (let ((g (make-array 16 :element-type '(unsigned-byte 8) :initial-element #x55)))
    (setf (aref g 11) lastbyte
          (aref g 12) #x00 (aref g 13) #x00 (aref g 14) #x01 (aref g 15) #x02)
    g))

(defun* run-reliable-multiwriter-test ()
    (function () t)
  "Test: two writers sharing EntityId 0x102 keep INDEPENDENT reliable reader-proxy state
   when keyed by their full GUID (RTPS 2.5 §8.3.5.4). Writer A is missing SN 3; writer B is
   missing SN 4. Each writer's ACKNACK NACKs only its own gap, and writer A's HEARTBEAT range
   does not perturb writer B's."
  (let* ((reader (dds.rtps.reliable:make-rtps-reader))
         (key-a (%aliasing-writer-guid #x0a))
         (key-b (%aliasing-writer-guid #x0b))
         (pl (lambda (sn) (map '(simple-array (unsigned-byte 8) (*)) #'char-code (format nil "m~d" sn)))))
    ;; A receives 1,2,4,5 (gap at 3); B receives 1,2,3,5 (gap at 4).
    (dolist (sn '(1 2 4 5)) (dds.rtps.reliable:reader-on-data reader key-a sn (funcall pl sn)))
    (dolist (sn '(1 2 3 5)) (dds.rtps.reliable:reader-on-data reader key-b sn (funcall pl sn)))
    (dds.rtps.reliable:reader-on-heartbeat reader key-a 1 5)
    (dds.rtps.reliable:reader-on-heartbeat reader key-b 1 5)
    (multiple-value-bind (base-a numbits-a bitmap-a) (dds.rtps.reliable:reader-acknack reader key-a)
      (%check :mw-a-nacks-3 (and (= base-a 3) (= numbits-a 3)
                                 (dds.rtps.message:seqnum-set-bit-p bitmap-a 0)
                                 (not (dds.rtps.message:seqnum-set-bit-p bitmap-a 1)))
              "writer A's ACKNACK must NACK only SN 3 (base 3, SN 4/5 received)"))
    (multiple-value-bind (base-b numbits-b bitmap-b) (dds.rtps.reliable:reader-acknack reader key-b)
      (%check :mw-b-nacks-4 (and (= base-b 4) (= numbits-b 2)
                                 (dds.rtps.message:seqnum-set-bit-p bitmap-b 0)
                                 (not (dds.rtps.message:seqnum-set-bit-p bitmap-b 1)))
              "writer B's ACKNACK must NACK only SN 4 (base 4, SN 5 received) — A's gap@3 absent"))
    ;; Independent ranges: B sees a higher last SN; A's range must be untouched.
    (dds.rtps.reliable:reader-on-heartbeat reader key-b 1 9)
    (%check :mw-a-range-unperturbed
            (= 5 (dds.rtps.reliable:writer-proxy-last-sn (dds.rtps.reliable:get-writer-proxy reader key-a)))
            "writer A's HEARTBEAT range must be unaffected by writer B's HEARTBEAT")
    (%check :mw-b-range-advanced
            (= 9 (dds.rtps.reliable:writer-proxy-last-sn (dds.rtps.reliable:get-writer-proxy reader key-b)))
            "writer B's HEARTBEAT range must advance independently"))
  t)

(defun* %guid-of (prefix entity-id)
    (function ((simple-array (unsigned-byte 8) (12)) (unsigned-byte 32))
              (simple-array (unsigned-byte 8) (16)))
  "A 16-octet GUID from PREFIX ++ ENTITY-ID (RTPS 2.5 §9.4.4 / §9.3.1.2) — the test-local twin of the
   disc layer's %source-guid, so the reliable tests need no disc dependency."
  (let ((g (make-array 16 :element-type '(unsigned-byte 8) :initial-element 0)))
    (replace g prefix :end2 12)
    (setf (aref g 12) (ldb (byte 8 24) entity-id) (aref g 13) (ldb (byte 8 16) entity-id)
          (aref g 14) (ldb (byte 8 8) entity-id)  (aref g 15) (ldb (byte 8 0) entity-id))
    g))

(defun* run-proxy-key-retention-test ()
    (function () t)
  "Test: ADR 0088 — the proxy tables OWN their keys, and the control-path GUID cache is safe by
   construction.

   (a) THE LOAD-BEARING ONE. Look a ReaderProxy up with a MUTABLE buffer, then MUTATE that buffer, then
   look up again with an equal-valued key. The same proxy must come back. Before %retained-endpoint-key
   this FAILS: the table kept the caller's array, mutating it changed the live hash key in place, the
   proxy became unfindable, a second one was created — and the writer's acked-base silently stopped
   advancing. This assertion is the whole justification for the copy; if it is ever weakened, the copy
   can be deleted without any test noticing.

   (b) The cache must never return a key for the WRONG endpoint: a GUID cached for one (prefix,
   entity-id) is rejected for another, even when they collide on the cache slot (mod +key-cache-size+).

   (c) A cache HIT must be the identical object (no per-datagram allocation), and a MISS must still
   produce the correct GUID.

   (d) The cache is BOUNDED: driving many distinct remote endpoints through it never grows it past
   +key-cache-size+ (a peer chooses how many readers it creates, so an unbounded cache would be
   remote-drivable, NFR-SEC-POSTURE)."
  (let* ((w (dds.rtps.reliable:make-rtps-writer))
         (mutable (%aliasing-writer-guid #x0a))
         (p1 (dds.rtps.reliable:get-reader-proxy w mutable)))
    (setf (aref mutable 11) #xFF)   ; the caller reuses/mutates its buffer
    (let ((p2 (dds.rtps.reliable:get-reader-proxy w (%aliasing-writer-guid #x0a))))
      (%check :proxy-key-retained
              (eq p1 p2)
              "the proxy table must OWN its key — mutating the caller's buffer must not orphan the proxy"))
    (let* ((prefix-a (make-array 12 :element-type '(unsigned-byte 8) :initial-element #x11))
           (prefix-b (make-array 12 :element-type '(unsigned-byte 8) :initial-element #x22))
           (ga (dds.rtps.reliable:writer-lookup-key w prefix-a 1))
           (ga2 (dds.rtps.reliable:writer-lookup-key w prefix-a 1)))
      (%check :key-cache-hit-is-same-object
              (and (eq ga ga2) (equalp ga (%guid-of prefix-a 1)))
              "a second lookup of the same endpoint must HIT the cache — the SAME object, no rebuild")
      ;; different PREFIX, same entity-id -> same cache slot, must NOT be confused
      (let ((gb (dds.rtps.reliable:writer-lookup-key w prefix-b 1)))
        (%check :key-cache-rejects-wrong-prefix
                (and (not (eq ga gb)) (equalp gb (%guid-of prefix-b 1)))
                "a cached GUID must be REJECTED for a different prefix that collides on the slot"))
      ;; different entity-id, same prefix
      (let ((gc (dds.rtps.reliable:writer-lookup-key w prefix-a 2)))
        (%check :key-cache-rejects-wrong-entity
                (equalp gc (%guid-of prefix-a 2))
                "a cached GUID must be REJECTED for a different entity-id"))
      ;; bounded: drive 64 distinct endpoints through it
      (dotimes (i 64)
        (dds.rtps.reliable:writer-lookup-key w prefix-a (+ 100 i)))
      (%check :key-cache-bounded
              (= (length (dds.rtps.reliable::rtps-writer-key-cache w))
                 dds.rtps.reliable::+key-cache-size+)
              "the key cache must stay bounded — a peer chooses how many readers it creates")))
  t)

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

(defun* run-history-purge-test ()
    (function () t)
  "Test: writer-purge-acked bounds a KEEP_ALL HistoryCache by the SLOWEST reader's ack (RTPS 2.5 §8.4.1).
   Two matched readers; a change is dropped only once EVERY reader has acked past it (min acked-base); a
   matched-but-unacked reader holds the watermark at 1 (nothing purged); a NACKed (unacked) change is
   never purged."
  (flet ((mk () (dds.rtps.reliable:make-rtps-writer
                 :hc (dds.rtps.history:make-history-cache :keep-all 1 nil nil)))
         (pl (k) (map '(simple-array (unsigned-byte 8) (*)) #'char-code (format nil "m~d" k)))
         (ack (w rid base) (dds.rtps.reliable:writer-on-acknack
                            w rid base 0 (make-array 1 :element-type '(unsigned-byte 32) :initial-element 0))))
    (let ((w (mk)) (a 10) (b 20))
      (dotimes (k 10) (dds.rtps.reliable:writer-write w (pl (1+ k))))   ; SN 1..10
      (%check :hp-full (= 10 (dds.rtps.history:hc-change-count (dds.rtps.reliable:rtps-writer-hc w)))
              "the KEEP_ALL writer must hold all 10 written changes before any ack")
      (ack w a 7)   ; reader A acked < 7 (acked-base 7)
      (%check :hp-unacked-holds
              (and (zerop (dds.rtps.reliable:writer-purge-acked w (list a b)))
                   (= 10 (dds.rtps.history:hc-change-count (dds.rtps.reliable:rtps-writer-hc w))))
              "an unacked second reader (acked-base 1) holds the watermark — nothing is purged")
      (ack w b 5)   ; reader B acked < 5 (acked-base 5); min(7,5)=5 -> purge SN 1..4
      (%check :hp-purged (= 4 (dds.rtps.reliable:writer-purge-acked w (list a b)))
              "min acked-base 5 purges exactly SN 1..4 (acked by BOTH readers)")
      (let ((hc (dds.rtps.reliable:rtps-writer-hc w)))
        (%check :hp-count (= 6 (dds.rtps.history:hc-change-count hc))
                "6 changes remain (SN 5..10)")
        (%check :hp-firstsn (= 5 (dds.rtps.history:hc-min-seq hc))
                "the HEARTBEAT firstSN (hc-min-seq) advances to 5 after the purge")
        (%check :hp-boundary-kept (dds.rtps.history:hc-get-change hc 5)
                "SN 5 (= acked-base, NACK-able, not fully-acked) is NOT purged — repair stays intact")
        (%check :hp-below-gone (null (dds.rtps.history:hc-get-change hc 4))
                "SN 4 (< min acked-base) is purged"))
      (%check :hp-empty (zerop (dds.rtps.reliable:writer-purge-acked w '()))
              "no matched readers -> purge is a no-op (keep everything)")))
  t)

(defun* run-durability-retention-test ()
    (function () t)
  "Test: a TRANSIENT_LOCAL writer RETAINS its fully-acked history for late-joiners (DDS 1.4 §2.2.3.4); a
   VOLATILE writer purges on full-ACK as before (RTPS 2.5 §8.4.1). Both writers hold 10 changes; both
   readers ACK past the end (acked-base 11). writer-purge-acked with DURABILITY :transient-local purges
   NOTHING (the cache is HISTORY-bounded, not ACK-bounded — retained for the writer's lifetime); with
   :volatile (the default) it purges the full-acked range to empty, byte-identical to before this WP."
  (flet ((mk () (dds.rtps.reliable:make-rtps-writer
                 :hc (dds.rtps.history:make-history-cache :keep-all 1 nil nil)))
         (pl (k) (map '(simple-array (unsigned-byte 8) (*)) #'char-code (format nil "m~d" k)))
         (ack (w rid base) (dds.rtps.reliable:writer-on-acknack
                            w rid base 0 (make-array 1 :element-type '(unsigned-byte 32) :initial-element 0))))
    ;; (a) TRANSIENT_LOCAL writer: full-ACK does NOT purge — the history is kept for a late-joiner.
    (let ((w (mk)) (a 10) (b 20))
      (dotimes (k 10) (dds.rtps.reliable:writer-write w (pl (1+ k))))   ; SN 1..10
      (ack w a 11) (ack w b 11)                                         ; BOTH readers acked all 10
      (%check :dret-tl-noop
              (and (zerop (dds.rtps.reliable:writer-purge-acked w (list a b) :transient-local))
                   (= 10 (dds.rtps.history:hc-change-count (dds.rtps.reliable:rtps-writer-hc w))))
              "a TRANSIENT_LOCAL writer must NOT full-ACK-purge — all 10 retained for late-joiners")
      (%check :dret-tl-firstsn (= 1 (dds.rtps.history:hc-min-seq (dds.rtps.reliable:rtps-writer-hc w)))
              "the TL writer's HEARTBEAT firstSN stays at 1 (full history available to a late-joiner)"))
    ;; (b) VOLATILE writer (the default DURABILITY arg): full-ACK purges to empty — UNCHANGED behavior.
    (let ((w (mk)) (a 10) (b 20))
      (dotimes (k 10) (dds.rtps.reliable:writer-write w (pl (1+ k))))   ; SN 1..10
      (ack w a 11) (ack w b 11)
      (%check :dret-vol-purges
              (and (= 10 (dds.rtps.reliable:writer-purge-acked w (list a b)))   ; default :volatile
                   (zerop (dds.rtps.history:hc-change-count (dds.rtps.reliable:rtps-writer-hc w))))
              "a VOLATILE writer (default) purges the full-acked history to empty — byte-identical to before")
      (%check :dret-vol-explicit
              (let ((w2 (mk)))
                (dotimes (k 10) (dds.rtps.reliable:writer-write w2 (pl (1+ k))))
                (ack w2 a 11) (ack w2 b 11)
                (= 10 (dds.rtps.reliable:writer-purge-acked w2 (list a b) :volatile)))
              "an EXPLICIT :volatile purges identically to the default arg")))
  t)

(defun* run-durability-replays-test ()
    (function () t)
  "Test: a TRANSIENT_LOCAL writer REPLAYS its retained history to a late-joining TL reader (DDS 1.4
   §2.2.3.4) — init-reader-proxy-base sets the new reader's UNSENT-BASE to firstSN (= hc-min-seq) so the
   writer pushes ALL retained changes, vs the future-only default (lastSN+1). A TL writer publishes 5; a
   NEW reader joins; its proxy initialized to firstSN replays all 5 (writer-unsent-list); a future-only
   reader (lastSN+1) replays 0 of the pre-existing 5 and only sees a subsequently-published 6th."
  (let* ((w (dds.rtps.reliable:make-rtps-writer
             :hc (dds.rtps.history:make-history-cache :keep-all 1 nil nil)))
         (late 30) (future 40)
         (pl (lambda (k) (map '(simple-array (unsigned-byte 8) (*)) #'char-code (format nil "m~d" k)))))
    (dotimes (k 5) (dds.rtps.reliable:writer-write w (funcall pl (1+ k))))   ; SN 1..5
    (multiple-value-bind (first last count) (dds.rtps.reliable:writer-heartbeat w)
      (declare (ignore count))
      (%check :drep-hb-range (and (= first 1) (= last 5)) "the writer advertises [firstSN=1, lastSN=5]")
      ;; TRANSIENT_LOCAL late-joiner: proxy unsent-base := firstSN -> the writer replays all 5.
      (dds.rtps.reliable:init-reader-proxy-base w late first)
      (%check :drep-tl-base
              (= 1 (dds.rtps.reliable:reader-proxy-unsent-base (dds.rtps.reliable:get-reader-proxy w late)))
              "a TL late-joiner's proxy unsent-base is initialized to firstSN=1 (replay all)")
      (let ((replayed (dds.rtps.reliable:writer-unsent-list w late)))
        (%check :drep-tl-all
                (equal '(1 2 3 4 5) (mapcar #'dds.rtps.history:cache-change-sn replayed))
                "the TL late-joiner is pushed ALL 5 retained changes (the firstSN proxy init)"))
      ;; VOLATILE (future-only) late-joiner: proxy unsent-base := lastSN+1 -> 0 of the pre-existing 5.
      (dds.rtps.reliable:init-reader-proxy-base w future (1+ last))
      (%check :drep-vol-empty (null (dds.rtps.reliable:writer-unsent-list w future))
              "a future-only (lastSN+1) reader replays NOTHING of the pre-existing history")
      (dds.rtps.reliable:writer-write w (funcall pl 6))                 ; SN 6, published AFTER both joined
      (%check :drep-vol-future
              (equal '(6) (mapcar #'dds.rtps.history:cache-change-sn
                                  (dds.rtps.reliable:writer-unsent-list w future)))
              "the future-only reader sees only SN 6 (published after it joined), not the retained 1..5")))
  t)

(defun* run-durability-reader-gate-test ()
    (function () t)
  "Test: the READER-SIDE durability gate (DDS 1.4 §2.2.3.4) — on the FIRST HEARTBEAT advertising
   [firstSN, lastSN] a reader that REQUESTS history (a TRANSIENT_LOCAL reader matched a retaining writer,
   skip-history NIL) NACKs the full range from firstSN, while a reader that SKIPS history (a VOLATILE reader
   matched a retaining/TRANSIENT_LOCAL writer, skip-history T) sets its expected base to lastSN+1, NACKing
   only future gaps. init-writer-proxy-durability records the per-writer skip decision at match time;
   reader-on-heartbeat applies it once, on the first HEARTBEAT. The behavior-defining branch: without it a
   VOLATILE reader would NACK the TL writer's advertised history and the TL writer (which retains) would
   retransmit it — wrongly delivering history to a VOLATILE reader. (The disc gate sets skip-history only for
   a VOLATILE reader against a RETAINING writer, so VOLATILE<->VOLATILE stays NIL = byte-identical; this test
   drives the reliable mechanism directly with both flag values.)"
  (let* ((reader (dds.rtps.reliable:make-rtps-reader))
         (tl-w (%aliasing-writer-guid #x1a))      ; skip-history NIL (a TL reader matched a TL writer) -> REQUEST
         (vol-w (%aliasing-writer-guid #x1b)))     ; skip-history T (a VOLATILE reader matched a TL writer) -> SKIP
    ;; (a) skip-history NIL (a TL reader matched a TL writer): request the full history.
    (dds.rtps.reliable:init-writer-proxy-durability reader tl-w nil)   ; skip-history NIL -> request
    (dds.rtps.reliable:reader-on-heartbeat reader tl-w 1 10)            ; late-joiner: [firstSN=1, lastSN=10]
    (%check :drg-tl-firstsn
            (= 1 (dds.rtps.reliable:writer-proxy-first-sn (dds.rtps.reliable:get-writer-proxy reader tl-w)))
            "a TL reader keeps firstSN=1 -> requests the retained history")
    (multiple-value-bind (base numbits) (dds.rtps.reliable:reader-acknack reader tl-w)
      (%check :drg-tl-nacks-all (and (= base 1) (= numbits 10))
              "a TL reader's ACKNACK base is firstSN=1 and NACKs the full advertised [1,10]"))
    ;; (b) VOLATILE reader: skip the advertised history (base := lastSN+1), NACK only future gaps.
    (dds.rtps.reliable:init-writer-proxy-durability reader vol-w t)    ; skip-history T -> skip
    (dds.rtps.reliable:reader-on-heartbeat reader vol-w 1 10)           ; late-joiner: [firstSN=1, lastSN=10]
    (%check :drg-vol-skip
            (= 11 (dds.rtps.reliable:writer-proxy-first-sn (dds.rtps.reliable:get-writer-proxy reader vol-w)))
            "a VOLATILE reader advances firstSN to lastSN+1=11 -> skips the retained history")
    (multiple-value-bind (base numbits) (dds.rtps.reliable:reader-acknack reader vol-w)
      (%check :drg-vol-no-history (and (= base 11) (zerop numbits))
              "a VOLATILE reader's ACKNACK NACKs NOTHING of the advertised history (base lastSN+1, 0 bits)"))
    ;; (c) the skip is applied ONCE (first HEARTBEAT only): a later HEARTBEAT does NOT re-skip new samples.
    (dds.rtps.reliable:reader-on-heartbeat reader vol-w 1 15)           ; the writer published SN 11..15
    (multiple-value-bind (base numbits) (dds.rtps.reliable:reader-acknack reader vol-w)
      (%check :drg-vol-future (and (= base 11) (= numbits 5))
              "a VOLATILE reader NACKs the FUTURE gap [11,15] (published after it joined), base still 11"))
    ;; (d) byte-identical default: a fresh reader with NO durability decision behaves EXACTLY as before
    ;; (full-range NACK of [firstSN, lastSN]) — the gate is OFF unless init-writer-proxy-durability set it.
    (let ((dflt (dds.rtps.reliable:make-rtps-reader)) (w (%aliasing-writer-guid #x1c)))
      (dds.rtps.reliable:reader-on-heartbeat dflt w 1 10)
      (multiple-value-bind (base numbits) (dds.rtps.reliable:reader-acknack dflt w)
        (%check :drg-default-unchanged (and (= base 1) (= numbits 10))
                "with NO durability decision the reader NACKs the full range — byte-identical to before"))))
  t)

(defun* run-durability-finalize-test ()
    (function () t)
  "Test: durability-finalize (DDS 1.4 §2.2.3.4; the OPT-IN extension ON TOP of the conformant default) —
   a finalized TRANSIENT_LOCAL writer reverts to the VOLATILE-style full-ACK purge, RELEASING its retained
   history once all current readers ACK; a subsequent late-joiner gets NOTHING of the pre-finalize history;
   samples published AFTER finalize behave VOLATILE (purged on full-ACK). The default (un-finalized) TL
   writer still RETAINS (byte-identical to Task 1), and a VOLATILE writer is unaffected (regression gate).
   The finalize is MONOTONIC (no un-finalize in v1)."
  (flet ((mk () (dds.rtps.reliable:make-rtps-writer
                 :hc (dds.rtps.history:make-history-cache :keep-all 1 nil nil)))
         (pl (k) (map '(simple-array (unsigned-byte 8) (*)) #'char-code (format nil "m~d" k)))
         (ack (w rid base) (dds.rtps.reliable:writer-on-acknack
                            w rid base 0 (make-array 1 :element-type '(unsigned-byte 32) :initial-element 0))))
    ;; (a) finalize releases the retained history: a TL writer holds 10, finalize, both readers ACK -> purged.
    (let ((w (mk)) (a 10) (b 20))
      (dotimes (k 10) (dds.rtps.reliable:writer-write w (pl (1+ k))))   ; SN 1..10
      (ack w a 11) (ack w b 11)                                         ; both readers acked all 10
      (%check :dfin-default-retains
              (zerop (dds.rtps.reliable:writer-purge-acked w (list a b) :transient-local))
              "before finalize a TL writer still RETAINS on full-ACK (byte-identical to Task 1)")
      (dds.rtps.reliable:writer-finalize-durability w)                  ; no more late-joiners expected
      (%check :dfin-flag (dds.rtps.reliable:rtps-writer-finalized w)
              "writer-finalize-durability sets the per-writer FINALIZED flag")
      (%check :dfin-releases
              (and (= 10 (dds.rtps.reliable:writer-purge-acked w (list a b) :transient-local))
                   (zerop (dds.rtps.history:hc-change-count (dds.rtps.reliable:rtps-writer-hc w))))
              "a FINALIZED TL writer purges the full-acked history to empty (reverts to VOLATILE)"))
    ;; (b) a subsequent late-joiner gets NOTHING of the released pre-finalize history (firstSN moved past it).
    (let ((w (mk)) (a 10) (b 20) (late 30))
      (dotimes (k 5) (dds.rtps.reliable:writer-write w (pl (1+ k))))    ; SN 1..5
      (ack w a 6) (ack w b 6)
      (dds.rtps.reliable:writer-finalize-durability w)
      (dds.rtps.reliable:writer-purge-acked w (list a b) :transient-local)   ; release 1..5
      (multiple-value-bind (first last) (dds.rtps.reliable:writer-heartbeat w)
        (dds.rtps.reliable:init-reader-proxy-base w late first)          ; TL late-joiner: replay from firstSN
        (%check :dfin-latejoiner-nothing
                (null (dds.rtps.reliable:writer-unsent-list w late))
                "a late-joiner after finalize gets NOTHING of the released pre-finalize history")
        (%check :dfin-empty-after-release (zerop last)
                "the released cache advertises an empty range (lastSN 0) to the late-joiner")))
    ;; (c) samples published AFTER finalize behave VOLATILE: purged on full-ACK (not retained).
    (let ((w (mk)) (a 10) (b 20))
      (dds.rtps.reliable:writer-finalize-durability w)                 ; finalize an empty writer
      (dotimes (k 4) (dds.rtps.reliable:writer-write w (pl (1+ k))))   ; SN 1..4 published after finalize
      (ack w a 5) (ack w b 5)
      (%check :dfin-post-volatile
              (and (= 4 (dds.rtps.reliable:writer-purge-acked w (list a b) :transient-local))
                   (zerop (dds.rtps.history:hc-change-count (dds.rtps.reliable:rtps-writer-hc w))))
              "samples published AFTER finalize are purged on full-ACK (VOLATILE behavior)"))
    ;; (d) regression: a VOLATILE writer is UNAFFECTED by finalize (already purges); finalize is MONOTONIC.
    (let ((w (mk)) (a 10) (b 20))
      (dotimes (k 3) (dds.rtps.reliable:writer-write w (pl (1+ k))))   ; SN 1..3
      (ack w a 4) (ack w b 4)
      (%check :dfin-volatile-unaffected
              (= 3 (dds.rtps.reliable:writer-purge-acked w (list a b) :volatile))
              "a VOLATILE writer purges on full-ACK regardless of finalize (byte-identical)")
      (dds.rtps.reliable:writer-finalize-durability w)
      (dds.rtps.reliable:writer-finalize-durability w)                 ; idempotent / monotonic
      (%check :dfin-monotonic (dds.rtps.reliable:rtps-writer-finalized w)
              "finalize is monotonic: a second call keeps the writer FINALIZED")))
  t)

(defun* run-reader-compaction-test ()
    (function () t)
  "Test: the reader WriterProxy received-table stays bounded to the live window, not O(history) (RTPS 2.5
   §8.4.10). reader-on-data records a presence marker (no payload retained); reader-on-heartbeat compacts
   markers below the advancing firstSN (the writer purged them); firstSN is monotonic (a stale lower
   HEARTBEAT does not un-compact); ACKNACK/complete-p remain correct."
  (let* ((reader (dds.rtps.reliable:make-rtps-reader))
         (w 7)
         (pl (map '(simple-array (unsigned-byte 8) (*)) #'char-code "x")))
    (dotimes (k 100)                                   ; SN 1..100, a 10-wide moving window
      (let ((sn (1+ k)))
        (dds.rtps.reliable:reader-on-data reader w sn pl)
        (dds.rtps.reliable:reader-on-heartbeat reader w (max 1 (- sn 9)) sn)))
    (let* ((proxy (dds.rtps.reliable:get-writer-proxy reader w))
           (received (dds.rtps.reliable:writer-proxy-received proxy)))
      (%check :rc-bounded (<= (hash-table-count received) 10)
              "received markers must be bounded to the ~10-wide window, not the 100 samples")
      (%check :rc-window-present
              (and (gethash 100 received) (gethash 91 received) (null (gethash 90 received)))
              "the live window [91,100] is retained; compacted SNs below firstSN are dropped")
      (%check :rc-complete (dds.rtps.reliable:reader-complete-p reader w)
              "reader-complete-p stays correct over the live window after compaction")
      (multiple-value-bind (base numbits) (dds.rtps.reliable:reader-acknack reader w)
        (declare (ignore numbits))
        (%check :rc-acknack-base (= 101 base)
                "with the whole window received, the ACKNACK base is last+1 (101) — no spurious NACK"))
      ;; monotonic firstSN: a stale lower HEARTBEAT must not lower firstSN or un-compact
      (dds.rtps.reliable:reader-on-heartbeat reader w 50 100)
      (%check :rc-monotonic
              (and (= 91 (dds.rtps.reliable:writer-proxy-first-sn proxy))
                   (<= (hash-table-count received) 10))
              "a stale lower-firstSN HEARTBEAT must not lower firstSN nor re-grow the received table")))
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

;;; WP-KEYED-FLATDATA: keyed FlatData keyhash byte-exactness (FR-PF-4, RTPS 2.5 §9.6.4.8). Lifting the
;;; FlatData NO_KEY restriction (fixed-size scalar @key only) emits key-hash-<name>-fd, a buffer-reading
;;; BE keyhash byte-identical to the spec keyhash. A <=16 direct/zero-padded key (one i32) and a >16 MD5
;;; key (three i64) are both pinned; the -fd value source is the in-place -fd accessor, so it equals the
;;; struct key-hash-<name> for the same values. NOT cleared for ship — pending counsel (R6); see ADR 0015/0017.
(dds.gen:define-dds-type keyed-fd-i32 (:flatdata t)
  (k :i32 :key t) (v :i32))

(dds.gen:define-dds-type keyed-fd-md5 (:flatdata t)
  (k1 :i64 :key t) (k2 :i64 :key t) (k3 :i64 :key t) (v :i32))

;; WP-KEYED-FLATDATA cross-DDS interop type, byte-identical to dds.shapes:keyed-flat and to the foreign
;; peers' interop/keyed-flatdata/KeyedFlat.idl (struct KeyedFlat { @key long id; long x; long y; }). Defined
;; test-local (dds-tests does not depend on dds-shapes) so the cross-impl keyhash conformance proof runs in
;; the core suite on BOTH impls. The keyhash depends ONLY on the @key member (i32 id); the trailing x/y do
;; not enter the key holder, so this is keyhash-identical to a single-i32-@key type for any given id.
(dds.gen:define-dds-type keyed-flat-iop (:flatdata t)
  (id :i32 :key t) (x :i32) (y :i32))

(defun* run-keyed-flatdata-keyhash-test ()
    (function () t)
  "WP-KEYED-FLATDATA keyhash byte-exactness (FR-PF-4, RTPS 2.5 §9.6.4.8). (a) a keyed FlatData type
   compiles (NO_KEY lifted); (b) key-hash-keyed-fd-i32-fd over an owned buffer with a known i32 @key
   equals the PINNED <=16 direct vector (the key BIG-ENDIAN, zero-padded to 16); (c) the three-i64 type's
   -fd keyhash equals MD5 of its BE-serialized 24-octet key holder (the >16 path); (d) -fd == the struct
   key-hash-<name> for the same values (the struct keyhash is also emitted); (e) a :flatdata t type with a
   variable-size (:string) @key still raises the compile error."
  ;; (b) <=16 direct path: i32 @key #x01020304 -> BE {01 02 03 04} zero-padded to 16
  (let ((b (make-keyed-fd-i32-flatdata)))
    (setf (keyed-fd-i32-k-fd b) #x01020304)
    (setf (keyed-fd-i32-v-fd b) #x7f7f7f7f)
    (%check :kfd-direct
            (equalp (key-hash-keyed-fd-i32-fd b)
                    (octets #x01 #x02 #x03 #x04 0 0 0 0 0 0 0 0 0 0 0 0))
            "keyed FlatData i32 keyhash = big-endian XCDR2 key bytes zero-padded to 16")
    ;; (d) the buffer-reading -fd keyhash equals the struct keyhash for the same key value
    (%check :kfd-direct-vs-struct
            (equalp (key-hash-keyed-fd-i32-fd b)
                    (key-hash-keyed-fd-i32 (make-keyed-fd-i32 :k #x01020304 :v 0)))
            "key-hash-<name>-fd equals the struct key-hash-<name> for the same i32 key")
    ;; the key drives the hash distinctly; a different key value gives a different hash
    (let ((b2 (make-keyed-fd-i32-flatdata)))
      (setf (keyed-fd-i32-k-fd b2) #x01020305)
      (%check :kfd-distinct
              (not (equalp (key-hash-keyed-fd-i32-fd b) (key-hash-keyed-fd-i32-fd b2)))
              "distinct key values yield distinct keyhashes")
      (dds.pal:free-static (dds.core.buffer:octet-buffer-vec b2)))
    (dds.pal:free-static (dds.core.buffer:octet-buffer-vec b)))
  ;; (c) >16 MD5 path: three i64 keys (24 octets > 16) -> MD5 of the BE XCDR2 key holder
  (let ((b (make-keyed-fd-md5-flatdata))
        (k1 #x0102030405060708) (k2 #x1112131415161718) (k3 #x2122232425262728))
    (setf (keyed-fd-md5-k1-fd b) k1)
    (setf (keyed-fd-md5-k2-fd b) k2)
    (setf (keyed-fd-md5-k3-fd b) k3)
    (setf (keyed-fd-md5-v-fd b) 1)
    ;; expected = MD5 of the three i64 keys serialized big-endian, contiguous (XCDR2, all 4-aligned at 0/8/16)
    (let ((be (octets #x01 #x02 #x03 #x04 #x05 #x06 #x07 #x08
                      #x11 #x12 #x13 #x14 #x15 #x16 #x17 #x18
                      #x21 #x22 #x23 #x24 #x25 #x26 #x27 #x28)))
      (%check :kfd-md5
              (equalp (key-hash-keyed-fd-md5-fd b) (dds.core.md5:md5 be))
              "three-i64 keyed FlatData keyhash = MD5 of the big-endian XCDR2 key holder")
      ;; it MUST be the 16-octet MD5, not the direct >16-octet copy (the first 16 BE bytes)
      (%check :kfd-md5-not-direct
              (not (equalp (key-hash-keyed-fd-md5-fd b) (subseq be 0 16)))
              ">16 key takes the MD5 path, not a direct copy of the first 16 octets"))
    ;; (d) -fd == struct keyhash on the MD5 path too
    (%check :kfd-md5-vs-struct
            (equalp (key-hash-keyed-fd-md5-fd b)
                    (key-hash-keyed-fd-md5 (make-keyed-fd-md5 :k1 k1 :k2 k2 :k3 k3 :v 1)))
            "key-hash-<name>-fd equals the struct key-hash-<name> on the MD5 path")
    (dds.pal:free-static (dds.core.buffer:octet-buffer-vec b)))
  ;; (e) a variable-size (:string) @key on a :flatdata t type must still be a compile-time error
  (%check :kfd-string-key-rejected
          (nth-value 1 (ignore-errors
                         (macroexpand-1 '(dds.gen:define-dds-type keyed-fd-bad (:flatdata t)
                                          (k :string :key t) (v :i32)))))
          ":flatdata t with a variable-size (:string) @key must signal at macroexpand (fixed-size scalar only)")
  t)

(defun* %be-i32 (v)
    (function ((signed-byte 32)) (simple-array (unsigned-byte 8) (4)))
  "The 4-octet big-endian two's-complement encoding of an i32 V — an INDEPENDENT derivation of the XCDR2
   big-endian key-member serialization (RTPS 2.5 §9.6.4.8), not via the project's own serializer, so the
   cross-impl keyhash oracle does not circularly reuse the code under test."
  (let ((u (ldb (byte 32 0) v))
        (b (make-array 4 :element-type '(unsigned-byte 8))))
    (setf (aref b 0) (ldb (byte 8 24) u) (aref b 1) (ldb (byte 8 16) u)
          (aref b 2) (ldb (byte 8 8) u) (aref b 3) (ldb (byte 8 0) u))
    b))

(defun* %expected-i32-keyhash (id)
    (function ((signed-byte 32)) (simple-array (unsigned-byte 8) (16)))
  "The 16-octet DDS keyhash a STANDARDS-CONFORMANT peer (RTI Connext / Fast DDS) computes for a keyed type
   whose only @key is an i32 = ID (RTPS 2.5 §9.6.4.8): the key holder is the @key members in member order,
   PLAIN_CDR2 (XCDR2) big-endian, no encapsulation/type/member headers, origin-0; its maximum serialized
   size is 4 (<=16), so the keyhash is the key bytes directly, right-zero-padded to 16. Derived here from
   first principles (%be-i32), independent of the project's keyhash, to serve as the cross-impl oracle."
  (let ((out (make-array 16 :element-type '(unsigned-byte 8) :initial-element 0)))
    (replace out (%be-i32 id))
    out))

(defun* run-keyed-flat-interop-keyhash-test ()
    (function () t)
  "WP-KEYED-FLATDATA F1 (per-feature DoD 2026-06-17) — the CROSS-DDS interop conformance crux for the
   keyed FlatData KeyedFlat type (FR-PF-4, RTPS 2.5 §9.6.4.8, R6). KeyedFlat is the interop type shared with
   the foreign peers: struct KeyedFlat { @key long id; long x; long y; } (interop/keyed-flatdata/KeyedFlat.idl;
   dds.shapes:keyed-flat). This proves OUR keyed-FlatData instance identity equals what a standards-conformant
   peer (RTI Connext / Fast DDS) computes for the SAME key value, so keyed matching + dispose-by-key
   interoperate on the WIRE (copy path; same-host ZC loan is out of scope). The peer keyhash is derived from
   first principles (%expected-i32-keyhash, INDEPENDENT of our serializer), not copied from our own struct
   keyhash. Asserts: (a) key-hash-keyed-flat-iop-fd off the FlatData buffer EQUALP the independently-derived
   peer keyhash for several id values, INCLUDING the spec Example-1-style pinned vector for id=1
   (#(00 00 00 01 0..0)) and a negative id (two's-complement BE); (b) the trailing non-key x/y do NOT enter
   the key holder (changing x/y leaves the keyhash unchanged — only id drives instance identity); (c) the
   -fd keyhash equals the struct key-hash-keyed-flat-iop for the same id (the FlatData and non-FlatData
   keyhash of OUR own stack coincide, so the copy-path reader and a non-FlatData peer agree). Both impls."
  (let ((b (make-keyed-flat-iop-flatdata)))
    (unwind-protect
         (progn
           ;; (a) the cross-impl crux: our -fd keyhash == the independently-derived conformant-peer keyhash
           (dolist (id '(1 7 305419896 -1 -2 #x7fffffff))
             (setf (keyed-flat-iop-id-fd b) id
                   (keyed-flat-iop-x-fd b) 50 (keyed-flat-iop-y-fd b) 60)
             (%check (intern (format nil "KFLAT-PEER-~d" id) :keyword)
                     (equalp (key-hash-keyed-flat-iop-fd b) (%expected-i32-keyhash id))
                     (format nil "keyed FlatData keyhash for id=~d must equal the standards-conformant peer keyhash (RTPS 2.5 §9.6.4.8)" id)))
           ;; pinned spec Example-1-style vector: id=1 -> BE {00 00 00 01} zero-padded to 16
           (setf (keyed-flat-iop-id-fd b) 1 (keyed-flat-iop-x-fd b) 99 (keyed-flat-iop-y-fd b) 99)
           (%check :kflat-pinned-id1
                   (equalp (key-hash-keyed-flat-iop-fd b)
                           (octets #x00 #x00 #x00 #x01 0 0 0 0 0 0 0 0 0 0 0 0))
                   "id=1 keyhash is the pinned big-endian XCDR2 key zero-padded to 16 (#(00 00 00 01 0..0))")
           ;; (b) the non-key x/y must NOT enter the key holder — only id drives instance identity
           (let ((kh-x50 (let () (setf (keyed-flat-iop-id-fd b) 42 (keyed-flat-iop-x-fd b) 50 (keyed-flat-iop-y-fd b) 50)
                              (copy-seq (key-hash-keyed-flat-iop-fd b))))
                 (kh-x77 (let () (setf (keyed-flat-iop-id-fd b) 42 (keyed-flat-iop-x-fd b) 77 (keyed-flat-iop-y-fd b) 88)
                              (copy-seq (key-hash-keyed-flat-iop-fd b)))))
             (%check :kflat-key-is-id-only
                     (equalp kh-x50 kh-x77)
                     "changing the non-key x/y must NOT change the keyhash (only the @key id enters the key holder)")
             (%check :kflat-id42-vector
                     (equalp kh-x50 (%expected-i32-keyhash 42))
                     "id=42 keyhash matches the conformant-peer derivation regardless of x/y"))
           ;; (c) the -fd keyhash equals OUR struct keyhash for the same id (FlatData == non-FlatData, our side)
           (setf (keyed-flat-iop-id-fd b) 305419896 (keyed-flat-iop-x-fd b) 7 (keyed-flat-iop-y-fd b) 8)
           (%check :kflat-fd-vs-struct
                   (equalp (key-hash-keyed-flat-iop-fd b)
                           (key-hash-keyed-flat-iop (make-keyed-flat-iop :id 305419896 :x 0 :y 0)))
                   "key-hash-<name>-fd equals the struct key-hash-<name> for the same id (FlatData/non-FlatData agree)"))
      (dds.pal:free-static (dds.core.buffer:octet-buffer-vec b)))
    t))

;;; WP-FLATDATA-XCDR-TRANSCODE (FR-PF-4, DDS-XTypes 1.3 §7.6.3.1.2, R6 — NOT cleared for ship, see ADR 0015):
;;; a :flatdata t reader transcodes a FOREIGN representation (XCDR1 BE/LE, XCDR2 BE) into its canonical
;;; XCDR2-LE buffer via the sibling struct codec, instead of rejecting it (the WP-KEYED-FLATDATA forward-leg
;;; false-REJECT a stock Connext peer — defaulting to XCDR1-BE — surfaced). The native PLAIN_CDR2_LE (0x0007)
;;; path stays read-in-place (0-copy). The transcode-test type carries an :i8 then an :i64 @key so the
;;; XCDR1<->XCDR2 8-vs-4 alignment divergence is exercised: in XCDR1 the i64 sits at body offset 8 (8-align
;;; after the i8), in XCDR2 at offset 4 (4-align cap) — so the transcode is a re-align, not a pure byte-swap.
(dds.gen:define-dds-type xcv (:flatdata t)
  (a :i8) (k :i64 :key t) (v :i32))

(defun* %be-i64 (v)
    (function ((signed-byte 64)) (simple-array (unsigned-byte 8) (8)))
  "The 8-octet big-endian two's-complement encoding of an i64 V — an INDEPENDENT derivation of the XCDR2
   big-endian @key serialization (RTPS 2.5 §9.6.4.8), not via the project's own serializer, so the keyhash
   oracle does not circularly reuse the code under test."
  (let ((u (ldb (byte 64 0) v))
        (b (make-array 8 :element-type '(unsigned-byte 8))))
    (dotimes (i 8) (setf (aref b i) (ldb (byte 8 (* 8 (- 7 i))) u)))
    b))

(defun* %expected-i64-keyhash (k)
    (function ((signed-byte 64)) (simple-array (unsigned-byte 8) (16)))
  "The 16-octet DDS keyhash a STANDARDS-CONFORMANT peer computes for a keyed type whose only @key is an i64 = K
   (RTPS 2.5 §9.6.4.8): key holder max serialized size 8 (<=16), so the key bytes (XCDR2 big-endian) directly,
   right-zero-padded to 16. Derived from first principles (%be-i64), independent of our keyhash, as the oracle."
  (let ((out (make-array 16 :element-type '(unsigned-byte 8) :initial-element 0)))
    (replace out (%be-i64 k))
    out))

(defun* %xcv-transcode-check (wire tag)
    (function ((simple-array (unsigned-byte 8) (*)) symbol) t)
  "DRY: feed a HAND-BUILT SerializedPayload WIRE through the engine RX (dds.dcps::%deserialize-sample, which
   parses the encap header then funcalls the FlatData :deserialize = deserialize-xcv-fd) and assert the
   canonical -fd accessors read the pinned values (a=#x11, k=#x0102030405060708, v=#x21222324) AND
   key-hash-xcv-fd equals the independently-derived i64 keyhash. WIRE is built by hand (not our serializer) so
   the test is a genuine oracle of the foreign-rep transcode + the XCDR1<->XCDR2 re-alignment."
  (let* ((ts (dds.types:find-type-support "xcv"))
         (sample (dds.dcps::%deserialize-sample ts wire)))
    (unwind-protect
         (progn
           (%check (intern (format nil "XCV-TRANSCODE-A-~a" tag) :keyword)
                   (= (xcv-a-fd sample) #x11)
                   (format nil "~a: a-fd should read #x11, got #x~x" tag (xcv-a-fd sample)))
           (%check (intern (format nil "XCV-TRANSCODE-K-~a" tag) :keyword)
                   (= (xcv-k-fd sample) #x0102030405060708)
                   (format nil "~a: k-fd should read #x0102030405060708, got #x~x" tag (xcv-k-fd sample)))
           (%check (intern (format nil "XCV-TRANSCODE-V-~a" tag) :keyword)
                   (= (xcv-v-fd sample) #x21222324)
                   (format nil "~a: v-fd should read #x21222324, got #x~x" tag (xcv-v-fd sample)))
           (%check (intern (format nil "XCV-TRANSCODE-KH-~a" tag) :keyword)
                   (equalp (key-hash-xcv-fd sample) (%expected-i64-keyhash #x0102030405060708))
                   (format nil "~a: key-hash-xcv-fd must equal the native i64 keyhash (RTPS 2.5 §9.6.4.8)" tag)))
      (dds.pal:free-static (dds.core.buffer:octet-buffer-vec sample)))
    t))

(defun* run-flatdata-transcode-xcdr1be-test ()
    (function () t)
  "WP-FLATDATA-XCDR-TRANSCODE: a FlatData reader transcodes a PLAIN_CDR_BE (0x0000, XCDR1 big-endian) foreign
   SerializedPayload into its canonical XCDR2-LE buffer (FR-PF-4, DDS-XTypes 1.3 §7.6.3.1.2). The body is HAND
   built per §7.6.3.1.2 + the XCDR1 8-byte alignment: a@0 (1 octet), pad to 8, k@8 (i64 BE), v@16 (i32 BE) —
   so the i64 sits at offset 8 (NOT the XCDR2 offset 4); the transcode must re-align, not just byte-swap. The
   -fd accessors and key-hash-xcv-fd then read the pinned values (the oracle). A stock RTI Connext defaults to
   this representation — this is the forward-leg false-REJECT closed."
  (let ((wire (octets #x00 #x00 #x00 #x00                          ; encap: PLAIN_CDR_BE (0x0000), options 0
                      #x11 #x00 #x00 #x00 #x00 #x00 #x00 #x00      ; a@0=11, pad to 8-align k (XCDR1)
                      #x01 #x02 #x03 #x04 #x05 #x06 #x07 #x08      ; k@8 = i64 BE 0x0102030405060708
                      #x21 #x22 #x23 #x24)))                       ; v@16 = i32 BE 0x21222324
    (%xcv-transcode-check wire :xcdr1be)))

(defun* run-flatdata-transcode-xcdr1le-test ()
    (function () t)
  "WP-FLATDATA-XCDR-TRANSCODE: a FlatData reader transcodes a PLAIN_CDR_LE (0x0001, XCDR1 little-endian)
   foreign payload into XCDR2-LE (FR-PF-4, §7.6.3.1.2). Same XCDR1 layout as the BE case (i64 still @8 — the
   8-byte alignment is endianness-independent) but little-endian field bytes; the -fd accessors read the pinned
   values. HAND-BUILT (not our serializer)."
  (let ((wire (octets #x00 #x01 #x00 #x00                          ; encap: PLAIN_CDR_LE (0x0001), options 0
                      #x11 #x00 #x00 #x00 #x00 #x00 #x00 #x00      ; a@0=11, pad to 8-align k (XCDR1)
                      #x08 #x07 #x06 #x05 #x04 #x03 #x02 #x01      ; k@8 = i64 LE 0x0102030405060708
                      #x24 #x23 #x22 #x21)))                       ; v@16 = i32 LE 0x21222324
    (%xcv-transcode-check wire :xcdr1le)))

(defun* run-flatdata-transcode-xcdr2be-test ()
    (function () t)
  "WP-FLATDATA-XCDR-TRANSCODE: a FlatData reader transcodes a PLAIN_CDR2_BE (0x0006, XCDR2 big-endian) foreign
   payload into XCDR2-LE (FR-PF-4, §7.6.3.1.2). XCDR2 4-byte alignment cap: a@0, pad to 4, k@4 (i64 BE), v@12
   (i32 BE) — so the i64 is at offset 4 (NOT the XCDR1 offset 8); only the endianness differs from the native
   layout, so this exercises the byte-swap-only transcode. HAND-BUILT."
  (let ((wire (octets #x00 #x06 #x00 #x00                          ; encap: PLAIN_CDR2_BE (0x0006), options 0
                      #x11 #x00 #x00 #x00                          ; a@0=11, pad to 4-align k (XCDR2)
                      #x01 #x02 #x03 #x04 #x05 #x06 #x07 #x08      ; k@4 = i64 BE 0x0102030405060708
                      #x21 #x22 #x23 #x24)))                       ; v@12 = i32 BE 0x21222324
    (%xcv-transcode-check wire :xcdr2be)))

(defun* run-flatdata-transcode-native-test ()
    (function () t)
  "WP-FLATDATA-XCDR-TRANSCODE regression: the native PLAIN_CDR2_LE (0x0007) path still reads IN PLACE (0-copy,
   UNCHANGED) — a hand-built canonical XCDR2-LE payload (a@0, pad to 4, k@4 i64 LE, v@12 i32 LE) reads the
   pinned values via the -fd accessors with NO transcode (the native branch). This proves the rep-id branch
   does not perturb the shipped 0-copy path."
  (let ((wire (octets #x00 #x07 #x00 #x00                          ; encap: PLAIN_CDR2_LE (0x0007), options 0
                      #x11 #x00 #x00 #x00                          ; a@0=11, pad to 4-align k (XCDR2)
                      #x08 #x07 #x06 #x05 #x04 #x03 #x02 #x01      ; k@4 = i64 LE 0x0102030405060708
                      #x24 #x23 #x22 #x21)))                       ; v@12 = i32 LE 0x21222324
    (%xcv-transcode-check wire :native)))

(defun* run-flatdata-transcode-rejects-pl-test ()
    (function () t)
  "WP-FLATDATA-XCDR-TRANSCODE: non-transcodable representations on a FINAL fixed-size FlatData type — PL_CDR2
   (0x000b), DELIMITED_CDR_LE (0x0009), XML (0x0004) — keep the CLEAN reject (a FINAL fixed-size FlatData type
   is PLAIN-encapsulated, so these are unexpected; rejecting is correct, not a regression). The reject must be
   a controlled signal, never an OOB / crash (false-REJECT-safe + NFR-SEC-POSTURE). The bodies are arbitrary
   (the rep-id alone decides the reject); each must raise."
  (let ((ts (dds.types:find-type-support "xcv")))
    (dolist (rep '((#x00 #x0b . :pl-cdr2-le)
                   (#x00 #x09 . :delimited-cdr-le)
                   (#x00 #x04 . :xml)))
      (let ((wire (octets (first rep) (second rep) #x00 #x00
                          #x11 #x00 #x00 #x00
                          #x08 #x07 #x06 #x05 #x04 #x03 #x02 #x01
                          #x24 #x23 #x22 #x21)))
        (%check (intern (format nil "XCV-TRANSCODE-REJECT-~a" (cddr rep)) :keyword)
                (nth-value 1 (ignore-errors (dds.dcps::%deserialize-sample ts wire)))
                (format nil "FlatData RX of ~a must cleanly reject (signal), not read-in-place or crash" (cddr rep)))))
    t))

(defun* run-original-writer-info-vector-test ()
    (function () t)
  "PID_ORIGINAL_WRITER_INFO (0x0061) byte-exact encode/decode vs the spike capture (RTPS 2.5 §8.3.5.4)."
  (let* ((guid (make-array 16 :element-type '(unsigned-byte 8)
                           :initial-contents '(#x01 #x01 #x66 #xf2 #x8f #x4f #x79 #x5f
                                               #xa0 #x8e #xcd #xa9 #x80 #x00 #x00 #x02)))
         (sn 1)
         (expect (make-array 24 :element-type '(unsigned-byte 8)
                             :initial-contents '(#x01 #x01 #x66 #xf2 #x8f #x4f #x79 #x5f
                                                 #xa0 #x8e #xcd #xa9 #x80 #x00 #x00 #x02
                                                 #x00 #x00 #x00 #x00 #x01 #x00 #x00 #x00)))
         (body (dds.rtps.message:encode-original-writer-info guid sn)))
    (%check :owi-encode (equalp body expect)
            (format nil "OriginalWriterInfo body mismatch: ~s vs ~s" body expect))
    (multiple-value-bind (g s) (dds.rtps.message:parse-original-writer-info body 0 24)
      (%check :owi-decode-guid (equalp g guid) "round-trip GUID mismatch")
      (%check :owi-decode-sn (eql s 1) "round-trip SN mismatch"))
    ;; large SN exercises the high word
    (let* ((big (+ (ash 1 33) 7))
           (b2 (dds.rtps.message:encode-original-writer-info guid big)))
      (multiple-value-bind (g s) (dds.rtps.message:parse-original-writer-info b2 0 24)
        (declare (ignore g))
        (%check :owi-bigsn (eql s big) "high-word SN round-trip mismatch")))
    ;; bounds: wrong length -> (nil nil), never an error/OOB
    (multiple-value-bind (g s) (dds.rtps.message:parse-original-writer-info body 0 20)
      (%check :owi-badlen (and (null g) (null s)) "len/=24 must yield (nil nil)"))
    t))

;;; DATA inline-QoS emit: Q-bit + ParameterList before payload (RTPS 2.5 §9.4.5.4).
;;; The nil path MUST be byte-identical to today; the non-nil path sets Q-bit and
;;; inserts the complete caller-supplied ParameterList (sentinel-terminated) between
;;; the 20-octet fixed prefix and the serializedPayload.

(defun* run-data-inline-qos-emit-test ()
    (function () t)
  "Test: write-data :inline-qos nil → byte-identical to no-arg form (Q-bit clear, no extra
   bytes); write-data :inline-qos <block> → Q-bit set, inline-QoS bytes precede payload,
   parse-data-body round-trips the payload and reports inline-QoS present.
   RTPS 2.5 §9.4.5.4."
  (let* ((arena (dds.core.arena:init-arena :bytes (* 256 1024)))
         (pool  (dds.core.arena:make-buffer-pool arena 512 4))
         (rid   dds.rtps.message:+entityid-participant+)
         (wid   dds.rtps.message:+entityid-unknown+)
         (sn    7)
         (payload (make-array 8 :element-type '(unsigned-byte 8)
                                :initial-contents '(0 #x11 0 0 #x2a 0 0 0)))
         ;; (a) nil-arg baseline — call without :inline-qos
         (buf-base (dds.core.arena:pool-acquire pool))
         (c-base   (dds.core.buffer:cursor buf-base :endianness :little))
         ;; (b) explicit nil — must equal (a) byte-for-byte
         (buf-nil  (dds.core.arena:pool-acquire pool))
         (c-nil    (dds.core.buffer:cursor buf-nil :endianness :little))
         ;; (c) with inline-QoS built via write-original-writer-info-parameter + sentinel
         (buf-iq   (dds.core.arena:pool-acquire pool))
         (c-iq     (dds.core.buffer:cursor buf-iq :endianness :little))
         ;; scratch buffer to capture the inline-QoS ParameterList bytes
         (scratch  (dds.core.arena:pool-acquire pool))
         (c-sc     (dds.core.buffer:cursor scratch :endianness :little))
         (guid     (make-array 16 :element-type '(unsigned-byte 8)
                               :initial-contents '(#x01 #x01 #x66 #xf2 #x8f #x4f #x79 #x5f
                                                   #xa0 #x8e #xcd #xa9 #x80 #x00 #x00 #x02))))
    ;; build inline-QoS block: PID_ORIGINAL_WRITER_INFO(28 bytes) + PID_SENTINEL(4 bytes) = 32
    (dds.rtps.message:write-original-writer-info-parameter c-sc guid 42)
    (dds.rtps.message:write-parameter-sentinel c-sc)
    (let* ((iq-len  (dds.core.buffer:cursor-position c-sc))  ; 32
           (iq-vec  (dds.core.buffer:octet-buffer-vec scratch))
           (iq-blob (make-array iq-len :element-type '(unsigned-byte 8))))
      (replace iq-blob iq-vec :end2 iq-len)
      ;; write the three variants
      (dds.rtps.message:write-data c-base rid wid sn payload 0 8)
      (dds.rtps.message:write-data c-nil  rid wid sn payload 0 8 :inline-qos nil)
      (dds.rtps.message:write-data c-iq   rid wid sn payload 0 8 :inline-qos iq-blob)
      (let ((len-base (dds.core.buffer:cursor-position c-base))
            (len-nil  (dds.core.buffer:cursor-position c-nil))
            (len-iq   (dds.core.buffer:cursor-position c-iq))
            (v-base   (dds.core.buffer:octet-buffer-vec buf-base))
            (v-nil    (dds.core.buffer:octet-buffer-vec buf-nil))
            (v-iq     (dds.core.buffer:octet-buffer-vec buf-iq)))
        ;; nil branch: byte-identical to no-arg baseline
        (%check :diq-nil-len  (= len-base len-nil)        "nil inline-qos must not change submsg length")
        (%check :diq-nil-bytes (loop for i below len-base always (= (aref v-base i) (aref v-nil i)))
                "nil inline-qos must be byte-identical to baseline")
        ;; Q-bit: flags byte is index 1 (flags field of submsg header)
        (%check :diq-qbit-clear (zerop (logand (aref v-base 1) dds.rtps.message:+data-flag-inline-qos+))
                "baseline must have Q-bit clear")
        (%check :diq-qbit-set   (not (zerop (logand (aref v-iq 1) dds.rtps.message:+data-flag-inline-qos+)))
                "inline-qos branch must set Q-bit")
        ;; inline-QoS branch: total length = 4(header) + 20(body-prefix) + 32(iq) + 8(payload)
        (%check :diq-iq-len (= len-iq (+ 4 20 iq-len 8)) "inline-QoS submsg length accounting")
        ;; inline-QoS bytes precede payload: bytes [24, 24+iq-len) must equal iq-blob
        (%check :diq-iq-bytes
                (loop for i below iq-len always (= (aref v-iq (+ 24 i)) (aref iq-blob i)))
                "inline-QoS bytes must appear between body-prefix and payload")
        ;; payload round-trip via parse-data-body
        (dds.core.buffer:cursor-reset c-iq)
        (multiple-value-bind (id flags octets le) (dds.rtps.message:parse-submessage-header c-iq)
          (declare (ignore id le))
          (multiple-value-bind (r w psn has poff plen key ck pkh psf)
              (dds.rtps.message:parse-data-body c-iq flags octets)
            (declare (ignore r w ck pkh psf))
            (%check :diq-parse-sn    (= psn sn)   "parse-data-body SN round-trip")
            (%check :diq-parse-has   has           "parse-data-body has-payload")
            (%check :diq-parse-key   (not key)     "parse-data-body key-flag clear")
            (%check :diq-parse-len   (= plen 8)    "parse-data-body payload length")
            (%check :diq-parse-payload
                    (loop for i below 8
                          always (= (aref v-iq (+ poff i)) (aref payload i)))
                    "payload bytes round-trip after inline-QoS")
            ;; parse-data-body must report inline-QoS was present (key-hash and status-flags
            ;; from parse-inline-qos-key-status are the indicators — the iq block contains
            ;; PID_ORIGINAL_WRITER_INFO which is not PID_KEY_HASH/PID_STATUS_INFO, so
            ;; key-hash=nil status-flags=0, but parse-data-body must NOT return nil (it must
            ;; successfully walk the unknown pid and reach the sentinel)
            (%check :diq-flags-qset
                    (logtest flags dds.rtps.message:+data-flag-inline-qos+)
                    "parsed flags must have Q-bit set")))))
    (dds.core.arena:teardown-arena arena)
    t))

;;; Original-GUID per-SN dedup gate (WP-DURABILITY-DEDUP, RTPS 2.5 §8.3.5.4).

(defun* run-original-writer-dedup-test ()
    (function () t)
  "Unit test for reader-dedup-accept-p: watermark semantics + independence + boundedness.
   SN sequence 1,2,2,1,3 -> T,T,NIL,NIL,T (SN 2 repeated is dup; SN 1 is below watermark
   after 1+2 compact LO to 2; SN 3 continues). A different originalGUID tracked independently.
   Nil guid always returns T without touching the map. Boundedness: 1000 in-order SNs yield
   an empty ABOVE set (LO advances through every prefix, O(1)/GUID, NFR-MEM)."
  (let* ((reader  (dds.rtps.reliable:make-rtps-reader))
         (guid-a  (make-array 16 :element-type '(unsigned-byte 8) :initial-element #xAA))
         (guid-b  (make-array 16 :element-type '(unsigned-byte 8) :initial-element #xBB)))
    ;; PID-absent path: nil guid ALWAYS returns T, map never touched
    (%check :dedup-nil-1 (eq t (dds.rtps.reliable:reader-dedup-accept-p reader nil nil))
            "nil guid must return T (no PID, normal path)")
    (%check :dedup-nil-2 (eq t (dds.rtps.reliable:reader-dedup-accept-p reader nil 99))
            "nil guid with non-nil sn must still return T")
    (%check :dedup-nil-map-empty
            (zerop (hash-table-count (dds.rtps.reliable:rtps-reader-dedup-map reader)))
            "nil guid must never touch the dedup map")
    ;; guid-a: SN 1 -> accept; SN 2 -> accept; both compact LO to 2, ABOVE stays empty
    (%check :dedup-a-sn1 (eq t (dds.rtps.reliable:reader-dedup-accept-p reader guid-a 1))
            "guid-a SN 1: first time -> T (accept)")
    (%check :dedup-a-sn2 (eq t (dds.rtps.reliable:reader-dedup-accept-p reader guid-a 2))
            "guid-a SN 2: not yet seen -> T (accept)")
    ;; guid-a: SN 2 again -> exact duplicate -> NIL (in the compacted LO range)
    (%check :dedup-a-sn2-dup (null (dds.rtps.reliable:reader-dedup-accept-p reader guid-a 2))
            "guid-a SN 2 repeat: below watermark -> NIL (discard)")
    ;; guid-a: SN 1 again -> below watermark -> NIL (LO = 2 after compaction)
    (%check :dedup-a-sn1-dup (null (dds.rtps.reliable:reader-dedup-accept-p reader guid-a 1))
            "guid-a SN 1 repeat: below watermark -> NIL")
    ;; guid-a: SN 3 -> not yet seen -> accept
    (%check :dedup-a-sn3 (eq t (dds.rtps.reliable:reader-dedup-accept-p reader guid-a 3))
            "guid-a SN 3: not yet seen -> T (accept)")
    ;; guid-b tracked INDEPENDENTLY: SN 1 still accepted (guid-b is a separate tracking entry)
    (%check :dedup-b-sn1 (eq t (dds.rtps.reliable:reader-dedup-accept-p reader guid-b 1))
            "guid-b SN 1: independent tracking -> T (accept)")
    ;; guid-b: SN 1 again -> duplicate for guid-b
    (%check :dedup-b-sn1-dup (null (dds.rtps.reliable:reader-dedup-accept-p reader guid-b 1))
            "guid-b SN 1 repeat: duplicate -> NIL")
    ;; outer map has exactly 2 entries (guid-a + guid-b), nil path left map untouched
    (%check :dedup-map-size
            (= 2 (hash-table-count (dds.rtps.reliable:rtps-reader-dedup-map reader)))
            "dedup outer map must have exactly 2 entries after guid-a + guid-b (nil left none)")
    ;; Boundedness: 1000 in-order SNs -> ABOVE stays EMPTY (watermark advances, O(1)/GUID, NFR-MEM)
    (let* ((reader2 (dds.rtps.reliable:make-rtps-reader))
           (guid-c  (make-array 16 :element-type '(unsigned-byte 8) :initial-element #xCC)))
      (loop for sn from 1 to 1000
            do (dds.rtps.reliable:reader-dedup-accept-p reader2 guid-c sn))
      (let* ((origin (gethash guid-c (dds.rtps.reliable:rtps-reader-dedup-map reader2)))
             (marked (dds.rtps.reliable::dedup-origin-marked origin))
             (bits   (dds.rtps.reliable::dedup-origin-bits origin)))
        (%check :dedup-inorder-above-empty (zerop marked)
                (format nil "in-order delivery must record NOTHING out-of-order (got ~d marked)" marked))
        ;; Stronger than the old ABOVE-is-empty check: in-order traffic must not even ALLOCATE the window.
        (%check :dedup-inorder-no-window (null bits)
                "in-order delivery must never allocate the out-of-order bit window (LO just advances)")))
    t))

;;; Cap/shedding path: proves lo never jumps a hole and no fresh SN is ever discarded.

(defun* run-dedup-cap-test ()
    (function () t)
  "Unit test for reader-dedup-accept-p at-cap shedding.  Uses *max-gap-range* = 4.
   Setup: deliver SNs 1..4 in order (lo advances to 4, above empty).  Then deliver SNs
   9,8,7,6 out-of-order, filling above to the cap.  SN 5 is deliberately withheld (the gap).
   SN 5+ causes the cap to trigger on the next out-of-order SN.
   Assertions: (1) every fresh SN is accepted (T); (2) lo stays at 4 after the cap path
   (never jumps the withheld SN 5); (3) when SN 5 later arrives it is ACCEPTED (T) — no
   silent loss; (4) lo then advances through the compacted run; (5) the shed high SN is
   re-admitted on re-arrival (benign duplicate, not silent loss)."
  (let* ((reader (dds.rtps.reliable:make-rtps-reader))
         (guid   (make-array 16 :element-type '(unsigned-byte 8) :initial-element #xDD)))
    (let ((dds.rtps.reliable:*max-gap-range* 4))
      ;; SNs 1..4 in order: lo advances to 4, above stays empty
      (loop for sn from 1 to 4
            do (%check (intern (format nil "DEDUP-CAP-INORDER-~d" sn) :keyword)
                       (eq t (dds.rtps.reliable:reader-dedup-accept-p reader guid sn))
                       (format nil "SN ~d (in-order) -> T" sn)))
      ;; Deliver SNs 9,8,7,6 — all above the withheld gap SN 5; fills above to {6,7,8,9}
      (%check :dedup-cap-sn9 (eq t (dds.rtps.reliable:reader-dedup-accept-p reader guid 9))
              "SN 9 out-of-order fresh -> T")
      (%check :dedup-cap-sn8 (eq t (dds.rtps.reliable:reader-dedup-accept-p reader guid 8))
              "SN 8 out-of-order fresh -> T")
      (%check :dedup-cap-sn7 (eq t (dds.rtps.reliable:reader-dedup-accept-p reader guid 7))
              "SN 7 out-of-order fresh -> T")
      (%check :dedup-cap-sn6 (eq t (dds.rtps.reliable:reader-dedup-accept-p reader guid 6))
              "SN 6 out-of-order fresh -> T; above = {6,7,8,9} = cap (4)")
      ;; above = {6,7,8,9} = cap (4); lo = 4. SN 10 overflows: shed highest (9), admit 10.
      (%check :dedup-cap-sn10 (eq t (dds.rtps.reliable:reader-dedup-accept-p reader guid 10))
              "SN 10 -> T; triggers cap: shed highest (10) -> above={6,7,8,9}")
      ;; KEY: lo must still be 4 (SN 5 never arrived; cap MUST NOT have jumped the hole)
      (let* ((origin (gethash guid (dds.rtps.reliable:rtps-reader-dedup-map reader)))
             (lo-val (dds.rtps.reliable::dedup-origin-lo origin)))
        (%check :dedup-cap-lo-stable (= lo-val 4)
                (format nil "lo must be 4 (SN 5 never arrived, cap must not jump hole); got ~d" lo-val)))
      ;; SN 5 (the withheld gap SN) now arrives — must be ACCEPTED (T), never silently lost
      (%check :dedup-cap-gap-sn5 (eq t (dds.rtps.reliable:reader-dedup-accept-p reader guid 5))
              "SN 5 (withheld gap SN) -> T (no silent loss)")
      ;; After SN 5, the contiguous prefix 5,6,7,8 compacts into lo (9 was shed, so lo stops at 8;
      ;; above = {10}).  lo = 8.
      (let* ((origin (gethash guid (dds.rtps.reliable:rtps-reader-dedup-map reader)))
             (lo-val (dds.rtps.reliable::dedup-origin-lo origin)))
        (%check :dedup-cap-lo-after-gap (= lo-val 8)
                (format nil "lo must be 8 after SN 5 arrives (prefix 5..8 compact; 9 shed); got ~d" lo-val)))
      ;; SN 9 was shed; re-arrival must be accepted (benign duplicate of a high out-of-order SN)
      (%check :dedup-cap-shed-readmit (eq t (dds.rtps.reliable:reader-dedup-accept-p reader guid 9))
              "SN 9 (shed entry) re-arrives -> T (benign duplicate, not silent loss)"))
    t))

(defun* run-vendor-sedp-pid-test ()
    (function () t)
  "PID_ENTITY_VIRTUAL_GUID (0x8002) + PID_SERVICE_KIND (0x8003) byte-exact emit + round-trip
   in a SEDP ParameterList. Verifies that a relay endpoint-data with service-kind = PERSISTENCE_SERVICE
   emits both PIDs correctly (ADR 0024 Task 8; RTI vendor PIDs, spike 2026-06-18)."
  ;; Build a relay endpoint-data with entity-virtual-guid + service-kind set.
  (let* ((vguid (make-array 16 :element-type '(unsigned-byte 8)
                            :initial-contents '(#x01 #x01 #x93 #xbb #x4d #x4e #x9f #xa4
                                                #xac #x3c #x26 #x96 #x80 #x00 #x00 #x02)))
         (ep (dds.rtps.discovery:make-endpoint-data
              :role :writer
              :guid (make-array 16 :element-type '(unsigned-byte 8) :initial-element 1)
              :topic-name "Square" :type-name "ShapeType"
              :entity-virtual-guid vguid
              :service-kind dds.rtps.message:+service-kind-persistence+))
         (ob (dds.core.buffer:make-octet-buffer 512))
         (wc (dds.core.buffer:cursor ob :endianness :little))
         (vec (dds.core.buffer:octet-buffer-vec ob)))
    (dds.rtps.discovery:serialize-endpoint-data wc ep)
    (let ((end (dds.core.buffer:cursor-position wc)))
      ;; Locate PID_ENTITY_VIRTUAL_GUID (0x8002 LE = #x02 #x80) in the ParameterList.
      (let ((at-vg (loop for i from 0 to (- end 20)
                         when (and (= (aref vec i) #x02) (= (aref vec (1+ i)) #x80)
                                   (= (aref vec (+ i 2)) #x10) (= (aref vec (+ i 3)) #x00))
                           return i)))
        (%check :vguid-present at-vg "PID_ENTITY_VIRTUAL_GUID (02 80 10 00) not found in SEDP ParameterList")
        (when at-vg
          ;; Value bytes [4..19] must equal vguid verbatim.
          (dotimes (k 16)
            (%check (intern (format nil "VGUID-BYTE-~d" k) :keyword)
                    (= (aref vec (+ at-vg 4 k)) (aref vguid k))
                    (format nil "PID_ENTITY_VIRTUAL_GUID byte ~d mismatch: got #x~2,'0x expected #x~2,'0x"
                            k (aref vec (+ at-vg 4 k)) (aref vguid k))))))
      ;; Locate PID_SERVICE_KIND (0x8003 LE = #x03 #x80) in the ParameterList.
      (let ((at-sk (loop for i from 0 to (- end 8)
                         when (and (= (aref vec i) #x03) (= (aref vec (1+ i)) #x80)
                                   (= (aref vec (+ i 2)) #x04) (= (aref vec (+ i 3)) #x00))
                           return i)))
        (%check :service-kind-present at-sk
                "PID_SERVICE_KIND (03 80 04 00) not found in SEDP ParameterList")
        (when at-sk
          ;; Value = 1 (PERSISTENCE_SERVICE_QOS) as u32 LE = #x01 #x00 #x00 #x00.
          (%check :service-kind-value-byte0 (= (aref vec (+ at-sk 4)) #x01)
                  (format nil "PID_SERVICE_KIND[0] got #x~2,'0x want #x01" (aref vec (+ at-sk 4))))
          (%check :service-kind-value-bytes1-3
                  (and (= (aref vec (+ at-sk 5)) 0)
                       (= (aref vec (+ at-sk 6)) 0)
                       (= (aref vec (+ at-sk 7)) 0))
                  "PID_SERVICE_KIND bytes [1..3] must be zero (u32 LE)"))))
    ;; Round-trip: parse back and verify the fields survive.
    (let* ((rc (dds.core.buffer:cursor ob :endianness :little))
           (back (dds.rtps.discovery:parse-endpoint-data rc :writer)))
      (%check :vendor-sedp-roundtrip-vguid
              (and back (equalp (dds.rtps.discovery:endpoint-data-entity-virtual-guid back) vguid))
              "entity-virtual-guid must round-trip through SEDP parse")
      (%check :vendor-sedp-roundtrip-sk
              (and back (= (dds.rtps.discovery:endpoint-data-service-kind back)
                           dds.rtps.message:+service-kind-persistence+))
              "service-kind must round-trip as +service-kind-persistence+"))
    ;; Absent case: a non-relay endpoint must NOT emit either PID.
    (let* ((plain (dds.rtps.discovery:make-endpoint-data
                   :role :writer :topic-name "Square" :type-name "ShapeType"
                   :guid (make-array 16 :element-type '(unsigned-byte 8) :initial-element 2)))
           (ob2 (dds.core.buffer:make-octet-buffer 512))
           (wc2 (dds.core.buffer:cursor ob2 :endianness :little))
           (vec2 (dds.core.buffer:octet-buffer-vec ob2)))
      (dds.rtps.discovery:serialize-endpoint-data wc2 plain)
      (let ((end2 (dds.core.buffer:cursor-position wc2)))
        (%check :no-vguid-on-plain
                (not (loop for i from 0 to (- end2 4)
                           when (and (= (aref vec2 i) #x02) (= (aref vec2 (1+ i)) #x80)) return t))
                "PID_ENTITY_VIRTUAL_GUID must NOT appear in a non-relay endpoint")
        (%check :no-sk-on-plain
                (not (loop for i from 0 to (- end2 4)
                           when (and (= (aref vec2 i) #x03) (= (aref vec2 (1+ i)) #x80)) return t))
                "PID_SERVICE_KIND must NOT appear in a non-relay endpoint")))
    t))

(defun* run-reader-concurrent-receivers-test ()
    (function () t)
  "Regression: ONE rtps-reader driven by SEVERAL threads at once, which is what a live node actually does —
   start-node runs up to THREE receiver threads (unicast UDP, multicast UDP, SHMEM) and they ALL feed
   %handle-datagram, which lands in reader-on-data / reader-dedup-accept-p with no enclosing lock. The
   reader-side docstrings used to assume a 'single receiver thread per proxy' discipline that does not exist.

   Every thread offers the SAME (GUID, SN) set, so the three properties below are exactly the ones the
   unsynchronized engine broke:
   (1) EXACTLY-ONCE (RTPS 2.5 §8.3.5.4). reader-dedup-accept-p is a seen-test-then-mark; unlocked, two
       threads both find an SN unseen and BOTH return T, so the sample is delivered twice. The accept
       counts summed over all threads must be exactly the number of distinct SNs — not more.
   (2) NO LOST PROXY. get-writer-proxy is (or (gethash k) (setf (gethash k) ...)); unlocked, two threads
       both miss and both construct, and one proxy — with every received-SN marker written into it — is
       silently dropped, so the reader NACKs samples it already holds.
   (3) NO LOST MARKER. Every SN offered must be present in RECEIVED, and LAST-SN must be the true maximum
       (it is updated by a read-compare-write that interleaves into a lost update).

   FALSIFIED, seen red, not assumed: with the reader lock removed from %get-writer-proxy and
   reader-dedup-accept-p this fails :rxrace-dedup-exactly-once (accepts exceed the SN count) and
   :rxrace-markers (RECEIVED short of the SNs offered)."
  (let* ((reader (dds.rtps.reliable:make-rtps-reader))
         (guid (make-array 16 :element-type '(unsigned-byte 8) :initial-element #xC7))
         (payload (make-array 0 :element-type '(unsigned-byte 8)))
         (n-threads 4)
         (n-sns 500)
         (accepts (make-array n-threads :initial-element 0))
         (go-flag (list nil)))
    (let ((threads (loop for i below n-threads
                         collect (let ((idx i))
                                   (dds.pal:spawn
                                    (lambda ()
                                      (loop until (car go-flag))   ; release them together: skewed starts do not race
                                      (let ((accepted 0))
                                        (dotimes (s n-sns)
                                          (let ((sn (1+ s)))
                                            (dds.rtps.reliable:reader-on-data reader guid sn payload)
                                            (when (dds.rtps.reliable:reader-dedup-accept-p reader guid sn)
                                              (incf accepted))))
                                        (setf (aref accepts idx) accepted)))
                                    :name "rx-race")))))
      (setf (car go-flag) t)
      (dolist (th threads) (dds.pal:join th)))
    (let* ((total (reduce #'+ accepts))
           (proxies (dds.rtps.reliable::rtps-reader-proxies reader))   ; internal: the proxy TABLE is not part of the exported surface
           (proxy (dds.rtps.reliable:get-writer-proxy reader guid))
           (received (dds.rtps.reliable:writer-proxy-received proxy)))
      (%check :rxrace-dedup-exactly-once
              (= total n-sns)
              (format nil "~d threads offering the same ~d SNs must yield EXACTLY ~d accepts in total (exactly-once, RTPS 2.5 §8.3.5.4); got ~d"
                      n-threads n-sns n-sns total))
      (%check :rxrace-single-proxy
              (= 1 (hash-table-count proxies))
              (format nil "one writer GUID must yield exactly ONE WriterProxy however many threads race its creation; got ~d"
                      (hash-table-count proxies)))
      (%check :rxrace-markers
              (= n-sns (hash-table-count received))
              (format nil "every offered SN must survive in RECEIVED (a dropped proxy loses its markers and the reader re-NACKs); expected ~d, got ~d"
                      n-sns (hash-table-count received)))
      (%check :rxrace-last-sn
              (= n-sns (dds.rtps.reliable:writer-proxy-last-sn proxy))
              (format nil "LAST-SN is a read-compare-write and must not lose an update; expected ~d, got ~d"
                      n-sns (dds.rtps.reliable:writer-proxy-last-sn proxy))))
    t))

(defun* run-dedup-origin-cap-test ()
    (function () t)
  "Resource-exhaustion guard on the dedup ORIGIN table (NFR-SEC-POSTURE; RTPS 2.5 §8.3.5.4).

   The key this table is grown by is WIRE-SUPPLIED — the GUID inside PID_ORIGINAL_WRITER_INFO in a DATA's
   inline QoS — so without a cap any peer able to send us a DATA mints unbounded dedup-origins, each with
   its own out-of-order window, simply by varying it. That is an unbounded memory DoS keyed by attacker
   data. *max-dedup-origins* caps it.

   The direction of the refusal is the point and is asserted here: at the cap a new origin is NOT tracked,
   but its sample is still ACCEPTED (T). Refusing to track risks a duplicate; refusing to deliver would be
   silent loss, and a false reject is the worse failure. Tracked origins are never evicted to make room —
   evicting a watermark would risk double-delivering everything that origin had already dedup'd.

   FALSIFIED, seen red, not assumed: removing the cap check fails :dedup-origin-cap-bounded (the table
   grows to 6) and :dedup-origin-cap-counted (nothing is refused)."
  (let* ((reader (dds.rtps.reliable:make-rtps-reader))
         (cap 4))
    (flet ((guid (n) (make-array 16 :element-type '(unsigned-byte 8) :initial-element n)))
      (let ((dds.rtps.reliable:*max-dedup-origins* cap))
        ;; CAP distinct origins are tracked; each first sample accepted
        (loop for n from 1 to cap
              do (%check (intern (format nil "DEDUP-ORIGIN-CAP-TRACKED-~d" n) :keyword)
                         (eq t (dds.rtps.reliable:reader-dedup-accept-p reader (guid n) 1))
                         (format nil "origin ~d (within cap) SN 1 -> T" n)))
        ;; a tracked origin still dedups
        (%check :dedup-origin-cap-still-dedups
                (null (dds.rtps.reliable:reader-dedup-accept-p reader (guid 1) 1))
                "a TRACKED origin must still reject its duplicate SN 1")
        ;; two origins beyond the cap: ACCEPTED (never dropped) but NOT tracked
        (%check :dedup-origin-cap-overflow-accepted-1
                (eq t (dds.rtps.reliable:reader-dedup-accept-p reader (guid 90) 1))
                "an origin beyond the cap must still be ACCEPTED (untracked, never silently lost)")
        (%check :dedup-origin-cap-overflow-accepted-2
                (eq t (dds.rtps.reliable:reader-dedup-accept-p reader (guid 91) 1))
                "a second origin beyond the cap must also be ACCEPTED")
        ;; an untracked origin cannot dedup — the documented residual, asserted so it stays documented
        (%check :dedup-origin-cap-untracked-residual
                (eq t (dds.rtps.reliable:reader-dedup-accept-p reader (guid 90) 1))
                "an UNTRACKED origin's repeat is accepted again — the documented duplicate residual")
        (let ((n (hash-table-count (dds.rtps.reliable:rtps-reader-dedup-map reader))))
          (%check :dedup-origin-cap-bounded (= n cap)
                  (format nil "the origin table must stay at the cap ~d however many GUIDs arrive; got ~d" cap n)))
        (%check :dedup-origin-cap-not-evicted
                (null (dds.rtps.reliable:reader-dedup-accept-p reader (guid 1) 1))
                "a tracked origin must NOT have been evicted to admit a new one (its dedup state survives)")
        (let ((refused (dds.rtps.reliable:reader-dedup-origins-refused reader)))
          (%check :dedup-origin-cap-counted (= refused 3)
                  (format nil "refusals must be COUNTED and readable (expected 3, got ~d)" refused)))))
    t))

(defun* %app-ack-body (vw-count intervals &key (trailing-count 7))
    (function (integer list &key (:trailing-count integer))
              (simple-array (unsigned-byte 8) (*)))
  "Build an APP_ACK body (ADR 0090 layout) with VW-COUNT declared and INTERVALS actually written, each
   (first last flags payload-len). Declaring a count that disagrees with what follows is the POINT: it is
   how a hostile peer drives the parser's loops past the end of the buffer."
  (let* ((buf (make-array 4096 :element-type '(unsigned-byte 8) :initial-element 0))
         (ob (dds.core.buffer:octet-buffer-over buf))
         (c (dds.core.buffer:cursor ob :endianness :little)))
    (dolist (b '(#x80 #x00 #x00 #x07 #x80 #x00 #x00 #x02)) (dds.core.buffer:put-u8 c b))
    (dds.core.buffer:put-u32 c (ldb (byte 32 0) vw-count))
    (when intervals
      (dotimes (i 16) (declare (ignorable i)) (dds.core.buffer:put-u8 c #xAA))   ; virtualWriterGuid
      (dds.core.buffer:put-u16 c (ldb (byte 16 0) (length intervals)))        ; intervalCount
      (dds.core.buffer:put-u16 c 0)                                          ; octetsToNextVirtualWriter
      (dolist (iv intervals)
        (destructuring-bind (first last flags plen) iv
          (dds.core.buffer:put-u32 c 0) (dds.core.buffer:put-u32 c first)
          (dds.core.buffer:put-u32 c 0) (dds.core.buffer:put-u32 c last)
          (dds.core.buffer:put-u16 c (ldb (byte 16 0) flags))
          (dds.core.buffer:put-u16 c (ldb (byte 16 0) plen)))))
    (dds.core.buffer:put-u32 c (ldb (byte 32 0) trailing-count))
    (subseq buf 0 (dds.core.buffer:cursor-position c))))

(defun* %parse-app-ack-octets (octets)
    (function ((array (unsigned-byte 8) (*))) t)
  "Run PARSE-APP-ACK-BODY over OCTETS. Returns the reader-id (non-NIL = accepted) or NIL (rejected)."
  (let* ((ob (dds.core.buffer:octet-buffer-over (coerce octets '(simple-array (unsigned-byte 8) (*)))))
         (c (dds.core.buffer:cursor ob :endianness :little)))
    (dds.rtps.message:parse-app-ack-body c 0 (lambda (&rest r) (declare (ignore r)) nil))))

(defun* run-app-ack-hostile-test ()
    (function () t)
  "ADR 0090 / NFR-SEC-POSTURE: PARSE-APP-ACK-BODY faces the NETWORK, so a malformed or hostile APP_ACK
   must yield NIL — never an out-of-bounds read, never an unbounded walk, never a partial accept.

   THE STRUCTURAL HAZARD IS THAT THIS SUBMESSAGE CARRIES ITS OWN LOOP BOUNDS. virtualWriterCount and
   intervalCount come straight off the wire and drive nested loops, so a peer that sends 0x7fffffff
   dictates how long we spin. That is remotely-drivable CPU, in the same family as the relay-dedup defect
   fixed at 65d87fe. Both counts are also SIGNED in RTI's layout, so reading them unsigned would turn a
   negative into an enormous bound — which is why the parser uses %read-i32/%read-i16 and rejects on
   MINUSP rather than trusting the value.

   A partially-parsed acknowledgment is worse than none at all: under APP-ACK semantics a writer that
   believes a sample acknowledged may purge it, so a truncated body that yielded 'some intervals' would
   be silent data loss. Every rejection below is therefore total.

   FALSIFIED: remove either count guard in parse-app-ack-body and the corresponding check hangs or fails."
  ;; the shapes a real peer sends still parse
  (%check :aa-good-single
          (%parse-app-ack-octets (%app-ack-body 1 '((1 1 #x0000 0))))
          "a well-formed single-interval APP_ACK must parse")
  (%check :aa-good-multi
          (%parse-app-ack-octets (%app-ack-body 1 '((1 1 #x0100 0) (2 2 #x0000 0))))
          "a well-formed two-interval APP_ACK must parse")
  ;; wire-supplied loop bounds
  (%check :aa-huge-vw-count
          (null (%parse-app-ack-octets (%app-ack-body #x7fffffff '((1 1 0 0)))))
          "an absurd virtualWriterCount must be REJECTED, not walked — it is remotely-drivable CPU")
  (%check :aa-negative-vw-count
          (null (%parse-app-ack-octets (%app-ack-body #xffffffff '((1 1 0 0)))))
          "a NEGATIVE virtualWriterCount (0xffffffff read signed) must be rejected; read unsigned it would be ~4 billion iterations")
  (%check :aa-huge-interval-count
          (null (%parse-app-ack-octets
                 (let ((b (%app-ack-body 1 '((1 1 0 0)))))
                   (setf (aref b 28) #xff (aref b 29) #x7f)   ; intervalCount := 0x7fff
                   b)))
          "an intervalCount far beyond the body must be rejected")
  ;; truncation at every length
  (let ((full (%app-ack-body 1 '((1 1 #x0100 0) (2 2 #x0000 0)))) (survived 0))
    (dotimes (n (length full))
      (when (%parse-app-ack-octets (subseq full 0 n)) (incf survived)))
    (%check :aa-truncation
            (zerop survived)
            (format nil "every TRUNCATION of a valid body must be rejected (~d prefix(es) were accepted)" survived)))
  ;; a payload length that runs off the end
  (%check :aa-payload-overrun
          (null (%parse-app-ack-octets (%app-ack-body 1 '((1 1 #x0000 4096)))))
          "an intervalPayloadLength beyond the buffer must be rejected, not read past the end")
  ;; random octets: never a crash, never a partial accept that reads OOB
  (let ((accepted 0))
    (dotimes (i 2000)
      (let ((v (make-array (+ 12 (mod i 90)) :element-type '(unsigned-byte 8))))
        (dotimes (j (length v)) (setf (aref v j) (random 256)))
        (when (%parse-app-ack-octets v) (incf accepted))))
    (%check :aa-fuzz-safe t
            (format nil "2000 random bodies parsed without OOB or hang (~d structurally acceptable)" accepted)))
  t)
