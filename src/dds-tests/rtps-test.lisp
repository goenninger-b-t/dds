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
      (dolist (cell (reverse (dds.rtps.reliable:writer-data-list writer rid)))
        (deliver (car cell) (cdr cell) 0))
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
              (dolist (cell resends) (deliver (car cell) (cdr cell) (1+ round))))))
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
        (%check :gap-resends (equal '(4 5) (mapcar #'car resends)) "present SNs resent")
        (%check :gap-gaps (equal '(1 2 3) gaps) "evicted SNs gapped")
        (dolist (cell resends) (dds.rtps.reliable:reader-on-data reader wid (car cell) (cdr cell)))
        (dds.rtps.reliable:reader-on-gap
         reader wid 1 4 0 (make-array 1 :element-type '(unsigned-byte 32) :initial-element 0))
        (%check :gap-complete (dds.rtps.reliable:reader-complete-p reader wid)
                "reader complete after GAP(1..3) + DATA(4,5)")))
    t))

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

;;; NACK_FRAG round-trip (RTPS 2.5 §9.4.5.14): 24+4*M body, only E flag.

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
      (%check :nf-octets (= octets 28) "NACK_FRAG body length 24+4*1=28")
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
