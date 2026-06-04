(in-package #:dds.tests)

;;; M2 increment 1: RTPS Message Header + SubmessageHeader + EntityId byte-exact
;;; against RTPS 2.5 (§9.4.4 / §9.4.5.1 / §9.3.1.2). The wire-layer analogue of
;;; the byte-exact CDR corpus; values pinned from docs/specs, not memory.

(declaim (ftype (function () t) run-rtps-wire-test))
(defun run-rtps-wire-test ()
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

(declaim (ftype (function () t) run-rtps-data-test))
(defun run-rtps-data-test ()
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

;;; RTPS message framing: build Header + DATA + HEARTBEAT into one buffer, then
;;; dispatch-message walks the submessages back out (RTPS 2.5 §8.3.4 / §9.4.5).

(declaim (ftype (function () t) run-rtps-dispatch-test))
(defun run-rtps-dispatch-test ()
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

(declaim (ftype (function () t) run-paramlist-test))
(defun run-paramlist-test ()
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

(declaim (ftype (function () t) run-port-mapping-test))
(defun run-port-mapping-test ()
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

(declaim (ftype (function () t) run-history-test))
(defun run-history-test ()
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

(declaim (ftype (function () t) run-reliability-test))
(defun run-reliability-test ()
  (let* ((writer (dds.rtps.reliable:make-rtps-writer
                  :hc (dds.rtps.history:make-history-cache :keep-all 1 nil nil)))
         (reader (dds.rtps.reliable:make-rtps-reader))
         (wid 1) (rid 2) (n 10))
    (dotimes (i n) (dds.rtps.reliable:writer-write writer (format nil "m~d" (1+ i))))
    (labels ((deliver (sn payload round)
               (when (or (>= round 3) (zerop (logand 1 (+ (* sn 7) (* round 13)))))
                 (dds.rtps.reliable:reader-on-data reader wid sn payload))))
      ;; initial blast: reversed (reorder) + a duplicate delivery of SN 1
      (deliver 1 "m1" 0)
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

(declaim (ftype (function () t) run-gap-handling-test))
(defun run-gap-handling-test ()
  (let* ((writer (dds.rtps.reliable:make-rtps-writer
                  :hc (dds.rtps.history:make-history-cache :keep-last 2 nil nil)))
         (reader (dds.rtps.reliable:make-rtps-reader))
         (wid 1) (rid 2))
    (dotimes (i 5) (dds.rtps.reliable:writer-write writer (format nil "m~d" (1+ i))))  ; hc holds 4,5
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

(declaim (ftype (function () t) run-rtps-submessage-test))
(defun run-rtps-submessage-test ()
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

(declaim (ftype (function () t) run-rtps-seqnum-test))
(defun run-rtps-seqnum-test ()
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
