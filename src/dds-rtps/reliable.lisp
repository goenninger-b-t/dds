(in-package #:dds.rtps.reliable)

;;;; Stateful reliable writer/reader protocol logic (RTPS 2.5 §8.4). Operates on
;;;; submessage field VALUES (not bytes) so the state machines are directly
;;;; testable; the byte/transport wiring is a later increment. CLOS-free; the
;;;; consing here (per-reader proxies, resend lists) is a documented v1 concern.

;;; ---- Writer side (§8.4.2): one ReaderProxy per matched reader ----

(defstruct* (reader-proxy (:constructor make-reader-proxy))
  "Writer-side proxy for one matched reader (RTPS 2.5 §8.4.2). ACKED-BASE is the
   reader's acknowledged watermark: it has acknowledged all SN < acked-base."
  (acked-base 1 :type integer))            ; reader has acknowledged all SN < acked-base

(defstruct* (rtps-writer (:constructor make-rtps-writer))
  "Stateful reliable RTPS writer (RTPS 2.5 §8.4.2): a HistoryCache, the last SN
   written, the HEARTBEAT count, and a reader-id -> ReaderProxy table."
  (hc nil :type t)                                  ; a HistoryCache
  (last-sn 0 :type integer)
  (hb-count 0 :type integer)
  (proxies (make-hash-table :test 'eql) :type hash-table))   ; reader-id -> reader-proxy

(defun* get-reader-proxy (writer reader-id)
    (function (rtps-writer (unsigned-byte 32)) reader-proxy)
  "The ReaderProxy for READER-ID, created on first use."
  (or (gethash reader-id (rtps-writer-proxies writer))
      (setf (gethash reader-id (rtps-writer-proxies writer)) (make-reader-proxy))))

(defun* writer-write (writer payload)
    (function (rtps-writer t) integer)
  "Add a new change to the writer's HistoryCache; return its sequence number."
  (let ((sn (incf (rtps-writer-last-sn writer))))
    (dds.rtps.history:hc-add-change
     (rtps-writer-hc writer)
     (dds.rtps.history:make-cache-change :sn sn :serialized-payload payload))
    sn))

(defun* writer-heartbeat (writer)
    (function (rtps-writer) (values integer integer integer))
  "Return (values firstSN lastSN count) for a HEARTBEAT (RTPS 2.5 §8.3.7.5)."
  (values (or (dds.rtps.history:hc-min-seq (rtps-writer-hc writer)) 1)
          (or (dds.rtps.history:hc-max-seq (rtps-writer-hc writer)) 0)
          (incf (rtps-writer-hb-count writer))))

(defun* writer-data-list (writer reader-id)
    (function (rtps-writer (unsigned-byte 32)) list)
  "Changes not yet acked by READER-ID, as a list of (sn . payload) in SN order."
  (let ((base (reader-proxy-acked-base (get-reader-proxy writer reader-id))))
    (loop for ch in (dds.rtps.history:hc-changes-for-reader (rtps-writer-hc writer) nil)
          when (>= (dds.rtps.history:cache-change-sn ch) base)
            collect (cons (dds.rtps.history:cache-change-sn ch)
                          (dds.rtps.history:cache-change-serialized-payload ch)))))

(defun* writer-on-acknack (writer reader-id base numbits bitmap)
    (function (rtps-writer (unsigned-byte 32) integer (unsigned-byte 32) (simple-array (unsigned-byte 32) (*))) (values list list))
  "Process an ACKNACK from READER-ID (RTPS 2.5 §8.3.7.1). Confirm SN < BASE, then
   for each NACKed SN (bit set in BITMAP) return a resend if present, else a GAP.
   Returns (values data-resends gap-sns), data-resends a list of (sn . payload)."
  (let ((proxy (get-reader-proxy writer reader-id))
        (resends '())
        (gaps '()))
    (setf (reader-proxy-acked-base proxy) (max (reader-proxy-acked-base proxy) base))
    (dotimes (i numbits)
      (when (dds.rtps.message:seqnum-set-bit-p bitmap i)
        (let* ((sn (+ base i))
               (ch (dds.rtps.history:hc-get-change (rtps-writer-hc writer) sn)))
          (if ch
              (push (cons sn (dds.rtps.history:cache-change-serialized-payload ch)) resends)
              (push sn gaps)))))
    (values (nreverse resends) (nreverse gaps))))

;;; ---- Reader side (§8.4.10): one WriterProxy per matched writer ----

(defstruct* (writer-proxy (:constructor make-writer-proxy))
  "Reader-side proxy for one matched writer (RTPS 2.5 §8.4.10). RECEIVED maps SN ->
   payload | :gap; FIRST-SN/LAST-SN bound the available range from HEARTBEAT."
  (received (make-hash-table :test 'eql) :type hash-table)   ; SN -> payload | :gap
  (first-sn 1 :type integer)
  (last-sn 0 :type integer))                ; available range from HEARTBEAT

(defstruct* (rtps-reader (:constructor make-rtps-reader))
  "Stateful reliable RTPS reader (RTPS 2.5 §8.4.10): a writer-id -> WriterProxy table."
  (proxies (make-hash-table :test 'eql) :type hash-table))   ; writer-id -> writer-proxy

(defun* get-writer-proxy (reader writer-id)
    (function (rtps-reader (unsigned-byte 32)) writer-proxy)
  "The WriterProxy for WRITER-ID, created on first use."
  (or (gethash writer-id (rtps-reader-proxies reader))
      (setf (gethash writer-id (rtps-reader-proxies reader)) (make-writer-proxy))))

(defun* reader-on-data (reader writer-id sn payload)
    (function (rtps-reader (unsigned-byte 32) integer t) t)
  "Accept a DATA. Idempotent (duplicate SN overwrites — dedup); tracks the highest
   SN seen so reordered delivery is harmless (stored by SN)."
  (let ((proxy (get-writer-proxy reader writer-id)))
    (setf (gethash sn (writer-proxy-received proxy)) payload)
    (when (> sn (writer-proxy-last-sn proxy)) (setf (writer-proxy-last-sn proxy) sn))
    t))

(defun* reader-on-heartbeat (reader writer-id first-sn last-sn)
    (function (rtps-reader (unsigned-byte 32) integer integer) t)
  "Update the available range [firstSN, lastSN] (RTPS 2.5 §8.3.7.5)."
  (let ((proxy (get-writer-proxy reader writer-id)))
    (setf (writer-proxy-first-sn proxy) first-sn
          (writer-proxy-last-sn proxy) (max (writer-proxy-last-sn proxy) last-sn))
    t))

(defun* reader-acknack (reader writer-id)
    (function (rtps-reader (unsigned-byte 32)) (values integer (unsigned-byte 32) (simple-array (unsigned-byte 32) (*))))
  "Compute an ACKNACK (RTPS 2.5 §8.3.7.1): (values base numBits bitmap). BASE is
   the lowest unreceived SN in [first, last] (or last+1 if none); the bitmap NACKs
   the unreceived SNs in [base, last] (capped at 256)."
  (let* ((proxy (get-writer-proxy reader writer-id))
         (first (writer-proxy-first-sn proxy))
         (last (writer-proxy-last-sn proxy))
         (received (writer-proxy-received proxy))
         (base (loop for sn from first to last
                     unless (gethash sn received) return sn
                     finally (return (1+ last))))
         (numbits (max 0 (min 256 (- (1+ last) base))))
         (bitmap (make-array (max 1 (ceiling numbits 32))
                             :element-type '(unsigned-byte 32) :initial-element 0)))
    (loop for sn from base below (+ base numbits)
          unless (gethash sn received)
            do (dds.rtps.message:seqnum-set-bit bitmap (- sn base)))
    (values base numbits bitmap)))

(defun* reader-on-gap (reader writer-id gap-start base numbits bitmap)
    (function (rtps-reader (unsigned-byte 32) integer integer (unsigned-byte 32) (simple-array (unsigned-byte 32) (*))) t)
  "Mark GAPped SNs as irrelevant so they do not block the ack (RTPS 2.5 §8.3.7.4):
   the range [gapStart, base-1] plus the SNs listed in the bitmap."
  (let ((received (writer-proxy-received (get-writer-proxy reader writer-id))))
    (loop for sn from gap-start below base do (setf (gethash sn received) :gap))
    (dotimes (i numbits)
      (when (dds.rtps.message:seqnum-set-bit-p bitmap i)
        (setf (gethash (+ base i) received) :gap)))
    t))

(defun* reader-complete-p (reader writer-id)
    (function (rtps-reader (unsigned-byte 32)) t)
  "T iff every SN in the available range [first, last] has been received or GAPped."
  (let* ((proxy (get-writer-proxy reader writer-id))
         (received (writer-proxy-received proxy)))
    (loop for sn from (writer-proxy-first-sn proxy) to (writer-proxy-last-sn proxy)
          always (gethash sn received))))
