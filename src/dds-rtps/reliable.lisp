(in-package #:dds.rtps.reliable)

;;;; Stateful reliable writer/reader protocol logic (RTPS 2.5 §8.4). Operates on
;;;; submessage field VALUES (not bytes) so the state machines are directly
;;;; testable; the byte/transport wiring is a later increment. CLOS-free; the
;;;; consing here (per-reader proxies, resend lists) is a documented v1 concern.

(defparameter *fragment-size* 1024
  "Outbound RTPS fragmentSize in octets (uint16, <=65535; RTPS 2.5 §9.4.5.5 DATA_FRAG). A sample whose serialized size exceeds this is sent as DATA_FRAG submessages.")

(defparameter *max-reassembly-bytes* (* 4 1024 1024)
  "Reject an inbound DATA_FRAG sampleSize larger than this BEFORE allocating the reassembly buffer (resource-exhaustion guard, NFR-SEC-POSTURE).")

(defparameter *max-reassembly-fragments* 8192
  "Cap on the fragment count per reassembled sample (NFR-SEC-POSTURE).")

;;; ---- Writer side (§8.4.2): one ReaderProxy per matched reader ----

(defstruct* (reader-proxy (:constructor make-reader-proxy))
  "Writer-side proxy for one matched reader (RTPS 2.5 §8.4.2). Two distinct
   watermarks (RTPS 2.5 §8.4.2.2): ACKED-BASE is the reader's ACKNOWLEDGED watermark
   (it has acknowledged all SN < acked-base; advanced only by ACKNACK); UNSENT-BASE
   is the UNSENT watermark = 1 + highestSentChangeSN (next_unsent_change pushes the
   change at UNSENT-BASE once, then advances it). Push pacing keys off UNSENT-BASE;
   ACKNACK-driven repair (requested_changes) is independent of it."
  (acked-base 1 :type integer)             ; reader has acknowledged all SN < acked-base
  (unsent-base 1 :type integer))           ; 1 + highestSentChangeSN; changes >= this are unsent

(defstruct* (rtps-writer (:constructor make-rtps-writer))
  "Stateful reliable RTPS writer (RTPS 2.5 §8.4.2): a HistoryCache, the last SN
   written, the HEARTBEAT count, and a reader-id -> ReaderProxy table."
  (hc nil :type (or null dds.rtps.history:history-cache))  ; a HistoryCache
  (last-sn 0 :type integer)
  (hb-count 0 :type integer)
  (proxies (make-hash-table :test 'equalp) :type hash-table)   ; reader key (opaque, equalp) -> reader-proxy
  (frag-hb-count 0 :type integer))   ; HEARTBEAT_FRAG Count, separate from hb-count

(defun* get-reader-proxy (writer reader-id)
    (function (rtps-writer t) reader-proxy)
  "The ReaderProxy for the matched reader named by the opaque per-endpoint key READER-ID, created on
   first use. The key is treated only as an equalp hash key (the disc layer passes the remote reader's
   full 16-octet GUID; the value-level tests pass an integer): a SequenceNumber is unique only within
   one writer GUID (RTPS 2.5 §8.3.5.4), so each remote reader's watermarks are kept independent."
  (or (gethash reader-id (rtps-writer-proxies writer))
      (setf (gethash reader-id (rtps-writer-proxies writer)) (make-reader-proxy))))

(defun* writer-write (writer payload)
    (function (rtps-writer (array (unsigned-byte 8) (*))) integer)
  "Add a new :data change to the writer's HistoryCache; return its sequence number."
  (let ((sn (incf (rtps-writer-last-sn writer))))
    (dds.rtps.history:hc-add-change
     (rtps-writer-hc writer)
     (dds.rtps.history:make-cache-change :sn sn :serialized-payload payload))
    sn))

(defun* writer-lifecycle-change (writer key-hash status-flags)
    (function (rtps-writer (simple-array (unsigned-byte 8) (*)) (unsigned-byte 8)) integer)
  "Add a dispose/unregister change for the instance named by KEY-HASH (16 octets) to the
   writer's HistoryCache and return its sequence number (RTPS 2.5 §9.6.4.9). STATUS-FLAGS is
   the StatusInfo_t flag octet; the change KIND (:dispose/:unregister) is derived from it
   (status-info->kind). The change carries NO serializedPayload — the instance is identified
   by its key hash — yet occupies a real SN, so it is reliably ordered and ACKNACK-repairable
   like any DATA (RTPS 2.5 §8.4.2.2)."
  (let ((sn (incf (rtps-writer-last-sn writer))))
    (dds.rtps.history:hc-add-change
     (rtps-writer-hc writer)
     (dds.rtps.history:make-cache-change
      :sn sn :kind (dds.rtps.message:status-info->kind status-flags)
      :instance-key-hash key-hash :status-info status-flags))
    sn))

(defun* writer-heartbeat (writer)
    (function (rtps-writer) (values integer integer integer))
  "Return (values firstSN lastSN count) for a HEARTBEAT (RTPS 2.5 §8.3.7.5)."
  (values (or (dds.rtps.history:hc-min-seq (rtps-writer-hc writer)) 1)
          (or (dds.rtps.history:hc-max-seq (rtps-writer-hc writer)) 0)
          (incf (rtps-writer-hb-count writer))))

(defun* %changes-from (writer base)
    (function (rtps-writer integer) list)
  "The writer's HistoryCache CacheChanges with SN >= BASE, in SN order. The element is the
   CacheChange itself (carrying KIND, SN, payload, key-hash, status-info) so the send path
   can dispatch :data vs :dispose/:unregister (RTPS 2.5 §8.4.2.2 / §9.6.4.9)."
  (loop for ch in (dds.rtps.history:hc-changes-for-reader (rtps-writer-hc writer) nil)
        when (>= (dds.rtps.history:cache-change-sn ch) base)
          collect ch))

(defun* writer-data-list (writer reader-id)
    (function (rtps-writer t) list)
  "Changes not yet acked by READER-ID (the opaque per-reader key), as a list of CacheChanges in SN order."
  (%changes-from writer (reader-proxy-acked-base (get-reader-proxy writer reader-id))))

(defun* writer-unsent-list (writer reader-id)
    (function (rtps-writer t) list)
  "The UNSENT changes for READER-ID (the opaque per-reader key; next_unsent_change, RTPS 2.5 §8.4.2.2): the
   CacheChanges with SN >= the reader's UNSENT-BASE, in SN order. On a non-empty result the
   UNSENT-BASE watermark is advanced past the highest SN collected, so each change is pushed
   EXACTLY ONCE in pushMode (§8.4.2.2). Lost/late changes are recovered via the ACKNACK repair
   path (writer-on-acknack), not by re-pushing. Each element is the CacheChange (KIND/SN/
   payload/key-hash/status-info) so a :dispose/:unregister is pushed as a no-payload DATA."
  (let* ((proxy (get-reader-proxy writer reader-id))
         (changes (%changes-from writer (reader-proxy-unsent-base proxy))))
    (when changes
      (setf (reader-proxy-unsent-base proxy)
            (1+ (dds.rtps.history:cache-change-sn (first (last changes))))))
    changes))

(defun* writer-on-acknack (writer reader-id base numbits bitmap)
    (function (rtps-writer t integer (unsigned-byte 32) (simple-array (unsigned-byte 32) (*))) (values list list))
  "Process an ACKNACK from READER-ID (the opaque per-reader key; RTPS 2.5 §8.3.7.1). Confirm SN < BASE, then
   for each NACKed SN (bit set in BITMAP) return a resend if present, else a GAP.
   Returns (values data-resends gap-sns), data-resends a list of CacheChanges (so the
   resend path dispatches :data vs :dispose/:unregister exactly as the initial push)."
  (let ((proxy (get-reader-proxy writer reader-id))
        (resends '())
        (gaps '()))
    (setf (reader-proxy-acked-base proxy) (max (reader-proxy-acked-base proxy) base))
    (dotimes (i numbits)
      (when (dds.rtps.message:seqnum-set-bit-p bitmap i)
        (let* ((sn (+ base i))
               (ch (dds.rtps.history:hc-get-change (rtps-writer-hc writer) sn)))
          (if ch
              (push ch resends)
              (push sn gaps)))))
    (values (nreverse resends) (nreverse gaps))))

;;; ---- Reader side (§8.4.10): one WriterProxy per matched writer ----

(defstruct* (frag-reassembly (:constructor %make-frag-reassembly))
  "Reader-side reassembly state for one in-progress fragmented sample (RTPS 2.5 §9.4.5.5): declared total SAMPLE-SIZE and FRAGMENT-SIZE, accumulating BUFFER, a RECEIVED bitmap (one bit per 1-based fragment), and the count received."
  (sample-size 0 :type (integer 0))
  (fragment-size 0 :type (integer 0))
  (total-fragments 0 :type (integer 0))
  (buffer (make-array 0 :element-type '(unsigned-byte 8)) :type (simple-array (unsigned-byte 8) (*)))
  (received (make-array 0 :element-type 'bit) :type (simple-array bit (*)))
  (received-count 0 :type (integer 0)))

(defstruct* (writer-proxy (:constructor make-writer-proxy))
  "Reader-side proxy for one matched writer (RTPS 2.5 §8.4.10). RECEIVED maps SN ->
   payload | :gap; FIRST-SN/LAST-SN bound the available range from HEARTBEAT;
   REASSEMBLY maps SN -> frag-reassembly for in-progress DATA_FRAG samples."
  (received (make-hash-table :test 'eql) :type hash-table)   ; SN -> payload | :gap
  (first-sn 1 :type integer)
  (last-sn 0 :type integer)                ; available range from HEARTBEAT
  (reassembly (make-hash-table :test 'eql) :type hash-table)) ; SN -> frag-reassembly

(defstruct* (rtps-reader (:constructor make-rtps-reader))
  "Stateful reliable RTPS reader (RTPS 2.5 §8.4.10): an opaque-writer-key -> WriterProxy table."
  (proxies (make-hash-table :test 'equalp) :type hash-table))   ; writer key (opaque, equalp) -> writer-proxy

(defun* get-writer-proxy (reader writer-id)
    (function (rtps-reader t) writer-proxy)
  "The WriterProxy for the matched writer named by the opaque per-endpoint key WRITER-ID, created on
   first use. The key is treated only as an equalp hash key (the disc layer passes the remote writer's
   full 16-octet GUID; the value-level tests pass an integer): a SequenceNumber is unique only within
   one writer GUID (RTPS 2.5 §8.3.5.4), so two writers sharing EntityId 0x102 on different participants
   get independent received-SN sets / HEARTBEAT ranges / ACKNACK / GAP / reassembly state."
  (or (gethash writer-id (rtps-reader-proxies reader))
      (setf (gethash writer-id (rtps-reader-proxies reader)) (make-writer-proxy))))

(defun* reader-on-data (reader writer-id sn payload)
    (function (rtps-reader t integer (array (unsigned-byte 8) (*))) t)
  "Accept a DATA. Idempotent (duplicate SN overwrites — dedup); tracks the highest
   SN seen so reordered delivery is harmless (stored by SN)."
  (let ((proxy (get-writer-proxy reader writer-id)))
    (setf (gethash sn (writer-proxy-received proxy)) payload)
    (when (> sn (writer-proxy-last-sn proxy)) (setf (writer-proxy-last-sn proxy) sn))
    t))

(defun* reader-on-heartbeat (reader writer-id first-sn last-sn)
    (function (rtps-reader t integer integer) t)
  "Update the available range [firstSN, lastSN] (RTPS 2.5 §8.3.7.5)."
  (let ((proxy (get-writer-proxy reader writer-id)))
    (setf (writer-proxy-first-sn proxy) first-sn
          (writer-proxy-last-sn proxy) (max (writer-proxy-last-sn proxy) last-sn))
    t))

(defun* reader-acknack (reader writer-id)
    (function (rtps-reader t) (values integer (unsigned-byte 32) (simple-array (unsigned-byte 32) (*))))
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
    (function (rtps-reader t integer integer (unsigned-byte 32) (simple-array (unsigned-byte 32) (*))) t)
  "Mark GAPped SNs as irrelevant so they do not block the ack (RTPS 2.5 §8.3.7.4):
   the range [gapStart, base-1] plus the SNs listed in the bitmap."
  (let ((received (writer-proxy-received (get-writer-proxy reader writer-id))))
    (loop for sn from gap-start below base do (setf (gethash sn received) :gap))
    (dotimes (i numbits)
      (when (dds.rtps.message:seqnum-set-bit-p bitmap i)
        (setf (gethash (+ base i) received) :gap)))
    t))

(defun* reader-complete-p (reader writer-id)
    (function (rtps-reader t) t)
  "T iff every SN in the available range [first, last] has been received or GAPped."
  (let* ((proxy (get-writer-proxy reader writer-id))
         (received (writer-proxy-received proxy)))
    (loop for sn from (writer-proxy-first-sn proxy) to (writer-proxy-last-sn proxy)
          always (gethash sn received))))

(defun* reader-on-data-frag (reader writer-id sn fragment-starting-num fragments-in-submsg
                                    fragment-size sample-size payload)
    (function (rtps-reader t integer (unsigned-byte 32) (unsigned-byte 32)
               (unsigned-byte 32) (unsigned-byte 32) (array (unsigned-byte 8) (*)))
              (or null (simple-array (unsigned-byte 8) (*))))
  "Accept one DATA_FRAG submessage's fragment range for (WRITER-ID, SN). Reassembles into the
   per-(writer,sn) frag-reassembly; returns the complete SAMPLE-SIZE octet vector once all
   fragments have arrived, else NIL. Guards (NFR-SEC-POSTURE): rejects (NIL) a zero/over-limit
   SAMPLE-SIZE (> *max-reassembly-bytes*), a fragment count over *max-reassembly-fragments*, a
   zero FRAGMENT-SIZE, or a fragment range exceeding the sample; a sample whose declared
   fragment/sample size changes mid-stream is dropped. Duplicate fragments are idempotent.
   RTPS 2.5 §8.3.8.3 / §9.4.5.5."
  (when (or (zerop fragment-size) (zerop sample-size) (> sample-size *max-reassembly-bytes*))
    (return-from reader-on-data-frag nil))
  (let ((total (ceiling sample-size fragment-size)))
    (when (> total *max-reassembly-fragments*) (return-from reader-on-data-frag nil))
    (when (or (< fragment-starting-num 1) (zerop fragments-in-submsg)
              (> (+ fragment-starting-num fragments-in-submsg -1) total))
      (return-from reader-on-data-frag nil))
    (let* ((proxy (get-writer-proxy reader writer-id))
           (table (writer-proxy-reassembly proxy))
           (entry (or (gethash sn table)
                      (setf (gethash sn table)
                            (%make-frag-reassembly
                             :sample-size sample-size :fragment-size fragment-size
                             :total-fragments total
                             :buffer (make-array sample-size :element-type '(unsigned-byte 8))
                             :received (make-array total :element-type 'bit :initial-element 0))))))
      (when (or (/= (frag-reassembly-sample-size entry) sample-size)
                (/= (frag-reassembly-fragment-size entry) fragment-size))
        (remhash sn table)
        (return-from reader-on-data-frag nil))
      (let ((buf (frag-reassembly-buffer entry))
            (rcv (frag-reassembly-received entry)))
        (dotimes (k fragments-in-submsg)
          (let* ((fnum (+ fragment-starting-num k))
                 (dst (* (1- fnum) fragment-size))
                 (this (min fragment-size (- sample-size dst)))
                 (src (* k fragment-size)))
            (when (<= (+ src this) (length payload))
              (replace buf payload :start1 dst :end1 (+ dst this) :start2 src :end2 (+ src this))
              (when (zerop (sbit rcv (1- fnum)))
                (setf (sbit rcv (1- fnum)) 1)
                (incf (frag-reassembly-received-count entry))))))
        (when (= (frag-reassembly-received-count entry) total)
          (remhash sn table)
          buf)))))

(defun* reader-frag-acknack (reader writer-id sn)
    (function (rtps-reader t integer) t)
  "Compute a NACK_FRAG fragment set for the in-progress reassembly of (WRITER-ID, SN):
   (values base numBits bitmap) naming the 1-based fragment numbers NOT yet received, or
   NIL if there is no such reassembly (unknown or already complete). The window
   [base, base+numBits) is capped at 256 fragments per NACK_FRAG (§9.4.2.8). RTPS 2.5 §8.3.7.2."
  (let* ((proxy (get-writer-proxy reader writer-id))
         (entry (gethash sn (writer-proxy-reassembly proxy))))
    (when (null entry) (return-from reader-frag-acknack nil))
    (let* ((rcv (frag-reassembly-received entry))
           (total (frag-reassembly-total-fragments entry))
           (first-missing (loop for f from 1 to total
                                when (zerop (sbit rcv (1- f))) return f)))
      (when (null first-missing) (return-from reader-frag-acknack nil))
      (let* ((base first-missing)
             (last-missing (loop for f from total downto base
                                 when (zerop (sbit rcv (1- f))) return f))
             (numbits (min 256 (1+ (- last-missing base))))
             (words (ceiling numbits 32))
             (bitmap (make-array (max 1 words) :element-type '(unsigned-byte 32) :initial-element 0)))
        (loop for f from base below (+ base numbits)
              when (zerop (sbit rcv (1- f)))
                do (dds.rtps.message:fragnum-set-bit bitmap (- f base)))
        (values base numbits bitmap)))))

;;; ---- Writer-side fragmentation planners (RTPS 2.5 §8.3.8.3) ----

(defun* writer-frag-heartbeat (writer sn)
    (function (rtps-writer integer) t)
  "Compute a HEARTBEAT_FRAG for the sample at SN: (values last-fragment-num count) where
   last-fragment-num is the sample's total fragment count at *fragment-size* and count is the
   writer's monotonically increasing HEARTBEAT_FRAG counter; NIL if SN is absent/empty.
   RTPS 2.5 §8.3.7.5 (fragment variant)."
  (let ((ch (dds.rtps.history:hc-get-change (rtps-writer-hc writer) sn)))
    (when (null ch) (return-from writer-frag-heartbeat nil))
    (let ((payload (dds.rtps.history:cache-change-serialized-payload ch)))
      (when (null payload) (return-from writer-frag-heartbeat nil))
      (values (ceiling (length payload) *fragment-size*)
              (incf (rtps-writer-frag-hb-count writer))))))

(defun* writer-on-nack-frag (writer sn base numbits bitmap)
    (function (rtps-writer integer (unsigned-byte 32) (unsigned-byte 32) (simple-array (unsigned-byte 32) (*))) list)
  "Plan the DATA_FRAG resends for a NACK_FRAG naming missing fragments of the sample at SN:
   the writer-frag-plan-for descriptors over SN's payload, or NIL if SN is absent/empty.
   RTPS 2.5 §8.3.8.x."
  (let ((ch (dds.rtps.history:hc-get-change (rtps-writer-hc writer) sn)))
    (when (null ch) (return-from writer-on-nack-frag nil))
    (let ((payload (dds.rtps.history:cache-change-serialized-payload ch)))
      (when (null payload) (return-from writer-on-nack-frag nil))
      (writer-frag-plan-for (length payload) *fragment-size* base numbits bitmap))))

(defun* writer-sample-payload (writer sn)
    (function (rtps-writer integer) (or null (array (unsigned-byte 8) (*))))
  "The stored SerializedPayload octets for the writer's sample SN, or NIL if absent."
  (let ((ch (dds.rtps.history:hc-get-change (rtps-writer-hc writer) sn)))
    (and ch (dds.rtps.history:cache-change-serialized-payload ch))))

(defun* writer-frag-plan (sample-size fragment-size budget)
    (function ((unsigned-byte 32) (unsigned-byte 32) (integer 1)) list)
  "Plan the DATA_FRAG submessages for a SAMPLE-SIZE-octet sample at FRAGMENT-SIZE, packing as
   many whole fragments as fit BUDGET octets per submessage (>=1). Returns a list of
   (fragment-starting-num fragments-in-submsg payload-offset payload-length) in fragment order;
   the final fragment of the sample may be short. fragmentSize is constant across the sample
   (RTPS 2.5 §8.3.8.3)."
  (let ((total (ceiling sample-size fragment-size))
        (per (max 1 (floor budget fragment-size)))
        (out '()))
    (loop for fstart from 1 to total by per
          for fcount = (min per (1+ (- total fstart)))
          for off = (* (1- fstart) fragment-size)
          for len = (min (* fcount fragment-size) (- sample-size off))
          do (push (list fstart fcount off len) out))
    (nreverse out)))

(defun* writer-frag-plan-for (sample-size fragment-size base numbits bitmap)
    (function ((unsigned-byte 32) (unsigned-byte 32) (unsigned-byte 32) (unsigned-byte 32)
               (simple-array (unsigned-byte 32) (*))) list)
  "Plan DATA_FRAG submessages re-sending ONLY the fragments named in a NACK_FRAG
   FragmentNumberSet (BASE/NUMBITS/BITMAP); one fragment per submessage. Returns
   (fragment-starting-num fragments-in-submsg payload-offset payload-length) descriptors in
   fragment order; the final fragment may be short. RTPS 2.5 §8.3.8.3."
  (let ((total (ceiling sample-size fragment-size))
        (out '()))
    (loop for f from base below (+ base numbits)
          when (and (<= 1 f total) (dds.rtps.message:fragnum-set-member-p base numbits bitmap f))
            do (let* ((off (* (1- f) fragment-size))
                      (len (min fragment-size (- sample-size off))))
                 (push (list f 1 off len) out)))
    (nreverse out)))
