(in-package #:dds.durability)

;;; Task 1 — append-log-per-topic durable-store backend (WP-DURABILITY-PERSISTENT).
;;; Layout: D/topics/<topic-id>.log (topic-id = lowercase hex of topic UTF-8 bytes)
;;;         D/topics.map (topic-id -> topic-name, one line each)
;;; Frame v2: magic(1)=0xDA version(1)=0x02 flags(1) guid(16) sn(8 LE) [key-hash(16)]
;;;           payload-len(4 LE) header-crc32(4 LE) payload frame-crc32(4 LE)
;;; Frame v1 (legacy, read-only): magic(1)=0xDA version(1)=0x01 flags(1) guid(16) sn(8 LE)
;;;           [key-hash(16)] payload-len(4 LE) payload frame-crc32(4 LE)   ; NO header-crc
;;; The header-crc (over magic..payload-len) is validated BEFORE payload-len is trusted, so a
;;; corrupt length is caught as :corrupt (fail loud) instead of masquerading as a torn tail
;;; (ADR 0026 §10.9). Stores OPAQUE payload bytes — unaware of DARE.

;;; CRC-32 (IEEE 802.3 / PKZIP polynomial 0xEDB88320 — bit-reversed).
;;; Table-driven; 256-entry table built once at load time.

(defparameter %crc32-table
  (let ((tbl (make-array 256 :element-type '(unsigned-byte 32))))
    (dotimes (i 256 tbl)
      (let ((c (the (unsigned-byte 32) i)))
        (dotimes (_ 8)
          (setf c (if (logbitp 0 c)
                      (logxor (ash c -1) #xEDB88320) ; poly 0xEDB88320 (ISO 3309 / IEEE 802.3)
                      (ash c -1))))
        (setf (aref tbl i) c))))
  "Precomputed CRC-32 IEEE table (256 entries, poly 0xEDB88320).")

(defun* %crc32 (octets start end)
    (function ((simple-array (unsigned-byte 8) (*)) (integer 0) (integer 0)) (unsigned-byte 32))
  "Compute CRC-32/ISO-HDLC (IEEE 802.3) over OCTETS[START..END)."
  (let ((crc #xFFFFFFFF))
    (declare (type (unsigned-byte 32) crc))
    (loop for i from start below end
          do (setf crc (logxor (ash crc -8)
                               (aref %crc32-table (logand (logxor crc (aref octets i)) #xFF)))))
    (logxor crc #xFFFFFFFF)))

;;; Frame constants.
(defconstant +magic-0+ #xDA "Frame magic byte 0 (fixed).")
;;; Frame format version occupies the SECOND magic byte (was a fixed #x01). The reader dispatches
;;; per-frame on it, so a single log may contain v1 frames (from a prior run) followed by v2 frames
;;; (appended after upgrade) — mirrors the DARE envelope per-blob version byte (ADR 0025 §5).
(defconstant +frame-version-v1+ #x01
  "Frame format version 1 (legacy, NO header CRC). Read-only back-compat; never written now.")
(defconstant +frame-version-v2+ #x02
  "Frame format version 2: adds a CRC-32 header-integrity field immediately after payload-len, so a
   corrupt LENGTH field is DETECTED (fail loud) instead of mis-parsed as a torn tail (ADR 0026 §10.9).
   The sole version the store WRITES.")
(defconstant +flag-kind-mask+     #x03 "Bits 0-1 of flags byte encode the change kind.")
(defconstant +flag-key-hash-bit+  #x04 "Bit 2 of flags byte: key-hash present in frame.")

(defconstant +kind-data+        0 "Kind encoding for :data.")
(defconstant +kind-dispose+     1 "Kind encoding for :dispose.")
(defconstant +kind-unregister+  2 "Kind encoding for :unregister.")

;;; Minimum frame size without optional key-hash:
;;; 2(magic) + 1(flags) + 16(guid) + 8(sn) + 4(plen) + 0(payload) + 4(crc) = 35
(defconstant +frame-min-bytes+ 35 "Minimum bytes for a frame (no key-hash, empty payload).")
(defconstant +frame-kh-extra+  16 "Extra bytes when key-hash present.")

;;; Resource guard (NFR-SEC-POSTURE: bound an untrusted length before trusting it). A declared
;;; payload-len above this is treated as :corrupt (fail loud), NOT a torn tail — a gross length-field
;;; corruption must never be silently truncated as if it were an incomplete trailing write. Generous
;;; (64 MiB ≫ any realistic sealed sample) so a legitimate record is never false-rejected.
(defconstant +frame-max-payload+ (* 64 1024 1024)
  "Maximum accepted frame payload length in bytes (NFR-SEC-POSTURE sanity cap; over-cap ⇒ :corrupt).")

(defun* %kind->int (kind)
    (function ((member :data :dispose :unregister)) (unsigned-byte 2))
  "Map change-kind keyword to 2-bit encoding."
  (ecase kind
    (:data +kind-data+)
    (:dispose +kind-dispose+)
    (:unregister +kind-unregister+)))

(defun* %int->kind (n)
    (function ((unsigned-byte 8)) (or null (member :data :dispose :unregister)))
  "Map 2-bit encoding back to change-kind keyword; returns NIL for unassigned values."
  (cond ((= n +kind-data+) :data)
        ((= n +kind-dispose+) :dispose)
        ((= n +kind-unregister+) :unregister)
        (t nil)))

(defun* %string->utf8 (s)
    (function (string) (simple-array (unsigned-byte 8) (*)))
  "Encode string S to UTF-8 octets (standard CL char-code covers BMP; surrogates absent in CL)."
  (let ((result '()))
    (dotimes (i (length s))
      (let ((cp (char-code (char s i))))
        (cond
          ((< cp #x80)
           (push cp result))
          ((< cp #x800)
           (push (logior #xC0 (ash cp -6)) result)
           (push (logior #x80 (logand cp #x3F)) result))
          ((< cp #x10000)
           (push (logior #xE0 (ash cp -12)) result)
           (push (logior #x80 (logand (ash cp -6) #x3F)) result)
           (push (logior #x80 (logand cp #x3F)) result))
          (t
           (push (logior #xF0 (ash cp -18)) result)
           (push (logior #x80 (logand (ash cp -12) #x3F)) result)
           (push (logior #x80 (logand (ash cp -6) #x3F)) result)
           (push (logior #x80 (logand cp #x3F)) result)))))
    (let* ((lst (nreverse result))
           (v   (make-array (length lst) :element-type '(unsigned-byte 8))))
      (loop for b in lst for i from 0 do (setf (aref v i) b))
      v)))

(defun* %topic->id (topic)
    (function (string) string)
  "Encode TOPIC name to lowercase hex of its UTF-8 bytes (filesystem-safe, deterministic)."
  (let* ((utf8 (%string->utf8 topic))
         (hex (make-array (* 2 (length utf8)) :element-type 'character)))
    (loop for b across utf8
          for i from 0 by 2
          do (let* ((hi (ldb (byte 4 4) b))
                    (lo (ldb (byte 4 0) b)))
               (setf (aref hex i)       (char "0123456789abcdef" hi))
               (setf (aref hex (1+ i))  (char "0123456789abcdef" lo))))
    (coerce hex 'string)))

(defun* %topics-dir (dir)
    (function (pathname) pathname)
  "Return the topics/ subdirectory pathname under the store root DIR (the dir that holds the logs)."
  (merge-pathnames (make-pathname :directory '(:relative "topics")) dir))

(defun* %topic-log-path (dir topic-id)
    (function (pathname string) pathname)
  "Return the path for the topic append-log given the store DIR and TOPIC-ID."
  (merge-pathnames (make-pathname :directory '(:relative "topics")
                                  :name topic-id :type "log")
                   dir))

(defun* %topics-map-path (dir)
    (function (pathname) pathname)
  "Return the path for the topics.map file in DIR."
  (merge-pathnames (make-pathname :name "topics" :type "map") dir))

;;; u64/u32 little-endian pack/unpack into octet vectors.

(defun* %put-u64-le (vec offset value)
    (function ((simple-array (unsigned-byte 8) (*)) (integer 0) (integer 0)) t)
  "Write VALUE as 8 bytes little-endian into VEC at OFFSET."
  (dotimes (i 8)
    (setf (aref vec (+ offset i)) (ldb (byte 8 (* 8 i)) value))))

(defun* %put-u32-le (vec offset value)
    (function ((simple-array (unsigned-byte 8) (*)) (integer 0) (unsigned-byte 32)) t)
  "Write VALUE as 4 bytes little-endian into VEC at OFFSET."
  (dotimes (i 4)
    (setf (aref vec (+ offset i)) (ldb (byte 8 (* 8 i)) value))))

(defun* %get-u64-le (vec offset)
    (function ((simple-array (unsigned-byte 8) (*)) (integer 0)) (integer 0))
  "Read 8 bytes little-endian from VEC at OFFSET as an unsigned integer."
  (let ((v 0))
    (dotimes (i 8 v)
      (setf v (logior v (ash (aref vec (+ offset i)) (* 8 i)))))))

(defun* %get-u32-le (vec offset)
    (function ((simple-array (unsigned-byte 8) (*)) (integer 0)) (unsigned-byte 32))
  "Read 4 bytes little-endian from VEC at OFFSET as a (unsigned-byte 32)."
  (let ((v 0))
    (declare (type (unsigned-byte 32) v))
    (dotimes (i 4 v)
      (setf v (logior v (ash (aref vec (+ offset i)) (* 8 i)))))))

;;; Frame serialization.

(defun* %frame-record-versioned (record version)
    (function (durable-record (member #x01 #x02)) (simple-array (unsigned-byte 8) (*)))
  "Serialize RECORD into a frame of format VERSION (#x01 = legacy no-header-CRC, read-only
   back-compat used only by tests; #x02 = header-CRC after payload-len, the sole version the
   store WRITES). v2 inserts a 4-byte CRC-32 over the header (magic..payload-len) between the
   payload-len field and the payload; the trailing frame CRC still covers the whole frame. ADR 0026 §10.9."
  (let* ((payload    (durable-record-payload record))
         (key-hash   (durable-record-key-hash record))
         (kh-p       (not (null key-hash)))
         (hdr-crc-p  (= version +frame-version-v2+))
         (plen       (length payload))
         ;; magic+version(2) flags(1) guid(16) sn(8) [kh(16)] plen(4) [hdr-crc(4)] payload frame-crc(4)
         (frame-len  (+ 2 1 16 8 (if kh-p 16 0) 4 (if hdr-crc-p 4 0) plen 4))
         (frame      (make-array frame-len :element-type '(unsigned-byte 8) :initial-element 0))
         (flags      (logior (%kind->int (durable-record-kind record))
                             (if kh-p +flag-key-hash-bit+ 0))))
    (setf (aref frame 0) +magic-0+)
    (setf (aref frame 1) (the (unsigned-byte 8) version))
    (setf (aref frame 2) (the (unsigned-byte 8) flags))
    (replace frame (durable-record-writer-guid record) :start1 3 :end1 19)
    (%put-u64-le frame 19 (durable-record-sn record))
    (let ((after-sn 27))
      (when kh-p
        (replace frame key-hash :start1 after-sn :end1 (+ after-sn 16))
        (incf after-sn 16))
      (%put-u32-le frame after-sn (the (unsigned-byte 32) plen))
      (let ((payload-off (+ after-sn 4)))
        (when hdr-crc-p
          ;; header CRC over [0 .. after-sn+4) = magic..payload-len; validated before plen is trusted
          (%put-u32-le frame payload-off (%crc32 frame 0 payload-off))
          (setf payload-off (+ after-sn 8)))
        (replace frame payload :start1 payload-off :end1 (+ payload-off plen))
        (let ((crc-offset (+ payload-off plen)))
          (%put-u32-le frame crc-offset (%crc32 frame 0 crc-offset)))))
    frame))

(defun* %frame-record (record)
    (function (durable-record) (simple-array (unsigned-byte 8) (*)))
  "Serialize RECORD into a complete v2 frame — the store writes only the current version (ADR 0026 §10.9)."
  (%frame-record-versioned record +frame-version-v2+))

;;; Frame parsing for replay; returns (values record next-pos reason).
;;; reason: :ok on success; :short = insufficient bytes (torn tail); :corrupt = full bytes present but invalid.

(defun* %parse-frame (buf start end topic)
    (function ((simple-array (unsigned-byte 8) (*)) (integer 0) (integer 0) string)
              (values (or null durable-record) (integer 0) (member :ok :short :corrupt)))
  "Parse one frame (v1 or v2) from BUF[START..END) for TOPIC, dispatching on the version byte.
   Returns (values record next-pos :ok) on success.
   Returns (values nil start :short) when bytes from START to END are fewer than the full declared frame.
   Returns (values nil start :corrupt) when the full frame is present but magic/version/header-CRC/
   kind/frame-CRC is invalid. A v2 bad HEADER CRC is :corrupt — a corrupt length is detected here
   rather than mis-parsed as a torn tail (ADR 0026 §10.9); a torn write yields :short (fewer bytes),
   never a bad header CRC, so the discrimination is clean."
  (let ((avail (- end start)))
    ;; Not enough bytes even for the minimum frame header → torn tail
    (when (< avail +frame-min-bytes+)
      (return-from %parse-frame (values nil start :short)))
    ;; Wrong magic with full header bytes available → corrupt
    (unless (= (aref buf start) +magic-0+)
      (return-from %parse-frame (values nil start :corrupt)))
    (let ((version (aref buf (1+ start))))
      ;; Unknown version byte with the magic present → corrupt (fail loud, never silent-skip)
      (unless (or (= version +frame-version-v1+) (= version +frame-version-v2+))
        (return-from %parse-frame (values nil start :corrupt)))
      (let* ((hdr-crc-p (= version +frame-version-v2+))
             (flags     (aref buf (+ start 2)))
             (kh-p      (logbitp 2 flags))
             (kind-int  (logand flags +flag-kind-mask+))
             (guid      (make-array 16 :element-type '(unsigned-byte 8)))
             (sn-off    (+ start 19))
             (kh-off    (+ start 27))
             (plen-off  (if kh-p (+ kh-off 16) kh-off))
             (hdr-crc-off (+ plen-off 4))                       ; v2 header CRC sits right after plen
             (payload-off (if hdr-crc-p (+ hdr-crc-off 4) (+ plen-off 4)))
             (hdr-need  (+ (- payload-off start) 4)))           ; bytes through header(+hdr-crc) + empty payload + frame-crc
        ;; Not enough bytes to read the header (incl. v2 header-crc) → short (torn at header boundary)
        (when (< avail hdr-need)
          (return-from %parse-frame (values nil start :short)))
        (replace guid buf :start2 (+ start 3) :end2 (+ start 19))
        ;; v2: validate the header CRC BEFORE trusting plen. A mismatch means header bytes are
        ;; present but wrong — a clean truncating crash can only SHORTEN (→ :short above), never
        ;; corrupt present header bytes; so a bad header CRC is genuine corruption → fail loud.
        (when hdr-crc-p
          (let ((stored-hdr (%get-u32-le buf hdr-crc-off))
                (actual-hdr (%crc32 buf start hdr-crc-off)))
            (unless (= stored-hdr actual-hdr)
              (return-from %parse-frame (values nil start :corrupt)))))
        (let* ((sn         (%get-u64-le buf sn-off))
               (kh         (when kh-p
                             (let ((v (make-array 16 :element-type '(unsigned-byte 8))))
                               (replace v buf :start2 kh-off :end2 (+ kh-off 16))
                               v)))
               (plen       (%get-u32-le buf plen-off))
               (crc-off    (+ payload-off plen))
               (frame-end  (+ crc-off 4)))
          ;; Gross length-field corruption: a declared payload above the sanity cap is corrupt, not a
          ;; torn tail. (For v2 this is normally already caught by the header CRC; retained as the
          ;; v1 backstop and defense-in-depth.) Checked BEFORE the frame-end>end test.
          (when (> plen +frame-max-payload+)
            (return-from %parse-frame (values nil start :corrupt)))
          ;; Full declared frame does not fit in buffer → short (torn write)
          (when (> frame-end end)
            (return-from %parse-frame (values nil start :short)))
          ;; Full frame present; validate kind bits before CRC to keep :corrupt reason consistent
          (let ((kind (%int->kind kind-int)))
            (unless kind
              (return-from %parse-frame (values nil start :corrupt)))
            (let ((stored-crc (%get-u32-le buf crc-off))
                  (actual-crc (%crc32 buf start crc-off)))
              (unless (= stored-crc actual-crc)
                (return-from %parse-frame (values nil start :corrupt)))
              (let ((payload (make-array plen :element-type '(unsigned-byte 8))))
                (replace payload buf :start2 payload-off :end2 crc-off)
                (values (make-durable-record
                         :topic      topic
                         :writer-guid guid
                         :sn         sn
                         :key-hash   kh
                         :kind       kind
                         :payload    payload)
                        frame-end
                        :ok)))))))))

;;; Topics.map I/O.

(defun* %write-topics-map (dir topic-map)
    (function (pathname hash-table) t)
  "Write the topics.map file: one 'topic-id TAB topic-name' line per entry."
  (with-open-file (s (%topics-map-path dir)
                     :direction :output :if-exists :supersede :if-does-not-exist :create)
    (maphash (lambda (id name)
               (format s "~a~c~a~%" id #\Tab name))
             topic-map))
  ;; persist the topics.map dirent (create/replace) across power loss (ADR 0026 §10.10)
  (dds.pal:fsync-directory dir)
  t)

(defun* %read-topics-map (dir)
    (function (pathname) hash-table)
  "Read topics.map into a hash-table id->name; return empty table if file absent."
  (let ((tbl (make-hash-table :test #'equal))
        (path (%topics-map-path dir)))
    (when (probe-file path)
      (with-open-file (s path :direction :input)
        (loop for line = (read-line s nil nil)
              while line
              do (let ((tab (position #\Tab line)))
                   (when tab
                     (setf (gethash (subseq line 0 tab) tbl)
                           (subseq line (1+ tab))))))))
    tbl))

;;; File truncation: portable via open-for-output + copy.

(defun* %truncate-file (path offset)
    (function (pathname (integer 0)) t)
  "Truncate PATH to OFFSET bytes by rewriting via a temp file (portable CL, no #+)."
  (when (zerop offset)
    (with-open-file (s path :direction :output :if-exists :supersede :element-type '(unsigned-byte 8))
      (declare (ignore s)))
    ;; persist the truncated (possibly re-created) dirent (ADR 0026 §10.10)
    (dds.pal:fsync-directory (uiop:pathname-directory-pathname path))
    (return-from %truncate-file t))
  (let ((tmp (merge-pathnames (make-pathname :name (concatenate 'string (pathname-name path) ".tmp")
                                              :type (pathname-type path))
                               (pathname path))))
    (let ((buf (make-array (min offset 65536) :element-type '(unsigned-byte 8))))
      (with-open-file (in path :direction :input :element-type '(unsigned-byte 8))
        (with-open-file (out tmp :direction :output :element-type '(unsigned-byte 8)
                                 :if-exists :supersede :if-does-not-exist :create)
          (let ((remaining offset))
            (loop while (plusp remaining)
                  do (let* ((want (min remaining (length buf)))
                            (got  (read-sequence buf in :end want)))
                       (when (zerop got) (return))
                       (write-sequence buf out :end got)
                       (decf remaining got))))
          ;; fsync the temp CONTENT before the rename so the durable rename never points at
          ;; unsynced bytes (mirrors %rewrite-topic-log; ADR 0026 §10.10)
          (dds.pal:fsync-stream out))))
    ;; delete destination first (rename-file is not atomic-replace on all platforms)
    (when (probe-file path) (delete-file path))
    (rename-file tmp path)
    ;; fsync the containing dir so the delete+rename dirents survive power loss (ADR 0026 §10.10)
    (dds.pal:fsync-directory (uiop:pathname-directory-pathname path))
    t))

;;; Replay one topic log, returning a list of durable-records.
;;; :short at the tail → truncate to last-valid, recover.
;;; :corrupt anywhere → error (fail loud; never silently drop mid-file data).

(defun* %replay-log (path topic)
    (function (pathname string) list)
  "Replay frames from PATH for TOPIC into a list of durable-records.
   A :short reason at the trailing position truncates to last-valid and recovers.
   A :corrupt reason at any position signals an error (ADR 0026 §File-store on-disk format)."
  (unless (probe-file path)
    (return-from %replay-log '()))
  (let* ((size   (with-open-file (s path :element-type '(unsigned-byte 8)) (file-length s)))
         (buf    (make-array size :element-type '(unsigned-byte 8)))
         (records '())
         (pos     0)
         (last-valid 0))
    (with-open-file (s path :element-type '(unsigned-byte 8) :direction :input)
      (read-sequence buf s))
    (loop
      (when (>= pos size) (return))
      (multiple-value-bind (rec next reason) (%parse-frame buf pos size topic)
        (cond
          (rec
           (push rec records)
           (setf last-valid next)
           (setf pos next))
          ;; :short → not enough bytes for the full declared frame; torn tail if at last-valid
          ((eq reason :short)
           (when (< last-valid size)
             (%truncate-file path last-valid))
           (return))
          ;; :corrupt → full frame bytes present but magic/kind/CRC invalid; fail loud
          (t
           (error "dds.durability: mid-file corruption in ~a at offset ~d (last valid ~d; reason ~s)"
                  path pos last-valid reason)))))
    (when (and (zerop last-valid) (plusp size))
      ;; file had bytes but the very first frame was :short (all-garbage file) → truncate
      (%truncate-file path 0))
    (nreverse records)))

;;; Compaction: drop settled (dispose+unregister both present) instances.

(defun* %compact-topic-records (records &optional (history-kind :keep-all) (history-depth 1))
    (function (list &optional (member :keep-all :keep-last) (integer 1)) list)
  "Filter RECORDS keeping only live entries.
   Pass 1 (unconditional): drop settled instances (dispose+unregister both present AND the
   FINAL record is a tombstone; order-aware so a RESURRECTED instance is never dropped).
   Records with NIL key-hash are NEVER dropped. Conservative: any doubt keeps the data.
   Pass 2 (HISTORY-KIND :keep-last only): for each non-NIL-key-hash instance, keep only the
   HISTORY-DEPTH :data records sorting HIGHEST by %record-guid-sn< (drop older superseded ones).
   Lifecycle records (:dispose/:unregister) and NIL-key-hash records pass through untouched.
   Append order is preserved in the output. :keep-all skips pass 2 (byte-identical to no-arg call)."
  (let ((dispose-set  (make-hash-table :test #'equalp))
        (unreg-set    (make-hash-table :test #'equalp))
        (last-kind    (make-hash-table :test #'equalp)))
    ;; pass 1a (append order): tombstone presence + the FINAL kind per key-hash
    (dolist (r records)
      (let ((kh (durable-record-key-hash r)))
        (when kh
          (setf (gethash kh last-kind) (durable-record-kind r))
          (case (durable-record-kind r)
            (:dispose    (setf (gethash kh dispose-set)  t))
            (:unregister (setf (gethash kh unreg-set)    t))
            (otherwise   nil)))))
    ;; pass 1b: drop a record only if its key-hash is settled
    (let ((kept (loop for r in records
                      for kh = (durable-record-key-hash r)
                      unless (and kh
                                  (gethash kh dispose-set)
                                  (gethash kh unreg-set)
                                  (let ((lk (gethash kh last-kind)))
                                    (or (eq lk :dispose) (eq lk :unregister))))
                        collect r)))
      (if (eq history-kind :keep-last)
          ;; pass 2: per-instance KEEP_LAST — keep only the newest HISTORY-DEPTH :data records
          ;; per non-NIL key-hash; lifecycle records + NIL-key-hash records pass through
          (let ((drop-set (make-hash-table :test #'eq))) ; record identity -> drop?
            ;; bucket :data records per non-NIL key-hash
            (let ((buckets (make-hash-table :test #'equalp)))
              (dolist (r kept)
                (let ((kh (durable-record-key-hash r)))
                  (when (and kh (eq :data (durable-record-kind r)))
                    (push r (gethash kh buckets '())))))
              ;; for each bucket, mark the OLDER (below newest depth) records for dropping
              (maphash (lambda (kh bucket)
                         (declare (ignore kh))
                         (when (> (length bucket) history-depth)
                           ;; sort ascending by (guid sn); oldest first; drop all but last depth
                           (let* ((sorted  (sort (copy-list bucket) #'%record-guid-sn<))
                                  (n-drop  (- (length sorted) history-depth))
                                  (to-drop (subseq sorted 0 n-drop)))
                             (dolist (r to-drop)
                               (setf (gethash r drop-set) t)))))
                       buckets))
            ;; filter kept, preserving append order
            (loop for r in kept unless (gethash r drop-set) collect r))
          ;; :keep-all — pass 2 skipped; return settled-only result
          kept))))

(defun* %rewrite-topic-log (dir tid records)
    (function (pathname string list) (eql t))
  "Atomically rewrite the log for TID under DIR with RECORDS.
   Writes to <log>.tmp, fsyncs, then renames .tmp over the original in one atomic step
   (uiop:rename-file-overwriting-target is POSIX rename(2) — no crash window)."
  (let* ((log-path (%topic-log-path dir tid))
         (tmp-path (merge-pathnames
                    (make-pathname :name (concatenate 'string tid ".tmp") :type "log")
                    (merge-pathnames (make-pathname :directory '(:relative "topics")) dir))))
    (with-open-file (stm tmp-path
                         :direction :output
                         :element-type '(unsigned-byte 8)
                         :if-exists :supersede
                         :if-does-not-exist :create)
      (dolist (r records)
        (write-sequence (%frame-record r) stm))
      (dds.pal:fsync-stream stm))
    (uiop:rename-file-overwriting-target tmp-path log-path)
    ;; fsync the containing dir so the compaction rename's dirent survives power loss (ADR 0026 §10.10 / 0029)
    (dds.pal:fsync-directory (%topics-dir dir))
    t))

;;; File-store make-file-store.

(defun* make-file-store (&key dir (max-samples 0)
                              (history-kind :keep-all) (history-depth 1))
    (function (&key (:dir (or null pathname)) (:max-samples (integer 0))
                    (:history-kind (member :keep-all :keep-last)) (:history-depth (integer 1)))
              durable-store)
  "Construct an append-log-per-topic durable-store.
   DIR is the root directory for topic logs (required on open).
   MAX-SAMPLES 0 = unbounded; positive caps total records across all topics (:rejected when full).
   HISTORY-KIND / HISTORY-DEPTH govern per-instance compaction-on-open (DDS 1.4 §2.2.3.5):
   :keep-all (default, byte-identical) or :keep-last with DEPTH >= 1 keeps only the newest DEPTH
   :data records per non-NIL-key-hash instance on each store-open."
  (let* ((outer     (make-hash-table :test #'equal)) ; topic-id -> inner hash-table
         (streams   (make-hash-table :test #'equal)) ; topic-id -> open output stream
         (id-map    (make-hash-table :test #'equal)) ; topic -> topic-id
         (lock      (dds.pal:make-lock "dds-file-store"))
         (store-dir (when dir (pathname dir))))

    (flet ((%inner (topic-id)
             (or (gethash topic-id outer)
                 (setf (gethash topic-id outer) (make-hash-table :test #'equal))))
           (%total-count ()
             (let ((n 0))
               (maphash (lambda (k v) (declare (ignore k)) (incf n (hash-table-count v))) outer)
               n))
           (%ensure-stream (topic-id)
             (or (gethash topic-id streams)
                 (let* ((log-path (%topic-log-path store-dir topic-id))
                        (existed  (probe-file log-path))
                        (s (open log-path
                                 :direction :output
                                 :element-type '(unsigned-byte 8)
                                 :if-exists :append
                                 :if-does-not-exist :create)))
                   (setf (gethash topic-id streams) s)
                   ;; a NEW log file's dirent must be fsynced into topics/ to survive power loss
                   ;; (ADR 0026 §10.10); a re-opened existing log needs no new dirent
                   (unless existed
                     (dds.pal:fsync-directory (%topics-dir store-dir)))
                   s)))
           (%record-key (writer-guid sn)
             (cons (coerce writer-guid 'list) sn)))

      (%make-durable-store
       :name :file

       :put
       (lambda (topic writer-guid sn key-hash kind payload)
         (dds.pal:with-lock (lock)
           (let* ((tid  (or (gethash topic id-map)
                            (setf (gethash topic id-map) (%topic->id topic))))
                  (inn  (%inner tid))
                  (k    (%record-key writer-guid sn)))
             (cond
               ((gethash k inn) t)
               ((and (plusp max-samples) (>= (%total-count) max-samples)) :rejected)
               (t
                (let* ((rec   (make-durable-record :topic topic :writer-guid writer-guid
                                                   :sn sn :key-hash key-hash
                                                   :kind kind :payload payload))
                       (frame (%frame-record rec))
                       (stm   (%ensure-stream tid)))
                  (write-sequence frame stm)
                  (finish-output stm)
                  (setf (gethash k inn) rec)
                  t))))))

       :get-range
       (lambda (topic)
         (dds.pal:with-lock (lock)
           (let* ((tid  (gethash topic id-map))
                  (inn  (when tid (gethash tid outer))))
             (if (null inn)
                 '()
                 (let ((recs '()))
                   (maphash (lambda (k v) (declare (ignore k)) (push v recs)) inn)
                   (sort recs #'%record-guid-sn<))))))

       :topics
       (lambda ()
         (dds.pal:with-lock (lock)
           (let ((ts '()))
             (maphash (lambda (topic tid)
                        (let ((inn (gethash tid outer)))
                          (when (and inn (plusp (hash-table-count inn)))
                            (push topic ts))))
                      id-map)
             ts)))

       :purge
       (lambda (topic)
         (dds.pal:with-lock (lock)
           (let ((tid (gethash topic id-map)))
             (when tid
               ;; close + delete the topic log
               (let ((stm (gethash tid streams)))
                 (when stm
                   (ignore-errors (close stm))
                   (remhash tid streams)))
               (let ((log-path (%topic-log-path store-dir tid)))
                 (when (probe-file log-path)
                   (delete-file log-path)
                   ;; fsync the unlink dirent so a purged topic cannot reappear after
                   ;; power loss (ADR 0026 §10.10)
                   (dds.pal:fsync-directory (%topics-dir store-dir))))
               (remhash tid outer)
               (remhash topic id-map)))
           t))

       :open
       (lambda (open-hk open-hd)
         ;; effective policy: caller override wins when non-NIL; fall back to factory default
         (let ((eff-hk (or open-hk history-kind))
               (eff-hd (or open-hd history-depth)))
           ;; reset in-memory index so a re-open does not accumulate stale state
           (clrhash outer)
           (clrhash id-map)
           (clrhash streams)
           ;; enforce 0700 on the store dir D (holds cleartext frame metadata): chmod ONLY on first
           ;; creation, then ALWAYS verify (fail-closed refuse on loose/unverifiable perms) — exactly
           ;; the key-dir K discipline, one shared helper (DRY; ADR 0026 §10.12).
           (let ((existed (uiop:directory-exists-p store-dir)))
             (ensure-directories-exist (%topic-log-path store-dir "x"))
             (unless existed
               (dds.dare:enforce-directory-perms-0700 store-dir))
             (dds.dare:assert-directory-perms-0700 store-dir))
           ;; read topics.map to resolve topic-ids back to names
           (let ((tmap (%read-topics-map store-dir)))
             ;; build reverse: id -> topic
             (let ((id->topic (make-hash-table :test #'equal)))
               (maphash (lambda (id name) (setf (gethash id id->topic) name)) tmap)
               ;; replay each *.log in the topics/ subdir
               (let ((topics-dir (merge-pathnames
                                  (make-pathname :directory '(:relative "topics")) store-dir)))
                 (when (uiop:directory-exists-p topics-dir)
                   (dolist (log-path (uiop:directory-files topics-dir "*.log"))
                     (let* ((tid   (pathname-name log-path))
                            (topic (or (gethash tid id->topic) tid)))
                       (let* ((recs      (%replay-log log-path topic))
                              (compacted (%compact-topic-records recs eff-hk eff-hd)))
                         ;; rewrite the log when compaction dropped at least one record
                         (when (and recs (< (length compacted) (length recs)))
                           (%rewrite-topic-log store-dir tid compacted))
                         (when compacted
                           (setf (gethash topic id-map) tid)
                           (let ((inn (%inner tid)))
                             (dolist (r compacted)
                               (let ((k (%record-key (durable-record-writer-guid r)
                                                     (durable-record-sn r))))
                                 (setf (gethash k inn) r)))))))))
                 ;; rebuild topics.map with any recovered topics
                 (when (plusp (hash-table-count id-map))
                   (let ((new-map (make-hash-table :test #'equal)))
                     (maphash (lambda (topic tid) (setf (gethash tid new-map) topic)) id-map)
                     (%write-topics-map store-dir new-map))))))
           t))

       :close
       (lambda ()
         ;; fsync + close all open topic streams
         (maphash (lambda (tid stm)
                    (declare (ignore tid))
                    (ignore-errors (dds.pal:fsync-stream stm))
                    (ignore-errors (close stm)))
                  streams)
         (clrhash streams)
         ;; persist topics.map
         (when (plusp (hash-table-count id-map))
           (let ((tmap (make-hash-table :test #'equal)))
             (maphash (lambda (topic tid) (setf (gethash tid tmap) topic)) id-map)
             (%write-topics-map store-dir tmap)))
         t)

       :sync
       (lambda ()
         ;; group-commit: fsync every open stream after a drain tick. A fsync failure PROPAGATES
         ;; (no ignore-errors) so the collect loop surfaces it via *durability-error-hook* — a
         ;; failed flush must never be silently treated as durable (fail-closed, NFR-SEC-POSTURE).
         (dds.pal:with-lock (lock)
           (maphash (lambda (tid stm)
                      (declare (ignore tid))
                      (dds.pal:fsync-stream stm))
                    streams))
         t)

       :count-fn
       (lambda (topic)
         (dds.pal:with-lock (lock)
           (if topic
               (let* ((tid (gethash topic id-map))
                      (inn (when tid (gethash tid outer))))
                 (if inn (hash-table-count inn) 0))
               (%total-count))))))))

(defun* file-store-sync (store)
    (function (durable-store) (eql t))
  "Group-commit sync: call the store's :sync vtable slot if present, else no-op.
   Intended for the collect-loop drain tick (group-commit fsync per tick, not per put)."
  (let ((fn (durable-store-sync store)))
    (when fn (funcall fn)))
  t)
