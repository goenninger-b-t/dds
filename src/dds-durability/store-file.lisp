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
   The version the store writes when NO log-MAC chain is active.")
(defconstant +frame-version-v3+ #x03
  "Frame format version 3: v2 layout plus a 32-byte keyed HMAC-SHA-256 chain MAC between the payload
   and the trailing frame-CRC (ADR 0045). MAC_i = HMAC(logmac-key, chain_{i-1} ∥ frame_i[0..mac-off)),
   binding each frame to its predecessor so interior delete/reorder/substitution/insertion is
   tamper-evident at store-open. Written ONLY when a chain MAC oracle is installed (keyed store); the
   reader reads v1/v2/v3 per-frame (mixed logs legal). CRC = accidental detection; MAC = tamper.")
(defconstant +frame-mac-len+ 32
  "Width of the v3 frame chain-MAC field: HMAC-SHA-256 output length (FIPS 198-1; ADR 0045).")
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

(defun* %tmp-log-name-p (name)
    (function ((or null string)) boolean)
  "T iff NAME is a compaction-rewrite temp basename (`<topic-id>.tmp`, from `<topic-id>.tmp.log`).
   A real topic-id is lowercase hex (no `.`), so a `.tmp` suffix unambiguously marks an orphaned,
   UNCOMMITTED rewrite temp left by a crash between %rewrite-topic-log's tmp-write and its atomic
   rename (the rename is the commit point) — such files are discarded/skipped on open (ADR 0029 §10)."
  (let ((n (and name (length name))))
    (and n (>= n 4) (string= ".tmp" (subseq name (- n 4))))))

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

;;; Keyed log-MAC chain (ADR 0045). The MAC oracle is a closure (data)->HMAC-SHA-256(logmac-key,data)
;;; supplied by the encrypted-store decorator; the file store NEVER holds the key, only the oracle.

(defparameter %logmac-seed-label
  (map '(simple-array (unsigned-byte 8) (*)) #'char-code "dds-dare/logmac/seed/v1")
  "ASCII octets of the per-topic chain-seed HKDF domain label (ADR 0045 §4.2).")

(defun* %chain-mac-input (prev-mac buf start end)
    (function ((simple-array (unsigned-byte 8) (*)) (simple-array (unsigned-byte 8) (*))
               (integer 0) (integer 0))
              (simple-array (unsigned-byte 8) (*)))
  "Assemble one v3 chain-link HMAC input: PREV-MAC (first +frame-mac-len+ bytes) ∥ BUF[START..END)."
  (let* ((n   (- end start))
         (out (make-array (+ +frame-mac-len+ n) :element-type '(unsigned-byte 8))))
    (replace out prev-mac :end1 +frame-mac-len+ :end2 +frame-mac-len+)
    (replace out buf :start1 +frame-mac-len+ :start2 start :end2 end)
    out))

(defun* %chain-mac (mac-fn prev-mac buf start mac-off)
    (function (function (simple-array (unsigned-byte 8) (*)) (simple-array (unsigned-byte 8) (*))
               (integer 0) (integer 0))
              (simple-array (unsigned-byte 8) (*)))
  "Compute the v3 chain MAC for the frame at BUF[START..MAC-OFF): MAC-FN(PREV-MAC ∥ frame-prefix)."
  (funcall mac-fn (%chain-mac-input prev-mac buf start mac-off)))

(defun* %chain-seed (mac-fn topic)
    (function (function string) (simple-array (unsigned-byte 8) (*)))
  "Per-topic keyed chain head: MAC-FN(label ∥ utf8(TOPIC)) (ADR 0045 §4.2). Binds each topic's chain
   head to the topic identity + log-MAC key so another topic's valid log cannot be swapped in."
  (let* ((tb    (%string->utf8 topic))
         (ln    (length %logmac-seed-label))
         (input (make-array (+ ln (length tb)) :element-type '(unsigned-byte 8))))
    (replace input %logmac-seed-label :end1 ln)
    (replace input tb :start1 ln)
    (funcall mac-fn input)))

;;; Frame serialization.

(defun* %frame-record-versioned (record version &optional prev-mac chain-mac-fn)
    (function (durable-record (member #x01 #x02 #x03) &optional
               (or null (simple-array (unsigned-byte 8) (*))) (or null function))
              (values (simple-array (unsigned-byte 8) (*))
                      (or null (simple-array (unsigned-byte 8) (*)))))
  "Serialize RECORD into a frame of format VERSION, returning (values frame frame-mac).
   #x01 = legacy no-header-CRC (read-only back-compat, tests only). #x02 = header-CRC after
   payload-len (ADR 0026 §10.9). #x03 = v2 layout plus a 32-byte keyed chain MAC before the frame
   CRC (ADR 0045); v3 REQUIRES PREV-MAC (the previous frame's chain MAC, or the per-topic seed for
   the first) and CHAIN-MAC-FN (the HMAC oracle). FRAME-MAC is the frame's chain MAC for v3 (the
   running state for the next frame), NIL for v1/v2. The header/frame CRCs are unchanged; the frame
   CRC covers through the MAC field (CRC = accidental, MAC = tamper)."
  (let* ((payload    (durable-record-payload record))
         (key-hash   (durable-record-key-hash record))
         (kh-p       (not (null key-hash)))
         (hdr-crc-p  (or (= version +frame-version-v2+) (= version +frame-version-v3+)))
         (mac-p      (= version +frame-version-v3+))
         (plen       (length payload))
         ;; magic+version(2) flags(1) guid(16) sn(8) [kh(16)] plen(4) [hdr-crc(4)] payload [mac(32)] frame-crc(4)
         (frame-len  (+ 2 1 16 8 (if kh-p 16 0) 4 (if hdr-crc-p 4 0) plen (if mac-p +frame-mac-len+ 0) 4))
         (frame      (make-array frame-len :element-type '(unsigned-byte 8) :initial-element 0))
         (frame-mac  nil)
         (flags      (logior (%kind->int (durable-record-kind record))
                             (if kh-p +flag-key-hash-bit+ 0))))
    (when (and mac-p (or (null prev-mac) (null chain-mac-fn)))
      (error "dds.durability: v3 frame serialization requires prev-mac + chain-mac-fn (ADR 0045)"))
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
          (when mac-p
            ;; chain MAC over prev-mac ∥ frame[0..mac-off); frame CRC (below) then covers it
            (setf frame-mac (%chain-mac chain-mac-fn prev-mac frame 0 crc-offset))
            (replace frame frame-mac :start1 crc-offset :end1 (+ crc-offset +frame-mac-len+))
            (setf crc-offset (+ crc-offset +frame-mac-len+)))
          (%put-u32-le frame crc-offset (%crc32 frame 0 crc-offset)))))
    (values frame frame-mac)))

(defun* %frame-record (record)
    (function (durable-record) (simple-array (unsigned-byte 8) (*)))
  "Serialize RECORD into a complete v2 frame (no chain MAC) — used when NO log-MAC chain is active."
  (values (%frame-record-versioned record +frame-version-v2+)))

;;; Frame parsing for replay; returns (values record next-pos reason).
;;; reason: :ok on success; :short = insufficient bytes (torn tail); :corrupt = full bytes present but invalid.

(defun* %parse-frame (buf start end topic &optional chain-mac-fn prev-mac chain-started)
    (function ((simple-array (unsigned-byte 8) (*)) (integer 0) (integer 0) string &optional
               (or null function) (or null (simple-array (unsigned-byte 8) (*))) t)
              (values (or null durable-record) (integer 0) (member :ok :short :corrupt)
                      (or null (simple-array (unsigned-byte 8) (*)))))
  "Parse one frame (v1/v2/v3) from BUF[START..END) for TOPIC, dispatching on the version byte.
   Returns (values record next-pos :ok frame-mac) on success — FRAME-MAC is the v3 chain MAC (the
   running state for the next frame) or NIL for v1/v2.
   Returns (values nil start :short nil) when bytes from START to END are fewer than the full frame.
   Returns (values nil start :corrupt nil) when the full frame is present but invalid.
   A bad HEADER CRC / kind / frame CRC is :corrupt (a corrupt length is detected here rather than
   mis-parsed as a torn tail; a clean truncating crash can only SHORTEN → :short — ADR 0026 §10.9).
   v3 chain (ADR 0045): the frame's keyed HMAC is verified against CHAIN-MAC-FN(PREV-MAC ∥ prefix);
   a mismatch is :corrupt (tamper). A v3 frame with NO CHAIN-MAC-FN/PREV-MAC is :corrupt (key
   absent — a chain frame is never accepted unverified). Once the chain has started (CHAIN-STARTED),
   a subsequent non-v3 frame is a chain break → :corrupt."
  (let ((avail (- end start)))
    ;; Not enough bytes even for the minimum frame header → torn tail
    (when (< avail +frame-min-bytes+)
      (return-from %parse-frame (values nil start :short nil)))
    ;; Wrong magic with full header bytes available → corrupt
    (unless (= (aref buf start) +magic-0+)
      (return-from %parse-frame (values nil start :corrupt nil)))
    (let ((version (aref buf (1+ start))))
      ;; Unknown version byte with the magic present → corrupt (fail loud, never silent-skip)
      (unless (or (= version +frame-version-v1+) (= version +frame-version-v2+)
                  (= version +frame-version-v3+))
        (return-from %parse-frame (values nil start :corrupt nil)))
      (let* ((mac-p     (= version +frame-version-v3+))
             (hdr-crc-p (or (= version +frame-version-v2+) mac-p)))
        ;; Chain break: a non-v3 frame after the chain has started (an inserted/spliced pre-chain
        ;; frame mid-chain, or a truncation-and-append with older framing) → fail loud (ADR 0045).
        (when (and chain-started (not mac-p))
          (return-from %parse-frame (values nil start :corrupt nil)))
        ;; A v3 (chain) frame demands the key: no MAC oracle / no predecessor state ⇒ fail closed.
        (when (and mac-p (or (null chain-mac-fn) (null prev-mac)))
          (return-from %parse-frame (values nil start :corrupt nil)))
        (let* ((flags     (aref buf (+ start 2)))
               (kh-p      (logbitp 2 flags))
               (kind-int  (logand flags +flag-kind-mask+))
               (guid      (make-array 16 :element-type '(unsigned-byte 8)))
               (sn-off    (+ start 19))
               (kh-off    (+ start 27))
               (plen-off  (if kh-p (+ kh-off 16) kh-off))
               (hdr-crc-off (+ plen-off 4))                     ; v2/v3 header CRC sits right after plen
               (payload-off (if hdr-crc-p (+ hdr-crc-off 4) (+ plen-off 4)))
               (hdr-need  (+ (- payload-off start) 4)))         ; bytes through header(+hdr-crc)+empty payload+crc
          ;; Not enough bytes to read the header (incl. header-crc) → short (torn at header boundary)
          (when (< avail hdr-need)
            (return-from %parse-frame (values nil start :short nil)))
          (replace guid buf :start2 (+ start 3) :end2 (+ start 19))
          ;; v2/v3: validate the header CRC BEFORE trusting plen (a mismatch is genuine corruption).
          (when hdr-crc-p
            (let ((stored-hdr (%get-u32-le buf hdr-crc-off))
                  (actual-hdr (%crc32 buf start hdr-crc-off)))
              (unless (= stored-hdr actual-hdr)
                (return-from %parse-frame (values nil start :corrupt nil)))))
          (let* ((sn         (%get-u64-le buf sn-off))
                 (kh         (when kh-p
                               (let ((v (make-array 16 :element-type '(unsigned-byte 8))))
                                 (replace v buf :start2 kh-off :end2 (+ kh-off 16))
                                 v)))
                 (plen        (%get-u32-le buf plen-off))
                 (payload-end (+ payload-off plen))             ; = mac-off for v3, = crc-off for v1/v2
                 (mac-off     payload-end)
                 (crc-off     (+ payload-end (if mac-p +frame-mac-len+ 0)))
                 (frame-end   (+ crc-off 4)))
            ;; Gross length-field corruption: declared payload above the sanity cap is corrupt.
            (when (> plen +frame-max-payload+)
              (return-from %parse-frame (values nil start :corrupt nil)))
            ;; Full declared frame does not fit in buffer → short (torn write)
            (when (> frame-end end)
              (return-from %parse-frame (values nil start :short nil)))
            ;; Full frame present; validate kind bits before CRC to keep :corrupt reason consistent
            (let ((kind (%int->kind kind-int)))
              (unless kind
                (return-from %parse-frame (values nil start :corrupt nil)))
              (let ((stored-crc (%get-u32-le buf crc-off))
                    (actual-crc (%crc32 buf start crc-off)))
                (unless (= stored-crc actual-crc)
                  (return-from %parse-frame (values nil start :corrupt nil)))
                ;; v3: verify the keyed chain MAC (the frame CRC above already passed, so a
                ;; CRC-recomputing substitution adversary is caught HERE — a MAC forgery needs the key).
                (let ((frame-mac nil))
                  (when mac-p
                    (let ((expected (%chain-mac chain-mac-fn prev-mac buf start mac-off))
                          (stored   (make-array +frame-mac-len+ :element-type '(unsigned-byte 8))))
                      (replace stored buf :start2 mac-off :end2 crc-off)
                      (unless (equalp expected stored)
                        (return-from %parse-frame (values nil start :corrupt nil)))
                      (setf frame-mac stored)))
                  (let ((payload (make-array plen :element-type '(unsigned-byte 8))))
                    (replace payload buf :start2 payload-off :end2 payload-end)
                    (values (make-durable-record
                             :topic      topic
                             :writer-guid guid
                             :sn         sn
                             :key-hash   kh
                             :kind       kind
                             :payload    payload)
                            frame-end
                            :ok
                            frame-mac)))))))))))

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

(defun* %chain-walk (path topic mac-fn stop-at)
    (function (pathname string function (or null (integer 0)))
              (values (integer 0) (simple-array (unsigned-byte 8) (*))
                      (member :reached :clean :torn :corrupt)))
  "READ-ONLY walk of the v3 chain in PATH for TOPIC under MAC-FN (never truncates/rewrites, unlike
   %replay-log) — the shared engine of the sealed high-water tail anchor (ADR 0045 §7.1). Seeds from the
   per-topic keyed head, verifies each v3 frame's MAC in on-disk order, and counts ONLY v3 frames (a
   legacy v1/v2 prefix is walked over without counting, matching how the frames were sealed). Returns
   (values v3-count running-mac end-reason):
     STOP-AT non-NIL and reached ⇒ :reached, RUNNING-MAC = the running chain MAC after exactly STOP-AT
       v3 frames (the tail anchor's prefix-containment probe; forward frames past STOP-AT are ignored);
     else the walk runs to its natural end — :clean (ended on a frame boundary), :torn (a short trailing
       partial frame = an honest crash mid-append), or :corrupt (a bad/mismatched frame).
   The tail-anchor SEAL (STOP-AT NIL → v3-count + tail-MAC) and the prefix-containment VERIFY (STOP-AT N)
   share this ONE walk, so their counting + MAC computation are byte-identical (no drift)."
  (let ((seed (%chain-seed mac-fn topic)))
    (unless (probe-file path)
      (return-from %chain-walk (values 0 seed :clean)))
    (let* ((size    (with-open-file (s path :element-type '(unsigned-byte 8)) (file-length s)))
           (buf     (make-array size :element-type '(unsigned-byte 8)))
           (pos     0)
           (count   0)
           (running seed)
           (started nil))
      (with-open-file (s path :element-type '(unsigned-byte 8) :direction :input)
        (read-sequence buf s))
      (loop
        (when (and stop-at (>= count stop-at))
          (return (values count running :reached)))     ; committed prefix reached (running = MAC@count)
        (when (>= pos size)
          (return (values count running :clean)))        ; ended on a frame boundary (< STOP-AT if any)
        (multiple-value-bind (rec next reason frame-mac)
            (%parse-frame buf pos size topic mac-fn running started)
          (declare (ignore rec))
          (cond
            ((eq reason :ok)
             (when frame-mac                              ; a v3 frame advances + counts the chain
               (setf running frame-mac started t)
               (incf count))
             (setf pos next))
            ((eq reason :short) (return (values count running :torn)))    ; honest torn trailing frame
            (t                  (return (values count running :corrupt))))))))) ; tamper — defer to open

;;; Replay one topic log, returning a list of durable-records.
;;; :short at the tail → truncate to last-valid, recover.
;;; :corrupt anywhere → error (fail loud; never silently drop mid-file data).

(defun* %replay-log (path topic &optional chain-mac-fn chain-required)
    (function (pathname string &optional (or null function) t)
              (values list (or null (simple-array (unsigned-byte 8) (*)))))
  "Replay frames from PATH for TOPIC into (values records tail-mac).
   A :short reason at the trailing position truncates to last-valid and recovers.
   A :corrupt reason at any position signals an error (ADR 0026 §File-store on-disk format).
   When CHAIN-MAC-FN is supplied (keyed store, ADR 0045) the per-topic running chain MAC is verified:
   the seed is the keyed per-topic head, each v3 frame's MAC is checked against its predecessor, and
   TAIL-MAC is the last v3 frame's MAC (NIL if no v3 frame seen) — the running state the file store
   carries into the next appended frame, so the chain is continuous across epochs/restarts.
   When CHAIN-REQUIRED is true (ADR 0045 §3.2 downgrade defense) a non-empty log that replays to ZERO
   v3 frames — a full v3->v2 keyless downgrade — SIGNALS (fail loud, before any compaction rewrite).
   (A v2/v1 frame AFTER a v3 frame is already rejected mid-replay, so a v3-tail proves an active chain.)"
  (unless (probe-file path)
    (return-from %replay-log (values '() nil)))
  (let* ((size   (with-open-file (s path :element-type '(unsigned-byte 8)) (file-length s)))
         (buf    (make-array size :element-type '(unsigned-byte 8)))
         (records '())
         (pos     0)
         (last-valid 0)
         (seed    (when chain-mac-fn (%chain-seed chain-mac-fn topic)))
         (running seed)                                        ; prev-mac for the next v3 frame
         (started nil)
         (tail-mac nil))
    (with-open-file (s path :element-type '(unsigned-byte 8) :direction :input)
      (read-sequence buf s))
    (loop
      (when (>= pos size) (return))
      (multiple-value-bind (rec next reason frame-mac)
          (%parse-frame buf pos size topic chain-mac-fn running started)
        (cond
          (rec
           (push rec records)
           (when frame-mac                                     ; a v3 frame advances the chain
             (setf running  frame-mac
                   tail-mac frame-mac
                   started  t))
           (setf last-valid next)
           (setf pos next))
          ;; :short → not enough bytes for the full declared frame; torn tail if at last-valid
          ((eq reason :short)
           (when (< last-valid size)
             (%truncate-file path last-valid))
           (return))
          ;; :corrupt → full frame bytes present but magic/kind/CRC/MAC invalid; fail loud
          (t
           (error "dds.durability: mid-file corruption in ~a at offset ~d (last valid ~d; reason ~s)"
                  path pos last-valid reason)))))
    (when (and (zerop last-valid) (plusp size))
      ;; file had bytes but the very first frame was :short (all-garbage file) → truncate
      (%truncate-file path 0))
    ;; downgrade defense (ADR 0045 §3.2): a chain-committed store whose non-empty log carries NO v3
    ;; frame has been rolled back to keyless v2 — refuse the open (like a mid-log chain break), and
    ;; do it HERE so the caller's compaction rewrite can never launder the tampered set into a fresh chain.
    (when (and chain-required records (not started))
      (error "dds.durability: chain-required log ~a has ~d record(s) but NO v3 chain frame — ~
              refusing to open (full v3->v2 downgrade / tamper; ADR 0045 §3.2)"
             path (length records)))
    (values (nreverse records) tail-mac)))

;;; Compaction: drop settled (dispose+unregister both present) instances.

(defun* %keep-last-latest (records history-depth)
    (function (list (integer 1)) list)
  "Pass-2 KEEP_LAST filter: keep only the newest HISTORY-DEPTH :data records per non-NIL key-hash
   instance (highest by %record-guid-sn<); lifecycle (:dispose/:unregister) and NIL-key-hash records
   pass through; append order preserved. Shared by %compact-topic-records pass 2 AND the file store's
   read-time logical view (store-get-range / per-topic store-count), so the file store's online newest-D
   view matches the memory + SQLite backends' DEPTH-ONLY online eviction exactly (DRY, one definition).
   Depth-only (no settled/pass-1 drop) — the bare backends never drop settled instances on read."
  (let ((drop-set (make-hash-table :test #'eq))     ; record identity -> drop?
        (buckets  (make-hash-table :test #'equalp))) ; non-NIL key-hash -> its :data records
    (dolist (r records)
      (let ((kh (durable-record-key-hash r)))
        (when (and kh (eq :data (durable-record-kind r)))
          (push r (gethash kh buckets '())))))
    (maphash (lambda (kh bucket)
               (declare (ignore kh))
               (when (> (length bucket) history-depth)
                 ;; sort ascending by (guid sn); oldest first; drop all but the newest depth
                 (let* ((sorted  (sort (copy-list bucket) #'%record-guid-sn<))
                        (to-drop (subseq sorted 0 (- (length sorted) history-depth))))
                   (dolist (r to-drop) (setf (gethash r drop-set) t)))))
             buckets)
    (loop for r in records unless (gethash r drop-set) collect r)))

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
          ;; pass 2 (shared %keep-last-latest): per-instance KEEP_LAST — keep only the newest
          ;; HISTORY-DEPTH :data records per non-NIL key-hash; lifecycle + NIL-key-hash pass through
          (%keep-last-latest kept history-depth)
          ;; :keep-all — pass 2 skipped; return settled-only result
          kept))))

;;; Runtime threshold compaction (Sliver 2, ADR 0029 §10 / ADR 0026 §10 item 2). The file store is
;;; APPEND-ONLY — it cannot delete-a-record-in-place — so a continuously-open KEEP_LAST log cannot
;;; evict per put like the memory/SQLite backends. Instead each superseding put bumps an O(1) per-topic
;;; counter and crossing *compaction-superseded-threshold* triggers ONE atomic %rewrite-topic-log MID-RUN
;;; (no close/open cycle), bounding the on-disk log to (live-count + threshold) records. The rewrite is
;;; the SAME crash-atomic tmp+fsync+rename path the on-open compaction already uses (NO new transaction
;;; machinery — the atomicity is inherited); the batch amortizes the O(topic) rewrite over ~threshold puts.

(defparameter *compaction-superseded-threshold* 128
  "Runtime file-store compaction trigger (ADR 0029 §10): the number of KEEP_LAST-superseded :data
   records a per-topic append-log may accumulate before the store compacts that topic MID-RUN via the
   atomic %rewrite-topic-log — WITHOUT a store-close/store-open cycle. An append-only log cannot
   delete-in-place, so it compacts in BATCHES: each superseding :data put bumps an O(1) per-topic
   counter, and crossing this threshold triggers ONE O(topic) atomic rewrite. Amortizes the rewrite
   over ~threshold puts and bounds the on-disk log to (live-count + threshold) records (the memory /
   SQLite backends evict per put, so they bound to live-count exactly; the append-only file store
   trades a bounded slack for a batched rewrite). Larger ⇒ fewer rewrites, looser bound; smaller ⇒
   tighter log, more frequent rewrites. Default 128: at most a few KiB of superseded frames per topic
   between rewrites, negligible against the amortized rewrite cost. A special variable so it is tunable
   (rebind before/among puts; read per put). KEEP_ALL stores never consult it (no depth supersession).")

(defparameter *durability-debug-file-rewrite-fault* nil
  "Test-only fault injector (ADR 0029 §10 crash-consistency). NIL (default) ⇒ inert; byte-identical
   behavior. When non-NIL, %rewrite-topic-log signals an error AFTER the compacted <log>.tmp is written
   and fsynced but BEFORE the atomic rename over the original — exercising the crash-before-commit path:
   the original log stays intact, the .tmp is orphaned, and a reopen recovers the pre-rewrite log and
   recompacts it (no torn log, no data loss, no false-reject). Proves the MID-RUN rewrite inherits the
   tmp+fsync+rename atomicity exactly. Never set in production code.")

(defun* %rewrite-topic-log (dir tid records &optional chain-mac-fn topic)
    (function (pathname string list &optional (or null function) (or null string))
              (or null (simple-array (unsigned-byte 8) (*))))
  "Atomically rewrite the log for TID under DIR with RECORDS; return the new tail chain MAC (or NIL).
   Writes to <log>.tmp, fsyncs, then renames .tmp over the original in one atomic step
   (uiop:rename-file-overwriting-target is POSIX rename(2) — no crash window).
   When CHAIN-MAC-FN is supplied (keyed store, ADR 0045) the compacted records are re-emitted as a
   FRESH v3 chain (re-seed from the per-topic keyed head, re-MAC each kept record in order) — an
   authorized local rewrite an adversary without the key cannot forge; without it, byte-identical v2."
  (let* ((log-path (%topic-log-path dir tid))
         (tmp-path (merge-pathnames
                    (make-pathname :name (concatenate 'string tid ".tmp") :type "log")
                    (merge-pathnames (make-pathname :directory '(:relative "topics")) dir)))
         (running  (when chain-mac-fn (%chain-seed chain-mac-fn (or topic tid))))
         (tail-mac  nil))
    (with-open-file (stm tmp-path
                         :direction :output
                         :element-type '(unsigned-byte 8)
                         :if-exists :supersede
                         :if-does-not-exist :create)
      (dolist (r records)
        (if chain-mac-fn
            (multiple-value-bind (frame mac)
                (%frame-record-versioned r +frame-version-v3+ running chain-mac-fn)
              (write-sequence frame stm)
              (setf running mac tail-mac mac))
            (write-sequence (%frame-record r) stm)))
      (dds.pal:fsync-stream stm))
    ;; crash-consistency fault seam (ADR 0029 §10): the <log>.tmp is fully written + fsynced; a crash
    ;; HERE (before the rename) leaves the ORIGINAL log intact (rename is the atomic commit point).
    (when *durability-debug-file-rewrite-fault*
      (error "dds.durability: *durability-debug-file-rewrite-fault* — simulated crash after ~a.tmp ~
              fsync, before the atomic rename (crash-before-commit; original log intact)" tid))
    (uiop:rename-file-overwriting-target tmp-path log-path)
    ;; fsync the containing dir so the compaction rename's dirent survives power loss (ADR 0026 §10.10 / 0029)
    (dds.pal:fsync-directory (%topics-dir dir))
    tail-mac))

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
         (store-dir (when dir (pathname dir)))
         ;; keyed log-MAC chain (ADR 0045): oracle closure installed by the encrypted decorator;
         ;; NIL for a bare file store (no key ⇒ writes v2, and a v3 frame on replay fails loud).
         (chain-mac-fn nil)
         ;; chain-REQUIRED (ADR 0045 §3.2 downgrade defense): set by the decorator iff the log-MAC
         ;; anchor is present. When true, a non-empty topic log that replays to ZERO v3 frames
         ;; (a full v3->v2 keyless downgrade) fails the open loudly, before compaction.
         (chain-required nil)
         ;; grandfather set (ADR 0045 §3.2): topic-ids EXEMPT from the per-topic downgrade check
         ;; (the pre-existing legacy topics recorded, authenticated, in the anchor). NIL = none.
         (chain-grandfather nil)
         (chain-macs   (make-hash-table :test #'equal)) ; topic-id -> running chain MAC (32 octets)
         ;; runtime threshold compaction state (Sliver 2, ADR 0029 §10). The effective policy cells are
         ;; set by :open (mirroring the memory store's hk-cell/depth-cell) so the :put path knows the
         ;; depth D + whether KEEP_LAST is active; super-pending counts KEEP_LAST-superseded :data
         ;; records per topic since the last rewrite; data-counts is a per-instance :data tally giving
         ;; O(1) supersede detection (no per-put whole-topic scan).
         (eff-hk-cell  (cons history-kind nil))   ; car = effective history-kind (:keep-all/:keep-last)
         (eff-hd-cell  (cons history-depth nil))  ; car = effective history-depth D
         (super-pending (make-hash-table :test #'equal))  ; topic-id -> pending superseded/settled reclaimable count
         (data-counts  (make-hash-table :test #'equal))   ; topic-id -> (equalp key-hash -> :data count)
         ;; settled-instance-churn trigger (ADR 0029 §10.1): topic-id -> (equalp key-hash -> settle-tally).
         ;; Mirrors data-counts but tracks the FULL lifecycle so a settling instance (dispose+unregister,
         ;; final tombstone — the pass-1 predicate) that never bumps the KEEP_LAST supersede counter still
         ;; folds its reclaimable frame count into super-pending, firing the SAME threshold rewrite (which
         ;; pass-1 reclaims). TRIGGER-ONLY: the rewrite machinery is unchanged; a live instance never settles.
         (settle-tallies (make-hash-table :test #'equal))
         ;; Sliver 3b (ADR 0025 §10.3): topic-id -> (equal %record-key -> t) set of surrogates the
         ;; encrypted decorator's store-delete has remhashed from the index but NOT yet physically excluded
         ;; from the append log; its size is the O(1) reclaim trigger (the inner :keep-all store's own
         ;; KEEP_LAST counter never fires here — NIL key-hash). IN-MEMORY (empty on reopen; the surrogates
         ;; reappear in the log and get-range logically compacts them — self-healing; cross-restart sweep = 3c).
         (pending-delete (make-hash-table :test #'equal)))

    (labels ((%inner (topic-id)
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
             (cons (coerce writer-guid 'list) sn))
           (%topic-logical-records (topic-id)
             ;; the LOGICAL KEEP_LAST view for TOPIC-ID: the raw index records, sorted canonically by
             ;; %record-guid-sn<, then under :keep-last the shared pass-2 %keep-last-latest (newest-D
             ;; :data per instance). So store-get-range + per-topic store-count return exactly the
             ;; newest-D view — matching the memory + SQLite backends' DEPTH-ONLY online eviction — while
             ;; the physical log stays batched-bounded by the threshold rewrite (ADR 0029 §10.1). Pass-2
             ;; ONLY, not on-open's pass-1 settled drop: the bare backends never drop settled instances
             ;; on read (memory keeps them, SQLite keeps them), so :keep-all is the raw sorted view
             ;; (byte-identical) — the encrypted decorator does its own both-pass compaction on top.
             (let ((inn (and topic-id (gethash topic-id outer))))
               (if (null inn)
                   '()
                   (let* ((recs   (let ((acc '()))
                                    (maphash (lambda (k v) (declare (ignore k)) (push v acc)) inn)
                                    acc))
                          (sorted (sort recs #'%record-guid-sn<)))
                     (if (eq :keep-last (car eff-hk-cell))
                         (%keep-last-latest sorted (car eff-hd-cell))
                         sorted)))))
           (%init-topic-counts (topic-id records)
             ;; (re)seed the runtime-compaction counters for TOPIC-ID from RECORDS (append order): a zeroed
             ;; pending counter + a per-instance :data tally (O(1) supersede test) + a per-instance settle
             ;; tally (O(1) settle test + reclaimable count). RECORDS are the post-compaction survivors, so
             ;; no instance is settled here (pass-1 already dropped those) ⇒ every reseeded tally ends
             ;; COUNTED nil (a resurrected survivor's trailing :data clears the transient settle).
             (setf (gethash topic-id super-pending) 0)
             (let ((dc (make-hash-table :test #'equalp))
                   (st (make-hash-table :test #'equalp)))
               (dolist (r records)
                 (let ((kh (durable-record-key-hash r)))
                   (when kh
                     (when (eq :data (durable-record-kind r))
                       (incf (gethash kh dc 0)))
                     (%settle-tally-fold (or (gethash kh st)
                                             (setf (gethash kh st) (%make-settle-tally)))
                                         (durable-record-kind r)))))
               (setf (gethash topic-id data-counts) dc)
               (setf (gethash topic-id settle-tallies) st)))
           (%compact-topic-log (topic-id topic pre-filter reset-thunk)
             ;; shared MID-RUN atomic-rewrite core (Sliver 2 threshold-compact + Sliver 3b delete-reclaim,
             ;; DRY): release the append fd BEFORE the rewrite so no stale fd survives the atomic rename (a
             ;; stale fd appending to the renamed-away log = DATA LOSS); replay the log; apply PRE-FILTER
             ;; (Sliver-3b pending-delete exclusion; #'identity for Sliver 2); %compact-topic-records
             ;; (pass-1 settled + pass-2 KEEP_LAST, IDENTICAL to on-open); and on a SHRINK run the EXISTING
             ;; atomic %rewrite-topic-log (tmp+fsync+rename — crash-atomicity inherited, no new transaction
             ;; machinery) + rebuild the in-memory index + reseed counters + carry the fresh tail chain MAC
             ;; (ADR 0045). RESET-THUNK clears the per-topic trigger last (super-pending / pending-delete);
             ;; a rewrite fault propagates BEFORE it, leaving the trigger armed so the next call retries.
             (let ((log-path (%topic-log-path store-dir topic-id))
                   (stm      (gethash topic-id streams)))
               (when stm
                 (ignore-errors (dds.pal:fsync-stream stm))
                 (ignore-errors (close stm))
                 (remhash topic-id streams))
               (let* ((recs      (%replay-log log-path topic chain-mac-fn nil))
                      (filtered  (funcall pre-filter recs))
                      (compacted (%compact-topic-records filtered (car eff-hk-cell) (car eff-hd-cell))))
                 (when (and recs (< (length compacted) (length recs)))
                   (let ((tail (%rewrite-topic-log store-dir topic-id compacted chain-mac-fn topic)))
                     ;; carry the rewritten tail so the next appended v3 frame chains from it (ADR 0045)
                     (if tail
                         (setf (gethash topic-id chain-macs) tail)
                         (remhash topic-id chain-macs))
                     (let ((inn (%inner topic-id)))
                       (clrhash inn)
                       (dolist (r compacted)
                         (setf (gethash (%record-key (durable-record-writer-guid r)
                                                     (durable-record-sn r))
                                        inn)
                               r)))
                     (%init-topic-counts topic-id compacted)))
                 (funcall reset-thunk))))
           (%threshold-compact (topic-id topic)
             ;; Sliver 2 (ADR 0029 §10): the append-only KEEP_LAST log compacts MID-RUN — each superseding
             ;; put bumps super-pending, and crossing the threshold runs the shared atomic core (identity
             ;; filter; the KEEP_LAST drop is %compact-topic-records's own pass-2), then resets super-pending.
             (%compact-topic-log topic-id topic #'identity
                                 (lambda () (setf (gethash topic-id super-pending) 0))))
           (%reclaim-deleted-topic (topic-id topic)
             ;; Sliver 3b (ADR 0025 §10.3): physically reclaim the encrypted decorator's pending-delete
             ;; surrogates from the append-only log via the shared atomic core, replaying EXCLUDING the
             ;; pending-delete keys (they are NIL-key-hash, so %compact-topic-records never drops them —
             ;; store-delete's own size trigger drives this, not the dormant KEEP_LAST counter). Clear the
             ;; pending-delete set after the rewrite; a rewrite fault leaves it populated (size still over
             ;; threshold) so the next store-delete retries (self-heals the continuously-open case).
             (let ((pd (gethash topic-id pending-delete)))
               (%compact-topic-log topic-id topic
                                   (if pd
                                       (lambda (recs)
                                         (remove-if (lambda (r)
                                                      (gethash (%record-key
                                                                (durable-record-writer-guid r)
                                                                (durable-record-sn r))
                                                               pd))
                                                    recs))
                                       #'identity)
                                   (lambda () (when pd (clrhash pd)))))))

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
                       (stm   (%ensure-stream tid)))
                  (if chain-mac-fn
                      ;; keyed store: write a v3 frame chained from this topic's running MAC
                      ;; (seeded per topic on the first put), then advance the running state.
                      (let ((prev (or (gethash tid chain-macs)
                                      (%chain-seed chain-mac-fn topic))))
                        (multiple-value-bind (frame mac)
                            (%frame-record-versioned rec +frame-version-v3+ prev chain-mac-fn)
                          (write-sequence frame stm)
                          (setf (gethash tid chain-macs) mac)))
                      (write-sequence (%frame-record rec) stm))
                  (finish-output stm)
                  (setf (gethash k inn) rec)
                  ;; settled-instance-churn trigger (ADR 0029 §10.1): an endlessly-distinct settling
                  ;; instance (new key → ≤D :data → dispose → unregister, never re-touched) stays within
                  ;; depth D, so it NEVER bumps the KEEP_LAST supersede counter below → a continuously-open
                  ;; log would grow without bound. Fold every keyed put into a per-instance lifecycle tally
                  ;; and, on the SETTLE transition (the pass-1 predicate: dispose+unregister both seen AND
                  ;; this tombstone is the final record), charge its reclaimable frame count into super-
                  ;; pending — the SAME threshold then fires the SAME atomic %rewrite-topic-log, whose
                  ;; UNCHANGED pass-1 reclaims the settle. TRIGGER-ONLY (only the counting is new); a live
                  ;; instance never settles ⇒ no false-reclaim. Runs BEFORE the :data-gated supersede block
                  ;; (a tombstone put never also supersedes), so a compaction here reseeds cleanly.
                  (when (and key-hash (not *durability-debug-disable-settle-trigger*))
                    (let* ((st    (or (gethash tid settle-tallies)
                                      (setf (gethash tid settle-tallies)
                                            (make-hash-table :test #'equalp))))
                           (tally (or (gethash key-hash st)
                                      (setf (gethash key-hash st) (%make-settle-tally)))))
                      (when (%settle-tally-fold tally kind)
                        (let ((reclaim (settle-tally-frames tally)))
                          (setf (settle-tally-frames tally) 0)   ; charge each frame at most once/rewrite
                          (when (>= (incf (gethash tid super-pending 0) reclaim)
                                    *compaction-superseded-threshold*)
                            (%threshold-compact tid topic))))))
                  ;; runtime threshold compaction (Sliver 2, ADR 0029 §10): O(1) supersede detection —
                  ;; a :data put that pushes a KEEP_LAST instance PAST depth D makes an older record
                  ;; droppable; bump the per-topic superseded counter and, on crossing
                  ;; *compaction-superseded-threshold*, run the atomic %rewrite-topic-log MID-RUN so a
                  ;; continuously-open log stays bounded (~ live-count + threshold) with NO reopen.
                  (when (and (eq :keep-last (car eff-hk-cell)) (eq :data kind) key-hash)
                    (let* ((dc (or (gethash tid data-counts)
                                   (setf (gethash tid data-counts)
                                         (make-hash-table :test #'equalp))))
                           (c  (incf (gethash key-hash dc 0))))
                      (when (and (> c (car eff-hd-cell))
                                 (>= (incf (gethash tid super-pending 0))
                                     *compaction-superseded-threshold*))
                        (%threshold-compact tid topic))))
                  t))))))

       :get-range
       (lambda (topic)
         (dds.pal:with-lock (lock)
           ;; LOGICAL KEEP_LAST view (exactly newest-D), matching memory / SQLite / encrypted; the
           ;; physical log stays batched-bounded by the Sliver-2 threshold rewrite (ADR 0029 §10.1)
           (%topic-logical-records (gethash topic id-map))))

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
               (remhash tid pending-delete)   ; Sliver-3b: drop any pending physical deletes for the purged topic
               (remhash tid settle-tallies)   ; drop the purged topic's settle tally (ADR 0029 §10.1; mirrors pending-delete)
               ;; drop the stale running chain head so a reput re-seeds from the per-topic head, not the
               ;; pre-purge tail — else reopen's re-seeded replay mismatches the first frame (no false-reject; ADR 0045)
               (remhash tid chain-macs)
               (remhash topic id-map)))
           t))

       :open
       (lambda (open-hk open-hd)
         ;; effective policy: caller override wins when non-NIL; fall back to factory default
         (let ((eff-hk (or open-hk history-kind))
               (eff-hd (or open-hd history-depth)))
           ;; stash the effective policy so the :put path can drive Sliver-2 threshold compaction
           (setf (car eff-hk-cell) eff-hk
                 (car eff-hd-cell) eff-hd)
           ;; reset in-memory index so a re-open does not accumulate stale state
           (clrhash outer)
           (clrhash id-map)
           (clrhash streams)
           (clrhash chain-macs)          ; running chain state is rebuilt from disk on replay (ADR 0045)
           (clrhash super-pending)       ; Sliver-2 runtime-compaction counters reseeded per topic below
           (clrhash data-counts)
           (clrhash settle-tallies)      ; settled-instance-churn tallies reseeded per topic below (ADR 0029 §10.1)
           (clrhash pending-delete)      ; Sliver-3b pending physical deletes are IN-MEMORY (empty on reopen; 3c sweeps cross-restart leftovers)
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
                   ;; crash recovery (ADR 0029 §10): discard orphaned <tid>.tmp.log files left by a
                   ;; crash BETWEEN a compaction rewrite's tmp-write and its atomic rename — the rename
                   ;; is the commit point, so an un-renamed .tmp is uncommitted and the original
                   ;; <tid>.log is authoritative. Skip them in replay so the *.log glob never mis-loads
                   ;; a temp as a bogus topic (which would fail the keyed chain verify → false-reject).
                   (dolist (pn (uiop:directory-files topics-dir "*.log"))
                     (when (%tmp-log-name-p (pathname-name pn))
                       (ignore-errors (delete-file pn))))
                   (dolist (log-path (remove-if (lambda (pn) (%tmp-log-name-p (pathname-name pn)))
                                                (uiop:directory-files topics-dir "*.log")))
                     (let* ((tid   (pathname-name log-path))
                            (topic (or (gethash tid id->topic) tid))
                            ;; per-topic downgrade guard: required unless this legacy topic is
                            ;; grandfathered (exempt) by the authenticated anchor set (ADR 0045 §3.2)
                            (topic-required (and chain-required
                                                 (not (and chain-grandfather
                                                           (gethash tid chain-grandfather))))))
                       (multiple-value-bind (recs tail-mac)
                           (%replay-log log-path topic chain-mac-fn topic-required) ; verifies + downgrade-guards
                        (let ((compacted (%compact-topic-records recs eff-hk eff-hd)))
                         ;; rewrite the log when compaction dropped at least one record (a keyed
                         ;; rewrite re-emits a fresh v3 chain and returns its new tail MAC, ADR 0045)
                         (when (and recs (< (length compacted) (length recs)))
                           (setf tail-mac
                                 (%rewrite-topic-log store-dir tid compacted chain-mac-fn topic)))
                         ;; carry the replayed (or rewritten) tail into the running chain state
                         (when tail-mac (setf (gethash tid chain-macs) tail-mac))
                         (when compacted
                           (setf (gethash topic id-map) tid)
                           (let ((inn (%inner tid)))
                             (dolist (r compacted)
                               (let ((k (%record-key (durable-record-writer-guid r)
                                                     (durable-record-sn r))))
                                 (setf (gethash k inn) r))))
                           ;; seed the Sliver-2 runtime-compaction counters from the compacted survivors
                           (%init-topic-counts tid compacted)))))))
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
       ;; per-topic count is LOGICAL (post-compaction, matching get-range + the encrypted decorator),
       ;; since the append-only log retains superseded frames physically between threshold rewrites;
       ;; total count (NIL topic) is the PHYSICAL record count (identical to the decorator's contract).
       (lambda (topic)
         (dds.pal:with-lock (lock)
           (if topic
               (length (%topic-logical-records (gethash topic id-map)))
               (%total-count))))

       :set-chain-mac-fn
       ;; keyed-store seam (ADR 0045): the encrypted decorator installs the log-MAC oracle here
       ;; BEFORE it drives store-open, so replay verifies + writes chain with the key in hand.
       ;; The file store holds only this closure, never the key bytes. REQUIRED (§3.2) marks the
       ;; store as chain-committed so a full v3->v2 downgrade of a non-empty log fails the open;
       ;; GRANDFATHER (a topic-id hash-set or NIL) names legacy topics exempt from that check.
       (lambda (fn required grandfather)
         (dds.pal:with-lock (lock)
           (setf chain-mac-fn fn)
           (setf chain-required required)
           (setf chain-grandfather grandfather))
         t)

       :chain-tails-fn
       ;; sealed high-water tail-anchor SEAL seam (ADR 0045 §7.1): for each CHAINED topic (a live v3
       ;; chain in chain-macs), re-walk its on-disk log via the shared %chain-walk to its natural end,
       ;; yielding (v3-count N . tail-MAC M_N). The re-walk reads the durable bytes (the decorator
       ;; store-syncs first), so the sealed (N, M_N) is byte-identical to what the open-time verify
       ;; re-walks. id-map's key is the topic name the frames were sealed under (the encrypted
       ;; surrogate th), used for the per-topic seed. A bare (un-chained) store returns an empty set.
       (lambda ()
         (dds.pal:with-lock (lock)
           (let ((result (make-hash-table :test #'equal)))
             (when chain-mac-fn
               (maphash (lambda (topic tid)
                          (when (gethash tid chain-macs)
                            (multiple-value-bind (n mac reason)
                                (%chain-walk (%topic-log-path store-dir tid) topic chain-mac-fn nil)
                              (declare (ignore reason))
                              (when (plusp n)
                                (setf (gethash tid result) (cons n mac))))))
                        id-map))
             result)))

       :verify-chain-prefix-fn
       ;; sealed high-water tail-anchor VERIFY seam (ADR 0045 §7.1): re-walk TOPIC-ID's on-disk chain to
       ;; ordinal N (%chain-walk STOP-AT) and decide prefix-containment. Resolve TOPIC-ID -> the seed
       ;; topic via topics.map (fallback to the raw tid, mirroring the :open replay) since id-map is empty
       ;; before store-open. :reached ⇒ compare the running MAC@N to the sealed M_N (== intact/may-extend
       ;; = CLEAN; != = :diverged rollback); :clean (ended below N on a boundary) ⇒ :truncated (whole-tail
       ;; truncation / whole-topic drop [absent log] / whole-store rollback); :torn (honest crash mid-append)
       ;; ⇒ tolerate; :corrupt (interior tamper) ⇒ defer to store-open's fail-loud replay. No oracle ⇒ T.
       (lambda (tid n mac)
         (dds.pal:with-lock (lock)
           (if (null chain-mac-fn)
               t
               (let ((topic (or (gethash tid (%read-topics-map store-dir)) tid)))
                 (multiple-value-bind (count running reason)
                     (%chain-walk (%topic-log-path store-dir tid) topic chain-mac-fn n)
                   (declare (ignore count))
                   (cond
                     ((eq reason :reached) (if (equalp running mac) t :diverged))
                     ((eq reason :clean)   :truncated)
                     (t                    t)))))))

       :delete
       ;; Sliver 3b (ADR 0025 §10.3 / ADR 0029 §10): per-record physical reclaim for the encrypted
       ;; decorator's superseded surrogate. The append-only log CANNOT delete-in-place, so: (1) IMMEDIATE
       ;; remhash from the in-memory index (store-count nil + get-range reflect the logical removal at once);
       ;; (2) add the surrogate key to the per-topic pending-delete set — its size is the O(1) reclaim
       ;; trigger (the inner :keep-all store's own KEEP_LAST supersede counter never bumps here — NIL
       ;; key-hash); (3) crossing *compaction-superseded-threshold* runs %reclaim-deleted-topic (the shared
       ;; atomic %rewrite-topic-log, replaying EXCLUDING the pending-delete keys, append-fd guard preserved).
       ;; A crash between the in-mem remhash and the batched rewrite reappears the surrogate on reopen but
       ;; get-range stays logically newest-D + the chain verifies (self-healing SPACE leak — the 3a
       ;; lower-bar). A bare (non-encrypted) file store has the slot but no decorator/chain-oracle driving
       ;; it, so its Sliver-2 KEEP_LAST path is unchanged. remhash returns T iff the key was live, so an
       ;; absent/double delete is a no-op (never inflates pending-delete).
       (lambda (topic writer-guid sn)
         (dds.pal:with-lock (lock)
           (let* ((tid (gethash topic id-map))
                  (inn (and tid (gethash tid outer))))
             (when inn
               (let ((k (%record-key writer-guid sn)))
                 (when (remhash k inn)
                   (let ((pd (or (gethash tid pending-delete)
                                 (setf (gethash tid pending-delete)
                                       (make-hash-table :test #'equal)))))
                     (setf (gethash k pd) t)
                     (when (>= (hash-table-count pd) *compaction-superseded-threshold*)
                       (%reclaim-deleted-topic tid topic)))))))
           t))

       :replace-topic-fn
       ;; atomic whole-topic REPLACE (ADR 0050 §4.4): the microservice server calls this after a KEEP_LAST
       ;; reclaim re-MACs the survivors client-side, so a persistent file inner swaps the topic's frames
       ;; CRASH-ATOMICALLY (a partial topic would brick the re-MAC'd chain). Reuses the SAME primitives as
       ;; %compact-topic-log (DRY): release the append fd BEFORE the rewrite (a stale fd appending to the
       ;; renamed-away log = DATA LOSS), the atomic %rewrite-topic-log (tmp+fsync+rename — the
       ;; *durability-debug-file-rewrite-fault* seam gives crash-before-commit rollback), rebuild the
       ;; in-memory index, reseed the Sliver-2 counters, carry the fresh tail chain MAC. A bare inner
       ;; (chain-mac-fn NIL — the DARE-blind server's) writes byte-identical v2 frames; the folded
       ;; mac/chain_seq ride as OPAQUE payload bytes the server never parses.
       (lambda (topic records)
         (dds.pal:with-lock (lock)
           (let* ((tid (or (gethash topic id-map)
                           (setf (gethash topic id-map) (%topic->id topic))))
                  (stm (gethash tid streams)))
             (when stm
               (ignore-errors (dds.pal:fsync-stream stm))
               (ignore-errors (close stm))
               (remhash tid streams))
             (let ((tail (%rewrite-topic-log store-dir tid records chain-mac-fn topic)))
               (if tail
                   (setf (gethash tid chain-macs) tail)
                   (remhash tid chain-macs))
               (let ((inn (%inner tid)))
                 (clrhash inn)
                 (dolist (r records)
                   (setf (gethash (%record-key (durable-record-writer-guid r)
                                               (durable-record-sn r)) inn) r)))
               (%init-topic-counts tid records)))
           t))))))

(defun* file-store-sync (store)
    (function (durable-store) (eql t))
  "Group-commit sync: call the store's :sync vtable slot if present, else no-op.
   Intended for the collect-loop drain tick (group-commit fsync per tick, not per put)."
  (let ((fn (durable-store-sync store)))
    (when fn (funcall fn)))
  t)
