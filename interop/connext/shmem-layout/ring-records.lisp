;;;; ADR 0081 slice 7c — application-level delivery of a USER-DATA sample over an RTI Connext SHMEM ring.
;;;;
;;;; Slice 7b proved RING-level acceptance: a record this stack wrote into a live RTI Connext shared-memory
;;;; ring was drained by RTI's own consumer. What it did not show is RTI's APPLICATION-level delivery — the
;;;; subscriber's `issue received` counter did not move. This program closes that: it re-issues a real
;;;; user-data sample with the NEXT sequence number, which is the one thing a verbatim replay can never be.
;;;;
;;;; WHY THE SEQUENCE NUMBER IS THE WHOLE POINT. Every record still lying in the ring has already been
;;;; delivered to the reader, so its writerSN is at or below the reader's high-water mark and RTPS duplicate
;;;; suppression drops it before the application ever sees it (RTPS 2.5 §8.4.13.2 best-effort: accept only
;;;; SN > max received; §8.4.12 reliable: already-received changes are not re-delivered). Re-issuing the same
;;;; bytes at max+1 makes the record indistinguishable from the writer's next sample.
;;;;
;;;; Three modes, selected by the RTI_MODE environment variable:
;;;;   analyze  — parse a captured record from a hex file (RTI_HEX). NO IPC AT ALL: the parse/patch logic is
;;;;              exercised off-line, against a real captured record, before it is ever pointed at a live ring.
;;;;   replay   — write a captured record (RTI_HEX) VERBATIM into the ring at RTI_PORT. This is slice 7b's
;;;;              acceptance test: it answers whether RTI's consumer drains what we wrote, and nothing above.
;;;;   inject   — scan the live ring of the receiver at RTI_PORT, pick the newest user-data record, re-issue it
;;;;              at the next sequence number, and report both ring-level and application-level acceptance.
;;;;
;;;; Everything except the single final write is read-only. Run it ONLY against a throwaway participant.

(asdf:load-system :dds-xport)
(asdf:load-system :dds-rtps)   ; the RTPS parser this harness reads records with

(defpackage #:rti-userdata-inject
  (:use #:common-lisp #:net.goenninger.dds.lang)
  (:documentation
   "Harness for ADR 0081 slice 7c. Not part of the shipped stack: it lives in interop/ because it drives a
    live RTI Connext peer. It uses this stack's own RTPS parser (DDS.RTPS.MESSAGE) to read the record, so
    the submessage layout it reports is the spec-pinned one, never a second hand-rolled decoder."))

(in-package #:rti-userdata-inject)

;;; ---- constants ----------------------------------------------------------------------------------

(defconstant +entity-kind-class-mask+ #xC0
  "Mask selecting the two most significant bits of an EntityId_t's entityKind octet, which encode the
   entity's class (RTPS 2.5 §9.3.1.2). Read against the whole 4-octet entityId, whose LOW octet is
   entityKind (entityKey[3] then entityKind, MSB-first).")

(defconstant +entity-kind-class-user-defined+ #x00
  "The entityKind class value for a USER-DEFINED entity (RTPS 2.5 §9.3.1.2); builtin is 0xC0 and
   vendor-specific 0x40. A DATA whose writerId is user-defined carries an application sample, which is
   what the subscriber's `issue received` counter counts.")

(defconstant +data-sn-offset-in-body+ 12
  "Octets from the start of a DATA submessage BODY to its writerSN (RTPS 2.5 §9.4.5.4): extraFlags(2) +
   octetsToInlineQos(2) + readerId(4) + writerId(4). Every field ahead of writerSN is fixed-width, so this
   offset does not depend on any wire value — octetsToInlineQos is read anyway and reported, as a check.")

(defconstant +heartbeat-last-sn-offset-in-body+ 16
  "Octets from the start of a HEARTBEAT submessage BODY to its lastSN (RTPS 2.5 §9.4.5.7): readerId(4) +
   writerId(4) + firstSN(8).")

(defconstant +data-octets-to-inline-qos-standard+ 16
  "The value RTPS 2.5 §9.4.5.4 gives octetsToInlineQos for the standard DATA layout: readerId(4) +
   writerId(4) + writerSN(8) follow it. Reported, not required — a vendor may insert fields after the
   inlineQos anchor without moving writerSN.")

(defconstant +block-a-offset+ #x78
  "Byte offset of ring control block A (the head). Measured, ADR 0081 §5.0 — not a published constant.")

(defconstant +block-b-offset+ #xb0
  "Byte offset of ring control block B (the tail). Measured, ADR 0081 §5.0.")

(defparameter *record-window* 2048
  "Octets copied out of the ring per RTPS-magic hit before parsing. Generous for the record sizes this
   harness targets (an rtiddsping sample is ~64 octets); a longer record is reported as truncated rather
   than silently half-parsed.")

;;; ---- record parsing (this stack's own RTPS parser, never a second decoder) -----------------------

(defun* user-defined-writer-p (writer-id)
    (function ((unsigned-byte 32)) t)
  "T iff WRITER-ID is a USER-DEFINED EntityId_t (RTPS 2.5 §9.3.1.2) — i.e. an application endpoint rather
   than a builtin (0xC0) or vendor-specific (0x40) one."
  (= (logand writer-id +entity-kind-class-mask+) +entity-kind-class-user-defined+))

(defun* %data-fields (buf body flags octets)
    (function (dds.core.buffer:octet-buffer (integer 0) (unsigned-byte 8) (unsigned-byte 16)) list)
  "Parse the DATA submessage body at BODY in BUF and return its fields as a plist. The cursor endianness
   follows the submessage E flag (RTPS 2.5 §9.4.5.1.2), not the reader's preference."
  (let ((c (dds.core.buffer:cursor buf :endianness (if (logbitp 0 flags) :little :big))))
    (dds.core.buffer:cursor-set-position c (+ body 2))
    (let ((oti (dds.core.buffer:get-u16 c)))
      (dds.core.buffer:cursor-set-position c body)
      (multiple-value-bind (reader writer sn has-payload poff plen)
          (dds.rtps.message:parse-data-body c flags octets)
        (when (null reader) (return-from %data-fields (list :parsed nil)))
        (list :parsed t :reader reader :writer writer :sn sn
              :payload-p (and has-payload t) :payload-off poff :payload-len plen
              :octets-to-inline-qos oti :little-endian (logbitp 0 flags)
              :sn-offset (+ body +data-sn-offset-in-body+))))))

(defun* record-report (vec limit)
    (function ((simple-array (unsigned-byte 8) (*)) (integer 0)) list)
  "Walk the RTPS datagram at the start of VEC, reading at most LIMIT octets, and return a plist:
   :OK T with :LEN (the datagram's exact length, from the submessage chain), :SUBS (one plist per
   submessage) and :DATA / :HEARTBEAT (the first of each, as plists); or :OK NIL with :WHY.

   The length comes from the chain of octetsToNextHeader fields (RTPS 2.5 §9.4.5.1), which is what makes an
   RTPS datagram self-delimiting — the ring stores records verbatim, so this is the record's exact length.
   A zero octetsToNextHeader means 'to the end of the message' and leaves the length undetermined here, so
   it is refused rather than guessed."
  (let* ((buf (dds.core.buffer:octet-buffer-over vec))
         (c (dds.core.buffer:cursor buf :endianness :little))
         (subs '()) (data nil) (heartbeat nil) (end 20))
    (unless (dds.rtps.message:parse-header c)
      (return-from record-report (list :ok nil :why :not-rtps)))
    (loop
      (let ((at (dds.core.buffer:cursor-position c)))
        ;; Fewer than a header-plus-a-word left: this is the 8-byte-alignment PADDING between records
        ;; (ADR 0081 §5.0 — the cursor advances by align8(length), so up to 7 octets of the previous ring
        ;; content follow a record). Walking into it would read stale bytes as a submessage header and run
        ;; the length past the record's true end.
        (when (< (- limit at) 8) (return))
        (multiple-value-bind (id flags octets) (dds.rtps.message:parse-submessage-header c)
          (unless id (return))
          (let* ((body (dds.core.buffer:cursor-position c))
                 (next (+ body octets)))
            (push (list :id id :flags flags :octets octets :at at) subs)
            (when (or (zerop octets) (> next limit))
              (return-from record-report
                (list :ok nil :why (if (zerop octets) :open-ended-submessage :truncated)
                      :subs (nreverse subs))))
            (when (and (= id dds.rtps.message:+submsg-data+) (null data))
              (setf data (%data-fields buf body flags octets)))
            (when (and (= id dds.rtps.message:+submsg-heartbeat+) (null heartbeat))
              (setf heartbeat (list :body body :little-endian (logbitp 0 flags)
                                    :last-sn-offset (+ body +heartbeat-last-sn-offset-in-body+))))
            (setf end next)
            (dds.core.buffer:cursor-set-position c next)
            (when (>= next limit) (return))))))
    (list :ok t :len end :subs (nreverse subs) :data data :heartbeat heartbeat)))

(defun* patch-sequence-number (vec offset little-endian sn)
    (function ((simple-array (unsigned-byte 8) (*)) (integer 0) t integer) t)
  "Overwrite the 8-octet SequenceNumber_t at OFFSET in VEC with SN, in the submessage's byte order
   (RTPS 2.5 §9.3.2.10: high as a signed 32-bit, then low as unsigned). Uses this stack's own writer so the
   layout cannot drift from the one the parser reads."
  (let ((c (dds.core.buffer:cursor (dds.core.buffer:octet-buffer-over vec)
                                   :endianness (if little-endian :little :big))))
    (dds.core.buffer:cursor-set-position c offset)
    (dds.rtps.message:write-sequence-number c sn)))

;;; ---- reporting ----------------------------------------------------------------------------------

(defun* submessage-name (id)
    (function ((unsigned-byte 8)) string)
  "A readable name for SubmessageKind ID (RTPS 2.5 §9.4.5.1.1), or its hex value when this stack has no
   constant for it — an unrecognised submessage in a record we are about to re-issue must be VISIBLE."
  (cond ((= id dds.rtps.message:+submsg-pad+) "PAD")
        ((= id dds.rtps.message:+submsg-acknack+) "ACKNACK")
        ((= id dds.rtps.message:+submsg-heartbeat+) "HEARTBEAT")
        ((= id dds.rtps.message:+submsg-gap+) "GAP")
        ((= id dds.rtps.message:+submsg-info-ts+) "INFO_TS")
        ((= id dds.rtps.message:+submsg-info-src+) "INFO_SRC")
        ((= id dds.rtps.message:+submsg-info-reply-ip4+) "INFO_REPLY_IP4")
        ((= id dds.rtps.message:+submsg-info-dst+) "INFO_DST")
        ((= id dds.rtps.message:+submsg-info-reply+) "INFO_REPLY")
        ((= id dds.rtps.message:+submsg-nack-frag+) "NACK_FRAG")
        ((= id dds.rtps.message:+submsg-heartbeat-frag+) "HEARTBEAT_FRAG")
        ((= id dds.rtps.message:+submsg-data+) "DATA")
        ((= id dds.rtps.message:+submsg-data-frag+) "DATA_FRAG")
        (t (format nil "UNKNOWN(0x~2,'0x)" id))))

(defun* print-report (label report)
    (function (string list) t)
  "Print a record REPORT (RECORD-REPORT's plist) under LABEL, one line per submessage plus the DATA fields."
  (format t "~&<<RT>> ~a: ok=~a~@[ why=~a~] len=~a~%" label (getf report :ok) (getf report :why)
          (getf report :len))
  (dolist (s (getf report :subs))
    (format t "<<RT>>   @~3d ~14a flags=0x~2,'0x octetsToNextHeader=~d~%"
            (getf s :at) (submessage-name (getf s :id)) (getf s :flags) (getf s :octets)))
  (let ((d (getf report :data)))
    (when d
      (if (getf d :parsed)
          (format t "<<RT>>   DATA readerId=0x~8,'0x writerId=0x~8,'0x (~a) SN=~d payload=~d octets~
                     ~%<<RT>>        octetsToInlineQos=~d~a snOffset=~d~%"
                  (getf d :reader) (getf d :writer)
                  (if (user-defined-writer-p (getf d :writer)) "USER-DEFINED" "builtin/vendor")
                  (getf d :sn) (getf d :payload-len)
                  (getf d :octets-to-inline-qos)
                  (if (= (getf d :octets-to-inline-qos) +data-octets-to-inline-qos-standard+)
                      " (standard)" " (NON-STANDARD)")
                  (getf d :sn-offset))
          (format t "<<RT>>   DATA present but did not parse~%")))))

;;; ---- mode: analyze (no IPC) ---------------------------------------------------------------------

(defun* hex-file-record (path)
    (function (string) (simple-array (unsigned-byte 8) (*)))
  "Read PATH — one line of space-separated hex octets, as `shmprobe dump` produces — into an octet vector."
  (let* ((line (with-open-file (f path) (read-line f)))
         (toks (remove "" (uiop:split-string line :separator " ") :test #'string=)))
    (make-array (length toks) :element-type '(unsigned-byte 8)
                              :initial-contents (mapcar (lambda (h) (parse-integer h :radix 16)) toks))))

(defun* analyze (path)
    (function (string) t)
  "Parse the captured record in PATH and print what it is — including whether its DATA is a user sample and
   what sequence number a re-issue would have to carry. Touches no shared memory."
  (let* ((vec (hex-file-record path))
         (report (record-report vec (length vec))))
    (format t "~&<<RT>> analyze ~a (~d octets on file)~%" path (length vec))
    (print-report "record" report)
    (let ((d (getf report :data)))
      (cond ((null d) (format t "<<RT>> VERDICT: no DATA submessage — not a sample record.~%"))
            ((not (getf d :parsed)) (format t "<<RT>> VERDICT: DATA did not parse.~%"))
            ((not (user-defined-writer-p (getf d :writer)))
             (format t "<<RT>> VERDICT: DATA is from a BUILTIN writer — carries no application sample.~%"))
            (t (format t "<<RT>> VERDICT: USER-DATA sample, writer 0x~8,'0x, SN ~d. A verbatim replay is a~
                          ~%<<RT>>          DUPLICATE and is dropped before the application; re-issue at SN ~d.~%"
                       (getf d :writer) (getf d :sn) (1+ (getf d :sn))))))))

;;; ---- mode: selftest (no IPC) --------------------------------------------------------------------

(defparameter *selftest-sn* 4242
  "The sequence number SELFTEST patches in. Far from any value a captured record carries, so reading it
   back cannot be a coincidence.")

(defun* %check (label got want)
    (function (string t t) t)
  "Report one assertion and return T iff it held."
  (let ((ok (equal got want)))
    (format t "<<RT>>   ~:[FAIL~;pass~] ~a~:[ — got ~s, wanted ~s~;~]~%" ok label ok got want)
    ok))

(defun* %sn-of (vec)
    (function ((simple-array (unsigned-byte 8) (*))) t)
  "The first DATA submessage's sequence number in VEC, or NIL if it does not parse."
  (let ((d (getf (record-report vec (length vec)) :data)))
    (and d (getf d :parsed) (getf d :sn))))

(defun* selftest (path)
    (function (string) t)
  "Exercise the parse and patch paths against the real captured record in PATH, INCLUDING the ways they
   could be wrong. Patching the sequence number is the one step whose failure would be invisible in a live
   run — a wrong offset or byte order produces a well-formed record that RTI silently drops — so it is
   checked both by round-trip AND by confirming that a deliberately wrong offset and a deliberately wrong
   byte order do NOT read back. No IPC: this runs anywhere, with no Connext present."
  (let* ((vec (hex-file-record path))
         (report (record-report vec (length vec)))
         (d (getf report :data))
         (results '()))
    (format t "~&<<RT>> selftest against ~a~%" path)
    (push (%check "record parses" (getf report :ok) t) results)
    (push (%check "length from the submessage chain" (getf report :len) (length vec)) results)
    (push (%check "DATA parsed" (and d (getf d :parsed)) t) results)
    (when (and d (getf d :parsed))
      (push (%check "writer is user-defined" (user-defined-writer-p (getf d :writer)) t) results)
      ;; round trip: the patch must be readable back by the parser, at the offset the parser reports.
      (let ((v (copy-seq vec)))
        (patch-sequence-number v (getf d :sn-offset) (getf d :little-endian) *selftest-sn*)
        (push (%check "patched SN reads back" (%sn-of v) *selftest-sn*) results)
        (push (%check "patch left the writerId alone" (getf (getf (record-report v (length v)) :data) :writer)
                      (getf d :writer))
              results)
        (push (%check "patch left the length alone" (getf (record-report v (length v)) :len)
                      (getf report :len))
              results))
      ;; falsification 1: one octet off. If this still read back, the check above would prove nothing.
      (let ((v (copy-seq vec)))
        (patch-sequence-number v (1+ (getf d :sn-offset)) (getf d :little-endian) *selftest-sn*)
        (push (%check "a one-octet-off patch does NOT read back"
                      (eql (%sn-of v) *selftest-sn*) nil)
              results))
      ;; falsification 2: wrong byte order. The record's E flag is little-endian; writing big-endian must
      ;; produce a different value, or the harness is not honouring RTPS 2.5 §9.4.5.1.2 at all.
      (let ((v (copy-seq vec)))
        (patch-sequence-number v (getf d :sn-offset) nil *selftest-sn*)
        (push (%check "a wrong-byte-order patch does NOT read back"
                      (eql (%sn-of v) *selftest-sn*) nil)
              results))
      ;; classification: flip the writerId's entityKind to builtin (0xC2) and the record must stop counting
      ;; as an application sample. entityId is entityKey[3]+entityKind MSB-first, so the kind is the octet
      ;; immediately before writerSN (RTPS 2.5 §9.3.1.2).
      (let ((v (copy-seq vec)))
        (setf (aref v (1- (getf d :sn-offset))) #xC2)
        (push (%check "a builtin writerId is not classified as user data"
                      (user-defined-writer-p (getf (getf (record-report v (length v)) :data) :writer))
                      nil)
              results)))
    ;; A record in the ring is followed by up to 7 octets of 8-byte-alignment padding — stale ring content,
    ;; not a submessage. Parsing a window that includes it must still report the RECORD's length; walking
    ;; into it would produce a length that runs past the record and a re-issue that carries garbage.
    (let ((v (make-array (+ (length vec) 4) :element-type '(unsigned-byte 8) :initial-element #xAB)))
      (replace v vec)
      (push (%check "trailing alignment padding does not extend the length"
                    (getf (record-report v (length v)) :len) (length vec))
            results))
    ;; a truncated record must be refused, not half-parsed into a length someone then writes.
    (push (%check "a truncated record is refused"
                  (getf (record-report (subseq vec 0 30) 30) :ok) nil)
          results)
    (push (%check "a non-RTPS buffer is refused"
                  (getf (record-report (make-array 64 :element-type '(unsigned-byte 8)) 64) :why)
                  :not-rtps)
          results)
    (let ((failed (count nil results)))
      (format t "<<RT>> selftest: ~d checks, ~d failed~%" (length results) failed)
      (zerop failed))))

;;; ---- mode: inject (live ring) -------------------------------------------------------------------

(defun* %rtps-magic-at-p (sap offset)
    (function (t (integer 0)) t)
  "T iff the four octets at SAP+OFFSET are 'R','T','P','S' — the prefix of every RTPS message
   (RTPS 2.5 §8.3.3.1.1), and how a record start is recognised in the ring."
  (and (= (dds.pal:load-sap-u8 sap offset) (char-code #\R))
       (= (dds.pal:load-sap-u8 sap (+ offset 1)) (char-code #\T))
       (= (dds.pal:load-sap-u8 sap (+ offset 2)) (char-code #\P))
       (= (dds.pal:load-sap-u8 sap (+ offset 3)) (char-code #\S))))

(defun* ring-records (port)
    (function ((unsigned-byte 16)) (values list (or null keyword)))
  "Every RTPS record currently lying in the ring of the receiver serving RTPS PORT, as a list of
   (offset . plist) ordered by ADDRESS — the ring is a wrapping buffer, so address order is not age order.
   Read-only: attaches with SHM_RDONLY and takes no lock (an observer, exactly like RTI-SHMEM-READ-RECORD;
   the caller freezes the producer first so the ring is static). Records are 8-octet aligned (ADR 0081
   §5.0), so only aligned offsets are probed.

   EACH LENGTH IS ESTABLISHED TWICE, and a record whose two answers disagree is reported and not used. The
   first answer is the SPACING: records are packed contiguously, so the distance to the next record's magic
   is `align8(length)`. The second is the submessage chain (RTPS 2.5 §9.4.5.1). They agree exactly when the
   chain ends within the last 8 octets of the stride — the alignment padding — and a record we are about to
   re-issue is one whose extent we are not entitled to guess."
  (multiple-value-bind (props pstatus) (dds.xport.rti-shmem:rti-shmem-segment-properties port)
    (when pstatus (return-from ring-records (values nil pstatus)))
    (let* ((size (dds.xport.rti-shmem:rti-shmem-properties-segment-size props))
           (start (dds.xport.rti-shmem:rti-shmem-ring-start
                   (dds.xport.rti-shmem:rti-shmem-properties-received-message-count-max props)))
           (end (min size (+ start (dds.xport.rti-shmem:rti-shmem-ring-modulus props))))
           (offsets '()) (found '()))
      (multiple-value-bind (seg astatus)
          (dds.pal:sysv-shm-attach-readonly (dds.xport.rti-shmem:rti-shmem-segment-key port) size)
        (when astatus (return-from ring-records (values nil astatus)))
        (let ((sap (dds.pal:sysv-shm-sap seg)))
          (loop for off from start below (- end 4) by 8
                do (when (%rtps-magic-at-p sap off) (push off offsets)))
          (setf offsets (nreverse offsets))
          (loop for (off . rest) on offsets
                for stride = (min *record-window* (- (or (first rest) end) off))
                do (let ((vec (make-array stride :element-type '(unsigned-byte 8))))
                     (dotimes (i stride) (setf (aref vec i) (dds.pal:load-sap-u8 sap (+ off i))))
                     (let* ((report (record-report vec stride))
                            (len (getf report :len)))
                       (push (cons off (list :vec vec :report report :stride stride
                                             :corroborated (and (getf report :ok)
                                                                (<= len stride)
                                                                (< (- stride len) 8))))
                             found)))))
        (dds.pal:sysv-shm-detach seg))
      (values (nreverse found) nil))))

(defun* control-block (port offset)
    (function ((unsigned-byte 16) (integer 0)) list)
  "The eight u32s of the ring control block at OFFSET (ADR 0081 §5.0), read read-only. Block A's index 0 is
   the producer head and index 1 the consumer position; the consumer fields advancing across a write is the
   RING-level acceptance signal."
  (multiple-value-bind (seg astatus)
      (dds.pal:sysv-shm-attach-readonly (dds.xport.rti-shmem:rti-shmem-segment-key port) 512)
    (if astatus
        (list :error astatus)
        (let ((sap (dds.pal:sysv-shm-sap seg)))
          (prog1 (loop for i below 8 collect (dds.pal:load-sap-u32 sap (+ offset (* 4 i))))
            (dds.pal:sysv-shm-detach seg))))))

(defun* data-semaphore-value (port)
    (function ((unsigned-byte 16)) t)
  "The current value of the receiver's data-available semaphore (ADR 0081 §5.0: a wakeup latch, not a
   counter), or :ABSENT. Read-only (GETVAL)."
  (multiple-value-bind (s status)
      (dds.pal:sysv-sem-open (+ dds.xport.rti-shmem:+rti-shmem-semaphore-key-base+ port))
    (if status :absent (dds.pal:sysv-sem-getval s 0))))

(defun* write-and-report (port vec len)
    (function ((unsigned-byte 16) (simple-array (unsigned-byte 8) (*)) (integer 0)) t)
  "Write LEN octets of VEC into PORT's ring and print the ring state either side of it — the RING-level
   acceptance signal. Block A index 0 is the producer head (ours, so it always moves); index 1 and index 5
   are the CONSUMER's position and counter, and those advancing is RTI accepting the record. The data
   semaphore is read at three points because it separates two different failures: `1 then 1` means the
   consumer never woke, `1 then 0` means it woke and declined (ADR 0081 §5.0)."
  (format t "<<RT>> BEFORE A@0x78 = ~s~%" (control-block port +block-a-offset+))
  (format t "<<RT>>        B@0xb0 = ~s   data-sem = ~s~%"
          (control-block port +block-b-offset+) (data-semaphore-value port))
  (multiple-value-bind (ok status) (dds.xport.rti-shmem:rti-shmem-write-record port vec len)
    (format t "<<RT>> WRITE ok=~s status=~s (~d octets)   data-sem just after = ~s~%"
            ok status len (data-semaphore-value port))
    (sleep 0.6)
    (format t "<<RT>> AFTER  A@0x78 = ~s~%" (control-block port +block-a-offset+))
    (format t "<<RT>>        B@0xb0 = ~s   data-sem = ~s~%"
            (control-block port +block-b-offset+) (data-semaphore-value port))
    (format t "<<RT>> RING-level acceptance iff a consumer field (A index 1 / index 5) advanced.~%")
    (and ok (null status))))

(defun* newest-user-data (records)
    (function (list) list)
  "Of RECORDS (RING-RECORDS' output), the entry whose DATA is a user-defined-writer sample with the HIGHEST
   sequence number, or NIL. Highest-SN is the right choice for two reasons: with the producer frozen it is
   the last sample the writer sent, so SN+1 is exactly the reader's next expected sequence number; and it is
   independent of where in the wrapping ring the record happens to sit."
  (let ((best nil))
    (dolist (entry records best)
      (let* ((report (getf (cdr entry) :report))
             (d (getf report :data)))
        (when (and (getf report :ok) (getf (cdr entry) :corroborated)
                   d (getf d :parsed) (getf d :payload-p)
                   (user-defined-writer-p (getf d :writer))
                   (or (null best)
                       (> (getf d :sn) (getf (getf (getf (cdr best) :report) :data) :sn))))
          (setf best entry))))))

(defun* inject (port &key (bump 1))
    (function ((unsigned-byte 16) &key (:bump (integer 1))) t)
  "Re-issue the newest user-data record in PORT's ring at sequence number SN+BUMP, and report both
   acceptance signals: the ring-level one (the consumer's own position/counter advancing) and — read by the
   caller from the subscriber's log — the application-level one.

   Refuses rather than guesses: no user-data record found, a record whose length the submessage chain does
   not determine, or a write the transport declines all report and stop. Nothing is written until a record
   has been parsed, classified as a user sample, and had its exact length established."
  (multiple-value-bind (records status) (ring-records port)
    (when status
      (format t "~&<<RT>> ring read failed: ~a~%" status)
      (return-from inject nil))
    (format t "~&<<RT>> ring at port ~d holds ~d RTPS record(s)~%" port (length records))
    (dolist (entry records)
      (let* ((report (getf (cdr entry) :report))
             (d (getf report :data)))
        (format t "<<RT>>   offset ~6d  len=~a/stride ~d ~:[UNCORROBORATED~;ok~]  ~{~a~^+~}~
                   ~@[  writer=0x~8,'0x~]~@[ SN=~d~]~%"
                (car entry) (getf report :len) (getf (cdr entry) :stride)
                (getf (cdr entry) :corroborated)
                (mapcar (lambda (s) (submessage-name (getf s :id))) (getf report :subs))
                (and d (getf d :parsed) (getf d :writer))
                (and d (getf d :parsed) (getf d :sn)))))
    (let ((chosen (newest-user-data records)))
      (unless chosen
        (format t "<<RT>> NO user-data record in the ring — nothing re-issued (the ring may hold only~
                   ~%<<RT>> builtin traffic; let the publisher run a little longer and retry).~%")
        (return-from inject nil))
      (let* ((report (getf (cdr chosen) :report))
             (d (getf report :data))
             (len (getf report :len))
             (vec (getf (cdr chosen) :vec))
             (new-sn (+ (getf d :sn) bump)))
        (print-report "chosen record" report)
        (patch-sequence-number vec (getf d :sn-offset) (getf d :little-endian) new-sn)
        (let ((hb (getf report :heartbeat)))
          (when hb
            (patch-sequence-number vec (getf hb :last-sn-offset) (getf hb :little-endian) new-sn)
            (format t "<<RT>> record also carries a HEARTBEAT: its lastSN was advanced to ~d too, so the~
                       ~%<<RT>> announced range does not contradict the sample.~%" new-sn)))
        (format t "<<RT>> re-issuing writer 0x~8,'0x  SN ~d -> ~d  (~d octets)~%"
                (getf d :writer) (getf d :sn) new-sn len)
        (write-and-report port vec len)))))

(defun* replay (port path)
    (function ((unsigned-byte 16) string) t)
  "Write the captured record in PATH into PORT's ring VERBATIM — slice 7b's acceptance test. It answers one
   question only: does RTI's consumer drain a record this stack wrote? It cannot show application delivery,
   because a captured record's sequence number has already been delivered and RTPS drops the duplicate
   (that is what INJECT exists for)."
  (let* ((vec (hex-file-record path))
         (report (record-report vec (length vec))))
    (print-report "replay record" report)
    (unless (getf report :ok)
      (format t "<<RT>> refusing to write a record whose length the submessage chain does not determine~%")
      (return-from replay nil))
    (write-and-report port vec (getf report :len))))

;;; ---- entry point --------------------------------------------------------------------------------

(let ((mode (or (uiop:getenv "RTI_MODE") "analyze"))
      (hex (or (uiop:getenv "RTI_HEX") "/tmp/rt-record.hex"))
      (port (parse-integer (or (uiop:getenv "RTI_PORT") "0"))))
  (cond ((string= mode "analyze") (analyze hex))
        ((string= mode "selftest") (selftest hex))
        ((string= mode "replay") (replay port hex))
        ((string= mode "inject") (inject port))
        (t (format t "~&<<RT>> unknown RTI_MODE ~a (expected analyze | selftest | replay | inject)~%"
                   mode))))
(finish-output)
