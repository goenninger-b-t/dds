(in-package #:dds.security)

;;; DDS-Security 1.1 §9.3.4 DataHolder + §7.4.4 ParticipantGenericMessage wire codec (CDR-LE).
;;; Serializes the internal handshake-token struct into CDR-LE DataHolder bytes and wraps them
;;; in a ParticipantStatelessMessage (PSM) envelope for the PSM DATA submessage payload.
;;;
;;; DataHolder wire layout (CDR-LE, §9.3.4 / OMG dds_security_plugins_spis.idl):
;;;   class_id: u32-LE(strlen+1) | ascii | NUL | pad4
;;;   PropertySeq: u32-LE(count=0)      -- always present; count=0 for HandshakeMessageToken
;;;   BinaryPropertySeq: u32-LE(count) | BinaryProperty*
;;;     BinaryProperty: name(CDR-LE string) | value(u32-LE(len) | bytes) | propagate(1B) | 3pad
;;;
;;; ENDIANNESS NOTE: this file is CDR-LE (PSM wire). handshake.lisp BE helpers are for
;;;   hash_c1/hash_c2/Sign inputs only. Two distinct serializations; never mixed.
;;;
;;; PropertySeq @optional (XCDR1): emits count=0 (empty sequence), NOT an absent flag.
;;;   Source: T0 spike §10.5 — Fast DDS emits count=0; confirmed HIGH confidence.
;;;
;;; Bounds caps: seq-count <= 65536; string len <= 65536; value len <= 0x1000000 (mirror %parse-token).
;;; Every parse-path length is bounds-checked before allocating/reading (NFR-SEC-POSTURE, fail-closed).

;;; --- CDR-LE serialization helpers (DataHolder-local; reuses %cdr-string-le / %cdr-u32-le
;;;     from identity.lisp which loads first in the same package) ---

(defun* %cdr-binary-property-le (name value-octets)
    (function (string (simple-array (unsigned-byte 8) (*))) (simple-array (unsigned-byte 8) (*)))
  "Encode one CDR-LE BinaryProperty: name(CDR-LE string) + value(u32-LE len + bytes) + propagate(1)+3pad.
   Layout per OMG dds_security_plugins_spis.idl BinaryProperty, CDR-LE (§9.3.4 / §7.4.4)."
  (let* ((n   (length value-octets))
         (hdr (%cdr-u32-le n))
         (pad (make-array 4 :element-type '(unsigned-byte 8) :initial-contents '(1 0 0 0))))
    (%concat-octets (%cdr-string-le name) hdr value-octets pad)))

(defun* %build-dataholder-le (class-id binary-props)
    (function (string list) (simple-array (unsigned-byte 8) (*)))
  "Build a CDR-LE DataHolder from CLASS-ID and BINARY-PROPS ((name . octets) alist) (§9.3.4).
   PropertySeq emits count=0 (all HST values are binary). BinaryPropertySeq carries all pairs.
   Both sequences always present — count=0 is the CDR encoding for an absent @optional in XCDR1."
  (let ((count (length binary-props)))
    (apply #'%concat-octets
           (%cdr-string-le class-id)
           (%cdr-u32-le +dataholder-empty-property-seq-count+)   ; PropertySeq count=0
           (%cdr-u32-le count)
           (mapcar (lambda (pair) (%cdr-binary-property-le (car pair) (cdr pair)))
                   binary-props))))

;;; --- CDR-LE parse primitives for the DataHolder / envelope parse path ---
;;; All return (values result new-pos) or signal a simple-error on any malformed input.
;;; The public API catches (error ...) via handler-bind so all failures are fail-closed.

(defmacro %dh-fail ()
  "Signal a simple-error (fail-closed parse abort); caught by handler-bind in public API."
  `(error "dataholder-parse-error"))

(defun* %dh-read-u32-le (octets pos n)
    (function ((simple-array (unsigned-byte 8) (*)) fixnum fixnum)
              (values (unsigned-byte 32) fixnum))
  "Read u32-LE at POS in OCTETS (length N); advance POS by 4. Signals dataholder-parse-error on truncation."
  (when (> (+ pos 4) n) (%dh-fail))
  (values (logior (aref octets pos)
                  (ash (aref octets (+ pos 1))  8)
                  (ash (aref octets (+ pos 2)) 16)
                  (ash (aref octets (+ pos 3)) 24))
          (+ pos 4)))

(defun* %dh-read-string-le (octets pos n)
    (function ((simple-array (unsigned-byte 8) (*)) fixnum fixnum)
              (values string fixnum))
  "Read a CDR-LE string at POS (u32-LE(len+1) | ascii | NUL | pad4). Returns (values string new-pos).
   Signals dataholder-parse-error on truncation or if len > 65536."
  (multiple-value-bind (len p2) (%dh-read-u32-le octets pos n)
    (when (> len 65536) (%dh-fail))
    (let* ((pad   (mod (- 4 (mod len 4)) 4))
           (total (+ len pad)))
      (when (> (+ p2 total) n) (%dh-fail))
      (let* ((str-len (max 0 (1- len)))
             (s       (make-string str-len)))
        (dotimes (i str-len)
          (setf (char s i) (code-char (aref octets (+ p2 i)))))
        (values s (+ p2 total))))))

(defun* %dh-read-octet-seq-le (octets pos n)
    (function ((simple-array (unsigned-byte 8) (*)) fixnum fixnum)
              (values (simple-array (unsigned-byte 8) (*)) fixnum))
  "Read a CDR-LE octet sequence (u32-LE(len) | bytes, no post-pad). Returns (values bytes new-pos).
   Signals dataholder-parse-error on truncation or if len > 0x1000000."
  (multiple-value-bind (len p2) (%dh-read-u32-le octets pos n)
    (when (> len #x1000000) (%dh-fail))
    (when (> (+ p2 len) n) (%dh-fail))
    (let ((v (make-array len :element-type '(unsigned-byte 8))))
      (dotimes (i len) (setf (aref v i) (aref octets (+ p2 i))))
      (values v (+ p2 len)))))

(defun* %dh-skip-string-le (octets pos n)
    (function ((simple-array (unsigned-byte 8) (*)) fixnum fixnum)
              fixnum)
  "Advance POS past a CDR-LE string. Signals dataholder-parse-error on truncation."
  (multiple-value-bind (_ p2) (%dh-read-string-le octets pos n)
    (declare (ignore _))
    p2))

(defun* %dh-skip-octet-seq-le (octets pos n)
    (function ((simple-array (unsigned-byte 8) (*)) fixnum fixnum)
              fixnum)
  "Advance POS past a CDR-LE octet sequence. Signals dataholder-parse-error on truncation."
  (multiple-value-bind (_ p2) (%dh-read-octet-seq-le octets pos n)
    (declare (ignore _))
    p2))

;;; --- DataHolder extent scanner: determines the byte-length of one DataHolder without fully
;;;     deserialising it. Used by parse-generic-message to slice DataHolder blobs from the envelope. ---

(defun* %dh-scan-extent (octets pos n)
    (function ((simple-array (unsigned-byte 8) (*)) fixnum fixnum)
              fixnum)
  "Return the new POS after consuming one complete CDR-LE DataHolder starting at POS.
   Signals dataholder-parse-error on any malformed/truncated structure."
  ;; class_id string
  (setf pos (%dh-skip-string-le octets pos n))
  ;; PropertySeq: u32-LE count + count*(name-str + value-str + 4B propagate)
  (multiple-value-bind (pc p2) (%dh-read-u32-le octets pos n)
    (when (> pc 65536) (%dh-fail))
    (setf pos p2)
    (dotimes (_ pc)
      (setf pos (%dh-skip-string-le octets pos n))  ; name
      (setf pos (%dh-skip-string-le octets pos n))  ; value
      (when (> (+ pos 4) n) (%dh-fail))
      (incf pos 4))
    ;; BinaryPropertySeq: u32-LE count + count*(name-str + octet-seq + 4B propagate)
    (multiple-value-bind (bc p3) (%dh-read-u32-le octets pos n)
      (when (> bc 65536) (%dh-fail))
      (setf pos p3)
      (dotimes (_ bc)
        (setf pos (%dh-skip-string-le  octets pos n))   ; name
        (setf pos (%dh-skip-octet-seq-le octets pos n)) ; value
        (when (> (+ pos 4) n) (%dh-fail))
        (incf pos 4))
      pos)))

;;; --- Public DataHolder codec ---

(defun* handshake-token->dataholder (token)
    (function (handshake-token) (simple-array (unsigned-byte 8) (*)))
  "Serialize TOKEN (internal handshake-token struct, §9.3.2) as CDR-LE DataHolder octets (§9.3.4).
   class_id -> DataHolder.class_id; binary-props -> DataHolder.binary_properties (in wire order).
   PropertySeq = empty (count=0). Signature bytes transferred verbatim; no crypto recomputation."
  (%build-dataholder-le (handshake-token-class-id token)
                         (handshake-token-binary-props token)))

(defun* dataholder->handshake-token (octets)
    (function ((simple-array (unsigned-byte 8) (*))) (or handshake-token null))
  "Parse CDR-LE DataHolder octets (§9.3.4) back to a handshake-token (§9.3.2). Fail-closed.
   Bounds-checks every length. Returns NIL on any malformed/truncated/over-declared input.
   Caps: seq count <= 65536; string len <= 65536; value len <= 0x1000000."
  (block %dh-parse-token
    (handler-bind
        ((error (lambda (c) (declare (ignore c)) (return-from %dh-parse-token nil))))
      (let ((n   (length octets))
            (pos 0))
        ;; class_id — all §9.3.2 HandshakeMessageToken class_ids are non-empty
        (multiple-value-bind (class-id p2) (%dh-read-string-le octets pos n)
          (when (zerop (length class-id)) (%dh-fail))
          (setf pos p2)
          ;; PropertySeq (skip entries — HST has count=0 but we tolerate non-zero for parsing)
          (multiple-value-bind (pc p3) (%dh-read-u32-le octets pos n)
            (when (> pc 65536) (%dh-fail))
            (setf pos p3)
            (dotimes (_ pc)
              (setf pos (%dh-skip-string-le octets pos n))   ; name
              (setf pos (%dh-skip-string-le octets pos n))   ; value
              (when (> (+ pos 4) n) (%dh-fail))
              (incf pos 4))                                   ; propagate
            ;; BinaryPropertySeq
            (multiple-value-bind (bc p4) (%dh-read-u32-le octets pos n)
              (when (> bc 65536) (%dh-fail))
              (setf pos p4)
              (let ((props nil))
                (dotimes (_ bc)
                  ;; name
                  (multiple-value-bind (name p5) (%dh-read-string-le octets pos n)
                    (setf pos p5)
                    ;; value (octet sequence)
                    (multiple-value-bind (val p6) (%dh-read-octet-seq-le octets pos n)
                      (setf pos p6)
                      ;; propagate (4 bytes)
                      (when (> (+ pos 4) n) (%dh-fail))
                      (incf pos 4)
                      (push (cons name val) props))))
                (%make-handshake-token :class-id class-id
                                       :binary-props (nreverse props))))))))))

;;; --- ParticipantGenericMessage / ParticipantStatelessMessage envelope codec (§7.4.4) ---
;;;
;;; Field order (Fast DDS CDRMessage::addParticipantGenericMessage + OMG §7.4.4 IDL):
;;;   message_identity        (MessageIdentity: GUID_t[16] + int64[8] = 24 octets)
;;;   related_message_identity (MessageIdentity, 24 octets)
;;;   destination_participant_key (GUID_t, 16 octets)
;;;   destination_endpoint_key    (GUID_t, 16 octets)
;;;   source_endpoint_key         (GUID_t, 16 octets)
;;;   message_class_id (CDR-LE string)
;;;   message_data (DataHolderSeq: u32-LE(count) + DataHolder*)
;;; No message_aux field (Fast DDS corroboration; T0 spike §10.1 — HIGH confidence).
;;; Field names in OMG §7.4.4 IDL: "key" fields = GUID_t; canonical names used above.

(defun* %pgm-write-guid (out pos guid)
    (function ((simple-array (unsigned-byte 8) (*)) fixnum (simple-array (unsigned-byte 8) (16))) fixnum)
  "Write 16 GUID bytes into OUT at POS (MSB-first raw copy, §7.4.4). Returns new pos."
  (dotimes (i 16) (setf (aref out (+ pos i)) (aref guid i)))
  (+ pos 16))

(defun* %pgm-write-sn64-le (out pos sn)
    (function ((simple-array (unsigned-byte 8) (*)) fixnum integer) fixnum)
  "Write SN as 8-byte LE int64 into OUT at POS (MessageIdentity.sequence_number §7.4.4). Returns new pos."
  (dotimes (i 8) (setf (aref out (+ pos i)) (ldb (byte 8 (* 8 i)) sn)))
  (+ pos 8))

(defun* make-generic-message (&key source-guid sequence-number related-guid related-sn
                                   dest-participant-guid dest-endpoint-guid
                                   source-endpoint-guid message-class-id dataholders)
    (function (&key (:source-guid (simple-array (unsigned-byte 8) (16)))
                    (:sequence-number integer)
                    (:related-guid (simple-array (unsigned-byte 8) (16)))
                    (:related-sn integer)
                    (:dest-participant-guid (simple-array (unsigned-byte 8) (16)))
                    (:dest-endpoint-guid (simple-array (unsigned-byte 8) (16)))
                    (:source-endpoint-guid (simple-array (unsigned-byte 8) (16)))
                    (:message-class-id string)
                    (:dataholders list))
              (simple-array (unsigned-byte 8) (*)))
  "Serialize a ParticipantGenericMessage / ParticipantStatelessMessage envelope as CDR-LE (§7.4.4).
   DATAHOLDERS: list of (simple-array (unsigned-byte 8) (*)) CDR-LE DataHolder blobs.
   Returns the raw CDR-LE octet vector for use as a PSM DATA submessage SerializedPayload body."
  (let* ((class-id-enc (%cdr-string-le message-class-id))
         (dh-count     (length dataholders))
         (dh-total     (reduce #'+ dataholders :key #'length :initial-value 0))
         ;; 24(msg-id)+24(rel-id)+16+16+16+len(class-id-enc)+4(dh-count)+dh-total
         (total        (+ 96 (length class-id-enc) 4 dh-total))
         (out          (make-array total :element-type '(unsigned-byte 8) :initial-element 0))
         (pos          0))
    ;; message_identity: source_guid(16) + sequence_number(8)
    (setf pos (%pgm-write-guid   out pos source-guid))
    (setf pos (%pgm-write-sn64-le out pos sequence-number))
    ;; related_message_identity: related_guid(16) + related_sn(8)
    (setf pos (%pgm-write-guid   out pos related-guid))
    (setf pos (%pgm-write-sn64-le out pos related-sn))
    ;; destination_participant_key(16), destination_endpoint_key(16), source_endpoint_key(16)
    (setf pos (%pgm-write-guid out pos dest-participant-guid))
    (setf pos (%pgm-write-guid out pos dest-endpoint-guid))
    (setf pos (%pgm-write-guid out pos source-endpoint-guid))
    ;; message_class_id (CDR-LE string)
    (replace out class-id-enc :start1 pos)
    (setf pos (+ pos (length class-id-enc)))
    ;; message_data: u32-LE(count) + DataHolder*
    (setf (aref out pos)       (ldb (byte 8  0) dh-count)
          (aref out (+ pos 1)) (ldb (byte 8  8) dh-count)
          (aref out (+ pos 2)) (ldb (byte 8 16) dh-count)
          (aref out (+ pos 3)) (ldb (byte 8 24) dh-count))
    (setf pos (+ pos 4))
    (dolist (dh dataholders)
      (replace out dh :start1 pos)
      (setf pos (+ pos (length dh))))
    out))

(defun* parse-generic-message (octets)
    (function ((simple-array (unsigned-byte 8) (*)))
              (values (or (simple-array (unsigned-byte 8) (16)) null)
                      integer
                      (or (simple-array (unsigned-byte 8) (16)) null)
                      integer
                      (or (simple-array (unsigned-byte 8) (16)) null)
                      (or (simple-array (unsigned-byte 8) (16)) null)
                      (or (simple-array (unsigned-byte 8) (16)) null)
                      (or string null)
                      list))
  "Parse a CDR-LE ParticipantGenericMessage / ParticipantStatelessMessage (§7.4.4).
   Returns (values source-guid sn related-guid related-sn dest-participant-guid dest-endpoint-guid
                   source-endpoint-guid message-class-id dataholder-octets-list) on success.
   Returns (values NIL 0 NIL 0 NIL NIL NIL NIL NIL) on any malformed/truncated/over-declared input.
   Caps: DataHolderSeq count <= 65536. Each DataHolder blob is sliced as raw CDR-LE octets."
  (block %pgm-parse
    (handler-bind
        ((error (lambda (c) (declare (ignore c))
                  (return-from %pgm-parse (values nil 0 nil 0 nil nil nil nil nil)))))
      (let ((n   (length octets))
            (pos 0))
        (flet ((read-guid ()
                 (when (> (+ pos 16) n) (%dh-fail))
                 (let ((g (make-array 16 :element-type '(unsigned-byte 8))))
                   (dotimes (i 16) (setf (aref g i) (aref octets (+ pos i))))
                   (setf pos (+ pos 16))
                   g))
               (read-sn64 ()
                 (when (> (+ pos 8) n) (%dh-fail))
                 (let ((v 0))
                   (dotimes (i 8)
                     (setf v (logior v (ash (aref octets (+ pos i)) (* 8 i)))))
                   (setf pos (+ pos 8))
                   v)))
          (let* ((src-guid  (read-guid))
                 (sn        (read-sn64))
                 (rel-guid  (read-guid))
                 (rel-sn    (read-sn64))
                 (dest-part (read-guid))
                 (dest-ep   (read-guid))
                 (src-ep    (read-guid)))
            ;; message_class_id (CDR-LE string)
            (multiple-value-bind (class-id p2) (%dh-read-string-le octets pos n)
              (setf pos p2)
              ;; message_data DataHolderSeq
              (multiple-value-bind (dh-count p3) (%dh-read-u32-le octets pos n)
                (when (> dh-count 65536) (%dh-fail))
                (setf pos p3)
                (let ((dh-list nil))
                  (dotimes (_ dh-count)
                    (let ((start pos))
                      (setf pos (%dh-scan-extent octets pos n))
                      (let* ((dh-len  (- pos start))
                             (dh-blob (make-array dh-len :element-type '(unsigned-byte 8))))
                        (replace dh-blob octets :start2 start :end2 pos)
                        (push dh-blob dh-list))))
                  (values src-guid sn rel-guid rel-sn
                          dest-part dest-ep src-ep
                          class-id
                          (nreverse dh-list)))))))))))
