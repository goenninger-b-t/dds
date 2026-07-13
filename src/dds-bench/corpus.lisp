;;;; Byte-exact XCDR corpus (FR-CDR-8, `make corpus`) — capture + verify.
;;;;
;;;; THE ORACLE IS THE WIRE. The reference bytes are the SerializedPayloads RTI Connext actually TRANSMITS,
;;;; captured verbatim off our own receive path — NOT Connext's rti::topic::to_cdr_buffer output, which is a
;;;; local CDR buffer that is neither padded nor carries the OPTIONS pad bits, and would therefore have
;;;; enshrined the exact bytes ADR 0061 proved malformed. Verified: for a 1-octet sequence Connext's
;;;; to_cdr_buffer yields 13 unpadded octets with options=0x0000, while Connext's WIRE payload for the same
;;;; sample is 16 octets with options=0x0003 (pad=3). Only the second is the wire.
;;;;
;;;; Clean-room (NFR-IP): we copy no RTI code and no rtiddsgen output — only the resulting OCTETS, which are
;;;; the OMG-specified encoding, not RTI's expression of it.

(in-package #:dds.bench)

(defparameter *corpus-dir* "corpus/xcdr2/"
  "Directory holding the byte-exact XCDR2 reference vectors + their manifest (FR-CDR-8). One .bin per case,
   each the SerializedPayload RTI Connext put ON THE WIRE for a known PerfData sample.")

(defun* %corpus-payload (len)
    (function ((integer 0)) (simple-array (unsigned-byte 8) (*)))
  "The corpus payload of LEN octets: byte i = i mod 256. Fixed by RULE so a vector's expected CONTENT is
   reproducible without shipping it — the .bin holds the reference ENCODING, this function the sample."
  (let ((v (make-array len :element-type '(unsigned-byte 8))))
    (dotimes (i len v) (setf (aref v i) (mod i 256)))))

(defun* %corpus-case-name (id len)
    (function (integer (integer 0)) string)
  "The canonical file name for the (ID, LEN) corpus case."
  (format nil "perfdata-id~d-len~d.bin" id len))

(defun* corpus-capture (&key (domain 0) (advertise-address "192.168.2.148") (seconds 240))
    (function (&key (:domain (integer 0)) (:advertise-address string) (:seconds (integer 1))) t)
  "CAPTURE MODE: subscribe PerfPing and write every DISTINCT (id, sequence-length) sample's raw
   SerializedPayload — exactly the octets RTI Connext transmitted — to *CORPUS-DIR* as a .bin, plus a
   manifest. Drive it with the Connext perf_pinger at each length (scripts/capture-corpus.sh).

   This is how the corpus is REGENERATED; `make corpus` only VERIFIES against the committed .bin files, so
   the gate does not need Connext installed."
  (ensure-directories-exist *corpus-dir*)
  (let ((seen (make-hash-table :test #'equal))
        (ts (dds.types:find-type-support "perf-data")))
    (let ((orig (symbol-function 'dds.disc::%deliver-user-sample)))
      (setf (fdefinition 'dds.disc::%deliver-user-sample)
            (lambda (node writer-id sn vec &rest r)
              (when (and (typep vec '(array (unsigned-byte 8) (*))) (>= (length vec) 12))
                (let* ((id (logior (aref vec 4) (ash (aref vec 5) 8)
                                   (ash (aref vec 6) 16) (ash (aref vec 7) 24)))
                       (slen (logior (aref vec 8) (ash (aref vec 9) 8)
                                     (ash (aref vec 10) 16) (ash (aref vec 11) 24)))
                       (key (cons id slen)))
                  (unless (gethash key seen)
                    (setf (gethash key seen) t)
                    (let ((path (merge-pathnames (%corpus-case-name id slen) *corpus-dir*)))
                      (with-open-file (out path :direction :output :element-type '(unsigned-byte 8)
                                                :if-exists :supersede :if-does-not-exist :create)
                        (write-sequence vec out))
                      (format t "~&[corpus] captured ~a: ~d octets (mod4=~d) options=~2,'0x~2,'0x~%"
                              (%corpus-case-name id slen) (length vec) (mod (length vec) 4)
                              (aref vec 2) (aref vec 3))
                      (finish-output)))))
              (apply orig node writer-id sn vec r))))
    (let* ((p (%perf-participant domain advertise-address nil))
           (tp (dds.dcps:create-topic p "PerfPing" "PerfData" ts))
           (tpo (dds.dcps:create-topic p "PerfPong" "PerfData" ts))
           (sub (dds.dcps:create-subscriber p))
           (pub (dds.dcps:create-publisher p)))
      (dds.dcps:create-datareader
       sub tp :qos (dds.qos:make-reader-qos :reliability :reliable :history-kind :keep-all))
      ;; A PerfPong writer we never write to: the Connext pinger waits for BOTH its endpoints to match
      ;; before it sends a single sample, so without this it exits before putting anything on the wire.
      ;; It will send its ping, wait in vain for an echo, and exit — which is exactly what we want.
      (dds.dcps:create-datawriter
       pub tpo :qos (dds.qos:make-writer-qos :reliability :reliable :history-kind :keep-all))
      (format t "~&[corpus] capturing Connext's WIRE payloads into ~a for ~d s~%" *corpus-dir* seconds)
      (finish-output)
      (sleep seconds)
      (dds.dcps:delete-participant p)))
  t)

(defun* corpus-verify ()
    (function () (integer 0))
  "THE GATE (`make corpus`): for every committed reference vector, serialize the SAME sample with OUR codec
   and require the bytes to be IDENTICAL to what RTI Connext put on the wire. Returns the number of
   MISMATCHES (0 = pass); prints a byte-level diff for each failure.

   This is the gate that would have caught ADR 0061 (the SerializedPayload trailing pad counted in the
   OPTIONS bits but never emitted) on day one: our unit suite, our byte-exact vector tests and our
   ours<->ours echo all passed while the wire bytes were malformed, because every one of them compared our
   encoder against our own decoder. An EXTERNAL encoder is the only thing that can falsify us."
  (let ((ts (dds.types:find-type-support "perf-data"))
        (files (sort (directory (merge-pathnames "*.bin" *corpus-dir*)) #'string< :key #'namestring))
        (bad 0) (n 0))
    (when (null files)
      (format t "~&corpus: NO VECTORS in ~a — regenerate with scripts/capture-corpus.sh~%" *corpus-dir*)
      (return-from corpus-verify 1))
    (dolist (f files)
      (let* ((name (file-namestring f))
             (id-len (%corpus-parse-name name)))
        (when id-len
          (destructuring-bind (id . len) id-len
            (incf n)
            (let ((expect (with-open-file (in f :element-type '(unsigned-byte 8))
                            (let ((v (make-array (file-length in) :element-type '(unsigned-byte 8))))
                              (read-sequence v in) v)))
                  (got (dds.dcps::%serialize-sample
                        ts (make-perf-data :id id :data (%corpus-payload len)) :xcdr2)))
              (cond
                ((and (= (length expect) (length got)) (every #'= expect got))
                 (format t "~&  ok   ~a (~d octets)~%" name (length expect)))
                (t
                 (incf bad)
                 (format t "~&  FAIL ~a: expected ~d octets, got ~d~%    connext: ~a~%    ours:    ~a~%"
                         name (length expect) (length got)
                         (%hex expect) (%hex got)))))))))
    (format t "~&corpus: ~d vector(s), ~d mismatch(es) — ~a~%" n bad (if (zerop bad) "PASS" "FAIL"))
    bad))

(defun* %corpus-parse-name (name)
    (function (string) (or null cons))
  "(ID . LEN) parsed from a corpus file name \"perfdata-id<ID>-len<LEN>.bin\", or NIL."
  (let ((idp (search "-id" name)) (lenp (search "-len" name)) (dot (search ".bin" name)))
    (when (and idp lenp dot (< idp lenp dot))
      (let ((id (ignore-errors (parse-integer name :start (+ idp 3) :end lenp)))
            (len (ignore-errors (parse-integer name :start (+ lenp 4) :end dot))))
        (when (and id len) (cons id len))))))

(defun* %hex (v)
    (function ((array (unsigned-byte 8) (*))) string)
  "V as a hex string, truncated for readability."
  (with-output-to-string (s)
    (let ((n (min (length v) 32)))
      (dotimes (i n) (format s "~2,'0x " (aref v i)))
      (when (> (length v) n) (format s "... (~d octets)" (length v))))))
