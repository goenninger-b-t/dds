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

(defparameter *corpus-verified-elsewhere*
  '("logevent-connext.bin")
  "Corpus vectors this gate does NOT verify, each because another gate does — named here so they are
   ACCOUNTED FOR rather than silently ignored, and so adding one is a deliberate edit.

   logevent-connext.bin is the @appendable LogEvent vector; it is verified byte-exact by
   dds.tests::run-log-corpus-test in `make test`, not here, because this corpus machinery lives in
   dds-bench and dds-bench does not load dds-log. Anything in the corpus directory that is neither
   parseable as a case nor listed here FAILS the gate.")

(defparameter *corpus-dir* "corpus/xcdr2/"
  "Directory holding the byte-exact XCDR2 reference vectors + their manifest (FR-CDR-8). One .bin per case,
   each the SerializedPayload RTI Connext put ON THE WIRE for a known PerfData sample.")

(defparameter *rtps-corpus-dir* "corpus/rtps/"
  "Directory holding captured RTPS SUBMESSAGE vectors — a different kind of artefact from *corpus-dir*,
   which holds SerializedPayloads. Each .bin is a COMPLETE submessage (4-octet header + body) exactly as
   RTI Connext 7.3.1 emitted it (ADR 0090, captured by interop/connext/appack/).

   These exist because the RTI vendor extensions have NO OMG clause to check against: for XCDR the spec is
   the oracle and the vector is the check, whereas here the vector IS the oracle. Verified by
   %rtps-corpus-verify, which DECODES each one — nothing in this stack emits APP_ACK, so a byte-exact
   ENCODE comparison would be verifying an encoder that deliberately does not exist.")

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
  ;; Same reason, and the same SETF-not-LET reason, as mutable-corpus-capture: with the RX store pool on
  ;; VEC is a pooled SLOT rather than the payload, and every vector would carry kilobytes of trailing slack.
  (setf dds.disc::*rx-store-pool-enabled* nil)
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

;;;; ---- The MUTABLE reference vector (ADR 0086) ----
;;;;
;;;; MUTABLE is the extensibility kind with the most room for two conformant writers to disagree: the
;;;; LENGTH CODE for a variable-width member is a WRITER'S CHOICE the spec does not fix (XTypes 1.3
;;;; §7.4.3.4.2 — codes 5-7 "save 4 bytes" but are never required). This stack emits LC 0-4; RTI Connext
;;;; may emit LC 5/6 for `label` and `vals`, reusing NEXTINT as the member's own leading length. Only a
;;;; captured vector can say which, and the vector wins.

(dds.gen:define-dds-type mutable-data (:extensibility :mutable)
  (a :i32 :id 0 :key t)
  (b :i16 :id 1)
  (label :string :id 2)
  ;; :name is the IDL spelling. A Lisp slot T-NS renders "t-ns"; MutableData.idl declares "t_ns",
  ;; and assignability matches members by NameHash — so without this the type gate refuses the peer
  ;; that uses the very same type, silently, as matched=0.
  (t-ns :i64 :id 3 :name "t_ns")
  (vals (:sequence :i32) :id 4))

(defparameter +mutable-corpus-file+ "mutabledata-connext.bin"
  "File name of the MUTABLE reference vector: the SerializedPayload RTI Connext transmits for the ONE fixed
   MutableData sample defined by %corpus-mutable-sample. Captured from the live peer in
   interop/connext/mutable/ (mutable_pub), whose IDL declares the same members with the same @ids.

   IT IS PL_CDR, NOT PL_CDR2. Connext 7.3.1 stamps an @mutable type 0x0003 (PL_CDR_LE, encoding version 1)
   by default, not the 0x000b (PL_CDR2_LE) this stack sends — so the XCDR1 parameter-list framing of rules
   (23)-(25) is the one that actually carries MUTABLE to Connext, and the length-code question of rules
   (21)-(22) does not even arise on this wire. That is worth stating plainly, because ADR 0086 expected
   the vector to settle the LC choice and instead it settled something more basic.")

(defun* %corpus-mutable-sample ()
    (function () mutable-data)
  "THE fixed MutableData sample the vector encodes — a=1, b=2, label=\"hello\", t_ns=3, vals=[7,8,9].
   Defined by RULE, exactly as %corpus-payload is, so the vector holds the reference ENCODING while this
   holds the sample. It must stay identical to the literal in interop/connext/mutable/mutable_pub.cxx."
  (make-mutable-data :a 1 :b 2 :label "hello" :t-ns 3
                     :vals (make-array 3 :element-type '(signed-byte 32)
                                         :initial-contents '(7 8 9))))

(defun* mutable-corpus-capture (&key (domain 0) (advertise-address "192.168.2.148") (seconds 60)
                                     peers (file +mutable-corpus-file+))
    (function (&key (:domain (integer 0)) (:advertise-address string) (:seconds (integer 1))
                    (:peers (or null string)) (:file string)) t)
  "CAPTURE MODE for the MUTABLE vector: subscribe the MutableCorpus topic and write the FIRST payload
   RTI Connext transmits to *CORPUS-DIR*/+mutable-corpus-file+, verbatim.

   Off our own receive path, for the reason the file header gives: Connext's rti::topic::to_cdr_buffer is
   not the wire. Drive it with interop/connext/mutable/mutable_pub."
  (ensure-directories-exist *corpus-dir*)
  ;; THE RX STORE POOL MUST BE OFF WHILE CAPTURING. With it on, the copy out of the receive buffer lands
  ;; in a POOLED slot and %deliver-user-sample is handed that slot's WHOLE vector — 16 KB of it for a
  ;; 72-octet sample — with the true extent (plen) known only to the caller. A vector captured that way
  ;; is the payload followed by kilobytes of pool slack, and nothing about it looks wrong. Off, the copy
  ;; is (make-array plen): exactly the octets Connext transmitted.
  ;;
  ;; SETF, NOT LET. The receive path runs on the RECEIVER THREAD, and a dynamic binding is thread-local —
  ;; a LET here rebinds the special in the capturing thread only and the receiver keeps seeing the global
  ;; value, so the pool stays on and the capture is silently 16 KB long again.
  (setf dds.disc::*rx-store-pool-enabled* nil)
  (let ((ts (dds.types:find-type-support "mutable-data"))
        (done nil))
    (let ((orig (symbol-function 'dds.disc::%deliver-user-sample)))
      (setf (fdefinition 'dds.disc::%deliver-user-sample)
            (lambda (node writer-id sn vec &rest r)
              (when (and (not done)
                         (typep vec '(array (unsigned-byte 8) (*)))
                         (>= (length vec) 8))
                (setf done t)
                (let ((path (merge-pathnames file *corpus-dir*)))
                  (with-open-file (out path :direction :output :element-type '(unsigned-byte 8)
                                            :if-exists :supersede :if-does-not-exist :create)
                    (write-sequence vec out))
                  (format t "~&[corpus] captured ~a: ~d octets, encap=~2,'0x~2,'0x options=~2,'0x~2,'0x~%~
                               [corpus] body: ~a~%"
                          file (length vec) (aref vec 0) (aref vec 1)
                          (aref vec 2) (aref vec 3) (%hex vec))
                  (finish-output)))
              (apply orig node writer-id sn vec r))))
    (let* ((p (dds.dcps:create-participant :domain domain :advertise-address advertise-address
                                           :peers (dds.disc:parse-peers peers) :autonomous t))
           (tp (dds.dcps:create-topic p "MutableCorpus" "MutableData" ts))
           (sub (dds.dcps:create-subscriber p)))
      (dds.dcps:create-datareader
       sub tp :qos (dds.qos:make-reader-qos :reliability :reliable :history-kind :keep-all))
      (format t "~&[corpus] capturing Connext's MUTABLE wire payload into ~a for ~d s~%"
              *corpus-dir* seconds)
      (finish-output)
      (sleep seconds)
      (dds.dcps:delete-participant p)))
  t)

(defun* run-mutable-publisher (&key (domain 0) (advertise-address "127.0.0.1")
                                    (count 200) (rate 20) (data-representation :xcdr1) peers)
    (function (&key (:domain (integer 0)) (:advertise-address string) (:count (integer 0))
                    (:rate (integer 1)) (:data-representation symbol) (:peers (or null string))) t)
  "Publish the fixed MutableData sample on MutableCorpus so a LIVE peer can be shown decoding a
   @mutable type this stack wrote (FR-IO, ADR 0086).

   DATA-REPRESENTATION defaults to :XCDR1, and that is not a tuning choice. RTI Connext sends and expects
   @mutable as PL_CDR (encoding version 1) — the vector proves it — and DATA_REPRESENTATION is an RxO
   policy, so an XCDR2-default writer SILENTLY fails to match a stock Connext reader (matched=0, no
   error). This is the same trap ADR 0057's leg documented for Shapes."
  (let* ((ts (dds.types:find-type-support "mutable-data"))
         (p (dds.dcps:create-participant :domain domain :advertise-address advertise-address
                                         :peers (dds.disc:parse-peers peers)
                                         :autonomous t))
         (tp (dds.dcps:create-topic p "MutableCorpus" "MutableData" ts))
         (pub (dds.dcps:create-publisher p))
         (dw (dds.dcps:create-datawriter
              pub tp :qos (dds.qos:make-writer-qos
                           :reliability :reliable
                           :data-representation (list data-representation)))))
    (format t "~&[mut-pub] MutableCorpus/MutableData rep=~a count=~d domain=~d~%"
            data-representation count domain)
    (finish-output)
    (unwind-protect
         ;; The MATCHED COUNT is reported, not just the write count. A writer that matches NOTHING still
         ;; writes happily and reports nothing wrong — that is precisely how a false type-gate reject
         ;; hid for six slices (ADR 0057). Without this line an outbound leg failure is indistinguishable
         ;; from a peer that simply did not print.
         (let ((last -1))
           (dotimes (n count)
             (let ((m (dds.dcps:matched-count p)))
               (when (/= m last)
                 (format t "~&[mut-pub] MATCHED ~d -> ~d remote reader(s)~%" (max last 0) m)
                 (finish-output)
                 (setf last m)))
             (dds.dcps:write-sample dw (%corpus-mutable-sample))
             (sleep (/ 1.0 rate))))
      (dds.dcps:delete-participant p))
    t))

(defun* run-mutable-subscriber (&key (domain 0) (advertise-address "127.0.0.1") (seconds 20) peers)
    (function (&key (:domain (integer 0)) (:advertise-address string) (:seconds (integer 1))
                    (:peers (or null string))) t)
  "Subscribe MutableCorpus and print EVERY member of every received sample, so a live leg asserts
   VALUES rather than a sample count — a decode that silently defaulted a member would otherwise pass.
   Used for the Connext -> us MUTABLE leg (FR-IO, ADR 0086)."
  (let* ((ts (dds.types:find-type-support "mutable-data"))
         (p (dds.dcps:create-participant :domain domain :advertise-address advertise-address
                                         ;; Fast DDS's profile whitelists 127.0.0.1 and never sees LAN
                                         ;; multicast SPDP, so reaching it needs a unicast peer at its
                                         ;; builtin metatraffic port (127.0.0.1:7410).
                                         :peers (dds.disc:parse-peers peers)
                                         :autonomous t))
         (tp (dds.dcps:create-topic p "MutableCorpus" "MutableData" ts))
         (sub (dds.dcps:create-subscriber p))
         (dr (dds.dcps:create-datareader
              sub tp :qos (dds.qos:make-reader-qos :reliability :reliable))))
    (format t "~&[mut-sub] MutableCorpus/MutableData domain=~d for ~ds~%" domain seconds)
    (finish-output)
    (unwind-protect
         (let ((deadline (+ (get-internal-real-time)
                            (* seconds internal-time-units-per-second)))
               (n 0))
           (loop while (< (get-internal-real-time) deadline)
                 do (dolist (cs (dds.dcps:take-samples dr))
                      (let ((info (dds.dcps:cached-sample-info cs))
                            (s (dds.dcps:cached-sample-data cs)))
                        (when (and (dds.dcps:sample-info-valid-data info) s)
                          (incf n)
                          (format t "~&[mut-sub] a=~d b=~d label=~a t_ns=~d vals=~d~{ ~d~}~%"
                                  (mutable-data-a s) (mutable-data-b s) (mutable-data-label s)
                                  (mutable-data-t-ns s) (length (mutable-data-vals s))
                                  (coerce (mutable-data-vals s) 'list))
                          (finish-output))))
                    (sleep 0.05))
           (format t "~&[mut-sub] received ~d sample(s)~%" n)
           (finish-output))
      (dds.dcps:delete-participant p))
    t))

(defparameter +mutable-fastdds-file+ "mutabledata-fastdds.bin"
  "The SECOND vendor's PL_CDR payload for the SAME fixed MutableData sample — eProsima Fast DDS.

   It is NOT byte-compared against our encoder, and that is the point of it. Fast DDS and RTI Connext
   DISAGREE on three fields of the XCDR1 parameter framing, and both readings are defensible:

     field                        Connext        Fast DDS
     b (a 2-octet short) length    4 (padded)     2 (exact)
     label (10-octet) length      12 (padded)    10 (exact)
     list terminator          0x7F02 (MU set)  0x3F02 (bare)

   Rules (24)/(25) say `M.value.ssize`, which is Fast DDS's literal reading; a PL_CDR list is also the
   RTPS ParameterList of RTPS 2.5 §9.4.2.11, where lengths are 4-multiples, which is Connext's. Table 34
   marks PID_LIST_END must-understand; rule (23) names a bare `PID_SENTINEL`. No encoder can be
   byte-exact against both, so ours matches Connext — the strict oracle — and this vector instead pins
   the half that MUST hold for either: that we DECODE the other vendor's choice correctly.")

(defun* %corpus-verify-mutable-decode (path)
    (function (t) (integer 0))
  "Verify the Fast DDS vector by DECODING it and checking every field, rather than by re-encoding it.

   A byte comparison would be the wrong test here: it would fail on a conformant peer's legitimately
   different framing choice and would say nothing about the property that actually matters, which is
   that a second vendor's payload round-trips through our decoder intact. Returns the mismatch count."
  (let* ((bytes (with-open-file (in path :element-type '(unsigned-byte 8))
                  (let ((v (make-array (file-length in) :element-type '(unsigned-byte 8))))
                    (read-sequence v in) v)))
         (want (%corpus-mutable-sample)))
    (multiple-value-bind (got status)
        (dds.dcps::%deserialize-payload (dds.types:find-type-support "mutable-data")
                                        (dds.core.buffer:octet-buffer-over bytes))
      (cond
        ((or status (null got))
         (format t "~&  FAIL ~a: decode refused it — status ~s~%" +mutable-fastdds-file+ status)
         1)
        ((and (= (mutable-data-a got) (mutable-data-a want))
              (= (mutable-data-b got) (mutable-data-b want))
              (string= (mutable-data-label got) (mutable-data-label want))
              (= (mutable-data-t-ns got) (mutable-data-t-ns want))
              (equalp (coerce (mutable-data-vals got) 'list)
                      (coerce (mutable-data-vals want) 'list)))
         (format t "~&  ok   ~a (~d octets, PL_CDR/XCDR1, DECODE-verified — a 2nd vendor's framing)~%"
                 +mutable-fastdds-file+ (length bytes))
         0)
        (t
         (format t "~&  FAIL ~a: decoded to a DIFFERENT sample: a=~s b=~s label=~s t-ns=~s vals=~s~%"
                 +mutable-fastdds-file+ (mutable-data-a got) (mutable-data-b got)
                 (mutable-data-label got) (mutable-data-t-ns got)
                 (coerce (mutable-data-vals got) 'list))
         1)))))

(defun* %corpus-verify-mutable (path)
    (function (t) (integer 0))
  "Verify the MUTABLE vector at PATH against our own encoder for the same fixed sample; returns the
   mismatch count (0 or 1) and prints a byte-level diff on failure.

   A mismatch here is NOT automatically our bug. The length code for a variable-width member is the one
   part of this encoding the spec leaves to the writer, so a diff confined to `label`'s and `vals`'
   member headers means Connext chose LC 5/6 where we chose LC 4 — both conformant, and the fix is to
   change dds.gen::%mutable-lc to match the vector, never to change the vector (ADR 0086 §A2)."
  (let ((expect (with-open-file (in path :element-type '(unsigned-byte 8))
                  (let ((v (make-array (file-length in) :element-type '(unsigned-byte 8))))
                    (read-sequence v in) v)))
        ;; :XCDR1 — the representation Connext actually used for this @mutable type (see
        ;; +mutable-corpus-file+). Comparing our XCDR2 output against a PL_CDR vector would compare two
        ;; different encodings and fail for a reason that says nothing about either.
        (got (dds.dcps::%serialize-sample
              (dds.types:find-type-support "mutable-data") (%corpus-mutable-sample) :xcdr1)))
    (cond
      ((and (= (length expect) (length got)) (every #'= expect got))
       (format t "~&  ok   ~a (~d octets, PL_CDR/XCDR1)~%" +mutable-corpus-file+ (length expect))
       0)
      (t
       (format t "~&  FAIL ~a: expected ~d octets, got ~d~%    connext: ~a~%    ours:    ~a~%~
                    NOTE: a diff in a VARIABLE member's header is a length-code choice, not a defect —~%~
                    the spec does not fix it. Match the vector via dds.gen::%mutable-lc (ADR 0086 §A2).~%"
               +mutable-corpus-file+ (length expect) (length got) (%hex expect) (%hex got))
       1))))

(defun* %rtps-corpus-expect (name)
    (function (string) list)
  "The expected decode of RTPS corpus vector NAME, as
   (submessage-id reader-id writer-id virtual-writer-count count intervals), where each interval is
   (first-sn last-sn interval-flags payload-len) — transcribed from the committed capture decode
   (interop/connext/appack/captures/appack-decoded.txt), NOT from our parser.

   ⚠️ THE EXPECTATION IS WRITTEN OUT BY HAND ON PURPOSE. Deriving it by running our own parser would make
   this gate compare the parser with itself, which is the exact failure ADR 0061 shipped through: our
   encoder, our decoder and our echo test all agreed while the wire bytes were wrong. An external encoder
   — here, RTI's — is the only thing that can falsify us."
  (cond
    ((string= name "appack-connext-1interval.bin")
     (list dds.rtps.message:+submsg-app-ack+ #x80000007 #x80000002 1 1
           '((1 1 #x0000 0))))
    ((string= name "appack-connext-2intervals.bin")
     (list dds.rtps.message:+submsg-app-ack+ #x80000007 #x80000002 1 2
           '((1 1 #x0100 0) (2 2 #x0000 0))))
    ((string= name "appackconf-connext.bin")
     (list dds.rtps.message:+submsg-app-ack-conf+ #x80000007 #x80000002 1 1 nil))
    (t nil)))

(defun* %rtps-corpus-verify-one (path)
    (function (t) (integer 0))
  "Decode one captured RTPS submessage vector and compare against its hand-transcribed expectation.
   Returns 1 on mismatch, 0 on match."
  (let* ((name (file-namestring path))
         (expect (%rtps-corpus-expect name)))
    (when (null expect)
      (format t "~&  FAIL ~a: unrecognised RTPS corpus vector — this gate verifies nothing for it.~%~
                    Add an arm to %rtps-corpus-expect naming what it should decode to.~%" name)
      (return-from %rtps-corpus-verify-one 1))
    (let* ((raw (with-open-file (in path :element-type '(unsigned-byte 8))
                  (let ((v (make-array (file-length in) :element-type '(unsigned-byte 8))))
                    (read-sequence v in) v)))
           (buf (dds.core.buffer:octet-buffer-over raw))
           (cur (dds.core.buffer:cursor buf :endianness :little))
           (sid (aref raw 0))
           (flags (aref raw 1))
           (intervals '()))
      (destructuring-bind (xid xrid xwid xvw xcount xintervals) expect
        (unless (= sid xid)
          (format t "~&  FAIL ~a: submessage id 0x~2,'0x, expected 0x~2,'0x~%" name sid xid)
          (return-from %rtps-corpus-verify-one 1))
        ;; skip the 4-octet submessage header; the parsers take a cursor positioned at the body
        (dds.core.buffer:cursor-set-position cur 4)
        (multiple-value-bind (rid wid vw count)
            (if (= sid dds.rtps.message:+submsg-app-ack+)
                (dds.rtps.message:parse-app-ack-body
                 cur flags
                 (lambda (v goff first last iflags poff plen)
                   (declare (ignore v goff poff))
                   (push (list first last iflags plen) intervals)))
                (dds.rtps.message:parse-app-ack-conf-body cur flags))
          (setf intervals (nreverse intervals))
          (cond
            ((null rid)
             (format t "~&  FAIL ~a: parser REJECTED a vector RTI actually emitted~%" name) 1)
            ((not (and (= rid xrid) (= wid xwid) (= vw xvw) (= count xcount)
                       (equal intervals xintervals)))
             (format t "~&  FAIL ~a~%    expected reader=~8,'0x writer=~8,'0x vw=~d count=~d intervals=~s~%~
                          ~&    got      reader=~8,'0x writer=~8,'0x vw=~d count=~d intervals=~s~%"
                     name xrid xwid xvw xcount xintervals rid wid vw count intervals)
             1)
            (t (format t "~&  ok   ~a (~d octets, ~d interval(s))~%" name (length raw) (length intervals))
               0)))))))

(defun* %rtps-corpus-verify ()
    (function () (integer 0))
  "Verify every captured RTPS submessage vector in *rtps-corpus-dir*. Returns the mismatch count.
   An EMPTY directory is a FAILURE, not a pass: a gate whose corpus silently vanished reads green while
   verifying nothing, which is the shape make corpus was already burned by once (ADR 0086)."
  (let ((files (sort (directory (merge-pathnames "*.bin" *rtps-corpus-dir*)) #'string< :key #'namestring))
        (bad 0))
    (when (null files)
      (format t "~&corpus: NO RTPS VECTORS in ~a — the APP_ACK decode (ADR 0090) is unverified~%"
              *rtps-corpus-dir*)
      (return-from %rtps-corpus-verify 1))
    (dolist (f files) (incf bad (%rtps-corpus-verify-one f)))
    bad))

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
        ;; EVERY vector must be accounted for. Previously an unrecognised file was silently skipped, so a
        ;; newly-dropped vector could sit in the corpus directory forever while the gate still said PASS —
        ;; the shape of a gate that cannot fail. Now it is verified here, named in
        ;; *corpus-verified-elsewhere*, or it is a FAILURE.
        (when (null id-len)
          (cond
            ;; The MUTABLE vector (ADR 0086) is a different TYPE, not another (id, len) case of
            ;; perf-data, so it gets its own arm rather than a name this loop could parse.
            ((string= name +mutable-corpus-file+)
             (incf n)
             (incf bad (%corpus-verify-mutable f)))
            ;; The second vendor's vector is DECODE-verified, not byte-compared — see
            ;; +mutable-fastdds-file+ for why no encoder can be byte-exact against both.
            ((string= name +mutable-fastdds-file+)
             (incf n)
             (incf bad (%corpus-verify-mutable-decode f)))
            ((member name *corpus-verified-elsewhere* :test #'string=)
             (format t "~&  --   ~a (verified elsewhere — see *corpus-verified-elsewhere*)~%" name))
            (t
             (incf bad)
             (format t "~&  FAIL ~a: unrecognised corpus vector — this gate verifies nothing for it.~%~
                          Name it perfdata-id<ID>-len<LEN>.bin so it is checked here, or add it to~%~
                          *corpus-verified-elsewhere* naming the gate that does.~%"
                     name))))
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
    ;; ADR 0090: the captured RTI submessage vectors are a SEPARATE corpus (different artefact, decode-
    ;; verified rather than byte-compared), folded into the same gate so there is one command to trust.
    (let ((rtps-bad (%rtps-corpus-verify)))
      (incf bad rtps-bad)
      (format t "~&corpus: ~d vector(s) verified here, ~d deferred, ~d file(s) total, ~d mismatch(es) — ~a~%"
              n (length *corpus-verified-elsewhere*) (length files) bad (if (zerop bad) "PASS" "FAIL")))
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
