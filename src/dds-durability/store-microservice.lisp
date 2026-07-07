(in-package #:dds.durability)

;;; MICROSERVICE-backed durable-store (WP-DURABILITY-MICROSERVICE-1, ADR 0050; ADR 0021 capability 6 —
;;; pluggable persistence file/db/MICROSERVICE). A client durable-store that implements the FIXED
;;; vtable (store.lisp:18-35) UNCHANGED by proxying every operation over ONE TCP connection to a
;;; reference server (make-microservice-server) that holds an inner durable-store (memory in Slice 1).
;;; The server is a DUMB opaque proxy: it dispatches each decoded op to its inner store and knows
;;; nothing of DARE/MAC. Record wire encoding REUSES the file store's frame format verbatim
;;; (%frame-record / %parse-frame) — no new record format is invented; the frame omits the topic (a
;;; file-store basename), so the topic travels as a separate u16-length UTF-8 field.
;;;
;;; Slice-1 scope (thinnest end-to-end): connect-on-open, put/get-range/topics/purge/open/close/count/
;;; delete round-trip, byte-exact + ordered, both impls. DEFERRED: DARE-wrapping the proxied bytes
;;; (Slice 2 — the opaque-proxy composition means make-encrypted-store layers OVER this client
;;; unchanged); persistent inner store + cross-restart + the DPERSIST_BACKEND=microservice config seam
;;; + graceful reconnect / error-recovery posture (Slice 3). The :sync and :set-chain-mac-fn vtable
;;; slots stay NIL — MEMORY-TIER PARITY: the client cannot ship a secret-holding chain-MAC closure over
;;; TCP, and per-record DARE-GCM (Slice 2) still authenticates each record; the cross-frame keyed chain
;;; is a local-store-tier feature (ADR 0045), documented as absent here exactly as for make-memory-store.
;;;
;;; WIRE PROTOCOL (length-prefixed request/response over the single stream; all integers little-endian):
;;;   REQUEST:  u32 body-len | u8 op-code | op-payload      (body-len counts the op-code + payload)
;;;   RESPONSE: u32 body-len | u8 status  | resp-payload     (status 0 = ok; body-len counts status + payload)
;;; A topic is [u16 len | UTF-8 bytes]; a record is [u32 frame-len | %frame-record bytes]. Every length
;;; and count is validated against the buffer extent BEFORE it is trusted (operating contract §4,
;;; NFR-SEC-POSTURE); the topic UTF-8 is well-formedness-validated (Table 3-7 / RFC 3629) before
;;; code-char; %parse-frame's own :short/:corrupt guards do the frame-body checking. So a malformed
;;; message raises a MICROSERVICE-PROTOCOL-ERROR that is caught (server: drop that connection AND keep
;;; accepting — %ms-serve-connection's SERIOUS-CONDITION backstop means no per-connection fault can kill
;;; the serve thread; client: re-signal MICROSERVICE-STORE-ERROR) — never an out-of-bounds access, an
;;; uncaught TYPE-ERROR, a crash, or a hang.

;;; ---- protocol constants ----

(defconstant +ms-op-put+       1 "Op-code: persist one record for a topic (payload: topic + frame).")
(defconstant +ms-op-get-range+ 2 "Op-code: fetch all records for a topic (payload: topic).")
(defconstant +ms-op-topics+    3 "Op-code: list non-empty topics (payload: none).")
(defconstant +ms-op-purge+     4 "Op-code: remove all records for a topic (payload: topic).")
(defconstant +ms-op-count+     5 "Op-code: count records (payload: u8 has-topic + [topic]).")
(defconstant +ms-op-open+      6 "Op-code: open the inner store (payload: u8 hk-code + u32 depth[0=nil]).")
(defconstant +ms-op-close+     7 "Op-code: end this client session (payload: none).")
(defconstant +ms-op-delete+    9 "Op-code: delete one record (payload: topic + guid16 + u64 sn).")

(defconstant +ms-status-ok+    0 "Response status byte: the op completed; op-specific result follows.")
(defconstant +ms-status-error+ 1 "Response status byte: the server rejected/failed the request.")

(defconstant +ms-result-t+        1 "Op-result byte for a boolean-T outcome (put stored, delete removed).")
(defconstant +ms-result-rejected+ 2 "Op-result byte for store-put :REJECTED (bounded inner store full).")

(defconstant +ms-hk-nil+       0 "history-kind wire code: NIL (defer to the inner store factory default).")
(defconstant +ms-hk-keep-all+  1 "history-kind wire code: :keep-all.")
(defconstant +ms-hk-keep-last+ 2 "history-kind wire code: :keep-last.")

(defconstant +ms-max-message+ (* 256 1024 1024)
  "Resource-exhaustion cap (NFR-SEC-POSTURE) on a single wire-message body length: a declared body-len
   above this is refused BEFORE any buffer is allocated. Generous (256 MiB >> one 64 MiB frame + slack,
   and a whole slice-scale get-range response) so a legitimate message is never false-rejected; a Slice-3
   chunked/streamed get-range removes the single-message ceiling for very large topics.")

;;; ---- conditions ----

(define-condition microservice-store-error (error)
  ((detail :initarg :detail :reader microservice-store-error-detail :initform "microservice store error"))
  (:report (lambda (c s) (format s "dds.durability microservice store: ~a"
                                 (microservice-store-error-detail c))))
  (:documentation "A microservice client operation failed at the connection level — the server closed
    the connection, the store is not open, or the response was unusable. Slice 1 signals it (graceful
    degradation + reconnect is Slice 3); a caller sees a clean Lisp error, never a hang or garbage."))

(define-condition microservice-protocol-error (error)
  ((detail :initarg :detail :reader microservice-protocol-error-detail :initform "protocol error"))
  (:report (lambda (c s) (format s "dds.durability microservice protocol: ~a"
                                 (microservice-protocol-error-detail c))))
  (:documentation "A wire message was malformed (a length/count/frame exceeded the buffer extent, or an
    op-code was unknown). Raised by the bounds-checked decoder BEFORE any out-of-bounds access; the
    server drops the offending connection, a client op surfaces it (operating contract §4)."))

;;; ---- message writer (adjustable octet buffer; durability is off the wire hot path) ----

(defun* %ms-buf ()
    (function () (array (unsigned-byte 8) (*)))
  "A fresh adjustable, fill-pointered octet accumulator for building one message body."
  (make-array 0 :element-type '(unsigned-byte 8) :adjustable t :fill-pointer 0))

(defun* %ms-put-u8 (b v)
    (function ((array (unsigned-byte 8) (*)) (unsigned-byte 8)) t)
  "Append one octet V to accumulator B."
  (vector-push-extend v b) t)

(defun* %ms-put-u16 (b v)
    (function ((array (unsigned-byte 8) (*)) (unsigned-byte 16)) t)
  "Append V as two little-endian octets to accumulator B."
  (vector-push-extend (ldb (byte 8 0) v) b)
  (vector-push-extend (ldb (byte 8 8) v) b)
  t)

(defun* %ms-put-u32 (b v)
    (function ((array (unsigned-byte 8) (*)) (unsigned-byte 32)) t)
  "Append V as four little-endian octets to accumulator B."
  (dotimes (i 4 t) (vector-push-extend (ldb (byte 8 (* 8 i)) v) b)))

(defun* %ms-put-u64 (b v)
    (function ((array (unsigned-byte 8) (*)) (integer 0)) t)
  "Append V as eight little-endian octets to accumulator B."
  (dotimes (i 8 t) (vector-push-extend (ldb (byte 8 (* 8 i)) v) b)))

(defun* %ms-put-bytes (b vec)
    (function ((array (unsigned-byte 8) (*)) (simple-array (unsigned-byte 8) (*))) t)
  "Append every octet of VEC to accumulator B."
  (loop for x across vec do (vector-push-extend x b))
  t)

(defun* %ms-put-string (b s)
    (function ((array (unsigned-byte 8) (*)) string) t)
  "Append S as a u16-length-prefixed UTF-8 field (reuses the file-store %string->utf8 encoder)."
  (let ((u (%string->utf8 s)))
    (when (> (length u) #xFFFF)
      (error 'microservice-protocol-error :detail "topic UTF-8 length exceeds u16"))
    (%ms-put-u16 b (length u))
    (%ms-put-bytes b u))
  t)

(defun* %ms-put-frame (b frame)
    (function ((array (unsigned-byte 8) (*)) (simple-array (unsigned-byte 8) (*))) t)
  "Append FRAME as a u32-length-prefixed record field (the transport slot length brackets the reused
   file-store frame, so the decoder bounds the frame BEFORE %parse-frame reads it)."
  (%ms-put-u32 b (length frame))
  (%ms-put-bytes b frame)
  t)

(defun* %ms-finalize (b)
    (function ((array (unsigned-byte 8) (*))) (simple-array (unsigned-byte 8) (*)))
  "Copy accumulator B's active contents into a fresh simple octet vector."
  (let ((v (make-array (length b) :element-type '(unsigned-byte 8))))
    (replace v b)
    v))

(defun* %ms-frame-message (code payload)
    (function ((unsigned-byte 8) (simple-array (unsigned-byte 8) (*))) (simple-array (unsigned-byte 8) (*)))
  "Assemble a wire message: u32 body-len | u8 CODE | PAYLOAD (body-len = 1 + |PAYLOAD|). Used for both a
   request (CODE = op-code) and a response (CODE = status)."
  (let* ((body-len (+ 1 (length payload)))
         (out (make-array (+ 4 body-len) :element-type '(unsigned-byte 8))))
    (%put-u32-le out 0 body-len)
    (setf (aref out 4) code)
    (replace out payload :start1 5)
    out))

;;; ---- bounds-checked message reader (every read validated against END before trusting wire data) ----

(defstruct* (ms-reader (:constructor %make-ms-reader))
  "A cursor over a received message body with an explicit END: every accessor checks it has the bytes
   before reading, signalling MICROSERVICE-PROTOCOL-ERROR rather than indexing out of bounds."
  (buf (make-array 0 :element-type '(unsigned-byte 8)) :type (simple-array (unsigned-byte 8) (*)))
  (pos 0 :type (integer 0))
  (end 0 :type (integer 0)))

(defun* %rd-need (r n)
    (function (ms-reader (integer 0)) t)
  "Assert R has at least N more octets before END; else signal a protocol error (no OOB read)."
  (when (> (+ (ms-reader-pos r) n) (ms-reader-end r))
    (error 'microservice-protocol-error :detail "truncated message (length exceeds buffer extent)"))
  t)

(defun* %rd-u8 (r)
    (function (ms-reader) (unsigned-byte 8))
  "Read one octet from R (bounds-checked)."
  (%rd-need r 1)
  (prog1 (aref (ms-reader-buf r) (ms-reader-pos r))
    (incf (ms-reader-pos r))))

(defun* %rd-u16 (r)
    (function (ms-reader) (unsigned-byte 16))
  "Read a little-endian u16 from R (bounds-checked)."
  (%rd-need r 2)
  (let ((p (ms-reader-pos r)) (b (ms-reader-buf r)))
    (prog1 (logior (aref b p) (ash (aref b (+ p 1)) 8))
      (incf (ms-reader-pos r) 2))))

(defun* %rd-u32 (r)
    (function (ms-reader) (unsigned-byte 32))
  "Read a little-endian u32 from R (bounds-checked; reuses the file-store %get-u32-le decode)."
  (%rd-need r 4)
  (prog1 (%get-u32-le (ms-reader-buf r) (ms-reader-pos r))
    (incf (ms-reader-pos r) 4)))

(defun* %rd-u64 (r)
    (function (ms-reader) (integer 0))
  "Read a little-endian u64 from R (bounds-checked; reuses the file-store %get-u64-le decode)."
  (%rd-need r 8)
  (prog1 (%get-u64-le (ms-reader-buf r) (ms-reader-pos r))
    (incf (ms-reader-pos r) 8)))

(defun* %rd-bytes (r n)
    (function (ms-reader (integer 0)) (simple-array (unsigned-byte 8) (*)))
  "Read N octets from R into a fresh simple vector (bounds-checked)."
  (%rd-need r n)
  (let ((v (make-array n :element-type '(unsigned-byte 8))))
    (replace v (ms-reader-buf r) :start2 (ms-reader-pos r) :end2 (+ (ms-reader-pos r) n))
    (incf (ms-reader-pos r) n)
    v))

(defun* %ms-utf8->string (buf start end)
    (function ((simple-array (unsigned-byte 8) (*)) (integer 0) (integer 0)) string)
  "Decode UTF-8 octets BUF[START..END) into a string — the bounds-checked, WELL-FORMEDNESS-VALIDATING
   inverse of %string->utf8. Enforces the Unicode Standard Table 3-7 / RFC 3629 §4 well-formed byte
   ranges: a lead byte C2..DF / E0..EF / F0..F4, second byte in the sequence-specific range (E0->A0..BF,
   ED->80..9F [excludes surrogates], F0->90..BF [excludes overlong], F4->80..8F [excludes >U+10FFFF]),
   and each further continuation byte 80..BF. A standalone continuation byte (80..BF), an overlong lead
   (C0/C1), and an invalid lead (F5..FF) are rejected. This rejects overlong encodings, surrogates
   (#xD800-#xDFFF), and scalars > #x10FFFF, so CODE-CHAR is only ever called on a valid Unicode scalar —
   ANY ill-formed sequence signals MICROSERVICE-PROTOCOL-ERROR BEFORE code-char, never a TYPE-ERROR /
   out-of-range crash (operating contract §4, the fuzz posture). A well-formed topic (a Unicode scalar
   string, the only thing %string->utf8 emits) round-trips exactly."
  (let ((out (make-array 0 :element-type 'character :adjustable t :fill-pointer 0))
        (i start))
    (declare (type (integer 0) i))
    (flet ((tail (j)                    ; validate + fold in a trailing continuation byte at index J
             (unless (<= #x80 (aref buf j) #xBF)
               (error 'microservice-protocol-error :detail "invalid UTF-8 continuation byte"))
             (logand (aref buf j) #x3F)))
      (loop while (< i end) do
        (let ((b0 (aref buf i)))
          (cond
            ((<= b0 #x7F)                                   ; 1-byte  00..7F
             (vector-push-extend (code-char b0) out) (incf i))
            ((<= #xC2 b0 #xDF)                              ; 2-byte  C2..DF 80..BF
             (when (> (+ i 2) end) (error 'microservice-protocol-error :detail "truncated UTF-8 (2-byte)"))
             (vector-push-extend (code-char (logior (ash (logand b0 #x1F) 6) (tail (+ i 1)))) out)
             (incf i 2))
            ((<= #xE0 b0 #xEF)                              ; 3-byte, second-byte range per lead
             (when (> (+ i 3) end) (error 'microservice-protocol-error :detail "truncated UTF-8 (3-byte)"))
             (let ((b1 (aref buf (+ i 1)))
                   (lo (if (= b0 #xE0) #xA0 #x80))
                   (hi (if (= b0 #xED) #x9F #xBF)))
               (unless (<= lo b1 hi)
                 (error 'microservice-protocol-error :detail "invalid UTF-8 3-byte sequence"))
               (vector-push-extend (code-char (logior (ash (logand b0 #x0F) 12)
                                                      (ash (logand b1 #x3F) 6) (tail (+ i 2)))) out))
             (incf i 3))
            ((<= #xF0 b0 #xF4)                              ; 4-byte, second-byte range per lead
             (when (> (+ i 4) end) (error 'microservice-protocol-error :detail "truncated UTF-8 (4-byte)"))
             (let ((b1 (aref buf (+ i 1)))
                   (lo (if (= b0 #xF0) #x90 #x80))
                   (hi (if (= b0 #xF4) #x8F #xBF)))
               (unless (<= lo b1 hi)
                 (error 'microservice-protocol-error :detail "invalid UTF-8 4-byte sequence"))
               (vector-push-extend (code-char (logior (ash (logand b0 #x07) 18) (ash (logand b1 #x3F) 12)
                                                      (ash (tail (+ i 2)) 6) (tail (+ i 3)))) out))
             (incf i 4))
            (t (error 'microservice-protocol-error :detail "invalid UTF-8 lead byte"))))))   ; 80..BF, C0/C1, F5..FF
    (coerce out 'string)))

(defun* %rd-string (r)
    (function (ms-reader) string)
  "Read a u16-length-prefixed UTF-8 topic field from R (bounds-checked, then UTF-8 decoded)."
  (let ((n (%rd-u16 r)))
    (%rd-need r n)
    (prog1 (%ms-utf8->string (ms-reader-buf r) (ms-reader-pos r) (+ (ms-reader-pos r) n))
      (incf (ms-reader-pos r) n))))

(defun* %rd-frame (r topic)
    (function (ms-reader string) durable-record)
  "Read a u32-length-prefixed record frame from R and decode it for TOPIC via the file-store %parse-frame
   (no chain MAC — memory-tier parity). The transport frame-len is validated against the buffer extent
   first; %parse-frame must return :ok and consume EXACTLY frame-len bytes, else a protocol error."
  (let ((flen (%rd-u32 r)))
    (%rd-need r flen)
    (let ((start (ms-reader-pos r))
          (fend  (+ (ms-reader-pos r) flen)))
      (multiple-value-bind (rec next reason) (%parse-frame (ms-reader-buf r) start fend topic)
        (unless (and (eq reason :ok) rec (= next fend))
          (error 'microservice-protocol-error :detail "malformed record frame"))
        (setf (ms-reader-pos r) fend)
        rec))))

;;; ---- op payload encoders (client side) ----

(defun* %ms-encode-put (topic writer-guid sn key-hash kind payload)
    (function (string (simple-array (unsigned-byte 8) (16)) (integer 0)
               (or null (simple-array (unsigned-byte 8) (16)))
               (member :data :dispose :unregister) (simple-array (unsigned-byte 8) (*)))
              (simple-array (unsigned-byte 8) (*)))
  "Encode a put op payload: topic (u16-len UTF-8) + one v2 record frame (reused %frame-record)."
  (let ((b (%ms-buf))
        (rec (make-durable-record :topic topic :writer-guid writer-guid :sn sn
                                  :key-hash key-hash :kind kind :payload payload)))
    (%ms-put-string b topic)
    (%ms-put-frame b (%frame-record rec))
    (%ms-finalize b)))

(defun* %ms-encode-topic (topic)
    (function (string) (simple-array (unsigned-byte 8) (*)))
  "Encode a single-topic op payload (get-range / purge)."
  (let ((b (%ms-buf))) (%ms-put-string b topic) (%ms-finalize b)))

(defun* %ms-encode-count (topic)
    (function ((or null string)) (simple-array (unsigned-byte 8) (*)))
  "Encode a count op payload: u8 has-topic + [topic]."
  (let ((b (%ms-buf)))
    (if topic (progn (%ms-put-u8 b 1) (%ms-put-string b topic)) (%ms-put-u8 b 0))
    (%ms-finalize b)))

(defun* %ms-encode-open (history-kind history-depth)
    (function ((or null (member :keep-all :keep-last)) (or null (integer 1)))
              (simple-array (unsigned-byte 8) (*)))
  "Encode an open op payload: u8 history-kind code + u32 depth (0 = NIL, defer to factory default)."
  (let ((b (%ms-buf))
        (hk (ecase history-kind
              ((nil) +ms-hk-nil+) (:keep-all +ms-hk-keep-all+) (:keep-last +ms-hk-keep-last+)))
        (depth (or history-depth 0)))
    (when (> depth #xFFFFFFFF)
      (error 'microservice-protocol-error :detail "history-depth exceeds u32"))
    (%ms-put-u8 b hk)
    (%ms-put-u32 b depth)
    (%ms-finalize b)))

(defun* %ms-encode-delete (topic writer-guid sn)
    (function (string (simple-array (unsigned-byte 8) (16)) (integer 0))
              (simple-array (unsigned-byte 8) (*)))
  "Encode a delete op payload: topic (u16-len UTF-8) + 16 raw GUID octets + u64 sn."
  (let ((b (%ms-buf)))
    (%ms-put-string b topic)
    (%ms-put-bytes b (coerce writer-guid '(simple-array (unsigned-byte 8) (*))))
    (%ms-put-u64 b sn)
    (%ms-finalize b)))

(defun* %ms-empty-payload ()
    (function () (simple-array (unsigned-byte 8) (*)))
  "The zero-length payload for a no-argument op (topics / close)."
  (make-array 0 :element-type '(unsigned-byte 8)))

;;; ---- client transport core ----

(defun* %ms-recv-message (sock)
    (function (t) (or null (simple-array (unsigned-byte 8) (*))))
  "Read one length-prefixed message body (op-code/status + payload) from SOCK. Returns the body simple
   vector, or NIL on EOF / peer-close. The declared body-len is bounds-checked against +ms-max-message+
   BEFORE the body buffer is allocated (resource guard); a zero or over-cap length is a protocol error.
   Shared by the client (reading responses) and the server (reading requests)."
  (let ((hdr (make-array 4 :element-type '(unsigned-byte 8))))
    (unless (dds.pal:tcp-recv sock hdr 4) (return-from %ms-recv-message nil))
    (let ((body-len (%get-u32-le hdr 0)))
      (when (or (zerop body-len) (> body-len +ms-max-message+))
        (error 'microservice-protocol-error :detail "message body length out of range"))
      (let ((body (make-array body-len :element-type '(unsigned-byte 8))))
        (unless (dds.pal:tcp-recv sock body body-len) (return-from %ms-recv-message nil))
        body))))

(defun* %ms-exchange (sock code payload)
    (function (t (unsigned-byte 8) (simple-array (unsigned-byte 8) (*))) ms-reader)
  "Send request (CODE + PAYLOAD) on SOCK, read the response, verify status ok, and return an ms-reader
   positioned just after the status byte (at the op result). Signals MICROSERVICE-STORE-ERROR if the
   server closed the connection or returned a non-ok status. Caller holds the store lock."
  (let ((msg (%ms-frame-message code payload)))
    (dds.pal:tcp-send sock msg (length msg))
    (let ((body (%ms-recv-message sock)))
      (unless body (error 'microservice-store-error :detail "server closed the connection"))
      (let ((r (%make-ms-reader :buf body :pos 0 :end (length body))))
        (let ((status (%rd-u8 r)))
          (unless (= status +ms-status-ok+)
            (error 'microservice-store-error :detail "server returned an error status"))
          r)))))

(defun* %ms-call (conn-cell lock code build-fn decode-fn)
    (function (cons t (unsigned-byte 8) function function) t)
  "Run one client op under the store LOCK on the open connection in CONN-CELL: build the request payload
   (BUILD-FN), exchange it, and decode the result (DECODE-FN on the response ms-reader). Signals if the
   store is not open. A MALFORMED server response (a bounds/well-formedness violation surfaced by the
   decoder as MICROSERVICE-PROTOCOL-ERROR) is re-signalled as a MICROSERVICE-STORE-ERROR so the client
   API presents ONE clean error type for any bad/torn response — never a raw decode TYPE-ERROR."
  (dds.pal:with-lock (lock)
    (let ((sock (car conn-cell)))
      (unless sock (error 'microservice-store-error :detail "store is not open"))
      (handler-case
          (funcall decode-fn (%ms-exchange sock code (funcall build-fn)))
        (microservice-protocol-error (e)
          (error 'microservice-store-error
                 :detail (format nil "malformed server response: ~a"
                                 (microservice-protocol-error-detail e))))))))

(defun* %ms-open (conn-cell lock host port history-kind history-depth)
    (function (cons t string (integer 0 65535)
               (or null (member :keep-all :keep-last)) (or null (integer 1)))
              (eql t))
  "store-open: connect (once) to HOST:PORT and drive the inner store's open with the effective history
   policy. Connect-on-open (Slice 1); reconnect/error-recovery is Slice 3."
  (dds.pal:with-lock (lock)
    (unless (car conn-cell)
      (setf (car conn-cell) (dds.pal:tcp-connect host port)))
    (%ms-exchange (car conn-cell) +ms-op-open+ (%ms-encode-open history-kind history-depth))
    t))

(defun* %ms-close (conn-cell lock)
    (function (cons t) (eql t))
  "store-close: best-effort send the close op, then tcp-close and forget the connection. Idempotent —
   a no-op when already closed. Returns T (store-close contract)."
  (dds.pal:with-lock (lock)
    (let ((sock (car conn-cell)))
      (when sock
        (ignore-errors (%ms-exchange sock +ms-op-close+ (%ms-empty-payload)))
        (ignore-errors (dds.pal:tcp-close sock))
        (setf (car conn-cell) nil))))
  t)

;;; ---- client store factory ----

(defun* make-microservice-store (&key host port (name :microservice))
    (function (&key (:host (or null string)) (:port (integer 0 65535)) (:name keyword)) durable-store)
  "Construct a MICROSERVICE-backed durable-store (ADR 0050) that implements the fixed durable-store
   vtable by proxying every operation over ONE TCP connection to a make-microservice-server holding an
   inner store. HOST defaults to 127.0.0.1; PORT is the server's (ephemeral) port from
   microservice-server-port. store-open connects and drives the inner store's open; store-close ends the
   session and closes the socket. Drop-in for memory/file/sqlite: the same store-put / store-get-range /
   store-count / store-delete dispatchers work identically, byte-exact and (guid,sn)-ordered.

   The :sync and :set-chain-mac-fn vtable slots are NIL — MEMORY-TIER PARITY (documented, exactly as
   make-memory-store): the client cannot ship a secret-holding chain-MAC closure over TCP, so the
   cross-frame keyed log-MAC chain (ADR 0045) is absent; per-record DARE-GCM (Slice 2, layered by
   make-encrypted-store OVER this opaque proxy) still authenticates each record. Slice 1 connects on
   open with no reconnect (a lost server surfaces as MICROSERVICE-STORE-ERROR; recovery is Slice 3)."
  (let ((lock (dds.pal:make-lock "dds-durability-microservice"))
        (conn-cell (list nil))
        (host* (or host "127.0.0.1"))
        (port* port))
    (unless port*
      (error 'microservice-store-error :detail "make-microservice-store requires :port"))
    (%make-durable-store
     :name name
     :put (lambda (topic writer-guid sn key-hash kind payload)
            (%ms-call conn-cell lock +ms-op-put+
                      (lambda () (%ms-encode-put topic writer-guid sn key-hash kind payload))
                      (lambda (r)
                        (let ((res (%rd-u8 r)))
                          (cond ((= res +ms-result-t+) t)
                                ((= res +ms-result-rejected+) :rejected)
                                (t (error 'microservice-store-error :detail "bad put result")))))))
     :get-range (lambda (topic)
                  (%ms-call conn-cell lock +ms-op-get-range+
                            (lambda () (%ms-encode-topic topic))
                            (lambda (r) (%ms-decode-records r topic))))
     :topics (lambda ()
               (%ms-call conn-cell lock +ms-op-topics+
                         (lambda () (%ms-empty-payload))
                         (lambda (r) (%ms-decode-topics r))))
     :purge (lambda (topic)
              (%ms-call conn-cell lock +ms-op-purge+
                        (lambda () (%ms-encode-topic topic))
                        (lambda (r) (%rd-u8 r) t)))
     :open (lambda (history-kind history-depth)
             (%ms-open conn-cell lock host* port* history-kind history-depth))
     :close (lambda () (%ms-close conn-cell lock))
     :count-fn (lambda (topic)
                 (%ms-call conn-cell lock +ms-op-count+
                           (lambda () (%ms-encode-count topic))
                           (lambda (r) (%rd-u64 r))))
     ;; :sync and :set-chain-mac-fn LEFT NIL — memory-tier parity (see the docstring).
     :delete (lambda (topic writer-guid sn)
               (%ms-call conn-cell lock +ms-op-delete+
                         (lambda () (%ms-encode-delete topic writer-guid sn))
                         (lambda (r)
                           (let ((res (%rd-u8 r)))
                             (if (= res +ms-result-t+) t
                                 (error 'microservice-store-error :detail "bad delete result")))))))))

;;; ---- client response decoders ----

(defun* %ms-decode-records (r topic)
    (function (ms-reader string) list)
  "Decode a get-range response (u32 count + count length-prefixed frames) into DURABLE-RECORDs for
   TOPIC, sorted by (writer-guid, sn) via the shared %record-guid-sn< so the microservice-store honours
   the same ordering contract as memory/file/sqlite (DRY). COUNT is bounded against the remaining buffer
   (each frame needs >= 1 byte) so a corrupt count cannot spin; each %rd-frame is itself bounds-checked."
  (let ((count (%rd-u32 r)))
    (when (> count (- (ms-reader-end r) (ms-reader-pos r)))
      (error 'microservice-protocol-error :detail "record count exceeds buffer extent"))
    (let ((recs '()))
      (dotimes (i count) (push (%rd-frame r topic) recs))
      (sort (nreverse recs) #'%record-guid-sn<))))

(defun* %ms-decode-topics (r)
    (function (ms-reader) list)
  "Decode a topics response (u32 count + count u16-length-prefixed UTF-8 strings) into a list of topic
   strings. COUNT is bounded against the remaining buffer; each string is bounds-checked."
  (let ((count (%rd-u32 r)))
    (when (> count (- (ms-reader-end r) (ms-reader-pos r)))
      (error 'microservice-protocol-error :detail "topic count exceeds buffer extent"))
    (let ((ts '()))
      (dotimes (i count) (push (%rd-string r) ts))
      (nreverse ts))))

;;; ---- reference server (opaque inner-store proxy) ----

(defstruct* (microservice-server (:constructor %make-microservice-server))
  "Handle for a running reference microservice server: the inner durable-store it proxies, the TCP
   listener, the accept/serve thread, the bound (ephemeral) PORT clients connect to, the HOST, a
   one-shot STOP-CELL flag, and a LOCK guarding stop against double-invocation."
  (inner (make-memory-store) :type durable-store)
  (listener nil :type t)
  (thread   nil :type t)
  (port     0   :type (integer 0 65535))
  (host     "127.0.0.1" :type string)
  (stop-cell (list nil) :type cons)
  ;; car = the connection currently being served, or NIL. Closing it on stop unblocks a serve thread
  ;; parked in recv on an idle client (a stop must never hang on a still-connected client).
  (conn-cell (list nil) :type cons)
  (lock nil :type t))

(defun* %ms-handle-request (body inner)
    (function ((simple-array (unsigned-byte 8) (*)) durable-store) (simple-array (unsigned-byte 8) (*)))
  "Decode one request BODY (op-code + payload), dispatch it to the opaque INNER store, and return the
   framed response (status ok + result). Every field is read through the bounds-checked ms-reader, so a
   malformed request raises MICROSERVICE-PROTOCOL-ERROR (the caller drops the connection) — never an OOB
   access. The server understands NO DARE/MAC: it just relays the vtable op to its inner store."
  (let* ((r (%make-ms-reader :buf body :pos 0 :end (length body)))
         (code (%rd-u8 r))
         (out (%ms-buf)))
    (cond
      ((= code +ms-op-put+)
       (let* ((topic (%rd-string r))
              (rec   (%rd-frame r topic))
              (res   (store-put inner topic (durable-record-writer-guid rec) (durable-record-sn rec)
                                (durable-record-key-hash rec) (durable-record-kind rec)
                                (durable-record-payload rec))))
         (%ms-put-u8 out (if (eq res :rejected) +ms-result-rejected+ +ms-result-t+))))
      ((= code +ms-op-get-range+)
       (let ((recs (store-get-range inner (%rd-string r))))
         (%ms-put-u32 out (length recs))
         (dolist (rec recs) (%ms-put-frame out (%frame-record rec)))))
      ((= code +ms-op-topics+)
       (let ((ts (store-topics inner)))
         (%ms-put-u32 out (length ts))
         (dolist (topic ts) (%ms-put-string out topic))))
      ((= code +ms-op-purge+)
       (store-purge inner (%rd-string r))
       (%ms-put-u8 out +ms-result-t+))
      ((= code +ms-op-count+)
       (let* ((has (%rd-u8 r))
              (topic (when (= has 1) (%rd-string r))))
         (%ms-put-u64 out (store-count inner topic))))
      ((= code +ms-op-open+)
       (let* ((hk-code (%rd-u8 r))
              (depth   (%rd-u32 r))
              (hk (cond ((= hk-code +ms-hk-keep-all+) :keep-all)
                        ((= hk-code +ms-hk-keep-last+) :keep-last)
                        (t nil))))
         (store-open inner hk (if (zerop depth) nil depth))
         (%ms-put-u8 out +ms-result-t+)))
      ((= code +ms-op-close+)
       ;; connection-scoped: acknowledge only. The inner store's lifecycle is the SERVER's, closed at
       ;; microservice-server-stop, not on a client disconnect (Slice-3 reconnect keeps the store alive).
       (%ms-put-u8 out +ms-result-t+))
      ((= code +ms-op-delete+)
       (let* ((topic (%rd-string r))
              (guid  (%rd-bytes r 16))
              (sn    (%rd-u64 r))
              (res   (store-delete inner topic (coerce guid '(simple-array (unsigned-byte 8) (16))) sn)))
         (%ms-put-u8 out (if (eq res t) +ms-result-t+ +ms-result-rejected+))))
      (t (error 'microservice-protocol-error :detail "unknown op-code")))
    (%ms-frame-message +ms-status-ok+ (%ms-finalize out))))

(defun* %ms-serve-connection (conn inner)
    (function (t durable-store) t)
  "Serve one client connection: read a request, dispatch, reply, repeat until the client closes (EOF) or
   ANY per-connection fault occurs. A MICROSERVICE-PROTOCOL-ERROR (a bounds/well-formedness violation) is
   the common clean case — it drops the connection fail-safe. The outer SERIOUS-CONDITION handler is the
   defense-in-depth BACKSTOP mandated for a network listener serving untrusted clients: any UNANTICIPATED
   per-connection error (a decode fault, a torn send, …) drops THAT connection and returns so the accept
   loop KEEPS ACCEPTING — a single malformed message can never kill the serve thread or wedge the
   listener. It closes the connection + continues (never retries the faulting op), so there is no spin."
  (handler-case
      (loop
        (let ((body (%ms-recv-message conn)))
          (when (null body) (return t))
          (let ((resp (%ms-handle-request body inner)))
            (dds.pal:tcp-send conn resp (length resp)))))
    (serious-condition () t)))

(defun* %ms-serve-loop (listener inner stop-cell conn-cell)
    (function (t durable-store cons cons) t)
  "The server accept loop: accept a connection (recording it in CONN-CELL so stop can close it), serve
   it to completion, loop, until STOP-CELL is set. microservice-server-stop sets the flag, closes the
   in-flight connection to wake a serve thread parked in recv, then makes a throwaway self-connection to
   wake a serve thread parked in accept (closing the listener alone does not portably unblock accept)."
  (loop
    (when (car stop-cell) (return t))
    (let ((conn (handler-case (dds.pal:tcp-accept listener)
                  (error () nil))))
      (cond
        ((car stop-cell) (when conn (ignore-errors (dds.pal:tcp-close conn))) (return t))
        (conn (setf (car conn-cell) conn)
              (unwind-protect (%ms-serve-connection conn inner)
                (setf (car conn-cell) nil)
                (ignore-errors (dds.pal:tcp-close conn))))
        (t nil)))))

(defun* make-microservice-server (&key (host "127.0.0.1") (port 0) (inner (make-memory-store)))
    (function (&key (:host string) (:port (integer 0 65535)) (:inner durable-store)) microservice-server)
  "Start a reference microservice server (ADR 0050) that proxies the durable-store vtable over TCP to
   the INNER store (memory in Slice 1). Binds HOST:PORT (port 0 = ephemeral — read the assigned port
   with microservice-server-port) and spawns one accept/serve thread. The server is a DUMB opaque proxy:
   it decodes each request, dispatches to INNER, and encodes the reply, with ZERO DARE/MAC knowledge.
   One client at a time (inline per-connection serving) is sufficient for Slice 1. Stop it with
   microservice-server-stop (clean thread join + socket close, no leak)."
  (let* ((listener (dds.pal:tcp-listen host port))
         (bound (dds.pal:tcp-local-port listener))
         (stop-cell (list nil))
         (conn-cell (list nil))
         (srv (%make-microservice-server :inner inner :listener listener :port bound :host host
                                         :stop-cell stop-cell :conn-cell conn-cell
                                         :lock (dds.pal:make-lock "dds-durability-microservice-server"))))
    (setf (microservice-server-thread srv)
          (dds.pal:spawn (lambda () (%ms-serve-loop listener inner stop-cell conn-cell))
                         :name "dds-durability-ms"))
    srv))

(defun* microservice-server-stop (srv)
    (function (microservice-server) (eql t))
  "Stop SRV cleanly and idempotently: set the stop flag, wake the blocked accept with a throwaway
   self-connection, join the serve thread, close the listener, and close the inner store. No thread
   leak, no lingering socket. Returns T."
  (dds.pal:with-lock ((microservice-server-lock srv))
    (unless (car (microservice-server-stop-cell srv))
      (setf (car (microservice-server-stop-cell srv)) t)
      ;; unblock a serve thread parked in recv on the live connection
      (let ((c (car (microservice-server-conn-cell srv))))
        (when c (ignore-errors (dds.pal:tcp-close c))))
      ;; unblock a serve thread parked in accept via a throwaway self-connection
      (ignore-errors
       (let ((waker (dds.pal:tcp-connect (microservice-server-host srv) (microservice-server-port srv))))
         (dds.pal:tcp-close waker)))
      (ignore-errors (dds.pal:join (microservice-server-thread srv)))
      (ignore-errors (dds.pal:tcp-close (microservice-server-listener srv)))
      (ignore-errors (store-close (microservice-server-inner srv)))))
  t)

;;; ---- DARE-wrapping store factory (Slice 2 — ADR 0021 cap 6 x cap 7 compose) ----

(defun* make-microservice-store-factory (&key host port epoch-dir key-dir)
    (function (&key (:host (or null string)) (:port (integer 0 65535))
                    (:epoch-dir (or pathname string)) (:key-dir (or pathname string)))
              function)
  "Return a 0-arg store factory producing the DARE-wrapped MICROSERVICE composition (ADR 0050 Slice 2;
   ADR 0021 capability 6 x capability 7): make-encrypted-store(make-microservice-store(:host HOST
   :port PORT), make-file-key-provider(:dir KEY-DIR), :epoch-dir EPOCH-DIR). Sibling of
   make-sqlite-store-factory / make-persistent-store-factory — the ONLY change is make-microservice-store
   in place of the local inner store, because the durable-store vtable is the fixed backend contract
   every tier fills unchanged. Pass this as the :STORE argument to MAKE-SERVICE-SPEC to config-select the
   encrypted tier whose persistence is a REMOTE microservice.

   The always-on CNSA-2.0 DARE runs entirely CLIENT-SIDE: the ML-KEM-1024 anchor, epochs.dat, the log-MAC
   anchor, and k_meta ALL live in the LOCAL EPOCH-DIR / KEY-DIR, and make-encrypted-store SEALS every
   record before it reaches the wire — so the remote microservice server stores ONLY opaque ciphertext
   (a hex topic-hash, a 16-byte GUID surrogate, sn=0, and the sealed blob), NEVER a plaintext
   topic/GUID/SN/key-hash/payload or any key. The cross-frame keyed chain-MAC (ADR 0045) is ABSENT at the
   microservice tier (make-microservice-store leaves :set-chain-mac-fn NIL — MEMORY-TIER PARITY: a
   secret-holding chain oracle cannot ship over TCP); per-record DARE-GCM still authenticates each frame.
   Unlike the sqlite/file siblings the inner tier's HISTORY policy is NOT a construction argument — it
   travels to the remote inner store at STORE-OPEN (the service-spec's history-kind/depth), the same
   open-time policy path memory and microservice share. HOST defaults to 127.0.0.1; PORT is the server's
   port. :PROCESS service mode does NOT carry this factory across the subprocess boundary — use :THREAD
   mode. The returned store requires STORE-OPEN before reads/writes and STORE-CLOSE (frees the DEK map +
   ends the client session); STORE-CLOSE is mandatory."
  (let ((h  host)
        (p  port)
        (ed (uiop:ensure-directory-pathname epoch-dir))
        (kd (uiop:ensure-directory-pathname key-dir)))
    (lambda ()
      (make-encrypted-store (make-microservice-store :host h :port p)
                            (dds.dare:make-file-key-provider :dir kd)
                            :epoch-dir ed))))
