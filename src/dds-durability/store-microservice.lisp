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
;;; delete round-trip, byte-exact + ordered, both impls. Slice 2 (DONE): DARE-wrapping the proxied bytes
;;; (make-microservice-store-factory — the opaque-proxy composition means make-encrypted-store layers
;;; OVER this client unchanged). Slice 3a (DONE): the server OWNS a PERSISTENT (file/SQLite) inner —
;;; opened@server-start (replays from disk) / closed@server-stop (fsync) — proving cross-restart recovery
;;; (bare + DARE-wrapped), plus the DPERSIST_BACKEND=microservice config seam (make-durability-store-
;;; factory). Slice 3b (built) — the client-side v3 log-MAC chain (ADR 0045) over the remote tier: the
;;; encrypted-store installs its HMAC oracle into the CLIENT-SIDE microservice-store (same process — only
;;; the 32-byte MAC OUTPUT ships, never the oracle closure), so :set-chain-mac-fn is now a real fn; each
;;; put computes the v3 MAC client-side and FOLDS mac(32) ∥ chain_seq(8) into the opaque payload (server +
;;; wire protocol UNCHANGED), and store-open re-verifies every topic's chain fail-closed — DETECTING a
;;; malicious server's frame DROP / REORDER / TAMPER (file/SQLite tamper-evidence parity). WP-DURABILITY-
;;; TAIL-ANCHOR-MS (ADR 0045 §7.1) now CLOSES the last two residuals for this tier: make-microservice-store
;;; FILLS the read-only chain-tails / verify-chain-prefix seam CLIENT-SIDE, so the decorator's sealed high-
;;; water tail anchor engages for encrypted-store(microservice-store) — closing tail-truncation-of-a-valid-
;;; prefix AND (uniquely) WHOLE-TOPIC-DROP-BY-A-MALICIOUS-SERVER (the sealed topic-SET is the client-trusted
;;; enumeration, so a server that omits a topic from store-topics is still verified -> :truncated). :sync
;;; stays NIL (no group-commit over TCP). WP-DURABILITY-MS-RECLAIM-REMAC (ADR 0050 §4.4) RESOLVES the former
;;; KEEP_LAST-reclaim limitation: a reclaim's store-delete now RE-MACs the surviving client chain (mirroring
;;; the file store's %rewrite-topic-log / SQLite's %sqlite-recompute-topic) and REPLACES the server's opaque
;;; frames via a new +ms-op-topic-rewrite+ op, so a KEEP_LAST reclaim through the microservice reopens CLEAN
;;; (the chained :delete = get-range + drop + re-seed + re-walk + re-fold + atomic topic-rewrite; %ms-delete-
;;; rechain). The server stays DARE-blind (it replaces opaque frames, never parses the mac). DEFERRED (Slice
;;; 3c): HISTORY-policy forwarding + graceful reconnect / multi-client concurrency / chunked large get-range /
;;; DoS-hardening.
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
(defconstant +ms-op-topic-rewrite+ 8
  "Op-code: atomically REPLACE a topic's records with the supplied opaque frames (payload: topic +
   u32 count + count record frames). The client ships the KEEP_LAST-reclaim re-MAC'd survivors here so the
   DARE-blind server replaces the stale-chained frames — mac/chain_seq ride INSIDE each opaque payload the
   server never parses (ADR 0050 §4.4).")
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
    the connection, the store is not open, or the response was unusable. A caller sees a clean Lisp
    error, never a hang or garbage. MICROSERVICE-CONN-LOST is the connection-drop SUBTYPE that %ms-call
    attempts ONE bounded reconnect+retry against before surfacing (Slice 3c-1, ADR 0050 §4.5); a caller
    catching MICROSERVICE-STORE-ERROR catches both."))

(define-condition microservice-conn-lost (microservice-store-error)
  ()
  (:documentation "The single TCP connection to the microservice server dropped mid-op — the peer
    closed / reset (recv returned NIL) or a send failed on a torn socket (tcp-send error). A SUBTYPE of
    MICROSERVICE-STORE-ERROR (so any store-error handler still catches it) but distinguishable, so
    %ms-call can CLOSE+CLEAR the dead socket, RE-DIAL once, and RETRY the op once — a bounded single
    reconnect, never an unbounded loop (ADR 0050 §4.5, Slice 3c-1). The reference server holds ZERO
    per-session state (open = policy-confirm no-op, close = ack), so re-establishment is a plain
    re-dial; the ops are idempotent, so a byte-identical retry cannot corrupt/duplicate."))

(define-condition microservice-protocol-error (error)
  ((detail :initarg :detail :reader microservice-protocol-error-detail :initform "protocol error"))
  (:report (lambda (c s) (format s "dds.durability microservice protocol: ~a"
                                 (microservice-protocol-error-detail c))))
  (:documentation "A wire message was malformed (a length/count/frame exceeded the buffer extent, or an
    op-code was unknown). Raised by the bounds-checked decoder BEFORE any out-of-bounds access; the
    server drops the offending connection, a client op surfaces it (operating contract §4)."))

(defparameter *durability-debug-ms-skip-reclaim-remac* nil
  "Test-only RED control (ADR 0050 §4.4). NIL (default) ⇒ inert: a KEEP_LAST reclaim's chained store-delete
   RE-MACs the survivors + rewrites the topic (%ms-delete-rechain), so the store reopens CLEAN. When non-NIL
   the chained :delete falls back to the OLD bare server-proxy delete (no re-MAC) — reproducing the pre-fix
   BRICK (the survivors' stale folded MACs mismatch the next open's re-seeded %ms-verify-chain) to prove the
   re-MAC is load-bearing. Never set in production code (mirrors *durability-debug-skip-tail-invalidate*).")

(defparameter *ms-reconnect-backoff-seconds* 0.05
  "The SHORT bounded pause before a single reconnect re-dial (%ms-reconnect, ADR 0050 §4.5, Slice 3c-1),
   giving a mid-restart server a moment to re-bind the port before the client re-dials. BOUNDED: one sleep
   per op failure, NOT a retry loop — a re-dial to a still-down port fails fast (ECONNREFUSED), so a dead
   server surfaces MICROSERVICE-STORE-ERROR quickly, never a hang. Small (50 ms) so a genuine reconnect is
   near-instant and NO-INFINITE-LOOP holds.")

(defparameter *durability-debug-ms-force-recv-drop* 0
  "Test-only DRIVER (ADR 0050 §4.5). A positive integer N makes the next N client %ms-exchange calls whose
   op-code is *durability-debug-ms-force-recv-drop-op* signal MICROSERVICE-CONN-LOST *after* a SUCCESSFUL
   tcp-send but *before* reading the response — the exact server-APPLIED-but-ack-LOST shape (the server
   processed the request; the client never saw the reply). Used to deterministically drive the exhausted-retry
   double-failure (set to 2 so an op's original + its reconnect-retry both lose their ack while the server
   applies it). Never set in production code.")

(defparameter *durability-debug-ms-force-recv-drop-op* +ms-op-put+
  "Test-only DRIVER (ADR 0050 §4.5): the op-code *durability-debug-ms-force-recv-drop* targets (default
   +ms-op-put+; set to +ms-op-purge+ / +ms-op-topic-rewrite+ to drive an ack-lost purge / rewrite). Scoping to
   ONE op-code keeps a store-open enumerate / re-sync get-range on the same connection undisturbed. Never set
   in production code.")

(defparameter *durability-debug-ms-skip-stale-resync* nil
  "Test-only RED control (ADR 0050 §4.5). NIL (default) ⇒ inert: a chained mutation whose retry EXHAUSTED
   marks its topic STALE, and the next chained mutation FORCE-re-syncs the client chain state from the server
   (%ms-resync-if-stale) before proceeding, so it chains from ground truth (no fork). When non-NIL the re-sync
   is SKIPPED — reproducing the exhausted-retry chain FORK (a second chain_seq-0 record) that bricks the next
   open's %ms-verify-chain, proving the re-sync is load-bearing. Never set in production code.")

(defparameter *durability-debug-ms-skip-redial-dropped* nil
  "Test-only RED control (ADR 0050 §4.5). NIL (default) ⇒ inert: an op on a DROPPED connection (sock NIL from
   a prior op's failed re-dial, but the store was never store-closed) re-dials once before failing, so an
   op-during-outage recovers when the server returns. When non-NIL the dropped-connection re-dial is SKIPPED —
   reproducing the TERMINAL 'store is not open' (the pre-fix behavior where a single outage permanently
   disabled the store), proving the re-dial-from-dropped is load-bearing. Never set in production code.")

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

(defun* %ms-encode-topic-rewrite (topic records)
    (function (string list) (simple-array (unsigned-byte 8) (*)))
  "Encode a topic-rewrite op payload: topic (u16-len UTF-8) + u32 count + count × record frames (each the
   REUSED %frame-record of a folded record). The DARE-blind server REPLACES the topic's records with these
   OPAQUE frames; the mac/chain_seq ride INSIDE each folded payload the server never parses (ADR 0050 §4.4)."
  (let ((b (%ms-buf)))
    (%ms-put-string b topic)
    (%ms-put-u32 b (length records))
    (dolist (rec records) (%ms-put-frame b (%frame-record rec)))
    (%ms-finalize b)))

(defun* %ms-empty-payload ()
    (function () (simple-array (unsigned-byte 8) (*)))
  "The zero-length payload for a no-argument op (topics / close)."
  (make-array 0 :element-type '(unsigned-byte 8)))

;;; ---- client transport core ----

(defstruct* (ms-conn (:constructor %make-ms-conn))
  "The client's ONE connection to the microservice server, carrying the dial coordinates so %ms-call /
   %ms-exchange can RE-DIAL after a drop (Slice 3c-1, ADR 0050 §4.5): HOST + PORT (immutable, set at
   store construction from the :host/:port args) and the current SOCK (NIL when closed / not yet
   connected). Replaces the Slice-1 bare (sock) cons — a drop no longer permanently bricks the store
   because the reconnect path re-dials HOST:PORT. Accessed ONLY under the store lock (the same discipline
   the cons had); a fresh SOCK re-appears in the cell after a successful reconnect.

   Two flags distinguish sock=NIL states so an op-during-outage recovers WITHOUT letting a never-opened
   store proceed: EVER-CONNECTED-P (a dial has succeeded at least once) marks the DROPPED state (sock NIL
   after a failed re-dial, but the connection WAS established) as re-dial-able on the next op — vs a
   never-opened store (sock NIL, EVER-CONNECTED-P NIL) which is 'store is not open'. CLOSED-P (set only by
   %ms-close) is the TERMINAL state: after store-close no op re-dials. store-open clears CLOSED-P (re-open)."
  (host "127.0.0.1" :type string)
  (port 0 :type (integer 0 65535))
  (sock nil :type t)
  (ever-connected-p nil :type t)
  (closed-p nil :type t))

(defun* %ms-dial (conn)
    (function (ms-conn) t)
  "Dial CONN's HOST:PORT and store the connected socket in CONN (caller holds the store lock; SOCK must be
   NIL). Reuses dds.pal:tcp-connect — the single dial primitive shared by connect-on-open and reconnect. On
   success marks EVER-CONNECTED-P (so a later sock=NIL is a re-dial-able DROP, not a never-opened store) and
   clears CLOSED-P (FIX B, ADR 0050 §4.5): a successful dial re-establishes the connection, so a same-object
   close→reopen works — the decorator's PRE-open tail-anchor probe (%ms-fetch-tuples) dials here and must not
   then be refused by %ms-call's closed-p guard (which %ms-open clears too late for the pre-open probe)."
  (setf (ms-conn-sock conn) (dds.pal:tcp-connect (ms-conn-host conn) (ms-conn-port conn)))
  (setf (ms-conn-ever-connected-p conn) t)
  (setf (ms-conn-closed-p conn) nil)
  (ms-conn-sock conn))

(defun* %ms-ensure-connected (conn)
    (function (ms-conn) t)
  "Connect-on-demand: dial CONN if it has no live socket (caller holds the store lock). The connect-on-open
   and the tail-anchor connect-on-demand share this (DRY). A dial failure (server down at first connect)
   propagates as-is — reconnect-after-a-drop is %ms-reconnect's bounded path, not this first connect."
  (unless (ms-conn-sock conn) (%ms-dial conn))
  t)

(defun* %ms-reconnect (conn)
    (function (ms-conn) t)
  "Bounded SINGLE reconnect after a dropped connection (ADR 0050 §4.5): CLOSE+CLEAR the dead socket, pause
   one short backoff (*ms-reconnect-backoff-seconds*), and RE-DIAL ONCE. Signals MICROSERVICE-STORE-ERROR if
   the re-dial fails (server still down) — a fast, clean failure, NOT an unbounded loop or a hang. Caller
   holds the store lock; on return CONN has a fresh live socket and the caller retries the op ONCE."
  (let ((old (ms-conn-sock conn)))
    (setf (ms-conn-sock conn) nil)
    (when old (ignore-errors (dds.pal:tcp-close old))))
  (sleep *ms-reconnect-backoff-seconds*)
  (handler-case (%ms-dial conn)
    (error (e)
      (error 'microservice-store-error
             :detail (format nil "reconnect to ~a:~d failed: ~a"
                             (ms-conn-host conn) (ms-conn-port conn) e))))
  t)

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
   positioned just after the status byte (at the op result). A DROPPED connection — a failed send (tcp-send
   signals a plain error on a torn socket, pal-net) OR a server-closed read (%ms-recv-message NIL) — is
   translated to MICROSERVICE-CONN-LOST so %ms-call attempts one bounded reconnect (the send-side raw error
   no longer escapes the one-clean-error contract). A non-ok STATUS is a legit server rejection, NOT a drop,
   so it stays MICROSERVICE-STORE-ERROR (never retried). Caller holds the store lock."
  (let ((msg (%ms-frame-message code payload)))
    (handler-case (dds.pal:tcp-send sock msg (length msg))
      (error (e)
        (error 'microservice-conn-lost
               :detail (format nil "send failed (connection dropped): ~a" e))))
    ;; test-only: simulate a server-APPLIED-but-ack-LOST drop of the targeted op (the send reached the server
    ;; + it applied the op; the client never ADVANCES its state because DECODE-FN doesn't run). Scoped to
    ;; *durability-debug-ms-force-recv-drop-op* so a store-open enumerate / re-sync get-range on the same
    ;; connection is NOT dropped. DRAIN the response first so no stale bytes linger on the reused socket.
    (when (and (plusp *durability-debug-ms-force-recv-drop*) (= code *durability-debug-ms-force-recv-drop-op*))
      (decf *durability-debug-ms-force-recv-drop*)
      (%ms-recv-message sock)
      (error 'microservice-conn-lost :detail "forced post-send recv drop (test-only)"))
    (let ((body (%ms-recv-message sock)))
      (unless body (error 'microservice-conn-lost :detail "server closed the connection"))
      (let ((r (%make-ms-reader :buf body :pos 0 :end (length body))))
        (let ((status (%rd-u8 r)))
          (unless (= status +ms-status-ok+)
            (error 'microservice-store-error :detail "server returned an error status"))
          r)))))

(defun* %ms-call (conn lock code build-fn decode-fn)
    (function (ms-conn t (unsigned-byte 8) function function) t)
  "Run one client op under the store LOCK on CONN's open connection: build the request payload (BUILD-FN),
   exchange it, and decode the result (DECODE-FN on the response ms-reader). Signals if the store is not
   open. A MALFORMED server response (a bounds/well-formedness violation surfaced by the decoder as
   MICROSERVICE-PROTOCOL-ERROR) is re-signalled as a MICROSERVICE-STORE-ERROR so the client API presents
   ONE clean error type for any bad/torn response — never a raw decode TYPE-ERROR.

   RECONNECT (Slice 3c-1, ADR 0050 §4.5): if the connection DROPPED (MICROSERVICE-CONN-LOST from a send
   failure or a server-closed read), CLOSE+CLEAR the dead socket, RE-DIAL once (%ms-reconnect), and RETRY
   the op ONCE — a BOUNDED single reconnect. The retry re-invokes BUILD-FN + DECODE-FN, which is SAFE only
   because every op is idempotent AND advances client chain/put-index state ONLY in DECODE-FN after a
   confirmed response: a byte-identical retry re-sends folded frames the DARE-blind server INSERT-OR-IGNOREs
   (put), replaces with the same survivor set (topic-rewrite), or re-drops (delete/purge). A second
   consecutive drop (or a failed re-dial) surfaces cleanly as MICROSERVICE-STORE-ERROR (no third attempt,
   no loop, no hang). A non-drop server error (bad status) is NOT retried.

   DROPPED-vs-CLOSED (Fix 2, ADR 0050 §4.5): a prior op whose re-dial failed leaves sock NIL but the store
   is NOT closed (EVER-CONNECTED-P set). This op RE-DIALS from that dropped state (bounded) so an op-during-
   outage recovers when the server returns — it is NOT a terminal 'store is not open'. Only %ms-close (which
   sets CLOSED-P) or a never-opened store is terminal. The exhausted-retry marks the topic STALE at the chain
   layer (%ms-resync-if-stale) so the NEXT chained mutation re-syncs from the server (no fork; Fix 1)."
  (dds.pal:with-lock (lock)
    (cond
      ((ms-conn-closed-p conn) (error 'microservice-store-error :detail "store is not open"))
      ((ms-conn-sock conn))                                     ; connected — proceed
      ((and (ms-conn-ever-connected-p conn) (not *durability-debug-ms-skip-redial-dropped*))
       (%ms-reconnect conn))                                    ; DROPPED — bounded re-dial (clean error if down; NOT terminal)
      (t (error 'microservice-store-error :detail "store is not open")))   ; never opened (or the RED knob)
    (labels ((clean-protocol (e)
               (error 'microservice-store-error
                      :detail (format nil "malformed server response: ~a"
                                      (microservice-protocol-error-detail e))))
             (run () (funcall decode-fn (%ms-exchange (ms-conn-sock conn) code (funcall build-fn)))))
      (handler-case (run)
        (microservice-conn-lost ()
          (%ms-reconnect conn)              ; bounded single re-dial (signals store-error if the server is down)
          (handler-case (run)               ; retry ONCE; a second conn-lost propagates as a clean store-error
            (microservice-protocol-error (e) (clean-protocol e))))
        (microservice-protocol-error (e) (clean-protocol e))))))

(defun* %ms-open (conn lock history-kind history-depth)
    (function (ms-conn t (or null (member :keep-all :keep-last)) (or null (integer 1)))
              (eql t))
  "store-open: connect-on-demand to CONN's HOST:PORT (%ms-ensure-connected) and drive the inner store's
   open with the effective history policy. A dropped connection surfaces as a clean MICROSERVICE-CONN-LOST
   (a MICROSERVICE-STORE-ERROR subtype); mid-session reconnect is %ms-call's bounded path (the post-restart
   op that reconnects goes through %ms-call, not a re-open)."
  (dds.pal:with-lock (lock)
    (setf (ms-conn-closed-p conn) nil)              ; store-open (re-)opens — clear any prior terminal close
    (%ms-ensure-connected conn)
    (%ms-exchange (ms-conn-sock conn) +ms-op-open+ (%ms-encode-open history-kind history-depth))
    t))

(defun* %ms-close (conn lock)
    (function (ms-conn t) (eql t))
  "store-close: best-effort send the close op, then tcp-close and forget the connection. Idempotent —
   a no-op when already closed. Sets CLOSED-P so a post-close op is TERMINAL 'store is not open' (a dropped
   connection re-dials, but an explicitly CLOSED store does not). Returns T (store-close contract)."
  (dds.pal:with-lock (lock)
    (let ((sock (ms-conn-sock conn)))
      (when sock
        (ignore-errors (%ms-exchange sock +ms-op-close+ (%ms-empty-payload)))
        (ignore-errors (dds.pal:tcp-close sock)))
      (setf (ms-conn-sock conn) nil)
      (setf (ms-conn-closed-p conn) t)))
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

   The :sync slot is NIL (memory-tier parity — group-commit sync is a local-store concern). The
   :set-chain-mac-fn slot is LIVE (Slice 3b, ADR 0050 §4.3): the encrypted-store decorator installs its
   log-MAC oracle into THIS client-side store, arming the client-side v3 chain-MAC over the remote tier —
   a malicious server that DROPS / REORDERS / TAMPERS sealed frames is detected fail-closed on open
   (file/SQLite parity). The 32-byte MAC + chain_seq are FOLDED into the OPAQUE payload, so the server +
   wire protocol are UNCHANGED (the server stores a slightly-longer opaque blob it never parses). The
   :chain-tails-fn / :verify-chain-prefix-fn seam slots are ALSO LIVE (WP-DURABILITY-TAIL-ANCHOR-MS, ADR 0045
   §7.1), filled CLIENT-SIDE: the decorator's sealed high-water tail anchor engages for this tier, closing
   tail-truncation AND whole-topic-drop-by-a-malicious-server (the sealed topic-SET is the client-trusted
   enumeration). A BARE microservice-store (no encrypted-store to install the oracle) leaves the chain
   uninstalled and seals no anchor — memory parity, Slice 1 round-trip unchanged. store-open connects on
   demand; a mid-session drop (server restart / network blip) triggers a BOUNDED single reconnect +
   idempotent retry per op in %ms-call (Slice 3c-1, ADR 0050 §4.5) — a restarted server on the SAME port is
   transparently re-dialled; a server that stays down surfaces a clean MICROSERVICE-STORE-ERROR (no hang)."
  (let* ((lock (dds.pal:make-lock "dds-durability-microservice"))
         (host* (or host "127.0.0.1"))
         ;; the conn carries host/port so %ms-call can RE-DIAL after a drop (Slice 3c-1); :port is REQUIRED.
         (port* (or port (error 'microservice-store-error :detail "make-microservice-store requires :port")))
         (conn (%make-ms-conn :host host* :port port* :sock nil))
         ;; client-side remote-tier chain-MAC state (Slice 3b, ADR 0045/0050 §4.3), installed by the
         ;; encrypted decorator via :set-chain-mac-fn; NIL oracle ⇒ chain absent (bare store, memory parity).
         (chain-mac-fn nil)                              ; the log-MAC oracle (data)->HMAC, or NIL
         (chain-macs   (make-hash-table :test #'equal))  ; topic-hash -> running tail chain MAC (32 octets)
         (chain-seqs   (make-hash-table :test #'equal))  ; topic-hash -> next monotonic chain_seq (u64)
         ;; per-topic (guid . sn) set of records already put this session (rebuilt on open/get-range from the
         ;; server's authoritative records) — the microservice analogue of the file store's in-memory index:
         ;; an idempotent re-put must NOT advance the chain (else a later put false-rejects on re-verify).
         (put-index    (make-hash-table :test #'equal))
         ;; topics whose LAST chain-mutating op EXHAUSTED its reconnect-retry (Fix 1, ADR 0050 §4.5): the op
         ;; MAY have been applied-but-unacked, so the client chain state may have diverged from the server.
         ;; The next chained mutation FORCE-re-syncs the topic from the server (%ms-resync-if-stale) before
         ;; proceeding, so it chains from ground truth — no fork, no later-open false-reject brick.
         (stale-topics (make-hash-table :test #'equal)))
    (%make-durable-store
     :name name
     :put (lambda (topic writer-guid sn key-hash kind payload)
            (if chain-mac-fn
                ;; chained tier: compute the v3 MAC client-side over the UNWRAPPED sealed frame, FOLD
                ;; mac ∥ chain_seq into the opaque payload, ship the (format-unchanged) put, advance the
                ;; running MAC + chain_seq. Idempotent re-put (index hit) = no chain advance (file parity);
                ;; the shared cells thread state build->decode, both running under one %ms-call lock.
                (let ((reput nil) (new-mac nil) (new-seq 0) (kkey nil) (idx nil))
                  ;; Fix 1 (ADR 0050 §4.5): if a prior op EXHAUSTED and left TOPIC stale, re-sync the client
                  ;; chain state from the server BEFORE building this put so it chains from ground truth (the
                  ;; re-sync re-learns whether the exhausted op was applied); mark stale if THIS put exhausts.
                  (%ms-resync-if-stale conn lock topic chain-mac-fn chain-macs chain-seqs put-index stale-topics)
                  (handler-case
                  (%ms-call conn lock +ms-op-put+
                            (lambda ()
                              (setf idx (or (gethash topic put-index)
                                            (setf (gethash topic put-index) (make-hash-table :test #'equal))))
                              (setf kkey (cons (coerce writer-guid 'list) sn))
                              (if (gethash kkey idx)
                                  (progn (setf reput t)
                                         (%ms-encode-put topic writer-guid sn key-hash kind payload))
                                  (let* ((prev (or (gethash topic chain-macs) (%chain-seed chain-mac-fn topic)))
                                         (seq  (the (integer 0) (gethash topic chain-seqs 0)))
                                         (rec  (make-durable-record :topic topic :writer-guid writer-guid :sn sn
                                                                    :key-hash key-hash :kind kind :payload payload))
                                         (mac  (nth-value 1 (%frame-record-versioned
                                                             rec +frame-version-v3+ prev chain-mac-fn))))
                                    (setf new-mac mac new-seq seq)
                                    (%ms-encode-put topic writer-guid sn key-hash kind
                                                    (%ms-fold-payload
                                                     payload (the (simple-array (unsigned-byte 8) (*)) mac) seq)))))
                            (lambda (r)
                              (let ((res (%rd-u8 r)))
                                (cond ((= res +ms-result-t+)
                                       (unless reput
                                         (setf (gethash topic chain-macs) new-mac)
                                         (setf (gethash topic chain-seqs) (1+ new-seq))
                                         (setf (gethash kkey idx) t))
                                       t)
                                      ((= res +ms-result-rejected+) :rejected)
                                      (t (error 'microservice-store-error :detail "bad put result"))))))
                    ;; the exhausted-retry MAY have applied the put but lost the ack — mark the topic STALE so
                    ;; the next chained mutation re-syncs the chain state from the server (Fix 1), then re-signal.
                    (microservice-store-error (e) (setf (gethash topic stale-topics) t) (error e))))
                ;; bare tier: no oracle installed ⇒ no chain (memory parity, Slice 1 unchanged).
                (%ms-call conn lock +ms-op-put+
                          (lambda () (%ms-encode-put topic writer-guid sn key-hash kind payload))
                          (lambda (r)
                            (let ((res (%rd-u8 r)))
                              (cond ((= res +ms-result-t+) t)
                                    ((= res +ms-result-rejected+) :rejected)
                                    (t (error 'microservice-store-error :detail "bad put result"))))))))
     :get-range (lambda (topic)
                  (if chain-mac-fn
                      (%ms-get-range-verified conn lock topic chain-mac-fn chain-macs chain-seqs put-index)
                      (%ms-call conn lock +ms-op-get-range+
                                (lambda () (%ms-encode-topic topic))
                                (lambda (r) (%ms-decode-records r topic)))))
     :topics (lambda () (%ms-topics-list conn lock))
     :purge (lambda (topic)
              ;; drop the purged topic's client-side chain head (mirrors the file/SQLite :purge fix,
              ;; store-file.lisp / store-sqlite.lisp): the decode-fn runs under the store lock, so clear it
              ;; atomically with the purge. Else store-chain-tails would seal a STALE (N, M_N) for a
              ;; server-purged topic -> the next open's tail-anchor verify fetches 0 records -> :truncated ->
              ;; false-reject/brick; AND a reput to the purged topic in the SAME session would chain from the
              ;; stale tail -> reopen mismatch. Clearing all three (+ the stale mark, since the topic is now
              ;; empty) drops it from the seal and re-seeds a reput from the per-topic head (no false-reject).
              (flet ((do-purge ()
                       (%ms-call conn lock +ms-op-purge+
                                 (lambda () (%ms-encode-topic topic))
                                 (lambda (r)
                                   (%rd-u8 r)
                                   (remhash topic chain-macs)
                                   (remhash topic chain-seqs)
                                   (remhash topic put-index)
                                   (remhash topic stale-topics)
                                   t))))
                ;; chained tier: an exhausted purge MAY have applied server-side but lost the ack (client head
                ;; NOT cleared) -> mark STALE so the next chained mutation re-syncs (Fix 1, ADR 0050 §4.5).
                (if chain-mac-fn
                    (handler-case (do-purge)
                      (microservice-store-error (e) (setf (gethash topic stale-topics) t) (error e)))
                    (do-purge))))
     :open (lambda (history-kind history-depth)
             (%ms-open conn lock history-kind history-depth)
             ;; fail-closed-on-OPEN parity (file/SQLite verify EVERY topic at store-open, before any read):
             ;; with the oracle installed (the decorator installs it BEFORE store-open), get-range-verify
             ;; each topic — a dropped/reordered/tampered chain FAILS THE OPEN loudly. A WHOLE dropped topic
             ;; is now caught EARLIER by the decorator's sealed high-water tail anchor (the :verify-chain-
             ;; prefix-fn seam, run BEFORE this store-open over the client-trusted sealed topic-SET; ADR 0045
             ;; §7.1) — it no longer depends on this server-provided topic list (closes the ADR 0050 §4.3 gap).
             (when chain-mac-fn
               (dolist (tp (%ms-topics-list conn lock))
                 (%ms-get-range-verified conn lock tp chain-mac-fn chain-macs chain-seqs put-index)))
             t)
     :close (lambda () (%ms-close conn lock))
     :count-fn (lambda (topic)
                 (%ms-call conn lock +ms-op-count+
                           (lambda () (%ms-encode-count topic))
                           (lambda (r) (%rd-u64 r))))
     ;; :sync LEFT NIL — memory-tier parity (group-commit sync is a local-store concern).
     ;; :set-chain-mac-fn LIVE (Slice 3b, ADR 0045/0050 §4.3): the decorator installs the log-MAC oracle
     ;; client-side BEFORE it drives store-open, arming the remote-tier chain (compute+fold on put,
     ;; strip+verify on get-range/open). Filling the EXISTING slot — no vtable change. REQUIRED /
     ;; GRANDFATHER are accepted for contract parity but not separately enforced: every chained record is
     ;; folded (≥ suffix bytes), so the strip+verify already fails-closed on any unfolded/tampered record
     ;; (subsuming the downgrade check); there is no legacy-unfolded migration path at this tier.
     :set-chain-mac-fn
     (lambda (fn required grandfather)
       (declare (ignore required grandfather))
       (dds.pal:with-lock (lock)
         (setf chain-mac-fn fn)
         (clrhash chain-macs)
         (clrhash chain-seqs)
         (clrhash put-index)
         (clrhash stale-topics))
       t)
     ;; sealed high-water tail-anchor SEAL seam (ADR 0045 §7.1), CLIENT-SIDE: the sealed tail set is the
     ;; CLIENT's own chained topic-hashes (chain-macs keys), NOT the server's store-topics — so a malicious
     ;; server that later omits a whole topic can NOT shrink the sealed enumeration (this is the microservice
     ;; whole-topic-drop closure — the anchor's topic-SET becomes the trusted enumeration, closing the
     ;; Slice-3b store-microservice.lisp gap). Per client-chained topic-hash: N = its chain_seq-count
     ;; (chain-seqs), M_N = its running tail MAC (chain-macs). No server round-trip — the tail state is
     ;; client-tracked (server DARE-blind). The (N . M_N) shape MATCHES the file/SQLite tiers EXACTLY; a bare
     ;; (no-oracle) store returns an empty set (no anchor, mirrors the local tiers).
     :chain-tails-fn
     (lambda ()
       ;; Fix A (ADR 0050 §4.5): resync-or-skip any STALE topic BEFORE the maphash, so an apply-then-ack-lost
       ;; purge/rewrite + clean-close never seals a diverged (N, M_N) that bricks the next open (runs outside
       ;; the lock — it re-takes it per topic). NON-stale topics are untouched (the maphash below is unchanged).
       (when chain-mac-fn
         (%ms-reseal-stale-topics conn lock chain-mac-fn chain-macs chain-seqs put-index stale-topics))
       (dds.pal:with-lock (lock)
         (let ((result (make-hash-table :test #'equal)))
           (when chain-mac-fn
             (maphash (lambda (topic tail-mac)
                        (let ((n (the (integer 0) (gethash topic chain-seqs 0))))
                          (when (plusp n)
                            (setf (gethash topic result) (cons n tail-mac)))))
                      chain-macs))
           result)))
     ;; sealed high-water tail-anchor VERIFY seam (ADR 0045 §7.1), CLIENT-SIDE: fetch TOPIC's records from the
     ;; server (%ms-fetch-tuples connect-on-demand — the decorator runs this BEFORE store-open connects) and
     ;; re-walk the client chain to ordinal N via the shared read-only %ms-chain-walk, deciding prefix-
     ;; containment BEFORE store-open's own get-range-verify. :reached ⇒ compare running-MAC@N to the sealed
     ;; M_N (== may-extend-forward = CLEAN; != = :diverged rollback/substitution); :clean (ran out below N —
     ;; INCLUDING 0 records = a whole-topic the server omitted) ⇒ :truncated; :mismatch (interior tamper before
     ;; N) ⇒ tolerate T, deferring to store-open's fail-loud %ms-verify-chain (parity with file/SQLite). No
     ;; oracle ⇒ T. RETURN semantics MATCH the file/SQLite tiers EXACTLY.
     :verify-chain-prefix-fn
     (lambda (topic n mac)
       (if (null chain-mac-fn)
           t
           (let ((tuples (%ms-fetch-tuples conn lock topic)))
             (multiple-value-bind (count running reason) (%ms-chain-walk topic chain-mac-fn tuples n)
               (declare (ignore count))
               (cond
                 ((eq reason :reached) (if (equalp running mac) t :diverged))
                 ((eq reason :clean)   :truncated)
                 (t                    t))))))
     ;; chained tier: a KEEP_LAST reclaim's store-delete must RE-MAC the survivors' chain (mirroring the file
     ;; store's %rewrite-topic-log / SQLite's %sqlite-recompute-topic) and REPLACE the server's opaque frames,
     ;; else the survivors' stale folded MACs brick the next open's %ms-verify-chain (ADR 0050 §4.4 —
     ;; RESOLVES the former store-microservice.lisp documented limitation). A BARE store (no oracle) has no
     ;; chain to re-MAC ⇒ the plain server-proxy delete (memory parity, Slice 1 unchanged).
     :delete (lambda (topic writer-guid sn)
               (if (and chain-mac-fn (not *durability-debug-ms-skip-reclaim-remac*))
                   (%ms-delete-rechain conn lock topic writer-guid sn
                                       chain-mac-fn chain-macs chain-seqs put-index stale-topics)
                   (%ms-call conn lock +ms-op-delete+
                             (lambda () (%ms-encode-delete topic writer-guid sn))
                             ;; a reconnect-retry of a delete must TOLERATE +ms-result-rejected+ (ADR 0050 §4.5):
                             ;; the record is already gone, which is the delete's goal — treat rejected as
                             ;; success (T), so an idempotent delete replayed across a drop never false-errors.
                             (lambda (r)
                               (let ((res (%rd-u8 r)))
                                 (cond ((= res +ms-result-t+) t)
                                       ((= res +ms-result-rejected+) t)
                                       (t (error 'microservice-store-error :detail "bad delete result")))))))))))

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

;;; ---- client-side remote-tier chain-MAC (Slice 3b, ADR 0050 §4.3; ADR 0045 log-MAC chain) ----
;;; A malicious/compromised REMOTE server that silently DROPS / REORDERS / TAMPERS sealed frames is
;;; DETECTED (fail-closed on open) — reaching file/SQLite tamper-evidence parity — WITHOUT any server or
;;; protocol change. The encrypted-store decorator installs its log-MAC oracle into THIS client-side store
;;; (store-set-chain-mac-fn); only the 32-byte MAC OUTPUT ever ships. The v3 chain MAC is computed
;;; client-side over the UNWRAPPED sealed frame (the REUSED ADR-0045 %frame-record-versioned) and FOLDED
;;; into the OPAQUE payload — sealed' = sealed ∥ mac(+frame-mac-len+) ∥ chain_seq(u64 LE) — so the DARE-blind
;;; server stores/returns a slightly-longer opaque blob it never parses. get-range STRIPS the suffix
;;; (bounds-checked) + VERIFIES the chain (a near-verbatim port of %sqlite-verify-topic); open verifies
;;; EVERY topic before any read (fail-closed-on-open parity). chain_seq is MANDATORY: the server sorts
;;; get-range by (guid,sn) (%record-guid-sn<) ≠ append/chain order, so the client assigns chain_seq
;;; monotonically per topic-hash on put and re-sorts by it to re-verify (same reason SQLite needs an
;;; explicit chain_seq column). The two former RESIDUALS (ADR 0050 §4.3 / ADR 0045 §7, the SAME as
;;; file/SQLite) are now CLOSED by WP-DURABILITY-TAIL-ANCHOR-MS (ADR 0045 §7.1): the sealed high-water tail
;;; anchor (the :chain-tails-fn / :verify-chain-prefix-fn seam below, CLIENT-SIDE) detects TAIL-TRUNCATION of
;;; a valid prefix AND WHOLE-TOPIC-DROP — the latter because the decorator iterates the sealed topic-SET
;;; (from the CLIENT's logmac.tail), NOT the server's store-topics, so a server omitting a topic still gets a
;;; verify-prefix that fetches 0 records -> :truncated -> fail-closed. The chain engages ONLY under the
;;; encrypted-store (which installs the oracle); a bare microservice-store leaves the oracle uninstalled
;;; (memory-parity, Slice 1 unchanged), and a bare store also seals NO anchor (chain-tails empty).

(defun* %ms-fold-payload (sealed mac chain-seq)
    (function ((simple-array (unsigned-byte 8) (*)) (simple-array (unsigned-byte 8) (*)) (integer 0))
              (simple-array (unsigned-byte 8) (*)))
  "Fold the client-computed v3 chain MAC (+frame-mac-len+ bytes) and CHAIN-SEQ (u64 LE) onto SEALED,
   producing sealed' = sealed ∥ mac ∥ chain_seq — the OPAQUE payload the DARE-blind server stores blindly
   (server + wire protocol UNCHANGED; the MAC/chain_seq ride INSIDE the payload the server never parses)."
  (let* ((sl  (length sealed))
         (out (make-array (+ sl +frame-mac-len+ 8) :element-type '(unsigned-byte 8))))
    (replace out sealed :end1 sl)
    (replace out mac :start1 sl :end1 (+ sl +frame-mac-len+))
    (%put-u64-le out (+ sl +frame-mac-len+) chain-seq)
    out))

(defun* %ms-rechain-survivors (topic fn survivors)
    (function (string function list)
              (values list (or null (simple-array (unsigned-byte 8) (*))) (integer 0)))
  "Re-MAC SURVIVORS (clean DURABLE-RECORDs, payload=sealed, IN chain order) as a FRESH v3 chain for TOPIC —
   the microservice write-side analogue of the file store's %rewrite-topic-log / SQLite's %sqlite-recompute-
   topic (ADR 0045; the no-false-reject-on-reopen invariant). Re-seeds from the per-topic keyed head
   (%chain-seed), re-walks assigning DENSE chain_seq 0..M-1 and recomputing each record's MAC over the
   canonical v3 frame via the REUSED %frame-record-versioned (identical to %ms-chain-walk's per-step
   expected — so the next open's %ms-verify-chain recomputes the SAME macs and reopens clean), and re-folds
   each survivor via %ms-fold-payload. NO new crypto. Returns (values folded-records tail-mac count)."
  (let ((running (%chain-seed fn topic))
        (seq  0)
        (tail nil)
        (out  '()))
    (dolist (rec survivors)
      (let ((mac (nth-value 1 (%frame-record-versioned rec +frame-version-v3+ running fn))))
        (push (make-durable-record :topic topic :writer-guid (durable-record-writer-guid rec)
                                   :sn (durable-record-sn rec) :key-hash (durable-record-key-hash rec)
                                   :kind (durable-record-kind rec)
                                   :payload (%ms-fold-payload (durable-record-payload rec) mac seq))
              out)
        (setf running mac tail mac)
        (incf seq)))
    (values (nreverse out) tail seq)))

(defun* %ms-unfold-payload (folded)
    (function ((simple-array (unsigned-byte 8) (*)))
              (values (simple-array (unsigned-byte 8) (*)) (simple-array (unsigned-byte 8) (*)) (integer 0)))
  "Strip the folded suffix from FOLDED = sealed ∥ mac(+frame-mac-len+) ∥ chain_seq(u64 LE): return
   (values sealed mac chain_seq). BOUNDS-CHECKED (operating contract §4, NFR-SEC-POSTURE): a malicious
   server returning a payload SHORTER than the mac+chain_seq suffix signals MICROSERVICE-PROTOCOL-ERROR (a
   clean fail-closed), never an out-of-bounds access."
  (let ((n (length folded))
        (suffix (+ +frame-mac-len+ 8)))
    (when (< n suffix)
      (error 'microservice-protocol-error
             :detail "folded record payload shorter than the mac+chain_seq suffix (malformed/tampered)"))
    (let* ((sl     (- n suffix))
           (sealed (make-array sl :element-type '(unsigned-byte 8)))
           (mac    (make-array +frame-mac-len+ :element-type '(unsigned-byte 8))))
      (replace sealed folded :end2 sl)
      (replace mac folded :start2 sl :end2 (+ sl +frame-mac-len+))
      (values sealed mac (%get-u64-le folded (+ sl +frame-mac-len+))))))

(defun* %ms-chain-walk (topic fn tuples stop-at)
    (function (string function list (or null (integer 0)))
              (values (integer 0) (simple-array (unsigned-byte 8) (*)) (member :reached :clean :mismatch)))
  "READ-ONLY walk of TOPIC's client-side v3 chain over TUPLES (each (clean-record stored-mac chain_seq)) in
   chain_seq order under oracle FN — the shared engine of BOTH the open-time verifier (%ms-verify-chain) AND
   the sealed high-water tail-anchor VERIFY seam (store-verify-chain-prefix), the microservice analogue of
   the file/SQLite %chain-walk / %sqlite-chain-walk (ADR 0045 §7.1). Seeds from the per-topic keyed head
   (%chain-seed), recomputes each record's expected MAC over the canonical v3 frame via the REUSED
   %frame-record-versioned, and equalp-compares to the stored (folded) mac. NEVER signals — RETURNS a reason
   so each caller applies its own policy (open-verify fails loud; the tail seam maps :clean→:truncated).
   Every folded record carries a mac (there are no unchained rows, UNLIKE SQLite's NULL-mac legacy prefix),
   so a break can only be a :mismatch. Returns (values chained running reason):
     STOP-AT non-NIL and reached ⇒ :reached, RUNNING = the running chain MAC after exactly STOP-AT records
       (the prefix-containment probe; records past STOP-AT are ignored);
     else runs to the natural end — :clean (chained < STOP-AT if any) or :mismatch (a stored mac ≠ recomputed)."
  (let ((sorted  (sort (copy-list tuples) #'< :key #'third))
        (running (%chain-seed fn topic))
        (chained 0))
    (dolist (tp sorted)
      (when (and stop-at (>= chained stop-at))
        (return-from %ms-chain-walk (values chained running :reached)))
      (destructuring-bind (rec stored cseq) tp
        (declare (ignore cseq))
        (let ((expected (nth-value 1 (%frame-record-versioned rec +frame-version-v3+ running fn))))
          (unless (equalp expected stored)
            (return-from %ms-chain-walk (values chained running :mismatch)))
          (setf running expected)
          (incf chained))))
    (if (and stop-at (>= chained stop-at))
        (values chained running :reached)
        (values chained running :clean))))

(defun* %ms-verify-chain (topic fn tuples chain-macs chain-seqs put-index)
    (function (string function list hash-table hash-table hash-table) t)
  "Verify TUPLES (each (clean-record stored-mac chain_seq)) as TOPIC's v3 chain in chain_seq order via the
   shared read-only %ms-chain-walk (DRY — the SAME engine the tail-anchor prefix seam uses, so their counting
   + MAC computation cannot drift) and apply the fail-closed open policy: a :mismatch (an interior DROP /
   REORDER / TAMPER that breaks the running MAC) SIGNALS (fail-closed, = file/SQLite parity). On success seeds
   chain-macs[TOPIC]=tail-mac + chain-seqs[TOPIC]=max chain_seq + 1 (so a continued put chains correctly across
   a reopen) and rebuilds put-index[TOPIC] from the server's authoritative (guid,sn) keys (the microservice
   analogue of the file store rebuilding its in-memory index on replay — needed for idempotent re-put detection)."
  (multiple-value-bind (chained running reason) (%ms-chain-walk topic fn tuples nil)
    (when (eq reason :mismatch)
      (error "dds.durability: microservice chain MAC mismatch in topic ~a — a remote server ~
              dropped/reordered/tampered a sealed frame (refusing to open; ADR 0045/0050 §4.3)" topic))
    (let ((idx    (make-hash-table :test #'equal))
          (maxseq -1))
      (dolist (tp tuples)
        (destructuring-bind (rec stored cseq) tp
          (declare (ignore stored))
          (when (> cseq maxseq) (setf maxseq cseq))
          (setf (gethash (cons (coerce (durable-record-writer-guid rec) 'list)
                               (durable-record-sn rec)) idx) t)))
      (setf (gethash topic put-index) idx)
      (when (plusp chained)
        (setf (gethash topic chain-macs) running)
        (setf (gethash topic chain-seqs) (1+ maxseq)))
      t)))

(defun* %ms-decode-tuples (r topic)
    (function (ms-reader string) list)
  "Decode a get-range response into a list of (clean-record folded-mac chain_seq) tuples — the raw,
   UNVERIFIED input BOTH %ms-decode-strip-verify (open-time full verify) AND the tail-anchor prefix probe
   (%ms-fetch-tuples) consume (DRY). STRIPS the folded (mac ∥ chain_seq) suffix from each record's payload
   (bounds-checked via %ms-unfold-payload — a <suffix-length payload from a malicious server fails cleanly).
   No chain verify + no side effects here — the caller runs %ms-verify-chain / %ms-chain-walk. COUNT is
   bounded against the remaining buffer (each frame needs ≥ 1 byte); each %rd-frame is itself bounds-checked."
  (let ((count (%rd-u32 r)))
    (when (> count (- (ms-reader-end r) (ms-reader-pos r)))
      (error 'microservice-protocol-error :detail "record count exceeds buffer extent"))
    (let ((tuples '()))
      (dotimes (i count)
        (let ((raw (%rd-frame r topic)))
          (multiple-value-bind (sealed mac cseq) (%ms-unfold-payload (durable-record-payload raw))
            (push (list (make-durable-record :topic topic :writer-guid (durable-record-writer-guid raw)
                                             :sn (durable-record-sn raw) :key-hash (durable-record-key-hash raw)
                                             :kind (durable-record-kind raw) :payload sealed)
                        mac cseq)
                  tuples))))
      tuples)))

(defun* %ms-decode-strip-verify (r topic fn chain-macs chain-seqs put-index)
    (function (ms-reader string function hash-table hash-table hash-table) list)
  "Decode a get-range response (via the shared %ms-decode-tuples), VERIFY the per-topic v3 chain
   (fail-closed), and return the CLEAN (payload=sealed) records (guid,sn)-sorted so the decorator sees only
   sealed — the mac stripped transparently."
  (let ((tuples (%ms-decode-tuples r topic)))
    (%ms-verify-chain topic fn tuples chain-macs chain-seqs put-index)
    (sort (mapcar #'first tuples) #'%record-guid-sn<)))

(defun* %ms-topics-list (conn lock)
    (function (ms-conn t) list)
  "The server's non-empty topic list (the shared body of the :topics slot + the open verify pass)."
  (%ms-call conn lock +ms-op-topics+ (lambda () (%ms-empty-payload)) (lambda (r) (%ms-decode-topics r))))

(defun* %ms-get-range-verified (conn lock topic fn chain-macs chain-seqs put-index)
    (function (ms-conn t string function hash-table hash-table hash-table) list)
  "Chained store-get-range: fetch TOPIC's records over the connection, strip the folded mac/chain_seq, and
   VERIFY the v3 chain (fail-closed), returning the clean (guid,sn)-ordered records. The shared body of the
   chained :get-range slot + the open verify pass (DRY)."
  (%ms-call conn lock +ms-op-get-range+
            (lambda () (%ms-encode-topic topic))
            (lambda (r) (%ms-decode-strip-verify r topic fn chain-macs chain-seqs put-index))))

(defun* %ms-resync-topic (conn lock topic fn chain-macs chain-seqs put-index)
    (function (ms-conn t string function hash-table hash-table hash-table) t)
  "Rebuild TOPIC's client chain state from the server's ACTUAL records after an exhausted chain-mutating op
   left it possibly-stale (Fix 1, ADR 0050 §4.5): get-range, then CLEAR TOPIC's (possibly stale) chain head
   and REBUILD via %ms-verify-chain — so the empty/purged case stays CLEARED (a bare %ms-get-range-verified
   would LEAVE a purged topic's stale head, since %ms-verify-chain only overwrites on a non-empty result;
   the pre-clear is what makes a purge-exhaust safe). Re-learns whether the exhausted op was applied (server
   has the record -> chain-seqs advances; server empty -> stays cleared). Read-only on the server; fails
   CLOSED on a genuine server tamper (%ms-verify-chain :mismatch). Clear+verify run in ONE decode-fn under
   the store lock (atomic). NOT the common-path verify — only reached for a topic a prior op left stale."
  (%ms-call conn lock +ms-op-get-range+
            (lambda () (%ms-encode-topic topic))
            (lambda (r)
              (let ((tuples (%ms-decode-tuples r topic)))
                (remhash topic chain-macs)
                (remhash topic chain-seqs)
                (remhash topic put-index)
                (%ms-verify-chain topic fn tuples chain-macs chain-seqs put-index)
                t))))

(defun* %ms-resync-if-stale (conn lock topic fn chain-macs chain-seqs put-index stale-topics)
    (function (ms-conn t string function hash-table hash-table hash-table hash-table) t)
  "If TOPIC was marked STALE by a prior EXHAUSTED chain-mutating op (Fix 1, ADR 0050 §4.5), FORCE-re-sync the
   client chain state from the server (%ms-resync-topic) BEFORE the next chained mutation, so the mutation
   chains from ground truth (no fork -> no later-open false-reject brick). Clears the stale mark ONLY on a
   successful re-sync; a re-sync that cannot reach the server SIGNALS (the mutation aborts, TOPIC stays stale
   for the next attempt when the server is back). The *durability-debug-ms-skip-stale-resync* RED knob makes
   this a no-op (reproducing the fork). No-op (fast hash miss) for the common case where TOPIC is not stale."
  (when (and (gethash topic stale-topics) (not *durability-debug-ms-skip-stale-resync*))
    (%ms-resync-topic conn lock topic fn chain-macs chain-seqs put-index)
    (remhash topic stale-topics))
  t)

(defun* %ms-reseal-stale-topics (conn lock fn chain-macs chain-seqs put-index stale-topics)
    (function (ms-conn t function hash-table hash-table hash-table hash-table) t)
  "Before the sealed tail anchor is committed at CLEAN close (store-chain-tails), RESYNC every STALE topic from
   the server so NO stale/diverged (N, M_N) is ever sealed (Fix A, ADR 0050 §4.5). An apply-then-ack-lost PURGE
   / TOPIC-REWRITE (whose decode-fn never ran) leaves the client tail state stale, and sealing it would BRICK
   the next open's tail-anchor prefix-verify over HONEST data (:truncated for a purge -> 0 server records;
   :truncated/:diverged for a rewrite -> the server shrank below the sealed N). A clean close means the server
   is reachable, so %ms-resync-topic re-learns the true state: a purged topic clears its head (-> not sealed);
   a rewritten topic seals the correct shrunk (M, M'). If a topic cannot be resync'd (server unreachable, or a
   genuine tamper -> %ms-verify-chain :mismatch), it is SKIPPED from the seal (its head is dropped) — no
   diverged value is committed (no false-reject), and the narrow protection gap heals at the topic's next
   successful mutation + re-seal (a genuine tamper is still caught by store-open's own %ms-verify-chain over
   the server topic list). Runs OUTSIDE the store lock (resync re-takes it per topic); NON-stale topics are
   untouched (store-chain-tails stays byte-identical for them). Respects the skip-stale-resync RED knob."
  (unless *durability-debug-ms-skip-stale-resync*
    (let ((stale (dds.pal:with-lock (lock)
                   (let ((ts '()))
                     (maphash (lambda (k v) (declare (ignore v)) (push k ts)) stale-topics)
                     ts))))
      (dolist (topic stale)
        (handler-case
            (progn (%ms-resync-topic conn lock topic fn chain-macs chain-seqs put-index)
                   (dds.pal:with-lock (lock) (remhash topic stale-topics)))
          (error ()
            (dds.pal:with-lock (lock)
              (remhash topic chain-macs)
              (remhash topic chain-seqs)
              (remhash topic put-index)
              (remhash topic stale-topics)))))))
  t)

(defun* %ms-fetch-tuples (conn lock topic)
    (function (ms-conn t string) list)
  "Fetch TOPIC's records from the server and decode them to raw (clean-record folded-mac chain_seq) tuples
   for the tail-anchor's READ-ONLY prefix probe (store-verify-chain-prefix) — WITHOUT verifying (no side
   effects on chain-macs/chain-seqs/put-index) and WITHOUT signalling on a mismatch (the caller's
   %ms-chain-walk maps that to a reason). CONNECT-ON-DEMAND: the decorator runs %verify-tail-anchor BEFORE
   store-open establishes the connection, so ensure it here (the server owns the inner lifecycle — a
   get-range needs no prior client open op); the dial coordinates ride in CONN. A malicious server's
   records are network-facing, so %ms-unfold-payload's bounds-check + %rd-frame's guards apply (a
   short/torn payload fails clean as MICROSERVICE-STORE-ERROR, never OOB)."
  (dds.pal:with-lock (lock)
    (%ms-ensure-connected conn))
  (%ms-call conn lock +ms-op-get-range+
            (lambda () (%ms-encode-topic topic))
            (lambda (r) (%ms-decode-tuples r topic))))

(defun* %ms-delete-rechain (conn lock topic writer-guid sn fn chain-macs chain-seqs put-index stale-topics)
    (function (ms-conn t string (simple-array (unsigned-byte 8) (16)) (integer 0)
               function hash-table hash-table hash-table hash-table) (eql t))
  "Chained store-delete = the microservice analogue of SQLite's :delete = DELETE + %sqlite-recompute-topic
   (ADR 0050 §4.4). A KEEP_LAST reclaim removed (WRITER-GUID, SN) from TOPIC; the survivors' stored folded
   MACs are now stale (they chained over the deleted predecessor). FETCH the topic's current folded records
   (get-range over the wire), DROP the deleted (guid,sn), RE-CHAIN the survivors in chain_seq order via
   %ms-rechain-survivors (re-seed + dense chain_seq 0..M-1 + running MAC — mirroring file/SQLite EXACTLY, so
   the next open's %ms-verify-chain recomputes the SAME macs and reopens CLEAN), REPLACE the server's opaque
   frames with the re-folded survivors in ONE atomic +ms-op-topic-rewrite+, and UPDATE the client chain state
   (chain-macs/chain-seqs/put-index) to the re-chained state so a continued put, the sealed tail anchor, and
   the next open all see the fresh chain. Serialized by the DECORATOR's lock (store-delete is called under it,
   from %evict-prior-surrogates), so the fetch+rewrite two-step needs no cross-op atomicity here; the client
   state mutation runs UNDER the store lock (the rewrite %ms-call decode-fn). The server stays DARE-BLIND —
   it replaces OPAQUE frames and never parses the mac/chain_seq. Returns T (store-delete contract)."
  (let* ((tuples    (%ms-fetch-tuples conn lock topic))
         (survivors (mapcar #'first
                            (remove-if (lambda (tp)
                                         (let ((rec (first tp)))
                                           (and (equalp (durable-record-writer-guid rec) writer-guid)
                                                (= (durable-record-sn rec) sn))))
                                       (sort (copy-list tuples) #'< :key #'third)))))
    (multiple-value-bind (folded tail count) (%ms-rechain-survivors topic fn survivors)
      ;; the fetch+rechain re-derived from the server's ACTUAL frames, so the rewrite self-syncs TOPIC (no
      ;; resync-before needed); an EXHAUSTED rewrite MAY have applied but lost the ack -> mark STALE (Fix 1).
      (handler-case
      (%ms-call conn lock +ms-op-topic-rewrite+
                (lambda () (%ms-encode-topic-rewrite topic folded))
                (lambda (r)
                  (let ((res (%rd-u8 r)))
                    (unless (= res +ms-result-t+)
                      (error 'microservice-store-error :detail "bad topic-rewrite result"))
                    ;; the server confirmed the replace: advance the client chain to the dense survivor state
                    (if (plusp count)
                        (progn (setf (gethash topic chain-macs) tail)
                               (setf (gethash topic chain-seqs) count))
                        (progn (remhash topic chain-macs)
                               (remhash topic chain-seqs)))
                    (let ((idx (make-hash-table :test #'equal)))
                      (dolist (rec survivors)
                        (setf (gethash (cons (coerce (durable-record-writer-guid rec) 'list)
                                             (durable-record-sn rec)) idx) t))
                      (setf (gethash topic put-index) idx))
                    (remhash topic stale-topics)   ; the rewrite synced TOPIC from server truth -> clear stale
                    t)))
        (microservice-store-error (e) (setf (gethash topic stale-topics) t) (error e))))))

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
       ;; POLICY-CONFIRM / no-op (ADR 0050 Slice 3a): the SERVER owns the inner, opened ONCE at
       ;; server-start; a per-client store-open must NOT re-open/re-replay the shared persistent inner
       ;; (a second store-open on a file/SQLite inner re-replays the whole log per client session —
       ;; wasteful, and leaks/rebuilds the inner's streams; the server-owned tier's history policy is
       ;; set once at server-start, not per client). Still DECODE hk-code + depth so the payload is
       ;; bounds-validated (a malformed open drops the connection) — then just acknowledge.
       (%rd-u8 r)                       ; hk-code — decoded to bounds-validate, not applied (server owns policy)
       (%rd-u32 r)                      ; depth
       (%ms-put-u8 out +ms-result-t+))
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
      ((= code +ms-op-topic-rewrite+)
       ;; atomically REPLACE the topic's records with the supplied OPAQUE frames (the client's KEEP_LAST
       ;; re-MAC'd survivors, ADR 0050 §4.4). DARE-BLIND: %rd-frame decodes each frame to a record whose
       ;; payload is the folded blob (mac/chain_seq ride inside, never parsed here); store-replace-topic
       ;; swaps them all-or-nothing (memory: in-process serial; file/SQLite: tmp+rename / transaction).
       ;; COUNT is bounded against the remaining buffer (each frame needs >= 1 byte, mirroring
       ;; %ms-decode-records); each %rd-frame is itself bounds-checked (network-facing, no OOB).
       (let* ((topic (%rd-string r))
              (count (%rd-u32 r)))
         (when (> count (- (ms-reader-end r) (ms-reader-pos r)))
           (error 'microservice-protocol-error :detail "rewrite record count exceeds buffer extent"))
         (let ((recs '()))
           (dotimes (i count) (push (%rd-frame r topic) recs))
           (store-replace-topic inner topic (nreverse recs))
           (%ms-put-u8 out +ms-result-t+))))
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

(defun* make-microservice-server (&key (host "127.0.0.1") (port 0) (inner (make-memory-store))
                                       history-kind history-depth)
    (function (&key (:host string) (:port (integer 0 65535)) (:inner durable-store)
                    (:history-kind (or null (member :keep-all :keep-last)))
                    (:history-depth (or null (integer 1))))
              microservice-server)
  "Start a reference microservice server (ADR 0050) that proxies the durable-store vtable over TCP to
   the INNER store (memory default; a persistent make-file-store / make-sqlite-store is the Slice-3a
   persistence tier). Binds HOST:PORT (port 0 = ephemeral — read the assigned port with
   microservice-server-port) and spawns one accept/serve thread. The server is a DUMB opaque proxy: it
   decodes each request, dispatches to INNER, and encodes the reply, with ZERO DARE/MAC knowledge. One
   client at a time (inline per-connection serving) is sufficient (multi-client is Slice 3c).

   SERVER-OWNED INNER LIFECYCLE (ADR 0050 Slice 3a): the server OWNS the inner's lifecycle, correct for a
   persistence tier that OUTLIVES individual client sessions. The inner is opened ONCE here at
   server-start — a persistent file/SQLite inner REPLAYS from disk (recovers prior history across a
   restart), a memory inner opens empty — with the server's configured HISTORY-KIND / HISTORY-DEPTH (NIL
   = defer to the inner's factory default). It is closed ONCE at microservice-server-stop (store-close ->
   fsync). A client's store-open is then a POLICY-CONFIRM no-op (it does NOT re-open/re-replay the shared
   inner, see %ms-handle-request +ms-op-open); a client's store-close ends only that client SESSION (it
   does NOT close the inner). So multiple client sessions against one server see the SAME persisted store,
   and the inner survives every client connect/disconnect until the server stops. Stop it with
   microservice-server-stop (clean thread join + socket close + inner close, no leak)."
  (let* ((listener (dds.pal:tcp-listen host port))
         (bound (dds.pal:tcp-local-port listener))
         (stop-cell (list nil))
         (conn-cell (list nil))
         (srv (%make-microservice-server :inner inner :listener listener :port bound :host host
                                         :stop-cell stop-cell :conn-cell conn-cell
                                         :lock (dds.pal:make-lock "dds-durability-microservice-server"))))
    ;; server-owned lifecycle: open the inner ONCE (persistent inner replays from disk) BEFORE the serve
    ;; thread accepts, so the inner is ready for the first client; a failed open closes the listener.
    (handler-case (store-open inner history-kind history-depth)
      (error (e) (ignore-errors (dds.pal:tcp-close listener)) (error e)))
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
   topic/GUID/SN/key-hash/payload or any key. The cross-frame keyed chain-MAC (ADR 0045) IS PRESENT at the
   microservice tier (Slice 3b): the encrypted-store installs its HMAC oracle into the CLIENT-SIDE
   microservice-store (only the 32-byte MAC output ships, never the oracle/key), each put computes the v3
   MAC client-side and folds mac ∥ chain_seq into the opaque payload, and store-open re-verifies every
   topic's chain FAIL-CLOSED — DETECTING a malicious remote server's frame DROP / REORDER / TAMPER
   (file/SQLite tamper-evidence parity). The former tail-truncation + whole-topic-drop residuals are now
   CLOSED (WP-DURABILITY-TAIL-ANCHOR-MS, ADR 0045 §7.1): make-microservice-store fills the sealed high-water
   tail-anchor seam CLIENT-SIDE, so the decorator seals logmac.tail (in the LOCAL epoch-dir) on close and
   verifies it on open over the CLIENT-TRUSTED sealed topic-SET — a server that truncates a tail or omits a
   whole topic fails-closed. Per-record DARE-GCM additionally authenticates each frame. A pre-Slice-3b
   microservice store (un-folded records) has NO legacy migration path — the fold is unversioned, so a
   3b reopen would strip 40 real bytes and false-reject; re-create the store under 3b (the backend is new).
   HISTORY-POLICY OWNERSHIP — the DECORATOR owns retention; server-side HISTORY-QoS is DESCOPED (ADR 0050
   §4.2/§7). Unlike the sqlite/file siblings the inner tier's HISTORY policy is NOT a construction argument
   here, and it is deliberately NOT forwarded over the wire: under the always-on DARE production composition
   the ENCRYPTED-STORE DECORATOR owns retention end-to-end. It always opens the inner KEEP_ALL (it cannot
   order/interpret the hashed surrogates), LOGICALLY compacts newest-D on get-range (%compact-topic-records)
   and PHYSICALLY reclaims a keyed KEEP_LAST put's superseded surrogate (%evict-prior-surrogates -> the §4.4
   chained store-delete -> +ms-op-topic-rewrite+ survivor re-MAC) — delivered + tested KEEP_LAST-through-
   microservice (run-durability-microservice-keep-last-reclaim-test: newest-D + physical-1 + cross-restart).
   The server MUST therefore stay KEEP_ALL: server-side HISTORY-QoS is INERT under DARE (the decorator puts
   key-hash NIL, so the inner's per-instance KEEP_LAST never triggers) AND WRONG (a server eviction of a
   chained record would brick the client's %ms-verify-chain :mismatch). Matching the server to a KEEP_LAST
   QoS is not merely unnecessary, it is AGAINST the decorator's model; HISTORY-QoS-over-the-wire forwarding
   is NOT required and is DESCOPED. (The bare non-DARE microservice path — no decorator — is not a
   production composition.) HOST defaults to
   127.0.0.1; PORT is the server's port. :PROCESS service mode does NOT carry this factory across the
   subprocess boundary — use :THREAD mode. The returned store requires STORE-OPEN before reads/writes and
   STORE-CLOSE (frees the DEK map + ends the client session); STORE-CLOSE is mandatory."
  (let ((h  host)
        (p  port)
        (ed (uiop:ensure-directory-pathname epoch-dir))
        (kd (uiop:ensure-directory-pathname key-dir)))
    (lambda ()
      (make-encrypted-store (make-microservice-store :host h :port p)
                            (dds.dare:make-file-key-provider :dir kd)
                            :epoch-dir ed))))
