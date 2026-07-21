;;;; L5/L6 bridge — user data plane over UDP (FR-RTPS-*, FR-DDS-*). Wires the
;;;; value-level reliable writer/reader state machines (dds.rtps.reliable) to the
;;;; UDP transport: a publisher serializes a sample into a DATA submessage and
;;;; sends it plus a HEARTBEAT to its peers; the subscriber stores the DATA and
;;;; answers the HEARTBEAT with an ACKNACK; the publisher retransmits any NACKed
;;;; change. For v1 the user/metatraffic share one socket (routing is by
;;;; EntityId), peers double as the data destination, and the SerializedPayload is
;;;; opaque bytes (a generated-type codec is the follow-up). The reliable handshake
;;;; runs in the receiver thread, so its sends use the node's separate rx-tx-msg
;;;; buffer (publish runs on the caller thread and uses tx-msg) — no shared buffer
;;;; across threads. This file is NOT a measured hot path (per-sample heap copies
;;;; here are a documented v1 concern; the gated hot-path files are untouched).

(in-package #:dds.disc)

;; User-defined EntityIds: entityKey[3] << 8 | entityKind (RTPS 2.5 §9.3.1.2).
;; ShapeType is keyed (color), so the endpoints are WITH-KEY kinds (0x02 / 0x07) —
;; a no-key writer on a keyed topic is what RTI is fed otherwise.
(defconstant +user-writer-id+ #x00000102)   ; key 000001, kind 02 (user writer WITH key)
(defconstant +user-reader-id+ #x00000107)   ; key 000001, kind 07 (user reader WITH key)
;; These MUST equal the EntityIds that add-local-writer/add-local-reader announce via
;; SEDP (key 1, kinds 0x02/0x07): a peer matches the announced endpoint and routes its
;; HEARTBEAT/ACKNACK by that EntityId, so the data-plane endpoint must carry the same id.

(defparameter *datagram-sink* nil
  "Test/bench affordance (default NIL = off): when bound to a function, %SEND-RAW-BUF calls it with a
   fresh octet-vector copy of each outgoing datagram (buf[0..LEN]) BEFORE sending — so a test can
   capture and re-parse coalesced datagrams (count submessages, assert ≤ budget). The real send still
   happens. The copy is allocated only while the sink is bound, so there is no production cost. Never
   set in production.")

(define-condition sender-emit-test-fault (error) ()
  (:report (lambda (c s) (declare (ignore c)) (format s "synthetic sender-thread emit fault (test only)")))
  (:documentation "Test-only synthetic ERROR injected by *DEBUG-EMIT-FAULT* to exercise the sender-thread emit
   guards (WITH-SENDER-EMIT-GUARD). Never signalled in production (*DEBUG-EMIT-FAULT* defaults NIL)."))

(defparameter *debug-emit-fault* nil
  "Test affordance (inert when NIL): a positive integer N signals SENDER-EMIT-TEST-FAULT on the next N
   %SEND-RAW-BUF calls (decrementing toward NIL, single-driver only — the decrement is non-atomic, fine for a
   single sender thread under test); :PERSISTENT signals on EVERY call (the no-spin test). Production default
   NIL = byte-identical wire, zero effect. Mirrors *DEBUG-DROP-SAMPLE-NUMBERS*. Never set in production.")

(defun* %power-of-ten-p (n)
    (function ((integer 1)) t)
  "T iff N is a positive power of ten (1, 10, 100, …): divide out 10s, accept iff the residue is 1."
  (loop for x of-type (integer 1) = n then (truncate x 10)
        when (= x 1) return t
        when (plusp (mod x 10)) return nil))

(defun* %default-sender-emit-error-hook (condition context count)
    (function (condition t (integer 1)) t)
  "Default *SENDER-EMIT-ERROR-HOOK*: a clockless rate-limited WARN to *ERROR-OUTPUT* — log only when COUNT is
   a power of ten (1, 10, 100, …) so a persistent emit failure logs O(log n) lines, never a per-iteration
   flood (no logging framework exists; this is the minimal observable default). Runs ON the sender thread."
  (when (%power-of-ten-p count)
    (warn "dds sender thread (~a) emit error #~d: ~a" context count condition))   ; NOCOND(WARN): rate-limited diagnostic hook; prints + returns, no control transfer
  t)

(defparameter *sender-emit-error-hook* #'%default-sender-emit-error-hook
  "Funcallable (CONDITION CONTEXT COUNT) invoked when a sender thread's emit signals an ERROR that
   WITH-SENDER-EMIT-GUARD caught. CONTEXT is a keyword tagging the thread (:ASYNC-SENDER / :FLOW-SCHEDULER);
   COUNT is that thread's running error count (>= 1). Runs ON the sender thread, so it MUST NOT block; a
   signalling hook is itself swallowed (IGNORE-ERRORS in the guard) so the thread is never re-killed by the
   hook. Bind it to observe sender-thread emit errors. Default = %DEFAULT-SENDER-EMIT-ERROR-HOOK.")

(defmacro with-sender-emit-guard ((context count-place) &body body)
  "Run BODY (one sender-thread emit). On a caught ERROR — NOT a SERIOUS-CONDITION (a fatal VM state such as
   storage-condition/control-stack-exhausted SHOULD still terminate the thread; masking it would hide an
   unrecoverable condition) — INCF COUNT-PLACE, fire *SENDER-EMIT-ERROR-HOOK* (itself IGNORE-ERRORS-guarded so
   a signalling hook cannot re-kill the thread), and return NIL; on success return BODY's value. CONTEXT is a
   keyword tagging the thread. The thread never dies from one bad emit (RTPS 2.5 §8.4: a dropped reliable DATA
   is recovered via the HEARTBEAT/ACKNACK repair path; a best-effort drop is conformant). A macro (no per-emit
   closure) → 0-alloc; the sender threads are off the measured CDR hot path regardless."
  (let ((c (gensym "C")))
    `(handler-case (progn ,@body)
       (error (,c)
         (let ((n (incf ,count-place)))
           (ignore-errors (funcall *sender-emit-error-hook* ,c ,context n)))
         nil))))

(defun* %note-shmem-send-fault (node condition)
    (function (disc-node condition) fixnum)
  "WP-SHMEM-SEND-SELF-GUARD: a hard %shmem-send fault was caught in %send-raw-buf and the datagram is falling
   back to UDP — bump the node's SHMEM-SEND-FAULTS counter and fire *SENDER-EMIT-ERROR-HOOK* (context
   :shmem-send-fault), the hook call IGNORE-ERRORS-guarded so a signalling hook can't break the send."
  (let ((n (incf (disc-node-shmem-send-faults node))))
    (ignore-errors (funcall *sender-emit-error-hook* condition :shmem-send-fault n))
    n))

(defun* %ensure-send-scratch-pool (node)
    (function (disc-node) t)
  "Return NODE's SRTPS send-scratch pool, carving it (arena + fixed pool of datagram-sized static buffers) lazily
   on the first %maybe-wrap-srtps and returning it thereafter (WP-DDS-SECURITY-ZEROALLOC-AEAD T3). element-bytes =
   +srtps-scratch-datagram-bytes+ + +srtps-scratch-overhead+ (a wrapped datagram + the SRTPS bracket); capacity =
   *srtps-send-scratch-capacity* (concurrent wrapping sender threads + headroom). Carved OFF the steady state (first
   secured send only) under SEND-SCRATCH-LOCK, double-checked so it happens exactly once across the sender threads;
   the symmetric RX decode pool carve (%ensure-secure-rx-pool) uses its own dedicated SECURE-RX-LOCK. On arena/static-alloc failure returns
   NIL — %maybe-wrap-srtps then falls back to the allocating encode-rtps-message (correct, byte-identical wire),
   never a per-datagram GC on the pooled path. The arena is stored only after the pool carve succeeds (teardown
   reachability); stop-node tears it down. NIL until the first wrap -> a node with rtps_protection off reserves no
   static memory (zero-cost when off), consistent with the other per-node security pools (T5a/T5b, all lazy)."
  (or (disc-node-send-scratch-pool node)
      (dds.pal:with-lock ((disc-node-send-scratch-lock node))
        (or (disc-node-send-scratch-pool node)
            (handler-case
                (let* ((eb    (+ (srtps-scratch-datagram-bytes) +srtps-scratch-overhead+))
                       (cap   *srtps-send-scratch-capacity*)
                       (arena (dds.core.arena:init-arena :bytes (* eb (1+ cap))))   ; +1 slot slack
                       (pool  (dds.core.arena:make-buffer-pool arena eb cap)))
                  ;; ADR 0064: an exhausted arena is a STATUS now, not a condition — so it MUST be TESTED.
                  ;; An unchecked NIL pool would still run the SETF below, storing the ARENA whose own
                  ;; comment says 'only after the carve succeeds' — orphaning its static allocation on
                  ;; every failed carve.
                  (when (null pool) (dds.core.arena:teardown-arena arena) (return-from %ensure-send-scratch-pool nil))
                  (setf (disc-node-send-scratch-arena node) arena   ; store the arena only after the carve succeeds (teardown reachability)
                        (disc-node-send-scratch-pool node) pool))   ; set the pool LAST — the double-checked-carve flag
              (error () nil))))))   ; arena-exhausted / static-alloc failure -> leave NIL -> allocating fallback

(defmacro %with-send-scratch ((var node) &body body)
  "Borrow a datagram-sized scratch octet-buffer from NODE's send-scratch pool (the send twin of %with-secure-rx-scratch;
   both expand to the shared %with-scratch borrow over their pool + dedicated lock), bind it to VAR, run BODY, and
   RELEASE it (always, even on non-local exit) — WP-DDS-SECURITY-ZEROALLOC-AEAD T3. Evaluates to BODY's value, or NIL
   when the pool is not carved / EXHAUSTED: %maybe-wrap-srtps treats NIL as the fail-closed required-but-failed drop
   (RESOURCE_LIMITS backpressure; never a GC fallback, NFR-MEM). Acquire + release are O(1) index ops under
   SEND-SCRATCH-LOCK so concurrent sender threads never corrupt the pool; BODY (the AEAD bracket build) runs OUTSIDE
   the lock. Assumes the pool is already carved (the caller ensures it first)."
  (let ((n (gensym "NODE")))
    `(let ((,n ,node))
       (%with-scratch (,var (disc-node-send-scratch-pool ,n) (disc-node-send-scratch-lock ,n))
         ,@body))))

(defun* %ensure-submsg-scratch-pool (node)
    (function (disc-node) t)
  "Return NODE's metadata_protection SUBMESSAGE-scratch pool, carving it (arena + fixed pool of static buffers) lazily on
   the first %maybe-wrap-user-submessages and returning it thereafter (WP-DDS-SECURITY-ZEROALLOC-AEAD T4). element-bytes =
   +srtps-scratch-datagram-bytes+ + +submsg-scratch-overhead+ (a datagram + the per-submessage bracket expansion headroom,
   ~10240); capacity = *srtps-send-scratch-capacity* (the concurrent wrapping sender threads + headroom — the submessage
   wrap runs on the SAME sender threads as the SRTPS wrap and RELEASES its borrow before the SRTPS wrap acquires, so peak
   concurrent submsg borrows = the sender-thread count). A DEDICATED pool (its own SUBMSG-SCRATCH-LOCK, so its ops never
   contend with the send / RX pool ops), so the SRTPS send-scratch pool keeps its efficient 2104-octet buffers. Carved OFF
   the steady state (first metadata_protection send only) under SUBMSG-SCRATCH-LOCK, double-checked so it happens exactly
   once across the sender threads. On arena/static-alloc failure returns NIL — %maybe-wrap-user-submessages then falls back
   to the allocating make-octet-buffer path (correct, byte-identical wire), never a per-datagram GC on the pooled path. The
   arena is stored only after the pool carve succeeds (teardown reachability); stop-node tears it down. NIL until the first
   wrap -> a node with metadata_protection off reserves no static memory (zero-cost when off), consistent with the other
   per-node security pools (all lazy)."
  (or (disc-node-submsg-scratch-pool node)
      (dds.pal:with-lock ((disc-node-submsg-scratch-lock node))
        (or (disc-node-submsg-scratch-pool node)
            (handler-case
                (let* ((eb    (+ (srtps-scratch-datagram-bytes) +submsg-scratch-overhead+))
                       (cap   *srtps-send-scratch-capacity*)
                       (arena (dds.core.arena:init-arena :bytes (* eb (1+ cap))))   ; +1 slot slack
                       (pool  (dds.core.arena:make-buffer-pool arena eb cap)))
                  ;; ADR 0064: an exhausted arena is a STATUS now, not a condition — so it MUST be TESTED.
                  ;; An unchecked NIL pool would still run the SETF below, storing the ARENA whose own
                  ;; comment says 'only after the carve succeeds' — orphaning its static allocation on
                  ;; every failed carve.
                  (when (null pool) (dds.core.arena:teardown-arena arena) (return-from %ensure-submsg-scratch-pool nil))
                  (setf (disc-node-submsg-scratch-arena node) arena   ; store the arena only after the carve succeeds (teardown reachability)
                        (disc-node-submsg-scratch-pool node) pool))   ; set the pool LAST — the double-checked-carve flag
              (error () nil))))))   ; arena-exhausted / static-alloc failure -> leave NIL -> allocating fallback

(defmacro %with-submsg-scratch ((var node) &body body)
  "Borrow one metadata_protection submessage-scratch octet-buffer from NODE's submsg-scratch pool (the metadata_protection
   twin of %with-send-scratch; both expand to the shared %with-scratch borrow over their pool + dedicated lock), bind it to
   VAR, run BODY, and RELEASE it (always, even on non-local exit) — WP-DDS-SECURITY-ZEROALLOC-AEAD T4. Evaluates to BODY's
   value, or NIL when the pool is not carved / EXHAUSTED: %maybe-wrap-user-submessages treats NIL as the fail-closed
   required-but-failed drop (RESOURCE_LIMITS backpressure; never a GC fallback, NFR-MEM). Acquire + release are O(1) index
   ops under SUBMSG-SCRATCH-LOCK so concurrent sender threads never corrupt the pool; BODY (the multi-bracket build) runs
   OUTSIDE the lock. Assumes the pool is already carved (the caller ensures it first)."
  (let ((n (gensym "NODE")))
    `(let ((,n ,node))
       (%with-scratch (,var (disc-node-submsg-scratch-pool ,n) (disc-node-submsg-scratch-lock ,n))
         ,@body))))

(defun* %maybe-wrap-srtps (node buf len dest-prefix)
    (function (disc-node dds.core.buffer:octet-buffer (integer 0) (simple-array (unsigned-byte 8) (12)))
              (or null (integer 0)))
  "T10 whole-RTPS-message protection (DDS-Security 1.1 §8.5.1.10-.12 / §9.4.1.2.3) SEND-side engagement. If
   rtps_protection is in effect for DEST-PREFIX — the node's RTPS-PROTECTION-ENCODE resolver (installed cross-layer
   by the crypto-manager) returns the LOCAL ParticipantCrypto KeyMaterial for a :keyed destination under a non-NONE
   governance rtps_protection_kind — WRAP BUF's post-RTPS-header submessage stream (octets [20,LEN)) as
   SRTPS_PREFIX ‖ <body> ‖ SRTPS_POSTFIX keyed by that KM per the resolver's KIND (:receivers = the destination's
   ParticipantCrypto receiver descriptor for the *_WITH_ORIGIN_AUTHENTICATION tier, §9.5.3.3.4.3), overwrite [20,…)
   IN PLACE in BUF, and return the new datagram length (the 20-octet RTPS Header at [0,20) is kept verbatim — the
   transform protects only the submessage stream).
   ZERO-ALLOC (WP-DDS-SECURITY-ZEROALLOC-AEAD T3 / ZA-2): the bracket is built BY OFFSET straight into a
   datagram-sized scratch borrowed from NODE's per-node send-scratch pool (%with-send-scratch over
   %ensure-send-scratch-pool) via encode-rtps-message-into — no per-datagram plain-region subseq, no
   encode-rtps-message →octets return — then copied back over [20,…) and the scratch released. Steady-state secured
   send over the reused BUF + pooled scratch conses ~0 GC-heap B/datagram (the origin-auth receivers tier keeps the
   core's deferred allocating fallback, still into the scratch).
   Returns LEN UNCHANGED when no wrap applies: no resolver installed (security OFF), or the resolver returns NIL
   (the dest is not :keyed / rtps_protection NONE) -> plain, BYTE-IDENTICAL (the pool is never touched). Returns NIL
   (the caller DROPS, fail-closed; NFR-SEC-POSTURE) when a wrap WAS required but the pool is EXHAUSTED
   (RESOURCE_LIMITS backpressure — never a GC fallback), or the encode failed, or the result would not fit BUF —
   never emits an unprotected datagram to a keyed peer. If the pool could not be carved (arena exhausted at first
   wrap) the wrap DEGRADES to the allocating encode-rtps-message (correct, byte-identical wire), self-healing when
   the arena frees.
   §9.5.3.3.5 SOURCE BINDING: before protecting, a 24-octet source-declaring INFO_SRC (NODE's guid-prefix,
   put-info-src-into) is prepended to the submessage stream via an in-place right-shift of [20,LEN) by 24 — so the
   protected payload begins with it and a strict rtps_protection peer (live RTI Connext) accepts the SRTPS message
   (its decode_rtps_message rejects a payload whose first recovered submessage is not this INFO_SRC, 'wrong
   INFO_SRC'). The INFO_SRC rides INSIDE the SEC_BODY (encrypted for ENCRYPT), so the CLEAR wire is unchanged
   (SRTPS_PREFIX‖SEC_BODY‖SRTPS_POSTFIX); the receiver's dispatch skips it (an unhandled submessage id) and takes
   the source prefix from the outer RTPS Header. Zero-alloc (raw-offset shift + write, no per-datagram cons)."
  (let ((enc (disc-node-rtps-protection-encode node)))
    (if (or (null enc) (<= len 20))
        len                                            ; no protection installed / header-only -> plain (byte-identical)
        (multiple-value-bind (km kind receivers) (funcall enc dest-prefix)
          (if (null km)
              len                                      ; dest not :keyed / rtps_protection NONE -> plain
              (let ((vec  (dds.core.buffer:octet-buffer-vec buf))
                    (cap  (dds.core.buffer:octet-buffer-capacity buf)))
                (if (> (+ len 24) cap)
                    nil                                 ; even the §9.5.3.3.5 INFO_SRC prepend won't fit -> fail-closed drop
                    ;; §9.5.3.3.5 SOURCE BINDING (the T10 whole-RTPS payload must begin with a source-declaring
                    ;; INFO_SRC so a strict rtps_protection peer accepts it — live RTI Connext's decode_rtps_message
                    ;; rejects a protected payload whose first recovered submessage is not this INFO_SRC, 'wrong
                    ;; INFO_SRC'). Zero-alloc: in-place right-shift of the submessage stream [20,LEN) by 24 (reverse
                    ;; copy, overlap-safe: dest>src so iterate high->low) then write the 24-octet INFO_SRC BY OFFSET at
                    ;; [20,44); the INFO_SRC is inside the SRTPS SEC_BODY (encrypted for ENCRYPT), so the CLEAR wire is
                    ;; still SRTPS_PREFIX‖SEC_BODY‖SRTPS_POSTFIX (matches Connext). Decode skips it (dispatch-message
                    ;; no-ops an unhandled submessage id; the source prefix comes from the outer RTPS Header).
                    (let ((pool nil))
                      (loop for i of-type fixnum from (1- len) downto 20
                            do (setf (aref vec (+ i 24)) (aref vec i)))
                      (dds.rtps.message:put-info-src-into vec 20 (disc-node-guid-prefix node))
                      (incf len 24)
                      (setf pool (%ensure-send-scratch-pool node))
                      (if (null pool)
                          ;; pool carve failed (arena exhausted at first wrap): allocating fallback — correct +
                          ;; byte-identical wire, never a silent drop of legit keyed traffic (self-heals once the arena frees).
                          (let ((srtps (dds.security:encode-rtps-message km kind (subseq vec 20 len) :receivers receivers)))
                            (if (and srtps (<= (+ 20 (length srtps)) cap))
                                (progn (replace vec srtps :start1 20) (+ 20 (length srtps)))
                                nil))
                          ;; ZA-2 zero-alloc: borrow a scratch, build the bracket into it BY OFFSET (no subseq / →octets),
                          ;; copy [0,BLEN) back over [20,…) in BUF, release the scratch. Pool exhausted -> %with-send-scratch
                          ;; is NIL -> fail-closed drop (never a GC fallback).
                          (%with-send-scratch (scratch node)
                            (handler-case
                                (let ((blen (dds.security:encode-rtps-message-into
                                             scratch 0 km kind vec 20 (- len 20) :receivers receivers)))
                                  (when (<= (+ 20 blen) cap)
                                    (replace vec (dds.core.buffer:octet-buffer-vec scratch)
                                             :start1 20 :end1 (+ 20 blen) :end2 blen)   ; in-place wrap; header kept
                                    (+ 20 blen)))
                              (error () nil)))))))))))) ; encode overflow/failure or won't-fit -> fail-closed drop

(defun* %submessage-extent (vec pos len)
    (function ((simple-array (unsigned-byte 8) (*)) fixnum (integer 0))
              (values (or null (unsigned-byte 8)) fixnum))
  "Parse the 4-octet RTPS SubmessageHeader at VEC[POS] (DDSI-RTPS 2.5 §9.4.5.1.2: id ‖ flags ‖ octetsToNextHeader,
   E flag = bit 0 of flags selects octn endianness; octn 0 = the last submessage runs to LEN, §9.4.5.1.3) and return
   (VALUES ID SM-END) — SM-END the EXCLUSIVE end offset of this submessage in VEC. Returns (VALUES NIL POS) fail-closed
   when the 4-octet header is truncated (POS+4 > LEN) or the declared body overruns LEN. The SINGLE walk-extent decision
   shared by %WRAP-USER-SUBMESSAGES-INTO (the metadata_protection wrap loop) and %PRESCAN-USER-SUBMESSAGES (the pool-
   exhaustion pre-scan) so their fail-closed malformed / overrun handling AND octn=0 semantics CANNOT diverge (a walk
   divergence could make the pre-scan skip a submessage the wrap loop would wrap -> leak an unprotected datagram; NFR-
   SEC-POSTURE). Zero-alloc: raw-offset reads only (assumes POS < LEN — the caller's loop guards end-of-stream first)."
  (if (> (+ pos 4) len)
      (values nil pos)                                             ; truncated 4-octet submessage header -> fail-closed
      (let* ((id     (aref vec pos))
             (flags  (aref vec (+ pos 1)))
             (o0     (aref vec (+ pos 2)))
             (o1     (aref vec (+ pos 3)))
             (octn   (if (logbitp 0 flags) (logior o0 (ash o1 8)) (logior (ash o0 8) o1)))
             (body   (+ pos 4))
             (sm-end (the fixnum (+ body (if (zerop octn) (- len body) octn)))))   ; octn 0 = last submessage runs to LEN
        (if (> sm-end len) (values nil pos) (values id sm-end)))))                 ; body overruns the datagram -> fail-closed

(defun* %user-submessage-protectable-p (node id)
    (function (disc-node (unsigned-byte 8)) (values t (or null keyword) t))
  "The SINGLE metadata_protection (DDS-Security 1.1 §8.5.1.7-.9) protectability predicate for ONE user-plane RTPS
   submessage of submessageId ID under NODE's USER-SUBMESSAGE-ENCODE resolver — shared by %WRAP-ONE-USER-SUBMESSAGE-INTO
   (which then PERFORMS the wrap) and %PRESCAN-USER-SUBMESSAGES (which only TESTS it) so the two CANNOT diverge: were the
   pre-scan to under-detect a submessage the wrap loop WOULD wrap, an unprotected datagram could be emitted to a keyed
   peer (a security hole). Returns (VALUES KM KIND WRITER-P) — the resolver's KeyMaterial + transformation kind + the
   writer/reader class — when the submessage IS protectable: a resolver is installed, ID is a WRITER submessage
   (DATA/DATA_FRAG/HEARTBEAT/GAP/HEARTBEAT_FRAG) or a READER submessage (ACKNACK/NACK_FRAG), AND the resolver returns a
   non-NIL KM for that class. Returns a single NIL otherwise (no resolver / INFO_* / the resolver declines — not keyed /
   kind NONE). ONE resolver call per submessage; the wrap uses EXACTLY the KM/KIND/WRITER-P this returns (no re-resolve)."
  (let ((enc (disc-node-user-submessage-encode node)))
    (when enc
      (let ((writer-p (or (= id dds.rtps.message:+submsg-data+)
                          (= id dds.rtps.message:+submsg-data-frag+)
                          (= id dds.rtps.message:+submsg-heartbeat+)
                          (= id dds.rtps.message:+submsg-gap+)
                          (= id dds.rtps.message:+submsg-heartbeat-frag+)))
            (reader-p (or (= id dds.rtps.message:+submsg-acknack+)
                          (= id dds.rtps.message:+submsg-nack-frag+))))
        (when (or writer-p reader-p)
          (multiple-value-bind (km kind) (funcall enc writer-p)
            (when km (values km kind writer-p))))))))

(defun* %wrap-one-user-submessage-into (node id out out-off plain plain-off plain-len)
    (function (disc-node (unsigned-byte 8) dds.core.buffer:octet-buffer fixnum
               (simple-array (unsigned-byte 8) (*)) fixnum fixnum)
              (or null fixnum))
  "Submessage-protect ONE complete user-plane RTPS submessage PLAIN[PLAIN-OFF..+PLAIN-LEN] (header+body, submessageId
   = ID) BY OFFSET directly INTO OUT starting at OUT-OFF, under the LOCAL user endpoint EntityCrypto per the node's
   USER-SUBMESSAGE-ENCODE resolver (DDS-Security 1.1 §8.5.1.7-.9); return the SEC_PREFIX … SEC_POSTFIX bracket LENGTH
   written, or NIL when the resolver declines (not keyed / kind NONE) or ID is not a protectable submessage (INFO_*
   etc.) — the caller then copies the submessage through VERBATIM. The zero-alloc, into-buffer twin of the pre-ZA-2
   %wrap-one-user-submessage (which subseq'd the submessage + returned a fresh bracket vector). The PLAINTEXT submessage
   is NOT padded — the §8.3.4 4-alignment lives in the SEC_BODY CryptoContent container (the -into core rounds the
   SEC_BODY up to a 4-multiple with pad octets AFTER the ciphertext, Fast DDS serialize_SecureDataBody) so the recovered
   submessage's octetsToNextHeader reflects its TRUE length and a data_protection SecuredPayload payload round-trips
   (T10 review fix-2). Writer submessages (DATA/DATA_FRAG/HEARTBEAT/GAP/HEARTBEAT_FRAG) are protected under the user
   WRITER's EntityCrypto via encode-datawriter-submessage-into; reader submessages (ACKNACK/NACK_FRAG) under the user
   READER's via encode-datareader-submessage-into (the §8.5 DataWriter/DataReader transforms are the same mechanism).
   Signals BUFFER-OVERFLOW (caught by %wrap-user-submessages-into's fail-closed handler) if OUT lacks room at OUT-OFF."
  (multiple-value-bind (km kind writer-p) (%user-submessage-protectable-p node id)
    (when km
      (if writer-p
          (dds.security:encode-datawriter-submessage-into out out-off km kind plain plain-off plain-len)
          (dds.security:encode-datareader-submessage-into out out-off km kind plain plain-off plain-len)))))

(defun* %wrap-user-submessages-into (node buf len out)
    (function (disc-node dds.core.buffer:octet-buffer (integer 0) dds.core.buffer:octet-buffer) (or null (integer 0)))
  "Walk BUF's post-RTPS-header submessage stream [20,LEN) and build the metadata_protection-wrapped stream BY OFFSET
   into OUT (the submessage stream ONLY, from OUT offset 0): each user-plane submessage becomes its SEC_PREFIX …
   SEC_POSTFIX bracket (%wrap-one-user-submessage-into, input = BUF's vec + the submessage's OFFSET + LENGTH, NO
   per-submessage subseq); INFO_* (and any submessage the resolver declines) is copied VERBATIM by offset (no alloc).
   Return the NEW datagram length (20 + the built stream length) after overwriting BUF[20,newlen) in place, or LEN
   UNCHANGED when nothing was wrapped (the caller leaves BUF untouched — byte-identical), or NIL fail-closed
   (NFR-SEC-POSTURE) on a malformed / overrunning submessage header, a verbatim copy that would not fit OUT, or a
   rebuilt stream that would not fit BUF. The SHARED walk for BOTH %maybe-wrap-user-submessages paths — the pooled
   scratch (common) and the allocating fallback (arena-exhausted carve) — so the multi-bracket logic lives ONCE (DRY).
   A BUFFER-OVERFLOW from a bracket that would not fit OUT is caught here and mapped to the fail-closed NIL, exactly
   like a too-big rebuild. The 20-octet RTPS Header BUF[0,20) is kept verbatim (never copied into OUT)."
  (let ((vec     (dds.core.buffer:octet-buffer-vec buf))
        (out-vec (dds.core.buffer:octet-buffer-vec out))
        (out-cap (dds.core.buffer:octet-buffer-capacity out))
        (buf-cap (dds.core.buffer:octet-buffer-capacity buf))
        (pos     20)      ; walk BY RAW OFFSET (no cursor consed) — RTPS Header [0,20) kept verbatim in BUF
        (ooff    0)
        (depth   0)       ; SEC_PREFIX..SEC_POSTFIX bracket nesting depth: wrap ONLY at depth 0 (§8.5.1.7-.9, below)
        (any     nil))
    (declare (type fixnum pos ooff depth))
    (handler-case
        (block walk
          (loop
            (when (>= pos len) (return))
            ;; 4-octet RTPS SubmessageHeader by raw offset (id + exclusive sm-end) via the SHARED %submessage-extent walk,
            ;; so this wrap loop and the exhaustion pre-scan cannot diverge on malformed / overrun / octn=0 (§9.4.5.1.2/.3).
            (multiple-value-bind (id sm-end) (%submessage-extent vec pos len)
              (when (null id) (return-from walk nil))                     ; truncated header / body overruns LEN -> fail-closed
              (let* ((sublen  (- sm-end pos))
                     (prefixp (= id dds.security:+submessage-sec-prefix+))
                     (postfixp (= id dds.security:+submessage-sec-postfix+))
                     ;; §8.5.1.7-.9: a submessage ALREADY inside a SEC_PREFIX..SEC_POSTFIX protection bracket (a
                     ;; secure-builtin discovery_protection wrap, or any prior metadata bracket) is NOT re-protected —
                     ;; under SIGN its inner submessage rides VERBATIM/visible, so without this depth gate the
                     ;; metadata_protection walk would DOUBLE-wrap it (under ENCRYPT the inner is an opaque SEC_BODY,
                     ;; never protectable, so it was implicitly skipped — the depth gate makes SIGN behave identically).
                     (blen    (and (zerop depth) (not prefixp) (not postfixp)
                                   (%wrap-one-user-submessage-into node id out ooff vec pos sublen))))
                (when postfixp (when (plusp depth) (decf depth)))         ; leaving a bracket
                (if blen
                    (progn (setf any t) (incf ooff blen))                 ; wrapped bracket (the -into's O(1) extent check bounds OUT)
                    (progn                                                 ; INFO_* / already-bracketed / declined -> copy verbatim by offset
                      (when (> (+ ooff sublen) out-cap) (return-from walk nil))   ; verbatim won't fit OUT -> fail-closed
                      (replace out-vec vec :start1 ooff :end1 (+ ooff sublen) :start2 pos :end2 sm-end)
                      (incf ooff sublen)))
                (when prefixp (incf depth))                               ; entering a bracket (its inners stay verbatim)
                (setf pos sm-end))))
          (if (null any)
              len                                                         ; nothing wrapped -> leave BUF untouched (byte-identical)
              (let ((newlen (+ 20 ooff)))
                (if (<= newlen buf-cap)
                    (progn (replace vec out-vec :start1 20 :end1 newlen :start2 0 :end2 ooff) newlen)
                    nil))))                                               ; rebuilt stream won't fit BUF -> fail-closed
      (error () nil))))                                                   ; -into extent overflow / any signal -> fail-closed drop

(defun* %prescan-user-submessages (node buf len)
    (function (disc-node dds.core.buffer:octet-buffer (integer 0)) (or null (integer 0)))
  "Zero-alloc walk of BUF's post-RTPS-header submessage stream [20,LEN) BY RAW OFFSET — the SAME %submessage-extent
   header-walk + %user-submessage-protectable-p predicate the metadata_protection wrap loop (%WRAP-USER-SUBMESSAGES-INTO)
   uses, so the two CANNOT diverge — deciding, WITHOUT wrapping, whether the datagram REQUIRES metadata_protection. Used
   ONLY when the submessage-scratch pool is EXHAUSTED (%MAYBE-WRAP-USER-SUBMESSAGES) to avoid DROPPING a datagram that
   needs no protection (the ZA-2 review fix — false-REJECT is the worst class). Returns LEN (pass-through, BUF untouched,
   byte-identical) when NO submessage is protectable; NIL (fail-closed drop, NFR-SEC-POSTURE) when ANY submessage IS
   protectable (a required wrap could not be performed — never emit an unprotected datagram to a keyed peer) OR a
   submessage header is malformed / overruns LEN (identical fail-closed to the wrap walk). ZERO-ALLOC: raw-offset reads
   + the shared predicate (INFO_* short-circuits before the resolver; a protectable id calls the resolver, which conses
   nothing) — no subseq, no cursor, no per-submessage object."
  (let ((vec (dds.core.buffer:octet-buffer-vec buf))
        (pos 20)
        (depth 0))       ; SEC_PREFIX..SEC_POSTFIX depth — MUST mirror %wrap-user-submessages-into (no divergence)
    (declare (type fixnum pos depth))
    (loop
      (when (>= pos len) (return len))                              ; end of stream, nothing protectable -> pass-through
      (multiple-value-bind (id sm-end) (%submessage-extent vec pos len)
        (when (null id) (return nil))                              ; truncated header / body overruns LEN -> fail-closed
        (let ((prefixp (= id dds.security:+submessage-sec-prefix+))
              (postfixp (= id dds.security:+submessage-sec-postfix+)))
          (when postfixp (when (plusp depth) (decf depth)))
          ;; only a depth-0, non-bracket submessage is protectable (mirrors the wrap loop's depth gate — an
          ;; already-bracketed inner submessage rides verbatim, never re-wrapped, so it must not force a drop)
          (when (and (zerop depth) (not prefixp) (not postfixp) (%user-submessage-protectable-p node id))
            (return nil))                                          ; a required wrap could not be performed -> drop
          (when prefixp (incf depth)))
        (setf pos sm-end)))))

(defun* %maybe-wrap-user-submessages (node buf len)
    (function (disc-node dds.core.buffer:octet-buffer (integer 0)) (or null (integer 0)))
  "DDS-Security 1.1 §8.5.1.7-.9 USER-DATA submessage protection (metadata_protection) SEND-side engagement —
   the INNER complement of %MAYBE-WRAP-SRTPS (which wraps the whole datagram OUTSIDE this). When the node's
   USER-SUBMESSAGE-ENCODE resolver is installed (security on, metadata_protection != NONE, keyed), WALK BUF's
   post-RTPS-header submessage stream [20,LEN) and replace each user-plane submessage with its SEC_PREFIX …
   SEC_POSTFIX bracket (%wrap-user-submessages-into + %wrap-one-user-submessage-into), passing INFO_* (and any
   submessage the resolver declines) through VERBATIM; rebuild the stream and overwrite BUF in place, returning the
   new datagram length.
   ZERO-ALLOC (WP-DDS-SECURITY-ZEROALLOC-AEAD T4 / ZA-2): the wrapped stream is built BY OFFSET straight into a
   datagram-sized scratch borrowed from NODE's per-node SUBMESSAGE-scratch pool (%with-submsg-scratch over
   %ensure-submsg-scratch-pool) via the encode-datawriter-/datareader-submessage-into cores — dropping the pre-ZA-2
   per-datagram (make-octet-buffer (+ len 8192)) AND the per-submessage (subseq vec start sm-end) — then copied back
   over [20,…) and the scratch released. Steady-state metadata_protection send over the reused BUF + pooled scratch
   conses ~0 GC-heap B/datagram (the origin-auth receivers tier keeps the core's deferred allocating fallback, still
   into the scratch).
   Returns LEN UNCHANGED when no resolver is installed / it declines every submessage (security OFF / metadata NONE /
   not yet keyed) -> byte-identical. The metadata_protection NONE tier short-circuits BEFORE the scratch borrow +
   stream walk (the resolver would decline every submessage anyway — see the crypto-manager USER-SUBMESSAGE-ENCODE
   install — so the walk is pure overhead): a keyed user-data send with metadata_protection NONE pays nothing
   (byte-identical, the pool is never touched). Returns NIL (caller DROPS, fail-closed; NFR-SEC-POSTURE) when a
   submessage header is malformed / overruns LEN, the rebuilt stream would not fit BUF, or — for a datagram that HAS a
   protectable submessage — the submessage-scratch pool is EXHAUSTED (RESOURCE_LIMITS backpressure — never a GC fallback;
   a required wrap could not be performed, so an unprotected datagram is never emitted to a keyed peer). On pool
   EXHAUSTION a datagram with NOTHING protectable (all INFO_* / all-declined) is NOT dropped: a zero-alloc pre-scan
   (%PRESCAN-USER-SUBMESSAGES — the SAME %submessage-extent walk + %user-submessage-protectable-p predicate the wrap loop
   uses, so the two cannot diverge into leaking an unprotected datagram) returns LEN and it passes through byte-identical
   (ZA-2 review — a datagram needing no protection must never be false-REJECTed). If the pool could not be carved (arena
   exhausted at first wrap) the wrap DEGRADES to the allocating make-octet-buffer path (correct, byte-identical wire),
   self-healing when the arena frees. The 20-octet RTPS Header [0,20) is kept verbatim. Called BEFORE %MAYBE-WRAP-SRTPS
   in %SEND-RAW-BUF so the wire is SRTPS( … SEC_PREFIX(submessage) … ), matching Fast DDS RTPSMessageGroup
   (payload-protect -> submessage-protect -> rtps-protect)."
  (let ((enc (disc-node-user-submessage-encode node)))
    ;; NONE tier (metadata_protection off): skip the borrow + walk — wire byte-identical (the resolver declines all).
    (if (or (null enc) (<= len 20)
            (eq (disc-node-user-submessage-protection-kind node) :none))
        len
        (let ((pool (%ensure-submsg-scratch-pool node)))
          (if (null pool)
              ;; pool carve failed (arena exhausted at first wrap): allocating fallback — correct + byte-identical wire,
              ;; never a silent drop of legit keyed traffic (self-heals once the arena frees).
              (let ((out (dds.core.buffer:make-octet-buffer (+ +srtps-scratch-datagram-bytes+ +submsg-scratch-overhead+))))
                (unwind-protect (%wrap-user-submessages-into node buf len out)
                  (dds.pal:free-static (dds.core.buffer:octet-buffer-vec out))))
              ;; ZA-2 zero-alloc: borrow a submessage scratch, build the wrapped stream into it BY OFFSET (no subseq /
              ;; →octets), copy back over [20,…) in BUF, release. Pool EXHAUSTED -> %with-submsg-scratch never runs the
              ;; body -> the zero-alloc pre-scan decides (ZA-2 review): a datagram with NOTHING protectable passes through
              ;; byte-identical (LEN, never a drop); one WITH a protectable submessage stays fail-closed (NIL — a required
              ;; wrap could not be performed, never emit an unprotected datagram to a keyed peer).
              (let ((wrapped nil))
                (if (%with-submsg-scratch (scratch node)
                      (setf wrapped (%wrap-user-submessages-into node buf len scratch))
                      t)                                            ; body ran = scratch acquired; the T disambiguates it from an exhausted NIL
                    wrapped                                         ; acquired: authoritative (LEN / newlen / its own fail-closed NIL)
                    (%prescan-user-submessages node buf len))))))))

(defun* %send-raw-buf (node buf len host port &optional shmem-dest dest-prefix)
    (function (disc-node dds.core.buffer:octet-buffer (integer 0) string (unsigned-byte 16)
               &optional t (or null (simple-array (unsigned-byte 8) (12)))) t)
  "Send the first LEN octets of BUF (a complete RTPS message) as ONE datagram — the raw one-datagram send
   shared by %SEND-MSG-BUF and the %SEND-PACKED coalescer (one dds.xport:send = one sendto). DEST-PREFIX
   (default NIL), the 12-octet destination GUID-prefix on the USER-DATA path, engages T10 whole-RTPS-message
   protection: when the dest is :keyed under a non-NONE governance rtps_protection_kind, %MAYBE-WRAP-SRTPS wraps
   the post-header submessage stream IN PLACE (SRTPS_PREFIX‖SEC_BODY‖SRTPS_POSTFIX) BEFORE *DATAGRAM-SINK* + the
   send, so the wire (and the sink) carries the SRTPS sandwich; a required-but-failed wrap DROPS (fail-closed).
   NIL DEST-PREFIX (every discovery/HB/ACKNACK/bootstrap caller) keeps the plain path, byte-identical. When
   SHMEM-DEST (a dds.xport.shmem:shmem-locator) is supplied, the datagram goes over SHARED MEMORY to that
   same-host peer (FR-XPORT-2); if the SHMEM send returns 0 (lane full / claim fail) it FALLS BACK to the
   UDP send to HOST:PORT (no loss, no double-delivery — exactly one of the two carries it). A SIGNALED hard
   SHMEM fault (segment detached / pshared / bounds) is caught here (WP-SHMEM-SEND-SELF-GUARD): it bumps
   SHMEM-SEND-FAULTS + fires *SENDER-EMIT-ERROR-HOOK* (context :shmem-send-fault) via %NOTE-SHMEM-SEND-FAULT,
   then falls back to UDP exactly like a return-0 — so the datagram still delivers (the HANDLER-CASE fires only
   on a SIGNAL; a benign return-0 lane-full takes the silent UDP fallback with no counter/hook). With SHMEM-DEST
   NIL (every discovery/HB/ACKNACK caller, and every cross-host data send) the path is the original UDP send,
   byte-for-byte unchanged. Hands a copy to *DATAGRAM-SINK* first when that test hook is bound."
  (when dest-prefix   ; secured user path (wrap in place; BEFORE the sink)
    ;; Slice 5: INNER user-DATA submessage protection (metadata_protection, §8.5.1.7-.9) FIRST, then the OUTER
    ;; whole-RTPS-message protection (T10 rtps_protection, §8.5.1.10-.12) — matching Fast DDS send order.
    (let ((sm-len (%maybe-wrap-user-submessages node buf len)))
      (when (null sm-len) (return-from %send-raw-buf nil))   ; required submessage wrap failed -> fail-closed drop
      (setf len sm-len))
    (let ((wrapped-len (%maybe-wrap-srtps node buf len dest-prefix)))
      (when (null wrapped-len) (return-from %send-raw-buf nil))   ; required wrap failed -> fail-closed drop
      (setf len wrapped-len)))
  (when *datagram-sink*
    (funcall *datagram-sink* (subseq (dds.core.buffer:octet-buffer-vec buf) 0 len)))
  (when *debug-emit-fault*
    (when (integerp *debug-emit-fault*)
      (setf *debug-emit-fault* (when (> *debug-emit-fault* 1) (1- *debug-emit-fault*))))   ; N -> N-1, last -> NIL
    (error 'sender-emit-test-fault))   ; :persistent or a positive integer: inject; inert when NIL   ; NOCOND(TEST): inert in production (armed only by *debug-emit-fault* defaulting NIL); the UNWIND is the emit-fault mechanism under test
  (when (and shmem-dest (disc-node-shmem node))
    (when (plusp (handler-case
                     (dds.xport:send (dds.xport.shmem:shmem-transport-transport (disc-node-shmem node))
                                     shmem-dest buf 0 len)
                   (error (c) (%note-shmem-send-fault node c) 0)))   ; hard SHMEM fault -> counter+hook, fall to UDP
      (incf (disc-node-shmem-sends node))
      (return-from %send-raw-buf t)))   ; delivered over SHMEM: do NOT also UDP-send (no double-delivery)
  (dds.xport:send (disc-node-transport node)
                  (dds.xport.udp:make-udp-locator :host host :port port)
                  buf 0 len))

(defun* %send-msg-buf (node buf build-fn host port &optional dest-prefix)
    (function (disc-node dds.core.buffer:octet-buffer function string (unsigned-byte 16)
               &optional (or null (simple-array (unsigned-byte 8) (12)))) t)
  "Build an RTPS message (Header + whatever BUILD-FN writes on the cursor) into BUF
   and send it to HOST:PORT. BUF selects the thread's scratch message buffer. DEST-PREFIX
   (default NIL) is the 12-octet destination GUID-prefix on the USER-DATA path; non-NIL engages
   T10 whole-RTPS-message protection at %send-raw-buf when that dest is :keyed (NIL = plain,
   byte-identical — every builtin/discovery/bootstrap caller leaves it NIL)."
  (let ((mc (dds.core.buffer:cursor buf :endianness :little)))
    (dds.rtps.message:write-header mc (disc-node-guid-prefix node))
    (funcall build-fn mc)
    (%send-raw-buf node buf (dds.core.buffer:cursor-position mc) host port nil dest-prefix)))

(defparameter *coalesce-datagram-budget* 1400
  "Soft upper bound (octets) on a coalesced RTPS datagram built by %SEND-PACKED. Default 1400 keeps the
   UDP datagram under the common Ethernet path MTU (1500 − 20 IPv4 − 8 UDP = 1472) so a coalesced
   message is not IP-fragmented (the real hazard of over-large datagrams). The effective budget is
   min(this, buffer-capacity − 64). A single submessage larger than the budget is still sent (alone in
   its datagram), never truncated. Tunable; pinned to no spec constant (a local batching policy, not a
   wire field).")

(defun* %pack-budget (buf)
    (function (dds.core.buffer:octet-buffer) (integer 0))
  "The effective coalescing budget for BUF: min(*COALESCE-DATAGRAM-BUDGET*, capacity−64) — the per-datagram
   octet ceiling %PACK-PLAN partitions to (RTPS 2.5 §8.3.4). Factored so the plan and the build agree on it."
  (min *coalesce-datagram-budget* (- (dds.core.buffer:octet-buffer-capacity buf) 64)))

(defun* %pack-plan (items budget)
    (function (list (integer 0)) list)
  "Partition ITEMS — each a (SIZE . BUILD-FN) packable submessage of at most SIZE octets — into the ORDERED
   list of per-datagram item groups %SEND-PACKED would flush at BUDGET (RTPS 2.5 §8.3.4): a fresh group is
   started before a submessage that would push the current (non-empty) group past BUDGET, and a submessage
   whose SIZE is not a multiple of 4 forces a group boundary after it (RTPS 2.5 §8.3.4 requires the next
   submessage to start 32-bit-aligned). Pure (no I/O, no cursor) — the boundary decision depends only on the
   SIZE sequence and BUDGET, so the partition is identical whether the caller sends eagerly (%SEND-PACKED) or
   one group at a time (the per-datagram step), making the two byte-identical by construction. NIL ITEMS ->
   NIL (no datagram)."
  (let ((groups '()) (cur '()) (used 0))
    (dolist (item items)
      (when (and cur (> (+ used (car item)) budget))
        (push (nreverse cur) groups) (setf cur '() used 0))   ; would overflow: close the current group
      (push item cur) (incf used (car item))
      (when (plusp (mod (car item) 4))
        (push (nreverse cur) groups) (setf cur '() used 0)))   ; non-4-aligned: must be this datagram's last
    (when cur (push (nreverse cur) groups))
    (nreverse groups)))

(defun* %build-packed-datagram (node buf group)
    (function (disc-node dds.core.buffer:octet-buffer list) (integer 0))
  "Build ONE coalesced RTPS datagram for the item GROUP (a %PACK-PLAN sublist) into BUF — one shared Header
   (RTPS 2.5 §8.3.4 / §9.4.4) then each item's submessage in order — and return its octet length. No I/O: the
   send is the caller's (so the per-datagram step can build-then-send, accounting tokens on the returned
   length before sending). The byte-exact body shared by %SEND-PACKED and %EMIT-NEXT-DATAGRAM."
  (let ((mc (dds.core.buffer:cursor buf :endianness :little)))
    (dds.rtps.message:write-header mc (disc-node-guid-prefix node))
    (dolist (item group)
      (funcall (cdr item) mc))
    (dds.core.buffer:cursor-position mc)))

(defun* %send-packed (node buf host port items &optional shmem-dest)
    (function (disc-node dds.core.buffer:octet-buffer string (unsigned-byte 16) list &optional t) t)
  "Coalesce ITEMS — each a (SIZE . BUILD-FN) where BUILD-FN writes exactly ONE submessage of at most
   SIZE octets — into as few RTPS datagrams as fit the budget, one shared Header per datagram (RTPS 2.5
   §8.3.4 / §9.4.4), and send each to HOST:PORT. The datagram partition is %PACK-PLAN (a fresh datagram is
   started before a submessage that would push a non-empty datagram past min(*COALESCE-DATAGRAM-BUDGET*,
   capacity−64), so the cursor never exceeds the budget ≪ buffer capacity: no buffer overflow on legitimate
   input; a submessage whose body does not end on a 4-octet boundary, RTPS 2.5 §8.3.4 requires the next to
   start 32-bit-aligned, is the last in its datagram — a no-op for this stack: every DATA payload is
   XCDR-padded to 4, dispose=52, HEARTBEAT=28, all aligned, a graceful degrade otherwise); each group is then
   built (%BUILD-PACKED-DATAGRAM) and sent. Cuts the sendto count from one-per-submessage to
   ceil(total/budget). NIL ITEMS sends nothing. SHMEM-DEST (a shmem-locator, default NIL) routes every
   datagram over shared memory with UDP fallback (%send-raw-buf, FR-XPORT-2); NIL keeps the original all-UDP
   path."
  (dolist (group (%pack-plan items (%pack-budget buf)))
    (%send-raw-buf node buf (%build-packed-datagram node buf group) host port shmem-dest)))

(defun* %resolve-usable-destination (p)
    (function (dds.rtps.discovery:spdp-data) t)
  "Compute (uncached) a sendable (host . port) for user traffic to participant P — see %USABLE-DESTINATION,
   which memoizes this. Allocates a dotted-quad string and a cons; called once per discovered SPDP record."
  (let* ((dlocs (dds.rtps.discovery:spdp-data-default-unicast-locators p))
         (mlocs (dds.rtps.discovery:spdp-data-metatraffic-unicast-locators p))
         (d (dds.rtps.discovery:usable-udpv4-locator dlocs))
         (m (dds.rtps.discovery:usable-udpv4-locator mlocs)))
    (cond
      (d (cons (dds.rtps.discovery:locator-ipv4-string d)
               (%locator-port (dds.rtps.discovery:locator-port d))))
      ((and m dlocs)
       (cons (dds.rtps.discovery:locator-ipv4-string m)
             (%locator-port (dds.rtps.discovery:locator-port (first dlocs)))))
      (t nil))))

(defun* %usable-destination (p)
    (function (dds.rtps.discovery:spdp-data) t)
  "A sendable (host . port) for user traffic to participant P, selected from its
   advertised locator LISTS: a routable UDPv4 default-unicast locator (host+port
   from that locator); else — if every default-unicast locator is non-routable — a
   routable metatraffic ADDRESS paired with a default-unicast PORT (same host, user
   port). NIL if none is usable. Foreign stacks (RTI) advertise several locators
   including 0.0.0.0 placeholders; this picks one that can actually be reached.

   NFR-MEM: MEMOIZED on P's user-dest slot. The result is a pure function of P's locator lists, but this
   sits on the per-sample send path (every ACKNACK/DATA destination resolution), where it was building a
   dotted-quad STRING (a full FORMAT NIL) and a fresh CONS on EVERY send. The memo cannot go stale: a
   re-announce parses a FRESH spdp-data carrying a fresh :UNRESOLVED memo (%record-discovered REPLACES the
   struct in disc-node-discovered), so the cache lifetime is exactly the record's. A benign race between
   receiver threads recomputes the same value.

   The memoized cons is SHARED, so callers MUST treat it as read-only."
  (let ((memo (dds.rtps.discovery:spdp-data-user-dest p)))
    (if (eq memo :unresolved)
        (setf (dds.rtps.discovery:spdp-data-user-dest p) (%resolve-usable-destination p))
        memo)))

(defun* %prefix-user-destination (node prefix)
    (function (disc-node (simple-array (unsigned-byte 8) (12))) (or null cons))
  "User-plane (host . port) for participant PREFIX, or NIL — the user-traffic twin of
   %REMOTE-METATRAFFIC (disc.lisp): look up the discovered SPDP record for the 12-octet GUID-prefix
   (RTPS 2.5 §9.4.4) and resolve its sendable default-unicast destination via %USABLE-DESTINATION.
   NIL when PREFIX is undiscovered or resolves to no usable (port>0) destination. Lets an inbound
   submessage (e.g. an ACKNACK) be answered at the originating participant ALONE instead of every
   matched peer."
  (let ((spdp (dds.pal:with-lock ((disc-node-lock node))
                (gethash prefix (disc-node-discovered node)))))
    (when spdp
      (let ((hp (%usable-destination spdp)))
        (when (and hp (plusp (cdr hp))) hp)))))

(defun* %shmem-wire-locator (spdp)
    (function (dds.rtps.discovery:spdp-data) t)
  "The first SHMEM Locator_t (kind +locator-kind-shmem+) a peer advertised in its default-unicast
   locators (FR-XPORT-2 / E1 make-shmem-locator-wire), or NIL — proves the peer offers a SHMEM receive
   segment. The ring geometry (lane-count, capacity) rides in the locator: address[0..3]=lane-count,
   port=capacity."
  (find dds.rtps.discovery:+locator-kind-shmem+
        (dds.rtps.discovery:spdp-data-default-unicast-locators spdp)
        :key #'dds.rtps.discovery:locator-kind :test #'=))

(defun* %resolve-shmem-dest (node prefix)
    (function (disc-node (simple-array (unsigned-byte 8) (12))) t)
  "Resolve participant PREFIX's SHMEM destination from the discovered SPDP record, or NIL. CALLER HOLDS
   the node lock. A peer qualifies iff the discovered remote advertised the SAME host-uuid as this node
   (same physical host, RTPS-level so a hostname collision degrades to a failed attach + UDP fallback,
   never data loss), AND it advertised a SHMEM locator (so a receive segment exists). The destination NAME
   is derived deterministically from PREFIX (seg-name-for-guid, RTPS 2.5 §9.4.4) and the ring geometry
   from the wire locator (lane-count from its address, capacity from its port). Off the hot path — called
   only on a %shmem-dest cache miss (once per peer)."
  (let ((spdp (gethash prefix (disc-node-discovered node))))
    (when (and spdp
               (plusp (dds.rtps.discovery:spdp-data-host-uuid spdp))
               (= (dds.rtps.discovery:spdp-data-host-uuid spdp) (disc-node-host-uuid node)))
      (let ((wl (%shmem-wire-locator spdp)))
        (when wl
          (dds.xport.shmem:make-shmem-locator
           :name (dds.xport.shmem:seg-name-for-guid prefix)
           :host-uuid (disc-node-host-uuid node)
           :lane-count (dds.rtps.discovery:shmem-locator-wire-lane-count wl)
           :capacity (dds.rtps.discovery:locator-port wl)))))))

(defun* %shmem-dest (node prefix)
    (function (disc-node (simple-array (unsigned-byte 8) (12))) t)
  "A dds.xport.shmem:shmem-locator addressing participant PREFIX's receive segment iff PREFIX is a
   SAME-HOST SHMEM peer reachable over shared memory, else NIL (caller then uses UDP). A peer qualifies
   iff: SHMEM is on for this node (the shmem slot is set — which already encodes *shmem-enabled* + the
   platform gate), AND the discovered remote advertised the SAME host-uuid as this node, AND it advertised
   a SHMEM locator. MEMOIZED per remote prefix (FR-XPORT-2 / FR-LANG-7): the resolved locator (or the
   sentinel :none for 'not a SHMEM peer') is cached in shmem-dest-cache, so the steady-state send does ONE
   cheap gethash and NO per-datagram make-shmem-locator allocation or full re-resolve (the prior cost the
   WP-SHMEM bench charged at ~800-2000 bytes/sample). The cache is read + filled under the node lock and is
   invalidated when PREFIX's SPDP is re-recorded (%record-participant) or it leases out (%lease-sweep), so a
   changed or removed peer never sends to a stale locator."
  (when (disc-node-shmem node)
    (dds.pal:with-lock ((disc-node-lock node))
      (let ((cached (gethash prefix (disc-node-shmem-dest-cache node))))
        (cond
          ((eq cached :none) nil)               ; memoized non-SHMEM peer: skip the resolve, UDP
          (cached cached)                        ; memoized live shmem-locator: reuse, no alloc
          (t (let ((resolved (%resolve-shmem-dest node prefix)))
               (setf (gethash (copy-seq prefix) (disc-node-shmem-dest-cache node))
                     (or resolved :none))        ; cache the verdict (:none for not-a-peer) keyed by an owned copy
               resolved)))))))

(defun* %reader-guid-p (guid)
    (function ((simple-array (unsigned-byte 8) (16))) t)
  "T iff the GUID's entity kind is a user reader (0x04 no-key / 0x07 with-key)."
  (let ((k (aref guid 15))) (or (= k #x04) (= k #x07))))

(defun* %writer-guid-p (guid)
    (function ((simple-array (unsigned-byte 8) (16))) t)
  "T iff the GUID's entity kind is a user writer (0x02 with-key / 0x03 no-key)."
  (let ((k (aref guid 15))) (or (= k #x02) (= k #x03))))

(defun* %endpoint-keyed-p (guid)
    (function ((simple-array (unsigned-byte 8) (16))) t)
  "T iff the endpoint GUID's entity kind is a WITH_KEY user endpoint: writer 0x02 or
   reader 0x07 (vs NO_KEY writer 0x03 / reader 0x04) — RTPS 2.5 §9.3.1.2 Table 9.1."
  (let ((k (aref guid 15))) (or (= k #x02) (= k #x07))))

(defun* %guid-entityid (guid)
    (function ((simple-array (unsigned-byte 8) (16))) (unsigned-byte 32))
  "The 4-octet EntityId (u32, big-endian octets 12..15) of a 16-octet GUID (RTPS 2.5 §9.3.1.2)."
  (logior (ash (aref guid 12) 24) (ash (aref guid 13) 16) (ash (aref guid 14) 8) (aref guid 15)))

(defun* %writer-topic (node writer)
    (function (disc-node dds.rtps.reliable:rtps-writer) (or null string))
  "The topic-name of local user WRITER — matched from its RTPS EntityId to the advertised endpoint-data in
   disc-node-local-writers (WP-N-ENDPOINT-S1, ADR 0048). The per-writer push-target topic filter so a DataWriter
   pushes DATA only to the remote readers matched to ITS topic (RxO matches on topic-name), never to a sibling
   writer's readers. NIL (no local endpoint for that id — the discovery-less value path) disables the filter."
  (let ((eid (dds.rtps.reliable:rtps-writer-entityid writer)))
    (dolist (w (disc-node-local-writers node))
      (when (= eid (%guid-entityid (dds.rtps.discovery:endpoint-data-guid w)))
        (return (dds.rtps.discovery:endpoint-data-topic-name w))))))

(defun* %user-writer-entityid-p (entity-id)
    (function ((unsigned-byte 32)) t)
  "T iff ENTITY-ID's kind is an application-defined writer (0x02 with-key / 0x03 no-key) —
   a user-data writer, not a builtin (kind 0xc2). Lets the reader ACKNACK ANY matched
   remote writer's HEARTBEAT, not only a writer sharing this stack's local EntityId
   convention (a peer such as RTI Connext picks its own writer EntityIds)."
  (let ((k (logand entity-id #xff))) (or (= k #x02) (= k #x03))))

(defun* %matched-reader-keys (node)
    (function (disc-node) list)
  "The full 16-octet GUIDs of every matched RELIABLE remote user READER — the writer-proxy keys for
   purge-on-full-ACK (writer-purge-acked). Identical keys to the ones %on-user-acknack advances
   (%source-guid src-prefix rid = the reader's GUID, RTPS 2.5 §9.4.4 / §8.3.5.4), so the purge watermark
   is the min acked-base across every matched RELIABLE reader (a not-yet-ACKed reliable reader's proxy
   reads acked-base 1 and holds the watermark — nothing purged until it acks). A BEST_EFFORT reader is
   EXCLUDED: it never ACKNACKs (its proxy would pin the watermark at 1 forever, disabling the purge) and
   the writer owes it no retransmit (best-effort = no delivery guarantee, §2.2.3.13), so purging samples
   it never acked is correct."
  (loop for remote in (%matched-endpoints node)
        for guid = (dds.rtps.discovery:endpoint-data-guid remote)
        for q = (dds.rtps.discovery:endpoint-data-qos remote)
        when (and (%reader-guid-p guid) q (eq (dds.qos:qos-reliability q) :reliable))
          collect (copy-seq guid)))

(defun* %matched-endpoints (node)
    (function (disc-node) list)
  "Snapshot of the remote endpoints matched to one of NODE's local endpoints."
  (dds.pal:with-lock ((disc-node-lock node))
    (loop for v being the hash-values of (disc-node-matches node) collect v)))

(defun* %local-writer-durability (node &optional writer-id)
    (function (disc-node &optional (or null (unsigned-byte 32)))
              (member :volatile :transient-local :transient :persistent))
  "NODE's local user writer's DURABILITY kind (DDS 1.4 §2.2.3.4), read from its advertised endpoint-data
   QoS (disc-node-local-writers — the same QoS the SEDP advertises + RxO-matches). WRITER-ID (WP-N-ENDPOINT-S2B,
   ADR 0048) selects a SPECIFIC local writer by its engine EntityId — its OWN advertised durability, so the
   late-joiner replay in %writer-durability-init and the full-ACK purge in %on-user-acknack each consult the
   ADDRESSED writer's kind, never a list head. NIL (or an unregistered id) -> the head local-writer (the primary;
   byte-identical N=1); :VOLATILE when there is no local writer yet (the discovery-less value-level path). A
   TRANSIENT_LOCAL writer retains for late-joiners (writer-purge-acked DURABILITY)."
  (let ((w (or (and writer-id
                    (find writer-id (disc-node-local-writers node)
                          :key (lambda (ep) (%guid-entityid (dds.rtps.discovery:endpoint-data-guid ep)))
                          :test #'eql))
               (first (disc-node-local-writers node)))))   ; NIL or an unregistered id -> head (primary), N=1 byte-identical
    (if w (dds.qos:qos-durability (dds.rtps.discovery:endpoint-data-qos w)) :volatile)))

(defun* finalize-writer-durability (node &optional writer-id)
    (function (disc-node &optional (or null (unsigned-byte 32))) (eql t))
  "Mark NODE's local user writer FINALIZED (DDS 1.4 §2.2.3.4; the OPT-IN durability-finalize extension ON
   TOP of the conformant default). The disc-level bridge for DCPS durability-finalize: forwards to the engine
   writer (writer-finalize-durability), after which the full-ACK purge in %on-user-acknack RELEASES the
   TRANSIENT_LOCAL writer's retained late-joiner history once all current readers ACK (writer-purge-acked treats
   a finalized writer as VOLATILE). WP-N-ENDPOINT-S2B (ADR 0048): WRITER-ID finalizes the SPECIFIC engine writer
   (the calling DataWriter's own EntityId), so one durable writer's finalize never releases a sibling's retained
   history; NIL (or unregistered) -> the PRIMARY (byte-identical N=1). A no-op (still T) when there is no user
   writer. Monotonic."
  (let ((w (%resolve-user-writer node writer-id)))
    (when w (dds.rtps.reliable:writer-finalize-durability w)))
  t)

(defun* %local-reader-durability (node)
    (function (disc-node) (member :volatile :transient-local :transient :persistent))
  "NODE's local user reader's DURABILITY kind (DDS 1.4 §2.2.3.4), read from its advertised endpoint-data
   QoS (disc-node-local-readers — the same QoS the SEDP advertises + RxO-matches). v1 is one engine reader
   per node (the single dp-user-reader), so the node's lone local-reader's durability IS the engine
   reader's; :VOLATILE when there is no local reader yet (the discovery-less value-level path). Gates the
   reader-side history request in %reader-durability-init: a VOLATILE reader skips a matched writer's
   advertised pre-match history; a TRANSIENT_LOCAL reader matched a TRANSIENT_LOCAL writer requests it.
   Mirrors %local-writer-durability; the same one-reader-per-node caveat applies if that invariant is lifted."
  (let ((r (first (disc-node-local-readers node))))
    (if r (dds.qos:qos-durability (dds.rtps.discovery:endpoint-data-qos r)) :volatile)))

(defun* %match-destinations-prefixed (node want-readers)
    (function (disc-node t) list)
  "User-traffic destinations gated on MATCHING, each a (DEST-PREFIX . (HOST . PORT)) cons: the union of the
   participants holding a matched remote endpoint of the wanted kind — readers (WANT-READERS t) for a writer's
   DATA/HEARTBEAT, writers (nil) for a reader's ACKNACK — plus the static PEERS. DEST-PREFIX is the matched
   participant's 12-octet GUID-prefix (RTPS 2.5 §9.4.4) for a discovered match, NIL for a static PEERS bootstrap
   entry. A matched (prefix-bearing) entry takes precedence over a static one at the SAME (HOST . PORT), so a
   :keyed participant's user-data sends engage T10 whole-RTPS-message protection (DEST-PREFIX threads to
   %send-raw-buf -> %maybe-wrap-srtps). RxO-incompatible / topic-mismatched peers never match, so they receive
   nothing (FR-QOS-2). The (host . port) SET is identical to the pre-T10 plain helper (only the per-dest prefix
   is added); %match-destinations is the prefix-stripped projection (DRY).
   NFR-MEM (ADR 0062): the union is MEMOIZED per WANT-READERS on the node (match-dest-cache), a ~100 B/sample
   win across the 6 hot-path callers; dropped WHOLESALE by %invalidate-dest-cache on match/unmatch/prune + an
   SPDP locator update — a STALE DESTINATION IS SILENT MIS-DELIVERY, so invalidation is coarse on purpose. The
   returned list is SHARED (callers MUST treat it read-only; they only ever dolist / mapcar it)."
  (multiple-value-bind (cached gen)
      (dds.pal:with-lock ((disc-node-lock node))
        (values (gethash want-readers (disc-node-match-dest-cache node) :none)
                (disc-node-match-dest-generation node)))
   (unless (eq cached :none)
     (return-from %match-destinations-prefixed cached))
   (let ((dests '())
        (parts (%discovered-participants node)))
    (dolist (remote (%matched-endpoints node))
      (let ((guid (dds.rtps.discovery:endpoint-data-guid remote)))
        (when (if want-readers (%reader-guid-p guid) (%writer-guid-p guid))
          (let ((spdp (find (subseq guid 0 12) parts
                            :key #'dds.rtps.discovery:spdp-data-guid-prefix :test #'equalp)))
            (when spdp
              (let ((hp (%usable-destination spdp)))
                (when (and hp (plusp (cdr hp)) (not (member hp dests :key #'cdr :test #'equal)))
                  (push (cons (subseq guid 0 12) hp) dests))))))))   ; matched: prefix-bearing
    (dolist (peer (disc-node-peers node))   ; static PEERS not already covered by a matched (host . port)
      (unless (member peer dests :key #'cdr :test #'equal)
        (push (cons nil peer) dests)))
    (let ((result (nreverse dests)))
      ;; STORE ONLY IF NO INVALIDATION RACED THE RESOLVE. %discovered-participants / %matched-endpoints each
      ;; take the node lock, so a match/unmatch/SPDP can land between them; caching a now-stale union would be
      ;; permanent silent mis-delivery. On a race, return the fresh value and re-resolve next call.
      (dds.pal:with-lock ((disc-node-lock node))
        (when (= gen (disc-node-match-dest-generation node))
          (setf (gethash want-readers (disc-node-match-dest-cache node)) result)))
      result))))

(defun* %match-destinations (node want-readers)
    (function (disc-node t) list)
  "The prefix-stripped (host . port) projection of %match-destinations-prefixed (DRY) — the union of static
   PEERS and the participants holding a matched remote endpoint of the wanted kind (readers for a writer's
   DATA/HEARTBEAT, writers for a reader's ACKNACK). RxO-incompatible / topic-mismatched peers never match
   (FR-QOS-2). For a send that should engage T10 whole-RTPS-message protection, use the prefixed variant."
  (mapcar #'cdr (%match-destinations-prefixed node want-readers)))

(defparameter *debug-drop-fragment-numbers* nil
  "Debug-only fragment-loss injection (default NIL = off): a list of 1-based fragment
   numbers that %SEND-SAMPLE silently SKIPS when fragmenting a sample into DATA_FRAGs
   (both the initial push and sample-level ACKNACK retransmits). NACK_FRAG-driven
   resends (%ON-USER-NACK-FRAG) are NOT filtered, so the only recovery path for a
   dropped fragment is the peer's NACK_FRAG — proving fragment-level reliability
   against a live peer (RTPS 2.5 §8.3.8.12 NackFrag). Never set in production.")

(defparameter *debug-drop-sample-numbers* nil
  "Debug-only whole-sample-loss injection (default NIL = off): a list of sequence numbers whose
   non-fragmented DATA %SEND-SAMPLE silently SKIPS, proving lost-final-sample recovery via the
   periodic HEARTBEAT (RTPS 2.5 §8.4.2.2). Never set in production.")

(defparameter *tx-single-group* t
  "NFR-MEM (ADR 0062, task #29): when T (default), %PUSH-ONE-WRITER-CHANGES emits the common single-destination
   case (exactly one %reader-push-targets group) DIRECTLY, skipping %capture-push-groups' per-group
   %zc-push-group struct + the groups/all lists — the ADR 0047 cross-group freeze is trivially satisfied by one
   group (no change reaches >=2 groups, so the shared-ZC table is +no-shared-zc-refs+). Bind NIL to force the
   general %capture-push-groups path for the SAME input (the byte-identity/allocation A/B). Never bound in production.")

(defparameter *tx-fast-path* t
  "NFR-MEM (ADR 0062, task #29): when T (default), %SEND-CHANGES-PACKED emits the common case — one small
   non-ZC change (+ optional HB) fitting a single budget-bounded datagram to one destination (UDP or SHMEM) —
   directly, skipping the %changes-datagram-plan closure allocation. Bind to NIL to FORCE the plan path for
   the SAME input: the byte-identity oracle (run-tx-fast-path-equivalence-test) captures both and asserts
   they are byte-for-byte identical. Never bound in production.")

(defparameter *emit-writer* nil
  "WP-N-ENDPOINT-S1 (ADR 0048): the local user ENGINE WRITER (rtps-writer) whose changes / HEARTBEAT / HEARTBEAT_FRAG
   / GAP the send path is CURRENTLY emitting — dynamically bound per-writer by the fan-out (%push-one-writer-changes,
   %push-heartbeat) and by the writerId-routed retransmit (%on-user-acknack). The DATA/HEARTBEAT/GAP builders stamp
   its EntityId (%emit-wid) AND the DATA_FRAG HEARTBEAT_FRAG is sourced from its OWN HistoryCache (%emit-writer), so
   each of a participant's N DataWriters emits — and repairs fragments — under its OWN GUID + SN space. NIL (unbound —
   no fan-out active: the flow/durability/single-writer paths) falls back to the primary, keeping the single-writer
   wire byte-identical (RTPS 2.5 §9.3.1.2 / §9.4.5.5).")

(defun* %emit-writer (node)
    (function (disc-node) (or null dds.rtps.reliable:rtps-writer))
  "The engine writer the send path is CURRENTLY emitting for: the fan-out's bound *emit-writer*, or — absent a
   binding — the node's primary user writer (WP-N-ENDPOINT-S1; N=1 byte-identical). Used where the emit needs the
   writer's OWN HistoryCache (the DATA_FRAG HEARTBEAT_FRAG, RTPS 2.5 §9.4.5.5), not just its EntityId."
  (or *emit-writer* (disc-node-user-writer node)))

(defun* %emit-wid (node)
    (function (disc-node) (unsigned-byte 32))
  "The writerId to stamp on the CURRENTLY-emitted user DATA/HEARTBEAT/GAP submessage: the EntityId of the bound
   per-writer *emit-writer*, or — absent a binding — the node's primary user-writer-id (WP-N-ENDPOINT-S1; N=1
   byte-identical)."
  (if *emit-writer* (dds.rtps.reliable:rtps-writer-entityid *emit-writer*) (disc-node-user-writer-id node)))

(defun* %small-change-p (change)
    (function (dds.rtps.history:cache-change) t)
  "T iff CHANGE is a single-submessage (packable) change: a no-payload dispose/unregister (always
   small) or a :data sample whose serializedPayload fits one DATA submessage (≤ *fragment-size*, so it
   is NOT fragmented into a DATA_FRAG series). Large samples go through %changes-datagram-plan / %sample-plan."
  (or (not (eq (dds.rtps.history:cache-change-kind change) :data))
      (<= (dds.rtps.history:cache-change-payload-len change)   ; TRUE length (a secured change's payload is an oversized pooled vec, T5a)
          dds.rtps.reliable:*fragment-size*)))

(defun* %ns->rtps-time (ns)
    (function (integer) (values (unsigned-byte 32) (unsigned-byte 32)))
  "Split a nanosecond source_timestamp into the RTPS Time_t (seconds, 2^-32 fraction) for an INFO_TS
   (RTPS 2.5 §9.4.5.9 / §9.3.2.1), reusing the shared discovery Duration fraction codec (no hardcoded 2^32)."
  (multiple-value-bind (sec nsec) (floor ns 1000000000)
    (values (logand sec #xffffffff) (dds.qos:duration-nanosec->wire-fraction nsec))))

(defun* %change-submessage-size (change)
    (function (dds.rtps.history:cache-change) (integer 0))
  "The exact octet length of CHANGE's small (packable) submessage(s): an optional INFO_TS (12, when
   source_timestamp>0) plus either one DATA (:data — 4 submsg-header + 20 body-prefix + inlineQoS + payload)
   or one no-payload dispose/unregister DATA (56). The fit bound %pack-plan and the %send-changes-packed
   single-datagram fast path check before writing so a datagram never overflows the buffer. Extracted from
   %data-builder so the plan and the fast path agree on the size by construction (DRY)."
  (let ((ts-size (if (plusp (dds.rtps.history:cache-change-source-timestamp change)) 12 0)))
    (if (eq (dds.rtps.history:cache-change-kind change) :data)
        (+ 24 (let ((iq (dds.rtps.history:cache-change-inline-qos change))) (if iq (length iq) 0))
           (dds.rtps.history:cache-change-payload-len change)   ; TRUE length, not the oversized pooled vec (T5a)
           ts-size)
        (+ 56 ts-size))))

(defun* %write-change-submessage (node change wid mc)
    (function (disc-node dds.rtps.history:cache-change (unsigned-byte 32) dds.core.buffer:cursor) t)
  "Write CHANGE's small submessage(s) into cursor MC at writerId WID (RTPS 2.5 §9.4.5.4): an optional INFO_TS
   (source_timestamp>0, §9.4.5.9 / §8.3.7.9) then either one DATA (:data, D-flag, inlineQoS from the change's
   slot when non-nil — byte-identical when nil) or one no-payload dispose/unregister DATA (flags E+Q, inlineQoS
   PID_KEY_HASH + PID_STATUS_INFO, §9.6.4.9). WID is PASSED IN (not read from *emit-writer* here) so a deferred
   flow-controller emit stamps the writerId captured when the change was PACKED, not whenever it is stepped.
   The byte-exact writer shared by %data-builder's pack closure and %send-changes-packed's fast path (DRY)."
  (declare (ignore node))
  (when (plusp (dds.rtps.history:cache-change-source-timestamp change))
    (multiple-value-bind (sec frac) (%ns->rtps-time (dds.rtps.history:cache-change-source-timestamp change))
      (dds.rtps.message:write-info-ts mc sec frac)))
  (if (eq (dds.rtps.history:cache-change-kind change) :data)
      (dds.rtps.message:write-data
       mc dds.rtps.message:+entityid-unknown+ wid (dds.rtps.history:cache-change-sn change)
       (dds.rtps.history:cache-change-serialized-payload change) 0
       (dds.rtps.history:cache-change-payload-len change)   ; TRUE length (T5a)
       :inline-qos (dds.rtps.history:cache-change-inline-qos change))
      (dds.rtps.message:write-data-dispose
       mc dds.rtps.message:+entityid-unknown+ wid (dds.rtps.history:cache-change-sn change)
       (dds.rtps.history:cache-change-instance-key-hash change)
       (dds.rtps.history:cache-change-status-info change)))
  t)

(defun* %data-builder (node change)
    (function (disc-node dds.rtps.history:cache-change) cons)
  "A (SIZE . BUILD-FN) packable item for the SMALL CHANGE (for %send-packed): SIZE from %change-submessage-size,
   BUILD-FN a closure that writes the submessage(s) via %write-change-submessage. WID is captured HERE, at pack
   time, into the closure so a deferred flow-controller emit stamps the right per-writer EntityId
   (WP-N-ENDPOINT-S1; N=1 byte-identical). Both the SIZE and the writer are shared verbatim with the
   single-datagram fast path in %send-changes-packed (DRY), keeping the two paths byte-identical."
  (let ((wid (%emit-wid node)))
    (cons (%change-submessage-size change)
          (lambda (mc) (%write-change-submessage node change wid mc)))))

(defun* %write-hb-submessage (first last count wid mc)
    (function (integer integer integer (unsigned-byte 32) dds.core.buffer:cursor) t)
  "Write one NON-FINAL user-writer HEARTBEAT (FIRST,LAST,COUNT) at writerId WID into cursor MC — readerId
   UNKNOWN, FinalFlag NOT_SET so it solicits an ACKNACK (RTPS 2.5 §8.3.7.5 / §8.4.9.2.7). WID is PASSED IN
   (captured at pack time by %heartbeat-builder) so a deferred flow-controller emit stamps the writerId from
   when the HB was packed. The byte-exact HB writer shared by %heartbeat-builder's pack closure and
   %send-changes-packed's single-datagram fast path (DRY)."
  (dds.rtps.message:write-heartbeat mc dds.rtps.message:+entityid-unknown+ wid first last count :final nil)
  t)

(defun* %heartbeat-builder (node first last count)
    (function (disc-node integer integer integer) cons)
  "A (SIZE . BUILD-FN) packable item for one NON-FINAL user-writer HEARTBEAT (FIRST,LAST,COUNT) —
   readerId UNKNOWN, FinalFlag NOT_SET so it solicits an ACKNACK (RTPS 2.5 §8.3.7.5 / §8.4.9.2.7);
   mirrors %send-user-heartbeat. SIZE = 4 submsg-header + 28 body. WID captured HERE (pack time) into the
   closure. Delegates the write to %write-hb-submessage, shared verbatim with the fast path (DRY)."
  (let ((wid (%emit-wid node)))
    (cons 32
          (lambda (mc) (%write-hb-submessage first last count wid mc)))))

(defun* %zc-payload-wire-protected-p (node)
    (function (disc-node) boolean)
  "T iff NODE's user writer is under a DATAGRAM- or SUBMESSAGE-tier governance protection that the raw
   Zero-Copy/SHMEM sample-pool would BYPASS: rtps_protection (whole-RTPS, DDS-Security 1.1 §8.5.1.10-.12 /
   §9.4.1.2.3) or metadata_protection (user-submessage, §8.5.1.7-.9 / §9.4.1.2.4) with a non-NONE kind.
   Those tiers are applied to the DATAGRAM at send time (%maybe-wrap-user-submessages then %maybe-wrap-srtps
   in %send-raw-buf), AFTER the sample already sits in the pool — so with Zero-Copy only the 16-byte reference
   datagram is wrapped while the user payload stays in shared memory in the CLEAR (ADR 0036 Carry 10). When
   this is T the raw ZC path is DISABLED FAIL-CLOSED (%zc-change-item returns NIL) and the sample is emitted as
   a normal DATA whose datagram %send-raw-buf protects over UDP or the SHMEM ring — so no cleartext user
   payload ever lands in the ZC pool for a writer whose governance mandates payload/RTPS confidentiality.
   data_protection (§9.4.1.2.4 data_protection_kind) is NOT gated here: it is applied at serialize time
   (publish-sample), so the pool receives the already-transformed SecuredPayload (ciphertext for ENCRYPT,
   plaintext+MAC for SIGN) and is never LESS protected than the wire at the payload tier. Both kinds default
   :none, so a non-secured writer -> NIL -> the Zero-Copy/SHMEM fast path stays byte-identical + untouched."
  (or (not (eq (disc-node-rtps-protection-kind node) :none))
      (not (eq (disc-node-user-submessage-protection-kind node) :none))))

(defun* %zc-overlay-km (node &optional (weid (%emit-wid node)))
    (function (disc-node &optional (unsigned-byte 32)) (or null dds.security:key-material))
  "WP-SECURITY-ZC-SHMEM-OVERLAY (ADR 0051; S6.T3 per-endpoint): resolve the EMITTING writer's EntityCrypto
   KeyMaterial for the in-slot data_protection SecuredPayload overlay. WEID defaults to %emit-wid — the
   writer whose change is being sealed (the SAME per-endpoint identity publish-sample resolves by, WP-N-
   ENDPOINT-S1) — so N SAME-topic secured-ZC writers each seal under their OWN EntityCrypto km (distinct
   sender_key_id), NOT the node-primary's key (the pre-S6 N=1 collapse). %emit-wid falls back to the
   primary user-writer id when no writer is emitting, so the eligibility check and the non-send path are
   byte-identical. A crypto-keys resolver -> the writer's km by its own GUID; a raw key-material -> itself
   (Slice-1 / test config). NIL when no crypto-transform is installed (fail-closed)."
  (let ((ct (disc-node-crypto-transform node)))
    (and ct
         (if (typep ct 'dds.security:crypto-keys)
             (funcall (dds.security:crypto-keys-encode-key-fn ct)
                      (%local-writer-guid-vec node weid))
             ct))))

(defun* %zc-overlay-eligible-p (node)
    (function (disc-node) boolean)
  "WP-SECURITY-ZC-SHMEM-OVERLAY (ADR 0051; SIGN tier added by ADR 0058): T iff a wire-protected writer may use
   Zero-Copy/SHMEM via the in-slot data_protection SecuredPayload overlay instead of being gated off
   (%zc-payload-wire-protected-p). Requires: the writer IS wire-protected (rtps/metadata_protection non-NONE —
   else it takes the raw ZC fast path, no overlay); its data_protection is explicitly NONE (data=SIGN/ENCRYPT
   already puts a SecuredPayload in the slot via the existing ungated path; :unset with a crypto-transform
   installed would be sealed at publish, so the change payload is NOT known-plaintext -> not overlay-eligible);
   AND an EntityCrypto KM resolves (%zc-overlay-km).
   BOTH AEAD tiers are eligible (ADR 0058). An ENCRYPT (AES256-GCM) KM seals CIPHERTEXT into the slot
   (confidentiality + integrity). A SIGN (AES256-GMAC) KM seals a GMAC SecuredPayload — the payload stays
   VISIBLE in the slot, exactly as the SIGN tier leaves it visible on the wire, and is AUTHENTICATED by the
   common_mac the reader verifies fail-closed. The alternative once recorded in ADR 0051 (relax SIGN to RAW ZC,
   no overlay) is REJECTED: the RTPS signature covers only the 20-octet reference datagram, so a raw slot
   payload would be UNAUTHENTICATED — a co-resident process could tamper with the sample undetected, silently
   dropping the very integrity guarantee the SIGN tier exists to provide. The overlay costs one seal and keeps it.
   Fail-closed: no KM -> NIL (stays gated off)."
  (and (%zc-payload-wire-protected-p node)
       (eq (disc-node-user-data-protection-kind node) :none)
       (and (%zc-overlay-km node) t)))

(defun* %ensure-zc-overlay-scratch (node)
    (function (disc-node) (or null dds.core.arena:buffer-pool))
  "WP-SECURITY-ZC-SHMEM-OVERLAY (ADR 0051): lazily carve NODE's overlay seal-scratch pool — static octet-buffers
   each sized to hold a slot's worth of data_protection SecuredPayload (44 + slot-bytes + 3 — the ENCRYPT framing,
   which is the LARGER of the two tiers, so it also covers a SIGN/GMAC seal at 40 + align4(N); ADR 0058). Returns the
   pool, or NIL if the arena carve fails (caller then skips the overlay -> the writer stays gated off for that
   sample, fail-closed, never a GC fallback). Idempotent, double-checked under the dedicated overlay lock; the
   arena is stored only after the carve succeeds (teardown reachability); stop-node tears it down. Mirrors
   %ensure-submsg-scratch-pool / %ensure-secure-rx-pool (init-arena + make-buffer-pool)."
  (or (disc-node-zc-overlay-scratch-pool node)
      (dds.pal:with-lock ((disc-node-zc-overlay-scratch-lock node))
        (or (disc-node-zc-overlay-scratch-pool node)
            (handler-case
                (let* ((eb    (+ 44 +zerocopy-pool-slot-bytes+ 3))
                       (cap   4)
                       (arena (dds.core.arena:init-arena :bytes (* eb (1+ cap))))   ; +1 slot slack
                       (pool  (dds.core.arena:make-buffer-pool arena eb cap)))
                  ;; ADR 0064: an exhausted arena is a STATUS now, not a condition — so it MUST be TESTED.
                  ;; An unchecked NIL pool would still run the SETF below, storing the ARENA whose own
                  ;; comment says 'only after the carve succeeds' — orphaning its static allocation on
                  ;; every failed carve.
                  (when (null pool) (dds.core.arena:teardown-arena arena) (return-from %ensure-zc-overlay-scratch nil))
                  (setf (disc-node-zc-overlay-scratch-arena node) arena   ; store the arena only after the carve succeeds (teardown reachability)
                        (disc-node-zc-overlay-scratch-pool node) pool))   ; set the pool LAST — the double-checked-carve flag
              (error () nil))))))   ; arena-exhausted / static-alloc failure -> leave NIL -> fail-closed skip

;;;; WP-FLATDATA-LOAN-WRITE (FR-PF-4, R6, ADR 0042; NOT cleared for ship — pending counsel). The TX loan-write
;;;; pool API DCPS loan-sample/discard-loan calls: a writer acquires a pool slot, the app writes its FlatData
;;;; fields straight into the slot via the SAP-mode Offset setters, and the loan is either published (delivered
;;;; via the normal send path — v1) or aborted. This keeps the pool internals (disc-node-zc-pool-sap +
;;;; dds.xport.zerocopy) inside dds-disc; DCPS never reaches into them.

(defun* %loan-write-data-protected-p (node)
    (function (disc-node) boolean)
  "WP-FLATDATA-LOAN-WRITE (FR-PF-4, R6, ADR 0042 §6). T iff NODE's user writer would TRANSFORM its
   SerializedPayload at publish (§9.4.1.2.4 SecuredPayload) — i.e. loan-write's raw slot bytes would diverge
   from the wire payload AND leak plaintext into SHMEM. Fail-closed: a governance-mandated data_protection
   (:sign/:encrypt) blocks loan-write even if no crypto-transform is installed yet; :unset (no governance, the
   Slice-1 direct-KM config) blocks only when a crypto-transform IS installed (publish-sample then applies it —
   the exact condition its ct binding uses); :none (governance says data=NONE) rides plain — never blocked."
  (let ((kind (disc-node-user-data-protection-kind node)))
    (or (and (member kind '(:sign :encrypt)) t)
        (and (eq kind :unset) (disc-node-crypto-transform node) t))))

(defun* node-secured-reader-p (node)
    (function (disc-node) boolean)
  "WP-DCPS-SECURED-TAKE-LOAN (ADR 0038 residual (i)). The RECEIVE-side analog of %loan-write-data-protected-p:
   T iff NODE's user reader DECODES a SecuredPayload (data_protection) on receive — i.e. its topic is secured, so
   the DCPS opt-in (create-datareader) may route it through the zero-decode-buffer-alloc secured LOAN path
   (set-secured-loan-capable). Governance-mandated data_protection (:sign/:encrypt) is secured even before a
   crypto-transform is installed (the LIVE-handshake config carves the decode pool lazily on the first secured
   receive, when the runtime decode gate's crypto-transform IS present); :unset (no governance, the Slice-1
   direct-KM config) is secured only when a crypto-transform is already installed (the exact condition the receive
   decode gate uses, dataplane.lisp %deliver-user-sample); :none (governance says data=NONE) rides plain — never
   loan-capable. A plain reader (kind :unset, no crypto) -> NIL -> the allocating decode path stays byte-identical."
  (let ((kind (disc-node-user-reader-data-protection-kind node)))
    (or (and (member kind '(:sign :encrypt)) t)
        (and (eq kind :unset) (disc-node-crypto-transform node) t))))

(defun* node-loan-write-eligible-p (node size)
    (function (disc-node (integer 0)) boolean)
  "WP-FLATDATA-LOAN-WRITE (FR-PF-4, R6, ADR 0042). T iff NODE can loan-write a SIZE-octet FlatData
   SerializedPayload straight into its writer pool: the node has a ZC writer pool (built iff *zerocopy-enabled*
   + SHMEM at make-disc-node), SIZE is above *zerocopy-min-payload-bytes* (a small sample is not worth a slot),
   the writer is NOT wire-protected (%zc-payload-wire-protected-p) — a secured writer's plaintext must never
   land in a pool slot at all (ADR 0036 Carry-10, fail-closed at the loan end) — AND the writer's payload is NOT
   data_protection-transformed (%loan-write-data-protected-p): under data_protection the SerializedPayload is
   TRANSFORMED at publish (§9.4.1.2.4 SecuredPayload), so the app's raw field writes in a slot would be BOTH a
   plaintext leak into SHMEM and a payload-format mismatch against the wire — unlike the classic ZC path, where
   the pool receives the already-transformed bytes (the ADR 0036 rationale for not gating data_protection there
   does NOT transfer to loan-write; ADR 0042 §6). NIL ⇒ DCPS loan-sample degrades to a heap/pool-backed FlatData
   sample (graceful, no error)."
  (and (disc-node-zc-pool node)
       (dds.xport.shmem:shm-attach-by-name-reliable-p)   ; a peer must be able to ATTACH the pool by name (ADR 0013)
       (> size *zerocopy-min-payload-bytes*)
       (not (%zc-payload-wire-protected-p node))
       (not (%loan-write-data-protected-p node))   ; loan-write-specific: the slot would hold pre-transform plaintext (ADR 0042 §6)
       t))

(defun* node-loan-write-acquire (node size)
    (function (disc-node (integer 0)) (values t (integer 0) (integer 0) (unsigned-byte 32)))
  "WP-FLATDATA-LOAN-WRITE (FR-PF-4, R6, ADR 0042). Acquire a writer-pool slot for a SIZE-octet FlatData loan
   (%zc-loan-acquire, readers=1): returns (values POOL-SAP SLOT PAYLOAD-BASE GENERATION) — POOL-SAP + PAYLOAD-BASE
   (the segment byte offset of the slot payload) for the app to store-sap-u8 its sample into, SLOT + GENERATION
   the loan handle for node-loan-write-abort / the later commit. (values NIL 0 0 0) on pool saturation ⇒ DCPS
   degrades to a heap sample (graceful). The slot is held (refcount=1) until abort/commit; a lock-free reader can
   never observe it before commit (ADR 0042 §2)."
  (let ((sap (disc-node-zc-pool-sap node)))
    (if (null sap)
        (values nil 0 0 0)
        (multiple-value-bind (slot base gen) (dds.xport.zerocopy::%zc-loan-acquire sap size 1)
          (if (null slot) (values nil 0 0 0) (values sap slot base gen))))))

(defun* node-loan-write-abort (node slot)
    (function (disc-node (integer 0)) t)
  "WP-FLATDATA-LOAN-WRITE (FR-PF-4, R6, ADR 0042). Release an acquired-but-unpublished writer loan on SLOT
   (%zc-loan-abort): the slot returns to reclaimable (refcount=0) without ever publishing a generation, so it is
   invisible to every reader. Idempotent-safe (a second abort re-zeroes an already-0 refcount). No-op when the
   node has no pool."
  (let ((sap (disc-node-zc-pool-sap node)))
    (when sap (dds.xport.zerocopy::%zc-loan-abort sap slot)))
  t)

(defun* node-loan-write-commit (node slot generation)
    (function (disc-node (integer 0) (unsigned-byte 32)) t)
  "WP-FLATDATA-LOAN-WRITE (FR-PF-4, R6, ADR 0042). COMMIT an acquired writer loan on SLOT: %zc-loan-commit —
   dds.pal:fence :release then store GENERATION LAST, the single release point that publishes the app's field
   writes to a future lock-free reader (ADR 0042 §2). After commit the slot (still held at refcount=1) may be
   handed to publish-sample as the change's pre-committed slot; the send site emits its ref once or releases it
   (%zc-change-item / the sweeps). No-op when the node has no pool."
  (let ((sap (disc-node-zc-pool-sap node)))
    (when sap (dds.xport.zerocopy::%zc-loan-commit sap slot generation)))
  t)

(defun* node-loan-write-pin-capable-p (node)
    (function (disc-node) boolean)
  "WP-ACKED-SLOT-PINNING (FR-PF-4, R6, ADR 0044; NOT cleared for ship — pending counsel). T iff a slot-backed
   loan-written change on NODE may be PINNED-until-ACK (holding its committed Zero-Copy slot live) INSTEAD of
   eagerly materialising the per-write retained SerializedPayload. Requires ALL of (ADR 0044 §3): a ZC writer
   pool with the pin release-fn wired; DURABILITY :volatile OR a FINALIZED writer (an un-finalized
   TRANSIENT_LOCAL late-joiner could need the sample arbitrarily later — infeasible to pin with 32 slots); and
   >=1 MATCHED RELIABLE READER (%matched-reader-keys non-empty) — the necessary-and-sufficient condition that the
   pin will be RELEASED (the pin drops at the full-ACK purge, driven by reliable readers' ACKNACKs; it also
   subsumes writer-reliability by RxO). NIL ⇒ write-loaned materialises the retained payload eagerly, exactly as
   ADR 0042 (byte- and alloc-identical). The pin BUDGET is re-checked atomically at the pin site (publish-sample)
   — this predicate gates only whether the retained copy may be skipped. NOT cleared for ship — pending counsel."
  (and (disc-node-zc-pool-sap node)
       (disc-node-user-writer node)
       (dds.rtps.history:history-cache-zc-release-fn
        (dds.rtps.reliable:rtps-writer-hc (disc-node-user-writer node)))
       (let ((d (%local-writer-durability node)))
         (or (eq d :volatile)
             (dds.rtps.reliable:rtps-writer-finalized (disc-node-user-writer node))))
       (consp (%matched-reader-keys node))
       t))

(defun* %ensure-change-payload (node change)
    (function (disc-node dds.rtps.history:cache-change) (or null (simple-array (unsigned-byte 8) (*))))
  "WP-ACKED-SLOT-PINNING on-demand slot read (FR-PF-4, R6, ADR 0044; NOT cleared for ship — pending counsel).
   Return CHANGE's serialized SerializedPayload for a send that needs the BYTES (a non-ZC destination, an extra
   ZC destination, a retransmit, or a DATA_FRAG series). For a normal change this is just CACHE-CHANGE-SERIALIZED-
   PAYLOAD (byte-identical, no-op). For a PINNED change (serialized-payload NIL, the TX pin holding its slot live)
   it RESOLVES the committed slot ON DEMAND via %zc-resolve-fresh — a fresh heap vector byte-IDENTICAL to what
   %loan-write-payload would have eagerly produced (both copy the true-length payload from the self-describing
   slot base) — and CACHES it onto the change (so a later send reuses it and the change thereafter behaves like a
   fallback change: LAZY retained payload, materialised only WHEN a non-pure-ZC send actually needs it, vs today's
   eager-on-every-write). The slot is guaranteed live for the read because the pin hold keeps refcount>=1; a
   legitimate retransmit happens only because the reader NACKed (has not ACKed) ⇒ the pin has not released.
   %zc-resolve-fresh is generation-guarded, so a theoretical concurrent reclaim is SAFE (returns NIL = a
   best-effort dropped datagram the reader re-NACKs — never torn/wrong bytes). Returns NIL only for a no-payload
   change (a dispose/unregister, which needs none) or an impossible stale slot. NOT cleared for ship — counsel."
  (or (dds.rtps.history:cache-change-serialized-payload change)
      (when (and (dds.rtps.history:cache-change-zc-pinned change)
                 (>= (dds.rtps.history:cache-change-zc-slot change) 0)
                 (disc-node-zc-pool-sap node))
        (let ((vec (dds.xport.zerocopy::%zc-resolve-fresh
                    (disc-node-zc-pool-sap node)
                    (dds.rtps.history:cache-change-zc-slot change)
                    (dds.rtps.history:cache-change-zc-generation change))))
          (when vec (setf (dds.rtps.history:cache-change-serialized-payload change) vec))
          vec))))

(defun* %zc-change-item (node change zc-readers)
    (function (disc-node dds.rtps.history:cache-change (integer 0)) (or null cons))
  "WP-ZEROCOPY (FR-PF-3, ADR 0014): if CHANGE is a :data sample whose serialized payload is LARGER than
   *zerocopy-min-payload-bytes* AND ZC-READERS (same-host ZC-capable readers at this destination) > 0,
   loan the payload into the writer pool and return a (SIZE . BUILD-FN) DATA item carrying the 16-byte
   reference (%zc-ref-builder). NIL when not ZC-eligible OR the pool is saturated — the caller then emits
   the FULL serialized payload (no loss, exactly one of {ref, payload} per reader). ZC-READERS is used
   only as a >0 GATE; the slot refcount is 1 (this ref reaches ONE destination, resolved ONCE there —
   see %zc-ref-builder). The eligibility gate AND the loan span use cache-change-payload-len — the TRUE
   serialized length — NOT (length serialized-payload): a secured change's payload vec is the OVERSIZED
   fixed pool buffer (T5a), so loaning (length pl) would copy the garbage tail past the true length into
   the ZC slot, and the remote decode-serialized-payload-into exact-frame check (len == 44+ct_len+pad)
   would reject the sample (a secured+ZC false-reject). For a non-pooled change payload-len IS
   (length serialized-payload) — byte-identical to the prior non-secured ZC path.
   SECURITY GATE (WP-SECURITY-ZC-SHMEM-CLEARTEXT, ADR 0036 Carry 10, DDS-Security 1.1 §8.5): when
   %zc-payload-wire-protected-p (rtps_protection or metadata_protection non-NONE) the raw ZC path is
   DISABLED fail-closed (returns NIL) — the datagram/submessage encryption those tiers apply lives OUTSIDE
   the pool, so a raw payload in shared memory would be readable by any co-resident participant; the sample
   instead takes the normal serialize -> %send-raw-buf (submessage+SRTPS wrap) path.
   OVERLAY (WP-SECURITY-ZC-SHMEM-OVERLAY, ADR 0051; SIGN tier added by ADR 0058): when a wire-protected writer has
   data_protection = NONE and an EntityCrypto KM resolves (%zc-overlay-eligible-p), the payload is instead SEALED as
   a data_protection SecuredPayload into a pooled scratch and loaned into the slot, and the emitted ref carries
   +zc-ref-overlay-secured+ — so the writer regains Zero-Copy while the slot content keeps the protection its
   governance tier promises: an ENCRYPT KM puts CIPHERTEXT in the slot (no cleartext in SHMEM), a SIGN (GMAC) KM
   puts the VISIBLE payload plus an authenticating common_mac (the SIGN tier never promised confidentiality, but it
   DOES promise integrity — and raw ZC would leave the slot payload unauthenticated, since the RTPS signature covers
   only the reference datagram). Fail-closed: no KM / no scratch / carve-fail -> NIL (the writer stays gated off).
   WP-FLATDATA-LOAN-WRITE PRE-COMMITTED SLOT (FR-PF-4, R6, ADR 0042): a loan-written change carries the
   committed pool slot its sample already sits in (zc-state :armed). When the FULL eligibility above holds,
   the send site PREFERS that slot (%zc-armed-item, a one-shot claim) — the emitted ref bytes are EXACTLY
   what %zc-ref-builder would emit, with NO payload->slot copy; the claim is spent on the FIRST ZC-eligible
   destination (exactly-one-ZC-destination = the pure-0-copy envelope; any further ZC destination takes the
   fresh-loan path from the retained payload, as today). When the decision here is NOT ZC (gate active /
   zc-readers 0 — including every RETRANSMIT, which passes zc-readers 0 — / non-:data / undersized), an
   armed slot is RELEASED one-shot (%zc-drop-armed: refcount 1->0, reclaimable, no generation published
   beyond the committed one) — the send-site gate stays AUTHORITATIVE over the pre-committed slot
   (ADR 0036 Carry-10 inheritance) and a committed slot never strands on a fallback decision. NOT cleared
   for ship — pending counsel (R6)."
  (cond
    ;; raw ZC (non-secured / data_protection already SecuredPayload) — UNCHANGED
    ((and (plusp zc-readers)
          (eq (dds.rtps.history:cache-change-kind change) :data)
          (not (%zc-payload-wire-protected-p node)))   ; fail-closed: never a cleartext payload in SHMEM for a wire-protected writer (ADR 0036 Carry 10)
     (let ((len (dds.rtps.history:cache-change-payload-len change)))   ; TRUE length, not the oversized pooled vec (T5a)
       (if (> len *zerocopy-min-payload-bytes*)
           (or (and (eq (dds.rtps.history:cache-change-zc-state change) :armed)   ; fast hint; the claim re-checks under the writer lock
                    (%zc-armed-item node change))                                 ; ADR 0042: emit the PRE-COMMITTED slot, 0 copies
               (let ((pl (%ensure-change-payload node change)))   ; ADR 0044: resolve a pinned slot on demand for the fresh-loan fallback (extra ZC dest)
                 (and pl (%zc-ref-builder node (dds.rtps.history:cache-change-sn change) pl 0 len 1))))
           (progn (%zc-drop-armed node change) nil))))   ; undersized: release an armed slot (one-shot no-op otherwise)
    ;; WP-SECURITY-ZC-SHMEM-OVERLAY (ADR 0051): a wire-protected ENCRYPT-tier writer (data=NONE) seals the payload as a
    ;; data_protection SecuredPayload INTO the slot instead of being gated off — no cleartext in SHMEM, the wire reference
    ;; stays rtps/metadata-wrapped, and the ref carries the overlay sentinel (copy-on-read decode only — Task 3).
    ((and (plusp zc-readers)
          (eq (dds.rtps.history:cache-change-kind change) :data)
          (%zc-overlay-eligible-p node))
     ;; INVARIANT: an overlay-eligible writer (wire-protected, data=NONE/ENCRYPT KM) never carries an :armed
     ;; loan-written slot — %loan-write-data-protected-p blocks arming for :sign/:encrypt and :unset+ct — so the
     ;; fail-closed NIL branches below need no %zc-drop-armed (nothing to strand); a future change that lets a
     ;; secured writer arm a slot MUST revisit this (add the drop like the raw undersized arm / the t fallback).
     (let* ((len (dds.rtps.history:cache-change-payload-len change))
            (km  (%zc-overlay-km node)))
       ;; SIZE GATE (fail-closed, no exception-driven control flow): the raw arm caps only *zerocopy-min-payload-bytes*,
       ;; but the sealed SecuredPayload must ALSO fit a pool slot — else the seal would overflow the scratch buffer /
       ;; never loan. The bound is the EXACT per-tier sealed length (dds.security:secured-payload-length — ENCRYPT
       ;; 44+N+pad, SIGN/GMAC 40+align4(N)), not a hardcoded ENCRYPT-only estimate. Gate BEFORE the pool carve so the
       ;; over-slot case is portable (returns NIL, no SHMEM touched) and the sample falls through to serialize.
       (if (and km
                (> len *zerocopy-min-payload-bytes*)
                (<= (dds.security:secured-payload-length km len) +zerocopy-pool-slot-bytes+))
           (let ((pl   (%ensure-change-payload node change))     ; data=NONE => pl is the exact plaintext, (length pl)==len
                 (pool (%ensure-zc-overlay-scratch node)))
             (if (and pl km pool)
                 (let ((sb (dds.core.arena:pool-acquire pool)))
                   (if (null sb)
                       nil                                        ; scratch exhausted: fail-closed skip (no ZC this sample)
                       (unwind-protect
                            (let ((slen (dds.security:encode-serialized-payload-into sb km pl)))   ; seal exactly (length pl)==len plaintext bytes; fits by the size gate above
                              (%zc-ref-builder node (dds.rtps.history:cache-change-sn change)   ; loan the SecuredPayload bytes into the slot; ref carries the overlay sentinel
                                               (dds.core.buffer:octet-buffer-vec sb) 0 slen 1
                                               dds.cdr:+zc-ref-overlay-secured+))
                         (dds.core.arena:pool-release pool sb))))
                 nil))
           nil)))
    (t (progn (%zc-drop-armed node change) nil))))     ; gated / non-ZC / retransmit: the fallback decision releases an armed slot

(defun* %zc-shareable-change-p (node change)
    (function (disc-node dds.rtps.history:cache-change) boolean)
  "WP-ZC-MULTI-DEST-REFCOUNT (FR-PF-4, R6, ADR 0047; NOT cleared for ship — pending counsel). T iff CHANGE is
   eligible to SHARE one Zero-Copy slot across the ZC-capable destinations that carry it — the change-level half
   of %zc-change-item's gate (kind :data, NOT wire-protected, payload-len > *zerocopy-min-payload-bytes*), i.e.
   the per-group %zc-readers>0 count aside. The security gate (%zc-payload-wire-protected-p) is UNCHANGED and
   authoritative: a secured/wire-protected writer never shares a slot (it never ZCs at all, ADR 0036 Carry-10).
   Uses cache-change-payload-len (the TRUE serialized length, T5a), matching %zc-change-item byte-for-byte."
  (and (eq (dds.rtps.history:cache-change-kind change) :data)
       (not (%zc-payload-wire-protected-p node))
       (> (dds.rtps.history:cache-change-payload-len change) *zerocopy-min-payload-bytes*)
       t))

(defun* %zc-emit-item (node change zc-readers shared)
    (function (disc-node dds.rtps.history:cache-change (integer 0) (or null hash-table)) (or null cons))
  "WP-ZC-MULTI-DEST-REFCOUNT (FR-PF-4, R6, ADR 0047; NOT cleared for ship — pending counsel). The per-group ZC
   DATA-item chooser threaded into %changes-datagram-plan. If CHANGE carries a cross-group SHARED ref (loaned
   ONCE this pass with refcount = the ZC-eligible GROUP count, %shared-zc-refs) AND this destination is
   ZC-eligible (ZC-READERS > 0), emit that SAME (slot, gen) ref via %zc-ref-item — the ref BYTES are byte-identical
   to a fresh %zc-ref-builder / %zc-armed-item emission and zc-sends bumps once per emitted datagram (N groups ->
   N ref datagrams, still), but NO per-group loan or copy runs (the N-1 slots + copies saved). Otherwise — no
   sharing this pass, a non-shared change, or a non-ZC destination — the unchanged per-destination %zc-change-item
   (fresh loan / one-shot armed claim / fallback release). SHARED nil is exactly today's behaviour (byte-identical)."
  (let ((sh (and shared (plusp zc-readers) (gethash change shared))))
    (if sh
        (%zc-ref-item node (dds.rtps.history:cache-change-sn change) (car sh) (cdr sh))
        (%zc-change-item node change zc-readers))))

(defun* %msg-datagram (node build-fn)
    (function (disc-node function) function)
  "Wrap a submessage BUILD-FN (writing onto a cursor after the Header) as a ONE-DATAGRAM build-thunk
   (lambda (buf) -> octet-length): write the RTPS Header (RTPS 2.5 §8.3.4) then BUILD-FN, return the
   cursor length. No I/O — the byte-exact twin of %SEND-MSG-BUF's build half, so the per-datagram step
   builds the identical bytes %SEND-MSG-BUF would, then sends them itself."
  (lambda (buf)
    (let ((mc (dds.core.buffer:cursor buf :endianness :little)))
      (dds.rtps.message:write-header mc (disc-node-guid-prefix node))
      (funcall build-fn mc)
      (dds.core.buffer:cursor-position mc))))

(defun* %sample-plan (node sn pl size budget)
    (function (disc-node integer (simple-array (unsigned-byte 8) (*)) (integer 0) (integer 1)) list)
  "The ORDERED list of one-datagram build-thunks (each lambda (buf) -> octet-length) for sample (SN, PL) of
   SIZE octets (SIZE is the TRUE serialized length — for a secured change PL is the oversized pooled vec and
   SIZE < (length PL), T5a; the codec offsets all index within [0, SIZE)): one DATA datagram if SIZE fits
   *fragment-size*, else a DATA_FRAG series (packing as many fragments as fit
   BUDGET per datagram, RTPS 2.5 §9.4.5.5) followed by a HEARTBEAT_FRAG. Loss injection is applied HERE,
   via *DEBUG-DROP-SAMPLE-NUMBERS*: a small DATA whose SN is in *DEBUG-DROP-SAMPLE-NUMBERS* and
   a DATA_FRAG submessage covering a fragment in *DEBUG-DROP-FRAGMENT-NUMBERS* are omitted (no thunk). The
   HEARTBEAT_FRAG count side-effect (writer-frag-heartbeat increments a counter) runs ONCE here — exactly as
   the prior flush-all ran it once — and the captured (lastfrag count) close over the thunk, so stepping is
   byte-identical and does not double-count. No I/O: the step builds+sends each thunk.
   NOTE: inline-QoS (cache-change-inline-qos) is carried ONLY on the small-DATA path (%data-builder above);
   this DATA_FRAG path does NOT thread inline-QoS — RTPS 2.5 §9.4.5.5 makes it optional, and relay samples
   are ShapeType-sized, always below *fragment-size*, so they never reach this branch."
  (let ((wid (%emit-wid node)))
    (if (<= size dds.rtps.reliable:*fragment-size*)
        (if (and *debug-drop-sample-numbers* (member sn *debug-drop-sample-numbers*))
            '()
            (list (%msg-datagram node
                                 (lambda (mc)
                                   ; inline-QoS intentionally not threaded here — only %data-builder carries it (DATA_FRAG/large-sample path; durability relay uses small DATA only)
                                   (dds.rtps.message:write-data
                                     mc dds.rtps.message:+entityid-unknown+ wid sn pl 0 size)))))
        (let ((thunks '()))
          (dolist (desc (dds.rtps.reliable:writer-frag-plan size dds.rtps.reliable:*fragment-size* budget))
            (destructuring-bind (fstart fcount off len) desc
              (unless (and *debug-drop-fragment-numbers*
                           (loop for f from fstart below (+ fstart fcount)
                                   thereis (member f *debug-drop-fragment-numbers*)))
                (push (%msg-datagram node
                                     (lambda (mc) (dds.rtps.message:write-data-frag
                                                   mc dds.rtps.message:+entityid-unknown+ wid sn size
                                                   fstart fcount dds.rtps.reliable:*fragment-size* pl off len)))
                      thunks))))
          (multiple-value-bind (lastfrag cnt)
              (dds.rtps.reliable:writer-frag-heartbeat (%emit-writer node) sn)   ; WP-N-ENDPOINT-S1 (F1): the EMITTING writer's HC, not the primary
            (when lastfrag
              (push (%msg-datagram node
                                   (lambda (mc) (dds.rtps.message:write-heartbeat-frag
                                                 mc dds.rtps.message:+entityid-unknown+ wid sn lastfrag cnt)))
                    thunks)))
          (nreverse thunks)))))

(defun* %changes-datagram-plan (node buf changes hb shmem-dest zc-readers &optional shared)
    (function (disc-node dds.core.buffer:octet-buffer list (or null cons) t (integer 0)
               &optional (or null hash-table)) list)
  "The ORDERED per-datagram send-plan for pushing CHANGES (+ optional trailing HEARTBEAT item HB) to ONE
   destination: a list of (BUILD-THUNK . SHMEM-DEST), each BUILD-THUNK a lambda (buf) -> octet-length that
   builds exactly ONE datagram. The order, and each datagram's bytes, are IDENTICAL to the prior flush-all
   %send-changes-packed: every LARGE change's DATA_FRAG datagrams (%sample-plan, in CHANGES order, UDP only
   in v1 -> SHMEM-DEST NIL) come FIRST, then the coalesced small-:data / ZC-ref items + HB packed into ≤budget
   datagrams (%pack-plan + %build-packed-datagram, carrying SHMEM-DEST). Loss injection, ZC substitution
   (ZC-READERS > 0, WP-ZEROCOPY FR-PF-3 — exactly one of {ref, payload} per reader), and the HEARTBEAT_FRAG
   count side-effect all happen here, once, exactly as before — so consuming this plan one datagram at a time
   (the step) is byte-identical to flush-all by construction. Pure of I/O; BUF supplies only the packing
   budget (%pack-budget). SHARED (WP-ZC-MULTI-DEST-REFCOUNT, ADR 0047; default NIL = byte-identical): the
   per-pass cross-group CHANGE -> (slot . gen) table so a change reaching >=2 ZC destinations emits ONE shared
   slot's ref to each (via %zc-emit-item) rather than one fresh loan per destination — the ref bytes are unchanged."
  (let ((frag-plans '()) (items '()) (budget (%pack-budget buf)))
    (dolist (change changes)
      (let ((sn (dds.rtps.history:cache-change-sn change))
            (zc nil))
        (cond
          ((and *debug-drop-sample-numbers* (member sn *debug-drop-sample-numbers*)))
          ((setf zc (%zc-emit-item node change zc-readers shared)) (push zc items))   ; WP-ZEROCOPY / ADR 0047: shared or per-dest ref, not payload
          ;; ADR 0044 (I1 defense-in-depth): materialise a pinned change's payload on demand for a non-ZC / retransmit
          ;; send, and USE the result — a :data change whose slot resolve returned NIL (a reclaimed/stale slot,
          ;; unreachable now the pin defers on send-refcount but proven safe) is SKIPPED (best-effort drop, the reader
          ;; re-NACKs), never a NIL payload with a nonzero length onto the wire. A dispose/unregister carries no
          ;; payload (NIL is expected) and is emitted as before.
          ((and (eq (dds.rtps.history:cache-change-kind change) :data)
                (null (%ensure-change-payload node change))))   ; pinned :data, resolve failed -> drop this datagram
          ((%small-change-p change) (push (%data-builder node change) items))
          (t (dolist (thunk (%sample-plan node sn (dds.rtps.history:cache-change-serialized-payload change)
                                          (dds.rtps.history:cache-change-payload-len change)   ; TRUE length (T5a)
                                          (- (dds.core.buffer:octet-buffer-capacity buf) 64)))
               (push (cons thunk nil) frag-plans))))))   ; large samples: UDP only (v1), one datagram per thunk
    (when hb (push hb items))
    (let ((packed (loop for group in (%pack-plan (nreverse items) budget)
                        collect (cons (let ((g group)) (lambda (buf) (%build-packed-datagram node buf g)))
                                      shmem-dest))))
      (nconc (nreverse frag-plans) packed))))

(defun* %emit-next-datagram (node buf state &optional dest-prefix)
    (function (disc-node dds.core.buffer:octet-buffer list
               &optional (or null (simple-array (unsigned-byte 8) (12)))) (values (integer 0) t list))
  "The per-datagram STEP (WP-ASYNC-FLOW core, FR-PF-2): build the NEXT single datagram of STATE into BUF and
   send it, returning (values BYTES-SENT MORE-REMAIN-P NEW-STATE). STATE is a list of (BUILD-THUNK . SHMEM-DEST)
   plan entries with the destination (HOST . PORT) consed on its head — i.e. ((HOST . PORT) . PLAN); NEW-STATE
   carries the SAME head with PLAN's tail, so threading it across calls walks the plan one datagram at a time.
   MORE-REMAIN-P is NIL once the plan is exhausted. Build-then-send by construction: the thunk builds the
   datagram into BUF and reports its length (the exact token cost the Phase-C scheduler acquires) BEFORE the
   %send-raw-buf — so a scheduler can build, acquire(length), then send the already-built buffer. An empty/
   exhausted STATE sends nothing and returns (values 0 NIL STATE). Flow control is wire-invisible: this only
   changes WHEN a datagram is sent, never its bytes (ADR 0016)."
  (let ((dest (car state)) (plan (cdr state)))
    (if (null plan)
        (values 0 nil state)
        (let* ((entry (car plan))
               (len (funcall (car entry) buf)))
          (%send-raw-buf node buf len (car dest) (cdr dest) (cdr entry) dest-prefix)
          (values len (and (cdr plan) t) (cons dest (cdr plan)))))))

(defun* %send-changes-packed (node buf changes host port hb-first hb-last hb-count &optional shmem-dest (zc-readers 0) dest-prefix shared)
    (function (disc-node dds.core.buffer:octet-buffer list string (unsigned-byte 16)
               (or null integer) (or null integer) (or null integer)
               &optional t (integer 0) (or null (simple-array (unsigned-byte 8) (12))) (or null hash-table)) t)
  "Send CHANGES (+ optional trailing HEARTBEAT (HB-FIRST,HB-LAST,HB-COUNT); HB-FIRST NIL = no HB) to HOST:PORT, coalescing the
   small ones into as few datagrams as fit the budget: this is now the per-datagram STEP run to completion —
   build the %changes-datagram-plan once, then %emit-next-datagram in a loop until no datagram remains. The
   plan emits every LARGE change's DATA_FRAG series first (one datagram per fragment group, UDP only in v1),
   then the coalesced small-:data / ZC-ref items + HB; so the wire bytes are byte-IDENTICAL to the prior
   flush-all (the loop is the same datagram sequence, now stepped). The shared writer push/retransmit emit
   path (RTPS 2.5 §8.3.4 §8.4.2.2). When SHMEM-DEST is supplied the COALESCED small-sample datagrams go over
   shared memory with UDP fallback (FR-XPORT-2); large fragmented samples stay on UDP in v1 (the bulk
   small-sample path is the SHMEM throughput target). NIL SHMEM-DEST is the original all-UDP behaviour,
   byte-for-byte. ZC-READERS > 0 (WP-ZEROCOPY, FR-PF-3) substitutes a 16-byte reference for a large :data
   sample's payload at THIS destination (%zc-change-item) instead of fragmenting it — exactly one of
   {ref, full payload} reaches each reader (no double-delivery); ZC-READERS 0 (the default, and always when
   *zerocopy-enabled* is nil) is the existing path verbatim. SHARED (WP-ZC-MULTI-DEST-REFCOUNT, ADR 0047;
   default NIL) is the per-pass cross-group CHANGE -> (slot . gen) table so a change reaching >=2 ZC destinations
   emits ONE shared slot's ref here instead of a fresh per-destination loan (byte-identical ref bytes)."
  ;; NFR-MEM fast path (ADR 0062, task #29): the common case — exactly ONE small non-ZC change (+ optional
  ;; trailing HB) to ONE destination (UDP or SHMEM) that fits a single budget-bounded datagram — is emitted
  ;; DIRECTLY, with none of %changes-datagram-plan's list / %pack-plan group / per-group closure / state-cons
  ;; allocation, AND without building the HEARTBEAT pack closure (%heartbeat-builder) — the HB submessage is
  ;; written inline via %write-hb-submessage. Byte-IDENTICAL to the plan path by construction: same header, the
  ;; same %write-change-submessage + %write-hb-submessage in the same order, and %pack-plan would put a
  ;; 4-aligned change followed by the 4-aligned HB (both within budget) in exactly ONE group. SHMEM-DEST is
  ;; passed through to %send-raw-buf unchanged (datagram BYTES are transport-independent). Any precondition
  ;; failing (>1 change, ZC, a pinned :data whose slot will not resolve, non-4-aligned or over-budget) falls
  ;; through to the plan path, which builds the HB closure lazily only there.
  (when (and *tx-fast-path* changes (null (cdr changes)) (zerop zc-readers)
             (null (disc-node-zc-pool node)))
    (let ((change (car changes)))
      (when (and (%small-change-p change)
                 (not (and *debug-drop-sample-numbers*
                           (member (dds.rtps.history:cache-change-sn change) *debug-drop-sample-numbers*)))
                 (or (not (eq (dds.rtps.history:cache-change-kind change) :data))
                     (%ensure-change-payload node change)))   ; resolve+cache a pinned slot; NIL -> fall through (plan drops it)
        (let ((size (%change-submessage-size change)))
          (when (and (zerop (mod size 4))                       ; 4-aligned -> %pack-plan would NOT force a boundary after it
                     (<= (+ size (if hb-first 32 0)) (%pack-budget buf)))   ; change (+ 32-octet HB) fit ONE datagram
            (let ((mc (dds.core.buffer:cursor buf :endianness :little))
                  (wid (%emit-wid node)))
              (dds.rtps.message:write-header mc (disc-node-guid-prefix node))
              (%write-change-submessage node change wid mc)
              (when hb-first (%write-hb-submessage hb-first hb-last hb-count wid mc))
              (%send-raw-buf node buf (dds.core.buffer:cursor-position mc) host port shmem-dest dest-prefix))
            (return-from %send-changes-packed t))))))
  (let ((state (cons (cons host port)
                     (%changes-datagram-plan node buf changes
                                             (and hb-first (%heartbeat-builder node hb-first hb-last hb-count))
                                             shmem-dest zc-readers shared))))
    (loop while (cdr state)   ; (cdr state) = the remaining datagram plan; NIL when exhausted
          do (setf state (nth-value 2 (%emit-next-datagram node buf state dest-prefix))))   ; T10: wrap to a keyed dest
    t))


(defun* %send-user-heartbeat (node buf first last count host port &optional dest-prefix)
    (function (disc-node dds.core.buffer:octet-buffer integer integer integer string (unsigned-byte 16)
               &optional (or null (simple-array (unsigned-byte 8) (12)))) t)
  "Send one NON-FINAL user-writer HEARTBEAT (FIRST,LAST,COUNT) to HOST:PORT (RTPS 2.5 §8.3.7.5;
   readerId = ENTITYID_UNKNOWN, FinalFlag NOT_SET per the Reliable StatefulWriter T7 transition §8.4.9.2.7),
   prompting the reader to ACKNACK. BUF selects the thread's scratch message buffer. DEST-PREFIX (default NIL,
   the 12-octet dest GUID-prefix) engages T10 whole-RTPS-message protection when that dest is :keyed."
  (%send-msg-buf node buf
                 (lambda (mc)
                   (dds.rtps.message:write-heartbeat
                    mc dds.rtps.message:+entityid-unknown+ (%emit-wid node) first last count :final nil))
                 host port dest-prefix))

(defun* %send-user-gap (node buf reader-id gap-sns host port &optional dest-prefix)
    (function (disc-node dds.core.buffer:octet-buffer (unsigned-byte 32) cons string (unsigned-byte 16)
               &optional (or null (simple-array (unsigned-byte 8) (12)))) t)
  "Send ONE GAP to HOST:PORT declaring every SN in the non-empty GAP-SNS list irrelevant (RTPS 2.5 §8.3.7.4 /
   §9.4.5.6): readerId = the NACKing reader's EntityId READER-ID, writerId = this user writer's EntityId. The
   SequenceNumberSet is built by seqnum-set-from-sns (shared MSB-first layout) and gapStart = its base, so the
   [gapStart, base) contiguous-prefix range is empty and the set is EXACTLY the bitmapped SNs. The gap SNs all
   came from ONE inbound ACKNACK's SequenceNumberSet, so they fit one 256-SN window. BUF selects the thread's
   scratch message buffer; mirrors %send-user-heartbeat (single-submessage send via %send-msg-buf). DEST-PREFIX
   (default NIL, the 12-octet dest GUID-prefix) engages T10 whole-RTPS-message protection when that dest is :keyed."
  (multiple-value-bind (base numbits bitmap) (dds.rtps.message:seqnum-set-from-sns gap-sns)
    (%send-msg-buf node buf
                   (lambda (mc)
                     (dds.rtps.message:write-gap
                      mc reader-id (%emit-wid node) base base numbits bitmap))
                   host port dest-prefix)))

(defun* %reader-push-targets (node &optional topic)
    (function (disc-node &optional (or null string)) list)
  "Per matched-reader DESTINATION, a ((host . port) READER-KEY…) group for the writer push path: the
   keys are the FULL 16-octet GUIDs of EVERY matched reader resolving to that (host . port) (RTPS 2.5
   §8.3.5.4 — a SN is unique only within one writer GUID, and the corresponding ACKNACK keys by the
   same remote reader GUID, %on-user-acknack). Two DataReaders in one remote participant share a
   unicast destination — a DATA with readerId UNKNOWN reaches both — so they are grouped, not deduped
   away: the push sends the union to the destination ONCE while advancing EACH reader's unsent-base
   (%merge-unsent, %push-data), keeping every co-located reader's send-once accounting honest. Falls
   back to the static PEERS (each carrying this node's local reader-id) ONLY when NO matched reader
   resolved to a destination (the discovery-less test path) — a :peers entry is an SPDP metatraffic
   BOOTSTRAP locator (FR-DISC-4), not a user-data destination, so once a real reader is matched its
   DEFAULT_UNICAST locator (§9.6.1.4) is the destination and the SPDP peer is NOT also blasted with user
   DATA (which a foreign peer binds on a different port from its user-data locator). WP-N-ENDPOINT-S1 (ADR 0048):
   when TOPIC is non-NIL, ONLY matched readers on that topic are targeted — the per-writer push filter so a
   participant's DataWriter reaches only its OWN readers, never a sibling writer's (RxO matches on topic-name).
   NIL TOPIC (the default / discovery-less value path) targets every matched reader, byte-identical to pre-S1.
   NFR-MEM (ADR 0062): MEMOIZED per TOPIC on the node (reader-push-cache), dropped WHOLESALE by
   %invalidate-dest-cache on match/unmatch/prune + an SPDP locator update — a STALE grouping is SILENT
   MIS-DELIVERY, so invalidation is coarse on purpose. The returned alist is SHARED (callers only READ it:
   %capture-push-groups reads (car group)=dest + (cdr group)=reader-keys; writer-capture-unsent reads the keys)."
  (multiple-value-bind (cached gen)
      (dds.pal:with-lock ((disc-node-lock node))
        (values (gethash topic (disc-node-reader-push-cache node) :none)
                (disc-node-match-dest-generation node)))
   (unless (eq cached :none)
     (return-from %reader-push-targets cached))
   (let ((groups '())   ; alist: (host . port) -> list of matched reader GUID keys at that destination
        (parts (%discovered-participants node)))
    (dolist (remote (%matched-endpoints node))
      (let ((guid (dds.rtps.discovery:endpoint-data-guid remote)))
        (when (and (%reader-guid-p guid)
                   (or (null topic) (string= topic (dds.rtps.discovery:endpoint-data-topic-name remote))))
          (let ((spdp (find (subseq guid 0 12) parts
                            :key #'dds.rtps.discovery:spdp-data-guid-prefix :test #'equalp)))
            (when spdp
              (let ((hp (%usable-destination spdp)))
                (when (and hp (plusp (cdr hp)))
                  (let ((cell (assoc hp groups :test #'equal)))
                    (if cell
                        (pushnew (copy-seq guid) (cdr cell) :test #'equalp)
                        (push (list hp (copy-seq guid)) groups))))))))))
    (when (null groups)   ; discovery-less ONLY: a :peers entry is an SPDP bootstrap locator, not a user-data dest
      (dolist (peer (disc-node-peers node))
        (unless (assoc peer groups :test #'equal)   ; dedup duplicate :peers entries
          (push (list peer (disc-node-user-reader-id node)) groups))))
    ;; STORE ONLY IF NO INVALIDATION RACED THE RESOLVE (the sub-reads take the node lock, so a match/unmatch/SPDP
    ;; can land between them); caching a now-stale grouping would be permanent silent mis-delivery.
    (dds.pal:with-lock ((disc-node-lock node))
      (when (= gen (disc-node-match-dest-generation node))
        (setf (gethash topic (disc-node-reader-push-cache node)) groups)))
    groups)))

(defun* %merge-unsent (writer keys)
    (function (dds.rtps.reliable:rtps-writer list) list)
  "The UNSENT CacheChanges to push ONCE to a destination shared by the readers KEYS, in ascending SN order
   (the SN-deduplicated union; advancing EACH reader's unsent-base so none re-pushes history on a later write,
   RTPS 2.5 §8.4.2.2 / §8.3.5.4 — one datagram per change reaches every reader at the destination via readerId
   UNKNOWN). The NET-ZERO inspection wrapper over the send-path writer-capture-unsent (DRY): it acquires a
   send-ref on each unique change then immediately RELEASES it, so the union + watermark advance are identical
   to the send path but NO send-ref is left held (this entry point does not itself emit). The send path
   (%push-data-buf / %node-datagram-plan) calls writer-capture-unsent directly and HOLDS the ref across the emit."
  (let ((changes (dds.rtps.reliable:writer-capture-unsent writer keys)))
    (dds.rtps.reliable:writer-release-change-refs writer changes)
    changes))

(defun* %group-shmem-dest (node group)
    (function (disc-node cons) t)
  "The SHMEM destination for a %reader-push-targets GROUP, or NIL — resolves the remote participant prefix
   from the group's reader keys (the first 12 octets of any matched-reader GUID at that destination, RTPS
   2.5 §9.3.1.2 / §8.3.5.4; every reader in one group shares a unicast (host . port), hence one participant
   prefix) and asks %shmem-dest whether that participant is a same-host SHMEM peer (FR-XPORT-2). NIL for the
   discovery-less PEERS fallback group (its key is this node's own reader-id, not a remote GUID) — those
   stay UDP."
  (let ((k (first (cdr group))))   ; a 16-octet GUID for a real matched reader; a u32 reader-id for the PEERS fallback
    (when (typep k '(simple-array (unsigned-byte 8) (16)))
      (%shmem-dest node (subseq k 0 12)))))

(defun* %group-dest-prefix (group)
    (function (cons) (or null (simple-array (unsigned-byte 8) (12))))
  "The 12-octet remote participant GUID-prefix of a %reader-push-targets GROUP (the first 12 octets of any
   matched-reader GUID at that destination — every reader in one group shares a unicast (host . port), hence one
   participant prefix; RTPS 2.5 §9.3.1.2 / §8.3.5.4), or NIL for the discovery-less PEERS fallback group (whose
   key is this node's own reader-id, not a remote GUID). Drives T10 whole-RTPS-message protection: a non-NIL
   prefix lets the user-data send wrap its datagrams when that participant is :keyed (NIL -> plain). Mirrors
   %group-shmem-dest's prefix resolution; allocates the prefix once per push group (off the per-sample hot path)."
  (let ((k (first (cdr group))))   ; a 16-octet GUID for a real matched reader; a u32 reader-id for the PEERS fallback
    (when (typep k '(simple-array (unsigned-byte 8) (16)))
      (subseq k 0 12))))

(defun* %reader-zc-capable-p (node reader-guid)
    (function (disc-node (simple-array (unsigned-byte 8) (16))) t)
  "T iff the matched remote reader with 16-octet READER-GUID is BOTH same-host SHMEM-reachable (its
   participant is a %shmem-dest peer — host-uuid match + a SHMEM receive segment) AND advertised
   PID_ZEROCOPY_CAPABLE in SEDP (WP-ZEROCOPY, FR-PF-3, ADR 0014). The endpoint-data is read from the
   matches table; off the hot path (called once per push group, not per sample). NIL on any miss."
  (let ((ep (dds.pal:with-lock ((disc-node-lock node))
              (gethash reader-guid (disc-node-matches node)))))
    (and ep
         (dds.rtps.discovery:endpoint-data-zerocopy-capable ep)
         (%shmem-dest node (subseq reader-guid 0 12))
         t)))

(defun* %zc-readers (node targets)
    (function (disc-node list) (integer 0))
  "WP-ZEROCOPY (FR-PF-3, ADR 0014): the count of reader keys in TARGETS (a %reader-push-targets group's
   cdr — 16-octet matched-reader GUIDs) that are same-host AND ZC-capable, when this node has a writer
   pool (the pool exists iff *zerocopy-enabled* was set at make-disc-node — gate on the SLOT, not the
   special, since the WP-ASYNC sender thread that also pushes cannot see a dynamic binding). 0 disables
   zero-copy for the group (the writer sends normal DATA — the no-double-delivery fallback), so the
   flag-off (no-pool) path is untouched."
  (if (disc-node-zc-pool node)
      (count-if (lambda (k)
                  (and (typep k '(simple-array (unsigned-byte 8) (16)))
                       (%reader-zc-capable-p node k)))
                targets)
      0))

(defun* %encode-zc-ref-vec (slot generation slot-bytes &optional (overlay 0))
    (function ((unsigned-byte 32) (unsigned-byte 32) (unsigned-byte 32) &optional (unsigned-byte 32))
              (simple-array (unsigned-byte 8) (20)))
  "Encode a 20-octet WP-ZEROCOPY SerializedPayload reference (encode-zc-reference) into a fresh vector.
   The 20-byte alloc is negligible against the large-sample payload copy it REPLACES; this file is not a
   measured hot path (the gated hot-path files are untouched). OVERLAY (default 0) is the reserved field:
   +zc-ref-overlay-secured+ marks the slot as holding a data_protection SecuredPayload (ADR 0051); 0 is
   byte-identical to every pre-change caller. ADR 0014, FR-PF-3."
  (let* ((v (make-array 20 :element-type '(unsigned-byte 8)))
         (c (dds.core.buffer:cursor (dds.core.buffer:octet-buffer-over v) :endianness :little)))
    (dds.cdr:encode-zc-reference c slot generation slot-bytes overlay)
    v))

(defun* %zc-ref-item (node sn slot gen &optional (overlay 0))
    (function (disc-node integer (integer 0) (unsigned-byte 32) &optional (unsigned-byte 32)) cons)
  "WP-ZEROCOPY/WP-FLATDATA-LOAN-WRITE shared ref-item tail (FR-PF-3/4, ADR 0014/0042; R6): the (SIZE . BUILD-FN)
   packable DATA item (SN) whose SerializedPayload is the 20-octet zero-copy reference to (SLOT, GEN) — drop-in
   for %data-builder so the ref rides the existing coalesced DATA path. Byte-identical to what %zc-ref-builder
   emitted before the factoring (%encode-zc-ref-vec + write-data, the SAME emitters — no wire constant invented);
   now ALSO consumed by the loan-write send site for a PRE-COMMITTED slot (ADR 0042). OVERLAY (default 0) marks a
   data_protection SecuredPayload slot (ADR 0051). Bumps zc-sends."
  (incf (disc-node-zc-sends node))
  (let ((ref (%encode-zc-ref-vec slot gen +zerocopy-pool-slot-bytes+ overlay))
        (wid (%emit-wid node)))
    (cons (+ 24 (length ref))   ; mirrors %data-builder's small-:data SIZE (4 hdr + 20 body-prefix + payload)
          (lambda (mc) (dds.rtps.message:write-data
                        mc dds.rtps.message:+entityid-unknown+ wid sn ref 0 (length ref))))))

(defun* %zc-ref-builder (node sn payload off len resolves &optional (overlay 0))
    (function (disc-node integer (simple-array (unsigned-byte 8) (*)) (integer 0) (integer 0) (integer 1)
              &optional (unsigned-byte 32)) (or null cons))
  "WP-ZEROCOPY (FR-PF-3, ADR 0014): loan PAYLOAD[off,off+len) into this node's writer pool with refcount
   RESOLVES (the number of times the slot will be resolved+released), and return the %zc-ref-item for the
   loaned slot (a (SIZE . BUILD-FN) packable DATA item carrying the 20-octet reference). Returns NIL if the
   pool is saturated / the payload exceeds a slot (%zc-loan NIL) so the caller falls back to the full
   serialized payload (no loss, no double-delivery). RESOLVES is ONE here: this ref is emitted to a SINGLE
   destination and a DATA with readerId UNKNOWN is processed ONCE by that participant's receiver
   (%on-user-data -> one %zc-release), regardless of how many reader endpoints are co-located there — so
   refcount 1 frees the slot after that single resolve (refcount = the matched-reader COUNT would leak the
   slot when a destination has >1 ZC reader endpoint). WP-FLATDATA-over-ZC (FR-PF-4, ADR
   0015): for a FlatData type the published PAYLOAD already IS the FlatData SerializedPayload (the type's
   serialize=IDENTITY block-copy ran once in %serialize-sample), so loaning it here is %zc-loan's single
   app-buffer->slot copy with NO per-field re-serialize — there is no second serialization on the FlatData
   TX path. (WP-FLATDATA-LOAN-WRITE, ADR 0042, removes even that copy for a loan-written change: its
   PRE-COMMITTED slot is emitted directly via %zc-armed-item, and this fresh-loan path serves the fallback +
   any extra destination.) OVERLAY (default 0) marks a data_protection SecuredPayload slot (ADR 0051). NOT
   cleared for ship — counsel (R6)."
  (multiple-value-bind (slot gen)
      (dds.xport.zerocopy::%zc-loan (disc-node-zc-pool-sap node) payload off len resolves)
    (when slot (%zc-ref-item node sn slot gen overlay))))

(defun* %zc-armed-item (node change)
    (function (disc-node dds.rtps.history:cache-change) (or null cons))
  "WP-FLATDATA-LOAN-WRITE send site (FR-PF-4, R6, ADR 0042; NOT cleared for ship — pending counsel). Consume
   CHANGE's PRE-COMMITTED Zero-Copy slot: writer-zc-claim wins the ONE-SHOT :armed -> :consumed transition under
   the writer lock (a concurrent emit on another thread can never double-spend the slot's single refcount) and
   returns the %zc-ref-item for (zc-slot, zc-generation) — the ref bytes are EXACTLY what %zc-ref-builder emits
   for a fresh loan (%encode-zc-ref-vec on the same emitters), but with NO payload->slot copy: the sample already
   sits in the slot, written there by the app's SAP-mode Offset setters (the loan-write 0-copy TX win). NIL when
   the claim is lost (no slot / already consumed or released) — the caller then takes the fresh-loan
   %zc-ref-builder path from the retained payload (byte-identical to today). After the claim the slot's
   refcount=1 belongs to the RESOLVING READER (its %zc-release at resolve/return-loan frees it); a retransmit of
   the consumed change falls back to the retained payload and never re-emits the slot (ADR 0042 lifecycle)."
  (let ((writer (disc-node-user-writer node)))
    (when (and writer (dds.rtps.reliable:writer-zc-claim writer change))
      (%zc-ref-item node (dds.rtps.history:cache-change-sn change)
                    (dds.rtps.history:cache-change-zc-slot change)
                    (dds.rtps.history:cache-change-zc-generation change)))))

(defstruct* (%zc-push-group (:constructor %make-zc-push-group))
  "WP-ZC-MULTI-DEST-REFCOUNT (FR-PF-4, R6, ADR 0047; NOT cleared for ship — pending counsel). One
   %reader-push-targets destination captured ONCE for a push pass: its (host . port) DEST, T10 DEST-PREFIX,
   SHMEM dest, same-host ZC-capable reader COUNT (%zc-readers), and the send-ref-held UNSENT CHANGES for it.
   Capturing every group into these bundles BEFORE any loan/emit is what makes the cross-group shared-ZC
   refcount EXACT — the count and the emit read the SAME frozen captured sets (ADR 0047 §crux)."
  (dest nil :type t)
  (dest-prefix nil :type (or null (simple-array (unsigned-byte 8) (12))))
  (shmem nil :type t)
  (zc-count 0 :type (integer 0))
  (changes '() :type list))

(defun* %capture-push-groups (node writer)
    (function (disc-node dds.rtps.reliable:rtps-writer) (values list list))
  "WP-ZC-MULTI-DEST-REFCOUNT (FR-PF-4, R6, ADR 0047; NOT cleared for ship — pending counsel). Capture EVERY
   %reader-push-targets destination's UNSENT set ONCE (writer-capture-unsent: advances each reader's unsent-base
   AND acquires a send-ref, exactly the per-group loop's semantics, just hoisted ahead of any emit), returning
   (values GROUPS ALL-CHANGES): GROUPS a list of %zc-push-group in %reader-push-targets order (so the per-group
   emit stays byte-order-identical), ALL-CHANGES the flat list of every captured change (one held send-ref each,
   released by the caller AFTER the emit / on plan drain — balanced). Freezing all captured sets up front is the
   whole stability argument: the shared-ZC emitter COUNT and the per-group EMIT read the SAME lists, so refcount
   = the exact number of receivers that each %zc-release once — no re-scan, no TOCTOU, no extra lock beyond the
   per-capture writer lock (ADR 0047 §crux/§stability)."
  (let ((groups '()) (all '()))
    (dolist (group (%reader-push-targets node (%writer-topic node writer)))   ; WP-N-ENDPOINT-S1: only THIS writer's readers
      (let ((changes (dds.rtps.reliable:writer-capture-unsent writer (cdr group))))
        (dolist (ch changes) (push ch all))
        (push (%make-zc-push-group :dest (car group)
                                   :dest-prefix (%group-dest-prefix group)
                                   :shmem (%group-shmem-dest node group)
                                   :zc-count (%zc-readers node (cdr group))
                                   :changes changes)
              groups)))
    (values (nreverse groups) all)))

(defun* %shared-loan-for (node writer change n)
    (function (disc-node dds.rtps.reliable:rtps-writer dds.rtps.history:cache-change (integer 2))
              (values (or null (integer 0)) (unsigned-byte 32)))
  "WP-ZC-MULTI-DEST-REFCOUNT (FR-PF-4, R6, ADR 0047; NOT cleared for ship — pending counsel). Loan ONE Zero-Copy
   slot for CHANGE to be shared across N (>=2) ZC-eligible destination GROUPS; returns (values SLOT GEN) for the
   shared ref, or (values NIL 0) to FALL BACK to today's per-destination fresh loans (always correct). For an
   :armed (loan-write) change: win the one-shot writer-zc-claim, then %zc-bump the pre-committed slot's DELIVERY
   hold from 1 to N (delta N-1, generation-guarded, the dual of %zc-release) — the ADR-0044 TX PIN, a DISTINCT
   hold, composes ADDITIVELY (refcount becomes N + optional-pin, freed by whichever release is last). A LOST claim
   (a concurrent emit already won it) -> NIL. A FAILED bump (unreachable for a slot held at refcount>=1) -> release
   the claimed hold + NIL (the change is now :consumed so the per-group path fresh-loans it). For a non-armed
   change: ONE %zc-loan readers=N from the change payload (%ensure-change-payload — a pinned change resolves on
   demand; a classic change is its retained/pooled payload, len = payload-len, T5a). Saturation (%zc-loan NIL) ->
   NIL. The later-emitted ref bytes are byte-identical to %zc-ref-builder / %zc-armed-item — only the slot is shared."
  (let ((sap (disc-node-zc-pool-sap node)))
    (cond
      ((null sap) (values nil 0))
      ((eq (dds.rtps.history:cache-change-zc-state change) :armed)
       (if (dds.rtps.reliable:writer-zc-claim writer change)
           (let ((slot (dds.rtps.history:cache-change-zc-slot change))
                 (gen (dds.rtps.history:cache-change-zc-generation change)))
             (if (dds.xport.zerocopy::%zc-bump sap slot gen (1- n))   ; delivery hold 1 -> N (ADR 0047; the pin composes additively)
                 (values slot gen)
                 (progn (dds.xport.zerocopy::%zc-release sap slot gen) (values nil 0))))   ; unreachable defense: undo the claimed hold, per-group fresh-loans
           (values nil 0)))   ; lost claim -> fall back
      (t (let ((pl (%ensure-change-payload node change)))
           (if (null pl)
               (values nil 0)
               (multiple-value-bind (slot gen)
                   (dds.xport.zerocopy::%zc-loan sap pl 0 (dds.rtps.history:cache-change-payload-len change) n)
                 (if slot (values slot gen) (values nil 0)))))))))

(defparameter +no-shared-zc-refs+ (make-hash-table :test 'eq :size 1)
  "The IMMUTABLE empty shared-ZC-ref table returned by %shared-zc-refs when no destination group is
   ZC-eligible (Zero-Copy off, or no ZC-capable peer — the common case). Callers only GETHASH the table, and
   an entry can only be added for a change reaching >=2 ZC-eligible groups, which cannot exist here — so
   returning this constant instead of consing a fresh pair of hash tables on EVERY send pass is
   observationally identical. NEVER write to it.")

(defun* %shared-zc-refs (node writer groups)
    (function (disc-node dds.rtps.reliable:rtps-writer list) hash-table)
  "WP-ZC-MULTI-DEST-REFCOUNT (FR-PF-4, R6, ADR 0047; NOT cleared for ship — pending counsel). The pool-economy
   optimization: build the per-pass CHANGE -> (SLOT . GEN) table so a change reaching >=2 ZC-eligible destination
   GROUPS is loaned ONCE (refcount = that GROUP count) and its SINGLE (slot, gen) ref is emitted to all N groups —
   saving N-1 slots + N-1 app->slot copies at fan-out. N is the ZC-eligible destination-GROUP count, NOT the
   %zc-readers endpoint count: a participant-receiver resolves a readerId-UNKNOWN DATA ONCE regardless of how many
   co-located ZC reader endpoints it has (%zc-ref-builder docstring), so counting endpoints would over-count and
   LEAK the slot (ADR 0047 §crux). A change appears in exactly those groups whose captured unsent set contains it
   (divergent late-joiner watermarks are handled EXACTLY — N counts only the emitting groups). N=1 is left to the
   per-group path (byte-identical to today); a lost claim / failed loan / failed bump adds no entry (per-group
   fresh-loan fallback). Runs BEFORE the per-group emit, over the frozen captured GROUPS, so the count is exact.
   WRITER scopes the ZC refcounting to ONE local writer's captured groups (WP-N-ENDPOINT-S1 fan-out)."
  ;; WP-PERF (NFR-MEM): fast-out when NO group is ZC-eligible — the overwhelmingly common case (Zero-Copy off,
  ;; or no ZC-capable destination). This built TWO hash tables on EVERY send pass regardless, ~1.6 KB/write for
  ;; a feature that was not in use: 46% of the write path's allocation in the sb-sprof :mode :alloc profile,
  ;; and that garbage is what drives the peer's GC — the pause that IS our 15-60x tail deficit
  ;; (bench/report/2026-07-13-the-tail-is-the-peers-gc.md). Callers only GETHASH the result, so the shared
  ;; empty table is indistinguishable from a freshly-consed one; it is never mutated on this path (a mutation
  ;; requires a >=2-group ZC-eligible change, which cannot exist when no group is ZC-eligible).
  (unless (some (lambda (g) (plusp (%zc-push-group-zc-count g))) groups)
    (return-from %shared-zc-refs +no-shared-zc-refs+))
  (let ((table (make-hash-table :test 'eq))
        (counts (make-hash-table :test 'eq)))
    (dolist (g groups)   ; count ZC-eligible emitter groups per shareable change (endpoints NEVER, groups)
      (when (plusp (%zc-push-group-zc-count g))
        (dolist (ch (%zc-push-group-changes g))
          (when (%zc-shareable-change-p node ch)
            (setf (gethash ch counts 0) (1+ (the fixnum (gethash ch counts 0))))))))
    (maphash (lambda (ch n)
               (when (>= n 2)   ; N=1 (single ZC dest) rides today's per-group path, byte-identical
                 (multiple-value-bind (slot gen) (%shared-loan-for node writer ch n)
                   (when slot (setf (gethash ch table) (cons slot gen))))))
             counts)
    table))

(declaim (ftype (function (disc-node dds.core.buffer:octet-buffer dds.rtps.reliable:rtps-writer) t)
                %push-one-writer-changes))   ; WP-N-ENDPOINT-S1: defined below %push-data-buf, called by it (forward ref)

(defun* %push-data-buf (node buf)
    (function (disc-node dds.core.buffer:octet-buffer) t)
  "Writer side: send each UNSENT change ONCE as a DATA (or DATA_FRAG series for large samples)
   submessage, COALESCED with the trailing HEARTBEAT into as few datagrams as fit the budget
   (%send-changes-packed, RTPS 2.5 §8.3.4/§8.4.2.2), to each matched-reader DESTINATION, using BUF as the
   scratch message buffer (tx-msg on the caller thread; async-tx-msg on the WP-ASYNC sender thread — each
   thread owns its buffer). The unsent-base watermark is kept PER matched reader (keyed by its full GUID,
   §8.3.5.4); %merge-unsent advances every reader sharing a destination and sends their union once. Lost
   or late changes are repaired only via the reader's ACKNACK (%on-user-acknack). When a destination is a
   same-host SHMEM peer (%group-shmem-dest) the coalesced small-sample datagrams take shared memory with
   UDP fallback (FR-XPORT-2); the reader's ACKNACK return path is UDP (%on-user-heartbeat, untouched).
   When the destination's readers are same-host ZC-capable (%zc-readers > 0, WP-ZEROCOPY FR-PF-3) a large
   :data sample crosses as a 16-byte reference instead of a fragmented payload; ZC off -> 0 -> untouched.
   WP-FLATDATA-LOAN-WRITE leak sweep (ADR 0042): the armed-change registry is SNAPSHOT before the pass and
   %zc-armed-sweep'd after it — any pre-committed slot the pass never consumed/released (zero destinations,
   debug-drop, evicted-before-push) is released here, so a committed slot never strands past one push pass;
   changes armed concurrently by a mid-pass publish survive to their own pass (the snapshot discipline).
   WP-ZC-MULTI-DEST-REFCOUNT (ADR 0047): every group is CAPTURED once up front (%capture-push-groups) and the
   cross-group shared-ZC ref table (%shared-zc-refs) is built from those frozen sets BEFORE any emit, so a change
   reaching >=2 co-resident ZC destinations shares ONE pool slot (refcount = the ZC-group count) instead of one
   fresh loan per destination; the send-refs are all released once after the whole emit (strictly release-safe)."
  ;; WP-N-ENDPOINT-S1 (ADR 0048): fan out over %all-user-writers so EACH local DataWriter pushes its OWN unsent
  ;; changes + HEARTBEATs; at N=1 the sole writer IS the primary -> byte-identical to the pre-fan-out path. The
  ;; node-global armed-change leak sweep (ZC) is snapshotted once before the fan-out + swept once after.
  (let ((armed (dds.pal:with-lock ((disc-node-lock node)) (disc-node-zc-armed-changes node))))   ; snapshot (ADR 0042)
    (dolist (cell (disc-node-user-writers node))   ; iterate the registry alist directly — no per-push cons (NFR-MEM); N=1 = one writer
      (%push-one-writer-changes node buf (cdr cell)))
    (%zc-armed-sweep node armed)))   ; ADR 0042: release any slot the pass never consumed/released

(defun* %push-one-writer-changes (node buf writer)
    (function (disc-node dds.core.buffer:octet-buffer dds.rtps.reliable:rtps-writer) t)
  "Emit ONE local user WRITER's unsent changes (DATA/DATA_FRAG) coalesced with its trailing HEARTBEAT to each of
   its matched-reader destinations (WP-N-ENDPOINT-S1 fan-out unit; the pre-S1 single-writer %push-data-buf body).
   Captures the writer's push groups once, builds its cross-group shared-ZC ref table, emits, then releases every
   send-ref after the datagrams are copied out (release-safety, operating contract §4). Binds *emit-writer-entityid*
   so every DATA/HEARTBEAT it emits carries THIS writer's own EntityId (WP-N-ENDPOINT-S1)."
  (let ((*emit-writer* writer))   ; WP-N-ENDPOINT-S1: stamp + source (HEARTBEAT_FRAG) from this writer's own GUID/HC
    (multiple-value-bind (first last count) (dds.rtps.reliable:writer-heartbeat writer)
      (let ((targets (and *tx-single-group* (%reader-push-targets node (%writer-topic node writer)))))
        (if (and targets (null (cdr targets)))
            ;; NFR-MEM single-destination fast path (ADR 0062): exactly ONE %reader-push-targets group -> capture
            ;; + emit DIRECTLY, with none of %capture-push-groups' %zc-push-group struct / groups / all-changes
            ;; allocation. The ADR 0047 cross-group freeze is a no-op with one group (no change reaches >=2
            ;; groups), so the shared-ZC ref table is +no-shared-zc-refs+ — byte-identical to the general path.
            (let* ((group (car targets))
                   (dest (car group))
                   (changes (dds.rtps.reliable:writer-capture-unsent writer (cdr group))))
              (unwind-protect
                   (%send-changes-packed node buf changes
                                         (car dest) (cdr dest)
                                         first last count
                                         (%group-shmem-dest node group)
                                         (%zc-readers node (cdr group))
                                         (%group-dest-prefix group)
                                         +no-shared-zc-refs+)
                (dds.rtps.reliable:writer-release-change-refs writer changes)))
            ;; general path: freeze EVERY destination's unsent set up front (ADR 0047 stability) before any emit
            (multiple-value-bind (groups all-changes) (%capture-push-groups node writer)   ; ADR 0047: freeze every dest's unsent set once
              (let ((shared (%shared-zc-refs node writer groups)))   ; ADR 0047: one slot per change reaching >=2 ZC dests (exact refcount)
                (unwind-protect
                     (dolist (g groups)   ; DATA + HEARTBEAT -> each matched-reader destination, in %reader-push-targets order
                       (%send-changes-packed node buf
                                             (%zc-push-group-changes g)
                                             (car (%zc-push-group-dest g)) (cdr (%zc-push-group-dest g))
                                             first last count   ; raw HB -> written inline on the fast path (no per-send closure); the plan path builds it lazily
                                             (%zc-push-group-shmem g)
                                             (%zc-push-group-zc-count g)
                                             (%zc-push-group-dest-prefix g)   ; T10: wrap user data to a :keyed destination
                                             shared))
                  (dds.rtps.reliable:writer-release-change-refs writer all-changes)))))))) ; release all send-refs after every destination's datagrams are emitted (copied)
  t)

(defun* %push-data (node)
    (function (disc-node) t)
  "Push unsent changes on the caller thread using tx-msg (the synchronous send path)."
  (%push-data-buf node (disc-node-tx-msg node)))

(defun* %node-datagram-plan (node writer buf)
    (function (disc-node dds.rtps.reliable:rtps-writer dds.core.buffer:octet-buffer) (values list list))
  "The FULL per-datagram send-plan for the explicit WRITER across ALL its matched-reader destinations — a flat
   list of ((HOST . PORT) DEST-PREFIX BUILD-THUNK . SHMEM-DEST) entries, in the SAME order, with the SAME datagram
   bytes, that %push-one-writer-changes' flush-all would send (it walks %reader-push-targets in the same order and
   each group's plan is %changes-datagram-plan). The unsent watermark is captured ONCE here
   (writer-capture-unsent advances each reader's unsent-base exactly as flush-all does, AND acquires a send-ref
   on each captured change — held until the plan drains, %flow-step-advance, release-safety) — so the scheduler
   must build this plan once and then step it, never rebuild mid-drain (that would re-read an already-advanced
   watermark and send nothing). Returns (values PLAN CAPTURED-CHANGES): the caller stores both on the per-writer
   flow-state (WP-N-ENDPOINT-S1B — no node-single slot, so N writers of one participant drain independently). The
   build runs under *emit-writer* = WRITER so every DATA/HEARTBEAT/HEARTBEAT_FRAG carries THIS writer's own EntityId
   + is sourced from its OWN HistoryCache (RTPS 2.5 §9.3.1.2 / §9.4.5.5); at N=1 the sole writer IS the primary, so
   the wire is byte-identical to the pre-S1B single-writer plan. The seam the Phase-C FlowController scheduler
   drives: build the plan (capturing the unsent set), then for each entry build into a scratch buffer (the thunk
   reports the token cost = datagram length), acquire that many tokens, and send — one datagram per step. BUF
   supplies only the packing budget. WP-ZC-MULTI-DEST-REFCOUNT (ADR 0047): the destinations are CAPTURED once
   (%capture-push-groups) and the cross-group shared-ZC ref table (%shared-zc-refs) is built from those frozen sets
   BEFORE the per-group plan build, so a change reaching >=2 co-resident ZC destinations shares ONE slot (refcount
   = the ZC-group count); the ref bytes are already materialized in the plan closures, so the armed sweep after the
   build is unchanged."
  (let ((*emit-writer* writer)   ; WP-N-ENDPOINT-S1B: stamp + source every submessage from THIS writer's GUID/HC
        (armed (dds.pal:with-lock ((disc-node-lock node)) (disc-node-zc-armed-changes node)))   ; snapshot (ADR 0042)
        (plan '()) (captured '()))
    (multiple-value-bind (first last count) (dds.rtps.reliable:writer-heartbeat writer)
      (multiple-value-bind (groups all-changes) (%capture-push-groups node writer)   ; ADR 0047: freeze every dest's unsent set once
        (let ((shared (%shared-zc-refs node writer groups)))   ; ADR 0047: one slot per change reaching >=2 ZC dests (exact refcount)
          (dolist (g groups)
            (let ((dest (%zc-push-group-dest g)) (dp (%zc-push-group-dest-prefix g)))   ; T10: the group's :keyed-dest prefix | nil
              (dolist (entry (%changes-datagram-plan node buf (%zc-push-group-changes g)
                                                     (%heartbeat-builder node first last count)
                                                     (%zc-push-group-shmem g)
                                                     (%zc-push-group-zc-count g)
                                                     shared))
                (push (cons dest (cons dp entry)) plan))))   ; ((host . port) DEST-PREFIX BUILD-THUNK . SHMEM-DEST)
          (setf captured all-changes))))   ; release-on-drain set: one entry per capture (balanced)
    (%zc-armed-sweep node armed)   ; ADR 0042: the ref bytes are already materialized in the plan's closures — sweep any slot the plan build never consumed/released
    (values (nreverse plan) captured)))

(defun* %emit-plan-entry (node buf entry &optional before-send)
    (function (disc-node dds.core.buffer:octet-buffer cons &optional (or null function)) (integer 0))
  "Build ONE node-plan ENTRY — a ((HOST . PORT) DEST-PREFIX BUILD-THUNK . SHMEM-DEST) from %node-datagram-plan —
   into BUF (the thunk writes the datagram and returns its octet length) and send it, returning the length. The
   build-then-send SEAM for the Phase-C FlowController scheduler: BEFORE-SEND, when supplied, is called with
   the just-built datagram's LENGTH AFTER the build but BEFORE the %send-raw-buf — so the scheduler interposes
   its token acquire(length) there (build → acquire → send), the built datagram simply held in BUF across any
   deficit wait, never rebuilt. This is the single place that knows the entry cons-shape (DRY): %flow-step-emit
   passes no BEFORE-SEND (build+send); the scheduler passes its acquire hook. DEST-PREFIX threads to %send-raw-buf
   for T10 whole-RTPS-message protection (the datagram is wrapped when that dest is :keyed; NIL -> plain). The
   token cost is the PLAIN built length; the ~56-octet SRTPS overhead is not separately token-charged (a benign
   soft-pacing under-charge, off the wire-correctness path)."
  (let* ((dest (car entry)) (dest-prefix (cadr entry)) (thunk (caddr entry)) (shmem-dest (cdddr entry))
         (len (funcall thunk buf)))
    (when before-send (funcall before-send len))
    (%send-raw-buf node buf len (car dest) (cdr dest) shmem-dest dest-prefix)
    len))

(defun* %flow-release-step-refs (ws)
    (function (flow-writer-state) t)
  "Release the send-refs %node-datagram-plan acquired at the last snapshot (FLOW-WRITER-STATE-STEP-REFS) and clear
   the slot — the DEFERRED-emit half of the operating contract §4 release-safety: the paced/async plan HELD a
   send-ref on each captured change from snapshot until the plan DRAINED, so a pooled payload (T5a) cannot be
   recycled mid-drain. Idempotent (a NIL slot releases nothing; the floored decrement tolerates a double call).
   Single-mutator: only the thread draining the plan runs it (the scheduler thread for an associated writer, or
   the %flow-step-emit caller). Per-writer (WP-N-ENDPOINT-S1B): each writer's refs release when ITS plan drains,
   so one writer's mid-drain snapshot never holds another writer's changes."
  (let ((writer (flow-writer-state-writer ws))
        (refs (flow-writer-state-step-refs ws)))
    (when (and writer refs)
      (dds.rtps.reliable:writer-release-change-refs writer refs))
    (setf (flow-writer-state-step-refs ws) nil))
  t)

(defun* %flow-step-advance (ws plan)
    (function (flow-writer-state list) list)
  "Advance writer-state WS's flow-step plan past the just-emitted head PLAN: set STEP-STATE to PLAN's tail and,
   when the plan has now DRAINED (tail NIL), release the snapshot's captured send-refs (%flow-release-step-refs).
   The single drain choke point shared by %flow-step-emit AND the flow-controller scheduler (DRY) so BOTH
   deferred-emit drivers release the held refs exactly when the last datagram of a snapshot has been emitted
   (release-safety, operating contract §4). Returns the tail."
  (let ((next (cdr plan)))
    (setf (flow-writer-state-step-state ws) next)
    (unless next (%flow-release-step-refs ws))
    next))

(defun* %flow-step-emit (ws buf)
    (function (flow-writer-state dds.core.buffer:octet-buffer) (values (integer 0) t))
  "WP-ASYNC-FLOW STEP entry (FR-PF-2; WP-N-ENDPOINT-S1B per-writer): build + send the NEXT single datagram for
   writer-state WS's writer across its matched-reader push-targets, returning (values BYTES-SENT MORE-REMAIN-P).
   The first call (when STEP-STATE is NIL) snapshots THIS writer's datagram plan (%node-datagram-plan on WS's
   explicit writer, capturing the unsent set + its send-refs ONCE — the watermark advances here, not per step);
   each call thereafter emits exactly ONE datagram (%emit-plan-entry) from the cached plan and advances it; when
   the plan drains, STEP-STATE is cleared so the next call re-snapshots any newly-unsent changes. MORE-REMAIN-P
   is T while the current plan still holds datagrams. The build+emit run under *emit-writer* = WS's writer.
   Returns (values 0 NIL) when there is nothing to send. Wire-invisible: pacing changes only WHEN a datagram is
   sent (ADR 0016). BUF is the caller thread's scratch buffer."
  (let ((*emit-writer* (flow-writer-state-writer ws))   ; WP-N-ENDPOINT-S1B: this writer's own GUID/HC across build+emit
        (node (flow-writer-state-node ws)))
    (when (null (flow-writer-state-step-state ws))
      (multiple-value-bind (plan refs) (%node-datagram-plan node (flow-writer-state-writer ws) buf)
        (setf (flow-writer-state-step-state ws) plan (flow-writer-state-step-refs ws) refs)))
    (let ((plan (flow-writer-state-step-state ws)))
      (if (null plan)
          (progn (setf (flow-writer-state-step-state ws) nil) (values 0 nil))
          (let ((len (%emit-plan-entry node buf (car plan))))
            (%flow-step-advance ws plan)   ; advance + release the snapshot's send-refs when the plan drains (release-safety)
            (values len (and (cdr plan) t)))))))

(defun* %push-heartbeat (node)
    (function (disc-node) (eql t))
  "Writer side: send a PERIODIC standalone non-final HEARTBEAT (no new DATA) to each matched
   reader on the announce cadence (RTPS 2.5 §8.4.2.2: a reliable Writer must periodically inform
   each matching reliable Reader of the availability of a sample; Reliable StatefulWriter T7
   transition §8.4.9.2.7). This closes the lost-final-sample edge: when a reliable writer's final sample's
   DATA was lost and no further write follows, nothing else re-prompts the reader to NACK, so the
   gap is never repaired; the periodic HEARTBEAT keeps reliability live and triggers the ACKNACK
   repair path. Non-final (FinalFlag NOT_SET) so it solicits an ACKNACK. A no-op on an empty
   HistoryCache (LAST < FIRST), no user writer, or no matched readers (uses tx-msg, caller thread).
   WP-N-ENDPOINT-S1 (ADR 0048): fans out over %all-user-writers so EACH local DataWriter emits its OWN periodic
   HEARTBEAT (its own SN range); at N=1 the sole writer IS the primary, byte-identical to the pre-fan-out path."
  (dolist (cell (disc-node-user-writers node))   ; iterate the registry alist directly — no per-cadence cons (NFR-MEM)
    (let* ((w (cdr cell))
           (*emit-writer* w))   ; WP-N-ENDPOINT-S1: this writer's own GUID/HC
      (multiple-value-bind (first last count) (dds.rtps.reliable:writer-heartbeat w)
        (when (>= last first)
          (dolist (pd (%match-destinations-prefixed node t))   ; (DEST-PREFIX . (host . port)); T10 wraps a :keyed dest
            (%send-user-heartbeat node (disc-node-tx-msg node) first last count (cadr pd) (cddr pd) (car pd)))))))
  t)

(defun* %writer-durability-init (node reader-guid reader-durability &optional writer-id)
    (function (disc-node (simple-array (unsigned-byte 8) (16))
               (member :volatile :transient-local :transient :persistent)
               &optional (or null (unsigned-byte 32))) (eql t))
  "Writer-side late-joiner proxy init for a newly matched remote reader (DDS 1.4 §2.2.3.4, RTPS 2.5
   §8.4.2.2). Called once at match time from the DCPS on-match hook — on the RECEIVER thread, so every send
   here uses the node's rx-tx-msg buffer, never tx-msg (the announce/caller thread's, dataplane.lisp §top).
   READER-GUID = the matched handle; READER-DURABILITY = the remote reader's advertised DURABILITY.
   WP-N-ENDPOINT-S2B (ADR 0048): WRITER-ID selects the MATCHED local writer (the one whose topic RxO-matched
   this reader) — its OWN HistoryCache, advertised durability, and GUID; *emit-writer* is bound to it so the
   prompt HEARTBEAT (%emit-wid) carries THIS writer's EntityId, not the primary's. So N durable writers each
   replay their OWN retained history to a matched late reader. NIL (or unregistered) -> the primary
   (byte-identical N=1). When BOTH this writer (its advertised DURABILITY) AND the reader are TRANSIENT_LOCAL,
   initialize the reader's ReaderProxy UNSENT-BASE to firstSN (hc-min-seq) so the existing push
   (writer-unsent-list) REPLAYS the entire retained history, then send a prompt HEARTBEAT [firstSN,lastSN] so it
   ACKNACKs and the existing retransmit path delivers the history — to that reader's participant alone when its
   unicast destination is resolved (by the 12-octet GUID prefix), else fanned out to every matched-reader
   destination (each reader NACKs only its own gaps). firstSN/lastSN/count are taken from a SINGLE
   writer-heartbeat call (one lock, one consistent snapshot — no torn read vs a concurrent write/purge).
   Otherwise (a VOLATILE writer or a VOLATILE reader) init UNSENT-BASE to lastSN+1 — future-only, the effective
   pre-WP behavior (a new reader never gets the pre-existing history). A no-op (still returns T) when there is no
   user writer. Sets only the push watermark; the ACKNACK repair watermark (acked-base) is left at its default
   (independent, §8.4.2.2)."
  (let ((w (%resolve-user-writer node writer-id)))
    (when w
      (let ((*emit-writer* w))   ; the prompt HB (%emit-wid) carries THIS matched writer's EntityId, not the primary's
        (multiple-value-bind (first last count) (dds.rtps.reliable:writer-heartbeat w)   ; one locked snapshot
          (let* ((tl-tl (and (eq reader-durability :transient-local)
                             (eq (%local-writer-durability node (dds.rtps.reliable:rtps-writer-entityid w))
                                 :transient-local)))
                 (base (if tl-tl first (1+ last))))
            (dds.rtps.reliable:init-reader-proxy-base w reader-guid base)
            (when (and tl-tl (>= last first))              ; retained history exists -> prompt a NACK
              (let* ((prefix (subseq reader-guid 0 12))
                     (dest (%prefix-user-destination node prefix))
                     ;; (DEST-PREFIX . (host . port)) entries (T10): the resolved reader's prefix, or the prefixed fan-out
                     (peers (if dest (list (cons prefix dest)) (%match-destinations-prefixed node t))))
                (dolist (pd peers)
                  (%send-user-heartbeat node (disc-node-rx-tx-msg node) first last count
                                        (cadr pd) (cddr pd) (car pd)))))))))) ; T10: wrap the prompt HB to a :keyed reader
  t)

(defun* %reader-durability-init (node writer-guid writer-durability)
    (function (disc-node (simple-array (unsigned-byte 8) (16))
               (member :volatile :transient-local :transient :persistent)) (eql t))
  "Reader-side late-joiner gate for a newly matched remote writer (DDS 1.4 §2.2.3.4, RTPS 2.5 §8.4.2.2).
   Called once at match time from the DCPS on-match hook. WRITER-GUID = the matched handle;
   WRITER-DURABILITY = the remote writer's advertised DURABILITY. SKIP iff this reader is VOLATILE AND the
   writer is a RETAINING durability (TRANSIENT_LOCAL / TRANSIENT / PERSISTENT — RxO admits a non-volatile
   writer matching a VOLATILE reader, offered-rank >= requested-rank): then the reader SKIPS the writer's
   advertised pre-match history (init-writer-proxy-durability SKIP-HISTORY T → the first HEARTBEAT advances
   the WriterProxy firstSN to lastSN+1, NACKing only future gaps) — the behavior-defining branch: a VOLATILE
   reader must NOT pull a TRANSIENT_LOCAL writer's retained history even though it is advertised. In EVERY
   other admitted combination — a TRANSIENT_LOCAL reader (matched a retaining writer → REQUEST the history)
   AND, crucially, VOLATILE-reader<->VOLATILE-writer — SKIP-HISTORY is NIL: byte-identical to before this WP,
   so a VOLATILE reader against a VOLATILE writer still NACKs a dropped LIVE sample (a VOLATILE writer
   retains no history to wrongly pull; gating the skip on a RETAINING writer is what keeps reliable
   drop-recovery intact). A no-op (still T) when there is no user reader. Mirrors %writer-durability-init;
   sets ONLY the reader-side gate (no send here — the answering ACKNACK rides the existing
   %on-user-heartbeat path)."
  (let ((r (disc-node-user-reader node)))
    (when r
      (let ((skip (and (eq (%local-reader-durability node) :volatile)
                       (not (eq writer-durability :volatile)))))   ; VOLATILE reader skips a RETAINING writer
        (dds.rtps.reliable:init-writer-proxy-durability r writer-guid skip))))
  t)

(defun* %async-signal (node)
    (function (disc-node) t)
  "WP-ASYNC: mark work pending and wake the sender thread (the reliable unsent-list IS the queue; the
   sender flushes ALL unsent on wake). Guarded by async-lock."
  (dds.pal:with-lock ((disc-node-async-lock node))
    (setf (disc-node-async-pending node) t)
    (dds.pal:condvar-signal (disc-node-async-cv node)))
  t)

(defun* %async-sender-loop (node)
    (function (disc-node) t)
  "WP-ASYNC sender thread (FR-PF-2): wait for a publish/dispose signal (or shutdown), then flush ALL
   unsent changes on the node's OWN async-tx-msg buffer (%push-data-buf). The async-lock is RELEASED
   before the send (which takes the reliable writer lock) so there is no nested-lock deadlock; the 0.5 s
   wait timeout means a missed signal cannot wedge shutdown. On async-stop, drains a final flush + exits."
  (loop
    (let ((stop nil))
      (dds.pal:with-lock ((disc-node-async-lock node))
        (loop until (or (disc-node-async-stop node) (disc-node-async-pending node))
              do (dds.pal:condvar-wait (disc-node-async-cv node) (disc-node-async-lock node) 0.5))
        (setf stop (disc-node-async-stop node)
              (disc-node-async-pending node) nil))
      (when (disc-node-user-writer node)
        (with-sender-emit-guard (:async-sender (disc-node-async-emit-errors node))
          (%push-data-buf node (disc-node-async-tx-msg node))))
      (when stop (return))))
  t)

(defun* enable-async (node)
    (function (disc-node) disc-node)
  "WP-ASYNC (FR-PF-2): give NODE a background SENDER thread so publish-sample returns without blocking on
   the socket. Idempotent. The sender owns its own async-tx-msg scratch buffer (the app thread keeps
   tx-msg, the receiver keeps rx-tx-msg). Call after enable-publisher; stop-node joins + drains it. With
   async on, publish/dispose SIGNAL the sender (the flush-all is adaptive batching); batch-max-samples is
   superseded."
  (unless (disc-node-async-thread node)
    (setf (disc-node-async-tx-msg node) (dds.core.buffer:make-octet-buffer *max-datagram-bytes*)
          (disc-node-async-stop node) nil
          (disc-node-async-pending node) nil
          (disc-node-async-thread node)
          (dds.pal:spawn (lambda () (%async-sender-loop node)) :name "dds-async-sender")))
  node)

(defun* flush-batch (node)
    (function (disc-node) (eql t))
  "WP-BATCH time/explicit trigger (FR-PF-1): if any batched samples are pending, push them now (coalesced)
   and reset the pending counter. A no-op when nothing is pending. Called on the announce cadence (so a
   partial batch is never stranded) and on stop-node. In WP-ASYNC mode the sender thread does the push, so
   this just signals it."
  (when (plusp (disc-node-batch-pending node))
    (setf (disc-node-batch-pending node) 0)
    (if (disc-node-async-thread node) (%async-signal node) (%push-data node)))
  t)

(defun* %local-writer-guid-vec (node &optional (entity-id (disc-node-user-writer-id node)))
    (function (disc-node &optional (unsigned-byte 32)) (simple-array (unsigned-byte 8) (16)))
  "The 16-octet local user-data writer GUID (prefix + ENTITY-ID, RTPS 2.5 §9.3.1.2) — the encode-key resolution key
   for the crypto-keys resolver (T6). WP-N-ENDPOINT-S3 (ADR 0048): ENTITY-ID is the ACTUAL publishing writer's
   EntityId (the send-crux — each secured writer resolves its OWN EntityCrypto km, never the node-single writer's);
   it defaults to the node-single user-writer-id (byte-identical N=1)."
  (let ((g (make-array 16 :element-type '(unsigned-byte 8) :initial-element 0)))
    (replace g (disc-node-guid-prefix node) :end2 12)
    (let ((id entity-id))
      (setf (aref g 12) (ldb (byte 8 24) id)
            (aref g 13) (ldb (byte 8 16) id)
            (aref g 14) (ldb (byte 8  8) id)
            (aref g 15) (ldb (byte 8  0) id)))
    g))

(defun* publish-sample (node payload &optional (key-hash nil) (zc-slot nil) (zc-gen 0) (zc-len nil) (writer-id nil) (source-timestamp nil) (in-pooled nil) (in-plen nil))
    (function (disc-node (or null (simple-array (unsigned-byte 8) (*)))
               &optional (or null (array (unsigned-byte 8) (*))) (or null (integer 0)) (unsigned-byte 32)
                         (or null (integer 0)) (or null (unsigned-byte 32)) (or null integer)
                         t (or null (integer 0)))
              (or (eql t) (eql :timeout)))
  "Publish PAYLOAD (an opaque SerializedPayload) on the node's user writer: add it to the writer
   HistoryCache, then push DATA + HEARTBEAT to peers (FR-RTPS-8). Returns T normally, or the :timeout
   sentinel (RETCODE_TIMEOUT) if the writer's cache was full and block-up-to-max_blocking_time elapsed
   without freeing a slot — WP-ASYNC-FLOW backpressure (FR-PF-2/FR-QOS, ADR 0016 §Backpressure; only a
   writer enable-publisher'd with a finite :max-samples + :max-blocking-ns can return :timeout, so the
   default path is byte-identical). On :timeout the change was NOT added, so nothing is pushed/signalled
   and no flow/batch state advances (the cache is intact). With WP-BATCH (batch-max-samples > 1,
   FR-PF-1/NFR-PERF-4) the push is DEFERRED — the write accumulates and the batch flushes only when
   batch-max-samples have accumulated (size trigger) or flush-batch fires (time/cadence trigger), so N
   small samples go out coalesced in few datagrams with one amortized HEARTBEAT. Default
   batch-max-samples=1 flushes every write (unchanged behaviour). With WP-ASYNC (enable-async, FR-PF-2)
   the write returns immediately after signalling the sender thread, which does the push off the caller
   thread (the sender's flush-all is adaptive batching, superseding batch-max-samples). With WP-ASYNC-FLOW
   (a flow-controller associated, FR-PF-2, ADR 0016) the write returns immediately after marking the writer
   pending + signalling the controller, whose scheduler thread does the RATE-PACED push off the caller
   thread (an associated controller supersedes both batch and the per-node async sender for that writer).
   WP-N-ENDPOINT-S1B: the paced tail resolves THIS write's per-writer flow-state via %resolve-user-writer +
   %flow-writer-state-for — two O(N-local-writers) alist walks (allocation-free; opt-in flow-ON only, the
   flow-OFF default never reaches this branch and is byte-identical), an accepted O(N) control-plane cost.
   KEY-HASH (WP-KEEPLAST, ADR 0019, DDS 1.4 §2.2.3.18) is the sample's 16-octet instance handle threaded
   onto the data CacheChange (writer-write) for per-instance KEEP_LAST eviction; NIL (default) is unchanged.
   When KEY-HASH is non-nil and exactly 16 octets, a PID_KEY_HASH inline-QoS block is also built
   (%build-key-hash-iq) and carried on the DATA submessage (RTPS 2.5 §9.6.4.8), mirroring the wire
   behaviour of Connext 7.3.1 and Fast DDS 3.6.1 on keyed writes (ADR 0029). NIL KEY-HASH = byte-identical.
   ZC-SLOT / ZC-GEN (WP-FLATDATA-LOAN-WRITE, FR-PF-4, R6, ADR 0042; default NIL = byte-identical): the
   PRE-COMMITTED Zero-Copy pool slot PAYLOAD's bytes already sit in (loan-write wrote the sample straight into
   the slot and committed it; refcount=1 held). The data CacheChange is BORN :armed with the slot identity and
   registered for the leak sweep; the send site (%zc-change-item) then emits the slot's ref ONCE to the first
   ZC-eligible destination with NO payload->slot copy, or releases the slot on its fallback decision. On
   :timeout (nothing added -> the slot could never be emitted) the slot is released here. FAIL-SAFE (unreachable
   through the DCPS loan gate): under data_protection the payload below is TRANSFORMED, so a pre-committed
   plaintext slot must never be emitted — it is released up front and the publish proceeds payload-only.
   ZC-LEN + a NIL PAYLOAD (WP-ACKED-SLOT-PINNING, FR-PF-4, R6, ADR 0044): a PIN REQUEST — a committed slot with
   NO retained payload (write-loaned skipped %loan-write-payload for a pin-capable writer). A pin-budget slot is
   reserved + a SECOND refcount hold taken (%zc-pin) so the slot outlives the HistoryCache change and serves
   retransmit / non-ZC / extra-ZC on demand (the pin drops at the full-ACK purge); at budget (or a stale slot) the
   retained payload is materialised on demand from the still-armed slot (byte-identical to %loan-write-payload)
   and the publish proceeds as a normal change (the always-correct fallback, ADR 0044 §2).
   WRITER-ID (WP-N-ENDPOINT-S1, ADR 0048; default NIL = byte-identical) selects WHICH local user DataWriter's
   engine writer receives the change: the node's registered engine writer for that EntityId (%user-writer-for),
   so a participant's 2nd/N-th DataWriter writes into its OWN HistoryCache + per-writer SN space instead of
   aliasing the primary. NIL (or an unregistered id) resolves to the primary — the pre-S1 single-writer path."
  (when (and zc-slot (%loan-write-data-protected-p node))
    (when (disc-node-zc-pool-sap node)   ; fail-safe: never emit a plaintext slot for a data_protection writer
      (when (null payload)   ; a pin request would leave NO payload — recover it before dropping the slot
        (setf payload (dds.xport.zerocopy::%zc-resolve-fresh (disc-node-zc-pool-sap node) zc-slot zc-gen)))
      (dds.xport.zerocopy::%zc-release (disc-node-zc-pool-sap node) zc-slot zc-gen))
    (setf zc-slot nil))
  (let ((iq (when (and key-hash (= 16 (length key-hash)))
              (%build-key-hash-iq (coerce key-hash '(simple-array (unsigned-byte 8) (16))))))
        (writer (%resolve-user-writer node writer-id))   ; WP-N-ENDPOINT-S1: write into THIS DataWriter's own HistoryCache/SN space; NIL/unregistered -> primary (N=1 byte-identical)
        (pin-granted nil)          ; ADR 0044: T iff the TX pin was reserved + %zc-pin'd for this write
        ;; T5a: the acquired pool buffer + its TRUE payload length (NIL = non-pooled path). WP-PERF: a caller
        ;; that already SERIALIZED INTO a pool buffer (publish-sample-into — the zero-alloc DCPS TX path) hands
        ;; it in here, so the change OWNS it and the pool reclaims it at the eviction/ref-drop gate exactly as a
        ;; secured payload does. The secured branch below overrides both (it re-encodes into its own buffer).
        (pooled in-pooled) (plen in-plen))
    ;; WP-ACKED-SLOT-PINNING (ADR 0044): a pin request (a committed slot + NO retained payload). Reserve a pin
    ;; budget slot + %zc-pin (a SECOND, distinct refcount hold, ADR 0044 §4.1); at budget / a stale slot, resolve
    ;; the retained payload on demand from the still-armed slot and publish as a normal change (the fallback).
    (when (and zc-slot (null payload))
      (let ((sap (disc-node-zc-pool-sap node)))
        (when (and sap
                   (< (dds.pal:atomic-cell-value (disc-node-zc-pin-count node)) *zc-pin-budget*)
                   (dds.xport.zerocopy::%zc-pin sap zc-slot zc-gen))
          (dds.pal:atomic-incf (disc-node-zc-pin-count node) 1)
          (setf pin-granted t))
        (unless pin-granted
          (setf payload (and sap (dds.xport.zerocopy::%zc-resolve-fresh sap zc-slot zc-gen))))))
    ;; DDS-Security §9.5.3.3.4.4 encode (ADR 0031 T6): crypto-keys resolver or Slice-1 key-material; fail-closed on nil key.
    ;; §9.4.1.2.4: the SecuredPayload (data_protection) transform is applied UNLESS governance set data_protection=NONE
    ;; for this topic (data=NONE: the payload rides plain). :unset (no governance) keeps the transform — Slice-1
    ;; direct-KM path unchanged. The tier (ENCRYPT vs SIGN/GMAC) is selected by the resolved km's transformation_kind
    ;; (%cm-entity-protection-kind derives it from user-data-protection-kind): data=ENCRYPT -> AES256-GCM ciphertext
    ;; (HIDDEN); data=SIGN -> AES256-GMAC (the payload rides VISIBLE + GMAC-authenticated, encode-serialized-payload
    ;; GMAC sub-tier). data_protection=SIGN (payload-tier GMAC) is IMPLEMENTED; supported tiers: NONE + SIGN + ENCRYPT
    ;; (ADR-0040 §9.5.3.3.4.3).
    (let* ((weid (dds.rtps.reliable:rtps-writer-entityid writer))   ; WP-N-ENDPOINT-S3: the ACTUAL publishing writer's EntityId (the send crux)
           (wdk  (nth-value 0 (%user-endpoint-kinds node weid)))    ; THIS writer's OWN data_protection kind (per-endpoint, never the node-single slot)
           (ct   (and (not (eq wdk :none)) (disc-node-crypto-transform node))))   ; ADR 0046/0048: the WRITER's OWN kind (never a shared slot a reader/other writer could downgrade)
      (when (and ct pooled)   ; WP-PERF: a secured writer re-encodes below into its OWN pool buffer; return the caller's pre-serialized one or it leaks a slot (publish-sample-into gates this case out, so this is belt-and-braces)
        (dds.rtps.reliable:writer-release-payload-buffer writer pooled)
        (setf pooled nil plen nil))
      (when ct
        (let ((km (if (typep ct 'dds.security:crypto-keys)
                      (funcall (dds.security:crypto-keys-encode-key-fn ct) (%local-writer-guid-vec node weid))   ; resolve THIS writer's EntityCrypto km by its OWN EntityId
                      ct)))
          (if km
              ;; T5a: encode INTO a POOLED buffer (zero per-sample payload alloc) when a payload-pool is provisioned,
              ;; else the allocating wrapper (byte-identical). Pool exhaustion / oversize -> RESOURCE_LIMITS, never GC.
              (let ((hc (dds.rtps.reliable:rtps-writer-hc writer)))
                ;; T5a review: lazily carve the pool on the FIRST secured publish so the LIVE handshake config
                ;; (keys installed AFTER enable-publisher by the crypto-manager) is zero-alloc too, not only the
                ;; static-key config. The unlocked nil-gate keeps steady state to one slot read; the carve
                ;; re-checks + provisions under the writer lock (idempotent), so it runs at most once.
                (unless (dds.rtps.history:history-cache-payload-pool hc)
                  (%ensure-secured-payload-pool node writer))
                (if (dds.rtps.history:history-cache-payload-pool hc)
                    (let ((buf (dds.rtps.reliable:writer-acquire-payload-buffer writer)))
                      (if buf
                          (let ((committed nil))
                            (unwind-protect
                                 (handler-case
                                     (let ((len (dds.security:encode-serialized-payload-into buf km payload)))
                                       (setf payload (dds.core.buffer:octet-buffer-vec buf) pooled buf plen len committed t))
                                   (dds.core.buffer:buffer-overflow ()   ; payload > element-bytes: RESOURCE_LIMITS reject, never a GC fallback
                                     (return-from publish-sample :timeout)))
                              (unless committed   ; any non-local exit before commit: release the pool slot
                                (dds.rtps.reliable:writer-release-payload-buffer writer buf))))
                          (return-from publish-sample :timeout)))   ; pool exhausted: RESOURCE_LIMITS, never a GC fallback
                    (setf payload (dds.security:encode-serialized-payload km payload))))   ; carve failed/unavailable: allocating fallback (byte-identical)
              (return-from publish-sample t)))))   ; fail-closed: no key -> drop
    (multiple-value-bind (rc change)
        (dds.rtps.reliable:writer-write writer payload key-hash iq pooled plen zc-slot zc-gen
                                        pin-granted (and pin-granted zc-len))   ; ADR 0044: born pinned (no retained payload) when the pin was granted
      (when (eq :timeout rc)
        (when pooled (dds.rtps.reliable:writer-release-payload-buffer writer pooled))   ; full cache: return the buffer, nothing added
        (when (and zc-slot (disc-node-zc-pool-sap node))   ; ADR 0042: nothing added -> the committed slot can never be emitted; release the armed hold
          (dds.xport.zerocopy::%zc-release (disc-node-zc-pool-sap node) zc-slot zc-gen))
        (when pin-granted   ; ADR 0044: nothing added -> release the pin hold too + un-reserve the budget
          (dds.xport.zerocopy::%zc-release (disc-node-zc-pool-sap node) zc-slot zc-gen)
          (dds.pal:atomic-incf (disc-node-zc-pin-count node) -1))
        (return-from publish-sample :timeout))  ; full bounded cache, max_blocking_time elapsed: nothing added, nothing to push
      (when (and change source-timestamp)   ; S5.T4: carry the source_timestamp (ns) so %data-builder emits INFO_TS before this DATA (retransmits carry it too)
        (setf (dds.rtps.history:cache-change-source-timestamp change) source-timestamp))
      (when (and zc-slot change)   ; ADR 0042: register the armed change for the post-push-pass / teardown leak sweep
        (dds.pal:with-lock ((disc-node-lock node))
          (push change (disc-node-zc-armed-changes node))))))
  (cond
    ((disc-node-flow-controller node)   ; WP-ASYNC-FLOW paced async send; WP-N-ENDPOINT-S1B: signal THIS writer's per-writer flow-state (re-resolve the writer — the writer let has closed)
     (%flow-signal (disc-node-flow-controller node)
                   (%flow-writer-state-for node (%resolve-user-writer node writer-id))))
    ((disc-node-async-thread node) (%async-signal node))   ; WP-ASYNC: hand off to the sender thread
    ((>= (incf (disc-node-batch-pending node)) (disc-node-batch-max-samples node)) (flush-batch node))
    (t nil))   ; batch size trigger not reached: defer to the next flush (cadence or fill)
  t)

(defun* %build-key-hash-iq (key-hash)
    (function ((simple-array (unsigned-byte 8) (16))) (simple-array (unsigned-byte 8) (*)))
  "Build a 24-octet PID_SENTINEL-terminated inline-QoS block carrying PID_KEY_HASH for DATA-with-payload
   (RTPS 2.5 §9.6.4.8): 4 bytes PID header + 16 bytes hash + 4 bytes PID_SENTINEL = 24. Mirrors what
   Connext 7.3.1 and Fast DDS 3.6.1 emit on every keyed write() call (spike 2026-06-21). Off the hot path —
   only publish-sample callers that opt in via a non-nil key-hash call this. Control-plane (ADR 0029)."
  (let* ((scratch (make-array 24 :element-type '(unsigned-byte 8) :initial-element 0))
         (buf (dds.core.buffer:octet-buffer-over scratch))
         (mc (dds.core.buffer:cursor buf :endianness :little)))
    (dds.rtps.message:write-parameter mc dds.rtps.message:+pid-key-hash+ key-hash 0 16)
    (dds.rtps.message:write-parameter-sentinel mc)
    scratch))

(defun* %build-original-writer-info-iq (guid sn)
    (function ((simple-array (unsigned-byte 8) (16)) (integer 0))
              (simple-array (unsigned-byte 8) (*)))
  "Build a 32-octet PID_SENTINEL-terminated inline-QoS block carrying PID_ORIGINAL_WRITER_INFO for the
   given (GUID, SN). Returns a fresh octet vector: 28 bytes PID_ORIGINAL_WRITER_INFO parameter (pid 2 +
   len 2 + body 24) + 4 bytes PID_SENTINEL = 32. RTPS 2.5 §8.3.5.4 / §9.4.2.11 / Table 9.12.
   Called only from publish-relay-sample — off the hot path (relay/control-plane publish)."
  (let* ((scratch (make-array 32 :element-type '(unsigned-byte 8) :initial-element 0))
         (buf (dds.core.buffer:octet-buffer-over scratch))
         (mc (dds.core.buffer:cursor buf :endianness :little)))
    (dds.rtps.message:write-original-writer-info-parameter mc guid sn)
    (dds.rtps.message:write-parameter-sentinel mc)
    scratch))

(defun* publish-relay-sample (node payload original-guid original-sn &optional (key-hash nil))
    (function (disc-node (simple-array (unsigned-byte 8) (*))
               (simple-array (unsigned-byte 8) (16)) (integer 0)
               &optional (or null (array (unsigned-byte 8) (*))))
              (or (eql t) (eql :timeout)))
  "Publish PAYLOAD as a RELAY write: identical to PUBLISH-SAMPLE but attaches PID_ORIGINAL_WRITER_INFO
   (ORIGINAL-GUID, ORIGINAL-SN) as inline-QoS on the emitted DATA (RTPS 2.5 §8.3.5.4 / §9.4.5.4).
   PUBLISH-SAMPLE remains byte-identical (no PID, Q-bit clear). KEY-HASH mirrors publish-sample's arg
   (WP-KEEPLAST instance handle, default NIL). Returns T normally, :timeout under the same
   block-up-to-max_blocking_time backpressure as publish-sample (ADR 0016). The inline-QoS block is
   built off-heap by %build-original-writer-info-iq (32 octets; off the hot path — relay is control-plane).
   Inline-QoS is scoped to small (non-fragmented) DATA samples (%data-builder); the DATA_FRAG path
   (%sample-plan) does NOT carry it — RTPS 2.5 §9.4.5.5 makes it optional, and relay samples
   (ShapeType-sized) are always below *fragment-size* and never fragment."
  (let ((iq (%build-original-writer-info-iq original-guid original-sn)))
    (when (eq :timeout (dds.rtps.reliable:writer-write (disc-node-user-writer node) payload key-hash iq))
      (return-from publish-relay-sample :timeout))
    (cond
      ((disc-node-flow-controller node)   ; WP-N-ENDPOINT-S1B: relay writes to the primary writer -> its flow-state
       (%flow-signal (disc-node-flow-controller node) (%flow-writer-state-for node (disc-node-user-writer node))))
      ((disc-node-async-thread node) (%async-signal node))
      ((>= (incf (disc-node-batch-pending node)) (disc-node-batch-max-samples node)) (flush-batch node))
      (t nil))
    t))

(defun* publish-relay-lifecycle (node key-hash status-flags original-guid original-sn)
    (function (disc-node (simple-array (unsigned-byte 8) (16)) (unsigned-byte 8)
               (simple-array (unsigned-byte 8) (16)) (integer 0))
              (or (eql t) (eql :timeout)))
  "Replay a dispose/unregister as a RELAY lifecycle change: identical to %dispose-or-unregister
   but attaches PID_ORIGINAL_WRITER_INFO (ORIGINAL-GUID, ORIGINAL-SN) as inline-QoS on the
   emitted DATA (RTPS 2.5 §9.4.5.4) so the late-joiner can dedup it against a direct dispose
   from the original writer. KEY-HASH is the instance key hash, STATUS-FLAGS the StatusInfo_t
   octet (Disposed / Unregistered / both). Returns T normally, :timeout under the same
   backpressure as %dispose-or-unregister."
  (let* ((iq (%build-original-writer-info-iq original-guid original-sn))
         (sn (dds.rtps.reliable:writer-lifecycle-change
              (disc-node-user-writer node) key-hash status-flags iq)))
    (when (eq sn :timeout) (return-from publish-relay-lifecycle :timeout))
    (setf (disc-node-batch-pending node) 0)
    (cond
      ((disc-node-flow-controller node)   ; WP-N-ENDPOINT-S1B: relay lifecycle writes to the primary writer -> its flow-state
       (%flow-signal (disc-node-flow-controller node) (%flow-writer-state-for node (disc-node-user-writer node))))
      ((disc-node-async-thread node) (%async-signal node))
      (t (%push-data node)))
    t))

(defun* %dispose-or-unregister (node key-hash status-flags &optional (source-timestamp 0))
    (function (disc-node (simple-array (unsigned-byte 8) (16)) (unsigned-byte 8) &optional integer) (or integer (eql :timeout)))
  "Writer side: add a dispose/unregister change for the instance named by KEY-HASH (16 octets)
   to the user writer's HistoryCache (writer-lifecycle-change, deriving the KIND from
   STATUS-FLAGS), then push DATA + HEARTBEAT to peers exactly like publish-sample — so the
   lifecycle DATA is sent AND reliably ACKNACK-repairable (RTPS 2.5 §8.4.2.2 / §9.6.4.9).
   Returns the change's sequence number, OR the :timeout sentinel (RETCODE_TIMEOUT) if the bounded cache
   was full and block-up-to-max_blocking_time elapsed (WP-ASYNC-FLOW backpressure, ADR 0016 §Backpressure;
   a lifecycle change occupies a SN so it is bounded CONSISTENTLY with a DATA write). On :timeout nothing
   was added, so nothing is flushed/pushed/signalled (the batch pacer is left untouched). A lifecycle change
   is NEVER batch-delayed: it pushes immediately, which also flushes any pending batched data first (sent in
   SN order, so a dispose never overtakes its instance's batched samples). With a flow-controller associated
   (WP-ASYNC-FLOW, ADR 0016) it goes through the same paced async path as publish-sample — the lifecycle
   DATA is rate-shaped with the writer's data, in SN order, by the controller thread."
  (let ((sn (dds.rtps.reliable:writer-lifecycle-change (disc-node-user-writer node) key-hash status-flags
                                                       nil source-timestamp)))   ; S5.T4: source_timestamp (ns, 0 = none)
    (when (eq sn :timeout) (return-from %dispose-or-unregister :timeout))   ; full bounded cache: nothing added, nothing to push
    (setf (disc-node-batch-pending node) 0)   ; the push flushes the pending batch too (data SN < dispose SN)
    (cond
      ((disc-node-flow-controller node)   ; WP-ASYNC-FLOW paced async send; WP-N-ENDPOINT-S1B: dispose writes to the primary writer -> its flow-state
       (%flow-signal (disc-node-flow-controller node) (%flow-writer-state-for node (disc-node-user-writer node))))
      ((disc-node-async-thread node) (%async-signal node))
      (t (%push-data node)))
    sn))

(defun* dispose-instance (node key-hash &optional (source-timestamp 0))
    (function (disc-node (simple-array (unsigned-byte 8) (16)) &optional integer) (or integer (eql :timeout)))
  "Dispose the instance named by KEY-HASH on NODE's user writer (DDS 1.4 §2.2.2.4.2.10): emit a
   no-payload dispose DATA (StatusInfo Disposed, RTPS 2.5 §9.6.4.9) over the reliable engine.
   Returns the change SN, or :timeout (RETCODE_TIMEOUT) under the same block-up-to-max_blocking_time
   backpressure as publish-sample (ADR 0016 §Backpressure; only with a finite bounded cache). Mirrors
   publish-sample so the dispose is reliably repairable. SOURCE-TIMESTAMP (ns, 0 = none, S5.T4): a
   dispose_w_timestamp emits an INFO_TS before the lifecycle DATA."
  (%dispose-or-unregister node key-hash dds.rtps.message:+statusinfo-disposed+ source-timestamp))

(defun* unregister-instance (node key-hash &optional (autodispose t) (source-timestamp 0))
    (function (disc-node (simple-array (unsigned-byte 8) (16)) &optional t integer) (or integer (eql :timeout)))
  "Unregister the instance named by KEY-HASH on NODE's user writer (DDS 1.4 §2.2.2.4.2.7): emit a
   no-payload unregister DATA over the reliable engine. When AUTODISPOSE is true (the
   WRITER_DATA_LIFECYCLE default, DDS 1.4 §2.2.3.21) the StatusInfo is Disposed|Unregistered (the
   unregister also disposes the instance, behaviour identical to a dispose before the unregister);
   when false it is Unregistered only (RTPS 2.5 §9.6.4.9). Returns the change SN, or :timeout
   (RETCODE_TIMEOUT) under the same block-up-to-max_blocking_time backpressure as publish-sample
   (ADR 0016 §Backpressure; only with a finite bounded cache). Mirrors
   publish-sample so the unregister is reliably repairable."
  (%dispose-or-unregister
   node key-hash
   (if autodispose
       (logior dds.rtps.message:+statusinfo-unregistered+ dds.rtps.message:+statusinfo-disposed+)
       dds.rtps.message:+statusinfo-unregistered+)
   source-timestamp))

(defun* %source-guid (src-prefix writer-id)
    (function ((simple-array (unsigned-byte 8) (12)) (unsigned-byte 32)) (simple-array (unsigned-byte 8) (16)))
  "Assemble the 16-octet source GUID from the datagram's RTPS-header SRC-PREFIX (§9.4.4) and the
   DATA submessage's WRITER-ID EntityId (§9.3.1.2) — the key for EXCLUSIVE ownership arbitration."
  (let ((g (make-array 16 :element-type '(unsigned-byte 8))))
    (replace g src-prefix :end2 12)
    (setf (aref g 12) (ldb (byte 8 24) writer-id) (aref g 13) (ldb (byte 8 16) writer-id)
          (aref g 14) (ldb (byte 8 8) writer-id) (aref g 15) (ldb (byte 8 0) writer-id))
    g))

(defun* %reader-routes-for (node writer-guid)
    (function (disc-node (simple-array (unsigned-byte 8) (16))) list)
  "WP-N-ENDPOINT-S2/2C1 (ADR 0048): the local user readers matched to remote writer WRITER-GUID, as a list of
   (reader-EntityId . engine-rtps-reader) pairs — the receive-hook DEMUX. The FIRST pair is the CANONICAL reader:
   it holds the single reliability truth for this writer (received-SN / dedup / reassembly / instance state), so a
   HEARTBEAT is applied and an ACKNACK is COMPUTED from it once. WP-N-ENDPOINT-2C1: the route now holds N reader-ids
   per writer — %match-remote-endpoint route-adds ALL matching local readers (route-add-all), so two SAME-topic
   NON-loan readers each add their id under W's GUID. The per-reader emit loop in the HEARTBEAT/NACK_FRAG hooks
   (dolist over this list) fans out ONE ACKNACK/NACK_FRAG per reader-id (each remote ReaderProxy is keyed by the
   reader GUID it matched, so it expects THAT reader's id) while the single canonical reader supplies the reliability
   truth. Different-topic readers each match their OWN writer (distinct GUID -> distinct single-entry route,
   byte-identical to S2). An EMPTY route (discovery-less / pre-match / N=1) falls back to the PRIMARY reader under
   disc-node-user-reader-id — byte-identical to the pre-S2 single-reader hooks. A route id with no live engine
   reader is skipped (never a crash)."
  (let ((memo (dds.pal:with-lock ((disc-node-lock node))
                (gethash writer-guid (disc-node-reader-routes-cache node)))))
    (cond
      ((eq memo :none) nil)                    ; resolved before: this writer reaches no reader
      (memo memo)                              ; resolved before: the SHARED list (read-only, see below)
      (t
       ;; NFR-MEM (ADR 0062): this rebuilt a copy-list + a fresh cons per route on EVERY data/heartbeat/gap
       ;; handler call — 328 B/sample, the single biggest RX allocation — for a value that changes only on
       ;; match/unmatch. Resolve once and memoize. The memo is dropped WHOLESALE by %invalidate-route-cache
       ;; from every mutation of reader-routes / user-readers, because a STALE ROUTE IS SILENT MIS-DELIVERY
       ;; (a sample lost, or handed to a dead reader) — the invalidation is coarse on purpose.
       ;; The returned list is SHARED: callers MUST treat it as read-only (they only ever dolist it).
       ;; %user-reader-for is called OUTSIDE the node lock, exactly as before (it may take the lock itself).
       (multiple-value-bind (ids gen)
           (dds.pal:with-lock ((disc-node-lock node))
             (values (copy-list (gethash writer-guid (disc-node-reader-routes node)))
                     (disc-node-reader-routes-generation node)))
         (let ((resolved (if ids
                             (loop for rid in ids
                                   for r = (%user-reader-for node rid)
                                   when r collect (cons rid r))
                             (let ((r (disc-node-user-reader node)))
                               (and r (list (cons (disc-node-user-reader-id node) r)))))))
           (dds.pal:with-lock ((disc-node-lock node))
             ;; STORE ONLY IF THE ROUTES DID NOT CHANGE UNDER US. %user-reader-for runs outside the lock
             ;; (it may take it), so an unmatch/prune can land mid-resolve; caching that result would make
             ;; the memo permanently stale — i.e. silent mis-delivery. On a race we simply return the fresh
             ;; value and re-resolve next call. Key by a COPY: the caller's GUID buffer must never become a
             ;; live hash key.
             (when (= gen (disc-node-reader-routes-generation node))
               (setf (gethash (copy-seq writer-guid) (disc-node-reader-routes-cache node))
                     (or resolved :none))))
           resolved))))))

(defun* %on-user-lifecycle (node writer-id sn kind key-hash status-flags src-prefix)
    (function (disc-node (unsigned-byte 32) integer (member :dispose :unregister) t (unsigned-byte 8)
              (simple-array (unsigned-byte 8) (12))) t)
  "Reader side: a no-payload dispose/unregister DATA arrived from WRITER-ID at SRC-PREFIX (RTPS 2.5
   §9.6.4.9). Feed its SN to the reliable reader (so the ACKNACK/HEARTBEAT bookkeeping treats it as a
   real change), record (KIND KEY-HASH STATUS-FLAGS WRITER-ID SOURCE-GUID) by SN — the full 16-octet
   source GUID (§9.4.4 prefix + EntityId) lets S2 owner-clear target the EXACT disposing writer (DDS
   1.4 §2.2.3.9.2; an EntityId alone aliases writers sharing 0x102 across participants) — then fire the
   DCPS-facing lifecycle-event callback OUTSIDE the node lock (mirrors %deliver-user-sample). Gated on
   a matched user writer EntityId."
  (when (and (disc-node-user-reader node) (%user-writer-entityid-p writer-id))
    (let* ((guid (%source-guid src-prefix writer-id))
           (routes (%reader-routes-for node guid)))   ; WP-N-ENDPOINT-S2: drive the CANONICAL reader matched to this writer (not unconditionally the primary)
      (when routes
        (dds.rtps.reliable:reader-on-data (cdr (first routes)) guid sn
                                          (make-array 0 :element-type '(unsigned-byte 8))))
      (dds.pal:with-lock ((disc-node-lock node))
        ;; 2-level (source-GUID -> SN) keying mirrors the data store: a SequenceNumber is unique only
        ;; within one writer GUID (RTPS 2.5 §8.3.5.4), so two writers sharing EntityId 0x102 on different
        ;; participants disposing different instances at the SAME SN do not clobber each other.
        (setf (gethash sn (%inner-table (disc-node-lifecycle-changes node) guid))
              (list kind key-hash status-flags writer-id guid))))
    (when (disc-node-on-lifecycle-event node)
      (funcall (disc-node-on-lifecycle-event node) writer-id sn kind key-hash status-flags)))
  t)

(defun* node-lifecycle-change (node key)
    (function (disc-node cons) t)
  "The received lifecycle change for composite KEY (a (GUID . SN) cons, see node-lifecycle-sns) as
   (kind key-hash status-flags writer-id source-guid), or NIL. Lets a subscriber observe that a
   dispose/unregister DATA was received and classified (S1), and lets the user-thread S2 consumer
   (%drain) recover the originating writer (EntityId to drop it from the instance's writers-set on an
   :unregister, DDS 1.4 §2.2.2.5.1.3; full 16-octet SOURCE-GUID to clear ownership of only the exact
   disposing writer, §2.2.3.9.2). Keyed by GUID then SN (§8.3.5.4) so two writers sharing EntityId 0x102
   never alias in the SN space."
  (dds.pal:with-lock ((disc-node-lock node))
    (let ((inner (gethash (car key) (disc-node-lifecycle-changes node))))
      (and inner (gethash (cdr key) inner)))))

(defun* node-lifecycle-change-by-sn (node sn)
    (function (disc-node integer) t)
  "The lifecycle change of ANY received dispose/unregister whose RTPS SN equals SN, or NIL. A
   single-writer convenience (the store is keyed by GUID then SN, §8.3.5.4) — for tests/diagnostics
   that know only the SN, mirroring node-sample-by-sn."
  (dds.pal:with-lock ((disc-node-lock node))
    (loop for inner being the hash-values of (disc-node-lifecycle-changes node)
          thereis (gethash sn inner))))

(defun* node-lifecycle-count (node)
    (function (disc-node) (integer 0))
  "Number of distinct dispose/unregister lifecycle DATAs the subscriber has received (S1), summed over
   every writer's inner SN map."
  (dds.pal:with-lock ((disc-node-lock node))
    (let ((n 0))
      (maphash (lambda (g inner) (declare (ignore g)) (incf n (hash-table-count inner)))
               (disc-node-lifecycle-changes node))
      n)))

(defun* node-lifecycle-sns (node)
    (function (disc-node) list)
  "Composite (GUID . SN) cons keys of the dispose/unregister lifecycle DATAs received so far (unordered).
   Lets the user-thread S2 consumer (%drain) drain newly-classified lifecycle changes the same way
   node-sample-sns drains data samples — per writer GUID, without assuming SNs start at 1 (Connext may
   not) and without aliasing two writers sharing EntityId 0x102 (§8.3.5.4). The cons is built here on
   the user thread, not on the per-change receive path (NFR-MEM)."
  (dds.pal:with-lock ((disc-node-lock node))
    (let ((keys '()))
      (maphash (lambda (guid inner)
                 (loop for sn being the hash-keys of inner do (push (cons guid sn) keys)))
               (disc-node-lifecycle-changes node))
      keys)))

(defun* %inner-table (outer guid)
    (function (hash-table (simple-array (unsigned-byte 8) (16))) hash-table)
  "The per-writer inner SN->value table for 16-octet GUID in OUTER, created on first use (RTPS 2.5
   §8.3.5.4: a SequenceNumber is unique only within one writer GUID, so each writer GUID owns an
   independent eql-keyed SN map; no per-sample composite-key allocation)."
  (or (gethash guid outer)
      (setf (gethash (copy-seq guid) outer) (make-hash-table :test 'eql))))

(defun* %record-sample-origin (node wire-guid sn eff-guid eff-sn)
    (function (disc-node (simple-array (unsigned-byte 8) (16)) integer
              (simple-array (unsigned-byte 8) (16)) integer) t)
  "Record the logical origin (EFF-GUID . EFF-SN) for the sample stored under wire (WIRE-GUID, SN) — but
   ONLY when it differs from the wire identity, i.e. the sample arrived relayed with PID_ORIGINAL_WRITER_INFO
   (RTPS 2.5 §8.3.5.4). A direct sample stores nothing here (the wire GUID/SN IS the origin), so the common
   path stays byte-identical and allocation-free. Caller holds the node lock. Control-plane (relay store)."
  (when (or (not (equalp eff-guid wire-guid)) (/= eff-sn sn))
    (setf (gethash sn (%inner-table (disc-node-sample-origins node) wire-guid))
          (cons (copy-seq eff-guid) eff-sn)))
  t)

(defun* %record-sample-key-hash (node wire-guid sn key-hash)
    (function (disc-node (simple-array (unsigned-byte 8) (16)) integer
              (or null (simple-array (unsigned-byte 8) (*)))) t)
  "Record the wire PID_KEY_HASH (RTPS 2.5 §9.6.4.8) of the :data sample stored under (WIRE-GUID, SN) when
   one was captured (a keyed sample whose peer sent it inline; the durability collect node opts in via
   capture-data-key-hash). NIL or non-16-octet -> store nothing (the store treats absent key-hash as
   'unknown instance', never compacted). Caller holds the node lock. Control-plane (relay store, ADR 0029)."
  (when (and key-hash (= 16 (length key-hash)))
    (setf (gethash sn (%inner-table (disc-node-sample-key-hashes node) wire-guid))
          (coerce key-hash '(simple-array (unsigned-byte 8) (16)))))
  t)

(defun* node-sample-key-hash (node key)
    (function (disc-node cons) (or null (simple-array (unsigned-byte 8) (16))))
  "The captured 16-octet wire PID_KEY_HASH (RTPS 2.5 §9.6.4.8) of the :data sample at composite KEY
   (a (GUID . SN) cons), or NIL when none was captured (capture not enabled, or the sample carried no
   inline PID_KEY_HASH). A durability relay uses THIS as the per-instance handle for KEEP_LAST compaction
   (ADR 0029)."
  (dds.pal:with-lock ((disc-node-lock node))
    (let ((inner (gethash (car key) (disc-node-sample-key-hashes node))))
      (and inner (gethash (cdr key) inner)))))

(defun* %record-sample-timestamp (node wire-guid sn source-timestamp)
    (function (disc-node (simple-array (unsigned-byte 8) (16)) integer (or null integer)) t)
  "Record the source_timestamp (nanoseconds, from the INFO_TS preceding this DATA — RTPS 2.5 §9.4.5.9) of
   the :data sample stored under (WIRE-GUID, SN), when one was present. NIL -> store nothing (the reader's
   SampleInfo source_timestamp stays NIL — reception order, the pre-S5 behaviour). Caller holds the node
   lock. Control plane (the store is per-sample metadata, like the key-hash)."
  (when source-timestamp
    (setf (gethash sn (%inner-table (disc-node-sample-timestamps node) wire-guid)) source-timestamp))
  t)

(defun* node-sample-timestamp (node key)
    (function (disc-node cons) (or null integer))
  "The source_timestamp (nanoseconds) of the :data sample at composite KEY (a (GUID . SN) cons), from the
   INFO_TS that preceded it (RTPS 2.5 §9.4.5.9 / §8.3.7.9), or NIL when the DATA carried no timestamp. The
   drain copies THIS into the delivered SampleInfo's source_timestamp (DDS 1.4 §2.2.2.5.4)."
  (dds.pal:with-lock ((disc-node-lock node))
    (let ((inner (gethash (car key) (disc-node-sample-timestamps node))))
      (and inner (gethash (cdr key) inner)))))

;;;; NOT cleared for ship — pending counsel (R6); see ADR 0017.
(defstruct* (zc-loan-marker (:constructor %make-zc-loan-marker))
  "WP-FLATDATA-ZC-LOAN unresolved ZC-ref marker (FR-PF-3/4, R6, ADR 0017): the receiver thread stores THIS
   (not a resolved/copied octet-vector) in disc-node-samples for a zc-loan-capable reader, so the slot stays
   loaned (no copy, no %zc-release on the receiver thread) until DCPS take-loaned acquires + return-loan
   releases it. POOL-SAP is the reader-side attached pool base SAP, SLOT-INDEX + GENERATION the loan handle,
   LEN the wire-declared payload length (re-validated against the slot at acquire). Distinguishable from a
   normal resolved-bytes sample (a simple-array) by ZC-LOAN-MARKER-P, so %drain knows to acquire-for-read vs
   deserialize-normally. NOT cleared for ship — pending counsel (R6)."
  (pool-sap nil :type t) (slot-index 0 :type (integer 0))
  (generation 0 :type (unsigned-byte 32)) (len 0 :type (integer 0)))

(defun* set-zc-loan-capable (node capable)
    (function (disc-node t) t)
  "WP-FLATDATA-ZC-LOAN wiring (FR-PF-3/4, R6, ADR 0017): mark NODE's local user reader loan-capable (CAPABLE
   non-NIL) or not. DCPS calls this on a :flatdata-topic reader created while *zerocopy-enabled* is on, so the
   receiver thread defers ZC resolution (stores the unresolved marker, holds the slot) and DCPS take-loaned /
   return-loan owns the slot lifetime. Default NIL leaves the shipped resolve-copy-release path byte-unchanged.
   NOT cleared for ship — pending counsel (R6)."
  (setf (disc-node-zc-loan-capable node) capable))

(defun* %zc-attach-pool (node src-prefix)
    (function (disc-node (simple-array (unsigned-byte 8) (12))) t)
  "WP-ZEROCOPY reader side (FR-PF-3, ADR 0014): the mapped base SAP of the writer pool published by the
   participant at SRC-PREFIX, or NIL if the pool cannot be opened (a forged/stale source prefix derives a
   deterministic %zc-pool-name that simply does not exist -> shm-attach returns :SHM-OPEN-FAILED -> cached
   as :none, dropped — never a crash). A MISSING PEER POOL IS AN ORDINARY OUTCOME HERE, NOT AN ERROR: it
   used to be an shm-attach CONDITION swallowed by IGNORE-ERRORS, which also swallowed every other fault;
   it is now the explicit status value the PAL returns. MEMOIZED per source prefix under zc-attach-lock
   (attach once per remote writer; two receiver threads racing the first attach for one writer are
   serialized). The attach SIZE uses the SHARED geometry constants (+zerocopy-pool-slots+ /
   +zerocopy-pool-slot-bytes+), NOT a wire-supplied value, so an untrusted ref can never size the mapping
   (NFR-SEC-POSTURE)."
  (dds.pal:with-lock ((disc-node-zc-attach-lock node))
    (let ((cached (gethash src-prefix (disc-node-zc-attach-cache node))))
      (cond
        ((eq cached :none) nil)
        (cached (dds.pal:shm-sap cached))
        (t (multiple-value-bind (seg status)
               (dds.pal:shm-attach (%zc-pool-name src-prefix)
                                   (dds.xport.zerocopy::%zc-bytes
                                    +zerocopy-pool-slots+ +zerocopy-pool-slot-bytes+))
             (when status (setf seg nil))          ; no such pool (or it will not map): remember "none"
             (setf (gethash (copy-seq src-prefix) (disc-node-zc-attach-cache node)) (or seg :none))
             (and seg
                  (dds.xport.zerocopy::%zc-validate (dds.pal:shm-sap seg))   ; ABI magic/version guard
                  (dds.pal:shm-sap seg))))))))

(defun* %zc-ref-overlay-p (buf poff plen)
    (function (dds.core.buffer:octet-buffer (integer 0) (integer 0)) boolean)
  "WP-SECURITY-ZC-SHMEM-OVERLAY (ADR 0051): T iff BUF[poff,poff+plen) is a ZC reference whose reserved field
   is +zc-ref-overlay-secured+ (the slot holds a data_protection SecuredPayload). Used at the receive dispatch
   to force copy-on-read for a loan-capable reader (an overlay slot cannot be read in place — it is ciphertext)."
  (multiple-value-bind (slot gen slot-bytes overlay)
      (dds.cdr:parse-zc-reference (dds.core.buffer:octet-buffer-vec buf) poff plen)
    (declare (ignore gen slot-bytes))
    (and slot (= overlay dds.cdr:+zc-ref-overlay-secured+) t)))

(defun* %zc-try-resolve (node buf poff plen src-prefix)
    (function (disc-node dds.core.buffer:octet-buffer (integer 0) (integer 0)
              (simple-array (unsigned-byte 8) (12))) (values t (unsigned-byte 32)))
  "WP-ZEROCOPY / WP-FLATDATA reader side (FR-PF-3/4, ADR 0014/0015; NOT cleared for ship — pending counsel
   R6): test the DATA SerializedPayload at BUF[poff,poff+plen) for a 16-byte zero-copy reference. Returns
   TWO values (RESOLVED . OVERLAY): the 1st is :NOT-A-REF for a normal payload (the caller delivers it
   unchanged); a fresh (simple-array (unsigned-byte 8)) holding the RESOLVED serialized payload on a valid
   ref; or NIL when it IS a ref but resolution fails (stale/forced-reclaimed/OOB/attach-fail) — best-effort
   DROP, no delivery, no crash. The 2nd value is the reference's reserved OVERLAY field (0 for a normal ref;
   +zc-ref-overlay-secured+ when the slot holds a data_protection SecuredPayload, ADR 0051) — the caller
   threads it into %deliver-user-sample to force the in-slot decode; 0 on the :not-a-ref / attach-fail arms.
   READ-THEN-RELEASE lifetime (the Phase-D crux): the resolved payload is read IN PLACE from the writer's
   SHMEM pool slot straight into a fresh exact-length node-OWNED vector under the slot mutex
   (%zc-resolve-fresh — a SINGLE intra-host copy; the WP-ZEROCOPY v1 resolve-into-slot-sized-sink-then-re-copy
   is gone), then the slot is %zc-released IMMEDIATELY. The slot's cross-process lifetime therefore ends here
   and never spans the app's later (other-thread, %drain/read) access — so a writer force-reclaim cannot
   corrupt a delivered sample (no cross-process use-after-free). A literal-0-copy SHMEM VIEW handed to the
   reader is NOT done in v1 and would be unsafe here: this stack delivers samples into an async store read on
   another thread with no slot-aware release hook, and an octet-buffer cannot wrap a raw foreign SAP (the
   FlatData accessors need a Lisp simple-array) — see ADR 0015. The ref is UNTRUSTED cross-process input:
   parse-zc-reference bounds-checks the payload region and %zc-resolve-fresh clamps the copy to the fixed
   slot-bytes + validates generation against the slot header (NFR-SEC-POSTURE: never OOB into SHMEM)."
  (multiple-value-bind (slot gen slot-bytes overlay)
      (dds.cdr:parse-zc-reference (dds.core.buffer:octet-buffer-vec buf) poff plen)
    (declare (ignore slot-bytes))
    (if (null slot)
        (values :not-a-ref 0)
        (let ((sap (%zc-attach-pool node src-prefix)))
          (if (null sap)
              (values nil 0)
              ;; READ-THEN-RELEASE (the WP-FLATDATA-over-ZC single-copy RX path): %zc-resolve-fresh reads the
              ;; slot IN PLACE straight into a freshly-allocated, exact-payload-length owned vector under one
              ;; mutex acquisition (no slot-sized scratch sink + re-copy, as WP-ZEROCOPY v1 did), then we
              ;; %zc-release the slot IMMEDIATELY. The payload now lives in a node-owned Lisp vector, so the
              ;; slot's cross-process lifetime ends here and does NOT span the app's later (other-thread,
              ;; %drain) read — no cross-process use-after-free. The copy is clamped to the fixed slot-bytes,
              ;; never OOB into SHMEM (NFR-SEC-POSTURE).
              (let ((vec (dds.xport.zerocopy::%zc-resolve-fresh sap slot gen)))
                (dds.xport.zerocopy::%zc-release sap slot gen)   ; release now: bytes already copied into the owned VEC
                (values vec overlay)))))))

(defun* %zc-defer (node buf poff plen src-prefix)
    (function (disc-node dds.core.buffer:octet-buffer (integer 0) (integer 0)
              (simple-array (unsigned-byte 8) (12))) t)
  "WP-FLATDATA-ZC-LOAN reader side, the LOAN-CAPABLE branch (FR-PF-3/4, R6, ADR 0017; NOT cleared for ship —
   pending counsel): test the DATA SerializedPayload at BUF[poff,poff+plen) for a 16-byte zero-copy reference.
   Returns :NOT-A-REF for a normal payload (the caller copies+delivers it unchanged); a ZC-LOAN-MARKER (pool-sap
   + slot + generation + len) on a valid ref WITHOUT resolving/copying/releasing — the slot stays loaned via the
   writer's refcount so the app reads it in place through DCPS take-loaned (literal 0 intra-host copies); or NIL
   when it IS a ref but the writer pool cannot be attached (forged/stale src-prefix) — best-effort DROP. This is
   the Phase-D defer: unlike %zc-try-resolve (which read-then-RELEASEs on the receiver thread), the slot's
   cross-process lifetime is HANDED to DCPS — the receiver thread does NOT release it (releasing here would free
   the slot before the app's later read = use-after-free). The ref is UNTRUSTED: parse-zc-reference bounds-checks
   the payload region; the attach SIZE uses the fixed pool geometry, never a wire value; %zc-acquire-for-read
   re-validates the slot + generation + len at acquire (NFR-SEC-POSTURE)."
  (multiple-value-bind (slot gen slot-bytes)
      (dds.cdr:parse-zc-reference (dds.core.buffer:octet-buffer-vec buf) poff plen)
    (if (null slot)
        :not-a-ref
        (let ((sap (%zc-attach-pool node src-prefix)))
          (when sap
            ;; LEN here is the ref's advisory slot-capacity; %zc-acquire-for-read re-derives the AUTHORITATIVE
            ;; clamped payload length from the slot header at acquire, so a forged wire LEN cannot widen a read.
            (%make-zc-loan-marker :pool-sap sap :slot-index slot :generation gen :len slot-bytes))))))

(defun* %deliver-user-marker (node writer-id sn marker src-prefix effective-guid effective-sn)
    (function (disc-node (unsigned-byte 32) integer zc-loan-marker
              (simple-array (unsigned-byte 8) (12))
              (simple-array (unsigned-byte 8) (16)) integer) t)
  "WP-FLATDATA-ZC-LOAN (R6, ADR 0017): store the UNRESOLVED ZC-LOAN-MARKER as the sample value (mirrors
   %deliver-user-sample, but the value is the marker, not an octet-vector). The reliable-reader proxy is still
   fed the marker as the change so ACKNACK/HEARTBEAT bookkeeping advances; the 2-level (source-GUID -> SN) store
   keeps the marker so DCPS %drain can acquire-for-read it. ON-SAMPLE fires outside the node lock. NOT cleared
   for ship — pending counsel (R6). EFFECTIVE-GUID/EFFECTIVE-SN are the logical-origin GUID+SN for dedup
   (orig-guid/orig-sn on the relay path; wire GUID+SN on the direct path) per RTPS 2.5 §8.3.5.4.
   WP-N-ENDPOINT-S4 (ADR 0048): the marker is delivered to the CANONICAL reader MATCHED to this writer
   (%reader-routes-for demux, mirroring the secured %deliver-user-sample) — NOT unconditionally the primary — so
   each ZC reader's loan/marker state is driven only by ITS OWN writers. N=1/pre-match -> primary, byte-identical.
   WP-N-ENDPOINT-2C3 / WP-DDS-ZC-REFCOUNT-LEAK (ADR 0017/0048 §17.7; MEMORY-SAFETY): with same-topic LOAN-CAPABLE
   readers co-located on this node, each reader that WILL drain THIS one stored marker (the never-purged store +
   per-reader dr-drained fan-out) %zc-releases the slot once; a FROZEN joiner does NOT drain it, so it must NOT be
   counted. The writer's %zc-loan preset the slot's refcount to 1 (per-PARTICIPANT, %zc-ref-builder) which covers ONE
   drainer; the OTHER drainers each need a hold. DEMUX-TIME BUMP: on the receiver thread, ELIGIBLE = %count-eligible-
   drainers = the route members (RE-READ UNDER the node lock — authoritative, NOT the pre-dedup snapshot) that WILL
   drain THIS marker (SN > their frozen join-watermark, the EXACT W-term of the %drain gate), and the {ELIGIBLE ->
   %zc-bump(ELIGIBLE-1) -> store} sequence runs in ONE node-lock hold BEFORE the marker is stored (hence before it is
   drainable, hence strictly before any %zc-release). A FROZEN joiner (watermark >= SN) is EXCLUDED from ELIGIBLE, so
   its phantom +1 is NEVER added -> the slot reaches refcount 0 -> reclaimable (§17.7: raw route-length K counted the
   joiner -> a permanently leaked slot). refcount = preset 1 + (ELIGIBLE-1) = ELIGIBLE; each drainer releases once ->
   0. ELIGIBLE omits the dcps dr-drained term (unreachable from disc) which only RAISES the drain bar, so ELIGIBLE is a
   SUPERSET of the true drainers -> NEVER under-counts a drainer -> a drainer's slot is never freed under its read (an
   under-count would be a cross-reader use-after-free, strictly worse than the leak). The slot is provably held
   (refcount>=1 — no reader has drained/released yet; the receiver never releases here), so its generation is STABLE
   and the bump's up-front generation read cannot race a reclaim; the slot frees only at the true refcount 0. Because a
   JOINER's high-water freeze (%reader-route-add) runs under the SAME node lock, the demux and the route-add serialize:
   a marker stored before a joiner joined is <= its watermark (skipped AND excluded from ELIGIBLE) and one stored after
   has it in this snapshot (counted iff it will drain) — no drain-an-unbumped-marker window. ELIGIBLE <= 1 / route
   length <= 1 (N=1 / different-topic S4) -> no bump, byte-identical. NOT cleared for ship — pending counsel (R6)."
  (let* ((guid (%source-guid src-prefix writer-id))
         (routes (%reader-routes-for node guid))     ; WP-N-ENDPOINT-S4: the ZC reader(s) matched to this writer (mirrors %deliver-user-sample's demux)
         (canon (and routes (cdr (first routes)))))   ; the CANONICAL engine reader (N=1/pre-match -> primary, byte-identical to the old primary-only path)
    (when canon
      ;; reader-on-data ALWAYS (keeps reliable NACK/HEARTBEAT state correct for relay proxy too)
      (dds.rtps.reliable:reader-on-data canon guid sn
                                        (make-array 0 :element-type '(unsigned-byte 8)))
      ;; app delivery gated: only if this (logical-origin GUID, SN) pair is new (§8.3.5.4)
      (when (dds.rtps.reliable:reader-dedup-accept-p canon effective-guid effective-sn)
        ;; WP-N-ENDPOINT-2C3 / WP-DDS-ZC-REFCOUNT-LEAK (ADR 0048 §17.7; MEMORY-SAFETY): {re-snapshot the route ->
        ;; ELIGIBLE -> %zc-bump(ELIGIBLE-1) -> store} ATOMIC under ONE node-lock hold (serialises with the joiner
        ;; freeze in %reader-route-add, which runs under the SAME lock). ELIGIBLE = %count-eligible-drainers = the
        ;; route members that WILL drain THIS marker (SN > their frozen join-watermark, the EXACT W-term of the %drain
        ;; gate), so a FROZEN joiner (watermark >= SN, which SKIPS this marker) is EXCLUDED -> no phantom +1 -> the
        ;; slot's refcount reaches 0 (§17.7 leak fix; raw route-length K counted the joiner -> a permanently leaked slot).
        ;; ELIGIBLE omits the dcps dr-drained term (unreachable from disc) which only RAISES the drain bar, so ELIGIBLE
        ;; is a SUPERSET of the true drainers -> NEVER under-counts a drainer -> never frees a slot a drainer still holds
        ;; (an under-count would be a use-after-free, strictly worse than the leak — see %count-eligible-drainers).
        ;; refcount = preset 1 + (ELIGIBLE-1) = ELIGIBLE; each drainer %zc-releases once -> reaches exactly 0. The bump
        ;; is a lock-free CAS run BEFORE the marker is stored (hence before drainable, before any release), so it is
        ;; deadlock-free under the node lock and its up-front generation read cannot race a reclaim (refcount>=1). Real
        ;; pool-sap only (a NIL-pool test marker never bumps); route length <= 1 or ELIGIBLE <= 1 -> no bump (the delta
        ;; is clamped >= 0 — no negative bump / refcount underflow; N=1 / different-topic S4 stays byte-identical).
        (dds.pal:with-lock ((disc-node-lock node))
          (let ((ids (gethash guid (disc-node-reader-routes node))))   ; the AUTHORITATIVE route under the lock (empty / length-1 -> primary fallback -> no bump)
            (when (and ids (cdr ids) (zc-loan-marker-pool-sap marker))   ; route length >= 2 AND a real pool slot
              (let ((eligible (%count-eligible-drainers node guid sn ids)))   ; count ONLY members that WILL drain (SN > join-watermark) — frozen joiners excluded (§17.7)
                (when (> eligible 1)   ; preset 1 covers one drainer; bump the rest (eligible-1) >= 1; eligible <= 1 -> no bump (no negative delta -> no underflow)
                  (dds.xport.zerocopy::%zc-bump (zc-loan-marker-pool-sap marker)
                                                (zc-loan-marker-slot-index marker)
                                                (zc-loan-marker-generation marker)
                                                (1- eligible)))))
            (setf (gethash sn (%inner-table (disc-node-samples node) guid)) marker
                  (gethash sn (%inner-table (disc-node-sample-writers node) guid)) writer-id
                  (gethash sn (%inner-table (disc-node-sample-writer-guids node) guid)) guid)
            (%record-sample-origin node guid sn effective-guid effective-sn)))
        (when (disc-node-on-sample node) (funcall (disc-node-on-sample node))))))
  t)

;; WP-DDS-SECURITY-ZEROALLOC-AEAD T5b: the loan-registry-backed plaintext handle for a SECURED loan-capable reader.
(defstruct* (secured-loan-handle (:constructor %make-secured-loan-handle))
  "WP-DDS-SECURITY-ZEROALLOC-AEAD T5b: the LOANED decoded plaintext of a secured (data_protection) sample. The
   receiver thread decodes the SecuredPayload into BUFFER (a decode-pool octet-buffer, via
   decode-serialized-payload-into — zero per-sample plaintext alloc) and stores THIS handle (not a bare vector)
   in disc-node-samples, so the pooled buffer's lifetime is tied to the loan registry (disc-node-secured-loan-vec)
   and node-return-loan, NOT the never-purged samples store. The recovered plaintext is BUFFER's octet vector
   over [0, LEN) — read it in place via secured-loan-bytes + secured-loan-handle-len (the loan contract; no copy).
   GUID/SN identify the samples-store slot so node-return-loan invalidates the dangling entry on release.
   T5d: the handle is itself POOLED (%secured-handle-acquire from disc-node-decode-handle-vec, recycled on
   release — no per-sample struct cons). On release it is FULLY DISSOCIATED (BUFFER->NIL, LEN->0, SN->0, GUID
   zeroed, REG-INDEX->-1) BEFORE re-entering the freelist so a stale reference cannot alias a new sample; GUID is
   reused in place (replace, no alloc) on refill. REG-INDEX is the handle's slot in disc-node-secured-loan-vec
   (-1 = not registered) — it gives O(1) swap-remove AND is the outstanding-flag that makes node-return-loan
   idempotent (reg-index<0 AND buffer NIL -> no-op). The freelist NEVER hands out a still-outstanding handle, so
   a deduped duplicate's fresh handle is always a DISTINCT object from the stored original -> the identity-guarded
   store-eviction (eq the slot occupant) stays correct with pooling. Distinguishable from a plain plaintext vector
   by SECURED-LOAN-HANDLE-P, mirroring how zc-loan-marker-p distinguishes the ZC-loan marker. NIL pool / secured
   loan OFF -> the allocating decode path stores a bare vector, byte-identical."
  (buffer nil :type t)                                                           ; the pooled octet-buffer (NIL after release)
  (len 0 :type fixnum)                                                           ; recovered plaintext length (BUFFER[0,LEN))
  (guid (make-array 16 :element-type '(unsigned-byte 8) :initial-element 0)
        :type (simple-array (unsigned-byte 8) (16)))                            ; samples-store outer key (source GUID); reused in place on refill
  (sn 0 :type integer)                                                           ; samples-store inner key (RTPS SN)
  (reg-index -1 :type fixnum)                                                    ; index in disc-node-secured-loan-vec (-1 = not registered); O(1) swap-remove + outstanding-flag
  (return-count 1 :type (integer 1)))                                            ; WP-N-ENDPOINT-2C3 (ADR 0048): # of co-located same-topic readers that will each return this shared handle once; %secured-loan-release purges the store slot + frees the buffer ONLY on the LAST return (defers so an early-returning reader-A does not deny reader-B its sample). 1 = N=1 (immediate purge, byte-identical)

(defun* secured-loan-bytes (handle)
    (function (secured-loan-handle) (simple-array (unsigned-byte 8) (*)))
  "The octet vector backing a secured loan HANDLE: the recovered plaintext lives in [0, secured-loan-handle-len)
   (read in place — the loan contract; no copy). Signals if the loan was already returned (BUFFER is NIL)."
  (dds.core.buffer:octet-buffer-vec (secured-loan-handle-buffer handle)))

(defun* %secured-handle-acquire (node)
    (function (disc-node) t)
  "WP-DDS-SECURITY-ZEROALLOC-AEAD T5d: pop a recycled secured-loan-handle off NODE's handle freelist (zero
   per-sample struct cons — mirrors pool-acquire). NIL on an empty freelist; the freelist is sized == the decode
   buffer pool and a handle is only acquired AFTER a buffer acquire succeeded (paired 1:1), so this never returns
   NIL when a buffer was free. CALLER holds decode-pool-lock (freelist top is shared: receiver pops, app pushes)."
  (let ((top (disc-node-decode-handle-top node)))
    (if (zerop top)
        nil
        (let ((nt (1- top)))
          (setf (disc-node-decode-handle-top node) nt)
          (let ((h (svref (disc-node-decode-handle-vec node) nt)))
            (setf (svref (disc-node-decode-handle-vec node) nt) nil)
            h)))))

(defun* %secured-handle-recycle (node handle)
    (function (disc-node secured-loan-handle) (values))
  "WP-DDS-SECURITY-ZEROALLOC-AEAD T5d: FULLY DISSOCIATE HANDLE (BUFFER->NIL, LEN->0, SN->0, GUID zeroed,
   REG-INDEX->-1) then return it to NODE's handle freelist for reuse. Dissociation BEFORE re-entry guarantees a
   stale handle reference cannot alias a freshly-refilled sample and that a recycled handle re-enters as -1/NIL
   (so a subsequent stray release is a no-op). CALLER holds decode-pool-lock (freelist push)."
  (setf (secured-loan-handle-buffer handle) nil
        (secured-loan-handle-len handle) 0
        (secured-loan-handle-sn handle) 0
        (secured-loan-handle-reg-index handle) -1
        (secured-loan-handle-return-count handle) 1)   ; WP-N-ENDPOINT-2C3: reset the shared-return counter before reuse (a fresh sample starts single-holder)
  (fill (secured-loan-handle-guid handle) 0)
  (let ((top (disc-node-decode-handle-top node)))
    (setf (svref (disc-node-decode-handle-vec node) top) handle
          (disc-node-decode-handle-top node) (1+ top)))
  (values))

(defun* %secured-handle-fill (handle buf plen guid sn)
    (function (secured-loan-handle dds.core.buffer:octet-buffer fixnum
              (simple-array (unsigned-byte 8) (16)) integer) secured-loan-handle)
  "WP-DDS-SECURITY-ZEROALLOC-AEAD T5d: populate a freshly-acquired pooled HANDLE for a new sample — the pooled
   BUFFER, recovered plaintext length PLEN, and the samples-store keys (GUID copied IN PLACE into the handle's
   own preallocated array, SN). No allocation (the guid array is reused). Receiver thread solely owns HANDLE here
   (not yet stored/registered) so no lock is needed."
  (setf (secured-loan-handle-buffer handle) buf
        (secured-loan-handle-len handle) plen
        (secured-loan-handle-sn handle) sn)
  (replace (secured-loan-handle-guid handle) guid)
  handle)

(defun* %secured-loan-register (node handle)
    (function (disc-node secured-loan-handle) (values))
  "WP-DDS-SECURITY-ZEROALLOC-AEAD T5d: append HANDLE to NODE's outstanding-loan registry vector and stamp its
   REG-INDEX (O(1), no cons — replaces the per-loan list push). The vector is sized == the decode pool and an
   outstanding registered loan always pins a pooled buffer, so the fill count never exceeds capacity. CALLER holds
   disc-node-lock."
  (let ((v (disc-node-secured-loan-vec node))
        (n (disc-node-secured-loan-count node)))
    (setf (svref v n) handle
          (secured-loan-handle-reg-index handle) n
          (disc-node-secured-loan-count node) (1+ n)))
  (values))

(defun* %secured-loan-deregister (node handle)
    (function (disc-node secured-loan-handle) (values))
  "WP-DDS-SECURITY-ZEROALLOC-AEAD T5d: remove HANDLE from NODE's registry vector by O(1) swap-remove (move the
   last entry into HANDLE's slot, fix that entry's REG-INDEX, shrink the count) and set HANDLE's REG-INDEX to -1.
   Idempotent: a handle already deregistered (REG-INDEX < 0) is a no-op. CALLER holds disc-node-lock."
  (let ((i (secured-loan-handle-reg-index handle)))
    (when (>= i 0)
      (let* ((v (disc-node-secured-loan-vec node))
             (last (1- (disc-node-secured-loan-count node)))
             (moved (svref v last)))
        (setf (svref v i) moved)
        (when (secured-loan-handle-p moved)
          (setf (secured-loan-handle-reg-index moved) i))
        (setf (svref v last) nil
              (disc-node-secured-loan-count node) last
              (secured-loan-handle-reg-index handle) -1))))
  (values))

;; ADR 0078: the RX store-copy pool helpers are defined after the pool-sizing specials (loaded later);
;; forward-declared so the purge choke below and %on-user-data reach them without an undefined-function
;; warning (the build fails on any promoted warning).
(declaim (ftype (function (disc-node (integer 0)) (or null dds.core.buffer:octet-buffer)) %rx-store-acquire))
(declaim (ftype (function (disc-node dds.core.buffer:octet-buffer) (values)) %rx-store-release))

(defun* %purge-secured-sample (node guid sn)
    (function (disc-node (simple-array (unsigned-byte 8) (16)) integer) t)
  "WP-SECURED-STORE-GROWTH: the SINGLE purge choke for a released / evicted / drained secured sample — remove
   (GUID,SN) from EVERY parallel per-(guid,sn) store table at one place so no table retains a released sample's
   metadata. Closes a pre-existing unbounded-heap-growth path: %secured-loan-release cleaned only
   disc-node-samples, leaking the parallel tables (sample-writers / -writer-guids / -origins / -key-hashes) on a
   never-drained secured stream (memory-exhaustion, attacker-drivable by a keyed peer streaming samples never
   loaned back). Zero-alloc — 5 gethash + up to 5 remhash, no cons (the macrolet expands inline) — so it stays on
   the drain/release path without perturbing the secured zero-alloc receive arms (operating contract §4 NFR-MEM).
   Caller holds the node lock. The inner per-GUID SN maps are left in place (bounded by the matched-writer count,
   not by sample count — §8.3.5.4), only their (GUID,SN) entry is dropped."
  ;; ADR 0078: this is the SINGLE choke every (GUID,SN) store entry is dropped through, so returning a pooled
  ;; store-copy buffer HERE covers every present and future drop path (node-consume-sample on the copy path,
  ;; %secured-loan-release on the loan path) with one site. A loan handle / ZC marker is a different type and
  ;; is skipped. Zero-cons: one gethash + a structure typep.
  (let ((inner (gethash guid (disc-node-samples node))))
    (when inner
      (let ((v (gethash sn inner)))
        (when (typep v 'dds.core.buffer:octet-buffer) (%rx-store-release node v)))))
  (macrolet ((drop (accessor)
               `(let ((inner (gethash guid (,accessor node)))) (when inner (remhash sn inner)))))   ; no auto-create; zero-cons
    (drop disc-node-samples)
    (drop disc-node-sample-writers)
    (drop disc-node-sample-writer-guids)
    (drop disc-node-sample-origins)
    (drop disc-node-sample-key-hashes)
    (drop disc-node-sample-timestamps))   ; S5.T4
  t)

(defun* node-sole-consumer-p (node guid)
    (function (disc-node (simple-array (unsigned-byte 8) (16))) t)
  "T iff AT MOST ONE local user reader is matched to remote writer GUID (its reader-route holds <= 1 id), so a
   sample from that writer has exactly ONE consumer and may be dropped from the shared node store the moment that
   reader has copied it out (node-consume-sample).

   This gate is the correctness crux of the purge: disc-node-samples is SHARED by all of a participant's readers,
   so with TWO same-topic readers (WP-N-ENDPOINT-2C1) purging on the FIRST reader's drain would delete the sample
   out from under the SECOND — silent data loss. When the route holds >= 2 readers the sample is therefore LEFT in
   the store (the pre-existing behaviour: it leaks, and the drain stays O(stored) for that reader set — recorded as
   the follow-on; a per-sample remaining-consumers refcount, like the ZC %zc-bump, is the general fix). Zero-cons."
  (let ((ids (gethash guid (disc-node-reader-routes node))))
    (or (null ids) (null (cdr ids)))))

(defun* node-consume-sample (node guid sn)
    (function (disc-node (simple-array (unsigned-byte 8) (16)) integer) t)
  "WP-PERF (the RX leak + the quadratic drain): drop the received sample (GUID, SN) from the node's store and
   every parallel per-(guid,sn) table, once the DCPS reader that owns it has COPIED it out (%drain-one-sample).

   WHY THIS HAS TO EXIST. Nothing ever removed a plain (copy-path) sample from disc-node-samples: every sample a
   participant ever received was retained FOREVER. That is (a) an unbounded memory leak, and (b) far worse, a
   QUADRATIC receive path — %drain rebuilds its pending-key list from the WHOLE store on EVERY take-samples, so
   the cost of a take grew linearly with the number of samples ever received (measured: an EMPTY take-samples
   cost 54 us / 5.9 KB at 200 stored samples and 278 us / 32 KB at 1000 — ~278 ns and ~32 B per stored sample,
   per call). A long-running reader got monotonically slower forever. The SECURED loan path already purged at
   this exact choke (%purge-secured-sample, WP-SECURED-STORE-GROWTH, which found the same leak class for a
   never-drained secured stream); the plain path simply never did.

   Safe for the loan paths: a loan-capable reader does NOT come here — its sample is invalidated by
   node-return-loan / %secured-loan-release (which own the buffer lifetime), so the store entry is dropped
   exactly once, by exactly one owner. Zero-cons (gethash + remhash only). Takes the node lock."
  (dds.pal:with-lock ((disc-node-lock node))
    (%purge-secured-sample node guid sn))
  t)

(defun* %secured-loan-release (node handle)
    (function (disc-node secured-loan-handle) t)
  "WP-DDS-SECURITY-ZEROALLOC-AEAD T5b/T5d: release HANDLE — invalidate its dangling store entry (WP-SECURED-STORE-GROWTH:
   %purge-secured-sample drops (GUID,SN) from ALL parallel per-(guid,sn) tables at one choke — a surviving handle
   would point at a recycled buffer = a wrong-bytes read, and the parallel tables would otherwise leak the released
   sample's metadata unbounded), deregister it from the loan registry, return its pooled plaintext buffer to the decode pool,
   and RECYCLE the (fully dissociated) handle to the freelist. Two disjoint cases share this one entry point:
   (1) a REGISTERED handle (REG-INDEX >= 0: a normally-accepted+stored loan) — evict its store slot
   IDENTITY-GUARDED (clear (GUID,SN) only when THIS handle still occupies it) then deregister; (2) an UNREGISTERED
   handle (REG-INDEX < 0: a deduped DUPLICATE's fresh handle, never stored/registered) — skip the store/registry
   entirely and just free its buffer. The identity guard + the never-hand-out-an-outstanding-handle freelist
   invariant mean a duplicate's handle is a DISTINCT object from the stored original, so the original is never
   evicted (no silent sample loss / no pinned slot). IDEMPOTENT / double-return-safe: after release REG-INDEX is
   -1 and BUFFER is NIL, so a repeated release (of a handle NOT since recycled for a new sample) is a no-op.
   Lock order: disc-node-lock OUTER (samples store + registry), decode-pool-lock INNER (buffer pool + handle
   freelist)."
  (dds.pal:with-lock ((disc-node-lock node))
    (when (>= (secured-loan-handle-reg-index handle) 0)   ; registered => a stored loan: evict store (identity-guarded) + deregister
      ;; WP-N-ENDPOINT-2C3 (ADR 0048; MEMORY-SAFETY): with K co-located same-topic secured readers, ALL K drain
      ;; THIS one stored handle (independent-struct deserialize at drain — already memory-safe) and each returns it
      ;; once. Purge the store slot + free the pooled buffer ONLY on the LAST return: a not-last returner just
      ;; decrements and leaves the entry live, so an early-returning reader-A can never purge (guid,sn) before a
      ;; not-yet-drained reader-B finds it (silent sample-LOSS). Per-reader return is single-shot (the DCPS
      ;; dr-secured-loans membership guard), so the counter decrements exactly K times. K=1 -> LAST immediately
      ;; (byte-identical). Return the LOCK here (unwinds with-lock) BEFORE touching the buffer.
      (when (> (secured-loan-handle-return-count handle) 1)
        (decf (secured-loan-handle-return-count handle))
        (return-from %secured-loan-release t))
      ;; T5d review Minor #1: this REG-INDEX>=0 gate is the PRIMARY dup-guard (a dedup duplicate's fresh handle is unregistered -> reg-index<0 -> filtered here, before any store touch); the eq identity-guard below is now redundant belt-and-suspenders.
      (let ((inner (gethash (secured-loan-handle-guid handle) (disc-node-samples node))))
        (when (and inner (eq (gethash (secured-loan-handle-sn handle) inner) handle))   ; identity-guard: a deduped duplicate must NOT evict the original occupant (silent loss + pinned slot)
          (%purge-secured-sample node (secured-loan-handle-guid handle) (secured-loan-handle-sn handle))))   ; WP-SECURED-STORE-GROWTH: purge ALL parallel tables, not just disc-node-samples
      (%secured-loan-deregister node handle))
    (let ((buf (secured-loan-handle-buffer handle)))
      (when buf
        (dds.pal:with-lock ((disc-node-decode-pool-lock node))
          (dds.core.arena:pool-release (disc-node-decode-pool node) buf)
          (%secured-handle-recycle node handle)))))   ; recycle only when a buffer was actually freed -> idempotent
  t)

(defun* node-return-loan (node loans &optional (count -1))
    (function (disc-node t &optional fixnum) t)
  "DataReader::return_loan for the SECURED decode loan (WP-DDS-SECURITY-ZEROALLOC-AEAD T5b/T5d read contract):
   release the loans taken via node-take-loaned. Each release invalidates the samples-store entry, returns the
   pooled plaintext buffer to the decode pool, and recycles the handle to the freelist. Three call shapes:
   (NODE VEC COUNT) — the canonical ZERO-CONS form: release every secured-loan-handle in VEC[0,COUNT) (exactly
     the (values VEC COUNT) node-take-loaned returns; non-handle bare-vector elements are skipped); (NODE HANDLE)
     — release a single handle; (NODE LIST) — release each handle in LIST (legacy). IDEMPOTENT (a returned /
     recycled / never-loaned handle is skipped: its REG-INDEX is < 0 and its buffer NIL). COUNT is MANDATORY for
     a VECTOR of loans (ADR 0038 residual g RESOLVED): a reused node-take-loaned VEC's tail holds handles from
     PRIOR takes that may since have been recycled onto NEW outstanding samples, so walking the whole vector could
     prematurely double-release a live loan; passing a vector WITHOUT its populated COUNT now SIGNALS an error
     rather than walking that stale tail — the double-release is impossible by construction. The app MUST return
     every loan it takes AND must NOT retain/reuse a handle after returning it (a returned handle may be recycled
     for a new sample — use-after-return is a caller-contract violation, memory-safe within the arena but
     undefined); a leaked loan pins a decode-pool slot until the pool exhausts (SAMPLE_REJECTED / writer
     backpressure, graceful — never GC, never a crash)."
  (declare (type fixnum count))
  (cond ((secured-loan-handle-p loans) (%secured-loan-release node loans))
        ((vectorp loans)
         (when (< count 0)   ; ADR 0038 residual g: a vector's stale tail must never be walked -> premature double-release
           (error "node-return-loan: a vector of loans MUST be returned with its populated COUNT (its stale tail could double-release a live loan)")) ; NOCOND(GUARD): a negative loan COUNT is caller misuse; cannot fire on valid input; contained at the node-return-loan API (defense against double-release)
         (dotimes (i count) (let ((h (aref loans i))) (when (secured-loan-handle-p h) (%secured-loan-release node h)))))
        ((listp loans) (dolist (h loans) (when (secured-loan-handle-p h) (%secured-loan-release node h)))))
  t)

(defun* node-return-all-loans (node)
    (function (disc-node) t)
  "WP-DDS-SECURITY-ZEROALLOC-AEAD T5b reader-close safety: return EVERY outstanding secured loan (over a snapshot
   of the registry vector) so stop-node leaves no acquired buffer outside the pool — teardown-arena frees the
   pool's slots, and an un-returned (acquired) buffer is NOT in the slots, so it must be released first or its
   static memory leaks. Called by stop-node AFTER the receiver thread is joined (no concurrent acquire). The
   snapshot is taken first (release swap-removes from the same vector), then each handle is released once; the
   teardown-time snapshot list is off the hot path."
  (dolist (h (dds.pal:with-lock ((disc-node-lock node))
               (loop with v = (disc-node-secured-loan-vec node)
                     for i below (disc-node-secured-loan-count node)
                     collect (svref v i))))
    ;; WP-N-ENDPOINT-2C3: teardown = no reader will drain/return again, so force the FULL release of every still-
    ;; registered handle (reset the shared-return counter to 1) — an un-drained multi-reader handle must not stay
    ;; deferred past teardown (its pooled buffer would leak outside the pool slots before teardown-arena).
    (when (secured-loan-handle-p h) (setf (secured-loan-handle-return-count h) 1))
    (%secured-loan-release node h))
  t)

(defun* node-take-loaned (node)
    (function (disc-node) (values simple-vector fixnum))
  "DataReader::take by LOAN for the SECURED decode path (WP-DDS-SECURITY-ZEROALLOC-AEAD T5b/T5d read contract).
   Snapshot the received user samples into NODE's REUSED take buffer and return (values VEC COUNT): VEC[0,COUNT)
   are the per-sample values — a secured-loan-handle for a secured loan-capable reader (read the plaintext in
   place via secured-loan-bytes + secured-loan-handle-len, zero copy) or a bare plaintext vector for any non-loan
   sample mixed in. Pass VEC and COUNT straight to node-return-loan. VEC is the node's own scratch vector, REUSED
   across calls (the next take clobbers it) with a SINGLE consumer (the node's one user reader), so a steady-state
   take conses 0 B (T5d); it grows once (off steady state) only if the store ever holds more samples than the
   carved capacity (only reachable in the arena-carve-fail bare-vector fallback below). ARENA-CARVE-FAIL FALLBACK:
   if the decode pool could not be carved (arena exhausted at the first secured sample) the reader stays
   loan-capable but the store holds BARE plaintext vectors (byte-correct); they ride in VEC with NO loan, so a
   caller MUST test secured-loan-handle-p before secured-loan-bytes (the same test the mixed non-loan case needs).
   INVARIANT THIS RELIES ON (ADR 0078): a plaintext value here is a BARE VECTOR, never a pooled RX store-copy
   octet-buffer — %on-user-data refuses to pool for a SECURED-LOAN-CAPABLE node precisely so that this
   two-way dispatch stays exhaustive. Relaxing that gate means teaching every caller here a third type.
   The buffer is held by the loan until node-return-loan releases it, so the app's in-place read can never race a
   pool recycle. Leaves the samples in the store until node-return-loan invalidates them (mirrors take-loaned)."
  (dds.pal:with-lock ((disc-node-lock node))
    (let ((vec (or (disc-node-secured-take-vec node)
                   (setf (disc-node-secured-take-vec node) (make-array 16 :initial-element nil))))
          (i 0))
      (declare (type simple-vector vec) (type fixnum i))
      (maphash (lambda (guid inner)
                 (declare (ignore guid))
                 (loop for v being the hash-values of inner do
                   (when (>= i (length vec))                                     ; grow (off steady state; carved cap covers the pooled path)
                     (let ((bigger (make-array (* 2 (length vec)) :initial-element nil)))
                       (replace bigger vec)
                       (setf vec bigger (disc-node-secured-take-vec node) bigger)))
                   (setf (svref vec i) v)
                   (incf i)))
               (disc-node-samples node))
      (values vec i))))

;; WP-DDS-SECURITY-ZEROALLOC-AEAD T5b: defined after the secured-pool sizing specials (loaded later); forward-declared
;; so %deliver-user-sample reaches the lazy decode-pool carve without an undefined-function warning.
(declaim (ftype (function (disc-node) t) %ensure-secured-decode-pool))
;; WP-SECURED-STORE-GROWTH: node-sample-count is defined below; forward-declared so the carve-fail cap in
;; %deliver-user-sample reaches it without an undefined-function warning (build fails on any promoted warning).
(declaim (ftype (function (disc-node) (integer 0)) node-sample-count))

(defparameter *decode-fail-suppress-threshold* 3
  "WP-RESIDUAL-FIXES-BATCH-A / ADR 0031 limitation 1 (RTPS 2.5 §8.3.5 / §8.4): the number of CONSECUTIVE
   KM-PRESENT decode failures of ONE (writer-GUID, SN) after which the reliable reader locally SUPPRESSES that
   SN — marks it GAP-equivalent-irrelevant (reader-suppress-sn) so the writer stops retransmitting it. NEVER
   applies to a missing-KM failure (that returns before counting; the key-exchange race must keep self-healing).
   FAIL-SAFE ordering: BELOW the threshold the sample keeps retransmitting (a transient wire corruption or a
   slow-arriving-but-present key still recovers — no data loss); AT/ABOVE it, delivery is FAIL-CLOSED
   (undecodable/tampered data is never delivered) and availability is BOUNDED (the unbounded retransmit churn
   stops). 3 tolerates a couple of transient re-tries before deciding the sample is permanently undecodable.")

(defparameter *decode-fail-track-limit* 256
  "WP-RESIDUAL-FIXES-BATCH-A / ADR 0031 limitation 1: the per-writer cap on the decode-failure counter's inner
   SN map (bounded memory — NFR-MEM / NFR-SEC-POSTURE, mirroring *max-gap-range*). At the cap a further DISTINCT
   failing SN is not newly tracked (it keeps retransmitting — bounded per-writer churn, never unbounded memory);
   an ALREADY-tracked SN still progresses to suppression. The whole per-writer map is also pruned on writer
   unmatch (%lease-sweep), so the table is bounded by matched-writer count × this limit.")

(defun* %decode-fail-clear (node guid sn)
    (function (disc-node (simple-array (unsigned-byte 8) (16)) integer) t)
  "ADR 0031 lim.1: drop any decode-failure counter for (GUID, SN) — a sample that DECODED clears its transient
   failure count so it never counts toward a future unrelated suppression and frees a track-limit slot. Called on
   the accept path under the node lock, GATED on a non-empty table so the steady-state (zero-failure) zero-alloc
   secured receive arm is untouched (the guard is one hash-table-count, no gethash/cons). Zero-cons."
  (let ((entry (gethash guid (disc-node-decode-fail-counts node))))   ; no auto-create; value = (km-key-id . SN-table)
    (when entry (remhash sn (cdr entry))))
  t)

(defun* %decode-fail-inner (node guid km)
    (function (disc-node (simple-array (unsigned-byte 8) (16)) t) hash-table)
  "The per-writer SN->failure-count table for GUID, STAMPED with the identity of the KM the failures were
   classified under (its §9.5.2 sender_key_id) — and RESET whenever that identity changes (ADR 0059).

   WHY THE STAMP. A count here means 'this SN failed to decode while its KM was PRESENT', which %secured-decode-fail
   reads as tamper-or-permanent-mismatch and eventually SUPPRESSES (stops the reliable repair). That classification
   is only sound while a live writer's KeyMaterial is never REPLACED with samples in flight. If a future rekeying WP
   rotates a writer's KM, samples encoded under the NEW key would keep counting against the STALE classification,
   cross the threshold, be suppressed — and then be silently LOST when the retransmit finally becomes decodable (the
   SN is already GAP-irrelevant). ADR 0031 lim.1 recorded that as a FORWARD REQUIREMENT on the rekey WP; stamping the
   table discharges it HERE instead, so a future rotation cannot inherit the bug by forgetting: a new key id is a new
   classification, and the stale counts are dropped. Costs one 4-octet compare on a path that only runs when a decode
   has ALREADY failed (never on the steady-state zero-alloc receive arm). CALLER HOLDS the node lock."
  (let* ((outer (disc-node-decode-fail-counts node))
         (entry (gethash guid outer))
         (kid   (and km (dds.security:key-material-sender-key-id km))))
    (if (and entry (equalp (car entry) kid))
        (cdr entry)
        (let ((fresh (make-hash-table :test 'eql)))   ; no entry, or the KM identity changed -> a FRESH classification
          (setf (gethash (copy-seq guid) outer) (cons kid fresh))
          fresh))))

(defun* %secured-decode-fail (node guid sn km)
    (function (disc-node (simple-array (unsigned-byte 8) (16)) integer t) t)
  "ADR 0031 lim.1 (RTPS 2.5 §8.3.5 / §8.4): record ONE KM-PRESENT decode failure of (GUID, SN) and, once it has
   failed *decode-fail-suppress-threshold* times, SUPPRESS the SN (reader-suppress-sn marks it GAP-irrelevant) so
   the reliable writer stops retransmitting a sample that can never decode. Called ONLY from the KM-present decode
   branches of %deliver-user-sample (the missing-KM branch returns earlier, uncounted — the key race self-heals).
   KM is the KeyMaterial the failed decode was attempted under: its identity STAMPS the counter table, so a future
   KM rotation resets the classification instead of suppressing samples encoded under the new key (%decode-fail-inner,
   ADR 0059 — discharging the ADR 0031 lim.1 forward requirement).
   Bounded: an existing counter always progresses to suppression; a NEW SN is tracked only below
   *decode-fail-track-limit* (else it keeps retransmitting — bounded churn over unbounded memory). Node-lock
   guarded (the counter table is also pruned under that lock by %lease-sweep). Receiver-thread call."
  (let ((suppressed nil))
    (dds.pal:with-lock ((disc-node-lock node))
      (let ((inner (%decode-fail-inner node guid km)))
        (multiple-value-bind (cur present) (gethash sn inner)
          (let ((n (1+ (if present (the fixnum cur) 0))))
            (declare (type fixnum n))
            (cond
              ((>= n *decode-fail-suppress-threshold*)
               (dds.rtps.reliable:reader-suppress-sn (disc-node-user-reader node) guid sn)   ; persistent KM-present failure -> stop the NACK/repair of this SN
               (remhash sn inner)
               (setf suppressed t))                                                          ; ADR 0060: the sample is now permanently gone -> SAMPLE_LOST (fired OUTSIDE the lock)
              ((or present (< (hash-table-count inner) *decode-fail-track-limit*))
               (setf (gethash sn inner) n)))))))   ; below cap / already tracked: keep counting (retransmit continues, still recoverable)
    ;; ADR 0060 (DDS 1.4 §2.2.4.1): a SUPPRESSED SN will never be delivered — the reader stops NACKing it, so no
    ;; retransmit can ever recover it. That is precisely a LOST sample, so raise SAMPLE_LOST on the DataReader(s)
    ;; routed from this writer, exactly as the irrecoverable-GAP path does (%on-user-gap). ADR 0054 left this
    ;; uncounted in v1 ("reader-suppress-sn not counted as SAMPLE_LOST"), which under-reported a real loss: the
    ;; application saw the sample silently vanish with no status. Fired OUTSIDE the node lock (the hook re-enters
    ;; DCPS, which takes its own locks — the %fire-unmatch / on-participant-lost discipline).
    (when (and suppressed (disc-node-on-sample-lost node))
      (dolist (rr (%reader-routes-for node guid))
        (funcall (disc-node-on-sample-lost node) (car rr) 1))))
  t)

(defun* %deliver-user-sample (node writer-id sn vec src-prefix effective-guid effective-sn
                             &optional key-hash overlay-secured pooled)
    (function (disc-node (unsigned-byte 32) integer (simple-array (unsigned-byte 8) (*))
              (simple-array (unsigned-byte 8) (12))
              (simple-array (unsigned-byte 8) (16)) integer
              &optional (or null (simple-array (unsigned-byte 8) (*))) t
              (or null dds.core.buffer:octet-buffer)) t)
  "Feed a complete user sample VEC (SN from WRITER-ID at SRC-PREFIX) to the reliable reader, record it
   under the 2-level (source-GUID -> SN) store (payload + writer EntityId for the S2 writers-set + full
   source GUID for S1 EXCLUSIVE ownership arbitration), then fire ON-SAMPLE outside the node lock
   (DATA_AVAILABLE + WaitSet wake). Two-level keying by GUID then SN avoids a per-sample composite-key
   alloc (NFR-MEM) and stops two writers sharing EntityId 0x102 from aliasing in the SN space
   (§8.3.5.4); ONE %source-guid per sample is reused for the reliable-reader proxy key AND the three inner tables.
   EFFECTIVE-GUID/EFFECTIVE-SN are the logical-origin GUID+SN for dedup (orig-guid/orig-sn on the relay
   path; wire GUID+SN on the direct path) per RTPS 2.5 §8.3.5.4.
   KEY-HASH (ADR 0029, RTPS 2.5 §9.6.4.8): the captured wire PID_KEY_HASH; NIL unless the node has
   capture-data-key-hash set. Stored via %record-sample-key-hash inside the lock.
   DDS-Security §9.5.3.3.4.5 decode (ADR 0031): crypto-keys resolver or Slice-1 key-material; fail-closed on nil
   key or bad ciphertext. WP-DDS-SECURITY-ZEROALLOC-AEAD T5b: when the reader is SECURED-LOAN-CAPABLE, decode the
   SecuredPayload into a DECODE-POOL buffer (decode-serialized-payload-into — zero per-sample plaintext alloc) and
   store a SECURED-LOAN-HANDLE (not a bare plaintext vector), registering it in the loan registry so node-return-loan
   releases the buffer; pool exhaustion -> SAMPLE_REJECTED (drop + count, un-acked -> writer backpressure, never GC);
   decode failure / a deduped duplicate releases the buffer (no leak). WP-DDS-SECURITY-ZEROALLOC-AEAD T5d: the
   handle is POOLED (%secured-handle-acquire, paired 1:1 with the buffer pool) and the registry is a fixed vector,
   so the accepted loan wrapper conses 0 B/sample. Security OFF or not loan-capable keeps the allocating decode ->
   bare-vector path, byte-identical.
   OVERLAY-SECURED (WP-SECURITY-ZC-SHMEM-OVERLAY, ADR 0051): T when this sample is a resolved ZC overlay slot —
   a data_protection SecuredPayload sealed under the writer's EntityCrypto key (%on-user-data threads it from
   %zc-try-resolve's reserved-field 2nd value). It ORs into the decode gate so the SecuredPayload is decoded to
   plaintext EVEN when the reader's OWN data_protection governance is NONE (an ENCRYPT-tier writer regains
   Zero-Copy with no cleartext in SHMEM); the KM resolves + fail-closes via the SAME block as a normal
   data_protection decode (no parallel path). NIL (default) is byte-identical to every pre-overlay caller.
   POOLED (ADR 0078, NFR-MEM): when the receiver thread copied this sample into a buffer drawn from the node's
   RX store-copy pool, that octet-buffer — VEC is then its backing vector and the buffer's CAPACITY is the exact
   payload extent. It becomes the STORED value (a pooled entry is a DISTINCT TYPE, so no extent-unaware consumer
   can misread it) and is returned to the pool at the store-drop choke, or here on the dedup-reject arm. It is
   drawn only for a node with NO crypto-transform; should a live handshake have installed one since, the decode
   below needs the EXACT ciphertext extent, so the buffer is returned and the exact-length vector materialised
   (the pre-pool path, byte-identical). NIL (the default, and always on the secured path) changes nothing."
  (let* ((guid (%source-guid src-prefix writer-id))   ; ONE source GUID: km-resolve + reliable proxy + the three inner tables + the loan handle
         (routes (%reader-routes-for node guid))       ; WP-N-ENDPOINT-S2/S4: the reader(s) matched to this writer — resolved ONCE (tier + delivery, DRY)
         (canon (and routes (cdr (first routes))))     ; the CANONICAL engine reader (single reliability truth for this writer)
         (rid (if routes (car (first routes)) (disc-node-user-reader-id node)))   ; WP-N-ENDPOINT-S4: the target reader's EntityId (route id; N=1/pre-match -> primary id)
         (rkind (%user-endpoint-kinds node rid))       ; WP-N-ENDPOINT-S4 (ADR 0046/0048): THIS reader's OWN data_protection tier (per-endpoint map; N=1 -> node-single, byte-identical)
         (stored (or pooled vec))                      ; the value stored in disc-node-samples (a plaintext vec, an ADR 0078 pooled octet-buffer, or a T5b secured-loan-handle)
         (loan nil))                                   ; non-NIL = the pooled-buffer loan handle to register / release-on-reject (T5b)
    ;; §9.4.1.2.4: apply the SecuredPayload (data_protection) DECODE UNLESS governance set data_protection=NONE (data=NONE:
    ;; the payload rides PLAIN; decoding a plain payload as a SecuredPayload fails-closed and would DROP every sample).
    ;; :unset (no governance) keeps the decode — direct-KM path unchanged. The tier is selected by the resolved km's
    ;; transformation_kind: data=ENCRYPT -> AES-256-GCM open; data=SIGN -> AES256-GMAC verify of the VISIBLE payload
    ;; (decode-serialized-payload GMAC sub-tier, fail-closed on tamper). data_protection=SIGN (payload-tier GMAC) is
    ;; IMPLEMENTED; supported tiers: NONE + SIGN + ENCRYPT (ADR-0040 §9.5.3.3.4.3). WP-N-ENDPOINT-S4: the tier is
    ;; RKIND — the target reader's OWN topic kind (per-endpoint map), so 2 different-topic readers of different kinds
    ;; each decode under their OWN tier (no cross-tier decode); N=1 RKIND == the node-single slot (byte-identical).
    ;; WP-SECURITY-ZC-SHMEM-OVERLAY (ADR 0051): a ZC overlay sample is a data_protection SecuredPayload even when
    ;; the reader's own data_protection governance is NONE — OVERLAY-SECURED forces the decode (the KM resolves as
    ;; the remote-writer EntityCrypto key exactly as the normal data_protection decode; fail-closed reuse below).
    (let ((ct (and (or overlay-secured (not (eq rkind :none))) (disc-node-crypto-transform node))))
      ;; ADR 0078: the RX store pool is drawn only for a node with NO crypto-transform, but the transform can be
      ;; installed by a live DDS-Security handshake between that test (on the receiver thread, before this call)
      ;; and here. The decode below reads VEC as the CIPHERTEXT and needs its exact extent, which a fixed-size
      ;; pooled buffer does not carry in its length — so return the buffer and materialise the exact-length
      ;; vector, taking the pre-pool path unchanged. Never in steady state (one test, both arms constant-time);
      ;; it also guarantees POOLED is NIL inside the CT block, so none of its early returns can leak a slot.
      (when (and ct pooled)
        (setf vec (subseq vec 0 (dds.core.buffer:octet-buffer-capacity pooled)))
        (%rx-store-release node pooled)
        (setf pooled nil stored vec))
      (when ct
        (let ((km (if (typep ct 'dds.security:crypto-keys)
                      (funcall (dds.security:crypto-keys-decode-key-fn ct) guid)
                      ct)))
          (unless km (return-from %deliver-user-sample t))
          (if (disc-node-secured-loan-capable node)
              ;; T5b LOAN path: decode into a POOLED buffer; store a length-tagged handle (zero per-sample plaintext alloc)
              (let ((pool (%ensure-secured-decode-pool node)))
                (if (null pool)
                    ;; arena carve failed -> bounded allocating fallback (byte-identical, correct). WP-SECURED-STORE-GROWTH:
                    ;; a carve-fail bare vector carries no loan, so node-return-loan can never purge it -> an undrained
                    ;; carve-fail stream would grow the store unbounded. Cap the undrained store at the SAME working-set
                    ;; budget the pool would have used (*secured-pool-capacity* + *secured-pool-headroom*): fail-closed
                    ;; RESOURCE_LIMITS (SAMPLE_REJECTED) at the cap, mirroring pool exhaustion, never a GC-silent unbounded
                    ;; store (operating contract §4 NFR-MEM). The reject precedes reader-on-data -> un-acked -> writer backpressure.
                    (if (>= (node-sample-count node) (+ *secured-pool-capacity* *secured-pool-headroom*))
                        (progn (incf (disc-node-decode-pool-rejects node))
                               (return-from %deliver-user-sample t))
                        (let ((plain (dds.security:decode-serialized-payload km vec)))
                          (unless plain (%secured-decode-fail node guid sn km) (return-from %deliver-user-sample t))   ; ADR 0031 lim.1: KM present, decode failed -> bounded suppression
                          (setf stored plain)))
                    ;; T5d: acquire buffer + pooled handle together (paired 1:1 capacity -> the handle acquire
                    ;; succeeds whenever a buffer was free; the defensive release keeps it never-crash/never-GC)
                    (multiple-value-bind (buf h)
                        (dds.pal:with-lock ((disc-node-decode-pool-lock node))
                          (let ((b (dds.core.arena:pool-acquire pool)))
                            (if b
                                (let ((hh (%secured-handle-acquire node)))
                                  (if hh
                                      (values b hh)
                                      (progn (dds.core.arena:pool-release pool b) (values nil nil))))
                                (values nil nil))))
                      (if (null buf)
                          ;; pool exhausted -> SAMPLE_REJECTED: drop + count, do NOT advance the reliable reader (un-acked -> writer backpressure), never GC
                          (progn (incf (disc-node-decode-pool-rejects node))
                                 (return-from %deliver-user-sample t))
                          (let ((plen (dds.security:decode-serialized-payload-into buf km vec)))
                            (if (null plen)
                                ;; decode failed -> release the buffer + recycle the handle (no leak), fail-closed drop
                                (progn (dds.pal:with-lock ((disc-node-decode-pool-lock node))
                                         (dds.core.arena:pool-release pool buf)
                                         (%secured-handle-recycle node h))
                                       (%secured-decode-fail node guid sn km)   ; ADR 0031 lim.1: KM present, decode failed (pool-lock released first: node-lock is OUTER)
                                       (return-from %deliver-user-sample t))
                                (progn (%secured-handle-fill h buf plen guid sn)
                                       (setf stored h loan h))))))))
              ;; non-loan secured path: allocating decode -> bare vec (byte-identical to the shipped path)
              (let ((plain (dds.security:decode-serialized-payload km vec)))
                (unless plain (%secured-decode-fail node guid sn km) (return-from %deliver-user-sample t))   ; ADR 0031 lim.1: KM present, decode failed -> bounded suppression
                (setf stored plain))))))
    ;; reader-on-data ALWAYS (keeps reliable NACK/HEARTBEAT state correct for relay proxy too); the loan path feeds
    ;; the proxy an EMPTY payload (the plaintext lives in the loaned buffer, not the proxy) — mirrors %deliver-user-marker.
    ;; WP-N-ENDPOINT-S2 (ADR 0048): drive the CANONICAL reader matched to this writer (ROUTES/CANON resolved once
    ;; above; N=1/pre-match -> the primary, byte-identical). The node-global store + the per-reader %drain filter
    ;; separate delivery per reader.
    (when canon
      (dds.rtps.reliable:reader-on-data canon guid sn
                                        (if loan
                                            (load-time-value (make-array 0 :element-type '(unsigned-byte 8)))
                                            (if pooled vec stored))))   ; ADR 0078: STORED is the octet-buffer when pooled — hand the engine the backing VECTOR (it ignores the payload, but the declared type is a vector)
    (cond
      ;; app delivery gated: only if this (logical-origin GUID, SN) pair is new (§8.3.5.4)
      ((and canon (dds.rtps.reliable:reader-dedup-accept-p canon effective-guid effective-sn))
       (dds.pal:with-lock ((disc-node-lock node))
         (setf (gethash sn (%inner-table (disc-node-samples node) guid)) stored
               (gethash sn (%inner-table (disc-node-sample-writers node) guid)) writer-id
               (gethash sn (%inner-table (disc-node-sample-writer-guids node) guid)) guid)
         (%record-sample-origin node guid sn effective-guid effective-sn)
         (%record-sample-key-hash node guid sn key-hash)
         (%record-sample-timestamp node guid sn *rx-source-timestamp*)   ; S5.T4: the INFO_TS source_timestamp (ns) preceding this DATA (NIL default = none)
         (when (plusp (hash-table-count (disc-node-decode-fail-counts node)))   ; ADR 0031 lim.1: gated -> steady-state (no failures) keeps the zero-alloc secured arm untouched
           (%decode-fail-clear node guid sn))
         (when loan
           ;; WP-N-ENDPOINT-2C3 (ADR 0048): all K readers matched to this writer (ROUTES) drain THIS one stored
           ;; handle and each returns it once — record K so %secured-loan-release purges the store slot + frees the
           ;; buffer only on the LAST return (no early-return sample-loss). K=1 (N=1) -> immediate purge, byte-identical.
           (setf (secured-loan-handle-return-count loan) (max 1 (length routes)))
           (%secured-loan-register node loan)))   ; T5b/T5d: register the loan in the fixed registry vector (receiver registers; app return-loan releases)
       (when (disc-node-on-sample node) (funcall (disc-node-on-sample node))))
      ;; T5b: a deduped DUPLICATE on the loan path -> release the unused pooled buffer (no store, no leak)
      (loan (%secured-loan-release node loan))
      ;; ADR 0078: the same for the copy path — a deduped duplicate (or no canonical reader) was never stored,
      ;; so nothing will ever reach the store-drop choke to return its buffer. Release it here.
      (pooled (%rx-store-release node pooled))))
  t)

(defun* %on-user-data (node writer-id sn buf poff plen src-prefix
                       &optional orig-guid orig-sn key-hash)
    (function (disc-node (unsigned-byte 32) integer dds.core.buffer:octet-buffer (integer 0) (integer 0)
              (simple-array (unsigned-byte 8) (12))
              &optional
              (or null (simple-array (unsigned-byte 8) (16)))
              (or null integer)
              (or null (simple-array (unsigned-byte 8) (*)))) t)
  "Reader side: deliver the DATA SerializedPayload at BUF[poff,poff+plen). WP-ZEROCOPY (FR-PF-3, ADR
   0014): when this node has a ZC pool (which exists iff *zerocopy-enabled* was set at make-disc-node —
   the gate is the SLOT, not the special, because this runs on the receiver thread where a dynamic
   binding is invisible), FIRST test the payload for a 16-byte zero-copy reference (%zc-try-resolve) — a
   valid ref is resolved from the writer pool to the real serialized payload (then delivered exactly as a
   normal sample); an INVALID ref (stale/forced/OOB/attach-fail) is DROPPED best-effort (no delivery, no
   crash); a normal payload (:not-a-ref) takes the existing copy-and-deliver path verbatim. With ZC off
   (no pool) the ref test is skipped entirely — byte-identical to today (dedup/reorder, store by SN, fire
   ON-SAMPLE outside the node lock — no lock-order inversion).
   WP-FLATDATA-ZC-LOAN (FR-PF-3/4, R6, ADR 0017; NOT cleared for ship — pending counsel): when this node's
   local reader is ZC-LOAN-CAPABLE (DCPS marked it — a :flatdata topic + ZC armed), a valid ref is stored as an
   UNRESOLVED ZC-LOAN-MARKER (%zc-defer) and NOT released — the slot stays loaned via the writer's refcount so
   DCPS take-loaned reads it in place (literal 0 intra-host copies) and return-loan releases it; releasing here
   would free the slot before the app's later read (use-after-free). A non-loan-capable reader keeps the shipped
   resolve-copy-release path (%zc-try-resolve), byte-unchanged.
   ORIG-GUID/ORIG-SN: from PID_ORIGINAL_WRITER_INFO (§8.3.5.4) on relay-forwarded samples; NIL on direct
   path. KEY-HASH: the wire PID_KEY_HASH (RTPS 2.5 §9.6.4.8) when the node has capture-data-key-hash set;
   NIL otherwise. The effective logical-origin (orig-guid or wire-guid, orig-sn or wire-sn) is computed here and
   threaded into %deliver-user-sample/%deliver-user-marker for the dedup gate."
  ;; effective-guid/sn: relay path uses PID values; direct path uses the wire writer GUID + SN
  (let* ((eff-guid (or orig-guid (%source-guid src-prefix writer-id)))
         (eff-sn   (or orig-sn sn)))
    (multiple-value-bind (zc overlay)
        (cond
          ((null (disc-node-zc-pool node)) :not-a-ref)              ; ZC off -> normal path (overlay -> NIL, unused: :not-a-ref arm)
          ((and (disc-node-zc-loan-capable node)
                (not (%zc-ref-overlay-p buf poff plen)))            ; ADR 0051: an overlay slot is ciphertext -> cannot be read in place -> copy-on-read
           (%zc-defer node buf poff plen src-prefix))
          (t (%zc-try-resolve node buf poff plen src-prefix)))      ; the ONLY arm that yields a numeric overlay (2nd value)
      (cond
        ((null zc))                                                 ; armed + ref present but defer/resolve FAILED -> drop (best-effort)
        ((eq zc :not-a-ref)                                         ; normal payload (or ZC off)
         ;; ADR 0078 (NFR-MEM): the copy out of the reusable receive buffer is drawn from the node's RX
         ;; store-copy pool — the last receive-path allocation that scaled with payload size. No pool /
         ;; exhausted / oversize -> OB is NIL and the copy allocates exactly as before, byte-identical;
         ;; exhaustion here is never data loss, because the drain copies the sample out again into an
         ;; independent struct. TWO GATES, both about a SECURED node, and both structural rather than
         ;; incidental: (a) NO CRYPTO-TRANSFORM — the secured arm of %deliver-user-sample reads VEC as
         ;; ciphertext and needs its exact extent (it has its own T5b decode pool); (b) NOT SECURED-LOAN-CAPABLE
         ;; — node-take-loaned hands the store's VALUES to the app, whose contract is "a secured-loan-handle or
         ;; a bare plaintext vector", and its callers dispatch on secured-loan-handle-p alone; a pooled buffer
         ;; reaching there would be read as a bare vector. That is reachable in the window where a node is
         ;; marked loan-capable but the live handshake has not yet installed its transform, so gate (a) does not
         ;; subsume gate (b). Such a node's steady state is the loan path, which is already pooled — excluding
         ;; it costs nothing.
         (let* ((ob  (and (null (disc-node-crypto-transform node))
                          (not (disc-node-secured-loan-capable node))
                          (%rx-store-acquire node plen)))
                (vec (if ob
                         (dds.core.buffer:octet-buffer-vec ob)
                         (make-array plen :element-type '(unsigned-byte 8)))))
           (replace vec (dds.core.buffer:octet-buffer-vec buf) :end1 plen :start2 poff :end2 (+ poff plen))
           (%deliver-user-sample node writer-id sn vec src-prefix eff-guid eff-sn key-hash nil ob)))
        ((zc-loan-marker-p zc)
         (%deliver-user-marker node writer-id sn zc src-prefix eff-guid eff-sn)) ; loan-capable: the unresolved marker
        ;; resolved ZC payload (non-loan-capable): OVERLAY is numeric here (only the %zc-try-resolve arm reaches this);
        ;; a data_protection SecuredPayload slot (ADR 0051) forces the in-slot decode in %deliver-user-sample.
        (t (%deliver-user-sample node writer-id sn zc src-prefix eff-guid eff-sn key-hash
                                 (= (or overlay 0) dds.cdr:+zc-ref-overlay-secured+)))))
    t))

(defun* %on-user-heartbeat (node c flags src-prefix)
    (function (disc-node dds.core.buffer:cursor (unsigned-byte 8) (simple-array (unsigned-byte 8) (12))) t)
  "Reader side: apply the HEARTBEAT's available range, then answer with an ACKNACK
   (acking received SNs, NACKing the rest) to each peer (uses rx-tx-msg). The reliable reader-proxy is
   keyed by the remote writer's FULL 16-octet GUID (SRC-PREFIX + WID, §9.4.4 / §9.3.1.2) so two writers
   sharing EntityId 0x102 across participants keep independent received-SN / ACKNACK state (§8.3.5.4).
   WP-ACKNACK-MATCH-GATE (RTPS 2.5 §8.4.10.1; DDS 1.4 §2.2.3.4): the HEARTBEAT is applied and answered ONLY
   for a MATCHED writer (%guid-matched-p) — a pre-match HEARTBEAT (a periodic user HEARTBEAT arriving before
   the reader has processed the writer's SEDP publication) must NOT create a WriterProxy with skip-history NIL
   nor NACK the full [1..N] pre-join range before the on-match durability baseline is armed (which would let a
   VOLATILE late-joiner wrongly pull a retaining writer's pre-match history); it is DROPPED and the writer's
   next periodic HEARTBEAT re-arrives post-match, when the correct durability baseline applies (VOLATILE
   baselines at the writer's current lastSN; TRANSIENT_LOCAL still requests the retained history)."
  (multiple-value-bind (rid wid first last count finalp livep)
      (dds.rtps.message:parse-heartbeat-body c flags)
    (declare (ignore rid count finalp livep))
    (when (and (disc-node-user-reader node) (%user-writer-entityid-p wid))
      (let ((wguid (%source-guid src-prefix wid)))
        ;; ADR 0043 RESIDUAL -> now FAIL-SAFE, not merely documented (ADR 0059). The match gate below admits a
        ;; MATCHED writer's HEARTBEAT; the reader-side durability baseline is armed just AFTER %record-match
        ;; (%fire-match -> %reader-durability-init -> init-writer-proxy-durability, which CREATES the WriterProxy).
        ;; Between those two, a HEARTBEAT would lazily create a proxy with skip-history NIL and NACK the writer's
        ;; whole pre-match range — a VOLATILE reader silently pulling a retaining writer's history (a DURABILITY
        ;; violation). That window is unreachable today ONLY because SEDP and user HEARTBEATs both ride the ONE
        ;; unicast rx thread (discovery/HEARTBEAT/ACKNACK never leave UDP), so it cannot be an accident of a future
        ;; WP that adds user-data multicast / splits metatraffic: require the baseline to be ARMED (the proxy to
        ;; EXIST) as well as matched. Unarmed-but-matched -> DROP + count (disc-node-hb-unarmed-drops) and the
        ;; writer's next periodic HEARTBEAT re-arrives post-arm — the same recovery the match gate already relies
        ;; on. Byte-identical today (the condition never fires); a future reopening is loud, never silent.
        (when (and (%guid-matched-p node wguid)   ; match gate: process/answer only a MATCHED writer's HEARTBEAT (§8.4.10.1)
                   (or (not (disc-node-durability-gate-active node))   ; a bare dds.disc node never arms a baseline by design -> the guard does not apply (byte-identical)
                       (dds.rtps.reliable:writer-proxy-armed-p (disc-node-user-reader node) wguid)
                       (progn (incf (disc-node-hb-unarmed-drops node)) nil)))
          ;; WP-N-ENDPOINT-S2/2C1 (ADR 0048): apply the HEARTBEAT to + compute the ACKNACK from the CANONICAL reader
          ;; matched to this writer, then EMIT the ACKNACK stamped with EACH matched local reader's EntityId (a
          ;; remote ReaderProxy is keyed by the reader GUID it matched — the ACKNACK must carry THAT reader's id,
          ;; not the primary's). N=1/pre-match -> the primary under disc-node-user-reader-id, byte-identical. WP-2C1:
          ;; the route now holds N reader-ids (two same-topic readers), so the dolist FANS OUT one ACKNACK per
          ;; reader-id (each remote ReaderProxy acked under its own id); the single canonical reader is the truth.
          (let ((routes (%reader-routes-for node wguid)))
            (when routes
              (let ((reader (cdr (first routes))))
                (dds.rtps.reliable:reader-on-heartbeat reader wguid first last)
                ;; REUSE-BITMAP t: the returned bitmap is the proxy's reused scratch, serialized synchronously
                ;; in the dolist below on this receiver thread (no lock release, no same-proxy recall) — zero
                ;; per-ACKNACK alloc under the single-receiver-thread-per-proxy discipline (RX zero-alloc, NFR-MEM).
                (multiple-value-bind (base numbits bitmap) (dds.rtps.reliable:reader-acknack reader wguid t)
                  (dolist (rr routes)
                    (let ((cnt (incf (disc-node-ack-count node))))
                      (dolist (pd (%match-destinations-prefixed node nil))   ; ACKNACK -> matched writers; T10 wraps a :keyed dest
                        ;; flet + dynamic-extent (ADR 0072): %send-msg-buf funcalls the builder and never stores it
                        ;; (a downward funarg), so this stack-allocates instead of consing a closure per ACKNACK send.
                        (flet ((%build-acknack (mc)
                                 ;; writerEntityId = the REMOTE writer's id (WID), so the peer routes the
                                 ;; ACKNACK to its writer (not our local convention).
                                 (dds.rtps.message:write-acknack mc (car rr) wid base numbits bitmap cnt :final t)))
                          (declare (dynamic-extent #'%build-acknack))
                          (%send-msg-buf node (disc-node-rx-tx-msg node) #'%build-acknack
                                         (cadr pd) (cddr pd) (car pd))))))))))))))
  t)

(defun* %on-user-gap (node c flags src-prefix)
    (function (disc-node dds.core.buffer:cursor (unsigned-byte 8) (simple-array (unsigned-byte 8) (12))) t)
  "Reader side: a GAP from a matched remote writer marks the SNs it declares irrelevant — the half-open range
   [gapStart, base) plus the bitmap'd SNs — as :gap in the reliable reader's writer-proxy (reader-on-gap), so a
   reliable reader stops NACKing an evicted/unrepairable SN forever and its ack watermark advances (RTPS 2.5
   §8.3.7.4 / §9.4.5.6). parse-gap-body bounds-checks the SequenceNumberSet against the body extent (numBits<=256,
   the M bitmap words fit) BEFORE this trusts it (NFR-SEC-POSTURE) — returns NIL on a short/malformed GAP, which
   this drops. The reader-proxy is keyed by the remote writer's FULL 16-octet GUID (SRC-PREFIX + the GAP's WID,
   §9.4.4 / §9.3.1.2) — the SAME key %on-user-heartbeat / %deliver-user-sample use — so two writers sharing
   EntityId 0x102 across participants keep independent received-SN state (§8.3.5.4). Gated on a matched user
   writer EntityId; mirrors %on-user-heartbeat."
  (multiple-value-bind (rid wid gap-start base numbits bitmap) (dds.rtps.message:parse-gap-body c flags)
    (when (and base (disc-node-user-reader node) (%user-writer-entityid-p wid))
      (let* ((routes (%reader-routes-for node (%source-guid src-prefix wid)))   ; WP-N-ENDPOINT-S2: the readers matched to this writer
             ;; RTPS 2.5 §8.3.7.4: readerGUID = { Receiver.destGuidPrefix, Gap.readerId }, and "the Gap
             ;; readerId can be ENTITYID_UNKNOWN, in which case the Gap applies to ALL Readers of that
             ;; writerGUID within the Participant" — so a NON-unknown readerId addresses exactly ONE reader.
             ;; We used to (declare (ignore rid)) and apply every GAP to the canonical route, so a GAP
             ;; addressed to reader A also suppressed SNs on a co-located reader B: B stopped NACKing SNs it
             ;; had never received and its ack watermark advanced past them — SILENT SAMPLE LOSS on a reader
             ;; the writer never sent the GAP to. Honour the readerId; a GAP naming a reader we do not host
             ;; is DROPPED.
             (targets (if (= rid dds.rtps.message:+entityid-unknown+)
                          routes
                          (remove-if-not (lambda (rr) (= (car rr) rid)) routes))))
        (when targets
          (let ((lost (dds.rtps.reliable:reader-on-gap (cdr (first targets)) (%source-guid src-prefix wid)
                                                       gap-start base numbits bitmap)))
            ;; WP-DCPS-API-COMPLETION S4: a GAP that declares never-received SNs permanently gone raises
            ;; SAMPLE_LOST on the matched DataReader(s) (DDS 1.4 §2.2.4.1); N=1 -> the canonical route's id.
            (when (and (plusp lost) (disc-node-on-sample-lost node))
              (dolist (rr targets) (funcall (disc-node-on-sample-lost node) (car rr) lost))))))))
  t)

(defun* %on-user-acknack (node c flags src-prefix)
    (function (disc-node dds.core.buffer:cursor (unsigned-byte 8) (simple-array (unsigned-byte 8) (12))) t)
  "Writer side: on an ACKNACK, retransmit each NACKed change PRESENT in the HistoryCache as a DATA submessage
   to the ONE reader that NACKed (uses rx-tx-msg); for each NACKed SN the HC NO LONGER HOLDS (a per-instance
   KEEP_LAST eviction or a RESOURCE_LIMITS drop left the hole, ADR 0019) send ONE GAP marking those SNs
   irrelevant (RTPS 2.5 §8.3.7.4 / §9.4.5.6) so the reliable reader advances past the unrepairable SN instead
   of NACKing it forever; then purge the HistoryCache of changes ALL matched readers have acked
   (writer-purge-acked, §8.4.1). The default unlimited KEEP_ALL writer never evicts, so writer-on-acknack
   returns an EMPTY gaps list and NO GAP is sent (a fully-acked change is purged, never GAPped). The
   reader-proxy is keyed by the REMOTE reader's FULL 16-octet GUID (SRC-PREFIX + the ACKNACK's reader EntityId
   RID, §9.4.4 / §9.3.1.2) — the SAME key %push-data uses for that reader — so two readers sharing EntityId
   0x107 across participants advance independent acked-base watermarks (§8.3.5.4). The resend AND the GAP go
   ONLY to the ACKNACKing participant's destination, resolved from SRC-PREFIX (a NACK is from exactly one
   reader, so fanning out to every matched reader is pure over-send); falls back to every matched reader only
   when the prefix is undiscovered (the discovery-less test path). WP-N-ENDPOINT-S1 (ADR 0048): the ACKNACK's
   target writerId WID selects WHICH local DataWriter repairs — the retransmit + GAP + purge run against that
   writer's OWN HistoryCache (%user-writer-for), so an ACKNACK for the 2nd writer never mis-repairs from the
   primary. WID that resolves to no local writer (a foreign/builtin id) is ignored; at N=1 WID IS the primary."
  (multiple-value-bind (rid wid base numbits bitmap count finalp)
      (dds.rtps.message:parse-acknack-body c flags)
    (declare (ignore count finalp))
    (let ((w (%user-writer-for node wid)))   ; route to the addressed local DataWriter (N=1: the primary)
      (when w
        (incf (disc-node-acks-in node))   ; a matched reader (incl. RTI) acked our writer
        (multiple-value-bind (resends gaps)
            (dds.rtps.reliable:writer-on-acknack w
                                                 (%source-guid src-prefix rid) base numbits bitmap t)   ; acquire send-refs on resends, atomic with the read (release-safety)
          (unwind-protect
               (let* ((*emit-writer* w)   ; WP-N-ENDPOINT-S1: retransmit + GAP + frag-HB under the ADDRESSED writer's own GUID/HC
                      (dest (%prefix-user-destination node src-prefix))
                      ;; (DEST-PREFIX . (host . port)) (T10): the NACKing reader's prefix (src-prefix), or the prefixed fan-out
                      (peers (if dest (list (cons src-prefix dest)) (%match-destinations-prefixed node t))))
                 (dolist (pd peers)   ; retransmit present DATA(_FRAG)/dispose, then GAP the missing -> the NACKing reader
                   (let ((peer (cdr pd)))
                     (%send-changes-packed node (disc-node-rx-tx-msg node) resends (car peer) (cdr peer) nil nil nil nil 0 (car pd))
                     (when gaps (%send-user-gap node (disc-node-rx-tx-msg node) rid gaps (car peer) (cdr peer) (car pd))))))
            (dds.rtps.reliable:writer-release-change-refs w resends))   ; release after the retransmit datagrams are emitted (copied)
          ;; the ACKNACK advanced this reader's acked-base -> purge HistoryCache changes ALL matched readers
          ;; have now acknowledged (RTPS 2.5 §8.4.1), bounding the KEEP_ALL writer history. NACKed (resent)
          ;; changes are not fully acked, so they are never purged. A TRANSIENT_LOCAL writer (DDS 1.4
          ;; §2.2.3.4) RETAINS its acked history for late-joiners — the durability arg makes the purge a
          ;; no-op for it (HISTORY-bounded, not ACK-bounded); a VOLATILE writer purges as before.
          (dds.rtps.reliable:writer-purge-acked w (%matched-reader-keys node)
                                                (%local-writer-durability
                                                 node (dds.rtps.reliable:rtps-writer-entityid w)))))))
  t)

(defun* %on-user-data-frag (node c flags body-len buf src-prefix)
    (function (disc-node dds.core.buffer:cursor (unsigned-byte 8) (integer 0) dds.core.buffer:octet-buffer
              (simple-array (unsigned-byte 8) (12))) t)
  "Reader side: accept a DATA_FRAG, reassemble; on the final fragment deliver the complete sample."
  (multiple-value-bind (rdr wtr sn ssize fstart frags fsize poff plen keyp)
      (dds.rtps.message:parse-data-frag-body c flags body-len)
    (declare (ignore rdr keyp))
    (when (and (disc-node-user-reader node) (%user-writer-entityid-p wtr))
      (let* ((region (make-array plen :element-type '(unsigned-byte 8)))
             (wguid (%source-guid src-prefix wtr))
             (routes (%reader-routes-for node wguid)))   ; WP-N-ENDPOINT-S2: reassemble on the CANONICAL reader matched to this writer (same reader %on-user-heartbeat-frag NACK_FRAGs from)
        (when routes
          (replace region (dds.core.buffer:octet-buffer-vec buf) :start2 poff :end2 (+ poff plen))
          (let ((done (dds.rtps.reliable:reader-on-data-frag
                       (cdr (first routes)) wguid sn fstart frags fsize ssize region)))
            ;; DATA_FRAG: no relay forwarding -> wire GUID/SN are the logical origin (no PID_ORIGINAL_WRITER_INFO on frags)
            (when done (%deliver-user-sample node wtr sn done src-prefix wguid sn)))))))
  t)

(defun* %on-user-heartbeat-frag (node c flags src-prefix)
    (function (disc-node dds.core.buffer:cursor (unsigned-byte 8) (simple-array (unsigned-byte 8) (12))) t)
  "Reader side: on a HEARTBEAT_FRAG, NACK_FRAG the still-missing fragments to matched writers. The
   reassembly proxy is keyed by the remote writer's FULL 16-octet GUID (SRC-PREFIX + WID, §9.4.4 /
   §9.3.1.2) so two writers sharing EntityId 0x102 keep independent reassembly state (§8.3.5.4).
   WP-ACKNACK-MATCH-GATE (RTPS 2.5 §8.4.10.1): gated on a MATCHED writer, mirroring %on-user-heartbeat — a
   pre-match HEARTBEAT_FRAG must not NACK_FRAG pre-join history fragments before the match arms."
  (multiple-value-bind (rid wid sn lastfrag count) (dds.rtps.message:parse-heartbeat-frag-body c flags)
    (declare (ignore rid lastfrag count))
    (when (and (disc-node-user-reader node) (%user-writer-entityid-p wid)
               (%guid-matched-p node (%source-guid src-prefix wid)))
      ;; WP-N-ENDPOINT-S2/2C1 (ADR 0048): NACK_FRAG from the CANONICAL reader (its reassembly proxy, same one
      ;; %on-user-data-frag fed), stamped with EACH matched local reader's EntityId (correct wire reader id). The
      ;; dolist FANS OUT one NACK_FRAG per reader-id when the route holds N same-topic readers (route-add-all, 2C1).
      (let ((routes (%reader-routes-for node (%source-guid src-prefix wid))))
        (when routes
          (multiple-value-bind (base numbits bitmap)
              (dds.rtps.reliable:reader-frag-acknack (cdr (first routes)) (%source-guid src-prefix wid) sn)
            (when base
              (dolist (rr routes)
                (let ((cnt (incf (disc-node-ack-count node))))
                  (dolist (pd (%match-destinations-prefixed node nil))   ; T10: wrap the NACK_FRAG to a :keyed writer
                    (%send-msg-buf node (disc-node-rx-tx-msg node)
                                   (lambda (mc) (dds.rtps.message:write-nack-frag
                                                 mc (car rr) wid sn base numbits bitmap cnt))
                                   (cadr pd) (cddr pd) (car pd)))))))))))
  t)

(defun* %on-user-nack-frag (node c flags)
    (function (disc-node dds.core.buffer:cursor (unsigned-byte 8)) t)
  "Writer side: on a NACK_FRAG, resend exactly the named fragments as DATA_FRAGs to matched readers. WP-N-ENDPOINT-S1
   (ADR 0048): the NACK_FRAG's target writerId WID selects WHICH local DataWriter repairs (%user-writer-for) and is
   echoed as the resent DATA_FRAG's writer EntityId, so a fragment NACK for the 2nd writer repairs from its OWN
   HistoryCache under its OWN GUID; an unmatched WID is ignored. At N=1 WID IS the primary (byte-identical)."
  (multiple-value-bind (rid wid sn base numbits bitmap count) (dds.rtps.message:parse-nack-frag-body c flags)
    (declare (ignore rid count))
    (let ((w (%user-writer-for node wid)))   ; route to the addressed local DataWriter (N=1: the primary)
      (when w
        (let ((ch (dds.rtps.reliable:writer-acquire-sample w sn)))   ; acquire send-ref atomic with the lookup (release-safety)
          (when ch
            (unwind-protect
                 (let ((descs (dds.rtps.reliable:writer-on-nack-frag w sn base numbits bitmap))
                       (pl (%ensure-change-payload node ch)))   ; ADR 0044: resolve a pinned slot on demand; else the retained payload (read off the ref-held change)
                   (when (and descs pl)
                     (let ((size (dds.rtps.history:cache-change-payload-len ch)))   ; TRUE length, not the oversized pooled vec (T5a)
                       (dolist (pd (%match-destinations-prefixed node t))   ; T10: wrap the DATA_FRAG retransmit to a :keyed reader
                         (dolist (desc descs)
                           (destructuring-bind (fstart fcount off len) desc
                             (%send-msg-buf node (disc-node-rx-tx-msg node)
                                            (lambda (mc) (dds.rtps.message:write-data-frag
                                                          mc dds.rtps.message:+entityid-unknown+ wid sn size
                                                          fstart fcount dds.rtps.reliable:*fragment-size* pl off len))
                                            (cadr pd) (cddr pd) (car pd))))))))
              (dds.rtps.reliable:writer-release-change-ref w ch)))))))   ; release after the DATA_FRAG retransmits are emitted (copied)
  t)

(defparameter *plain-payload-max-bytes* 16384
  "WP-PERF (NFR-MEM / NFR-PERF-8): the maximum SerializedPayload octet length the ZERO-ALLOC plain TX path
   (publish-sample-into) sizes its arena-pooled buffers for. A sample whose serialized form exceeds it does not
   fail — it DEGRADES to the allocating path (byte-identical wire), so raising this knob is a PERFORMANCE
   decision, not a correctness one. Sized to match *secured-payload-max-bytes* so a writer's one pool serves the
   plain and the secured shape alike (the pool's element size, (+ 44 *secured-payload-max-bytes* 3), already
   bounds any plain payload of this length). Read when a writer's pool is carved, i.e. at its first publish.")

(defparameter *secured-payload-max-bytes* 16384
  "WP-DDS-SECURITY-ZEROALLOC-AEAD T5a: the maximum PLAINTEXT octet length the data_protection encode pool sizes
   each buffer for; the pool's fixed element size is (+ 44 *secured-payload-max-bytes* 3) — the SecuredPayload
   codec's exact upper bound (transform.lisp encode-serialized-payload-into: 44-byte header/tag + N + ≤3 pad).
   A secured publish of a LARGER plaintext is rejected with RETCODE_TIMEOUT (RESOURCE_LIMITS), NEVER a GC-heap
   fallback (NFR-MEM). Sized to cover the secured large/fragmented payloads exercised by the suite (≤2000 B) with
   headroom; raise it (before enable-publisher) for a writer with larger secured samples.")

(defparameter *secured-pool-capacity* 64
  "WP-DDS-SECURITY-ZEROALLOC-AEAD T5a: the number of buffers the data_protection encode pool is provisioned with
   when the writer's RESOURCE_LIMITS max_samples is unbounded (KEEP_ALL unlimited / KEEP_LAST) — the
   in-flight working-set budget. A bounded writer instead uses (max_samples + *secured-pool-headroom*). Pool
   exhaustion routes to RETCODE_TIMEOUT (RESOURCE_LIMITS), never a GC fallback. NOTE: a secured KEEP_ALL writer
   with no max_samples is thereby effectively capped at this capacity + *secured-pool-headroom* un-acked samples
   in flight (the pool, not the cache, is the binding bound) — exhaustion yields :timeout and self-corrects once
   the ACKNACK purge frees buffers; raise *secured-pool-capacity* for a deeper secured backlog.")

(defparameter *secured-pool-headroom* 16
  "WP-DDS-SECURITY-ZEROALLOC-AEAD T5a: extra encode-pool buffers ON TOP of the cache bound, covering the buffers
   transiently held by in-flight/deferred sends — a change EVICTED while a captured push/retransmit thunk still
   references it keeps its buffer until the last send-ref drops (hc-try-release-pooled), so it is momentarily
   out of the pool while a successor occupies the cache slot (the operating contract §4 release-safety).")

(defun* %secured-pool-capacity (kind depth max-samples)
    (function ((member :keep-last :keep-all) (integer 1) (or null (integer 0))) (integer 1))
  "WP-DDS-SECURITY-ZEROALLOC-AEAD T5a: the encode-pool buffer count for a writer with HISTORY (KIND/DEPTH) and
   RESOURCE_LIMITS MAX-SAMPLES. A bounded cache (finite max_samples) sizes to that bound; an unbounded KEEP_LAST
   uses max(depth, *secured-pool-capacity*) (per-instance depth × instances is not known at enable time, so the
   default working-set budget bounds it); an unbounded KEEP_ALL uses *secured-pool-capacity*. *secured-pool-headroom*
   is added in all cases for the in-flight/deferred-send buffers held across eviction (the deferred pool-release)."
  (+ (cond (max-samples max-samples)
           ((eq kind :keep-last) (max depth *secured-pool-capacity*))
           (t *secured-pool-capacity*))
     *secured-pool-headroom*))

(defun* %writer-secured-p (node writer)
    (function (disc-node t) t)
  "T iff WRITER publishes a data_protection-transformed payload (its OWN per-endpoint kind is non-NONE and a
   crypto-transform is installed) — i.e. publish-sample will re-encode its payload into a pool buffer of its
   own. Such a writer is NOT eligible for the zero-alloc pre-serialized path (publish-sample-into), which
   would otherwise hand it a buffer it immediately discards."
  (let ((wdk (nth-value 0 (%user-endpoint-kinds node (dds.rtps.reliable:rtps-writer-entityid writer)))))
    (and (not (eq wdk :none)) (disc-node-crypto-transform node) t)))

(defun* publish-sample-into (node serialize-fn &optional (key-hash nil) (writer-id nil) (source-timestamp nil))
    (function (disc-node function &optional (or null (array (unsigned-byte 8) (*)))
                                            (or null (unsigned-byte 32)) (or null integer))
              (or (eql t) (eql :timeout)))
  "WP-PERF (NFR-MEM / NFR-PERF-8) — the ZERO-ALLOC publish path. SERIALIZE-FN is (lambda (octet-buffer) ->
   LENGTH): it writes the SerializedPayload straight into a buffer drawn from the writer's arena-backed
   payload pool and returns the octet length. The change then OWNS that pool buffer and the pool reclaims it
   at the eviction / send-ref-drop gate (hc-try-release-pooled) — exactly as a secured payload does (T5a).
   Steady state therefore allocates ZERO bytes per sample on the TX path.

   This replaces the previous DCPS TX shape, which per sample did: make-octet-buffer (a foreign/static alloc
   + zero) -> serialize -> make-array (a fresh GC-HEAP vector) -> memcpy -> free-static. Two allocations, a
   zeroing, a copy and a free, on every write — the inverse of the operating contract's static-arena rule,
   and (via GC) the source of the p99.99 tail.

   FAIL-SAFE, never a silent regression: if no pool can be carved OR the pool is EXHAUSTED, this falls back
   to the allocating path (serialize into a fresh buffer, then publish-sample) — byte-identical on the wire.
   Pool exhaustion is therefore NOT a data-loss path; it is a performance degradation, and the arena's
   RESOURCE_LIMITS backpressure still governs the cache itself.
   A SECURED writer is routed to the allocating path too: publish-sample re-encodes its payload into a pool
   buffer of its own, so pre-serializing into one would just be discarded."
  (let ((writer (%resolve-user-writer node writer-id)))
    (labels ((allocating ()   ; the byte-identical fallback: serialize into a fresh buffer, publish as before
               (let* ((cap (+ 4 *plain-payload-max-bytes* 8))
                      (buf (dds.core.buffer:make-octet-buffer cap)))
                 (unwind-protect
                      (let* ((len (funcall serialize-fn buf))
                             (out (make-array len :element-type '(unsigned-byte 8))))
                        (replace out (dds.core.buffer:octet-buffer-vec buf) :end1 len)
                        (publish-sample node out key-hash nil 0 nil writer-id source-timestamp))
                   (dds.pal:free-static (dds.core.buffer:octet-buffer-vec buf))))))
      (if (%writer-secured-p node writer)
          (allocating)
          (progn
            (unless (dds.rtps.history:history-cache-payload-pool (dds.rtps.reliable:rtps-writer-hc writer))
              (%ensure-secured-payload-pool node writer))   ; the SAME carve serves the plain path (DRY): its element size already bounds any plain payload
            (let ((buf (and (dds.rtps.history:history-cache-payload-pool
                             (dds.rtps.reliable:rtps-writer-hc writer))
                            (dds.rtps.reliable:writer-acquire-payload-buffer writer))))
              (if (null buf)
                  (allocating)                       ; no pool / exhausted -> degrade to allocating, never drop
                  (let ((committed nil))
                    (unwind-protect
                         (handler-case
                             (let ((len (funcall serialize-fn buf)))
                               (setf committed t)
                               (publish-sample node (dds.core.buffer:octet-buffer-vec buf)
                                               key-hash nil 0 nil writer-id source-timestamp buf len))
                           (dds.core.buffer:buffer-overflow ()   ; payload > element-bytes: degrade, never a wire change
                             (setf committed t)
                             (dds.rtps.reliable:writer-release-payload-buffer writer buf)
                             (allocating)))
                      (unless committed   ; non-local exit before the change took ownership: return the slot
                        (dds.rtps.reliable:writer-release-payload-buffer writer buf)))))))))))

(defun* %ensure-secured-payload-pool (node writer)
    (function (disc-node dds.rtps.reliable:rtps-writer) t)
  "Provision NODE's secured-payload encode pool onto WRITER's HistoryCache if absent — the SINGLE carve point
   for BOTH enable-publisher (static-key config: crypto on AT enable) AND the LIVE DDS-Security handshake, where
   the keys (and thus the need to pool) are installed AFTER enable-publisher by the crypto-manager, so the pool
   is carved LAZILY on the first secured publish (WP-DDS-SECURITY-ZEROALLOC-AEAD T5a). Idempotent and run under
   the writer lock (writer-ensure-payload-pool), so a concurrent first publish carves exactly once; the carve is
   off the steady state (first publish only), so steady publish stays 0 B/sample. Sizes element-bytes from
   *secured-payload-max-bytes* (the encode-serialized-payload-into exact bound) and the pool capacity from the
   HC's own HISTORY/RESOURCE_LIMITS (%secured-pool-capacity). On arena-allocation failure (no room) leaves the
   pool NIL and the node arena unset — the publish then takes the allocating encode (byte-identical + correct),
   never an error and never a GC-silent zero-claim. The arena is stored on NODE only after the pool carve
   succeeds, so stop-node's teardown reaches exactly the live arena. Returns the pool, or NIL when none carved."
  (dds.rtps.reliable:writer-ensure-payload-pool
   writer
   (lambda (hc)
     (let ((element-bytes (+ 44 *secured-payload-max-bytes* 3))   ; encode-serialized-payload-into exact bound (transform.lisp)
           (capacity (%secured-pool-capacity (dds.rtps.history:hc-kind hc)
                                             (dds.rtps.history:hc-depth hc)
                                             (dds.rtps.history:hc-max-samples hc))))
       (handler-case
           (let* ((arena (dds.core.arena:init-arena :bytes (* element-bytes (1+ capacity))))   ; +1 slot slack
                  (pool (dds.core.arena:make-buffer-pool arena element-bytes capacity)))
             ;; ADR 0064: :arena-exhausted is a STATUS now. Test it — an unchecked NIL pool would still PUSH
             ;; the arena onto the per-writer list ("only after the carve succeeds"), leaking it.
             (when (null pool) (dds.core.arena:teardown-arena arena) (return-from %ensure-secured-payload-pool nil))
             (dds.pal:with-lock ((disc-node-payload-arena-lock node))   ; WP-N-ENDPOINT-S3: serialize the shared-list push (the carve runs under the per-WRITER lock; a dedicated leaf lock stops two writers' first-publishes lost-updating the list)
               (push arena (disc-node-payload-arena node)))   ; add to the per-writer arena LIST (never overwrite a prior writer's), only after the carve succeeds (teardown reachability)
             pool)
         (error () nil))))))   ; arena-exhausted / static-alloc failure: leave the pool NIL -> allocating encode fallback

(defun* %ensure-secured-decode-pool (node)
    (function (disc-node) t)
  "Provision NODE's secured DECODE plaintext pool if absent and return it (or NIL on arena-allocation failure —
   the caller then falls back to the allocating decode, byte-identical). The SINGLE carve point (DRY) for BOTH
   the EAGER path (set-secured-loan-capable when crypto is already on) AND the LAZY path (the first secured receive
   when keys arrive after enable via the live DDS-Security handshake, WP-DDS-SECURITY-ZEROALLOC-AEAD T5b).
   Idempotent + double-checked under decode-pool-lock so the carve happens exactly once OFF the steady state (first
   receive only -> steady receive stays 0 B/sample for the plaintext). element-bytes = *secured-payload-max-bytes*
   (the max recovered plaintext = decode-serialized-payload-into's ct_len output bound); capacity =
   *secured-pool-capacity* + *secured-pool-headroom* (the in-flight working set + outstanding-loan headroom). PER-NODE
   ownership: the disc-node owns the pool and its single user reader is the sole consumer. stop-node returns every
   outstanding loan then tears the arena down. On arena-exhausted leaves the pool NIL (allocating-decode fallback),
   never an error, never a GC-silent zero-claim (NFR-MEM). WP-DDS-SECURITY-ZEROALLOC-AEAD T5d: alongside the buffer
   pool this carves (once, off steady state) the CAPACITY-sized loan-WRAPPER structures so the accepted loan
   conses 0 B/sample — the handle freelist (CAPACITY preallocated secured-loan-handle structs, recycled on
   return), the registry vector (CAPACITY slots, swap-remove), and the node-take-loaned scratch vector (CAPACITY
   slots, reused per take). These are plain Lisp heap objects (NOT arena/SAP — like type-support's sample-pool),
   allocated once at carve; only the off-heap plaintext BUFFERS come from the static arena."
  (or (disc-node-decode-pool node)                       ; fast unlocked check (steady state: no lock)
      (dds.pal:with-lock ((disc-node-decode-pool-lock node))
        (or (disc-node-decode-pool node)                 ; re-check under the lock (double-checked carve)
            (let ((element-bytes *secured-payload-max-bytes*)
                  (capacity (+ *secured-pool-capacity* *secured-pool-headroom*)))
              (handler-case
                  (let* ((arena (dds.core.arena:init-arena :bytes (* element-bytes (1+ capacity))))   ; +1 slot slack
                         (pool (dds.core.arena:make-buffer-pool arena element-bytes capacity))
                         (handles (make-array capacity)))
                    ;; ADR 0064: :arena-exhausted is a STATUS now — test it before installing anything.
                    (when (null pool) (dds.core.arena:teardown-arena arena) (return-from %ensure-secured-decode-pool nil))
                    (dotimes (i capacity) (setf (svref handles i) (%make-secured-loan-handle)))   ; preallocate the handle freelist (recycled, zero per-sample cons)
                    (setf (disc-node-decode-handle-vec node) handles
                          (disc-node-decode-handle-top node) capacity
                          (disc-node-secured-loan-vec node) (make-array capacity :initial-element nil)   ; registry: fixed vector + fill pointer (no per-loan cons)
                          (disc-node-secured-loan-count node) 0
                          (disc-node-secured-take-vec node) (make-array capacity :initial-element nil)   ; reused take result (no per-take cons)
                          (disc-node-decode-arena node) arena   ; only after the carve succeeds (teardown reachability)
                          (disc-node-decode-pool node) pool)
                    pool)
                ;; WP-SECURED-STORE-GROWTH: catch storage-condition too (a real off-heap/static-alloc OOM signals
                ;; storage-condition, NOT error, on SBCL/Clasp) so carve-fail is graceful as documented — leave NIL ->
                ;; bounded allocating-decode fallback, never propagate (operating contract §4 NFR-MEM).
                ((or error storage-condition) () nil)))))))   ; arena-exhausted / static-alloc failure: leave NIL -> allocating-decode fallback

(defparameter *rx-store-pool-capacity* 64
  "ADR 0078 (NFR-MEM): the number of buffers in a disc-node's RX store-copy pool — the working set of
   received copy-path samples resident in the node sample store between the receiver thread storing one and
   the draining user thread consuming it. Read once per node, at the lazy carve on the first copy-path
   receive; rebinding it later has no effect on an already-carved node. Exhaustion is NOT data loss and NOT
   a RESOURCE_LIMITS reject here (unlike the secured decode pool, whose loan accounting depends on its
   bound): the store copy is copied out again at the drain, so a receive that finds the pool empty simply
   allocates its vector as before — bounded degradation, byte-identical delivery.")

(defun* %ensure-rx-store-pool (node)
    (function (disc-node) t)
  "ADR 0078: provision NODE's RX store-copy pool if absent and return it (or NIL on arena-allocation
   failure — the caller then allocates the copy exactly as before, byte-identical). Carved LAZILY on the
   first copy-path receive and double-checked under RX-STORE-POOL-LOCK, so the carve happens exactly once
   and off the steady state (the steady receive then stores 0 B/sample).

   element-bytes is (+ 4 *plain-payload-max-bytes* 8) — deliberately the SAME bound publish-sample-into's
   allocating fallback uses, so ONE knob governs the pooled payload extent in both directions; a received
   SerializedPayload larger than that keeps allocating (the documented, bounded degradation). capacity is
   *rx-store-pool-capacity*.

   On arena exhaustion this leaves the pool NIL — never an error, and never a GC-silent claim of a zero it
   did not achieve (operating contract §4 / NFR-MEM). storage-condition is caught alongside error because a
   static/off-heap allocation failure signals storage-condition, not error, on SBCL and Clasp."
  (or (disc-node-rx-store-pool node)                      ; fast unlocked check (steady state: no lock)
      (dds.pal:with-lock ((disc-node-rx-store-pool-lock node))
        (or (disc-node-rx-store-pool node)                ; re-check under the lock (double-checked carve)
            (let ((element-bytes (+ 4 *plain-payload-max-bytes* 8))
                  (capacity *rx-store-pool-capacity*))
              (handler-case
                  (let* ((arena (dds.core.arena:init-arena :bytes (* element-bytes (1+ capacity))))   ; +1 slot slack
                         (pool (dds.core.arena:make-buffer-pool arena element-bytes capacity)))
                    ;; ADR 0064: :arena-exhausted is a STATUS — test it before installing anything, or the
                    ;; arena is pushed onto the node and orphaned ("store the arena only after the carve succeeds").
                    (when (null pool) (dds.core.arena:teardown-arena arena) (return-from %ensure-rx-store-pool nil))
                    (setf (disc-node-rx-store-element-bytes node) element-bytes
                          (disc-node-rx-store-arena node) arena   ; only after the carve succeeds (teardown reachability)
                          (disc-node-rx-store-pool node) pool)
                    pool)
                ((or error storage-condition) () nil)))))))   ; arena-exhausted / static-alloc failure: leave NIL -> allocating copy

(defun* %rx-store-acquire (node plen)
    (function (disc-node (integer 0)) (or null dds.core.buffer:octet-buffer))
  "ADR 0078: draw a buffer for the receiver thread's PLEN-octet store copy, with its CAPACITY set to
   exactly PLEN. That capacity is the payload's extent everywhere downstream — %deserialize-payload
   bounds-checks against it (buffer.lisp) — so a pooled sample is decoded under byte-identical bounds to
   the exact-length vector it replaces, and a truncated or hostile payload can never over-read into the
   previous sample's bytes (NFR-SEC-POSTURE).

   NIL when there is no pool (not yet carved / arena exhausted), when the pool is exhausted, or when PLEN
   exceeds the carved element size; the caller then allocates as before. Runs on the receiver thread with
   NO node lock held; the pool lock is a leaf taken only here and in %rx-store-release."
  (let ((pool (or (disc-node-rx-store-pool node) (%ensure-rx-store-pool node))))
    (when (and pool (<= plen (disc-node-rx-store-element-bytes node)))
      (let ((ob (dds.pal:with-lock ((disc-node-rx-store-pool-lock node))
                  (dds.core.arena:pool-acquire pool))))
        (when ob
          (setf (dds.core.buffer:octet-buffer-capacity ob) plen)
          ob)))))

(defun* %rx-store-release (node ob)
    (function (disc-node dds.core.buffer:octet-buffer) (values))
  "ADR 0078: return a pooled store-copy buffer OB to NODE's RX store pool. Called from the SINGLE store-drop
   choke (%purge-secured-sample) and from the dedup-reject arm of %deliver-user-sample (a sample that was
   never stored). Zero-alloc.

   Ownership is the store's single-owner discipline: an entry is dropped exactly once, by exactly one owner,
   under the node lock. The in-use guard is belt-and-braces for that invariant — a release when the pool has
   nothing checked out could only be a double release, and degrading it to a LEAKED SLOT (bounded; the pool
   then falls back to allocating) is strictly better than corrupting the pool's free list.
   Lock order: the pool lock nests INSIDE disc-node-lock (the purge choke calls this holding it)."
  (let ((pool (disc-node-rx-store-pool node)))
    (when pool
      (dds.pal:with-lock ((disc-node-rx-store-pool-lock node))
        (when (plusp (dds.core.arena:pool-in-use pool))
          (dds.core.arena:pool-release pool ob)))))
  (values))

(defun* set-secured-loan-capable (node capable)
    (function (disc-node t) t)
  "WP-DDS-SECURITY-ZEROALLOC-AEAD T5b: mark NODE's secured (data_protection) RECEIVE path LOAN-CAPABLE (CAPABLE
   non-NIL) or not. When capable AND a crypto-transform is present, the receiver thread decodes each SecuredPayload
   into a DECODE-POOL buffer (decode-serialized-payload-into — zero per-sample plaintext alloc) and stores a
   SECURED-LOAN-HANDLE instead of a bare plaintext vector; the APP then reads the plaintext IN PLACE via
   node-take-loaned + secured-loan-bytes / secured-loan-handle-len and MUST node-return-loan each loan (the
   app-facing read-contract change — a leaked loan pins a pool slot and the pool eventually exhausts:
   SAMPLE_REJECTED / writer backpressure, graceful, never GC). Carves the decode pool EAGERLY when crypto is
   already on (so the steady receive never carves under load); otherwise the first secured receive carves it
   lazily (the live-handshake config). Default NIL leaves the shipped allocating-decode -> bare-vector path
   byte-unchanged — a plain (non-secured) reader is entirely unaffected."
  (setf (disc-node-secured-loan-capable node) (and capable t))
  (when (and capable (disc-node-crypto-transform node))
    (%ensure-secured-decode-pool node))
  (disc-node-secured-loan-capable node))

(defun* enable-publisher (node &key max-samples (max-blocking-ns nil)
                                    (history-kind :keep-last) (history-depth 1))
    (function (disc-node &key (:max-samples (or null (integer 1))) (:max-blocking-ns (or null (integer 0)))
                              (:history-kind (member :keep-last :keep-all)) (:history-depth (integer 1)))
              disc-node)
  "Give NODE a reliable user writer honoring its HISTORY QoS and install the writer-side data-plane hooks
   (retransmit on ACKNACK; resend named fragments on NACK_FRAG). Call after add-local-writer. HISTORY-KIND /
   HISTORY-DEPTH (DDS 1.4 §2.2.3.18; defaulting to the spec generic default KEEP_LAST depth 1) size the writer
   HistoryCache: KEEP_LAST retains the last HISTORY-DEPTH changes PER INSTANCE for late-joiner/retransmit;
   KEEP_ALL ignores depth and retains-until-acked, bounded only by RESOURCE_LIMITS (the prior behavior — pass
   :keep-all to preserve it byte-identically). MAX-SAMPLES (RESOURCE_LIMITS max_samples; NIL = unlimited)
   bounds the HistoryCache; MAX-BLOCKING-NS (RELIABILITY.max_blocking_time in ns; NIL = never block) makes
   publish-sample / dispose / unregister BLOCK up to that long on a FULL bounded cache, then return
   RETCODE_TIMEOUT — DDS-standard block-up-to-max_blocking_time backpressure (WP-ASYNC-FLOW, FR-PF-2/FR-QOS,
   ADR 0016 §Backpressure; pairs with a flow-controller, which paces the drain so a bounded cache + bounded
   block keeps the backlog bounded). With MAX-SAMPLES NIL the cache never fills, so MAX-BLOCKING-NS has no
   effect (the bound is the trigger). NOTE (ADR 0019; N-user-endpoint S0 registry landed, ADR 0048): the engine
   writer is now held in the node's entity-id-keyed user-writer registry (disc-node-user-writer returns the
   PRIMARY = first-registered). At N=1 the PRIMARY is shared by all of a publisher's DataWriters, so the HC honors
   the HISTORY QoS of the DataWriter that (re)enabled the publisher — the pre-existing single-user-endpoint limit,
   now foundation-refactored; N-local send fan-out is Slice S1, deliver routing S2. When NODE has a crypto-transform
   (data_protection ON), a per-node static arena + a fixed secured-payload pool are carved onto the writer's
   HistoryCache so a secured publish reuses a buffer (zero per-sample payload alloc, WP-DDS-SECURITY-ZEROALLOC-AEAD
   T5a): the pool holds %secured-pool-capacity buffers of (44 + *secured-payload-max-bytes* + 3) octets each; a
   larger secured plaintext OR pool exhaustion is rejected with RETCODE_TIMEOUT (RESOURCE_LIMITS), never a GC
   fallback. Security OFF leaves no pool — the publish path is byte-identical. stop-node tears the arena down."
  ;; WP-N-ENDPOINT-S0-REGISTRY (ADR 0048): register the engine writer under the node's user-writer EntityId (first =
  ;; primary; re-enable with the same id replaces — byte-identical to the pre-S0 slot clobber). N-local send = S1.
  (%register-user-writer node (disc-node-user-writer-id node)
                         (dds.rtps.reliable:make-rtps-writer
                          :hc (dds.rtps.history:make-history-cache history-kind history-depth max-samples nil)
                          :entityid (disc-node-user-writer-id node)   ; WP-N-ENDPOINT-S1: the writer stamps its OWN EntityId on the wire
                          :max-blocking-ns max-blocking-ns))
  ;; WP-ACKED-SLOT-PINNING (ADR 0044): wire the pin RELEASE-FN onto the writer HistoryCache when the node has a ZC
  ;; pool. The change-removal choke (%hc-remove-change, under the writer lock) funcalls it to %zc-release a pinned
  ;; change's TX slot hold + decrement the live-pin budget — the layering-clean release (history must not depend on
  ;; dds.xport.zerocopy). No pool -> no release-fn -> node-loan-write-pin-capable-p is NIL -> no pinning (ADR 0042).
  (when (disc-node-zc-pool-sap node)
    (setf (dds.rtps.history:history-cache-zc-release-fn
           (dds.rtps.reliable:rtps-writer-hc (disc-node-user-writer node)))
          (lambda (slot generation)
            (dds.xport.zerocopy::%zc-release (disc-node-zc-pool-sap node) slot generation)
            (dds.pal:atomic-incf (disc-node-zc-pin-count node) -1))))
  ;; WP-DDS-SECURITY-ZEROALLOC-AEAD T5a: when data_protection is ALREADY engaged at enable (the static-key
  ;; config), carve the per-node static arena + secured-payload pool onto the writer's HistoryCache now, so a
  ;; secured publish encodes into a reused buffer (zero per-sample payload alloc). The LIVE handshake config
  ;; (keys installed AFTER enable by the crypto-manager) carves the SAME pool LAZILY on the first secured publish
  ;; (publish-sample) — both go through the single %ensure-secured-payload-pool carve point (DRY). Pool ownership
  ;; is the writer's HC (reachable by the acquire path, the eviction choke %hc-remove-change, AND the ref-drop
  ;; release — all under the one writer lock). Security OFF (crypto-transform NIL) -> no arena/pool until/unless
  ;; keys arrive -> publish-sample's allocating path -> byte-identical.
  (when (disc-node-crypto-transform node)
    (%ensure-secured-payload-pool node (disc-node-user-writer node)))
  (setf (disc-node-on-acknack node) (lambda (c flags src-prefix) (%on-user-acknack node c flags src-prefix)))
  (setf (disc-node-on-nack-frag node) (lambda (c flags) (%on-user-nack-frag node c flags)))
  node)

(defun* enable-subscriber (node)
    (function (disc-node) disc-node)
  "Give NODE a reliable user reader and install the reader-side data-plane hooks (store DATA, ACKNACK on
   HEARTBEAT, mark GAP'd SNs irrelevant on GAP, reassemble DATA_FRAG, NACK_FRAG on HEARTBEAT_FRAG). Call after
   add-local-reader."
  ;; WP-N-ENDPOINT-S0-REGISTRY (ADR 0048): register the engine reader under the node's user-reader EntityId (first =
  ;; primary; re-enable with the same id replaces — byte-identical to the pre-S0 slot clobber). N-local deliver = S2.
  (%register-user-reader node (disc-node-user-reader-id node) (dds.rtps.reliable:make-rtps-reader))
  (setf (disc-node-on-data node)
        (lambda (wid sn buf poff plen src-prefix &optional og os kh)
          (%on-user-data node wid sn buf poff plen src-prefix og os kh)))
  (setf (disc-node-on-lifecycle node)
        (lambda (wid sn kind kh sf src-prefix) (%on-user-lifecycle node wid sn kind kh sf src-prefix)))
  (setf (disc-node-on-heartbeat node)
        (lambda (c flags src-prefix) (%on-user-heartbeat node c flags src-prefix)))
  (setf (disc-node-on-gap node)
        (lambda (c flags src-prefix) (%on-user-gap node c flags src-prefix)))
  (setf (disc-node-on-data-frag node)
        (lambda (c flags body-len buf src-prefix) (%on-user-data-frag node c flags body-len buf src-prefix)))
  (setf (disc-node-on-heartbeat-frag node)
        (lambda (c flags src-prefix) (%on-user-heartbeat-frag node c flags src-prefix)))
  node)

(defun* node-sample-count (node)
    (function (disc-node) (integer 0))
  "Number of distinct user samples the subscriber has received (summed over every writer's inner
   SN map)."
  (dds.pal:with-lock ((disc-node-lock node))
    (let ((n 0))
      (maphash (lambda (g inner) (declare (ignore g)) (incf n (hash-table-count inner)))
               (disc-node-samples node))
      n)))

(defun* node-sample-key-sn (key)
    (function (cons) integer)
  "Recover the raw RTPS SequenceNumber from a (GUID . SN) composite sample KEY (§8.3.5.4)."
  (cdr key))

(defun* %normalize-stored-sample (stored)
    (function (t) t)
  "ADR 0078: present a store entry as the EXACT-LENGTH payload vector node-sample has always returned. A
   pooled store-copy buffer (an octet-buffer whose CAPACITY is the payload extent, drawn from the RX store
   pool) is copied out to a fresh exact-length vector; every other entry — a plain vector, a
   secured-loan-handle, a zc-loan-marker, NIL — passes through untouched.

   WHY A COPY IS THE RIGHT ANSWER HERE. Consumers of this value keep it beyond the entry's lifetime: the
   durability relay PERSISTS it and re-publishes it. Handing them the pooled buffer would hand them a
   fixed-size buffer (wrong length written to the store) that the next receive may reuse underneath them.
   The one HOT consumer, the DCPS drain, does not come through here at all — it takes node-sample-raw and
   decodes in place — so this copy is off every hot path."
  (if (typep stored 'dds.core.buffer:octet-buffer)
      (subseq (dds.core.buffer:octet-buffer-vec stored) 0 (dds.core.buffer:octet-buffer-capacity stored))
      stored))

(defun* node-sample (node key)
    (function (disc-node cons) t)
  "The received payload for composite sample KEY (a (GUID . SN) cons, see node-sample-sns), or NIL.
   The payload is an EXACT-LENGTH octet vector: a sample copied into an ADR 0078 pooled buffer is copied out
   here, so this accessor's contract is unchanged by pooling. For the verbatim store entry (the hot DCPS
   drain, which type-dispatches and decodes in place) use node-sample-raw."
  (%normalize-stored-sample
   (dds.pal:with-lock ((disc-node-lock node))
     (let ((inner (gethash (car key) (disc-node-samples node))))
       (and inner (gethash (cdr key) inner))))))

(defun* node-sample-raw (node key)
    (function (disc-node cons) t)
  "ADR 0078: the VERBATIM store entry for composite sample KEY, or NIL — a plain octet vector, a pooled
   store-copy octet-buffer (whose CAPACITY is the exact payload extent), a secured-loan-handle, or a
   zc-loan-marker. For the ONE hot consumer, the DCPS drain, which already type-dispatches the store entry
   and decodes it in place; it must not pay node-sample's normalising copy. Every other caller wants
   node-sample."
  (dds.pal:with-lock ((disc-node-lock node))
    (let ((inner (gethash (car key) (disc-node-samples node))))
      (and inner (gethash (cdr key) inner)))))

(defun* node-sample-by-sn (node sn)
    (function (disc-node integer) t)
  "The payload of ANY received user sample whose RTPS SN equals SN, or NIL. A single-writer convenience
   (the sample store is keyed by GUID then SN, §8.3.5.4) — for tests/diagnostics that know only the SN.
   Exact-length, on the same terms as node-sample (an ADR 0078 pooled entry is copied out)."
  (%normalize-stored-sample
   (dds.pal:with-lock ((disc-node-lock node))
     (loop for inner being the hash-values of (disc-node-samples node)
           thereis (gethash sn inner)))))

(defun* node-collect-pending-samples (node pending-p out)
    (function (disc-node function (array t (*))) (array t (*)))
  "WP-PERF (NFR-MEM / NFR-PERF-8): push the composite (GUID . SN) key of every stored user sample the
   caller still considers PENDING into OUT (a caller-owned adjustable vector, REUSED across calls), and
   return OUT. PENDING-P is called as (GUID SN) — with the raw guid and sn, NOT a key — so the deciding
   walk conses NOTHING; a key cons is created ONLY for a sample that is actually pending.

   WHY. node-sample-sns builds a fresh key cons for EVERY sample in the store, and %drain called it on
   EVERY take-samples, then filtered. So the drain consed O(STORED) per call while delivering O(PENDING)
   samples — normally ONE. Measured: 3716 B/sample of GC garbage on the receive path, the single largest
   remaining allocation there. This makes the drain O(pending) in both time and allocation.

   DEADLOCK CONTRACT: PENDING-P RUNS UNDER THE NODE LOCK (unlike the old filter, which ran after
   node-sample-sns had released it), and that lock is a plain NON-RECURSIVE mutex. A predicate that calls a
   public lock-taking node accessor therefore SELF-DEADLOCKS the drain — and with it every take-samples on
   the participant. Use the -UNLOCKED accessors: node-reader-matches-writer-p-unlocked,
   node-reader-join-watermark-unlocked."
  (setf (fill-pointer out) 0)
  (dds.pal:with-lock ((disc-node-lock node))
    (maphash (lambda (guid inner)
               (loop for sn being the hash-keys of inner
                     do (when (funcall pending-p guid sn)
                          (vector-push-extend (cons guid sn) out))))
             (disc-node-samples node)))
  out)

(defun* node-collect-pending-lifecycle (node pending-p out)
    (function (disc-node function (array t (*))) (array t (*)))
  "The lifecycle-change twin of node-collect-pending-samples: push the (GUID . SN) key of every stored
   dispose/unregister change the caller still considers PENDING into the reused vector OUT. PENDING-P is
   called as (GUID SN), so the walk conses nothing for an already-drained change. Replaces
   node-lifecycle-sns + a SET-DIFFERENCE (which was O(stored x drained) with an EQUALP test, and consed
   both lists) on the %drain path. Same DEADLOCK CONTRACT as node-collect-pending-samples: PENDING-P runs
   under the non-recursive node lock — it must use the -UNLOCKED node accessors, never the public ones."
  (setf (fill-pointer out) 0)
  (dds.pal:with-lock ((disc-node-lock node))
    (maphash (lambda (guid inner)
               (loop for sn being the hash-keys of inner
                     do (when (funcall pending-p guid sn)
                          (vector-push-extend (cons guid sn) out))))
             (disc-node-lifecycle-changes node)))
  out)

(defun* node-sample-sns (node)
    (function (disc-node) list)
  "Composite (GUID . SN) cons keys of the user samples received so far (unordered). Lets a subscriber
   drain new samples per writer without assuming SNs start at 1 (Connext may not) and without aliasing
   two writers that share EntityId 0x102 (§8.3.5.4). The cons is built here on the user thread, not on
   the per-sample receive path (NFR-MEM)."
  (dds.pal:with-lock ((disc-node-lock node))
    (let ((keys '()))
      (maphash (lambda (guid inner)
                 (loop for sn being the hash-keys of inner do (push (cons guid sn) keys)))
               (disc-node-samples node))
      keys)))

(defun* node-sample-writer (node key)
    (function (disc-node cons) t)
  "The remote writer EntityId that wrote the user sample at composite KEY (a (GUID . SN) cons), or NIL.
   Lets the DCPS reader register which writer keeps an instance alive (the writers-set,
   DDS 1.4 §2.2.2.5.1.3) so a writer vanishing can transition the instance NOT_ALIVE_NO_WRITERS."
  (dds.pal:with-lock ((disc-node-lock node))
    (let ((inner (gethash (car key) (disc-node-sample-writers node))))
      (and inner (gethash (cdr key) inner)))))

(defun* node-sample-writer-guid (node key)
    (function (disc-node cons) t)
  "The FULL 16-octet source GUID (RTPS-header prefix + DATA writer EntityId, §9.3.1.2) that wrote the
   user sample at composite KEY (a (GUID . SN) cons), or NIL. The key for EXCLUSIVE ownership
   arbitration (DDS 1.4 §2.2.3.9.2): two writers on different participants share an EntityId, so the
   GUID — not the EntityId — distinguishes them when selecting the highest-strength owner of an
   instance."
  (dds.pal:with-lock ((disc-node-lock node))
    (let ((inner (gethash (car key) (disc-node-sample-writer-guids node))))
      (and inner (gethash (cdr key) inner)))))

(defun* node-sample-origin-guid (node key)
    (function (disc-node cons) (simple-array (unsigned-byte 8) (16)))
  "The LOGICAL ORIGIN GUID of the user sample at composite KEY (a (GUID . SN) cons): the original
   writer's GUID when the sample was relayed with PID_ORIGINAL_WRITER_INFO (RTPS 2.5 §8.3.5.4), else the
   wire sender GUID (= (car KEY)). Always defined. A durability relay re-stamps THIS as the OWI origin so
   a foreign persistence service's relayed copies converge with directly-collected copies (ADR 0028)."
  (dds.pal:with-lock ((disc-node-lock node))
    (let* ((inner (gethash (car key) (disc-node-sample-origins node)))
           (entry (and inner (gethash (cdr key) inner))))
      (if entry (car entry) (car key)))))

(defun* node-sample-origin-sn (node key)
    (function (disc-node cons) integer)
  "The LOGICAL ORIGIN SN of the user sample at composite KEY: the original writer's SN when relayed with
   PID_ORIGINAL_WRITER_INFO (RTPS 2.5 §8.3.5.4), else the wire SN (= (cdr KEY)). Pairs with
   node-sample-origin-guid."
  (dds.pal:with-lock ((disc-node-lock node))
    (let* ((inner (gethash (car key) (disc-node-sample-origins node)))
           (entry (and inner (gethash (cdr key) inner))))
      (if entry (cdr entry) (cdr key)))))

(defun* matched-writer-ownership (node guid)
    (function (disc-node (simple-array (unsigned-byte 8) (16))) (values t t))
  "The (values OWNERSHIP-KIND OWNERSHIP-STRENGTH) of the matched remote writer with 16-octet GUID,
   read from its endpoint-data QoS in NODE's matches table (the SEDP-carried OwnershipQosPolicy +
   OwnershipStrengthQosPolicy, RTPS 2.5 §8.5.4 / DDS 1.4 §2.2.3.9-.10). (values NIL NIL) when GUID is
   not (or no longer) matched — the writer vanished; the caller treats that as not-the-owner."
  (let ((ep (dds.pal:with-lock ((disc-node-lock node))
              (gethash guid (disc-node-matches node)))))
    (if ep
        (let ((q (dds.rtps.discovery:endpoint-data-qos ep)))
          (values (dds.qos:qos-ownership q) (dds.qos:qos-ownership-strength q)))
        (values nil nil))))

(defun* node-discovered-participants (node)
    (function (disc-node) list)
  "Snapshot of the SPDP data for every participant NODE has discovered (diagnostic)."
  (%discovered-participants node))

(defun* resolved-destination (p)
    (function (dds.rtps.discovery:spdp-data) t)
  "The (host . port) this stack would send user data to for participant P (its
   resolved routable locator), or NIL — exactly what the data plane uses. Diagnostic."
  (%usable-destination p))

(defun* node-acks-in (node)
    (function (disc-node) integer)
  "Count of ACKNACKs received for this node's user writer — i.e. how many times a
   matched reader (incl. a foreign one like RTI) acknowledged our data. >0 proves a
   remote reliable reader is actually receiving our samples. Diagnostic."
  (disc-node-acks-in node))

(defun* run-dataplane-test ()
    (function () (eql t))
  "Full stack over UDP: two participants discover (SPDP) and match (SEDP), then the
   publisher sends a user sample the subscriber receives reliably (DATA + HEARTBEAT
   -> ACKNACK). Asserts the exact payload bytes arrive within a bounded wait. The
   reliable protocol makes this robust to UDP reorder/loss (FR-RTPS-8)."
  (let* ((p1 (make-array 12 :element-type '(unsigned-byte 8)
                         :initial-contents '(1 1 1 1 1 1 1 1 1 1 1 1)))
         (p2 (make-array 12 :element-type '(unsigned-byte 8)
                         :initial-contents '(2 2 2 2 2 2 2 2 2 2 2 2)))
         (node1 (make-disc-node :guid-prefix p1 :host "127.0.0.1" :port 0))
         (node2 (make-disc-node :guid-prefix p2 :host "127.0.0.1" :port 0))
         (payload (make-array 8 :element-type '(unsigned-byte 8)
                              :initial-contents '(#xDE #xAD #xBE #xEF #x01 #x02 #x03 #x04))))
    (unwind-protect
         (progn
           (add-local-writer node1 :topic "Square" :type "ShapeType"
                                   :reliability dds.rtps.discovery:+reliability-reliable+)
           (enable-publisher node1)
           (add-local-reader node2 :topic "Square" :type "ShapeType"
                                   :reliability dds.rtps.discovery:+reliability-reliable+)
           (enable-subscriber node2)
           (setf (disc-node-peers node1) (list (cons "127.0.0.1" (disc-node-port node2))))
           (setf (disc-node-peers node2) (list (cons "127.0.0.1" (disc-node-port node1))))
           (start-node node1)
           (start-node node2)
           (announce-participant node1)
           (announce-participant node2)
           (loop repeat 100
                 until (and (plusp (disc-node-discovered-count node1))
                            (plusp (disc-node-discovered-count node2)))
                 do (sleep 0.02))
           (announce-endpoints node1)
           (announce-endpoints node2)
           (loop repeat 100
                 until (and (plusp (disc-node-matched-count node1))
                            (plusp (disc-node-matched-count node2)))
                 do (sleep 0.02))
           (assert (and (plusp (disc-node-matched-count node1))
                        (plusp (disc-node-matched-count node2)))
                   () "endpoints did not match before publish")
           (publish-sample node1 payload)
           (loop repeat 150 until (plusp (node-sample-count node2)) do (sleep 0.02))
           (assert (plusp (node-sample-count node2)) ()
                   "subscriber never received the sample over UDP")
           (assert (equalp (node-sample-by-sn node2 1) payload) ()
                   "subscriber received the wrong payload bytes")
           t)
      (stop-node node1)
      (stop-node node2))))

(defun* run-n-writer-dataplane-test ()
    (function () (eql t))
  "WP-N-ENDPOINT-S1 (ADR 0048): ONE participant with TWO non-secured user DataWriters on DIFFERENT topics, each
   matched to its own remote reader participant. Asserts: (1) the two writers get DISTINCT EntityIds/GUIDs (pre-S1
   both collided on #x0102 — the RED); (2) BOTH writers publish and each remote reader receives ITS writer's exact
   payload (send fan-out over %all-user-writers + writer-id threading, not the aliased primary); (3) independent
   reliable retransmit — writer-B's sample is dropped, and B's periodic HEARTBEAT + the ACKNACK routed by writerId
   to B (%user-writer-for) repairs it while writer-A's already-delivered sample is untouched. Also asserts: a 2nd
   SECURED writer now REGISTERS (WP-N-ENDPOINT-S3, secured multi-writer supported — per-key derivation proven by
   run-security-n-secured-writer-test); and a 2nd SAME-topic durable writer now REGISTERS (WP-N-ENDPOINT-2C2,
   fence C lifted — same-topic durable multi-writer supported; per-writer replay proven by run-dcps-durability-multiwriter-test)."
  (let* ((pp (make-array 12 :element-type '(unsigned-byte 8) :initial-contents '(1 1 1 1 1 1 1 1 1 1 1 1)))
         (pa (make-array 12 :element-type '(unsigned-byte 8) :initial-contents '(2 2 2 2 2 2 2 2 2 2 2 2)))
         (pb (make-array 12 :element-type '(unsigned-byte 8) :initial-contents '(3 3 3 3 3 3 3 3 3 3 3 3)))
         (pub  (make-disc-node :guid-prefix pp :host "127.0.0.1" :port 0))
         (suba (make-disc-node :guid-prefix pa :host "127.0.0.1" :port 0))
         (subb (make-disc-node :guid-prefix pb :host "127.0.0.1" :port 0))
         (payla (make-array 6 :element-type '(unsigned-byte 8) :initial-contents '(#xA1 #xA2 #xA3 #xA4 #xA5 #xA6)))
         (paylb (make-array 6 :element-type '(unsigned-byte 8) :initial-contents '(#xB1 #xB2 #xB3 #xB4 #xB5 #xB6))))
    (unwind-protect
         (let (ida idb)
           (let ((ea (add-local-writer pub :topic "NWA" :type "X"
                                           :reliability dds.rtps.discovery:+reliability-reliable+)))
             (enable-publisher pub)
             (setf ida (disc-node-user-writer-id pub))
             (let ((eb (add-local-writer pub :topic "NWB" :type "X"
                                             :reliability dds.rtps.discovery:+reliability-reliable+)))
               (enable-publisher pub)
               (setf idb (disc-node-user-writer-id pub))
               (assert (/= ida idb) () "the two DataWriters did not get DISTINCT EntityIds (pre-S1 clobber: both #x~8,'0X)" ida)
               (assert (not (equalp (dds.rtps.discovery:endpoint-data-guid ea)
                                    (dds.rtps.discovery:endpoint-data-guid eb)))
                       () "the two DataWriters announce IDENTICAL SEDP GUIDs (a remote peer would see 1 aliased writer)")))
           (add-local-reader suba :topic "NWA" :type "X" :reliability dds.rtps.discovery:+reliability-reliable+)
           (enable-subscriber suba)
           (add-local-reader subb :topic "NWB" :type "X" :reliability dds.rtps.discovery:+reliability-reliable+)
           (enable-subscriber subb)
           (setf (disc-node-peers pub)  (list (cons "127.0.0.1" (disc-node-port suba)) (cons "127.0.0.1" (disc-node-port subb)))
                 (disc-node-peers suba) (list (cons "127.0.0.1" (disc-node-port pub)))
                 (disc-node-peers subb) (list (cons "127.0.0.1" (disc-node-port pub))))
           (start-node pub) (start-node suba) (start-node subb)
           (announce-participant pub) (announce-participant suba) (announce-participant subb)
           (loop repeat 150
                 until (and (>= (disc-node-discovered-count pub) 2)
                            (plusp (disc-node-discovered-count suba))
                            (plusp (disc-node-discovered-count subb)))
                 do (sleep 0.02))
           (announce-endpoints pub) (announce-endpoints suba) (announce-endpoints subb)
           (loop repeat 150
                 until (and (>= (disc-node-matched-count pub) 2)
                            (plusp (disc-node-matched-count suba))
                            (plusp (disc-node-matched-count subb)))
                 do (announce-endpoints pub) (sleep 0.02))
           (assert (and (>= (disc-node-matched-count pub) 2)
                        (plusp (disc-node-matched-count suba))
                        (plusp (disc-node-matched-count subb)))
                   () "the 2 writers did not both match their remote readers")
           ;; (2) both writers publish -> each remote reader receives ITS writer's exact bytes
           (publish-sample pub payla nil nil 0 nil ida)   ; writer A -> subA
           (loop repeat 150 until (plusp (node-sample-count suba)) do (sleep 0.02))
           (assert (equalp (node-sample-by-sn suba 1) payla) () "subA did not receive writer-A's payload")
           (sleep 0.1)   ; let subA's ACKNACK settle so writer-A's SN 1 is acked before the drop
           ;; (3) independent retransmit: drop writer-B's SN 1, repair via B's HEARTBEAT + writerId-routed ACKNACK
           (setf *debug-drop-sample-numbers* (list 1))
           (publish-sample pub paylb nil nil 0 nil idb)   ; writer B -> subB, SN 1 dropped on send
           (sleep 0.1)
           (assert (null (node-sample-by-sn subb 1)) () "drop hook failed: subB received the dropped writer-B DATA")
           (setf *debug-drop-sample-numbers* nil)
           (loop repeat 60 until (node-sample-by-sn subb 1) do (announce-endpoints pub) (sleep 0.02))
           (assert (equalp (node-sample-by-sn subb 1) paylb) ()
                   "writer-B's dropped sample never recovered via its HEARTBEAT + the writerId-routed ACKNACK")
           (assert (equalp (node-sample-by-sn suba 1) payla) ()
                   "writer-A's delivered sample was disturbed by writer-B's retransmit (routing leaked)")
           ;; over-send guard (explicit negatives): each reader sees EXACTLY its own writer's sample, never the sibling's
           (assert (= 1 (node-sample-count suba)) ()
                   "subA must receive EXACTLY writer-A's 1 sample — a 2nd sample means writer-B over-sent to it")
           (assert (= 1 (node-sample-count subb)) ()
                   "subB must receive EXACTLY writer-B's 1 sample — a 2nd sample means writer-A over-sent to it")
           (assert (not (equalp (node-sample-by-sn suba 1) paylb)) () "subA must NEVER see writer-B's payload")
           (assert (not (equalp (node-sample-by-sn subb 1) payla)) () "subB must NEVER see writer-A's payload")
           ;; (4a) WP-N-ENDPOINT-S3: a 2nd SECURED writer now REGISTERS (each keyed under its OWN EntityCrypto km) — the
           ;; S1-era fail-fast is LIFTED. The per-writer key derivation is proven by run-security-n-secured-writer-test.
           (let ((sn (make-disc-node :guid-prefix pp :host "127.0.0.1" :port 0)))
             (unwind-protect
                  (progn (add-local-writer sn :topic "SA" :type "X") (enable-publisher sn)
                         (setf (disc-node-user-data-protection-kind sn) :sign)   ; mark the node secured (governance data_protection)
                         (add-local-writer sn :topic "SB" :type "X")
                         (assert (ignore-errors (enable-publisher sn) t) ()
                                 "a 2nd SECURED writer must now REGISTER (WP-N-ENDPOINT-S3 — secured multi-writer supported)")
                         (assert (= 2 (length (%all-user-writer-ids sn))) ()
                                 "the participant must hold 2 secured user writers with distinct EntityIds (S3)"))
               (stop-node sn)))
           ;; (4b) WP-N-ENDPOINT-S1B: a flow-controller now ASSOCIATES on a 2-writer participant (the S1-era fail-fast
           ;; is LIFTED) — each writer becomes a distinct per-writer selection entry. Full both-drained delivery is
           ;; proven by run-flow-multiwriter-onenode-test.
           (let ((fc (make-flow-controller :tokens-per-period 100000 :period 1000000 :max-burst 65536)))
             (unwind-protect
                  (progn
                    (assert (ignore-errors (flow-controller-associate fc pub) t) ()
                            "flow-controller-associate on a 2-writer participant must now SUCCEED (WP-N-ENDPOINT-S1B)")
                    (assert (= 2 (length (disc-node-flow-writer-states pub))) ()
                            "the controller must register a per-writer flow-state for EACH of the 2 writers (S1b)")
                    (flow-controller-unregister fc pub))
               (destroy-flow-controller fc)))
           ;; (4c) WP-N-ENDPOINT-S2B: a 2nd writer on a node with a TRANSIENT_LOCAL writer now REGISTERS (the S1-era
           ;; fail-fast is LIFTED) — the match-time late-joiner replay (%writer-durability-init / %prearm) is per-writer,
           ;; so each durable writer replays its OWN retained history. Full per-writer replay + cross-isolation is
           ;; proven by run-dcps-durability-multiwriter-test.
           (let ((dn (make-disc-node :guid-prefix pp :host "127.0.0.1" :port 0)))
             (unwind-protect
                  (progn (add-local-writer dn :topic "DA" :type "X"
                                              :qos (dds.qos:make-writer-qos :durability :transient-local))
                         (enable-publisher dn)
                         (add-local-writer dn :topic "DB" :type "X"
                                              :qos (dds.qos:make-writer-qos :durability :transient-local))
                         (assert (ignore-errors (enable-publisher dn) t) ()
                                 "a 2nd RETAINING-durability writer must now REGISTER (WP-N-ENDPOINT-S2B — durable multi-writer supported)")
                         (assert (= 2 (length (%all-user-writer-ids dn))) ()
                                 "the participant must hold 2 durable user writers with distinct EntityIds (S2B)")
                         ;; (4d) WP-N-ENDPOINT-2C2: a 2nd SAME-topic (DA) durable writer now REGISTERS (fence C
                         ;; LIFTED) — %match-remote-endpoint fires per-(local,remote) pair, so each same-topic durable
                         ;; writer's match-side replay (%writer-durability-init / %prearm with ITS writer-id) is armed.
                         ;; Full per-writer same-topic replay + cross-isolation is proven by run-dcps-durability-multiwriter-test.
                         (assert (ignore-errors
                                  (add-local-writer dn :topic "DA" :type "X"
                                                       :qos (dds.qos:make-writer-qos :durability :transient-local))
                                  (enable-publisher dn) t) ()
                                 "a 2nd SAME-topic (DA) durable writer must now REGISTER (WP-N-ENDPOINT-2C2 — same-topic durable multi-writer supported)")
                         (assert (>= (length (%all-user-writer-ids dn)) 3) ()
                                 "the participant must now hold the 2nd same-topic durable writer with a distinct EntityId (2c-2)")
                         ;; a 2nd SAME-topic VOLATILE writer stays allowed (S1)
                         (assert (ignore-errors
                                  (add-local-writer dn :topic "VA" :type "X")
                                  (add-local-writer dn :topic "VA" :type "X") t) ()
                                 "two SAME-topic VOLATILE writers must still register (S1)"))
               (stop-node dn)))
           t)
      (setf *debug-drop-sample-numbers* nil)
      (stop-node pub) (stop-node suba) (stop-node subb))))

(defun* run-n-same-topic-writer-dataplane-test ()
    (function () (eql t))
  "WP-N-ENDPOINT-2C2 (ADR 0048): ONE participant with TWO user DataWriters on the SAME topic, matched to ONE
   remote reader participant. THE match-side dispatch slice. Asserts: (1) both writers get DISTINCT EntityIds/GUIDs
   (S1); (2) the ON-MATCH hook fires ONCE PER (writer,reader) PAIR — the counting hook records BOTH writer EntityIds
   for the :remote-reader match (pre-2c2 the per-remote %record-match gate fired for the FIRST same-topic writer
   ONLY — the RED); (3) IDEMPOTENCY — repeated SEDP re-announce does NOT re-fire (still exactly 2, one per writer),
   so PUBLICATION_MATCHED never double-counts; (4) DELIVERY — both writers publish and the remote reader receives
   BOTH streams (2 samples, dedup by distinct source GUID, automatic once both are matched); (5) UNMATCH per pair —
   %collect-and-remove-matches yields ONE unmatch entry PER matched (writer,reader) pair, each carrying its OWN
   writer EntityId (so the DECREMENT lands on the RIGHT endpoint), not a single per-remote entry."
  (let* ((pp (make-array 12 :element-type '(unsigned-byte 8) :initial-contents '(21 21 21 21 21 21 21 21 21 21 21 21)))
         (pr (make-array 12 :element-type '(unsigned-byte 8) :initial-contents '(22 22 22 22 22 22 22 22 22 22 22 22)))
         (pub (make-disc-node :guid-prefix pp :host "127.0.0.1" :port 0))
         (sub (make-disc-node :guid-prefix pr :host "127.0.0.1" :port 0))
         (payla (make-array 6 :element-type '(unsigned-byte 8) :initial-contents '(#xA1 #xA2 #xA3 #xA4 #xA5 #xA6)))
         (paylb (make-array 6 :element-type '(unsigned-byte 8) :initial-contents '(#xB1 #xB2 #xB3 #xB4 #xB5 #xB6)))
         (matched-eids '()))
    (unwind-protect
         (let (ida idb)
           (let ((ea (add-local-writer pub :topic "STW" :type "X" :reliability dds.rtps.discovery:+reliability-reliable+)))
             (enable-publisher pub)
             (setf ida (disc-node-user-writer-id pub))
             (let ((eb (add-local-writer pub :topic "STW" :type "X" :reliability dds.rtps.discovery:+reliability-reliable+)))
               (enable-publisher pub)
               (setf idb (disc-node-user-writer-id pub))
               (assert (/= ida idb) () "the two SAME-topic DataWriters did not get DISTINCT EntityIds")
               (assert (not (equalp (dds.rtps.discovery:endpoint-data-guid ea)
                                    (dds.rtps.discovery:endpoint-data-guid eb)))
                       () "the two SAME-topic DataWriters announce IDENTICAL SEDP GUIDs")))
           (setf (disc-node-on-match pub)
                 (lambda (kind remote local-eid)
                   (declare (ignore remote))
                   (when (eq kind :remote-reader) (push local-eid matched-eids))))
           (add-local-reader sub :topic "STW" :type "X" :reliability dds.rtps.discovery:+reliability-reliable+)
           (enable-subscriber sub)
           (setf (disc-node-peers pub) (list (cons "127.0.0.1" (disc-node-port sub)))
                 (disc-node-peers sub) (list (cons "127.0.0.1" (disc-node-port pub))))
           (start-node pub) (start-node sub)
           (announce-participant pub) (announce-participant sub)
           (loop repeat 150
                 until (and (plusp (disc-node-discovered-count pub)) (plusp (disc-node-discovered-count sub)))
                 do (sleep 0.02))
           (announce-endpoints pub) (announce-endpoints sub)
           ;; drive the match; keep re-announcing (exercises the re-announce IDEMPOTENCY path) until both writers fired
           (loop repeat 150
                 until (and (= 2 (length (remove-duplicates matched-eids)))
                            (plusp (disc-node-matched-count sub)))
                 do (announce-endpoints pub) (announce-endpoints sub) (sleep 0.02))
           ;; keep hammering re-announce so a double-count bug would show
           (dotimes (i 20) (announce-endpoints pub) (announce-endpoints sub) (sleep 0.01))
           ;; (2)+(3) exactly 2 fires, one per writer eid, NO double-count on re-announce
           (assert (= 2 (length matched-eids)) ()
                   "the ON-MATCH hook must fire EXACTLY twice (one per same-topic writer), no double-count on re-announce; got ~D" (length matched-eids))
           (assert (and (member ida matched-eids :test #'=) (member idb matched-eids :test #'=)) ()
                   "the ON-MATCH hook must fire for BOTH writer EntityIds (per-(local,remote) pair), not the first-by-topic only")
           ;; (4) both writers deliver -> the remote reader receives BOTH streams
           (publish-sample pub payla nil nil 0 nil ida)
           (publish-sample pub paylb nil nil 0 nil idb)
           (loop repeat 150 until (>= (node-sample-count sub) 2) do (announce-endpoints pub) (sleep 0.02))
           (assert (>= (node-sample-count sub) 2) ()
                   "the remote reader must receive BOTH same-topic writers' streams (2 samples, dedup by source GUID)")
           ;; (5) UNMATCH per pair: %collect-and-remove-matches yields one entry PER matched writer, each with its own eid
           (let ((removed '()))
             (dds.pal:with-lock ((disc-node-lock pub))
               (%collect-and-remove-matches pub (disc-node-guid-prefix sub)
                                            (lambda (dm) (push dm removed))))
             (assert (= 2 (length removed)) ()
                     "unmatch (lease-sweep) must yield ONE entry PER matched (writer,reader) pair (2), not a single per-remote entry; got ~D" (length removed))
             (let ((eids (mapcar #'cddr removed)))
               (assert (every (lambda (dm) (eq :remote-reader (car dm))) removed) ()
                       "each unmatch entry must be direction :remote-reader")
               (assert (and (member ida eids :test #'eql) (member idb eids :test #'eql)) ()
                       "unmatch must carry BOTH writers' EntityIds (so the DECREMENT lands on the RIGHT endpoint per writer)")))
           t)
      (stop-node pub) (stop-node sub))))

(defun* run-n-writer-frag-heartbeat-test ()
    (function () (eql t))
  "WP-N-ENDPOINT-S1 (ADR 0048, fix F1): a participant with 2 writers, where the NON-PRIMARY writer publishes a
   FRAGMENTED (> *fragment-size*) sample, must draw its DATA_FRAG HEARTBEAT_FRAG from ITS OWN HistoryCache — NOT
   the primary's (the pre-fix %sample-plan bug hard-coded (disc-node-user-writer node) = primary). The precise
   observable is the writer's HEARTBEAT_FRAG COUNT side-effect (writer-frag-heartbeat increments the SOURCED
   writer's frag-hb-count): end-to-end delivery is masked here because the coalesced regular HEARTBEAT lets the
   coarse ACKNACK path re-send all fragments, so the fine-recovery routing is only visible at the frag-HB level.
   Both writers publish a fragmented SN 1; after both pushes EACH writer's frag-hb-count must be exactly 1 — pre-fix
   the primary's is 2 (it was consulted for BOTH writers) and the non-primary's is 0 (its recovery was suppressed/
   mis-sourced). No subscriber needed: a bogus PEER makes the push form a destination so %sample-plan runs."
  (let* ((pp (make-array 12 :element-type '(unsigned-byte 8) :initial-contents '(4 4 4 4 4 4 4 4 4 4 4 4)))
         (pub (make-disc-node :guid-prefix pp :host "127.0.0.1" :port 0))
         (big-a (make-array (* 3 dds.rtps.reliable:*fragment-size*) :element-type '(unsigned-byte 8)
                            :initial-element #xAA))
         (big-b (make-array (* 2 dds.rtps.reliable:*fragment-size*) :element-type '(unsigned-byte 8)
                            :initial-element #xBB)))
    (unwind-protect
         (progn
           (add-local-writer pub :topic "FA" :type "X" :reliability dds.rtps.discovery:+reliability-reliable+)
           (enable-publisher pub)
           (let ((ida (disc-node-user-writer-id pub)))
             (add-local-writer pub :topic "FB" :type "X" :reliability dds.rtps.discovery:+reliability-reliable+)
             (enable-publisher pub)
             (let* ((idb (disc-node-user-writer-id pub))
                    (wa (%user-writer-for pub ida))
                    (wb (%user-writer-for pub idb)))
               (assert (/= ida idb) () "the 2 fragmenting writers must have distinct EntityIds")
               (setf (disc-node-peers pub) (list (cons "127.0.0.1" 59999)))   ; a bogus dest so each push forms a group + runs %sample-plan
               (start-node pub)
               (publish-sample pub big-a nil nil 0 nil ida)   ; primary A: fragmented SN 1
               (publish-sample pub big-b nil nil 0 nil idb)   ; non-primary B: fragmented SN 1
               (sleep 0.05)
               (assert (= 1 (dds.rtps.reliable::rtps-writer-frag-hb-count wb)) ()
                       "F1: the NON-PRIMARY writer's HEARTBEAT_FRAG must come from ITS OWN HC (frag-hb-count=1); ~
                        got ~D (pre-fix 0 — the primary was consulted for writer B)"
                       (dds.rtps.reliable::rtps-writer-frag-hb-count wb))
               (assert (= 1 (dds.rtps.reliable::rtps-writer-frag-hb-count wa)) ()
                       "F1: the PRIMARY writer's frag-hb-count must be exactly 1 (its OWN push only); ~
                        got ~D (pre-fix 2 — it was wrongly consulted for writer B too)"
                       (dds.rtps.reliable::rtps-writer-frag-hb-count wa))))
           t)
      (stop-node pub))))

(defun* run-n-reader-dataplane-test ()
    (function () (eql t))
  "WP-N-ENDPOINT-S2 (ADR 0048): ONE participant with TWO non-secured user DataReaders on DIFFERENT topics, each fed
   by its own remote writer participant. Asserts: (1) the two readers get DISTINCT EntityIds/GUIDs (pre-S2 both
   collided on #x0107 — the RED); (2) both readers match their own writer + the DELIVERY ROUTE is correct — reader-A
   is matched to writer-A's GUID and NOT to writer-B's, and vice-versa (node-reader-matches-writer-p; a cross entry
   would be the cross-topic-deserialize corruption source); (3) the node store receives BOTH writers' samples under
   the demux (canonical-reader routing), one per writer. Then the ROUTE LIFECYCLE (unmatch/lease-expiry drops the
   route, re-announce re-adds it — no dropped own-samples). WP-N-ENDPOINT-S4: (4) a 2nd SECURED reader and (4b) a
   2nd ZC-loan-capable reader on DIFFERENT topics now REGISTER (the secured/ZC fence is LIFTED — 2 distinct
   EntityIds). WP-N-ENDPOINT-2C1: (4c) a 2nd NON-loan SAME-topic reader now REGISTERS and ROUTE-ADD-ALL routes BOTH
   reader-ids to their common writer's GUID (pre-2c1 only the first matched — the RED); WP-N-ENDPOINT-2C3: (4d) a
   2nd SAME-topic LOAN-CAPABLE reader now REGISTERS with a distinct EntityId (the LAST same-topic fence is lifted;
   the ADR-0017 refcount-per-reader UAF is closed at its site, not fenced)."
  (let* ((pp (make-array 12 :element-type '(unsigned-byte 8) :initial-contents '(7 7 7 7 7 7 7 7 7 7 7 7)))
         (pa (make-array 12 :element-type '(unsigned-byte 8) :initial-contents '(8 8 8 8 8 8 8 8 8 8 8 8)))
         (pb (make-array 12 :element-type '(unsigned-byte 8) :initial-contents '(9 9 9 9 9 9 9 9 9 9 9 9)))
         (sub  (make-disc-node :guid-prefix pp :host "127.0.0.1" :port 0))   ; ONE participant, TWO readers
         (puba (make-disc-node :guid-prefix pa :host "127.0.0.1" :port 0))
         (pubb (make-disc-node :guid-prefix pb :host "127.0.0.1" :port 0))
         (payla (make-array 6 :element-type '(unsigned-byte 8) :initial-contents '(#xA1 #xA2 #xA3 #xA4 #xA5 #xA6)))
         (paylb (make-array 6 :element-type '(unsigned-byte 8) :initial-contents '(#xB1 #xB2 #xB3 #xB4 #xB5 #xB6))))
    (unwind-protect
         (let (ida idb wga wgb)
           (let ((epwa (add-local-writer puba :topic "NRA" :type "X" :reliability dds.rtps.discovery:+reliability-reliable+)))
             (enable-publisher puba)
             (setf wga (dds.rtps.discovery:endpoint-data-guid epwa)))
           (let ((epwb (add-local-writer pubb :topic "NRB" :type "X" :reliability dds.rtps.discovery:+reliability-reliable+)))
             (enable-publisher pubb)
             (setf wgb (dds.rtps.discovery:endpoint-data-guid epwb)))
           (let ((epra (add-local-reader sub :topic "NRA" :type "X" :reliability dds.rtps.discovery:+reliability-reliable+)))
             (enable-subscriber sub)
             (setf ida (disc-node-user-reader-id sub))
             (let ((eprb (add-local-reader sub :topic "NRB" :type "X" :reliability dds.rtps.discovery:+reliability-reliable+)))
               (enable-subscriber sub)
               (setf idb (disc-node-user-reader-id sub))
               (assert (/= ida idb) () "the two DataReaders did not get DISTINCT EntityIds (pre-S2 clobber: both #x~8,'0X)" ida)
               (assert (not (equalp (dds.rtps.discovery:endpoint-data-guid epra)
                                    (dds.rtps.discovery:endpoint-data-guid eprb)))
                       () "the two DataReaders announce IDENTICAL SEDP GUIDs (a remote peer would see 1 aliased reader)")))
           (setf (disc-node-peers sub)  (list (cons "127.0.0.1" (disc-node-port puba)) (cons "127.0.0.1" (disc-node-port pubb)))
                 (disc-node-peers puba) (list (cons "127.0.0.1" (disc-node-port sub)))
                 (disc-node-peers pubb) (list (cons "127.0.0.1" (disc-node-port sub))))
           (start-node sub) (start-node puba) (start-node pubb)
           (announce-participant sub) (announce-participant puba) (announce-participant pubb)
           (loop repeat 150
                 until (and (>= (disc-node-discovered-count sub) 2)
                            (plusp (disc-node-discovered-count puba))
                            (plusp (disc-node-discovered-count pubb)))
                 do (sleep 0.02))
           (announce-endpoints sub) (announce-endpoints puba) (announce-endpoints pubb)
           (loop repeat 150
                 until (and (>= (disc-node-matched-count sub) 2)
                            (plusp (disc-node-matched-count puba))
                            (plusp (disc-node-matched-count pubb)))
                 do (announce-endpoints sub) (sleep 0.02))
           (assert (>= (disc-node-matched-count sub) 2) () "the 2 readers did not both match their remote writer")
           ;; (2) route correctness: reader-A <-> writer-A only, reader-B <-> writer-B only (no cross = no corruption source)
           (assert (node-reader-matches-writer-p sub ida wga) () "reader-A must be routed to writer-A's GUID")
           (assert (node-reader-matches-writer-p sub idb wgb) () "reader-B must be routed to writer-B's GUID")
           (assert (not (node-reader-matches-writer-p sub ida wgb)) () "reader-A must NOT be routed to writer-B (cross-topic route = corruption)")
           (assert (not (node-reader-matches-writer-p sub idb wga)) () "reader-B must NOT be routed to writer-A (cross-topic route = corruption)")
           ;; (3) both writers publish -> the node store receives each writer's sample (demux canonical routing)
           (publish-sample puba payla) (publish-sample pubb paylb)
           (loop repeat 150 until (>= (node-sample-count sub) 2) do (announce-endpoints puba) (announce-endpoints pubb) (sleep 0.02))
           (assert (= 2 (node-sample-count sub)) () "the store must hold EXACTLY one sample per writer (2)")
           (assert (equalp payla (node-sample sub (cons wga 1))) () "writer-A's sample must be stored under writer-A's GUID")
           (assert (equalp paylb (node-sample sub (cons wgb 1))) () "writer-B's sample must be stored under writer-B's GUID")
           ;; route lifecycle: unmatch/lease-expiry drops the route; a re-announce re-adds it (no dropped own-samples)
           (dds.pal:with-lock ((disc-node-lock sub)) (%purge-prefix sub pa #'disc-node-reader-routes)
             (%invalidate-route-cache sub))
           (assert (not (node-reader-matches-writer-p sub ida wga)) () "unmatch/lease-expiry must drop reader-A's route to writer-A")
           (%reader-route-add sub wga ida)
           (assert (node-reader-matches-writer-p sub ida wga) () "a re-announce must re-add reader-A's route (no permanent drop)")
           ;; (4) WP-N-ENDPOINT-S4: a 2nd SECURED reader on a DIFFERENT topic now REGISTERS (the S2/S3 fence is LIFTED)
           (let ((sn (make-disc-node :guid-prefix pp :host "127.0.0.1" :port 0)))
             (unwind-protect
                  (progn (add-local-reader sn :topic "SA" :type "X") (enable-subscriber sn)
                         (setf (disc-node-user-reader-data-protection-kind sn) :sign)   ; mark the node secured (governance data_protection)
                         (let ((sa (disc-node-user-reader-id sn)))
                           (add-local-reader sn :topic "SB" :type "X")
                           (assert (ignore-errors (enable-subscriber sn) t) ()
                                   "a 2nd SECURED reader on a DIFFERENT topic must now REGISTER (WP-N-ENDPOINT-S4)")
                           (assert (/= sa (disc-node-user-reader-id sn)) () "the 2 secured readers must get distinct EntityIds (S4)")
                           (assert (= 2 (length (%all-user-reader-ids sn))) ()
                                   "the participant must hold 2 secured user readers with distinct EntityIds (S4)")))
               (stop-node sn)))
           ;; (4b) WP-N-ENDPOINT-S4: a 2nd ZC-loan-capable reader on a DIFFERENT topic now REGISTERS (fence LIFTED)
           (let ((zn (make-disc-node :guid-prefix pp :host "127.0.0.1" :port 0)))
             (unwind-protect
                  (progn (add-local-reader zn :topic "ZA" :type "X") (enable-subscriber zn)
                         (set-zc-loan-capable zn t)   ; mark the node ZC-loan-capable
                         (let ((za (disc-node-user-reader-id zn)))
                           (add-local-reader zn :topic "ZB" :type "X")
                           (assert (ignore-errors (enable-subscriber zn) t) ()
                                   "a 2nd ZC-loan-capable reader on a DIFFERENT topic must now REGISTER (WP-N-ENDPOINT-S4)")
                           (assert (/= za (disc-node-user-reader-id zn)) () "the 2 ZC readers must get distinct EntityIds (S4)")
                           (assert (= 2 (length (%all-user-reader-ids zn))) ()
                                   "the participant must hold 2 ZC-loan-capable user readers with distinct EntityIds (S4)")))
               (stop-node zn)))
           ;; (4c) WP-N-ENDPOINT-2C1: a 2nd NON-loan reader on the SAME topic now REGISTERS (fence A lifted for the
           ;; non-loan case) and ROUTE-ADD-ALL routes BOTH same-topic reader-ids to their ONE common remote writer.
           (let ((rn (make-disc-node :guid-prefix pp :host "127.0.0.1" :port 0))
                 (wn (make-disc-node :guid-prefix (make-array 12 :element-type '(unsigned-byte 8) :initial-element 6)
                                     :host "127.0.0.1" :port 0)))
             (unwind-protect
                  (let (r1 r2 wg)
                    (let ((ep (add-local-writer wn :topic "SAME" :type "X" :reliability dds.rtps.discovery:+reliability-reliable+)))
                      (enable-publisher wn) (setf wg (dds.rtps.discovery:endpoint-data-guid ep)))
                    (add-local-reader rn :topic "SAME" :type "X" :reliability dds.rtps.discovery:+reliability-reliable+)
                    (enable-subscriber rn) (setf r1 (disc-node-user-reader-id rn))
                    (add-local-reader rn :topic "SAME" :type "X" :reliability dds.rtps.discovery:+reliability-reliable+)
                    (enable-subscriber rn) (setf r2 (disc-node-user-reader-id rn))
                    (assert (/= r1 r2) () "the 2 NON-loan same-topic readers must register with DISTINCT ids (fence A lifted for non-loan)")
                    (setf (disc-node-peers rn) (list (cons "127.0.0.1" (disc-node-port wn)))
                          (disc-node-peers wn) (list (cons "127.0.0.1" (disc-node-port rn))))
                    (start-node rn) (start-node wn)
                    (announce-participant rn) (announce-participant wn)
                    (loop repeat 150 until (and (plusp (disc-node-discovered-count rn)) (plusp (disc-node-discovered-count wn))) do (sleep 0.02))
                    (announce-endpoints rn) (announce-endpoints wn)
                    (loop repeat 150 until (and (node-reader-matches-writer-p rn r1 wg) (node-reader-matches-writer-p rn r2 wg))
                          do (announce-endpoints rn) (announce-endpoints wn) (sleep 0.02))
                    ;; route-add-all: BOTH same-topic reader-ids are routed to the ONE writer's GUID (pre-2c1: only the first)
                    (assert (node-reader-matches-writer-p rn r1 wg) () "reader-1 must be route-added to the same-topic writer")
                    (assert (node-reader-matches-writer-p rn r2 wg) () "reader-2 must ALSO be route-added to the same-topic writer (route-add-all — the RED: pre-2c1 only the first matched)"))
               (stop-node rn) (stop-node wn)))
           ;; (4d) WP-N-ENDPOINT-2C3: the LAST same-topic fence is LIFTED — a 2nd SAME-topic LOAN-CAPABLE reader now
           ;; REGISTERS with a DISTINCT EntityId (mirrors how S4 flipped 4/4b and 2c-1 flipped 4c). The ADR-0017
           ;; cross-reader UAF is closed at its site (demux bump + joiner freeze + secured purge-defer), not fenced.
           (let ((tn (make-disc-node :guid-prefix pp :host "127.0.0.1" :port 0)))
             (unwind-protect
                  (progn (add-local-reader tn :topic "SAME" :type "X") (enable-subscriber tn)
                         (set-zc-loan-capable tn t)   ; mark the node loan-capable (ZC) BEFORE the 2nd same-topic add
                         (let ((ta (disc-node-user-reader-id tn)))
                           (assert (ignore-errors (add-local-reader tn :topic "SAME" :type "X") t) ()
                                   "a 2nd SAME-topic LOAN-CAPABLE reader must now REGISTER (WP-N-ENDPOINT-2C3, fence lifted)")
                           (enable-subscriber tn)
                           (assert (/= ta (disc-node-user-reader-id tn)) ()
                                   "the 2 same-topic loan-capable readers must get distinct EntityIds (2c-3)")))
               (stop-node tn)))
           t)
      (stop-node sub) (stop-node puba) (stop-node pubb))))

(defun* run-n-reader-s4-decode-tier-test ()
    (function () (eql t))
  "WP-N-ENDPOINT-S4 (ADR 0048/0046; ADR 0017): the PER-READER DECODE-TIER correctness gate — ONE participant with
   TWO loan-capable DataReaders on DIFFERENT topics of DIFFERENT data_protection kinds, each decoding under ITS OWN
   topic tier (%user-endpoint-kinds), NEVER the node-single last-set slot. Two node-single orderings prove BOTH
   directions of the cross-tier bug %deliver-user-sample would have if the tier stayed node-single (the RED):
   (1) node-single DOWNGRADED to NONE (the plain reader added LAST): a secured reader must STILL REJECT an
       unprotected sample under its OWN ENCRYPT tier — a node-single NONE would false-ACCEPT unauthenticated data
       (the security-critical direction); the plain reader coexisting still receives its plaintext;
   (2) node-single UPGRADED to secured (the secured reader added LAST): a plain reader must STILL RECEIVE its
       plaintext under its OWN NONE tier — a node-single ENCRYPT would decode-attempt + DROP it (false-REJECT).
   (d) no-cross-free: two distinct secured-loan handles in the shared registry — releasing one leaves the other's
   buffer + registration + stored slot intact (the identity-guarded %secured-loan-release; disjoint different-topic
   slots). The deterministic arms are DARE-free (a <44-octet plaintext fails the SecuredPayload length gate before
   any AES); the live ENCRYPT-decode arm is DARE-gated. Clasp FIRST."
  (let ((km (dds.security:make-test-key-material :kind :encrypt))
        (payl (make-array 6 :element-type '(unsigned-byte 8) :initial-contents '(#xD1 #xD2 #xD3 #xD4 #xD5 #xD6))))
    (flet ((dres (tp) (declare (type string tp)) (if (string= tp "TENC") :encrypt :none))
           (mres (tp) (declare (ignore tp)) :none))
      ;; --- Scenario 1: node-single DOWNGRADED to NONE (plain reader added last) ---
      (let ((n (make-disc-node :guid-prefix (make-array 12 :element-type '(unsigned-byte 8) :initial-element #x51)
                               :host "127.0.0.1" :port 0)))
        (unwind-protect
             (progn
               (setf (disc-node-topic-data-protection-resolver n) #'dres
                     (disc-node-topic-metadata-protection-resolver n) #'mres
                     (disc-node-crypto-transform n) km)
               (add-local-reader n :topic "TENC" :type "X") (enable-subscriber n)   ; secured reader = primary
               (let ((id-sec (disc-node-user-reader-id n)))
                 (add-local-reader n :topic "TPLAIN" :type "X") (enable-subscriber n)   ; plain reader (fence lifted)
                 (let ((id-plain (disc-node-user-reader-id n)))
                   (assert (/= id-sec id-plain) () "S4: the 2 different-topic secured/plain readers must get distinct EntityIds")
                   (assert (eq :encrypt (%user-endpoint-kinds n id-sec)) () "S4: the secured reader's OWN tier must be :encrypt (per-endpoint map)")
                   (assert (eq :none (%user-endpoint-kinds n id-plain)) () "S4: the plain reader's OWN tier must be :none")
                   (assert (eq :none (disc-node-user-reader-data-protection-kind n)) () "S4 precondition: node-single slot is :none (plain reader last)")
                   (let* ((src-sec (make-array 12 :element-type '(unsigned-byte 8) :initial-element #x5A))
                          (src-pl  (make-array 12 :element-type '(unsigned-byte 8) :initial-element #x5B))
                          (gsec (%source-guid src-sec #x00000102))
                          (gpl  (%source-guid src-pl  #x00000102)))
                     (%reader-route-add n gsec id-sec)
                     (%reader-route-add n gpl id-plain)
                     (%deliver-user-sample n #x00000102 1 payl src-sec gsec 1)   ; unprotected sample to the SECURED reader
                     (assert (null (node-sample n (cons gsec 1))) ()
                             "S4 GATE (security-critical): a secured reader must REJECT an unprotected sample under its OWN ENCRYPT tier — a node-single NONE downgrade would false-ACCEPT it")
                     (%deliver-user-sample n #x00000102 1 payl src-pl gpl 1)   ; plaintext to the PLAIN reader
                     (assert (equalp payl (node-sample n (cons gpl 1))) ()
                             "S4: the plain reader must RECEIVE its plaintext under its OWN NONE tier (coexisting with the secured reader)")))))
          (stop-node n)))
      ;; --- Scenario 2: node-single UPGRADED to secured (secured reader added last) ---
      (let ((n2 (make-disc-node :guid-prefix (make-array 12 :element-type '(unsigned-byte 8) :initial-element #x52)
                                :host "127.0.0.1" :port 0)))
        (unwind-protect
             (progn
               (setf (disc-node-topic-data-protection-resolver n2) #'dres
                     (disc-node-topic-metadata-protection-resolver n2) #'mres
                     (disc-node-crypto-transform n2) km)
               (add-local-reader n2 :topic "TPLAIN" :type "X") (enable-subscriber n2)   ; plain reader = primary
               (let ((id-plain (disc-node-user-reader-id n2)))
                 (add-local-reader n2 :topic "TENC" :type "X") (enable-subscriber n2)   ; secured reader (fence lifted)
                 (let ((id-sec (disc-node-user-reader-id n2)))
                   (assert (eq :encrypt (disc-node-user-reader-data-protection-kind n2)) () "S4 precondition: node-single slot is :encrypt (secured reader last)")
                   (let* ((src-pl (make-array 12 :element-type '(unsigned-byte 8) :initial-element #x6B))
                          (gpl (%source-guid src-pl #x00000102)))
                     (%reader-route-add n2 gpl id-plain)
                     (%deliver-user-sample n2 #x00000102 1 payl src-pl gpl 1)   ; plaintext to the PLAIN reader
                     (assert (equalp payl (node-sample n2 (cons gpl 1))) ()
                             "S4 GATE: the plain reader must RECEIVE its plaintext under its OWN NONE tier — a node-single ENCRYPT upgrade would decode-attempt + DROP it (false-REJECT)")
                     (when (dds.dare:dare-available-p)   ; ADR 0064: dare-available-p returns AVAILABLE directly
                       (let* ((src-sec (make-array 12 :element-type '(unsigned-byte 8) :initial-element #x6A))
                              (gsec (%source-guid src-sec #x00000102))
                              (sealed (dds.security:encode-serialized-payload km payl)))
                         (%reader-route-add n2 gsec id-sec)
                         (%deliver-user-sample n2 #x00000102 1 sealed src-sec gsec 1)   ; real ENCRYPT payload to the SECURED reader
                         (assert (equalp payl (node-sample n2 (cons gsec 1))) ()
                                 "S4: the secured reader must DECODE a real ENCRYPT payload to plaintext under its OWN tier")))))))
          (stop-node n2)))
      ;; --- (d) no-cross-free: releasing reader-A's secured loan must not free reader-B's buffer ---
      (let ((zn (make-disc-node :guid-prefix (make-array 12 :element-type '(unsigned-byte 8) :initial-element #x53)
                                :host "127.0.0.1" :port 0)))
        (unwind-protect
             (progn
               (enable-subscriber zn)
               (set-secured-loan-capable zn t)
               (let ((pool (%ensure-secured-decode-pool zn)))
                 (when pool
                   (let ((ga (make-array 16 :element-type '(unsigned-byte 8) :initial-element #xA0))
                         (gb (make-array 16 :element-type '(unsigned-byte 8) :initial-element #xB0)))
                     (multiple-value-bind (ba bb ha hb)
                         (dds.pal:with-lock ((disc-node-decode-pool-lock zn))
                           (let ((a (dds.core.arena:pool-acquire pool))
                                 (b (dds.core.arena:pool-acquire pool)))
                             (values a b (%secured-handle-acquire zn) (%secured-handle-acquire zn))))
                       (%secured-handle-fill ha ba 4 ga 1)   ; reader-A's loan: distinct buffer + (GUID,SN) slot
                       (%secured-handle-fill hb bb 4 gb 1)   ; reader-B's loan: DISJOINT buffer + slot (different-topic source GUID)
                       (dds.pal:with-lock ((disc-node-lock zn))
                         (setf (gethash 1 (%inner-table (disc-node-samples zn) ga)) ha
                               (gethash 1 (%inner-table (disc-node-samples zn) gb)) hb)
                         (%secured-loan-register zn ha)
                         (%secured-loan-register zn hb))
                       (node-return-loan zn ha)   ; reader-A returns ITS loan
                       (assert (null (secured-loan-handle-buffer ha)) () "S4 no-cross-free: reader-A's returned handle must be dissociated")
                       (assert (secured-loan-handle-buffer hb) () "S4 no-cross-free: reader-B's buffer must SURVIVE reader-A's return-loan")
                       (assert (>= (secured-loan-handle-reg-index hb) 0) () "S4 no-cross-free: reader-B's handle must stay REGISTERED after reader-A's return")
                       (assert (eq hb (node-sample zn (cons gb 1))) () "S4 no-cross-free: reader-B's stored sample must be untouched by reader-A's return")
                       (node-return-loan zn hb))))))   ; clean up reader-B
          (stop-node zn)))))
  t)

(defun* run-n-reader-s4-zc-marker-test ()
    (function () (eql t))
  "WP-N-ENDPOINT-S4 (ADR 0048/0017): the ZC-loan MARKER path demux. ONE participant, TWO ZC-loan-capable readers on
   DIFFERENT topics. %deliver-user-marker must deliver each ZC marker to the CANONICAL reader MATCHED to its source
   writer (%reader-routes-for) — NOT unconditionally the primary. Proven through the PER-READER dedup: a marker for
   reader-B carrying a logical-origin (GUID,SN) the PRIMARY reader-A already saw must STILL be ACCEPTED (reader-B's
   OWN dedup is fresh) and stored under reader-B's source GUID. RED if the marker were routed to the primary:
   reader-A's dedup would REJECT the shared logical-origin as a duplicate -> reader-B silently loses its marker."
  (let ((zn (make-disc-node :guid-prefix (make-array 12 :element-type '(unsigned-byte 8) :initial-element #x54)
                            :host "127.0.0.1" :port 0)))
    (unwind-protect
         (progn
           (set-zc-loan-capable zn t)
           (add-local-reader zn :topic "ZMA" :type "X") (enable-subscriber zn)   ; reader-A = primary
           (let ((ida (disc-node-user-reader-id zn)))
             (add-local-reader zn :topic "ZMB" :type "X") (enable-subscriber zn)   ; reader-B (fence lifted)
             (let* ((idb (disc-node-user-reader-id zn))
                    (src-a (make-array 12 :element-type '(unsigned-byte 8) :initial-element #x7A))
                    (src-b (make-array 12 :element-type '(unsigned-byte 8) :initial-element #x7B))
                    (ga (%source-guid src-a #x00000102))
                    (gb (%source-guid src-b #x00000102))
                    (origin (make-array 16 :element-type '(unsigned-byte 8) :initial-element #x99))   ; a shared relay logical-origin GUID
                    (mka (%make-zc-loan-marker :slot-index 1))
                    (mkb (%make-zc-loan-marker :slot-index 2)))
               (assert (/= ida idb) () "S4 ZC: the 2 different-topic ZC readers must get distinct EntityIds")
               (%reader-route-add zn ga ida)
               (%reader-route-add zn gb idb)
               (%deliver-user-marker zn #x00000102 1 mka src-a origin 7)   ; reader-A records logical-origin (origin,7)
               (assert (eq mka (node-sample zn (cons ga 1))) () "S4 ZC: reader-A's marker must be stored under its OWN source GUID")
               (%deliver-user-marker zn #x00000102 2 mkb src-b origin 7)   ; reader-B: SAME logical-origin, its OWN dedup is fresh
               (assert (eq mkb (node-sample zn (cons gb 2))) ()
                       "S4 ZC GATE: reader-B's marker must be delivered to reader-B (its OWN dedup) and stored — RED if routed to the primary (reader-A's dedup would reject the shared logical-origin as a duplicate)")))
           t)
      (stop-node zn))))

(defun* run-n-reader-2c3-zc-uaf-test ()
    (function () (eql t))
  "WP-N-ENDPOINT-2C3 (ADR 0017/0048; MEMORY-SAFETY): the same-topic ZC cross-reader use-after-free contract + the
   generation-guard stale-acquire no-op. Model-level (no wire, no SHMEM — a LOCAL static pool), opt-in via
   set-zc-loan-capable. ONE participant, TWO same-topic ZC-loan-capable readers (distinct EntityIds) both routed to
   ONE source writer; the writer %zc-loans a 1-slot pool for readers=1 (refcount 1). Delivering the marker must
   DEMUX-BUMP the slot to refcount K=2 (the (K-1) bump) BEFORE it is drainable. Then, driving the EXACT pool
   primitives %drain-one-loan / return-loan funcall — %zc-acquire-for-read (NO increment) and %zc-release:
     (1) reader-A returns (2->1) and the slot is STILL held (NOT reclaimable — a writer re-loan finds no free slot),
     (2) reader-B STILL reads its CORRECT bytes off its live view (the UAF RED: pre-fix no bump -> A's return frees
         the slot -> a writer re-loan recycles it -> reader-B reads a DIFFERENT sample's bytes),
     (3) reader-B returns (1->0) and only THEN is the slot reclaimable (frees at the true 0, after ALL K holders),
     (4) GENERATION-GUARD: after force-reclaim (a re-loan bumps the generation), reader-B's stale acquire/release at
         the OLD generation is a validated no-op (NIL) — never a decrement of the reused slot.
   SBCL-only: the ZC refcount primitives are cas-sap-u32 (SBCL PAL; NFR-PORT ZC gap on Clasp, ADR 0013). NOT cleared
   for ship — pending counsel (R6)."
  (if (not (eq (dds.pal:pal-impl-name) :sbcl))
      (progn (format t "~&  [skip] n-reader-2c3-zc-uaf: %zc-bump/%zc-release use cas-sap-u32 (SBCL-only, ADR 0018) — NFR-PORT gap~%") t)
      (let ((m (dds.pal:alloc-static (dds.xport.zerocopy::%zc-bytes 1 64)))
            (pa (make-array 12 :element-type '(unsigned-byte 8) :initial-element #x5C))
            (payload (make-array 8 :element-type '(unsigned-byte 8) :initial-contents '(#xC1 #xC2 #xC3 #xC4 #xC5 #xC6 #xC7 #xC8)))
            (other (make-array 8 :element-type '(unsigned-byte 8) :initial-contents '(#x11 #x22 #x33 #x44 #x55 #x66 #x77 #x88)))
            (zn (make-disc-node :guid-prefix (make-array 12 :element-type '(unsigned-byte 8) :initial-element #x5D)
                                :host "127.0.0.1" :port 0)))
        (unwind-protect
             (let ((sap (dds.pal:static-pointer m)))
               (flet ((rc (slot) (dds.pal:load-sap-u32 sap (+ (dds.xport.zerocopy::%zc-slot-off sap slot)
                                                              dds.xport.zerocopy::+zc-slot-off-refcount+))))
                 (dds.xport.zerocopy::%zc-init sap 1 64)
                 (set-zc-loan-capable zn t)
                 (add-local-reader zn :topic "Z2C3" :type "X") (enable-subscriber zn)
                 (let ((ida (disc-node-user-reader-id zn)))
                   (add-local-reader zn :topic "Z2C3" :type "X") (enable-subscriber zn)
                   (let ((idb (disc-node-user-reader-id zn))
                         (gw (%source-guid pa #x00000102)))
                     (assert (/= ida idb) () "2c-3: the 2 same-topic ZC readers must get distinct EntityIds")
                     (%reader-route-add zn gw ida) (%reader-route-add zn gw idb)
                     (multiple-value-bind (slot gen) (dds.xport.zerocopy::%zc-loan sap payload 0 (length payload) 1)
                       (assert (and slot (= 1 (rc slot))) () "2c-3: the writer loan must set refcount 1 (the per-participant preset)")
                       (let ((marker (%make-zc-loan-marker :pool-sap sap :slot-index slot :generation gen :len 64)))
                         (%deliver-user-marker zn #x00000102 1 marker pa gw 1)
                         (assert (= 2 (rc slot)) ()
                                 "2c-3 CORE: the demux must bump the shared slot to refcount K=2 (RED: without the (K-1) bump it stays 1 -> A's return frees B's view)")
                         (assert (eq marker (node-sample zn (cons gw 1))) () "2c-3: the marker must be stored under the source GUID")
                         (assert (zerop (dds.xport.zerocopy::%zc-free-count sap)) () "2c-3: with refcount 2 the slot must NOT be reclaimable")
                         (multiple-value-bind (sa2 sla ga la ba) (dds.xport.zerocopy::%zc-acquire-for-read sap slot gen)
                           (declare (ignore sla ga la))
                           (assert sa2 () "2c-3: reader-A must acquire the slot for read (no refcount increment)")
                           (assert (loop for i below (length payload) always (= (dds.pal:load-sap-u8 sap (+ ba i)) (aref payload i)))
                                   () "2c-3: reader-A must read the CORRECT payload bytes"))
                         (dds.xport.zerocopy::%zc-release sap slot gen)   ; reader-A return-loan
                         (assert (= 1 (rc slot)) () "2c-3 INVARIANT: after reader-A returns, refcount must be 1 (reader-B still holds)")
                         (assert (zerop (dds.xport.zerocopy::%zc-free-count sap)) ()
                                 "2c-3 INVARIANT: reader-A's return must NOT free the slot reader-B still views")
                         (multiple-value-bind (rs rg) (dds.xport.zerocopy::%zc-loan sap other 0 (length other) 1)
                           (declare (ignore rg))
                           (assert (null rs) () "2c-3 UAF-SAFETY: while reader-B holds, a writer re-loan must NOT reclaim the slot (no premature recycle)"))
                         (multiple-value-bind (sb2 slb gb lb bb) (dds.xport.zerocopy::%zc-acquire-for-read sap slot gen)
                           (declare (ignore slb gb lb))
                           (assert sb2 () "2c-3: reader-B's view must still be valid (generation stable while held)")
                           (assert (loop for i below (length payload) always (= (dds.pal:load-sap-u8 sap (+ bb i)) (aref payload i)))
                                   () "2c-3 UAF RED->GREEN: reader-B must read the CORRECT bytes, not a recycled sample"))
                         (dds.xport.zerocopy::%zc-release sap slot gen)   ; reader-B return-loan (1->0)
                         (assert (= 0 (rc slot)) () "2c-3: after BOTH readers return, refcount must be 0")
                         (assert (= 1 (dds.xport.zerocopy::%zc-free-count sap)) ()
                                 "2c-3: the slot frees only at the true 0 (after ALL K holders return)")
                         (multiple-value-bind (rs2 rg2) (dds.xport.zerocopy::%zc-loan sap other 0 (length other) 1)
                           (assert (and rs2 (/= rg2 gen)) () "2c-3: the writer re-loan must reclaim the freed slot with a bumped generation")
                           (assert (null (dds.xport.zerocopy::%zc-acquire-for-read sap slot gen)) ()
                                   "2c-3 GEN-GUARD: a stale acquire at the OLD generation must be a validated no-op (NIL)")
                           (assert (null (dds.xport.zerocopy::%zc-release sap slot gen)) ()
                                   "2c-3 GEN-GUARD: a stale release at the OLD generation must be a validated no-op (NIL, never a decrement of the reused slot)")
                           (assert (= 1 (rc slot)) () "2c-3 GEN-GUARD: the reused slot's refcount must be untouched by the stale release")
                           (dds.xport.zerocopy::%zc-release sap slot rg2))))))   ; clean up the re-loan
                 (dds.xport.zerocopy::%zc-destroy sap))
               t)
          (stop-node zn)
          (dds.pal:free-static m)))))

(defun* run-n-reader-2c3-zc-refcount-leak-test ()
    (function () (eql t))
  "WP-DDS-ZC-REFCOUNT-LEAK (ADR 0048 §17.7; MEMORY-SAFETY): the out-of-order-across-join ZC slot refcount LEAK — the
   headline RED->GREEN — plus the NO-UAF / no-under-count + ELIGIBLE>=1 clamp gates. Model-level (a LOCAL 1-slot static
   pool), ONE participant, TWO same-topic ZC-loan-capable readers A,B routed to ONE source writer W. A routed FIRST
   (empty route -> NOT frozen, watermark 0). A marker SN=5 is stored (raising max-stored to 5); THEN B joins -> frozen
   to 5. A LOWER-SN marker SN=3 arrives OUT OF ORDER: B's watermark 5 >= 3 -> B SKIPS it in %drain. The demux bumps by
   (ELIGIBLE-1), ELIGIBLE = {A} (SN=3 > watermark 0; B excluded, SN=3 > 5 false) = 1 -> NO bump -> refcount stays at
   the writer's preset 1. A drains (acquire+release) -> refcount 0 -> the slot is RECLAIMABLE (a writer re-loan reuses
   it). RED (pre-fix, raw route-length K=2): the demux bumped K-1=1 -> refcount 2; A's single release -> 1; B skips
   (never releases) -> refcount STUCK at 1 -> the slot NEVER reclaims -> the pool erodes (a later writer degrades to
   non-ZC). This test drives BOTH bumps on the slot to prove RED->GREEN directly.
   NO-UAF / NO-UNDER-COUNT: ELIGIBLE is the EXACT drain-gate W-term (SN > join-watermark) — unit-checked incl. the
   boundary (SN==watermark -> NOT eligible, matching the strict `>` gate) — and a SUPERSET of the true drainers (it
   omits dr-drained), so every reader that ACTUALLY drains IS counted (A here) -> the refcount never underflows -> a
   drainer's slot is never freed under its read (A's read is asserted refcount-protected). ELIGIBLE>=1 invariant: with
   the never-frozen first reader A present ELIGIBLE >= 1 (unit-checked); with only frozen readers ELIGIBLE=0
   (unit-checked) -> the `(> eligible 1)` demux guard clamps the delta to >= 0 (never a -1 bump). SBCL-only: the ZC
   refcount primitives are cas-sap-u32 (SBCL PAL; NFR-PORT ZC gap on Clasp, ADR 0018). NOT cleared for ship (R6)."
  (if (not (eq (dds.pal:pal-impl-name) :sbcl))
      (progn (format t "~&  [skip] n-reader-2c3-zc-refcount-leak: %zc-bump/%zc-release use cas-sap-u32 (SBCL-only, ADR 0018) — NFR-PORT gap~%") t)
      (let ((m (dds.pal:alloc-static (dds.xport.zerocopy::%zc-bytes 1 64)))
            (pa (make-array 12 :element-type '(unsigned-byte 8) :initial-element #x60))
            (payload (make-array 8 :element-type '(unsigned-byte 8) :initial-contents '(#xA1 #xA2 #xA3 #xA4 #xA5 #xA6 #xA7 #xA8)))
            (other (make-array 8 :element-type '(unsigned-byte 8) :initial-contents '(#x1F #x2F #x3F #x4F #x5F #x6F #x7F #x8F)))
            (zn (make-disc-node :guid-prefix (make-array 12 :element-type '(unsigned-byte 8) :initial-element #x61)
                                :host "127.0.0.1" :port 0)))
        (unwind-protect
             (let ((sap (dds.pal:static-pointer m)))
               (flet ((rc (slot) (dds.pal:load-sap-u32 sap (+ (dds.xport.zerocopy::%zc-slot-off sap slot)
                                                              dds.xport.zerocopy::+zc-slot-off-refcount+))))
                 (dds.xport.zerocopy::%zc-init sap 1 64)
                 (set-zc-loan-capable zn t)
                 (add-local-reader zn :topic "Z2C3L" :type "X") (enable-subscriber zn)
                 (let ((ida (disc-node-user-reader-id zn)))
                   (add-local-reader zn :topic "Z2C3L" :type "X") (enable-subscriber zn)
                   (let ((idb (disc-node-user-reader-id zn))
                         (gw (%source-guid pa #x00000102)))
                     (assert (/= ida idb) () "2c-3 leak: the 2 same-topic ZC readers must get distinct EntityIds")
                     (%reader-route-add zn gw ida)   ; A FIRST: empty route -> NOT frozen (watermark 0)
                     (assert (= 0 (node-reader-join-watermark zn ida gw)) () "2c-3 leak: the first reader (empty route) must NOT be frozen")
                     (%deliver-user-marker zn #x00000102 5 (%make-zc-loan-marker :slot-index 0) pa gw 5)   ; NIL-pool SN=5 -> raises max-stored to 5 (no refcount)
                     (%reader-route-add zn gw idb)   ; B joins: route non-empty -> frozen to max-stored (5)
                     (assert (= 5 (node-reader-join-watermark zn idb gw)) () "2c-3 leak: the joiner B must be frozen to the max stored SN (5)")
                     ;; ELIGIBLE unit checks (caller-holds-lock): the EXACT drain-gate W-term + boundary + the ELIGIBLE>=1 / =0 clamp
                     (dds.pal:with-lock ((disc-node-lock zn))
                       (let ((ids (gethash gw (disc-node-reader-routes zn))))
                         (assert (= 1 (%count-eligible-drainers zn gw 3 ids)) () "2c-3 leak: ELIGIBLE(SN=3)=1 (A only; B frozen@5 excluded — the headline)")
                         (assert (= 2 (%count-eligible-drainers zn gw 7 ids)) () "2c-3 leak: ELIGIBLE(SN=7)=2 (both above watermark — byte-identical to raw K)")
                         (assert (= 1 (%count-eligible-drainers zn gw 5 ids)) () "2c-3 leak: ELIGIBLE(SN=5)=1 (boundary: SN==watermark is NOT eligible — strict `>` drain gate)")
                         (assert (= 0 (%count-eligible-drainers zn gw 3 (list idb))) () "2c-3 leak: ELIGIBLE=0 for an all-frozen route (clamp: the demux guard yields delta 0, never -1)")
                         (assert (>= (%count-eligible-drainers zn gw 3 ids) 1) () "2c-3 leak INVARIANT: ELIGIBLE >= 1 while the never-frozen first reader A is routed")))
                     ;; GREEN: the SN=3 out-of-order marker through the FIXED demux -> ELIGIBLE=1 -> NO bump -> refcount 1
                     (multiple-value-bind (slot gen) (dds.xport.zerocopy::%zc-loan sap payload 0 (length payload) 1)
                       (assert (and slot (= 1 (rc slot))) () "2c-3 leak: the writer loan presets refcount 1")
                       (let ((mk (%make-zc-loan-marker :pool-sap sap :slot-index slot :generation gen :len 64)))
                         (%deliver-user-marker zn #x00000102 3 mk pa gw 3)
                         (assert (= 1 (rc slot)) ()
                                 "2c-3 leak GREEN: the demux must NOT bump for the out-of-order SN=3 (ELIGIBLE=1, B excluded) -> refcount stays 1 (RED raw-K would bump to 2)")
                         (assert (eq mk (node-sample zn (cons gw 3))) () "2c-3 leak: the SN=3 marker must be stored")
                         (assert (zerop (dds.xport.zerocopy::%zc-free-count sap)) () "2c-3 leak: with refcount 1 the slot is NOT yet reclaimable")
                         (multiple-value-bind (sa sl gg ln ba) (dds.xport.zerocopy::%zc-acquire-for-read sap slot gen)
                           (declare (ignore sl gg ln))
                           (assert sa () "2c-3 leak: reader-A must acquire the slot for read")
                           (assert (>= (rc slot) 1) () "2c-3 leak NO-UAF: A's read is refcount-PROTECTED (>=1) — the slot cannot be reclaimed under it")
                           (assert (loop for i below (length payload) always (= (dds.pal:load-sap-u8 sap (+ ba i)) (aref payload i)))
                                   () "2c-3 leak: reader-A must read the CORRECT payload bytes"))
                         (dds.xport.zerocopy::%zc-release sap slot gen)   ; reader-A return-loan (the ONLY drainer)
                         (assert (= 0 (rc slot)) ()
                                 "2c-3 leak GREEN: after A's SINGLE release the refcount reaches EXACTLY 0 (the joiner B added no phantom +1) — LEAK CLOSED")
                         (assert (= 1 (dds.xport.zerocopy::%zc-free-count sap)) () "2c-3 leak GREEN: the slot is now RECLAIMABLE (refcount 0)"))
                       ;; reclaimability: a writer re-loan reuses the freed slot (pre-fix it was stuck at 1 -> pool erosion)
                       (multiple-value-bind (rs rg) (dds.xport.zerocopy::%zc-loan sap other 0 (length other) 1)
                         (assert rs () "2c-3 leak GREEN: a writer re-loan must reclaim the freed slot (the leak would have degraded this to non-ZC)")
                         (dds.xport.zerocopy::%zc-release sap rs rg)))
                     ;; RED contrast on the (now-free) slot: the OLD raw-K bump (K=2 -> +1) leaks under the SAME A-drains/B-skips
                     (multiple-value-bind (slot gen) (dds.xport.zerocopy::%zc-loan sap payload 0 (length payload) 1)
                       (assert (and slot (= 1 (rc slot))) () "2c-3 leak RED: the writer loan presets refcount 1")
                       (dds.xport.zerocopy::%zc-bump sap slot gen 1)   ; the OLD raw-K bump: K-1=1 for route length 2 (counts the frozen joiner)
                       (assert (= 2 (rc slot)) () "2c-3 leak RED: the raw-K bump raises the refcount to 2 (counting the joiner B)")
                       (dds.xport.zerocopy::%zc-release sap slot gen)   ; reader-A releases; B skips -> no second release
                       (assert (= 1 (rc slot)) ()
                               "2c-3 leak RED: A's single release leaves the refcount STUCK at 1 (the joiner's phantom +1) — the LEAK the fix removes")
                       (assert (zerop (dds.xport.zerocopy::%zc-free-count sap)) () "2c-3 leak RED: the leaked slot is NOT reclaimable (refcount 1)")
                       (assert (null (nth-value 0 (dds.xport.zerocopy::%zc-loan sap other 0 (length other) 1))) ()
                               "2c-3 leak RED: the leaked slot blocks a re-loan -> the writer degrades to non-ZC (capacity erosion)"))
                     (dds.xport.zerocopy::%zc-destroy sap))))
               t)
          (stop-node zn)
          (dds.pal:free-static m)))))

(defun* run-n-reader-2c3-secured-purge-defer-test ()
    (function () (eql t))
  "WP-N-ENDPOINT-2C3 (ADR 0048): the SECURED same-topic store-purge-defer (sample-LOSS fix, not a UAF — the secured
   path is memory-safe via independent-struct deserialize). Model-level, mirrors run-n-reader-s4-decode-tier-test (d)
   but on ONE shared (guid,sn) handle drained by K=2 co-located same-topic secured readers (return-count 2). Reader-A's
   early return-loan must NOT purge (guid,sn) nor free the pooled buffer (a not-yet-drained reader-B would otherwise
   LOSE the sample); only reader-B's return (the LAST, count -> 0) purges the store slot + frees the buffer. Clasp
   FIRST (no cas — pool-acquire/release only)."
  (let ((zn (make-disc-node :guid-prefix (make-array 12 :element-type '(unsigned-byte 8) :initial-element #x5E)
                            :host "127.0.0.1" :port 0)))
    (unwind-protect
         (progn
           (enable-subscriber zn)
           (set-secured-loan-capable zn t)
           (let ((pool (%ensure-secured-decode-pool zn)))
             (when pool
               (let ((g (make-array 16 :element-type '(unsigned-byte 8) :initial-element #xC0)))
                 (multiple-value-bind (buf h)
                     (dds.pal:with-lock ((disc-node-decode-pool-lock zn))
                       (values (dds.core.arena:pool-acquire pool) (%secured-handle-acquire zn)))
                   (%secured-handle-fill h buf 4 g 1)
                   (setf (secured-loan-handle-return-count h) 2)   ; K=2 co-located same-topic secured readers share this handle
                   (dds.pal:with-lock ((disc-node-lock zn))
                     (setf (gethash 1 (%inner-table (disc-node-samples zn) g)) h)
                     (%secured-loan-register zn h))
                   (node-return-loan zn h)   ; reader-A returns FIRST -> must DEFER (count 2->1)
                   (assert (secured-loan-handle-buffer h) () "2c-3 secured: reader-A's early return must NOT free the shared buffer (defer)")
                   (assert (>= (secured-loan-handle-reg-index h) 0) () "2c-3 secured: the handle must stay REGISTERED after reader-A's return")
                   (assert (eq h (node-sample zn (cons g 1))) ()
                           "2c-3 secured GATE: (guid,sn) must SURVIVE reader-A's return so reader-B still finds its sample (RED: pre-fix A's return purged it -> B sample-loss)")
                   (assert (= 1 (secured-loan-handle-return-count h)) () "2c-3 secured: the shared-return counter must decrement to 1")
                   (node-return-loan zn h)   ; reader-B returns LAST (count 1->0) -> purge + free
                   (assert (null (secured-loan-handle-buffer h)) () "2c-3 secured: reader-B's return (the last) must free the buffer")
                   (assert (null (node-sample zn (cons g 1))) () "2c-3 secured: (guid,sn) must be purged only after ALL K readers return"))))))
      (stop-node zn)))
  t)

(defun* run-n-reader-2c3-watermark-purge-test ()
    (function () (eql t))
  "WP-N-ENDPOINT-2C3 (ADR 0048/0017): the ZC-joiner high-water is PURGED on unmatch/lease-expiry (alongside the
   reader-route purge, same node-lock section) and RE-FROZEN on re-match — no unbounded growth, no lease-flap
   stale-gate sample-loss. Model-level (both impls; no cas, no pool — watermark arithmetic + route/purge). ONE node,
   TWO same-topic ZC-loan-capable readers. A routed first (empty route -> NOT frozen); 3 markers stored; B joins ->
   frozen to the max stored SN (3). A participant lease-expiry purges the route AND the watermarks (by prefix). Then
   a re-announce where the JOINER B re-matches FIRST (empty route -> not frozen): its watermark must be 0 (drains
   from SN 1), NOT the stale 3. RED (pre-purge): B's stale watermark 3 persists -> B (re-matched first, hence never
   re-frozen) skips SN 1-3 = bounded sample-loss; and the watermarks table would keep the stale entry (growth). Also
   asserts the table is PRUNED to 0 entries on purge."
  (let ((zn (make-disc-node :guid-prefix (make-array 12 :element-type '(unsigned-byte 8) :initial-element #x5F)
                            :host "127.0.0.1" :port 0))
        (pa (make-array 12 :element-type '(unsigned-byte 8) :initial-element #x77)))
    (unwind-protect
         (let ((gw (%source-guid pa #x00000102)))
           (set-zc-loan-capable zn t)
           (add-local-reader zn :topic "Z2C3P" :type "X") (enable-subscriber zn)
           (let ((ida (disc-node-user-reader-id zn)))
             (add-local-reader zn :topic "Z2C3P" :type "X") (enable-subscriber zn)
             (let ((idb (disc-node-user-reader-id zn)))
               (assert (/= ida idb) () "2c-3 purge: the 2 same-topic ZC readers must get distinct EntityIds")
               (%reader-route-add zn gw ida)   ; A first: empty route -> NOT frozen
               (assert (= 0 (node-reader-join-watermark zn ida gw)) () "2c-3 purge: the first reader (empty route) must NOT be frozen")
               (dotimes (i 3)   ; store 3 markers for W (route=[A], K=1)
                 (%deliver-user-marker zn #x00000102 (1+ i) (%make-zc-loan-marker :slot-index (1+ i)) pa gw (1+ i)))
               (%reader-route-add zn gw idb)   ; B joins: route non-empty -> frozen to max-stored (3)
               (assert (= 3 (node-reader-join-watermark zn idb gw)) () "2c-3 purge: the joiner must be frozen to the max stored SN (3)")
               ;; lease-expiry: purge the route + the watermarks (by prefix) under the node lock (as %lease-sweep does)
               (dds.pal:with-lock ((disc-node-lock zn))
                 (%purge-prefix zn pa #'disc-node-reader-routes)
                 (%invalidate-route-cache zn)
                 (%purge-reader-join-watermarks zn pa))
               (assert (= 0 (node-reader-join-watermark zn idb gw)) () "2c-3 purge: the watermark must be PURGED on unmatch/lease-expiry (0)")
               (assert (not (node-reader-matches-writer-p zn idb gw)) () "2c-3 purge: the route must be purged too")
               (assert (zerop (hash-table-count (disc-node-reader-join-watermarks zn))) ()
                       "2c-3 purge: the watermarks table must be PRUNED (no stale-entry accumulation / growth)")
               ;; re-announce with B re-matching FIRST (empty route -> B NOT frozen -> watermark stays the purged 0)
               (%reader-route-add zn gw idb)
               (assert (= 0 (node-reader-join-watermark zn idb gw)) ()
                       "2c-3 purge GATE: after purge, the joiner re-matching FIRST must NOT carry a stale watermark (0 -> drains from SN 1; RED pre-purge: stale 3 -> skips SN 1-3 = sample-loss)")
               (%reader-route-add zn gw ida)   ; A re-joins: route non-empty -> re-frozen to the current max stored SN
               (assert (= 3 (node-reader-join-watermark zn ida gw)) ()
                       "2c-3 purge: a subsequent joiner is RE-FROZEN to the current max stored SN (re-match re-establishes correct gating)"))))
      (stop-node zn)))
  t)

(defun* run-dispose-dataplane-test ()
    (function () (eql t))
  "Full stack over UDP, instance lifecycle S1 (writer side): two participants discover (SPDP) +
   match (SEDP); A publishes a sample, then dispose-instance on a 16-octet key-hash. B receives the
   ALIVE sample, then a no-payload dispose DATA that parse-data-body classifies :dispose carrying
   A's exact key-hash + StatusInfo Disposed (RTPS 2.5 §9.6.4.9). B's instance-state handling is S2;
   here the wire is asserted received + classified. The unregister case is exercised too."
  (let* ((p1 (make-array 12 :element-type '(unsigned-byte 8)
                         :initial-contents '(1 1 1 1 1 1 1 1 1 1 1 1)))
         (p2 (make-array 12 :element-type '(unsigned-byte 8)
                         :initial-contents '(2 2 2 2 2 2 2 2 2 2 2 2)))
         (node1 (make-disc-node :guid-prefix p1 :host "127.0.0.1" :port 0))
         (node2 (make-disc-node :guid-prefix p2 :host "127.0.0.1" :port 0))
         (payload (make-array 8 :element-type '(unsigned-byte 8)
                              :initial-contents '(#xDE #xAD #xBE #xEF #x01 #x02 #x03 #x04)))
         (kh (make-array 16 :element-type '(unsigned-byte 8)
                         :initial-contents '(#xca #xc2 #x17 #xc3 #x18 #x36 #x3f #x8e
                                             #xf1 #x16 #x0e #xee #xde #xf9 #xe8 #x86))))
    (unwind-protect
         (progn
           (add-local-writer node1 :topic "Square" :type "ShapeType"
                                   :reliability dds.rtps.discovery:+reliability-reliable+)
           (enable-publisher node1)
           (add-local-reader node2 :topic "Square" :type "ShapeType"
                                   :reliability dds.rtps.discovery:+reliability-reliable+)
           (enable-subscriber node2)
           (setf (disc-node-peers node1) (list (cons "127.0.0.1" (disc-node-port node2))))
           (setf (disc-node-peers node2) (list (cons "127.0.0.1" (disc-node-port node1))))
           (start-node node1)
           (start-node node2)
           (announce-participant node1)
           (announce-participant node2)
           (loop repeat 100
                 until (and (plusp (disc-node-discovered-count node1))
                            (plusp (disc-node-discovered-count node2)))
                 do (sleep 0.02))
           (announce-endpoints node1)
           (announce-endpoints node2)
           (loop repeat 100
                 until (and (plusp (disc-node-matched-count node1))
                            (plusp (disc-node-matched-count node2)))
                 do (sleep 0.02))
           (assert (and (plusp (disc-node-matched-count node1))
                        (plusp (disc-node-matched-count node2)))
                   () "endpoints did not match before publish")
           (publish-sample node1 payload)              ; SN 1 = ALIVE sample
           (loop repeat 150 until (plusp (node-sample-count node2)) do (sleep 0.02))
           (assert (equalp (node-sample-by-sn node2 1) payload) () "subscriber missed the ALIVE sample")
           (dispose-instance node1 kh)                 ; SN 2 = dispose DATA
           (loop repeat 150 until (node-lifecycle-change-by-sn node2 2) do (sleep 0.02))
           (let ((lc (node-lifecycle-change-by-sn node2 2)))
             (assert lc () "subscriber never received the dispose DATA over UDP")
             (assert (eq (first lc) :dispose) () "dispose DATA not classified :dispose")
             (assert (equalp (second lc) kh) () "dispose DATA carried the wrong key-hash")
             (assert (= (third lc) dds.rtps.message:+statusinfo-disposed+) ()
                     "dispose DATA carried the wrong StatusInfo flags"))
           (unregister-instance node1 kh)              ; SN 3 = unregister DATA
           (loop repeat 150 until (node-lifecycle-change-by-sn node2 3) do (sleep 0.02))
           (let ((lc (node-lifecycle-change-by-sn node2 3)))
             (assert lc () "subscriber never received the unregister DATA over UDP")
             (assert (eq (first lc) :unregister) () "unregister DATA not classified :unregister"))
           t)
      (stop-node node1)
      (stop-node node2))))

(defun* run-dispose-repair-test ()
    (function () (eql t))
  "Reliability of a lifecycle change S1: A's dispose DATA is dropped on send
   (*debug-drop-sample-numbers* on its SN), then the drop is cleared with NO further write; A's
   periodic HEARTBEAT prompts B to NACK the gap, A resends the dispose via write-data-dispose, B
   recovers — asserted within a BOUNDED number of iterations. Proves a dispose/unregister occupies a
   real SN and rides the same ACKNACK/HEARTBEAT repair path as an ALIVE DATA (RTPS 2.5 §8.4.2.2)."
  (let* ((p1 (make-array 12 :element-type '(unsigned-byte 8)
                         :initial-contents '(1 1 1 1 1 1 1 1 1 1 1 1)))
         (p2 (make-array 12 :element-type '(unsigned-byte 8)
                         :initial-contents '(2 2 2 2 2 2 2 2 2 2 2 2)))
         (node1 (make-disc-node :guid-prefix p1 :host "127.0.0.1" :port 0))
         (node2 (make-disc-node :guid-prefix p2 :host "127.0.0.1" :port 0))
         (payload (make-array 8 :element-type '(unsigned-byte 8)
                              :initial-contents '(#xCA #xFE #xBA #xBE #x05 #x06 #x07 #x08)))
         (kh (make-array 16 :element-type '(unsigned-byte 8)
                         :initial-contents '(#xca #xc2 #x17 #xc3 #x18 #x36 #x3f #x8e
                                             #xf1 #x16 #x0e #xee #xde #xf9 #xe8 #x86))))
    (unwind-protect
         (progn
           (add-local-writer node1 :topic "Square" :type "ShapeType"
                                   :reliability dds.rtps.discovery:+reliability-reliable+)
           (enable-publisher node1)
           (add-local-reader node2 :topic "Square" :type "ShapeType"
                                   :reliability dds.rtps.discovery:+reliability-reliable+)
           (enable-subscriber node2)
           (setf (disc-node-peers node1) (list (cons "127.0.0.1" (disc-node-port node2))))
           (setf (disc-node-peers node2) (list (cons "127.0.0.1" (disc-node-port node1))))
           (start-node node1)
           (start-node node2)
           (announce-participant node1)
           (announce-participant node2)
           (loop repeat 100
                 until (and (plusp (disc-node-discovered-count node1))
                            (plusp (disc-node-discovered-count node2)))
                 do (sleep 0.02))
           (announce-endpoints node1)
           (announce-endpoints node2)
           (loop repeat 100
                 until (and (plusp (disc-node-matched-count node1))
                            (plusp (disc-node-matched-count node2)))
                 do (sleep 0.02))
           (assert (and (plusp (disc-node-matched-count node1))
                        (plusp (disc-node-matched-count node2)))
                   () "endpoints did not match before publish")
           (publish-sample node1 payload)             ; SN 1 ALIVE sample
           (loop repeat 100 until (plusp (node-sample-count node2)) do (sleep 0.02))
           (assert (plusp (node-sample-count node2)) () "ALIVE sample never arrived")
           (setf *debug-drop-sample-numbers* (list 2))  ; drop the dispose DATA (SN 2) on every thread
           (dispose-instance node1 kh)
           (sleep 0.1)
           (assert (null (node-lifecycle-change-by-sn node2 2)) ()
                   "drop hook failed: B received the dropped dispose DATA")
           (setf *debug-drop-sample-numbers* nil)        ; clear; do NOT dispose again
           (loop repeat 40                               ; BOUNDED: drive A's HB cadence
                 until (node-lifecycle-change-by-sn node2 2)
                 do (announce-endpoints node1) (sleep 0.02))
           (let ((lc (node-lifecycle-change-by-sn node2 2)))
             (assert lc () "lost dispose never recovered via the periodic HEARTBEAT")
             (assert (and (eq (first lc) :dispose) (equalp (second lc) kh)) ()
                     "recovered dispose has the wrong kind/key-hash"))
           t)
      (setf *debug-drop-sample-numbers* nil)
      (stop-node node1)
      (stop-node node2))))

(defun* run-large-dataplane-test ()
    (function () (eql t))
  "Full stack over UDP with a sample LARGER than *fragment-size*: two participants discover
   (SPDP) and match (SEDP), then the publisher sends a 4000-octet user sample. The writer
   fragments it into DATA_FRAG submessages + a HEARTBEAT_FRAG; the subscriber reassembles it
   and delivers a byte-exact copy. Proves send-side fragmentation + receive-side reassembly +
   NACK_FRAG recovery over real UDP loopback (RTPS 2.5 §9.4.5.5)."
  (let* ((p1 (make-array 12 :element-type '(unsigned-byte 8)
                         :initial-contents '(1 1 1 1 1 1 1 1 1 1 1 1)))
         (p2 (make-array 12 :element-type '(unsigned-byte 8)
                         :initial-contents '(2 2 2 2 2 2 2 2 2 2 2 2)))
         (node1 (make-disc-node :guid-prefix p1 :host "127.0.0.1" :port 0))
         (node2 (make-disc-node :guid-prefix p2 :host "127.0.0.1" :port 0))
         (payload (make-array 4000 :element-type '(unsigned-byte 8))))
    (dotimes (i 4000) (setf (aref payload i) (logand (* i 7) #xff)))
    (unwind-protect
         (progn
           (add-local-writer node1 :topic "Square" :type "ShapeType"
                                   :reliability dds.rtps.discovery:+reliability-reliable+)
           (enable-publisher node1)
           (add-local-reader node2 :topic "Square" :type "ShapeType"
                                   :reliability dds.rtps.discovery:+reliability-reliable+)
           (enable-subscriber node2)
           (setf (disc-node-peers node1) (list (cons "127.0.0.1" (disc-node-port node2))))
           (setf (disc-node-peers node2) (list (cons "127.0.0.1" (disc-node-port node1))))
           (start-node node1)
           (start-node node2)
           (announce-participant node1)
           (announce-participant node2)
           (loop repeat 100
                 until (and (plusp (disc-node-discovered-count node1))
                            (plusp (disc-node-discovered-count node2)))
                 do (sleep 0.02))
           (announce-endpoints node1)
           (announce-endpoints node2)
           (loop repeat 100
                 until (and (plusp (disc-node-matched-count node1))
                            (plusp (disc-node-matched-count node2)))
                 do (sleep 0.02))
           (assert (and (plusp (disc-node-matched-count node1))
                        (plusp (disc-node-matched-count node2)))
                   () "endpoints did not match before publish")
           (publish-sample node1 payload)
           (loop repeat 150 until (plusp (node-sample-count node2)) do (sleep 0.02))
           (assert (plusp (node-sample-count node2)) ()
                   "subscriber never received the fragmented sample over UDP")
           (assert (equalp (node-sample-by-sn node2 1) payload) ()
                   "subscriber received the wrong reassembled payload bytes")
           t)
      (stop-node node1)
      (stop-node node2))))

(defun* run-lost-final-sample-test ()
    (function () (eql t))
  "Reliability edge: a reliable writer's FINAL sample's DATA is lost and there is no
   subsequent write, so nothing re-prompts the reader to NACK — only the periodic
   standalone HEARTBEAT keeps reliability live and triggers recovery (RTPS 2.5
   §8.4.2.2: a reliable Writer must periodically inform each matching reliable Reader
   of the availability of a sample). Two participants discover (SPDP) + match (SEDP);
   *debug-drop-sample-numbers* drops the ONE published sample's DATA on send; the drop
   is then cleared but NO further sample is published; A's announce cadence then emits
   the periodic non-final HEARTBEAT, B NACKs the gap, A resends, B recovers — asserted
   within a BOUNDED number of iterations (no unbounded wait)."
  (let* ((p1 (make-array 12 :element-type '(unsigned-byte 8)
                         :initial-contents '(1 1 1 1 1 1 1 1 1 1 1 1)))
         (p2 (make-array 12 :element-type '(unsigned-byte 8)
                         :initial-contents '(2 2 2 2 2 2 2 2 2 2 2 2)))
         (node1 (make-disc-node :guid-prefix p1 :host "127.0.0.1" :port 0))
         (node2 (make-disc-node :guid-prefix p2 :host "127.0.0.1" :port 0))
         (payload (make-array 8 :element-type '(unsigned-byte 8)
                              :initial-contents '(#xCA #xFE #xBA #xBE #x05 #x06 #x07 #x08))))
    (unwind-protect
         (progn
           (add-local-writer node1 :topic "Square" :type "ShapeType"
                                   :reliability dds.rtps.discovery:+reliability-reliable+)
           (enable-publisher node1)
           (add-local-reader node2 :topic "Square" :type "ShapeType"
                                   :reliability dds.rtps.discovery:+reliability-reliable+)
           (enable-subscriber node2)
           (setf (disc-node-peers node1) (list (cons "127.0.0.1" (disc-node-port node2))))
           (setf (disc-node-peers node2) (list (cons "127.0.0.1" (disc-node-port node1))))
           (start-node node1)
           (start-node node2)
           (announce-participant node1)
           (announce-participant node2)
           (loop repeat 100
                 until (and (plusp (disc-node-discovered-count node1))
                            (plusp (disc-node-discovered-count node2)))
                 do (sleep 0.02))
           (announce-endpoints node1)
           (announce-endpoints node2)
           (loop repeat 100
                 until (and (plusp (disc-node-matched-count node1))
                            (plusp (disc-node-matched-count node2)))
                 do (sleep 0.02))
           (assert (and (plusp (disc-node-matched-count node1))
                        (plusp (disc-node-matched-count node2)))
                   () "endpoints did not match before publish")
           (setf *debug-drop-sample-numbers* (list 1))     ; drop on EVERY thread (incl. resend)
           (publish-sample node1 payload)                  ; DATA dropped; HEARTBEAT prompts NACK
           (sleep 0.1)                                     ; NACK-resend also dropped -> still gone
           (assert (zerop (node-sample-count node2)) ()
                   "drop hook failed: B received the dropped sample's DATA")
           (setf *debug-drop-sample-numbers* nil)          ; clear; do NOT publish again
           (loop repeat 40                                 ; BOUNDED: drive A's HB cadence
                 until (plusp (node-sample-count node2))
                 do (announce-endpoints node1) (sleep 0.02))
           (assert (plusp (node-sample-count node2)) ()
                   "lost final sample never recovered via the periodic HEARTBEAT")
           (assert (equalp (node-sample-by-sn node2 1) payload) ()
                   "recovered sample has the wrong payload bytes")
           t)
      (setf *debug-drop-sample-numbers* nil)
      (stop-node node1)
      (stop-node node2))))

(defun* run-locator-filter-test ()
    (function () (eql t))
  "Locator-list selection + foreign-participant robustness (regression for the
   EHOSTUNREACH crash vs RTI DDSSpy, which advertises several locators incl.
   0.0.0.0): %usable-destination (1) picks a routable default-unicast locator,
   skipping a 0.0.0.0 entry; (2) falls back to a routable metatraffic ADDRESS + a
   default-unicast PORT when every default-unicast locator is non-routable; (3)
   yields NIL when nothing is routable; (4) a UDP send to 0.0.0.0 is non-fatal."
  (flet ((loc (a b c d port)
           (dds.rtps.discovery:make-locator
            :kind dds.rtps.discovery:+locator-kind-udpv4+ :port port
            :address (dds.rtps.discovery:make-ipv4-locator
                      (make-array 4 :element-type '(unsigned-byte 8)
                                  :initial-contents (list a b c d)))))
         (sd (du mt)
           (dds.rtps.discovery:make-spdp-data :default-unicast-locators du
                                              :metatraffic-unicast-locators mt)))
    (assert (equal (%usable-destination (sd (list (loc 0 0 0 0 7411) (loc 192 168 1 7 7411)) '()))
                   '("192.168.1.7" . 7411))
            () "must pick the routable default-unicast locator, skipping 0.0.0.0")
    (assert (equal (%usable-destination (sd (list (loc 0 0 0 0 7411)) (list (loc 192 168 1 7 7410))))
                   '("192.168.1.7" . 7411))
            () "must fall back to metatraffic address + default-unicast port")
    (assert (null (%usable-destination (sd (list (loc 0 0 0 0 7411)) (list (loc 0 0 0 0 7410)))))
            () "all-0.0.0.0 must yield NIL, not a bad destination")
    (multiple-value-bind (tr sock) (dds.xport.udp:make-udp-transport :host "127.0.0.1" :port 0)
      (unwind-protect
           (let ((buf (dds.core.buffer:make-octet-buffer 16)))
             (dds.xport:send tr (dds.xport.udp:make-udp-locator :host "0.0.0.0" :port 7411) buf 0 1)
             (dds.pal:free-static (dds.core.buffer:octet-buffer-vec buf)))
        (dds.pal:udp-close sock)))
    t))
