(in-package #:dds.durability)

;;; SQLite-backed durable-store (WP-DURABILITY-SQLITE, ADR 0049). Implements the FIXED durable-store
;;; vtable (store.lisp:18-32) UNCHANGED — a pluggable backend selected via the store-factory seam,
;;; identical to make-file-store. Stores OPAQUE payload bytes; DARE at-rest is layered by the
;;; make-encrypted-store decorator (this backend has ZERO crypto knowledge).
;;;
;;; Schema (one row per retained sample, keyed by (topic, writer-guid, sn)):
;;;   CREATE TABLE record (topic TEXT, writer_guid BLOB, sn BLOB, key_hash BLOB, kind INTEGER,
;;;                        payload BLOB, PRIMARY KEY (topic, writer_guid, sn));
;;; SN is stored as an 8-byte BIG-ENDIAN BLOB: SQLite INTEGER is SIGNED 64-bit and the file/memory
;;; stores impose NO SN bound, so a signed INTEGER would sort a real DDS SN past 2^63 as negative
;;; (silent reorder — a durability defect). A big-endian 8-byte BLOB is lexicographic == numeric u64
;;; order with the FULL unsigned range and no bound, matching the no-limit file-store contract.
;;; get-range still sorts in Lisp via the shared %record-guid-sn< (store.lisp:185) so the ordering is
;;; BYTE-EXACT identical to the memory + file backends regardless of SQL collation (DRY, one order).

;;; u64 <-> 8-byte big-endian blob (lexicographic blob order == numeric u64 order, no bound).

(defun* %sn->be8 (sn)
    (function ((integer 0)) (simple-array (unsigned-byte 8) (8)))
  "Encode SN as an 8-byte big-endian octet vector (most-significant byte first)."
  (let ((v (make-array 8 :element-type '(unsigned-byte 8))))
    (dotimes (i 8 v)
      (setf (aref v i) (ldb (byte 8 (* 8 (- 7 i))) sn)))))

(defun* %be8->sn (blob)
    (function ((array (unsigned-byte 8) (*))) (integer 0))
  "Decode an 8-byte big-endian octet vector back to an unsigned integer."
  (let ((v 0))
    (dotimes (i 8 v)
      (setf v (logior (ash v 8) (aref blob i))))))

(defun* %to-octets-n (blob n)
    (function ((array (unsigned-byte 8) (*)) (integer 0)) (simple-array (unsigned-byte 8) (*)))
  "Copy BLOB into a fresh simple (unsigned-byte 8) vector of length N (normalizes SQLite's blob type)."
  (let ((v (make-array n :element-type '(unsigned-byte 8))))
    (replace v blob)
    v))

(defun* %sqlite-row->record (topic wg-blob sn-blob kh-blob kind-int pl-blob)
    (function (string (array (unsigned-byte 8) (*)) (array (unsigned-byte 8) (*))
               (or null (array (unsigned-byte 8) (*))) (unsigned-byte 8) (array (unsigned-byte 8) (*)))
              durable-record)
  "Build a DURABLE-RECORD from one raw SQLite row, normalizing blobs to simple octet vectors."
  (let ((kind (%int->kind kind-int)))
    (unless kind
      ;; A row kind outside {0,1,2} cannot arise from our own writes — it is DB corruption / tamper. The kind
      ;; byte is authenticated INSIDE the per-row v3 MAC chain (ADR 0045), so in the production DARE-wrapped tier
      ;; a corrupted kind fails the open-time chain verify (%sqlite-verify-topic, the sibling refusals below) at
      ;; the durability start boundary (runner-start) BEFORE any get-range reads it; file-store frame-contract parity.
      (error "dds.durability: SQLite record with unassigned kind ~d (topic ~a)" kind-int topic))   ; NOCOND(SECURITY-FAILCLOSED): DB corruption/tamper refusal, fail-closed at store-open, caught at the durability start boundary
    (make-durable-record
     :topic       topic
     :writer-guid (%to-octets-n wg-blob 16)
     :sn          (%be8->sn sn-blob)
     :key-hash    (when kh-blob (%to-octets-n kh-blob 16))
     :kind        kind
     :payload     (%to-octets-n pl-blob (length pl-blob)))))

;;; Per-row keyed-MAC tamper-evidence chain (ADR 0045 parity). The MAC over a row is BYTE-IDENTICAL
;;; to the file store: reuse %frame-record-versioned to build the canonical v3 frame and take its
;;; 32-byte chain MAC. The chain order is the explicit chain_seq column (stable vs rowid reuse after a
;;; compacting DELETE), NOT rowid. Verify runs BEFORE compaction (fail-closed); after any compacting
;;; DELETE the surviving rows are re-MAC'd as a fresh chain so a clean KEEP_LAST store never
;;; false-rejects on the next reopen (mirrors %rewrite-topic-log).

(defun* %sqlite-row-mac (fn prev topic wg-blob sn-blob kh-blob kind-int pl-blob)
    (function (function (simple-array (unsigned-byte 8) (*)) string
               (array (unsigned-byte 8) (*)) (array (unsigned-byte 8) (*))
               (or null (array (unsigned-byte 8) (*))) (unsigned-byte 8) (array (unsigned-byte 8) (*)))
              (simple-array (unsigned-byte 8) (*)))
  "The v3 chain MAC of one row chained over PREV: byte-identical to the file store — reuse
   %frame-record-versioned to produce the canonical v3 frame and take its 32-byte MAC (ADR 0045)."
  (let ((rec (%sqlite-row->record topic wg-blob sn-blob kh-blob kind-int pl-blob)))
    (nth-value 1 (%frame-record-versioned rec +frame-version-v3+ prev fn))))

(defun* %sqlite-chain-walk (db topic fn stop-at)
    (function (t string function (or null (integer 0)))
              (values (integer 0) (simple-array (unsigned-byte 8) (*))
                      (member :reached :clean :break :mismatch) (integer 0)))
  "READ-ONLY walk of TOPIC's per-row v3 MAC chain in chain_seq order under oracle FN — the shared engine
   of BOTH the open-time verifier (%sqlite-verify-topic) AND the sealed high-water tail-anchor seam
   (store-chain-tails / store-verify-chain-prefix), the SQLite analogue of the file store's %chain-walk
   (ADR 0045 §7.1). Seeds from the per-topic keyed head, recomputes each non-NULL-mac row's expected MAC
   over (running ∥ canonical frame prefix), and counts ONLY chained rows (a NULL-mac legacy/pre-chain
   prefix is walked over without counting; a NULL-mac row AFTER a chained row is a break). UNLIKE
   %sqlite-verify-topic it NEVER signals — it RETURNS a reason so each caller applies its own policy.
   Returns (values chained running reason nrows):
     STOP-AT non-NIL and reached ⇒ :reached, RUNNING = the running chain MAC after exactly STOP-AT chained
       rows (the tail anchor's prefix-containment probe; rows past STOP-AT are ignored);
     else runs to the natural end — :clean (chained < STOP-AT if any) / :break (an unchained row after a
       chained row) / :mismatch (a stored mac ≠ the recomputed mac). NROWS = rows examined (downgrade check).
   The tail-anchor SEAL (STOP-AT NIL → chained + tail-MAC) and the prefix-containment VERIFY (STOP-AT N)
   share this ONE walk, so their counting + MAC computation are byte-identical (no drift)."
  (let ((rows (sqlite:execute-to-list
               db
               "SELECT writer_guid, sn, key_hash, kind, payload, mac FROM record WHERE topic=? ORDER BY chain_seq ASC, rowid ASC"
               topic))
        (running (%chain-seed fn topic))
        (started nil)
        (chained 0)
        (nrows   0))
    (dolist (row rows)
      (when (and stop-at (>= chained stop-at))
        (return-from %sqlite-chain-walk (values chained running :reached nrows)))  ; committed prefix reached
      (incf nrows)
      (destructuring-bind (wg sn-blob kh kind-int pl mac) row
        (if (null mac)
            (when started
              (return-from %sqlite-chain-walk (values chained running :break nrows)))  ; unchained-after-chained
            (let ((expected (%sqlite-row-mac fn running topic wg sn-blob kh kind-int pl))
                  (stored   (%to-octets-n mac +frame-mac-len+)))
              (unless (equalp expected stored)
                (return-from %sqlite-chain-walk (values chained running :mismatch nrows)))  ; stored ≠ recomputed
              (setf running expected started t)
              (incf chained)))))
    (if (and stop-at (>= chained stop-at))
        (values chained running :reached nrows)                     ; prefix reached exactly at the last row
        (values chained running :clean nrows))))                    ; natural end (chained < STOP-AT if any)

(defun* %sqlite-verify-topic (db topic fn required grandfather)
    (function (t string function t (or null hash-table))
              (or null (simple-array (unsigned-byte 8) (*))))
  "Verify TOPIC's per-row MAC chain in chain_seq order and return the tail MAC (or NIL). Delegates the walk
   to the shared %sqlite-chain-walk (DRY — the SAME engine the tail-anchor seam uses) and applies the
   fail-closed policy: a :break (a NULL-mac/unchained row after a chained row) or :mismatch (a stored mac ≠
   the recomputed mac) SIGNALS (tamper — refusing to open). A NULL-mac row is a legacy/pre-chain prefix row,
   legal ONLY before the chain starts. Downgrade defense (ADR 0045 §3.2): when REQUIRED, a non-empty topic
   that walks to ZERO chained rows on a NON-grandfathered topic SIGNALS (a full v3->v2 keyless downgrade)."
  (multiple-value-bind (chained running reason nrows) (%sqlite-chain-walk db topic fn nil)
    (case reason
      (:break
       ;; NOCOND(SECURITY-FAILCLOSED): SQLite MAC chain break (tamper); fail-closed at store-open, caught at the durability start boundary
       (error "dds.durability: SQLite MAC chain break in topic ~a — unchained row after a ~
               chained row (tamper — refusing to open; ADR 0045)" topic))
      (:mismatch
       ;; NOCOND(SECURITY-FAILCLOSED): SQLite chain MAC mismatch (tamper); fail-closed at store-open, caught at the durability start boundary
       (error "dds.durability: SQLite chain MAC mismatch in topic ~a ~
               (tamper — refusing to open; ADR 0045)" topic)))
    (when (and required (plusp nrows) (zerop chained)
               (not (and grandfather (gethash (%topic->id topic) grandfather))))
      ;; NOCOND(SECURITY-FAILCLOSED): SQLite v3->v2 downgrade (tamper); fail-closed at store-open, caught at the durability start boundary
      (error "dds.durability: SQLite chain-required topic ~a has ~d row(s) but ZERO chained rows — ~
              refusing to open (full v3->v2 downgrade / tamper; ADR 0045 §3.2)" topic nrows))
    (and (plusp chained) running)))

(defun* %sqlite-recompute-topic (db topic fn)
    (function (t string function) (or null (simple-array (unsigned-byte 8) (*))))
  "Re-MAC every surviving row of TOPIC as a FRESH v3 chain in chain_seq order and rewrite its mac +
   dense chain_seq columns; return the new tail MAC. Called after a compacting DELETE so the surviving
   rows' chain is continuous — a KEEP_LAST store must reopen clean any number of times (ADR 0045; the
   no-false-reject invariant, mirroring the file store's %rewrite-topic-log post-compaction)."
  (let ((rows (sqlite:execute-to-list
               db
               "SELECT writer_guid, sn, key_hash, kind, payload FROM record WHERE topic=? ORDER BY chain_seq ASC, rowid ASC"
               topic))
        (running (%chain-seed fn topic))
        (seq  0)
        (tail nil))
    (dolist (row rows)
      (destructuring-bind (wg sn-blob kh kind-int pl) row
        (let ((mac (%sqlite-row-mac fn running topic wg sn-blob kh kind-int pl)))
          (sqlite:execute-non-query
           db
           "UPDATE record SET mac=?, chain_seq=? WHERE topic=? AND writer_guid=? AND sn=?"
           mac seq topic wg sn-blob)
          (setf running mac tail mac)
          (incf seq))))
    tail))

(defparameter *durability-debug-compact-fault* nil
  "Test-only fault injector (ADR 0049 §10 crash-consistency). NIL (default) = inert; byte-identical
   behavior. When non-NIL, the SQLite compaction paths signal an error AFTER the compacting DELETE(s)
   but BEFORE the survivor chain re-MAC, INSIDE the wrapping transaction — so the rollback path
   (a crash between the DELETE and the recompute) is exercised. Never set in production code.")

(defun* %sqlite-evict-instance (db topic key-hash depth)
    (function (t string (simple-array (unsigned-byte 8) (16)) (integer 1)) (integer 0))
  "Online KEEP_LAST eviction on put (ADR 0029, ADR 0049 §7, DDS 1.4 §2.2.3.5): DELETE the lowest
   (writer-guid, sn) :data rows of the instance KEY-HASH in TOPIC until at most DEPTH :data rows remain;
   return the number of rows deleted (0 when nothing was superseded). Same KEEP_LAST intent as the memory
   store's %mem-evict-instance: only :data rows for a non-NIL key-hash are evicted, lifecycle
   (:dispose/:unregister) rows are never touched. The drop-candidate order matches the FILE store's
   %compact-topic-records pass 2 — the shared %record-guid-sn< (writer-guid, then sn); the memory store
   evicts by PURE sn (ignoring guid) and diverges ONLY for a single instance fed by multiple writer GUIDs
   (the SQLite/file order is the self-consistent one — it matches get-range's ordering). Bounded by the
   instance's own :data-row count (a continuously-evicted KEEP_LAST instance holds at most DEPTH+1 rows at
   put time), never a whole-topic scan. Reuses the on-open compaction DELETE (store-sqlite.lisp) — DRY.
   The CALLER wraps this DELETE plus the survivor re-MAC in a single transaction (crash-atomic; ADR 0049 §10)."
  (let ((rows (sqlite:execute-to-list
               db
               "SELECT writer_guid, sn FROM record WHERE topic=? AND key_hash=? AND kind=?"
               topic key-hash (%kind->int :data))))
    (if (<= (length rows) depth)
        0
        (let* ((recs    (mapcar (lambda (row)
                                  (make-durable-record :writer-guid (%to-octets-n (first row) 16)
                                                       :sn (%be8->sn (second row))))
                                rows))
               (sorted  (sort recs #'%record-guid-sn<))
               (to-drop (subseq sorted 0 (- (length sorted) depth))))
          (dolist (r to-drop)
            (sqlite:execute-non-query
             db
             "DELETE FROM record WHERE topic=? AND writer_guid=? AND sn=?"
             topic (durable-record-writer-guid r) (%sn->be8 (durable-record-sn r))))
          (length to-drop)))))

;;; SQL text — pinned once (DRY; no ad-hoc string building on the hot loop).

(defparameter %sqlite-ddl-table
  "CREATE TABLE IF NOT EXISTS record (topic TEXT NOT NULL, writer_guid BLOB NOT NULL, sn BLOB NOT NULL, key_hash BLOB, kind INTEGER NOT NULL, payload BLOB NOT NULL, mac BLOB, chain_seq INTEGER, PRIMARY KEY (topic, writer_guid, sn))"
  "DDL for the durable-record table (ADR 0049). SN is an 8-byte big-endian BLOB (full u64, no bound).
   mac = per-row v3 keyed HMAC chain MAC (32 octets, NULL for pre-chain/legacy rows; ADR 0045).
   chain_seq = explicit per-topic chain order (NULL for unchained rows; stable vs rowid-reuse-after-DELETE).")

(defparameter %sqlite-ddl-index
  "CREATE INDEX IF NOT EXISTS idx_topic_order ON record(topic, writer_guid, sn)"
  "DDL for the per-topic (writer_guid, sn) ordering/lookup index (ADR 0049).")

(defun* %sqlite-open-db (path)
    (function ((or pathname string)) t)
  "Connect to the SQLite DB at PATH, set WAL journaling + FULL synchronous (durability barrier,
   off the per-sample hot path), and ensure the schema. Returns the connection handle."
  (let ((db (sqlite:connect (namestring path))))
    (sqlite:execute-non-query db "PRAGMA journal_mode=WAL")
    (sqlite:execute-non-query db "PRAGMA synchronous=FULL")
    (sqlite:execute-non-query db %sqlite-ddl-table)
    ;; migrate a pre-chain (WP-DURABILITY-SQLITE) DB: add the v3 mac/chain_seq columns idempotently
    ;; (a duplicate-column error on an already-migrated/fresh DB is the expected no-op; ADR 0045)
    (ignore-errors (sqlite:execute-non-query db "ALTER TABLE record ADD COLUMN mac BLOB"))
    (ignore-errors (sqlite:execute-non-query db "ALTER TABLE record ADD COLUMN chain_seq INTEGER"))
    (sqlite:execute-non-query db %sqlite-ddl-index)
    db))

(defun* make-sqlite-store (&key path (max-samples 0)
                                (history-kind :keep-all) (history-depth 1))
    (function (&key (:path (or null pathname string)) (:max-samples (integer 0))
                    (:history-kind (member :keep-all :keep-last)) (:history-depth (integer 1)))
              (values (or null durable-store) (or null keyword)))
  "Construct a SQLite-backed durable-store implementing the fixed durable-store vtable (ADR 0049).
   PATH is the DB file (required). MAX-SAMPLES 0 = unbounded; positive caps total records across all
   topics (store-put returns :REJECTED when full). HISTORY-KIND / HISTORY-DEPTH govern per-instance
   compaction (DDS 1.4 §2.2.3.5): :keep-all (default) drops only settled instances; :keep-last with
   DEPTH >= 1 additionally keeps only the newest DEPTH :data records per non-NIL-key-hash instance,
   evicted BOTH online on each put (ADR 0049 §7 — a continuously-open store stays bounded without a
   reopen) AND on compaction-on-open (restart recovery). After an online eviction the surviving rows'
   keyed MAC chain is recomputed (ADR 0045) so the next reopen verifies clean (no false-reject).
   Stores OPAQUE payload bytes (DARE-unaware); wrap with make-encrypted-store for at-rest sealing.
   store-open (re)establishes the connection — a fresh store on an existing PATH replays all prior rows
   (restart recovery). The keyed per-row MAC chain seam (store-set-chain-mac-fn, ADR 0045) is LIVE:
   when the encrypted decorator installs the log-MAC oracle each put writes a v3 chain MAC (byte-
   identical to the file store) into the mac column and verify-on-open (before compaction) fail-closes
   on any tamper; a NIL-oracle bare store writes NULL mac columns = byte-behaviorally unchanged.
   The sealed high-water tail-anchor seam (store-chain-tails / store-verify-chain-prefix, ADR 0045 §7.1)
   is ALSO filled: at the encrypted decorator's clean close the per-topic (chained-count N . tail-MAC M_N)
   is sealed into D/logmac.tail, and at open prefix-containment closes the whole-tail-truncation /
   whole-topic-drop / whole-store-rollback residuals for the SQLite tier — reusing the SAME
   %sqlite-chain-walk as verify-on-open (no new crypto; the (N . M_N) contract matches the file tier).
   Returns (VALUES STORE STATUS): STATUS is NIL on success, or :REQUIRES-PATH when :PATH was omitted
   (ADR 0064: a construction precondition returns a status here instead of a deferred unwind on first use)."
  (unless path
    (bail :requires-path))
  (let* ((db-path (when path (pathname path)))
         (lock    (dds.pal:make-lock "dds-sqlite-store"))
         (db-cell (list nil))                 ; car = live connection or NIL when closed
         ;; mutable policy cells (factory defaults; store-open overrides car when non-NIL)
         (hk-cell   (cons history-kind nil))
         (depth-cell (cons history-depth nil))
         ;; keyed log-MAC chain (ADR 0045): oracle closure + downgrade flag + grandfather set, all
         ;; installed by the encrypted decorator via store-set-chain-mac-fn; NIL = bare store (no MAC).
         (cmf-cell  (list nil))               ; car = HMAC oracle (data)->HMAC-SHA-256, or NIL
         (req-cell  (list nil))               ; car = chain-REQUIRED (downgrade defense)
         (gf-cell   (list nil))               ; car = grandfather-set hash-table (topic-ids) or NIL
         (chain-macs (make-hash-table :test #'equal))) ; topic -> running chain MAC (32 octets)
    (flet ((%total ()
             (sqlite:execute-single (car db-cell) "SELECT COUNT(*) FROM record")))
      (labels ((%ensure-db ()
                 (unless (car db-cell)
                   ;; db-path is guaranteed non-NIL: make-sqlite-store bails :requires-path up front (ADR 0064)
                   (let ((dir (uiop:pathname-directory-pathname db-path)))
                     (let ((existed (uiop:directory-exists-p dir)))
                       (ensure-directories-exist db-path)
                       (unless existed
                         (dds.dare:enforce-directory-perms-0700 dir))
                       (dds.dare:assert-directory-perms-0700 dir)))
                   (setf (car db-cell) (%sqlite-open-db db-path)))
                 (car db-cell))
               (%topic-records-in-order (topic)
                 ;; append (insert) order via rowid — %compact-topic-records is order-sensitive
                 (mapcar (lambda (row)
                           (%sqlite-row->record topic (first row) (second row) (third row)
                                                (fourth row) (fifth row)))
                         (sqlite:execute-to-list
                          (car db-cell)
                          "SELECT writer_guid, sn, key_hash, kind, payload FROM record WHERE topic=? ORDER BY rowid"
                          topic)))
               (%verify-chains ()
                 ;; verify EVERY topic's MAC chain BEFORE compaction (fail-closed) so a tampered
                 ;; store cannot be laundered by the compacting DELETE; seed the running-MAC state
                 ;; (chain-macs) from each verified tail so subsequent puts continue the chain (ADR 0045).
                 (clrhash chain-macs)
                 (dolist (topic (sqlite:execute-to-list (car db-cell) "SELECT DISTINCT topic FROM record"))
                   (let ((tail (%sqlite-verify-topic (car db-cell) (first topic)
                                                     (car cmf-cell) (car req-cell) (car gf-cell))))
                     (when tail (setf (gethash (first topic) chain-macs) tail)))))
               (%compact-on-open (eff-hk eff-hd)
                 ;; compaction-on-open (DDS 1.4 §2.2.3.5): run the SHARED %compact-topic-records per
                 ;; topic (identical to the file store) and DELETE any dropped rows. Cheap (durability
                 ;; is off the wire hot path); :keep-all drops settled instances, :keep-last also caps.
                 (dolist (topic (sqlite:execute-to-list (car db-cell) "SELECT DISTINCT topic FROM record"))
                   (let* ((tn   (first topic))
                          (recs (%topic-records-in-order tn))
                          (kept (%compact-topic-records recs eff-hk eff-hd)))
                     (when (< (length kept) (length recs))
                       ;; ATOMIC (ADR 0049 §10): the compacting DELETE(s) + the survivor re-MAC commit
                       ;; TOGETHER — a crash between them leaves survivors chained over a deleted row so a
                       ;; clean store false-rejects on the next open; with-transaction rolls the DELETE(s)
                       ;; back on any mid-op failure (one fsync at COMMIT under WAL+synchronous=FULL).
                       (sqlite:with-transaction (car db-cell)
                         (let ((keep-keys (make-hash-table :test #'equal)))
                           (dolist (r kept)
                             (setf (gethash (cons (coerce (durable-record-writer-guid r) 'list)
                                                  (durable-record-sn r))
                                            keep-keys)
                                   t))
                           (dolist (r recs)
                             (unless (gethash (cons (coerce (durable-record-writer-guid r) 'list)
                                                    (durable-record-sn r))
                                              keep-keys)
                               (sqlite:execute-non-query
                                (car db-cell)
                                "DELETE FROM record WHERE topic=? AND writer_guid=? AND sn=?"
                                tn (durable-record-writer-guid r)
                                (%sn->be8 (durable-record-sn r))))))
                         ;; simulated crash between the DELETE and the re-MAC (test-only; rolls back)
                         (when *durability-debug-compact-fault*   ; NOCOND(TEST): inert in production; the UNWIND aborts the live txn — that is the mechanism under test
                           (error "dds.durability: *durability-debug-compact-fault* — simulated crash ~
                                   between the compacting DELETE and the chain re-MAC (topic ~a)" tn))
                         ;; recompute the surviving chain so the next reopen never false-rejects (ADR 0045)
                         (when (car cmf-cell)
                           (let ((tail (%sqlite-recompute-topic (car db-cell) tn (car cmf-cell))))
                             (if tail
                                 (setf (gethash tn chain-macs) tail)
                                 (remhash tn chain-macs))))))))))
        (%ensure-db)
        (%make-durable-store
         :name :sqlite

         :put
         (lambda (topic writer-guid sn key-hash kind payload)
           (dds.pal:with-lock (lock)
             (%ensure-db)
             (cond
               ;; idempotent: same (topic, writer-guid, sn) already present -> no-op T
               ((sqlite:execute-single (car db-cell)
                                       "SELECT 1 FROM record WHERE topic=? AND writer_guid=? AND sn=? LIMIT 1"
                                       topic writer-guid (%sn->be8 sn))
                t)
               ;; bounded store full -> reject (RESOURCE_LIMITS)
               ((and (plusp max-samples) (>= (%total) max-samples)) :rejected)
               (t
                (let ((mac nil) (seq nil))
                  (when (car cmf-cell)
                    ;; keyed store: v3 chain MAC over this topic's running MAC (seeded on the first
                    ;; put), byte-identical to the file store; explicit chain_seq = per-topic MAX+1.
                    (let* ((prev (or (gethash topic chain-macs) (%chain-seed (car cmf-cell) topic)))
                           (rec  (make-durable-record :topic topic :writer-guid writer-guid :sn sn
                                                      :key-hash key-hash :kind kind :payload payload)))
                      (setf mac (nth-value 1 (%frame-record-versioned
                                              rec +frame-version-v3+ prev (car cmf-cell))))
                      (setf seq (1+ (or (sqlite:execute-single
                                         (car db-cell)
                                         "SELECT MAX(chain_seq) FROM record WHERE topic=?" topic)
                                        -1)))
                      (setf (gethash topic chain-macs) mac)))
                  (sqlite:execute-non-query
                   (car db-cell)
                   "INSERT OR IGNORE INTO record (topic, writer_guid, sn, key_hash, kind, payload, mac, chain_seq) VALUES (?,?,?,?,?,?,?,?)"
                   topic writer-guid (%sn->be8 sn) key-hash (%kind->int kind) payload mac seq)
                  ;; online per-instance KEEP_LAST eviction (ADR 0049 §7, Sliver 1): drop superseded
                  ;; :data rows for this instance so a continuously-open store stays bounded WITHOUT a
                  ;; reopen (mirrors %mem-put); guard identical to the memory store.
                  (when (and (eq :keep-last (car hk-cell)) (eq :data kind) key-hash)
                    ;; ATOMIC (ADR 0049 §10): the evict DELETE(s) + the survivor re-MAC commit TOGETHER —
                    ;; a crash between them leaves survivors chained over a deleted row so a clean store
                    ;; false-rejects on the next open; with-transaction rolls the DELETE(s) back on any
                    ;; mid-op failure (one fsync at COMMIT under WAL+synchronous=FULL, not N).
                    (sqlite:with-transaction (car db-cell)
                      (when (plusp (%sqlite-evict-instance (car db-cell) topic key-hash (car depth-cell)))
                        ;; simulated crash between the DELETE and the re-MAC (test-only; rolls back)
                        (when *durability-debug-compact-fault*   ; NOCOND(TEST): inert in production; the UNWIND aborts the live txn
                          (error "dds.durability: *durability-debug-compact-fault* — simulated crash ~
                                  between the online evict DELETE and the chain re-MAC (topic ~a)" topic))
                        ;; re-MAC the survivors so the chain still verifies on the next reopen (ADR 0045;
                        ;; the machinery %compact-on-open uses after its DELETEs — no false-reject).
                        (when (car cmf-cell)
                          (let ((tail (%sqlite-recompute-topic (car db-cell) topic (car cmf-cell))))
                            (if tail
                                (setf (gethash topic chain-macs) tail)
                                (remhash topic chain-macs)))))))
                  t)))))

         :get-range
         (lambda (topic)
           (dds.pal:with-lock (lock)
             (%ensure-db)
             ;; fetch all rows for TOPIC, then sort in Lisp via the SHARED %record-guid-sn< so the
             ;; order is byte-exact identical to the memory + file backends (DRY, one order defn)
             (sort (%topic-records-in-order topic) #'%record-guid-sn<)))

         :topics
         (lambda ()
           (dds.pal:with-lock (lock)
             (%ensure-db)
             (mapcar #'first
                     (sqlite:execute-to-list (car db-cell) "SELECT DISTINCT topic FROM record"))))

         :purge
         (lambda (topic)
           (dds.pal:with-lock (lock)
             (%ensure-db)
             (sqlite:execute-non-query (car db-cell) "DELETE FROM record WHERE topic=?" topic)
             ;; drop the stale running chain head so a reput re-seeds from the per-topic head, not the
             ;; pre-purge tail — else reopen's re-seeded verify mismatches at row 0 (no false-reject; ADR 0045)
             (remhash topic chain-macs)
             t))

         :open
         (lambda (open-hk open-hd)
           ;; restart-recovery entry point: (re)connect to the DB (prior rows queryable for free),
           ;; then apply the effective compaction policy (caller override wins over factory default).
           (dds.pal:with-lock (lock)
             (%ensure-db)
             (when open-hk (setf (car hk-cell) open-hk))
             (when open-hd (setf (car depth-cell) open-hd))
             ;; keyed store: verify EVERY chain BEFORE compaction (fail-closed; tamper cannot be
             ;; laundered by the compacting DELETE). A bare store skips verification (ADR 0045).
             (when (car cmf-cell)
               (%verify-chains))
             (%compact-on-open (car hk-cell) (car depth-cell))
             t))

         :close
         (lambda ()
           (dds.pal:with-lock (lock)
             (when (car db-cell)
               ;; durability barrier: checkpoint the WAL into the main DB, then disconnect
               (ignore-errors (sqlite:execute-single (car db-cell) "PRAGMA wal_checkpoint(FULL)"))
               (ignore-errors (sqlite:disconnect (car db-cell)))
               (setf (car db-cell) nil))
             t))

         :count-fn
         (lambda (topic)
           (dds.pal:with-lock (lock)
             (%ensure-db)
             (if topic
                 (sqlite:execute-single (car db-cell) "SELECT COUNT(*) FROM record WHERE topic=?" topic)
                 (%total))))

         :sync
         (lambda ()
           ;; group-commit durability barrier: checkpoint the WAL so committed data survives a crash.
           ;; A checkpoint failure PROPAGATES (no ignore-errors) so the collect loop surfaces it via
           ;; *durability-error-hook* — a failed flush must never be treated as durable (fail-closed).
           (dds.pal:with-lock (lock)
             (%ensure-db)
             (sqlite:execute-single (car db-cell) "PRAGMA wal_checkpoint(FULL)"))
           t)

         :set-chain-mac-fn
         ;; keyed-store seam (ADR 0045): the encrypted decorator installs the log-MAC oracle here
         ;; BEFORE it drives store-open, so replay verifies + puts write the chain with the key in
         ;; hand. The store holds only the closure, never the key bytes. REQUIRED marks the store
         ;; chain-committed (a full v3->v2 downgrade of a non-empty topic fails the open); GRANDFATHER
         ;; (a topic-id hash-set or NIL) names legacy topics exempt from that per-topic check.
         (lambda (fn required grandfather)
           (dds.pal:with-lock (lock)
             (setf (car cmf-cell) fn)
             (setf (car req-cell) required)
             (setf (car gf-cell) grandfather))
           t)

         :chain-tails-fn
         ;; sealed high-water tail-anchor SEAL seam (ADR 0045 §7.1): for each topic with chained rows,
         ;; walk its rows via the shared %sqlite-chain-walk to the natural end, yielding (chained-count N .
         ;; tail-MAC M_N). Keyed by the raw `topic` column value (= the encrypted decorator's topic-hash th,
         ;; an ASCII hex string) — the SAME value store-verify-chain-prefix re-walks, so the sealed key
         ;; round-trips through logmac.tail losslessly. The (N . M_N) shape MATCHES the file tier EXACTLY
         ;; (%chain-walk). A bare (no-oracle) store returns an empty set (no anchor, mirrors the file tier).
         (lambda ()
           (dds.pal:with-lock (lock)
             (%ensure-db)
             (let ((result (make-hash-table :test #'equal)))
               (when (car cmf-cell)
                 (dolist (topic (sqlite:execute-to-list (car db-cell) "SELECT DISTINCT topic FROM record"))
                   (let ((tn (first topic)))
                     (multiple-value-bind (n mac reason)
                         (%sqlite-chain-walk (car db-cell) tn (car cmf-cell) nil)
                       (declare (ignore reason))
                       (when (plusp n)
                         (setf (gethash tn result) (cons n mac)))))))
               result)))

         :verify-chain-prefix-fn
         ;; sealed high-water tail-anchor VERIFY seam (ADR 0045 §7.1): re-walk TOPIC's chained rows to
         ;; ordinal N (%sqlite-chain-walk STOP-AT) and decide prefix-containment, BEFORE the store-open
         ;; %verify-chains + %compact-on-open mutate the rows. :reached ⇒ compare the running MAC@N to the
         ;; sealed M_N (== intact/may-extend forward = CLEAN; != = :diverged rollback/substitution); :clean
         ;; (ran out below N — including 0 rows = a whole-topic drop) ⇒ :truncated; :break/:mismatch (an
         ;; interior tamper before N) ⇒ tolerate T here, deferring to store-open's fail-loud %verify-chains
         ;; (parity with the file tier's :corrupt→T). No oracle ⇒ T. RETURN semantics MATCH the file tier EXACTLY.
         (lambda (topic n mac)
           (dds.pal:with-lock (lock)
             (%ensure-db)
             (if (null (car cmf-cell))
                 t
                 (multiple-value-bind (count running reason)
                     (%sqlite-chain-walk (car db-cell) topic (car cmf-cell) n)
                   (declare (ignore count))
                   (cond
                     ((eq reason :reached) (if (equalp running mac) t :diverged))
                     ((eq reason :clean)   :truncated)
                     (t                    t))))))

         :delete
         ;; per-record physical reclaim (ADR 0025 §10.3, Sliver 3a — the encrypted decorator's
         ;; superseded-surrogate eviction): DELETE the (topic, writer-guid, sn) row and re-MAC the
         ;; survivors in ONE transaction — INTERNALLY ATOMIC (a crash between the DELETE and the re-MAC
         ;; rolls back so a clean chained store never false-rejects on reopen; the Sliver-1 hazard the
         ;; txn wrap closed). Near-verbatim lift of the online-evict block's DELETE + %sqlite-recompute-
         ;; topic + with-transaction (DRY). The put+delete PAIR need NOT be atomic (a LOWER bar than the
         ;; compacting DELETE): a crash between the decorator's put and this delete leaks the prior blob
         ;; (get-range still logically compacts it) and self-heals on the next delete.
         (lambda (topic writer-guid sn)
           (dds.pal:with-lock (lock)
             (%ensure-db)
             (sqlite:with-transaction (car db-cell)
               (sqlite:execute-non-query
                (car db-cell)
                "DELETE FROM record WHERE topic=? AND writer_guid=? AND sn=?"
                topic writer-guid (%sn->be8 sn))
               ;; simulated crash between the DELETE and the re-MAC (test-only; rolls back -> leak, no reject)
               (when *durability-debug-compact-fault*   ; NOCOND(TEST): inert in production; the UNWIND aborts the live txn
                 (error "dds.durability: *durability-debug-compact-fault* — simulated crash between the ~
                         store-delete DELETE and the chain re-MAC (topic ~a)" topic))
               ;; re-MAC the survivors so the chain still verifies on the next reopen (ADR 0045; the same
               ;; machinery the online evict + on-open compaction use after their DELETEs — no false-reject)
               (when (car cmf-cell)
                 (let ((tail (%sqlite-recompute-topic (car db-cell) topic (car cmf-cell))))
                   (if tail
                       (setf (gethash topic chain-macs) tail)
                       (remhash topic chain-macs)))))
             t))

         :replace-topic-fn
         ;; atomic whole-topic REPLACE (ADR 0050 §4.4): the microservice server calls this after a KEEP_LAST
         ;; reclaim re-MACs the survivors client-side, so a persistent SQLite inner swaps the topic's rows in
         ;; ONE transaction (DELETE the topic + INSERT the survivors) — a crash mid-swap ROLLS BACK (a partial
         ;; topic would brick the re-MAC'd chain). The DARE-blind server inner is BARE (cmf-cell NIL): the
         ;; mac/chain_seq COLUMNS stay NULL exactly as the bare :put writes them, and the folded mac/chain_seq
         ;; ride INSIDE the opaque payload BLOB the server never parses. Reuses the :put INSERT + :purge DELETE
         ;; shapes (DRY); *durability-debug-compact-fault* exercises the mid-swap rollback.
         (lambda (topic records)
           (dds.pal:with-lock (lock)
             (%ensure-db)
             (sqlite:with-transaction (car db-cell)
               (sqlite:execute-non-query (car db-cell) "DELETE FROM record WHERE topic=?" topic)
               ;; simulated crash between the DELETE and the survivor INSERTs (test-only; rolls back)
               (when *durability-debug-compact-fault*   ; NOCOND(TEST): inert in production; the UNWIND aborts the live txn
                 (error "dds.durability: *durability-debug-compact-fault* — simulated crash mid ~
                         topic-rewrite (topic ~a)" topic))
               (dolist (r records)
                 (sqlite:execute-non-query
                  (car db-cell)
                  "INSERT OR IGNORE INTO record (topic, writer_guid, sn, key_hash, kind, payload, mac, chain_seq) VALUES (?,?,?,?,?,?,?,?)"
                  topic (durable-record-writer-guid r) (%sn->be8 (durable-record-sn r))
                  (durable-record-key-hash r) (%kind->int (durable-record-kind r))
                  (durable-record-payload r) nil nil)))
             ;; parity with :purge — drop any stale running chain head (a bare inner never seeds it)
             (remhash topic chain-macs)
             t)))))))

(defun* make-sqlite-store-factory (&key dir key-dir (db-name "durability.sqlite3")
                                        (history-kind :keep-all) (history-depth 1))
    (function (&key (:dir (or pathname string)) (:key-dir (or pathname string)) (:db-name string)
                    (:history-kind (member :keep-all :keep-last)) (:history-depth (integer 1)))
              function)
  "Return a 0-arg store factory producing the PERSISTENT-tier SECURE SQLite composition (ADR 0049):
   make-encrypted-store(make-sqlite-store(:path DIR/DB-NAME, :history-kind …),
   make-file-key-provider(:dir KEY-DIR), :epoch-dir DIR). Mirrors make-persistent-store-factory
   (the file-store sibling) exactly — the ONLY change is make-sqlite-store in place of make-file-store,
   because the durable-store vtable is the fixed backend contract both fill unchanged. Pass this as the
   :STORE argument to MAKE-SERVICE-SPEC to config-select the SQLite-on-disk encrypted tier.
   DIR holds the SQLite DB + epochs.dat + logmac.anchor (they coexist); KEY-DIR holds the ML-KEM-1024
   keypair (perms enforced 0700/0600, fail-closed by the key-provider). :PROCESS service mode does NOT
   carry this factory across the subprocess boundary — use :THREAD mode. The returned store requires
   STORE-OPEN before reads/writes and STORE-CLOSE to checkpoint + flush; STORE-CLOSE is mandatory."
  (let ((d  (uiop:ensure-directory-pathname dir))
        (k  (uiop:ensure-directory-pathname key-dir))
        (nm db-name)
        (hk history-kind)
        (hd history-depth))
    (lambda ()
      (make-encrypted-store (make-sqlite-store :path (merge-pathnames nm d)
                                               :history-kind hk :history-depth hd)
                            (dds.dare:make-file-key-provider :dir k)
                            :epoch-dir d))))
