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
      (error "dds.durability: SQLite record with unassigned kind ~d (topic ~a)" kind-int topic))
    (make-durable-record
     :topic       topic
     :writer-guid (%to-octets-n wg-blob 16)
     :sn          (%be8->sn sn-blob)
     :key-hash    (when kh-blob (%to-octets-n kh-blob 16))
     :kind        kind
     :payload     (%to-octets-n pl-blob (length pl-blob)))))

;;; SQL text — pinned once (DRY; no ad-hoc string building on the hot loop).

(defparameter %sqlite-ddl-table
  "CREATE TABLE IF NOT EXISTS record (topic TEXT NOT NULL, writer_guid BLOB NOT NULL, sn BLOB NOT NULL, key_hash BLOB, kind INTEGER NOT NULL, payload BLOB NOT NULL, PRIMARY KEY (topic, writer_guid, sn))"
  "DDL for the durable-record table (ADR 0049). SN is an 8-byte big-endian BLOB (full u64, no bound).")

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
    (sqlite:execute-non-query db %sqlite-ddl-index)
    db))

(defun* make-sqlite-store (&key path (max-samples 0)
                                (history-kind :keep-all) (history-depth 1))
    (function (&key (:path (or null pathname string)) (:max-samples (integer 0))
                    (:history-kind (member :keep-all :keep-last)) (:history-depth (integer 1)))
              durable-store)
  "Construct a SQLite-backed durable-store implementing the fixed durable-store vtable (ADR 0049).
   PATH is the DB file (required). MAX-SAMPLES 0 = unbounded; positive caps total records across all
   topics (store-put returns :REJECTED when full). HISTORY-KIND / HISTORY-DEPTH govern per-instance
   compaction-on-open (DDS 1.4 §2.2.3.5): :keep-all (default) drops only settled instances; :keep-last
   with DEPTH >= 1 additionally keeps only the newest DEPTH :data records per non-NIL-key-hash instance.
   Stores OPAQUE payload bytes (DARE-unaware); wrap with make-encrypted-store for at-rest sealing.
   store-open (re)establishes the connection — a fresh store on an existing PATH replays all prior rows
   (restart recovery). The chain-MAC seam is intentionally absent (per-row keyed MAC = ADR 0049 §7
   follow-on); store-set-chain-mac-fn no-ops, composing cleanly with the encrypted decorator."
  (let* ((db-path (when path (pathname path)))
         (lock    (dds.pal:make-lock "dds-sqlite-store"))
         (db-cell (list nil))                 ; car = live connection or NIL when closed
         ;; mutable policy cells (factory defaults; store-open overrides car when non-NIL)
         (hk-cell   (cons history-kind nil))
         (depth-cell (cons history-depth nil)))
    (flet ((%total ()
             (sqlite:execute-single (car db-cell) "SELECT COUNT(*) FROM record")))
      (labels ((%ensure-db ()
                 (unless (car db-cell)
                   (unless db-path
                     (error "dds.durability: make-sqlite-store requires :path"))
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
               (%compact-on-open (eff-hk eff-hd)
                 ;; compaction-on-open (DDS 1.4 §2.2.3.5): run the SHARED %compact-topic-records per
                 ;; topic (identical to the file store) and DELETE any dropped rows. Cheap (durability
                 ;; is off the wire hot path); :keep-all drops settled instances, :keep-last also caps.
                 (dolist (topic (sqlite:execute-to-list (car db-cell) "SELECT DISTINCT topic FROM record"))
                   (let* ((tn   (first topic))
                          (recs (%topic-records-in-order tn))
                          (kept (%compact-topic-records recs eff-hk eff-hd)))
                     (when (< (length kept) (length recs))
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
                              (%sn->be8 (durable-record-sn r)))))))))))
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
                (sqlite:execute-non-query
                 (car db-cell)
                 "INSERT OR IGNORE INTO record (topic, writer_guid, sn, key_hash, kind, payload) VALUES (?,?,?,?,?,?)"
                 topic writer-guid (%sn->be8 sn) key-hash (%kind->int kind) payload)
                t))))

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
             t))

         :open
         (lambda (open-hk open-hd)
           ;; restart-recovery entry point: (re)connect to the DB (prior rows queryable for free),
           ;; then apply the effective compaction policy (caller override wins over factory default).
           (dds.pal:with-lock (lock)
             (%ensure-db)
             (when open-hk (setf (car hk-cell) open-hk))
             (when open-hd (setf (car depth-cell) open-hd))
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
           t))))))

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
