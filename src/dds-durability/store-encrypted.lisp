(in-package #:dds.durability)

;;; Task 6 — DARE-encrypted durable-store decorator (ADR 0021 cap.7).
;;; Seals every payload on put via ML-KEM-1024 + AES-256-GCM; opens on get-range.
;;; Per-store counter nonce (96-bit LE): starts at 0, incremented before each seal.
;;; On auth failure in get-range: record is DROPPED + *dare-error-hook* fires.
;;; Topics / purge / count delegate to inner store unchanged (metadata cleartext).

(defparameter *dare-error-hook* nil
  "Funcallable (CONDITION CONTEXT COUNT) invoked when open-payload returns NIL (auth/tamper fail).
   CONTEXT is :dare-open-failed; COUNT is the running tally. Default = rate-limited WARN.")

(defun* %default-dare-error-hook (condition context count)
    (function (t t (integer 1)) t)
  "Default *DARE-ERROR-HOOK*: power-of-ten rate-limited WARN (mirrors %default-durability-error-hook)."
  (when (%durability-error-count-p count)
    (warn "dds.durability dare (~a) open-payload failure #~d: ~a" context count condition))
  t)

(eval-when (:load-toplevel :execute)
  (setf *dare-error-hook* #'%default-dare-error-hook))

(defun* %render-nonce (counter)
    (function ((integer 0)) (simple-array (unsigned-byte 8) (*)))
  "Encode 96-bit COUNTER as 12-byte little-endian nonce vector."
  (let ((v (make-array 12 :element-type '(unsigned-byte 8))))
    (dotimes (i 12 v)
      (setf (aref v i) (ldb (byte 8 (* 8 i)) counter)))))

(defun* %encrypted-store-fresh-dek (public-key)
    (function ((simple-array (unsigned-byte 8) (*))) (simple-array (unsigned-byte 8) (*)))
  "Encapsulate to PUBLIC-KEY, derive a fresh per-session DEK (foreign/static), and zeroize+free
   the transient shared secret even if derivation throws (§6 all-secrets posture)."
  (multiple-value-bind (kem-ct ss) (dds.dare:ml-kem-1024-encapsulate public-key)
    (declare (ignore kem-ct))
    (unwind-protect (dds.dare:derive-dek ss)
      (dds.dare:free-secret-octets ss))))

(defun* make-encrypted-store (inner-store key-provider)
    (function (durable-store dds.dare:key-provider) durable-store)
  "Construct a durable-store decorator that DARE-seals payloads on put and opens them on get-range.
   Construction: key-provider-open; ML-KEM-1024-encapsulate(recipient-public-key) -> (kem-ct ss);
   DEK = derive-dek(ss); per-store 96-bit counter nonce starts at 0, increments per put.
   Put: seal payload + delegate sealed blob to inner-store.
   Get-range: open each record; on NIL (auth fail/tamper) DROP + fire *dare-error-hook*.
   Topics/purge/count-fn: delegate to inner unchanged.
   The DEK is a foreign-backed secret buffer (static-vector, design spec §6) held for the store
   lifetime; the transient shared secret is freed once the DEK is derived.
   Open/close: key-provider-open/close + DEK zeroize+free on close (a second close is safe)."
  (dds.dare:key-provider-open key-provider)
  (let* ((pub-key  (dds.dare:key-provider-recipient-public-key key-provider))
         (dek      (%encrypted-store-fresh-dek pub-key))
         (counter  0)
         (err-count 0))
    (%make-durable-store
     :name :encrypted
     :put
     (lambda (topic writer-guid sn key-hash kind payload)
       (let* ((nonce  (progn (incf counter) (%render-nonce counter)))
              (aad    (dds.dare:make-record-aad topic writer-guid sn kind))
              (sealed (dds.dare:seal-payload dek nonce aad payload)))
         (store-put inner-store topic writer-guid sn key-hash kind sealed)))
     :get-range
     (lambda (topic)
       (let ((result '()))
         (dolist (r (store-get-range inner-store topic))
           (let* ((aad    (dds.dare:make-record-aad
                           (durable-record-topic r)
                           (durable-record-writer-guid r)
                           (durable-record-sn r)
                           (durable-record-kind r)))
                  (opened (dds.dare:open-payload dek (durable-record-payload r) aad)))
             (if opened
                 (push (make-durable-record
                        :topic      (durable-record-topic r)
                        :writer-guid (durable-record-writer-guid r)
                        :sn         (durable-record-sn r)
                        :key-hash   (durable-record-key-hash r)
                        :kind       (durable-record-kind r)
                        :payload    opened)
                       result)
                 (let ((n (incf err-count)))
                   (ignore-errors
                    (funcall *dare-error-hook*
                             (format nil "open-payload NIL (topic ~a, ~d sealed bytes)"
                                     (durable-record-topic r) (length (durable-record-payload r)))
                             :dare-open-failed n))))))
         (nreverse result)))
     :topics
     (lambda () (store-topics inner-store))
     :purge
     (lambda (topic) (store-purge inner-store topic))
     :open
     (lambda ()
       (unless dek
         (dds.dare:key-provider-open key-provider)
         ;; defensive: never double-hold a DEK; free any stale one before re-deriving (§6)
         (setf dek (dds.dare:free-secret-octets dek))
         (setf dek (%encrypted-store-fresh-dek
                    (dds.dare:key-provider-recipient-public-key key-provider))))
       t)
     :close
     (lambda ()
       ;; zeroize + free the foreign secret DEK (idempotent on NIL); §6
       (setf dek (dds.dare:free-secret-octets dek))
       (dds.dare:key-provider-close key-provider)
       t)
     :count-fn
     (lambda (topic) (store-count inner-store topic)))))
