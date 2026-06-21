;;;; RELAY 2 = our durability service, alongside RTI Persistence Service (RELAY 1).
;;;;
;;;; WP-DURABILITY-COEXIST-DEDUP (M6/P5, ADR 0026 §10).  A long-running durability service on domain 0:
;;;; its RELIABLE/TRANSIENT_LOCAL/KEEP_ALL collecting reader RxO-matches the foreign Connext TRANSIENT
;;;; publisher (offered TRANSIENT rank 2 >= requested TRANSIENT_LOCAL rank 1), collects each origin
;;;; sample, and its replay writer (advertising TRANSIENT_LOCAL, stamping PID_ORIGINAL_WRITER_INFO 0x0061
;;;; + PID_SERVICE_KIND=PERSISTENCE_SERVICE) serves late-joiners.  This is the relay used by BOTH
;;;; direction (a) (our-stack reader) and direction (b) (Connext shapes_sub).
;;;;
;;;; This driver advertises :RELAY-DURABILITY :TRANSIENT (rank 2) — the cross-vendor coexistence option
;;;; landed in Task 2 (make-service-spec :qos-overrides '(:relay-durability :transient)).  A TRANSIENT
;;;; receiver (Connext shapes_sub or our-stack reader requesting :transient) RxO-matches BOTH this relay
;;;; (offered TRANSIENT 2 >= requested 2) AND RTI PS (likewise 2 >= 2) — so a single late-joiner can take
;;;; retained replay from BOTH relays at once (resolving blocker B1, the prior TL-only tier wall).  Both
;;;; relays stamp the OMG-standard PID_ORIGINAL_WRITER_INFO 0x0061 (RTPS 2.5 §8.3.5.4); when both relay
;;;; the SAME single Connext TRANSIENT publisher, both origins == that publisher's (GUID, SN), so the
;;;; receiver's dedup collapses the two identical-origin streams to exactly N.
;;;;
;;;; LIVE RESULT (WP-DURABILITY-COEXIST-LIVE, ADR 0028, 2026-06-21): dir-a N=545, dir-b N=550; both
;;;; relays stamped the same publisher origin GUID in each direction; UNION=N; sum=2N; captures in
;;;; captures/coexist-dir-{a,b}.pcap; analyze-capture.py --assert-converged exits 0. The :collect-durability
;;;; :transient + logical-origin fix (node-sample-origin-guid/sn in disc-node) was the key: our relay now
;;;; records the OWI origin GUID (the publisher's) not the wire sender GUID (RTI PS's relay) when RTI PS
;;;; replay wins the arrival race.
;;;;
;;;; In-memory store (make-memory-store): persistence/at-rest is a separate concern
;;;; (interop/durability-persistent/).  Two QoS overrides as the other durability drivers:
;;;; :data-representation (:xcdr1) for the XCDR1-only ShapeType peers and :peers — 7410 (domain-0
;;;; well-known SPDP) plus the our-stack reader's fixed port (so this relay can SPDP-reach + match it).
;;;;
;;;; Prints OUR-RELAY-SPDP-PORT=<port> so run-coexist-both.sh can point the our-stack reader at it.
;;;; Config (env): COEXIST_SECS (lifetime), COEXIST_READER_PORT (the our-stack reader's fixed port).

(asdf:load-system :dds-durability)

(defpackage #:coexist-relay2 (:use #:cl))
(in-package #:coexist-relay2)

(defun env-int (name default)
  (let ((v (uiop:getenv name)))
    (if (and v (plusp (length v))) (parse-integer v) default)))

(let* ((secs (env-int "COEXIST_SECS" 90))
       ;; The our-stack reader (direction a) binds a FIXED port so we can list it as an SPDP peer here
       ;; — RTPS SPDP is announced only to the static peer list (announce-participant), and SEDP only
       ;; to discovered participants, so the relay must SPDP-reach the reader for the reader to discover
       ;; the relay and announce its subscription back (else the relay never matches it / never replays).
       (reader-port (env-int "COEXIST_READER_PORT" 7600))
       ;; :store is a 0-arg FACTORY thunk (service-start calls it once); make-memory-store returns a
       ;; store instance, so close one in a lambda (mirrors the no-double-delivery test's pattern).
       (mem-store (dds.durability:make-memory-store))
       (spec (dds.durability:make-service-spec
              :domain 0
              :topics '(("Square" . "ShapeType"))
              :store (lambda () mem-store)
              ;; :relay-durability :transient (Task 2) — advertise TRANSIENT so a TRANSIENT receiver
              ;; matches BOTH this relay and RTI PS (B1 fix).
              ;; :collect-durability :transient (Task 3) — our COLLECT reader requests TRANSIENT so RTI
              ;; PS replays its OWI-stamped history to us; that OWI origin (the original publisher's GUID)
              ;; collapses against the publisher samples we collect directly, so this relay re-stamps the
              ;; ONE publisher origin instead of recording RTI PS's virtual GUID (B2 origin convergence).
              :qos-overrides `(:data-representation (:xcdr1)
                               :relay-durability :transient
                               :collect-durability :transient
                               :peers (("127.0.0.1" . 7410)
                                       ("127.0.0.1" . ,reader-port)))
              :name "dcoexist-relay2"))
       (svc (dds.durability:make-durability-service spec)))
  (dds.durability:service-start svc)
  (let* ((node (dds.durability:durability-service-node svc))
         (port (dds.disc:disc-node-port node)))
    (format t "~%SVC-COEXIST-STARTED (relay 2 of 2)~%")
    (format t "OUR-RELAY-SPDP-PORT=~d~%" port)
    (force-output)
    (let ((store (dds.durability:durability-service-store svc)))
      ;; B2 diagnostic (printed EVERY 5s alongside COLLECTED so it is captured before the harness kills
      ;; the relay): which ORIGIN GUID(s) did our relay record for the Square topic?  The collect path
      ;; records node-sample-writer-guid (the WIRE sender) per sample (src/dds-durability/service.lisp).
      ;; Convergence requires this == RTI PS's stamped OWI origin so a receiver's dedup collapses the two
      ;; relay streams; the capture's --owi-dump is the authoritative cross-check.
      (flet ((dump-origins ()
               (let ((per-origin (make-hash-table :test 'equalp)))
                 (dolist (r (dds.durability:store-get-range store "Square"))
                   (let* ((g (dds.durability:durable-record-writer-guid r))
                          (hx (when g (string-downcase (format nil "~{~2,'0x~}" (coerce g 'list))))))
                     (when hx (push (dds.durability:durable-record-sn r) (gethash hx per-origin)))))
                 (format t "SVC-COEXIST-ORIGINS distinct=~d~%" (hash-table-count per-origin))
                 (maphash (lambda (hx sns)
                            (format t "  origin-guid=~a count=~d sn[min=~d max=~d]~%"
                                    hx (length sns) (reduce #'min sns) (reduce #'max sns)))
                          per-origin)
                 (force-output))))
        (dotimes (i secs)
          (sleep 1)
          (when (zerop (mod (1+ i) 5))
            (format t "SVC-COEXIST-COLLECTED Square=~d matched=~d topics=~a acks-in=~d disc-parts=~d disc-readers=~d (t+~ds)~%"
                    (dds.durability:store-count store "Square")
                    (dds.disc:disc-node-matched-count node)
                    (dds.disc:disc-node-matched-topics node)
                    (dds.disc:node-acks-in node)
                    (length (dds.disc:node-discovered-participants node))
                    (length (dds.disc:disc-node-discovered-readers-list node))
                    (1+ i))
            (dump-origins)))
        (format t "~%SVC-COEXIST-FINAL Square=~d~%"
                (dds.durability:store-count store "Square"))
        (dump-origins)
        (force-output))))
  (dds.durability:service-stop svc)
  (format t "~%SVC-COEXIST-STOPPED~%")
  (finish-output)
  (uiop:quit 0))
