;;;; Direction (a): OUR-STACK reader as the late-joining receiver, two relays present.
;;;;
;;;; WP-DURABILITY-COEXIST-DEDUP (M6/P5, ADR 0026 §10).  An our-stack disc-node reader
;;;; (RELIABLE / TRANSIENT_LOCAL / KEEP_ALL) late-joins domain 0 AFTER the original Connext
;;;; TRANSIENT publisher has exited, with TWO relays live:
;;;;   RELAY 1 = RTI Persistence Service v7.3.1 (TRANSIENT tier; OWI on replay, Branch A spike)
;;;;   RELAY 2 = our durability service (:relay-durability :transient replay writer; OWI per sample, ADR 0024)
;;;; The reader's receiver-side dedup (reader-dedup-accept-p, RTPS 2.5 §8.3.5.4) keys on the
;;;; effective origin (GUID, SN); duplicates of the same origin collapse to one delivery.
;;;;
;;;; FINDING (authoritative: README §direction-a + ADR 0027): RTI PS emits the standard
;;;; PID_ORIGINAL_WRITER_INFO with the publisher's real (GUID,SN) on replay; with our relay advertising
;;;; :relay-durability :transient a TRANSIENT receiver matches BOTH relays (the tier wall is gone). A live
;;;; dual-relay exactly-once was NOT captured — the two relays' recorded origins diverged on our
;;;; collect/orchestration side (NOT an RTI virtual-GUID wall) — a documented follow-on. The authoritative
;;;; two-OWI-relay exactly-once proof is the in-process dds.tests:run-durability-no-double-delivery-test +
;;;; run-durability-multi-relay-dedup-test.
;;;;
;;;; Reliability (the real work vs Phase-3b): the reader binds a FIXED port (relay2 lists it as an SPDP
;;;; peer so the relay can SPDP-reach + match it), drives SPDP+SEDP every ~50 ms, requests each matched
;;;; relay writer's retained history via %reader-durability-init, and polls node-sample-count to a
;;;; settled fixpoint.  This makes the our-relay late-joiner replay deterministic every run.
;;;;
;;;; Config (env): COEXIST_PEER_PS_PORT (RTI PS SPDP port, default 7410), COEXIST_SVC_PORT (our relay's
;;;;   SPDP port — passed by the runner), COEXIST_READER_PORT (this reader's fixed port), COEXIST_SECS.

(asdf:load-system :dds-durability)

(defpackage #:coexist-our-reader (:use #:cl))
(in-package #:coexist-our-reader)

(defun env-int (name default)
  (let ((v (uiop:getenv name)))
    (if (and v (plusp (length v))) (parse-integer v) default)))

(defun distinct-origin-sns (node)
  "Deduplicated delivery count: distinct user samples the reader stored after reader-dedup-accept-p
   (RTPS 2.5 §8.3.5.4) dropped any duplicate (origin-GUID, SN).  When the wire carries the same origin
   twice (e.g. a relay's reliable retransmits, or two relays of the same origin) this count stays N."
  (dds.disc:node-sample-count node))

(let* ((ps-port  (env-int "COEXIST_PEER_PS_PORT" 7410))
       (svc-port (env-int "COEXIST_SVC_PORT" 0))
       (my-port  (env-int "COEXIST_READER_PORT" 7600))   ; fixed: relay2 lists it as an SPDP peer
       (secs     (env-int "COEXIST_SECS" 30))
       (peers    (remove-duplicates
                  (append (list (cons "127.0.0.1" ps-port))
                          (when (plusp svc-port) (list (cons "127.0.0.1" svc-port)))
                          ;; well-known SPDP unicast ports for the first few participants on
                          ;; domain 0 (RTPS 2.5 §9.6.1.1: 7400 + 250*0 + 10 + 2*pid), so the
                          ;; reader finds both relays regardless of which index each took.
                          (loop for pid from 0 to 6 collect (cons "127.0.0.1" (+ 7410 (* 2 pid)))))
                  :test #'equal))
       (prefix (make-array 12 :element-type '(unsigned-byte 8)
                              :initial-contents '(#x0C #x0E #x15 #x7E #xD0 #x00
                                                  #x00 #x00 #x00 #x00 #x01 #x02)))
       ;; Unicast SPDP to the static peer list: the relay2 reciprocal peer (my-port) lets our relay
       ;; SPDP-reach us; the 7410..7422 well-known ports reach RTI PS (Connext replies SPDP unicast to a
       ;; discovered participant's advertised locator), so the reader discovers BOTH relays and can send
       ;; its subscription SEDP back to each — the prerequisite for either relay to replay to it.
       (node (dds.disc:make-disc-node :guid-prefix prefix :domain 0
                                      :host "127.0.0.1" :port my-port
                                      :peers peers :multicast nil))
       (deadline (+ (get-internal-real-time)
                    (* secs internal-time-units-per-second))))
  ;; RELIABLE / TRANSIENT / KEEP_ALL reader.  DURABILITY = :transient (rank 2) now RxO-matches BOTH
  ;; relays: our relay advertises :transient (Task 2 :relay-durability), RTI PS replays only to a
  ;; TRANSIENT reader — so a single late-joiner takes retained replay from BOTH (B1 wall resolved).
  ;; With both relays stamping PID_ORIGINAL_WRITER_INFO with the SAME origin (the one publisher's GUID,
  ;; via our B2 :collect-durability fix + RTI PS Branch A), reader-dedup-accept-p (RTPS 2.5 §8.3.5.4)
  ;; collapses the two identical-origin streams to exactly N.
  ;; REQUEST BOTH (:xcdr2 :xcdr1): our relay offers [XCDR1], RTI PS re-advertises [XCDR2] — accept both
  ;; so the reader MATCHES both writers (DDS 1.4 §2.2.3).  Payloads stored OPAQUE.
  (dds.disc:add-local-reader node
                             :topic "Square" :type "ShapeType"
                             :qos (dds.qos:make-reader-qos
                                   :reliability :reliable
                                   :durability :transient
                                   :history-kind :keep-all
                                   :data-representation '(:xcdr2 :xcdr1)))
  (dds.disc:enable-subscriber node)
  ;; diagnostic: surface RxO rejections (a keyed-ness disagreement is a SILENT non-match upstream,
  ;; so it will NOT appear here — its absence with a discovered-but-unmatched writer implies keyedness).
  (setf (dds.disc:disc-node-on-incompatible-qos node)
        (lambda (kind remote bad)
          (declare (ignore kind))
          (let ((g (dds.rtps.discovery:endpoint-data-guid remote)))
            (format t "OUR-READER-INCOMPAT eid=~2,'0x~2,'0x~2,'0x~2,'0x bad=~a~%"
                    (aref g 12) (aref g 13) (aref g 14) (aref g 15) bad)
            (force-output))))
  ;; on-match: a newly matched relay WRITER -> request its retained history (late-joiner gate).
  (setf (dds.disc:disc-node-on-match node)
        (lambda (kind remote)
          (when (eq kind :remote-writer)
            (let ((g (dds.rtps.discovery:endpoint-data-guid remote)))
              (format t "OUR-READER-MATCH writer eid=~2,'0x~2,'0x~2,'0x~2,'0x dur=~a~%"
                      (aref g 12) (aref g 13) (aref g 14) (aref g 15)
                      (dds.qos:qos-durability (dds.rtps.discovery:endpoint-data-qos remote)))
              (force-output))
            (dds.disc:%reader-durability-init
             node
             (copy-seq (dds.rtps.discovery:endpoint-data-guid remote))
             (dds.qos:qos-durability (dds.rtps.discovery:endpoint-data-qos remote))))))
  (dds.disc:start-node node)
  (format t "~%OUR-READER-STARTED domain=0 peers=~a~%" peers) (force-output)
  ;; ONE loop: every ~50 ms re-announce SPDP+SEDP (so both relays keep discovering us and replaying),
  ;; drain via the receive thread, and poll node-sample-count.  The receive thread stores deduped
  ;; deliveries as they arrive; we announce throughout so a slow second-relay match still lands.  We
  ;; declare SETTLED once the deduped count has held POSITIVE + UNCHANGED for ~3 s AND >=1 relay is
  ;; matched — the reliable history repair has quiesced.
  (let ((last -1) (stable 0) (tick 0) (announced-matched-2 nil))
    (loop while (< (get-internal-real-time) deadline)
          do (dds.disc:announce-participant node)
             (dds.disc:announce-endpoints node)
             (let ((n (distinct-origin-sns node))
                   (m (dds.disc:disc-node-matched-count node)))
               (when (and (>= m 2) (not announced-matched-2))
                 (setf announced-matched-2 t)
                 (format t "OUR-READER-MATCHED relays=~d~%" m) (force-output))
               (when (zerop (mod (incf tick) 20))   ; ~1 s cadence
                 (format t "OUR-READER-PROGRESS matched=~d delivered=~d~%" m n) (force-output))
               (if (and (= n last) (plusp n)) (incf stable) (setf stable 0))
               (setf last n)
               (when (and (>= stable 60) (>= m 1))   ; ~3 s stable + matched => repair quiesced
                 (format t "OUR-READER-SETTLED~%") (force-output)
                 (return)))
             (sleep 0.05)))
  ;; diagnostic: what publications did we discover, and which matched? (helps see if RTI PS was found)
  (format t "OUR-READER-DISCOVERED-WRITERS:~%") (force-output)
  (dolist (w (dds.disc:disc-node-discovered-writers-list node))
    (let* ((g (dds.rtps.discovery:endpoint-data-guid w))
           (q (dds.rtps.discovery:endpoint-data-qos w)))
      (format t "  eid=~2,'0x~2,'0x~2,'0x~2,'0x kind#x~2,'0x topic=~a type=~a dur=~a rel=~a rep=~a~%"
              (aref g 12) (aref g 13) (aref g 14) (aref g 15) (aref g 15)
              (dds.rtps.discovery:endpoint-data-topic-name w)
              (dds.rtps.discovery:endpoint-data-type-name w)
              (ignore-errors (dds.qos:qos-durability q))
              (ignore-errors (dds.qos:qos-reliability q))
              (ignore-errors (dds.qos:qos-data-representation q)))))
  (format t "OUR-READER-DISCOVERED-PARTICIPANTS=~d~%"
          (length (dds.disc:node-discovered-participants node)))
  (force-output)
  ;; per-source breakdown of what we STORED (wire source-GUID -> count): shows whether RTI PS's stream
  ;; (a 0x80000002 source) landed in our store, or only our relay's (a 0x00000102 source).
  (let ((per-src (make-hash-table :test 'equalp)))
    (dolist (key (dds.disc:node-sample-sns node))
      (let* ((g (car key)) (eid (format nil "~2,'0x~2,'0x~2,'0x~2,'0x"
                                        (aref g 12) (aref g 13) (aref g 14) (aref g 15))))
        (incf (gethash eid per-src 0))))
    (format t "OUR-READER-STORE-BY-SOURCE:~%") (force-output)
    (maphash (lambda (eid c) (format t "  src-eid=~a count=~d~%" eid c)) per-src))
  (let ((n (distinct-origin-sns node))
        (matched (dds.disc:disc-node-matched-count node)))
    (format t "~%OUR-READER-RESULT delivered=~d matched-relays=~d~%" n matched)
    (force-output))
  (ignore-errors (dds.disc:stop-node node))
  (finish-output)
  (uiop:quit 0))
