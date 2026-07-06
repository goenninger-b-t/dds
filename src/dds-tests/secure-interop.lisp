;;;; T12 — LIVE Fast DDS-Security cross-vendor secure-discovery driver (M7/P6 Slice 4).
;;;; A standalone, long-running secure DomainParticipant (NOT part of run-all-tests; opt-in only)
;;;; that speaks real RTPS-Security over UDP loopback to an external Fast DDS-Security peer. Mirrors
;;;; the dds.shapes live runners but takes the §8.4/§8.7 identity+governance+permissions config, so a
;;;; separate-process Fast DDS peer on the same domain authenticates, keys, secure-discovers, and
;;;; exchanges protected data with it. Reused by interop/security-secure-discovery/run-fastdds-interop.sh.

(in-package #:net.goenninger.dds.tests)

(defun* %slurp-octets (path)
    (function (string) (simple-array (unsigned-byte 8) (*)))
  "Read PATH (a PEM / S-MIME / signed-XML fixture, all ASCII) into a fresh octet vector."
  (map '(simple-array (unsigned-byte 8) (*)) #'char-code (uiop:read-file-string path)))

(defun* %parse-peer-list (s)
    (function (string) list)
  "Parse \"host:port,host:port\" into an ((host . port) ...) unicast-peer list (empty -> NIL)."
  (let ((out '()))
    (dolist (tok (uiop:split-string s :separator ",") (nreverse out))
      (let ((tok (string-trim " " tok)))
        (when (plusp (length tok))
          (let ((c (position #\: tok)))
            (when c
              (push (cons (subseq tok 0 c)
                          (parse-integer tok :start (1+ c) :junk-allowed t))
                    out))))))))

(defun* %hello-world-payload (index message rep)
    (function ((unsigned-byte 32) string (member :xcdr1 :xcdr2))
              (simple-array (unsigned-byte 8) (*)))
  "Serialize Fast DDS's example @extensibility(APPENDABLE) struct HelloWorld { unsigned long index; string
   message; } as a SerializedPayload in REP (XTypes 1.3 §7.4.3.4, §7.6.3.1.2 Table 60). :xcdr2 -> D_CDR2_LE
   encapsulation {00 09 00 00} ‖ DHEADER(uint32 LE = body length) ‖ members; :xcdr1 -> PLAIN_CDR_LE {00 01 00 00}
   ‖ members, with NO DHEADER (XCDR1 carries no APPENDABLE delimiter). Members = index(uint32 LE) ‖ string(uint32
   LE length-incl-NUL ‖ chars ‖ NUL). A Fast DDS DataReader at the example default DataReaderQos offers only XCDR1
   (an empty DATA_REPRESENTATION sequence = XCDR_DATA_REPRESENTATION, EDP::checkDataRepresentationQos), so it
   QoS-matches + decodes the :xcdr1 form; an XCDR2-only writer is data-representation-incompatible with it (the
   XTypes 1.3 Table 7.57 W=XCDR2/R=XCDR1 = false rule — the live ours2fast 'Incompatible Data Representation QoS')."
  (let* ((mbytes (map '(simple-array (unsigned-byte 8) (*)) #'char-code message))
         (slen   (1+ (length mbytes)))                 ; CDR string length includes the NUL
         (xcdr2  (eq rep :xcdr2))
         (dhdr   (if xcdr2 4 0))                        ; XCDR2 APPENDABLE DHEADER; XCDR1 has none
         (body-len (+ 4 4 slen))                        ; index(4) + strlen(4) + chars+NUL
         (out (make-array (+ 4 dhdr body-len) :element-type '(unsigned-byte 8) :initial-element 0))
         (i 4))
    (flet ((u32 (v) (setf (aref out i) (ldb (byte 8 0) v) (aref out (+ i 1)) (ldb (byte 8 8) v)
                          (aref out (+ i 2)) (ldb (byte 8 16) v) (aref out (+ i 3)) (ldb (byte 8 24) v))
             (incf i 4)))
      (setf (aref out 1) (if xcdr2 #x09 #x01))          ; D_CDR2_LE (XCDR2) / PLAIN_CDR_LE (XCDR1) encap id
      (when xcdr2 (u32 body-len))                       ; DHEADER — XCDR2 only
      (u32 index)                                       ; index
      (u32 slen)                                        ; string length (incl NUL)
      (replace out mbytes :start1 i)                    ; chars (trailing NUL already 0)
      out)))

(defun* %remote-states (p)
    (function (dds.dcps:domain-participant) string)
  "A compact \"prefix8=STATE\" summary of every remote P has discovered + its §8.7 auth state
   (NIL = discovered but no auth-remote record yet; :handshaking/:authenticated/:keyed = handshake progress)."
  (let ((node (dds.dcps::dp-node p)) (parts '()))
    (dolist (sp (dds.disc:node-discovered-participants node))
      (let* ((pre (dds.rtps.discovery:spdp-data-guid-prefix sp))
             (st  (ignore-errors (%am-remote-state p pre))))
        (push (format nil "~{~2,'0x~}=~a"
                      (coerce (subseq pre 0 4) 'list) (or st "nil"))
              parts)))
    (format nil "~{~a~^,~}" (nreverse parts))))

(defun* %any-remote-keyed-p (p)
    (function (dds.dcps:domain-participant) t)
  "T if P has reached :keyed with ANY discovered remote (crypto established cross-vendor)."
  (let ((node (dds.dcps::dp-node p)))
    (some (lambda (sp) (%am-remote-keyed-p p (dds.rtps.discovery:spdp-data-guid-prefix sp)))
          (dds.disc:node-discovered-participants node))))

(defun* %sample-plaintext (x)
    (function (t) (values (simple-array (unsigned-byte 8) (*)) (integer 0)))
  "Extract (values OCTETS LEN) from one node-take-loaned element X: a secured-loan-handle (read the plaintext
   IN PLACE over [0,LEN), zero copy) or a bare plaintext octet-vector (the non-loan / arena-carve-fail form)."
  (if (dds.disc:secured-loan-handle-p x)
      (values (dds.disc:secured-loan-bytes x) (dds.disc:secured-loan-handle-len x))
      (values x (length x))))

(defun* %decode-hello-world (payload len)
    (function ((simple-array (unsigned-byte 8) (*)) (integer 0))
              (values (or null (unsigned-byte 32)) (or null string)))
  "Deserialize a HelloWorld SerializedPayload PAYLOAD[0,LEN) (the plaintext of a decoded user sample; the
   inverse of %hello-world-payload) into (values INDEX MESSAGE). Reads the XTypes 1.3 §7.6.3.1.2 Table 60
   encapsulation id at octet 1 for endianness (LE iff its low bit is 1) and whether an XCDR2 DELIMITED/PL
   DHEADER prefixes the body (D_CDR2 0x08/0x09, PL_CDR2 0x0a/0x0b -> skip 4), then INDEX(uint32) ‖ strlen
   (uint32, incl NUL) ‖ chars ‖ NUL. Defensive: returns NIL fields when PAYLOAD is too short to hold them (a
   real decode failure already dropped fail-closed upstream; this is display-only, never a security gate)."
  (when (< len 12) (return-from %decode-hello-world (values nil nil)))
  (let* ((eid (aref payload 1))
         (le (logbitp 0 eid))
         (base (if (member eid '(#x08 #x09 #x0a #x0b)) 8 4)))
    (flet ((u32 (o) (if le
                        (logior (aref payload o) (ash (aref payload (+ o 1)) 8)
                                (ash (aref payload (+ o 2)) 16) (ash (aref payload (+ o 3)) 24))
                        (logior (ash (aref payload o) 24) (ash (aref payload (+ o 1)) 16)
                                (ash (aref payload (+ o 2)) 8) (aref payload (+ o 3))))))
      (when (> (+ base 8) len) (return-from %decode-hello-world (values nil nil)))
      (let ((index (u32 base)) (slen (u32 (+ base 4))) (soff (+ base 8)))
        (when (or (< slen 1) (> (+ soff slen) len))
          (return-from %decode-hello-world (values index nil)))
        (values index (map 'string #'code-char (subseq payload soff (+ soff (1- slen)))))))))

(defun* %key-id-hex (k)
    (function (t) string)
  "Hex-render a §9.5.2 sender_key_id octet vector K (or \"nil\") for the 2-secured-writer interop log."
  (if k (format nil "~{~2,'0x~}" (coerce k 'list)) "nil"))

(defun* %two-writer-key-ids (node id-a id-b)
    (function (dds.disc:disc-node (unsigned-byte 32) (unsigned-byte 32)) (values t t))
  "Register NODE's local EntityCryptos in a fresh crypto-manager exactly as cm-on-authenticated does, then
   return the §9.5.2 sender_key_id of writer ID-A's and writer ID-B's OWN EntityCrypto km (WP-N-ENDPOINT-S3,
   ADR 0048). The 2-secured-writer live run proves these DISTINCT on the wire — each writer keyed under its
   own km. Reuses run-security-n-secured-writer-test's assertion shape (control-plane, no OpenSSL needed)."
  (let ((cm (dds.dcps::make-crypto-manager)))
    (dolist (e (dds.dcps::%cm-local-token-entities node))
      (dds.dcps::cm-register-local-entity cm (car e) :kind (dds.dcps::%cm-entity-protection-kind node (car e))))
    (let ((km-a (dds.dcps::cm-encode-entity-km cm id-a))
          (km-b (dds.dcps::cm-encode-entity-km cm id-b)))
      (values (and km-a (dds.security:key-material-sender-key-id km-a))
              (and km-b (dds.security:key-material-sender-key-id km-b))))))

(defun* run-secure-interop-peer (&key (role "sub") (domain 0)
                                      ca cert key perm-ca governance permissions
                                      (topic "HelloWorldTopic") (topic2 "HelloWorldTopic2")
                                      (type "HelloWorld")
                                      (seconds 30) (peers "") (samples 5) (interval 0.5)
                                      (advertise "127.0.0.1") (port 0)
                                      (guid-byte #x7c))
    (function (&key (:role string) (:domain (integer 0))
                    (:ca string) (:cert string) (:key string) (:perm-ca string)
                    (:governance string) (:permissions string)
                    (:topic string) (:topic2 string) (:type string) (:seconds real) (:peers string)
                    (:samples (integer 0)) (:interval real) (:advertise string)
                    (:port (unsigned-byte 16)) (:guid-byte (unsigned-byte 8)))
              t)
  "Run ONE long-lived secure DomainParticipant for a live cross-vendor secure-discovery interop run
   (T12). CA/CERT/KEY = our DDS-Security identity (PEM paths); PERM-CA/GOVERNANCE/PERMISSIONS = the
   §8.4 AccessControl config (Permissions-CA PEM + signed S-MIME governance/permissions PEM paths).
   ROLE \"pub\" adds a reliable HelloWorld writer and publishes SAMPLES HelloWorld samples at INTERVAL
   s; \"sub\" adds a reliable reader and counts received samples. ROLE \"pub2\" (WP-N-ENDPOINT-S3, ADR 0048)
   stands up TWO independently-keyed secured writers on TOPIC + TOPIC2 (each its OWN EntityCrypto km) from ONE
   participant and publishes on EACH under its OWN EntityId (publish-sample writer-id = %local-user-writer-id-
   for-topic per topic), proving distinct §9.5.2 sender_key_ids so a live secured observer decodes both writers'
   DATA each under its own key (the S3 per-endpoint crypto on the wire). DOMAIN/PEERS/ADVERTISE/PORT plumb
   discovery (multicast plus optional \"host:port,...\" unicast peers, e.g. the Fast DDS metatraffic
   locator). Runs for SECONDS, spinning announcements, printing per-second discovered/matched/sample/
   keyed status, and a final SUMMARY + RESULT line the orchestrator greps. The receiver thread does the
   §8.7 handshake, PVMS crypto-token exchange, secure SEDP and rtps_protection decode; this loop drives
   the outbound side. Fail-soft: a peer-config error is reported, never crashes the harness."
  (handler-case (dds.dare:dare-available-p)
    (dds.dare:dare-unavailable (c)
      (format t "~&RESULT: SKIP — OpenSSL >= 3.5 unavailable: ~a~%" (dds.dare:dare-unavailable-reason c))
      (finish-output) (return-from run-secure-interop-peer t)))
  ;; Surface §8.7 handshake / crypto-token events from the receiver thread (global, not a dynamic
  ;; binding: the handshake runs on the receiver thread) — the cross-vendor reject-reason diagnostic.
  (setf dds.dcps::*auth-manager-log* *standard-output*)
  (let* ((ca-o (%slurp-octets ca)) (cert-o (%slurp-octets cert)) (key-o (%slurp-octets key))
         (perm-ca-o (%slurp-octets perm-ca)) (gov-o (%slurp-octets governance))
         (perm-o (%slurp-octets permissions))
         (guid (make-array 16 :element-type '(unsigned-byte 8) :initial-element guid-byte)))
    (multiple-value-bind (id reason) (dds.security:validate-local-identity ca-o cert-o key-o guid)
      (unless id
        (format t "~&RESULT: FAIL — validate-local-identity: ~a~%" reason)
        (finish-output) (return-from run-secure-interop-peer nil))
      (unwind-protect
           (let ((p (dds.dcps:create-participant
                     :domain domain :identity id :permissions-ca perm-ca-o
                     :governance gov-o :permissions perm-o :port port
                     :advertise-address advertise :peers (%parse-peer-list peers))))
             (unwind-protect
                  (let* ((node (dds.dcps::dp-node p))
                         (pub2p (string-equal role "pub2"))          ; WP-N-ENDPOINT-S3: two secured writers
                         (pubp (or (string-equal role "pub") pub2p))
                         (wqos (dds.qos:make-writer-qos :reliability :reliable :data-representation '(:xcdr1)))
                         (id-a nil) (id-b nil) (kid-a nil) (kid-b nil) (pub2-distinct nil))
                    ;; Fast DDS's example HelloWorld is NO_KEY (no @key member); declare our interop endpoint
                    ;; NO_KEY too (RTPS 2.5 §9.3.1.2 Table 9.1 writer 0x03 / reader 0x04) so the user match is not
                    ;; QoS-rejected on keyed-ness. Offer XCDR1 (PLAIN_CDR): the default DataReaderQos = XCDR1, so
                    ;; an XCDR2 writer is QoS-incompatible (XTypes 1.3 Table 7.57) and REJECTED before any crypto.
                    (cond
                      (pub2p
                       ;; TWO secured writers on distinct topics -> distinct EntityIds (S1 alloc); enable-publisher
                       ;; per writer registers each. Both NO_KEY + XCDR1 + reliable (match-compatible, as pub).
                       (dds.disc:add-local-writer node :topic topic :type type :keyed nil :qos wqos)
                       (dds.disc:enable-publisher node :history-kind :keep-all)
                       (dds.disc:add-local-writer node :topic topic2 :type type :keyed nil :qos wqos)
                       (dds.disc:enable-publisher node :history-kind :keep-all))
                      (pubp
                       (dds.disc:add-local-writer node :topic topic :type type :keyed nil :qos wqos)
                       (dds.disc:enable-publisher node :history-kind :keep-all))
                      (t
                       (dds.disc:add-local-reader node :topic topic :type type :keyed nil
                                                  :qos (dds.qos:make-reader-qos :reliability :reliable))
                       (dds.disc:enable-subscriber node)))
                    ;; Slice 5: honor each user topic's metadata_protection_kind on the user-DATA submessage tier.
                    ;; The harness builds the endpoint via add-local-{writer,reader} (to force NO_KEY for the Fast
                    ;; DDS HelloWorld match), bypassing create-data{writer,reader}, so set the kind here (the SAME
                    ;; %set-user-metadata-protection the dcps entity path calls — DRY) from the participant governance.
                    (if pub2p
                        (progn                                        ; ADR 0046: per-role, per-topic (BOTH writers)
                          (dds.dcps::%set-user-metadata-protection node (dds.dcps::dp-access-state p) topic :writer)
                          (dds.dcps::%set-user-metadata-protection node (dds.dcps::dp-access-state p) topic2 :writer))
                        (dds.dcps::%set-user-metadata-protection node (dds.dcps::dp-access-state p) topic
                                                                 (if pubp :writer :reader)))   ; ADR 0046: per-role
                    ;; WP-N-ENDPOINT-S3: resolve each writer's OWN EntityId + prove its OWN km's DISTINCT sender_key_id
                    ;; (the load-bearing bit — each writer publishes under its own km, NOT the primary).
                    (when pub2p
                      (setf id-a (dds.disc:%local-user-writer-id-for-topic node topic)
                            id-b (dds.disc:%local-user-writer-id-for-topic node topic2))
                      (multiple-value-setq (kid-a kid-b) (%two-writer-key-ids node id-a id-b))
                      (setf pub2-distinct (and kid-a kid-b (not (equalp kid-a kid-b))))
                      (format t "~&[pub2] writer-A topic=~a entityid=~6,'0x key_id=~a~%" topic id-a (%key-id-hex kid-a))
                      (format t "~&[pub2] writer-B topic=~a entityid=~6,'0x key_id=~a~%" topic2 id-b (%key-id-hex kid-b))
                      (format t "~&[pub2] distinct-key-ids=~a~%" pub2-distinct)
                      (finish-output))
                    (format t "~&[~a] secure participant up: domain=~d topic=~a type=~a guid-prefix=~{~2,'0x~} port=~d peers=~a~%"
                            role domain topic type (coerce (dds.disc:disc-node-guid-prefix node) 'list)
                            (dds.disc:disc-node-port node) peers)
                    (finish-output)
                    (let ((deadline (+ (get-internal-real-time)
                                       (* seconds internal-time-units-per-second)))
                          (sent 0) (last-tick 0) (peak-match 0) (peak-samples 0) (ever-keyed nil) (recv 0))
                      (loop
                        (dds.dcps:spin p)
                        (when (and pubp (< sent samples)
                                   (plusp (dds.disc:disc-node-matched-count node)))
                          (if pub2p
                              (progn   ; PER-WRITER publish: each writer under its OWN EntityId's km (the S3 send crux)
                                (dds.disc:publish-sample node (%hello-world-payload sent (format nil "Hello from ~a" topic) :xcdr1)
                                                         nil nil 0 nil id-a)
                                (dds.disc:publish-sample node (%hello-world-payload sent (format nil "Hello from ~a" topic2) :xcdr1)
                                                         nil nil 0 nil id-b)
                                (incf sent)
                                (format t "~&[pub2] SENT A(~a)+B(~a) index=~d~%" topic topic2 sent))
                              (progn
                                (dds.disc:publish-sample node (%hello-world-payload sent "Hello world from Lisp" :xcdr1))
                                (incf sent)
                                (format t "~&[pub] SENT HelloWorld index=~d~%" sent)))
                          (finish-output))
                        (let ((m (dds.disc:disc-node-matched-count node))
                              (s (dds.disc:node-sample-count node)))
                          (setf peak-match (max peak-match m) peak-samples (max peak-samples s))
                          (when (%any-remote-keyed-p p) (setf ever-keyed t))
                          (let ((now (get-internal-real-time)))
                            (when (> now (+ last-tick internal-time-units-per-second))
                              (setf last-tick now)
                              (format t "~&[~a] discovered=~d matched=~d samples=~d keyed=~a states=~a~%"
                                      role (dds.dcps:discovered-count p) m s
                                      (%any-remote-keyed-p p) (%remote-states p))
                              (finish-output))))
                        (when (> (get-internal-real-time) deadline) (return))
                        (sleep interval))
                      ;; Reverse-direction oracle (M7/P6 Slice 5b): decode + print the AEAD-decrypted Connext
                      ;; user samples (index+message) — the live decode is the proof ours OPENED Connext's
                      ;; GOV=secure protected DATA. Bare-vec or loan-handle; the take/return leaves the reliable
                      ;; state intact (return-loan releases any loan handle; bare vecs are read-only peeks).
                      (unless pubp
                        (multiple-value-bind (data cnt) (dds.disc:node-take-loaned node)
                          (dotimes (i cnt)
                            (multiple-value-bind (bytes blen) (%sample-plaintext (svref data i))
                              (multiple-value-bind (idx msg) (%decode-hello-world bytes blen)
                                (incf recv)
                                (format t "~&[sub] decoded HelloWorld #~d index=~a message=~s~%" recv idx msg))))
                          (finish-output)
                          (dds.disc:node-return-loan node data cnt)))
                      (when pub2p
                        (format t "~&SUMMARY-2W: topic=~a topic2=~a key-id-A=~a key-id-B=~a distinct-key-ids=~a~%"
                                topic topic2 (%key-id-hex kid-a) (%key-id-hex kid-b) pub2-distinct)
                        (finish-output))
                      (format t "~&SUMMARY: role=~a discovered=~d peak-matched=~d peak-samples=~d ever-keyed=~a sent=~d decoded=~d~%"
                              role (dds.dcps:discovered-count p) peak-match peak-samples ever-keyed sent recv)
                      ;; RESULT: a pub succeeds when it matched + sent; pub2 additionally requires the 2 writers'
                      ;; DISTINCT key_ids; a sub succeeds when it matched + received (peak-samples = delivered/AEAD-
                      ;; decrypted; recv = decoded-at-drain — either proves receipt).
                      (let ((ok (cond (pub2p (and (plusp peak-match) (plusp sent) pub2-distinct))
                                      (pubp  (and (plusp peak-match) (plusp sent)))
                                      (t     (and (plusp peak-match) (or (plusp peak-samples) (plusp recv)))))))
                        (format t "~&RESULT: ~a~%" (if ok "PASS" "FAIL")) (finish-output)
                        (return-from run-secure-interop-peer ok)))) ; through both unwind-protects
               (ignore-errors (dds.dcps:delete-participant p))))
        (dds.security:free-identity-handle id))))
  t)

(defun* run-security-2secured-writer-harness-test ()
    (function () t)
  "WP-2SECURED-WRITER-CONNEXT (validates WP-N-ENDPOINT-S3, ADR 0048): the our-to-our sanity for the
   2-secured-writer LIVE Connext harness MODE (run-secure-interop-peer ROLE \"pub2\"). Stands up ONE secured
   participant with TWO secured writers on TWO topics (the pub2 setup — no network), then asserts the harness's
   per-writer plumbing: (a) %local-user-writer-id-for-topic resolves EACH topic's OWN writer EntityId, DISTINCT;
   (b) %two-writer-key-ids returns each writer's OWN EntityCrypto km §9.5.2 sender_key_id, DISTINCT — the
   load-bearing proof that each writer is keyed under its OWN km (not the primary), so a live secured observer
   decodes both writers' DATA each under its own key; (c) %key-id-hex renders a resolved sender_key_id. Full
   send/decode crypto correctness (cross-key fails closed) is run-security-n-secured-writer-test; this proves the
   new harness MODE runs. Control-plane only (no OpenSSL/dare needed). Clasp FIRST."
  (let ((gov (dds.security:make-governance
              :discovery-protection-kind :none :liveliness-protection-kind :none :rtps-protection-kind :none
              :topic-rules
              (list (dds.security:make-topic-rule :topic-expr "HelloWorldTopic"
                                                  :metadata-protection-kind :encrypt :data-protection-kind :encrypt)
                    (dds.security:make-topic-rule :topic-expr "HelloWorldTopic2"
                                                  :metadata-protection-kind :encrypt :data-protection-kind :encrypt)))))
    (let ((ah (dds.security:make-access-handle :governance gov))
          (p (dds.dcps:create-participant :domain (test-domain +td-collect+))))
      (let ((node (dds.dcps::dp-node p)))
        (unwind-protect
             (progn
               (setf (dds.dcps::dp-auth-state p)
                     (dds.dcps::%make-auth-manager-state :identity (dds.security::%make-identity-handle)))
               (dds.dcps::%install-access-control p ah)
               ;; the pub2 setup: TWO secured writers on distinct topics -> distinct EntityIds
               (dds.disc:add-local-writer node :topic "HelloWorldTopic" :type "HelloWorld" :keyed nil)
               (dds.disc:enable-publisher node :history-kind :keep-all)
               (dds.disc:add-local-writer node :topic "HelloWorldTopic2" :type "HelloWorld" :keyed nil)
               (dds.disc:enable-publisher node :history-kind :keep-all)
               (let ((id-a (dds.disc:%local-user-writer-id-for-topic node "HelloWorldTopic"))
                     (id-b (dds.disc:%local-user-writer-id-for-topic node "HelloWorldTopic2")))
                 (%check :pub2-ids-resolved (and id-a id-b (/= id-a id-b))
                         "%local-user-writer-id-for-topic must resolve each topic's OWN writer EntityId (distinct)")
                 (multiple-value-bind (kid-a kid-b) (%two-writer-key-ids node id-a id-b)
                   (%check :pub2-distinct-key-ids
                           (and kid-a kid-b (not (equalp kid-a kid-b)))
                           "each secured writer resolves its OWN EntityCrypto km sender_key_id, DISTINCT (each under its own km, not the primary)")
                   (%check :pub2-key-id-hex
                           (and (plusp (length (%key-id-hex kid-a))) (string/= "nil" (%key-id-hex kid-a)))
                           "%key-id-hex renders a resolved sender_key_id"))))
          (dds.dcps:delete-participant p)))))
  t)
