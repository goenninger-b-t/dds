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

(defun* %hello-world-xcdr2 (index message)
    (function ((unsigned-byte 32) string) (simple-array (unsigned-byte 8) (*)))
  "Serialize Fast DDS's example type @extensibility(APPENDABLE) struct HelloWorld { unsigned long index;
   string message; } as an XCDR2 DELIMITED_CDR SerializedPayload (XTypes 1.3 §7.4.3.4 / RTPS 2.5 §10):
   encapsulation header D_CDR2_LE {00 09 00 00} ‖ DHEADER(uint32 LE = body length) ‖ index(uint32 LE) ‖
   string(uint32 LE length-incl-NUL ‖ chars ‖ NUL). The APPENDABLE DHEADER is what a Fast DDS reader
   strips before deserializing the members."
  (let* ((mbytes (map '(simple-array (unsigned-byte 8) (*)) #'char-code message))
         (slen   (1+ (length mbytes)))                 ; CDR string length includes the NUL
         (body-len (+ 4 4 slen))                       ; index(4) + strlen(4) + chars+NUL
         (out (make-array (+ 4 4 body-len) :element-type '(unsigned-byte 8) :initial-element 0))
         (i 0))
    (flet ((u32 (v) (setf (aref out i) (ldb (byte 8 0) v) (aref out (+ i 1)) (ldb (byte 8 8) v)
                          (aref out (+ i 2)) (ldb (byte 8 16) v) (aref out (+ i 3)) (ldb (byte 8 24) v))
             (incf i 4)))
      (setf (aref out 0) #x00 (aref out 1) #x09 (aref out 2) #x00 (aref out 3) #x00) ; D_CDR2_LE encap
      (setf i 4)
      (u32 body-len)                                   ; DHEADER
      (u32 index)                                      ; index
      (u32 slen)                                       ; string length (incl NUL)
      (replace out mbytes :start1 i) (incf i (length mbytes)) ; chars (NUL already 0)
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

(defun* run-secure-interop-peer (&key (role "sub") (domain 0)
                                      ca cert key perm-ca governance permissions
                                      (topic "HelloWorldTopic") (type "HelloWorld")
                                      (seconds 30) (peers "") (samples 5) (interval 0.5)
                                      (advertise "127.0.0.1") (port 0)
                                      (guid-byte #x7c))
    (function (&key (:role string) (:domain (integer 0))
                    (:ca string) (:cert string) (:key string) (:perm-ca string)
                    (:governance string) (:permissions string)
                    (:topic string) (:type string) (:seconds real) (:peers string)
                    (:samples (integer 0)) (:interval real) (:advertise string)
                    (:port (unsigned-byte 16)) (:guid-byte (unsigned-byte 8)))
              t)
  "Run ONE long-lived secure DomainParticipant for a live cross-vendor secure-discovery interop run
   (T12). CA/CERT/KEY = our DDS-Security identity (PEM paths); PERM-CA/GOVERNANCE/PERMISSIONS = the
   §8.4 AccessControl config (Permissions-CA PEM + signed S-MIME governance/permissions PEM paths).
   ROLE \"pub\" adds a reliable HelloWorld writer and publishes SAMPLES HelloWorld samples at INTERVAL
   s; \"sub\" adds a reliable reader and counts received samples. DOMAIN/PEERS/ADVERTISE/PORT plumb
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
                         (pubp (string-equal role "pub")))
                    (if pubp
                        (progn
                          (dds.disc:add-local-writer node :topic topic :type type
                                                     :qos (dds.qos:make-writer-qos :reliability :reliable))
                          (dds.disc:enable-publisher node :history-kind :keep-all))
                        (progn
                          (dds.disc:add-local-reader node :topic topic :type type
                                                     :qos (dds.qos:make-reader-qos :reliability :reliable))
                          (dds.disc:enable-subscriber node)))
                    (format t "~&[~a] secure participant up: domain=~d topic=~a type=~a guid-prefix=~{~2,'0x~} port=~d peers=~a~%"
                            role domain topic type (coerce (dds.disc:disc-node-guid-prefix node) 'list)
                            (dds.disc:disc-node-port node) peers)
                    (finish-output)
                    (let ((deadline (+ (get-internal-real-time)
                                       (* seconds internal-time-units-per-second)))
                          (sent 0) (last-tick 0) (peak-match 0) (peak-samples 0) (ever-keyed nil))
                      (loop
                        (dds.dcps:spin p)
                        (when (and pubp (< sent samples)
                                   (plusp (dds.disc:disc-node-matched-count node)))
                          (dds.disc:publish-sample node (%hello-world-xcdr2 sent "Hello world from Lisp"))
                          (incf sent)
                          (format t "~&[pub] SENT HelloWorld index=~d~%" sent) (finish-output))
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
                      (format t "~&SUMMARY: role=~a discovered=~d peak-matched=~d peak-samples=~d ever-keyed=~a sent=~d~%"
                              role (dds.dcps:discovered-count p) peak-match peak-samples ever-keyed sent)
                      ;; RESULT: a pub succeeds when it matched + sent; a sub succeeds when it matched + received.
                      (let ((ok (if pubp (and (plusp peak-match) (plusp sent))
                                    (and (plusp peak-match) (plusp peak-samples)))))
                        (format t "~&RESULT: ~a~%" (if ok "PASS" "FAIL")) (finish-output)
                        (return-from run-secure-interop-peer ok)))) ; through both unwind-protects
               (ignore-errors (dds.dcps:delete-participant p))))
        (dds.security:free-identity-handle id))))
  t)
