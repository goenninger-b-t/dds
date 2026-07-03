(in-package #:dds.tests)

;;; WP-DDS-SECURITY-ACCESS-CONTROL T2 — Governance/Permissions parser + allow/deny matcher tests.

(defun* %read-ac-xml (filename)
    (function (string) (simple-array (unsigned-byte 8) (*)))
  "Read an unsigned XML fixture file relative to +TEST-AC-PKI-ROOT+."
  (let* ((path (merge-pathnames filename dds.security:+test-ac-pki-root+)))
    (with-open-file (s path :element-type '(unsigned-byte 8))
      (let* ((n (file-length s))
             (v (make-array n :element-type '(unsigned-byte 8))))
        (read-sequence v s)
        v))))

(defun* run-access-governance-parse-test ()
    (function () t)
  "T2: parse governance.xml -> governance struct; assert allow-unauth=NIL, enable-join-ac=T, topic-rules."
  (let* ((xml (%read-ac-xml "governance.xml"))
         (gov (dds.security:parse-governance xml)))
    (%check :gov-not-nil     (not (null gov))                 "parse-governance returned NIL on fixture")
    (%check :gov-type        (dds.security:governance-p gov)  "result is not a governance struct")
    (%check :gov-allow-unauth
            (not (dds.security:governance-allow-unauthenticated gov))
            "allow_unauthenticated_participants must be false in fixture")
    (%check :gov-enable-join-ac
            (dds.security:governance-enable-join-ac gov)
            "enable_join_access_control must be true in fixture")
    (let ((rules (dds.security:governance-topic-rules gov)))
      (%check :gov-topic-rules-nonempty (not (null rules)) "topic-rules must be non-empty")
      (let ((r (first rules)))
        (%check :gov-topic-rule-type (dds.security:topic-rule-p r) "first rule is not a topic-rule struct")
        (%check :gov-topic-expr  (string= "*" (dds.security:topic-rule-topic-expr r))
                (format nil "first topic_expression must be '*'; got ~s" (dds.security:topic-rule-topic-expr r)))
        (%check :gov-read-ac     (dds.security:topic-rule-enable-read-ac r)
                "enable_read_access_control must be T for '*'")
        (%check :gov-write-ac    (dds.security:topic-rule-enable-write-ac r)
                "enable_write_access_control must be T for '*'")))
    (multiple-value-bind (r-ac w-ac) (dds.security:governance-topic-rule gov "Square")
      (%check :gov-rule-read  r-ac "governance-topic-rule must return read-ac=T for 'Square'")
      (%check :gov-rule-write w-ac "governance-topic-rule must return write-ac=T for 'Square'"))
    ;; Malformed inputs must return NIL
    (%check :gov-empty-nil
            (null (dds.security:parse-governance (make-array 0 :element-type '(unsigned-byte 8))))
            "empty octets must return NIL")
    (%check :gov-garbage-nil
            (null (dds.security:parse-governance (octets 60 104 116 109 108 62)))
            "garbage bytes must return NIL"))
  t)

(defun* run-access-permissions-parse-test ()
    (function () t)
  "T2: parse permissions.xml -> list of permissions structs; assert 4-grant count + EC grant fields."
  (let* ((xml       (%read-ac-xml "permissions.xml"))
         (perm-list (dds.security:parse-permissions xml))
         (perm      (find "/CN=TestParticipantEC/O=DDS-Test/C=DE" perm-list
                          :key #'dds.security:permissions-subject-name :test #'string=)))
    (%check :perm-list-not-nil (not (null perm-list)) "parse-permissions returned NIL on fixture")
    (%check :perm-list-count
            (= 4 (length perm-list))
            (format nil "expected 4 grants in fixture; got ~d" (length perm-list)))
    (%check :perm-not-nil  (not (null perm))                   "EC grant not found in parsed list")
    (%check :perm-type     (dds.security:permissions-p perm)   "EC grant is not a permissions struct")
    (%check :perm-subject
            (string= "/CN=TestParticipantEC/O=DDS-Test/C=DE"
                     (dds.security:permissions-subject-name perm))
            (format nil "subject-name mismatch: ~s" (dds.security:permissions-subject-name perm)))
    (%check :perm-not-before
            (string= "2026-01-01T00:00:00" (dds.security:permissions-not-before perm))
            (format nil "not-before mismatch: ~s" (dds.security:permissions-not-before perm)))
    (%check :perm-not-after
            (string= "2036-01-01T00:00:00" (dds.security:permissions-not-after perm))
            (format nil "not-after mismatch: ~s" (dds.security:permissions-not-after perm)))
    (%check :perm-default-deny
            (eq :deny (dds.security:permissions-default perm))
            "default must be :deny in fixture")
    (let ((rules (dds.security:permissions-rules perm)))
      ;; allow_rule yields 2 entries (publish + subscribe); deny_rule yields 2 more
      (%check :perm-rules-count
              (= 4 (length rules))
              (format nil "expected 4 rules; got ~d" (length rules)))
      (let ((r0 (first rules)))
        (%check :perm-r0-allow  (eq :allow   (car r0))  "rule[0] action must be :allow")
        (%check :perm-r0-pub    (eq :publish (cadr r0)) "rule[0] op must be :publish")
        (%check :perm-r0-square (member "Square" (cddr r0) :test #'string=)
                "rule[0] topics must contain 'Square'"))
      (let ((r2 (third rules)))
        (%check :perm-r2-deny   (eq :deny    (car r2))  "rule[2] action must be :deny")
        (%check :perm-r2-pub    (eq :publish (cadr r2)) "rule[2] op must be :publish")
        (%check :perm-r2-circle (member "Circle" (cddr r2) :test #'string=)
                "rule[2] topics must contain 'Circle'")))
    ;; Malformed inputs must return NIL (empty list is also nil/falsy in CL)
    (%check :perm-empty-nil
            (null (dds.security:parse-permissions (make-array 0 :element-type '(unsigned-byte 8))))
            "empty octets must return NIL")
    (%check :perm-garbage-nil
            (null (dds.security:parse-permissions (octets 65 66 67 68)))
            "garbage bytes must return NIL"))
  t)

(defun* run-access-matcher-test ()
    (function () t)
  "T2: allow/deny matcher — Square allowed, Circle denied, Triangle -> default DENY."
  (let* ((xml       (%read-ac-xml "permissions.xml"))
         (perm-list (dds.security:parse-permissions xml))
         (perm      (find "/CN=TestParticipantEC/O=DDS-Test/C=DE" perm-list
                          :key #'dds.security:permissions-subject-name :test #'string=)))
    (%check :matcher-not-nil (not (null perm)) "EC grant not found by parse-permissions")
    (%check :allow-pub-square
            (dds.security:permissions-allow-publish-p perm "Square")
            "permissions-allow-publish-p('Square') must be T")
    (%check :allow-sub-square
            (dds.security:permissions-allow-subscribe-p perm "Square")
            "permissions-allow-subscribe-p('Square') must be T")
    (%check :deny-pub-circle
            (not (dds.security:permissions-allow-publish-p perm "Circle"))
            "permissions-allow-publish-p('Circle') must be NIL (deny rule)")
    (%check :deny-sub-circle
            (not (dds.security:permissions-allow-subscribe-p perm "Circle"))
            "permissions-allow-subscribe-p('Circle') must be NIL (deny rule)")
    (%check :default-deny-triangle-pub
            (not (dds.security:permissions-allow-publish-p perm "Triangle"))
            "permissions-allow-publish-p('Triangle') must be NIL (no rule -> default DENY)")
    (%check :default-deny-triangle-sub
            (not (dds.security:permissions-allow-subscribe-p perm "Triangle"))
            "permissions-allow-subscribe-p('Triangle') must be NIL (no rule -> default DENY)"))
  t)

(defun* run-access-glob-test ()
    (function () t)
  "T2: %topic-match-p — */?-subset of POSIX fnmatch (§9.4.1.3.2.7): *, ?, literal, prefix*, *suffix, no-match."
  (flet ((m (p n) (dds.security::%topic-match-p p n)))
    (%check :glob-star-any    (m "*" "Square")           "* must match any non-empty string")
    (%check :glob-star-empty  (m "*" "")                 "* must match empty string")
    (%check :glob-literal-ok  (m "Square" "Square")      "literal exact match")
    (%check :glob-literal-no  (not (m "Square" "Circle")) "literal non-match")
    (%check :glob-q-match     (m "Sq??re" "Square")      "? matches single char (both ?)")
    (%check :glob-q-no        (not (m "Sq?re" "Square")) "? must match exactly one char")
    (%check :glob-prefix-ok   (m "Sq*" "Square")         "prefix* matches rest of string")
    (%check :glob-prefix-no   (not (m "Sq*" "Triangle")) "prefix* non-match on different prefix")
    (%check :glob-infix-ok    (m "*uare" "Square")       "*suffix matches suffix")
    (%check :glob-any-between (m "S*e" "Square")         "S*e matches 'Square'")
    (%check :glob-empty-both  (m "" "")                  "empty pattern matches empty string")
    (%check :glob-empty-str   (not (m "" "X"))           "empty pattern must not match non-empty"))
  t)

;;; Safety-0 inner loop compiled separately to exercise the call path without runtime checks (NFR-SEC-POSTURE).

(defun* %fuzz-ac-loop-s0 (blobs)
    (function (list) (unsigned-byte 32))
  "Feed each blob through both parsers at (safety 0); return count of nil-or-valid passes."
  (declare (optimize (safety 0) (speed 3)))
  (let ((n 0))
    (declare (type (unsigned-byte 32) n))
    (dolist (blob blobs n)
      (let ((g (dds.security:parse-governance blob))
            (p (dds.security:parse-permissions blob)))
        (when (or (null g) (dds.security:governance-p g)) (incf n))
        ;; parse-permissions returns (or list null); nil = malformed; list = zero-or-more grants
        (when (and (listp p) (every #'dds.security:permissions-p p)) (incf n))))))

(defun* run-access-parser-fuzz ()
    (function () t)
  "T2 fuzz: 2000 random/truncated blobs through both parsers (normal + safety-0); nil-or-valid, no crash."
  (let ((blobs '()))
    ;; Short blobs (0-63 bytes) — covers empty and sub-minimum truncation
    (dotimes (len 64)
      (let ((b (make-array len :element-type '(unsigned-byte 8))))
        (dotimes (i len) (setf (aref b i) (random 256)))
        (push b blobs)))
    ;; Mid-size and larger random blobs (fills total to 2000)
    (dotimes (_ (- 2000 64))
      (let* ((len (+ 64 (random 448)))
             (b   (make-array len :element-type '(unsigned-byte 8))))
        (dotimes (i len) (setf (aref b i) (random 256)))
        (push b blobs)))
    (setf blobs (nreverse blobs))
    ;; Normal-safety pass
    (dolist (blob blobs)
      (let ((g (dds.security:parse-governance blob))
            (p (dds.security:parse-permissions blob)))
        (%check :fuzz-gov-nil-or-valid
                (or (null g) (dds.security:governance-p  g))
                "parse-governance returned unexpected non-nil non-governance")
        ;; parse-permissions returns (or list null); valid = nil or list of permissions structs
        (%check :fuzz-perm-nil-or-valid
                (and (listp p) (every #'dds.security:permissions-p p))
                "parse-permissions returned non-nil non-list or list with non-permissions elements")))
    ;; Safety-0 pass via separately-compiled helper
    (let ((s0-n (%fuzz-ac-loop-s0 blobs)))
      (declare (ignore s0-n)))
    (format t "~&  [access-parser-fuzz] 2000 blobs: all nil-or-valid (normal + safety-0)~%"))
  t)

(defun* run-access-plugin-validate-test ()
    (function () t)
  "T3: validate-local-permissions + check predicates (DDS-Security 1.1 §8.4.2).
   (a) Good: non-nil handle; check-create-participant T; Square allowed; Circle denied.
   (b) validate-remote-permissions: non-nil; check-remote-datawriter/datareader Square/Circle.
   (c) Fail-closed: wrong local-subject → NIL; tampered governance.p7s → NIL. Both SBCL+Clasp."
  (handler-case (dds.dare:dare-available-p)
    (dds.dare:dare-unavailable (c)
      (format t "~&  [access-plugin-validate] SKIP: ~a~%" (dds.dare:dare-unavailable-reason c))
      (return-from run-access-plugin-validate-test t)))
  (let* ((perm-ca  (%read-ac-fixture-pem "perm-ca-cert.pem"))
         (gov-p7s  (%read-ac-fixture-pem "governance.p7s"))
         (perm-p7s (%read-ac-fixture-pem "permissions.p7s"))
         (subject  "/CN=TestParticipantEC/O=DDS-Test/C=DE"))
    (let ((h (dds.security:validate-local-permissions perm-ca gov-p7s perm-p7s subject)))
      (%check :ac-plugin-handle-non-nil (not (null h))
              "validate-local-permissions must return non-nil on valid fixtures")
      (%check :ac-plugin-handle-type (dds.security:access-handle-p h)
              "validate-local-permissions must return an access-handle struct")
      (unwind-protect
           (progn
             (%check :ac-plugin-create-participant
                     (dds.security:check-create-participant h)
                     "check-create-participant must return T (join-ac=T, permissions bound)")
             (%check :ac-plugin-writer-square
                     (dds.security:check-create-datawriter h "Square")
                     "check-create-datawriter('Square') must be T")
             (%check :ac-plugin-writer-circle
                     (not (dds.security:check-create-datawriter h "Circle"))
                     "check-create-datawriter('Circle') must be NIL (deny rule)")
             (%check :ac-plugin-reader-square
                     (dds.security:check-create-datareader h "Square")
                     "check-create-datareader('Square') must be T")
             (%check :ac-plugin-reader-circle
                     (not (dds.security:check-create-datareader h "Circle"))
                     "check-create-datareader('Circle') must be NIL (deny rule)")
             (let ((rp (dds.security:validate-remote-permissions h perm-p7s subject)))
               (%check :ac-plugin-remote-perms-non-nil (not (null rp))
                       "validate-remote-permissions must return non-nil for matching subject")
               (%check :ac-plugin-remote-perms-type (dds.security:permissions-p rp)
                       "validate-remote-permissions must return a permissions struct")
               (%check :ac-plugin-remote-writer-square
                       (dds.security:check-remote-datawriter h rp "Square")
                       "check-remote-datawriter('Square') must be T")
               (%check :ac-plugin-remote-writer-circle
                       (not (dds.security:check-remote-datawriter h rp "Circle"))
                       "check-remote-datawriter('Circle') must be NIL")
               (%check :ac-plugin-remote-reader-square
                       (dds.security:check-remote-datareader h rp "Square")
                       "check-remote-datareader('Square') must be T")
               (%check :ac-plugin-remote-reader-circle
                       (not (dds.security:check-remote-datareader h rp "Circle"))
                       "check-remote-datareader('Circle') must be NIL"))
             (let ((rp-wrong (dds.security:validate-remote-permissions h perm-p7s "/CN=WRONG/O=X/C=XX")))
               (%check :ac-plugin-remote-wrong-subject (null rp-wrong)
                       "validate-remote-permissions must return NIL for wrong remote-subject")))
        (dds.security:free-access-handle h)))
    (let ((h-ws (dds.security:validate-local-permissions perm-ca gov-p7s perm-p7s
                                                         "/CN=WRONG/O=X/C=XX")))
      (%check :ac-plugin-wrong-subject-nil (null h-ws)
              "validate-local-permissions must return NIL for wrong local-subject"))
    (let* ((tampered (copy-seq gov-p7s))
           (mid      (floor (length tampered) 2)))
      (setf (aref tampered mid) (logxor (aref tampered mid) #x01))
      (let ((h-t (dds.security:validate-local-permissions perm-ca tampered perm-p7s subject)))
        (%check :ac-plugin-tampered-gov-nil (null h-t)
                "validate-local-permissions must return NIL for tampered governance.p7s")))
    ;; I2(a): multi-grant — 2nd grant subject (ECB) must be found by select-by-subject (proves I1)
    ;; Under first-grant-only code this would return NIL since ECB is not the first grant.
    (let ((h-ecb (dds.security:validate-local-permissions
                  perm-ca gov-p7s perm-p7s
                  "/CN=TestParticipantECB/O=DDS-Test/C=DE")))
      (%check :ac-plugin-multigrant-ecb-non-nil (not (null h-ecb))
              "validate-local-permissions for 2nd grant (ECB) must return non-nil handle")
      (when h-ecb (dds.security:free-access-handle h-ecb))))
  ;; I2(b): asymmetric AC toggle (read-AC=T, write-AC=NIL) — directly detects C1 swap.
  ;; Builds structs without DARE so this runs regardless of OpenSSL availability.
  ;; With OLD swapped code: remote-writer would return T (bypass); remote-reader would return NIL (false-deny).
  (let* ((asym-gov (dds.security:make-governance
                    :allow-unauthenticated nil
                    :enable-join-ac t
                    :topic-rules (list (dds.security:make-topic-rule
                                        :topic-expr "Square"
                                        :enable-read-ac t :enable-write-ac nil))))
         ;; deny-perms: empty rules + default=:deny => publish/subscribe both NIL
         (deny-perms (dds.security:make-permissions
                      :subject-name "/CN=AsymTest/O=Test/C=DE"
                      :not-before "" :not-after ""
                      :default :deny :rules '()))
         ;; ca-store not used by check predicates; null-pointer is safe here
         (asym-ah (dds.security:make-access-handle
                   :governance asym-gov
                   :permissions deny-perms
                   :ca-store (cffi:null-pointer)
                   :subject "/CN=AsymTest/O=Test/C=DE")))
    ;; read-AC=T gates check-remote-datawriter: deny-perms denies publish => NIL
    (%check :ac-asym-toggle-remote-writer-nil
            (not (dds.security:check-remote-datawriter asym-ah deny-perms "Square"))
            "check-remote-datawriter(read-AC=T, deny-perms) must be NIL — read-AC enforced")
    ;; write-AC=NIL makes check-remote-datareader unrestricted => T
    (%check :ac-asym-toggle-remote-reader-t
            (dds.security:check-remote-datareader asym-ah deny-perms "Square")
            "check-remote-datareader(write-AC=NIL, deny-perms) must be T — write-AC off, unrestricted"))
  t)

;;; WP-DDS-SECURITY-ACCESS-CONTROL T5 — AccessControl MANAGER (dds-dcps) + permissions-gate unit test (DARE-free, unsigned XML); remote grant selected by authenticated subject; full e2e is T6.

(defun* %ac-test-endpoint (prefix kind topic)
    (function ((simple-array (unsigned-byte 8) (12)) (unsigned-byte 8) string)
              dds.rtps.discovery:endpoint-data)
  "A discovered endpoint with GUID = PREFIX(12) + the entityKind octet KIND in octet 15 (RTPS 2.5
   §9.3.1.2: user writer-with-key #x02, user reader-with-key #x07) on TOPIC; the gate reads the kind
   (%remote-writer-p) to pick the §8.4 remote check (datawriter vs datareader)."
  (let ((guid (make-array 16 :element-type '(unsigned-byte 8) :initial-element 0)))
    (replace guid prefix :end2 12)
    (setf (aref guid 15) kind)
    (dds.rtps.discovery:make-endpoint-data
     :guid guid :role (if (member kind '(#x02 #x03)) :writer :reader)
     :topic-name topic :type-name "ShapeType")))

(defun* %ac-insert-remote (node prefix subject state &optional (validated subject))
    (function (dds.disc:disc-node (simple-array (unsigned-byte 8) (12)) string symbol &optional string)
              dds.dcps::auth-remote)
  "Build + insert a Slice-2 auth-remote keyed by PREFIX into NODE's auth-state table, with STATE, a
   SELF-ASSERTED SPDP IdentityToken carrying cert-sn SUBJECT, and VALIDATED-SUBJECT set to VALIDATED
   (defaults to SUBJECT — the honest case where the §8.7.2.5-validated handshake-cert subject equals the
   advertised token cert-sn). The §8.4 gate authorizes on VALIDATED-SUBJECT, never the token; passing a
   VALIDATED that differs from SUBJECT models a peer that advertised a forged token cert-sn but whose
   handshake cert (hence validated subject) is something else. Returns the auth-remote so a caller may
   flip its state to exercise the not-:keyed -> :keyed path."
  (let ((ar (dds.dcps::%make-auth-remote
             :remote-token (dds.security::%build-identity-token
                            subject "ECDSA-SHA256" "/CN=TestPermCA/O=DDS-Test/C=DE" "ECDSA-SHA256")
             :validated-subject validated)))
    (setf (dds.dcps::auth-remote-state ar) state)
    (setf (gethash prefix (dds.disc:disc-node-auth-state node)) ar)
    ar))

(defun* run-access-manager-test ()
    (function () t)
  "T5: %install-access-control + %participant-permissions-gate (shared-document model, DARE-free).
   (a) install sets dp-access-state + the disc-node permissions-gate;
   (b) a keyed remote whose authenticated subject has the EC grant: Square WRITER -> :compatible,
       Circle WRITER -> :incompatible (check_remote_datawriter); Square READER -> :compatible,
       Circle READER -> :incompatible (check_remote_datareader) — real allow/deny + direction;
   (c) no auth-remote, and a genuinely in-flight (:handshaking) one -> :pending (parked); an :authenticated
       remote under this all-NONE governance -> :compatible (§8.5 keying not a match precondition, §8.4.2.9);
   (d) a keyed remote whose authenticated subject has NO grant -> :incompatible (no permissions -> deny)."
  (let* ((subject  "/CN=TestParticipantEC/O=DDS-Test/C=DE")
         (grants   (dds.security:parse-permissions (%read-ac-xml "permissions.xml")))
         (gov      (dds.security:parse-governance  (%read-ac-xml "governance.xml")))
         (ec-grant (find subject grants :key #'dds.security:permissions-subject-name :test #'string=))
         (ah       (dds.security:make-access-handle
                    :governance gov :permissions ec-grant :grants grants
                    :ca-store (cffi:null-pointer) :subject subject)))
    (%check :am-grants-4 (= 4 (length grants))
            (format nil "expected 4 grants in the shared Permissions; got ~d" (length grants)))
    (%check :am-ec-grant (not (null ec-grant)) "EC grant must be present in the shared Permissions")
    (let ((p (dds.dcps:create-participant :domain (test-domain +td-collect+))))
      (unwind-protect
           (let* ((node   (dds.dcps::dp-node p))
                  (prefix (make-array 12 :element-type '(unsigned-byte 8) :initial-element #xAA))
                  (sq-w   (%ac-test-endpoint prefix #x02 "Square"))
                  (ci-w   (%ac-test-endpoint prefix #x02 "Circle"))
                  (sq-r   (%ac-test-endpoint prefix #x07 "Square"))
                  (ci-r   (%ac-test-endpoint prefix #x07 "Circle"))
                  (local  (%ac-test-endpoint
                           (make-array 12 :element-type '(unsigned-byte 8) :initial-element #x11)
                           #x07 "Square")))
             ;; fake auth manager state — the gate uses only its lock, never the identity (DARE-free)
             (setf (dds.dcps::dp-auth-state p)
                   (dds.dcps::%make-auth-manager-state :identity (dds.security::%make-identity-handle)))
             ;; (a) install the manager
             (dds.dcps::%install-access-control p ah)
             (%check :am-dp-access-state (eq ah (dds.dcps::dp-access-state p))
                     "%install-access-control must store the access-handle in dp-access-state")
             (%check :am-gate-installed (not (null (dds.disc:disc-node-permissions-gate node)))
                     "%install-access-control must install the disc-node permissions-gate")
             ;; (c) no auth-remote yet -> :pending (auth has not started)
             (%check :am-no-authremote-pending
                     (eq :pending (dds.dcps::%participant-permissions-gate p node sq-w local))
                     "no auth-remote (auth not started) must be :pending")
             ;; genuinely in-flight auth-remote (handshake NOT complete) -> :pending (parked until auth settles)
             (let ((ar (%ac-insert-remote node prefix subject :handshaking)))
               (%check :am-handshaking-pending
                       (eq :pending (dds.dcps::%participant-permissions-gate p node sq-w local))
                       "auth-remote :handshaking (auth in flight) must be :pending")
               ;; §8.4.2.9 / §8.5: governance.xml mandates NO protection (every kind NONE) so disc-node-crypto-
               ;; keying-required-p is NIL -> §8.5 keying is NOT a match precondition. At :authenticated (auth
               ;; complete, the §8.7.2.5 validated subject bound) the gate authorizes on §8.7 auth + §8.4 permissions
               ;; alone: the EC grant allows Square + remote writer -> :compatible (a keyed remote is not required —
               ;; a conformant peer such as RTI Connext sends no crypto token at GOV=none).
               (setf (dds.dcps::auth-remote-state ar) :authenticated)
               (%check :am-authenticated-noprotection-compatible
                       (eq :compatible (dds.dcps::%participant-permissions-gate p node sq-w local))
                       "auth-remote :authenticated + all-NONE governance -> :compatible (keying not a match precondition, §8.4.2.9)")
               ;; (b) flip to :keyed -> the real allow/deny matcher decides per topic + direction (unchanged)
               (setf (dds.dcps::auth-remote-state ar) :keyed)
               (%check :am-keyed-square-writer-compatible
                       (eq :compatible (dds.dcps::%participant-permissions-gate p node sq-w local))
                       "keyed + EC grant allows Square + remote writer -> :compatible")
               (%check :am-keyed-circle-writer-incompatible
                       (eq :incompatible (dds.dcps::%participant-permissions-gate p node ci-w local))
                       "keyed + EC grant denies Circle (deny rule) + remote writer -> :incompatible")
               (%check :am-keyed-square-reader-compatible
                       (eq :compatible (dds.dcps::%participant-permissions-gate p node sq-r local))
                       "keyed + EC grant allows Square + remote reader -> :compatible")
               (%check :am-keyed-circle-reader-incompatible
                       (eq :incompatible (dds.dcps::%participant-permissions-gate p node ci-r local))
                       "keyed + EC grant denies Circle + remote reader -> :incompatible"))
             ;; (d) a keyed remote whose authenticated subject has NO grant in the shared doc -> :incompatible
             (let* ((ng-prefix (make-array 12 :element-type '(unsigned-byte 8) :initial-element #xBB))
                    (ng-w      (%ac-test-endpoint ng-prefix #x02 "Square")))
               (%ac-insert-remote node ng-prefix "/CN=Stranger/O=Nope/C=ZZ" :keyed)
               (%check :am-keyed-nogrant-incompatible
                       (eq :incompatible (dds.dcps::%participant-permissions-gate p node ng-w local))
                       "keyed remote whose authenticated subject has NO grant must be :incompatible"))
             ;; (e) PRIVILEGE-ESCALATION exploit: a keyed remote whose SELF-ASSERTED SPDP IdentityToken
             ;; CLAIMS the privileged granted subject (SUBJECT = /CN=TestParticipantEC, which HAS a Square
             ;; grant) but whose VALIDATED handshake-cert subject is the UN-granted /CN=Eve. The fix
             ;; authorizes on the validated subject -> no grant -> :incompatible. The pre-fix gate read the
             ;; token claim -> found the EC grant -> wrongly :compatible (the hole). MUST be :incompatible.
             (let* ((evil-prefix (make-array 12 :element-type '(unsigned-byte 8) :initial-element #xDD))
                    (evil-w      (%ac-test-endpoint evil-prefix #x02 "Square")))
               (%ac-insert-remote node evil-prefix subject :keyed "/CN=Eve/O=Attacker/C=XX")
               (%check :am-exploit-validated-subject-incompatible
                       (eq :incompatible (dds.dcps::%participant-permissions-gate p node evil-w local))
                       "PRIVILEGE ESCALATION: a remote whose token claims the granted /CN=TestParticipantEC but whose VALIDATED cert subject is the un-granted /CN=Eve must be :incompatible (authorize on the validated subject, never the self-asserted token)"))
             ;; Non-masking direction assertion: grant allows PUBLISH but denies SUBSCRIBE on "Asym".
             ;; A writer/reader direction swap in the gate inverts both verdicts — this detects it.
             (let* ((dir-gov    (dds.security:make-governance
                                 :allow-unauthenticated nil :enable-join-ac t
                                 :topic-rules (list (dds.security:make-topic-rule  ; read-AC=T, write-AC=T
                                                     :topic-expr "*"
                                                     :enable-read-ac t :enable-write-ac t))))
                    ;; allow-publish "Asym" only; subscribe falls through to default :deny
                    (dir-perms  (dds.security:make-permissions
                                 :subject-name "/CN=DirTest/O=DDS-Test/C=DE"
                                 :not-before "" :not-after "" :default :deny
                                 :rules (list (list :allow :publish "Asym"))))
                    (dir-ah     (dds.security:make-access-handle
                                 :governance dir-gov :permissions dir-perms
                                 :grants (list dir-perms)
                                 :ca-store (cffi:null-pointer)
                                 :subject "/CN=DirTest/O=DDS-Test/C=DE"))
                    (dir-prefix (make-array 12 :element-type '(unsigned-byte 8) :initial-element #xCC))
                    (dir-w      (%ac-test-endpoint dir-prefix #x02 "Asym"))   ; remote writer
                    (dir-r      (%ac-test-endpoint dir-prefix #x07 "Asym"))   ; remote reader
                    (orig-ah    (dds.dcps::dp-access-state p)))
               (%ac-insert-remote node dir-prefix "/CN=DirTest/O=DDS-Test/C=DE" :keyed)
               (setf (dds.dcps::dp-access-state p) dir-ah)
               (unwind-protect
                   (progn
                     ;; check-remote-datawriter: read-AC=T -> publish allowed -> :compatible
                     (%check :am-dir-writer-compatible
                             (eq :compatible (dds.dcps::%participant-permissions-gate p node dir-w local))
                             "direction: remote writer on Asym must be :compatible (publish allowed)")
                     ;; check-remote-datareader: write-AC=T -> subscribe denied -> :incompatible
                     (%check :am-dir-reader-incompatible
                             (eq :incompatible (dds.dcps::%participant-permissions-gate p node dir-r local))
                             "direction: remote reader on Asym must be :incompatible (subscribe denied)"))
                 ;; restore original access-handle before delete-participant frees it
                 (setf (dds.dcps::dp-access-state p) orig-ah))))
        (dds.dcps:delete-participant p))))
  t)

;;; WP-DDS-SECURITY-ACCESS-CONTROL T6 — headline integration (allow/deny e2e, local-deny, default-off): full gate ladder (auth-gate -> permissions-gate) e2e, real participants + signed docs + wire.

(defun* run-access-control-allow-deny-test ()
    (function () t)
  "WP-DDS-SECURITY-ACCESS-CONTROL T6a: permissions-gate allow/deny end-to-end — our-to-our.
   ALLOW pair (domain 85): EC + ECB identities with shared governance.p7s + permissions.p7s;
   Square writer on sq-a, Square reader on sq-b; both reach :keyed, Square endpoints MATCH,
   and a Square sample (8 bytes 'SQTST001') round-trips byte-exact.
   DENY pair (domain 86): fresh EC + ECB identities, same AC config; Circle writer on ci-a,
   Circle reader on ci-b; both reach :keyed (auth passes) but the Circle endpoints do NOT match
   (permissions-gate :incompatible — EC + ECB grants both deny Circle pub/sub).
   NON-VACUOUS: sq-b matched-count >= 1 (Square allowed) AND ci-b matched-count = 0 (Circle denied);
   the ONLY difference is the topic name — same identities, same auth :keyed, same QoS/type.
   Requires OpenSSL >= 3.5; skips gracefully if absent. Both SBCL and Clasp must pass."
  (handler-case (dds.dare:dare-available-p)
    (dds.dare:dare-unavailable (c)
      (format t "~&  [ac-allow-deny] SKIP — OpenSSL >= 3.5 not available: ~a~%"
              (dds.dare:dare-unavailable-reason c))
      (return-from run-access-control-allow-deny-test t)))

  (let* ((ca-pem      (%read-fixture-pem "ca/ca-cert.pem"))
         (ec-cert-a   (%read-fixture-pem "participant_ec/identity_cert.pem"))
         (ec-key-a    (%read-fixture-pem "participant_ec/identity_key.pem"))
         (ec-cert-b   (%read-fixture-pem "participant_ec_b/identity_cert.pem"))
         (ec-key-b    (%read-fixture-pem "participant_ec_b/identity_key.pem"))
         ;; AC config — shared governance.p7s + permissions.p7s, signed by perm-ca-cert.pem
         (perm-ca     (%read-ac-fixture-pem "perm-ca-cert.pem"))
         (gov-p7s     (%read-ac-fixture-pem "governance.p7s"))
         (perm-p7s    (%read-ac-fixture-pem "permissions.p7s"))
         ;; identity GUIDs — sq-a (0x01..) < sq-b (0xC8..) forces A=requester (§8.7.2.4 GUID order)
         (guid-sq-a   (make-array 16 :element-type '(unsigned-byte 8)
                                     :initial-contents '(1 2 3 4 5 6 7 8 9 10 11 12 13 14 15 1)))
         (guid-sq-b   (make-array 16 :element-type '(unsigned-byte 8)
                                     :initial-contents '(200 2 3 4 5 6 7 8 9 10 11 12 13 14 15 1)))
         (guid-ci-a   (make-array 16 :element-type '(unsigned-byte 8)
                                     :initial-contents '(1 2 3 4 5 6 7 8 9 10 11 12 13 14 15 2)))
         (guid-ci-b   (make-array 16 :element-type '(unsigned-byte 8)
                                     :initial-contents '(200 2 3 4 5 6 7 8 9 10 11 12 13 14 15 2)))
         ;; known plaintext — 8 bytes, not a valid CDR pattern, distinguishable from zeros
         (sq-pt       (make-array 8 :element-type '(unsigned-byte 8)
                                    :initial-contents '(#x53 #x51 #x54 #x53 #x54 #x30 #x30 #x31))))
    (multiple-value-bind (id-sq-a reason-sq-a)
        (dds.security:validate-local-identity ca-pem ec-cert-a ec-key-a guid-sq-a)
      (%check :acad-id-sq-a (not (null id-sq-a))
              (format nil "validate-local-identity sq-a failed: ~a" reason-sq-a))
      (unless id-sq-a (return-from run-access-control-allow-deny-test t))
      (unwind-protect
           (multiple-value-bind (id-sq-b reason-sq-b)
               (dds.security:validate-local-identity ca-pem ec-cert-b ec-key-b guid-sq-b)
             (%check :acad-id-sq-b (not (null id-sq-b))
                     (format nil "validate-local-identity sq-b failed: ~a" reason-sq-b))
             (unless id-sq-b (return-from run-access-control-allow-deny-test t))
             (unwind-protect
                  (multiple-value-bind (id-ci-a reason-ci-a)
                      (dds.security:validate-local-identity ca-pem ec-cert-a ec-key-a guid-ci-a)
                    (%check :acad-id-ci-a (not (null id-ci-a))
                            (format nil "validate-local-identity ci-a failed: ~a" reason-ci-a))
                    (unless id-ci-a (return-from run-access-control-allow-deny-test t))
                    (unwind-protect
                         (multiple-value-bind (id-ci-b reason-ci-b)
                             (dds.security:validate-local-identity ca-pem ec-cert-b ec-key-b guid-ci-b)
                           (%check :acad-id-ci-b (not (null id-ci-b))
                                   (format nil "validate-local-identity ci-b failed: ~a" reason-ci-b))
                           (unless id-ci-b (return-from run-access-control-allow-deny-test t))
                           (unwind-protect
                                ;; create-participant installs identity + AC (validate-local-permissions,
                                ;; check_create_participant, and %install-access-control) fail-closed
                                (let ((p-sq-a (dds.dcps:create-participant
                                               :domain (test-domain +td-ac-allow+) :identity id-sq-a
                                               :permissions-ca perm-ca :governance gov-p7s :permissions perm-p7s))
                                      (p-sq-b (dds.dcps:create-participant
                                               :domain (test-domain +td-ac-allow+) :identity id-sq-b
                                               :permissions-ca perm-ca :governance gov-p7s :permissions perm-p7s))
                                      (p-ci-a (dds.dcps:create-participant
                                               :domain (test-domain +td-ac-deny+) :identity id-ci-a
                                               :permissions-ca perm-ca :governance gov-p7s :permissions perm-p7s))
                                      (p-ci-b (dds.dcps:create-participant
                                               :domain (test-domain +td-ac-deny+) :identity id-ci-b
                                               :permissions-ca perm-ca :governance gov-p7s :permissions perm-p7s)))
                                  (unwind-protect
                                       (let* ((node-sq-a (dds.dcps::dp-node p-sq-a))
                                              (node-sq-b (dds.dcps::dp-node p-sq-b))
                                              (node-ci-a (dds.dcps::dp-node p-ci-a))
                                              (node-ci-b (dds.dcps::dp-node p-ci-b))
                                              (prefix-sq-a (dds.disc:disc-node-guid-prefix node-sq-a))
                                              (prefix-sq-b (dds.disc:disc-node-guid-prefix node-sq-b))
                                              (prefix-ci-a (dds.disc:disc-node-guid-prefix node-ci-a))
                                              (prefix-ci-b (dds.disc:disc-node-guid-prefix node-ci-b))
                                              (wqos (dds.qos:make-writer-qos :reliability :reliable
                                                                              :durability :transient-local))
                                              (rqos (dds.qos:make-reader-qos :reliability :reliable
                                                                              :durability :transient-local)))
                                         ;; confirm AC installed on all four participants
                                         (%check :acad-sq-a-ac (not (null (dds.dcps::dp-access-state p-sq-a)))
                                                 "sq-a must have dp-access-state set (AC installed)")
                                         (%check :acad-sq-b-ac (not (null (dds.dcps::dp-access-state p-sq-b)))
                                                 "sq-b must have dp-access-state set (AC installed)")
                                         (%check :acad-ci-a-ac (not (null (dds.dcps::dp-access-state p-ci-a)))
                                                 "ci-a must have dp-access-state set (AC installed)")
                                         (%check :acad-ci-b-ac (not (null (dds.dcps::dp-access-state p-ci-b)))
                                                 "ci-b must have dp-access-state set (AC installed)")
                                         ;; wire unicast peers — ALLOW pair (sq) and DENY pair (ci) are isolated
                                         (setf (dds.disc:disc-node-peers node-sq-a)
                                               (list (cons "127.0.0.1" (dds.disc:disc-node-port node-sq-b))))
                                         (setf (dds.disc:disc-node-peers node-sq-b)
                                               (list (cons "127.0.0.1" (dds.disc:disc-node-port node-sq-a))))
                                         (setf (dds.disc:disc-node-peers node-ci-a)
                                               (list (cons "127.0.0.1" (dds.disc:disc-node-port node-ci-b))))
                                         (setf (dds.disc:disc-node-peers node-ci-b)
                                               (list (cons "127.0.0.1" (dds.disc:disc-node-port node-ci-a))))
                                         ;; add endpoints BEFORE the handshake; matched after :keyed (same as keyx test)
                                         ;; ALLOW: Square writer on sq-a, Square reader on sq-b (disc layer = no local AC re-check)
                                         (dds.disc:add-local-writer node-sq-a :topic "Square" :type "ShapeType" :qos wqos)
                                         (dds.disc:enable-publisher node-sq-a :history-kind :keep-all)
                                         (dds.disc:add-local-reader node-sq-b :topic "Square" :type "ShapeType" :qos rqos)
                                         (dds.disc:enable-subscriber node-sq-b)
                                         ;; DENY: Circle writer on ci-a, Circle reader on ci-b (local AC bypassed at disc layer; remote permissions-gate fires after :keyed and blocks the match)
                                         (dds.disc:add-local-writer node-ci-a :topic "Circle" :type "ShapeType" :qos wqos)
                                         (dds.disc:enable-publisher node-ci-a :history-kind :keep-all)
                                         (dds.disc:add-local-reader node-ci-b :topic "Circle" :type "ShapeType" :qos rqos)
                                         (dds.disc:enable-subscriber node-ci-b)
                                         ;; NON-VACUITY pre-check: neither pair is :keyed yet
                                         (%check :acad-not-keyed-before
                                                 (and (not (%am-remote-keyed-p p-sq-a prefix-sq-b))
                                                      (not (%am-remote-keyed-p p-sq-b prefix-sq-a))
                                                      (not (%am-remote-keyed-p p-ci-a prefix-ci-b))
                                                      (not (%am-remote-keyed-p p-ci-b prefix-ci-a)))
                                                 "no remote may be :keyed before the handshake/key-exchange completes")
                                         ;; drive auth + key-exchange to :keyed for BOTH pairs (~6 s budget)
                                         (loop repeat 300
                                               until (and (%am-remote-keyed-p p-sq-a prefix-sq-b)
                                                          (%am-remote-keyed-p p-sq-b prefix-sq-a)
                                                          (%am-remote-keyed-p p-ci-a prefix-ci-b)
                                                          (%am-remote-keyed-p p-ci-b prefix-ci-a))
                                               do (dds.dcps:spin p-sq-a) (dds.dcps:spin p-sq-b)
                                                  (dds.dcps:spin p-ci-a) (dds.dcps:spin p-ci-b)
                                                  (sleep 0.02))
                                         ;; assert auth :keyed for both pairs — auth-gate is NOT the cause of any non-match
                                         (%check :acad-sq-a-keyed (%am-remote-keyed-p p-sq-a prefix-sq-b)
                                                 (format nil "sq-a did not reach :keyed for sq-b (state ~a)"
                                                         (%am-remote-state p-sq-a prefix-sq-b)))
                                         (%check :acad-sq-b-keyed (%am-remote-keyed-p p-sq-b prefix-sq-a)
                                                 (format nil "sq-b did not reach :keyed for sq-a (state ~a)"
                                                         (%am-remote-state p-sq-b prefix-sq-a)))
                                         (%check :acad-ci-a-keyed (%am-remote-keyed-p p-ci-a prefix-ci-b)
                                                 (format nil "ci-a did not reach :keyed for ci-b (state ~a)"
                                                         (%am-remote-state p-ci-a prefix-ci-b)))
                                         (%check :acad-ci-b-keyed (%am-remote-keyed-p p-ci-b prefix-ci-a)
                                                 (format nil "ci-b did not reach :keyed for ci-a (state ~a)"
                                                         (%am-remote-state p-ci-b prefix-ci-a)))
                                         ;; wait for the ALLOW (Square) pair to match and deliver a sample
                                         (loop repeat 300
                                               until (>= (dds.disc:disc-node-matched-count node-sq-b) 1)
                                               do (dds.dcps:spin p-sq-a) (dds.dcps:spin p-sq-b) (sleep 0.02))
                                         (%check :acad-sq-matched
                                                 (>= (dds.disc:disc-node-matched-count node-sq-b) 1)
                                                 (format nil "ALLOW: Square reader sq-b did not match (count ~d)"
                                                         (dds.disc:disc-node-matched-count node-sq-b)))
                                         ;; publish a Square sample and wait for delivery
                                         (dds.disc:publish-sample node-sq-a sq-pt)
                                         (loop repeat 300
                                               until (plusp (dds.disc:node-sample-count node-sq-b))
                                               do (dds.dcps:spin p-sq-a) (dds.dcps:spin p-sq-b) (sleep 0.02))
                                         (%check :acad-sq-received
                                                 (plusp (dds.disc:node-sample-count node-sq-b))
                                                 "ALLOW: sq-b did not receive a Square sample from sq-a")
                                         ;; assert Square sample byte-exact round-trip
                                         (let* ((sq-key     (first (dds.disc:node-sample-sns node-sq-b)))
                                                (sq-payload (dds.disc:node-sample node-sq-b sq-key)))
                                           (%check :acad-sq-byte-exact
                                                   (and sq-payload (equalp sq-payload sq-pt))
                                                   (format nil "ALLOW: Square sample byte mismatch; got ~a expected ~{~2,'0x~^ ~}"
                                                           (and sq-payload (coerce sq-payload 'list))
                                                           (coerce sq-pt 'list))))
                                         ;; give the DENY (Circle) pair time to settle (permissions-gate fires after :keyed)
                                         (loop repeat 100
                                               do (dds.dcps:spin p-ci-a) (dds.dcps:spin p-ci-b) (sleep 0.02))
                                         ;; NON-VACUOUS headline assertion: Square matched, Circle did NOT match
                                         (%check :acad-sq-count-ge1
                                                 (>= (dds.disc:disc-node-matched-count node-sq-b) 1)
                                                 (format nil "NON-VACUOUS: Square reader matched-count ~d (expect >= 1)"
                                                         (dds.disc:disc-node-matched-count node-sq-b)))
                                         (%check :acad-ci-count-zero
                                                 (zerop (dds.disc:disc-node-matched-count node-ci-b))
                                                 (format nil "DENY: Circle reader ci-b matched ~d endpoint(s) — permissions-gate must return :incompatible for a Circle endpoint (grant denies Circle pub/sub)"
                                                         (dds.disc:disc-node-matched-count node-ci-b))))
                                    (ignore-errors (dds.dcps:delete-participant p-ci-b))
                                    (ignore-errors (dds.dcps:delete-participant p-ci-a))
                                    (ignore-errors (dds.dcps:delete-participant p-sq-b))
                                    (ignore-errors (dds.dcps:delete-participant p-sq-a))))
                             (dds.security:free-identity-handle id-ci-b)))
                      (dds.security:free-identity-handle id-ci-a)))
               (dds.security:free-identity-handle id-sq-b)))
        (dds.security:free-identity-handle id-sq-a))))
  t)

(defun* run-access-control-local-deny-test ()
    (function () t)
  "WP-DDS-SECURITY-ACCESS-CONTROL T6b: local check_create_datawriter / check_create_datareader deny.
   A security-enabled participant (EC identity + shared AC config) on domain 87:
   (a) create-datawriter on a 'Circle' topic SIGNALS a clear access-denied error — the local
       check_create_datawriter sees the EC grant denies Circle publish (fail-closed).
   (b) create-datawriter on a 'Square' topic SUCCEEDS — EC grant allows Square publish.
   (c) create-datareader on a 'Circle' topic SIGNALS access-denied (EC grant denies Circle subscribe).
   (d) create-datareader on a 'Square' topic SUCCEEDS (EC grant allows Square subscribe).
   Both SBCL and Clasp must pass."
  (handler-case (dds.dare:dare-available-p)
    (dds.dare:dare-unavailable (c)
      (format t "~&  [ac-local-deny] SKIP — OpenSSL >= 3.5 not available: ~a~%"
              (dds.dare:dare-unavailable-reason c))
      (return-from run-access-control-local-deny-test t)))

  (let* ((ca-pem    (%read-fixture-pem "ca/ca-cert.pem"))
         (ec-cert   (%read-fixture-pem "participant_ec/identity_cert.pem"))
         (ec-key    (%read-fixture-pem "participant_ec/identity_key.pem"))
         (perm-ca   (%read-ac-fixture-pem "perm-ca-cert.pem"))
         (gov-p7s   (%read-ac-fixture-pem "governance.p7s"))
         (perm-p7s  (%read-ac-fixture-pem "permissions.p7s"))
         (guid-ld   (make-array 16 :element-type '(unsigned-byte 8)
                                   :initial-contents '(3 0 0 0 0 0 0 0 0 0 0 0 0 0 0 1))))
    (multiple-value-bind (id-ld reason-ld)
        (dds.security:validate-local-identity ca-pem ec-cert ec-key guid-ld)
      (%check :acld-id-ok (not (null id-ld))
              (format nil "validate-local-identity failed: ~a" reason-ld))
      (unless id-ld (return-from run-access-control-local-deny-test t))
      (unwind-protect
           (let ((p-ld (dds.dcps:create-participant
                        :domain (test-domain +td-multitopic+) :identity id-ld
                        :permissions-ca perm-ca :governance gov-p7s :permissions perm-p7s)))
             (unwind-protect
                  (let* ((pub      (dds.dcps:create-publisher p-ld))
                         (sub      (dds.dcps:create-subscriber p-ld))
                         ;; nil type-support: AC check fires before any codec or type-info is needed
                         (sq-topic (dds.dcps:create-topic p-ld "Square" "ShapeType" nil))
                         (ci-topic (dds.dcps:create-topic p-ld "Circle" "ShapeType" nil))
                         (wqos     (dds.qos:make-writer-qos :reliability :best-effort))
                         (rqos     (dds.qos:make-reader-qos :reliability :best-effort)))
                    ;; (a) Circle publish: local check_create_datawriter MUST signal an error
                    (let ((circle-writer-denied-p
                           (handler-case
                               (progn (dds.dcps:create-datawriter pub ci-topic :qos wqos) nil)
                             (error () t))))
                      (%check :acld-circle-writer-denied circle-writer-denied-p
                              "create-datawriter('Circle') must signal an error (EC grant denies Circle publish)"))
                    ;; (b) Square publish: MUST succeed (EC grant allows Square publish)
                    (let ((sq-dw
                           (handler-case
                               (dds.dcps:create-datawriter pub sq-topic :qos wqos)
                             (error (e)
                               (error 'test-failure :name :acld-square-writer-allowed
                                      :detail (format nil "create-datawriter('Square') must not signal; got: ~a" e))))))
                      (%check :acld-square-writer-allowed (not (null sq-dw))
                              "create-datawriter('Square') must return a non-nil DataWriter (EC grant allows Square publish)"))
                    ;; (c) Circle subscribe: local check_create_datareader MUST signal an error
                    (let ((circle-reader-denied-p
                           (handler-case
                               (progn (dds.dcps:create-datareader sub ci-topic :qos rqos) nil)
                             (error () t))))
                      (%check :acld-circle-reader-denied circle-reader-denied-p
                              "create-datareader('Circle') must signal an error (EC grant denies Circle subscribe)"))
                    ;; (d) Square subscribe: MUST succeed (EC grant allows Square subscribe)
                    (let ((sq-dr
                           (handler-case
                               (dds.dcps:create-datareader sub sq-topic :qos rqos)
                             (error (e)
                               (error 'test-failure :name :acld-square-reader-allowed
                                      :detail (format nil "create-datareader('Square') must not signal; got: ~a" e))))))
                      (%check :acld-square-reader-allowed (not (null sq-dr))
                              "create-datareader('Square') must return a non-nil DataReader (EC grant allows Square subscribe)")))
               (ignore-errors (dds.dcps:delete-participant p-ld))))
        (dds.security:free-identity-handle id-ld))))
  t)

(defun* run-access-control-default-off-test ()
    (function () t)
  "WP-DDS-SECURITY-ACCESS-CONTROL T6c: AccessControl off = byte-identical plain baseline.
   Two PLAIN participants (no identity, no AC config) on domain 88 discover each other, match on
   'AcOffTopic'/'AcOffType' with reliable/transient-local QoS, and a sample (8 bytes 'ACOFFDAT')
   round-trips byte-exact — confirming the security build does not regress the default unauthenticated
   path (AccessControl off behaves byte-identically to the non-security baseline).
   Also confirms neither participant has DP-AUTH-STATE or DP-ACCESS-STATE (AC truly off).
   No OpenSSL dependency; passes unconditionally on both SBCL and Clasp."
  (let ((p-off-w nil)
        (p-off-r nil))
    (unwind-protect
         (progn
           (setf p-off-w (dds.dcps:create-participant :domain (test-domain +td-secure-discovery+)))
           (setf p-off-r (dds.dcps:create-participant :domain (test-domain +td-secure-discovery+)))
           (let* ((node-w (dds.dcps::dp-node p-off-w))
                  (node-r (dds.dcps::dp-node p-off-r))
                  (pt     (make-array 8 :element-type '(unsigned-byte 8)
                                        :initial-contents '(#x41 #x43 #x4f #x46 #x46 #x44 #x41 #x54)))
                  (wqos   (dds.qos:make-writer-qos :reliability :reliable :durability :transient-local))
                  (rqos   (dds.qos:make-reader-qos :reliability :reliable :durability :transient-local)))
             ;; confirm AC and auth are truly off (no DP-AUTH-STATE, no DP-ACCESS-STATE)
             (%check :acoff-w-no-auth (null (dds.dcps::dp-auth-state p-off-w))
                     "writer participant must have NIL DP-AUTH-STATE (AccessControl off)")
             (%check :acoff-r-no-auth (null (dds.dcps::dp-auth-state p-off-r))
                     "reader participant must have NIL DP-AUTH-STATE (AccessControl off)")
             (%check :acoff-w-no-ac (null (dds.dcps::dp-access-state p-off-w))
                     "writer participant must have NIL DP-ACCESS-STATE (AccessControl off)")
             (%check :acoff-r-no-ac (null (dds.dcps::dp-access-state p-off-r))
                     "reader participant must have NIL DP-ACCESS-STATE (AccessControl off)")
             ;; wire unicast peers and set up endpoints
             (setf (dds.disc:disc-node-peers node-w)
                   (list (cons "127.0.0.1" (dds.disc:disc-node-port node-r))))
             (setf (dds.disc:disc-node-peers node-r)
                   (list (cons "127.0.0.1" (dds.disc:disc-node-port node-w))))
             (dds.disc:add-local-writer node-w :topic "AcOffTopic" :type "AcOffType" :qos wqos)
             (dds.disc:enable-publisher node-w :history-kind :keep-all)
             (dds.disc:add-local-reader node-r :topic "AcOffTopic" :type "AcOffType" :qos rqos)
             (dds.disc:enable-subscriber node-r)
             ;; drive discovery until matched
             (loop repeat 300
                   until (>= (dds.disc:disc-node-matched-count node-r) 1)
                   do (dds.dcps:spin p-off-w) (dds.dcps:spin p-off-r) (sleep 0.02))
             (%check :acoff-matched
                     (>= (dds.disc:disc-node-matched-count node-r) 1)
                     (format nil "plain writer/reader did not match without AC (count ~d)"
                             (dds.disc:disc-node-matched-count node-r)))
             ;; publish and wait for delivery
             (dds.disc:publish-sample node-w pt)
             (loop repeat 300
                   until (plusp (dds.disc:node-sample-count node-r))
                   do (dds.dcps:spin p-off-w) (dds.dcps:spin p-off-r) (sleep 0.02))
             (%check :acoff-received
                     (plusp (dds.disc:node-sample-count node-r))
                     "plain reader did not receive a sample (AccessControl off should not change delivery)")
             ;; assert byte-exact payload round-trip
             (let* ((key     (first (dds.disc:node-sample-sns node-r)))
                    (payload (dds.disc:node-sample node-r key)))
               (%check :acoff-byte-exact
                       (and payload (equalp payload pt))
                       (format nil "AccessControl-off payload mismatch; got ~a expected ~{~2,'0x~^ ~}"
                               (and payload (coerce payload 'list))
                               (coerce pt 'list))))))
      (when p-off-r (ignore-errors (dds.dcps:delete-participant p-off-r)))
      (when p-off-w (ignore-errors (dds.dcps:delete-participant p-off-w)))))
  t)

;;; WP-DDS-SECURITY-SECURE-DISCOVERY T5 — Governance protection-kind model.

(defun* %read-ssd-xml (filename)
    (function (string) (simple-array (unsigned-byte 8) (*)))
  "Read an unsigned XML fixture file relative to +TEST-SSD-PKI-ROOT+."
  (let* ((path (merge-pathnames filename dds.security:+test-ssd-pki-root+)))
    (with-open-file (s path :element-type '(unsigned-byte 8))
      (let* ((n (file-length s))
             (v (make-array n :element-type '(unsigned-byte 8))))
        (read-sequence v s)
        v))))

(defun* %make-governance-xml-octets (disc-kind-str)
    (function (string) (simple-array (unsigned-byte 8) (*)))
  "Build minimal Governance XML with the given DISC-KIND-STR for discovery_protection_kind (test helper)."
  (let ((xml (format nil
               "<?xml version=\"1.0\"?><dds><policies><domain_access_rules><domain_rule>~
                <domains><id>0</id></domains>~
                <allow_unauthenticated_participants>false</allow_unauthenticated_participants>~
                <enable_join_access_control>true</enable_join_access_control>~
                <discovery_protection_kind>~a</discovery_protection_kind>~
                <liveliness_protection_kind>SIGN</liveliness_protection_kind>~
                <rtps_protection_kind>SIGN</rtps_protection_kind>~
                <topic_access_rules><topic_rule>~
                <topic_expression>*</topic_expression>~
                <enable_discovery_protection>false</enable_discovery_protection>~
                <enable_liveliness_protection>false</enable_liveliness_protection>~
                <enable_read_access_control>true</enable_read_access_control>~
                <enable_write_access_control>true</enable_write_access_control>~
                <metadata_protection_kind>ENCRYPT</metadata_protection_kind>~
                <data_protection_kind>ENCRYPT</data_protection_kind>~
                </topic_rule></topic_access_rules>~
                </domain_rule></domain_access_rules></policies></dds>"
               disc-kind-str)))
    (map '(simple-array (unsigned-byte 8) (*)) #'char-code xml)))

(defun* %make-governance-xml-no-disc-kind ()
    (function () (simple-array (unsigned-byte 8) (*)))
  "Build minimal Governance XML with discovery_protection_kind ABSENT — proves fail-closed on missing required element."
  (let ((xml "<?xml version=\"1.0\"?><dds><policies><domain_access_rules><domain_rule>\
<domains><id>0</id></domains>\
<allow_unauthenticated_participants>false</allow_unauthenticated_participants>\
<enable_join_access_control>true</enable_join_access_control>\
<liveliness_protection_kind>SIGN</liveliness_protection_kind>\
<rtps_protection_kind>SIGN</rtps_protection_kind>\
<topic_access_rules><topic_rule>\
<topic_expression>*</topic_expression>\
<enable_discovery_protection>false</enable_discovery_protection>\
<enable_liveliness_protection>false</enable_liveliness_protection>\
<enable_read_access_control>true</enable_read_access_control>\
<enable_write_access_control>true</enable_write_access_control>\
<metadata_protection_kind>ENCRYPT</metadata_protection_kind>\
<data_protection_kind>ENCRYPT</data_protection_kind>\
</topic_rule></topic_access_rules>\
</domain_rule></domain_access_rules></policies></dds>"))
    (map '(simple-array (unsigned-byte 8) (*)) #'char-code xml)))

(defun* %make-governance-xml-bad-topic-kind ()
    (function () (simple-array (unsigned-byte 8) (*)))
  "Build Governance XML with SIGN_WITH_ORIGIN_AUTHENTICATION in metadata_protection_kind — valid domain token, wrong per-topic tier."
  (let ((xml "<?xml version=\"1.0\"?><dds><policies><domain_access_rules><domain_rule>\
<domains><id>0</id></domains>\
<allow_unauthenticated_participants>false</allow_unauthenticated_participants>\
<enable_join_access_control>true</enable_join_access_control>\
<discovery_protection_kind>SIGN</discovery_protection_kind>\
<liveliness_protection_kind>SIGN</liveliness_protection_kind>\
<rtps_protection_kind>SIGN</rtps_protection_kind>\
<topic_access_rules><topic_rule>\
<topic_expression>*</topic_expression>\
<enable_discovery_protection>false</enable_discovery_protection>\
<enable_liveliness_protection>false</enable_liveliness_protection>\
<enable_read_access_control>true</enable_read_access_control>\
<enable_write_access_control>true</enable_write_access_control>\
<metadata_protection_kind>SIGN_WITH_ORIGIN_AUTHENTICATION</metadata_protection_kind>\
<data_protection_kind>ENCRYPT</data_protection_kind>\
</topic_rule></topic_access_rules>\
</domain_rule></domain_access_rules></policies></dds>"))
    (map '(simple-array (unsigned-byte 8) (*)) #'char-code xml)))

(defun* run-governance-protection-kind-test ()
    (function () t)
  "T5 (WP-DDS-SECURITY-SECURE-DISCOVERY): Governance protection-kind model.
   (a) governance-secure.xml: ENCRYPT/SIGN/ENCRYPT + topic enable_discovery=T + meta/data ENCRYPT.
   (b) governance-origin-auth.xml: all ENCRYPT_WITH_ORIGIN_AUTHENTICATION / SIGN_WITH_ORIGIN_AUTHENTICATION.
   (c) governance-none.xml: all NONE; enable_discovery=NIL; meta/data NONE.
   (d) Missing required discovery_protection_kind element -> NIL (fail-closed; §9.4.1.2.3 requires element).
   (e) Unknown token -> fail-closed (NIL, never :none).
   (f) topic-discovery-protected-p: T for * in secure, NIL in none (non-vacuous parse assertions added).
   (g) topic-metadata-protection: :encrypt for * in secure, :none in none (non-vacuous parse assertions added).
   (h) Wrong-tier token (SIGN_WITH_ORIGIN_AUTHENTICATION in per-topic metadata field) -> NIL (tier guard)."

  ;; (a) governance-secure.xml — ENCRYPT/SIGN/ENCRYPT
  (let* ((xml (if (probe-file (merge-pathnames "governance-secure.xml" dds.security:+test-ssd-pki-root+))
                  (%read-ssd-xml "governance-secure.xml")
                  nil))
         (gov (and xml (dds.security:parse-governance xml))))
    (%check :t5-secure-parsed (not (null gov))
            "parse-governance(governance-secure.xml) must return a governance struct")
    (when gov
      (%check :t5-secure-disc
              (eq :encrypt (dds.security:governance-discovery-protection gov))
              (format nil "governance-secure: discovery-protection must be :encrypt; got ~s"
                      (dds.security:governance-discovery-protection gov)))
      (%check :t5-secure-live
              (eq :sign (dds.security:governance-liveliness-protection gov))
              (format nil "governance-secure: liveliness-protection must be :sign; got ~s"
                      (dds.security:governance-liveliness-protection gov)))
      (%check :t5-secure-rtps
              (eq :encrypt (dds.security:governance-rtps-protection gov))
              (format nil "governance-secure: rtps-protection must be :encrypt; got ~s"
                      (dds.security:governance-rtps-protection gov)))
      (let ((rules (dds.security:governance-topic-rules gov)))
        (%check :t5-secure-rules-nonempty (not (null rules))
                "governance-secure: topic-rules must be non-empty")
        (when rules
          (let ((r (first rules)))
            (%check :t5-secure-disc-p
                    (dds.security:topic-rule-enable-discovery-protection r)
                    "governance-secure: first topic-rule enable_discovery_protection must be T")
            (%check :t5-secure-meta
                    (eq :encrypt (dds.security:topic-rule-metadata-protection-kind r))
                    (format nil "governance-secure: metadata_protection_kind must be :encrypt; got ~s"
                            (dds.security:topic-rule-metadata-protection-kind r)))
            (%check :t5-secure-data
                    (eq :encrypt (dds.security:topic-rule-data-protection-kind r))
                    (format nil "governance-secure: data_protection_kind must be :encrypt; got ~s"
                            (dds.security:topic-rule-data-protection-kind r))))))))

  ;; (b) governance-origin-auth.xml — ENCRYPT_WITH_ORIGIN_AUTHENTICATION
  (let* ((xml (and (probe-file (merge-pathnames "governance-origin-auth.xml"
                                                dds.security:+test-ssd-pki-root+))
                   (%read-ssd-xml "governance-origin-auth.xml")))
         (gov (and xml (dds.security:parse-governance xml))))
    (%check :t5-oa-parsed (not (null gov))
            "parse-governance(governance-origin-auth.xml) must return non-nil")
    (when gov
      (%check :t5-oa-disc
              (eq :encrypt-with-origin-auth (dds.security:governance-discovery-protection gov))
              (format nil "governance-origin-auth: discovery must be :encrypt-with-origin-auth; got ~s"
                      (dds.security:governance-discovery-protection gov)))
      (%check :t5-oa-live
              (eq :sign-with-origin-auth (dds.security:governance-liveliness-protection gov))
              (format nil "governance-origin-auth: liveliness must be :sign-with-origin-auth; got ~s"
                      (dds.security:governance-liveliness-protection gov)))
      (%check :t5-oa-rtps
              (eq :encrypt-with-origin-auth (dds.security:governance-rtps-protection gov))
              (format nil "governance-origin-auth: rtps must be :encrypt-with-origin-auth; got ~s"
                      (dds.security:governance-rtps-protection gov)))))

  ;; (c) governance-none.xml — all NONE; enable_discovery=NIL
  (let* ((xml (and (probe-file (merge-pathnames "governance-none.xml"
                                                dds.security:+test-ssd-pki-root+))
                   (%read-ssd-xml "governance-none.xml")))
         (gov (and xml (dds.security:parse-governance xml))))
    (%check :t5-none-parsed (not (null gov))
            "parse-governance(governance-none.xml) must return non-nil")
    (when gov
      (%check :t5-none-disc
              (eq :none (dds.security:governance-discovery-protection gov))
              (format nil "governance-none: discovery must be :none; got ~s"
                      (dds.security:governance-discovery-protection gov)))
      (%check :t5-none-live
              (eq :none (dds.security:governance-liveliness-protection gov))
              (format nil "governance-none: liveliness must be :none; got ~s"
                      (dds.security:governance-liveliness-protection gov)))
      (%check :t5-none-rtps
              (eq :none (dds.security:governance-rtps-protection gov))
              (format nil "governance-none: rtps must be :none; got ~s"
                      (dds.security:governance-rtps-protection gov)))
      (let ((rules (dds.security:governance-topic-rules gov)))
        (when rules
          (let ((r (first rules)))
            (%check :t5-none-disc-p-false
                    (not (dds.security:topic-rule-enable-discovery-protection r))
                    "governance-none: enable_discovery_protection must be NIL")
            (%check :t5-none-meta
                    (eq :none (dds.security:topic-rule-metadata-protection-kind r))
                    (format nil "governance-none: metadata_protection_kind must be :none; got ~s"
                            (dds.security:topic-rule-metadata-protection-kind r))))))))

  ;; (d) Missing required protection-kind → parse must return NIL (fail-closed; §9.4.1.2.3 requires element)
  (let* ((xml (%make-governance-xml-no-disc-kind))
         (gov (dds.security:parse-governance xml)))
    (%check :t5-missing-disc-fail-closed (null gov)
            "absent required discovery_protection_kind must make parse-governance return NIL (fail-closed)"))

  ;; (e) Unknown token -> fail-closed (NIL, never :none)
  (let* ((xml  (%make-governance-xml-octets "BOGUS_UNKNOWN_KIND"))
         (gov  (dds.security:parse-governance xml)))
    (%check :t5-unknown-token-nil (null gov)
            "unknown protection-kind token BOGUS_UNKNOWN_KIND must make parse-governance return NIL (fail-closed)"))

  ;; (f) topic-discovery-protected-p
  (let* ((xml-s (and (probe-file (merge-pathnames "governance-secure.xml"
                                                  dds.security:+test-ssd-pki-root+))
                     (%read-ssd-xml "governance-secure.xml")))
         (gov-s (and xml-s (dds.security:parse-governance xml-s)))
         (xml-n (and (probe-file (merge-pathnames "governance-none.xml"
                                                  dds.security:+test-ssd-pki-root+))
                     (%read-ssd-xml "governance-none.xml")))
         (gov-n (and xml-n (dds.security:parse-governance xml-n))))
    (%check :t5-f-gov-s-parsed (not (null gov-s))
            "parse-governance(governance-secure.xml) must succeed for (f) subtests")
    (%check :t5-f-gov-n-parsed (not (null gov-n))
            "parse-governance(governance-none.xml) must succeed for (f) subtests")
    (when gov-s
      (%check :t5-disc-protected-p-secure
              (dds.security:topic-discovery-protected-p gov-s "*")
              "topic-discovery-protected-p('*') must be T in governance-secure"))
    (when gov-n
      (%check :t5-disc-protected-p-none
              (not (dds.security:topic-discovery-protected-p gov-n "*"))
              "topic-discovery-protected-p('*') must be NIL in governance-none")))

  ;; (g) topic-metadata-protection
  (let* ((xml-s (and (probe-file (merge-pathnames "governance-secure.xml"
                                                  dds.security:+test-ssd-pki-root+))
                     (%read-ssd-xml "governance-secure.xml")))
         (gov-s (and xml-s (dds.security:parse-governance xml-s)))
         (xml-n (and (probe-file (merge-pathnames "governance-none.xml"
                                                  dds.security:+test-ssd-pki-root+))
                     (%read-ssd-xml "governance-none.xml")))
         (gov-n (and xml-n (dds.security:parse-governance xml-n))))
    (%check :t5-g-gov-s-parsed (not (null gov-s))
            "parse-governance(governance-secure.xml) must succeed for (g) subtests")
    (%check :t5-g-gov-n-parsed (not (null gov-n))
            "parse-governance(governance-none.xml) must succeed for (g) subtests")
    (when gov-s
      (%check :t5-meta-secure
              (eq :encrypt (dds.security:topic-metadata-protection gov-s "*"))
              (format nil "topic-metadata-protection('*') must be :encrypt in governance-secure; got ~s"
                      (dds.security:topic-metadata-protection gov-s "*"))))
    (when gov-n
      (%check :t5-meta-none
              (eq :none (dds.security:topic-metadata-protection gov-n "*"))
              (format nil "topic-metadata-protection('*') must be :none in governance-none; got ~s"
                      (dds.security:topic-metadata-protection gov-n "*")))))

  ;; (h) Wrong-tier token: SIGN_WITH_ORIGIN_AUTHENTICATION in per-topic metadata_protection_kind → parse nil (tier guard)
  (let* ((xml (%make-governance-xml-bad-topic-kind))
         (gov (dds.security:parse-governance xml)))
    (%check :t5-bad-topic-tier-nil (null gov)
            "SIGN_WITH_ORIGIN_AUTHENTICATION in metadata_protection_kind must make parse-governance return NIL (tier guard)"))
  t)

(defun* run-security-data-protection-downgrade-test ()
    (function () t)
  "Review follow-up (DDS-Security 1.1 §9.4.1.2.4): a MULTI-RULE governance whose FIRST topic_rule is data=NONE
   while a LATER rule is data=ENCRYPT for a specific topic must NOT let an add-local-{writer,reader} endpoint
   inherit the FIRST-rule participant default. The fix: (1) the participant-level default is MOST-PROTECTIVE
   (governance-effective-data-protection, max :encrypt>:sign>:none — fail-closed), and (2) add-local resolves
   the ACTUAL per-topic data_protection via the %install-access-control-installed resolver. Asserts, on the
   PRE-fix first-rule logic, RED on both a FALSE-ACCEPT (an ENCRYPT topic left :none) and a FALSE-REJECT (a
   genuine NONE topic forced to protection). Rules are ordered so the wildcard-free FIRST rule (Square) does
   NOT shadow the LATER Circle rule (topic-data-protection = first-MATCHING rule, §9.4.1.2.4)."
  (let* ((gov (dds.security:make-governance
               :discovery-protection-kind :none
               :liveliness-protection-kind :none
               :rtps-protection-kind :none
               :topic-rules
               (list (dds.security:make-topic-rule :topic-expr "Square"    ; FIRST rule: a genuine data=NONE topic
                                                   :metadata-protection-kind :none
                                                   :data-protection-kind :none)
                     (dds.security:make-topic-rule :topic-expr "Circle"    ; LATER rule: data=ENCRYPT (Square rule does not shadow it)
                                                   :metadata-protection-kind :none
                                                   :data-protection-kind :encrypt))))
         (ah  (dds.security:make-access-handle :governance gov)))
    (%check :dp-downgrade-effective-most-protective
            (eq :encrypt (dds.security:governance-effective-data-protection gov))
            "governance-effective-data-protection must be MOST-PROTECTIVE over ALL rules (max :encrypt>:sign>:none): a FIRST data=NONE rule must NOT downgrade the participant default below a LATER data=ENCRYPT rule (fail-closed)")
    (let ((p (dds.dcps:create-participant :domain (test-domain +td-collect+))))
      (unwind-protect
           (let ((node (dds.dcps::dp-node p)))
             (setf (dds.dcps::dp-auth-state p)
                   (dds.dcps::%make-auth-manager-state :identity (dds.security::%make-identity-handle)))
             (dds.dcps::%install-access-control p ah)
             ;; the data=ENCRYPT topic (a LATER rule) via add-local must resolve per-topic to :encrypt — never the FIRST rule's :none (false-ACCEPT)
             (dds.disc:add-local-writer node :topic "Circle" :type "ShapeType")
             (%check :dp-downgrade-encrypt-topic-not-none
                     (eq :encrypt (dds.disc:disc-node-user-data-protection-kind node))
                     "add-local-writer on the data=ENCRYPT topic (a LATER rule; the FIRST rule is data=NONE) must resolve per-topic to :encrypt, never :none — a plain payload accepted on an ENCRYPT topic is a false-ACCEPT")
             ;; a genuine data=NONE topic (the FIRST rule) via add-local must resolve to :none — never forced to protection by the most-protective default (false-REJECT)
             (dds.disc:add-local-reader node :topic "Square" :type "ShapeType")
             (%check :dp-downgrade-none-topic-not-forced
                     (eq :none (dds.disc:disc-node-user-data-protection-kind node))
                     "add-local-reader on a genuine data=NONE topic (the FIRST rule) must resolve per-topic to :none, never forced to protection by the most-protective participant default — over-encrypting a NONE topic is a false-REJECT"))
        (dds.dcps:delete-participant p))))
  t)

(defun* run-security-metadata-protection-downgrade-test ()
    (function () t)
  "ADR-0040 carry (DDS-Security 1.1 §9.4.1.2.4), SYMMETRIC to run-security-data-protection-downgrade-test but for
   metadata_protection (the user-DATA submessage tier, disc-node-user-submessage-protection-kind): a MULTI-RULE
   governance whose FIRST topic_rule is metadata=NONE while a LATER rule is metadata=ENCRYPT for a specific topic
   must NOT let an add-local-{writer,reader} endpoint inherit the FIRST-rule participant default. The fix: (1) the
   participant-level default is MOST-PROTECTIVE (governance-effective-metadata-protection, max :encrypt>:sign>:none
   — fail-closed), and (2) add-local resolves the ACTUAL per-topic metadata_protection via the
   %install-access-control-installed resolver. Asserts, on the PRE-fix (no add-local metadata refinement, slot
   stayed the :none default) logic, RED on both a FALSE-ACCEPT (an ENCRYPT topic left :none = an unprotected user
   submessage on a protected topic) and a FALSE-REJECT (a genuine NONE topic forced to protection). Rules are
   ordered so the wildcard-free FIRST rule (Square) does NOT shadow the LATER Circle rule (topic-metadata-protection
   = first-MATCHING rule, §9.4.1.2.4)."
  (let* ((gov (dds.security:make-governance
               :discovery-protection-kind :none
               :liveliness-protection-kind :none
               :rtps-protection-kind :none
               :topic-rules
               (list (dds.security:make-topic-rule :topic-expr "Square"    ; FIRST rule: a genuine metadata=NONE topic
                                                   :metadata-protection-kind :none
                                                   :data-protection-kind :none)
                     (dds.security:make-topic-rule :topic-expr "Circle"    ; LATER rule: metadata=ENCRYPT (Square rule does not shadow it)
                                                   :metadata-protection-kind :encrypt
                                                   :data-protection-kind :none))))
         (ah  (dds.security:make-access-handle :governance gov)))
    (%check :mp-downgrade-effective-most-protective
            (eq :encrypt (dds.security:governance-effective-metadata-protection gov))
            "governance-effective-metadata-protection must be MOST-PROTECTIVE over ALL rules (max :encrypt>:sign>:none): a FIRST metadata=NONE rule must NOT downgrade the participant default below a LATER metadata=ENCRYPT rule (fail-closed)")
    (let ((p (dds.dcps:create-participant :domain (test-domain +td-collect+))))
      (unwind-protect
           (let ((node (dds.dcps::dp-node p)))
             (setf (dds.dcps::dp-auth-state p)
                   (dds.dcps::%make-auth-manager-state :identity (dds.security::%make-identity-handle)))
             (dds.dcps::%install-access-control p ah)
             ;; the metadata=ENCRYPT topic (a LATER rule) via add-local must resolve per-topic to :encrypt — never the FIRST rule's :none (false-ACCEPT)
             (dds.disc:add-local-writer node :topic "Circle" :type "ShapeType")
             (%check :mp-downgrade-encrypt-topic-not-none
                     (eq :encrypt (dds.disc:disc-node-user-submessage-protection-kind node))
                     "add-local-writer on the metadata=ENCRYPT topic (a LATER rule; the FIRST rule is metadata=NONE) must resolve per-topic to :encrypt, never :none — an unprotected user submessage emitted on a protected topic is a false-ACCEPT")
             ;; a genuine metadata=NONE topic (the FIRST rule) via add-local must resolve to :none — never forced to protection by the most-protective default (false-REJECT)
             (dds.disc:add-local-reader node :topic "Square" :type "ShapeType")
             (%check :mp-downgrade-none-topic-not-forced
                     (eq :none (dds.disc:disc-node-user-submessage-protection-kind node))
                     "add-local-reader on a genuine metadata=NONE topic (the FIRST rule) must resolve per-topic to :none, never forced to protection by the most-protective participant default — protecting a NONE topic's user submessage is a false-REJECT"))
        (dds.dcps:delete-participant p))))
  t)

(defun* run-security-mixed-kind-reject-test ()
    (function () t)
  "ADR-0040 payload-tier review follow-up (Important 2, DDS-Security 1.1 §9.5.2): the user writer/reader carries ONE
   EntityCrypto key that serves BOTH the data_protection (payload/SecuredPayload) AND metadata_protection (user
   submessage) tiers, so a topic_rule setting them to DIFFERENT non-NONE kinds is unrepresentable — the payload kind
   WINS in %cm-entity-protection-kind and, for data=SIGN + metadata=ENCRYPT, DOWNGRADES the ENCRYPT-mandated submessage
   onto the visible GMAC kind (a confidentiality downgrade). Such a contradictory governance MUST be FAIL-CLOSED
   REJECTED at %install-access-control (create-participant), never silently collapsed to one km. Asserts:
   (a) governance-mixed-nonnone-kind-conflict FLAGS both data=SIGN+metadata=ENCRYPT and data=ENCRYPT+metadata=SIGN, and
       passes same-kind (SIGN/SIGN, ENCRYPT/ENCRYPT) + any-NONE (SIGN/NONE, NONE/ENCRYPT, NONE/NONE) combos (no
       false-REJECT of a representable governance);
   (b) %install-access-control SIGNALS on a mixed-kind governance and does NOT signal on a same-kind one."
  (flet ((mk (data meta)
           (dds.security:make-governance
            :discovery-protection-kind :none :liveliness-protection-kind :none :rtps-protection-kind :none
            :topic-rules (list (dds.security:make-topic-rule :topic-expr "*"
                                                             :metadata-protection-kind meta
                                                             :data-protection-kind data)))))
    ;; (a) the pure conflict finder: mixed non-NONE kinds -> flagged; same-kind / any-NONE -> NIL
    (%check :mk-sign-encrypt-flagged  (dds.security:governance-mixed-nonnone-kind-conflict (mk :sign :encrypt))
            "data=SIGN + metadata=ENCRYPT must be flagged (single-km downgrade)")
    (%check :mk-encrypt-sign-flagged  (dds.security:governance-mixed-nonnone-kind-conflict (mk :encrypt :sign))
            "data=ENCRYPT + metadata=SIGN must be flagged (single-km, unrepresentable)")
    (%check :mk-sign-sign-ok       (null (dds.security:governance-mixed-nonnone-kind-conflict (mk :sign :sign)))
            "data=SIGN + metadata=SIGN (same kind) must NOT be flagged")
    (%check :mk-encrypt-encrypt-ok (null (dds.security:governance-mixed-nonnone-kind-conflict (mk :encrypt :encrypt)))
            "data=ENCRYPT + metadata=ENCRYPT (same kind) must NOT be flagged")
    (%check :mk-sign-none-ok       (null (dds.security:governance-mixed-nonnone-kind-conflict (mk :sign :none)))
            "data=SIGN + metadata=NONE (a NONE tier) must NOT be flagged")
    (%check :mk-none-encrypt-ok    (null (dds.security:governance-mixed-nonnone-kind-conflict (mk :none :encrypt)))
            "data=NONE + metadata=ENCRYPT (a NONE tier) must NOT be flagged")
    (%check :mk-none-none-ok       (null (dds.security:governance-mixed-nonnone-kind-conflict (mk :none :none)))
            "data=NONE + metadata=NONE must NOT be flagged")
    ;; (b) %install-access-control: FAIL-CLOSED REJECT (signal) on a mixed-kind governance; ACCEPT a same-kind one
    (let ((p (dds.dcps:create-participant :domain (test-domain +td-collect+))))
      (unwind-protect
           (progn
             (setf (dds.dcps::dp-auth-state p)
                   (dds.dcps::%make-auth-manager-state :identity (dds.security::%make-identity-handle)))
             (%check :mk-install-rejects-mixed
                     (handler-case
                         (progn (dds.dcps::%install-access-control
                                 p (dds.security:make-access-handle :governance (mk :sign :encrypt)))
                                nil)
                       (error () t))
                     "%install-access-control must SIGNAL on data=SIGN + metadata=ENCRYPT (fail-closed, no silent single-km collapse)")
             (%check :mk-install-accepts-samekind
                     (handler-case
                         (progn (dds.dcps::%install-access-control
                                 p (dds.security:make-access-handle :governance (mk :encrypt :encrypt)))
                                t)
                       (error () nil))
                     "%install-access-control must ACCEPT a same-kind (data=ENCRYPT + metadata=ENCRYPT) governance (no false-REJECT)"))
        (dds.dcps:delete-participant p))))
  t)

(defun* run-security-dn-match-test ()
    (function () t)
  "ADR-0036/0037 carry (DDS-Security 1.1 §9.4.1.3 subject-name binding; RFC2253 §2.1-2.4): the serialization-
   insensitive X.509 DN match (%dn-equal / %dn-normalize) that binds a permissions grant to a peer cert's subject.
   Covers oneline vs RFC2253 form (direction pinning §2.1 — oneline forward, RFC2253 reverse), attribute-TYPE
   case-fold (types case-insensitive §2.3, VALUES case-sensitive), whitespace, RFC2253 `\\`-ESCAPING (an escaped
   separator/`+` is DATA not a boundary §2.4; `\\XX` hex), and multi-valued RDNs (an X.501 RDN is an UNORDERED SET
   of `+`-joined AVAs §2.2). SECURITY (no false-ACCEPT): an X.501 DN is a SEQUENCE of RDNs whose ORDER IS
   SIGNIFICANT — a genuine RDN reorder (CN=a,O=b vs O=b,CN=a) is a DIFFERENT subject and must NOT match (the
   identity-confusion fix, replacing the old sort-collapse); the canonical form is STRUCTURAL (list of RDNs, each
   a sorted AVA list — a re-joined string is non-injective and let CN=x\\+O=y forge CN=x+O=y); likewise a
   wrong-value / wrong-case-value / different-RDN-count-or-grouping / escaped-vs-unescaped-structure / MALFORMED
   DN must NOT match — an ambiguous or unparseable DN never authorizes, not even against an identical unparseable
   grant. A trailing `\\ `-escaped space is value DATA (§2.4): it survives trimming (no false-REJECT) and
   distinguishes 'a ' from 'a'."
  ;; POSITIVE — the SAME subject in different conformant serializations MUST match (no false-REJECT)
  (%check :dn-m-identical (dds.security::%dn-equal "/CN=a/O=b/C=DE" "/CN=a/O=b/C=DE")
          "identical oneline DNs match")
  (%check :dn-m-order (dds.security::%dn-equal "/CN=a/O=b/C=DE" "C=DE,O=b,CN=a")
          "oneline vs RFC2253 (reversed RDN order) match — order-insensitive")
  (%check :dn-m-attr-case (dds.security::%dn-equal "/O=Acme/CN=Alice" "cn=Alice,o=Acme")
          "attribute TYPE case-fold: CN==cn, O==o (types are case-insensitive, RFC2253 §2.3); same sequence [O,CN] both forms (oneline forward, RFC2253 reverse §2.1)")
  (%check :dn-m-whitespace (dds.security::%dn-equal "CN=a, O=b, C=DE" "CN=a,O=b,C=DE")
          "whitespace after the RDN separator is trimmed")
  (%check :dn-m-escaped-comma (dds.security::%dn-equal "CN=Doe\\, John,O=Acme" "/O=Acme/CN=Doe, John")
          "RFC2253 escaped-comma value (CN=Doe, John) matches the oneline form — the escaped separator is DATA, not a boundary; both denote sequence [O,CN] (RFC2253 reverse §2.1)")
  (%check :dn-m-hex-escape (dds.security::%dn-equal "CN=\\41,O=x" "CN=A,O=x")
          "RFC2253 hex escape backslash-41 == 'A'")
  ;; POSITIVE — multi-valued RDNs (RFC2253 §2.2: an RDN is an UNORDERED SET of `+`-joined AVAs) MUST match regardless of AVA order
  (%check :dn-m-mv-ava-order (dds.security::%dn-equal "CN=a+SN=b,O=x" "SN=b+CN=a,O=x")
          "multi-valued RDN AVA order is not significant (RFC2253 §2.2, X.501 RDN is a SET): CN=a+SN=b == SN=b+CN=a")
  (%check :dn-m-mv-cross-form (dds.security::%dn-equal "/O=x/SN=b+CN=a" "CN=a+SN=b,O=x")
          "multi-valued RDN, cross-form: oneline [O, {SN,CN}] == RFC2253 reversed [O, {CN,SN}] (§2.1 + §2.2)")
  (%check :dn-m-mv-type-case (dds.security::%dn-equal "cn=a+sn=b,O=x" "CN=a+SN=b,O=x")
          "multi-valued RDN with TYPE case-fold: cn=a+sn=b == CN=a+SN=b (types case-insensitive, §2.3)")
  (%check :dn-m-mv-escaped-plus (dds.security::%dn-equal "CN=a\\+b,O=x" "CN=a\\2Bb,O=x")
          "an escaped `\\+` is value DATA, not an AVA boundary (§2.4): value literally a+b, matches the `\\2B` hex form of '+' (0x2B)")
  ;; POSITIVE — a trailing `\\ `-escaped space is value DATA (§2.4) and must survive trimming (no false-REJECT)
  (%check :dn-m-escaped-trailing-space-self (dds.security::%dn-equal "CN=a\\ " "CN=a\\ ")
          "a conformant trailing escaped space (CN=a\\ , value 'a ') matches itself — unescaped-only trim, no stranded backslash")
  (%check :dn-m-escaped-trailing-space-hex (dds.security::%dn-equal "CN=a\\ " "CN=a\\20")
          "trailing escaped space `\\ ` == its `\\20` hex form (both canonical value 'a ', §2.4)")
  ;; NEGATIVE — a DIFFERENT or ambiguous subject must NOT match (no false-ACCEPT of a wrong identity)
  (%check :dn-n-diff-value (not (dds.security::%dn-equal "CN=a,O=b" "CN=a,O=c"))
          "a different attribute VALUE does not match")
  (%check :dn-n-value-case (not (dds.security::%dn-equal "CN=Alice" "CN=alice"))
          "attribute VALUES are case-SENSITIVE (Alice != alice) — the strict/safe default, no false-ACCEPT")
  (%check :dn-n-escaped-structure (not (dds.security::%dn-equal "CN=a\\,O=x" "CN=a,O=x"))
          "an escaped comma (ONE RDN, CN value a,O=x) must NOT match an unescaped comma (TWO RDNs) — different subjects")
  (%check :dn-n-subset (not (dds.security::%dn-equal "CN=a" "CN=a,O=b"))
          "a subset DN does not match a superset (different RDN count)")
  (%check :dn-n-malformed-trailing (not (dds.security::%dn-equal "CN=a\\" "CN=a"))
          "a MALFORMED DN (trailing lone backslash) does not match — fail-closed")
  (%check :dn-n-malformed-self (not (dds.security::%dn-equal "CN=a\\" "CN=a\\"))
          "a malformed DN does not even match an IDENTICAL malformed grant — fail-closed (no false-ACCEPT)")
  (%check :dn-n-no-equals (not (dds.security::%dn-equal "CN" "CN=x"))
          "a DN with no unescaped '=' is malformed -> no match (fail-closed)")
  (%check :dn-n-empty-attr (not (dds.security::%dn-equal "=x,CN=a" "CN=a"))
          "an empty attribute type is malformed -> no match (fail-closed)")
  ;; NEGATIVE — RDN SEQUENCE order is SIGNIFICANT (X.501 DN is a SEQUENCE): a reorder is a DIFFERENT subject (the identity-confusion fix, no false-ACCEPT)
  (%check :dn-n-rdn-reorder (not (dds.security::%dn-equal "CN=a,O=b" "O=b,CN=a"))
          "same-serialization RDN reorder is a DIFFERENT DN (X.501 sequence order is significant) -> no match (closes the sort-collapse false-ACCEPT)")
  (%check :dn-n-rdn-reorder-oneline (not (dds.security::%dn-equal "/CN=a/O=b" "/O=b/CN=a"))
          "the oneline twin: /CN=a/O=b is a different sequence than /O=b/CN=a -> no match")
  (%check :dn-n-attr-case-reorder (not (dds.security::%dn-equal "/CN=Alice/O=Acme" "cn=Alice,o=Acme"))
          "inconsistently-ordered twin of :dn-m-attr-case (oneline [CN,O] vs RFC2253-reverse [O,CN]) must NOT match — strictness asserted")
  (%check :dn-n-escaped-comma-reorder (not (dds.security::%dn-equal "CN=Doe\\, John,O=Acme" "/CN=Doe, John/O=Acme"))
          "inconsistently-ordered twin of :dn-m-escaped-comma (RFC2253-reverse [O,CN] vs oneline [CN,O]) must NOT match")
  ;; NEGATIVE — multi-valued vs single-valued / different RDN grouping is a DIFFERENT subject
  (%check :dn-n-mv-vs-single (not (dds.security::%dn-equal "CN=a+SN=b" "CN=a"))
          "a multi-valued RDN {CN=a,SN=b} is not the single-AVA RDN {CN=a} -> no match")
  (%check :dn-n-mv-vs-two-rdns (not (dds.security::%dn-equal "CN=a+SN=b" "CN=a,SN=b"))
          "ONE multi-valued RDN {CN=a,SN=b} is not TWO RDNs [CN=a][SN=b] (different RDN count/grouping) -> no match")
  (%check :dn-n-mv-vs-two-avas (not (dds.security::%dn-equal "CN=a\\+b,O=x" "CN=a+B=b,O=x"))
          "escaped `\\+` (single AVA, value a+b) is not the two-AVA structure CN=a + B=b (structure vs data, §2.2/§2.4) -> no match")
  ;; NEGATIVE — join-forgery attack pairs: a single-AVA value containing literal '+' and '=' must NOT collide with the multi-AVA structure it spells (structural canonical form, non-injective-join fix)
  (%check :dn-n-mv-join-forgery (not (dds.security::%dn-equal "CN=x\\+O=y" "CN=x+O=y"))
          "single AVA CN with value x+O=y must NOT match the AVA set {CN=x, O=y} — a re-joined canonical string collided them (false-ACCEPT)")
  (%check :dn-n-mv-join-forgery-2 (not (dds.security::%dn-equal "A=1\\+B=2" "A=1+B=2"))
          "single AVA A with value 1+B=2 must NOT match the AVA set {A=1, B=2} — the sort-independent twin of the join-forgery")
  ;; NEGATIVE — a trailing escaped space is part of the VALUE ('a ' != 'a')
  (%check :dn-n-escaped-trailing-space (not (dds.security::%dn-equal "CN=a\\ " "CN=a"))
          "CN=a\\  (value 'a ') must NOT match CN=a (value 'a') — the escaped trailing space is DATA (§2.4)")
  ;; NEGATIVE — malformed multi-valued RDN fails closed, not even against itself
  (%check :dn-n-mv-empty-ava (not (dds.security::%dn-equal "CN=a+" "CN=a+"))
          "an empty AVA (CN=a+) is malformed -> no match even against an identical malformed grant (fail-closed)")
  (%check :dn-n-mv-no-equals (not (dds.security::%dn-equal "CN=a+SN" "CN=a+SN"))
          "a multi-valued AVA with no `=` (CN=a+SN) is malformed -> no match even against itself (fail-closed)")
  t)
