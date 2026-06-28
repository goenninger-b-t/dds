(in-package #:dds.security)

;;; DDS-Security 1.1 §9.4.1.2.3 — Governance document data model + XML parser (T5 extension).

(defstruct* (topic-rule (:constructor make-topic-rule))
  "DDS-Security 1.1 §9.4.1.2.3/§9.4.1.2.4 per-topic protection-kind rule.
   Constructor defaults: enable_discovery/liveliness_protection=NIL, metadata/data_protection_kind=:none.
   These are constructor defaults only — the parse path requires both protection-kind elements
   to be present and fails closed (parse→NIL) if either is absent."
  (topic-expr                  ""       :type string)
  (enable-read-ac              nil      :type boolean)
  (enable-write-ac             nil      :type boolean)
  (enable-discovery-protection nil      :type boolean)
  (enable-liveliness-protection nil     :type boolean)
  (metadata-protection-kind    :none    :type keyword)
  (data-protection-kind        :none    :type keyword))

(defstruct* (governance (:constructor make-governance))
  "DDS-Security 1.1 §9.4.1.2.3 governance data model (first domain_rule, slice-scope subset).
   Constructor defaults: discovery/liveliness/rtps protection kinds = :sign (inert-safe).
   These are constructor defaults only — the parse path requires all three elements present
   and fails closed (parse→NIL) if any is absent."
  (allow-unauthenticated      nil    :type boolean)
  (enable-join-ac             nil    :type boolean)
  (discovery-protection-kind  :sign  :type keyword)
  (liveliness-protection-kind :sign  :type keyword)
  (rtps-protection-kind       :sign  :type keyword)
  (topic-rules                '()   :type list))

(defun* parse-governance (octets)
    (function ((simple-array (unsigned-byte 8) (*))) (or governance null))
  "Parse DDS-Security 1.1 §9.4.1.2.3 Governance document from OCTETS; NIL on any malformed input."
  (block parse
    (handler-bind ((error (lambda (c) (declare (ignore c)) (return-from parse nil))))
      (let* ((str   (map 'string #'code-char octets))
             (tree  (xmls:parse str))
             ;; OMG dds_governance.xsd: <dds><domain_access_rules> is a DIRECT child of the root (corroborated
             ;; against Fast DDS GovernanceParser.cpp:105 — it rejects any other first child). Prefer that
             ;; conformant form; still tolerate the legacy <policies> wrapper so neither form is false-REJECTed.
             (dar   (or (%ac-node-child tree "domain_access_rules")
                        (let ((pols (%ac-node-child tree "policies")))
                          (and pols (%ac-node-child pols "domain_access_rules")))))
             (drule (and dar (%ac-node-child dar "domain_rule"))))
        (unless drule (return-from parse nil))
        (let* ((allow-u (%ac-node-bool drule "allow_unauthenticated_participants"))
               (join-ac (%ac-node-bool drule "enable_join_access_control"))
               ;; §9.4.1.2.3 domain-rule ProtectionKind — fail-closed on absent, unknown, or wrong-tier token
               (disc-k  (%ac-node-protection-kind drule "discovery_protection_kind"
                                                  +protection-kinds+))
               (live-k  (%ac-node-protection-kind drule "liveliness_protection_kind"
                                                  +protection-kinds+))
               (rtps-k  (%ac-node-protection-kind drule "rtps_protection_kind"
                                                  +protection-kinds+)))
          (unless (and disc-k live-k rtps-k) (return-from parse nil))
          (let* ((tar    (%ac-node-child drule "topic_access_rules"))
                 (trules (when tar
                           (let ((result '()))
                             (dolist (tr (%ac-node-children-named tar "topic_rule")
                                        (nreverse result))
                               (let* ((expr    (or (%ac-node-text-req tr "topic_expression") ""))
                                      (read-ac (%ac-node-bool tr "enable_read_access_control"))
                                      (wrt-ac  (%ac-node-bool tr "enable_write_access_control"))
                                      (disc-p  (%ac-node-bool tr "enable_discovery_protection"))
                                      (live-p  (%ac-node-bool tr "enable_liveliness_protection"))
                                      ;; §9.4.1.2.4 BasicProtectionKind — fail-closed on absent, unknown, or wrong-tier token
                                      (meta-k  (%ac-node-protection-kind tr "metadata_protection_kind"
                                                                          +basic-protection-kinds+))
                                      (data-k  (%ac-node-protection-kind tr "data_protection_kind"
                                                                          +basic-protection-kinds+)))
                                 (unless (and meta-k data-k) (return-from parse nil))
                                 (push (make-topic-rule
                                        :topic-expr                   expr
                                        :enable-read-ac               read-ac
                                        :enable-write-ac              wrt-ac
                                        :enable-discovery-protection  disc-p
                                        :enable-liveliness-protection live-p
                                        :metadata-protection-kind     meta-k
                                        :data-protection-kind         data-k)
                                       result)))))))
            (make-governance :allow-unauthenticated      allow-u
                             :enable-join-ac             join-ac
                             :discovery-protection-kind  disc-k
                             :liveliness-protection-kind live-k
                             :rtps-protection-kind       rtps-k
                             :topic-rules                (or trules '()))))))))

(defun* governance-topic-rule (gov topic-name)
    (function (governance string) (values boolean boolean))
  "Values (read-ac write-ac) for the first topic_rule matching TOPIC-NAME (§9.4.1.2.4); (nil nil) if none."
  (dolist (rule (governance-topic-rules gov) (values nil nil))
    (when (%topic-match-p (topic-rule-topic-expr rule) topic-name)
      (return (values (topic-rule-enable-read-ac rule) (topic-rule-enable-write-ac rule))))))

(defun* governance-discovery-protection (gov)
    (function (governance) keyword)
  "ProtectionKind for RTPS discovery traffic — one of +protection-kinds+ (§9.4.1.2.3)."
  (governance-discovery-protection-kind gov))

(defun* governance-liveliness-protection (gov)
    (function (governance) keyword)
  "ProtectionKind for liveliness traffic — one of +protection-kinds+ (§9.4.1.2.3)."
  (governance-liveliness-protection-kind gov))

(defun* governance-rtps-protection (gov)
    (function (governance) keyword)
  "ProtectionKind for whole-RTPS-message protection — one of +protection-kinds+ (§9.4.1.2.3)."
  (governance-rtps-protection-kind gov))

(defun* protection-kind-base (kind)
    (function (keyword) (values (member :none :sign :encrypt) boolean))
  "Decompose a DDS-Security 1.1 §9.4.1.2 ProtectionKind KIND into (values BASE-KIND ORIGIN-AUTH-P): the
   base submessage-protection kind (:none | :sign | :encrypt — exactly the KIND argument of
   dds.security:encode-datawriter-submessage) plus whether the *_WITH_ORIGIN_AUTHENTICATION
   receiver-specific-MAC tier (§9.5.3.3.4.3) additionally applies. :none -> (:none nil); :sign/:encrypt ->
   themselves with NIL; :sign/:encrypt-with-origin-auth -> the base kind with T. ECASE fail-closes on an
   unknown keyword (it never silently maps to :none — false-NONE would be a silent protection downgrade)."
  (ecase kind
    (:none                     (values :none    nil))
    (:sign                     (values :sign    nil))
    (:encrypt                  (values :encrypt nil))
    (:sign-with-origin-auth    (values :sign    t))
    (:encrypt-with-origin-auth (values :encrypt t))))

(defun* topic-discovery-protected-p (gov topic-name)
    (function (governance string) boolean)
  "T if the first topic_rule matching TOPIC-NAME has enable_discovery_protection set (§9.4.1.2.4)."
  (dolist (rule (governance-topic-rules gov) nil)
    (when (%topic-match-p (topic-rule-topic-expr rule) topic-name)
      (return (topic-rule-enable-discovery-protection rule)))))

(defun* topic-metadata-protection (gov topic-name)
    (function (governance string) keyword)
  "BasicProtectionKind for the first topic_rule matching TOPIC-NAME (§9.4.1.2.4); :none if no rule matches."
  (dolist (rule (governance-topic-rules gov) :none)
    (when (%topic-match-p (topic-rule-topic-expr rule) topic-name)
      (return (topic-rule-metadata-protection-kind rule)))))
