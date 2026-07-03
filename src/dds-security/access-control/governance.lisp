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

(defun* governance-any-protection-p (gov)
    (function (governance) boolean)
  "T iff GOV mandates ANY cryptographic protection — a domain rtps/discovery/liveliness kind non-NONE, or a
   topic rule with metadata/data protection non-NONE or discovery/liveliness protection enabled (§9.4.1.2.3/.4).
   §8.5 crypto-token keying is a §7.3 endpoint-match precondition ONLY when this holds; when NIL (every kind
   NONE) matched endpoints communicate in the clear and gate on §8.7 authentication + §8.4 permissions alone
   (§8.4.2.9 — matching is an access-control decision; §8.5 crypto is engaged only for protected endpoints)."
  (or (not (eq (governance-rtps-protection-kind gov) :none))
      (not (eq (governance-discovery-protection-kind gov) :none))
      (not (eq (governance-liveliness-protection-kind gov) :none))
      (some (lambda (r)
              (or (not (eq (topic-rule-metadata-protection-kind r) :none))
                  (not (eq (topic-rule-data-protection-kind r) :none))
                  (topic-rule-enable-discovery-protection r)
                  (topic-rule-enable-liveliness-protection r)))
            (governance-topic-rules gov))))

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

(defun* topic-data-protection (gov topic-name)
    (function (governance string) keyword)
  "data_protection_kind (BasicProtectionKind, §9.4.1.2.4) for the first topic_rule matching TOPIC-NAME — the
   serialized-payload (SecuredPayload) protection tier; :none if no rule matches. :none means the payload rides
   PLAIN (no SecuredPayload) — the crypto-transform serialized-payload encode/decode MUST be skipped, else a plain
   payload is wrongly encrypted on send / decode-failed-and-dropped on receive (the SIGN-tier data=NONE path)."
  (dolist (rule (governance-topic-rules gov) :none)
    (when (%topic-match-p (topic-rule-topic-expr rule) topic-name)
      (return (topic-rule-data-protection-kind rule)))))

(defun* %basic-protection-rank (kind)
    (function (keyword) (integer 0 2))
  "Rank a §9.4.1.2.4 BasicProtectionKind for MOST-PROTECTIVE (max) selection: :encrypt 2 > :sign 1 > :none 0.
   Shared by governance-effective-{data,metadata}-protection. ECASE fail-closes on an unknown keyword — it never
   silently ranks 0 (a silent protection downgrade)."
  (ecase kind (:none 0) (:sign 1) (:encrypt 2)))

(defun* %governance-effective-basic-protection (gov accessor)
    (function (governance function) keyword)
  "The MOST-PROTECTIVE BasicProtectionKind (max :encrypt > :sign > :none, §9.4.1.2.4) that ACCESSOR reads off any
   topic_rule; :none only when EVERY rule (or no rule) is that-kind=NONE. Shared engine for
   governance-effective-data-protection (ACCESSOR = topic-rule-data-protection-kind) and
   governance-effective-metadata-protection (ACCESSOR = topic-rule-metadata-protection-kind) — the fail-closed
   participant-level default so a first-rule NONE can never downgrade below a later protected rule."
  (let ((best :none))
    (dolist (r (governance-topic-rules gov) best)
      (when (> (%basic-protection-rank (funcall accessor r))
               (%basic-protection-rank best))
        (setf best (funcall accessor r))))))

(defun* governance-effective-data-protection (gov)
    (function (governance) keyword)
  "The MOST-PROTECTIVE data_protection_kind over ALL topic_rules (max :encrypt > :sign > :none, §9.4.1.2.4);
   :none only when EVERY rule (or no rule) is data=NONE. The PARTICIPANT-level serialized-payload default the
   access layer stamps at create-participant (%install-access-control) as a FAIL-CLOSED fallback: a governance
   whose FIRST rule is data=NONE while a LATER rule is data=ENCRYPT must NEVER downgrade the participant default
   to :none (a plain payload wrongly accepted on an ENCRYPT topic = false-ACCEPT). The DCPS create path and
   add-local-{writer,reader} REFINE this to the endpoint's ACTUAL per-topic kind (topic-data-protection via the
   %install-access-control-installed resolver), so a genuine data=NONE topic is NOT forced to protection (no
   false-REJECT); this most-protective value governs only when no per-topic refinement has run."
  (%governance-effective-basic-protection gov #'topic-rule-data-protection-kind))

(defun* governance-effective-metadata-protection (gov)
    (function (governance) keyword)
  "The MOST-PROTECTIVE metadata_protection_kind over ALL topic_rules (max :encrypt > :sign > :none, §9.4.1.2.4);
   :none only when EVERY rule (or no rule) is metadata=NONE. The PARTICIPANT-level user-DATA-submessage default the
   access layer stamps at create-participant (%install-access-control) as a FAIL-CLOSED fallback: a governance
   whose FIRST rule is metadata=NONE while a LATER rule is metadata=SIGN/ENCRYPT must NEVER downgrade the
   participant default to :none (an unprotected user submessage wrongly emitted on a protected topic =
   false-ACCEPT). The DCPS create path (%set-user-metadata-protection) and add-local-{writer,reader}
   (%refine-user-protection) REFINE this to the endpoint's ACTUAL per-topic kind (topic-metadata-protection via the
   %install-access-control-installed resolver), so a genuine metadata=NONE topic stays NONE (no false-REJECT); this
   most-protective value governs only when no per-topic refinement has run."
  (%governance-effective-basic-protection gov #'topic-rule-metadata-protection-kind))

(defun* governance-mixed-nonnone-kind-conflict (gov)
    (function (governance) (or null topic-rule))
  "The first topic_rule whose data_protection AND metadata_protection are BOTH non-NONE §9.4.1.2.4
   BasicProtectionKinds of DIFFERENT base kind (protection-kind-base: :sign vs :encrypt) — e.g. data=SIGN +
   metadata=ENCRYPT, or data=ENCRYPT + metadata=SIGN — the mixed-kind combo a SINGLE user-endpoint EntityCrypto
   key cannot represent (§9.5.2: one transformation_kind serves BOTH the payload/data and submessage/metadata
   tiers on the user writer/reader). The payload kind WINS in %cm-entity-protection-kind, so data=SIGN would
   DOWNGRADE an ENCRYPT-mandated user submessage onto the visible GMAC kind — a confidentiality downgrade.
   NIL when every rule is same-base-kind or has NONE on a tier (both representable — the payload kind and the
   submessage kind agree, or one tier is inert). Consulted at %install-access-control to FAIL-CLOSED REJECT such a
   contradictory governance at create-participant (a clear error) rather than silently collapse to one km
   (ADR-0040). Base-compared (protection-kind-base) so an origin-auth submessage variant of the SAME base kind is
   NOT flagged (it maps to the same GMAC/GCM km). Fast DDS represents this with separate EntityKeyMaterials
   (payload=last, submessage=first); we do not, so we reject the unrepresentable combo instead of mis-protecting."
  (find-if (lambda (r)
             (let ((d (protection-kind-base (topic-rule-data-protection-kind r)))
                   (m (protection-kind-base (topic-rule-metadata-protection-kind r))))
               (and (not (eq d :none)) (not (eq m :none)) (not (eq d m)))))
           (governance-topic-rules gov)))
