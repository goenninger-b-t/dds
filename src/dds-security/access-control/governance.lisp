(in-package #:dds.security)

;;; DDS-Security 1.1 §9.4.1.2.3 — Governance document data model + XML parser.

(defstruct* (governance (:constructor make-governance))
  "DDS-Security 1.1 §9.4.1.2.3 governance data model: first domain_rule (slice-scope subset)."
  (allow-unauthenticated nil :type boolean)
  (enable-join-ac        nil :type boolean)
  (topic-rules           '() :type list))

;;; topic-rules entries: (topic-expr . (read-ac . write-ac)).

(defun* parse-governance (octets)
    (function ((simple-array (unsigned-byte 8) (*))) (or governance null))
  "Parse DDS-Security 1.1 §9.4.1.2.3 Governance document from OCTETS; NIL on any malformed input."
  (block parse
    (handler-bind ((error (lambda (c) (declare (ignore c)) (return-from parse nil))))
      (let* ((str   (map 'string #'code-char octets))
             (tree  (xmls:parse str))
             (pols  (%ac-node-child tree "policies"))
             (dar   (%ac-node-child pols "domain_access_rules"))
             (drule (%ac-node-child dar  "domain_rule")))
        (unless drule (return-from parse nil))
        (let* ((allow-u (%ac-node-bool drule "allow_unauthenticated_participants"))
               (join-ac (%ac-node-bool drule "enable_join_access_control"))
               (tar     (%ac-node-child drule "topic_access_rules"))
               (trules  (when tar
                          (mapcar (lambda (tr)
                                    (cons (or (%ac-node-text-req tr "topic_expression") "")
                                          (cons (%ac-node-bool tr "enable_read_access_control")
                                                (%ac-node-bool tr "enable_write_access_control"))))
                                  (%ac-node-children-named tar "topic_rule")))))
          (make-governance :allow-unauthenticated allow-u
                           :enable-join-ac        join-ac
                           :topic-rules           (or trules '())))))))

(defun* governance-topic-rule (gov topic-name)
    (function (governance string) (values boolean boolean))
  "Values (read-ac write-ac) for the first topic_rule matching TOPIC-NAME (§9.4.1.2.4); (nil nil) if none."
  (dolist (rule (governance-topic-rules gov) (values nil nil))
    (when (%topic-match-p (car rule) topic-name)
      (return (values (cadr rule) (cddr rule))))))
