(in-package #:dds.security)

;;; DDS-Security 1.1 §9.4.1.3.2 — Permissions data model + XML parser + allow/deny matcher.

(defstruct* (permissions (:constructor make-permissions))
  "DDS-Security 1.1 §9.4.1.3.2 permissions grant data model (one struct per <grant> element)."
  (subject-name "" :type string)
  (not-before   "" :type string)
  (not-after    "" :type string)
  (default      :deny :type (member :allow :deny))
  (rules        '() :type list))

;;; rules: (action . (operation . topic-expr-list)); action ∈ {:allow :deny}, op ∈ {:publish :subscribe}.

(defun* parse-permissions (octets)
    (function ((simple-array (unsigned-byte 8) (*))) (or list null))
  "Parse DDS-Security 1.1 §9.4.1.3.2 Permissions XML from OCTETS; return a list of PERMISSIONS structs
   (one per <grant> element, XSD grant+, in document order), or NIL on malformed input or no grants."
  (block parse
    (handler-bind ((error (lambda (c) (declare (ignore c)) (return-from parse nil))))
      (let* ((str      (map 'string #'code-char octets))
             (tree     (xmls:parse str))
             (perms-nd (%ac-node-child tree "permissions"))
             (grants   (%ac-node-children-named perms-nd "grant")))
        (unless grants (return-from parse nil))
        (let ((result '()))
          (dolist (grant grants)
            (let* ((sname   (or (%ac-node-text-req grant "subject_name") ""))
                   (val     (%ac-node-child grant "validity"))
                   (nbefore (or (and val (%ac-node-text-req val "not_before")) ""))
                   (nafter  (or (and val (%ac-node-text-req val "not_after")) ""))
                   (dflt-nd (%ac-node-child grant "default"))
                   (dflt-s  (and dflt-nd
                                 (string-trim +ac-whitespace+
                                              (or (%ac-node-text dflt-nd) ""))))
                   (dflt    (if (and dflt-s (string= "ALLOW" dflt-s)) :allow :deny))
                   (rules   (%ac-parse-grant-rules grant)))
              (push (make-permissions :subject-name sname
                                      :not-before   nbefore
                                      :not-after    nafter
                                      :default      dflt
                                      :rules        rules)
                    result)))
          (and result (nreverse result)))))))

(defun* %permissions-match-p (perms operation topic-name)
    (function (permissions symbol string) boolean)
  "First-match-wins rule evaluation for OPERATION on TOPIC-NAME; default on no match (§9.4.1.3.2.10)."
  (dolist (rule (permissions-rules perms) (eq (permissions-default perms) :allow))
    (let ((action (car  rule))
          (op     (cadr rule))
          (topics (cddr rule)))
      (when (and (eq op operation)
                 (some (lambda (expr) (%topic-match-p expr topic-name)) topics))
        (return (eq action :allow))))))

(defun* permissions-allow-publish-p (perms topic-name)
    (function (permissions string) boolean)
  "T if PERMS grants publish on TOPIC-NAME; first-match-wins ordered rules (§9.4.1.3.2.10)."
  (%permissions-match-p perms :publish topic-name))

(defun* permissions-allow-subscribe-p (perms topic-name)
    (function (permissions string) boolean)
  "T if PERMS grants subscribe on TOPIC-NAME; first-match-wins ordered rules (§9.4.1.3.2.10)."
  (%permissions-match-p perms :subscribe topic-name))
