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

(defun* %dn-normalize (s)
    (function (string) list)
  "Parse an X.500 Distinguished Name string — OpenSSL oneline (/CN=a/O=b/C=DE, what X509_NAME_oneline
   emits) OR RFC2253/RFC1779 (CN=a,O=b,C=DE, what X509_NAME_print_ex+XN_FLAG_RFC2253 and Fast DDS's
   rfc2253_string_compare use) — into a SORTED list of canonical \"ATTR=value\" tokens (ATTR upcased,
   surrounding whitespace trimmed). Sorting absorbs the oneline-forward vs RFC2253-reverse RDN order;
   the leading separator selects '/' vs ','. Empty tokens dropped."
  (let ((toks '()) (start 0) (n (length s))
        (sep (if (and (plusp (length s)) (char= (char s 0) #\/)) #\/ #\,)))
    (flet ((emit (piece)
             (let* ((piece (string-trim " " piece))
                    (eqp   (position #\= piece)))
               (when (and eqp (plusp eqp))
                 (push (concatenate 'string
                                    (string-upcase (string-trim " " (subseq piece 0 eqp)))
                                    "=" (string-trim " " (subseq piece (1+ eqp))))
                       toks)))))
      (dotimes (i (1+ n))
        (when (or (= i n) (char= (char s i) sep))
          (emit (subseq s start i))
          (setf start (1+ i)))))
    (sort toks #'string<)))

(defun* %dn-equal (a b)
    (function (string string) boolean)
  "T iff DN strings A and B denote the same X.509 subject independent of serialization (OpenSSL oneline
   vs RFC2253) and RDN order — DDS-Security 1.1 §9.4.1.3 binds the grant by the X.509 subject DN, not by
   one string form. Requires equal RDN count + every normalized token equal (strict; no false-accept,
   and the cert is CA-validated upstream so a reordered-RDN forgery is out of scope)."
  (let ((na (%dn-normalize a)) (nb (%dn-normalize b)))
    (and na (= (length na) (length nb)) (every #'string= na nb))))

(defun* permissions-grant-for (subject grants)
    (function (string list) (or permissions null))
  "The first PERMISSIONS grant in GRANTS whose subject_name denotes the same X.509 DN as SUBJECT, via
   the serialization-insensitive %dn-equal (DDS-Security 1.1 §9.4.1.3 subject binding). NIL if none. The
   single subject-match site for both local (validate-local-permissions) and remote (validate-remote-
   permissions, secure-endpoint authorize) binding, so cross-vendor oneline/RFC2253 forms interoperate."
  (find-if (lambda (g) (%dn-equal subject (permissions-subject-name g))) grants))

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
