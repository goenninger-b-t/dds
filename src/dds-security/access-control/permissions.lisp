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

(defun* %dn-unescape (s)
    (function (string) (or string null))
  "RFC2253 §2.4 DN-value un-escaping -> the canonical (serialization-independent) value: `\\c` -> the literal char
   c (an escaped separator / space / #, so it compares as DATA, not a boundary), `\\XX` (exactly two hex digits) ->
   the byte 0xXX. NIL (FAIL-CLOSED) on a MALFORMED escape — a trailing lone `\\`, or `\\` + a single hex digit — so
   an ambiguous DN never normalizes to a matchable token (no false-ACCEPT of a wrong identity)."
  (let ((out (make-string-output-stream)) (i 0) (n (length s)))
    (loop while (< i n) do
      (let ((c (char s i)))
        (cond
          ((char/= c #\\) (write-char c out) (incf i))
          ((>= (1+ i) n) (return-from %dn-unescape nil))   ; trailing lone backslash -> malformed
          (t (let* ((d (char s (1+ i))) (dv (digit-char-p d 16)))
               (cond
                 ((null dv) (write-char d out) (incf i 2))   ; \special -> the literal char
                 ((or (>= (+ i 2) n) (null (digit-char-p (char s (+ i 2)) 16)))
                  (return-from %dn-unescape nil))            ; \ + a single hex digit -> malformed
                 (t (write-char (code-char (+ (* 16 dv) (digit-char-p (char s (+ i 2)) 16))) out)
                    (incf i 3))))))))
    (get-output-stream-string out)))

(defun* %dn-split-unescaped (s sep)
    (function (string character) list)
  "Split DN string S into raw RDN tokens on UNESCAPED SEP only (RFC2253 §2.4 — a `\\`-escaped separator is part of
   a value, never a boundary; a naive split mis-cut an escaped comma -> a latent false-REJECT of a conformant DN).
   Escapes are left IN the tokens (unescaped per-field afterwards); a trailing lone `\\` leaves its token ending in
   `\\` so %dn-unescape then fail-closes it."
  (let ((toks '()) (start 0) (esc nil) (n (length s)))
    (dotimes (i n)
      (let ((c (char s i)))
        (cond (esc            (setf esc nil))
              ((char= c #\\)  (setf esc t))
              ((char= c sep)  (push (subseq s start i) toks) (setf start (1+ i))))))
    (nreverse (cons (subseq s start n) toks))))

(defun* %dn-attr-value-pos (tok)
    (function (string) (or fixnum null))
  "The index of the first UNESCAPED `=` in RDN token TOK — the attribute-type / value boundary (RFC2253 §2.3) — or
   NIL if TOK has no unescaped `=` (a malformed RDN)."
  (let ((esc nil))
    (dotimes (i (length tok) nil)
      (let ((c (char tok i)))
        (cond (esc            (setf esc nil))
              ((char= c #\\)  (setf esc t))
              ((char= c #\=)  (return i)))))))

(defun* %dn-trim-unescaped (s)
    (function (string) string)
  "Trim leading spaces and trailing UNESCAPED spaces from DN fragment S. RFC2253 §2.4: a space at the end of a
   value may be `\\`-escaped — that space is value DATA and must survive to %dn-unescape (a plain trim stranded
   its `\\` -> a spurious :malformed -> a false-REJECT of a conformant DN, while the equivalent `\\20` hex form
   worked). A trailing lone `\\` is preserved so %dn-unescape still fail-closes it."
  (let* ((n     (length s))
         (start (or (position #\Space s :test #'char/=) n))
         (end   start)
         (esc   nil))
    (loop for i from start below n
          for c = (char s i)
          do (cond (esc                (setf esc nil end (1+ i)))
                   ((char= c #\\)      (setf esc t))
                   ((char/= c #\Space) (setf end (1+ i)))))
    (when esc (setf end n))   ; trailing lone backslash stays -> %dn-unescape fail-closes it
    (subseq s start end)))

(defun* %dn-normalize-ava (ava)
    (function (string) (or string null))
  "Canonicalize ONE RFC2253 AttributeTypeAndValue AVA (§2.3) to \"TYPE=value\": the attribute TYPE upcased (types
   are case-INSENSITIVE, §2.3) + whitespace-trimmed, the VALUE trimmed of UNESCAPED whitespace only
   (%dn-trim-unescaped — a `\\ `-escaped trailing space is DATA, §2.4) then RFC2253-UN-escaped to its canonical
   (serialization-independent) form (%dn-unescape — an escaped separator/space and a `\\XX` hex escape then
   compare as DATA, §2.4). NIL (FAIL-CLOSED) on a malformed AVA — no unescaped `=`, an empty attribute type,
   or a malformed escape — so an ambiguous AVA never yields a matchable token (no false-ACCEPT)."
  (let* ((tok (%dn-trim-unescaped ava))
         (eqp (%dn-attr-value-pos tok)))
    (when (and eqp (plusp eqp))
      (let ((val (%dn-unescape (%dn-trim-unescaped (subseq tok (1+ eqp))))))
        (when val
          (concatenate 'string
                       (string-upcase (string-trim " " (subseq tok 0 eqp)))
                       "=" val))))))

(defun* %dn-normalize-rdn (rdn)
    (function (string) (or list (eql :malformed)))
  "Canonicalize ONE RelativeDistinguishedName — an X.501 RDN is a SET of one-or-more `+`-joined AVAs (RFC2253
   §2.2) — to the SORTED LIST of canonical AVA strings. STRUCTURAL, never re-joined into one string: a `+`-joined
   form is NON-INJECTIVE because an un-escaped value may contain literal `+` and `=`, so a single-AVA value could
   forge a multi-AVA join (CN=x\\+O=y vs CN=x+O=y — a false-ACCEPT); the list keeps the AVA boundary structural.
   Split on UNESCAPED `+` only (%dn-split-unescaped; an escaped `\\+` stays value DATA, §2.4), canonicalize each
   AVA (%dn-normalize-ava), then SORT the AVA strings. Sorting is correct HERE (the RDN is a SET — its AVA order
   is not significant), unlike sorting the RDN SEQUENCE. :MALFORMED (FAIL-CLOSED) if ANY AVA is malformed (no
   `=`, empty type, empty AVA e.g. `CN=a+`, or bad escape)."
  (let ((avas '()))
    (dolist (raw (%dn-split-unescaped rdn #\+))
      (let ((a (%dn-normalize-ava raw)))
        (unless a (return-from %dn-normalize-rdn :malformed))
        (push a avas)))
    (sort avas #'string<)))

(defun* %dn-normalize (s)
    (function (string) (or list (eql :malformed)))
  "Parse an X.500 Distinguished Name string — OpenSSL oneline (/CN=a/O=b/C=DE, what X509_NAME_oneline emits) OR
   RFC2253/RFC1779 (CN=a,O=b,C=DE, what X509_NAME_print_ex+XN_FLAG_RFC2253 and Fast DDS's rfc2253_string_compare
   use) — into the DN's canonical RDN SEQUENCE: a STRUCTURAL list, in DN-sequence order (root-first), of RDNs,
   each RDN itself the sorted list of its canonical \"TYPE=value\" AVA strings (%dn-normalize-rdn — the AVA
   boundary stays structural, never re-joined into a string, which would be non-injective). The sequence is
   ORDER-PRESERVING, NOT sorted: an X.501 DN is a SEQUENCE of RDNs (order is significant) — sorting the sequence
   would collide two genuinely-different DNs (CN=a,O=b vs O=b,CN=a) into one list (identity confusion /
   false-ACCEPT). The leading char selects the '/' (oneline) vs ',' (RFC2253) RDN separator; RDNs are split only
   on UNESCAPED separators (%dn-split-unescaped). DIRECTION PINNING (RFC2253 §2.1): oneline is printed FORWARD
   (root-first) so parse order IS the sequence; RFC2253 prints the sequence in REVERSE (the string starts with
   the LAST RDN) so the parse order is reversed to recover the sequence — both forms of one DN thus map to the
   SAME canonical sequence. Each RDN is canonicalized as an unordered AVA SET (multi-valued `+`, §2.2); each
   attribute TYPE is upcased (case-INSENSITIVE, §2.3) while the VALUE keeps its case (case-SENSITIVE) and is
   RFC2253-UN-escaped (§2.4). Empty (separator-artifact) RDNs are dropped. Returns :malformed (FAIL-CLOSED —
   never matched by %dn-equal) on ANY malformed RDN/AVA: no unescaped `=`, an empty attribute type, an empty
   AVA, or a malformed escape — so an ambiguous/malformed DN does NOT authorize (no false-ACCEPT)."
  (let ((oneline (and (plusp (length s)) (char= (char s 0) #\/)))
        (rdns '()))
    (dolist (raw (%dn-split-unescaped s (if oneline #\/ #\,)))
      (let ((tok (%dn-trim-unescaped raw)))
        (when (plusp (length tok))
          (let ((c (%dn-normalize-rdn tok)))
            (when (eq c :malformed) (return-from %dn-normalize :malformed))
            (push c rdns)))))
    ;; rdns is in REVERSE parse order (push): oneline sequence = parse order (nreverse); RFC2253 sequence = reverse
    ;; of parse order (§2.1) = the push order as-accumulated.
    (if oneline (nreverse rdns) rdns)))

(defun* %dn-equal (a b)
    (function (string string) boolean)
  "T iff DN strings A and B denote the SAME X.509 subject independent of serialization (OpenSSL oneline vs
   RFC2253), attribute-TYPE case, whitespace, multi-valued-RDN AVA order (§2.2), and RFC2253 value ESCAPING
   (§2.4) — DDS-Security 1.1 §9.4.1.3 binds the grant by the X.509 subject DN, not by one string form. The RDN
   SEQUENCE order is SIGNIFICANT (X.501) and PINNED, not sorted: %dn-normalize recovers the same canonical
   sequence from either serialization (direction pinning, §2.1), so a genuine RDN reorder (CN=a,O=b vs O=b,CN=a)
   correctly does NOT match. Comparison is STRUCTURAL: equal (NON-ZERO) RDN count + per-RDN equal AVA count +
   every AVA string equal, all IN ORDER (RDNs) / in sorted-set order (AVAs within an RDN) — no sort of RDNs, no
   reversal-tolerant fallback (would reintroduce the reorder collision), no string re-join (would let a value
   containing literal `+`/`=` forge an AVA boundary — false-ACCEPT). FAIL-CLOSED: a :malformed or empty
   normalization on EITHER side -> NIL (no false-ACCEPT of a wrong or ambiguous identity — an unparseable DN
   never matches, not even an identical unparseable grant)."
  (let ((na (%dn-normalize a)) (nb (%dn-normalize b)))
    (and (consp na) (consp nb) (= (length na) (length nb))
         (every (lambda (ra rb)
                  (and (= (length ra) (length rb)) (every #'string= ra rb)))
                na nb))))

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
