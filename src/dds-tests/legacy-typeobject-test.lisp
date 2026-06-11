(in-package #:dds.tests)

;;; Legacy-TypeObject structural TLV tokenizer (ADR 0009, NFR-SEC-POSTURE). Inflates the
;;; locked live Connext C_Shape PID_TYPE_OBJECT_LB capture (interop/connext/typeobject-corpus/
;;; README.md, 232 octets -> 536-octet inflated legacy TypeObject) and asserts the tree shape
;;; the C_Shape vs C_Shape2 differential walk established (docs/provenance.md 2026-06-11): a
;;; synthetic root over top-level nodes; the type-name node "C_Shape"; member-name nodes
;;; "color"/"x"/"y"/"shapesize" and the dependent "string_255_character"; and that the walk
;;; consumes EXACTLY to the buffer end (no trailing garbage). Plus bounds/resource-guard
;;; rejections so a malformed inflated buffer never tokenizes into an unbounded or OOB walk.

(defun* %connext-c-shape-lb ()
    (function () (simple-array (unsigned-byte 8) (*)))
  "The live RTI Connext 7.3.1 C_Shape PID_TYPE_OBJECT_LB parameter value (232 octets),
   captured 2026-06-11 (interop/connext/typeobject-corpus/README.md); inflates to a 536-octet
   legacy TypeObject (ADR 0009). C_Shape reproduces ShapeType (@key string color; long x,y,
   shapesize), so its member-name set cross-checks the structural tokenizer."
  (coerce
   '(1 0 0 0 24 2 0 0 219 0 0 0 120 218 99 172 231 96 0 129 55 140 12 12 76 96 22 11 131 24 144
     100 4 138 115 2 105 23 70 8 27 4 100 64 226 96 89 6 134 106 110 249 25 103 138 117 223 130
     100 156 227 131 51 18 11 82 193 234 24 193 38 64 0 136 159 130 198 79 5 217 5 21 131 153
     171 2 54 23 2 132 161 116 197 85 159 52 75 166 45 149 108 64 118 114 126 78 126 17 84 61
     178 249 76 245 8 51 68 96 118 0 49 43 16 130 252 82 65 164 30 38 36 61 149 4 244 200 64
     197 152 161 122 184 128 116 49 200 247 197 153 85 169 56 244 194 48 72 84 24 170 6 100 90
     9 82 24 232 128 221 33 140 226 119 81 144 217 37 69 153 121 233 241 70 166 166 241 201 25
     137 69 137 201 37 169 69 12 88 236 65 14 107 30 32 76 133 202 128 196 79 64 197 255 35 185
     7 166 95 0 136 197 160 102 192 226 20 36 15 0 9 35 54 22 0)
   '(simple-array (unsigned-byte 8) (*))))

(defun* %lto-collect-names (root)
    (function (dds.types:lto-node) list)
  "All non-NIL NAMEs in the LTO-NODE tree under ROOT, in pre-order (test fixture)."
  (let ((names '()))
    (labels ((walk (n)
               (when (dds.types:lto-node-name n) (push (dds.types:lto-node-name n) names))
               (dolist (c (dds.types:lto-node-children n)) (walk c))))
      (walk root))
    (nreverse names)))

(defun* %lto-find-named (root name)
    (function (dds.types:lto-node string) (or null dds.types:lto-node))
  "The first LTO-NODE in the tree under ROOT whose NAME equals NAME, or NIL (test fixture)."
  (labels ((walk (n)
             (when (and (dds.types:lto-node-name n)
                        (string= (dds.types:lto-node-name n) name))
               (return-from walk n))
             (dolist (c (dds.types:lto-node-children n))
               (let ((hit (walk c))) (when hit (return-from walk hit))))
             nil))
    (walk root)))

(defun* run-lto-tokenize-test ()
    (function () t)
  "Test: structural TLV tokenizer over the locked live Connext C_Shape legacy TypeObject,
   plus bounds/resource-guard rejections (ADR 0009, NFR-SEC-POSTURE)."
  (let* ((lb (%connext-c-shape-lb))
         (inflated (dds.types:inflate-type-object-lb lb)))
    (%check :lto-inflate (and inflated (= (length inflated) 536))
            "C_Shape PID_TYPE_OBJECT_LB inflates to the declared 536-octet legacy TypeObject")
    (let ((root (dds.types:tokenize-legacy-type-object inflated)))
      (%check :lto-root (dds.types:lto-node-p root)
              "tokenize-legacy-type-object returns an lto-node root")
      ;; the synthetic root spans the whole buffer and consumed exactly to the end
      (%check :lto-root-extent
              (and (zerop (dds.types:lto-node-value-start root))
                   (= (dds.types:lto-node-value-end root) (length inflated)))
              "the root value-extent is exactly [0, buffer-end) — the walk consumed all bytes")
      (%check :lto-root-children (plusp (length (dds.types:lto-node-children root)))
              "the root has at least one top-level node")
      ;; the type name and the full member/dependent name set the differential walk established
      (let ((names (%lto-collect-names root)))
        (%check :lto-type-name (member "C_Shape" names :test #'string=)
                "the type-name node 'C_Shape' is recovered")
        (%check :lto-member-names
                (every (lambda (n) (member n names :test #'string=))
                       '("color" "shapesize" "string_255_character"))
                "the member/dependent names color, shapesize, string_255_character are recovered")
        (%check :lto-single-char-members
                (and (member "x" names :test #'string=) (member "y" names :test #'string=))
                "the single-character member names x, y are recovered (length-2 NUL-terminated)"))
      ;; a named node's value-extent lies strictly within its parent's — structural sanity
      (let ((cnode (%lto-find-named root "color")))
        (%check :lto-named-node
                (and cnode (< (dds.types:lto-node-value-start cnode)
                              (dds.types:lto-node-value-end cnode)))
                "the 'color' node carries a non-empty value extent")))
    ;; resource guards (NFR-SEC-POSTURE): a depth-0 limit forces NIL on any nested structure
    (let ((dds.types:*lto-max-depth* 0))
      (%check :lto-depth-guard (null (dds.types:tokenize-legacy-type-object inflated))
              "*lto-max-depth* 0 rejects the nested C_Shape tree (no OOB / runaway recursion)"))
    (let ((dds.types:*lto-max-elements* 2))
      (%check :lto-element-guard (null (dds.types:tokenize-legacy-type-object inflated))
              "*lto-max-elements* 2 rejects the multi-node C_Shape tree (resource guard)"))
    ;; trailing-garbage guard: one extra octet past a clean tree must reject (no partial accept)
    (let ((padded (make-array (1+ (length inflated)) :element-type '(unsigned-byte 8))))
      (replace padded inflated)
      (%check :lto-trailing-garbage (null (dds.types:tokenize-legacy-type-object padded))
              "a trailing garbage octet past the node stream rejects (consumed /= end)"))
    ;; truncation: a buffer cut mid-node must reject, never read OOB
    (%check :lto-truncated
            (null (dds.types:tokenize-legacy-type-object (subseq inflated 0 30)))
            "a buffer truncated mid-node rejects (bounds-checked, no OOB access)")
    (%check :lto-empty (null (dds.types:tokenize-legacy-type-object
                              (make-array 0 :element-type '(unsigned-byte 8))))
            "an empty buffer rejects"))
  t)
