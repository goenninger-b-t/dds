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

(defun* %lto-find-parent (root target)
    (function (dds.types:lto-node dds.types:lto-node) (or null dds.types:lto-node))
  "The first node in the tree under ROOT that has TARGET as a direct child, or NIL (test fixture)."
  (labels ((walk (n)
             (dolist (c (dds.types:lto-node-children n))
               (when (eq c target) (return-from walk n)))
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
                "color, shapesize, string_255_character recovered (x/y checked in :lto-single-char-members)")
        (%check :lto-single-char-members
                (and (member "x" names :test #'string=) (member "y" names :test #'string=))
                "the single-character member names x, y are recovered (length-2 NUL-terminated)"))
      ;; a named node's value-extent is non-empty and lies within its direct parent's extent
      (let* ((cnode (%lto-find-named root "color"))
             (parent (and cnode (%lto-find-parent root cnode))))
        (%check :lto-named-node
                (and cnode parent
                     (< (dds.types:lto-node-value-start cnode)
                        (dds.types:lto-node-value-end cnode))
                     (<= (dds.types:lto-node-value-start parent)
                         (dds.types:lto-node-value-start cnode))
                     (<= (dds.types:lto-node-value-end cnode)
                         (dds.types:lto-node-value-end parent)))
                "the 'color' node has non-empty value extent contained within its parent's extent")))
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

;;; Legacy-TypeObject semantic interpreter, struct skeleton (Task 2.1). Folds the inflated
;;; C_Shape legacy TypeObject into a minimal-struct-type and asserts name/extensibility and the
;;; per-member name+id the C_Shape / C_Shape3 / C_Shape4 differential established (docs/provenance.md
;;; 2026-06-11): the id is the 0-based declaration order (color 0, x 1, y 2, shapesize 3). Member
;;; TYPEs are not decoded (Task 2.2/2.3) and so are not asserted; extensibility defaults :final
;;; (Task 2.4 derives appendable/mutable).

(defun* %lto-model-equal-p (parsed name extensibility name-id-alist)
    (function ((or null dds.types:minimal-struct-type (member :unsupported)) string symbol list) t)
  "Assert PARSED is a minimal-struct-type with type NAME, EXTENSIBILITY, and exactly the
   members in NAME-ID-ALIST ((member-name . member-id) in order). Compares name, extensibility,
   member count, and per-member name + id; SKIPS member TypeIdentifiers (Task 2.2/2.3 decodes
   member types). Test fixture."
  (and (dds.types:minimal-struct-type-p parsed)
       (string= (dds.types:minimal-struct-type-name parsed) name)
       (eq (dds.types:minimal-struct-type-extensibility parsed) extensibility)
       (let ((ms (dds.types:minimal-struct-type-members parsed)))
         (and (= (length ms) (length name-id-alist))
              (every (lambda (m ni)
                       (and (string= (dds.types:minimal-struct-member-name m) (car ni))
                            (= (dds.types:minimal-struct-member-id m) (cdr ni))))
                     ms name-id-alist)))))

(defun* run-lto-parse-shape-test ()
    (function () t)
  "Test: parse-legacy-type-object folds the locked live Connext C_Shape legacy TypeObject into
   a minimal-struct-type skeleton — name C_Shape, :final, members color/x/y/shapesize with the
   0-based declaration-order ids the differential experiments established (ADR 0009,
   docs/provenance.md 2026-06-11). Plus the :unsupported / NIL fail discipline."
  (let* ((lb (%connext-c-shape-lb))
         (inflated (dds.types:inflate-type-object-lb lb))
         (parsed (dds.types:parse-legacy-type-object inflated)))
    (%check :lto-parse-shape
            (%lto-model-equal-p parsed "C_Shape" :final
                                '(("color" . 0) ("x" . 1) ("y" . 2) ("shapesize" . 3)))
            "parse-legacy-type-object recovers C_Shape :final {color 0, x 1, y 2, shapesize 3}")
    ;; member-order check: members are listed in declaration order, color first
    (%check :lto-parse-order
            (string= (dds.types:minimal-struct-member-name
                      (first (dds.types:minimal-struct-type-members parsed)))
                     "color")
            "members are in declaration order (color first)")
    ;; primitive members (x/y/shapesize are long=i32) carry a TI (Task 2.2); the string member
    ;; (color) now decodes to a STRING8 bound 255 with @key set (Task 2.3)
    (let ((ms (dds.types:minimal-struct-type-members parsed)))
      (let ((cti (dds.types:minimal-struct-member-type-identifier (first ms))))
        (%check :lto-parse-string-ti
                (and cti
                     (= (dds.types:type-identifier-kind cti) dds.types:+ti-string8-small+)
                     (= (dds.types:type-identifier-bound cti) 255))
                "the string member 'color' decodes to a STRING8 TI with bound 255 (Task 2.3)")
        (%check :lto-parse-color-key
                (dds.types:minimal-struct-member-key-p (first ms))
                "the @key string member 'color' has key-p T (Task 2.3)"))
      (%check :lto-parse-long-tis
              (every (lambda (m)
                       (let ((ti (dds.types:minimal-struct-member-type-identifier m)))
                         (and ti (= (dds.types:type-identifier-kind ti) dds.types:+tk-int32+))))
                     (rest ms))
              "the long members x/y/shapesize decode to TK_INT32 TIs (Task 2.2)")
      (%check :lto-parse-long-nonkey
              (notany #'dds.types:minimal-struct-member-key-p (rest ms))
              "the non-key long members x/y/shapesize have key-p NIL (Task 2.3)"))
    ;; malformed input (does not tokenize) -> NIL, mirroring parse-minimal-type-object
    (%check :lto-parse-malformed
            (null (dds.types:parse-legacy-type-object (subseq inflated 0 30)))
            "input that does not tokenize cleanly returns NIL")
    ;; a tokenizable buffer with no struct-definition node -> :unsupported (fail-open)
    (let ((bare (make-array 4 :element-type '(unsigned-byte 8)
                              :initial-contents '(2 #x7F 0 0))))
      (%check :lto-parse-unsupported
              (eq (dds.types:parse-legacy-type-object bare) :unsupported)
              "a tokenizable tree with no struct-definition node returns :unsupported")))
  t)

;;; Legacy-TypeObject primitive member-kind decode (Task 2.2). Each fixture is a locked live
;;; Connext 7.3.1 C_ShapeP_<prim> capture (interop/connext/typeobject-corpus, 2026-06-11): C_Shape
;;; with member `x` retyped to one primitive. The differential localized the primitive kind to the
;;; member node's VALUE-START+8 (u16); *lto-primitive-kind-keyword* maps RTI's OWN kind octet to a
;;; primitive-type-identifier (RTI's enum differs from XTypes TK_*: boolean 1, octet 2, short 3,
;;; ushort 4, long 5, ulong 6, longlong 7, ulonglong 8, float 9, double 0x0A, char 0x0C —
;;; docs/provenance.md 2026-06-11). Each test parses the variant and asserts member x carries a TI
;;; of the expected +tk-*+ kind, while y/shapesize (still long) stay TK_INT32 and color (the
;;; unbounded @key string) decodes to a STRING8 bound 255 (Task 2.3).

(defun* %lto-prim-fixtures ()
    (function () list)
  "Locked C_ShapeP_<prim> captures: (prim-keyword expected-tk . raw-LB-octet-list). Member x is
   retyped to PRIM-KEYWORD; EXPECTED-TK is the +tk-*+ kind octet x's decoded TI must carry. Test
   fixture (live Connext 7.3.1, interop/connext/typeobject-corpus, 2026-06-11)."
  (list
   (list* :short dds.types:+tk-int16+
          '(1 0 0 0 32 2 0 0 225 0 0 0 120 218 99 172 231 96 0 129 47 140 12 12 76 96 22 11 131 24 144 100 4 138 115 2 105 31 70 8 27 4 84 64 226 96 89 6 134 80 230 29 243 38 70 204 223 192 15 100 59 199 7 103 36 22 164 6 196 23 103 228 23 149 64 212 51 130 77 130 0 16 63 5 141 159 10 164 223 64 197 80 205 135 0 97 40 93 113 213 39 205 146 105 75 37 27 144 157 156 159 147 95 196 128 105 62 83 61 194 12 17 152 29 64 204 12 132 32 63 85 16 169 7 164 150 21 8 65 116 37 1 61 50 80 49 102 168 30 46 32 93 12 10 133 226 204 170 84 28 122 97 24 36 42 12 85 3 50 173 4 41 12 116 192 238 16 70 241 187 40 200 236 146 162 204 188 244 120 35 83 211 248 228 140 196 162 196 228 146 212 34 6 6 252 97 205 3 132 169 80 25 144 248 9 168 248 127 36 247 192 244 11 0 177 24 212 12 88 220 130 228 1 96 157 57 176 0 0 0))
   (list* :ushort dds.types:+tk-uint16+
          '(1 0 0 0 32 2 0 0 227 0 0 0 120 218 99 172 231 96 0 129 47 140 12 12 76 96 22 11 131 24 144 100 4 138 115 2 105 31 70 8 27 4 84 64 226 96 89 6 134 23 93 225 79 55 181 136 206 18 0 178 157 227 131 51 18 11 82 3 226 75 139 51 242 139 74 192 234 25 193 38 65 0 136 159 130 198 79 5 210 111 160 98 168 230 67 128 48 148 174 184 234 147 102 201 180 165 146 13 200 78 206 207 201 47 130 170 71 54 159 169 30 97 134 8 204 14 176 60 11 216 79 21 68 234 1 169 101 5 66 16 93 73 64 143 12 84 140 25 170 135 11 72 23 131 66 161 56 179 42 21 135 94 24 6 137 10 67 213 128 76 43 65 10 3 29 176 59 132 81 252 46 10 50 187 164 40 51 47 61 222 200 212 52 62 57 35 177 40 49 185 36 181 136 1 139 61 200 97 205 3 132 169 80 25 144 248 9 168 248 127 36 247 192 244 131 226 81 12 106 6 44 110 65 242 0 141 252 59 130 0))
   (list* :ulong dds.types:+tk-uint32+
          '(1 0 0 0 32 2 0 0 225 0 0 0 120 218 99 172 231 96 0 129 47 140 12 12 76 96 22 11 131 24 144 100 4 138 115 2 105 31 70 8 27 4 84 64 226 96 89 6 134 216 9 190 111 154 10 220 31 240 3 217 206 241 193 25 137 5 169 1 241 165 57 249 121 233 16 245 140 96 147 32 0 196 79 65 227 167 2 233 55 80 49 84 243 33 64 24 74 87 92 245 73 179 100 218 82 201 6 100 39 231 231 228 23 49 96 154 207 84 143 48 67 4 102 7 16 179 1 33 200 79 21 68 234 1 169 101 5 66 16 93 73 64 143 12 84 140 25 170 135 11 72 23 131 66 161 56 179 42 21 135 94 24 6 137 10 67 213 128 76 43 65 10 3 29 176 59 132 81 252 46 10 50 187 164 40 51 47 61 222 200 212 52 62 57 35 177 40 49 185 36 181 136 129 1 127 88 243 0 97 42 84 6 36 126 2 42 254 31 201 61 48 253 2 64 44 6 53 3 22 183 32 121 0 2 3 58 93 0 0 0))
   (list* :longlong dds.types:+tk-int64+
          '(1 0 0 0 36 2 0 0 227 0 0 0 120 218 99 172 231 96 0 129 31 140 12 12 76 96 22 11 131 24 144 100 4 138 115 2 233 0 70 8 27 4 52 64 226 96 89 6 134 179 105 171 155 100 211 221 157 132 128 108 231 248 224 140 196 130 212 128 248 156 252 188 116 16 134 234 103 4 155 6 1 32 126 10 26 63 21 72 191 129 138 193 236 80 1 219 1 1 194 80 186 226 170 79 154 37 211 150 74 54 32 59 57 63 39 191 8 139 249 76 245 8 51 68 96 118 0 49 59 16 130 252 85 65 164 30 144 90 86 32 4 209 149 4 244 200 64 197 152 161 122 184 128 116 49 40 36 138 51 171 82 113 232 133 97 144 168 48 84 13 200 180 18 164 48 208 1 187 67 24 197 239 162 32 179 75 138 50 243 210 227 141 76 77 227 147 51 18 139 18 147 75 82 139 24 8 132 53 15 16 166 66 101 64 226 39 160 226 255 145 220 3 211 47 0 196 98 80 51 96 241 11 146 7 0 2 111 58 5 0))
   (list* :ulonglong dds.types:+tk-uint64+
          '(1 0 0 0 36 2 0 0 230 0 0 0 120 218 99 172 231 96 0 129 31 140 12 12 76 96 22 11 131 24 144 100 4 138 115 2 233 0 70 8 27 4 52 64 226 96 89 6 134 179 114 231 222 101 157 251 187 83 24 200 118 142 15 206 72 44 72 13 136 47 205 201 207 75 7 97 136 30 70 176 105 16 0 226 167 160 241 83 129 244 27 168 24 204 14 21 176 29 16 32 12 165 43 174 250 164 89 50 109 169 100 3 178 147 243 115 242 139 24 48 205 103 170 71 152 33 2 179 3 136 57 128 16 228 175 10 34 245 128 212 178 2 33 136 174 36 160 71 6 42 198 12 213 195 5 164 139 65 33 81 156 89 149 138 67 47 12 131 68 133 161 106 64 166 149 32 133 129 14 216 29 194 40 126 23 5 153 93 82 148 153 151 30 111 100 106 26 159 156 145 88 148 152 92 146 90 196 192 128 63 172 121 128 48 21 42 3 18 63 1 21 255 143 228 30 152 126 1 32 22 131 154 1 139 95 144 60 0 1 203 62 205 0 0))
   (list* :octet dds.types:+tk-byte+
          '(1 0 0 0 32 2 0 0 223 0 0 0 120 218 99 172 231 96 0 129 47 140 12 12 76 96 22 11 131 24 144 100 4 138 115 2 105 31 70 8 27 4 84 64 226 96 89 6 6 203 130 187 87 174 156 148 243 229 7 178 157 227 131 51 18 11 82 3 226 243 147 75 82 75 32 234 25 193 38 65 0 136 159 130 198 79 5 210 111 160 98 168 230 67 128 48 148 174 184 234 147 102 201 180 165 146 13 200 78 206 207 201 47 98 192 52 159 169 30 97 134 8 204 14 144 56 24 2 205 32 82 15 72 45 43 16 130 232 74 2 122 100 160 98 204 80 61 92 64 186 24 20 10 197 153 85 169 56 244 194 48 72 84 24 170 6 100 90 9 82 24 232 128 221 33 140 226 119 81 144 217 37 69 153 121 233 241 70 166 166 241 201 25 137 69 137 192 144 46 98 96 192 31 214 60 64 152 10 149 1 137 159 128 138 255 71 114 15 76 191 0 16 139 65 205 128 197 45 72 30 0 51 183 58 149 0))
   (list* :float dds.types:+tk-float32+
          '(1 0 0 0 32 2 0 0 225 0 0 0 120 218 99 172 231 96 0 129 47 140 12 12 76 96 22 11 131 24 144 100 4 138 115 2 105 31 70 8 27 4 84 64 226 96 89 6 134 19 94 17 243 214 165 236 243 228 7 178 157 227 131 51 18 11 82 3 226 211 114 242 19 75 32 234 25 193 38 65 0 136 159 130 198 79 5 210 111 160 98 168 230 67 128 48 148 174 184 234 147 102 201 180 165 146 13 200 78 206 207 201 47 98 192 52 159 169 30 97 134 8 204 14 32 230 4 66 144 159 42 136 212 3 82 203 10 132 32 186 146 128 30 25 168 24 51 84 15 23 144 46 6 133 66 113 102 85 42 14 189 48 12 18 21 134 170 1 153 86 130 20 6 58 96 119 8 163 248 93 20 100 118 73 81 102 94 122 188 145 169 105 124 114 70 98 81 98 114 73 106 17 3 3 254 176 230 1 194 84 168 12 72 252 4 84 252 63 146 123 96 250 5 128 88 12 106 6 44 110 65 242 0 183 126 58 24 0 0 0))
   (list* :double dds.types:+tk-float64+
          '(1 0 0 0 32 2 0 0 229 0 0 0 120 218 99 172 231 96 0 129 47 140 12 12 76 96 22 11 131 24 144 100 4 138 115 2 105 31 70 8 27 4 84 64 226 96 89 6 134 173 55 95 191 178 44 243 253 32 0 100 59 199 7 103 36 22 164 6 196 167 228 151 38 229 164 130 213 51 130 77 130 0 16 63 5 141 159 10 164 223 64 197 80 205 135 0 97 40 93 113 213 39 205 146 105 75 37 27 144 157 156 159 147 95 4 85 143 108 62 83 61 194 12 17 152 29 64 204 5 132 32 63 85 16 169 7 164 150 21 8 65 116 37 1 61 50 80 49 102 168 30 46 32 93 12 10 133 226 204 170 84 28 122 97 24 36 42 12 85 3 50 173 4 41 12 116 192 238 16 70 241 187 40 200 236 146 162 204 188 244 120 35 83 211 248 228 140 196 162 196 228 146 212 34 6 44 246 32 135 53 15 16 166 66 101 64 226 39 160 226 255 145 220 3 211 15 138 71 49 168 25 176 184 5 201 3 0 186 41 60 220 0 0 0))
   (list* :boolean dds.types:+tk-boolean+
          '(1 0 0 0 36 2 0 0 227 0 0 0 120 218 99 172 231 96 0 129 31 140 12 12 76 96 22 11 131 24 144 100 4 138 115 2 233 0 70 8 27 4 52 64 226 96 89 6 6 62 246 35 41 249 154 250 51 4 129 108 231 248 224 140 196 130 212 128 248 164 252 252 156 212 196 60 6 168 126 70 176 105 16 0 226 167 160 241 83 129 244 27 168 24 204 14 21 176 29 16 32 12 165 43 174 250 164 89 50 109 169 100 3 178 147 243 115 242 139 176 152 207 84 143 48 67 4 102 7 24 51 130 253 85 65 164 30 144 90 86 32 4 209 149 4 244 200 64 197 152 161 122 184 128 116 49 40 36 138 51 171 82 113 232 133 97 144 168 48 84 13 200 180 18 164 48 208 1 187 67 24 197 239 162 32 179 75 138 50 243 210 227 141 76 77 227 147 51 18 139 18 147 75 82 139 8 133 53 15 16 166 66 101 64 226 39 160 226 255 145 220 3 211 47 0 196 98 80 51 96 241 11 146 7 0 106 186 55 214 0))
   (list* :char dds.types:+tk-char8+
          '(1 0 0 0 32 2 0 0 219 0 0 0 120 218 99 172 231 96 0 129 47 140 12 12 76 96 22 11 131 24 144 100 4 138 115 2 105 31 70 8 27 4 84 64 226 96 89 6 134 201 231 174 29 186 31 61 89 130 15 200 118 142 15 206 72 44 72 13 136 79 206 72 44 130 234 101 4 155 4 1 32 126 10 26 63 21 72 191 129 138 161 154 15 1 194 80 186 226 170 79 154 37 211 150 74 54 32 59 57 63 39 31 155 249 76 245 8 51 68 96 118 0 49 15 16 130 252 84 65 164 30 144 90 86 32 4 209 149 4 244 200 64 197 152 161 122 184 128 116 49 40 20 138 51 171 82 113 232 133 97 144 168 48 84 13 200 180 18 164 48 208 1 187 67 24 197 239 162 32 179 75 138 50 243 210 227 141 76 77 193 161 156 152 92 146 90 196 64 32 172 65 254 79 133 202 128 196 79 64 197 255 35 185 7 166 95 0 136 197 160 102 192 226 22 36 15 0 84 228 59 31 0))))

(defun* run-lto-parse-primitives-test ()
    (function () t)
  "Test: parse-legacy-type-object decodes PRIMITIVE member type-identifiers (Task 2.2). For each
   locked C_ShapeP_<prim> capture, member x's decoded TI carries the expected +tk-*+ kind; the
   still-long y/shapesize stay TK_INT32; the @key string member color decodes to a STRING8 bound
   255 (Task 2.3). Pinned to the live Connext 7.3.1 corpus (docs/provenance.md 2026-06-11)."
  (dolist (fx (%lto-prim-fixtures))
    (destructuring-bind (prim expected-tk . octlist) fx
      (let* ((lb (coerce octlist '(simple-array (unsigned-byte 8) (*))))
             (inflated (dds.types:inflate-type-object-lb lb))
             (parsed (and inflated (dds.types:parse-legacy-type-object inflated))))
        (%check (intern (format nil "LTO-PRIM-~A-PARSE" prim) :keyword)
                (dds.types:minimal-struct-type-p parsed)
                (format nil "C_ShapeP_~(~a~) parses to a minimal-struct-type" prim))
        (when (dds.types:minimal-struct-type-p parsed)
          (let* ((ms (dds.types:minimal-struct-type-members parsed))
                 ;; declaration order is color(0) x(1) y(2) shapesize(3); x is the retyped member
                 (xm (find "x" ms :key #'dds.types:minimal-struct-member-name :test #'string=))
                 (xti (and xm (dds.types:minimal-struct-member-type-identifier xm)))
                 (color (find "color" ms :key #'dds.types:minimal-struct-member-name :test #'string=)))
            (%check (intern (format nil "LTO-PRIM-~A-KIND" prim) :keyword)
                    (and xti (= (dds.types:type-identifier-kind xti) expected-tk))
                    (format nil "C_ShapeP_~(~a~) member x decodes to the expected primitive kind" prim))
            ;; color is the @key unbounded string -> STRING8 bound 255 (Task 2.3); y/shapesize stay long
            (let ((cti (and color (dds.types:minimal-struct-member-type-identifier color))))
              (%check (intern (format nil "LTO-PRIM-~A-OTHERS" prim) :keyword)
                      (and cti
                           (= (dds.types:type-identifier-kind cti) dds.types:+ti-string8-small+)
                           (= (dds.types:type-identifier-bound cti) 255)
                           (every (lambda (nm)
                                    (let* ((m (find nm ms :key #'dds.types:minimal-struct-member-name
                                                    :test #'string=))
                                           (ti (and m (dds.types:minimal-struct-member-type-identifier m))))
                                      (and ti (= (dds.types:type-identifier-kind ti)
                                                 dds.types:+tk-int32+))))
                                  '("y" "shapesize")))
                      (format nil "C_ShapeP_~(~a~) color is STRING8/255 and y/shapesize TK_INT32" prim))))))))
  t)

;;; Legacy-TypeObject string-bound + @key-flag decode (Task 2.3). Locked live Connext 7.3.1
;;; captures (interop/connext/typeobject-corpus, 2026-06-11). The base C_Shape's `color` is an
;;; unbounded `string` -> RTI default bound 255; C_ShapeS32/S300 bound it (32 / 300); C_ShapeNoKey
;;; drops @key from color and puts it on `x`. The differential (docs/provenance.md 2026-06-11)
;;; localized: the string member node carries kind 0x13 (19) at +8 plus an 8-octet type-hash at
;;; +16 referencing a string-definition node (CODE 8) whose CODE-200 child holds the bound as a
;;; u32; and the member node's +0 word is the @key flag (1 key / 0 non-key). The bound is ALWAYS a
;;; u32 on RTI's wire (32/255/300 all u32) — the small(<=255)/large(>255) split is OUR XTypes model
;;; (string8-type-identifier), so the decoded TI carries +ti-string8-small+ for 255/32 and
;;; +ti-string8-large+ for 300.

(defun* %lto-string-fixtures ()
    (function () list)
  "Locked Task-2.3 captures: (label expected-bound color-key-p . raw-LB-octet-list). Each is a
   C_Shape string-bound / @key differential; EXPECTED-BOUND is color's decoded string bound (0
   never appears — RTI defaults unbounded to 255) and COLOR-KEY-P whether color is @key. Test
   fixture (live Connext 7.3.1, interop/connext/typeobject-corpus, 2026-06-11)."
  (list
   (list* "C_Shape" 255 t
          '(1 0 0 0 24 2 0 0 219 0 0 0 120 218 99 172 231 96 0 129 55 140 12 12 76 96 22 11 131 24 144 100 4 138 115 2 105 23 70 8 27 4 100 64 226 96 89 6 134 106 110 249 25 103 138 117 223 130 100 156 227 131 51 18 11 82 193 234 24 193 38 64 0 136 159 130 198 79 5 217 5 21 131 153 171 2 54 23 2 132 161 116 197 85 159 52 75 166 45 149 108 64 118 114 126 78 126 17 84 61 178 249 76 245 8 51 68 96 118 0 49 43 16 130 252 82 65 164 30 38 36 61 149 4 244 200 64 197 152 161 122 184 128 116 49 200 247 197 153 85 169 56 244 194 48 72 84 24 170 6 100 90 9 82 24 232 128 221 33 140 226 119 81 144 217 37 69 153 121 233 241 70 166 166 241 201 25 137 69 137 201 37 169 69 12 88 236 65 14 107 30 32 76 133 202 128 196 79 64 197 255 35 185 7 166 95 0 136 197 160 102 192 226 20 36 15 0 9 35 54 22 0))
   (list* "C_ShapeS32" 32 t
          '(1 0 0 0 24 2 0 0 218 0 0 0 120 218 99 172 231 96 0 129 55 140 12 12 76 96 22 11 131 24 144 100 4 138 115 2 105 15 70 8 27 4 20 64 226 96 89 6 6 203 126 21 254 71 39 248 46 113 3 217 206 241 193 25 137 5 169 193 198 70 16 181 140 96 83 32 0 196 79 65 227 167 130 236 131 138 193 204 86 1 155 13 1 194 80 58 173 159 107 182 90 91 209 36 54 32 59 57 63 39 191 136 1 211 124 166 122 132 25 34 48 59 128 152 21 8 65 254 169 32 82 15 19 146 158 74 2 122 100 160 98 204 80 61 92 64 186 24 20 2 197 153 85 169 56 244 194 48 72 84 24 170 6 100 90 1 82 24 104 128 221 33 140 226 119 144 251 138 75 138 50 243 210 227 141 141 226 147 51 18 139 18 147 75 82 139 240 134 51 15 16 166 66 101 64 226 39 160 226 10 72 110 129 233 23 0 98 49 168 25 176 56 5 201 3 0 68 88 53 94 0 0))
   (list* "C_ShapeS300" 300 t
          '(1 0 0 0 28 2 0 0 225 0 0 0 120 218 99 172 231 96 0 129 15 140 12 12 76 96 22 11 131 24 144 100 4 138 115 2 105 15 70 8 27 4 20 64 226 96 89 6 134 29 235 166 92 56 58 177 204 129 7 200 118 142 15 206 72 44 72 13 54 54 48 0 171 101 4 155 2 1 32 126 10 26 63 21 72 191 129 138 193 204 86 1 155 13 1 194 80 122 223 242 200 147 7 125 185 254 177 1 217 201 249 57 249 69 80 245 200 230 51 213 35 204 16 129 217 1 196 172 64 8 242 79 5 145 122 152 144 244 84 18 208 35 3 21 99 134 234 225 2 210 197 160 16 40 206 172 74 197 161 23 134 65 162 194 80 53 32 211 74 144 194 64 7 236 14 97 20 191 139 130 204 46 41 202 204 75 143 7 6 111 124 114 70 98 81 98 114 73 106 17 3 22 123 144 195 154 7 8 83 161 50 32 241 19 80 113 29 70 132 91 96 250 5 128 88 12 106 6 44 94 65 242 0 155 187 59 29 0 0 0))
   (list* "C_ShapeNoKey" 255 nil
          '(1 0 0 0 32 2 0 0 219 0 0 0 120 218 99 172 231 96 0 129 47 140 12 12 76 96 22 11 131 24 144 100 4 138 115 2 105 31 70 8 27 4 84 64 226 96 89 6 6 1 61 173 198 25 121 135 94 242 2 217 206 241 193 25 137 5 169 126 249 222 169 149 12 80 189 140 96 147 32 0 196 79 65 227 167 2 233 55 80 49 100 243 97 64 24 74 87 92 245 73 179 100 218 82 201 6 100 39 231 231 228 23 97 49 159 169 30 97 134 8 216 141 16 204 10 132 32 63 85 16 161 7 44 134 164 167 146 128 30 25 168 24 51 84 15 23 144 46 6 133 66 113 102 85 42 14 189 48 12 18 21 134 170 1 153 86 130 20 6 58 96 119 8 163 248 93 20 100 118 73 81 102 94 122 188 145 169 105 124 114 70 98 81 98 114 73 106 17 161 176 230 1 194 84 168 12 72 252 4 84 252 63 146 123 96 250 5 128 88 12 106 6 44 110 65 242 0 6 183 56 33 0))))

(defun* %lto-member-named (parsed name)
    (function (dds.types:minimal-struct-type string) (or null dds.types:minimal-struct-member))
  "The member of PARSED named NAME, or NIL (test fixture)."
  (find name (dds.types:minimal-struct-type-members parsed)
        :key #'dds.types:minimal-struct-member-name :test #'string=))

(defun* run-lto-parse-strings-keys-test ()
    (function () t)
  "Test: parse-legacy-type-object decodes STRING member bounds (bounded + unbounded) and the
   @key flag (Task 2.3). For each locked C_Shape string/@key differential: color's TI is a
   STRING8 with the expected bound (255 default / 32 / 300, large form > 255), and the @key flag
   tracks the wire (color @key in C_Shape{,S32,S300}; not in C_ShapeNoKey, where x is @key).
   Pinned to the live Connext 7.3.1 corpus (docs/provenance.md 2026-06-11)."
  (dolist (fx (%lto-string-fixtures))
    (destructuring-bind (label bound color-key-p . octlist) fx
      (let* ((lb (coerce octlist '(simple-array (unsigned-byte 8) (*))))
             (inflated (dds.types:inflate-type-object-lb lb))
             (parsed (and inflated (dds.types:parse-legacy-type-object inflated))))
        (%check (intern (format nil "LTO-STR-~A-PARSE" (string-upcase label)) :keyword)
                (dds.types:minimal-struct-type-p parsed)
                (format nil "~a parses to a minimal-struct-type" label))
        (when (dds.types:minimal-struct-type-p parsed)
          (let* ((color (%lto-member-named parsed "color"))
                 (cti (and color (dds.types:minimal-struct-member-type-identifier color)))
                 (x (%lto-member-named parsed "x")))
            (%check (intern (format nil "LTO-STR-~A-BOUND" (string-upcase label)) :keyword)
                    (and cti
                         (= (dds.types:type-identifier-kind cti)
                            (if (> bound 255) dds.types:+ti-string8-large+
                                dds.types:+ti-string8-small+))
                         (= (dds.types:type-identifier-bound cti) bound))
                    (format nil "~a color is a STRING8 TI with bound ~d (~:[small~;large~] form)"
                            label bound (> bound 255)))
            (%check (intern (format nil "LTO-STR-~A-COLORKEY" (string-upcase label)) :keyword)
                    (and color (eq (and (dds.types:minimal-struct-member-key-p color) t) color-key-p))
                    (format nil "~a color key-p = ~a" label color-key-p))
            (%check (intern (format nil "LTO-STR-~A-XKEY" (string-upcase label)) :keyword)
                    (and x (eq (and (dds.types:minimal-struct-member-key-p x) t) (not color-key-p)))
                    (format nil "~a x key-p = ~a (the key moves to x iff color is not @key)"
                            label (not color-key-p))))))))
  t)

;;; Legacy-TypeObject struct EXTENSIBILITY decode (Task 2.4). Locked live Connext 7.3.1 captures
;;; (interop/connext/typeobject-corpus, 2026-06-11): the base C_Shape is @final; C_ShapeAppend is
;;; @appendable; C_ShapeMutable is @mutable (members otherwise identical). The differential
;;; (docs/provenance.md 2026-06-11) localized the extensibility flag to the struct-definition node's
;;; FIRST CODE-0 child's VALUE-START+0 u16 — RTI's OWN enum (appendable 0, final 1, mutable 2), NOT
;;; the XTypes IS_FINAL/APPENDABLE/MUTABLE struct-flag bits (which coincide only for :final). The
;;; member encoding was byte-identical across all three (no non-final member-parse gap for these
;;; scalar/string members).

(defun* %lto-extensibility-fixtures ()
    (function () list)
  "Locked Task-2.4 captures: (label expected-extensibility . raw-LB-octet-list). Each is a base
   C_Shape with only the struct extensibility changed; EXPECTED-EXTENSIBILITY is the keyword the
   decoded minimal-struct-type must carry. Test fixture (live Connext 7.3.1,
   interop/connext/typeobject-corpus, 2026-06-11, docs/provenance.md)."
  (list
   (list* "C_Shape" :final
          '(1 0 0 0 24 2 0 0 219 0 0 0 120 218 99 172 231 96 0 129 55 140 12 12 76 96 22 11 131 24 144 100 4 138 115 2 105 23 70 8 27 4 100 64 226 96 89 6 134 106 110 249 25 103 138 117 223 130 100 156 227 131 51 18 11 82 193 234 24 193 38 64 0 136 159 130 198 79 5 217 5 21 131 153 171 2 54 23 2 132 161 116 197 85 159 52 75 166 45 149 108 64 118 114 126 78 126 17 84 61 178 249 76 245 8 51 68 96 118 0 49 43 16 130 252 82 65 164 30 38 36 61 149 4 244 200 64 197 152 161 122 184 128 116 49 200 247 197 153 85 169 56 244 194 48 72 84 24 170 6 100 90 9 82 24 232 128 221 33 140 226 119 81 144 217 37 69 153 121 233 241 70 166 166 241 201 25 137 69 137 201 37 169 69 12 88 236 65 14 107 30 32 76 133 202 128 196 79 64 197 255 35 185 7 166 95 0 136 197 160 102 192 226 20 36 15 0 9 35 54 22 0))
   (list* "C_ShapeAppend" :appendable
          '(1 0 0 0 32 2 0 0 217 0 0 0 120 218 99 172 231 96 0 129 47 140 12 12 76 96 22 11 131 24 144 100 4 138 115 2 105 31 70 8 27 4 84 192 164 24 152 60 175 173 37 116 192 91 188 129 15 200 118 142 15 206 72 44 72 117 44 40 72 205 75 129 234 101 4 155 4 1 32 126 10 26 63 21 72 191 129 138 33 155 207 8 85 35 12 165 43 174 250 164 89 50 109 169 100 3 178 147 243 115 242 139 176 152 207 84 143 48 67 4 102 7 16 179 2 33 200 79 21 68 234 97 66 210 83 73 64 143 12 84 140 25 170 135 11 72 23 131 66 161 56 179 42 21 135 94 24 6 137 10 67 213 128 76 43 65 10 3 29 176 59 132 81 252 46 10 50 187 164 40 51 47 61 222 200 212 52 62 57 35 177 40 49 185 36 181 136 129 64 88 243 0 97 42 84 6 36 126 2 42 254 31 201 61 48 253 2 240 152 69 196 45 72 30 0 107 59 55 15 0 0 0))
   (list* "C_ShapeMutable" :mutable
          '(1 0 0 0 32 2 0 0 224 0 0 0 120 218 99 172 231 96 0 129 47 140 12 12 76 96 22 11 131 24 144 100 4 138 115 2 105 31 70 8 27 4 84 24 64 106 196 192 236 175 169 254 57 37 233 251 207 240 3 217 206 241 193 25 137 5 169 190 165 37 137 73 57 169 16 245 140 96 147 32 0 196 79 65 227 3 149 49 188 129 138 33 155 207 8 85 35 12 165 43 174 250 164 89 50 109 169 100 3 178 147 243 115 242 139 24 48 205 103 170 71 152 33 2 179 3 136 89 129 16 228 167 10 34 245 48 33 233 169 36 160 71 6 42 198 12 213 195 5 164 139 65 161 80 156 89 149 138 67 47 12 131 68 133 161 106 64 166 149 32 133 129 14 216 29 194 40 126 23 5 153 93 82 148 153 151 30 111 100 106 26 159 156 145 88 148 152 92 146 90 196 192 128 63 172 121 128 48 21 42 3 18 63 1 21 255 143 228 30 152 126 1 32 22 131 154 1 139 91 144 60 0 100 50 58 202))))

(defun* run-lto-parse-extensibility-test ()
    (function () t)
  "Test: parse-legacy-type-object decodes the struct EXTENSIBILITY (Task 2.4). For each locked
   C_Shape{,Append,Mutable} capture, the decoded minimal-struct-type's extensibility is
   :final/:appendable/:mutable respectively. Pinned to the live Connext 7.3.1 corpus
   (docs/provenance.md 2026-06-11)."
  (dolist (fx (%lto-extensibility-fixtures))
    (destructuring-bind (label expected . octlist) fx
      (let* ((lb (coerce octlist '(simple-array (unsigned-byte 8) (*))))
             (inflated (dds.types:inflate-type-object-lb lb))
             (parsed (and inflated (dds.types:parse-legacy-type-object inflated))))
        (%check (intern (format nil "LTO-EXT-~A-PARSE" (string-upcase label)) :keyword)
                (dds.types:minimal-struct-type-p parsed)
                (format nil "~a parses to a minimal-struct-type" label))
        (when (dds.types:minimal-struct-type-p parsed)
          (%check (intern (format nil "LTO-EXT-~A" (string-upcase label)) :keyword)
                  (eq (dds.types:minimal-struct-type-extensibility parsed) expected)
                  (format nil "~a decodes extensibility ~a" label expected))))))
  t)

;;; Legacy-TypeObject assignability proof (Task 2.4). Parses the live C_Shape legacy TypeObject and
;;; drives it through the REAL struct-assignable-from gate (assignability.lisp) against a locally-
;;; built minimal-struct-type for the SAME shape — proving the parsed wire model feeds the type-
;;; compatibility decision. A deliberately-incompatible local (x retyped i32->f64) must fail.

(defun* %lto-local-c-shape (&key (x-kind :i32) (drop-shapesize nil))
    (function (&key (:x-kind symbol) (:drop-shapesize t)) dds.types:minimal-struct-type)
  "A locally-built minimal-struct-type mirroring C_Shape: @final, @key string<255> color (id 0),
   long x/y/shapesize (ids 1/2/3). X-KIND retypes member x (:i32 = matching, :f64 = incompatible);
   DROP-SHAPESIZE omits shapesize (an incompatible member-set). Test fixture (mirrors xtypes-test)."
  (dds.types:make-minimal-struct-type
   :name "C_Shape" :extensibility :final
   :members (append
             (list (dds.types:make-struct-member
                    "color" 0 (dds.types:string8-type-identifier 255) :key-p t)
                   (dds.types:make-struct-member
                    "x" 1 (dds.types:primitive-type-identifier x-kind))
                   (dds.types:make-struct-member
                    "y" 2 (dds.types:primitive-type-identifier :i32)))
             (unless drop-shapesize
               (list (dds.types:make-struct-member
                      "shapesize" 3 (dds.types:primitive-type-identifier :i32)))))))

(defun* run-lto-assignability-test ()
    (function () t)
  "Test: the PARSED live C_Shape legacy TypeObject drives the real struct-assignable-from gate
   (Task 2.4, FR-TYPE-4). A local minimal-struct-type for the same shape is assignable from the
   parsed model (and vice versa); an incompatible local (x retyped i32->f64, or shapesize dropped)
   is NOT. Pinned to the live Connext 7.3.1 corpus (docs/provenance.md 2026-06-11)."
  (let* ((lb (%connext-c-shape-lb))
         (inflated (dds.types:inflate-type-object-lb lb))
         (parsed (dds.types:parse-legacy-type-object inflated))
         (opts (dds.types:default-assignability-options)))
    (%check :lto-asgn-parse (dds.types:minimal-struct-type-p parsed)
            "the live C_Shape legacy TypeObject parses to a minimal-struct-type")
    (when (dds.types:minimal-struct-type-p parsed)
      (let ((local-ok (%lto-local-c-shape))
            (local-bad (%lto-local-c-shape :x-kind :f64))
            (local-drop (%lto-local-c-shape :drop-shapesize t)))
        (%check :lto-asgn-compatible
                (dds.types:struct-assignable-from local-ok parsed opts)
                "a matching local C_Shape is assignable from the parsed legacy model (compatible -> T)")
        (%check :lto-asgn-compatible-rev
                (dds.types:struct-assignable-from parsed local-ok opts)
                "the parsed legacy model is assignable from the matching local C_Shape (both directions)")
        (%check :lto-asgn-incompatible-type
                (not (dds.types:struct-assignable-from local-bad parsed opts))
                "an incompatible local (x retyped long->double) is NOT assignable (incompatible -> NIL)")
        (%check :lto-asgn-incompatible-members
                (not (dds.types:struct-assignable-from local-drop parsed opts))
                "an incompatible local (shapesize dropped) is NOT assignable under :final (incompatible -> NIL)"))))
  t)
