;;;; Structural TLV tokenizer for RTI Connext's PROPRIETARY legacy TypeObject — the inflated
;;;; PID_TYPE_OBJECT_LB (0x8021) payload (ADR 0009). It walks the byte structure WITHOUT
;;;; interpreting type semantics: it recovers the node tree, each node's [value-start,value-end)
;;;; extent, and the length-prefixed names embedded in node values. This is the security
;;;; boundary of a reverse-engineering feature; every wire read is bounds-checked against the
;;;; buffer extent FIRST (NFR-SEC-POSTURE), and depth/element/string resource guards bound the
;;;; walk. Clean-room: the framing below is derived ONLY from captured bytes + differential
;;;; experiments (no RTI source, no GPL dissector); see docs/provenance.md.
;;;;
;;;; FRAMING (little-endian; derived from the 536-octet inflated C_Shape TypeObject and the
;;;; C_Shape vs C_Shape2 member-rename differential, docs/provenance.md 2026-06-11):
;;;;   The payload is a SEQUENCE of top-level nodes consumed back to back to the buffer end.
;;;;   A node is one of two forms, distinguished by its leading 4-octet TAG:
;;;;     LONG  tag = 01 7F 08 00 : tag(4) + code:u32(4) + length:u32(4) + value[length]
;;;;     SHORT tag = 02 7F 00 00 : tag(4) only — a leaf/terminator marker, empty value
;;;;   A LONG node's VALUE is [tag+12, tag+12+length): a kind-specific fixed-field header
;;;;   (counts/ids/8-octet type-hashes — NOT interpreted here) interleaved with nested LONG/
;;;;   SHORT child nodes. Tokenizing the value: scan word-aligned; a word equal to either TAG
;;;;   begins a nested child (recurse); otherwise the word is opaque value data. A length-
;;;;   prefixed string in the value — len:u32 + len octets (the trailing NUL counted) padded
;;;;   with NULs to the next 4-octet boundary — is decoded as the node's NAME.
;;;; EVIDENCE (offsets into the 536-octet inflated C_Shape capture, docs/provenance.md): outer
;;;; LONG @0x000 (code=0, len=492) spans value [0x0C,0x1F8); type-name length-field @0x040
;;;; (len=8, "C_Shape\0"); color length-field @0x0A0 (len=6). The C_Shape→C_Shape2 rename
;;;; (color→colour, len 06→07) cascaded +4 through every enclosing length field (outer 492→496,
;;;; etc.) — confirming length is the real content extent and strings are len-prefixed + NUL-
;;;; padded to 4. (ShapeType 540-octet sibling capture: outer len=496, value [0x0C,0x1FC);
;;;; type-name @0x3C len=10 "ShapeType\0"; member "color" @0x9C len=6.)
;;;;
;;;; This is NOT pure generic TLV: LONG values carry fixed header fields ahead of any nested
;;;; node, so the tokenizer anchors on the two known TAG words to separate structure from the
;;;; opaque (un-interpreted) header/hash bytes. That minimal anchoring is the only structural
;;;; assumption; no per-type-kind semantics are decoded.

(in-package #:dds.types)

(defparameter *lto-max-depth* 32
  "Max nesting depth for the legacy-TypeObject tokenizer (NFR-SEC-POSTURE): a value whose
   nested nodes recurse deeper is rejected (the whole tokenize returns NIL).")

(defparameter *lto-max-elements* 4096
  "Max total nodes the legacy-TypeObject tokenizer will produce before rejecting the input
   (NFR-SEC-POSTURE): a resource-exhaustion guard so a small inflated buffer cannot expand
   into an unbounded node tree.")

(defparameter *lto-max-string-bytes* 8192
  "Max length-prefixed string (in octets, the declared len) the tokenizer will accept as a
   node NAME (NFR-SEC-POSTURE); a larger declared length is treated as opaque data, not a name.")

(defconstant +lto-tag-long+ #x00087F01
  "The LONG-node 4-octet TAG (little-endian octets 01 7F 08 00) opening a code+length+value
   node in RTI's legacy TypeObject. Reverse-engineered from the Connext wire (clean-room,
   docs/provenance.md), NOT an OMG-spec constant.")

(defconstant +lto-tag-short+ #x00007F02
  "The SHORT-node 4-octet TAG (little-endian octets 02 7F 00 00): a bare leaf/terminator
   marker with no length or value in RTI's legacy TypeObject. Reverse-engineered from the
   Connext wire (clean-room, docs/provenance.md), NOT an OMG-spec constant.")

(defstruct* (lto-node (:constructor %make-lto-node))
  "One node of the parsed legacy-TypeObject TLV tree: its 4-octet TAG, the node's CODE word
   (the u32 after a LONG tag; 0 for a SHORT node), the absolute byte range [VALUE-START,
   VALUE-END) of its value, child nodes, and the decoded length-prefixed NAME when the node's
   value carries one (else NIL). Structure only, no type semantics. The synthetic ROOT
   returned by TOKENIZE-LEGACY-TYPE-OBJECT has TAG 0, VALUE-START 0, VALUE-END = the buffer
   length, and the top-level nodes as CHILDREN.
   TAG discriminates node kind: CODE is meaningful only for a LONG node (= +LTO-TAG-LONG+);
   it is 0 and unused for a SHORT node (= +LTO-TAG-SHORT+). Do not read CODE when TAG /=
   +LTO-TAG-LONG+.
   Stage-2 data-access contract: each LONG node's code-specific opaque fields (8-octet
   member/type hashes, member ids, string bounds, etc.) live in the raw octet buffer within
   [VALUE-START, VALUE-END) and are NOT decoded by the tokenizer. The Stage-2 interpreter
   therefore consumes BOTH the node tree AND the original octet buffer, reading those fields
   by offset once their per-code layout is known from differential analysis."
  (tag 0 :type (unsigned-byte 32))
  (code 0 :type (unsigned-byte 32))
  (value-start 0 :type (integer 0 #.array-dimension-limit))
  (value-end 0 :type (integer 0 #.array-dimension-limit))
  (children '() :type list)
  (name nil :type (or null string)))

(defun* %lto-u32 (octets pos end)
    (function ((simple-array (unsigned-byte 8) (*)) (integer 0 #.array-dimension-limit) (integer 0 #.array-dimension-limit))
              (or null (unsigned-byte 32)))
  "The little-endian u32 at OCTETS[POS..POS+4), or NIL if [POS,POS+4) is not wholly within
   [0,END) — the mandatory bounds-check before trusting any 4-octet wire field (NFR-SEC-POSTURE)."
  (when (and (<= 0 pos) (<= (+ pos 4) end))
    (logior (aref octets pos)
            (ash (aref octets (+ pos 1)) 8)
            (ash (aref octets (+ pos 2)) 16)
            (ash (aref octets (+ pos 3)) 24))))

(defun* %lto-u16 (octets pos end)
    (function ((simple-array (unsigned-byte 8) (*)) (integer 0 #.array-dimension-limit) (integer 0 #.array-dimension-limit))
              (or null (unsigned-byte 16)))
  "The little-endian u16 at OCTETS[POS..POS+2), or NIL if [POS,POS+2) is not wholly within
   [0,END) — bounds-checked before trusting the 2-octet field (NFR-SEC-POSTURE)."
  (when (and (<= 0 pos) (<= (+ pos 2) end))
    (logior (aref octets pos) (ash (aref octets (+ pos 1)) 8))))

(defun* %lto-read-name (octets pos end)
    (function ((simple-array (unsigned-byte 8) (*)) (integer 0 #.array-dimension-limit) (integer 0 #.array-dimension-limit))
              (values (or null string) (integer 0 #.array-dimension-limit)))
  "Try to decode a length-prefixed NAME at OCTETS[POS..): len:u32 + len octets (trailing NUL
   counted) NUL-padded to the next 4-octet boundary. Returns (values NAME NEXT-POS) on a valid
   name (NEXT-POS past the padded string) or (values NIL POS) otherwise. A name is valid only
   when 2 <= len <= *LTO-MAX-STRING-BYTES* (a real name is >= 1 printable octet + a NUL; len=1
   is a bare NUL, a degenerate non-name), the padded extent fits within END, the final declared
   octet is NUL, and every preceding octet is printable ASCII. Bounds-checked FIRST."
  (let ((len (%lto-u32 octets pos end)))
    (if (or (null len) (< len 2) (> len *lto-max-string-bytes*))
        (values nil pos)
        (let* ((sstart (+ pos 4))
               (send (+ sstart len))
               (padded (+ sstart (* 4 (ceiling len 4)))))
          (if (or (> send end) (> padded end))
              (values nil pos)
              (let ((last (1- send)))
                (if (/= (aref octets last) 0)
                    (values nil pos)
                    (let ((ok t))
                      (loop for i from sstart below last
                            unless (<= 32 (aref octets i) 126) do (setf ok nil) (return))
                      (if (not ok)
                          (values nil pos)
                          (values (map 'string #'code-char (subseq octets sstart last))
                                  padded))))))))))

(defun* %lto-read-node (octets pos end depth count)
    (function ((simple-array (unsigned-byte 8) (*)) (integer 0 #.array-dimension-limit) (integer 0 #.array-dimension-limit) (integer 0 #.array-dimension-limit) cons)
              (values (or null lto-node) (integer 0 #.array-dimension-limit)))
  "Read ONE node at OCTETS[POS..) within the extent END, recursively. Returns (values NODE
   NEXT-POS) on success, or (values NIL POS) on any framing/bounds/resource violation (the
   caller treats NIL as failure). DEPTH bounds nesting against *LTO-MAX-DEPTH*; COUNT is a
   mutable (CAR-incremented) cons bounding total nodes against *LTO-MAX-ELEMENTS*. Every TAG,
   CODE, LENGTH and name read is bounds-checked against END FIRST (NFR-SEC-POSTURE)."
  (when (> depth *lto-max-depth*)
    (return-from %lto-read-node (values nil pos)))
  (let ((tag (%lto-u32 octets pos end)))
    (when (null tag)
      (return-from %lto-read-node (values nil pos)))
    (incf (car count))
    (when (> (car count) *lto-max-elements*)
      (return-from %lto-read-node (values nil pos)))
    (cond
      ((= tag +lto-tag-short+)
       (values (%make-lto-node :tag tag :code 0 :value-start (+ pos 4) :value-end (+ pos 4))
               (+ pos 4)))
      ((= tag +lto-tag-long+)
       (let ((code (%lto-u32 octets (+ pos 4) end))
             (len (%lto-u32 octets (+ pos 8) end)))
         (when (or (null code) (null len))
           (return-from %lto-read-node (values nil pos)))
         (let ((vstart (+ pos 12))
               (vend (+ pos 12 len)))
           (when (> vend end)
             (return-from %lto-read-node (values nil pos)))
           (let ((children '())
                 (name nil)
                 (cur (+ pos 12)))
             ;; cur advances >= 4 per iteration (4-aligned) within [vstart,vend) so the loop terminates.
             (loop while (<= (+ cur 4) vend) do
               (let ((w (%lto-u32 octets cur vend)))
                 (when (null w)
                   (return-from %lto-read-node (values nil pos)))
                 (cond
                   ((or (= w +lto-tag-long+) (= w +lto-tag-short+))
                    (multiple-value-bind (child next) (%lto-read-node octets cur vend (1+ depth) count)
                      (when (null child)
                        (return-from %lto-read-node (values nil pos)))
                      (push child children)
                      (setf cur next)))
                   (t
                    (multiple-value-bind (str next) (%lto-read-name octets cur vend)
                      (cond
                        ((and str (null name))
                         (setf name str cur next))
                        (str (setf cur next))
                        (t (incf cur 4))))))))
             (values (%make-lto-node :tag tag :code code :value-start vstart :value-end vend
                                     :children (nreverse children) :name name)
                     vend)))))
      (t (values nil pos)))))

(defun* tokenize-legacy-type-object (octets)
    (function ((simple-array (unsigned-byte 8) (*))) (or null lto-node))
  "Structurally tokenize an INFLATED RTI legacy TypeObject (the inflated PID_TYPE_OBJECT_LB /
   0x8021 payload, ADR 0009) into an LTO-NODE tree, or NIL if the buffer does not tokenize
   cleanly to its end. Returns a synthetic ROOT (TAG 0, VALUE-START 0, VALUE-END = (length
   OCTETS)) whose CHILDREN are the top-level nodes consumed back to back from offset 0. NIL is
   returned on any bounds/framing violation, on exceeding the *LTO-MAX-DEPTH* / *LTO-MAX-ELEMENTS*
   resource guards, or when the walk does not consume EXACTLY to the buffer end (trailing-garbage
   guard) — structure only, no type semantics are interpreted. Pair OCTETS with
   INFLATE-TYPE-OBJECT-LB to go from the raw vendor parameter to this tree."
  (let ((end (length octets))
        (count (cons 0 nil))
        (children '())
        (pos 0))
    (when (zerop end)
      (return-from tokenize-legacy-type-object nil))
    (loop while (< pos end) do
      (multiple-value-bind (node next) (%lto-read-node octets pos end 0 count)
        (when (or (null node) (<= next pos))
          (return-from tokenize-legacy-type-object nil))
        (push node children)
        (setf pos next)))
    (unless (= pos end)
      (return-from tokenize-legacy-type-object nil))
    (%make-lto-node :tag 0 :code 0 :value-start 0 :value-end end
                    :children (nreverse children) :name nil)))

;;;; Semantic interpreter, stage 2 part 1 (legacy-TypeObject Task 2.1): fold the tokenized
;;;; legacy-TypeObject tree into a MINIMAL-STRUCT-TYPE skeleton — the type name, member
;;;; names, and member ids — MIRRORING parse-minimal-type-object's contract (typeobject-cdr.lisp):
;;;; minimal-struct-type on success, :UNSUPPORTED on a recognized-but-unmodeled shape, NIL on
;;;; malformed/untokenizable input. Member TYPES are NOT decoded here (the member type-identifier
;;;; is left NIL; that is Task 2.2/2.3); extensibility is decoded from the struct-node flag
;;;; (Task 2.4: @final/@appendable/@mutable). Clean-room: the node mapping below is derived
;;;; ONLY from captured bytes + the C_Shape / C_Shape3 / C_Shape4 differential experiments
;;;; (docs/provenance.md 2026-06-11), no RTI source / GPL dissector.
;;;; STRUCTURE (offsets cite the 536-octet C_Shape inflate; identical across the C_Shape3/4
;;;; variants): the struct definition is the unique LONG node with CODE +LTO-CODE-STRUCT+ (9);
;;;; its first NAMED child carries the struct type name; its child with CODE +LTO-CODE-MEMBERS+
;;;; (101) is the member-list container whose NAMED CODE-0 children are the members in order.
;;;; Each member node's value carries the 0-based declaration-order member id as the u32 at
;;;; VALUE-START+4 (the +0 word is the @key flag — not interpreted here). The C_Shape4 reorder
;;;; (x first, @key color second) proved the id is POSITIONAL (declaration index, autoid
;;;; SEQUENTIAL), not a stable per-member assignment: color's id moved 0->1 when it moved to
;;;; declaration index 1. The container's first value word is the member count (cross-check only).

(defconstant +lto-code-struct+ 9
  "Legacy-TypeObject node CODE marking the struct-definition node (the one whose first named
   child is the type name and which holds the member-list container). Reverse-engineered from
   the Connext wire (clean-room, docs/provenance.md 2026-06-11), NOT an OMG-spec constant.")

(defconstant +lto-code-members+ 101
  "Legacy-TypeObject node CODE marking the member-list container (its named CODE-0 children
   are the struct members, its first value word the member count). Reverse-engineered from the
   Connext wire (clean-room, docs/provenance.md 2026-06-11), NOT an OMG-spec constant.")

(defconstant +lto-code-string-def+ 8
  "Legacy-TypeObject node CODE marking a STRING-definition node: a string member's node carries
   an 8-octet type-hash (at member VALUE-START+16) referencing this node, whose CODE-0 child
   echoes that hash at its VALUE-START+8 and whose CODE-200 child holds the string bound (u32).
   Reverse-engineered clean-room from the C_Shape / C_ShapeS32 / C_ShapeS300 differentials
   (docs/provenance.md 2026-06-11), NOT an OMG-spec constant.")

(defconstant +lto-code-string-bound+ 200
  "Legacy-TypeObject node CODE marking the string-bound child of a +LTO-CODE-STRING-DEF+ node:
   the string bound is the u32 at this child's VALUE-START (255 for an unbounded string — RTI's
   default — 32 / 300 for string<32>/string<300>; ALWAYS a u32 regardless of magnitude — the
   small/large split is OUR XTypes model, not RTI's wire). Reverse-engineered clean-room from
   the C_ShapeS32 / C_ShapeS300 differentials (docs/provenance.md 2026-06-11), NOT an OMG constant.")

(defconstant +lto-member-kind-string+ #x13
  "Legacy-TypeObject member type-kind u16 (at a member node's VALUE-START+8) marking a STRING8
   member: its bound lives in a referenced +LTO-CODE-STRING-DEF+ node (NOT inline). Reverse-
   engineered clean-room from the C_Shape capture (docs/provenance.md 2026-06-11), NOT an OMG constant.")

(defconstant +lto-member-kind-sequence+ #x12
  "Legacy-TypeObject member type-kind u16 (at a member node's VALUE-START+8) marking a SEQUENCE
   member: its element type + bound live in a referenced +LTO-CODE-SEQUENCE-DEF+ node (NOT inline),
   addressed by the same 8-octet type-hash@+16 mechanism strings use (string is 0x13, sequence is
   0x12). Reverse-engineered clean-room from the C_Seq / C_SeqL / C_SeqL100 differentials
   (docs/provenance.md 2026-06-11), NOT an OMG-spec constant.")

(defconstant +lto-member-kind-struct+ #x16
  "Legacy-TypeObject member type-kind u16 (at a member node's VALUE-START+8) marking a NESTED
   STRUCT (aggregate) member: the member's struct type lives in a referenced +LTO-CODE-STRUCT+
   (9) definition node — a TypeLibrary SIBLING of the outer struct — addressed by the same
   8-octet type-hash@+16 mechanism strings (0x13) and sequences (0x12) use (nested struct is
   0x16). Reverse-engineered clean-room from the C_Nested / C_Nested2 differentials
   (docs/provenance.md 2026-06-11), NOT an OMG-spec constant.")

(defparameter *lto-max-type-depth* 16
  "Max NESTED-STRUCT resolution depth for the legacy-TypeObject interpreter (NFR-SEC-POSTURE): a
   member chain (struct referencing a struct referencing …) deeper than this fails open — the
   over-depth member's TypeIdentifier is left NIL and the parse continues. Bounds a hostile
   deeply-nested TypeObject; complements the visited-hash cycle guard so a self-referential
   reference can never loop.")

(defconstant +lto-code-sequence-def+ 7
  "Legacy-TypeObject node CODE marking a SEQUENCE-definition node: a sequence member's node
   carries an 8-octet type-hash (at member VALUE-START+16) referencing this node, whose CODE-0
   child echoes that hash at its VALUE-START+8, whose +LTO-CODE-SEQUENCE-ELEMENT+ (100) child
   holds the element type-kind (u16, RTI's primitive enum), and whose +LTO-CODE-STRING-BOUND+
   (200) child holds the sequence bound (u32). Reverse-engineered clean-room from the C_Seq /
   C_SeqL / C_SeqL100 differentials (docs/provenance.md 2026-06-11), NOT an OMG-spec constant.")

(defconstant +lto-code-sequence-element+ 100
  "Legacy-TypeObject node CODE marking the element-type child of a +LTO-CODE-SEQUENCE-DEF+ node:
   the element type-kind is the u16 at this child's VALUE-START (octet 2 / long 5 — RTI's OWN
   primitive enum, *LTO-PRIMITIVE-KIND-KEYWORD*, repeated at +2). Reverse-engineered clean-room
   from the C_Seq (octet) / C_SeqL (long) differentials (docs/provenance.md 2026-06-11), NOT an
   OMG-spec constant.")

(defconstant +lto-sequence-default-bound+ 100
  "RTI's default bound for an UNBOUNDED legacy-TypeObject sequence (the C_Seq sequence<octet>
   capture emits bound 100, mirroring the 255 default for unbounded strings). Reverse-engineered
   clean-room (docs/provenance.md 2026-06-11), NOT an OMG-spec constant; recorded for documentation
   — the decoder reads the wire bound directly, it does not synthesize this value.")

(defconstant +lto-member-kind-enum+ #x0E
  "Legacy-TypeObject member type-kind u16 (at a member node's VALUE-START+8) marking an ENUM
   member: its bit-bound + literals live in a referenced +LTO-CODE-ENUM-DEF+ node (NOT inline),
   addressed by the same 8-octet type-hash@+16 mechanism strings (0x13), sequences (0x12) and
   nested structs (0x16) use (enum is 0x0E). Reverse-engineered clean-room from the C_Enum
   differential (docs/provenance.md 2026-06-12), NOT an OMG-spec constant.")

(defconstant +lto-code-enum-def+ 5
  "Legacy-TypeObject node CODE marking an ENUM-definition node: an enum member's node carries an
   8-octet type-hash (at member VALUE-START+16) referencing this node, whose CODE-0 child echoes
   that hash at its VALUE-START+8, whose +LTO-CODE-ENUM-BITBOUND+ (100) child holds the bit-bound
   (u32) and whose +LTO-CODE-ENUM-LITERALS+ (101) child holds the literal list. Reverse-engineered
   clean-room from the C_Enum differential (docs/provenance.md 2026-06-12), NOT an OMG-spec constant.")

(defconstant +lto-code-enum-bitbound+ 100
  "Legacy-TypeObject node CODE marking the bit-bound child of a +LTO-CODE-ENUM-DEF+ node: the
   storage bit width is the u32 at this child's VALUE-START (0x20 = 32 for a default enum). Shares
   the CODE value (100) with the sequence element-type child, disambiguated by parent CODE (enum-def
   5 vs sequence-def 7). Reverse-engineered clean-room from the C_Enum differential
   (docs/provenance.md 2026-06-12), NOT an OMG-spec constant.")

(defconstant +lto-code-enum-literals+ 101
  "Legacy-TypeObject node CODE marking the literal-list child of a +LTO-CODE-ENUM-DEF+ node: its
   value is count:u32 then, per literal, value:u32 + a length-prefixed NUL-padded literal name
   (the same string framing %LTO-READ-NAME decodes). Shares the CODE value (101) with the struct
   member-list container, disambiguated by parent CODE (enum-def 5 vs struct-def 9) — the enum
   decoder reads it only via the resolved enum-def node, so there is no collision. Reverse-engineered
   clean-room from the C_Enum differential (docs/provenance.md 2026-06-12), NOT an OMG-spec constant.")

(defconstant +lto-member-kind-array+ #x11
  "Legacy-TypeObject member type-kind u16 (at a member node's VALUE-START+8) marking an ARRAY
   member: its element kind + dimensions live in a referenced +LTO-CODE-ARRAY-DEF+ node (NOT inline),
   addressed by the same 8-octet type-hash@+16 mechanism strings (0x13), sequences (0x12), nested
   structs (0x16) and enums (0x0E) use (array is 0x11). Reverse-engineered clean-room from the C_Array
   differential (docs/provenance.md 2026-06-12), NOT an OMG-spec constant.")

(defconstant +lto-code-array-def+ 3
  "Legacy-TypeObject node CODE marking an ARRAY-definition node: an array member's node carries an
   8-octet type-hash (at member VALUE-START+16) referencing this node, whose CODE-0 child echoes that
   hash at its VALUE-START+8, whose +LTO-CODE-ARRAY-ELEMENT+ (100) child holds the element type-kind
   (u16, RTI's primitive enum) and whose +LTO-CODE-ARRAY-DIMS+ (200) child holds the dimension list
   (count:u32 then COUNT bounds:u32). Reverse-engineered clean-room from the C_Array differential
   (docs/provenance.md 2026-06-12), NOT an OMG-spec constant.")

(defconstant +lto-code-array-element+ 100
  "Legacy-TypeObject node CODE marking the element-type child of a +LTO-CODE-ARRAY-DEF+ node: the
   element type-kind is the u16 at this child's VALUE-START (RTI's OWN primitive enum,
   *LTO-PRIMITIVE-KIND-KEYWORD*, repeated at +2). Shares the CODE value (100) with the sequence
   element-type and the enum bit-bound children, disambiguated by parent CODE (array-def 3 vs
   sequence-def 7 vs enum-def 5). Reverse-engineered clean-room from the C_Array differential
   (docs/provenance.md 2026-06-12), NOT an OMG-spec constant.")

(defconstant +lto-code-array-dims+ 200
  "Legacy-TypeObject node CODE marking the dimension-list child of a +LTO-CODE-ARRAY-DEF+ node: its
   value is count:u32 at VALUE-START then COUNT bounds:u32 (for `long arr[4]`: count=1, dim[0]=4). The
   decoder accepts ONLY a single-dimension array (count=1, child extent exactly 8 octets); count/=1 or
   a longer extent is a MULTI-DIM array → fail open (the in-memory model is single-dimension). Shares
   the CODE value (200) with the string/sequence bound child, disambiguated by parent CODE (array-def 3
   vs string-def 8 / sequence-def 7). Reverse-engineered clean-room from the C_Array differential
   (docs/provenance.md 2026-06-12), NOT an OMG-spec constant.")

(defparameter *lto-max-enum-literals* 4096
  "Max enum literals the legacy-TypeObject enum decoder will read from a +LTO-CODE-ENUM-LITERALS+
   node before failing open (NFR-SEC-POSTURE): a resource-exhaustion guard bounding a hostile
   literal-count word; a larger declared count yields NIL (the enum member is unmodelable, the
   whole parse degrades to :unsupported).")

(defun* %lto-member-id (octets node)
    (function ((simple-array (unsigned-byte 8) (*)) lto-node) (or null (unsigned-byte 32)))
  "The 0-based declaration-order member id encoded as the u32 at the member NODE's VALUE-START+4
   (docs/provenance.md 2026-06-11), or NIL if that field falls outside the node's value extent
   — bounds-checked against VALUE-END FIRST (NFR-SEC-POSTURE)."
  (%lto-u32 octets (+ (lto-node-value-start node) 4) (lto-node-value-end node)))

(defun* %lto-member-has-kind-p (octets node)
    (function ((simple-array (unsigned-byte 8) (*)) lto-node) t)
  "T iff member NODE has a present (in-bounds) type-kind word at VALUE-START+8: i.e. the member
   declares a type. Used by the degrading policy (the operating contract, Task 4.1): a member
   that HAS a kind word but whose type cannot be modeled (%LTO-MEMBER-TYPE-IDENTIFIER returns NIL)
   is UNMODELABLE -> the whole parse degrades to :unsupported (fail-open). Bounds-checked FIRST
   (NFR-SEC-POSTURE)."
  (and (%lto-u16 octets (+ (lto-node-value-start node) 8) (lto-node-value-end node)) t))

(defun* %lto-member-key-p (octets node)
    (function ((simple-array (unsigned-byte 8) (*)) lto-node) t)
  "T iff member NODE is a @key member: the u32 @key flag at the member node's VALUE-START+0 is
   non-zero (1 for the key member, 0 otherwise — docs/provenance.md 2026-06-11). NIL if that
   field is OOB — bounds-checked against VALUE-END FIRST (NFR-SEC-POSTURE)."
  (let ((flag (%lto-u32 octets (lto-node-value-start node) (lto-node-value-end node))))
    (and flag (/= flag 0))))

(defparameter *lto-primitive-kind-keyword*
  '((#x01 . :bool) (#x02 . :u8) (#x03 . :i16) (#x04 . :u16) (#x05 . :i32)
    (#x06 . :u32) (#x07 . :i64) (#x08 . :u64) (#x09 . :f32) (#x0A . :f64) (#x0C . :char))
  "RTI legacy-TypeObject primitive type-kind octet -> our PRIMITIVE-TYPE-IDENTIFIER keyword.
   This is RTI's OWN internal type-kind enumeration (NOT the XTypes TK_* octets — they differ,
   e.g. RTI long=5 vs XTypes TK_INT32=4, RTI char=0x0C vs TK_CHAR8=0x10). Reverse-engineered
   clean-room from the C_ShapeP_<prim> differentials (each retypes member x; the kind sits at
   the member node's VALUE-START+8 as a u16, repeated at +10): boolean 1, octet 2, short 3,
   unsigned short 4, long 5, unsigned long 6, long long 7, unsigned long long 8, float 9,
   double 0x0A, char 0x0C (docs/provenance.md 2026-06-11). A kind not in this table (strings,
   sequences, nested aggregates, char16/wstring/enum) is NON-PRIMITIVE here and leaves the
   member type-identifier NIL — Task 2.3 decodes those. NOT an OMG-spec constant.")

(defun* %lto-octets-equal-p (octets a-start b-start n end)
    (function ((simple-array (unsigned-byte 8) (*)) (integer 0 #.array-dimension-limit) (integer 0 #.array-dimension-limit) (integer 0 #.array-dimension-limit) (integer 0 #.array-dimension-limit)) t)
  "T iff the N octets at OCTETS[A-START..) equal those at OCTETS[B-START..), with BOTH spans
   wholly within [0,END) — bounds-checked FIRST (NFR-SEC-POSTURE); NIL if either span is OOB."
  (and (<= 0 a-start) (<= (+ a-start n) end) (<= 0 b-start) (<= (+ b-start n) end)
       (loop for i from 0 below n
             always (= (aref octets (+ a-start i)) (aref octets (+ b-start i))))))

(defun* %lto-find-def-node (octets root member-node def-code)
    (function ((simple-array (unsigned-byte 8) (*)) lto-node lto-node (unsigned-byte 32)) (or null lto-node))
  "The DEF-CODE definition node referenced by MEMBER-NODE's 8-octet type-hash (at member
   VALUE-START+16): the LONG node with CODE DEF-CODE whose CODE-0 child echoes that hash at its
   VALUE-START+8 (the shared string/sequence hash-reference pattern). NIL if the hash field is
   OOB or no matching node exists — every span bounds-checked against the relevant VALUE-END
   FIRST (NFR-SEC-POSTURE). Clean-room (docs/provenance.md 2026-06-11)."
  (let ((hash-pos (+ (lto-node-value-start member-node) 16))
        (mend (lto-node-value-end member-node))
        (buf-end (length octets)))
    (when (> (+ hash-pos 8) mend)
      (return-from %lto-find-def-node nil))
    (labels ((find-def (n)
               (when (and (= (lto-node-tag n) +lto-tag-long+)
                          (= (lto-node-code n) def-code))
                 (dolist (c (lto-node-children n))
                   (when (and (= (lto-node-tag c) +lto-tag-long+) (= (lto-node-code c) 0)
                              (%lto-octets-equal-p octets hash-pos
                                                   (+ (lto-node-value-start c) 8) 8
                                                   buf-end))
                     (return-from find-def n))))
               (dolist (ch (lto-node-children n))
                 (let ((hit (find-def ch))) (when hit (return-from find-def hit))))
               nil))
      (find-def root))))

(defun* %lto-def-child-u32 (octets def-node child-code)
    (function ((simple-array (unsigned-byte 8) (*)) lto-node (unsigned-byte 32)) (or null (unsigned-byte 32)))
  "The u32 at the VALUE-START of DEF-NODE's first CHILD-CODE child, or NIL if absent or OOB —
   bounds-checked against the child's VALUE-END FIRST (NFR-SEC-POSTURE)."
  (dolist (c (lto-node-children def-node))
    (when (and (= (lto-node-tag c) +lto-tag-long+) (= (lto-node-code c) child-code))
      (return-from %lto-def-child-u32
        (%lto-u32 octets (lto-node-value-start c) (lto-node-value-end c)))))
  nil)

(defun* %lto-def-child-u16 (octets def-node child-code)
    (function ((simple-array (unsigned-byte 8) (*)) lto-node (unsigned-byte 32)) (or null (unsigned-byte 16)))
  "The u16 at the VALUE-START of DEF-NODE's first CHILD-CODE child, or NIL if absent or OOB —
   bounds-checked against the child's VALUE-END FIRST (NFR-SEC-POSTURE)."
  (dolist (c (lto-node-children def-node))
    (when (and (= (lto-node-tag c) +lto-tag-long+) (= (lto-node-code c) child-code))
      (return-from %lto-def-child-u16
        (%lto-u16 octets (lto-node-value-start c) (lto-node-value-end c)))))
  nil)

(defun* %lto-find-string-bound (octets root member-node)
    (function ((simple-array (unsigned-byte 8) (*)) lto-node lto-node) (or null (unsigned-byte 32)))
  "The string bound for a STRING member-node: resolve its referenced +LTO-CODE-STRING-DEF+ node
   (%LTO-FIND-DEF-NODE) and return the u32 bound at that node's +LTO-CODE-STRING-BOUND+ child.
   NIL if the reference or the bound field is missing/OOB — bounds-checked FIRST (NFR-SEC-POSTURE).
   Clean-room (docs/provenance.md 2026-06-11)."
  (let ((sdef (%lto-find-def-node octets root member-node +lto-code-string-def+)))
    (and sdef (%lto-def-child-u32 octets sdef +lto-code-string-bound+))))

(defun* %lto-sequence-type-identifier (octets root member-node)
    (function ((simple-array (unsigned-byte 8) (*)) lto-node lto-node) (or null type-identifier))
  "The TypeIdentifier for a SEQUENCE member-node: resolve its referenced +LTO-CODE-SEQUENCE-DEF+
   node (%LTO-FIND-DEF-NODE), read the element type-kind (u16) from its +LTO-CODE-SEQUENCE-ELEMENT+
   child and the bound (u32) from its +LTO-CODE-STRING-BOUND+ child, and build a
   SEQUENCE-TYPE-IDENTIFIER over the decoded element + bound. The element is decoded via
   *LTO-PRIMITIVE-KIND-KEYWORD* — sequence-of-PRIMITIVE only; a non-primitive element kind (string /
   nested aggregate / sequence-of-sequence) is a Task-3.2 gap and yields NIL (member TI stays NIL,
   parse continues). NIL if the reference, the element-kind, or the bound field is missing/OOB —
   every span bounds-checked FIRST (NFR-SEC-POSTURE). Clean-room (docs/provenance.md 2026-06-11)."
  (let ((sdef (%lto-find-def-node octets root member-node +lto-code-sequence-def+)))
    (when sdef
      (let ((ek (%lto-def-child-u16 octets sdef +lto-code-sequence-element+))
            (bound (%lto-def-child-u32 octets sdef +lto-code-string-bound+)))
        (when (and ek bound)
          (let ((kw (cdr (assoc ek *lto-primitive-kind-keyword*))))
            (and kw (sequence-type-identifier (primitive-type-identifier kw) bound))))))))

(defun* %lto-array-single-dim (octets def-node)
    (function ((simple-array (unsigned-byte 8) (*)) lto-node) (or null (integer 1)))
  "The single fixed dimension of array-definition DEF-NODE: read its +LTO-CODE-ARRAY-DIMS+ child,
   whose value is count:u32 at VALUE-START then COUNT bounds:u32. Returns the lone bound (dim[0],
   >= 1) for a 1-D array (count = 1 AND the child value extent is exactly 8 octets: 4 count + 4 one
   bound), else NIL — a MULTI-DIM array (count /= 1 or a longer extent carrying extra bounds), a zero
   bound, or a missing/OOB field fails open (the in-memory model is single-dimension). Every span
   bounds-checked against the child's VALUE-END FIRST (NFR-SEC-POSTURE). Clean-room
   (docs/provenance.md 2026-06-12)."
  (dolist (c (lto-node-children def-node))
    (when (and (= (lto-node-tag c) +lto-tag-long+) (= (lto-node-code c) +lto-code-array-dims+))
      (let* ((vs (lto-node-value-start c))
             (ve (lto-node-value-end c))
             (count (%lto-u32 octets vs ve))
             (dim (%lto-u32 octets (+ vs 4) ve)))
        (return-from %lto-array-single-dim
          (and count dim (= count 1) (= (- ve vs) 8) (>= dim 1) dim)))))
  nil)

(defun* %lto-array-type-identifier (octets root member-node)
    (function ((simple-array (unsigned-byte 8) (*)) lto-node lto-node) (or null type-identifier))
  "The TypeIdentifier for an ARRAY member-node: resolve its referenced +LTO-CODE-ARRAY-DEF+ node
   (%LTO-FIND-DEF-NODE), read the element type-kind (u16) from its +LTO-CODE-ARRAY-ELEMENT+ child and
   the single fixed dimension from its +LTO-CODE-ARRAY-DIMS+ child (%LTO-ARRAY-SINGLE-DIM), and build
   an ARRAY-TYPE-IDENTIFIER over the decoded PRIMITIVE element + size. The element is decoded via
   *LTO-PRIMITIVE-KIND-KEYWORD* — array-of-PRIMITIVE only; a non-primitive element kind (string /
   nested aggregate / sequence) yields NIL (member TI stays NIL, parse degrades). A MULTI-DIM array
   (dimension count /= 1) also yields NIL (single-dimension model only). NIL if the reference, the
   element-kind, or the dimension field is missing/OOB — every span bounds-checked FIRST
   (NFR-SEC-POSTURE). Clean-room (docs/provenance.md 2026-06-12)."
  (let ((adef (%lto-find-def-node octets root member-node +lto-code-array-def+)))
    (when adef
      (let ((ek (%lto-def-child-u16 octets adef +lto-code-array-element+))
            (size (%lto-array-single-dim octets adef)))
        (when (and ek size)
          (let ((kw (cdr (assoc ek *lto-primitive-kind-keyword*))))
            (and kw (array-type-identifier (primitive-type-identifier kw) size))))))))

(defun* %lto-enum-literals (octets lit-node)
    (function ((simple-array (unsigned-byte 8) (*)) lto-node) (or null list))
  "Decode the literal list of an enum's +LTO-CODE-ENUM-LITERALS+ child LIT-NODE into a list of
   ENUM-LITERAL: count:u32 at VALUE-START, then per literal value:u32 (the i32 enum constant) + a
   length-prefixed NUL-padded literal NAME (%LTO-READ-NAME framing). Each literal is built with
   MAKE-ENUM-LITERAL on the decoded NAME so its NameHash matches a locally-built model's (the wire
   carries names, not hashes). Returns NIL (the enum is unmodelable → degrade) when the count, any
   value, or any name is missing/OOB, the count exceeds *LTO-MAX-ENUM-LITERALS*, or the walk does
   not consume exactly to VALUE-END. Every wire read is bounds-checked against VALUE-END FIRST
   (NFR-SEC-POSTURE). Clean-room (docs/provenance.md 2026-06-12)."
  (let* ((vstart (lto-node-value-start lit-node))
         (vend (lto-node-value-end lit-node))
         (count (%lto-u32 octets vstart vend)))
    (when (or (null count) (> count *lto-max-enum-literals*))
      (return-from %lto-enum-literals nil))
    (let ((literals '())
          (pos (+ vstart 4)))
      (dotimes (i count)
        (let ((value (%lto-u32 octets pos vend)))
          (when (null value)
            (return-from %lto-enum-literals nil))
          (multiple-value-bind (name next) (%lto-read-name octets (+ pos 4) vend)
            (when (null name)
              (return-from %lto-enum-literals nil))
            (push (make-enum-literal name (- (logxor value #x80000000) #x80000000)) literals)
            (setf pos next))))
      (when (/= pos vend)
        (return-from %lto-enum-literals nil))
      (nreverse literals))))

(defun* %lto-enum-type-identifier (octets root member-node)
    (function ((simple-array (unsigned-byte 8) (*)) lto-node lto-node) (or null type-identifier))
  "The TypeIdentifier for an ENUM member-node: resolve its referenced +LTO-CODE-ENUM-DEF+ node
   (%LTO-FIND-DEF-NODE), read the bit-bound (u32) from its +LTO-CODE-ENUM-BITBOUND+ child and the
   literals from its +LTO-CODE-ENUM-LITERALS+ child (%LTO-ENUM-LITERALS), build a
   MINIMAL-ENUMERATED-TYPE and wrap it in an EK_MINIMAL ENUMERATED-TYPE-IDENTIFIER so assignability
   (enum-assignable-from) recurses into it. NIL (member TI stays NIL → degrade) when the reference,
   the bit-bound, or the literals are missing/OOB/over-budget — every span bounds-checked FIRST
   (NFR-SEC-POSTURE). Clean-room (docs/provenance.md 2026-06-12)."
  (let ((edef (%lto-find-def-node octets root member-node +lto-code-enum-def+)))
    (when edef
      (let ((bit-bound (%lto-def-child-u32 octets edef +lto-code-enum-bitbound+))
            (lit-node (find-if (lambda (c)
                                 (and (= (lto-node-tag c) +lto-tag-long+)
                                      (= (lto-node-code c) +lto-code-enum-literals+)))
                               (lto-node-children edef))))
        (when (and bit-bound (<= 1 bit-bound 64) lit-node)
          (let ((literals (%lto-enum-literals octets lit-node)))
            (and literals
                 (enumerated-type-identifier
                  (make-minimal-enumerated-type :bit-bound bit-bound
                                                :literals literals)))))))))

(defun* %lto-member-hash-key (octets node)
    (function ((simple-array (unsigned-byte 8) (*)) lto-node) (or null (unsigned-byte 64)))
  "The 8-octet type-hash at member NODE's VALUE-START+16 packed little-endian into a u64 — the
   cycle-guard key for a hash-referencing member (nested struct / string / sequence). NIL if that
   span is OOB — bounds-checked against the node's VALUE-END FIRST (NFR-SEC-POSTURE)."
  (let* ((p (+ (lto-node-value-start node) 16))
         (lo (%lto-u32 octets p (lto-node-value-end node)))
         (hi (%lto-u32 octets (+ p 4) (lto-node-value-end node))))
    (and lo hi (logior lo (ash hi 32)))))

(defun* %lto-nested-type-identifier (octets root node depth visited)
    (function ((simple-array (unsigned-byte 8) (*)) lto-node lto-node
               (integer 0 #.array-dimension-limit) list)
              (or null type-identifier))
  "The TypeIdentifier for a NESTED-STRUCT member NODE: resolve its 8-octet type-hash@+16 to the
   referenced +LTO-CODE-STRUCT+ (9) definition node (%LTO-FIND-DEF-NODE — a TypeLibrary sibling),
   parse THAT node into a MINIMAL-STRUCT-TYPE (%LTO-PARSE-STRUCT-NODE, recursively), and wrap it
   in an EK_MINIMAL HASH-TYPE-IDENTIFIER whose REFERENCED slot is the parsed nested model so
   assignability (struct-assignable-from) recurses into it. Fails open to NIL (member TI stays
   NIL, parse continues) when: the reference is unresolvable; DEPTH has reached *LTO-MAX-TYPE-DEPTH*;
   the member's hash is already in VISITED (a cycle — a struct referencing itself, directly or
   transitively); or the nested parse does not yield a struct. The hash key bounds-check is done
   FIRST (NFR-SEC-POSTURE). Clean-room (docs/provenance.md 2026-06-11)."
  (when (>= depth *lto-max-type-depth*)
    (return-from %lto-nested-type-identifier nil))
  (let ((key (%lto-member-hash-key octets node)))
    (when (or (null key) (member key visited))
      (return-from %lto-nested-type-identifier nil))
    (let ((def (%lto-find-def-node octets root node +lto-code-struct+)))
      (when (null def)
        (return-from %lto-nested-type-identifier nil))
      (let ((model (%lto-parse-struct-node octets root def (1+ depth) (cons key visited))))
        (and (minimal-struct-type-p model)
             (hash-type-identifier +ek-minimal+ :referenced model))))))

(defun* %lto-member-type-identifier (octets root node depth visited)
    (function ((simple-array (unsigned-byte 8) (*)) lto-node lto-node
               (integer 0 #.array-dimension-limit) list)
              (or null type-identifier))
  "The TypeIdentifier for a struct member NODE: a PRIMITIVE-TYPE-IDENTIFIER for a primitive
   member, a STRING8 TypeIdentifier (with the decoded bound, small/large per the 255 threshold)
   for a string member, a SEQUENCE-TYPE-IDENTIFIER (over a PRIMITIVE element, with the decoded
   bound) for a sequence-of-primitive member, an EK_MINIMAL HASH-TYPE-IDENTIFIER carrying the
   parsed nested MINIMAL-STRUCT-TYPE for a nested-struct member, else NIL. The type-kind is the
   u16 at the member node's VALUE-START+8 (the @key flag is +0, the id +4; the +10 copy is a
   redundant mirror, +8 is canonical). A primitive kind maps via *LTO-PRIMITIVE-KIND-KEYWORD*;
   kind +LTO-MEMBER-KIND-STRING+ (0x13) resolves the bound from the referenced
   +LTO-CODE-STRING-DEF+ node (%LTO-FIND-STRING-BOUND); kind +LTO-MEMBER-KIND-SEQUENCE+ (0x12)
   resolves the element + bound from the referenced +LTO-CODE-SEQUENCE-DEF+ node
   (%LTO-SEQUENCE-TYPE-IDENTIFIER); kind +LTO-MEMBER-KIND-STRUCT+ (0x16) resolves + parses the
   referenced +LTO-CODE-STRUCT+ node (%LTO-NESTED-TYPE-IDENTIFIER, recursive under DEPTH/VISITED
   guards); kind +LTO-MEMBER-KIND-ENUM+ (0x0E) resolves the bit-bound + literals from the referenced
   +LTO-CODE-ENUM-DEF+ node (%LTO-ENUM-TYPE-IDENTIFIER) into an EK_MINIMAL enumerated TI; kind
   +LTO-MEMBER-KIND-ARRAY+ (0x11) resolves the element kind + single dimension from the referenced
   +LTO-CODE-ARRAY-DEF+ node (%LTO-ARRAY-TYPE-IDENTIFIER) into a plain-array TI — all under
   ROOT. DEPTH + VISITED bound nested-struct recursion (*LTO-MAX-TYPE-DEPTH*
   and a visited-hash cycle guard). Returns NIL for a sequence/array-of-non-primitive (Task 3.x), a
   multi-dim array, an over-depth/cyclic nested struct, or when the kind field is OOB — bounds-checked
   against VALUE-END FIRST (NFR-SEC-POSTURE)."
  (let ((kind (%lto-u16 octets (+ (lto-node-value-start node) 8) (lto-node-value-end node))))
    (cond
      ((null kind) nil)
      ((= kind +lto-member-kind-string+)
       (let ((bound (%lto-find-string-bound octets root node)))
         (and bound (string8-type-identifier bound))))
      ((= kind +lto-member-kind-sequence+)
       (%lto-sequence-type-identifier octets root node))
      ((= kind +lto-member-kind-struct+)
       (%lto-nested-type-identifier octets root node depth visited))
      ((= kind +lto-member-kind-enum+)
       (%lto-enum-type-identifier octets root node))
      ((= kind +lto-member-kind-array+)
       (%lto-array-type-identifier octets root node))
      (t (let ((kw (cdr (assoc kind *lto-primitive-kind-keyword*))))
           (and kw (primitive-type-identifier kw)))))))

(defparameter *lto-extensibility-keyword*
  '((0 . :appendable) (1 . :final) (2 . :mutable))
  "RTI legacy-TypeObject struct extensibility flag (u16) -> our minimal-struct-type extensibility
   keyword. This is RTI's OWN internal enumeration (appendable 0, final 1, mutable 2), NOT the
   XTypes IS_FINAL/IS_APPENDABLE/IS_MUTABLE struct-flag bits (typeobject-cdr.lisp: final 0x0001,
   appendable 0x0002, mutable 0x0004 — they COINCIDE only for :final). Reverse-engineered clean-room
   from the C_Shape (@final) / C_ShapeAppend (@appendable) / C_ShapeMutable (@mutable) differentials
   (docs/provenance.md 2026-06-11), NOT an OMG-spec constant. A value not in this table -> :final
   (fail-open; :final is the strictest extensibility for assignability gating).")

(defun* %lto-struct-extensibility (octets sdef)
    (function ((simple-array (unsigned-byte 8) (*)) lto-node) (member :final :appendable :mutable))
  "The struct extensibility for struct-definition node SDEF: the u16 at VALUE-START+0 of SDEF's
   first NAMED child (the type-name-bearing CODE-0 node) mapped via *LTO-EXTENSIBILITY-KEYWORD*
   (docs/provenance.md 2026-06-11). Returns :FINAL when the flag is missing/OOB or carries an
   unknown value (fail-open — :final is the strictest/safest for gating). Bounds-checked against
   the child's VALUE-END FIRST (NFR-SEC-POSTURE)."
  (let ((c0 (find-if #'lto-node-name (lto-node-children sdef))))
    (or (and c0
             (let ((flag (%lto-u16 octets (lto-node-value-start c0) (lto-node-value-end c0))))
               (and flag (cdr (assoc flag *lto-extensibility-keyword*)))))
        :final)))

(defun* %lto-find-code (node code)
    (function (lto-node (unsigned-byte 32)) (or null lto-node))
  "The first descendant of NODE (pre-order, NODE included) whose TAG is +LTO-TAG-LONG+ and
   whose CODE equals CODE, or NIL. CODE is read only for LONG nodes (the SHORT-node guard).
   Note: code=0 is ambiguous (also the outer wrapper node), so do NOT pass 0 to locate members."
  (when (and (= (lto-node-tag node) +lto-tag-long+) (= (lto-node-code node) code))
    (return-from %lto-find-code node))
  (dolist (c (lto-node-children node))
    (let ((hit (%lto-find-code c code)))
      (when hit (return-from %lto-find-code hit))))
  nil)

(defun* %lto-first-named (node)
    (function (lto-node) (or null string))
  "The NAME of the first NAMED child of NODE (the struct-definition node's type name), or NIL."
  (dolist (c (lto-node-children node))
    (when (lto-node-name c) (return-from %lto-first-named (lto-node-name c))))
  nil)

(defun* %lto-parse-struct-node (octets root sdef depth visited)
    (function ((simple-array (unsigned-byte 8) (*)) lto-node lto-node
               (integer 0 #.array-dimension-limit) list)
              (or null minimal-struct-type (member :unsupported)))
  "Fold one +LTO-CODE-STRUCT+ node SDEF into a MINIMAL-STRUCT-TYPE — the shared struct-node→model
   core called BOTH by the top-level PARSE-LEGACY-TYPE-OBJECT entry and by the nested-struct
   resolver (%LTO-NESTED-TYPE-IDENTIFIER), so nesting recurses naturally. ROOT is the whole
   tokenized tree (a member's hash reference may point at a TypeLibrary SIBLING def node); DEPTH +
   VISITED bound nested-struct recursion (passed through to %LTO-MEMBER-TYPE-IDENTIFIER's nested
   arm). Returns a MINIMAL-STRUCT-TYPE on success, :UNSUPPORTED when SDEF carries no type name /
   no member-list container / no members / a member-count mismatch (mirroring the top-level
   discipline) OR when any member declares a type (kind word present) that cannot be modeled
   (%LTO-MEMBER-TYPE-IDENTIFIER NIL: an unmapped kind — union/bitmask/multi-dim-array — an unresolvable
   hash, or an over-depth/cyclic nested struct) — the degrading policy (the operating contract,
   Task 4.1): an unmodelable member fails the WHOLE parse open to :unsupported rather than emit a
   partial model with a NIL-TI member the Stage-5 gate could mis-handle. Every wire read is
   bounds-checked inside the helpers (NFR-SEC-POSTURE)."
  (let ((tname (%lto-first-named sdef))
        (container (%lto-find-code sdef +lto-code-members+)))
    (when (or (null tname) (null container))
      (return-from %lto-parse-struct-node :unsupported))
    (let ((members '()))
      (dolist (c (lto-node-children container))
        ;; code=0 is the observed member discriminator (docs/provenance.md 2026-06-11)
        (when (and (lto-node-name c) (= (lto-node-tag c) +lto-tag-long+)
                   (= (lto-node-code c) 0))
          (let ((id (%lto-member-id octets c)))
            (when (null id)
              (return-from %lto-parse-struct-node :unsupported))
            (let ((ti (%lto-member-type-identifier octets root c depth visited)))
              ;; degrading policy: an unmodelable typed member -> whole parse :unsupported (gate falls open)
              (when (and (null ti) (%lto-member-has-kind-p octets c))
                (return-from %lto-parse-struct-node :unsupported))
              (push (%make-minimal-struct-member
                     :name (lto-node-name c) :id id
                     :type-identifier ti
                     :key-p (%lto-member-key-p octets c)
                     :name-hash (member-name-hash (lto-node-name c)))
                    members)))))
      (when (null members)
        (return-from %lto-parse-struct-node :unsupported))
      ;; cross-check: container's first value word is the declared member count (docs/provenance.md 2026-06-11)
      (let ((wire-count (%lto-u32 octets (lto-node-value-start container)
                                 (lto-node-value-end container))))
        (when (and wire-count (/= wire-count (length members)))
          (return-from %lto-parse-struct-node :unsupported)))
      (make-minimal-struct-type :name tname
                                :extensibility (%lto-struct-extensibility octets sdef)
                                :members (nreverse members)))))

(defun* parse-legacy-type-object (octets)
    (function ((simple-array (unsigned-byte 8) (*)))
              (or null minimal-struct-type (member :unsupported)))
  "Interpret an INFLATED RTI legacy TypeObject (the inflated PID_TYPE_OBJECT_LB / 0x8021
   payload, ADR 0009) into a MINIMAL-STRUCT-TYPE skeleton: the struct type name, its member
   names, member ids (0-based declaration order), member TypeIdentifiers, and @key flags. MIRRORS
   parse-minimal-type-object's discipline: a minimal-struct-type on success, :UNSUPPORTED for a
   tree that tokenizes but carries no recognizable struct shape (no +LTO-CODE-STRUCT+ node, no
   member-list container, no type name), and NIL for input that does not tokenize cleanly
   (bounds/framing/resource violation per TOKENIZE-LEGACY-TYPE-OBJECT). PRIMITIVE member
   TYPE-IDENTIFIERs (Task 2.2) and STRING member TypeIdentifiers — with the decoded bound,
   small/large per the 255 threshold (Task 2.3) — are decoded via %LTO-MEMBER-TYPE-IDENTIFIER;
   SEQUENCE-of-primitive members get a plain-sequence TI with element kind + bound (Task 3.1);
   a NESTED-STRUCT member gets an EK_MINIMAL HASH-TYPE-IDENTIFIER whose REFERENCED slot is the
   parsed nested MINIMAL-STRUCT-TYPE — resolved from the referenced +LTO-CODE-STRUCT+ TypeLibrary-
   sibling node, recursively, under *LTO-MAX-TYPE-DEPTH* + a visited-hash cycle guard (Task 3.2);
   an ARRAY-of-primitive member gets a plain-array TI (element kind + single fixed dimension) resolved
   from the referenced +LTO-CODE-ARRAY-DEF+ node (Task 1.3);
   a member that declares a type the model cannot represent — an unmapped member-kind word
   (union/bitmask), an unresolvable hash, a sequence/array-of-aggregate, a multi-dim array, or an
   over-depth/cyclic nested struct — degrades the WHOLE result to :UNSUPPORTED (the operating contract, Task 4.1: fail
   the unmodelable member OPEN to name-match at the Stage-5 gate, never gate on a partial model with
   a NIL-TI member). Each member's @key flag is set from the wire (%LTO-MEMBER-KEY-P). EXTENSIBILITY is
   decoded from the wire (%LTO-STRUCT-EXTENSIBILITY: :final/:appendable/:mutable; an unknown flag
   fails open to :final). The struct-node→model fold is the shared %LTO-PARSE-STRUCT-NODE helper
   (reused by the nested resolver so nesting recurses naturally). The node-to-model
   mapping is reverse-engineered clean-room from the C_Shape / C_Shape3 / C_Shape4 / C_ShapeP_<prim>
   / C_ShapeS32 / C_ShapeS300 / C_ShapeNoKey / C_Seq / C_Nested differentials (docs/provenance.md
   2026-06-11): the
   +LTO-CODE-STRUCT+ node's first named child is the type name; its +LTO-CODE-MEMBERS+ container's
   named CODE-0 children are the members in order; each member's @key flag is the u32 at
   VALUE-START+0, its id the u32 at VALUE-START+4, its type-kind the u16 at VALUE-START+8 (string
   members reference a +LTO-CODE-STRING-DEF+ node for the bound; nested-struct members reference a
   +LTO-CODE-STRUCT+ node by the same hash@+16). Pair OCTETS with INFLATE-TYPE-OBJECT-LB."
  (let ((root (tokenize-legacy-type-object octets)))
    (when (null root)
      (return-from parse-legacy-type-object nil))
    ;; the first CODE-9 node (pre-order) is the OUTER struct; nested-type defs are later siblings
    (let ((sdef (%lto-find-code root +lto-code-struct+)))
      (when (null sdef)
        (return-from parse-legacy-type-object :unsupported))
      (%lto-parse-struct-node octets root sdef 0 '()))))
