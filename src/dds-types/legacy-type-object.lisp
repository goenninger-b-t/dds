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
