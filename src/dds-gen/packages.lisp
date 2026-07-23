;;;; L3 — Type compiler (FR-TOOL-1). The s-expr DSL `define-dds-type` is the
;;;; linchpin of the no-CLOS strategy: it emits a defstruct + monomorphic codec
;;;; functions + a registered type-support. Build-time only (a macro); the macro
;;;; itself is off the hot path, the code it EMITS is the hot path.

(defpackage #:net.goenninger.dds.gen
  (:nicknames #:dds.gen)
  (:use #:common-lisp #:net.goenninger.dds.lang)
  (:documentation
   "s-expr type DSL -> defstruct + serialize/deserialize/serialized-size +
    type-support (IMPLEMENTATION-PLAN §7.2/§7.3, FR-TOOL-1). v1 supports :final
    extensibility with primitive and string members; appendable/mutable framing,
    sequences, nested types, and key-hash are later increments.")
  (:export #:define-dds-type #:define-dds-enum))
