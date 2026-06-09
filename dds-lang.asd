;;;; L-1 — Language tools (load-order root). Fully-contracted DEFUN*/DEFSTRUCT*.
(defsystem "dds-lang"
  :description "DDS.LANG — fully-contracted DEFUN*/DEFSTRUCT* definition forms (FR-LANG-8 + §5.1)."
  :pathname "src/dds-lang"
  :serial t
  :components ((:file "lisp-lang-tools"))
  :in-order-to ((test-op (test-op "dds-tests"))))
