;;;; Shapes interop harness package. Defines the canonical OMG Shapes ShapeType
;;;; (string<128> color [@key]; long x; long y; long shapesize) and standalone
;;;; publisher/subscriber participants for the "Square" topic over multicast
;;;; discovery. Meant to interop with RTI rtishapesdemo / Fast DDS / Cyclone.

(defpackage #:net.goenninger.dds.shapes
  (:nicknames #:dds.shapes)
  (:use #:common-lisp #:net.goenninger.dds.lang)
  (:documentation
   "Standalone Square/ShapeType publisher + subscriber on the participant data
    plane (dds.disc) for cross-process and Connext interop. run-publisher animates
    a Square; run-subscriber prints received Squares.")
  (:export #:shape-type #:make-shape-type
           #:shape-type-color #:shape-type-x #:shape-type-y #:shape-type-shapesize
           #:tagged-shape #:make-tagged-shape
           #:tagged-shape-color #:tagged-shape-x #:tagged-shape-y #:tagged-shape-shapesize
           #:tagged-shape-uuid #:tagged-shape-seq
           #:large-data #:make-large-data #:large-data-id #:large-data-payload
           #:serialize-large-data #:deserialize-large-data
           #:shape-mismatch #:make-shape-mismatch
           #:shape-mismatch-color #:shape-mismatch-x #:shape-mismatch-y #:shape-mismatch-shapesize
           #:run-publisher #:run-subscriber #:run-spy
           #:run-large-publisher #:run-large-subscriber
           #:run-gated-subscriber
           #:run-corpus-capture-subscriber))
