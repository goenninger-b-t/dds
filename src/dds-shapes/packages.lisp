;;;; Shapes interop harness package. Defines the canonical OMG Shapes ShapeType
;;;; (string<128> color [@key]; long x; long y; long shapesize) and standalone
;;;; publisher/subscriber participants for the "Square" topic over multicast
;;;; discovery. Meant to interop with RTI rtishapesdemo / Fast DDS / Cyclone.

(defpackage #:net.goenninger.dds.shapes
  (:nicknames #:dds.shapes)
  (:use #:common-lisp)
  (:documentation
   "Standalone Square/ShapeType publisher + subscriber on the participant data
    plane (dds.disc) for cross-process and Connext interop. run-publisher animates
    a Square; run-subscriber prints received Squares.")
  (:export #:shape-type #:make-shape-type
           #:shape-type-color #:shape-type-x #:shape-type-y #:shape-type-shapesize
           #:run-publisher #:run-subscriber))
