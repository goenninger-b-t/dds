;;;; Standalone Square/ShapeType publisher + subscriber over multicast discovery.
;;;; Also includes LargeData publisher/subscriber harness for DATA_FRAG interop testing.
;;;; Built entirely on the participant data plane (dds.disc) + the generated codec
;;;; (dds.gen). Two processes discover each other via SPDP multicast on the domain's
;;;; well-known group, match the "Square" topic via SEDP, and exchange ShapeType
;;;; samples reliably. The same participant is intended to interop with RTI
;;;; rtishapesdemo / Fast DDS / Cyclone Shapes (see docs/interop-shapes.md).

(in-package #:dds.shapes)

;; Two selectable Square payload types (:type :canonical | :tagged at runtime):
;;  - shape-type   : the EXACT RTI canonical ShapeType (color @key; x; y; shapesize).
;;                   Use for interop with rtishapesdemo / DDSSpy.
;;  - tagged-shape : the same + a per-publisher uuid + per-sample seq (stream id +
;;                   ordering/loss). DIVERGES from canonical => harness<->harness only.
;; Both :final with only 32-bit/string members => XCDR1 and XCDR2 bytes coincide.
(dds.gen:define-dds-type shape-type (:extensibility :final)
  (color :string :key t)
  (x :i32)
  (y :i32)
  (shapesize :i32))

(dds.gen:define-dds-type tagged-shape (:extensibility :final)
  (color :string :key t)
  (x :i32)
  (y :i32)
  (shapesize :i32)
  (uuid :string)
  (seq :u32))

;; C_Shape with shapesize retyped i32->i64 (same id, different kind => NOT assignable, Table 15): the gate's incompatible-reject fixture.
(dds.gen:define-dds-type shape-mismatch (:extensibility :final)
  (color :string :key t)
  (x :i32)
  (y :i32)
  (shapesize :i64))

;; No @key member => type-support-keyed-p NIL => endpoints come up NO_KEY (writer 0x03 / reader 0x04, RTPS 2.5 §9.3.1.2). Live-proof type for the keyed/no-key endpoint-kinds feature.
(dds.gen:define-dds-type nokey-data (:extensibility :final)
  (a :i32)
  (b :i32))

(defun* %shape-type-information ()
    (function () (or null (simple-array (unsigned-byte 8) (*))))
  "Opaque serialized XTypes TypeInformation for the canonical ShapeType, advertised in
   PID_TYPE_INFORMATION so rtishapesdemo / DDSSpy see our type; NIL if unavailable.
   The EK_MINIMAL hash + size inside are externally confirmed vs live Fast DDS 3.6.1
   (FR-IO-2 S3; test fastdds-type-information-vector — see typeobject-cdr.lisp)."
  (handler-case
      (let ((ts (dds.types:find-type-support "shape-type")))
        (and ts (dds.types:serialize-type-information (dds.types:type-support-typeobject ts))))
    (error () nil)))

(defun* %make-uuid ()
    (function () string)
  "A random RFC-4122 v4 UUID string identifying one publisher stream. Demo-grade
   (seeds from make-random-state t; production wants a vetted UUID source)."
  (let ((rs (make-random-state t))
        (b (make-array 16 :element-type '(unsigned-byte 8))))
    (dotimes (i 16) (setf (aref b i) (random 256 rs)))
    (setf (aref b 6) (logior #x40 (logand (aref b 6) #x0f)))   ; version 4
    (setf (aref b 8) (logior #x80 (logand (aref b 8) #x3f)))   ; variant 10x
    (format nil "~(~2,'0x~2,'0x~2,'0x~2,'0x-~2,'0x~2,'0x-~2,'0x~2,'0x-~2,'0x~2,'0x-~2,'0x~2,'0x~2,'0x~2,'0x~2,'0x~2,'0x~)"
            (aref b 0) (aref b 1) (aref b 2) (aref b 3) (aref b 4) (aref b 5)
            (aref b 6) (aref b 7) (aref b 8) (aref b 9) (aref b 10) (aref b 11)
            (aref b 12) (aref b 13) (aref b 14) (aref b 15))))

(defun* %make-prefix (role)
    (function ((unsigned-byte 8)) (simple-array (unsigned-byte 8) (12)))
  "A 12-octet GUID prefix: marker 'G' 'B' + ROLE byte + wall-clock-derived tail, so
   a publisher (role #x50) and subscriber (role #x53), and successive runs, get
   distinct prefixes. Demo-grade, not a real GUID allocator."
  (let ((p (make-array 12 :element-type '(unsigned-byte 8) :initial-element 0))
        (clk (get-universal-time)))
    (setf (aref p 0) #x47 (aref p 1) #x42 (aref p 2) role)
    (loop for i from 3 below 12
          do (setf (aref p i) (logand (ash clk (* -8 (- i 3))) #xff)))
    p))

(defun* %serialize-payload (serialize-fn &optional (capacity 256))
    (function (function &optional (integer 1)) (simple-array (unsigned-byte 8) (*)))
  "Build a PLAIN_CDR2_LE SerializedPayload: an encapsulation header + whatever
   SERIALIZE-FN writes (called with the XCDR2 cursor) into a CAPACITY-octet scratch
   buffer (default 256; pass a larger CAPACITY for large samples). Returns a fresh
   octet vector — the data-plane publish payload. Works for either shape type."
  (let* ((buf (dds.core.buffer:make-octet-buffer capacity))
         (wc (dds.core.buffer:cursor buf :endianness :little)))
    (dds.cdr:make-encapsulation-header wc :plain-cdr2-le)
    (funcall serialize-fn wc)
    (let* ((len (dds.core.buffer:cursor-position wc))
           (out (make-array len :element-type '(unsigned-byte 8))))
      (replace out (dds.core.buffer:octet-buffer-vec buf) :end1 len)
      (dds.pal:free-static (dds.core.buffer:octet-buffer-vec buf))
      out)))

(defun* %deserialize-with (bytes deserialize-fn)
    (function ((simple-array (unsigned-byte 8) (*)) function) t)
  "Parse a SerializedPayload's encapsulation header (honoring representation +
   endianness, so a foreign CDR_LE/BE or CDR2_LE/BE sender is handled), then call
   DESERIALIZE-FN with (cursor mode). Both shape types are :final (no DHEADER)."
  (let* ((ob (dds.core.buffer:make-octet-buffer (length bytes)))
         (rc (dds.core.buffer:cursor ob :endianness :little)))
    (replace (dds.core.buffer:octet-buffer-vec ob) bytes)
    (let ((rep (dds.cdr:parse-encapsulation-header rc)))
      (dds.core.buffer:cursor-set-endianness
       rc (if (member rep '(:plain-cdr-be :plain-cdr2-be :pl-cdr-be :pl-cdr2-be :delimited-cdr-be))
              :big :little))
      (let ((mode (if (member rep '(:plain-cdr-le :plain-cdr-be)) :xcdr1 :xcdr2)))
        (prog1 (funcall deserialize-fn rc mode)
          (dds.pal:free-static (dds.core.buffer:octet-buffer-vec ob)))))))

(defun* %reannounce (node last)
    (function (dds.disc:disc-node (integer 0)) t)
  "Re-announce SPDP + SEDP if more than ~1.5 s have passed since LAST (an internal
   real-time stamp). Returns the new stamp (LAST if no announce). Keeps a late-
   joining peer (or Connext) discovering + matching this participant."
  (let ((now (get-internal-real-time)))
    (if (> (- now last) (round (* 1.5 internal-time-units-per-second)))
        (progn (dds.disc:announce-participant node)
               (dds.disc:announce-endpoints node)
               now)
        last)))

(defun* %parse-peers (peers)
    (function ((or null string)) list)
  "Parse a \"host:port[,host:port]...\" PEERS string into the ((host . port) ...)
   list make-disc-node expects (FR-DISC-4 unicast announce targets). NIL or \"\"
   parses to NIL (multicast-only discovery). A malformed entry (missing colon,
   empty host, non-numeric or out-of-range port) signals one uniform error."
  (when (and peers (plusp (length peers)))
    (loop for entry in (uiop:split-string peers :separator ",")
          for colon = (position #\: entry :from-end t)
          for port = (and colon (ignore-errors (parse-integer entry :start (1+ colon))))
          unless (and colon (plusp colon) (typep port '(unsigned-byte 16)))
            do (error "peer ~s is not host:port (port 0..65535)" entry)
          collect (cons (subseq entry 0 colon) port))))

(defun* run-publisher (&key (domain 0) (color "BLUE") (shapesize 30) (rate 30) (count 0)
                           (advertise-address "127.0.0.1") (type :tagged) (peers nil))
    (function (&key (:domain (integer 0)) (:color string) (:shapesize (integer 0)) (:rate (integer 1)) (:count (integer 0)) (:advertise-address string) (:type symbol) (:peers (or null string))) t)
  "Publish an animated Square on DOMAIN via multicast discovery. TYPE selects the
   payload: :canonical = the exact RTI ShapeType (color/x/y/shapesize — for interop
   with rtishapesdemo / DDSSpy); :tagged = + per-publisher uuid + per-sample seq
   (harness<->harness). RATE updates/sec; COUNT 0 = forever (Ctrl-C). PEERS is an
   optional \"host:port[,host:port]\" list of unicast SPDP announce targets
   (FR-DISC-4) on top of multicast — e.g. \"127.0.0.1:7410\" reaches a same-host
   peer over loopback when the macOS application firewall / local-network privacy
   layer silently drops LAN-sourced UDP for unapproved peer binaries."
  (check-type type (member :canonical :tagged))
  (let ((node (dds.disc:make-disc-node :guid-prefix (%make-prefix #x50) :domain domain
                                       :multicast t :advertise-address advertise-address
                                       :peers (%parse-peers peers))))
    (dds.disc:add-local-writer node :topic "Square" :type "ShapeType"
                               :reliability dds.rtps.discovery:+reliability-reliable+
                               :type-information (%shape-type-information))
    (dds.disc:enable-publisher node)
    (dds.disc:start-node node)
    (let ((uuid (%make-uuid)))
      (format t "~&[pub] Square/ShapeType[~(~a~)] color=~a domain=~d uuid=~a (multicast 239.255.0.1). Ctrl-C to stop.~%"
              type color domain uuid)
      (let ((x 50) (y 50) (dx 3) (dy 2) (period (/ 1.0 rate)) (n 0) (last 0) (seq 0)
            (dests (make-hash-table :test 'equalp)))
        (unwind-protect
             (loop
               (setf last (%reannounce node last))
               ;; report the data destination we resolve for each discovered peer
               (dolist (p (dds.disc:node-discovered-participants node))
                 (let ((prefix (dds.rtps.discovery:spdp-data-guid-prefix p)))
                   (unless (gethash prefix dests)
                     (setf (gethash prefix dests) t)
                     (let ((d (dds.disc:resolved-destination p)))
                       (format t "~&[pub] peer discovered -> DATA destination ~a~%"
                               (if d (format nil "~a:~d" (car d) (cdr d))
                                   "NONE (no routable UDPv4 locator)"))))))
               (setf x (+ x dx) y (+ y dy))
               (when (or (<= x 0) (>= x 240)) (setf dx (- dx) x (min 240 (max 0 x))))
               (when (or (<= y 0) (>= y 240)) (setf dy (- dy) y (min 240 (max 0 y))))
               (incf seq)
               (dds.disc:publish-sample
                node (ecase type
                       (:canonical
                        (%serialize-payload
                         (lambda (wc) (serialize-shape-type
                                       (make-shape-type :color color :x x :y y :shapesize shapesize)
                                       wc :xcdr2))))
                       (:tagged
                        (%serialize-payload
                         (lambda (wc) (serialize-tagged-shape
                                       (make-tagged-shape :color color :x x :y y :shapesize shapesize
                                                          :uuid uuid :seq seq)
                                       wc :xcdr2))))))
               (incf n)
               (when (zerop (mod n 30))
                 (format t "~&[pub] sent ~d samples; peers=~d; ACKNACKs received=~d~%"
                         n (hash-table-count dests) (dds.disc:node-acks-in node)))
               (when (and (plusp count) (>= n count)) (return))
               (sleep period))
          (dds.disc:stop-node node)
          (format t "~&[pub] stopped after ~d samples; ACKNACKs received=~d (uuid=~a).~%"
                  n (dds.disc:node-acks-in node) uuid))))
    t))

(defun* %octets-hex (octets)
    (function (vector) string)
  "Lowercase hex rendering of an octet vector (GUID prefixes, EquivalenceHashes)."
  (format nil "~(~{~2,'0x~}~)" (coerce octets 'list)))

(defun* %hex-prefix (prefix)
    (function ((simple-array (unsigned-byte 8) (12))) string)
  "Lowercase hex of a 12-octet GUID prefix."
  (%octets-hex prefix))

(defun* %fmt-locator (loc)
    (function (dds.rtps.discovery:locator) string)
  "Human-readable locator: 'UDPv4 a.b.c.d:port', or 'kind=#xK port=P' for non-UDPv4
   (e.g. SHMEM / UDPv6 — exactly the entries a foreign stack may also advertise)."
  (let ((kind (dds.rtps.discovery:locator-kind loc))
        (port (dds.rtps.discovery:locator-port loc)))
    (if (= kind dds.rtps.discovery:+locator-kind-udpv4+)
        (format nil "UDPv4 ~a:~d" (dds.rtps.discovery:locator-ipv4-string loc) port)
        (format nil "kind=#x~x port=~d" kind port))))

(defun* %fmt-locators (locs)
    (function (list) string)
  "Comma-separated locator list, or '(none)'."
  (if (null locs) "(none)" (format nil "~{~a~^, ~}" (mapcar #'%fmt-locator locs))))

(defun* %print-participant (p)
    (function (dds.rtps.discovery:spdp-data) t)
  "Print a discovered participant's advertised locators + the data destination this
   stack resolves for it."
  (format t "~&[spy] participant ~a~%" (%hex-prefix (dds.rtps.discovery:spdp-data-guid-prefix p)))
  (format t "        vendor=~2,'0x.~2,'0x version=~d.~d lease=~ds endpoints=#x~8,'0x~%"
          (ldb (byte 8 8) (dds.rtps.discovery:spdp-data-vendor-id p))
          (ldb (byte 8 0) (dds.rtps.discovery:spdp-data-vendor-id p))
          (dds.rtps.discovery:spdp-data-version-major p)
          (dds.rtps.discovery:spdp-data-version-minor p)
          (dds.rtps.discovery:spdp-data-lease-duration-seconds p)
          (dds.rtps.discovery:spdp-data-builtin-endpoint-set p))
  (format t "        default-unicast:     ~a~%"
          (%fmt-locators (dds.rtps.discovery:spdp-data-default-unicast-locators p)))
  (format t "        metatraffic-unicast: ~a~%"
          (%fmt-locators (dds.rtps.discovery:spdp-data-metatraffic-unicast-locators p)))
  (let ((dest (dds.disc:resolved-destination p)))
    (format t "        -> resolved data destination: ~a~%"
            (if dest (format nil "~a:~d" (car dest) (cdr dest))
                "NONE (no routable UDPv4 locator advertised)"))))

(defun* run-spy (&key (domain 0) (seconds 0) (advertise-address "127.0.0.1"))
    (function (&key (:domain (integer 0)) (:seconds (integer 0)) (:advertise-address string)) t)
  "Discovery diagnostic: join multicast SPDP on DOMAIN and print every discovered
   participant's advertised locators + the destination this stack resolves for it
   (no reader/writer). Use it to see exactly what we extract from a foreign SPDP
   announcement, e.g. RTI DDSSpy. SECONDS 0 = forever (Ctrl-C to stop)."
  (let ((node (dds.disc:make-disc-node :guid-prefix (%make-prefix #x59) :domain domain
                                       :multicast t :advertise-address advertise-address)))
    (dds.disc:start-node node)
    (format t "~&[spy] watching domain ~d (multicast 239.255.0.1). Ctrl-C to stop.~%" domain)
    (let ((seen (make-hash-table :test 'equalp)) (last 0) (start (get-internal-real-time)))
      (unwind-protect
           (loop
             (let ((now (get-internal-real-time)))
               (when (> (- now last) (round (* 1.5 internal-time-units-per-second)))
                 (dds.disc:announce-participant node)
                 (setf last now)))
             (dolist (p (dds.disc:node-discovered-participants node))
               (let ((prefix (dds.rtps.discovery:spdp-data-guid-prefix p)))
                 (unless (gethash prefix seen)
                   (setf (gethash prefix seen) t)
                   (%print-participant p))))
             (when (and (plusp seconds)
                        (> (/ (- (get-internal-real-time) start) internal-time-units-per-second)
                           seconds))
               (return))
             (sleep 0.1))
        (dds.disc:stop-node node)
        (format t "~&[spy] stopped; ~d participant(s) discovered.~%" (hash-table-count seen)))
      t)))

(defun* run-subscriber (&key (domain 0) (seconds 0) (advertise-address "127.0.0.1") (type :tagged))
    (function (&key (:domain (integer 0)) (:seconds (integer 0)) (:advertise-address string) (:type symbol)) t)
  "Subscribe to Square on DOMAIN via multicast discovery and print every shape.
   TYPE selects the payload codec (:canonical | :tagged) and must match the
   publisher. SECONDS 0 = forever (Ctrl-C). Receives from rtishapesdemo / DDSSpy
   (use :canonical) or this harness's publisher."
  (check-type type (member :canonical :tagged))
  (let ((node (dds.disc:make-disc-node :guid-prefix (%make-prefix #x53) :domain domain
                                       :multicast t :advertise-address advertise-address)))
    (dds.disc:add-local-reader node :topic "Square" :type "ShapeType"
                               :reliability dds.rtps.discovery:+reliability-reliable+
                               :type-information (%shape-type-information))
    (dds.disc:enable-subscriber node)
    (dds.disc:start-node node)
    (format t "~&[sub] Square/ShapeType[~(~a~)] domain=~d (multicast 239.255.0.1). Ctrl-C to stop.~%" type domain)
    (let ((printed (make-hash-table :test 'eql))
          (expected (make-hash-table :test 'equal))   ; uuid -> next expected app seq
          (last 0) (seen 0) (start (get-internal-real-time)))
      (unwind-protect
           (loop
             (setf last (%reannounce node last))
             (dolist (sn (sort (dds.disc:node-sample-sns node) #'<))
               (unless (gethash sn printed)
                 (setf (gethash sn printed) t)
                 ;; a sample we cannot parse (wrong TYPE, foreign encoding, malformed)
                 ;; must never crash the subscriber — skip it with a hint.
                 (handler-case
                     (ecase type
                       (:canonical
                        (let ((s (%deserialize-with (dds.disc:node-sample node sn) #'deserialize-shape-type)))
                          (declare (type shape-type s))
                          (format t "~&[sub] Square ~a x=~d y=~d size=~d~%"
                                  (shape-type-color s) (shape-type-x s)
                                  (shape-type-y s) (shape-type-shapesize s))
                          (incf seen)))
                       (:tagged
                        (let ((s (%deserialize-with (dds.disc:node-sample node sn) #'deserialize-tagged-shape)))
                          (declare (type tagged-shape s))
                          (let* ((u (tagged-shape-uuid s)) (q (tagged-shape-seq s)) (exp (gethash u expected)))
                            (when (and exp (/= q exp))
                              (format t "~&[sub] GAP from ~a: expected seq ~d, got ~d~%" u exp q))
                            (setf (gethash u expected) (1+ q))
                            (format t "~&[sub] Square ~a x=~d y=~d size=~d uuid=~a seq=~d~%"
                                    (tagged-shape-color s) (tagged-shape-x s) (tagged-shape-y s)
                                    (tagged-shape-shapesize s) u q)
                            (incf seen)))))
                   (error (e)
                     (format t "~&[sub] sn=~d: cannot parse as ~(~a~) (~a) — TYPE mismatch? RTI Squares are canonical: run TYPE=canonical~%"
                             sn type (type-of e))))))
             (when (and (plusp seconds)
                        (> (/ (- (get-internal-real-time) start) internal-time-units-per-second)
                           seconds))
               (return))
             (sleep 0.05))
        (dds.disc:stop-node node)
        (format t "~&[sub] stopped; received ~d shapes.~%" seen))
      t)))

;;; LargeData type: keyed (id) + unbounded octet sequence payload for DATA_FRAG testing.
(dds.gen:define-dds-type large-data (:extensibility :final)
  (id :i32 :key t)
  (payload (:sequence :u8)))

(defun* run-large-publisher (&key (domain 0) (size 8000) (rate 2) (count 0)
                                  (advertise-address "127.0.0.1") drop-fragments)
    (function (&key (:domain (integer 0)) (:size (integer 1)) (:rate (integer 1))
                    (:count (integer 0)) (:advertise-address string) (:drop-fragments list)) t)
  "Publish LargeData samples on DOMAIN via multicast discovery. SIZE is the octet count of
   the payload (default 8000, well above *fragment-size*=1024); RATE updates/sec; COUNT 0
   = forever (Ctrl-C). The payload is filled with i*7 mod 256 so the subscriber can verify.
   DROP-FRAGMENTS (a list of 1-based fragment numbers) sets
   dds.disc:*debug-drop-fragment-numbers* for the duration of the run (globally — the
   ACKNACK retransmit path runs on the receiver thread): those fragments are never
   pushed, so a reliable peer must NACK_FRAG them back (fragment-loss injection)."
  (let ((node (dds.disc:make-disc-node :guid-prefix (%make-prefix #x4c) :domain domain
                                       :multicast t :advertise-address advertise-address)))
    (dds.disc:add-local-writer node :topic "LargeData" :type "LargeData"
                               :reliability dds.rtps.discovery:+reliability-reliable+)
    (dds.disc:enable-publisher node)
    (dds.disc:start-node node)
    (format t "~&[large-pub] LargeData domain=~d size=~d (multicast 239.255.0.1). Ctrl-C to stop.~%"
            domain size)
    (let ((period (/ 1.0 rate)) (n 0) (last 0)
          (dests (make-hash-table :test 'equalp)))
      (unwind-protect
           (progn
             (when drop-fragments
               (setf dds.disc:*debug-drop-fragment-numbers* drop-fragments)
               (format t "~&[large-pub] LOSS INJECTION: dropping fragment(s) ~a on push.~%" drop-fragments))
             (loop
               (setf last (%reannounce node last))
               (dolist (p (dds.disc:node-discovered-participants node))
                 (let ((prefix (dds.rtps.discovery:spdp-data-guid-prefix p)))
                   (unless (gethash prefix dests)
                     (setf (gethash prefix dests) t)
                     (let ((d (dds.disc:resolved-destination p)))
                       (format t "~&[large-pub] peer discovered -> DATA destination ~a~%"
                               (if d (format nil "~a:~d" (car d) (cdr d))
                                   "NONE (no routable UDPv4 locator)"))))))
               (incf n)
               (let* ((pv (make-array size :element-type '(unsigned-byte 8)))
                      (sample (make-large-data :id n :payload pv)))
                 (dotimes (i size) (setf (aref pv i) (logand (* i 7) #xff)))
                 (dds.disc:publish-sample
                  node (%serialize-payload
                        (lambda (wc) (serialize-large-data sample wc :xcdr2))
                        (+ size 64))))
               (when (zerop (mod n 10))
                 (format t "~&[large-pub] sent ~d samples; size=~d; peers=~d~%"
                         n size (hash-table-count dests)))
               (when (and (plusp count) (>= n count)) (return))
               (sleep period)))
        (setf dds.disc:*debug-drop-fragment-numbers* nil)
        (dds.disc:stop-node node)
        (format t "~&[large-pub] stopped after ~d samples.~%" n)))
    t))

(defun* run-large-subscriber (&key (domain 0) (seconds 0) (advertise-address "127.0.0.1"))
    (function (&key (:domain (integer 0)) (:seconds (integer 0)) (:advertise-address string)) t)
  "Subscribe to LargeData on DOMAIN via multicast discovery and print a one-line summary
   (id + payload length + octet-by-octet (i*7) mod 256 pattern verdict) per received
   sample. SECONDS 0 = forever (Ctrl-C)."
  (let ((node (dds.disc:make-disc-node :guid-prefix (%make-prefix #x6c) :domain domain
                                       :multicast t :advertise-address advertise-address)))
    (dds.disc:add-local-reader node :topic "LargeData" :type "LargeData"
                               :reliability dds.rtps.discovery:+reliability-reliable+)
    (dds.disc:enable-subscriber node)
    (dds.disc:start-node node)
    (format t "~&[large-sub] LargeData domain=~d (multicast 239.255.0.1). Ctrl-C to stop.~%" domain)
    (let ((printed (make-hash-table :test 'eql))
          (last 0) (seen 0) (start (get-internal-real-time)))
      (unwind-protect
           (loop
             (setf last (%reannounce node last))
             (dolist (sn (sort (dds.disc:node-sample-sns node) #'<))
               (unless (gethash sn printed)
                 (setf (gethash sn printed) t)
                 (handler-case
                     (let ((s (%deserialize-with (dds.disc:node-sample node sn) #'deserialize-large-data)))
                       (declare (type large-data s))
                       (let* ((pv (large-data-payload s))
                              (bad (loop for i from 0 below (length pv)
                                         unless (= (aref pv i) (logand (* i 7) #xff)) return i)))
                         (format t "~&[large-sub] id=~d payload-length=~d pattern=~a~%"
                                 (large-data-id s) (length pv)
                                 (if bad (format nil "BAD@~d" bad) "OK")))
                       (incf seen))
                   (error (e)
                     (format t "~&[large-sub] sn=~d: cannot parse LargeData (~a)~%" sn (type-of e))))))
             (when (and (plusp seconds)
                        (> (/ (- (get-internal-real-time) start) internal-time-units-per-second)
                           seconds))
               (return))
             (sleep 0.05))
        (dds.disc:stop-node node)
        (format t "~&[large-sub] stopped; received ~d samples.~%" seen))
      t)))

(defun* run-gated-subscriber (&key (domain 0) (topic "Square") (type-name "C_Shape")
                                   (local-type "shape-type") (seconds 25)
                                   (advertise-address "127.0.0.1"))
    (function (&key (:domain (integer 0)) (:topic string) (:type-name string)
                    (:local-type string) (:seconds (integer 0)) (:advertise-address string)) t)
  "DCPS-level gated live subscriber (FR-TYPE-4, ADR 0010 live DoD): create a
   DomainParticipant (whose disc-node carries the installed %PARTICIPANT-TYPE-GATE),
   bind LOCAL-TYPE's registered type-support under TOPIC / TYPE-NAME, and subscribe.
   Against a stock Connext writer (PID_TYPE_OBJECT_LB 0x8021, no PID_TYPE_INFORMATION)
   the gate inflates + parses the legacy TypeObject and assesses it against LOCAL-TYPE:
   a :compatible verdict matches and delivers samples; an :incompatible verdict joins
   the INCONSISTENT_TOPIC path (no match, no data). Sets DDS.DCPS:*TYPE-COMPAT-LOG* to
   stdout so the gate verdict line is visible. LOCAL-TYPE 'shape-type' is the compatible
   C_Shape; 'shape-mismatch' is the incompatible (shapesize i64) variant. SECONDS 0 =
   forever (Ctrl-C)."
  (unless (dds.types:find-type-support local-type)
    (error "run-gated-subscriber: no registered type-support ~s" local-type))
  (let* ((ts (dds.types:find-type-support local-type))
         (p (dds.dcps:create-participant :domain domain :advertise-address advertise-address)))
    (setf dds.dcps:*type-compat-log* *standard-output*)
    (let* ((tp (dds.dcps:create-topic p topic type-name ts))
           (sub (dds.dcps:create-subscriber p))
           (dr (dds.dcps:create-datareader sub tp :qos (dds.qos:make-reader-qos :reliability :reliable))))
      (format t "~&[gated-sub] ~a/~a local-type=~a domain=~d (multicast 239.255.0.1). Gate verdict + samples below.~%"
              topic type-name local-type domain)
      (let ((fa (dds.types:type-support-field-accessors ts))
            (seen 0) (start (get-internal-real-time)) (matched-reported nil))
        (flet ((field (s name) (funcall (cdr (assoc name fa :test #'string-equal)) s)))
          (unwind-protect
               (loop
                 (dds.dcps:spin p)
                 ;; per-sample guard: parse errors skip the offending sample
                 (dolist (cs (dds.dcps:take-samples dr))
                   (handler-case
                       (let ((s (dds.dcps:cached-sample-data cs)))
                         (incf seen)
                         (format t "~&[gated-sub] sample #~d: color=~a x=~a y=~a shapesize=~a~%"
                                 seen (field s "color") (field s "x") (field s "y")
                                 (field s "shapesize")))
                     (error (e)
                       (format t "~&[gated-sub] skipped undeliverable sample (~a) — gate rejected peer?~%"
                               (type-of e)))))
                 (let ((ms (dds.dcps:matched-count p)))
                   (when (and (plusp ms) (not matched-reported))
                     (setf matched-reported t)
                     (format t "~&[gated-sub] MATCHED ~d remote endpoint(s) (gate verdict :compatible).~%" ms)))
                 (let ((it (dds.dcps:get-inconsistent-topic-status tp)))
                   (when (plusp (dds.dcps:inconsistent-topic-status-total-count it))
                     (format t "~&[gated-sub] INCONSISTENT_TOPIC total=~d (gate verdict :incompatible -> REJECTED, no data).~%"
                             (dds.dcps:inconsistent-topic-status-total-count it))))
                 (when (and (plusp seconds)
                            (> (/ (- (get-internal-real-time) start) internal-time-units-per-second)
                               seconds))
                   (return))
                 (sleep 0.1))
            (let ((it (dds.dcps:get-inconsistent-topic-status tp)))
              (format t "~&[gated-sub] stopped: received ~d sample(s); matched=~d; INCONSISTENT_TOPIC total=~d.~%"
                      seen (dds.dcps:matched-count p)
                      (dds.dcps:inconsistent-topic-status-total-count it)))
            (setf dds.dcps:*type-compat-log* nil)
            (dds.dcps:delete-participant p)))))
    t))

(defun* run-corpus-capture-subscriber (&key (domain 0) (topic "Square") (type "ShapeType")
                                            (seconds 20))
    (function (&key (:domain (integer 0)) (:topic string) (:type string) (:seconds (integer 0)))
              (or null (simple-array (unsigned-byte 8) (*))))
  "Subscribe on TOPIC/TYPE, spin up to SECONDS, and on the first matched remote writer that
   announced a PID_TYPE_OBJECT_LB print it as a Lisp byte vector (for the corpus) and return
   it; NIL if none seen. Clean-room capture: reuses our own SEDP parser, no external dissector."
  (let ((node (dds.disc:make-disc-node :guid-prefix (%make-prefix #x43) :domain domain
                                       :multicast t :advertise-address "127.0.0.1")))
    (dds.disc:add-local-reader node :topic topic :type type
                               :reliability dds.rtps.discovery:+reliability-reliable+
                               :type-information (%shape-type-information))
    (dds.disc:enable-subscriber node)
    (dds.disc:start-node node)
    (format t "~&[corpus] watching ~a/~a domain=~d for a peer PID_TYPE_OBJECT_LB (multicast 239.255.0.1).~%"
            topic type domain)
    (let ((last 0) (start (get-internal-real-time)))
      (unwind-protect
           (loop
             (setf last (%reannounce node last))
             (dolist (w (dds.disc:disc-node-discovered-writers-list node))
               (let ((lb (dds.rtps.discovery:endpoint-data-type-object-lb w)))
                 (when lb
                   (format t "~&;; corpus LB: ~a / ~a (~a octets)~%(~{~a~^ ~})~%"
                           topic type (length lb) (coerce lb 'list))
                   (return-from run-corpus-capture-subscriber
                     (coerce lb '(simple-array (unsigned-byte 8) (*)))))))
             (when (and (plusp seconds)
                        (> (/ (- (get-internal-real-time) start) internal-time-units-per-second)
                           seconds))
               (return))
             (sleep 0.05))
        (dds.disc:stop-node node)
        (format t "~&[corpus] stopped; no PID_TYPE_OBJECT_LB captured.~%"))
      nil)))

(defun* run-typelookup-probe (&key (domain 0) (seconds 15) (advertise-address "127.0.0.1"))
    (function (&key (:domain (integer 0)) (:seconds (integer 1)) (:advertise-address string)) t)
  "FR-IO-2 S4 probe: discover one remote participant on DOMAIN, take the
   EquivalenceHash from its SEDP PID_TYPE_INFORMATION (0x0075), issue a
   TypeLookup getTypes toward it (XTypes 1.3 §7.6.3.3), and report whether the
   returned TypeObject parses (parse-minimal-type-object) and re-hashes
   (equivalence-hash) to the queried hash. Prints PASS/FAIL lines; returns T on
   PASS. SECONDS bounds discovery + reply wait."
  (let ((node (dds.disc:make-disc-node :guid-prefix (%make-prefix #x54) :domain domain
                                       :multicast t :advertise-address advertise-address)))
    ;; a Square reader makes the peer SEDP-announce its Square writer (+ 0x0075) at us
    (dds.disc:add-local-reader node :topic "Square" :type "ShapeType"
                               :reliability dds.rtps.discovery:+reliability-reliable+
                               :type-information (%shape-type-information))
    (dds.disc:enable-subscriber node)
    (dds.disc:start-node node)
    (format t "~&[tl-probe] domain=~d: waiting for a Square writer announcing PID_TYPE_INFORMATION ...~%"
            domain)
    (let ((lock (dds.pal:make-lock "tl-probe"))
          (fired nil) (got-pairs nil) (got-okp nil)
          (last 0) (start (get-internal-real-time)) (passed nil))
      (flet ((expired-p ()
               (> (/ (- (get-internal-real-time) start) internal-time-units-per-second) seconds)))
        (unwind-protect
             (block probe
               (let ((remote nil))
                 ;; phase 1: spin until a remote Square writer carries 0x0075
                 (loop
                   (setf last (%reannounce node last))
                   (dolist (w (dds.disc:disc-node-discovered-writers-list node))
                     (when (and (string= (dds.rtps.discovery:endpoint-data-topic-name w) "Square")
                                (dds.rtps.discovery:endpoint-data-type-information w))
                       (setf remote w)
                       (return)))
                   (when remote (return))
                   (when (expired-p)
                     (format t "~&[tl-probe] FAIL no remote Square writer with PID_TYPE_INFORMATION within ~ds~%"
                             seconds)
                     (return-from probe nil))
                   (sleep 0.05))
                 (let* ((prefix (subseq (dds.rtps.discovery:endpoint-data-guid remote) 0 12))
                        (hash (handler-case
                                  (dds.types:deserialize-type-information-hash
                                   (dds.rtps.discovery:endpoint-data-type-information remote))
                                (error (e)
                                  (format t "~&[tl-probe] FAIL TypeInformation parse: ~a~%" e)
                                  (return-from probe nil)))))
                   (format t "~&[tl-probe] peer ~a announces EK_MINIMAL hash ~a; sending getTypes ...~%"
                           (%hex-prefix prefix) (%octets-hex hash))
                   (dds.disc:type-lookup-query
                    node prefix (list hash)
                    (lambda (pairs okp)
                      ;; fires on the receiver/announce thread: record under OUR lock only
                      (dds.pal:with-lock (lock)
                        (setf got-pairs pairs got-okp okp fired t))))
                   ;; phase 2: keep spinning — the announce cadence drives tl-sweep expiry
                   (loop
                     (setf last (%reannounce node last))
                     (when (dds.pal:with-lock (lock) fired) (return))
                     (when (expired-p)
                       (format t "~&[tl-probe] FAIL no TypeLookup reply within ~ds~%" seconds)
                       (return-from probe nil))
                     (sleep 0.05))
                   (multiple-value-bind (pairs okp)
                       (dds.pal:with-lock (lock) (values got-pairs got-okp))
                     (unless okp
                       (format t "~&[tl-probe] FAIL reply not REMOTE_EX_OK (non-OK / expired / guard)~%")
                       (return-from probe nil))
                     (let ((pair (assoc hash pairs :test #'equalp)))
                       (unless pair
                         (format t "~&[tl-probe] FAIL OK reply lacks the queried hash (~d pair(s) returned)~%"
                                 (length pairs))
                         (return-from probe nil))
                       (let ((parsed (dds.types:parse-minimal-type-object (cdr pair))))
                         (unless (dds.types:minimal-struct-type-p parsed)
                           (format t "~&[tl-probe] FAIL returned TypeObject (~d octets) did not parse: ~a~%"
                                   (length (cdr pair)) parsed)
                           (return-from probe nil))
                         (let ((rehash (dds.types:equivalence-hash parsed)))
                           (cond ((equalp rehash hash)
                                  (format t "~&[tl-probe] PASS getTypes reply: TypeObject ~d octets parses and re-hashes to ~a~%"
                                          (length (cdr pair)) (%octets-hex rehash))
                                  (setf passed t))
                                 (t
                                  (format t "~&[tl-probe] FAIL re-hash mismatch: queried ~a, re-hashed ~a~%"
                                          (%octets-hex hash) (%octets-hex rehash)))))))))))
          (dds.disc:stop-node node)
          (format t "~&[tl-probe] stopped (~:[FAIL~;PASS~]).~%" passed)))
      passed)))

(defun* run-nokey-publisher (&key (domain 0) (rate 5) (count 0)
                                  (advertise-address "127.0.0.1") (peers nil))
    (function (&key (:domain (integer 0)) (:rate (integer 1)) (:count (integer 0))
                    (:advertise-address string) (:peers (or null string))) t)
  "Publish NoKeyData (a,b) on topic 'NoKeyTopic' / type 'nokey-data' via the DCPS
   path, so the topic type's keyed-ness (NIL) selects the NO_KEY writer kind 0x03
   (RTPS 2.5 §9.3.1.2). Proves the live no-key OUT direction against a Connext
   keyless reader. RATE updates/sec; COUNT 0 = forever (Ctrl-C). PEERS is an optional
   \"host:port[,host:port]\" list of unicast SPDP announce targets (FR-DISC-4) on top
   of multicast — e.g. \"127.0.0.1:7410\" reaches a same-host peer over loopback when
   the macOS application firewall silently drops LAN-sourced UDP for an unapproved
   peer binary."
  (let* ((ts (dds.types:find-type-support "nokey-data"))
         (p (dds.dcps:create-participant :domain domain :advertise-address advertise-address
                                         :peers (%parse-peers peers))))
    (unless ts (error "run-nokey-publisher: no registered type-support \"nokey-data\""))
    (let* ((tp (dds.dcps:create-topic p "NoKeyTopic" "nokey-data" ts))
           (pub (dds.dcps:create-publisher p))
           (dw (dds.dcps:create-datawriter pub tp
                                           :qos (dds.qos:make-writer-qos :reliability :reliable))))
      (format t "~&[nokey-pub] NoKeyTopic/nokey-data domain=~d (NO_KEY writer 0x03, multicast 239.255.0.1). Ctrl-C to stop.~%"
              domain)
      (let ((period (/ 1.0 rate)) (n 0))
        (unwind-protect
             (loop
               (dds.dcps:spin p)
               (incf n)
               (dds.dcps:write-sample dw (make-nokey-data :a n :b (* n 10)))
               (when (zerop (mod n 5))
                 (format t "~&[nokey-pub] sent ~d samples; matched=~d~%" n (dds.dcps:matched-count p)))
               (when (and (plusp count) (>= n count)) (return))
               (sleep period))
          (format t "~&[nokey-pub] stopped after ~d samples; matched=~d.~%" n (dds.dcps:matched-count p))
          (dds.dcps:delete-participant p))))
    t))

(defun* run-nokey-subscriber (&key (domain 0) (seconds 0) (advertise-address "127.0.0.1") (peers nil))
    (function (&key (:domain (integer 0)) (:seconds (integer 0)) (:advertise-address string) (:peers (or null string))) t)
  "Subscribe to NoKeyData on topic 'NoKeyTopic' / type 'nokey-data' via the DCPS
   path, so the topic type's keyed-ness (NIL) selects the NO_KEY reader kind 0x04
   (RTPS 2.5 §9.3.1.2). Proves the live no-key IN direction from a Connext keyless
   writer. SECONDS 0 = forever (Ctrl-C). PEERS is an optional \"host:port[,host:port]\"
   list of unicast SPDP announce targets (FR-DISC-4) on top of multicast — e.g.
   \"127.0.0.1:7410\" reaches a same-host peer over loopback when the macOS application
   firewall silently drops LAN-sourced UDP for an unapproved peer binary."
  (let* ((ts (dds.types:find-type-support "nokey-data"))
         (p (dds.dcps:create-participant :domain domain :advertise-address advertise-address
                                         :peers (%parse-peers peers))))
    (unless ts (error "run-nokey-subscriber: no registered type-support \"nokey-data\""))
    (let* ((tp (dds.dcps:create-topic p "NoKeyTopic" "nokey-data" ts))
           (sub (dds.dcps:create-subscriber p))
           (dr (dds.dcps:create-datareader sub tp
                                           :qos (dds.qos:make-reader-qos :reliability :reliable))))
      (format t "~&[nokey-sub] NoKeyTopic/nokey-data domain=~d (NO_KEY reader 0x04, multicast 239.255.0.1). Ctrl-C to stop.~%"
              domain)
      (let ((seen 0) (start (get-internal-real-time)) (matched-reported nil))
        (unwind-protect
             (loop
               (dds.dcps:spin p)
               (dolist (cs (dds.dcps:take-samples dr))
                 (handler-case
                     (let ((s (dds.dcps:cached-sample-data cs)))
                       (incf seen)
                       (format t "~&[nokey-sub] sample #~d: a=~d b=~d~%"
                               seen (nokey-data-a s) (nokey-data-b s)))
                   (error (e)
                     (format t "~&[nokey-sub] skipped undeliverable sample (~a)~%" (type-of e)))))
               (let ((ms (dds.dcps:matched-count p)))
                 (when (and (plusp ms) (not matched-reported))
                   (setf matched-reported t)
                   (format t "~&[nokey-sub] MATCHED ~d remote endpoint(s) (no-key pair).~%" ms)))
               (when (and (plusp seconds)
                          (> (/ (- (get-internal-real-time) start) internal-time-units-per-second)
                             seconds))
                 (return))
               (sleep 0.1))
          (format t "~&[nokey-sub] stopped; received ~d sample(s); matched=~d.~%"
                  seen (dds.dcps:matched-count p))
          (dds.dcps:delete-participant p))))
    t))
