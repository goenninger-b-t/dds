(in-package #:dds.tests)

;;; Native UDPv4 PAL loopback (FR-XPORT-1): bind a receiver, send a datagram from
;;; a second socket to 127.0.0.1:<rx-port>, receive it, verify the octets. Uses
;;; each implementation's own sb-bsd-sockets; no portability library.

(defun* run-udp-loopback-test ()
    (function () t)
  "Test: the UDPv4 PAL sends and receives a datagram over loopback — under BOTH send mechanisms.

   THIS TEST IS THE FALSIFIER FOR THE struct sockaddr_in LAYOUT (ADR 0065) AND FOR THE RAW recvfrom(2)
   PATH (ADR 0066). The raw arm builds the destination address in our own foreign block and calls
   sendto(2)/recvfrom(2) directly; the NIL arm takes the sb-bsd-sockets SOCKET-SEND / SOCKET-RECEIVE
   path. The sockaddr_in layouts differ between Darwin and Linux in their first two octets, and getting
   them wrong is not a crash — the kernel rejects the address family and the datagram silently goes
   nowhere. Asserting DELIVERY under the raw arm is what turns that into a loud, platform-specific
   failure; CI/Linux is the oracle for the non-Darwin branch, which macOS cannot see.

   Runs on the test runner's own thread, which the PAL did not spawn, so *THREAD-SOCKADDR* is NIL and
   this exercises UDP-SEND-TO's WITH-FOREIGN-OBJECT fallback; the per-thread fast path is exercised by
   every integration test (a receiver thread answers each HEARTBEAT with an ACKNACK)."
  (let ((rx (dds.pal:udp-open :host "127.0.0.1" :port 0)))
    (unwind-protect
        (let ((tx (dds.pal:udp-open :host "127.0.0.1" :port 0))
              ;; PAL-static both ways: the kernel reads OUT and writes IN by raw pointer (NFR-MEM).
              (out (dds.pal:alloc-static 4))
              (in (dds.pal:alloc-static 16)))
          (replace out #(#xde #xad #xbe #xef))
          (unwind-protect
              (let ((port (dds.pal:udp-local-port rx)))
                (dolist (raw '(t nil))
                  (let ((dds.pal:*udp-raw-sendto* raw)
                        (dds.pal:*udp-raw-recvfrom* raw))
                    (fill in 0)
                    (dds.pal:udp-send-to tx out 4 "127.0.0.1" port)
                    (sleep 0.2)
                    (multiple-value-bind (n addr sport) (dds.pal:udp-recv rx in 4)
                      (declare (ignore addr sport))
                      (%check (if raw :udp-loopback-raw-syscalls :udp-loopback)
                              (and (= n 4) (= (aref in 0) #xde) (= (aref in 1) #xad)
                                   (= (aref in 2) #xbe) (= (aref in 3) #xef))
                              (format nil "UDP loopback datagram round-trip (raw syscalls ~a)"
                                      raw))))))
            (dds.pal:free-static out)
            (dds.pal:free-static in)
            (dds.pal:udp-close tx)))
      (dds.pal:udp-close rx))
    t))
