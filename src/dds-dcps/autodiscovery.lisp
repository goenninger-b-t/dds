;;;; WP-DCPS-API-COMPLETION S7 — the autonomous-discovery announcer.
;;;; CONTROL-PLANE (not the measured hot path): a per-participant background thread that periodically
;;;; drives the spin body (%spin-once — SPDP + SEDP announce + the lease/liveliness/autopurge sweeps) so a
;;;; participant in AUTONOMOUS mode discovers, matches, and ages peers with NO app-driven spin. Inbound
;;;; discovery (SPDP/SEDP receive + matching) already runs on the disc-node's receiver thread; this adds
;;;; the periodic ANNOUNCE + aging drive that spin does manually. Mirrors the S4 deadline-monitor lifecycle
;;;; exactly: LOCK + CV + RUNNING flag; spawned on enable (when autonomous); stopped + JOINED on
;;;; delete-participant BEFORE the node/buffers are torn down (no strand, no use-after-free). The announcer
;;;; OWNS the node's announce send buffers (tx-msg/tx-payload) — so spin is a no-op in autonomous mode (a
;;;; concurrent spin would race those buffers). A non-autonomous participant never creates the thread.

(in-package #:dds.dcps)

(defstruct* (auto-announcer (:constructor %make-auto-announcer))
  "The per-participant autonomous-discovery announcer (DDS 1.4 §2.2.2.2 / RTPS 2.5 §8.5 SPDP/SEDP): a
   background thread (THREAD) that, while RUNNING, drives one %spin-once cycle then waits on CV for
   PERIOD-SECONDS (the announce cadence) or until stopped. LOCK guards RUNNING, PERIOD-SECONDS, and the CV.
   Created + started once on enable when the participant is autonomous; stopped + JOINED on
   delete-participant. PERIOD-SECONDS comes from the participant's DISCOVERY_CONFIG announce-period QoS
   (default {1,0} = 1 s) and is CHANGEABLE: set_qos writes it under the lock and signals the CV, so a
   waiting thread re-waits on the new cadence (%apply-discovery-cadence)."
  (lock (dds.pal:make-lock "auto-announcer") :type t)
  (cv (dds.pal:make-condvar) :type t)
  (thread nil :type t)
  (running nil :type boolean)
  (period-seconds 1.0d0 :type double-float))

(declaim (ftype (function (auto-announcer domain-participant) t) %auto-announcer-loop))

(defun* %participant-discovery-qos (p)
    (function (domain-participant) dds.qos:qos)
  "P's effective QoS as a dds.qos:qos — the DISCOVERY_CONFIG source (announce period + announced lease).
   A participant created with no QoS reports the defaults ({1,0} period / {100,0} lease)."
  (let ((q (entity-qos p)))
    (if (typep q 'dds.qos:qos) q (dds.qos:make-qos))))

(defun* %announce-period-seconds (p)
    (function (domain-participant) double-float)
  "P's DISCOVERY_CONFIG announce period in seconds (the announcer's SPDP/SEDP cadence). A non-positive or
   INFINITE period is meaningless for a cadence, so it falls back to the {1,0} default — the QoS consistency
   validator rejects such a QoS up front (INCONSISTENT_POLICY); this is the belt-and-braces floor for a
   participant whose QoS was never routed through set_qos."
  (let ((s (dds.qos:duration->seconds
            (dds.qos:qos-discovery-announce-period (%participant-discovery-qos p)))))
    (if (and (plusp s) (< s most-positive-double-float)) s 1.0d0)))

(defun* %apply-discovery-cadence (p)
    (function (domain-participant) t)
  "Apply P's DISCOVERY_CONFIG QoS (WP-DCPS-API-COMPLETION S7): push the announced leaseDuration onto the
   disc-node (every subsequent SPDP announce carries it — PID_PARTICIPANT_LEASE_DURATION, RTPS 2.5
   §8.5.3.3.2) and the announce period onto a RUNNING announcer, signalling its CV UNDER the lock so the
   thread wakes and re-waits on the NEW cadence instead of finishing the old (possibly much longer) one.
   Called at create-participant and again from set_qos — both policies are CHANGEABLE, so a live
   re-configure takes effect on the next announce, not at the next restart."
  (let* ((qos (%participant-discovery-qos p))
         (lease (dds.qos:qos-discovery-lease-duration qos))
         (node (dp-node p))
         (a (dp-announcer p)))
    (setf (dds.disc:disc-node-lease-duration-seconds node)
          (if (dds.qos:duration-infinite-p lease)
              #x7fffffff
              (dds.qos:qos-duration-sec lease)))
    (setf (dds.disc:disc-node-lease-duration-nanosec node)
          (if (dds.qos:duration-infinite-p lease) 0 (dds.qos:qos-duration-nanosec lease)))
    (when a
      (dds.pal:with-lock ((auto-announcer-lock a))
        (setf (auto-announcer-period-seconds a) (%announce-period-seconds p))
        (dds.pal:condvar-signal (auto-announcer-cv a)))))
  t)

(defun* %start-auto-announcer (p)
    (function (domain-participant) t)
  "Start P's autonomous-discovery announcer thread — iff P is in autonomous mode, ENABLED, and not already
   running (idempotent: safe to call from both create-participant and enable). The thread periodically
   drives %spin-once (SPDP/SEDP announce + aging + liveliness + autopurge), so P needs no app-driven spin.
   Guarded by the participant deadline-lock (the participant's single lazy-thread-creation lock, shared with
   the deadline monitor — the two never contend, both are one-shot creations). A non-autonomous participant
   never reaches the spawn."
  (when (and (dp-autonomous-p p) (entity-enabled-p p) (null (dp-announcer p)))
    (dds.pal:with-lock ((dp-deadline-lock p))
      (unless (dp-announcer p)
        (let ((a (%make-auto-announcer :period-seconds (%announce-period-seconds p))))
          (setf (auto-announcer-running a) t)
          (setf (auto-announcer-thread a)
                (dds.pal:spawn (lambda () (%auto-announcer-loop a p)) :name "dds-autodiscovery"))
          (setf (dp-announcer p) a)))))
  t)

(defun* %stop-auto-announcer (p)
    (function (domain-participant) (values t (or null keyword)))
  "Stop + JOIN P's autonomous announcer thread (on delete-participant), BEFORE the node/buffers are torn
   down — the clean-shutdown discipline (no strand, no use-after-free: the thread is joined while the node
   + its announce buffers are still live). Sets RUNNING NIL and signals the CV UNDER the announcer lock (so
   a thread about to wait sees the flag — no lost wakeup), then joins BOUNDED. Null-safe + idempotent (a
   non-autonomous participant has no announcer).

   Returns (values T NIL) when the announcer is provably gone, (values NIL :TIMEOUT) when it is not.
   ⚠️ THE STATUS GATES DELETE-PARTICIPANT'S TEARDOWN (ADR 0092). This thread's %SPIN-ONCE builds and SENDS
   SPDP/SEDP announcements THROUGH THE NODE'S announce buffers, so an unproven stop followed by STOP-NODE's
   FREE-STATIC is a use-after-free on static memory by a thread that is still publishing. On :TIMEOUT the
   caller MUST leave the node standing and leave the participant retryable; the announcer slot is likewise
   NOT cleared, so a later delete re-attempts the join instead of forgetting the thread exists."
  (let ((a (dp-announcer p)))
    (when a
      (dds.pal:with-lock ((auto-announcer-lock a))
        (setf (auto-announcer-running a) nil)
        (dds.pal:condvar-signal (auto-announcer-cv a)))
      (let ((th (auto-announcer-thread a)))
        (when th
          (multiple-value-bind (r status) (dds.pal:join-bounded th :dcps-auto-announcer)
            (declare (ignore r))
            (when status (return-from %stop-auto-announcer (values nil status))))))
      (setf (dp-announcer p) nil)))
  (values t nil))

(defun* %auto-announcer-loop (a p)
    (function (auto-announcer domain-participant) t)
  "The announcer thread body (DDS 1.4 §2.2.2.2, RTPS 2.5 §8.5.3 SPDP cadence). Announce FIRST (so a fresh
   autonomous participant advertises promptly), then under the lock re-check RUNNING and wait on CV for the
   announce period; a stop (%stop-auto-announcer) sets RUNNING NIL + signals under the same lock, so the
   waiting thread wakes, re-checks, and exits (no lost wakeup). Each %spin-once is guarded — a transient
   send error (a wedged socket) must not kill autonomous discovery; the next cycle retries. Exits when
   RUNNING goes NIL (delete-participant); the in-flight %spin-once completes before join returns, so the
   node/buffers it touches are never freed under it."
  (loop named outer do
    (handler-case (%spin-once p) (error () nil))
    (dds.pal:with-lock ((auto-announcer-lock a))
      (unless (auto-announcer-running a) (return-from outer t))
      (dds.pal:condvar-wait (auto-announcer-cv a) (auto-announcer-lock a)
                            (auto-announcer-period-seconds a))
      (unless (auto-announcer-running a) (return-from outer t)))))
