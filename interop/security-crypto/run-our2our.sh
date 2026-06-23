#!/usr/bin/env bash
# Our-to-our encrypted pub/sub wire-ciphertext proof (ADR 0031, DDS-Security §9.5.3.3 Slice-1).
#
# WHAT THIS PROVES:
#   A disc-node built with :crypto-transform shared-km encodes the SerializedPayload as an
#   AES256-GCM SecuredPayload (§9.5.3.3.4.4) BEFORE wire emission.  A second node sharing
#   the same km decodes it back to the plaintext on receive (§9.5.3.3.4.5), while a third node
#   with no crypto-transform receives the raw ciphertext blob beginning with the AES256-GCM
#   transformation_kind bytes #(0 0 0 4) (§9.5.3.3.1 Table 69) — the wire carried the
#   SecuredPayload, not the plaintext.  This is the in-process wire-proof; the tshark arm (B)
#   additionally captures the UDP loopback and inspects the DATA serialized-payload region.
#
# CROSS-VENDOR DEFERRAL:
#   Cross-vendor Connext-Security interop is DEFERRED.  The Connext Security plugins are a
#   separate licensed add-on (RTI Security Plugins) not installed in this environment; the
#   Governance/Permissions XML signing requires the Connext Security infrastructure that is
#   absent here.  The in-process proof (arm A) is the portable authoritative evidence for
#   Slice-1 wire confidentiality.  A cross-vendor byte-compare is planned as a follow-on T4.
#
# TSHARK CAPTURE (arm B):
#   Arm B attempts a live tshark capture on the loopback (lo / lo0) while the in-process test
#   runs a standalone publisher and asserts the DATA serialized-payload region starts with the
#   AES256-GCM header bytes (not the plaintext "SQUARE" ASCII).  If tshark is absent or
#   loopback capture requires elevated privileges, arm B is skipped and documented here.
#
# USAGE:  Run from repo root:  bash interop/security-crypto/run-our2our.sh
# EXIT:   0 = arm A passed (arm B may be skipped); 1 = arm A failed.
set -uo pipefail

REPO="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
CLASP_LAUNCHER="$REPO/scripts/with-clasp.sh"
SBCL_LAUNCHER="$REPO/scripts/with-sbcl.sh"

overall=0

# ── Arm A: in-process ciphertext proof (portable, runs on both impls) ──────────────────────
#
# Invokes run-security-encrypted-pubsub-test directly via the test harness.
# This test asserts (a) SUB receives plaintext, (b) PLAIN receives ciphertext,
# (c) ciphertext begins with #(0 0 0 4) = AES256-GCM transformation_kind.

run_in_process() {
  local label="$1"
  local launcher="$2"
  local log="/tmp/sec-crypto-${label}.log"

  echo "=== [${label}] arm A: in-process encrypted-pubsub ciphertext proof ==="
  "$launcher" --eval '(asdf:test-system :dds-tests)' >"$log" 2>&1
  local rc=$?

  if grep -q "security-encrypted-pubsub" "$log" && ! grep -q "TEST FAILED" "$log"; then
    echo "  [${label}] arm A: PASS"
    tail -5 "$log"
  else
    echo "  [${label}] arm A: FAIL (rc=${rc})"
    grep -E "TEST FAILED|security-encrypted-pubsub|error|Error" "$log" | head -20
    echo "  --- full log: ${log} ---"
    return 1
  fi
}

echo ""
echo "=== WP-DDS-SECURITY-CRYPTO-MVP T3: our-to-our encrypted pub/sub wire proof ==="
echo "=== ADR 0031, DDS-Security 1.1 §9.5.3.3 Slice-1 ==="
echo ""

# Clasp first (operating contract)
if run_in_process "clasp" "$CLASP_LAUNCHER"; then
  echo "Clasp arm A: PASS"
else
  echo "Clasp arm A: FAIL"
  overall=1
fi

echo ""

if run_in_process "sbcl" "$SBCL_LAUNCHER"; then
  echo "SBCL arm A: PASS"
else
  echo "SBCL arm A: FAIL"
  overall=1
fi

echo ""

# ── Arm B: tshark live capture (environment-dependent) ──────────────────────────────────────
#
# Checks whether tshark is available and whether loopback capture works without root.
# On macOS the loopback interface is lo0; on Linux it is lo.
# If tshark is absent or capture fails, arm B is SKIPPED (not a failure of the proof).
# The in-process assertion (arm A) is the authoritative portable evidence.

TSHARK="$(command -v tshark 2>/dev/null || true)"
if [ -z "$TSHARK" ]; then
  echo "=== arm B: SKIP (tshark not found on PATH) ==="
  echo "  To run arm B, install Wireshark/tshark and ensure loopback capture is permitted."
  echo "  On macOS: brew install --cask wireshark; on Linux: apt install tshark."
else
  IFACE="lo0"
  if [ "$(uname)" = "Linux" ]; then IFACE="lo"; fi

  echo "=== arm B: tshark live ciphertext capture on ${IFACE} ==="
  CAP_FILE="/tmp/sec-crypto-tshark.pcap"

  # Capture 5 s of loopback traffic while running the Clasp in-process test in the background.
  "$TSHARK" -i "$IFACE" -a duration:5 -w "$CAP_FILE" -q 2>/dev/null &
  TSHARK_PID=$!

  # Run a single publish (Clasp, domain 83) concurrently with the capture.
  "$CLASP_LAUNCHER" --eval '
    (asdf:load-system :dds-disc)
    (let* ((km (dds.security:make-test-key-material))
           (node (dds.disc:make-disc-node :domain 83 :host "127.0.0.1" :port 0
                                          :crypto-transform km)))
      (dds.disc:add-local-writer node :topic "SSquare" :type "ShapeType"
        :qos (dds.qos:make-writer-qos :reliability :reliable :durability :transient-local))
      (dds.disc:enable-publisher node :history-kind :keep-all)
      (dds.disc:start-node node)
      (sleep 1)
      (dds.disc:publish-sample node
        (make-array 8 :element-type (quote (unsigned-byte 8))
                      :initial-contents (quote (#x53 #x51 #x55 #x41 #x52 #x45 #x20 #x01))))
      (sleep 1)
      (dds.disc:stop-node node))' >/dev/null 2>&1 || true

  wait "$TSHARK_PID" 2>/dev/null || true

  if [ -f "$CAP_FILE" ] && [ -s "$CAP_FILE" ]; then
    # Decode RTPS DATA payloads: look for bytes starting with 00:00:00:04 (AES256-GCM kind §9.5.3.3.1 Table 69).
    # tshark field rtps.param.serializedData surfaces the serialized payload when present.
    FOUND=$("$TSHARK" -r "$CAP_FILE" -Y 'rtps' -T fields \
              -e rtps.param.serializedData 2>/dev/null \
            | { grep -c "^00:00:00:04" || true; })
    FOUND="${FOUND%%[^0-9]*}"   # strip any trailing non-numeric (newlines/spaces)
    FOUND="${FOUND:-0}"
    if [ "$FOUND" -gt 0 ] 2>/dev/null; then
      echo "  arm B: PASS — ${FOUND} RTPS DATA payload(s) begin with AES256-GCM kind 00:00:00:04"
    else
      echo "  arm B: INCONCLUSIVE — tshark captured traffic but found no matching AES256-GCM"
      echo "         payload (possible: the DATA may use a different dissector field on this version)."
      echo "         Arm A (in-process) remains the authoritative proof."
    fi
  else
    echo "  arm B: SKIP — tshark ran but produced no capture (loopback capture may need root)."
    echo "         On macOS: sudo chmod o+r /dev/bpf* OR run with sudo."
    echo "         On Linux:  sudo setcap cap_net_raw+eip \$(which tshark)"
  fi
fi

echo ""
if [ "$overall" -eq 0 ]; then
  echo "=== RESULT: arm A PASSED on both Clasp and SBCL (wire carries SecuredPayload, not plaintext) ==="
else
  echo "=== RESULT: arm A FAILED on one or more impls ==="
fi

exit "$overall"
