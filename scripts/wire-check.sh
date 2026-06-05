#!/usr/bin/env bash
# make wire — validate the project's RTPS wire output against the Wireshark/tshark
# RTPS dissector, the SAME reference dissector used to validate Connext interop
# (CLAUDE.md §4: "the wire is the oracle"). Builds a pcap from the project codecs
# (tools/rtps-pcap.lisp) and asserts the dissector parses every submessage shape
# with no Unknown encapsulation and no Malformed marker. This is a necessary (not
# sufficient) condition for M2 Connext interop. Skips cleanly if tshark is absent.
set -euo pipefail
cd "$(dirname "${BASH_SOURCE[0]}")/.."

TS=""
for c in tshark /Applications/Wireshark.app/Contents/MacOS/tshark; do
  if command -v "$c" >/dev/null 2>&1; then TS="$c"; break; fi
  [[ -x "$c" ]] && { TS="$c"; break; }
done
if [[ -z "$TS" ]]; then echo "wire: SKIP — tshark not found (install Wireshark to validate)"; exit 0; fi

# Use a clean Wireshark config dir so the gate is immune to the user's local
# profile (a stray ~/.config/wireshark/disabled_protos can globally disable
# dissection — exactly the kind of environment trap that produces false failures).
WSCFG="$(mktemp -d)"
export WIRESHARK_CONFIG_DIR="$WSCFG"
trap 'rm -rf "$WSCFG"' EXIT

PCAP=/tmp/rtps_wire.pcap
if ! sbcl --non-interactive --load tools/rtps-pcap.lisp >/dev/null 2>&1; then
  echo "wire: FAIL — pcap generation (tools/rtps-pcap.lisp)"; exit 1
fi

OUT="$("$TS" -r "$PCAP" -O rtps 2>/dev/null)"
SUM="$("$TS" -r "$PCAP" -Y rtps 2>/dev/null)"
BOTH="$OUT
$SUM"

fail=0
have() { if grep -qiE -e "$1" <<<"$BOTH"; then echo "  ok    $2"; else echo "  FAIL  $2"; fail=1; fi; }
lack() { if grep -qiE -e "$1" <<<"$OUT";  then echo "  FAIL  $2"; fail=1; else echo "  ok    $2"; fi; }

have 'Magic: RTPS'                          'RTPS magic recognized'
have 'DATA\(p\)'                            'SPDP participant DATA (DATA(p))'
have '-> Square'                            'SEDP PID_TOPIC_NAME extracted (-> Square)'
have 'submessageId: HEARTBEAT'              'HEARTBEAT submessage'
have 'submessageId: ACKNACK'                'ACKNACK submessage + SequenceNumberSet'
have 'CDR2_LE \(0x0007\)'                   'XCDR2 encapsulation = CDR2_LE (0x0007)'
have 'PL_CDR_LE \(0x0003\)'                 'discovery encapsulation = PL_CDR_LE (0x0003)'
have 'ENTITYID_BUILTIN_PARTICIPANT_WRITER'  'SPDP builtin writer EntityId recognized'
lack 'encapsulation kind: Unknown'          'no Unknown encapsulation kind'
lack 'Malformed'                            'no Malformed submessage'

if [[ $fail -ne 0 ]]; then
  echo "wire: FAIL — the RTPS dissector rejected something above"; exit 1
fi
echo "wire: PASS — tshark RTPS dissector validates every submessage shape"
