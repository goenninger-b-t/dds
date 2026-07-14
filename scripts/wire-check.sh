#!/usr/bin/env bash
# make wire — validate the project's RTPS wire output against the Wireshark/tshark
# RTPS dissector, the SAME reference dissector used to validate Connext interop
# (the operating contract §4: "the wire is the oracle"). Builds a pcap from the project codecs
# (tools/rtps-pcap.lisp) and asserts the dissector parses every submessage shape
# with no Unknown encapsulation and no Malformed marker. This is a necessary (not
# sufficient) condition for M2 Connext interop. Skips cleanly if tshark is absent.
set -euo pipefail
cd "$(dirname "${BASH_SOURCE[0]}")/.."

TS=""
# TSHARK_BIN, when set, is the ONLY candidate — it overrides the search rather than being prepended to
# it. That is what makes this gate falsifiable: point it at a nonexistent path and the gate MUST go red
# rather than pass vacuously. (Prepending would silently fall through to the real tshark and the
# falsification would prove nothing — which is exactly the class of mistake this gate exists to catch.)
CANDIDATES=(tshark /Applications/Wireshark.app/Contents/MacOS/tshark)
[[ -n "${TSHARK_BIN:-}" ]] && CANDIDATES=("$TSHARK_BIN")
for c in "${CANDIDATES[@]}"; do
  if command -v "$c" >/dev/null 2>&1; then TS="$c"; break; fi
  [[ -x "$c" ]] && { TS="$c"; break; }
done
if [[ -z "$TS" ]]; then
  # A gate that CANNOT RUN must not report success. This used to `exit 0` on a missing tshark, so on any
  # machine without Wireshark `make wire` — and `make interop`, which depends on it — passed VACUOUSLY,
  # validating nothing while printing a green line. That is the same permanently-green failure mode as the
  # make-corpus stub and the ql:quickload-blinded build gate.
  echo "wire: FAIL — tshark not found; this gate cannot validate anything without it." >&2
  echo "      Install Wireshark, or set WIRE_ALLOW_MISSING_TSHARK=1 to DELIBERATELY skip (exits 0)." >&2
  [[ "${WIRE_ALLOW_MISSING_TSHARK:-}" == "1" ]] && { echo "wire: SKIPPED BY REQUEST (WIRE_ALLOW_MISSING_TSHARK=1) — NOT validated." >&2; exit 0; }
  exit 1
fi

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
# TypeLookup dissection is a DISSECTOR CAPABILITY, not a property of our bytes: older tshark builds do not
# know the TypeLookup service at all. Ubuntu's Wireshark (~4.2) does not; 4.6 does. Probing the dissector —
# rather than pinning a version — is the honest test: if THIS tshark cannot name TypeLookup on ANY input, it
# cannot judge ours, so the check is SKIPPED and SAID SO. It is never silently dropped, and it never passes
# vacuously: every other check still runs, including 'no Malformed submessage'.
if "$TS" -G fields 2>/dev/null | grep -qi 'typelookup\|type.lookup'; then
  have 'ENTITYID_TL_SVC_REQ_WRITER'           'TypeLookup builtin EntityIds recognized'
  have 'Type Lookup Request'                  'TypeLookup_Request payload dissected (CDR2_LE)'
  have 'Type Lookup Reply'                    'TypeLookup_Reply payload dissected (CDR2_LE)'
else
  echo "  SKIP  TypeLookup checks (3) — this tshark's RTPS dissector does not know TypeLookup at all," >&2
  echo "        so it cannot judge ours. NOT validated here. Install Wireshark >= 4.6 to cover them." >&2
fi
lack 'encapsulation kind: Unknown'          'no Unknown encapsulation kind'
lack 'Malformed'                            'no Malformed submessage'

if [[ $fail -ne 0 ]]; then
  echo "wire: FAIL — the RTPS dissector rejected something above"; exit 1
fi
echo "wire: PASS — tshark RTPS dissector validates every submessage shape"
