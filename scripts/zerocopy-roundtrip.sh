#!/usr/bin/env bash
# WP-ZEROCOPY Phase E2 — REAL two-OS-process cross-process Zero-Copy round-trip (FR-PF-3, ADR 0014).
# NOT cleared for ship — pending counsel (R6); see ADR 0014.
# The wire/shared-memory is the oracle (the operating contract section 4): two SEPARATE SBCL processes on
# THIS host get the same host-uuid (MD5 of hostname) and, with *zerocopy-enabled* T, each brings up a
# per-writer SHMEM sample-pool. After they discover over loopback UDP (deterministic domain-derived ports +
# :peers, no multicast so the macOS app-firewall LAN-UDP drop is irrelevant), the publisher places each LARGE
# LargeData sample (> the ZC threshold) into its pool and sends only a 16-byte REFERENCE; the subscriber
# resolves it against the writer's pool CROSS-PROCESS and verifies the payload byte-exact. Proof = the sub
# received the samples (byte-exact) AND the pub's disc-node-zc-sends > 0 (i.e. a reference, not the
# fragmented payload, crossed the OS-process boundary). SBCL only: the by-name SHMEM attach the pool relies
# on is reliable on SBCL everywhere + Clasp/Linux; Clasp/macOS falls back (ADR 0013), so this harness pins
# SBCL and a non-default domain to dodge stray peers.
set -euo pipefail
cd "$(dirname "${BASH_SOURCE[0]}")/.."

DOMAIN="${DOMAIN:-9}"           # non-default domain => distinct ports, fewer stray peers
COUNT="${COUNT:-24}"            # large samples the pub publishes
SIZE="${SIZE:-4000}"           # payload octets per sample (> *zerocopy-min-payload-bytes* = 1024)
THRESHOLD="${THRESHOLD:-8}"    # byte-exact samples the sub must receive to PASS
DEADLINE="${DEADLINE:-60}"     # seconds before a hung process is killed (fail, not wedge)
SBCL="./scripts/with-sbcl.sh"

SUBOUT="$(mktemp -t zc-sub.XXXXXX)"
PUBOUT="$(mktemp -t zc-pub.XXXXXX)"
SUBPID=""
PUBPID=""
cleanup() {
  [[ -n "$PUBPID" ]] && kill "$PUBPID" 2>/dev/null || true
  [[ -n "$SUBPID" ]] && kill "$SUBPID" 2>/dev/null || true
  rm -f "$SUBOUT" "$PUBOUT"
}
trap cleanup EXIT

# Clear any straggler holding our two loopback discovery ports (PB+DG*domain+d1+PG*pid:
# domain 9 => sub 9660 / pub 9662) so a stale process never poisons fresh discovery.
P_SUB=$(( 7400 + 250 * DOMAIN + 10 ))
P_PUB=$(( 7400 + 250 * DOMAIN + 10 + 2 ))
if command -v lsof >/dev/null 2>&1; then
  for p in "$P_SUB" "$P_PUB"; do
    while read -r pid; do
      [[ -n "$pid" ]] && { echo "zc-xproc: killing straggler pid $pid on UDP $p"; kill "$pid" 2>/dev/null || true; }
    done < <(lsof -nP -iUDP:"$p" -t 2>/dev/null || true)
  done
fi

echo "zc-xproc: domain=$DOMAIN count=$COUNT size=$SIZE threshold=$THRESHOLD deadline=${DEADLINE}s (loopback :peers, no multicast; SBCL Zero-Copy; NOT cleared for ship — R6)"

# --- subscriber: own OS process, bound to the deterministic sub port, :peers at the pub
"$SBCL" --eval '(asdf:load-system :dds-shapes)' \
        --eval "(uiop:symbol-call :dds.shapes :run-zc-xproc-sub :domain $DOMAIN :threshold $THRESHOLD :size $SIZE :seconds $((DEADLINE - 5)))" \
        >"$SUBOUT" 2>&1 &
SUBPID=$!

# wait (bounded) for the sub to print its bind line before launching the pub
for _ in $(seq 1 100); do
  grep -q '\[zc-sub\]' "$SUBOUT" 2>/dev/null && break
  kill -0 "$SUBPID" 2>/dev/null || break
  sleep 0.1
done

# --- publisher: own OS process, bound to the deterministic pub port, :peers at the sub
"$SBCL" --eval '(asdf:load-system :dds-shapes)' \
        --eval "(uiop:symbol-call :dds.shapes :run-zc-xproc-pub :domain $DOMAIN :count $COUNT :size $SIZE :match-timeout $((DEADLINE - 20)))" \
        >"$PUBOUT" 2>&1 &
PUBPID=$!

# --- bounded wait for BOTH to exit; kill (fail) if the deadline passes (no wedge)
waited=0
while kill -0 "$SUBPID" 2>/dev/null || kill -0 "$PUBPID" 2>/dev/null; do
  if (( waited >= DEADLINE )); then
    echo "zc-xproc: DEADLINE ${DEADLINE}s exceeded — killing processes (FAIL: hang)"
    kill "$PUBPID" "$SUBPID" 2>/dev/null || true
    break
  fi
  sleep 1
  waited=$(( waited + 1 ))
done
wait "$SUBPID" 2>/dev/null || true
SUB_RC=$?
wait "$PUBPID" 2>/dev/null || true
PUB_RC=$?

echo "----- subscriber output -----"; cat "$SUBOUT"
echo "----- publisher output ------"; cat "$PUBOUT"
echo "-----------------------------"

# --- assert: sub RECEIVED >= threshold (byte-exact) AND pub ZC-SENDS > 0 (a reference carried the data)
SUB_LINE="$(grep -E '^ZC-SUB-RECEIVED: [0-9]+' "$SUBOUT" | tail -1 || true)"
PUB_LINE="$(grep -E '^ZC-PUB-SENDS: [0-9]+ / [0-9]+' "$PUBOUT" | tail -1 || true)"
RECVD="$(sed -nE 's/^ZC-SUB-RECEIVED: ([0-9]+).*/\1/p' <<<"$SUB_LINE")"
SENDS="$(sed -nE 's/^ZC-PUB-SENDS: ([0-9]+) .*/\1/p' <<<"$PUB_LINE")"
RECVD="${RECVD:-0}"; SENDS="${SENDS:-0}"

echo "zc-xproc: sub received=$RECVD (>= $THRESHOLD?), pub zc-sends=$SENDS (> 0?)"
fail=0
[[ -z "$SUB_LINE" ]] && { echo "  FAIL  subscriber printed no ZC-SUB-RECEIVED line"; fail=1; }
[[ -z "$PUB_LINE" ]] && { echo "  FAIL  publisher printed no ZC-PUB-SENDS line"; fail=1; }
(( RECVD >= THRESHOLD )) || { echo "  FAIL  sub received $RECVD < threshold $THRESHOLD (byte-exact)"; fail=1; }
(( SENDS > 0 ))          || { echo "  FAIL  pub zc-sends $SENDS — no reference carried the data (fragmented fallback?)"; fail=1; }

if (( fail != 0 )); then
  echo "zc-xproc: FAIL — cross-process Zero-Copy round-trip not proven (sub_rc=$SUB_RC pub_rc=$PUB_RC)"
  exit 1
fi
echo "zc-xproc: PASS — two OS processes exchanged $RECVD byte-exact large samples; pub published $SENDS as 16-byte references resolved from the writer's SHMEM pool CROSS-PROCESS (FR-PF-3; NOT cleared for ship — R6)."
exit 0
