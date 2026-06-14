#!/usr/bin/env bash
# WP-SHMEM Task F1 — REAL two-OS-process cross-process SHMEM round-trip (FR-XPORT-2).
# The wire/shared-memory is the oracle (the operating contract §4): two SEPARATE SBCL
# processes on THIS host get the same host-uuid (MD5 of hostname) and, after they
# discover each other over loopback UDP (deterministic domain-derived ports + :peers,
# no multicast so the macOS app-firewall LAN-UDP drop is irrelevant), the publisher
# routes user DATA over SHARED MEMORY. Proof = the sub received the samples AND the
# pub's disc-node-shmem-sends > 0 (i.e. SHMEM, not UDP, carried the user data across
# the OS-process boundary). SBCL only: SHMEM is on for SBCL everywhere + Clasp/Linux;
# Clasp/macOS falls back to UDP (ADR 0013 shm_open variadic-mode ABI gap), so this
# harness pins SBCL and a different domain than the default 0 to dodge stray peers.
set -euo pipefail
cd "$(dirname "${BASH_SOURCE[0]}")/.."

DOMAIN="${DOMAIN:-7}"           # non-default domain => distinct ports, fewer stray peers
COUNT="${COUNT:-60}"            # samples the pub publishes
THRESHOLD="${THRESHOLD:-20}"   # samples the sub must receive to PASS
DEADLINE="${DEADLINE:-60}"     # seconds before a hung process is killed (fail, not wedge)
SBCL="./scripts/with-sbcl.sh"

SUBOUT="$(mktemp -t shmem-sub.XXXXXX)"
PUBOUT="$(mktemp -t shmem-pub.XXXXXX)"
SUBPID=""
PUBPID=""
cleanup() {
  [[ -n "$PUBPID" ]] && kill "$PUBPID" 2>/dev/null || true
  [[ -n "$SUBPID" ]] && kill "$SUBPID" 2>/dev/null || true
  rm -f "$SUBOUT" "$PUBOUT"
}
trap cleanup EXIT

# Clear any straggler holding our two loopback discovery ports (PB+DG*domain+d1+PG*pid:
# domain 7 => sub 9160 / pub 9162) so a stale process never poisons fresh discovery.
P_SUB=$(( 7400 + 250 * DOMAIN + 10 ))
P_PUB=$(( 7400 + 250 * DOMAIN + 10 + 2 ))
if command -v lsof >/dev/null 2>&1; then
  for p in "$P_SUB" "$P_PUB"; do
    while read -r pid; do
      [[ -n "$pid" ]] && { echo "shmem-xproc: killing straggler pid $pid on UDP $p"; kill "$pid" 2>/dev/null || true; }
    done < <(lsof -nP -iUDP:"$p" -t 2>/dev/null || true)
  done
fi

echo "shmem-xproc: domain=$DOMAIN count=$COUNT threshold=$THRESHOLD deadline=${DEADLINE}s (loopback :peers, no multicast; SBCL SHMEM)"

# --- subscriber: own OS process, bound to the deterministic sub port, :peers at the pub
"$SBCL" --eval '(asdf:load-system :dds-shapes)' \
        --eval "(uiop:symbol-call :dds.shapes :run-shmem-xproc-sub :domain $DOMAIN :threshold $THRESHOLD :seconds $((DEADLINE - 5)))" \
        >"$SUBOUT" 2>&1 &
SUBPID=$!

# wait (bounded) for the sub to print its bind line before launching the pub
for _ in $(seq 1 100); do
  grep -q '\[shmem-sub\]' "$SUBOUT" 2>/dev/null && break
  kill -0 "$SUBPID" 2>/dev/null || break
  sleep 0.1
done

# --- publisher: own OS process, bound to the deterministic pub port, :peers at the sub
"$SBCL" --eval '(asdf:load-system :dds-shapes)' \
        --eval "(uiop:symbol-call :dds.shapes :run-shmem-xproc-pub :domain $DOMAIN :count $COUNT :match-timeout $((DEADLINE - 20)))" \
        >"$PUBOUT" 2>&1 &
PUBPID=$!

# --- bounded wait for BOTH to exit; kill (fail) if the deadline passes (no wedge)
waited=0
while kill -0 "$SUBPID" 2>/dev/null || kill -0 "$PUBPID" 2>/dev/null; do
  if (( waited >= DEADLINE )); then
    echo "shmem-xproc: DEADLINE ${DEADLINE}s exceeded — killing processes (FAIL: hang)"
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

# --- assert: sub RECEIVED >= threshold AND pub SHMEM-SENDS > 0 (SHMEM carried the data)
SUB_LINE="$(grep -E '^SHMEM-SUB-RECEIVED: [0-9]+' "$SUBOUT" | tail -1 || true)"
PUB_LINE="$(grep -E '^SHMEM-PUB-SENDS: [0-9]+ / [0-9]+' "$PUBOUT" | tail -1 || true)"
RECVD="$(sed -nE 's/^SHMEM-SUB-RECEIVED: ([0-9]+).*/\1/p' <<<"$SUB_LINE")"
SENDS="$(sed -nE 's/^SHMEM-PUB-SENDS: ([0-9]+) .*/\1/p' <<<"$PUB_LINE")"
RECVD="${RECVD:-0}"; SENDS="${SENDS:-0}"

echo "shmem-xproc: sub received=$RECVD (>= $THRESHOLD?), pub shmem-sends=$SENDS (> 0?)"
fail=0
[[ -z "$SUB_LINE" ]] && { echo "  FAIL  subscriber printed no SHMEM-SUB-RECEIVED line"; fail=1; }
[[ -z "$PUB_LINE" ]] && { echo "  FAIL  publisher printed no SHMEM-PUB-SENDS line"; fail=1; }
(( RECVD >= THRESHOLD )) || { echo "  FAIL  sub received $RECVD < threshold $THRESHOLD"; fail=1; }
(( SENDS > 0 ))          || { echo "  FAIL  pub shmem-sends $SENDS — SHMEM did NOT carry user data (UDP fallback?)"; fail=1; }

if (( fail != 0 )); then
  echo "shmem-xproc: FAIL — cross-process SHMEM round-trip not proven (sub_rc=$SUB_RC pub_rc=$PUB_RC)"
  exit 1
fi
echo "shmem-xproc: PASS — two OS processes exchanged $RECVD samples; pub routed $SENDS user DATA datagrams over SHARED MEMORY (FR-XPORT-2)."
exit 0
