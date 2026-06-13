# Static-:peers user-data isolation — design

**Context.** Re-confirming change-coalescing on the wire, our `square-pub` → Fast DDS `shapes_sub` on
pure loopback initially showed the Fast DDS app receiving 0 samples. Systematic debugging found the
*primary* cause was a harness-timing artifact (`count=8 ÷ rate=30` exits the publisher in ~0.27 s, before
SPDP/SEDP discovery completes), NOT a locator-resolution bug — with discovery time the publisher resolves
Fast DDS's `PID_DEFAULT_UNICAST_LOCATOR` (127.0.0.1:7411), matches its reader, and Fast DDS receives
299/300 coalesced samples (live, `interop/fastdds/captures/`). The investigation also surfaced a real
design wart, fixed here.

**The wart.** `%reader-push-targets` (src/dds-disc/dataplane.lisp) appended every static `:peers` entry
as a user-data push target *in addition to* matched-reader destinations (any peer whose `(host . port)`
wasn't already a matched destination). A `:peers` entry is an **SPDP metatraffic BOOTSTRAP locator**
(FR-DISC-4, where to send SPDP to start discovery), **not** a user-data destination. A foreign peer
binds its metatraffic port (7410) and user-data port (7411) on **separate** sockets, so user DATA sent to
the `:peers` SPDP port (7410) lands on the metatraffic socket and is dropped. (Our own stack shares one
socket for metatraffic + user data — routing by EntityId — so it was merely wasteful, never observed.)

**Fix.** Fall back to the static `:peers` as user-data destinations **only when no matched reader
resolved to a destination** (`(when (null groups) …)`) — the genuine discovery-less path (the
value-level UDP tests that wire two nodes by `:peers` and never complete SEDP, where the peer port *is*
the shared-socket user-data port). Once a real reader is matched, its `DEFAULT_UNICAST` locator
(RTPS 2.5 §9.6.1.4) is the sole destination; the SPDP bootstrap peer is not also blasted with user DATA.

**Why safe (verified).** Every over-UDP test (`reliable-data-over-udp`, `large-data-over-udp`,
`dispose-over-udp`, `lost-final-sample-repair`, `typed-shape-over-udp`, …) completes SEDP matching before
publishing, so `groups` is non-empty and the matched-reader destination — the same shared-socket port as
the `:peers` entry — is used: behaviour unchanged. The discovery-less branch still fires when there is no
match. Offline tests (`acknack-addressing`, `colocated-push`, `coalesce-*`) seed matches directly and
never relied on the fallback.

**Test (TDD).** `push-spdp-peer-isolation`: a node with a matched reader (DEFAULT_UNICAST 127.0.0.1:7411)
AND a static `:peers` SPDP locator on a different port (7410) — `%reader-push-targets` returns ONLY the
7411 destination (red before the fix: it also returned 7410). Then with matches cleared, the static peer
IS the sole (discovery-less fallback) destination.

**Live confirmation.** After the fix, Fast DDS still receives 299/300 (loopback), and the capture shows
our user DATA going to 7411 post-match with only a brief pre-match tail to 7410 (the legitimate bootstrap
window) — vs all user data to 7410 before.

**Note (not a code bug).** For a short-count run against a foreign peer to deliver every sample, the
publisher must run long enough for discovery to complete first; the harness/docs, not the stack,
own that. The stack's resolution and delivery are correct.
