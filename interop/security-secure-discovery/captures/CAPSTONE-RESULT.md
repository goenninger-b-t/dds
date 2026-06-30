# Slice-5 capstone — live Fast DDS-Security cross-vendor secure discovery: PROTECTED USER DATA BOTH DIRECTIONS

**WP-DDS-SECURITY-FASTDDS-INTEROP (M7/P6 Slice 5), ADR 0037 — 2026-06-30. The Fast-DDS half of the P6 exit gate is MET.**

## Run

```
pkill -f fastdds; pkill -f security
bash interop/security-secure-discovery/run-fastdds-interop.sh secure 45
```

- Peer: a live SECURITY=ON eProsima Fast DDS v3.6.1 `security` example.
- Governance: `GOV=secure` — `discovery_protection` / `rtps_protection` / `metadata_protection` /
  `data_protection` = ENCRYPT.
- Shared trust: the reused Identity-CA / Permissions-CA / Governance (`interop/security-auth/pki`,
  `interop/security-access-control/pki`, the `fastdds/certs` S/MIME fixtures).
- Path exercised both directions: plain SPDP → §8.7 PKI-DH auth → SharedSecret → permissions validation →
  reliable-PVMS ParticipantCryptoToken exchange → `:keyed` → reliable secure-SEDP endpoint match → protected
  user DATA over SRTPS rtps_protection + SEC_PREFIX metadata_protection + serialized-payload data_protection.

## Result — BOTH DIRECTIONS PASS

| Direction | our SUMMARY | cross-vendor evidence |
|---|---|---|
| **ours2fast** (our pub → Fast DDS sub) | `role=pub discovered=1 peak-matched=1 peak-samples=0 ever-keyed=T sent=8 RESULT: PASS` | Fast DDS subscriber logged **8/8** `'Hello world from Lisp' index 0..7 RECEIVED` (our ENCRYPT-protected samples decoded by Fast DDS) |
| **fast2ours** (Fast DDS pub → our sub) | `role=sub discovered=3 peak-matched=1 peak-samples=88 ever-keyed=T sent=0 RESULT: PASS` | we **decoded 88** of Fast DDS's ENCRYPT-protected `'Hello world'` samples |

Protected user data crosses the full secure stack in **both directions** = the DoD.

## Captures (this run, 2026-06-30)

- `ssd-secure-ours2fast.pcapng` + `ssd-secure-ours2fast-ours.log` + `ssd-secure-ours2fast-fastdds.log`
- `ssd-secure-fast2ours.pcapng` + `ssd-secure-fast2ours-ours.log` + `ssd-secure-fast2ours-fastdds.log`

tshark cannot dissect the macOS `lo0` NULL/Loopback link-layer (the per-direction submessage histograms are
therefore empty); `tcpdump -r` confirms well-formed RTPS, and the **live cross-vendor decode in both
directions is itself the wire proof** — Fast DDS's plugins parse our protected frames and ours parse its.
The `.pcapng` files are gitignored (large, undissectable, reproducible — the Slice-4 convention); the `.log`
files + this `CAPSTONE-RESULT.md` are committed.

## Honesty

**Fast-DDS-validated, NOT Connext-validated.** Live RTI Connext-Security secure discovery is **Slice 5b** —
the licensed RTI Security Plugins (`libnddssecurity*`) are not installed on this host. No statement here
asserts Connext interop.

## Reproduce

The campaign + every reconciled divergence + the residual carries are in ADR 0037
(`docs/adr/0037-dds-security-fastdds-interop.md`); the two shipped crypto-wire changes (empty-AAD, SecureDataTag
4-align) are ADR-0031 addenda. The per-task captures `T2-RESULT.md` … `T11reverse-RESULT.md` are the
commit-by-commit live evidence.
