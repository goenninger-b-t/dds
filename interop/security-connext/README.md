# LIVE RTI Connext-Security cross-vendor secure interop (M7/P6, Slice 5b)

`run-connext-interop.sh` stands up a real RTI Connext-Security participant (`rtiddsspy` with
the security plugin, or the built `hello_secure_pub` secured publisher) and one of OURS on
domain 0 over UDP loopback, sharing the reused Identity-CA / Permissions-CA / Governance /
S/MIME permissions, and drives the DDS-Security 1.1 path end to end: SPDP -> §8.7 mutual
PKI-DH auth -> crypto-token exchange over PVMS -> secure SEDP match -> protected DATA.

Setup and the OpenSSL `@loader_path` symlink fix are documented in the script header.

## Usage

```
bash interop/security-connext/run-connext-interop.sh [GOV] [SECS]
```

- `GOV` = `none` | `secure` (all-ENCRYPT) | `sign` (all-SIGN, authenticated-but-visible) |
  `datasign` (SIGN including the user payload). Default `none`.
- `SECS` = seconds ours runs per direction. Default `25`.

## 2-secured-writer mode (WP-2SECURED-WRITER-CONNEXT — validates WP-N-ENDPOINT-S3)

```
WRITERS=2 bash interop/security-connext/run-connext-interop.sh secure 25
```

**What it validates on the wire.** S3 (ADR 0048) enabled N secured DataWriters per
participant, each keyed under its OWN EntityCrypto km: the send crux derives the encode
key/kind from the ACTUAL publishing writer's EntityId, not a node-single writer. This mode
proves that per-endpoint crypto against a REAL Connext security observer: ONE secured
participant stands up TWO independently-keyed secured writers on `HelloWorldTopic` +
`HelloWorldTopic2` (`run-secure-interop-peer` role `pub2`), publishes on EACH writer under
its own EntityId's km (`publish-sample` `writer-id` = `%local-user-writer-id-for-topic` per
topic), and `rtiddsspy` (Connext security) decodes samples from BOTH writers, each under its
own key.

Only the `ours2connext` direction runs (the Connext observer watches both writers); `WRITERS=1`
(default) is byte-identical to the single-writer modes.

**The distinct-key_id proof.** The two writers get DISTINCT EntityIds (S1 key alloc) and each
resolves its OWN EntityCrypto km — a DISTINCT §9.5.2 `sender_key_id` (the receiver's `find_key`
discriminator). The peer log surfaces this before the run:

```
[pub2] writer-A topic=HelloWorldTopic  entityid=... key_id=...
[pub2] writer-B topic=HelloWorldTopic2 entityid=... key_id=...
[pub2] distinct-key-ids=T
SUMMARY-2W: topic=HelloWorldTopic topic2=HelloWorldTopic2 key-id-A=... key-id-B=... distinct-key-ids=T
```

`RESULT: PASS` for role `pub2` requires matched + sent + DISTINCT key_ids.

**Our-to-our sanity.** `run-security-2secured-writer-harness-test` (in the standard suite)
proves the `pub2` MODE plumbing our-to-our with no network: two secured writers register with
distinct EntityIds, `%local-user-writer-id-for-topic` resolves each, and the two writers'
`sender_key_id`s are DISTINCT. Full send/decode crypto correctness (each payload keyed under its
own km, cross-key decode fails closed) is `run-security-n-secured-writer-test`.

## Files in this directory

| File | Purpose |
|---|---|
| `run-connext-interop.sh` | The live driver (single-writer directions + `WRITERS=2` 2-secured-writer mode) |
| `USER_QOS_PROFILES.xml` | `OursConnextInterop::${GOV}` Connext security profiles |
| `hello_secure_pub.cxx` / `HelloWorld.*` | The reverse-direction Connext secured publisher (built via `make`) |
| `captures/` | tshark pcapng + per-direction Connext/ours logs |
