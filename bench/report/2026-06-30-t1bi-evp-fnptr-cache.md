# T1b-i: EVP fn-pointer cache — before/after (WP-DDS-SECURITY-ZEROALLOC-AEAD)

Date: 2026-06-30  
Host: SBCL 2.6.5, OpenSSL 3.6.2 (arm64-macOS)  
Method: `dds.pal:bytes-consed` delta, 200k iters, reused static buffers, NIST TC16 sizes (key 32, nonce 12, aad 20, pt 60).

## seal-into

| stage | B/iter |
|---|---|
| baseline (before) | **863.94** |
| after T1b-i (fn-ptrs + cipher cache) | **79.95** |
| expected T1b-ii residual (SAP/scratch) | ~48 |

Reduction: 784 B/iter removed (~91%), matching spike forecast.

## open-into

| stage | B/iter |
|---|---|
| baseline (before) | ~847 (spike) |
| after T1b-i | **63.90** |

## What was changed

- `%ossl-sym` macro in `src/dds-dare/openssl-ffi.lisp`: `cffi:foreign-symbol-pointer` → `(load-time-value ... t)`. Every call site already used a literal string, so each resolves once per FASL load. Safe for all DARE EVP paths (SHA/HKDF/AEAD/ML-KEM/X.509/CMS).
- `*%aes-256-gcm-cipher*` in `src/dds-dare/openssl-ffi.lisp`: calls `EVP_aes_256_gcm()` once via `eval-when (:load-toplevel :execute)` after `*libcrypto*` is set; the const static `EVP_CIPHER*` is reused by all 4 AES-GCM functions.
- `src/dds-dare/primitives.lisp`: replaced `(cffi:foreign-funcall-pointer (%ossl-sym "EVP_aes_256_gcm") nil :pointer)` with `*%aes-256-gcm-cipher*` at all 4 sites (seal, open, seal-into, open-into).

## Tests

SBCL: 383/383 passed. Clasp: 383/383 passed. gate-types: PASS (2059 defuns declared).
NIST KAT (run-dare-aes-gcm-kat-test): KAT-PASS — CT+tag byte-identical to TC16.
