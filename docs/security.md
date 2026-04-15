# Security Considerations

---

## Cryptographic Primitives

### ML-DSA (FIPS 204)

`mlpki` uses ML-DSA (Module-Lattice-Based Digital Signature Algorithm),
standardised by NIST as FIPS 204 in August 2024. It is designed to resist
attacks from both classical and quantum computers.

| Variant | NIST Level | Classical bits | Quantum bits | Recommended use |
|---|---|---|---|---|
| ML-DSA-44 | 2 | ≥ 128 | ≥ 64 | Development, testing, constrained devices |
| ML-DSA-65 | 3 | ≥ 192 | ≥ 96 | General purpose (default) |
| ML-DSA-87 | 5 | ≥ 256 | ≥ 128 | High-security or long-lived certificates |

For production deployments choose **ML-DSA-65** or **ML-DSA-87**.
ML-DSA-44 is offered for speed in testing and constrained environments
but its classical security level (128 bits) matches AES-128.

ML-DSA signing is **randomised** — repeated calls with the same message
and key produce different signatures, all of which verify correctly.
This is by design and required by FIPS 204.

### SHA3-256

Used for:
- **Subject Key ID** — `SHA3-256(public_key_bytes)[:16]`
- **Certificate fingerprint** — `SHA3-256(tbs_bytes)` (full 256-bit digest)

SHA3 (Keccak) is quantum-safe at its full output length. The 16-byte
truncation used for key identifiers is only for matching purposes, not
for cryptographic binding. Full fingerprints always use the 32-byte output.

### Argon2id + AES-256-GCM (key files)

Secret keys at rest are protected with:

1. **Argon2id** key derivation (current OWASP / NIST recommendation):
   - `time_cost = 3` iterations
   - `memory_cost = 65536 KiB` (64 MiB)
   - `parallelism = 4`
   - 16-byte random salt (unique per file)

2. **AES-256-GCM** authenticated encryption:
   - 256-bit key derived by Argon2id
   - 12-byte random nonce (unique per file)
   - 16-byte authentication tag verifies both ciphertext and key ID

The GCM tag provides **integrity protection**: any modification to the
ciphertext or stored metadata will cause decryption to fail with a
`ValueError`.

---

## Threat Model

### What `mlpki` protects against

| Threat | Mitigation |
|---|---|
| Forged certificates | ML-DSA signatures; `VerificationError` on any signature failure |
| Tampered certificates | Signature over canonical `tbs_bytes` encoding; modification detectable |
| Expired certificates | `not_before` / `not_after` checked in `verify_chain` |
| Unauthorised issuance | `is_ca` and `KEY_CERT_SIGN` checks in chain validation |
| Path-length abuse | `path_len` constraint enforced during chain validation |
| Key substitution | Authority Key ID matching links each cert to its issuer's exact key |
| Revoked certificates | CRL checked per serial in `verify_chain` |
| Offline key theft | Argon2id + AES-256-GCM encryption for key files |
| Harvest-now-decrypt-later | ML-DSA provides post-quantum signature security |

### What `mlpki` does NOT protect against

| Threat | Note |
|---|---|
| Compromised CA private key | A stolen CA key allows issuance of arbitrary certs; protect key files |
| Stale CRLs | `mlpki` does not enforce `next_update`; callers must refresh CRLs |
| OCSP / real-time revocation | Only batch CRL revocation is implemented |
| Trust anchor compromise | The `trusted_root` passed to `verify_chain` is unconditionally trusted |
| Side-channel attacks on signing | liboqs provides constant-time implementations; the Python wrapper adds overhead |
| Key exchange / confidentiality | No KEM; `mlpki` is signatures-only |

---

## Secret Key Handling

### In memory

Secret key bytes are plain Python `bytes` objects. Python does not
guarantee that `bytes` objects are zeroed on garbage collection. For
long-running processes handling many keys, consider:

- Keeping secret keys in memory only as long as needed.
- Avoiding storing them in durable Python objects (caches, global state).

### On disk

- Use `save_secret_key` with a **strong, randomly generated password**.
  Do not use a human-memorable passphrase for production root CA keys.
- Restrict file permissions to the process owner (e.g. `chmod 600`).
- Store root CA key files on offline or hardware-secured media when possible.
- The salt and nonce are stored in plaintext in the key file; this is
  cryptographically safe but means two encryptions of the same key can
  be distinguished. Re-encrypting a key produces a fresh salt and nonce.

---

## Certificate Lifetime Recommendations

| Certificate type | Recommended lifetime |
|---|---|
| Root CA | 10–20 years (`validity_days=3650–7300`) |
| Intermediate CA | 3–5 years (`validity_days=1095–1825`) |
| End-entity | 1 year or less (`validity_days=365`) |
| Self-signed service cert | 1 year or less |

Short-lived end-entity certificates reduce the window of exposure if a
key is compromised without relying solely on CRL distribution.

---

## CRL Freshness

`mlpki` does not enforce the `next_update` timestamp of a CRL. Applications
that use CRLs for revocation checking **must** implement their own freshness
policy — for example, refusing to accept a CRL whose `next_update` is in
the past:

```python
import time
if crl.next_update < int(time.time()):
    raise RuntimeError("CRL has expired — refresh before use")
verify_chain(chain, trusted_root=root_cert, crl=crl)
```

---

## Path-Length Semantics

`path_len` in `mlpki` follows RFC 5280 semantics: it counts the number
of **CA certificates** that may appear below the issuer, not the total
chain depth.

| `path_len` | Meaning |
|---|---|
| `None` | No constraint |
| `0` | Issuer may sign end-entity certs only (no sub-CAs) |
| `1` | Issuer may sign one level of intermediate CAs |

Root CAs created by `create_root_ca` default to `path_len=1`. Change this
if you need deeper hierarchies or want to enforce a flat PKI.

---

## Denial-of-Service Considerations

### Key generation

ML-DSA key generation and signing are computationally intensive relative
to RSA or ECDSA. ML-DSA-87 key generation is roughly 3× slower than
ML-DSA-44. Avoid calling `generate_keypair` or `sign` in hot paths.

### Argon2id on key load

`load_secret_key` runs Argon2id with `memory_cost=64 MiB` by default.
This is intentional to resist brute-force attacks but means it takes
measurable wall-clock time (~0.1–0.5 s depending on hardware). Cache
loaded keys rather than re-loading on every operation.

### Chain depth

`verify_chain` is linear in the chain length. There is no built-in
maximum chain depth. Applications should enforce a reasonable limit
(e.g. ≤ 10 certificates) before calling `verify_chain`.

---

## Dependency Security

| Dependency | Purpose | Security note |
|---|---|---|
| `liboqs` (C library) | ML-DSA operations | Keep updated; security advisories at https://openquantumsafe.org |
| `liboqs-python` | Python bindings | Thin ctypes wrapper; tracks liboqs releases |
| `cbor2` | CBOR encoding / decoding | Pure Python; audit for CBOR injection if parsing untrusted data |
| `argon2-cffi` | Argon2id KDF | Well-audited; uses native C implementation |
| `cryptography` | AES-256-GCM | PyCA cryptography; widely audited; keep updated |

---

## Reporting Vulnerabilities

Please report security issues via the repository's private disclosure
mechanism rather than opening a public issue.
