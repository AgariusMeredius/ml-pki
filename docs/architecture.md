# Architecture

## Overview

`mlpki` is a pure-Python library for Post-Quantum certificate management.
It provides the building blocks of a classic X.509-style PKI, but uses
ML-DSA (FIPS 204) instead of RSA/ECDSA, and CBOR instead of ASN.1/DER.

The library intentionally has a narrow scope:

- **In scope:** key generation, certificate issuance, CSR workflows, chain
  validation, revocation lists, encrypted key storage.
- **Out of scope:** TLS, key exchange (no KEM), network transport, OCSP,
  certificate databases.

---

## Module Dependency Graph

```
      ┌─────────────┐
      │  constants  │  ← imported by all other modules
      └──────┬──────┘
             │
      ┌──────▼──────┐     ┌───────┐
      │ certificate │◄────│  ca   │
      └──────┬──────┘     └───┬───┘
             │                │
      ┌──────▼──────┐         │
      │    keys     │◄────────┘
      └──────┬──────┘     ┌──────────┐
             │        ┌───│   csr    │
             │        │   └──────────┘
      ┌──────▼────────▼──┐
      │     verify       │
      └──────────────────┘
             ▲
      ┌──────┴──────┐
      │  revocation │
      └─────────────┘
```

**`constants`** — no dependencies; defines all integer field numbers, algorithm
IDs, and key-usage bitmask values used across the library.

**`certificate`** — depends on `constants`. Provides the data model
(`Name`, `PublicKeyInfo`, `TBSCertificate`, `Certificate`) and
CBOR/PEM/binary serialization. No cryptographic operations.

**`keys`** — depends on `constants`. Wraps `liboqs` for ML-DSA and
`cryptography`/`argon2-cffi` for encrypted key storage. All
cryptographic primitives live here.

**`csr`** — depends on `certificate`, `constants`, `keys`. Builds and
verifies Certificate Signing Requests.

**`ca`** — depends on `certificate`, `constants`, `keys`, `csr`. Implements
all issuance logic (root CA, self-signed, issue from CSR/direct).

**`revocation`** — depends on `constants`, `keys`. Implements CRL creation,
immutable serial append, and signature verification.

**`verify`** — depends on `certificate`, `constants`, `keys`, `revocation`.
Implements the complete path validation algorithm.

---

## Certificate Data Model

### Two-Layer Structure

Every certificate has two encoded layers:

```
Certificate (outer, CBOR)
├── tbs_bytes  : bytes   ← CBOR-encoded TBSCertificate
├── sig_alg    : int     ← algorithm ID
└── signature  : bytes   ← ML-DSA signature over tbs_bytes
```

The signature is computed **exclusively over the raw `tbs_bytes`** — the
canonical CBOR encoding of the TBS structure. This means the signed content
can be extracted and verified without decoding the outer structure first.

```
TBSCertificate (inner, CBOR)
├── version        : int
├── serial         : bytes[16]   ← random
├── issuer         : Name map
├── subject        : Name map
├── not_before     : int         ← Unix timestamp
├── not_after      : int         ← Unix timestamp
├── public_key     : PublicKeyInfo map
├── is_ca          : bool
├── path_len       : int | null
├── key_usage      : int         ← bitmask
├── subject_key_id : bytes[16]   ← SHA3-256(pub_key_bytes)[:16]
└── auth_key_id    : bytes[16]   ← issuer's subject_key_id
```

### Key Identifiers

```
subject_key_id = SHA3-256(public_key_bytes)[:16]
auth_key_id    = issuer_cert.tbs.subject_key_id
```

These 16-byte identifiers are used during chain validation to match
each certificate to its issuer without comparing full public keys.

---

## Chain Validation Algorithm

`verify_chain(chain, trusted_root, crl=None)` expects the chain ordered
from end-entity (index 0) to the last intermediate before the root:

```
chain = [intermediate_cert, ee_cert]   # root is separate
```

The full chain that is validated internally is `[trusted_root] + chain`.

For each certificate at index `i` in `chain`, the issuer is `full[i]`
(i.e. `trusted_root` for the first element, previous intermediate for
subsequent elements). The following checks run in order:

1. **Trusted root self-signature** — verified once before the loop.
2. **Temporal validity** — `not_before ≤ now ≤ not_after` for every cert.
3. **CA flag** — `issuer.tbs.is_ca` must be `True`.
4. **Key usage** — `issuer.tbs.key_usage & KEY_CERT_SIGN` must be set.
5. **path_len** — counts remaining CA certificates below the issuer and
   compares against `issuer.tbs.path_len`.
6. **Authority Key ID** — `cert.tbs.auth_key_id == issuer.tbs.subject_key_id`.
7. **ML-DSA signature** — verifies `cert.signature` over `cert.tbs_bytes`
   using the issuer's public key.
8. **Revocation** — if a CRL is supplied, checks
   `crl.is_revoked(cert.tbs.serial)`.

Any failure raises `VerificationError(message, code)` with a
`VerificationCode` enum value identifying the failure reason.

---

## Key Storage Format

Secret keys are stored as CBOR files encrypted with Argon2id → AES-256-GCM:

```
KeyFile (CBOR)
├── 1: alg_id         ← mlpki algorithm ID
├── 2: argon2_params
│   ├── 1: time_cost
│   ├── 2: memory_cost
│   ├── 3: parallelism
│   └── 4: salt       ← 16 bytes, random per file
├── 3: nonce          ← 12 bytes, random per file
├── 4: ciphertext     ← AES-256-GCM encrypted secret key
└── 5: tag            ← 16-byte GCM authentication tag
```

The 256-bit AES key is derived as:
```
aes_key = Argon2id(password, salt, time_cost, memory_cost, parallelism, 32)
```

Default Argon2id parameters: `time_cost=3`, `memory_cost=65536` (64 MiB),
`parallelism=4`. These can be tuned for the deployment environment by
modifying the constants in `keys.py`.

---

## CSR Design

The CSR self-signature covers all fields **except** the signature field
itself:

```
signed_content = CBOR({
    1: version,
    2: subject,
    3: public_key,
    4: sig_alg,
    6: is_ca,
    7: path_len,
    8: key_usage,
})
```

Field 5 (signature) is excluded. This is analogous to PKCS#10 but
using integer keys and ML-DSA instead of RSA/ECDSA.

The CSR carries `is_ca`, `path_len`, and `key_usage` as requested
extensions that the CA may honour or override. `issue_from_csr` transfers
these values directly; `issue_certificate` allows the CA to specify them
independently.

---

## CRL Design

CRLs are immutable value objects. Adding a serial produces a new,
independently-signed CRL:

```python
crl2 = crl.add_serial(serial, issuer_cert, issuer_sec)
# crl is unchanged; crl2 is a new object with a fresh signature
```

The CRL signature covers fields 1–5 (everything except the signature):

```
signed_content = CBOR({
    1: issuer_key_id,
    2: this_update,
    3: next_update,
    4: revoked_serials,
    5: sig_alg,
})
```

---

## Design Decisions

| Decision | Rationale |
|---|---|
| CBOR with integer keys | Compact binary encoding; no string overhead; deterministic field order for canonical encoding |
| Separate TBS encoding | Signature is over raw bytes, not a re-encoded structure; avoids canonicalization ambiguity |
| SHA3-256 for key IDs and fingerprints | Consistent hash family with ML-DSA; quantum-resistant |
| 16-byte serials and key IDs | Sufficient collision resistance; smaller than full SHA hashes |
| Immutable CRL updates | Prevents accidental mutation of signed data; encourages explicit re-signing |
| Argon2id for key derivation | Current OWASP / NIST recommendation for password-based KDF; memory-hard |
| AES-256-GCM for key encryption | Standard authenticated encryption; 256-bit key well-matched to ML-DSA security level |
