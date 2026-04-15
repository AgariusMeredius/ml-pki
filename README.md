# mlpki

> **Disclaimer:** This project was developed, tested, and audited with
> Claude Sonnet 4.6 and Claude Code (Sonnet 4.6).
> It is an AI-assisted research project and has not undergone
> independent human peer review. See the [Disclaimer](#disclaimer) section
> for full limitations before any production use.

Post-Quantum Public Key Infrastructure library for Python.

`mlpki` implements certificate management and digital signatures using
**ML-DSA** (FIPS 204 / CRYSTALS-Dilithium) via
[liboqs](https://github.com/open-quantum-safe/liboqs). All data structures
are serialized as **CBOR** with integer keys — no ASN.1, no TLS, no key
exchange. The library covers the complete PKI lifecycle: key generation,
certificate issuance, CSR workflows, chain validation, and revocation.

## Features

- **ML-DSA-44 / 65 / 87** — all three NIST PQC security levels
- **CBOR serialization** with integer keys and Unix timestamps
- **Two-layer certificate format** — TBS bytes signed separately, outer
  structure carries `tbs_bytes + sig_alg + signature`
- **Certificate Signing Requests** with self-signature for key possession proof
- **Full chain validation** — signatures, validity windows, CA flags,
  `KEY_CERT_SIGN`, `path_len` constraints, Authority Key ID matching,
  revocation
- **Certificate Revocation Lists** — immutable append, CBOR-serialized,
  ML-DSA signed
- **Encrypted key storage** — Argon2id key derivation + AES-256-GCM,
  CBOR file format
- **PEM-like export** for certificates and CSRs (`-----BEGIN ML-CERTIFICATE-----`)

## Requirements

- Python ≥ 3.11
- [liboqs](https://github.com/open-quantum-safe/liboqs) shared library (≥ 0.14)
- `liboqs-python`, `cbor2`, `argon2-cffi`, `cryptography`

## Installation

```bash
# 1. Build and install liboqs (shared library)
git clone --depth 1 --branch 0.14.0 https://github.com/open-quantum-safe/liboqs.git
cmake -S liboqs -B liboqs/build -GNinja \
      -DCMAKE_BUILD_TYPE=Release \
      -DBUILD_SHARED_LIBS=ON \
      -DOQS_BUILD_ONLY_LIB=ON
cmake --build liboqs/build
sudo cmake --install liboqs/build

# 2. Install Python dependencies
pip install liboqs-python cbor2 argon2-cffi "cryptography>=42"

# 3. Install mlpki (editable)
pip install -e .
```

## Quick Start

### 1 — Create a Root CA

```python
from mlpki import create_root_ca, Name, ALG_ML_DSA_65, save_secret_key

root_cert, root_sec = create_root_ca(
    subject=Name(cn="My Root CA", org="My Organisation"),
    validity_days=3650,
    alg=ALG_ML_DSA_65,
)

save_secret_key("root_ca.mlkey", root_sec, ALG_ML_DSA_65, b"strong-password")

with open("root_ca.pem", "w") as f:
    f.write(root_cert.to_pem())
```

### 2 — Issue a Certificate

```python
from mlpki import (
    Certificate, generate_keypair, issue_certificate,
    load_secret_key, verify_chain, KEY_USAGE_DIGITAL_SIGNATURE,
)

root_cert = Certificate.from_pem(open("root_ca.pem").read())
root_sec, root_alg = load_secret_key("root_ca.mlkey", b"strong-password")

ee_pub, ee_sec = generate_keypair(root_alg)
ee_cert = issue_certificate(
    subject=Name(cn="service.example.com", org="My Organisation"),
    subject_pub=ee_pub,
    issuer_cert=root_cert,
    issuer_sec=root_sec,
    validity_days=365,
    key_usage=KEY_USAGE_DIGITAL_SIGNATURE,
)

verify_chain([ee_cert], trusted_root=root_cert)  # raises on failure
```

### 3 — CSR Workflow

```python
from mlpki import (
    CertificateSigningRequest, generate_keypair,
    issue_from_csr, verify_chain, Name, ALG_ML_DSA_44,
)

# --- Applicant ---
pub, sec = generate_keypair(ALG_ML_DSA_44)
csr = CertificateSigningRequest.create(
    subject=Name(cn="applicant.example.com", org="Applicant Org"),
    pub=pub, sec=sec, alg=ALG_ML_DSA_44,
)
csr_pem = csr.to_pem()          # transmit to CA

# --- CA ---
csr = CertificateSigningRequest.from_pem(csr_pem)
assert csr.verify_self_signature()
cert = issue_from_csr(csr, issuer_cert=root_cert, issuer_sec=root_sec)
```

### 4 — Revocation

```python
from mlpki import RevocationList

crl = RevocationList.create(root_cert, root_sec, next_update_days=30)
crl = crl.add_serial(ee_cert.tbs.serial, root_cert, root_sec)

from mlpki.verify import VerificationError
try:
    verify_chain([ee_cert], trusted_root=root_cert, crl=crl)
except VerificationError as e:
    print(e.code)  # VerificationCode.REVOKED
```

### 5 — Sign and Verify Data

```python
from mlpki import generate_keypair, sign, ALG_ML_DSA_65
from mlpki.keys import verify

pub, sec = generate_keypair(ALG_ML_DSA_65)
sig = sign(b"my message", sec, ALG_ML_DSA_65)
ok  = verify(b"my message", sig, pub, ALG_ML_DSA_65)
```

## Project Layout

```
mlpki/
├── __init__.py       Public API re-exports
├── constants.py      Field numbers, algorithm IDs, key-usage flags
├── certificate.py    Name, PublicKeyInfo, TBSCertificate, Certificate
├── keys.py           Key generation, sign, verify, encrypted storage
├── csr.py            CertificateSigningRequest
├── ca.py             CA operations (create_root_ca, issue_certificate …)
├── revocation.py     RevocationList (CRL)
└── verify.py         verify_chain, verify_signature, VerificationError

tests/                pytest suite — 144 tests, no network required
examples/             Runnable end-to-end scripts
docs/                 Architecture, API reference, format spec, security
```

## Running Tests

```bash
pytest tests/ -q
```

## Documentation

Detailed documentation lives in [`docs/`](docs/):

| File | Content |
|---|---|
| [`architecture.md`](docs/architecture.md) | Module overview, data flow, design decisions |
| [`api-reference.md`](docs/api-reference.md) | Full API reference for every public function |
| [`formats.md`](docs/formats.md) | CBOR serialization format specification |
| [`security.md`](docs/security.md) | Security considerations and threat model |

## Usage Warnings and Security Notes

### Algorithm Selection

| Variant | NIST Level | Recommended for |
|---|---|---|
| `ALG_ML_DSA_44` | 2 (128-bit classical) | **Development and testing only** |
| `ALG_ML_DSA_65` | 3 (192-bit classical) | General-purpose production use |
| `ALG_ML_DSA_87` | 5 (256-bit classical) | High-security or long-lived certificates (> 10 years) |

**Do not use `ALG_ML_DSA_44` in production.** Its 128-bit classical security level is the lowest NIST accepts and is offered solely for speed in tests and constrained devices.

### Key Management

- Use `save_secret_key()` with a **strong randomly generated password** (≥ 32 bytes from `secrets.token_bytes()`). Human-memorable passphrases are not adequate for root CA keys.
- Restrict key file permissions: `chmod 600 root_ca.mlkey`
- Store root CA key files on **offline or hardware-secured media** when not actively signing.
- Secret key bytes are plain Python `bytes` objects — Python does not zero memory on garbage collection. Keep secret keys in local scope; do not cache them in global state.

### CRL Freshness

`verify_chain()` now **enforces** that the provided CRL's `next_update` timestamp is in the future. A stale CRL will raise `VerificationError` with code `CRL_EXPIRED`. Applications must refresh CRLs before they expire:

```python
# Refresh before next_update; never let CRLs go stale.
crl = RevocationList.create(issuer_cert, issuer_sec, next_update_days=7)
```

### Chain Depth

`verify_chain()` rejects chains longer than `max_depth` (default: 10). Set a tighter limit for flat PKI hierarchies to reduce attack surface:

```python
verify_chain([ee_cert], trusted_root=root_cert, max_depth=2)
```

### CSR Handling

`issue_from_csr()` automatically verifies the CSR self-signature. Still, the CA must independently apply its own **issuance policy** — for example, whether to honour a CSR's `is_ca=True` request. The library transfers requested extensions from the CSR subject to issuer constraints; it does not enforce naming policies or organisational vetting.

### What `mlpki` Does NOT Provide

- **No key exchange or confidentiality** — ML-DSA is a signature scheme only; no KEM, no TLS, no encrypted channels
- **No OCSP** — revocation is batch CRL only; no real-time revocation status
- **No X.509 / TLS compatibility** — certificates use a custom CBOR format and are not interoperable with existing X.509 infrastructure
- **No name constraints** — CAs cannot restrict the subject namespace of subordinate CAs
- **No clock skew tolerance** — validity window checks use exact integer comparisons; NTP drift of even 1 second can cause `NOT_YET_VALID` on freshly issued certificates

### Security Audit

A full security and functionality audit was performed on 2026-04-13.  
See [`AUDIT.md`](AUDIT.md) for all findings, applied fixes, and residual accepted risks.

---

## Disclaimer

`mlpki` is an **experimental research library** implementing post-quantum PKI
primitives based on ML-DSA (FIPS 204). It is provided for educational purposes,
prototyping, and evaluation of post-quantum certificate infrastructures.

**This project was developed, tested, and audited with Claude Sonnet 4.6
and Claude Code (Sonnet 4.6).** The entire codebase — including design,
implementation, test suite, and security audit — was produced through
AI-assisted development. It has not undergone independent human peer review
by qualified cryptographers.

**This software is not a certified cryptographic product and has not undergone
a formal third-party security evaluation.**

The following limitations apply:

- **No warranty of any kind** is provided, express or implied, including fitness
  for a particular purpose or security in production environments.
- The CBOR-based certificate format is **not interoperable** with X.509,
  TLS, or any standard PKI infrastructure. It is a custom format defined by
  this library alone.
- Post-quantum cryptography standards are **recently standardised** (FIPS 204:
  August 2024). While ML-DSA is considered secure against known quantum and
  classical attacks, the broader ecosystem of implementations, tooling, and
  operational guidance is still maturing.
- Correct security outcomes depend on callers following the guidance in
  [`docs/security.md`](docs/security.md) and [`AUDIT.md`](AUDIT.md). Misuse
  of the API — such as skipping chain verification, using stale CRLs, or
  handling secret keys insecurely — cannot be prevented by the library alone.
- The underlying `liboqs` C library must be kept updated independently.
  Security fixes in `liboqs` are not automatically applied by updating this
  package.

**Before deploying `mlpki` or any derivative work in a production or
security-sensitive environment, obtain an independent security review by
qualified cryptographers.**

## Export Control

This project is published as open-source software and is not subject to
U.S. export control regulations under the public domain exemption
(EAR § 740.17(b)(1)). The cryptographic algorithms used (ML-DSA / FIPS 204,
AES-256-GCM) are publicly standardised by NIST and their implementations
are freely available worldwide.

## License

MIT
