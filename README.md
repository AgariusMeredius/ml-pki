# mlpki

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

tests/                pytest suite — 129 tests, no network required
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

## License

MIT
