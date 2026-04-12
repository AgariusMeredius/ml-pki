# API Reference

All public symbols are re-exported from the top-level `mlpki` package.
Low-level cryptographic primitives (`keys.verify`) are accessible via
`mlpki.keys` directly.

---

## `mlpki.constants`

Named constants used as CBOR integer keys, algorithm identifiers, and
key-usage bitmask values. Import directly if you need the raw numbers.

### Algorithm IDs

| Constant | Value | ML-DSA variant |
|---|---|---|
| `ALG_ML_DSA_44` | `1` | NIST security level 2 |
| `ALG_ML_DSA_65` | `2` | NIST security level 3 |
| `ALG_ML_DSA_87` | `3` | NIST security level 5 |

```python
ALG_NAMES: dict[int, str]   # maps ID → liboqs algorithm name string
```

### Key-Usage Flags

| Constant | Bit | Meaning |
|---|---|---|
| `KEY_USAGE_DIGITAL_SIGNATURE` | `0x01` | Certificate or data signing |
| `KEY_USAGE_KEY_CERT_SIGN` | `0x02` | Required for CAs issuing certificates |
| `KEY_USAGE_CRL_SIGN` | `0x04` | Required for CAs signing CRLs |

---

## `mlpki.certificate`

### `Name`

```python
@dataclass
class Name:
    cn:  str
    org: str
    ou:  str | None = None
```

Represents a distinguished name used for subject and issuer fields.

| Method | Signature | Description |
|---|---|---|
| `to_map` | `() -> dict` | Encode to CBOR-ready integer-keyed map |
| `from_map` | `(m: dict) -> Name` | Decode from integer-keyed map |

---

### `PublicKeyInfo`

```python
@dataclass
class PublicKeyInfo:
    alg_id:    int
    key_bytes: bytes
```

Wraps a raw ML-DSA public key together with its algorithm identifier.

| Method / Property | Description |
|---|---|
| `alg_name: str` | Human-readable algorithm name (e.g. `"ML-DSA-65"`) |
| `to_map() -> dict` | Encode to CBOR-ready map |
| `from_map(m) -> PublicKeyInfo` | Decode from map |

---

### `TBSCertificate`

```python
@dataclass
class TBSCertificate:
    version:        int
    serial:         bytes          # 16 bytes
    issuer:         Name
    subject:        Name
    not_before:     int            # Unix timestamp
    not_after:      int            # Unix timestamp
    public_key:     PublicKeyInfo
    is_ca:          bool
    path_len:       int | None
    key_usage:      int            # bitmask
    subject_key_id: bytes          # 16 bytes
    auth_key_id:    bytes          # 16 bytes
```

The to-be-signed content of a certificate. Its canonical CBOR encoding
is what the ML-DSA signature is computed over.

| Method | Signature | Description |
|---|---|---|
| `encode` | `() -> bytes` | Canonical CBOR encoding |
| `decode` | `(data: bytes) -> TBSCertificate` | Decode from CBOR bytes |

---

### `Certificate`

```python
@dataclass
class Certificate:
    tbs_bytes: bytes    # CBOR-encoded TBSCertificate
    sig_alg:   int      # algorithm ID
    signature: bytes    # ML-DSA signature over tbs_bytes
```

The signed outer certificate structure.

| Method / Property | Signature | Description |
|---|---|---|
| `tbs` | `-> TBSCertificate` | Lazily decoded TBS (cached) |
| `encode` | `() -> bytes` | CBOR encode outer structure |
| `decode` | `(data: bytes) -> Certificate` | Decode from CBOR bytes |
| `to_pem` | `() -> str` | PEM-like export (`-----BEGIN ML-CERTIFICATE-----`) |
| `from_pem` | `(pem: str) -> Certificate` | Import from PEM string |
| `fingerprint` | `() -> bytes` | SHA3-256 digest over `tbs_bytes` (32 bytes) |
| `save` | `(path: str)` | Write binary `.mlcert` file |
| `load` | `(path: str) -> Certificate` | Read binary `.mlcert` file |

---

## `mlpki.keys`

### `generate_keypair`

```python
def generate_keypair(alg: int = ALG_ML_DSA_65) -> tuple[bytes, bytes]
```

Generate a fresh ML-DSA key pair.

**Parameters:**
- `alg` — algorithm ID (`ALG_ML_DSA_44`, `ALG_ML_DSA_65`, or `ALG_ML_DSA_87`)

**Returns:** `(public_key_bytes, secret_key_bytes)`

---

### `sign`

```python
def sign(message: bytes, secret_key: bytes, alg: int) -> bytes
```

Produce an ML-DSA signature. ML-DSA signing is randomised; repeated calls
with the same inputs produce different (but all valid) signatures.

**Parameters:**
- `message` — arbitrary byte string to sign
- `secret_key` — raw secret key bytes from `generate_keypair`
- `alg` — algorithm ID matching the key

**Returns:** raw signature bytes

---

### `verify` *(accessible via `mlpki.keys`)*

```python
def verify(message: bytes, signature: bytes, public_key: bytes, alg: int) -> bool
```

Verify an ML-DSA signature.

**Returns:** `True` if valid, `False` otherwise. Never raises on
cryptographic failure — only on incorrect parameters.

---

### `save_secret_key`

```python
def save_secret_key(
    path: str,
    secret_key: bytes,
    alg: int,
    password: bytes,
) -> None
```

Encrypt and persist a secret key.

- Key derivation: **Argon2id** (`time_cost=3`, `memory_cost=64 MiB`,
  `parallelism=4`) with a 16-byte random salt.
- Encryption: **AES-256-GCM** with a 12-byte random nonce.
- Output: CBOR file (see [formats.md](formats.md) for field layout).

**Parameters:**
- `path` — destination file path
- `secret_key` — raw secret key bytes
- `alg` — algorithm ID
- `password` — arbitrary bytes; use a strong, random password in production

---

### `load_secret_key`

```python
def load_secret_key(path: str, password: bytes) -> tuple[bytes, int]
```

Decrypt and load a secret key from disk.

**Returns:** `(secret_key_bytes, alg_id)`

**Raises:** `ValueError("Decryption failed: …")` if the password is wrong
or the file is corrupted.

---

## `mlpki.csr`

### `CertificateSigningRequest`

```python
@dataclass
class CertificateSigningRequest:
    version:   int
    subject:   Name
    public_key: PublicKeyInfo
    sig_alg:   int
    signature: bytes
    is_ca:     bool
    path_len:  int | None
    key_usage: int
```

#### `CertificateSigningRequest.create`

```python
@classmethod
def create(
    cls,
    subject:   Name,
    pub:       bytes,
    sec:       bytes,
    alg:       int,
    is_ca:     bool = False,
    path_len:  int | None = None,
    key_usage: int = KEY_USAGE_DIGITAL_SIGNATURE,
) -> CertificateSigningRequest
```

Create and self-sign a new CSR. The signature covers all fields except
the signature itself (see [architecture.md](architecture.md)).

#### `verify_self_signature`

```python
def verify_self_signature(self) -> bool
```

Verify the CSR's self-signature. Returns `True` if valid.
Call this before calling `issue_from_csr`.

#### Serialization

| Method | Description |
|---|---|
| `encode() -> bytes` | CBOR encoding |
| `decode(data) -> CertificateSigningRequest` | Decode from CBOR |
| `to_pem() -> str` | PEM export (`-----BEGIN ML-CERTIFICATE REQUEST-----`) |
| `from_pem(pem) -> CertificateSigningRequest` | Import from PEM |

---

## `mlpki.ca`

### `create_root_ca`

```python
def create_root_ca(
    subject:       Name,
    validity_days: int = 3650,
    alg:           int = ALG_ML_DSA_65,
) -> tuple[Certificate, bytes]
```

Create a self-signed root CA certificate and generate a fresh key pair.

Properties of the issued certificate:
- `is_ca = True`
- `path_len = 1`
- `key_usage = KEY_CERT_SIGN | CRL_SIGN | DIGITAL_SIGNATURE`
- `issuer == subject`
- `auth_key_id == subject_key_id`

**Returns:** `(certificate, secret_key_bytes)`

---

### `create_self_signed`

```python
def create_self_signed(
    subject:       Name,
    pub:           bytes,
    sec:           bytes,
    validity_days: int,
    alg:           int,
    key_usage:     int = KEY_USAGE_DIGITAL_SIGNATURE,
    is_ca:         bool = False,
    path_len:      int | None = None,
) -> Certificate
```

Create a self-signed certificate for an externally generated key pair.
Suitable for local services that do not need a CA hierarchy.

---

### `issue_certificate`

```python
def issue_certificate(
    subject:       Name,
    subject_pub:   bytes,
    issuer_cert:   Certificate,
    issuer_sec:    bytes,
    validity_days: int = 365,
    is_ca:         bool = False,
    path_len:      int | None = None,
    key_usage:     int = KEY_USAGE_DIGITAL_SIGNATURE,
) -> Certificate
```

Issue a certificate signed by `issuer_cert`.

- The signing algorithm is taken from `issuer_cert.sig_alg`.
- `subject_key_id` is computed as `SHA3-256(subject_pub)[:16]`.
- `auth_key_id` is taken from `issuer_cert.tbs.subject_key_id`.

---

### `issue_from_csr`

```python
def issue_from_csr(
    csr:          CertificateSigningRequest,
    issuer_cert:  Certificate,
    issuer_sec:   bytes,
    validity_days: int = 365,
) -> Certificate
```

Issue a certificate from a verified CSR, transferring `is_ca`,
`path_len`, and `key_usage` from the CSR.

The caller is responsible for calling `csr.verify_self_signature()` before
passing the CSR to this function.

---

## `mlpki.revocation`

### `RevocationList`

```python
@dataclass
class RevocationList:
    issuer_key_id:   bytes        # 16 bytes
    this_update:     int          # Unix timestamp
    next_update:     int          # Unix timestamp
    revoked_serials: list[bytes]  # list of 16-byte serials
    sig_alg:         int
    signature:       bytes
```

#### `RevocationList.create`

```python
@classmethod
def create(
    cls,
    issuer_cert:      Certificate,
    issuer_sec:       bytes,
    serials:          list[bytes] | None = None,
    next_update_days: int = 30,
) -> RevocationList
```

Create a new, signed CRL. `serials` is the initial list of revoked
serials (may be empty). The `this_update` timestamp is set to `now`.

#### `add_serial`

```python
def add_serial(
    self,
    serial:      bytes,
    issuer_cert: Certificate,
    issuer_sec:  bytes,
) -> RevocationList
```

Return a **new** CRL containing `serial`, re-signed with the current
timestamp. The original CRL is not modified. Duplicate serials are
silently deduplicated.

#### `verify`

```python
def verify(self, issuer_cert: Certificate) -> bool
```

Verify the CRL signature against `issuer_cert`. Returns `True` if valid.

#### `is_revoked`

```python
def is_revoked(self, serial: bytes) -> bool
```

Return `True` if `serial` is in the revocation list.

#### Serialization

| Method | Description |
|---|---|
| `encode() -> bytes` | CBOR encoding |
| `decode(data) -> RevocationList` | Decode from CBOR |

---

## `mlpki.verify`

### `VerificationCode`

```python
class VerificationCode(Enum):
    INVALID_SIGNATURE      = "invalid_signature"
    EXPIRED                = "expired"
    NOT_YET_VALID          = "not_yet_valid"
    NOT_CA                 = "not_ca"
    MISSING_KEY_CERT_SIGN  = "missing_key_cert_sign"
    PATH_LEN_EXCEEDED      = "path_len_exceeded"
    AUTH_KEY_ID_MISMATCH   = "auth_key_id_mismatch"
    REVOKED                = "revoked"
    CHAIN_TOO_SHORT        = "chain_too_short"
    UNTRUSTED_ROOT         = "untrusted_root"
```

### `VerificationError`

```python
class VerificationError(Exception):
    def __init__(self, message: str, code: VerificationCode) -> None: ...
    code: VerificationCode
```

Raised by all verification functions on failure.

```python
try:
    verify_chain(chain, trusted_root=root_cert, crl=crl)
except VerificationError as e:
    print(e)          # human-readable message
    print(e.code)     # VerificationCode enum value
    print(e.code.value)  # string, e.g. "revoked"
```

---

### `verify_signature`

```python
def verify_signature(cert: Certificate, issuer_cert: Certificate) -> None
```

Verify that `cert` is signed by `issuer_cert`. Does **not** check
validity windows, key usage, or chain constraints.

**Raises:** `VerificationError(…, INVALID_SIGNATURE)`

---

### `verify_self_signed`

```python
def verify_self_signed(cert: Certificate) -> None
```

Verify a self-signed certificate (root CA or self-signed end-entity).
Uses the certificate's own public key as the verifying key.

**Raises:** `VerificationError(…, INVALID_SIGNATURE)`

---

### `verify_chain`

```python
def verify_chain(
    chain:        list[Certificate],
    trusted_root: Certificate,
    crl:          RevocationList | None = None,
) -> None
```

Full path validation.

**Parameters:**
- `chain` — ordered list of certificates, **end-entity first**, last
  intermediate last. Must not include the trusted root.
- `trusted_root` — the self-signed root CA certificate to anchor the chain.
- `crl` — optional CRL; if provided, every certificate's serial is checked.

**Raises:** `VerificationError` with the appropriate `VerificationCode`
on the first failure encountered.

**Example — two-level hierarchy:**
```python
# chain = [intermediate, end_entity]
verify_chain([inter_cert, ee_cert], trusted_root=root_cert)
```

**Example — single-level (root issues EE directly):**
```python
verify_chain([ee_cert], trusted_root=root_cert)
```
