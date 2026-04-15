# Security & Functionality Audit — ML-PKI

**System:** mlpki v0.1.0 — Post-Quantum PKI Library (ML-DSA / FIPS 204)  
**Audit date:** 2026-04-13  
**Auditor:** Claude (Anthropic) — automated code audit  
**Branch:** `claude/audit-pqc-pki-system-U3fIp`

---

## 1. Executive Summary

`mlpki` is a Python library implementing a post-quantum Public Key Infrastructure based on ML-DSA (FIPS 204) and CBOR serialization. The library covers the full PKI lifecycle: key generation, certificate issuance (root CA, intermediate, end-entity, and CSR-based), revocation via CRL, and multi-level chain verification.

The codebase is well-structured and demonstrates solid cryptographic design choices (authenticated encryption for key files, quantum-safe signatures, canonical CBOR encoding, immutable CRL updates). The audit identified **four critical/high-severity security gaps** and **four medium-severity issues** that were fixed as part of this audit.

**Overall verdict before fixes:** MODERATE risk — functional, but with exploitable logic flaws  
**Overall verdict after fixes:** LOW risk — all identified issues resolved, 144 tests passing

---

## 2. Scope

| Component | Files |
|---|---|
| Core library | `mlpki/ca.py`, `mlpki/verify.py`, `mlpki/revocation.py`, `mlpki/certificate.py`, `mlpki/keys.py`, `mlpki/csr.py`, `mlpki/constants.py` |
| Tests | `tests/test_ca.py`, `tests/test_verify.py`, `tests/test_revocation.py`, `tests/test_keys.py`, `tests/test_certificate.py`, `tests/test_csr.py`, `tests/test_chain.py`, `tests/conftest.py` |
| Examples | `examples/` (5 files, reviewed for API misuse) |
| Documentation | `docs/` (architecture, api-reference, formats, security) |

---

## 3. Cryptographic Primitives Assessment

### 3.1 ML-DSA (FIPS 204) — PASS

- Implemented via `liboqs` (Open Quantum Safe project)
- Three variants offered: ML-DSA-44 (NIST Level 2), ML-DSA-65 (Level 3, default), ML-DSA-87 (Level 5)
- Signing is correctly randomised per FIPS 204 specification
- Key generation uses `liboqs`'s internal DRBG seeded from OS entropy

**Recommendation:** ML-DSA-65 is appropriate for most deployments. Use ML-DSA-87 for certificates with lifetime > 10 years.

### 3.2 SHA3-256 — PASS

- Used for subject key identifiers (truncated to 16 bytes for matching)
- Used for certificate fingerprints (full 32-byte digest)
- Quantum-safe at full output length; 16-byte truncation is for identifier matching only, not cryptographic binding

### 3.3 Argon2id + AES-256-GCM (key files) — PASS

- Argon2id defaults: time_cost=3, memory_cost=64 MiB, parallelism=4 — above OWASP minimums
- 16-byte random salt and 12-byte random nonce unique per key file
- AES-256-GCM provides authenticated encryption; tag covers both ciphertext and metadata
- Error messages are generic, preventing oracle attacks

### 3.4 CBOR Serialisation — PASS

- Integer-only field keys prevent string injection
- Signatures computed over raw canonical CBOR bytes prevent re-encoding ambiguity
- Separate TBS/signature structure matches standard X.509 design pattern

---

## 4. Functional Audit

### 4.1 Key Operations (`keys.py`)

| Check | Result |
|---|---|
| Key generation delegates to liboqs correctly | PASS |
| Signing uses correct algorithm OID | PASS |
| Verification returns bool without exception leakage | PASS |
| Key file encryption uses authenticated encryption | PASS |
| Salt/nonce freshness (unique per file) | PASS |
| Argon2id parameters correctly passed on save | PASS |

### 4.2 Certificate Construction (`certificate.py`, `ca.py`)

| Check | Result |
|---|---|
| TBSCertificate encodes all 12 fields | PASS |
| Signature computed over TBS bytes only | PASS |
| subject_key_id = SHA3-256(pub)[:16] | PASS |
| auth_key_id = issuer's subject_key_id | PASS |
| Random 16-byte serial via os.urandom | PASS |
| PEM round-trip preserves all fields | PASS |
| Self-signed: issuer == subject, auth_kid == skid | PASS |
| Fingerprint uses full SHA3-256 digest | PASS |

### 4.3 CSR Workflow (`csr.py`)

| Check | Result |
|---|---|
| CSR signature excludes the signature field itself | PASS |
| Self-signature covers all TBS fields | PASS |
| PEM round-trip preserves all CSR fields | PASS |
| Decoded CSR requires explicit signature verification | PASS (now automatic in `issue_from_csr`) |

### 4.4 Chain Verification (`verify.py`)

| Check | Result |
|---|---|
| Root self-signature verified first | PASS |
| Root temporal validity checked | PASS |
| Each cert's temporal validity checked | PASS |
| Issuer is_ca flag enforced | PASS |
| Issuer KEY_CERT_SIGN usage enforced | PASS |
| path_len constraint enforced (RFC 5280 semantics) | PASS |
| auth_key_id ↔ issuer subject_key_id matching | PASS |
| Signature verified over raw tbs_bytes | PASS |
| CRL revocation check by serial | PASS |

### 4.5 CRL Operations (`revocation.py`)

| Check | Result |
|---|---|
| CRL signed over all fields except signature | PASS |
| add_serial preserves next_update interval | PASS |
| add_serial deduplicates entries | PASS |
| Immutable update pattern (new instance on change) | PASS |
| CBOR round-trip preserves all fields | PASS |

---

## 5. Security Findings and Fixes

### FINDING 1 — CRITICAL: No Issuer Validation in `issue_certificate()`

**File:** `mlpki/ca.py:133`  
**Severity:** Critical  
**Status:** Fixed

**Description:**  
`issue_certificate()` accepted any `Certificate` as `issuer_cert` without verifying that the issuer actually had the authority to sign certificates (`is_ca=True` and `KEY_CERT_SIGN` key usage). An attacker who could construct a certificate chain would be able to present an end-entity certificate as an issuer, producing a certificate that claimed a trusted lineage it did not have.

**Impact:**  
- Certificates could be issued from non-CA issuers
- Resulting certificates would fail `verify_chain`, but the malformed cert might be accepted by implementations that only check the signature and not the CA flag

**Fix applied (`mlpki/ca.py`):**
```python
# Added to issue_certificate()
if not issuer_tbs.is_ca:
    raise ValueError("Issuer certificate is not a CA (is_ca must be True)")
if not (issuer_tbs.key_usage & KEY_USAGE_KEY_CERT_SIGN):
    raise ValueError("Issuer certificate lacks KEY_CERT_SIGN key usage")
```

---

### FINDING 2 — CRITICAL: Path Length Constraint Not Enforced at Issuance

**File:** `mlpki/ca.py:109,133`  
**Severity:** Critical  
**Status:** Fixed

**Description:**  
When issuing a CA certificate (`is_ca=True`), neither `issue_certificate()` nor `issue_from_csr()` validated the requested `path_len` against the issuer's constraint. A CSR or direct call could request an arbitrarily large `path_len` even when the issuer's `path_len=1` should limit sub-CAs to `path_len=0`.

**Impact:**  
- A sub-CA could claim `path_len=99`, gaining excessive certificate issuance authority
- If this sub-CA were used as a trust anchor in a different context (cross-certification), it would permit arbitrarily deep certificate chains
- This bypasses defence-in-depth — `verify_chain` still catches it during validation, but the window exists between issuance and first verification

**Fix applied (`mlpki/ca.py`):**
```python
# Added to issue_certificate()
if is_ca and issuer_tbs.path_len is not None:
    if issuer_tbs.path_len == 0:
        raise ValueError("Issuer path_len=0 forbids issuing CA certificates")
    max_sub_path_len = issuer_tbs.path_len - 1
    if path_len is None or path_len > max_sub_path_len:
        raise ValueError(
            f"Requested path_len ({path_len!r}) exceeds the maximum allowed "
            f"by the issuer's constraint (max: {max_sub_path_len})"
        )
```

---

### FINDING 3 — HIGH: CRL Not Authenticated in `verify_chain()`

**File:** `mlpki/verify.py:80`  
**Severity:** High  
**Status:** Fixed

**Description:**  
`verify_chain()` accepted a `RevocationList` and used it for revocation checks without:
1. Verifying the CRL's ML-DSA signature
2. Confirming the CRL was issued by a CA in the verified chain (`issuer_key_id` matching)
3. Checking the CRL's freshness (`next_update` timestamp)

An attacker who could substitute or tamper with the CRL could:
- **Inject revocations**: Revoke valid certificates by providing a forged CRL with their serials
- **Remove revocations**: Present a stale CRL that pre-dates a revocation event
- **Use a foreign CRL**: Pass a CRL from an unrelated CA that happens to list valid serials

**Fix applied (`mlpki/verify.py`):**
```python
# Added CRL pre-validation block before the chain loop
if crl is not None:
    now = int(time.time())
    # 1. Locate CRL issuer in the chain
    crl_issuer = next(
        (c for c in full if c.tbs.subject_key_id == crl.issuer_key_id), None
    )
    if crl_issuer is None:
        raise VerificationError("CRL issuer not found in chain", VerificationCode.CRL_UNTRUSTED)
    # 2. Verify CRL signature
    if not crl.verify(crl_issuer):
        raise VerificationError("CRL signature is invalid", VerificationCode.INVALID_SIGNATURE)
    # 3. Enforce freshness
    if crl.next_update < now:
        raise VerificationError("CRL has expired", VerificationCode.CRL_EXPIRED)
```

New `VerificationCode` values added: `CRL_EXPIRED`, `CRL_UNTRUSTED`, `CHAIN_TOO_LONG`.

---

### FINDING 4 — HIGH: CSR Self-Signature Not Verified Before Issuance

**File:** `mlpki/ca.py:109`  
**Severity:** High  
**Status:** Fixed

**Description:**  
`issue_from_csr()` had a docstring note "The CSR's self-signature must have been verified before calling this" but provided no enforcement. Callers that forgot to call `csr.verify_self_signature()` first would issue certificates for CSRs that might be forged or tampered — potentially binding the CA's signature to a public key the applicant does not actually possess (key substitution attack).

**Fix applied (`mlpki/ca.py`):**
```python
def issue_from_csr(...) -> Certificate:
    if not csr.verify_self_signature():
        raise ValueError("CSR self-signature is invalid")
    return issue_certificate(...)
```

---

### FINDING 5 — MEDIUM: No Maximum Chain Depth Limit

**File:** `mlpki/verify.py:80`  
**Severity:** Medium  
**Status:** Fixed

**Description:**  
`verify_chain()` had no upper bound on chain length. A maliciously crafted or accidentally constructed chain with thousands of certificates would cause linear-time processing, enabling DoS.

**Fix applied (`mlpki/verify.py`):**
```python
def verify_chain(
    chain: list[Certificate],
    trusted_root: Certificate,
    crl: Optional[RevocationList] = None,
    max_depth: int = 10,          # New parameter
) -> None:
    if len(chain) > max_depth:
        raise VerificationError(
            f"Certificate chain depth ({len(chain)}) exceeds maximum allowed ({max_depth})",
            VerificationCode.CHAIN_TOO_LONG,
        )
```

---

### FINDING 6 — MEDIUM: `Certificate._tbs` Equality Bug

**File:** `mlpki/certificate.py:147`  
**Severity:** Medium  
**Status:** Fixed

**Description:**  
The `_tbs` field (lazy-decoded TBS cache) was included in the dataclass-generated `__eq__` comparison. Two `Certificate` objects with identical `tbs_bytes`, `sig_alg`, and `signature` would compare as **unequal** if one had `_tbs` populated (after accessing `.tbs`) and the other had it as `None`. This could cause subtle bugs in application code that stores or compares certificates.

**Fix applied (`mlpki/certificate.py`):**
```python
_tbs: Optional[TBSCertificate] = field(
    default=None, compare=False, repr=False, hash=False
)
```
Also removed the redundant `object.__setattr__` call (unnecessary for non-frozen dataclasses):
```python
@property
def tbs(self) -> TBSCertificate:
    if self._tbs is None:
        self._tbs = TBSCertificate.decode(self.tbs_bytes)
    return self._tbs
```

---

### FINDING 7 — MEDIUM: Tampered Key File Can Downgrade Argon2 Work Factor

**File:** `mlpki/keys.py:140`  
**Severity:** Medium  
**Status:** Fixed

**Description:**  
`load_secret_key()` read Argon2id parameters (time_cost, memory_cost, parallelism) from the key file and used them verbatim. An attacker who gained write access to the key file could set `memory_cost=1` (1 KiB instead of 64 MiB), making brute-force of the password approximately 65,536× faster. The algorithm ID was similarly unchecked.

**Fix applied (`mlpki/keys.py`):**
```python
_MIN_ARGON2_TIME_COST: int = 1
_MIN_ARGON2_MEMORY_COST: int = 8192   # 8 MiB absolute floor
_MIN_ARGON2_PARALLELISM: int = 1

# In load_secret_key():
if alg not in ALG_NAMES:
    raise ValueError(f"Unknown algorithm ID in key file: {alg!r}")
if time_cost < _MIN_ARGON2_TIME_COST:
    raise ValueError(f"Key file time_cost={time_cost} is below the minimum ...")
if memory_cost < _MIN_ARGON2_MEMORY_COST:
    raise ValueError(f"Key file memory_cost={memory_cost} KiB is below the minimum ...")
if parallelism < _MIN_ARGON2_PARALLELISM:
    raise ValueError(f"Key file parallelism={parallelism} is below the minimum ...")
```

---

### FINDING 8 — MEDIUM: O(n) Revocation Lookup

**File:** `mlpki/revocation.py:134`  
**Severity:** Medium (Performance / Correctness)  
**Status:** Fixed

**Description:**  
`is_revoked()` performed a linear scan through `revoked_serials` (`serial in self.revoked_serials`). For large CRLs (e.g., 100,000+ revoked certificates), this becomes a bottleneck for every certificate verification, particularly in high-throughput validation scenarios.

**Fix applied (`mlpki/revocation.py`):**
```python
def __post_init__(self) -> None:
    self._revoked_set: frozenset = frozenset(self.revoked_serials)

def is_revoked(self, serial: bytes) -> bool:
    return serial in self._revoked_set   # O(1)
```
The frozenset is rebuilt whenever a new `RevocationList` instance is created (create, add_serial, decode), keeping it always in sync.

---

### FINDING 9 — MEDIUM: No Input Size Limits on CBOR-Decoded Structures

**File:** `mlpki/certificate.py:128,59`  
**Severity:** Medium  
**Status:** Fixed

**Description:**  
`Name.from_map()` and `TBSCertificate.decode()` accepted arbitrary-length strings and byte sequences from CBOR without size limits. A crafted certificate with gigabyte-long `cn` or `org` fields could cause excessive memory consumption during parsing.

**Fix applied (`mlpki/certificate.py`):**
```python
_MAX_NAME_FIELD_LEN: int = 256
_SERIAL_LEN: int = 16
_KEY_ID_LEN: int = 16

# In Name.from_map():
if len(cn) > _MAX_NAME_FIELD_LEN:
    raise ValueError(f"Name.cn exceeds maximum length ({_MAX_NAME_FIELD_LEN})")
# ... similar checks for org and ou

# In TBSCertificate.decode():
if len(serial) != _SERIAL_LEN:
    raise ValueError(f"TBS serial must be exactly {_SERIAL_LEN} bytes ...")
if len(subject_key_id) != _KEY_ID_LEN:
    raise ValueError(f"subject_key_id must be exactly {_KEY_ID_LEN} bytes ...")
if len(auth_key_id) != _KEY_ID_LEN:
    raise ValueError(f"auth_key_id must be exactly {_KEY_ID_LEN} bytes ...")
```

---

## 6. Findings Not Fixed (Accepted Risk / Out of Scope)

### 6.1 Python Memory Security for Secret Keys

**Severity:** Low  
**Status:** Accepted (documented)

Secret key bytes reside in plain Python `bytes` objects. Python's garbage collector does not guarantee zeroing of freed memory. For long-running processes that handle many keys, residual key material could remain in heap memory.

**Recommendation:** Keep secret keys in scope only as long as needed. Do not cache them in global state. Consider third-party `zeroize` bindings for HSM-equivalent security. This is documented in `docs/security.md`.

### 6.2 No Clock Skew Tolerance

**Severity:** Low  
**Status:** Accepted

`verify_chain()` uses exact integer timestamp comparison (`int(time.time())`). On systems with NTP clock drift, a certificate valid from `now-1` could be rejected if the verifier's clock is 1 second behind. This is documented in `docs/security.md`.

**Recommendation:** Add an optional `clock_skew_seconds: int = 0` parameter to `verify_chain()` for environments with known clock drift.

### 6.3 No OCSP Support

**Severity:** Informational  
**Status:** Out of scope

Only batch CRL revocation is implemented. Real-time revocation via OCSP is not supported. This is an architecture decision, documented in `docs/security.md`.

### 6.4 Potential Thread Safety of `Certificate.tbs` Cache

**Severity:** Low (theoretical)  
**Status:** Accepted

The lazy `_tbs` initialisation (`if self._tbs is None: self._tbs = ...`) is not synchronised. Under concurrent access from multiple threads, two threads might both decode `tbs_bytes` and assign `_tbs`. Due to Python's GIL, the attribute assignment is atomic, and both threads write the same value, so the race is benign. The equality fix (Finding 6) prevents the pre-existing consistency issue.

---

## 7. Test Coverage Summary

| Module | Tests before | Tests after | New tests added |
|---|---|---|---|
| test_ca.py | 14 | 28 | 14 (issuer validation, path_len enforcement, CSR sig check) |
| test_verify.py | 14 | 25 | 11 (max_depth, CRL freshness, CRL sig, CRL untrusted, path_len/key_usage via direct cert construction) |
| test_revocation.py | 13 | 13 | 0 (existing tests cover frozenset behaviour) |
| test_certificate.py | 20 | 20 | 0 |
| test_csr.py | 16 | 16 | 0 |
| test_keys.py | 18 | 18 | 0 |
| test_chain.py | 34 | 24 | -10* |

*The path_len and missing-key-usage chain tests were restructured to use direct certificate construction rather than `issue_certificate()`, since `issue_certificate()` now enforces these constraints at issuance time. The tests continue to cover `verify_chain()`'s independent enforcement.

**Total: 129 → 144 tests, all passing**

---

## 8. Code Quality Observations

### Positive

- Consistent type annotations throughout (Python 3.11+)
- Clear module separation with single-responsibility design
- Immutable CRL update pattern prevents accidental mutation of signed data
- `VerificationCode` enum provides structured error handling
- Custom PEM headers distinguish mlpki formats from X.509 (reduces parser confusion)
- Canonical CBOR encoding with integer-only keys prevents injection

### Improvements Made

- Added `_MAX_VALIDITY_DAYS` constant in `ca.py` (not yet enforced at issuance — future hardening)
- Removed `object.__setattr__` from the `Certificate.tbs` property (unnecessary for mutable dataclass)
- Added `field(compare=False, repr=False, hash=False)` to the `_tbs` cache field

---

## 9. Dependency Assessment

| Library | Version | Role | Status |
|---|---|---|---|
| `liboqs` (C) | 0.15.0 | ML-DSA primitives | PASS — keep updated for FIPS 204 compliance fixes |
| `liboqs-python` | 0.14.0 | Python bindings | PASS — minor version mismatch with liboqs (0.14 vs 0.15) is API-compatible |
| `cbor2` | ≥5.6 | CBOR encoding | PASS — pure Python; audit if parsing attacker-controlled data |
| `argon2-cffi` | ≥23.1 | Argon2id KDF | PASS — well-audited C implementation |
| `cryptography` (PyCA) | ≥42.0 | AES-256-GCM | PASS — extensively audited; update regularly |

**Recommendation:** Pin exact versions in production deployments (`pip freeze > requirements-lock.txt`). Subscribe to OpenQuantumSafe security advisories.

---

## 10. Architecture Observations

### Strengths

1. **Two-layer certificate structure**: Signature computed over raw `tbs_bytes` prevents any re-encoding ambiguity attack
2. **Algorithm inheritance**: `issue_certificate` copies the algorithm from the issuer certificate, preventing algorithm downgrade
3. **Auth Key ID linking**: Connects each certificate to its specific issuer key, not just issuer name
4. **Path length semantics**: Correctly follows RFC 5280 (counts CA certs below issuer, not total depth)

### Gaps (for future work)

1. **No Name Constraints extension**: CAs cannot restrict the subject namespace for subordinate CAs
2. **No Extended Key Usage**: Cannot restrict certificates to specific use cases (TLS server, code signing)
3. **No OCSP stapling**: Revocation requires out-of-band CRL distribution
4. **No certificate policies extension**: Cannot encode issuance policy OIDs

---

## 11. Recommendations for Production Deployment

1. **Key management**: Use ML-DSA-87 for root CA keys; store offline or in HSM; use strong random passwords (≥32 bytes from `secrets.token_bytes()`)
2. **Certificate lifetimes**: Root CA ≤ 20 years; intermediate ≤ 5 years; end-entity ≤ 1 year
3. **CRL policy**: Refresh CRLs every 24 hours; set `next_update_days=7` maximum; validate freshness before use (now enforced automatically by `verify_chain`)
4. **Chain depth**: Default `max_depth=10` is conservative; lower to 3-4 for flat PKI hierarchies
5. **Argon2id**: Current defaults (64 MiB, t=3, p=4) are appropriate; increase `time_cost` to 5 for HSM-grade key files
6. **Dependency updates**: Follow `liboqs` releases closely as FIPS 204 implementation improvements are ongoing

---

## 12. Change Log

| File | Change | Finding |
|---|---|---|
| `mlpki/ca.py` | Added issuer `is_ca` + `KEY_CERT_SIGN` validation | #1 |
| `mlpki/ca.py` | Added path_len constraint enforcement at issuance | #2 |
| `mlpki/ca.py` | Auto-verify CSR self-signature in `issue_from_csr()` | #4 |
| `mlpki/verify.py` | CRL issuer lookup, signature verification, freshness check | #3 |
| `mlpki/verify.py` | `max_depth` parameter for `verify_chain()` | #5 |
| `mlpki/verify.py` | New `VerificationCode` values: `CRL_EXPIRED`, `CRL_UNTRUSTED`, `CHAIN_TOO_LONG` | #3, #5 |
| `mlpki/certificate.py` | Fixed `_tbs` field equality/repr exclusion | #6 |
| `mlpki/certificate.py` | Added input size limits in `Name.from_map()` and `TBSCertificate.decode()` | #9 |
| `mlpki/keys.py` | Minimum Argon2id parameter validation on key file load | #7 |
| `mlpki/revocation.py` | O(1) revocation lookup via internal `frozenset` | #8 |
| `tests/test_ca.py` | 14 new tests covering issuer validation and path_len enforcement | — |
| `tests/test_verify.py` | 11 new/restructured tests for chain depth, CRL validation, path_len, key usage | — |
