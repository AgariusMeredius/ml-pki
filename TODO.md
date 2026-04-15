# TODO — mlpki Improvements and Hardening

This list collects planned extensions, security hardening measures, and
quality improvements for `mlpki`. Items are grouped by category and ordered
roughly by priority within each group.

> **Note:** This project was developed and audited with AI assistance and has
> not undergone independent human peer review. Several items below address
> known limitations documented in [`AUDIT.md`](AUDIT.md) and
> [`docs/security.md`](docs/security.md).

---

## Security Hardening

- [ ] **Memory zeroing for secret keys** (`keys.py`)<br>
  Python does not zero memory on garbage collection. Introduce a
  `SecretKey` wrapper that calls `ctypes.memset` on the underlying buffer
  when the object is finalised, reducing the window in which key material
  sits in heap memory after use.

- [ ] **Minimum clock skew tolerance** (`verify.py`)<br>
  `verify_chain` uses exact integer comparisons for `not_before` /
  `not_after`. Add an optional `clock_skew_seconds` parameter (default 0,
  recommended ≤ 60) so that freshly issued certificates do not fail
  `NOT_YET_VALID` due to NTP drift between signer and verifier.

- [ ] **Name constraints extension** (`certificate.py`, `ca.py`, `verify.py`)<br>
  Add a `name_constraints` field to `TBSCertificate` restricting the
  subject namespace of subordinate CAs (RFC 5280 §4.2.1.10). Enforce
  permitted/excluded subtrees during chain validation. This is the most
  significant missing RFC 5280 feature.

- [ ] **Certificate policy extensions** (`certificate.py`, `verify.py`)<br>
  Add a `policy_oids` field and enforce `requireExplicitPolicy` / policy
  mapping during chain validation (RFC 5280 §4.2.1.4). Required for
  formal PKI policy frameworks.

- [ ] **Delta CRL support** (`revocation.py`, `verify.py`)<br>
  For large revocation lists, implement incremental delta CRLs (RFC 5280
  §5.2.4) so that relying parties do not need to download the full CRL on
  every update cycle.

- [ ] **Rate-limit / issuance-policy hook in `issue_certificate`** (`ca.py`)<br>
  Add a pluggable `policy` callback parameter so callers can enforce
  naming rules, rate limits, or organisational vetting without forking the
  library. Currently the CA must re-implement policy on top of the API.

- [ ] **Audit logging for CA operations** (`ca.py`)<br>
  Emit structured (JSON) log entries for every certificate issuance,
  CSR acceptance/rejection, and CRL update. This provides a tamper-evident
  audit trail without requiring callers to instrument every call site.

---

## Algorithm and Cryptography

- [ ] **SLH-DSA (FIPS 205 / SPHINCS+) support**<br>
  Add `ALG_SLH_DSA_*` constants and plumb them through `generate_keypair`,
  `sign`, `verify`, and the key file format. SLH-DSA is stateless and
  hash-based — a useful diversity option for long-lived root CA keys.

- [ ] **FALCON / FN-DSA support**<br>
  Add `ALG_FALCON_512` and `ALG_FALCON_1024`. FALCON has smaller signatures
  than ML-DSA at equivalent security levels, making it attractive for
  bandwidth-constrained environments.

- [ ] **Hybrid (composite) signatures**<br>
  Implement composite certificates that carry both a classical (e.g.
  Ed25519) and a post-quantum (ML-DSA) signature over the same TBS bytes.
  This supports migration scenarios where verifiers may not yet support
  ML-DSA but must remain secure if one primitive is broken.

- [ ] **ML-KEM integration for encrypted channels**<br>
  `mlpki` currently covers authentication only. Add an optional companion
  module (`mlpki.kem`) using ML-KEM (FIPS 203) to negotiate shared secrets
  — the minimal building block for an encrypted, mutually authenticated
  channel using this PKI.

- [ ] **NIST official test vectors**<br>
  Add a test module that runs NIST-published ML-DSA Known-Answer Tests
  (KATs) against the liboqs implementation to catch regressions when
  upgrading the native library.

---

## Revocation and Status

- [ ] **OCSP-like responder interface**<br>
  Implement a lightweight real-time revocation status protocol as an
  alternative to batch CRL. An `OCSPRequest` / `OCSPResponse` pair (or a
  simplified custom CBOR equivalent) would let relying parties query
  revocation status for a single serial without downloading the full CRL.

- [ ] **CRL Distribution Points in certificates** (`certificate.py`, `ca.py`)<br>
  Add a `crl_distribution_points` field to `TBSCertificate` so that
  verifiers can automatically fetch the current CRL via URL rather than
  requiring callers to supply it out-of-band.

- [ ] **Automatic CRL refresh helper**<br>
  Add a `CRLFetcher` utility (optional dependency: `httpx` or `urllib`)
  that fetches, verifies, and caches CRLs from distribution points,
  surfacing `CRL_EXPIRED` before it causes a verification failure.

---

## API and Usability

- [ ] **Async-friendly API** (`ca.py`, `verify.py`)<br>
  Expose `async` variants of the signing and verification functions so
  that the CPU-heavy liboqs operations can be offloaded to a thread pool
  (`asyncio.to_thread`) without blocking an event loop.

- [ ] **`pathlib.Path` support throughout**<br>
  Extend `save_secret_key` / `load_secret_key` and certificate file I/O
  to accept `pathlib.Path` in addition to `str`, matching modern Python
  conventions.

- [ ] **Certificate builder / fluent API** (`ca.py`)<br>
  Add a `CertificateBuilder` class with a fluent interface as a more
  ergonomic alternative to the current keyword-heavy `issue_certificate`
  signature. Reduces the risk of callers accidentally omitting fields.

- [ ] **`__slots__` on dataclasses** (`certificate.py`, `csr.py`, `revocation.py`)<br>
  Adding `__slots__` reduces per-instance memory overhead and prevents
  accidental attribute injection, which is a minor hardening measure for
  library objects that should be treated as value types.

---

## Infrastructure and Quality

- [ ] **Continuous Integration (CI)**<br>
  Add a GitHub Actions workflow that runs `pytest` against Python 3.11,
  3.12, and 3.13, builds liboqs from source, and publishes coverage reports.
  Include a nightly job that tests against the latest liboqs `main` branch.

- [ ] **Performance benchmarks**<br>
  Add a `benchmarks/` suite (e.g. using `pytest-benchmark`) measuring
  key generation, signing, verification, and chain validation for all
  three ML-DSA variants. Track regressions across liboqs versions.

- [ ] **liboqs version pinning and deprecation warnings**<br>
  At import time, check the loaded liboqs version against a tested-and-
  known-good range. Warn (or raise) if the installed version is outside
  that range, preventing silent behaviour changes after a `liboqs` upgrade.

- [ ] **`py.typed` marker and full type coverage**<br>
  Add a `py.typed` marker file and run `mypy --strict` in CI. Several
  internal helpers currently lack return-type annotations, which reduces
  tooling support for callers using type checkers.

- [ ] **Packaging: publish to PyPI**<br>
  Finalize `pyproject.toml` classifiers, add a `CHANGELOG.md`, and set up
  a GitHub Actions release workflow that builds and uploads source + wheel
  distributions to PyPI on version tags.

- [ ] **Independent security review**<br>
  Commission a formal third-party security audit by qualified
  cryptographers before any production deployment. The current audit
  (`AUDIT.md`) was AI-assisted and does not substitute for human expert
  review.
