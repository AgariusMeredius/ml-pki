"""
Certificate chain verification with full path validation.
"""

from __future__ import annotations

import time
from enum import Enum
from typing import Optional

from .certificate import Certificate
from .constants import (
    KEY_USAGE_KEY_CERT_SIGN,
)
from .keys import verify as _verify_sig
from .revocation import RevocationList


class VerificationCode(Enum):
    """Error codes for verification failures."""

    INVALID_SIGNATURE = "invalid_signature"
    EXPIRED = "expired"
    NOT_YET_VALID = "not_yet_valid"
    NOT_CA = "not_ca"
    MISSING_KEY_CERT_SIGN = "missing_key_cert_sign"
    PATH_LEN_EXCEEDED = "path_len_exceeded"
    AUTH_KEY_ID_MISMATCH = "auth_key_id_mismatch"
    REVOKED = "revoked"
    CHAIN_TOO_SHORT = "chain_too_short"
    UNTRUSTED_ROOT = "untrusted_root"


class VerificationError(Exception):
    """Raised when certificate verification fails."""

    def __init__(self, message: str, code: VerificationCode) -> None:
        super().__init__(message)
        self.code = code


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------

def verify_signature(cert: Certificate, issuer_cert: Certificate) -> None:
    """
    Verify that *cert* is signed by *issuer_cert*.

    Raises VerificationError on failure.
    """
    issuer_pub = issuer_cert.tbs.public_key.key_bytes
    alg = cert.sig_alg
    ok = _verify_sig(cert.tbs_bytes, cert.signature, issuer_pub, alg)
    if not ok:
        raise VerificationError(
            "Signature verification failed",
            VerificationCode.INVALID_SIGNATURE,
        )


def verify_self_signed(cert: Certificate) -> None:
    """
    Verify a self-signed certificate (root CA or self-signed end-entity).

    Uses the certificate's own public key as the issuer key.

    Raises VerificationError on failure.
    """
    pub = cert.tbs.public_key.key_bytes
    alg = cert.sig_alg
    ok = _verify_sig(cert.tbs_bytes, cert.signature, pub, alg)
    if not ok:
        raise VerificationError(
            "Self-signed signature verification failed",
            VerificationCode.INVALID_SIGNATURE,
        )


def verify_chain(
    chain: list[Certificate],
    trusted_root: Certificate,
    crl: Optional[RevocationList] = None,
) -> None:
    """
    Verify a certificate chain against *trusted_root*.

    *chain* must be ordered from the end-entity certificate (index 0)
    up to but not including the trusted root. The trusted root itself is
    provided separately via *trusted_root*.

    Checks performed (in order):
    1. Trusted root self-signature
    2. For each certificate in the chain (from root down to EE):
       a. Temporal validity
       b. Issuer is a CA (is_ca flag)
       c. Issuer has KEY_CERT_SIGN key usage
       d. path_len constraint
       e. Authority Key ID matching
       f. Signature from the issuer
       g. Revocation (if CRL provided)

    Raises VerificationError with a descriptive code on the first failure.
    """
    if not chain:
        raise VerificationError(
            "Certificate chain is empty",
            VerificationCode.CHAIN_TOO_SHORT,
        )

    # Verify the trusted root is self-signed and temporally valid
    verify_self_signed(trusted_root)
    _check_validity(trusted_root)

    # Full chain: [trusted_root] + chain (root first, EE last)
    full = [trusted_root] + list(chain)

    for depth, cert in enumerate(chain):
        issuer = full[depth]  # issuer of chain[depth] is full[depth]
        issuer_tbs = issuer.tbs
        cert_tbs = cert.tbs

        # Temporal validity of the *current* certificate
        _check_validity(cert)

        # Issuer must be a CA
        if not issuer_tbs.is_ca:
            raise VerificationError(
                f"Issuer at depth {depth} is not a CA",
                VerificationCode.NOT_CA,
            )

        # Issuer must have KEY_CERT_SIGN
        if not (issuer_tbs.key_usage & KEY_USAGE_KEY_CERT_SIGN):
            raise VerificationError(
                f"Issuer at depth {depth} missing KEY_CERT_SIGN",
                VerificationCode.MISSING_KEY_CERT_SIGN,
            )

        # path_len constraint: number of CA certs that may follow
        if issuer_tbs.path_len is not None:
            # depth = 0 means issuer is the root; count intermediate CAs below it
            remaining_ca_certs = sum(1 for c in chain[depth:] if c.tbs.is_ca)
            if remaining_ca_certs > issuer_tbs.path_len:
                raise VerificationError(
                    f"path_len constraint violated at depth {depth}",
                    VerificationCode.PATH_LEN_EXCEEDED,
                )

        # Authority Key ID matching
        if cert_tbs.auth_key_id != issuer_tbs.subject_key_id:
            raise VerificationError(
                f"Authority key ID mismatch at depth {depth}",
                VerificationCode.AUTH_KEY_ID_MISMATCH,
            )

        # Signature
        verify_signature(cert, issuer)

        # Revocation check
        if crl is not None and crl.is_revoked(cert_tbs.serial):
            raise VerificationError(
                f"Certificate at depth {depth} has been revoked",
                VerificationCode.REVOKED,
            )


# ---------------------------------------------------------------------------
# Internal helpers
# ---------------------------------------------------------------------------

def _check_validity(cert: Certificate) -> None:
    """Raise VerificationError if *cert* is outside its validity window."""
    now = int(time.time())
    tbs = cert.tbs
    if now < tbs.not_before:
        raise VerificationError(
            "Certificate is not yet valid",
            VerificationCode.NOT_YET_VALID,
        )
    if now > tbs.not_after:
        raise VerificationError(
            "Certificate has expired",
            VerificationCode.EXPIRED,
        )
