"""
Certificate Authority operations.

Provides functions to create root CAs, issue certificates from CSRs,
and issue certificates directly.
"""

from __future__ import annotations

import hashlib
import os
import time
from typing import Optional

from .certificate import Certificate, Name, PublicKeyInfo, TBSCertificate
from .constants import (
    ALG_ML_DSA_65,
    CERT_VERSION,
    KEY_USAGE_CRL_SIGN,
    KEY_USAGE_DIGITAL_SIGNATURE,
    KEY_USAGE_KEY_CERT_SIGN,
)
from .csr import CertificateSigningRequest
from .keys import generate_keypair, sign

# Maximum allowed validity in days (~30 years) to prevent unreasonably
# long-lived certificates that would be hard to revoke.
_MAX_VALIDITY_DAYS: int = 10_950


def _subject_key_id(public_key_bytes: bytes) -> bytes:
    """Compute subject key identifier: SHA3-256(public_key_bytes)[:16]."""
    return hashlib.sha3_256(public_key_bytes).digest()[:16]


def _random_serial() -> bytes:
    """Generate a random 16-byte serial number."""
    return os.urandom(16)


def _validity_window(validity_days: int) -> tuple[int, int]:
    """Return (not_before, not_after) as Unix timestamps."""
    now = int(time.time())
    return now, now + validity_days * 86400


def create_root_ca(
    subject: Name,
    validity_days: int = 3650,
    alg: int = ALG_ML_DSA_65,
) -> tuple[Certificate, bytes]:
    """
    Create a self-signed root CA certificate.

    Returns:
        (certificate, secret_key_bytes)
    """
    pub, sec = generate_keypair(alg)
    key_usage = KEY_USAGE_KEY_CERT_SIGN | KEY_USAGE_CRL_SIGN | KEY_USAGE_DIGITAL_SIGNATURE
    cert = create_self_signed(
        subject=subject,
        pub=pub,
        sec=sec,
        validity_days=validity_days,
        alg=alg,
        key_usage=key_usage,
        is_ca=True,
        path_len=1,
    )
    return cert, sec


def create_self_signed(
    subject: Name,
    pub: bytes,
    sec: bytes,
    validity_days: int,
    alg: int,
    key_usage: int = KEY_USAGE_DIGITAL_SIGNATURE,
    is_ca: bool = False,
    path_len: Optional[int] = None,
) -> Certificate:
    """
    Create a self-signed certificate (e.g. for local services).

    The issuer equals the subject; auth_key_id equals subject_key_id.
    """
    skid = _subject_key_id(pub)
    not_before, not_after = _validity_window(validity_days)
    serial = _random_serial()

    tbs = TBSCertificate(
        version=CERT_VERSION,
        serial=serial,
        issuer=subject,
        subject=subject,
        not_before=not_before,
        not_after=not_after,
        public_key=PublicKeyInfo(alg_id=alg, key_bytes=pub),
        is_ca=is_ca,
        path_len=path_len,
        key_usage=key_usage,
        subject_key_id=skid,
        auth_key_id=skid,
    )

    tbs_bytes = tbs.encode()
    signature = sign(tbs_bytes, sec, alg)

    return Certificate(tbs_bytes=tbs_bytes, sig_alg=alg, signature=signature)


def issue_from_csr(
    csr: CertificateSigningRequest,
    issuer_cert: Certificate,
    issuer_sec: bytes,
    validity_days: int = 365,
) -> Certificate:
    """
    Issue a certificate from a CSR.

    Automatically verifies the CSR self-signature before issuance.
    Transfers is_ca, path_len, and key_usage from the CSR (subject to
    issuer constraints enforced by issue_certificate).

    Raises:
        ValueError: if the CSR self-signature is invalid, or if the issuer
                    is not a valid CA, or if path_len constraints are violated.
    """
    if not csr.verify_self_signature():
        raise ValueError("CSR self-signature is invalid")

    return issue_certificate(
        subject=csr.subject,
        subject_pub=csr.public_key.key_bytes,
        issuer_cert=issuer_cert,
        issuer_sec=issuer_sec,
        validity_days=validity_days,
        is_ca=csr.is_ca,
        path_len=csr.path_len,
        key_usage=csr.key_usage,
    )


def issue_certificate(
    subject: Name,
    subject_pub: bytes,
    issuer_cert: Certificate,
    issuer_sec: bytes,
    validity_days: int = 365,
    is_ca: bool = False,
    path_len: Optional[int] = None,
    key_usage: int = KEY_USAGE_DIGITAL_SIGNATURE,
) -> Certificate:
    """
    Issue a certificate signed by *issuer_cert*.

    subject_key_id  = SHA3-256(subject_pub)[:16]
    auth_key_id     = issuer_cert.tbs.subject_key_id

    Raises:
        ValueError: if the issuer is not a CA, lacks KEY_CERT_SIGN, or the
                    requested path_len violates the issuer's constraint.
    """
    issuer_tbs = issuer_cert.tbs

    # --- Issuer validation ---
    # The issuer must be a CA with KEY_CERT_SIGN; passing an end-entity
    # certificate or a CA without signing authority is rejected immediately
    # rather than producing a certificate that would fail chain validation.
    if not issuer_tbs.is_ca:
        raise ValueError(
            "Issuer certificate is not a CA (is_ca must be True)"
        )
    if not (issuer_tbs.key_usage & KEY_USAGE_KEY_CERT_SIGN):
        raise ValueError(
            "Issuer certificate lacks KEY_CERT_SIGN key usage"
        )

    # --- Path-length constraint enforcement ---
    # Enforce at issuance time so that issued CA certificates cannot claim
    # a path_len that exceeds what the issuer permits (defence-in-depth;
    # verify_chain enforces this again at verification time).
    if is_ca and issuer_tbs.path_len is not None:
        if issuer_tbs.path_len == 0:
            raise ValueError(
                "Issuer path_len=0 forbids issuing CA certificates"
            )
        max_sub_path_len = issuer_tbs.path_len - 1
        if path_len is None or path_len > max_sub_path_len:
            raise ValueError(
                f"Requested path_len ({path_len!r}) exceeds the maximum allowed "
                f"by the issuer's constraint (max: {max_sub_path_len})"
            )

    skid = _subject_key_id(subject_pub)
    not_before, not_after = _validity_window(validity_days)
    serial = _random_serial()
    alg = issuer_cert.sig_alg

    tbs = TBSCertificate(
        version=CERT_VERSION,
        serial=serial,
        issuer=issuer_tbs.subject,
        subject=subject,
        not_before=not_before,
        not_after=not_after,
        public_key=PublicKeyInfo(alg_id=issuer_tbs.public_key.alg_id, key_bytes=subject_pub),
        is_ca=is_ca,
        path_len=path_len,
        key_usage=key_usage,
        subject_key_id=skid,
        auth_key_id=issuer_tbs.subject_key_id,
    )

    tbs_bytes = tbs.encode()
    signature = sign(tbs_bytes, issuer_sec, alg)

    return Certificate(tbs_bytes=tbs_bytes, sig_alg=alg, signature=signature)
