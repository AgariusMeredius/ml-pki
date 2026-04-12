"""
mlpki — Post-Quantum PKI library based on ML-DSA and CBOR serialization.

Public API re-exports for convenient access.
"""

from .ca import (
    create_root_ca,
    create_self_signed,
    issue_certificate,
    issue_from_csr,
)
from .certificate import Certificate, Name, PublicKeyInfo, TBSCertificate
from .constants import (
    ALG_ML_DSA_44,
    ALG_ML_DSA_65,
    ALG_ML_DSA_87,
    KEY_USAGE_CRL_SIGN,
    KEY_USAGE_DIGITAL_SIGNATURE,
    KEY_USAGE_KEY_CERT_SIGN,
)
from .csr import CertificateSigningRequest
from .keys import (
    generate_keypair,
    load_secret_key,
    save_secret_key,
    sign,
    verify as raw_verify,
)
from .revocation import RevocationList
from .verify import (
    VerificationCode,
    VerificationError,
    verify_chain,
    verify_self_signed,
    verify_signature,
)

__all__ = [
    # ca
    "create_root_ca",
    "create_self_signed",
    "issue_certificate",
    "issue_from_csr",
    # certificate
    "Certificate",
    "Name",
    "PublicKeyInfo",
    "TBSCertificate",
    # constants
    "ALG_ML_DSA_44",
    "ALG_ML_DSA_65",
    "ALG_ML_DSA_87",
    "KEY_USAGE_CRL_SIGN",
    "KEY_USAGE_DIGITAL_SIGNATURE",
    "KEY_USAGE_KEY_CERT_SIGN",
    # csr
    "CertificateSigningRequest",
    # keys
    "generate_keypair",
    "load_secret_key",
    "save_secret_key",
    "sign",
    "raw_verify",
    # revocation
    "RevocationList",
    # verify
    "VerificationCode",
    "VerificationError",
    "verify_chain",
    "verify_self_signed",
    "verify_signature",
]
