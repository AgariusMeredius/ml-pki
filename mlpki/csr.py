"""
Certificate Signing Request (CSR) implementation.
"""

from __future__ import annotations

import base64
from dataclasses import dataclass
from typing import Optional

import cbor2

from .certificate import Name, PublicKeyInfo
from .constants import (
    CSR_IS_CA,
    CSR_KEY_USAGE,
    CSR_PATH_LEN,
    CSR_PUBLIC_KEY,
    CSR_SIG_ALG,
    CSR_SIGNATURE,
    CSR_SUBJECT,
    CSR_VERSION,
    PEM_CSR_FOOTER,
    PEM_CSR_HEADER,
)
from .keys import sign, verify


@dataclass
class CertificateSigningRequest:
    """
    CSR with subject, public key, requested extensions and self-signature.

    The self-signature is computed over CBOR({1, 2, 3, 4, 6, 7, 8}),
    i.e. all fields except field 5 (signature).
    """

    version: int
    subject: Name
    public_key: PublicKeyInfo
    sig_alg: int
    signature: bytes
    is_ca: bool
    path_len: Optional[int]
    key_usage: int

    # ------------------------------------------------------------------
    # Factory
    # ------------------------------------------------------------------

    @classmethod
    def create(
        cls,
        subject: Name,
        pub: bytes,
        sec: bytes,
        alg: int,
        is_ca: bool = False,
        path_len: Optional[int] = None,
        key_usage: int = 0x01,
    ) -> "CertificateSigningRequest":
        """Create a new CSR, signing over the TBS fields."""
        pub_info = PublicKeyInfo(alg_id=alg, key_bytes=pub)
        tbs = _encode_tbs(
            version=1,
            subject=subject,
            public_key=pub_info,
            sig_alg=alg,
            is_ca=is_ca,
            path_len=path_len,
            key_usage=key_usage,
        )
        signature = sign(tbs, sec, alg)
        return cls(
            version=1,
            subject=subject,
            public_key=pub_info,
            sig_alg=alg,
            signature=signature,
            is_ca=is_ca,
            path_len=path_len,
            key_usage=key_usage,
        )

    # ------------------------------------------------------------------
    # Signature verification
    # ------------------------------------------------------------------

    def verify_self_signature(self) -> bool:
        """Return True if the CSR's self-signature is valid."""
        tbs = _encode_tbs(
            version=self.version,
            subject=self.subject,
            public_key=self.public_key,
            sig_alg=self.sig_alg,
            is_ca=self.is_ca,
            path_len=self.path_len,
            key_usage=self.key_usage,
        )
        return verify(tbs, self.signature, self.public_key.key_bytes, self.sig_alg)

    # ------------------------------------------------------------------
    # Serialization
    # ------------------------------------------------------------------

    def encode(self) -> bytes:
        """Encode CSR to CBOR bytes."""
        m = {
            CSR_VERSION: self.version,
            CSR_SUBJECT: self.subject.to_map(),
            CSR_PUBLIC_KEY: self.public_key.to_map(),
            CSR_SIG_ALG: self.sig_alg,
            CSR_SIGNATURE: self.signature,
            CSR_IS_CA: self.is_ca,
            CSR_PATH_LEN: self.path_len,
            CSR_KEY_USAGE: self.key_usage,
        }
        return cbor2.dumps(m)

    @classmethod
    def decode(cls, data: bytes) -> "CertificateSigningRequest":
        """Decode CSR from CBOR bytes."""
        m = cbor2.loads(data)
        return cls(
            version=m[CSR_VERSION],
            subject=Name.from_map(m[CSR_SUBJECT]),
            public_key=PublicKeyInfo.from_map(m[CSR_PUBLIC_KEY]),
            sig_alg=m[CSR_SIG_ALG],
            signature=bytes(m[CSR_SIGNATURE]),
            is_ca=m[CSR_IS_CA],
            path_len=m[CSR_PATH_LEN],
            key_usage=m[CSR_KEY_USAGE],
        )

    def to_pem(self) -> str:
        """Export CSR to PEM-like format."""
        b64 = base64.b64encode(self.encode()).decode("ascii")
        lines = [PEM_CSR_HEADER]
        for i in range(0, len(b64), 64):
            lines.append(b64[i : i + 64])
        lines.append(PEM_CSR_FOOTER)
        return "\n".join(lines) + "\n"

    @classmethod
    def from_pem(cls, pem: str) -> "CertificateSigningRequest":
        """Import CSR from PEM-like format."""
        lines = pem.strip().splitlines()
        b64_lines = [
            line
            for line in lines
            if line != PEM_CSR_HEADER and line != PEM_CSR_FOOTER
        ]
        data = base64.b64decode("".join(b64_lines))
        return cls.decode(data)


# ---------------------------------------------------------------------------
# Internal helper
# ---------------------------------------------------------------------------

def _encode_tbs(
    version: int,
    subject: Name,
    public_key: PublicKeyInfo,
    sig_alg: int,
    is_ca: bool,
    path_len: Optional[int],
    key_usage: int,
) -> bytes:
    """Encode the fields that are covered by the CSR signature."""
    m = {
        CSR_VERSION: version,
        CSR_SUBJECT: subject.to_map(),
        CSR_PUBLIC_KEY: public_key.to_map(),
        CSR_SIG_ALG: sig_alg,
        CSR_IS_CA: is_ca,
        CSR_PATH_LEN: path_len,
        CSR_KEY_USAGE: key_usage,
    }
    return cbor2.dumps(m)
