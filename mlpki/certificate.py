"""
Certificate data structures and serialization.

Provides dataclasses for Name, PublicKeyInfo, TBSCertificate and Certificate
with CBOR encoding/decoding and PEM import/export.
"""

from __future__ import annotations

import base64
import hashlib
from dataclasses import dataclass
from typing import Optional

import cbor2

from .constants import (
    ALG_NAMES,
    CERT_SIG_ALG,
    CERT_SIGNATURE,
    CERT_TBS_BYTES,
    NAME_CN,
    NAME_ORG,
    NAME_OU,
    PEM_CERT_FOOTER,
    PEM_CERT_HEADER,
    PUBKEY_ALG_ID,
    PUBKEY_KEY_BYTES,
    TBS_AUTH_KEY_ID,
    TBS_IS_CA,
    TBS_ISSUER,
    TBS_KEY_USAGE,
    TBS_NOT_AFTER,
    TBS_NOT_BEFORE,
    TBS_PATH_LEN,
    TBS_PUBLIC_KEY,
    TBS_SERIAL,
    TBS_SUBJECT,
    TBS_SUBJECT_KEY_ID,
    TBS_VERSION,
    CERT_VERSION,
)


@dataclass
class Name:
    """Distinguished name for certificate subject/issuer."""

    cn: str
    org: str
    ou: Optional[str] = None

    def to_map(self) -> dict:
        m: dict = {NAME_CN: self.cn, NAME_ORG: self.org}
        if self.ou is not None:
            m[NAME_OU] = self.ou
        return m

    @classmethod
    def from_map(cls, m: dict) -> "Name":
        return cls(
            cn=m[NAME_CN],
            org=m[NAME_ORG],
            ou=m.get(NAME_OU),
        )

    def __eq__(self, other: object) -> bool:
        if not isinstance(other, Name):
            return NotImplemented
        return self.cn == other.cn and self.org == other.org and self.ou == other.ou


@dataclass
class PublicKeyInfo:
    """Public key info with algorithm identifier."""

    alg_id: int
    key_bytes: bytes

    def to_map(self) -> dict:
        return {PUBKEY_ALG_ID: self.alg_id, PUBKEY_KEY_BYTES: self.key_bytes}

    @classmethod
    def from_map(cls, m: dict) -> "PublicKeyInfo":
        return cls(alg_id=m[PUBKEY_ALG_ID], key_bytes=bytes(m[PUBKEY_KEY_BYTES]))

    @property
    def alg_name(self) -> str:
        return ALG_NAMES[self.alg_id]


@dataclass
class TBSCertificate:
    """To-Be-Signed certificate content."""

    version: int
    serial: bytes          # 16 bytes
    issuer: Name
    subject: Name
    not_before: int        # Unix timestamp
    not_after: int         # Unix timestamp
    public_key: PublicKeyInfo
    is_ca: bool
    path_len: Optional[int]
    key_usage: int         # bitmask
    subject_key_id: bytes  # 16 bytes
    auth_key_id: bytes     # 16 bytes

    def encode(self) -> bytes:
        """Encode TBS to canonical CBOR bytes."""
        m: dict = {
            TBS_VERSION: self.version,
            TBS_SERIAL: self.serial,
            TBS_ISSUER: self.issuer.to_map(),
            TBS_SUBJECT: self.subject.to_map(),
            TBS_NOT_BEFORE: self.not_before,
            TBS_NOT_AFTER: self.not_after,
            TBS_PUBLIC_KEY: self.public_key.to_map(),
            TBS_IS_CA: self.is_ca,
            TBS_PATH_LEN: self.path_len,
            TBS_KEY_USAGE: self.key_usage,
            TBS_SUBJECT_KEY_ID: self.subject_key_id,
            TBS_AUTH_KEY_ID: self.auth_key_id,
        }
        return cbor2.dumps(m)

    @classmethod
    def decode(cls, data: bytes) -> "TBSCertificate":
        """Decode TBS from CBOR bytes."""
        m = cbor2.loads(data)
        return cls(
            version=m[TBS_VERSION],
            serial=bytes(m[TBS_SERIAL]),
            issuer=Name.from_map(m[TBS_ISSUER]),
            subject=Name.from_map(m[TBS_SUBJECT]),
            not_before=m[TBS_NOT_BEFORE],
            not_after=m[TBS_NOT_AFTER],
            public_key=PublicKeyInfo.from_map(m[TBS_PUBLIC_KEY]),
            is_ca=m[TBS_IS_CA],
            path_len=m[TBS_PATH_LEN],
            key_usage=m[TBS_KEY_USAGE],
            subject_key_id=bytes(m[TBS_SUBJECT_KEY_ID]),
            auth_key_id=bytes(m[TBS_AUTH_KEY_ID]),
        )


@dataclass
class Certificate:
    """Signed certificate: outer structure containing TBS bytes + signature."""

    tbs_bytes: bytes
    sig_alg: int
    signature: bytes

    # Decoded TBS (cached lazily)
    _tbs: Optional[TBSCertificate] = None

    @property
    def tbs(self) -> TBSCertificate:
        if self._tbs is None:
            object.__setattr__(self, "_tbs", TBSCertificate.decode(self.tbs_bytes))
        return self._tbs  # type: ignore[return-value]

    def encode(self) -> bytes:
        """Encode outer certificate to CBOR bytes."""
        m = {
            CERT_TBS_BYTES: self.tbs_bytes,
            CERT_SIG_ALG: self.sig_alg,
            CERT_SIGNATURE: self.signature,
        }
        return cbor2.dumps(m)

    @classmethod
    def decode(cls, data: bytes) -> "Certificate":
        """Decode outer certificate from CBOR bytes."""
        m = cbor2.loads(data)
        return cls(
            tbs_bytes=bytes(m[CERT_TBS_BYTES]),
            sig_alg=m[CERT_SIG_ALG],
            signature=bytes(m[CERT_SIGNATURE]),
        )

    def to_pem(self) -> str:
        """Export certificate to PEM-like format."""
        b64 = base64.b64encode(self.encode()).decode("ascii")
        lines = [PEM_CERT_HEADER]
        for i in range(0, len(b64), 64):
            lines.append(b64[i : i + 64])
        lines.append(PEM_CERT_FOOTER)
        return "\n".join(lines) + "\n"

    @classmethod
    def from_pem(cls, pem: str) -> "Certificate":
        """Import certificate from PEM-like format."""
        lines = pem.strip().splitlines()
        b64_lines = [
            line
            for line in lines
            if line != PEM_CERT_HEADER and line != PEM_CERT_FOOTER
        ]
        data = base64.b64decode("".join(b64_lines))
        return cls.decode(data)

    def fingerprint(self) -> bytes:
        """SHA3-256 fingerprint over the TBS bytes."""
        return hashlib.sha3_256(self.tbs_bytes).digest()

    def save(self, path: str) -> None:
        """Save certificate as binary .mlcert file."""
        with open(path, "wb") as f:
            f.write(self.encode())

    @classmethod
    def load(cls, path: str) -> "Certificate":
        """Load certificate from binary .mlcert file."""
        with open(path, "rb") as f:
            return cls.decode(f.read())
