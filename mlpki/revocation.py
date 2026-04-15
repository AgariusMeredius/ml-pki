"""
Certificate Revocation List (CRL) implementation.
"""

from __future__ import annotations

import time
from dataclasses import dataclass, field
from typing import List

import cbor2

from .certificate import Certificate
from .constants import (
    CRL_ISSUER_KEY_ID,
    CRL_NEXT_UPDATE,
    CRL_REVOKED_SERIALS,
    CRL_SIG_ALG,
    CRL_SIGNATURE,
    CRL_THIS_UPDATE,
)
from .keys import sign, verify


@dataclass
class RevocationList:
    """
    Certificate Revocation List (CRL).

    Immutable: modifying the list produces a new, re-signed instance via
    add_serial(). Direct mutation of revoked_serials bypasses the internal
    lookup index; always use add_serial() for correct behaviour.
    """

    issuer_key_id: bytes          # 16 bytes — subject_key_id of the issuer
    this_update: int              # Unix timestamp
    next_update: int              # Unix timestamp
    revoked_serials: List[bytes]  # list of 16-byte serial numbers
    sig_alg: int
    signature: bytes

    def __post_init__(self) -> None:
        # Build an O(1) lookup set from the serial list. Created once at
        # construction time; all factory methods (create, add_serial, decode)
        # go through __init__ so this is always in sync.
        self._revoked_set: frozenset = frozenset(self.revoked_serials)

    # ------------------------------------------------------------------
    # Factory
    # ------------------------------------------------------------------

    @classmethod
    def create(
        cls,
        issuer_cert: Certificate,
        issuer_sec: bytes,
        serials: List[bytes] | None = None,
        next_update_days: int = 30,
    ) -> "RevocationList":
        """Create a new, signed CRL."""
        now = int(time.time())
        next_update = now + next_update_days * 86400
        revoked = list(serials) if serials else []
        alg = issuer_cert.sig_alg
        issuer_key_id = issuer_cert.tbs.subject_key_id

        tbs = _encode_tbs(
            issuer_key_id=issuer_key_id,
            this_update=now,
            next_update=next_update,
            revoked_serials=revoked,
            sig_alg=alg,
        )
        signature = sign(tbs, issuer_sec, alg)

        return cls(
            issuer_key_id=issuer_key_id,
            this_update=now,
            next_update=next_update,
            revoked_serials=revoked,
            sig_alg=alg,
            signature=signature,
        )

    # ------------------------------------------------------------------
    # Immutable update
    # ------------------------------------------------------------------

    def add_serial(
        self,
        serial: bytes,
        issuer_cert: Certificate,
        issuer_sec: bytes,
    ) -> "RevocationList":
        """
        Return a new, re-signed CRL containing *serial*.

        The this_update timestamp is refreshed; next_update interval is
        preserved from the original.
        """
        interval = self.next_update - self.this_update
        now = int(time.time())
        new_serials = list(self.revoked_serials)
        if serial not in new_serials:
            new_serials.append(serial)

        alg = issuer_cert.sig_alg
        tbs = _encode_tbs(
            issuer_key_id=self.issuer_key_id,
            this_update=now,
            next_update=now + interval,
            revoked_serials=new_serials,
            sig_alg=alg,
        )
        signature = sign(tbs, issuer_sec, alg)

        return RevocationList(
            issuer_key_id=self.issuer_key_id,
            this_update=now,
            next_update=now + interval,
            revoked_serials=new_serials,
            sig_alg=alg,
            signature=signature,
        )

    # ------------------------------------------------------------------
    # Verification
    # ------------------------------------------------------------------

    def verify(self, issuer_cert: Certificate) -> bool:
        """Return True if the CRL signature is valid for *issuer_cert*."""
        tbs = _encode_tbs(
            issuer_key_id=self.issuer_key_id,
            this_update=self.this_update,
            next_update=self.next_update,
            revoked_serials=self.revoked_serials,
            sig_alg=self.sig_alg,
        )
        pub = issuer_cert.tbs.public_key.key_bytes
        return verify(tbs, self.signature, pub, self.sig_alg)

    def is_revoked(self, serial: bytes) -> bool:
        """Return True if *serial* appears in the revoked serials list (O(1))."""
        return serial in self._revoked_set

    # ------------------------------------------------------------------
    # Serialization
    # ------------------------------------------------------------------

    def encode(self) -> bytes:
        m = {
            CRL_ISSUER_KEY_ID: self.issuer_key_id,
            CRL_THIS_UPDATE: self.this_update,
            CRL_NEXT_UPDATE: self.next_update,
            CRL_REVOKED_SERIALS: self.revoked_serials,
            CRL_SIG_ALG: self.sig_alg,
            CRL_SIGNATURE: self.signature,
        }
        return cbor2.dumps(m)

    @classmethod
    def decode(cls, data: bytes) -> "RevocationList":
        m = cbor2.loads(data)
        return cls(
            issuer_key_id=bytes(m[CRL_ISSUER_KEY_ID]),
            this_update=m[CRL_THIS_UPDATE],
            next_update=m[CRL_NEXT_UPDATE],
            revoked_serials=[bytes(s) for s in m[CRL_REVOKED_SERIALS]],
            sig_alg=m[CRL_SIG_ALG],
            signature=bytes(m[CRL_SIGNATURE]),
        )


# ---------------------------------------------------------------------------
# Internal helper
# ---------------------------------------------------------------------------

def _encode_tbs(
    issuer_key_id: bytes,
    this_update: int,
    next_update: int,
    revoked_serials: List[bytes],
    sig_alg: int,
) -> bytes:
    """Encode the fields covered by the CRL signature."""
    m = {
        CRL_ISSUER_KEY_ID: issuer_key_id,
        CRL_THIS_UPDATE: this_update,
        CRL_NEXT_UPDATE: next_update,
        CRL_REVOKED_SERIALS: revoked_serials,
        CRL_SIG_ALG: sig_alg,
    }
    return cbor2.dumps(m)
