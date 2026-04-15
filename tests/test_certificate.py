"""Tests for certificate.py — CBOR round-trips, PEM round-trips, fingerprint."""

import pytest

from mlpki import (
    ALG_ML_DSA_44,
    Certificate,
    Name,
    PublicKeyInfo,
    TBSCertificate,
    KEY_USAGE_DIGITAL_SIGNATURE,
    KEY_USAGE_KEY_CERT_SIGN,
    KEY_USAGE_CRL_SIGN,
    create_root_ca,
)
from mlpki.constants import CERT_VERSION


# ---------------------------------------------------------------------------
# Name
# ---------------------------------------------------------------------------

class TestName:
    def test_round_trip_with_ou(self):
        n = Name(cn="My CN", org="My Org", ou="My OU")
        assert Name.from_map(n.to_map()) == n

    def test_round_trip_without_ou(self):
        n = Name(cn="My CN", org="My Org")
        recovered = Name.from_map(n.to_map())
        assert recovered == n
        assert recovered.ou is None

    def test_equality(self):
        a = Name(cn="A", org="B")
        b = Name(cn="A", org="B")
        assert a == b

    def test_inequality(self):
        a = Name(cn="A", org="B")
        b = Name(cn="A", org="C")
        assert a != b


# ---------------------------------------------------------------------------
# PublicKeyInfo
# ---------------------------------------------------------------------------

class TestPublicKeyInfo:
    def test_round_trip(self):
        pk = PublicKeyInfo(alg_id=ALG_ML_DSA_44, key_bytes=b"\xde\xad\xbe\xef" * 8)
        recovered = PublicKeyInfo.from_map(pk.to_map())
        assert recovered.alg_id == pk.alg_id
        assert recovered.key_bytes == pk.key_bytes

    def test_alg_name(self):
        pk = PublicKeyInfo(alg_id=ALG_ML_DSA_44, key_bytes=b"\x00")
        assert pk.alg_name == "ML-DSA-44"


# ---------------------------------------------------------------------------
# TBSCertificate
# ---------------------------------------------------------------------------

class TestTBSCertificate:
    def _make_tbs(self) -> TBSCertificate:
        return TBSCertificate(
            version=CERT_VERSION,
            serial=b"\x01" * 16,
            issuer=Name(cn="Issuer", org="Org"),
            subject=Name(cn="Subject", org="Org"),
            not_before=1000000,
            not_after=2000000,
            public_key=PublicKeyInfo(alg_id=ALG_ML_DSA_44, key_bytes=b"\xab" * 32),
            is_ca=True,
            path_len=1,
            key_usage=KEY_USAGE_KEY_CERT_SIGN | KEY_USAGE_CRL_SIGN,
            subject_key_id=b"\x11" * 16,
            auth_key_id=b"\x22" * 16,
        )

    def test_cbor_round_trip(self):
        tbs = self._make_tbs()
        recovered = TBSCertificate.decode(tbs.encode())
        assert recovered.version == tbs.version
        assert recovered.serial == tbs.serial
        assert recovered.issuer == tbs.issuer
        assert recovered.subject == tbs.subject
        assert recovered.not_before == tbs.not_before
        assert recovered.not_after == tbs.not_after
        assert recovered.is_ca == tbs.is_ca
        assert recovered.path_len == tbs.path_len
        assert recovered.key_usage == tbs.key_usage
        assert recovered.subject_key_id == tbs.subject_key_id
        assert recovered.auth_key_id == tbs.auth_key_id

    def test_path_len_none_round_trip(self):
        tbs = self._make_tbs()
        tbs.path_len = None
        recovered = TBSCertificate.decode(tbs.encode())
        assert recovered.path_len is None

    def test_encode_is_deterministic(self):
        tbs = self._make_tbs()
        assert tbs.encode() == tbs.encode()


# ---------------------------------------------------------------------------
# Certificate
# ---------------------------------------------------------------------------

class TestCertificate:
    def test_cbor_round_trip(self, root_cert):
        data = root_cert.encode()
        recovered = Certificate.decode(data)
        assert recovered.tbs_bytes == root_cert.tbs_bytes
        assert recovered.sig_alg == root_cert.sig_alg
        assert recovered.signature == root_cert.signature

    def test_pem_round_trip(self, root_cert):
        pem = root_cert.to_pem()
        assert "-----BEGIN ML-CERTIFICATE-----" in pem
        assert "-----END ML-CERTIFICATE-----" in pem
        recovered = Certificate.from_pem(pem)
        assert recovered.tbs_bytes == root_cert.tbs_bytes
        assert recovered.signature == root_cert.signature

    def test_pem_round_trip_with_whitespace(self, root_cert):
        pem = root_cert.to_pem()
        # Add extra whitespace — should still parse
        padded = "\n" + pem + "\n"
        recovered = Certificate.from_pem(padded)
        assert recovered.tbs_bytes == root_cert.tbs_bytes

    def test_fingerprint_is_bytes(self, root_cert):
        fp = root_cert.fingerprint()
        assert isinstance(fp, bytes)
        assert len(fp) == 32  # SHA3-256

    def test_fingerprint_stability(self, root_cert):
        """Same cert must always produce the same fingerprint."""
        assert root_cert.fingerprint() == root_cert.fingerprint()

    def test_fingerprint_uniqueness(self, root_cert, intermediate_cert):
        assert root_cert.fingerprint() != intermediate_cert.fingerprint()

    def test_tbs_property_cached(self, root_cert):
        tbs1 = root_cert.tbs
        tbs2 = root_cert.tbs
        assert tbs1 is tbs2

    def test_save_and_load(self, root_cert, tmp_path):
        path = str(tmp_path / "root.mlcert")
        root_cert.save(path)
        loaded = Certificate.load(path)
        assert loaded.tbs_bytes == root_cert.tbs_bytes
        assert loaded.signature == root_cert.signature
