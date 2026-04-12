"""
Tests for verify.py — chain verification, error cases.
"""

import time

import pytest

from mlpki import (
    ALG_ML_DSA_44,
    Certificate,
    Name,
    TBSCertificate,
    create_root_ca,
    create_self_signed,
    generate_keypair,
    issue_certificate,
    sign,
    verify_chain,
    verify_self_signed,
    verify_signature,
    KEY_USAGE_CRL_SIGN,
    KEY_USAGE_DIGITAL_SIGNATURE,
    KEY_USAGE_KEY_CERT_SIGN,
)
from mlpki.verify import VerificationCode, VerificationError


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _make_ca(name_str: str, issuer_cert=None, issuer_sec=None, path_len=0):
    """Create a CA cert. If issuer given, issue from it; else make root."""
    if issuer_cert is None:
        return create_root_ca(Name(cn=name_str, org="O"), validity_days=3650, alg=ALG_ML_DSA_44)
    pub, sec = generate_keypair(ALG_ML_DSA_44)
    cert = issue_certificate(
        subject=Name(cn=name_str, org="O"),
        subject_pub=pub,
        issuer_cert=issuer_cert,
        issuer_sec=issuer_sec,
        validity_days=1825,
        is_ca=True,
        path_len=path_len,
        key_usage=KEY_USAGE_KEY_CERT_SIGN | KEY_USAGE_CRL_SIGN | KEY_USAGE_DIGITAL_SIGNATURE,
    )
    return cert, sec


# ---------------------------------------------------------------------------
# verify_self_signed
# ---------------------------------------------------------------------------

class TestVerifySelfSigned:
    def test_valid_root(self, root_cert):
        verify_self_signed(root_cert)  # must not raise

    def test_tampered_tbs_raises(self, root_cert):
        # Build a cert with valid structure but wrong tbs_bytes
        bad = Certificate(
            tbs_bytes=root_cert.tbs_bytes + b"\x00",
            sig_alg=root_cert.sig_alg,
            signature=root_cert.signature,
        )
        with pytest.raises(VerificationError) as exc_info:
            verify_self_signed(bad)
        assert exc_info.value.code == VerificationCode.INVALID_SIGNATURE

    def test_tampered_signature_raises(self, root_cert):
        bad_sig = bytearray(root_cert.signature)
        bad_sig[10] ^= 0xFF
        bad = Certificate(
            tbs_bytes=root_cert.tbs_bytes,
            sig_alg=root_cert.sig_alg,
            signature=bytes(bad_sig),
        )
        with pytest.raises(VerificationError) as exc_info:
            verify_self_signed(bad)
        assert exc_info.value.code == VerificationCode.INVALID_SIGNATURE


# ---------------------------------------------------------------------------
# verify_signature
# ---------------------------------------------------------------------------

class TestVerifySignature:
    def test_valid_ee_cert(self, intermediate_cert, ee_cert):
        verify_signature(ee_cert, intermediate_cert)  # must not raise

    def test_wrong_issuer_raises(self, root_cert, ee_cert):
        with pytest.raises(VerificationError) as exc_info:
            verify_signature(ee_cert, root_cert)
        assert exc_info.value.code == VerificationCode.INVALID_SIGNATURE


# ---------------------------------------------------------------------------
# verify_chain — happy path
# ---------------------------------------------------------------------------

class TestVerifyChainHappy:
    def test_single_level(self, root_cert, root_sec):
        pub, _ = generate_keypair(ALG_ML_DSA_44)
        ee = issue_certificate(
            Name(cn="EE", org="O"), pub, root_cert, root_sec, 365
        )
        verify_chain([ee], trusted_root=root_cert)  # must not raise

    def test_two_level(self, root_cert, intermediate_cert, ee_cert):
        verify_chain([intermediate_cert, ee_cert], trusted_root=root_cert)

    def test_chain_with_empty_crl(self, root_cert, intermediate_cert, ee_cert, crl):
        verify_chain([intermediate_cert, ee_cert], trusted_root=root_cert, crl=crl)


# ---------------------------------------------------------------------------
# verify_chain — expired certificate
# ---------------------------------------------------------------------------

class TestVerifyChainExpired:
    def test_expired_cert_raises(self, root_cert, root_sec):
        pub, _ = generate_keypair(ALG_ML_DSA_44)
        # Issue a cert with already-expired validity (backdated by sign manipulation)
        # We build TBS manually with past timestamps
        import hashlib, cbor2
        from mlpki.constants import (
            CERT_VERSION, TBS_VERSION, TBS_SERIAL, TBS_ISSUER, TBS_SUBJECT,
            TBS_NOT_BEFORE, TBS_NOT_AFTER, TBS_PUBLIC_KEY, TBS_IS_CA,
            TBS_PATH_LEN, TBS_KEY_USAGE, TBS_SUBJECT_KEY_ID, TBS_AUTH_KEY_ID,
            PUBKEY_ALG_ID, PUBKEY_KEY_BYTES,
        )
        import os

        now = int(time.time())
        skid = hashlib.sha3_256(pub).digest()[:16]
        tbs_map = {
            TBS_VERSION: CERT_VERSION,
            TBS_SERIAL: os.urandom(16),
            TBS_ISSUER: root_cert.tbs.subject.to_map(),
            TBS_SUBJECT: Name(cn="Expired", org="O").to_map(),
            TBS_NOT_BEFORE: now - 7200,
            TBS_NOT_AFTER: now - 3600,  # already expired
            TBS_PUBLIC_KEY: {PUBKEY_ALG_ID: ALG_ML_DSA_44, PUBKEY_KEY_BYTES: pub},
            TBS_IS_CA: False,
            TBS_PATH_LEN: None,
            TBS_KEY_USAGE: KEY_USAGE_DIGITAL_SIGNATURE,
            TBS_SUBJECT_KEY_ID: skid,
            TBS_AUTH_KEY_ID: root_cert.tbs.subject_key_id,
        }
        tbs_bytes = cbor2.dumps(tbs_map)
        signature = sign(tbs_bytes, root_sec, ALG_ML_DSA_44)
        expired_cert = Certificate(tbs_bytes=tbs_bytes, sig_alg=ALG_ML_DSA_44, signature=signature)

        with pytest.raises(VerificationError) as exc_info:
            verify_chain([expired_cert], trusted_root=root_cert)
        assert exc_info.value.code == VerificationCode.EXPIRED


# ---------------------------------------------------------------------------
# verify_chain — tampered TBS
# ---------------------------------------------------------------------------

class TestVerifyChainTampered:
    def test_tampered_tbs_raises(self, root_cert, intermediate_cert, ee_cert):
        # Flip a byte near the middle of tbs_bytes to corrupt the content.
        # Depending on which byte is flipped this may trigger AUTH_KEY_ID_MISMATCH
        # (if the key-id fields are corrupted) or INVALID_SIGNATURE (if only
        # signature-covered data changes).  Either way a VerificationError must be raised.
        mid = len(ee_cert.tbs_bytes) // 2
        corrupted = bytearray(ee_cert.tbs_bytes)
        corrupted[mid] ^= 0xFF
        bad_ee = Certificate(
            tbs_bytes=bytes(corrupted),
            sig_alg=ee_cert.sig_alg,
            signature=ee_cert.signature,
        )
        with pytest.raises(VerificationError):
            verify_chain([intermediate_cert, bad_ee], trusted_root=root_cert)


# ---------------------------------------------------------------------------
# verify_chain — wrong issuer (auth_key_id mismatch)
# ---------------------------------------------------------------------------

class TestVerifyChainWrongIssuer:
    def test_wrong_root_raises(self, root_cert, intermediate_cert, ee_cert):
        other_root, _ = create_root_ca(Name(cn="Other Root", org="O"), 3650, ALG_ML_DSA_44)
        with pytest.raises(VerificationError):
            verify_chain([intermediate_cert, ee_cert], trusted_root=other_root)


# ---------------------------------------------------------------------------
# verify_chain — path_len constraint violation
# ---------------------------------------------------------------------------

class TestVerifyChainPathLen:
    def test_path_len_violation(self):
        """Root has path_len=0 → no intermediate CA allowed."""
        root_cert, root_sec = create_root_ca(
            Name(cn="Root", org="O"), validity_days=3650, alg=ALG_ML_DSA_44
        )
        # Root has path_len=1; issue intermediate with path_len=0
        inter_pub, inter_sec = generate_keypair(ALG_ML_DSA_44)
        inter = issue_certificate(
            Name(cn="Inter", org="O"), inter_pub, root_cert, root_sec,
            1825, is_ca=True, path_len=0,
            key_usage=KEY_USAGE_KEY_CERT_SIGN | KEY_USAGE_CRL_SIGN,
        )
        # Issue a second intermediate under the first (path_len=0 means no CA below)
        inter2_pub, inter2_sec = generate_keypair(ALG_ML_DSA_44)
        inter2 = issue_certificate(
            Name(cn="Inter2", org="O"), inter2_pub, inter, inter_sec,
            1825, is_ca=True, path_len=0,
            key_usage=KEY_USAGE_KEY_CERT_SIGN | KEY_USAGE_CRL_SIGN,
        )
        ee_pub, _ = generate_keypair(ALG_ML_DSA_44)
        ee = issue_certificate(
            Name(cn="EE", org="O"), ee_pub, inter2, inter2_sec, 365
        )
        with pytest.raises(VerificationError) as exc_info:
            verify_chain([inter, inter2, ee], trusted_root=root_cert)
        assert exc_info.value.code == VerificationCode.PATH_LEN_EXCEEDED


# ---------------------------------------------------------------------------
# verify_chain — missing KEY_CERT_SIGN
# ---------------------------------------------------------------------------

class TestVerifyChainMissingKeyUsage:
    def test_missing_key_cert_sign_raises(self, root_cert, root_sec):
        """Issue an intermediate without KEY_CERT_SIGN; using it as CA should fail."""
        inter_pub, inter_sec = generate_keypair(ALG_ML_DSA_44)
        # Issuer with only DIGITAL_SIGNATURE, not KEY_CERT_SIGN
        bad_inter = issue_certificate(
            Name(cn="Bad Inter", org="O"), inter_pub, root_cert, root_sec,
            1825, is_ca=True, path_len=0,
            key_usage=KEY_USAGE_DIGITAL_SIGNATURE,  # missing KEY_CERT_SIGN
        )
        ee_pub, _ = generate_keypair(ALG_ML_DSA_44)
        ee = issue_certificate(
            Name(cn="EE", org="O"), ee_pub, bad_inter, inter_sec, 365
        )
        with pytest.raises(VerificationError) as exc_info:
            verify_chain([bad_inter, ee], trusted_root=root_cert)
        assert exc_info.value.code == VerificationCode.MISSING_KEY_CERT_SIGN
