"""
Tests for verify.py — chain verification, error cases.
"""

import time

import pytest

from mlpki import (
    ALG_ML_DSA_44,
    Certificate,
    Name,
    RevocationList,
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
        """verify_chain catches path_len violations in directly constructed chains.

        issue_certificate now enforces path_len at issuance time, so a
        second intermediate under an issuer with path_len=0 cannot be
        produced via the normal API.  Here we construct the chain directly
        to confirm that verify_chain still catches the violation independently.
        """
        import hashlib
        import cbor2
        import os as _os
        from mlpki.constants import (
            CERT_VERSION, TBS_VERSION, TBS_SERIAL, TBS_ISSUER, TBS_SUBJECT,
            TBS_NOT_BEFORE, TBS_NOT_AFTER, TBS_PUBLIC_KEY, TBS_IS_CA,
            TBS_PATH_LEN, TBS_KEY_USAGE, TBS_SUBJECT_KEY_ID, TBS_AUTH_KEY_ID,
            PUBKEY_ALG_ID, PUBKEY_KEY_BYTES,
        )

        root_cert, root_sec = create_root_ca(
            Name(cn="Root", org="O"), validity_days=3650, alg=ALG_ML_DSA_44
        )
        now = int(time.time())

        # Directly construct an intermediate (path_len=0) — valid under root.
        inter_pub, inter_sec = generate_keypair(ALG_ML_DSA_44)
        inter_skid = hashlib.sha3_256(inter_pub).digest()[:16]
        inter_tbs = cbor2.dumps({
            TBS_VERSION: CERT_VERSION,
            TBS_SERIAL: _os.urandom(16),
            TBS_ISSUER: root_cert.tbs.subject.to_map(),
            TBS_SUBJECT: Name(cn="Inter", org="O").to_map(),
            TBS_NOT_BEFORE: now,
            TBS_NOT_AFTER: now + 1825 * 86400,
            TBS_PUBLIC_KEY: {PUBKEY_ALG_ID: ALG_ML_DSA_44, PUBKEY_KEY_BYTES: inter_pub},
            TBS_IS_CA: True,
            TBS_PATH_LEN: 0,
            TBS_KEY_USAGE: KEY_USAGE_KEY_CERT_SIGN | KEY_USAGE_CRL_SIGN,
            TBS_SUBJECT_KEY_ID: inter_skid,
            TBS_AUTH_KEY_ID: root_cert.tbs.subject_key_id,
        })
        inter = Certificate(
            tbs_bytes=inter_tbs,
            sig_alg=ALG_ML_DSA_44,
            signature=sign(inter_tbs, root_sec, ALG_ML_DSA_44),
        )

        # Directly construct a second CA under inter — violates inter's path_len=0.
        inter2_pub, inter2_sec = generate_keypair(ALG_ML_DSA_44)
        inter2_skid = hashlib.sha3_256(inter2_pub).digest()[:16]
        inter2_tbs = cbor2.dumps({
            TBS_VERSION: CERT_VERSION,
            TBS_SERIAL: _os.urandom(16),
            TBS_ISSUER: Name(cn="Inter", org="O").to_map(),
            TBS_SUBJECT: Name(cn="Inter2", org="O").to_map(),
            TBS_NOT_BEFORE: now,
            TBS_NOT_AFTER: now + 1825 * 86400,
            TBS_PUBLIC_KEY: {PUBKEY_ALG_ID: ALG_ML_DSA_44, PUBKEY_KEY_BYTES: inter2_pub},
            TBS_IS_CA: True,
            TBS_PATH_LEN: 0,
            TBS_KEY_USAGE: KEY_USAGE_KEY_CERT_SIGN | KEY_USAGE_CRL_SIGN,
            TBS_SUBJECT_KEY_ID: inter2_skid,
            TBS_AUTH_KEY_ID: inter_skid,
        })
        inter2 = Certificate(
            tbs_bytes=inter2_tbs,
            sig_alg=ALG_ML_DSA_44,
            signature=sign(inter2_tbs, inter_sec, ALG_ML_DSA_44),
        )

        # EE under inter2 (is_ca=False, so issue_certificate permits it)
        ee_pub, _ = generate_keypair(ALG_ML_DSA_44)
        ee = issue_certificate(Name(cn="EE", org="O"), ee_pub, inter2, inter2_sec, 365)

        with pytest.raises(VerificationError) as exc_info:
            verify_chain([inter, inter2, ee], trusted_root=root_cert)
        assert exc_info.value.code == VerificationCode.PATH_LEN_EXCEEDED


# ---------------------------------------------------------------------------
# verify_chain — missing KEY_CERT_SIGN
# ---------------------------------------------------------------------------

class TestVerifyChainMissingKeyUsage:
    def test_missing_key_cert_sign_raises(self, root_cert, root_sec):
        """Intermediate without KEY_CERT_SIGN in chain fails verification.

        The bad intermediate is issued normally from root (root is valid).
        The EE cert is constructed directly to bypass the new issuer validation
        in issue_certificate (which would also catch missing KEY_CERT_SIGN).
        """
        import hashlib
        import cbor2
        import os as _os
        from mlpki.constants import (
            CERT_VERSION, TBS_VERSION, TBS_SERIAL, TBS_ISSUER, TBS_SUBJECT,
            TBS_NOT_BEFORE, TBS_NOT_AFTER, TBS_PUBLIC_KEY, TBS_IS_CA,
            TBS_PATH_LEN, TBS_KEY_USAGE, TBS_SUBJECT_KEY_ID, TBS_AUTH_KEY_ID,
            PUBKEY_ALG_ID, PUBKEY_KEY_BYTES,
        )
        now = int(time.time())

        inter_pub, inter_sec = generate_keypair(ALG_ML_DSA_44)
        bad_inter = issue_certificate(
            Name(cn="Bad Inter", org="O"), inter_pub, root_cert, root_sec,
            1825, is_ca=True, path_len=0,
            key_usage=KEY_USAGE_DIGITAL_SIGNATURE,  # missing KEY_CERT_SIGN
        )

        # Directly construct EE under bad_inter so issue_certificate's new
        # KEY_CERT_SIGN check doesn't block creating the test scenario.
        inter_skid = bad_inter.tbs.subject_key_id
        ee_pub, _ = generate_keypair(ALG_ML_DSA_44)
        ee_skid = hashlib.sha3_256(ee_pub).digest()[:16]
        ee_tbs = cbor2.dumps({
            TBS_VERSION: CERT_VERSION,
            TBS_SERIAL: _os.urandom(16),
            TBS_ISSUER: bad_inter.tbs.subject.to_map(),
            TBS_SUBJECT: Name(cn="EE", org="O").to_map(),
            TBS_NOT_BEFORE: now,
            TBS_NOT_AFTER: now + 365 * 86400,
            TBS_PUBLIC_KEY: {PUBKEY_ALG_ID: ALG_ML_DSA_44, PUBKEY_KEY_BYTES: ee_pub},
            TBS_IS_CA: False,
            TBS_PATH_LEN: None,
            TBS_KEY_USAGE: KEY_USAGE_DIGITAL_SIGNATURE,
            TBS_SUBJECT_KEY_ID: ee_skid,
            TBS_AUTH_KEY_ID: inter_skid,
        })
        ee = Certificate(
            tbs_bytes=ee_tbs,
            sig_alg=ALG_ML_DSA_44,
            signature=sign(ee_tbs, inter_sec, ALG_ML_DSA_44),
        )

        with pytest.raises(VerificationError) as exc_info:
            verify_chain([bad_inter, ee], trusted_root=root_cert)
        assert exc_info.value.code == VerificationCode.MISSING_KEY_CERT_SIGN


# ---------------------------------------------------------------------------
# verify_chain — maximum chain depth
# ---------------------------------------------------------------------------

class TestVerifyChainMaxDepth:
    def test_chain_exceeding_max_depth_raises(self, root_cert, root_sec):
        """verify_chain raises CHAIN_TOO_LONG when chain length exceeds max_depth."""
        pub, _ = generate_keypair(ALG_ML_DSA_44)
        ee = issue_certificate(Name(cn="EE", org="O"), pub, root_cert, root_sec, 365)
        # 11 certs in chain with default max_depth=10
        with pytest.raises(VerificationError) as exc_info:
            verify_chain([ee] * 11, trusted_root=root_cert)
        assert exc_info.value.code == VerificationCode.CHAIN_TOO_LONG

    def test_chain_at_max_depth_passes(self, root_cert, root_sec):
        """verify_chain accepts a chain whose length equals max_depth."""
        pub, _ = generate_keypair(ALG_ML_DSA_44)
        ee = issue_certificate(Name(cn="EE", org="O"), pub, root_cert, root_sec, 365)
        verify_chain([ee], trusted_root=root_cert, max_depth=1)  # must not raise

    def test_custom_max_depth_enforced(self, root_cert, root_sec):
        """Custom max_depth=0 rejects even a single-cert chain."""
        pub, _ = generate_keypair(ALG_ML_DSA_44)
        ee = issue_certificate(Name(cn="EE", org="O"), pub, root_cert, root_sec, 365)
        with pytest.raises(VerificationError) as exc_info:
            verify_chain([ee], trusted_root=root_cert, max_depth=0)
        assert exc_info.value.code == VerificationCode.CHAIN_TOO_LONG


# ---------------------------------------------------------------------------
# verify_chain — CRL authentication and freshness
# ---------------------------------------------------------------------------

class TestVerifyChainCRLValidation:
    def test_expired_crl_raises(self, root_cert, root_sec):
        """verify_chain raises CRL_EXPIRED for a CRL whose next_update is in the past."""
        from mlpki.revocation import _encode_tbs as _crl_tbs

        now = int(time.time())
        alg = root_cert.sig_alg
        issuer_key_id = root_cert.tbs.subject_key_id
        tbs = _crl_tbs(
            issuer_key_id=issuer_key_id,
            this_update=now - 86400,
            next_update=now - 3600,   # 1 hour ago — expired
            revoked_serials=[],
            sig_alg=alg,
        )
        expired_crl = RevocationList(
            issuer_key_id=issuer_key_id,
            this_update=now - 86400,
            next_update=now - 3600,
            revoked_serials=[],
            sig_alg=alg,
            signature=sign(tbs, root_sec, alg),
        )

        pub, _ = generate_keypair(ALG_ML_DSA_44)
        ee = issue_certificate(Name(cn="EE", org="O"), pub, root_cert, root_sec, 365)

        with pytest.raises(VerificationError) as exc_info:
            verify_chain([ee], trusted_root=root_cert, crl=expired_crl)
        assert exc_info.value.code == VerificationCode.CRL_EXPIRED

    def test_crl_invalid_signature_raises(self, root_cert, root_sec):
        """verify_chain raises INVALID_SIGNATURE for a CRL with tampered signature."""
        crl = RevocationList.create(root_cert, root_sec, [], next_update_days=30)
        bad_sig = bytearray(crl.signature)
        bad_sig[0] ^= 0xFF
        tampered_crl = RevocationList(
            issuer_key_id=crl.issuer_key_id,
            this_update=crl.this_update,
            next_update=crl.next_update,
            revoked_serials=crl.revoked_serials,
            sig_alg=crl.sig_alg,
            signature=bytes(bad_sig),
        )

        pub, _ = generate_keypair(ALG_ML_DSA_44)
        ee = issue_certificate(Name(cn="EE", org="O"), pub, root_cert, root_sec, 365)

        with pytest.raises(VerificationError) as exc_info:
            verify_chain([ee], trusted_root=root_cert, crl=tampered_crl)
        assert exc_info.value.code == VerificationCode.INVALID_SIGNATURE

    def test_crl_issuer_not_in_chain_raises(self, root_cert, root_sec):
        """verify_chain raises CRL_UNTRUSTED when CRL issuer is not in the chain."""
        other_root, other_sec = create_root_ca(
            Name(cn="Other CA", org="O"), 3650, ALG_ML_DSA_44
        )
        foreign_crl = RevocationList.create(other_root, other_sec, [], next_update_days=30)

        pub, _ = generate_keypair(ALG_ML_DSA_44)
        ee = issue_certificate(Name(cn="EE", org="O"), pub, root_cert, root_sec, 365)

        with pytest.raises(VerificationError) as exc_info:
            verify_chain([ee], trusted_root=root_cert, crl=foreign_crl)
        assert exc_info.value.code == VerificationCode.CRL_UNTRUSTED
