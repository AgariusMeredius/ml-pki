"""Tests for ca.py — root CA, intermediate, end-entity certificate issuance."""

import time

import pytest

from mlpki import (
    ALG_ML_DSA_44,
    Certificate,
    Name,
    create_root_ca,
    create_self_signed,
    generate_keypair,
    issue_certificate,
    issue_from_csr,
    verify_chain,
    verify_self_signed,
    verify_signature,
    KEY_USAGE_CRL_SIGN,
    KEY_USAGE_DIGITAL_SIGNATURE,
    KEY_USAGE_KEY_CERT_SIGN,
    CertificateSigningRequest,
)


# ---------------------------------------------------------------------------
# Root CA creation
# ---------------------------------------------------------------------------

class TestCreateRootCA:
    def test_returns_cert_and_bytes(self):
        cert, sec = create_root_ca(Name(cn="Root", org="Org"), validity_days=365, alg=ALG_ML_DSA_44)
        assert isinstance(cert, Certificate)
        assert isinstance(sec, bytes)

    def test_is_ca_flag(self, root_cert):
        assert root_cert.tbs.is_ca is True

    def test_path_len_is_1(self, root_cert):
        assert root_cert.tbs.path_len == 1

    def test_self_signed(self, root_cert):
        tbs = root_cert.tbs
        assert tbs.issuer == tbs.subject

    def test_auth_key_id_equals_subject_key_id(self, root_cert):
        tbs = root_cert.tbs
        assert tbs.auth_key_id == tbs.subject_key_id

    def test_valid_self_signature(self, root_cert):
        verify_self_signed(root_cert)  # must not raise

    def test_has_key_cert_sign(self, root_cert):
        assert root_cert.tbs.key_usage & KEY_USAGE_KEY_CERT_SIGN

    def test_has_crl_sign(self, root_cert):
        assert root_cert.tbs.key_usage & KEY_USAGE_CRL_SIGN

    def test_validity_window(self):
        before = int(time.time()) - 2
        cert, _ = create_root_ca(Name(cn="R", org="O"), validity_days=100, alg=ALG_ML_DSA_44)
        after = int(time.time()) + 2
        assert before <= cert.tbs.not_before <= after
        expected_after = cert.tbs.not_before + 100 * 86400
        assert cert.tbs.not_after == expected_after

    def test_serial_is_16_bytes(self, root_cert):
        assert len(root_cert.tbs.serial) == 16

    def test_unique_serials(self):
        cert1, _ = create_root_ca(Name(cn="R1", org="O"), validity_days=1, alg=ALG_ML_DSA_44)
        cert2, _ = create_root_ca(Name(cn="R2", org="O"), validity_days=1, alg=ALG_ML_DSA_44)
        assert cert1.tbs.serial != cert2.tbs.serial


# ---------------------------------------------------------------------------
# Intermediate CA issuance
# ---------------------------------------------------------------------------

class TestIssueIntermediate:
    def test_intermediate_is_ca(self, intermediate_cert):
        assert intermediate_cert.tbs.is_ca is True

    def test_intermediate_path_len(self, intermediate_cert):
        assert intermediate_cert.tbs.path_len == 0

    def test_intermediate_signature_valid(self, root_cert, intermediate_cert):
        verify_signature(intermediate_cert, root_cert)  # must not raise

    def test_auth_key_id_matches_root(self, root_cert, intermediate_cert):
        assert intermediate_cert.tbs.auth_key_id == root_cert.tbs.subject_key_id


# ---------------------------------------------------------------------------
# End-entity issuance
# ---------------------------------------------------------------------------

class TestIssueEndEntity:
    def test_ee_not_ca(self, ee_cert):
        assert ee_cert.tbs.is_ca is False

    def test_ee_signature_valid(self, intermediate_cert, ee_cert):
        verify_signature(ee_cert, intermediate_cert)  # must not raise

    def test_ee_auth_key_id_matches_intermediate(self, intermediate_cert, ee_cert):
        assert ee_cert.tbs.auth_key_id == intermediate_cert.tbs.subject_key_id

    def test_ee_key_usage(self, ee_cert):
        assert ee_cert.tbs.key_usage & KEY_USAGE_DIGITAL_SIGNATURE


# ---------------------------------------------------------------------------
# Self-signed (non-CA)
# ---------------------------------------------------------------------------

class TestCreateSelfSigned:
    def test_self_signed_not_ca_by_default(self):
        pub, sec = generate_keypair(ALG_ML_DSA_44)
        cert = create_self_signed(
            subject=Name(cn="Service", org="Org"),
            pub=pub, sec=sec,
            validity_days=365, alg=ALG_ML_DSA_44,
        )
        assert cert.tbs.is_ca is False

    def test_self_signed_signature_valid(self):
        pub, sec = generate_keypair(ALG_ML_DSA_44)
        cert = create_self_signed(
            subject=Name(cn="Service", org="Org"),
            pub=pub, sec=sec,
            validity_days=365, alg=ALG_ML_DSA_44,
        )
        verify_self_signed(cert)  # must not raise

    def test_self_signed_subject_key_id(self):
        import hashlib
        pub, sec = generate_keypair(ALG_ML_DSA_44)
        cert = create_self_signed(
            subject=Name(cn="S", org="O"),
            pub=pub, sec=sec,
            validity_days=1, alg=ALG_ML_DSA_44,
        )
        expected_skid = hashlib.sha3_256(pub).digest()[:16]
        assert cert.tbs.subject_key_id == expected_skid


# ---------------------------------------------------------------------------
# issue_from_csr
# ---------------------------------------------------------------------------

class TestIssueFromCSR:
    def test_csr_to_cert(self, root_cert, root_sec):
        pub, sec = generate_keypair(ALG_ML_DSA_44)
        csr = CertificateSigningRequest.create(
            subject=Name(cn="CSR Holder", org="Org"),
            pub=pub, sec=sec, alg=ALG_ML_DSA_44,
            key_usage=KEY_USAGE_DIGITAL_SIGNATURE,
        )
        cert = issue_from_csr(csr, root_cert, root_sec, validity_days=365)
        verify_signature(cert, root_cert)  # must not raise

    def test_csr_fields_transferred(self, root_cert, root_sec):
        pub, sec = generate_keypair(ALG_ML_DSA_44)
        csr = CertificateSigningRequest.create(
            subject=Name(cn="CA Holder", org="Org"),
            pub=pub, sec=sec, alg=ALG_ML_DSA_44,
            is_ca=True, path_len=0,
            key_usage=KEY_USAGE_KEY_CERT_SIGN | KEY_USAGE_CRL_SIGN,
        )
        cert = issue_from_csr(csr, root_cert, root_sec, validity_days=365)
        assert cert.tbs.is_ca is True
        assert cert.tbs.path_len == 0

    def test_invalid_csr_sig_raises(self, root_cert, root_sec):
        """issue_from_csr raises ValueError when CSR self-signature is invalid."""
        pub, sec = generate_keypair(ALG_ML_DSA_44)
        csr = CertificateSigningRequest.create(
            subject=Name(cn="CSR Holder", org="Org"),
            pub=pub, sec=sec, alg=ALG_ML_DSA_44,
        )
        tampered_csr = CertificateSigningRequest(
            version=csr.version,
            subject=csr.subject,
            public_key=csr.public_key,
            sig_alg=csr.sig_alg,
            signature=bytes([x ^ 0xFF for x in csr.signature[:8]]) + csr.signature[8:],
            is_ca=csr.is_ca,
            path_len=csr.path_len,
            key_usage=csr.key_usage,
        )
        with pytest.raises(ValueError, match="self-signature"):
            issue_from_csr(tampered_csr, root_cert, root_sec)


# ---------------------------------------------------------------------------
# Issuer validation (new security checks)
# ---------------------------------------------------------------------------

class TestIssuerValidation:
    def test_non_ca_issuer_raises(self, root_cert, root_sec):
        """issue_certificate raises ValueError when the issuer is not a CA."""
        ee_pub, ee_sec = generate_keypair(ALG_ML_DSA_44)
        ee = issue_certificate(
            Name(cn="EE", org="Org"), ee_pub, root_cert, root_sec, validity_days=365
        )
        sub_pub, _ = generate_keypair(ALG_ML_DSA_44)
        with pytest.raises(ValueError, match="not a CA"):
            issue_certificate(
                subject=Name(cn="Sub", org="Org"),
                subject_pub=sub_pub,
                issuer_cert=ee,      # end-entity cert, not a CA
                issuer_sec=ee_sec,
                validity_days=365,
            )

    def test_missing_key_cert_sign_raises(self, root_cert, root_sec):
        """issue_certificate raises ValueError when the issuer lacks KEY_CERT_SIGN."""
        bad_pub, bad_sec = generate_keypair(ALG_ML_DSA_44)
        bad_ca = create_self_signed(
            subject=Name(cn="Bad CA", org="Org"),
            pub=bad_pub, sec=bad_sec,
            validity_days=365, alg=ALG_ML_DSA_44,
            key_usage=KEY_USAGE_CRL_SIGN,  # CRL_SIGN but NOT KEY_CERT_SIGN
            is_ca=True,
        )
        sub_pub, _ = generate_keypair(ALG_ML_DSA_44)
        with pytest.raises(ValueError, match="KEY_CERT_SIGN"):
            issue_certificate(
                subject=Name(cn="Sub", org="Org"),
                subject_pub=sub_pub,
                issuer_cert=bad_ca,
                issuer_sec=bad_sec,
                validity_days=365,
            )


# ---------------------------------------------------------------------------
# Path-length constraint enforcement at issuance time
# ---------------------------------------------------------------------------

class TestPathLenEnforcement:
    def test_path_len_zero_blocks_ca_issuance(self, intermediate_cert, intermediate_sec):
        """issue_certificate raises when issuer path_len=0 and is_ca=True requested."""
        sub_pub, _ = generate_keypair(ALG_ML_DSA_44)
        with pytest.raises(ValueError, match="path_len"):
            issue_certificate(
                subject=Name(cn="Sub CA", org="Org"),
                subject_pub=sub_pub,
                issuer_cert=intermediate_cert,  # path_len=0 in conftest fixture
                issuer_sec=intermediate_sec,
                validity_days=365,
                is_ca=True,
                path_len=0,
            )

    def test_path_len_none_under_constrained_issuer_raises(self, root_cert, root_sec):
        """Requesting path_len=None (unconstrained) under a constrained issuer raises."""
        sub_pub, _ = generate_keypair(ALG_ML_DSA_44)
        with pytest.raises(ValueError, match="path_len"):
            issue_certificate(
                subject=Name(cn="Sub CA", org="Org"),
                subject_pub=sub_pub,
                issuer_cert=root_cert,   # path_len=1, max allowed = 0
                issuer_sec=root_sec,
                validity_days=365,
                is_ca=True,
                path_len=None,           # unconstrained > 0
            )

    def test_path_len_too_large_raises(self, root_cert, root_sec):
        """Requesting path_len > max_allowed by issuer raises ValueError."""
        sub_pub, _ = generate_keypair(ALG_ML_DSA_44)
        with pytest.raises(ValueError, match="path_len"):
            issue_certificate(
                subject=Name(cn="Sub CA", org="Org"),
                subject_pub=sub_pub,
                issuer_cert=root_cert,   # path_len=1 → max_sub = 0
                issuer_sec=root_sec,
                validity_days=365,
                is_ca=True,
                path_len=1,              # 1 > 0
            )

    def test_path_len_at_max_succeeds(self, root_cert, root_sec):
        """Requesting exactly max_allowed path_len succeeds."""
        sub_pub, _ = generate_keypair(ALG_ML_DSA_44)
        cert = issue_certificate(
            subject=Name(cn="Sub CA", org="Org"),
            subject_pub=sub_pub,
            issuer_cert=root_cert,   # path_len=1 → max_sub = 0
            issuer_sec=root_sec,
            validity_days=365,
            is_ca=True,
            path_len=0,              # exactly at maximum
        )
        assert cert.tbs.path_len == 0

    def test_unconstrained_issuer_allows_any_path_len(self):
        """When issuer path_len=None, any sub-CA path_len is accepted."""
        pub, sec = generate_keypair(ALG_ML_DSA_44)
        unconstrained_root = create_self_signed(
            subject=Name(cn="Unconstrained Root", org="Org"),
            pub=pub, sec=sec,
            validity_days=3650, alg=ALG_ML_DSA_44,
            key_usage=KEY_USAGE_KEY_CERT_SIGN | KEY_USAGE_CRL_SIGN,
            is_ca=True,
            path_len=None,
        )
        sub_pub, _ = generate_keypair(ALG_ML_DSA_44)
        cert = issue_certificate(
            subject=Name(cn="Sub CA", org="Org"),
            subject_pub=sub_pub,
            issuer_cert=unconstrained_root,
            issuer_sec=sec,
            validity_days=365,
            is_ca=True,
            path_len=5,              # accepted — no issuer constraint
        )
        assert cert.tbs.path_len == 5

    def test_non_ca_issuance_ignores_path_len_check(self, intermediate_cert, intermediate_sec):
        """Issuing a non-CA cert never triggers the path_len enforcement."""
        ee_pub, _ = generate_keypair(ALG_ML_DSA_44)
        # intermediate_cert has path_len=0, but EE (is_ca=False) is always allowed
        cert = issue_certificate(
            subject=Name(cn="EE", org="Org"),
            subject_pub=ee_pub,
            issuer_cert=intermediate_cert,
            issuer_sec=intermediate_sec,
            validity_days=365,
            is_ca=False,
        )
        assert cert.tbs.is_ca is False
