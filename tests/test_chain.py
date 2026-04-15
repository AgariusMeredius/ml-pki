"""
End-to-end 3-level chain test: Root → Intermediate → End Entity with CRL.

This test covers the full workflow without any mocks or shortcuts.
No network access required.
"""

import pytest

from mlpki import (
    ALG_ML_DSA_44,
    CertificateSigningRequest,
    Name,
    RevocationList,
    create_root_ca,
    generate_keypair,
    issue_certificate,
    issue_from_csr,
    save_secret_key,
    load_secret_key,
    verify_chain,
    verify_self_signed,
    verify_signature,
    KEY_USAGE_CRL_SIGN,
    KEY_USAGE_DIGITAL_SIGNATURE,
    KEY_USAGE_KEY_CERT_SIGN,
)
from mlpki.verify import VerificationCode, VerificationError


@pytest.fixture(scope="module")
def pki():
    """Build a complete 3-level PKI hierarchy for this module."""
    alg = ALG_ML_DSA_44

    # --- Root CA ---
    root_cert, root_sec = create_root_ca(
        Name(cn="Test Root CA", org="Chain Test Org", ou="Root"), validity_days=3650, alg=alg
    )

    # --- Intermediate CA ---
    inter_pub, inter_sec = generate_keypair(alg)
    inter_cert = issue_certificate(
        subject=Name(cn="Test Intermediate CA", org="Chain Test Org", ou="Intermediate"),
        subject_pub=inter_pub,
        issuer_cert=root_cert,
        issuer_sec=root_sec,
        validity_days=1825,
        is_ca=True,
        path_len=0,
        key_usage=KEY_USAGE_KEY_CERT_SIGN | KEY_USAGE_CRL_SIGN | KEY_USAGE_DIGITAL_SIGNATURE,
    )

    # --- End-Entity certificate (via CSR) ---
    ee_pub, ee_sec = generate_keypair(alg)
    csr = CertificateSigningRequest.create(
        subject=Name(cn="Test End Entity", org="Chain Test Org"),
        pub=ee_pub,
        sec=ee_sec,
        alg=alg,
        key_usage=KEY_USAGE_DIGITAL_SIGNATURE,
    )
    ee_cert = issue_from_csr(csr, inter_cert, inter_sec, validity_days=365)

    # --- Second EE that we'll revoke ---
    ee2_pub, _ = generate_keypair(alg)
    ee2_cert = issue_certificate(
        subject=Name(cn="Revocable EE", org="Chain Test Org"),
        subject_pub=ee2_pub,
        issuer_cert=inter_cert,
        issuer_sec=inter_sec,
        validity_days=365,
        key_usage=KEY_USAGE_DIGITAL_SIGNATURE,
    )

    # --- CRL (empty initially) ---
    crl = RevocationList.create(inter_cert, inter_sec, [], next_update_days=30)

    return {
        "root_cert": root_cert,
        "root_sec": root_sec,
        "inter_cert": inter_cert,
        "inter_sec": inter_sec,
        "ee_cert": ee_cert,
        "ee_pub": ee_pub,
        "ee_sec": ee_sec,
        "ee2_cert": ee2_cert,
        "csr": csr,
        "crl": crl,
        "alg": alg,
    }


# ---------------------------------------------------------------------------
# Root CA assertions
# ---------------------------------------------------------------------------

class TestChainRootCA:
    def test_root_is_self_signed(self, pki):
        verify_self_signed(pki["root_cert"])

    def test_root_is_ca(self, pki):
        assert pki["root_cert"].tbs.is_ca is True

    def test_root_has_required_key_usage(self, pki):
        ku = pki["root_cert"].tbs.key_usage
        assert ku & KEY_USAGE_KEY_CERT_SIGN
        assert ku & KEY_USAGE_CRL_SIGN


# ---------------------------------------------------------------------------
# Intermediate CA assertions
# ---------------------------------------------------------------------------

class TestChainIntermediate:
    def test_intermediate_signed_by_root(self, pki):
        verify_signature(pki["inter_cert"], pki["root_cert"])

    def test_intermediate_is_ca(self, pki):
        assert pki["inter_cert"].tbs.is_ca is True

    def test_intermediate_path_len_is_0(self, pki):
        assert pki["inter_cert"].tbs.path_len == 0


# ---------------------------------------------------------------------------
# End-entity assertions
# ---------------------------------------------------------------------------

class TestChainEndEntity:
    def test_ee_signed_by_intermediate(self, pki):
        verify_signature(pki["ee_cert"], pki["inter_cert"])

    def test_ee_not_ca(self, pki):
        assert pki["ee_cert"].tbs.is_ca is False

    def test_ee_has_digital_signature(self, pki):
        assert pki["ee_cert"].tbs.key_usage & KEY_USAGE_DIGITAL_SIGNATURE


# ---------------------------------------------------------------------------
# Full chain verification
# ---------------------------------------------------------------------------

class TestChainVerification:
    def test_valid_chain_no_crl(self, pki):
        verify_chain(
            [pki["inter_cert"], pki["ee_cert"]],
            trusted_root=pki["root_cert"],
        )

    def test_valid_chain_with_empty_crl(self, pki):
        verify_chain(
            [pki["inter_cert"], pki["ee_cert"]],
            trusted_root=pki["root_cert"],
            crl=pki["crl"],
        )

    def test_valid_chain_ee2_no_crl(self, pki):
        verify_chain(
            [pki["inter_cert"], pki["ee2_cert"]],
            trusted_root=pki["root_cert"],
        )


# ---------------------------------------------------------------------------
# Revocation
# ---------------------------------------------------------------------------

class TestChainRevocation:
    def test_revoke_ee2_fails_chain(self, pki):
        crl_with_revocation = pki["crl"].add_serial(
            pki["ee2_cert"].tbs.serial,
            pki["inter_cert"],
            pki["inter_sec"],
        )
        with pytest.raises(VerificationError) as exc_info:
            verify_chain(
                [pki["inter_cert"], pki["ee2_cert"]],
                trusted_root=pki["root_cert"],
                crl=crl_with_revocation,
            )
        assert exc_info.value.code == VerificationCode.REVOKED

    def test_ee1_not_affected_by_ee2_revocation(self, pki):
        crl_with_revocation = pki["crl"].add_serial(
            pki["ee2_cert"].tbs.serial,
            pki["inter_cert"],
            pki["inter_sec"],
        )
        # ee_cert (first EE) must still pass
        verify_chain(
            [pki["inter_cert"], pki["ee_cert"]],
            trusted_root=pki["root_cert"],
            crl=crl_with_revocation,
        )

    def test_crl_round_trip_still_works(self, pki):
        crl2 = RevocationList.decode(pki["crl"].encode())
        verify_chain(
            [pki["inter_cert"], pki["ee_cert"]],
            trusted_root=pki["root_cert"],
            crl=crl2,
        )


# ---------------------------------------------------------------------------
# CSR workflow assertions
# ---------------------------------------------------------------------------

class TestChainCSRWorkflow:
    def test_csr_self_signature(self, pki):
        assert pki["csr"].verify_self_signature() is True

    def test_csr_pem_round_trip_and_issue(self, pki):
        pem = pki["csr"].to_pem()
        recovered_csr = CertificateSigningRequest.from_pem(pem)
        assert recovered_csr.verify_self_signature()
        cert = issue_from_csr(recovered_csr, pki["inter_cert"], pki["inter_sec"], 365)
        verify_chain(
            [pki["inter_cert"], cert],
            trusted_root=pki["root_cert"],
        )


# ---------------------------------------------------------------------------
# Key encryption round-trip in workflow
# ---------------------------------------------------------------------------

class TestChainKeyStorage:
    def test_save_load_root_key_and_sign(self, pki, tmp_path):
        path = str(tmp_path / "root.mlkey")
        save_secret_key(path, pki["root_sec"], pki["alg"], b"secure-pw")
        loaded_sec, loaded_alg = load_secret_key(path, b"secure-pw")
        assert loaded_sec == pki["root_sec"]
        # Issue a cert with the loaded key
        pub, _ = generate_keypair(loaded_alg)
        cert = issue_certificate(
            Name(cn="Loaded Key EE", org="O"),
            pub, pki["root_cert"], loaded_sec, 365,
        )
        verify_chain([cert], trusted_root=pki["root_cert"])

    def test_save_load_inter_key_and_sign(self, pki, tmp_path):
        path = str(tmp_path / "inter.mlkey")
        save_secret_key(path, pki["inter_sec"], pki["alg"], b"pw")
        loaded_sec, loaded_alg = load_secret_key(path, b"pw")
        pub, _ = generate_keypair(loaded_alg)
        cert = issue_certificate(
            Name(cn="Loaded Inter EE", org="O"),
            pub, pki["inter_cert"], loaded_sec, 365,
        )
        verify_chain([pki["inter_cert"], cert], trusted_root=pki["root_cert"])
