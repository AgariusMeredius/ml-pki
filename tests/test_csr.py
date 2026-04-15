"""Tests for csr.py — CSR creation, self-signature, round-trips, workflow."""

import pytest

from mlpki import (
    ALG_ML_DSA_44,
    CertificateSigningRequest,
    Name,
    generate_keypair,
    issue_from_csr,
    verify_chain,
    verify_signature,
    KEY_USAGE_DIGITAL_SIGNATURE,
    KEY_USAGE_KEY_CERT_SIGN,
    KEY_USAGE_CRL_SIGN,
)


# ---------------------------------------------------------------------------
# CSR creation
# ---------------------------------------------------------------------------

class TestCSRCreate:
    def test_creates_csr(self):
        pub, sec = generate_keypair(ALG_ML_DSA_44)
        csr = CertificateSigningRequest.create(
            subject=Name(cn="Test", org="Org"),
            pub=pub, sec=sec, alg=ALG_ML_DSA_44,
        )
        assert isinstance(csr, CertificateSigningRequest)

    def test_version_is_1(self):
        pub, sec = generate_keypair(ALG_ML_DSA_44)
        csr = CertificateSigningRequest.create(
            subject=Name(cn="T", org="O"), pub=pub, sec=sec, alg=ALG_ML_DSA_44
        )
        assert csr.version == 1

    def test_subject_preserved(self):
        pub, sec = generate_keypair(ALG_ML_DSA_44)
        subject = Name(cn="My Name", org="My Org", ou="My OU")
        csr = CertificateSigningRequest.create(
            subject=subject, pub=pub, sec=sec, alg=ALG_ML_DSA_44
        )
        assert csr.subject == subject

    def test_public_key_preserved(self):
        pub, sec = generate_keypair(ALG_ML_DSA_44)
        csr = CertificateSigningRequest.create(
            subject=Name(cn="T", org="O"), pub=pub, sec=sec, alg=ALG_ML_DSA_44
        )
        assert csr.public_key.key_bytes == pub

    def test_is_ca_false_by_default(self):
        pub, sec = generate_keypair(ALG_ML_DSA_44)
        csr = CertificateSigningRequest.create(
            subject=Name(cn="T", org="O"), pub=pub, sec=sec, alg=ALG_ML_DSA_44
        )
        assert csr.is_ca is False

    def test_is_ca_can_be_true(self):
        pub, sec = generate_keypair(ALG_ML_DSA_44)
        csr = CertificateSigningRequest.create(
            subject=Name(cn="T", org="O"), pub=pub, sec=sec, alg=ALG_ML_DSA_44,
            is_ca=True, path_len=0,
        )
        assert csr.is_ca is True
        assert csr.path_len == 0


# ---------------------------------------------------------------------------
# Self-signature verification
# ---------------------------------------------------------------------------

class TestCSRSelfSignature:
    def test_valid_self_signature(self):
        pub, sec = generate_keypair(ALG_ML_DSA_44)
        csr = CertificateSigningRequest.create(
            subject=Name(cn="T", org="O"), pub=pub, sec=sec, alg=ALG_ML_DSA_44
        )
        assert csr.verify_self_signature() is True

    def test_tampered_subject_fails(self):
        pub, sec = generate_keypair(ALG_ML_DSA_44)
        csr = CertificateSigningRequest.create(
            subject=Name(cn="Original", org="O"), pub=pub, sec=sec, alg=ALG_ML_DSA_44
        )
        csr.subject = Name(cn="Tampered", org="O")
        assert csr.verify_self_signature() is False

    def test_tampered_signature_fails(self):
        pub, sec = generate_keypair(ALG_ML_DSA_44)
        csr = CertificateSigningRequest.create(
            subject=Name(cn="T", org="O"), pub=pub, sec=sec, alg=ALG_ML_DSA_44
        )
        bad_sig = bytearray(csr.signature)
        bad_sig[0] ^= 0xFF
        csr.signature = bytes(bad_sig)
        assert csr.verify_self_signature() is False


# ---------------------------------------------------------------------------
# CBOR round-trip
# ---------------------------------------------------------------------------

class TestCSRCBOR:
    def test_encode_decode(self):
        pub, sec = generate_keypair(ALG_ML_DSA_44)
        subject = Name(cn="Round-Trip", org="Org", ou="Unit")
        csr = CertificateSigningRequest.create(
            subject=subject, pub=pub, sec=sec, alg=ALG_ML_DSA_44,
            is_ca=False, key_usage=KEY_USAGE_DIGITAL_SIGNATURE
        )
        recovered = CertificateSigningRequest.decode(csr.encode())
        assert recovered.subject == csr.subject
        assert recovered.public_key.key_bytes == csr.public_key.key_bytes
        assert recovered.sig_alg == csr.sig_alg
        assert recovered.signature == csr.signature
        assert recovered.is_ca == csr.is_ca
        assert recovered.key_usage == csr.key_usage

    def test_self_signature_still_valid_after_round_trip(self):
        pub, sec = generate_keypair(ALG_ML_DSA_44)
        csr = CertificateSigningRequest.create(
            subject=Name(cn="T", org="O"), pub=pub, sec=sec, alg=ALG_ML_DSA_44
        )
        recovered = CertificateSigningRequest.decode(csr.encode())
        assert recovered.verify_self_signature() is True


# ---------------------------------------------------------------------------
# PEM round-trip
# ---------------------------------------------------------------------------

class TestCSRPEM:
    def test_to_pem_contains_headers(self):
        pub, sec = generate_keypair(ALG_ML_DSA_44)
        csr = CertificateSigningRequest.create(
            subject=Name(cn="T", org="O"), pub=pub, sec=sec, alg=ALG_ML_DSA_44
        )
        pem = csr.to_pem()
        assert "-----BEGIN ML-CERTIFICATE REQUEST-----" in pem
        assert "-----END ML-CERTIFICATE REQUEST-----" in pem

    def test_pem_round_trip(self):
        pub, sec = generate_keypair(ALG_ML_DSA_44)
        csr = CertificateSigningRequest.create(
            subject=Name(cn="PEM Test", org="Org"), pub=pub, sec=sec, alg=ALG_ML_DSA_44
        )
        recovered = CertificateSigningRequest.from_pem(csr.to_pem())
        assert recovered.subject == csr.subject
        assert recovered.signature == csr.signature

    def test_self_signature_valid_after_pem_round_trip(self):
        pub, sec = generate_keypair(ALG_ML_DSA_44)
        csr = CertificateSigningRequest.create(
            subject=Name(cn="T", org="O"), pub=pub, sec=sec, alg=ALG_ML_DSA_44
        )
        recovered = CertificateSigningRequest.from_pem(csr.to_pem())
        assert recovered.verify_self_signature() is True


# ---------------------------------------------------------------------------
# CSR → Certificate workflow
# ---------------------------------------------------------------------------

class TestCSRWorkflow:
    def test_csr_to_issued_cert(self, root_cert, root_sec):
        pub, sec = generate_keypair(ALG_ML_DSA_44)
        csr = CertificateSigningRequest.create(
            subject=Name(cn="Applicant", org="Org"),
            pub=pub, sec=sec, alg=ALG_ML_DSA_44,
            key_usage=KEY_USAGE_DIGITAL_SIGNATURE,
        )
        assert csr.verify_self_signature()
        cert = issue_from_csr(csr, root_cert, root_sec, validity_days=365)
        verify_signature(cert, root_cert)
        verify_chain([cert], trusted_root=root_cert)
