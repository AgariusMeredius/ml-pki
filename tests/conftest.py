"""
Shared pytest fixtures for the mlpki test suite.

All cryptographic material is generated once per session to keep tests fast.
No network access is required.
"""

import pytest

from mlpki import (
    ALG_ML_DSA_44,
    ALG_ML_DSA_65,
    Certificate,
    CertificateSigningRequest,
    Name,
    RevocationList,
    create_root_ca,
    generate_keypair,
    issue_certificate,
    issue_from_csr,
    KEY_USAGE_CRL_SIGN,
    KEY_USAGE_DIGITAL_SIGNATURE,
    KEY_USAGE_KEY_CERT_SIGN,
)


# ---------------------------------------------------------------------------
# Algorithm — use the smallest ML-DSA variant to keep tests fast
# ---------------------------------------------------------------------------
ALG = ALG_ML_DSA_44


@pytest.fixture(scope="session")
def root_name() -> Name:
    return Name(cn="Test Root CA", org="Test Organization", ou="PKI")


@pytest.fixture(scope="session")
def intermediate_name() -> Name:
    return Name(cn="Test Intermediate CA", org="Test Organization", ou="PKI")


@pytest.fixture(scope="session")
def ee_name() -> Name:
    return Name(cn="Test End Entity", org="Test Organization")


@pytest.fixture(scope="session")
def root(root_name) -> tuple[Certificate, bytes]:
    """Root CA certificate and secret key."""
    return create_root_ca(root_name, validity_days=3650, alg=ALG)


@pytest.fixture(scope="session")
def root_cert(root) -> Certificate:
    return root[0]


@pytest.fixture(scope="session")
def root_sec(root) -> bytes:
    return root[1]


@pytest.fixture(scope="session")
def intermediate_keys() -> tuple[bytes, bytes]:
    return generate_keypair(ALG)


@pytest.fixture(scope="session")
def intermediate_cert(intermediate_keys, intermediate_name, root_cert, root_sec) -> Certificate:
    inter_pub, _ = intermediate_keys
    return issue_certificate(
        subject=intermediate_name,
        subject_pub=inter_pub,
        issuer_cert=root_cert,
        issuer_sec=root_sec,
        validity_days=1825,
        is_ca=True,
        path_len=0,
        key_usage=KEY_USAGE_KEY_CERT_SIGN | KEY_USAGE_CRL_SIGN | KEY_USAGE_DIGITAL_SIGNATURE,
    )


@pytest.fixture(scope="session")
def intermediate_sec(intermediate_keys) -> bytes:
    return intermediate_keys[1]


@pytest.fixture(scope="session")
def ee_keys() -> tuple[bytes, bytes]:
    return generate_keypair(ALG)


@pytest.fixture(scope="session")
def ee_cert(ee_keys, ee_name, intermediate_cert, intermediate_sec) -> Certificate:
    ee_pub, _ = ee_keys
    return issue_certificate(
        subject=ee_name,
        subject_pub=ee_pub,
        issuer_cert=intermediate_cert,
        issuer_sec=intermediate_sec,
        validity_days=365,
        key_usage=KEY_USAGE_DIGITAL_SIGNATURE,
    )


@pytest.fixture(scope="session")
def crl(root_cert, root_sec) -> RevocationList:
    return RevocationList.create(root_cert, root_sec, [], next_update_days=30)
