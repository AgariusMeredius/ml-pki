"""
Constants for the mlpki library.

All field numbers, algorithm IDs, and key-usage flags used throughout
the CBOR-serialized data structures.
"""

# ---------------------------------------------------------------------------
# Algorithm IDs
# ---------------------------------------------------------------------------
ALG_ML_DSA_44: int = 1
ALG_ML_DSA_65: int = 2
ALG_ML_DSA_87: int = 3

ALG_NAMES: dict[int, str] = {
    ALG_ML_DSA_44: "ML-DSA-44",
    ALG_ML_DSA_65: "ML-DSA-65",
    ALG_ML_DSA_87: "ML-DSA-87",
}

# ---------------------------------------------------------------------------
# Key-Usage bitmask flags
# ---------------------------------------------------------------------------
KEY_USAGE_DIGITAL_SIGNATURE: int = 0x01
KEY_USAGE_KEY_CERT_SIGN: int = 0x02
KEY_USAGE_CRL_SIGN: int = 0x04

# ---------------------------------------------------------------------------
# TBSCertificate field numbers (CBOR integer keys)
# ---------------------------------------------------------------------------
TBS_VERSION: int = 1
TBS_SERIAL: int = 2
TBS_ISSUER: int = 3
TBS_SUBJECT: int = 4
TBS_NOT_BEFORE: int = 5
TBS_NOT_AFTER: int = 6
TBS_PUBLIC_KEY: int = 7
TBS_IS_CA: int = 8
TBS_PATH_LEN: int = 9
TBS_KEY_USAGE: int = 10
TBS_SUBJECT_KEY_ID: int = 11
TBS_AUTH_KEY_ID: int = 12

# ---------------------------------------------------------------------------
# Name sub-map field numbers
# ---------------------------------------------------------------------------
NAME_CN: int = 1
NAME_ORG: int = 2
NAME_OU: int = 3

# ---------------------------------------------------------------------------
# PublicKey sub-map field numbers
# ---------------------------------------------------------------------------
PUBKEY_ALG_ID: int = 1
PUBKEY_KEY_BYTES: int = 2

# ---------------------------------------------------------------------------
# Certificate outer structure field numbers
# ---------------------------------------------------------------------------
CERT_TBS_BYTES: int = 1
CERT_SIG_ALG: int = 2
CERT_SIGNATURE: int = 3

# ---------------------------------------------------------------------------
# CSR field numbers
# ---------------------------------------------------------------------------
CSR_VERSION: int = 1
CSR_SUBJECT: int = 2
CSR_PUBLIC_KEY: int = 3
CSR_SIG_ALG: int = 4
CSR_SIGNATURE: int = 5
CSR_IS_CA: int = 6
CSR_PATH_LEN: int = 7
CSR_KEY_USAGE: int = 8

# ---------------------------------------------------------------------------
# CRL field numbers
# ---------------------------------------------------------------------------
CRL_ISSUER_KEY_ID: int = 1
CRL_THIS_UPDATE: int = 2
CRL_NEXT_UPDATE: int = 3
CRL_REVOKED_SERIALS: int = 4
CRL_SIG_ALG: int = 5
CRL_SIGNATURE: int = 6

# ---------------------------------------------------------------------------
# Encrypted key file field numbers
# ---------------------------------------------------------------------------
KEYFILE_ALG_ID: int = 1
KEYFILE_ARGON2_PARAMS: int = 2
KEYFILE_NONCE: int = 3
KEYFILE_CIPHERTEXT: int = 4
KEYFILE_TAG: int = 5

# Argon2id parameter sub-map field numbers
ARGON2_TIME_COST: int = 1
ARGON2_MEMORY_COST: int = 2
ARGON2_PARALLELISM: int = 3
ARGON2_SALT: int = 4

# ---------------------------------------------------------------------------
# Certificate format
# ---------------------------------------------------------------------------
CERT_VERSION: int = 1

PEM_CERT_HEADER: str = "-----BEGIN ML-CERTIFICATE-----"
PEM_CERT_FOOTER: str = "-----END ML-CERTIFICATE-----"
PEM_CSR_HEADER: str = "-----BEGIN ML-CERTIFICATE REQUEST-----"
PEM_CSR_FOOTER: str = "-----END ML-CERTIFICATE REQUEST-----"
