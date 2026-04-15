"""
Key generation, signing, verification and encrypted key storage.

Uses liboqs (ML-DSA) for asymmetric operations and
Argon2id + AES-256-GCM for encrypted key storage.
"""

from __future__ import annotations

import os

import cbor2
from argon2.low_level import Type, hash_secret_raw
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

from .constants import (
    ALG_ML_DSA_44,
    ALG_ML_DSA_65,
    ALG_ML_DSA_87,
    ALG_NAMES,
    ARGON2_MEMORY_COST,
    ARGON2_PARALLELISM,
    ARGON2_SALT,
    ARGON2_TIME_COST,
    KEYFILE_ALG_ID,
    KEYFILE_ARGON2_PARAMS,
    KEYFILE_CIPHERTEXT,
    KEYFILE_NONCE,
    KEYFILE_TAG,
)

# Argon2id defaults used when saving a new key file.
_ARGON2_TIME_COST: int = 3
_ARGON2_MEMORY_COST: int = 65536  # 64 MiB
_ARGON2_PARALLELISM: int = 4
_SALT_LEN: int = 16
_NONCE_LEN: int = 12
_KEY_LEN: int = 32

# Minimum Argon2id parameters accepted when *loading* a key file.
# These guards prevent a tampered key file from downgrading the KDF work
# factor to make offline brute-force attacks trivially cheap.
# Values are conservative minimums; production files should exceed them.
_MIN_ARGON2_TIME_COST: int = 1
_MIN_ARGON2_MEMORY_COST: int = 8192   # 8 MiB absolute floor
_MIN_ARGON2_PARALLELISM: int = 1


def _oqs_sig(alg: int):
    """Return an oqs Signature instance for the given algorithm ID."""
    from oqs.oqs import Signature  # deferred to avoid top-level native load
    name = ALG_NAMES.get(alg)
    if name is None:
        raise ValueError(f"Unknown algorithm ID: {alg}")
    return Signature(name)


def generate_keypair(alg: int = ALG_ML_DSA_65) -> tuple[bytes, bytes]:
    """
    Generate an ML-DSA key pair.

    Returns:
        (public_key_bytes, secret_key_bytes)
    """
    sig = _oqs_sig(alg)
    pub = sig.generate_keypair()
    sec = sig.export_secret_key()
    return bytes(pub), bytes(sec)


def sign(message: bytes, secret_key: bytes, alg: int) -> bytes:
    """
    Sign *message* with *secret_key* using the given algorithm.

    Returns:
        Raw signature bytes.
    """
    from oqs.oqs import Signature
    name = ALG_NAMES.get(alg)
    if name is None:
        raise ValueError(f"Unknown algorithm ID: {alg}")
    # Pass secret_key directly to constructor; avoids a generate_keypair call
    sig = Signature(name, secret_key=secret_key)
    return bytes(sig.sign(message))


def verify(message: bytes, signature: bytes, public_key: bytes, alg: int) -> bool:
    """
    Verify *signature* over *message* with *public_key*.

    Returns:
        True if valid, False otherwise.
    """
    sig = _oqs_sig(alg)
    return bool(sig.verify(message, signature, public_key))


def save_secret_key(
    path: str,
    secret_key: bytes,
    alg: int,
    password: bytes,
) -> None:
    """
    Encrypt and save *secret_key* to *path*.

    Encryption: Argon2id key derivation → AES-256-GCM.
    File format: CBOR map with integer keys.
    """
    salt = os.urandom(_SALT_LEN)
    nonce = os.urandom(_NONCE_LEN)

    derived = hash_secret_raw(
        secret=password,
        salt=salt,
        time_cost=_ARGON2_TIME_COST,
        memory_cost=_ARGON2_MEMORY_COST,
        parallelism=_ARGON2_PARALLELISM,
        hash_len=_KEY_LEN,
        type=Type.ID,
    )

    aesgcm = AESGCM(derived)
    encrypted = aesgcm.encrypt(nonce, secret_key, None)
    # AESGCM.encrypt returns ciphertext + 16-byte tag appended
    ciphertext = encrypted[:-16]
    tag = encrypted[-16:]

    argon2_params = {
        ARGON2_TIME_COST: _ARGON2_TIME_COST,
        ARGON2_MEMORY_COST: _ARGON2_MEMORY_COST,
        ARGON2_PARALLELISM: _ARGON2_PARALLELISM,
        ARGON2_SALT: salt,
    }

    data = {
        KEYFILE_ALG_ID: alg,
        KEYFILE_ARGON2_PARAMS: argon2_params,
        KEYFILE_NONCE: nonce,
        KEYFILE_CIPHERTEXT: ciphertext,
        KEYFILE_TAG: tag,
    }

    with open(path, "wb") as f:
        f.write(cbor2.dumps(data))


def load_secret_key(path: str, password: bytes) -> tuple[bytes, int]:
    """
    Load and decrypt a secret key from *path*.

    Returns:
        (secret_key_bytes, alg_id)

    Raises:
        ValueError: if the password is incorrect or the file is corrupted.
    """
    with open(path, "rb") as f:
        data = cbor2.loads(f.read())

    alg: int = data[KEYFILE_ALG_ID]
    params = data[KEYFILE_ARGON2_PARAMS]
    nonce = bytes(data[KEYFILE_NONCE])
    ciphertext = bytes(data[KEYFILE_CIPHERTEXT])
    tag = bytes(data[KEYFILE_TAG])

    salt = bytes(params[ARGON2_SALT])
    time_cost = params[ARGON2_TIME_COST]
    memory_cost = params[ARGON2_MEMORY_COST]
    parallelism = params[ARGON2_PARALLELISM]

    # Reject key files whose Argon2id parameters fall below minimums.
    # A tampered file could use e.g. memory_cost=1 to make brute-force
    # of the password trivially fast.
    if alg not in ALG_NAMES:
        raise ValueError(f"Unknown algorithm ID in key file: {alg!r}")
    if time_cost < _MIN_ARGON2_TIME_COST:
        raise ValueError(
            f"Key file time_cost={time_cost} is below the minimum "
            f"({_MIN_ARGON2_TIME_COST}); file may be tampered"
        )
    if memory_cost < _MIN_ARGON2_MEMORY_COST:
        raise ValueError(
            f"Key file memory_cost={memory_cost} KiB is below the minimum "
            f"({_MIN_ARGON2_MEMORY_COST} KiB); file may be tampered"
        )
    if parallelism < _MIN_ARGON2_PARALLELISM:
        raise ValueError(
            f"Key file parallelism={parallelism} is below the minimum "
            f"({_MIN_ARGON2_PARALLELISM}); file may be tampered"
        )

    derived = hash_secret_raw(
        secret=password,
        salt=salt,
        time_cost=time_cost,
        memory_cost=memory_cost,
        parallelism=parallelism,
        hash_len=_KEY_LEN,
        type=Type.ID,
    )

    aesgcm = AESGCM(derived)
    try:
        secret_key = aesgcm.decrypt(nonce, ciphertext + tag, None)
    except Exception as exc:
        raise ValueError("Decryption failed: wrong password or corrupted file") from exc

    return bytes(secret_key), alg
