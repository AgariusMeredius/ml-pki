"""Tests for keys.py — key generation, sign/verify, encrypted key storage."""

import os
import tempfile

import pytest

from mlpki import (
    ALG_ML_DSA_44,
    ALG_ML_DSA_65,
    ALG_ML_DSA_87,
    generate_keypair,
    load_secret_key,
    save_secret_key,
    sign,
)
from mlpki.keys import verify


# ---------------------------------------------------------------------------
# Key generation
# ---------------------------------------------------------------------------

class TestGenerateKeypair:
    @pytest.mark.parametrize("alg", [ALG_ML_DSA_44, ALG_ML_DSA_65, ALG_ML_DSA_87])
    def test_returns_bytes(self, alg):
        pub, sec = generate_keypair(alg)
        assert isinstance(pub, bytes)
        assert isinstance(sec, bytes)

    @pytest.mark.parametrize("alg", [ALG_ML_DSA_44, ALG_ML_DSA_65, ALG_ML_DSA_87])
    def test_key_lengths_nonzero(self, alg):
        pub, sec = generate_keypair(alg)
        assert len(pub) > 0
        assert len(sec) > 0

    def test_different_keys_each_call(self):
        pub1, sec1 = generate_keypair(ALG_ML_DSA_44)
        pub2, sec2 = generate_keypair(ALG_ML_DSA_44)
        assert pub1 != pub2
        assert sec1 != sec2

    def test_unknown_alg_raises(self):
        with pytest.raises((ValueError, KeyError, Exception)):
            generate_keypair(999)


# ---------------------------------------------------------------------------
# Sign / Verify
# ---------------------------------------------------------------------------

class TestSignVerify:
    def test_valid_signature(self):
        pub, sec = generate_keypair(ALG_ML_DSA_44)
        msg = b"hello world"
        sig = sign(msg, sec, ALG_ML_DSA_44)
        assert verify(msg, sig, pub, ALG_ML_DSA_44)

    def test_different_messages_give_different_sigs(self):
        pub, sec = generate_keypair(ALG_ML_DSA_44)
        sig1 = sign(b"msg1", sec, ALG_ML_DSA_44)
        sig2 = sign(b"msg2", sec, ALG_ML_DSA_44)
        # ML-DSA is randomised; these should almost certainly differ
        # (same message also typically differs, but we test different msgs)
        assert sig1 != sig2

    def test_wrong_key_fails_verify(self):
        pub1, sec1 = generate_keypair(ALG_ML_DSA_44)
        pub2, _sec2 = generate_keypair(ALG_ML_DSA_44)
        msg = b"test"
        sig = sign(msg, sec1, ALG_ML_DSA_44)
        assert not verify(msg, sig, pub2, ALG_ML_DSA_44)

    def test_tampered_message_fails_verify(self):
        pub, sec = generate_keypair(ALG_ML_DSA_44)
        msg = b"original"
        sig = sign(msg, sec, ALG_ML_DSA_44)
        assert not verify(b"tampered", sig, pub, ALG_ML_DSA_44)

    def test_tampered_signature_fails_verify(self):
        pub, sec = generate_keypair(ALG_ML_DSA_44)
        msg = b"test"
        sig = bytearray(sign(msg, sec, ALG_ML_DSA_44))
        sig[0] ^= 0xFF
        assert not verify(msg, bytes(sig), pub, ALG_ML_DSA_44)

    def test_empty_message(self):
        pub, sec = generate_keypair(ALG_ML_DSA_44)
        sig = sign(b"", sec, ALG_ML_DSA_44)
        assert verify(b"", sig, pub, ALG_ML_DSA_44)

    @pytest.mark.parametrize("alg", [ALG_ML_DSA_44, ALG_ML_DSA_65, ALG_ML_DSA_87])
    def test_all_algorithms(self, alg):
        pub, sec = generate_keypair(alg)
        msg = b"algorithm test"
        sig = sign(msg, sec, alg)
        assert verify(msg, sig, pub, alg)


# ---------------------------------------------------------------------------
# Encrypted key storage
# ---------------------------------------------------------------------------

class TestKeyEncryption:
    def test_round_trip(self, tmp_path):
        pub, sec = generate_keypair(ALG_ML_DSA_44)
        path = str(tmp_path / "key.mlkey")
        save_secret_key(path, sec, ALG_ML_DSA_44, b"my-password")
        loaded_sec, loaded_alg = load_secret_key(path, b"my-password")
        assert loaded_sec == sec
        assert loaded_alg == ALG_ML_DSA_44

    def test_wrong_password_raises(self, tmp_path):
        pub, sec = generate_keypair(ALG_ML_DSA_44)
        path = str(tmp_path / "key.mlkey")
        save_secret_key(path, sec, ALG_ML_DSA_44, b"correct-password")
        with pytest.raises(ValueError, match="Decryption failed"):
            load_secret_key(path, b"wrong-password")

    def test_alg_id_preserved(self, tmp_path):
        for alg in [ALG_ML_DSA_44, ALG_ML_DSA_65]:
            _, sec = generate_keypair(alg)
            path = str(tmp_path / f"key_{alg}.mlkey")
            save_secret_key(path, sec, alg, b"pw")
            _, loaded_alg = load_secret_key(path, b"pw")
            assert loaded_alg == alg

    def test_different_salts_each_call(self, tmp_path):
        """Two saves of the same key must produce different ciphertexts."""
        import cbor2
        _, sec = generate_keypair(ALG_ML_DSA_44)
        path1 = str(tmp_path / "key1.mlkey")
        path2 = str(tmp_path / "key2.mlkey")
        save_secret_key(path1, sec, ALG_ML_DSA_44, b"pw")
        save_secret_key(path2, sec, ALG_ML_DSA_44, b"pw")
        with open(path1, "rb") as f1, open(path2, "rb") as f2:
            d1 = cbor2.loads(f1.read())
            d2 = cbor2.loads(f2.read())
        # Salt and nonce must differ
        assert d1[2][4] != d2[2][4]  # salt
        assert d1[3] != d2[3]         # nonce

    def test_loaded_key_can_sign(self, tmp_path):
        pub, sec = generate_keypair(ALG_ML_DSA_44)
        path = str(tmp_path / "key.mlkey")
        save_secret_key(path, sec, ALG_ML_DSA_44, b"pw")
        loaded_sec, loaded_alg = load_secret_key(path, b"pw")
        msg = b"sign after load"
        sig = sign(msg, loaded_sec, loaded_alg)
        assert verify(msg, sig, pub, loaded_alg)
