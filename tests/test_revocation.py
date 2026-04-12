"""Tests for revocation.py — CRL creation, serial management, chain integration."""

import time

import pytest

from mlpki import (
    ALG_ML_DSA_44,
    Name,
    RevocationList,
    create_root_ca,
    generate_keypair,
    issue_certificate,
    verify_chain,
    KEY_USAGE_DIGITAL_SIGNATURE,
)
from mlpki.verify import VerificationCode, VerificationError


# ---------------------------------------------------------------------------
# CRL creation
# ---------------------------------------------------------------------------

class TestCRLCreate:
    def test_creates_crl(self, root_cert, root_sec):
        crl = RevocationList.create(root_cert, root_sec, [], 30)
        assert isinstance(crl, RevocationList)

    def test_issuer_key_id(self, root_cert, root_sec):
        crl = RevocationList.create(root_cert, root_sec, [], 30)
        assert crl.issuer_key_id == root_cert.tbs.subject_key_id

    def test_empty_revoked_list(self, root_cert, root_sec):
        crl = RevocationList.create(root_cert, root_sec, [], 30)
        assert crl.revoked_serials == []

    def test_initial_serials(self, root_cert, root_sec):
        serial = b"\xab" * 16
        crl = RevocationList.create(root_cert, root_sec, [serial], 30)
        assert crl.is_revoked(serial)

    def test_this_update_close_to_now(self, root_cert, root_sec):
        before = int(time.time()) - 2
        crl = RevocationList.create(root_cert, root_sec, [], 30)
        after = int(time.time()) + 2
        assert before <= crl.this_update <= after

    def test_next_update_correct(self, root_cert, root_sec):
        crl = RevocationList.create(root_cert, root_sec, [], 30)
        expected = crl.this_update + 30 * 86400
        assert crl.next_update == expected


# ---------------------------------------------------------------------------
# CRL signature verification
# ---------------------------------------------------------------------------

class TestCRLVerify:
    def test_valid_crl(self, root_cert, root_sec):
        crl = RevocationList.create(root_cert, root_sec, [], 30)
        assert crl.verify(root_cert) is True

    def test_tampered_crl_fails(self, root_cert, root_sec):
        crl = RevocationList.create(root_cert, root_sec, [], 30)
        bad_sig = bytearray(crl.signature)
        bad_sig[5] ^= 0xFF
        crl.signature = bytes(bad_sig)
        assert crl.verify(root_cert) is False

    def test_wrong_issuer_fails(self, root_cert, root_sec):
        crl = RevocationList.create(root_cert, root_sec, [], 30)
        other_root, _ = create_root_ca(Name(cn="Other", org="O"), 3650, ALG_ML_DSA_44)
        assert crl.verify(other_root) is False


# ---------------------------------------------------------------------------
# add_serial (immutable update)
# ---------------------------------------------------------------------------

class TestCRLAddSerial:
    def test_add_serial_revokes_it(self, root_cert, root_sec):
        crl = RevocationList.create(root_cert, root_sec, [], 30)
        serial = b"\xde\xad" * 8
        crl2 = crl.add_serial(serial, root_cert, root_sec)
        assert crl2.is_revoked(serial)

    def test_original_unchanged(self, root_cert, root_sec):
        crl = RevocationList.create(root_cert, root_sec, [], 30)
        serial = b"\xde\xad" * 8
        crl.add_serial(serial, root_cert, root_sec)
        assert not crl.is_revoked(serial)

    def test_new_crl_is_signed(self, root_cert, root_sec):
        crl = RevocationList.create(root_cert, root_sec, [], 30)
        crl2 = crl.add_serial(b"\x01" * 16, root_cert, root_sec)
        assert crl2.verify(root_cert)

    def test_add_same_serial_twice_no_duplicate(self, root_cert, root_sec):
        serial = b"\xff" * 16
        crl = RevocationList.create(root_cert, root_sec, [], 30)
        crl2 = crl.add_serial(serial, root_cert, root_sec)
        crl3 = crl2.add_serial(serial, root_cert, root_sec)
        assert crl3.revoked_serials.count(serial) == 1

    def test_not_revoked_returns_false(self, root_cert, root_sec):
        crl = RevocationList.create(root_cert, root_sec, [], 30)
        assert not crl.is_revoked(b"\x00" * 16)


# ---------------------------------------------------------------------------
# CBOR round-trip
# ---------------------------------------------------------------------------

class TestCRLCBOR:
    def test_encode_decode(self, root_cert, root_sec):
        serial = b"\xca\xfe" * 8
        crl = RevocationList.create(root_cert, root_sec, [serial], 30)
        recovered = RevocationList.decode(crl.encode())
        assert recovered.issuer_key_id == crl.issuer_key_id
        assert recovered.this_update == crl.this_update
        assert recovered.next_update == crl.next_update
        assert serial in recovered.revoked_serials
        assert recovered.sig_alg == crl.sig_alg
        assert recovered.signature == crl.signature

    def test_verify_after_round_trip(self, root_cert, root_sec):
        crl = RevocationList.create(root_cert, root_sec, [], 30)
        recovered = RevocationList.decode(crl.encode())
        assert recovered.verify(root_cert)


# ---------------------------------------------------------------------------
# Revoked cert in chain
# ---------------------------------------------------------------------------

class TestCRLInChain:
    def test_revoked_cert_fails_chain(self, root_cert, root_sec):
        pub, _ = generate_keypair(ALG_ML_DSA_44)
        ee = issue_certificate(
            Name(cn="Revoked EE", org="O"), pub, root_cert, root_sec, 365
        )
        crl = RevocationList.create(root_cert, root_sec, [ee.tbs.serial], 30)
        with pytest.raises(VerificationError) as exc_info:
            verify_chain([ee], trusted_root=root_cert, crl=crl)
        assert exc_info.value.code == VerificationCode.REVOKED

    def test_non_revoked_cert_passes(self, root_cert, root_sec):
        pub, _ = generate_keypair(ALG_ML_DSA_44)
        ee = issue_certificate(
            Name(cn="Good EE", org="O"), pub, root_cert, root_sec, 365
        )
        crl = RevocationList.create(root_cert, root_sec, [], 30)
        verify_chain([ee], trusted_root=root_cert, crl=crl)  # must not raise

    def test_other_cert_revoked_does_not_affect_good_cert(self, root_cert, root_sec):
        pub1, _ = generate_keypair(ALG_ML_DSA_44)
        pub2, _ = generate_keypair(ALG_ML_DSA_44)
        bad_ee = issue_certificate(Name(cn="Bad", org="O"), pub1, root_cert, root_sec, 365)
        good_ee = issue_certificate(Name(cn="Good", org="O"), pub2, root_cert, root_sec, 365)
        crl = RevocationList.create(root_cert, root_sec, [bad_ee.tbs.serial], 30)
        verify_chain([good_ee], trusted_root=root_cert, crl=crl)  # must not raise
