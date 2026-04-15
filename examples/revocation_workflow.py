"""
Example: Revocation Workflow
=============================
Demonstrates how to create a CRL, revoke a certificate, and how
verify_chain behaves with and without the revoked certificate.

Steps:
  1. Create Root CA
  2. Issue two end-entity certificates (EE-A and EE-B)
  3. Create an empty CRL
  4. Verify both certificates pass
  5. Revoke EE-B by adding its serial to the CRL
  6. Verify EE-A still passes; EE-B now fails

Run:
    python examples/revocation_workflow.py
"""

import sys
import os

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

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
from mlpki.verify import VerificationError


def main() -> None:
    print("=== Revocation Workflow ===\n")

    # 1. Root CA
    print("1. Creating Root CA …")
    root_cert, root_sec = create_root_ca(
        Name(cn="Revocation Demo Root", org="Demo Org"),
        validity_days=3650, alg=ALG_ML_DSA_44,
    )
    print(f"   Root CA serial: {root_cert.tbs.serial.hex()}\n")

    # 2. Issue EE-A and EE-B
    print("2. Issuing end-entity certificates …")
    pub_a, _ = generate_keypair(ALG_ML_DSA_44)
    ee_a = issue_certificate(
        Name(cn="EE-A", org="Demo Org"), pub_a,
        root_cert, root_sec, 365, key_usage=KEY_USAGE_DIGITAL_SIGNATURE,
    )
    print(f"   EE-A serial: {ee_a.tbs.serial.hex()}")

    pub_b, _ = generate_keypair(ALG_ML_DSA_44)
    ee_b = issue_certificate(
        Name(cn="EE-B", org="Demo Org"), pub_b,
        root_cert, root_sec, 365, key_usage=KEY_USAGE_DIGITAL_SIGNATURE,
    )
    print(f"   EE-B serial: {ee_b.tbs.serial.hex()}\n")

    # 3. Empty CRL
    print("3. Creating empty CRL (next update in 30 days) …")
    crl = RevocationList.create(root_cert, root_sec, [], next_update_days=30)
    print(f"   CRL valid:   {crl.verify(root_cert)}")
    print(f"   Revoked:     {len(crl.revoked_serials)} serial(s)\n")

    # 4. Both pass with empty CRL
    print("4. Verifying both certificates against empty CRL …")
    verify_chain([ee_a], trusted_root=root_cert, crl=crl)
    print("   EE-A: PASSED")
    verify_chain([ee_b], trusted_root=root_cert, crl=crl)
    print("   EE-B: PASSED\n")

    # 5. Revoke EE-B
    print("5. Revoking EE-B …")
    crl_updated = crl.add_serial(ee_b.tbs.serial, root_cert, root_sec)
    print(f"   Revoked: {len(crl_updated.revoked_serials)} serial(s)")
    print(f"   CRL re-signed and valid: {crl_updated.verify(root_cert)}\n")

    # 6. EE-A still passes; EE-B is now rejected
    print("6. Verifying certificates against updated CRL …")
    verify_chain([ee_a], trusted_root=root_cert, crl=crl_updated)
    print("   EE-A: PASSED (not revoked)")

    try:
        verify_chain([ee_b], trusted_root=root_cert, crl=crl_updated)
        print("   EE-B: PASSED  ← unexpected!")
    except VerificationError as e:
        print(f"   EE-B: REJECTED — {e} (code={e.code.value})")

    # CRL round-trip demonstration
    print("\n7. CRL CBOR round-trip …")
    crl_decoded = RevocationList.decode(crl_updated.encode())
    assert crl_decoded.is_revoked(ee_b.tbs.serial)
    assert crl_decoded.verify(root_cert)
    print("   CRL encoded/decoded successfully, signature still valid.")

    print("\nRevocation workflow complete.")


if __name__ == "__main__":
    main()
