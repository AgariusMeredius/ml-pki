"""
Example: Self-Signed Certificate
=================================
Create and verify a self-signed certificate suitable for local services
(not part of a CA hierarchy).

Run:
    python examples/self_signed.py
"""

import sys
import os

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from mlpki import (
    ALG_ML_DSA_44,
    Name,
    create_self_signed,
    generate_keypair,
    verify_self_signed,
    KEY_USAGE_DIGITAL_SIGNATURE,
)


def main() -> None:
    print("=== Self-Signed Certificate ===\n")

    # 1. Generate key pair
    print("1. Generating ML-DSA-44 key pair …")
    pub, sec = generate_keypair(ALG_ML_DSA_44)
    print(f"   Public key : {len(pub)} bytes")
    print(f"   Secret key : {len(sec)} bytes")

    # 2. Create self-signed certificate
    print("\n2. Creating self-signed certificate …")
    subject = Name(cn="local.service.example", org="Local Services", ou="Dev")
    cert = create_self_signed(
        subject=subject,
        pub=pub,
        sec=sec,
        validity_days=365,
        alg=ALG_ML_DSA_44,
        key_usage=KEY_USAGE_DIGITAL_SIGNATURE,
        is_ca=False,
    )
    tbs = cert.tbs
    print(f"   Subject    : {tbs.subject.cn}")
    print(f"   Org        : {tbs.subject.org} / {tbs.subject.ou}")
    print(f"   Serial     : {tbs.serial.hex()}")
    print(f"   Not before : {tbs.not_before}")
    print(f"   Not after  : {tbs.not_after}")
    print(f"   is_CA      : {tbs.is_ca}")
    print(f"   key_usage  : 0x{tbs.key_usage:02x}")

    # 3. Verify self-signature
    print("\n3. Verifying self-signature …")
    verify_self_signed(cert)
    print("   Verification: PASSED")

    # 4. PEM export/import round-trip
    print("\n4. PEM round-trip …")
    pem = cert.to_pem()
    cert2 = type(cert).from_pem(pem)
    assert cert2.tbs_bytes == cert.tbs_bytes
    verify_self_signed(cert2)
    print("   PEM import/export: OK")
    print(f"   PEM size: {len(pem)} bytes")

    # 5. Fingerprint
    fp = cert.fingerprint()
    print(f"\n5. Certificate fingerprint (SHA3-256):")
    print(f"   {fp.hex()}")

    print("\nSelf-signed certificate workflow complete.")


if __name__ == "__main__":
    main()
