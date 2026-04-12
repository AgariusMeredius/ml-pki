"""
Example: Issue End-Entity Certificate
======================================
Load the Root CA created by root_ca_setup.py, issue an end-entity
certificate directly, and verify the chain.

Run root_ca_setup.py first, then:
    python examples/issue_end_entity.py
"""

import sys
import os

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from mlpki import (
    Certificate,
    Name,
    generate_keypair,
    issue_certificate,
    load_secret_key,
    verify_chain,
    verify_signature,
    KEY_USAGE_DIGITAL_SIGNATURE,
)

ROOT_DIR = "/tmp/mlpki_root_ca"
ROOT_CERT_PEM = os.path.join(ROOT_DIR, "root_ca.pem")
ROOT_KEY_FILE = os.path.join(ROOT_DIR, "root_ca.mlkey")
PASSWORD = b"example-password-change-me"

EE_CERT_FILE = "/tmp/end_entity.mlcert"


def main() -> None:
    print("=== Issue End-Entity Certificate ===\n")

    # 1. Load Root CA certificate and secret key
    print(f"1. Loading Root CA from {ROOT_DIR} …")
    with open(ROOT_CERT_PEM) as f:
        root_cert = Certificate.from_pem(f.read())
    root_sec, root_alg = load_secret_key(ROOT_KEY_FILE, PASSWORD)
    print(f"   Loaded cert: {root_cert.tbs.subject.cn}")
    print(f"   Algorithm  : {root_cert.tbs.public_key.alg_name}")

    # 2. Generate end-entity key pair
    print("\n2. Generating end-entity key pair …")
    ee_pub, ee_sec = generate_keypair(root_alg)
    print(f"   Public key: {len(ee_pub)} bytes")

    # 3. Issue certificate
    print("\n3. Issuing end-entity certificate …")
    ee_cert = issue_certificate(
        subject=Name(cn="example.service.local", org="Example Organisation"),
        subject_pub=ee_pub,
        issuer_cert=root_cert,
        issuer_sec=root_sec,
        validity_days=365,
        is_ca=False,
        key_usage=KEY_USAGE_DIGITAL_SIGNATURE,
    )
    print(f"   Subject    : {ee_cert.tbs.subject.cn}")
    print(f"   Serial     : {ee_cert.tbs.serial.hex()}")
    print(f"   Issued by  : {ee_cert.tbs.issuer.cn}")
    print(f"   key_usage  : 0x{ee_cert.tbs.key_usage:02x}")

    # 4. Verify chain
    print("\n4. Verifying certificate chain …")
    verify_chain([ee_cert], trusted_root=root_cert)
    print("   Chain verification: PASSED")

    # Also verify the individual signature
    verify_signature(ee_cert, root_cert)
    print("   Signature  : VALID")

    # 5. Save certificate
    ee_cert.save(EE_CERT_FILE)
    print(f"\n5. Certificate saved to {EE_CERT_FILE}")
    print(f"   Fingerprint: {ee_cert.fingerprint().hex()}")


if __name__ == "__main__":
    main()
