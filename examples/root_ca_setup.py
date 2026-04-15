"""
Example: Root CA Setup
======================
Create a Root CA, save the encrypted secret key to disk, and export
the certificate as PEM.

Run:
    python examples/root_ca_setup.py
"""

import sys
import os

# Allow running from the project root without installing the package
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from mlpki import (
    ALG_ML_DSA_65,
    Name,
    create_root_ca,
    save_secret_key,
)

# ---------------------------------------------------------------------------
# Configuration
# ---------------------------------------------------------------------------
OUTPUT_DIR = "/tmp/mlpki_root_ca"
KEY_FILE = os.path.join(OUTPUT_DIR, "root_ca.mlkey")
CERT_PEM_FILE = os.path.join(OUTPUT_DIR, "root_ca.pem")
CERT_BIN_FILE = os.path.join(OUTPUT_DIR, "root_ca.mlcert")

# In a real deployment use a strong, randomly generated password stored securely.
PASSWORD = b"example-password-change-me"


def main() -> None:
    os.makedirs(OUTPUT_DIR, exist_ok=True)

    print("=== Root CA Setup ===\n")

    # 1. Create Root CA
    print("1. Generating Root CA key pair and self-signed certificate …")
    subject = Name(cn="Example Root CA", org="Example Organisation", ou="PKI")
    root_cert, root_sec = create_root_ca(
        subject=subject,
        validity_days=3650,
        alg=ALG_ML_DSA_65,
    )
    tbs = root_cert.tbs
    print(f"   Subject : {tbs.subject.cn} / {tbs.subject.org}")
    print(f"   Serial  : {tbs.serial.hex()}")
    print(f"   Valid   : {tbs.not_before} → {tbs.not_after}")
    print(f"   is_CA   : {tbs.is_ca}")
    print(f"   path_len: {tbs.path_len}")

    # 2. Save encrypted secret key
    print(f"\n2. Saving encrypted secret key to {KEY_FILE} …")
    save_secret_key(KEY_FILE, root_sec, ALG_ML_DSA_65, PASSWORD)
    print("   Key encrypted with Argon2id + AES-256-GCM.")

    # 3. Export certificate as PEM
    print(f"\n3. Exporting certificate as PEM to {CERT_PEM_FILE} …")
    pem = root_cert.to_pem()
    with open(CERT_PEM_FILE, "w") as f:
        f.write(pem)
    print("   PEM written.")

    # 4. Export certificate as binary
    print(f"\n4. Exporting certificate as binary to {CERT_BIN_FILE} …")
    root_cert.save(CERT_BIN_FILE)
    print("   Binary .mlcert written.")

    # 5. Fingerprint
    fp = root_cert.fingerprint()
    print(f"\n5. Certificate fingerprint (SHA3-256 over TBS):")
    print(f"   {fp.hex()}")

    print("\nRoot CA setup complete.")


if __name__ == "__main__":
    main()
