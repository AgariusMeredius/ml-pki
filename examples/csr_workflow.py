"""
Example: CSR Workflow
=====================
Demonstrates the separation between an applicant (who generates the key pair
and CSR) and a CA (who verifies the CSR and issues the certificate).

  Applicant side:
    - Generates key pair
    - Creates a CSR with self-signature
    - Exports CSR as PEM for transmission to CA

  CA side:
    - Receives CSR PEM
    - Verifies the self-signature
    - Issues the certificate
    - Returns the certificate

Run:
    python examples/csr_workflow.py
"""

import sys
import os

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from mlpki import (
    ALG_ML_DSA_44,
    Certificate,
    CertificateSigningRequest,
    Name,
    create_root_ca,
    generate_keypair,
    issue_from_csr,
    verify_chain,
    KEY_USAGE_DIGITAL_SIGNATURE,
)


def applicant_generate_csr(alg: int) -> tuple[bytes, bytes, str]:
    """
    Applicant side: generate key pair and create a PEM-encoded CSR.

    Returns (public_key_bytes, secret_key_bytes, csr_pem).
    """
    print("[Applicant] Generating ML-DSA key pair …")
    pub, sec = generate_keypair(alg)
    print(f"[Applicant]   Public key : {len(pub)} bytes")

    subject = Name(cn="applicant.example.com", org="Applicant Organisation")
    print(f"[Applicant] Creating CSR for: {subject.cn} / {subject.org}")

    csr = CertificateSigningRequest.create(
        subject=subject,
        pub=pub,
        sec=sec,
        alg=alg,
        key_usage=KEY_USAGE_DIGITAL_SIGNATURE,
    )
    csr_pem = csr.to_pem()
    print("[Applicant] CSR created and self-signed.")
    return pub, sec, csr_pem


def ca_issue_from_csr_pem(
    csr_pem: str,
    ca_cert: Certificate,
    ca_sec: bytes,
) -> str:
    """
    CA side: verify the CSR self-signature and issue a certificate.

    Returns the issued certificate as PEM.
    """
    print("\n[CA] Received CSR.")
    csr = CertificateSigningRequest.from_pem(csr_pem)
    print(f"[CA]   Subject  : {csr.subject.cn} / {csr.subject.org}")
    print(f"[CA]   Algorithm: {csr.public_key.alg_name}")

    print("[CA] Verifying CSR self-signature …")
    if not csr.verify_self_signature():
        raise ValueError("CSR self-signature verification FAILED!")
    print("[CA]   Self-signature: VALID")

    print("[CA] Issuing certificate …")
    cert = issue_from_csr(csr, ca_cert, ca_sec, validity_days=365)
    print(f"[CA]   Certificate serial: {cert.tbs.serial.hex()}")
    return cert.to_pem()


def main() -> None:
    print("=== CSR Workflow ===\n")

    # Set up a minimal Root CA (would normally be loaded from disk)
    print("[Setup] Creating Root CA …")
    root_cert, root_sec = create_root_ca(
        Name(cn="Example Root CA", org="Example Org"),
        validity_days=3650,
        alg=ALG_ML_DSA_44,
    )
    print(f"[Setup]   Root CA: {root_cert.tbs.subject.cn}\n")

    # ---- Applicant side ----
    _pub, _sec, csr_pem = applicant_generate_csr(ALG_ML_DSA_44)

    # CSR would normally be transmitted over a network here.
    print(f"\n[Transport] CSR PEM size: {len(csr_pem)} bytes")

    # ---- CA side ----
    cert_pem = ca_issue_from_csr_pem(csr_pem, root_cert, root_sec)

    # ---- Applicant receives certificate and verifies chain ----
    print("\n[Applicant] Received certificate PEM.")
    ee_cert = Certificate.from_pem(cert_pem)
    print("[Applicant] Verifying chain against Root CA …")
    verify_chain([ee_cert], trusted_root=root_cert)
    print("[Applicant]   Chain verification: PASSED")
    print(f"[Applicant]   Fingerprint: {ee_cert.fingerprint().hex()}")

    print("\nCSR workflow complete.")


if __name__ == "__main__":
    main()
