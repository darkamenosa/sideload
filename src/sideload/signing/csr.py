"""Signing keypair and CSR generation for the developer certificate.

Apple issues the IOS_DEVELOPMENT certificate to a CSR generated locally
with an RSA-2048 key, exactly as AltSign does
(AltSign/Model/Apple API/ALTCertificateRequest.m, OpenSSL RSA_generate_key_ex
with RSA_F4 and SHA-256). The private key never leaves this Mac: it is
generated here, submitted only as the public CSR, and stored in the
keychain (keychain.py) alongside the issued certificate.

Uses the "cryptography" package (Apache-2.0 / BSD dual licensed).

Ownership: SIGN agent.
"""

from __future__ import annotations

import platform
import re
import subprocess
import uuid
from pathlib import Path

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import NameOID

CSR_COMMON_NAME_TEMPLATE = "{machine_name}"
RSA_KEY_BITS = 2048
RSA_PUBLIC_EXPONENT = 65537  # RSA_F4, the exponent AltSign pins
MACHINE_NAME_SUFFIX = "sideload"


def generate_private_key() -> bytes:
    """Generate an RSA-2048 signing key and return PKCS#8 PEM bytes.

    The key is generated in memory; the caller routes it straight into
    the keychain and never writes plaintext key material to the state
    directory. The unencrypted PKCS#8 form is directly importable into
    a temporary keychain (keychain.py wraps it into a .p12 together
    with the issued certificate).
    """
    key = rsa.generate_private_key(
        public_exponent=RSA_PUBLIC_EXPONENT,
        key_size=RSA_KEY_BITS,
    )
    return key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption(),
    )


def create_csr(private_key_pem: bytes, machine_name: str) -> str:
    """Create a PKCS#10 certificate signing request as a PEM string.

    Subject: CN=<machine_name>, O=<team name if available>. AltSign
    uses the machine name only; the Apple portal does not validate the
    subject beyond parseability.
    """
    key = serialization.load_pem_private_key(private_key_pem, password=None)
    if not isinstance(key, rsa.RSAPrivateKey):
        raise TypeError("private key is not an RSA key")
    subject = x509.Name(
        [
            x509.NameAttribute(
                NameOID.COMMON_NAME,
                CSR_COMMON_NAME_TEMPLATE.format(machine_name=machine_name),
            )
        ]
    )
    request = (
        x509.CertificateSigningRequestBuilder()
        .subject_name(subject)
        .sign(key, hashes.SHA256())
    )
    return request.public_bytes(serialization.Encoding.PEM).decode("ascii")


def make_machine_name() -> str:
    """A stable, human readable machine name for Apple's records.

    Format: "<ComputerName>-sideload" (for example "MacBook-Pro-sideload").
    Must be stable across runs so certificate records stay identifiable
    in the Apple portal.
    """
    base = _computer_name()
    cleaned = re.sub(r"[^A-Za-z0-9]+", "-", base).strip("-")
    if not cleaned:
        cleaned = "Mac"
    return f"{cleaned}-{MACHINE_NAME_SUFFIX}"


def _computer_name() -> str:
    """The macOS ComputerName, falling back to the hostname."""
    try:
        result = subprocess.run(
            ["scutil", "--get", "ComputerName"],
            capture_output=True,
            text=True,
            timeout=10,
            check=True,
        )
        name = result.stdout.strip()
        if name:
            return name
    except (OSError, subprocess.SubprocessError):
        pass
    return platform.node()


def load_or_create_machine_id(state_path: str) -> str:
    """A stable random UUID persisted under the state directory,
    sent as "machineId" with every CSR submission.
    """
    path = Path(state_path)
    if path.is_file():
        try:
            value = path.read_text(encoding="utf-8").strip()
        except OSError:
            value = ""
        if value:
            return value
    machine_id = str(uuid.uuid4()).upper()
    try:
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(machine_id + "\n", encoding="utf-8")
    except OSError:
        # A missing machine id file is not fatal; Apple only uses it
        # for display in the certificate list.
        pass
    return machine_id
