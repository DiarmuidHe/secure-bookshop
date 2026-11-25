from datetime import UTC, datetime, timedelta
from ipaddress import ip_address
import os
from pathlib import Path
import secrets
from tempfile import TemporaryDirectory

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa

from .store import create_database


# Use exclusive creation when writing a key file.
def private_file(path, data):
    with os.fdopen(os.open(path, os.O_CREAT | os.O_EXCL | os.O_WRONLY | getattr(os, "O_BINARY", 0), 0o600), "wb") as handle:
        handle.write(data)


# Convert a private key to PEM bytes for local storage.
def private_pem(key):
    return key.private_bytes(
        serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8, serialization.NoEncryption()
    )


# Build a self-signed certificate for the local HTTPS server.
def localhost_certificate(key):
    now = datetime.now(UTC)
    name = x509.Name([x509.NameAttribute(x509.NameOID.COMMON_NAME, "Bookshop local demo")])
    return (
        x509.CertificateBuilder()
        .subject_name(name)
        .issuer_name(name)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - timedelta(minutes=5))
        .not_valid_after(now + timedelta(days=30))
        .add_extension(x509.SubjectAlternativeName([x509.DNSName("localhost"), x509.IPAddress(ip_address("127.0.0.1"))]), critical=False)
        .add_extension(x509.BasicConstraints(ca=False, path_length=None), critical=True)
        .add_extension(x509.ExtendedKeyUsage([x509.oid.ExtendedKeyUsageOID.SERVER_AUTH]), critical=False)
        .sign(key, hashes.SHA256())
    )


# Create the database and keys for a new shop instance.
def initialize(instance, accounts):
    instance = Path(instance).resolve()
    if instance.exists():
        raise FileExistsError("Choose a new instance directory")
    instance.parent.mkdir(parents=True, exist_ok=True)
    # Prepare the files in a temporary directory first.
    with TemporaryDirectory(prefix="bookshop-init-", dir=instance.parent) as temporary:
        staging = Path(temporary) / "instance"
        staging.mkdir(mode=0o700)
        secret_dir = staging / "private"
        secret_dir.mkdir(mode=0o700)
        # Generate the 256-bit key for encrypted orders.
        private_file(secret_dir / "orders.key", secrets.token_bytes(32))
        # Save the receipt signing key and export its public verification key.
        signing_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        private_file(secret_dir / "receipts.pem", private_pem(signing_key))
        (staging / "receipts-public.pem").write_bytes(signing_key.public_key().public_bytes(
            serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo
        ))
        # Generate a separate key and certificate for HTTPS.
        tls_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        private_file(secret_dir / "tls.pem", private_pem(tls_key))
        (staging / "localhost.pem").write_bytes(localhost_certificate(tls_key).public_bytes(serialization.Encoding.PEM))
        # Seed SQLite and move the completed instance into place.
        create_database(staging / "bookshop.sqlite3", accounts)
        staging.rename(instance)