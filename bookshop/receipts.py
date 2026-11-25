import base64
from datetime import datetime
import json
import os
from pathlib import Path
import re
import stat

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding, rsa


# Limit local file reads and use the same RSA-PSS settings for signing and verification.
MAX_FILE_SIZE = 8192
SIGNATURE_PADDING = padding.PSS(
    mgf=padding.MGF1(hashes.SHA256()), salt_length=padding.PSS.DIGEST_LENGTH
)


# Turn JSON data into consistent bytes, regardless of the original key order.
def json_bytes(value):
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=True).encode("ascii")


# Reject JSON objects that repeat a field name.
def reject_duplicates(pairs):
    value = dict(pairs)
    if len(value) != len(pairs):
        raise ValueError("Duplicate receipt field")
    return value


# Read a regular file with a fixed size limit.
def read_local_file(path, limit=MAX_FILE_SIZE):
    path = Path(path)
    if not stat.S_ISREG(path.stat().st_mode):
        raise ValueError("Expected a regular file")
    flags = os.O_RDONLY | getattr(os, "O_BINARY", 0) | getattr(os, "O_NONBLOCK", 0)
    with os.fdopen(os.open(path, flags), "rb") as stream:
        if not stat.S_ISREG(os.fstat(stream.fileno()).st_mode):
            raise ValueError("Expected a regular file")
        # Read one extra byte so we can tell when the file exceeds the limit.
        data = stream.read(limit + 1)
    if len(data) > limit:
        raise ValueError("File is too large")
    return data


# Sign the shareable receipt fields with the shop's private key.
def sign_receipt(private_key, reference, amount_cents, issued_at):
    receipt = {
        "version": 1,
        "receipt_reference": reference,
        "amount_cents": amount_cents,
        "currency": "USD",
        "issued_at": issued_at,
    }
    signature = private_key.sign(json_bytes(receipt), SIGNATURE_PADDING, hashes.SHA256())
    # Encode the signature bytes as text so they fit inside JSON.
    return {"receipt": receipt, "signature": base64.b64encode(signature).decode("ascii")}


# Check the receipt's format and verify its signature with the shop's public key.
def verify_receipt(data, public_key):
    if not isinstance(public_key, rsa.RSAPublicKey) or public_key.key_size != 2048:
        raise ValueError("Expected the shop's RSA-2048 public key")
    if len(data) > MAX_FILE_SIZE:
        raise ValueError("Receipt is too large")
    try:
        envelope = json.loads(data.decode("utf-8"), object_pairs_hook=reject_duplicates)
    except (ValueError, RecursionError) as error:
        raise ValueError("Invalid receipt JSON") from error
    if not isinstance(envelope, dict) or set(envelope) != {"receipt", "signature"}:
        raise ValueError("Invalid receipt format")
    # Validate the fields that the shop signs before checking the signature.
    receipt = envelope["receipt"]
    expected_fields = {"version", "receipt_reference", "amount_cents", "currency", "issued_at"}
    if not isinstance(receipt, dict) or set(receipt) != expected_fields:
        raise ValueError("Invalid receipt fields")
    if type(receipt["version"]) is not int or receipt["version"] != 1 or receipt["currency"] != "USD":
        raise ValueError("Unsupported receipt version or currency")
    amount = receipt["amount_cents"]
    if type(amount) is not int or not 1 <= amount <= 99_999_999:
        raise ValueError("Invalid receipt amount")
    reference = receipt["receipt_reference"]
    if not isinstance(reference, str) or re.fullmatch(r"[0-9a-f]{32}", reference) is None:
        raise ValueError("Invalid receipt reference")
    issued_at = receipt["issued_at"]
    if not isinstance(issued_at, str) or re.fullmatch(r"[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}Z", issued_at) is None:
        raise ValueError("Invalid receipt timestamp")
    datetime.strptime(issued_at, "%Y-%m-%dT%H:%M:%SZ")
    encoded_signature = envelope["signature"]
    if not isinstance(encoded_signature, str) or len(encoded_signature) != 344:
        raise ValueError("Invalid signature format")
    signature = base64.b64decode(encoded_signature, validate=True)
    # Rebuild the exact JSON bytes the shop would have signed for these values.
    try:
        public_key.verify(signature, json_bytes(receipt), SIGNATURE_PADDING, hashes.SHA256())
    except InvalidSignature as error:
        raise ValueError("Receipt signature is invalid") from error
    return receipt


# Load the recipient's trusted public key from a local PEM file.
def load_verification_key(path):
    return serialization.load_pem_public_key(read_local_file(path))