"""
Core vault encryption/decryption logic.

File format (compatible with the original Go env-vault):
  Line 1: env-vault;1.0;AES256
  Rest:    base64-encoded ciphertext
           ciphertext = nonce (12 bytes) + AES-256-GCM encrypted data

Key derivation: SHA-256 hash of the password (same as Go implementation).
"""

import base64
import hashlib
import os
import secrets

from cryptography.hazmat.primitives.ciphers.aead import AESGCM

HEADER = b"env-vault;1.0;AES256"
NONCE_SIZE = 12  # AES-GCM standard nonce size


def _cipher_key(password: bytes) -> bytes:
    """Derive a 32-byte AES key by SHA-256 hashing the password."""
    return hashlib.sha256(password).digest()


def encrypt(plaintext: bytes, password: bytes) -> bytes:
    """Encrypt plaintext with AES-256-GCM. Returns nonce + ciphertext."""
    key = _cipher_key(password)
    aesgcm = AESGCM(key)
    nonce = secrets.token_bytes(NONCE_SIZE)
    ciphertext = aesgcm.encrypt(nonce, plaintext, None)
    return nonce + ciphertext


def decrypt(data: bytes, password: bytes) -> bytes:
    """Decrypt nonce+ciphertext with AES-256-GCM."""
    key = _cipher_key(password)
    aesgcm = AESGCM(key)
    nonce, ciphertext = data[:NONCE_SIZE], data[NONCE_SIZE:]
    try:
        return aesgcm.decrypt(nonce, ciphertext, None)
    except Exception:
        raise ValueError("decryption failed: wrong password or corrupted file")


def _check_header(header: bytes) -> None:
    parts = header.split(b";")
    if len(parts) != 3:
        raise ValueError("vault header not found")
    if parts[0] != b"env-vault":
        raise ValueError("unknown format ID. was the file encrypted with est-vault?")
    if parts[1] != b"1.0":
        raise ValueError("incompatible file version. only 1.0 is supported")
    if parts[2] != b"AES256":
        raise ValueError("unsupported cipher. only AES256 is supported")


def read_file(filename: str, password: bytes) -> bytes:
    """Read and decrypt a vault file. Returns plaintext bytes."""
    with open(filename, "rb") as f:
        data = f.read()

    newline = data.find(b"\n")
    if newline < 0:
        raise ValueError("vault header not found")

    header = data[:newline]
    body = data[newline + 1:]

    _check_header(header)

    ciphertext = base64.b64decode(body)
    return decrypt(ciphertext, password)


def write_file(filename: str, plaintext: bytes, password: bytes) -> None:
    """Encrypt plaintext and write to a vault file."""
    ciphertext = encrypt(plaintext, password)
    body = base64.b64encode(ciphertext)
    content = HEADER + b"\n" + body
    with open(filename, "wb") as f:
        f.write(content)
    # Restrict permissions (best-effort on Windows)
    try:
        os.chmod(filename, 0o700)
    except OSError:
        pass
