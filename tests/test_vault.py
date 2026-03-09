"""Tests for the vault crypto module (vault.py)."""

import os
import tempfile

import pytest

from est_vault import vault as v


PASSWORD = b"correct-horse-battery-staple"
PLAINTEXT = b"DB_HOST=localhost\nDB_PORT=5432\nDB_PASSWORD=super_secret\n"


# ---------------------------------------------------------------------------
# encrypt / decrypt (low-level)
# ---------------------------------------------------------------------------

class TestEncryptDecrypt:
    def test_roundtrip(self):
        ciphertext = v.encrypt(PLAINTEXT, PASSWORD)
        assert v.decrypt(ciphertext, PASSWORD) == PLAINTEXT

    def test_ciphertext_differs_from_plaintext(self):
        ciphertext = v.encrypt(PLAINTEXT, PASSWORD)
        assert ciphertext != PLAINTEXT

    def test_random_nonce_produces_different_ciphertext_each_time(self):
        c1 = v.encrypt(PLAINTEXT, PASSWORD)
        c2 = v.encrypt(PLAINTEXT, PASSWORD)
        assert c1 != c2

    def test_wrong_password_raises(self):
        ciphertext = v.encrypt(PLAINTEXT, PASSWORD)
        with pytest.raises(ValueError, match="decryption failed"):
            v.decrypt(ciphertext, b"wrong-password")

    def test_empty_plaintext(self):
        ciphertext = v.encrypt(b"", PASSWORD)
        assert v.decrypt(ciphertext, PASSWORD) == b""

    def test_large_plaintext(self):
        large = b"KEY=VALUE\n" * 10_000
        ciphertext = v.encrypt(large, PASSWORD)
        assert v.decrypt(ciphertext, PASSWORD) == large

    def test_corrupted_ciphertext_raises(self):
        ciphertext = bytearray(v.encrypt(PLAINTEXT, PASSWORD))
        ciphertext[-1] ^= 0xFF  # flip a bit in the GCM tag
        with pytest.raises(ValueError, match="decryption failed"):
            v.decrypt(bytes(ciphertext), PASSWORD)


# ---------------------------------------------------------------------------
# write_file / read_file
# ---------------------------------------------------------------------------

class TestFileIO:
    def test_roundtrip(self, tmp_path):
        path = str(tmp_path / "secrets.env")
        v.write_file(path, PLAINTEXT, PASSWORD)
        assert v.read_file(path, PASSWORD) == PLAINTEXT

    def test_file_starts_with_header(self, tmp_path):
        path = str(tmp_path / "secrets.env")
        v.write_file(path, PLAINTEXT, PASSWORD)
        with open(path, "rb") as f:
            first_line = f.readline().rstrip(b"\n")
        assert first_line == b"env-vault;1.0;AES256"

    def test_wrong_password_raises(self, tmp_path):
        path = str(tmp_path / "secrets.env")
        v.write_file(path, PLAINTEXT, PASSWORD)
        with pytest.raises(ValueError, match="decryption failed"):
            v.read_file(path, b"wrong")

    def test_missing_file_raises(self, tmp_path):
        path = str(tmp_path / "nonexistent.env")
        with pytest.raises(OSError):
            v.read_file(path, PASSWORD)

    def test_overwrite_existing_file(self, tmp_path):
        path = str(tmp_path / "secrets.env")
        v.write_file(path, PLAINTEXT, PASSWORD)
        new_plaintext = b"API_KEY=abc123\n"
        v.write_file(path, new_plaintext, PASSWORD)
        assert v.read_file(path, PASSWORD) == new_plaintext


# ---------------------------------------------------------------------------
# Header validation
# ---------------------------------------------------------------------------

class TestHeaderValidation:
    def _write_raw(self, path: str, header: bytes, body: bytes = b"dummy") -> None:
        with open(path, "wb") as f:
            f.write(header + b"\n" + body)

    def test_missing_header_newline_raises(self, tmp_path):
        path = str(tmp_path / "bad.env")
        with open(path, "wb") as f:
            f.write(b"no-newline-at-all")
        with pytest.raises(ValueError, match="vault header not found"):
            v.read_file(path, PASSWORD)

    def test_unknown_format_id_raises(self, tmp_path):
        path = str(tmp_path / "bad.env")
        self._write_raw(path, b"unknown;1.0;AES256")
        with pytest.raises(ValueError, match="unknown format ID"):
            v.read_file(path, PASSWORD)

    def test_unsupported_version_raises(self, tmp_path):
        path = str(tmp_path / "bad.env")
        self._write_raw(path, b"env-vault;9.9;AES256")
        with pytest.raises(ValueError, match="incompatible file version"):
            v.read_file(path, PASSWORD)

    def test_unsupported_cipher_raises(self, tmp_path):
        path = str(tmp_path / "bad.env")
        self._write_raw(path, b"env-vault;1.0;DES")
        with pytest.raises(ValueError, match="unsupported cipher"):
            v.read_file(path, PASSWORD)


# ---------------------------------------------------------------------------
# Key derivation
# ---------------------------------------------------------------------------

class TestCipherKey:
    def test_key_is_32_bytes(self):
        key = v._cipher_key(b"any password")
        assert len(key) == 32

    def test_same_password_same_key(self):
        assert v._cipher_key(b"abc") == v._cipher_key(b"abc")

    def test_different_password_different_key(self):
        assert v._cipher_key(b"abc") != v._cipher_key(b"xyz")
