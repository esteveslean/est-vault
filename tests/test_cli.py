"""Tests for the CLI commands (cli.py)."""

import os
import sys

import pytest
from click.testing import CliRunner

from est_vault.cli import main
from est_vault import vault as vault_mod
from est_vault.version import full_version

PASSWORD = "mypassword"
PLAINTEXT = b"DB_HOST=localhost\nDB_PORT=5432\nDB_PASSWORD=secret\n"


@pytest.fixture
def runner():
    return CliRunner()


@pytest.fixture
def vault_file(tmp_path):
    """A pre-created encrypted vault file."""
    path = str(tmp_path / "test.env")
    vault_mod.write_file(path, PLAINTEXT, PASSWORD.encode())
    return path


@pytest.fixture
def plain_file(tmp_path):
    """A plaintext .env file."""
    path = str(tmp_path / "plain.env")
    with open(path, "wb") as f:
        f.write(PLAINTEXT)
    return path


# ---------------------------------------------------------------------------
# version
# ---------------------------------------------------------------------------

class TestVersion:
    def test_prints_version(self, runner):
        result = runner.invoke(main, ["version"])
        assert result.exit_code == 0
        assert full_version() in result.output


# ---------------------------------------------------------------------------
# encrypt
# ---------------------------------------------------------------------------

class TestEncrypt:
    def test_encrypts_plaintext_file(self, runner, plain_file):
        result = runner.invoke(main, ["encrypt", plain_file], input=f"{PASSWORD}\n{PASSWORD}\n")
        assert result.exit_code == 0
        # File should now be an encrypted vault
        content = open(plain_file, "rb").read()
        assert content.startswith(b"env-vault;1.0;AES256")

    def test_encrypted_content_is_decryptable(self, runner, plain_file):
        runner.invoke(main, ["encrypt", plain_file], input=f"{PASSWORD}\n{PASSWORD}\n")
        recovered = vault_mod.read_file(plain_file, PASSWORD.encode())
        assert recovered == PLAINTEXT

    def test_passwords_must_match(self, runner, plain_file):
        result = runner.invoke(main, ["encrypt", plain_file], input="pass1\npass2\n")
        assert result.exit_code != 0
        assert "passwords do not match" in result.output

    def test_missing_file_errors(self, runner, tmp_path):
        result = runner.invoke(main, ["encrypt", str(tmp_path / "ghost.env")], input=f"{PASSWORD}\n{PASSWORD}\n")
        assert result.exit_code != 0
        assert "file not found" in result.output


# ---------------------------------------------------------------------------
# decrypt
# ---------------------------------------------------------------------------

class TestDecrypt:
    def test_decrypts_to_plaintext(self, runner, vault_file):
        result = runner.invoke(main, ["decrypt", vault_file], env={"ENV_VAULT_PASSWORD": PASSWORD})
        assert result.exit_code == 0
        content = open(vault_file, "rb").read()
        assert content == PLAINTEXT

    def test_wrong_password_errors(self, runner, vault_file):
        result = runner.invoke(main, ["decrypt", vault_file], input="wrong\n")
        assert result.exit_code != 0
        assert "decryption failed" in result.output

    def test_missing_file_errors(self, runner, tmp_path):
        result = runner.invoke(main, ["decrypt", str(tmp_path / "ghost.env")], env={"ENV_VAULT_PASSWORD": PASSWORD})
        assert result.exit_code != 0
        assert "file not found" in result.output


# ---------------------------------------------------------------------------
# rekey
# ---------------------------------------------------------------------------

class TestRekey:
    def test_changes_password(self, runner, vault_file):
        new_pw = "newpassword"
        result = runner.invoke(
            main, ["rekey", vault_file],
            input=f"{PASSWORD}\n{new_pw}\n{new_pw}\n",
        )
        assert result.exit_code == 0
        # Old password should no longer work
        with pytest.raises(ValueError):
            vault_mod.read_file(vault_file, PASSWORD.encode())
        # New password should work
        assert vault_mod.read_file(vault_file, new_pw.encode()) == PLAINTEXT

    def test_wrong_current_password_errors(self, runner, vault_file):
        result = runner.invoke(main, ["rekey", vault_file], input="wrong\nnew\nnew\n")
        assert result.exit_code != 0

    def test_new_passwords_must_match(self, runner, vault_file):
        result = runner.invoke(main, ["rekey", vault_file], input=f"{PASSWORD}\npass1\npass2\n")
        assert result.exit_code != 0
        assert "passwords do not match" in result.output

    def test_missing_file_errors(self, runner, tmp_path):
        result = runner.invoke(main, ["rekey", str(tmp_path / "ghost.env")], input=f"{PASSWORD}\nnew\nnew\n")
        assert result.exit_code != 0
        assert "file not found" in result.output


# ---------------------------------------------------------------------------
# create
# ---------------------------------------------------------------------------

class TestCreate:
    def test_creates_encrypted_file(self, runner, tmp_path, monkeypatch):
        output_path = str(tmp_path / "new.env")
        # Mock the editor to write known content to the temp file
        def fake_editor(filename):
            with open(filename, "wb") as f:
                f.write(PLAINTEXT)

        monkeypatch.setattr("est_vault.cli._open_in_editor", fake_editor)

        result = runner.invoke(main, ["create", output_path], input=f"{PASSWORD}\n{PASSWORD}\n")
        assert result.exit_code == 0
        assert os.path.exists(output_path)
        content = open(output_path, "rb").read()
        assert content.startswith(b"env-vault;1.0;AES256")

    def test_created_file_is_decryptable(self, runner, tmp_path, monkeypatch):
        output_path = str(tmp_path / "new.env")

        def fake_editor(filename):
            with open(filename, "wb") as f:
                f.write(PLAINTEXT)

        monkeypatch.setattr("est_vault.cli._open_in_editor", fake_editor)
        runner.invoke(main, ["create", output_path], input=f"{PASSWORD}\n{PASSWORD}\n")
        assert vault_mod.read_file(output_path, PASSWORD.encode()) == PLAINTEXT

    def test_passwords_must_match(self, runner, tmp_path, monkeypatch):
        output_path = str(tmp_path / "new.env")
        monkeypatch.setattr("est_vault.cli._open_in_editor", lambda f: None)
        result = runner.invoke(main, ["create", output_path], input="pass1\npass2\n")
        assert result.exit_code != 0
        assert "passwords do not match" in result.output


# ---------------------------------------------------------------------------
# view
# ---------------------------------------------------------------------------

class TestView:
    def test_opens_decrypted_content_in_editor(self, runner, vault_file, monkeypatch):
        seen = {}

        def fake_editor(filename):
            seen["content"] = open(filename, "rb").read()

        monkeypatch.setattr("est_vault.cli._open_in_editor", fake_editor)
        result = runner.invoke(main, ["view", vault_file], env={"ENV_VAULT_PASSWORD": PASSWORD})
        assert result.exit_code == 0
        assert seen["content"] == PLAINTEXT

    def test_temp_file_is_deleted_after_view(self, runner, vault_file, monkeypatch):
        seen = {}

        def fake_editor(filename):
            seen["tmp_path"] = filename

        monkeypatch.setattr("est_vault.cli._open_in_editor", fake_editor)
        runner.invoke(main, ["view", vault_file], env={"ENV_VAULT_PASSWORD": PASSWORD})
        assert not os.path.exists(seen["tmp_path"])

    def test_missing_file_errors(self, runner, tmp_path):
        result = runner.invoke(main, ["view", str(tmp_path / "ghost.env")], env={"ENV_VAULT_PASSWORD": PASSWORD})
        assert result.exit_code != 0
        assert "file not found" in result.output

    def test_wrong_password_errors(self, runner, vault_file, monkeypatch):
        monkeypatch.setattr("est_vault.cli._open_in_editor", lambda f: None)
        result = runner.invoke(main, ["view", vault_file], input="wrong\n")
        assert result.exit_code != 0


# ---------------------------------------------------------------------------
# edit
# ---------------------------------------------------------------------------

class TestEdit:
    def test_saves_modified_content(self, runner, vault_file, monkeypatch):
        new_content = b"API_KEY=new_value\n"

        def fake_editor(filename):
            with open(filename, "wb") as f:
                f.write(new_content)

        monkeypatch.setattr("est_vault.cli._open_in_editor", fake_editor)
        result = runner.invoke(main, ["edit", vault_file], env={"ENV_VAULT_PASSWORD": PASSWORD})
        assert result.exit_code == 0
        assert vault_mod.read_file(vault_file, PASSWORD.encode()) == new_content

    def test_temp_file_is_deleted_after_edit(self, runner, vault_file, monkeypatch):
        seen = {}

        def fake_editor(filename):
            seen["tmp_path"] = filename

        monkeypatch.setattr("est_vault.cli._open_in_editor", fake_editor)
        runner.invoke(main, ["edit", vault_file], env={"ENV_VAULT_PASSWORD": PASSWORD})
        assert not os.path.exists(seen["tmp_path"])

    def test_missing_file_errors(self, runner, tmp_path):
        result = runner.invoke(main, ["edit", str(tmp_path / "ghost.env")], env={"ENV_VAULT_PASSWORD": PASSWORD})
        assert result.exit_code != 0
        assert "file not found" in result.output


# ---------------------------------------------------------------------------
# ENV_VAULT_PASSWORD env var
# ---------------------------------------------------------------------------

class TestEnvVaultPassword:
    def test_password_read_from_env_var(self, runner, vault_file, monkeypatch):
        monkeypatch.setattr("est_vault.cli._open_in_editor", lambda f: None)
        result = runner.invoke(main, ["view", vault_file], env={"ENV_VAULT_PASSWORD": PASSWORD})
        assert result.exit_code == 0

    def test_env_var_not_used_for_new_passwords(self, runner, plain_file):
        # encrypt always prompts, even if ENV_VAULT_PASSWORD is set
        result = runner.invoke(
            main, ["encrypt", plain_file],
            env={"ENV_VAULT_PASSWORD": PASSWORD},
            input=f"{PASSWORD}\n{PASSWORD}\n",
        )
        assert result.exit_code == 0
