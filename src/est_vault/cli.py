"""
est-vault CLI.

Commands:
  est-vault <vault> <program> [-- args]   Run program with decrypted env vars
  est-vault create <filename>             Create new encrypted vault
  est-vault view   <filename>             View decrypted vault in editor
  est-vault edit   <filename>             Edit encrypted vault
  est-vault encrypt <filename>            Encrypt a plaintext file in-place
  est-vault decrypt <filename>            Decrypt an encrypted file in-place
  est-vault rekey  <filename>             Change vault password
  est-vault version                       Print version
"""

import os
import platform
import subprocess
import sys
import tempfile

import click

from est_vault import vault as vault_mod
from est_vault.version import full_version

DEFAULT_EDITOR_UNIX = "vim"
DEFAULT_EDITOR_WINDOWS = "notepad"


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _get_password(prompt: str, *, allow_env: bool = True) -> bytes:
    """Read password from ENV_VAULT_PASSWORD or prompt the user."""
    if allow_env:
        env_pw = os.environ.get("ENV_VAULT_PASSWORD", "")
        if env_pw:
            return env_pw.encode()
    return click.prompt(prompt, hide_input=True).encode()


def _get_preferred_editor() -> str:
    for var in ("ENV_VAULT_EDITOR", "EDITOR"):
        val = os.environ.get(var, "")
        if val:
            return val
    return DEFAULT_EDITOR_WINDOWS if platform.system() == "Windows" else DEFAULT_EDITOR_UNIX


def _open_in_editor(filename: str) -> None:
    editor = _get_preferred_editor()
    subprocess.run([editor, filename], check=True)


def _assert_file_exists(filename: str) -> None:
    if not os.path.exists(filename):
        raise click.ClickException(f"file not found: {filename}")


# ---------------------------------------------------------------------------
# Root command  (est-vault <vault> <program> [-- args])
# ---------------------------------------------------------------------------

@click.group(
    invoke_without_command=True,
    context_settings={"allow_extra_args": True, "allow_interspersed_args": False},
)
@click.option(
    "--pristine",
    is_flag=True,
    default=False,
    help="Only use values from vault; do not inherit current environment variables.",
)
@click.pass_context
def main(ctx: click.Context, pristine: bool) -> None:
    """Launch a subprocess with environment variables from an encrypted file.

    \b
    Usage:
      est-vault [--pristine] <vault> <program> [-- program-args...]
      est-vault <subcommand> [args...]

    \b
    Examples:
      est-vault prod.env docker-compose -- up -d
      est-vault create secrets.env
      est-vault view secrets.env
    """
    if ctx.invoked_subcommand is not None:
        return

    args = ctx.args
    if len(args) < 2:
        click.echo(ctx.get_help())
        ctx.exit(1)

    vault_file = args[0]
    program = args[1]
    program_args = args[2:]

    import shutil
    executable = shutil.which(program)
    if not executable:
        raise click.ClickException(f"executable not found: {program}")

    password = _get_password("Password: ")

    try:
        plaintext = vault_mod.read_file(vault_file, password)
    except Exception as e:
        raise click.ClickException(str(e))

    new_env: dict[str, str] = {}
    if not pristine:
        new_env.update(os.environ)

    for line in plaintext.decode().splitlines():
        line = line.strip()
        if line and "=" in line:
            key, _, value = line.partition("=")
            new_env[key.strip()] = value.strip()

    result = subprocess.run([executable, *program_args], env=new_env)
    sys.exit(result.returncode)


# ---------------------------------------------------------------------------
# Subcommands
# ---------------------------------------------------------------------------

@main.command("create")
@click.argument("filename")
def create(filename: str) -> None:
    """Create a new encrypted vault file."""
    password = _get_password("New password: ", allow_env=False)
    password2 = _get_password("Confirm new password: ", allow_env=False)

    if password != password2:
        raise click.ClickException("passwords do not match")

    with tempfile.NamedTemporaryFile(prefix="est-vault-", delete=False, suffix=".env") as tmp:
        tmp_path = tmp.name

    try:
        _open_in_editor(tmp_path)
        with open(tmp_path, "rb") as f:
            plaintext = f.read()
        vault_mod.write_file(filename, plaintext, password)
    except Exception as e:
        raise click.ClickException(str(e))
    finally:
        try:
            os.remove(tmp_path)
        except OSError:
            pass


@main.command("view")
@click.argument("filename")
def view(filename: str) -> None:
    """View the decrypted contents of a vault file in the editor."""
    _assert_file_exists(filename)

    password = _get_password("Password: ")

    try:
        plaintext = vault_mod.read_file(filename, password)
    except Exception as e:
        raise click.ClickException(str(e))

    with tempfile.NamedTemporaryFile(prefix="est-vault-", delete=False, suffix=".env") as tmp:
        tmp.write(plaintext)
        tmp_path = tmp.name

    try:
        _open_in_editor(tmp_path)
    except Exception as e:
        raise click.ClickException(str(e))
    finally:
        try:
            os.remove(tmp_path)
        except OSError:
            pass


@main.command("edit")
@click.argument("filename")
def edit(filename: str) -> None:
    """Edit the contents of an encrypted vault file."""
    _assert_file_exists(filename)

    password = _get_password("Password: ")

    try:
        plaintext = vault_mod.read_file(filename, password)
    except Exception as e:
        raise click.ClickException(str(e))

    with tempfile.NamedTemporaryFile(prefix="est-vault-", delete=False, suffix=".env") as tmp:
        tmp.write(plaintext)
        tmp_path = tmp.name

    try:
        _open_in_editor(tmp_path)
        with open(tmp_path, "rb") as f:
            modified = f.read()
        vault_mod.write_file(filename, modified, password)
    except Exception as e:
        raise click.ClickException(str(e))
    finally:
        try:
            os.remove(tmp_path)
        except OSError:
            pass


@main.command("encrypt")
@click.argument("filename")
def encrypt(filename: str) -> None:
    """Permanently encrypt a plaintext file in-place."""
    _assert_file_exists(filename)

    password = _get_password("New password: ", allow_env=False)
    password2 = _get_password("Confirm new password: ", allow_env=False)

    if password != password2:
        raise click.ClickException("passwords do not match")

    try:
        with open(filename, "rb") as f:
            plaintext = f.read()
        vault_mod.write_file(filename, plaintext, password)
    except Exception as e:
        raise click.ClickException(str(e))


@main.command("decrypt")
@click.argument("filename")
def decrypt(filename: str) -> None:
    """Permanently decrypt an encrypted vault file in-place."""
    _assert_file_exists(filename)

    password = _get_password("Password: ")

    try:
        plaintext = vault_mod.read_file(filename, password)
        with open(filename, "wb") as f:
            f.write(plaintext)
        try:
            os.chmod(filename, 0o700)
        except OSError:
            pass
    except Exception as e:
        raise click.ClickException(str(e))


@main.command("rekey")
@click.argument("filename")
def rekey(filename: str) -> None:
    """Change the password of an encrypted vault file."""
    _assert_file_exists(filename)

    password = _get_password("Current password: ")
    new_password = _get_password("New password: ", allow_env=False)
    new_password2 = _get_password("Confirm new password: ", allow_env=False)

    if new_password != new_password2:
        raise click.ClickException("passwords do not match")

    try:
        plaintext = vault_mod.read_file(filename, password)
        vault_mod.write_file(filename, plaintext, new_password)
    except Exception as e:
        raise click.ClickException(str(e))


@main.command("version")
def version() -> None:
    """Print the est-vault version."""
    click.echo(full_version())
