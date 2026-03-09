# est-vault

**est-vault** is a command-line tool for managing application secrets securely. Instead of storing sensitive environment variables in plaintext `.env` files or hardcoding them in scripts, you keep them in an encrypted vault and let `est-vault` inject them into any process at runtime — no plaintext ever touches disk during normal operation.

It's designed to be simple: one vault file, one password, any program.

---

## How it works

1. Create an encrypted vault containing your `KEY=VALUE` secrets
2. `est-vault` decrypts the file at runtime (prompting for a password or reading from an env var)
3. The decrypted variables are injected into the child process environment
4. Your program runs with access to the secrets — no plaintext files on disk

```
est-vault prod.env docker-compose -- up -d
```

---

## Installation

Requires Python 3.9+.

```sh
pip install est-vault
```

Or install from source:

```sh
git clone https://github.com/esteveslean/est-vault
cd est-vault
pip install -e .
```

---

## Usage

### Run a program with vault secrets

```sh
est-vault <vault-file> <program> [-- program-args...]
```

```sh
# Basic usage
est-vault prod.env python manage.py migrate

# Pass arguments to the program with --
est-vault prod.env docker-compose -- up -d

# Only use vault variables (don't inherit current environment)
est-vault --pristine prod.env python app.py
```

### Commands

| Command | Description |
|---|---|
| `est-vault <vault> <program>` | Run program with env vars from vault |
| `est-vault create <file>` | Create a new encrypted vault (opens editor) |
| `est-vault view <file>` | View decrypted contents in editor (read-only) |
| `est-vault edit <file>` | Edit an encrypted vault in-place |
| `est-vault encrypt <file>` | Encrypt a plaintext file in-place |
| `est-vault decrypt <file>` | Decrypt a vault file to plaintext in-place |
| `est-vault rekey <file>` | Change the password of a vault |
| `est-vault version` | Print version |

---

## Quickstart

**1. Create a vault**

```sh
est-vault create prod.env
```

This opens your editor. Write your secrets in plain `KEY=VALUE` format:

```
DB_HOST=db.example.com
DB_PORT=5432
DB_PASSWORD=super_secret
API_KEY=abc123
```

Save and close — the file is encrypted automatically.

**2. Use the vault**

```sh
est-vault prod.env docker-compose -- up -d
```

**3. View or edit later**

```sh
# Read-only view
est-vault view prod.env

# Edit and re-encrypt
est-vault edit prod.env
```

**4. Rotate the password**

```sh
est-vault rekey prod.env
```

---

## Non-interactive usage (CI/CD)

Set the `ENV_VAULT_PASSWORD` environment variable to skip the password prompt:

```sh
export ENV_VAULT_PASSWORD="my-vault-password"
est-vault prod.env ./deploy.sh
```

> **Note:** `ENV_VAULT_PASSWORD` is intentionally ignored when creating a new password (i.e., `create`, `encrypt`, `rekey`) to prevent accidentally reusing an exposed variable as a new secret.

---

## Editor

The editor is selected in the following order:

1. `ENV_VAULT_EDITOR` environment variable
2. `EDITOR` environment variable
3. `notepad` on Windows / `vim` on Unix

```sh
ENV_VAULT_EDITOR=nano est-vault create prod.env
```

---

## Docker Compose

A common use case is injecting secrets into Docker Compose without committing a `.env` file:

```sh
# Create the vault
est-vault create prod.env

# Start services with secrets from vault
est-vault prod.env docker-compose -- up -d
```

> **Warning:** Do not name your vault `.env`. Docker Compose reads that filename automatically for variable interpolation, and will fail to parse the encrypted content.

---


## Development

```sh
# Install with dev dependencies
pip install -e ".[dev]"

# Run tests
python -m pytest tests/ -v
```

---

## License

MIT
