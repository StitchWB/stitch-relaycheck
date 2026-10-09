"""Fernet-compatible at-rest encryption for the plugin secret store.

Copied from the stitch-totp plugin (which mirrors
``stitch_backend.security.fernet_at_rest``) — service plugins must not
import ``stitch_backend``, so the scheme constants and helpers live here.
Tokens are interchangeable with the core's: same Fernet format, same key
source order:

1. ``TOKEN_ENCRYPTION_KEY`` env var (inherited from the host process —
   the host only passes it to storage-declaring plugins from trusted
   sources).
2. Core key file ``<app_data>/stitch-manager/.db_key`` — shared with the
   host so migrated tokens stay readable by both sides.
3. Plugin-local ``<data_dir>/.db_key`` (generated on first use).
"""

from __future__ import annotations

import os
import sys
from pathlib import Path

_ENV_KEY_NAME = "TOKEN_ENCRYPTION_KEY"
_KEY_FILE_NAME = ".db_key"

#: Resolved Fernet key (urlsafe-base64 bytes); set by init_crypto().
_key: bytes | None = None


def _app_data_dir() -> Path:
    """OS-specific local app-data dir (mirrors core config._app_data_dir)."""
    if sys.platform == "win32":
        return Path(
            os.environ.get("LOCALAPPDATA", str(Path.home() / "AppData" / "Local"))
        )
    if sys.platform == "darwin":
        return Path.home() / "Library" / "Application Support"
    return Path.home() / ".local" / "share"


def _core_key_path() -> Path:
    """Core key file location (fernet_at_rest._key_file_path mirror)."""
    return _app_data_dir() / "stitch-manager" / _KEY_FILE_NAME


def init_crypto(data_dir: str) -> None:
    """Resolve the Fernet key: env var → core key file → plugin-local file.

    Called from ``plugin.init``.  Raises ``ValueError`` when a configured
    key is not a valid Fernet key (same contract as core).
    """
    global _key
    from cryptography.fernet import Fernet

    env_key = os.environ.get(_ENV_KEY_NAME, "").strip()
    if env_key:
        Fernet(env_key.encode())  # validate — raises ValueError
        _key = env_key.encode()
        return

    core_path = _core_key_path()
    if core_path.exists():
        data = core_path.read_bytes().strip()
        Fernet(data)  # validate
        _key = data
        return

    local_path = Path(data_dir) / _KEY_FILE_NAME
    if local_path.exists():
        data = local_path.read_bytes().strip()
        Fernet(data)  # validate
        _key = data
        return

    _key = Fernet.generate_key()
    Path(data_dir).mkdir(parents=True, exist_ok=True)
    local_path.write_bytes(_key)


def encrypt(plaintext: str) -> str:
    """Encrypt *plaintext* to a urlsafe-base64 Fernet token string."""
    from cryptography.fernet import Fernet

    if _key is None:
        raise RuntimeError("crypto not initialised — plugin.init missing")
    return Fernet(_key).encrypt(plaintext.encode("utf-8")).decode("ascii")


def decrypt(ciphertext: str) -> str:
    """Decrypt a Fernet token produced by :func:`encrypt`."""
    from cryptography.fernet import Fernet

    if _key is None:
        raise RuntimeError("crypto not initialised — plugin.init missing")
    return Fernet(_key).decrypt(ciphertext.encode("ascii")).decode("utf-8")


def decrypt_lenient(ciphertext: str) -> str:
    """Decrypt a Fernet token; return the raw value when not decryptable.

    Mirrors the core ``EncryptedText`` read contract: legacy plaintext
    rows and wrong-key tokens pass through instead of raising, so a read
    never crashes on an undecryptable value.
    """
    from cryptography.fernet import Fernet, InvalidToken

    if _key is None:
        raise RuntimeError("crypto not initialised — plugin.init missing")
    try:
        return Fernet(_key).decrypt(ciphertext.encode("ascii")).decode("utf-8")
    except (InvalidToken, ValueError, UnicodeEncodeError):
        return ciphertext
