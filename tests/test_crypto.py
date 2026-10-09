"""Unit tests for the Fernet at-rest crypto helpers."""

from __future__ import annotations

import pytest

from stitch_relaycheck import crypto


@pytest.fixture()
def initialized(tmp_path, monkeypatch):
    # Isolate from any ambient env key and from a real core key file.
    monkeypatch.delenv("TOKEN_ENCRYPTION_KEY", raising=False)
    monkeypatch.setattr(crypto, "_core_key_path", lambda: tmp_path / "nonexistent" / ".db_key")
    crypto.init_crypto(str(tmp_path / "data"))
    return tmp_path / "data"


def test_roundtrip(initialized):
    token = crypto.encrypt("sk-secret-1234567890")
    assert token != "sk-secret-1234567890"
    assert crypto.decrypt(token) == "sk-secret-1234567890"


def test_plugin_local_key_file_created(initialized):
    assert (initialized / ".db_key").exists()


def test_decrypt_lenient_passes_plaintext(initialized):
    assert crypto.decrypt_lenient("not-a-token") == "not-a-token"


def test_decrypt_lenient_passes_tampered(initialized):
    token = crypto.encrypt("sk-secret-1234567890")
    tampered = token[:-4] + "AAAA"
    assert crypto.decrypt_lenient(tampered) == tampered


def test_env_key_wins(tmp_path, monkeypatch):
    from cryptography.fernet import Fernet

    env_key = Fernet.generate_key().decode()
    monkeypatch.setenv("TOKEN_ENCRYPTION_KEY", env_key)
    crypto.init_crypto(str(tmp_path / "data"))
    assert crypto.decrypt(crypto.encrypt("x")) == "x"
    monkeypatch.setattr(crypto, "_key", None)  # reset for other tests
