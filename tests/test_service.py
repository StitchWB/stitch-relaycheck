"""Unit tests for the RelayCheck service layer (client mocked, no network)."""

from __future__ import annotations

import pytest

from stitch_relaycheck import client, crypto, service, storage


@pytest.fixture()
def env(tmp_path, monkeypatch):
    """Isolated db + crypto; returns (db_path, tmp_path)."""
    monkeypatch.delenv("TOKEN_ENCRYPTION_KEY", raising=False)
    monkeypatch.setattr(crypto, "_core_key_path", lambda: tmp_path / "nope" / ".db_key")
    monkeypatch.setattr(crypto, "_key", None)
    crypto.init_crypto(str(tmp_path / "data"))
    db_path = str(tmp_path / "plugin.db")
    storage.migrate(db_path)
    return db_path


class TestSettings:
    def test_defaults(self, env):
        db_path = env
        s = service.get_settings(db_path)
        assert s == {"timeoutSeconds": 15, "persistKeys": True}

    def test_set_and_merge(self, env):
        db_path = env
        s = service.set_settings(db_path, {"timeoutSeconds": 30})
        assert s["timeoutSeconds"] == 30
        assert s["persistKeys"] is True  # untouched

    def test_unknown_key_rejected(self, env):
        with pytest.raises(ValueError):
            service.set_settings(env, {"nope": 1})

    def test_bad_int_rejected(self, env):
        with pytest.raises(ValueError):
            service.set_settings(env, {"timeoutSeconds": "abc"})
        with pytest.raises(ValueError):
            service.set_settings(env, {"timeoutSeconds": -5})


class TestSaveTarget:
    def test_validation(self, env):
        with pytest.raises(ValueError):
            service.save_target(env, name="", base_url="https://a.com", api_key="k")
        with pytest.raises(ValueError):
            service.save_target(env, name="n", base_url="", api_key="k")
        with pytest.raises(ValueError):
            service.save_target(
                env, name="n", base_url="https://a.com", api_key="", persist_key=True
            )

    def test_key_encrypted_at_rest(self, env):
        db_path = env
        out = service.save_target(
            db_path,
            name="relay",
            base_url="https://a.com/v1/",
            api_key="sk-secret-1234567890",
        )
        target = out["target"]
        assert target["base_url"] == "https://a.com"
        assert target["key_mask"] == "sk-secr…7890"

        raw = storage.get_target(db_path, target["id"])
        assert raw is not None
        assert raw["api_key_enc"] is not None
        assert "sk-secret-1234567890" not in raw["api_key_enc"]
        # And it decrypts back.
        assert crypto.decrypt(raw["api_key_enc"]) == "sk-secret-1234567890"

    def test_persist_key_false_stores_no_secret(self, env):
        db_path = env
        out = service.save_target(
            db_path,
            name="relay",
            base_url="https://a.com",
            api_key="sk-secret-1234567890",
            persist_key=False,
        )
        raw = storage.get_target(db_path, out["target"]["id"])
        assert raw is not None
        assert raw["api_key_enc"] is None
        assert out["target"]["key_mask"] == "—"


class TestQuickCheck:
    def test_report_written_and_key_never_leaks(self, env, monkeypatch):
        db_path = env
        api_key = "sk-secret-LEAKCHECK"
        monkeypatch.setattr(
            client,
            "quick_check",
            lambda base_url, key, model="", timeout=15.0: {
                "success": True,
                "protocol": "openai",
                "models": [{"id": "gpt-5"}],
                "model_count": 1,
                "latency_ms": 42,
                "normalized_url": "https://a.com",
                "model_available": True,
            },
        )
        result = service.quick_check(db_path, "https://a.com/v1", api_key, model="gpt-5")
        assert result["success"] is True
        assert result["model_available"] is True
        assert result["report_id"]

        report = storage.get_report(db_path, result["report_id"])
        assert report is not None
        assert report["verdict"] == "ok"
        assert report["latency_ms"] == 42
        # The raw key must not appear anywhere in the stored summary.
        assert api_key not in str(report["summary"])

    def test_error_result_still_recorded(self, env, monkeypatch):
        db_path = env
        monkeypatch.setattr(
            client,
            "quick_check",
            lambda base_url, key, model="", timeout=15.0: {
                "success": False,
                "error_text": "HTTP 401: ключ отклонён",
                "normalized_url": "https://a.com",
            },
        )
        result = service.quick_check(db_path, "https://a.com", "sk-x")
        assert result["success"] is False
        report = storage.get_report(db_path, result["report_id"])
        assert report is not None
        assert report["verdict"] == "error"

    def test_error_text_is_redacted(self, env, monkeypatch):
        db_path = env
        api_key = "sk-secret-LEAKCHECK"
        monkeypatch.setattr(
            client,
            "quick_check",
            lambda base_url, key, model="", timeout=15.0: {
                "success": False,
                "error_text": f"upstream said key {key} is bad",
                "normalized_url": "https://a.com",
            },
        )
        result = service.quick_check(db_path, "https://a.com", api_key)
        report = storage.get_report(db_path, result["report_id"])
        assert report is not None
        assert api_key not in str(report["summary"])


class TestReports:
    def test_markdown_latest(self, env, monkeypatch):
        db_path = env
        monkeypatch.setattr(
            client,
            "quick_check",
            lambda base_url, key, model="", timeout=15.0: {
                "success": True,
                "protocol": "openai",
                "models": [{"id": "gpt-5"}],
                "model_count": 1,
                "latency_ms": 42,
                "normalized_url": "https://a.com",
                "model_available": True,
            },
        )
        service.quick_check(db_path, "https://a.com", "sk-x", model="gpt-5")
        md = service.get_report_markdown(db_path, "latest")
        assert "# RelayCheck" in md["text"]
        assert "gpt-5" in md["text"]
        assert "**Модель доступна:** да" in md["text"]

    def test_markdown_empty(self, env):
        md = service.get_report_markdown(env, "latest")
        assert "no reports" in md["text"]


class TestCheckTarget:
    def test_missing_target(self, env):
        out = service.check_target(env, "nope")
        assert out["success"] is False

    def test_target_without_key(self, env):
        out = service.save_target(
            env, name="r", base_url="https://a.com", api_key="k", persist_key=False
        )
        result = service.check_target(env, out["target"]["id"])
        assert result["success"] is False
        assert "persistKey" in result["error_text"]
