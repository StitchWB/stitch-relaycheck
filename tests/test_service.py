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


def _fake_fp_result(verdict="authentic", score=100):
    return {
        "model": "mock-gpt",
        "profile_id": "mock-gpt",
        "tokenizer": {
            "pairs": [
                {"id": "latin", "observed_delta": 16, "expected_delta": 16, "tolerance_pct": 30, "match": True},
                {"id": "code", "observed_delta": 15, "expected_delta": 17, "tolerance_pct": 30, "match": True},
            ],
            "matched": 2,
            "answered": 2,
            "ratio": 1.0,
        },
        "capability": {
            "probes": [{"id": "arithmetic", "ok": True, "detail": "passed"}],
            "passed": 1,
            "expected": 1,
            "ratio": 1.0,
        },
        "consistency": {"identical": True, "answered": 2},
        "stream": {"ok": True, "ttft_ms": 120, "events": ["role", "content", "[DONE]"]},
        "metadata": {"model_echo": "mock-gpt", "system_fingerprint": "fp_x", "id_prefix": "chatcmpl"},
        "verdict": verdict,
        "score": score,
        "reasons": ["совпадение токенайзера: 100%"],
        "probe_count": 12,
        "duration_ms": 4321,
    }


class TestVerifyModel:
    def test_model_required(self, env):
        with pytest.raises(ValueError):
            service.verify_model(env, model="")
        # Unknown target id is an API-result failure, not a validation error.
        out = service.verify_model(env, model="", target_id="nope")
        assert out["success"] is False

    def test_adhoc_requires_url_and_key(self, env):
        with pytest.raises(ValueError):
            service.verify_model(env, model="m", base_url="", api_key="")

    def test_missing_target(self, env):
        out = service.verify_model(env, model="m", target_id="nope")
        assert out["success"] is False
        assert "not found" in out["error_text"]

    def test_target_model_fallback(self, env, monkeypatch):
        """Model may come from the saved target when not passed explicitly."""
        out = service.save_target(
            env,
            name="r",
            base_url="http://127.0.0.1:1",
            api_key="sk-test-fingerprint-key",
            model="mock-gpt",
        )
        tid = out["target"]["id"]
        monkeypatch.setattr(
            client, "detect_protocol", lambda *a, **k: {"success": False, "error_text": "x"}
        )
        monkeypatch.setattr(
            "stitch_relaycheck.fingerprint.run_fingerprint",
            lambda *a, **k: _fake_fp_result(),
        )
        result = service.verify_model(env, model="", target_id=tid)
        assert result["success"] is True
        assert result["model"] == "mock-gpt"
        assert result["verdict"] == "authentic"
        assert result["score"] == 100
        assert result["report_id"]

        report = storage.get_report(env, result["report_id"])
        assert report is not None
        assert report["kind"] == "fingerprint"
        assert report["verdict"] == "authentic"
        assert report["score"] == 100
        # Key never leaks into the report.
        assert "sk-test-fingerprint-key" not in str(report["summary"])

        # Target row stamped.
        row = storage.list_targets(env)[0]
        assert row["last_verdict"] == "authentic"
        assert row["last_score"] == 100

    def test_adhoc_fingerprint(self, env, monkeypatch):
        monkeypatch.setattr(
            client,
            "detect_protocol",
            lambda *a, **k: {"success": True, "protocol": "openai"},
        )
        monkeypatch.setattr(
            "stitch_relaycheck.fingerprint.run_fingerprint",
            lambda *a, **k: _fake_fp_result(verdict="substituted", score=12),
        )
        result = service.verify_model(
            env, model="gpt-5", base_url="https://relay.example.com", api_key="sk-x"
        )
        assert result["success"] is True
        assert result["verdict"] == "substituted"
        report = storage.get_report(env, result["report_id"])
        assert report is not None
        assert report["base_url"] == "https://relay.example.com"

    def test_fingerprint_markdown(self, env, monkeypatch):
        monkeypatch.setattr(
            client, "detect_protocol", lambda *a, **k: {"success": True, "protocol": "openai"}
        )
        monkeypatch.setattr(
            "stitch_relaycheck.fingerprint.run_fingerprint",
            lambda *a, **k: _fake_fp_result(),
        )
        service.verify_model(
            env, model="mock-gpt", base_url="https://a.com", api_key="sk-x"
        )
        md = service.get_report_markdown(env, "latest")
        assert "fingerprint" in md["text"]
        assert "authentic" in md["text"]
        assert "Tokenizer deltas" in md["text"]


def _fake_watering_result(verdict="watered", score=55):
    return {
        "model": "mock-gpt",
        "score": score,
        "verdict": verdict,
        "reasons": ["[marketing_tail] в ответе найдена маркетинговая вставка"],
        "prompts": [
            {
                "id": "reasoning",
                "ok": True,
                "relay_text": "ответ… хвост про канал",
                "latency_ms": 100,
                "heuristics": [{"id": "marketing_tail", "severity": "high", "detail": "x"}],
            }
        ],
        "duration_ms": 1500,
        "probe_count": 5,
        "compared_with_reference": False,
    }


class TestWatering:
    def test_model_required(self, env):
        with pytest.raises(ValueError):
            service.detect_watering(env, model="")

    def test_adhoc_requires_url_and_key(self, env):
        with pytest.raises(ValueError):
            service.detect_watering(env, model="m", base_url="", api_key="")

    def test_report_written(self, env, monkeypatch):
        monkeypatch.setattr(
            client, "detect_protocol", lambda *a, **k: {"success": True, "protocol": "openai"}
        )
        monkeypatch.setattr(
            "stitch_relaycheck.watering.run_watering",
            lambda *a, **k: _fake_watering_result(),
        )
        result = service.detect_watering(
            env, model="mock-gpt", base_url="https://a.com", api_key="sk-x"
        )
        assert result["success"] is True
        assert result["verdict"] == "watered"
        assert result["score"] == 55
        report = storage.get_report(env, result["report_id"])
        assert report is not None
        assert report["kind"] == "watering"
        assert report["verdict"] == "watered"
        assert report["score"] == 55

    def test_reference_forwarded(self, env, monkeypatch):
        monkeypatch.setattr(
            client, "detect_protocol", lambda *a, **k: {"success": True, "protocol": "openai"}
        )
        captured = {}

        def fake_run(base_url, api_key, model, protocol, timeout, reference=None):
            captured["reference"] = reference
            return _fake_watering_result(verdict="clean", score=0)

        monkeypatch.setattr("stitch_relaycheck.watering.run_watering", fake_run)
        result = service.detect_watering(
            env,
            model="m",
            base_url="https://relay.example.com",
            api_key="sk-x",
            reference_base_url="https://official.example.com/v1/",
            reference_api_key="sk-ref",
            reference_model="m-ref",
        )
        assert result["success"] is True
        assert captured["reference"]["base_url"] == "https://official.example.com"
        assert captured["reference"]["model"] == "m-ref"


class TestBalance:
    def test_adhoc_requires_url_and_key(self, env):
        with pytest.raises(ValueError):
            service.get_balance(env, target_id="", base_url="", api_key="")

    def test_report_written(self, env, monkeypatch):
        monkeypatch.setattr(
            client,
            "get_balance",
            lambda *a, **k: {
                "success": True,
                "balance": {"software": "one-api/new-api", "remaining_usd_estimate": 0.97},
                "endpoint": "https://a.com/api/user/self",
            },
        )
        result = service.get_balance(env, base_url="https://a.com", api_key="sk-x")
        assert result["success"] is True
        assert result["balance"]["remaining_usd_estimate"] == 0.97
        report = storage.get_report(env, result["report_id"])
        assert report is not None
        assert report["kind"] == "balance"
        assert report["verdict"] == "ok"

    def test_target_resolution_error(self, env):
        out = service.get_balance(env, target_id="nope")
        assert out["success"] is False


def _fake_security_result(verdict="clean", risk=0):
    return {
        "model": "mock-gpt",
        "risk_score": risk,
        "verdict": verdict,
        "reasons": [],
        "findings": [],
        "ioc": {"host": "a.com", "matches": [], "blocklist_size": 0},
        "tls": {"ok": True, "plain_http": False, "san_match": True},
        "canary": [{"id": "canary_story", "ok": True, "findings": []}],
        "injection": [],
        "probe_count": 4,
        "duration_ms": 900,
        "rules_version": 4,
        "rules_compiled": 105,
        "rules_skipped": 0,
    }


class TestScanSecurity:
    def test_adhoc_requires_url_and_key(self, env):
        with pytest.raises(ValueError):
            service.scan_security(env, model="", base_url="", api_key="")

    def test_model_fallback_to_first_advertised(self, env, monkeypatch):
        monkeypatch.setattr(
            client,
            "detect_protocol",
            lambda *a, **k: {"success": True, "protocol": "openai", "models": [{"id": "mock-gpt"}]},
        )
        captured = {}

        def fake_scan(base_url, api_key, model, protocol, timeout, ruleset=None):
            captured["model"] = model
            return _fake_security_result(verdict="medium", risk=20)

        monkeypatch.setattr("stitch_relaycheck.security.run_security_scan", fake_scan)
        result = service.scan_security(env, model="", base_url="https://a.com", api_key="sk-x")
        assert result["success"] is True
        assert result["verdict"] == "medium"
        assert captured["model"] == "mock-gpt"
        report = storage.get_report(env, result["report_id"])
        assert report is not None
        assert report["kind"] == "security"
        assert report["score"] == 20

    def test_no_models_is_error_result(self, env, monkeypatch):
        monkeypatch.setattr(
            client,
            "detect_protocol",
            lambda *a, **k: {"success": True, "protocol": "openai", "models": []},
        )
        out = service.scan_security(env, model="", base_url="https://a.com", api_key="sk-x")
        assert out["success"] is False
        assert "model" in out["error_text"]

    def test_security_markdown(self, env, monkeypatch):
        monkeypatch.setattr(
            client, "detect_protocol", lambda *a, **k: {"success": True, "protocol": "openai", "models": []}
        )
        monkeypatch.setattr(
            "stitch_relaycheck.security.run_security_scan",
            lambda *a, **k: _fake_security_result(verdict="clean", risk=0),
        )
        service.scan_security(env, model="mock-gpt", base_url="https://a.com", api_key="sk-x")
        md = service.get_report_markdown(env, "latest")
        assert "security-скан" in md["text"]
        assert "clean" in md["text"]
