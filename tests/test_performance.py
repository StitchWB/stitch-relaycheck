"""Tests for performance measurement (unit + e2e vs mock relay)."""

from __future__ import annotations

from stitch_relaycheck import client, performance
from tests.mock_relay import MockRelay


class TestMeasureUnit:
    def test_latency_stats_and_score(self, monkeypatch):
        calls = {"n": 0}

        def fake_chat(base_url, api_key, model, messages, **kwargs):
            calls["n"] += 1
            if kwargs.get("stream"):
                return {
                    "ok": True, "latency_ms": 500, "ttft_ms": 200,
                    "text": "1, 2, 3", "usage": {"completion_tokens": 6},
                }
            return {"ok": True, "latency_ms": 100 * calls["n"], "text": "ок"}

        monkeypatch.setattr(client, "chat_completion", fake_chat)
        result = performance.measure("http://x", "sk", "m", "openai", 5.0, repeats=3)
        assert result["ok_count"] == 3
        assert result["ok_rate"] == 1.0
        assert result["latency_ms"]["min"] == 100
        assert result["latency_ms"]["max"] == 300
        assert result["latency_ms"]["avg"] == 200.0
        assert result["ttft_ms"] == 200
        # gen_ms = 500-200=300 → tps = 6 / 0.3 = 20
        assert result["tps"] == 20.0
        assert result["perf_score"] > 0

    def test_all_failed(self, monkeypatch):
        monkeypatch.setattr(
            client,
            "chat_completion",
            lambda *a, **k: {"ok": False, "error_text": "down"},
        )
        result = performance.measure("http://x", "sk", "m", "openai", 5.0, repeats=3)
        assert result["ok_count"] == 0
        assert result["ok_rate"] == 0.0
        assert result["perf_score"] == 0


def test_measure_e2e_mock():
    relay = MockRelay(model="mock-gpt").start()
    try:
        result = performance.measure(relay.base_url, "sk-test", "mock-gpt", "openai", 5.0, repeats=3)
    finally:
        relay.stop()
    assert result["ok_rate"] == 1.0
    assert result["latency_ms"]["avg"] is not None
    assert result["stream_ok"] is True
    assert result["ttft_ms"] is not None
    assert result["tps"] is not None
    assert 0 < result["perf_score"] <= 100
