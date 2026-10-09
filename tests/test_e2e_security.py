"""E2E: security scan against the mock relay (injection vs honest vs plain-http)."""

from __future__ import annotations

import pytest

from stitch_relaycheck import security
from tests.mock_relay import MockRelay


@pytest.fixture()
def tls_ok(monkeypatch):
    """Silence the plain-http finding (the mock relay is HTTP by design)."""
    monkeypatch.setattr(
        security,
        "check_tls",
        lambda *a, **k: {"ok": True, "plain_http": False, "san_match": True},
    )


def test_scan_clean_on_honest_relay(tls_ok):
    relay = MockRelay(model="mock-gpt").start()
    try:
        result = security.run_security_scan(
            relay.base_url, "sk-test", "mock-gpt", "openai", 5.0
        )
    finally:
        relay.stop()
    assert result["verdict"] == "clean"
    assert result["risk_score"] == 0
    assert result["findings"] == []
    assert len(result["canary"]) == 2
    assert result["rules_compiled"] > 90


def test_scan_detects_tool_use_injection(tls_ok):
    relay = MockRelay(model="mock-gpt", inject_tool_use=True).start()
    try:
        result = security.run_security_scan(
            relay.base_url, "sk-test", "mock-gpt", "openai", 5.0
        )
    finally:
        relay.stop()
    ids = {f["rule_id"] for f in result["findings"]}
    assert "proto-tooluse-unsolicited" in ids
    assert "dl-curl-pipe-sh" in ids  # the injected payload itself matches a rule
    assert result["verdict"] in ("high", "critical")
    assert result["risk_score"] >= 70
    # Excerpts must not leak the API key.
    assert "sk-test" not in str(result["findings"])


def test_scan_unreachable(tls_ok):
    result = security.run_security_scan(
        "http://127.0.0.1:1", "sk-test", "mock-gpt", "openai", 2.0
    )
    assert result["verdict"] == "error"


def test_scan_plain_http_flagged():
    """Real check_tls: plain-HTTP endpoint is a high finding (no patch here)."""
    relay = MockRelay(model="mock-gpt").start()
    try:
        result = security.run_security_scan(
            relay.base_url, "sk-test", "mock-gpt", "openai", 5.0
        )
    finally:
        relay.stop()
    ids = {f["rule_id"] for f in result["findings"]}
    assert "plain-http-no-tls" in ids
