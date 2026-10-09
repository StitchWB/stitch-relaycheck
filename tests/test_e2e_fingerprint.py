"""E2E tests: fingerprint against a local mock relay (no external network).

The mock computes prompt_tokens as ``overhead + len(content) // divisor``.
Divisor 4 matches the mock-gpt profile deltas; divisor 8 simulates a
substituted model with a different tokenizer.
"""

from __future__ import annotations

import pytest

from stitch_relaycheck import client, fingerprint
from tests.mock_relay import MockRelay

#: Profile tuned to the mock's tokenizer (divisor=4):
#:   latin 16, code 17, unicode 12 (measured deltas, see probe strings).
MOCK_DB = {
    "version": 1,
    "profiles": {
        "mock-gpt": {
            "family": "mock",
            "tokenizer_deltas": {
                "latin": {"expected": 16, "tolerance_pct": 30},
                "code": {"expected": 17, "tolerance_pct": 30},
                "unicode": {"expected": 12, "tolerance_pct": 30},
            },
            "capabilities": {"json_mode": True, "tools": True, "streaming": True},
            "metadata": {"system_fingerprint": "fp", "id_prefix": "chatcmpl"},
        }
    },
    "aliases": {},
}


@pytest.fixture()
def honest_relay():
    relay = MockRelay(model="mock-gpt", tokenizer_divisor=4).start()
    yield relay
    relay.stop()


def test_quick_check_against_mock(honest_relay):
    result = client.quick_check(honest_relay.base_url, "sk-test", model="mock-gpt", timeout=5)
    assert result["success"] is True
    assert result["protocol"] == "openai"
    assert result["model_available"] is True
    assert [m["id"] for m in result["models"]] == ["mock-gpt"]
    assert result["latency_ms"] is not None


def test_fingerprint_authentic(honest_relay):
    fp = fingerprint.run_fingerprint(
        honest_relay.base_url, "sk-test", "mock-gpt", "openai", 5.0, MOCK_DB
    )
    assert fp["verdict"] == "authentic"
    assert fp["score"] == 100
    assert fp["profile_id"] == "mock-gpt"
    # All tokenizer pairs matched.
    for pair in fp["tokenizer"]["pairs"]:
        assert pair["match"] is True, pair
    # Capability probes all passed.
    assert all(p["ok"] for p in fp["capability"]["probes"])
    # Split-half identical.
    assert fp["consistency"]["identical"] is True
    # Metadata captured.
    assert fp["metadata"]["model_echo"] == "mock-gpt"
    assert fp["metadata"]["system_fingerprint"] == "fp_mock_0123abcd"
    assert fp["metadata"]["id_prefix"] == "chatcmpl"
    # Stream shape sane.
    assert fp["stream"]["ok"] is True
    assert "role" in fp["stream"]["events"]


def test_fingerprint_substituted():
    relay = MockRelay(model="mock-gpt", tokenizer_divisor=8).start()
    try:
        fp = fingerprint.run_fingerprint(
            relay.base_url, "sk-test", "mock-gpt", "openai", 5.0, MOCK_DB
        )
    finally:
        relay.stop()
    assert fp["verdict"] == "substituted"
    for pair in fp["tokenizer"]["pairs"]:
        assert pair["match"] is False, pair


def test_fingerprint_echo_mismatch():
    relay = MockRelay(model="mock-gpt", echo_model="gpt-4o").start()
    try:
        fp = fingerprint.run_fingerprint(
            relay.base_url, "sk-test", "mock-gpt", "openai", 5.0, MOCK_DB
        )
    finally:
        relay.stop()
    assert fp["verdict"] == "suspicious"
    assert any("echo" in r for r in fp["reasons"])


def test_fingerprint_unknown_model_indeterminate(honest_relay):
    fp = fingerprint.run_fingerprint(
        honest_relay.base_url, "sk-test", "mystery-model-9000", "openai", 5.0, MOCK_DB
    )
    assert fp["verdict"] == "indeterminate"
    assert fp["profile_id"] is None


def test_fingerprint_unreachable():
    fp = fingerprint.run_fingerprint(
        "http://127.0.0.1:1", "sk-test", "mock-gpt", "openai", 2.0, MOCK_DB
    )
    assert fp["verdict"] == "error"
