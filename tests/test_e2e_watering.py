"""E2E: watering detection + balance lookup against the mock relay."""

from __future__ import annotations

import pytest

from stitch_relaycheck import client, watering
from tests.mock_relay import MockRelay


@pytest.fixture()
def honest_relay():
    relay = MockRelay(model="mock-gpt").start()
    yield relay
    relay.stop()


def test_watering_clean_on_honest_relay(honest_relay):
    result = watering.run_watering(
        honest_relay.base_url, "sk-test", "mock-gpt", "openai", 5.0
    )
    assert result["verdict"] == "clean"
    assert result["score"] == 0
    assert result["probe_count"] == len(watering.WATERING_PROMPTS)
    assert result["compared_with_reference"] is False
    # All prompts answered.
    assert all(p["ok"] for p in result["prompts"])


def test_watering_detects_marketing_suffix():
    relay = MockRelay(model="mock-gpt", watering=True).start()
    try:
        result = watering.run_watering(
            relay.base_url, "sk-test", "mock-gpt", "openai", 5.0
        )
    finally:
        relay.stop()
    assert result["verdict"] in ("watered", "heavy")
    assert result["score"] >= 45
    assert any("marketing_tail" in r for r in result["reasons"])


def test_watering_reference_comparison(honest_relay):
    watered = MockRelay(model="mock-gpt", watering=True).start()
    try:
        result = watering.run_watering(
            watered.base_url,
            "sk-test",
            "mock-gpt",
            "openai",
            5.0,
            reference={
                "base_url": honest_relay.base_url,
                "api_key": "sk-test",
                "model": "",
            },
        )
    finally:
        watered.stop()
    assert result["compared_with_reference"] is True
    assert result["verdict"] in ("watered", "heavy")
    # At least one prompt has a comparison block.
    assert any("comparison" in p for p in result["prompts"])


def test_watering_unreachable():
    result = watering.run_watering(
        "http://127.0.0.1:1", "sk-test", "mock-gpt", "openai", 2.0
    )
    assert result["verdict"] == "error"


def test_balance_one_api_shape(honest_relay):
    result = client.get_balance(honest_relay.base_url, "sk-test", timeout=5)
    assert result["success"] is True
    balance = result["balance"]
    assert balance["software"] == "one-api/new-api"
    assert balance["quota"] == 500000
    assert balance["used_quota"] == 12345
    assert balance["remaining_quota"] == 500000 - 12345
    assert balance["remaining_usd_estimate"] == round((500000 - 12345) / 500000, 4)


def test_balance_unreachable():
    result = client.get_balance("http://127.0.0.1:1", "sk-test", timeout=2)
    assert result["success"] is False
    assert result["error_text"]
