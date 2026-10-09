"""E2E: full audit job against the mock relay (background thread + polling)."""

from __future__ import annotations

import time

import pytest

from stitch_relaycheck import security, service, storage
from tests.mock_relay import MockRelay


@pytest.fixture()
def db(tmp_path, monkeypatch):
    monkeypatch.setattr(
        security,
        "check_tls",
        lambda *a, **k: {"ok": True, "plain_http": False, "san_match": True},
    )
    db_path = str(tmp_path / "plugin.db")
    storage.migrate(db_path)
    return db_path


def _wait_job(db_path, job_id, timeout=90.0):
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        job = storage.get_job(db_path, job_id)
        if job and job["status"] in ("done", "error"):
            return job
        time.sleep(0.3)
    return job


def test_full_audit_job_against_mock(db):
    relay = MockRelay(model="mock-gpt").start()
    try:
        started = service.start_audit_job(
            db, model="mock-gpt", base_url=relay.base_url, api_key="sk-test"
        )
        assert started["success"] is True
        job = _wait_job(db, started["job_id"])
    finally:
        relay.stop()

    assert job is not None
    assert job["status"] == "done", job.get("error_text")
    result = job["result"]
    for layer in ("check", "fingerprint", "watering", "security", "performance", "balance", "trust"):
        assert layer in result, f"missing layer {layer}"
    # check + balance succeeded against the mock
    assert result["check"]["success"] is True
    assert result["balance"]["success"] is True
    # fingerprint: mock-gpt has no bundled profile → indeterminate
    assert result["fingerprint"]["verdict"] == "indeterminate"
    # watering clean on honest mock
    assert result["watering"]["verdict"] == "clean"
    # security clean (TLS patched)
    assert result["security"]["verdict"] == "clean"
    # trust score computed
    trust = result["trust"]
    assert trust["score"] is not None
    assert trust["grade"] in ("A", "B", "C", "D", "F")
    # audit report persisted
    reports = storage.list_reports(db)
    audit = [r for r in reports if r["kind"] == "audit"]
    assert len(audit) == 1
    assert audit[0]["verdict"] == trust["grade"]
    # per-layer reports persisted
    kinds = {r["kind"] for r in reports}
    assert {"quick_check", "fingerprint", "watering", "security", "performance", "balance"} <= kinds


def test_audit_job_layers_subset(db):
    relay = MockRelay(model="mock-gpt").start()
    try:
        started = service.start_audit_job(
            db, model="mock-gpt", base_url=relay.base_url, api_key="sk-test",
            layers=["check", "balance"],
        )
        assert started["success"] is True
        job = _wait_job(db, started["job_id"])
    finally:
        relay.stop()
    assert job["status"] == "done"
    assert set(job["result"]["layers"] if "layers" in job["result"] else job["result"]) >= {"check", "balance", "trust"}


def test_start_audit_job_unknown_layer(db):
    relay = MockRelay(model="mock-gpt").start()
    try:
        with pytest.raises(ValueError):
            service.start_audit_job(
                db, model="mock-gpt", base_url=relay.base_url, api_key="sk-test",
                layers=["nope"],
            )
    finally:
        relay.stop()


def test_compare_targets(db):
    a = storage.upsert_target(db, name="A", base_url="https://a.com", api_key_enc="x", key_mask="m")
    b = storage.upsert_target(db, name="B", base_url="https://b.com", api_key_enc="y", key_mask="m")
    storage.add_report(db, kind="fingerprint", target_id=a["id"], target_name="A", verdict="authentic", score=90)
    storage.add_report(db, kind="watering", target_id=a["id"], target_name="A", verdict="clean", score=0)
    storage.add_report(db, kind="security", target_id=a["id"], target_name="A", verdict="clean", score=0)
    storage.add_report(db, kind="fingerprint", target_id=b["id"], target_name="B", verdict="substituted", score=20)

    out = service.compare_targets(db, target_id_a=a["id"], target_id_b=b["id"])
    assert out["success"] is True
    assert out["a"]["trust"]["score"] > out["b"]["trust"]["score"]
    assert "fingerprint" in out["a"]["layers"]
    assert "fingerprint" not in out["b"]["layers"] or out["b"]["layers"]["fingerprint"]["verdict"] == "substituted"

    missing = service.compare_targets(db, target_id_a="nope", target_id_b=b["id"])
    assert missing["success"] is False
