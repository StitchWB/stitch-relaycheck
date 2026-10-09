"""Unit tests for the RelayCheck SQLite storage layer."""

from __future__ import annotations

import pytest

from stitch_relaycheck import storage


@pytest.fixture()
def db(tmp_path):
    db_path = str(tmp_path / "plugin.db")
    storage.migrate(db_path)
    return db_path


class TestTargets:
    def test_upsert_list_get_delete(self, db):
        t = storage.upsert_target(
            db,
            name="relay",
            base_url="https://a.com",
            api_key_enc="ciphertext",
            key_mask="sk-…cdef",
        )
        assert t["id"]
        assert t["key_mask"] == "sk-…cdef"

        rows = storage.list_targets(db)
        assert len(rows) == 1
        assert "api_key_enc" not in rows[0]  # list view never exposes ciphertext

        full = storage.get_target(db, t["id"])
        assert full is not None
        assert full["api_key_enc"] == "ciphertext"  # internal view keeps it

        assert storage.delete_target(db, t["id"]) is True
        assert storage.delete_target(db, t["id"]) is False
        assert storage.list_targets(db) == []

    def test_update_last_check(self, db):
        t = storage.upsert_target(
            db, name="r", base_url="https://a.com", api_key_enc=None, key_mask="—"
        )
        storage.update_target_last_check(db, t["id"], verdict="ok", score=87)
        row = storage.list_targets(db)[0]
        assert row["last_verdict"] == "ok"
        assert row["last_score"] == 87
        assert row["last_checked_at"] != "—"


class TestReports:
    def test_add_get_list(self, db):
        r = storage.add_report(
            db,
            kind="quick_check",
            target_name="ad-hoc",
            base_url="https://a.com",
            verdict="ok",
            latency_ms=123,
            summary={"models": ["m1"]},
        )
        fetched = storage.get_report(db, r["id"])
        assert fetched is not None
        assert fetched["summary"]["models"] == ["m1"]
        assert fetched["target"] == "ad-hoc"

        rows = storage.list_reports(db)
        assert len(rows) == 1
        assert "summary" not in rows[0]  # list view stays light

    def test_get_missing(self, db):
        assert storage.get_report(db, "nope") is None


class TestSettings:
    def test_defaults_none(self, db):
        assert storage.get_setting(db, "timeoutSeconds") is None

    def test_set_get(self, db):
        storage.set_setting(db, "timeoutSeconds", "20")
        assert storage.get_setting(db, "timeoutSeconds") == "20"
        storage.set_setting(db, "timeoutSeconds", "30")
        assert storage.get_setting(db, "timeoutSeconds") == "30"
