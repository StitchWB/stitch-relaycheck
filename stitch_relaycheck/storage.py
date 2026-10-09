"""SQLite storage for the stitch-relaycheck service plugin.

The plugin owns its SQLite database at ``db_path`` (received in the
``plugin.init`` handshake).  Tables are created on ``_migrate_db``.

Schema (v1):
  - targets(id, name, base_url, api_key_enc, key_mask, note, is_reference,
            last_verdict, last_score, last_checked_at, created_at, updated_at)
  - reports(id, target_id, target_name, base_url, kind, verdict, score,
            latency_ms, summary_json, created_at)
  - settings(k, v)

API keys are stored ONLY as Fernet ciphertext (``api_key_enc``); the
plaintext key never touches this database.  ``key_mask`` is a display-safe
mask (``sk-…abcd``).
"""

# _generated_by: stitch_plugin_tools scaffold v3

# _generated_by: stitch_plugin_tools scaffold v3 (schema authored by RelayCheck)

from __future__ import annotations

import json
import uuid
from datetime import UTC, datetime
from typing import Any

try:
    from autoreg.plugin.helpers import connect_plugin_db
except ImportError:
    from ._vendor.plugin_helpers import connect_plugin_db


def _utcnow() -> str:
    return datetime.now(UTC).strftime("%Y-%m-%d %H:%M:%S")


def _new_id() -> str:
    return uuid.uuid4().hex[:12]


def migrate(db_path: str) -> None:
    """Create tables if they do not exist (raw_sql migration)."""
    conn = connect_plugin_db(db_path)
    try:
        conn.execute(
            """
            CREATE TABLE IF NOT EXISTS targets (
                id TEXT PRIMARY KEY,
                name TEXT NOT NULL,
                base_url TEXT NOT NULL,
                api_key_enc TEXT,
                key_mask TEXT NOT NULL DEFAULT '',
                note TEXT NOT NULL DEFAULT '',
                model TEXT NOT NULL DEFAULT '',
                is_reference INTEGER NOT NULL DEFAULT 0,
                last_verdict TEXT,
                last_score INTEGER,
                last_checked_at TEXT,
                created_at TEXT NOT NULL,
                updated_at TEXT NOT NULL
            )
            """
        )
        # v2 migration: add the model column to databases created by v1.
        cols = {r["name"] for r in conn.execute("PRAGMA table_info(targets)").fetchall()}
        if "model" not in cols:
            conn.execute("ALTER TABLE targets ADD COLUMN model TEXT NOT NULL DEFAULT ''")
        conn.execute(
            """
            CREATE TABLE IF NOT EXISTS reports (
                id TEXT PRIMARY KEY,
                target_id TEXT,
                target_name TEXT NOT NULL DEFAULT '',
                base_url TEXT NOT NULL DEFAULT '',
                kind TEXT NOT NULL,
                verdict TEXT,
                score INTEGER,
                latency_ms INTEGER,
                summary_json TEXT NOT NULL DEFAULT '{}',
                created_at TEXT NOT NULL
            )
            """
        )
        conn.execute(
            """
            CREATE TABLE IF NOT EXISTS settings (
                k TEXT PRIMARY KEY,
                v TEXT NOT NULL
            )
            """
        )
        conn.execute(
            """
            CREATE TABLE IF NOT EXISTS jobs (
                id TEXT PRIMARY KEY,
                target_id TEXT,
                target_name TEXT NOT NULL DEFAULT '',
                kind TEXT NOT NULL,
                status TEXT NOT NULL,
                progress TEXT NOT NULL DEFAULT '',
                result_json TEXT NOT NULL DEFAULT '{}',
                error_text TEXT,
                created_at TEXT NOT NULL,
                finished_at TEXT
            )
            """
        )
        conn.commit()
    finally:
        conn.close()


# ── Targets ─────────────────────────────────────────────────────────────────


def upsert_target(
    db_path: str,
    *,
    name: str,
    base_url: str,
    api_key_enc: str | None,
    key_mask: str,
    note: str = "",
    model: str = "",
    is_reference: bool = False,
    target_id: str | None = None,
) -> dict[str, Any]:
    """Insert or update a target; returns the stored row (no secrets)."""
    conn = connect_plugin_db(db_path)
    try:
        now = _utcnow()
        tid = target_id or _new_id()
        existing = conn.execute(
            "SELECT id FROM targets WHERE id = ?", (tid,)
        ).fetchone()
        if existing is None:
            conn.execute(
                """
                INSERT INTO targets (
                    id, name, base_url, api_key_enc, key_mask, note, model,
                    is_reference, created_at, updated_at
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    tid,
                    name,
                    base_url,
                    api_key_enc,
                    key_mask,
                    note,
                    model,
                    1 if is_reference else 0,
                    now,
                    now,
                ),
            )
        else:
            conn.execute(
                """
                UPDATE targets SET
                    name = ?, base_url = ?, api_key_enc = ?, key_mask = ?,
                    note = ?, model = ?, is_reference = ?, updated_at = ?
                WHERE id = ?
                """,
                (
                    name,
                    base_url,
                    api_key_enc,
                    key_mask,
                    note,
                    model,
                    1 if is_reference else 0,
                    now,
                    tid,
                ),
            )
        conn.commit()
        row = conn.execute("SELECT * FROM targets WHERE id = ?", (tid,)).fetchone()
        return _target_row_to_dict(row)
    finally:
        conn.close()


def get_target(db_path: str, target_id: str) -> dict[str, Any] | None:
    """Return one target row (includes ``api_key_enc`` — internal use only)."""
    conn = connect_plugin_db(db_path)
    try:
        row = conn.execute(
            "SELECT * FROM targets WHERE id = ?", (target_id,)
        ).fetchone()
        return dict(row) if row is not None else None
    finally:
        conn.close()


def list_targets(db_path: str) -> list[dict[str, Any]]:
    """Return all targets ordered by last check (newest first)."""
    conn = connect_plugin_db(db_path)
    try:
        rows = conn.execute(
            """
            SELECT id, name, base_url, key_mask, note, model, is_reference,
                   last_verdict, last_score, last_checked_at, created_at
            FROM targets
            ORDER BY last_checked_at DESC, created_at DESC
            """
        ).fetchall()
        return [_target_row_to_dict(r) for r in rows]
    finally:
        conn.close()


def delete_target(db_path: str, target_id: str) -> bool:
    """Delete a target; returns True when a row was removed."""
    conn = connect_plugin_db(db_path)
    try:
        cur = conn.execute("DELETE FROM targets WHERE id = ?", (target_id,))
        conn.commit()
        return cur.rowcount > 0
    finally:
        conn.close()


def update_target_last_check(
    db_path: str,
    target_id: str,
    *,
    verdict: str | None,
    score: int | None,
) -> None:
    """Stamp the result of the latest check onto the target row."""
    conn = connect_plugin_db(db_path)
    try:
        conn.execute(
            """
            UPDATE targets SET
                last_verdict = ?, last_score = ?,
                last_checked_at = ?, updated_at = ?
            WHERE id = ?
            """,
            (verdict, score, _utcnow(), _utcnow(), target_id),
        )
        conn.commit()
    finally:
        conn.close()


def _target_row_to_dict(row: Any) -> dict[str, Any]:
    return {
        "id": row["id"],
        "name": row["name"],
        "base_url": row["base_url"],
        "key_mask": row["key_mask"],
        "note": row["note"],
        "model": row["model"],
        "is_reference": bool(row["is_reference"]),
        "last_verdict": row["last_verdict"] or "—",
        "last_score": row["last_score"] if row["last_score"] is not None else "—",
        "last_checked_at": row["last_checked_at"] or "—",
        "created_at": row["created_at"],
    }


# ── Reports ─────────────────────────────────────────────────────────────────


def add_report(
    db_path: str,
    *,
    kind: str,
    target_id: str | None = None,
    target_name: str = "",
    base_url: str = "",
    verdict: str | None = None,
    score: int | None = None,
    latency_ms: int | None = None,
    summary: dict[str, Any] | None = None,
) -> dict[str, Any]:
    """Persist a check report; returns the stored row."""
    conn = connect_plugin_db(db_path)
    try:
        rid = _new_id()
        conn.execute(
            """
            INSERT INTO reports (
                id, target_id, target_name, base_url, kind,
                verdict, score, latency_ms, summary_json, created_at
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                rid,
                target_id,
                target_name,
                base_url,
                kind,
                verdict,
                score,
                latency_ms,
                json.dumps(summary or {}, ensure_ascii=False),
                _utcnow(),
            ),
        )
        conn.commit()
        row = conn.execute("SELECT * FROM reports WHERE id = ?", (rid,)).fetchone()
        return _report_row_to_dict(row)
    finally:
        conn.close()


def get_report(db_path: str, report_id: str) -> dict[str, Any] | None:
    """Return one report (``summary`` decoded from JSON)."""
    conn = connect_plugin_db(db_path)
    try:
        row = conn.execute(
            "SELECT * FROM reports WHERE id = ?", (report_id,)
        ).fetchone()
        return _report_row_to_dict(row) if row is not None else None
    finally:
        conn.close()


def list_reports(db_path: str, limit: int = 50) -> list[dict[str, Any]]:
    """Return recent reports (newest first)."""
    conn = connect_plugin_db(db_path)
    try:
        rows = conn.execute(
            """
            SELECT id, target_id, target_name, base_url, kind,
                   verdict, score, latency_ms, created_at
            FROM reports
            ORDER BY created_at DESC
            LIMIT ?
            """,
            (limit,),
        ).fetchall()
        return [_report_row_to_dict(r) for r in rows]
    finally:
        conn.close()


def _report_row_to_dict(row: Any) -> dict[str, Any]:
    out: dict[str, Any] = {
        "id": row["id"],
        "target_id": row["target_id"],
        "target": row["target_name"] or row["base_url"] or "—",
        "base_url": row["base_url"],
        "kind": row["kind"],
        "verdict": row["verdict"] or "—",
        "score": row["score"] if row["score"] is not None else "—",
        "latency_ms": row["latency_ms"] if row["latency_ms"] is not None else "—",
        "created_at": row["created_at"],
    }
    if "summary_json" in row.keys():
        try:
            out["summary"] = json.loads(row["summary_json"])
        except (json.JSONDecodeError, TypeError):
            out["summary"] = {}
    return out


# ── Settings ────────────────────────────────────────────────────────────────


def get_setting(db_path: str, key: str) -> str | None:
    conn = connect_plugin_db(db_path)
    try:
        row = conn.execute(
            "SELECT v FROM settings WHERE k = ?", (key,)
        ).fetchone()
        return row["v"] if row is not None else None
    finally:
        conn.close()


def set_setting(db_path: str, key: str, value: str) -> None:
    conn = connect_plugin_db(db_path)
    try:
        conn.execute(
            """
            INSERT INTO settings (k, v) VALUES (?, ?)
            ON CONFLICT(k) DO UPDATE SET v = excluded.v
            """,
            (key, value),
        )
        conn.commit()
    finally:
        conn.close()


# ── Jobs (long-running audits) ──────────────────────────────────────────────


def create_job(
    db_path: str,
    *,
    kind: str,
    target_id: str | None = None,
    target_name: str = "",
) -> dict[str, Any]:
    conn = connect_plugin_db(db_path)
    try:
        jid = _new_id()
        conn.execute(
            """
            INSERT INTO jobs (id, target_id, target_name, kind, status, created_at)
            VALUES (?, ?, ?, ?, 'queued', ?)
            """,
            (jid, target_id, target_name, kind, _utcnow()),
        )
        conn.commit()
        row = conn.execute("SELECT * FROM jobs WHERE id = ?", (jid,)).fetchone()
        return _job_row_to_dict(row)
    finally:
        conn.close()


def get_job(db_path: str, job_id: str) -> dict[str, Any] | None:
    conn = connect_plugin_db(db_path)
    try:
        row = conn.execute("SELECT * FROM jobs WHERE id = ?", (job_id,)).fetchone()
        return _job_row_to_dict(row) if row is not None else None
    finally:
        conn.close()


def list_jobs(db_path: str, limit: int = 30) -> list[dict[str, Any]]:
    conn = connect_plugin_db(db_path)
    try:
        rows = conn.execute(
            "SELECT * FROM jobs ORDER BY created_at DESC LIMIT ?", (limit,)
        ).fetchall()
        return [_job_row_to_dict(r) for r in rows]
    finally:
        conn.close()


def update_job(
    db_path: str,
    job_id: str,
    *,
    status: str | None = None,
    progress: str | None = None,
    result: dict[str, Any] | None = None,
    error_text: str | None = None,
) -> None:
    conn = connect_plugin_db(db_path)
    try:
        sets = []
        params: list[Any] = []
        if status is not None:
            sets.append("status = ?")
            params.append(status)
        if progress is not None:
            sets.append("progress = ?")
            params.append(progress)
        if result is not None:
            sets.append("result_json = ?")
            params.append(json.dumps(result, ensure_ascii=False))
        if error_text is not None:
            sets.append("error_text = ?")
            params.append(error_text)
        if status in ("done", "error"):
            sets.append("finished_at = ?")
            params.append(_utcnow())
        if not sets:
            return
        params.append(job_id)
        conn.execute(f"UPDATE jobs SET {', '.join(sets)} WHERE id = ?", params)
        conn.commit()
    finally:
        conn.close()


def _job_row_to_dict(row: Any) -> dict[str, Any]:
    out: dict[str, Any] = {
        "id": row["id"],
        "target_id": row["target_id"],
        "target": row["target_name"] or "—",
        "kind": row["kind"],
        "status": row["status"],
        "progress": row["progress"],
        "error_text": row["error_text"],
        "created_at": row["created_at"],
        "finished_at": row["finished_at"],
    }
    try:
        out["result"] = json.loads(row["result_json"])
    except (json.JSONDecodeError, TypeError):
        out["result"] = {}
    return out


# ── Latest report per kind (for target comparison) ──────────────────────────


def latest_reports_by_kind(
    db_path: str, target_id: str, kinds: list[str]
) -> dict[str, dict[str, Any]]:
    """Return {kind: latest report row} for a target."""
    conn = connect_plugin_db(db_path)
    try:
        out: dict[str, dict[str, Any]] = {}
        for kind in kinds:
            row = conn.execute(
                """
                SELECT * FROM reports
                WHERE target_id = ? AND kind = ?
                ORDER BY created_at DESC LIMIT 1
                """,
                (target_id, kind),
            ).fetchone()
            if row is not None:
                out[kind] = _report_row_to_dict(row)
        return out
    finally:
        conn.close()
