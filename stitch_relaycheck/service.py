"""Service layer for the stitch-relaycheck service plugin.

Business logic lives here — ``__main__.py`` handlers are thin wrappers
that parse params, call service functions, and return results.

Security contract:
- API keys are encrypted at rest (``crypto.py``, Fernet) and are NEVER
  written to logs, reports, or returned to the caller — only ``mask_key``
  output is exposed.
- Ad-hoc checks (``quick_check``) never persist the key at all
  (use-and-burn).
- Report summaries store metadata (counts, verdicts, latencies) and
  sanitized error strings — never keys.
"""

from __future__ import annotations

from typing import Any

from . import client, crypto, fingerprint, storage

#: Default plugin settings (overridable via ``set_settings``).
DEFAULT_SETTINGS: dict[str, Any] = {
    "timeoutSeconds": 15,
    "persistKeys": True,
}


def health_check() -> dict[str, Any]:
    """Return a health-check response."""
    return {"pong": True}


# ── Settings ────────────────────────────────────────────────────────────────


def get_settings(db_path: str) -> dict[str, Any]:
    """Return effective settings (defaults merged with stored overrides)."""
    out = dict(DEFAULT_SETTINGS)
    for key in DEFAULT_SETTINGS:
        stored = storage.get_setting(db_path, key)
        if stored is None:
            continue
        if isinstance(DEFAULT_SETTINGS[key], bool):
            out[key] = stored.lower() in ("1", "true", "yes")
        elif isinstance(DEFAULT_SETTINGS[key], int):
            try:
                out[key] = int(stored)
            except ValueError:
                pass
        else:
            out[key] = stored
    return out


def set_settings(db_path: str, patch: dict[str, Any]) -> dict[str, Any]:
    """Merge a settings patch; unknown keys raise ``ValueError``."""
    if not isinstance(patch, dict):
        raise ValueError("settings patch must be an object")
    unknown = sorted(set(patch) - set(DEFAULT_SETTINGS))
    if unknown:
        raise ValueError(f"unknown settings keys: {', '.join(unknown)}")
    for key, value in patch.items():
        default = DEFAULT_SETTINGS[key]
        if isinstance(default, bool):
            if not isinstance(value, bool):
                raise ValueError(f"{key} must be a boolean")
            storage.set_setting(db_path, key, "true" if value else "false")
        elif isinstance(default, int):
            try:
                ivalue = int(value)
            except (TypeError, ValueError):
                raise ValueError(f"{key} must be an integer") from None
            if ivalue <= 0:
                raise ValueError(f"{key} must be positive")
            storage.set_setting(db_path, key, str(ivalue))
        else:
            storage.set_setting(db_path, key, str(value))
    return get_settings(db_path)


def _timeout(db_path: str) -> float:
    return float(get_settings(db_path).get("timeoutSeconds", 15))


# ── Quick endpoint check ────────────────────────────────────────────────────


def quick_check(
    db_path: str,
    base_url: str,
    api_key: str,
    model: str = "",
) -> dict[str, Any]:
    """Ad-hoc endpoint check (use-and-burn: the key is never persisted).

    Returns the client result plus ``report_id`` of the stored history row.
    """
    result = client.quick_check(
        base_url, api_key, model=model, timeout=_timeout(db_path)
    )
    report = storage.add_report(
        db_path,
        kind="quick_check",
        target_name="ad-hoc",
        base_url=client.normalize_base_url(base_url),
        verdict="ok" if result.get("success") else "error",
        latency_ms=result.get("latency_ms"),
        summary=_sanitize_summary(result, api_key),
    )
    result["report_id"] = report["id"]
    return result


def _sanitize_summary(result: dict[str, Any], api_key: str) -> dict[str, Any]:
    """Reduce a client result to a storable, key-free summary."""
    summary: dict[str, Any] = {
        "success": bool(result.get("success")),
        "protocol": result.get("protocol"),
        "normalized_url": result.get("normalized_url"),
        "model_count": result.get("model_count"),
        "latency_ms": result.get("latency_ms"),
        "model_fuzzy_matches": result.get("model_fuzzy_matches", []),
        "models": client.model_ids(result.get("models", [])),
    }
    if result.get("model_available") is not None:
        summary["model_available"] = bool(result["model_available"])
    if result.get("error_text"):
        summary["error_text"] = client.redact(str(result["error_text"]), api_key)
    if result.get("model_hint"):
        summary["model_hint"] = result["model_hint"]
    return summary


# ── Targets (saved relays) ──────────────────────────────────────────────────


def save_target(
    db_path: str,
    *,
    name: str,
    base_url: str,
    api_key: str,
    note: str = "",
    model: str = "",
    persist_key: bool = True,
) -> dict[str, Any]:
    """Save a relay target.  The key is Fernet-encrypted before storage.

    With ``persist_key=False`` only the URL/name are stored (the target is
    a placeholder for future manual checks).
    """
    if not name.strip():
        raise ValueError("name is required")
    if not base_url.strip():
        raise ValueError("baseUrl is required")

    normalized = client.normalize_base_url(base_url)
    api_key_enc: str | None = None
    key_mask = "—"
    if persist_key:
        if not api_key.strip():
            raise ValueError("apiKey is required when persistKey is true")
        api_key_enc = crypto.encrypt(api_key.strip())
        key_mask = client.mask_key(api_key)

    target = storage.upsert_target(
        db_path,
        name=name.strip(),
        base_url=normalized,
        api_key_enc=api_key_enc,
        key_mask=key_mask,
        note=note.strip(),
        model=model.strip(),
    )
    return {"success": True, "target": target}


def list_targets(db_path: str) -> dict[str, Any]:
    """List saved targets (table source — wraps rows under ``rows``)."""
    return {"rows": storage.list_targets(db_path)}


def delete_target(db_path: str, target_id: str) -> dict[str, Any]:
    """Delete a target by id."""
    if not target_id:
        raise ValueError("id is required")
    removed = storage.delete_target(db_path, target_id)
    return {"success": removed}


def check_target(db_path: str, target_id: str) -> dict[str, Any]:
    """Run a quick check against a saved target (decrypts the key in memory)."""
    if not target_id:
        raise ValueError("id is required")
    target = storage.get_target(db_path, target_id)
    if target is None:
        return {"success": False, "error_text": f"target {target_id!r} not found"}
    if not target.get("api_key_enc"):
        return {
            "success": False,
            "error_text": "у цели нет сохранённого ключа (persistKey был выключен)",
        }

    api_key = crypto.decrypt(str(target["api_key_enc"]))
    result = client.quick_check(
        str(target["base_url"]), api_key, timeout=_timeout(db_path)
    )
    storage.update_target_last_check(
        db_path,
        target_id,
        verdict="ok" if result.get("success") else "error",
        score=None,
    )
    report = storage.add_report(
        db_path,
        kind="target_check",
        target_id=target_id,
        target_name=str(target["name"]),
        base_url=str(target["base_url"]),
        verdict="ok" if result.get("success") else "error",
        latency_ms=result.get("latency_ms"),
        summary=_sanitize_summary(result, api_key),
    )
    result["report_id"] = report["id"]
    return result


# ── Reports / history ───────────────────────────────────────────────────────


def list_reports(db_path: str, limit: int = 50) -> dict[str, Any]:
    """List recent reports (table source — wraps rows under ``rows``)."""
    return {"rows": storage.list_reports(db_path, limit=limit)}


def get_report(db_path: str, report_id: str) -> dict[str, Any]:
    """Return one report by id (``latest`` resolves to the newest row)."""
    if not report_id:
        raise ValueError("reportId is required")
    if report_id == "latest":
        rows = storage.list_reports(db_path, limit=1)
        if not rows:
            return {"success": False, "error_text": "no reports yet"}
        report = storage.get_report(db_path, rows[0]["id"])
    else:
        report = storage.get_report(db_path, report_id)
    if report is None:
        return {"success": False, "error_text": f"report {report_id!r} not found"}
    return {"success": True, "report": report}


def get_report_markdown(db_path: str, report_id: str = "latest") -> dict[str, Any]:
    """Render a report as markdown (for the ``markdown`` UI node)."""
    outcome = get_report(db_path, report_id)
    if not outcome.get("success"):
        return {"text": f"_{outcome.get('error_text', 'no report')}_"}
    report = outcome["report"]
    if report["kind"] == "fingerprint":
        return {"text": _render_fingerprint_markdown(report)}
    summary = report.get("summary", {})

    lines = [
        f"# RelayCheck: {report['kind']}",
        "",
        f"- **Дата:** {report['created_at']}",
        f"- **Цель:** {report['target']}",
        f"- **Вердикт:** {report['verdict']}",
        f"- **Скор:** {report['score']}",
        f"- **Латентность:** {report['latency_ms']} мс",
    ]
    if summary.get("protocol"):
        lines.append(f"- **Протокол:** {summary['protocol']}")
    if summary.get("model_count") is not None:
        lines.append(f"- **Моделей:** {summary['model_count']}")
    if "model_available" in summary:
        avail = "да" if summary["model_available"] else "нет"
        lines.append(f"- **Модель доступна:** {avail}")
        if summary.get("model_fuzzy_matches"):
            lines.append(
                "- **Похожие имена:** "
                + ", ".join(f"`{m}`" for m in summary["model_fuzzy_matches"])
            )
    if summary.get("error_text"):
        lines += ["", f"> **Ошибка:** {summary['error_text']}"]
    models = summary.get("models") or []
    if models:
        lines += ["", "## Модели", ""]
        lines += [f"- `{m}`" for m in models[:50]]
        if len(models) > 50:
            lines.append(f"- …и ещё {len(models) - 50}")
    return {"text": "\n".join(lines)}


def _render_fingerprint_markdown(report: dict[str, Any]) -> str:
    """Render a fingerprint report: verdict, evidence tables, reasons."""
    s = report.get("summary", {})
    verdict = report.get("verdict") or "—"
    label = fingerprint.VERDICT_LABELS_RU.get(verdict, verdict)
    lines = [
        "# RelayCheck: fingerprint модели",
        "",
        f"- **Дата:** {report['created_at']}",
        f"- **Цель:** {report['target']}",
        f"- **Модель (заявлена):** `{s.get('model', '—')}`",
        f"- **Профиль:** {s.get('profile_id') or 'нет в базе — эвристики'}",
        f"- **Вердикт:** {label}",
        f"- **Скор:** {report['score']}",
        f"- **Проб:** {s.get('probe_count', '—')} · **Длительность:** {report['latency_ms']} мс",
        "",
        "## Почему такой вердикт",
        "",
    ]
    reasons = s.get("reasons") or []
    lines += [f"- {r}" for r in reasons] or ["- (нет причин)"]

    tok = s.get("tokenizer") or {}
    pairs = tok.get("pairs") or []
    if pairs:
        lines += [
            "",
            "## Tokenizer deltas (инвариантны к chat-template relay)",
            "",
            "| Проба | Δ токенов (наблюдение) | Ожидается | Совпадение |",
            "| --- | --- | --- | --- |",
        ]
        for p in pairs:
            match = p.get("match")
            match_txt = {True: "✅", False: "❌", None: "—"}[match]
            lines.append(
                f"| {p['id']} | {p.get('observed_delta')} | "
                f"{p.get('expected_delta')}±{p.get('tolerance_pct')}% | {match_txt} |"
            )

    cap = s.get("capability") or {}
    probes = cap.get("probes") or []
    if probes:
        lines += ["", "## Capability-пробы", ""]
        for p in probes:
            ok = p.get("ok")
            mark = {True: "✅", False: "❌", None: "—"}[ok]
            lines.append(f"- {mark} `{p['id']}` — {p.get('detail', '')}")

    cons = s.get("consistency") or {}
    stream = s.get("stream") or {}
    meta = s.get("metadata") or {}
    lines += [
        "",
        "## Прочее",
        "",
        f"- **Split-half consistency:** {'одинаковые ответы ✅' if cons.get('identical') else 'ответы различаются ⚠️' if cons.get('answered') else 'нет данных'}",
        f"- **Stream:** {'ок' if stream.get('ok') else stream.get('detail', 'ошибка')}"
        + (f" · TTFT {stream.get('ttft_ms')} мс" if stream.get('ttft_ms') is not None else ""),
        f"- **Model echo:** `{meta.get('model_echo') or '—'}`",
        f"- **system_fingerprint:** `{meta.get('system_fingerprint') or '—'}`",
        f"- **ID prefix:** `{meta.get('id_prefix') or '—'}`",
        "",
        "> Вердикт — эвристика, не доказательство. Ручная проверка на реальных задачах обязательна.",
    ]
    return "\n".join(lines)


def refresh(db_path: str) -> dict[str, Any]:
    """No-op used by table rowActions to force a refetch of the source table."""
    return {"ok": True}


# ── Model fingerprint (Этап 2) ──────────────────────────────────────────────


def verify_model(
    db_path: str,
    *,
    model: str,
    target_id: str = "",
    base_url: str = "",
    api_key: str = "",
) -> dict[str, Any]:
    """Fingerprint a model behind a relay: is it really the claimed model?

    Either ``target_id`` (saved target) or ad-hoc ``base_url`` + ``api_key``.
    Runs the probe battery (tokenizer deltas, capability, consistency,
    streaming shape, metadata) and returns verdict + score + evidence.
    Writes a ``fingerprint`` report and stamps the target row.
    """
    target_name = "ad-hoc"
    if target_id:
        target = storage.get_target(db_path, target_id)
        if target is None:
            return {"success": False, "error_text": f"target {target_id!r} not found"}
        if not target.get("api_key_enc"):
            return {
                "success": False,
                "error_text": "у цели нет сохранённого ключа (persistKey был выключен)",
            }
        base_url = str(target["base_url"])
        api_key = crypto.decrypt(str(target["api_key_enc"]))
        target_name = str(target["name"])
        if not model.strip() and target.get("model"):
            model = str(target["model"]).strip()
    else:
        if not base_url.strip() or not api_key.strip():
            raise ValueError("baseUrl and apiKey are required (or pass targetId)")
    if not model.strip():
        raise ValueError("model is required for fingerprint")
    model = model.strip()

    base_url = client.normalize_base_url(base_url)
    timeout = _timeout(db_path)

    proto = client.detect_protocol(base_url, api_key, timeout)
    protocol = proto.get("protocol") or "openai"

    fp = fingerprint.run_fingerprint(base_url, api_key, model, protocol, timeout)
    verdict = fp["verdict"]
    score = fp["score"]

    summary = {
        "model": model,
        "protocol": protocol,
        "profile_id": fp.get("profile_id"),
        "tokenizer": fp["tokenizer"],
        "capability": fp["capability"],
        "consistency": fp["consistency"],
        "stream": fp["stream"],
        "metadata": fp["metadata"],
        "reasons": fp["reasons"],
        "probe_count": fp["probe_count"],
    }
    report = storage.add_report(
        db_path,
        kind="fingerprint",
        target_id=target_id or None,
        target_name=target_name,
        base_url=base_url,
        verdict=verdict,
        score=score,
        latency_ms=fp["duration_ms"],
        summary=summary,
    )
    if target_id:
        storage.update_target_last_check(db_path, target_id, verdict=verdict, score=score)

    return {
        "success": True,
        "verdict": verdict,
        "score": score,
        "model": model,
        "profile_id": fp.get("profile_id"),
        "reasons": fp["reasons"],
        "tokenizer": fp["tokenizer"],
        "capability": fp["capability"],
        "consistency": fp["consistency"],
        "stream": fp["stream"],
        "metadata": fp["metadata"],
        "probe_count": fp["probe_count"],
        "duration_ms": fp["duration_ms"],
        "report_id": report["id"],
    }
