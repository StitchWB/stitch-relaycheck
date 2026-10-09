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

import threading
import time
from pathlib import Path
from typing import Any

from . import (
    client,
    crypto,
    fingerprint,
    holone_bridge,
    performance,
    scoring,
    security,
    storage,
    watering,
)

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
    if report["kind"] == "security":
        return {"text": _render_security_markdown(report)}
    if report["kind"] == "holone_scan":
        return {"text": _render_holone_markdown(report)}
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


#: Russian labels for security risk verdicts.
_SECURITY_LABELS_RU = {
    "clean": "clean — угроз не найдено",
    "low": "low — слабые сигналы",
    "medium": "medium — подозрительно",
    "high": "high — опасно",
    "critical": "critical — критично",
    "error": "error — техническая ошибка",
}


def _render_security_markdown(report: dict[str, Any]) -> str:
    """Render a security scan report: risk verdict, findings, IOC, TLS."""
    s = report.get("summary", {})
    verdict = report.get("verdict") or "—"
    label = _SECURITY_LABELS_RU.get(verdict, verdict)
    lines = [
        "# RelayCheck: security-скан",
        "",
        f"- **Дата:** {report['created_at']}",
        f"- **Цель:** {report['target']}",
        f"- **Модель:** `{s.get('model', '—')}`",
        f"- **Вердикт:** {label}",
        f"- **Risk score:** {report['score']} / 100 (0 = чисто)",
        f"- **Проб:** {s.get('probe_count', '—')} · **Длительность:** {report['latency_ms']} мс",
        f"- **Правил HoloNe:** v{s.get('rules_version', '?')} · скомпилировано {s.get('rules_compiled', '?')}"
        + (f" · пропущено {s.get('rules_skipped')}" if s.get("rules_skipped") else ""),
        "",
    ]

    findings = s.get("findings") or []
    if findings:
        lines += [
            "## Находки",
            "",
            "| Правило | Severity | Источник | Фрагмент |",
            "| --- | --- | --- | --- |",
        ]
        for f in findings[:30]:
            excerpt = str(f.get("excerpt", "")).replace("|", "\\|")
            lines.append(
                f"| `{f.get('rule_id', '?')}` | {f.get('severity', '?')} "
                f"| {f.get('source', '?')} | {excerpt[:100]} |"
            )
        if len(findings) > 30:
            lines.append(f"| … и ещё {len(findings) - 30} | | | |")
    else:
        lines += ["## Находки", "", "Ничего не найдено."]

    ioc = s.get("ioc") or {}
    tls = s.get("tls") or {}
    lines += [
        "",
        "## Сеть",
        "",
        f"- **Host:** `{ioc.get('host', '—')}` · блоклист: {ioc.get('blocklist_size', 0)} записей"
        + (f" · **совпадения:** {ioc.get('matches')}" if ioc.get("matches") else " · совпадений нет"),
    ]
    if tls.get("plain_http"):
        lines.append("- **TLS:** ❌ plain HTTP — ключ уходит незашифрованным")
    elif tls.get("ok"):
        lines += [
            f"- **TLS:** ✅ issuer={tls.get('issuer') or '—'} · до {tls.get('not_after') or '—'}"
            + ("" if tls.get("san_match", True) else " · ⚠️ SAN не покрывает host"),
        ]
    else:
        lines.append(f"- **TLS:** ⚠️ {tls.get('detail', 'недоступно')}")

    canary = s.get("canary") or []
    injection = s.get("injection") or []
    lines += [
        "",
        "## Probes",
        "",
        f"- **Canary:** {sum(1 for c in canary if c.get('ok'))}/{len(canary)} ответили"
        + (f" · ⚠️ tool_use без запроса: {sum(1 for c in canary if c.get('findings'))}" if any(c.get("findings") for c in canary) else ""),
        f"- **Injection:** {sum(1 for i in injection if i.get('triggered'))} сработали из {len(injection)}",
        "",
        "> Скан — эвристика, не гарантия: чистый результат не доказывает честность провайдера "
        "(пассивный слив промптов не детектится). Самый безопасный вариант — официальный endpoint.",
    ]
    return "\n".join(lines)


def _render_holone_markdown(report: dict[str, Any]) -> str:
    """Render an external holone deep-scan report."""
    s = report.get("summary", {})
    verdict = report.get("verdict") or "—"
    label = _SECURITY_LABELS_RU.get(verdict, verdict)
    lines = [
        "# RelayCheck: глубокий скан (внешний holone)",
        "",
        f"- **Дата:** {report['created_at']}",
        f"- **Цель:** {report['target']}",
        f"- **Модель:** `{s.get('model', '—')}`",
        f"- **Вердикт holone:** `{s.get('holone_verdict') or '—'}` → {label}",
        f"- **Risk score:** {report['score'] if report['score'] is not None else '—'} / 100",
        f"- **Официальный endpoint:** {'да' if s.get('official') else 'нет'}",
        f"- **Бинарь:** `{s.get('binary') or '—'}`",
    ]
    if s.get("summary"):
        lines += ["", str(s["summary"])]
    hits = s.get("blocklist_hits") or []
    if hits:
        lines += ["", "## Blocklist hits", ""] + [f"- `{h}`" for h in hits]
    recs = s.get("recommendations") or []
    if recs:
        lines += ["", "## Рекомендации holone", ""] + [f"- {r}" for r in recs[:10]]
    probes = s.get("probes") or []
    if probes:
        lines += ["", "## Probes", ""]
        for p in probes[:10]:
            lines.append(f"- `{p.get('name', '?')}`: {p.get('status', '?')}" +
                         (f" — findings: {p.get('findings')}" if p.get("findings") else ""))
    lines += [
        "",
        "> Внешний скан — тот же класс эвристики: чистый результат не доказывает честность. "
        "Для постоянной защиты направьте клиент через `holone proxy` (127.0.0.1:8787) "
        "или используйте встроенный HoloNe в Stitch AI Hub.",
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


# ── Watering + balance (Этап 3) ─────────────────────────────────────────────


def _resolve_endpoint(
    db_path: str,
    *,
    target_id: str,
    base_url: str,
    api_key: str,
) -> tuple[str, str, str, dict[str, Any] | None]:
    """Resolve (base_url, api_key, target_name) from a saved target or ad-hoc.

    Returns ``(..., None)`` on success or ``("", "", "", error_result)``.
    """
    target_name = "ad-hoc"
    if target_id:
        target = storage.get_target(db_path, target_id)
        if target is None:
            return "", "", "", {
                "success": False,
                "error_text": f"target {target_id!r} not found",
            }
        if not target.get("api_key_enc"):
            return "", "", "", {
                "success": False,
                "error_text": "у цели нет сохранённого ключа (persistKey был выключен)",
            }
        return (
            str(target["base_url"]),
            crypto.decrypt(str(target["api_key_enc"])),
            str(target["name"]),
            None,
        )
    if not base_url.strip() or not api_key.strip():
        raise ValueError("baseUrl and apiKey are required (or pass targetId)")
    return base_url.strip(), api_key.strip(), target_name, None


def detect_watering(
    db_path: str,
    *,
    model: str = "",
    target_id: str = "",
    base_url: str = "",
    api_key: str = "",
    reference_base_url: str = "",
    reference_api_key: str = "",
    reference_model: str = "",
) -> dict[str, Any]:
    """Watering check: are the relay's answers diluted/rewritten?

    Optional ``reference_*`` params enable answer-vs-answer comparison.
    """
    base_url, api_key, target_name, err = _resolve_endpoint(
        db_path, target_id=target_id, base_url=base_url, api_key=api_key
    )
    if err is not None:
        return err
    if not model.strip() and target_id:
        target = storage.get_target(db_path, target_id)
        if target and target.get("model"):
            model = str(target["model"]).strip()
    if not model.strip():
        raise ValueError("model is required for watering check")
    model = model.strip()

    base_url = client.normalize_base_url(base_url)
    timeout = _timeout(db_path)
    proto = client.detect_protocol(base_url, api_key, timeout)
    protocol = proto.get("protocol") or "openai"

    reference = None
    if reference_base_url.strip() and reference_api_key.strip():
        reference = {
            "base_url": client.normalize_base_url(reference_base_url),
            "api_key": reference_api_key.strip(),
            "model": reference_model.strip(),
        }

    result = watering.run_watering(
        base_url, api_key, model, protocol, timeout, reference
    )
    report = storage.add_report(
        db_path,
        kind="watering",
        target_id=target_id or None,
        target_name=target_name,
        base_url=base_url,
        verdict=result["verdict"],
        score=result["score"],
        latency_ms=result["duration_ms"],
        summary={
            "model": model,
            "protocol": protocol,
            "reasons": result["reasons"],
            "compared_with_reference": result["compared_with_reference"],
            "probe_count": result["probe_count"],
            "prompts": result["prompts"],
        },
    )
    return {
        "success": True,
        "score": result["score"],
        "verdict": result["verdict"],
        "reasons": result["reasons"],
        "model": model,
        "compared_with_reference": result["compared_with_reference"],
        "prompts": result["prompts"],
        "probe_count": result["probe_count"],
        "duration_ms": result["duration_ms"],
        "report_id": report["id"],
    }


def get_balance(
    db_path: str,
    *,
    target_id: str = "",
    base_url: str = "",
    api_key: str = "",
) -> dict[str, Any]:
    """Read-only balance/quota lookup against the relay dashboard."""
    base_url, api_key, target_name, err = _resolve_endpoint(
        db_path, target_id=target_id, base_url=base_url, api_key=api_key
    )
    if err is not None:
        return err
    base_url = client.normalize_base_url(base_url)
    result = client.get_balance(base_url, api_key, _timeout(db_path))
    report = storage.add_report(
        db_path,
        kind="balance",
        target_id=target_id or None,
        target_name=target_name,
        base_url=base_url,
        verdict="ok" if result.get("success") else "error",
        summary={"balance": result.get("balance"), "error_text": result.get("error_text")},
    )
    return {**result, "report_id": report["id"]}


# ── Security scan (Этап 4) ──────────────────────────────────────────────────


def scan_security(
    db_path: str,
    *,
    model: str = "",
    target_id: str = "",
    base_url: str = "",
    api_key: str = "",
) -> dict[str, Any]:
    """Security scan of an endpoint: canary, injection probes, IOC, TLS.

    ``model`` is optional — falls back to the target's default model, then to
    the first model the endpoint advertises.
    """
    base_url, api_key, target_name, err = _resolve_endpoint(
        db_path, target_id=target_id, base_url=base_url, api_key=api_key
    )
    if err is not None:
        return err
    if not model.strip() and target_id:
        target = storage.get_target(db_path, target_id)
        if target and target.get("model"):
            model = str(target["model"]).strip()

    base_url = client.normalize_base_url(base_url)
    timeout = _timeout(db_path)
    proto = client.detect_protocol(base_url, api_key, timeout)
    protocol = proto.get("protocol") or "openai"
    if not model.strip():
        models = proto.get("models") or []
        if models:
            model = str(models[0]["id"]).strip()
        else:
            return {
                "success": False,
                "error_text": "model is required (endpoint advertises no models)",
            }
    model = model.strip()

    result = security.run_security_scan(base_url, api_key, model, protocol, timeout)
    report = storage.add_report(
        db_path,
        kind="security",
        target_id=target_id or None,
        target_name=target_name,
        base_url=base_url,
        verdict=result["verdict"],
        score=result["risk_score"],
        latency_ms=result["duration_ms"],
        summary={
            "model": model,
            "protocol": protocol,
            "reasons": result["reasons"],
            "findings": result["findings"],
            "ioc": result["ioc"],
            "tls": result["tls"],
            "canary": result["canary"],
            "injection": result["injection"],
            "probe_count": result["probe_count"],
            "rules_version": result["rules_version"],
            "rules_compiled": result["rules_compiled"],
            "rules_skipped": result["rules_skipped"],
        },
    )
    return {
        "success": True,
        "verdict": result["verdict"],
        "risk_score": result["risk_score"],
        "reasons": result["reasons"],
        "findings": result["findings"],
        "ioc": result["ioc"],
        "tls": result["tls"],
        "canary": result["canary"],
        "injection": result["injection"],
        "probe_count": result["probe_count"],
        "duration_ms": result["duration_ms"],
        "report_id": report["id"],
    }


# ── Performance (Этап 5) ────────────────────────────────────────────────────


def measure_performance(
    db_path: str,
    *,
    model: str = "",
    target_id: str = "",
    base_url: str = "",
    api_key: str = "",
    repeats: int = 5,
) -> dict[str, Any]:
    """Measure latency / TTFT / TPS / error rate."""
    base_url, api_key, target_name, err = _resolve_endpoint(
        db_path, target_id=target_id, base_url=base_url, api_key=api_key
    )
    if err is not None:
        return err
    if not model.strip() and target_id:
        target = storage.get_target(db_path, target_id)
        if target and target.get("model"):
            model = str(target["model"]).strip()

    base_url = client.normalize_base_url(base_url)
    timeout = _timeout(db_path)
    proto = client.detect_protocol(base_url, api_key, timeout)
    protocol = proto.get("protocol") or "openai"
    if not model.strip():
        models = proto.get("models") or []
        if models:
            model = str(models[0]["id"]).strip()
        else:
            raise ValueError("model is required for performance measurement")
    model = model.strip()
    try:
        repeats = int(repeats)
    except (TypeError, ValueError):
        repeats = 5
    repeats = max(1, min(20, repeats))

    result = performance.measure(base_url, api_key, model, protocol, timeout, repeats=repeats)
    verdict = "ok" if result["ok_rate"] > 0 else "error"
    report = storage.add_report(
        db_path,
        kind="performance",
        target_id=target_id or None,
        target_name=target_name,
        base_url=base_url,
        verdict=verdict,
        score=result["perf_score"],
        latency_ms=result["duration_ms"],
        summary={"model": model, "protocol": protocol, **result},
    )
    return {
        "success": True,
        "verdict": verdict,
        **result,
        "score": result["perf_score"],
        "report_id": report["id"],
    }


# ── Full audit jobs (Этап 5) ────────────────────────────────────────────────

#: All audit layers, in execution order.
AUDIT_LAYERS = ("check", "fingerprint", "watering", "security", "performance", "balance")


def start_audit_job(
    db_path: str,
    *,
    model: str = "",
    target_id: str = "",
    base_url: str = "",
    api_key: str = "",
    layers: list[str] | None = None,
) -> dict[str, Any]:
    """Start a full audit in a background thread; returns ``job_id`` immediately.

    Use ``get_job`` / ``list_jobs`` to poll progress.  This is the UI-friendly
    path — the host's 30 s RPC timeout never applies to the audit itself.
    """
    base_url, api_key, target_name, err = _resolve_endpoint(
        db_path, target_id=target_id, base_url=base_url, api_key=api_key
    )
    if err is not None:
        return err
    if not model.strip() and target_id:
        target = storage.get_target(db_path, target_id)
        if target and target.get("model"):
            model = str(target["model"]).strip()

    base_url = client.normalize_base_url(base_url)
    timeout = _timeout(db_path)
    proto = client.detect_protocol(base_url, api_key, timeout)
    if not model.strip():
        models = proto.get("models") or []
        if models:
            model = str(models[0]["id"]).strip()
        else:
            raise ValueError("model is required (endpoint advertises no models)")
    model = model.strip()

    if layers is None:
        layers = list(AUDIT_LAYERS)
    unknown = [layer for layer in layers if layer not in AUDIT_LAYERS]
    if unknown:
        raise ValueError(f"unknown audit layers: {', '.join(unknown)}")
    layers = [layer for layer in AUDIT_LAYERS if layer in layers]  # canonical order

    job = storage.create_job(
        db_path, kind="audit", target_id=target_id or None, target_name=target_name
    )
    thread = threading.Thread(
        target=_run_audit_job,
        args=(db_path, job["id"], base_url, api_key, model, target_id, target_name, layers),
        daemon=True,
        name=f"relaycheck-audit-{job['id']}",
    )
    thread.start()
    return {"success": True, "job_id": job["id"], "status": "queued", "model": model}


def _run_audit_job(
    db_path: str,
    job_id: str,
    base_url: str,
    api_key: str,
    model: str,
    target_id: str,
    target_name: str,
    layers: list[str],
) -> None:
    """Background worker: runs audit layers sequentially, writes reports."""
    storage.update_job(db_path, job_id, status="running", progress="starting")
    results: dict[str, Any] = {}
    try:
        for idx, layer in enumerate(layers):
            storage.update_job(
                db_path, job_id, progress=f"{layer} ({idx + 1}/{len(layers)})"
            )
            if layer == "check":
                r = quick_check(db_path, base_url, api_key, model=model)
                results[layer] = {
                    "success": bool(r.get("success")),
                    "verdict": r.get("verdict", "ok" if r.get("success") else "error"),
                    "report_id": r.get("report_id"),
                }
            elif layer == "fingerprint":
                r = verify_model(
                    db_path, model=model, target_id=target_id,
                    base_url=base_url, api_key=api_key,
                )
                results[layer] = _slim(r)
            elif layer == "watering":
                r = detect_watering(
                    db_path, model=model, target_id=target_id,
                    base_url=base_url, api_key=api_key,
                )
                results[layer] = _slim(r)
            elif layer == "security":
                r = scan_security(
                    db_path, model=model, target_id=target_id,
                    base_url=base_url, api_key=api_key,
                )
                results[layer] = _slim(r)
            elif layer == "performance":
                r = measure_performance(
                    db_path, model=model, target_id=target_id,
                    base_url=base_url, api_key=api_key,
                )
                results[layer] = _slim(r)
            elif layer == "balance":
                r = get_balance(
                    db_path, target_id=target_id, base_url=base_url, api_key=api_key
                )
                results[layer] = {
                    "success": bool(r.get("success")),
                    "verdict": r.get("verdict"),
                    "report_id": r.get("report_id"),
                }

        trust = scoring.trust_from_layers(results)
        report = storage.add_report(
            db_path,
            kind="audit",
            target_id=target_id or None,
            target_name=target_name,
            base_url=base_url,
            verdict=trust["grade"],
            score=trust["score"],
            summary={"layers": results, "trust": trust, "model": model},
        )
        results["trust"] = trust
        results["report_id"] = report["id"]
        storage.update_job(db_path, job_id, status="done", progress="done", result=results)
    except Exception as exc:  # noqa: BLE001 — job must always reach a terminal state
        storage.update_job(
            db_path, job_id, status="error", progress="error", error_text=str(exc)
        )


def _slim(r: dict[str, Any]) -> dict[str, Any]:
    """Keep only the fields the trust score and job result need."""
    out = {
        "success": bool(r.get("success")),
        "verdict": r.get("verdict"),
        "report_id": r.get("report_id"),
    }
    if "score" in r:
        out["score"] = r["score"]
    if "risk_score" in r:
        out["risk_score"] = r["risk_score"]
    return out


def run_full_audit(
    db_path: str,
    *,
    model: str = "",
    target_id: str = "",
    base_url: str = "",
    api_key: str = "",
    layers: list[str] | None = None,
    wait_seconds: float = 120.0,
) -> dict[str, Any]:
    """Synchronous convenience wrapper: start a job and block until it finishes.

    Prefer ``start_audit_job`` + polling from the UI — this call can exceed
    the host's RPC timeout on slow endpoints.
    """
    started = start_audit_job(
        db_path, model=model, target_id=target_id,
        base_url=base_url, api_key=api_key, layers=layers,
    )
    if not started.get("success"):
        return started
    job_id = started["job_id"]
    deadline = time.monotonic() + wait_seconds
    while time.monotonic() < deadline:
        job = storage.get_job(db_path, job_id)
        if job is None:
            return {"success": False, "error_text": f"job {job_id!r} not found"}
        if job["status"] in ("done", "error"):
            return {"success": True, "job": job}
        time.sleep(0.5)
    return {
        "success": False,
        "error_text": "audit did not finish in time (job still running)",
        "job_id": job_id,
    }


def get_job(db_path: str, job_id: str) -> dict[str, Any]:
    if not job_id:
        raise ValueError("jobId is required")
    job = storage.get_job(db_path, job_id)
    if job is None:
        return {"success": False, "error_text": f"job {job_id!r} not found"}
    return {"success": True, "job": job}


def list_jobs(db_path: str, limit: int = 30) -> dict[str, Any]:
    try:
        limit = int(limit)
    except (TypeError, ValueError):
        limit = 30
    return {"rows": storage.list_jobs(db_path, limit=limit)}


# ── Target comparison (Этап 5) ──────────────────────────────────────────────


def _trust_for_target(db_path: str, target_id: str) -> dict[str, Any]:
    """Trust score from the target's latest per-layer reports."""
    kinds = ["fingerprint", "watering", "security", "performance", "balance"]
    latest = storage.latest_reports_by_kind(db_path, target_id, kinds)
    scores: dict[str, float | None] = {}
    for kind, report in latest.items():
        verdict = report.get("verdict")
        score = report.get("score")
        score = score if isinstance(score, (int, float)) else None
        if kind == "fingerprint":
            if verdict == "error":
                scores[kind] = 0.0
            elif verdict == "indeterminate" or score is None:
                scores[kind] = 50.0
            else:
                scores[kind] = float(score)
        elif kind in ("watering", "security"):
            if verdict == "error" or score is None:
                scores[kind] = 0.0
            else:
                scores[kind] = float(100 - score)
        elif kind == "performance":
            scores[kind] = 0.0 if verdict == "error" or score is None else float(score)
        elif kind == "balance":
            scores[kind] = 100.0 if verdict == "ok" else 40.0
    return scoring.trust_from_scores(scores)


def compare_targets(
    db_path: str, *, target_id_a: str, target_id_b: str
) -> dict[str, Any]:
    """Side-by-side comparison of two saved targets (latest reports + trust)."""
    if not target_id_a or not target_id_b:
        raise ValueError("targetIdA and targetIdB are required")
    out: dict[str, Any] = {}
    for label, tid in (("a", target_id_a), ("b", target_id_b)):
        target = storage.get_target(db_path, tid)
        if target is None:
            return {"success": False, "error_text": f"target {tid!r} not found"}
        kinds = ["fingerprint", "watering", "security", "performance", "balance"]
        latest = storage.latest_reports_by_kind(db_path, tid, kinds)
        layers = {
            kind: {"verdict": r["verdict"], "score": r["score"], "at": r["created_at"]}
            for kind, r in latest.items()
        }
        out[label] = {
            "target": {
                "id": tid,
                "name": target["name"],
                "base_url": target["base_url"],
                "model": target["model"],
            },
            "layers": layers,
            "trust": _trust_for_target(db_path, tid),
        }
    return {"success": True, **out}


# ── External holone deep scan (Этап 6) ──────────────────────────────────────


def holone_deep_scan(
    db_path: str,
    *,
    model: str = "",
    target_id: str = "",
    base_url: str = "",
    api_key: str = "",
) -> dict[str, Any]:
    """Deep security scan via the external ``holone`` binary (vanndh/holone).

    Optional: uses the bundled engine by default; this command runs the real
    ``holone scan`` (finds the binary in PATH or downloads it with sha256
    verification).  Note: the key is passed as a CLI argument to holone.
    """
    base_url, api_key, target_name, err = _resolve_endpoint(
        db_path, target_id=target_id, base_url=base_url, api_key=api_key
    )
    if err is not None:
        return err
    if not model.strip() and target_id:
        target = storage.get_target(db_path, target_id)
        if target and target.get("model"):
            model = str(target["model"]).strip()

    base_url = client.normalize_base_url(base_url)
    timeout = _timeout(db_path)
    if not model.strip():
        proto = client.detect_protocol(base_url, api_key, timeout)
        models = proto.get("models") or []
        if models:
            model = str(models[0]["id"]).strip()
        else:
            raise ValueError("model is required (endpoint advertises no models)")
    model = model.strip()

    data_dir = str(Path(db_path).parent) if db_path else ""
    result = holone_bridge.run_holone_scan(
        base_url, api_key, model, data_dir=data_dir, timeout=max(60.0, timeout * 4)
    )
    if not result.get("success"):
        return result
    report = storage.add_report(
        db_path,
        kind="holone_scan",
        target_id=target_id or None,
        target_name=target_name,
        base_url=base_url,
        verdict=result["verdict"],
        score=result.get("risk_score"),
        summary={
            "model": model,
            "holone_verdict": result.get("holone_verdict"),
            "summary": result.get("summary"),
            "summary_en": result.get("summary_en"),
            "recommendations": result.get("recommendations"),
            "official": result.get("official"),
            "blocklist_hits": result.get("blocklist_hits"),
            "probes": result.get("probes"),
            "tls": result.get("tls"),
            "holone": result.get("holone"),
            "binary": result.get("binary"),
        },
    )
    return {**result, "report_id": report["id"]}
