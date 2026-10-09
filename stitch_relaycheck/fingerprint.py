"""Model authenticity fingerprinting — «а правда ли заявленная модель за relay?».

Methodology (Этап 2, v1):

1. **Tokenizer probes (template-offset invariant).** We do NOT compare absolute
   ``prompt_tokens`` — relays wrap the prompt in their own chat template, which
   adds a constant offset.  Instead we measure the **delta** between a short and
   a long version of the same probe string; the template offset cancels out, and
   the delta is a stable fingerprint of the *tokenizer* (cl100k vs o200k vs
   SentencePiece differ measurably).
2. **Capability probes.** A fixed mini-set with known outcomes (arithmetic,
   strict JSON mode, one-line code style).  Checked against the profile.
3. **Consistency (split-half).** The same deterministic prompt twice at
   temperature=0 — a caching/rewriting proxy answers inconsistently.
4. **Metadata.** ``model`` echo, ``system_fingerprint`` presence, response id
   prefix (``chatcmpl-`` vs ``msg_``).
5. **Streaming shape.** SSE event ordering + TTFT (informational).

Verdicts: ``authentic`` / ``likely_authentic`` / ``indeterminate`` /
``suspicious`` / ``substituted`` / ``error`` (technical failure).

Everything is heuristics: the verdict always ships with per-probe evidence and
reasons, and unknown models honestly report ``indeterminate``.
"""

from __future__ import annotations

import json
import time
from collections.abc import Callable
from functools import lru_cache
from pathlib import Path
from typing import Any

from . import client

#: Verdict vocabulary (kept stable — the UI table renders these strings).
VERDICTS = (
    "authentic",
    "likely_authentic",
    "indeterminate",
    "suspicious",
    "substituted",
    "error",
)

#: Russian labels for verdicts (markdown reports are RU-first).
VERDICT_LABELS_RU: dict[str, str] = {
    "authentic": "authentic — оригинальная модель",
    "likely_authentic": "likely_authentic — похоже на оригинал",
    "indeterminate": "indeterminate — недостаточно данных",
    "suspicious": "suspicious — подозрительно",
    "substituted": "substituted — подмена модели",
    "error": "error — техническая ошибка",
}

_DATA_DIR = Path(__file__).resolve().parent.parent / "data"
_PROFILES_PATH = _DATA_DIR / "fingerprints.json"

#: Probe string pairs (short, long).  Deltas are measured between the two.
PROBE_PAIRS: list[dict[str, str]] = [
    {
        "id": "latin",
        "short": "The quick brown fox.",
        "long": (
            "The quick brown fox jumps over the lazy dog. "
            "Pack my box with five dozen liquor jugs."
        ),
    },
    {
        "id": "code",
        "short": "def f(): return 1",
        "long": (
            "def f():\n"
            "    total = 0\n"
            "    for i in range(100):\n"
            "        total += i * 2\n"
            "    return total\n"
        ),
    },
    {
        "id": "unicode",
        "short": "café",
        "long": "東京, Delhi, café, München, 👩🏽‍💻, naïve, zero-width: a​b",
    },
]


def _arithmetic_messages() -> list[dict[str, str]]:
    return [
        {
            "role": "user",
            "content": "Сколько будет 17 умножить на 23? Ответь одним числом.",
        }
    ]


def _check_arithmetic(text: str) -> bool:
    return "391" in text


def _check_json_mode(text: str) -> bool:
    try:
        payload = json.loads(text)
    except (ValueError, TypeError):
        return False
    return isinstance(payload, dict) and payload.get("ok") is True


def _check_code_style(text: str) -> bool:
    return "def is_even" in text and ("% 2" in text or "%2" in text)


#: Capability probe definitions.  ``response_format``/``check`` per probe.
CAPABILITY_PROBES: list[dict[str, Any]] = [
    {
        "id": "arithmetic",
        "messages": _arithmetic_messages(),
        "max_tokens": 16,
        "check": _check_arithmetic,
        "expect": True,
    },
    {
        "id": "json_mode",
        "messages": [
            {
                "role": "user",
                "content": (
                    "Ответь строго в формате JSON, объект с одним полем "
                    '"ok" значением true. Никакого другого текста.'
                ),
            }
        ],
        "max_tokens": 32,
        "response_format": {"type": "json_object"},
        "check": _check_json_mode,
        "expect": True,
    },
    {
        "id": "code_style",
        "messages": [
            {
                "role": "user",
                "content": (
                    "Напиши на Python функцию is_even(n) в одну строку, "
                    "с def и return. Только код."
                ),
            }
        ],
        "max_tokens": 64,
        "check": _check_code_style,
        "expect": True,
    },
]


# ── Fingerprint profile DB ──────────────────────────────────────────────────


@lru_cache(maxsize=1)
def load_profiles() -> dict[str, Any]:
    """Load the bundled fingerprint profile DB (``data/fingerprints.json``)."""
    try:
        raw = _PROFILES_PATH.read_text(encoding="utf-8")
        data = json.loads(raw)
    except (OSError, ValueError):
        return {"version": 0, "profiles": {}, "aliases": {}}
    if not isinstance(data, dict):
        return {"version": 0, "profiles": {}, "aliases": {}}
    data.setdefault("profiles", {})
    data.setdefault("aliases", {})
    return data


def find_profile(
    model_id: str, db: dict[str, Any]
) -> tuple[dict[str, Any] | None, str | None]:
    """Resolve a model id to a profile: exact → alias → family prefix.

    Returns ``(profile, profile_id)``; ``(None, None)`` when unknown.
    """
    profiles: dict[str, Any] = db.get("profiles", {})
    aliases: dict[str, str] = db.get("aliases", {})
    mid = model_id.strip().lower()

    if mid in profiles:
        return profiles[mid], mid
    canonical = aliases.get(mid)
    if canonical and canonical in profiles:
        return profiles[canonical], canonical
    # Family prefix: "claude-opus-4-8-2026-05-01" → "claude-opus-4-8".
    for pid in profiles:
        if mid.startswith(pid) or pid.startswith(mid):
            return profiles[pid], pid
    return None, None


# ── Probe runners ───────────────────────────────────────────────────────────


def _probe_tokenizer(
    base_url: str,
    api_key: str,
    model: str,
    protocol: str,
    timeout: float,
    profiles: dict[str, Any],
    profile: dict[str, Any] | None,
) -> dict[str, Any]:
    pairs_out: list[dict[str, Any]] = []
    matched = 0
    answered = 0
    expected_deltas: dict[str, dict[str, Any]] = {}
    if profile:
        expected_deltas = profile.get("tokenizer_deltas", {}) or {}

    for pair in PROBE_PAIRS:
        pid = pair["id"]
        counts: dict[str, int | None] = {}
        for variant in ("short", "long"):
            resp = client.chat_completion(
                base_url,
                api_key,
                model,
                [{"role": "user", "content": pair[variant]}],
                protocol=protocol,
                max_tokens=1,
                timeout=timeout,
            )
            usage = resp.get("usage") or {}
            counts[variant] = usage.get("prompt_tokens")
        observed = None
        if counts["short"] is not None and counts["long"] is not None:
            observed = counts["long"] - counts["short"]
            answered += 1

        exp = expected_deltas.get(pid)
        match: bool | None = None
        if observed is not None and exp and exp.get("expected") is not None:
            tolerance = float(exp.get("tolerance_pct", 30)) / 100.0
            match = abs(observed - float(exp["expected"])) <= float(exp["expected"]) * tolerance
            if match:
                matched += 1
        pairs_out.append(
            {
                "id": pid,
                "observed_delta": observed,
                "expected_delta": exp.get("expected") if exp else None,
                "tolerance_pct": exp.get("tolerance_pct") if exp else None,
                "match": match,
            }
        )
    ratio = (matched / len(expected_deltas)) if expected_deltas else None
    return {"pairs": pairs_out, "matched": matched, "answered": answered, "ratio": ratio}


def _probe_capability(
    base_url: str,
    api_key: str,
    model: str,
    protocol: str,
    timeout: float,
    profile: dict[str, Any] | None,
) -> dict[str, Any]:
    probes_out: list[dict[str, Any]] = []
    passed = 0
    expected_checks = 0
    capabilities: dict[str, bool] = (profile or {}).get("capabilities", {}) or {}

    for probe in CAPABILITY_PROBES:
        pid = probe["id"]
        if capabilities and pid in capabilities and not capabilities[pid]:
            # Profile says the model can't do this — skip, not a failure.
            probes_out.append({"id": pid, "ok": None, "detail": "not expected for this model"})
            continue
        expected_checks += 1
        resp = client.chat_completion(
            base_url,
            api_key,
            model,
            probe["messages"],
            protocol=protocol,
            max_tokens=int(probe.get("max_tokens", 32)),
            response_format=probe.get("response_format"),
            timeout=timeout,
        )
        if not resp.get("ok"):
            probes_out.append(
                {"id": pid, "ok": False, "detail": resp.get("error_text", "probe failed")}
            )
            continue
        check: Callable[[str], bool] = probe["check"]
        ok = bool(check(resp.get("text", "")))
        if ok:
            passed += 1
        probes_out.append({"id": pid, "ok": ok, "detail": "passed" if ok else "unexpected answer shape"})
    ratio = (passed / expected_checks) if expected_checks else None
    return {"probes": probes_out, "passed": passed, "expected": expected_checks, "ratio": ratio}


def _probe_consistency(
    base_url: str,
    api_key: str,
    model: str,
    protocol: str,
    timeout: float,
) -> dict[str, Any]:
    """Same deterministic prompt twice at temperature=0."""
    answers: list[str] = []
    ok_count = 0
    for _ in range(2):
        resp = client.chat_completion(
            base_url,
            api_key,
            model,
            _arithmetic_messages(),
            protocol=protocol,
            max_tokens=16,
            temperature=0.0,
            timeout=timeout,
        )
        if resp.get("ok"):
            ok_count += 1
            answers.append(resp.get("text", ""))
    identical = ok_count == 2 and answers[0] == answers[1]
    return {"identical": identical, "answered": ok_count}


def _probe_stream(
    base_url: str,
    api_key: str,
    model: str,
    protocol: str,
    timeout: float,
) -> dict[str, Any]:
    resp = client.chat_completion(
        base_url,
        api_key,
        model,
        [{"role": "user", "content": "Скажи одно слово: ок"}],
        protocol=protocol,
        max_tokens=4,
        stream=True,
        timeout=timeout,
    )
    if not resp.get("ok"):
        return {"ok": False, "detail": resp.get("error_text", "stream probe failed")}
    return {
        "ok": True,
        "ttft_ms": resp.get("ttft_ms"),
        "events": resp.get("sse_events", []),
        "latency_ms": resp.get("latency_ms"),
    }


# ── Aggregation ─────────────────────────────────────────────────────────────


def aggregate_verdict(result: dict[str, Any], profile: dict[str, Any] | None) -> dict[str, Any]:
    """Combine probe evidence into a verdict + score + human-readable reasons."""
    reasons: list[str] = []
    tok_ratio = result["tokenizer"]["ratio"]
    cap_ratio = result["capability"]["ratio"]
    consistent = result["consistency"]["identical"]
    echo = (result["metadata"].get("model_echo") or "").strip().lower()
    requested = result["model"].strip().lower()
    echo_mismatch = bool(echo) and echo != requested and not echo.startswith(requested)

    # Technical failure: every probe failed.
    if result["tokenizer"]["answered"] == 0 and result["capability"]["passed"] == 0:
        return {
            "verdict": "error",
            "score": 0,
            "reasons": ["все пробы завершились ошибкой — endpoint недоступен или отклоняет запросы"],
        }

    # Score: tokenizer 50%, capability 30%, consistency 20%.
    parts = []
    if tok_ratio is not None:
        parts.append(0.5 * tok_ratio)
    if cap_ratio is not None:
        parts.append(0.3 * cap_ratio)
    parts.append(0.2 * (1.0 if consistent else 0.0))
    weight = (0.5 if tok_ratio is not None else 0.0) + (0.3 if cap_ratio is not None else 0.0) + 0.2
    score = round(100 * (sum(parts) / weight)) if weight else None

    if profile is None:
        reasons.append("нет профиля отпечатка для этой модели — эвристики без сравнения с эталоном")
        if echo_mismatch:
            reasons.append(f"model echo {echo!r} не совпадает с запрошенной {requested!r}")
        return {"verdict": "indeterminate", "score": score, "reasons": reasons}

    if tok_ratio is not None and tok_ratio <= 0.34:
        reasons.append(
            f"дельты токенайзера совпали лишь на {tok_ratio:.0%} — другой токенайзер/семейство моделей"
        )
        return {"verdict": "substituted", "score": score, "reasons": reasons}
    if echo_mismatch:
        reasons.append(f"model echo {echo!r} не совпадает с запрошенной {requested!r}")
        return {"verdict": "suspicious", "score": score, "reasons": reasons}

    if tok_ratio is not None:
        reasons.append(f"совпадение токенайзера: {tok_ratio:.0%}")
    if cap_ratio is not None:
        reasons.append(f"capability-пробы: {cap_ratio:.0%}")
    reasons.append("консистентность (split-half): " + ("ок" if consistent else "ответы различаются"))

    if score is None:
        return {"verdict": "indeterminate", "score": None, "reasons": reasons}
    if score >= 85:
        verdict = "authentic"
    elif score >= 60:
        verdict = "likely_authentic"
    elif score >= 35:
        verdict = "suspicious"
    else:
        verdict = "substituted"
    return {"verdict": verdict, "score": score, "reasons": reasons}


# ── Full fingerprint run ────────────────────────────────────────────────────


def run_fingerprint(
    base_url: str,
    api_key: str,
    model: str,
    protocol: str,
    timeout: float,
    profiles: dict[str, Any] | None = None,
) -> dict[str, Any]:
    """Run the full probe battery against ``model`` on ``base_url``.

    Returns evidence + verdict.  Never raises on endpoint failures — probe
    errors are evidence.  ~11 requests, typically 6–20 s end to end.
    """
    profiles = profiles if profiles is not None else load_profiles()
    profile, profile_id = find_profile(model, profiles)
    started = time.monotonic()

    tokenizer = _probe_tokenizer(base_url, api_key, model, protocol, timeout, profiles, profile)
    capability = _probe_capability(base_url, api_key, model, protocol, timeout, profile)
    consistency = _probe_consistency(base_url, api_key, model, protocol, timeout)
    stream = _probe_stream(base_url, api_key, model, protocol, timeout)

    # Metadata from the first successful non-stream answer.
    metadata: dict[str, Any] = {"model_echo": None, "system_fingerprint": None, "id_prefix": None}
    meta_resp = client.chat_completion(
        base_url,
        api_key,
        model,
        [{"role": "user", "content": "Скажи одно слово: ок"}],
        protocol=protocol,
        max_tokens=4,
        timeout=timeout,
    )
    if meta_resp.get("ok"):
        metadata["model_echo"] = meta_resp.get("model_echo")
        metadata["system_fingerprint"] = meta_resp.get("system_fingerprint")
        rid = meta_resp.get("response_id")
        if isinstance(rid, str) and "-" in rid:
            metadata["id_prefix"] = rid.split("-", 1)[0]

    duration_ms = int((time.monotonic() - started) * 1000)
    result: dict[str, Any] = {
        "model": model,
        "profile_id": profile_id,
        "tokenizer": tokenizer,
        "capability": capability,
        "consistency": consistency,
        "stream": stream,
        "metadata": metadata,
        "duration_ms": duration_ms,
        "probe_count": 2 * len(PROBE_PAIRS)
        + len(CAPABILITY_PROBES)
        + 2
        + 1
        + 1,
    }
    verdict = aggregate_verdict(result, profile)
    result["verdict"] = verdict["verdict"]
    result["score"] = verdict["score"]
    result["reasons"] = verdict["reasons"]
    return result
