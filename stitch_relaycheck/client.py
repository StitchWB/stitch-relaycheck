"""HTTP client layer for RelayCheck — talks to user-supplied AI endpoints.

Design rules:
- **Local only.** Every request goes directly from the user's machine to
  the endpoint the user typed.  Nothing is sent to Stitch servers or any
  third party.  The API key is used against the target endpoint only.
- **Defensive parsing.** Relay stations run every flavor of software
  (one-api, new-api, LiteLLM, vLLM, Ollama, OpenRouter-style aggregators…),
  so model-list parsing tolerates OpenAI-, Anthropic- and Google-flavored
  shapes and never raises on unexpected payloads.
- **No secrets in errors.** Error strings are built from status codes and
  sanitized bodies — never echo the key back.

Protocol auto-detection (``detect_protocol``):
  1. ``GET {base}/v1/models`` with ``Authorization: Bearer`` (OpenAI style).
  2. ``GET {base}/v1/models`` with ``x-api-key`` (Anthropic style).
  3. ``GET {base}/models`` fallbacks for simpler servers.
The response *shape* decides the detected protocol.
"""

from __future__ import annotations

import re
import time
from typing import Any

#: Default per-request timeout (seconds).  Overridden by plugin settings.
DEFAULT_TIMEOUT_S = 15.0


# ── URL & key helpers ───────────────────────────────────────────────────────


def normalize_base_url(base_url: str) -> str:
    """Strip trailing /v1, /v1/models, and slashes from a base URL."""
    url = base_url.strip()
    url = url.rstrip("/")
    url = re.sub(r"/v1/models$", "", url)
    url = re.sub(r"/v1$", "", url)
    return url


def mask_key(api_key: str) -> str:
    """Display-safe mask of an API key: ``sk-abc…wxyz`` (never reversible)."""
    key = api_key.strip()
    if len(key) <= 12:
        return "***"
    return f"{key[:7]}…{key[-4:]}"


def redact(text: str, api_key: str) -> str:
    """Remove occurrences of the API key from a string (logs/errors/reports)."""
    key = api_key.strip()
    if not key:
        return text
    return text.replace(key, "***")


# ── Model-list parsing ──────────────────────────────────────────────────────

_REASONING_KEYWORDS = ["o1", "o3", "o4", "reasoning", "thinking", "deepseek-r1", "qwq", "r1"]
_VISION_KEYWORDS = ["vision", "vl", "multimodal", "image"]
_EXPERIMENTAL_KEYWORDS = ["deprecated", "alpha", "beta", "preview", "experimental"]


def parse_models(payload: dict[str, Any], protocol: str) -> list[dict[str, Any]]:
    """Normalize a models-list payload into a list of model info dicts.

    Tolerates the common shapes:
      - OpenAI:   ``{"data": [{"id": "...", "owned_by": "..."}]}``
      - Anthropic:``{"data": [{"id": "...", "display_name": "..."}]}``
      - Google:   ``{"models": [{"name": "models/..."}]}``
      - Plain:    ``["model-a", "model-b"]`` or ``{"models": [...]}``
    """
    items: list[Any] = []
    if isinstance(payload, dict):
        raw = payload.get("data")
        if not isinstance(raw, list):
            raw = payload.get("models")
        if isinstance(raw, list):
            items = raw
    elif isinstance(payload, list):
        items = payload

    models: list[dict[str, Any]] = []
    for item in items:
        if isinstance(item, str):
            model_id = item
            extra: dict[str, Any] = {}
        elif isinstance(item, dict):
            model_id = str(
                item.get("id") or item.get("name") or item.get("model") or ""
            )
            # Google style: "models/gemini-2.0-flash" → strip prefix.
            if model_id.startswith("models/"):
                model_id = model_id[len("models/"):]
            extra = dict(item)
        else:
            continue
        if not model_id:
            continue

        model_lower = model_id.lower()
        info: dict[str, Any] = {
            "id": model_id,
            "owned_by": str(extra.get("owned_by") or ""),
            "vision": any(kw in model_lower for kw in _VISION_KEYWORDS),
            "reasoning": any(kw in model_lower for kw in _REASONING_KEYWORDS),
            "status": (
                "experimental"
                if any(kw in model_lower for kw in _EXPERIMENTAL_KEYWORDS)
                else "stable"
            ),
            "protocol": protocol,
        }
        models.append(info)
    return models


def model_ids(models: list[dict[str, Any]]) -> list[str]:
    return [m["id"] for m in models]


# ── Endpoint probing ────────────────────────────────────────────────────────


def _auth_headers(api_key: str, protocol: str) -> dict[str, str]:
    if protocol == "anthropic":
        return {"x-api-key": api_key, "anthropic-version": "2023-06-01"}
    return {"Authorization": f"Bearer {api_key}"}


def detect_protocol(base_url: str, api_key: str, timeout: float) -> dict[str, Any]:
    """Probe the endpoint and detect the protocol flavor.

    Returns ``{"success": bool, "protocol": str, "models": [...],
    "latency_ms": int, "error_text": str?}``.
    """
    import httpx

    normalized = normalize_base_url(base_url)
    candidates = [
        ("openai", f"{normalized}/v1/models"),
        ("anthropic", f"{normalized}/v1/models"),
        ("openai", f"{normalized}/models"),
    ]

    last_error = "connection failed"
    for protocol, url in candidates:
        headers = _auth_headers(api_key, protocol)
        started = time.monotonic()
        try:
            with httpx.Client(timeout=timeout) as http:
                response = http.get(url, headers=headers)
            latency_ms = int((time.monotonic() - started) * 1000)
            if response.status_code == 200:
                try:
                    payload = response.json()
                except ValueError:
                    return {
                        "success": False,
                        "error_text": "Endpoint returned 200 but the body is not JSON",
                        "latency_ms": latency_ms,
                    }
                models = parse_models(payload, protocol)
                return {
                    "success": True,
                    "protocol": protocol,
                    "models": models,
                    "model_count": len(models),
                    "latency_ms": latency_ms,
                    "normalized_url": normalized,
                }
            # 401/403 → auth problem; 404 → wrong path, try next candidate.
            if response.status_code in (401, 403):
                return {
                    "success": False,
                    "protocol": protocol,
                    "latency_ms": latency_ms,
                    "error_text": (
                        f"HTTP {response.status_code}: ключ отклонён "
                        f"(недействителен, отозван или нет доступа)"
                    ),
                    "normalized_url": normalized,
                }
            last_error = f"HTTP {response.status_code}"
        except httpx.TimeoutException:
            last_error = "таймаут подключения"
        except httpx.ConnectError:
            last_error = "не удалось подключиться (DNS/сеть/блокировка)"
        except httpx.HTTPError as exc:
            last_error = f"HTTP-ошибка: {type(exc).__name__}"

    return {"success": False, "error_text": last_error, "normalized_url": normalized}


def quick_check(
    base_url: str,
    api_key: str,
    model: str = "",
    timeout: float = DEFAULT_TIMEOUT_S,
) -> dict[str, Any]:
    """Full quick check: protocol + models + latency + optional model lookup.

    Result shape (API-result contract — never raises on endpoint errors):
      ``{"success": bool, "protocol"?, "models"?, "model_available"?,
         "latency_ms"?, "error_text"?, "normalized_url"?}``
    """
    if not base_url.strip():
        raise ValueError("baseUrl is required")
    if not api_key.strip():
        raise ValueError("apiKey is required")

    result = detect_protocol(base_url, api_key, timeout)
    if not result.get("success"):
        return result

    if model.strip():
        wanted = model.strip().lower()
        available = any(m["id"].lower() == wanted for m in result.get("models", []))
        fuzzy = [
            m["id"] for m in result.get("models", [])
            if wanted in m["id"].lower() or m["id"].lower() in wanted
        ]
        result["model_available"] = available
        result["model_fuzzy_matches"] = fuzzy
        if not available:
            result["model_hint"] = (
                "Модель не найдена в списке. Relay мог скрыть её или имя "
                "отличается — проверьте написание или уточните у провайдера."
            )
    return result


def check_known_endpoint_shape(base_url: str, timeout: float = 5.0) -> dict[str, Any]:
    """Fingerprint the server *software* behind an endpoint (no key needed).

    Lightweight signature probes inspired by service-fingerprinting tools:
    one-api/new-api and LiteLLM expose distinctive unauthenticated routes.
    Returns ``{"software": str|None, "hints": [...]}`` — best effort, never
    raises.
    """
    import httpx

    normalized = normalize_base_url(base_url)
    probes = [
        ("one-api/new-api", f"{normalized}/api/status"),
        ("litellm", f"{normalized}/health/liveliness"),
        ("vllm", f"{normalized}/health"),
    ]
    hints: list[str] = []
    software: str | None = None
    try:
        with httpx.Client(timeout=timeout) as http:
            for name, url in probes:
                try:
                    response = http.get(url)
                except httpx.HTTPError:
                    continue
                if response.status_code == 200:
                    software = name
                    hints.append(f"{name}: {url} → 200")
                    break
                if response.status_code in (401, 403):
                    hints.append(f"{name}: {url} → {response.status_code} (защищено)")
    except httpx.HTTPError:
        pass
    return {"software": software, "hints": hints, "normalized_url": normalized}
