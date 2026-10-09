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

import json
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


# ── Chat completions (fingerprint / watering probes) ────────────────────────


def _short_error(response: Any, api_key: str = "") -> str:
    """Compact, key-free error text from an HTTP response."""
    try:
        body = response.text
    except Exception:  # noqa: BLE001 — best effort
        body = ""
    body = " ".join(body.split())[:200]
    if api_key:
        body = redact(body, api_key)
    return f"HTTP {response.status_code}" + (f": {body}" if body else "")


def _extract_text_from_content(content: Any) -> str:
    """OpenAI content may be a string or a list of typed parts."""
    if isinstance(content, str):
        return content
    if isinstance(content, list):
        parts = []
        for part in content:
            if isinstance(part, dict) and part.get("type") == "text":
                parts.append(str(part.get("text", "")))
            elif isinstance(part, dict) and "text" in part:
                parts.append(str(part["text"]))
        return "".join(parts)
    return ""


def _normalize_chat_payload(
    data: dict[str, Any], latency_ms: int, protocol: str
) -> dict[str, Any]:
    """Normalize OpenAI- or Anthropic-shaped chat payloads to one shape."""
    out: dict[str, Any] = {
        "ok": True,
        "status": 200,
        "latency_ms": latency_ms,
        "text": "",
        "model_echo": None,
        "system_fingerprint": None,
        "usage": None,
        "finish_reason": None,
        "response_id": None,
        "tool_calls": [],
    }
    try:
        if protocol == "anthropic":
            blocks = data.get("content")
            if isinstance(blocks, list):
                out["text"] = "".join(
                    str(b.get("text", ""))
                    for b in blocks
                    if isinstance(b, dict) and b.get("type") == "text"
                )
                tool_uses = []
                for block in blocks:
                    if isinstance(block, dict) and block.get("type") == "tool_use":
                        tool_uses.append(
                            {
                                "name": block.get("name", "?"),
                                "arguments": json.dumps(
                                    block.get("input", {}), ensure_ascii=False
                                ),
                            }
                        )
                out["tool_calls"] = tool_uses
            out["model_echo"] = data.get("model")
            usage = data.get("usage")
            if isinstance(usage, dict):
                out["usage"] = {
                    "prompt_tokens": usage.get("input_tokens"),
                    "completion_tokens": usage.get("output_tokens"),
                    "total_tokens": (usage.get("input_tokens") or 0)
                    + (usage.get("output_tokens") or 0),
                }
            out["finish_reason"] = data.get("stop_reason")
            out["response_id"] = data.get("id")
        else:
            choices = data.get("choices")
            if isinstance(choices, list) and choices:
                first = choices[0]
                if isinstance(first, dict):
                    message = first.get("message")
                    if isinstance(message, dict):
                        out["text"] = _extract_text_from_content(message.get("content"))
                        tool_calls = message.get("tool_calls")
                        if isinstance(tool_calls, list):
                            out["tool_calls"] = tool_calls
                    out["finish_reason"] = first.get("finish_reason")
            out["model_echo"] = data.get("model")
            out["system_fingerprint"] = data.get("system_fingerprint")
            usage = data.get("usage")
            if isinstance(usage, dict):
                out["usage"] = {
                    "prompt_tokens": usage.get("prompt_tokens"),
                    "completion_tokens": usage.get("completion_tokens"),
                    "total_tokens": usage.get("total_tokens"),
                }
            out["response_id"] = data.get("id")
    except (AttributeError, TypeError, KeyError):
        pass
    return out


def _sse_event_name(event: dict[str, Any], protocol: str) -> str:
    """Short type name of one SSE event (for streaming-shape fingerprint)."""
    if protocol == "anthropic":
        return str(event.get("type", "unknown"))
    choices = event.get("choices")
    if isinstance(choices, list) and choices and isinstance(choices[0], dict):
        delta = choices[0].get("delta")
        if isinstance(delta, dict):
            if delta.get("role"):
                return "role"
            if delta.get("content"):
                return "content"
            if delta.get("tool_calls"):
                return "tool_calls"
        if choices[0].get("finish_reason"):
            return "finish"
    if event.get("usage"):
        return "usage"
    return "other"


def chat_completion(
    base_url: str,
    api_key: str,
    model: str,
    messages: list[dict[str, str]],
    *,
    protocol: str = "openai",
    max_tokens: int = 16,
    temperature: float = 0.0,
    stream: bool = False,
    response_format: dict[str, Any] | None = None,
    timeout: float = DEFAULT_TIMEOUT_S,
) -> dict[str, Any]:
    """POST one chat completion; returns a normalized, key-free result.

    Success shape:
      ``{"ok": True, "status": 200, "latency_ms", "text", "model_echo",
         "system_fingerprint", "usage": {...}, "finish_reason", "response_id",
         "ttft_ms"?, "sse_events"?}``
    Failure shape:
      ``{"ok": False, "status"?, "latency_ms"?, "error_text"}``
    """
    import httpx

    normalized = normalize_base_url(base_url)
    started = time.monotonic()

    if protocol == "anthropic":
        url = f"{normalized}/v1/messages"
        headers = _auth_headers(api_key, "anthropic")
        sys_parts = [str(m.get("content", "")) for m in messages if m.get("role") == "system"]
        body: dict[str, Any] = {
            "model": model,
            "max_tokens": max_tokens,
            "temperature": temperature,
            "messages": [
                {"role": m.get("role", "user"), "content": m.get("content", "")}
                for m in messages
                if m.get("role") != "system"
            ],
            "stream": stream,
        }
        if sys_parts:
            body["system"] = "\n".join(sys_parts)
    else:
        url = f"{normalized}/v1/chat/completions"
        headers = _auth_headers(api_key, "openai")
        body = {
            "model": model,
            "messages": messages,
            "max_tokens": max_tokens,
            "temperature": temperature,
            "stream": stream,
        }
        if response_format is not None:
            body["response_format"] = response_format
        if stream:
            body["stream_options"] = {"include_usage": True}

    try:
        with httpx.Client(timeout=timeout) as http:
            if not stream:
                response = http.post(url, headers=headers, json=body)
                latency_ms = int((time.monotonic() - started) * 1000)
                if response.status_code != 200:
                    return {
                        "ok": False,
                        "status": response.status_code,
                        "latency_ms": latency_ms,
                        "error_text": _short_error(response, api_key),
                    }
                try:
                    data = response.json()
                except ValueError:
                    return {
                        "ok": False,
                        "status": 200,
                        "latency_ms": latency_ms,
                        "error_text": "200 but body is not JSON",
                    }
                return _normalize_chat_payload(data, latency_ms, protocol)

            # Streaming: collect SSE event types, text, ttft, usage/model.
            sse_events: list[str] = []
            chunks: list[str] = []
            ttft_ms: int | None = None
            model_echo: str | None = None
            system_fingerprint: str | None = None
            usage: dict[str, Any] | None = None
            tool_calls: list[dict[str, Any]] = []
            with http.stream("POST", url, headers=headers, json=body) as response:
                if response.status_code != 200:
                    response.read()
                    latency_ms = int((time.monotonic() - started) * 1000)
                    return {
                        "ok": False,
                        "status": response.status_code,
                        "latency_ms": latency_ms,
                        "error_text": _short_error(response, api_key),
                    }
                for line in response.iter_lines():
                    if ttft_ms is None and line:
                        ttft_ms = int((time.monotonic() - started) * 1000)
                    if not line.startswith("data:"):
                        continue
                    payload = line[len("data:") :].strip()
                    if payload == "[DONE]":
                        sse_events.append("[DONE]")
                        continue
                    try:
                        event = json.loads(payload)
                    except ValueError:
                        continue
                    if not isinstance(event, dict):
                        continue
                    sse_events.append(_sse_event_name(event, protocol))
                    if protocol == "anthropic":
                        if event.get("type") == "message_start":
                            msg = event.get("message")
                            if isinstance(msg, dict):
                                model_echo = msg.get("model")
                        if event.get("type") == "message_delta":
                            u = event.get("usage")
                            if isinstance(u, dict) and u.get("output_tokens") is not None:
                                usage = {
                                    "prompt_tokens": None,
                                    "completion_tokens": u.get("output_tokens"),
                                    "total_tokens": None,
                                }
                        delta = event.get("delta")
                        if isinstance(delta, dict) and delta.get("type") == "text_delta":
                            chunks.append(str(delta.get("text", "")))
                        if event.get("type") == "content_block_start":
                            cb = event.get("content_block")
                            if isinstance(cb, dict) and cb.get("type") == "tool_use":
                                tool_calls.append(
                                    {"name": cb.get("name", "?"), "arguments": ""}
                                )
                        if event.get("type") == "content_block_delta":
                            delta = event.get("delta")
                            if (
                                isinstance(delta, dict)
                                and delta.get("type") == "input_json_delta"
                                and tool_calls
                            ):
                                tool_calls[-1]["arguments"] += str(delta.get("partial_json", ""))
                    else:
                        if event.get("model"):
                            model_echo = event.get("model")
                        if event.get("system_fingerprint"):
                            system_fingerprint = event.get("system_fingerprint")
                        choices = event.get("choices")
                        if isinstance(choices, list) and choices and isinstance(choices[0], dict):
                            delta = choices[0].get("delta")
                            if isinstance(delta, dict):
                                if delta.get("content"):
                                    chunks.append(str(delta["content"]))
                                tcs = delta.get("tool_calls")
                                if isinstance(tcs, list):
                                    for tc in tcs:
                                        if isinstance(tc, dict):
                                            tool_calls.append(tc)
                        if event.get("usage"):
                            u = event["usage"]
                            usage = {
                                "prompt_tokens": u.get("prompt_tokens"),
                                "completion_tokens": u.get("completion_tokens"),
                                "total_tokens": u.get("total_tokens"),
                            }
            latency_ms = int((time.monotonic() - started) * 1000)
            return {
                "ok": True,
                "status": 200,
                "latency_ms": latency_ms,
                "ttft_ms": ttft_ms,
                "text": "".join(chunks),
                "model_echo": model_echo,
                "system_fingerprint": system_fingerprint,
                "usage": usage,
                "sse_events": sse_events,
                "tool_calls": tool_calls,
            }
    except httpx.TimeoutException:
        return {"ok": False, "latency_ms": int((time.monotonic() - started) * 1000),
                "error_text": "таймаут запроса"}
    except httpx.ConnectError:
        return {"ok": False, "latency_ms": int((time.monotonic() - started) * 1000),
                "error_text": "не удалось подключиться (DNS/сеть/блокировка)"}
    except httpx.HTTPError as exc:
        return {"ok": False, "latency_ms": int((time.monotonic() - started) * 1000),
                "error_text": f"HTTP-ошибка: {type(exc).__name__}"}


# ── Balance parsers (relay dashboards) ──────────────────────────────────────


def _parse_one_api_user(payload: dict[str, Any]) -> dict[str, Any] | None:
    """one-api / new-api ``GET /api/user/self`` shape."""
    data = payload.get("data")
    if not isinstance(data, dict):
        return None
    if "quota" not in data and "used_quota" not in data:
        return None
    quota = data.get("quota")
    used = data.get("used_quota", 0)
    out: dict[str, Any] = {
        "software": "one-api/new-api",
        "username": data.get("username"),
        "quota": quota,
        "used_quota": used,
    }
    if isinstance(quota, (int, float)) and isinstance(used, (int, float)):
        out["remaining_quota"] = quota - used
        # one-api quota units: 1 USD = 500000 quota units (convention).
        out["remaining_usd_estimate"] = round((quota - used) / 500000, 4)
        out["used_usd_estimate"] = round(used / 500000, 4)
    return out


def _parse_one_api_billing(payload: dict[str, Any]) -> dict[str, Any] | None:
    """one-api ``GET /v1/dashboard/billing`` shape (subscription/quota info)."""
    data = payload.get("data")
    if not isinstance(data, dict):
        return None
    if "quota" not in data and "total_quota" not in data:
        return None
    quota = data.get("quota", data.get("total_quota"))
    used = data.get("used_quota", data.get("total_used_quota", 0))
    out: dict[str, Any] = {
        "software": "one-api/new-api",
        "quota": quota,
        "used_quota": used,
    }
    if isinstance(quota, (int, float)) and isinstance(used, (int, float)):
        out["remaining_quota"] = quota - used
        out["remaining_usd_estimate"] = round((quota - used) / 500000, 4)
    return out


def _parse_litellm_key_info(payload: dict[str, Any]) -> dict[str, Any] | None:
    """LiteLLM ``GET /key/info`` shape."""
    if not isinstance(payload, dict):
        return None
    if "spend" not in payload and "max_budget" not in payload:
        return None
    spend = payload.get("spend", 0) or 0
    max_budget = payload.get("max_budget")
    out: dict[str, Any] = {
        "software": "litellm",
        "spend_usd": spend,
        "max_budget_usd": max_budget,
    }
    if isinstance(max_budget, (int, float)):
        out["remaining_usd"] = round(max_budget - spend, 4)
    info = payload.get("info")
    if isinstance(info, dict):
        out["key_alias"] = info.get("key_alias")
        out["models"] = info.get("models")
    return out


def get_balance(
    base_url: str, api_key: str, timeout: float = DEFAULT_TIMEOUT_S
) -> dict[str, Any]:
    """Best-effort balance/quota lookup against a relay dashboard.

    Tries known panel shapes (one-api/new-api, LiteLLM).  Returns:
      ``{"success": True, "balance": {...}, "endpoint": str}`` or
      ``{"success": False, "error_text": str}``.
    Read-only: never spends anything.
    """
    import httpx

    normalized = normalize_base_url(base_url)
    bearer = {"Authorization": f"Bearer {api_key}"}
    attempts = [
        (f"{normalized}/api/user/self", bearer, _parse_one_api_user),
        (f"{normalized}/v1/dashboard/billing", bearer, _parse_one_api_billing),
        (f"{normalized}/key/info", bearer, _parse_litellm_key_info),
        # Some panels accept the key as a query param.
        (f"{normalized}/key/info?key={api_key}", {}, _parse_litellm_key_info),
    ]

    errors: list[str] = []
    try:
        with httpx.Client(timeout=timeout) as http:
            for url, headers, parser in attempts:
                try:
                    response = http.get(url, headers=headers)
                except httpx.HTTPError as exc:
                    errors.append(f"{url}: {type(exc).__name__}")
                    continue
                if response.status_code != 200:
                    errors.append(f"{url}: HTTP {response.status_code}")
                    continue
                try:
                    payload = response.json()
                except ValueError:
                    errors.append(f"{url}: not JSON")
                    continue
                parsed = parser(payload)
                if parsed is not None:
                    return {"success": True, "balance": parsed, "endpoint": url}
                errors.append(f"{url}: unrecognized shape")
    except httpx.HTTPError as exc:
        return {"success": False, "error_text": f"HTTP-ошибка: {type(exc).__name__}"}

    return {
        "success": False,
        "error_text": (
            "панель баланса не распознана (не one-api/new-api/LiteLLM или "
            "ключ не имеет доступа к дашборду): " + "; ".join(errors[:3])
        ),
    }
