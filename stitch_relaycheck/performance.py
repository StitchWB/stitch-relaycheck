"""Performance measurement: latency, TTFT, TPS, error rate (Этап 5).

- ``repeats`` short non-streaming chats → per-request latency stats + ok rate.
- One streaming chat → TTFT and tokens-per-second (TPS).
- ``perf_score`` 0–100 (100 = fast and reliable).
"""

from __future__ import annotations

import time
from typing import Any

from . import client


def _latency_score(avg_ms: float) -> float:
    if avg_ms <= 800:
        return 100.0
    if avg_ms <= 1500:
        return 85.0
    if avg_ms <= 3000:
        return 70.0
    if avg_ms <= 5000:
        return 50.0
    if avg_ms <= 10000:
        return 30.0
    return 10.0


def measure(
    base_url: str,
    api_key: str,
    model: str,
    protocol: str,
    timeout: float,
    repeats: int = 5,
) -> dict[str, Any]:
    """Measure endpoint performance.  Never raises on endpoint failures."""
    started = time.monotonic()
    latencies: list[int] = []
    errors: list[str] = []

    for _ in range(max(1, repeats)):
        resp = client.chat_completion(
            base_url,
            api_key,
            model,
            [{"role": "user", "content": "Скажи одним словом: ок"}],
            protocol=protocol,
            max_tokens=8,
            timeout=timeout,
        )
        if resp.get("ok"):
            latencies.append(int(resp.get("latency_ms") or 0))
        else:
            errors.append(str(resp.get("error_text", "error")))

    # Streaming probe: TTFT + TPS.
    ttft_ms: int | None = None
    tps: float | None = None
    stream_ok = False
    stream = client.chat_completion(
        base_url,
        api_key,
        model,
        [{"role": "user", "content": "Посчитай от 1 до 10 через запятую"}],
        protocol=protocol,
        max_tokens=64,
        stream=True,
        timeout=timeout,
    )
    if stream.get("ok"):
        stream_ok = True
        ttft_ms = stream.get("ttft_ms")
        usage = stream.get("usage") or {}
        completion_tokens = usage.get("completion_tokens")
        latency_ms = stream.get("latency_ms") or 0
        gen_ms = max(1, latency_ms - (ttft_ms or 0))
        if completion_tokens:
            tps = round(completion_tokens / (gen_ms / 1000.0), 1)

    ok_count = len(latencies)
    ok_rate = (ok_count / max(1, repeats)) if repeats else 0.0
    avg_ms = (sum(latencies) / len(latencies)) if latencies else None

    if avg_ms is None:
        perf_score = 0
    else:
        perf_score = round(0.6 * _latency_score(avg_ms) + 0.4 * ok_rate * 100)

    return {
        "repeats": repeats,
        "ok_count": ok_count,
        "ok_rate": round(ok_rate, 3),
        "errors": errors[:3],
        "latency_ms": {
            "min": min(latencies) if latencies else None,
            "avg": round(avg_ms, 1) if avg_ms is not None else None,
            "max": max(latencies) if latencies else None,
        },
        "ttft_ms": ttft_ms,
        "tps": tps,
        "stream_ok": stream_ok,
        "perf_score": perf_score,
        "duration_ms": int((time.monotonic() - started) * 1000),
    }
