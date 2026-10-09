"""Trust score — единый скор «насколько этому провайдеру можно доверять».

Слои (все нормализованы к 0–100, где 100 = хорошо):
- ``check``       — доступность (вес 5)
- ``fingerprint`` — оригинальность модели (вес 30)
- ``watering``    — «водность» ответов, инвертировано (вес 20)
- ``security``    — risk score, инвертирован (вес 25)
- ``performance`` — скорость/стабильность (вес 15)
- ``balance``     — прозрачность биллинга (вес 5)

Грейды: A ≥ 85, B ≥ 70, C ≥ 55, D ≥ 40, иначе F.
Отсутствующие слои исключаются из среднего (веса renormalize).
"""

from __future__ import annotations

from typing import Any

WEIGHTS: dict[str, float] = {
    "check": 5.0,
    "fingerprint": 30.0,
    "watering": 20.0,
    "security": 25.0,
    "performance": 15.0,
    "balance": 5.0,
}

LAYER_ORDER = ("check", "fingerprint", "watering", "security", "performance", "balance")


def normalize_layer(layer: str, result: dict[str, Any]) -> float | None:
    """Normalize one layer result to 0–100 (100 = good).  None = no data."""
    if not isinstance(result, dict):
        return None
    if layer == "check":
        return 100.0 if result.get("success") else 30.0
    if layer == "fingerprint":
        verdict = result.get("verdict")
        if verdict == "error":
            return 0.0
        if verdict == "indeterminate":
            return 50.0
        score = result.get("score")
        return float(score) if isinstance(score, (int, float)) else None
    if layer == "watering":
        verdict = result.get("verdict")
        if verdict == "error":
            return 0.0
        score = result.get("score")
        if not isinstance(score, (int, float)):
            return None
        return float(100 - score)
    if layer == "security":
        verdict = result.get("verdict")
        if verdict == "error":
            return 0.0
        risk = result.get("risk_score", result.get("score"))
        if not isinstance(risk, (int, float)):
            return None
        return float(100 - risk)
    if layer == "performance":
        if result.get("verdict") == "error":
            return 0.0
        score = result.get("score", result.get("perf_score"))
        return float(score) if isinstance(score, (int, float)) else None
    if layer == "balance":
        return 100.0 if result.get("success") else 40.0
    return None


def grade_of(score: float) -> str:
    if score >= 85:
        return "A"
    if score >= 70:
        return "B"
    if score >= 55:
        return "C"
    if score >= 40:
        return "D"
    return "F"


def trust_from_layers(results: dict[str, dict[str, Any]]) -> dict[str, Any]:
    """Aggregate layer results into a trust score.

    ``results`` maps layer name → raw layer result (as returned by the
    corresponding service command).
    """
    layers: dict[str, Any] = {}
    total_weight = 0.0
    weighted = 0.0
    for layer in LAYER_ORDER:
        if layer not in results:
            continue
        value = normalize_layer(layer, results[layer])
        if value is None:
            continue
        weight = WEIGHTS[layer]
        layers[layer] = {
            "score": round(value),
            "weight": weight,
            "verdict": results[layer].get("verdict"),
        }
        total_weight += weight
        weighted += weight * value

    if total_weight == 0:
        return {
            "score": None,
            "grade": "—",
            "layers": layers,
            "reasons": ["нет данных ни по одному слою"],
        }

    score = round(weighted / total_weight)
    # Top contributing factors for the report.
    reasons = []
    for layer in LAYER_ORDER:
        info = layers.get(layer)
        if info is None:
            continue
        reasons.append(
            f"{layer}: {info['score']}/100 (вес {info['weight']:.0f})"
            + (f" — {info['verdict']}" if info.get("verdict") else "")
        )
    return {
        "score": score,
        "grade": grade_of(score),
        "layers": layers,
        "reasons": reasons,
    }


def trust_from_scores(scores: dict[str, float | None]) -> dict[str, Any]:
    """Aggregate pre-normalized layer scores (0–100, 100 = good)."""
    layers: dict[str, Any] = {}
    total_weight = 0.0
    weighted = 0.0
    for layer in LAYER_ORDER:
        if layer not in scores:
            continue
        value = scores[layer]
        if value is None:
            continue
        weight = WEIGHTS[layer]
        layers[layer] = {"score": round(value), "weight": weight, "verdict": None}
        total_weight += weight
        weighted += weight * value
    if total_weight == 0:
        return {"score": None, "grade": "—", "layers": layers,
                "reasons": ["нет данных ни по одному слою"]}
    score = round(weighted / total_weight)
    reasons = [
        f"{layer}: {layers[layer]['score']}/100 (вес {layers[layer]['weight']:.0f})"
        for layer in LAYER_ORDER
        if layer in layers
    ]
    return {"score": score, "grade": grade_of(score), "layers": layers, "reasons": reasons}
