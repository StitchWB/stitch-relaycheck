"""Watering detection («掺水») — разбавлены ли ответы relay.

Два режима:

1. **Эвристики без reference** (v1, всегда доступен): маректинговые хвосты,
   «P.S./Кстати» секции, чужие ссылки, отказы на безопасных запросах,
   аномальное укорочение, игнорирование формата.
2. **Сравнение с reference** (если пользователь дал reference endpoint):
   тот же fixed prompt-set на reference → similarity (difflib), доля
   потерянных предложений, добавленные «водные» блоки.

Метрики → watering score 0–100 (0 = чисто, 100 = вода) и вердикт
``clean / mild / watered / heavy``.  Эвристика, не доказательство —
все сигналы сохраняются как evidence.
"""

from __future__ import annotations

import re
import time
from difflib import SequenceMatcher
from typing import Any

from . import client

#: Вердикты watering (стабильный vocabulary для UI).
WATERING_VERDICTS = ("clean", "mild", "watered", "heavy")

#: Веса эвристик (суммируются, cap 100).
HEURISTIC_WEIGHTS = {
    "marketing_tail": 40,
    "refusal_on_safe": 25,
    "length_anomaly": 20,
    "extra_section": 15,
    "foreign_link": 15,
}

_MARKETING_RE = re.compile(
    r"(?i)(подпиш\w+|подписывайтесь|наш(его)?\s+(телеграм|telegram|канал|чат|бот)"
    r"|t\.me/|лучш\w+\s+цен\w+|промокод|промо\s*код|скидк\w+\s*\d+\s*%"
    r"|рекламн\w+|партн[её]р\w+\s+ссылк\w+|зарабатывайте\s+с\s+нами)"
)
_EXTRA_SECTION_RE = re.compile(
    r"(?i)(\bкстати\b|\bобратите внимание\b|\bне забудьте\b|\bp\.?\s*s\.?\b|\bp\.?\s*p\.?\s*s\.?\b"
    r"|\bк слову\b|\bесьте в нашем\b)"
)
_REFUSAL_RE = re.compile(
    r"(?i)(не могу (выполнить|ответить|помочь)|i can('|no)t (help|answer|assist)"
    r"|не (могу|вправе)|отказываюсь|запрещено политикой)"
)
_URL_RE = re.compile(r"https?://[^\s)\]»\"']+")

#: Fixed probe set.  Deterministic at temperature=0, short, safe.
_LONG_CONTEXT_TEXT = (
    "небо облака дождь ветер солнце " * 60
)  # слово «небо» встречается 60 раз

WATERING_PROMPTS: list[dict[str, str]] = [
    {
        "id": "paraphrase",
        "content": (
            "Перескажи одним предложением вот этот текст: «Быстрая сортировка "
            "(quicksort) выбирает опорный элемент и рекурсивно сортирует "
            "подмассивы слева и справа от него. В среднем она работает за "
            "O(n log n), в худшем — за O(n^2).»"
        ),
    },
    {
        "id": "long_context_count",
        "content": (
            "В тексте ниже посчитай, сколько раз встречается слово «небо». "
            "Ответь одним числом.\n\n" + _LONG_CONTEXT_TEXT
        ),
    },
    {
        "id": "code_review",
        "content": (
            "Найди баг в коде и объясни одной фразой:\n"
            "```python\n"
            "def divide(a, b):\n"
            "    return a / b\n"
            "print(divide(10, 0))\n"
            "```"
        ),
    },
    {
        "id": "translate",
        "content": "Переведи на английский одной строкой: «Сегодня хорошая погода».",
    },
    {
        "id": "reasoning",
        "content": "Объясни двумя предложениями, почему небо голубое.",
    },
]

_MAX_TEXT_IN_REPORT = 400


def _truncate(text: str, limit: int = _MAX_TEXT_IN_REPORT) -> str:
    text = text.strip()
    return text if len(text) <= limit else text[: limit - 1] + "…"


def heuristic_scan(text: str, prompt_content: str) -> list[dict[str, Any]]:
    """Run reference-free heuristics over one answer."""
    findings: list[dict[str, Any]] = []
    if not text:
        findings.append({"id": "empty_answer", "severity": "medium", "detail": "пустой ответ"})
        return findings

    if _MARKETING_RE.search(text):
        findings.append(
            {
                "id": "marketing_tail",
                "severity": "high",
                "detail": "в ответе найдена маркетинговая вставка/призыв подписаться",
            }
        )
    if _EXTRA_SECTION_RE.search(text):
        findings.append(
            {
                "id": "extra_section",
                "severity": "low",
                "detail": "добавлена неспрашиваемая секция (P.S./«кстати»/«обратите внимание»)",
            }
        )
    prompt_urls = set(_URL_RE.findall(prompt_content))
    answer_urls = set(_URL_RE.findall(text))
    foreign = answer_urls - prompt_urls
    if foreign:
        findings.append(
            {
                "id": "foreign_link",
                "severity": "low",
                "detail": f"в ответе появились ссылки, которых не было в запросе: {sorted(foreign)[:2]}",
            }
        )
    if _REFUSAL_RE.search(text):
        findings.append(
            {
                "id": "refusal_on_safe",
                "severity": "medium",
                "detail": "отказ на безопасном/нейтральном запросе (возможна цензура/фильтрация)",
            }
        )
    return findings


def _length_anomaly(prompt_id: str, text: str) -> dict[str, Any] | None:
    """Answers that are suspiciously short for the probe kind."""
    if prompt_id == "paraphrase" and 0 < len(text) < 20:
        return {
            "id": "length_anomaly",
            "severity": "medium",
            "detail": f"ответ на paraphrase подозрительно короткий ({len(text)} символов)",
        }
    if prompt_id == "long_context_count":
        digits = re.findall(r"\d+", text)
        if not digits:
            return {
                "id": "length_anomaly",
                "severity": "high",
                "detail": "на прямой вопрос о счёте в длинном контексте нет числа — возможно, контекст обрезан",
            }
    return None


def _sentences(text: str) -> list[str]:
    parts = re.split(r"(?<=[.!?])\s+", text.strip())
    return [p.strip() for p in parts if len(p.strip()) > 3]


def compare_answers(relay_text: str, ref_text: str) -> dict[str, Any]:
    """Compare a relay answer against a reference answer (same prompt)."""
    relay_norm = " ".join(relay_text.lower().split())
    ref_norm = " ".join(ref_text.lower().split())
    similarity = SequenceMatcher(None, relay_norm, ref_norm).ratio()

    ref_sentences = _sentences(ref_text)
    relay_sentences = _sentences(relay_text)
    missing = 0
    for sent in ref_sentences:
        sent_norm = " ".join(sent.lower().split())
        best = max(
            (SequenceMatcher(None, sent_norm, " ".join(r.lower().split())).ratio()
             for r in relay_sentences),
            default=0.0,
        )
        if best < 0.6:
            missing += 1
    missing_ratio = (missing / len(ref_sentences)) if ref_sentences else 0.0

    relay_set = {" ".join(s.lower().split()) for s in relay_sentences}
    added = []
    for sent in relay_sentences:
        sent_norm = " ".join(sent.lower().split())
        if sent_norm in relay_set and not any(
            SequenceMatcher(None, sent_norm, " ".join(r.lower().split())).ratio() >= 0.6
            for r in ref_sentences
        ):
            added.append(sent)
    added_ratio = (len(added) / len(relay_sentences)) if relay_sentences else 0.0
    added_marketing = any(_MARKETING_RE.search(s) or _EXTRA_SECTION_RE.search(s) for s in added)

    return {
        "similarity": round(similarity, 3),
        "missing_ratio": round(missing_ratio, 3),
        "added_ratio": round(added_ratio, 3),
        "added_marketing": added_marketing,
        "added_examples": [_truncate(s, 120) for s in added[:3]],
    }


def _score_and_verdict(
    heuristic_findings: list[dict[str, Any]],
    comparisons: list[dict[str, Any]],
) -> tuple[int, str, list[str]]:
    reasons: list[str] = []
    score = 0
    for finding in heuristic_findings:
        weight = HEURISTIC_WEIGHTS.get(finding["id"], 10)
        score += weight
        reasons.append(f"[{finding['id']}] {finding['detail']}")

    if comparisons:
        sims = [c["similarity"] for c in comparisons]
        miss = [c["missing_ratio"] for c in comparisons]
        avg_sim = sum(sims) / len(sims)
        avg_missing = sum(miss) / len(miss)
        score += (1.0 - avg_sim) * 40
        score += avg_missing * 30
        reasons.append(
            f"с reference: сходство ответов {avg_sim:.0%}, потеряно предложений {avg_missing:.0%}"
        )
        if any(c["added_marketing"] for c in comparisons):
            score += 20
            reasons.append("в ответах relay найдены маркетинговые добавки, которых нет в reference")

    score = min(100, round(score))
    if score < 20:
        verdict = "clean"
    elif score < 45:
        verdict = "mild"
    elif score < 70:
        verdict = "watered"
    else:
        verdict = "heavy"
    if score == 0:
        reasons.append("сигналов разбавления не найдено")
    return score, verdict, reasons


def _run_prompt_set(
    base_url: str,
    api_key: str,
    model: str,
    protocol: str,
    timeout: float,
) -> list[dict[str, Any]]:
    """Run the fixed prompt set; returns per-prompt relay answers."""
    out = []
    for probe in WATERING_PROMPTS:
        resp = client.chat_completion(
            base_url,
            api_key,
            model,
            [{"role": "user", "content": probe["content"]}],
            protocol=protocol,
            max_tokens=256,
            temperature=0.0,
            timeout=timeout,
        )
        out.append(
            {
                "id": probe["id"],
                "ok": bool(resp.get("ok")),
                "text": resp.get("text", "") if resp.get("ok") else "",
                "error_text": resp.get("error_text"),
                "latency_ms": resp.get("latency_ms"),
            }
        )
    return out


def run_watering(
    base_url: str,
    api_key: str,
    model: str,
    protocol: str,
    timeout: float,
    reference: dict[str, str] | None = None,
) -> dict[str, Any]:
    """Full watering check.  ``reference`` = {base_url, api_key, model} (optional)."""
    started = time.monotonic()
    relay_answers = _run_prompt_set(base_url, api_key, model, protocol, timeout)

    ref_answers: list[dict[str, Any]] | None = None
    if reference:
        ref_answers = _run_prompt_set(
            reference["base_url"],
            reference["api_key"],
            reference.get("model") or model,
            protocol,
            timeout,
        )

    prompts_out: list[dict[str, Any]] = []
    all_findings: list[dict[str, Any]] = []
    comparisons: list[dict[str, Any]] = []
    ok_count = 0

    for idx, ans in enumerate(relay_answers):
        entry: dict[str, Any] = {
            "id": ans["id"],
            "ok": ans["ok"],
            "relay_text": _truncate(ans["text"]),
            "latency_ms": ans["latency_ms"],
        }
        if not ans["ok"]:
            entry["error_text"] = ans.get("error_text")
            prompts_out.append(entry)
            continue
        ok_count += 1
        findings = heuristic_scan(ans["text"], WATERING_PROMPTS[idx]["content"])
        anomaly = _length_anomaly(ans["id"], ans["text"])
        if anomaly:
            findings.append(anomaly)
        entry["heuristics"] = findings
        all_findings.extend(findings)

        if ref_answers is not None and ref_answers[idx]["ok"]:
            comparison = compare_answers(ans["text"], ref_answers[idx]["text"])
            entry["reference_text"] = _truncate(ref_answers[idx]["text"])
            entry["comparison"] = comparison
            comparisons.append(comparison)
        prompts_out.append(entry)

    if ok_count == 0:
        return {
            "model": model,
            "score": 0,
            "verdict": "error",
            "reasons": ["все пробы завершились ошибкой — endpoint недоступен"],
            "prompts": prompts_out,
            "duration_ms": int((time.monotonic() - started) * 1000),
            "probe_count": len(prompts_out),
            "compared_with_reference": ref_answers is not None,
        }

    score, verdict, reasons = _score_and_verdict(all_findings, comparisons)
    return {
        "model": model,
        "score": score,
        "verdict": verdict,
        "reasons": reasons,
        "prompts": prompts_out,
        "duration_ms": int((time.monotonic() - started) * 1000),
        "probe_count": len(prompts_out),
        "compared_with_reference": ref_answers is not None,
    }
