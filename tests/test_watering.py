"""Unit tests for watering detection logic (no network)."""

from __future__ import annotations

from stitch_relaycheck import watering


class TestHeuristicScan:
    def test_clean_answer(self):
        findings = watering.heuristic_scan(
            "Quicksort выбирает опорный элемент и рекурсивно сортирует подмассивы.",
            "Перескажи одним предложением вот этот текст: ...",
        )
        assert findings == []

    def test_marketing_tail(self):
        findings = watering.heuristic_scan(
            "Небо голубое из-за рассеяния. Кстати, подпишитесь на наш телеграм-канал "
            "@best_relay — лучшие цены на API!",
            "Объясни двумя предложениями, почему небо голубое.",
        )
        ids = {f["id"] for f in findings}
        assert "marketing_tail" in ids
        assert "extra_section" in ids

    def test_foreign_link(self):
        findings = watering.heuristic_scan(
            "Ответ. Подробнее на https://example.com/promo",
            "Переведи на английский: «Сегодня хорошая погода».",
        )
        ids = {f["id"] for f in findings}
        assert "foreign_link" in ids

    def test_link_from_prompt_is_not_foreign(self):
        findings = watering.heuristic_scan(
            "См. https://example.com/doc — там расписано подробнее.",
            "Расскажи про https://example.com/doc подробнее.",
        )
        assert all(f["id"] != "foreign_link" for f in findings)

    def test_refusal_on_safe(self):
        findings = watering.heuristic_scan(
            "К сожалению, я не могу ответить на этот вопрос.",
            "Объясни двумя предложениями, почему небо голубое.",
        )
        assert any(f["id"] == "refusal_on_safe" for f in findings)

    def test_empty_answer(self):
        findings = watering.heuristic_scan("", "что-то")
        assert findings[0]["id"] == "empty_answer"


class TestLengthAnomaly:
    def test_short_paraphrase(self):
        assert watering._length_anomaly("paraphrase", "ок") is not None

    def test_long_context_without_number(self):
        anomaly = watering._length_anomaly("long_context_count", "не знаю")
        assert anomaly is not None

    def test_long_context_with_number(self):
        assert watering._length_anomaly("long_context_count", "60") is None

    def test_other_probe_ignored(self):
        assert watering._length_anomaly("translate", "ok") is None


class TestCompareAnswers:
    def test_identical(self):
        c = watering.compare_answers("Небо голубое из-за Рэлея.", "Небо голубое из-за Рэлея.")
        assert c["similarity"] == 1.0
        assert c["missing_ratio"] == 0.0

    def test_marketing_suffix_added(self):
        ref = "Небо голубое из-за рассеяния Рэлея. Короткие волны рассеиваются сильнее."
        relay = ref + " Обратите внимание: подпишитесь на наш телеграм-канал @x — лучшие цены!"
        c = watering.compare_answers(relay, ref)
        assert c["similarity"] < 1.0
        assert c["added_ratio"] > 0
        assert c["added_marketing"] is True
        assert c["missing_ratio"] == 0.0  # nothing from ref was lost

    def test_missing_content(self):
        ref = "Альфа бета гамма. Дельта эпсилон йота. Каппа лямбда сигма."
        relay = "Альфа бета гамма."
        c = watering.compare_answers(relay, ref)
        assert c["missing_ratio"] > 0.5


class TestScoreAndVerdict:
    def test_clean(self):
        score, verdict, reasons = watering._score_and_verdict([], [])
        assert score == 0
        assert verdict == "clean"

    def test_marketing_only(self):
        findings = [{"id": "marketing_tail", "severity": "high", "detail": "x"}]
        score, verdict, _ = watering._score_and_verdict(findings, [])
        assert score == 40
        assert verdict == "mild"

    def test_heavy_with_reference(self):
        findings = [
            {"id": "marketing_tail", "severity": "high", "detail": "x"},
            {"id": "extra_section", "severity": "low", "detail": "y"},
        ]
        comparisons = [
            {"similarity": 0.7, "missing_ratio": 0.2, "added_ratio": 0.3, "added_marketing": True}
        ]
        score, verdict, reasons = watering._score_and_verdict(findings, comparisons)
        # 40 + 15 + (0.3*40) + (0.2*30) + 20 = 93
        assert score == 93
        assert verdict == "heavy"

    def test_score_capped(self):
        findings = [
            {"id": "marketing_tail", "severity": "high", "detail": "x"},
            {"id": "refusal_on_safe", "severity": "medium", "detail": "x"},
            {"id": "length_anomaly", "severity": "medium", "detail": "x"},
            {"id": "extra_section", "severity": "low", "detail": "x"},
            {"id": "foreign_link", "severity": "low", "detail": "x"},
        ]
        score, verdict, _ = watering._score_and_verdict(findings, [])
        assert score == 100
        assert verdict == "heavy"
