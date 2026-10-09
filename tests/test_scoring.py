"""Unit tests for the trust score aggregation."""

from __future__ import annotations

from stitch_relaycheck import scoring


class TestNormalizeLayer:
    def test_check(self):
        assert scoring.normalize_layer("check", {"success": True}) == 100.0
        assert scoring.normalize_layer("check", {"success": False}) == 30.0

    def test_fingerprint(self):
        assert scoring.normalize_layer("fingerprint", {"verdict": "authentic", "score": 92}) == 92.0
        assert scoring.normalize_layer("fingerprint", {"verdict": "indeterminate", "score": 70}) == 50.0
        assert scoring.normalize_layer("fingerprint", {"verdict": "error"}) == 0.0

    def test_watering_inverted(self):
        assert scoring.normalize_layer("watering", {"verdict": "clean", "score": 0}) == 100.0
        assert scoring.normalize_layer("watering", {"verdict": "heavy", "score": 90}) == 10.0
        assert scoring.normalize_layer("watering", {"verdict": "error"}) == 0.0

    def test_security_inverted(self):
        assert scoring.normalize_layer("security", {"verdict": "clean", "risk_score": 0}) == 100.0
        assert scoring.normalize_layer("security", {"verdict": "critical", "risk_score": 90}) == 10.0
        assert scoring.normalize_layer("security", {"verdict": "error"}) == 0.0

    def test_performance(self):
        assert scoring.normalize_layer("performance", {"verdict": "ok", "score": 80}) == 80.0
        assert scoring.normalize_layer("performance", {"verdict": "error"}) == 0.0

    def test_balance(self):
        assert scoring.normalize_layer("balance", {"success": True}) == 100.0
        assert scoring.normalize_layer("balance", {"success": False}) == 40.0


class TestTrustFromLayers:
    def test_renormalize_present_layers(self):
        trust = scoring.trust_from_layers({
            "fingerprint": {"verdict": "authentic", "score": 92},
            "security": {"verdict": "clean", "risk_score": 0},
        })
        # (30*92 + 25*100) / 55 = 95.6 → 96
        assert trust["score"] == 96
        assert trust["grade"] == "A"
        assert set(trust["layers"]) == {"fingerprint", "security"}

    def test_all_layers(self):
        trust = scoring.trust_from_layers({
            "check": {"success": True},
            "fingerprint": {"verdict": "authentic", "score": 92},
            "watering": {"verdict": "clean", "score": 0},
            "security": {"verdict": "clean", "risk_score": 0},
            "performance": {"verdict": "ok", "score": 90},
            "balance": {"success": True},
        })
        # (5*100 + 30*92 + 20*100 + 25*100 + 15*90 + 5*100) / 100 = 96.1 → 96
        assert trust["score"] == 96
        assert trust["grade"] == "A"

    def test_bad_provider(self):
        trust = scoring.trust_from_layers({
            "fingerprint": {"verdict": "substituted", "score": 10},
            "watering": {"verdict": "heavy", "score": 90},
            "security": {"verdict": "critical", "risk_score": 90},
        })
        # (30*10 + 20*10 + 25*10) / 75 = 10
        assert trust["score"] == 10
        assert trust["grade"] == "F"

    def test_no_data(self):
        trust = scoring.trust_from_layers({})
        assert trust["score"] is None
        assert trust["grade"] == "—"


class TestGrades:
    def test_boundaries(self):
        assert scoring.grade_of(100) == "A"
        assert scoring.grade_of(85) == "A"
        assert scoring.grade_of(84) == "B"
        assert scoring.grade_of(70) == "B"
        assert scoring.grade_of(55) == "C"
        assert scoring.grade_of(40) == "D"
        assert scoring.grade_of(39) == "F"
