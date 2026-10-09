"""Unit tests for fingerprint logic (aggregation, profile DB, resolution)."""

from __future__ import annotations

import json
from pathlib import Path

from stitch_relaycheck import fingerprint


def _result(
    tok_ratio=1.0,
    cap_ratio=1.0,
    identical=True,
    echo="mock-gpt",
    answered=3,
    cap_passed=3,
    cap_expected=3,
):
    return {
        "model": "mock-gpt",
        "tokenizer": {
            "pairs": [],
            "matched": 3 if tok_ratio else 0,
            "answered": answered,
            "ratio": tok_ratio,
        },
        "capability": {
            "probes": [],
            "passed": cap_passed,
            "expected": cap_expected,
            "ratio": cap_ratio,
        },
        "consistency": {"identical": identical, "answered": 2 if identical else 1},
        "stream": {"ok": True},
        "metadata": {"model_echo": echo, "system_fingerprint": "fp_x", "id_prefix": "chatcmpl"},
    }


PROFILE = {
    "family": "mock",
    "tokenizer_deltas": {"latin": {"expected": 16, "tolerance_pct": 30}},
    "capabilities": {"json_mode": True},
}


class TestProfileDb:
    def test_bundled_db_is_valid(self):
        db = fingerprint.load_profiles()
        assert db["version"] >= 1
        assert isinstance(db["profiles"], dict) and db["profiles"]
        for pid, profile in db["profiles"].items():
            assert "tokenizer_deltas" in profile, pid
            for pair_id, spec in profile["tokenizer_deltas"].items():
                assert spec["expected"] > 0, (pid, pair_id)
                assert 0 < spec["tolerance_pct"] <= 100, (pid, pair_id)

    def test_db_file_parses(self):
        raw = Path(fingerprint._PROFILES_PATH).read_text(encoding="utf-8")
        data = json.loads(raw)
        assert "profiles" in data and "aliases" in data

    def test_find_profile_exact(self):
        db = fingerprint.load_profiles()
        profile, pid = fingerprint.find_profile("gpt-5", db)
        assert profile is not None and pid == "gpt-5"

    def test_find_profile_alias_and_prefix(self):
        db = fingerprint.load_profiles()
        profile, pid = fingerprint.find_profile("gpt-5-chat-latest", db)
        assert pid == "gpt-5"
        profile, pid = fingerprint.find_profile("claude-opus-4-8-2026-05-01", db)
        assert pid == "claude-opus-4-8"

    def test_find_profile_unknown(self):
        db = fingerprint.load_profiles()
        assert fingerprint.find_profile("totally-unknown-xyz", db) == (None, None)


class TestAggregateVerdict:
    def test_authentic(self):
        v = fingerprint.aggregate_verdict(_result(), PROFILE)
        assert v["verdict"] == "authentic"
        assert v["score"] == 100

    def test_substituted_on_tokenizer_mismatch(self):
        v = fingerprint.aggregate_verdict(_result(tok_ratio=0.0), PROFILE)
        assert v["verdict"] == "substituted"
        assert v["score"] == 50  # 0.3 * 1 + 0.2 * 1

    def test_suspicious_on_echo_mismatch(self):
        v = fingerprint.aggregate_verdict(_result(echo="gpt-4o"), PROFILE)
        assert v["verdict"] == "suspicious"

    def test_indeterminate_without_profile(self):
        v = fingerprint.aggregate_verdict(_result(), None)
        assert v["verdict"] == "indeterminate"
        assert v["score"] == 100  # heuristics still scored

    def test_error_when_all_probes_failed(self):
        v = fingerprint.aggregate_verdict(
            _result(answered=0, cap_passed=0, cap_expected=3), PROFILE
        )
        assert v["verdict"] == "error"

    def test_likely_authentic_partial(self):
        # tokenizer 2/3 matched → ratio .67; cap 1.0; consistent → score 89? compute:
        # 0.5*.67 + 0.3*1 + 0.2*1 = .335+.5=.835 → 84 → likely_authentic (60..84)
        result = _result(tok_ratio=2 / 3)
        result["tokenizer"]["matched"] = 2
        v = fingerprint.aggregate_verdict(result, PROFILE)
        assert v["verdict"] == "likely_authentic"
        assert 60 <= v["score"] < 85


class TestCapabilityChecks:
    def test_arithmetic(self):
        assert fingerprint._check_arithmetic("Ответ: 391")
        assert not fingerprint._check_arithmetic("не знаю")

    def test_json_mode(self):
        assert fingerprint._check_json_mode('{"ok": true}')
        assert not fingerprint._check_json_mode("вот ваш json: {ok}")
        assert not fingerprint._check_json_mode("not json")

    def test_code_style(self):
        assert fingerprint._check_code_style("```python\ndef is_even(n):\n    return n % 2 == 0\n```")
        assert not fingerprint._check_code_style("def is_even(n):\n    return n & 1 == 0")
