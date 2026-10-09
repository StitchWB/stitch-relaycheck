"""Unit tests for the RelayCheck HTTP client helpers (no network)."""

from __future__ import annotations

from stitch_relaycheck import client


class TestNormalizeBaseUrl:
    def test_strips_trailing_slash(self):
        assert client.normalize_base_url("https://a.com/") == "https://a.com"

    def test_strips_v1(self):
        assert client.normalize_base_url("https://a.com/v1") == "https://a.com"

    def test_strips_v1_models(self):
        assert client.normalize_base_url("https://a.com/v1/models") == "https://a.com"

    def test_strips_v1_trailing_slash(self):
        assert client.normalize_base_url("https://a.com/v1/") == "https://a.com"

    def test_keeps_other_paths(self):
        assert client.normalize_base_url("https://a.com/api/v2") == "https://a.com/api/v2"

    def test_whitespace(self):
        assert client.normalize_base_url("  https://a.com/v1 \n") == "https://a.com"


class TestMaskKey:
    def test_long_key(self):
        assert client.mask_key("sk-test-1234567890abcdef") == "sk-test…cdef"

    def test_short_key(self):
        assert client.mask_key("sk-123") == "***"

    def test_empty(self):
        assert client.mask_key("") == "***"


class TestRedact:
    def test_replaces_key(self):
        out = client.redact("error with sk-abc123 inside", "sk-abc123")
        assert "sk-abc123" not in out
        assert "***" in out

    def test_no_key(self):
        assert client.redact("plain text", "") == "plain text"


class TestParseModels:
    def test_openai_shape(self):
        payload = {"data": [{"id": "gpt-5", "owned_by": "openai"}]}
        models = client.parse_models(payload, "openai")
        assert models[0]["id"] == "gpt-5"
        assert models[0]["owned_by"] == "openai"
        assert models[0]["protocol"] == "openai"

    def test_anthropic_shape(self):
        payload = {"data": [{"id": "claude-opus-4-8", "display_name": "Opus"}]}
        models = client.parse_models(payload, "anthropic")
        assert models[0]["id"] == "claude-opus-4-8"

    def test_google_shape_strips_prefix(self):
        payload = {"models": [{"name": "models/gemini-3-pro"}]}
        models = client.parse_models(payload, "google")
        assert models[0]["id"] == "gemini-3-pro"

    def test_plain_list(self):
        models = client.parse_models(["a", "b"], "openai")
        assert [m["id"] for m in models] == ["a", "b"]

    def test_heuristics(self):
        payload = {"data": [
            {"id": "gpt-5-vision-preview"},
            {"id": "deepseek-r1"},
        ]}
        models = client.parse_models(payload, "openai")
        assert models[0]["vision"] is True
        assert models[0]["status"] == "experimental"
        assert models[1]["reasoning"] is True
        assert models[1]["status"] == "stable"

    def test_junk_never_raises(self):
        assert client.parse_models({}, "openai") == []
        assert client.parse_models({"data": "nope"}, "openai") == []
        assert client.parse_models({"data": [{"no_id": 1}, 42, None]}, "openai") == []


class TestQuickCheckValidation:
    def test_requires_base_url(self):
        try:
            client.quick_check("", "sk-x")
        except ValueError:
            return
        raise AssertionError("expected ValueError")

    def test_requires_api_key(self):
        try:
            client.quick_check("https://a.com", " ")
        except ValueError:
            return
        raise AssertionError("expected ValueError")
