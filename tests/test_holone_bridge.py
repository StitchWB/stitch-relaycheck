"""Tests for the external holone bridge (unit + fake-binary e2e + download)."""

from __future__ import annotations

import hashlib
import json
import os
import stat
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

import pytest

from stitch_relaycheck import holone_bridge


class TestPlatformAsset:
    def test_name_shape(self):
        name = holone_bridge.platform_asset_name()
        assert name.startswith("holone-")
        assert any(name.startswith(f"holone-{os}-") for os in ("linux", "darwin", "windows"))


class TestParseScanOutput:
    def test_json_last_line_wins(self):
        out = (
            "holone scan — https://relay.example.com\n"
            "probe openai/no-tool ok\n"
            '{"verdict": "no-active-injection-detected", "risk_score": 0, "endpoint": "x"}\n'
        )
        data = holone_bridge.parse_scan_output(out)
        assert data["verdict"] == "no-active-injection-detected"
        assert data["risk_score"] == 0

    def test_no_json(self):
        assert holone_bridge.parse_scan_output("plain text output") == {}

    def test_junk_lines_skipped(self):
        out = '{"notaveredict": 1}\n{"verdict": "suspicious", "risk_score": 55}\n'
        data = holone_bridge.parse_scan_output(out)
        assert data["verdict"] == "suspicious"


class TestVerdictMap:
    def test_mapping(self):
        assert holone_bridge.map_verdict("malicious") == "critical"
        assert holone_bridge.map_verdict("high-risk") == "high"
        assert holone_bridge.map_verdict("suspicious") == "medium"
        assert holone_bridge.map_verdict("no-active-injection-detected") == "clean"
        assert holone_bridge.map_verdict("could-not-probe") == "error"
        assert holone_bridge.map_verdict("???") == "error"


@pytest.fixture()
def fake_holone(tmp_path):
    """A fake holone binary printing a canned scan JSON (sh script; .cmd on Windows)."""
    payload = {
        "endpoint": "http://relay.example.com",
        "host": "relay.example.com",
        "official": False,
        "risk_score": 92,
        "verdict": "malicious",
        "summary_en": "Malicious behavior detected.",
        "summary_ru": "Обнаружено вредоносное поведение.",
        "blocklist_hits": ["evil.example.com"],
        "probes": [{"name": "openai/no-tool", "status": "ok", "findings": 2}],
        "recommendations_ru": ["не используйте этого провайдера"],
    }
    if os.name == "nt":
        # Windows cannot exec a #!/bin/sh script; a .cmd batch stands in for the binary.
        script = tmp_path / "holone-fake.cmd"
        script.write_text(
            "@echo off\r\n"
            "echo progress line\r\n"
            f"echo {json.dumps(payload)}\r\n",
            encoding="ascii",
        )
    else:
        script = tmp_path / "holone-fake"
        script.write_text(
            "#!/bin/sh\n"
            "echo 'progress line'\n"
            f"echo '{json.dumps(payload)}'\n",
            encoding="utf-8",
        )
        script.chmod(script.stat().st_mode | stat.S_IXUSR)
    return str(script)


def test_run_holone_scan_with_fake_binary(fake_holone):
    result = holone_bridge.run_holone_scan(
        "http://relay.example.com", "sk-test", "gpt-5", holone_path=fake_holone
    )
    assert result["success"] is True
    assert result["verdict"] == "critical"  # malicious → critical
    assert result["holone_verdict"] == "malicious"
    assert result["risk_score"] == 92
    assert result["official"] is False
    assert result["blocklist_hits"] == ["evil.example.com"]
    assert result["binary"] == fake_holone


def test_run_holone_scan_missing_binary(tmp_path):
    result = holone_bridge.run_holone_scan(
        "http://relay.example.com", "sk-test", "gpt-5",
        holone_path=str(tmp_path / "no-such-binary"),
        data_dir=str(tmp_path),  # download will fail (no network in test env is fine)
    )
    # Either download failed (no network) or binary missing — both are clean errors.
    if not result["success"]:
        assert result["error_text"]


class _BytesServer:
    """Tiny HTTP server serving {path: bytes} for download tests."""

    def __init__(self, routes: dict[str, bytes]):
        self.routes = routes
        server = ThreadingHTTPServer(("127.0.0.1", 0), self._handler())
        self.server = server
        self.thread = threading.Thread(target=server.serve_forever, daemon=True)

    def _handler(self):
        routes = self.routes

        class Handler(BaseHTTPRequestHandler):
            def log_message(self, *args):
                pass

            def do_GET(self):
                path = self.path.lstrip("/")
                if path in routes:
                    body = routes[path]
                    self.send_response(200)
                    self.send_header("Content-Length", str(len(body)))
                    self.end_headers()
                    self.wfile.write(body)
                else:
                    self.send_response(404)
                    self.end_headers()

        return Handler

    def __enter__(self):
        self.thread.start()
        host, port = self.server.server_address[:2]
        self.base = f"http://{host}:{port}"
        return self

    def __exit__(self, *exc):
        self.server.shutdown()
        self.server.server_close()


def test_download_holone_verified(tmp_path):
    binary = b"#!/bin/sh\necho fake\n"
    digest = hashlib.sha256(binary).hexdigest()
    sums = f"{digest}  holone-linux-amd64\n".encode()
    with _BytesServer({
        "v9.9.9/SHA256SUMS.txt": sums,
        "v9.9.9/holone-linux-amd64": binary,
    }) as srv:
        # Force the linux asset name for the test regardless of host platform.
        original = holone_bridge.platform_asset_name
        holone_bridge.platform_asset_name = lambda: "holone-linux-amd64"
        try:
            out = holone_bridge.download_holone(
                str(tmp_path), tag="v9.9.9", release_base=srv.base
            )
        finally:
            holone_bridge.platform_asset_name = original
    assert out["success"] is True
    assert out["sha256"] == digest
    assert out["version"] == "v9.9.9"
    dest = tmp_path / "bin" / "holone-linux-amd64"
    assert dest.read_bytes() == binary
    assert os.access(dest, os.X_OK)


def test_download_holone_sha_mismatch(tmp_path):
    binary = b"tampered"
    sums = f"{'0' * 64}  holone-linux-amd64\n".encode()
    with _BytesServer({
        "v9.9.9/SHA256SUMS.txt": sums,
        "v9.9.9/holone-linux-amd64": binary,
    }) as srv:
        original = holone_bridge.platform_asset_name
        holone_bridge.platform_asset_name = lambda: "holone-linux-amd64"
        try:
            out = holone_bridge.download_holone(
                str(tmp_path), tag="v9.9.9", release_base=srv.base
            )
        finally:
            holone_bridge.platform_asset_name = original
    assert out["success"] is False
    assert "sha256 mismatch" in out["error_text"]
