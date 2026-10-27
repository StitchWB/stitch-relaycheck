"""Protocol smoke test for the stitch-relaycheck service plugin.

Spawns the plugin as a subprocess (``python -m stitch_relaycheck``) and
drives the raw JSON-RPC 2.0 line protocol — init → ping → _migrate_db →
commands → shutdown — with **no host dependency** and no external network
(the only "network" call uses 127.0.0.1:1, which refuses instantly).

Run from the package root::

    pytest tests/test_plugin_protocol.py -q --timeout=60
"""

from __future__ import annotations

import json
import os
import select
import socket
import subprocess
import sys
import threading
import time
from pathlib import Path

import pytest

# Package dir = parent of this tests/ dir (holds plugin.json + stitch_relaycheck/).
_PACKAGE_DIR = Path(__file__).resolve().parent.parent
_MODULE = "stitch_relaycheck"


class PluginProc:
    """Minimal line-delimited JSON-RPC 2.0 client for the plugin subprocess."""

    def __init__(self, package_dir: Path, data_dir: Path) -> None:
        env = dict(os.environ)
        env["PYTHONUNBUFFERED"] = "1"
        # No TOKEN_ENCRYPTION_KEY on purpose: crypto falls back to a
        # plugin-local key file under data_dir.
        env.pop("TOKEN_ENCRYPTION_KEY", None)
        self.proc = subprocess.Popen(
            [sys.executable, "-m", _MODULE],
            cwd=str(package_dir),
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            env=env,
        )
        self._next_id = 0
        self.data_dir = data_dir
        # Windows select() is sockets-only; the pump bridges pipe lines into a socketpair.
        self._sock, self._pump_sock = socket.socketpair()
        self._recv_buf = b""
        self._pump = threading.Thread(target=self._pump_stdout, daemon=True)
        self._pump.start()

    def _pump_stdout(self) -> None:
        assert self.proc.stdout is not None
        try:
            for raw in iter(self.proc.stdout.readline, ""):
                self._pump_sock.sendall(raw.encode("utf-8"))
        except OSError:
            pass
        finally:
            try:
                self._pump_sock.shutdown(socket.SHUT_WR)
            except OSError:
                pass

    def _readline(self, deadline: float) -> str | None:
        """One line from the transport; None on EOF, TimeoutError past deadline."""
        while b"\n" not in self._recv_buf:
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                raise TimeoutError
            ready, _, _ = select.select([self._sock], [], [], remaining)
            if not ready:
                raise TimeoutError
            chunk = self._sock.recv(65536)
            if not chunk:
                return None
            self._recv_buf += chunk
        line, self._recv_buf = self._recv_buf.split(b"\n", 1)
        return line.decode("utf-8")

    def request(self, method: str, params: dict | None = None, timeout: float = 15.0):
        """Send one request and wait for the response with the same id."""
        self._next_id += 1
        rid = self._next_id
        line = json.dumps(
            {"jsonrpc": "2.0", "id": rid, "method": method, "params": params or {}}
        )
        assert self.proc.stdin is not None
        self.proc.stdin.write(line + "\n")
        self.proc.stdin.flush()

        deadline = time.monotonic() + timeout
        while True:
            try:
                raw = self._readline(deadline)
            except TimeoutError:
                raise TimeoutError(f"no response for {method} (id={rid})") from None
            if raw is None:
                stderr = self.proc.stderr.read() if self.proc.stderr else ""
                raise RuntimeError(f"plugin exited while waiting for {method}: {stderr}")
            message = json.loads(raw)
            if message.get("id") == rid:
                if "error" in message:
                    raise RpcError(message["error"])
                return message.get("result")

    def init(self) -> dict:
        return self.request(
            "plugin.init",
            {
                "engine_api": 2,
                "plugin_id": "stitch-relaycheck",
                "db_path": str(self.data_dir / "plugin.db"),
                "data_dir": str(self.data_dir),
                "supported": ["reverse_rpc", "caller_identity"],
            },
        )

    def close(self) -> None:
        try:
            self.request("plugin.shutdown", {}, timeout=5.0)
        except (TimeoutError, RpcError, RuntimeError, BrokenPipeError, OSError):
            pass
        try:
            self.proc.wait(timeout=5)
        except subprocess.TimeoutExpired:
            self.proc.kill()
        for sock in (self._sock, self._pump_sock):
            try:
                sock.close()
            except OSError:
                pass


class RpcError(Exception):
    def __init__(self, error: dict) -> None:
        super().__init__(f"JSON-RPC error {error.get('code')}: {error.get('message')}")
        self.error = error


@pytest.fixture()
def plugin(tmp_path):
    proc = PluginProc(_PACKAGE_DIR, tmp_path)
    yield proc
    proc.close()


def test_plugin_protocol_roundtrip(plugin: PluginProc) -> None:
    """init → ping → migrate → commands → shutdown."""
    init = plugin.init()
    assert isinstance(init, dict)
    assert init["plugin_id"] == "stitch-relaycheck"
    assert init["capabilities"] == []

    assert plugin.request("plugin.ping") == "pong"

    ack = plugin.request(
        "plugin.call", {"name": "_migrate_db", "params": {"from_version": 0, "to_version": 1}}
    )
    assert ack["to_version"] == 1

    assert plugin.request("plugin.call", {"name": "health_check", "params": {}}) == {"pong": True}

    settings = plugin.request("plugin.call", {"name": "get_settings", "params": {}})
    assert settings["settings"]["timeoutSeconds"] == 15
    assert "persistKeys" not in settings["settings"]

    updated = plugin.request(
        "plugin.call",
        {"name": "set_settings", "params": {"timeoutSeconds": 20}},
    )
    assert updated["settings"]["timeoutSeconds"] == 20

    # save → list → delete roundtrip (key encrypted at rest, masked in output).
    saved = plugin.request(
        "plugin.call",
        {
            "name": "save_target",
            "params": {
                "name": "demo relay",
                "baseUrl": "http://127.0.0.1:1/v1/",
                "apiKey": "sk-test-1234567890abcdef",
                "persistKey": True,
            },
        },
    )
    target = saved["target"]
    assert target["base_url"] == "http://127.0.0.1:1"  # normalized
    assert "1234567890abcdef" not in target["key_mask"]

    rows = plugin.request("plugin.call", {"name": "list_targets", "params": {}})
    assert len(rows["rows"]) == 1
    row = rows["rows"][0]
    assert "api_key_enc" not in row  # never expose ciphertext over RPC
    assert row["key_mask"].endswith("cdef")

    # check_target against a closed local port → fast, deterministic failure.
    checked = plugin.request(
        "plugin.call",
        {
            "name": "check_target",
            "params": {"id": target["id"]},
        },
        timeout=30.0,
    )
    # NOTE: check_target hits the network (127.0.0.1-style failure is fine);
    # we only assert the shape here, not the outcome.
    assert "success" in checked

    deleted = plugin.request(
        "plugin.call", {"name": "delete_target", "params": {"id": target["id"]}}
    )
    assert deleted["success"] is True
    rows = plugin.request("plugin.call", {"name": "list_targets", "params": {}})
    assert rows["rows"] == []

    # Reports history recorded the target check.
    reports = plugin.request("plugin.call", {"name": "list_reports", "params": {}})
    assert any(r["kind"] == "target_check" for r in reports["rows"])

    md = plugin.request(
        "plugin.call", {"name": "get_report_markdown", "params": {"reportId": "latest"}}
    )
    assert "RelayCheck" in md["text"]

    plugin.request("plugin.shutdown")


def test_check_endpoint_validates_params(plugin: PluginProc) -> None:
    """Missing baseUrl/apiKey → JSON-RPC error (-32603), not a result dict."""
    plugin.init()
    plugin.request("plugin.ping")
    with pytest.raises(RpcError) as excinfo:
        plugin.request(
            "plugin.call",
            {"name": "check_endpoint", "params": {"baseUrl": "", "apiKey": ""}},
        )
    assert excinfo.value.error["code"] == -32603
    plugin.request("plugin.shutdown")


def test_verify_model_validates_params(plugin: PluginProc) -> None:
    """verify_model without model and without targetId → JSON-RPC error."""
    plugin.init()
    plugin.request("plugin.ping")
    with pytest.raises(RpcError) as excinfo:
        plugin.request(
            "plugin.call",
            {"name": "verify_model", "params": {}},
        )
    assert excinfo.value.error["code"] == -32603
    plugin.request("plugin.shutdown")


def test_detect_watering_validates_params(plugin: PluginProc) -> None:
    """detect_watering without model/endpoint → JSON-RPC error."""
    plugin.init()
    plugin.request("plugin.ping")
    with pytest.raises(RpcError) as excinfo:
        plugin.request(
            "plugin.call",
            {"name": "detect_watering", "params": {}},
        )
    assert excinfo.value.error["code"] == -32603
    plugin.request("plugin.shutdown")


def test_scan_security_validates_params(plugin: PluginProc) -> None:
    """scan_security without any endpoint → JSON-RPC error."""
    plugin.init()
    plugin.request("plugin.ping")
    with pytest.raises(RpcError) as excinfo:
        plugin.request(
            "plugin.call",
            {"name": "scan_security", "params": {}},
        )
    assert excinfo.value.error["code"] == -32603
    plugin.request("plugin.shutdown")


def test_start_audit_job_validates_params(plugin: PluginProc) -> None:
    """start_audit_job without any endpoint → JSON-RPC error."""
    plugin.init()
    plugin.request("plugin.ping")
    with pytest.raises(RpcError) as excinfo:
        plugin.request(
            "plugin.call",
            {"name": "start_audit_job", "params": {}},
        )
    assert excinfo.value.error["code"] == -32603
    plugin.request("plugin.shutdown")


def test_holone_deep_scan_validates_params(plugin: PluginProc) -> None:
    """holone_deep_scan without any endpoint → JSON-RPC error."""
    plugin.init()
    plugin.request("plugin.ping")
    with pytest.raises(RpcError) as excinfo:
        plugin.request(
            "plugin.call",
            {"name": "holone_deep_scan", "params": {}},
        )
    assert excinfo.value.error["code"] == -32603
    plugin.request("plugin.shutdown")
