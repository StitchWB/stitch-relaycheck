"""External HoloNe deep-scan bridge (Этап 6).

Опциональный «глубокий» скан через внешний бинарь ``holone``
(``vanndh/holone``):

- ищет ``holone`` в PATH;
- если бинаря нет — скачивает release-ассет под текущую платформу из
  GitHub releases, сверяя sha256 по ``SHA256SUMS.txt``;
- запускает ``holone scan <url> --key <key> --model <model> --json`` и
  парсит структурированный результат (risk_score, verdict, probes, TLS,
  blocklist hits, рекомендации).

**Предупреждение:** внешний ``holone scan`` принимает ключ аргументом
(``--key``) — он виден в списке процессов долю секунды.  Встроенный движок
(``security.py``) — default; внешний бинарь — опция «глубокий скан».

Verdict mapping (holone → RelayCheck risk vocabulary):
  malicious → critical; high-risk → high; suspicious → medium;
  no-active-injection-detected → clean; could-not-probe → error.
"""

from __future__ import annotations

import hashlib
import json
import platform
import shutil
import stat
import subprocess
import urllib.request
from pathlib import Path
from typing import Any

HOLONE_REPO = "vanndh/holone"
#: Fallback release tag if the GitHub API is unreachable.
FALLBACK_TAG = "v0.3.0"

_VERDICT_MAP = {
    "malicious": "critical",
    "high-risk": "high",
    "suspicious": "medium",
    "no-active-injection-detected": "clean",
    "could-not-probe": "error",
}


def platform_asset_name() -> str:
    """Release asset name for the current platform (holone-<os>-<arch>[.exe])."""
    system = platform.system().lower()
    machine = platform.machine().lower()
    arch = {"x86_64": "amd64", "amd64": "amd64", "aarch64": "arm64", "arm64": "arm64"}.get(
        machine, "amd64"
    )
    if system == "windows":
        return f"holone-windows-{arch}.exe"
    if system == "darwin":
        return f"holone-darwin-{arch}"
    return f"holone-linux-{arch}"


def find_holone() -> str | None:
    """Return the path of an installed ``holone`` binary, if any."""
    return shutil.which("holone")


def _github_latest_tag() -> str:
    url = f"https://api.github.com/repos/{HOLONE_REPO}/releases/latest"
    try:
        with urllib.request.urlopen(url, timeout=10) as resp:  # noqa: S310 — fixed upstream
            data = json.loads(resp.read())
        tag = data.get("tag_name")
        if isinstance(tag, str) and tag:
            return tag
    except Exception:  # noqa: BLE001 — network is best-effort here
        pass
    return FALLBACK_TAG


def _download(url: str, timeout: float = 60.0) -> bytes:
    with urllib.request.urlopen(url, timeout=timeout) as resp:  # noqa: S310 — fixed upstream
        return resp.read()


def download_holone(
    data_dir: str,
    *,
    tag: str | None = None,
    release_base: str = "https://github.com/vanndh/holone/releases/download",
) -> dict[str, Any]:
    """Download the platform ``holone`` binary with SHA256 verification.

    Returns ``{"success": True, "path", "version", "sha256"}`` or
    ``{"success": False, "error_text"}``.
    """
    tag = tag or _github_latest_tag()
    asset = platform_asset_name()
    bin_dir = Path(data_dir) / "bin"
    bin_dir.mkdir(parents=True, exist_ok=True)
    dest = bin_dir / asset

    try:
        sums_raw = _download(f"{release_base}/{tag}/SHA256SUMS.txt").decode()
        expected: dict[str, str] = {}
        for line in sums_raw.splitlines():
            parts = line.split()
            if len(parts) == 2:
                expected[parts[1].lstrip("*")] = parts[0]
        if asset not in expected:
            return {
                "success": False,
                "error_text": f"asset {asset!r} not found in SHA256SUMS for {tag}",
            }
        blob = _download(f"{release_base}/{tag}/{asset}", timeout=300.0)
        digest = hashlib.sha256(blob).hexdigest()
        if digest != expected[asset]:
            return {
                "success": False,
                "error_text": (
                    f"sha256 mismatch for {asset}: expected {expected[asset]}, got {digest}"
                ),
            }
        dest.write_bytes(blob)
        dest.chmod(dest.stat().st_mode | stat.S_IXUSR | stat.S_IXGRP | stat.S_IXOTH)
        return {"success": True, "path": str(dest), "version": tag, "sha256": digest}
    except Exception as exc:  # noqa: BLE001 — download is best-effort
        return {"success": False, "error_text": f"download failed: {exc}"}


def parse_scan_output(stdout: str) -> dict[str, Any]:
    """Parse ``holone scan`` stdout: JSON result if present, else raw text."""
    # The last JSON object line wins (progress lines may precede it).
    for line in reversed(stdout.strip().splitlines()):
        line = line.strip()
        if line.startswith("{"):
            try:
                data = json.loads(line)
            except ValueError:
                continue
            if isinstance(data, dict) and "verdict" in data:
                return data
    return {}


def map_verdict(holone_verdict: str) -> str:
    return _VERDICT_MAP.get(holone_verdict, "error")


def run_holone_scan(
    base_url: str,
    api_key: str,
    model: str,
    *,
    holone_path: str | None = None,
    data_dir: str = "",
    timeout: float = 120.0,
) -> dict[str, Any]:
    """Run ``holone scan`` against the endpoint and return a normalized result.

    Result: ``{"success", "verdict", "risk_score", "summary", "holone": {...},
    "binary", "error_text"?}``.
    """
    binary = holone_path or find_holone()
    if binary is None:
        if not data_dir:
            return {
                "success": False,
                "error_text": (
                    "holone binary not found in PATH — install it "
                    "(https://github.com/vanndh/holone) or allow the plugin "
                    "to download it"
                ),
            }
        fetched = download_holone(data_dir)
        if not fetched.get("success"):
            return {"success": False, "error_text": fetched.get("error_text", "download failed")}
        binary = fetched["path"]

    cmd = [binary, "scan", base_url, "--key", api_key, "--model", model, "--json"]
    try:
        proc = subprocess.run(
            cmd, capture_output=True, text=True, timeout=timeout, check=False
        )
    except subprocess.TimeoutExpired:
        return {"success": False, "error_text": f"holone scan timed out after {timeout:.0f}s"}
    except OSError as exc:
        return {"success": False, "error_text": f"failed to run holone: {exc}"}

    if proc.returncode != 0 and not proc.stdout.strip():
        return {
            "success": False,
            "error_text": f"holone scan failed (exit {proc.returncode}): "
            f"{(proc.stderr or '').strip()[:200]}",
        }

    data = parse_scan_output(proc.stdout)
    if not data:
        return {
            "success": False,
            "error_text": "could not parse holone scan output",
            "raw_output": (proc.stdout or "")[-500:],
        }

    holone_verdict = str(data.get("verdict", ""))
    risk_score = data.get("risk_score")
    risk_score = int(risk_score) if isinstance(risk_score, (int, float)) else None
    return {
        "success": True,
        "verdict": map_verdict(holone_verdict),
        "holone_verdict": holone_verdict,
        "risk_score": risk_score,
        "summary": data.get("summary_ru") or data.get("summary_en") or "",
        "summary_en": data.get("summary_en"),
        "recommendations": data.get("recommendations_ru") or data.get("recommendations_en") or [],
        "official": bool(data.get("official")),
        "blocklist_hits": data.get("blocklist_hits") or [],
        "probes": data.get("probes") or [],
        "tls": data.get("tls"),
        "holone": {
            "endpoint": data.get("endpoint"),
            "host": data.get("host"),
            "resolved_ips": data.get("resolved_ips") or [],
        },
        "binary": binary,
    }
