#!/usr/bin/env python3
"""Sync HoloNe detection rules into the plugin's vendored copy.

Downloads ``rules.json`` and ``blocklist.json`` from the upstream
``vanndh/holone`` repository into ``stitch_relaycheck/holone_rules/``.

Usage:
    python scripts/sync_holone_rules.py           # download + report sha256
    python scripts/sync_holone_rules.py --check   # CI mode: fail if drifted
"""

from __future__ import annotations

import hashlib
import sys
import urllib.request
from pathlib import Path

REPO = "vanndh/holone"
BRANCH = "main"
FILES = ("rules.json", "blocklist.json")

_HERE = Path(__file__).resolve().parent
_DEST_DIR = _HERE.parent / "stitch_relaycheck" / "holone_rules"


def _fetch(name: str) -> bytes:
    url = f"https://raw.githubusercontent.com/{REPO}/{BRANCH}/rules/{name}"
    with urllib.request.urlopen(url, timeout=30) as resp:  # noqa: S310 — fixed upstream URL
        return resp.read()


def _sha(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def main() -> int:
    check_only = "--check" in sys.argv
    drifted = False
    for name in FILES:
        data = _fetch(name)
        dest = _DEST_DIR / name
        current = dest.read_bytes() if dest.exists() else None
        status = "unchanged"
        if current != data:
            status = "would-update" if check_only else "updated"
            drifted = True
            if not check_only:
                _DEST_DIR.mkdir(parents=True, exist_ok=True)
                dest.write_bytes(data)
        print(f"{name}: {status} sha256={_sha(data)[:16]}… size={len(data)}")
    if check_only and drifted:
        print("DRIFT: vendored rules differ from upstream — run without --check", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
