#!/usr/bin/env python3
"""
LateralX cross-platform launcher (Windows / Linux / macOS).

Usage:
    python start.py

Starts the API + investigation UI on one port and opens your browser.
Requires Python 3.10+ and dependencies from backend/requirements.txt
(installed automatically on first run if missing).
"""

from __future__ import annotations

import argparse
import os
import socket
import subprocess
import sys
import threading
import time
import webbrowser
from pathlib import Path

ROOT = Path(__file__).resolve().parent
BACKEND = ROOT / "backend"
REQUIREMENTS = BACKEND / "requirements.txt"
DEFAULT_HOST = "127.0.0.1"
DEFAULT_PORT = 8000


def _port_open(host: str, port: int) -> bool:
    try:
        with socket.create_connection((host, port), timeout=0.4):
            return True
    except OSError:
        return False


def _ensure_deps() -> None:
    try:
        import fastapi  # noqa: F401
        import networkx  # noqa: F401
        import uvicorn  # noqa: F401
    except ImportError:
        print("Installing Python dependencies…")
        subprocess.check_call(
            [sys.executable, "-m", "pip", "install", "-r", str(REQUIREMENTS)],
        )


def _wait_and_open(url: str, host: str, port: int, timeout: float = 40.0) -> None:
    deadline = time.time() + timeout
    while time.time() < deadline:
        if _port_open(host, port):
            webbrowser.open(url)
            return
        time.sleep(0.25)
    print(f"Server did not become ready; open manually: {url}")


def main() -> int:
    parser = argparse.ArgumentParser(description="Start LateralX")
    parser.add_argument("--host", default=DEFAULT_HOST, help="Bind host (default 127.0.0.1)")
    parser.add_argument("--port", type=int, default=DEFAULT_PORT, help="Bind port (default 8000)")
    parser.add_argument("--no-browser", action="store_true", help="Do not open a browser")
    args = parser.parse_args()

    if not BACKEND.is_dir():
        print("error: backend/ folder missing", file=sys.stderr)
        return 1

    os.chdir(BACKEND)
    if str(BACKEND) not in sys.path:
        sys.path.insert(0, str(BACKEND))

    _ensure_deps()

    import uvicorn

    url = f"http://{args.host}:{args.port}/"
    print("LateralX")
    print(f"  UI + API  {url}")
    print(f"  Docs      http://{args.host}:{args.port}/docs")
    print("  Press Ctrl+C to stop.\n")

    if not args.no_browser:
        threading.Thread(
            target=_wait_and_open,
            args=(url, args.host, args.port),
            daemon=True,
        ).start()

    uvicorn.run(
        "app.main:app",
        host=args.host,
        port=args.port,
        reload=False,
        log_level="info",
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
