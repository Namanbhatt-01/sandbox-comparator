#!/usr/bin/env python3
"""
Single-command launcher for Evidence-Aware Sandbox Comparator Local Web Application.
Usage:
    python3 run_app.py
    python3 run_app.py --port 8080 --host 127.0.0.1
"""

import argparse
import webbrowser
import uvicorn


def main():
    parser = argparse.ArgumentParser(description="Launch Evidence-Aware Sandbox Comparator Local UI")
    parser.add_argument("--host", default="127.0.0.1", help="Host interface to bind (default: 127.0.0.1)")
    parser.add_argument("--port", type=int, default=8000, help="Port to bind (default: 8000)")
    parser.add_argument("--no-browser", action="store_true", help="Do not open browser automatically")
    args = parser.parse_args()

    url = f"http://{args.host}:{args.port}"
    print("=" * 70)
    print("  Evidence-Aware Sandbox Comparator — Local-First SaaS MVP")
    print(f"  Access UI at: {url}")
    print("  Offline-first execution: No sandbox telemetry is sent to any server.")
    if args.host == "0.0.0.0":
        print("  [SECURITY WARNING] Bound to 0.0.0.0! Service is reachable across your LAN.")
    print("=" * 70)

    if not args.no_browser:
        try:
            webbrowser.open(url)
        except Exception:
            pass

    uvicorn.run("web.app:app", host=args.host, port=args.port, reload=False)


if __name__ == "__main__":
    main()

