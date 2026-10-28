#!/usr/bin/env python3
"""
Privacy and Air-Gap Verification Script.
Audits the codebase and web assets to verify:
1. Zero external font imports (fonts.googleapis.com, fonts.gstatic.com).
2. Zero external CDN references (cdnjs, unpkg, jsdelivr, etc.).
3. Strict localhost-only default network binding (127.0.0.1).
4. Zero outbound telemetry or tracking endpoints.
"""

import re
import sys
from pathlib import Path

BASE_DIR = Path(__file__).resolve().parent.parent
STATIC_DIR = BASE_DIR / "web" / "static"
INDEX_HTML = STATIC_DIR / "index.html"
APP_PY = BASE_DIR / "web" / "app.py"
RUN_APP_PY = BASE_DIR / "run_app.py"

EXTERNAL_URL_PATTERN = re.compile(
    r'(https?:)?//(fonts\.googleapis\.com|fonts\.gstatic\.com|cdnjs\.cloudflare\.com|unpkg\.com|cdn\.jsdelivr\.net|google-analytics\.com|segment\.io)',
    re.IGNORECASE
)


def verify_html_air_gap():
    print("[1/3] Verifying web/static/index.html air-gap compliance...")
    if not INDEX_HTML.exists():
        print("  FAIL: index.html not found!")
        return False

    with open(INDEX_HTML, "r", encoding="utf-8") as f:
        content = f.read()

    matches = EXTERNAL_URL_PATTERN.findall(content)
    if matches:
        print(f"  FAIL: Found forbidden external asset references in index.html: {matches}")
        return False

    if "@import url" in content or "<link rel=\"stylesheet\" href=\"http" in content:
        print("  FAIL: Found remote stylesheet link in index.html!")
        return False

    print("  PASS: Zero external font, CDN, or analytics references detected in index.html.")
    return True


def verify_network_binding():
    print("[2/3] Verifying default network binding in launcher...")
    if not RUN_APP_PY.exists():
        print("  FAIL: run_app.py not found!")
        return False

    with open(RUN_APP_PY, "r", encoding="utf-8") as f:
        content = f.read()

    if 'default="127.0.0.1"' not in content and "default='127.0.0.1'" not in content:
        print("  FAIL: run_app.py does not default host to 127.0.0.1!")
        return False

    if "0.0.0.0" in content and "SECURITY WARNING" not in content:
        print("  FAIL: Missing security warning when binding to 0.0.0.0 in run_app.py!")
        return False

    print("  PASS: Default host is strictly 127.0.0.1 with security warning on 0.0.0.0.")
    return True


def verify_backend_telemetry():
    print("[3/3] Verifying zero outbound network calls in engine and web app...")
    forbidden_terms = [
        "requests.post", "requests.get", "urllib.request.urlopen",
        "httpx.post", "httpx.get", "sentry_sdk", "mixpanel", "analytics.track"
    ]
    
    python_files = list(BASE_DIR.glob("engine/**/*.py")) + [APP_PY]
    for p in python_files:
        with open(p, "r", encoding="utf-8") as f:
            code = f.read()
        for term in forbidden_terms:
            if term in code:
                print(f"  FAIL: Found unexpected outbound network call '{term}' in {p.name}!")
                return False

    print("  PASS: Zero outbound network client calls found in engine or backend.")
    return True


def main():
    print("=" * 60)
    print("Sandbox Comparator: Offline-First Privacy & Air-Gap Audit")
    print("=" * 60)

    ok1 = verify_html_air_gap()
    ok2 = verify_network_binding()
    ok3 = verify_backend_telemetry()

    print("=" * 60)
    if ok1 and ok2 and ok3:
        print("RESULT: ALL AUDITS PASSED. Air-gapped zero-egress posture confirmed.")
        sys.exit(0)
    else:
        print("RESULT: AUDIT FAILED. Review issues above.")
        sys.exit(1)


if __name__ == "__main__":
    main()
