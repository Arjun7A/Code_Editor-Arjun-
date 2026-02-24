"""Deployment smoke verifier for backend/frontend URLs.

Usage examples:
  python scripts/verify_deployment.py --backend-url https://your-api.onrender.com
  python scripts/verify_deployment.py --backend-url https://your-api.onrender.com --frontend-url https://your-app.vercel.app
"""

from __future__ import annotations

import argparse
import json
import os
import sys
import time
from dataclasses import dataclass, asdict
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, Optional

import requests


@dataclass
class CheckResult:
    name: str
    url: str
    ok: bool
    status_code: int
    duration_ms: int
    detail: str


def _build_url(base_url: str, path: str) -> str:
    return f"{base_url.rstrip('/')}/{path.lstrip('/')}"


def _check_get_json(name: str, url: str, timeout: int = 15) -> CheckResult:
    start = time.perf_counter()
    try:
        response = requests.get(url, timeout=timeout)
        elapsed_ms = int((time.perf_counter() - start) * 1000)
        if response.status_code != 200:
            return CheckResult(name, url, False, response.status_code, elapsed_ms, "unexpected status")
        try:
            response.json()
            return CheckResult(name, url, True, response.status_code, elapsed_ms, "ok")
        except Exception:
            return CheckResult(name, url, False, response.status_code, elapsed_ms, "response is not JSON")
    except Exception as exc:
        elapsed_ms = int((time.perf_counter() - start) * 1000)
        return CheckResult(name, url, False, 0, elapsed_ms, str(exc))


def _check_scan_endpoint(base_url: str, timeout: int = 20) -> CheckResult:
    url = _build_url(base_url, "/api/scan")
    payload = {
        "code": "print('deployment smoke')\n",
        "filename": "deployment_smoke.py",
    }
    start = time.perf_counter()
    try:
        response = requests.post(url, json=payload, timeout=timeout)
        elapsed_ms = int((time.perf_counter() - start) * 1000)
        if response.status_code != 200:
            return CheckResult("backend_scan", url, False, response.status_code, elapsed_ms, "unexpected status")
        body = response.json()
        required_keys = {"scan_id", "status", "summary"}
        if not required_keys.issubset(set(body.keys())):
            return CheckResult("backend_scan", url, False, response.status_code, elapsed_ms, "missing response keys")
        return CheckResult("backend_scan", url, True, response.status_code, elapsed_ms, "ok")
    except Exception as exc:
        elapsed_ms = int((time.perf_counter() - start) * 1000)
        return CheckResult("backend_scan", url, False, 0, elapsed_ms, str(exc))


def _check_frontend(frontend_url: str, timeout: int = 15) -> CheckResult:
    start = time.perf_counter()
    try:
        response = requests.get(frontend_url, timeout=timeout)
        elapsed_ms = int((time.perf_counter() - start) * 1000)
        if response.status_code != 200:
            return CheckResult("frontend_root", frontend_url, False, response.status_code, elapsed_ms, "unexpected status")
        body = response.text.lower()
        if "<html" not in body:
            return CheckResult("frontend_root", frontend_url, False, response.status_code, elapsed_ms, "missing html marker")
        return CheckResult("frontend_root", frontend_url, True, response.status_code, elapsed_ms, "ok")
    except Exception as exc:
        elapsed_ms = int((time.perf_counter() - start) * 1000)
        return CheckResult("frontend_root", frontend_url, False, 0, elapsed_ms, str(exc))


def _write_report(path: Path, payload: Dict[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(payload, indent=2), encoding="utf-8")


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Verify deployment URLs and export a smoke report.")
    parser.add_argument(
        "--backend-url",
        default=os.getenv("BACKEND_URL", "").strip(),
        help="Backend base URL (for example: https://your-api.onrender.com)",
    )
    parser.add_argument(
        "--frontend-url",
        default=os.getenv("FRONTEND_URL", "").strip(),
        help="Frontend URL (for example: https://your-app.vercel.app)",
    )
    parser.add_argument(
        "--output",
        default=str(Path(__file__).resolve().parents[2] / "docs" / "deployment" / "latest-verification.json"),
        help="Path to write JSON verification report",
    )
    parser.add_argument("--timeout", type=int, default=15, help="HTTP timeout in seconds")
    return parser.parse_args()


def main() -> int:
    args = parse_args()
    backend_url = args.backend_url.strip().rstrip("/")
    frontend_url = args.frontend_url.strip().rstrip("/")

    if not backend_url:
        print("Missing --backend-url (or BACKEND_URL env var).")
        return 2

    checks = [
        _check_get_json("backend_health", _build_url(backend_url, "/api/health"), timeout=args.timeout),
        _check_get_json("backend_dashboard", _build_url(backend_url, "/api/dashboard-stats"), timeout=args.timeout),
        _check_get_json("backend_policy_rules", _build_url(backend_url, "/api/policy/rules"), timeout=args.timeout),
        _check_scan_endpoint(backend_url, timeout=max(args.timeout, 60)),
    ]

    if frontend_url:
        checks.append(_check_frontend(frontend_url, timeout=args.timeout))

    ok = all(item.ok for item in checks)
    report = {
        "generated_at_utc": datetime.now(timezone.utc).isoformat(),
        "backend_url": backend_url,
        "frontend_url": frontend_url or None,
        "overall_status": "pass" if ok else "fail",
        "checks": [asdict(item) for item in checks],
    }

    output_path = Path(args.output).resolve()
    _write_report(output_path, report)

    print(f"Wrote deployment verification report: {output_path}")
    for item in checks:
        status = "PASS" if item.ok else "FAIL"
        print(f"[{status}] {item.name} ({item.status_code}) {item.url} :: {item.detail}")

    return 0 if ok else 1


if __name__ == "__main__":
    sys.exit(main())
