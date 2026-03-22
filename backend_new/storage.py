from __future__ import annotations

import datetime
import glob
import json
import logging
import os
from functools import lru_cache
from typing import Any

from dotenv import load_dotenv

load_dotenv()

try:
    from supabase import create_client
except ImportError:  # pragma: no cover - handled at runtime in deployed env
    create_client = None


LOGGER = logging.getLogger("secureaudit.storage")
BASE_DIR = os.path.dirname(os.path.abspath(__file__))
DATASET_DIR = os.path.join(BASE_DIR, "dataset")
DEFAULT_SUPABASE_TABLE = "scan_history"

os.makedirs(DATASET_DIR, exist_ok=True)


def _utc_now_iso() -> str:
    return datetime.datetime.now(datetime.timezone.utc).isoformat()


def _scan_total_issues(scan: dict[str, Any]) -> int:
    summary_value = scan.get("scan_summary", {}).get("total_issues")
    if isinstance(summary_value, int) and summary_value >= 0:
        return summary_value

    return (
        len(scan.get("issues", []))
        + len(scan.get("gitleaks", []))
        + len(scan.get("checkov", []))
        + len(scan.get("ai_audit", {}).get("findings", []))
    )


def build_scan_record(repo_url: str, pr_url: str, result: dict[str, Any]) -> dict[str, Any]:
    return {
        "repo_url": repo_url,
        "pr_url": pr_url,
        "scanned_at": _utc_now_iso(),
        "scan_summary": result.get("scan_summary", {}),
        "issues": result.get("issues", []),
        "ai_audit": result.get("ai_audit", {}),
        "gitleaks": result.get("gitleaks", []),
        "checkov": result.get("checkov", []),
    }


def _normalize_scan(scan: dict[str, Any]) -> dict[str, Any]:
    return {
        "repo_url": scan.get("repo_url", ""),
        "pr_url": scan.get("pr_url", ""),
        "scanned_at": scan.get("scanned_at", ""),
        "scan_summary": scan.get("scan_summary", {}) or {},
        "issues": scan.get("issues", []) or [],
        "ai_audit": scan.get("ai_audit", {}) or {},
        "gitleaks": scan.get("gitleaks", []) or [],
        "checkov": scan.get("checkov", []) or [],
    }


def _dataset_filename(scan: dict[str, Any]) -> str:
    repo_name = scan["repo_url"].rstrip("/").split("/")[-1] or "repo"
    pr_num = scan["pr_url"].rstrip("/").split("/")[-1] or "pr"

    try:
        timestamp = datetime.datetime.fromisoformat(scan["scanned_at"])
    except (KeyError, TypeError, ValueError):
        timestamp = datetime.datetime.now(datetime.timezone.utc)

    safe_timestamp = timestamp.strftime("%Y%m%d_%H%M%S")
    return f"scan_{repo_name}_pr{pr_num}_{safe_timestamp}.json"


def _use_supabase() -> bool:
    return bool(os.getenv("SUPABASE_URL") and os.getenv("SUPABASE_SERVICE_ROLE_KEY"))


@lru_cache(maxsize=1)
def _get_supabase_client():
    supabase_url = os.getenv("SUPABASE_URL")
    supabase_key = os.getenv("SUPABASE_SERVICE_ROLE_KEY")

    if not supabase_url or not supabase_key:
        raise RuntimeError("SUPABASE_URL and SUPABASE_SERVICE_ROLE_KEY must both be set.")

    if create_client is None:
        raise RuntimeError("The supabase package is not installed in this environment.")

    return create_client(supabase_url, supabase_key)


def _supabase_table() -> str:
    return os.getenv("SUPABASE_TABLE", DEFAULT_SUPABASE_TABLE)


def _save_scan_local(scan: dict[str, Any]) -> None:
    filename = _dataset_filename(scan)
    filepath = os.path.join(DATASET_DIR, filename)

    with open(filepath, "w", encoding="utf-8") as file_handle:
        json.dump(scan, file_handle, indent=2)

    LOGGER.info("Saved scan locally to %s", filepath)


def _save_scan_supabase(scan: dict[str, Any]) -> None:
    payload = _normalize_scan(scan)
    _get_supabase_client().table(_supabase_table()).insert(payload).execute()
    LOGGER.info("Saved scan to Supabase table %s", _supabase_table())


def save_scan(repo_url: str, pr_url: str, result: dict[str, Any]) -> dict[str, Any]:
    scan = build_scan_record(repo_url, pr_url, result)

    if _use_supabase():
        try:
            _save_scan_supabase(scan)
            return scan
        except Exception as exc:  # pragma: no cover - depends on runtime env
            LOGGER.exception("Supabase save failed, falling back to local storage: %s", exc)

    _save_scan_local(scan)
    return scan


def _load_scans_local() -> list[dict[str, Any]]:
    scans: list[dict[str, Any]] = []

    for path in glob.glob(os.path.join(DATASET_DIR, "*.json")):
        try:
            with open(path, encoding="utf-8") as file_handle:
                scans.append(_normalize_scan(json.load(file_handle)))
        except Exception as exc:  # pragma: no cover - invalid local file edge case
            LOGGER.warning("Skipping unreadable local scan file %s: %s", path, exc)

    return sorted(scans, key=lambda scan: scan.get("scanned_at", ""), reverse=True)


def _load_scans_supabase() -> list[dict[str, Any]]:
    response = (
        _get_supabase_client()
        .table(_supabase_table())
        .select("repo_url,pr_url,scanned_at,scan_summary,issues,ai_audit,gitleaks,checkov")
        .order("scanned_at", desc=True)
        .execute()
    )
    return [_normalize_scan(scan) for scan in response.data]


def load_scans() -> list[dict[str, Any]]:
    if _use_supabase():
        try:
            return _load_scans_supabase()
        except Exception as exc:  # pragma: no cover - depends on runtime env
            LOGGER.exception("Supabase read failed, falling back to local storage: %s", exc)

    return _load_scans_local()


def build_features(scans: list[dict[str, Any]]) -> list[dict[str, Any]]:
    features: list[dict[str, Any]] = []

    for scan in scans:
        summary = scan.get("scan_summary", {}) or {}
        all_findings = [
            *(scan.get("issues", []) or []),
            *(scan.get("gitleaks", []) or []),
            *(scan.get("checkov", []) or []),
            *(scan.get("ai_audit", {}).get("findings", []) or []),
        ]

        features.append(
            {
                "repo_url": scan.get("repo_url", ""),
                "pr_url": scan.get("pr_url", ""),
                "scanned_at": scan.get("scanned_at", ""),
                "semgrep_count": summary.get("semgrep", 0),
                "osv_count": summary.get("osv", 0),
                "ai_agent_count": summary.get("ai_agent", 0),
                "gitleaks_count": summary.get("gitleaks", 0),
                "checkov_count": summary.get("checkov", 0),
                "total_issues": summary.get("total_issues", _scan_total_issues(scan)),
                "pr_files_scanned": summary.get("pr_files_scanned", 0),
                "critical_count": sum(1 for finding in all_findings if finding.get("severity") == "critical"),
                "high_count": sum(1 for finding in all_findings if finding.get("severity") == "high"),
                "medium_count": sum(1 for finding in all_findings if finding.get("severity") == "medium"),
                "low_count": sum(1 for finding in all_findings if finding.get("severity") == "low"),
                "has_secret": 1 if scan.get("gitleaks") else 0,
                "has_iac_issue": 1 if scan.get("checkov") else 0,
                "has_ai_finding": 1 if scan.get("ai_audit", {}).get("findings") else 0,
                "risk_label": None,
            }
        )

    return features


def build_dashboard_stats(scans: list[dict[str, Any]]) -> dict[str, int]:
    return {
        "total_scans": len(scans),
        "total_issues": sum(_scan_total_issues(scan) for scan in scans),
    }
