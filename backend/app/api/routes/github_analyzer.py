"""
GitHub Repo Analyzer — /api/analyze_github
Accepts a GitHub repo URL/owner (e.g., "facebook/react"),
fetches recent PRs, runs ML predictions, and returns results.
"""
from fastapi import APIRouter, HTTPException, Depends
from sqlalchemy.orm import Session
from pydantic import BaseModel, Field
from typing import List, Optional, Dict, Any
import requests
import os
import shutil
import tempfile
import subprocess
import logging
from datetime import datetime, timezone
from app.services.ml_predictor import MLPredictor
from app.services.scanner_orchestrator import ScannerOrchestrator
from app.core.config import settings
from app.core.database import get_db
from app.models.database_models import PullRequest as PRModel, ScanResult as ScanResultModel

logger = logging.getLogger(__name__)
router = APIRouter()

ml_predictor = MLPredictor(model_path=settings.ML_MODEL_PATH)
scanner_orchestrator = ScannerOrchestrator()

GITHUB_API = "https://api.github.com"

SECURITY_KEYWORDS = [
    "security", "vulnerability", "vuln", "cve", "exploit", "injection",
    "xss", "csrf", "ssrf", "rce", "dos", "overflow", "bypass",
    "auth", "authentication", "authorization", "privilege", "sanitize",
    "encrypt", "decrypt", "hash", "token", "password", "secret",
    "credential", "leak", "exposure", "unsafe", "malicious", "attack",
    "patch", "fix", "critical",
]

SENSITIVE_PATHS = [
    "auth", "login", "session", "token", "crypto", "encrypt", "security",
    "password", "secret", "key", "cert", "ssl", "tls", "oauth",
    "permission", "access", "admin", "config", ".env",
]

_MANIFEST_NAMES = {
    "package.json", "package-lock.json", "yarn.lock", "pnpm-lock.yaml",
    "pnpm-workspace.yaml",
    "requirements.txt", "pipfile", "pipfile.lock", "poetry.lock", "pyproject.toml", "setup.py",
    "pom.xml", "build.gradle", "gradle.lockfile",
    "gemfile", "gemfile.lock",
    "go.mod", "go.sum",
    "cargo.toml", "cargo.lock",
    "composer.json", "composer.lock",
    "packages.lock.json", "paket.lock", "project.assets.json",
}


# ── Schemas ──────────────────────────────────────────────────────────────

class AnalyzeGitHubRequest(BaseModel):
    repo: str = Field(..., description="GitHub repo as 'owner/name'")
    num_prs: int = Field(default=10, ge=1, le=30, description="Number of PRs to analyze")

    class Config:
        json_schema_extra = {
            "example": {
                "repo": "facebook/react",
                "num_prs": 10,
            }
        }


class PRPrediction(BaseModel):
    pr_number: int
    title: str
    author: str
    risk_score: float
    risk_label: str
    risk_percentage: float
    feature_importance: Dict[str, float]
    features: Dict[str, Any]
    security_findings: List[str]
    url: str
    created_at: str
    state: str
    model_version: str
    using_fallback: bool
    snyk_vulnerabilities: List[Dict[str, Any]] = []
    semgrep_findings: List[Dict[str, Any]] = []
    scanner_results: List[Dict[str, Any]] = []


class AnalyzeGitHubResponse(BaseModel):
    repo: str
    total_prs_analyzed: int
    high_risk_count: int
    low_risk_count: int
    avg_risk_score: float
    predictions: List[PRPrediction]


# ── Helper functions ─────────────────────────────────────────────────────

_user_cache: Dict[str, float] = {}


def _github_headers():
    token = os.environ.get("GITHUB_TOKEN", "")
    headers = {
        "Accept": "application/vnd.github.v3+json",
        "User-Agent": "SecurityGate-API",
    }
    if token:
        headers["Authorization"] = f"token {token}"
    return headers


def _api_get(url, params=None):
    try:
        r = requests.get(url, headers=_github_headers(), params=params, timeout=30)
        if r.status_code == 200:
            return r.json()
        logger.warning(f"GitHub API returned {r.status_code} for {url}")
        return None
    except Exception as e:
        logger.error(f"GitHub API error: {e}")
        return None


def _get_user_reputation(username: str) -> float:
    if username in _user_cache:
        return _user_cache[username]
    user = _api_get(f"{GITHUB_API}/users/{username}")
    if not user:
        _user_cache[username] = 0.5
        return 0.5
    repos = user.get("public_repos", 0)
    followers = user.get("followers", 0)
    try:
        created = datetime.fromisoformat(user["created_at"].replace("Z", "+00:00"))
        age = (datetime.now(timezone.utc) - created).days / 365
    except Exception:
        age = 1
    score = min(repos / 100, 1) * 0.3 + min(followers / 500, 1) * 0.4 + min(age / 10, 1) * 0.3
    _user_cache[username] = round(max(0, min(1, score)), 3)
    return _user_cache[username]


def _severity_counts(items: List[Dict[str, Any]]) -> Dict[str, int]:
    counts = {"critical": 0, "high": 0, "medium": 0, "low": 0}
    for item in items:
        sev = str(item.get("severity", "low")).lower()
        if sev in counts:
            counts[sev] += 1
    return counts


def _top_severity(severity_counts: Dict[str, int]) -> str:
    for sev in ("critical", "high", "medium", "low"):
        if severity_counts.get(sev, 0) > 0:
            return sev
    return "info"


def _scanner_result_row(
    *,
    tool: str,
    pr_num: int,
    findings: List[Dict[str, Any]],
    execution_time: float,
    status: str,
) -> Dict[str, Any]:
    return {
        "id": f"sr-{tool}-{pr_num}",
        "name": "Snyk" if tool == "snyk" else "Semgrep",
        "status": status,
        "issuesFound": len(findings),
        "executionTime": execution_time,
        "severity": _severity_counts(findings),
    }


def _normalize_status(raw: str) -> str:
    status = str(raw or "").lower()
    if status in ("success", "skipped", "failed"):
        return status
    if status == "error":
        return "failed"
    return "success"


def _checkout_pr_head(repo_dir: str, pr_number: int) -> bool:
    """
    Checkout PR head in the local clone so scanners run on that PR's actual
    revision instead of the repository default branch.
    """
    branch = f"sg-pr-{pr_number}"
    try:
        subprocess.run(
            ["git", "fetch", "--depth", "1", "origin", f"pull/{pr_number}/head:{branch}"],
            cwd=repo_dir,
            check=True,
            capture_output=True,
            timeout=90,
        )
        subprocess.run(
            ["git", "checkout", "--force", branch],
            cwd=repo_dir,
            check=True,
            capture_output=True,
            timeout=60,
        )
        return True
    except Exception as exc:
        logger.warning("Could not checkout PR head for #%s: %s", pr_number, exc)
        return False


def _manifest_touched(changed_filenames: List[str]) -> bool:
    def _is_manifest(filename: str) -> bool:
        base = filename.lower().rsplit("/", 1)[-1]
        if base in _MANIFEST_NAMES:
            return True
        # Common Python manifest families
        if base.startswith("requirements") and base.endswith(".txt"):
            return True
        return False

    return any(_is_manifest(f) for f in changed_filenames)


def _fetch_pr_files(repo: str, pr_number: int) -> List[Dict[str, Any]]:
    """
    Fetch all changed files for a PR (GitHub paginates at 100 entries/page).
    """
    files: List[Dict[str, Any]] = []
    page = 1
    while page <= 20:  # hard cap for safety
        chunk = _api_get(
            f"{GITHUB_API}/repos/{repo}/pulls/{pr_number}/files",
            {"per_page": 100, "page": page},
        )
        if not chunk or not isinstance(chunk, list):
            break
        files.extend(chunk)
        if len(chunk) < 100:
            break
        page += 1
    return files


def _fetch_pr_detail(repo: str, pr_number: int) -> Dict[str, Any]:
    detail = _api_get(f"{GITHUB_API}/repos/{repo}/pulls/{pr_number}")
    return detail if isinstance(detail, dict) else {}


def _to_int(value: Any, default: int = 0) -> int:
    try:
        return int(value)
    except Exception:
        return default


# ── Main endpoint ────────────────────────────────────────────────────────

@router.post("/analyze_github", response_model=AnalyzeGitHubResponse)
async def analyze_github_repo(request: AnalyzeGitHubRequest, db: Session = Depends(get_db)):
    """
    Analyze recent PRs from any public GitHub repository using the trained ML model.
    Fetches real PR metadata from the GitHub API and runs XGBoost predictions.
    """
    repo = request.repo.strip().strip("/")
    if "/" not in repo:
        raise HTTPException(status_code=400, detail="Repo must be in 'owner/name' format (e.g., 'facebook/react')")

    # Get repo languages
    langs = _api_get(f"{GITHUB_API}/repos/{repo}/languages") or {}
    js_bytes = langs.get("JavaScript", 0) + langs.get("TypeScript", 0)
    py_bytes = langs.get("Python", 0)
    web_bytes = js_bytes + py_bytes
    lang_ratio = round(js_bytes / web_bytes, 3) if web_bytes > 0 else 0.5

    # Fetch PRs
    prs = _api_get(
        f"{GITHUB_API}/repos/{repo}/pulls",
        params={
            "state": "all",
            "sort": "updated",
            "direction": "desc",
            "per_page": request.num_prs,
        },
    )

    if prs is None:
        raise HTTPException(
            status_code=404,
            detail=f"Could not fetch PRs from '{repo}'. Check the repo name and ensure GITHUB_TOKEN is set."
        )

    if len(prs) == 0:
        raise HTTPException(
            status_code=404,
            detail=f"No PRs found for '{repo}'."
        )

    # ── Clone repository once. Each PR will be checked out independently. ──
    tmp_dir: Optional[str] = None
    try:
        tmp_dir = tempfile.mkdtemp(prefix="sg_gh_")
        subprocess.run(
            ["git", "clone", "--depth", "1", f"https://github.com/{repo}.git", tmp_dir],
            check=True, capture_output=True, timeout=120,
        )
    except Exception as exc:
        logger.warning("Could not clone %s: %s", repo, exc)

    def _snyk_for_pr(changed_filenames: List[str], checked_out: bool) -> tuple[List[Dict[str, Any]], float, str]:
        """
        Run Snyk for this PR only if dependency manifests changed.
        Returns findings, execution_time, status.
        """
        if not checked_out or not tmp_dir:
            return [], 0.0, "failed"
        if not settings.SNYK_RUN_ALL_PRS and not _manifest_touched(changed_filenames):
            return [], 0.0, "skipped"
        snyk_scan_result = scanner_orchestrator.snyk.scan_dependencies(tmp_dir)
        findings = scanner_orchestrator._to_vulnerability_list(snyk_scan_result)
        return (
            findings,
            snyk_scan_result.get("execution_time", 0.0),
            _normalize_status(snyk_scan_result.get("status", "success")),
        )

    predictions: List[PRPrediction] = []

    for pr in prs:
        pr_num = pr["number"]
        pr_detail = _fetch_pr_detail(repo, pr_num)
        merged_pr = {**pr, **pr_detail}

        title = str(merged_pr.get("title", ""))
        user_obj = merged_pr.get("user") or {}
        author = user_obj.get("login", "unknown")
        created_raw = merged_pr.get("created_at") or pr.get("created_at")
        created = datetime.fromisoformat(str(created_raw).replace("Z", "+00:00"))
        additions = _to_int(merged_pr.get("additions", 0))
        deletions = _to_int(merged_pr.get("deletions", 0))
        changed_files_count = _to_int(merged_pr.get("changed_files", 0))
        commit_count = max(1, _to_int(merged_pr.get("commits", 1), 1))
        comment_count = _to_int(merged_pr.get("comments", 0))
        review_comment_count = _to_int(merged_pr.get("review_comments", 0))

        # Get files changed in this PR (all pages)
        files = _fetch_pr_files(repo, pr_num)

        # List of filenames changed in this PR (used for scanner filtering)
        changed_filenames = [f.get("filename", "") for f in files if f.get("filename")]

        has_tests = any(
            any(p in f.get("filename", "").lower() for p in ["test", "spec", "__test__"])
            for f in files
        )

        # Find specific sensitive files
        sensitive_files = []
        for f in files:
            fname = f.get("filename", "").lower()
            for p in SENSITIVE_PATHS:
                if p in fname:
                    sensitive_files.append(f.get("filename", ""))
                    break
        sensitive = len(sensitive_files)

        body = merged_pr.get("body") or ""
        combined_text = (title + " " + body).lower()

        # Find specific security keywords matched
        matched_keywords = [kw for kw in SECURITY_KEYWORDS if kw in combined_text]
        sec_keywords = len(matched_keywords)

        # Build human-readable security findings
        security_findings: list[str] = []
        for sf in sensitive_files[:5]:  # cap at 5
            security_findings.append(f"Sensitive file modified: {sf}")
        for kw in matched_keywords[:5]:
            # Find context in title or body
            if kw in title.lower():
                security_findings.append(f'Security keyword "{kw}" found in PR title')
            else:
                security_findings.append(f'Security keyword "{kw}" mentioned in description')
        if not has_tests and len(files) > 3:
            security_findings.append("No test files modified despite multiple file changes")
        if additions > 500:
            security_findings.append(f"Large PR with {additions} lines added — harder to review")

        # Checkout each PR head so scanner results are PR-specific.
        checked_out = bool(tmp_dir) and _checkout_pr_head(tmp_dir, pr_num)

        # Per-PR Semgrep scan on only files changed in this PR.
        semgrep_status = "failed" if not checked_out else "skipped"
        pr_semgrep: List[Dict[str, Any]] = []
        semgrep_exec_time: float = 0.0
        if checked_out and changed_filenames:
            pr_file_paths = [
                os.path.join(tmp_dir, fn.replace("/", os.sep))
                for fn in changed_filenames
            ]
            semgrep_scan_result = scanner_orchestrator.semgrep.scan_files(pr_file_paths)
            pr_semgrep = scanner_orchestrator._to_semgrep_finding_list(semgrep_scan_result)
            semgrep_exec_time = semgrep_scan_result.get("execution_time", 0.0)
            semgrep_status = _normalize_status(semgrep_scan_result.get("status", "success"))

        # Run Snyk per-PR only when dependency manifests changed.
        pr_snyk, snyk_exec_time, snyk_status = _snyk_for_pr(changed_filenames, checked_out)
        snyk_counts = _severity_counts(pr_snyk)
        semgrep_counts = _severity_counts(pr_semgrep)

        # Derive ML features from real PR + scanner signals.
        features = {
            "files_changed": changed_files_count or len(files),
            "lines_added": additions,
            "lines_deleted": deletions,
            "commit_count": commit_count,
            "author_reputation": _get_user_reputation(author),
            "time_of_day": created.hour,
            "day_of_week": created.weekday(),
            "has_test_changes": int(has_tests),
            "num_issues": (
                comment_count
                + review_comment_count
                + len(pr_snyk)
                + len(pr_semgrep)
            ),
            "num_severity": (
                sensitive
                + snyk_counts["critical"]
                + snyk_counts["high"]
                + semgrep_counts["critical"]
                + semgrep_counts["high"]
            ),
            "lang_ratio": lang_ratio,
            "historical_vuln_rate": round(sec_keywords / max(len(SECURITY_KEYWORDS), 1), 4),
        }

        # Run ML prediction
        result = ml_predictor.predict_risk(features)

        if pr_snyk:
            security_findings.append(f"Snyk found {len(pr_snyk)} dependency vulnerabilities")
        if pr_semgrep:
            security_findings.append(f"Semgrep found {len(pr_semgrep)} code findings")

        pr_scanner_results = [
            _scanner_result_row(
                tool="snyk",
                pr_num=pr_num,
                findings=pr_snyk,
                execution_time=snyk_exec_time,
                status=snyk_status,
            ),
            _scanner_result_row(
                tool="semgrep",
                pr_num=pr_num,
                findings=pr_semgrep,
                execution_time=semgrep_exec_time,
                status=semgrep_status,
            ),
        ]

        predictions.append(PRPrediction(
            pr_number=pr_num,
            title=title[:100],
            author=author,
            risk_score=result["risk_score"],
            risk_label=result["risk_label"],
            risk_percentage=result["risk_percentage"],
            feature_importance=result["feature_importance"],
            features=features,
            security_findings=security_findings,
            url=merged_pr.get("html_url", f"https://github.com/{repo}/pull/{pr_num}"),
            created_at=str(created_raw),
            state=merged_pr.get("state", "unknown"),
            model_version=result["model_version"],
            using_fallback=result["using_fallback"],
            snyk_vulnerabilities=pr_snyk,
            semgrep_findings=pr_semgrep,
            scanner_results=pr_scanner_results,
        ))

    # ── Clean up cloned repo now that all per-PR semgrep scans are done ──
    if tmp_dir:
        try:
            shutil.rmtree(tmp_dir, ignore_errors=True)
        except Exception:
            pass
        tmp_dir = None

    high_risk = sum(1 for p in predictions if p.risk_label == "high")
    low_risk = len(predictions) - high_risk
    avg_score = sum(p.risk_score for p in predictions) / len(predictions) if predictions else 0

    # ── Persist predictions to the database ──────────────────────────────
    try:
        for pred in predictions:
            # Upsert: check if this PR already exists
            existing = (
                db.query(PRModel)
                .filter(PRModel.repo_name == repo, PRModel.pr_number == pred.pr_number)
                .first()
            )
            risk_pct = round(pred.risk_percentage, 1)
            if pred.risk_label == "high":
                verdict = "BLOCK"
            elif pred.risk_percentage >= 40:
                verdict = "MANUAL_REVIEW"
            else:
                verdict = "AUTO_APPROVE"

            if existing:
                existing.risk_score = risk_pct
                existing.verdict = verdict
                existing.status = "completed"
                existing.author_name = pred.author
                existing.files_changed = int(pred.features.get("files_changed", 0))
                existing.lines_added = int(pred.features.get("lines_added", 0))
                existing.lines_deleted = int(pred.features.get("lines_deleted", 0))
                existing.feature_importance = pred.feature_importance
                pr_record = existing
            else:
                pr_record = PRModel(
                    repo_name=repo,
                    pr_number=pred.pr_number,
                    pr_url=pred.url,
                    status="completed",
                    risk_score=risk_pct,
                    verdict=verdict,
                    author_name=pred.author,
                    files_changed=int(pred.features.get("files_changed", 0)),
                    lines_added=int(pred.features.get("lines_added", 0)),
                    lines_deleted=int(pred.features.get("lines_deleted", 0)),
                    feature_importance=pred.feature_importance,
                )
                db.add(pr_record)
                db.flush()  # get the id assigned

            # Remove old scan results for this PR to avoid duplicates
            db.query(ScanResultModel).filter(ScanResultModel.pr_id == pr_record.id).delete()

            scanner_rows = {
                str(row.get("name", "")).lower(): row
                for row in pred.scanner_results
            }

            snyk_row = scanner_rows.get("snyk", {})
            snyk_status = _normalize_status(snyk_row.get("status", "success"))
            snyk_counts = _severity_counts(pred.snyk_vulnerabilities)
            snyk_summary = (
                "Snyk skipped (no manifest change in this PR)"
                if snyk_status == "skipped"
                else (
                    "Snyk scan failed"
                    if snyk_status == "failed"
                    else f"Snyk found {len(pred.snyk_vulnerabilities)} vulnerabilities"
                )
            )
            db.add(ScanResultModel(
                pr_id=pr_record.id,
                tool="snyk",
                findings=pred.snyk_vulnerabilities,
                severity=_top_severity(snyk_counts),
                summary=snyk_summary,
                execution_time=float(snyk_row.get("executionTime", 0.0) or 0.0),
                severity_counts=snyk_counts if snyk_status == "success" else None,
            ))

            semgrep_row = scanner_rows.get("semgrep", {})
            semgrep_status = _normalize_status(semgrep_row.get("status", "success"))
            semgrep_counts = _severity_counts(pred.semgrep_findings)
            semgrep_summary = (
                "Semgrep skipped"
                if semgrep_status == "skipped"
                else (
                    "Semgrep scan failed"
                    if semgrep_status == "failed"
                    else f"Semgrep found {len(pred.semgrep_findings)} findings"
                )
            )
            db.add(ScanResultModel(
                pr_id=pr_record.id,
                tool="semgrep",
                findings=pred.semgrep_findings,
                severity=_top_severity(semgrep_counts),
                summary=semgrep_summary,
                execution_time=float(semgrep_row.get("executionTime", 0.0) or 0.0),
                severity_counts=semgrep_counts if semgrep_status == "success" else None,
            ))

        db.commit()
        logger.info("Saved %d PR predictions to database for repo %s", len(predictions), repo)
    except Exception as db_err:
        logger.error("Failed to save predictions to DB: %s", db_err)
        db.rollback()

    return AnalyzeGitHubResponse(
        repo=repo,
        total_prs_analyzed=len(predictions),
        high_risk_count=high_risk,
        low_risk_count=low_risk,
        avg_risk_score=round(avg_score, 4),
        predictions=predictions,
    )
