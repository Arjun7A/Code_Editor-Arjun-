from fastapi import APIRouter, Depends, HTTPException, BackgroundTasks
from fastapi.encoders import jsonable_encoder
from sqlalchemy.orm import Session
from sqlalchemy import func
from typing import List, Dict, Any
from app.core.database import get_db, SessionLocal
from app.models.database_models import PullRequest, ScanResult, AuditLog
from app.schemas.pr_schemas import (
    PRAnalyzeRequest,
    PRAnalysisResponse,
    PRAnalysisStatusResponse,
    ScanRequest,
    ScanResponse,
    DashboardStatsResponse,
)
from app.services.scanner_orchestrator import ScannerOrchestrator
from app.services.ml_predictor import MLPredictor
from app.services.ai_agent import AIAgent
from app.services.git_metadata import extract_repo_metadata
from app.services.policy_engine import PolicyEngine
from app.services.blockchain_service import BlockchainService
from app.services.cache_service import cache
from app.core.config import settings
from datetime import datetime, timedelta
import tempfile
import os
import subprocess
import logging
import requests

logger = logging.getLogger(__name__)

router = APIRouter()
scanner = ScannerOrchestrator()
ml_predictor = MLPredictor(model_path=settings.ML_MODEL_PATH)
ai_agent = AIAgent(
    api_key=settings.XAI_API_KEY,
    model=settings.GROK_MODEL,
    base_url=settings.XAI_API_BASE_URL,
)
policy_engine = PolicyEngine(policy_path=settings.POLICY_RULES_PATH)
blockchain_service = BlockchainService()

GITHUB_API = "https://api.github.com"
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

_CACHE_DASHBOARD_KEY = "dashboard-stats:v1"
_CACHE_POLICY_RULES_KEY = "policy-rules:v1"
_CACHE_RESULTS_PREFIX = "results:v1:"
_CACHE_RESULT_BY_ID_PREFIX = "result:v1:"


def _invalidate_read_caches() -> None:
    """Drop caches affected by new scans/policy decisions."""
    cache.delete(_CACHE_DASHBOARD_KEY)
    cache.delete(_CACHE_POLICY_RULES_KEY)
    cache.delete_prefix(_CACHE_RESULTS_PREFIX)
    cache.delete_prefix(_CACHE_RESULT_BY_ID_PREFIX)


def _severity_counts(findings: list) -> dict:
    counts = {"critical": 0, "high": 0, "medium": 0, "low": 0}
    for finding in findings:
        sev = str(finding.get("severity", "low")).lower()
        if sev in counts:
            counts[sev] += 1
    return counts


def _top_severity(severity_counts: dict) -> str:
    for sev in ("critical", "high", "medium", "low"):
        if severity_counts.get(sev, 0) > 0:
            return sev
    return "info"


def _derive_repo_clone_url(url: str) -> str:
    """
    Accept repository URLs or GitHub PR URLs and return a cloneable repo URL.
    """
    clean = url.strip()
    if "://" not in clean and clean.count("/") == 1:
        return f"https://github.com/{clean}"
    if "github.com" not in clean:
        return clean
    if "/pull/" in clean:
        clean = clean.split("/pull/")[0]
    return clean.rstrip("/")


def _author_reputation_from_repo(commit_count: int) -> float:
    """
    Fallback estimate for author reputation when no GitHub author profile is available.
    """
    return round(min(1.0, 0.25 + (max(commit_count, 1) / 500.0)), 3)


def _github_headers() -> Dict[str, str]:
    token = (settings.GITHUB_TOKEN or os.environ.get("GITHUB_TOKEN", "")).strip()
    headers = {
        "Accept": "application/vnd.github.v3+json",
        "User-Agent": "SecurityGate-API",
        "X-GitHub-Api-Version": "2022-11-28",
    }
    if token:
        headers["Authorization"] = f"token {token}"
    return headers


def _api_get(url: str, params: Dict[str, Any] | None = None) -> Any:
    try:
        resp = requests.get(url, headers=_github_headers(), params=params, timeout=30)
        if resp.status_code == 200:
            return resp.json()
        detail = ""
        try:
            payload = resp.json()
            if isinstance(payload, dict):
                detail = str(payload.get("message", "")).strip()
        except Exception:
            detail = ""
        rate_remaining = resp.headers.get("X-RateLimit-Remaining", "")
        logger.warning(
            "GitHub API returned %s for %s (remaining=%s, detail=%s)",
            resp.status_code,
            url,
            rate_remaining or "?",
            detail[:180] if detail else "-",
        )
        return None
    except Exception as exc:
        logger.warning("GitHub API request failed for %s: %s", url, exc)
        return None


def _derive_repo_slug(repo_name: str, repo_url: str) -> str:
    repo = (repo_name or "").strip().strip("/").replace(".git", "")
    if repo.count("/") == 1:
        return repo

    raw = (repo_url or "").strip()
    if "://" not in raw and raw.count("/") == 1:
        return raw.replace(".git", "")
    if "github.com" not in raw:
        return ""

    path = raw.split("github.com/", 1)[-1].strip("/")
    if "/pull/" in path:
        path = path.split("/pull/", 1)[0]
    parts = [p for p in path.split("/") if p]
    if len(parts) >= 2:
        return f"{parts[0]}/{parts[1].replace('.git', '')}"
    return ""


def _fetch_pr_detail(repo: str, pr_number: int) -> Dict[str, Any]:
    payload = _api_get(f"{GITHUB_API}/repos/{repo}/pulls/{pr_number}")
    return payload if isinstance(payload, dict) else {}


def _fetch_pr_files(repo: str, pr_number: int) -> List[Dict[str, Any]]:
    files: List[Dict[str, Any]] = []
    page = 1
    while page <= 20:
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


def _git_stdout(repo_dir: str, args: List[str], timeout: int = 30) -> str:
    result = subprocess.run(
        args,
        cwd=repo_dir,
        check=True,
        capture_output=True,
        text=True,
        timeout=timeout,
    )
    return (result.stdout or "").strip()


def _resolve_base_ref(repo_dir: str) -> str:
    try:
        remote_head = _git_stdout(
            repo_dir,
            ["git", "symbolic-ref", "refs/remotes/origin/HEAD"],
            timeout=20,
        )
        if remote_head.startswith("refs/remotes/"):
            return remote_head.replace("refs/remotes/", "", 1)
    except Exception:
        pass

    for candidate in ("origin/main", "origin/master", "main", "master"):
        try:
            _git_stdout(repo_dir, ["git", "rev-parse", "--verify", candidate], timeout=20)
            return candidate
        except Exception:
            continue

    return ""


def _collect_pr_files_from_git(repo_dir: str) -> List[Dict[str, Any]]:
    """
    Build PR-like file objects from local git history when GitHub API files are unavailable.
    """
    base_ref = _resolve_base_ref(repo_dir)
    if not base_ref:
        return []

    try:
        merge_base = _git_stdout(
            repo_dir,
            ["git", "merge-base", "HEAD", base_ref],
            timeout=30,
        )
        if not merge_base:
            return []
        diff_base = f"{merge_base}..HEAD"
        name_status = _git_stdout(
            repo_dir,
            ["git", "diff", "--name-status", diff_base],
            timeout=60,
        )
    except Exception as exc:
        logger.warning("Git fallback diff discovery failed: %s", exc)
        return []

    status_map = {
        "A": "added",
        "M": "modified",
        "D": "removed",
        "R": "renamed",
        "C": "copied",
        "T": "modified",
        "U": "modified",
    }
    files: List[Dict[str, Any]] = []

    for raw_line in name_status.splitlines():
        line = raw_line.strip()
        if not line:
            continue
        parts = line.split("\t")
        if len(parts) < 2:
            continue

        status_token = parts[0].strip().upper()
        status_key = status_token[:1] if status_token else "M"
        filename = parts[-1].strip()
        if not filename:
            continue

        try:
            patch = _git_stdout(
                repo_dir,
                ["git", "diff", "--unified=3", diff_base, "--", filename],
                timeout=90,
            )
        except Exception:
            patch = ""

        files.append(
            {
                "filename": filename,
                "status": status_map.get(status_key, "modified"),
                "patch": patch,
            }
        )
        if len(files) >= 400:
            break

    return files


def _manifest_touched(changed_filenames: List[str]) -> bool:
    def _is_manifest(filename: str) -> bool:
        base = filename.lower().rsplit("/", 1)[-1]
        if base in _MANIFEST_NAMES:
            return True
        if base.startswith("requirements") and base.endswith(".txt"):
            return True
        return False

    return any(_is_manifest(f) for f in changed_filenames)


def _checkout_pr_head(repo_dir: str, pr_number: int) -> bool:
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


def _normalize_status(raw: str) -> str:
    status = str(raw or "").lower()
    if status in ("success", "skipped", "failed"):
        return status
    if status == "error":
        return "failed"
    return "success"


def _to_int(value: Any, default: int = 0) -> int:
    try:
        return int(value)
    except Exception:
        return default


def _resolve_commit_hash(pr_detail: Dict[str, Any], repo_dir: str) -> str:
    head = (pr_detail.get("head") or {}) if isinstance(pr_detail, dict) else {}
    head_sha = str(head.get("sha") or "").strip()
    if head_sha:
        return head_sha

    try:
        result = subprocess.run(
            ["git", "rev-parse", "HEAD"],
            cwd=repo_dir,
            check=True,
            capture_output=True,
            text=True,
            timeout=30,
        )
        return (result.stdout or "").strip() or "unknown"
    except Exception:
        return "unknown"


# ══════════════════════════════════════════════════════════════════════════
#  /api/scan  – direct scanner endpoint (Snyk + Semgrep only)
# ══════════════════════════════════════════════════════════════════════════

@router.post("/scan", response_model=ScanResponse)
async def scan_code(request: ScanRequest):
    """
    Run Snyk + Semgrep on the provided code/directory and return
    structured results ready for the frontend to consume directly.

    Accepts either:
      - `code`     : raw source-code string to scan in-memory
      - `repo_url` : a cloneable git URL (public repo)
      - `path`     : a server-side absolute path (for dev/testing)
    """
    import time, uuid

    start = time.time()

    # ── Determine what to scan ────────────────────────────────────────────
    if request.code:
        # In-memory code scan
        results = await scanner.run_all_scans(
            project_path=tempfile.gettempdir(),
            code_content=request.code,
            filename_hint=request.filename or "code.py",
        )
    elif request.repo_url:
        # Clone repo and scan
        with tempfile.TemporaryDirectory() as tmp:
            try:
                subprocess.run(
                    ["git", "clone", "--depth", "1", request.repo_url, tmp],
                    check=True, capture_output=True, timeout=120,
                )
            except Exception as exc:
                raise HTTPException(
                    status_code=422,
                    detail=f"Failed to clone repository: {exc}",
                )
            results = await scanner.run_all_scans(tmp)
    elif request.path:
        if not os.path.exists(request.path):
            raise HTTPException(status_code=422, detail="Provided path does not exist")
        results = await scanner.run_all_scans(request.path)
    else:
        raise HTTPException(
            status_code=422,
            detail="Provide one of: code, repo_url, or path",
        )

    summary = results.get("summary", {})
    elapsed = round(time.time() - start, 2)

    return ScanResponse(
        scan_id=str(uuid.uuid4()),
        status="completed",
        elapsed_seconds=elapsed,
        snyk_vulnerabilities=results.get("snykVulnerabilities", []),
        semgrep_findings=results.get("semgrepFindings", []),
        scanner_results=results.get("scannerResults", []),
        summary=summary,
    )


# ══════════════════════════════════════════════════════════════════════════
#  /api/dashboard-stats – real stats from the DB
# ══════════════════════════════════════════════════════════════════════════

@router.get("/dashboard-stats", response_model=DashboardStatsResponse)
async def get_dashboard_stats(db: Session = Depends(get_db)):
    """
    Return live statistics computed from the database.
    Used by the frontend Dashboard's stats cards and charts.
    """
    cached = cache.get_json(_CACHE_DASHBOARD_KEY)
    if cached is not None:
        return cached

    total = db.query(func.count(PullRequest.id)).scalar() or 0
    approved = (
        db.query(func.count(PullRequest.id))
        .filter(PullRequest.verdict == "AUTO_APPROVE")
        .scalar() or 0
    )
    blocked = (
        db.query(func.count(PullRequest.id))
        .filter(PullRequest.verdict == "BLOCK")
        .scalar() or 0
    )
    manual = (
        db.query(func.count(PullRequest.id))
        .filter(PullRequest.verdict == "MANUAL_REVIEW")
        .scalar() or 0
    )
    avg_risk = (
        db.query(func.avg(PullRequest.risk_score))
        .filter(PullRequest.risk_score.isnot(None))
        .scalar() or 0.0
    )

    # Critical issues = scan results with severity "critical"
    critical_issues = (
        db.query(func.count(ScanResult.id))
        .filter(ScanResult.severity == "critical")
        .scalar() or 0
    )

    # Scans today
    today_start = datetime.utcnow().replace(hour=0, minute=0, second=0, microsecond=0)
    scans_today = (
        db.query(func.count(PullRequest.id))
        .filter(PullRequest.created_at >= today_start)
        .scalar() or 0
    )

    # Severity breakdown across all scan results
    severity_rows = (
        db.query(ScanResult.severity, func.count(ScanResult.id))
        .group_by(ScanResult.severity)
        .all()
    )
    severity_breakdown = {row[0]: row[1] for row in severity_rows if row[0]}

    # Verdict distribution
    verdict_rows = (
        db.query(PullRequest.verdict, func.count(PullRequest.id))
        .filter(PullRequest.verdict.isnot(None))
        .group_by(PullRequest.verdict)
        .all()
    )
    verdict_map = {row[0]: row[1] for row in verdict_rows}

    # Risk trend – last 30 days average daily risk score
    risk_trend = []
    for i in range(29, -1, -1):
        day = datetime.utcnow().date() - timedelta(days=i)
        day_start = datetime.combine(day, datetime.min.time())
        day_end = day_start + timedelta(days=1)
        avg = (
            db.query(func.avg(PullRequest.risk_score))
            .filter(
                PullRequest.created_at >= day_start,
                PullRequest.created_at < day_end,
                PullRequest.risk_score.isnot(None),
            )
            .scalar()
        )
        risk_trend.append({
            "date": day.isoformat(),
            "value": round(float(avg), 1) if avg else 0.0,
            "label": day.strftime("%b %d"),
        })

    # Scanner metrics from stored scan results
    tool_stats = {}
    for tool_name in ("snyk", "semgrep"):
        total_tool = (
            db.query(func.count(ScanResult.id))
            .filter(ScanResult.tool == tool_name)
            .scalar() or 0
        )
        avg_time = (
            db.query(func.avg(ScanResult.execution_time))
            .filter(ScanResult.tool == tool_name, ScanResult.execution_time.isnot(None))
            .scalar() or 0.0
        )
        # Count scans that completed without error (severity_counts is not null)
        success_count = (
            db.query(func.count(ScanResult.id))
            .filter(ScanResult.tool == tool_name, ScanResult.severity_counts.isnot(None))
            .scalar() or 0
        )
        tool_stats[tool_name] = {
            "total": total_tool,
            "success": success_count,
            "avg_time": round(float(avg_time), 2),
        }

    response = DashboardStatsResponse(
        total_prs=total,
        approved=approved,
        blocked=blocked,
        manual_review=manual,
        avg_risk_score=round(float(avg_risk), 1),
        critical_issues=critical_issues,
        scans_today=scans_today,
        severity_breakdown=severity_breakdown,
        verdict_distribution=[
            {"verdict": k, "count": v} for k, v in verdict_map.items()
        ],
        risk_trend=risk_trend,
        scanner_stats=tool_stats,
    )
    cache.set_json(
        _CACHE_DASHBOARD_KEY,
        jsonable_encoder(response),
        settings.CACHE_TTL_DASHBOARD_SECONDS,
    )
    return response


# ══════════════════════════════════════════════════════════════════════════
#  /api/results  – paginated PR list
# ══════════════════════════════════════════════════════════════════════════

@router.get("/results", response_model=List[PRAnalysisResponse])
async def list_all_results(
    skip: int = 0,
    limit: int = 100,
    db: Session = Depends(get_db),
):
    """List all PR analysis results (paginated)."""
    cache_key = f"{_CACHE_RESULTS_PREFIX}{skip}:{limit}"
    cached = cache.get_json(cache_key)
    if cached is not None:
        return cached

    prs = (
        db.query(PullRequest)
        .order_by(PullRequest.updated_at.desc(), PullRequest.created_at.desc())
        .offset(skip)
        .limit(limit)
        .all()
    )
    cache.set_json(
        cache_key,
        jsonable_encoder(prs),
        settings.CACHE_TTL_RESULTS_SECONDS,
    )
    return prs


@router.get("/results/{pr_id}", response_model=PRAnalysisResponse)
async def get_analysis_results(pr_id: int, db: Session = Depends(get_db)):
    """Get analysis results for a specific PR."""
    cache_key = f"{_CACHE_RESULT_BY_ID_PREFIX}{pr_id}"
    cached = cache.get_json(cache_key)
    if cached is not None:
        return cached

    pr = db.query(PullRequest).filter(PullRequest.id == pr_id).first()
    if not pr:
        raise HTTPException(status_code=404, detail=f"PR {pr_id} not found")
    cache.set_json(
        cache_key,
        jsonable_encoder(pr),
        settings.CACHE_TTL_RESULTS_SECONDS,
    )
    return pr


@router.get("/blockchain/verify/{pr_id}")
async def verify_blockchain_record(pr_id: int, db: Session = Depends(get_db)):
    """Verify a PR's blockchain audit record."""
    audit = db.query(AuditLog).filter(AuditLog.pr_id == pr_id).first()
    if not audit:
        raise HTTPException(status_code=404, detail=f"No audit log found for PR {pr_id}")

    verification = blockchain_service.verify_transaction(
        tx_hash=audit.blockchain_tx,
        record_hash=audit.blockchain_hash,
        fallback_timestamp=audit.timestamp.isoformat() if audit.timestamp else None,
    )
    verification["pr_id"] = pr_id
    verification["decision"] = audit.decision
    return verification


@router.get("/policy/rules")
async def get_policy_rules():
    """Expose active policy rules used by the verdict engine."""
    cached = cache.get_json(_CACHE_POLICY_RULES_KEY)
    if cached is not None:
        return cached

    policy_engine.reload()
    payload = {
        "default_action": policy_engine.default_action,
        "rules": [
            {
                "name": rule.name,
                "description": rule.description,
                "enabled": rule.enabled,
                "priority": rule.priority,
                "condition": rule.condition,
                "action": rule.action,
            }
            for rule in policy_engine.rules
        ],
    }
    cache.set_json(
        _CACHE_POLICY_RULES_KEY,
        payload,
        settings.CACHE_TTL_POLICY_SECONDS,
    )
    return payload


# ══════════════════════════════════════════════════════════════════════════
#  /api/analyze  – submit a PR for background analysis
# ══════════════════════════════════════════════════════════════════════════

async def run_analysis(pr_id: int, repo_url: str):
    """
    Background task: clone repository, checkout submitted PR head, run scanners
    in PR-specific mode, compute ML features, and persist results.
    """
    db = SessionLocal()
    try:
        pr = db.query(PullRequest).filter(PullRequest.id == pr_id).first()
        if not pr:
            return

        clone_url = _derive_repo_clone_url(repo_url)
        repo_slug = _derive_repo_slug(pr.repo_name, pr.pr_url or repo_url)
        pr_number = max(1, _to_int(pr.pr_number, 1))

        with tempfile.TemporaryDirectory() as temp_dir:
            try:
                subprocess.run(
                    ["git", "clone", "--depth", "1", clone_url, temp_dir],
                    check=True, capture_output=True, timeout=120,
                )
            except Exception as exc:
                logger.error("Clone failed for PR %s (%s): %s", pr_id, clone_url, exc)
                pr.status = "error"
                pr.verdict = "ERROR"
                db.commit()
                return

            checked_out = _checkout_pr_head(temp_dir, pr_number)
            if not checked_out:
                logger.error("Could not checkout PR head for PR %s", pr_id)
                pr.status = "error"
                pr.verdict = "ERROR"
                db.commit()
                return

            # PR details/files from GitHub API (best effort).
            pr_detail: Dict[str, Any] = {}
            pr_files: List[Dict[str, Any]] = []
            if repo_slug:
                pr_detail = _fetch_pr_detail(repo_slug, pr_number)
                pr_files = _fetch_pr_files(repo_slug, pr_number)
            if not pr_files:
                git_fallback_files = _collect_pr_files_from_git(temp_dir)
                if git_fallback_files:
                    logger.info(
                        "Using git diff fallback for PR %s (%d file(s))",
                        pr_id,
                        len(git_fallback_files),
                    )
                    pr_files = git_fallback_files

            changed_filenames = [
                f.get("filename", "") for f in pr_files if f.get("filename")
            ]

            # ── AI Agent analysis (runs on GitHub diff patches, no disk access needed) ──
            ai_result = await ai_agent.analyze_pr_diff(
                pr_files, repo=repo_slug, pr_number=pr_number
            )

            # Repository metadata from checked-out PR revision.
            metadata = extract_repo_metadata(temp_dir)

            # Semgrep on changed files only.
            semgrep_result: Dict[str, Any]
            if changed_filenames:
                pr_file_paths = [
                    os.path.join(temp_dir, fn.replace("/", os.sep))
                    for fn in changed_filenames
                ]
                semgrep_result = scanner.semgrep.scan_files(pr_file_paths)
            else:
                semgrep_result = {
                    "tool": "semgrep",
                    "findings": [],
                    "severity": "info",
                    "summary": "Semgrep skipped (no changed files found for this PR)",
                    "total_count": 0,
                    "severity_counts": {"critical": 0, "high": 0, "medium": 0, "low": 0},
                    "execution_time": 0.0,
                    "status": "skipped",
                }

            # Snyk runs only when dependency manifests changed (unless forced on all PRs).
            snyk_result: Dict[str, Any]
            if settings.SNYK_RUN_ALL_PRS or _manifest_touched(changed_filenames):
                snyk_result = scanner.snyk.scan_dependencies(temp_dir)
            else:
                snyk_result = {
                    "tool": "snyk",
                    "findings": [],
                    "severity": "info",
                    "summary": "Snyk skipped (no manifest change in this PR)",
                    "total_count": 0,
                    "severity_counts": {"critical": 0, "high": 0, "medium": 0, "low": 0},
                    "execution_time": 0.0,
                    "status": "skipped",
                }

            snyk_status = _normalize_status(snyk_result.get("status", "success"))
            semgrep_status = _normalize_status(semgrep_result.get("status", "success"))

            snyk_findings = scanner._to_vulnerability_list(snyk_result)
            semgrep_findings = scanner._to_semgrep_finding_list(semgrep_result)

            # Merge scanner and metadata signals for ML features.
            snyk_counts = _severity_counts(snyk_findings)
            semgrep_counts = _severity_counts(semgrep_findings)
            total_findings = len(snyk_findings) + len(semgrep_findings)
            high_critical = (
                snyk_counts["critical"] + snyk_counts["high"]
                + semgrep_counts["critical"] + semgrep_counts["high"]
            )

            additions = _to_int(pr_detail.get("additions", metadata.get("lines_added", 0)))
            deletions = _to_int(pr_detail.get("deletions", metadata.get("lines_deleted", 0)))
            changed_files = _to_int(
                pr_detail.get(
                    "changed_files",
                    len(changed_filenames) or metadata.get("files_changed", 0),
                )
            )
            commit_count = max(1, _to_int(pr_detail.get("commits", metadata.get("commit_count", 1)), 1))
            has_test_changes = (
                any(
                    any(token in fn.lower() for token in ("test", "spec", "__test__"))
                    for fn in changed_filenames
                )
                if changed_filenames
                else bool(metadata.get("has_test_changes", False))
            )
            comment_count = _to_int(pr_detail.get("comments", 0))
            review_comment_count = _to_int(pr_detail.get("review_comments", 0))
            author_name = (
                (pr_detail.get("user") or {}).get("login")
                or metadata.get("author_name")
                or "unknown"
            )

            ml_features = {
                "files_changed": changed_files,
                "lines_added": additions,
                "lines_deleted": deletions,
                "commit_count": commit_count,
                "author_reputation": _author_reputation_from_repo(commit_count),
                "time_of_day": datetime.utcnow().hour,
                "day_of_week": datetime.utcnow().weekday(),
                "has_test_changes": int(has_test_changes),
                "num_issues": int(comment_count + review_comment_count + total_findings),
                "num_severity": int(high_critical),
                "lang_ratio": float(metadata.get("lang_ratio", 0.5)),
                "historical_vuln_rate": (
                    round(high_critical / total_findings, 4)
                    if total_findings > 0 else 0.0
                ),
            }

            ml_result = ml_predictor.predict_risk(ml_features)
            risk_score = ml_result["risk_score"] * 100

            # AI agent severity signals
            ai_findings = ai_result.get("findings", [])
            ai_sev_counts = ai_result.get("severity_counts", {"critical": 0, "high": 0, "medium": 0, "low": 0})
            ai_status = ai_result.get("status", "skipped")
            ai_provider = str(ai_result.get("provider", "none"))
            ai_model = ai_result.get("model")
            ai_summary = str(ai_result.get('summary', ''))
            # High-confidence security findings from AI agent
            ai_confirmed_high = sum(
                1 for f in ai_findings
                if f.get("type") == "security"
                and f.get("confidence", 0) >= 0.8
                and f.get("severity") in ("critical", "high")
            )

            critical_count = (
                snyk_counts["critical"]
                + semgrep_counts["critical"]
                + ai_sev_counts.get("critical", 0)
            )
            high_count = (
                snyk_counts["high"]
                + semgrep_counts["high"]
                + ai_sev_counts.get("high", 0)
            )
            medium_count = (
                snyk_counts["medium"]
                + semgrep_counts["medium"]
                + ai_sev_counts.get("medium", 0)
            )
            low_count = (
                snyk_counts["low"]
                + semgrep_counts["low"]
                + ai_sev_counts.get("low", 0)
            )
            policy_signals = {
                "critical_count": critical_count,
                "high_count": high_count,
                "medium_count": medium_count,
                "low_count": low_count,
                "risk_score": round(risk_score, 1),
                "ai_high_security_findings": ai_confirmed_high,
            }
            policy_decision = policy_engine.evaluate(policy_signals)

            pr.status = "completed"
            pr.risk_score = round(risk_score, 1)
            pr.author_name = author_name
            pr.files_changed = ml_features["files_changed"]
            pr.lines_added = ml_features["lines_added"]
            pr.lines_deleted = ml_features["lines_deleted"]
            pr.feature_importance = ml_result.get("feature_importance", {})
            pr.verdict = policy_decision["verdict"]

            # Replace existing scan rows to keep the latest analysis.
            db.query(ScanResult).filter(ScanResult.pr_id == pr_id).delete()
            snyk_summary = (
                "Snyk skipped (no manifest change in this PR)"
                if snyk_status == "skipped"
                else (
                    "Snyk scan failed"
                    if snyk_status == "failed"
                    else f"Snyk found {len(snyk_findings)} vulnerabilities"
                )
            )
            semgrep_summary = (
                "Semgrep skipped (no changed files found for this PR)"
                if semgrep_status == "skipped"
                else (
                    (
                        f"Semgrep scan failed: {str(semgrep_result.get('error', '')).strip()[:220]}"
                        if str(semgrep_result.get("error", "")).strip()
                        else "Semgrep scan failed"
                    )
                    if semgrep_status == "failed"
                    else f"Semgrep found {len(semgrep_findings)} findings"
                )
            )

            db.add(ScanResult(
                pr_id=pr_id,
                tool="snyk",
                findings=snyk_findings,
                severity=_top_severity(snyk_counts),
                summary=snyk_summary,
                execution_time=float(snyk_result.get("execution_time", 0.0) or 0.0),
                severity_counts=snyk_counts if snyk_status == "success" else None,
            ))
            db.add(ScanResult(
                pr_id=pr_id,
                tool="semgrep",
                findings=semgrep_findings,
                severity=_top_severity(semgrep_counts),
                summary=semgrep_summary,
                execution_time=float(semgrep_result.get("execution_time", 0.0) or 0.0),
                severity_counts=semgrep_counts if semgrep_status == "success" else None,
            ))
            db.add(ScanResult(
                pr_id=pr_id,
                tool="ai_agent",
                findings=ai_findings,
                severity=ai_result.get("severity", "info"),
                summary=ai_summary,
                execution_time=float(ai_result.get("execution_time", 0.0) or 0.0),
                severity_counts=ai_sev_counts if ai_status == "success" else None,
            ))

            commit_hash = _resolve_commit_hash(pr_detail, temp_dir)
            blockchain_result = blockchain_service.log_decision(
                pr_id=pr_id,
                commit_hash=commit_hash,
                risk_score=pr.risk_score or 0.0,
                verdict=pr.verdict or "UNKNOWN",
                metadata={"repo": pr.repo_name, "pr_number": pr.pr_number},
            )
            risk_payload = {
                "risk_score": pr.risk_score,
                "ml_model_version": ml_result.get("model_version"),
                "ml_features": ml_features,
                "policy": policy_decision,
                "signals": policy_signals,
                "scanner_counts": {
                    "snyk": snyk_counts,
                    "semgrep": semgrep_counts,
                    "ai_agent": ai_sev_counts,
                },
                "ai_provider": ai_provider,
                "ai_model": ai_model,
                "ai_summary": ai_summary,
                "ai_status": ai_status,
                "commit_hash": commit_hash,
                "blockchain": blockchain_result,
            }
            existing_audit = db.query(AuditLog).filter(AuditLog.pr_id == pr_id).first()
            if existing_audit:
                existing_audit.blockchain_hash = blockchain_result.get("record_hash")
                existing_audit.blockchain_tx = blockchain_result.get("tx_hash")
                existing_audit.decision = pr.verdict or "UNKNOWN"
                existing_audit.risk_data = risk_payload
                existing_audit.timestamp = datetime.utcnow()
            else:
                db.add(
                    AuditLog(
                        pr_id=pr_id,
                        blockchain_hash=blockchain_result.get("record_hash"),
                        blockchain_tx=blockchain_result.get("tx_hash"),
                        decision=pr.verdict or "UNKNOWN",
                        risk_data=risk_payload,
                    )
                )

            db.commit()
            _invalidate_read_caches()

    except Exception:
        logger.exception("Background analysis failed for PR %s", pr_id)
        try:
            pr = db.query(PullRequest).filter(PullRequest.id == pr_id).first()
            if pr:
                pr.status = "error"
                pr.verdict = "ERROR"
                db.commit()
                _invalidate_read_caches()
        except Exception:
            db.rollback()
    finally:
        db.close()


@router.post("/analyze", response_model=PRAnalysisStatusResponse, status_code=202)
async def analyze_pull_request(
    request: PRAnalyzeRequest,
    background_tasks: BackgroundTasks,
    db: Session = Depends(get_db),
):
    """Submit a PR for analysis. Returns immediately; analysis runs in background."""
    normalized_repo = (
        _derive_repo_slug(request.repo_name, request.pr_url)
        or request.repo_name.strip().strip("/").replace(".git", "")
    )

    # Upsert by (repo_name, pr_number) so repeated submissions update the same row.
    pr = (
        db.query(PullRequest)
        .filter(
            PullRequest.repo_name == normalized_repo,
            PullRequest.pr_number == request.pr_number,
        )
        .order_by(PullRequest.updated_at.desc())
        .first()
    )

    if pr:
        pr.pr_url = request.pr_url
        pr.status = "pending"
        pr.risk_score = None
        pr.verdict = None
        pr.author_name = None
        pr.files_changed = None
        pr.lines_added = None
        pr.lines_deleted = None
        pr.feature_importance = None
        db.query(ScanResult).filter(ScanResult.pr_id == pr.id).delete()
        db.query(AuditLog).filter(AuditLog.pr_id == pr.id).delete()
    else:
        pr = PullRequest(
            repo_name=normalized_repo,
            pr_number=request.pr_number,
            pr_url=request.pr_url,
            status="pending",
        )
        db.add(pr)

    db.commit()
    _invalidate_read_caches()
    db.refresh(pr)

    background_tasks.add_task(run_analysis, pr.id, request.pr_url)

    return PRAnalysisStatusResponse(
        id=pr.id,
        status="pending",
        risk_score=None,
        verdict=None,
        message=f"PR #{request.pr_number} queued. Poll /api/results/{pr.id} for status.",
    )
