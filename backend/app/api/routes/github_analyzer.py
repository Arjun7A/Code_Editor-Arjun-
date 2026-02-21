"""
GitHub Repo Analyzer — /api/analyze_github
Accepts a GitHub repo URL/owner (e.g., "facebook/react"),
fetches recent PRs, runs ML predictions, and returns results.
"""
from fastapi import APIRouter, HTTPException
from pydantic import BaseModel, Field
from typing import List, Optional, Dict, Any
import requests
import os
import numpy as np
import logging
from datetime import datetime, timezone
from app.services.ml_predictor import MLPredictor
from app.core.config import settings

logger = logging.getLogger(__name__)
router = APIRouter()

ml_predictor = MLPredictor(model_path=settings.ML_MODEL_PATH)

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


# ── Main endpoint ────────────────────────────────────────────────────────

@router.post("/analyze_github", response_model=AnalyzeGitHubResponse)
async def analyze_github_repo(request: AnalyzeGitHubRequest):
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

    predictions: List[PRPrediction] = []

    for pr in prs:
        pr_num = pr["number"]
        title = pr.get("title", "")
        author = pr["user"]["login"]
        created = datetime.fromisoformat(pr["created_at"].replace("Z", "+00:00"))

        # Get files changed in this PR
        files = _api_get(
            f"{GITHUB_API}/repos/{repo}/pulls/{pr_num}/files",
            {"per_page": 50},
        ) or []

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

        body = pr.get("body") or ""
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
        if pr.get("additions", 0) > 500:
            security_findings.append(f"Large PR with {pr.get('additions', 0)} lines added — harder to review")

        features = {
            "files_changed": pr.get("changed_files", len(files)),
            "lines_added": pr.get("additions", 0),
            "lines_deleted": pr.get("deletions", 0),
            "commit_count": pr.get("commits", 1),
            "author_reputation": _get_user_reputation(author),
            "time_of_day": created.hour,
            "day_of_week": created.weekday(),
            "has_test_changes": int(has_tests),
            "num_issues": pr.get("comments", 0) + pr.get("review_comments", 0),
            "num_severity": sensitive,
            "lang_ratio": lang_ratio,
            "historical_vuln_rate": round(sec_keywords / max(len(SECURITY_KEYWORDS), 1), 4),
        }

        # Run ML prediction
        result = ml_predictor.predict_risk(features)

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
            url=pr.get("html_url", f"https://github.com/{repo}/pull/{pr_num}"),
            created_at=pr["created_at"],
            state=pr.get("state", "unknown"),
            model_version=result["model_version"],
            using_fallback=result["using_fallback"],
        ))

    high_risk = sum(1 for p in predictions if p.risk_label == "high")
    low_risk = len(predictions) - high_risk
    avg_score = sum(p.risk_score for p in predictions) / len(predictions) if predictions else 0

    return AnalyzeGitHubResponse(
        repo=repo,
        total_prs_analyzed=len(predictions),
        high_risk_count=high_risk,
        low_risk_count=low_risk,
        avg_risk_score=round(avg_score, 4),
        predictions=predictions,
    )
