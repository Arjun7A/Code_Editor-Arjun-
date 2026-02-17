"""
Real GitHub PR Data Collector
==============================
Scrapes Pull Request metadata from major open-source repositories
using the GitHub REST API and extracts 12 features for ML training.

Usage:
    1. Set your GitHub token: set GITHUB_TOKEN=ghp_your_token_here
    2. Run: python scripts/collect_real_data.py
    3. Retrain: python scripts/train_model.py

The script collects PRs from repos like tensorflow, kubernetes, react, etc.
and labels them as high/low risk based on real security signals.
"""

import os
import sys
import re
import time
import json
import requests
import pandas as pd
import numpy as np
from datetime import datetime, timezone
from typing import Dict, List, Optional

# ── Configuration ────────────────────────────────────────────────────────────

GITHUB_TOKEN = os.environ.get("GITHUB_TOKEN", "")

# Target repositories (large, active, with security-relevant PRs)
TARGET_REPOS = [
    "facebook/react",
    "tensorflow/tensorflow",
    "kubernetes/kubernetes",
    "nodejs/node",
    "django/django",
    "pallets/flask",
    "expressjs/express",
    "angular/angular",
    "microsoft/vscode",
    "torvalds/linux",
]

# How many PRs to collect per repo (max 100 per API page)
PRS_PER_REPO = 100

# Output paths
BASE_DIR = os.path.join(os.path.dirname(__file__), "..")
OUTPUT_DIR = os.path.join(BASE_DIR, "data", "processed")
RAW_DIR = os.path.join(BASE_DIR, "data", "raw")
OUTPUT_FILE = os.path.join(OUTPUT_DIR, "pr_features.csv")
RAW_FILE = os.path.join(RAW_DIR, "github_prs_raw.json")

# Security-related keywords for labeling
SECURITY_KEYWORDS = [
    "security", "vulnerability", "vuln", "cve", "exploit", "injection",
    "xss", "csrf", "ssrf", "rce", "dos", "ddos", "overflow", "bypass",
    "auth", "authentication", "authorization", "privilege", "escalation",
    "sanitize", "escape", "encrypt", "decrypt", "hash", "token",
    "password", "secret", "credential", "leak", "exposure", "unsafe",
    "malicious", "attack", "patch", "fix", "critical", "severity",
]

# Sensitive file paths that indicate higher risk
SENSITIVE_PATHS = [
    "auth", "login", "session", "token", "crypto", "encrypt", "security",
    "password", "secret", "key", "cert", "ssl", "tls", "oauth",
    "permission", "access", "admin", "config", "env", ".env",
    "network", "http", "socket", "api/v", "middleware",
]

# ── API Helpers ──────────────────────────────────────────────────────────────

GITHUB_API = "https://api.github.com"


def get_headers():
    """Build request headers with authentication."""
    headers = {
        "Accept": "application/vnd.github.v3+json",
        "User-Agent": "SecurityGate-MLDataCollector",
    }
    if GITHUB_TOKEN:
        headers["Authorization"] = f"token {GITHUB_TOKEN}"
    return headers


def api_request(url: str, params: dict = None) -> Optional[dict]:
    """Make a rate-limit-aware GitHub API request."""
    try:
        response = requests.get(url, headers=get_headers(), params=params, timeout=30)

        # Handle rate limiting
        if response.status_code == 403:
            remaining = int(response.headers.get("X-RateLimit-Remaining", 0))
            if remaining == 0:
                reset_time = int(response.headers.get("X-RateLimit-Reset", 0))
                wait_seconds = max(0, reset_time - int(time.time())) + 5
                print(f"    ⏳ Rate limited. Waiting {wait_seconds}s...")
                time.sleep(wait_seconds)
                return api_request(url, params)  # Retry

        if response.status_code == 200:
            return response.json()
        else:
            print(f"    ⚠️  API error {response.status_code}: {url}")
            return None

    except requests.exceptions.RequestException as e:
        print(f"    ⚠️  Request failed: {e}")
        return None


def check_rate_limit():
    """Check and display current rate limit status."""
    data = api_request(f"{GITHUB_API}/rate_limit")
    if data:
        core = data["resources"]["core"]
        remaining = core["remaining"]
        limit = core["limit"]
        reset_at = datetime.fromtimestamp(core["reset"], tz=timezone.utc)
        print(f"  API Rate Limit: {remaining}/{limit} remaining (resets at {reset_at.strftime('%H:%M:%S UTC')})")
        if remaining < 50:
            print("  ⚠️  Low on API calls! Consider reducing PRS_PER_REPO.")
        return remaining
    return 0


# ── Data Collection ──────────────────────────────────────────────────────────

def get_repo_languages(repo: str) -> Dict[str, int]:
    """Get language breakdown for a repository."""
    data = api_request(f"{GITHUB_API}/repos/{repo}/languages")
    return data if data else {}


def get_pr_files(repo: str, pr_number: int) -> List[dict]:
    """Get the list of files changed in a PR."""
    data = api_request(
        f"{GITHUB_API}/repos/{repo}/pulls/{pr_number}/files",
        params={"per_page": 100},
    )
    return data if data else []


def get_user_info(username: str) -> dict:
    """Get user profile info for reputation scoring."""
    data = api_request(f"{GITHUB_API}/users/{username}")
    return data if data else {}


def calculate_author_reputation(user_data: dict) -> float:
    """
    Calculate author reputation score (0-1) based on:
    - Public repos count
    - Followers count
    - Account age
    """
    if not user_data:
        return 0.5

    repos = user_data.get("public_repos", 0)
    followers = user_data.get("followers", 0)
    created_at = user_data.get("created_at", "")

    # Account age in years
    try:
        created = datetime.fromisoformat(created_at.replace("Z", "+00:00"))
        age_years = (datetime.now(timezone.utc) - created).days / 365
    except (ValueError, TypeError):
        age_years = 1

    # Weighted score (normalized to 0-1)
    score = 0.0
    score += min(repos / 100, 1.0) * 0.3       # Repos (max at 100)
    score += min(followers / 500, 1.0) * 0.4    # Followers (max at 500)
    score += min(age_years / 10, 1.0) * 0.3     # Age (max at 10 years)

    return round(max(0.0, min(1.0, score)), 3)


def calculate_lang_ratio(languages: dict) -> float:
    """Calculate JS/PY language ratio from repo language data."""
    total = sum(languages.values()) if languages else 1
    js_bytes = languages.get("JavaScript", 0) + languages.get("TypeScript", 0)
    py_bytes = languages.get("Python", 0)

    if total == 0:
        return 0.5

    # Ratio of JS+TS vs Python (0 = all Python, 1 = all JS)
    web_bytes = js_bytes + py_bytes
    if web_bytes == 0:
        return 0.5

    return round(js_bytes / web_bytes, 3)


def has_test_file_changes(files: List[dict]) -> bool:
    """Check if any changed files are test files."""
    test_patterns = ["test", "spec", "__test__", "_test.", ".test.", "tests/", "spec/"]
    for f in files:
        filename = f.get("filename", "").lower()
        if any(p in filename for p in test_patterns):
            return True
    return False


def count_security_sensitive_files(files: List[dict]) -> int:
    """Count files that touch security-sensitive paths."""
    count = 0
    for f in files:
        filename = f.get("filename", "").lower()
        if any(p in filename for p in SENSITIVE_PATHS):
            count += 1
    return count


def has_security_keywords(text: str) -> int:
    """Count security-related keywords in text."""
    text_lower = text.lower()
    return sum(1 for kw in SECURITY_KEYWORDS if kw in text_lower)


def label_pr_risk(pr_data: dict, files: List[dict]) -> int:
    """
    Label a PR as high risk (1) or low risk (0) based on real signals.

    High risk indicators:
    - Security keywords in title/body
    - Touches security-sensitive files
    - Large PR with no test changes
    - Has CVE references
    - Labeled with security/vulnerability tags
    """
    risk_score = 0.0

    title = pr_data.get("title", "")
    body = pr_data.get("body", "") or ""
    labels = [l.get("name", "").lower() for l in pr_data.get("labels", [])]

    # Security keywords in title (strong signal)
    title_keywords = has_security_keywords(title)
    risk_score += title_keywords * 0.3

    # Security keywords in body
    body_keywords = has_security_keywords(body)
    risk_score += min(body_keywords * 0.05, 0.3)

    # CVE references
    cve_pattern = r"CVE-\d{4}-\d{4,}"
    cve_count = len(re.findall(cve_pattern, title + " " + body, re.IGNORECASE))
    risk_score += cve_count * 0.5

    # Security-related labels
    security_labels = ["security", "vulnerability", "cve", "critical", "urgent", "bug"]
    for label in labels:
        if any(sl in label for sl in security_labels):
            risk_score += 0.3

    # Sensitive files touched
    sensitive_count = count_security_sensitive_files(files)
    risk_score += sensitive_count * 0.1

    # Large PR with no tests
    additions = pr_data.get("additions", 0)
    if additions > 500 and not has_test_file_changes(files):
        risk_score += 0.15

    return 1 if risk_score >= 0.3 else 0


# ── Main Collection Loop ────────────────────────────────────────────────────

def collect_prs_from_repo(repo: str, per_page: int = 100) -> List[dict]:
    """Collect PRs and extract features from a single repository."""
    print(f"\n  📦 {repo}")

    # Get repo languages
    languages = get_repo_languages(repo)
    lang_ratio = calculate_lang_ratio(languages)

    # Fetch closed/merged PRs (they have complete data)
    prs_data = api_request(
        f"{GITHUB_API}/repos/{repo}/pulls",
        params={
            "state": "closed",
            "sort": "updated",
            "direction": "desc",
            "per_page": per_page,
        },
    )

    if not prs_data:
        print(f"    ⚠️  No PRs found")
        return []

    # Cache for user reputation (avoid repeated API calls)
    user_cache = {}
    records = []

    for i, pr in enumerate(prs_data):
        pr_number = pr["number"]
        author = pr["user"]["login"]

        # Get PR files (shows which files were changed)
        files = get_pr_files(repo, pr_number)

        # Get author reputation (cached)
        if author not in user_cache:
            user_info = get_user_info(author)
            user_cache[author] = calculate_author_reputation(user_info)

        # Parse timestamp
        created_at = datetime.fromisoformat(pr["created_at"].replace("Z", "+00:00"))

        # Build feature record
        record = {
            "files_changed": pr.get("changed_files", len(files)),
            "lines_added": pr.get("additions", 0),
            "lines_deleted": pr.get("deletions", 0),
            "commit_count": pr.get("commits", 1),
            "author_reputation": user_cache[author],
            "time_of_day": created_at.hour,
            "day_of_week": created_at.weekday(),
            "has_test_changes": int(has_test_file_changes(files)),
            "num_issues": pr.get("comments", 0) + pr.get("review_comments", 0),
            "num_severity": count_security_sensitive_files(files),
            "lang_ratio": lang_ratio,
            "historical_vuln_rate": round(
                has_security_keywords(pr.get("title", "") + " " + (pr.get("body", "") or ""))
                / max(len(SECURITY_KEYWORDS), 1),
                4,
            ),
            # Label
            "high_risk": label_pr_risk(pr, files),
            # Metadata (for reference, not used in training)
            "_repo": repo,
            "_pr_number": pr_number,
            "_title": pr.get("title", ""),
            "_author": author,
            "_url": pr.get("html_url", ""),
        }

        records.append(record)

        if (i + 1) % 20 == 0:
            print(f"    Processed {i + 1}/{len(prs_data)} PRs...")

        # Small delay to be nice to the API
        time.sleep(0.5)

    print(f"    ✅ Collected {len(records)} PRs ({sum(r['high_risk'] for r in records)} high-risk)")
    return records


def main():
    print("=" * 60)
    print("  Real GitHub PR Data Collector")
    print("=" * 60)

    # Check token
    if not GITHUB_TOKEN:
        print("\n  ⚠️  No GITHUB_TOKEN found!")
        print("  Set it with: set GITHUB_TOKEN=ghp_your_token_here")
        print("  Or export GITHUB_TOKEN=ghp_your_token_here (Linux/Mac)")
        print("\n  Without a token, you're limited to 60 requests/hour.")
        print("  With a token, you get 5,000 requests/hour.")
        response = input("\n  Continue without token? (y/n): ").strip().lower()
        if response != "y":
            sys.exit(0)

    # Check rate limit
    print("\n[1/4] Checking API rate limit...")
    remaining = check_rate_limit()

    # Estimate API calls needed
    # Per repo: 1 (languages) + 1 (PR list) + N * 2 (files + user per PR)
    estimated_calls = len(TARGET_REPOS) * (2 + PRS_PER_REPO * 2)
    print(f"  Estimated API calls needed: ~{estimated_calls}")

    if remaining < estimated_calls:
        print(f"\n  ⚠️  Not enough API calls remaining ({remaining} < {estimated_calls})")
        print(f"  Options:")
        print(f"    1. Reduce repos: edit TARGET_REPOS in the script")
        print(f"    2. Reduce PRs per repo: edit PRS_PER_REPO (currently {PRS_PER_REPO})")
        print(f"    3. Wait for rate limit reset")
        response = input("\n  Continue anyway? (y/n): ").strip().lower()
        if response != "y":
            sys.exit(0)

    # Collect from all repos
    print(f"\n[2/4] Collecting PRs from {len(TARGET_REPOS)} repositories...")
    all_records = []

    for repo in TARGET_REPOS:
        try:
            records = collect_prs_from_repo(repo, per_page=PRS_PER_REPO)
            all_records.extend(records)
        except KeyboardInterrupt:
            print("\n\n  ⚠️  Interrupted! Saving collected data so far...")
            break
        except Exception as e:
            print(f"    ❌ Error with {repo}: {e}")
            continue

    if not all_records:
        print("\n  ❌ No data collected. Check your token and network.")
        sys.exit(1)

    # Save raw data
    print(f"\n[3/4] Saving raw data ({len(all_records)} records)...")
    os.makedirs(RAW_DIR, exist_ok=True)
    with open(RAW_FILE, "w", encoding="utf-8") as f:
        json.dump(all_records, f, indent=2, default=str)
    print(f"  Raw data saved to: {RAW_FILE}")

    # Build training DataFrame (exclude metadata columns)
    feature_cols = [
        "files_changed", "lines_added", "lines_deleted", "commit_count",
        "author_reputation", "time_of_day", "day_of_week", "has_test_changes",
        "num_issues", "num_severity", "lang_ratio", "historical_vuln_rate",
        "high_risk",
    ]

    df = pd.DataFrame(all_records)[feature_cols]

    # Save processed data
    os.makedirs(OUTPUT_DIR, exist_ok=True)
    df.to_csv(OUTPUT_FILE, index=False)
    print(f"\n[4/4] Saved training data to: {OUTPUT_FILE}")

    # Summary
    print(f"\n{'─' * 50}")
    print(f"  Collection Summary")
    print(f"{'─' * 50}")
    print(f"  Total PRs collected:  {len(df)}")
    print(f"  High risk (1):        {df['high_risk'].sum()} ({df['high_risk'].mean()*100:.1f}%)")
    print(f"  Low risk  (0):        {(1-df['high_risk']).sum().astype(int)} ({(1-df['high_risk'].mean())*100:.1f}%)")
    print(f"  Repos scraped:        {len(set(r['_repo'] for r in all_records))}")
    print(f"\n  Feature stats:")
    print(df.describe().round(2).to_string())

    print(f"\n{'=' * 60}")
    print(f"  Done! Now retrain the model:")
    print(f"    python scripts/train_model.py")
    print(f"{'=' * 60}\n")

    return df


if __name__ == "__main__":
    main()
