"""
ML Model Live Demo — Analyze Any GitHub Repo
==============================================
Point this at any GitHub repository and the trained XGBoost model
will analyze its recent PRs and predict risk levels.

Usage:
    $env:GITHUB_TOKEN = "ghp_your_token"
    python scripts/demo_predict.py facebook/react
    python scripts/demo_predict.py tensorflow/tensorflow
    python scripts/demo_predict.py <owner>/<repo>
"""

import os
import sys
import time
import requests
import numpy as np
import joblib
from datetime import datetime, timezone

# ── Setup ────────────────────────────────────────────────────────────────────

GITHUB_TOKEN = os.environ.get("GITHUB_TOKEN", "")
GITHUB_API = "https://api.github.com"
MODEL_PATH = os.path.join(os.path.dirname(__file__), "..", "models", "xgboost_v1.pkl")

FEATURE_NAMES = [
    "files_changed", "lines_added", "lines_deleted", "commit_count",
    "author_reputation", "time_of_day", "day_of_week", "has_test_changes",
    "num_issues", "num_severity", "lang_ratio", "historical_vuln_rate",
]

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


def get_headers():
    headers = {"Accept": "application/vnd.github.v3+json", "User-Agent": "SecurityGate-Demo"}
    if GITHUB_TOKEN:
        headers["Authorization"] = f"token {GITHUB_TOKEN}"
    return headers


def api_get(url, params=None):
    try:
        r = requests.get(url, headers=get_headers(), params=params, timeout=30)
        if r.status_code == 200:
            return r.json()
        return None
    except:
        return None


def get_user_reputation(username, cache={}):
    if username in cache:
        return cache[username]
    user = api_get(f"{GITHUB_API}/users/{username}")
    if not user:
        cache[username] = 0.5
        return 0.5
    repos = user.get("public_repos", 0)
    followers = user.get("followers", 0)
    try:
        created = datetime.fromisoformat(user["created_at"].replace("Z", "+00:00"))
        age = (datetime.now(timezone.utc) - created).days / 365
    except:
        age = 1
    score = min(repos / 100, 1) * 0.3 + min(followers / 500, 1) * 0.4 + min(age / 10, 1) * 0.3
    cache[username] = round(max(0, min(1, score)), 3)
    return cache[username]


def main():
    if len(sys.argv) < 2:
        print("Usage: python scripts/demo_predict.py <owner/repo>")
        print("Example: python scripts/demo_predict.py facebook/react")
        sys.exit(1)

    repo = sys.argv[1]
    num_prs = int(sys.argv[2]) if len(sys.argv) > 2 else 10

    # Load model
    print(f"\n{'='*70}")
    print(f"  ML Risk Predictor — Live Demo")
    print(f"{'='*70}")
    print(f"  Repo:  {repo}")
    print(f"  PRs:   {num_prs}")

    if not os.path.exists(MODEL_PATH):
        print(f"\n  ❌ Model not found at {MODEL_PATH}")
        print(f"     Run 'python scripts/train_model.py' first.")
        sys.exit(1)

    model = joblib.load(MODEL_PATH)
    print(f"  Model: xgboost_v1.pkl ✅")

    # Get repo languages
    langs = api_get(f"{GITHUB_API}/repos/{repo}/languages") or {}
    total_bytes = sum(langs.values()) or 1
    js_bytes = langs.get("JavaScript", 0) + langs.get("TypeScript", 0)
    py_bytes = langs.get("Python", 0)
    web_bytes = js_bytes + py_bytes
    lang_ratio = round(js_bytes / web_bytes, 3) if web_bytes > 0 else 0.5

    # Fetch PRs
    print(f"\n  Fetching {num_prs} recent PRs from {repo}...")
    prs = api_get(
        f"{GITHUB_API}/repos/{repo}/pulls",
        params={"state": "all", "sort": "updated", "direction": "desc", "per_page": num_prs},
    )

    if not prs:
        print(f"  ❌ Could not fetch PRs. Check repo name and token.")
        sys.exit(1)

    print(f"  Found {len(prs)} PRs. Analyzing...\n")

    # Table header
    print(f"  {'#':<6} {'Risk':<7} {'Score':<8} {'Title':<45} {'Author':<15}")
    print(f"  {'─'*6} {'─'*7} {'─'*8} {'─'*45} {'─'*15}")

    high_risk_prs = []
    low_risk_prs = []

    for pr in prs:
        pr_num = pr["number"]
        title = pr.get("title", "")[:44]
        author = pr["user"]["login"][:14]
        created = datetime.fromisoformat(pr["created_at"].replace("Z", "+00:00"))

        # Get files
        files = api_get(f"{GITHUB_API}/repos/{repo}/pulls/{pr_num}/files", {"per_page": 50}) or []
        time.sleep(0.3)

        # Build features
        has_tests = any(
            any(p in f.get("filename", "").lower() for p in ["test", "spec", "__test__"])
            for f in files
        )
        sensitive = sum(
            1 for f in files
            if any(p in f.get("filename", "").lower() for p in SENSITIVE_PATHS)
        )
        sec_keywords = sum(1 for kw in SECURITY_KEYWORDS if kw in (title + " " + (pr.get("body", "") or "")).lower())

        features = {
            "files_changed": pr.get("changed_files", len(files)),
            "lines_added": pr.get("additions", 0),
            "lines_deleted": pr.get("deletions", 0),
            "commit_count": pr.get("commits", 1),
            "author_reputation": get_user_reputation(author),
            "time_of_day": created.hour,
            "day_of_week": created.weekday(),
            "has_test_changes": int(has_tests),
            "num_issues": pr.get("comments", 0) + pr.get("review_comments", 0),
            "num_severity": sensitive,
            "lang_ratio": lang_ratio,
            "historical_vuln_rate": round(sec_keywords / max(len(SECURITY_KEYWORDS), 1), 4),
        }

        # Predict
        vec = np.array([[features[f] for f in FEATURE_NAMES]])
        score = float(model.predict_proba(vec)[0][1])
        label = "HIGH" if score >= 0.5 else "LOW"

        # Color output
        if label == "HIGH":
            marker = "🔴"
            high_risk_prs.append((pr_num, title, round(score, 3)))
        else:
            marker = "🟢"
            low_risk_prs.append((pr_num, title, round(score, 3)))

        print(f"  #{pr_num:<5} {marker} {label:<5} {score:<8.3f} {title:<45} {author}")

    # Summary
    print(f"\n{'─'*70}")
    print(f"  SUMMARY for {repo}")
    print(f"{'─'*70}")
    print(f"  Total PRs analyzed:    {len(prs)}")
    print(f"  🔴 High risk:          {len(high_risk_prs)}")
    print(f"  🟢 Low risk:           {len(low_risk_prs)}")

    if high_risk_prs:
        print(f"\n  ⚠️  High-risk PRs that need review:")
        for num, title, score in sorted(high_risk_prs, key=lambda x: -x[2]):
            print(f"     #{num} (score: {score}) — {title}")

    print(f"\n{'='*70}\n")


if __name__ == "__main__":
    main()
