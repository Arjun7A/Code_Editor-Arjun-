import json
import os
import datetime
from fastapi import FastAPI, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel
from analyzer import analyze

app = FastAPI(title="PR Security Scanner")

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_methods=["*"],
    allow_headers=["*"],
)

DATASET_DIR = os.path.join(os.path.dirname(os.path.abspath(__file__)), "dataset")
os.makedirs(DATASET_DIR, exist_ok=True)


class PRRequest(BaseModel):
    repo_url: str
    pr_url:   str


def save_scan(repo_url: str, pr_url: str, result: dict):
    """Auto-save every scan result to dataset folder for ML training."""
    try:
        timestamp = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
        # Make a safe filename from repo name
        repo_name = repo_url.rstrip("/").split("/")[-1]
        pr_num    = pr_url.rstrip("/").split("/")[-1]
        filename  = f"scan_{repo_name}_pr{pr_num}_{timestamp}.json"
        filepath  = os.path.join(DATASET_DIR, filename)

        data = {
            "repo_url":     repo_url,
            "pr_url":       pr_url,
            "scanned_at":   datetime.datetime.now().isoformat(),
            "scan_summary": result["scan_summary"],
            "issues":       result["issues"],
            "ai_audit":     result["ai_audit"],
            "gitleaks":     result["gitleaks"],
            "checkov":      result["checkov"],
        }

        with open(filepath, "w", encoding="utf-8") as f:
            json.dump(data, f, indent=2)

        print(f"[Dataset] Saved scan to {filepath}")
    except Exception as e:
        print(f"[Dataset] Failed to save scan: {e}")


@app.get("/")
def home():
    return {"message": "PR Security Scanner Running"}


@app.post("/analyze-pr")
def analyze_pr(request: PRRequest):
    if not request.repo_url or not request.pr_url:
        raise HTTPException(status_code=400, detail="repo_url and pr_url are required")

    result = analyze(request.repo_url, request.pr_url)

    # Auto-save to dataset folder for ML training
    save_scan(request.repo_url, request.pr_url, result)

    return {
        "repo_url":     request.repo_url,
        "pr_url":       request.pr_url,
        "scan_summary": result["scan_summary"],
        "issues":       result["issues"],
        "ai_audit":     result["ai_audit"],
        "gitleaks":     result["gitleaks"],
        "checkov":      result["checkov"],
    }


@app.get("/dataset")
def get_dataset():
    """Returns all saved scans for ML training."""
    import glob
    scans = []
    for f in sorted(glob.glob(os.path.join(DATASET_DIR, "*.json"))):
        try:
            with open(f, encoding="utf-8") as fh:
                scans.append(json.load(fh))
        except Exception:
            continue
    return {
        "total": len(scans),
        "scans": scans
    }


@app.get("/dataset/features")
def get_features():
    """
    Returns extracted ML features from all saved scans.
    Your friend calls this endpoint to get ready-to-train feature vectors.
    """
    import glob
    features = []
    for f in sorted(glob.glob(os.path.join(DATASET_DIR, "*.json"))):
        try:
            with open(f, encoding="utf-8") as fh:
                scan = json.load(fh)

            summary = scan.get("scan_summary", {})
            issues  = scan.get("issues", [])

            features.append({
                "repo_url":        scan.get("repo_url", ""),
                "pr_url":          scan.get("pr_url", ""),
                "scanned_at":      scan.get("scanned_at", ""),
                # Tool counts
                "semgrep_count":   summary.get("semgrep", 0),
                "osv_count":       summary.get("osv", 0),
                "ai_agent_count":  summary.get("ai_agent", 0),
                "gitleaks_count":  summary.get("gitleaks", 0),
                "checkov_count":   summary.get("checkov", 0),
                "total_issues":    summary.get("total_issues", 0),
                "pr_files_scanned": summary.get("pr_files_scanned", 0),
                # Severity breakdown
                "critical_count":  sum(1 for i in issues if i.get("severity") == "critical"),
                "high_count":      sum(1 for i in issues if i.get("severity") == "high"),
                "medium_count":    sum(1 for i in issues if i.get("severity") == "medium"),
                "low_count":       sum(1 for i in issues if i.get("severity") == "low"),
                # Binary flags
                "has_secret":      1 if scan.get("gitleaks") else 0,
                "has_iac_issue":   1 if scan.get("checkov") else 0,
                "has_ai_finding":  1 if scan.get("ai_audit", {}).get("findings") else 0,
                # Label — to be filled manually for training
                "risk_label":      None
            })
        except Exception:
            continue

    return {
        "total":    len(features),
        "features": features
    }


@app.get("/api/dashboard-stats")
def dashboard_stats():
    """Stub endpoint for frontend dashboard."""
    import glob
    total_scans = len(glob.glob(os.path.join(DATASET_DIR, "*.json")))
    return {
        "total_scans":  total_scans,
        "total_issues": 0
    }


@app.get("/api/results")
def get_results(skip: int = 0, limit: int = 200):
    """Stub endpoint for frontend dashboard."""
    return []


if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="127.0.0.1", port=8001)