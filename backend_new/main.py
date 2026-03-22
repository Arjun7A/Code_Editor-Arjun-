from fastapi import FastAPI, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel
from dotenv import load_dotenv
from analyzer import analyze
from storage import build_dashboard_stats, build_features, load_scans, save_scan

load_dotenv()

app = FastAPI(title="PR Security Scanner")

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_methods=["*"],
    allow_headers=["*"],
)


class PRRequest(BaseModel):
    repo_url: str
    pr_url:   str
@app.get("/")
def home():
    return {"message": "PR Security Scanner Running"}


@app.post("/analyze-pr")
def analyze_pr(request: PRRequest):
    if not request.repo_url or not request.pr_url:
        raise HTTPException(status_code=400, detail="repo_url and pr_url are required")

    result = analyze(request.repo_url, request.pr_url)

    # Auto-save to shared storage and return the persisted record shape
    return save_scan(request.repo_url, request.pr_url, result)


@app.get("/dataset")
def get_dataset():
    """Returns all saved scans from Supabase or local fallback storage."""
    scans = load_scans()
    return {"total": len(scans), "scans": scans}


@app.get("/dataset/features")
def get_features():
    """
    Returns extracted ML features from all saved scans.
    Your friend calls this endpoint to get ready-to-train feature vectors.
    """
    scans = load_scans()
    features = build_features(scans)
    return {"total": len(features), "features": features}


@app.get("/api/dashboard-stats")
def dashboard_stats():
    """Returns live dashboard totals from shared scan storage."""
    return build_dashboard_stats(load_scans())


@app.get("/api/results")
def get_results(skip: int = 0, limit: int = 200):
    """Stub endpoint for frontend dashboard."""
    return []


if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="127.0.0.1", port=8001)
