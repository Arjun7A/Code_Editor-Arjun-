from fastapi import APIRouter, Depends, HTTPException, BackgroundTasks
from sqlalchemy.orm import Session
from typing import List
from app.core.database import get_db
from app.models.database_models import PullRequest, ScanResult
from app.schemas.pr_schemas import (
    PRAnalyzeRequest,
    PRAnalysisResponse,
    PRAnalysisStatusResponse
)
from app.services.scanner_orchestrator import ScannerOrchestrator
from app.services.ml_predictor import MLPredictor
from app.core.config import settings
from datetime import datetime
import asyncio
import tempfile
import os
import subprocess

router = APIRouter()
scanner = ScannerOrchestrator()
ml_predictor = MLPredictor(model_path=settings.ML_MODEL_PATH)


async def run_analysis(pr_id: int, repo_url: str, db: Session):
    """Background task to run security analysis on PR"""
    try:
        # Clone repository to temporary directory
        with tempfile.TemporaryDirectory() as temp_dir:
            # Clone the repo
            try:
                subprocess.run(
                    ["git", "clone", "--depth", "1", repo_url, temp_dir],
                    check=True,
                    capture_output=True,
                    timeout=120
                )
            except Exception as e:
                # If clone fails, update PR with error
                pr = db.query(PullRequest).filter(PullRequest.id == pr_id).first()
                if pr:
                    pr.status = "error"
                    pr.verdict = "ERROR"
                    db.commit()
                return
            
            # Run all security scans
            scan_results = await scanner.run_all_scans(temp_dir)
            
            # Update PR record with results
            pr = db.query(PullRequest).filter(PullRequest.id == pr_id).first()
            if pr:
                summary = scan_results.get("summary", {})
                pr.status = "completed"
                
                # ── ML-based risk scoring ───────────────────────────────
                # Build feature dict from scan results for ML prediction
                ml_features = {
                    "files_changed": summary.get("files_changed", 5),
                    "lines_added": summary.get("lines_added", 100),
                    "lines_deleted": summary.get("lines_deleted", 30),
                    "commit_count": summary.get("commit_count", 3),
                    "author_reputation": summary.get("author_reputation", 0.5),
                    "time_of_day": datetime.utcnow().hour,
                    "day_of_week": datetime.utcnow().weekday(),
                    "has_test_changes": int(summary.get("has_test_changes", False)),
                    "num_issues": summary.get("total_findings", 0),
                    "num_severity": summary.get("critical", 0) + summary.get("high", 0),
                    "lang_ratio": summary.get("lang_ratio", 0.5),
                    "historical_vuln_rate": summary.get("historical_vuln_rate", 0.05),
                }
                
                ml_result = ml_predictor.predict_risk(ml_features)
                risk_score = ml_result["risk_score"] * 100  # Convert 0-1 to 0-100
                pr.risk_score = round(risk_score, 1)
                
                # Determine verdict based on ML risk score
                if risk_score >= 70:
                    pr.verdict = "BLOCK"
                elif risk_score >= 40:
                    pr.verdict = "MANUAL_REVIEW"
                else:
                    pr.verdict = "AUTO_APPROVE"
                
                # Save individual scan results
                for tool_name, tool_result in scan_results.items():
                    if tool_name != "summary":
                        scan_record = ScanResult(
                            pr_id=pr_id,
                            tool=tool_name,
                            findings=tool_result.get("findings", []),
                            severity=tool_result.get("severity", "info")
                        )
                        db.add(scan_record)
                
                db.commit()
                
    except Exception as e:
        # Handle errors
        pr = db.query(PullRequest).filter(PullRequest.id == pr_id).first()
        if pr:
            pr.status = "error"
            pr.verdict = "ERROR"
            db.commit()


@router.post("/analyze", response_model=PRAnalysisStatusResponse, status_code=202)
async def analyze_pull_request(
    request: PRAnalyzeRequest,
    background_tasks: BackgroundTasks,
    db: Session = Depends(get_db)
):
    """
    Analyze a Pull Request
    Returns immediately with PR ID, analysis runs in background
    """
    # Create PR record
    pr = PullRequest(
        repo_name=request.repo_name,
        pr_number=request.pr_number,
        pr_url=request.pr_url,
        status="pending"
    )
    db.add(pr)
    db.commit()
    db.refresh(pr)
    
    # Add background task for actual analysis
    background_tasks.add_task(run_analysis, pr.id, request.pr_url, db)
    
    return PRAnalysisStatusResponse(
        id=pr.id,
        status="pending",
        risk_score=None,
        verdict=None,
        message=f"PR #{request.pr_number} analysis started. Check status at /api/results/{pr.id}"
    )


@router.get("/results/{pr_id}", response_model=PRAnalysisResponse)
async def get_analysis_results(
    pr_id: int,
    db: Session = Depends(get_db)
):
    """
    Get analysis results for a specific PR
    """
    pr = db.query(PullRequest).filter(PullRequest.id == pr_id).first()
    
    if not pr:
        raise HTTPException(status_code=404, detail=f"PR with ID {pr_id} not found")
    
    return pr


@router.get("/results", response_model=List[PRAnalysisResponse])
async def list_all_results(
    skip: int = 0,
    limit: int = 10,
    db: Session = Depends(get_db)
):
    """
    List all PR analysis results (paginated)
    """
    prs = db.query(PullRequest).offset(skip).limit(limit).all()
    return prs
