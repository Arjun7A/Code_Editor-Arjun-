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
from datetime import datetime
import asyncio
import tempfile
import os
import subprocess

router = APIRouter()
scanner = ScannerOrchestrator()


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
                pr.verdict = summary.get("verdict", "MANUAL_REVIEW")
                
                # Calculate risk score (0-100)
                total_findings = summary.get("total_findings", 0)
                critical = summary.get("critical", 0)
                high = summary.get("high", 0)
                medium = summary.get("medium", 0)
                
                risk_score = min(100, (critical * 25) + (high * 10) + (medium * 5))
                pr.risk_score = risk_score
                
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
