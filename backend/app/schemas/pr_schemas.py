from pydantic import BaseModel, HttpUrl
from typing import Optional, List, Dict, Any
from datetime import datetime

# ============ Pull Request Schemas ============

class PRAnalyzeRequest(BaseModel):
    """Request body for analyzing a PR"""
    repo_name: str
    pr_number: int
    pr_url: str
    
    class Config:
        json_schema_extra = {
            "example": {
                "repo_name": "owner/repository",
                "pr_number": 123,
                "pr_url": "https://github.com/owner/repo/pull/123"
            }
        }


class ScanResultResponse(BaseModel):
    """Schema for scan result"""
    id: int
    tool: str
    severity: Optional[str]
    summary: Optional[str]
    findings: Optional[Dict[str, Any]]
    created_at: datetime
    
    class Config:
        from_attributes = True


class AuditLogResponse(BaseModel):
    """Schema for audit log"""
    id: int
    blockchain_hash: Optional[str]
    blockchain_tx: Optional[str]
    decision: str
    timestamp: datetime
    
    class Config:
        from_attributes = True


class PRAnalysisResponse(BaseModel):
    """Response for PR analysis"""
    id: int
    repo_name: str
    pr_number: int
    pr_url: str
    status: str
    risk_score: Optional[float]
    verdict: Optional[str]
    created_at: datetime
    updated_at: datetime
    scan_results: List[ScanResultResponse] = []
    audit_log: Optional[AuditLogResponse] = None
    
    class Config:
        from_attributes = True


class PRAnalysisStatusResponse(BaseModel):
    """Quick status response"""
    id: int
    status: str
    risk_score: Optional[float]
    verdict: Optional[str]
    message: str
