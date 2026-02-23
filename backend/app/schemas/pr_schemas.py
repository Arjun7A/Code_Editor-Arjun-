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
                "pr_url": "https://github.com/owner/repo/pull/123",
            }
        }


class ScanResultResponse(BaseModel):
    """Schema for scan result"""
    id: int
    tool: str
    severity: Optional[str]
    summary: Optional[str]
    findings: Optional[Any]
    execution_time: Optional[float] = None
    severity_counts: Optional[Dict[str, Any]] = None
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
    author_name: Optional[str] = None
    files_changed: Optional[int] = None
    lines_added: Optional[int] = None
    lines_deleted: Optional[int] = None
    feature_importance: Optional[Dict[str, Any]] = None
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


# ============ Direct Scan Schemas ============

class ScanRequest(BaseModel):
    """
    Request for the /api/scan endpoint.
    Provide exactly ONE of: code, repo_url, path.
    """
    code: Optional[str] = None
    filename: Optional[str] = "code.py"
    repo_url: Optional[str] = None
    path: Optional[str] = None

    class Config:
        json_schema_extra = {
            "examples": [
                {"code": "import os\neval(input())", "filename": "evil.py"},
                {"repo_url": "https://github.com/owner/repo"},
            ]
        }


class VulnerabilitySchema(BaseModel):
    """Frontend Vulnerability type"""
    id: str
    title: str
    description: str
    severity: str
    cwe: Optional[str] = None
    cvss: Optional[float] = None
    package: Optional[str] = None
    version: Optional[str] = None
    fixedVersion: Optional[str] = None


class SemgrepFindingSchema(BaseModel):
    """Frontend SemgrepFinding type"""
    id: str
    ruleId: str
    message: str
    severity: str
    path: str
    startLine: int
    endLine: int
    snippet: Optional[str] = None


class ScannerResultSchema(BaseModel):
    """Frontend ScannerResult type"""
    id: str
    name: str
    status: str   # success | failed | skipped
    issuesFound: int
    executionTime: float
    severity: Dict[str, int]   # critical/high/medium/low counts


class ScanResponse(BaseModel):
    """Response from /api/scan"""
    scan_id: str
    status: str
    elapsed_seconds: float
    snyk_vulnerabilities: List[VulnerabilitySchema] = []
    semgrep_findings: List[SemgrepFindingSchema] = []
    scanner_results: List[ScannerResultSchema] = []
    summary: Dict[str, Any] = {}


# ============ Dashboard Stats Schema ============

class DashboardStatsResponse(BaseModel):
    """Response from /api/dashboard-stats"""
    total_prs: int
    approved: int
    blocked: int
    manual_review: int
    avg_risk_score: float
    critical_issues: int
    scans_today: int
    severity_breakdown: Dict[str, int] = {}
    verdict_distribution: List[Dict[str, Any]] = []
    risk_trend: List[Dict[str, Any]] = []
    scanner_stats: Dict[str, Any] = {}
