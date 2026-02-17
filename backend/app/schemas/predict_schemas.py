from pydantic import BaseModel, Field
from typing import Dict, Optional


class PredictRiskRequest(BaseModel):
    """Request body for ML risk prediction."""
    files_changed: int = Field(..., ge=0, description="Number of files modified")
    lines_added: int = Field(..., ge=0, description="Lines added")
    lines_deleted: int = Field(..., ge=0, description="Lines deleted")
    commit_count: int = Field(..., ge=1, description="Number of commits")
    author_reputation: float = Field(..., ge=0, le=1, description="Author trust score (0-1)")
    time_of_day: int = Field(..., ge=0, le=23, description="Hour of day (0-23)")
    day_of_week: int = Field(..., ge=0, le=6, description="Day of week (0=Mon, 6=Sun)")
    has_test_changes: bool = Field(..., description="Whether test files were modified")
    num_issues: int = Field(..., ge=0, description="Number of linked issues")
    num_severity: int = Field(..., ge=0, description="Count of high/critical scanner findings")
    lang_ratio: float = Field(..., ge=0, le=1, description="JS/PY code ratio")
    historical_vuln_rate: float = Field(..., ge=0, le=1, description="Author's past vulnerability rate")

    class Config:
        json_schema_extra = {
            "example": {
                "files_changed": 15,
                "lines_added": 200,
                "lines_deleted": 50,
                "commit_count": 5,
                "author_reputation": 0.7,
                "time_of_day": 14,
                "day_of_week": 2,
                "has_test_changes": True,
                "num_issues": 3,
                "num_severity": 1,
                "lang_ratio": 0.6,
                "historical_vuln_rate": 0.1,
            }
        }


class PredictRiskResponse(BaseModel):
    """Response from ML risk prediction."""
    risk_score: float = Field(..., description="Risk probability (0-1)")
    risk_label: str = Field(..., description="Risk classification: 'high' or 'low'")
    risk_percentage: float = Field(..., description="Risk as percentage (0-100)")
    feature_importance: Dict[str, float] = Field(default_factory=dict, description="Feature importance scores")
    model_version: str = Field(..., description="Model version used")
    using_fallback: bool = Field(..., description="Whether fallback heuristic was used")
