from sqlalchemy import Column, Integer, String, Float, DateTime, Text, ForeignKey, JSON
from sqlalchemy.orm import relationship
from datetime import datetime
from app.core.database import Base

class PullRequest(Base):
    __tablename__ = "pull_requests"
    
    id = Column(Integer, primary_key=True, index=True)
    repo_name = Column(String, nullable=False)
    pr_number = Column(Integer, nullable=False)
    pr_url = Column(String, nullable=False)
    status = Column(String, default="pending")  # pending, completed, failed
    risk_score = Column(Float, nullable=True)
    verdict = Column(String, nullable=True)  # AUTO_APPROVE, MANUAL_REVIEW, BLOCK
    created_at = Column(DateTime, default=datetime.utcnow)
    updated_at = Column(DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)
    
    # Relationships
    scan_results = relationship("ScanResult", back_populates="pull_request", cascade="all, delete-orphan")
    audit_log = relationship("AuditLog", back_populates="pull_request", uselist=False, cascade="all, delete-orphan")


class ScanResult(Base):
    __tablename__ = "scan_results"
    
    id = Column(Integer, primary_key=True, index=True)
    pr_id = Column(Integer, ForeignKey("pull_requests.id"), nullable=False)
    tool = Column(String, nullable=False)  # snyk, semgrep, ai, ml
    findings = Column(JSON, nullable=True)
    severity = Column(String, nullable=True)  # critical, high, medium, low
    summary = Column(Text, nullable=True)
    created_at = Column(DateTime, default=datetime.utcnow)
    
    # Relationship
    pull_request = relationship("PullRequest", back_populates="scan_results")


class AuditLog(Base):
    __tablename__ = "audit_logs"
    
    id = Column(Integer, primary_key=True, index=True)
    pr_id = Column(Integer, ForeignKey("pull_requests.id"), nullable=False, unique=True)
    blockchain_hash = Column(String, nullable=True)
    blockchain_tx = Column(String, nullable=True)
    decision = Column(String, nullable=False)
    risk_data = Column(JSON, nullable=True)
    timestamp = Column(DateTime, default=datetime.utcnow)
    
    # Relationship
    pull_request = relationship("PullRequest", back_populates="audit_log")
