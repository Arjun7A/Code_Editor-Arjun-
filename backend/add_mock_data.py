"""
Add mock PR data directly to database for testing dashboard
"""
import sys
sys.path.append("C:\\Users\\Arjun\\OneDrive\\Desktop\\capstone\\Code_Editor\\backend")

from app.core.database import SessionLocal
from app.models.database_models import PullRequest, ScanResult
from datetime import datetime

def add_mock_data():
    """Add mock PR analysis data"""
    db = SessionLocal()
    
    try:
        # Clear existing data
        db.query(ScanResult).delete()
        db.query(PullRequest).delete()
        db.commit()
        
        # Mock PR 1: Auto-approved (low risk)
        pr1 = PullRequest(
            repo_name="example/secure-app",
            pr_number=123,
            pr_url="https://github.com/example/secure-app/pull/123",
            status="completed",
            verdict="AUTO_APPROVE",
            risk_score=15
        )
        db.add(pr1)
        db.commit()
        db.refresh(pr1)
        
        # Add scan results for PR1
        scan1_snyk = ScanResult(
            pr_id=pr1.id,
            tool="snyk",
            findings=["Low: Outdated dependency"],
            severity="low"
        )
        scan1_semgrep = ScanResult(
            pr_id=pr1.id,
            tool="semgrep",
            findings=["Info: Code style improvement suggested"],
            severity="info"
        )
        db.add(scan1_snyk)
        db.add(scan1_semgrep)
        
        # Mock PR 2: Manual review (medium risk)
        pr2 = PullRequest(
            repo_name="example/api-service",
            pr_number=456,
            pr_url="https://github.com/example/api-service/pull/456",
            status="completed",
            verdict="MANUAL_REVIEW",
            risk_score=45
        )
        db.add(pr2)
        db.commit()
        db.refresh(pr2)
        
        # Add scan results for PR2
        scan2_snyk = ScanResult(
            pr_id=pr2.id,
            tool="snyk",
            findings=["Medium: SQL injection risk", "Low: Missing input validation"],
            severity="medium"
        )
        scan2_semgrep = ScanResult(
            pr_id=pr2.id,
            tool="semgrep",
            findings=["Warning: Potential XSS vulnerability"],
            severity="warning"
        )
        db.add(scan2_snyk)
        db.add(scan2_semgrep)
        
        # Mock PR 3: Blocked (high risk)
        pr3 = PullRequest(
            repo_name="example/frontend-app",
            pr_number=789,
            pr_url="https://github.com/example/frontend-app/pull/789",
            status="completed",
            verdict="BLOCK",
            risk_score=85
        )
        db.add(pr3)
        db.commit()
        db.refresh(pr3)
        
        # Add scan results for PR3
        scan3_snyk = ScanResult(
            pr_id=pr3.id,
            tool="snyk",
            findings=["Critical: Remote code execution vulnerability", "High: Authentication bypass"],
            severity="critical"
        )
        scan3_semgrep = ScanResult(
            pr_id=pr3.id,
            tool="semgrep",
            findings=["Error: Hardcoded credentials detected", "Warning: Unsafe deserialization"],
            severity="error"
        )
        db.add(scan3_snyk)
        db.add(scan3_semgrep)
        
        # Mock PR 4: Pending
        pr4 = PullRequest(
            repo_name="example/microservice",
            pr_number=101,
            pr_url="https://github.com/example/microservice/pull/101",
            status="pending",
            verdict=None,
            risk_score=None
        )
        db.add(pr4)
        
        db.commit()
        
        print("✅ Successfully added 4 mock PRs to database")
        print(f"  - PR #123: AUTO_APPROVE (Risk: 15)")
        print(f"  - PR #456: MANUAL_REVIEW (Risk: 45)")
        print(f"  - PR #789: BLOCK (Risk: 85)")
        print(f"  - PR #101: PENDING")
        
    except Exception as e:
        print(f"❌ Error: {e}")
        db.rollback()
    finally:
        db.close()

if __name__ == "__main__":
    add_mock_data()
