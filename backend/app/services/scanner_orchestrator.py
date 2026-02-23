"""
Scanner Orchestrator
Coordinates Snyk + Semgrep scans and produces a unified result that
maps 1-to-1 onto the frontend's ScannerResult / PRAnalysis types.
"""
import asyncio
import logging
import time
import uuid
from concurrent.futures import ThreadPoolExecutor, as_completed
from typing import Dict, List, Optional

from app.services.snyk_scanner import SnykScanner
from app.services.semgrep_scanner import SemgrepScanner

logger = logging.getLogger(__name__)


class ScannerOrchestrator:
    def __init__(self):
        self.snyk = SnykScanner()
        self.semgrep = SemgrepScanner()

    # ------------------------------------------------------------------ #
    #  Parallel scan runner                                                 #
    # ------------------------------------------------------------------ #

    async def run_all_scans(
        self,
        project_path: str,
        code_content: Optional[str] = None,
        filename_hint: str = "code.py",
    ) -> Dict:
        """
        Run Snyk + Semgrep in parallel (using a thread-pool because both
        scanners shell-out to CLI tools).

        Returns a unified dict that includes:
          - snyk / semgrep raw results
          - snykVulnerabilities  – frontend Vulnerability[] format
          - semgrepFindings      – frontend SemgrepFinding[] format
          - scannerResults       – frontend ScannerResult[] format
          - summary
        """
        loop = asyncio.get_event_loop()

        with ThreadPoolExecutor(max_workers=2) as executor:
            snyk_future = loop.run_in_executor(
                executor, self.snyk.scan_dependencies, project_path
            )
            semgrep_future = loop.run_in_executor(
                executor,
                lambda: self.semgrep.scan_code(
                    project_path,
                    code_content=code_content,
                    filename_hint=filename_hint,
                ),
            )
            snyk_result, semgrep_result = await asyncio.gather(
                snyk_future, semgrep_future
            )

        summary = self._generate_summary({"snyk": snyk_result, "semgrep": semgrep_result})

        return {
            "snyk": snyk_result,
            "semgrep": semgrep_result,
            "summary": summary,
            # Frontend-typed arrays
            "snykVulnerabilities": self._to_vulnerability_list(snyk_result),
            "semgrepFindings": self._to_semgrep_finding_list(semgrep_result),
            "scannerResults": self._to_scanner_result_list(snyk_result, semgrep_result),
        }

    # ------------------------------------------------------------------ #
    #  Sync wrapper (for use from non-async contexts like BackgroundTasks)  #
    # ------------------------------------------------------------------ #

    def run_all_scans_sync(
        self,
        project_path: str,
        code_content: Optional[str] = None,
        filename_hint: str = "code.py",
    ) -> Dict:
        """Synchronous version for use in thread-pool background tasks."""
        snyk_result = self.snyk.scan_dependencies(project_path)
        semgrep_result = self.semgrep.scan_code(
            project_path,
            code_content=code_content,
            filename_hint=filename_hint,
        )

        summary = self._generate_summary({"snyk": snyk_result, "semgrep": semgrep_result})

        return {
            "snyk": snyk_result,
            "semgrep": semgrep_result,
            "summary": summary,
            "snykVulnerabilities": self._to_vulnerability_list(snyk_result),
            "semgrepFindings": self._to_semgrep_finding_list(semgrep_result),
            "scannerResults": self._to_scanner_result_list(snyk_result, semgrep_result),
        }

    # ------------------------------------------------------------------ #
    #  Frontend-type converters                                             #
    # ------------------------------------------------------------------ #

    def _to_vulnerability_list(self, snyk_result: Dict) -> List[Dict]:
        """
        Convert Snyk findings → frontend Vulnerability[] shape.
        Private internal keys (prefixed with _) are stripped.
        """
        out = []
        for f in snyk_result.get("findings", []):
            out.append({
                "id": f.get("id", str(uuid.uuid4())),
                "title": f.get("title", "Unknown vulnerability"),
                "description": f.get("description", ""),
                "severity": f.get("severity", "low"),
                "cwe": f.get("cwe"),
                "cvss": f.get("cvss"),
                "package": f.get("package", ""),
                "version": f.get("version", ""),
                "fixedVersion": f.get("fixedVersion"),
            })
        return out

    def _to_semgrep_finding_list(self, semgrep_result: Dict) -> List[Dict]:
        """
        Convert Semgrep findings → frontend SemgrepFinding[] shape.
        """
        out = []
        for f in semgrep_result.get("findings", []):
            out.append({
                "id": f.get("id", str(uuid.uuid4())),
                "ruleId": f.get("ruleId", ""),
                "message": f.get("message", ""),
                "severity": f.get("severity", "medium"),
                "path": f.get("path", ""),
                "startLine": f.get("startLine", 1),
                "endLine": f.get("endLine", f.get("startLine", 1)),
                "snippet": f.get("snippet", ""),
            })
        return out

    def _to_scanner_result_list(
        self, snyk_result: Dict, semgrep_result: Dict
    ) -> List[Dict]:
        """
        Build the ScannerResult[] array shown in the scanner results table.
        """
        def _counts(result: Dict) -> Dict:
            sc = result.get("severity_counts", {})
            return {
                "critical": sc.get("critical", 0),
                "high": sc.get("high", 0),
                "medium": sc.get("medium", 0),
                "low": sc.get("low", 0),
            }

        def _status(result: Dict) -> str:
            s = result.get("status", "success")
            if s == "skipped":
                return "skipped"
            if s == "error" or result.get("error"):
                return "failed"
            return "success"

        return [
            {
                "id": f"snyk-{uuid.uuid4()}",
                "name": "Snyk",
                "status": _status(snyk_result),
                "issuesFound": snyk_result.get("total_count", 0),
                "executionTime": snyk_result.get("execution_time", 0.0),
                "severity": _counts(snyk_result),
            },
            {
                "id": f"semgrep-{uuid.uuid4()}",
                "name": "Semgrep",
                "status": _status(semgrep_result),
                "issuesFound": semgrep_result.get("total_count", 0),
                "executionTime": semgrep_result.get("execution_time", 0.0),
                "severity": _counts(semgrep_result),
            },
        ]

    # ------------------------------------------------------------------ #
    #  Summary generation                                                   #
    # ------------------------------------------------------------------ #

    def _generate_summary(self, scan_results: Dict) -> Dict:
        """Aggregate counts across all tools and derive a verdict."""
        total_findings = 0
        critical_count = 0
        high_count = 0
        medium_count = 0
        low_count = 0

        for tool, result in scan_results.items():
            if tool == "summary":
                continue
            sc = result.get("severity_counts", {})
            critical_count += sc.get("critical", 0)
            high_count += sc.get("high", 0)
            medium_count += sc.get("medium", 0)
            low_count += sc.get("low", 0)
            total_findings += result.get("total_count", 0)

        if critical_count > 0:
            verdict = "BLOCK"
            overall_severity = "critical"
        elif high_count >= 3:
            verdict = "BLOCK"
            overall_severity = "high"
        elif high_count > 0 or medium_count >= 5:
            verdict = "MANUAL_REVIEW"
            overall_severity = "high" if high_count > 0 else "medium"
        elif medium_count > 0 or low_count > 0:
            verdict = "MANUAL_REVIEW"
            overall_severity = "medium"
        else:
            verdict = "AUTO_APPROVE"
            overall_severity = "low"

        return {
            "total_findings": total_findings,
            "total_issues": total_findings,
            "critical": critical_count,
            "high": high_count,
            "medium": medium_count,
            "low": low_count,
            "overall_severity": overall_severity,
            "verdict": verdict,
            "tools_run": [t for t in scan_results if t != "summary"],
        }
