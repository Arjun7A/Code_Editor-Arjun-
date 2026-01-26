"""
Scanner Orchestrator
Coordinates running multiple security scanners
"""
from typing import Dict, List
from app.services.snyk_scanner import SnykScanner
from app.services.semgrep_scanner import SemgrepScanner
import asyncio
from concurrent.futures import ThreadPoolExecutor


class ScannerOrchestrator:
    def __init__(self):
        self.snyk = SnykScanner()
        self.semgrep = SemgrepScanner()
    
    async def run_all_scans(self, project_path: str) -> Dict:
        """
        Run all available scanners in parallel
        
        Args:
            project_path: Path to project to scan
            
        Returns:
            Dict with results from all scanners
        """
        results = {
            "snyk": {},
            "semgrep": {},
            "summary": {}
        }
        
        # Run scanners in parallel using thread pool
        with ThreadPoolExecutor(max_workers=2) as executor:
            # Submit tasks
            snyk_future = executor.submit(self.snyk.scan_dependencies, project_path)
            semgrep_future = executor.submit(self.semgrep.scan_code, project_path)
            
            # Get results
            results["snyk"] = snyk_future.result()
            results["semgrep"] = semgrep_future.result()
        
        # Generate summary
        results["summary"] = self._generate_summary(results)
        
        return results
    
    def _generate_summary(self, scan_results: Dict) -> Dict:
        """Generate overall scan summary"""
        total_findings = 0
        critical_count = 0
        high_count = 0
        medium_count = 0
        low_count = 0
        
        for tool, result in scan_results.items():
            if tool == "summary":
                continue
                
            if "findings" in result:
                findings = result["findings"]
                total_findings += len(findings)
                
                for finding in findings:
                    severity = finding.get("severity", "").lower()
                    if severity == "critical":
                        critical_count += 1
                    elif severity == "high" or severity == "error":
                        high_count += 1
                    elif severity == "medium" or severity == "warning":
                        medium_count += 1
                    elif severity == "low" or severity == "info":
                        low_count += 1
        
        # Determine overall verdict
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
            "critical": critical_count,
            "high": high_count,
            "medium": medium_count,
            "low": low_count,
            "overall_severity": overall_severity,
            "verdict": verdict,
            "tools_run": [tool for tool in scan_results.keys() if tool != "summary"]
        }
