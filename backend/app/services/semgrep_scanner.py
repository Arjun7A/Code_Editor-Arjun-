"""
Semgrep Scanner Service
Wraps Semgrep CLI for static code analysis
"""
import subprocess
import json
from typing import Dict, List
from pathlib import Path


class SemgrepScanner:
    def __init__(self):
        self.tool_name = "semgrep"
        # Default rule sets
        self.default_rules = [
            "p/security-audit",
            "p/owasp-top-ten",
            "p/sql-injection",
            "p/xss"
        ]
    
    def check_installed(self) -> bool:
        """Check if Semgrep CLI is installed"""
        try:
            result = subprocess.run(
                ["semgrep", "--version"],
                capture_output=True,
                text=True,
                timeout=10
            )
            return result.returncode == 0
        except (subprocess.TimeoutExpired, FileNotFoundError):
            return False
    
    def scan_code(self, project_path: str, rules: List[str] = None) -> Dict:
        """
        Scan code for security issues
        
        Args:
            project_path: Path to project directory
            rules: List of Semgrep rules to use
            
        Returns:
            Dict with scan results
        """
        if not self.check_installed():
            return {
                "error": "Semgrep CLI not installed",
                "tool": "semgrep",
                "findings": [],
                "severity": "info"
            }
        
        rules_to_use = rules or self.default_rules
        
        try:
            # Run semgrep with JSON output
            cmd = ["semgrep", "--config"] + rules_to_use + ["--json", project_path]
            
            result = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=180
            )
            
            # Parse JSON output
            if result.stdout:
                data = json.loads(result.stdout)
                return self._parse_semgrep_output(data)
            else:
                return {
                    "tool": "semgrep",
                    "findings": [],
                    "severity": "info",
                    "summary": "No issues found"
                }
                
        except subprocess.TimeoutExpired:
            return {
                "error": "Semgrep scan timeout",
                "tool": "semgrep",
                "findings": [],
                "severity": "error"
            }
        except json.JSONDecodeError as e:
            return {
                "error": f"Failed to parse Semgrep output: {str(e)}",
                "tool": "semgrep",
                "findings": [],
                "severity": "error"
            }
        except Exception as e:
            return {
                "error": f"Semgrep scan failed: {str(e)}",
                "tool": "semgrep",
                "findings": [],
                "severity": "error"
            }
    
    def _parse_semgrep_output(self, data: Dict) -> Dict:
        """Parse Semgrep JSON output into standardized format"""
        findings = []
        
        if "results" in data:
            for result in data["results"]:
                # Extract severity from check_id or metadata
                severity = result.get("extra", {}).get("severity", "medium")
                
                findings.append({
                    "rule_id": result.get("check_id", ""),
                    "severity": severity.lower(),
                    "message": result.get("extra", {}).get("message", ""),
                    "file": result.get("path", ""),
                    "line": result.get("start", {}).get("line", 0),
                    "code_snippet": result.get("extra", {}).get("lines", ""),
                    "fix": result.get("extra", {}).get("fix", "")
                })
        
        # Determine overall severity
        severities = [f["severity"] for f in findings]
        critical_high = ["critical", "high", "error"]
        
        if any(s in critical_high for s in severities):
            overall_severity = "high"
        elif "medium" in severities or "warning" in severities:
            overall_severity = "medium"
        elif "low" in severities or "info" in severities:
            overall_severity = "low"
        else:
            overall_severity = "info"
        
        return {
            "tool": "semgrep",
            "findings": findings,
            "severity": overall_severity,
            "summary": f"Found {len(findings)} security issues",
            "total_count": len(findings)
        }
