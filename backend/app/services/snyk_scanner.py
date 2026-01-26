"""
Snyk Scanner Service
Wraps Snyk CLI for dependency vulnerability scanning
"""
import subprocess
import json
from typing import Dict, List, Optional
from pathlib import Path


class SnykScanner:
    def __init__(self):
        self.tool_name = "snyk"
    
    def check_installed(self) -> bool:
        """Check if Snyk CLI is installed"""
        try:
            result = subprocess.run(
                ["snyk", "--version"],
                capture_output=True,
                text=True,
                timeout=10
            )
            return result.returncode == 0
        except (subprocess.TimeoutExpired, FileNotFoundError):
            return False
    
    def scan_dependencies(self, project_path: str) -> Dict:
        """
        Scan project dependencies for vulnerabilities
        
        Args:
            project_path: Path to project directory
            
        Returns:
            Dict with scan results
        """
        if not self.check_installed():
            return {
                "error": "Snyk CLI not installed",
                "tool": "snyk",
                "findings": [],
                "severity": "info"
            }
        
        try:
            # Run snyk test with JSON output
            result = subprocess.run(
                ["snyk", "test", "--json"],
                cwd=project_path,
                capture_output=True,
                text=True,
                timeout=120
            )
            
            # Parse JSON output
            if result.stdout:
                data = json.loads(result.stdout)
                return self._parse_snyk_output(data)
            else:
                return {
                    "tool": "snyk",
                    "findings": [],
                    "severity": "info",
                    "summary": "No vulnerabilities found"
                }
                
        except subprocess.TimeoutExpired:
            return {
                "error": "Snyk scan timeout",
                "tool": "snyk",
                "findings": [],
                "severity": "error"
            }
        except json.JSONDecodeError as e:
            return {
                "error": f"Failed to parse Snyk output: {str(e)}",
                "tool": "snyk",
                "findings": [],
                "severity": "error"
            }
        except Exception as e:
            return {
                "error": f"Snyk scan failed: {str(e)}",
                "tool": "snyk",
                "findings": [],
                "severity": "error"
            }
    
    def _parse_snyk_output(self, data: Dict) -> Dict:
        """Parse Snyk JSON output into standardized format"""
        findings = []
        
        if "vulnerabilities" in data:
            for vuln in data["vulnerabilities"]:
                findings.append({
                    "title": vuln.get("title", "Unknown vulnerability"),
                    "severity": vuln.get("severity", "unknown"),
                    "package": vuln.get("packageName", ""),
                    "version": vuln.get("version", ""),
                    "cve": vuln.get("identifiers", {}).get("CVE", []),
                    "fixedIn": vuln.get("fixedIn", []),
                    "description": vuln.get("description", "")
                })
        
        # Determine overall severity
        severities = [f["severity"] for f in findings]
        if "critical" in severities:
            overall_severity = "critical"
        elif "high" in severities:
            overall_severity = "high"
        elif "medium" in severities:
            overall_severity = "medium"
        elif "low" in severities:
            overall_severity = "low"
        else:
            overall_severity = "info"
        
        return {
            "tool": "snyk",
            "findings": findings,
            "severity": overall_severity,
            "summary": f"Found {len(findings)} vulnerabilities",
            "total_count": len(findings)
        }
