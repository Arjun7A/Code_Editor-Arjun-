"""
Snyk Scanner Service
Wraps Snyk CLI for dependency vulnerability scanning.
Produces frontend-compatible Vulnerability[] objects.
"""
import subprocess
import json
import time
import uuid
import logging
import os
import shutil
from typing import Dict, List, Optional
from pathlib import Path
from app.core.config import settings

logger = logging.getLogger(__name__)

# Snyk severity → frontend RiskLevel
_SEV_MAP = {
    "critical": "critical",
    "high": "high",
    "medium": "medium",
    "low": "low",
}

# Manifest file names that indicate a scannable project
_MANIFESTS = {
    "package.json",
    "package-lock.json",
    "yarn.lock",
    "pnpm-lock.yaml",
    "requirements.txt",
    "pipfile",
    "pyproject.toml",
    "setup.py",
    "pom.xml",
    "build.gradle",
    "gemfile",
    "go.mod",
    "cargo.toml",
}

_SKIP_DIRS = {
    ".git",
    "node_modules",
    ".venv",
    "venv",
    "__pycache__",
    "dist",
    "build",
}


def _find_snyk() -> Optional[str]:
    """Locate the snyk executable. On Windows snyk is installed as snyk.cmd."""
    for name in ("snyk", "snyk.cmd", "snyk.exe"):
        found = shutil.which(name)
        if found:
            return found
    return None


class SnykScanner:
    def __init__(self):
        self.tool_name = "snyk"

    # ------------------------------------------------------------------ #
    #  Installation check                                                   #
    # ------------------------------------------------------------------ #

    def check_installed(self) -> bool:
        """Return True if the snyk binary can be found."""
        return _find_snyk() is not None

    def _has_manifest(self, project_path: str) -> bool:
        """
        Check whether the project contains any dependency manifest.
        Searches recursively so monorepos/subfolders are detected too.
        """
        root = Path(project_path)
        if not root.exists():
            return False

        for current_root, dirs, files in os.walk(root):
            dirs[:] = [d for d in dirs if d not in _SKIP_DIRS]
            lower_files = {f.lower() for f in files}
            if lower_files.intersection(_MANIFESTS):
                return True
            if any(f.startswith("requirements") and f.endswith(".txt") for f in lower_files):
                return True
        return False

    # ------------------------------------------------------------------ #
    #  Main scanning entry-point                                            #
    # ------------------------------------------------------------------ #

    def scan_dependencies(self, project_path: str) -> Dict:
        """
        Scan project dependencies for vulnerabilities using Snyk CLI.

        Returns a dict compatible with the frontend Vulnerability[] type.
        """
        start_time = time.time()

        snyk_bin = _find_snyk()
        if not snyk_bin:
            logger.warning("Snyk CLI not found.")
            return self._empty_result(
                error="Snyk CLI not installed. Install via: npm install -g snyk",
                elapsed=time.time() - start_time,
            )

        if not self._has_manifest(project_path):
            logger.info("No dependency manifest found at %s – skipping Snyk.", project_path)
            return {
                "tool": "snyk",
                "findings": [],
                "severity": "info",
                "summary": "No dependency manifest found – Snyk skipped",
                "total_count": 0,
                "severity_counts": {"critical": 0, "high": 0, "medium": 0, "low": 0},
                "execution_time": 0.0,
                "status": "skipped",
            }

        # Read token from settings (loaded from .env by pydantic-settings)
        env = os.environ.copy()
        snyk_token = settings.SNYK_TOKEN or env.get("SNYK_TOKEN", "")
        # Inject into subprocess environment so snyk CLI picks it up
        if snyk_token:
            env["SNYK_TOKEN"] = snyk_token

        try:
            cmd = [snyk_bin, "test", "--json", "--all-projects"]
            if snyk_token:
                cmd += [f"--token={snyk_token}"]

            logger.info("Running snyk in %s", project_path)

            result = subprocess.run(
                cmd,
                cwd=project_path,
                capture_output=True,
                text=True,
                encoding="utf-8",
                errors="replace",
                timeout=180,
                env=env,
            )
            elapsed = time.time() - start_time

            raw_stdout = (result.stdout or "").strip()
            raw_stderr = (result.stderr or "").strip()
            raw = raw_stdout
            if not raw and (raw_stderr.startswith("{") or raw_stderr.startswith("[")):
                raw = raw_stderr

            # snyk exits 1 when vulnerabilities are found (not an error)
            if raw:
                try:
                    data = json.loads(raw)
                    return self._parse_snyk_output(data, elapsed)
                except json.JSONDecodeError as exc:
                    logger.error("JSON parse error: %s\nRaw: %s", exc, raw[:500])
                    return self._empty_result(
                        error=f"Could not parse Snyk JSON: {exc}", elapsed=elapsed
                    )

            if result.returncode not in (0, 1):
                stderr = raw_stderr[:300]
                return self._empty_result(
                    error=f"Snyk exited {result.returncode}: {stderr}", elapsed=elapsed
                )

            return {
                "tool": "snyk",
                "findings": [],
                "severity": "info",
                "summary": "No vulnerabilities found",
                "total_count": 0,
                "severity_counts": {"critical": 0, "high": 0, "medium": 0, "low": 0},
                "execution_time": round(elapsed, 2),
                "status": "success",
            }

        except subprocess.TimeoutExpired:
            elapsed = time.time() - start_time
            return self._empty_result(error="Snyk timed out (180 s)", elapsed=elapsed)
        except Exception as exc:
            elapsed = time.time() - start_time
            logger.exception("Unexpected Snyk error")
            return self._empty_result(error=str(exc), elapsed=elapsed)

    # ------------------------------------------------------------------ #
    #  Parse Snyk JSON output                                               #
    # ------------------------------------------------------------------ #

    def _parse_snyk_output(self, data: Dict, elapsed: float) -> Dict:
        """
        Convert raw Snyk JSON into frontend-compatible Vulnerability[] format.
        Handles both single-project and multi-project (--all-projects) output.
        """
        findings: List[Dict] = []
        severity_counts = {"critical": 0, "high": 0, "medium": 0, "low": 0}
        seen_ids: set = set()  # deduplicate by vuln ID

        # Snyk --all-projects returns a list; single project returns a dict
        projects = data if isinstance(data, list) else [data]

        for project in projects:
            if not isinstance(project, dict):
                continue
            for vuln in project.get("vulnerabilities", []):
                vuln_id = vuln.get("id", str(uuid.uuid4()))
                if vuln_id in seen_ids:
                    continue
                seen_ids.add(vuln_id)

                raw_sev = vuln.get("severity", "low").lower()
                severity = _SEV_MAP.get(raw_sev, "low")

                # CVEs and CWEs
                identifiers = vuln.get("identifiers", {})
                cves = identifiers.get("CVE", [])
                cwes = identifiers.get("CWE", [])
                cwe_str = cwes[0] if cwes else None
                cve_str = cves[0] if cves else None

                # CVSS score
                cvss_details = vuln.get("cvssScore") or vuln.get("CVSSv3") or None
                try:
                    cvss = float(cvss_details) if cvss_details else None
                except (TypeError, ValueError):
                    cvss = None

                # Fixed version
                fixed_in = vuln.get("fixedIn", [])
                fixed_version = fixed_in[0] if fixed_in else None

                finding = {
                    "id": str(uuid.uuid4()),
                    "title": vuln.get("title", "Unknown vulnerability"),
                    "description": (vuln.get("description") or "")[:500],
                    "severity": severity,
                    "cwe": cwe_str,
                    "cvss": cvss,
                    "package": vuln.get("packageName", ""),
                    "version": vuln.get("version", ""),
                    "fixedVersion": fixed_version,
                    # Extra metadata kept for backend storage
                    "_cve": cve_str,
                    "_vuln_id": vuln_id,
                    "_upgrade_path": vuln.get("upgradePath", []),
                    "_is_patchable": vuln.get("isPatchable", False),
                }
                findings.append(finding)

                if severity in severity_counts:
                    severity_counts[severity] += 1

        if severity_counts["critical"] > 0:
            overall = "critical"
        elif severity_counts["high"] > 0:
            overall = "high"
        elif severity_counts["medium"] > 0:
            overall = "medium"
        elif severity_counts["low"] > 0:
            overall = "low"
        else:
            overall = "info"

        return {
            "tool": "snyk",
            "findings": findings,
            "severity": overall,
            "summary": f"Found {len(findings)} vulnerability(ies)",
            "total_count": len(findings),
            "severity_counts": severity_counts,
            "execution_time": round(elapsed, 2),
            "status": "success",
        }

    # ------------------------------------------------------------------ #
    #  Helpers                                                              #
    # ------------------------------------------------------------------ #

    def _empty_result(self, error: str = "", elapsed: float = 0.0) -> Dict:
        return {
            "tool": "snyk",
            "findings": [],
            "severity": "info",
            "summary": error or "No findings",
            "total_count": 0,
            "severity_counts": {"critical": 0, "high": 0, "medium": 0, "low": 0},
            "execution_time": round(elapsed, 2),
            "status": "error" if error else "success",
            "error": error,
        }
