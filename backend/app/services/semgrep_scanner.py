"""
Semgrep Scanner Service
Wraps Semgrep CLI for static code analysis.
Falls back gracefully when CLI is unavailable.
"""
import subprocess
import json
import time
import uuid
import logging
import os
import sys
import shutil
import tempfile
from typing import Dict, List, Optional
from pathlib import Path

logger = logging.getLogger(__name__)

# Severity normalisation map (semgrep -> frontend)
_SEV_MAP = {
    "error": "critical",
    "warning": "high",
    "info": "medium",
    "critical": "critical",
    "high": "high",
    "medium": "medium",
    "low": "low",
}


def _find_semgrep() -> Optional[str]:
    """Locate the semgrep executable, checking PATH and venv Scripts dir."""
    # 1. Same Scripts/bin dir as the running Python interpreter
    scripts_dir = os.path.dirname(sys.executable)
    for name in ("semgrep.exe", "semgrep"):
        candidate = os.path.join(scripts_dir, name)
        if os.path.isfile(candidate):
            return candidate
    # 2. shutil.which (honours PATH)
    found = shutil.which("semgrep")
    if found:
        return found
    return None


class SemgrepScanner:
    def __init__(self):
        self.tool_name = "semgrep"
        # Open-source rules that work without semgrep login.
        # Uses the community registry (r/) instead of managed packs (p/).
        self.default_rules = [
            "r/python.lang.security",
            "r/python.flask",
            "r/python.django",
            "r/javascript.lang.security",
            "r/generic.secrets",
        ]

    def _snippet_from_file(self, path: str, start_line: int, end_line: int) -> str:
        """
        Build snippet directly from source file when possible.
        This avoids occasional malformed `extra.lines` payloads.
        """
        if not path or path == "unknown":
            return ""
        try:
            p = Path(path)
            if not p.is_file():
                return ""
            lines = p.read_text(encoding="utf-8", errors="replace").splitlines()
            if not lines:
                return ""
            s = max(1, int(start_line))
            e = max(s, int(end_line))
            s_idx = s - 1
            e_idx = min(len(lines), e)
            return "\n".join(lines[s_idx:e_idx]).strip()
        except Exception:
            return ""

    # ------------------------------------------------------------------ #
    #  Installation check                                                   #
    # ------------------------------------------------------------------ #

    def check_installed(self) -> bool:
        """Return True if the semgrep binary can be found."""
        return _find_semgrep() is not None

    # ------------------------------------------------------------------ #
    #  Main scanning entry-point                                            #
    # ------------------------------------------------------------------ #

    def scan_code(
        self,
        project_path: str,
        rules: Optional[List[str]] = None,
        code_content: Optional[str] = None,
        filename_hint: str = "code.py",
    ) -> Dict:
        """
        Scan source code for security issues.

        If `code_content` is given it is written to a temp file and scanned.
        Otherwise the directory at `project_path` is scanned.
        """
        start_time = time.time()
        rules_to_use = rules or self.default_rules

        tmp_path: Optional[str] = None
        scan_target = project_path

        if code_content:
            suffix = Path(filename_hint).suffix or ".py"
            with tempfile.NamedTemporaryFile(
                mode="w", suffix=suffix, delete=False, encoding="utf-8"
            ) as f:
                f.write(code_content)
                tmp_path = f.name
            scan_target = tmp_path

        try:
            return self._run_semgrep(scan_target, rules_to_use, start_time)
        finally:
            if tmp_path:
                try:
                    os.unlink(tmp_path)
                except OSError:
                    pass

    # ------------------------------------------------------------------ #
    #  Per-file scan (for per-PR scanning in GitHub analyzer)               #
    # ------------------------------------------------------------------ #

    def scan_files(self, file_paths: List[str], rules: Optional[List[str]] = None) -> Dict:
        """
        Scan a specific list of absolute file paths (not a whole directory).
        Used by the GitHub analyzer to scan only files changed in a given PR.
        """
        start_time = time.time()

        # Only pass paths that actually exist on disk
        existing = [p for p in file_paths if os.path.isfile(p)]
        if not existing:
            return self._empty_result(
                error="None of the changed files exist in the cloned repo",
                elapsed=0.0,
            )

        semgrep_bin = _find_semgrep()
        if not semgrep_bin:
            return self._empty_result(
                error="Semgrep CLI not installed. Install via: pip install semgrep",
                elapsed=time.time() - start_time,
            )

        rules_to_use = rules or self.default_rules
        # Pass each existing file path as a positional argument to semgrep
        cmd = (
            [semgrep_bin, "--json", "--quiet", "--no-git-ignore"]
            + ["--config=" + r for r in rules_to_use]
            + existing
        )
        logger.info("Running semgrep on %d file(s) for PR", len(existing))

        try:
            result = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                encoding="utf-8",
                errors="replace",
                timeout=300,
            )
            elapsed = time.time() - start_time

            raw_stdout = result.stdout.strip()
            raw_stderr = result.stderr.strip()

            if not raw_stdout:
                raw_stdout = raw_stderr if raw_stderr.startswith("{") else ""

            if raw_stdout:
                try:
                    data = json.loads(raw_stdout)
                    return self._parse_semgrep_output(data, elapsed)
                except json.JSONDecodeError as exc:
                    return self._empty_result(
                        error=f"Could not parse Semgrep JSON: {exc}", elapsed=elapsed
                    )

            return {
                "tool": "semgrep",
                "findings": [],
                "severity": "info",
                "summary": "No security issues found in changed files",
                "total_count": 0,
                "severity_counts": {"critical": 0, "high": 0, "medium": 0, "low": 0},
                "execution_time": round(elapsed, 2),
                "status": "success",
            }

        except subprocess.TimeoutExpired:
            elapsed = time.time() - start_time
            return self._empty_result(error="Semgrep timed out (300 s)", elapsed=elapsed)
        except Exception as exc:
            elapsed = time.time() - start_time
            logger.exception("Unexpected Semgrep error in scan_files")
            return self._empty_result(error=str(exc), elapsed=elapsed)

    # ------------------------------------------------------------------ #
    #  Internal: run semgrep CLI                                            #
    # ------------------------------------------------------------------ #

    def _run_semgrep(self, target: str, rules: List[str], start_time: float) -> Dict:
        semgrep_bin = _find_semgrep()
        if not semgrep_bin:
            logger.warning("Semgrep CLI not found.")
            return self._empty_result(
                error="Semgrep CLI not installed. Install via: pip install semgrep",
                elapsed=time.time() - start_time,
            )

        cmd = (
            [semgrep_bin, "--json", "--quiet", "--no-git-ignore"]
            + ["--config=" + r for r in rules]
            + [target]
        )
        logger.info("Running semgrep: %s", " ".join(cmd))

        try:
            result = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                encoding="utf-8",
                errors="replace",
                timeout=300,
            )
            elapsed = time.time() - start_time

            raw_stdout = result.stdout.strip()
            raw_stderr = result.stderr.strip()

            if not raw_stdout:
                raw_stdout = raw_stderr if raw_stderr.startswith("{") else ""

            if raw_stdout:
                try:
                    data = json.loads(raw_stdout)
                    return self._parse_semgrep_output(data, elapsed)
                except json.JSONDecodeError as exc:
                    logger.error("JSON parse error: %s", exc)
                    return self._empty_result(
                        error=f"Could not parse Semgrep JSON: {exc}",
                        elapsed=elapsed,
                    )

            if result.returncode not in (0, 1):
                return self._empty_result(
                    error=f"Semgrep exited with code {result.returncode}: {raw_stderr[:300]}",
                    elapsed=elapsed,
                )

            return {
                "tool": "semgrep",
                "findings": [],
                "severity": "info",
                "summary": "No security issues found",
                "total_count": 0,
                "severity_counts": {"critical": 0, "high": 0, "medium": 0, "low": 0},
                "execution_time": round(elapsed, 2),
                "status": "success",
            }

        except subprocess.TimeoutExpired:
            elapsed = time.time() - start_time
            return self._empty_result(error="Semgrep timed out (300 s)", elapsed=elapsed)
        except Exception as exc:
            elapsed = time.time() - start_time
            logger.exception("Unexpected Semgrep error")
            return self._empty_result(error=str(exc), elapsed=elapsed)

    # ------------------------------------------------------------------ #
    #  Parse Semgrep JSON output                                            #
    # ------------------------------------------------------------------ #

    def _parse_semgrep_output(self, data: Dict, elapsed: float) -> Dict:
        """Convert raw Semgrep JSON into frontend-compatible format."""
        findings: List[Dict] = []
        severity_counts = {"critical": 0, "high": 0, "medium": 0, "low": 0}

        for idx, result in enumerate(data.get("results", [])):
            extra = result.get("extra", {})
            metadata = extra.get("metadata", {})

            raw_sev = (
                extra.get("severity")
                or metadata.get("severity")
                or result.get("severity")
                or "medium"
            ).lower()
            severity = _SEV_MAP.get(raw_sev, "medium")

            start = result.get("start", {})
            end = result.get("end", {})
            start_line = start.get("line", 1)
            end_line = end.get("line", start_line)

            path = result.get("path", "unknown")
            snippet = self._snippet_from_file(path, start_line, end_line)
            if not snippet:
                snippet = (extra.get("lines") or extra.get("snippet") or "").strip()
            rule_id = result.get("check_id", f"semgrep-rule-{idx}")

            finding = {
                "id": str(uuid.uuid4()),
                "ruleId": rule_id,
                "message": (extra.get("message") or "Security issue detected").strip(),
                "severity": severity,
                "path": path,
                "startLine": start_line,
                "endLine": end_line,
                "snippet": snippet,
                "_fix": extra.get("fix", ""),
                "_cwe": metadata.get("cwe", []),
                "_owasp": metadata.get("owasp", []),
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

        errors = data.get("errors", [])
        if errors:
            logger.warning("Semgrep reported %d parse errors", len(errors))

        return {
            "tool": "semgrep",
            "findings": findings,
            "severity": overall,
            "summary": f"Found {len(findings)} security issue(s)",
            "total_count": len(findings),
            "severity_counts": severity_counts,
            "execution_time": round(elapsed, 2),
            "status": "success",
            "parse_errors": len(errors),
        }

    # ------------------------------------------------------------------ #
    #  Helpers                                                              #
    # ------------------------------------------------------------------ #

    def _empty_result(self, error: str = "", elapsed: float = 0.0) -> Dict:
        return {
            "tool": "semgrep",
            "findings": [],
            "severity": "info",
            "summary": error or "No findings",
            "total_count": 0,
            "severity_counts": {"critical": 0, "high": 0, "medium": 0, "low": 0},
            "execution_time": round(elapsed, 2),
            "status": "error" if error else "success",
            "error": error,
        }
