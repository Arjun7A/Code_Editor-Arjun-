import subprocess
import json
import tempfile
import shutil
import re
import os
import time
import sys
import asyncio
import logging
from scanner_extras import run_extras
from groq import Groq
from dotenv import load_dotenv

load_dotenv()

# ── Shared path helper ─────────────────────────────────────────────────────────
def _make_relative(file_path: str, repo_path: str) -> str:
    """Strip repo_path prefix and normalize separators to forward slashes."""
    import re as _re
    # Normalize all backslashes to forward slashes
    fp   = file_path.replace("\\", "/")
    rp   = repo_path.replace("\\", "/").rstrip("/")
    # Try direct prefix strip
    if fp.startswith(rp):
        return fp[len(rp):].lstrip("/")
    # Try case-insensitive (Windows)
    if fp.lower().startswith(rp.lower()):
        return fp[len(rp):].lstrip("/")
    # Fallback: strip any temp path pattern
    cleaned = _re.sub(r'^.*/[Tt]emp/tmp[^/]+/', '', fp)
    cleaned = _re.sub(r'^.*/AppData/[^/]+/[^/]+/[^/]+/', '', cleaned)
    if cleaned != fp:
        return cleaned.lstrip("/")
    # Last resort: just strip repo_path as-is
    return file_path.replace(repo_path, "").lstrip("/\\").replace("\\", "/")


# ── Patch seclab env before importing it ───────────────────────────────────────
os.environ.setdefault("AI_API_TOKEN",    os.getenv("GROQ_API_KEY", ""))
os.environ.setdefault("AI_API_ENDPOINT", "https://api.groq.com/openai/v1")
os.environ.setdefault("COPILOT_DEFAULT_MODEL", os.getenv("GROQ_MODEL", "llama-3.3-70b-versatile"))

# ── Validate keys on startup ───────────────────────────────────────────────────
_groq_key     = os.getenv("GROQ_API_KEY", "")
_github_token = os.getenv("GITHUB_USER_TOKEN", "")

if not _groq_key:
    print("[WARNING] GROQ_API_KEY is not set in .env")
if not _github_token:
    print("[WARNING] GITHUB_USER_TOKEN is not set in .env")

# ── Tool paths ─────────────────────────────────────────────────────────────────
BASE_DIR    = os.path.dirname(os.path.abspath(__file__))
# Auto-detect semgrep — works on Windows, Mac, Linux
import shutil as _shutil
import sys as _sys

def _find_semgrep() -> str:
    # 1. Check env override
    env_path = os.getenv("SEMGREP_PATH")
    if env_path and os.path.exists(env_path):
        return env_path
    # 2. Check same venv as current Python
    venv_bin = os.path.join(os.path.dirname(_sys.executable),
                            "semgrep.exe" if os.name == "nt" else "semgrep")
    if os.path.exists(venv_bin):
        return venv_bin
    # 3. Check PATH
    path_semgrep = _shutil.which("semgrep")
    if path_semgrep:
        return path_semgrep
    raise FileNotFoundError(
        "semgrep not found. Install it with: pip install semgrep\n"
        "Or set SEMGREP_PATH in your .env to the full path."
    )

SEMGREP_CMD = _find_semgrep()
print(f"[Semgrep] Using: {SEMGREP_CMD}")
OSV_CMD     = os.path.join(BASE_DIR, "osv-scanner_windows_amd64.exe")
GROQ_MODEL  = os.getenv("GROQ_MODEL", "llama-3.3-70b-versatile")
GROQ_CLIENT = Groq(api_key=_groq_key)

# Global flag to stop enrichment if daily quota is hit
_daily_quota_exhausted = False


# ══════════════════════════════════════════════════════════════════════════════
# GITHUB PR HELPERS
# ══════════════════════════════════════════════════════════════════════════════
def parse_pr_url(pr_url: str) -> tuple[str, str, str]:
    """
    Extract owner, repo, pr_number from a GitHub PR URL.
    e.g. https://github.com/owner/repo/pull/123
    """
    match = re.match(r"https://github\.com/([^/]+)/([^/]+)/pull/(\d+)", pr_url)
    if not match:
        raise ValueError(f"Invalid PR URL: {pr_url}")
    return match.group(1), match.group(2), match.group(3)


def get_pr_changed_files(owner: str, repo: str, pr_number: str) -> list[dict]:
    """
    Fetch list of changed files in a PR via GitHub API.
    Returns list of {filename, status, additions, deletions, patch}
    """
    import urllib.request
    url = f"https://api.github.com/repos/{owner}/{repo}/pulls/{pr_number}/files"
    req = urllib.request.Request(url, headers={
        "Authorization": f"token {_github_token}",
        "Accept": "application/vnd.github.v3+json",
        "User-Agent": "PR-Security-Scanner"
    })
    try:
        with urllib.request.urlopen(req) as resp:
            return json.loads(resp.read().decode())
    except Exception as e:
        print(f"[PR] Failed to fetch PR files: {e}")
        return []


def get_pr_diff(owner: str, repo: str, pr_number: str) -> str:
    """Fetch the full unified diff of the PR."""
    import urllib.request
    url = f"https://api.github.com/repos/{owner}/{repo}/pulls/{pr_number}"
    req = urllib.request.Request(url, headers={
        "Authorization": f"token {_github_token}",
        "Accept": "application/vnd.github.v3.diff",
        "User-Agent": "PR-Security-Scanner"
    })
    try:
        with urllib.request.urlopen(req) as resp:
            return resp.read().decode("utf-8", errors="ignore")
    except Exception as e:
        print(f"[PR] Failed to fetch PR diff: {e}")
        return ""


# ══════════════════════════════════════════════════════════════════════════════
# CLONE REPO
# ══════════════════════════════════════════════════════════════════════════════
def clone_repo(repo_url: str) -> str:
    temp_dir = tempfile.mkdtemp()
    subprocess.run(
        ["git", "clone", "--depth", "1", repo_url, temp_dir],
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
        check=True
    )
    return temp_dir


# ══════════════════════════════════════════════════════════════════════════════
# SEMGREP  (scoped to PR changed files only)
# ══════════════════════════════════════════════════════════════════════════════
def run_semgrep(repo_path: str, changed_files: list[str] = None) -> list:
    try:
        # Always scan full repo — p/security-audit rules only trigger on
        # source code files (.py, .js, .java etc.), not .html/.jsp/.properties
        # Then filter results to changed files only
        result = subprocess.run(
            [
                SEMGREP_CMD,
                "--config=p/security-audit",
                "--json",
                "--no-rewrite-rule-ids",
                "--quiet",
                repo_path
            ],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            timeout=300
        )

        stdout = result.stdout.decode("utf-8", errors="ignore").strip()
        if not stdout:
            print("[Semgrep] No output received.")
            return []

        data = json.loads(stdout)
        for err in data.get("errors", []):
            print(f"[Semgrep][Error] {err.get('message', '')}")

        severity_map = {
            "error": "high", "warning": "medium",
            "info": "low",   "critical": "critical",
        }

        # Semgrep rule-level severity overrides — specific dangerous rules
        critical_rules = {
            "exec-detected", "eval-detected", "code-injection",
            "deserialization", "rce", "command-injection",
            "unsafe-deserialization", "arbitrary-code-execution"
        }
        high_rules = {
            "sql-injection", "sqli", "xss", "ssrf", "xxe",
            "path-traversal", "lfi", "rfi", "open-redirect",
            "hardcoded-secret", "hardcoded-password", "hardcoded-token",
            "insecure-direct-object-reference", "idor",
            "authentication-bypass", "auth-bypass",
            "use-defused-xml", "avoid-pickle", "avoid-mark-safe",
            "raw-query", "avoid-raw-sql", "query-set-extra"
        }

        def _semgrep_severity(rule_id: str, raw_sev: str) -> str:
            rule_lower = rule_id.lower()
            # Check if rule_id contains any critical keyword
            if any(k in rule_lower for k in critical_rules):
                return "critical"
            # Check if rule_id contains any high keyword
            if any(k in rule_lower for k in high_rules):
                return "high"
            # Fall back to Semgrep's own severity level
            return severity_map.get(raw_sev, "medium")

        issues = []
        for res in data.get("results", []):
            raw_sev   = res.get("extra", {}).get("severity", "warning").lower()
            rule_id   = res.get("check_id", "")
            file_path = res.get("path", "")
            rel_path = _make_relative(file_path, repo_path)
            # False positive filter — skip known noisy/incorrect rules
            fp_rule_fragments = [
                "test",           # test files rarely have real vulns
                "audit.use-sys-argv",  # not a real vuln
                "audit.formatted-sql-query",  # too noisy
                "avoid-assert",   # assert is fine in non-prod
                "debugging-code", # not a security issue
            ]
            if any(fp in rule_id.lower() for fp in fp_rule_fragments):
                continue

            # Skip low confidence findings on test/mock files
            if rel_path and any(x in rel_path.lower() for x in ["test_", "_test.", "/tests/", "/test/", "mock", "fixture", "conftest"]):
                if _semgrep_severity(rule_id, raw_sev) in ("low", "medium"):
                    continue

            issues.append({
                "tool":     "semgrep",
                "severity": _semgrep_severity(rule_id, raw_sev),
                "message":  res.get("extra", {}).get("message", "No message").strip(),
                "file":     rel_path,
                "line":     res.get("start", {}).get("line", 0),
                "rule_id":  res.get("check_id", "")
            })

        print(f"[Semgrep] Found {len(issues)} issue(s) across full repo.")
        return issues

    except subprocess.TimeoutExpired:
        print("[Semgrep] Timed out.")
        return []
    except json.JSONDecodeError as e:
        print(f"[Semgrep] JSON parse error: {e}")
        return []
    except Exception as e:
        print(f"[Semgrep] Unexpected error: {e}")
        return []


# ══════════════════════════════════════════════════════════════════════════════
# OSV-SCANNER
# ══════════════════════════════════════════════════════════════════════════════
def _find_package_line(file_path: str, package_name: str) -> int:
    try:
        artifact = package_name.split(":")[-1] if ":" in package_name else package_name
        artifact = artifact.split("@")[0]
        with open(file_path, "r", encoding="utf-8", errors="ignore") as f:
            for i, line in enumerate(f, start=1):
                if artifact.lower() in line.lower():
                    return i
    except Exception:
        pass
    return 0


# Cache for OSV API lookups to avoid repeated calls
_osv_severity_cache: dict = {}

def _lookup_osv_severity(vuln_id: str) -> str:
    """
    Look up real CVSS severity from OSV API for a given vuln ID.
    Caches results to avoid repeated API calls.
    """
    if not vuln_id:
        return ""
    if vuln_id in _osv_severity_cache:
        return _osv_severity_cache[vuln_id]
    try:
        import urllib.request as _req
        import json as _json
        url = f"https://api.osv.dev/v1/vulns/{vuln_id}"
        req = _req.Request(url, headers={"User-Agent": "PR-Security-Scanner"})
        with _req.urlopen(req, timeout=5) as resp:
            data = _json.loads(resp.read())

        # Try severity array first
        for sev in data.get("severity", []):
            score_str = sev.get("score", "")
            result = _cvss_score_to_severity(score_str)
            if result:
                _osv_severity_cache[vuln_id] = result
                return result

        # Try database_specific
        db_sev = data.get("database_specific", {}).get("severity", "").upper()
        mapping = {"CRITICAL": "critical", "HIGH": "high", "MODERATE": "medium", "MEDIUM": "medium", "LOW": "low"}
        if db_sev in mapping:
            _osv_severity_cache[vuln_id] = mapping[db_sev]
            return mapping[db_sev]

        # Try affected ecosystem_specific
        for affected in data.get("affected", []):
            eco_sev = affected.get("ecosystem_specific", {}).get("severity", "").upper()
            if eco_sev in mapping:
                _osv_severity_cache[vuln_id] = mapping[eco_sev]
                return mapping[eco_sev]

    except Exception as e:
        print(f"[OSV Severity] API lookup failed for {vuln_id}: {e}")
    return ""


def _cvss_score_to_severity(score_str: str) -> str:
    """Convert a CVSS score string or vector to a severity label."""
    try:
        # Extract numeric score from CVSS vector e.g. CVSS:3.1/AV:N/.../8.8
        # or plain numeric string e.g. "8.8"
        nums = re.findall(r"\b(\d+\.\d+)\b", score_str)
        if nums:
            cvss = float(nums[-1])
        else:
            cvss = float(score_str)
        if cvss >= 9.0:
            return "critical"
        elif cvss >= 7.0:
            return "high"
        elif cvss >= 4.0:
            return "medium"
        else:
            return "low"
    except (ValueError, TypeError):
        return ""


def _parse_osv_severity(vuln: dict) -> str:
    """
    Extract severity from an OSV vulnerability object.
    Checks all possible locations including live OSV API lookup.
    Priority: severity[] array (CVSS) > database_specific > affected[].ecosystem_specific > OSV API > keyword fallback
    """
    # 0. Try live OSV API lookup first for accurate CVSS score
    vuln_id = vuln.get("id", "")
    api_result = _lookup_osv_severity(vuln_id)
    if api_result:
        return api_result

    # 1. Top-level severity array — CVSS scores (most reliable)
    for sev_info in vuln.get("severity", []):
        score_str = sev_info.get("score", "")
        result = _cvss_score_to_severity(score_str)
        if result:
            return result
        # Sometimes score is a text label
        score_upper = score_str.upper()
        if "CRITICAL" in score_upper:
            return "critical"
        elif "HIGH" in score_upper:
            return "high"
        elif "LOW" in score_upper:
            return "low"
        elif "MODERATE" in score_upper or "MEDIUM" in score_upper:
            return "medium"

    # 2. database_specific.severity (GitHub Advisory format)
    db_sev = vuln.get("database_specific", {}).get("severity", "").upper()
    if db_sev == "CRITICAL":
        return "critical"
    elif db_sev == "HIGH":
        return "high"
    elif db_sev == "LOW":
        return "low"
    elif db_sev in ("MODERATE", "MEDIUM"):
        return "medium"

    # 3. affected[].ecosystem_specific.severity (npm/PyPI format)
    for affected in vuln.get("affected", []):
        eco_sev = affected.get("ecosystem_specific", {}).get("severity", "").upper()
        if eco_sev == "CRITICAL":
            return "critical"
        elif eco_sev == "HIGH":
            return "high"
        elif eco_sev == "LOW":
            return "low"
        elif eco_sev in ("MODERATE", "MEDIUM"):
            return "medium"

        # Also check database_specific inside affected
        db_sev2 = affected.get("database_specific", {}).get("severity", "").upper()
        if db_sev2 == "CRITICAL":
            return "critical"
        elif db_sev2 == "HIGH":
            return "high"
        elif db_sev2 == "LOW":
            return "low"
        elif db_sev2 in ("MODERATE", "MEDIUM"):
            return "medium"

    # 4. Fallback — infer from vuln type keywords in summary + id
    summary = vuln.get("summary", "").lower()
    vuln_id = vuln.get("id", "").lower()
    text = summary + " " + vuln_id

    critical_keywords = [
        "remote code execution", "rce", "arbitrary code execution",
        "privilege escalation", "authentication bypass", "auth bypass",
        "unauthenticated", "zero-click", "zero click"
    ]
    high_keywords = [
        "sql injection", "sqli", "xxe", "xml external entity",
        "ssrf", "server-side request forgery",
        "arbitrary file write", "path traversal", "directory traversal",
        "private key", "key recovery", "secret extraction",
        "template injection", "ssti", "code injection",
        "prototype pollution", "deserialization",
        "arbitrary file read", "lfi", "rfi",
        "open redirect", "header injection", "crlf injection",
        "request smuggling", "http smuggling"
    ]
    medium_keywords = [
        "denial of service", " dos ", "redos", "regex denial",
        "information disclosure", "data leakage", "sensitive data",
        "timing attack", "algorithm confusion", "cryptographic",
        "infinite loop", "memory consumption", "unbounded",
        "unhandled exception", "crash"
    ]

    if any(k in text for k in critical_keywords):
        return "critical"
    elif any(k in text for k in high_keywords):
        return "high"
    elif any(k in text for k in medium_keywords):
        return "medium"
    else:
        return "medium"


def run_osv(repo_path: str) -> list:
    try:
        result = subprocess.run(
            [OSV_CMD, "--recursive", "--format", "json", repo_path],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            timeout=300
        )

        stdout = result.stdout.decode("utf-8", errors="ignore").strip()
        if not stdout:
            print("[OSV] No output received.")
            return []

        data   = json.loads(stdout)
        issues = []

        for result_item in data.get("results", []):
            source = result_item.get("source", {}).get("path", "")
            # Normalize separators and make path relative
            source = _make_relative(source, repo_path)

            for pkg in result_item.get("packages", []):
                pkg_name    = pkg.get("package", {}).get("name", "")
                pkg_version = pkg.get("package", {}).get("version", "")
                line_number = _find_package_line(
                    os.path.join(repo_path, source.replace("/", os.sep)), pkg_name
                )

                for vuln in pkg.get("vulnerabilities", []):
                    severity = _parse_osv_severity(vuln)

                    issues.append({
                        "tool":     "osv-scanner",
                        "severity": severity,
                        "message":  f"{vuln.get('id', '')} — {vuln.get('summary', 'No summary')}",
                        "file":     source,
                        "line":     line_number,
                        "package":  f"{pkg_name}@{pkg_version}",
                    })

        print(f"[OSV] Found {len(issues)} issue(s).")
        return issues

    except subprocess.TimeoutExpired:
        print("[OSV] Timed out.")
        return []
    except json.JSONDecodeError as e:
        print(f"[OSV] JSON parse error: {e}")
        return []
    except Exception as e:
        print(f"[OSV] Unexpected error: {e}")
        return []


# ══════════════════════════════════════════════════════════════════════════════
# GROQ ENRICHMENT  (for Semgrep + OSV findings)
# ══════════════════════════════════════════════════════════════════════════════
def _extract_retry_delay(error_str: str) -> float:
    match = re.search(r'try again in (\d+(?:\.\d+)?)s', str(error_str), re.IGNORECASE)
    if match:
        return float(match.group(1)) + 2.0
    return 10.0


def _read_code_context(repo_path: str, file: str, line: int, context: int = 8) -> str:
    """Read real code around the finding line from the cloned repo."""
    if not repo_path or not file or not line:
        return ""
    try:
        full_path = os.path.join(repo_path, file.replace("/", os.sep))
        if not os.path.exists(full_path):
            # try alternate separators
            full_path = os.path.join(repo_path, file.replace("\\", os.sep))
        if not os.path.exists(full_path):
            return ""
        with open(full_path, "r", encoding="utf-8", errors="ignore") as f:
            lines = f.readlines()
        start = max(0, line - context - 1)
        end   = min(len(lines), line + context)
        snippet = ""
        for i, l in enumerate(lines[start:end], start=start+1):
            marker = ">>>" if i == line else "   "
            snippet += f"{marker} {i:4d} | {l}"
        return snippet.strip()
    except Exception:
        return ""


def _enrich_issue(issue: dict, repo_path: str = "", retries: int = 5) -> dict:
    for attempt in range(retries):
        try:
            tool    = issue.get("tool", "")
            message = issue.get("message", "")
            file    = issue.get("file", "")
            line    = issue.get("line", 0)
            package = issue.get("package", "")

            # Read REAL code from the cloned repo
            code_context = _read_code_context(repo_path, file, line) if repo_path else ""

            if tool == "osv-scanner":
                prompt = f"""You are a senior security engineer. A dependency vulnerability was found.

Vulnerability: {message}
Package: {package}
Dependency file: {file}

Explain this vulnerability and give the exact fix for this specific package version.

Respond in this exact JSON format only, no markdown, no preamble:
{{
  "explanation": "2-3 sentences: what this CVE is, what an attacker can do with it, what data or systems are at risk",
  "fix": "exact fix: e.g. upgrade {package} to version X.Y.Z by running: pip install package==X.Y.Z and updating requirements.txt line N"
}}"""
            else:
                prompt = f"""You are a senior security engineer reviewing a real code finding.

Security Issue: {message}
File: {file}
Line: {line}

Real code from the file (>>> marks the vulnerable line):
```
{code_context if code_context else "Code not available"}
```

Based on the ACTUAL CODE above, explain this vulnerability and give the exact fix.

Respond in this exact JSON format only, no markdown, no preamble:
{{
  "explanation": "2-3 sentences referencing the ACTUAL CODE shown: what the vulnerable line does, why it is dangerous, what an attacker can do",
  "fix": "exact fix referencing the ACTUAL CODE: what specific line to change, what to replace it with, copy-pasteable code"
}}"""

            response = GROQ_CLIENT.chat.completions.create(
                model=GROQ_MODEL,
                messages=[{"role": "user", "content": prompt}],
                temperature=0
            )

            text = response.choices[0].message.content.strip()
            text = re.sub(r"```(?:json)?", "", text).replace("```", "").strip()

            try:
                parsed = json.loads(text)
            except json.JSONDecodeError:
                # fix common escape issues from LLM output
                fixed = text.replace('\\', '').replace('\"', '')
                fixed = fixed.replace('', '\"').replace('', '\\\\')
                try:
                    parsed = json.loads(fixed)
                except json.JSONDecodeError:
                    # last resort — extract with regex
                    exp_match = re.search(r'"explanation"\s*:\s*"(.*?)"(?:\s*,|\s*})', text, re.DOTALL)
                    fix_match = re.search(r'"fix"\s*:\s*"(.*?)"(?:\s*,|\s*})', text, re.DOTALL)
                    parsed = {
                        "explanation": exp_match.group(1).strip() if exp_match else "",
                        "fix": fix_match.group(1).strip() if fix_match else ""
                    }

            issue["explanation"] = parsed.get("explanation", "")
            issue["fix"]         = parsed.get("fix", "")
            return issue

        except Exception as e:
            error_str = str(e)
            if "429" in error_str or "rate_limit" in error_str.lower():
                wait = _extract_retry_delay(error_str)
                print(f"[Enrichment] Rate limited. Waiting {wait:.0f}s (attempt {attempt+1}/{retries})...")
                time.sleep(wait)
            elif "503" in error_str or "unavailable" in error_str.lower():
                wait = (2 ** attempt) * 5
                print(f"[Enrichment] Server overloaded. Waiting {wait}s (attempt {attempt+1}/{retries})...")
                time.sleep(wait)
            else:
                print(f"[Enrichment] Failed: {e}")
                issue["explanation"] = ""
                issue["fix"]         = ""
                return issue

    print(f"[Enrichment] All retries exhausted for: {issue.get('message', '')[:60]}")
    issue["explanation"] = ""
    issue["fix"]         = ""
    return issue


def enrich_issues(issues: list, repo_path: str = "") -> list:
    unique_issues   = []
    seen_issue_keys = set()

    for issue in issues:
        tool = issue.get("tool", "")
        if tool == "osv-scanner":
            cve_id    = issue.get("message", "").split("—")[0].strip()
            pkg_name  = issue.get("package", "").split("@")[0]
            dedup_key = f"{cve_id}|{pkg_name}"
        elif tool == "semgrep":
            dedup_key = issue.get("rule_id", issue.get("message", ""))
        else:
            dedup_key = issue.get("message", "")[:100]

        if dedup_key not in seen_issue_keys:
            seen_issue_keys.add(dedup_key)
            unique_issues.append(issue)

    removed = len(issues) - len(unique_issues)
    print(f"[Enrichment] Deduplicated {len(issues)} → {len(unique_issues)} unique issues ({removed} duplicates removed).")

    seen     = {}
    enriched = []
    calls    = 0

    for issue in unique_issues:
        tool = issue.get("tool", "")
        if tool == "osv-scanner":
            enrich_key = issue.get("message", "").split("—")[0].strip()
        elif tool == "semgrep":
            enrich_key = issue.get("rule_id", issue.get("message", ""))
        else:
            enrich_key = issue.get("message", "")[:100]

        if enrich_key in seen:
            issue["explanation"] = seen[enrich_key]["explanation"]
            issue["fix"]         = seen[enrich_key]["fix"]
        else:
            print(f"[Enrichment] Enriching {calls+1}: {enrich_key[:60]}")
            issue = _enrich_issue(issue, repo_path=repo_path)
            seen[enrich_key] = {"explanation": issue["explanation"], "fix": issue["fix"]}
            calls += 1
            time.sleep(2)

        enriched.append(issue)

    print(f"[Enrichment] {calls} Groq calls for {len(unique_issues)} unique issues.")
    return enriched


# ══════════════════════════════════════════════════════════════════════════════
# AI AGENT  (seclab-taskflow-agent scoped to PR diff)
# ══════════════════════════════════════════════════════════════════════════════
def run_ai_agent(repo_url: str, pr_url: str, changed_files: list[dict]) -> dict:
    """
    Run AI security audit on the PR diff.
    Returns a structured dict with detailed findings as a separate section.
    """
    result = {
        "status":   "not_run",
        "model":    GROQ_MODEL,
        "findings": [],
        "error":    None
    }

    if not changed_files:
        result["status"] = "skipped"
        result["error"]  = "No changed files found in PR"
        return result

    try:
        # Build focused diff context — cap per file to stay within token limits
        file_summaries = []
        max_files = int(os.getenv("AI_AGENT_MAX_FILES", "20"))
        for f in changed_files[:max_files]:
            fname  = f.get("filename", "")
            status = f.get("status", "")
            max_patch = int(os.getenv("AI_AGENT_MAX_PATCH_CHARS", "3000"))
            patch  = f.get("patch", "")[:max_patch]
            file_summaries.append(
                f"File: {fname} ({status})\n"
                f"Changes:\n{patch}\n"
            )

        diff_context = "\n---\n".join(file_summaries)

        prompt = f"""You are a senior application security engineer reviewing a GitHub Pull Request for security vulnerabilities.

Repository: {repo_url}
PR: {pr_url}

The following files were changed in this PR. Audit ONLY these changes.

{diff_context}

For every security issue you find, produce a detailed report entry. Respond with a JSON array only — no markdown, no preamble.

Use this exact schema for each finding:
[
  {{
    "title": "Short precise name e.g. 'Remote JS Injection via External Script Tag in main.jsp'",
    "severity": "critical|high|medium|low — use CVSS 3.1 scale: critical=RCE/auth bypass/data exfil no interaction, high=significant impact needs some interaction, medium=limited impact or requires privileges, low=minimal impact",
    "file": "exact filename where the issue was found",
    "category": "e.g. SQL Injection, XSS, IDOR, Auth Bypass, Hardcoded Secret, Path Traversal, SSRF, RCE, etc.",
    "cwe": "CWE-XXX or empty string",
    "severity_reasoning": "1-2 sentences: exactly why this severity — what specific impact makes it critical vs high vs medium. Reference the actual code.",
    "explanation": "4-5 sentences: (1) Quote the exact vulnerable code snippet from the diff. (2) Explain what it does and why it is dangerous. (3) Describe step by step what an attacker does to exploit it. (4) State exactly what gets compromised — user sessions, credentials, server, database. (5) Explain why this specific change in this PR introduces the risk.",
    "fix": {{
      "summary": "One line: exactly what to do to fix this",
      "before": "Copy the EXACT vulnerable line(s) from the diff verbatim — this must match the diff character for character",
      "after": "Paste the exact replacement code here — working, copy-pasteable code",
      "steps": [
        "Step 1: Open <exact filename>, find this exact code: <paste the before snippet>",
        "Step 2: Replace it with <exact code to paste>",
        "Step 3: <Any additional config, import, or dependency change needed — be specific>"
      ]
    }},
    "references": [
      "https://owasp.org/relevant-page",
      "https://cwe.mitre.org/data/definitions/XXX.html"
    ]
  }}
]

Rules:
- Only report vulnerabilities actually visible in the diff — no theoretical issues
- The 'before' field MUST be copied character-for-character from the diff — it will be used to highlight the exact code in the UI
- Do NOT include line numbers anywhere — we do not use line numbers
- before/after must be real code from the diff, not pseudocode or placeholders
- Steps must reference exact filenames and exact code snippets — never say 'validate input' or 'test the application'
- If no issues found, return exactly: []
- Return only the JSON array, nothing else

STRICT FALSE POSITIVE RULES — never flag these as vulnerabilities:

ENVIRONMENT & SECRETS:
- os.environ.get(), os.getenv(), os.environ[] — reading from env vars is CORRECT and SECURE. Never flag.
- dotenv, load_dotenv(), python-decouple — these are best practices for secret management. Never flag.
- settings.SECRET_KEY, config.API_KEY — reading from config objects is not hardcoding. Never flag.
- Any variable named token, key, secret, password that READS from env/config — never flag.
- Only flag if a secret VALUE is hardcoded as a string literal e.g. token = "ghp_abc123xyz"

HTTP & NETWORK:
- requests.get/post/put/delete() without verify= — verify=True is the DEFAULT. Only flag if verify=False is explicit.
- httpx, aiohttp, urllib — same rule, only flag explicit verify=False or ssl=False.
- timeout parameter in requests — having a timeout is GOOD practice, never flag.
- HTTPS URLs — using https:// is secure. Never flag.
- Only flag HTTP (not HTTPS) if sensitive data is clearly being transmitted.

LOGGING & DEBUGGING:
- logging.info(), logging.debug(), logging.warning(), logging.error(), logging.critical() — never flag unless a password/token VALUE is literally inside the log string.
- print() statements — never a vulnerability.
- Sentry, Datadog, New Relic integrations — standard monitoring, never flag.

STANDARD PATTERNS:
- Standard library imports (os, sys, json, re, hashlib, base64, uuid) — never flag.
- Type hints, dataclasses, pydantic models — never flag.
- Docstrings, comments, TODO comments — never flag.
- try/except blocks — never flag.
- assert statements in tests — never flag.
- __init__.py files — never flag.
- Test files (test_*.py, *_test.py) — only flag if they contain real credentials.

AUTHENTICATION & CRYPTO:
- JWT decode without verification ONLY flag if verify=False or options={{"verify_signature": False}} is explicit.
- bcrypt, argon2, passlib — these are CORRECT password hashing. Never flag.
- hashlib.sha256(), hashlib.sha512() — secure hashes. Never flag. Only flag md5/sha1 used for passwords.
- secrets.token_hex(), secrets.token_urlsafe() — correct secret generation. Never flag.
- uuid.uuid4() — correct ID generation. Never flag.

DATABASE:
- ORM queries (Django ORM, SQLAlchemy ORM) — parameterized by default. Never flag ORM usage.
- Only flag raw SQL strings with f-strings or % formatting e.g. f"SELECT * WHERE id={{user_id}}"

GENERAL:
- Any pattern where the code is clearly intentional framework/library usage — never flag.
- Any pattern where you are not 100% certain it is exploitable — do NOT report it.
- If the fix would be "add verify=True" when it already defaults to True — do NOT report it.
- Only report things that are unambiguously exploitable vulnerabilities in the actual diff."""

        response = GROQ_CLIENT.chat.completions.create(
            model=GROQ_MODEL,
            messages=[
                {
                    "role": "system",
                    "content": (
                        "You are a senior application security engineer doing a code review. "
                        "When you find a vulnerability, you explain it the way a senior dev would explain it to a junior dev — "
                        "specific, direct, and actionable. You always reference the EXACT line or code snippet from the diff. "
                        "Your fix steps are like pair programming instructions: tell them exactly what to delete, "
                        "exactly what to paste in its place, and exactly why. "
                        "Never use generic advice like 'validate inputs' or 'test the application'. "
                        "Always say EXACTLY what to change, where to change it, and what to replace it with. "
                        "CRITICAL: os.environ.get(), os.getenv() are SECURE ways to read secrets — NEVER flag them. "
                        "CRITICAL: requests.get() without verify= is already secure by default (verify=True) — NEVER flag it. "
                        "CRITICAL: Only report things you are 100% certain are real exploitable vulnerabilities. "
                        "If in doubt, do NOT report it. False positives are worse than missed findings. "
                        "You always respond with valid JSON only — no markdown fences, no preamble."
                    )
                },
                {
                    "role": "user",
                    "content": prompt
                }
            ],
            temperature=0,
            max_tokens=8192
        )

        text = response.choices[0].message.content.strip()
        text = re.sub(r"```(?:json)?", "", text).replace("```", "").strip()

        if text in ("[]", "[ ]"):
            result["status"]   = "completed"
            result["findings"] = []
            print("[AI Agent] No security issues found in PR diff.")
            return result

        findings = json.loads(text)

        # Validate and normalise each finding
        normalised = []
        for f in findings:
            if not isinstance(f, dict):
                continue

            # fix field can be dict (new schema) or string (fallback)
            fix_raw = f.get("fix", {})
            if isinstance(fix_raw, str):
                fix = {
                    "summary": fix_raw,
                    "before":  "",
                    "after":   "",
                    "steps":   []
                }
            else:
                fix = {
                    "summary": fix_raw.get("summary", ""),
                    "before":  fix_raw.get("before", ""),
                    "after":   fix_raw.get("after", ""),
                    "steps":   fix_raw.get("steps", [])
                }

            normalised.append({
                "title":              f.get("title", "Unknown Issue"),
                "severity":           f.get("severity", "medium").lower(),
                "file":               f.get("file", ""),
                "category":           f.get("category", ""),
                "cwe":                f.get("cwe", ""),
                "severity_reasoning": f.get("severity_reasoning", ""),
                "explanation":        f.get("explanation", ""),
                "fix":                fix,
                "references":         f.get("references", [])
            })

        result["status"]   = "completed"
        result["findings"] = normalised
        print(f"[AI Agent] Found {len(normalised)} security issue(s) in PR diff.")
        return result

    except json.JSONDecodeError as e:
        print(f"[AI Agent] JSON parse error: {e}")
        result["status"] = "error"
        result["error"]  = f"JSON parse error: {str(e)}"
        return result
    except Exception as e:
        print(f"[AI Agent] Error: {e}")
        result["status"] = "error"
        result["error"]  = str(e)
        return result


# ══════════════════════════════════════════════════════════════════════════════
# MAIN ENTRY POINT
# ══════════════════════════════════════════════════════════════════════════════
def analyze(repo_url: str, pr_url: str) -> dict:
    """
    Full security analysis of a PR.
    Returns a structured dict with:
      - issues:      Semgrep + OSV findings (enriched with Groq explanations)
      - ai_audit:    AI agent deep audit findings (separate section)
      - scan_summary: counts per tool
    """
    repo_path    = None
    issues       = []
    changed_files = []

    try:
        # ── Step 1: Fetch PR metadata ──────────────────────────────────────
        print(f"[Analyzer] Fetching PR info from {pr_url} ...")
        try:
            owner, repo, pr_number = parse_pr_url(pr_url)
            changed_files = get_pr_changed_files(owner, repo, pr_number)
            changed_filenames = [f["filename"] for f in changed_files]
            print(f"[Analyzer] PR has {len(changed_files)} changed file(s).")
        except Exception as e:
            print(f"[Analyzer] Could not fetch PR files: {e}. Will scan full repo.")
            changed_filenames = []

        # ── Step 2: Clone repo ─────────────────────────────────────────────
        print(f"[Analyzer] Cloning {repo_url} ...")
        repo_path = clone_repo(repo_url)
        print(f"[Analyzer] Cloned to {repo_path}")

        # ── Step 3: Semgrep (scoped to changed files) ──────────────────────
        print("[Analyzer] Running Semgrep ...")
        issues.extend(run_semgrep(repo_path, changed_filenames if changed_filenames else None))

        # ── Step 4: OSV Scanner ────────────────────────────────────────────
        print("[Analyzer] Running OSV-Scanner ...")
        issues.extend(run_osv(repo_path))

        # ── Step 5: Enrich Semgrep + OSV with Groq ────────────────────────
        print("[Analyzer] Enriching Semgrep/OSV issues with Groq ...")
        issues = enrich_issues(issues, repo_path=repo_path)

        # ── Step 6: AI Agent deep audit on PR diff ─────────────────────────
        print("[Analyzer] Running AI Agent audit on PR diff ...")
        ai_audit = run_ai_agent(repo_url, pr_url, changed_files)

        # ── Step 7: Gitleaks + Checkov ─────────────────────────────────────
        print("[Analyzer] Running Gitleaks + Checkov ...")
        extras = run_extras(repo_path)

    except Exception as e:
        print(f"[Analyzer] Fatal error: {e}")
        issues.append({
            "tool":     "system",
            "severity": "high",
            "message":  str(e),
            "file":     "",
            "line":     0
        })
        ai_audit = {
            "status":   "error",
            "model":    GROQ_MODEL,
            "findings": [],
            "error":    str(e)
        }
        extras = {"gitleaks": [], "checkov": []}
    finally:
        if repo_path:
            shutil.rmtree(repo_path, ignore_errors=True)
            print("[Analyzer] Cleaned up temp directory.")

    # ── Build final structured response ────────────────────────────────────
    semgrep_count   = sum(1 for i in issues if i.get("tool") == "semgrep")
    osv_count       = sum(1 for i in issues if i.get("tool") == "osv-scanner")
    ai_count        = len(ai_audit.get("findings", []))
    gitleaks_count  = len(extras.get("gitleaks", []))
    checkov_count   = len(extras.get("checkov", []))
    total           = len(issues) + ai_count + gitleaks_count + checkov_count

    print(f"[Analyzer] Done. Semgrep: {semgrep_count}, OSV: {osv_count}, AI Agent: {ai_count}, Gitleaks: {gitleaks_count}, Checkov: {checkov_count}")

    return {
        "scan_summary": {
            "total_issues":     total,
            "semgrep":          semgrep_count,
            "osv":              osv_count,
            "ai_agent":         ai_count,
            "gitleaks":         gitleaks_count,
            "checkov":          checkov_count,
            "pr_files_scanned": len(changed_files)
        },
        "issues":   issues,                    # Semgrep + OSV findings
        "ai_audit": ai_audit,                  # AI agent findings
        "gitleaks": extras.get("gitleaks", []),# Secret scanning findings
        "checkov":  extras.get("checkov", []), # IaC misconfiguration findings
    }