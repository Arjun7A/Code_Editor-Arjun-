"""
Git Metadata Extractor
Extracts real repository statistics (files changed, lines added/deleted,
commit count, language ratio, etc.) from a locally-cloned git repository.

Used to replace hardcoded ML-feature fallback values in the /api/analyze flow.
"""
import subprocess
import os
import logging
from pathlib import Path
from typing import Dict, Any, Optional
from collections import Counter

logger = logging.getLogger(__name__)

# Extensions used for language-ratio calculation
_JS_EXTENSIONS = {".js", ".jsx", ".ts", ".tsx", ".mjs", ".cjs"}
_PY_EXTENSIONS = {".py", ".pyx", ".pyi"}
_TEST_INDICATORS = {"test", "spec", "__test__", "__tests__", "tests", "test_", "_test"}

# Sensitive paths that indicate security-relevant files
SENSITIVE_PATHS = [
    "auth", "login", "session", "token", "crypto", "encrypt", "security",
    "password", "secret", "key", "cert", "ssl", "tls", "oauth",
    "permission", "access", "admin", "config", ".env",
]


def _run_git(args: list, cwd: str, timeout: int = 30) -> Optional[str]:
    """Run a git command and return stdout, or None on failure."""
    try:
        result = subprocess.run(
            ["git"] + args,
            cwd=cwd,
            capture_output=True,
            text=True,
            timeout=timeout,
        )
        if result.returncode == 0:
            return result.stdout.strip()
        logger.debug("git %s exited %d: %s", " ".join(args), result.returncode, result.stderr[:200])
        return None
    except (subprocess.TimeoutExpired, FileNotFoundError, Exception) as exc:
        logger.debug("git %s failed: %s", " ".join(args), exc)
        return None


def extract_repo_metadata(repo_path: str) -> Dict[str, Any]:
    """
    Extract real statistics from a cloned git repository.

    Returns a dict with keys that map directly to ML feature names:
        - files_changed (int): number of files changed in the most recent commit
        - lines_added (int): total lines added in the most recent commit
        - lines_deleted (int): total lines deleted in the most recent commit
        - commit_count (int): total number of commits in the repo
        - author_name (str): author of the most recent commit
        - has_test_changes (bool): whether any test files were modified
        - lang_ratio (float): ratio of JS/TS bytes to total (JS/TS + Python)
        - sensitive_files_count (int): number of security-sensitive files changed
    """
    p = Path(repo_path)
    if not (p / ".git").exists():
        logger.info("No .git directory at %s — returning defaults from file analysis", repo_path)
        return _analyze_files_only(repo_path)

    metadata: Dict[str, Any] = {}

    # ── Commit count ─────────────────────────────────────────────────────
    commit_count_raw = _run_git(["rev-list", "--count", "HEAD"], repo_path)
    metadata["commit_count"] = int(commit_count_raw) if commit_count_raw and commit_count_raw.isdigit() else 1

    # ── Latest commit author ─────────────────────────────────────────────
    author = _run_git(["log", "-1", "--format=%an"], repo_path)
    metadata["author_name"] = author or "unknown"

    # ── Diffstat for the latest commit ───────────────────────────────────
    diff_stat = _run_git(["diff", "--shortstat", "HEAD~1", "HEAD"], repo_path)
    files_changed, lines_added, lines_deleted = _parse_shortstat(diff_stat)

    # If HEAD~1 doesn't exist (single-commit repo), diff against empty tree
    if diff_stat is None:
        diff_stat = _run_git(
            ["diff", "--shortstat", "4b825dc642cb6eb9a060e54bf899d69f82e9e5f4", "HEAD"],
            repo_path,
        )
        files_changed, lines_added, lines_deleted = _parse_shortstat(diff_stat)

    metadata["files_changed"] = files_changed
    metadata["lines_added"] = lines_added
    metadata["lines_deleted"] = lines_deleted

    # ── Files changed in latest commit (for test detection & sensitive files) ───
    changed_files_raw = _run_git(["diff", "--name-only", "HEAD~1", "HEAD"], repo_path)
    if changed_files_raw is None:
        changed_files_raw = _run_git(
            ["diff", "--name-only", "4b825dc642cb6eb9a060e54bf899d69f82e9e5f4", "HEAD"],
            repo_path,
        )
    changed_files = changed_files_raw.splitlines() if changed_files_raw else []

    # In shallow/single-commit clones `git diff HEAD~1 HEAD` can fail.
    # Fallback to `git show` for the latest commit.
    if not changed_files:
        show_names = _run_git(["show", "--name-only", "--pretty=format:", "HEAD"], repo_path)
        changed_files = [line for line in (show_names or "").splitlines() if line.strip()]
    if files_changed == 0 and changed_files:
        files_changed = len(changed_files)
        metadata["files_changed"] = files_changed
    if lines_added == 0 and lines_deleted == 0:
        show_stat = _run_git(["show", "--shortstat", "--pretty=format:", "HEAD"], repo_path)
        s_files, s_add, s_del = _parse_shortstat(show_stat)
        if s_files or s_add or s_del:
            metadata["files_changed"] = s_files or metadata.get("files_changed", 0)
            metadata["lines_added"] = s_add
            metadata["lines_deleted"] = s_del

    # Test file detection
    metadata["has_test_changes"] = any(
        any(indicator in f.lower() for indicator in _TEST_INDICATORS)
        for f in changed_files
    )

    # Sensitive file detection
    sensitive_files = []
    for f in changed_files:
        fname_lower = f.lower()
        for sp in SENSITIVE_PATHS:
            if sp in fname_lower:
                sensitive_files.append(f)
                break
    metadata["sensitive_files_count"] = len(sensitive_files)
    metadata["sensitive_files"] = sensitive_files[:10]  # cap for logging

    # ── Language ratio (JS/TS vs Python across the whole repo) ───────────
    metadata["lang_ratio"] = _compute_lang_ratio(repo_path)

    return metadata


def _parse_shortstat(stat: Optional[str]) -> tuple:
    """
    Parse output of `git diff --shortstat`.
    Example: " 3 files changed, 120 insertions(+), 45 deletions(-)"
    Returns (files_changed, lines_added, lines_deleted).
    """
    if not stat:
        return 0, 0, 0

    files_changed = 0
    insertions = 0
    deletions = 0

    parts = stat.split(",")
    for part in parts:
        part = part.strip()
        tokens = part.split()
        if not tokens:
            continue
        try:
            num = int(tokens[0])
        except ValueError:
            continue
        part_lower = part.lower()
        if "file" in part_lower:
            files_changed = num
        elif "insertion" in part_lower:
            insertions = num
        elif "deletion" in part_lower:
            deletions = num

    return files_changed, insertions, deletions


def _compute_lang_ratio(repo_path: str) -> float:
    """
    Compute the ratio of JS/TS code to total (JS/TS + Python) code
    based on file sizes in the repository.
    Returns a float between 0.0 and 1.0.
    """
    js_bytes = 0
    py_bytes = 0

    try:
        for root, _dirs, files in os.walk(repo_path):
            # Skip hidden dirs and common non-source dirs
            rel = os.path.relpath(root, repo_path)
            if any(part.startswith(".") or part in ("node_modules", "venv", "__pycache__", "dist", "build")
                   for part in rel.split(os.sep)):
                continue

            for fname in files:
                ext = os.path.splitext(fname)[1].lower()
                if ext in _JS_EXTENSIONS:
                    try:
                        js_bytes += os.path.getsize(os.path.join(root, fname))
                    except OSError:
                        pass
                elif ext in _PY_EXTENSIONS:
                    try:
                        py_bytes += os.path.getsize(os.path.join(root, fname))
                    except OSError:
                        pass
    except Exception as exc:
        logger.debug("Error walking repo for lang ratio: %s", exc)

    total = js_bytes + py_bytes
    if total == 0:
        return 0.5  # neutral when no JS/TS or Python found
    return round(js_bytes / total, 3)


def _analyze_files_only(repo_path: str) -> Dict[str, Any]:
    """
    Fallback when no .git directory exists — count files and compute
    language ratio purely from the filesystem.
    """
    all_files = []
    try:
        for root, _dirs, files in os.walk(repo_path):
            rel = os.path.relpath(root, repo_path)
            if any(part.startswith(".") or part in ("node_modules", "venv", "__pycache__", "dist", "build")
                   for part in rel.split(os.sep)):
                continue
            for f in files:
                all_files.append(os.path.join(rel, f))
    except Exception:
        pass

    has_tests = any(
        any(ind in f.lower() for ind in _TEST_INDICATORS)
        for f in all_files
    )

    sensitive_count = 0
    for f in all_files:
        fl = f.lower()
        if any(sp in fl for sp in SENSITIVE_PATHS):
            sensitive_count += 1

    return {
        "files_changed": len(all_files),
        "lines_added": 0,
        "lines_deleted": 0,
        "commit_count": 0,
        "author_name": "unknown",
        "has_test_changes": has_tests,
        "lang_ratio": _compute_lang_ratio(repo_path),
        "sensitive_files_count": sensitive_count,
        "sensitive_files": [],
    }
