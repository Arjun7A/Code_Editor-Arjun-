"""PR-Agent adapter for Layer-2 AI analysis."""

from __future__ import annotations

import importlib.util
import json
import logging
import os
import re
import shutil
import subprocess
import sys
import uuid
from pathlib import Path
from typing import Any, Dict, List, Optional

from app.core.config import settings
from app.models.pipeline_contracts import PRContext

logger = logging.getLogger(__name__)


class PRAgentAdapter:
    """Runs PR-Agent and maps output to the pipeline AI contract."""

    _SECURITY_HINTS = (
        "sql injection",
        "xss",
        "ssrf",
        "csrf",
        "rce",
        "command injection",
        "vulnerability",
        "security",
        "hardcoded secret",
        "secret",
        "unsafe",
    )
    _SMELL_HINTS = (
        "code smell",
        "maintainability",
        "large function",
        "complex",
        "duplicate",
        "refactor",
        "dead code",
        "unused",
    )
    _USAGE_PATTERNS = (
        r"^\s*usage:",
        r"^\s*error:\s*",
        r"--pr-url",
        r"--pr_url",
        r"supported git hosting service",
    )
    _FAILURE_PATTERNS = (
        r"failed to review pr",
        r"traceback",
        r"error:",
        r"retryerror",
        r"apiconnectionerror",
        r"valueerror",
        r"exception",
    )
    _RATE_LIMIT_PATTERNS = (
        r"ratelimiterror",
        r"rate limit",
        r"too many requests",
        r"429",
        r"insufficient_quota",
        r"quota",
    )

    def __init__(
        self,
        binary: Optional[str] = None,
        timeout_seconds: int = 90,
        provider_name: str = "pr-agent",
        model_name: str = "pr-agent-cli",
        use_diff_mode: bool = True,
        allow_module_fallback: bool = True,
    ):
        self.binary = (binary or "pr-agent").strip() or "pr-agent"
        self.timeout_seconds = max(15, int(timeout_seconds))
        self.provider_name = provider_name.strip() or "pr-agent"
        self.model_name = model_name.strip() or "pr-agent-cli"
        self.use_diff_mode = bool(use_diff_mode)
        self.allow_module_fallback = bool(allow_module_fallback)
        self._active_env: Optional[Dict[str, str]] = None
        self._last_meta: Dict[str, Any] = {
            "status": "skipped",
            "error": "",
            "provider": self.provider_name,
            "model": self.model_name,
            "command_prefix": self.binary,
        }

    def last_meta(self) -> Dict[str, Any]:
        """Read metadata from the most recent PR-Agent execution."""
        return dict(self._last_meta)

    def analyze_pr(
        self,
        pr_context: PRContext | Dict[str, Any],
        scan_results: Optional[Dict[str, Any]] = None,
    ) -> Dict[str, Any]:
        """
        Analyze PR context using PR-Agent and return strict Layer-2 JSON contract.

        Contract:
        {
          "ai_security_flags": [],
          "ai_code_smells": [],
          "ai_summary": ""
        }
        """
        _ = scan_results  # kept for interface parity with other adapters
        self._set_meta(status="skipped", error="", command_prefix=self.binary)
        context = self._coerce_context(pr_context)
        diff = (context.diff or "").strip()
        if not diff:
            self._set_meta(status="skipped", error="empty diff", command_prefix=self.binary)
            return self._empty_result()

        if not self._is_installed():
            self._set_meta(
                status="failed",
                error="pr-agent CLI/module not found",
                command_prefix=self.binary,
            )
            logger.warning("PR-Agent CLI not found on PATH; returning empty AI result.")
            return self._empty_result()

        cmd_prefix = self._command_prefix() or [self.binary]
        attempted = False
        last_error = ""
        rate_limit_error = ""
        profiles = self._execution_profiles()

        # Try command candidates for each provider profile (OpenAI -> xAI fallback).
        for profile in profiles:
            self._active_env = profile["env"]
            for cmd in self._build_candidate_commands(cmd_prefix, context, diff):
                attempted = True
                rc, stdout, stderr = self._run_command(cmd)
                combined_output = "\n".join(part for part in (stdout, stderr) if part).strip()

                if self._looks_like_usage_output(combined_output):
                    last_error = "pr-agent returned CLI usage output"
                    continue

                if self._looks_like_runtime_failure_output(combined_output):
                    last_error = self._extract_failure_reason(stdout, stderr)
                    if self._is_rate_limit_error(last_error) and not rate_limit_error:
                        rate_limit_error = last_error
                    # Try next provider profile (if configured) on runtime failures.
                    break

                if rc == 0 and stdout and not self._looks_like_usage_output(stdout):
                    mapped = self._map_output(stdout)
                    if self._has_meaningful_output(mapped):
                        self._set_meta(
                            status="success",
                            error="",
                            command_prefix=" ".join(cmd_prefix),
                            provider=profile["provider"],
                            model=profile["model"],
                        )
                        self._active_env = None
                        return mapped
                    last_error = "pr-agent returned empty/non-actionable output"
                    continue

                last_error = (stderr or f"exit code {rc}").strip() or "pr-agent execution failed"
            # proceed to next provider profile
            self._active_env = None

        if attempted:
            effective_error = rate_limit_error or last_error
            degraded = bool(rate_limit_error) or self._is_rate_limit_error(last_error)
            self._set_meta(
                status="skipped" if degraded else "failed",
                error=effective_error or "pr-agent returned no output",
                command_prefix=" ".join(cmd_prefix),
            )
        else:
            self._set_meta(
                status="skipped",
                error="missing pr_url and diff mode disabled",
                command_prefix=" ".join(cmd_prefix),
            )
        logger.warning(
            "PR-Agent execution failed (repo=%s pr=%s): %s",
            context.repo,
            context.pr_number,
            (last_error or "unknown error")[:300],
        )
        return self._empty_result()

    def _build_candidate_commands(
        self,
        cmd_prefix: List[str],
        context: PRContext,
        diff: str,
    ) -> List[List[str]]:
        commands: List[List[str]] = []

        if self.use_diff_mode:
            commands.append([*cmd_prefix, "review", "--diff", diff])

        pr_url = context.pr_url
        if pr_url:
            # This PR-Agent build primarily documents --pr_url.
            commands.extend(
                [
                    [*cmd_prefix, f"--pr_url={pr_url}", "review"],
                    [*cmd_prefix, "--pr_url", pr_url, "review"],
                    # Compatibility forms for newer CLI variants.
                    [*cmd_prefix, f"--pr-url={pr_url}", "review"],
                    [*cmd_prefix, "--pr-url", pr_url, "review"],
                ]
            )
        return commands

    def _execution_profiles(self) -> List[Dict[str, Any]]:
        profiles: List[Dict[str, Any]] = [
            {
                "name": "default",
                "provider": self.provider_name,
                "model": self.model_name,
                "env": self._build_subprocess_env(profile="default"),
            }
        ]
        if self._can_use_xai_fallback():
            xai_model = (settings.PR_AGENT_XAI_MODEL or "").strip() or "xai/grok-3-latest"
            profiles.append(
                {
                    "name": "xai-fallback",
                    "provider": f"{self.provider_name}-xai",
                    "model": xai_model,
                    "env": self._build_subprocess_env(profile="xai"),
                }
            )
        return profiles

    @staticmethod
    def _can_use_xai_fallback() -> bool:
        if not bool(settings.PR_AGENT_ENABLE_XAI_FALLBACK):
            return False
        key = (
            os.environ.get("XAI_API_KEY")
            or os.environ.get("XAI__API_KEY")
            or (settings.XAI_API_KEY or "").strip()
        )
        model = (settings.PR_AGENT_XAI_MODEL or "").strip()
        return bool(key and model)

    @staticmethod
    def build_diff_from_files(file_diffs: List[Dict[str, Any]], max_chars: int = 120_000) -> str:
        """Build a unified diff string from GitHub PR files payload."""
        chunks: List[str] = []
        current_len = 0
        for fd in file_diffs or []:
            filename = str(fd.get("filename", "")).strip()
            patch = str(fd.get("patch", "") or "").strip()
            if not filename or not patch:
                continue

            if patch.startswith("diff --git"):
                block = patch
            else:
                block = f"diff --git a/{filename} b/{filename}\n{patch}"

            block_len = len(block) + 2
            if current_len + block_len > max_chars:
                break
            chunks.append(block)
            current_len += block_len
        return "\n\n".join(chunks).strip()

    @staticmethod
    def findings_from_contract(ai_result: Dict[str, Any]) -> List[Dict[str, Any]]:
        """Convert contract payload to legacy finding rows used in DB/UI tables."""
        out: List[Dict[str, Any]] = []
        for item in ai_result.get("ai_security_flags", []) or []:
            text = str(item).strip()
            if not text:
                continue
            out.append(
                {
                    "id": str(uuid.uuid4()),
                    "type": "security",
                    "title": text[:200],
                    "description": text,
                    "recommendation": "Review and remediate this security issue before merge.",
                    "confidence": 0.85,
                    "severity": "high",
                }
            )

        for item in ai_result.get("ai_code_smells", []) or []:
            text = str(item).strip()
            if not text:
                continue
            out.append(
                {
                    "id": str(uuid.uuid4()),
                    "type": "best_practice",
                    "title": text[:200],
                    "description": text,
                    "recommendation": "Refactor this area to reduce maintainability risk.",
                    "confidence": 0.70,
                    "severity": "medium",
                }
            )
        return out

    def _coerce_context(self, pr_context: PRContext | Dict[str, Any]) -> PRContext:
        if isinstance(pr_context, PRContext):
            return pr_context
        if isinstance(pr_context, dict):
            return PRContext.from_payload(pr_context)
        return PRContext(repo="", pr_number=0)

    def _is_installed(self) -> bool:
        return self._command_prefix() is not None

    def _command_prefix(self) -> Optional[List[str]]:
        resolved_binary = self._resolve_binary(self.binary)
        if resolved_binary:
            return [resolved_binary]

        if self.allow_module_fallback and importlib.util.find_spec("pr_agent.cli"):
            return [sys.executable, "-m", "pr_agent.cli"]
        return None

    def _resolve_binary(self, binary: str) -> Optional[str]:
        candidate = (binary or "").strip()
        if not candidate:
            return None

        if any(token in candidate for token in ("/", "\\", os.sep)):
            path_candidate = Path(candidate)
            if path_candidate.exists():
                return str(path_candidate)

        which_candidate = shutil.which(candidate)
        if which_candidate:
            return which_candidate

        if candidate == "pr-agent":
            for fallback in self._fallback_binary_candidates():
                if fallback.exists():
                    return str(fallback)
        return None

    def _fallback_binary_candidates(self) -> List[Path]:
        names = ["pr-agent.exe", "pr-agent"] if os.name == "nt" else ["pr-agent"]
        roots: List[Path] = []

        for location in (Path.cwd(), Path(sys.executable).resolve().parent, Path(__file__).resolve()):
            if location.is_file():
                location = location.parent
            roots.append(location)
            roots.extend(location.parents)

        seen: set[str] = set()
        out: List[Path] = []
        for root in roots:
            for venv_dir in ("venv", ".venv"):
                for relative in ("Scripts", "bin"):
                    for name in names:
                        candidate = root / venv_dir / relative / name
                        key = str(candidate).lower()
                        if key in seen:
                            continue
                        seen.add(key)
                        out.append(candidate)
        return out

    def _set_meta(
        self,
        status: str,
        error: str,
        command_prefix: str,
        provider: Optional[str] = None,
        model: Optional[str] = None,
    ) -> None:
        self._last_meta = {
            "status": status,
            "error": (error or "").strip(),
            "provider": (provider or self.provider_name).strip(),
            "model": (model or self.model_name).strip(),
            "command_prefix": command_prefix,
        }

    def _run_command(self, cmd: List[str]) -> tuple[int, str, str]:
        import time
        start_time = time.time()
        logger.info(f"PR-Agent adapter running command: {' '.join(cmd)}")
        try:
            env_payload = self._active_env if self._active_env is not None else self._build_subprocess_env()
            result = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                encoding="utf-8",
                errors="replace",
                timeout=self.timeout_seconds,
                env=env_payload,
            )
            elapsed = time.time() - start_time
            logger.info(f"PR-Agent command completed in {elapsed:.2f}s with exit code {result.returncode}")
            if result.returncode != 0:
                logger.error(f"PR-Agent err: {result.stderr[:500]}")
            return result.returncode, result.stdout.strip(), result.stderr.strip()
        except subprocess.TimeoutExpired:
            elapsed = time.time() - start_time
            logger.error(f"PR-Agent command TIMED OUT after {elapsed:.2f}s (timeout={self.timeout_seconds})")
            return 124, "", f"timeout after {self.timeout_seconds}s"
        except FileNotFoundError:
            logger.error("PR-Agent binary not found")
            return 127, "", "pr-agent binary not found"
        except Exception as exc:
            logger.error(f"PR-Agent execution error: {exc}")
            return 1, "", str(exc)

    def _map_output(self, raw_output: str) -> Dict[str, Any]:
        if self._looks_like_usage_output(raw_output) or self._looks_like_runtime_failure_output(raw_output):
            return self._empty_result()

        clean_output = self._strip_ansi(raw_output)
        parsed = self._try_parse_json(clean_output)
        if isinstance(parsed, dict):
            security = self._normalize_list(
                parsed.get("ai_security_flags", parsed.get("security_flags", []))
            )
            smells = self._normalize_list(
                parsed.get("ai_code_smells", parsed.get("code_smells", []))
            )
            summary = str(parsed.get("ai_summary", parsed.get("summary", "")) or "").strip()
            if summary or security or smells:
                return {
                    "ai_security_flags": security,
                    "ai_code_smells": smells,
                    "ai_summary": summary,
                }

        # Markdown/text fallback parser for non-JSON PR-Agent responses.
        text_lines = self._normalize_list(clean_output.splitlines())
        security_flags: List[str] = []
        code_smells: List[str] = []

        for line in text_lines:
            lowered = line.lower()
            if any(token in lowered for token in self._SECURITY_HINTS):
                security_flags.append(line)
                continue
            if any(token in lowered for token in self._SMELL_HINTS):
                code_smells.append(line)

        summary = self._extract_summary(text_lines)
        return {
            "ai_security_flags": self._dedupe(security_flags),
            "ai_code_smells": self._dedupe(code_smells),
            "ai_summary": summary,
        }

    def _try_parse_json(self, raw: str) -> Optional[Dict[str, Any]]:
        payload = (raw or "").strip()
        if not payload:
            return None

        candidates: List[str] = [payload]
        fenced = re.findall(r"```(?:json)?\s*(.*?)```", payload, flags=re.IGNORECASE | re.DOTALL)
        candidates.extend(chunk.strip() for chunk in fenced if chunk.strip())

        first_obj = payload.find("{")
        last_obj = payload.rfind("}")
        if first_obj >= 0 and last_obj > first_obj:
            candidates.append(payload[first_obj : last_obj + 1].strip())

        for candidate in candidates:
            try:
                parsed = json.loads(candidate)
            except Exception:
                continue
            if isinstance(parsed, dict):
                return parsed
        return None

    @staticmethod
    def _normalize_list(items: Any) -> List[str]:
        if not items:
            return []
        if isinstance(items, str):
            items = [items]
        out: List[str] = []
        for item in items:
            text = str(item).strip()
            if not text:
                continue
            text = re.sub(r"^\s*[-*]\s*", "", text).strip()
            out.append(text)
        return out

    @staticmethod
    def _dedupe(items: List[str]) -> List[str]:
        seen = set()
        out: List[str] = []
        for item in items:
            key = item.lower()
            if key in seen:
                continue
            seen.add(key)
            out.append(item)
        return out

    @staticmethod
    def _extract_summary(lines: List[str]) -> str:
        for line in lines:
            lowered = line.lower()
            if lowered.startswith("usage:"):
                continue
            if lowered.startswith("summary:"):
                return line.split(":", 1)[1].strip()
        for line in lines:
            lowered = line.lower()
            if lowered.startswith("usage:"):
                continue
            if len(line) >= 20:
                return line
        return ""

    @classmethod
    def _looks_like_usage_output(cls, raw_output: str) -> bool:
        text = cls._strip_ansi((raw_output or "").strip())
        if not text:
            return False

        lines = [ln.strip() for ln in text.splitlines() if ln.strip()]
        if not lines:
            return False

        head = " ".join(lines[:3]).lower()
        matches = 0
        for pattern in cls._USAGE_PATTERNS:
            if re.search(pattern, head, flags=re.IGNORECASE):
                matches += 1

        # Treat as usage/help only when multiple hints are present.
        return matches >= 2

    @classmethod
    def _looks_like_runtime_failure_output(cls, raw_output: str) -> bool:
        text = cls._strip_ansi((raw_output or "").strip()).lower()
        if not text:
            return False

        window = "\n".join(text.splitlines()[-30:])
        for pattern in cls._FAILURE_PATTERNS:
            if re.search(pattern, window, flags=re.IGNORECASE):
                return True
        return False

    @classmethod
    def _extract_failure_reason(cls, stdout: str, stderr: str) -> str:
        for source in (stderr, stdout):
            text = cls._strip_ansi((source or "").strip())
            if not text:
                continue
            lines = [ln.strip() for ln in text.splitlines() if ln.strip()]
            for line in reversed(lines):
                lowered = line.lower()
                if "failed to review pr" in lowered:
                    return line[:300]
                if "apiconnectionerror" in lowered:
                    return line[:300]
                if lowered.startswith("valueerror:"):
                    return line[:300]
                if lowered.startswith("error:"):
                    return line[:300]
            return lines[-1][:300]
        return "pr-agent execution failed"

    @classmethod
    def _is_rate_limit_error(cls, text: str) -> bool:
        payload = (text or "").lower()
        if not payload:
            return False
        return any(re.search(pattern, payload, flags=re.IGNORECASE) for pattern in cls._RATE_LIMIT_PATTERNS)

    @staticmethod
    def _strip_ansi(text: str) -> str:
        if not text:
            return ""
        return re.sub(r"\x1B\[[0-9;]*[A-Za-z]", "", text)

    def _build_subprocess_env(self, profile: str = "default") -> Dict[str, str]:
        env = os.environ.copy()

        github_token = (
            env.get("GITHUB__USER_TOKEN")
            or env.get("GITHUB_USER_TOKEN")
            or env.get("GITHUB_TOKEN")
            or (settings.GITHUB_TOKEN or "").strip()
        )
        openai_key = (
            env.get("OPENAI__KEY")
            or env.get("OPENAI_KEY")
            or env.get("OPENAI_API_KEY")
            or (settings.OPENAI_API_KEY or "").strip()
        )
        xai_key = (
            env.get("XAI_API_KEY")
            or env.get("XAI__API_KEY")
            or (settings.XAI_API_KEY or "").strip()
        )
        groq_key = (
            env.get("GROQ_API_KEY")
            or (getattr(settings, "GROQ_API_KEY", None) or "").strip()
            or xai_key  # fallback: XAI_API_KEY is a Groq key in this project
        )

        if github_token:
            env["GITHUB_TOKEN"] = github_token
            env["GITHUB_USER_TOKEN"] = github_token
            env["GITHUB__USER_TOKEN"] = github_token

        if openai_key:
            env["OPENAI_API_KEY"] = openai_key
            env["OPENAI_KEY"] = openai_key
            env["OPENAI__KEY"] = openai_key

        if xai_key:
            env["XAI_API_KEY"] = xai_key
            env["XAI__API_KEY"] = xai_key

        # Always set GROQ_API_KEY so LiteLLM can route groq/* models
        if groq_key:
            env["GROQ_API_KEY"] = groq_key

        # If the configured model is a groq/ model, set CONFIG__MODEL vars
        # so the PR-Agent subprocess uses Groq instead of OpenAI.
        model_name = self.model_name.strip()
        if model_name.startswith("groq/") and groq_key:
            env["CONFIG__MODEL"] = model_name
            env["CONFIG__MODEL_TURBO"] = model_name
            env["CONFIG__FALLBACK_MODELS"] = json.dumps([model_name])
            env["CONFIG__CUSTOM_MODEL_MAX_TOKENS"] = str(
                max(0, int(getattr(settings, "PR_AGENT_XAI_CUSTOM_MODEL_MAX_TOKENS", 0) or 0)) or 32768
            )

        if profile == "xai" and xai_key:
            xai_model = (settings.PR_AGENT_XAI_MODEL or "").strip() or "xai/grok-3-latest"
            # PR-Agent reads OPENAI.* keys and forwards model/provider to LiteLLM.
            env["OPENAI_API_KEY"] = xai_key
            env["OPENAI_KEY"] = xai_key
            env["OPENAI__KEY"] = xai_key
            env["CONFIG__MODEL"] = xai_model
            env["CONFIG__MODEL_TURBO"] = xai_model
            env["CONFIG__FALLBACK_MODELS"] = json.dumps([xai_model])
            custom_tokens = max(0, int(settings.PR_AGENT_XAI_CUSTOM_MODEL_MAX_TOKENS or 0))
            if custom_tokens > 0:
                env["CONFIG__CUSTOM_MODEL_MAX_TOKENS"] = str(custom_tokens)

        return env

    @staticmethod
    def _has_meaningful_output(ai_result: Dict[str, Any]) -> bool:
        if not isinstance(ai_result, dict):
            return False
        flags = ai_result.get("ai_security_flags") or []
        smells = ai_result.get("ai_code_smells") or []
        summary = str(ai_result.get("ai_summary", "") or "").strip()
        return bool(flags or smells or summary)

    @staticmethod
    def _empty_result() -> Dict[str, Any]:
        return {
            "ai_security_flags": [],
            "ai_code_smells": [],
            "ai_summary": "",
        }
