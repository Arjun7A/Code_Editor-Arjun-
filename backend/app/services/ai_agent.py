"""
AI Security Agent
=================
Uses LangChain + xAI Grok to analyse PR code diffs for
security vulnerabilities and suggest concrete fixes.

Why Grok?
  • Strong code understanding and structured output support
  • Model can be configured via GROK_MODEL (default: grok-3-latest)
  • xAI API is OpenAI-compatible, so langchain-openai works directly

Get your API key:  https://console.x.ai/
Set it in backend/.env:  XAI_API_KEY=your_key_here
"""

import asyncio
import json
import logging
import os
import re
import time
import uuid
from pathlib import Path
from typing import Any, Dict, List, Optional

from pydantic import BaseModel, Field
import yaml
from app.core.config import settings

logger = logging.getLogger(__name__)


def _is_valid_model_name(model_name: str) -> bool:
    token = (model_name or "").strip()
    if not token:
        return False
    lowered = token.lower()
    # Guard common misconfigurations where URL/path is accidentally placed in model.
    if lowered in {"api/v1", "openai/v1", "v1"}:
        return False
    if lowered.startswith("http://") or lowered.startswith("https://"):
        return False
    return True


# ── Maximum characters per analysis chunk (~2 000–3 000 tokens) ──────────────
MAX_CHUNK_CHARS = 9_000
MAX_ANALYSIS_CHUNKS = max(1, int(os.getenv("AI_MAX_CHUNKS", str(settings.AI_MAX_CHUNKS))))
AI_CHUNK_TIMEOUT_SECONDS = max(15.0, float(settings.AI_CHUNK_TIMEOUT_SECONDS or 45))
AI_MAX_OUTPUT_TOKENS = max(128, int(os.getenv("AI_MAX_OUTPUT_TOKENS", str(settings.AI_MAX_OUTPUT_TOKENS))))
AI_REQUIRE_XAI = (
    os.getenv("AI_REQUIRE_XAI", str(settings.AI_REQUIRE_XAI))
    .strip()
    .lower()
    in ("1", "true", "yes")
)
AI_ENABLE_HEURISTIC_FALLBACK = (
    os.getenv("AI_ENABLE_HEURISTIC_FALLBACK", str(settings.AI_ENABLE_HEURISTIC_FALLBACK))
    .strip()
    .lower()
    in ("1", "true", "yes")
)
HARDCODED_GROK_MODEL = "grok-3-latest"
_configured_default_model = (settings.GROK_MODEL or "").strip()
if _configured_default_model and not _is_valid_model_name(_configured_default_model):
    logger.warning(
        "AI agent: invalid model '%s'; falling back to '%s'",
        _configured_default_model,
        HARDCODED_GROK_MODEL,
    )
    _configured_default_model = ""
DEFAULT_GROK_MODEL = _configured_default_model or HARDCODED_GROK_MODEL
DEFAULT_XAI_BASE_URL = (settings.XAI_API_BASE_URL or "https://api.x.ai/v1").strip()
FALLBACK_GROK_MODELS = tuple(
    model.strip()
    for model in os.getenv("GROK_FALLBACK_MODELS", "").split(",")
    if model.strip()
)

# ── Binary extensions to skip ─────────────────────────────────────────────────
_BINARY_EXTS = {
    ".png", ".jpg", ".jpeg", ".gif", ".ico", ".svg", ".webp",
    ".pdf", ".zip", ".tar", ".gz", ".bz2", ".xz", ".whl", ".egg",
    ".pyc", ".pyo", ".dll", ".so", ".dylib", ".exe", ".bin",
    ".ttf", ".woff", ".woff2", ".eot",
    ".mp3", ".mp4", ".avi", ".mov",
}

_SENSITIVE_FILE_TOKENS = (
    "auth", "login", "session", "token", "crypto", "security", "password",
    "secret", "key", "cert", "ssl", "tls", "oauth", "permission", "access",
    "admin", "config", ".env", "docker", "workflow", "deploy", "helm",
)
_RISKY_PATCH_TOKENS = (
    "eval(", "exec(", "subprocess", "shell=True", "os.system(", "yaml.load(",
    "pickle.load(", "verify=False", "jwt", "secret", "password", "token",
    "SELECT ", "INSERT ", "UPDATE ", "DELETE ", "http://", "cors",
)
_AI_HEURISTICS_PATH = Path(__file__).resolve().parents[1] / "policy" / "ai_heuristics.yaml"

# ─────────────────────────────────────────────────────────────────────────────
#  Pydantic schemas for structured LLM output
# ─────────────────────────────────────────────────────────────────────────────

class _AIFinding(BaseModel):
    """Single security/code finding – returned by the LLM."""
    type: str = Field(
        description="Category: security | logic | performance | best_practice"
    )
    title: str = Field(description="Short, precise title ≤ 100 chars")
    description: str = Field(description="Detailed explanation of the issue")
    recommendation: str = Field(description="Concrete remediation with example if possible")
    confidence: float = Field(
        ge=0.0, le=1.0,
        description="Model confidence this is a real issue (0.0 – 1.0)"
    )
    affected_code: Optional[str] = Field(
        default=None,
        description="The exact problematic snippet (≤ 15 lines)"
    )


class _AIAnalysisResult(BaseModel):
    """Structured result from one LLM analysis call."""
    findings: List[_AIFinding] = Field(default_factory=list)
    summary: str = Field(description="One-sentence overall assessment")
    overall_risk: str = Field(
        description="Assessed risk level: critical | high | medium | low | none"
    )


# ─────────────────────────────────────────────────────────────────────────────
#  Prompt templates
# ─────────────────────────────────────────────────────────────────────────────

SYSTEM_PROMPT = """You are a senior application security engineer performing a thorough \
code review on a GitHub pull request.

Analyse the provided diff for:
1. **Security vulnerabilities** – injection (SQL/OS/LDAP), XSS, SSRF, path traversal,
   hardcoded secrets/keys, insecure crypto, broken auth, sensitive data exposure,
   unsafe deserialization, missing input validation.
2. **Logic errors** – conditions that can produce incorrect or dangerous behaviour.
3. **Performance issues** – N+1 queries, unbounded loops, memory leaks, blocking I/O.
4. **Best-practice violations** – missing error handling, secrets in logs, broad exception
   catching, overly permissive CORS / file permissions.

Rules:
• Only report REAL, demonstrable issues – do NOT hallucinate problems.
• For each finding give a specific code reference (affected_code).
• Confidence 0.9+ means high certainty; 0.5–0.9 means probable; < 0.5 means speculative.
• Skip cosmetic/style issues (typos, formatting) unless they hide a real bug.
• Be concise but actionable."""


# ─────────────────────────────────────────────────────────────────────────────
#  Helper functions
# ─────────────────────────────────────────────────────────────────────────────

def _is_binary(filename: str) -> bool:
    ext = ("." + filename.rsplit(".", 1)[-1].lower()) if "." in filename else ""
    return ext in _BINARY_EXTS


def _finding_severity(finding_type: str, confidence: float) -> str:
    """Map (type, confidence) → severity label used by frontend."""
    if finding_type == "security":
        if confidence >= 0.8:
            return "high"
        if confidence >= 0.5:
            return "medium"
        return "low"
    else:
        if confidence >= 0.9:
            return "medium"
        return "low"


def _top_severity(counts: Dict[str, int]) -> str:
    for sev in ("critical", "high", "medium", "low"):
        if counts.get(sev, 0) > 0:
            return sev
    return "info"


_VALID_SEVERITIES = {"critical", "high", "medium", "low"}
_VALID_TYPES = {"security", "logic", "performance", "best_practice"}
_VALID_REGEX_FLAGS = {
    "IGNORECASE": re.IGNORECASE,
    "MULTILINE": re.MULTILINE,
    "DOTALL": re.DOTALL,
}


def _load_heuristic_rules() -> List[Dict[str, Any]]:
    """Load regex-based heuristic rules from YAML configuration."""
    if not _AI_HEURISTICS_PATH.exists():
        logger.warning(
            "AI heuristics config not found at %s; heuristic fallback disabled.",
            _AI_HEURISTICS_PATH,
        )
        return []

    try:
        payload = yaml.safe_load(_AI_HEURISTICS_PATH.read_text(encoding="utf-8")) or {}
    except Exception as exc:
        logger.warning(
            "Failed to parse AI heuristics config %s: %s",
            _AI_HEURISTICS_PATH,
            exc,
        )
        return []

    raw_rules = payload.get("rules", [])
    if not isinstance(raw_rules, list):
        logger.warning(
            "AI heuristics config %s has invalid 'rules' shape; expected list.",
            _AI_HEURISTICS_PATH,
        )
        return []

    rules: List[Dict[str, Any]] = []

    for raw_rule in raw_rules:
        if not isinstance(raw_rule, dict):
            continue

        rule_id = str(raw_rule.get("id", "")).strip()
        pattern_text = str(raw_rule.get("pattern", "")).strip()
        if not rule_id or not pattern_text:
            continue

        regex_flags = 0
        raw_flags = raw_rule.get("flags", [])
        if isinstance(raw_flags, list):
            for name in raw_flags:
                token = str(name).strip().upper()
                regex_flags |= _VALID_REGEX_FLAGS.get(token, 0)

        try:
            compiled_pattern = re.compile(pattern_text, regex_flags)
        except re.error as exc:
            logger.warning("Skipping invalid heuristic regex '%s': %s", rule_id, exc)
            continue

        raw_severity = str(raw_rule.get("severity", "medium")).strip().lower()
        severity = raw_severity if raw_severity in _VALID_SEVERITIES else "medium"

        raw_type = str(raw_rule.get("type", "security")).strip().lower()
        finding_type = raw_type if raw_type in _VALID_TYPES else "security"

        try:
            confidence = float(raw_rule.get("confidence", 0.8))
        except Exception:
            confidence = 0.8
        confidence = max(0.0, min(1.0, confidence))

        rules.append({
            "id": rule_id,
            "pattern": compiled_pattern,
            "title": str(raw_rule.get("title", "Security heuristic match")).strip(),
            "description": str(raw_rule.get("description", "Potential security issue detected by heuristic.")).strip(),
            "recommendation": str(raw_rule.get("recommendation", "Review and harden this code path.")).strip(),
            "confidence": confidence,
            "severity": severity,
            "type": finding_type,
        })

    logger.info("Loaded %d AI heuristic rule(s) from %s", len(rules), _AI_HEURISTICS_PATH)
    return rules


if AI_ENABLE_HEURISTIC_FALLBACK:
    _HEURISTIC_RULES = _load_heuristic_rules()
else:
    _HEURISTIC_RULES: List[Dict[str, Any]] = []


def _scan_heuristics(file_diffs: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    findings: List[Dict[str, Any]] = []
    seen: set[str] = set()

    for fd in file_diffs:
        filename = str(fd.get("filename", "unknown"))
        patch = str(fd.get("patch", "") or "")
        if not patch:
            continue

        for raw_line in patch.splitlines():
            if not raw_line.startswith("+") or raw_line.startswith("+++"):
                continue
            line = raw_line[1:]
            stripped = line.strip()
            if not stripped:
                continue

            for rule in _HEURISTIC_RULES:
                if not rule["pattern"].search(stripped):
                    continue
                key = f"{rule['id']}::{filename}::{stripped[:160]}"
                if key in seen:
                    continue
                seen.add(key)
                findings.append({
                    "id": str(uuid.uuid4()),
                    "type": rule.get("type", "security"),
                    "title": rule["title"],
                    "description": f"{rule['description']} File: {filename}",
                    "recommendation": rule["recommendation"],
                    "confidence": rule["confidence"],
                    "affectedCode": f"{filename}: +{stripped[:240]}",
                    "severity": rule["severity"],
                })

                if len(findings) >= 30:
                    return findings

    return findings


def _dedupe_findings(findings: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    merged: List[Dict[str, Any]] = []
    seen: set[str] = set()
    for finding in findings:
        key = (
            f"{str(finding.get('title', '')).strip().lower()}::"
            f"{str(finding.get('affectedCode', '')).strip().lower()}"
        )
        if key in seen:
            continue
        seen.add(key)
        merged.append(finding)
    return merged


def _file_risk_score(file_diff: Dict[str, Any]) -> int:
    filename = str(file_diff.get("filename", "")).lower()
    patch = str(file_diff.get("patch", "") or "").lower()
    score = 0

    for token in _SENSITIVE_FILE_TOKENS:
        if token in filename:
            score += 3
    for token in _RISKY_PATCH_TOKENS:
        if token.lower() in patch:
            score += 4

    # Favor files with meaningful diff content.
    score += min(len(patch) // 1200, 6)
    return score


def _is_quota_error(exc: Exception) -> bool:
    text = str(exc).lower()
    return (
        "429" in text
        or "quota" in text
        or "resourceexhausted" in text
        or "credit" in text
        or "insufficient" in text
        or "rate limit" in text
    )


def _looks_like_grok_model(model_name: str) -> bool:
    return _is_valid_model_name(model_name)


def _is_json_schema_error(exc: Exception) -> bool:
    text = str(exc).lower()
    return (
        "json_validate_failed" in text
        or "failed to generate json" in text
        or "response format" in text
    )


def _coerce_text_content(content: Any) -> str:
    if isinstance(content, str):
        return content
    if isinstance(content, list):
        parts: List[str] = []
        for item in content:
            if isinstance(item, str):
                parts.append(item)
            elif isinstance(item, dict):
                token = item.get("text")
                if isinstance(token, str):
                    parts.append(token)
        return "\n".join(parts)
    return str(content or "")


def _parse_ai_result_payload(raw_text: str) -> Optional[_AIAnalysisResult]:
    text = (raw_text or "").strip()
    if not text:
        return None

    fenced = re.findall(r"```(?:json)?\s*(.*?)```", text, flags=re.IGNORECASE | re.DOTALL)
    if fenced:
        text = fenced[0].strip()

    candidates = [text]
    start = text.find("{")
    end = text.rfind("}")
    if start >= 0 and end > start:
        candidates.append(text[start : end + 1])

    for candidate in candidates:
        try:
            payload = json.loads(candidate)
        except Exception:
            continue
        if not isinstance(payload, dict):
            continue
        try:
            return _AIAnalysisResult.model_validate(payload)  # type: ignore[attr-defined]
        except AttributeError:
            try:
                return _AIAnalysisResult.parse_obj(payload)  # type: ignore[attr-defined]
            except Exception:
                continue
        except Exception:
            continue
    return None


def _compact_provider_reason(reason: str) -> str:
    text = (reason or "").lower()
    if "402" in text and ("credit" in text or "afford" in text):
        return "OpenRouter credits unavailable (402). Add credits and re-run."
    if "429" in text and ("quota" in text or "resourceexhausted" in text):
        return "Provider quota exhausted (429). Retry later or change provider limits."
    return (reason or "No compatible model available")[:260]


def _provider_from_base_url(base_url: str) -> str:
    lowered = (base_url or "").lower()
    if "api.groq.com" in lowered:
        return "groq"
    if "openrouter.ai" in lowered:
        return "openrouter"
    if "api.x.ai" in lowered or "x.ai" in lowered:
        return "xai"
    return "openai_compatible"


# ─────────────────────────────────────────────────────────────────────────────
#  Main AI Agent class
# ─────────────────────────────────────────────────────────────────────────────

class AIAgent:
    """
    LangChain-powered AI agent for PR security analysis.

    Usage
    -----
    agent = AIAgent(api_key=settings.XAI_API_KEY)
    result = await agent.analyze_pr_diff(pr_files, repo="owner/repo", pr_number=42)
    """

    def __init__(
        self,
        api_key: Optional[str] = None,
        model: Optional[str] = None,
        base_url: Optional[str] = None,
    ):
        self._api_key = api_key or ""
        configured_model = (
            model
            or os.getenv("GROK_MODEL")
            or ""
        ).strip()
        if configured_model and not _looks_like_grok_model(configured_model):
            logger.warning(
                "AI agent: ignoring invalid model '%s'; using '%s' instead",
                configured_model,
                DEFAULT_GROK_MODEL,
            )
            configured_model = ""
        self._model = configured_model or DEFAULT_GROK_MODEL
        self._base_url = (base_url or os.getenv("XAI_API_BASE_URL") or DEFAULT_XAI_BASE_URL).strip()
        self._provider = _provider_from_base_url(self._base_url)
        self._llm_cache: Dict[str, Any] = {}  # lazy-initialised per model
        self._available = bool(self._api_key)

    # ── Private helpers ───────────────────────────────────────────────────────

    def _candidate_models(self) -> List[str]:
        models = [self._model]
        for fallback in FALLBACK_GROK_MODELS:
            if not _looks_like_grok_model(fallback):
                logger.warning("AI agent: skipping invalid fallback model '%s'", fallback)
                continue
            if fallback and fallback not in models:
                models.append(fallback)
        return models

    def _get_llm(self, model_name: str):
        """Lazily initialise an xAI Grok client for the requested model."""
        if model_name in self._llm_cache:
            return self._llm_cache[model_name]
        if not self._available:
            return None
        try:
            from langchain_openai import ChatOpenAI  # type: ignore
            extra_headers = {}
            if "openrouter.ai" in self._base_url:
                extra_headers = {
                    "HTTP-Referer": "https://securitygate.app",
                    "X-Title": "SecurityGate",
                }
            llm = ChatOpenAI(
                model=model_name,
                api_key=self._api_key,
                base_url=self._base_url,
                temperature=0.1,
                max_tokens=AI_MAX_OUTPUT_TOKENS,
                max_retries=0,
                default_headers=extra_headers or None,
            )
            self._llm_cache[model_name] = llm
            logger.info("AI agent: xAI model '%s' initialised", model_name)
        except ImportError:
            logger.error(
                "AI agent: langchain-openai not installed. "
                "Run: pip install langchain-openai"
            )
            self._available = False
        except Exception as exc:
            logger.error("AI agent: failed to init xAI model '%s' – %s", model_name, exc)
        return self._llm_cache.get(model_name)

    async def _invoke_without_schema(self, llm: Any, messages: List[Any]) -> Optional[_AIAnalysisResult]:
        """
        Retry a chunk using plain-text completion and parse JSON manually.
        Keeps the same model/provider; only response formatting changes.
        """
        try:
            from langchain_core.messages import HumanMessage  # type: ignore
            retry_messages = list(messages) + [
                HumanMessage(
                    content=(
                        "Return ONLY valid JSON (no markdown). "
                        "Schema: {\"findings\": [{\"type\":\"security|logic|performance|best_practice\","
                        "\"title\":\"...\",\"description\":\"...\",\"recommendation\":\"...\","
                        "\"confidence\":0.0,\"affected_code\":\"...\"}],"
                        "\"summary\":\"...\",\"overall_risk\":\"critical|high|medium|low|none\"}"
                    )
                )
            ]
            raw = await asyncio.wait_for(
                llm.ainvoke(retry_messages),
                timeout=AI_CHUNK_TIMEOUT_SECONDS,
            )
            text = _coerce_text_content(getattr(raw, "content", raw))
            return _parse_ai_result_payload(text)
        except Exception as exc:
            logger.warning("AI agent: no-schema retry failed – %s", exc)
            return None

    def _chunk_diffs(self, file_diffs: List[Dict]) -> List[List[Dict]]:
        """
        Batch file diffs into chunks that fit within the model context.
        Very large individual files are truncated at MAX_CHUNK_CHARS.
        """
        chunks: List[List[Dict]] = []
        current: List[Dict] = []
        current_size = 0

        for fd in file_diffs:
            patch = fd.get("patch", "") or ""
            if not patch:
                continue
            # Truncate oversized individual files
            if len(patch) > MAX_CHUNK_CHARS:
                fd = {**fd, "patch": patch[:MAX_CHUNK_CHARS] + "\n… (truncated)"}
                patch = fd["patch"]
            plen = len(patch)
            if current and current_size + plen > MAX_CHUNK_CHARS:
                chunks.append(current)
                current, current_size = [], 0
            current.append(fd)
            current_size += plen

        if current:
            chunks.append(current)
        return chunks

    @staticmethod
    def _build_user_prompt(chunk: List[Dict], repo: str, pr_number: int, idx: int, total: int) -> str:
        parts = [f"Analyse this PR diff – repository: `{repo}`, PR #{pr_number}"]
        if total > 1:
            parts[0] += f"  (chunk {idx + 1}/{total})"
        parts.append("")
        for fd in chunk:
            filename = fd.get("filename", "unknown")
            status = fd.get("status", "modified")
            patch = fd.get("patch", "")
            parts.append(f"### {filename}  [{status}]\n```diff\n{patch}\n```")
        return "\n".join(parts)

    # ── Public API ────────────────────────────────────────────────────────────

    async def analyze_pr_diff(
        self,
        pr_files: List[Dict],
        repo: str = "",
        pr_number: int = 0,
    ) -> Dict[str, Any]:
        """
        Analyse the changed files of a PR and return structured findings.

        Parameters
        ----------
        pr_files   : list of GitHub PR file objects (must include 'patch' field)
        repo       : "owner/repo" slug (for prompt context)
        pr_number  : PR number (for prompt context)

        Returns
        -------
        Dict shaped like a ScanResult, compatible with the existing DB schema.
        """
        start = time.time()
        if not self._available:
            return self._skipped_result(
                "XAI_API_KEY not configured. "
                "Set XAI_API_KEY in backend/.env."
            )

        # Filter: only text files with a diff patch
        files_with_diff = [
            f for f in pr_files
            if f.get("patch") and not _is_binary(f.get("filename", ""))
        ]

        if not files_with_diff:
            return self._skipped_result("No analysable code diffs (all files binary or empty)")

        prioritized_files = sorted(
            files_with_diff,
            key=_file_risk_score,
            reverse=True,
        )
        analyzed_files = [f["filename"] for f in prioritized_files]
        chunks = self._chunk_diffs(prioritized_files)
        total_chunks = len(chunks)
        sampled_chunks = False
        if total_chunks > MAX_ANALYSIS_CHUNKS:
            chunks = chunks[:MAX_ANALYSIS_CHUNKS]
            sampled_chunks = True
        heuristic_findings = (
            _scan_heuristics(files_with_diff)
            if AI_ENABLE_HEURISTIC_FALLBACK
            else []
        )
        model_failures: List[str] = []
        stop_after_quota_error = False

        for model_name in self._candidate_models():
            if stop_after_quota_error:
                break
            llm = self._get_llm(model_name)
            if not llm:
                model_failures.append(f"{model_name}: model initialisation failed")
                continue

            all_findings: List[Dict[str, Any]] = []
            chunk_successes = 0
            chunk_failures = 0
            last_error = ""
            abort_current_model = False

            try:
                from langchain_core.messages import HumanMessage, SystemMessage  # type: ignore
                structured_llm = llm.with_structured_output(_AIAnalysisResult)

                for i, chunk in enumerate(chunks):
                    user_msg = self._build_user_prompt(chunk, repo, pr_number, i, len(chunks))
                    messages = [
                        SystemMessage(content=SYSTEM_PROMPT),
                        HumanMessage(content=user_msg),
                    ]
                    try:
                        result: _AIAnalysisResult = await asyncio.wait_for(
                            structured_llm.ainvoke(messages),
                            timeout=AI_CHUNK_TIMEOUT_SECONDS,
                        )
                        if result is None:
                            chunk_failures += 1
                            last_error = "empty model response"
                            logger.warning(
                                "AI agent: model %s chunk %d/%d returned empty result",
                                model_name, i + 1, len(chunks),
                            )
                            continue
                        chunk_successes += 1
                        for finding in result.findings:
                            # Normalise the type field
                            ftype = finding.type if finding.type in (
                                "security", "logic", "performance", "best_practice"
                            ) else "security"
                            all_findings.append({
                                "id": str(uuid.uuid4()),
                                "type": ftype,
                                "title": finding.title[:200],
                                "description": finding.description,
                                "recommendation": finding.recommendation,
                                "confidence": round(finding.confidence, 2),
                                "affectedCode": finding.affected_code,
                                # Extra field used for scanner severity counts
                                "severity": _finding_severity(ftype, finding.confidence),
                            })
                        logger.info(
                            "AI agent: model %s chunk %d/%d → %d findings",
                            model_name, i + 1, len(chunks), len(result.findings),
                        )
                    except asyncio.TimeoutError:
                        chunk_failures += 1
                        last_error = "chunk timeout"
                        logger.warning(
                            "AI agent: model %s chunk %d/%d timed out (>%.0f s)",
                            model_name, i + 1, len(chunks), AI_CHUNK_TIMEOUT_SECONDS,
                        )
                    except Exception as exc:
                        if _is_json_schema_error(exc):
                            fallback_result = await self._invoke_without_schema(llm, messages)
                            if fallback_result is not None:
                                chunk_successes += 1
                                for finding in fallback_result.findings:
                                    ftype = finding.type if finding.type in (
                                        "security", "logic", "performance", "best_practice"
                                    ) else "security"
                                    all_findings.append({
                                        "id": str(uuid.uuid4()),
                                        "type": ftype,
                                        "title": finding.title[:200],
                                        "description": finding.description,
                                        "recommendation": finding.recommendation,
                                        "confidence": round(finding.confidence, 2),
                                        "affectedCode": finding.affected_code,
                                        "severity": _finding_severity(ftype, finding.confidence),
                                    })
                                logger.info(
                                    "AI agent: model %s chunk %d/%d recovered via no-schema retry",
                                    model_name, i + 1, len(chunks),
                                )
                                continue

                        chunk_failures += 1
                        last_error = str(exc)
                        logger.error(
                            "AI agent: model %s chunk %d/%d failed – %s",
                            model_name, i + 1, len(chunks), exc,
                        )
                        if _is_quota_error(exc):
                            abort_current_model = True
                            stop_after_quota_error = True
                            break

            except Exception as exc:
                logger.exception("AI agent: model %s unexpected error – %s", model_name, exc)
                model_failures.append(f"{model_name}: {exc}")
                continue

            if chunk_successes == 0 and chunk_failures > 0:
                model_failures.append(f"{model_name}: {last_error or 'all chunks failed'}")
                if abort_current_model:
                    break
                continue

            if AI_ENABLE_HEURISTIC_FALLBACK and heuristic_findings:
                all_findings.extend(heuristic_findings)
                all_findings = _dedupe_findings(all_findings)

            # Build severity counts from findings
            sev_counts: Dict[str, int] = {"critical": 0, "high": 0, "medium": 0, "low": 0}
            for f in all_findings:
                sev = f.get("severity", "low")
                if sev in sev_counts:
                    sev_counts[sev] += 1

            elapsed = round(time.time() - start, 2)
            total_found = len(all_findings)
            top_sev = _top_severity(sev_counts)
            partial_note = ""
            if sampled_chunks:
                partial_note += f" (sampled {len(chunks)}/{total_chunks} chunks)"
            if chunk_failures > 0 and chunk_successes > 0:
                partial_note += f" (partial: {chunk_successes}/{len(chunks)} chunks succeeded)"

            logger.info(
                "AI agent: completed using %s on %d file(s) in %.1fs → %d finding(s) [top: %s]",
                model_name, len(analyzed_files), elapsed, total_found, top_sev,
            )

            return {
                "tool": "ai_agent",
                "provider": self._provider,
                "model": model_name,
                "findings": all_findings,
                "severity": top_sev,
                "summary": (
                    f"AI agent found {total_found} issue(s) across {len(analyzed_files)} file(s){partial_note}"
                    if total_found
                    else f"AI agent: no issues found in {len(analyzed_files)} file(s){partial_note}"
                ),
                "total_count": total_found,
                "severity_counts": sev_counts,
                "execution_time": elapsed,
                "status": "success",
                "analyzed_files": analyzed_files,
                "llm_chunk_successes": chunk_successes,
                "llm_chunk_failures": chunk_failures,
                "heuristic_added": bool(heuristic_findings),
            }

        reason = "; ".join(model_failures) if model_failures else "No compatible model available"
        reason = _compact_provider_reason(reason)
        return self._error_result(reason, provider=self._provider, model=self._model)

    # ── Static result factories ───────────────────────────────────────────────

    @staticmethod
    def _skipped_result(reason: str) -> Dict[str, Any]:
        return {
            "tool": "ai_agent",
            "provider": "none",
            "model": None,
            "findings": [],
            "severity": "info",
            "summary": f"AI agent skipped: {reason}",
            "total_count": 0,
            "severity_counts": {"critical": 0, "high": 0, "medium": 0, "low": 0},
            "execution_time": 0.0,
            "status": "skipped",
            "analyzed_files": [],
            "llm_chunk_successes": 0,
            "llm_chunk_failures": 0,
            "heuristic_added": False,
        }

    @staticmethod
    def _error_result(
        error: str,
        provider: str = "none",
        model: Optional[str] = None,
    ) -> Dict[str, Any]:
        return {
            "tool": "ai_agent",
            "provider": provider,
            "model": model,
            "findings": [],
            "severity": "info",
            "summary": f"AI agent error: {error[:300]}",
            "total_count": 0,
            "severity_counts": {"critical": 0, "high": 0, "medium": 0, "low": 0},
            "execution_time": 0.0,
            "status": "failed",
            "analyzed_files": [],
            "llm_chunk_successes": 0,
            "llm_chunk_failures": 0,
            "heuristic_added": False,
        }
