"""Pipeline-level shared contracts."""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Dict, List


@dataclass(slots=True)
class PRContext:
    """Canonical context object shared across pipeline layers."""

    repo: str
    pr_number: int
    commit_hash: str = ""
    diff: str = ""
    files_changed: List[str] = field(default_factory=list)
    lines_added: int = 0
    lines_deleted: int = 0

    @property
    def pr_url(self) -> str:
        repo = (self.repo or "").strip().strip("/")
        if "/" not in repo or self.pr_number <= 0:
            return ""
        return f"https://github.com/{repo}/pull/{self.pr_number}"

    @classmethod
    def from_payload(cls, payload: Dict[str, Any]) -> "PRContext":
        return cls(
            repo=str(payload.get("repo", "")).strip(),
            pr_number=int(payload.get("pr_number", 0) or 0),
            commit_hash=str(payload.get("commit_hash", "")).strip(),
            diff=str(payload.get("diff", "") or ""),
            files_changed=list(payload.get("files_changed", []) or []),
            lines_added=int(payload.get("lines_added", 0) or 0),
            lines_deleted=int(payload.get("lines_deleted", 0) or 0),
        )

