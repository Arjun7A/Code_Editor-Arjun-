"""YAML-driven policy engine for PR verdict decisions."""

from __future__ import annotations

import ast
import logging
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Dict, List, Optional

import yaml

logger = logging.getLogger(__name__)

_ALLOWED_ACTIONS = {"AUTO_APPROVE", "MANUAL_REVIEW", "BLOCK"}
_ALLOWED_AST_NODES = {
    ast.Expression,
    ast.BoolOp,
    ast.BinOp,
    ast.UnaryOp,
    ast.Compare,
    ast.Name,
    ast.Load,
    ast.Constant,
    ast.And,
    ast.Or,
    ast.Not,
    ast.Gt,
    ast.GtE,
    ast.Lt,
    ast.LtE,
    ast.Eq,
    ast.NotEq,
    ast.Add,
    ast.Sub,
    ast.Mult,
    ast.Div,
    ast.Mod,
    ast.UAdd,
    ast.USub,
}


@dataclass
class PolicyRule:
    name: str
    condition: str
    action: str
    description: str = ""
    enabled: bool = True
    priority: int = 100


class PolicyEngine:
    """Evaluates PR security signals against YAML policy rules."""

    def __init__(self, policy_path: Optional[str] = None):
        base_dir = Path(__file__).resolve().parents[1]
        self.policy_path = Path(policy_path) if policy_path else (base_dir / "policy" / "rules.yaml")
        self.default_action = "AUTO_APPROVE"
        self.rules: List[PolicyRule] = []
        self.reload()

    def reload(self) -> None:
        """Load policy rules from YAML; fallback to built-ins on error."""
        self.rules = []
        self.default_action = "AUTO_APPROVE"

        if not self.policy_path.exists():
            logger.warning("Policy file %s not found. Using defaults.", self.policy_path)
            self.rules = self._default_rules()
            return

        try:
            payload = yaml.safe_load(self.policy_path.read_text(encoding="utf-8")) or {}
            raw_rules = payload.get("rules", [])
            self.default_action = self._normalize_action(payload.get("default_action", "AUTO_APPROVE"))

            for item in raw_rules:
                if not isinstance(item, dict):
                    continue
                action = self._normalize_action(item.get("action", "MANUAL_REVIEW"))
                rule = PolicyRule(
                    name=str(item.get("name", "Unnamed rule")),
                    description=str(item.get("description", "")),
                    enabled=bool(item.get("enabled", True)),
                    priority=int(item.get("priority", 100)),
                    condition=str(item.get("condition", "False")),
                    action=action,
                )
                self.rules.append(rule)

            if not self.rules:
                logger.warning("Policy file loaded but no rules found. Falling back to defaults.")
                self.rules = self._default_rules()

            self.rules.sort(key=lambda r: r.priority)

        except Exception as exc:
            logger.exception("Failed to load policy file %s: %s", self.policy_path, exc)
            self.rules = self._default_rules()

    def evaluate(self, signals: Dict[str, Any]) -> Dict[str, Any]:
        """Return a verdict and matched policy rule for a set of signals."""
        context = self._normalize_signals(signals)

        for rule in self.rules:
            if not rule.enabled:
                continue
            matched, error = self._evaluate_condition(rule.condition, context)
            if error:
                logger.warning("Skipping invalid policy condition for '%s': %s", rule.name, error)
                continue
            if matched:
                return {
                    "verdict": rule.action,
                    "reason": rule.description or rule.name,
                    "matched_rule": {
                        "name": rule.name,
                        "condition": rule.condition,
                        "action": rule.action,
                        "priority": rule.priority,
                    },
                }

        return {
            "verdict": self.default_action,
            "reason": "No blocking/review rules matched",
            "matched_rule": None,
        }

    def _evaluate_condition(self, expression: str, context: Dict[str, Any]) -> tuple[bool, Optional[str]]:
        """Safely evaluate a boolean expression against known context keys."""
        try:
            tree = ast.parse(expression, mode="eval")
            for node in ast.walk(tree):
                if type(node) not in _ALLOWED_AST_NODES:
                    return False, f"Unsupported token: {type(node).__name__}"
            compiled = compile(tree, "<policy-condition>", "eval")
            matched = bool(eval(compiled, {"__builtins__": {}}, context))
            return matched, None
        except Exception as exc:
            return False, str(exc)

    @staticmethod
    def _normalize_signals(signals: Dict[str, Any]) -> Dict[str, Any]:
        normalized: Dict[str, Any] = {}
        for key, value in signals.items():
            if isinstance(value, bool):
                normalized[key] = value
            elif isinstance(value, (int, float)):
                normalized[key] = value
            else:
                try:
                    normalized[key] = float(value)
                except Exception:
                    normalized[key] = value
        return normalized

    @staticmethod
    def _normalize_action(action: str) -> str:
        normalized = str(action or "").strip().upper()
        return normalized if normalized in _ALLOWED_ACTIONS else "MANUAL_REVIEW"

    @staticmethod
    def _default_rules() -> List[PolicyRule]:
        """Fallback rules mirroring the intended scan/AI/ML gate behavior."""
        return [
            PolicyRule(
                name="Block critical findings",
                condition="critical_count > 0",
                action="BLOCK",
                description="At least one critical finding was detected.",
                priority=10,
            ),
            PolicyRule(
                name="Block repeated high findings",
                condition="high_count >= 3",
                action="BLOCK",
                description="Three or more high-severity findings were detected.",
                priority=20,
            ),
            PolicyRule(
                name="Block high ML risk",
                condition="risk_score >= 70",
                action="BLOCK",
                description="ML model marked this PR as high-risk.",
                priority=30,
            ),
            PolicyRule(
                name="Manual review for medium risk",
                condition="risk_score >= 40 or ai_high_security_findings >= 1",
                action="MANUAL_REVIEW",
                description="Medium-risk signal requires human approval.",
                priority=40,
            ),
        ]
