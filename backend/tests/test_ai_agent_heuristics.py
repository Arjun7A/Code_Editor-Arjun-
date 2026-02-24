import re
from pathlib import Path

import pytest

from app.services import ai_agent


def test_load_heuristic_rules_from_yaml(tmp_path: Path, monkeypatch: pytest.MonkeyPatch):
    rules_file = tmp_path / "ai_heuristics.yaml"
    rules_file.write_text(
        "\n".join(
            [
                "rules:",
                "  - id: demo_rule",
                "    pattern: 'dangerous\\(.*\\)'",
                "    flags:",
                "      - IGNORECASE",
                '    title: "Demo heuristic"',
                '    description: "Demo description"',
                '    recommendation: "Fix this"',
                "    confidence: 0.77",
                "    severity: high",
                "    type: security",
            ]
        ),
        encoding="utf-8",
    )

    monkeypatch.setattr(ai_agent, "_AI_HEURISTICS_PATH", rules_file)
    loaded = ai_agent._load_heuristic_rules()

    assert len(loaded) == 1
    assert loaded[0]["id"] == "demo_rule"
    assert loaded[0]["severity"] == "high"
    assert loaded[0]["type"] == "security"
    assert loaded[0]["pattern"].flags & re.IGNORECASE
    assert loaded[0]["pattern"].search("Dangerous(user_input)")


def test_scan_heuristics_uses_loaded_rules(monkeypatch: pytest.MonkeyPatch):
    demo_rules = [
        {
            "id": "eval_demo",
            "pattern": re.compile(r"\beval\s*\("),
            "title": "Eval usage",
            "description": "Eval is unsafe.",
            "recommendation": "Remove eval.",
            "confidence": 0.9,
            "severity": "high",
            "type": "security",
        }
    ]
    monkeypatch.setattr(ai_agent, "_HEURISTIC_RULES", demo_rules)

    findings = ai_agent._scan_heuristics(
        [
            {
                "filename": "app.py",
                "patch": "@@ -1 +1 @@\n+result = eval(user_input)\n",
            }
        ]
    )

    assert len(findings) == 1
    finding = findings[0]
    assert finding["title"] == "Eval usage"
    assert finding["type"] == "security"
    assert finding["severity"] == "high"
    assert finding["confidence"] == 0.9
