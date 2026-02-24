from pathlib import Path

from app.services.policy_engine import PolicyEngine


def test_policy_engine_loads_yaml_and_applies_priority(tmp_path: Path):
    policy_file = tmp_path / "rules.yaml"
    policy_file.write_text(
        "\n".join(
            [
                "default_action: AUTO_APPROVE",
                "rules:",
                "  - name: medium-risk-review",
                "    description: medium risk should be reviewed",
                "    enabled: true",
                "    priority: 30",
                "    condition: risk_score >= 40",
                "    action: MANUAL_REVIEW",
                "  - name: critical-block",
                "    description: critical findings must block",
                "    enabled: true",
                "    priority: 10",
                "    condition: critical_count > 0",
                "    action: BLOCK",
            ]
        ),
        encoding="utf-8",
    )

    engine = PolicyEngine(policy_path=str(policy_file))

    decision = engine.evaluate({"risk_score": 80, "critical_count": 1})
    assert decision["verdict"] == "BLOCK"
    assert decision["matched_rule"]["name"] == "critical-block"

    decision = engine.evaluate({"risk_score": 45, "critical_count": 0})
    assert decision["verdict"] == "MANUAL_REVIEW"
    assert decision["matched_rule"]["name"] == "medium-risk-review"


def test_policy_engine_skips_unsafe_conditions(tmp_path: Path):
    policy_file = tmp_path / "unsafe.yaml"
    policy_file.write_text(
        "\n".join(
            [
                "default_action: AUTO_APPROVE",
                "rules:",
                "  - name: unsafe-call",
                "    enabled: true",
                "    priority: 1",
                "    condition: __import__('os').system('echo no')",
                "    action: BLOCK",
            ]
        ),
        encoding="utf-8",
    )

    engine = PolicyEngine(policy_path=str(policy_file))
    decision = engine.evaluate({"risk_score": 100, "critical_count": 5})
    assert decision["verdict"] == "AUTO_APPROVE"
    assert decision["matched_rule"] is None
