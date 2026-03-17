import subprocess

from app.core.config import settings
from app.models.pipeline_contracts import PRContext
from app.pipeline.ai_layer.pr_agent_adapter import PRAgentAdapter


def test_returns_empty_when_diff_missing():
    adapter = PRAgentAdapter()
    result = adapter.analyze_pr(
        PRContext(repo="owner/repo", pr_number=7, diff="")
    )
    assert result == {
        "ai_security_flags": [],
        "ai_code_smells": [],
        "ai_summary": "",
    }


def test_maps_json_output(monkeypatch):
    adapter = PRAgentAdapter()
    monkeypatch.setattr(adapter, "_is_installed", lambda: True)
    monkeypatch.setattr(adapter, "_command_prefix", lambda: [adapter.binary])

    payload = (
        '{"security_flags":["possible SQL injection"],'
        '"code_smells":["large function"],'
        '"summary":"Unsafe DB query construction"}'
    )

    def _fake_run(cmd):
        return 0, payload, ""

    monkeypatch.setattr(adapter, "_run_command", _fake_run)

    result = adapter.analyze_pr(
        PRContext(
            repo="owner/repo",
            pr_number=42,
            diff='diff --git a/app.py b/app.py\n+query = "SELECT * FROM users WHERE id=" + user_id\n',
        )
    )

    assert result["ai_security_flags"] == ["possible SQL injection"]
    assert result["ai_code_smells"] == ["large function"]
    assert result["ai_summary"] == "Unsafe DB query construction"


def test_pr_url_fallback_after_diff_mode_failure(monkeypatch):
    adapter = PRAgentAdapter()
    monkeypatch.setattr(adapter, "_is_installed", lambda: True)
    monkeypatch.setattr(adapter, "_command_prefix", lambda: [adapter.binary])

    calls = []

    def _fake_run(cmd):
        calls.append(cmd)
        # First command (diff mode) fails, second command (pr_url) succeeds
        if len(calls) == 1:
            return 2, "", "unknown flag --diff"
        return 0, "summary: potential SQL injection", ""

    monkeypatch.setattr(adapter, "_run_command", _fake_run)

    result = adapter.analyze_pr(
        PRContext(
            repo="owner/repo",
            pr_number=11,
            diff='diff --git a/app.py b/app.py\n+query = "SELECT * FROM users WHERE id=" + user_id\n',
        )
    )

    assert len(calls) == 2
    assert calls[0][:3] == ["pr-agent", "review", "--diff"]
    assert calls[1][0] == "pr-agent"
    assert calls[1][1].startswith("--pr_url")
    assert calls[1][-1] == "review"
    assert "potential sql injection" in result["ai_summary"].lower()


def test_returns_empty_on_total_failure(monkeypatch):
    adapter = PRAgentAdapter()
    monkeypatch.setattr(adapter, "_is_installed", lambda: True)
    monkeypatch.setattr(adapter, "_command_prefix", lambda: [adapter.binary])
    monkeypatch.setattr(adapter, "_run_command", lambda cmd: (1, "", "failure"))

    result = adapter.analyze_pr(
        PRContext(
            repo="owner/repo",
            pr_number=10,
            diff='diff --git a/a.py b/a.py\n+print("x")',
        )
    )

    assert result == {
        "ai_security_flags": [],
        "ai_code_smells": [],
        "ai_summary": "",
    }


def test_run_command_handles_timeout(monkeypatch):
    adapter = PRAgentAdapter(timeout_seconds=1)

    def _raise_timeout(*args, **kwargs):
        raise subprocess.TimeoutExpired(cmd="pr-agent", timeout=1)

    monkeypatch.setattr(subprocess, "run", _raise_timeout)
    rc, stdout, stderr = adapter._run_command(["pr-agent", "--help"])
    assert rc == 124
    assert stdout == ""
    assert "timeout" in stderr


def test_meta_marks_failure_when_binary_missing():
    adapter = PRAgentAdapter(binary="__missing_pr_agent_binary__", allow_module_fallback=False)
    result = adapter.analyze_pr(
        PRContext(
            repo="owner/repo",
            pr_number=1,
            diff='diff --git a/app.py b/app.py\n+print("x")',
        )
    )
    meta = adapter.last_meta()

    assert result == {
        "ai_security_flags": [],
        "ai_code_smells": [],
        "ai_summary": "",
    }
    assert meta["status"] == "failed"
    assert "not found" in meta["error"]


def test_ignores_cli_usage_output_and_falls_back(monkeypatch):
    adapter = PRAgentAdapter()
    monkeypatch.setattr(adapter, "_is_installed", lambda: True)
    monkeypatch.setattr(adapter, "_command_prefix", lambda: [adapter.binary])

    calls = []

    def _fake_run(cmd):
        calls.append(cmd)
        # First attempt returns CLI usage text (invalid invocation); second returns real content.
        if len(calls) == 1:
            return (
                0,
                "usage: Usage: cli.py --pr-url=<URL on supported git hosting service> <command> [<args>].",
                "",
            )
        return 0, "summary: potential SQL injection in dynamic query", ""

    monkeypatch.setattr(adapter, "_run_command", _fake_run)

    result = adapter.analyze_pr(
        PRContext(
            repo="owner/repo",
            pr_number=19,
            diff='diff --git a/app.py b/app.py\n+query = "SELECT * FROM users WHERE id=" + user_id\n',
        )
    )

    assert len(calls) >= 2
    assert "usage:" not in result["ai_summary"].lower()
    assert "sql injection" in result["ai_summary"].lower()


def test_runtime_failure_logs_are_treated_as_failure(monkeypatch):
    adapter = PRAgentAdapter()
    monkeypatch.setattr(adapter, "_is_installed", lambda: True)
    monkeypatch.setattr(adapter, "_command_prefix", lambda: [adapter.binary])

    def _fake_run(cmd):
        return (
            0,
            "INFO Reviewing PR\nERROR Failed to review PR: RetryError[APIConnectionError]",
            "",
        )

    monkeypatch.setattr(adapter, "_run_command", _fake_run)

    result = adapter.analyze_pr(
        PRContext(
            repo="owner/repo",
            pr_number=22,
            diff='diff --git a/app.py b/app.py\n+print("x")',
        )
    )
    meta = adapter.last_meta()

    assert result == {
        "ai_security_flags": [],
        "ai_code_smells": [],
        "ai_summary": "",
    }
    assert meta["status"] == "failed"
    assert "failed to review pr" in meta["error"].lower()


def test_build_subprocess_env_sets_pr_agent_alias_keys(monkeypatch):
    adapter = PRAgentAdapter()
    monkeypatch.setenv("GITHUB_TOKEN", "gh-test")
    monkeypatch.setenv("OPENAI_API_KEY", "sk-test")

    env = adapter._build_subprocess_env()

    assert env["GITHUB_TOKEN"] == "gh-test"
    assert env["GITHUB_USER_TOKEN"] == "gh-test"
    assert env["GITHUB__USER_TOKEN"] == "gh-test"
    assert env["OPENAI_API_KEY"] == "sk-test"
    assert env["OPENAI_KEY"] == "sk-test"
    assert env["OPENAI__KEY"] == "sk-test"


def test_rate_limit_error_marks_ai_as_skipped(monkeypatch):
    adapter = PRAgentAdapter()
    monkeypatch.setattr(adapter, "_is_installed", lambda: True)
    monkeypatch.setattr(adapter, "_command_prefix", lambda: [adapter.binary])
    monkeypatch.setattr(
        adapter,
        "_execution_profiles",
        lambda: [{"name": "default", "provider": adapter.provider_name, "model": adapter.model_name, "env": {}}],
    )
    monkeypatch.setattr(
        adapter,
        "_run_command",
        lambda cmd: (0, "ERROR Failed to review PR: RetryError[RateLimitError]", ""),
    )

    result = adapter.analyze_pr(
        PRContext(repo="owner/repo", pr_number=99, diff='diff --git a/a.py b/a.py\n+print("x")')
    )
    meta = adapter.last_meta()

    assert result == {
        "ai_security_flags": [],
        "ai_code_smells": [],
        "ai_summary": "",
    }
    assert meta["status"] == "skipped"
    assert "ratelimit" in meta["error"].lower()


def test_xai_profile_injects_model_and_keys(monkeypatch):
    adapter = PRAgentAdapter()
    monkeypatch.setenv("GITHUB_TOKEN", "gh-test")
    monkeypatch.setenv("XAI_API_KEY", "xai-test")
    monkeypatch.setattr(settings, "PR_AGENT_XAI_MODEL", "xai/grok-3-latest", raising=False)
    monkeypatch.setattr(settings, "PR_AGENT_XAI_CUSTOM_MODEL_MAX_TOKENS", 16384, raising=False)

    env = adapter._build_subprocess_env(profile="xai")

    assert env["GITHUB__USER_TOKEN"] == "gh-test"
    assert env["XAI_API_KEY"] == "xai-test"
    assert env["OPENAI__KEY"] == "xai-test"
    assert env["CONFIG__MODEL"] == "xai/grok-3-latest"
    assert env["CONFIG__MODEL_TURBO"] == "xai/grok-3-latest"
    assert env["CONFIG__CUSTOM_MODEL_MAX_TOKENS"] == "16384"


def test_rate_limit_reason_preserved_across_profiles(monkeypatch):
    adapter = PRAgentAdapter()
    monkeypatch.setattr(adapter, "_is_installed", lambda: True)
    monkeypatch.setattr(adapter, "_command_prefix", lambda: [adapter.binary])
    monkeypatch.setattr(
        adapter,
        "_execution_profiles",
        lambda: [
            {"name": "default", "provider": "pr-agent", "model": "m1", "env": {"PROFILE": "default"}},
            {"name": "xai", "provider": "pr-agent-xai", "model": "m2", "env": {"PROFILE": "xai"}},
        ],
    )

    def _fake_run(cmd):
        profile = adapter._active_env.get("PROFILE", "")
        if profile == "default":
            return 0, "ERROR Failed to review PR: RetryError[RateLimitError]", ""
        return 0, "ERROR Failed to review PR: RetryError[BadRequestError]", ""

    monkeypatch.setattr(adapter, "_run_command", _fake_run)

    _ = adapter.analyze_pr(
        PRContext(repo="owner/repo", pr_number=101, diff='diff --git a/a.py b/a.py\n+print("x")')
    )
    meta = adapter.last_meta()

    assert meta["status"] == "skipped"
    assert "ratelimit" in meta["error"].lower()
