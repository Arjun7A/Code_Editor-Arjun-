import asyncio
import logging
logging.basicConfig(level=logging.DEBUG)
from app.pipeline.ai_layer.pr_agent_adapter import PRAgentAdapter
from app.models.pipeline_contracts import PRContext
from app.core.config import settings

adapter = PRAgentAdapter(
    binary=settings.PR_AGENT_BINARY,
    timeout_seconds=90,
    provider_name=settings.PR_AGENT_PROVIDER_NAME,
    model_name=settings.PR_AGENT_MODEL_NAME,
    use_diff_mode=settings.PR_AGENT_USE_DIFF_MODE,
    allow_module_fallback=True,
)

ctx = PRContext(
    repo="langchain-ai/langchain",
    pr_number=1,
    commit_hash="abcdef123456",
    diff="fake diff",
    files_changed=["langchain/formatting.py"],
    lines_added=10,
    lines_deleted=0,
)

print("Running adapter analyze_pr...")
res = adapter.analyze_pr(ctx, scan_results={})
print("Result:", res)
print("Meta:", adapter.last_meta())
