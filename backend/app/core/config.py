from pathlib import Path
from typing import Optional

from pydantic import field_validator
from pydantic_settings import BaseSettings

_DEFAULT_SQLITE_PATH = (Path(__file__).resolve().parents[2] / "security_gate.db").as_posix()
_DEFAULT_POLICY_RULES_PATH = (Path(__file__).resolve().parents[1] / "policy" / "rules.yaml").as_posix()

class Settings(BaseSettings):
    # API Settings
    API_VERSION: str = "0.1.0"
    API_TITLE: str = "Security Gate API"
    DEBUG: bool = True
    
    # Database
    DATABASE_URL: str = f"sqlite:///{_DEFAULT_SQLITE_PATH}"
    
    # CORS – comma-separated list of allowed origins
    CORS_ORIGINS: str = "http://localhost:5173,http://localhost:3000"
    
    # API Keys
    CLAUDE_API_KEY: Optional[str] = None
    OPENAI_API_KEY: Optional[str] = None
    # xAI Grok
    XAI_API_KEY: Optional[str] = None
    XAI_API_BASE_URL: str = "https://api.x.ai/v1"
    GROK_MODEL: str = "grok-3-latest"
    AI_REQUIRE_XAI: bool = True
    AI_ENABLE_HEURISTIC_FALLBACK: bool = False
    SNYK_TOKEN: Optional[str] = None
    GITHUB_TOKEN: Optional[str] = None
    SNYK_RUN_ALL_PRS: bool = False
    SNYK_TIMEOUT_SECONDS: int = 120
    SEMGREP_TIMEOUT_SECONDS: int = 120
    SEMGREP_MAX_FILES_PER_PR: int = 60
    AI_MAX_CHUNKS: int = 10
    AI_MAX_OUTPUT_TOKENS: int = 1024
    PR_AGENT_BINARY: Optional[str] = None
    PR_AGENT_TIMEOUT_SECONDS: int = 90
    PR_AGENT_PROVIDER_NAME: str = "pr-agent"
    PR_AGENT_MODEL_NAME: str = "pr-agent-cli"
    PR_AGENT_USE_DIFF_MODE: bool = True
    PR_AGENT_ALLOW_MODULE_FALLBACK: bool = True
    PR_AGENT_ENABLE_XAI_FALLBACK: bool = True
    PR_AGENT_XAI_MODEL: str = "xai/grok-3-latest"
    PR_AGENT_XAI_CUSTOM_MODEL_MAX_TOKENS: int = 32768
    
    # Blockchain
    BLOCKCHAIN_PRIVATE_KEY: Optional[str] = None
    BLOCKCHAIN_CONTRACT_ADDRESS: Optional[str] = None
    SEPOLIA_RPC_URL: Optional[str] = None
    BLOCKCHAIN_NETWORK: str = "sepolia"
    BLOCKCHAIN_EXPLORER_TX_BASE: str = "https://sepolia.etherscan.io/tx/"

    # Policy Engine
    POLICY_RULES_PATH: str = _DEFAULT_POLICY_RULES_PATH

    # Redis / API caching
    REDIS_ENABLED: bool = True
    REDIS_URL: str = "redis://localhost:6379/0"
    CACHE_TTL_DASHBOARD_SECONDS: int = 30
    CACHE_TTL_RESULTS_SECONDS: int = 20
    CACHE_TTL_POLICY_SECONDS: int = 60
    
    # ML Model
    ML_MODEL_PATH: str = "../ml-model/models/xgboost_v1.pkl"
    AI_CHUNK_TIMEOUT_SECONDS: int = 45

    @field_validator("DEBUG", mode="before")
    @classmethod
    def _coerce_debug(cls, value):
        if isinstance(value, str):
            token = value.strip().lower()
            if token in {"release", "prod", "production", "false", "0", "no", "off"}:
                return False
            if token in {"debug", "dev", "development", "true", "1", "yes", "on"}:
                return True
        return value

    @field_validator("DATABASE_URL", mode="before")
    @classmethod
    def _normalize_database_url(cls, value):
        raw = str(value or "").strip()
        if not raw:
            return f"sqlite:///{_DEFAULT_SQLITE_PATH}"

        sqlite_prefix = "sqlite:///"
        if not raw.startswith(sqlite_prefix):
            return raw

        db_path = raw[len(sqlite_prefix):].strip()
        if not db_path or db_path == ":memory:" or db_path.startswith("file:"):
            return raw

        path = Path(db_path).expanduser()
        if not path.is_absolute():
            project_root = Path(__file__).resolve().parents[2]
            path = (project_root / path).resolve()

        return f"{sqlite_prefix}{path.as_posix()}"

    @field_validator("POLICY_RULES_PATH", mode="before")
    @classmethod
    def _normalize_policy_rules_path(cls, value):
        raw = str(value or "").strip()
        if not raw:
            return _DEFAULT_POLICY_RULES_PATH

        path = Path(raw).expanduser()
        if not path.is_absolute():
            project_root = Path(__file__).resolve().parents[2]
            path = (project_root / path).resolve()
        return path.as_posix()
    
    class Config:
        env_file = ".env"
        case_sensitive = True
        extra = "ignore"

settings = Settings()
