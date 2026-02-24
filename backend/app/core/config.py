from pydantic_settings import BaseSettings
from typing import Optional

class Settings(BaseSettings):
    # API Settings
    API_VERSION: str = "0.1.0"
    API_TITLE: str = "Security Gate API"
    DEBUG: bool = True
    
    # Database
    DATABASE_URL: str = "sqlite:///./security_gate.db"
    
    # API Keys
    CLAUDE_API_KEY: Optional[str] = None
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
    
    # Blockchain
    BLOCKCHAIN_PRIVATE_KEY: Optional[str] = None
    BLOCKCHAIN_CONTRACT_ADDRESS: Optional[str] = None
    SEPOLIA_RPC_URL: Optional[str] = None
    BLOCKCHAIN_NETWORK: str = "sepolia"
    BLOCKCHAIN_EXPLORER_TX_BASE: str = "https://sepolia.etherscan.io/tx/"

    # Policy Engine
    POLICY_RULES_PATH: str = "app/policy/rules.yaml"

    # Redis / API caching
    REDIS_ENABLED: bool = True
    REDIS_URL: str = "redis://localhost:6379/0"
    CACHE_TTL_DASHBOARD_SECONDS: int = 30
    CACHE_TTL_RESULTS_SECONDS: int = 20
    CACHE_TTL_POLICY_SECONDS: int = 60
    
    # ML Model
    ML_MODEL_PATH: str = "../ml-model/models/xgboost_v1.pkl"
    AI_CHUNK_TIMEOUT_SECONDS: int = 45
    
    class Config:
        env_file = ".env"
        case_sensitive = True

settings = Settings()
