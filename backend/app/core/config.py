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
    SNYK_TOKEN: Optional[str] = None
    GITHUB_TOKEN: Optional[str] = None
    
    # Blockchain
    BLOCKCHAIN_PRIVATE_KEY: Optional[str] = None
    BLOCKCHAIN_CONTRACT_ADDRESS: Optional[str] = None
    SEPOLIA_RPC_URL: Optional[str] = None
    
    # ML Model
    ML_MODEL_PATH: str = "../ml-model/models/xgboost_v1.pkl"
    
    class Config:
        env_file = ".env"
        case_sensitive = True

settings = Settings()
