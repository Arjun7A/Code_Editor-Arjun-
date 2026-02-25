from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from app.api.routes import health, analyze, predict, github_analyzer
from app.core.database import engine, Base
from app.services.cache_service import cache
from app.core.config import settings
import logging

logger = logging.getLogger(__name__)

# Create database tables (only for SQLite / local dev; Postgres schema is managed via SQL migrations)
if "sqlite" in settings.DATABASE_URL:
    Base.metadata.create_all(bind=engine)

app = FastAPI(
    title="Security Gate API",
    description="AI-Driven PR Analysis System with ML Risk Modeling & Blockchain Audit Trail",
    version="0.1.0"
)

# CORS middleware – allow origins listed in CORS_ORIGINS env var (comma-separated)
# Default to localhost for local dev; set to your Vercel URL on Render
allow_origins = [o.strip() for o in settings.CORS_ORIGINS.split(",") if o.strip()]

app.add_middleware(
    CORSMiddleware,
    allow_origins=allow_origins,
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Include routers
app.include_router(health.router, prefix="/api", tags=["health"])
app.include_router(analyze.router, prefix="/api", tags=["analysis"])
app.include_router(predict.router, prefix="/api", tags=["ml"])
app.include_router(github_analyzer.router, prefix="/api", tags=["github"])


@app.on_event("startup")
async def _startup() -> None:
    cache.connect()


@app.on_event("shutdown")
async def _shutdown() -> None:
    cache.close()

@app.get("/")
async def root():
    return {
        "message": "Security Gate API",
        "version": "0.1.0",
        "status": "running"
    }
