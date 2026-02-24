from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from app.api.routes import health, analyze, predict, github_analyzer
from app.core.database import engine, Base
from app.services.cache_service import cache
import logging

logger = logging.getLogger(__name__)

# Create database tables
Base.metadata.create_all(bind=engine)


def _migrate_db():
    """Add new columns to existing tables (safe for SQLite — ignores if column exists)."""
    migrations = [
        "ALTER TABLE pull_requests ADD COLUMN files_changed INTEGER",
        "ALTER TABLE pull_requests ADD COLUMN lines_added INTEGER",
        "ALTER TABLE pull_requests ADD COLUMN lines_deleted INTEGER",
        "ALTER TABLE pull_requests ADD COLUMN author_name VARCHAR",
        "ALTER TABLE scan_results ADD COLUMN execution_time FLOAT",
        "ALTER TABLE scan_results ADD COLUMN severity_counts JSON",
        "ALTER TABLE pull_requests ADD COLUMN feature_importance JSON",
    ]
    with engine.connect() as conn:
        for stmt in migrations:
            try:
                conn.execute(__import__("sqlalchemy").text(stmt))
                conn.commit()
            except Exception:
                # Column already exists — that's fine
                try:
                    conn.rollback()
                except Exception:
                    pass


_migrate_db()

app = FastAPI(
    title="Security Gate API",
    description="AI-Driven PR Analysis System with ML Risk Modeling & Blockchain Audit Trail",
    version="0.1.0"
)

# CORS middleware
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],  # Update in production
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
