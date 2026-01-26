from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from app.api.routes import health, analyze
from app.core.database import engine, Base

# Create database tables
Base.metadata.create_all(bind=engine)

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

@app.get("/")
async def root():
    return {
        "message": "Security Gate API",
        "version": "0.1.0",
        "status": "running"
    }
