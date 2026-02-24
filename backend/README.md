# Backend - FastAPI Application

## Overview
FastAPI backend that orchestrates security scans, AI analysis, ML predictions, and blockchain logging.

## Structure
```
backend/
├── app/
│   ├── main.py              # FastAPI app entry point
│   ├── api/
│   │   ├── routes/          # API endpoints
│   │   └── dependencies.py  # Shared dependencies
│   ├── core/
│   │   ├── config.py        # Configuration
│   │   └── security.py      # Security utilities
│   ├── models/              # Database models
│   ├── services/
│   │   ├── scanner.py       # Snyk + Semgrep integration
│   │   ├── ai_agent.py      # LangChain AI
│   │   ├── ml_model.py      # XGBoost predictor
│   │   ├── policy.py        # Policy engine
│   │   └── blockchain.py    # Web3 integration
│   └── schemas/             # Pydantic models
├── tests/                   # Unit tests
├── Dockerfile
├── requirements.txt
└── README.md
```

## Setup

```bash
# Create virtual environment
python -m venv venv
source venv/bin/activate  # Windows: venv\Scripts\activate

# Install dependencies
pip install -r requirements.txt

# Optional: enable Redis cache
# REDIS_ENABLED=true
# REDIS_URL=redis://localhost:6379/0

# Configure xAI Grok provider
# XAI_API_KEY=...
# GROK_MODEL=grok-3-latest

# Verify deployed frontend/backend URLs and export a JSON report
python scripts/verify_deployment.py --backend-url https://your-api.onrender.com --frontend-url https://your-app.vercel.app --timeout 60

# Run development server
uvicorn app.main:app --reload
```

## API Endpoints

- `POST /api/analyze` - Analyze a Pull Request
- `GET /api/results/{pr_id}` - Get analysis results
- `GET /api/policy/rules` - Active policy rules
- `GET /api/blockchain/verify/{pr_id}` - Verify blockchain audit record
- `GET /api/health` - Health check
- `GET /api/dashboard-stats` - Cached dashboard stats (Redis if enabled)
