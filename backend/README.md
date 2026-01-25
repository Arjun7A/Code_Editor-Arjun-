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

# Run development server
uvicorn app.main:app --reload
```

## API Endpoints

- `POST /api/analyze` - Analyze a Pull Request
- `GET /api/results/{pr_id}` - Get analysis results
- `GET /api/health` - Health check

## Owner
**Arjun** - Primary developer
