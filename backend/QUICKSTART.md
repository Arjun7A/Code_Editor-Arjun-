# Quick Start Backend

## Option 1: Run with Docker (Recommended)
```bash
# From project root
docker-compose up backend

# Visit: http://localhost:8000
# API Docs: http://localhost:8000/docs
```

## Option 2: Run Locally (Without Docker)
```bash
cd backend

# Create virtual environment
python -m venv venv
venv\Scripts\activate  # Windows
# source venv/bin/activate  # Mac/Linux

# Install dependencies
pip install -r requirements.txt

# Create .env file
copy .env.example .env

# Run the server
uvicorn app.main:app --reload

# Visit: http://localhost:8000
```

## Test Health Check
```bash
curl http://localhost:8000/api/health
```

Expected response:
```json
{
  "status": "healthy",
  "timestamp": "2026-01-26T...",
  "service": "security-gate-api"
}
```
