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

## Supabase (Postgres) Setup
If you want data stored in Supabase instead of local SQLite:

1. Set `DATABASE_URL` in `backend/.env` to your Supabase Postgres connection string:
```bash
DATABASE_URL=postgresql://postgres.<project-ref>:<password>@aws-0-<region>.pooler.supabase.com:6543/postgres
```

2. In Supabase SQL Editor, run:
- `backend/supabase/001_create_core_tables.sql`
- `backend/supabase/002_verify_core_tables.sql`

3. Validate schema + write access from backend:
```bash
cd backend
python scripts/check_supabase_schema.py
```

4. Start backend normally. New analysis rows will be written to:
- `pull_requests`
- `scan_results`
- `audit_logs`

### Snyk Behavior in `/api/analyze_github`
- Default: Snyk runs only when a PR changes dependency manifests.
- Force run on every PR: set in `backend/.env`:
```bash
SNYK_RUN_ALL_PRS=true
```
