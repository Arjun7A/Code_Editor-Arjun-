# Deployment Runbook

This runbook captures how to prove a live deployment is healthy and traceable.

## 1) Required URLs
- Frontend URL: `https://<your-app>.vercel.app`
- Backend URL: `https://<your-api>.onrender.com`

## 2) Manual Smoke Checks
Run these commands after deployment:

```bash
curl -fsS https://<your-api>.onrender.com/api/health
curl -fsS https://<your-api>.onrender.com/api/dashboard-stats
curl -fsS https://<your-api>.onrender.com/api/policy/rules
curl -fsS -X POST "https://<your-api>.onrender.com/api/scan" \
  -H "Content-Type: application/json" \
  -d '{"code":"print(\"smoke\")","filename":"smoke.py"}'
```

## 3) Automated Verification Report

Use the verifier script to generate an auditable JSON artifact:

```bash
cd backend
python scripts/verify_deployment.py \
  --backend-url https://<your-api>.onrender.com \
  --frontend-url https://<your-app>.vercel.app \
  --timeout 60 \
  --output ../docs/deployment/latest-verification.json
```

- Exit code `0` means all checks passed.
- Exit code `1` means at least one check failed.

## 4) Load Test Proof

Run at least one k6 profile against the deployed backend:

```bash
k6 run -e BASE_URL=https://<your-api>.onrender.com ../load-tests/k6-smoke.js
```

Or trigger GitHub Actions workflow `load-test` with:
- `backend_url`: deployed backend URL
- `profile`: `smoke` or `stress`

## 5) Evidence to Commit
- `docs/deployment/latest-verification.json`
- k6 summary JSON outputs (from workflow artifacts or local export)
- Any incident notes for failed checks and fixes applied
