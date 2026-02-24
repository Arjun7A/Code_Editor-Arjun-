# Security Gate Gap Checklist (Plan vs Implementation)
Last verified: 2026-02-24

Legend:
- `[x]` Done
- `[~]` Partial / implemented but with caveats
- `[ ]` Missing

## 1) Foundation (Week 1-2)
- `[x]` FastAPI backend scaffold and routing
- `[x]` Core DB models (`pull_requests`, `scan_results`, `audit_logs`)
- `[x]` Main endpoints: `/api/analyze`, `/api/results/{id}`, `/api/health`
- `[x]` Scanner orchestrator for Snyk + Semgrep
- `[x]` React dashboard structure and routing
- `[x]` ML data + model artifacts (XGBoost `.pkl`, metrics)
- `[x]` `/api/predict_risk` endpoint
- `[x]` Frontend uses explicit unavailable state instead of silent zero-value fallbacks

Evidence:
- `backend/app/main.py`
- `backend/app/models/database_models.py`
- `backend/app/api/routes/analyze.py`
- `backend/app/services/scanner_orchestrator.py`
- `frontend/src/pages/Dashboard.tsx`
- `frontend/src/pages/Reports.tsx`
- `frontend/src/components/dashboard/stats-cards.tsx`
- `backend/app/api/routes/predict.py`
- `ml-model/models/xgboost_v1.pkl`

## 2) Core Intelligence (Week 3-4)
- `[x]` LangChain-based AI agent implemented and wired
- `[x]` ML + scanner + AI signal aggregation into policy decision
- `[x]` YAML policy engine and policy route
- `[x]` Smart contract + contract tests
- `[x]` Backend blockchain service integration and verification endpoint
- `[~]` Plan asked for Claude path; implementation uses Gemini provider
- `[~]` On-chain logging support exists, but runtime depends on reachable Sepolia RPC + funded key

Evidence:
- `backend/app/services/ai_agent.py`
- `backend/app/services/policy_engine.py`
- `backend/app/policy/rules.yaml`
- `blockchain/contracts/AuditLog.sol`
- `blockchain/test/AuditLog.test.js`
- `backend/app/services/blockchain_service.py`

## 3) Integration (Week 5-6)
- `[x]` Frontend consumes backend APIs for dashboard, PR detail, audit logs
- `[x]` GitHub Actions workflow for PR security gate exists
- `[~]` Backend tests expanded (heuristics + policy + cache + route helper coverage), but full integration/e2e coverage is still limited
- `[~]` Frontend automated tests expanded (Vitest API mapping/dedupe/error suites), but component/e2e coverage is still limited
- `[x]` Load testing artifacts implemented (k6 smoke/stress + workflow)
- `[x]` Redis caching implemented for hot read endpoints with invalidation on analysis writes

Evidence:
- `frontend/src/lib/api.ts`
- `.github/workflows/security-gate.yml`
- `backend/tests/test_ai_agent_heuristics.py`
- `backend/tests/test_policy_engine.py`
- `backend/tests/test_cache_service.py`
- `backend/tests/test_analyze_helpers.py`
- `frontend/src/lib/api.test.ts`
- `frontend/vitest.config.ts`
- `load-tests/k6-smoke.js`
- `load-tests/k6-stress.js`
- `.github/workflows/load-test.yml`
- `backend/app/services/cache_service.py`

## 4) Deployment & Demo (Week 7-8)
- `[~]` Dockerfile and deployment-ready structure present
- `[~]` Deployment verification automation/runbook implemented; real production URL evidence still needs one live run
- `[ ]` Final demo collateral (slides/video/script) not in repo

Evidence:
- `backend/Dockerfile`
- `docker-compose.yml`
- `backend/scripts/verify_deployment.py`
- `docs/deployment/RUNBOOK.md`
- `docs/deployment/verification-template.json`

## 5) Must-Have MVP Status
- `[x]` Snyk + Semgrep scanning
- `[x]` Basic LangChain AI analysis
- `[x]` ML risk scoring
- `[x]` Policy engine
- `[x]` React dashboard
- `[x]` GitHub Actions trigger
- `[x]` Blockchain logging path (with environment-dependent on-chain mode)

## 6) No-Hardcoding Refactor Status (This Pass)
- `[x]` Frontend removed hardcoded verdict threshold mapping for GitHub analyzer results
  - Now consumes backend `verdict` from policy output.
- `[x]` Backend `/api/analyze_github` now accepts runtime analysis flags:
  - `enable_ai`, `enable_ml`, `enable_security_scan`
- `[x]` Submit page now forwards these flags to backend and respects scan toggle
- `[x]` Security keyword/path heuristics moved to YAML config:
  - `backend/app/policy/analysis_terms.yaml`
- `[x]` AI heuristic detection rules moved to YAML config:
  - `backend/app/policy/ai_heuristics.yaml`

## 7) Remaining Blockers to “Fully Complete Without Hardcoding”
- `[x]` Remove AI heuristic rule constants from code into config-driven rule file(s) + loader
- `[x]` Remove frontend policy fallback defaults (replace with explicit offline/disabled state)
- `[~]` Add backend and frontend automated tests per plan (coverage materially expanded; broader integration/e2e still pending)
- `[~]` Close deployment proof gaps (runbook + verifier added; needs live Render/Vercel URL verification report commit)
