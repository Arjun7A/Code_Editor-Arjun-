# Implementation Plan (Updated for Layered Security Pipeline)

Last updated: 2026-03-16

Implementation status:
- Layer 2 (PR-Agent adapter integration) implemented in backend routes.
- Remaining pipeline modularization/orchestrator work still pending.

## 1. Goal

Refactor the current system into a strict layered pipeline for GitHub PR security gating:

1. PR trigger (GitHub Actions)
2. Layer 1: Static scanning (Semgrep + Snyk)
3. Layer 2: AI code analysis (open-source PR-Agent)
4. Layer 3: Feature engineering
5. Layer 4: ML risk scoring
6. Layer 5: Policy engine
7. Layer 6: Blockchain audit logging
8. Dashboard visualization

The refactor must remove hardcoded orchestration logic and make each layer swappable, testable, and CI-friendly.

---

## 2. Key Innovation

The system combines multiple security signals (static analysis, AI reasoning, and PR metadata) into an ML-driven risk prediction model that automatically enforces policy decisions in CI/CD and records tamper-proof audit logs on blockchain.

---

## 3. Current Codebase Snapshot (What Exists Today)

### Backend

- FastAPI app entry: `backend/app/main.py`
- Existing API routes:
  - `POST /api/scan`
  - `POST /api/analyze`
  - `POST /api/analyze_github`
  - `GET /api/results*`, `GET /api/dashboard-stats`, `GET /api/blockchain/verify/{pr_id}`, `GET /api/policy/rules`
- Existing services:
  - `services/semgrep_scanner.py`
  - `services/snyk_scanner.py`
  - `services/scanner_orchestrator.py`
  - `services/ai_agent.py`
  - `services/ml_predictor.py`
  - `services/policy_engine.py`
  - `services/blockchain_service.py`

### Frontend

- React dashboard consumes backend through `frontend/src/lib/api.ts`.
- Existing pages already render PR list, risk score, scanner findings, AI summary, and blockchain status.

### CI/CD

- `Code_Editor/.github/workflows/security-gate.yml` exists.
- Current workflow runs scanner commands directly and does backend smoke test.
- It does not yet execute one strict backend pipeline endpoint.

---

## 4. Gap vs New Requirements

### Already available

- Semgrep + Snyk structured scanners
- AI analysis service
- ML predictor
- YAML policy engine
- Blockchain logging
- Dashboard wiring

### Gaps to close

- Orchestration is still mixed in routes instead of a pipeline module.
- Feature engineering is embedded ad hoc in route logic.
- Canonical `PRContext` exists, but full orchestrator-wide adoption is still pending.
- Layer 2 is standardized on PR-Agent in active analysis routes; legacy AI module cleanup remains.
- No explicit degraded-mode/error strategy by layer.
- No single canonical persistence record for pipeline output.
- `POST /api/analyze_pr` endpoint exists; GitHub Action is not yet centered on it.

---

## 5. PR Context Object (Canonical Input)

All layers should receive the same `PRContext` object.

```python
from dataclasses import dataclass
from typing import List

@dataclass
class PRContext:
    repo: str
    pr_number: int
    commit_hash: str
    diff: str
    files_changed: List[str]
    lines_added: int
    lines_deleted: int
```

Pipeline call pattern:

- `run_scanners(context)`
- `run_ai(context, scan_results)`
- `build_features(context, scan_results, ai_results)`

---

## 6. Target Architecture (Refactor Direction)

Keep `backend/app` as package root and add dedicated pipeline modules.

```text
backend/
  app/
    main.py
    api/
      routes/
        analyze_pr.py
        analyze.py            # compatibility wrapper (temporary)
        github_analyzer.py    # compatibility wrapper (temporary)
    pipeline/
      orchestrator.py
      scanner_layer/
        base_scanner.py
        semgrep_runner.py
        snyk_runner.py
      ai_layer/
        base_ai_reviewer.py
        pr_agent_adapter.py
      feature_engineering/
        feature_builder.py
      ml_layer/
        risk_model.py
      policy_engine/
        decision_engine.py
      audit_layer/
        blockchain_logger.py
    services/
      github_service.py
      pr_data_fetcher.py
      # external integrations only
    models/
      pipeline_contracts.py
      feature_schema.py
      risk_output.py
```

Boundary rule:

- `pipeline/*` contains orchestration and layer logic only.
- `services/*` contains external integrations only (CLI/API/chain/DB clients).
- Pipeline layers use interface/adapters, not direct service-specific logic spread across routes.

---

## 7. Canonical Pipeline Contracts

### Layer 1 output

```json
{
  "semgrep_issues": [],
  "snyk_vulnerabilities": []
}
```

### Layer 2 output

```json
{
  "ai_security_flags": [],
  "ai_code_smells": [],
  "ai_summary": ""
}
```

### Layer 3 output

```json
{
  "files_changed": 0,
  "lines_added": 0,
  "lines_deleted": 0,
  "semgrep_issue_count": 0,
  "snyk_vulnerability_count": 0,
  "ai_issue_count": 0,
  "ai_security_flag_count": 0
}
```

### Layer 4 output

```json
{
  "risk_score": 0.0,
  "risk_level": "LOW"
}
```

Constraint: `risk_level` must be one of `LOW | MEDIUM | HIGH`.

### Layer 5 output

```json
{
  "verdict": "APPROVE",
  "action": "AUTO_APPROVE",
  "reason": "Risk LOW"
}
```

### Layer 6 output

```json
{
  "commit_hash": "",
  "risk_score": 0.0,
  "verdict": "",
  "timestamp": "",
  "tx_hash": "",
  "record_hash": "",
  "status": "confirmed"
}
```

---

## 8. ML Layer Specification

### 8.1 Prediction Target

The ML layer predicts PR security risk as:

- `risk_score` in range `0.0 -> 1.0`
- `risk_level` in classes: `LOW | MEDIUM | HIGH`

Example:

```json
{
  "risk_score": 0.82,
  "risk_level": "HIGH"
}
```

### 8.2 Input Source (No Raw Code in ML)

The ML model must not read code directly.
It only consumes structured outputs from previous layers:

- Layer 1: Semgrep + Snyk results
- Layer 2: PR-Agent results
- Layer 3: engineered PR metadata features

### 8.3 Feature Vector Schema (Exact)

Each PR is one feature row.

| Feature | Meaning |
|---|---|
| `files_changed` | Number of files modified |
| `lines_added` | Lines added |
| `lines_deleted` | Lines deleted |
| `semgrep_issue_count` | Total Semgrep findings |
| `semgrep_high_severity` | High/Critical Semgrep findings |
| `snyk_vulnerability_count` | Total Snyk dependency vulnerabilities |
| `snyk_high_severity` | High/Critical Snyk vulnerabilities |
| `ai_issue_count` | Total AI findings |
| `ai_security_flags` | AI security issue count |
| `ai_code_smell_count` | AI code quality smell count |

Example feature row:

```json
{
  "files_changed": 6,
  "lines_added": 230,
  "lines_deleted": 40,
  "semgrep_issue_count": 2,
  "semgrep_high_severity": 1,
  "snyk_vulnerability_count": 1,
  "snyk_high_severity": 0,
  "ai_issue_count": 1,
  "ai_security_flags": 1,
  "ai_code_smell_count": 2,
  "risk_level": "HIGH"
}
```

### 8.4 Dataset Structure and Size

Dataset format: tabular CSV (`ml-model/data/security_pr_dataset.csv`)

Header:

```csv
files_changed,lines_added,lines_deleted,semgrep_issue_count,semgrep_high_severity,snyk_vulnerability_count,snyk_high_severity,ai_issue_count,ai_security_flags,ai_code_smell_count,risk_level
```

Sample rows:

```csv
2,45,10,0,0,0,0,0,0,1,LOW
4,120,20,1,0,0,0,1,0,2,MEDIUM
8,300,50,3,1,2,1,2,1,3,HIGH
1,10,5,0,0,0,0,0,0,0,LOW
6,200,60,2,1,1,0,1,1,2,HIGH
```

Recommended size:

- initial: `300-1000` rows (sufficient for XGBoost baseline)

### 8.5 Scenario Coverage Required in Dataset

Dataset generation must include realistic patterns:

- Code vulnerabilities: SQL injection, XSS, insecure input validation, hardcoded secrets, weak crypto
- Dependency vulnerabilities: outdated/CVE-affected packages
- Code quality risks: poor error handling, large risky changes, bad practices
- Risky PR characteristics: very large PRs, many files changed

### 8.6 Synthetic Labeling Logic (Bootstrapping)

Risk label generation rules for synthetic dataset:

- `LOW`: small PR + no scanner/AI security issues
- `MEDIUM`: moderate PR + limited findings/warnings
- `HIGH`: large PR and/or multiple high-severity scanner/AI security findings

This labeling logic is only for initial bootstrapping; production should transition to outcome-based labels.

### 8.7 Training Pipeline

Model: `XGBoost` multiclass classifier (`LOW | MEDIUM | HIGH`)

Training flow:

1. Load CSV dataset
2. Split into `X` (features) and `y` (`risk_level`)
3. Train/test split
4. Train model
5. Evaluate and persist model artifact

Reference training shape:

```python
import pandas as pd
from xgboost import XGBClassifier
from sklearn.model_selection import train_test_split

data = pd.read_csv("security_pr_dataset.csv")
X = data.drop("risk_level", axis=1)
y = data["risk_level"]

X_train, X_test, y_train, y_test = train_test_split(X, y)

model = XGBClassifier()
model.fit(X_train, y_train)
model.save_model("risk_model.json")
```

### 8.8 Runtime Inference in Pipeline

Runtime order:

`PR -> scanners -> AI review -> feature engineering -> ML prediction`

Prediction output:

```json
{
  "risk_score": 0.73,
  "risk_level": "HIGH"
}
```

---

## 9. Layer-2 AI Integration (PR-Agent)

### 9.1 Objective

Integrate open-source `PR-Agent` as Layer-2 AI analysis.

Layer-2 responsibilities only:

- analyze PR diff
- identify potential bugs/security concerns
- provide summary

It does not perform:

- ML risk scoring
- policy decisions
- blockchain auditing

### 9.2 Installation

Install CLI:

```bash
pip install pr-agent
```

or:

```bash
pip install git+https://github.com/qodo-ai/pr-agent.git
```

Verify:

```bash
pr-agent --help
```

### 9.3 LLM Provider Configuration

Set provider credentials (example OpenAI):

```bash
export OPENAI_API_KEY="your_key_here"
```

Supported providers (via PR-Agent):

- OpenAI
- Anthropic
- Azure OpenAI
- local/API-compatible providers

Runtime path note:

- If `pr-agent` is not available on system `PATH`, set:

```bash
export PR_AGENT_BINARY="/absolute/path/to/pr-agent"
```

- Backend adapter fallback order:
1. `PR_AGENT_BINARY` (if set)
2. `pr-agent` from `PATH`
3. `python -m pr_agent.cli` (module fallback in active backend interpreter)

### 9.4 Adapter Module

Create adapter:

`backend/app/pipeline/ai_layer/pr_agent_adapter.py`

Adapter responsibilities:

1. Receive `PRContext`
2. Read `diff` from context
3. Invoke PR-Agent CLI
4. Capture stdout/stderr
5. Map output to Layer-2 contract JSON

### 9.5 PR-Agent Contract Mapping

Required Layer-2 return format:

```json
{
  "ai_security_flags": [],
  "ai_code_smells": [],
  "ai_summary": ""
}
```

Example:

```json
{
  "ai_security_flags": ["possible SQL injection"],
  "ai_code_smells": ["large function"],
  "ai_summary": "PR introduces database query without input sanitization."
}
```

### 9.6 Orchestrator Integration

In orchestrator:

```python
ai_results = ai_reviewer.analyze_pr(pr_context, scan_results)
```

`ai_results` must flow directly into feature engineering.

### 9.7 Feature Engineering Usage

Minimum derived AI features:

- `ai_issue_count = len(ai_results["ai_security_flags"])`
- `ai_code_smell_count = len(ai_results["ai_code_smells"])`

These join scanner and PR metadata features for ML input.

### 9.8 Failure Behavior

If PR-Agent fails, fallback to empty AI output and continue pipeline:

```json
{
  "ai_security_flags": [],
  "ai_code_smells": [],
  "ai_summary": ""
}
```

### 9.9 Adapter Test Case

Sample diff for adapter validation:

```diff
diff --git a/app.py b/app.py
+ query = "SELECT * FROM users WHERE id=" + user_id
```

Expected Layer-2 behavior:

- includes SQL injection-style flag in `ai_security_flags`
- non-empty `ai_summary`

### 9.10 Design Constraint

PR-Agent is signal provider only:

- AI layer -> insights
- ML layer -> risk scoring
- Policy layer -> decision
- Blockchain layer -> audit

---

## 10. ML Model Training Source

- Initial model: synthetic PR security dataset built from scanner + AI + PR metadata feature patterns.
- Future model versions: trained/retrained using historical real PR outcomes (approved/manual_review/blocked and post-merge security outcomes) for calibration.
- Model artifact and metadata should be versioned (`model_version`, training date, feature schema version).

---

## 11. Orchestrator Contract

`run_security_pipeline(context: PRContext) -> PipelineResult`

Strict order:

1. `scan_results = run_scanners(context)`
2. `ai_results = run_ai_with_pr_agent(context, scan_results)`
3. `features = build_features(context, scan_results, ai_results)`
4. `risk = predict_risk(features)`  # ML risk layer
5. `decision = apply_policy(risk, scan_results, ai_results)`
6. `audit = log_to_blockchain(context.commit_hash, risk, decision)`
7. `persist + return`

---

## 12. Error Handling Strategy

Pipeline should support `completed_degraded` mode.

Rules:

- Semgrep/Snyk failure: continue pipeline, mark layer status as `failed`, set `degraded=true`, and continue with available scanner signals.
- PR-Agent failure: continue with scanner-only feature/risk path; set AI layer status `failed` and apply empty AI fallback payload.
- ML prediction failure: use deterministic fallback heuristic model and mark `ml_fallback=true`.
- Policy evaluation failure: default to `MANUAL_REVIEW` (safe fallback).
- Blockchain failure: do not block verdict; store record as `pending_audit` and retry async.

Response should include:

- `pipeline_status`: `completed | completed_degraded | failed`
- `layer_status`: per-layer status map
- `errors`: normalized list of non-fatal and fatal errors

---

## 13. State Persistence

Canonical persistence record for dashboard/API:

`PRAnalysis`

Fields:

- `pr_id`
- `repo`
- `pr_number`
- `commit_hash`
- `risk_score`
- `risk_level`
- `decision`
- `pipeline_status`
- `timestamp`
- `blockchain_tx`
- `record_hash`

Layer payloads should also be stored as JSON for traceability:

- `scan_results_json`
- `ai_results_json`
- `feature_vector_json`

---

## 14. API Changes

### New primary endpoint

- `POST /api/analyze_pr`
- Status: implemented as alias to existing analyze submission flow in `backend/app/api/routes/analyze.py`.

Request:

```json
{
  "repo": "owner/repo",
  "pr_number": 123,
  "pr_id": 123
}
```

Response (top-level):

```json
{
  "pr_id": 123,
  "status": "completed",
  "pipeline_status": "completed",
  "scan_results": {},
  "ai_results": {},
  "features": {},
  "risk": {},
  "decision": {},
  "audit": {},
  "layer_status": {}
}
```

Compatibility:

- Keep current `/api/analyze` and `/api/analyze_github` temporarily.
- Internally route them to orchestrator where possible.

---

## 15. GitHub Actions Plan (`security-gate.yml`)

Workflow should:

1. Trigger on `pull_request` (`opened`, `synchronize`, `reopened`).
2. Send PR context to backend `POST /api/analyze_pr`.
3. Gate result by `decision.action`:
   - `AUTO_APPROVE` -> success
   - `MANUAL_REVIEW` -> check requiring manual intervention
   - `BLOCK` -> fail status check
4. Upload per-layer JSON artifacts.
5. Post PR comment with risk, verdict, scanner summary, AI summary, and blockchain state.

---

## 16. Frontend/Dashboard Plan

No major UI redesign required. Keep current pages and remap data source to new pipeline response.

Dashboard must show:

- PR list
- risk score and risk level
- Semgrep/Snyk findings
- AI summary and flags
- blockchain audit status

---

## 17. Ownership Note

- Aditya owns Layer 1 scanner implementation/refactor (`snyk_runner.py`, `semgrep_runner.py`, scanner contracts).
- Arjun owns all remaining layers and integrations (PR-Agent adapter, feature engineering, ML, policy, blockchain, orchestrator, API, CI, dashboard mapping).

---

## 18. Definition of Done

- Single orchestrator runs all six layers in fixed order using `PRContext`.
- Layer outputs and feature schema are explicit and validated.
- Error strategy supports degraded execution for non-fatal layer failures.
- ML layer has documented dataset format, feature schema, and training/inference pipeline.
- Layer-2 AI analysis uses PR-Agent adapter and returns contract-compliant output.
- `POST /api/analyze_pr` is the canonical CI entrypoint.
- Policy decision gates PR checks in GitHub Actions.
- Pipeline results persist as `PRAnalysis` records for dashboard/API use.
- Dashboard consumes new pipeline outputs without hardcoded layer logic.

---

## 19. Immediate Next Instruction Expected

Layer-2 implementation is already in code:
- `backend/app/models/pipeline_contracts.py` (`PRContext`)
- `backend/app/pipeline/ai_layer/pr_agent_adapter.py`
- route integration in:
  - `backend/app/api/routes/analyze.py`
  - `backend/app/api/routes/github_analyzer.py`

Next implementation priority:
1. Create canonical `orchestrator.py` with strict six-layer flow.
2. Wire GitHub Actions to `POST /api/analyze_pr` as canonical CI entrypoint.
3. Move feature engineering into dedicated module.
4. Normalize pipeline/layer status + degraded mode in a single response contract.
