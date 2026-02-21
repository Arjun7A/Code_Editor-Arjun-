# 🚀 8-Week Implementation Plan
## Capstone: Automated Secure Release Governance

**Timeline**: January 26 - March 22, 2026 (8 weeks)  
**Strategy**: MVP-first approach, parallel workstreams where possible

---

## 🎯 Phase 1: Foundation & Infrastructure (Week 1-2)

### Week 1: Project Setup & Backend Foundation
**Goal**: Get basic infrastructure running

#### Days 1-2: Repository & Environment Setup
- [x] Create GitHub repository structure
  ```
  /backend (FastAPI)
  /frontend (React + Vite)
  /ml-model (XGBoost training)
  /blockchain (Hardhat + Solidity)
  /scripts (utilities)
  /.github/workflows (CI/CD)
  ```
- [x] Initialize backend with FastAPI
  - Basic project structure
  - Docker setup (Dockerfile + docker-compose)
  - Requirements.txt with core dependencies
  - Health check endpoint
- [x] Setup local development environment
  - Python 3.11+ virtual environment
  - Node.js 18+
  - Docker Desktop
  - Git hooks (pre-commit)

#### Days 3-4: Database & Core API Structure
- [ ] Setup SQLite/PostgreSQL for storing PR analysis results
- [ ] Create data models:
  - PullRequest (id, repo, pr_number, status, risk_score, timestamp)
  - ScanResult (pr_id, tool, findings, severity)
  - AuditLog (pr_id, decision, blockchain_hash)
- [ ] Build core FastAPI endpoints:
  - `POST /api/analyze` - Main analysis endpoint
  - `GET /api/results/{pr_id}` - Fetch results
  - `GET /api/health` - Health check

#### Days 5-7: Security Scanner Integration
- [ ] Integrate Snyk CLI
  - Install and configure Snyk
  - Create scanner wrapper function
  - Parse JSON output into structured format
- [ ] Integrate Semgrep
  - Setup custom rule config
  - Create scanner wrapper
  - Parse SARIF/JSON output
- [ ] Create unified scan orchestrator
- [ ] Test with sample vulnerable code

**Deliverable**: Dockerized FastAPI backend that can scan code with Snyk + Semgrep

---

### Week 2: Frontend Foundation & ML Preparation

#### Days 8-10: React Dashboard Setup
- [ ] Initialize Vite + React project
- [ ] Setup routing (React Router)
- [ ] Create basic layout:
  - Header/Nav
  - Dashboard page
  - PR Details page
  - Audit Log page
- [ ] Setup state management (Zustand/Context)
- [ ] Configure Tailwind CSS / Material-UI
- [ ] Create mock data for UI development

#### Days 11-14: ML Model Data Collection & Training
- [ ] **Critical**: Collect training data
  - Scrape GitHub PR metadata (use GitHub API)
  - Target repos: tensorflow, kubernetes, react, etc.
  - Aim for 500-1000 PRs minimum
  - Extract 12 features:
    - files_changed, lines_added/deleted
    - commit_count, author_reputation
    - time_of_day, day_of_week
    - Has_test_changes, etc.
- [ ] Label data (high/medium/low risk based on:
  - Security-related keywords in commits
  - CVE references
  - Files touched (auth, crypto, network)
- [ ] Train baseline XGBoost model
  - 80/20 train/test split
  - Optimize hyperparameters
  - Save model as .pkl file
- [ ] Create feature engineering pipeline
- [ ] Build model API endpoint: `POST /api/predict_risk`

**Deliverable**: Working React dashboard + Trained ML model with 70%+ accuracy

---

## 🔥 Phase 2: Core Intelligence (Week 3-4)

### Week 3: AI Agent Integration

#### Days 15-17: LangChain Setup
- [ ] Get Claude API key (Anthropic)
- [ ] Setup LangChain with Claude
- [ ] Create prompt templates:
  ```
  System: "You are a security engineer..."
  User: "Analyze this code for vulnerabilities: {code}"
  ```
- [ ] Build agent chain:
  - Code chunker (split large PRs)
  - Parallel analysis
  - Result aggregator
- [ ] Implement retry logic & error handling
- [ ] Add streaming for large files

#### Days 18-21: Policy Engine
- [ ] Create YAML policy schema:
  ```yaml
  rules:
    - name: "Critical vulnerabilities block"
      condition: "severity == 'critical'"
      action: "BLOCK"
    - name: "High risk needs review"
      condition: "risk_score > 0.8"
      action: "MANUAL_REVIEW"
  ```
- [ ] Build policy parser
- [ ] Implement decision engine:
  - Aggregate signals: AI findings + ML score + scan results
  - Apply policy rules
  - Generate verdict: AUTO_APPROVE | MANUAL_REVIEW | BLOCK
- [ ] Create override mechanism (manual approval)

**Deliverable**: End-to-end analysis pipeline (Scan → AI → ML → Policy → Decision)

---

### Week 4: Blockchain Integration

#### Days 22-24: Smart Contract Development
- [ ] Initialize Hardhat project
- [ ] Write Solidity contract:
  ```solidity
  contract AuditLog {
      struct Record {
          string commit;
          uint risk;
          string verdict;
          uint256 timestamp;
      }
      mapping(bytes32 => Record) public logs;
      event AuditLogged(bytes32 txId, uint risk, string verdict);
      
      function addLog(...) external { }
  }
  ```
- [ ] Write tests (Hardhat/Chai)
- [ ] Deploy to Sepolia testnet
- [ ] Get testnet ETH from faucet

#### Days 25-28: Backend-Blockchain Connection
- [ ] Install web3.py / ethers.js
- [ ] Create blockchain service layer
- [ ] Implement functions:
  - `log_to_blockchain(pr_id, risk, verdict)`
  - `verify_audit_trail(pr_id)`
- [ ] Add blockchain transaction to analysis flow
- [ ] Handle async blockchain writes (don't block API)
- [ ] Create retry logic for failed transactions

**Deliverable**: Working blockchain audit logging

---

## 💎 Phase 3: Integration & Polish (Week 5-6)

### Week 5: Full System Integration

#### Days 29-31: Connect Frontend to Backend
- [ ] Implement API client (Axios)
- [ ] Build dashboard components:
  - PR risk chart (recharts/chart.js)
  - Status badges
  - Risk score gauge
  - Recent PRs list
- [ ] Create PR detail view:
  - Code diff viewer
  - AI findings panel
  - ML feature breakdown
  - Scanner results table
- [ ] Add blockchain explorer link

#### Days 32-35: GitHub Actions Pipeline
- [ ] Create `.github/workflows/security-gate.yml`
  ```yaml
  on: pull_request
  jobs:
    security-scan:
      - Checkout code
      - Run Snyk
      - Run Semgrep
      - Docker build
      - Call FastAPI /analyze endpoint
      - Post results as PR comment
      - Block merge if verdict = BLOCK
  ```
- [ ] Setup GitHub App / webhook (alternative)
- [ ] Configure secrets (API keys, private key)
- [ ] Test with dummy PRs

**Deliverable**: Fully automated PR analysis triggered by GitHub Actions

---

### Week 6: Testing & Refinement

#### Days 36-38: Testing
- [ ] Unit tests (backend - pytest)
  - Scanner modules
  - ML prediction
  - Policy engine
- [ ] Integration tests
  - Full analysis flow
  - Blockchain logging
- [ ] Frontend tests (Vitest/Jest)
- [ ] Load testing (simulate 10 concurrent PRs)

#### Days 39-42: Performance Optimization
- [ ] Cache ML model in memory
- [ ] Parallelize scanner execution
- [ ] Optimize LangChain token usage
- [ ] Add Redis caching for repeated analyses
- [ ] Optimize Docker image size
- [ ] Database indexing

**Deliverable**: Stable system with <60s analysis time

---

## 🎨 Phase 4: Deployment & Demo (Week 7-8)

### Week 7: Deployment

#### Days 43-45: Backend Deployment (Render)
- [ ] Create Render account
- [ ] Configure Dockerfile for production
- [ ] Deploy FastAPI backend
- [ ] Setup environment variables
- [ ] Configure PostgreSQL database
- [ ] Test deployed API

#### Days 46-49: Frontend Deployment (Vercel)
- [ ] Create Vercel account
- [ ] Configure build settings
- [ ] Deploy React app
- [ ] Connect to backend API
- [ ] Setup custom domain (optional)
- [ ] Test production frontend

---

### Week 8: Demo Preparation & Documentation

#### Days 50-52: Demo Setup
- [ ] Create vulnerable test repository
- [ ] Record demo scenarios:
  1. Low-risk PR → AUTO_APPROVE
  2. Medium-risk PR → MANUAL_REVIEW (with AI suggestions)
  3. High-risk PR → BLOCKED (SQL injection detected)
- [ ] Create demo script (5 minutes)
- [ ] Polish dashboard UI

#### Days 53-56: Documentation & Final Polish
- [ ] Write comprehensive README.md
  - Architecture diagram
  - Setup instructions
  - API documentation
- [ ] Create presentation slides
  - Problem statement
  - Architecture
  - Technical implementation
  - Results & metrics
  - Live demo
- [ ] Record backup demo video (in case live fails)
- [ ] Final testing on fresh PRs
- [ ] Buffer for last-minute issues

**Deliverable**: Production-ready system + Polished demo + Documentation

---

## 🎯 Priority Matrix (If Time Runs Short)

### Must-Have (MVP)
✅ Snyk + Semgrep scanning  
✅ Basic LangChain AI analysis  
✅ ML risk scoring (even if 70% accuracy)  
✅ Policy engine with hardcoded rules  
✅ Simple React dashboard  
✅ GitHub Actions trigger  
✅ Basic blockchain logging  

### Should-Have
⚡ Advanced AI prompting  
⚡ YAML-based policy config  
⚡ Real-time dashboard updates  
⚡ Comprehensive test coverage  

### Nice-to-Have (Cut if needed)
🌟 Redis caching  
🌟 Custom Semgrep rules  
🌟 Historical trend analysis  
🌟 Multi-repo support  

---

## 📦 Tech Stack Checklist

### Backend
- [ ] FastAPI
- [ ] Python 3.11+
- [ ] LangChain + Claude API
- [ ] Scikit-learn / XGBoost
- [ ] Snyk CLI
- [ ] Semgrep
- [ ] SQLAlchemy
- [ ] Web3.py
- [ ] Docker

### Frontend
- [ ] React 18
- [ ] Vite
- [ ] TailwindCSS / Material-UI
- [ ] Recharts (charts)
- [ ] Axios

### Blockchain
- [ ] Hardhat
- [ ] Solidity
- [ ] Ethers.js
- [ ] Sepolia testnet

### DevOps
- [ ] GitHub Actions
- [ ] Docker
- [ ] Render (backend)
- [ ] Vercel (frontend)

---

## 🚨 Risk Mitigation

### Week 1-2 Risks
- **Data collection takes too long** → Use pre-labeled dataset (Kaggle, academic)
- **API setup issues** → Start with FastAPI template

### Week 3-4 Risks
- **Claude API rate limits** → Implement exponential backoff, batch requests
- **Blockchain deployment fails** → Use Hardhat local network for demo

### Week 5-6 Risks
- **GitHub Actions permissions** → Use personal repo, enable all permissions
- **Integration bugs** → Add logging at every step

### Week 7-8 Risks
- **Deployment issues** → Test deployment early (Week 6), keep local backup
- **Demo day failures** → Record backup video, have local environment ready

---

## 💡 Pro Tips

1. **Commit daily** - Push progress to GitHub every day
2. **Demo-driven development** - Always keep something working for demos
3. **Parallel work** - Frontend and ML can be done simultaneously
4. **Use mocks** - Don't wait for backend, use mock data in frontend
5. **Document as you go** - Write README sections as you complete features
6. **Test incrementally** - Don't wait until the end
7. **Ask for help early** - Don't spend more than 2 hours stuck

---

## 📊 Success Metrics

By end of Week 8, you should have:
- ✅ Working demo with 3 test cases
- ✅ Deployed production system
- ✅ 10-slide presentation
- ✅ Comprehensive README
- ✅ Risk detection accuracy: 75%+
- ✅ Analysis time: <60 seconds
- ✅ 100+ commits on GitHub
- ✅ Blockchain audit trail with 10+ entries

---

## 🎓 Final Deliverables Checklist

- [ ] GitHub repository (public)
- [ ] Live demo (5 minutes)
- [ ] Presentation slides (PDF)
- [ ] Technical report / README
- [ ] Demo video (backup)
- [ ] Deployed URLs
  - Frontend: https://your-app.vercel.app
  - Backend: https://your-api.onrender.com
  - Blockchain: Sepolia contract address

---

**Remember**: Perfect is the enemy of done. Ship MVP by Week 6, polish in Week 7-8.

Good luck! 🚀
