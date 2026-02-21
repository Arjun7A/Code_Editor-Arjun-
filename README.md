# 🛡️ Security Gate - Automated Secure Release Governance

**AI-Driven PR Analysis System with ML Risk Modeling & Blockchain Audit Trail**

---

## 🎯 Project Overview

Automated DevSecOps security gate that analyzes every GitHub Pull Request using:
- 🤖 **AI Semantic Analysis** (LangChain + Claude API)
- 📊 **ML Risk Prediction** (XGBoost)
- 🔍 **Security Scanning** (Snyk + Semgrep)
- ⛓️ **Blockchain Audit Logging** (Solidity + Polygon Amoy Testnet)

**Goal**: Catch security vulnerabilities before they reach production.

---

## 📁 Project Structure

```
Security-Gate/
├── backend/               # FastAPI backend + orchestration
├── frontend/              # React + Vite dashboard
├── ml-model/              # XGBoost risk prediction model
├── blockchain/            # Hardhat + Solidity contracts
├── .github/workflows/     # GitHub Actions CI/CD
├── docs/                  # Documentation
└── scripts/               # Utility scripts
```

---

## 👥 Team & Branch Structure

### Main Branches
- `main` - Production-ready code (protected)
- `dev` - Integration branch (daily merges)

### Personal Branches
- `arjun` - Personal development branch
- `kunal` - Personal development branch
- `aditya` - Personal development branch

---

## 🚀 Quick Start

### Prerequisites
- Python 3.11+
- Node.js 18+
- Docker Desktop
- Git

### Setup
```bash
# Clone repository
git clone https://github.com/KunalSiyag/Code_Editor.git
cd Code_Editor

# Switch to dev branch for development
git checkout dev

# Backend setup
cd backend
python -m venv venv
source venv/bin/activate  # Windows: venv\Scripts\activate
pip install -r requirements.txt

# Frontend setup
cd ../frontend
npm install

# Blockchain setup
cd ../blockchain
npm install
```

---

## 🔄 Development Workflow

```bash
# Morning: Pull latest changes
git checkout <your-name>
git pull origin dev

# Work on your features
git add .
git commit -m "Descriptive message"
git push origin <your-name>

# End of day: Merge to dev
git checkout dev
git pull origin dev
git merge <your-name>
git push origin dev
```

---

## 🏗️ Tech Stack

**Backend**: FastAPI, Python, SQLAlchemy, Docker  
**Frontend**: React, Vite, TailwindCSS, Recharts  
**ML**: Scikit-learn, XGBoost, Pandas  
**AI**: LangChain, Claude API  
**Security**: Snyk CLI, Semgrep  
**Blockchain**: Hardhat, Solidity, Ethers.js, Polygon Amoy  
**CI/CD**: GitHub Actions  
**Deploy**: Render (backend), Vercel (frontend)

---

## 📅 Timeline

**Start Date**: January 26, 2026  
**Duration**: 8 weeks  
**Demo Date**: March 22, 2026

See [IMPLEMENTATION_PLAN.md](../IMPLEMENTATION_PLAN.md) for detailed week-by-week breakdown.

---

## 🎓 Capstone Project

**Course**: DevSecOps & Secure Software Development  
**Institution**: [Your University]  
**Year**: 2026

---

## 📝 License

This project is for educational purposes.

---

## 🤝 Contributors

- **Arjun** 
- **Kunal** 
- **Aditya** 

---

**Last Updated**: January 26, 2026
