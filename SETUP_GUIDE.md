# 🚀 Setup Guide for Teammates

## Quick Start (For Team Members)

This guide will help you set up the entire project on your local machine.

---
# Backend
cd backend
pip install -r requirements.txt
pip install semgrep

# Frontend  
cd frontend
npm install

# Blockchain
cd blockchain
npm install

## ✅ All Dependency Files Are Ready!

- ✅ `backend/requirements.txt` - Python packages
- ✅ `frontend/package.json` - React packages  
- ✅ `blockchain/package.json` - Hardhat packages
- ✅ `docker-compose.yml` - Docker setup

---

## 📋 Prerequisites

Install these on your machine:

1. **Python 3.11+**
   - Download: https://www.python.org/downloads/
   - Verify: `python --version`

2. **Node.js 18+**
   - Download: https://nodejs.org/
   - Verify: `node --version`

3. **Git**
   - Download: https://git-scm.com/
   - Verify: `git --version`

4. **Docker Desktop** (Optional, for containerized setup)
   - Download: https://www.docker.com/products/docker-desktop/

---

## 🔧 Installation Steps

### 1️⃣ Clone the Repository

```bash
git clone <repository-url>
cd Code_Editor
```

### 2️⃣ Backend Setup (Python)

```bash
cd backend

# Create virtual environment (recommended)
python -m venv venv

# Activate virtual environment
# Windows:
venv\Scripts\activate
# Mac/Linux:
source venv/bin/activate

# Install all dependencies from requirements.txt
pip install -r requirements.txt

# Install security scanners
pip install semgrep
npm install -g snyk

# Create .env file (copy from example)
copy .env.example .env
# Then edit .env and add your API keys

# Verify installation
python -c "import fastapi, langchain, sklearn, xgboost, web3; print('✅ Backend packages installed')"
```

### 3️⃣ Frontend Setup (React + Vite)

```bash
cd ../frontend

# Install all dependencies from package.json
npm install

# Verify installation
npm list --depth=0

# Start development server (to test)
npm run dev
```

### 4️⃣ Blockchain Setup (Hardhat)

```bash
cd ../blockchain

# Install all dependencies from package.json
npm install

# Create .env file for blockchain (if needed)
# Add your private keys and RPC URLs

# Compile smart contracts (to test)
npx hardhat compile
```

---

## 🐳 Alternative: Docker Setup (Easiest)

If you have Docker Desktop installed:

```bash
# From the Code_Editor root directory
docker-compose up --build

# This will:
# ✅ Install all backend dependencies
# ✅ Start the FastAPI backend on port 8000
# ✅ Set up PostgreSQL database
```

---

## 🔑 Environment Variables

### Backend (.env)

Create `backend/.env` with:

```env
# API Keys
CLAUDE_API_KEY=your_claude_api_key_here
SNYK_TOKEN=your_snyk_token_here
GITHUB_TOKEN=your_github_token_here

# Blockchain
BLOCKCHAIN_PRIVATE_KEY=your_private_key_here
BLOCKCHAIN_CONTRACT_ADDRESS=0x...
SEPOLIA_RPC_URL=https://sepolia.infura.io/v3/YOUR_PROJECT_ID

# Database
DATABASE_URL=sqlite:///./security_gate.db

# Debug
DEBUG=True
```

### Get API Keys:

- **Claude API**: https://console.anthropic.com/
- **Snyk**: https://snyk.io/ (free for open source)
- **GitHub Token**: https://github.com/settings/tokens
- **Infura/Alchemy**: https://infura.io/ or https://www.alchemy.com/

---

## 📦 Package Counts (Reference)

- **Backend**: 20+ Python packages
- **Frontend**: 228 npm packages
- **Blockchain**: 343 npm packages

---

## 🧪 Verify Installation

Run these commands to verify everything is installed:

### Backend
```bash
cd backend
python -c "import fastapi, langchain, anthropic, sklearn, xgboost, pandas, web3; print('✅ All core packages working')"
```

### Frontend
```bash
cd frontend
npm run dev
# Should start on http://localhost:5173
```

### Blockchain
```bash
cd blockchain
npx hardhat compile
# Should compile successfully
```

---

## 🚀 Running the Project

### Development Mode

**Terminal 1 - Backend:**
```bash
cd backend
python -m uvicorn app.main:app --reload --host 0.0.0.0 --port 8000
```

**Terminal 2 - Frontend:**
```bash
cd frontend
npm run dev
```

**Terminal 3 - Blockchain (when needed):**
```bash
cd blockchain
npx hardhat node  # Local blockchain
```

### Access:
- Backend API: http://localhost:8000
- Frontend: http://localhost:5173
- API Docs: http://localhost:8000/docs

---

## 📝 Common Commands

### Backend
```bash
# Install new package
pip install package-name

# Update requirements.txt
pip freeze > requirements.txt

# Run tests
pytest

# Run with Docker
docker-compose up backend
```

### Frontend
```bash
# Install new package
npm install package-name

# Build for production
npm run build

# Run linter
npm run lint
```

### Blockchain
```bash
# Compile contracts
npx hardhat compile

# Run tests
npx hardhat test

# Deploy to local network
npx hardhat run scripts/deploy.js

# Deploy to Sepolia testnet
npx hardhat run scripts/deploy.js --network sepolia
```

---

## 🆘 Troubleshooting

### Python packages not found
```bash
# Make sure virtual environment is activated
# Windows:
venv\Scripts\activate
# Mac/Linux:
source venv/bin/activate

# Reinstall requirements
pip install -r requirements.txt
```

### npm install fails
```bash
# Clear npm cache
npm cache clean --force

# Delete node_modules and reinstall
rm -rf node_modules package-lock.json
npm install
```

### Port already in use
```bash
# Backend (default 8000)
python -m uvicorn app.main:app --port 8001

# Frontend (default 5173)
npm run dev -- --port 3000
```

### Docker issues
```bash
# Rebuild containers
docker-compose down
docker-compose up --build

# Clear everything
docker-compose down -v
docker system prune -a
```

---

## 📚 Project Structure

```
Code_Editor/
├── backend/                 # FastAPI backend
│   ├── requirements.txt    ← Install: pip install -r requirements.txt
│   ├── .env.example
│   └── app/
├── frontend/               # React + Vite frontend
│   ├── package.json       ← Install: npm install
│   └── src/
├── blockchain/            # Hardhat + Solidity
│   ├── package.json      ← Install: npm install
│   └── contracts/
├── ml-model/             # ML training scripts
├── docs/                 # Documentation
└── docker-compose.yml    ← Install: docker-compose up
```

---

## 🤝 Contributing

1. Create a new branch
2. Make changes
3. Test locally
4. Commit with clear messages
5. Push and create PR

---

## 📞 Need Help?

- Check documentation in `/docs`
- Review [IMPLEMENTATION_PLAN.md](./IMPLEMENTATION_PLAN.md)
- Ask the team lead

---

**Last Updated**: January 26, 2026  
**All dependency files verified and ready!** ✅
