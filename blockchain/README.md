# Blockchain - Solidity Audit Trail

## Overview
Smart contract on Sepolia testnet that logs every PR analysis decision immutably.

## Structure
```
blockchain/
├── contracts/
│   └── AuditLog.sol        # Main smart contract
├── scripts/
│   ├── deploy.js           # Deployment script
│   └── interact.js         # Test interactions
├── test/
│   └── AuditLog.test.js    # Contract tests
├── hardhat.config.js
├── package.json
└── README.md
```

## Setup

```bash
# Install dependencies
npm install

# Compile contracts
npx hardhat compile

# Run tests
npx hardhat test

# Deploy to Sepolia
npx hardhat run scripts/deploy.js --network sepolia
```

## Contract Functions
- `addLog(commit, risk, verdict)` - Log a PR decision
- `getLog(txId)` - Retrieve audit record
- `verifyLog(txId)` - Verify integrity

## Testnet
- Network: Sepolia
- Explorer: https://sepolia.etherscan.io
- Faucet: https://sepoliafaucet.com

## Owner
**Aditya** - Primary developer
