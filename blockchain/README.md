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

# Interact with deployed contract
BLOCKCHAIN_CONTRACT_ADDRESS=0x... npx hardhat run scripts/interact.js --network sepolia
```

## Contract Functions
- `addLog(recordId, commit, risk, verdict)` - Log a PR decision
- `getLog(recordId)` - Retrieve audit record
- `verifyLog(recordId)` - Verify integrity

## Testnet
- Network: Sepolia
- Explorer: https://sepolia.etherscan.io
- Faucet: https://sepoliafaucet.com
