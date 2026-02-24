const hre = require("hardhat");

async function main() {
  const contractAddress = process.env.BLOCKCHAIN_CONTRACT_ADDRESS;
  if (!contractAddress) {
    throw new Error("BLOCKCHAIN_CONTRACT_ADDRESS is required");
  }

  const auditLog = await hre.ethers.getContractAt("AuditLog", contractAddress);

  const commitHash = process.env.TEST_COMMIT_HASH || "demo-commit-hash";
  const riskScore = Number(process.env.TEST_RISK_SCORE || 42);
  const verdict = process.env.TEST_VERDICT || "MANUAL_REVIEW";

  const recordId = hre.ethers.keccak256(
    hre.ethers.toUtf8Bytes(`${Date.now()}:${commitHash}:${riskScore}:${verdict}`)
  );

  const tx = await auditLog.addLog(recordId, commitHash, riskScore, verdict);
  const receipt = await tx.wait();

  console.log("Record ID:", recordId);
  console.log("Transaction Hash:", receipt.hash);

  const stored = await auditLog.getLog(recordId);
  console.log("Stored verdict:", stored.verdict);
}

main().catch((error) => {
  console.error(error);
  process.exitCode = 1;
});
