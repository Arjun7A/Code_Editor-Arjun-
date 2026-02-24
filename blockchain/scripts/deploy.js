const hre = require("hardhat");

async function main() {
  const AuditLog = await hre.ethers.getContractFactory("AuditLog");
  const auditLog = await AuditLog.deploy();
  await auditLog.waitForDeployment();

  const address = await auditLog.getAddress();
  console.log("AuditLog deployed to:", address);
}

main().catch((error) => {
  console.error(error);
  process.exitCode = 1;
});
