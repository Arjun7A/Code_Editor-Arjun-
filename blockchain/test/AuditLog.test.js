const { expect } = require("chai");
const { ethers } = require("hardhat");

describe("AuditLog", function () {
  async function deployFixture() {
    const AuditLog = await ethers.getContractFactory("AuditLog");
    const contract = await AuditLog.deploy();
    await contract.waitForDeployment();
    return contract;
  }

  it("stores and retrieves records", async function () {
    const contract = await deployFixture();
    const recordId = ethers.keccak256(ethers.toUtf8Bytes("record-1"));

    await contract.addLog(recordId, "abc123", 67, "MANUAL_REVIEW");

    const record = await contract.getLog(recordId);
    expect(record.commitHash).to.equal("abc123");
    expect(record.riskScore).to.equal(67);
    expect(record.verdict).to.equal("MANUAL_REVIEW");
    expect(record.timestamp).to.be.gt(0);

    expect(await contract.verifyLog(recordId)).to.equal(true);
  });

  it("rejects duplicate record ids", async function () {
    const contract = await deployFixture();
    const recordId = ethers.keccak256(ethers.toUtf8Bytes("record-dup"));

    await contract.addLog(recordId, "sha1", 10, "AUTO_APPROVE");

    await expect(
      contract.addLog(recordId, "sha2", 80, "BLOCK")
    ).to.be.revertedWith("Record already exists");
  });
});
