// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

contract AuditLog {
    struct Record {
        string commitHash;
        uint256 riskScore;
        string verdict;
        uint256 timestamp;
    }

    mapping(bytes32 => Record) private logs;

    event AuditLogged(
        bytes32 indexed recordId,
        string commitHash,
        uint256 riskScore,
        string verdict,
        uint256 timestamp
    );

    function addLog(
        bytes32 recordId,
        string calldata commitHash,
        uint256 riskScore,
        string calldata verdict
    ) external {
        require(bytes(logs[recordId].verdict).length == 0, "Record already exists");

        logs[recordId] = Record({
            commitHash: commitHash,
            riskScore: riskScore,
            verdict: verdict,
            timestamp: block.timestamp
        });

        emit AuditLogged(recordId, commitHash, riskScore, verdict, block.timestamp);
    }

    function getLog(bytes32 recordId) external view returns (Record memory) {
        return logs[recordId];
    }

    function verifyLog(bytes32 recordId) external view returns (bool) {
        return bytes(logs[recordId].verdict).length > 0;
    }
}
