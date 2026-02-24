"""Blockchain service for immutable PR audit logging on Sepolia."""

from __future__ import annotations

import hashlib
import json
import logging
from datetime import datetime, timezone
from typing import Any, Dict, Optional

from app.core.config import settings

logger = logging.getLogger(__name__)

try:
    from web3 import Web3
    from web3.exceptions import TransactionNotFound
except Exception:
    Web3 = None
    TransactionNotFound = Exception


class BlockchainService:
    """Write and verify audit records on a deployed AuditLog Solidity contract."""

    AUDIT_LOG_ABI = [
        {
            "inputs": [
                {"internalType": "bytes32", "name": "recordId", "type": "bytes32"},
                {"internalType": "string", "name": "commitHash", "type": "string"},
                {"internalType": "uint256", "name": "riskScore", "type": "uint256"},
                {"internalType": "string", "name": "verdict", "type": "string"},
            ],
            "name": "addLog",
            "outputs": [],
            "stateMutability": "nonpayable",
            "type": "function",
        },
        {
            "inputs": [{"internalType": "bytes32", "name": "recordId", "type": "bytes32"}],
            "name": "getLog",
            "outputs": [
                {
                    "components": [
                        {"internalType": "string", "name": "commitHash", "type": "string"},
                        {"internalType": "uint256", "name": "riskScore", "type": "uint256"},
                        {"internalType": "string", "name": "verdict", "type": "string"},
                        {"internalType": "uint256", "name": "timestamp", "type": "uint256"},
                    ],
                    "internalType": "struct AuditLog.Record",
                    "name": "",
                    "type": "tuple",
                }
            ],
            "stateMutability": "view",
            "type": "function",
        },
    ]

    def __init__(self):
        self.network = settings.BLOCKCHAIN_NETWORK
        self.rpc_url = settings.SEPOLIA_RPC_URL
        self.contract_address = settings.BLOCKCHAIN_CONTRACT_ADDRESS
        self.private_key = settings.BLOCKCHAIN_PRIVATE_KEY
        self.explorer_tx_base = settings.BLOCKCHAIN_EXPLORER_TX_BASE.rstrip("/") + "/"

        self._enabled = bool(self.rpc_url and self.contract_address and self.private_key)
        self._web3 = None
        self._contract = None
        self._account = None

        if self._enabled:
            self._init_web3()
        else:
            logger.info("Blockchain service disabled (missing rpc/contract/private key).")

    @property
    def enabled(self) -> bool:
        return bool(self._enabled and self._web3 and self._contract and self._account)

    def _init_web3(self) -> None:
        if Web3 is None:
            logger.warning("web3 not available; blockchain service running in simulated mode.")
            self._enabled = False
            return

        try:
            self._web3 = Web3(Web3.HTTPProvider(self.rpc_url, request_kwargs={"timeout": 30}))
            if not self._web3.is_connected():
                logger.warning("Unable to connect to Sepolia RPC; blockchain writes disabled.")
                self._enabled = False
                return

            self._account = self._web3.eth.account.from_key(self.private_key)
            checksum_address = self._web3.to_checksum_address(self.contract_address)
            self._contract = self._web3.eth.contract(address=checksum_address, abi=self.AUDIT_LOG_ABI)
            logger.info("Blockchain service connected to %s (%s)", self.network, checksum_address)

        except Exception as exc:
            logger.exception("Failed to initialize blockchain service: %s", exc)
            self._enabled = False
            self._web3 = None
            self._contract = None
            self._account = None

    @staticmethod
    def _compute_record_hash(
        *,
        pr_id: int,
        commit_hash: str,
        risk_score: float,
        verdict: str,
        timestamp: str,
    ) -> str:
        payload = {
            "pr_id": pr_id,
            "commit_hash": commit_hash,
            "risk_score": round(float(risk_score), 2),
            "verdict": verdict,
            "timestamp": timestamp,
        }
        digest = hashlib.sha256(json.dumps(payload, sort_keys=True).encode("utf-8")).hexdigest()
        return f"0x{digest}"

    def log_decision(
        self,
        *,
        pr_id: int,
        commit_hash: str,
        risk_score: float,
        verdict: str,
        metadata: Optional[Dict[str, Any]] = None,
    ) -> Dict[str, Any]:
        """Write decision to chain if configured; always return a deterministic record hash."""
        now_iso = datetime.now(timezone.utc).isoformat()
        commit = (commit_hash or "unknown")[:120]
        verdict_clean = (verdict or "UNKNOWN")[:32]
        risk_int = int(round(float(risk_score)))

        record_hash = self._compute_record_hash(
            pr_id=pr_id,
            commit_hash=commit,
            risk_score=float(risk_score),
            verdict=verdict_clean,
            timestamp=now_iso,
        )

        if not self.enabled:
            return {
                "status": "simulated",
                "record_hash": record_hash,
                "tx_hash": None,
                "block_number": None,
                "timestamp": now_iso,
                "network": self.network,
                "explorer_url": None,
                "metadata": metadata or {},
            }

        try:
            record_id = self._web3.keccak(text=f"{pr_id}:{record_hash}")
            nonce = self._web3.eth.get_transaction_count(self._account.address)

            transaction = self._contract.functions.addLog(
                record_id,
                commit,
                risk_int,
                verdict_clean,
            ).build_transaction(
                {
                    "from": self._account.address,
                    "nonce": nonce,
                    "gas": 250_000,
                    "gasPrice": self._web3.eth.gas_price,
                    "chainId": self._web3.eth.chain_id,
                }
            )

            signed = self._web3.eth.account.sign_transaction(transaction, self.private_key)
            tx_hash_obj = self._web3.eth.send_raw_transaction(signed.raw_transaction)
            receipt = self._web3.eth.wait_for_transaction_receipt(tx_hash_obj, timeout=120)
            tx_hash = tx_hash_obj.hex()

            return {
                "status": "confirmed" if int(receipt.status) == 1 else "failed",
                "record_hash": record_hash,
                "tx_hash": tx_hash,
                "block_number": int(receipt.blockNumber),
                "timestamp": now_iso,
                "network": self.network,
                "explorer_url": f"{self.explorer_tx_base}{tx_hash}",
                "metadata": metadata or {},
            }

        except Exception as exc:
            logger.exception("On-chain audit logging failed for PR %s: %s", pr_id, exc)
            return {
                "status": "failed",
                "record_hash": record_hash,
                "tx_hash": None,
                "block_number": None,
                "timestamp": now_iso,
                "network": self.network,
                "explorer_url": None,
                "error": str(exc)[:500],
                "metadata": metadata or {},
            }

    def verify_transaction(
        self,
        *,
        tx_hash: Optional[str],
        record_hash: Optional[str],
        fallback_timestamp: Optional[str] = None,
    ) -> Dict[str, Any]:
        """Verify a stored blockchain transaction hash."""
        if not tx_hash:
            return {
                "verified": False,
                "hash": record_hash or "",
                "tx_hash": None,
                "block_number": None,
                "timestamp": fallback_timestamp or datetime.now(timezone.utc).isoformat(),
                "network": self.network,
                "explorer_url": None,
                "status": "missing_tx",
            }

        explorer_url = f"{self.explorer_tx_base}{tx_hash}"

        if not self.enabled:
            return {
                "verified": False,
                "hash": record_hash or tx_hash,
                "tx_hash": tx_hash,
                "block_number": None,
                "timestamp": fallback_timestamp or datetime.now(timezone.utc).isoformat(),
                "network": self.network,
                "explorer_url": explorer_url,
                "status": "not_configured",
            }

        try:
            receipt = self._web3.eth.get_transaction_receipt(tx_hash)
            block = self._web3.eth.get_block(receipt.blockNumber)
            block_ts = datetime.fromtimestamp(block.timestamp, tz=timezone.utc).isoformat()

            return {
                "verified": int(receipt.status) == 1,
                "hash": record_hash or tx_hash,
                "tx_hash": tx_hash,
                "block_number": int(receipt.blockNumber),
                "timestamp": block_ts,
                "network": self.network,
                "explorer_url": explorer_url,
                "status": "confirmed" if int(receipt.status) == 1 else "failed",
            }

        except TransactionNotFound:
            return {
                "verified": False,
                "hash": record_hash or tx_hash,
                "tx_hash": tx_hash,
                "block_number": None,
                "timestamp": fallback_timestamp or datetime.now(timezone.utc).isoformat(),
                "network": self.network,
                "explorer_url": explorer_url,
                "status": "pending",
            }
        except Exception as exc:
            logger.exception("Blockchain verification failed for tx %s: %s", tx_hash, exc)
            return {
                "verified": False,
                "hash": record_hash or tx_hash,
                "tx_hash": tx_hash,
                "block_number": None,
                "timestamp": fallback_timestamp or datetime.now(timezone.utc).isoformat(),
                "network": self.network,
                "explorer_url": explorer_url,
                "status": "error",
                "error": str(exc)[:500],
            }
