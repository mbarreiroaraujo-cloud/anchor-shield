"""On-chain attestation publisher using Solana memo transactions."""

import json
import hashlib
import time
import struct
from typing import Optional

from solders.keypair import Keypair
from solders.pubkey import Pubkey
from solders.system_program import TransferParams, transfer
from solders.transaction import Transaction
from solders.message import Message
from solders.instruction import Instruction, AccountMeta
from solders.hash import Hash
from solana.rpc.api import Client
from solana.rpc.commitment import Confirmed

from agent.config import (
    SOLANA_DEVNET_URL,
    SOLANA_TESTNET_URL,
    MEMO_PROGRAM_ID,
    PROTOCOL_ID,
    PROTOCOL_VERSION,
    MEMO_PREFIX,
    AIRDROP_LAMPORTS,
    MIN_BALANCE_LAMPORTS,
    RPC_TIMEOUT,
    GRADE_TO_SCORE,
)


class AttestationPublisher:
    """Publishes security attestations as structured memo transactions on Solana."""

    def __init__(self, network: str = "devnet", keypair: Optional[Keypair] = None):
        self.network = network
        if network == "devnet":
            self.rpc_url = SOLANA_DEVNET_URL
        elif network == "testnet":
            self.rpc_url = SOLANA_TESTNET_URL
        else:
            raise ValueError(f"Unsupported network for attestations: {network}")

        self.client = Client(self.rpc_url, timeout=RPC_TIMEOUT)
        self.keypair = keypair or Keypair()
        self.memo_program = Pubkey.from_string(MEMO_PROGRAM_ID)

    @property
    def pubkey(self) -> Pubkey:
        return self.keypair.pubkey()

    def ensure_funded(self) -> bool:
        """Ensure the wallet has enough SOL for transactions via airdrop."""
        balance = self.get_balance()
        if balance < MIN_BALANCE_LAMPORTS:
            return self.request_airdrop()
        return True

    def get_balance(self) -> int:
        """Get wallet balance in lamports."""
        try:
            resp = self.client.get_balance(self.pubkey, commitment=Confirmed)
            return resp.value
        except Exception:
            return 0

    def request_airdrop(self, amount: int = AIRDROP_LAMPORTS) -> bool:
        """Request SOL airdrop on devnet/testnet."""
        try:
            resp = self.client.request_airdrop(self.pubkey, amount)
            sig = resp.value
            # Wait for confirmation
            self.client.confirm_transaction(sig, commitment=Confirmed)
            return True
        except Exception as e:
            # Airdrop may fail due to rate limits; retry once after delay
            time.sleep(2)
            try:
                resp = self.client.request_airdrop(self.pubkey, amount)
                sig = resp.value
                self.client.confirm_transaction(sig, commitment=Confirmed)
                return True
            except Exception:
                return False

    def create_attestation_memo(self, scan_report: dict) -> str:
        """Create a structured memo string from a scan report.

        Format: ASHIELD|v0.1.0|<target_hash>|s=<score>|i=<issues>|p=<patterns>|h=<report_hash>
        """
        target = scan_report.get("target", "unknown")
        target_hash = hashlib.sha256(target.encode()).hexdigest()[:16]

        # Convert letter grade to numeric score
        grade = scan_report.get("security_score", "A")
        score = GRADE_TO_SCORE.get(grade, 50)

        summary = scan_report.get("summary", {})
        total_issues = summary.get("total", 0)
        patterns_checked = scan_report.get("patterns_checked", 0)

        # Hash the full report for integrity
        report_json = json.dumps(scan_report, sort_keys=True, default=str)
        report_hash = hashlib.sha256(report_json.encode()).hexdigest()[:32]

        # Severity breakdown
        by_severity = summary.get("by_severity", {})
        sev_str = f"C{by_severity.get('Critical', 0)}H{by_severity.get('High', 0)}M{by_severity.get('Medium', 0)}L{by_severity.get('Low', 0)}"

        memo = (
            f"{MEMO_PREFIX}|{PROTOCOL_VERSION}|{target_hash}|"
            f"s={score}|i={total_issues}|p={patterns_checked}|"
            f"sev={sev_str}|h={report_hash}"
        )
        return memo

    def publish_attestation(self, scan_report: dict) -> Optional[str]:
        """Publish a security attestation as a memo transaction on Solana.

        Returns the transaction signature on success, None on failure.
        """
        if not self.ensure_funded():
            raise RuntimeError(
                f"Failed to fund wallet {self.pubkey} on {self.network}. "
                "Ensure you are connected to devnet/testnet."
            )

        memo_text = self.create_attestation_memo(scan_report)
        memo_bytes = memo_text.encode("utf-8")

        # Create memo instruction
        memo_ix = Instruction(
            program_id=self.memo_program,
            accounts=[AccountMeta(self.pubkey, is_signer=True, is_writable=False)],
            data=memo_bytes,
        )

        # Get recent blockhash
        blockhash_resp = self.client.get_latest_blockhash(commitment=Confirmed)
        recent_blockhash = blockhash_resp.value.blockhash

        # Build and sign transaction
        msg = Message.new_with_blockhash(
            [memo_ix],
            self.pubkey,
            recent_blockhash,
        )
        tx = Transaction.new_unsigned(msg)
        tx.sign([self.keypair], recent_blockhash)

        # Send transaction
        resp = self.client.send_transaction(tx)
        sig = resp.value

        # Confirm
        self.client.confirm_transaction(sig, commitment=Confirmed)

        return str(sig)

    def get_attestation_data(self, scan_report: dict, tx_signature: str) -> dict:
        """Build structured attestation data combining on-chain and off-chain info."""
        target = scan_report.get("target", "unknown")
        target_hash = hashlib.sha256(target.encode()).hexdigest()
        grade = scan_report.get("security_score", "A")
        score = GRADE_TO_SCORE.get(grade, 50)
        summary = scan_report.get("summary", {})

        return {
            "protocol": PROTOCOL_ID,
            "version": PROTOCOL_VERSION,
            "network": self.network,
            "authority": str(self.pubkey),
            "transaction": tx_signature,
            "target": target,
            "target_hash": target_hash,
            "timestamp": int(time.time()),
            "security_score": score,
            "security_grade": grade,
            "patterns_checked": scan_report.get("patterns_checked", 0),
            "issues_found": summary.get("total", 0),
            "severity_breakdown": summary.get("by_severity", {}),
            "files_scanned": scan_report.get("files_scanned", 0),
            "scan_time": scan_report.get("scan_time_seconds", 0),
            "report_hash": hashlib.sha256(
                json.dumps(scan_report, sort_keys=True, default=str).encode()
            ).hexdigest(),
            "explorer_url": (
                f"https://explorer.solana.com/tx/{tx_signature}?cluster={self.network}"
            ),
        }
