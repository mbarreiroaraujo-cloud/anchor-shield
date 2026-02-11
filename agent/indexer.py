"""On-chain attestation indexer - reads attestations from Solana transactions."""

import json
import time
from typing import Optional

from solders.pubkey import Pubkey
from solders.signature import Signature
from solana.rpc.api import Client
from solana.rpc.commitment import Confirmed

from agent.config import (
    SOLANA_DEVNET_URL,
    SOLANA_TESTNET_URL,
    MEMO_PREFIX,
    RPC_TIMEOUT,
)


class AttestationRecord:
    """Parsed attestation record from an on-chain memo."""

    def __init__(
        self,
        tx_signature: str,
        authority: str,
        version: str,
        target_hash: str,
        score: int,
        issues: int,
        patterns: int,
        severity: str,
        report_hash: str,
        timestamp: int,
        network: str,
    ):
        self.tx_signature = tx_signature
        self.authority = authority
        self.version = version
        self.target_hash = target_hash
        self.score = score
        self.issues = issues
        self.patterns = patterns
        self.severity = severity
        self.report_hash = report_hash
        self.timestamp = timestamp
        self.network = network

    def to_dict(self) -> dict:
        return {
            "tx_signature": self.tx_signature,
            "authority": self.authority,
            "version": self.version,
            "target_hash": self.target_hash,
            "score": self.score,
            "issues": self.issues,
            "patterns": self.patterns,
            "severity": self.severity,
            "report_hash": self.report_hash,
            "timestamp": self.timestamp,
            "network": self.network,
            "explorer_url": (
                f"https://explorer.solana.com/tx/{self.tx_signature}"
                f"?cluster={self.network}"
            ),
        }


class AttestationIndexer:
    """Indexes anchor-shield attestations from Solana transaction history."""

    def __init__(self, network: str = "devnet"):
        self.network = network
        if network == "devnet":
            self.rpc_url = SOLANA_DEVNET_URL
        elif network == "testnet":
            self.rpc_url = SOLANA_TESTNET_URL
        else:
            raise ValueError(f"Unsupported network: {network}")

        self.client = Client(self.rpc_url, timeout=RPC_TIMEOUT)

    def fetch_attestations(
        self,
        authority: str,
        limit: int = 20,
    ) -> list[AttestationRecord]:
        """Fetch attestation records from an authority's transaction history.

        Scans the authority's confirmed transactions for memo instructions
        matching the ASHIELD protocol format.
        """
        pubkey = Pubkey.from_string(authority)

        try:
            resp = self.client.get_signatures_for_address(
                pubkey,
                limit=limit,
                commitment=Confirmed,
            )
            signatures = resp.value
        except Exception:
            return []

        records = []
        for sig_info in signatures:
            sig_str = str(sig_info.signature)
            block_time = sig_info.block_time or 0

            record = self._parse_transaction(sig_str, authority, block_time)
            if record:
                records.append(record)

        return records

    def fetch_single_attestation(self, tx_signature: str) -> Optional[AttestationRecord]:
        """Fetch and parse a single attestation by transaction signature."""
        try:
            sig = Signature.from_string(tx_signature)
            resp = self.client.get_transaction(
                sig,
                encoding="jsonParsed",
                commitment=Confirmed,
                max_supported_transaction_version=0,
            )
            if not resp.value:
                return None

            tx_data = resp.value
            meta = tx_data.transaction.meta
            block_time = tx_data.block_time or 0

            # Extract log messages to find memo data
            if meta and meta.log_messages:
                for log in meta.log_messages:
                    log_str = str(log)
                    if MEMO_PREFIX in log_str:
                        # Extract memo content from log
                        memo_text = self._extract_memo_from_log(log_str)
                        if memo_text:
                            # Get authority from account keys
                            account_keys = tx_data.transaction.transaction.message.account_keys
                            authority = str(account_keys[0].pubkey) if account_keys else "unknown"
                            return self._parse_memo(
                                memo_text, tx_signature, authority, block_time
                            )
        except Exception:
            pass
        return None

    def _parse_transaction(
        self, tx_signature: str, authority: str, block_time: int
    ) -> Optional[AttestationRecord]:
        """Parse a transaction to extract attestation memo data."""
        try:
            sig = Signature.from_string(tx_signature)
            resp = self.client.get_transaction(
                sig,
                encoding="jsonParsed",
                commitment=Confirmed,
                max_supported_transaction_version=0,
            )
            if not resp.value:
                return None

            meta = resp.value.transaction.meta
            if not meta or not meta.log_messages:
                return None

            for log in meta.log_messages:
                log_str = str(log)
                if MEMO_PREFIX in log_str:
                    memo_text = self._extract_memo_from_log(log_str)
                    if memo_text:
                        return self._parse_memo(
                            memo_text, tx_signature, authority, block_time
                        )
        except Exception:
            pass
        return None

    @staticmethod
    def _extract_memo_from_log(log_line: str) -> Optional[str]:
        """Extract memo content from a Solana log message.

        Memo program logs look like:
        Program log: Memo (len N): "ASHIELD|..."
        """
        if MEMO_PREFIX not in log_line:
            return None

        # Try to find the memo content after "Memo (len ...): "
        idx = log_line.find(MEMO_PREFIX)
        if idx >= 0:
            # Extract from ASHIELD prefix to end, strip quotes
            memo = log_line[idx:].strip().rstrip('"')
            return memo
        return None

    @staticmethod
    def _parse_memo(
        memo_text: str,
        tx_signature: str,
        authority: str,
        block_time: int,
    ) -> Optional[AttestationRecord]:
        """Parse a structured memo string into an AttestationRecord.

        Expected format: ASHIELD|<version>|<target_hash>|s=<score>|i=<issues>|p=<patterns>|sev=<severity>|h=<hash>
        """
        parts = memo_text.split("|")
        if len(parts) < 7 or parts[0] != MEMO_PREFIX:
            return None

        try:
            version = parts[1]
            target_hash = parts[2]

            # Parse key=value fields
            kv = {}
            for part in parts[3:]:
                if "=" in part:
                    k, v = part.split("=", 1)
                    kv[k] = v

            return AttestationRecord(
                tx_signature=tx_signature,
                authority=authority,
                version=version,
                target_hash=target_hash,
                score=int(kv.get("s", 0)),
                issues=int(kv.get("i", 0)),
                patterns=int(kv.get("p", 0)),
                severity=kv.get("sev", ""),
                report_hash=kv.get("h", ""),
                timestamp=block_time,
                network="devnet",  # will be set by caller
            )
        except (ValueError, IndexError):
            return None

    def get_attestation_summary(self, authority: str) -> dict:
        """Get a summary of all attestations for an authority."""
        records = self.fetch_attestations(authority)

        return {
            "authority": authority,
            "network": self.network,
            "total_attestations": len(records),
            "attestations": [r.to_dict() for r in records],
            "indexed_at": int(time.time()),
        }
