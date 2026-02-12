"""Tests for the anchor-shield autonomous agent.

Tests cover:
  - Attestation memo creation and parsing
  - Agent scan pipeline (without network calls)
  - Indexer memo parsing logic
  - End-to-end agent flow (mocked Solana)
"""

import os
import sys
import json
import hashlib
import pytest
from unittest.mock import patch, MagicMock

# Add project root to path
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from scanner.engine import AnchorShieldEngine, ScanReport
from agent.attestation import AttestationPublisher
from agent.indexer import AttestationIndexer, AttestationRecord
from agent.autonomous import AutonomousAgent, AgentResult
from agent.config import MEMO_PREFIX, GRADE_TO_SCORE


TEST_DIR = os.path.join(os.path.dirname(__file__), "test_patterns")
VULN_DIR = os.path.join(TEST_DIR, "vulnerable")
SAFE_DIR = os.path.join(TEST_DIR, "safe")


# ─── Attestation Memo Tests ──────────────────────────────────────────

class TestAttestationMemo:
    """Test attestation memo creation and structure."""

    def _make_report(self, score="B", total=3, patterns=6, files=5) -> dict:
        return {
            "target": "https://github.com/test/repo",
            "scan_time_seconds": 1.23,
            "files_scanned": files,
            "patterns_checked": patterns,
            "security_score": score,
            "summary": {
                "total": total,
                "by_severity": {"Critical": 0, "High": 1, "Medium": 2, "Low": 0},
                "by_pattern": {"ANCHOR-001": 1, "ANCHOR-002": 2},
            },
            "findings": [],
        }

    def test_memo_has_correct_prefix(self):
        """Memo must start with ASHIELD prefix."""
        publisher = AttestationPublisher.__new__(AttestationPublisher)
        publisher.network = "devnet"
        memo = publisher.create_attestation_memo(self._make_report())
        assert memo.startswith(MEMO_PREFIX + "|")

    def test_memo_contains_score(self):
        """Memo must contain the numeric security score."""
        publisher = AttestationPublisher.__new__(AttestationPublisher)
        publisher.network = "devnet"
        report = self._make_report(score="A")
        memo = publisher.create_attestation_memo(report)
        assert "s=100" in memo

    def test_memo_contains_issues(self):
        """Memo must contain issue count."""
        publisher = AttestationPublisher.__new__(AttestationPublisher)
        publisher.network = "devnet"
        report = self._make_report(total=5)
        memo = publisher.create_attestation_memo(report)
        assert "i=5" in memo

    def test_memo_contains_patterns(self):
        """Memo must contain patterns checked count."""
        publisher = AttestationPublisher.__new__(AttestationPublisher)
        publisher.network = "devnet"
        report = self._make_report(patterns=6)
        memo = publisher.create_attestation_memo(report)
        assert "p=6" in memo

    def test_memo_contains_severity_breakdown(self):
        """Memo must contain severity breakdown."""
        publisher = AttestationPublisher.__new__(AttestationPublisher)
        publisher.network = "devnet"
        memo = publisher.create_attestation_memo(self._make_report())
        assert "sev=C0H1M2L0" in memo

    def test_memo_contains_report_hash(self):
        """Memo must contain a report hash for integrity."""
        publisher = AttestationPublisher.__new__(AttestationPublisher)
        publisher.network = "devnet"
        memo = publisher.create_attestation_memo(self._make_report())
        assert "h=" in memo
        # Hash should be 32 hex chars
        parts = memo.split("|")
        hash_part = [p for p in parts if p.startswith("h=")][0]
        hash_val = hash_part.split("=")[1]
        assert len(hash_val) == 32

    def test_memo_score_mapping(self):
        """Score grades should map correctly to numeric values."""
        publisher = AttestationPublisher.__new__(AttestationPublisher)
        publisher.network = "devnet"

        for grade, expected_score in GRADE_TO_SCORE.items():
            report = self._make_report(score=grade)
            memo = publisher.create_attestation_memo(report)
            assert f"s={expected_score}" in memo

    def test_memo_different_targets_different_hashes(self):
        """Different targets should produce different target hashes."""
        publisher = AttestationPublisher.__new__(AttestationPublisher)
        publisher.network = "devnet"

        report1 = self._make_report()
        report1["target"] = "https://github.com/user/repo1"
        report2 = self._make_report()
        report2["target"] = "https://github.com/user/repo2"

        memo1 = publisher.create_attestation_memo(report1)
        memo2 = publisher.create_attestation_memo(report2)

        # Extract target hashes (3rd field)
        hash1 = memo1.split("|")[2]
        hash2 = memo2.split("|")[2]
        assert hash1 != hash2


# ─── Indexer Memo Parsing Tests ──────────────────────────────────────

class TestIndexerParsing:
    """Test the indexer's ability to parse attestation memos."""

    def test_parse_valid_memo(self):
        """Indexer should parse a well-formed attestation memo."""
        memo = "ASHIELD|0.1.0|abc123def456|s=85|i=3|p=6|sev=C0H1M2L0|h=deadbeef12345678"
        record = AttestationIndexer._parse_memo(
            memo, "tx123", "authority123", 1700000000
        )
        assert record is not None
        assert record.version == "0.1.0"
        assert record.target_hash == "abc123def456"
        assert record.score == 85
        assert record.issues == 3
        assert record.patterns == 6
        assert record.severity == "C0H1M2L0"
        assert record.report_hash == "deadbeef12345678"
        assert record.timestamp == 1700000000

    def test_parse_invalid_prefix(self):
        """Memos with wrong prefix should return None."""
        memo = "NOTASHIELD|0.1.0|abc|s=85|i=3|p=6|sev=X|h=abc"
        record = AttestationIndexer._parse_memo(memo, "tx", "auth", 0)
        assert record is None

    def test_parse_truncated_memo(self):
        """Incomplete memos should return None."""
        memo = "ASHIELD|0.1.0"
        record = AttestationIndexer._parse_memo(memo, "tx", "auth", 0)
        assert record is None

    def test_extract_memo_from_log(self):
        """Should extract memo content from Solana log messages."""
        log = 'Program log: Memo (len 80): "ASHIELD|0.1.0|abc|s=85|i=3|p=6|sev=C0H1M2L0|h=deadbeef"'
        memo = AttestationIndexer._extract_memo_from_log(log)
        assert memo is not None
        assert memo.startswith("ASHIELD")

    def test_extract_non_memo_log(self):
        """Non-memo log messages should return None."""
        log = "Program log: invoke [1]"
        memo = AttestationIndexer._extract_memo_from_log(log)
        assert memo is None


# ─── Agent Pipeline Tests ────────────────────────────────────────────

class TestAgentPipeline:
    """Test the agent scan pipeline without network calls."""

    def test_scan_only_local_directory(self):
        """Agent should scan a local directory without publishing."""
        agent = AutonomousAgent.__new__(AutonomousAgent)
        agent.engine = AnchorShieldEngine()
        agent.github_client = MagicMock()
        agent.publisher = MagicMock()
        agent.indexer = MagicMock()
        agent.network = "devnet"

        result = agent.scan_only(VULN_DIR)
        assert result.success
        assert result.scan_report is not None
        assert result.scan_report["files_scanned"] > 0
        assert result.scan_report["summary"]["total"] > 0

    def test_scan_only_safe_directory(self):
        """Safe directory should produce clean results."""
        agent = AutonomousAgent.__new__(AutonomousAgent)
        agent.engine = AnchorShieldEngine()
        agent.github_client = MagicMock()
        agent.publisher = MagicMock()
        agent.indexer = MagicMock()
        agent.network = "devnet"

        result = agent.scan_only(SAFE_DIR)
        assert result.success

    def test_scan_and_attest_directory_mocked(self):
        """Agent should scan and attest a directory (mocked publisher)."""
        agent = AutonomousAgent.__new__(AutonomousAgent)
        agent.engine = AnchorShieldEngine()
        agent.github_client = MagicMock()
        agent.publisher = MagicMock()
        agent.publisher.publish_attestation.return_value = "mock_tx_signature_123"
        agent.publisher.get_attestation_data.return_value = {
            "protocol": "anchor-shield",
            "transaction": "mock_tx_signature_123",
            "security_score": 20,
            "security_grade": "F",
            "issues_found": 11,
            "patterns_checked": 6,
            "files_scanned": 6,
            "report_hash": "abc123",
            "explorer_url": "https://explorer.solana.com/tx/mock?cluster=devnet",
        }
        agent.indexer = MagicMock()
        agent.network = "devnet"

        result = agent.scan_and_attest_directory(VULN_DIR)
        assert result.success
        assert result.tx_signature == "mock_tx_signature_123"
        assert result.attestation is not None
        assert result.explorer_url is not None

    def test_scan_content_directly(self):
        """Agent should scan raw content."""
        agent = AutonomousAgent.__new__(AutonomousAgent)
        agent.engine = AnchorShieldEngine()
        agent.github_client = MagicMock()
        agent.publisher = MagicMock()
        agent.publisher.publish_attestation.return_value = "mock_tx_sig"
        agent.publisher.get_attestation_data.return_value = {
            "protocol": "anchor-shield",
            "transaction": "mock_tx_sig",
            "security_score": 100,
            "security_grade": "A",
            "issues_found": 0,
            "patterns_checked": 6,
            "files_scanned": 1,
            "report_hash": "xyz",
            "explorer_url": "https://explorer.solana.com/tx/mock?cluster=devnet",
        }
        agent.indexer = MagicMock()
        agent.network = "devnet"

        content = """
        #[derive(Accounts)]
        pub struct SafeAccounts<'info> {
            #[account(mut)]
            pub vault: Account<'info, Vault>,
            pub authority: Signer<'info>,
        }
        """
        result = agent.scan_and_attest_content(content, "test.rs")
        assert result.success
        assert result.scan_report["summary"]["total"] == 0

    def test_agent_result_serialization(self):
        """AgentResult should serialize to valid JSON."""
        result = AgentResult(
            success=True,
            target="test",
            scan_report={"target": "test", "findings": []},
            tx_signature="sig123",
            steps=[{"step": "scan", "status": "completed"}],
        )
        json_str = result.to_json()
        parsed = json.loads(json_str)
        assert parsed["success"] is True
        assert parsed["tx_signature"] == "sig123"

    def test_agent_handles_scan_failure(self):
        """Agent should handle scan failures gracefully."""
        agent = AutonomousAgent.__new__(AutonomousAgent)
        agent.engine = AnchorShieldEngine()
        agent.github_client = MagicMock()
        agent.publisher = MagicMock()
        agent.indexer = MagicMock()
        agent.network = "devnet"

        result = agent.scan_only("/nonexistent/path/to/scan")
        assert not result.success
        assert result.error is not None


# ─── Attestation Data Structure Tests ────────────────────────────────

class TestAttestationData:
    """Test attestation data structure and integrity."""

    def test_attestation_data_contains_required_fields(self):
        """Attestation data must contain all required fields."""
        publisher = AttestationPublisher.__new__(AttestationPublisher)
        publisher.network = "devnet"
        from solders.keypair import Keypair
        publisher.keypair = Keypair()

        report = {
            "target": "test-repo",
            "security_score": "B",
            "patterns_checked": 6,
            "files_scanned": 10,
            "scan_time_seconds": 2.5,
            "summary": {"total": 3, "by_severity": {"High": 1, "Medium": 2}},
        }

        data = publisher.get_attestation_data(report, "tx_sig_123")

        assert data["protocol"] == "anchor-shield"
        assert data["version"] == "0.1.0"
        assert data["network"] == "devnet"
        assert data["transaction"] == "tx_sig_123"
        assert data["security_score"] == 75  # Grade B = 75
        assert data["security_grade"] == "B"
        assert data["patterns_checked"] == 6
        assert data["issues_found"] == 3
        assert data["files_scanned"] == 10
        assert "report_hash" in data
        assert "explorer_url" in data
        assert "authority" in data
        assert "target_hash" in data
        assert "timestamp" in data

    def test_report_hash_is_deterministic(self):
        """Same report should produce same hash."""
        publisher = AttestationPublisher.__new__(AttestationPublisher)
        publisher.network = "devnet"
        from solders.keypair import Keypair
        publisher.keypair = Keypair()

        report = {
            "target": "test",
            "security_score": "A",
            "patterns_checked": 6,
            "files_scanned": 1,
            "scan_time_seconds": 0.1,
            "summary": {"total": 0, "by_severity": {}},
        }

        data1 = publisher.get_attestation_data(report, "tx1")
        data2 = publisher.get_attestation_data(report, "tx2")
        assert data1["report_hash"] == data2["report_hash"]


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
