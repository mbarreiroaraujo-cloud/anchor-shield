"""Autonomous agent loop: scan → analyze → attest → publish."""

import json
import hashlib
import os
import time
import tempfile
from typing import Optional
from dataclasses import dataclass, field

from solders.keypair import Keypair

from scanner.engine import AnchorShieldEngine, ScanReport
from scanner.github_client import GitHubClient
from agent.attestation import AttestationPublisher
from agent.indexer import AttestationIndexer
from agent.config import GRADE_TO_SCORE


@dataclass
class AgentResult:
    """Result of an autonomous agent scan-and-attest cycle."""

    success: bool
    target: str
    scan_report: Optional[dict] = None
    attestation: Optional[dict] = None
    tx_signature: Optional[str] = None
    explorer_url: Optional[str] = None
    error: Optional[str] = None
    steps: list = field(default_factory=list)

    def to_dict(self) -> dict:
        return {
            "success": self.success,
            "target": self.target,
            "scan_report": self.scan_report,
            "attestation": self.attestation,
            "tx_signature": self.tx_signature,
            "explorer_url": self.explorer_url,
            "error": self.error,
            "steps": self.steps,
        }

    def to_json(self, indent: int = 2) -> str:
        return json.dumps(self.to_dict(), indent=indent, default=str)


class AutonomousAgent:
    """Autonomous security scanning and attestation agent.

    The agent performs a complete scan-analyze-attest cycle:
    1. Accepts a target (local directory, GitHub repo, or raw content)
    2. Runs the anchor-shield scanner engine
    3. Generates a security report
    4. Publishes an on-chain attestation on Solana devnet
    5. Returns the complete result with transaction proof
    """

    def __init__(
        self,
        network: str = "devnet",
        keypair: Optional[Keypair] = None,
        github_token: Optional[str] = None,
    ):
        self.engine = AnchorShieldEngine()
        self.github_client = GitHubClient(token=github_token)
        self.publisher = AttestationPublisher(network=network, keypair=keypair)
        self.indexer = AttestationIndexer(network=network)
        self.network = network

    @property
    def wallet_address(self) -> str:
        return str(self.publisher.pubkey)

    def scan_and_attest_repo(self, repo_url: str) -> AgentResult:
        """Full autonomous cycle: scan a GitHub repo and publish attestation.

        Steps:
        1. Fetch source files from GitHub
        2. Scan each file with the security engine
        3. Aggregate findings into a report
        4. Publish attestation on-chain
        5. Return results with transaction proof
        """
        result = AgentResult(success=False, target=repo_url)

        # Step 1: Fetch repo files
        result.steps.append({"step": "fetch", "status": "started", "target": repo_url})
        try:
            files = self.github_client.fetch_repo_files(repo_url)
            result.steps[-1]["status"] = "completed"
            result.steps[-1]["files_found"] = len(files)
        except Exception as e:
            result.steps[-1]["status"] = "failed"
            result.error = f"Failed to fetch repo: {e}"
            return result

        if not files:
            result.error = "No Rust source files found in repository"
            return result

        # Step 2: Scan files
        result.steps.append({"step": "scan", "status": "started"})
        try:
            scan_report = self._scan_files(files, repo_url)
            result.scan_report = scan_report.to_dict()
            result.steps[-1]["status"] = "completed"
            result.steps[-1]["findings"] = len(scan_report.findings)
        except Exception as e:
            result.steps[-1]["status"] = "failed"
            result.error = f"Scan failed: {e}"
            return result

        # Step 3: Publish attestation
        result.steps.append({"step": "attest", "status": "started"})
        try:
            tx_sig = self.publisher.publish_attestation(result.scan_report)
            result.tx_signature = tx_sig
            result.attestation = self.publisher.get_attestation_data(
                result.scan_report, tx_sig
            )
            result.explorer_url = result.attestation["explorer_url"]
            result.steps[-1]["status"] = "completed"
            result.steps[-1]["tx_signature"] = tx_sig
        except Exception as e:
            result.steps[-1]["status"] = "failed"
            result.error = f"Attestation failed: {e}"
            # Still return partial result with scan data
            result.success = False
            return result

        result.success = True
        return result

    def scan_and_attest_directory(self, path: str) -> AgentResult:
        """Full autonomous cycle: scan a local directory and publish attestation."""
        result = AgentResult(success=False, target=path)

        # Step 1: Scan directory
        result.steps.append({"step": "scan", "status": "started", "target": path})
        try:
            scan_report = self.engine.scan_directory(path)
            result.scan_report = scan_report.to_dict()
            result.steps[-1]["status"] = "completed"
            result.steps[-1]["findings"] = len(scan_report.findings)
        except Exception as e:
            result.steps[-1]["status"] = "failed"
            result.error = f"Scan failed: {e}"
            return result

        # Step 2: Publish attestation
        result.steps.append({"step": "attest", "status": "started"})
        try:
            tx_sig = self.publisher.publish_attestation(result.scan_report)
            result.tx_signature = tx_sig
            result.attestation = self.publisher.get_attestation_data(
                result.scan_report, tx_sig
            )
            result.explorer_url = result.attestation["explorer_url"]
            result.steps[-1]["status"] = "completed"
            result.steps[-1]["tx_signature"] = tx_sig
        except Exception as e:
            result.steps[-1]["status"] = "failed"
            result.error = f"Attestation failed: {e}"
            result.success = False
            return result

        result.success = True
        return result

    def scan_and_attest_content(
        self, content: str, filename: str = "<input>"
    ) -> AgentResult:
        """Scan raw content and publish attestation."""
        result = AgentResult(success=False, target=filename)

        # Step 1: Scan content
        result.steps.append({"step": "scan", "status": "started"})
        try:
            scan_report = self.engine.scan_content(content, filename)
            result.scan_report = scan_report.to_dict()
            result.steps[-1]["status"] = "completed"
            result.steps[-1]["findings"] = len(scan_report.findings)
        except Exception as e:
            result.steps[-1]["status"] = "failed"
            result.error = f"Scan failed: {e}"
            return result

        # Step 2: Publish attestation
        result.steps.append({"step": "attest", "status": "started"})
        try:
            tx_sig = self.publisher.publish_attestation(result.scan_report)
            result.tx_signature = tx_sig
            result.attestation = self.publisher.get_attestation_data(
                result.scan_report, tx_sig
            )
            result.explorer_url = result.attestation["explorer_url"]
            result.steps[-1]["status"] = "completed"
            result.steps[-1]["tx_signature"] = tx_sig
        except Exception as e:
            result.steps[-1]["status"] = "failed"
            result.error = f"Attestation failed: {e}"
            result.success = False
            return result

        result.success = True
        return result

    def scan_only(self, target: str) -> AgentResult:
        """Scan without publishing attestation (offline mode)."""
        result = AgentResult(success=False, target=target)

        result.steps.append({"step": "scan", "status": "started"})
        try:
            if target.startswith("https://github.com/"):
                files = self.github_client.fetch_repo_files(target)
                scan_report = self._scan_files(files, target)
            elif os.path.isdir(target) or os.path.isfile(target):
                scan_report = self.engine.scan_directory(target)
            elif os.path.exists(target):
                scan_report = self.engine.scan_content(target)
            else:
                raise FileNotFoundError(f"Target not found: {target}")

            result.scan_report = scan_report.to_dict()
            result.steps[-1]["status"] = "completed"
            result.success = True
        except Exception as e:
            result.steps[-1]["status"] = "failed"
            result.error = str(e)

        return result

    def query_attestations(self, authority: Optional[str] = None) -> dict:
        """Query attestation history for an authority (defaults to own wallet)."""
        authority = authority or self.wallet_address
        return self.indexer.get_attestation_summary(authority)

    def _scan_files(self, files: dict, target_name: str) -> ScanReport:
        """Scan a dict of {filepath: content} and aggregate results."""
        all_findings = []
        for filepath, content in files.items():
            for pattern in self.engine.patterns:
                try:
                    findings = pattern.scan(filepath, content)
                    all_findings.extend(findings)
                except Exception:
                    pass

        report = ScanReport(
            target=target_name,
            files_scanned=len(files),
            patterns_checked=len(self.engine.patterns),
            findings=all_findings,
        )
        report.security_score = AnchorShieldEngine._compute_security_score(all_findings)
        report.summary = AnchorShieldEngine._compute_summary(all_findings)
        return report
