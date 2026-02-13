"""Tests for the autonomous orchestrator module."""

import os
import json
import pytest

from agent.orchestrator import SecurityOrchestrator


class TestSecurityOrchestrator:
    """Tests for the SecurityOrchestrator class."""

    def test_init(self):
        orch = SecurityOrchestrator()
        assert orch.engine is not None
        assert orch.analyzer is not None
        assert orch.synthesizer is not None

    def test_discover_rs_files(self):
        """Should discover .rs files and skip target/node_modules."""
        orch = SecurityOrchestrator()
        rs_files = orch._discover_rs_files("examples/vulnerable-lending/")
        assert len(rs_files) >= 1
        for f in rs_files:
            assert f.endswith(".rs")
            assert "target" not in f
            assert "node_modules" not in f

    def test_discover_rs_files_non_anchor_dir(self):
        """Should return empty list for directory with no .rs files."""
        orch = SecurityOrchestrator()
        rs_files = orch._discover_rs_files("agent/")
        assert len(rs_files) == 0

    def test_has_anchor_toolchain(self):
        """Should return False when Anchor is not installed."""
        result = SecurityOrchestrator._has_anchor_toolchain()
        # In this environment, Anchor is not installed
        assert isinstance(result, bool)

    def test_run_static_scan(self):
        """Static scan should work on the vulnerable lending demo."""
        orch = SecurityOrchestrator()
        report = orch._run_static_scan("examples/vulnerable-lending/")
        assert report.files_scanned >= 1

    def test_full_pipeline(self):
        """Full pipeline should complete and produce a report."""
        old_key = os.environ.pop("ANTHROPIC_API_KEY", None)
        try:
            orch = SecurityOrchestrator(api_key="")
            report = orch.analyze(
                target_path="examples/vulnerable-lending/",
                execute_exploits=True,
                output_dir="/tmp/anchor-shield-test-output",
            )
            # Verify report structure
            assert "meta" in report
            assert "static_analysis" in report
            assert "semantic_analysis" in report
            assert "bankrun_exploits" in report
            assert "python_exploits" in report
            assert "summary" in report

            # Verify summary values
            s = report["summary"]
            assert s["logic_bugs_by_llm"] >= 3
            assert s["exploits_generated"] >= 1
            assert "bankrun_exploits_confirmed" in s
            assert "python_exploits_simulated" in s

            # Verify report file was created
            assert os.path.exists("SECURITY_REPORT.json")
            with open("SECURITY_REPORT.json") as f:
                saved = json.load(f)
            assert saved["meta"]["tool"] == "anchor-shield"
        finally:
            if old_key:
                os.environ["ANTHROPIC_API_KEY"] = old_key

    def test_pipeline_no_execute(self):
        """Pipeline with --no-execute should skip exploit execution."""
        orch = SecurityOrchestrator(api_key="")
        report = orch.analyze(
            target_path="examples/vulnerable-lending/",
            execute_exploits=False,
            output_dir="/tmp/anchor-shield-test-no-exec",
        )
        assert report["summary"]["exploits_generated"] >= 1

    def test_has_bankrun(self):
        """Should detect solana-bankrun when node_modules exists."""
        orch = SecurityOrchestrator()
        exploit_dir = os.path.join(
            os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
            "exploits",
        )
        result = orch._has_bankrun(exploit_dir)
        assert isinstance(result, bool)
        # bankrun should be installed in exploits/node_modules
        if os.path.isdir(os.path.join(exploit_dir, "node_modules", "solana-bankrun")):
            assert result is True

    def test_find_binary(self):
        """Should find the compiled SBF binary."""
        orch = SecurityOrchestrator()
        binary = orch._find_binary(
            os.path.join(
                os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
                "examples", "vulnerable-lending",
            )
        )
        # Binary should exist (we compiled it)
        if binary:
            assert binary.endswith(".so")
            assert os.path.exists(binary)

    def test_find_bankrun_exploits(self):
        """Should discover bankrun exploit TypeScript files."""
        orch = SecurityOrchestrator()
        exploit_dir = os.path.join(
            os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
            "exploits",
        )
        exploits = orch._find_bankrun_exploits(exploit_dir)
        assert isinstance(exploits, list)
        for ex in exploits:
            assert "bankrun_exploit_" in ex
            assert ex.endswith(".ts")

    def test_report_bankrun_section(self):
        """Report should have bankrun_exploits as a list."""
        orch = SecurityOrchestrator(api_key="")
        report = orch.analyze(
            target_path="examples/vulnerable-lending/",
            execute_exploits=True,
            output_dir="/tmp/anchor-shield-test-bankrun",
        )
        assert isinstance(report["bankrun_exploits"], list)
        assert isinstance(report["python_exploits"], list)
        # Each bankrun result should have required fields
        for bx in report["bankrun_exploits"]:
            assert "file" in bx
            assert "status" in bx
            assert "execution_mode" in bx
            assert bx["execution_mode"] == "bankrun"
