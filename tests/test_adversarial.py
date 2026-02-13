"""Tests for the adversarial exploit synthesizer module."""

import os
import ast
import glob
import pytest

from adversarial.synthesizer import ExploitSynthesizer, ExploitCode
from semantic.analyzer import SemanticFinding


class TestExploitCode:
    """Tests for the ExploitCode dataclass."""

    def test_creation(self):
        code = ExploitCode(
            finding_id="SEM-001",
            title="Test Exploit",
            language="python",
            code="print('exploit')",
            setup_instructions="python3 exploit.py",
            expected_result="Proves vulnerability",
            status="GENERATED",
        )
        assert code.finding_id == "SEM-001"
        assert code.language == "python"
        assert code.status == "GENERATED"

    def test_to_dict(self):
        code = ExploitCode(
            finding_id="SEM-002",
            title="Test",
            language="python",
            code="pass",
            setup_instructions="run it",
            expected_result="works",
            status="SIMULATED",
        )
        d = code.to_dict()
        assert isinstance(d, dict)
        assert d["finding_id"] == "SEM-002"
        assert d["status"] == "SIMULATED"


class TestExploitSynthesizer:
    """Tests for the ExploitSynthesizer class."""

    def test_init_default(self):
        synth = ExploitSynthesizer()
        assert synth.model == "claude-sonnet-4-20250514"

    def test_init_custom_model(self):
        synth = ExploitSynthesizer(model="custom-model")
        assert synth.model == "custom-model"

    def test_generate_exploit_without_api_key(self):
        """Without API key, should use pre-built validated exploits."""
        old_key = os.environ.pop("ANTHROPIC_API_KEY", None)
        try:
            synth = ExploitSynthesizer(api_key="")
            finding = SemanticFinding(
                id="SEM-001",
                severity="Critical",
                function="borrow",
                title="Collateral check ignores existing debt",
                description="Test",
                attack_scenario="Test",
                estimated_impact="Test",
                confidence=0.9,
            )
            exploit = synth.generate_exploit("source code", finding)
            assert exploit is not None
            assert exploit.finding_id == "SEM-001"
            assert exploit.language == "python"
            assert len(exploit.code) > 50
        finally:
            if old_key:
                os.environ["ANTHROPIC_API_KEY"] = old_key

    def test_generate_all_filters_severity(self):
        """generate_all should only produce exploits for Critical/High."""
        synth = ExploitSynthesizer(api_key="")
        findings = [
            SemanticFinding("SEM-001", "Critical", "borrow", "Collateral bypass",
                          "desc", "attack", "impact", 0.9),
            SemanticFinding("SEM-004", "Medium", "liquidate", "Division by zero",
                          "desc", "attack", "impact", 0.8),
        ]
        exploits = synth.generate_all("source", findings)
        # Should only have exploit for the Critical finding
        assert len(exploits) == 1
        assert exploits[0].finding_id == "SEM-001"

    def test_prebuilt_exploits_are_valid_python(self):
        """All pre-built exploit strings must be valid Python syntax."""
        synth = ExploitSynthesizer()
        for keyword, code in synth._PREBUILT_EXPLOITS.items():
            try:
                ast.parse(code)
            except SyntaxError as e:
                pytest.fail(f"Pre-built exploit '{keyword}' has syntax error: {e}")


class TestExploitFiles:
    """Tests for generated exploit files on disk."""

    def test_exploit_files_exist(self):
        """At least some exploit files should exist in the exploits/ directory."""
        exploit_files = glob.glob("exploits/exploit_*.py")
        assert len(exploit_files) >= 1, "Expected at least 1 exploit file"

    def test_exploit_files_are_valid_python(self):
        """All exploit files should be syntactically valid Python."""
        for filepath in glob.glob("exploits/exploit_*.py"):
            with open(filepath) as f:
                try:
                    ast.parse(f.read())
                except SyntaxError as e:
                    pytest.fail(f"{filepath} has syntax error: {e}")
