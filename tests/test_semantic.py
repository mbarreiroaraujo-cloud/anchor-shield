"""Tests for the semantic analyzer module."""

import json
import os
import pytest

from semantic.analyzer import SemanticAnalyzer, SemanticFinding
from semantic.prompts import SECURITY_AUDITOR_SYSTEM_PROMPT


class TestSemanticFinding:
    """Tests for the SemanticFinding dataclass."""

    def test_finding_creation(self):
        finding = SemanticFinding(
            id="SEM-001",
            severity="Critical",
            function="borrow",
            title="Test bug",
            description="A test vulnerability",
            attack_scenario="1. Do something\n2. Exploit",
            estimated_impact="Loss of funds",
            confidence=0.95,
        )
        assert finding.id == "SEM-001"
        assert finding.severity == "Critical"
        assert finding.function == "borrow"
        assert finding.confidence == 0.95
        assert finding.source == "semantic"

    def test_finding_to_dict(self):
        finding = SemanticFinding(
            id="SEM-002",
            severity="High",
            function="withdraw",
            title="Test",
            description="Desc",
            attack_scenario="Attack",
            estimated_impact="Impact",
            confidence=0.8,
        )
        d = finding.to_dict()
        assert isinstance(d, dict)
        assert d["id"] == "SEM-002"
        assert d["severity"] == "High"
        assert d["confidence"] == 0.8
        assert "source" in d


class TestSemanticAnalyzer:
    """Tests for the SemanticAnalyzer class."""

    def test_init_default(self):
        analyzer = SemanticAnalyzer()
        assert analyzer.model == "claude-sonnet-4-20250514"
        assert analyzer.API_URL == "https://api.anthropic.com/v1/messages"

    def test_init_custom_model(self):
        analyzer = SemanticAnalyzer(model="claude-haiku-4-5-20251001")
        assert analyzer.model == "claude-haiku-4-5-20251001"

    def test_missing_api_key_uses_prevalidated(self):
        """Without API key, analyzer should fall back to pre-validated results."""
        # Ensure no API key
        old_key = os.environ.pop("ANTHROPIC_API_KEY", None)
        try:
            analyzer = SemanticAnalyzer(api_key="")
            findings = analyzer.analyze("some code", "test.rs")
            assert len(findings) == 4
            assert analyzer.is_demo_mode
            assert findings[0].source == "validated"
        finally:
            if old_key:
                os.environ["ANTHROPIC_API_KEY"] = old_key

    def test_prevalidated_findings_are_complete(self):
        """Pre-validated findings should have all required fields."""
        analyzer = SemanticAnalyzer(api_key="")
        findings = analyzer.analyze("code", "test.rs")
        for f in findings:
            assert f.id
            assert f.severity in ("Critical", "High", "Medium", "Low")
            assert f.function
            assert f.title
            assert f.description
            assert f.attack_scenario
            assert f.estimated_impact
            assert 0.0 <= f.confidence <= 1.0

    def test_prevalidated_covers_all_bugs(self):
        """Pre-validated findings should cover all 4 known bugs."""
        analyzer = SemanticAnalyzer(api_key="")
        findings = analyzer.analyze("code", "test.rs")
        functions = {f.function for f in findings}
        assert "borrow" in functions
        assert "withdraw" in functions
        assert "liquidate" in functions

    def test_parse_findings_valid_json(self):
        """Test JSON parsing of well-formed response."""
        analyzer = SemanticAnalyzer()
        text = json.dumps({
            "findings": [
                {
                    "severity": "High",
                    "function": "test_fn",
                    "title": "Test Finding",
                    "description": "A test",
                    "attack_scenario": "Step 1",
                    "estimated_impact": "Bad things",
                    "confidence": 0.85,
                }
            ]
        })
        findings = analyzer._parse_findings(text)
        assert len(findings) == 1
        assert findings[0].severity == "High"
        assert findings[0].function == "test_fn"
        assert findings[0].confidence == 0.85

    def test_parse_findings_with_markdown_fences(self):
        """Test parsing JSON wrapped in markdown code fences."""
        analyzer = SemanticAnalyzer()
        text = '```json\n{"findings": [{"severity": "Medium", "function": "f", "title": "T", "description": "D", "attack_scenario": "A", "estimated_impact": "I", "confidence": 0.5}]}\n```'
        findings = analyzer._parse_findings(text)
        assert len(findings) == 1
        assert findings[0].severity == "Medium"

    def test_parse_findings_empty(self):
        """Test parsing response with no findings."""
        analyzer = SemanticAnalyzer()
        text = '{"findings": []}'
        findings = analyzer._parse_findings(text)
        assert len(findings) == 0

    def test_parse_findings_invalid_json(self):
        """Test graceful handling of invalid JSON."""
        analyzer = SemanticAnalyzer()
        findings = analyzer._parse_findings("this is not json")
        assert len(findings) == 0


class TestPrompts:
    """Tests for the prompt constants."""

    def test_system_prompt_exists(self):
        assert len(SECURITY_AUDITOR_SYSTEM_PROMPT) > 100

    def test_system_prompt_contains_focus_areas(self):
        prompt = SECURITY_AUDITOR_SYSTEM_PROMPT
        assert "logic" in prompt.lower()
        assert "overflow" in prompt.lower()
        assert "division by zero" in prompt.lower()

    def test_system_prompt_requests_json(self):
        assert "JSON" in SECURITY_AUDITOR_SYSTEM_PROMPT
