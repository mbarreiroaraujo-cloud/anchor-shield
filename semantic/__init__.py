"""Semantic analysis module for anchor-shield.

Uses LLM reasoning to detect logic vulnerabilities that static
pattern matching cannot find. The analyzer sends Anchor program
source code to an LLM and receives structured vulnerability reports
with attack scenarios, confidence levels, and impact estimates.
"""

from semantic.analyzer import SemanticAnalyzer, SemanticFinding

__all__ = ["SemanticAnalyzer", "SemanticFinding"]
