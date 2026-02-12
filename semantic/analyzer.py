"""
Semantic Analyzer — LLM-powered logic vulnerability detection for Anchor programs.

Uses the Anthropic Claude API to analyze Solana/Anchor program source code
for logic bugs that regex-based pattern matching cannot detect.
"""

import json
import os
from dataclasses import dataclass, field, asdict
from typing import List, Optional


@dataclass
class SemanticFinding:
    """A logic vulnerability discovered by semantic analysis."""
    severity: str
    function: str
    title: str
    description: str
    attack_scenario: str
    confidence: float
    line_hint: Optional[int] = None
    category: str = "logic"

    def to_dict(self) -> dict:
        return asdict(self)


SYSTEM_PROMPT = """You are an expert Solana/Anchor smart contract security auditor.

Analyze the provided Anchor program source code for LOGIC vulnerabilities only.

Focus exclusively on:
- Business logic flaws (incorrect validation, missing checks, wrong ordering)
- Arithmetic issues (overflow, underflow, precision loss, division by zero)
- State manipulation bugs (inconsistent state updates, race conditions)
- Access control logic errors (missing authorization beyond what Anchor enforces)
- Economic exploits (flash loan attacks, price manipulation, drain scenarios)

Do NOT report:
- Missing CHECK comments on AccountInfo (Anchor convention, not a logic bug)
- AccountInfo typing suggestions (cosmetic, not exploitable)
- Generic best-practice warnings without a concrete exploit path
- Anchor framework limitations that are well-documented

For each vulnerability found, provide:
1. severity: "CRITICAL" or "HIGH" or "MEDIUM" (only report real bugs)
2. function: The function name where the bug exists
3. title: Short descriptive title (max 80 chars)
4. description: Technical explanation of the bug
5. attack_scenario: Step-by-step attack that exploits this bug
6. confidence: 0.0-1.0 (how confident you are this is a real bug)
7. line_hint: Approximate line number if identifiable

Respond with a JSON array of findings. If no logic bugs exist, return [].

Example format:
[
  {
    "severity": "CRITICAL",
    "function": "transfer",
    "title": "Missing balance check allows double-spend",
    "description": "The transfer function does not verify...",
    "attack_scenario": "1. Attacker deposits 100 SOL\\n2. Attacker calls transfer(200)\\n3. ...",
    "confidence": 0.95,
    "line_hint": 42
  }
]"""


class SemanticAnalyzer:
    """Analyzes Anchor program source code using LLM for logic vulnerability detection."""

    def __init__(self, api_key: Optional[str] = None, model: str = "claude-sonnet-4-20250514"):
        self.api_key = api_key or os.environ.get("ANTHROPIC_API_KEY", "")
        self.model = model
        if not self.api_key:
            raise ValueError(
                "Anthropic API key required. Set ANTHROPIC_API_KEY environment variable "
                "or pass api_key parameter."
            )

    def analyze(self, source_code: str, filename: str = "program.rs") -> List[SemanticFinding]:
        """Analyze source code and return list of semantic findings."""
        try:
            import httpx
        except ImportError:
            raise ImportError("httpx is required: pip install httpx")

        user_message = (
            f"Analyze this Anchor/Solana program for logic vulnerabilities.\n"
            f"Filename: {filename}\n\n"
            f"```rust\n{source_code}\n```"
        )

        response = httpx.post(
            "https://api.anthropic.com/v1/messages",
            headers={
                "Content-Type": "application/json",
                "x-api-key": self.api_key,
                "anthropic-version": "2023-06-01",
            },
            json={
                "model": self.model,
                "max_tokens": 4096,
                "system": SYSTEM_PROMPT,
                "messages": [{"role": "user", "content": user_message}],
            },
            timeout=120.0,
        )

        if response.status_code != 200:
            raise RuntimeError(
                f"Anthropic API error {response.status_code}: {response.text[:500]}"
            )

        data = response.json()
        content = data.get("content", [{}])[0].get("text", "")

        return self._parse_response(content)

    def _parse_response(self, text: str) -> List[SemanticFinding]:
        """Parse LLM response into SemanticFinding objects."""
        # Extract JSON from response (handle markdown code blocks)
        json_str = text.strip()
        if "```json" in json_str:
            json_str = json_str.split("```json")[1].split("```")[0].strip()
        elif "```" in json_str:
            json_str = json_str.split("```")[1].split("```")[0].strip()

        try:
            findings_data = json.loads(json_str)
        except json.JSONDecodeError:
            # Try to find JSON array in the text
            start = text.find("[")
            end = text.rfind("]") + 1
            if start >= 0 and end > start:
                try:
                    findings_data = json.loads(text[start:end])
                except json.JSONDecodeError:
                    return []
            else:
                return []

        if not isinstance(findings_data, list):
            findings_data = [findings_data]

        findings = []
        for item in findings_data:
            if not isinstance(item, dict):
                continue
            try:
                finding = SemanticFinding(
                    severity=item.get("severity", "MEDIUM").upper(),
                    function=item.get("function", "unknown"),
                    title=item.get("title", "Untitled finding"),
                    description=item.get("description", ""),
                    attack_scenario=item.get("attack_scenario", ""),
                    confidence=float(item.get("confidence", 0.5)),
                    line_hint=item.get("line_hint"),
                    category="logic",
                )
                findings.append(finding)
            except (ValueError, TypeError):
                continue

        return findings

    @staticmethod
    def load_demo_findings() -> List[SemanticFinding]:
        """Return pre-computed findings for the vulnerable lending pool demo.

        These findings represent what the LLM analysis discovers when run
        against the example lending pool program. They are provided so the
        demo pipeline can run without an API key.
        """
        return [
            SemanticFinding(
                severity="CRITICAL",
                function="borrow",
                title="Collateral check ignores existing debt",
                description=(
                    "The borrow() function validates collateral with "
                    "`require!(user.deposited >= amount)` but never subtracts "
                    "the user's existing borrowed amount. A user who deposited "
                    "100 SOL can borrow 100 SOL, then call borrow again for "
                    "another 100 SOL, because `user.deposited` remains 100 and "
                    "the check passes every time. This allows unlimited "
                    "borrowing against the same collateral."
                ),
                attack_scenario=(
                    "1. Attacker deposits 100 SOL into the pool\n"
                    "2. Attacker calls borrow(100) — passes because deposited(100) >= 100\n"
                    "3. Attacker calls borrow(100) again — still passes because deposited is still 100\n"
                    "4. Attacker repeats until pool is drained\n"
                    "5. Attacker walks away with all pool funds, leaving 100 SOL collateral"
                ),
                confidence=0.97,
                line_hint=63,
            ),
            SemanticFinding(
                severity="CRITICAL",
                function="withdraw",
                title="Withdrawal permitted with outstanding borrows",
                description=(
                    "The withdraw() function checks `user.deposited >= amount` "
                    "but does not verify that the remaining deposit covers "
                    "outstanding borrows. A user can deposit 100 SOL, borrow "
                    "90 SOL, then withdraw all 100 SOL. The pool loses 90 SOL "
                    "because the borrow is never repaid and the collateral is gone."
                ),
                attack_scenario=(
                    "1. Attacker deposits 100 SOL\n"
                    "2. Attacker borrows 90 SOL (collateral check passes: 100 >= 90)\n"
                    "3. Attacker withdraws 100 SOL (balance check passes: 100 >= 100)\n"
                    "4. Attacker now has 190 SOL (100 withdrawn + 90 borrowed)\n"
                    "5. Pool lost 90 SOL with no recourse — collateral is zero, debt uncollectable"
                ),
                confidence=0.96,
                line_hint=100,
            ),
            SemanticFinding(
                severity="HIGH",
                function="liquidate",
                title="Integer overflow in liquidation debt calculation",
                description=(
                    "The liquidate() function computes debt as "
                    "`user.borrowed * pool.interest_rate * pool.total_borrows / 10000`. "
                    "This multiplication chain on u64 values overflows when the "
                    "pool has significant total borrows and interest. The overflow "
                    "wraps the result to a small number, causing the liquidation "
                    "threshold check to fail. Insolvent positions become immune "
                    "to liquidation, accumulating bad debt in the protocol."
                ),
                attack_scenario=(
                    "1. Pool grows to have total_borrows = 1_000_000 SOL (1e15 lamports)\n"
                    "2. Interest rate is set to 500 (5%)\n"
                    "3. Attacker borrows maximum amount against minimal collateral\n"
                    "4. debt_with_interest = borrowed * 500 * 1e15 / 10000 overflows u64\n"
                    "5. Overflowed value is tiny, so `debt > deposit * threshold` is false\n"
                    "6. Liquidation reverts with PositionHealthy error\n"
                    "7. Attacker's insolvent position persists, draining pool value"
                ),
                confidence=0.92,
                line_hint=150,
            ),
        ]
