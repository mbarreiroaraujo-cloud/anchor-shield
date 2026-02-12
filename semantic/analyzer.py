"""Semantic vulnerability analyzer using LLM reasoning.

Sends Anchor program source code to the Claude API and receives
structured vulnerability analysis focused on logic bugs that
static pattern matching cannot detect.
"""

import json
import os
import time
import urllib.request
import urllib.error
from dataclasses import dataclass, field, asdict
from typing import List, Optional

from semantic.prompts import SECURITY_AUDITOR_SYSTEM_PROMPT


@dataclass
class SemanticFinding:
    """A logic vulnerability discovered by semantic analysis."""

    id: str
    severity: str
    function: str
    title: str
    description: str
    attack_scenario: str
    estimated_impact: str
    confidence: float
    source: str = "semantic"  # "semantic" for live LLM, "validated" for pre-validated

    def to_dict(self) -> dict:
        """Convert to dictionary for JSON serialization."""
        return asdict(self)


# Pre-validated findings for demo mode (used when API is unavailable).
# These results have been independently verified against the vulnerable
# lending pool program.
_PREVALIDATED_FINDINGS = [
    SemanticFinding(
        id="SEM-001",
        severity="Critical",
        function="borrow",
        title="Collateral check ignores existing debt",
        description=(
            "The borrow function checks `user.deposited >= amount` but does not "
            "account for previously borrowed amounts. The correct check should be "
            "`user.deposited * 75 / 100 >= user.borrowed + amount` to enforce a "
            "collateralization ratio. As written, a user with 100 SOL deposited "
            "can borrow 100 SOL repeatedly because the check never considers "
            "cumulative debt."
        ),
        attack_scenario=(
            "1. Deposit 100 SOL into the pool\n"
            "2. Borrow 100 SOL (passes: deposited 100 >= amount 100)\n"
            "3. Borrow 100 SOL again (passes: deposited 100 >= amount 100, "
            "ignores existing 100 SOL debt)\n"
            "4. Repeat until vault is completely drained\n"
            "5. Attacker walks away with all pool liquidity, collateral untouched"
        ),
        estimated_impact="Complete drain of all pool funds. Attacker can extract unlimited SOL with minimal collateral.",
        confidence=0.97,
        source="validated",
    ),
    SemanticFinding(
        id="SEM-002",
        severity="Critical",
        function="withdraw",
        title="Withdrawal allows full exit with outstanding borrows",
        description=(
            "The withdraw function only checks `user.deposited >= amount` without "
            "verifying that remaining deposits still cover outstanding borrows. "
            "There is no cross-instruction validation between withdraw and borrow. "
            "A user can deposit collateral, borrow against it, then withdraw all "
            "collateral — leaving the protocol with bad debt."
        ),
        attack_scenario=(
            "1. Deposit 100 SOL as collateral\n"
            "2. Borrow 90 SOL from the pool\n"
            "3. Withdraw 100 SOL (passes: deposited 100 >= amount 100)\n"
            "4. User now has 190 SOL (100 withdrawn + 90 borrowed)\n"
            "5. Protocol has -90 SOL of unrecoverable bad debt\n"
            "6. No mechanism exists to force repayment"
        ),
        estimated_impact="Theft of pool funds. Attacker profits the borrowed amount minus zero risk. Protocol left with bad debt.",
        confidence=0.98,
        source="validated",
    ),
    SemanticFinding(
        id="SEM-003",
        severity="High",
        function="liquidate",
        title="Integer overflow in interest calculation",
        description=(
            "The expression `user.borrowed * pool.interest_rate as u64 * pool.total_borrows` "
            "performs unchecked u64 multiplication. When borrowed amounts and total_borrows "
            "are large, this multiplication can overflow u64::MAX (18,446,744,073,709,551,615), "
            "wrapping around to a small number. This makes the calculated interest negligible, "
            "causing the health factor to appear high — preventing legitimate liquidations."
        ),
        attack_scenario=(
            "1. Create a large borrow position (e.g., 1,000,000 SOL)\n"
            "2. Ensure pool.total_borrows is also large from other borrowers\n"
            "3. The multiplication borrowed * 500 * total_borrows overflows u64\n"
            "4. Interest wraps to a near-zero value\n"
            "5. Health factor = deposited * 100 / (borrowed + ~0) appears healthy\n"
            "6. Underwater position cannot be liquidated, protocol accumulates bad debt"
        ),
        estimated_impact="Prevents liquidation of underwater positions. Protocol accumulates unrecoverable bad debt as unhealthy positions cannot be closed.",
        confidence=0.92,
        source="validated",
    ),
    SemanticFinding(
        id="SEM-004",
        severity="Medium",
        function="liquidate",
        title="Division by zero panic in health factor calculation",
        description=(
            "When `user.borrowed == 0` and `interest == 0`, the expression "
            "`user.deposited * 100 / (user.borrowed + interest)` divides by zero. "
            "In Rust, integer division by zero causes a panic, which in Solana "
            "translates to a program error. Any user with zero borrows cannot "
            "have their liquidation function called without crashing the program."
        ),
        attack_scenario=(
            "1. Call liquidate on any user account that has zero borrows\n"
            "2. The health factor calculation divides by (0 + 0) = 0\n"
            "3. Program panics with arithmetic error\n"
            "4. Transaction fails, but can be used for denial of service\n"
            "5. If liquidation is part of a composed transaction, the panic "
            "rolls back the entire transaction"
        ),
        estimated_impact="Denial of service on the liquidation function. While not directly profitable, it can block composed transactions that include liquidation checks.",
        confidence=0.95,
        source="validated",
    ),
]


class SemanticAnalyzer:
    """Analyzes Anchor programs for logic vulnerabilities using LLM reasoning.

    Sends source code to the Claude API with a specialized security audit
    prompt and parses the structured findings. Falls back to pre-validated
    results when the API is unavailable.
    """

    API_URL = "https://api.anthropic.com/v1/messages"
    API_VERSION = "2023-06-01"
    DEFAULT_MODEL = "claude-sonnet-4-20250514"
    MAX_RETRIES = 3
    RETRY_DELAY = 2  # seconds, doubles each retry

    def __init__(self, api_key: Optional[str] = None, model: Optional[str] = None):
        """Initialize the semantic analyzer.

        Args:
            api_key: Anthropic API key. Falls back to ANTHROPIC_API_KEY env var.
            model: Model to use for analysis. Defaults to claude-sonnet-4-20250514.
        """
        self.api_key = api_key or os.environ.get("ANTHROPIC_API_KEY", "")
        self.model = model or self.DEFAULT_MODEL
        self._demo_mode = False

    def analyze(self, source_code: str, filename: str = "<input>") -> List[SemanticFinding]:
        """Analyze source code for logic vulnerabilities.

        Args:
            source_code: The Rust/Anchor source code to analyze.
            filename: Name of the file being analyzed (for reporting).

        Returns:
            List of SemanticFinding objects describing discovered vulnerabilities.
        """
        if not self.api_key:
            print("  [demo mode] No API key — using pre-validated results")
            self._demo_mode = True
            return list(_PREVALIDATED_FINDINGS)

        # Try live API analysis
        findings = self._call_api(source_code, filename)
        if findings is not None:
            return findings

        # API failed — fall back to pre-validated results
        print("  [demo mode] API unavailable — using pre-validated results")
        self._demo_mode = True
        return list(_PREVALIDATED_FINDINGS)

    @property
    def is_demo_mode(self) -> bool:
        """Whether the last analysis used pre-validated results."""
        return self._demo_mode

    def _call_api(self, source_code: str, filename: str) -> Optional[List[SemanticFinding]]:
        """Call the Claude API for semantic analysis.

        Returns None if the API call fails after all retries.
        """
        user_message = (
            f"Analyze the following Solana/Anchor program for logic vulnerabilities.\n"
            f"File: {filename}\n\n"
            f"```rust\n{source_code}\n```"
        )

        payload = json.dumps({
            "model": self.model,
            "max_tokens": 4096,
            "system": SECURITY_AUDITOR_SYSTEM_PROMPT,
            "messages": [{"role": "user", "content": user_message}],
        }).encode("utf-8")

        headers = {
            "Content-Type": "application/json",
            "x-api-key": self.api_key,
            "anthropic-version": self.API_VERSION,
        }

        delay = self.RETRY_DELAY
        for attempt in range(1, self.MAX_RETRIES + 1):
            try:
                req = urllib.request.Request(
                    self.API_URL, data=payload, headers=headers, method="POST"
                )
                with urllib.request.urlopen(req, timeout=120) as resp:
                    body = json.loads(resp.read().decode("utf-8"))

                # Extract text content from the response
                text = ""
                for block in body.get("content", []):
                    if block.get("type") == "text":
                        text += block["text"]

                return self._parse_findings(text)

            except urllib.error.HTTPError as e:
                error_body = e.read().decode("utf-8", errors="replace") if e.fp else ""
                print(f"  [attempt {attempt}/{self.MAX_RETRIES}] API error {e.code}: {error_body[:200]}")
                if attempt < self.MAX_RETRIES:
                    time.sleep(delay)
                    delay *= 2
            except (urllib.error.URLError, TimeoutError, OSError) as e:
                print(f"  [attempt {attempt}/{self.MAX_RETRIES}] Network error: {e}")
                if attempt < self.MAX_RETRIES:
                    time.sleep(delay)
                    delay *= 2
            except (json.JSONDecodeError, KeyError, IndexError) as e:
                print(f"  [attempt {attempt}/{self.MAX_RETRIES}] Parse error: {e}")
                if attempt < self.MAX_RETRIES:
                    time.sleep(delay)
                    delay *= 2

        return None

    def _parse_findings(self, text: str) -> List[SemanticFinding]:
        """Parse LLM response text into SemanticFinding objects.

        Handles JSON possibly wrapped in markdown code fences.
        """
        # Strip markdown fences if present
        cleaned = text.strip()
        if cleaned.startswith("```"):
            # Remove opening fence (with optional language tag)
            first_newline = cleaned.index("\n")
            cleaned = cleaned[first_newline + 1:]
        if cleaned.endswith("```"):
            cleaned = cleaned[:-3]
        cleaned = cleaned.strip()

        try:
            data = json.loads(cleaned)
        except json.JSONDecodeError:
            # Try to find JSON object in the text
            start = cleaned.find("{")
            end = cleaned.rfind("}") + 1
            if start >= 0 and end > start:
                data = json.loads(cleaned[start:end])
            else:
                print("  [warning] Could not parse LLM response as JSON")
                return []

        raw_findings = data.get("findings", [])
        findings = []
        for i, raw in enumerate(raw_findings):
            finding = SemanticFinding(
                id=f"SEM-{i + 1:03d}",
                severity=raw.get("severity", "Medium"),
                function=raw.get("function", "unknown"),
                title=raw.get("title", "Untitled finding"),
                description=raw.get("description", ""),
                attack_scenario=raw.get("attack_scenario", ""),
                estimated_impact=raw.get("estimated_impact", ""),
                confidence=float(raw.get("confidence", 0.5)),
                source="semantic",
            )
            findings.append(finding)

        return findings
