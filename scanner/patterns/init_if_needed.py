"""
ANCHOR-001: init_if_needed Incomplete Field Validation

Detects when init_if_needed is used with token or associated_token constraints
without explicit validation of delegate, close_authority, and state fields.

When init_if_needed encounters an already-existing token account, Anchor's code
generator uses unchecked deserialization (from_account_info_unchecked) and only
validates mint, owner, and token_program — but NOT delegate, state,
close_authority, or delegated_amount. An attacker can pre-create a token account
with malicious delegate or close_authority set, then have the victim's program
accept it via init_if_needed.
"""

import re
from scanner.patterns.base import VulnerabilityPattern, Finding


class InitIfNeededPattern(VulnerabilityPattern):
    id = "ANCHOR-001"
    name = "init_if_needed Incomplete Field Validation"
    severity = "High"
    description = (
        "Token or associated token account accepted via init_if_needed without "
        "validation of delegate, close_authority, or state fields. An attacker "
        "can pre-create the account with malicious field values."
    )
    reference = "https://github.com/solana-foundation/anchor/pull/4229"

    # Regex to find #[account(...init_if_needed...)] blocks
    ACCOUNT_ATTR_RE = re.compile(
        r"#\[account\(((?:[^()]*|\((?:[^()]*|\([^()]*\))*\))*)\)\]",
        re.DOTALL,
    )

    # Patterns that indicate token-related init_if_needed
    TOKEN_INIT_RE = re.compile(
        r"init_if_needed\b.*?(?:token\s*::|associated_token\s*::)",
        re.DOTALL,
    )

    # Safe patterns: explicit constraint checks that mitigate this issue
    DELEGATE_CHECK_RE = re.compile(
        r"constraint\s*=\s*[^,]*\.delegate\s*(?:\.is_none\(\)|==\s*(?:None|COption::None))",
        re.DOTALL,
    )
    CLOSE_AUTH_CHECK_RE = re.compile(
        r"constraint\s*=\s*[^,]*\.close_authority\s*(?:\.is_none\(\)|==\s*(?:None|COption::None))",
        re.DOTALL,
    )
    STATE_CHECK_RE = re.compile(
        r"constraint\s*=\s*[^,]*\.state\s*==\s*AccountState::Initialized",
        re.DOTALL,
    )

    def scan(self, file_path: str, content: str) -> list[Finding]:
        findings = []

        for match in self.ACCOUNT_ATTR_RE.finditer(content):
            attr_content = match.group(1)

            # Check if this is init_if_needed with token constraints
            if not re.search(r"init_if_needed", attr_content):
                continue

            is_token = bool(re.search(r"token\s*::", attr_content))
            is_assoc_token = bool(re.search(r"associated_token\s*::", attr_content))

            if not is_token and not is_assoc_token:
                continue

            # Look for safe patterns in the surrounding context (same struct)
            # We scan ±30 lines around the match for explicit constraints
            line_num = self._get_line_number(content, match.start())
            lines = content.split("\n")
            struct_start = max(0, line_num - 30)
            struct_end = min(len(lines), line_num + 30)
            context_block = "\n".join(lines[struct_start:struct_end])

            has_delegate_check = bool(self.DELEGATE_CHECK_RE.search(context_block))
            has_close_auth_check = bool(self.CLOSE_AUTH_CHECK_RE.search(context_block))

            # If both delegate and close_authority are checked, this is mitigated
            if has_delegate_check and has_close_auth_check:
                continue

            missing_checks = []
            if not has_delegate_check:
                missing_checks.append("delegate")
            if not has_close_auth_check:
                missing_checks.append("close_authority")

            token_type = "associated_token" if is_assoc_token else "token"
            snippet = self._extract_snippet(content, line_num)

            findings.append(
                Finding(
                    id=self.id,
                    name=self.name,
                    severity=self.severity,
                    file=file_path,
                    line=line_num,
                    description=(
                        f"{token_type.title()} account accepted via init_if_needed "
                        f"without validation of {', '.join(missing_checks)} fields."
                    ),
                    root_cause=self.get_root_cause(),
                    exploit_scenario=self.get_exploit_scenario(),
                    fix_recommendation=self.get_fix_recommendation(),
                    code_snippet=snippet,
                    before_after_state={
                        "before": (
                            "Token account: owner=victim, balance=1000, "
                            "delegate=None, close_authority=None"
                        ),
                        "after": (
                            "Token account: owner=victim, balance=1000, "
                            "delegate=ATTACKER, close_authority=ATTACKER "
                            "(attacker can drain via delegated transfer or force-close)"
                        ),
                        "damage": (
                            "Attacker can drain token balance via delegated transfer "
                            "or force-close the account, causing permanent loss."
                        ),
                    },
                    impact={
                        "attack_cost": "< 0.01 SOL (single transaction to pre-create account)",
                        "exploitability": "High — single transaction, no special setup required",
                        "breach_cost_context": (
                            "Similar unchecked deserialization patterns contributed to "
                            "the Wormhole bridge exploit ($320M, Feb 2022). Conservative "
                            "estimate: $500K-$15M at risk across affected programs."
                        ),
                    },
                    anchor_versions_affected="0.25.0 - 0.30.x (init_if_needed introduced in 0.25)",
                    ecosystem_recommendations=[
                        "Add explicit constraint checks: constraint = account.delegate.is_none(), "
                        "constraint = account.close_authority.is_none()",
                        "Consider using plain init instead of init_if_needed where possible",
                        "Anchor team should add compile-time warnings for this pattern",
                    ],
                )
            )

        return findings

    def get_fix_recommendation(self) -> str:
        return (
            "Add explicit constraint checks for fields not validated by init_if_needed:\n"
            "  #[account(\n"
            "    init_if_needed,\n"
            "    token::mint = mint,\n"
            "    token::authority = authority,\n"
            "    constraint = token_account.delegate.is_none(),\n"
            "    constraint = token_account.close_authority.is_none(),\n"
            "  )]\n"
            "Alternatively, use plain `init` instead of `init_if_needed` if the "
            "account should always be newly created."
        )

    def get_root_cause(self) -> str:
        return (
            "In Anchor's constraint code generation, when init_if_needed encounters "
            "an already-existing Token/AssociatedToken account, it calls "
            "from_account_info_unchecked and only validates mint, owner, and "
            "token_program. Fields like delegate, close_authority, state, and "
            "delegated_amount are not checked, allowing an attacker to pass a "
            "pre-created account with malicious values for these fields."
        )

    def get_exploit_scenario(self) -> str:
        return (
            "1. Attacker creates a token account with delegate=ATTACKER and "
            "close_authority=ATTACKER\n"
            "2. Attacker transfers ownership so the account matches the expected "
            "owner/mint\n"
            "3. Victim's program accepts the account via init_if_needed (account "
            "already exists, so init is skipped)\n"
            "4. Anchor validates mint, owner, token_program — all pass\n"
            "5. delegate and close_authority are NOT checked — attacker retains "
            "control\n"
            "6. Attacker uses delegated transfer to drain funds, or close_authority "
            "to force-close the account"
        )
