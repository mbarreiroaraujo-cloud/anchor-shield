"""
ANCHOR-006: Missing Owner Validation

Detects when accounts are deserialized or used without verifying the program
owner field. This is the most common vulnerability in Solana programs — using
raw AccountInfo without checking that the account is owned by the expected
program allows attackers to pass fake accounts from programs they control.
"""

import re
from scanner.patterns.base import VulnerabilityPattern, Finding


class MissingOwnerPattern(VulnerabilityPattern):
    id = "ANCHOR-006"
    name = "Missing Owner Validation"
    severity = "High"
    description = (
        "Account used without verifying program ownership. An attacker can "
        "substitute a fake account from an arbitrary program."
    )

    SAFE_TYPES = {
        "Account", "InterfaceAccount", "Program", "Interface",
        "Signer", "SystemAccount", "AccountLoader",
    }

    SYSTEM_FIELD_NAMES = {
        "system_program", "token_program", "rent", "clock",
        "associated_token_program", "sysvar_rent", "sysvar_clock",
    }

    def scan(self, file_path: str, content: str) -> list[Finding]:
        findings = []

        for struct_name, struct_body, struct_start in self._find_derive_accounts_structs(content):
            lines = struct_body.split("\n")
            current_attrs = []
            for i, line in enumerate(lines):
                stripped = line.strip()
                if stripped.startswith("#[") or stripped.startswith("///"):
                    current_attrs.append(stripped)
                    continue

                # Check for AccountInfo or UncheckedAccount
                ai_match = re.search(r"(\w+)\s*:\s*AccountInfo\s*<", stripped)
                uc_match = re.search(r"(\w+)\s*:\s*UncheckedAccount\s*<", stripped)
                match = ai_match or uc_match
                if not match:
                    current_attrs = []
                    continue

                field_name = match.group(1)
                type_name = "AccountInfo" if ai_match else "UncheckedAccount"
                actual_line = struct_start + i + 1
                attrs_str = " ".join(current_attrs)
                current_attrs = []

                # Skip known safe field names
                if field_name.lower().rstrip("_") in self.SYSTEM_FIELD_NAMES:
                    continue
                if field_name.endswith("_program") or field_name == "program":
                    continue

                # Skip if signer constraint
                if re.search(r"\bsigner\b", attrs_str):
                    continue

                # Skip if owner constraint
                if re.search(r"owner\s*=|constraint\s*=\s*[^,]*\.owner\s*==", attrs_str):
                    continue

                # Skip CHECK comment
                if re.search(r"///\s*CHECK\s*:", attrs_str):
                    continue

                snippet = self._extract_snippet(content, actual_line)

                findings.append(
                    Finding(
                        id=self.id,
                        name=self.name,
                        severity=self.severity,
                        file=file_path,
                        line=actual_line,
                        description=(
                            f"In struct {struct_name}: field '{field_name}' uses "
                            f"raw {type_name} without owner validation or CHECK "
                            f"documentation."
                        ),
                        root_cause=self.get_root_cause(),
                        exploit_scenario=self.get_exploit_scenario(),
                        fix_recommendation=self.get_fix_recommendation(),
                        code_snippet=snippet,
                        before_after_state={
                            "before": "Expected: account owned by this program",
                            "after": "Actual: attacker passes account from their own program",
                            "damage": "Arbitrary state manipulation via fake account data.",
                        },
                        impact={
                            "attack_cost": "< 0.01 SOL",
                            "exploitability": "High — most common Solana vulnerability",
                            "breach_cost_context": "Missing owner checks: #1 audit finding in professional Solana security audits.",
                        },
                        anchor_versions_affected="All versions (developer-side pattern)",
                        ecosystem_recommendations=[
                            f"Replace {type_name}<'info> with Account<'info, T>",
                            "Add #[account(owner = program::ID)] constraint",
                            "Add /// CHECK: documentation",
                        ],
                    )
                )

        return findings

    def get_fix_recommendation(self) -> str:
        return (
            "Use Account<'info, T> for automatic owner + discriminator check, or add:\n"
            "  #[account(owner = my_program::ID)]\n"
            "  /// CHECK: Owner verified via constraint\n"
            "  pub data: AccountInfo<'info>,"
        )

    def get_root_cause(self) -> str:
        return (
            "Solana accounts are byte arrays with an owner field. Any program can create "
            "accounts with arbitrary data. Anchor's Account<T> verifies discriminator and "
            "owner. Raw AccountInfo provides no verification."
        )

    def get_exploit_scenario(self) -> str:
        return (
            "1. Program deserializes without owner check\n"
            "2. Attacker creates matching account in their program\n"
            "3. Attacker passes fake account to victim program\n"
            "4. Program operates on forged data"
        )
