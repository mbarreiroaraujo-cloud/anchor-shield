"""
ANCHOR-004: Account Type Cosplay / Missing Discriminator Check

Detects when raw AccountInfo is used to deserialize account data without
proper type checking. Anchor's Account<T> wrapper automatically verifies the
8-byte discriminator and program owner, but raw AccountInfo skips these checks
entirely. An attacker can craft an account from another program whose data
layout happens to match the expected fields.
"""

import re
from scanner.patterns.base import VulnerabilityPattern, Finding


class TypeCosplayPattern(VulnerabilityPattern):
    id = "ANCHOR-004"
    name = "Account Type Cosplay — Missing Discriminator Check"
    severity = "Medium"
    description = (
        "Raw AccountInfo used to deserialize account data without verifying "
        "discriminator or program owner. An attacker can substitute a fake "
        "account from another program with matching data layout."
    )

    # Known safe AccountInfo uses (system accounts, signers, programs)
    SAFE_FIELD_NAMES = {
        "system_program", "token_program", "rent", "clock",
        "associated_token_program", "authority", "payer", "owner",
        "signer", "fee_payer", "rent_sysvar",
    }

    def scan(self, file_path: str, content: str) -> list[Finding]:
        findings = []

        for struct_name, struct_body, struct_start in self._find_derive_accounts_structs(content):
            # Find AccountInfo and UncheckedAccount fields using simple line-by-line scan
            lines = struct_body.split("\n")
            for i, line in enumerate(lines):
                actual_line = struct_start + i + 1  # +1 for opening brace line

                # Check for AccountInfo<'info> or UncheckedAccount<'info>
                ai_match = re.search(r"(\w+)\s*:\s*(AccountInfo\s*<)", line)
                uc_match = re.search(r"(\w+)\s*:\s*(UncheckedAccount\s*<)", line)
                match = ai_match or uc_match
                if not match:
                    continue

                field_name = match.group(1)
                type_name = "AccountInfo" if ai_match else "UncheckedAccount"

                # Skip known safe field names
                if field_name.lower().rstrip("_") in self.SAFE_FIELD_NAMES:
                    continue
                if field_name.endswith("_program") or field_name == "program":
                    continue

                # Look for attributes in preceding lines (up to 10 lines back)
                context_start = max(0, i - 10)
                context_block = "\n".join(lines[context_start:i + 1])

                # Skip if signer constraint
                if re.search(r"\bsigner\b", context_block):
                    continue

                # Skip if owner constraint
                if re.search(r"owner\s*=|constraint\s*=\s*[^,]*\.owner\s*==", context_block):
                    continue

                # Skip if CHECK comment
                if re.search(r"///\s*CHECK\s*:", context_block):
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
                            f"raw {type_name} without owner or discriminator "
                            f"verification. An attacker can substitute a fake "
                            f"account from another program."
                        ),
                        root_cause=self.get_root_cause(),
                        exploit_scenario=self.get_exploit_scenario(),
                        fix_recommendation=self.get_fix_recommendation(),
                        code_snippet=snippet,
                        before_after_state={
                            "before": (
                                "Legitimate account: owner=this_program, "
                                "data=valid_state, discriminator=correct"
                            ),
                            "after": (
                                "Attacker-crafted account: owner=attacker_program, "
                                "data=malicious_state (matching byte layout), "
                                "discriminator=wrong (but unchecked)"
                            ),
                            "damage": (
                                "Program operates on attacker-controlled data "
                                "believing it's a legitimate account. Can lead to "
                                "arbitrary state manipulation or fund theft."
                            ),
                        },
                        impact={
                            "attack_cost": "< 0.01 SOL (create fake account + call instruction)",
                            "exploitability": (
                                "High — most common vulnerability in Solana programs"
                            ),
                            "breach_cost_context": (
                                "Missing owner/type checks are the #1 finding in "
                                "professional Solana security audits. Using raw "
                                "AccountInfo without owner verification allows "
                                "attackers to substitute crafted accounts."
                            ),
                        },
                        anchor_versions_affected="All versions (developer error, not framework bug)",
                        ecosystem_recommendations=[
                            f"Replace {type_name}<'info> with Account<'info, T>",
                            "If AccountInfo is required, add explicit owner check: "
                            "constraint = account.owner == &expected_program::ID",
                            "Add /// CHECK: comment documenting why the raw type is safe",
                        ],
                    )
                )

        return findings

    def get_fix_recommendation(self) -> str:
        return (
            "Replace raw AccountInfo with typed Account<'info, T> which "
            "automatically checks discriminator and owner:\n"
            "  // Before (vulnerable):\n"
            "  pub data_account: AccountInfo<'info>,\n\n"
            "  // After (safe):\n"
            "  pub data_account: Account<'info, MyDataType>,\n\n"
            "If raw AccountInfo is necessary, add explicit checks:\n"
            "  #[account(owner = my_program::ID)]\n"
            "  /// CHECK: Validated via owner constraint\n"
            "  pub data_account: AccountInfo<'info>,"
        )

    def get_root_cause(self) -> str:
        return (
            "Anchor's Account<'info, T> wrapper automatically verifies the 8-byte "
            "discriminator (first 8 bytes of sha256('account:<TypeName>')) and the "
            "account's program owner. Raw AccountInfo skips both checks. Developers "
            "sometimes use AccountInfo for flexibility but forget to add manual "
            "verification, allowing an attacker to pass accounts from arbitrary "
            "programs as long as the data layout happens to match."
        )

    def get_exploit_scenario(self) -> str:
        return (
            "1. Program expects a data account with specific fields (e.g., balance, owner)\n"
            "2. Field is declared as AccountInfo<'info> without owner check\n"
            "3. Attacker creates account in their own program with matching data layout\n"
            "4. Attacker sets balance field to MAX_VALUE in their fake account\n"
            "5. Attacker passes fake account to victim program\n"
            "6. Program reads balance=MAX_VALUE and processes accordingly\n"
            "7. Attacker extracts funds or manipulates state based on fake data"
        )
