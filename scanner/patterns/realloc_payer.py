"""
ANCHOR-003: Realloc Payer Signer Gap

Detects when realloc constraint payer is not explicitly typed as Signer.

In Anchor's realloc code generation, when account space decreases, lamports are
transferred directly via borrow_mut() without CPI. The payer's signer status is
only enforced by the field's type declaration — if declared as AccountInfo
instead of Signer, the realloc proceeds without verifying the payer actually
signed the transaction, allowing unauthorized lamport extraction.
"""

import re
from scanner.patterns.base import VulnerabilityPattern, Finding


class ReallocPayerPattern(VulnerabilityPattern):
    id = "ANCHOR-003"
    name = "Realloc Payer Missing Signer Verification"
    severity = "Medium"
    description = (
        "Realloc constraint payer may not be verified as a transaction signer. "
        "When account space decreases, lamports are transferred directly to the "
        "payer without CPI, relying entirely on the field type declaration for "
        "signer verification."
    )
    reference = "https://github.com/solana-foundation/anchor/pull/4229"

    REALLOC_PAYER_RE = re.compile(r"realloc\s*::\s*payer\s*=\s*(\w+)")

    def scan(self, file_path: str, content: str) -> list[Finding]:
        findings = []

        for struct_name, struct_body, struct_start in self._find_derive_accounts_structs(content):
            # Find realloc payer names
            payer_names = set()
            realloc_lines = []
            for m in self.REALLOC_PAYER_RE.finditer(struct_body):
                payer_name = m.group(1)
                payer_names.add(payer_name)
                line = struct_start + struct_body[:m.start()].count("\n") + 1
                realloc_lines.append((payer_name, line))

            if not payer_names:
                continue

            # Build field type/attrs map using proper multi-line parser
            field_types = {}
            field_attrs = {}
            for field in self._parse_struct_fields(struct_body, struct_start):
                field_types[field["name"]] = field["type"]
                field_attrs[field["name"]] = field["attrs"]

            for payer_name, realloc_line in realloc_lines:
                if payer_name not in field_types:
                    continue

                payer_type = field_types[payer_name]
                payer_attr = field_attrs.get(payer_name, "")

                # Safe: Signer<'info>
                if re.search(r"Signer\s*<", payer_type):
                    continue

                # Safe: has signer constraint in #[account(...)] (not doc comments)
                # Extract only #[account(...)] parts from attrs
                account_attrs = " ".join(
                    part for part in payer_attr.split(" ")
                    if part.startswith("#[")
                )
                if re.search(r"\bsigner\b", account_attrs):
                    continue

                snippet = self._extract_snippet(content, realloc_line)

                findings.append(
                    Finding(
                        id=self.id,
                        name=self.name,
                        severity=self.severity,
                        file=file_path,
                        line=realloc_line,
                        description=(
                            f"In struct {struct_name}: realloc payer '{payer_name}' is "
                            f"typed as '{payer_type}' instead of Signer<'info>. "
                            f"Lamports transferred without signer verification."
                        ),
                        root_cause=self.get_root_cause(),
                        exploit_scenario=self.get_exploit_scenario(),
                        fix_recommendation=self.get_fix_recommendation(),
                        code_snippet=snippet,
                        before_after_state={
                            "before": "Account: data_len=1000, lamports=10M. Payer: attacker, lamports=0",
                            "after": "Account: data_len=100, lamports=1M. Payer: attacker, lamports=9M",
                            "damage": "Attacker extracts rent lamports without signing.",
                        },
                        impact={
                            "attack_cost": "< 0.01 SOL",
                            "exploitability": "Medium — requires non-Signer payer",
                            "breach_cost_context": "Estimated: $10K-$500K per program.",
                        },
                        anchor_versions_affected="0.26.0 - 0.30.x",
                        ecosystem_recommendations=[
                            "Change payer to Signer<'info>",
                            "Add #[account(signer)] constraint",
                        ],
                    )
                )

        return findings

    def get_fix_recommendation(self) -> str:
        return (
            "Change the realloc payer field type to Signer<'info>:\n"
            "  // Before: pub payer: AccountInfo<'info>,\n"
            "  // After:  pub payer: Signer<'info>,"
        )

    def get_root_cause(self) -> str:
        return (
            "Anchor's realloc codegen transfers lamports via direct borrow_mut(), "
            "bypassing CPI and Solana runtime signer checks. Signer status depends "
            "entirely on the Rust type declaration."
        )

    def get_exploit_scenario(self) -> str:
        return (
            "1. Program uses realloc with non-Signer payer\n"
            "2. Attacker calls with smaller size to trigger shrink\n"
            "3. Excess lamports sent to payer without signer check\n"
            "4. Attacker receives lamports at specified address"
        )
