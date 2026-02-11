"""
ANCHOR-002: Duplicate Mutable Account Bypass

Detects when init_if_needed accounts coexist with other mutable accounts of
compatible types, potentially bypassing Anchor's duplicate mutable account check.

In Anchor's generated code, the duplicate mutable account check explicitly
excludes accounts with init constraints. If init_if_needed is used and the
account already exists, it is effectively mutable but bypasses the duplicate
check. An attacker could pass the same account for both an init_if_needed field
and a regular mutable field.
"""

import re
from scanner.patterns.base import VulnerabilityPattern, Finding


class DuplicateMutablePattern(VulnerabilityPattern):
    id = "ANCHOR-002"
    name = "Duplicate Mutable Account Bypass"
    severity = "Medium"
    description = (
        "init_if_needed accounts are excluded from Anchor's duplicate mutable "
        "account check. If the account already exists, an attacker could pass "
        "the same account for both the init_if_needed field and another mutable "
        "field, leading to unexpected double-mutation."
    )
    reference = "https://github.com/solana-foundation/anchor/pull/4229"

    def scan(self, file_path: str, content: str) -> list[Finding]:
        findings = []

        for struct_name, struct_body, struct_start in self._find_derive_accounts_structs(content):
            init_if_needed_fields = []
            mutable_fields = []

            for field in self._parse_struct_fields(struct_body, struct_start):
                attrs_str = field["attrs"]
                has_init_if_needed = bool(re.search(r"init_if_needed", attrs_str))
                has_mut = bool(re.search(r"\bmut\b", attrs_str))

                if has_init_if_needed:
                    init_if_needed_fields.append((field["name"], field["type"], field["line"]))
                elif has_mut:
                    mutable_fields.append((field["name"], field["type"], field["line"]))

            if not init_if_needed_fields or not mutable_fields:
                continue

            for init_field, init_type, init_line in init_if_needed_fields:
                for mut_field, mut_type, _ in mutable_fields:
                    init_base = self._extract_base_type(init_type)
                    mut_base = self._extract_base_type(mut_type)

                    if init_base and mut_base and init_base == mut_base:
                        snippet = self._extract_snippet(content, init_line)
                        findings.append(
                            Finding(
                                id=self.id,
                                name=self.name,
                                severity=self.severity,
                                file=file_path,
                                line=init_line,
                                description=(
                                    f"In struct {struct_name}: init_if_needed field "
                                    f"'{init_field}' ({init_base}) coexists with mutable "
                                    f"field '{mut_field}' ({mut_base}). The init_if_needed "
                                    f"field is excluded from Anchor's duplicate mutable "
                                    f"account check."
                                ),
                                root_cause=self.get_root_cause(),
                                exploit_scenario=self.get_exploit_scenario(),
                                fix_recommendation=self.get_fix_recommendation(),
                                code_snippet=snippet,
                                before_after_state={
                                    "before": "Account X passed as both fields. State: balance=1000",
                                    "after": "Account X mutated twice. State: balance=0 (double withdrawal)",
                                    "damage": "Double-mutation leads to accounting errors or fund extraction.",
                                },
                                impact={
                                    "attack_cost": "< 0.01 SOL (single transaction)",
                                    "exploitability": "Medium — requires compatible types",
                                    "breach_cost_context": "Duplicate account attacks: $100K-$5M exposure.",
                                },
                                anchor_versions_affected="0.25.0 - 0.30.x",
                                ecosystem_recommendations=[
                                    "Add explicit duplicate check: require!(a.key() != b.key())",
                                    "Prefer plain init over init_if_needed",
                                ],
                            )
                        )
                        break

        return findings

    @staticmethod
    def _extract_base_type(type_str: str) -> str:
        """Extract base account type from Account<'info, TokenAccount>."""
        m = re.search(r"Account\s*<\s*'[^,]+,\s*(\w+)", type_str)
        if m:
            return m.group(1)
        m = re.search(r"InterfaceAccount\s*<\s*'[^,]+,\s*(\w+)", type_str)
        if m:
            return m.group(1)
        return ""

    def get_fix_recommendation(self) -> str:
        return (
            "Add an explicit duplicate account check in the instruction body:\n"
            "  require!(init_field.key() != mut_field.key(), CustomError::DuplicateAccount);\n\n"
            "Or use plain `init` instead, which is included in the duplicate check."
        )

    def get_root_cause(self) -> str:
        return (
            "In Anchor's try_accounts code generation, the duplicate mutable account "
            "check filters out fields where constraints.init.is_some(). init_if_needed "
            "accounts are excluded from duplicate detection. If the account already "
            "exists, it behaves as a regular mutable account without duplicate protection."
        )

    def get_exploit_scenario(self) -> str:
        return (
            "1. Program has init_if_needed field A and mutable field B (same type)\n"
            "2. Attacker passes SAME account for both A and B\n"
            "3. Anchor's duplicate check skips A (has init constraint)\n"
            "4. Account already initialized — init_if_needed does nothing\n"
            "5. Both A and B reference the same account\n"
            "6. Instruction body double-mutates, causing state corruption"
        )
