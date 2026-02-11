"""Base class for vulnerability detection patterns."""

import re
from dataclasses import dataclass, field
from typing import Optional


@dataclass
class Finding:
    """A single vulnerability finding from a scan."""

    id: str
    name: str
    severity: str
    file: str
    line: int
    description: str
    root_cause: str
    exploit_scenario: str
    fix_recommendation: str
    code_snippet: str = ""
    before_after_state: Optional[dict] = None
    impact: Optional[dict] = None
    reference: str = "https://github.com/solana-foundation/anchor/pull/4229"
    anchor_versions_affected: str = "0.25.0 - 0.30.x"
    ecosystem_recommendations: list = field(default_factory=list)

    def to_dict(self) -> dict:
        """Convert finding to dictionary for JSON serialization."""
        return {
            "id": self.id,
            "name": self.name,
            "severity": self.severity,
            "file": self.file,
            "line": self.line,
            "description": self.description,
            "root_cause": self.root_cause,
            "exploit_scenario": self.exploit_scenario,
            "fix_recommendation": self.fix_recommendation,
            "code_snippet": self.code_snippet,
            "before_after_state": self.before_after_state,
            "impact": self.impact,
            "reference": self.reference,
            "anchor_versions_affected": self.anchor_versions_affected,
            "ecosystem_recommendations": self.ecosystem_recommendations,
        }


class VulnerabilityPattern:
    """Base class for vulnerability detection patterns."""

    id: str = ""
    name: str = ""
    severity: str = ""
    description: str = ""
    reference: str = "https://github.com/solana-foundation/anchor/pull/4229"

    def scan(self, file_path: str, content: str) -> list[Finding]:
        """Scan a file for this vulnerability pattern."""
        raise NotImplementedError

    def get_fix_recommendation(self) -> str:
        """Return actionable fix recommendation."""
        raise NotImplementedError

    def get_root_cause(self) -> str:
        """Return the root cause explanation."""
        raise NotImplementedError

    def get_exploit_scenario(self) -> str:
        """Return a step-by-step exploit scenario."""
        raise NotImplementedError

    @staticmethod
    def _get_line_number(content: str, pos: int) -> int:
        """Get line number from character position in content."""
        return content[:pos].count("\n") + 1

    @staticmethod
    def _extract_snippet(content: str, line: int, context: int = 3) -> str:
        """Extract code snippet around a given line."""
        lines = content.split("\n")
        start = max(0, line - context - 1)
        end = min(len(lines), line + context)
        snippet_lines = []
        for i in range(start, end):
            prefix = ">>> " if i == line - 1 else "    "
            snippet_lines.append(f"{prefix}{i + 1:4d} | {lines[i]}")
        return "\n".join(snippet_lines)

    @staticmethod
    def _find_derive_accounts_structs(content: str) -> list[tuple[str, str, int]]:
        """Find all #[derive(Accounts)] structs using brace-counting (not regex).

        Returns list of (struct_name, struct_body, start_line).
        """
        results = []
        # Find all derive(Accounts) occurrences
        for m in re.finditer(r"#\[derive\(Accounts\)\]", content):
            pos = m.end()
            # Find 'pub struct Name' after the derive
            struct_match = re.search(r"\s*(?:#\[.*?\]\s*)*pub\s+struct\s+(\w+)", content[pos:pos+500])
            if not struct_match:
                continue
            struct_name = struct_match.group(1)
            # Find opening brace
            brace_start = content.find("{", pos + struct_match.end())
            if brace_start == -1:
                continue
            # Count braces to find the matching close
            depth = 1
            i = brace_start + 1
            while i < len(content) and depth > 0:
                if content[i] == "{":
                    depth += 1
                elif content[i] == "}":
                    depth -= 1
                i += 1
            if depth == 0:
                struct_body = content[brace_start + 1 : i - 1]
                start_line = content[:m.start()].count("\n") + 1
                results.append((struct_name, struct_body, start_line))
        return results

    @staticmethod
    def _parse_struct_fields(struct_body: str, struct_start: int) -> list[dict]:
        """Parse fields from a derive(Accounts) struct body.

        Handles multi-line #[account(...)] attributes by counting parentheses.
        Returns list of dicts with: name, type, line, attrs (combined attribute string).
        """
        fields = []
        lines = struct_body.split("\n")
        current_attrs = []
        in_attr = False
        paren_depth = 0

        for i, line in enumerate(lines):
            stripped = line.strip()

            # Handle doc comments
            if stripped.startswith("///"):
                current_attrs.append(stripped)
                continue

            # Handle attributes (possibly multi-line)
            if in_attr:
                current_attrs.append(stripped)
                paren_depth += stripped.count("(") - stripped.count(")")
                if paren_depth <= 0:
                    in_attr = False
                    paren_depth = 0
                continue

            if stripped.startswith("#["):
                current_attrs.append(stripped)
                paren_depth = stripped.count("(") - stripped.count(")")
                if paren_depth > 0:
                    in_attr = True
                continue

            # Try to match a field declaration
            field_match = re.search(
                r"(?:pub\s+)?(\w+)\s*:\s*(.+?)(?:,\s*)?$", stripped
            )
            if field_match:
                fields.append({
                    "name": field_match.group(1),
                    "type": field_match.group(2).strip().rstrip(","),
                    "line": struct_start + i + 1,
                    "attrs": " ".join(current_attrs),
                })
                current_attrs = []
            elif stripped and not stripped.startswith("//"):
                # Non-field, non-comment line resets attrs
                current_attrs = []

        return fields
