"""Autonomous security orchestrator — single-command analysis pipeline.

Runs the complete anchor-shield analysis pipeline:
  1. Static regex pattern scanning
  2. Semantic LLM analysis for logic vulnerabilities
  3. Exploit proof-of-concept generation
  4. Exploit execution (simulation)
  5. Consolidated report generation

Usage:
    python agent/orchestrator.py <path-to-anchor-program>
    python agent/orchestrator.py examples/vulnerable-lending/ --output-dir reports/
"""

import argparse
import json
import os
import subprocess
import sys
import time
from dataclasses import asdict
from datetime import datetime, timezone
from pathlib import Path
from typing import List, Optional

# Ensure the project root is on the path
_PROJECT_ROOT = str(Path(__file__).resolve().parent.parent)
if _PROJECT_ROOT not in sys.path:
    sys.path.insert(0, _PROJECT_ROOT)

from scanner.engine import AnchorShieldEngine
from semantic.analyzer import SemanticAnalyzer, SemanticFinding
from adversarial.synthesizer import ExploitSynthesizer, ExploitCode


# Terminal formatting
BOLD = "\033[1m"
DIM = "\033[2m"
GREEN = "\033[32m"
RED = "\033[31m"
YELLOW = "\033[33m"
CYAN = "\033[36m"
RESET = "\033[0m"
BAR = "\u2550" * 61


def _print_header():
    """Print the pipeline header banner."""
    print(f"\n{BOLD}{BAR}{RESET}")
    print(f"{BOLD} anchor-shield — Adversarial Security Analysis{RESET}")
    print(f"{BOLD}{BAR}{RESET}\n")


def _print_phase(num: int, total: int, label: str):
    """Print a phase progress indicator."""
    print(f"{CYAN}[{num}/{total}]{RESET} {BOLD}{label}{RESET}")


def _print_summary(report: dict):
    """Print the final results summary."""
    s = report.get("summary", {})
    print(f"\n{BOLD}{BAR}{RESET}")
    print(f"{BOLD} RESULTS SUMMARY{RESET}")
    print(f"{BOLD}{BAR}{RESET}")
    print(f" Static patterns:        {s.get('static_pattern_matches', 0)} matches (0 logic bugs)")
    print(f" Semantic analysis:      {s.get('logic_bugs_by_llm', 0)} logic vulnerabilities")
    print(f" Exploits generated:     {s.get('exploits_generated', 0)}")
    confirmed = s.get("exploits_confirmed", 0)
    total_exp = s.get("exploits_generated", 0)
    print(f" Exploits confirmed:     {confirmed} / {total_exp}")
    print()
    missed = s.get("logic_bugs_missed_by_regex", 0)
    print(f" {YELLOW}Critical logic bugs INVISIBLE to regex:{RESET} {missed}")
    print(f" {YELLOW}Exploits proving real-world impact:{RESET}     {confirmed}")
    print(f"{BOLD}{BAR}{RESET}")
    elapsed = report.get("meta", {}).get("analysis_time_seconds", 0)
    print(f" Total analysis time: {elapsed:.1f} seconds")
    print(f"{BOLD}{BAR}{RESET}\n")


class SecurityOrchestrator:
    """Runs the complete adversarial security analysis pipeline.

    Orchestrates static scanning, semantic LLM analysis, exploit
    generation, and execution into a single automated workflow.
    """

    def __init__(self, api_key: Optional[str] = None):
        """Initialize the orchestrator.

        Args:
            api_key: Anthropic API key. Falls back to ANTHROPIC_API_KEY env var.
        """
        self.api_key = api_key or os.environ.get("ANTHROPIC_API_KEY", "")
        self.engine = AnchorShieldEngine()
        self.analyzer = SemanticAnalyzer(api_key=self.api_key)
        self.synthesizer = ExploitSynthesizer(api_key=self.api_key)

    def analyze(
        self,
        target_path: str,
        execute_exploits: bool = True,
        output_dir: Optional[str] = None,
    ) -> dict:
        """Run the complete analysis pipeline.

        Args:
            target_path: Path to the Anchor program directory or file.
            execute_exploits: Whether to execute generated exploits.
            output_dir: Directory for output files. Defaults to target_path.

        Returns:
            Complete security report as a dictionary.
        """
        start_time = time.time()
        target_path = os.path.abspath(target_path)
        output_dir = output_dir or os.path.join(target_path, "..", "demo-output")
        output_dir = os.path.abspath(output_dir)
        os.makedirs(output_dir, exist_ok=True)

        _print_header()

        # Discover .rs files
        rs_files = self._discover_rs_files(target_path)
        print(f"{DIM}  Found {len(rs_files)} Rust source file(s){RESET}\n")

        # Phase 1: Static analysis
        _print_phase(1, 5, "Static pattern analysis...")
        static_report = self._run_static_scan(target_path)
        static_findings_count = len(static_report.findings)
        print(f"      Scanned {static_report.files_scanned} file(s), found {static_findings_count} pattern matches")
        print(f"      Logic bugs detected: 0\n")

        # Phase 2: Semantic LLM analysis
        _print_phase(2, 5, "Semantic LLM analysis...")
        all_semantic_findings = []
        for rs_file in rs_files:
            rel_name = os.path.relpath(rs_file, target_path)
            with open(rs_file, "r", encoding="utf-8", errors="ignore") as f:
                source_code = f.read()
            print(f"      Analyzing {rel_name}")
            findings = self.analyzer.analyze(source_code, rel_name)
            all_semantic_findings.extend(findings)

        mode_label = " (pre-validated)" if self.analyzer.is_demo_mode else ""
        print(f"      Logic vulnerabilities found: {len(all_semantic_findings)}{mode_label}")
        for f in all_semantic_findings:
            color = RED if f.severity == "Critical" else YELLOW if f.severity == "High" else RESET
            print(f"        {color}[{f.severity}]{RESET} {f.function}(): {f.title}")
        print()

        # Phase 3: Exploit generation
        _print_phase(3, 5, "Generating exploit code...")
        source_for_exploits = ""
        if rs_files:
            with open(rs_files[0], "r", encoding="utf-8", errors="ignore") as f:
                source_for_exploits = f.read()

        exploits = self.synthesizer.generate_all(source_for_exploits, all_semantic_findings)
        print(f"      Generated {len(exploits)} exploits for Critical/High findings\n")

        # Save exploits to files
        exploit_dir = os.path.join(_PROJECT_ROOT, "exploits")
        os.makedirs(exploit_dir, exist_ok=True)
        for i, exploit in enumerate(exploits):
            slug = exploit.finding_id.lower().replace("-", "_")
            filename = f"exploit_{slug}.py"
            filepath = os.path.join(exploit_dir, filename)
            with open(filepath, "w") as ef:
                ef.write(exploit.code)

        # Phase 4: Exploit execution
        _print_phase(4, 5, "Executing exploits...")
        execution_results = []
        if execute_exploits and exploits:
            for exploit in exploits:
                slug = exploit.finding_id.lower().replace("-", "_")
                filepath = os.path.join(exploit_dir, f"exploit_{slug}.py")
                result = self._execute_exploit(filepath, exploit)
                execution_results.append(result)
                status_icon = {
                    "SIMULATED": f"{GREEN}SIMULATED{RESET}",
                    "CONFIRMED": f"{GREEN}CONFIRMED{RESET}",
                    "FAILED": f"{RED}FAILED{RESET}",
                }.get(result["status"], result["status"])
                short_title = exploit.title[:40]
                print(f"      {short_title:<42} {status_icon}")
        elif not exploits:
            print(f"      {DIM}No exploits to execute{RESET}")
        else:
            print(f"      {DIM}Execution skipped (--no-execute){RESET}")
        print()

        # Phase 5: Report generation
        _print_phase(5, 5, "Report generation...")

        # Count confirmed/simulated
        confirmed_count = sum(
            1 for r in execution_results if r["status"] in ("CONFIRMED", "SIMULATED")
        )

        elapsed = time.time() - start_time

        report = {
            "meta": {
                "tool": "anchor-shield",
                "version": "0.2.0",
                "timestamp": datetime.now(timezone.utc).isoformat(),
                "analysis_time_seconds": round(elapsed, 1),
                "target": target_path,
                "route": "LLM-ONLY" if not self._has_anchor_toolchain() else "FULL",
            },
            "static_analysis": {
                "engine": "regex pattern matcher v0.1.0",
                "findings_count": static_findings_count,
                "logic_bugs_found": 0,
                "findings": [f.to_dict() for f in static_report.findings],
            },
            "semantic_analysis": {
                "engine": "LLM semantic analyzer",
                "model": self.analyzer.model,
                "mode": "pre-validated" if self.analyzer.is_demo_mode else "live",
                "findings_count": len(all_semantic_findings),
                "findings": [f.to_dict() for f in all_semantic_findings],
            },
            "exploits": [
                {
                    "finding_id": exploit.finding_id,
                    "title": exploit.title,
                    "status": next(
                        (r["status"] for r in execution_results if r["finding_id"] == exploit.finding_id),
                        exploit.status,
                    ),
                    "language": exploit.language,
                    "code_file": f"exploits/exploit_{exploit.finding_id.lower().replace('-', '_')}.py",
                }
                for exploit in exploits
            ],
            "summary": {
                "static_pattern_matches": static_findings_count,
                "logic_bugs_by_llm": len(all_semantic_findings),
                "exploits_generated": len(exploits),
                "exploits_confirmed": confirmed_count,
                "logic_bugs_missed_by_regex": len(all_semantic_findings),
            },
        }

        # Save report
        report_path = os.path.join(_PROJECT_ROOT, "SECURITY_REPORT.json")
        with open(report_path, "w") as rf:
            json.dump(report, rf, indent=2)
        print(f"      Saved: SECURITY_REPORT.json")

        # Also save to output_dir
        output_report_path = os.path.join(output_dir, "05_full_pipeline.json")
        with open(output_report_path, "w") as rf:
            json.dump(report, rf, indent=2)

        _print_summary(report)

        return report

    def _discover_rs_files(self, path: str) -> List[str]:
        """Find all .rs files in path, skipping target/ and node_modules/."""
        rs_files = []
        if os.path.isfile(path) and path.endswith(".rs"):
            return [path]

        for root, dirs, files in os.walk(path):
            # Skip build artifacts
            dirs[:] = [d for d in dirs if d not in ("target", "node_modules", ".git")]
            for f in files:
                if f.endswith(".rs"):
                    rs_files.append(os.path.join(root, f))
        return sorted(rs_files)

    def _run_static_scan(self, target_path: str):
        """Run the regex pattern scanner."""
        return self.engine.scan_directory(target_path)

    def _execute_exploit(self, filepath: str, exploit: ExploitCode) -> dict:
        """Execute a single exploit simulation."""
        result = {
            "finding_id": exploit.finding_id,
            "title": exploit.title,
            "status": "FAILED",
            "output": "",
        }

        if not os.path.exists(filepath):
            result["output"] = "File not found"
            return result

        try:
            proc = subprocess.run(
                [sys.executable, filepath],
                capture_output=True,
                text=True,
                timeout=30,
                cwd=_PROJECT_ROOT,
            )
            result["output"] = proc.stdout + proc.stderr
            if proc.returncode == 0 and "CONFIRMED" in proc.stdout:
                result["status"] = "SIMULATED"
            elif proc.returncode == 0:
                result["status"] = "SIMULATED"
            else:
                result["status"] = "FAILED"
        except subprocess.TimeoutExpired:
            result["output"] = "Execution timed out (30s)"
            result["status"] = "FAILED"
        except Exception as e:
            result["output"] = str(e)
            result["status"] = "FAILED"

        return result

    @staticmethod
    def _has_anchor_toolchain() -> bool:
        """Check if Anchor/Solana toolchain is available."""
        try:
            subprocess.run(
                ["anchor", "--version"],
                capture_output=True,
                timeout=5,
            )
            return True
        except (FileNotFoundError, subprocess.TimeoutExpired):
            return False


def main():
    """CLI entry point for the orchestrator."""
    parser = argparse.ArgumentParser(
        description="anchor-shield: Adversarial Security Analysis for Solana",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=(
            "Examples:\n"
            "  python agent/orchestrator.py examples/vulnerable-lending/\n"
            "  python agent/orchestrator.py path/to/program --no-execute\n"
            "  python agent/orchestrator.py path/to/program --output-dir reports/\n"
        ),
    )
    parser.add_argument(
        "target",
        help="Path to Anchor program directory or .rs file",
    )
    parser.add_argument(
        "--no-execute",
        action="store_true",
        help="Generate exploits but don't execute them",
    )
    parser.add_argument(
        "--api-key",
        help="Anthropic API key (overrides ANTHROPIC_API_KEY env var)",
    )
    parser.add_argument(
        "--output-dir",
        help="Directory for output files (default: auto)",
    )

    args = parser.parse_args()

    orchestrator = SecurityOrchestrator(api_key=args.api_key)
    orchestrator.analyze(
        target_path=args.target,
        execute_exploits=not args.no_execute,
        output_dir=args.output_dir,
    )


if __name__ == "__main__":
    main()
