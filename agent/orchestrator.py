#!/usr/bin/env python3
"""
Orchestrator — Full autonomous security analysis pipeline.

Runs all three layers (static, semantic, adversarial) against an Anchor program
and produces a consolidated security report.

Usage:
    python agent/orchestrator.py <path-to-program-directory>
    python agent/orchestrator.py examples/vulnerable-lending/ --no-execute
    python agent/orchestrator.py examples/vulnerable-lending/ --demo
"""

import argparse
import json
import os
import sys
import time
from pathlib import Path
from datetime import datetime, timezone

# Add project root to path
PROJECT_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(PROJECT_ROOT))


def print_banner():
    print()
    print("=" * 55)
    print(" [*] Autonomous Security Analysis — anchor-shield")
    print("=" * 55)
    print()


def step(number: int, total: int, message: str):
    print(f"[{number}/{total}] {message}")


def run_static_scan(program_dir: str) -> dict:
    """Run the regex-based pattern scanner."""
    from scanner.engine import AnchorShieldEngine

    engine = AnchorShieldEngine()
    report = engine.scan_directory(program_dir)

    findings = []
    logic_bugs = 0
    for f in report.findings:
        d = f.to_dict() if hasattr(f, "to_dict") else vars(f)
        findings.append(d)

    return {
        "total_matches": len(findings),
        "logic_bugs": logic_bugs,
        "security_score": report.security_score,
        "findings": findings,
    }


def run_semantic_analysis(source_code: str, filename: str, demo_mode: bool) -> list:
    """Run LLM-powered semantic analysis."""
    if demo_mode or not os.environ.get("ANTHROPIC_API_KEY"):
        from semantic.analyzer import SemanticAnalyzer
        findings = SemanticAnalyzer.load_demo_findings()
        return [f.to_dict() for f in findings]

    from semantic.analyzer import SemanticAnalyzer
    analyzer = SemanticAnalyzer()
    findings = analyzer.analyze(source_code, filename)
    return [f.to_dict() for f in findings]


def run_exploit_generation(source_code: str, findings: list, demo_mode: bool) -> list:
    """Generate exploit PoCs for Critical/High findings."""
    if demo_mode or not os.environ.get("ANTHROPIC_API_KEY"):
        from adversarial.synthesizer import ExploitSynthesizer
        exploits = ExploitSynthesizer.load_demo_exploits()
        return [e.to_dict() for e in exploits]

    from adversarial.synthesizer import ExploitSynthesizer
    synth = ExploitSynthesizer()
    exploits = synth.generate_all(source_code, findings)
    return [e.to_dict() for e in exploits]


def save_exploits(exploits: list, output_dir: Path):
    """Save exploit code to individual files."""
    exploits_dir = PROJECT_ROOT / "exploits"
    exploits_dir.mkdir(exist_ok=True)

    for exploit in exploits:
        filepath = exploits_dir / exploit["filename"]
        filepath.write_text(exploit["code"])


def generate_report(
    program_dir: str,
    static_results: dict,
    semantic_findings: list,
    exploits: list,
    route: str,
) -> dict:
    """Generate the consolidated security report."""
    critical_high = [
        f for f in semantic_findings if f["severity"] in ("CRITICAL", "HIGH")
    ]

    confirmed = sum(1 for e in exploits if e["status"] == "CONFIRMED")
    generated = sum(1 for e in exploits if e["status"] in ("GENERATED", "THEORETICAL"))

    report = {
        "report_version": "2.0",
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "target": program_dir,
        "route": route,
        "static_analysis": {
            "pattern_matches": static_results["total_matches"],
            "logic_bugs_found": static_results["logic_bugs"],
            "security_score": static_results["security_score"],
            "findings": static_results["findings"],
        },
        "semantic_analysis": {
            "total_findings": len(semantic_findings),
            "critical": sum(1 for f in semantic_findings if f["severity"] == "CRITICAL"),
            "high": sum(1 for f in semantic_findings if f["severity"] == "HIGH"),
            "medium": sum(1 for f in semantic_findings if f["severity"] == "MEDIUM"),
            "findings": semantic_findings,
        },
        "adversarial_synthesis": {
            "exploits_generated": len(exploits),
            "exploits_confirmed": confirmed,
            "exploits_theoretical": generated,
            "exploits": exploits,
        },
        "summary": {
            "static_pattern_matches": static_results["total_matches"],
            "logic_bugs_invisible_to_regex": len(critical_high),
            "exploits_generated": len(exploits),
            "exploits_confirmed": confirmed,
        },
    }

    return report


def print_summary(report: dict):
    """Print the final report summary to terminal."""
    s = report["summary"]
    sem = report["semantic_analysis"]
    adv = report["adversarial_synthesis"]

    print()
    print("=" * 55)
    print(" SECURITY REPORT SUMMARY")
    print("=" * 55)
    print(f" Static patterns:     {s['static_pattern_matches']} matches "
          f"({report['static_analysis']['logic_bugs_found']} logic bugs)")
    print(f" Semantic analysis:   {sem['total_findings']} logic vulnerabilities")
    print(f" Exploits generated:  {adv['exploits_generated']}")
    print(f" Exploits confirmed:  {adv['exploits_confirmed']}")
    print()
    print(f" Critical bugs INVISIBLE to regex: "
          f"{s['logic_bugs_invisible_to_regex']}")
    print("=" * 55)


def main():
    parser = argparse.ArgumentParser(
        description="anchor-shield autonomous security analysis"
    )
    parser.add_argument(
        "target",
        help="Path to Anchor program directory (containing src/lib.rs)",
    )
    parser.add_argument(
        "--no-execute",
        action="store_true",
        help="Skip exploit execution (generate only)",
    )
    parser.add_argument(
        "--demo",
        action="store_true",
        help="Use pre-computed results (no API key needed)",
    )
    parser.add_argument(
        "--output",
        default=None,
        help="Output directory for report (default: examples/demo-output/)",
    )
    args = parser.parse_args()

    # Resolve paths
    target = Path(args.target).resolve()
    src_dir = target / "src" if (target / "src").is_dir() else target
    output_dir = Path(args.output) if args.output else PROJECT_ROOT / "examples" / "demo-output"
    output_dir.mkdir(parents=True, exist_ok=True)

    # Determine route
    has_api_key = bool(os.environ.get("ANTHROPIC_API_KEY"))
    demo_mode = args.demo or not has_api_key

    if demo_mode:
        route = "LLM-ONLY (demo mode)"
        if not has_api_key:
            print("  [info] No ANTHROPIC_API_KEY found — using pre-computed demo results")
    elif args.no_execute:
        route = "NO-VALIDATOR"
    else:
        route = "FULL"

    # Find source files
    rs_files = list(src_dir.glob("**/*.rs"))
    if not rs_files:
        print(f"[error] No .rs files found in {src_dir}")
        sys.exit(1)

    # Read source code
    source_code = ""
    main_file = ""
    for f in rs_files:
        content = f.read_text()
        source_code += content + "\n"
        if "declare_id" in content or "#[program]" in content:
            main_file = f.name

    print_banner()

    total_steps = 5

    # Step 1: Static scan
    step(1, total_steps, "Static pattern scan...")
    static_results = run_static_scan(str(src_dir))
    print(f"      Found {static_results['total_matches']} pattern matches "
          f"({static_results['logic_bugs']} logic bugs)")

    # Step 2: Semantic analysis
    step(2, total_steps, "Semantic LLM analysis...")
    semantic_findings = run_semantic_analysis(source_code, main_file, demo_mode)
    critical_high = sum(
        1 for f in semantic_findings if f["severity"] in ("CRITICAL", "HIGH")
    )
    print(f"      Found {len(semantic_findings)} logic vulnerabilities "
          f"({critical_high} Critical/High)")

    # Step 3: Exploit generation
    step(3, total_steps, "Generating exploits...")
    exploits = run_exploit_generation(source_code, semantic_findings, demo_mode)
    print(f"      Generated {len(exploits)} exploit PoCs")

    # Save exploit files
    save_exploits(exploits, output_dir)

    # Step 4: Exploit execution
    step(4, total_steps, "Executing exploits...")
    if route == "FULL" and not args.no_execute:
        print("      [skip] Full execution requires Solana toolchain")
        for e in exploits:
            e["status"] = "THEORETICAL"
            print(f"      {e['filename']}: THEORETICAL")
    else:
        for e in exploits:
            status = e.get("status", "THEORETICAL")
            print(f"      {e['filename']}: {status}")

    # Step 5: Generate report
    step(5, total_steps, "Generating report...")
    report = generate_report(
        str(target), static_results, semantic_findings, exploits, route
    )

    report_path = output_dir / "SECURITY_REPORT.json"
    report_path.write_text(json.dumps(report, indent=2, default=str))
    print(f"      Report saved: {report_path}")

    # Print summary
    print_summary(report)
    print(f" Report: {report_path}")
    print()

    # Save semantic analysis results
    semantic_output = output_dir / "semantic_analysis_result.txt"
    with open(semantic_output, "w") as f:
        f.write("anchor-shield Semantic Analysis Results\n")
        f.write("=" * 50 + "\n\n")
        for finding in semantic_findings:
            f.write(f"[{finding['severity']}] {finding['function']}: {finding['title']}\n")
            f.write(f"  {finding['description'][:200]}\n")
            f.write(f"  Confidence: {finding['confidence']}\n\n")

    # Save exploit results
    exploit_output = output_dir / "exploit_results.txt"
    with open(exploit_output, "w") as f:
        f.write("anchor-shield Exploit Results\n")
        f.write("=" * 50 + "\n")
        f.write(f"Route: {route}\n\n")
        for e in exploits:
            f.write(f"[{e['severity']}] {e['finding_title']}\n")
            f.write(f"  File: {e['filename']}\n")
            f.write(f"  Status: {e['status']}\n\n")

    return 0


if __name__ == "__main__":
    sys.exit(main())
