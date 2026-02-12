"""CLI for the anchor-shield autonomous agent."""

import sys
import os
import json
import time

# Add project root to path
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from agent.autonomous import AutonomousAgent
from agent.config import DEFAULT_NETWORK


BANNER = """
╔═══════════════════════════════════════════════════════════════╗
║       anchor-shield agent v0.1.0                              ║
║       Autonomous Security Attestation Protocol                ║
║       Network: {network:<47s} ║
╚═══════════════════════════════════════════════════════════════╝
"""


def print_step(step_num: int, msg: str, status: str = ""):
    """Print a formatted step message."""
    icons = {"started": "→", "completed": "✓", "failed": "✗"}
    icon = icons.get(status, "→")
    print(f"  [{icon}] Step {step_num}: {msg}")


def cmd_scan_and_attest(target: str, network: str, output: str = None):
    """Scan a target and publish attestation."""
    print(BANNER.format(network=network))

    agent = AutonomousAgent(network=network)
    print(f"  Wallet: {agent.wallet_address}")
    print(f"  Target: {target}")
    print()

    # Determine target type and run
    if target.startswith("https://github.com/") or (
        "/" in target and not os.path.exists(target) and "." not in target.split("/")[-1]
    ):
        print("  Mode: GitHub repository scan")
        print()
        result = agent.scan_and_attest_repo(target)
    elif os.path.isdir(target) or os.path.isfile(target):
        print("  Mode: Local directory scan")
        print()
        result = agent.scan_and_attest_directory(target)
    else:
        print("  Mode: Content scan")
        print()
        result = agent.scan_and_attest_content(target)

    # Print steps
    print("  Execution steps:")
    for i, step in enumerate(result.steps, 1):
        step_name = step["step"]
        status = step["status"]
        detail = ""
        if "files_found" in step:
            detail = f" ({step['files_found']} files)"
        elif "findings" in step:
            detail = f" ({step['findings']} findings)"
        elif "tx_signature" in step:
            detail = f" (tx: {step['tx_signature'][:16]}...)"
        print_step(i, f"{step_name}{detail}", status)

    print()

    if result.success:
        print("  ═══ ATTESTATION PUBLISHED ═══")
        print()
        att = result.attestation
        print(f"  Transaction:  {result.tx_signature}")
        print(f"  Explorer:     {result.explorer_url}")
        print(f"  Score:        {att['security_score']}/100 (Grade: {att['security_grade']})")
        print(f"  Issues:       {att['issues_found']}")
        print(f"  Patterns:     {att['patterns_checked']}")
        print(f"  Files:        {att['files_scanned']}")
        print(f"  Report hash:  {att['report_hash'][:32]}...")
        print()
    elif result.scan_report:
        print("  ═══ SCAN COMPLETED (attestation failed) ═══")
        print()
        sr = result.scan_report
        print(f"  Score:    {sr['security_score']}")
        print(f"  Issues:   {sr['summary'].get('total', 0)}")
        print(f"  Error:    {result.error}")
        print()
    else:
        print(f"  ✗ Failed: {result.error}")
        print()

    # Save output
    if output:
        with open(output, "w") as f:
            f.write(result.to_json())
        print(f"  Results saved to: {output}")

    return result


def cmd_scan_only(target: str, output: str = None):
    """Scan without publishing attestation."""
    agent = AutonomousAgent()
    result = agent.scan_only(target)

    if result.success and result.scan_report:
        sr = result.scan_report
        print(f"  Score:    {sr['security_score']}")
        print(f"  Issues:   {sr['summary'].get('total', 0)}")
        print(f"  Files:    {sr['files_scanned']}")
    else:
        print(f"  ✗ Failed: {result.error}")

    if output:
        with open(output, "w") as f:
            f.write(result.to_json())

    return result


def cmd_query(authority: str = None, network: str = "devnet"):
    """Query attestation history."""
    agent = AutonomousAgent(network=network)
    authority = authority or agent.wallet_address

    print(f"  Querying attestations for: {authority}")
    print(f"  Network: {network}")
    print()

    summary = agent.query_attestations(authority)

    print(f"  Total attestations: {summary['total_attestations']}")
    print()

    for att in summary["attestations"]:
        print(f"  ─── Attestation ───")
        print(f"  TX:     {att['tx_signature'][:32]}...")
        print(f"  Score:  {att['score']}/100")
        print(f"  Issues: {att['issues']}")
        print(f"  Time:   {time.strftime('%Y-%m-%d %H:%M:%S', time.gmtime(att['timestamp']))}")
        print(f"  URL:    {att['explorer_url']}")
        print()

    return summary


def main():
    """Main CLI entry point."""
    args = sys.argv[1:]

    if not args or args[0] in ("-h", "--help", "help"):
        print(BANNER.format(network=DEFAULT_NETWORK))
        print("  Usage:")
        print("    python -m agent attest <target>          Scan and publish attestation")
        print("    python -m agent scan <target>            Scan only (no attestation)")
        print("    python -m agent query [authority]        Query attestation history")
        print()
        print("  Options:")
        print("    --network devnet|testnet                 Solana network (default: devnet)")
        print("    --output <file>                          Save results to file")
        print()
        print("  Examples:")
        print("    python -m agent attest https://github.com/user/anchor-project")
        print("    python -m agent attest ./my-program/")
        print("    python -m agent scan ./tests/test_patterns/vulnerable/")
        print("    python -m agent query")
        print()
        return

    command = args[0]
    network = DEFAULT_NETWORK
    output = None
    target = None

    # Parse args
    i = 1
    while i < len(args):
        if args[i] == "--network" and i + 1 < len(args):
            network = args[i + 1]
            i += 2
        elif args[i] == "--output" and i + 1 < len(args):
            output = args[i + 1]
            i += 2
        elif args[i].startswith("-"):
            i += 1
        else:
            target = args[i]
            i += 1

    if command == "attest":
        if not target:
            print("Error: target is required for 'attest' command")
            sys.exit(1)
        result = cmd_scan_and_attest(target, network, output)
        sys.exit(0 if result.success else 1)

    elif command == "scan":
        if not target:
            print("Error: target is required for 'scan' command")
            sys.exit(1)
        result = cmd_scan_only(target, output)
        sys.exit(0 if result.success else 1)

    elif command == "query":
        cmd_query(target, network)

    else:
        print(f"Unknown command: {command}")
        print("Run 'python -m agent --help' for usage")
        sys.exit(1)


if __name__ == "__main__":
    main()
