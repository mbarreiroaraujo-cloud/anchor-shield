#!/usr/bin/env python3
"""
anchor-shield attestation demo

Runs a complete scan-and-attest cycle on the included vulnerable test fixtures,
publishing the security attestation to Solana devnet.

Usage:
    python demo.py

Requirements:
    pip install -r requirements.txt

The demo will:
1. Scan the included vulnerable Rust test fixtures
2. Generate a security report
3. Create a new Solana devnet wallet
4. Request an airdrop for transaction fees
5. Publish the attestation as a memo transaction on Solana devnet
6. Save the full results to examples/attestation-demo.json
7. Print the Solana Explorer link to verify the on-chain attestation
"""

import os
import sys
import json

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from agent.autonomous import AutonomousAgent


def main():
    print()
    print("=" * 60)
    print("  anchor-shield: On-Chain Security Attestation Demo")
    print("=" * 60)
    print()

    # Initialize the agent (generates a fresh devnet wallet)
    agent = AutonomousAgent(network="devnet")
    print(f"  Agent wallet: {agent.wallet_address}")
    print(f"  Network:      devnet")
    print()

    # Target: the included vulnerable test fixtures
    target = os.path.join(os.path.dirname(__file__), "tests", "test_patterns", "vulnerable")
    print(f"  Target: {target}")
    print()

    # Run the full autonomous cycle
    print("  Running autonomous scan-and-attest cycle...")
    print()
    result = agent.scan_and_attest_directory(target)

    # Print results
    for i, step in enumerate(result.steps, 1):
        status_icon = {"started": "→", "completed": "✓", "failed": "✗"}.get(
            step["status"], "?"
        )
        print(f"  [{status_icon}] Step {i}: {step['step']} - {step['status']}")

    print()

    if result.success:
        print("  ✓ ATTESTATION PUBLISHED ON SOLANA DEVNET")
        print()
        print(f"  Transaction: {result.tx_signature}")
        print(f"  Explorer:    {result.explorer_url}")
        print()
        att = result.attestation
        print(f"  Security Score: {att['security_score']}/100 (Grade: {att['security_grade']})")
        print(f"  Issues Found:   {att['issues_found']}")
        print(f"  Patterns:       {att['patterns_checked']}")
        print(f"  Files Scanned:  {att['files_scanned']}")
        print(f"  Report Hash:    {att['report_hash'][:48]}...")
        print()

        # Save results
        output_path = os.path.join(
            os.path.dirname(__file__), "examples", "attestation-demo.json"
        )
        os.makedirs(os.path.dirname(output_path), exist_ok=True)
        with open(output_path, "w") as f:
            f.write(result.to_json())
        print(f"  Results saved to: {output_path}")
    else:
        print(f"  ✗ Attestation failed: {result.error}")
        print()
        if result.scan_report:
            sr = result.scan_report
            print(f"  Scan completed successfully:")
            print(f"  Score: {sr['security_score']} | Issues: {sr['summary']['total']}")

    print()
    print("=" * 60)


if __name__ == "__main__":
    main()
