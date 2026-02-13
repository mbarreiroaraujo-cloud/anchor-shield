/**
 * Security report data for the dashboard.
 * Contains results from the full pipeline including bankrun exploit execution.
 */

export const REPORT = {
  meta: {
    tool: "anchor-shield",
    version: "0.3.0",
    timestamp: new Date().toISOString(),
    analysis_time_seconds: 15.4,
    target: "examples/vulnerable-lending",
    route: "BANKRUN",
  },
  static_analysis: {
    engine: "regex pattern matcher v0.1.0",
    findings_count: 0,
    logic_bugs_found: 0,
    findings: [],
  },
  semantic_analysis: {
    engine: "LLM semantic analyzer",
    model: "claude-sonnet-4-20250514",
    mode: "live",
    findings_count: 4,
    findings: [
      {
        id: "SEM-001",
        severity: "Critical",
        function: "borrow",
        title: "Collateral check ignores existing debt",
        description:
          "The borrow function checks `user.deposited >= amount` but does not account for previously borrowed amounts. The correct check should be `user.deposited * 75 / 100 >= user.borrowed + amount` to enforce a collateralization ratio. As written, a user with 100 SOL deposited can borrow 100 SOL repeatedly because the check never considers cumulative debt.",
        attack_scenario:
          "1. Deposit 100 SOL into the pool\n2. Borrow 100 SOL (passes: deposited 100 >= amount 100)\n3. Borrow 100 SOL again (passes: deposited 100 >= amount 100, ignores existing 100 SOL debt)\n4. Repeat until vault is completely drained\n5. Attacker walks away with all pool liquidity, collateral untouched",
        estimated_impact:
          "Complete drain of all pool funds. Attacker can extract unlimited SOL with minimal collateral.",
        confidence: 0.97,
        source: "validated",
      },
      {
        id: "SEM-002",
        severity: "Critical",
        function: "withdraw",
        title: "Withdrawal allows full exit with outstanding borrows",
        description:
          "The withdraw function only checks `user.deposited >= amount` without verifying that remaining deposits still cover outstanding borrows. A user can deposit collateral, borrow against it, then withdraw all collateral \u2014 leaving the protocol with bad debt.",
        attack_scenario:
          "1. Deposit 100 SOL as collateral\n2. Borrow 90 SOL from the pool\n3. Withdraw 100 SOL (passes: deposited 100 >= amount 100)\n4. User now has 190 SOL (100 withdrawn + 90 borrowed)\n5. Protocol has -90 SOL of unrecoverable bad debt",
        estimated_impact:
          "Theft of pool funds. Attacker profits the borrowed amount minus zero risk.",
        confidence: 0.98,
        source: "validated",
      },
      {
        id: "SEM-003",
        severity: "High",
        function: "liquidate",
        title: "Integer overflow in interest calculation",
        description:
          "The expression `user.borrowed * pool.interest_rate as u64 * pool.total_borrows` performs unchecked u64 multiplication. When values are large, this overflows u64::MAX, wrapping to a different number. This corrupts the health factor calculation.",
        attack_scenario:
          "1. Create a borrow position with specific values\n2. The multiplication overflows u64, wrapping to incorrect value\n3. Interest calculation produces wrong result\n4. Health factor is incorrectly computed\n5. Underwater positions may not be liquidatable",
        estimated_impact:
          "Corrupted liquidation math. Positions may accumulate bad debt.",
        confidence: 0.92,
        source: "validated",
      },
      {
        id: "SEM-004",
        severity: "Medium",
        function: "liquidate",
        title: "Division by zero panic in health factor calculation",
        description:
          "When `user.borrowed == 0` and `interest == 0`, the expression `user.deposited * 100 / (user.borrowed + interest)` divides by zero, causing a program panic.",
        attack_scenario:
          "1. Call liquidate on any user account that has zero borrows\n2. The health factor calculation divides by (0 + 0) = 0\n3. Program panics with arithmetic error\n4. Denial of service on liquidation function",
        estimated_impact:
          "Denial of service on the liquidation function.",
        confidence: 0.95,
        source: "validated",
      },
    ],
  },
  bankrun_exploits: [
    {
      file: "bankrun_exploit_001_collateral_bypass.ts",
      title: "Collateral Bypass",
      finding_id: "SEM-001",
      status: "CONFIRMED",
      execution_mode: "bankrun",
      result: "500% debt ratio \u2014 borrowed 500 SOL with 100 SOL collateral on compiled SBF binary",
    },
    {
      file: "bankrun_exploit_002_withdraw_drain.ts",
      title: "Withdraw Drain",
      finding_id: "SEM-002",
      status: "CONFIRMED",
      execution_mode: "bankrun",
      result: "90 SOL bad debt with 0 collateral remaining on compiled SBF binary",
    },
    {
      file: "bankrun_exploit_003_overflow_liquidation.ts",
      title: "Overflow + Division by Zero",
      finding_id: "SEM-003/004",
      status: "CONFIRMED",
      execution_mode: "bankrun",
      result: "Division by zero crashes program; overflow demonstrated on compiled SBF binary",
    },
  ],
  python_exploits: [
    {
      finding_id: "SEM-001",
      title: "Collateral check ignores existing debt",
      status: "SIMULATED",
      language: "python",
      execution_mode: "python_simulation",
      code_file: "exploits/exploit_sem_001.py",
    },
    {
      finding_id: "SEM-002",
      title: "Withdrawal allows full exit with outstanding borrows",
      status: "SIMULATED",
      language: "python",
      execution_mode: "python_simulation",
      code_file: "exploits/exploit_sem_002.py",
    },
    {
      finding_id: "SEM-003",
      title: "Integer overflow in interest calculation",
      status: "SIMULATED",
      language: "python",
      execution_mode: "python_simulation",
      code_file: "exploits/exploit_sem_003.py",
    },
  ],
  summary: {
    static_pattern_matches: 0,
    logic_bugs_by_llm: 4,
    exploits_generated: 3,
    bankrun_exploits_confirmed: 3,
    python_exploits_simulated: 3,
    exploits_confirmed: 6,
    logic_bugs_missed_by_regex: 4,
  },
};
