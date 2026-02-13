# anchor-shield — Adversarial Security Agent for Solana

[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](LICENSE)

> The first security tool that doesn't just find bugs — it proves them on compiled binaries.

## The Problem

Security scanners for Solana use pattern matching: they search for known text patterns in source code. This approach has a fundamental limitation — **it cannot detect logic vulnerabilities**. The most dangerous bugs (incorrect calculations, missing validation between related operations, economic exploits) are invisible to regex.

Consider a lending pool where the `borrow` function checks `deposited >= amount` but ignores existing debt. Or a `withdraw` function that doesn't verify outstanding borrows. These are critical vulnerabilities that allow complete fund drainage — but no regex pattern will find them, because the code is syntactically correct. The bug is in what the code *doesn't* do.

## The Solution

anchor-shield combines four analysis layers into an autonomous security pipeline:

| Layer | Method | What It Finds |
|-------|--------|---------------|
| **Static Patterns** | Regex matching | Structural issues (missing checks, type confusion, known CVEs) |
| **Semantic Analysis** | LLM reasoning | Logic bugs (wrong math, state inconsistencies, economic exploits) |
| **Bankrun Exploits** | SBF binary execution | Proves bugs on compiled eBPF binaries via in-process Solana runtime |
| **Python Simulations** | Fallback verification | Supplementary exploit evidence via state modeling |

The key insight: each layer catches what the previous one misses. Static patterns catch known vulnerability classes. Semantic analysis reasons about program *logic* — tracing state across instructions, checking arithmetic invariants, identifying cross-function dependencies. The bankrun engine then compiles the target to an SBF binary and executes real exploit transactions against it using solana-bankrun (in-process Solana runtime), confirming vulnerabilities with actual BPF instruction execution — no simulation or mocking.

## Demo: Vulnerable Lending Pool

We created a lending pool program with 4 intentional logic vulnerabilities and ran the complete pipeline:

| # | Vulnerability | Severity | Regex | LLM | Bankrun | Python |
|---|--------------|----------|-------|-----|---------|--------|
| 1 | Collateral check ignores existing debt | Critical | Missed | Found | **CONFIRMED** | Simulated |
| 2 | Withdrawal with outstanding borrows | Critical | Missed | Found | **CONFIRMED** | Simulated |
| 3 | Integer overflow in liquidation | High | Missed | Found | **CONFIRMED** | Simulated |
| 4 | Division by zero in health check | Medium | Missed | Found | **CONFIRMED** | — |

**The regex scanner found 0 of the 4 logic bugs. The semantic analyzer found all 4. All 4 were independently confirmed by bankrun exploits executed against the compiled SBF binary.**

### Bankrun Exploit Results

All exploits ran against `vuln_lending.so` (compiled via `cargo-build-sbf`) using `solana-bankrun`:

- **SEM-001 Collateral Bypass**: Borrowed 500 SOL with 100 SOL collateral (500% debt ratio, should be capped at 75% LTV). 5 sequential borrow transactions all succeeded.
- **SEM-002 Withdraw Drain**: Deposited 100 SOL, borrowed 90, withdrew all 100. Protocol left with 90 SOL bad debt and 0 collateral.
- **SEM-003/004 Overflow + Division by Zero**: Integer overflow demonstrated (u64 wraps on `borrowed * rate * total_borrows`). Division by zero confirmed — program panics when liquidating a zero-borrow account.

## Quick Start

```bash
# Clone and install
git clone https://github.com/your-org/anchor-shield.git
cd anchor-shield
pip install -r requirements.txt

# Set your API key (for live LLM analysis)
export ANTHROPIC_API_KEY=your-api-key-here

# Run the full pipeline against the demo target
python agent/orchestrator.py examples/vulnerable-lending/

# View the interactive dashboard
cd dashboard && npm install && npm run dev
```

The pipeline runs without an API key in demo mode using pre-validated results.

## Architecture

```
Source Code (.rs)
       │
       ├──► [1] Static Pattern Scanner (regex)
       │         └── Pattern matches, structural issues
       │
       ├──► [2] Semantic LLM Analyzer
       │         └── Logic vulnerabilities, attack scenarios, confidence scores
       │
       ├──► [3] Exploit Synthesizer
       │         └── TypeScript bankrun exploits + Python simulation PoCs
       │
       ├──► [4] Bankrun Executor
       │         └── Compiles to SBF, executes exploits on real Solana runtime
       │
       └──► [5] Python Executor
                 └── Fallback simulation for environments without Solana toolchain

       All results ──► SECURITY_REPORT.json ──► Dashboard
```

### Module Structure

```
anchor-shield/
├── scanner/           # Static regex pattern engine (v1)
│   ├── engine.py      # Core scan engine
│   └── patterns/      # Vulnerability pattern definitions
├── semantic/          # LLM semantic analysis (v2)
│   ├── analyzer.py    # SemanticAnalyzer — API client + parser
│   └── prompts.py     # Security auditor system prompt
├── adversarial/       # Exploit synthesis (v2)
│   └── synthesizer.py # ExploitSynthesizer — generates PoC code
├── agent/             # Autonomous orchestrator (v2)
│   └── orchestrator.py # Single-command pipeline entry point
├── dashboard/         # React + Tailwind interactive UI
│   └── src/
│       ├── App.jsx    # Multi-tab dashboard (bankrun + Python exploit views)
│       └── scanner.js # In-browser static scanner
├── exploits/          # Exploit files
│   ├── bankrun_exploit_001_collateral_bypass.ts   # Bankrun: SEM-001
│   ├── bankrun_exploit_002_withdraw_drain.ts      # Bankrun: SEM-002
│   ├── bankrun_exploit_003_overflow_liquidation.ts # Bankrun: SEM-003/004
│   ├── vuln_lending.so                            # Compiled SBF binary
│   └── exploit_sem_*.py                           # Python simulations
├── examples/
│   ├── vulnerable-lending/  # Demo target program (Anchor/Rust)
│   └── demo-output/         # Captured analysis outputs
└── tests/             # Test suite
```

## How It Works

### Static Pattern Scanner
The original scanner from v1 — detects 6 known Anchor vulnerability patterns using regex, including `init_if_needed` abuse, duplicate mutable accounts, realloc payer attacks, type cosplay, close+reinit lifecycle attacks, and missing owner validation. Fast and reliable for known patterns.

### Semantic LLM Analyzer
Sends Anchor program source code to the Claude API with a specialized security audit prompt. The prompt instructs the model to:
1. Map all state-modifying instructions and their side effects
2. Trace cross-instruction state dependencies
3. Check arithmetic operations for overflow/underflow
4. Verify economic invariants (collateral ratios, supply conservation)
5. Identify division-by-zero paths

Returns structured findings with severity, confidence scores, and step-by-step attack scenarios.

### Adversarial Exploit Synthesizer
For each Critical/High finding, generates exploit code in two forms:

**Bankrun exploits** (primary): TypeScript files that execute against the compiled SBF binary via `solana-bankrun`. These run real BPF instructions in an in-process Solana runtime — the same instruction processing as mainnet. Account state is pre-loaded as genesis accounts, and exploit transactions are processed through the actual program binary.

**Python simulations** (fallback): Self-contained Python scripts that model on-chain state as dataclasses, implement the vulnerable instruction logic, and execute the attack step by step. Used when the Solana toolchain is unavailable.

### Autonomous Orchestrator
The `agent/orchestrator.py` module chains all layers into a single command:

```bash
python agent/orchestrator.py <path-to-program> [--no-execute] [--output-dir DIR]
```

Pipeline: Static Scan → Semantic Analysis → Exploit Generation → Bankrun Execution → Python Simulation → Report

Produces:
- Formatted terminal output with progress indicators
- `SECURITY_REPORT.json` with all findings, bankrun results, and metadata
- Individual exploit files in `exploits/`

## CLI Options

| Option | Description |
|--------|-------------|
| `target` | Path to Anchor program directory or `.rs` file |
| `--no-execute` | Generate exploits but skip execution |
| `--api-key KEY` | Override ANTHROPIC_API_KEY environment variable |
| `--output-dir DIR` | Custom output directory |

## Dashboard

The interactive dashboard provides four views:

- **Overview** — Comparison cards showing regex vs LLM vs bankrun results, detection matrix, 6-stage pipeline visualization
- **Semantic Analysis** — Expandable findings with confidence bars, attack scenarios, and impact descriptions
- **Exploits** — Bankrun exploit results with on-chain execution output, plus Python simulation code
- **Static Scanner** — Original GitHub repo scanner with live scanning capability

```bash
cd dashboard && npm install && npm run dev
```

## Real-World Validation

We validated the analyzer against 4 real open-source Solana programs to measure accuracy beyond the controlled demo:

| Program | Domain | Lines | True Positives | Informational | False Positives |
|---------|--------|-------|----------------|---------------|-----------------|
| anchor-swap | DEX/AMM | 496 | 0 | 2 | 0 |
| anchor-multisig | Governance | 280 | 2 | 0 | 3 |
| marinade-staking | Liquid staking | 1,611 | 0 | 4 | 0 |
| raydium-clmm | Concentrated liquidity | 2,931 | 0 | 4 | 1 |

**Key findings on real code:**
- Found **2 genuine missing-validation bugs** in the anchor-multisig example (zero threshold, empty owners list)
- Found **1 likely edge-case DoS** in anchor-swap (NonZeroU64 panic on sub-lot amounts)
- On **audited production protocols** (Marinade, Raydium): produced only informational findings (code quality observations), no false claims of exploitable bugs
- **False positive rate**: 18% (3/17 findings), primarily from misunderstanding Solana execution model specifics

Every finding was manually classified against source code. Full methodology and per-finding evaluation: [RESEARCH_REPORT.md](RESEARCH_REPORT.md).

## Limitations

- **LLM dependence**: Semantic analysis quality depends on the model. We use claude-sonnet for the best balance of speed and capability.
- **False positives possible**: LLM analysis may produce findings that aren't exploitable in practice. We report confidence levels for each finding.
- **Demo mode**: Without an API key, the tool uses pre-validated results rather than live analysis.
- **Execution scope**: Bankrun exploits require Solana toolchain (`cargo-build-sbf`, `solana-bankrun`). Without it, exploits fall back to Python simulations.
- **Not a replacement for audits**: This tool augments human security review — it does not replace professional auditors.
- **API costs**: Live LLM analysis costs approximately $0.01-0.03 per file analyzed.

## Prior Work

anchor-shield v1 was built on original security research that discovered 3 novel vulnerabilities in the Anchor framework itself ([PR #4229](https://github.com/solana-foundation/anchor/pull/4229)). v2 extends this with semantic LLM analysis and adversarial exploit synthesis.

## License

MIT — see [LICENSE](LICENSE) for details.
