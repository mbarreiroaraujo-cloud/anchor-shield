# anchor-shield — Adversarial Security Agent for Solana

[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](LICENSE)

> The first security tool that doesn't just find bugs — it proves they're real.

## The Problem

Security scanners for Solana use pattern matching: they search for known text patterns in source code. This approach has a fundamental limitation — **it cannot detect logic vulnerabilities**. The most dangerous bugs (incorrect calculations, missing validation between related operations, economic exploits) are invisible to regex.

Consider a lending pool where the `borrow` function checks `deposited >= amount` but ignores existing debt. Or a `withdraw` function that doesn't verify outstanding borrows. These are critical vulnerabilities that allow complete fund drainage — but no regex pattern will find them, because the code is syntactically correct. The bug is in what the code *doesn't* do.

## The Solution

anchor-shield combines three analysis layers into an autonomous security pipeline:

| Layer | Method | What It Finds |
|-------|--------|---------------|
| **Static Patterns** | Regex matching | Structural issues (missing checks, type confusion, known CVEs) |
| **Semantic Analysis** | LLM reasoning | Logic bugs (wrong math, state inconsistencies, economic exploits) |
| **Adversarial Synthesis** | Auto-generated exploits | Proves bugs are exploitable with working attack code |

The key insight: each layer catches what the previous one misses. Static patterns catch known vulnerability classes. Semantic analysis reasons about program *logic* — tracing state across instructions, checking arithmetic invariants, identifying cross-function dependencies. The adversarial engine then generates and executes proof-of-concept exploits, turning theoretical findings into confirmed vulnerabilities.

## Demo: Vulnerable Lending Pool

We created a lending pool program with 4 intentional logic vulnerabilities and ran the complete pipeline:

| # | Vulnerability | Severity | Regex | LLM | Exploit |
|---|--------------|----------|-------|-----|---------|
| 1 | Collateral check ignores existing debt | Critical | Missed | Found | Confirmed |
| 2 | Withdrawal with outstanding borrows | Critical | Missed | Found | Confirmed |
| 3 | Integer overflow in liquidation | High | Missed | Found | Confirmed |
| 4 | Division by zero in health check | Medium | Missed | Found | — |

**The regex scanner found 0 of the 4 logic bugs. The semantic analyzer found all 4. Three were independently confirmed by automated exploit simulations.**

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
       │         └── Python simulation PoCs for Critical/High findings
       │
       └──► [4] Exploit Executor
                 └── Runs PoCs, confirms exploitability

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
│       ├── App.jsx    # Multi-tab dashboard
│       └── scanner.js # In-browser static scanner
├── exploits/          # Generated exploit simulations
├── examples/
│   ├── vulnerable-lending/  # Demo target program
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
For each Critical/High finding, generates a self-contained Python simulation that:
1. Models the on-chain state as dataclasses
2. Implements the vulnerable instruction logic
3. Executes the attack step by step
4. Asserts concrete outcomes (attacker profit, protocol loss)
5. Reports CONFIRMED or FAILED

### Autonomous Orchestrator
The `agent/orchestrator.py` module chains all three layers into a single command:

```bash
python agent/orchestrator.py <path-to-program> [--no-execute] [--output-dir DIR]
```

Produces:
- Formatted terminal output with progress indicators
- `SECURITY_REPORT.json` with all findings, exploits, and metadata
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

- **Overview** — Comparison cards showing regex vs LLM vs exploit results, detection matrix, pipeline visualization
- **Semantic Analysis** — Expandable findings with confidence bars, attack scenarios, and impact descriptions
- **Exploits** — Generated PoC code with syntax display and execution status badges
- **Static Scanner** — Original GitHub repo scanner with live scanning capability

```bash
cd dashboard && npm install && npm run dev
```

## Limitations

- **LLM dependence**: Semantic analysis quality depends on the model. We use claude-sonnet for the best balance of speed and capability.
- **False positives possible**: LLM analysis may produce findings that aren't exploitable in practice. We report confidence levels for each finding.
- **Demo mode**: Without an API key, the tool uses pre-validated results rather than live analysis.
- **Execution scope**: Without the Solana toolchain (Rust, Anchor, local validator), exploits run as Python simulations rather than on-chain tests.
- **Not a replacement for audits**: This tool augments human security review — it does not replace professional auditors.
- **API costs**: Live LLM analysis costs approximately $0.01-0.03 per file analyzed.

## Prior Work

anchor-shield v1 was built on original security research that discovered 3 novel vulnerabilities in the Anchor framework itself ([PR #4229](https://github.com/solana-foundation/anchor/pull/4229)). v2 extends this with semantic LLM analysis and adversarial exploit synthesis.

## License

MIT — see [LICENSE](LICENSE) for details.
