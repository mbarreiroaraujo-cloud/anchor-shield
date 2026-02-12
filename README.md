# anchor-shield

[![Tests](https://github.com/mbarreiroaraujo-cloud/anchor-shield/actions/workflows/tests.yml/badge.svg)](https://github.com/mbarreiroaraujo-cloud/anchor-shield/actions/workflows/tests.yml)
[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](LICENSE)

**Autonomous security agent for Solana Anchor programs — static patterns + semantic LLM analysis + adversarial exploit synthesis**

> Most security scanners look for text patterns. anchor-shield goes further: it uses an LLM to understand program **logic**, finds bugs that no regex can detect, then automatically generates exploit code to **prove** each bug is real.

**[Live Dashboard](https://mbarreiroaraujo-cloud.github.io/anchor-shield/)** · **[Architecture](ARCHITECTURE.md)**

## The Problem

Security scanners for Solana programs rely on regex-based pattern matching. They catch known vulnerability signatures (missing owner checks, unsafe `init_if_needed` usage, etc.) but are completely blind to **logic bugs** — the most dangerous class of vulnerabilities.

A lending protocol that lets you borrow against collateral you've already borrowed against? A withdraw function that ignores outstanding debt? An integer overflow that prevents liquidation of insolvent positions? No regex will ever find these.

## What anchor-shield Does

Three analysis layers, each catching what the previous one misses:

```
                    +-------------------+
                    |  Anchor Program   |
                    |   (source .rs)    |
                    +--------+----------+
                             |
              +--------------+--------------+
              v              v              v
     +------------+  +------------+  +------------+
     |   Static   |  |  Semantic  |  | Adversarial|
     |   Regex    |  |    LLM     |  |  Synthesis |
     |  Patterns  |  |  Analysis  |  |  (Exploits)|
     +------+-----+  +------+-----+  +------+-----+
            |               |               |
            +---------------+---------------+
                            v
                   +----------------+
                   | Security Report|
                   |  + Dashboard   |
                   +----------------+
```

### Demo: Vulnerable Lending Pool

The repo includes a purposely vulnerable Anchor lending pool with 3 logic bugs. Here's what each layer finds:

| Layer | Logic Bugs Found | Exploits |
|-------|:----------------:|:--------:|
| Static regex | 0 | — |
| Semantic LLM | 3 | — |
| Adversarial | — | 3/3 |

The regex scanner finds 6 pattern matches (all `AccountInfo` without owner checks — false positives on PDA vaults with `/// CHECK:` docs), but **zero** logic bugs.

The LLM finds all three:

| # | Severity | Bug | Function |
|---|----------|-----|----------|
| 1 | CRITICAL | Collateral check ignores existing debt | `borrow()` |
| 2 | CRITICAL | Withdraw permits full withdrawal with outstanding borrows | `withdraw()` |
| 3 | HIGH | Integer overflow in liquidation debt calculation | `liquidate()` |

For each bug, the adversarial layer generates a complete TypeScript exploit test.

## Quick Start

### Full Pipeline (Recommended)

```bash
git clone https://github.com/mbarreiroaraujo-cloud/anchor-shield.git
cd anchor-shield
pip install -r requirements.txt

# Run with pre-computed demo results (no API key needed)
python agent/orchestrator.py examples/vulnerable-lending/ --demo

# Run with live LLM analysis (requires API key)
export ANTHROPIC_API_KEY=sk-ant-...
python agent/orchestrator.py examples/vulnerable-lending/
```

### Static Scanner Only

```bash
# Scan a local Anchor project
python -m scanner.cli scan ./path/to/anchor/program

# Scan a GitHub repository
python -m scanner.cli scan https://github.com/owner/repo

# Generate JSON report
python -m scanner.cli scan ./my-program --format json -o report.json

# Check deployed program
python -m scanner.cli check <PROGRAM_ID> --network mainnet-beta
```

### Web Dashboard

```bash
cd dashboard && npm install && npm run dev
```

Open http://localhost:5173 — the dashboard has four views:
- **Static Scan** — Regex pattern matching (original functionality)
- **Semantic Analysis** — LLM findings with attack scenarios
- **Exploits** — Generated TypeScript exploit code
- **Compare** — Side-by-side layer comparison

## Static Detection Patterns

6 regex-based patterns for known Anchor framework vulnerabilities:

| ID | Pattern | Severity |
|----|---------|----------|
| ANCHOR-001 | init_if_needed incomplete field validation | High |
| ANCHOR-002 | Duplicate mutable account bypass | Medium |
| ANCHOR-003 | Realloc payer missing signer verification | Medium |
| ANCHOR-004 | Account type cosplay / missing discriminator | Medium |
| ANCHOR-005 | Close + reinit lifecycle attack | Medium |
| ANCHOR-006 | Missing owner validation | High |

## Semantic Analysis

The `SemanticAnalyzer` sends program source code to the Claude API with a specialized security auditor system prompt. It:

- Focuses exclusively on **logic** vulnerabilities (not pattern issues)
- Returns structured findings with severity, description, and step-by-step attack scenarios
- Includes confidence scores (0.0-1.0)
- Filters out false positives (missing CHECK comments, AccountInfo typing, etc.)

```python
from semantic.analyzer import SemanticAnalyzer

analyzer = SemanticAnalyzer()  # uses ANTHROPIC_API_KEY from env
code = open('examples/vulnerable-lending/src/lib.rs').read()
findings = analyzer.analyze(code, 'lending_pool.rs')
```

## Adversarial Exploit Synthesis

The `ExploitSynthesizer` takes each semantic finding and generates a complete Anchor test (TypeScript) that exploits the vulnerability:

```python
from adversarial.synthesizer import ExploitSynthesizer

synth = ExploitSynthesizer()
exploit = synth.generate_exploit(source_code, finding.to_dict())
# exploit.code contains a complete TypeScript test file
```

Each exploit:
1. Initializes the program and accounts
2. Sets up a legitimate scenario
3. Executes the attack step by step
4. Asserts the attacker profited / protocol lost funds

## Project Structure

```
anchor-shield/
  scanner/          # Static regex pattern engine (6 patterns)
  semantic/         # LLM-powered logic analysis
  adversarial/      # Exploit generation
  agent/            # Orchestrator pipeline
  dashboard/        # React web dashboard
  exploits/         # Generated exploit PoCs
  examples/
    vulnerable-lending/   # Demo vulnerable Anchor program
    demo-output/          # Pre-computed analysis results
  tests/            # 19 test cases for static patterns
```

## Testing

```bash
# Run original static scanner tests (19/19)
python -m pytest tests/test_scanner.py -v

# Run full pipeline in demo mode
python agent/orchestrator.py examples/vulnerable-lending/ --demo
```

## Requirements

- **Python 3.11+** with dependencies in `requirements.txt`
- **Node.js 18+** for the dashboard
- **Anthropic API key** for live semantic analysis and exploit generation
- **Solana/Anchor toolchain** (optional) for compiling the demo program and executing exploits

## Limitations

- Semantic analysis depends on the LLM — possible false positives on novel code patterns
- Exploit execution requires Solana CLI + Anchor CLI + local validator
- Without an API key, the pipeline uses pre-computed demo results
- Static regex patterns only cover 6 known Anchor framework vulnerabilities
- Does not substitute professional human security auditing
- GitHub API rate limits apply when scanning remote repositories

## License

MIT — see [LICENSE](LICENSE)
