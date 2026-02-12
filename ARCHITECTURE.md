# Architecture

## Overview

anchor-shield is a three-layer security analysis tool for Solana Anchor programs. It combines static pattern matching, semantic LLM analysis, and adversarial exploit synthesis into an autonomous security pipeline.

## System Components

```
┌──────────────────────────────────────────────────────────────┐
│                      User Interface                           │
│  ┌──────────┐  ┌───────────────┐  ┌──────────────────────┐  │
│  │   CLI    │  │  Web Dashboard │  │  SECURITY_REPORT.json│  │
│  │(argparse)│  │  (React+Vite) │  │   (structured data)  │  │
│  └────┬─────┘  └──────┬────────┘  └──────────┬───────────┘  │
│       │               │                       │              │
├───────┼───────────────┼───────────────────────┼──────────────┤
│       ▼               ▼                       ▼              │
│  ┌─────────────────────────────────────────────────────┐     │
│  │           Orchestrator (agent/orchestrator.py)       │     │
│  │  Chains all analysis phases into a single pipeline  │     │
│  └──┬────────────┬────────────────┬────────────────┬───┘     │
│     │            │                │                │         │
│     ▼            ▼                ▼                ▼         │
│  ┌────────┐  ┌──────────┐  ┌──────────────┐  ┌─────────┐   │
│  │ Static │  │ Semantic │  │   Exploit    │  │ Exploit │   │
│  │ Scan   │  │ Analyzer │  │  Synthesizer │  │Executor │   │
│  │(regex) │  │  (LLM)   │  │   (LLM)     │  │(Python) │   │
│  └────────┘  └──────────┘  └──────────────┘  └─────────┘   │
│                                                              │
│  scanner/     semantic/       adversarial/     subprocess    │
└──────────────────────────────────────────────────────────────┘
```

## Data Flow

```
Input: Path to Anchor program (.rs files)
  │
  ├─► Phase 1: Static Pattern Scan
  │     scanner.engine.AnchorShieldEngine
  │     Input:  .rs file content
  │     Output: List[Finding] — regex pattern matches
  │     No external calls
  │
  ├─► Phase 2: Semantic LLM Analysis
  │     semantic.analyzer.SemanticAnalyzer
  │     Input:  .rs source code + security audit prompt
  │     Output: List[SemanticFinding] — logic vulnerabilities
  │     API:    Claude API (claude-sonnet-4-20250514)
  │     Fallback: Pre-validated results when API unavailable
  │
  ├─► Phase 3: Exploit Generation
  │     adversarial.synthesizer.ExploitSynthesizer
  │     Input:  SemanticFinding + source code
  │     Output: List[ExploitCode] — Python simulation scripts
  │     API:    Claude API (optional)
  │     Fallback: Pre-built exploit simulations
  │
  └─► Phase 4: Exploit Execution
        subprocess.run(python3 exploit_*.py)
        Input:  Generated .py files
        Output: SIMULATED / CONFIRMED / FAILED status
        No external calls

Output: SECURITY_REPORT.json with all findings + exploit results
```

## Module Details

### scanner/ — Static Pattern Engine (v1)

The original regex-based scanner. Detects 6 known Anchor vulnerability patterns:

| Pattern | ID | Severity |
|---------|-----|----------|
| init_if_needed Incomplete Field Validation | ANCHOR-001 | High |
| Duplicate Mutable Account Bypass | ANCHOR-002 | Medium |
| Realloc Payer Missing Signer | ANCHOR-003 | Medium |
| Account Type Cosplay | ANCHOR-004 | Medium |
| Close + Reinit Lifecycle Attack | ANCHOR-005 | Medium |
| Missing Owner Validation | ANCHOR-006 | High |

Key files:
- `engine.py` — Core `AnchorShieldEngine` class, file discovery, scoring
- `patterns/base.py` — `Finding` dataclass, `VulnerabilityPattern` base class
- `patterns/*.py` — Individual pattern implementations

### semantic/ — LLM Semantic Analyzer (v2)

Sends source code to the Claude API with a specialized security prompt.

Key files:
- `analyzer.py` — `SemanticAnalyzer` class with API calls, response parsing, fallback
- `prompts.py` — `SECURITY_AUDITOR_SYSTEM_PROMPT` constant

The system prompt instructs the LLM to:
1. Map all state-modifying instructions
2. Trace cross-instruction dependencies
3. Check arithmetic for overflow/underflow
4. Verify economic invariants
5. Return structured JSON findings

### adversarial/ — Exploit Synthesizer (v2)

Generates proof-of-concept exploit simulations.

Key files:
- `synthesizer.py` — `ExploitSynthesizer` class, `ExploitCode` dataclass

Each generated exploit:
- Models on-chain state as Python dataclasses
- Implements vulnerable instruction logic
- Executes attack with state transitions
- Asserts exploit outcomes

### agent/ — Autonomous Orchestrator (v2)

Single-command entry point that chains all phases.

Key files:
- `orchestrator.py` — `SecurityOrchestrator` class, CLI interface

### dashboard/ — Web UI

React + Tailwind CSS single-page application.

Tabs: Overview | Semantic Analysis | Exploits | Static Scanner

## API Interaction

The tool makes API calls in two places:

1. **Semantic analysis** (`semantic/analyzer.py`):
   - Endpoint: `POST https://api.anthropic.com/v1/messages`
   - Model: `claude-sonnet-4-20250514`
   - Max tokens: 4096
   - Retry: 3 attempts with exponential backoff

2. **Exploit generation** (`adversarial/synthesizer.py`):
   - Same endpoint and model
   - Separate system prompt for exploit code generation
   - Retry: 3 attempts with exponential backoff

Both fall back to pre-validated/pre-built data when the API is unavailable.

## Adding New Patterns (Static Scanner)

1. Create a new file in `scanner/patterns/` (e.g., `my_pattern.py`)
2. Subclass `VulnerabilityPattern` from `base.py`
3. Implement the `scan()` method returning `List[Finding]`
4. Register in `scanner/patterns/__init__.py`

## Tuning the Semantic Prompt

The prompt in `semantic/prompts.py` can be adapted for different program types:

- **DeFi programs**: Emphasize collateral ratios, liquidity checks, price manipulation
- **Token programs**: Focus on supply conservation, mint authority, burn validation
- **Governance**: Check voting weight manipulation, timelock bypass, quorum gaming

The prompt structure (methodology -> focus areas -> output format) should be preserved.

## Dependencies

- **Python 3.9+**: Core analysis pipeline
- **Node.js 18+**: Dashboard build (Vite + React)
- **No compiled dependencies**: The tool uses only Python stdlib for API calls (urllib)
- **Optional**: Anthropic API key for live LLM analysis
