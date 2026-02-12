# anchor-shield

[![Tests](https://github.com/mbarreiroaraujo-cloud/anchor-shield/actions/workflows/tests.yml/badge.svg)](https://github.com/mbarreiroaraujo-cloud/anchor-shield/actions/workflows/tests.yml)
[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](LICENSE)

**On-chain security attestation protocol for Solana Anchor programs — powered by original vulnerability research**

> anchor-shield scans Anchor programs for known vulnerability patterns and publishes immutable security attestations on Solana. An autonomous agent handles the full cycle: scan source code, analyze findings, compute a security score, and write the result on-chain as a structured memo transaction. Other programs and users can query these attestations to verify whether a target has been audited.

> Built on original security research that discovered 3 novel vulnerabilities in the Anchor framework itself ([PR #4229](https://github.com/solana-foundation/anchor/pull/4229)).

**[Live Dashboard](https://mbarreiroaraujo-cloud.github.io/anchor-shield/)** · **[Audit PR #4229](https://github.com/solana-foundation/anchor/pull/4229)** · **[Architecture](ARCHITECTURE.md)**

---

## How It Works

```
                         anchor-shield protocol

  ┌──────────────┐     ┌──────────────────┐     ┌───────────────────┐
  │  Source Code  │────▶│  Scanner Engine   │────▶│  Security Report  │
  │  (GitHub/     │     │  (6 vulnerability │     │  (score, issues,  │
  │   local dir)  │     │   patterns)       │     │   severity map)   │
  └──────────────┘     └──────────────────┘     └────────┬──────────┘
                                                         │
                                                         ▼
                                              ┌──────────────────┐
                                              │  Attestation      │
                                              │  Publisher         │
                                              │  (Solana devnet)   │
                                              └────────┬──────────┘
                                                       │
                                                       ▼
                                            ┌────────────────────┐
                                            │  On-Chain Memo TX  │
                                            │  (immutable,       │
                                            │   queryable,       │
                                            │   verifiable)      │
                                            └────────────────────┘
```

1. **Scan**: The scanner engine analyzes Rust source code for 6 framework-level vulnerability patterns
2. **Analyze**: Findings are aggregated into a security report with score (A-F), severity breakdown, and fix recommendations
3. **Attest**: The autonomous agent publishes the scan result as a structured memo transaction on Solana devnet
4. **Query**: Anyone can look up attestations by wallet address or transaction signature via the dashboard or indexer

## Quick Start

### Install

```bash
# Python dependencies (scanner + agent)
pip install -r requirements.txt

# Dashboard (optional)
cd dashboard && npm install && cd ..
```

### Scan and Attest (Full Autonomous Cycle)

```bash
# Scan a local project and publish attestation on Solana devnet
python -m agent attest ./path/to/anchor/program

# Scan a GitHub repository and publish attestation
python -m agent attest https://github.com/owner/repo

# Save full results to a file
python -m agent attest ./my-program --output results.json
```

### Scan Only (No On-Chain Attestation)

```bash
# Scan a local directory
python -m agent scan ./path/to/anchor/program

# Scan with the original CLI (terminal/JSON/HTML output)
python -m scanner.cli scan ./my-program --format json -o report.json
```

### Query Attestations

```bash
# Query your own attestation history
python -m agent query

# Query a specific authority's attestations
python -m agent query <WALLET_ADDRESS>
```

### Check Deployed Program

```bash
python -m scanner.cli check <PROGRAM_ID> --network mainnet-beta
```

### Web Dashboard

```bash
cd dashboard && npm install && npm run dev
```

Open http://localhost:5173 — three modes available:
- **GitHub Repo**: Scan a repository for vulnerabilities
- **On-Chain Program**: Check deployed program metadata and risk
- **Attestations**: Query on-chain attestation history by wallet address

### Run the Demo

```bash
python demo.py
```

Runs a complete scan-and-attest cycle on the included test fixtures, publishing a real attestation on Solana devnet.

## Detection Patterns

| ID | Pattern | Severity | Origin |
|----|---------|----------|--------|
| ANCHOR-001 | init_if_needed incomplete field validation | High | [PR #4229](https://github.com/solana-foundation/anchor/pull/4229) |
| ANCHOR-002 | Duplicate mutable account bypass | Medium | [PR #4229](https://github.com/solana-foundation/anchor/pull/4229) |
| ANCHOR-003 | Realloc payer missing signer verification | Medium | [PR #4229](https://github.com/solana-foundation/anchor/pull/4229) |
| ANCHOR-004 | Account type cosplay / missing discriminator | Medium | Known pattern |
| ANCHOR-005 | Close + reinit lifecycle attack | Medium | Known pattern |
| ANCHOR-006 | Missing owner validation | High | Known pattern |

## On-Chain Attestation Protocol

### Memo Format

Each attestation is published as a structured memo transaction on Solana devnet:

```
ASHIELD|<version>|<target_hash>|s=<score>|i=<issues>|p=<patterns>|sev=<severity>|h=<report_hash>
```

| Field | Description |
|-------|-------------|
| `ASHIELD` | Protocol identifier |
| `version` | Scanner version (e.g., `0.1.0`) |
| `target_hash` | SHA-256 of the scanned target (first 16 hex chars) |
| `s=N` | Security score (0-100, where 100 = no issues) |
| `i=N` | Number of issues found |
| `p=N` | Number of patterns checked |
| `sev=CNHNMNLN` | Severity breakdown (Critical, High, Medium, Low counts) |
| `h=...` | SHA-256 hash of the full off-chain report (first 32 hex chars) |

### Anchor Program (Reference Design)

The `programs/security_attestation/` directory contains a full Anchor program (Rust) that stores attestations as PDAs:

- **PDA derivation**: `seeds = [b"attestation", target_hash]`
- **Instructions**: `create_attestation`, `update_attestation`
- **State**: SecurityAttestation account with score, issues, report hash, authority, timestamp
- **Events**: AttestationCreated, AttestationUpdated

This program can be deployed to devnet for richer on-chain storage. The current implementation uses Solana memo transactions as a lighter-weight approach that requires no program deployment.

### Verifiability

Every attestation includes:
1. **On-chain proof**: Transaction signature verifiable on Solana Explorer
2. **Report integrity**: SHA-256 hash of the full report for tamper detection
3. **Authority binding**: Signed by the scanner operator's keypair
4. **Timestamp**: Block time of the attestation transaction

## Architecture

```
anchor-shield/
├── scanner/                        # Static analysis engine (Python)
│   ├── engine.py                   # Core scanning engine
│   ├── cli.py                      # Original CLI interface
│   ├── report.py                   # Report generation (terminal/JSON/HTML)
│   ├── github_client.py            # GitHub API integration
│   ├── solana_client.py            # Solana RPC integration
│   └── patterns/                   # Pluggable detection patterns
│       ├── base.py                 # Base class + Finding dataclass
│       ├── init_if_needed.py       # ANCHOR-001
│       ├── duplicate_mutable.py    # ANCHOR-002
│       ├── realloc_payer.py        # ANCHOR-003
│       ├── type_cosplay.py         # ANCHOR-004
│       ├── close_reinit.py         # ANCHOR-005
│       └── missing_owner.py        # ANCHOR-006
├── agent/                          # Autonomous attestation agent (Python)
│   ├── autonomous.py               # Agent loop: scan → analyze → attest
│   ├── attestation.py              # On-chain publisher (Solana SDK)
│   ├── indexer.py                  # On-chain attestation reader
│   ├── cli.py                      # Agent CLI
│   └── config.py                   # Configuration
├── programs/                       # On-chain program (Rust/Anchor)
│   └── security_attestation/       # Attestation PDA program
│       └── src/lib.rs              # Program instructions + state
├── dashboard/                      # Web UI (React + Vite + Tailwind)
│   └── src/
│       ├── App.jsx                 # Main component with attestation view
│       └── scanner.js              # In-browser scanner + attestation query
├── tests/
│   ├── test_scanner.py             # Scanner unit tests (19 tests)
│   └── test_agent.py               # Agent unit tests (21 tests)
├── demo.py                         # One-command demo script
└── examples/                       # Example output files
```

See [ARCHITECTURE.md](ARCHITECTURE.md) for detailed technical documentation.

## Test Results

```
$ python -m pytest tests/ -v

tests/test_scanner.py   19 passed    Scanner patterns + engine integration
tests/test_agent.py     21 passed    Attestation memo, indexer parsing, agent pipeline

40 passed in 0.47s
```

## Research Foundation

This tool is built on original security research. We audited the Anchor framework and discovered 3 previously unknown vulnerabilities:

| Finding | Severity | Description |
|---------|----------|-------------|
| V-1: init_if_needed field validation | High | Token accounts accepted without delegate/close_authority validation |
| V-2: Duplicate mutable account bypass | Medium | init_if_needed accounts excluded from duplicate check |
| V-3: Realloc payer signer enforcement | Medium | Lamport transfer without signer verification |

These findings were submitted as [PR #4229](https://github.com/solana-foundation/anchor/pull/4229) to solana-foundation/anchor.

## How Solana Is Used

1. **On-chain attestations**: Security scan results are published as immutable memo transactions on Solana devnet, creating a verifiable audit trail
2. **Attestation indexing**: Transaction history is queried via RPC to retrieve and display past attestations
3. **Program metadata**: Fetches on-chain program account info (executable status, upgrade authority, owner) for risk assessment
4. **IDL detection**: Queries Anchor IDL accounts at derived PDA addresses
5. **Anchor program design**: Reference implementation of a custom attestation program using PDAs and events

## Agent Autonomy

The autonomous agent handles the complete security attestation lifecycle without human intervention:

1. **Accepts a target** (GitHub repo URL, local directory, or raw content)
2. **Fetches source files** from GitHub API or local filesystem
3. **Runs all 6 detection patterns** against every Rust file
4. **Aggregates findings** into a scored security report
5. **Generates a new Solana wallet** and requests a devnet airdrop
6. **Publishes the attestation** as a structured memo transaction
7. **Returns full results** with on-chain transaction proof

Each step is logged and trackable. The agent can also run in scan-only mode (no attestation) or query mode (read existing attestations).

## Scope and Limitations

- **Scanner type:** Static pattern analysis (source code only)
- **Languages supported:** Rust (Anchor framework programs)
- **Network:** Attestations published on Solana devnet (no real funds)
- **Known limitations:**
  - Cannot detect custom business logic vulnerabilities (only framework-level patterns)
  - GitHub API rate limits restrict scanning speed (60 req/hr unauthenticated)
  - On-chain attestations use memo program (lighter weight than custom program deployment)
  - Devnet attestations are subject to devnet data retention policies
- **Future development:** Custom program deployment, mainnet attestations, cross-program attestation queries

## License

MIT — see [LICENSE](LICENSE)

## Author

- **Miguel Barreiro Araujo**
- **GitHub:** [mbarreiroaraujo-cloud](https://github.com/mbarreiroaraujo-cloud)
