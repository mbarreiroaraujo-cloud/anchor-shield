# anchor-shield

[![Tests](https://github.com/mbarreiroaraujo-cloud/anchor-shield/actions/workflows/tests.yml/badge.svg)](https://github.com/mbarreiroaraujo-cloud/anchor-shield/actions/workflows/tests.yml)
[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](LICENSE)

**Automated security scanner for Solana Anchor programs — powered by original vulnerability research**

> anchor-shield detects known vulnerability patterns in Anchor programs and assesses real-world on-chain risk. Built on original security research that discovered 3 novel vulnerabilities in the Anchor framework itself ([PR #4229](https://github.com/solana-foundation/anchor/pull/4229)).

**[Live Dashboard](https://mbarreiroaraujo-cloud.github.io/anchor-shield/)** · **[Audit PR #4229](https://github.com/solana-foundation/anchor/pull/4229)** · **[Architecture](ARCHITECTURE.md)**

## What It Does

anchor-shield scans Anchor program source code for 6 framework-level vulnerability patterns. Unlike general-purpose auditing tools, it targets issues in how Anchor *generates* code — patterns that individual developers cannot easily spot because they originate in the framework's code generation layer.

The scanner works locally, against GitHub repositories, and can assess deployed programs via Solana RPC. Each finding includes root cause analysis, exploit scenarios, and specific fix recommendations.

### Screenshots

<details>
<summary>CLI Scanner Output</summary>

![CLI Scan Output](docs/screenshots/cli-scan-output.png)

</details>

<details>
<summary>Web Dashboard</summary>

![Dashboard](docs/screenshots/dashboard-scan-results.png)

</details>

<details>
<summary>Test Results (19/19 passing)</summary>

![Test Results](docs/screenshots/test-results.png)

</details>

### Detection Patterns

| ID | Pattern | Severity | Origin |
|----|---------|----------|--------|
| ANCHOR-001 | init_if_needed incomplete field validation | High | [PR #4229](https://github.com/solana-foundation/anchor/pull/4229) |
| ANCHOR-002 | Duplicate mutable account bypass | Medium | [PR #4229](https://github.com/solana-foundation/anchor/pull/4229) |
| ANCHOR-003 | Realloc payer missing signer verification | Medium | [PR #4229](https://github.com/solana-foundation/anchor/pull/4229) |
| ANCHOR-004 | Account type cosplay / missing discriminator | Medium | Known pattern |
| ANCHOR-005 | Close + reinit lifecycle attack | Medium | Known pattern |
| ANCHOR-006 | Missing owner validation | High | Known pattern |

## Quick Start

### CLI Scanner

```bash
# Install dependencies
pip install -r requirements.txt

# Scan a local Anchor project
python -m scanner.cli scan ./path/to/anchor/program

# Scan a GitHub repository
python -m scanner.cli scan https://github.com/solana-foundation/anchor

# Generate JSON report
python -m scanner.cli scan ./my-program --format json -o report.json

# Generate HTML report
python -m scanner.cli scan ./my-program --format html -o report.html
```

### Check Deployed Program

```bash
python -m scanner.cli check <PROGRAM_ID> --network mainnet-beta
```

### Web Dashboard

```bash
cd dashboard && npm install && npm run dev
```

Open http://localhost:5173 — paste a GitHub repo URL or Solana program ID to scan.

### One-Command Setup

```bash
bash setup.sh
```

## Example Output

### CLI Scan Results

```
anchor-shield Scan Report
============================================================
Target:           tests/test_patterns/vulnerable
Files scanned:    6
Patterns checked: 6
Scan time:        0.01s
Security score:   F

  Critical: 0  High: 5  Medium: 6  Low: 0

Findings (11):
------------------------------------------------------------

  [HIGH] ANCHOR-001 — init_if_needed Incomplete Field Validation
  File: init_if_needed_no_delegate_check.rs:21
  Token account accepted via init_if_needed without validation of
  delegate, close_authority fields.

  Fix: Add constraint = account.delegate.is_none() and
       constraint = account.close_authority.is_none()

  [MEDIUM] ANCHOR-003 — Realloc Payer Missing Signer Verification
  File: realloc_no_signer.rs:20
  Realloc payer 'payer' typed as 'AccountInfo<'info>' instead of
  Signer<'info>. Lamports transferred without signer verification.

  Fix: Change payer field type to Signer<'info>

  [MEDIUM] ANCHOR-005 — Close + Reinit Lifecycle Attack
  File: close_reinit_same_type.rs:31
  Account type 'Vault' used with both close and init_if_needed.
  Attacker can close and revive the account.

  Fix: Use plain init instead of init_if_needed
```

### Test Results

```
$ python -m pytest tests/test_scanner.py -v

tests/test_scanner.py::TestAnchor001::test_detects_vulnerable_init_if_needed PASSED
tests/test_scanner.py::TestAnchor001::test_ignores_safe_init_if_needed PASSED
tests/test_scanner.py::TestAnchor001::test_no_false_positive_plain_init PASSED
tests/test_scanner.py::TestAnchor002::test_detects_duplicate_mutable_bypass PASSED
tests/test_scanner.py::TestAnchor002::test_no_false_positive_different_types PASSED
tests/test_scanner.py::TestAnchor003::test_detects_realloc_without_signer PASSED
tests/test_scanner.py::TestAnchor003::test_ignores_realloc_with_signer PASSED
tests/test_scanner.py::TestAnchor004::test_detects_raw_account_info PASSED
tests/test_scanner.py::TestAnchor004::test_ignores_typed_account PASSED
tests/test_scanner.py::TestAnchor005::test_detects_close_reinit PASSED
tests/test_scanner.py::TestAnchor005::test_no_false_positive_close_only PASSED
tests/test_scanner.py::TestAnchor006::test_detects_missing_owner_check PASSED
tests/test_scanner.py::TestAnchor006::test_ignores_typed_account PASSED
tests/test_scanner.py::TestAnchor006::test_ignores_check_comment PASSED
tests/test_scanner.py::TestEngineIntegration::test_scan_vulnerable_directory PASSED
tests/test_scanner.py::TestEngineIntegration::test_scan_safe_directory PASSED
tests/test_scanner.py::TestEngineIntegration::test_report_json_serialization PASSED
tests/test_scanner.py::TestEngineIntegration::test_security_score_computation PASSED
tests/test_scanner.py::TestEngineIntegration::test_empty_file_no_crash PASSED

============================== 19 passed in 0.07s ==============================
```

## Architecture

- **Scanner Engine (Python):** Pattern-based static analysis of Anchor Rust code with multi-line attribute parsing and safe-pattern filtering
- **CLI Interface:** `scan`, `check`, and `report` commands with colored terminal output via `rich`
- **Web Dashboard (React):** In-browser scanning via GitHub API + Solana RPC — no backend needed
- **Detection Patterns:** Pluggable system — each pattern is a self-contained class with detection logic, false positive filters, and fix recommendations
- **Solana Integration:** Fetches program metadata, checks upgrade authority, queries IDL accounts

See [ARCHITECTURE.md](ARCHITECTURE.md) for detailed technical documentation.

## Research Foundation

This tool is built on original security research. We audited the Anchor framework and discovered 3 previously unknown vulnerabilities:

| Finding | Severity | Description |
|---------|----------|-------------|
| V-1: init_if_needed field validation | High | Token accounts accepted without delegate/close_authority validation |
| V-2: Duplicate mutable account bypass | Medium | init_if_needed accounts excluded from duplicate check |
| V-3: Realloc payer signer enforcement | Medium | Lamport transfer without signer verification |

These findings were submitted as [PR #4229](https://github.com/solana-foundation/anchor/pull/4229) to solana-foundation/anchor. anchor-shield doesn't just check for theoretical issues — it checks for patterns that are **proven exploitable** through direct analysis of Anchor's code generation.

## How Solana Is Used

1. **On-chain program metadata:** Fetches program account info via Solana RPC (executable status, owner, data size)
2. **Upgrade authority analysis:** Detects BPF Upgradeable Loader programs and identifies upgrade authority
3. **IDL account detection:** Queries Anchor IDL accounts at derived PDA addresses
4. **Deployment risk assessment:** Cross-references source findings with on-chain program status
5. **Ecosystem exposure estimation:** Quantifies how many programs may use each vulnerable pattern

## Scope and Limitations

- **Scanner type:** Static pattern analysis (source code only — does not execute or simulate programs)
- **Languages supported:** Rust (Anchor framework programs)
- **Detection methodology:** Pattern-based matching informed by original security research
- **Known limitations:**
  - Cannot detect custom business logic vulnerabilities (only framework-level patterns)
  - GitHub API rate limits restrict scanning speed for remote repos (60 req/hr unauthenticated)
  - On-chain IDL parsing requires the program to have published an IDL
  - False positive rate varies by pattern (documented per pattern in ARCHITECTURE.md)
- **Areas for future development:** Dynamic analysis, bytecode scanning, multi-framework support

## Agent Autonomy

This project was conceived, designed, and implemented autonomously by an AI agent:

- **Research:** Conducted original security audit of Anchor framework source code, analyzing `constraints.rs`, `try_accounts.rs`, and other code generation files
- **Discovery:** Identified 3 novel vulnerabilities through systematic analysis of trust boundaries, deserialization paths, and code generation gaps
- **Design:** Architected scanner engine with pluggable patterns, false positive mitigation, and multi-output format support
- **Implementation:** Built all components — Python scanner, CLI, Solana/GitHub integration, React dashboard
- **Testing:** Created true positive and true negative test fixtures for each pattern, achieving 19/19 test pass rate

The progression was: audit Anchor framework → discover vulnerabilities → submit fixes (PR #4229) → build automated detection tool.

## License

MIT — see [LICENSE](LICENSE)

## Author

- **Miguel Barreiro Araujo**
- **GitHub:** [mbarreiroaraujo-cloud](https://github.com/mbarreiroaraujo-cloud)
- **Telegram:** @miguelbarreiroaraujo
