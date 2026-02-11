# Architecture

## Overview

anchor-shield is a static analysis tool that detects known vulnerability patterns in Solana Anchor programs. It operates at the source code level, matching structural patterns in Rust code that indicate framework-level security issues.

## System Components

```
┌─────────────────────────────────────────────────────┐
│                    User Interface                     │
│  ┌──────────┐  ┌───────────────┐  ┌──────────────┐ │
│  │   CLI    │  │  Web Dashboard │  │  JSON/HTML   │ │
│  │ (click)  │  │  (React+Vite) │  │   Reports    │ │
│  └────┬─────┘  └──────┬────────┘  └──────┬───────┘ │
│       │               │                   │         │
├───────┼───────────────┼───────────────────┼─────────┤
│       ▼               ▼                   ▼         │
│  ┌────────────────────────────────────────────┐     │
│  │            Scanner Engine (Python)          │     │
│  │  ┌──────────────────────────────────────┐  │     │
│  │  │     Pattern Matcher (6 patterns)      │  │     │
│  │  │  ┌──────┐┌──────┐┌──────┐           │  │     │
│  │  │  │ 001  ││ 002  ││ 003  │  ...      │  │     │
│  │  │  └──────┘└──────┘└──────┘           │  │     │
│  │  └──────────────────────────────────────┘  │     │
│  │  ┌──────────────┐  ┌──────────────────┐   │     │
│  │  │ GitHub Client │  │  Solana Client   │   │     │
│  │  │ (fetch repos) │  │ (RPC queries)    │   │     │
│  │  └──────────────┘  └──────────────────┘   │     │
│  └────────────────────────────────────────────┘     │
└─────────────────────────────────────────────────────┘
```

## Scanner Engine

### Pattern Detection Approach

The scanner uses a two-phase approach for each file:

1. **Structure Extraction:** Parse `#[derive(Accounts)]` structs using brace-counting (not regex for struct bodies, avoiding catastrophic backtracking). Extract fields with their multi-line attributes.

2. **Pattern Matching:** Run each detection pattern against the extracted fields. Patterns check attribute combinations, field types, and cross-field relationships.

### Multi-line Attribute Handling

Anchor attributes often span multiple lines:
```rust
#[account(
    init_if_needed,
    payer = payer,
    token::mint = mint,
)]
```

The parser tracks parenthesis depth to correctly associate multi-line attributes with their fields, then joins them into a single string for pattern matching.

### False Positive Mitigation

Each pattern implements safe-pattern filters:

| Pattern | Safe Pattern (suppressed) |
|---------|--------------------------|
| ANCHOR-001 | `constraint = account.delegate.is_none()` present |
| ANCHOR-002 | Different base types on init_if_needed vs mut |
| ANCHOR-003 | Payer field typed as `Signer<'info>` |
| ANCHOR-004 | `/// CHECK:` comment, `owner =` constraint |
| ANCHOR-005 | Only `close` without `init_if_needed` on same type |
| ANCHOR-006 | `Account<T>`, `Signer`, `Program` types; CHECK comments |

## Detection Patterns

### ANCHOR-001: init_if_needed Incomplete Field Validation
- **Source:** Anchor's `constraints.rs` — `generate_constraint_init_group`
- **Issue:** `from_account_info_unchecked` validates only mint/owner/token_program
- **Detection:** Find `init_if_needed` + `token::` without delegate/close_authority constraints

### ANCHOR-002: Duplicate Mutable Account Bypass
- **Source:** Anchor's `try_accounts.rs` — `generate_duplicate_mutable_checks`
- **Issue:** `constraints.init.is_none()` filter excludes init_if_needed from duplicate check
- **Detection:** Find init_if_needed coexisting with mut of same Account<T> type

### ANCHOR-003: Realloc Payer Signer Gap
- **Source:** Anchor's `constraints.rs` — `generate_constraint_realloc`
- **Issue:** Lamport transfer via `borrow_mut()` bypasses CPI signer checks
- **Detection:** Find `realloc::payer = X` where X is not typed as `Signer<'info>`

### ANCHOR-004: Account Type Cosplay
- **Issue:** Raw `AccountInfo` skips discriminator and owner verification
- **Detection:** Find `AccountInfo<'info>` fields without owner constraints or CHECK docs

### ANCHOR-005: Close + Reinit Lifecycle Attack
- **Issue:** Closed accounts can be revived via init_if_needed
- **Detection:** Find same account type used in both close and init_if_needed constraints

### ANCHOR-006: Missing Owner Validation
- **Issue:** Unverified accounts can be substituted with attacker-controlled data
- **Detection:** Find AccountInfo/UncheckedAccount without owner checks, signer constraints, or CHECK docs

## Solana Integration

### Program Metadata (RPC)
- `getAccountInfo` to check program existence, owner, executable status
- BPF Upgradeable Loader detection for upgrade authority analysis
- PDA derivation for Anchor IDL account address

### On-Chain Risk Assessment
Risk score computed from:
- Is program upgradeable? (+2)
- Is account executable? (not = +5)
- IDL found on-chain? (no = +1)

## Web Dashboard

The dashboard runs entirely in the browser:
1. User enters GitHub repo URL
2. React app fetches file tree via GitHub API
3. Fetches raw content for each `.rs` file
4. Runs JavaScript scanner patterns against content
5. Displays results with severity indicators

No backend required — deployable as a static site.

## Adding New Patterns

1. Create `scanner/patterns/new_pattern.py` extending `VulnerabilityPattern`
2. Implement `scan(file_path, content) -> list[Finding]`
3. Add safe-pattern filters to avoid false positives
4. Register in `scanner/patterns/__init__.py`
5. Add tests in `tests/test_scanner.py`
6. Mirror detection logic in `dashboard/src/scanner.js`
