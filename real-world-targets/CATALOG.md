# Real-World Validation Targets

Programs acquired for real-world I+D validation of anchor-shield's semantic analysis capabilities.

| # | Program | Domain | Source | Lines | Audited? | Notes |
|---|---------|--------|--------|-------|----------|-------|
| 1 | anchor-swap | DEX/AMM | coral-xyz/anchor (tests/) | 496 | Framework test | Token swap with pool logic |
| 2 | anchor-multisig | Governance | coral-xyz/anchor (tests/) | 280 | Framework test | Multisig wallet with threshold signing |
| 3 | anchor-token-proxy | Token ops | coral-xyz/anchor (tests/) | 273 | Framework test | SPL token proxy operations |
| 4 | marinade-staking | Liquid staking | marinade-finance/liquid-staking-program | 1611 | Yes (audited) | Key files: deposit, withdraw, state, checks |
| 5 | raydium-clmm | Concentrated liquidity | raydium-io/raydium-clmm | 2931 | Yes (audited) | Key files: create_pool, liquidity, pool state |

## Selection Criteria

- **Diversity**: Different domains (DEX, staking, governance, token ops)
- **Complexity**: Range from simple (273 lines) to complex (2931 lines)
- **Audit status**: Mix of audited production protocols and framework examples
- **Relevance**: Financial operations with potential for logic bugs
