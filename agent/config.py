"""Configuration for the anchor-shield agent."""

import os

# Solana network endpoints
SOLANA_DEVNET_URL = "https://api.devnet.solana.com"
SOLANA_MAINNET_URL = "https://api.mainnet-beta.solana.com"
SOLANA_TESTNET_URL = "https://api.testnet.solana.com"

# Memo program ID (v2)
MEMO_PROGRAM_ID = "MemoSq4gqABAXKb96qnH8TysNcWxMyWCqXgDLGmfcHr"

# Attestation protocol identifier
PROTOCOL_ID = "anchor-shield"
PROTOCOL_VERSION = "0.1.0"

# Attestation memo prefix for indexing
MEMO_PREFIX = "ASHIELD"

# Maximum memo length (Solana memo program limit)
MAX_MEMO_LENGTH = 566

# Default network
DEFAULT_NETWORK = os.environ.get("ANCHOR_SHIELD_NETWORK", "devnet")

# Keypair path (if available)
KEYPAIR_PATH = os.environ.get(
    "ANCHOR_SHIELD_KEYPAIR",
    os.path.expanduser("~/.config/solana/id.json"),
)

# Airdrop amount in lamports (0.5 SOL for devnet)
AIRDROP_LAMPORTS = 500_000_000

# Minimum balance required for a transaction (in lamports)
MIN_BALANCE_LAMPORTS = 10_000_000

# RPC request timeout in seconds
RPC_TIMEOUT = 30

# Score mapping from letter grade to numeric (0-100)
GRADE_TO_SCORE = {
    "A": 100,
    "B+": 85,
    "B": 75,
    "C": 60,
    "D": 40,
    "F": 20,
}
