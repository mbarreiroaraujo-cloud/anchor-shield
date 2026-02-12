#!/bin/bash
# anchor-shield — One-command setup script

set -e

echo "Installing anchor-shield..."
echo ""

# Python dependencies
echo "[1/4] Installing Python dependencies..."
pip install solana solders requests rich click pyyaml 2>/dev/null || \
pip install --break-system-packages solana solders requests rich click pyyaml

# Dashboard dependencies
echo "[2/4] Installing dashboard dependencies..."
if command -v node &> /dev/null; then
    cd dashboard && npm install && cd ..
    echo "      Dashboard ready. Run: cd dashboard && npm run dev"
else
    echo "      Node.js not found — skipping dashboard setup."
    echo "      Install Node.js 18+ to use the web dashboard."
fi

# Verify scanner works
echo "[3/4] Verifying scanner..."
python -m scanner.cli scan tests/test_patterns/vulnerable --format json > /dev/null 2>&1
echo "      Scanner verified."

# Verify agent works
echo "[4/4] Verifying agent..."
python -m agent scan tests/test_patterns/vulnerable > /dev/null 2>&1
echo "      Agent verified."
echo ""

echo "Setup complete. Usage:"
echo ""
echo "  # Scan and publish attestation on Solana devnet"
echo "  python -m agent attest ./path/to/anchor/program"
echo ""
echo "  # Scan only (no on-chain attestation)"
echo "  python -m agent scan ./path/to/anchor/program"
echo ""
echo "  # Query attestation history"
echo "  python -m agent query"
echo ""
echo "  # Run the demo"
echo "  python demo.py"
echo ""
echo "  # Launch web dashboard"
echo "  cd dashboard && npm run dev"
echo ""
