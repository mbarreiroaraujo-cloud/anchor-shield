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
echo "[3/4] Verifying static scanner..."
python -c "from scanner.engine import AnchorShieldEngine; print('      Static scanner OK')"

# Verify semantic modules
echo "[4/4] Verifying semantic modules..."
python -c "from semantic.analyzer import SemanticAnalyzer; from adversarial.synthesizer import ExploitSynthesizer; print('      Semantic modules OK')"

echo ""
echo "Setup complete. Usage:"
echo ""
echo "  # Run full adversarial analysis pipeline"
echo "  export ANTHROPIC_API_KEY=your-api-key-here"
echo "  python agent/orchestrator.py examples/vulnerable-lending/"
echo ""
echo "  # Run without API key (demo mode with pre-validated results)"
echo "  python agent/orchestrator.py examples/vulnerable-lending/"
echo ""
echo "  # Launch web dashboard"
echo "  cd dashboard && npm run dev"
echo ""
