"""Adversarial exploit synthesis module for anchor-shield.

Generates proof-of-concept exploit code for vulnerabilities
discovered by the semantic analyzer. Exploits are self-contained
Python simulations that model on-chain state and demonstrate
the attack step by step.
"""

from adversarial.synthesizer import ExploitSynthesizer, ExploitCode

__all__ = ["ExploitSynthesizer", "ExploitCode"]
