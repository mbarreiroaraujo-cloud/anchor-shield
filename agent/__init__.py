"""Autonomous security orchestrator for anchor-shield.

Provides the single-command entry point that runs the complete
analysis pipeline: static scan -> semantic analysis -> exploit
generation -> exploit execution -> consolidated report.
"""

from agent.orchestrator import SecurityOrchestrator

__all__ = ["SecurityOrchestrator"]
