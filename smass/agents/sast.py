"""SAST Agent: run Semgrep over the target (default ruleset)."""

from __future__ import annotations

from .base import ScannerAgent


class SastAgent(ScannerAgent):
    category = "sast"
    name = "sast"
