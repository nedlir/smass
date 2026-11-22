"""SCA Agent: find known-vulnerable dependencies."""

from __future__ import annotations

from .base import ScannerAgent


class ScaAgent(ScannerAgent):
    category = "sca"
    name = "sca"
