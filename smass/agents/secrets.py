"""Secrets Agent: detect leaked credentials in code and git history."""

from __future__ import annotations

from .base import ScannerAgent


class SecretsAgent(ScannerAgent):
    category = "secrets"
    name = "secrets"
