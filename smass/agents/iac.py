"""IaC Agent: scan infrastructure-as-code and Dockerfiles.

The specific tool (checkov, kics, terrascan, tfsec, hadolint) comes from
`SMASS_IAC_TOOL`. If it is unset, or the tool's container is not up, the generic
ScannerAgent flow skips cleanly (the scan returns a non-success status).
"""

from __future__ import annotations

from .base import ScannerAgent


class IacAgent(ScannerAgent):
    category = "iac"
    name = "iac"
