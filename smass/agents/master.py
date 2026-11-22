"""Master Agent: rank findings, then dispatch review, PoC, and verification.

Triage uses the LLM to prioritize the consolidated findings (deterministic
severity sort as fallback), then the Code Review Agent reads the source for what
the scanners missed (logic bugs above all), and each high or critical finding
gets a PoC written and run in MCPwner's sandbox. A finding is marked verified
only when the sandbox oracle passes AND the Verifier Agent confirms the run
proves it.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field

from .. import ledger, source
from . import base
from .base import SEVERITY_ORDER
from .poc_writer import PocWriterAgent
from .reviewer import ReviewerAgent
from .verifier import VerifierAgent

TRIAGE_SYSTEM = (
    "You are a security triage lead. Given a numbered list of findings, return "
    "the indexes in priority order (most important first) as a JSON array of "
    "integers, e.g. [3, 0, 1]. Consider severity, exploitability, and blast "
    "radius. Return only the array."
)

PROVE_SEVERITIES = {"critical", "high"}


@dataclass
class ReportResult:
    report_path: str = ""
    verified: list = field(default_factory=list)
    considered: int = 0


class MasterAgent:
    def __init__(self, cfg):
        self.cfg = cfg

    def triage(self, findings: list[dict]) -> list[dict]:
        """Rank the consolidated findings. LLM order if parseable, else severity."""
        if not findings:
            return []
        try:
            summary = "\n".join(
                f"{i}: [{f.get('severity')}] {f.get('file')}:{f.get('line')} "
                f"{f.get('message')}"
                for i, f in enumerate(findings)
            )
            output = base.run_llm(
                self.cfg, self.cfg.master_model, TRIAGE_SYSTEM, summary
            )
            order = _parse_int_list(output, len(findings))
            if order:
                ranked = [findings[i] for i in order]
                missing = [f for j, f in enumerate(findings) if j not in set(order)]
                missing.sort(key=_severity_key, reverse=True)
                return ranked + missing
        except Exception:
            pass
        return sorted(findings, key=_severity_key, reverse=True)

    def dispatch(
        self, client, workspace_id: str, commit_sha: str, findings: list[dict],
        project_path=None,
    ) -> ReportResult:
        prioritized = self.triage(findings)
        # Read once, shared by review and PoC: the flagged files first.
        sources = (
            source.collect(project_path, priority=[f.get("file", "") for f in prioritized])
            if project_path else {}
        )
        reviewed = ReviewerAgent(self.cfg).review(
            client, workspace_id, commit_sha, prioritized, sources=sources
        )
        candidates = ledger.dedup(prioritized + reviewed, commit_sha)
        to_prove = [f for f in candidates if f.get("severity") in PROVE_SEVERITIES]

        poc_writer = PocWriterAgent(self.cfg)
        verifier = VerifierAgent(self.cfg)
        verified = []
        for finding in to_prove:
            finding_dir = poc_writer.author(finding, sources)
            oracle = poc_writer.run_poc(client, workspace_id, finding_dir, sources)
            if not _oracle_ok(oracle):
                continue  # sandbox oracle did not confirm the PoC
            if not verifier.verify(client, workspace_id, finding, sources):
                continue  # the run does not prove this finding
            if finding.get("id"):
                _mark_verified(client, workspace_id, finding["id"], oracle)
            verified.append({"finding": finding})

        report = client.call("generate_report", workspace_id=workspace_id)
        return ReportResult(
            report_path=report.get("report_path", ""),
            verified=verified,
            considered=len(candidates),
        )


def _mark_verified(client, workspace_id: str, finding_id: str, oracle) -> None:
    client.call(
        "upsert_finding", workspace_id=workspace_id,
        finding={
            "id": finding_id,
            "status": "review-approved",
            "review": {"verdict": "approved"},
            "poc": {"oracle": {
                "passed": True,
                "decided_by": (oracle or {}).get("oracle_decided_by"),
            }},
        },
    )


def _oracle_ok(result: dict) -> bool:
    # Fail closed: proceed only when the sandbox explicitly confirmed the PoC.
    return (result or {}).get("oracle_passed") is True


def _severity_key(finding: dict) -> int:
    return SEVERITY_ORDER.get(finding.get("severity", "info"), 0)


def _parse_int_list(text: str, n: int) -> list[int]:
    seen, order = set(), []
    for token in re.findall(r"\d+", text):
        i = int(token)
        if 0 <= i < n and i not in seen:
            seen.add(i)
            order.append(i)
    return order
