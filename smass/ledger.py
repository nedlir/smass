"""Findings ledger helpers.

Findings are written to MCPwner via `upsert_finding` so its report has them. We
do NOT read them back from MCPwner: the pipeline aggregates findings from the
agents' own results (so a run never depends on MCPwner echoing upserts).
"""

from __future__ import annotations

import hashlib


def fingerprint(finding: dict, commit_sha: str) -> str:
    """Stable id for a finding within a commit.

    Line is bucketed into bands of 10 so a small line shift does not read as a
    new finding.
    """
    line = int(finding.get("line", 0) or 0)
    key = "|".join(
        [
            commit_sha,
            str(finding.get("tool", "")),
            str(finding.get("rule_id", "")),
            str(finding.get("file", "")),
            str(line // 10),
            (str(finding.get("snippet", "")) or str(finding.get("message", "")))[:80],
        ]
    )
    return hashlib.sha256(key.encode()).hexdigest()[:16]


def dedup(findings: list[dict], commit_sha: str) -> list[dict]:
    """Drop exact duplicates (same fingerprint), keeping the first. Distinct
    findings are never merged by proximity, which could hide a real bug."""
    seen, out = set(), []
    for f in findings:
        fp = fingerprint(f, commit_sha)
        if fp not in seen:
            seen.add(fp)
            out.append(f)
    return out


def upsert(client, workspace_id: str, finding: dict) -> None:
    client.call("upsert_finding", workspace_id=workspace_id, finding=finding)
