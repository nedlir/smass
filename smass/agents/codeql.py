"""CodeQL Agent: build a database, then run a builtin query pack.

CodeQL is a separate MCPwner flow (not run_<cat>_scan): create_codeql_database
then execute_query, which returns already-parsed findings under "findings".
"""

from __future__ import annotations

from . import base
from .base import AgentResult


class CodeqlAgent:
    name = "codeql"

    def __init__(self, cfg=None):
        self.cfg = cfg

    def run(self, client, workspace_id: str) -> AgentResult:
        db = client.call("create_codeql_database", workspace_id=workspace_id)
        db_id = db.get("database_id")
        if not db_id or db.get("status") == "error":
            return AgentResult(
                "codeql", [], skipped=True, note=db.get("error") or "no codeql database"
            )
        result = client.call(
            "execute_query",
            workspace_id=workspace_id,
            database_id=db_id,
            query_pack="security-extended",
            query_type="builtin",
        )
        if result.get("status") != "success":
            # e.g. "running": the query is still going; don't report 0 as clean.
            return AgentResult(
                "codeql", [], skipped=True,
                note=result.get("message") or result.get("error") or "codeql incomplete",
            )
        findings = [
            base.normalize_finding(
                {
                    "tool": "codeql",
                    "rule_id": r.get("rule_id") or r.get("rule_name", ""),
                    "severity": base.normalize_severity(r.get("severity")),
                    "file": r.get("file", ""),
                    "line": r.get("start_line", 0),
                    "message": r.get("message") or r.get("description", ""),
                    "snippet": r.get("snippet", ""),
                },
                "codeql",
            )
            for r in (result.get("findings") or [])
            if isinstance(r, dict)
        ]
        base.upsert_findings(client, workspace_id, findings, "codeql")
        return AgentResult("codeql", findings, note=f"codeql: {len(findings)}")
