"""Test double for the MCP client, mirroring MCPwner's real response shapes.

Test-only (not part of the shipped package). No mocking framework: a dict of
canned responses plus a call log and an in-memory findings ledger keyed by id.
"""

from __future__ import annotations

import threading
from typing import Any


class FakeMcpClient:
    def __init__(self):
        self._responses: dict[str, Any] = {}
        self._ledger: dict[str, dict[str, dict]] = {}  # workspace_id -> {id: finding}
        self._lock = threading.RLock()
        self.calls: list[tuple[str, dict]] = []

    # --- test helpers -------------------------------------------------
    def set_response(self, tool: str, response) -> None:
        """Set a canned response (a dict, or a callable taking the call args)."""
        self._responses[tool] = response

    def count(self, tool: str) -> int:
        return sum(1 for name, _ in self.calls if name == tool)

    def last(self, tool: str) -> dict:
        """Arguments of the most recent call to `tool`."""
        return [args for name, args in self.calls if name == tool][-1]

    def ledger(self, workspace_id: str = "ws1") -> list[dict]:
        return list(self._ledger.get(workspace_id, {}).values())

    # --- McpClient protocol ------------------------------------------
    def list_tools(self) -> list[str]:
        return list(_DEFAULT_TOOLS)

    def call(self, name: str, **args: Any) -> dict:
        with self._lock:
            self.calls.append((name, args))
            if name == "upsert_finding":
                return self._upsert(args)
            if name == "list_findings":
                wsid = args.get("workspace_id", "ws")
                return {"status": "success", "findings": self.ledger(wsid)}
            if name in self._responses:
                resp = self._responses[name]
                return resp(args) if callable(resp) else resp
            return _default(name)

    def _upsert(self, args: dict) -> dict:
        wsid = args.get("workspace_id", "ws")
        finding = args.get("finding", {})
        fid = finding.get("id", "")
        store = self._ledger.setdefault(wsid, {})
        store[fid] = {**store.get(fid, {}), **finding}  # merge by id
        return {"status": "success", "id": fid, "finding": store[fid]}

    def close(self) -> None:
        pass


def _default(tool: str) -> dict:
    if tool == "create_workspace":
        return {"workspace_id": "ws1"}
    if tool == "detect_languages":
        return {"languages": ["python"]}
    if tool == "create_codeql_database":
        return {"database_id": "db1", "language": "python", "status": "success"}
    if tool == "execute_query":
        return {"status": "success", "findings": []}
    if tool == "generate_report":
        return {"status": "success", "report_path": "/workspaces/ws1/report.md"}
    if tool == "run_poc_scan":
        return {"oracle_passed": True, "finding_count": 1}
    if tool == "get_poc_report":
        run = {"script": "print('PROOF: x')", "exit_code": 0, "stdout": "PROOF: x\n",
               "stderr": "", "oracle": {"passed": True, "decided_by": "exit_code"}}
        return {"status": "success", "sarif": run, "report_content": run}
    if tool.startswith("run_") and tool.endswith("_scan"):
        return {"status": "success", "finding_count": 0, "report_path": "/x.sarif"}
    if tool.startswith("get_") and tool.endswith("_report"):
        return {"sarif": {"findings": []}}
    return {}


# Advertised tool surface (cosmetic; the real client probes MCPwner at startup).
_DEFAULT_TOOLS = [
    "create_workspace", "detect_languages",
    "run_secrets_scan", "get_secrets_report",
    "run_sast_scan", "get_sast_report",
    "run_sca_scan", "get_sca_report",
    "run_iac_scan", "get_iac_report",
    "create_codeql_database", "execute_query",
    "upsert_finding", "list_findings", "generate_report", "run_poc_scan",
    "get_poc_report",
]
