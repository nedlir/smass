"""Sandbox Agent: build the isolated workspace the whole run shares."""

from __future__ import annotations


class SandboxAgent:
    name = "sandbox"

    def __init__(self, cfg=None):
        self.cfg = cfg

    def run(self, client, project_path) -> str:
        result = client.call(
            "create_workspace", source_type="local", source=str(project_path)
        )
        workspace_id = result.get("workspace_id") or result.get("id")
        if not workspace_id:
            raise RuntimeError("create_workspace returned no workspace_id")
        return workspace_id
