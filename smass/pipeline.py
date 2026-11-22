"""The pipeline: sandbox, then the scanners, then the Master Agent dispatches
review and PoC.

Two runners share the same stages:
  - `run_full` / `run_quick`: in-process, one MCPwner session for the whole run.
  - `stage_*`: one stage per call, each opening its own MCPwner session, so an
    orchestrator (the Airflow DAG in `dags/smass_scan.py`) can run them as
    separate processes. This works because MCPwner persists workspaces and the
    findings ledger on disk, keyed by workspace id. Stage inputs and outputs are
    plain JSON-able dicts.
"""

from __future__ import annotations

import subprocess
from concurrent.futures import ThreadPoolExecutor
from dataclasses import asdict, dataclass, field
from pathlib import Path

from . import ledger
from .agents.base import SEVERITY_ORDER, AgentResult
from .agents.codeql import CodeqlAgent
from .agents.iac import IacAgent
from .agents.master import MasterAgent, ReportResult
from .agents.sandbox import SandboxAgent
from .agents.sast import SastAgent
from .agents.sca import ScaAgent
from .agents.secrets import SecretsAgent
from .mcp_client import open_client


@dataclass
class QuickResult:
    findings: list = field(default_factory=list)
    blocked: bool = False
    skipped: list = field(default_factory=list)  # scanners that did not run


_SCANNERS = {
    "sca": ScaAgent,
    "sast": SastAgent,
    "codeql": CodeqlAgent,
    "secrets": SecretsAgent,
    "iac": IacAgent,
}
SCANNER_NAMES = tuple(_SCANNERS)


def _scanners(cfg):
    return [cls(cfg) for cls in _SCANNERS.values()]


def _run_scanner(client, workspace_id, scanner) -> AgentResult:
    try:
        return scanner.run(client, workspace_id)
    except Exception as exc:  # isolate: one scanner failing must not abort the rest
        return AgentResult(
            getattr(scanner, "name", "scanner"), [], skipped=True,
            note=f"error: {exc}",
        )


def _run_scanners_parallel(client, workspace_id, scanners) -> list[AgentResult]:
    with ThreadPoolExecutor(max_workers=len(scanners)) as pool:
        return list(pool.map(lambda s: _run_scanner(client, workspace_id, s), scanners))


def _prove(cfg, client, workspace_id, commit_sha, results, project_path=None) -> ReportResult:
    findings = ledger.dedup([f for r in results for f in r.findings], commit_sha)
    return MasterAgent(cfg).dispatch(
        client, workspace_id, commit_sha, findings, project_path=project_path
    )


def run_full(cfg, project_path) -> ReportResult:
    client = open_client(cfg)
    try:
        commit_sha = git_commit(project_path)
        workspace_id = SandboxAgent().run(client, project_path)
        results = _run_scanners_parallel(client, workspace_id, _scanners(cfg))
        return _prove(cfg, client, workspace_id, commit_sha, results, project_path)
    finally:
        client.close()


# --- Per-process stages (used by the Airflow DAG) ---------------------------


def stage_sandbox(cfg, project_path: str) -> dict:
    path = Path(project_path)
    if not path.is_absolute() or not path.is_dir():
        raise ValueError(f"project_path must be an absolute directory: {project_path}")
    client = open_client(cfg)
    try:
        return {
            "workspace_id": SandboxAgent().run(client, str(path)),
            "commit_sha": git_commit(path),
        }
    finally:
        client.close()


def stage_scan(cfg, workspace_id: str, name: str) -> dict:
    if name not in _SCANNERS:
        raise ValueError(f"unknown scanner: {name}")
    client = open_client(cfg)
    try:
        return asdict(_run_scanner(client, workspace_id, _SCANNERS[name](cfg)))
    finally:
        client.close()


def stage_prove(
    cfg, workspace_id: str, commit_sha: str, results: list[dict],
    project_path: str | None = None,
) -> dict:
    client = open_client(cfg)
    try:
        report = _prove(
            cfg, client, workspace_id, commit_sha,
            [AgentResult(**r) for r in results], project_path,
        )
        return asdict(report)
    finally:
        client.close()


def run_quick(cfg, project_path) -> QuickResult:
    """Pre-push tier: Secrets + fast Semgrep only, blocks on anything risky."""
    client = open_client(cfg)
    try:
        workspace_id = SandboxAgent().run(client, project_path)
        results = [
            SecretsAgent(cfg).run(client, workspace_id),
            SastAgent(cfg).run(client, workspace_id),
        ]
        findings = [f for r in results for f in r.findings]
        blocked = any(_is_blocking(f) for f in findings)
        skipped = [r.name for r in results if r.skipped]
        return QuickResult(findings=findings, blocked=blocked, skipped=skipped)
    finally:
        client.close()


def _is_blocking(finding: dict) -> bool:
    # 'error'-level SAST findings normalize to 'high', which is the reachable gate.
    if finding.get("agent") == "secrets":
        return True
    return SEVERITY_ORDER.get(finding.get("severity", "info"), 0) >= SEVERITY_ORDER["high"]


def git_commit(project_path) -> str:
    try:
        out = subprocess.run(
            ["git", "-C", str(project_path), "rev-parse", "HEAD"],
            capture_output=True,
            text=True,
            timeout=10,
        )
        sha = out.stdout.strip()
        return sha or "unknown"
    except (OSError, subprocess.SubprocessError):
        return "unknown"
