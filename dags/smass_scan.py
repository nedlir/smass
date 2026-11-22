"""smass full scan as an Airflow DAG.

    sandbox ─┬─ scan_sca ─────┬─ prove
             ├─ scan_sast ────┤
             ├─ scan_codeql ──┤
             ├─ scan_secrets ─┤
             └─ scan_iac ─────┘

Task bodies are the `smass.pipeline.stage_*` functions; this file is wiring only.
Each task opens its own MCPwner session (MCPwner persists workspaces and the
findings ledger on disk, so the workspace id is all that crosses tasks), and
results move between tasks as XCom dicts.

Trigger it with `smass --airflow <path>`, or from the UI / CLI with run conf
`{"project_path": "/abs/path/to/project"}`. smass settings (SMASS_* env vars)
must be in the Airflow processes' environment; scripts/airflow-standalone.sh
loads them from .env.
"""

from __future__ import annotations

from datetime import timedelta

from airflow.sdk import Param, dag, task

from smass import config, pipeline


def summary(report: dict) -> str:
    """The proven findings as plain lines, for the prove task's log in the UI."""
    verified = report.get("verified") or []
    lines = [f"smass: {len(verified)} verified of {report.get('considered', 0)} "
             f"finding(s) considered"]
    for v in verified:
        f = v.get("finding", {})
        source = "AI review" if f.get("agent") == "review" else (f.get("tool") or f.get("agent"))
        lines.append(f"  PROVEN [{f.get('severity')}] {f.get('file')}:{f.get('line')} "
                     f"{f.get('rule_id')} (found by {source})")
    lines.append(f"report: {report.get('report_path', '')}")
    return "\n".join(lines)


def _cfg(project_path: str):
    # Run output (.smass/) goes under the scanned project, as with `smass .`.
    return config.with_paths_under(config.load(), project_path)


@dag(
    dag_id="smass_scan",
    schedule=None,
    catchup=False,
    tags=["smass", "security"],
    params={
        "project_path": Param(type="string", description="Absolute path of the project to scan"),
    },
    doc_md=__doc__,
)
def smass_scan():
    @task(retries=1, retry_delay=timedelta(seconds=30))
    def sandbox(params=None) -> dict:
        return pipeline.stage_sandbox(_cfg(params["project_path"]), params["project_path"])

    @task(retries=1, retry_delay=timedelta(seconds=30))
    def scan(ws: dict, name: str, params=None) -> dict:
        return pipeline.stage_scan(_cfg(params["project_path"]), ws["workspace_id"], name)

    # No retries: proving makes LLM calls and runs PoCs; a rerun is a deliberate act.
    @task
    def prove(ws: dict, results: list[dict], params=None) -> dict:
        report = pipeline.stage_prove(
            _cfg(params["project_path"]), ws["workspace_id"], ws["commit_sha"],
            list(results), project_path=params["project_path"],
        )
        # Readable result at the end of the task's log, one line per log entry
        # (the UI's log view shows only the first line of a multi-line entry).
        for line in summary(report).splitlines():
            print(line)
        return report

    ws = sandbox()
    results = [
        scan.override(task_id=f"scan_{name}")(ws, name)
        for name in pipeline.SCANNER_NAMES
    ]
    prove(ws, results)


smass_scan_dag = smass_scan()
