"""The smass_scan Airflow DAG. Skipped unless Airflow is installed
(run with .venv-airflow/bin/python -m pytest)."""

import atexit
import importlib.util
import os
import shutil
import subprocess
import sys
import tempfile
from pathlib import Path

import pytest

DAG_DIR = Path(__file__).resolve().parent.parent / "dags"
DAG_FILE = DAG_DIR / "smass_scan.py"

if importlib.util.find_spec("airflow") is None:
    pytest.skip("Airflow not installed", allow_module_level=True)

# A throwaway Airflow home (own SQLite metadata DB), set before Airflow loads its
# config, so the tests never touch a real ~/airflow.
_HOME = tempfile.mkdtemp(prefix="smass-airflow-test-")
atexit.register(shutil.rmtree, _HOME, ignore_errors=True)
os.environ.update({
    "AIRFLOW_HOME": _HOME,
    "AIRFLOW__CORE__DAGS_FOLDER": str(DAG_DIR),
    "AIRFLOW__CORE__LOAD_EXAMPLES": "False",
})

from smass import pipeline  # noqa: E402


@pytest.fixture(scope="module", autouse=True)
def airflow_db():
    subprocess.run([sys.executable, "-m", "airflow", "db", "migrate"], check=True,
                   capture_output=True, env=os.environ)


@pytest.fixture(scope="module")
def dag():
    spec = importlib.util.spec_from_file_location("smass_scan_dag", DAG_FILE)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module.smass_scan_dag


def test_dag_shape(dag):
    scans = {f"scan_{n}" for n in pipeline.SCANNER_NAMES}
    assert set(dag.task_ids) == {"sandbox", "prove", *scans}
    assert dag.get_task("sandbox").downstream_task_ids == {"prove", *scans}
    assert dag.get_task("prove").upstream_task_ids == {"sandbox", *scans}
    assert "project_path" in dag.params


def test_dag_runs_end_to_end_on_fake_client(dag, cfg, client, tmp_path, monkeypatch):
    from dataclasses import replace

    from smass import config
    from smass.agents import base

    monkeypatch.setattr(base, "run_llm", lambda *a, **k: "```python\nprint('PROOF: x')\n```\nVERDICT: CONFIRMED")
    monkeypatch.setattr(pipeline, "open_client", lambda c: client)
    monkeypatch.setattr(config, "load", lambda env=None: replace(cfg))
    client.set_response("get_secrets_report", {"sarif": {"findings": [
        {"severity": "critical", "file": "b.py", "line": 1, "message": "key", "rule_id": "S"}]}})

    dr = dag.test(run_conf={"project_path": str(tmp_path)})

    assert dr.state == "success"
    report = dr.get_task_instance("prove").xcom_pull(task_ids="prove")
    assert len(report["verified"]) == 1
    assert sum(1 for name, _ in client.calls if name == "create_workspace") == 1


def test_summary_lists_proven_findings():
    spec = importlib.util.spec_from_file_location("smass_scan_dag_sum", DAG_FILE)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    text = module.summary({"considered": 16, "report_path": "/w/report.md", "verified": [
        {"finding": {"severity": "high", "file": "app/main.py", "line": 28,
                     "rule_id": "idor", "agent": "review", "tool": ""}},
        {"finding": {"severity": "high", "file": "app/main.py", "line": 59,
                     "rule_id": "shell-true", "agent": "sast", "tool": "Semgrep OSS"}},
    ]})
    assert text.splitlines()[0] == "smass: 2 verified of 16 finding(s) considered"
    assert "app/main.py:28 idor (found by AI review)" in text
    assert "(found by Semgrep OSS)" in text and text.endswith("report: /w/report.md")
