import pytest

from smass import cli
from smass.agents.master import ReportResult
from smass.pipeline import QuickResult


def test_cli_quick_clean_exits_zero(monkeypatch):
    monkeypatch.setattr(cli, "run_quick", lambda cfg, p: QuickResult([], blocked=False))
    assert cli.main(["--quick", "."]) == 0


def test_cli_quick_blocked_exits_one(monkeypatch):
    finding = {"severity": "critical", "file": "a", "line": 1, "message": "m",
               "agent": "secrets"}
    monkeypatch.setattr(cli, "run_quick", lambda cfg, p: QuickResult([finding], blocked=True))
    assert cli.main(["--quick", "."]) == 1


def test_cli_quick_fails_closed_on_skipped_scanner(monkeypatch):
    monkeypatch.setattr(
        cli, "run_quick",
        lambda cfg, p: QuickResult(findings=[], blocked=False, skipped=["secrets"]),
    )
    assert cli.main(["--quick", "."]) == 1  # cannot vouch "clean" if a scanner skipped


def test_cli_quick_fails_open_on_error(monkeypatch):
    def boom(cfg, p):
        raise RuntimeError("mcpwner unavailable")

    monkeypatch.setattr(cli, "run_quick", boom)
    assert cli.main(["--quick", "."]) == 0  # advisory: does not block the push


def test_cli_full_exits_one_on_verified(monkeypatch):
    report = ReportResult(report_path="/x/report.md", verified=[{"finding": {}}], considered=1)
    monkeypatch.setattr(cli, "run_full", lambda cfg, p: report)
    assert cli.main(["."]) == 1


def test_cli_full_exits_zero_when_clean(monkeypatch):
    report = ReportResult(report_path="/x/report.md", verified=[], considered=0)
    monkeypatch.setattr(cli, "run_full", lambda cfg, p: report)
    assert cli.main(["."]) == 0


def test_cli_airflow_uses_dag_run(monkeypatch):
    report = ReportResult(report_path="/x/report.md", verified=[{"finding": {}}], considered=1)
    monkeypatch.setattr(cli, "run_via_airflow", lambda cfg, p: report)
    monkeypatch.setattr(cli, "run_full", lambda *a, **k: pytest.fail("ran in-process"))
    assert cli.main(["--airflow", "."]) == 1


def test_cli_airflow_error_exits_two(monkeypatch):
    def boom(cfg, p):
        raise cli.AirflowError("cannot reach Airflow")

    monkeypatch.setattr(cli, "run_via_airflow", boom)
    assert cli.main(["--airflow", "."]) == 2


def test_cli_quick_and_airflow_conflict():
    with pytest.raises(SystemExit):
        cli.main(["--quick", "--airflow", "."])
