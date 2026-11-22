from smass import pipeline
from smass.agents import base


def _stub_llms(monkeypatch):
    # Every model answer carries an exploit and a CONFIRMED verdict.
    monkeypatch.setattr(base, "run_llm", lambda *a, **k: "```python\nprint('PROOF: x')\n```\nVERDICT: CONFIRMED")


def _sarif(findings):
    return {"sarif": {"findings": findings}}


def test_run_full_orders_and_verifies(cfg, client, tmp_path, monkeypatch):
    _stub_llms(monkeypatch)
    monkeypatch.setattr(pipeline, "open_client", lambda c: client)
    client.set_response("get_sast_report", _sarif(
        [{"severity": "high", "file": "a.py", "line": 5, "message": "sqli", "rule_id": "R"}]))
    client.set_response("get_secrets_report", _sarif(
        [{"severity": "critical", "file": "b.py", "line": 1, "message": "key", "rule_id": "S"}]))

    result = pipeline.run_full(cfg, tmp_path)

    assert client.calls[0][0] == "create_workspace"
    assert any(c[0] == "generate_report" for c in client.calls)
    assert result.report_path  # MCPwner wrote a report
    assert len(result.verified) == 2  # high + critical, both oracle-passed and confirmed


def test_run_full_no_findings_still_reports(cfg, client, tmp_path, monkeypatch):
    _stub_llms(monkeypatch)
    monkeypatch.setattr(pipeline, "open_client", lambda c: client)
    result = pipeline.run_full(cfg, tmp_path)
    assert result.verified == []
    assert result.report_path


def test_scanner_failure_does_not_abort_run(cfg, client, tmp_path, monkeypatch):
    _stub_llms(monkeypatch)
    monkeypatch.setattr(pipeline, "open_client", lambda c: client)

    def boom(args):
        raise RuntimeError("scanner down")

    client.set_response("run_sca_scan", boom)
    client.set_response("get_secrets_report", _sarif(
        [{"severity": "critical", "file": "b.py", "line": 1, "message": "key", "rule_id": "S"}]))

    result = pipeline.run_full(cfg, tmp_path)
    assert len(result.verified) == 1  # SCA blew up, run still completed


def test_oracle_failure_is_not_verified(cfg, client, tmp_path, monkeypatch):
    _stub_llms(monkeypatch)
    monkeypatch.setattr(pipeline, "open_client", lambda c: client)
    client.set_response("get_secrets_report", _sarif(
        [{"severity": "critical", "file": "b.py", "line": 1, "message": "key", "rule_id": "S"}]))
    client.set_response("run_poc_scan", {"oracle_passed": False})

    result = pipeline.run_full(cfg, tmp_path)
    assert result.verified == []


def test_duplicate_findings_across_scanners_proven_once(cfg, client, tmp_path, monkeypatch):
    _stub_llms(monkeypatch)
    monkeypatch.setattr(pipeline, "open_client", lambda c: client)
    same = [{"severity": "high", "file": "db.py", "line": 12, "message": "sqli", "rule_id": "X"}]
    client.set_response("get_sca_report", _sarif(same))
    client.set_response("get_sast_report", _sarif(same))

    result = pipeline.run_full(cfg, tmp_path)
    assert len(result.verified) == 1  # deduped, not proven twice


def test_run_quick_blocks_on_secret(cfg, client, tmp_path, monkeypatch):
    _stub_llms(monkeypatch)
    monkeypatch.setattr(pipeline, "open_client", lambda c: client)
    client.set_response("get_secrets_report", _sarif(
        [{"severity": "high", "file": "b.py", "line": 1, "message": "token", "rule_id": "S"}]))

    assert pipeline.run_quick(cfg, tmp_path).blocked is True


def test_run_quick_blocks_on_high_sast(cfg, client, tmp_path, monkeypatch):
    _stub_llms(monkeypatch)
    monkeypatch.setattr(pipeline, "open_client", lambda c: client)
    client.set_response("get_sast_report", _sarif(
        [{"severity": "high", "file": "a.py", "line": 5, "message": "eval", "rule_id": "R"}]))

    assert pipeline.run_quick(cfg, tmp_path).blocked is True


def test_run_quick_reports_skipped_scanner(cfg, client, tmp_path, monkeypatch):
    _stub_llms(monkeypatch)
    monkeypatch.setattr(pipeline, "open_client", lambda c: client)
    client.set_response("run_secrets_scan", {"status": "error", "error": "down"})
    result = pipeline.run_quick(cfg, tmp_path)
    assert "secrets" in result.skipped  # gate did not fully run


def test_run_quick_clean_when_no_findings(cfg, client, tmp_path, monkeypatch):
    _stub_llms(monkeypatch)
    monkeypatch.setattr(pipeline, "open_client", lambda c: client)
    assert pipeline.run_quick(cfg, tmp_path).blocked is False


# --- per-process stages (the Airflow DAG's task bodies) ---------------------

def test_stages_chain_like_run_full(cfg, client, tmp_path, monkeypatch):
    """sandbox -> each scanner -> prove, with JSON round trips between stages
    (as XCom would do), proves the same findings run_full does."""
    import json

    _stub_llms(monkeypatch)
    opened = []
    monkeypatch.setattr(pipeline, "open_client", lambda c: opened.append(1) or client)
    client.set_response("get_sast_report", _sarif(
        [{"severity": "high", "file": "a.py", "line": 5, "message": "sqli", "rule_id": "R"}]))
    client.set_response("get_secrets_report", _sarif(
        [{"severity": "critical", "file": "b.py", "line": 1, "message": "key", "rule_id": "S"}]))

    def xcom(value):
        return json.loads(json.dumps(value))

    ws = xcom(pipeline.stage_sandbox(cfg, str(tmp_path)))
    assert ws["workspace_id"] == "ws1"
    results = [xcom(pipeline.stage_scan(cfg, ws["workspace_id"], n))
               for n in pipeline.SCANNER_NAMES]
    report = xcom(pipeline.stage_prove(cfg, ws["workspace_id"], ws["commit_sha"], results))

    assert len(opened) == 2 + len(pipeline.SCANNER_NAMES)  # one session per stage
    assert report["report_path"]
    assert len(report["verified"]) == 2


def test_stage_scan_isolates_scanner_error(cfg, client, monkeypatch):
    monkeypatch.setattr(pipeline, "open_client", lambda c: client)

    def boom(args):
        raise RuntimeError("scanner down")

    client.set_response("run_sca_scan", boom)
    result = pipeline.stage_scan(cfg, "ws1", "sca")
    assert result["skipped"] is True and "scanner down" in result["note"]


def test_stage_scan_rejects_unknown_scanner(cfg):
    import pytest

    with pytest.raises(ValueError):
        pipeline.stage_scan(cfg, "ws1", "nope")


def test_stage_sandbox_requires_absolute_dir(cfg, client, monkeypatch):
    import pytest

    monkeypatch.setattr(pipeline, "open_client", lambda c: client)
    with pytest.raises(ValueError):
        pipeline.stage_sandbox(cfg, "relative/path")
    assert client.calls == []  # rejected before touching MCPwner


def test_no_exploit_written_is_not_verified(cfg, client, tmp_path, monkeypatch):
    monkeypatch.setattr(base, "run_llm", lambda *a, **k: "")  # the model wrote no script
    monkeypatch.setattr(pipeline, "open_client", lambda c: client)
    client.set_response("get_secrets_report", _sarif(
        [{"severity": "critical", "file": "b.py", "line": 1, "message": "key", "rule_id": "S"}]))

    result = pipeline.run_full(cfg, tmp_path)
    assert result.verified == []
    assert not any(name == "run_poc_scan" for name, _ in client.calls)
