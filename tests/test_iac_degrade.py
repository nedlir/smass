from dataclasses import replace

from smass.agents.iac import IacAgent


def test_iac_skips_when_unset(cfg, client):
    # iac_tool is None in the fixture: nothing to run.
    result = IacAgent(cfg).run(client, "ws1")
    assert result.skipped is True
    assert result.findings == []


def test_iac_skips_when_scan_errors(cfg, client):
    cfg2 = replace(cfg, iac_tool="checkov")
    client.set_response("run_iac_scan", {"status": "error", "error": "container down"})
    result = IacAgent(cfg2).run(client, "ws1")
    assert result.skipped is True


def test_iac_runs_when_configured(cfg, client):
    cfg2 = replace(cfg, iac_tool="checkov")
    client.set_response(
        "get_iac_report",
        {"sarif": {"findings": [{"severity": "medium", "file": "main.tf", "line": 4,
                                 "message": "open sg", "rule_id": "CKV1"}]}},
    )
    result = IacAgent(cfg2).run(client, "ws1")
    assert not result.skipped
    assert len(result.findings) == 1
    scan = next(c for c in client.calls if c[0] == "run_iac_scan")
    assert scan[1].get("tool") == "checkov"
