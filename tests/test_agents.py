from smass.agents import base
from smass.agents.codeql import CodeqlAgent
from smass.agents.sca import ScaAgent
from smass.agents.secrets import SecretsAgent


def test_sca_agent_fetches_report_and_upserts(cfg, client):
    client.set_response(
        "get_sca_report",
        {"sarif": {"findings": [{"severity": "high", "file": "a.py", "line": 3,
                                 "message": "vuln dep", "rule_id": "CVE-1"}]}},
    )
    result = ScaAgent(cfg).run(client, "ws1")
    assert len(result.findings) == 1
    assert result.findings[0]["agent"] == "sca"
    assert result.findings[0]["id"]  # id assigned for the ledger
    assert client.count("upsert_finding") == 1
    # it ran the specific tool, then fetched the report
    scan = next(c for c in client.calls if c[0] == "run_sca_scan")
    assert scan[1].get("tool") == "grype"
    assert any(c[0] == "get_sca_report" for c in client.calls)


def test_scanner_parses_sarif_report(cfg, client):
    sarif = {
        "runs": [
            {
                "tool": {"driver": {"name": "trufflehog"}},
                "results": [
                    {
                        "ruleId": "secret.aws",
                        "level": "error",
                        "message": {"text": "aws key"},
                        "locations": [
                            {"physicalLocation": {
                                "artifactLocation": {"uri": "db.py"},
                                "region": {"startLine": 12}}}
                        ],
                    }
                ],
            }
        ]
    }
    client.set_response("get_secrets_report", {"sarif": sarif})
    result = SecretsAgent(cfg).run(client, "ws1")
    assert len(result.findings) == 1
    f = result.findings[0]
    assert f["file"] == "db.py" and f["line"] == 12 and f["severity"] == "high"
    assert f["agent"] == "secrets"


def test_secrets_agent_parses_trufflehog_native(cfg, client):
    # MCPwner returns trufflehog's native JSON (not SARIF) under the "sarif" key.
    th = {
        "SourceMetadata": {"Data": {"Filesystem": {
            "file": "/workspaces/abc/source/leak.py", "line": 2}}},
        "DetectorName": "AWS", "Verified": False, "Redacted": "AKIA...XQ5",
    }
    client.set_response("get_secrets_report", {"sarif": th})
    result = SecretsAgent(cfg).run(client, "ws1")
    assert len(result.findings) == 1
    f = result.findings[0]
    assert f["file"] == "leak.py" and f["line"] == 2
    assert f["severity"] == "high" and f["rule_id"] == "AWS"


def test_trufflehog_verified_is_critical_and_list_ok(cfg, client):
    items = [
        {"SourceMetadata": {"Data": {"Filesystem": {"file": "/x/source/a.py", "line": 1}}},
         "DetectorName": "AWS", "Verified": True, "Redacted": "r1"},
        {"SourceMetadata": {"Data": {"Git": {"file": "b.py", "line": 9}}},
         "DetectorName": "GitHub", "Verified": False, "Redacted": "r2"},
    ]
    client.set_response("get_secrets_report", {"sarif": items})
    result = SecretsAgent(cfg).run(client, "ws1")
    assert len(result.findings) == 2
    assert result.findings[0]["severity"] == "critical"  # verified
    assert result.findings[1]["severity"] == "high"       # unverified


def test_sarif_severity_from_rule_default_and_relative_path(cfg, client):
    sarif = {"runs": [{
        "tool": {"driver": {"name": "semgrep", "rules": [
            {"id": "r1", "defaultConfiguration": {"level": "error"}}]}},
        "results": [{"ruleId": "r1", "level": None,
                     "message": {"text": "cmd injection"},
                     "locations": [{"physicalLocation": {
                         "artifactLocation": {"uri": "/workspaces/w/source/app.py"},
                         "region": {"startLine": 5}}}]}]}]}
    client.set_response("get_sca_report", {"sarif": sarif})
    result = ScaAgent(cfg).run(client, "ws1")
    assert result.findings[0]["severity"] == "high"   # inherited rule level error -> high
    assert result.findings[0]["file"] == "app.py"     # repo-relative


def test_report_content_fallback_for_list(cfg, client):
    items = [
        {"SourceMetadata": {"Data": {"Filesystem": {"file": "/w/source/a.py", "line": 1}}},
         "DetectorName": "AWS", "Verified": False, "Redacted": "r1"},
        {"SourceMetadata": {"Data": {"Filesystem": {"file": "/w/source/b.py", "line": 2}}},
         "DetectorName": "GitHub", "Verified": True, "Redacted": "r2"},
    ]
    client.set_response("get_secrets_report", {"sarif": None, "report_content": items})
    result = SecretsAgent(cfg).run(client, "ws1")
    assert len(result.findings) == 2


def test_scanner_polls_backgrounded_scan(cfg, client, monkeypatch):
    # A scan over ~50s returns "backgrounded"; the agent must poll the report,
    # not report 0 as a clean scan.
    monkeypatch.setattr(base.time, "sleep", lambda s: None)
    client.set_response("run_sca_scan", {"status": "backgrounded"})
    client.set_response("get_sca_report", {"status": "success", "sarif": {"findings": [
        {"severity": "high", "file": "a.py", "line": 1, "message": "x", "rule_id": "R"}]}})
    result = ScaAgent(cfg).run(client, "ws1")
    assert not result.skipped
    assert len(result.findings) == 1


def test_scanner_skips_on_scan_error(cfg, client):
    client.set_response("run_secrets_scan", {"status": "error", "error": "down"})
    result = SecretsAgent(cfg).run(client, "ws1")
    assert result.skipped is True
    assert result.findings == []


def test_codeql_builds_db_then_queries(cfg, client):
    client.set_response(
        "execute_query",
        {"status": "success",
         "findings": [{"severity": "error", "file": "x.py", "start_line": 7,
                       "message": "taint", "rule_id": "ql"}]},
    )
    result = CodeqlAgent(cfg).run(client, "ws1")
    assert len(result.findings) == 1
    assert result.findings[0]["line"] == 7       # start_line mapped to line
    assert result.findings[0]["severity"] == "high"  # error -> high
    assert any(c[0] == "create_codeql_database" for c in client.calls)
    q = next(c for c in client.calls if c[0] == "execute_query")
    assert q[1].get("database_id") == "db1"
    assert q[1].get("query_type") == "builtin"


def test_paths_are_repo_relative_for_every_scanner_shape():
    from smass.agents.base import normalize_finding

    assert normalize_finding({"file": "/workspaces/x/source/app/main.py"})["file"] == "app/main.py"
    assert normalize_finding({"file": "/requirements.txt"})["file"] == "requirements.txt"  # grype
    assert normalize_finding({"file": "app/main.py"})["file"] == "app/main.py"
