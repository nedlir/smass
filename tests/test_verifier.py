from smass import pipeline
from smass.agents import base
from smass.agents.verifier import VerifierAgent, parse_verdict

FINDING = {"severity": "high", "file": "a.py", "line": 1, "message": "idor", "rule_id": "idor"}


def test_parse_verdict_takes_the_last_line_anchored_verdict():
    assert parse_verdict("thinking...\nVERDICT: CONFIRMED") is True
    assert parse_verdict("**VERDICT: REJECTED**") is False
    # A verdict mentioned earlier (e.g. quoting the options) is overruled by the final one.
    assert parse_verdict("VERDICT: CONFIRMED or VERDICT: REJECTED?\nVERDICT: REJECTED") is False
    assert parse_verdict("looks fine to me") is False  # no verdict: fail closed


def test_verifier_sends_what_really_ran(cfg, client, monkeypatch):
    seen = {}

    def llm(cfg_, model, system, user):
        seen["user"] = user
        return "VERDICT: CONFIRMED"

    monkeypatch.setattr(base, "run_llm", llm)
    assert VerifierAgent(cfg).verify(client, "ws1", FINDING, {"a.py": "x = 1\n"}) is True
    assert client.last("get_poc_report") == {"tool": "poc-sandbox", "workspace_id": "ws1"}
    assert "print('PROOF: x')" in seen["user"] and "PROOF: x" in seen["user"]
    assert "a.py" in seen["user"]


def test_verifier_fails_closed(cfg, client, monkeypatch):
    monkeypatch.setattr(base, "run_llm", lambda *a, **k: "VERDICT: CONFIRMED")
    client.set_response("get_poc_report", {"status": "error", "error": "no report"})
    assert VerifierAgent(cfg).verify(client, "ws1", FINDING) is False  # no run to judge

    client.set_response("get_poc_report", {"report_content": {"script": "x", "exit_code": 0}})

    def down(*a, **k):
        raise RuntimeError("LLM unavailable")

    monkeypatch.setattr(base, "run_llm", down)
    assert VerifierAgent(cfg).verify(client, "ws1", FINDING) is False


def test_oracle_pass_rejected_by_verifier_is_not_verified(cfg, client, tmp_path, monkeypatch):
    # The sandbox says pass, but the verifier sees a script that proves nothing.
    monkeypatch.setattr(base, "run_llm",
                        lambda *a, **k: "```python\nprint('PROOF: x')\n```\nVERDICT: REJECTED")
    monkeypatch.setattr(pipeline, "open_client", lambda c: client)
    client.set_response("get_secrets_report", {"sarif": {"findings": [
        {"severity": "critical", "file": "b.py", "line": 1, "message": "key", "rule_id": "S"}]}})

    result = pipeline.run_full(cfg, tmp_path)
    assert result.verified == []
    assert client.count("run_poc_scan") == 1  # it was run, and passed the oracle
