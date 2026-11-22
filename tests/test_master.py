from smass.agents import base
from smass.agents.master import MasterAgent


def _f(sev, name):
    return {"severity": sev, "file": name, "line": 1, "message": name}


def test_triage_uses_llm_order(cfg, monkeypatch):
    findings = [_f("low", "a"), _f("low", "b"), _f("low", "c")]
    monkeypatch.setattr(base, "run_llm", lambda *a, **k: "priority: [2, 0, 1]")
    ranked = MasterAgent(cfg).triage(findings)
    assert [f["file"] for f in ranked] == ["c", "a", "b"]


def test_triage_appends_unranked_by_severity(cfg, monkeypatch):
    findings = [_f("low", "a"), _f("critical", "b"), _f("high", "c")]
    # LLM only ranks index 0; the rest get appended by severity, desc.
    monkeypatch.setattr(base, "run_llm", lambda *a, **k: "[0]")
    ranked = MasterAgent(cfg).triage(findings)
    assert [f["file"] for f in ranked] == ["a", "b", "c"]


def test_triage_falls_back_to_severity_on_bad_output(cfg, monkeypatch):
    findings = [_f("low", "a"), _f("critical", "b"), _f("high", "c")]
    monkeypatch.setattr(base, "run_llm", lambda *a, **k: "no numbers here")
    ranked = MasterAgent(cfg).triage(findings)
    assert [f["file"] for f in ranked] == ["b", "c", "a"]


def test_triage_empty(cfg, monkeypatch):
    monkeypatch.setattr(base, "run_llm", lambda *a, **k: "[0]")
    assert MasterAgent(cfg).triage([]) == []


def test_dispatch_keeps_distinct_findings_near_lines(cfg, client, monkeypatch):
    # Regression: two DISTINCT high findings a few lines apart must both survive
    # (an earlier location-band dedup silently dropped one).
    monkeypatch.setattr(base, "run_llm", lambda *a, **k: "```python\nprint('PROOF: x')\n```\nVERDICT: CONFIRMED")  # reviewer finds nothing
    f1 = {"severity": "high", "file": "a.py", "line": 10, "message": "sqli",
          "rule_id": "r.sqli", "agent": "sast", "tool": "semgrep"}
    f2 = {"severity": "high", "file": "a.py", "line": 12, "message": "cmdi",
          "rule_id": "r.cmdi", "agent": "sast", "tool": "semgrep"}
    result = MasterAgent(cfg).dispatch(client, "ws1", "sha", [f1, f2])
    assert len(result.verified) == 2


def test_dispatch_collapses_exact_duplicates(cfg, client, monkeypatch):
    monkeypatch.setattr(base, "run_llm", lambda *a, **k: "```python\nprint('PROOF: x')\n```\nVERDICT: CONFIRMED")
    f = {"severity": "high", "file": "a.py", "line": 10, "message": "sqli",
         "rule_id": "r", "agent": "sast", "tool": "semgrep", "snippet": "x"}
    result = MasterAgent(cfg).dispatch(client, "ws1", "sha", [dict(f), dict(f)])
    assert len(result.verified) == 1
