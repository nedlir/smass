import json

from smass.agents import base
from smass.agents.reviewer import ReviewerAgent

FINDING = {
    "severity": "high",
    "file": "a.py",
    "line": 10,
    "message": "xss",
    "rule_id": "R1",
    "snippet": "render(x)",
}


def test_reviewer_dedups_across_passes(cfg, client, monkeypatch):
    # The LLM "finds" the same issue on every pass; it must only be reported once.
    monkeypatch.setattr(base, "run_llm", lambda *a, **k: json.dumps([FINDING]))

    new = ReviewerAgent(cfg).review(client, "ws1", "sha123", [], passes=3)

    assert len(new) == 1
    assert client.count("upsert_finding") == 1
    memory = json.loads(cfg.memory_path.read_text())
    assert len(memory["sha123"]) == 1


def test_reviewer_handles_empty_output(cfg, client, monkeypatch):
    monkeypatch.setattr(base, "run_llm", lambda *a, **k: "no issues found")
    new = ReviewerAgent(cfg).review(client, "ws1", "sha456", [], passes=3)
    assert new == []
    assert client.count("upsert_finding") == 0


def test_reviewer_does_not_re_report_scanner_findings(cfg, client, monkeypatch):
    # The LLM "finds" a finding the scanners already reported; it must be skipped.
    monkeypatch.setattr(base, "run_llm", lambda *a, **k: json.dumps([FINDING]))
    new = ReviewerAgent(cfg).review(client, "ws1", "sha789", [FINDING], passes=3)
    assert new == []
    assert client.count("upsert_finding") == 0
