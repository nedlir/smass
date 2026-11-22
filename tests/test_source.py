import json

from smass import source
from smass.agents import base
from smass.agents.master import MasterAgent
from smass.agents.poc_writer import PocWriterAgent
from smass.agents.reviewer import ReviewerAgent


def _project(tmp_path):
    (tmp_path / "app").mkdir()
    (tmp_path / "app" / "main.py").write_text("a = 1\nb = 2\nreturn_invoice(id)\n")
    (tmp_path / "app" / "util.py").write_text("x = 1\n")
    (tmp_path / "Dockerfile").write_text("FROM python:3.8\n")
    (tmp_path / "logo.png").write_bytes(b"\x89PNG\x00\xff")
    for skipped in (".git", "node_modules", ".smass", ".venv"):
        (tmp_path / skipped).mkdir()
        (tmp_path / skipped / "x.py").write_text("ignored = True\n")
    return tmp_path


def test_collect_reads_source_and_skips_vendored_dirs(tmp_path):
    sources = source.collect(_project(tmp_path))
    assert set(sources) == {"Dockerfile", "app/main.py", "app/util.py"}


def test_collect_puts_flagged_files_first_and_respects_budget(tmp_path):
    project = _project(tmp_path)
    sources = source.collect(project, priority=["app/util.py"])
    assert next(iter(sources)) == "app/util.py"
    # A budget that fits only the small file: the big one is skipped whole, not cut.
    small = source.collect(project, priority=["app/util.py"], budget=10)
    assert small == {"app/util.py": "x = 1\n"}


def test_collect_missing_dir_is_empty(tmp_path):
    assert source.collect(tmp_path / "nope") == {}


def test_render_numbers_lines_and_fences_as_data():
    listing = source.render({"a.py": "one\ntwo\n"})
    assert "=== a.py" in listing
    assert "    2| two" in listing
    assert "untrusted" in listing and listing.endswith("</source_code>")
    assert source.render({}) == ""


def test_ground_keeps_real_lines_and_drops_invented_ones():
    sources = {"a.py": "x = 1\n  danger(y)\n"}
    real = source.ground({"file": "a.py", "line": 2, "snippet": "made up"}, sources)
    assert real["snippet"] == "danger(y)"  # replaced with the actual line
    assert source.ground({"file": "a.py", "line": 9}, sources) is None
    assert source.ground({"file": "ghost.py", "line": 1}, sources) is None
    # No listing to check against (no project path): passed through unchanged.
    assert source.ground({"file": "ghost.py", "line": 1}, {}) == {"file": "ghost.py", "line": 1}


def test_reviewer_sees_the_code_and_drops_ungrounded_findings(cfg, client, monkeypatch):
    prompts = []
    reply = json.dumps([
        {"file": "app/main.py", "line": 3, "severity": "high",
         "rule_id": "idor", "message": "no owner check"},
        {"file": "app/main.py", "line": 99, "severity": "high",
         "rule_id": "made-up", "message": "hallucinated line"},
        {"file": "nowhere.py", "line": 1, "severity": "high",
         "rule_id": "made-up", "message": "hallucinated file"},
    ])
    monkeypatch.setattr(base, "run_llm", lambda c, m, s, u: prompts.append(u) or reply)
    sources = {"app/main.py": "a = 1\nb = 2\nreturn_invoice(id)\n"}

    new = ReviewerAgent(cfg).review(client, "ws1", "sha", [], passes=1, sources=sources)

    assert "    3| return_invoice(id)" in prompts[0]
    assert [(f["rule_id"], f["snippet"]) for f in new] == [("idor", "return_invoice(id)")]


def test_poc_writer_gets_code_and_ships_it_to_the_sandbox(cfg, client, monkeypatch, tmp_path):
    prompts = []
    monkeypatch.setattr(
        base, "run_llm",
        lambda c, m, s, u: prompts.append(u) or "# report\n```python\nprint('PROOF')\n```",
    )
    sources = {"app/main.py": "return_invoice(id)\n"}
    writer = PocWriterAgent(cfg)
    finding = {"file": "app/main.py", "line": 1, "rule_id": "idor", "severity": "high"}

    directory = writer.author(finding, sources)
    writer.run_poc(client, "ws1", directory, sources)

    assert "    1| return_invoice(id)" in prompts[0]
    config = client.last("run_poc_scan")["config"]
    assert config["files"] == sources
    assert "PROOF" in config["script"]


def test_dispatch_reads_the_project_for_review_poc_and_verify(cfg, client, monkeypatch, tmp_path):
    (tmp_path / "proj").mkdir()
    project = _project(tmp_path / "proj")
    seen = []

    def fake_llm(c, model, system, user):
        seen.append(user)
        if "secure-code reviewer" in system:
            return json.dumps([{"file": "app/main.py", "line": 3, "severity": "high",
                                "rule_id": "idor", "message": "no owner check"}])
        return "```python\nprint('PROOF')\n```\nVERDICT: CONFIRMED"

    monkeypatch.setattr(base, "run_llm", fake_llm)
    result = MasterAgent(cfg).dispatch(client, "ws1", "sha", [], project_path=project)

    assert [v["finding"]["rule_id"] for v in result.verified] == ["idor"]
    assert all("return_invoice(id)" in u for u in seen)  # review, PoC and verifier all saw the code
    assert "app/main.py" in client.last("run_poc_scan")["config"]["files"]


def test_poc_script_is_the_last_python_block_not_a_quoted_fix():
    from smass.agents.poc_writer import _split_poc

    output = (
        "# FINDING\nFix it like this:\n```python\nquantity: int = Field(gt=0)\n```\n"
        "## Exploit\n```python\nprint('PROOF: minted balance')\n```\n"
    )
    report, script = _split_poc(output)
    assert script == "print('PROOF: minted balance')"
    assert "Field(gt=0)" in report
