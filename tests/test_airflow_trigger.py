"""`smass --airflow` against a scripted Airflow REST API (no Airflow needed)."""

import json
from dataclasses import replace

import pytest

from smass import airflow_trigger as at


class FakeApi:
    """Records requests; answers like the Airflow 3 REST API."""

    def __init__(self, states, result=None, no_login=False):
        self.no_login = no_login
        self.states = list(states)
        self.result = result or {"report_path": "/r.md", "verified": [], "considered": 0}
        self.sent = []

    def __call__(self, method, path, payload, headers):
        self.sent.append((method, path, payload, headers))
        if path == "/auth/token" and method == "GET":
            if self.no_login:
                return {"access_token": "tok"}
            raise at.AirflowError("Airflow GET /auth/token -> HTTP 403")
        if path == "/auth/token":
            assert payload == {"username": "admin", "password": "pw"}
            return {"access_token": "tok"}
        assert headers == {"Authorization": "Bearer tok"}
        if method == "POST" and path.endswith("/dagRuns"):
            return {"dag_run_id": "manual__1", "state": "queued"}
        if path.endswith("/taskInstances"):
            return {"task_instances": [{"task_id": "prove", "state": "failed"},
                                       {"task_id": "sandbox", "state": "success"}]}
        if "/xcomEntries/" in path:
            return {"value": self.result}
        if method == "GET":
            return {"state": self.states.pop(0)}
        return {}


@pytest.fixture
def acfg(cfg):
    return replace(cfg, airflow_password="pw", airflow_timeout=60)


@pytest.fixture(autouse=True)
def no_sleep(monkeypatch):
    monkeypatch.setattr(at.time, "sleep", lambda s: None)


def test_triggers_waits_and_reads_result(acfg, monkeypatch):
    fake = FakeApi(["running", "success"],
                   {"report_path": "/r.md", "verified": [{"finding": {}}], "considered": 3})
    monkeypatch.setattr(at.AirflowApi, "_send", fake)

    result = at.run_via_airflow(acfg, "/proj")

    assert result.verified == [{"finding": {}}] and result.considered == 3
    methods = [(m, p) for m, p, *_ in fake.sent]
    assert ("PATCH", "/api/v2/dags/smass_scan") in methods  # unpaused first
    trigger = next(s for s in fake.sent if s[0] == "POST" and s[1].endswith("/dagRuns"))
    assert trigger[2]["conf"] == {"project_path": "/proj"}
    assert sum(1 for s in fake.sent if s[:2] == ("POST", "/auth/token")) == 1  # token reused


def test_failed_run_raises(acfg, monkeypatch):
    monkeypatch.setattr(at.AirflowApi, "_send", FakeApi(["failed"]))
    with pytest.raises(at.AirflowError, match=r"failed task\(s\): prove\)"):
        at.run_via_airflow(acfg, "/proj")


def test_timeout_raises(acfg, monkeypatch):
    monkeypatch.setattr(at.AirflowApi, "_send", FakeApi(["running"] * 5))
    monkeypatch.setattr(at.time, "monotonic", iter([0, 0, 100]).__next__)
    with pytest.raises(at.AirflowError, match="timed out"):
        at.run_via_airflow(acfg, "/proj")


def test_xcom_value_as_json_string(acfg, monkeypatch):
    fake = FakeApi(["success"])
    fake.result = json.dumps({"report_path": "/r.md", "verified": [], "considered": 0})
    monkeypatch.setattr(at.AirflowApi, "_send", fake)
    assert at.run_via_airflow(acfg, "/proj").report_path == "/r.md"


def test_password_falls_back_to_generated_file(cfg, tmp_path, monkeypatch):
    monkeypatch.setenv("AIRFLOW_HOME", str(tmp_path))
    (tmp_path / "simple_auth_manager_passwords.json.generated").write_text(
        json.dumps({"admin": "gen-pw"}))
    assert at._password(cfg) == "gen-pw"


def test_missing_password_is_a_clear_error(cfg, tmp_path, monkeypatch):
    monkeypatch.setenv("AIRFLOW_HOME", str(tmp_path))
    with pytest.raises(at.AirflowError, match="SMASS_AIRFLOW_PASSWORD"):
        at._password(cfg)


def test_unreachable_airflow_is_a_clear_error():
    api = at.AirflowApi("http://127.0.0.1:9", "admin", "pw")  # nothing listens on :9
    with pytest.raises(at.AirflowError, match="cannot reach Airflow"):
        api.request("GET", "/api/v2/version")


def test_no_login_airflow_needs_no_password(cfg, tmp_path, monkeypatch):
    # A local Airflow with no login: no password configured, no generated
    # password file, and the run still goes through.
    monkeypatch.setenv("AIRFLOW_HOME", str(tmp_path))
    fake = FakeApi(["success"], no_login=True)
    monkeypatch.setattr(at.AirflowApi, "_send", fake)
    result = at.run_via_airflow(replace(cfg, airflow_timeout=60), "/proj")
    assert result.report_path == "/r.md"
    assert not any(s[:2] == ("POST", "/auth/token") for s in fake.sent)
