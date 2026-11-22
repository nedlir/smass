"""`smass --airflow`: run a full scan as a DAG run on a local Airflow.

Talks to the Airflow 3 REST API (stdlib only, so the smass venv does not need
Airflow installed): get a token, unpause the DAG, trigger a run with the project
as run conf, wait for it, and read the `prove` task's result back.
"""

from __future__ import annotations

import json
import os
import time
import urllib.error
import urllib.parse
import urllib.request
from pathlib import Path

from .agents.master import ReportResult

DAG_ID = "smass_scan"
RESULT_TASK = "prove"
_TERMINAL = {"success", "failed"}
_POLL_SECONDS = 5


class AirflowError(RuntimeError):
    pass


def run_via_airflow(cfg, project_path) -> ReportResult:
    api = AirflowApi(cfg.airflow_url, cfg.airflow_user, lambda: _password(cfg))
    api.request("PATCH", f"/api/v2/dags/{DAG_ID}", {"is_paused": False})
    conf = {"project_path": str(project_path)}
    run = api.request(
        "POST", f"/api/v2/dags/{DAG_ID}/dagRuns", {"logical_date": None, "conf": conf}
    )
    run_id = run["dag_run_id"]
    print(f"smass: triggered Airflow run {run_id} "
          f"({cfg.airflow_url}/dags/{DAG_ID}/runs/{urllib.parse.quote(run_id)})",
          flush=True)

    run_path = f"/api/v2/dags/{DAG_ID}/dagRuns/{urllib.parse.quote(run_id, safe='')}"
    deadline = time.monotonic() + cfg.airflow_timeout
    state = run.get("state")
    while state not in _TERMINAL:
        if time.monotonic() > deadline:
            raise AirflowError(f"timed out after {cfg.airflow_timeout}s waiting for "
                               f"run {run_id} (state: {state})")
        time.sleep(_POLL_SECONDS)
        state = api.request("GET", run_path)["state"]
    if state != "success":
        tis = api.request("GET", f"{run_path}/taskInstances").get("task_instances", [])
        failed = sorted(t["task_id"] for t in tis if t.get("state") == "failed")
        raise AirflowError(f"Airflow run {run_id} {state} (failed task(s): "
                           f"{', '.join(failed) or 'none'}); see its task logs in the UI")

    xcom = api.request(
        "GET", f"{run_path}/taskInstances/{RESULT_TASK}/xcomEntries/return_value"
        "?deserialize=true&stringify=false",
    )
    value = xcom.get("value")
    if isinstance(value, str):
        value = json.loads(value)
    return ReportResult(**value)


def _password(cfg) -> str:
    """The configured password, else the one `airflow standalone` generated."""
    if cfg.airflow_password:
        return cfg.airflow_password
    home = Path(os.environ.get("AIRFLOW_HOME") or Path.home() / "airflow")
    generated = home / "simple_auth_manager_passwords.json.generated"
    try:
        return json.loads(generated.read_text())[cfg.airflow_user]
    except (OSError, ValueError, KeyError) as exc:
        raise AirflowError(
            f"no Airflow password: set SMASS_AIRFLOW_PASSWORD (could not read "
            f"{generated}: {exc})"
        ) from exc


class AirflowApi:
    """`password` is a string or a function returning one; it is only needed
    when Airflow asks for a login."""

    def __init__(self, base_url: str, user: str, password):
        self.base_url = base_url.rstrip("/")
        self._user = user
        self._password = password
        self._token: str | None = None

    def _token_header(self) -> dict:
        if self._token is None:
            self._token = self._no_login_token() or self._login_token()
        return {"Authorization": f"Bearer {self._token}"}

    def _no_login_token(self) -> str | None:
        # With simple_auth_manager_all_admins (a local no-login Airflow),
        # GET /auth/token hands out a token; otherwise it answers 403.
        try:
            return self._send("GET", "/auth/token", None, {}).get("access_token")
        except AirflowError:
            return None

    def _login_token(self) -> str:
        password = self._password() if callable(self._password) else self._password
        body = self._send("POST", "/auth/token",
                          {"username": self._user, "password": password}, {})
        return body["access_token"]

    def request(self, method: str, path: str, payload: dict | None = None) -> dict:
        return self._send(method, path, payload, self._token_header())

    def _send(self, method: str, path: str, payload, headers: dict) -> dict:
        data = None if payload is None else json.dumps(payload).encode()
        req = urllib.request.Request(
            self.base_url + path, data=data, method=method,
            headers={"Content-Type": "application/json", "Accept": "application/json",
                     **headers},
        )
        try:
            with urllib.request.urlopen(req, timeout=30) as resp:
                return json.loads(resp.read() or b"{}")
        except urllib.error.HTTPError as exc:
            detail = exc.read().decode(errors="replace")[:300]
            hint = ""
            if exc.code == 404 and "/dags/" in path:
                hint = " (is dags/ the Airflow dags_folder, and has the DAG been parsed?)"
            raise AirflowError(
                f"Airflow {method} {path} -> HTTP {exc.code}: {detail}{hint}"
            ) from exc
        except (urllib.error.URLError, OSError) as exc:
            raise AirflowError(
                f"cannot reach Airflow at {self.base_url} ({exc}); "
                "start it with scripts/airflow-standalone.sh"
            ) from exc
