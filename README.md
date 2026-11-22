# smass (scan my assets)

<p align="center"><img src="assets/so-anyway-i-started-blasting.gif" alt="So anyway, I started blasting" width="300"></p>

A local secure-coding validation suite. You run `smass` on your machine; it builds
an isolated sandbox, runs a battery of security scanners through **[MCPwner](https://github.com/Pigyon/MCPwner)** (every
scanner pre-containerized, so you configure none of them), has an LLM **Master
Agent** triage the results and dispatch a proof squad (deep review, write a PoC,
verify it for real), and writes a report of verified findings only.

No CI and no GitHub Action: it is a local CLI, with a fast pre-push git hook as the
first line of defense.

> **Only scan code you own or are allowed to test.** smass has an LLM write exploit
> code for what it finds and runs it in MCPwner's sandbox container. It is meant for
> your own projects; review a finding before you trust it, and never run a generated
> `exploit.py` on your host.

## Install

```sh
pip install -e .            # core
pip install -e ".[dev]"     # + pytest
pip install -e ".[openai]"  # + OpenAI-compatible interface
```

Copy `.env.example` to `.env` and set your LLM API key (needed by the LLM agents
in a full scan). Model defaults to `claude-opus-5-5`; override per agent with the
`SMASS_*_MODEL` env vars.

## LLM API key (provider-agnostic)

The LLM agents call any **Anthropic- or OpenAI-compatible** API with a key you
supply. You insert the key; smass does not manage credentials.

```sh
SMASS_LLM_API_KEY=sk-...        # or set ANTHROPIC_API_KEY instead
SMASS_LLM_API=anthropic         # "anthropic" (default) or "openai"
# SMASS_LLM_BASE_URL=https://...  # optional: a custom/compatible endpoint
```

- Anthropic API: set the key, keep `SMASS_LLM_API=anthropic`.
- OpenAI or any OpenAI-compatible API: `SMASS_LLM_API=openai` and install the
  extra (`pip install -e ".[openai]"`); set `SMASS_LLM_BASE_URL` for a non-OpenAI
  endpoint.
- Any compatible gateway, relay, or local proxy: point `SMASS_LLM_BASE_URL` at it
  and use its key. Set the `SMASS_*_MODEL` ids to models that endpoint serves.

## Bootstrap MCPwner

smass runs its scanners through [MCPwner](https://github.com/Pigyon/MCPwner), a set of Docker containers.

```sh
git clone https://github.com/Pigyon/MCPwner.git && cd MCPwner
cp .env.example .env && cp config/config.yaml.example config/config.yaml
# static scanners + the PoC sandbox; keep recon/DAST off
#   COMPOSE_PROFILES=sast,sca,secrets,iac,poc
docker compose up -d --build && docker compose ps   # mcpwner-server healthy?
```

MCPwner reads projects from its own filesystem, at the same absolute path as on
the host, so mount the folder you keep projects in into `mcpwner-server` at that
path (not at `/mnt/projects` as in MCPwner's own README), in MCPwner's
`docker-compose.yaml`:

```yaml
services:
  mcpwner:
    volumes:
      - /home/you/projects:/home/you/projects:ro
```

A project outside every mount looks empty to the scanners and comes back clean.

Confirm the real IaC tool name from the live tool list and set `SMASS_IAC_TOOL`.
If unset, the IaC agent skips cleanly.

## Run

```sh
smass .            # full scan of the current project
smass --quick .    # fast pre-push scan (secrets + semgrep)
smass --airflow .  # full scan as an Airflow DAG run (see below)
```

Both talk to a live MCPwner container (see below).

- The **full scan** also needs an LLM API key (its LLM agents). MCPwner
  writes the report; smass prints its path and exits non-zero when there are
  verified findings, so you can gate scripts on it.
- `--quick` runs **without an LLM**. It exits non-zero on a leaked secret or a
  high-or-worse finding.

### Airflow (optional orchestrator)

`smass --airflow .` runs the full scan as a run of the `smass_scan` DAG
(`dags/smass_scan.py`) on a local Airflow, waits for it, and prints and exits
exactly like `smass .`. Plain `smass .` never needs Airflow.

```
sandbox ─┬─ scan_sca / scan_sast / scan_codeql / scan_secrets / scan_iac ─┬─ prove
```

Each scanner is its own task (own logs and retries in the UI, one failing does
not hide the others). Task bodies are the same `smass.pipeline.stage_*` functions
the CLI uses; each opens its own MCPwner session, which works because MCPwner
persists workspaces and findings on disk.

One-time install, in its own venv (Airflow pins many dependencies):

```sh
python3 -m venv .venv-airflow
.venv-airflow/bin/pip install "apache-airflow==3.3.2" \
  --constraint https://raw.githubusercontent.com/apache/airflow/constraints-3.3.2/constraints-3.12.txt
.venv-airflow/bin/pip install -e .
```

Run it, then scan:

```sh
scripts/airflow-standalone.sh       # UI on http://127.0.0.1:8080, user "admin"
smass --airflow /abs/path/to/project
```

- The script loads `.env` (so tasks see your `SMASS_*` settings), points
  `dags_folder` at `dags/`, and binds to `127.0.0.1` only. `AIRFLOW_HOME` defaults
  to `~/airflow`.
- The admin password is generated into
  `$AIRFLOW_HOME/simple_auth_manager_passwords.json.generated`; `smass --airflow`
  reads it from there, or set `SMASS_AIRFLOW_PASSWORD`.
- On the default SQLite metadata DB, tasks run **one at a time** (SQLite has a
  single writer; concurrent tasks crash the scheduler with "database is locked").
  For parallel scanners, point `AIRFLOW__DATABASE__SQL_ALCHEMY_CONN` at Postgres.
- Run output (`.smass/`) goes under the scanned project. `--quick` (the pre-push
  gate) always runs in-process.
- You can also trigger from the UI ("Trigger" with conf
  `{"project_path": "/abs/path"}`).

### Pre-push hook

```sh
printf '#!/bin/sh\nexec smass --quick "$(git rev-parse --show-toplevel)"\n' > .git/hooks/pre-push
chmod +x .git/hooks/pre-push
```

Blocks a push on a leaked secret or a high-or-worse finding. It needs the MCPwner
container running; if MCPwner is unavailable the hook **fails open** (prints a
warning and does not block the push, since the full scan is the real gate).

## Agents

A sandbox step, five scanners (SCA, SAST, CodeQL, Secrets, IaC) and four LLM agents:
Master triages and dispatches, Code Review runs three deduped passes, PoC Writer
authors an exploit that MCPwner's sandbox runs, and Verifier checks that run really
proves the finding.

The Code Review and PoC Writer agents **read the source code** (`smass/source.py`):
the project's source files, line-numbered, flagged files first, within a size
budget. That is what lets the reviewer find logic bugs no scanner rule matches
(a missing ownership check, a negative quantity). A review finding must cite a
file and line that exist in the listing it was shown, or it is dropped, and its
snippet is replaced by the real line. The code is fenced as untrusted data in
the prompts. The same files are copied next to the exploit in MCPwner's PoC
sandbox, so the PoC imports and drives the real code, not a model of it.

### Claude Code skills

`skills/` holds two Claude Code skills. Link them into `~/.claude/skills/` to use them
from any project:

```sh
ln -s "$PWD/skills/smass" ~/.claude/skills/smass
ln -s "$PWD/skills/a-simple-security" ~/.claude/skills/a-simple-security
```

- `smass` runs smass for developers: check the setup, pick quick or full (through
  Airflow when it is up), wait for the run, and report what was proven with
  `file:line`, without ever running an exploit on the host. Type `/smass <what to
  scan>` or ask for a security scan.
- `a-simple-security` (a.s.s.), for vibe coders, runs the whole pipeline against your
  own project: it checks smass is ready, scans a snapshot of the project (your folder
  is never changed), reads what was proven, explains each problem in plain language,
  offers to fix it in your project, and checks again. Ask "is my app secure?" or type
  `/a-simple-security`.

A finding is **proven** only when its exploit passes MCPwner's sandbox oracle
(`run_poc_scan`: the script exited 0) **and** the Verifier agent, reading the script
and its output from `get_poc_report`, confirms the run drove the project's real code
to the harmful effect (the oracle alone would accept a script that only exits 0).
smass never runs an exploit on the host.

SAST runs Semgrep's default ruleset. (LLM-authored custom rules are not wired:
MCPwner's Semgrep runs in a container that cannot read host-written rule files;
re-enabling them needs MCPwner to accept inline rule bodies.)

MCPwner is reached through one stdio transport seam (`smass/mcp_client.py`).

## Test

```sh
pytest                                   # Airflow DAG tests are skipped
.venv-airflow/bin/python -m pytest       # + the DAG tests (shape, end-to-end dag.test)
```

Tests run offline against a test-double MCP client (`tests/fake_mcp_client.py`),
with LLM calls stubbed. No Docker, network, or API key required.

<p align="center"><img src="assets/its-always-sunny-lit.gif" alt="It's lit" width="300"></p>
