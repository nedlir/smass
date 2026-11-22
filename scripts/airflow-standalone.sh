#!/usr/bin/env bash
# Run a local, single-user Airflow (API server + UI, scheduler, DAG processor)
# serving smass's dags/ folder, on 127.0.0.1:8080.
#
# One-time install (separate venv, so Airflow's pinned deps never touch .venv):
#   python3 -m venv .venv-airflow
#   .venv-airflow/bin/pip install "apache-airflow==3.3.2" \
#     --constraint https://raw.githubusercontent.com/apache/airflow/constraints-3.3.2/constraints-3.12.txt
#   .venv-airflow/bin/pip install -e .
#
# Login: user "admin"; the password is generated into
# $AIRFLOW_HOME/simple_auth_manager_passwords.json.generated (smass --airflow
# reads it from there, or set SMASS_AIRFLOW_PASSWORD).
set -euo pipefail

REPO="$(cd "$(dirname "$0")/.." && pwd)"
AIRFLOW_BIN="${AIRFLOW_BIN:-$REPO/.venv-airflow/bin/airflow}"
[ -x "$AIRFLOW_BIN" ] || { echo "airflow not found at $AIRFLOW_BIN (see install steps in $0)" >&2; exit 1; }
# standalone launches its components as `airflow ...` subprocesses, found on PATH.
export PATH="$(dirname "$AIRFLOW_BIN"):$PATH"

# smass settings (SMASS_*) for the task processes.
if [ -f "$REPO/.env" ]; then
  set -a; . "$REPO/.env"; set +a
fi

export AIRFLOW_HOME="${AIRFLOW_HOME:-$HOME/airflow}"
export AIRFLOW__CORE__DAGS_FOLDER="$REPO/dags"
export AIRFLOW__CORE__LOAD_EXAMPLES=False
export AIRFLOW__CORE__SIMPLE_AUTH_MANAGER_USERS="${SMASS_AIRFLOW_USER:-admin}:admin"
export AIRFLOW__API__HOST=127.0.0.1   # local only; do not expose on the LAN

# SQLite (the default metadata DB) allows one writer: concurrent tasks crash the
# scheduler with "database is locked". On SQLite, run one task at a time. To run
# the scanners in parallel, point AIRFLOW__DATABASE__SQL_ALCHEMY_CONN at Postgres.
case "${AIRFLOW__DATABASE__SQL_ALCHEMY_CONN:-sqlite}" in
  sqlite*) export AIRFLOW__CORE__PARALLELISM=1 ;;
esac
export AIRFLOW__API__PORT="${AIRFLOW_PORT:-8080}"

exec "$AIRFLOW_BIN" standalone
