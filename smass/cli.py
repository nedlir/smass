"""smass command-line entry point.

    smass [path]            full scan (default path: current directory)
    smass --quick [path]    pre-push tier: Secrets + fast Semgrep, blocking exit
    smass --airflow [path]  full scan as a run of the smass_scan DAG on local Airflow
"""

from __future__ import annotations

import argparse
import sys
from pathlib import Path

from . import config
from .airflow_trigger import AirflowError, run_via_airflow
from .pipeline import run_full, run_quick


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        prog="smass", description="scan my assets: local secure-coding validation"
    )
    parser.add_argument("path", nargs="?", default=".", help="project to scan")
    parser.add_argument(
        "--quick", action="store_true", help="fast pre-push scan (secrets + semgrep)"
    )
    parser.add_argument(
        "--airflow", action="store_true",
        help="run the full scan as an Airflow DAG run (needs Airflow up)",
    )
    args = parser.parse_args(argv)

    cfg = config.load()
    path = Path(args.path).resolve()
    if not path.exists():
        print(f"smass: path not found: {path}", file=sys.stderr)
        return 2

    if args.quick and args.airflow:
        parser.error("--quick runs in-process; it cannot be combined with --airflow")

    if args.quick:
        try:
            result = run_quick(cfg, path)
        except Exception as exc:
            # Fail open: a convenience pre-push gate must not block a push because
            # MCPwner is unavailable. The full scan is the real gate.
            print(f"smass: quick scan could not run ({exc}); push NOT blocked "
                  "(advisory).", file=sys.stderr)
            return 0
        if result.blocked:
            print(f"smass: blocked. {len(result.findings)} issue(s) found:")
            for f in result.findings:
                print(f"  [{f.get('severity')}] {f.get('file')}:{f.get('line')} "
                      f"{f.get('message')}")
            return 1
        if result.skipped:
            # A scanner did not run, so "clean" cannot be trusted; fail closed.
            print(f"smass: gate incomplete, these scanners did not run: "
                  f"{', '.join(result.skipped)}", file=sys.stderr)
            return 1
        print(f"smass: clean ({len(result.findings)} non-blocking note(s)).")
        return 0

    try:
        if args.airflow:
            result = run_via_airflow(cfg, path)
        else:
            result = run_full(cfg, path)
    except AirflowError as exc:
        print(f"smass: {exc}", file=sys.stderr)
        return 2
    except Exception as exc:
        if "LLM API key" in str(exc):
            print(f"smass: {exc}", file=sys.stderr)
        else:
            print(f"smass: scan failed: {exc}", file=sys.stderr)
            print("smass: is the MCPwner container running? (docker compose up)",
                  file=sys.stderr)
        return 2
    print(f"smass: {len(result.verified)} verified of {result.considered} "
          f"finding(s) considered.")
    if result.report_path:
        print(f"smass: MCPwner wrote the report at {result.report_path}")
    return 1 if result.verified else 0


def run() -> None:
    sys.exit(main())


if __name__ == "__main__":
    run()
