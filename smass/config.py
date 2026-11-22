"""One frozen Config object, loaded from the environment.

No global singletons: `load()` is pure (env in, Config out) and the result is
threaded down through the pipeline and agents.
"""

from __future__ import annotations

import os
from dataclasses import dataclass, replace
from pathlib import Path

DEFAULT_MODEL = "claude-opus-5-5"


@dataclass(frozen=True)
class Config:
    llm_api_key: str
    llm_base_url: str | None
    llm_api: str  # "anthropic" or "openai"
    mcpwner_container: str
    # Which specific scanner to run in each MCPwner category.
    secrets_tool: str
    sast_tool: str
    sca_tool: str
    iac_tool: str | None
    master_model: str
    reviewer_model: str
    poc_model: str
    memory_path: Path
    findings_dir: Path
    # `smass --airflow`: the Airflow API server to trigger the smass_scan DAG on.
    airflow_url: str = "http://localhost:8080"
    airflow_user: str = "admin"
    airflow_password: str | None = None  # None: read Airflow's generated password file
    airflow_timeout: int = 7200  # seconds to wait for a DAG run
    mcpwner_log: str | None = None  # file for MCPwner's stderr; None: the terminal


def with_paths_under(cfg: Config, base: Path) -> Config:
    """Anchor relative run-output paths at `base` instead of the process cwd.

    The CLI runs from the user's shell, so relative paths land in their cwd. An
    Airflow task runs in a scratch cwd, so the DAG anchors them at the project.
    """
    def anchor(p: Path) -> Path:
        return p if p.is_absolute() else Path(base) / p

    return replace(
        cfg, memory_path=anchor(cfg.memory_path), findings_dir=anchor(cfg.findings_dir)
    )


def load(env: dict | None = None) -> Config:
    """Build a Config from a mapping (defaults to os.environ)."""
    env = os.environ if env is None else env
    return Config(
        llm_api_key=(env.get("SMASS_LLM_API_KEY") or env.get("ANTHROPIC_API_KEY") or ""),
        llm_base_url=(env.get("SMASS_LLM_BASE_URL") or None),
        llm_api=env.get("SMASS_LLM_API", "anthropic"),
        mcpwner_container=env.get("SMASS_MCPWNER_CONTAINER", "mcpwner-server"),
        secrets_tool=env.get("SMASS_SECRETS_TOOL", "trufflehog"),
        sast_tool=env.get("SMASS_SAST_TOOL", "semgrep"),
        sca_tool=env.get("SMASS_SCA_TOOL", "grype"),
        iac_tool=(env.get("SMASS_IAC_TOOL") or None),
        master_model=env.get("SMASS_MASTER_MODEL", DEFAULT_MODEL),
        reviewer_model=env.get("SMASS_REVIEWER_MODEL", DEFAULT_MODEL),
        poc_model=env.get("SMASS_POC_MODEL", DEFAULT_MODEL),
        memory_path=Path(env.get("SMASS_MEMORY_PATH", ".smass/reviewer_memory.json")),
        findings_dir=Path(env.get("SMASS_FINDINGS_DIR", ".smass/findings")),
        airflow_url=env.get("SMASS_AIRFLOW_URL", "http://localhost:8080").rstrip("/"),
        airflow_user=env.get("SMASS_AIRFLOW_USER", "admin"),
        airflow_password=(env.get("SMASS_AIRFLOW_PASSWORD") or None),
        airflow_timeout=int(env.get("SMASS_AIRFLOW_TIMEOUT", "7200")),
        mcpwner_log=(env.get("SMASS_MCPWNER_LOG") or None),
    )
