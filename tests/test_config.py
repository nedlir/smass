from pathlib import Path

from smass import config


def test_with_paths_under_anchors_relative_paths(cfg, tmp_path):
    rel = config.load({})  # defaults are relative (.smass/...)
    anchored = config.with_paths_under(rel, tmp_path)
    assert anchored.memory_path == tmp_path / ".smass/reviewer_memory.json"
    assert anchored.findings_dir == tmp_path / ".smass/findings"


def test_with_paths_under_keeps_absolute_paths(tmp_path):
    cfg = config.load({"SMASS_FINDINGS_DIR": "/abs/findings"})
    assert config.with_paths_under(cfg, tmp_path).findings_dir == Path("/abs/findings")


def test_airflow_settings_from_env():
    cfg = config.load({
        "SMASS_AIRFLOW_URL": "http://127.0.0.1:9090/",
        "SMASS_AIRFLOW_PASSWORD": "pw",
        "SMASS_AIRFLOW_TIMEOUT": "60",
    })
    assert cfg.airflow_url == "http://127.0.0.1:9090"
    assert cfg.airflow_password == "pw"
    assert cfg.airflow_timeout == 60
    assert config.load({}).airflow_password is None


def test_mcpwner_log_defaults_to_terminal_and_is_settable():
    from smass import config

    assert config.load({}).mcpwner_log is None
    assert config.load({"SMASS_MCPWNER_LOG": "/tmp/m.log"}).mcpwner_log == "/tmp/m.log"
