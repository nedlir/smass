import pytest

from fake_mcp_client import FakeMcpClient

from smass.config import Config


@pytest.fixture
def cfg(tmp_path):
    return Config(
        llm_api_key="test-key",
        llm_base_url=None,
        llm_api="anthropic",
        mcpwner_container="x",
        secrets_tool="trufflehog",
        sast_tool="semgrep",
        sca_tool="grype",
        iac_tool=None,
        master_model="m",
        reviewer_model="m",
        poc_model="m",
        memory_path=tmp_path / "reviewer_memory.json",
        findings_dir=tmp_path / "findings",
    )


@pytest.fixture
def client():
    return FakeMcpClient()
