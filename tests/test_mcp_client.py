"""Exercise the real McpwnerClient lifecycle with a fake async MCP session.

No Docker and no `mcp` package needed: we inject fake `mcp` / `mcp.client.stdio`
modules. This verifies the background-loop lifecycle, that calls work from the
main thread, and that close() exits the async contexts in the same task without
raising.
"""

import sys
import types

import pytest


class _FakeStdio:
    def __init__(self, params):
        self.params = params
        self.exited = False

    async def __aenter__(self):
        return ("read", "write")

    async def __aexit__(self, *exc):
        self.exited = True
        return False


class _FakeSession:
    def __init__(self, read, write):
        self.exited = False
        self.initialized = False

    async def __aenter__(self):
        return self

    async def __aexit__(self, *exc):
        self.exited = True
        return False

    async def initialize(self):
        self.initialized = True

    async def list_tools(self):
        t = types.SimpleNamespace
        return types.SimpleNamespace(
            tools=[t(name="run_secrets_scan"), t(name="create_workspace")]
        )

    async def call_tool(self, name, arguments=None):
        return types.SimpleNamespace(structuredContent={"echo": name, "args": arguments})


@pytest.fixture
def fake_mcp(monkeypatch):
    created = {}

    class StdioServerParameters:
        def __init__(self, **kw):
            self.kw = kw

    class ClientSession(_FakeSession):
        def __init__(self, read, write):
            super().__init__(read, write)
            created["session"] = self

    def stdio_client(params, **kw):
        s = _FakeStdio(params)
        created["stdio"] = s
        created["stdio_kw"] = kw
        return s

    mcp = types.ModuleType("mcp")
    mcp.ClientSession = ClientSession
    mcp.StdioServerParameters = StdioServerParameters
    stdio_mod = types.ModuleType("mcp.client.stdio")
    stdio_mod.stdio_client = stdio_client
    monkeypatch.setitem(sys.modules, "mcp", mcp)
    monkeypatch.setitem(sys.modules, "mcp.client", types.ModuleType("mcp.client"))
    monkeypatch.setitem(sys.modules, "mcp.client.stdio", stdio_mod)
    return created


def test_lifecycle_call_and_clean_close(fake_mcp):
    from smass.mcp_client import McpwnerClient

    client = McpwnerClient("mcpwner-server")
    assert "run_secrets_scan" in client.list_tools()

    result = client.call("run_secrets_scan", workspace_id="ws1", tool="trufflehog")
    assert result == {"echo": "run_secrets_scan",
                      "args": {"workspace_id": "ws1", "tool": "trufflehog"}}

    client.close()  # must not raise, and must exit both async contexts
    assert fake_mcp["stdio"].exited is True
    assert fake_mcp["session"].exited is True

    client.close()  # idempotent


def test_connect_error_surfaces(monkeypatch):
    def boom(params):
        raise RuntimeError("No such container: mcpwner-server")

    mcp = types.ModuleType("mcp")
    mcp.ClientSession = object
    mcp.StdioServerParameters = lambda **kw: None
    stdio_mod = types.ModuleType("mcp.client.stdio")
    stdio_mod.stdio_client = boom
    monkeypatch.setitem(sys.modules, "mcp", mcp)
    monkeypatch.setitem(sys.modules, "mcp.client", types.ModuleType("mcp.client"))
    monkeypatch.setitem(sys.modules, "mcp.client.stdio", stdio_mod)

    from smass.mcp_client import McpwnerClient

    client = McpwnerClient("mcpwner-server")
    with pytest.raises(RuntimeError, match="No such container"):
        client.list_tools()
    client.close()  # still clean


def test_mcpwner_stderr_goes_to_log_file_when_set(fake_mcp, tmp_path):
    from smass.mcp_client import McpwnerClient

    log = tmp_path / "logs" / "mcpwner.log"
    client = McpwnerClient("mcpwner-server", log_path=str(log))
    client.list_tools()
    assert fake_mcp["stdio_kw"]["errlog"].name == str(log)
    client.close()
    assert log.exists()
