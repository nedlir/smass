"""The MCPwner transport seam.

`McpClient` is the one place the stdio transport lives; agents call MCPwner tools
by name through it (the tool vocabulary itself lives in the agents). The test
double implements the same Protocol. `open_client(cfg)` returns the stdio client.
"""

from __future__ import annotations

import asyncio
import json
import threading
from pathlib import Path
from typing import Any, Protocol


class McpClient(Protocol):
    def list_tools(self) -> list[str]: ...
    def call(self, name: str, **args: Any) -> dict: ...
    def close(self) -> None: ...


def open_client(cfg) -> McpClient:
    return McpwnerClient(cfg.mcpwner_container, getattr(cfg, "mcpwner_log", None))


class McpwnerClient:
    """Synchronous wrapper over an MCPwner stdio session.

    MCPwner runs as a long-lived container; we attach with
    `docker exec -i <container> python src/server.py` and keep one session open
    (a background asyncio loop) so workspace state persists across calls.

    The mcp library is imported lazily so tests and offline runs never need it.
    """

    def __init__(self, container: str, log_path: str | None = None):
        self._container = container
        # MCPwner logs its startup and every scan to stderr. With a log path,
        # that goes to a file instead of the terminal.
        self._log_path = log_path
        self._lock = threading.Lock()
        self._loop = None
        self._thread = None
        self._session = None
        self._stop = None
        self._life = None
        self._ready = None
        self._error = None

    def _ensure(self) -> None:
        if self._session is not None:
            return
        self._loop = asyncio.new_event_loop()
        self._thread = threading.Thread(target=self._loop.run_forever, daemon=True)
        self._thread.start()
        self._ready = threading.Event()
        self._error = None
        self._life = asyncio.run_coroutine_threadsafe(self._lifecycle(), self._loop)
        self._ready.wait()
        if self._error is not None:
            raise self._error

    async def _lifecycle(self) -> None:
        # Enter AND exit the async contexts in this one task, so anyio's cancel
        # scopes are never crossed between tasks (which otherwise raises on close).
        from mcp import ClientSession, StdioServerParameters
        from mcp.client.stdio import stdio_client

        self._stop = asyncio.Event()
        params = StdioServerParameters(
            command="docker",
            args=["exec", "-i", self._container, "python", "src/server.py"],
        )
        errlog = None
        try:
            extra = {}
            if self._log_path:
                log = Path(self._log_path).expanduser()
                log.parent.mkdir(parents=True, exist_ok=True)
                errlog = extra["errlog"] = open(log, "a")
            async with stdio_client(params, **extra) as (read, write):
                async with ClientSession(read, write) as session:
                    await session.initialize()
                    self._session = session
                    self._ready.set()
                    await self._stop.wait()
        except Exception as exc:
            self._error = exc
        finally:
            self._session = None
            if errlog is not None:
                errlog.close()
            self._ready.set()

    def _run(self, coro):
        return asyncio.run_coroutine_threadsafe(coro, self._loop).result()

    def list_tools(self) -> list[str]:
        with self._lock:
            self._ensure()
            result = self._run(self._session.list_tools())
        return [t.name for t in result.tools]

    def call(self, name: str, **args: Any) -> dict:
        with self._lock:
            self._ensure()
            result = self._run(self._session.call_tool(name, arguments=args))
        return _parse_result(result)

    def close(self) -> None:
        if self._loop is None:
            return
        with self._lock:
            loop, life, stop, thread = self._loop, self._life, self._stop, self._thread
            if stop is not None:
                loop.call_soon_threadsafe(stop.set)
            try:
                if life is not None:
                    life.result(timeout=5)  # let the lifecycle unwind its contexts
            except Exception:
                pass
            loop.call_soon_threadsafe(loop.stop)
            self._session = None
            self._loop = None
            self._thread = None
        if thread is not None:
            thread.join(timeout=5)
            try:
                loop.close()
            except Exception:
                pass


def _parse_result(result) -> dict:
    """Pull a JSON object out of an MCP tool result's content blocks."""
    structured = getattr(result, "structuredContent", None)
    if isinstance(structured, dict):
        return structured
    for block in getattr(result, "content", []) or []:
        text = getattr(block, "text", None)
        if not text:
            continue
        try:
            parsed = json.loads(text)
        except (ValueError, TypeError):
            continue
        if isinstance(parsed, dict):
            return parsed
        return {"result": parsed}
    return {}
