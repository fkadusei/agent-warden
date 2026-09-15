"""The benchmark baseline (Phase 4): the same agent reaching the tool servers directly
and holding their credentials itself, with no Warden in between.

This is how agents commonly run today. It exists only so the benchmark can measure
what Warden changes; never deploy an agent this way against real tools.
"""

from __future__ import annotations

from collections.abc import AsyncIterator, Mapping, Sequence
from contextlib import AsyncExitStack, asynccontextmanager
from typing import Any, Protocol

import httpx2
from mcp import types
from mcp.client.session import ClientSession
from mcp.client.streamable_http import streamable_http_client

from .loop import CallOutcome, ToolInfo
from .warden import outcome_of


class Session(Protocol):
    async def list_tools(
        self, *, params: types.PaginatedRequestParams | None = None
    ) -> types.ListToolsResult: ...

    async def call_tool(self, name: str, arguments: dict[str, Any] | None = None) -> object: ...


class DirectTools:
    """Every tool of every server, named "server.tool" as Warden names them."""

    def __init__(self, sessions: Mapping[str, Session]) -> None:
        self._sessions = dict(sessions)

    async def list_tools(self) -> list[ToolInfo]:
        out: list[ToolInfo] = []
        for server, session in self._sessions.items():
            cursor: str | None = None
            while True:
                params = types.PaginatedRequestParams(cursor=cursor) if cursor else None
                page = await session.list_tools(params=params)
                out.extend(
                    ToolInfo(f"{server}.{t.name}", t.description or "", dict(t.input_schema))
                    for t in page.tools
                )
                cursor = page.next_cursor
                if not cursor:
                    break
        return out

    async def call(self, name: str, arguments: dict[str, Any]) -> CallOutcome:
        server, _, tool = name.partition(".")
        session = self._sessions.get(server)
        if session is None or not tool:
            return CallOutcome(f"no tool {name!r}", True)
        return outcome_of(await session.call_tool(tool, arguments))


@asynccontextmanager
async def connect_direct(
    base_url: str, servers: Sequence[str], headers: Mapping[str, Mapping[str, str]]
) -> AsyncIterator[DirectTools]:
    """Open an MCP session to base_url/<server> for each server. headers maps a server
    to the HTTP headers (credentials) the agent itself sends to it."""
    async with AsyncExitStack() as stack:
        sessions: dict[str, Session] = {}
        for server in servers:
            http = await stack.enter_async_context(
                httpx2.AsyncClient(timeout=60, headers=dict(headers.get(server, {})))
            )
            streams = await stack.enter_async_context(
                streamable_http_client(f"{base_url.rstrip('/')}/{server}", http_client=http)
            )
            session = await stack.enter_async_context(ClientSession(streams[0], streams[1]))
            await session.initialize()
            sessions[server] = session
        yield DirectTools(sessions)
