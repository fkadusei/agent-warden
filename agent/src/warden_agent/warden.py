"""Reaching tools through Warden: MCP over TLS 1.3 with the task credential as the
client certificate (ADR-0011). The agent holds no tool credentials."""

from __future__ import annotations

import ssl
from collections.abc import AsyncIterator
from contextlib import asynccontextmanager
from typing import Any

import httpx2
from mcp import types
from mcp.client.session import ClientSession
from mcp.client.streamable_http import streamable_http_client

from .loop import CallOutcome, ToolInfo


def tls_context(ca: str, cert: str, key: str) -> ssl.SSLContext:
    """Trust only Warden's root, require TLS 1.3, and present the task credential."""
    ctx = ssl.create_default_context(cafile=ca)
    ctx.minimum_version = ssl.TLSVersion.TLSv1_3
    ctx.load_cert_chain(cert, key)
    return ctx


class WardenTools:
    """The tools Warden exposes to this task's credential."""

    def __init__(self, session: ClientSession) -> None:
        self._session = session

    async def list_tools(self) -> list[ToolInfo]:
        out: list[ToolInfo] = []
        cursor: str | None = None
        while True:
            params = types.PaginatedRequestParams(cursor=cursor) if cursor else None
            page = await self._session.list_tools(params=params)
            out.extend(ToolInfo(t.name, t.description or "", dict(t.input_schema)) for t in page.tools)
            cursor = page.next_cursor
            if not cursor:
                return out

    async def call(self, name: str, arguments: dict[str, Any]) -> CallOutcome:
        res = await self._session.call_tool(name, arguments)
        if not isinstance(res, types.CallToolResult):
            return CallOutcome(f"unexpected {type(res).__name__} from Warden", True)
        text = "\n".join(c.text for c in res.content if isinstance(c, types.TextContent))
        return CallOutcome(text, bool(res.is_error))


@asynccontextmanager
async def connect(url: str, ca: str, cert: str, key: str) -> AsyncIterator[WardenTools]:
    async with (
        httpx2.AsyncClient(verify=tls_context(ca, cert, key), timeout=60) as http,
        streamable_http_client(url, http_client=http) as streams,
        ClientSession(streams[0], streams[1]) as session,
    ):
        await session.initialize()
        yield WardenTools(session)
