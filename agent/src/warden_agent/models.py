"""Model adapters (ADR-0012).

An adapter turns the conversation so far into the model's next turn: some text and
zero or more proposed tool calls. Nothing here is trusted; Warden decides every call.
"""

from __future__ import annotations

import json
import re
from collections.abc import Sequence
from dataclasses import dataclass, field
from typing import Any, Protocol


@dataclass(frozen=True)
class ToolSpec:
    """A tool as offered to a model."""

    name: str  # model-safe name, see model_name
    description: str
    schema: dict[str, Any]


@dataclass
class ToolCall:
    id: str
    name: str  # model-safe name, as the model sent it
    arguments: dict[str, Any]
    # Set when the model's arguments could not be used; the call is not made.
    error: str | None = None


@dataclass
class Turn:
    text: str
    tool_calls: list[ToolCall] = field(default_factory=list)


@dataclass
class ToolResult:
    call_id: str
    name: str
    text: str
    is_error: bool


@dataclass
class UserText:
    text: str


type Message = UserText | Turn | list[ToolResult]


class Model(Protocol):
    adapter: str
    model: str

    async def turn(self, system: str, history: Sequence[Message], tools: Sequence[ToolSpec]) -> Turn: ...


_SAFE_NAME = re.compile(r"^[A-Za-z0-9_-]{1,64}$")


def model_name(tool: str) -> str:
    """Map an MCP tool name ("crm.lookup") to one model APIs accept ("crm__lookup")."""
    name = tool.replace(".", "__")
    if not _SAFE_NAME.match(name):
        raise ValueError(f"tool name {tool!r} cannot be offered to a model")
    return name


# --- Anthropic Messages API ---------------------------------------------------------


def anthropic_messages(history: Sequence[Message]) -> list[dict[str, Any]]:
    out: list[dict[str, Any]] = []
    for m in history:
        if isinstance(m, UserText):
            out.append({"role": "user", "content": m.text})
        elif isinstance(m, Turn):
            blocks: list[dict[str, Any]] = []
            if m.text:
                blocks.append({"type": "text", "text": m.text})
            for c in m.tool_calls:
                blocks.append({"type": "tool_use", "id": c.id, "name": c.name, "input": c.arguments})
            if not blocks:
                blocks.append({"type": "text", "text": "(no reply)"})
            out.append({"role": "assistant", "content": blocks})
        else:
            out.append(
                {
                    "role": "user",
                    "content": [
                        {
                            "type": "tool_result",
                            "tool_use_id": r.call_id,
                            "content": r.text,
                            "is_error": r.is_error,
                        }
                        for r in m
                    ],
                }
            )
    return out


class AnthropicModel:
    """Claude models through the Anthropic Messages API. The key comes from
    ANTHROPIC_API_KEY."""

    adapter = "anthropic"

    def __init__(self, model: str, *, client: Any = None, max_tokens: int = 1024) -> None:
        if client is None:
            import anthropic

            client = anthropic.AsyncAnthropic()
        self.model = model
        self._client = client
        self._max_tokens = max_tokens

    async def turn(self, system: str, history: Sequence[Message], tools: Sequence[ToolSpec]) -> Turn:
        resp = await self._client.messages.create(
            model=self.model,
            max_tokens=self._max_tokens,
            system=system,
            messages=anthropic_messages(history),
            tools=[{"name": t.name, "description": t.description, "input_schema": t.schema} for t in tools],
        )
        text: list[str] = []
        calls: list[ToolCall] = []
        for block in resp.content:
            if block.type == "text":
                text.append(block.text)
            elif block.type == "tool_use":
                if isinstance(block.input, dict):
                    calls.append(ToolCall(block.id, block.name, dict(block.input)))
                else:
                    calls.append(ToolCall(block.id, block.name, {}, "arguments were not a JSON object"))
        return Turn("".join(text), calls)


# --- OpenAI-compatible Chat Completions (OpenAI, Ollama, vLLM, LM Studio) ----------


def openai_messages(system: str, history: Sequence[Message]) -> list[dict[str, Any]]:
    out: list[dict[str, Any]] = [{"role": "system", "content": system}]
    for m in history:
        if isinstance(m, UserText):
            out.append({"role": "user", "content": m.text})
        elif isinstance(m, Turn):
            msg: dict[str, Any] = {"role": "assistant", "content": m.text or None}
            if m.tool_calls:
                msg["tool_calls"] = [
                    {
                        "id": c.id,
                        "type": "function",
                        "function": {"name": c.name, "arguments": json.dumps(c.arguments)},
                    }
                    for c in m.tool_calls
                ]
            out.append(msg)
        else:
            # Chat Completions has no error flag on tool results, so say it in the text.
            out.extend(
                {
                    "role": "tool",
                    "tool_call_id": r.call_id,
                    "content": ("ERROR: " if r.is_error else "") + r.text,
                }
                for r in m
            )
    return out


def parse_arguments(raw: str | None) -> tuple[dict[str, Any], str | None]:
    try:
        value = json.loads(raw or "{}")
    except ValueError:
        return {}, "arguments were not valid JSON"
    if not isinstance(value, dict):
        return {}, "arguments were not a JSON object"
    return value, None


class OpenAICompatibleModel:
    """Any Chat Completions endpoint. base_url selects it (for example
    http://127.0.0.1:11434/v1 for Ollama); the key comes from an environment variable."""

    adapter = "openai-compatible"

    def __init__(
        self, model: str, *, base_url: str | None = None, api_key: str | None = None, client: Any = None
    ) -> None:
        if client is None:
            import openai

            client = openai.AsyncOpenAI(base_url=base_url, api_key=api_key)
        self.model = model
        self._client = client

    async def turn(self, system: str, history: Sequence[Message], tools: Sequence[ToolSpec]) -> Turn:
        resp = await self._client.chat.completions.create(
            model=self.model,
            messages=openai_messages(system, history),
            tools=[
                {
                    "type": "function",
                    "function": {"name": t.name, "description": t.description, "parameters": t.schema},
                }
                for t in tools
            ],
        )
        msg = resp.choices[0].message
        calls: list[ToolCall] = []
        for tc in msg.tool_calls or []:
            fn = getattr(tc, "function", None)
            if fn is None:
                calls.append(ToolCall(tc.id, "", {}, "unsupported tool call type"))
                continue
            args, err = parse_arguments(fn.arguments)
            calls.append(ToolCall(tc.id, fn.name, args, err))
        return Turn(msg.content or "", calls)


# --- Scripted replay -----------------------------------------------------------------


class ScriptModel:
    """Replays fixed calls, one per turn, without a model: the Python counterpart of
    the Go gate's scripted agent, useful for trying the whole path offline."""

    adapter = "script"

    def __init__(self, calls: Sequence[tuple[str, dict[str, Any]]], model: str = "scenario-script") -> None:
        self.model = model
        self._calls = list(calls)
        self._next = 0

    async def turn(self, system: str, history: Sequence[Message], tools: Sequence[ToolSpec]) -> Turn:
        if self._next >= len(self._calls):
            return Turn("Finished the scripted calls.")
        tool, args = self._calls[self._next]
        self._next += 1
        return Turn("", [ToolCall(f"script-{self._next}", model_name(tool), dict(args))])
