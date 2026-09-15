import asyncio
from types import SimpleNamespace
from typing import Any

from warden_agent.models import (
    AnthropicModel,
    OpenAICompatibleModel,
    ScriptModel,
    ToolCall,
    ToolResult,
    ToolSpec,
    Turn,
    UserText,
    anthropic_messages,
    openai_messages,
    parse_arguments,
)

HISTORY: list[Any] = [
    UserText("resolve T-1"),
    Turn("Reading.", [ToolCall("c1", "tickets__get", {"id": "T-1"})]),
    [ToolResult("c1", "tickets__get", "ticket text", False)],
    Turn("", [ToolCall("c2", "payments__refund", {"payment_id": "p-1", "amount": 60})]),
    [ToolResult("c2", "payments__refund", "This call needs human approval", True)],
]
TOOLS = [
    ToolSpec("tickets__get", "Read a ticket.", {"type": "object", "properties": {"id": {"type": "string"}}})
]


class Recorder:
    def __init__(self, response: Any) -> None:
        self.response = response
        self.kwargs: dict[str, Any] = {}

    async def create(self, **kwargs: Any) -> Any:
        self.kwargs = kwargs
        return self.response


def test_anthropic_messages() -> None:
    msgs = anthropic_messages(HISTORY)
    assert [m["role"] for m in msgs] == ["user", "assistant", "user", "assistant", "user"]
    assert msgs[1]["content"] == [
        {"type": "text", "text": "Reading."},
        {"type": "tool_use", "id": "c1", "name": "tickets__get", "input": {"id": "T-1"}},
    ]
    assert msgs[3]["content"] == [
        {
            "type": "tool_use",
            "id": "c2",
            "name": "payments__refund",
            "input": {"payment_id": "p-1", "amount": 60},
        },
    ]
    assert msgs[4]["content"][0] == {
        "type": "tool_result",
        "tool_use_id": "c2",
        "content": "This call needs human approval",
        "is_error": True,
    }
    assert anthropic_messages([Turn("")])[0]["content"] == [{"type": "text", "text": "(no reply)"}]


def test_anthropic_model_turn() -> None:
    rec = Recorder(
        SimpleNamespace(
            content=[
                SimpleNamespace(type="text", text="I'll refund it."),
                SimpleNamespace(
                    type="tool_use",
                    id="t1",
                    name="payments__refund",
                    input={"payment_id": "p-1", "amount": 5},
                ),
                SimpleNamespace(type="tool_use", id="t2", name="payments__refund", input="not an object"),
            ]
        )
    )
    model = AnthropicModel("claude-test", client=SimpleNamespace(messages=rec))
    turn = asyncio.run(model.turn("sys", HISTORY, TOOLS))
    assert turn.text == "I'll refund it."
    assert [(c.id, c.name, c.arguments, c.error) for c in turn.tool_calls] == [
        ("t1", "payments__refund", {"payment_id": "p-1", "amount": 5}, None),
        ("t2", "payments__refund", {}, "arguments were not a JSON object"),
    ]
    assert rec.kwargs["model"] == "claude-test"
    assert rec.kwargs["system"] == "sys"
    assert rec.kwargs["tools"] == [
        {"name": "tickets__get", "description": "Read a ticket.", "input_schema": TOOLS[0].schema}
    ]


def test_openai_messages() -> None:
    msgs = openai_messages("sys", HISTORY)
    assert [m["role"] for m in msgs] == ["system", "user", "assistant", "tool", "assistant", "tool"]
    assert msgs[2]["tool_calls"][0] == {
        "id": "c1",
        "type": "function",
        "function": {"name": "tickets__get", "arguments": '{"id": "T-1"}'},
    }
    assert msgs[4]["content"] is None
    assert msgs[5] == {
        "role": "tool",
        "tool_call_id": "c2",
        "content": "ERROR: This call needs human approval",
    }


def test_parse_arguments() -> None:
    assert parse_arguments('{"a": 1}') == ({"a": 1}, None)
    assert parse_arguments(None) == ({}, None)
    assert parse_arguments("{bad") == ({}, "arguments were not valid JSON")
    assert parse_arguments("[1]") == ({}, "arguments were not a JSON object")


def test_openai_compatible_model_turn() -> None:
    message = SimpleNamespace(
        content=None,
        tool_calls=[
            SimpleNamespace(id="x1", function=SimpleNamespace(name="tickets__get", arguments='{"id":"T-1"}')),
            SimpleNamespace(id="x2", function=SimpleNamespace(name="tickets__get", arguments="{oops")),
            SimpleNamespace(id="x3", custom=SimpleNamespace()),
        ],
    )
    rec = Recorder(SimpleNamespace(choices=[SimpleNamespace(message=message)]))
    model = OpenAICompatibleModel(
        "llama3.2:3b", client=SimpleNamespace(chat=SimpleNamespace(completions=rec))
    )
    turn = asyncio.run(model.turn("sys", HISTORY, TOOLS))
    assert turn.text == ""
    assert [(c.id, c.arguments, c.error) for c in turn.tool_calls] == [
        ("x1", {"id": "T-1"}, None),
        ("x2", {}, "arguments were not valid JSON"),
        ("x3", {}, "unsupported tool call type"),
    ]
    assert rec.kwargs["tools"][0]["function"]["parameters"] == TOOLS[0].schema


def test_script_model_replays_calls() -> None:
    model = ScriptModel([("tickets.get", {"id": "T-1"}), ("payments.refund", {"amount": 60})])
    first = asyncio.run(model.turn("", [], []))
    second = asyncio.run(model.turn("", [], []))
    third = asyncio.run(model.turn("", [], []))
    assert [c.name for c in first.tool_calls + second.tool_calls] == ["tickets__get", "payments__refund"]
    assert third.tool_calls == [] and third.text
