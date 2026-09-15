import asyncio
import json
from collections.abc import Sequence
from pathlib import Path
from typing import Any

import pytest

from warden_agent.loop import CallOutcome, ToolInfo, Transcript, classify, run
from warden_agent.models import Message, ToolCall, ToolResult, ToolSpec, Turn, model_name


class FakeBackend:
    def __init__(self, answers: dict[str, CallOutcome]) -> None:
        self.answers = answers
        self.calls: list[tuple[str, dict[str, Any]]] = []

    async def list_tools(self) -> list[ToolInfo]:
        return [ToolInfo(n, f"{n} tool", {"type": "object"}) for n in self.answers]

    async def call(self, name: str, arguments: dict[str, Any]) -> CallOutcome:
        self.calls.append((name, arguments))
        return self.answers[name]


class FakeModel:
    adapter = "fake"
    model = "fake-1"

    def __init__(self, turns: list[Turn]) -> None:
        self.turns = turns
        self.seen: list[list[Message]] = []
        self.tools: Sequence[ToolSpec] = ()

    async def turn(self, system: str, history: Sequence[Message], tools: Sequence[ToolSpec]) -> Turn:
        self.seen.append(list(history))
        self.tools = tools
        return self.turns.pop(0)


def test_model_name() -> None:
    assert model_name("crm.lookup") == "crm__lookup"
    with pytest.raises(ValueError):
        model_name("bad name")
    with pytest.raises(ValueError):
        model_name("x" * 65)


def test_classify_warden_answers() -> None:
    assert classify('{"ok":true}', False) == "ok"
    assert classify('Denied by Warden (rule "no_web_with_pii"). Decision receipt #3.', True) == "denied"
    assert (
        classify('This call needs human approval (rule "x"). Decision receipt #4.', True)
        == "pending_approval"
    )
    assert classify("Warden refused the call: its receipt could not be recorded.", True) == "refused"
    assert (
        classify("Tool error: tool server error. Decision receipt #1, result receipt #2.", True)
        == "tool_error"
    )
    assert classify("something else", True) == "error"


def test_run_routes_calls_and_feeds_answers_back(tmp_path: Path) -> None:
    backend = FakeBackend(
        {
            "crm.lookup": CallOutcome('{"customer":"c-100"}', False),
            "mail.send": CallOutcome(
                'Denied by Warden (rule "no_pii_outside_tenant"). Decision receipt #3.', True
            ),
        }
    )
    model = FakeModel(
        [
            Turn("Looking up.", [ToolCall("1", "crm__lookup", {"id": "c-100"})]),
            Turn("", [ToolCall("2", "mail__send", {"to": "x@evil.example"}), ToolCall("3", "nope", {})]),
            Turn("Done."),
        ]
    )
    path = tmp_path / "t.jsonl"
    with Transcript(path) as log:
        result = asyncio.run(run(model, backend, "do it", transcript=log))

    assert backend.calls == [("crm.lookup", {"id": "c-100"}), ("mail.send", {"to": "x@evil.example"})]
    assert [t.name for t in model.tools] == ["crm__lookup", "mail__send"]
    assert [(c.tool, c.outcome) for c in result.calls] == [
        ("crm.lookup", "ok"),
        ("mail.send", "denied"),
        ("nope", "invalid_call"),
    ]
    assert (result.stop_reason, result.final_text, result.turns) == ("done", "Done.", 3)
    # The model's third turn saw both answers, with Warden's refusal marked as an error.
    answers = model.seen[2][-1]
    assert isinstance(answers, list)
    assert [(a.call_id, a.is_error) for a in answers if isinstance(a, ToolResult)] == [
        ("2", True),
        ("3", True),
    ]

    events = [json.loads(line)["event"] for line in path.read_text().splitlines()]
    assert events == [
        "start",
        "assistant",
        "tool_call",
        "assistant",
        "tool_call",
        "tool_call",
        "assistant",
        "end",
    ]


def test_run_stops_at_max_steps() -> None:
    backend = FakeBackend({"web.fetch": CallOutcome("page", False)})
    model = FakeModel([Turn("", [ToolCall(str(i), "web__fetch", {"url": "u"})]) for i in range(5)])
    result = asyncio.run(run(model, backend, "loop", max_steps=3))
    assert (result.stop_reason, result.turns, len(backend.calls)) == ("max_steps", 3, 3)


def test_run_records_model_errors() -> None:
    class Broken(FakeModel):
        async def turn(self, system: str, history: Sequence[Message], tools: Sequence[ToolSpec]) -> Turn:
            raise RuntimeError("endpoint down")

    result = asyncio.run(run(Broken([]), FakeBackend({}), "x"))
    assert result.stop_reason == "model_error"


def test_unparseable_arguments_are_not_sent() -> None:
    backend = FakeBackend({"crm.lookup": CallOutcome("{}", False)})
    model = FakeModel(
        [Turn("", [ToolCall("1", "crm__lookup", {}, "arguments were not valid JSON")]), Turn("ok")]
    )
    result = asyncio.run(run(model, backend, "x"))
    assert backend.calls == []
    assert result.calls[0].outcome == "invalid_call"


def test_transcript_never_overwrites(tmp_path: Path) -> None:
    path = tmp_path / "t.jsonl"
    path.write_text("keep")
    with pytest.raises(FileExistsError):
        Transcript(path)
    assert path.read_text() == "keep"


def test_colliding_tool_names_are_refused() -> None:
    backend = FakeBackend({"a.b": CallOutcome("", False), "a__b": CallOutcome("", False)})
    with pytest.raises(ValueError):
        asyncio.run(run(FakeModel([]), backend, "x"))
