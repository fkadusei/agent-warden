import asyncio
from typing import Any

from mcp import types

from warden_agent.direct import DirectTools
from warden_agent.loop import run
from warden_agent.models import ScriptModel


class FakeSession:
    def __init__(self, tools: dict[str, str], pages: int = 1) -> None:
        self.tools = tools
        self.pages = pages
        self.calls: list[tuple[str, dict[str, Any] | None]] = []

    async def list_tools(
        self, *, params: types.PaginatedRequestParams | None = None
    ) -> types.ListToolsResult:
        names = sorted(self.tools)
        # Serve one tool per page when paginating, to exercise the cursor loop.
        if self.pages > 1:
            i = int(params.cursor) if params and params.cursor else 0
            nxt = str(i + 1) if i + 1 < len(names) else None
            names = names[i : i + 1]
        else:
            nxt = None
        return types.ListToolsResult(
            tools=[
                types.Tool(name=n, description=f"{n} tool", input_schema={"type": "object"}) for n in names
            ],
            next_cursor=nxt,
        )

    async def call_tool(self, name: str, arguments: dict[str, Any] | None = None) -> object:
        self.calls.append((name, arguments))
        return types.CallToolResult(
            content=[types.TextContent(type="text", text=self.tools[name])], is_error=False
        )


def test_direct_tools_names_and_routing() -> None:
    crm = FakeSession({"lookup": '{"customer":"c-100"}'})
    payments = FakeSession({"refund": '{"refunded":true}', "status": "{}"}, pages=2)
    tools = DirectTools({"crm": crm, "payments": payments})

    infos = asyncio.run(tools.list_tools())
    assert sorted(i.name for i in infos) == ["crm.lookup", "payments.refund", "payments.status"]

    out = asyncio.run(tools.call("payments.refund", {"payment_id": "p-1", "amount": 90}))
    assert (out.text, out.is_error) == ('{"refunded":true}', False)
    assert payments.calls == [("refund", {"payment_id": "p-1", "amount": 90})]
    assert crm.calls == []

    for bad in ("hr.salaries", "crm", ""):
        assert asyncio.run(tools.call(bad, {})).is_error


def test_baseline_run_records_success_and_latency() -> None:
    payments = FakeSession({"refund": '{"refunded":true}'})
    model = ScriptModel([("payments.refund", {"payment_id": "p-9001", "amount": 90})])
    result = asyncio.run(run(model, DirectTools({"payments": payments}), "refund"))
    assert [(c.tool, c.outcome) for c in result.calls] == [("payments.refund", "ok")]
    assert result.calls[0].duration_ms >= 0
