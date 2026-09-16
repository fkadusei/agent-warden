"""warden-agent: run a task or a scenario through Warden with any model."""

from __future__ import annotations

import argparse
import asyncio
import os
import sys
from contextlib import AbstractAsyncContextManager
from pathlib import Path

from . import scenarios as sc
from .direct import connect_direct
from .factory import make_model
from .loop import SYSTEM_PROMPT, RunResult, ToolBackend, Transcript, run
from .models import Model
from .warden import connect


def _parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(prog="warden-agent", description=__doc__)
    sub = p.add_subparsers(dest="command", required=True)

    def connection(sp: argparse.ArgumentParser) -> None:
        sp.add_argument("--url", default="https://127.0.0.1:8443", help="Warden's agent endpoint")
        sp.add_argument("--ca", default="warden-local/pki/ca.pem", help="Warden root certificate")
        sp.add_argument("--cert", default="warden-local/agent.pem", help="task credential")
        sp.add_argument("--key", default="warden-local/agent.key", help="task credential private key")

    r = sub.add_parser("run", help="run a task or a scenario's task")
    what = r.add_mutually_exclusive_group(required=True)
    what.add_argument("--task", help="the task to give the agent")
    what.add_argument("--scenario", help="use this scenario's task and report on its attack calls")
    r.add_argument("--scenarios-dir", default="scenarios", type=Path)
    r.add_argument(
        "--adapter",
        required=True,
        choices=["anthropic", "openai-compatible", "script"],
        help="script replays the scenario's calls without a model",
    )
    r.add_argument("--model", help="model name, e.g. a Claude model ID or llama3.2:3b")
    r.add_argument("--base-url", help="OpenAI-compatible endpoint, e.g. http://127.0.0.1:11434/v1 for Ollama")
    r.add_argument(
        "--api-key-env",
        default="OPENAI_API_KEY",
        help="environment variable holding the OpenAI-compatible key (keys are never taken as flags)",
    )
    r.add_argument("--max-steps", type=int, default=12)
    r.add_argument("--transcript", type=Path, help="write a JSON Lines transcript here (must not exist)")
    r.add_argument(
        "--check",
        action="store_true",
        help="with --scenario, exit 3 if Warden answered any scenario call differently than expected",
    )
    r.add_argument(
        "--direct",
        action="store_true",
        help="benchmark baseline: call the tool servers directly, holding their credentials, with no Warden",
    )
    r.add_argument(
        "--tools-url", default="http://127.0.0.1:9100", help="with --direct: tool servers base URL"
    )
    r.add_argument(
        "--servers", default="crm,payments,web,mail,tickets,hr", help="with --direct: server names"
    )
    r.add_argument(
        "--payments-token-env",
        default="EXAMPLE_PAYMENTS_TOKEN",
        help="with --direct: environment variable holding the payments token the agent itself sends",
    )
    connection(r)

    t = sub.add_parser("tools", help="list the tools Warden exposes to this credential")
    connection(t)

    s = sub.add_parser("scenarios", help="list the scenarios")
    s.add_argument("--scenarios-dir", default="scenarios", type=Path)
    return p


def _model(args: argparse.Namespace, scenario: sc.Scenario | None) -> Model:
    if args.adapter == "script" and scenario is None:
        raise SystemExit("--adapter script needs --scenario")
    script = [(st.call, st.args) for st in scenario.steps] if scenario else None
    try:
        return make_model(
            args.adapter,
            model=args.model,
            base_url=args.base_url,
            api_key_env=args.api_key_env,
            script=script,
        )
    except ValueError as exc:
        raise SystemExit(str(exc)) from exc


def _print_run(result: RunResult) -> None:
    for c in result.calls:
        print(f"  {c.tool} {c.arguments} -> {c.outcome}")
    print(f"stopped: {result.stop_reason} after {result.turns} turn(s)")
    if result.final_text:
        print(f"agent: {result.final_text.strip()}")


def _backend(args: argparse.Namespace) -> AbstractAsyncContextManager[ToolBackend]:
    if not args.direct:
        return connect(args.url, args.ca, args.cert, args.key)
    token = os.environ.get(args.payments_token_env)
    if not token:
        raise SystemExit(
            f"set {args.payments_token_env}: in the baseline the agent holds the tool credential itself"
        )
    servers = [s for s in args.servers.split(",") if s]
    return connect_direct(args.tools_url, servers, {"payments": {"Authorization": f"Bearer {token}"}})


async def _run(args: argparse.Namespace) -> int:
    if args.direct and args.check:
        raise SystemExit("--check compares Warden's answers; it does not apply to --direct")
    scenario = None
    if args.scenario:
        scenario = sc.load_dir(args.scenarios_dir).get(args.scenario)
        if scenario is None:
            raise SystemExit(f"no scenario {args.scenario!r} in {args.scenarios_dir}")
    model = _model(args, scenario)
    task = scenario.task if scenario else args.task
    mode = "direct (no Warden)" if args.direct else "through Warden"
    print(f"{model.adapter} / {model.model}, {mode}: {task}")
    with Transcript(args.transcript) as log:
        log.write("backend", mode="direct" if args.direct else "warden")
        async with _backend(args) as tools:
            result = await run(
                model, tools, task, system=SYSTEM_PROMPT, max_steps=args.max_steps, transcript=log
            )
    _print_run(result)
    if scenario:
        reports = sc.report(scenario, result.calls)
        for rep in reports:
            mark = "!" if rep.step.attack else " "
            seen = rep.outcome if rep.attempted else "not attempted"
            print(f"  {mark} scenario step {rep.step.call}: {seen} (with Warden: {rep.step.expect})")
        if args.direct and scenario.category != "benign":
            attacks = [r for r in reports if r.step.attack]
            tried = [r for r in attacks if r.attempted]
            succeeded = [r for r in tried if r.outcome == "ok"]
            print(
                f"{scenario.id}: no Warden; model attempted {len(tried)}/{len(attacks)} attack call(s), "
                f"{len(succeeded)} succeeded"
            )
        else:
            print(f"{scenario.id}: {sc.summarize(scenario, reports)}")
        if args.check:
            problems = sc.check(reports, require_all=model.adapter == "script")
            for p in problems:
                print(f"CHECK FAILED: {p}")
            if problems:
                return 3
    return 1 if result.stop_reason == "model_error" else 0


async def _tools(args: argparse.Namespace) -> int:
    async with connect(args.url, args.ca, args.cert, args.key) as tools:
        for info in await tools.list_tools():
            print(f"{info.name}: {info.description}")
    return 0


def main(argv: list[str] | None = None) -> int:
    args = _parser().parse_args(argv)
    if args.command == "scenarios":
        for s in sc.load_dir(args.scenarios_dir).values():
            print(f"{s.id:30} {s.category:9} {s.threat or '-':3} {s.title}")
        return 0
    try:
        return asyncio.run(_run(args) if args.command == "run" else _tools(args))
    except FileExistsError as exc:
        print(f"warden-agent: {exc.filename} already exists", file=sys.stderr)
        return 2


if __name__ == "__main__":
    sys.exit(main())
