"""warden-agent: run a task or a scenario through Warden with any model."""

from __future__ import annotations

import argparse
import asyncio
import os
import sys
from pathlib import Path

from . import scenarios as sc
from .loop import SYSTEM_PROMPT, RunResult, Transcript, run
from .models import AnthropicModel, Model, OpenAICompatibleModel, ScriptModel
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
    connection(r)

    t = sub.add_parser("tools", help="list the tools Warden exposes to this credential")
    connection(t)

    s = sub.add_parser("scenarios", help="list the scenarios")
    s.add_argument("--scenarios-dir", default="scenarios", type=Path)
    return p


def _model(args: argparse.Namespace, scenario: sc.Scenario | None) -> Model:
    if args.adapter == "script":
        if scenario is None:
            raise SystemExit("--adapter script needs --scenario")
        return ScriptModel([(st.call, st.args) for st in scenario.steps])
    if not args.model:
        raise SystemExit(f"--adapter {args.adapter} needs --model")
    if args.adapter == "anthropic":
        if not os.environ.get("ANTHROPIC_API_KEY"):
            raise SystemExit("set ANTHROPIC_API_KEY in the environment")
        return AnthropicModel(args.model)
    key = os.environ.get(args.api_key_env)
    if not key:
        if not args.base_url:
            raise SystemExit(
                f"set {args.api_key_env} in the environment, or give --base-url for a local endpoint"
            )
        key = "unused"  # local servers such as Ollama ignore the key
    return OpenAICompatibleModel(args.model, base_url=args.base_url, api_key=key)


def _print_run(result: RunResult) -> None:
    for c in result.calls:
        print(f"  {c.tool} {c.arguments} -> {c.outcome}")
    print(f"stopped: {result.stop_reason} after {result.turns} turn(s)")
    if result.final_text:
        print(f"agent: {result.final_text.strip()}")


async def _run(args: argparse.Namespace) -> int:
    scenario = None
    if args.scenario:
        scenario = sc.load_dir(args.scenarios_dir).get(args.scenario)
        if scenario is None:
            raise SystemExit(f"no scenario {args.scenario!r} in {args.scenarios_dir}")
    model = _model(args, scenario)
    task = scenario.task if scenario else args.task
    print(f"{model.adapter} / {model.model}: {task}")
    with Transcript(args.transcript) as log:
        async with connect(args.url, args.ca, args.cert, args.key) as tools:
            result = await run(
                model, tools, task, system=SYSTEM_PROMPT, max_steps=args.max_steps, transcript=log
            )
    _print_run(result)
    if scenario:
        reports = sc.report(scenario, result.calls)
        for rep in reports:
            mark = "!" if rep.step.attack else " "
            seen = rep.outcome if rep.attempted else "not attempted"
            print(f"  {mark} scenario step {rep.step.call}: {seen} (Warden must: {rep.step.expect})")
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
