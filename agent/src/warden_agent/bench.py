"""The Phase 4 benchmark: the same scenarios, model, and tools, with and without Warden.

Reports attack success, benign completion, added latency, and receipt bytes per call.
Model runs are measurements, never a pass/fail gate: results name the adapter, model,
and repetitions, and a model that barely uses its tools is visible in the numbers.
"""

from __future__ import annotations

import argparse
import asyncio
import json
import subprocess
import sys
import tempfile
from contextlib import AbstractAsyncContextManager
from dataclasses import asdict, dataclass, field
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from . import scenarios as sc
from .deployment import ToolServers, Warden, build, new_token
from .direct import connect_direct
from .factory import ADAPTERS, make_model
from .loop import SYSTEM_PROMPT, ToolBackend, Transcript, run
from .warden import connect

MODES = ("warden", "direct")


@dataclass
class RunRecord:
    mode: str
    scenario: str
    category: str
    repetition: int
    attacks: int
    attacks_attempted: int
    attacks_succeeded: int
    benign_completed: bool | None
    calls: int
    latencies_ms: list[float] = field(default_factory=list)
    stop_reason: str = ""
    turns: int = 0
    # With Warden: scenario expectations Warden did not meet (should stay empty).
    check_problems: list[str] = field(default_factory=list)


@dataclass
class ModeSummary:
    mode: str
    runs: int
    attacks: int
    attacks_attempted: int
    attacks_succeeded: int
    benign_total: int
    benign_completed: int
    calls: int
    latency_p50_ms: float
    latency_p99_ms: float
    receipt_bytes_per_call: float | None = None
    log_verified: bool | None = None
    check_problems: int = 0

    @property
    def attack_success_rate(self) -> float:
        return self.attacks_succeeded / self.attacks if self.attacks else 0.0

    @property
    def benign_completion_rate(self) -> float:
        return self.benign_completed / self.benign_total if self.benign_total else 0.0


def percentile(values: list[float], q: float) -> float:
    """Nearest-rank percentile; 0 for no samples."""
    if not values:
        return 0.0
    ordered = sorted(values)
    rank = max(1, min(len(ordered), int(-(-q * len(ordered) // 1))))
    return round(ordered[rank - 1], 2)


def summarize(mode: str, records: list[RunRecord]) -> ModeSummary:
    mine = [r for r in records if r.mode == mode]
    latencies = [ms for r in mine for ms in r.latencies_ms]
    benign = [r for r in mine if r.category == "benign"]
    return ModeSummary(
        mode=mode,
        runs=len(mine),
        attacks=sum(r.attacks for r in mine),
        attacks_attempted=sum(r.attacks_attempted for r in mine),
        attacks_succeeded=sum(r.attacks_succeeded for r in mine),
        benign_total=len(benign),
        benign_completed=sum(1 for r in benign if r.benign_completed),
        calls=sum(r.calls for r in mine),
        latency_p50_ms=percentile(latencies, 0.50),
        latency_p99_ms=percentile(latencies, 0.99),
        check_problems=sum(len(r.check_problems) for r in mine),
    )


def markdown(summaries: list[ModeSummary], meta: dict[str, Any]) -> str:
    lines = [
        "# Benchmark: with and without Warden",
        "",
        f"- **Model:** {meta['adapter']} / {meta['model']}",
        "- **Scenarios:** "
        f"{meta['scenarios']} ({meta['attack_scenarios']} attack, {meta['benign_scenarios']} benign)",
        f"- **Repetitions:** {meta['repetitions']}",
        f"- **Date (UTC):** {meta['date']}",
        f"- **Warden commit:** {meta['commit']}",
        "",
        "| | Attack success | Benign completed | Attack calls attempted | Calls | Latency p50 | p99 "
        "| Receipt bytes/call | Log verified |",
        "|---|---|---|---|---|---|---|---|---|",
    ]
    for s in summaries:
        name = "Without Warden" if s.mode == "direct" else "With Warden"
        bytes_per_call = "-" if s.receipt_bytes_per_call is None else f"{s.receipt_bytes_per_call:.0f}"
        verified = "-" if s.log_verified is None else ("yes" if s.log_verified else "NO")
        lines.append(
            f"| **{name}** | {s.attacks_succeeded}/{s.attacks} ({s.attack_success_rate:.0%}) | "
            f"{s.benign_completed}/{s.benign_total} ({s.benign_completion_rate:.0%}) | "
            f"{s.attacks_attempted}/{s.attacks} | {s.calls} | "
            f"{s.latency_p50_ms} ms | {s.latency_p99_ms} ms | "
            f"{bytes_per_call} | {verified} |"
        )
    lines += [
        "",
        "Attack success counts attack calls the agent made that reached the tool and succeeded.",
        "Attack calls attempted shows how often the model took the bait at all: a model that",
        "rarely calls tools scores a low attack success rate without Warden doing anything.",
    ]
    warden = next((s for s in summaries if s.mode == "warden"), None)
    if warden and warden.check_problems:
        lines.append(f"\n**{warden.check_problems} scenario expectation(s) were not met with Warden.**")
    return "\n".join(lines) + "\n"


async def _run_scenario(
    scenario: sc.Scenario,
    mode: str,
    repetition: int,
    backend_cm: Any,
    model: Any,
    transcript: Path,
    max_steps: int,
) -> RunRecord:
    with Transcript(transcript) as log:
        log.write("backend", mode=mode, repetition=repetition, scenario=scenario.id)
        async with backend_cm as tools:
            result = await run(
                model, tools, scenario.task, system=SYSTEM_PROMPT, max_steps=max_steps, transcript=log
            )
    reports = sc.report(scenario, result.calls)
    attacks = [r for r in reports if r.step.attack]
    attempted = [r for r in attacks if r.attempted]
    return RunRecord(
        mode=mode,
        scenario=scenario.id,
        category=scenario.category,
        repetition=repetition,
        attacks=len(attacks),
        attacks_attempted=len(attempted),
        attacks_succeeded=sum(1 for r in attempted if r.outcome == "ok"),
        benign_completed=(
            all(r.attempted and r.outcome == "ok" for r in reports) if scenario.category == "benign" else None
        ),
        calls=len(result.calls),
        latencies_ms=[round(c.duration_ms, 3) for c in result.calls if c.duration_ms > 0],
        stop_reason=result.stop_reason,
        turns=result.turns,
        check_problems=sc.check(reports, require_all=False) if mode == "warden" else [],
    )


def _model_for(args: argparse.Namespace, scenario: sc.Scenario) -> Any:
    return make_model(
        args.adapter,
        model=args.model,
        base_url=args.base_url,
        api_key_env=args.api_key_env,
        script=[(st.call, st.args) for st in scenario.steps],
    )


def run_mode(
    mode: str,
    scenarios: list[sc.Scenario],
    args: argparse.Namespace,
    work: Path,
    out_dir: Path,
    binaries: dict[str, Path],
) -> tuple[list[RunRecord], ModeSummary]:
    token = new_token()
    tools = ToolServers(binaries["example-tools"], token, work / "tools.log")
    records: list[RunRecord] = []
    warden: Warden | None = None

    # One event loop for the whole mode. A loop per scenario tore itself down while
    # httpx's aclose() was still pending, which printed "Event loop is closed" after
    # every run.
    async def scenarios_in_order() -> None:
        for repetition in range(1, args.repeat + 1):
            for scenario in scenarios:
                tools.restart(scenario.id)
                print(f"  [{mode} {repetition}/{args.repeat}] {scenario.id}", flush=True)
                transcript = out_dir / "transcripts" / mode / f"{scenario.id}-{repetition}.jsonl"
                transcript.parent.mkdir(parents=True, exist_ok=True)
                backend: AbstractAsyncContextManager[ToolBackend]
                if mode == "warden":
                    assert warden is not None
                    cred = warden.issue_task(scenario.principal, f"{scenario.id}-{repetition}")
                    backend = connect(warden.url, str(warden.ca), str(cred.cert), str(cred.key))
                else:
                    backend = connect_direct(
                        tools.url, args.servers.split(","), {"payments": {"Authorization": f"Bearer {token}"}}
                    )
                records.append(
                    await _run_scenario(
                        scenario,
                        mode,
                        repetition,
                        backend,
                        _model_for(args, scenario),
                        transcript,
                        args.max_steps,
                    )
                )

    try:
        tools.restart(scenarios[0].id)
        if mode == "warden":
            warden = Warden(binaries, work, tools.url, token)
            warden.pin()
            warden.start()
        asyncio.run(scenarios_in_order())
    finally:
        tools.stop()
    summary = summarize(mode, records)
    if warden is not None:
        evidence = warden.stop_and_export(out_dir / "evidence")
        summary.log_verified = evidence.verified
        summary.receipt_bytes_per_call = evidence.receipt_bytes / summary.calls if summary.calls else None
    return records, summary


def _commit(repo: Path) -> str:
    done = subprocess.run(["git", "rev-parse", "--short", "HEAD"], cwd=repo, capture_output=True, text=True)
    return done.stdout.strip() or "unknown"


def main(argv: list[str] | None = None) -> int:
    p = argparse.ArgumentParser(prog="warden-bench", description=__doc__)
    p.add_argument("--adapter", required=True, choices=list(ADAPTERS))
    p.add_argument("--model", help="model name; not needed for the script adapter")
    p.add_argument("--base-url", help="OpenAI-compatible endpoint, e.g. http://127.0.0.1:11434/v1 for Ollama")
    p.add_argument("--api-key-env", default="OPENAI_API_KEY")
    p.add_argument("--modes", default=",".join(MODES), help="comma-separated: warden, direct")
    p.add_argument("--repeat", type=int, default=1, help="repetitions per scenario (model runs vary)")
    p.add_argument("--scenarios-dir", type=Path, default=Path("scenarios"))
    p.add_argument("--only", help="comma-separated scenario IDs")
    p.add_argument("--servers", default="crm,payments,web,mail,tickets,hr")
    p.add_argument("--max-steps", type=int, default=12)
    p.add_argument("--out", type=Path, help="results directory (default: agent-runs/bench-<timestamp>)")
    p.add_argument("--repo", type=Path, default=Path(__file__).resolve().parents[3], help="repository root")
    args = p.parse_args(argv)

    modes = [m for m in args.modes.split(",") if m]
    for mode in modes:
        if mode not in MODES:
            p.error(f"unknown mode {mode!r}")
    if args.repeat < 1:
        p.error("--repeat must be at least 1")

    all_scenarios = sc.load_dir(args.scenarios_dir)
    chosen = list(all_scenarios.values())
    if args.only:
        wanted = [s for s in args.only.split(",") if s]
        missing = [s for s in wanted if s not in all_scenarios]
        if missing:
            p.error(f"no scenario(s): {', '.join(missing)}")
        chosen = [all_scenarios[s] for s in wanted]

    stamp = datetime.now(UTC).strftime("%Y%m%dT%H%M%SZ")
    out_dir = args.out or args.repo / "agent-runs" / f"bench-{stamp}"
    out_dir.mkdir(parents=True, exist_ok=True)

    records: list[RunRecord] = []
    summaries: list[ModeSummary] = []
    with tempfile.TemporaryDirectory(prefix="warden-bench.") as tmp:
        work = Path(tmp)
        print("building Warden...", flush=True)
        binaries = build(args.repo, work / "bin")
        for mode in modes:
            print(f"{mode} mode: {len(chosen)} scenarios x {args.repeat}", flush=True)
            mode_records, summary = run_mode(mode, chosen, args, work, out_dir, binaries)
            records += mode_records
            summaries.append(summary)

    meta = {
        "adapter": args.adapter,
        "model": args.model or "scripted",
        "scenarios": len(chosen),
        "attack_scenarios": sum(1 for s in chosen if s.category != "benign"),
        "benign_scenarios": sum(1 for s in chosen if s.category == "benign"),
        "repetitions": args.repeat,
        "date": stamp,
        "commit": _commit(args.repo),
    }
    (out_dir / "results.json").write_text(
        json.dumps(
            {"meta": meta, "summaries": [asdict(s) for s in summaries], "runs": [asdict(r) for r in records]},
            indent=2,
        ),
        encoding="utf-8",
    )
    table = markdown(summaries, meta)
    (out_dir / "summary.md").write_text(table, encoding="utf-8")
    print()
    print(table)
    print(f"results: {out_dir}")
    warden = next((s for s in summaries if s.mode == "warden"), None)
    if warden and (warden.check_problems or warden.log_verified is False):
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
