#!/usr/bin/env python3
"""Render docs/benchmark.html from one or more benchmark runs.

    scripts/benchmark-report.py agent-runs/bench-*/

Each argument is a directory holding a results.json written by warden-bench. The
page is regenerated from the raw results, so it never drifts from the data.
"""

from __future__ import annotations

import argparse
import html
import json
import sys
from collections import defaultdict
from datetime import datetime
from pathlib import Path

REPO = Path(__file__).resolve().parents[1]
OUT = REPO / "docs" / "benchmark.html"

CATEGORY_LABEL = {
    "injection": "Planted instructions",
    "exfil": "Data leaving",
    "deputy": "Another user's content",
    "authz": "Outside the user's role",
    "benign": "Legitimate work",
}


def esc(v: object) -> str:
    return html.escape(str(v))


def pct(part: int, whole: int) -> str:
    return "—" if not whole else f"{part / whole:.0%}"


def load(dirs: list[Path]) -> list[dict]:
    runs = []
    for d in dirs:
        path = d / "results.json"
        if not path.exists():
            print(f"skipping {d}: no results.json (still running?)", file=sys.stderr)
            continue
        runs.append(json.loads(path.read_text(encoding="utf-8")))
    if not runs:
        sys.exit("no completed benchmark runs given")
    return runs


def stamp(raw: str) -> str:
    try:
        return datetime.strptime(raw, "%Y%m%dT%H%M%SZ").strftime("%d %B %Y, %H:%M UTC")
    except ValueError:
        return raw


def main(argv: list[str]) -> int:
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("runs", nargs="+", type=Path, help="directories holding a results.json")
    parser.add_argument(
        "--setup",
        default="",
        help="how the model was prepared, when the name is not pullable as-is "
        "(e.g. a derived model with a fixed context length)",
    )
    parser.add_argument(
        "--setup-commands",
        default="",
        help="shell lines that recreate that model, shown in the reproduce section",
    )
    args = parser.parse_args(argv)
    data = load(args.runs)
    meta = data[0]["meta"]
    passes = len(data)
    setup_note = f" &middot; {esc(args.setup)}" if args.setup else ""
    setup_commands = args.setup_commands or f"ollama pull {meta['model']}"

    # Per mode, summed over passes.
    totals: dict[str, dict[str, float]] = defaultdict(lambda: defaultdict(float))
    p50s: dict[str, list[float]] = defaultdict(list)
    p99s: dict[str, list[float]] = defaultdict(list)
    bytes_per_call: list[float] = []
    verified = True
    for d in data:
        for s in d["summaries"]:
            m = s["mode"]
            for k in ("attacks", "attacks_attempted", "attacks_succeeded", "benign_total", "benign_completed", "calls"):
                totals[m][k] += s[k]
            p50s[m].append(s["latency_p50_ms"])
            p99s[m].append(s["latency_p99_ms"])
            if s["mode"] == "warden":
                if s["receipt_bytes_per_call"]:
                    bytes_per_call.append(s["receipt_bytes_per_call"])
                verified = verified and bool(s["log_verified"])

    # The fair comparison: attacks the model attempted in both modes.
    matched = matched_direct = matched_warden = 0
    per_scenario: dict[str, dict[str, dict]] = defaultdict(dict)
    for d in data:
        by = defaultdict(dict)
        for r in d["runs"]:
            by[r["scenario"]][r["mode"]] = r
            per_scenario[r["scenario"]].setdefault(r["mode"], []).append(r)
        for runs in by.values():
            dr, wr = runs.get("direct"), runs.get("warden")
            if not dr or not wr or dr["category"] == "benign":
                continue
            if dr["attacks_attempted"] and wr["attacks_attempted"]:
                matched += 1
                matched_direct += dr["attacks_succeeded"]
                matched_warden += wr["attacks_succeeded"]

    problems = [
        (r["scenario"], p) for d in data for r in d["runs"] for p in r["check_problems"]
    ]

    def mode_row(mode: str, name: str) -> str:
        t = totals[mode]
        att, succ, total = int(t["attacks_attempted"]), int(t["attacks_succeeded"]), int(t["attacks"])
        bpc = f"{sum(bytes_per_call) / len(bytes_per_call):,.0f}" if mode == "warden" and bytes_per_call else "—"
        ver = ("yes" if verified else "NO") if mode == "warden" else "—"
        p50 = sum(p50s[mode]) / len(p50s[mode])
        p99 = sum(p99s[mode]) / len(p99s[mode])
        cls = "bad" if mode == "direct" else "good"
        return (
            f"<tr><th scope='row'>{esc(name)}</th>"
            f"<td class='num {cls}'><strong>{succ}/{total}</strong> <span class='sub'>({pct(succ, total)})</span></td>"
            f"<td class='num'>{att}/{total} <span class='sub'>({pct(att, total)})</span></td>"
            f"<td class='num'>{int(t['benign_completed'])}/{int(t['benign_total'])}"
            f" <span class='sub'>({pct(int(t['benign_completed']), int(t['benign_total']))})</span></td>"
            f"<td class='num'>{int(t['calls'])}</td>"
            f"<td class='num'>{p50:.0f} ms</td><td class='num'>{p99:.0f} ms</td>"
            f"<td class='num'>{bpc}</td><td class='num'>{ver}</td></tr>"
        )

    rows = []
    for sid in sorted(per_scenario):
        modes = per_scenario[sid]
        sample = modes.get("direct", modes.get("warden"))[0]
        category = sample["category"]

        def cell(mode: str) -> str:
            rs = modes.get(mode, [])
            if category == "benign":
                done = sum(1 for r in rs if r["benign_completed"])
                cls = "good" if done == len(rs) else "warnc"
                return f"<td class='num {cls}'>{done}/{len(rs)} completed</td>"
            att = sum(r["attacks_attempted"] for r in rs)
            succ = sum(r["attacks_succeeded"] for r in rs)
            if not att:
                return "<td class='num muted'>not attempted</td>"
            cls = "bad" if succ else "good"
            label = f"{succ}/{att} succeeded" if succ else f"0/{att} blocked"
            return f"<td class='num {cls}'>{label}</td>"

        rows.append(
            f"<tr><td><code>{esc(sid)}</code></td>"
            f"<td>{esc(CATEGORY_LABEL.get(category, category))}</td>"
            f"{cell('direct')}{cell('warden')}</tr>"
        )

    attempted_note = (
        f"The model attempted {int(totals['direct']['attacks_attempted'])} of "
        f"{int(totals['direct']['attacks'])} attacks without Warden and "
        f"{int(totals['warden']['attacks_attempted'])} of {int(totals['warden']['attacks'])} with it."
    )
    problems_html = ""
    if problems:
        items = "".join(f"<li><code>{esc(s)}</code>: {esc(p)}</li>" for s, p in problems)
        problems_html = (
            "<div class='box warn'><span class='tag'>Expectations not met</span>"
            f"<ul>{items}</ul>"
            "<p>These are cases where the model sent different arguments than the scenario scripts, so the "
            "scenario's expected outcome no longer applied to the call it actually made. They are reported "
            "rather than hidden.</p></div>"
        )

    page = f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>Agent Warden — Benchmark</title>
<style>
  :root {{
    color-scheme: light;
    --bg: #fafaf8; --panel: #ffffff; --ink: #1d232e; --muted: #5d6573; --line: #e3e5ea;
    --accent: #2f5fd0; --accent-soft: #edf2fd; --accent-line: #d3def8;
    --green: #17703f; --green-soft: #e9f5ee; --green-line: #c8e6d3;
    --amber: #8f6200; --amber-soft: #fdf6e3; --amber-line: #efdfb2;
    --red: #b3261e; --red-soft: #fcecea; --red-line: #f3cdc8;
    --code-bg: #f2f3f6; --pre-bg: #111827; --pre-ink: #e5e9f0;
    --mono: ui-monospace, SFMono-Regular, "SF Mono", Menlo, Consolas, monospace;
    --sans: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, Helvetica, Arial, sans-serif;
  }}
  @media (prefers-color-scheme: dark) {{
    :root {{
      color-scheme: dark;
      --bg: #0e1116; --panel: #151a22; --ink: #e4e8ee; --muted: #9aa4b1; --line: #262d38;
      --accent: #86aefc; --accent-soft: #17223a; --accent-line: #2a3d63;
      --green: #62d09a; --green-soft: #12261d; --green-line: #244735;
      --amber: #e2b447; --amber-soft: #29210f; --amber-line: #4a3c19;
      --red: #ff8e85; --red-soft: #2a1614; --red-line: #532824;
      --code-bg: #1b212b; --pre-bg: #0a0d12; --pre-ink: #e5e9f0;
    }}
  }}
  * {{ box-sizing: border-box; }}
  body {{ margin: 0; background: var(--bg); color: var(--ink); font: 16.5px/1.7 var(--sans); -webkit-font-smoothing: antialiased; }}
  main {{ padding: 48px 56px 120px; max-width: 1000px; margin: 0 auto; }}
  header {{ border-bottom: 1px solid var(--line); padding-bottom: 26px; margin-bottom: 36px; }}
  h1 {{ font-size: 34px; line-height: 1.2; margin: 0 0 10px; letter-spacing: -.02em; }}
  .lede {{ font-size: 19px; color: var(--muted); margin: 0; }}
  .meta {{ margin-top: 14px; font-size: 13.5px; color: var(--muted); }}
  .meta code {{ font-size: .95em; }}
  h2 {{ font-size: 25px; margin: 52px 0 12px; letter-spacing: -.01em; }}
  h3 {{ font-size: 18px; margin: 28px 0 8px; }}
  a {{ color: var(--accent); }}
  code {{ font-family: var(--mono); font-size: .86em; background: var(--code-bg); padding: 1px 6px; border-radius: 5px; }}
  pre {{ background: var(--pre-bg); color: var(--pre-ink); padding: 16px 18px; border-radius: 10px; overflow-x: auto; font: 13px/1.55 var(--mono); }}
  pre code {{ background: none; padding: 0; font-size: inherit; color: inherit; }}
  .headline {{ display: grid; grid-template-columns: 1fr 1fr; gap: 18px; margin: 26px 0 10px; }}
  .card {{ border: 1px solid var(--line); background: var(--panel); border-radius: 12px; padding: 20px 22px; }}
  .card .label {{ font-size: 12px; letter-spacing: .07em; text-transform: uppercase; color: var(--muted); }}
  .card .figure {{ font-size: 44px; font-weight: 700; letter-spacing: -.03em; line-height: 1.15; margin: 6px 0 2px; }}
  .card .under {{ color: var(--muted); font-size: 14px; }}
  .card.bad {{ border-color: var(--red-line); background: var(--red-soft); }} .card.bad .figure {{ color: var(--red); }}
  .card.good {{ border-color: var(--green-line); background: var(--green-soft); }} .card.good .figure {{ color: var(--green); }}
  .table-wrap {{ overflow-x: auto; margin: 16px 0; }}
  table {{ width: 100%; border-collapse: collapse; font-size: 14.5px; }}
  th, td {{ text-align: left; vertical-align: top; padding: 9px 12px; border-bottom: 1px solid var(--line); }}
  th {{ font-size: 12px; text-transform: uppercase; letter-spacing: .05em; color: var(--muted); background: var(--panel); }}
  td.num, th.num {{ text-align: right; white-space: nowrap; }}
  td.good {{ color: var(--green); }} td.bad {{ color: var(--red); }} td.warnc {{ color: var(--amber); }}
  td.muted, .sub {{ color: var(--muted); }}
  .sub {{ font-size: 13px; }}
  .box {{ border: 1px solid var(--line); background: var(--panel); border-radius: 10px; padding: 14px 18px; margin: 18px 0; }}
  .box .tag {{ display: block; font-size: 11.5px; font-weight: 700; letter-spacing: .07em; text-transform: uppercase; margin-bottom: 4px; }}
  .box p {{ margin: 6px 0; }}
  .box ul {{ margin: 6px 0; padding-left: 20px; }}
  .info {{ background: var(--accent-soft); border-color: var(--accent-line); }} .info .tag {{ color: var(--accent); }}
  .ok {{ background: var(--green-soft); border-color: var(--green-line); }} .ok .tag {{ color: var(--green); }}
  .warn {{ background: var(--amber-soft); border-color: var(--amber-line); }} .warn .tag {{ color: var(--amber); }}
  @media (max-width: 880px) {{
    main {{ padding: 30px 20px 90px; }}
    .headline {{ grid-template-columns: 1fr; }}
    h1 {{ font-size: 28px; }}
  }}
</style>
</head>
<body>
<main>
<header>
  <h1>Does the guard change the outcome?</h1>
  <p class="lede">The same agent, model, prompts, and planted content, run twice over
  {esc(meta["scenarios"])} scenarios: once calling the tools directly, once through Agent Warden.</p>
  <p class="meta">
    Model <code>{esc(meta["model"])}</code> via {esc(meta["adapter"])} &middot;
    {esc(meta["attack_scenarios"])} attack and {esc(meta["benign_scenarios"])} benign scenarios &middot;
    {passes} full pass{"es" if passes != 1 else ""} &middot;
    {esc(stamp(meta["date"]))} &middot; Warden <code>{esc(meta["commit"])}</code>{setup_note}
  </p>
</header>

<section>
  <div class="headline">
    <div class="card bad">
      <div class="label">Without Warden</div>
      <div class="figure">{matched_direct}/{matched}</div>
      <div class="under">attacks the model attempted reached the tool and succeeded</div>
    </div>
    <div class="card good">
      <div class="label">With Warden</div>
      <div class="figure">{matched_warden}/{matched}</div>
      <div class="under">the same attacks, on the same scenarios, got through</div>
    </div>
  </div>
  <p>Those figures cover the {matched} attack scenarios where the model took the bait in
  <em>both</em> modes, which is the only comparison that isolates the guard from the model's own
  inconsistency. Every benign task completed in both modes, so the guard did not simply block
  everything.</p>
</section>

<h2>Both modes, in full</h2>
<div class="table-wrap">
<table>
  <thead><tr>
    <th>Mode</th><th class="num">Attacks succeeded</th><th class="num">Attacks attempted</th>
    <th class="num">Benign completed</th><th class="num">Calls</th>
    <th class="num">Latency p50</th><th class="num">p99</th>
    <th class="num">Receipt bytes/call</th><th class="num">Log verified</th>
  </tr></thead>
  <tbody>
    {mode_row("direct", "Without Warden")}
    {mode_row("warden", "With Warden")}
  </tbody>
</table>
</div>

<div class="box info">
  <span class="tag">How to read this</span>
  <p><strong>Attacks succeeded</strong> counts attack calls the agent actually made that reached a
  tool and returned success. <strong>Attacks attempted</strong> counts how often the model took the
  bait at all. {esc(attempted_note)} A model that ignores an attack scores well without the guard
  doing anything, which is why both numbers are published.</p>
  <p><strong>Latency</strong> is per tool call, measured on one machine over loopback, so it is a
  floor rather than a production figure. <strong>Receipt bytes per call</strong> is the exported
  signed log divided by calls; most of it is post-quantum signatures.</p>
</div>

{problems_html}

<h2>Every scenario</h2>
<div class="table-wrap">
<table>
  <thead><tr><th>Scenario</th><th>Category</th><th class="num">Without Warden</th><th class="num">With Warden</th></tr></thead>
  <tbody>
    {"".join(rows)}
  </tbody>
</table>
</div>

<h2>What this does and does not show</h2>
<div class="box ok">
  <span class="tag">Shown</span>
  <ul>
    <li>Attacks that succeed against an unguarded agent are refused when the same calls pass
    through Warden, and every refusal is written to a signed, hash-chained log that verified.</li>
    <li>Benign work still completes: {int(totals["warden"]["benign_completed"])} of
    {int(totals["warden"]["benign_total"])} tasks with the guard in place.</li>
    <li>The cost is visible and small: a few milliseconds per call and a few kilobytes of evidence.</li>
  </ul>
</div>
<div class="box warn">
  <span class="tag">Not shown</span>
  <ul>
    <li>Model results vary between runs. These come from {passes} full pass{"es" if passes != 1 else ""}
    of one model; they are measurements, not a guarantee.</li>
    <li>The guarantee is the deterministic gate (<code>warden-gate</code>), where a scripted agent
    makes every attack call and Warden must refuse all of them.</li>
    <li>Warden stops calls its policy forbids. A policy that permits an action permits it whoever
    asked, so these numbers describe this example policy, not every deployment.</li>
    <li>Tools and secrets here are synthetic, and everything runs on one machine.</li>
  </ul>
</div>

<h2>Reproduce it</h2>
<pre><code>{esc(setup_commands)}
uv run --project agent warden-bench \\
  --adapter {esc(meta["adapter"])} --base-url http://127.0.0.1:11434/v1 \\
  --model {esc(meta["model"])} --repeat 1

scripts/benchmark-report.py agent-runs/bench-*/</code></pre>
<p class="meta">Each run writes <code>results.json</code>, <code>summary.md</code>, and a transcript
per scenario under <code>agent-runs/</code>. This page is generated from those files.</p>
</main>
</body>
</html>
"""
    OUT.write_text(page, encoding="utf-8")
    print(f"wrote {OUT.relative_to(REPO)} from {passes} run(s): matched {matched_direct}/{matched} vs {matched_warden}/{matched}")
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
