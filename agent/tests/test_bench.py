from warden_agent.bench import ModeSummary, RunRecord, markdown, percentile, summarize


def records() -> list[RunRecord]:
    return [
        RunRecord(
            "direct", "injection-web-refund", "injection", 1, 1, 1, 1, None, 2, [10.0, 30.0], "done", 2
        ),
        RunRecord("direct", "benign-internal-note", "benign", 1, 0, 0, 0, True, 1, [20.0], "done", 2),
        RunRecord(
            "warden", "injection-web-refund", "injection", 1, 1, 1, 0, None, 2, [15.0, 45.0], "done", 2
        ),
        RunRecord("warden", "benign-internal-note", "benign", 1, 0, 0, 0, True, 1, [25.0], "done", 2),
    ]


def test_percentile() -> None:
    assert percentile([], 0.5) == 0.0
    assert percentile([5.0], 0.99) == 5.0
    assert percentile([1.0, 2.0, 3.0, 4.0], 0.5) == 2.0
    assert percentile([1.0, 2.0, 3.0, 4.0], 0.99) == 4.0


def test_summarize_counts_attacks_and_benign() -> None:
    direct = summarize("direct", records())
    warden = summarize("warden", records())
    assert (direct.attacks, direct.attacks_attempted, direct.attacks_succeeded) == (1, 1, 1)
    assert direct.attack_success_rate == 1.0
    assert (warden.attacks_succeeded, warden.attack_success_rate) == (0, 0.0)
    assert (warden.benign_total, warden.benign_completed, warden.benign_completion_rate) == (1, 1, 1.0)
    assert (direct.calls, warden.calls) == (3, 3)
    assert warden.latency_p50_ms == 25.0


def test_markdown_reports_both_modes_and_context() -> None:
    warden = summarize("warden", records())
    warden.log_verified = True
    warden.receipt_bytes_per_call = 1234.5
    meta = {
        "adapter": "anthropic",
        "model": "some-model",
        "scenarios": 41,
        "attack_scenarios": 31,
        "benign_scenarios": 10,
        "repetitions": 3,
        "date": "20260915T000000Z",
        "commit": "abc1234",
    }
    table = markdown([summarize("direct", records()), warden], meta)
    assert "**Without Warden** | 1/1 (100%)" in table
    assert "**With Warden** | 0/1 (0%)" in table
    assert "1234 | yes" in table
    assert "some-model" in table and "Repetitions:** 3" in table
    # The caveat about models that never take the bait must always be printed.
    assert "rarely calls tools" in table


def test_markdown_flags_unmet_expectations() -> None:
    warden = ModeSummary("warden", 1, 1, 1, 0, 0, 0, 1, 1.0, 1.0, check_problems=2)
    meta = {
        "adapter": "script",
        "model": "scripted",
        "scenarios": 1,
        "attack_scenarios": 1,
        "benign_scenarios": 0,
        "repetitions": 1,
        "date": "d",
        "commit": "c",
    }
    assert "2 scenario expectation(s) were not met" in markdown([warden], meta)
