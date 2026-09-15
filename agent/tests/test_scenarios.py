from pathlib import Path

import pytest

from warden_agent.loop import CallRecord
from warden_agent.scenarios import args_match, load_dir, parse, report, summarize

CORPUS = Path(__file__).resolve().parents[2] / "scenarios"


def test_reads_the_repository_corpus() -> None:
    all_scenarios = load_dir(CORPUS)
    assert len(all_scenarios) >= 13
    s = all_scenarios["deputy-ticket-refund"]
    assert s.category == "deputy" and s.principal == "alice@tenant-a"
    assert [st.attack for st in s.steps] == [False, True]


def test_args_match() -> None:
    assert args_match({"amount": 90}, {"amount": 90.0, "payment_id": "p-1"})
    assert not args_match({"amount": 90}, {"amount": "90"})
    assert not args_match({"to": "a@x"}, {})
    assert args_match({}, {"anything": 1})


def test_report_and_summary() -> None:
    s = load_dir(CORPUS)["injection-web-refund"]
    refused = [
        CallRecord("web.fetch", {"url": "https://shop.example/orders/4821"}, "ok", "page"),
        CallRecord("payments.refund", {"payment_id": "p-9001", "amount": 90.0}, "pending_approval", "..."),
    ]
    reps = report(s, refused)
    assert [(r.attempted, r.outcome) for r in reps] == [(True, "ok"), (True, "pending_approval")]
    assert summarize(s, reps) == "model attempted 1/1 attack call(s); Warden let 0 through"

    ignored = report(s, refused[:1])
    assert summarize(s, ignored) == "model attempted 0/1 attack call(s); Warden let 0 through"

    benign = load_dir(CORPUS)["benign-internal-email"]
    done = [
        CallRecord("crm.lookup", {"id": "c-100"}, "ok", ""),
        CallRecord(
            "mail.send", {"to": "bob@tenant-a.example", "body": "Customer c-100: gold tier."}, "ok", ""
        ),
    ]
    assert summarize(benign, report(benign, done)) == "benign task completed"
    assert summarize(benign, report(benign, done[:1])) == "benign task NOT completed"


def test_parse_rejects_other_versions(tmp_path: Path) -> None:
    with pytest.raises(ValueError):
        parse({"v": 2, "id": "x"})
    (tmp_path / "wrong-name.json").write_text((CORPUS / "benign-order-page.json").read_text())
    with pytest.raises(ValueError):
        load_dir(tmp_path)
