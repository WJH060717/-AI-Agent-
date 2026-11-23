import json

import httpx
import pytest


def test_replay_benchmark_prepares_more_than_one_source_fragment():
    from scripts.benchmark_p1_replay import source_records

    rows = [json.loads(line) for line in source_records(1201).splitlines()]
    assert len(rows) == len({r["uid"] for r in rows}) == 1201
    assert rows[-1]["ts"] > rows[0]["ts"]


def test_status_poll_records_transient_unavailability(monkeypatch):
    from scripts import benchmark_p1_replay as benchmark

    replies = [503, 200]
    monkeypatch.setattr(benchmark.time, "sleep", lambda _: None)
    samples = []
    with httpx.Client(
        transport=httpx.MockTransport(
            lambda request: httpx.Response(replies.pop(0), json={"state": "completed"})
        ),
        base_url="http://local",
    ) as client:
        assert (
            benchmark.poll_status(
                client, "/replays/job", benchmark.time.monotonic() + 2, samples.append
            )["state"]
            == "completed"
        )
    assert samples == [{"kind": "transient_poll_error", "path": "/replays/job", "status": 503}]


def test_status_poll_does_not_hide_other_errors_or_exceed_deadline():
    from scripts import benchmark_p1_replay as benchmark

    for status in [403, 500, 503]:
        with httpx.Client(
            transport=httpx.MockTransport(
                lambda request, code=status: httpx.Response(code, json={})
            ),
            base_url="http://local",
        ) as client:
            with pytest.raises(TimeoutError if status == 503 else httpx.HTTPStatusError):
                benchmark.poll_status(client, "/imports/batch", 0, lambda _: None)
