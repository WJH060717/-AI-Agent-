import json


def test_benchmark_input_fragments_have_stable_distinct_source_records():
    from scripts.benchmark_d11 import records

    first = records(0, 3)
    assert first == records(0, 3)
    rows = [json.loads(line) for line in (first + records(3, 2)).splitlines()]
    assert len({r["uid"] for r in rows}) == 5
    assert all(r["synthetic"] and r["id.resp_h"] == "10.10.0.20" for r in rows)


def test_benchmark_does_not_label_smoke_or_missing_records_as_full_acceptance():
    from scripts.benchmark_d11 import summarize

    samples = [
        {
            "kind": "batch",
            "phase": "ingest",
            "expected": 500,
            "status": "partial",
            "accepted": 499,
            "duplicate": 0,
            "quarantined": 1,
            "raw_records": 500,
            "error_code": "RULE_SCOPE_TOO_LARGE",
        },
        {"kind": "query", "status": 200, "elapsed_ms": 10},
        {"kind": "query", "status": 500, "elapsed_ms": 100},
    ]
    result = summarize(
        samples, profile="smoke", final_count=499, drain_seconds=1, duration_seconds=1
    )
    assert result["record_accounting"]["numerator"] == 500
    assert result["record_accounting"]["denominator"] == 500
    assert result["query_failures"] == 1 and result["query_p95_ms"] == 100
    assert result["full_protocol_passed"] is False
    assert result["detection_coverage"] == "partial"
    missing = summarize(
        samples[:-2], profile="full", final_count=499, drain_seconds=1, duration_seconds=1800
    )
    assert missing["full_protocol_passed"] is False
    assert missing["query_p95_ms"] is None


def test_benchmark_configuration_ignores_inherited_model_and_work_limits(tmp_path, monkeypatch):
    from scripts.benchmark_d11 import BENCHMARK_CONFIG, benchmark_settings, process_environment

    monkeypatch.setenv("DETECTION_EVENT_LIMIT", "1")
    monkeypatch.setenv("IMPORT_CHUNK_LINES", "1")
    monkeypatch.setenv("MODEL_PROVIDER", "compatible")
    monkeypatch.setenv("MODEL_API_KEY", "test-do-not-inherit")
    settings = benchmark_settings(tmp_path)
    assert settings.detection_event_limit == 10000 and settings.import_chunk_lines == 500
    assert settings.model_provider == "disabled" and settings.model_api_key is None
    env = process_environment(settings, 12345)
    assert env["DETECTION_EVENT_LIMIT"] == "10000"
    assert env["IMPORT_CHUNK_LINES"] == "500" and "MODEL_API_KEY" not in env
    assert env["WORKER_LEASE_SECONDS"] == str(BENCHMARK_CONFIG["worker_lease_seconds"])
