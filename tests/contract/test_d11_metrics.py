import pytest


def activity(key, start, end, asset="asset-a", observable=True):
    return {
        "id": key,
        "rule_id": "R02",
        "asset_id": asset,
        "start": f"2026-11-14T01:00:{start:02d}Z",
        "end": f"2026-11-14T01:00:{end:02d}Z",
        "observable": observable,
    }


def test_matching_is_maximum_one_to_one_not_greedy_or_duplicate_recall():
    from eval.metrics import detection_score

    truth = [activity("t1", 1, 5), activity("t2", 6, 10)]
    predictions = [activity("p1", 1, 10), activity("p2", 1, 5)]
    score = detection_score(predictions, truth)
    assert (score["tp"], score["fp"], score["fn"]) == (2, 0, 0)
    assert score["f1"] == 1
    score = detection_score(predictions + [activity("duplicate", 1, 5)], truth)
    assert (score["tp"], score["fp"], score["fn"]) == (2, 1, 0)
    assert score["recall"] == 1 and score["precision"] == pytest.approx(2 / 3)


def test_matching_requires_strong_asset_and_observable_time_overlap():
    from eval.metrics import detection_score

    score = detection_score([activity("p", 1, 5, None)], [activity("t", 1, 5)])
    assert (score["tp"], score["fp"], score["fn"]) == (0, 1, 1)
    score = detection_score([], [activity("hidden", 1, 5, observable=False)])
    assert score["unobservable_truth"] == 1 and score["fn"] == 0
    assert score["precision"] is None and score["recall"] is None and score["f1"] is None


def test_graph_projection_deduplicates_steps_and_keeps_unknown_edges_separate():
    from eval.metrics import graph_score

    truth = {
        "steps": [
            {"id": "a", "observable": True, "event_ids": ["e1", "e2"]},
            {"id": "b", "observable": True, "event_ids": ["e3"]},
            {"id": "hidden", "observable": False, "event_ids": []},
        ],
        "edges": [{"from_step": "a", "to_step": "b", "relation": "spawned", "observable": True}],
    }
    score = graph_score(
        [
            {"from_event_id": "e1", "to_event_id": "e3", "relation": "spawned"},
            {"from_event_id": "e2", "to_event_id": "e3", "relation": "spawned"},
            {"from_event_id": "unknown", "to_event_id": "e3", "relation": "spawned"},
        ],
        truth,
    )
    assert (score["tp"], score["fp"], score["fn"]) == (1, 0, 0)
    assert score["duplicate_projections"] == 1 and score["unknown_predictions"] == 1
    assert score["observable_steps"] == 2 and score["unobservable_steps"] == 1
    assert score["step_coverage"] == {"numerator": 2, "denominator": 2, "value": 1.0}


def test_ambiguous_truth_event_mapping_and_invalid_time_are_rejected():
    from eval.metrics import detection_score, graph_score

    with pytest.raises(ValueError):
        detection_score([activity("p", 10, 1)], [])
    with pytest.raises(ValueError):
        graph_score(
            [],
            {
                "steps": [
                    {"id": "a", "observable": True, "event_ids": ["same"]},
                    {"id": "b", "observable": True, "event_ids": ["same"]},
                ],
                "edges": [],
            },
        )


def test_zero_denominators_and_wilson_interval_are_not_fake_perfection():
    from eval.metrics import proportion

    assert proportion(0, 0) == {"numerator": 0, "denominator": 0, "value": None, "wilson95": None}
    score = proportion(0, 10)
    assert score["value"] == 0 and 0 <= score["wilson95"][0] < 0.001
    assert 0.27 < score["wilson95"][1] < 0.28
    with pytest.raises(ValueError):
        proportion(2, 1)


def test_missing_truth_and_failed_group_do_not_produce_f1_or_disappear():
    from eval.metrics import summarize_results

    records = [
        {
            "run_id": "engineering-s1",
            "group": "B0",
            "repeat": 0,
            "status": "completed",
            "elapsed_ms": 4,
        },
        {
            "run_id": "engineering-s1",
            "group": "B3",
            "repeat": 0,
            "status": "blocked",
            "elapsed_ms": 0,
            "error": "MODEL_DISABLED",
        },
    ]
    result = summarize_results(records)
    assert result["executions"] == 2 and result["statuses"] == {"completed": 1, "blocked": 1}
    assert result["formal_metrics_available"] is False
    assert result["groups"]["B0"]["detection_f1_macro"] is None
    assert result["groups"]["B3"]["failure_rate"]["numerator"] == 1


def test_unknown_origin_candidates_consume_rank_instead_of_promoting_fourth_candidate():
    from eval.metrics import summarize_results

    result = summarize_results(
        [
            {
                "run_id": "r",
                "group": "B1",
                "repeat": 0,
                "status": "completed",
                "elapsed_ms": 1,
                "origins": ["u1", "u2", "u3", "known"],
            }
        ],
        {
            "r": {
                "steps": [{"id": "a", "observable": True, "event_ids": ["known"]}],
                "edges": [],
                "activities": [],
                "observable_origins": ["a"],
            }
        },
    )
    assert result["groups"]["B1"]["origin_top1"]["numerator"] == 0
    assert result["groups"]["B1"]["origin_top3"]["numerator"] == 0


def test_macro_f1_groups_repeated_executions_by_run():
    from eval.metrics import summarize_results

    label = {"steps": [], "edges": [], "activities": [activity("t", 1, 5)]}
    rows = [
        {
            "run_id": "a",
            "group": "B0",
            "repeat": i,
            "status": "completed",
            "elapsed_ms": 1,
            "detections": [activity("p", 1, 5)],
        }
        for i in range(3)
    ]
    rows.append({"run_id": "b", "group": "B0", "repeat": 0, "status": "completed", "elapsed_ms": 1})
    result = summarize_results(rows, {"a": label, "b": label})
    assert result["groups"]["B0"]["detection_f1_macro"] == 0.5
    assert result["groups"]["B0"]["f1_interval"] is None
