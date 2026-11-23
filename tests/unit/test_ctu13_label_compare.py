"""Offline matching must not turn unknown/background flows into attack truth."""

import sqlite3

import pytest

from eval.ctu13_label_compare import (
    classify_candidate,
    create_schema,
    event_time_us,
    find_matches,
    label_kind,
    official_time_us,
)


@pytest.mark.parametrize(
    ("label", "expected"),
    [
        ("flow=From-Botnet-V48-TCP-CC77-HTTP-Not-Encrypted", "botnet"),
        ("flow=From-Normal-V48-Stribrek", "normal"),
        ("flow=Background-TCP-Established", "background"),
        ("flow=Background", "background"),
        ("flow=To-Background-Jist", "background"),
        ("flow=To-Botnet-V48-TCP", "unknown_direction"),
        ("flow=To-Normal-V48-Jist", "unknown_direction"),
        ("flow=Not-From-Botnet", "unknown_label"),
        ("flow=New-Unrecognized-Label", "unknown_label"),
    ],
)
def test_official_label_direction(label, expected):
    assert label_kind(label) == expected


def test_cest_conversion_preserves_microseconds():
    assert official_time_us("2011/08/16 13:51:24.057991") == 1313495484057991
    assert event_time_us("1313495484.057991") == 1313495484057991
    with pytest.raises(ValueError):
        official_time_us("2011/08/16 13:51:24")


@pytest.fixture
def database():
    db = sqlite3.connect(":memory:")
    db.row_factory = sqlite3.Row
    create_schema(db)
    yield db
    db.close()


def add_flow(
    db,
    line=2,
    start=1000000,
    src="192.0.2.1",
    sport=1234,
    dst="192.0.2.2",
    dport=80,
    label="flow=Background",
):
    db.execute(
        "INSERT INTO official_flows VALUES (?,?,?,?,?,?,?,?,?,?,?)",
        (
            line,
            start,
            "tcp",
            src,
            sport,
            dst,
            dport,
            "->",
            label,
            "original-time",
            "hash",
        ),
    )


def event(**overrides):
    return {
        "ts": 1,
        "proto": "tcp",
        "id.orig_h": "192.0.2.1",
        "id.orig_p": 1234,
        "id.resp_h": "192.0.2.2",
        "id.resp_p": 80,
        **overrides,
    }


def test_full_tuple_and_exact_time_not_ip_only(database):
    add_flow(database)
    assert find_matches(database, event())[0]["orientation"] == "same"
    assert find_matches(database, event(**{"id.orig_p": 1235})) == []
    assert find_matches(database, event(proto="udp")) == []
    assert find_matches(database, event(ts="1.000002")) == []


def test_one_microsecond_boundary(database):
    add_flow(database)
    assert len(find_matches(database, event(ts="1.000001"))) == 1


def test_reverse_bidirectional_record_keeps_original_label(database):
    add_flow(
        database,
        src="192.0.2.2",
        sport=80,
        dst="192.0.2.1",
        dport=1234,
        label="flow=To-Botnet-V48-TCP",
    )
    (match,) = find_matches(database, event())
    assert match["orientation"] == "reversed"
    assert match["label"] == "flow=To-Botnet-V48-TCP"
    assert label_kind(match["label"]) == "unknown_direction"


def test_conflicting_or_duplicate_matches_are_not_silently_chosen(database):
    add_flow(database, label="flow=From-Normal-X")
    add_flow(database, line=3, label="flow=From-Botnet-X")
    assert len(find_matches(database, event())) == 2
    assert classify_candidate([{"match_status": "ambiguous", "label_kind": None}]) == (
        "unknown_incomplete"
    )


def test_missing_port_cannot_match(database):
    add_flow(database, sport=None)
    assert find_matches(database, event()) == []


@pytest.mark.parametrize(
    ("kinds", "expected"),
    [
        (["normal", "normal"], "known_normal"),
        (["botnet", "botnet"], "botnet_supported"),
        (["background", "background"], "unknown_background"),
        (["background", "normal"], "unknown_background"),
        (["botnet", "normal"], "mixed_labels"),
        (["unknown_direction"], "unknown_label"),
        ([], "unknown_incomplete"),
    ],
)
def test_candidate_classification_keeps_unknown(kinds, expected):
    events = [{"match_status": "unique", "label_kind": kind} for kind in kinds]
    assert classify_candidate(events) == expected


def test_incomplete_or_reused_flow_cannot_prove_true_positive():
    evidence = [
        {"match_status": "unique", "label_kind": "botnet"},
        {"match_status": "unmatched", "label_kind": None},
    ]
    assert classify_candidate(evidence) == "unknown_incomplete"
    assert classify_candidate([{"match_status": "reused_flow", "label_kind": "normal"}]) == (
        "unknown_incomplete"
    )
