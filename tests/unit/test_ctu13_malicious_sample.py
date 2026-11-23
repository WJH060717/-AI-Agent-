"""Label-selected sample must preserve observations and reject ambiguous mappings."""

import csv
import io
import json

import pytest

from eval.ctu13_malicious_sample import prepare, select_records
from scripts.ctu13_sample import sha


def bro(rows):
    fields = "ts\tuid\tid.orig_h\tid.orig_p\tid.resp_h\tid.resp_p\tproto"
    return ("#fields\t" + fields + "\n" + "\n".join(rows) + "\n").encode()


ROW = "1313495484.057991\tuid1\t192.0.2.1\t1234\t192.0.2.2\t80\ttcp"


def labels(items):
    out = io.StringIO(newline="")
    writer = csv.writer(out)
    writer.writerow(["StartTime", "Proto", "SrcAddr", "Sport", "DstAddr", "Dport", "Label"])
    for extra in items:
        values = [
            "2011/08/16 13:51:24.057991",
            "tcp",
            "192.0.2.1",
            "1234",
            "192.0.2.2",
            "80",
            "flow=From-Botnet-Test",
        ]
        for index, value in extra.items():
            values[index] = value
        writer.writerow(values)
    return out.getvalue().encode()


def test_from_botnet_only_with_raw_line_provenance():
    result = select_records(
        bro([ROW]), labels([{}, {6: "flow=To-Botnet-Test"}, {6: "flow=From-Normal-Test"}])
    )
    assert result["official_from_botnet"] == 1
    (match,) = result["matched"]
    assert match["source_line"] == 2 and match["official_line"] == 2
    assert match["uid"] == "uid1" and match["orientation"] == "same"
    assert result["unresolved"] == []


def test_reverse_keeps_original_official_label():
    result = select_records(
        bro([ROW]), labels([{2: "192.0.2.2", 3: "80", 4: "192.0.2.1", 5: "1234"}])
    )
    (match,) = result["matched"]
    assert match["orientation"] == "reversed"
    assert match["label"] == "flow=From-Botnet-Test"


def test_other_port_or_time_cannot_match_by_ip():
    result = select_records(bro([ROW]), labels([{3: "1235"}, {0: "2011/08/16 13:51:24.057993"}]))
    assert result["matched"] == [] and len(result["unresolved"]) == 2


def test_multiple_bro_rows_are_ambiguous():
    result = select_records(bro([ROW, ROW.replace("uid1", "uid2")]), labels([{}]))
    assert result["matched"] == []
    assert result["unresolved"][0]["reason"] == "ambiguous_bro_rows"


def test_multiple_labels_cannot_reuse_one_bro_record():
    result = select_records(bro([ROW]), labels([{}, {}]))
    assert result["matched"] == [] and len(result["unresolved"]) == 2
    assert {r["reason"] for r in result["unresolved"]} == {"reused_bro_row"}


def test_missing_official_port_is_explicit_unknown():
    result = select_records(bro([ROW]), labels([{3: ""}]))
    assert result["matched"] == []
    assert result["unresolved"][0]["reason"] == "unkeyable_official_flow"


def test_prepared_upload_has_no_labels_and_original_physical_mapping(tmp_path):
    header = (
        "#separator \\x09\n#path\tconn\n"
        "#fields\tts\tuid\tid.orig_h\tid.orig_p\tid.resp_h\tid.resp_p\tproto\n"
        "#types\ttime\tstring\taddr\tport\taddr\tport\tenum\n"
    )
    original = (
        header + ROW.replace("uid1", "excluded").replace("1234", "9999") + "\n" + ROW + "\n"
    ).encode()
    source = tmp_path / "source.log"
    source.write_bytes(original)
    truth = tmp_path / "labels.csv"
    truth.write_bytes(labels([{}]))
    output = tmp_path / "new-sample"
    result = prepare(source, truth, output)
    adapted = output / "adapted"
    record = json.loads((adapted / "conn.jsonl").read_text())
    mapping = json.loads((adapted / "line-map.jsonl").read_text())
    assert record["uid"] == "uid1" and not any("label" in key for key in record)
    assert mapping["source_line"] == 6 and mapping["output_line"] == 1
    assert (adapted / "source-sample.log").read_bytes() == original
    assert result["source_sha256"] == result["sample_sha256"] == sha(original)
    assert result["accepted_records"] == 1 and result["scanned_records"] == 2
    assert result["runtime_input_contains_labels"] is False
    assert result["labels_used_only_for_offline_selection"] is True
    with pytest.raises(FileExistsError):
        prepare(source, truth, output)
    assert (adapted / "conn.jsonl").read_bytes() == (
        output / "adapter-intermediate/conn.jsonl"
    ).read_bytes()
