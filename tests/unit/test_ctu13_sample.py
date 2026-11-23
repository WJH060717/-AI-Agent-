import hashlib
import json
from pathlib import Path

import pytest

from scripts.ctu13_sample import convert

HEADER = (
    b"#separator \\x09\n#set_separator\t,\n#empty_field\t(empty)\n#unset_field\t-\n"
    b"#path\tconn\n#fields\tts\tuid\tid.orig_h\tid.orig_p\tid.resp_h\tid.resp_p\tproto"
    b"\tduration\torig_bytes\tresp_bytes\tconn_state\n"
    b"#types\ttime\tstring\taddr\tport\taddr\tport\tenum\tinterval\tcount\tcount\tstring\n"
)
ROW = b"1313495486.546001\tC-test\t192.0.2.1\t50000\t198.51.100.2\t443\ttcp\t0.000157\t0\t-\tREJ\n"


def run(tmp_path: Path, raw: bytes) -> tuple[dict, list[dict]]:
    source = tmp_path / "source.log"
    source.write_bytes(raw)
    output = tmp_path / "adapted"
    result = convert(source, output, limit=10000)
    return result, [json.loads(line) for line in (output / "conn.jsonl").read_bytes().splitlines()]


def test_values_missing_and_line_provenance(tmp_path):
    raw = HEADER + ROW
    result, rows = run(tmp_path, raw)
    assert len(rows) == 1
    assert rows[0]["ts"] == 1313495486.546001
    assert rows[0]["uid"] == "C-test"
    assert rows[0]["orig_bytes"] == 0
    assert "resp_bytes" not in rows[0]
    assert rows[0]["duration"] == 0.000157
    assert "synthetic" not in rows[0]
    assert result["source_sha256"] == hashlib.sha256(raw).hexdigest()
    mapping = json.loads((tmp_path / "adapted/line-map.jsonl").read_text())
    assert mapping["source_line"] == 8
    assert mapping["source_line_sha256"] == hashlib.sha256(ROW).hexdigest()
    assert (tmp_path / "adapted/source-sample.log").read_bytes() == raw
    assert (tmp_path / "source.log").read_bytes() == raw


def test_escaped_uid_and_icmp_type_code_do_not_become_service_ports(tmp_path):
    row = ROW.replace(b"C-test", b"C\\x2dtest").replace(b"50000", b"8")
    row = row.replace(b"443", b"0").replace(b"tcp", b"icmp")
    _, rows = run(tmp_path, HEADER + row)
    assert rows[0]["uid"] == "C-test"
    assert "id.orig_p" not in rows[0] and "id.resp_p" not in rows[0]
    assert rows[0]["icmp_type"] == 8 and rows[0]["icmp_code"] == 0


@pytest.mark.parametrize("replacement", [b"NaN", b"Infinity", b"-1"])
def test_invalid_duration_is_quarantined_without_losing_source(tmp_path, replacement):
    invalid = ROW.replace(b"0.000157", replacement)
    result, rows = run(tmp_path, HEADER + invalid + ROW)
    assert len(rows) == 1
    assert result["rejected_records"] == 1
    rejection = json.loads((tmp_path / "adapted/rejected.jsonl").read_text())
    assert rejection["source_line"] == 8


@pytest.mark.parametrize(
    "change",
    [
        lambda b: b.replace(b"50000", b"65536"),
        lambda b: b.replace(b"192.0.2.1", b"not-an-ip"),
        lambda b: b.replace(b"\t0\t-\tREJ", b"\t1.5\t-\tREJ"),
        lambda b: b.replace(b"1313495486.546001", b"nan"),
        lambda b: b.replace(b"\ttcp\t", b"\tmystery\t"),
        lambda b: b.rstrip(b"\n") + b"\textra\n",
    ],
)
def test_invalid_rows_are_counted_not_coerced(tmp_path, change):
    result, rows = run(tmp_path, HEADER + change(ROW))
    assert rows == [] and result["rejected_records"] == 1


def test_unset_optional_duration_stays_unknown(tmp_path):
    _, rows = run(tmp_path, HEADER + ROW.replace(b"0.000157", b"-"))
    assert "duration" not in rows[0]


def test_bad_schema_refused(tmp_path):
    source = tmp_path / "source.log"
    source.write_bytes(HEADER.replace(b"#path\tconn", b"#path\tauth") + ROW)
    with pytest.raises(ValueError, match="conn"):
        convert(source, tmp_path / "out")


def test_existing_output_and_source_overlap_refused(tmp_path):
    source = tmp_path / "source.log"
    source.write_bytes(HEADER + ROW)
    with pytest.raises(FileExistsError):
        convert(source, tmp_path)
    assert source.read_bytes() == HEADER + ROW


def test_prefix_stops_at_record_limit_and_preserves_bytes(tmp_path):
    source = tmp_path / "source.log"
    source.write_bytes(HEADER + ROW + ROW.replace(b"C-test", b"C-next") + b"unfinished")
    result = convert(source, tmp_path / "out", limit=1)
    assert result["selected_records"] == 1
    assert result["selection_truncated"] is True
    assert (tmp_path / "out/source-sample.log").read_bytes() == HEADER + ROW


def test_label_column_refused(tmp_path):
    source = tmp_path / "source.log"
    source.write_bytes(HEADER.replace(b"\tconn_state\n", b"\tLabel\n") + ROW)
    with pytest.raises(ValueError, match="field"):
        convert(source, tmp_path / "out")


def test_protocol_prefix_keeps_original_line_numbers_and_all_tcp_records(tmp_path):
    source = tmp_path / "source.log"
    udp = ROW.replace(b"tcp", b"udp")
    source.write_bytes(HEADER + udp + ROW + udp + ROW.replace(b"C-test", b"C-next"))
    result = convert(source, tmp_path / "out", limit=2, protocol="tcp")
    assert result["selected_records"] == 2 and result["skipped_other_protocol"] == 2
    assert result["scanned_records"] == 4
    rows = [
        json.loads(line) for line in (tmp_path / "out/line-map.jsonl").read_bytes().splitlines()
    ]
    assert [row["source_line"] for row in rows] == [9, 11]
    assert (tmp_path / "out/source-sample.log").read_bytes() == source.read_bytes()


def test_unsupported_protocol_filter_refused(tmp_path):
    source = tmp_path / "source.log"
    source.write_bytes(HEADER + ROW)
    with pytest.raises(ValueError, match="protocol"):
        convert(source, tmp_path / "out", protocol="invented")


def test_invalid_protocol_escape_is_recorded_even_when_filtering(tmp_path):
    source = tmp_path / "source.log"
    source.write_bytes(HEADER + ROW.replace(b"tcp", b"tc\\q") + ROW)
    result = convert(source, tmp_path / "out", protocol="tcp")
    assert result["accepted_records"] == 1 and result["rejected_records"] == 1
