import json

import pytest

from scripts.ctu13_focus import extract
from scripts.ctu13_sample import convert
from tests.unit.test_ctu13_sample import HEADER, ROW


def test_full_connection_sequence_kept_with_unrelated_rows_between(tmp_path):
    source = tmp_path / "source.log"
    source.write_bytes(HEADER + ROW + ROW.replace(b"443", b"80") + ROW.replace(b"C-test", b"C-two"))
    convert(source, tmp_path / "parent")
    result = extract(
        tmp_path / "parent", tmp_path / "focus", ["192.0.2.1", "198.51.100.2", 443, "tcp"]
    )
    assert result["accepted_records"] == 2
    assert result["scanned_records"] == 3 and result["skipped_other_connections"] == 1
    assert result["skipped_other_protocol"] == 0
    mapping = [
        json.loads(line) for line in (tmp_path / "focus/line-map.jsonl").read_bytes().splitlines()
    ]
    assert [item["source_line"] for item in mapping] == [8, 10]
    assert [item["output_line"] for item in mapping] == [1, 2]
    parent = (tmp_path / "parent/conn.jsonl").read_bytes().splitlines(keepends=True)
    assert (tmp_path / "focus/conn.jsonl").read_bytes() == parent[0] + parent[2]
    assert (tmp_path / "focus/source-sample.log").read_bytes() == source.read_bytes()


def test_over_limit_rejects_without_silently_trimming(tmp_path):
    source = tmp_path / "source.log"
    source.write_bytes(HEADER + ROW * 251)
    convert(source, tmp_path / "parent")
    with pytest.raises(ValueError, match="250"):
        extract(tmp_path / "parent", tmp_path / "focus", ["192.0.2.1", "198.51.100.2", 443, "tcp"])
    assert not (tmp_path / "focus").exists()


def test_changed_parent_is_rejected(tmp_path):
    source = tmp_path / "source.log"
    source.write_bytes(HEADER + ROW)
    convert(source, tmp_path / "parent")
    with (tmp_path / "parent/conn.jsonl").open("ab") as target:
        target.write(b"{}\n")
    with pytest.raises(ValueError, match="integrity"):
        extract(tmp_path / "parent", tmp_path / "focus", ["192.0.2.1", "198.51.100.2", 443, "tcp"])
