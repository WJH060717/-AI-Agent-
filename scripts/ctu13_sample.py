"""Offline, provenance-preserving Bro conn TSV -> supported Zeek JSONL adapter.

No label inputs, traffic execution, model calls or writes to an application DB.
"""

import argparse
import hashlib
import ipaddress
import json
import math
import re
from collections import Counter
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

VERSION = "bro-conn-tsv@2.1"
FIELDS = {
    "ts": "time",
    "uid": "string",
    "id.orig_h": "addr",
    "id.orig_p": "port",
    "id.resp_h": "addr",
    "id.resp_p": "port",
    "proto": "enum",
    "service": "string",
    "duration": "interval",
    "orig_bytes": "count",
    "resp_bytes": "count",
    "conn_state": "string",
    "local_orig": "bool",
    "local_resp": "bool",
    "missed_bytes": "count",
    "history": "string",
    "orig_pkts": "count",
    "orig_ip_bytes": "count",
    "resp_pkts": "count",
    "resp_ip_bytes": "count",
    "tunnel_parents": "set[string]",
    "ip_proto": "count",
}
REQUIRED = {"ts", "uid", "id.orig_h", "id.resp_h", "proto"}


def sha(raw: bytes) -> str:
    return hashlib.sha256(raw).hexdigest()


def decoded(raw: bytes) -> str:
    if re.search(rb"\\(?!x[0-9a-fA-F]{2})", raw):
        raise ValueError("invalid_escape")
    return re.sub(rb"\\x([0-9a-fA-F]{2})", lambda m: bytes([int(m[1], 16)]), raw).decode("utf-8")


def value(raw: bytes, kind: str, unset: bytes, empty: bytes) -> Any:
    if raw == unset:
        return None
    if kind == "set[string]":
        return [] if raw == empty else [decoded(part) for part in raw.split(b",")]
    text = "" if raw == empty else decoded(raw)
    if kind in {"time", "interval"}:
        result = float(text)
        if not math.isfinite(result) or kind == "interval" and result < 0:
            raise ValueError("invalid_time_or_interval")
        if kind == "time":
            datetime.fromtimestamp(result, UTC)
        return result
    if kind in {"count", "port"}:
        if not re.fullmatch(r"[0-9]+", text):
            raise ValueError("invalid_count_or_port")
        number = int(text)
        if number > (65535 if kind == "port" else 2**64 - 1):
            raise ValueError("count_or_port_out_of_range")
        return number
    if kind == "addr":
        ipaddress.ip_address(text)
        return text
    if kind == "bool":
        if text not in {"T", "F"}:
            raise ValueError("invalid_bool")
        return text == "T"
    return text


def convert(source: Path, output: Path, limit: int = 10000, protocol: str | None = None) -> dict:
    """Consume at most limit source data rows; reject bad rows without replacing them."""
    if not 1 <= limit <= 10000:
        raise ValueError("record_limit_must_be_1_to_10000")
    if protocol not in {None, "tcp", "udp", "icmp", "icmpv6"}:
        raise ValueError("unsupported_protocol_filter")
    if source.is_symlink() or not source.is_file():
        raise ValueError("source_must_be_regular_file")
    if source.stat().st_size > 32 * 1024 * 1024:
        raise ValueError("source_exceeds_32MiB_bound")
    if output.exists():
        raise FileExistsError(output)
    raw = source.read_bytes()
    lines = raw.splitlines(keepends=True)
    header: dict[str, bytes] = {}
    selected: list[bytes] = []
    records: list[bytes] = []
    mapping: list[dict] = []
    rejected: list[dict] = []
    protocols: Counter[str] = Counter()
    warnings: Counter[str] = Counter()
    fields: list[str] | None = None
    types: list[str] = []
    consumed = 0
    skipped = 0
    scanned = 0
    times: list[float] = []
    for index, original in enumerate(lines, 1):
        if consumed == limit:
            break
        if not original.endswith(b"\n"):
            raise ValueError("incomplete_source_row_before_record_limit")
        selected.append(original)
        line = original.rstrip(b"\r\n")
        if line.startswith(b"#"):
            if fields is not None and consumed:
                if line.startswith(b"#close\t"):
                    continue
                raise ValueError("unexpected_header_inside_data")
            if line.startswith(b"#separator "):
                if line != b"#separator \\x09":
                    raise ValueError("only_tab_separator_supported")
                header["separator"] = b"\t"
            else:
                name, _, content = line[1:].partition(b"\t")
                header[name.decode("ascii")] = content
            continue
        if fields is None:
            if header.get("path") != b"conn" or header.get("separator") != b"\t":
                raise ValueError("expected_Bro_conn_header")
            if header.get("set_separator", b",") != b",":
                raise ValueError("unsupported_set_separator")
            fields = header.get("fields", b"").decode("ascii").split("\t")
            types = header.get("types", b"").decode("ascii").split("\t")
            if (
                len(set(fields)) != len(fields)
                or not REQUIRED.issubset(fields)
                or any(field not in FIELDS for field in fields)
            ):
                raise ValueError("unsupported_or_missing_field")
            if len(types) != len(fields) or any(
                FIELDS[f] != t for f, t in zip(fields, types, strict=True)
            ):
                raise ValueError("field_type_mismatch")
        scanned += 1
        columns = line.split(b"\t")
        consumed += 1
        try:
            if protocol and len(columns) == len(fields):
                if decoded(columns[fields.index("proto")]) != protocol:
                    skipped += 1
                    consumed -= 1
                    continue
            if len(columns) != len(fields):
                raise ValueError("column_count_mismatch")
            row = {
                field: value(
                    cell,
                    kind,
                    header.get("unset_field", b"-"),
                    header.get("empty_field", b"(empty)"),
                )
                for field, kind, cell in zip(fields, types, columns, strict=True)
            }
            row = {key: item for key, item in row.items() if item is not None}
            if not REQUIRED.issubset(row) or not row["uid"]:
                raise ValueError("missing_required_value")
            if row["proto"] not in {"tcp", "udp", "icmp", "icmpv6", "other"}:
                raise ValueError("unsupported_transport")
            adjustments = []
            if row["proto"] in {"icmp", "icmpv6"}:
                for original_key, new_key in [
                    ("id.orig_p", "icmp_type"),
                    ("id.resp_p", "icmp_code"),
                ]:
                    if original_key in row:
                        row[new_key] = row.pop(original_key)
                adjustments.append("icmp_type_code_not_transport_ports")
                warnings["icmp_type_code_not_transport_ports"] += 1
            if "duration" not in row:
                warnings["duration_unknown"] += 1
            if "orig_bytes" not in row or "resp_bytes" not in row:
                warnings["byte_count_unknown"] += 1
            if row.get("missed_bytes", 0) > 0:
                warnings["source_reports_missed_bytes"] += 1
            result = json.dumps(row, ensure_ascii=False, allow_nan=False, separators=(",", ":"))
            records.append((result + "\n").encode("utf-8"))
            mapping.append(
                {
                    "output_line": len(records),
                    "source_line": index,
                    "source_line_sha256": sha(original),
                    "uid": row["uid"],
                    "adjustments": adjustments,
                }
            )
            protocols[row["proto"]] += 1
            times.append(row["ts"])
        except (ValueError, OverflowError, UnicodeError) as exc:
            rejected.append(
                {
                    "source_line": index,
                    "source_line_sha256": sha(original),
                    "reason": str(exc)[:200],
                }
            )
    if fields is None:
        raise ValueError("no_data_records")
    sample = b"".join(selected)
    jsonl = b"".join(records)
    manifest = {
        "adapter": VERSION,
        "adapter_sha256": sha(Path(__file__).read_bytes()),
        "provenance_type": "derived",
        "parent_provenance": "public_real_capture",
        "source_sha256": sha(raw),
        "sample_sha256": sha(sample),
        "jsonl_sha256": sha(jsonl),
        "source_bytes": len(raw),
        "sample_bytes": len(sample),
        "jsonl_bytes": len(jsonl),
        "selection": f"first_{limit}_{protocol or 'all'}_data_rows_in_source_file_order",
        "protocol_filter": protocol,
        "scanned_records": scanned,
        "skipped_other_protocol": skipped,
        "selected_records": consumed,
        "accepted_records": len(records),
        "rejected_records": len(rejected),
        "selection_truncated": len(sample) < len(raw),
        "source_is_complete_capture": False,
        "protocols": dict(protocols),
        "warnings": dict(warnings),
        "labels_read": False,
        "event_time_min": datetime.fromtimestamp(min(times), UTC).isoformat() if times else None,
        "event_time_max": datetime.fromtimestamp(max(times), UTC).isoformat() if times else None,
        "limitations": [
            "Prefix sample, not a complete time window or capture",
            "Original source clock calibration unknown; no offset invented",
            "No host, authentication, socket ownership or normal baseline supplied",
            "Evidence API refers to derived JSONL; source links are in line-map.jsonl",
        ],
    }
    output.mkdir(parents=True, exist_ok=False)
    for name, content in [("source-sample.log", sample), ("conn.jsonl", jsonl)]:
        (output / name).write_bytes(content)
    for name, rows in [("line-map.jsonl", mapping), ("rejected.jsonl", rejected)]:
        (output / name).write_text("".join(json.dumps(r) + "\n" for r in rows), encoding="utf-8")
    (output / "manifest.json").write_text(json.dumps(manifest, indent=2), encoding="utf-8")
    return manifest


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--source", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--limit", type=int, default=10000)
    parser.add_argument("--protocol", choices=["tcp", "udp", "icmp", "icmpv6"])
    args = parser.parse_args()
    print(json.dumps(convert(args.source, args.output, args.limit, args.protocol), indent=2))


if __name__ == "__main__":
    main()
