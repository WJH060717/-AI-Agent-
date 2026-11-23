"""Offline native Bro adaptation; no labels or application database access."""

import argparse
import base64
import json
import re
from pathlib import Path, PurePosixPath
from urllib.parse import urlsplit

from scripts.ctu13_sample import sha, value

FIELDS = {
    "zeek": {
        "ts",
        "uid",
        "id.orig_h",
        "id.orig_p",
        "id.resp_h",
        "id.resp_p",
        "proto",
        "duration",
        "orig_bytes",
        "resp_bytes",
        "missed_bytes",
    },
    "zeek_http": {
        "ts",
        "uid",
        "id.orig_h",
        "id.orig_p",
        "id.resp_h",
        "id.resp_p",
        "trans_depth",
        "method",
        "host",
        "uri",
        "status_code",
        "request_body_len",
        "response_body_len",
        "resp_mime_types",
    },
    "zeek_dns": {
        "ts",
        "uid",
        "id.orig_h",
        "id.orig_p",
        "id.resp_h",
        "id.resp_p",
        "proto",
        "query",
        "qtype",
        "rcode",
        "rejected",
        "answers",
    },
}


def rows(
    source: Path,
    *,
    rejected: list | None = None,
    allowed: set[str] | None = None,
    binary_fields: set[str] | None = None,
    restored: list | None = None,
) -> list[dict]:
    binary_fields = binary_fields or set()
    if not binary_fields <= {"uri", "user_agent"}:
        raise ValueError("only URI and User-Agent byte restoration is allowed")
    if source.is_symlink() or source.stat().st_size > 32 * 1024 * 1024:
        raise ValueError("invalid bounded source")
    raw = source.read_bytes()
    fields, types, header, result = [], [], {}, []
    for number, original in enumerate(raw.splitlines(keepends=True), 1):
        if not original.endswith(b"\n"):
            raise ValueError("incomplete source line")
        line = original.rstrip(b"\r\n")
        if line.startswith(b"#"):
            if line.startswith(b"#fields\t"):
                fields = line.decode().split("\t")[1:]
                if len(set(fields)) != len(fields):
                    raise ValueError("duplicate field")
            elif line.startswith(b"#types\t"):
                types = line.decode().split("\t")[1:]
            elif line.startswith(b"#separator "):
                if line != b"#separator \\x09":
                    raise ValueError("only tab separator supported")
            elif b"\t" in line:
                name, setting = line.split(b"\t", 1)
                header[name] = setting
            continue
        if not fields or len(fields) != len(types):
            raise ValueError("invalid header")
        if header.get(b"#set_separator") != b"," or header.get(b"#unset_field") != b"-":
            raise ValueError("unsupported header encoding")
        cells = line.split(b"\t")
        if len(cells) != len(fields):
            raise ValueError("column count mismatch")
        record, restored_fields = {}, []
        try:
            for name, kind, cell in zip(fields, types, cells, strict=True):
                if allowed is not None and name not in allowed:
                    continue
                if kind.startswith(("vector[", "set[")):
                    if cell == b"-":
                        item = None
                    else:
                        item = (
                            []
                            if cell == header[b"#empty_field"]
                            else [
                                value(
                                    part,
                                    kind[kind.index("[") + 1 : -1],
                                    b"-",
                                    header[b"#empty_field"],
                                )
                                for part in cell.split(b",")
                            ]
                        )
                else:
                    try:
                        item = value(cell, kind, b"-", header[b"#empty_field"])
                    except UnicodeDecodeError:
                        if name not in binary_fields or kind != "string":
                            raise
                        # value() already validated the native escape grammar.
                        decoded = re.sub(
                            rb"\\x([0-9a-fA-F]{2})", lambda m: bytes([int(m[1], 16)]), cell
                        )
                        record[name + "_b64"] = base64.b64encode(decoded).decode()
                        restored_fields.append(name)
                        continue
                if item is not None:
                    record[name] = item
        except (ValueError, OverflowError):
            if rejected is None:
                raise
            rejected.append(
                {
                    "source_line": number,
                    "source_line_sha256": sha(original),
                    "uid": record.get("uid"),
                    "reason": "invalid_field_encoding_or_type",
                }
            )
            continue
        if restored_fields and restored is not None:
            restored.append(
                {
                    "source_line": number,
                    "source_line_sha256": sha(original),
                    "uid": record.get("uid"),
                    "fields": restored_fields,
                }
            )
        result.append(
            {"source_line": number, "source_line_sha256": sha(original), "record": record}
        )
    return result


def save_sample(output: Path, sources: dict[str, Path], records: dict[str, list[dict]]) -> dict:
    output.mkdir(parents=True, exist_ok=False)
    manifest = {"adapter": "bro-protocol-tsv@1", "evaluation": "development_only", "sources": {}}
    for source, selected in records.items():
        data = b"".join(
            (
                json.dumps(
                    {k: v for k, v in item["record"].items() if k in FIELDS[source]},
                    ensure_ascii=False,
                )
                + "\n"
            ).encode()
            for item in selected
        )
        (output / f"{source}.jsonl").write_bytes(data)
        mapping = [
            {
                "output_line": i,
                "source_line": item["source_line"],
                "source_line_sha256": item["source_line_sha256"],
                "uid": item["record"]["uid"],
            }
            for i, item in enumerate(selected, 1)
        ]
        (output / f"{source}-map.json").write_text(json.dumps(mapping, indent=2), encoding="utf-8")
        manifest["sources"][source] = {
            "original": str(sources[source].resolve()),
            "original_sha256": sha(sources[source].read_bytes()),
            "jsonl_sha256": sha(data),
            "records": len(selected),
        }
    (output / "manifest.json").write_text(json.dumps(manifest, indent=2), encoding="utf-8")
    return manifest


def prepare(output: Path) -> dict:
    root = Path(__file__).resolve().parents[1]
    base = root / "artifacts/http-round1-01"
    sources = {
        "zeek": root / "artifacts/ctu13-source-02/download/conn.prefix.log",
        "zeek_http": base / "source-http/http.log",
        "zeek_dns": base / "source-dns/dns.log",
    }
    output.mkdir(parents=True, exist_ok=False)
    rejected = {key: [] for key in sources}
    data = {
        key: rows(path, rejected=rejected[key], allowed=FIELDS[key])
        for key, path in sources.items()
    }
    (output / "source-rejected.json").write_text(json.dumps(rejected, indent=2), encoding="utf-8")
    seeds = {
        json.loads(line)["uid"]
        for line in (root / "artifacts/ctu13-malicious-01/sample-01/adapted/conn.jsonl")
        .read_bytes()
        .splitlines()
    }
    # Development contrast: all successful executable-suffix requests. Not an accuracy sample.
    request_uids = {
        item["record"]["uid"]
        for item in data["zeek_http"]
        if item["record"].get("method") == "GET"
        and item["record"].get("status_code") in {200, 206}
        and PurePosixPath(urlsplit(item["record"].get("uri", "")).path).suffix.lower()
        in {".exe", ".dll", ".msi", ".scr", ".com", ".elf"}
    }
    summary = {}
    for name, uids in [("malicious-connections", seeds), ("request-contrast", request_uids)]:
        conn = [i for i in data["zeek"] if i["record"]["uid"] in uids]
        http = [i for i in data["zeek_http"] if i["record"]["uid"] in uids]
        clients = {i["record"]["id.orig_h"] for i in conn}
        times = [i["record"]["ts"] for i in conn + http]
        dns = [
            i
            for i in data["zeek_dns"]
            if i["record"]["id.orig_h"] in clients
            and min(times) - 300 <= i["record"]["ts"] <= max(times)
        ]
        # Keep protocol context bounded by exact host names, not official labels.
        from packages.ingest.http_dns import host_name

        hosts = {host_name(i["record"].get("host")) for i in http}
        dns = [
            i
            for i in dns
            if i["record"].get("query", "").lower().rstrip(".") in hosts
            or i["record"]["uid"] in uids
        ]
        summary[name] = save_sample(
            output / name, sources, {"zeek": conn, "zeek_http": http, "zeek_dns": dns}
        )
    return summary


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    result = prepare(args.output)
    print(
        json.dumps(
            {
                name: {key: v["records"] for key, v in item["sources"].items()}
                for name, item in result.items()
            }
        )
    )
