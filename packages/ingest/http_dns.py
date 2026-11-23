"""Zeek protocol JSON adapters, with credentials and arbitrary content excluded."""

from ipaddress import ip_address
from pathlib import PurePosixPath
from urllib.parse import urlsplit

from packages.contracts.protocols import DNSObservation, HTTPObservation, canonical_name
from packages.ingest.http_bytes import byte_field, query_shape, text_or_none
from packages.ingest.http_shape import client_shape


def host_name(value: object) -> str | None:
    if value is None:
        return None
    if not isinstance(value, str) or len(value) > 260:
        raise ValueError("invalid HTTP host")
    parsed = urlsplit("//" + value)
    if parsed.username or parsed.password or parsed.path or parsed.query or parsed.fragment:
        raise ValueError("invalid HTTP host")
    if parsed.port is not None and not 1 <= parsed.port <= 65535:
        raise ValueError("invalid HTTP host port")
    return canonical_name(parsed.hostname or "")


def protocol_payload(record: dict, source: str) -> dict:
    for field in ("id.orig_h", "id.resp_h", "uid"):
        if not isinstance(record.get(field), str) or not record[field]:
            raise ValueError("protocol record requires string endpoints and UID")
    common = {
        "schema_version": "1.2",
        "src": {"ip": record["id.orig_h"], "port": record["id.orig_p"]},
        "dst": {"ip": record["id.resp_h"], "port": record["id.resp_p"]},
        "network": {
            "transport": "tcp" if source == "zeek_http" else record["proto"],
            "uid": record["uid"],
        },
    }
    if source == "zeek_http":
        uri = record.get("uri")
        if uri is not None and (not isinstance(uri, str) or len(uri) > 16384):
            raise ValueError("invalid bounded HTTP URI")
        uri_bytes = byte_field(record, "uri", 16384)
        agent_bytes = byte_field(record, "user_agent", 2048)
        uri = text_or_none(uri_bytes)
        suffix = PurePosixPath(urlsplit(uri).path).suffix.lower() if uri else None
        if suffix not in {".exe", ".dll", ".msi", ".scr", ".com", ".elf"}:
            suffix = None
        observed = HTTPObservation(
            transaction_depth=record.get("trans_depth"),
            method=record.get("method"),
            host=host_name(record.get("host")),
            uri_suffix=suffix,
            status_code=record.get("status_code"),
            request_body_len=record.get("request_body_len"),
            response_body_len=record.get("response_body_len"),
            response_mime_types=record.get("resp_mime_types"),
            client_shape=client_shape(
                {**record, "uri": uri, "user_agent": text_or_none(agent_bytes)}
            ),
            query_shape=query_shape(uri_bytes),
        )
        return {**common, "schema_version": "1.4", "event_type": "network.http", "http": observed}
    answers = record.get("answers")
    addresses, omitted, non_ip = None, 0, 0
    if answers is not None:
        if not isinstance(answers, list) or len(answers) > 64:
            raise ValueError("DNS answers must be a bounded list")
        addresses = []
        for answer in answers:
            if not isinstance(answer, str) or len(answer) > 4096:
                raise ValueError("invalid DNS answer")
            try:
                address = ip_address(answer)
            except ValueError:
                omitted += 1
                non_ip += 1
                continue
            expected_family = {1: 4, 28: 6}.get(record.get("qtype"))
            if expected_family == address.version:
                addresses.append(address)
            else:
                omitted += 1
    observed_dns = DNSObservation(
        query=record.get("query"),
        qtype=record.get("qtype"),
        rcode=record.get("rcode"),
        rejected=record.get("rejected"),
        answers=addresses,
        non_ip_answers=non_ip,
        omitted_answers=omitted,
    )
    return {**common, "event_type": "network.dns", "dns": observed_dns}
