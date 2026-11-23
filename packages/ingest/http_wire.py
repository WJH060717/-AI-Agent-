"""Bounded HTTP/1 message framing. No decompression or payload execution."""

import base64
import re
from dataclasses import dataclass

from packages.ingest.http_bytes import byte_field

LIMIT = 2 * 1024 * 1024
HEADER_LIMIT = 32768


@dataclass(frozen=True)
class Message:
    start: int
    end: int
    first: bytes
    headers: dict[bytes, bytes]
    body: bytes


def messages(raw: bytes, *, response: bool = False) -> list[Message]:
    if len(raw) > LIMIT:
        raise ValueError("HTTP stream limit")
    result, offset = [], 0
    while offset < len(raw):
        if len(result) >= 256:
            raise ValueError("HTTP transaction limit")
        marker = raw.find(b"\r\n\r\n", offset, offset + HEADER_LIMIT)
        if marker < 0:
            raise ValueError("incomplete or oversized HTTP header")
        lines = raw[offset:marker].split(b"\r\n")
        first, headers = lines[0], {}
        pattern = (
            rb"HTTP/1\.[01] [1-5][0-9]{2}(?: [^\r\n]*)?"
            if response
            else rb"[A-Z-]{1,32} [^ \r\n]{1,16384} HTTP/1\.[01]"
        )
        if re.fullmatch(pattern, first) is None:
            raise ValueError("unsupported HTTP start line")
        for line in lines[1:]:
            key, sep, value = line.partition(b":")
            if not sep or not re.fullmatch(rb"[!#$%&'*+.^_`|~0-9A-Za-z-]+", key):
                raise ValueError("invalid HTTP header")
            key, value = key.lower(), value.strip(b" \t")
            if any(c < 32 and c != 9 or c == 127 for c in value):
                raise ValueError("invalid HTTP header value")
            # Duplicates of framing, routing and semantic headers are ambiguous.
            if key in headers and key in {
                b"content-length",
                b"transfer-encoding",
                b"host",
                b"user-agent",
                b"content-type",
            }:
                raise ValueError("ambiguous HTTP header")
            headers[key] = value
        length, transfer = headers.get(b"content-length"), headers.get(b"transfer-encoding")
        if length is not None and transfer is not None:
            raise ValueError("ambiguous HTTP framing")
        body_start = end = marker + 4
        status = int(first.split(b" ")[1]) if response else None
        if response and (status < 200 or status in {204, 304}):
            raise ValueError("interim or bodyless response unsupported")
        if transfer is not None:
            if transfer.lower() != b"chunked":
                raise ValueError("unsupported transfer encoding")
            chunks = []
            for _ in range(4096):
                size_end = raw.find(b"\r\n", end, end + 128)
                size_raw = raw[end:size_end] if size_end >= 0 else b""
                if not re.fullmatch(rb"[0-9a-fA-F]{1,8}", size_raw):
                    raise ValueError("invalid or unsupported chunk")
                size = int(size_raw, 16)
                end = size_end + 2
                if (
                    size > LIMIT
                    or end + size + 2 > len(raw)
                    or raw[end + size : end + size + 2] != b"\r\n"
                ):
                    raise ValueError("incomplete chunk or unsupported trailers")
                chunks.append(raw[end : end + size])
                end += size + 2
                if size == 0:
                    break
            else:
                raise ValueError("chunk count limit")
            body = b"".join(chunks)
        else:
            if length is None and response:
                raise ValueError("close-delimited response unsupported")
            if length is not None and not re.fullmatch(rb"[0-9]{1,10}", length):
                raise ValueError("invalid content length")
            end += int(length or b"0")
            if end > len(raw):
                raise ValueError("incomplete HTTP body")
            body = raw[body_start:end]
        result.append(Message(offset, end, first, headers, body))
        offset = end
    return result


def body_format(body: bytes) -> str:
    for magic, name in (
        (b"GIF87a", "gif"),
        (b"GIF89a", "gif"),
        (b"\xff\xd8\xff", "jpeg"),
        (b"\x89PNG\r\n\x1a\n", "png"),
        (b"\x00\x00\x01\x00", "ico"),
        (b"\x1f\x8b", "gzip"),
    ):
        if body.startswith(magic):
            return name
    if not body:
        return "empty"
    try:
        body.decode("utf-8")
    except UnicodeDecodeError:
        return "other"
    return "utf8_text"


def encoding_shape(uri: bytes) -> dict:
    query = uri.partition(b"#")[0].partition(b"?")[2]
    escaped = [int(v, 16) for v in re.findall(rb"%([a-fA-F0-9]{2})", query)]
    return {
        "version": "http-query-encoding@1",
        "valid_escapes": len(escaped),
        "escaped_non_ascii": sum(v >= 128 for v in escaped),
        "escaped_controls": sum(v < 32 or v == 127 for v in escaped),
        "invalid_percent": len(re.findall(rb"%(?![a-fA-F0-9]{2})", query)),
    }


def wire_record(record: dict) -> dict:
    if record.get("format") != "pcap-http@1":
        raise ValueError("missing PCAP adapter format")
    request_raw = byte_field(record, "request", LIMIT)
    response_raw = byte_field(record, "response", LIMIT)
    if request_raw is None or response_raw is None:
        raise ValueError("complete request and response bytes required")
    requests, responses = messages(request_raw), messages(response_raw, response=True)
    if len(requests) != 1 or len(responses) != 1:
        raise ValueError("one transaction per record required")
    req, resp = requests[0], responses[0]
    method, uri, _ = req.first.split(b" ")
    if method not in {b"GET", b"POST"} or b"host" not in req.headers:
        raise ValueError("unsupported method or missing Host")
    mime = resp.headers.get(b"content-type", b"").split(b";", 1)[0].strip().lower()
    # Ignore all supplied HTTP summary fields: derive observations from bytes.
    return {
        **{
            key: record[key]
            for key in ("ts", "uid", "id.orig_h", "id.orig_p", "id.resp_h", "id.resp_p")
        },
        "trans_depth": record.get("trans_depth"),
        "method": method.decode("ascii"),
        "uri_b64": base64.b64encode(uri).decode(),
        "user_agent_b64": base64.b64encode(req.headers.get(b"user-agent", b"")).decode(),
        "host": req.headers[b"host"].decode("ascii"),
        "status_code": int(resp.first.split(b" ")[1]),
        "request_body_len": len(req.body),
        "response_body_len": len(resp.body),
        "resp_mime_types": [mime.decode("ascii")] if mime else None,
        "query_encoding": encoding_shape(uri),
        "response_shape": {
            "version": "http-response-shape@1",
            "framing": "complete",
            "body_bytes": len(resp.body),
            "body_format": body_format(resp.body),
        },
    }
