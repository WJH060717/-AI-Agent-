"""Bounded, lossless byte input; only structural counts leave raw storage."""

import base64
import binascii
import re
from urllib.parse import unquote_to_bytes

from packages.contracts.protocols import HTTPQueryShape


def text_or_none(raw: bytes | None) -> str | None:
    if raw is None:
        return None
    try:
        return raw.decode("utf-8")
    except UnicodeDecodeError:
        return None


def byte_field(record: dict, name: str, limit: int) -> bytes | None:
    wrapper = name + "_b64"
    if wrapper in record:
        if name in record:
            raise ValueError("text and byte representations conflict")
        encoded = record[wrapper]
        if not isinstance(encoded, str) or len(encoded) > 4 * ((limit + 2) // 3):
            raise ValueError("invalid bounded byte wrapper")
        try:
            raw = base64.b64decode(encoded, validate=True)
        except (ValueError, binascii.Error):
            raise ValueError("invalid byte wrapper") from None
        if len(raw) > limit or base64.b64encode(raw).decode() != encoded:
            raise ValueError("invalid canonical byte wrapper")
        return raw
    value = record.get(name)
    return value.encode("utf-8") if isinstance(value, str) else None


def query_shape(raw: bytes | None) -> HTTPQueryShape:
    if raw is None:
        return HTTPQueryShape(status="unavailable")
    query = raw.partition(b"#")[0].partition(b"?")[2]
    valid_percent = re.search(rb"%(?![a-fA-F0-9]{2})", query) is None
    # Never partially decode malformed percent sequences or decode twice.
    decoded = unquote_to_bytes(query) if valid_percent else None
    return HTTPQueryShape(
        status="observed",
        raw_bytes=len(query),
        raw_non_utf8=text_or_none(query) is None,
        raw_control_count=sum(v < 32 or v == 127 for v in query),
        has_literal_kv=b"=" in query or b"&" in query,
        percent_encoding="valid" if valid_percent else "invalid",
        decoded_non_utf8=text_or_none(decoded) is None if decoded is not None else None,
        decoded_control_count=sum(v < 32 or v == 127 for v in decoded)
        if decoded is not None
        else None,
    )
