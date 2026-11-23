"""Project only bounded DNS correlation fields from stored UDP datagrams."""

import re
from hashlib import sha256
from struct import error as StructError
from struct import unpack_from

from packages.contracts.models import DnsDatagramObservation

MAX_MESSAGE_BYTES = 1232
MAX_ANSWERS = 16
LABEL = re.compile(rb"[a-zA-Z0-9_-]{1,63}")


def _name(data: bytes, offset: int) -> tuple[bytes, int]:
    labels = []
    start = offset
    while offset < len(data) and offset - start < 255:
        width = data[offset]
        offset += 1
        if width == 0 and labels:
            return b".".join(labels), offset
        end = offset + width
        if end > len(data) or not LABEL.fullmatch(data[offset:end]):
            break
        labels.append(data[offset:end].lower())
        offset = end
    raise ValueError("unsupported DNS name")


def describe_dns(data: bytes, *, response: bool) -> DnsDatagramObservation | None:
    if not 12 <= len(data) <= MAX_MESSAGE_BYTES:
        return None
    transaction, flags, questions, answers, authority, additional = unpack_from("!6H", data)
    if bool(flags & 0x8000) != response or flags & 0x7A4F or questions != 1:
        return None
    if response and (authority or additional or not 1 <= answers <= MAX_ANSWERS):
        return None
    result: set[bytes] = set()
    try:
        question, offset = _name(data, 12)
        qtype, qclass = unpack_from("!HH", data, offset)
        offset += 4
        if qtype not in (1, 28) or qclass != 1:
            return None
        for _ in range(answers if response else 0):
            if data[offset : offset + 2] == b"\xc0\x0c":
                owner, offset = question, offset + 2
            else:
                owner, offset = _name(data, offset)
            record_type, record_class, _, size = unpack_from("!HHIH", data, offset)
            offset += 10
            if (
                owner != question
                or (record_type, record_class) != (qtype, 1)
                or size != (4 if qtype == 1 else 16)
                or offset + size > len(data)
            ):
                return None
            result.add(data[offset : offset + size])
            offset += size
    except (StructError, ValueError):
        return None
    if response and offset != len(data):
        return None
    message_type = "response" if response else "query"
    if not response and (answers or authority or additional or offset != len(data)):
        message_type = "query_context"
    return DnsDatagramObservation(
        message_type=message_type,
        transaction_id=transaction,
        question_sha256=sha256(question).hexdigest(),
        qtype=qtype,
        answer_set_sha256=sha256(b"".join(sorted(result))).hexdigest() if response else None,
    )
