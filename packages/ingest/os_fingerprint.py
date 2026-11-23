"""Summarize archived fingerprint witnesses without exposing probe contents."""

from hashlib import sha256
from struct import pack, unpack_from

from packages.contracts.models import OsProbeObservation

MARKER_DIGEST = bytes.fromhex("a5c66bb4b5e430d98bffa9a5e84eed98c4654152c8a06aef5c1c7402c0481d38")


def _udp_key(ip_id: bytes, header: bytes) -> str | None:
    src_port, dst_port, datagram_length, _ = unpack_from("!4H", header)
    if min(src_port, dst_port) < 10_000 or datagram_length != 308:
        return None
    return sha256(ip_id + header[:8]).hexdigest()


def _quote_key(ip: bytes, transport: bytes) -> str | None:
    if transport[:2] != b"\x03\x03":
        return None
    quote = transport[8:]
    if len(quote) < 28 or quote[0] >> 4 != 4 or quote[9] != 17:
        return None
    if int.from_bytes(quote[6:8], "big") & 0xBFFF:
        return None
    if (quote[12:16], quote[16:20]) != (ip[16:20], ip[12:16]):
        return None
    header_length = (quote[0] & 15) * 4
    if not 20 <= header_length <= len(quote) - 8:
        return None
    if int.from_bytes(quote[2:4], "big") != header_length + 308:
        return None
    if (
        len(quote) < header_length + 308
        or sha256(quote[header_length + 8 : header_length + 308]).digest() != MARKER_DIGEST
    ):
        return None
    return _udp_key(quote[4:6], quote[header_length:])


def describe_os_probe(ip: bytes, transport: bytes) -> OsProbeObservation | None:
    protocol = ip[9]
    if protocol == 17:
        if len(transport) != 308 or sha256(transport[8:]).digest() != MARKER_DIGEST:
            return None
        key = _udp_key(ip[4:6], transport)
        return OsProbeObservation(role="udp_request", correlation_sha256=key) if key else None
    if protocol == 1:
        key = _quote_key(ip, transport)
        return OsProbeObservation(role="icmp_quote", correlation_sha256=key) if key else None
    if protocol != 6 or len(transport) < 20 or transport[12] & 1:
        return None
    flags = transport[13]
    if flags not in (2, 18, 20):
        return None
    source, destination, sequence, ack = unpack_from("!HHII", transport)
    if not source or not destination:
        return None
    if flags == 2:
        if (transport[12] >> 4) * 4 != len(transport):
            return None
        identity = pack("!HHI", source, destination, (sequence + 1) & 0xFFFFFFFF)
        return OsProbeObservation(
            role="tcp_request", correlation_sha256=sha256(identity).hexdigest()
        )
    identity = pack("!HHI", destination, source, ack)
    return OsProbeObservation(role="tcp_response", correlation_sha256=sha256(identity).hexdigest())
