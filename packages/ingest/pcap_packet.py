"""Bounded, passive observations from archived microsecond Ethernet PCAP."""

import re
import struct
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from ipaddress import IPv4Address
from typing import BinaryIO
from uuid import UUID

from packages.contracts.models import (
    ArpReplyObservation,
    ArpRequestObservation,
    Endpoint,
    GreEncapsulation,
    HttpSegmentObservation,
    NormalizedEvent,
    PacketObservation,
    PcapRecordRange,
    SourceLocator,
    stable_event_id,
)
from packages.ingest.dns_datagram import describe_dns
from packages.ingest.identity import apply_context, bound_profile
from packages.ingest.os_fingerprint import describe_os_probe
from packages.ingest.parsers import ParseContext

MAX_CAPTURE_BYTES = 32 * 1024 * 1024
MAX_PACKET_RECORDS = 100_000
PARSER_VERSION = "pcap-packet@1.2.0"
ARP_REQUEST_PARSER_VERSION = "pcap-packet@1.3.0"
GRE_PARSER_VERSION = "pcap-packet@1.4.0"
ARP_REPLY_PARSER_VERSION = "pcap-packet@1.5.0"
DNS_DATAGRAM_PARSER_VERSION = "pcap-packet@1.6.0"
OS_PROBE_PARSER_VERSION = "pcap-packet@1.7.0"
MICROSECOND_PCAP_ORDERS = {bytes.fromhex("d4c3b2a1"): "<", bytes.fromhex("a1b2c3d4"): ">"}


class PcapReadError(ValueError):
    def __init__(self, code: str, offset: int, record: int | None = None):
        super().__init__(code)
        self.code, self.offset, self.record = code, offset, record


class UnsupportedFrame(ValueError):
    pass


class InvalidFrame(ValueError):
    pass


@dataclass(frozen=True)
class PacketRecord:
    number: int
    start: int
    end: int
    seconds: int
    micros: int
    wire_length: int
    frame: bytes

    @property
    def original_time(self) -> str:
        return f"{self.seconds}.{self.micros:06d}"


def capture_header(source: BinaryIO, byte_size: int) -> tuple[str, int]:
    if byte_size > MAX_CAPTURE_BYTES:
        raise PcapReadError("PCAP_RESOURCE_LIMIT", 0)
    source.seek(0)
    raw = source.read(24)
    if len(raw) != 24 or raw[:4] not in MICROSECOND_PCAP_ORDERS:
        raise PcapReadError("PCAP_INVALID_HEADER", 0)
    order = MICROSECOND_PCAP_ORDERS[raw[:4]]
    major, minor, _, _, snaplen, link = struct.unpack_from(order + "HHIIII", raw, 4)
    if (major, minor, link) != (2, 4, 1) or not 14 <= snaplen <= 262144:
        raise PcapReadError("PCAP_INVALID_HEADER", 0)
    return order, snaplen


def record_at_cursor(
    source: BinaryIO, header: tuple[str, int], byte_size: int, number: int
) -> PacketRecord:
    start = source.tell()
    if number > MAX_PACKET_RECORDS:
        raise PcapReadError("PCAP_RESOURCE_LIMIT", start, number)
    order, snaplen = header
    raw = source.read(16)
    if len(raw) != 16:
        raise PcapReadError("PCAP_INVALID_RECORD_BOUNDARY", start, number)
    seconds, micros, caplen, wirelen = struct.unpack(order + "IIII", raw)
    end = start + 16 + caplen
    if caplen > min(snaplen, wirelen) or end > byte_size:
        raise PcapReadError("PCAP_INVALID_RECORD_BOUNDARY", start, number)
    frame = source.read(caplen)
    if len(frame) != caplen:
        raise PcapReadError("PCAP_INVALID_RECORD_BOUNDARY", start, number)
    return PacketRecord(number, start, end, seconds, micros, wirelen, frame)


def locate_record(source: BinaryIO, byte_size: int, locator: SourceLocator) -> PacketRecord:
    position = locator.pcap
    if position is None or position.byte_end > byte_size:
        raise ValueError("invalid PCAP locator")
    header = capture_header(source, byte_size)
    for number in range(1, locator.record_start + 1):
        if source.tell() > position.byte_start:
            raise ValueError("packet ordinal does not match byte range")
        record = record_at_cursor(source, header, byte_size, number)
    if (record.start, record.end) != (position.byte_start, position.byte_end):
        raise ValueError("packet ordinal does not match byte range")
    return record


HTTP_LINE = re.compile(
    rb"(?:GET|HEAD|POST|PUT|DELETE|OPTIONS|PATCH|CONNECT|TRACE) [!-~]{1,2048} HTTP/1\.[01]\r\n"
)
HTTP_BOUNDARY = b"\r\n\r\n"


def describe_http_segment(sequence: int, payload: bytes) -> HttpSegmentObservation:
    request = HTTP_LINE.match(payload, 0, 2080)
    end = payload.find(HTTP_BOUNDARY)
    relevant = payload if end < 0 else payload[: end + len(HTTP_BOUNDARY)]
    text_prefix = all(char in (9, 10, 13) or 32 <= char <= 126 for char in relevant)
    transitions = []
    for state in range(4):
        prefix = HTTP_BOUNDARY[:state]
        if end >= 0 or HTTP_BOUNDARY in prefix + payload[:3]:
            transitions.append(4)
        else:
            suffix = prefix + payload[-3:]
            transitions.append(next(i for i in (3, 2, 1, 0) if suffix.endswith(HTTP_BOUNDARY[:i])))
    return HttpSegmentObservation(
        sequence=sequence,
        request_start=request is not None,
        text_prefix=text_prefix,
        header_transitions=tuple(transitions),
    )


def arp_request_observation(
    record: PacketRecord,
) -> tuple[Endpoint, Endpoint, ArpRequestObservation, list[str]]:
    frame = record.frame
    standard_request = bytes.fromhex("0001080006040001")
    sender_mac = frame[22:28]
    if (
        len(frame) != record.wire_length
        or len(frame) < 42
        or frame[14:22] != standard_request
        or frame[:6] != b"\xff" * 6
        or sender_mac != frame[6:12]
        or sender_mac == bytes(6)
        or sender_mac[0] & 1
        or frame[32:38] != bytes(6)
    ):
        raise UnsupportedFrame("PCAP_ARP_REQUEST_OUTSIDE_SCOPE")
    src = Endpoint(ip=IPv4Address(frame[28:32]))
    dst = Endpoint(ip=IPv4Address(frame[38:42]))
    packet = ArpRequestObservation(
        arp_operation=1,
        sender_mac=sender_mac.hex(),
        captured_length=len(frame),
        wire_length=record.wire_length,
    )
    return src, dst, packet, []


def arp_reply_observation(
    record: PacketRecord,
) -> tuple[Endpoint, Endpoint, ArpReplyObservation, list[str]]:
    frame = record.frame
    sender_mac, target_mac = frame[22:28], frame[32:38]
    if (
        len(frame) != record.wire_length or len(frame) < 42
        or frame[14:22] != bytes.fromhex("0001080006040002")
        or sender_mac != frame[6:12] or target_mac != frame[:6]
        or sender_mac == bytes(6) or target_mac == bytes(6)
        or sender_mac[0] & 1 or target_mac[0] & 1 or sender_mac == target_mac
    ):
        raise UnsupportedFrame("PCAP_ARP_REPLY_OUTSIDE_SCOPE")
    src = Endpoint(ip=IPv4Address(frame[28:32]))
    dst = Endpoint(ip=IPv4Address(frame[38:42]))
    return src, dst, ArpReplyObservation(
        arp_operation=2, sender_mac=sender_mac.hex(), captured_length=len(frame),
        wire_length=record.wire_length,
    ), []


def _complete_inner_ip(protocol: int, payload: bytes) -> bool:
    if protocol == 0x0800 and len(payload) >= 20 and payload[0] >> 4 == 4:
        ihl = (payload[0] & 15) * 4
        total = int.from_bytes(payload[2:4], "big")
        return 20 <= ihl <= total <= len(payload) and payload[9] != 47
    if protocol == 0x86DD and len(payload) >= 40 and payload[0] >> 4 == 6:
        length = int.from_bytes(payload[4:6], "big")
        # IPv6 extension chains and jumbograms are outside this bound.
        return (
            0 < length <= len(payload) - 40
            and payload[6] not in {0, 43, 44, 47, 50, 51, 60, 135, 139, 140}
        )
    return False


def gre_encapsulation(transport: bytes) -> GreEncapsulation | None:
    if len(transport) < 4 or transport[:2] != bytes(2):
        return None
    protocol = int.from_bytes(transport[2:4], "big")
    inner = transport[4:]
    if protocol == 0x6558 and len(inner) >= 14:
        ether_type = int.from_bytes(inner[12:14], "big")
        if _complete_inner_ip(ether_type, inner[14:]):
            return "ethernet"
    elif _complete_inner_ip(protocol, inner):
        return "ip"
    return None


def observation(
    record: PacketRecord,
    *,
    include_echo_header: bool = False,
    include_http_segment: bool = False,
    include_arp_request: bool = False,
    include_gre_summary: bool = False,
    include_arp_reply: bool = False,
    include_dns_datagram: bool = False,
    include_os_probe: bool = False,
) -> tuple[
    Endpoint, Endpoint, PacketObservation | ArpRequestObservation | ArpReplyObservation, list[str]
]:
    frame = record.frame
    if record.micros >= 1_000_000:
        raise InvalidFrame("PCAP_INVALID_TIMESTAMP")
    if len(frame) < 14:
        raise InvalidFrame("PCAP_INCOMPLETE_ETHERNET_HEADER")
    if frame[12:14] == bytes.fromhex("0806"):
        if include_arp_reply and frame[20:22] == b"\x00\x02":
            return arp_reply_observation(record)
        if include_arp_request:
            return arp_request_observation(record)
    if frame[12:14] != bytes.fromhex("0800"):
        raise UnsupportedFrame("PCAP_NON_IPV4_ETHERTYPE")
    ip = frame[14:]
    if len(ip) < 20 or ip[0] >> 4 != 4:
        raise InvalidFrame("PCAP_INVALID_IPV4_HEADER")
    ihl = (ip[0] & 15) * 4
    total = int.from_bytes(ip[2:4], "big")
    if not 20 <= ihl <= total <= record.wire_length - 14 or len(ip) < ihl:
        raise InvalidFrame("PCAP_INVALID_IPV4_HEADER")
    fragment = int.from_bytes(ip[6:8], "big")
    proto = ip[9]
    offset = (fragment & 0x1FFF) * 8
    more = bool(fragment & 0x2000)
    body_size = total - ihl
    is_fragment = bool(offset or more)
    if (
        fragment & 0x8000
        or (is_fragment and (fragment & 0x4000 or not body_size))
        or (more and body_size % 8)
        or offset + body_size > 65535 - 20
    ):
        raise InvalidFrame("PCAP_INVALID_FRAGMENT")
    flags = []
    if len(frame) < record.wire_length:
        flags.append("capture_truncated")
    src = Endpoint(ip=IPv4Address(ip[12:16]))
    dst = Endpoint(ip=IPv4Address(ip[16:20]))
    transport = ip[ihl:total]
    derived = {}
    if include_gre_summary and proto == 47 and not is_fragment and not flags:
        derived["gre_encapsulation"] = gre_encapsulation(transport)
    if offset == 0 and proto in (1, 6, 17):
        minimum = {1: 4, 6: 20, 17: 8}[proto]
        if not more and body_size < minimum:
            raise InvalidFrame("PCAP_INVALID_TRANSPORT_HEADER")
        if len(transport) < minimum:
            flags.append("transport_header_incomplete")
        elif proto == 6:
            tcp_header_length = (transport[12] >> 4) * 4
            if tcp_header_length < 20 or (not more and tcp_header_length > total - ihl):
                raise InvalidFrame("PCAP_INVALID_TCP_HEADER")
            if tcp_header_length > len(transport):
                flags.append("transport_header_incomplete")
            else:
                src.port, dst.port = struct.unpack_from("!HH", transport)
                derived["tcp_flags"] = ((transport[12] & 1) << 8) | transport[13]
                payload = transport[tcp_header_length:]
                derived["tcp_payload_bytes_captured"] = len(payload)
                if (
                    include_http_segment
                    and not is_fragment
                    and not flags
                    and payload
                    and not derived["tcp_flags"] & 7
                ):
                    sequence = struct.unpack_from("!I", transport, 4)[0]
                    derived["http_segment"] = describe_http_segment(sequence, payload)
        elif proto == 17:
            src_port, dst_port, udp_length = struct.unpack_from("!HHH", transport)
            if udp_length < 8 or (not more and udp_length > body_size):
                raise InvalidFrame("PCAP_INVALID_UDP_LENGTH")
            src.port, dst.port = src_port, dst_port
            if (
                include_dns_datagram and not is_fragment and not flags
                and udp_length == len(transport) and min(src_port, dst_port) > 0
                and ((src_port == 53) != (dst_port == 53))
            ):
                derived["dns_message"] = describe_dns(transport[8:], response=src_port == 53)
        else:
            derived["icmp_type"], derived["icmp_code"] = transport[:2]
            if include_echo_header and (transport[0], transport[1]) in {(0, 0), (8, 0)}:
                derived["icmp_echo_header_complete"] = len(transport) >= 8
    if include_os_probe and not is_fragment and not flags:
        derived["os_probe"] = describe_os_probe(ip, transport)
    packet = PacketObservation(
        protocol_number=proto,
        captured_length=len(frame),
        wire_length=record.wire_length,
        ip_id=int.from_bytes(ip[4:6], "big"),
        fragment_offset_bytes=offset,
        more_fragments=more,
        **derived,
    )
    return src, dst, packet, flags


def packet_event(record: PacketRecord, context: ParseContext) -> NormalizedEvent:
    src, dst, packet, flags = observation(
        record,
        include_echo_header=True,
        include_http_segment=True,
        include_arp_request=True,
        include_gre_summary=True,
        include_arp_reply=True,
        include_dns_datagram=True,
        include_os_probe=True,
    )
    parser, schema = PARSER_VERSION, "1.6"
    if isinstance(packet, ArpRequestObservation):
        parser, schema = ARP_REQUEST_PARSER_VERSION, "1.7"
    elif isinstance(packet, ArpReplyObservation):
        parser, schema = ARP_REPLY_PARSER_VERSION, "1.8"
    elif packet.dns_message is not None:
        parser, schema = DNS_DATAGRAM_PARSER_VERSION, "1.8"
    elif packet.os_probe is not None:
        parser, schema = OS_PROBE_PARSER_VERSION, "1.9"
    elif packet.gre_encapsulation is not None:
        parser = GRE_PARSER_VERSION
    locator = SourceLocator(
        object_id=context.object_id,
        raw_sha256=context.sha256,
        record_start=record.number,
        record_end=record.number,
        pcap=PcapRecordRange(byte_start=record.start, byte_end=record.end),
    )
    profile = bound_profile(context)
    instance = profile.instance_id if profile else context.dataset_id
    return apply_context(
        NormalizedEvent(
            schema_version=schema,
            workspace_id=context.workspace_id,
            dataset_id=context.dataset_id,
            event_id=stable_event_id(
                UUID(context.workspace_id),
                UUID(context.dataset_id),
                context.sensor_id,
                [locator],
                native_record_id=f"pcap:{context.sha256}:{record.number}",
                instance_id=instance,
            ),
            event_type="network.packet",
            event_time=datetime.fromtimestamp(record.seconds, UTC)
            + timedelta(microseconds=record.micros),
            ingested_at=datetime.now(UTC),
            time_quality={
                "original": record.original_time,
                "timezone": "UTC",
                "offset_ms": 0,
                "uncertainty_ms": 1000,
                "basis": "source_timestamp_uncalibrated",
            },
            sensor={
                "sensor_id": context.sensor_id,
                "type": "pcap",
                "instance_id": instance,
                "observation_domain": context.dataset_id,
            },
            source_locators=[locator],
            parser_version=parser,
            src=src,
            dst=dst,
            packet=packet,
            quality_flags=["clock_uncertain", *flags],
        ),
        context,
    )
