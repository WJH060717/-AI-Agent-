"""Offline classic PCAP adapter with explicit scope and conservative TCP assembly."""

import base64
import hashlib
import socket
import struct
from collections import defaultdict
from dataclasses import dataclass

from packages.ingest.http_wire import LIMIT, Message, messages

MAX_CAPTURE = 32 * 1024 * 1024


@dataclass(frozen=True)
class Packet:
    number: int
    offset: int
    end: int
    timestamp: float
    key: tuple
    sequence: int
    acknowledgement: int
    flags: int
    payload: bytes


def packets(raw: bytes) -> list[Packet]:
    if len(raw) < 24 or len(raw) > MAX_CAPTURE:
        raise ValueError("capture size limit")
    endian = {b"\xd4\xc3\xb2\xa1": "<", b"\xa1\xb2\xc3\xd4": ">"}.get(raw[:4])
    if endian is None:
        raise ValueError("only microsecond classic PCAP supported")
    major, minor, _, _, snaplen, link = struct.unpack(endian + "HHIIII", raw[4:24])
    if (major, minor, link) != (2, 4, 1) or not 54 <= snaplen <= 262144:
        raise ValueError("unsupported capture header")
    result, offset, number = [], 24, 0
    while offset < len(raw):
        start, number = offset, number + 1
        if number > 100000 or offset + 16 > len(raw):
            raise ValueError("packet count or record header limit")
        seconds, micros, caplen, wirelen = struct.unpack_from(endian + "IIII", raw, offset)
        offset += 16
        if micros >= 1000000 or caplen != wirelen or caplen > snaplen or offset + caplen > len(raw):
            raise ValueError("truncated or invalid capture packet")
        frame = raw[offset : offset + caplen]
        offset += caplen
        if len(frame) < 14:
            raise ValueError("truncated Ethernet header")
        if frame[12:14] != b"\x08\x00":
            continue
        ip = frame[14:]
        if len(ip) < 20 or ip[0] >> 4 != 4:
            raise ValueError("invalid IPv4 header")
        ihl, total = (ip[0] & 15) * 4, int.from_bytes(ip[2:4], "big")
        if not 20 <= ihl <= total <= len(ip):
            raise ValueError("truncated IPv4 packet")
        if ip[9] != 6:
            continue
        if int.from_bytes(ip[6:8], "big") & 0x3FFF:
            raise ValueError("fragmented TCP unsupported")
        tcp = ip[ihl:total]
        if len(tcp) < 20 or not 20 <= (tcp[12] >> 4) * 4 <= len(tcp):
            raise ValueError("truncated TCP header")
        key = (
            socket.inet_ntoa(ip[12:16]),
            int.from_bytes(tcp[:2], "big"),
            socket.inet_ntoa(ip[16:20]),
            int.from_bytes(tcp[2:4], "big"),
        )
        result.append(
            Packet(
                number,
                start,
                offset,
                seconds + micros / 1e6,
                key,
                int.from_bytes(tcp[4:8], "big"),
                int.from_bytes(tcp[8:12], "big"),
                tcp[13],
                tcp[(tcp[12] >> 4) * 4 :],
            )
        )
    return result


def reassemble(segments: list[tuple[int, bytes]], initial: int) -> bytes:
    if len(segments) > 10000 or sum(len(data) for _, data in segments) > LIMIT * 4:
        raise ValueError("TCP resource limit")
    output = bytearray()
    for sequence, payload in sorted(segments, key=lambda item: (item[0] - initial) & 0xFFFFFFFF):
        start = (sequence - initial) & 0xFFFFFFFF
        if start > len(output) or start + len(payload) > LIMIT:
            raise ValueError("TCP gap or stream size limit")
        overlap = min(len(payload), len(output) - start)
        if output[start : start + overlap] != payload[:overlap]:
            raise ValueError("conflicting TCP overlap")
        output.extend(payload[overlap:])
    return bytes(output)


def validate_pairs(
    group: list[Packet],
    key: tuple,
    anchors: list[int],
    streams: list[bytes],
    requests: list[Message],
    responses: list[Message],
) -> None:
    # Reusing a tuple/ISN after data or termination is not a SYN retransmission
    # this bounded adapter can safely disambiguate.
    began = False
    for packet in group:
        if packet.flags & 2 and began:
            raise ValueError("TCP tuple reuse or late SYN unsupported")
        began = began or bool(packet.payload) or bool(packet.flags & 5)
    for side, direction in enumerate((key, (*key[2:], *key[:2]))):
        own = [p for p in group if p.key == direction]
        for packet in own:
            if packet.flags & 1:
                terminal = (packet.sequence + len(packet.payload) - anchors[side]) & 0xFFFFFFFF
                if terminal != len(streams[side]):
                    raise ValueError("TCP FIN proves incomplete or conflicting tail")
    for request, response in zip(requests, responses, strict=True):
        starts = [
            p
            for p in group
            if p.key != key
            and p.payload
            and ((p.sequence - anchors[1]) & 0xFFFFFFFF)
            <= response.start
            < ((p.sequence - anchors[1]) & 0xFFFFFFFF) + len(p.payload)
        ]
        first = min(starts, key=lambda p: p.number)
        ack = (first.acknowledgement - anchors[0]) & 0xFFFFFFFF
        if not first.flags & 16 or not request.end <= ack <= len(streams[0]) + 1:
            raise ValueError("response ACK does not cover corresponding request")
        prefix = []
        for packet in group:
            offset = (packet.sequence - anchors[0]) & 0xFFFFFFFF
            if (
                packet.key == key
                and packet.payload
                and packet.number < first.number
                and offset < request.end
            ):
                prefix.append((packet.sequence, packet.payload[: request.end - offset]))
        if len(reassemble(prefix, anchors[0])) != request.end:
            raise ValueError("response precedes complete captured request")


def adapt(raw: bytes, scope: set[tuple]) -> dict:
    if not scope or len(scope) > 1000:
        raise ValueError("bounded explicit tuple scope required")
    digest = hashlib.sha256(raw).hexdigest()
    grouped = defaultdict(list)
    for packet in packets(raw):
        reverse = (*packet.key[2:], *packet.key[:2])
        if packet.key in scope:
            grouped[packet.key].append(packet)
        elif reverse in scope:
            grouped[reverse].append(packet)
    conns, http, rejected, mapping = [], [], [], []
    for key in sorted(scope):
        group = grouped[key]
        try:
            if not group:
                raise ValueError("tuple not observed")
            if len(group) > 10000:
                raise ValueError("flow packet limit")
            streams, anchors = [], []
            for direction in (key, (*key[2:], *key[:2])):
                own = [p for p in group if p.key == direction]
                syns = {p.sequence for p in own if p.flags & 2}
                if len(syns) != 1 or any(p.payload for p in own if p.flags & 2):
                    raise ValueError("missing or reused TCP SYN")
                initial = (next(iter(syns)) + 1) & 0xFFFFFFFF
                anchors.append(initial)
                streams.append(
                    reassemble([(p.sequence, p.payload) for p in own if p.payload], initial)
                )
            if any(
                (p.key == key and (p.flags & 16))
                or (p.key != key and (not p.flags & 16 or p.acknowledgement != anchors[0]))
                for p in group
                if p.flags & 2
            ) or not any(
                p.key == key and p.flags & 16 and p.acknowledgement == anchors[1] for p in group
            ):
                raise ValueError("unpaired TCP handshake")
            reqs, resps = messages(streams[0]), messages(streams[1], response=True)
            if not reqs or len(reqs) != len(resps):
                raise ValueError("unpaired HTTP transactions")
            # Validate the entire flow before publishing any of its records.
            validate_pairs(group, key, anchors, streams, reqs, resps)
            uid = (
                "pcap-"
                + hashlib.sha256((digest + repr(key) + repr(anchors)).encode()).hexdigest()[:32]
            )
            common = {
                "uid": uid,
                "id.orig_h": key[0],
                "id.orig_p": key[1],
                "id.resp_h": key[2],
                "id.resp_p": key[3],
            }
            start, end = min(p.timestamp for p in group), max(p.timestamp for p in group)
            provenance = {"capture_sha256": digest, "capture_packets": [p.number for p in group]}
            conns.append(
                {
                    **common,
                    **provenance,
                    "format": "pcap-conn@1",
                    "ts": start,
                    "proto": "tcp",
                    "duration": end - start,
                    "orig_bytes": len(streams[0]),
                    "resp_bytes": len(streams[1]),
                }
            )
            for i, (req, resp) in enumerate(zip(reqs, resps, strict=True), 1):
                request_packets = [
                    p
                    for p in group
                    if p.key == key
                    and p.payload
                    and ((p.sequence - anchors[0]) & 0xFFFFFFFF)
                    <= req.start
                    < ((p.sequence - anchors[0]) & 0xFFFFFFFF) + len(p.payload)
                ]
                http.append(
                    {
                        **common,
                        **provenance,
                        "format": "pcap-http@1",
                        "ts": min(p.timestamp for p in request_packets),
                        "trans_depth": i,
                        "request_b64": base64.b64encode(streams[0][req.start : req.end]).decode(),
                        "response_b64": base64.b64encode(
                            streams[1][resp.start : resp.end]
                        ).decode(),
                        "request_stream_range": [req.start, req.end],
                        "response_stream_range": [resp.start, resp.end],
                    }
                )
            mapping.append(
                {
                    "uid": uid,
                    "tuple": key,
                    "packets": [
                        {
                            "number": p.number,
                            "offset": p.offset,
                            "end": p.end,
                            "sha256": hashlib.sha256(raw[p.offset : p.end]).hexdigest(),
                        }
                        for p in group
                    ],
                }
            )
        except ValueError as error:
            rejected.append({"tuple": key, "reason": str(error)})
    return {
        "pcap": conns,
        "pcap_http": http,
        "mapping": mapping,
        "rejected": rejected,
        "capture_sha256": digest,
    }
