import base64
from dataclasses import replace

import pytest

from packages.ingest.http_wire import messages, wire_record
from packages.ingest.pcap import reassemble
from tests.unit.test_http_dns import context, parse, record


def request(query=b"x" * 40 + b"%FF%Q", agent=b"Mozilla/5.0"):
    return (
        b"GET /q?"
        + query
        + b" HTTP/1.1\r\nHost: example.test\r\nUser-Agent: "
        + agent
        + b"\r\n\r\n"
    )


def response(body=b"no", status=404):
    return (
        f"HTTP/1.1 {status} Test\r\nContent-Length: {len(body)}\r\nContent-Type: text/plain\r\n\r\n"
    ).encode() + body


def raw_record(**changes):
    raw = record()
    for key in ("method", "host", "uri", "status_code", "resp_mime_types", "response_body_len"):
        raw.pop(key, None)
    raw.update(
        format="pcap-http@1",
        request_b64=base64.b64encode(request()).decode(),
        response_b64=base64.b64encode(response()).decode(),
    )
    raw.update(changes)
    return raw


def test_framing_multiple_chunked_and_body_magic():
    raw = (
        response(b"GIF89a")
        + b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n3\r\nabc\r\n0\r\n\r\n"
    )
    values = messages(raw, response=True)
    assert [m.body for m in values] == [b"GIF89a", b"abc"]
    assert values[1].end == len(raw)
    parsed = wire_record(raw_record(response_b64=base64.b64encode(response(b"GIF89a")).decode()))
    assert parsed["response_shape"]["body_format"] == "gif"


@pytest.mark.parametrize(
    "raw",
    [
        b"HTTP/1.1 200 OK\r\nContent-Length: 4\r\n\r\nx",
        b"HTTP/1.1 200 OK\r\nContent-Length: 0\r\nContent-Length: 0\r\n\r\n",
        b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\nContent-Length: 0\r\n\r\n0\r\n\r\n",
        b"HTTP/1.1 200 OK\r\n\r\nclose-delimited",
        b"HTTP/1.1 200 OK\r\n Bad: folded\r\n\r\n",
        b"HTTP/1.1 200 OK\r\nTransfer-Encoding: gzip\r\n\r\n",
    ],
)
def test_ambiguous_or_truncated_http_rejected(raw):
    with pytest.raises(ValueError):
        messages(raw, response=True)


def test_reassembly_deduplicates_overlap_reorders_and_wraps():
    assert (
        reassemble([(0xFFFFFFFE, b"abc"), (1, b"def"), (0xFFFFFFFE, b"abc")], 0xFFFFFFFE)
        == b"abcdef"
    )
    assert reassemble([(13, b"def"), (10, b"abcde")], 10) == b"abcdef"


@pytest.mark.parametrize(
    "segments", [[(10, b"abc"), (14, b"e")], [(10, b"abc"), (12, b"X")], [(11, b"abc")]]
)
def test_gaps_conflicts_and_missing_start_rejected(segments):
    with pytest.raises(ValueError):
        reassemble(segments, 10)


def pcap_pairs(count=2, query=None, gap=10):
    ctx = context()
    events = []
    for i in range(count):
        base = dict(ts=1000 + gap * i, uid=f"pcap-{i}", **{"id.orig_p": 45000 + i})
        events.append(
            parse(
                record(**base, format="pcap-conn@1", proto="tcp", duration=5),
                replace(ctx, source_type="pcap", sha256="b" * 64),
                i + 1,
            )
        )
        raw = raw_record(**base)
        if query is not None:
            raw["request_b64"] = base64.b64encode(request(query)).decode()
        events.append(parse(raw, replace(ctx, source_type="pcap_http"), i + 1))
    return events


def r11(events):
    from packages.detection.registry import detect_all

    return [f for f in detect_all(events, "session") if f["rule_id"] == "R11"]


def test_new_source_privacy_framing_and_unknown_decode():
    event = pcap_pairs()[1]
    assert event.sensor.type == "pcap" and event.schema_version == "1.5"
    assert event.http.query_shape.decoded_non_utf8 is None
    assert event.http.query_encoding.escaped_non_ascii == 1
    assert event.http.query_encoding.invalid_percent == 1
    assert event.http.response_shape.body_bytes == 2
    assert "request_b64" not in event.model_dump_json()
    assert "xxxxx" not in event.model_dump_json()


def test_r11_candidate_replay_and_retransmissions_not_extra_connections():
    from packages.detection.registry import reproduce

    events = pcap_pairs()
    found = r11(events)
    assert len(found) == 1 and found[0]["maliciousness"] == "unknown"
    assert found[0]["statistics"]["status_counts"] == {"404": 2}
    assert reproduce(events, "session", found[0]) == found
    assert r11(events + events) == found
    assert r11(events[:2]) == []


@pytest.mark.parametrize(
    "query",
    [
        b"x" * 40,
        b"x" * 40 + b"%Q",
        b"x" * 40 + b"%FF",
        b"x=" + b"%FF%Q" * 10,
        b"%FF%Q",
        b"x" * 40 + b"%41%Q",
    ],
)
def test_r11_normal_and_insufficient_queries(query):
    assert r11(pcap_pairs(query=query)) == []


@pytest.mark.parametrize(
    "mutation", ["missing", "ambiguous", "sensor", "dataset", "host", "same_uid", "late", "window"]
)
def test_r11_association_boundaries(mutation):
    from datetime import timedelta

    events = pcap_pairs()
    if mutation == "missing":
        events.pop(0)
    if mutation == "ambiguous":
        events.append(events[0].model_copy(deep=True, update={"event_id": "f" * 64}))
    if mutation == "sensor":
        events[0].sensor.sensor_id = "another"
    if mutation == "dataset":
        events[0].dataset_id = context().dataset_id
    if mutation == "host":
        events[1].http.host = "other.example"
    if mutation == "same_uid":
        for event in events:
            event.network.uid = "same"
    if mutation == "late":
        events[0].event_time -= timedelta(seconds=20)
    if mutation == "window":
        events[1].time_quality.uncertainty_ms = 400000
    assert r11(events) == []


def capture(
    *, gap=False, conflict=False, bad_ack=False, truncated=False, fragment=False, normal=False
):
    import socket
    import struct

    key = ("192.0.2.1", 40000, "198.51.100.2", 80)
    rows = []

    def packet(reverse, seq, ack, flags, data=b""):
        src, sport, dst, dport = (*key[2:], *key[:2]) if reverse else key
        tcp = struct.pack("!HHIIBBHHH", sport, dport, seq, ack, 80, flags, 65535, 0, 0) + data
        ip = (
            struct.pack(
                "!BBHHHBBH4s4s",
                69,
                0,
                20 + len(tcp),
                0,
                0x2000 if fragment else 0,
                64,
                6,
                0,
                socket.inet_aton(src),
                socket.inet_aton(dst),
            )
            + tcp
        )
        frame = b"\x00" * 12 + b"\x08\x00" + ip
        rows.append(
            struct.pack(
                "<IIII", 1000 + len(rows), 0, len(frame), len(frame) + (1 if truncated else 0)
            )
            + frame
        )

    packet(False, 100, 0, 2)
    packet(True, 200, 999 if bad_ack else 101, 18)
    packet(False, 101, 201, 16)
    req = request(b"search=ordinary" if normal else b"x" * 40 + b"%FF%Q")
    packet(False, 102 if gap else 101, 201, 24, req)
    packet(False, 101, 201, 24, b"X" + req[1:] if conflict else req)
    packet(True, 201, 101 + len(req), 24, response())
    return struct.pack("<IHHIIII", 0xA1B2C3D4, 2, 4, 0, 0, 65535, 1) + b"".join(rows), key


def test_capture_scope_provenance_and_retransmitted_payload():
    from packages.ingest.pcap import adapt

    raw, key = capture()
    result = adapt(raw, {key})
    assert not result["rejected"]
    assert len(result["pcap_http"]) == len(result["pcap"]) == 1
    assert result["pcap"][0]["orig_bytes"] == len(request())
    assert result["pcap_http"][0]["capture_packets"] == [1, 2, 3, 4, 5, 6]
    import hashlib

    for p in result["mapping"][0]["packets"]:
        assert p["sha256"] == hashlib.sha256(raw[p["offset"] : p["end"]]).hexdigest()
    assert adapt(raw, {("192.0.2.99", 40000, "198.51.100.2", 80)})["pcap"] == []


@pytest.mark.parametrize("change", ["gap", "conflict", "bad_ack"])
def test_capture_rejects_incomplete_conflicting_or_unpaired_handshake(change):
    from packages.ingest.pcap import adapt

    raw, key = capture(**{change: True})
    result = adapt(raw, {key})
    assert result["rejected"] and result["pcap"] == result["pcap_http"] == []


@pytest.mark.parametrize("change", ["truncated", "fragment"])
def test_capture_global_incompleteness_is_explicit(change):
    from packages.ingest.pcap import adapt

    raw, key = capture(**{change: True})
    with pytest.raises(ValueError):
        adapt(raw, {key})


def test_framed_synthetic_normal_packet_does_not_qualify():
    from packages.ingest.pcap import adapt

    raw, key = capture(normal=True)
    result = adapt(raw, {key})
    ctx = context()
    events = [
        parse(r, replace(ctx, source_type=source), i + 1)
        for source in ("pcap", "pcap_http")
        for i, r in enumerate(result[source])
    ]
    assert not result["rejected"] and len(events) == 2 and r11(events) == []


@pytest.mark.parametrize("case", ["reuse", "tail_gap", "unsolicited_response"])
def test_review_capture_lifecycle_completeness_and_response_pairing(case):
    import struct

    from packages.ingest.pcap import adapt

    raw, key = capture()
    rows, offset = [], 24
    while offset < len(raw):
        length = struct.unpack_from("<I", raw, offset + 8)[0]
        rows.append(bytearray(raw[offset : offset + 16 + length]))
        offset += 16 + length
    if case in {"reuse", "tail_gap"}:
        terminal = bytearray(rows[2])
        terminal[16 + 14 + 20 + 13] = 20 if case == "reuse" else 17
        struct.pack_into(
            "!I",
            terminal,
            16 + 14 + 20 + 4,
            101 + len(request()) + (100 if case == "tail_gap" else 0),
        )
        rows.append(terminal)
        if case == "reuse":
            rows.extend([bytearray(r) for r in rows[:6]])
    else:
        reply = rows.pop()
        struct.pack_into("!I", reply, 16 + 14 + 20 + 8, 101)
        rows.insert(3, reply)
    for index, row in enumerate(rows):
        struct.pack_into("<I", row, 0, 1000 + index)
    result = adapt(raw[:24] + b"".join(rows), {key})
    assert result["rejected"] and result["pcap"] == result["pcap_http"] == []


@pytest.mark.parametrize("normal,expected", [(True, 0), (False, 1)])
def test_two_independent_packet_flows_normal_control_and_positive(normal, expected):
    import struct

    from packages.ingest.pcap import adapt

    raw, key = capture(normal=normal)
    second, offset = bytearray(raw[24:]), 0
    while offset < len(second):
        size = struct.unpack_from("<I", second, offset + 8)[0]
        struct.pack_into("<I", second, offset, 1010 + offset // 1000)
        tcp = offset + 16 + 14 + 20
        # Only the client's ephemeral port changes; both directions are mapped.
        for field in (tcp, tcp + 2):
            if struct.unpack_from("!H", second, field)[0] == key[1]:
                struct.pack_into("!H", second, field, key[1] + 1)
        offset += 16 + size
    result = adapt(raw + second, {key, (key[0], key[1] + 1, key[2], key[3])})
    assert not result["rejected"] and len(result["pcap"]) == 2
    ctx = context()
    events = [
        parse(
            row,
            replace(ctx, source_type=source, sha256=("b" if source == "pcap" else "a") * 64),
            index + 1,
        )
        for source in ("pcap", "pcap_http")
        for index, row in enumerate(result[source])
    ]
    assert len(r11(events)) == expected
