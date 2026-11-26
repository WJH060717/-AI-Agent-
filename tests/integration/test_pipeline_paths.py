import json

import pytest

from packages.agent.executor import ToolExecutor
from packages.agent.runtime import AgentRuntime
from packages.storage.queue import Queue
from packages.storage.service import DomainError
from tests.integration.test_p1_context import create_s1


def test_path_tool_hides_unread_events_and_rejects_foreign_known_ids(context):
    _, _, service, _, _ = context
    actor, analysis, incident = create_s1(context)
    run = analysis.create_run(actor, incident["id"], "paths-known", "deterministic")
    tools = ToolExecutor(service, actor, run["run_id"])
    seeds = set(tools.membership["evidence_ids"])
    hidden = next(e for e in tools.events if e.event_id not in seeds)
    first = tools.call("get_candidate_paths", {"incident_id": tools.incident_id})
    assert hidden.event_id not in first.model_dump_json()
    assert set(first.evidence_ids) <= seeds
    assert "AGENT_KNOWN_EVIDENCE_ONLY" in first.warnings
    result = tools.call("search_events", {"limit": 100})
    known = seeds | set(result.evidence_ids)
    again = tools.call("get_candidate_paths", {"incident_id": tools.incident_id}, known_ids=known)
    assert set(again.evidence_ids) <= known
    with pytest.raises(DomainError):
        tools.call(
            "get_candidate_paths", {"incident_id": tools.incident_id}, known_ids=known | {"f" * 64}
        )


def test_path_cache_tracks_known_evidence_and_repeated_paths_add_nothing(context):
    settings, db, service, _, _ = context
    actor, analysis, incident = create_s1(context)
    analysis.create_run(actor, incident["id"], "paths-cache", "deterministic")
    queue = Queue(db, settings)
    runtime = AgentRuntime(service, queue, queue.claim("paths-cache"))
    runtime.step()
    runtime.step()
    decision = {
        "tool": "get_candidate_paths",
        "arguments": {"incident_id": runtime.tools.incident_id},
    }

    def call():
        runtime.payload["pending_tool"] = decision
        runtime.tool_call()

    call()
    assert runtime.actions()[-1]["new_evidence_count"] == 0
    count = runtime.payload["used"]["tool_calls"]
    call()
    assert runtime.payload["used"]["tool_calls"] == count
    runtime.payload["pending_tool"] = {
        "tool": "search_events",
        "arguments": {"types": ["host.process"], "limit": 100},
    }
    runtime.tool_call()
    assert runtime.payload["retrieved"]
    call()
    assert runtime.payload["used"]["tool_calls"] == count + 2
    last = runtime.actions()[-1]["result_payload"]
    assert last["coverage"]["known_evidence_hash"]
    assert runtime.actions()[-1]["new_evidence_count"] == 0
    assert "local-test-dummy" not in json.dumps(last)


def test_packet_discovery_uses_real_import_and_bounded_safe_summary(context):
    import struct

    from packages.storage.analysis import AnalysisService
    from tests.integration.test_pcap_packet import ipv4_frame, one_dataset, pcap, upload

    _, _, service, workspace, _ = context
    actor = service.system_actor(workspace)
    dataset = one_dataset(service, actor)
    frames = []
    for port in range(20000, 20024):
        tcp = struct.pack("!HHIIHHHH", 4321, port, 1, 0, 0x5002, 0, 0, 0)
        frame = ipv4_frame(6, tcp)
        frames.append((frame, len(frame)))
    upload(service, actor, dataset, pcap(*frames))
    service.process_one()
    analysis = AnalysisService(service)
    incident = analysis.list_incidents(actor, dataset["dataset_id"], dataset["default_session_id"])[
        0
    ]
    run = analysis.create_run(actor, incident["id"], "packets-query", "deterministic")
    tools = ToolExecutor(service, actor, run["run_id"])
    page = tools.call(
        "search_events",
        {
            "types": ["network.packet"],
            "limit": 1,
            "field_filter": [{"field": "src.ip", "op": "eq", "value": "192.0.2.1"}],
        },
    )
    assert page.status == "ok" and page.next_cursor and len(page.evidence_ids) == 1
    item = page.data["items"][0]
    assert item["event_type"] == "network.packet" and item["packet"]["tcp_flags"] == 2
    assert "dns_message" not in item["packet"] and "os_probe" not in item["packet"]
    assert len(page.model_dump_json().encode()) <= 16384
