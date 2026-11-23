"""Deterministic investigation grouping; common scope is not proof of causation."""

from datetime import datetime

from packages.contracts.models import NormalizedEvent
from packages.detection.limits import checkpoint


def aggregate_findings(findings: list[dict], events: list[NormalizedEvent]) -> list[dict]:
    by_event = {e.event_id: e for e in events}
    records = []
    for finding in {f["id"]: f for f in findings}.values():
        if not finding["evidence_ids"] or not set(finding["evidence_ids"]).issubset(by_event):
            raise ValueError("finding evidence missing")
        checkpoint(len(finding["evidence_ids"]))
        members = [by_event[eid] for eid in finding["evidence_ids"]]
        scopes = {
            (str(e.workspace_id), str(e.dataset_id), e.sensor.observation_domain) for e in members
        }
        if len(scopes) != 1:
            raise ValueError("finding evidence has conflicting scope")
        workspace, dataset, domain = next(iter(scopes))
        if finding["group_key"][:2] != [workspace, dataset]:
            raise ValueError("finding evidence outside scope")
        entities = set()
        for event in members:
            if event.asset_id and event.host and event.host.asset_id == event.asset_id:
                entities.add("host:" + str(event.asset_id))
            for endpoint in (event.src, event.dst):
                if (
                    endpoint
                    and endpoint.asset_id
                    and endpoint.resolution_quality == "inventory_interval"
                ):
                    entities.add("host:" + str(endpoint.asset_id))
            if event.user and event.user.entity_id:
                entities.add(event.user.entity_id)
        records.append(
            {
                "finding": finding,
                "packet_only": any(e.event_type == "network.packet" for e in members),
                "entities": entities,
                "scope": (workspace, dataset, finding["group_key"][2], domain),
                "start": datetime.fromisoformat(finding["start_time"]),
                "end": datetime.fromisoformat(finding["end_time"]),
            }
        )
    records.sort(key=lambda r: (r["start"], r["finding"]["id"]))
    components = [{i} for i in range(len(records))]
    reasons = []
    for i, left in enumerate(records):
        for j in range(i + 1, len(records)):
            checkpoint()
            right = records[j]
            if right["start"] > left["end"]:
                break
            if left["packet_only"] or right["packet_only"]:
                continue
            shared = sorted(left["entities"] & right["entities"])
            if left["scope"] != right["scope"] or not shared:
                continue
            a = next(c for c in components if i in c)
            b = next(c for c in components if j in c)
            if a is b:
                continue
            merged = a | b
            span = (
                max(records[k]["end"] for k in merged) - min(records[k]["start"] for k in merged)
            ).total_seconds()
            if span >= 1800:
                continue
            a.update(b)
            components.remove(b)
            reasons.append(
                {
                    "finding_ids": sorted([left["finding"]["id"], right["finding"]["id"]]),
                    "shared_entities": shared,
                    "method": "strong_entity_and_overlap",
                }
            )
    result = []
    for component in components:
        members = [records[i] for i in sorted(component)]
        ids = sorted(r["finding"]["id"] for r in members)
        result.append(
            {
                "finding_ids": ids,
                "evidence_ids": sorted(
                    {eid for r in members for eid in r["finding"]["evidence_ids"]}
                ),
                "strong_entities": sorted({entity for r in members for entity in r["entities"]}),
                "reasons": sorted(
                    [r for r in reasons if set(r["finding_ids"]).issubset(ids)],
                    key=lambda r: r["finding_ids"],
                ),
                "start_time": min(r["start"] for r in members).isoformat(timespec="microseconds"),
                "end_time": max(r["end"] for r in members).isoformat(timespec="microseconds"),
                "scope": list(members[0]["scope"]),
                "method_version": "incident_group@1.0.0",
            }
        )
    return sorted(result, key=lambda r: (r["start_time"], r["finding_ids"]))
