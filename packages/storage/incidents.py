"""Immutable incident membership versions and frozen queue catalogs."""

import json
from uuid import UUID, uuid5

from sqlalchemy import and_, or_, select

from packages.contracts.models import FloodObservation
from packages.detection.aggregation import aggregate_findings
from packages.detection.common import DOS_DDOS_FAMILY
from packages.detection.common import title as rule_title
from packages.detection.limits import checkpoint
from packages.storage import schema_v4 as t
from packages.storage.paging import decode, encode, validate_limit
from packages.storage.service import Actor, DataService, DomainError, digest, now


class CatalogService:
    def __init__(self, service: DataService):
        self.service = service

    def publish(
        self, conn, actor: Actor, dataset: str, session: str, findings: list[dict], events: list
    ) -> None:
        ids = []
        by_finding = {f["id"]: f for f in findings}
        for group in aggregate_findings(findings, events):
            checkpoint()
            membership = group["finding_ids"]
            version_key = (
                membership[0]
                if len(membership) == 1
                else digest(json.dumps(["incident_group@1.0.0", membership]).encode())
            )
            incident_id = str(uuid5(UUID(actor.workspace_id), version_key))
            ids.append(incident_id)
            if self.service._optional(conn, t.incidents, actor, incident_id) is not None:
                continue
            rules = sorted({by_finding[fid]["rule_id"] for fid in membership})
            if len(membership) == 1 and "attack_subtype" in by_finding[membership[0]]:
                group["attack_subtype"] = by_finding[membership[0]]["attack_subtype"]
            title = (
                rule_title(rules[0])
                if len(membership) == 1
                else " / ".join(rules) + " 聚合调查候选"
            )
            if (
                len(membership) == 1
                and by_finding[membership[0]]["kind"] == "http_request_unclassified"
            ):
                title = {
                    "R22": "R22 HTTP 请求突发观测（子类型未知）",
                    "R23": "R23 HTTP 请求头延迟观测（子类型未知）",
                }[rules[0]]
            if len(membership) == 1:
                observation = by_finding[membership[0]].get("flood_observation")
                if observation is not None:
                    checked = FloodObservation.model_validate(observation)
                    group["flood_observation"] = checked.model_dump(mode="json")
                    protocol = checked.behavior.split("_", 1)[0]
                    shape = (
                        "请求突发观测" if checked.support == "request_burst_only" else "洪泛形态"
                    )
                    title = f"{rules[0]} {protocol} {shape}（来源分布未知）"
            if group.get("attack_subtype", "").startswith(f"{DOS_DDOS_FAMILY}-"):
                title = f"{DOS_DDOS_FAMILY} · {title}"
            conn.execute(
                t.incidents.insert().values(
                    workspace_id=actor.workspace_id,
                    id=incident_id,
                    dataset_id=dataset,
                    session_id=session,
                    finding_id=membership[0],
                    title=title,
                    start_time=group["start_time"],
                    end_time=group["end_time"],
                    created_at=now(),
                )
            )
            conn.execute(
                t.details.insert().values(
                    workspace_id=actor.workspace_id, id=incident_id, payload=group
                )
            )
        catalog_id = digest(
            json.dumps([actor.workspace_id, dataset, session, sorted(ids)]).encode()
        )
        if self.service._optional(conn, t.catalogs, actor, catalog_id) is None:
            conn.execute(
                t.catalogs.insert().values(
                    workspace_id=actor.workspace_id,
                    id=catalog_id,
                    dataset_id=dataset,
                    session_id=session,
                    payload={"incident_ids": sorted(ids)},
                )
            )
        if self.service._optional(conn, t.heads, actor, session) is None:
            conn.execute(
                t.heads.insert().values(
                    workspace_id=actor.workspace_id, id=session, catalog_id=catalog_id
                )
            )
        else:
            conn.execute(
                t.heads.update()
                .where(t.heads.c.workspace_id == actor.workspace_id, t.heads.c.id == session)
                .values(catalog_id=catalog_id)
            )

    def page(
        self, actor: Actor, dataset: str, session: str, limit: int, cursor: str | None = None
    ) -> dict:
        validate_limit(limit)
        self.service.list_events(actor, dataset, session, 1)
        binding = ["incidents", dataset, session]
        with self.service.db.engine.connect() as conn:
            timestamp = identifier = None
            if cursor:
                position = decode(actor, binding, cursor)
                if len(position) != 3 or not all(isinstance(v, str) for v in position):
                    raise DomainError("INVALID_CURSOR", 422)
                catalog_id, timestamp, identifier = position
            else:
                head = self.service._optional(conn, t.heads, actor, session)
                if head is None:
                    return {"items": [], "next_cursor": None}
                catalog_id = head["catalog_id"]
            catalog = self.service._get(conn, t.catalogs, actor, catalog_id)
            if catalog["dataset_id"] != dataset or catalog["session_id"] != session:
                raise DomainError("INVALID_CURSOR", 422)
            query = (
                select(t.incidents, t.details.c.payload.label("detail"))
                .join(
                    t.details,
                    and_(
                        t.incidents.c.workspace_id == t.details.c.workspace_id,
                        t.incidents.c.id == t.details.c.id,
                    ),
                )
                .where(
                    t.incidents.c.workspace_id == actor.workspace_id,
                    t.incidents.c.id.in_(catalog["payload"]["incident_ids"]),
                )
            )
            if timestamp is not None:
                query = query.where(
                    or_(
                        t.incidents.c.start_time > timestamp,
                        and_(t.incidents.c.start_time == timestamp, t.incidents.c.id > identifier),
                    )
                )
            rows = (
                conn.execute(
                    query.order_by(t.incidents.c.start_time, t.incidents.c.id).limit(limit + 1)
                )
                .mappings()
                .all()
            )
        items = []
        for row in rows[:limit]:
            item = dict(row)
            detail = item.pop("detail")
            for key in ("attack_subtype", "flood_observation"):
                if key in detail:
                    item[key] = detail[key]
            items.append(
                item
                | {"finding_ids": detail["finding_ids"], "aggregation_reasons": detail["reasons"]}
            )
        next_cursor = (
            encode(
                actor, binding, [catalog_id, rows[limit - 1]["start_time"], rows[limit - 1]["id"]]
            )
            if len(rows) > limit
            else None
        )
        return {"items": items, "next_cursor": next_cursor}
