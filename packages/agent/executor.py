"""Six bounded read-only tools. All scope comes from the persisted run/snapshot."""

import json
import re
import time
from uuid import uuid4

from pydantic import ValidationError

from packages.contracts.agent import TOOL_SCHEMAS, ToolResult
from packages.contracts.models import InvestigationScope, NormalizedEvent
from packages.graph.paths import analyze_paths
from packages.storage import schema_v4 as t
from packages.storage.analysis import AnalysisService
from packages.storage.paging import decode, encode
from packages.storage.service import Actor, DataService, DomainError, digest


def summary(event: NormalizedEvent) -> dict:
    data = event.model_dump(mode="json")
    result = {
        key: data[key]
        for key in (
            "event_id",
            "event_time",
            "event_type",
            "asset_id",
            "sensor",
            "time_quality",
            "quality_flags",
        )
    }
    for key in ("host", "src", "dst", "user", "auth", "process", "network", "http", "dns"):
        if data[key] is not None:
            result[key] = data[key]
    if event.packet is not None:
        result["packet"] = data["packet"]
        result["packet"].pop("dns_message", None)
        result["packet"].pop("os_probe", None)
    # No command lines, arbitrary extensions, raw usernames or source paths in model context.
    if "process" in result:
        result["process"].pop("command_redacted", None)
        if result["process"].get("executable"):
            result["process"]["executable"] = result["process"]["executable"][:200]
    result["time_quality"] = {k: v for k, v in result["time_quality"].items() if k != "original"}
    return result


class ToolExecutor:
    def __init__(self, service: DataService, actor: Actor, run_id: str):
        self.service, self.actor, self.run_id = service, actor, run_id
        analysis = AnalysisService(service)
        with service.db.engine.connect() as conn:
            run = service._get(conn, t.runs, actor, run_id)
            snapshot = service._get(conn, t.snapshots, actor, run["snapshot_id"])
            self.incident_id = run["incident_id"]
            self.membership = service._get(conn, t.details, actor, self.incident_id)["payload"]
            self.events = analysis._snapshot_events(conn, actor, snapshot)
        self.scope = InvestigationScope.model_validate(snapshot["scope"])
        self.by_id = {e.event_id: e for e in self.events}
        if str(self.scope.workspace_id) != actor.workspace_id:
            raise DomainError("EVIDENCE_OUT_OF_SCOPE", 404)

    def validate(self, tool: str, arguments: dict):
        if tool not in TOOL_SCHEMAS:
            raise DomainError("TOOL_NOT_ALLOWED", 422)
        if len(json.dumps(arguments).encode()) > 8192:
            raise DomainError("TOOL_ARGUMENTS_TOO_LARGE", 422)
        try:
            args = TOOL_SCHEMAS[tool].model_validate(arguments)
        except (ValueError, TypeError, ValidationError):
            raise DomainError("INVALID_TOOL_ARGUMENTS", 422) from None
        start, end = getattr(args, "start", None), getattr(args, "end", None)
        if (
            start
            and not self.scope.start <= start < self.scope.end
            or end
            and not self.scope.start < end <= self.scope.end
            or start
            and end
            and start >= end
        ):
            raise DomainError("TOOL_TIME_OUT_OF_SCOPE", 422)
        for condition in getattr(args, "field_filter", []):
            values = condition.value if isinstance(condition.value, list) else [condition.value]
            if (
                not values
                or len(values) > 20
                or any(len(v) > 200 for v in values)
                or condition.op == "eq"
                and len(values) != 1
            ):
                raise DomainError("INVALID_TOOL_FILTER", 422)
        if tool == "get_technique_context" and any(
            not re.fullmatch(r"T\d{4}(?:\.\d{3})?", tid) for tid in args.technique_ids
        ):
            raise DomainError("INVALID_TECHNIQUE_ID", 422)
        return args

    def call(self, tool: str, arguments: dict, call_id: str | None = None) -> ToolResult:
        started = time.monotonic()
        args = self.validate(tool, arguments)
        normalized = args.model_dump(mode="json", exclude={"cursor", "limit"})
        binding = [
            "agent-tool",
            self.run_id,
            str(self.scope.snapshot_id),
            tool,
            digest(json.dumps(normalized, sort_keys=True).encode()),
        ]
        cursor = getattr(args, "cursor", None)
        if tool == "get_event_evidence":
            return self.evidence_page(args, binding, cursor, call_id, started)
        position = decode(self.actor, binding, cursor) if cursor else []
        if position and (len(position) != 1 or type(position[0]) is not int or position[0] < 0):
            raise DomainError("INVALID_CURSOR", 422)
        offset = position[0] if position else 0
        selected = self.events
        warnings = []
        if tool in ("search_events", "get_asset_timeline"):
            if getattr(args, "types", None):
                selected = [e for e in selected if e.event_type in args.types]
            if args.asset_id:
                selected = [
                    e
                    for e in selected
                    if e.asset_id == args.asset_id
                    or any(
                        ep
                        and ep.asset_id == args.asset_id
                        and ep.resolution_quality == "inventory_interval"
                        for ep in (e.src, e.dst)
                    )
                ]
                if tool == "get_asset_timeline" and not selected:
                    raise DomainError("ASSET_OUT_OF_SCOPE", 404)
            selected = [
                e
                for e in selected
                if (not args.start or e.event_time >= args.start)
                and (not args.end or e.event_time < args.end)
            ]
            for condition in getattr(args, "field_filter", []):
                values = condition.value if isinstance(condition.value, list) else [condition.value]
                if (
                    not values
                    or len(values) > 20
                    or any(len(v) > 200 for v in values)
                    or condition.op == "eq"
                    and len(values) != 1
                ):
                    raise DomainError("INVALID_TOOL_FILTER", 422)

                def matches(event, condition=condition, values=values):
                    value = event.model_dump(mode="json")
                    for part in condition.field.split("."):
                        value = value.get(part) if isinstance(value, dict) else None
                    return value in values

                selected = [e for e in selected if matches(e)]
            items = [summary(e) for e in selected]
        elif tool == "get_process_context":
            targets = [
                e for e in selected if e.process and e.process.entity_id == args.process_entity_id
            ]
            if not targets:
                items = []
            else:
                target = targets[0]
                known = {args.process_entity_id}
                for _ in range(args.depth):
                    expanded = set(known)
                    for e in selected:
                        if not e.process or e.host != target.host:
                            continue
                        if e.process.entity_id in known and e.process.parent_entity_id:
                            expanded.add(e.process.parent_entity_id)
                        if e.process.parent_entity_id in known and e.process.entity_id:
                            expanded.add(e.process.entity_id)
                    known = expanded
                items = [
                    summary(e)
                    for e in selected
                    if e.process and e.host == target.host and e.process.entity_id in known
                ]
        elif tool == "get_candidate_paths":
            if str(args.incident_id) != self.incident_id:
                raise DomainError("INCIDENT_OUT_OF_SCOPE", 404)
            paths = analyze_paths(self.events, self.scope, set(self.membership["evidence_ids"]))
            items = [path.model_dump(mode="json") for path in paths.paths[: args.top_k]]
            warnings = paths.limitations
            if paths.truncated:
                warnings = [*warnings, "PATH_SEARCH_TRUNCATED"]
        else:
            if any(not re.fullmatch(r"T\d{4}(?:\.\d{3})?", tid) for tid in args.technique_ids):
                raise DomainError("INVALID_TECHNIQUE_ID", 422)
            from packages.knowledge.catalog import Catalog, KnowledgeError

            items, warnings = [], ["KNOWLEDGE_CONTEXT_ONLY"]
            if not self.service.settings.knowledge_enabled:
                warnings.append("LOCAL_KNOWLEDGE_DISABLED")
            else:
                try:
                    catalog = Catalog()
                    items = catalog.lookup(args.technique_ids)
                    if set(args.technique_ids) - catalog.entries.keys():
                        warnings.append("TECHNIQUE_NOT_IN_CURATED_SET")
                except KnowledgeError:
                    warnings.append("LOCAL_KNOWLEDGE_INVALID")
        result = ToolResult(
            tool_call_id=call_id or str(uuid4()),
            status="empty",
            data={"items": []},
            coverage={
                "snapshot_id": str(self.scope.snapshot_id),
                "start": self.scope.start.isoformat(),
                "end": self.scope.end.isoformat(),
                "source_types": sorted({e.sensor.type for e in self.events}),
                "matched": len(items),
                "meaning": "empty不证明没有发生；仅覆盖当前快照",
            },
            warnings=warnings,
        )
        maximum = getattr(args, "limit", 100)
        for item in items[offset : offset + maximum]:
            proposed = result.data["items"] + [item]
            result.data["items"] = proposed
            if len(result.model_dump_json().encode()) > 14000:
                result.data["items"].pop()
                break
        end = offset + len(result.data["items"])
        if end < len(items):
            if not result.data["items"]:
                raise DomainError("TOOL_ITEM_TOO_LARGE", 422)
            result.next_cursor = encode(self.actor, binding, [end])
            result.truncated = True
        result.status = "ok" if result.data["items"] else "empty"
        for item in result.data["items"]:
            result.evidence_ids.extend(
                [item["event_id"]] if "event_id" in item else item.get("event_ids", [])
            )
        result.evidence_ids = sorted(set(result.evidence_ids))
        result.elapsed_ms = max(0, round((time.monotonic() - started) * 1000))
        if len(result.model_dump_json().encode()) > 16384:
            raise DomainError("TOOL_RESPONSE_TOO_LARGE", 422)
        return result

    def evidence_page(self, args, binding, cursor, call_id, started):
        if not set(args.event_ids).issubset(self.by_id):
            raise DomainError("EVIDENCE_OUT_OF_SCOPE", 404)
        position = decode(self.actor, binding, cursor) if cursor else [0, None]
        if (
            len(position) != 2
            or type(position[0]) is not int
            or not 0 <= position[0] < len(args.event_ids)
            or position[1] is not None
            and not isinstance(position[1], str)
        ):
            raise DomainError("INVALID_CURSOR", 422)
        index, source_cursor = position
        eid = args.event_ids[index]
        evidence = AnalysisService(self.service).evidence(
            self.actor, eid, str(self.scope.snapshot_id), source_cursor, limit=3
        )
        warnings = []
        for fragment in evidence["fragments"]:
            for line in fragment["lines"]:
                if len(line["text"].encode()) > 1000:
                    line["text"] = (
                        line["text"].encode()[:900].decode("utf-8", errors="ignore")
                        + " [truncated]"
                    )
                    warnings.append("EVIDENCE_TEXT_TRUNCATED")
        next_position = (
            [index, evidence["next_cursor"]] if evidence["next_cursor"] else [index + 1, None]
        )
        more = next_position[0] < len(args.event_ids)
        item = evidence | {
            "selected_fields": {
                k: v for k, v in summary(self.by_id[eid]).items() if k in args.fields
            }
        }
        result = ToolResult(
            tool_call_id=call_id or str(uuid4()),
            status="ok",
            data={"items": [item]},
            evidence_ids=[eid],
            next_cursor=encode(self.actor, binding, next_position) if more else None,
            truncated=more or bool(warnings),
            warnings=warnings,
            coverage={
                "snapshot_id": str(self.scope.snapshot_id),
                "event_id": eid,
                "meaning": "只覆盖本页白名单脱敏片段，长行裁剪有标记",
            },
            elapsed_ms=max(0, round((time.monotonic() - started) * 1000)),
        )
        if len(result.model_dump_json().encode()) > 16384:
            raise DomainError("TOOL_RESPONSE_TOO_LARGE", 422)
        return result
