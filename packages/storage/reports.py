"""Immutable report views, bounded redacted exports and append-only human reviews."""

import html
import json
from typing import Literal
from uuid import uuid4

from sqlalchemy import func, select

from packages.contracts.reports import ReportExport, ReportSummary, ReviewCreate, ReviewRecord
from packages.storage import schema_v6 as t
from packages.storage.analysis import AnalysisService
from packages.storage.paging import decode, encode, validate_limit
from packages.storage.service import Actor, DataService, DomainError, digest, now


class ReportService:
    def __init__(self, service: DataService):
        self.service, self.db = service, service.db

    def cached(self, actor: Actor, report_id: str) -> dict:
        from packages.agent.cache import report_cache_key

        analysis = AnalysisService(self.service)
        with self.db.engine.connect() as conn:
            report = self.service._get(conn, t.reports, actor, report_id)["payload"]
            run = self.service._get(conn, t.runs, actor, report["run_id"])
            snapshot = self.service._get(conn, t.snapshots, actor, run["snapshot_id"])
            events = analysis._snapshot_events(conn, actor, snapshot)
            state = self.service._optional(conn, t.agent_states, actor, run["id"])
            detail = self.service._get(conn, t.details, actor, run["incident_id"])["payload"]
            findings = [
                self.service._get(conn, t.findings, actor, fid)["payload"]
                for fid in detail["finding_ids"]
            ]
        if not state or not report["provenance"].get("cache_key"):
            raise DomainError("REPORT_CACHE_UNAVAILABLE", 409)
        current = report_cache_key(
            self.service.settings,
            snapshot,
            [e.model_dump(mode="json") for e in events],
            findings,
            state["payload"]["budget"],
        )
        if current != report["provenance"]["cache_key"]:
            raise DomainError("REPORT_CACHE_STALE", 409)
        analysis._verify(actor, events)
        return report | {
            "mode": "cached",
            "provenance": report["provenance"]
            | {"source_mode": report["mode"], "source_report_id": report_id},
        }

    def _require(self, actor: Actor, action: str, object_id: str) -> None:
        if actor.role not in {"analyst", "admin"}:
            with self.db.engine.begin() as conn:
                self.service._audit(conn, actor, action + ".denied", object_id)
            raise DomainError("FORBIDDEN", 403)

    @staticmethod
    def _review(row) -> dict:
        return ReviewRecord.model_validate(
            {
                "review_id": row["id"],
                **{
                    k: row[k]
                    for k in (
                        "report_id",
                        "claim_id",
                        "decision",
                        "comment",
                        "actor_id",
                        "created_at",
                    )
                },
            }
        ).model_dump(mode="json")

    def review(self, actor: Actor, report_id: str, payload: ReviewCreate, key: str) -> dict:
        self._require(actor, "report.review", report_id)
        request_hash = digest(payload.model_dump_json().encode())
        route = f"report-review:{report_id}"
        with self.db.engine.begin() as conn:
            if conn.dialect.name == "sqlite":
                # SQLite ignores SELECT FOR UPDATE; serialize the whole read/insert cycle.
                conn.exec_driver_sql("BEGIN IMMEDIATE")
            conn.execute(
                select(t.workspaces)
                .where(t.workspaces.c.id == actor.workspace_id)
                .with_for_update()
            ).first()
            report = self.service._get(conn, t.reports, actor, report_id)["payload"]
            previous = self.service._idem(conn, actor, route, key, request_hash)
            if previous:
                return previous
            if payload.claim_id not in {c["claim_id"] for c in report["claims"]}:
                raise DomainError("CLAIM_NOT_IN_REPORT", 422)
            row = dict(
                workspace_id=actor.workspace_id,
                id=str(uuid4()),
                report_id=report_id,
                actor_id=digest(("review-actor:" + actor.digest).encode()),
                created_at=now(),
                **payload.model_dump(),
            )
            conn.execute(t.reviews.insert().values(**row))
            result = self._review(row)
            self.service._remember(conn, actor, route, key, request_hash, result)
            self.service._audit(conn, actor, "report.review", report_id)
            return result

    def reviews(
        self, actor: Actor, report_id: str, limit: int = 50, cursor: str | None = None
    ) -> dict:
        validate_limit(limit)
        binding = ["report-reviews", report_id]
        with self.db.engine.connect() as conn:
            self.service._get(conn, t.reports, actor, report_id)
            scope = (t.reviews.c.workspace_id == actor.workspace_id) & (
                t.reviews.c.report_id == report_id
            )
            position = (
                decode(actor, binding, cursor)
                if cursor
                else [conn.execute(select(func.max(t.reviews.c.seq)).where(scope)).scalar() or 0, 0]
            )
            if len(position) != 2 or any(type(v) is not int or v < 0 for v in position):
                raise DomainError("INVALID_CURSOR", 422)
            high, after = position
            rows = (
                conn.execute(
                    select(t.reviews)
                    .where(scope, t.reviews.c.seq <= high, t.reviews.c.seq > after)
                    .order_by(t.reviews.c.seq)
                    .limit(limit + 1)
                )
                .mappings()
                .all()
            )
        selected = rows[:limit]
        return {
            "items": [self._review(r) for r in selected],
            "next_cursor": encode(actor, binding, [high, selected[-1]["seq"]])
            if len(rows) > limit
            else None,
        }

    def history(
        self, actor: Actor, incident_id: str, limit: int = 50, cursor: str | None = None
    ) -> dict:
        validate_limit(limit)
        binding = ["report-history", incident_id]
        ids = None
        offset = 0
        if cursor:
            position = decode(actor, binding, cursor)
            if (
                len(position) != 2
                or not isinstance(position[0], list)
                or type(position[1]) is not int
            ):
                raise DomainError("INVALID_CURSOR", 422)
            ids, offset = position
            if (
                not 1 <= len(ids) <= 50
                or not 0 <= offset < len(ids)
                or any(not isinstance(i, str) for i in ids)
            ):
                raise DomainError("INVALID_CURSOR", 422)
        with self.db.engine.connect() as conn:
            self.service._get(conn, t.incidents, actor, incident_id)
            rows = (
                conn.execute(
                    select(t.reports.c.payload)
                    .join(
                        t.runs,
                        (t.runs.c.workspace_id == t.reports.c.workspace_id)
                        & (t.runs.c.id == t.reports.c.run_id),
                    )
                    .where(
                        t.reports.c.workspace_id == actor.workspace_id,
                        t.runs.c.incident_id == incident_id,
                        t.reports.c.id.in_(ids) if ids is not None else True,
                    )
                    .limit(51)
                )
                .scalars()
                .all()
            )
        if ids is None and len(rows) > 50:
            raise DomainError("REPORT_HISTORY_LIMIT_EXCEEDED", 422)
        by_id = {r["report_id"]: r for r in rows}
        if ids is not None and any(i not in by_id for i in ids):
            raise DomainError("REPORT_HISTORY_UNAVAILABLE", 409)
        if ids is None:
            ids = [
                r["report_id"]
                for r in sorted(
                    rows, key=lambda r: (r["generated_at"], r["report_id"]), reverse=True
                )
            ]
            offset = 0
        selected = ids[offset : offset + limit]
        return {
            "items": [
                ReportSummary.model_validate(
                    {k: by_id[i][k] for k in ReportSummary.model_fields}
                ).model_dump(mode="json")
                for i in selected
            ],
            "next_cursor": encode(actor, binding, [ids, offset + limit])
            if offset + limit < len(ids)
            else None,
        }

    def raw_download(self, actor: Actor, object_id: str) -> bytes:
        return self.raw_download_with_extension(actor, object_id)[0]

    def raw_download_with_extension(self, actor: Actor, object_id: str) -> tuple[bytes, str]:
        self._require(actor, "raw.download", object_id)
        with self.db.engine.connect() as conn:
            obj = self.service._get(conn, t.objects, actor, object_id)
        path = self.service.archive_path(obj["storage_key"])
        if obj["byte_size"] > self.service.settings.max_upload_mb * 1024 * 1024:
            raise DomainError("RAW_DOWNLOAD_TOO_LARGE", 413)
        try:
            with path.open("rb") as stream:
                raw = stream.read(obj["byte_size"] + 1)
        except OSError:
            raise DomainError("EVIDENCE_UNAVAILABLE", 409) from None
        if len(raw) != obj["byte_size"] or digest(raw) != obj["sha256"]:
            raise DomainError("ARCHIVE_INTEGRITY_FAILED", 409)
        with self.db.engine.begin() as conn:
            self.service._audit(conn, actor, "raw.download", object_id)
        from packages.ingest.pcap_packet import MICROSECOND_PCAP_ORDERS

        extension = "pcap" if len(raw) >= 24 and raw[:4] in MICROSECOND_PCAP_ORDERS else "jsonl"
        return raw, extension

    def export(self, actor: Actor, report_id: str, format: Literal["json", "html"]) -> bytes:
        self._require(actor, "report.export", report_id)
        analysis = AnalysisService(self.service)
        with self.db.engine.connect() as conn:
            report = self.service._get(conn, t.reports, actor, report_id)["payload"]
            snapshot = self.service._get(conn, t.snapshots, actor, report["snapshot_id"])
            run = self.service._get(conn, t.runs, actor, report["run_id"])
            events = analysis._snapshot_events(conn, actor, snapshot)
            review_rows = (
                conn.execute(
                    select(t.reviews)
                    .where(
                        t.reviews.c.workspace_id == actor.workspace_id,
                        t.reviews.c.report_id == report_id,
                    )
                    .order_by(t.reviews.c.seq)
                    .limit(1001)
                )
                .mappings()
                .all()
            )
        if len(review_rows) > 1000:
            raise DomainError("EXPORT_REVIEW_LIMIT_EXCEEDED", 422)
        analysis._verify(actor, events)
        evidence = []
        total_lines = 0
        for event in events:
            item = {
                "event_id": event.event_id,
                "verified": True,
                "redacted": True,
                "fragments": [],
                "next_cursor": None,
            }
            cursor = None
            while True:
                page = analysis.evidence(actor, event.event_id, report["snapshot_id"], cursor)
                item["fragments"].extend(page["fragments"])
                total_lines += sum(
                    len(f["lines"]) + int(f.get("pcap_record") is not None)
                    for f in page["fragments"]
                )
                if total_lines > self.service.settings.report_export_max_lines:
                    raise DomainError("EXPORT_EVIDENCE_LIMIT_EXCEEDED", 422)
                cursor = page["next_cursor"]
                if not cursor:
                    break
            evidence.append(item)
        bundle = {
            "format_version": "1.0.0",
            "exported_at": now(),
            "report": report,
            "snapshot": {"scope": snapshot["scope"], "event_ids": snapshot["event_ids"]},
            "run_state": run["state"],
            "evidence": evidence,
            "reviews": [self._review(r) for r in review_rows],
            "limitations": [
                "脱敏证据投影，完整原始对象需单独授权下载。",
                "人工复核为追加意见，不改写原报告，也不等于独立实验标签。",
                "哈希仅验证归档完整性，不证明传感器或完整攻击因果。",
            ],
        }
        ReportExport.model_validate(bundle)
        raw = json.dumps(bundle, ensure_ascii=False, indent=2).encode()
        if len(raw) > self.service.settings.report_export_max_bytes:
            raise DomainError("EXPORT_TOO_LARGE", 422)
        if format == "html":
            raw = render_html(bundle).encode()
        if len(raw) > self.service.settings.report_export_max_bytes:
            raise DomainError("EXPORT_TOO_LARGE", 422)
        with self.db.engine.begin() as conn:
            self.service._audit(conn, actor, "report.export", report_id)
        return raw


def render_html(bundle: dict) -> str:
    def esc(value: object) -> str:
        return html.escape(str(value), quote=True)

    report = bundle["report"]
    parts = [
        '<!doctype html><html lang="zh-CN"><meta charset="utf-8">',
        '<meta http-equiv="Content-Security-Policy" '
        "content=\"default-src 'none'; style-src 'unsafe-inline'; "
        "base-uri 'none'; form-action 'none'\">",
        "<style>body{max-width:72rem;margin:2rem auto;padding:0 1rem;"
        "font:16px/1.6 system-ui;color:#17363b}pre{white-space:pre-wrap;"
        "overflow-wrap:anywhere;background:#f1f5f4;padding:1rem}"
        "h2{border-bottom:1px solid #cbd7d4}a{overflow-wrap:anywhere}"
        "article{margin-bottom:1.5rem}</style>",
        "<title>调查报告 · 离线脱敏导出</title><body><h1>调查报告 · 离线脱敏导出</h1>",
        f"<p>模式 {esc(report['mode'])} · 生成 {esc(report['generated_at'])}"
        f" · 调查 {esc(bundle['run_state'])}</p>",
        f"<p>{esc(report['summary'])}</p><h2>结论与引用</h2>",
    ]
    behavior_assessments = report.get("behavior_assessments")
    if behavior_assessments is None:
        parts.append("<p>历史报告未记录溯源结果。</p>")
    elif not behavior_assessments:
        parts.append("<p>本次未记录第 13.9 节的行为命中。</p>")
    for assessment in behavior_assessments or []:
        status = "溯源成功" if assessment["trace_status"] == "successful" else "溯源未成功"
        scope = " / ".join(assessment["observation_domains"] + assessment["sensor_instances"])
        parts.extend(
            [
                f"<article><h3>检测到 {esc(assessment['label'])} · {status}</h3>",
                f"<p>{esc(assessment['rule_id'])} / {esc(assessment['rule_version'])} · "
                f"{esc(assessment['start_time'])} 至 {esc(assessment['end_time'])} · "
                f"{esc(scope)}</p>",
                f"<p>溯源范围 {esc(assessment['trace_scope'])}。"
                f"{esc(assessment['trace_clue'])} {esc(assessment['trace_reason'])}</p>",
            ]
        )
        parts.extend(f"<p>{esc(text)}</p>" for text in assessment["limitations"])
        for key, label in (("evidence_refs", "检测证据"), ("trace_evidence_refs", "溯源证据")):
            for ref in assessment[key]:
                ident = esc(ref["event_id"])
                parts.append(f'<p><a href="#e-{ident}">{label} {ident}</a></p>')
        parts.append("</article>")
    progress = report.get("pipeline_progress")
    parts.append("<h2>六阶段执行状态</h2>")
    if progress is None:
        parts.append("<p>历史报告未记录六阶段执行状态。</p>")
    else:
        stage_labels = {
            "collect": "采集",
            "normalize": "归一化",
            "detect": "规则检测与标注",
            "trace": "图构建与溯源",
            "intelligence": "情报归因",
            "present": "前端展示",
        }
        status_labels = {
            "available": "输入已备",
            "running": "执行中",
            "completed": "本范围已执行",
            "partial": "部分完成",
            "failed": "执行失败",
            "cancelled": "已取消",
            "not_run": "未执行",
        }
        parts.append("<p>仅反映当前冻结快照的执行情况。</p><ol>")
        for stage in progress["stages"]:
            parts.append(
                f"<li>{esc(stage_labels[stage['stage']])} · "
                f"{esc(status_labels[stage['status']])}<p>{esc(stage['detail'])}</p>"
                f"<p>知识工具行动 {esc(', '.join(map(str, stage['action_seqs'])))}</p></li>"
            )
        parts.append("</ol>")
    comparison = report.get("investigation_analysis")
    if comparison:
        seeds = set(comparison["before"]["known_evidence_ids"])
        added = sorted(set(comparison["after"]["known_evidence_ids"]) - seeds)
        changes = comparison.get("changes", [])
        parts.append(
            "<h2>Agent 补证前后</h2>"
            f"<p>新增非种子证据 {len(added)} 条 · 有依据的判断变化 {len(changes)} 项</p>"
            f"<p>查询终止 {esc(comparison['stop_reason'])}</p>"
        )
        for eid in added:
            parts.append(f'<p><a href="#e-{esc(eid)}">新增证据 {esc(eid)}</a></p>')
        for change in changes:
            parts.append(
                f"<p>行动 {esc(change['action_seq'])} · {esc(change['before_status'])}"
                f" → {esc(change['after_status'])} · {esc(change['reason'])}</p>"
            )
        if comparison["before"].get("truncated") or comparison["after"].get("truncated"):
            parts.append("<p>判断范围已截断。</p>")
    for claim in report["claims"]:
        parts.append(f"<article><h3>{esc(claim['kind'])} · {esc(claim['statement'])}</h3>")
        for ref in claim.get("evidence_refs", []):
            parts.append(
                f'<p><a href="#e-{esc(ref["event_id"])}">证据 {esc(ref["event_id"])}</a></p>'
            )
        parts.append("</article>")
    for key, title in (
        ("alternatives", "其他解释"),
        ("gaps", "未知与缺口"),
        ("recommendations", "建议"),
    ):
        parts.append(
            f"<h2>{title}</h2><ul>"
            + "".join(f"<li>{esc(v)}</li>" for v in report.get(key, []))
            + "</ul>"
        )
    parts.append("<h2>证据目录</h2>")
    for item in bundle["evidence"]:
        parts.append(
            f'<section id="e-{esc(item["event_id"])}"><h3>{esc(item["event_id"])}</h3>'
            f"<pre>{esc(json.dumps(item, ensure_ascii=False, indent=2))}</pre></section>"
        )
    parts.append(
        "<h2>完整报告、快照、版本及人工复核</h2><pre>"
        + esc(json.dumps(bundle, ensure_ascii=False, indent=2))
        + "</pre></body></html>"
    )
    return "".join(parts)
