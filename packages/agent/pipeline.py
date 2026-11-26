"""Project persisted execution into snapshot-scoped stages without model decisions."""

from packages.contracts.models import PipelineProgress, PipelineStage


def progress_for_run(
    event_count: int,
    phase: str,
    state: str,
    actions: list[dict],
    report_ready: bool = False,
    graph_truncated: bool = False,
    *,
    prepared: bool = False,
    terminal_phase: str | None = None,
) -> PipelineProgress:
    verified = report_ready or prepared
    input_status = "completed" if verified else "available"
    trace_status = "completed" if verified else "not_run"
    if prepared and phase in {"planning", "querying", "checking"}:
        trace_status = "running"
    if verified and (graph_truncated or state == "partial"):
        trace_status = "partial"
    present_status = "not_run"
    if phase in {"drafting", "validating"}:
        present_status = "running"
    if report_ready:
        present_status = "partial" if state == "partial" else "completed"
    if state in {"failed", "cancelled"} and not report_ready:
        if terminal_phase in {"drafting", "validating"}:
            present_status = state
        elif prepared and terminal_phase in {"preparing", "planning", "querying", "checking"}:
            trace_status = state

    knowledge = [a for a in actions if a["kind"] == "tool" and a["name"] == "get_technique_context"]
    intel_status = "not_run"
    intel_detail = "未查询本地知识，家族与操作者归因仍需独立证据。"
    if knowledge:
        completed = [a for a in knowledge if a["status"] == "completed"]
        failed = [a for a in knowledge if a["status"] in {"failed", "rejected", "abandoned"}]
        pending = [a for a in knowledge if a not in completed and a not in failed]
        limited = bool(failed)
        for action in completed:
            result = action.get("result_payload") or {}
            limited = limited or bool(
                set(result.get("warnings", [])) - {"KNOWLEDGE_CONTEXT_ONLY"}
                or result.get("truncated")
                or not result.get("data", {}).get("items")
            )
        intel_status = "partial" if limited else "completed"
        intel_detail = "本地知识查询已返回；条目用于技术解释，现场证据及归因另行核验。"
        if failed and not completed and not pending:
            intel_status = "failed"
            intel_detail = "知识查询失败或中断，保留原行动结果。"
        elif pending:
            intel_status = state if state in {"failed", "cancelled", "partial"} else "running"
            intel_detail = "知识查询仍有未完成行动，保留已返回条目的覆盖限制。"
        elif limited:
            intel_detail += " 存在缺失、失败或裁剪，后续成功未覆盖此前限制。"

    return PipelineProgress(
        stages=[
            PipelineStage(
                stage="collect",
                status=input_status,
                detail=(
                    "当前快照原件引用已核验，范围限于选定事件。"
                    if verified
                    else "固定快照已建立，原件核验尚未记录。"
                ),
            ),
            PipelineStage(
                stage="normalize",
                status=input_status,
                detail=f"当前快照含 {event_count} 条规范事件；物理记录数按各来源另计。",
            ),
            PipelineStage(
                stage="detect",
                status=input_status,
                detail=(
                    "本次成员 finding 已按保存规则复现；检测总覆盖由会话限制另行说明。"
                    if verified
                    else "已有成员 finding，等待本次调查复现。"
                ),
            ),
            PipelineStage(
                stage="trace",
                status=trace_status,
                detail=(
                    (
                        "完整快照图与候选路径按确定性规则计算；Agent 仅在已知集合内补证。"
                        if verified
                        else "图计算与 Agent 补证尚未记录完成。"
                    )
                    + (" 图或路径有裁剪。" if graph_truncated else "")
                    + " 执行状态不代表溯源成功，具体结果见各项行为结论。"
                ),
            ),
            PipelineStage(
                stage="intelligence",
                status=intel_status,
                detail=intel_detail,
                action_seqs=[a["seq"] for a in knowledge][-6:],
            ),
            PipelineStage(
                stage="present",
                status=present_status,
                detail=(
                    "已保存当前快照的不可变报告，页面与导出读取同版结果。"
                    if report_ready
                    else "报告尚未发布。"
                ),
            ),
        ]
    )
