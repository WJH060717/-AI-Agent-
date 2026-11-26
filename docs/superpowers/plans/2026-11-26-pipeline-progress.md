# 六阶段执行状态实施计划

用户已授权按六阶段规约继续改造。本轮落实 M4 的运行状态及报告展示。
设计依据为 PROJECT_SPEC 第14节及 2026-11-25-tracex-agent-pipeline-design.md。

## 契约

Report 与 RunStatus 新增可选 pipeline_progress。结构含固定版本和按 collect/normalize/detect/trace/intelligence/present 排列的六条 stage。
stage 含 stage、status、detail、action_seqs。状态为 available/running/completed/partial/failed/cancelled/not_run。
available 表示固定快照输入已备，不证明全部采集完成。completed 限于本快照执行，不能表示溯源成功或完整检测覆盖。
源记录核验、finding 复现和图计算通过后，经 Queue.guard 和 checkpoint 追加 pipeline_prepared 标记，保存规范事件数及图/路径裁剪。状态投影依据该标记，终止前阶段另存 pipeline_terminal_phase，避免只由当前 phase 猜测已完成工作。
知识阶段依据同 run 全部持久工具行动的真实结果；未调用为 not_run，任一缺失/失败/裁剪保留 partial，全部失败保持 failed。后续成功不自动消除此前限制。
新报告在现有 guard 发布事务中保存完整进度。历史报告缺字段保持缺省。最终 run 状态优先读取原报告进度。
运行中进度由同一事务读取 run/state/snapshot/actions，失败与取消保留终态，报告发布前不显示展示完成。

## 任务

- [x] 添加固定六阶段的严格 Pydantic 契约和纯计算器，覆盖无模型、知识未查询、部分结果、失败取消和错误阶段顺序。
- [x] 接入 get_run 和新报告持久化，验证旧报告缺省、恢复和范围权限，JSON/HTML 一致。
- [x] 前端展示状态、说明和历史缺省，图区明确完整快照与 Agent 已知集合范围。
- [x] 生成类型、静态检查、后端回归、前端构建及隔离浏览器验证，记录限制。

不涉及规则判据调整、迁移或新增模型调用。应用版本更新 dev43，保留 dev42 原始工件。

最终工程证据见 ../../pipeline-dev43-verification.md。独立审阅提出的三项状态问题已修复并通过16项专项复验。
