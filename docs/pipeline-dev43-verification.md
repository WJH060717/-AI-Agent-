# 六阶段执行状态 dev43 验证记录

日期 2026-11-26。本轮完成六阶段规约 M4 的执行状态展示和记录。应用 0.1.0.dev43，数据库 head 0006_d9。

## 改变的行为

Report 和 RunStatus 新增可选 pipeline_progress，固定采集、归一化、规则检测与标注、图构建与溯源、情报归因、前端展示六阶段。
状态表示当前冻结快照的执行过程。输入已备、执行中、本范围已执行、部分完成、失败、取消及未执行分别呈现。
图和 finding 复现、原件核验完成后，通过 Queue.guard 和 checkpoint 保存 pipeline_prepared，记录规范事件数和图/路径裁剪。取消和失败保留终止前阶段，已完成核验不会倒退，排队取消不会显示图已运行。
知识状态依据全部同 run 工具行动，未查询保持未执行，任一缺失/失败/裁剪保留限制。
新报告在现有发布事务中保存进度，最终运行状态复用同版报告，JSON/HTML 和网页读取同一结果。
历史报告缺该字段时保持缺省，页面和 HTML 显示未记录。完整快照图与 Agent 已核查事件范围分别说明。

## 涉及模块

packages/contracts/models.py、api.py 及生成类型提供严格契约。
packages/agent/pipeline.py 投影状态，state.py 保存终止前阶段。
packages/storage/analysis.py 在受控事务中保存前置事实并发布报告；reports.py 渲染导出。
apps/web/src/PipelineProgress.tsx、ReportPanel.tsx、Investigation.tsx 展示实时及最终状态。
新增契约和集成测试覆盖真实队列取消、历史兼容及导出一致性。

## 验证

新增16项针对性测试通过，独立审阅复跑同样通过。前端类型生成、typecheck、lint 和生产构建通过。
初版已保留知识裁剪、多查询覆盖及取消归属的失败回归，按独立审阅修订后通过。
首次前端构建发现生成类型的默认数组可选，已处理缺省并通过构建。
最终固定源码相关回归 **191 passed，0 failed，0 skipped**，115.75 秒，前后源码摘要一致。保留1条既有 Starlette/httpx 依赖弃用警告。
最终隔离浏览器报告流程 **1 passed**，6.4 秒，核验六条状态、知识未执行、证据、导出、复核及历史读取，截图已人工检查。
最终回归（本地归档 `../artifacts/pipeline-dev43-01/regression-final.xml`） · 输入摘要（本地归档 `../artifacts/pipeline-dev43-01/test-inputs.json`） · 浏览器日志（本地归档 `../artifacts/pipeline-dev43-browser-02/playwright.log`） · 页面截图（本地归档 `../artifacts/pipeline-dev43-browser-02/report.png`）。


## 限制与阶段范围

本轮展示执行事实，具体溯源是否成功沿用 behavior_assessments 与逐条证据。知识阶段完成只表示查询返回，组织归因仍需独立证据。
验证使用隔离 SQLite、回环模型协议桩或模型 disabled。新增付费模型调用为0。既有服务的部署版本以独立部署记录为准。
M1 独立多源材料、M2 逐类抓包有限判断、M3 新 socket 采集适配和 M5 可选 IOC 仍需后续完成。历史验收成绩按原版本保存。
