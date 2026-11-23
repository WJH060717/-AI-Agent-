# D12 Implementation Plan / 执行台账

> 执行方式：superpowers:executing-plans，当前工作区内逐项实施，最后一次独立整体复核。

**目标：** 完成规约 D12 的完整备份恢复入口、资源/指标/失败/调查成本分析和可复算证据包。
**规约：** PROJECT_SPEC.md；docs/06-execution-plan.md D12；docs/07-evaluation.md；docs/08-deployment-demo.md §6。
**架构：** 运维离线命令在数据库写锁和排空检查下备份整库及引用对象，只恢复至空库和新目录；离线分析读取哈希固定的原始实验结果，保留各轮失败与未知。运行中 Agent 不读取 eval。
**技术：** 现有 Python/Pydantic/SQLAlchemy、PostgreSQL 16 pg_dump/pg_restore、SQLite 开发适配、SVG/HTML 静态证据页；不新增依赖或迁移。

## 全局约束与决定

- Ruling: 用户已授权按既定规约连续构建；沿用当前目录、内联执行，不重复征求设计批准。无 Git，保留台账和内容摘要，不创建仓库或提交。风险：分支隔离由不可覆盖候选及原始工件代替。
- Ruling: 备份恢复使用停止 API/worker 后的运维命令，并以数据库写锁及非终态作业检查再次防护；不实现新的在线维护 API。仅处理本地授权数据；不覆盖既有库/目录。风险：需要运维者停止服务，停机期间不可用。
- Ruling: D11 历史性能可按当时冻结版本复算，D12 不把它宣传为新版本性能；保留所有三轮、包括未达目标的第二轮。正式标签/真实模型缺失继续阻断，不制造 F1、误报率、供应商费用或人工评分。风险：本次工程分析不能回答正式效果优劣。
- Ruling: 本机自动恢复验证不能代替非部署作者验收，TC-036 保留该未完成条件。风险：跨机器/非作者运维问题需 D13 实际验收。

## Task 1：完整备份与空环境恢复

文件：scripts/backup.py、scripts/backup_contracts.py、tests/contract/test_d12_backup.py、scripts/recovery_d12.py。
接口：create_backup(settings, destination) -> manifest；verify_backup(folder) -> manifest；restore_backup(settings, folder) -> verification；命令 backup/create、verify、restore。

- [x] 先写正反测试：整库/原始对象一致，旧报告不变，新调查可运行；非空目标、排队作业、损坏/缺失对象、路径逃逸、版本不符均拒绝。
- [x] 实现数据库写锁、同一快照 dump、文件摘要/行数/高水位、无密钥配置副本；恢复后核验所有数据表和证据引用。
- [x] SQLite 测试通过；独立 PostgreSQL 源库→新空目标库真实演练，保存脱敏 JSON 证据及实际时长。

## Task 2：可复算分析与展示

文件：eval/analysis_d12.py、eval/d12-inputs.json、tests/contract/test_d12_analysis.py。
接口：build_analysis(root, input_manifest, output) -> summary；verify_analysis(root, output) 重算比较。

- [x] 先写正反测试：失败/partial/blocked 都进入分母，零分母与缺标签 null，预留/使用/实际账单区分，缺失/篡改输入拒绝。
- [x] 分组逐次耗时 p50/p95、费用/token/失败率；全轮性能与 CPU/内存曲线；按证据生成失败案例和正常替代解释，未经标签不称误报。
- [x] 固定文件清单含历史源码/截图，输出 JSON、CSV、HTML、SVG；相同输入可逐字节复算。

## Task 3：候选与验证归档

文件：D12 runbook/limitations/verification/acceptance/defects、scripts/check_d12.py、release_manifest 与版本标记。

- [x] D11 证据原件先保全，冻结规则/迁移不变。
- [x] 全部 Python、必要 PostgreSQL、前端检查及候选启动/恢复证据通过；独立整体复核并修复重要问题。
- [x] 创建不可覆盖 D12 候选与证据清单，完整 P0 状态如实保留。

## Review Focus

1. 正在写入或排队时备份，必须一致或明确拒绝；不能生成看似完整的备份。
2. 空目标判断、数据库/路径别名、符号链接、残留部分恢复，绝不覆盖用户资料。
3. dump 内的令牌摘要/HMAC 密钥与原始对象只能留受控本地备份，不能进入公开证据工件。
4. 历史性能的失败与代码版本漂移必须显示，不能择优或冒充当前性能。
5. 无标签/无真实模型账单/空组等统计缺口必须显示未知，不能用 0 或成功率填充。

## Evidence ledger

预检：已读 README、PROJECT_SPEC、AGENTS、D12 排期及评估/恢复规约。Task1 产出恢复验证给 Task3；Task2 产出哈希固定分析供 Task3；历史 D11 输入仅只读消费。

Task 1：11项SQLite正反测试通过（缺模块RED→实现→修正实际publication字段GREEN）；真实PG16.16演练28表/32事件/1旧报告一致，新调查completed，既有目标拒绝。1.52s备份/1.65s恢复是小夹具记录，非性能承诺；原始记录artifacts/d12-recovery-01。
Task 2：统计4项测试RED→GREEN；单次调查记录缺失测试RED→新增可选离线字段GREEN，2项真实管线测试通过。费用在无报告情况下仍记预算，避免失败费用被忽略。
Task 3：D12候选/必检项4项测试RED→GREEN；全部D11候选311文件和原证据219项摘要核对一致，原文档先保存在artifacts/d11-source-preserved。无迁移或规则阈值变化。独立复核与全量检查进行中。

独立整体复核（gpt-6-astra，fresh context，只读）：3项Important，无Critical。单次修复：数据库URL覆盖与PG环境在访问前拒绝（4个URL RED→GREEN）；失败后持久预算/单次耗时由finally留存，B3观察重试，B2失败停止（B2/B3 RED→GREEN，另验证真实Queue退避≥2s）；空/删减分析不能过门禁，输入清单也纳入冻结（空分析RED→GREEN）。针对性29项全通过，随后补充PG服务下实际写锁与新目录/非空库拒绝恢复，均通过。

Final: Ruling: 将复核提出的未知内存误画零及TC-038旧门禁表述按证据准确性处理，在同一次修复内纠正；无需增加新产品功能。PG非空库分支测试属于恢复目标修复的验证。风险：若不修，会让证据图和验收文字误导读者。
Final: Ruling: 复核未判断的真实LLM/标签/非作者/Compose保留现有P1；最终冻结与回归在本轮完成后另核验；恶意本地并发替换、加密和跨用户ACL仍限于文档中可信停机运维模型，不宣称额外防护。风险：不能将该备份工具用于不可信共享目录或远程上传恢复。
首轮全量预检405 passed / 1 failed，失败是旧health断言仍d11；已同步d12并单独复验通过。未修改任何规则/迁移/阈值。旧历史导入失败0ms改按未测处理而非低延迟，失败分母保留；早期D11缺input_unchanged元数据只记未知，未升级为通过。

Task 1/2/3 complete（工程范围）：最终422/123/6 Python/PG/browser通过，19项检查exit0，strict实际exit2。后续发现候选缺两份D11回归文档，独立候选RED→补打包GREEN；候选01/check01保留为superseded，候选02汇总器路径冲突已修复，候选03有测试import格式问题；最终以候选04完整验收为准。静态分析页面/资源图及最终浏览器截图人工视觉核验，无密钥/原始dump分发。所有Ruling见前文；未创建Git/远程提交。
