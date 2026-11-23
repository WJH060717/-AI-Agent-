# D9 验收记录

日期：2026-11-15；目录D:/挑杯；无Git仓库，因此没有提交标识。沿用D8锁定依赖，无新增依赖、业务库清理或对外调用。

## 已执行的开发验证

- 报告/复核/下载3项先以缺少路由404失败，后通过；费用/缓存3项先以缺字段/未区分cached失败，后与D6 Agent回归共20 passed（42.89s）。日志d9-t1-red、d9-t2-red、d9-t2-green。
- 清单冻结3 passed；`--require-ready`为独立资料门禁，不与冻结完整性混淆。
- 并发复核新增回归复现SQLite忽略行锁导致幂等唯一键冲突，采用BEGIN IMMEDIATE后，报告/配置/缓存边界15 passed（7.15s）。PG使用工作区行锁。
- 首轮D9浏览器3项因缺少报告面板失败；实现后因测试打开无扩展名下载临时文件被浏览器视为文本而失败。改为实际保存的HTML附件后3 passed（38.5s），验证真实API/worker、追加复核、JSON/HTML、离线引用与恶意HTML转义、cached原时间。
- 首次全量Python为1 failed、301 passed（163.02s）：唯一失败是健康契约仍预期stage=d8，已随D9版本更新；不把该次运行记为全绿。最终结果待下节填写。
- S1补入安全告警与后续出站计数，新增后端三源演示测试1 passed（1.27s）。R06保持独立事件组，未改检测/聚合规则以迎合演示。
- 一次独立审查发现共享证据读取根目录检查、viewer历史入口及固定目录分页问题，均经失败回归后修复；路径9项包含真实Windows目录junction，无跳过。
- 收尾补验暂停期间的执行代码漂移：旧实现继续调用，修复后恢复降级且不发布新缓存键。费用/缓存定向13 passed（7.54s）。
- 全链路中间轮313 Python / 110 PG通过；D9浏览器2 passed/1 failed，原因为测试提前记录异步创建前的数据集ID，刷新错误选择S1。修复等待条件后进行最终复验，不把单场景通过代替三线联跑。

## 需求对应

| 需求/用例 | D9验证入口 |
|---|---|
| REQ-005 / TC-025～027 | test_d9_agent、test_d9_cost及既有取消/恢复/超时用例 |
| REQ-006 / TC-028～030 | d9.spec.ts三线报告/复核/离线HTML，XSS纯文本与引用目录 |
| REQ-007 / TC-031～035 | test_d9_reports角色/工作区/并发幂等/固定分页/不可变原报告/证据损坏 |
| REQ-008 / TC-040受限子集 | 精确历史缓存、三线合成材料；不等同独立实验或完整8分钟现场验收 |
| T-22/资料门禁 | test_d9_inventory，0人工复核、33planned如实拒绝ready |

## 交付文件与行为

| 文件 | 改变行为 |
|---|---|
| packages/storage/schema_v6.py、migrations/versions/0006_d9.py、infra/roles.sql | 新增只追加复核表；迁移与应用角色权限边界 |
| packages/contracts/reports.py、evidence.py、api.py、agent.py、models.py及generated | 导出/复核/历史/配置契约、费用字段与生成类型 |
| packages/storage/reports.py、service.py、analysis.py、apps/api/main.py | 带权限审计的导出/下载/复核、固定历史分页、共享归档根目录验证 |
| packages/agent/cost.py、cache.py、state.py、runtime.py、packages/config.py、.env.example | 费用持久预留、恢复版本核对、精确历史缓存、安全配置摘要 |
| apps/web/src/ReportPanel.tsx、Investigation.tsx、AgentHistory.tsx、client.ts、main.tsx | 报告引用、逐条复核、下载、费用与历史入口 |
| eval/freeze.py、dossiers.json、freeze-d9.json | 离线冻结与资料就绪检查；不接入Agent运行时 |
| scripts/build_d9_fixture.py、browser_d3.py、check-d9.ps1、test_postgres.py | 明确合成的三线材料、浏览器与工程门禁 |
| tests/contract/test_d9_*、tests/integration/test_d9_*、apps/web/tests/d9.spec.ts | 权限、完整性、幂等、恢复、预算、冻结、离线HTML正反回归 |

## 验收范围

工程演示使用本地真实API/worker、只读工具和明确标记的HTTP协议桩；不等于真实LLM推理验收。S1的37个规范事件覆盖网络/主机/安全告警，后段R06仍为独立候选，缺socket不拼接完整攻击因果。S2正常进程仅context_only；S3保持partial与缺证。

33项planned、3个prepared开发输入包（同一开发谱系组）、0个双人人工复核。资料ready门禁实际exit2。真实采集、真实LLM及供应商账单、正式评估、知识条目、Compose/干净环境发布和8分钟现场彩排未验收；本次不生成这些指标或签字。

旧迁移和原始证据不回写；只在隔离PG实例的新随机数据库执行升级测试。没有Git仓库，不初始化/提交/推送；源码与验收证据通过本地SHA-256清单定位。失败日志中pytest自动打印的一次性测试令牌已脱敏，保留失败断言和计数。

## 最终结果

- `./scripts/check-d9.ps1 -Browser`：**exit0**；Python **314 passed，186.77s**；Ruff通过、195文件格式通过；pip check无依赖冲突；契约生成、TypeScript、ESLint及Vite生产构建通过。D3–D7各1项、D8两项、D9三项，合计**10项浏览器用例通过**；D9三线联跑39.6s，含viewer刷新后打开原数据集的历史报告且零POST调查。日志：`artifacts/d9-final-engineering.log`。
- `.venv/Scripts/python -m scripts.test_postgres`：**111 passed，164.25s**。PostgreSQL16.16新随机测试库，D2→D9迁移保留哨兵工作区；应用角色DDL、reader写入/秘密读取、复核更新/删除均被拒。日志：`artifacts/d9-final-postgres.log`。
- `.venv/Scripts/python -m eval.freeze --require-ready`：**exit2**，data_collection_complete=false、labels_review_complete=false，符合现有资料状态。冻结完整性核验成功。日志：`artifacts/d9-readiness-gate.log`。
- 项目包与API版本均为0.1.0.dev9；未新增依赖。隔离PG实例已由`pg_sandbox stop`正常停止，保留数据库及本地文件。日志：`artifacts/d9-pg-stop.log`。
- 独立审查的两项Important与提升后的分页项均已修复；审查不替代主执行者的回归记录。没有未处置的本次审查缺陷。
- S1/S2/S3脱敏JSON、离线HTML和页面截图保存在`artifacts/d9-browser/`；成功运行已清理临时浏览器trace，结果目录仅保留.last-run.json。浏览器脚本退出时关闭自己的API/worker/Vite/协议桩。
- `artifacts/d9-build-manifest.json`记录本次源码/契约/锁文件/合成材料/验收证据的SHA-256与实际生成时间；仅作本地可追溯清单，不是独立实验结果或发布签名。
