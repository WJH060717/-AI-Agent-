# D6验证记录｜2026-11-14

本次范围：REQ-003/004/005/006/007的D6纵向子集，任务T-10、T-14～16、T-18/20/23的相关部分。实现者为当前编码助手，另有一次独立代码审查；没有团队人工签字、Git提交或远程合入（当前目录不是Git仓库）。真实LLM及整个P0未验收。

## 实际执行结果

| 命令 | 本次实际结果 |
|---|---|
| `.venv/Scripts/python -m pytest -q` | 最终169 passed，78.68s；SQLite隔离测试，含实际HTTP桩及子进程退出 |
| `.venv/Scripts/python -m scripts.test_postgres` | 最终PostgreSQL16.16，69 passed，75.39s；随机测试库，应用受限角色；D2→D6迁移保留旧workspace |
| `.venv/Scripts/python -m ruff check .` | All checks passed |
| `.venv/Scripts/python -m ruff format --check .` | 成功，无需格式修改 |
| `.venv/Scripts/python -m pip check` | No broken requirements found |
| `npm run typegen`、`npm run typecheck`、`npm run lint`、`npm run build` | 全部成功；Vite8.3.8构建19个模块 |
| `.venv/Scripts/python -m scripts.browser_d3 --day6` | 1 passed，18.1s；真实API/worker/React/Chromium及本地HTTP协议桩 |
| `.venv/Scripts/python -m scripts.browser_d3 --day5` | 1 passed，12.3s；原D5聚合/路径/证据闭环兼容 |
| `.venv/Scripts/python -m scripts.browser_d3 --day4` | 1 passed，9.8s；原三源R02闭环兼容 |
| `.venv/Scripts/python -m scripts.browser_d3` | 1 passed，7.0s；原R01模板闭环兼容 |

全量169包含PostgreSQL运行的69项集成用例，不将两者简单相加称238个不同用例。并发运行耗时是本机记录，不是性能基准。命令入口scripts/check-d6.ps1按D1–D6组合导出契约、检查和可选数据库/浏览器验证。

## 测试覆盖与证据

| 门禁 | 正向 | 反例 / 故障 |
|---|---|---|
| R03、R04（TC-010～015相关） | 强父子异常；R02/R03资产上下文、管理连接、B成功认证；冻结配置复现 | 正常allowlist、弱身份、异scope/boot/域、逆序/时钟重叠、歧义IP、端口/认证不符；缺认证仅attempt |
| 六工具（TC-021/022、031～036相关） | 真实快照检索/证据/进程/时间线/路径，知识ID空响应；长事件证据22片段翻页且≤16KB | scope注入、跨工作区/incident/事件、越时间、未知字段/操作、limit/depth超限、游标换actor/参数、坏hash |
| 模型与校验（TC-023～027相关） | 本地HTTP JSON协议、usage、plan→2不同工具→draft；模板化真实谓词 | 非JSON、重复JSON key/非有限值、HTTP/重定向、usage不合规、未知shell、伪ID、真实ID相反事实、伪路径、真实身份归因；修复仍计预算 |
| 状态与恢复 | 持久阶段/转换、行动预留→结果、同run缓存；实际worker os._exit(29)后真实租约等待恢复 | 零/不足调用与token/等待预算；取消晚响应无报告；未决预留不退；过期validating不能完成；租约丢失关闭HTTP |
| API/页面 | analyst调查、行动及转换分页、模式/预算/补证数/证据展示 | viewer不能读行动、跨作用域游标、预算放大/非法输入拒绝；测试桩标签和令牌/原始账号不出页面 |

主要源码用例：tests/contract/test_d6_rules.py、test_d6_model.py、test_d6_validation.py；tests/integration/test_d6_tools.py、test_d6_agent.py、test_d6_api.py、test_d6_rules_pipeline.py、test_d6_review.py；apps/web/tests/d6.spec.ts。

## 独立审查及修复

最终独立审查指出3项重要边界问题，均先以失败回归复现，再修复并纳入上述169/69结果：

1. HTTP慢滴流让socket超时不断续期，线程外层超时后请求仍占连接。改为独立可终止传输进程及子进程超时退出；真实慢滴流总超时、主动取消、租约失效关闭连接均验证。
2. 恢复到planning后切换模型/endpoint仍可调用，provenance可能沿用旧配置。改为每个非终态步骤核对配置摘要；恢复后新旧endpoint均未收到请求，结果partial并记录MODEL_CONFIGURATION_CHANGED。另以失败回归修复报告读取新模型名称的问题：run创建时冻结不含密钥的provider/name/test_stub，发布时始终使用该元数据，旧状态缺字段显示unknown而不冒认当前配置。
3. 模型上下文遗漏incident、工具参数、next_cursor/truncated/coverage/warnings；后续裁剪也会整块删除结果，导致重复第一页。现在保留控制元数据、优先压缩数据与事实；实际HTTP桩按游标取第二页，2次工具补回2个事件。

另有一项较小问题：纯格式非法的technique ID/过滤参数在执行阶段才检查，拒绝前曾进入检查点/行动。将这些校验提前到持久化前，保存通用拒绝摘要；回归确认private-marker不进入状态/行动。审查未证实真实密钥泄漏，本次按不可信参数留存边界一并修复，不扩大为新的检索功能。

未再发起循环审查。范围决策见[d6-implementation](d6-implementation.md)：auto关闭模型兼容确定性完成；live失败partial；只验证JSON协议桩；调用预留保守扣减；R04不补socket因果。没有遗留已确认的重要审查项。

## 可复现输入与界面产物

data/fixtures/d6/manifest.json包含development/synthetic来源说明及每文件SHA-256。context_sha256为`e7fb18f763787e6a8e7090fc2fe9292b289c03dbba3879e1e20179eefb86b051`；四份正例共38物理行→35规范事件，最终5finding/一个聚合组；正常反例另建数据集不触发。真实算法不读取eval/ground_truth或夹具答案。

浏览器产物：artifacts/d6-browser/closed-loop.png、playwright.log、services.log、results/.last-run.json。已查看截图：阶段/预算、search_events/get_event_evidence、补充证据1条、协议桩标签、报告和哈希核验证据抽屉可见。截图与后台HTTP/行动持久化测试共同佐证，不用截图替代执行记录。

本地协议桩不是LLM，不评价生成质量或准确率；R04保留process_socket_binding缺口；知识库未加载；没有成本金额、生产吞吐、真实身份归因或独立测试集成绩。本次验证不替代后续真实模型、现场采集、干净Linux环境及竞赛发布验收。

验证结束已执行scripts.pg_sandbox stop，输出server stopped；保留测试数据目录，没有删除随机测试库或业务数据。浏览器脚本已退出其自行启动的API/worker/Vite及协议桩。
