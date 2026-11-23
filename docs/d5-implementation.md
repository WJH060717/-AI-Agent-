# D5 Implementation Plan

> For agentic workers: Use superpowers:executing-plans inline; test each change before implementation, one final independent whole-change review.

**Goal:** 可追证的最小事件聚合、稳定分页、入口候选与有界事件级路径，接通调查/模板/页面。
**Architecture:** 延用单库与冻结快照。增加不可变incident详情/目录及目录head；事件发布序号固定分页可见性。路径由已支持身份/五元组关系投影，存入不可变报告。
**Tech Stack:** 现有Python/Pydantic/SQLAlchemy/Alembic/FastAPI、React/TypeScript/Vite，不加依赖。
**Spec:** PROJECT_SPEC.md；docs/02-data-contracts.md；docs/03-detection-graph.md §§3–6；docs/05-api-ui.md；docs/06-execution-plan.md D5。

## Global Constraints

- 授权本地数据，不执行攻击、不联网采集、不调用模型。
- schema_v1/v2/v3冻结，新增0004_d5；不重写历史报告/快照/事件。
- 写入继续经workspace锁和Queue.guard；权限、租约、幂等、引用边界不可裁剪。
- 路径最多500事件/1000边、30分钟、6跳、beam20/top3；当前调查继续最多250事件。
- 不将IP/PID/同名账号/ATT&CK或时间接近当作身份或因果的充分证据。
- 无Git仓库，复用当前目录，不初始化Git、不提交远程；台账与测试结果留在本文件及验收文档。

## Review Focus

1. 合并链条不越过30分钟；同IP但不同强身份/观测域不能串联，旧目录与旧调查可继续读取。
2. 同时间数据、晚到数据与新目录切换不会让旧分页重排/漏页；游标跨令牌/作用域/路由必须拒绝。
3. 正常上下文不能单凭时间接近成为种子攻击路径；时间重叠、反序、PID/boot复用不得补边。
4. 纯扫描或缺session/socket的场景返回证据不足/断点；失败认证不能投影为远端成功。
5. 所有路径边/入口引用都属于冻结快照；候选裁剪、左右截断、启发式分数必须解释，历史报告不可改写。

## Task 1: 聚合与稳定列表

Files: packages/storage/schema_v4.py, migrations/versions/0004_d5.py, packages/detection/aggregation.py, packages/storage/incidents.py, packages/storage/paging.py, service.py, worker.py, analysis.py；tests/contract/test_d5_aggregation.py, tests/integration/test_d5_paging.py。

Interfaces: aggregate_findings(findings, events) -> list[dict]；CatalogService.publish(conn, actor, dataset, session, findings, events)；incident_page(actor,dataset,session,limit,cursor) -> items/next_cursor；list_events相同签名，新增可见发布序号。

- [x] 先测试：同强资产且窗口相交合并；仅同源IP/不同域/不相交不合并；乱序/重复输入结果稳定；30分钟上限。
- [x] 运行上述测试观察缺实现失败，再实现确定性分组、成员/理由与0004迁移。
- [x] 测试目录新版本/晚到事件不改变旧页；同时间按ID；游标篡改/换scope/令牌失败；旧单finding调查兼容。
- [x] 实现不可变目录+head、事件publication与共享签名游标；列表默认50/max100，按时间/ID。
- [x] 验证相关测试全绿；空库/0003升级保留原数据。

## Task 2: 证据支撑的入口和路径

Files: packages/contracts/models.py, packages/graph/paths.py, graph/service.py, storage/analysis.py；tests/contract/test_d5_paths.py, tests/integration/test_d5_analysis.py。

Interfaces: analyze_paths(events,scope,seed_ids) -> PathAnalysis；Report.path_analysis可选以兼容旧报告；Report.paths/candidate_origins保留ID数组；GET调查paths返回冻结结果。

- [x] 先测试网络→成功认证→会话进程→子进程的逐边证据；纯扫描无路径、失session/弱进程/时间重叠/反序断点；与种子无关联组件不得当攻击路径。
- [x] 测试稳定top3、6跳/beam20上限、拒绝越界/缺引用、入口分类与left_censored、同PID/不同boot不串联。
- [x] 实现固定投影、严格时间有序beam search、启发式分解/支持度、未选路径及差异、断点；不添加纯precedes/suggests因果边。
- [x] 调查复现全部成员finding，仅用各自原证据；报告原子存储路径结果和成员版本，旧报告不变；验相关正反例。

## Task 3: API、页面与复验

Files: packages/contracts/api.py, apps/api/main.py, apps/web/src/Investigation.tsx, Intake.tsx；scripts/build_d5_fixture.py, browser_d3.py, check-d5.ps1；apps/web/tests/d5.spec.ts；docs/d5-runbook.md, d5-verification.md及规约补充。

- [x] API契约测试先验证incidents分页、snapshot timeline分页、graph边分页/focus、paths权限与错误态。
- [x] 实现接口和生成类型；页面展示聚合理由、时间线、候选入口、top3/断点、边解释和逐条证据；不同分页状态请求可取消。
- [x] 生成安全合成三源/两规则/父子路径夹具与反例，不从真值读取答案。
- [x] 执行SQLite全量、PostgreSQL受限角色/迁移、R01/R02/D5浏览器；独立审查后以失败回归修复重要问题。
- [x] 同步README/AGENTS/CHG-005/运行手册/验收台账，停止自己的测试实例。

## Rulings / 台账

Ruling: 继续用户已指定的D5规约并在当前目录实施，不重新开启技术选型或设计审批；细化接口作为兼容增量记录。
Ruling: D5最小聚合采用“同观测域、共同强实体且finding时间窗相交”，确定性连通合并并限制总跨度30分钟；非相交finding凭显式边聚合留T-11后续。聚合只表示共同调查范围，不证明同一操作者或攻击。
Ruling: 入口缺完整采集覆盖声明时left_censored=true；unknown保留，外部地址仅作网络入口候选。未实现进程socket适配时进程→网络保持断点，不从最近进程猜测。
Ruling: 图分页保留完整有界节点集，边按稳定ID分页；快照时间线按(event_time,event_id)；事件列表以publication高水位、候选队列以不可变目录固定范围。
Pre-flight: 聚合详情finding_ids供调查逐项复现；catalog版本供队列分页；publication只在整批发布时递增；路径DTO进Report后由API生成类型，不另写前端契约。

Task1 complete: 聚合6项、分页5项，相关正反例先失败后通过；发布/创建序号固定可见范围，旧目录继续读取。
Task2 complete: 路径14项、调查API2项及升级契约1项通过，覆盖真实6跳长链、最早入口、坏证据和历史报告。
Task3 verification: check-d5.ps1 →104项、Ruff120文件、依赖/生成/类型/lint/build全通过；PostgreSQL34项；D3/D4/D5 Chromium均passed。
Final fixed: 独立审查Important“早记录遮蔽精确事件对”→test_additional_observations_cannot_hide_exact_session_or_parent_evidence RED→GREEN；保留所有合法认证/父进程配对并提前限制边数。
Final Ruling: 强主机/boot/session/parent显式身份继续按docs/02契约关联，不额外强制同传感器域；网络推断仍同域。若真实采集资产UUID或出生依据不可信，需在采集侧补验证，不能靠域名或时间猜测。
Final Ruling: 聚合跨度严格小于30分钟，为半开快照末端留空间；入口按目标/域最早根观测归并，不把每条孤立扫描称入口；图分页保留有界完整节点集，coverage仅为链内。较完整的跨段聚合/采集/场景验证留后续。
Final review: 一轮独立只读审查，重要项已修复，无minor待处理。无Git环境保留本计划作为实施台账，不删用户目录。
Final completion: README/AGENTS/CHG-005/契约说明/运行手册/验收记录同步；临时库实际运行manage migrate打印0004_d5；便携PG已停止。
