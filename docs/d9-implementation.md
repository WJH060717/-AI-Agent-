# D9 Implementation Plan

> **For agentic workers:** Use superpowers:executing-plans inline; one fresh whole-change review after implementation.

**Goal:** 按既定D9规约完成报告导出/审计、逐条复核、费用预算与缓存版本键、数据清单冻结和三线工程演示。
**Architecture:** 保留不可变报告/快照，0006_d9仅增加复核表；报告导出服务独立于控制器。缓存为同一报告的显式历史视图，不新建推理或改写原件。评估清单只在离线eval侧冻结。
**Tech Stack:** 现有Python/Pydantic/FastAPI/SQLAlchemy与React/TypeScript，无新增依赖。
**Spec:** PROJECT_SPEC.md；docs/02-data-contracts.md、04-agent.md、05-api-ui.md、06-execution-plan.md、07-evaluation.md、08-deployment-demo.md。

## Global Constraints
- schema_v1–v5与0001–0005冻结；原始对象、旧报告和快照不修改。
- 所有Agent写入经Queue.guard；费用调用前预留，失败/中断不退款；恢复检查配置。
- 导出和复核限analyst/admin，跨工作区404，权限拒绝和下载留审计；HTML安全转义。
- 缓存显示cached与原生成时间，输入replay维度独立，不宣称真实LLM。
- 33项planned与现有prepared不冒充采集完成或双人标签复核，不向运行时代码导入eval。

## Review Focus
1. 缓存跨快照/配置漂移、旧报告无缓存键、证据损坏不得命中。
2. HTML/复核恶意文本和原始对象路径逃逸，不得泄露秘密或执行脚本。
3. 并发幂等复核、外工作区引用、分页新增记录后固定水位不漂移。
4. 费用预算边界、失败/恢复不退款、定价缺失拒绝付费模型调用。
5. 清单冻结发现漂移、缺标签/复核仍明确未完成，三场景只报告实跑证据。

## Tasks
- [x] T1 报告/复核/下载：新增tests/integration/test_d9_reports.py与契约正反测试，RED→GREEN。新增schema_v6/0006；contracts/reports.py、storage/reports.py与API路由。review使用claim_id/decision/comment与幂等键；追加不改report。报告历史与复核列表使用actor绑定签名固定水位分页。JSON/HTML含引用目录/快照/版本/模式/人工记录；raw下载以对象ID解析且校验哈希。
- [x] T2 费用/缓存/配置：tests/integration/test_d9_agent.py和contract/test_d9_cache.py RED→GREEN。类型化USD微元费用/每百万token定价；持久预留与usage展示。发布绑定快照、事件内容/定位、规则、模型、prompt、工具/图/模板/知识、预算哈希；GET report?mode=cached核对当前版本及原始完整性，缓存不调用模型。管理员安全配置摘要不返回URL/密钥/路径。
- [x] T3 清单工程门禁：tests/contract/test_d9_inventory.py RED→GREEN；eval/freeze.py与冻结文件保存现有runs、输入hash和规则hash；核查33项资料/标签状态，缺失如实列出，新增数据需显式新版本。实际采集与双人复核仍未完成。
- [x] T4 前端/演示：ReportPanel.tsx展示版本、逐条复核、脱敏JSON/HTML下载、历史cached及费用；沿用文本渲染。浏览器测试三演示线S1/S2/S3含缺证、下载离线打开与XSS反例。
- [x] T5 验证：生成契约、check-d9、全量Python/Ruff/TS/构建、PG迁移与集成、三线浏览器；一次独立审查修复重要问题；更新README/契约/运行说明/验收台账。

## Interfaces / pre-flight
- T1→T4：ReviewCreate/ReviewRecord/ReviewPage/ReportPage/ReportExport由Pydantic生成；前端不另造字段。
- T2→T1/T4：缓存为GET /reports/{id}?mode=cached，仍返回Report；provenance存cache_key；预算Used新增兼容默认费用字段。
- T3→T5：eval.freeze仅离线使用，不接API/Agent，不产生实验指标。

## Rulings / evidence ledger
- Ruling: 用户已要求根据现有规约完成D9，直接执行，不重复请求设计授权。没有Git仓库，不初始化、不提交、不建工作树；执行证据保留在本台账。
- Ruling: Windows默认沙箱进程启动失败；经受控授权执行本地项目读写/测试，不触碰外部服务。
- Ruling: 33次独立资料和双人标签复核尚不存在；实现冻结/检查门禁并保留未完成状态，不制造采集或人工签字。三线使用现有明确合成夹具验证工程行为，不能替代S1真实采集或真实LLM验收。

## 执行与独立审查
- T1/T2：接口/费用/缓存RED→GREEN，与D6受控Agent回归20 passed；额外配置/并发/缓存边界15 passed。并发SQLite复核采用BEGIN IMMEDIATE，PG保留工作区行锁。
- T3：冻结完整性3 passed；资料ready实际exit2，明确33planned/3prepared/0双人复核。
- T4：三线浏览器RED缺面板→实现后实际HTML文件打开→3 passed。S1进一步增加告警与后段计数，后端37事件通过；R06不重叠则独立候选，绝不调整冻结规则强拼故事。
- T5预审：全量303 Python通过、静态/类型/构建通过、PG及历日浏览器继续验证。
- 一次fresh只读整体审查：2 Important（共享证据读取缺根目录检查、刷新后viewer无法打开历史报告），1 Minor（第51份报告破坏已有游标）；无Critical。
- Final Ruling: 将分页项提升为Important，因为新增记录令合法冻结游标失效，违反固定目录行为；纳入同一修复轮。没有额外评审席位或复审。
- Final fix RED：缓存/导出/证据读取的绝对路径与父目录逃逸6项及50→51分页1项均实际失败；Windows默认文件符号链接权限不足，补用真实目录junction验证相同解析边界，不能把skip算通过。
- Final Ruling: 审查未独立重复全量/PG/浏览器，测试结果由主执行者存档；无Git基线按当前文件审查，不能断言每行的引入时间。
- Final Ruling: 仅证明异常归档映射会越界，不宣称普通API用户可以修改映射或完成攻击；修复所有共享读取入口。真实LLM/费用账单/33份人工资料继续保留未验收，不以协议桩替代。
- Final fix GREEN：路径边界9项通过（含真实Windows junction，无skip），固定50→51目录通过；viewer刷新后载入历史报告与缓存的单场景浏览器通过。
- Final fix：补验暂停期间执行代码漂移，先复现继续调用模型/发布新缓存键，再将代码指纹纳入持久配置哈希；费用/缓存定向13 passed（7.54s），历史未终结运行升级保守降级。
- 全链路复验曾得到313 Python / 110 PG通过、D3–D8浏览器通过，D9为2 passed/1 failed：测试在异步创建数据集结束前记下旧ID，刷新后错误选中S1。改为等待新数据集选中，不放宽历史报告断言，继续完整三场景复验。
- 最终：314 Python / 111 PG / 10浏览器全部通过，静态/类型/构建通过；D9三线联跑39.6s。资料ready仍exit2。PG已正常停止，源码与证据保留本地，详见d9-verification与d9-build-manifest。
