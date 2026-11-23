# D8 Implementation Plan

> **For agentic workers:** Use superpowers:executing-plans inline; one fresh whole-change review after implementation.

**Goal:** 完成规约D8预算/限流/错误、六规则冻结与划分核验、引用/谓词校验及降级缺证展示。
**Architecture:** 复用0005_d6及不可变快照；新增有界API限流、有限谓词校验摘要、独立eval清单核验和配置冻结。没有新数据库表或依赖。
**Tech Stack:** Python/Pydantic/FastAPI/SQLAlchemy，React/TypeScript，pytest/Playwright。
**Spec:** PROJECT_SPEC.md；docs/02-data-contracts.md、03-detection-graph.md、04-agent.md、05-api-ui.md、06-execution-plan.md、07-evaluation.md。

## Global Constraints
- 仅授权本地合成数据，无攻击执行/公网扫描/外部模型调用。
- workspace/snapshot/lease、不可变证据和历史报告保持；Agent不能读取eval。
- 单调查工具6/模型4/规划2；input12000/output3000/wait60s/wall90s只可缩小。
- 所有新接口/权限/恢复/谓词必须正反测试；不声称真实LLM或独立测试集指标。

## Review Focus
1. 并发限流、拒绝请求不产生业务写入、角色/工作区互不挤占。
2. 真实ID搭配相反字段、bool/int混淆、伪路径与未检索证据不能变事实。
3. 一次修复和耗尽仍受累计预算、拒绝原因持久化且无恶意文本泄漏。
4. 派生链/重复原始哈希跨split、循环或缺失父项、路径逃逸必须拒绝。
5. 缺证/partial与完整通过的区别、旧报告缺字段兼容、冻结配置漂移可检出。

## Tasks
- [x] T1 API: tests/integration/test_d8_api.py RED→GREEN；apps/api/{limits,errors,main}.py及Settings实现每身份read/write窗口额度、统一安全错误和request ID；不新增数据库schema。
- [x] T2 Agent: tests/contract/test_d8_validation.py与integration/test_d8_agent.py RED→GREEN；严格谓词类型/引用支持字段，持久报告ClaimValidation摘要；修复后/失败后均可审计。根据实际R01–R06生成建议与替代解释，解决D7已知措辞问题。
- [x] T3 Evaluation: tests/contract/test_d8_evaluation.py RED→GREEN；eval清单契约/派生组与哈希隔离核验，33计划运行清单+既有开发夹具索引；rules/freeze.json冻结解析后配置摘要；开发六规则正反与地址变换回归；不运行正式test。
- [x] T4 UI: 缺证与拒绝/降级专用面板，沿用安全文本渲染、证据按钮与类型生成；D8浏览器正反闭环测试。
- [x] T5 验收: check-d8脚本，完整Python/PG/浏览器/前端检查；一次独立审查及重要问题修复；运行/验收/契约/变更文档更新。

## Interfaces / pre-flight
T1以现有Actor(workspace_id,id,role)识别；HTTP错误仍error{code,message,request_id,details}，增加Retry-After。
T2 Report新增可选claim_validation；老报告不回算。T4使用生成类型消费，显示有限谓词验证不等于攻击归因正确。
T3 eval只离线读夹具和配置，不进入API/Agent；freeze由检测入口检查当前默认配置，历史reproduce沿用已存配置。

## Rulings
- Ruling: 按用户明确要求直接执行现有规约，在本文件记录细化选择；当前无Git，不创建仓库/提交/工作树，保留此执行台账。
- Ruling: 项目已迁到D:/挑杯（应用项目目录及D7文件已核对），在原项目继续；写入使用沙箱授权，不复制旧目录。
- Ruling: 限流采用单API进程、线程安全、有界身份窗口，默认读120/分钟写20/分钟；重启重置，不能宣传分布式配额；Agent预算仍持久化。
- Ruling: D8冻结当前开发阈值且核查划分机制；33次运行清单保留planned状态，正式采集/双人标注与测试指标依D9–D12完成，不能虚构独立验证。

## Evidence ledger
实施前读取当前规约、D7边界和核心代码；.venv Python可运行，.git不存在。

T1: 3 tests RED (missing Settings/limiter/request header) → GREEN 3 passed.
T2: strict predicates/rejection summaries/report guidance RED → GREEN 18 passed incl D6.
T3: inventory/freeze RED missing modules → GREEN 58 incl R03–R06. Matrix fixture corrections: R04失败认证仍保留访问attempt，负例应移除管理连接；R02负例须深拷贝以免地址变换二次污染正例。不改变检测器语义。
T4: browser RED confirmed missing 缺证与校验 region; implementing component.
Ruling: 自由模型claim未通过有限谓词时统一显示未知，不原样发布未核实身份断言；原稿仍属行动审计，替代解释/缺口保持待人工复核标签。代价是减少自由语言细节，以免未知标签掩盖注入性事实。

T4: 浏览器RED缺少region → GREEN 1 passed（14.4s）；已查看缺证截图。六规则地址变换矩阵12 passed；六谓词完整正反矩阵及严格float/超长Content-Length回归17 passed。全量检查正在执行，结果另记。

## Final independent review

一次fresh-context只读审查发现2 Important，无Critical/Minor；不再派发复审。fix pass：
- auth asset_id缺失被字符串None冒充：正反回归RED已复现，增加非空条件。
- 当前原始证据不可验证却显示历史校验完成：真实React组件SSR+浏览器断言RED已复现；改以当前report.validation优先显示警告，历史摘要保持原样，不伪称调查未完成；补集成测试验证存储报告未修改、恢复原文件后重新通过。

Final: Ruling: 单进程/重启重置/无匿名限流、请求体可先于认证解析，保留原型边界；额度保证业务写入前拒绝，不宣称DoS防护。代价是扩为多进程或暴露公网需另行限流层。
Final: Ruling: 身份桶满拒绝新身份，避免驱逐绕过旧额度；代价是活跃身份多时暂时拒绝新身份。
Final: Ruling: 自由claim规范unknown、受限原稿留analyst审计、替代解释和缺口安全文本且待复核；代价是自动报告语言细节少且仍需人工判断。
Final: Ruling: 老报告可无claim_validation，不回算；历史校验记录与当前原始完整性分开，代价是旧记录信息较少。
Final: Ruling: 冻结无签名、隐瞒谱系/语义近重复需人工核查；代价是不能防项目管理员同时改配置/锁或虚假声明。
Final: Ruling: 33项planned/3个prepared不算已执行独立实验；真实LLM/知识/生产采集/导出/完整归因留后续；代价是D8只证明受控工程闭环，不能宣称已完成全部P0效果验收。
Final: Ruling: 独立审查未重复跑全量测试；由本主执行者保存实际结果，不称双重独立测试背书。

Final fixes: 两个Important均RED→GREEN；test_auth_asset_predicate_requires_a_present_matching_asset正反及集成合计22 passed（13.15s），D8浏览器/真实组件回归2 passed（14.8s）。最终完整验收正在执行，含所有既有回归，不再派发复审。


T5: complete — 最终Python277 passed107.96s；仅测试导入空行和SSR夹具Report类型修正后Ruff/format/pip/前端全部通过；PG90 passed101.60s；D3–D7各1、D8 2浏览器断言通过（六条端到端+一项组件回归）。最终remaining进程exit0，PGstop exit0 server stopped。完整实际命令与中途门禁失败如实记于d8-verification，不再重跑已经覆盖的测试。
Final: fixed auth missing-asset None — 正反测试RED→GREEN，完整Python277/277。
Final: fixed read-time integrity versus historical validation — 真实组件RED→GREEN，D8 2/2，完整Python277/277及PG90/90。
Final: no deferred minors. 使用finishing-a-development-branch流程核对完成；无Git/分支或工作树，按项目约定原地保留代码、文档及执行台账，不初始化Git、不发布或发送外部消息。
