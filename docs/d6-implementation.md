# D6 Implementation Plan

> Use superpowers:executing-plans inline, test-driven-development per task, one independent final review. Continue the user's approved D6 scope in this workspace; no Git repository or remote operations.

**Goal:** 持久Agent状态机、兼容JSON模型适配、受控只读工具与工作区/快照/预算门禁，接入R03/R04并完成正反例。
**Spec:** PROJECT_SPEC.md；docs/04-agent.md；docs/03-detection-graph.md R03/R04；docs/06-execution-plan.md D6。
**Architecture:** 延用Queue.guard/租约与不可变快照；新0005_d6/schema_v5增加Agent检查点、转换、模型/工具行动。模型只提出严格结构化决策，工具从真实快照查询，事实仍由程序谓词校验与模板生成。
**Stack:** 现有Python/Pydantic/SQLAlchemy/FastAPI、React；兼容模型用标准库HTTP，不加远程框架/训练。

## Global constraints

- 不执行攻击、任意shell/SQL，不上传原始日志或密钥；本次只调用本地模型协议测试桩，不冒充真实LLM验证。
- schema_v1–v4和旧报告/快照保持；新迁移、作用域过滤和所有持久写入继续经租约guard。
- 每run最多6工具、4模型、2轮规划、输入12000/输出3000 token、模型单次≤20秒/累计≤60秒、总≤90秒；客户端只可缩小预算。
- 工具超时≤3秒、响应≤16KB、limit≤100；模型不可覆盖scope；未知工具/参数拒绝且耗调用预算。
- 模型重试/修复和中断未完成调用也消耗预算；取消/租约失效后的晚响应不可发布。
- 图/路径缺进程socket证据不补跳，R04只称资产级跨主机访问候选。

## Task 1 — R03/R04

Files: detection/r03.py, r04.py, common.py, registry.py；rules/R03.json,R04.json；tests/contract/test_d6_rules.py。
- [x] 先测R03明确强父子异常/正常allowlist、弱PID/boot/反序/不同scope；R04有可疑源会话/进程+唯一A/B映射+匹配远端成功认证，缺证只attempt或不适用。
- [x] 实现固定版本配置与证据ID/支持finding快照，复现使用原配置，保持R01/R02 ID不变。
- [x] 通用候选标题/报告/成员复现接入；三源R03/R04集成正反例。

## Task 2 — 受控工具与模型协议

Files: contracts/agent.py, agent/executor.py, model.py, validation.py；保留D2 ReadOnlyTools兼容接口；tests/contract/test_d6_model.py, tests/integration/test_d6_tools.py。
- [x] 严格六工具参数Schema/字段操作符白名单；执行器只从run真实workspace/dataset/session/snapshot加载；scope注入、越权、未知参数、时间、数量、输出分页与哈希测试先失败后实现。
- [x] 兼容模型plan/draft严格JSON；限制输出、禁重定向/隐式重试、校验usage、超时与token累计；真实HTTP本地桩验证，不调用外部模型。
- [x] 事实谓词验证真实字段/引用；observed句由程序渲染，真实ID反向事实/伪ID/伪路径拒绝；自由文本仅未知/待人工复核解释。

## Task 3 — 可恢复状态机

Files: storage/schema_v5.py, migration0005_d6；agent/runtime.py；storage/analysis.py/queue.py；config/env/contracts API；tests/integration/test_d6_agent.py。
- [x] 持久queued/preparing/planning/querying/checking/drafting/validating/degraded/terminal，版本/原因/预算/行动摘要可查询。
- [x] 外部操作前持久预留调用数/token/时间；返回后guard再提交；中断恢复不退预算，不重复完整工具查询，连续2次无新证据/规划2轮/预算到达停止。
- [x] live兼容模型经两个不同工具补证再draft；模型禁用/非JSON/超时/不合规降级partial；单次修复也计费。
- [x] 跨工作区、快照、预算收紧、重启、取消晚响应、租约fencing、注入文本、结果≤16KB正反例。

## Task 4 — API、页面与验收

Files: API investigations新增mode/budget，status/phase与tool-calls；Web阶段/预算/模式/行动摘要；scripts.build_d6_fixture、browser_d3 --day6、check-d6；运行手册/CHG-006/验收。
- [x] API契约/角色/幂等/行动分页，生成类型；页面区分真实模型、测试桩和fallback。
- [x] 默认旧auto+disabled继续显式确定性完成（兼容D3–D5）；live即使模型禁用也创建run并partial，不伪造live成功。
- [x] PostgreSQL受限角色/迁移、全量pytest/前端、旧闭环及D6实际HTTP桩浏览器验证；最终独立审查、测试先行修复重要项。
- [x] 文档标明真实LLM/模型费用/生产采集未验证；停止自己的测试实例。

## Review focus

1. 嵌套工具参数、游标和模型日志不能越scope或泄露密钥/原始命令；模型响应不可信。
2. 预留后断进程/取消/晚响应必须fencing，失败调用不能重获预算；缓存只限同run/snapshot/tool/args。
3. token/时间边界和真实硬超时，供应商不提供usage时保守降级，不无限重试。
4. R03/R04正常运维/缺session/弱进程/NAT/同IP与跨realm不伪造成功或进程socket绑定。
5. 真实ID但错误谓词/恶意文本不能变observed；测试模型桩不得显示成真实LLM推理。

## Rulings / ledger

Ruling: 沿用已有规约和用户指定D6目标直接实施，不重新要求技术选型审批；无Git沿用当前目录。
Ruling: auto+disabled保留旧确定性完成语义并标fallback；显式live或已配置模型失败走degraded→partial。兼容旧演示，同时不把失败模型当完成。
Ruling: 模型协议采用明确的JSON兼容chat/completions子集，标准库HTTP、无自动重试/重定向；本次真实传输只验证本地测试桩，生产LLM与计费留用户配置后验证。
Ruling: 新调用先预留次数/token/等待，失败/重启未决调用保守扣预留；成功usage有效才结算，不假定崩溃时请求未发出。
Ruling: R04源绑定限强可疑会话/进程所在资产A的上下文，不能证明该进程发起socket；无远端成功认证只能remote_access_attempt，不称横向移动成功。

Review outcome: 完成一次独立最终审查。三个重要项（硬超时后连接存活、恢复配置漂移、上下文缺分页/incident元数据）均以失败回归复现并修复；配置漂移另涵盖报告元数据冻结。纯格式非法参数较晚拒绝为较小项，按不可信留存边界一并修复，不宣称已证实密钥泄漏。无重要审查项延期，无循环复审。真实LLM、知识条目、socket因果与整体P0仍按上文范围留后续。
