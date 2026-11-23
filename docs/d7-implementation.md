# D7 Implementation Plan

> Use superpowers:executing-plans inline and test-driven-development; one independent whole-change review at the end. Continue the user's specified D7 scope in the current workspace. No Git repository/commits or external model calls.

**Goal:** 接入R05/R06，按固定快照完成缺口补证、正常替代解释/反证处理和有界停止，页面展示可追溯的前后变化。
**Spec:** PROJECT_SPEC.md；docs/03-detection-graph.md §2 R05/R06；docs/04-agent.md；docs/06-execution-plan.md D7；docs/07-evaluation.md TC-014/015/021/026。
**Architecture:** 复用D6的JSON状态、租约guard、只读执行器和不可变报告。R05/R06输出冻结配置与统计；R06基线随不可变DatasetContext保存。程序按已知证据集合生成有界结构化assessment，模型在现有工具中自主补证；报告保存before/after/changes及终止原因。
**Stack:** 现有Python/Pydantic/SQLAlchemy/FastAPI、React/TypeScript；不新增依赖或外部服务。

## Design and approaches

沿用六个只读工具及固定谓词，在模型可见上下文中增加可补证缺口和判断摘要。没有采用让模型自由创建因果/反证结论的方案，因为程序无法证明任意自然语言蕴含；没有增设图数据库或训练器，现有250事件快照足够完成此纵向闭环。接口和UI沿用已有工作台，增设补证前后面板。

- R05：同workspace/dataset/session/domain/source-channel及源资产或端点→目标IP/port/transport，去重排序；1200秒有界滑窗，≥8条、考虑时钟误差的跨度≥300秒、CV保守上界≤0.15。保留原CV与误差上界、正常心跳解释，不合并独立传感器凑阈值。
- R06：UTC对齐300秒连接起始桶；唯一资产映射的Zeek originator→responder bytes_out，合计≥10,000,000字节。该值是连接计数归桶，不是逐秒传输速率。正常开发参考窗口至少30个、同资产/domain/channel、全部早于当前桶，nearest-rank p95，严格>3倍才为outbound_volume_anomaly；基线不足为fixed_threshold_signal，充分基线未超过则无R06候选。不把响应方向/未知资产算出站。
- Baseline：管理员在首次导入前配置历史开发参考窗口，含起止、bytes_out、来源hash、版本/度量说明；不读取eval/ground_truth，不在线拟合测试集，不宣称声明hash已被独立验证。重复/重叠/未来窗口不进入有效基线；相同资产通道不得配置歧义基线。
- Assessment：仅使用种子+当前已取回的快照事件；R02会话→进程只能按既有强关联核验。R05监控/R06备份进程以同强资产、同窗配置路径作为context_only反向线索，使恶意用途假设weakened，仍保留缺socket/授权/内容断点。无结果不证明没有发生；模型不能自行把假设升级。
- Before在首次preparing时冻结，After随checking更新；变化保存证据ID、原因及工具行动序号。停止理由独立于失败stop_reason，区分模型请求成稿、无新增证据、规划轮上限与缺口已补；次数/token/时间上限不放宽。旧报告缺新可选字段保持原样。

## Tasks / completion contracts

### Task 1 — Rules and baseline contract

Files: contracts/context.py；detection/r05.py,r06.py,registry.py,common.py；rules/R05.json,R06.json；storage/analysis.py；tests/contract/test_d7_rules.py、test_d7_baseline.py；tests/integration/test_d7_rules_pipeline.py。
- [x] RED：8次/5分钟/CV阈值与抖动、时间误差、跨传感器/域/资产、重复/乱序；10MB/3×p95边界、30正常窗口、缺基线/高基线备份、错误方向/歧义IP/历史时间；冻结配置复现及旧规则不变。
- [x] GREEN：实现可复现统计、不可变基线输入及当前目录/报告接入；JSON/生成契约同步。
- [x] Verify：上述用例及D3–D6规则集成通过，正常反例不被强判攻击。

### Task 2 — Gap assessment and persisted evidence changes

Files: contracts/investigation.py、models.py；agent/assessment.py,state.py,runtime.py,validation.py；rules/investigation.json；storage/analysis.py；tests/contract/test_d7_assessment.py；tests/integration/test_d7_agent.py。
- [x] RED：种子未知→两个工具补证→会话关系支持/正常解释削弱；异资产/boot/时间及只有无关文本不能反证；伪ID/模型文本不能改assessment；相同快照before不变，缓存/重启不重复变化。
- [x] GREEN：冻结判断配置，已知证据集合限定，最多20判断、100缺口/40变化并显式截断；模型上下文给有界缺口，保留D6游标/预算元数据；报告可选typed comparison。
- [x] RED→GREEN：零预算不调用；无新增两次、两规划轮、主动draft、预算耗尽、取消/租约恢复均有限终止且明确原因；periodicity_observed仅可引用已验证R05 finding。
- [x] Verify：D6状态机、scope/预算/晚响应及新正反例均通过。

### Task 3 — API/UI/demo and final verification

Files: API/contracts生成类型；apps/web补证前后面板及证据；scripts.build_d7_fixture、model_stub协议桩、browser_d3 --day7、check-d7.ps1；docs/CHG-007/runbook/verification。
- [x] RED→GREEN：真实API返回typed comparison、viewer脱敏只读与跨workspace拒绝，历史报告兼容；浏览器两个工具、前后变化/反向线索/终止原因及证据可点击，测试桩明确非LLM。
- [x] 全量pytest、受限PG迁移/权限/集成、Ruff/pip、前端生成类型/typecheck/lint/build、D3–D7浏览器；一次独立最终审查，重要问题先失败后修复，不循环复审。
- [x] 同步README/AGENTS/设计与运行文档、实际结果及限制，停止自建测试实例。

## Review focus

1. 不能把不同source-channel、资产、观测域凑成周期/出站量；源端资产与计数方向必须明确。
2. 基线必须是足够、同作用域、早于当前窗口的固定正常开发参考；无基线不能冒充p95异常；重放不得换基线影响旧finding。
3. 正常进程只提供上下文反向线索，不能据时间接近推断socket归属或宣布无攻击；空查询也不能否定事件。
4. before只用seed、after只用seed+真实检索；新数据不改变快照；恢复/缓存不重复记变化或重获预算。
5. 附加缺口/判断不能挤掉D6分页元数据或突破上下文预算；UI引用、对比与旧报告权限一致。

## Rulings / ledger

Ruling: 用户已明确要求按现有规约实施D7，沿用现有技术选型与当前目录，不重开审批或创建Git；若规约理解有误，以本文件显式阈值和验收用例便于纠正。
Ruling: R05用1200秒有界滑窗、R06用UTC固定5分钟连接起始计数桶；上限保留快照容量，代价是不能宣称连续流量速率或全时段检测。
Ruling: R06基线作为管理员冻结的正常开发参考输入，仅实现同资产基线；角色共享/自动学习不做。基线来源可信度须由团队另行核验，规则不把管理员声明变司法事实。
Ruling: 反证用可核查强关系或context_only正常解释，后者只削弱恶意用途假设，不作无攻击证明；代价是保留较多未知项。
Ruling: 不改冻结schema_v1–v5；新结构保存在现有JSON与Report可选字段，不需要无意义的新表。真实LLM、知识条目与整体P0/发布验收继续待后续。

Ruling: 对比契约并入现有models.py而不反向导入新contracts/investigation.py，以避免EvidenceRef/Report循环依赖；状态辅助独立evidence_state.py。每个判断最多5个缺口，因此20判断上限对应100缺口，40条变化上限保持。代价是主契约文件更长，后续拆分须统一基础契约。

Pre-review checks: R05/R06与基线首批46测试通过；新增assessment及状态集成通过。已以失败回归修复空基线改变旧context哈希、冻结policy仍读当前文件、模型上下文缺反向线索ID、R06 finding未绑定baseline_hash和三倍p95浮点边界；均已GREEN。浏览器先因缺补证面板失败，接入后D7完整闭环通过。

Ruling: 最终审查要求R05按连续重叠命中合并，1200秒保留为达标判定窗，合并候选段跨度严格<1800秒以兼容快照上限；更长活动有界分段。整体统计与达标窗口统计分开，代价是不能把超长活动当一个可无限扩展的调查或将整体CV用于单窗阈值。

Final: fixed R05前置噪声/同刻事件遮蔽有效连续后缀 — test_r05_earlier_noise_or_tie_does_not_hide_later_valid_contiguous_segment RED→GREEN；内部不规则记录不能被删除。
Final: fixed 重叠窗口占满判断上限 — test_r05_continuous_overlapping_windows_merge_with_auditable_bounded_witnesses RED→GREEN；90条/1780秒合为1finding，2个覆盖全段的达标窗口，assessment只有1判断且不截断；整体CV>阈值的合并反例另验证不冒充单窗。
Final: fixed 正常进程引用缺关键投影字段 — test_countercontext_evidence_shows_safe_process_fields_and_hides_commands_accounts_extensions RED→GREEN；真实哈希投影可查executable/出生标记，命令/账号/任意扩展不泄露，EOE不伪造进程字段。
Final: minor (deferred): R05/R06通用模板建议仍有扫描措辞，后续细化；不改变规则、结构化补证或引用。
Final: Ruling: 审查未报的context_only、连接起始桶、admin声明基线、known-ID集合对比、有限循环与真实LLM/知识条目后续边界继续按上述范围成立；这些是受限原型能力，不能升级为无攻击证明、实时流量速率、独立基线核验或真实模型效果。

单次修复的针对性用例43 passed，完整套件最终复验见d7-verification；无重要项延期，无循环复审。保留本记录，因为当前没有Git历史可替代它。
