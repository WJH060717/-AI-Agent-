# 02｜遥测、证据与数据契约

## P2 行为检测与溯源结果

Report 新增可选 `behavior_assessments`。每条绑定既有 finding、规则版本、观测时间和采集范围，附检测证据、溯源状态、范围、线索、原因及独立溯源引用。空数组表示本次未记录第 13.9 节行为命中，历史报告可省略。字段仅由已复现规则与已验证快照生成。迁移保持 0006_d9。

## D8已实现增量（CHG-008）

Report新增可选ClaimValidation（finite_predicates@2.0.0、integrity、validated_observed、unknown_claims、rejected_codes≤2、repair_attempts≤1、stop_reason）；旧报告不重算。FactPredicate.values保留string/int/bool类型集合但不允许浮点等隐式类型转换；谓词校验进一步逐字段限制。无schema迁移，head仍0005_d6。 详情见[d8-runbook](d8-runbook.md)。

## D7已实现补充（CHG-007）

DatasetContext新增可选egress_baselines：同资产/域/Zeek通道的固定正常开发参考，最多10组，每组≤120个互不重叠且UTC对齐300秒窗口，含来源声明hash/版本/度量。实际检测仅用当前桶之前的窗口，少于30个不作p95异常判断。空字段不进入旧context规范化字节，保留D4–D6哈希重试兼容；已有context不可更改。

R05 finding保存合并候选段的整体statistics及qualifying_windows端点/统计，整体CV不代替单窗阈值；R06另含冻结baseline/baseline_hash并绑定ID。NormalizedEvent维持1.1，数据库head0005_d6保持，没有修改冻结schema_v1–v5。

Report新增可选investigation_analysis：config_hash、before/after的known_evidence_ids/hypotheses/gaps、action_seq绑定changes、stop_reason。当前最多20判断/100缺口/40变化，裁剪显式truncated；旧报告不回填。类型定义与Report共同置于models.py以避免循环依赖。Agent检查点JSON冻结判断配置及初始已知证据，更新随行动结果在guard事务中提交。Linux audit证据增加嵌套process安全投影（可执行文件/动作/PID/出生字段），不包含命令、原始账号或任意扩展，长字段明确裁剪。

## D6已实现补充（CHG-006）

新迁移0005_d6/schema_v5，在冻结v1–v4之上增加agent_states（run检查点与CAS版本）、agent_actions（调用预留/结果/摘要/usage）和只追加agent_transitions。全部绑定workspace/run，行动序号及转换版本稳定分页；外部调用前与完成后均检查作业lease/version。取消/失败同步终态并封存未决行动；旧报告不改写。

严格工具/模型输入见packages/contracts/agent.py，API输出见contracts/api.py；未知字段拒绝。预算客户端只能缩小，input按请求UTF-8字节数保守预留、有效供应商usage结算，失败/中断保留预留。保守计数不是费用统计。报告provenance记录模型配置摘要、prompt/Agent版本、实际模式、usage及protocol_test_stub标签，不存密钥或原始命令行。

NormalizedEvent结构保持1.1；R03/R04 finding附冻结规则配置及支持finding/事件ID，R04另含missing_steps及资产候选解释，复现仍使用原证据与配置。当前目录由当前规则结果发布，历史attempt/成员/目录仍可读取；远端认证晚到后不会把旧attempt继续混进最新目录。

## D5已实现补充（CHG-005）

0004_d5增加数据集创建序号、session事件发布序号及不可变incident成员详情/目录；head仅指向最新目录。旧事件payload/快照/报告和HMAC密钥保留。队列新增finding_ids和有来源的aggregation_reasons；列表页绑定创建/发布高水位或目录版本，同时间以ID稳定排序。

Report新增可选PathAnalysis：scope、入口、top3路径、未选候选、事件边、断点、裁剪与方法版本。事件边保存精确from/to事件、entity_edge_ids、原始EvidenceRef、observed/inferred及分数分解；现有paths/candidate_origins保留ID数组。旧报告缺此字段时不重算；旧引用兼容。服务端私钥签名分页游标绑定actor/工作区/路由/scope，旧游标请刷新；私钥不得用用户可计算的令牌摘要替代。

## D4已实现补充（CHG-004）

以下为当前可运行子集；后文仍包含未来完整设计。NormalizedEvent接受1.0/1.1，1.1增加可选host(asset_id,boot_id)，旧字段及原始引用不变。实现源码在packages/contracts/context.py、ingest/linux.py、ingest/identity.py；完整输入见data/fixtures/d4与d4-runbook。

- 数据集先POST不可变DatasetContext，明确资产UUID、hostnames、IP/观测域半开有效区间、传感器实例/账号realm/时钟偏移与误差。Linux无绑定拒绝；网络无绑定沿用旧端点语义。工作区私有随机HMAC密钥单独保存，不进API、检查点、报告或reader权限。
- auth最小协议为结构化UTF-8 JSONL，有offset的timestamp和已绑定host。user.uid产生realm作用域的HMAC身份；用户名仅脱敏展示，不用于强合并。成功会话键含asset+boot+session，失败记录不造成功会话。
- audit按资产+boot+serial+时间分组，单上传内交错及500行恢复；每个物理片段独立引用。完整exec需SYSCALL+EXECVE+EOE，create/observe需SYSCALL+EOE；不完整EOF标partial_audit并降为弱进程。同原生ID但规范语义冲突的后续片段全部隔离NATIVE_ID_CONTENT_CONFLICT，原事件不改写。
- 批次新增raw_records（已消费物理行）、aggregated_records（进入合法规范事件的物理行）；accepted/duplicate按规范事件出现次数。终态raw_records=aggregated_records+quarantined；执行中还可能有pending行，不能混成事件守恒式。
- 证据响应新增next_cursor，每页最多20物理行。保留每段对象/哈希，游标绑定工作区、快照、事件及当前令牌；仅返回经哈希校验的白名单脱敏投影。

HTTP旋转文件manifest与跨批次未闭合组拼接、任意原生日志格式、完整T-07异常夹具仍未交付；后文完整目标不能解读成这些能力已经实现。

## 1. 输入范围与采集策略

| 输入 | P0 使用字段 | 获得方式 | 缺失影响 |
|---|---|---|---|
| Zeek conn JSONL | ts、uid、五元组、duration、orig/resp_bytes、conn_state | 授权实验 PCAP 离线解析或固定夹具 | 失去网络连通证据 |
| Suricata EVE JSONL | timestamp、event_type、flow_id、五元组、alert | 同一 PCAP 的规则告警 | 失去签名旁证，不直接否定攻击 |
| Linux audit 结构化 JSONL | host、boot_id、audit_serial、pid/ppid、exe、uid、会话；适配器补充start标识及采集依据 | audit多记录聚合；强身份需采集侧生命周期信息 | 失去进程与会话关联 |
| Linux auth 结构化 JSONL | host、时间、账号、来源、成功/失败、session | 已知格式适配，未知格式隔离 | 不能把连接当成功登录 |
| 资产清单 CSV | asset_id、网段、IP、有效区间、角色 | 人工确认实验室配置 | IP 只能视作网络端点 |
| Sysmon（P1） | EventID、UtcTime、ProcessGuid、ParentProcessGuid、网络字段 | 从事件记录导出 XML/JSON 后适配 | P0 不承诺 Windows 溯源 |

Zeek 的 originator/responder 保持原意，不把 originator 自动视作攻击者。Suricata `flow_id` 不能作为 Zeek `uid` 使用。可选 Community ID 需两侧统一算法版本与 seed，只辅助同一观测域和时间内的连接匹配，不能跨 NAT 证明同一流。依据：[Zeek conn](https://docs.zeek.org/en/current/reference/logs/conn.html)、[Suricata EVE](https://docs.suricata.io/en/latest/output/eve/eve-json-output.html)。

Linux audit 的一项系统调用可能包含多个 record；先以 `sensor_id + boot_id + audit_serial` 合并 SYSCALL/EXECVE/CWD/PATH 等记录，保留所有原始位置。缺少 boot_id 或进程创建信息时降低身份强度，不能把 PID 直接升级成确定进程实体。Sysmon 提供 ProcessGuid 等关联字段，网络连接事件需要在配置和采集结果中确认，不能假设默认全部开启。依据：[Microsoft Sysmon](https://learn.microsoft.com/en-us/sysinternals/downloads/sysmon)。

P0的强进程身份输入必须由实验采集适配器补全：读取host/boot标识，并通过受控进程启动记录或可靠生命周期记录获得进程/父进程的start标识；允许在受控实验中使用`/proc`开始时钟刻度，但须验证采样对应事件当时的同一进程、保留采样时刻与依据，不能事后对复用PID直接读取。`process.action=create/exec/observe`必须区分；exec通常不创建新PID，禁止把exec时间当出生时间。仅有audit PID/PPID且不能验证生命周期时，输出弱候选，不产生强父子观察边。D1验证真实采集能否满足这些字段，失败时补采或明确采用合成身份夹具，不伪造来源。

## 2. 通用事件结构 v1

所有字段名 snake_case；字符串 UTF-8；时间 RFC3339 UTC，至少毫秒精度；内部时间比较使用 UTC 时间对象。JSON 中可省略不适用的可选对象，必需字段不能以空字符串代替。IP 校验 IPv4/IPv6；端口 0～65535；协议枚举 `tcp/udp/icmp/icmpv6/other`；未知值使用 null。

| 字段 | 类型/必需 | 语义 |
|---|---|---|
| schema_version | string，必需 | 初始 `1.0` |
| event_id | string，必需 | 稳定摄取 ID，规则见下 |
| workspace_id | UUID，必需 | 工作区 |
| dataset_id | UUID，必需 | 一次独立采集/实验运行的数据集；其派生样本保持split一致 |
| event_type | enum，必需 | `network.connection / network.dns / host.process / auth.login / security.alert / file.write` |
| event_time | timestamp，必需 | 统一后的事件时间；无法确定则隔离 |
| ingested_at | timestamp，必需 | 服务端接受时间 |
| time_quality | object，必需 | original、timezone、offset_ms、uncertainty_ms、basis |
| sensor | object，必需 | sensor_id、type、instance_id、observation_domain |
| source_locators | object[]，必需且非空 | object_id、record_start、record_end、raw_sha256；JSONL为1基行号；不连续记录分多项，可跨对象 |
| parser_version | string，必需 | 如 `linux-audit-json@1.0.0` |
| asset_id | UUID/null | 主机遥测的稳定资产身份，不保证网络连接具有此字段 |
| src / dst | object，可选 | ip、port、asset_id、resolution_quality |
| network | object，可选 | transport、uid、flow_id、community_id、duration_ms、bytes_out、bytes_in |
| process | object，可选 | entity_id、pid、parent_entity_id、boot_id、start_time/start_ticks、action、identity_basis、executable、command_redacted |
| user | object，可选 | entity_id、name_redacted、realm、session_id |
| auth | object，可选 | outcome=`success/failure/unknown`、method、service |
| alert | object，可选 | rule_id、signature、native_severity、category |
| quality_flags | string[]，必需 | 如 `clock_uncertain/identity_weak/truncated`，默认 [] |
| extensions | object，可选 | 来源特有内容，有尺寸上限，不直接进入模型 |

类型条件：network.connection要求src/dst与network.transport；auth.login要求auth及目标资产/端点，缺user时允许入库但R02不适用；host.process要求process.action及pid，强entity_id仅在identity_basis可验证时赋值；security.alert要求alert.rule_id。缺少某规则所需字段不等于整条观测无用，入库质量标记与规则not_applicable分开。

`event_id = SHA256(canonical_json([workspace_id,dataset_id,sensor_id,source_stable_locator]))`；有可靠native_record_id时locator包含传感器实例/重启标识和该ID，audit使用boot_id与audit_serial；否则使用排序后的全部source_locators。相同dataset内同文件重复上传同sensor得到相同ID；重打包/重排的语义重复在没有可靠原生ID时可能保留，必须报告限制。不同dataset允许保留相同原始对象的独立实验上下文，但同一次采集派生版不能跨训练/测试划分。不能仅按正文哈希去重，否则同内容重复登录会丢失。

audit聚合器跨输入分片保留pending state，按manifest全部分片结束或明确结束标识封存；不连续record必须逐段定位，不能把夹在中间的其他事件算成证据。缺片输出`partial_audit`质量标记，缺boot_id时用传感器实例+原始审计时间/serial做弱聚合并保留歧义。规范事件在dataset冻结后不可原地改写；补到新片段建立新数据版本并保留旧引用。

合成样例（完整字段可由契约夹具补齐；UUID 使用固定合法格式，事件 ID 用 64 位十六进制）：

```json
{
  "schema_version": "1.0",
  "event_id": "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
  "workspace_id": "11111111-1111-4111-8111-111111111111",
  "dataset_id": "77777777-7777-4777-8777-777777777777",
  "event_type": "auth.login",
  "event_time": "2026-11-14T01:00:00.000Z",
  "ingested_at": "2026-11-14T01:00:02.000Z",
  "time_quality": {"original": "2026-11-14T01:00:00Z", "timezone": "UTC", "offset_ms": 0, "uncertainty_ms": 1000, "basis": "lab_clock_manifest"},
  "sensor": {"sensor_id": "host-web-01", "type": "linux_auth", "instance_id": "boot-a", "observation_domain": "lab-a"},
  "source_locators": [{"object_id": "22222222-2222-4222-8222-222222222222", "record_start": 42, "record_end": 42, "raw_sha256": "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"}],
  "parser_version": "linux-auth-json@1.0.0",
  "asset_id": "33333333-3333-4333-8333-333333333333",
  "src": {"ip": "192.0.2.10", "port": 42000, "asset_id": null, "resolution_quality": "unknown"},
  "dst": {"ip": "10.10.0.20", "port": 22, "asset_id": "33333333-3333-4333-8333-333333333333", "resolution_quality": "inventory_interval"},
  "user": {"entity_id": "user:lab-a:u01", "name_redacted": "u01", "realm": "lab-a", "session_id": "s-001"},
  "auth": {"outcome": "success", "method": "password", "service": "ssh"},
  "quality_flags": []
}
```

文档地址 `192.0.2.0/24` 等仅用于样例，不代表采集目标。实验网络实际地址写入场景清单，不硬编码在检测规则里。

## 3. 原始证据和文件契约

`RawObject`：`object_id, workspace_id, sha256, byte_size, format, source_type, sensor_id, storage_key, encoding, created_at, sealed_at, retention_until`。

`ImportBatch`：`batch_id, workspace_id, dataset_id, manifest_hash, status, expected_records, accepted, duplicate, quarantined, received_at, completed_at`。计数按解析单元定义，audit 聚合另列原始 record_count 与 normalized_event_count，不能混用。

`EvidenceRef`：`event_id, fragments:[{object_id,record_start,record_end,raw_sha256}], fields_used[]`。fragments必须来自事件的source_locators，不能增加无关片段。UI从证据API获取脱敏片段，服务端先验证工作区和每个对象哈希；超过20行的片段分页。完整对象下载仅特定角色允许，不能由Agent下载。

SHA-256 的保护范围是归档对象字节。授权、传感器配置、采集时间、传输链路与操作者记录另外存 manifest；不使用“哈希证明证据绝对真实”的表述。

## 4. 实体解析

| 实体 | 首选身份 | 回退与限制 |
|---|---|---|
| Host | 资产清单 UUID 或安装时生成的 host UUID | hostname/IP 仅候选，保留碰撞 |
| Endpoint | observation_domain + IP + 地址有效区间 | 无清单时是网络端点，不是 Host |
| Process | Host + boot_id + pid + start_time；Sysmon 用 Host + ProcessGuid | 缺开始时间仅建立弱进程候选，不跨窗口合并 |
| User | realm + SID/UID/稳定账户标识 | 展示名不能跨 realm 合并 |
| Session | Host + boot_id + auth_session_id | 无 session 不能证明某进程由该登录启动 |
| Connection | sensor instance + 原生 uid/flow_id | 跨源连接匹配单独产生 `corresponds_to` 推断关系 |
| File | Host + path + 文件版本时间，另存 hash | 相同路径可多次覆盖；同 hash 不证明执行关系 |
| Domain | 小写、去尾点、IDNA 规范化 | DNS 答案按 TTL/观测时间关联，不能永久绑定 IP |

IP 映射采用半开区间 `[valid_from,valid_to)`；区间重叠产生 `ambiguous`，不能任选。NAT、代理和 DHCP 分别需要转换日志、可信代理上下文和租约信息；缺失则保留边界，不把外部连接强接内网进程。资产角色仅上下文，不决定是否恶意。

## 5. 数据库逻辑表

所有业务表含 `workspace_id`；外键尽可能用 `(workspace_id,id)`，避免仅 ID 连接漏隔离。

| 表 | 主字段 | 约束/索引 |
|---|---|---|
| workspaces | id、name | 主键 id |
| datasets | id、parent_dataset_id、provenance_type、split_manifest_ref、frozen_at | 工作区内稳定ID；split只供评估管理，不进入模型上下文 |
| analysis_sessions / session_events | session_id、dataset_id、mode、replay_id、事件成员、可见时间、处理游标 | `(session_id,event_id)`唯一；默认导入会话或独立回放会话 |
| raw_objects | id、sha256、storage_key、sealed_at | `(workspace_id,sha256,sensor_id)` 唯一 |
| import_batches / import_items | 批次、对象关联、计数 | 支持一个对象被多个批次引用 |
| quarantine_records | object_id、range、error_code | object/range 索引 |
| events | event_id、dataset_id、event_time、type、asset_id、src_ip、dst_ip、payload JSONB | `(workspace_id,event_id)`主键；索引前缀workspace/dataset，后接time、asset/time、src/time、dst/time |
| assets / asset_addresses | 稳定资产与 IP 区间 | 区间检查；冲突检测，不静默覆盖 |
| findings | id、dataset_id、session_id、rule_id/version、window、group_key、evidence_ids | `(workspace_id,finding_key)` 唯一 |
| incidents / incident_events | dataset_id、session_id、状态、摘要、成员事件 | 成员二元唯一，保留membership reason，禁止跨session合并 |
| snapshots / snapshot_events | dataset_id、session_id、时间窗、摄取/回放高水位、版本与允许事件 | `(snapshot_id,event_id)`唯一；包含窗内全部可用事件而非只有种子 |
| graph_nodes | snapshot、entity_id、type、attributes | `(snapshot_id,entity_id)` 唯一 |
| graph_edges | snapshot、edge_id、src、dst、relation、kind、evidence、score | 唯一 edge_id；src/dst 索引 |
| investigation_runs | incident、snapshot、mode、state、budget、checkpoint、version | incident/time、state 索引 |
| tool_calls | run、sequence、tool、args_hash、result_digest、status、latency | `(run_id,sequence)` 唯一 |
| reports / report_claims | run、report_version、结构化报告、结论、引用 | `(run_id,report_version)` 唯一 |
| jobs | type、payload、state、lease、attempt、cursor、version | state/available_at 索引 |
| audit_logs | actor、action、object_id、request_id、result、timestamp | 工作区/time 索引；应用追加写 |
| idempotency_keys | actor、route、key、request_hash、response、expires_at | `(actor,route,key)` 唯一 |

P0 不做分区表与 JSONB 全字段 GIN 索引；先索引已知过滤列，避免写入膨胀。迁移需验证从空库建立以及从前一版本升级。事件 payload 不存测试标签。

## 6. 校验与异常处理

非法 JSON、未知 schema、无时间/来源、非法 IP、负字节数等进入隔离。超大字符串截断仅发生于派生展示字段，并置 `truncated`；原文保持不变。毫秒/秒单位转换需来源配置，不靠数值大小反复猜测。用户名脱敏用工作区加盐稳定 HMAC，原名只保留于授权原始对象；禁止将映射盐传给模型。

每个解析器至少夹具：正常、缺字段、时间格式变化、IPv6、超长字段、重复记录、乱序、字段类型错、编码错误、日志轮转。解析器版本升级前后对同一原始对象比较差异；若改变 ID 策略，必须有明确迁移和旧引用兼容方案。
## D9增量：报告复核与导出（CHG-009）

schema_v6/0006_d9仅新建report_reviews，旧基线不修改。review追加seq、workspace_id/id/report_id、claim_id、decision、comment、actor_id、created_at，报告复合外键保持工作区隔离，应用角色禁止UPDATE/DELETE。人工accepted不修改生成报告事实级别。ReportExport为严格契约，含Report、ExportSnapshot(scope/event_ids)、EvidenceResponse数组、ReviewRecord数组、run_state、导出时间和限制；脱敏目录覆盖快照中的每个事件及其所有源片段，原始对象另行授权。

AgentBudget新增可缺省max_cost_microusd（服务端限额可收紧）；BudgetUsed新增默认0的cost_microusd/actual_cost_microusd，旧报告可无费用或cache_key。缓存键保存在provenance；cached是读取视图，数据库原payload不修改。详细字段以packages/contracts/reports.py及生成Schema为准。

# P1 本地增量契约（dev16）

新增可缺省 DraftClaim.knowledge_refs（最多 5 个内容绑定引用）。只接受本次 run 已完成 get_technique_context 返回的引用，不替代 evidence_refs。知识项有技术 ID、对象 ID、对象版本、来源 URL、源对象 SHA256、知识版本与引用；摘要仅解释适用观测与正常替代。无事件支持的 observed 仍拒绝。

新增 ReplayCreate：source_session_id UUID，rate_eps 严格整数 1–1000（默认 50）。ReplayStatus 包含 job_id/dataset_id/session_id/source_session_id、input_mode=replay、state、source_high_water、total_events、published_events、rate_eps、detection_status、warnings。使用已有 jobs.payload 记录固定水位、进度游标、开始时间；无结构迁移。原始 events 不复制或改写。


# P1 全量检测兼容增量（dev17）

IncidentPage.warnings 从仅 RULE_SCOPE_TOO_LARGE 的枚举列表扩展为字符串列表，支持资源限制及回放 pending/取消/失败。ReplayStatus 与数据结构保持 dev16 契约；无新迁移。完整检测范围默认/最大 100000，资源预算耗尽明确 partial，不改变事件字段、冻结规则配置或历史 finding ID。
# dev21 HTTP/DNS additive contract

新增 `zeek_http` / `zeek_dns` JSONL 格式，复用同一 `source_type=zeek` 的传感器上下文；Sensor.type 保持 zeek。NormalizedEvent 1.2 新增 network.http 与有界 http/dns 对象；旧 1.0/1.1 继续有效。HTTP 仅保留规范化主机、可执行后缀、方法、状态、字节计数和 MIME，URI/查询串/凭据仅留在本地不可变原件。DNS 仅保留规范化查询、类型/返回码、拒绝状态、IP 答案及非 IP 答案数量。缺失字段为未知。数据库迁移不变。

# dev22 HTTP 客户端形态增量（第二轮）

HTTP 新导入使用 schema 1.3、parser v2，新增可选 client_shape（http-client-shape@1）：UA 外形分类、查询解析状态、字段数与十六进制不透明值形态数量。旧 1.0–1.2 继续有效；缺失形态为未知。只保留计数，不保留 UA、参数名/值、完整 URI 或令牌摘要；数量不证明标识相同或进程身份。查询解码失败/超界仅使形态 unknown，不回退覆盖旧证据。DNS 保持 1.2，数据库迁移不变。

# dev23 HTTP 非文本查询增量（第三轮）

新 HTTP 为 schema1.4/parser3，兼容1.0–1.3。原始 JSONL 可用严格 base64 的 uri_b64/user_agent_b64 表达字节，分别与 uri/user_agent 互斥；仅原件保存，URI/UA 解码上限16384/2048。新增可缺省 query_shape@1 只记录字节/控制计数、UTF-8及转义有效性和键值分隔符存在性，非法百分号不猜测解码。旧 client_shape@1 定义不变，非UTF-8字符串保留未知；DNS/迁移不变。详情见第三轮设计。

最终 parser3.0.1 先去除字面片段符号 `#` 再识别 `?` 查询，防止将片段内容当查询。上述字节上限只约束新增base64输入；旧文本URI仍为16384字符上限，旧文本UA超2048字符保留unknown，保持兼容。query_shape计数最多65536以容纳旧文本UTF-8编码。非法百分号后的解码统计为null，不等同零。

# dev24 抓包派生输入（第四轮）

新增 source_type=pcap / pcap_http，传感器类型/上下文族为 pcap；不冒充 Zeek，不跨探针合并时间或 UID。入口仍是 JSONL，二进制 PCAP 须先由本地有界适配器转换。pcap-conn@1 保存观测时间/持续时间、唯一重组字节计数、端点及派生 UID。pcap-http@1 保存完整单次 request_b64 / response_b64，服务端重算协议摘要，不信任提交的 status/method/URI 摘要。

HTTP schema1.5/parser pcap_http-json@1.0.0 新增可选 query_encoding@1（有效转义数、非ASCII/控制转义数、非法百分号数）及 response_shape@1（完整分帧、实体字节数、魔数/UTF8格式类别）。统计合法 %HH 片段不等于解码非法查询；旧 query_shape@1 的 decoded 字段仍未知。格式不证明完整文件、内容安全、执行或控制。旧 HTTP 版本和解析语义保持。迁移仍0006_d9。

原始请求/响应、PCAP哈希/包号/重组区间仅留本地原始 JSONL 及离线映射，不进入模型和证据投影。网页 evidence.verified 只验证已导入 JSONL；PCAP→JSONL 由离线重新适配并核对包范围/哈希，不能称为网页直接验证 PCAP。classic PCAP/Ethernet/IPv4/TCP 有界支持，拒绝分片、缺口、冲突、歧义 HTTP、close-delimited/HEAD/1xx 等未支持格式；不执行或解压响应内容。


## P2 经典 PCAP 包观测（1.6）

采集来源 pcap_packet 使用 pcap 传感器族。二进制原件由现有导入入口接收并原样封存。支持 Ethernet 和微秒经典 PCAP，观测 Ethernet 上的 IPv4 及可读 TCP、UDP 和 ICMP 首部，包时钟沿用现有采集器上下文校正。32 MiB 或 100,000 包上限同时受已有导入预算约束。只接受可验证的记录边界。

network.packet 事件的 packet 对象记录线上/捕获长度、IPv4 协议号、标识、分片偏移（字节）及后续分片标志。可用的 TCP 标志、ICMP 类型与代码、TCP 可见载荷字节数为可空值；端口沿用 src/dst。在可定位的非首片或截断首部保留未知。后续规则只从可靠首部读字段。源定位的 pcap 对象含从原件起算的半开 byte_start/byte_end，单包序号使用现有 record_start/record_end，不含载荷。普通 JSONL 行定位保持兼容。

已消费完整物理记录数为 accepted + duplicate + skipped + quarantined。范围外帧计跳过；可定位的坏包隔离；无法安全恢复记录边界或超限时整批停止发布并报告原因和字节位置。保存摘要、解析版本、下一个偏移及计数，不保存载荷、原始 HTTP 头部或离线标签。数据库迁移仍为 0006_d9。

分片规则的包作用域上限为 100,000 条已发布包观测，独立于旧规则的事件条数上限。两类输入共同遵守现有检测资源预算。

pcap-packet@1.1.0 增加可选 icmp_echo_header_complete。该字段以 IPv4 声明范围内实际捕获的首部为准，不把 Ethernet 填充算作 ICMP 首部。历史观测仍按自己的解析版本校验，未提供此字段的历史包不能作为新版 R21 正证据。在新数据集导入原件可以获取新版观测。

pcap-packet@1.2.0 增加可选 packet.http_segment，仅对完整捕获、未分片且含数据的 TCP 包作保守观测，带 SYN、FIN 或 RST 的包不提供该摘要。摘要含 32 位 TCP 序号、可见 HTTP/1.x 请求行标记、文本形态标记和 CRLFCRLF 分隔符的四个状态转移。不保存请求行、头部或载荷内容。旧证据按写入时的解析版本验证，可在新数据集重导原件以取得新增观测。

### Ethernet ARP 请求包观测 1.7（dev36）

`pcap_packet` 继续归档原件，仅对可验证的标准未标记 Ethernet/IPv4 广播 ARP 请求使用 `network.packet` schema 1.7 和 `pcap-packet@1.3.0`。包对象含操作码 1、发送者硬件地址和捕获/线上长度；端点分别取 ARP 发送者与查询目标的 IPv4，端口留空。发送者硬件地址用于按可见来源分组，不能作为设备身份凭证。未支持的 ARP 记录计入跳过，原 PCAP 定位及哈希仍用于复核。IPv4 继续使用 1.6 与原解析版本，历史原件和观测保持。

## GRE 封装摘要（dev38）

`network.packet` 的 IPv4 包对象新增可选 `gre_encapsulation`。可读的 GRE v0 基本头及内层 IP 结构产生 `ip` 或 `ethernet`，只在有该摘要时写 `pcap-packet@1.4.0`。包证据按保存的解析版本重读原件，不输出内层地址、端口或载荷。旧 IPv4、ARP 证据的解析版本继续有效。

## ARP 应答与 DNS 事务摘要 1.8（dev39）

`pcap-packet@1.5.0` 为可核查的未标记 Ethernet/IPv4 ARP 单播应答记录操作码 2、发送者硬件地址和帧长度。`pcap-packet@1.6.0` 为可读的 IPv4 UDP DNS 观测增加请求或应答类型、事务 ID、A/AAAA 类型、规范问题摘要和可选的答案集合摘要。扩展查询保留用于拒绝歧义的 `query_context`，不能作贡献证据。应用的证据投影省略问题与答案原文，模型工具摘要省略整个 DNS 包摘要。证据核验按原解析器版本重读存档包。旧数据集重复导入沿用原事件与投影，需要对旧抓包补充新版观测时，应在新数据集导入同一原件。数据库迁移仍为 0006_d9。

## 指纹探测配对字段 1.9（dev40）

`pcap-packet@1.7.0` 在有可核查配对信息时提供 `os_probe`，包含包级角色和关联字段摘要。原始序号、载荷及 ICMP 引用的内部首部留在本地归档。可配对的普通 TCP 包也可带此字段。R30 需凑齐规约 13.2.3 的四条独立贡献，单包角色字段没有探测结论。模型工具摘要省略该字段；证据接口按原件重算核对。在新数据集重导旧抓包可取得 1.9 投影。


## 六阶段流程改造 dev42 增量

dev42 复用调查比较与行为报告字段，网页及 HTML 由 before/after 集合差计算新增非种子事件，返回数与新增数分别展示。旧报告缺字段沿用历史缺省。迁移仍为 0006_d9。


## 六阶段执行状态 dev43 契约

dev43 已实现增加可选 PipelineProgress，固定六阶段及 available/running/completed/partial/failed/cancelled/not_run 状态。阶段仅表示当前冻结快照执行情况，模型不能写入。历史报告缺字段不回填。
