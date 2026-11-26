# 05｜API、前端与联调契约

## 2026-11-16 网页简化增量（P2）

当前导航为“导入数据 → 查看异常 → 阅读报告”；下文四页布局保留为历史设计。沿用全部 API / 角色 / 幂等 / 预算契约，无数据库或规则变更。连接后选择已有数据集；创建合成数据集、资产配置、回放及事件查询按需展开。异常页自动只读查询，导入完成直达默认 import 会话异常；不自动创建调查。

选文件时只读最多 64 KiB、前五个非空记录，根据字段给出四类来源的表单提示；冲突/未知/格式不完整不猜测，要求手动选择。仍由服务端逐条验证。只从本页已成功配置的传感器列表自动填入唯一同类型项，多候选要求选择；不推断资产身份，不改变原始文件或上下文。

报告分为结论、关系与时间线、补证对比、运行记录；导出/复核/缓存/历史/分页全部保留。证据用可关闭对话框显示，Escape 关闭并恢复焦点。partial、证据不可验证、检测覆盖限制与裁剪仍显式显示；未核验的历史结论先提示再展示。请求模式/快照在运行记录中保留。

切换身份/数据集/会话销毁旧调查状态、终止旧查询。导入排队不阻止离开工作区；切换后后台任务仍继续。上传/创建调查响应不确定时保留同键同参数重试，读结果失败只重试 GET。未确定的模型请求不自动重复，模式选择与费用可能性保持可见。令牌仍只在内存，不写存储/URL。新界面不能替代真实模型策略验收，P1 状态不变。

## D8已实现增量（CHG-008）

默认每认证workspace+token身份读120/分钟、写20/分钟；最多1024活跃身份窗口，满时拒绝不驱逐额度；限流只单API进程有效，重启重置。429含Retry-After；本应用错误含统一信封及X-Request-ID，意外500不回显异常。前端MissingEvidence显示缺证、partial、拒绝代码、修复次数与人工核查建议；旧报告无校验摘要兼容。若读取时report.validation=partial，缺证面板优先显示当前原始证据不可验证，保留生成时历史摘要而不宣称当前校验完成。 详情见[d8-runbook](d8-runbook.md)。

## D7运行接口补充（CHG-007）

GET investigations/{id}增加query_stop_reason，与失败原因分开。GET reports/{id}可含InvestigationComparison：方法/配置摘要、before、after、changes、停止原因；判断引用均属于已有快照。viewer可读脱敏对比及证据，跨工作区404，行动明细权限沿用D6。契约从Pydantic生成OpenAPI/TypeScript，旧报告可无新字段，不新增重复分析路由。

新EvidenceChanges组件显示同快照种子数→已核查数、每个判断前后状态、行动变化与仍未解决缺口，点击反向线索展示包含安全进程字段的哈希核验证据。context_only与未采集socket明确显示，不把正常程序名当运维授权或无攻击证明。健康阶段d7、队列R01–R06；真实LLM、导出复核与完整独立四页仍未验收。

## D6运行接口补充（CHG-006）

POST investigations现接受mode=auto/live/deterministic及可选budget（只能缩小上限）；仍要求analyst/admin、Idempotency-Key和本workspace事件组。GET investigations/{id}增加phase/state_version/budget/budget_used/retrieved_count/cache_hits/stop_reason。GET investigations/{id}/tool-calls仅analyst/admin，返回行动序号、工具/阶段、预留/结果、受限摘要及usage；GET /transitions允许viewer，按转换版本分页。两者游标绑定actor/run/水位，跨范围拒绝，类型从后端生成。

页面增加模式、工具/模型次数上限、阶段/预算显示、行动摘要和证据按钮、转换记录分页；completed和partial均可查看报告。实际模式以报告为准，本地HTTP协议测试桩明确标非真实LLM；调用详情手动刷新，viewer不因无权读取行动而丢失报告。恶意文本仅作为React文本显示。完整独立四页、导出及人工复核仍待后续。

## D5运行接口补充（CHG-005）

datasets、events、incidents均返回真实next_cursor；默认limit50/max100，页面常用20。新增GET investigations/{id}/timeline（冻结EventPage）、/paths（冻结PathAnalysis）；graph支持limit/cursor/focus_entity，返回完整有界节点、当前页边、total_nodes/total_edges/next_cursor。详情包含成员findings与membership，旧单finding字段保留。游标换scope/actor/路由/focus被拒。

页面显示聚合成员和理由、冻结时间线翻页、最早观测入口、路径切换/逐边匹配依据/分数分解/证据、未选候选及断点；图焦点可查询邻接，边分页有载入数/总数，端点聚合保留观测域。历史报告不补算路径；证据失效时paths409，报告partial视图。未接Agent、导出及完整独立四页联动。

## D4运行接口补充（CHG-004）

后文为完整目标；实际可执行路由以生成OpenAPI及d4-runbook为准。新增admin+Idempotency-Key的`POST /datasets/{id}/context`，接收DatasetContext并仅返回dataset_id/context_hash；首次导入前封存，相同配置幂等，修订409。`POST /imports`新增linux_auth/linux_audit；GET imports返回raw_records/aggregated_records。`GET /evidence/{event_id}`始终要求snapshot_id，可传cursor，返回next_cursor，每页最多20行。

页面可配置上下文、选择四类来源、查看两种计数，R01/R02共用最小调查工作台。SVG按不同身份分节点，实线observed/虚线inferred，最多12节点，完整边列表仍可展开；证据抽屉可翻页。四个导航仍共用部分页面，完整独立时间线、路径交互及导出未在D4完成。

## 1. 通用约定

所有路由 `/api/v1`，JSON UTF-8。使用 `Authorization: Bearer <role-token>`；单工作区 ID 由认证上下文注入，不信任请求体里的工作区。ID 使用 UUID，事件 ID 使用 SHA-256 十六进制。时间 UTC，前端统一转换显示时区。契约由 Pydantic 生成 OpenAPI，再生成 TypeScript 类型，禁止手写两套字段名。

前端全局选择dataset与analysis_session，列表查询必须携带这两个ID并由服务端核实所属工作区；对象路由从对象本身反查其范围。上传前创建dataset，导入使用默认analysis_session；回放创建新session并返回session_id。快照固定session高水位，禁止用别的回放数据补证。OpenAPI由后端类型生成的能力可参考[FastAPI官方特性](https://fastapi.tiangolo.com/features/)，前端类型生成工具在D1实际锁定。

列表响应 `{items:[],next_cursor:null,request_id:"..."}`；默认 limit=50，最大100；cursor 为服务端签名的不透明游标，包含稳定排序键 `time,id`，不能接受用户传 SQL 片段。

错误示例：

```json
{"error":{"code":"EVIDENCE_OUT_OF_SCOPE","message":"证据不属于当前调查范围","request_id":"req-demo-01","details":{}}}
```

状态：400 不合法格式；401 未认证；403 角色不允许；404 对象不存在或不属于工作区（避免泄漏）；409 幂等冲突/状态冲突；413 过大；422 Schema 不符；429 频率限制；503 依赖不可用。服务日志保存内部原因，外部不泄露路径和堆栈。

## 2. 路由表

| 方法/路径 | 请求要点 | 返回/状态 | 最低角色 |
|---|---|---|---|
| GET `/health/live` | 无 | 进程存活，不含机密 | 公共 |
| GET `/health/ready` | 无 | DB/worker/归档可用摘要 | admin |
| GET `/overview` | 时间范围 | 数据量、来源健康、事件数、分析状态 | viewer |
| POST `/datasets` | name、provenance_type、可选parent_dataset_id | 201 dataset_id、default_session_id | admin |
| GET `/datasets` | 分页 | 数据集与可用会话 | viewer |
| POST `/datasets/{id}/freeze` | manifest_hash | 200固定数据版本；重复调用幂等 | admin |
| POST `/imports` | multipart file、source_type、sensor_id、dataset_id、timezone | 202 batch_id、job_id | admin |
| GET `/imports/{id}` | 无 | 计数、错误摘要、处理进度 | analyst |
| POST `/datasets/{id}/replays` | rate_eps≤100、mode=`original_time` | 202 replay_id、session_id、job_id；只接受frozen数据集 | admin |
| GET `/jobs/{id}` | 无 | state、progress、error、可取消 | analyst |
| POST `/jobs/{id}/cancel` | 无 | 202/409 | 创建者或admin |
| GET `/events` | 类型、时间、资产、分页 | 脱敏事件摘要 | viewer |
| GET `/events/{id}` | 无 | 规范事件与证据引用 | viewer |
| GET `/evidence/{event_id}` | 可选snapshot_id、cursor | 授权脱敏原文片段与哈希状态；调查内必须传snapshot_id，未调查时按工作区/数据集授权 | viewer |
| GET `/raw-objects/{id}/download` | 无 | 授权完整对象，附件下载并审计 | analyst |
| GET `/incidents` | 状态、风险、分页 | 事件列表 | viewer |
| POST `/incidents` | dataset_id、session_id、seed_event_ids≤100、title | 201 incident_id；所有种子必须在同session可见 | analyst |
| GET `/incidents/{id}` | 无 | findings、成员范围、最新报告概览 | viewer |
| POST `/incidents/{id}/investigations` | mode=`live/auto`，可选限额更小的budget | 202 run_id、snapshot_id | analyst |
| GET `/investigations/{id}` | 无 | state、mode、budget、阶段、结果ID | viewer |
| POST `/investigations/{id}/cancel` | 无 | 202/409 | 创建者或admin |
| GET `/investigations/{id}/graph` | cursor、focus_entity | nodes/edges、truncated、total | viewer |
| GET `/investigations/{id}/timeline` | 时间、分页 | 固定快照时间线 | viewer |
| GET `/investigations/{id}/tool-calls` | 分页 | 脱敏行动摘要和工具结果摘要 | analyst |
| GET `/reports/{id}` | 无 | 不可变报告版本 | viewer |
| GET `/reports/{id}/export` | format=`json/html` | 自包含附件 | analyst |
| POST `/reports/{id}/reviews` | claim_id、decision、comment | 201 review_id | analyst |

所有变更 POST 接受 `Idempotency-Key`；取消本身天然幂等，已取消返回当前状态。显式要求 `live` 且模型不可用时也应返回已创建 run 的 partial/fallback 状态，不静默假装 live 成功。

## 3. 调查示例

```http
POST /api/v1/incidents/44444444-4444-4444-8444-444444444444/investigations
Authorization: Bearer <token>
Idempotency-Key: demo-run-001
Content-Type: application/json

{"mode":"auto","budget":{"max_tool_calls":6,"timeout_seconds":90}}
```

202 响应示例：

```json
{"run_id":"55555555-5555-4555-8555-555555555555","snapshot_id":"66666666-6666-4666-8666-666666666666","state":"queued","request_id":"req-demo-02"}
```

客户端每2秒查询状态；切换页面停止轮询；隐藏标签页降频；达到终态后只查询报告一次。网络错误显示重试，不重新 POST 创建第二次调查。

## 4. 四个页面与操作闭环

### 页面一：概览与数据导入

显示当前工作区、输入模式、来源状态、导入计数、异常/隔离数、最近任务。上传前展示支持格式与100MB上限；完成后展示 accepted/duplicate/quarantined。没有主机日志时出现“进程关联受限”，不能一直绿灯。

### 页面二：安全事件队列

表格列：开始时间、受影响资产、规则类型、支持度、处理状态、证据源数量。风险与证据支持度分开，不能把高危严重性当高可信度。点击进入事件，选择“开始调查”；已进行中的 run 展示进度并防止误重复。

### 页面三：调查工作台

```text
┌ 事件名称 | 输入：回放 | 报告：实时AI/历史缓存/确定性 | 时间范围 ┐
│ 左：时间线/筛选 │ 中：证据图与候选路径 │ 右：结论与证据抽屉 │
│ 主机/网络/告警 │ 实线观察、虚线推断    │ 事实/假设/未知      │
│ 缺失来源标记   │ 入口候选、断点、反证  │ 点击引用展开原文    │
├ Agent 当前阶段 | 只读工具摘要 | 已用预算 | 停止调查按钮      ┤
└ 生成时间、快照、规则/模型版本 | 重新调查 | 导出报告          ┘
```

交互：点击节点同步筛选时间线；点击边显示关系类型、匹配依据与原始证据；点击结论高亮引用的边/事件；切换 top-3 路径显示差异；没有强证据的跳跃显示断口，不能画实线。初始100节点，扩展不超过500；大图有“结果已裁剪”提示。

前端将攻击日志当纯文本渲染，禁止 `dangerouslySetInnerHTML` 加载原始日志；工具返回 URL 不自动预览。图节点文本截断但可展开，完整恶意字符串不能作为 HTML。

### 页面四：报告与运行记录

展示摘要、观察事实、候选入口、攻击路径、影响范围、反证/正常解释、未知项、建议人工检查事项、版本和引用目录。支持逐条复核，不给“真实攻击者姓名”栏目。报告历史可比较但不能覆盖。

## 5. 必须实现的空态与异常态

无数据→上传入口；格式不支持→明确支持列表；部分解析失败→隔离计数与样例；无告警→显示正常观测与检测覆盖，不造一条攻击；无图→说明缺哪种数据；模型不可用→保留确定性结果；超时→显示已完成部分；证据损坏→引用失效标记；无权限→说明角色限制；缓存→显示历史时间。

加载、空结果、错误、权限不足和部分成功不能共用同一个“暂无数据”。所有重要按钮有处理中状态；取消后不继续闪现新报告。

## 6. 前后端联调方式

D1 定义真实 Schema；D2 用同一 Schema 创建固定 mock；D3 切入实际 API。mock 只能用于页面开发，必须显著显示开发模式，不进入最终演示发布配置。D5 开始前端默认连集成环境，不继续双轨手改 mock。

集成用一个稳定的小夹具：20～50条事件、两台主机、一个成功认证、一个强父子关系、一个错误引用反例。接口契约测试验证返回 Schema；E2E 验证上传→调查→点击引用→导出，不依赖像素级截图断言。

## 7. 界面质量底线

目标分辨率1366×768和1920×1080；核心动作无横向滚动；正文至少14px；键盘可操作主按钮；颜色之外同时用线型和标签区分关系；日期标时区；数值显示单位。三周不做复杂主题、多语言和移动端适配，避免冲淡调查流程。
## D9已实现增量（CHG-009）

落实GET reports/{id}/export?format=json/html、GET raw-objects/{id}/download、POST reports/{id}/reviews。复核用严格ReviewCreate和Idempotency-Key；返回ReviewRecord，支持GET同路径分页。新增GET incidents/{id}/reports历史列表，最多50版、固定ID目录游标；GET reports/{id}?mode=original|cached，默认原报告兼容。GET runtime-config仅admin可看安全预算/限流/导出配置摘要。导出和复核仅analyst/admin，跨工作区404；角色拒绝与成功下载审计。导出有行数/字节上限、损坏证据409。

## D10部署契约（CHG-010）

WEB_DIST可选，指向可信Vite生产构建。只开放GET /入口和/assets静态资源，未知API路由仍404，业务路由仍鉴权；不挂载工作目录。未配置时沿用独立开发前端。health/live返回stage=d10，数据库head仍0006_d9。scripts.preflight为本地只读检查，不等同worker存活证明或真实模型连通验收。

报告面板加入逐条复核、JSON/HTML附件、历史版本、cached来源模式/原时间与USD费用占用和usage估算。旧报告费用缺失不当作实测账单；HTML引用离线可跳转，动态内容安全转义；控制器不实现模板/文件路径逻辑。四个导航仍共享调查组件，不宣称独立页面重构完成。详细演示与边界见[d9-runbook](d9-runbook.md)。

# D11 覆盖状态增量（CHG-011）

GET overview追加detection_status（complete/partial）和warnings；IncidentPage追加默认空warnings。超过DETECTION_EVENT_LIMIT（默认/上限10000）时，导入仍发布已核算事件，但批次/作业为partial、error_code=RULE_SCOPE_TOO_LARGE；检测不对超限会话静默截样，已有目录保留且列表明确标覆盖不足。该错误不代表原始数据丢失，也不能把已有告警目录当最新完整检测。其他检测异常仍回滚发布并按既有队列策略处理。字段为向后兼容增量，数据库不变。


D11复验补充：RULE_SCOPE_TOO_LARGE对应的已发布partial批次按工作区/数据集/session持久保留覆盖警告；提高DETECTION_EVENT_LIMIT不能让旧缺口变complete。目前无检测水位修复机制，提示采取保守策略，不自动抹除历史partial。

D11查询优化保持原字段和游标语义：按现有时间索引分页，EXISTS绑定工作区/session/publication；概览仅做直接scope验证及计数。未更改游标签名、固定水位或权限。
# P1 本地增量接口（dev16）

- `POST /api/v1/datasets/{dataset_id}/replays`：analyst/admin，必需 Idempotency-Key，ReplayCreate 请求，202 返回 ReplayStatus。源 session 必须属于当前工作区/数据集且为 import，冻结已发布水位；空源和超出配置资源上限拒绝。
- `GET /api/v1/replays/{job_id}`：已认证角色可读当前工作区 ReplayStatus；取消复用现有 job cancel 接口，analyst 只能取消自己的任务。
- 回放仅使既有事件分批可见；计数不能称为新日志导入吞吐。检测在回放结束后执行，超过 10000 的当前检测能力明确 partial，取消/失败保留已发布成员与状态。
- dataset 列表仍每数据集一个 default import session；overview.input_mode 返回实际 session 模式。
- get_technique_context 的参数和工具白名单不变；未启用/资料无效时空结果并显式 warning。精选知识不属于现场证据。


# P1 回放界面与检测警告增量（dev17）

“概览与导入”新增已有事件回放：1–1000 EPS 创建、轮询固定源水位/成员计数/检测状态、取消、按作业 ID 打开及返回导入会话。只复用 dev16 的 POST /datasets/{id}/replays、GET /replays/{id} 和 POST /jobs/{id}/cancel；令牌仍仅页面内存。POST 响应不确定时同键同参数重试。按 ID 恢复只接受当前数据集，权限由现有工作区 API 校验。

事件查询和候选队列使用显式选定 sessionId；default_session_id 不改写。切换令牌、数据集或会话时取消旧查询并清除旧结果。pending/partial/cancelled/failed 的警告不会当作已完成且无告警。IncidentPage.warnings 扩展为字符串列表以兼容 RULE_RESOURCE_LIMIT、REPLAY_DETECTION_PENDING、REPLAY_CANCELLED、REPLAY_FAILED；旧 RULE_SCOPE_TOO_LARGE 继续支持。导航仍共享调查组件。
# dev21 协议格式增量

导入接口 source_type 新增 zeek_http、zeek_dns，权限、幂等、队列保护及响应结构不变。网页增加 HTTP/DNS 短选项与文件识别，均使用 Zeek 采集器身份。证据页只显示安全协议字段及不可变原始引用，不显示 URL 查询串、凭据或任意 DNS 文本。旧客户端仍可使用原格式；新增事件客户端需支持 1.2 契约。


## P2 二进制 PCAP 入口与包证据

POST /imports 可显式选择 pcap_packet，沿用 admin、UTC、幂等及数据集范围约束。GET /imports/{id} 对 PCAP 批次有额外对账信息，包括 skipped、按原因计数和失败位置。GET /events 的包事件页提供可选 packet_evidence_scope。GET /evidence/{event_id} 使用既有 snapshot_id，或对纯 PCAP 事件使用事件页签发的 packet_scope。后者验证签名和认证身份，并绑定工作区、数据集、会话和固定发布水位。两者互斥，packet_scope 每次仅核验一个已发布包。fragment.pcap_record 提供安全包观测，旧行返回保持兼容。原件下载沿用角色、审计与附件响应，包证据不回显二进制载荷。

P2 的 IPv4 分片候选通过既有异常目录、调查与证据入口展示。包规则调查快照限定为候选固定的包证据；用户可按包号核查原始记录。


## P2 导入传感器自动选择

POST /imports 的 multipart 字段 sensor_id 可省略。显式提交沿用原校验。省略时，配置了上下文的数据集按日志家族查找唯一配置项；未配置的数据集沿用同日志家族唯一已有采集点，新采集家族使用既有界面默认名 lab-sensor-01。多个匹配项返回 SENSOR_SELECTION_REQUIRED 与经工作区授权的候选名，用户可选或显式填写。Linux 继续要求有效资产上下文。网页可直接上传，传感器字段留作可选覆盖及消歧。

在作业入队事务中确定并持久化具体 sensor_id，后续处理、证据和去重沿用既有身份。省略字段的重试绑定同一已受理请求；显式请求的幂等摘要完全沿用。按本节先验证新 PCAP 上载、已有采集点去重、单配置、多配置选择、Linux 拒绝和幂等重试，再运行相关回归。无数据库迁移。

## P2 同名洪泛候选展示（dev33）

新 R18–R20、R22 候选在异常列表与详情可携带 flood_observation。behavior 标记协议行为，support 为 flood_candidate 或 request_burst_only，observed_source_ip_count 为贡献证据中的可见源 IP 数，campaign_scope 为 unknown。页面显示计数和来源分布未知，证据仍可逐包核查。相关新候选省略 attack_subtype；历史存储、其他规则及数据库迁移保持原契约。

## P2 DoS/DDoS 合并类别（dev34）

异常和 finding 的现有可选 attack_subtype 字段可返回 `DoS/DDoS-<行为>`，异常标题与确定性报告展示合并类别。来源分布字段继续表示证据所能支持的范围。单次 HTTP 突发和未获足够进展证据的 SlowLoris 省略该字段。历史记录保留其写入时的类别和证据。

## P2 ARP 抓包证据（dev36）

事件与证据接口的 packet 可携带既有 IPv4 对象或 ARP 请求对象。旧 IPv4 字段保持，浏览器在原始证据弹窗为 ARP 显示请求类型、包号与原件偏移。访问范围、鉴权和原件核验沿用既有包证据契约。

## P2 ARP 应答与 DNS 包证据（dev39）

原事件和证据路由增加包观测 1.8，支持 ARP 应答及 IPv4 DNS 摘要。异常标题和报告显示 R28 ARP 映射冲突或 R29 DNS 答复差异及未知子类型。证据弹窗区分 ARP 请求和应答，显示 DNS 查询或应答与 A/AAAA 类型，并沿用已核验的包号和字节范围。

## P2 指纹探测包证据（dev40）

包观测 1.9 增加可选的 `packet.os_probe`，包含角色和关联字段摘要。R30 候选使用现有 `Recon-OSScan` 子类型及原事件证据路由，报告说明探测形态及待核实的目标系统与授权。包上单独的配对字段仍是观测，同一输入的其他候选由各自证据独立保留。


## 六阶段流程改造 dev42 增量

dev42 在补证对比显示 before/after 差集数量与新增证据按钮，HTML 导出加入相同新增数量、行动变化与停止原因，JSON 沿用调查比较。没有新增 HTTP 路由，历史报告与角色边界沿用既有行为。
