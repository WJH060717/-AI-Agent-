# 03｜检测、事件关联与证据图谱

## D8已实现增量（CHG-008）

rules/freeze.json记录六规则完整解析配置及语义SHA-256；registry.detect_all核对后以同批配置执行，漂移拒绝。历史reproduce仅用finding冻结配置，不受当前阈值变更影响。D8六规则正反矩阵包含一对一地址变换，不构成统计评估。 详情见[d8-runbook](d8-runbook.md)。

## D7已实现范围（CHG-007）

R05/R06现已接入固定配置、目录、冻结成员复现与报告。R05按独立来源通道分组，检验1200秒内所有合法连续子窗，≥8连接、最坏跨度≥300秒且CV误差上界≤0.15；前置噪声不能遮蔽有效后缀，也不能删内部异常点。重叠达标窗口确定性合并为跨度<1800秒候选段，超长活动有界分段；保留覆盖整个候选段的达标窗口端点及统计。整体CV是合并摘要，可超过0.15，不能冒充单个1200秒窗；连续90条20秒连接合为一个90成员候选段。

R06为明确资产originator bytes_out的UTC五分钟连接起始桶；至少30个有效历史正常开发参考窗口时，计数≥10,000,000字节且严格大于nearest-rank p95的3倍才触发，使用整数精确比较。参考不足只fixed_threshold_signal，充分高基线下不报体积异常。参考按资产/域/通道隔离，随不可变context提供，finding ID绑定冻结baseline_hash；不能据字节数证明公网外传或具体内容。

Agent正常监控/备份进程只能提供同资产同窗context_only替代解释，程序保留socket、授权、内容等缺口；R02会话与R04远端认证补证使用已有强关系/严格端点时间条件，不由模型造边。完整因果、真实LLM和独立场景检测指标仍未验收；下方D4–D6为历史范围，当前见d7-runbook/d7-verification。

## D6已实现范围（CHG-006）

新增固定版本rules/R03.json、R04.json，全部成员复现接入聚合与报告。R03要求同workspace/dataset/观测域、强Host/boot/出生标记与明确parent_entity_id，严格时间先后≤600秒；当前检测nginx/apache2派生配置中的shell/python3，nginx→nginx为正常allowlist。exec、弱PID、反序/误差重叠、异boot不当出生链。

R04从R02强成功会话或R03强异常子进程所在资产A取上下文，再找同域600秒内唯一inventory_interval映射的A→B管理TCP连接（22/3389/445/5985/5986）。远端B成功认证必须有强host/boot/账号/session、匹配端点端口和有界严格时间；匹配则remote_access_candidate，否则仅remote_access_attempt并保留认证缺口。源进程与网络没有socket证据，因此两种结果均保留process_socket_binding断点，不称成功横向移动。

R01–R04可复现、可查看原始证据；Agent查询已有图/路径，不允许模型创建边。R05/R06、真实LLM、完整因果与攻击意图仍待后续。下方D4/D5段落为当日历史交付范围，当前以本段及d6-runbook为准。

## D5已实现范围（CHG-005）

当前已实现同域、共同强实体且finding窗口相交的最小聚合，组件跨度小于30分钟，保留成员版本与理由；非相交finding依显式边聚合/人工拆并仍属T-11后续。不同IP端点不能取代强主机/账号，聚合不声称同一操作者。

入口按目标与观测域选择相关根事件的最早记录，缺采集覆盖声明则left_censored=true。事件级路径仅投影网络→成功认证、成功认证→显式会话进程、强父子创建；不以precedes/suggests/仅同主机补边。强Host/boot/session身份遵循实体契约，不因传感器域不同就自动改身份；网络五元组推断仍必须同域。进程→网络缺socket绑定保留断点。

严格时间区间先后、beam20/max6/top3、ID确定性打平、候选差异/断点/裁剪在D5接通不可变报告。分数沿用§6公式，无独立通道声明时旁证0；coverage仅为选中链内部证据覆盖。D5当日未实现R03–R06和Agent；D6新增范围见上方，不将后文完整设计解读为全部已交付。

## D4已实现范围（CHG-004）

当前落地R01与R02，R03–R06及路径搜索仍为设计。R02固定JSON配置为rules/R02.json，5分钟内≥5失败后2分钟内成功；完整分组含workspace/dataset/session/observation_domain、sensor_id+instance_id主来源、realm+稳定账号、src.ip、稳定目标asset、boot、service。独立传感器只能旁证，不累加阈值。无强账号/asset/boot不适用；session可缺，但不得生成会话关系。

时间使用[event_time-uncertainty,event_time+uncertainty]；先后要求严格不重叠，窗口按最坏边界计算。乱序输入排序后处理，成功终结前一失败段，重复事件ID不重复计数。仅复现原finding证据子集，快照可含新增上下文，历史报告不改写。

evidence_graph保留通信边，增加User→Session authenticated、强父子且create/确定先后的spawned、显式同Host/boot/账号/session的associated_process。exec不是出生。网络→auth corresponds_to仅在同域、同端点/端口/TCP、唯一目标资产一致且时间有界时作为inferred候选；当前没有Process→Connection opened或事件级因果路径。每条边保留原始事件/片段；模板仍deterministic_fallback，不调用模型。

## 1. 三层分析职责

第一层是确定性提取与规则，指出“哪些观测值得调查”；第二层是身份与事件图，指出“哪些观测可能属于同一条路径”；第三层是 Agent，选择下一步补证并组织可核验报告。三层均不能直接证明现实攻击者身份。

P0 不训练分类模型，原因是三周内多源真值、数据泄漏控制与证据链比堆算法更重要。统计异常可用于候选排序，但不能单独宣布攻击。

## 2. 六类规则的初始实现

下表阈值是实验室初始值；仅用开发/验证集调整，D8 冻结。窗口按 `event_time`，聚合前移除确定重复，不合并跨源观测计数。

| ID | 条件与窗口 | 必要字段/输出 | 反例与抑制 |
|---|---|---|---|
| R01 扫描候选 | 同 observation_domain/source endpoint 在 60 秒访问同一目标 ≥20 个不同端口，或 ≥10 个内部目标同一服务；滑窗每 10 秒计算 | conn 时间/五元组；证据为贡献连接 ID；severity medium | 经批准的运维扫描按清单标记上下文，不直接删除；NAT 共享源降低身份强度 |
| R02 失败后成功 | 同 realm/user/source/target/service 5 分钟内 ≥5 次认证失败，随后 2 分钟内成功 | auth.outcome、user、目标、session；输出 failure_ids + success_id | 仅网络握手不算登录；不同账号或主机不能凑阈值；正常输错密码反例 |
| R03 异常父子进程 | 实验室基线中的服务父进程产生未允许的解释器/工具子进程 | 强父子实体键、executable；不依赖敏感命令正文 | 正常维护子进程、PID 复用；没有父实体只能弱告警 |
| R04 跨主机访问候选 | 已有可疑会话/进程所在 A 在 10 分钟内连接 B 管理服务，B 有相符成功认证 | A、B 稳定身份，连接、登录、会话；图关联 | 只有端口连接只能标 `remote_access_attempt`；不能称成功横向移动 |
| R05 周期连接异常 | 同 src asset/endpoint→dst endpoint/port，≥8 次连接且跨度≥5 分钟；间隔 CV≤0.15 | conn start；CV=std(interval)/mean(interval)，mean>0 | 更新、心跳、监控均可正常；只标 `periodic_connection`，不能直接认定 C2 |
| R06 出站量异常 | 5 分钟窗口出站≥10 MB，且高于同资产/角色历史开发基线 p95 的3倍；基线至少30个正常窗口 | 明确方向的 bytes_out、资产、目标 | 备份/上传反例；基线不足则只输出 fixed_threshold_signal；不能证明外传了什么 |

`finding_key = SHA256(canonical_json([workspace_id,dataset_id,session_id,rule_id,rule_version,group_key,window_start,window_end]))`，滑窗重叠命中通过同规则/分组的连续窗口合并为一个finding version，不能用重复窗口堆高事件数量。聚合计数以某一主来源为准，其他来源仅旁证。相同session重试幂等，不同回放session的窗口与告警互不串联。

规则配置（项目自定义 YAML，不宣称兼容 Sigma）：

```yaml
id: R02
version: 1.0.0
enabled: true
event_type: auth.login
group_by: [user.entity_id, src.ip, dst.asset_id, auth.service]
window_seconds: 300
condition:
  failure_count_gte: 5
  success_after_seconds_lte: 120
requires: [user.entity_id, src.ip, dst.asset_id, auth.outcome]
severity: medium
attack_technique_candidates: [T1110]
```

配置由严格Schema校验；缺少group字段则规则返回`not_applicable`并计数，不把null聚成一组。所有规则执行器自动注入workspace/dataset/session/observation_domain边界，source IP不能替代这些范围。

## 3. 事件分组

先从 finding 的强资产/用户/会话建立候选组，再扩展前后各 10 分钟相关事件。两个 finding 只有共同强实体且时间窗相交或存在有证据关系时合并；共同公网 IP、同一 ATT&CK 技术、同一高危分数不足以合并。

事件范围最多 30 分钟，超限按会话/资产分段并以 `related_incident` 关联。人工合并/拆分创建新成员版本，不删除历史。无命中但被分析员选择的事件也可调查，避免系统只能解释自己告警。

## 4. 图模型

节点包含 `Host/Endpoint/Process/User/Session/Connection/File/Domain/Event/Technique`；P0 真正需要前七类及 Event/Technique，DNS 为空时不造 Domain 节点。关系存方向、时间区间、来源和强度。

| 关系 | 边类型 | 证据要求 |
|---|---|---|
| Process → Process `spawned` | observed | 主机明确父子记录，强进程标识 |
| User → Session `authenticated` | observed | 成功认证记录 |
| Process → Connection `opened` | observed 或 inferred | 记录直接绑定为 observed；仅五元组/时间匹配为 inferred |
| Endpoint → Endpoint `communicated_with` | observed | 网络流记录；方向是观测方向 |
| Session → Process `associated_process` | observed/inferred | 会话明确绑定/弱匹配分别标识 |
| Connection → Event(auth.login) `corresponds_to` | inferred | 网络、认证端点/端口/时间/身份匹配 |
| Event → Technique `suggests` | inferred | 规则与知识映射，仅表示候选行为类别 |
| Event → Event `precedes` | derived | 时间关系；不作为攻击路径的因果强边 |

每条边：`edge_id, snapshot_id, source, target, relation, kind, evidence_refs, method, method_version, score, contradicting_refs, time_interval, explanation`。`observed` 也只代表传感器记录到关系，不代表事件恶意。

攻击路径计算在事件级有向图上进行；UI 可显示实体投影图，但不能把实体投影的环直接解释成时间上的攻击循环。图构建必须保留节点→原始事件映射。

实体关系转事件边的固定投影规则如下；每条路径边保存`from_event_id,to_event_id,entity_edge_ids,relation,kind,evidence_refs,score`，两端均属于当前快照：

| 起点事件→终点事件 | 必要关联 | 类型 |
|---|---|---|
| 成功认证→会话内进程 | 明确同一强session ID及主机绑定 | 有直接记录为observed，否则不连强边 |
| 父进程记录→子进程创建/执行记录 | child.parent_entity_id与父强实体相等，符合生命周期 | observed；父记录只是事后观察则仅context，不作为出生顺序证明 |
| 进程事件→连接事件 | 主机明确记录该进程发起连接，或受限多字段跨源匹配 | 直接绑定observed；匹配inferred；仅同主机/时间不连 |
| 网络连接→远端成功认证 | 匹配服务/端点/时间，且远端主机提供认证证据 | inferred；没有认证结果不得补成功边 |

Linux audit/auth不必然提供进程到连接的直接证据；P0通过受控采集适配器补充进程socket关联，或明确把这一跳标inferred/断开。不能因为需要完整图而把网络连接自动归给最近的进程。候选路径可混合observed与inferred，但界面和指标需逐边区分。

## 5. 跨源匹配与时间约束

优先级：显式 session/process/connection ID > 资产与时间有效 IP 映射 > 五元组和时间 > 纯时间相近。最后一项只用于候选检索，不产生强边。

网络匹配窗口初始 ±2 秒，加双方 `uncertainty_ms`，最高放宽至 ±10 秒；超过该界限只返回候选列表。跨 NAT 没有转换证据则拒绝端点等价。反向五元组匹配需显式记录方向翻转。

因果候选事件 A→B 必须满足 A 最早可能时间不晚于 B 最晚可能时间。若时间区间重叠但顺序无法确认，标记 `order_uncertain`，不能为构造 DAG 强行指定顺序；此类边不进入“严格时间有序路径”，单独显示关联簇。

## 6. 候选入口和路径算法

1. 从受影响资产/高优先 finding 向前查询有界事件图，最多前溯 30 分钟、深度 6、节点 500、边 1000。
2. 入口候选取“可观测范围内首次涉及受影响资产的可疑活动”；外部入口、内部起始点、最早观测点分类型。日志窗口起点有截断时强制标 `left_censored=true`。
3. 去除纯 `precedes` 和 `suggests` 作为路径连接依据；这些只提供上下文。
4. 对时间有序且证据满足的边用 beam search，beam width=20、max_hops=6，禁止重复事件节点，输出 top-3 简单路径。
5. 同分按稳定 ID 排序保证确定性。保留未选择路径与差异摘要，不能只显示最“好看”的一条。
6. 任何必需跳跃缺证时以断点表示，报告“未证实此跳”，不要补一条没有证据的线。

启发式单边分数（初始值，非概率）：

`s = clamp(0.40*identity + 0.25*time + 0.20*relation_support + 0.15*independent_corroboration - penalties, 0, 1)`。

- identity：强原生标识=1；有效资产映射=0.7；仅 IP=0.2；冲突=0。
- time：在允许窗内按距离线性衰减；明确反序=0 并禁止该路径。
- relation_support：明确主机关系=1；多字段匹配=0.6；纯共现=0。
- independent_corroboration：独立采集通道支持=1；同 PCAP 经两个解析器得到的结果不视为两个独立通道，值最多0.3。
- penalties：身份冲突0.4、关键字段缺失0.2、时钟不可靠0.2，累加并裁剪。

`path_score = 0.6*min(edge_score) + 0.4*mean(edge_score)`，并单独展示 `observed_steps, missing_steps, coverage`。不用边分数简单累加，以免长路径天然占优；路径长短与完整性单独评估。输出高/中/低支持度：≥0.8、0.5～0.8、<0.5，仅为界面分层，不等于校准概率。若路径全无合格边，返回“证据不足”，不强制 top-1。

## 7. 知识库与检索

P0 只做与6类规则和3条演示线有关的精选知识条目，每条包括 technique ID/name、平台、适用观测、检测策略链接、已知正常解释、版本和来源。不将整个 ATT&CK 全量内容塞进提示词，也不需要向量数据库。

以 technique ID 精确查找和关键词匹配为主；Agent 获取最多 5 条摘要。ATT&CK 标签是技术分类，不能证明攻击链时间顺序，也不能仅因某组织用过该技术就推断组织归属。

MITRE 已在 v18 弃用旧 Data Sources；新方案保留 Technique、Detection Strategy、Analytics、Data Component 的版本化映射，只在兼容旧资料时保留原 source ID。依据：[弃用说明](https://attack.mitre.org/datasources/)、[检测策略](https://attack.mitre.org/detectionstrategies/)。D1 下载/整理时记录实际版本、对象 ID、来源 URL 和内容哈希，不在规约里猜最新版本号。

## 8. 意图推理

允许输出“更符合凭据尝试/远程访问/周期通信/数据传输的行为模式”；必须附观察、正常替代解释及区分它们所缺的信息。只有流量体积异常时不能断言“敏感数据被窃取”；只有固定周期时不能断言“存在木马 C2”。由知识条目支持调查方向，由事件证据支持现场事实，两类引用分开。
# D11 规模边界补充

图构建先校验全部输入的工作区、数据集与时间范围，再按(event_time,event_id)稳定排序。只投影前500事件，最多500节点/1000边；不能完整加入端点或边时确定性裁剪并设置truncated，不抛出整个调查失败或产生悬空边。合法的同session/parent证据对仍逐个保留至上限。路径输出继承图裁剪标记；coverage仍只表示所选链内覆盖。检测会话上限由DETECTION_EVENT_LIMIT控制（默认/最大10000）；超限保留历史目录并明确partial，详见接口补充。

# P1 精选知识实现增量

已实现固定 ATT&CK Enterprise 18.1 六技术目录和 Technique → Detection Strategy → Analytics → Data Component 版本化映射，文件与许可见 knowledge/README.md。原始来源对象供离线核验，运行时仅提供精确 ID 的最多五条白名单摘要。无匹配不表示该技术不存在；知识不支持攻击因果或操作者归属。R01–R06 冻结规则配置保持。


# P1 全量检测增量（dev17，替代 D11 的 10000 条限制）

默认/最大 DETECTION_EVENT_LIMIT=100000。R03/R04 按既有匹配条件索引并保留同键全部记录；R05 用连续窗口前缀矩优化，阈值附近保留原 Welford 判定，未改规则冻结配置或阈值。R01–R06 全部完成才能标记 complete。

输入字节默认 256MiB、工作单元 2000000、检测时间 20 秒（且不超过 lease/3）、finding 2000、引用总数 500000；各配置与上限见 .env.example / Settings。达到范围上限返回 RULE_SCOPE_TOO_LARGE，其他资源上限返回 RULE_RESOURCE_LIMIT；不截取前 N 条冒充完整检测。检测/目录嵌套事务回滚，原始事件及已发布导入成员保留，旧目录不可当作完整覆盖。调查快照仍最多 250；大候选可能返回 SNAPSHOT_EMPTY_OR_TOO_LARGE，不能强制创建完整调查。
# dev21 独立 R07 扩展

R07 为 HTTP 可执行文件请求候选：GET、200/206、可执行后缀或 MIME，须唯一关联同采集器/UID/端点/时间内的 TCP conn；不是恶意或完成下载判断。DNS 仅可选上下文。旧六规则与 freeze.json 不变；扩展使用独立 http-round1-freeze.json，历史使用 finding 的原配置复现。完整设计见 docs/superpowers/specs/2026-11-17-http-round1-design.md。

# dev22 R08 疑似 C&C 回连候选

R08 组合自定义客户端样式、opaque query 形态、多条唯一关联 TCP 连接与实际响应，在有界 600 秒窗口筛选回连候选，不修改 R05 或 R07。至少 3 请求/3 连接、保守跨度 30 秒、至少 1 条 2xx 且正响应体字节。正常更新/遥测亦可匹配，不代表确认 C&C。使用独立 R08.json/cc-round2-freeze.json；实际设计与边界见 docs/superpowers/specs/2026-11-17-cc-round2-design.md。

第二轮首次真实运行 R08 为零，原结果和冻结保留。独立 R09 使用相同阈值，在同一远端 IP/端口聚合至少两个 Host 的符合条件请求；输出明确标为多 Host 端点候选，不能证明同一服务/控制者，共享托管可能符合。单 Host 不触发 R09。使用新的 R09.json/cc-endpoint-freeze.json；属于已看过样本上的开发补充，不是盲测。

# dev23 独立 R10 非文本查询候选

至少两个唯一关联 TCP 连接的长非文本无键值查询，在保守600秒窗口内产生候选；具体组合谓词、32字节门槛和正常替代见第三轮设计。允许失败响应但不表示控制成功；原始编码、恶意性和身份仍未知。独立 R10.json/cc-nontext-freeze.json；不改R01–R09冻结，不用官方标签或固定样本标识。全部规则执行完成才可发布完整检测目录。

# dev24 独立 R11 增量

R11 使用 rules/cc-encoding-freeze.json 独立冻结，旧 R01–R10 配置及来源语义不变。仅 pcap 来源、GET/POST、同采集器和完整端点/UID唯一连接关联、同源/目的IP:port/Host；查询至少32字节、无字面&/=、非法百分号至少1且合法%HH非ASCII字节至少1，响应完成分帧。600秒窗口使用所有请求时间不确定性极值，至少2请求/2独立连接。重传重组去重，失败响应可形成候选但不证明控制。输出 maliciousness=unknown；正常旧客户端/遥测也可能符合。本轮数据已见，属于开发验证，不能称盲测。跨探针对照仅离线统计，不向运行时注入官方标签。


## P2 包观测消费边界

network.packet 是独立的捕获记录事件。R01–R11 继续匹配各自的旧事件类型，包导入阶段的已解析或已回查仅用于验证证据链。包观测由事件页固定发布水位回查，与旧规则调查快照隔离。具体分片、洪泛及 HTTP 子类型在后续冻结规则实现后再验收，见 PROJECT_SPEC.md 第 10 节。

## P2 IPv4 分片突发候选

R12、R13 和 R14 使用独立 ipv4-fragments-freeze.json。规则从同原件、同探针、同目标、同协议捕获的连续物理记录中提取首片与终片配对。短窗只报告观测到的异常形态；捕获不能证明来源分布、完整分片重组、服务影响或恶意性。候选固定整窗及配对引用，使用持久化配置复现。包候选不参与旧规则的跨事件聚合。

当前分片冻结位于 rules/ipv4-fragments-v11/，版本为 1.1.0。1.0.0 保留，历史结果按保存配置复现。对重复 IPv4 标识，只接受同组物理顺序连续的完整首尾观测序列且组间时间严格不重叠。重复标识的配对数量单独记录。

## P2 HTTP 请求候选

R22 根据同原件、同探针和同目标服务的不同方向连接上可见的完整明文 HTTP/1.x 请求头识别短时请求突发。R23 同时要求不同连接上的延迟序号连续进展及重叠观测区间，缺失后续记录时保留未知。明文应用层形态不说明来源分布、服务是否中断或请求是否恶意。证据固定为实际贡献包，初始阈值见 rules/http-packet-requests-freeze.json，历史复现使用 finding 内保存的配置。旧包观测缺少 HTTP 摘要时不能补造。HTTPS、完整请求头跨包的 R22、反向 TCP 状态与未捕获数据超出这些谓词的能力。

R23 1.1.0 在初始首部分段后要求单独的延迟时间间隔，达到一秒后的头部进展段仍不得超过 128 字节。当前独立冻结为 rules/http-packet-requests-v11-freeze.json，旧 R23 1.0.0 根据已保存的配置按旧语义复现。固定样本与同源扩展单列，见 PROJECT_SPEC.md 第 10.9 节。


dev30 的 HTTP 冻结为 rules/http-packet-requests-v12-freeze.json。R22 1.1.0 核对相隔的两个短时请求组。R23 1.2.0 核查首次延迟后的实际进展，快速完成的连接退出慢头部匹配。缺少进一步证据时目录使用中性的「子类型未知」标签，报告保留原始观测引用。旧 finding 按存储版本复现。R23 在固定 v2 上只生成未分类观测，详见规约 10.11。


## 剩余 21 类首批扩展

dev32 新增 R24 TCP 目的端口扫描候选，配置独立冻结在 rules/ipv4-port-scan-freeze.json。规则按源文件、采集点、可见源和单一目标隔离，同一目的端口在固定窗口内只计一次。报告保留实际包证据与原始位置。对应采集场景是 Recon-PortScan。本阶段区分固定片段、同源补证和独立正常对照，详见 PROJECT_SPEC.md 第 11 节。

## 四类同名洪泛的来源判定（dev33）

R18–R20 1.2.0 与 R22 1.2.0 用实际贡献包统计可见源 IP 数。SYN、TCP、UDP 与重复 HTTP 请求窗发布洪泛形态候选，R22 单次请求窗发布单次突发观测。行为、计数、证据支持级别与来源结论由 flood_observation 记录。单探针数据的来源结论为 unknown，见规约第 12 节。旧 finding 依赖其原冻结，R23 沿用现有语义。

## DoS/DDoS 合并分类（dev34）

R12–R14 1.2.0、R15–R23 1.3.0 在满足原证据门槛时用 `DoS/DDoS-<行为>` 发布候选。匹配窗口、贡献证据、分片配对与 HTTP 进展条件沿用上一冻结。R18–R20、R22 保留可见源地址数与未知来源分布。单次 HTTP 突发和缺少后续进展的 SlowLoris 继续仅发布未分类观测。旧 finding 按原规则版本复现。

## R25 ICMP Echo 地址扫描候选（dev35）

R25 按规约 13.2.1，以同一包级采集范围、同一可见源及 10 秒内 8 个不同 IPv4 目的地址匹配 Recon-PingSweep。只用完整、未分片的 ICMP Echo Request，每目标保留一个实际贡献包。报告区分地址覆盖、目标响应和授权。配置独立冻结，历史 R24 继续按原包证据与版本复现。

## R26 批量 ARP 查询观测（dev36）

R26 按规约 13.2.2 对同一原件和采集范围内的 ARP 请求按可见发送者与不同 IPv4 目标统计。首个有证据的窗口固定保存每目标一条贡献记录。R25 继续独立使用 ICMP Echo，ARP 应答和普通单目标邻居解析不会增加 R26 目标数。R26 1.1.0 将精确子类型保留为未知，直至独立证据能区分主机发现与其他业务的批量 ARP。响应和授权亦保持未知。

## R18 同服务 SYN 证据（dev37）

R18 1.4.0 在原 64 包窗口中至少需要 48 条指向同一 TCP 服务端口的 SYN 作为贡献。只对这些贡献统计套接字和可见源，完整 64 包仍用于回查。已见数据用于回归，其中端口散布与同服务洪泛须分别判定。R24 和其他规则的证据条件延用原冻结。同现的其他独立观测继续输出。

## Recon-OSScan 被动指纹证据验证

按规约 13.2，离线验证采用 Proofpoint Emerging Threats Open 2018489 rev.4 包谓词的保守子集，要求可唯一配对的引用应答和同一可见对端之间独立的 TCP 请求与响应，四条证据位于同一原件与 5 秒窗口。丢失应答或配对歧义时保留未知。完整 OSScan 原件找到 30 组证据，真实 PingSweep 等 4 份其他侦察原件与 10 份正常样本均无匹配。曾固定的三个 2,048 包片段均未覆盖该证据。另选的原件区间可复核同一包号和原件偏移，去掉配对应答后不再形成完整候选。当前仅为离线开发证据，生产规则暂未接入。判据和出处见 artifacts/ciciot2023-recon-os-signature-01/criterion-freeze.json。

## R27 GRE 封装突发（dev38）

R27 按规约 13.3.1 区分 GRE 直接承载 IP 和透明以太网内层，在同一外层目的地址与采集范围使用独立冻结。R20 继续只计外层直接 UDP。R27 的可回查观察不带攻击子类型，精确 Mirai 家族结论需要独立进程或终端证据。

## R28 和 R29 欺骗类证据观测（dev39）

规约 13.4.1 的两份独立冻结限定 ARP 声明的 10 秒范围和 DNS 事务的 3 秒范围。R28 保留同一 IPv4 的两条相邻不同发送地址声明。R29 保留一条无歧义请求及两条地址集合不同的响应。两者均绑定工作区、数据集、会话、观察域、采集器实例和原件。证据可逐包回查，候选保留精确子类型未知。可信解析或绑定对照以及独立授权和路径记录仍为相应精确判定所需。

## R30 被动操作系统指纹探测（dev40）

R30 将已复核的被动指纹判据接入 13.2.3 的原件证据链。要求一对 UDP 与反向 ICMP 引用应答，以及一对 TCP 请求与反向确认，具有四条独立贡献、唯一配对和最多 5 秒跨度。报告说明具体目标系统、授权和操作者未知。同一抓包若也满足 R24，保留两种候选，独立固定集仍按唯一精确类型评分。


## 六阶段流程改造 dev42 增量

dev42 的 Agent get_candidate_paths 只对种子和已完成工具返回集合 K 建图，K 由服务端注入。未知事件通过搜索/上下文工具取得后才进入路径。完整图 API 仍展示授权快照，路径调用不增加非种子证据。既有身份/时间/断点判据保持。
