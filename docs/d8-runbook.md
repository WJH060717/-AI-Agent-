# D8 运行说明

日期：2026-11-15。当前项目路径 D:/挑杯；API 0.1.0.dev8 / stage=d8，数据库head仍0005_d6。沿用D7依赖，不需要新增数据库迁移，不修改旧快照、原始证据或旧报告。

## 本日范围

| 规约任务 | 实现入口 | 可观察行为 |
|---|---|---|
| 预算/限流/统一错误 | apps/api/limits.py、errors.py、main.py；原AgentRuntime | 持久预算保持；API超额429和Retry-After；异常统一安全信封 |
| 六规则验收和冻结 | rules/freeze.json、packages/detection/freeze.py | 主检测入口使用核对后的配置，语义漂移拒绝；旧finding仍用自身配置复现 |
| 引用/谓词/降级 | agent/validation.py、Report.claim_validation | 六种有限谓词、严格字段类型、原始定位、已知ID范围；一次修复，失败partial |
| 缺证界面 | MissingEvidence.tsx | 事实校验不等于调查完整；停止原因、拒绝代码、未解决缺口及补采建议 |
| 批量数据清单 | eval/runs.json、eval/inventory.py | 33项待采集计划+3份已有开发输入包；核验派生链、划分、原始哈希 |

## 运行与复验

在项目根目录执行（PowerShell）：

```powershell
.venv/Scripts/python -m eval.inventory --output artifacts/d8-inventory.json
./scripts/check-d8.ps1
# PostgreSQL测试实例已存在时，启动独立本地测试服务后执行：
.venv/Scripts/python -m scripts.pg_sandbox start
./scripts/check-d8.ps1 -Postgres -Browser
.venv/Scripts/python -m scripts.pg_sandbox stop
# 仅D8真实浏览器闭环，使用临时SQLite和本地协议桩：
.venv/Scripts/python -m scripts.browser_d3 --day8
```

check-d8委托D1–D7检查，运行全部Python测试、Ruff、pip check、契约生成、前端typegen/typecheck/lint/build；可选PG及D3–D8六个浏览器闭环。PG脚本创建随机隔离测试数据库和角色，保留它们供复查，不清业务数据。浏览器脚本只停止自己启动的进程。运行日志/screenshot在artifacts中；不把测试桩称为真实LLM。

业务启动沿用d7-runbook，必须先配置数据库及角色令牌。模型默认disabled，不新增付费调用。D8开发期与既有规约一样只处理授权合成/本地实验数据。

## API额度和错误

.env.example新增：API_READ_REQUESTS_PER_MINUTE=120、API_WRITE_REQUESTS_PER_MINUTE=20、API_RATE_MAX_IDENTITIES=1024。每个已认证workspace+token摘要身份共用60秒固定窗口，GET/HEAD读与其他方法写分别计数，线程锁保证同进程并发一致；失败业务请求和幂等重试也计数。满额先返回429，业务处理器未执行；Retry-After为至少1秒的剩余窗口时间。无效令牌不建立身份桶。活跃身份表满时不驱逐旧额度，直到某桶过期；health不占额度。

这是单API进程原型限流，进程重启重置，多个API进程不共享额度，不提供匿名流量/分布式DoS防护。Agent的调用、token、等待和总时长预算仍在数据库持久预留，不随API限流重置。预算上限和失败/中断不退逻辑保持D6；没有虚构货币费用估计。

错误保持error{code,message,request_id,details}，所有本应用生成错误有匹配的X-Request-ID；429额外Retry-After。401/403/404/409/413/422/429/503及意外500不回显原始异常、请求体、路径或密钥。超长/异常Content-Length也受约束。基础HTTP服务器在进入应用前拒绝的请求不保证本应用信封。

## 有限事实校验

六谓词：connection_seen、auth_outcome、process_parent、rule_triggered、path_candidate、periodicity_observed。引用必须在种子/实际检索已知集合且在快照事件表中，具有原始定位；对象完整性在分析开始及发布前校验。端口仅严格整数，不接受布尔/浮点数；请求验证asset_id时必须存在真实资产，字符串None不能匹配缺失值；无值谓词、缺失字段不能充当事实。程序生成observed措辞，模型statement不能覆盖已验证事实。

自由inferred/unknown claim统一为待核查的未知，不原样发布未核实身份陈述；行动审计保留受限原稿供analyst复查，文本不会执行。模型替代解释和缺口仍明确标待复核，不作为观测事实。真实操作者归因、任意工具、scope注入、伪引用/伪路径/反向事实拒绝。

Report新增可选claim_validation：方法finite_predicates@2.0.0、生成时integrity=verified、最终观测/未知数、rejected_codes最多2、repair_attempts最多1、stop_reason。修复计入四次总模型调用；修复成功仍保留曾拒绝代码，仍失败为partial+deterministic_fallback，仅发布程序核验事实。validation=passed只表示保留结论通过，不能覆盖run.partial语义。旧报告无字段时显示缺少历史摘要，不重算。读取时原始文件缺失或损坏会使当前report.validation=partial；页面优先醒目警告“当前原始证据不可验证”，历史claim_validation不被回写，也不把此情况混称为调查未完成。

R01–R06报告分别使用扫描、认证、进程维护、远程管理、心跳、备份解释与建议，修复D7纯R05/R06仍写扫描的问题。正常进程仍只context_only；未知socket、授权、内容保持。

## 配置冻结与批量清单

rules/freeze.json冻结六规则解析后的全部配置（含默认值）及SHA-256，来源为既有开发回归，不声称验证集调参或正式测试指标。registry.detect_all核对当前文件后用同一批已核对对象执行；格式/空白变更不改变语义摘要。漂移导致RULE_CONFIGURATION_DRIFT拒绝检测，不静默重写锁。直接底层规则函数用于显式配置开发测试；历史reproduce不依赖当前冻结文件。冻结文件不是签名，也不防止具有项目写权限的人同时改规则与冻结记录。

更新阈值需新版本、说明理由与开发/验证依据、更新冻结记录和回归；已看过的test不能再称未见盲测。运行时包不导入eval。

eval/runs.json中dev12/val6/test12/demo3均为planned，seed和activity_group只是预约，尚无原始数据/双人标注。额外legacy-d3/d6/d7三个prepared输入包有实际文件哈希，统一legacy-development-regression组，不能当作3个独立实验。prepared仅表示输入可读且哈希正确，不能当已运行或已验收。正式33次采集、真实S1多源采集、双人复核及指标属于后续工作。

核验器只检查清单/哈希/分组/谱系，不执行任何正式test；同活动组跨split、父子split/group不一致、缺父项/循环、重复run ID、原始对象哈希跨split、目录逃逸或输入损坏均失败。派生/回放必须声明parent。相同内容不同格式、隐瞒谱系或其他语义近重复仍需人工审查。

## 演示D8

浏览器脚本先只导入D7 network，创建live且max_model_calls=0调查：不调用模型，partial/fallback、MODEL_CALL_BUDGET_EXHAUSTED、9→9、正常进程缺口未解决。再导入audit后创建新调查，预算恢复为4；本地协议桩实际调用两个只读工具，9→11且有context_only变化。旧调查不补写，新调查继续保留socket/授权未知。

artifacts/d8-browser/missing-evidence.png与closed-loop.png展示两阶段；不是正式评估结果。可人工创建live模型不可用/零预算调查验证降级，不需要发送攻击或真实敏感日志。D8另有真实MissingEvidence组件的SSR+浏览器断言，验证当前完整性失败不会展示历史校验成功；它是组件回归，不算第二条完整端到端场景。

## 剩余边界

没有验收真实LLM、生产多源采集、完整攻击因果、真实操作者、知识库、导出复核或正式33次统计。缺证页面按已有结构化缺口和报告显示，不推断从未记录的来源完整性。所有P0发布门禁仍需D9–D15后续验收。
