# D6运行说明

D6增加可恢复Agent状态机、兼容JSON模型协议、六个受控只读工具接口、预算与快照门禁，接入R03/R04。验证输入为本地合成development文件；没有执行攻击、扫描、生产采集或外部模型调用。

## 启动、升级和权限

沿用[d5-runbook](d5-runbook.md)及[d2-runbook](d2-runbook.md)的环境、数据库和令牌配置。在项目根目录，以迁移owner连接执行迁移；运行API/worker前切回应用角色，不用应用角色执行DDL。

```powershell
.venv/Scripts/python -m apps.api.manage migrate
.venv/Scripts/python -m scripts.build_d6_fixture
.venv/Scripts/python -m apps.api.main
# 另开终端
.venv/Scripts/python -m apps.worker
# 另开终端，在apps/web运行npm run dev
```

迁移head为0005_d6，新增agent_states、agent_actions、agent_transitions，不改冻结schema_v1–v4、旧事件/目录/快照/报告。首次建角色使用infra/roles.sql；已有角色只追加授权，不重复CREATE ROLE。已有trace_app应由owner执行：

```sql
GRANT SELECT, INSERT, UPDATE ON agent_states, agent_actions TO trace_app;
GRANT SELECT, INSERT ON agent_transitions TO trace_app;
REVOKE UPDATE, DELETE ON agent_transitions FROM trace_app;
```

reader不新增对Agent行动/状态、令牌或工作区私钥的读取权限。Agent选工具的模型只看到受限Schema与脱敏摘要；固定执行器通过领域服务访问数据，不接受自由SQL、文件路径、shell或任意URL。

## 模式与模型配置

默认MODEL_PROVIDER=disabled，保留旧演示行为。创建调查的mode含义：

| 请求 | 实际行为 |
|---|---|
| auto，模型关闭 | completed + deterministic_fallback，规则/图/模板事实 |
| deterministic | 主动选择模板，completed + deterministic_fallback |
| live，模型关闭或失败 | degraded→partial，保留已验证事实、原因与缺口 |
| auto/live，兼容模型成功 | 模型规划→真实工具→成稿校验，报告live；测试桩另有明确标签 |

启用获授权的模型时，在API与worker相同环境中一起配置MODEL_PROVIDER=compatible、MODEL_BASE_URL、MODEL_NAME、MODEL_API_KEY。BASE_URL是不含chat/completions后缀的根路径，如获准服务的`https://host/v1`；仅回环地址允许HTTP，不允许凭据、query或fragment。不支持自动重定向、隐式重试、流式响应或厂商原生tool-calling；要求JSON chat/completions响应及有效prompt_tokens/completion_tokens。密钥只在本地环境配置，不放URL、浏览器、报告或日志。

本次未验证任何真实供应商/LLM，也未测实际费用。真实模型启用前应另做小样本兼容和费用验收，不能把下方测试桩记录作为真实模型效果。

独立复验本地HTTP协议桩，运行：

```powershell
.venv/Scripts/python -m scripts.browser_d3 --day6
```

脚本自动使用临时数据库、随机回环端口、临时令牌及APP_ENV=test/MODEL_TEST_STUB=true，结束只清理自己启动的进程。可手动以`.venv/Scripts/python -m scripts.model_stub --port 18081`启动桩；配套API/worker仅在测试环境设置BASE_URL=http://127.0.0.1:18081/v1、MODEL_NAME=protocol-test-stub、任意本地测试key、MODEL_PROVIDER=compatible、MODEL_TEST_STUB=true，关闭后恢复原环境。页面必须显示“本地协议测试桩（非真实LLM）”。

## 四规则闭环

创建新synthetic数据集，先配置data/fixtures/d6/context.json，再按顺序导入并等终态：

| 文件 | source_type | sensor_id | 新增规范事件 / 物理行 |
|---|---|---|---|
| network.jsonl | zeek | net-a | 25 / 25 |
| auth_a.jsonl | linux_auth | auth-a | 6 / 6 |
| audit.jsonl | linux_audit | audit-a | 3 / 6 |
| auth_b.jsonl | linux_auth | auth-b | 1 / 1 |

最终35条规范事件、38物理行。最新事件目录应有一个R01 / R02 / R03 / R04聚合候选、5个finding：R01和R02各一、R03一、R04两个不同源锚点。A的强可疑会话与异常子进程分别支持资产级A→B访问候选，不代表两个独立攻击或已证实横向移动。未导入auth_b时R04只显示attempt；新目录升级候选，历史attempt版本保持可读。

选择live开始调查，查看阶段/状态版本/预算。协议桩第一轮search_events读取3条主机事件，补充1条未入规则种子的生命周期记录；第二轮get_event_evidence读取真实哈希核验脱敏片段；第三次模型调用成稿。点击“刷新 Agent 记录”查看5条行动（3模型、2工具）、新增证据数和转换记录。工具证据可点开抽屉；图、时间线、路径沿用固定快照。模型草稿不会创建图边，observed文字由程序根据已验证谓词生成。

普通反例：在另一个新数据集配置相同context，导入normal_network/net-a、normal_auth_a/auth-a、normal_audit/audit-a和auth_b/auth-b，预期无R01–R04。不要把两套夹具导入同一数据集当独立正反例。

## 预算、恢复与只读边界

默认6工具、4模型、2规划轮、输入12000/输出3000 token、单模型≤20秒/累计等待≤60秒、总墙钟≤90秒；API预算只能缩小。未知工具/不合规参数计入预算后拒绝；零预算不会发出模型请求。缓存只复用同run/snapshot/规范参数的已完成工具结果，连续2次无新增证据或两轮结束转成稿。

调用前持久预留；input用请求UTF-8字节数作为保守上界，成功有效usage才结算。失败、取消、进程退出后未决行动的预留保留，不退回重新调用。数字可能含未实际完成的预留，不等于模型实际收费。worker租约恢复不会重置预算或总时间；配置摘要改变转partial，需新建调查使用新模型配置。

模型传输使用可终止子进程；超时、取消、租约失效关闭连接；子进程也有父进程崩溃后的超时退出。清理进程有有限等待，90秒是调查计算预算而非承诺任何系统故障下的端到端响应SLA。工具是固定只读有界查询，单次≤3秒、响应≤16KB、limit≤100；超时/租约失效结果不得发布。证据工具最多3个物理片段/页、长行900字节截断并提示，通过签名游标继续；人工API仍最多20行/页。

范围来自真实run/snapshot，最多250事件/30分钟；越工作区、事件、时间窗、incident、游标作用域均拒绝。上下文裁剪保留scope、工具参数/游标、truncated、coverage和warnings，预算不够则降级。日志/模型内容不能提升权限；不记录隐式思维链。

GET investigations/{id}/tool-calls仅analyst/admin，GET /transitions允许viewer。行动和转换都有稳定游标；取消沿用作业取消API。completed/partial报告均可查看；数据损坏仍按旧规则拒绝不可验证证据。

## 复验与剩余工作

```powershell
./scripts/check-d6.ps1
# 若本机便携PostgreSQL已准备好，先启动再附加真实数据库/浏览器测试
.venv/Scripts/python -m scripts.pg_sandbox start
./scripts/check-d6.ps1 -Postgres -Browser
.venv/Scripts/python -m scripts.pg_sandbox stop
```

PostgreSQL脚本新建随机测试库/角色，不操作业务库，也不声称自动删除这些测试库。浏览器截图/日志在artifacts/d3-browser至d6-browser；D6运行结果见[d6-verification](d6-verification.md)。

未交付：真实LLM/费用验收、知识条目（工具返回LOCAL_KNOWLEDGE_NOT_LOADED）、R05/R06、进程socket与完整横向移动因果、任意原生日志/在线采集、跨批次audit轮转、报告缓存/replay/导出/人工复核、独立场景性能评估及Compose部署。D6是受控调查原型，不等于全部P0或竞赛发布已验收。
