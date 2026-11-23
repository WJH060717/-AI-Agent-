# D4运行说明

D4在D3持续worker/租约/快照基础上增加Linux结构化主机输入与R02。只处理授权离线文件，不执行攻击或采集命令；模型仍未启用。

## 启动与迁移

使用已有`.venv`与`apps/web/node_modules`。环境、数据库启动、令牌初始化见[d3-runbook.md](d3-runbook.md)和[d2-runbook.md](d2-runbook.md)。先用迁移owner执行：

```powershell
.venv/Scripts/python -m apps.api.manage migrate
.venv/Scripts/python -m scripts.build_d4_fixture
.venv/Scripts/python -m apps.api.main
```

另开终端启动`.venv/Scripts/python -m apps.worker`，在`apps/web`运行`npm run dev`。新迁移`0003_d4`从0002升级，保留旧事件/报告；增加批次物理计数、作业JSON检查点、不可变上下文与工作区私有HMAC密钥。schema_v1/v2保持冻结。应用角色升级后需由owner追加对两张新表的SELECT/INSERT，并禁止UPDATE/DELETE；reader不能读workspace_private_keys。完整首次建角色模板见infra/roles.sql，已有角色不要重复CREATE ROLE。

## 页面演示

1. 在“概览与导入”连接admin令牌，创建新的synthetic数据集。
2. “上下文 JSON”选择`data/fixtures/d4/context.json`，点击“配置上下文”。必须在首次导入之前；返回哈希，不返回密钥。相同配置可重试，不同配置409，应创建新数据集。
3. 分别导入下表文件，等每批终态后继续。上下文配置了哪些sensor，就必须使用相应来源和sensor_id。

| 文件 | 来源 | sensor_id | 预期新增事件 / 物理记录 |
|---|---|---|---|
| network.jsonl | zeek | net-a | 6 / 6 |
| auth_positive.jsonl | linux_auth | auth-a | 6 / 6 |
| audit.jsonl | linux_audit | audit-a | 1 / 3 |

4. 刷新事件可查13条规范事件。audit的SYSCALL/EXECVE/EOE合为1条host.process，引用3个原始行；`aggregated_records=3`表示进入聚合的物理行，`accepted=1`表示新增规范事件。
5. 打开“安全事件”→刷新检测事件→R02→生成模板调查。可见通信、成功认证、会话关联进程，以及五元组/资产/时间匹配的corresponds_to推断关系。exec本身不是新进程出生，不产生spawned。
6. 展开全部边或报告证据查看脱敏行。每页最多20行，续页游标绑定令牌、工作区、快照和事件；哈希损坏或越界拒绝。SVG最多12节点，列表保留全部返回边；虚线推断不等同攻击因果。
7. 同数据集重新选同一文件上传，新增0、重复计数增加，事件总数及原报告不变。

反例在独立新数据集配置相同context后，仅导入`auth_below_threshold.jsonl`、`auth_other_account.jsonl`或`auth_reverse_time.jsonl`之一，预期无R02。这些是development合成例，不是独立性能评估集；运行时不读取真值或答案。

## 上下文和最小输入协议

上下文为严格DatasetContext：assets含稳定UUID、允许hostnames与IP半开有效区间；sensors含sensor_id/source_type、asset_id、instance_id、observation_domain、realm_type/realm、offset_ms、uncertainty_ms、clock_basis。Linux必须绑定已有资产。校正定义`event_time=原时间+offset_ms`。错误时钟配置需新数据集重导，不能改历史。

auth每行是UTF-8 JSON对象，必需带offset的timestamp、已绑定host、src_ip和auth(outcome/method/service)。强账号另需user.uid（数字稳定UID）与匹配realm；boot_id和session_id用于会话。用户名只作工作区HMAC显示；本地账号按资产隔离，域账号按realm隔离。缺UID/boot不伪造，R02不适用。示例文件是完整可运行协议，不是任意syslog原文。

audit每行含timestamp、host、boot_id、audit_serial、record_type。支持SYSCALL/EXECVE/CWD/PATH/EOE；SYSCALL.process需pid/action，强身份需可信identity_basis(lifecycle_record/verified_proc)+start_ticks或start_time+boot。父身份需ppid+parent_start_ticks，exec时间不能充当出生时间。命令行不复制到派生事件。聚合键含资产、boot、序号、时间；最多64片段/256待定组，单上传内支持交错和跨500行检查点。EOF缺片段保留弱partial_audit事件，不能赋强进程身份；非法/超限行隔离。

IP映射必须在同观测域且整个不确定时间区间内唯一有效；重叠、跨租约边界保持ambiguous。先后约束要求前一事件最晚时间严格早于后一事件最早时间；不能凭接近、PID、IP或用户名合并。corresponds_to只作有界候选；NAT缺转换证据时不会越过端点变化强接。

## API与复验

新增`POST /api/v1/datasets/{dataset_id}/context`，Bearer admin、Idempotency-Key，JSON为context.json；返回dataset_id/context_hash。Linux上传沿用`POST /imports`，source_type选linux_auth/linux_audit。GET imports增加raw_records/aggregated_records；GET evidence新增可选cursor和next_cursor。规范事件1.1增加host；旧1.0仍接受，旧快照引用保持有效。

```powershell
./scripts/check-d4.ps1
# 本机便携PostgreSQL需先启动；可选验收需要本地进程权限
./scripts/check-d4.ps1 -Postgres -Browser
```

浏览器自动化使用随机本地端口、临时SQLite/令牌，只清理自己创建的进程。输出`artifacts/d4-browser/closed-loop.png`、`playwright.log`、`services.log`、`results/.last-run.json`；D3回归另存d3-browser。PostgreSQL脚本创建随机独立库，不改业务库；便携实例使用后可`.venv/Scripts/python -m scripts.pg_sandbox stop`。

## 尚未实现

任意发行版原生auth.log/audit.log文本解析、在线collector、轮转文件HTTP manifest及跨批次未闭合audit合并，仍属T-07后续。底层parse_audit_group可以接收来自不同对象的显式片段，但HTTP上传不声称自动跨文件拼接。Agent、攻击路径搜索和R03–R06仍待后续；本日没有准确率、吞吐量或真实攻击溯源成绩声明。
