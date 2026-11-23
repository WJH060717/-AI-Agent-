# D9 运行说明

日期：2026-11-15。API 0.1.0.dev9 / stage=d9；数据库head为0006_d9。新增report_reviews，旧迁移、原始证据、报告与快照不回写。依赖沿用现有锁文件。

## 运行与验证

配置既有本地DATABASE_URL后，用迁移账号执行：

```powershell
.venv/Scripts/python -m apps.api.manage migrate
.venv/Scripts/python -m scripts.build_d9_fixture
.venv/Scripts/python -m apps.api.main
# 另一个终端
.venv/Scripts/python -m apps.worker
# 前端终端：apps/web
npm run dev
```

不重新init已有工作区、不轮换令牌、不清库。PostgreSQL应用角色须追加report_reviews的SELECT/INSERT及report_reviews_seq_seq的USAGE/SELECT，禁止UPDATE/DELETE；完整新装权限模板见infra/roles.sql，已有角色不要重复CREATE ROLE。

```powershell
./scripts/check-d9.ps1
# 使用已存在且已启动的隔离PG测试实例；新建随机测试库，不操作业务库
./scripts/check-d9.ps1 -Postgres -Browser
.venv/Scripts/python -m eval.freeze --output artifacts/d9-inventory.json
# 完整资料/双人标签门禁：当前预期exit 2，不得称为已通过
.venv/Scripts/python -m eval.freeze --require-ready
```

PG测试实例启动/停止使用既有scripts.pg_sandbox start/stop；不使用init覆盖现有实例。浏览器脚本只启动/关闭自己的回环服务与协议桩。

## 报告、审计和人工复核

- GET `/api/v1/reports/{id}/export?format=json|html`：analyst/admin下载自包含脱敏附件，含原报告、冻结快照范围、全部快照事件的逐行投影与哈希、run终态、追加复核。HTML不依赖外网，结论引用链接跳到同附件目录，所有动态文字转义。默认最多5000投影行/5000000字节/1000复核，超限明确422；原始证据损坏409。不是原始对象打包，也不是司法真实性背书。
- GET `/api/v1/raw-objects/{id}/download`：analyst/admin单独下载完整原始对象，校验哈希/字节数/归档根目录；成功及角色拒绝记审计。前端令牌只在Authorization头，附件不含令牌、数据库配置或原始路径。
- POST `/api/v1/reports/{id}/reviews`：claim_id、accepted/rejected/needs_more_evidence、1–2000字符comment；Idempotency-Key必填。意见只追加，返回review_id、服务端actor_id/time。同键同内容返回原记录，不同内容409；claim不在报告422；跨工作区404。actor_id是本地角色令牌身份的不可逆派生标识，不代表实名或独立评审人。
- GET reviews分页：固定序号水位，游标绑定工作区/身份/报告；viewer可看意见。GET `/incidents/{id}/reports`：首次建立目录最多50份历史版本，超限422；已签发的固定ID目录不受后续新增报告影响，不重算旧报告。
- 网页报告面板提供逐条复核、历史版本切换、导出和缓存。刷新后可从候选的“查看历史报告”载入已有版本；viewer无需创建调查。缓存显示下的导出仍下载原报告模式/原时间，页面明确说明。

## 费用预算与缓存

所有费用是USD估算，不提供或编造供应商报价。`.env.example`的示例价格只是占位；真实模型需配置MODEL_INPUT_USD_PER_MILLION、MODEL_OUTPUT_USD_PER_MILLION、MODEL_PRICE_VERSION（报价日期/版本）及AGENT_MAX_COST_MICROUSD。100000微美元=USD0.10。默认费用上限0；未配置定价返回MODEL_PRICING_UNAVAILABLE并降级。仅显式回环test_stub且两种价格均缺省时计为免费协议测试。

请求budget.max_cost_microusd只能收紧服务端限额。调用前按输入UTF-8字节上界及最大输出token向上取整预留，Queue.guard与状态版本检查后持久化，再调用模型；cost_microusd保守占用不退款，actual_cost_microusd只累计有合法usage返回的估算。失败、超时、恢复均不能重置占用；价格、上限和执行代码指纹进入持久配置哈希，恢复时变化则以MODEL_CONFIGURATION_CHANGED降级，且不发布新缓存键。旧版未终结运行升级后也保守降级；已有报告保持原件。

GET `/reports/{id}?mode=cached`显式读取历史视图；无新run、无模型调用、原生成时间不变。精确键绑定workspace/snapshot/scope/事件内容与原始定位/成员finding配置/预算/模型配置，以及Prompt、工具Schema、检测、图、解析器、报告模板代码和规则配置文件的摘要；知识版本固定not_loaded。无键的旧报告409，配置或内容漂移409，原始完整性失败409；普通GET仍允许看有标记的历史报告。格式化相关代码也会保守使缓存失效，不做模糊匹配。

GET `/runtime-config`仅admin读取安全运行摘要，不返回URL、口令或路径。API限流仍为单进程重启重置；不替代持久Agent预算。

## 三条工程演示线

`build_d9_fixture`输出明确合成的开发演示材料，不执行网络活动、不算33次独立实验，不导入eval真值。

| 线 | 输入 | 可演示及保留边界 |
|---|---|---|
| S1 | d9/S1/context.json，network(net-a)、auth_a(auth-a)、audit(audit-a)、auth_b(auth-b)、alerts(alert-a) | 37规范事件；网络/主机/安全告警三类齐备；认证、进程、管理连接、后续出站计数。后段R06时间窗不重叠，保持独立候选，不能为了完整故事硬合并；缺进程socket，不能证明文件内容、成功横移或完整因果 |
| S2 | d9/S2/context.json、network、audit | 周期通信、出站量与监控/备份正常替代上下文；工具补证，context_only不等于无攻击 |
| S3 | S2 context/network，省略audit且将模型调用上限设为0 | partial、缺主机证据与预算停止原因仍可导出；不补造跳跃 |

先配置context再上传；来源依次zeek/linux_auth/linux_audit/linux_auth/suricata。每条线从候选→调查→引用→复核→JSON/HTML→离线打开→匹配缓存。浏览器测试使用真实API/worker与回环协议桩，**不是真实LLM或真实采集验收**。

## 数据冻结与未完成项

eval/freeze-d9.json冻结runs、dossiers和规则配置的语义摘要；校验同时复核输入对象hash、谱系和跨split泄漏。eval/dossiers.json为待补资料台账，不伪造真值或人名。新冻结用`--create --freeze <新文件>`只允许新建，不覆盖旧版本；资料/标签变化必须新版本、来源依据和人工复核，不修改旧冻结来冒充盲测。

当前33项planned（dev12/val6/test12/demo3），3个prepared开发输入包，0个双人复核。真实S1多源采集、33份独立资料、两人标签复核、真实LLM调用/价格实测、完整评估、知识条目、Compose及干净环境发布仍未验收。D9工程可构建与完整D9业务资料门禁分开报告。
