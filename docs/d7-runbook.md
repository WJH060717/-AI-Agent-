# D7运行说明

D7接入R05/R06、按已核查证据更新的缺口/判断、context_only反向线索、补证前后对比及明确循环停止原因。输入为授权离线文件，验证使用synthetic/development数据及明确标注的本地HTTP协议桩；没有攻击执行、真实采集或外部模型调用。

## 升级和启动

沿用[d6-runbook](d6-runbook.md)的环境、令牌和API/worker/Web启动方式。数据库结构没有变化，迁移head仍为0005_d6；schema_v1–v5保持冻结，不创建无用途的新表。首次部署/旧版本升级仍由owner执行迁移，API/worker切回应用角色，权限沿用D6。

```powershell
.venv/Scripts/python -m apps.api.manage migrate
.venv/Scripts/python -m scripts.build_d7_fixture
.venv/Scripts/python -m apps.api.main
# 另开终端
.venv/Scripts/python -m apps.worker
# 另开终端，在apps/web执行npm run dev
```

API健康阶段为d7，软件版本0.1.0.dev7。模型默认关闭；auto+disabled或deterministic保留模板完成模式，显式live失败为partial。协议、密钥配置、预算及HTTP硬超时沿用D6，不提高6工具/4模型/2规划轮、12000/3000 token、累计60秒等待/90秒总预算。

## 六规则中的新增规则

R05按workspace/dataset/session/domain及sensor_id+instance_id隔离，同源资产或端点→目标IP/port/协议聚合。检验1200秒内连续子窗、≥8次、最坏时间跨度≥300秒、间隔CV保守上界≤0.15；去重排序、严格间隔，无法确定顺序或IP映射歧义时不强算。前置噪声不能遮蔽后续周期段，也不能删除内部不规则记录。连续重叠达标窗口合并成跨度<1800秒候选段，超长活动有界分段；qualifying_windows保留覆盖整段的达标窗口端点/统计，statistics是整体摘要，其CV可高于阈值，不能当作单一1200秒窗。只称periodic_connection，监控心跳、更新也可符合，不直接认定C2。

R06只计唯一inventory_interval源资产对应的Zeek originator bytes_out，按UTC对齐300秒连接起始桶求和；它表示该桶开始的连接字节计数，不是实际逐秒传输速率，也不自动等于向公网发送。跨桶不确定的时间记录不强分桶，bytes_in、未知/歧义源资产、不同采集通道不凑数。固定阈值10,000,000字节（十进制10 MB）。

基线充分时，严格大于同资产/域/通道正常开发参考窗口的nearest-rank p95三倍才产生outbound_volume_anomaly；等于三倍不触发，整数精确比较。少于30个有效历史参考窗口时只输出fixed_threshold_signal。充分高基线下的正常备份不触发R06，但周期监控仍可触发R05模式，不把正常进程简单作为规则全局豁免。

## 冻结历史参考输入

首次导入前，DatasetContext可包含egress_baselines（最多10组）。每组有id/version、asset_id、sensor_id/instance_id、observation_domain、metric=connection_start_bytes_out@1、purpose=normal_development_reference、provenance_type、source_sha256、samples。每条sample含start/end/bytes_out，必须UTC对齐5分钟、长度300秒、不重复不重叠，最多120条。只能引用已配置资产及匹配的Zeek通道，每个绑定唯一；实际检测只用end≤当前桶开始的历史窗口。

data/fixtures/d7/context.json是可运行示例。正常开发参考是管理员提供的运行配置，不从eval/ground_truth、测试标签或模型自评分读取；来源声明hash不等于已独立核验的采集事实。R06 finding冻结实际参考和baseline_hash，ID也绑定该hash；旧finding复现不读取当前新基线。既有context不可修改，调整参考应新建数据集；没有基线时旧context的规范化字节与哈希保持兼容。

## 正例闭环与前后变化

1. 创建新synthetic数据集，先上传data/fixtures/d7/context.json封存上下文。
2. 导入network.jsonl，来源zeek、sensor_id=net-a，等待9条规范事件成功。
3. 导入audit.jsonl，来源linux_audit、sensor_id=audit-a，等待2条规范事件成功（4物理行）。最终11事件/13物理行。
4. 安全事件刷新：一个R05 / R06聚合调查候选、两个finding。R05为8次60秒周期连接，跨度420秒；R06第一桶计数12,005,000字节，正常参考30窗、p95=1,000,000字节。
5. 在已配置协议桩的测试环境选择live开始调查。第一轮get_asset_timeline实际取得同快照的11事件，补回2条不在规则种子中的强主机进程观测（node_exporter、rsync）；第二轮get_event_evidence核对所选反向线索的真实哈希/脱敏片段，再成稿。
6. “缺口补证与分析变化”显示种子9条→已核查11条；R05/R06恶意用途判断由open变weakened，两个变化都标行动2并可点开证据。正常线索仅context_only，不证明进程发起连接、运维已授权或没有攻击。
7. 查询终止ACTIONABLE_GAPS_RESOLVED只表示当前可补证缺口已得到上下文；socket绑定、运维授权及传输内容仍列为未解决/当前能力不可补齐，不能宣称完整溯源。

before/after是Agent已核查集合的变化：before只用成员规则种子，after只加真实工具返回的快照事件。既有规则和图算法可以使用全快照；这里不把既有图边假称为工具事后新增。比较不会把窗口外新数据混进来，也不从隐藏真值或预写答案读取变化。

本地独立复验：

```powershell
.venv/Scripts/python -m scripts.browser_d3 --day7
```

脚本自动启动临时SQLite、随机回环端口、API/worker/Web和HTTP协议桩，界面明确“本地协议测试桩（非真实LLM）”。实际模型自主选择的查询可能不同；该桩只验证协议和控制流程，不能作为真实LLM推理效果。截图/日志输出artifacts/d7-browser。

## 正常、缺证与恢复反例

- 在另一新数据集配置normal_context.json，再导入相同network/audit：高正常备份参考使R06不触发；R05仍报告周期观测，补证后保留正常监控替代解释。
- 新数据集配置context.json，导入irregular_network/audit：不规则小连接不触发R05/R06。
- 独立数据集从context移除egress_baselines再导入network：R06只固定阈值信号；当前调查无法补写冻结基线。
- 相同进程名但异资产/域、弱PID、窗口外记录或日志里自称“已批准”都不能削弱判断。空查询保留open，不据此排除活动。
- R02会话缺口只由同Host/boot/账号/session且严格先后的进程证据支持；旧R04 attempt可在新建的固定快照内由匹配B成功认证补齐判断，原finding仍是原版本，缺socket仍保留。
- 反复同参数查询复用同run缓存；连续2次无新增事件ID→NO_NEW_EVIDENCE；最多2规划轮→MAX_PLANNING_ROUNDS；模型主动成稿→MODEL_REQUESTED_DRAFT。次数/token/时间耗尽或非法调用→partial并保留原因，零工具预算不执行工具。
- 检查点冻结判断配置与before，行动结果、检索集合、changes与阶段同一guard事务提交；恢复不重复变化、不重置预算。取消/租约失效晚响应继续按D6拒绝发布。

## API和复验

GET investigations/{id}新增query_stop_reason，与失败stop_reason分开。GET reports/{id}可含typed investigation_analysis（config_hash、before、after、changes、stop_reason）；viewer可读脱敏对比及快照证据，行动明细仍仅analyst/admin；跨工作区404。旧报告缺新字段保持原内容，不回填重算。

每run最多20判断、100缺口、40状态变化；超出判断范围明确truncated，不把裁剪当全量完成。对比契约在packages/contracts/models.py，状态辅助在agent/evidence_state.py，固定判断配置在rules/investigation.json。模型可见摘要更小且显式标截断，仍保留D6作用域/游标/覆盖范围，无法装入剩余输入额度则降级。

```powershell
./scripts/check-d7.ps1
# 已准备好的便携PostgreSQL，可选数据库与D3–D7浏览器验收
.venv/Scripts/python -m scripts.pg_sandbox start
./scripts/check-d7.ps1 -Postgres -Browser
.venv/Scripts/python -m scripts.pg_sandbox stop
```

PostgreSQL验证新建随机测试库与角色，不操作业务库，不自动删除测试库。实际结果见[d7-verification](d7-verification.md)。未完成真实LLM/费用、知识条目、独立数据集检测指标、实际Linux采集/socket、导出复核/缓存replay和发布部署验收；当前结果不代表完整P0已交付。

已知低优先级文案项：通用模板建议仍部分沿用扫描措辞，后续按R05/R06细化；本日结构化判断、反向线索与引用已按新规则核验。
