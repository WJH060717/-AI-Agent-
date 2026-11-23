# D3运行说明

已打通：上传→连续worker→500行检查点→R01候选→事件队列→冻结快照→调查作业→连接观测图→确定性模板报告→引用对应的脱敏原始行。没有调用模型、执行网络扫描或新增攻击处置能力。

## 1. 升级

先停止旧D2 worker/API。备份已有数据库与原始归档；使用迁移owner设置DATABASE_URL后执行：

```powershell
.venv/Scripts/python -m apps.api.manage migrate
```

升级至0002_d3，保留0001表定义与现有数据；新增租约/检查点列、batch_events、findings、incidents、snapshots、investigation_runs、reports。已有D2 running作业lease为空，可被接管；已有完成的会话事件仍可查询。

owner对新表重新为应用角色授权，参考更新后的infra/roles.sql：已有角色不要重复CREATE，执行GRANT/REVOKE部分。应用账号可以追加新证据与报告，但不能UPDATE/DELETE events、raw_objects、findings、snapshots、reports、batch_events、audit_logs；不能建表或改alembic_version。API/worker切回应用DSN，勿使用owner长期运行。

未配置过本地环境时先按d2-runbook初始化、保存一次性令牌。不要覆盖已有.env；新增参数参见.env.example，默认60秒租约、10秒心跳、3次尝试、1秒轮询、500行分段、250事件快照上限。心跳周期必须小于租约。

## 2. 启动

在相同DATABASE_URL/RAW_STORE/STAGING_STORE配置下，三个终端分别运行：

```powershell
# 根目录：API
.venv/Scripts/python -m apps.api.main
```

```powershell
# 根目录：持续worker，Ctrl+C请求退出；当前作业完成后停止领取
.venv/Scripts/python -m apps.worker
# 可选：一次作业或有限批量（按尝试次数计数）
.venv/Scripts/python -m apps.worker --once
.venv/Scripts/python -m apps.worker --max-jobs 2
```

```powershell
# apps/web
npm ci
npm run dev
```

worker默认串行处理导入和调查，空闲等待；不创建无限线程。每个已领取作业有一个受控心跳线程，结束后停止。SIGINT/SIGTERM停止后续领取，强制终止通过租约恢复。数据库不可用时记录警告并继续轮询；不可重试的数据完整性错误直接失败。

## 3. 第一个可演示场景

1. 根目录运行`python -m scripts.build_d3_fixture`（使用项目.venv），生成三个明确标注synthetic/development的本地JSONL，没有任何真实网络扫描。
2. 页面“概览与导入”输入admin令牌，创建合成数据集，上传`data/fixtures/d3/port_scan.jsonl`，选择Zeek。后台自动消费，完成后accepted=24。
3. 点击“刷新事件”看到规范连接，切换“安全事件”，点“刷新检测事件”，出现R01扫描候选。
4. 点“生成模板调查”，等待queued→running→completed，出现观测图、deterministic_fallback报告、未知项与正常解释。
5. 点报告“证据1”或展开边的引用，显示对象ID、SHA-256和行号/脱敏投影。完整原始对象不暴露给viewer。
6. 三个分析导航目前共用同一最小调查组件，切换不丢失当前run；并非三个独立完整工作台。令牌与选择仅在当前页面内存，刷新后重新连接。
7. 分别在**新数据集**上传`below_threshold.jsonl`和`normal_repeated_service.jsonl`，应无R01命中。不要把反例混到同一时间窗再据此断言误报。

D1小夹具不含20个不同目标端口，正常情况下不会命中R01。

## 4. 作业语义

- PostgreSQL短事务`SKIP LOCKED`领取，另用version+worker_id+state+lease_until约束所有写入；SQLite兼容测试使用同样CAS版本更新，不宣称它提供PostgreSQL行锁语义。
- 心跳每10秒续租；过期running作业可由新worker接管，attempt递增。旧lease在检查点/发布前被拒绝，不能覆盖新owner。
- 最多3次总尝试。可重试IO/数据库操作错误按2秒、4秒加0～1秒抖动等待；第3次失败或第3次租约到期后终态failed，不领取第4次。8秒理论退避不再执行，因为总尝试已用尽。
- 每500行保存cursor_line、cursor_byte和批次计数，与事件/隔离记录同事务。已提交的部分事件留在events/batch_events，但整批成功/partial前不加入session_events，因此对用户与检测不可见。
- 原始对象先封存并核验哈希，重启可从归档继续，不依赖仍存在的staging副本；不会覆盖原始对象。归档复制在事务外，发布对象关联与检查点均检查lease。
- final事务发布会话成员、执行R01、写候选并完成import作业。重复导入不增加已有事件，不复制相同finding版本；新观测可能形成同base_key下的新证据版本，保留历史候选。
- POST jobs/{id}/cancel、investigations/{id}/cancel：创建者analyst或admin可取消，viewer不可；取消幂等，已完成返回409。取消递增version并阻止迟到发布，已提交但未发布的分段不对外可见。
- 任务状态接口返回attempt/version/lease_until/cursor_line/error_code，可用于核对恢复；终态失败无“自动无限重试”，需人工判断后新建导入/调查。

## 5. 检测、快照和报告边界

R01配置在rules/R01.json：60秒窗口，10秒步长；同观测域、源IP、协议、目标IP访问≥20个不同端口，或访问≥10个内部目标的同一端口。内部网段显式来自配置。仅Zeek作为主计数来源；不同源IP/目标/协议不凑阈值；重复端口不累加为新端口。

这是候选检测。源IP不等于人，网络连接不等于成功入侵，批准的运维扫描也可能触发。源端口是易变化客户端端口，因此R01源聚合键使用源IP，图仍保留每条源/目标端口。

调查创建时冻结候选前后各5分钟内的已发布事件ID，最长30分钟、最多250事件；超限422，要求缩小数据集/范围，不静默截断。旧报告的snapshot、图和生成内容不因新数据自动改变；重新调查另建run。复现旧finding时只用其原证据子集，新快照中的其他观测仅作上下文，避免新数据让旧候选无法调查。

报告是程序模板：固定配置重跑R01、核验证据完整性与范围后写入。`observed`只陈述“规则触发”；真实身份、入侵成功和意图为unknown。模式明确deterministic_fallback，不冒充Agent。图只有communicated_with观测关系；按IP聚合仅为显示层，底层仍有带端口的精确边和逐条引用。

原始内容变化时，报告GET返回partial校验视图并提示证据不可验证，数据库中的原报告不覆盖；证据GET返回完整性错误。脱敏片段是白名单字段投影，不是可下载的完整原文；对象ID、哈希与原始行号可以复核。快照外或跨工作区引用拒绝。

## 6. 孤立对象与部署限制

`python -m apps.worker.cleanup`只输出dry-run候选：超过24小时、未被DB引用、无活跃工作区任务保护的随机命名临时对象。不自动删除证据；被报告/对象清单引用的原始文件保留。取消/失败任务的归档仍可能占用空间，后续保留策略需单独落实。

本机验证使用本地Python/Node与便携PostgreSQL，Docker四服务集成仍未执行。SQLite用于快速隔离测试，正式目标为PostgreSQL16。没有生产HA、RLS多租户隔离、主机auth解析、R02～R06、因果路径重建、人工复核/导出或真实模型调用。

## 7. 复验

```powershell
./scripts/check-d3.ps1
# 本机的隔离PG测试集群启动后：
.venv/Scripts/python -m scripts.pg_sandbox start
./scripts/check-d3.ps1 -Postgres
.venv/Scripts/python -m scripts.pg_sandbox stop
```

浏览器依赖已加入前端锁文件；首次需要将Playwright Chromium安装到`.tools/pw-browsers`（设置PLAYWRIGHT_BROWSERS_PATH）。然后：

```powershell
.venv/Scripts/python -m scripts.browser_d3
# 或： ./scripts/check-d3.ps1 -Browser
```

浏览器复验创建临时库/令牌与随机回环端口，自动启动并关闭自己的API/worker/Vite进程树，使用24条合成连接走完整点击流程。诊断与截图存artifacts/d3-browser，不提交临时令牌或原始真实日志。
