# D5运行说明

本日完成最小事件聚合、数据集/事件/队列/时间线/图边分页、入口候选及有证据的事件级路径。继续使用D4结构化Linux协议，模型关闭，输入仅授权本地文件。

## 启动和升级

沿用[d4-runbook](d4-runbook.md)的环境、数据库、令牌与三个终端启动方式。先以migration owner执行：

```powershell
.venv/Scripts/python -m apps.api.manage migrate
.venv/Scripts/python -m scripts.build_d5_fixture
.venv/Scripts/python -m apps.api.main
# 另开终端
.venv/Scripts/python -m apps.worker
# 另开终端，在apps/web运行npm run dev
```

新迁移0004_d5增加session_events.publication、datasets.created_seq，以及incident_details/incident_catalogs/incident_heads。旧ID、事件payload、快照和报告不改写；已有单finding事件组回填目录。现有workspace缺私钥时创建，已有HMAC密钥不更换。升级后旧分页游标失效，请刷新第一页；原始证据引用保持。

已有app角色由owner授予三个新表SELECT/INSERT，head另需UPDATE；禁止UPDATE/DELETE incidents、incident_details、incident_catalogs。reader不应读私钥。首次建角色用infra/roles.sql；不要对已有角色重复CREATE ROLE。首次干净安装与已有业务库升级需使用owner，不用app执行DDL。

## 三源、两规则、路径演示

1. 页面连接admin，创建新的synthetic数据集，先上传`data/fixtures/d5/context.json`配置上下文。
2. 按下表依次导入并等待终态：

| 文件 | source_type | sensor_id | 新增规范事件 / 物理行 |
|---|---|---|---|
| network.jsonl | zeek | net-a | 24 / 24 |
| auth.jsonl | linux_auth | auth-a | 6 / 6 |
| audit.jsonl | linux_audit | audit-a | 2 / 4 |

3. 共32条规范事件、34物理行。安全事件刷新后出现一个“R01 / R02 聚合调查候选”，成员2。展开聚合理由：同域、共同强目标资产、finding窗口相交；这不证明同一攻击者。
4. 生成模板调查：两条成员规则分别复现；快照时间线第一页20条、下一页12条，后续导入不改变该快照。
5. “候选入口与证据路径”显示该目标在当前观测范围内的最早相关观测，left_censored=true。样例地址192.0.2.10不是现实攻击者或已证明的外部公网入口。
6. 主路径：01:00:21网络连接→01:00:22成功认证（corresponds_to，inferred）→01:00:30会话进程（associated_process，observed）→01:00:40子进程创建（spawned，observed）。另有跳过父进程观测的较短候选，按分数和ID稳定排序。
7. 每条边可展开身份/时间/关系分数分解，并点击起点/终点原始证据。图节点焦点可查询邻接关系，边列表按ID翻页；没有完整加载时显示已载入/总边数。图的实体连线与事件路径含义分开。
8. 同一文件重复导入不增加事件或成员；新数据生成新的目录/事件组版本，旧incident ID仍能调查，已有报告保持。

## 反例与边界

- 在独立新数据集只导入network.jsonl：R01可触发，但没有成功认证/进程链，显示证据不足及断点，不强造top1。
- 独立新数据集配置相同context，导入network/auth及audit_without_session.jsonl：认证到进程不连；仍可有网络→认证局部路径。父子显式生命周期关系可在独立上下文保留，不代表已归到登录。
- 后端测试覆盖账号、主机、域、boot/PID复用、缺session/出生标记、反序/重叠时钟、无关正常组件、缺证引用、签名/作用域与晚到数据。
- 不从最近进程猜网络发起者；缺进程socket适配时这一跳明确断开。

聚合最小条件为共同强实体且finding时间窗相交，同workspace/dataset/session/observation_domain；组件跨度严格小于30分钟，给半开快照末端留空间。不相交finding凭显式边合并、人工拆并仍留T-11后续。调查上下文最多250事件、30分钟，超限拒绝，不静默假装全量。

路径算法只连接成功认证/显式会话、强父子生命周期、同域五元组/唯一资产与有界时间。严格先后按不确定区间；重叠、反序、身份冲突不进入路径。beam20、最多6跳、top3，另存最多20条未选候选及差异，裁剪显式标记。纯precedes/suggests不作为连接。强Host/boot/session/parent身份按既有全局资产契约关联，不额外把观测域当成主机身份；网络推断必须同域。

启发式分数沿用规约0.40身份+0.25时间+0.20关系+0.15独立旁证−惩罚；没有可信独立通道声明时旁证项0。路径0.6×最弱边+0.4×平均边，不是概率。coverage=100%仅表示所选链内部每跳有证据，不表示攻击全貌；此前活动/漏采步骤数量未知。

## API和复验

所有列表limit默认50、最大100（页面常用20）。datasets按created_at/id，events与冻结timeline按event_time/event_id，incidents按start_time/id，graph边按edge_id。数据集created_seq、事件publication与不可变目录固定翻页范围；cursor由服务端私钥签名并绑定actor、工作区、路由和scope。切换令牌、数据集、快照或focus不能复用旧游标。

新增`GET /investigations/{id}/timeline`、`/paths`，graph支持limit/cursor/focus_entity；队列和数据集列表返回真实next_cursor。报告新增可选path_analysis，paths/candidate_origins仍为ID数组。旧报告不重算路径，GET paths返回LEGACY_PATH_ANALYSIS_UNAVAILABLE 409，需新建调查。当前原始哈希不可校验时paths返回409，报告只降为partial视图，历史内容不改。

```powershell
./scripts/check-d5.ps1
# 本机PG实例启动后，可执行全部可选验收
./scripts/check-d5.ps1 -Postgres -Browser
```

浏览器各自使用随机端口和临时库，仅清理自身进程。输出artifacts/d3-browser、d4-browser、d5-browser下的closed-loop.png、playwright.log、services.log及results/.last-run.json。便携测试PG使用完可执行`python -m scripts.pg_sandbox stop`（使用.venv）。合成fixture为development，不作为准确率、性能或真实攻击成绩。

未完成：在线collector、任意原生Linux文本、HTTP跨轮转audit manifest、进程socket适配、Agent、完整攻击意图和真实操作者归因、R03–R06、Docker集成及生产规模性能验收。
