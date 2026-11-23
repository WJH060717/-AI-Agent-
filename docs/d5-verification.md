# D5验收记录｜2026-11-14

范围：最小事件聚合、固定可见范围分页、稳定排序、有证据的入口/路径、正反例与D1–D4兼容。复验时间约20:05（Asia/Shanghai），规约调整见CHG-005。

## 最终结果

| 检查 | 实际结果 |
|---|---|
| `./scripts/check-d5.ps1` | 104项pytest全部通过；Ruff检查、120文件格式通过；pip check通过；Schema/OpenAPI导出、TypeScript生成/类型、ESLint、Vite build全部通过 |
| PostgreSQL16.16 `python -m scripts.test_postgres`（.venv） | 新建随机独立数据库；D2→D5迁移保留工作区；受限app账号34项集成测试全部通过 |
| 角色边界 | app不能DDL或改删incident_details/catalogs；reader不能写events、读令牌/私钥；head仍可更新目录指针 |
| 0003→0004升级（独立SQLite契约测试） | 真实24条合成规范事件、旧finding/incident/快照/Report保留；身份HMAC密钥不换；旧目录可分页，旧报告paths接口409而不重算 |
| 聚合正反例 | 强身份+相交窗口合并；同IP但异资产/账号、异域、异scope、不相交不合并；乱序与重复finding稳定；传递合并不越30分钟 |
| 分页 | 同时间ID稳定；新数据集/晚到事件不进入旧页；新目录不重排旧队列；篡改/换令牌/作用域/路由失败；graph focus与timeline分页范围一致 |
| 私有签名 | 用已知Bearer摘要重新签名旧游标的失败回归通过；新游标使用服务端私钥和actor绑定 |
| 路径正例 | 网络→成功认证→会话进程→子进程，3跳精确证据，2 observed + 1 inferred；同输入反序结果一致 |
| 路径反例 | 缺session、弱进程/boot、时间重叠/反序、失败认证、不相关组件、纯扫描不补跳；坏scope/种子拒绝 |
| 搜索边界 | 25分支beam/top3有裁剪；真实长生命周期链停在6跳；不重复事件；孤立规则种子不挤占可扩展beam；目标入口仅保留最早相关根观测 |
| 证据/冻结 | 全成员finding各自复现；后续导入不改旧报告；篡改快照所引原始对象后paths409、report partial视图，数据库报告原文保持 |
| R01浏览器 | 上传→规则→调查/图/模板→证据，且纯扫描显示证据不足；passed |
| R02浏览器 | context→三源→R02→身份图/模板→脱敏行；passed |
| D5浏览器 | context→24+6+2规范事件→R01/R02成员2聚合→3跳路径→边证据→时间线20+12；最终passed |

三个浏览器使用真实Chromium，随机本地端口、临时SQLite/令牌，非mock服务。输出分别在artifacts/d3-browser、d4-browser、d5-browser，包含closed-loop.png、services.log、playwright.log及results/.last-run.json。图/路径截图已实际查看，1440×1000；其他分辨率、大规模图和完整交互视觉未全面验证。没有Docker验收或吞吐/准确率成绩。

输入：data/fixtures/d5/manifest.json SHA-256 `26f9aed3d9524552de2d78ba23b76c49358c7ef05c1d734384cf3beb7596a344`；含各原始文件/context哈希，provenance=synthetic、split=development。没有生成网络流量或实际攻击；运行时不读取真值。方法版本：incident_group@1.0.0、event_paths@1.0.0、evidence_graph@1.1.0、template@1.2.0，R01/R02配置仍原版本。

## 实施与审查证据

聚合/分页/路径模块先运行缺实现失败，再实现；晚到数据污染后续页、已知令牌摘要重签、孤立种子消耗beam均先复现后修复。浏览器初次在缺成员/路径页面断言处失败，再接通页面；后一次定位到关闭details里的left_censored，改为验证实际可见说明后通过。

独立只读审查发现1项Important、无Critical：实体图用next()只保留更早的同会话认证/父进程创建，遮蔽当前精确事件对。新回归先失败，再保留全部合法配对并提前执行1000边上限，相关16项通过，随后最终104项全量/34项PG/D5浏览器通过。没有未处理的重要审查项或minor项。

收尾核对另复现“每条孤立扫描都成为入口”，修正为按目标/观测域只取最早根观测；补齐外部/内部候选分类和6跳真实长链。证据损坏测试按快照明确引用的对象选择，避免误把后来无关隔离对象当作报告证据。

## 范围决策与限制

- D5聚合只实现同域强实体+相交窗口；非相交finding依据显式关系聚合、人工拆并仍留T-11。目录/成员版本不可变，当前列表head可前进，旧调查不改。
- 入口缺完整覆盖声明时left_censored=true；外部网络地址与最早观测点均不证明现实身份。更早未观测活动未知，入口未必是某条局部路径的第一步。
- 未实现进程socket适配，缺证保留断点。显式强主机/boot/session/parent关系沿用既有身份契约，可跨传感器域；网络候选五元组必须同域。真实collector身份可信度仍需另外验证。
- coverage只覆盖所选链内部；启发式支持度不当概率，beam/top3会裁剪；当前快照250事件、30分钟，超规模拒绝，不宣称完整攻击因果。
- 图分页保留完整有界节点集，只分页边；列表游标升级需刷新，证据ID/历史报告不受影响。Agent、原生Linux任意文本、HTTP轮转manifest、R03–R06、在线采集和生产部署仍未验收。

无Git仓库，无提交ID/远程合并；独立自动审查不代替团队人工签字。便携测试实例完成复验后停止，未操作业务库或其他服务。
