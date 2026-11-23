# D10构建与冻结验收记录

日期2026-11-15，工作目录D:/挑杯。D10开始时复核D9归档282个文件，全部SHA-256一致；无Git仓库，不初始化或提交。沿用锁定依赖，无实际外部模型调用，不采集/执行攻击。

## 实现与范围

| 文件 | 行为 |
|---|---|
| apps/api/web.py、main.py、packages/config.py、.env.example | 可选WEB_DIST，只提供生产入口与/assets；业务鉴权保留，stage/version升d10 |
| scripts/preflight.py | 只读检查迁移head、目录、前端与配置，明确worker/模型未验证 |
| scripts/release_manifest.py、infra/release-inputs.json | 分组冻结源码/契约/规则/开发数据/页面/演示稿，输入按明确路径和hash收录，检测漂移与越界，仅创建新候选 |
| scripts/verify_environment.py | 核对实际Python包与已安装Node包的锁定版本，记录未安装的可选包 |
| scripts/d10_gate.py、check_d10.py、check-d10.ps1 | 绑定真实检查日志/JUnit/冻结摘要，区分工程通过和完整P0就绪 |
| docs/d10-acceptance.json、d10-defects.json | 40项需求用例映射及可追踪优先级缺陷，缺口不自动升级为通过 |
| scripts/browser_d3.py、apps/web/tests/d8.spec.ts、d9.spec.ts | 支持独立候选API/worker/生产前端与独立证据目录，不覆盖旧演示工件 |
| docs/d10-runbook.md、d10-demo.md、d10-limitations.md | 原生候选安装、冻结操作顺序和实际能力限制 |

数据库继续0006_d9，未新增迁移。D10未变更原始证据、身份算法、六规则阈值、Agent推理或现有报告；此阶段固定现有工程候选并列出剩余P0验收缺口。

## 开发验证

- T1四项先因缺配置/入口/预检失败，后4 passed（1.53s）；覆盖API权限、目录外内容不公开、预检不创建数据库、不输出配置路径/URL。
- T2八项先缺模块失败，后8 passed（2.38s）；覆盖增删改、删清单项、路径/实际junction越界、秘密排除、拒绝覆盖旧冻结和候选。
- T3映射/JUnit/命令退出码九项通过；额外资料ready反例先复现误通过，再独立要求数据/双人标签状态，10 passed（1.31s）。
- 定向24项Python通过（4.00s），Ruff、TypeScript、ESLint、Vite生产构建通过。
- 独立probe候选281文件，候选自己的迁移/初始化/API/worker，加生产dist同源页面，三场景浏览器3 passed（35.5s）；仍为合成输入和回环HTTP协议桩。probe属于中间开发工件，不能代替修复后的最终冻结。
- 本机Docker客户端存在，但dockerDesktopLinuxEngine命名管道不可连接；没有更改系统配置或重建引擎。原生候选路径按此实际条件交付；Compose仍未验收。
- 首轮完整检查：336 Python passed（200.88s）；PG 1 failed/114 passed（175.61s），失败为只读预检测试假设整个共享测试库只有一个工作区。已改为比较前后集合，保持已有测试数据。
- 一次独立整体审查提出4项Important（新增可执行文件漏检、输入通配过宽、未核对实际包版本、JUnit缺执行绑定）；12项失败回归复现后一次修复，34项D10定向通过（12.04s）。实际环境核对Python与已安装Node包均匹配锁文件；可选未安装Node包单列。无第二轮审查或人工标签复核。

## 最终门禁

最终使用Windows、项目.venv的Python3.13.5、Node v22.17.0、PostgreSQL16.16。曾误用系统Python3.11触发目录联接接口缺失；系统解释器不在pyproject支持范围内，改用既有.venv后通过，未为此修改冻结版本。

实际执行命令：

```powershell
.venv/Scripts/python -m scripts.check_d10 --freeze release/d10-freeze-01.json --output artifacts/d10-check-01 --postgres --browser --candidate release/d10-candidate-01
.venv/Scripts/python -m scripts.d10_gate --freeze release/d10-freeze-01.json --evidence artifacts/d10-check-01 --require-release
```

第一条exit0；第二条严格发布门禁实际exit2。检查日志与执行绑定见[checks.json](../artifacts/d10-check-01/checks.json)，结果见[gate.json](../artifacts/d10-check-01/gate.json)及[严格门禁输出](../artifacts/d10-strict-gate-01.json)。已完成的证据可按运行说明只读复验；不要重新使用已有输出目录。

| 检查 | 实际结果 |
|---|---|
| 全量Python | 348 passed，206.53s；JUnit已绑定此次pytest检查记录 |
| PostgreSQL集成 | 115 passed，168.00s；D2→D9迁移保留既有工作区，应用/只读角色越权被拒 |
| D8浏览器回归 | 2 passed，16.2s |
| 独立候选S1/S2/S3浏览器 | 3 passed，40.2s；使用候选自身API/worker/迁移及生产前端，无Vite |
| 静态与构建 | 契约导出、Ruff、format、pip check、类型生成、TypeScript、ESLint、Vite均exit0 |
| 实际依赖 | 34个Python包、132个已安装Node包版本匹配锁文件；32个未安装可选Node包单列 |
| 资料冻结 | 清单完整性exit0；33 planned、3 prepared、0 reviewed，资料与标签ready仍false |
| 候选预检 | ready=true，仅迁移/目录/静态资源等只读检查；模型/worker连通性仍not_verified |
| 门禁结果 | engineering_passed=true、nonwaivable_safety_passed=true；无缺少检查/失败检查/缺失映射测试；p0_release_ready=false |

115项PG测试是集成测试在真实PG上的重跑，不与348项相加宣称独立用例数。浏览器使用合成输入、回环HTTP协议桩及显式降级/缓存，不是真实LLM或攻击采集验收。40项规约用例已映射：32项implemented、5项partial、3项blocked；未完成8项与9项P1均保留在门禁，不把工程通过称为完整P0通过。

## 冻结交付物

- [冻结清单](../release/d10-freeze-01.json)：284个源码、契约、规则/允许输入、页面及文档文件；规范化摘要`203cdb82fb42d1f3c3d7335754da2b2ac6466cc46458111eecf135859c265171`。
- [本地候选ZIP](../release/d10-candidate-01.zip)：284冻结文件加4个元数据文件，556864字节；逐文件比对及ZIP完整性通过。SHA-256：`154a4cfc8100cf6f339911e43d9b97d3c5fad10ed8c9a52d5b1b0d306b0e550b`。
- [安装说明](d10-runbook.md)、[演示稿](d10-demo.md)、[限制](d10-limitations.md)、[缺陷表](d10-defects.json)。候选不含运行时/依赖包，离线安装依赖需另行准备；本机独立目录验证不等于干净机器验收。
- [浏览器证据](../artifacts/d10-check-01/browser)包含S1/S2/S3截图、JSON与HTML导出；S3截图已检查，partial、cached和缺socket未知项显示明确，复核测试文本按纯文本呈现。
- [构建工件摘要](../artifacts/d10-build-manifest.json)绑定最终日志、工件及交付记录。这些本地哈希不构成签名或第三方证明。

本轮启动的隔离PG已正常停止，日志见[停止记录](../artifacts/d10-pg-stop.log)；测试数据库和历史工件保留。API/worker/协议桩由浏览器脚本关闭。未执行远程提交、发布或联系团队成员；工作目录无Git，不能声称已合入集成分支。

## 未验收项

33项仍planned、3个prepared旧开发包同一谱系、0双人标签复核。真实LLM/供应商成本、精选知识条目、整库+raw备份恢复、正式指标复算、性能负载、全新机器/非作者/Compose部署及8分钟计时仍未验收。P0完整发布就绪不能标true；工程测试与本机独立目录启动不代替这些证据。
