# D10 Implementation Plan

> **For agentic workers:** Use superpowers:executing-plans inline, with one fresh whole-change review at the end. No Git repository is present; preserve the working directory and evidence ledger.

**Goal:** 冻结D10候选的API、数据/规则、Prompt/模型/图与页面版本，交付可启动的本地部署候选、可执行P0门禁及缺陷优先级表。
**Architecture:** 延续FastAPI/worker/React与0006_d9，不新增数据库结构。构建产物通过API同源托管；离线脚本创建只追加冻结清单、验证漂移并按白名单打包。工程验证与完整P0发布就绪分开判定。
**Tech Stack:** 现有Python/Pydantic/SQLAlchemy、Vite/TypeScript、pytest/Playwright；不新增依赖。
**Spec:** PROJECT_SPEC.md；docs/02-data-contracts.md、04-agent.md、05-api-ui.md、06-execution-plan.md、07-evaluation.md、08-deployment-demo.md。

## Design and decisions

沿用用户已指定的规约和D9实现，D10只收束冻结及当前P0依赖。原生候选与Compose均可作为部署路径；本机Docker客户端存在但Linux引擎连接失败，因此先验证独立目录中的原生候选。Compose、全新机器与非作者启动仍需后续验收，不把它们改成已通过。候选默认模型disabled，不引入报价、真实采集、知识条目或实验指标。

冻结清单保存明确相对路径、字节数、SHA-256、分组和版本声明；比较新增/缺失/修改文件。路径与文件集限制防止归档根目录外读取、打包.env/原始库/密钥或不受控文件。创建只允许新文件/新目录，漂移须新候选并说明依据，不覆盖旧冻结。测试证据绑定冻结摘要和实际子进程退出码；任何缺失/失败不标通过。

40项用例映射到真实测试入口和implemented/partial/blocked范围；TC-008/009/022/023/024/030/031/032不可豁免。真实LLM、33次独立资料/双人标签、备份恢复、正式评估、性能、干净部署与计时彩排的缺口明确进入缺陷表。工程通过不将这些门禁自动升级为通过。

## Global constraints

- D9归档282文件初检无漂移；不改旧冻结/迁移/报告/原始对象，不重置库或令牌。
- 运行时不导入eval；冻结和资料校验只运行于离线脚本。
- 模型默认关闭；所有浏览器模型行为为明确的本地HTTP协议桩。
- 测试只用新的临时库/目录；不得启动公网服务、扫描或上传日志。
- 所有新增对外配置进入Settings与.env.example；不回显凭据或数据库URL。

## Review focus

1. 冻结文件删项、目录新增文件、版本漂移、路径穿越/链接不得漏检。
2. 打包不得混入.env、数据库、真实raw、临时token或eval真值；不得覆盖已有目标。
3. 静态资源不能暴露源代码/配置，API权限与错误路由保持有效。
4. 门禁不得把未执行、失败、缺证、协议桩或手填状态伪装为完整P0通过。
5. 候选必须从自身目录启动并读取自身规则/模板/前端，不能依赖原工作区路径。

## Tasks

- [x] T1 部署入口：先新增静态托管/只读预检正反测试并观察失败；实现WEB_DIST、生产前端同源服务及scripts.preflight。预检验证迁移head、目录、模型配置和本地绑定，只返回安全状态；版本升dev10，更新契约说明。验证相关API/配置用例。
- [x] T2 冻结与候选：tests/contract/test_d10_release.py先覆盖漂移、新增/删除、秘密排除、越界和已有目标拒绝。scripts/release_manifest.py提供build_manifest(root)、verify_manifest(root,manifest)、create_freeze(root,path)、build_candidate(root,freeze,target)。只打包审核过的文件集，绑定实际web/dist与源文件，复制后再验hash。
- [x] T3 P0门禁：docs/d10-acceptance.json与docs/d10-defects.json逐项映射40用例和缺口。scripts/d10_gate.py严格验证映射/测试存在/安全门禁、执行结果和冻结摘要，产生工程状态与P0就绪两个结果。scripts/check_d10.py及check-d10.ps1执行实际检查；失败exit1，完整发布未就绪exit2，工程子集明确标注。
- [x] T4 真实候选验证：构建生产前端；从独立候选目录启动API/worker，SQLite空库迁移/初始化、只读预检、三演示场景浏览器闭环；只以候选文件提供页面/API。新增script参数保持历日行为兼容；提供冻结演示稿、安装说明与限制。
- [x] T5 工程冻结/验收：全量Python、静态/类型/构建、PG迁移与权限、浏览器通过；一次独立整体审查的重要问题已修复。新的不可覆盖D10冻结与部署候选已创建，实际工程门禁通过；完整P0仍因9项P1和8项不完整用例而未就绪，不发布或提交远程。

## Interfaces and pre-flight

- T1→T4：Settings.web_dist(Path|None)、preflight(settings)->dict；无写库或工作区初始化。
- T2→T3/T4：Manifest包含files映射和version metadata；verify_manifest在差异时抛ReleaseError。候选包含原相对源码/静态路径、freeze.json和README-install.md，运行数据放候选目录外。
- T3→T5：结构化CheckResult记录真实命令、时间、退出码、日志摘要、freeze hash。完整P0仍受partial/blocked用例及open高优先级缺陷约束。

## Evidence ledger

- Ruling: 用户要求继续按既有规约完成D10，沿用本地内联执行，不重复请求设计或执行授权；实现选项由助手承担并明确记录。
- Ruling: 无Git仓库，不初始化、不提交、不创建工作树；技能的Git台账操作改为本文件和本地工件。
- D9 baseline: 282文件SHA-256一致；docker客户端存在，连接dockerDesktopLinuxEngine失败，未尝试改系统配置或重建引擎。
- T1 RED→GREEN：4项缺字段/入口失败后通过；只读预检不会创建缺失SQLite库，不输出数据库URL。
- T2 RED→GREEN：8项先缺模块失败后通过；含实际目录junction越界、增删改/清单删项、秘密排除、已有目标拒绝。
- T3 RED→GREEN：映射/证据/JUnit/失败退出码10项通过；额外反例先证实仅手填台账可误过ready，现已独立要求真实资料/标签ready。不是签名或第三方证明。
- T4 RED缺candidate参数→GREEN：独立281文件probe候选，生产前端+候选自身API/worker/迁移/初始化，三线3 passed（35.5s）。probe是中间测试产物，后续代码修正后不再作为最终冻结。
- 定向24项Python、Ruff、TypeScript/ESLint/Vite已通过；全量与最终审查仍在执行。
- 首轮全量336 Python passed（200.88s），PG为1 failed/114 passed（175.61s）：只读预检测试误将共享隔离PG库假设为单工作区，实际既有3个工作区；改为比较预检前后工作区集合，不清理其他测试数据。
- 一次fresh整体审查：4 Important、无Critical/Minor。接受四项：可执行扩展/根模块漏检、数据通配收录、实际依赖未核锁、JUnit未绑定执行记录。
- 同一修复轮RED→GREEN：12项审查反例均实际失败后修复；34项D10定向通过（12.04s）。未知可执行/配置文件拒绝；64个既有合成夹具/规则对象使用明确路径+hash白名单；Python/已安装Node包逐项核锁；JUnit摘要在pytest完成时入记录。
- Ruling: 审查未判断的真实LLM、33次/双人复核、恢复、性能、干净环境/Compose/计时继续作为明确发布阻塞，不新增虚假证据；没有Git历史不推断提交范围；全量结果由实际执行日志决定；本地hash不当作签名或第三方证明。
- Ruling: 输入白名单基于D9来源/构建器和本轮已验证probe的既有对象，仅表示允许打包，不代替人工真值复核。未知数据拒绝自动加入，后续变更须新版本依据。
- Ruling: pycache等合法运行缓存不打包；核验针对源码/输入与包版本，不宣称可抵抗主机管理员篡改或已失陷Python运行环境。
- 最终复验曾误用系统Python3.11而触发Path.is_junction缺失；项目pyproject要求>=3.12,<3.14，改用既有.venv的Python3.13.5后源码及候选284文件均通过，未修改冻结代码或依赖。
- 最终固定版本全量：348 Python passed（206.53s），115 PostgreSQL集成passed（168.00s），D8浏览器2 passed（16.2s），候选S1/S2/S3 3 passed（40.2s）。契约、Ruff、format、pip check、实际包版本、TypeScript、ESLint、Vite、资料冻结检查全部exit0。
- 最终工件：release/d10-freeze-01.json、release/d10-candidate-01、release/d10-candidate-01.zip；284冻结文件+4个候选元数据文件，ZIP逐文件核对成功。证据artifacts/d10-check-01，工程检查exit0；严格发布门禁实际exit2，engineering_passed=true、p0_release_ready=false，非豁免安全门禁通过。
- 本轮启动的隔离PostgreSQL已正常停止，测试库/归档未删除。浏览器脚本退出时关闭自身API/worker/协议桩；交付保留本地，无Git集成、远程提交、发布或团队联系。
