# D13 Implementation Plan / 实施台账

> 使用 superpowers:executing-plans 原地执行；现有规约与继续构建指令提供范围授权。无 Git，不创建仓库、不提交；以文件摘要和不可变候选代替提交标识。

**Goal:** 让非部署作者得到可核验的本地安装入口、场景资料和诚实的八分钟展示材料。
**Architecture:** D13 是部署/展示套件，内置不改字节的 D12 candidate-04（应用0.1.0.dev12，数据库0006_d9）。新增纯标准库安装器，新目录、新虚拟环境、新SQLite演示库；生产PG角色沿用原手册。公开材料与私有运行数据分开。
**Tech Stack:** Python3.12/3.13、venv/pip锁文件、现有FastAPI/React、Playwright实际录屏、静态HTML材料。
**Spec:** PROJECT_SPEC.md；docs/06-execution-plan.md D13；docs/08-deployment-demo.md。

## 设计裁定与接口

- 选择固定底座的原生部署套件；Docker引擎不可连接，不能用未运行的Compose替代验收。新机器/非作者验收保留待办。
- 不改应用字段、API、规则、Agent或冻结迁移，不重新宣称D12和D11实验是D13新测量。
- Task1产出 `deploy.py verify/install/run/status`，Task2文档使用同一命令，Task3实际从打包后新目录安装并录制。包内app始终是D12冻结副本，安装器不得导入当前工作目录运行时代码。
- Pre-flight: 安装器和套件生成器共同消费D12冻结/摘要；拒绝漂移、路径穿越、链接、未知文件。资料/视频不能包含角色令牌、原始账号或真实日志。

## Review Focus

1. 目标已存在、链接/路径重叠时必须在写入前拒绝，失败目录保留。
2. 环境变量或当前.env不能把新安装导向已有数据库/外部模型。
3. 包/候选文件被改或注入额外代码时必须拒绝，不能只核对一个版本字符串。
4. 子进程失败不能继续宣称安装成功；令牌只能一次显示且不进入公开证据。
5. 预录/自动化/同机新环境不得冒充现场、真人、干净机器或真实模型验收。

## Task 1: 安装套件

- [x] 先写部署边界正反测试并看到失败。
- [x] 实现 scripts/deploy_d13.py（打包为deploy.py）、scripts/build_d13.py，最小锁定安装与同配置启动。
- [x] 测试新目录、环境隔离、漂移/未知文件/穿越、子进程失败、重复安装拒绝；Expected: 全通过。

## Task 2: 展示与交付资料

- [x] docs/d13-runbook.md、scenarios、defense、demo、limitations、acceptance模板与静态展示页。只引用可追溯事实，来源/许可证未知不伪造。
- [x] 准备实际UI录屏脚本，八分钟字幕/时间表，模型disabled、合成数据、自动预录常驻标识。
- [x] 浏览器核查材料布局、链接、实际UI与录屏长度。

## Task 3: 验证与冻结

- [x] 新venv/新库实装，预检、实际worker导入与调查、重启持久化；Expected: 可启动且显式fallback。
- [x] 针对新增工具运行测试/静态检查；沿用底座已归档422Python/123PG/6浏览器结果，不算本轮新增成绩。
- [x] 一名新审查代理整体审查，一轮必要修复，最终包hash/证据清单/严格未完成状态。
- [ ] 非作者真实验收由其亲自填写，不能自动签署；D13工程交付与完整P0发布状态分离。

## 进度

- 基线：D12 candidate-04 325个源文件逐项hash通过；拟修改历史文档已保存到artifacts/d12-source-preserved-for-d13。
- Task 1: complete — 先缺模块RED，14项GREEN；独立审查3项边界问题新增8项真实反例RED（包括同步改清单额外代码、已存在ZIP与链接父目录先写入、占用端口），一次修复后最终22项全部GREEN。Ruff与格式检查通过。
- Task 2: complete — 六份手册/场景/答辩/演示/限制/空白验收表、静态HTML、198依赖条目与166份可取得许可文本。38条未取得原文（含未装平台可选项），不标法律复核完成。
- Task 3: engineering complete — kit-02固定505文件/506ZIP条目，943016字节，实解压核验成功。第二新venv安装成功；配置注入仍disabled且未触碰哨兵。full-02实际41响应无HTTP错误，46事件/2调查；包内CLI重启原令牌有效、旧报告逐字段一致。原片保留，成片479.2秒/2588582字节，无加速，仅去编码关闭重复尾帧。验证与最终清单见d13-verification.md。
- Ruling: 本机Docker引擎不可连接，交付原生SQLite工程路径，不宣称PG角色/Compose/非作者完成。应用不变，沿用D12历史422/123/6证据，不重复计数为本轮测试。
- Ruling: 初次录屏用草案health路由404，按真实API修为/api/v1/health/live；首次视觉复验发现aside全局样式使字幕变窄，改div且对齐章节滚动。失败/试跑保留。
- Review: 独立代理d13_review只读审查，2项P1+1项P2已在同一修复轮补测试并处理；不进行第二轮审查。法律充分性、独立机器和真人验收不以代码审查替代。
- External acceptance: pending — D13-INTEGRATION需要真实非部署作者独立按手册启动；空白清单未签署。不能将工程交付complete理解为完整P0或人类验收complete。
