# 网络遥测与 AI Agent 攻击溯源

面向授权实验环境的防御性调查原型。系统把网络连接、主机认证与审计、安全告警和离线抓包整理为可回查的证据，生成检测候选、资产与传播路径分析，以及带证据引用和未知项的调查报告。

**源码版本** `0.1.0.dev43` · **数据库迁移** `0006_d9` · **默认模型** `disabled`

## dev43 六阶段执行状态

运行接口和新报告增加六阶段执行状态。前置核验、裁剪及终止位置依据持久记录，知识查询累计保留缺失与失败。网页、JSON 和 HTML 读取同版结果，历史报告缺省保持未记录。

本轮固定源码相关回归 **191 passed**，前端类型、lint 和构建通过，隔离浏览器报告流程 **1 passed**。阶段状态仅描述执行，具体检测与溯源仍按证据核验。见[dev43 验证记录](docs/pipeline-dev43-verification.md)及[实施计划](docs/superpowers/plans/2026-11-26-pipeline-progress.md)。

## dev42 六阶段改造

按“采集 → 归一化 → 规则检测与标注 → 图构建与溯源 → 情报归因 → 前端展示”推进。Agent 在初始图和缺口形成后选择有界只读查询，依据真实返回更新判断，并结合本地 ATT&CK 知识整理报告。

本次增加抓包事件查询、带缺口说明的建议、末页续读修复、已知证据范围内的路径及缓存，以及网页/HTML 的新增非种子证据展示。完整规约见[六阶段设计](docs/superpowers/specs/2026-11-25-tracex-agent-pipeline-design.md)，阶段实现和限制见[dev42 工程记录](docs/pipeline-dev42-verification.md)。

M1 的独立多源材料、新 socket 来源、逐类抓包判断策略及六阶段完整进度展示仍待完成。IOC 富化为可选后续阶段。当前使用既有本地 ATT&CK 目录。

## 系统流程

1. API 接收导入请求，worker 解析并封存日志，保存原始位置和摘要。
2. 规则在固定会话内产生候选。证据图按可核实的观测构建关系，缺失关联处保留断点。
3. 调查以不可变快照为范围。Agent 只能使用受限的只读工具，查询和模型调用受预算约束。
4. 网页查看时间线、证据与检测/溯源结论，可导出 JSON 和 HTML。回放复用已封存事件，固定源会话水位。

## 项目导航

| 目录 | 内容 |
| --- | --- |
| [`apps/api`](apps/api)、[`apps/worker`](apps/worker)、[`apps/web`](apps/web) | FastAPI、后台作业和 React/TypeScript 界面 |
| [`packages`](packages) | 数据契约、摄取、检测、证据图、受控 Agent、知识和存储 |
| [`rules`](rules)、[`knowledge`](knowledge) | 检测配置及冻结摘要、精选 ATT&CK 知识和来源许可 |
| [`migrations`](migrations)、[`infra`](infra) | Alembic 迁移、PostgreSQL 角色、容器构建与部署模板 |
| [`tests`](tests)、[`eval`](eval)、[`scripts`](scripts) | 契约和集成回归、离线评估、开发与运维入口 |
| [`data/fixtures`](data/fixtures) | 有来源和摘要的合成开发夹具 |

设计入口见[项目规划](PROJECT_PLAN.md)、[项目规约](PROJECT_SPEC.md)、[架构](docs/01-architecture.md)、[数据契约](docs/02-data-contracts.md)、[检测与图谱](docs/03-detection-graph.md)、[Agent](docs/04-agent.md)、[API 与界面](docs/05-api-ui.md)和[评估说明](docs/07-evaluation.md)。

## 本地启动（Windows PowerShell）

在新检出的仓库根目录使用 Python 3.13 和 Node.js 22.17+。SQLite 演示和前端均监听回环地址，默认关闭模型。

```powershell
python -m venv .venv
.\.venv\Scripts\python.exe -m pip install -r requirements-dev.lock
Copy-Item .env.example .env
Add-Content .env -Value 'DATABASE_URL=sqlite:///data/demo.db'
.\.venv\Scripts\python.exe -m apps.api.manage migrate
.\.venv\Scripts\python.exe -m apps.api.manage init-demo
```

初始化只在首次显示令牌。保存到本地私有位置，在网页中使用 `admin` 令牌创建演示数据集。

在两个 PowerShell 窗口分别从仓库根目录启动 API 和 worker。

```powershell
.\.venv\Scripts\python.exe -m apps.api.main
```

```powershell
.\.venv\Scripts\python.exe -m apps.worker
```

在第三个窗口启动开发界面。

```powershell
Set-Location apps/web
npm ci
npm run dev
```

打开 `http://127.0.0.1:5173/`，连接、创建数据集，再按 Zeek 来源导入 [`data/fixtures/d1/zeek.jsonl`](data/fixtures/d1/zeek.jsonl)。API 文档位于 `http://127.0.0.1:8000/docs`。Docker/PostgreSQL 配置见[四服务说明](docs/p1-compose.md)。

## GitHub 内容复核

本轮复核涉及全部已跟踪路径、文档相对链接及改造源码。远程历史文档中 75 处指向受控本地归档的链接已改为位置说明。具体检查范围及保留问题见GitHub 同步复核（本地归档 `docs/github-sync-dev42-review.md`）。

## 测试与验收

从仓库根目录运行以下源码自带回归。

```powershell
.\.venv\Scripts\python.exe -m pytest -q tests/contract/test_contracts.py tests/contract/test_ciciot_behavior.py tests/integration/test_d2.py tests/integration/test_p1_knowledge.py
npm --prefix apps/web run build
```

此前 dev41 源码快照的全量 pytest 实测有 998 项通过、58 项初始化报错。报错用例属于 D13–D15 历史打包测试或两组 P1 私有试跑测试，需要对应的归档、wheel 和本地试跑脚本。

待上传快照直接回归 49 项通过。dev42 的本地固定源码相关回归 175 项通过，前端类型、lint 和生产构建通过，隔离浏览器报告流程 1 项通过。逐项行为检测和溯源报告沿用 dev41 的验收范围。历史固定行为集为 **2/16**，独立 DoS/DDoS 固定集 v2 为 **11/12**，两组使用各自的样本与门禁。这些结果来自项目既往隔离评估，详见[dev41 验收摘要](docs/ciciot-behavior-verification.md)。行为候选的成立无法确认完整因果链或真实操作者身份。

本仓库提供源码和合成夹具。固定抓包、正式标签、原始日志、运行数据库、密钥、私有备份、历史候选 ZIP 与运行工件保存在原有受控环境。依赖这些本地输入的历史评估和打包命令需要另行准备对应的授权材料。GitHub 首次源码提交是一次工程交接，正式竞赛验收仍以项目门禁与人工记录为准。
