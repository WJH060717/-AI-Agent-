# 08｜部署、运行与竞赛交付手册

## 1. 环境假设与D1核验

开发机可用Windows；后端、数据库和传感器优先在Linux虚拟机或WSL2中运行。展示应用建议8逻辑核、16GB内存、40GB空闲SSD；无GPU仍可运行规则、图谱与远程模型适配。此配置是预算假设，尚未在用户设备验证。

D1填写：CPU/内存/磁盘、系统、虚拟化、Docker/Compose版本、Python/Node版本、监听端口、是否允许外网模型、代理情况、模型接口、预算上限、数据来源、赛场网络和展示时长。不预设需要购买服务器。

如果只有8GB内存：预生成传感器日志；应用图上限先降至200节点；关闭并发调查；用远程模型或明确fallback；10万事件性能目标需要重新基准并记录，不能悄悄沿用。

## 2. Compose部署契约

| 服务 | 职责 | 端口/卷 | 启动健康条件 |
|---|---|---|---|
| db | PostgreSQL | 不对公网暴露；db_data持久卷 | 连接可用 |
| api | API/鉴权 | 内网8000；原始对象只读挂载 | DB迁移版本一致、归档可读 |
| worker | 导入/检测/调查 | 无外部端口；raw_store可写、work_store可写 | DB连接、租约心跳、归档可写 |
| web | 前端/反向代理 | 默认127.0.0.1:8080 | 静态文件可用、API反代可用 |

API上传临时目录可写；封存由worker完成，api不得因上传需求获得已封存对象的覆盖权限。使用 `staging_store` 共享暂存卷及worker归档，与架构文档保持一致。

推荐P0统一选择：**API写staging_store，worker写raw_store并封存，API只读raw_store**。上传响应的batch在worker封存前保持queued，不可分析。staging和raw在同一文件系统时可原子移动；不同文件系统则复制→fsync→校验→原子重命名，再清理暂存。以此细化架构中的上传归档流程。

日志输出到stdout，由Docker轮转；原始归档不放容器可写层。迁移作为一次性作业运行，不能让api和worker同时抢着迁移。检查点与报告必须落库，不存在浏览器缓存里。

## 3. 配置模板契约

下列内容待D1实现为 `.env.example`；值是占位和建议，不含可用密钥：

```dotenv
APP_ENV=demo
APP_BIND=127.0.0.1
APP_PORT=8080
DATABASE_URL=postgresql+psycopg://app:<password>@db:5432/trace
WORKSPACE_ID=<uuid>
RAW_STORE=/data/raw
STAGING_STORE=/data/staging
MODEL_PROVIDER=disabled
MODEL_BASE_URL=
MODEL_NAME=
MODEL_API_KEY=
MODEL_MODE=auto
AGENT_MAX_TOOL_CALLS=6
AGENT_MAX_MODEL_CALLS=4
AGENT_MAX_INPUT_TOKENS=12000
AGENT_MAX_OUTPUT_TOKENS=3000
AGENT_MODEL_WAIT_SECONDS=60
AGENT_TOTAL_TIMEOUT_SECONDS=90
AGENT_MAX_COST_PER_RUN=<D1根据模型填写；disabled时为0>
MAX_UPLOAD_MB=100
GRAPH_MAX_NODES=500
GRAPH_MAX_EDGES=1000
RAW_RETENTION_DAYS=30
DERIVED_RETENTION_DAYS=90
```

令牌用专门初始化命令生成并显示一次，只把摘要存入数据库，避免在Compose文件保存所有角色明文。生产或远程展示需额外TLS与密钥管理，不将本地演示令牌机制宣传为完备身份管理。

`MODEL_PROVIDER=disabled` 为可安装默认值；使用远程模型时先确认数据为授权脱敏实验数据，记录提供商、接口、具体模型标识和参数。温度若受支持建议0；仍不承诺模型确定性。模型名不写“最新”，请求与响应可用的版本信息进入run记录。

## 4. 待实现的统一运行入口

下列命令是开发交付要求，**当前文档包未包含这些脚本**。A在D2/D13实现并实际验证；项目未实现前不能照此宣称已部署。

```bash
# Linux / WSL2 项目目录内
cp .env.example .env
# 编辑本地环境变量，不把密钥复制进Git
docker compose build
docker compose up -d db
docker compose run --rm api python -m apps.api.manage migrate
docker compose run --rm api python -m apps.api.manage init-demo
docker compose up -d api worker web
docker compose ps
```

`init-demo` 必须幂等；初始化工作区、资产和角色令牌。真实身份/密码不写进示例。首次访问页面后由admin导入演示manifest对应的日志，不用内置写死报告冒充分析。

健康检查分两级：`/health/live`仅检查进程；`/health/ready`需管理员查看数据库、worker心跳、磁盘可用量、模型状态。模型不可用不会让规则分析服务整体不可用，但应标降级。

## 5. 开发与发布检查

待仓库建立后统一提供并记录执行结果：

```bash
python -m pytest tests/unit tests/contract tests/integration
python -m ruff check .
python -m ruff format --check .
# apps/web中
npm ci
npm run typecheck
npm run build
npm run test:e2e
```

项目选用其他包管理器时整套替换并锁定；不能混用多个前端锁文件。纯文字修改无需跑全栈测试；涉及契约、权限、图与Agent时必须运行相应回归及主流程。

## 6. 备份、恢复与保留

演示发布前暂停新导入和新调查，等待队列结束，记录数据库快照高水位；备份PostgreSQL、原始对象manifest、对象字节、配置无密钥副本、锁文件、镜像摘要和报告。备份清单分别计算SHA-256，验证数据库引用对象全部存在。

恢复到空环境：加载指定镜像→恢复库→恢复原始对象→校验哈希→核验迁移版本→启动服务→打开旧报告→运行一个新调查。至少由非部署作者执行一次并记录耗时。

raw默认保留30天，派生数据90天；被报告引用的对象设置保留锁，报告保留期间不得清理，除非显式删除整套报告及关联并保留删除审计。TTL作业先列出候选与受保护原因，不自动删未知路径。数据量达到配额时拒绝新导入并提示清理，不悄悄截断。

## 7. 故障处置表

| 症状 | 优先检查 | 处理与展示口径 |
|---|---|---|
| 无告警 | 数据时间、规则启用、必要字段、来源健康 | 显示无命中及覆盖，不创建假告警 |
| 图为空 | 身份映射、事件成员、时间窗 | 展示事实列表与缺证说明 |
| Agent卡住 | run预算、工具超时、worker租约 | 取消或fallback，保留已有证据 |
| 模型无法联网 | 健康状态、代理、授权配置 | 显示确定性分析或历史AI结果 |
| 导入过慢 | 文件规模、索引、队列、磁盘 | 使用已封存小场景，解释规模边界 |
| 数据库异常 | 卷、连接、磁盘、迁移版本 | 切到已验证备机/备份，不在现场重置数据 |
| 证据哈希不匹配 | 原始对象、备份清单 | 标记不可验证，恢复正确备份 |
| 演示页面崩溃 | 静态包、API状态、浏览器缓存 | 使用同版备机；录屏明确标“预录演示” |

## 8. 8分钟演示脚本

| 时间 | 主讲/操作 | 画面与论点 |
|---|---|---|
| 0:00–0:45 | D开场 | 日志分散、人工关联困难；说明授权实验室与能力边界 |
| 0:45–1:30 | B | 导入三源日志，展示输入模式、原始对象和来源计数 |
| 1:30–2:15 | B | 打开一个可疑事件，解释规则为什么命中及正常反例 |
| 2:15–3:30 | C | 图上点父子进程/远程会话边，回到原始日志；区分实线虚线 |
| 3:30–4:45 | C | 开始Agent调查，显示查缺口、工具补证、版本与预算；不必现场等满90秒 |
| 4:45–5:30 | D | 点报告引用，展示事实、假设、未知项与替代解释 |
| 5:30–6:15 | A | 缺主机日志/恶意日志指令反例：不乱连、不执行、不编造 |
| 6:15–7:15 | B | 展示真实评估表：样本量、基线、路径与引用指标、失败例 |
| 7:15–8:00 | A收尾 | 三周完成范围、已知限制、未来实时接入与更多场景 |

网络或模型不稳定时，现场先展示规则与图，再切换有原生成时间和工具轨迹的历史AI报告；明确说明该部分为历史运行。准备一段完整真实运行录屏作为备份，不能把缓存/录像包装为现场实时推理。

## 9. 竞赛材料与答辩

必须交付：技术说明（本方案更新为实施结果）、系统架构图、界面截图、实验设计与原始指标、8分钟演示稿与视频、源代码与部署包、数据来源/许可证清单、局限性页。

建议8～10页展示结构：问题→目标与边界→架构→多源证据→图与路径→Agent补证和约束→实测结果→反例→落地与展望。避免堆技术名词而不解释数据如何流动。

常见问答口径：

- “AI的作用是什么？”展示模型决定下一项查询并依据新增证据修订报告；规则/图是事实基础。
- “与SIEM有什么区别？”强调本原型的证据路径、查询补证与可点击报告；不宣称替代成熟SIEM。
- “能找到真实黑客吗？”当前定位观测入口与传播路径，真实身份通常需要额外跨域证据。
- “为什么不用Neo4j？”三周数据量由关系表与内存子图满足；是否更换由测得瓶颈决定。
- “是不是模型幻觉？”给出引用/谓词校验、未知输出和失败案例，同时承认自由语言仍需复核。
- “有没有创新？”陈述已验证的工程机制和对比结果；研究新颖性需进一步检索与实验，不声称首创。
- “数据真实吗？”逐份说明真实采集、合成、回放和派生，展示来源manifest。

## 10. 发布目录

```text
release/<version>/
  README-install.md
  compose.yaml
  env.example
  version-manifest.json
  SHA256SUMS
  source/ 或源代码归档
  images/ 或离线镜像导入说明
  demo-data/ 与授权、来源、哈希
  reports/ 含mode和原生成时间
  evaluation/ 含配置、逐run结果与指标
  media/ 演示视频、截图、展示材料
  known-limitations.md
  recovery-guide.md
```

发布命名建议 `v0.1.0-demo`；发布日期使用实际完成日期。不要把文档编制日期当作系统发布日期。
## D9本地运行增量（CHG-009）

当前实际启动、迁移0006_d9、复核权限、费用配置、离线HTML与三条合成工程演示见[d9-runbook](d9-runbook.md)。`.env.example`已提供REPORT_EXPORT_MAX_LINES/BYTES、MODEL_INPUT/OUTPUT_USD_PER_MILLION、MODEL_PRICE_VERSION、AGENT_MAX_COST_MICROUSD；默认禁付费调用。示例价格不是供应商实测报价。本文所述Compose、完整备份恢复、实际采集与8分钟现场目标仍是后续验收，不因D9工程构建自动视为通过。

## D10冻结候选增量（CHG-010）

原生候选以WEB_DIST同源提供生产页面，scripts.preflight只读核查环境，scripts.release_manifest与check_d10提供版本/输入白名单/实际依赖/检查证据绑定。操作见[d10-runbook](d10-runbook.md)，冻结演示顺序见[d10-demo](d10-demo.md)。原生独立目录启动只覆盖本机工程子集；Compose、完整备份恢复、非作者干净环境和实测彩排仍按缺陷表阻断完整发布。

D12增量：完整停机备份与空目标恢复现已实现，精确命令和安全边界见[d12-runbook](d12-runbook.md)。备份包括整库（含HMAC私钥）、引用对象和无密钥配置，必须私有保管；不进入公开候选。自动演练不代替非部署作者验收；角色授权、独立机器、镜像与Compose仍待D13验证。原第4节的未实现草案命令不能替代实际CLI。

D13增量：原生部署套件固定D12 candidate-04，`deploy.py verify/install/run/status`实际入口见[d13-runbook](d13-runbook.md)，支持新venv/新SQLite演示库；生产前端随包。来源、许可证元数据、架构/答辩、自动预录与未签署非作者清单分开提供。四服务Compose、独立机器、非作者和真人彩排尚未验收；第4节草案命令仍不是当前入口。

D14增量：`d14-offline-02.zip`将34个锁定wheel与原套件一起交付，目标须已有Windows CPython3.13 x64。实际`offline.py verify/install/backup/restore/run/status`命令见[d14-runbook](d14-runbook.md)，不联网补依赖、不覆盖旧目录；备份拒绝写入公开包/app源码范围。第三目录回退只回到备份高水位，保留备用目录的新调查而不合并，不宣称零损失。连接中断、坏引用与两轮自动计时记录不替代物理断网、独立机器或真人验收；实际结果见[d14-verification](d14-verification.md)。

D15增量：本地工程候选使用START-HERE.html和独立verify.py，固定D14部署ZIP，直接打开展示/报告/两轮预录与历史分析，外部freeze绑定候选与清单。入口和复算命令见[d15-runbook](d15-runbook.md)。普通完整性exit0与strict完整P0阻断exit2明确分开；不生成提交回执、不代签，不改变旧应用或备份。
