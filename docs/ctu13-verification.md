# CTU-13 实采小样本验证记录

日期：2026-11-16。性质：本地工程验证，非检测准确率评测、非正式发布验收。

20 条真实连接记录完成了导入、检测、证据查询、确定性报告和网页查看闭环。较大 TCP 样本的检测完成，但报告被现有快照上限拒绝；不能将本轮概括为所有规模的报告均可用。

## 实际结果

三个样本来自同一次采集且有重叠，不能相加为独立样本数。

| 样本及最终工件 | 首次导入 / 重复导入去重 | 检测 | 调查与报告 | 浏览器检查 |
| --- | --- | --- | --- | --- |
| 源顺序前 10,000 条全协议，`ctu13-check-06` | 10,000 / 10,000；隔离 0 | 完成，0 个候选 | 无候选，未生成报告；报告测试跳过 | 1 通过、2 跳过 |
| 源顺序前 10,000 条 TCP，`ctu13-check-05` | 10,000 / 10,000；隔离 0 | 完成，18 个 R05 候选 | 18 次均返回 422 `SNAPSHOT_EMPTY_OR_TOO_LARGE`；报告未生成 | 2 通过、1 跳过 |
| 上述 TCP 样本内一个连接键的全部 20 条记录，`ctu13-check-04` | 20 / 20；隔离 0 | 完成，1 个 R05 候选 | `completed / deterministic_fallback / passed`；20 条快照证据校验通过 | 2 通过、1 跳过 |

R05 命中仅表示周期连接候选，不等于已确认恶意通信。没有命中也不证明没有攻击。`passed` 是保留结论的引用/谓词校验结果，不是事实真值或模型效果评分。

第三组是为验证报告链路而选取的**定向工程正例**，不是盲测、独立样本或准确率成绩。规则和阈值没有调整。完整连接序列指冻结的 10,000 条 TCP 父样本内的全部成员，不代表原始完整采集中的全部连接。

## 来源与格式适配

- 来源：[CTU-13 官方说明](https://www.stratosphereips.org/datasets-ctu13)，场景 7 / `CTU-Malware-Capture-Botnet-48`。
- 实际下载：[官方 Bro conn.log](https://mcfp.felk.cvut.cz/publicDatasets/CTU-Malware-Capture-Botnet-48/bro/conn.log)。未下载或运行恶意程序、PCAP；未连接日志中的地址。
- 来源署名：Garcia, Sebastian. Malware Capture Facility Project. Retrieved from https://stratosphereips.org。
- 原始连接日志为 Bro TSV；字段语义参照 [Zeek 日志文档](https://docs.zeek.org/en/current/tutorial/logs.html)。只读转换为应用已有 Zeek JSONL 接口，数据集标记 `derived`，保留公开实采来源。
- 下载走官方 HTTPS 并验证 TLS。先获取 4 MiB 前缀，随后在 32 MiB 硬上限内取得完整 17,912,559 字节文件；下载响应与时间见各 `download/download.json`。
- 完整下载 SHA-256：`37af6042144c5590603b5f986202914e4d78f5c74ef96e2aa88052c57e04639d`。
- 没有读取标签文件、`eval/ground_truth`，没有向运行中的规则或 Agent 注入测试答案。

适配器 `bro-conn-tsv@2.1` 校验字段白名单、类型、转义、地址与数值；`-` 保持未知，不能变成 0。ICMP 的原端口栏按类型/代码保留，规范化端口为空。没有补造时间、UID、主机、账号、进程或 socket 归属，原时钟校准未知状态保留。

每个样本保留 `source-sample.log` 原字节、`conn.jsonl`、`line-map.jsonl`、`manifest.json` 和拒绝记录。行映射记录真实源文件行号、源行哈希、原 UID 和输出行号。验证脚本独立从原 TSV 读取 UID、时间、IP、端口或 ICMP 类型/代码、字节数、时长，与 JSONL 及入库事件逐条比较。三组最终运行分别核对 10,000、10,000、20 条，没有字段不一致。

证据 API 指向已导入的派生 JSONL；回溯原始 TSV 使用本地行映射与哈希，不声称应用已经原生支持 Bro TSV。

| 采样 | 真实事件时间（UTC） | 采样边界及源质量 |
| --- | --- | --- |
| 全协议 10,000 条 | 2011-08-16 11:51:24.051606 至 11:53:27.067174 | TCP 2,110 / UDP 7,824 / ICMP 66；246 条时长/字节数未知，424 条源日志报告 `missed_bytes > 0` |
| TCP 10,000 条 | 2011-08-16 11:51:24.053062 至 12:01:11.733374 | 扫描前 58,331 条，按原顺序跳过 48,331 条非 TCP；588 条时长/字节数未知，2,735 条源日志报告 `missed_bytes > 0` |
| 连接键 20 条 | 2011-08-16 11:51:24.057991 至 12:01:06.990701 | 保留父样本中该键全部 20 条；没有删内部异常点或截取满足阈值的子段；本组无上述缺值/丢字节标记 |

20 条样本的键为源地址、目的地址、目的端口、协议；不按变化的源端口拆散。先用已冻结 R05 对固定父样本作离线候选检查，再对满足整组不超过 250 条的键排序选首组；来源及选择依据保存在 `ctu13-source-02/cohort-candidates.json`。选中键是 `147.32.84.170 → 195.24.233.55:80 / tcp`，无身份或恶意归属推断。

最终 20 条 JSONL SHA-256：`8aea101387ff2092eb1df6f1300563fb3281497264aa09b1d9c2e18d4735f73b`；父 TCP JSONL SHA-256：`b469ed29b70212e2119716d35cdcddd5821c113338f63e4ce9ae1680e5989312`。

## 运行环境与证据检查

使用与 8080 一致的安装镜像：后端 dev17 `92ea169ca1a95…`，新版前端 `21f6b34d4ba9…`，PostgreSQL `dd2bf3ce2dc8…`。完整镜像标识见每次运行 `environment.json`。工作区源码版本 dev20 不等于本次受测后端版本。

每轮新建独立 PostgreSQL、原始数据卷、API、worker 和 web；没有挂载 8080 的任何数据卷。API/worker/db 使用内部网络，测试 web 只绑定临时 loopback 端口。`MODEL_PROVIDER=disabled`，启动时断言模型密钥为空；本轮付费模型调用为 **0**。

真实 HTTP 导入经过 worker，非导入接口桩。再次提交相同文件全量去重。查询遍历全部事件页；网页检查数据集来源、事件详情、分页和实际候选显示。

20 条样本生成报告 `b088804f-1794-5865-9a1e-5c45292cdb9e`：

- 调查完成，模型预算调用数 0，模式 `deterministic_fallback`。
- 20 个事件都属于冻结快照；20 条引用片段及哈希与导入文件匹配；报告引用均落在快照内。
- 时间线和关系图引用合法，图没有悬空端点，`truncated=false`。
- JSON / HTML 导出完成，导出证据核对通过。
- 网页实际打开历史报告、证据弹窗、关系与时间线、运行记录并下载 HTML；无页面异常。没有把跳过的测试计入通过。

可查看：HTML 报告（本地归档 `../artifacts/ctu13-check-04/report-1-export.html`）、JSON 报告（本地归档 `../artifacts/ctu13-check-04/report-1-export.json`）、网页截图（本地归档 `../artifacts/ctu13-check-04/report-browser.png`）、完整测试结果（本地归档 `../artifacts/ctu13-check-04/result.json`）、可复用的 20 条样本（本地归档 `../artifacts/ctu13-source-04/adapted/conn.jsonl`）。

## 发现的问题、修复与保留限制

1. 新增适配器在协议预筛选时，坏转义可能提前终止整个转换。已移入逐行异常处理，坏行明确拒绝并保留来源，其余行继续；回归先失败后通过。
2. 新增连接子集清单继承了父样本的跳过计数。已按当前输入重算 `skipped_other_connections` / 协议跳过数和质量统计，另存父样本警告，避免混算；回归先失败后通过。
3. 验证脚本曾使用不存在的 finding 列和错误的 RunStatus 字段；已按实际存储/接口修复。早期 `check-01`、`check-02`、`check-03` 的失败记录和旧样本保持原样；最终依据是 `check-04/05/06`。`source-03` 的旧子集清单保留，最终使用 `source-04`。
4. 较大样本的报告限制仍存在：当前调查按时间窗取快照，最多 250 条；10,000 条 TCP 样本的 18 个候选调查均明确拒绝。没有提高安全上限、静默截断证据或用小样本成功掩盖该结果。浏览器确认显示错误；对应报告用例跳过。若需支持此类稠密时间窗，需另行设计有明确覆盖范围的快照选择，不能直接放宽预算。
5. 最终保全脚本首次误查未实现的 `/api/v1/health/ready` 得到 404；核对契约后使用现有 `/api/v1/health/live` 重验通过。保留初版脚本及错误记录，不作为应用故障。

本轮没有修改应用业务代码、六规则冻结、迁移、8080 配置或镜像；修复范围是新增的适配、溯源与验证工具。

## 保全及最终检查

`ctu13-final-01/preservation.json` 记录最终只读核验：

- 8080 共 28 张表的行数及行内容聚合指纹，与任务开始前一致；六轮共 12 个前后检查点均一致。
- 仍为 37 条事件、5 份报告；5 个原始证据对象重新计算 SHA-256 全部匹配。
- 原四个容器正常运行、镜像未替换、重启策略仍为 `unless-stopped`；首页及已有健康接口返回 200，模型仍 disabled。本轮没有重启原服务，未再次验证整机重启。
- 6 轮独立测试的容器与网络已清理；12 个独立测试数据卷保留，名称见各 `environment.json`，原服务数据卷未操作。测试访问令牌未写入交付工件。
- 新增适配器与子集工具：**22 项单元测试通过**；相关 Python Ruff 和浏览器测试脚本 ESLint 通过。
- 本轮浏览器最终合计 5 项通过、4 项按实际适用范围跳过。这不是 9 项全部通过。

只读保全证据：汇总（本地归档 `../artifacts/ctu13-final-01/preservation.json`）、原始文件哈希核对（本地归档 `../artifacts/ctu13-final-01/production-raw-integrity.json`）、JUnit（本地归档 `../artifacts/ctu13-final-01/unit-tests.xml`）。

## 未验证范围

- 真实 LLM、模型多轮补证、推理质量、调用费用和真实账单。本轮仅确定性模式，没有使用任何付费授权。
- 检测准确率、召回率、误报率、盲测分数；未使用标签，也未调参。
- R01、R02、R03、R04、R06 的真实正例闭环。本轮真实正例仅 R05；连接日志没有主机进程、登录、审计或可靠 socket 归属，无法覆盖多源因果/身份关联。
- 完整 CTU-13、超过 10,000 条的检测规模、持续回放、压力与故障恢复。这些不是本轮实验结论。
- 超过 250 条快照的调查报告：已验证其明确拒绝，但报告能力未完成。
- 人工复核写入、取消/恢复调查、生产写入、自动重启；本轮未做这些操作。

## 文件与复现

新增工具：`scripts/fetch_ctu13_sample.ps1`、`scripts/ctu13_sample.py`、`scripts/ctu13_focus.py`、`scripts/ctu13_environment.py`、`scripts/verify_ctu13.py`。

新增测试：`tests/unit/test_ctu13_sample.py`、`tests/unit/test_ctu13_focus.py`、`apps/web/tests/ctu13.spec.ts`。设计与计划在 `docs/superpowers/specs/2026-11-16-ctu13-real-sample-design.md` 和相应 plans 文件。

在仓库根目录执行下列已使用的命令结构。输出目录必须是全新目录；示例编号 `07` 尚未运行，不能当作新的已完成实验。需要既有 Docker 镜像及本地依赖，不自动安装或拉取模型。

```powershell
& .venv/Scripts/python -m pytest tests/unit/test_ctu13_sample.py tests/unit/test_ctu13_focus.py -q
& .venv/Scripts/python scripts/verify_ctu13.py --source artifacts/ctu13-source-04/adapted --artifacts artifacts/ctu13-check-07
```

`verify_ctu13.py` 默认复用 8080 的镜像标识来启动新环境，不向 8080 导入。最终工件摘要与工具代码哈希见 `artifacts/ctu13-final-01/artifact-manifest.json`；摘要是完整性记录，不是数字签名或正式验收批准。
