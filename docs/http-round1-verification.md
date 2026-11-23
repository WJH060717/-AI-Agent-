# HTTP/DNS 第一轮补充：实际验证结果

日期：2026-11-17。源码 dev21，最终独立候选 `artifacts/http-round1-candidate-03`，数据库迁移仍为 `0006_d9`。这是开发验证，不是正式准确率或发布批准；没有部署到 8080。

## 新增行为

- 新增 `zeek_http`、`zeek_dns` JSONL 导入及网页自动识别，复用 Zeek 采集器身份。规范化事件支持 1.2；旧事件与原有导入继续兼容。
- R07 检查 GET、200/206 与可执行后缀/MIME，必须唯一关联同工作区、数据集、采集器、UID、TCP 端点及时间范围的 conn。DNS 仅为可选上下文，限 A/AAAA 对应地址族；不能用 IP 形态的 TXT 答案证明地址解析。
- 请求候选接入原有调查、证据核验与 HTML/JSON 报告。页面增加可展开的“适用限制”。URI 查询参数、凭据、任意 DNS 答案不进入安全投影。
- 原六规则、`rules/freeze.json` 与 7 个迁移文件字节不变；R07 使用独立冻结文件，缓存/恢复身份绑定新增代码与配置。没有修改检测预算或调用付费模型。

主要涉及 `packages/contracts/{models,protocols,agent}.py`、`packages/ingest/{parsers,http_dns,identity}.py`、`packages/detection/{r07,freeze_http,registry,common}.py`、`packages/storage/{service,context,analysis}.py`、`packages/agent/{executor,reporting}.py`、`apps/web/src/{Intake,importHints,ReportPanel}` 以及生成契约、新适配/验证脚本与测试。具体变更和哈希见 `artifacts/http-round1-01/change-manifest.json`。

## 真实数据结果

原始数据来自 CTU-13 场景 7 官方 Bro conn/http/dns 日志；适配后只把协议字段送入应用，官方标签只在检测结束后离线比对。规则没有加入样本 IP、域名或恶意标签，也没有降低 R05 阈值。

| 独立样本 | conn / HTTP / DNS | 导入事件 | R07 候选 | 报告 |
|---|---:|---:|---:|---:|
| 已有官方恶意连接及协议上下文 | 46 / 85 / 23 | 154 | 1 | 1，通过 |
| 成功可执行后缀请求对照 | 6 / 24 / 7 | 37 | 7 | 7，通过 |
| 已核实正常连接及协议上下文 | 20 / 19 / 38 | 77 | 0 | 本组未新建调查 |

前两组使用全新的 Docker/PostgreSQL/API/worker/web；第一次导入合计 191 条、重复导入识别 191 条、运行时隔离 0 条。两组浏览器重复上传均新增 0。8 份报告均 `completed / deterministic_fallback / passed`，证据查询及 HTML/JSON 导出通过，模型调用数均为 0。两组有重叠来源，不能把 8 份报告算作 8 个独立攻击。

正常组在独立 SQLite/原始对象目录验证，20 条 conn 均唯一匹配官方 From-Normal。新增 R07 为 0；原 R05 仍产生 1 个周期候选，本轮没有修改或消除这个旧候选。

### 官方标签核对

恶意组的 1 个候选唯一匹配官方标签：

`flow=From-Botnet-V48-TCP-Established-HTTP-Binary-Download-12`

匹配依据是连接五元组、方向及时间；HTTP 请求再通过同采集器 UID/端点/时间关联。该请求为 `.exe`、HTTP 200，日志的响应体字节为 **0**，因此系统标记为 `request_only`。这证明新增规则能够发现官方恶意下载连接上的可疑请求，不能从日志证明文件内容、完整下载、执行或操作者身份。该候选没有符合条件的 DNS 佐证。

请求对照组的 7 个候选中：1 个是上述同源恶意请求，另外 6 个对应官方 **Background**。Background 没有足够的恶意/正常真值，不能算作已证实命中或误报。这说明 R07 是待核查候选筛选，尚不能用于自动恶意定性；不能以本次定向开发样本给出准确率/召回率。

离线逐项结果：`artifacts/http-round1-labels-01/comparison.json`。标签从未进入运行容器、模型或规则输入。

## 发现并修复

1. HTTP/DNS 格式原来不受支持：增加严格类型解析、同采集器绑定与安全投影。
2. HTTP 事件原来不能按工具类型查询：补齐白名单类型与契约测试。
3. 报告页面遗漏 claim 的适用限制：新增可展开显示，并通过真实浏览器验证。
4. DNS IP 形态 TXT 被当作地址答案：限定 A/AAAA 及地址族，其他答案省略并计数；补充反例。
5. 新版本 compose 标签仍指向 dev20：源文件改为 dev21，未执行该 compose 或改变现有部署。

官方 HTTP 全文件中有 74 行在本次所需字段解码时遇到非 UTF-8 字节，保留原件、行哈希和失败记录，没有猜测编码。其 UID 中有 3 行属于恶意连接组，因此该组 HTTP 原始关联记录为 88 行，实际适配 85 行。**运行时隔离 0 不代表整个原始文件无解析缺失。** 正常组所选 UID 无此类排除。

独立审查发现的 DNS 问题已修复，新增反例先失败后通过。构建候选 01、验证 check-01/02/03 和初次回归的失败原件均保留：分别涉及本地镜像引用、验证脚本 run 字段、页面限制遗漏，以及测试期间源码变化导致恢复身份拒绝/版本标签不一致。最后固定源码重跑，不改写旧失败。

## 最终检查

- 全量 Python：**710 passed**，1 个现有 Starlette/httpx 弃用警告；`artifacts/http-round1-01/full-pytest-02.txt`。
- 新协议及规则/链路针对性测试：50 passed；覆盖缺字段、类型/范围、TXT、跨采集器、时间、歧义、重复请求、DNS 上限、冻结漂移、历史复现、权限与原始证据篡改。
- 原网页工作流：**9 passed**；真实两组浏览器各 **2 passed**。
- TypeScript 类型生成、构建、ESLint、相关 Python Ruff 检查通过。
- 最终候选 114 个清单文件哈希通过，运行源与已测当前代码一致。
- 8080 的 **28 张表行数/内容摘要一致**，**5 个原始对象 SHA-256 一致**，原模型仍 disabled；4 个原容器保持运行。基线指纹文件末尾换行差异不属于数据差异。

实际端到端结果：`artifacts/http-round1-check-04/result.json`；正常对照：`artifacts/http-round1-normal-01/result.json`；数据保护：`artifacts/http-round1-01/preservation.json`。测试容器/网络已移除，独立测试卷与原始工件保留。

## 尚未补齐/验证

- 通用 C&C、HTTPS/TLS 加密内容、完整恶意软件识别、文件哈希/签名与主机执行闭环仍未实现；原来那批 C&C 连接不能因本轮下载候选成功就算已检出。
- 74 行非 UTF-8 字段的完整无损导入仍未实现（包含恶意组关联的 3 行）。
- 此轮是已看过场景上的开发回归；没有独立盲测、全量流量性能或正式准确率/误报率结论。
- 没有新能力的真实 LLM 调查验收，所有结果来自确定性流程。
- 新版本尚未接入 8080，也未做其上线/重启验收；本轮按要求保留既有服务和数据。
