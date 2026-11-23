# 第三轮 C&C：漏检原因、补充能力与实际结果

日期：2026-11-17。最终源码 `0.1.0.dev23` / HTTP parser `3.0.1` / R10 `1.0.1` / 数据库 `0006_d9`，独立候选 `cc-round3-candidate-02`。仅本地独立数据库、禁用模型，未替换 8080。属于已见开发样本上的回归，不是盲测、正式准确率或恶意内容确证。

## 结果

此前未检出的 23 条中，**新增覆盖 2 条，仍有 21 条未覆盖**。加上第二轮已有的 3 条，当前 26 条官方 C&C 连接共覆盖 **5 条**，对应 **R09、R10 各 1 个候选**。候选数、连接数和 HTTP 行数不能混算。

| 独立用例 | conn / HTTP 输入 | 候选 | 官方 C&C 覆盖 | 正常连接被新规则覆盖 | 报告 |
|---|---:|---|---:|---:|---:|
| 上轮剩余连接 | 23 / 74 | R10 ×1 | 2/23 | 不适用 | 1 |
| 全部原 C&C | 26 / 77 | R09 ×1、R10 ×1 | 5/26 | 不适用 | 2 |
| 官方正常对照 | 20 / 19 | 旧 R05 ×1 | 不适用 | 0/20 | 1 |
| 全部 C&C 与正常混合 | 46 / 96 | R05、R09、R10 各1 | 5/26 | 0/20 | 3 |

这些用例复用同一批真实连接，不能累加为独立样本数。每组全部成功入库，重复上传分别去重 97 / 103 / 39 / 142 条，入库隔离记录均为 0。7 份报告均为 completed / deterministic_fallback / passed、模型调用0；逐条快照证据查询与 JSON/HTML 导出通过，4 项真实样本浏览器用例通过。passed 仅表示保留结论通过校验，不代表攻击因果或控制成功。

R10 的两条连接 UID 为 `CfIh094sh2uOr4ceCf`、`CmBPVehVWu2pWCnPb`；原生 HTTP 行号为 4769、4931。两条都唯一对齐官方 `flow=From-Botnet-V48-TCP-CC77-HTTP-Not-Encrypted`，各含一条恢复的 HTTP 请求，响应均 **404**。报告有 2 条 conn + 2 条 HTTP 引用，保守跨度上限 15.265426 秒。标签吻合不证明查询字节是控制命令，404 不能解释成成功控制。

正常对照未产生 R08/R09/R10 候选，但旧 R05 周期性候选仍存在。若把所有候选直接当作恶意结论，该正常候选仍属于误报；不能宣传整个系统零误报。

## 23 条的漏检原因

| 数量 | 原因与观测 | 本轮处理 |
|---:|---|---|
| 2 | 原始 HTTP 存在，URI 含非 UTF-8 字节，旧原生 TSV 适配拒绝整行；查询为长无键值分隔形式，百分号转义亦不合法 | 可逆字节适配恢复；R10 独立命中 |
| 1 | `CqHf0wiBJbjQOoJNh`，源 conn 行28852，S0/history S，发2包/收0包，双向载荷0，未见 HTTP | 保留未检出，不能凭一次无响应连接判断 C&C |
| 19 | 官方 CC108，共71次GET，39个GIF、21个JPG、其余ICO/CSS/HTML/JS/PNG及无后缀；9条状态200、62条状态未知，均浏览器兼容UA外形 | 不能只凭网页资源外形区别恶意，继续未覆盖 |
| 1 | `CWhYaxEr6mIvRe9Ih`，浏览器兼容UA，6个查询字段、两个16字符十六进制值，不满足旧R08/R09的客户端与32字符标识形态条件；响应404 | 现有证据不足以支持放宽后的可靠区分，继续未覆盖 |

19 条网页资源请求和单条浏览器请求都是“缺少恶意区分依据”，不是已经证明正常。官方标签未输入运行中的检测算法或 Agent；没有用固定 IP、域名、UID、URI 路径或参数名制造命中。逐条记录见 `artifacts/cc-round3-01/samples-01/miss-diagnosis.json`，逐条结果附于本文末尾。

## 修复和新增行为

- **字节适配**：`scripts/bro_protocol_sample.py` 增加显式可选的 URI/UA 字节恢复，原默认严格行为不变。新样本生成器仅选白名单字段，严格保留原物理行号及 SHA256；base64 解码与原 Bro 转义后字节逐一吻合，不猜测字符编码或改写原始日志。
- **安全契约与解析**：`packages/ingest/http_bytes.py`、`http_dns.py`、`parsers.py`，`packages/contracts/models.py`、`protocols.py`。HTTP schema1.4 新增可缺省 query_shape；原始 uri_b64/user_agent_b64 与文本字段互斥，严格格式/上限。投影只保留计数和有效性，原 URI、UA、base64、参数值和内容摘要不进入证据/报告/Agent。旧1.0–1.3可读，DNS仍1.2；旧文本URI字符上限保持，新字节包装使用字节上限。
- **独立 R10**：`packages/detection/r10.py`、`freeze_nontext.py`、`registry.py`、`common.py`，新 `rules/R10.json`、`cc-nontext-freeze.json`。同采集器/作用域/源和远端端点/Host，至少2个唯一关联TCP连接的长非文本查询，在保守600秒内才产生候选。连接歧义、缺少可靠时间等不强连，重复记录不增连接数；失败响应不等于成功控制。
- **报告限制**：`packages/agent/reporting.py`、`packages/storage/analysis.py` 明确正常二进制遥测、旧编码和损坏日志等解释，以及响应、进程/socket、身份和因果缺口。
- **独立核验**：`eval/ctu13_cc_round3.py`、`ctu13_cc_round3_audit.py`、`scripts/verify_cc_round3.py` 及新单元/集成/浏览器测试。离线标签只用于选样和检测结束后的核对；应用镜像没有打包本轮 eval 或样本。生成契约/前端类型及版本元数据同步，无新依赖、迁移或API路由。

编码语法参考 [RFC 3986](https://www.rfc-editor.org/rfc/rfc3986.html)，字节保留参考 [Zeek 日志格式说明](https://docs.zeek.org/en/current/frameworks/logging.html)；实际适配以本地2011年TSV文件头和转义字节为准。这些格式说明不是恶意判据，R10仍是开发启发式。

全 HTTP 源中本轮可逆恢复67行，仍拒绝10行；所选测试数据涉及其中2条恢复记录、0条拒绝记录。67条恢复不等于67条恶意命中；其余恢复行未作为本轮实际输入验收。

## 审查发现与修复

初版 candidate-01 真实运行可覆盖5/26，但独立只读审查发现两个边界问题：窗口只算首尾时间误差、fragment中的问号被误作查询。4个反例先失败，再修复；旧候选/结果/失败日志保留，不覆盖为通过。

最终 parser3.0.1 先移除字面 `#` 片段，再识别 `?` 查询；R10 1.0.1 对**全部窗口请求**的时间区间维护极值，窗口合并和统计使用同一边界。内部不确定观测不会被删掉来拼接两端；这可能保守漏检。旧R10 1.0.0保留仅供历史finding精确复现，不能把归档有缺陷的版本当作最终候选。原R01–R09代码语义配置与冻结没有更新，本次新窗口算法不替代旧规则的边界验收。

最终新能力39项测试通过，覆盖包装冲突/非法/超限、隐私、普通UTF-8/旧编码键值/ASCII反例、失败响应、跨范围/采集器/Host、歧义连接、重复、时间极限、随机异质误差窗口和自身证据精确复现。正常二进制遥测可符合的合成正例明确保留，不能据20条正常对照推断广泛零误报。

## 版本化工件与验证范围

- 最终候选：`artifacts/cc-round3-candidate-02`；最终真实运行：`artifacts/cc-round3-check-02`；离线标签核对：`artifacts/cc-round3-labels-02/comparison.json`。
- 原因与恢复输入：`artifacts/cc-round3-01/samples-01`；逐字节恢复核对：`source-roundtrip.json`；零载荷原始状态：`zero-payload-connection.json`。
- 原网页9项流程在最终代码上通过，含导入、重试、会话/回放、证据、报告/导出/复核/历史、缺证与排队：`artifacts/cc-round3-ui-regression-02`。
- 第一轮真实HTTP回归：`artifacts/cc-round3-r07-regression-01`，154条输入仍1个候选/报告，37条请求对照仍7个候选/报告；导入、去重、查询、证据、8份确定性报告及两组浏览器流程通过。
- 最终完整 Python：**784 passed，1个既有Starlette/httpx弃用警告，569.75秒**；`artifacts/cc-round3-01/full-pytest-01.txt` / `full-junit-01.xml`。Ruff、前端TypeScript/Vite构建与ESLint通过。新能力39项反例及正例包含于全套测试。

## 最终保全与版本绑定

`artifacts/cc-round3-01/preservation.json`：8080全28张表的行数/聚合摘要前后一致，仍37事件、5报告；5个原始对象哈希全部吻合，模型disabled，原API/worker/web镜像未替换。806个旧工件、27个原规则/冻结/schema/迁移文件与基线一致。R01–R09没有修改语义配置或冻结；源旧事件/报告不补写新字段。

candidate-01与candidate-02各130文件通过清单核对，candidate-02后台/前端字节与最终源码/构建一致，清单SHA256为 `a038a2e8f336e403581ad8592710b1fbe66b78eaa4270b9114ae7ff0341d28bf`。旧R09与修复前R10实测finding仅凭原证据精确复现，记录在 `historical-replay.json`。完整测试/JUnit、冻结、样本、标签结果和本说明以 `verification-binding.json` 绑定。

测试容器/临时网络已退出，独立数据库和原件卷保留；未清理、挂载到测试容器或重建生产卷。没有付费模型调用、生产部署、远程提交或公开发布。模型报告仅为deterministic_fallback。

## 剩余缺口与未验证

1. 21条官方 C&C 仍未检出；20条有HTTP但可与正常行为相似，1条无应用载荷。不能给它们补造命令/进程证据或改为“正常”。
2. 其他CTU场景、独立盲测、更多正常浏览/二进制遥测/代理及损坏日志；当前少量正常对照不能估计普适误报率。重复使用这些样本属于开发回归。
3. PCAP重新解析、HTTP响应内容/恶意语义、主机进程/socket、HTTPS/TLS、DNS隧道、非HTTP C&C与控制成功；本轮不重放真实攻击或访问样本远端。
4. 新R10的大规模性能和不同采集器生产时钟条件；R01–R09保留原冻结，本轮未扩大旧规则在所有时钟不确定组合下的验证。时间极值条件选择保守，不跳过内部不确定观测，可能漏检。
5. 生产部署、存量自动补写/迁移、重启切换和真实LLM效果未验证。本轮模型完全disabled，不能将确定性报告当作真实模型验收或关闭原有正式发布/P1门禁。

## 原23条逐条核对

| UID | 官方类别 | 上轮原因 | 最终结果 |
|---|---|---|---|
| `CfIh094sh2uOr4ceCf` | CC77 | URI非UTF-8导致原行被拒绝 | R10候选覆盖 |
| `CqHf0wiBJbjQOoJNh` | CC77 | 零载荷，无HTTP | 仍未覆盖 |
| `CEGEKG2uwbeDuCAuD5` | CC108 | 浏览器外形/查询门槛不满足 | 仍未覆盖 |
| `CcVdPVPo6HIQCLVfh` | CC108 | 浏览器外形/查询门槛不满足 | 仍未覆盖 |
| `C7piMg2m0qJ67wOKZa` | CC108 | 浏览器外形/查询门槛不满足 | 仍未覆盖 |
| `CbHraftLGrm7pmz4j` | CC108 | 浏览器外形/查询门槛不满足 | 仍未覆盖 |
| `Cfs5Va3XpLQfOr8lY9` | CC108 | 浏览器外形/查询门槛不满足 | 仍未覆盖 |
| `CcRxq8smoNVkVd0di` | CC108 | 浏览器外形/查询门槛不满足 | 仍未覆盖 |
| `Ci7o243oXfoDOeVaGk` | CC108 | 浏览器外形/查询门槛不满足 | 仍未覆盖 |
| `C32ztp2vK6jCP8SeW6` | CC108 | 浏览器外形/查询门槛不满足 | 仍未覆盖 |
| `CmBPVehVWu2pWCnPb` | CC77 | URI非UTF-8导致原行被拒绝 | R10候选覆盖 |
| `CO8Lmw1NDy4ly3zw1b` | CC108 | 浏览器外形/查询门槛不满足 | 仍未覆盖 |
| `CEM77s4njFzZo1uY7e` | CC108 | 浏览器外形/查询门槛不满足 | 仍未覆盖 |
| `CBB84X36fGaQojpGo` | CC108 | 浏览器外形/查询门槛不满足 | 仍未覆盖 |
| `CpW98c2GBGis7DSARk` | CC108 | 浏览器外形/查询门槛不满足 | 仍未覆盖 |
| `Cxci95E9IvWbSmHxi` | CC108 | 浏览器外形/查询门槛不满足 | 仍未覆盖 |
| `CWhYaxEr6mIvRe9Ih` | CC77 | 浏览器外形/查询门槛不满足 | 仍未覆盖 |
| `C8hX271l6Z46E4o4Ij` | CC108 | 浏览器外形/查询门槛不满足 | 仍未覆盖 |
| `C7izfL284OTEF2JJY5` | CC108 | 浏览器外形/查询门槛不满足 | 仍未覆盖 |
| `CFq2j01egwbnlwHjm8` | CC108 | 浏览器外形/查询门槛不满足 | 仍未覆盖 |
| `Ciwgyk9v84MrKaABg` | CC108 | 浏览器外形/查询门槛不满足 | 仍未覆盖 |
| `Cga5ig33cM9HuH02jf` | CC108 | 浏览器外形/查询门槛不满足 | 仍未覆盖 |
| `C5OJbx3OQZyRL3klA1` | CC108 | 浏览器外形/查询门槛不满足 | 仍未覆盖 |
