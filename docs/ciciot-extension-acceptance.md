# CICIoT2023 第 13.7 节离线验收

验收按规约中的 17 个精确子类型计分。清单的固定版本和 SHA-256 绑定样本角色、物理记录数、输入摘要和来源记录摘要。同源截取或其他公开对象的补充片段单独验证。采集失败引用历史记录，未取得原始输入的类别保留在分母。

在项目根目录运行以下命令并为本次结果选择新路径。

```powershell
.\.venv\Scripts\python.exe -X utf8 -m eval.ciciot_extension --manifest eval/configs/ciciot-extension-01.json --result artifacts/spec-remaining-dev38-02/extension.json
```

程序在临时 SQLite 和隔离 ASGI 应用中使用中性名称逐份导入。报告核验包号、字节范围和对象摘要。改名重导前后比较原会话候选，回放核对首次导入接受数、规则版本、证据及贡献事件。`exact_pass` 要求唯一精确子类型、物理记录对账、引用核验和回放一致。`unknown` 表示处理已完成但精确子类型缺证。`unverified` 表示缺少固定输入，`collection_failed` 引用已有采集失败。额外或冲突子类型记作 `cross_class`，执行或验证失败记作 `failed`。Mirai 的通用 UDP 洪泛可作为行为旁证，家族分类仍为未知。

退出码 0 表示清单内全部固定输入通过精确验收，退出码 2 表示仍有未通过的固定输入。所有类别和补充输入的结果均保存于 JSON。原 DoS/DDoS 固定集独立按第 12.1 节验证。

```powershell
.\.venv\Scripts\python.exe -X utf8 -m scripts.verify_fragment_rules --manifest artifacts/ciciot2023-ddos-samples-02/manifest.json --fixed-set v2 --result artifacts/spec-remaining-dev38-02/fixed-v2.json
```

应用和运行 Agent 不消费 `eval`。隔离应用使用显式验收配置和默认值，模型关闭。API 模块在导入时仍会解析默认应用配置，无效的应用配置可导致启动失败。本版处理登记的 PCAP 输入。涉及独立终端、服务或探针审计的类别，还需要相应的原始阶段记录和跨源关联验收。

## dev38 本机复验（2026-11-22）

| 检查 | 实际结果 |
| --- | --- |
| 第 13.7 节的 17 个固定验收类别 | 1 个精确通过（PingSweep）、4 个未知、2 个出现其他类别候选、1 个采集失败、9 个无固定原始输入。退出码 2。 |
| 同源及独立对象补充片段 | PortScan 在已见的 221 包同源片段中精确通过。两个 GRE 封装在其补充抓包分别复现 R27，Mirai 家族仍未知。 |
| 混淆记录 | OSScan 和 VulnerabilityScan 的固定前缀各出现一个 R24 PortScan 子类型候选，均已核验证据并回放。发布结果保留原观察及精确标签缺口。 |
| DoS/DDoS 固定集 v2 | 11/12 精确匹配，SlowLoris 未知。12/12 完成物理记录对账及重导、回放，0 个跨类候选。按第 12.1 节门禁退出码 0。 |
| 正常对照覆盖 | 第 13.7 节这次运行的正常抓包数为 0。既有 dev38 R27 的 10 份正常对照另见 历史记录（本地归档 `../artifacts/ciciot2023-mirai-protocol-01/acceptance.json`）。 |
| PostgreSQL 独立本机试验 | PostgreSQL 16.16 新集群、合成数据，空库恢复核对 28 张表、32 个事件、1 份旧报告。旧令牌和 HMAC 保持，恢复后新调查完成，写入排斥及非空目标拒绝通过。非作者验收待办。 |
| Compose 和页面 | P1 Compose 的应用与网页镜像标签已对齐 dev38，静态配置解析通过。Docker Linux 引擎不可连接。隔离浏览器 9 项、前端生产构建、TypeScript、ESLint、Ruff 通过。 |
| Python 回归 | 原有全量收集的 1,007 项通过。最终的抓包、验收门禁、备份和 P1 针对性回归 95 项通过。 |

17 类执行报告（本地归档 `../artifacts/spec-remaining-dev38-01/extension-verified.json`） · 固定集 v2（本地归档 `../artifacts/spec-remaining-dev38-01/fixed-v2-verified.json`） · PostgreSQL 恢复（本地归档 `../artifacts/spec-remaining-dev38-01/postgres-recovery/recovery.json`） · 浏览器日志（本地归档 `../artifacts/spec-remaining-dev38-01/browser/playwright.log`） · 最终回归 JUnit（本地归档 `../artifacts/spec-remaining-dev38-01/acceptance-verified.xml`） · P1 就绪门禁（本地归档 `../artifacts/spec-remaining-dev38-01/p1-readiness-final.json`）

本机 P1 就绪门禁退出码 2。真实模型及账单、33 次独立资料及双人复核、非作者恢复、干净机器启动、物理断网和真人彩排仍待验收。正式资料门禁为 33 项计划、3 项已准备、0 项已复核。需要的证据及验收人员见 [五项 P1 验收材料](p1-user-actions.md)。

## dev39 欺骗类包证据

R28 与 R29 只发布同一采集范围内的 ARP 映射冲突和 DNS 答复差异。合成正例覆盖 ARP 应答、IPv4 上的 A 与 AAAA 答复，逐包证据、改名重导和回放通过。对照覆盖窗口外、跨原件、缺请求、相同答案集、可读扩展重试及观测时间回拨。

10 份已冻结正常抓包完成重导和回放，观察到 396 条 ARP 请求、195 条 ARP 应答、876 条 UDP 端口 53 记录，其中有 417 条支持的 DNS 查询和 241 条支持的答复。R28 和 R29 均为 0 个候选。样本来源的场景标签不代表对每包的独立真值。17 类固定验收仍只有 PingSweep 精确通过，两个欺骗类仍缺固定原始输入和可信对照。旧固定集 v2 保持 11/12 精确、12/12 对账与回放，SlowLoris 未知。Python 回归 541 项、浏览器 9 项及生产构建通过。

dev39 扩展与正常对照报告（本地归档 `../artifacts/p2-packet-conflicts-dev39-01/extension.json`） · dev39 固定集 v2（本地归档 `../artifacts/p2-packet-conflicts-dev39-01/fixed-v2.json`） · 工件摘要（本地归档 `../artifacts/p2-packet-conflicts-dev39-01/verified-inputs.json`）

## dev40 OSScan 补充证据复验

`ciciot-extension-02.json` 在旧固定输入之外登记已见的 OSScan 同源片段和扣留配对应答的对照。包号、字节范围和原件摘要见 补充片段来源（本地归档 `../artifacts/p2-os-fingerprint-dev40-01/supplement.json`）。仍沿用 17 类分母和独立固定集 v2。

```powershell
.\.venv\Scripts\python.exe -X utf8 -m eval.ciciot_extension --manifest eval/configs/ciciot-extension-02.json --normal-controls --result artifacts/p2-os-fingerprint-dev40-02/extension.json
.\.venv\Scripts\python.exe -X utf8 -m scripts.verify_fragment_rules --manifest artifacts/ciciot2023-ddos-samples-02/manifest.json --fixed-set v2 --result artifacts/p2-os-fingerprint-dev40-02/fixed-v2.json
```

2026-11-22 复验中，OSScan 同源片段同时发布了 R30 和独立的 R24。R30 四条贡献分别对应原件第 2169、2217、5207、5219 包，跨度 4,857,147 微秒。报告、改名重导和回放均核验通过。扣留第 5219 包的对照只留下 R24。原始固定 OSScan 输入仍有分类混淆，补充片段也有两个精确候选，均留在各自验收位置。R30 只使用能完整覆核载荷的 ICMP 引用，配对键的读取范围是同一原件。

| 门禁 | dev40 结果 |
| --- | --- |
| 第 13.7 节 17 类 | 1 个固定精确通过、4 个未知、2 个分类混淆、1 个采集失败、9 个缺固定原始输入。退出码 2。 |
| 独立固定集 v2 | 11/12 精确通过，SlowLoris 仍为未知，12/12 对账和回放一致，0 个跨类候选。退出码 0。 |
| 正常对照 | 10/10 完成核验。R28、R29、R30 均无候选。DNS 和 ARP 的协议覆盖数与 dev39 相同，另有 243 条 TCP 请求和 185 条应答带 R30 配对字段。 |
| 回归 | 551 项 Python 和 9 项浏览器通过，Ruff、生成契约、前端生产构建通过。旧数据集重导保留 3 条原有 1.6 事件，隔离新数据集取得对应的 1.8 DNS 观测。 |

逐类与正常对照报告（本地归档 `../artifacts/p2-os-fingerprint-dev40-01/extension.json`） · 固定集 v2（本地归档 `../artifacts/p2-os-fingerprint-dev40-01/fixed-v2.json`） · 四包原件回查（本地归档 `../artifacts/p2-os-fingerprint-dev40-01/source-readback.json`） · 测试与来源摘要（本地归档 `../artifacts/p2-os-fingerprint-dev40-01/verified-inputs.json`）

精确验收仍缺固定原始输入及可信旁证，包括用于解析与地址绑定的独立基线、主机发现与具体服务检查的审计、能关联到同段流量的 Mirai 家族证据，以及认证、应用和终端记录。剩余证据缺口逐类记录在报告中。

按规约第 13.8 节开展的后续原件回读、16 项逐类阻塞和本轮复验见 [P2 下一阶段执行台账](p2-next-stage-verification.md)。

规约第 13.9 节的行为检测主指标按 16 条任务单独计分。新报告在结论和导出显示溯源状态，新口径与本页历次严格分类成绩分别保留。[dev41 行为检测验收](ciciot-behavior-verification.md)
